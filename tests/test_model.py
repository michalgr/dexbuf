"""Comprehensive unit tests for dexbuf.model module."""

import hashlib
import io
import os
import struct
import tempfile
import unittest
import zipfile
import zlib
from collections.abc import Iterator, Sequence
from typing import Any

from dexbuf import (
    AccessFlags,
    ClassLoader,
    ClassLoaderElement,
    DexAdapter,
    DexFile,
    ResolvedClass,
    UnresolvedClass,
    VdexAdapter,
    VdexFile,
    ZipAdapter,
    ZipArchive,
    load,
    open,
)
from dexbuf.mutf8 import encode_mutf8


def build_dex_bytes(classes: list[dict[str, Any]]) -> bytes:
    """Build a minimal valid DEX binary buffer for testing."""
    raw_strings = {"V"}
    for c in classes:
        raw_strings.add(c["name"])
        if c.get("super"):
            raw_strings.add(c["super"])
        for iface in c.get("interfaces", []):
            raw_strings.add(iface)
        if c.get("source_file"):
            raw_strings.add(c["source_file"])
    strings = sorted(raw_strings)
    str_map = {s: i for i, s in enumerate(strings)}

    type_descs = sorted({s for s in strings if s.startswith("L") or s.startswith("[") or s == "V"})
    type_map = {t: i for i, t in enumerate(type_descs)}

    data = bytearray()

    str_offsets = []
    for s in strings:
        str_offsets.append(len(data))
        encoded = encode_mutf8(s, null_terminated=True)
        utf16_len = len(s)
        uleb = bytearray()
        val = utf16_len
        while True:
            b = val & 0x7F
            val >>= 7
            if val > 0:
                uleb.append(b | 0x80)
            else:
                uleb.append(b)
                break
        data.extend(uleb)
        data.extend(encoded)

    iface_offsets = {}
    for c in classes:
        ifaces = c.get("interfaces", [])
        if ifaces:
            while len(data) % 4 != 0:
                data.append(0)
            iface_offsets[c["name"]] = len(data)
            data.extend(struct.pack("<I", len(ifaces)))
            for iface in ifaces:
                data.extend(struct.pack("<H", type_map[iface]))
            if len(ifaces) % 2 == 1:
                data.extend(struct.pack("<H", 0))

    header_size = 0x70
    str_ids_off = header_size
    type_ids_off = str_ids_off + len(strings) * 4
    class_defs_off = type_ids_off + len(type_descs) * 4
    data_off = class_defs_off + len(classes) * 32

    abs_data_start = data_off

    buf = bytearray()
    buf.extend(b"\x00" * header_size)

    for off in str_offsets:
        buf.extend(struct.pack("<I", abs_data_start + off))

    for tdesc in type_descs:
        buf.extend(struct.pack("<I", str_map[tdesc]))

    for c in classes:
        c_idx = type_map[c["name"]]
        flags = c.get("access_flags", 1)
        s_idx = type_map[c["super"]] if c.get("super") else 0xFFFF_FFFF
        i_off = abs_data_start + iface_offsets[c["name"]] if c["name"] in iface_offsets else 0
        sf_idx = str_map[c["source_file"]] if c.get("source_file") else 0xFFFF_FFFF
        buf.extend(struct.pack("<8I", c_idx, flags, s_idx, i_off, sf_idx, 0, 0, 0))

    buf.extend(data)

    while len(buf) % 4 != 0:
        buf.append(0)
    map_off = len(buf)

    map_items = [
        (0x0000, 1, 0),
        (0x0001, len(strings), str_ids_off),
        (0x0002, len(type_descs), type_ids_off),
        (0x0006, len(classes), class_defs_off),
        (0x1000, 1, map_off),
    ]
    map_bytes = struct.pack("<I", len(map_items))
    for k, sz, off in map_items:
        map_bytes += struct.pack("<HHII", k, 0, sz, off)
    buf.extend(map_bytes)

    file_size = len(buf)
    data_size = file_size - abs_data_start

    magic = b"dex\n035\x00"
    struct.pack_into(
        "<8sI20sIII", buf, 0, magic, 0, b"\x00" * 20, file_size, header_size, 0x12345678
    )
    struct.pack_into("<I", buf, 0x34, map_off)
    struct.pack_into(
        "<IIIIII", buf, 0x38, len(strings), str_ids_off, len(type_descs), type_ids_off, 0, 0
    )
    struct.pack_into("<IIIIII", buf, 0x50, 0, 0, 0, 0, len(classes), class_defs_off)
    struct.pack_into("<II", buf, 0x68, data_size, abs_data_start)

    sig = hashlib.sha1(buf[32:]).digest()
    buf[12:32] = sig
    chk = zlib.adler32(buf[12:]) & 0xFFFF_FFFF
    struct.pack_into("<I", buf, 8, chk)

    return bytes(buf)


def build_vdex_bytes(dex_buffers: list[bytes]) -> bytes:
    """Build a minimal valid VDEX v027 binary buffer for testing."""
    buf = bytearray()
    buf.extend(struct.pack("<4s4sI", b"vdex", b"027\x00", 2))

    chk_size = len(dex_buffers) * 4
    dex_sec_offset = 12 + 2 * 12 + chk_size
    while dex_sec_offset % 4 != 0:
        dex_sec_offset += 1

    dex_payload = bytearray()
    for d in dex_buffers:
        dex_payload.extend(d)
        while len(dex_payload) % 4 != 0:
            dex_payload.append(0)

    buf.extend(struct.pack("<3I", 0, 12 + 2 * 12, chk_size))
    buf.extend(struct.pack("<3I", 1, dex_sec_offset, len(dex_payload)))

    for d in dex_buffers:
        chk = struct.unpack_from("<I", d, 8)[0]
        buf.extend(struct.pack("<I", chk))

    while len(buf) < dex_sec_offset:
        buf.append(0)

    buf.extend(dex_payload)
    return bytes(buf)


class TestClassHierarchy(unittest.TestCase):
    def test_unresolved_class_properties_and_normalization(self) -> None:
        unresolved1 = UnresolvedClass.from_name_or_descriptor("android.app.Activity")
        self.assertFalse(unresolved1.is_resolved)
        self.assertEqual(unresolved1.descriptor, "Landroid/app/Activity;")
        self.assertEqual(unresolved1.name, "android.app.Activity")
        self.assertEqual(unresolved1.package, "android.app")
        self.assertEqual(unresolved1.simple_name, "Activity")
        self.assertEqual(str(unresolved1), "android.app.Activity")
        self.assertEqual(repr(unresolved1), "<UnresolvedClass 'android.app.Activity'>")

        unresolved2 = UnresolvedClass("Landroid/app/Activity;")
        self.assertEqual(unresolved1, unresolved2)
        self.assertEqual(hash(unresolved1), hash(unresolved2))

        unresolved3 = UnresolvedClass.from_name_or_descriptor("Landroid/app/Activity;")
        self.assertEqual(unresolved1, unresolved3)

        unresolved_arr = UnresolvedClass("[Landroid/app/Activity;")
        self.assertEqual(unresolved_arr.descriptor, "[Landroid/app/Activity;")
        self.assertEqual(unresolved_arr.name, "android.app.Activity[]")

        unresolved_arr2 = UnresolvedClass.from_name_or_descriptor("[Landroid/app/Activity;")
        self.assertEqual(unresolved_arr, unresolved_arr2)

        default_pkg = UnresolvedClass.from_name_or_descriptor("GlobalClass")
        self.assertEqual(default_pkg.descriptor, "LGlobalClass;")
        self.assertEqual(default_pkg.package, "")
        self.assertEqual(default_pkg.simple_name, "GlobalClass")

    def test_resolved_class_properties_and_flags(self) -> None:
        dex_bytes = build_dex_bytes(
            [
                {
                    "name": "Lcom/example/Foo;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": int(
                        AccessFlags.PUBLIC
                        | AccessFlags.FINAL
                        | AccessFlags.SYNTHETIC
                        | AccessFlags.ENUM
                    ),
                    "source_file": "Foo.java",
                }
            ]
        )
        dex = DexFile(dex_bytes)
        loader = ClassLoader([dex])

        cls = loader.load_class("com.example.Foo")
        self.assertIsNotNone(cls)
        assert cls is not None
        self.assertTrue(cls.is_resolved)
        self.assertEqual(cls.descriptor, "Lcom/example/Foo;")
        self.assertEqual(cls.name, "com.example.Foo")
        self.assertEqual(cls.package, "com.example")
        self.assertEqual(cls.simple_name, "Foo")
        self.assertEqual(cls.loader, loader)
        self.assertEqual(cls.dex_file, dex)
        self.assertEqual(cls.source_file, "Foo.java")
        self.assertTrue(cls.is_public)
        self.assertTrue(cls.is_final)
        self.assertFalse(cls.is_interface)
        self.assertFalse(cls.is_abstract)
        self.assertTrue(cls.is_synthetic)
        self.assertFalse(cls.is_annotation)
        self.assertTrue(cls.is_enum)
        self.assertEqual(str(cls), "com.example.Foo")
        self.assertEqual(repr(cls), "<Class 'com.example.Foo'>")

    def test_resolved_class_superclass_and_interfaces(self) -> None:
        dex_bytes = build_dex_bytes(
            [
                {
                    "name": "Lcom/example/Child;",
                    "super": "Lcom/example/Parent;",
                    "interfaces": ["Lcom/example/Iface;", "Landroid/view/View;"],
                    "access_flags": int(AccessFlags.PUBLIC),
                },
                {
                    "name": "Lcom/example/Parent;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": int(AccessFlags.PUBLIC),
                },
                {
                    "name": "Lcom/example/Iface;",
                    "super": None,
                    "access_flags": int(AccessFlags.PUBLIC | AccessFlags.INTERFACE),
                },
            ]
        )
        dex = DexFile(dex_bytes)
        loader = ClassLoader([dex])

        child = loader["com.example.Child"]
        parent = child.super_class
        self.assertIsInstance(parent, ResolvedClass)
        assert parent is not None
        self.assertEqual(parent.name, "com.example.Parent")

        # Parent's superclass is java.lang.Object which is external to loader
        obj_super = parent.super_class
        self.assertIsInstance(obj_super, UnresolvedClass)
        assert obj_super is not None
        self.assertEqual(obj_super.name, "java.lang.Object")

        ifaces = child.interfaces
        self.assertEqual(len(ifaces), 2)
        self.assertIsInstance(ifaces[0], ResolvedClass)
        self.assertEqual(ifaces[0].name, "com.example.Iface")
        self.assertIsInstance(ifaces[1], UnresolvedClass)
        self.assertEqual(ifaces[1].name, "android.view.View")

    def test_java_lang_object_superclass_none(self) -> None:
        dex_bytes = build_dex_bytes(
            [
                {
                    "name": "Ljava/lang/Object;",
                    "super": None,
                    "access_flags": int(AccessFlags.PUBLIC),
                }
            ]
        )
        loader = ClassLoader([DexFile(dex_bytes)])
        obj_cls = loader["java.lang.Object"]
        self.assertIsNone(obj_cls.super_class)

    def test_equality_and_hashing(self) -> None:
        dex_bytes = build_dex_bytes(
            [{"name": "Lcom/example/Foo;", "super": "Ljava/lang/Object;", "access_flags": 1}]
        )
        loader = ClassLoader([DexFile(dex_bytes)])
        cls1 = loader["com.example.Foo"]
        cls2 = loader["com.example.Foo"]
        unresolved = UnresolvedClass.from_name_or_descriptor("com.example.Foo")

        self.assertEqual(cls1, cls2)
        self.assertEqual(hash(cls1), hash(cls2))
        self.assertNotEqual(cls1, unresolved)
        self.assertNotEqual(cls1, "com.example.Foo")


class TestClassLoader(unittest.TestCase):
    def test_element_type_validation(self) -> None:
        with self.assertRaises(TypeError):
            ClassLoader(["invalid_path_str"])  # type: ignore[arg-type]

        dex = DexFile(
            build_dex_bytes(
                [{"name": "Lcom/example/Foo;", "super": "Ljava/lang/Object;", "access_flags": 1}]
            )
        )
        loader = ClassLoader([dex])
        self.assertFalse(hasattr(loader, "dex_files"))

    def test_resolution_order_parent_first_self_first_interleaved(self) -> None:
        parent_dex = DexFile(
            build_dex_bytes(
                [
                    {
                        "name": "Lcom/example/Foo;",
                        "super": "Ljava/lang/Object;",
                        "access_flags": 1,
                        "source_file": "ParentFoo.java",
                    }
                ]
            )
        )
        child_dex = DexFile(
            build_dex_bytes(
                [
                    {
                        "name": "Lcom/example/Foo;",
                        "super": "Ljava/lang/Object;",
                        "access_flags": 1,
                        "source_file": "ChildFoo.java",
                    }
                ]
            )
        )

        parent_loader = ClassLoader([parent_dex])

        # Parent-first loader
        parent_first = ClassLoader([parent_loader, child_dex])
        foo_pf = parent_first["com.example.Foo"]
        self.assertEqual(foo_pf.source_file, "ParentFoo.java")

        # Self-first loader
        self_first = ClassLoader([child_dex, parent_loader])
        foo_sf = self_first["com.example.Foo"]
        self.assertEqual(foo_sf.source_file, "ChildFoo.java")

        # Interleaved loader
        interleaved = ClassLoader([parent_dex, parent_loader, child_dex])
        foo_il = interleaved["com.example.Foo"]
        self.assertEqual(foo_il.source_file, "ParentFoo.java")

    def test_resolution_caching(self) -> None:
        dex = DexFile(
            build_dex_bytes(
                [{"name": "Lcom/example/Foo;", "super": "Ljava/lang/Object;", "access_flags": 1}]
            )
        )
        loader = ClassLoader([dex])

        cls1 = loader.load_class("com.example.Foo")
        cls2 = loader.load_class("Lcom/example/Foo;")
        self.assertIs(cls1, cls2)

        missing1 = loader.load_class("com.example.Missing")
        self.assertIsNone(missing1)

        missing2 = loader.load_class("com.example.Missing")
        self.assertIsNone(missing2)

    def test_find_all_shadow_classes(self) -> None:
        dex1 = DexFile(
            build_dex_bytes(
                [
                    {
                        "name": "Lcom/example/Foo;",
                        "super": "Ljava/lang/Object;",
                        "access_flags": 1,
                        "source_file": "Foo1.java",
                    }
                ]
            )
        )
        dex2 = DexFile(
            build_dex_bytes(
                [
                    {
                        "name": "Lcom/example/Foo;",
                        "super": "Ljava/lang/Object;",
                        "access_flags": 1,
                        "source_file": "Foo2.java",
                    }
                ]
            )
        )

        loader = ClassLoader([dex1, dex2])
        all_foos = loader.find_all("com.example.Foo")
        self.assertEqual(len(all_foos), 2)
        self.assertEqual(all_foos[0].source_file, "Foo1.java")
        self.assertEqual(all_foos[1].source_file, "Foo2.java")

        iter_classes = list(loader)
        self.assertEqual(len(iter_classes), 2)
        self.assertEqual(len(loader), 2)
        self.assertEqual(iter_classes[0].source_file, "Foo1.java")
        self.assertEqual(iter_classes[1].source_file, "Foo2.java")

    def test_find_glob_pattern(self) -> None:
        dex = DexFile(
            build_dex_bytes(
                [
                    {
                        "name": "Lcom/example/MainActivity;",
                        "super": "Ljava/lang/Object;",
                        "access_flags": 1,
                    },
                    {
                        "name": "Lcom/example/DetailActivity;",
                        "super": "Ljava/lang/Object;",
                        "access_flags": 1,
                    },
                    {
                        "name": "Lcom/example/util/Helper;",
                        "super": "Ljava/lang/Object;",
                        "access_flags": 1,
                    },
                ]
            )
        )
        loader = ClassLoader([dex])

        activities = loader.find("*.Activity")
        # Simple name ends with Activity, but full name is com.example.*Activity
        self.assertEqual(len(activities), 0)

        activities_wildcard = loader.find("*Activity")
        self.assertEqual(len(activities_wildcard), 2)
        names = {a.name for a in activities_wildcard}
        self.assertEqual(names, {"com.example.MainActivity", "com.example.DetailActivity"})

    def test_mapping_semantics(self) -> None:
        dex = DexFile(
            build_dex_bytes(
                [
                    {"name": "Lcom/example/A;", "super": "Ljava/lang/Object;", "access_flags": 1},
                    {"name": "Lcom/example/B;", "super": "Ljava/lang/Object;", "access_flags": 1},
                ]
            )
        )
        loader = ClassLoader([dex])

        # __getitem__
        cls_a = loader["com.example.A"]
        self.assertEqual(cls_a.name, "com.example.A")
        with self.assertRaises(KeyError):
            _ = loader["com.example.C"]

        # get
        self.assertEqual(loader.get("com.example.A"), cls_a)
        self.assertIsNone(loader.get("com.example.C"))

        # __contains__
        self.assertIn("com.example.A", loader)
        self.assertIn("Lcom/example/A;", loader)
        self.assertIn(cls_a, loader)
        self.assertNotIn("com.example.C", loader)
        self.assertNotIn(123, loader)

        # __iter__ and __len__
        all_classes = list(loader)
        self.assertEqual(len(all_classes), 2)
        self.assertEqual(len(loader), 2)

    def test_context_manager_and_close(self) -> None:
        dex = DexFile(
            build_dex_bytes(
                [{"name": "Lcom/example/Foo;", "super": "Ljava/lang/Object;", "access_flags": 1}]
            )
        )
        res_mock = io.BytesIO(b"data")

        with ClassLoader([dex]) as loader:
            loader._resources.append(res_mock)
            self.assertFalse(res_mock.closed)

        self.assertTrue(res_mock.closed)


class TestMultiDexAndContainers(unittest.TestCase):
    def test_multidex_apk_class_resolution(self) -> None:
        dex1 = build_dex_bytes(
            [{"name": "Lcom/example/Base;", "super": "Ljava/lang/Object;", "access_flags": 1}]
        )
        dex2 = build_dex_bytes(
            [
                {
                    "name": "Lcom/example/Derived;",
                    "super": "Lcom/example/Base;",
                    "access_flags": 1,
                }
            ]
        )

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
            zf.writestr("classes.dex", dex1)
            zf.writestr("classes2.dex", dex2)

        zip_archive = ZipArchive(buf.getvalue())
        loader = ClassLoader([zip_archive])

        derived = loader["com.example.Derived"]
        base = derived.super_class

        self.assertIsInstance(base, ResolvedClass)
        assert base is not None
        self.assertEqual(base.name, "com.example.Base")

    def test_vdex_container_class_resolution(self) -> None:
        dex1 = build_dex_bytes(
            [{"name": "Lcom/example/VdexClass;", "super": "Ljava/lang/Object;", "access_flags": 1}]
        )
        vdex_bytes = build_vdex_bytes([dex1])
        vdex = VdexFile(vdex_bytes)

        loader = ClassLoader([vdex])
        cls = loader["com.example.VdexClass"]
        self.assertEqual(cls.name, "com.example.VdexClass")


class TestTopLevelEntryPoints(unittest.TestCase):
    def test_load_entry_point_format_detection(self) -> None:
        dex_bytes = build_dex_bytes(
            [{"name": "Lcom/example/Foo;", "super": "Ljava/lang/Object;", "access_flags": 1}]
        )
        loader_dex = load(dex_bytes)
        self.assertIn("com.example.Foo", loader_dex)

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
            zf.writestr("classes.dex", dex_bytes)
        loader_zip = load(buf.getvalue())
        self.assertIn("com.example.Foo", loader_zip)

        vdex_bytes = build_vdex_bytes([dex_bytes])
        loader_vdex = load(vdex_bytes)
        self.assertIn("com.example.Foo", loader_vdex)

        with self.assertRaises(ValueError):
            load(b"INVALID_HEADER")

    def test_open_entry_point_mmap_and_read(self) -> None:
        dex_bytes = build_dex_bytes(
            [{"name": "Lcom/example/Foo;", "super": "Ljava/lang/Object;", "access_flags": 1}]
        )

        with tempfile.NamedTemporaryFile(suffix=".dex", delete=False) as f:
            f.write(dex_bytes)
            f.flush()
            temp_path = f.name

        try:
            # mmap=True
            with open(temp_path, mmap=True) as loader_mmap:
                self.assertIn("com.example.Foo", loader_mmap)

            # mmap=False
            with open(temp_path, mmap=False) as loader_read:
                self.assertIn("com.example.Foo", loader_read)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)


class TestAdaptersAndCustomElements(unittest.TestCase):
    def test_adapters_protocol_conformance(self) -> None:
        dex_bytes = build_dex_bytes(
            [{"name": "Lcom/example/Foo;", "super": "Ljava/lang/Object;", "access_flags": 1}]
        )
        dex = DexFile(dex_bytes)
        loader = ClassLoader([dex])

        vdex_bytes = build_vdex_bytes([dex_bytes])
        vdex = VdexFile(vdex_bytes)

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
            zf.writestr("classes.dex", dex_bytes)
        zip_archive = ZipArchive(buf.getvalue())

        dex_adapter = DexAdapter(dex, loader)
        vdex_adapter = VdexAdapter(vdex, loader)
        zip_adapter = ZipAdapter(zip_archive, loader)

        self.assertIsInstance(dex_adapter, ClassLoaderElement)
        self.assertIsInstance(vdex_adapter, ClassLoaderElement)
        self.assertIsInstance(zip_adapter, ClassLoaderElement)
        self.assertIsInstance(loader, ClassLoaderElement)

    def test_direct_adapter_queries(self) -> None:
        dex_bytes = build_dex_bytes(
            [{"name": "Lcom/example/Foo;", "super": "Ljava/lang/Object;", "access_flags": 1}]
        )
        dex = DexFile(dex_bytes)
        loader = ClassLoader([dex])

        vdex_bytes = build_vdex_bytes([dex_bytes])
        vdex = VdexFile(vdex_bytes)

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
            zf.writestr("classes.dex", dex_bytes)
        zip_archive = ZipArchive(buf.getvalue())

        # DexAdapter
        dex_adapter = DexAdapter(dex, loader)
        self.assertIs(dex_adapter.dex_file, dex)
        cls_dex = dex_adapter.load_class("Lcom/example/Foo;")
        self.assertIsNotNone(cls_dex)
        self.assertEqual(len(dex_adapter.find_all("Lcom/example/Foo;")), 1)
        self.assertEqual(len(list(dex_adapter)), 1)
        self.assertEqual(len(dex_adapter), 1)

        # VdexAdapter
        vdex_adapter = VdexAdapter(vdex, loader)
        self.assertIs(vdex_adapter.vdex_file, vdex)
        cls_vdex = vdex_adapter.load_class("Lcom/example/Foo;")
        self.assertIsNotNone(cls_vdex)
        self.assertEqual(len(vdex_adapter.find_all("Lcom/example/Foo;")), 1)
        self.assertEqual(len(list(vdex_adapter)), 1)
        self.assertEqual(len(vdex_adapter), 1)

        # ZipAdapter
        zip_adapter = ZipAdapter(zip_archive, loader)
        self.assertIs(zip_adapter.archive, zip_archive)
        cls_zip = zip_adapter.load_class("Lcom/example/Foo;")
        self.assertIsNotNone(cls_zip)
        self.assertEqual(len(zip_adapter.find_all("Lcom/example/Foo;")), 1)
        self.assertEqual(len(list(zip_adapter)), 1)
        self.assertEqual(len(zip_adapter), 1)

    def test_custom_user_element(self) -> None:
        dex_bytes = build_dex_bytes(
            [{"name": "Lcom/example/Custom;", "super": "Ljava/lang/Object;", "access_flags": 1}]
        )
        dex = DexFile(dex_bytes)

        class CustomElement:
            __slots__ = ("_dex",)

            def __init__(self, dex_file: DexFile) -> None:
                self._dex = dex_file

            def load_class(self, descriptor: str) -> ResolvedClass | None:
                cdef = self._dex.find_class_def(descriptor)
                if cdef is not None:
                    # Construct dummy ResolvedClass with dummy loader
                    return ResolvedClass(ClassLoader([]), self._dex, cdef)
                return None

            def find_all(self, descriptor: str) -> Sequence[ResolvedClass]:
                cls = self.load_class(descriptor)
                return [cls] if cls is not None else []

            def __iter__(self) -> Iterator[ResolvedClass]:
                for cdef in self._dex.class_defs:
                    yield ResolvedClass(ClassLoader([]), self._dex, cdef)

            def __len__(self) -> int:
                return len(self._dex.class_defs)

        custom_elem = CustomElement(dex)
        self.assertIsInstance(custom_elem, ClassLoaderElement)

        loader = ClassLoader([custom_elem])
        cls = loader.load_class("com.example.Custom")
        self.assertIsNotNone(cls)
        assert cls is not None
        self.assertEqual(cls.name, "com.example.Custom")
        self.assertEqual(len(loader.find_all("com.example.Custom")), 1)
        self.assertIn("com.example.Custom", loader)


if __name__ == "__main__":
    unittest.main()
