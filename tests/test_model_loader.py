"""Tests for ClassLoader creation, multi-DEX lookup, and container adapters."""

import io
import os
import tempfile
import unittest
import zipfile
from collections.abc import Iterator, Sequence

from dexbuf import (
    ClassLoader,
    ClassLoaderElement,
    DexAdapter,
    DexFile,
    ResolvedClass,
    VdexAdapter,
    VdexFile,
    ZipAdapter,
    ZipArchive,
    load,
    open,
)
from tests.builders import (
    build_dex_bytes,
    build_vdex_bytes,
)


class TestClassLoader(unittest.TestCase):
    def test_element_type_validation(self) -> None:
        with self.assertRaises(TypeError):
            ClassLoader(["invalid_path_str"])  # type: ignore[arg-type]

        dex = DexFile(
            build_dex_bytes(
                [{"name": "Lcom/example/Foo;", "super": "Ljava/lang/Object;", "access_flags": 1}]
            )
        )
        vdex_bytes = build_vdex_bytes([build_dex_bytes([])])
        vdex = VdexFile(vdex_bytes)

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
            zf.writestr("classes.dex", build_dex_bytes([]))
        zip_archive = ZipArchive(buf.getvalue())

        # ClassLoader.__init__ strictly rejects raw unadapted containers
        with self.assertRaises(TypeError):
            ClassLoader([dex])  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            ClassLoader([vdex])  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            ClassLoader([zip_archive])  # type: ignore[arg-type]

        # ClassLoader.from_elements wraps raw containers into adapters
        loader = ClassLoader.from_elements([dex])
        self.assertEqual(len(loader.elements), 1)
        self.assertIsInstance(loader.elements[0], DexAdapter)

        # Direct ClassLoader instantiation with ClassLoaderElement
        adapter = DexAdapter(dex, loader)
        strict_loader = ClassLoader([adapter])
        self.assertEqual(strict_loader.elements, (adapter,))

        # Nested ClassLoader as element
        nested_loader = ClassLoader([strict_loader])
        self.assertEqual(nested_loader.elements, (strict_loader,))

        # from_elements rejects invalid types
        with self.assertRaises(TypeError):
            ClassLoader.from_elements(["invalid_path_str"])  # type: ignore[arg-type]

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

        parent_loader = ClassLoader.from_elements([parent_dex])

        # Parent-first loader
        parent_first = ClassLoader.from_elements([parent_loader, child_dex])
        foo_pf = parent_first["com.example.Foo"]
        self.assertEqual(foo_pf.source_file, "ParentFoo.java")

        # Self-first loader
        self_first = ClassLoader.from_elements([child_dex, parent_loader])
        foo_sf = self_first["com.example.Foo"]
        self.assertEqual(foo_sf.source_file, "ChildFoo.java")

        # Interleaved loader
        interleaved = ClassLoader.from_elements([parent_dex, parent_loader, child_dex])
        foo_il = interleaved["com.example.Foo"]
        self.assertEqual(foo_il.source_file, "ParentFoo.java")

    def test_resolution_caching(self) -> None:
        dex = DexFile(
            build_dex_bytes(
                [{"name": "Lcom/example/Foo;", "super": "Ljava/lang/Object;", "access_flags": 1}]
            )
        )
        loader = ClassLoader.from_elements([dex])

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

        loader = ClassLoader.from_elements([dex1, dex2])
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
        loader = ClassLoader.from_elements([dex])

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
        loader = ClassLoader.from_elements([dex])

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

        with ClassLoader.from_elements([dex]) as loader:
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
        loader = ClassLoader.from_elements([zip_archive])

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

        loader = ClassLoader.from_elements([vdex])
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
        loader = ClassLoader.from_elements([dex])

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
        loader = ClassLoader.from_elements([dex])

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
                    return ResolvedClass(ClassLoader(), self._dex, cdef)
                return None

            def find_all(self, descriptor: str) -> Sequence[ResolvedClass]:
                cls = self.load_class(descriptor)
                return [cls] if cls is not None else []

            def __iter__(self) -> Iterator[ResolvedClass]:
                for cdef in self._dex.class_defs:
                    yield ResolvedClass(ClassLoader(), self._dex, cdef)

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
