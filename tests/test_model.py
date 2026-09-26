"""Unit tests for DexCollection, ClassCollection, Class, and UnresolvedClass domain models."""

import hashlib
import io
import tempfile
import unittest
import zipfile
import zlib
from typing import Any

import dexbuf
from dexbuf import (
    DEX_FILE_MAGIC,
    ENDIAN_CONSTANT,
    NO_INDEX,
    NO_OFFSET,
    AccessFlags,
    Class,
    ClassDefItem,
    Count,
    FieldIdItem,
    HeaderItem,
    Idx,
    ItemType,
    MapItem,
    MapList,
    MethodIdItem,
    Offset,
    ProtoIdItem,
    StringDataItem,
    StringIdItem,
    TypeIdItem,
    TypeList,
    UnresolvedClass,
)


def create_test_zip(entries: list[tuple[str, bytes, int]], comment: bytes = b"") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.comment = comment
        for filename, data, compress_type in entries:
            zf.writestr(filename, data, compress_type=compress_type)
    return buf.getvalue()


def create_dex_file_bytes(classes_info: list[dict[str, Any]]) -> bytes:
    """Helper to generate valid DEX file bytes from a list of class specification dicts.

    Each dict in classes_info can contain:
        - "descriptor": str (e.g. "Lcom/example/Child;")
        - "access_flags": int (default 0x0001)
        - "superclass": str | None (e.g. "Lcom/example/Parent;", "Ljava/lang/Object;", or None)
        - "interfaces": list[str] (e.g. ["Lcom/example/IFace;"])
        - "source_file": str | None (e.g. "Child.java")
    """
    header_size = 0x70

    # Collect all strings
    string_set: set[str] = set()
    for c in classes_info:
        string_set.add(c["descriptor"])
        if c.get("superclass"):
            string_set.add(c["superclass"])
        for iface in c.get("interfaces", []):
            string_set.add(iface)
        if c.get("source_file"):
            string_set.add(c["source_file"])

    sorted_strings = sorted(string_set)
    string_to_idx = {s: i for i, s in enumerate(sorted_strings)}

    # Collect and sort type IDs by descriptor string_idx
    type_descriptors = sorted(
        {c["descriptor"] for c in classes_info}
        | {c["superclass"] for c in classes_info if c.get("superclass")}
        | {iface for c in classes_info for iface in c.get("interfaces", [])}
    )
    # Sort type descriptors by string index
    type_descriptors.sort(key=lambda d: string_to_idx[d])
    type_to_idx = {d: i for i, d in enumerate(type_descriptors)}

    type_ids = [
        TypeIdItem(descriptor_idx=Idx[StringIdItem](string_to_idx[d])) for d in type_descriptors
    ]
    type_ids_bytes = b"".join(t.to_bytes() for t in type_ids)

    # Serialize StringDataItems and TypeLists
    string_data_bytes = bytearray()
    string_data_offsets: list[int] = []

    string_ids_off = header_size
    string_ids_bytes_len = 4 * len(sorted_strings)
    type_ids_off = string_ids_off + string_ids_bytes_len
    class_defs_off = type_ids_off + len(type_ids_bytes)
    data_start_off = class_defs_off + 32 * len(classes_info)

    curr_data_off = data_start_off

    # String data items
    for s in sorted_strings:
        item = StringDataItem.from_str(s)
        string_data_offsets.append(curr_data_off)
        b = item.to_bytes()
        string_data_bytes.extend(b)
        curr_data_off += len(b)

    # Type lists for interfaces
    type_list_bytes = bytearray()
    class_interfaces_off: list[int] = []
    for c in classes_info:
        ifaces = c.get("interfaces", [])
        if ifaces:
            t_items = tuple(
                TypeList.Item(type_idx=Idx[TypeIdItem](type_to_idx[iface])) for iface in ifaces
            )
            t_list = TypeList(list=t_items)
            class_interfaces_off.append(curr_data_off)
            b = t_list.to_bytes()
            type_list_bytes.extend(b)
            curr_data_off += len(b)
        else:
            class_interfaces_off.append(NO_OFFSET)

    # String IDs table
    string_ids_bytes = b"".join(
        StringIdItem(string_data_off=Offset[StringDataItem](off)).to_bytes()
        for off in string_data_offsets
    )

    # Class Defs
    class_defs: list[ClassDefItem] = []
    for i, c in enumerate(classes_info):
        class_idx = Idx[TypeIdItem](type_to_idx[c["descriptor"]])
        super_desc = c.get("superclass")
        if super_desc is not None:
            super_idx = Idx[TypeIdItem](type_to_idx[super_desc])
        else:
            super_idx = NO_INDEX

        ifaces_off = Offset[TypeList](class_interfaces_off[i])

        src = c.get("source_file")
        if src is not None:
            src_idx = Idx[StringIdItem](string_to_idx[src])
        else:
            src_idx = NO_INDEX

        class_defs.append(
            ClassDefItem(
                class_idx=class_idx,
                access_flags=c.get("access_flags", 0x0001),
                superclass_idx=super_idx,
                interfaces_off=ifaces_off,
                source_file_idx=src_idx,
                annotations_off=NO_OFFSET,
                class_data_off=NO_OFFSET,
                static_values_off=NO_OFFSET,
            )
        )

    class_defs_bytes = b"".join(cd.to_bytes() for cd in class_defs)

    # Map list
    map_items = [
        MapItem(item_type=ItemType.HEADER_ITEM, size=1, offset=Offset[Any](0)),
        MapItem(
            item_type=ItemType.STRING_ID_ITEM,
            size=len(sorted_strings),
            offset=Offset[Any](string_ids_off),
        ),
        MapItem(
            item_type=ItemType.TYPE_ID_ITEM, size=len(type_ids), offset=Offset[Any](type_ids_off)
        ),
        MapItem(
            item_type=ItemType.CLASS_DEF_ITEM,
            size=len(class_defs),
            offset=Offset[Any](class_defs_off),
        ),
        MapItem(item_type=ItemType.MAP_LIST, size=1, offset=Offset[Any](curr_data_off)),
    ]
    map_list = MapList(list=tuple(map_items))
    map_list_bytes = map_list.to_bytes()

    total_file_size = curr_data_off + len(map_list_bytes)

    header = HeaderItem(
        magic=DEX_FILE_MAGIC,
        checksum=0,
        signature=b"\x00" * 20,
        file_size=total_file_size,
        header_size=header_size,
        endian_tag=ENDIAN_CONSTANT,
        link_size=0,
        link_off=NO_OFFSET,
        map_off=Offset[MapList](curr_data_off),
        string_ids_size=Count[StringIdItem](len(sorted_strings)),
        string_ids_off=Offset[StringIdItem](string_ids_off),
        type_ids_size=Count[TypeIdItem](len(type_ids)),
        type_ids_off=Offset[TypeIdItem](type_ids_off),
        proto_ids_size=Count[ProtoIdItem](0),
        proto_ids_off=NO_OFFSET,
        field_ids_size=Count[FieldIdItem](0),
        field_ids_off=NO_OFFSET,
        method_ids_size=Count[MethodIdItem](0),
        method_ids_off=NO_OFFSET,
        class_defs_size=Count[ClassDefItem](len(class_defs)),
        class_defs_off=Offset[ClassDefItem](class_defs_off),
        data_size=total_file_size - data_start_off,
        data_off=Offset[Any](data_start_off),
    )

    buf = bytearray(header.to_bytes())
    buf.extend(string_ids_bytes)
    buf.extend(type_ids_bytes)
    buf.extend(class_defs_bytes)
    buf.extend(string_data_bytes)
    buf.extend(type_list_bytes)
    buf.extend(map_list_bytes)

    # Sign and checksum
    sig = hashlib.sha1(buf[32:]).digest()
    buf[12:32] = sig
    chk = zlib.adler32(buf[12:]) & 0xFFFF_FFFF
    buf[8:12] = chk.to_bytes(4, "little")

    return bytes(buf)


def create_vdex_file_bytes(dex_buffers: list[bytes]) -> bytes:
    """Helper to generate a v027 VDEX container file from a list of DEX buffers."""
    hdr_size = 12
    sec_count = 2
    sec_table_size = sec_count * 12

    # Calculate DEX section payload
    dex_payload = bytearray()
    for db in dex_buffers:
        dex_payload.extend(db)
        # Pad to 4 bytes
        rem = len(db) % 4
        if rem != 0:
            dex_payload.extend(b"\x00" * (4 - rem))

    # Section 0: CHECKSUM
    checksum_data = bytearray()
    for db in dex_buffers:
        chk = zlib.adler32(db[12:]) & 0xFFFF_FFFF
        checksum_data.extend(chk.to_bytes(4, "little"))

    checksum_off = hdr_size + sec_table_size
    checksum_size = len(checksum_data)

    dex_off = checksum_off + checksum_size
    dex_size = len(dex_payload)

    # VdexHeader: magic(4s), version(4s), number_of_sections(I)
    header_bytes = b"vdex027\x00" + (2).to_bytes(4, "little")

    # VdexSectionHeader: kind(I), offset(I), size(I)
    sec_checksum = (
        (0).to_bytes(4, "little")
        + checksum_off.to_bytes(4, "little")
        + checksum_size.to_bytes(4, "little")
    )
    sec_dex = (
        (1).to_bytes(4, "little") + dex_off.to_bytes(4, "little") + dex_size.to_bytes(4, "little")
    )

    return header_bytes + sec_checksum + sec_dex + checksum_data + dex_payload


class TestModel(unittest.TestCase):
    def setUp(self) -> None:
        self.dex1_bytes = create_dex_file_bytes(
            [
                {
                    "descriptor": "Lcom/example/ParentActivity;",
                    "access_flags": AccessFlags.PUBLIC | AccessFlags.ABSTRACT,
                    "superclass": "Landroid/app/Activity;",
                    "interfaces": ["Lcom/example/IInterface;"],
                    "source_file": "ParentActivity.java",
                },
                {
                    "descriptor": "Lcom/example/IInterface;",
                    "access_flags": AccessFlags.PUBLIC
                    | AccessFlags.INTERFACE
                    | AccessFlags.ABSTRACT,
                    "superclass": "Ljava/lang/Object;",
                    "interfaces": [],
                    "source_file": "IInterface.java",
                },
                {
                    "descriptor": "Ljava/lang/Object;",
                    "access_flags": AccessFlags.PUBLIC,
                    "superclass": None,
                    "interfaces": [],
                    "source_file": None,
                },
            ]
        )

        self.dex2_bytes = create_dex_file_bytes(
            [
                {
                    "descriptor": "Lcom/example/MainActivity;",
                    "access_flags": AccessFlags.PUBLIC | AccessFlags.FINAL,
                    "superclass": "Lcom/example/ParentActivity;",
                    "interfaces": ["Lcom/example/IInterface;"],
                    "source_file": "MainActivity.java",
                },
            ]
        )

    def test_single_dex_load_and_open(self) -> None:
        """Verify DexCollection loaded from single DEX buffer or file."""
        collection = dexbuf.load(self.dex1_bytes)
        self.assertEqual(len(collection.dex_files), 1)
        self.assertEqual(len(collection.classes), 3)

        cls_obj = collection.get_class("com.example.ParentActivity")
        self.assertIsNotNone(cls_obj)
        self.assertEqual(cls_obj.name, "com.example.ParentActivity")  # type: ignore[union-attr]

        with tempfile.NamedTemporaryFile("wb", suffix=".dex", delete=False) as tmp:
            tmp.write(self.dex1_bytes)
            tmp_path = tmp.name

        try:
            with dexbuf.open(tmp_path, mmap=True) as col_mmap:
                self.assertEqual(len(col_mmap.classes), 3)
                self.assertIsNotNone(col_mmap.get_class("Lcom/example/ParentActivity;"))

            with dexbuf.open(tmp_path, mmap=False) as col_buf:
                self.assertEqual(len(col_buf.classes), 3)
        finally:
            import os

            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_multidex_apk_load(self) -> None:
        """Verify DexCollection loaded from MultiDEX APK archive."""
        zip_bytes = create_test_zip(
            [
                ("classes.dex", self.dex1_bytes, 0),
                ("classes2.dex", self.dex2_bytes, 0),
                ("unrelated.txt", b"foo", 0),
            ]
        )

        collection = dexbuf.load(zip_bytes)
        self.assertEqual(len(collection.dex_files), 2)
        self.assertEqual(len(collection.classes), 4)

        # Canonical sorting order: classes.dex first, classes2.dex second
        cls1 = collection.classes[0]
        cls_last = collection.classes[-1]
        self.assertEqual(cls1.dex_file, collection.dex_files[0])
        self.assertEqual(cls_last.dex_file, collection.dex_files[1])

    def test_vdex_container_load(self) -> None:
        """Verify DexCollection loaded from VDEX container file."""
        vdex_bytes = create_vdex_file_bytes([self.dex1_bytes, self.dex2_bytes])
        collection = dexbuf.load(vdex_bytes)
        self.assertEqual(len(collection.dex_files), 2)
        self.assertEqual(len(collection.classes), 4)

    def test_dual_lookup_in_class_collection(self) -> None:
        """Verify ClassCollection lookup by canonical Java name and Dalvik descriptor."""
        zip_bytes = create_test_zip(
            [
                ("classes.dex", self.dex1_bytes, 0),
                ("classes2.dex", self.dex2_bytes, 0),
            ]
        )
        collection = dexbuf.load(zip_bytes)

        # Lookup by canonical Java name
        cls_by_name = collection.classes["com.example.MainActivity"]
        self.assertIsInstance(cls_by_name, Class)
        self.assertEqual(cls_by_name.name, "com.example.MainActivity")

        # Lookup by Dalvik descriptor
        cls_by_desc = collection.classes["Lcom/example/MainActivity;"]
        self.assertEqual(cls_by_desc, cls_by_name)

        # Safe get()
        self.assertEqual(collection.classes.get("com.example.MainActivity"), cls_by_name)
        self.assertEqual(collection.classes.get("Lcom/example/MainActivity;"), cls_by_name)
        self.assertIsNone(collection.classes.get("non.existent.Class"))
        self.assertEqual(collection.classes.get("non.existent.Class", "default"), "default")

        # KeyError on missing
        with self.assertRaises(KeyError):
            _ = collection.classes["non.existent.Class"]

    def test_cross_dex_superclass_and_interface_resolution(self) -> None:
        """Verify cross-DEX superclass and interface resolution across DEX files."""
        zip_bytes = create_test_zip(
            [
                ("classes.dex", self.dex1_bytes, 0),
                ("classes2.dex", self.dex2_bytes, 0),
            ]
        )
        collection = dexbuf.load(zip_bytes)

        # MainActivity in classes2.dex extends ParentActivity in classes.dex
        main_activity = collection.classes["com.example.MainActivity"]
        parent_activity = main_activity.super_class

        self.assertIsInstance(parent_activity, Class)
        self.assertEqual(parent_activity.name, "com.example.ParentActivity")  # type: ignore[union-attr]
        self.assertTrue(parent_activity.is_resolved)  # type: ignore[union-attr]

        # Interfaces resolution
        ifaces = main_activity.interfaces
        self.assertEqual(len(ifaces), 1)
        self.assertIsInstance(ifaces[0], Class)
        self.assertEqual(ifaces[0].name, "com.example.IInterface")

    def test_unresolved_class_and_object_superclass(self) -> None:
        """Verify UnresolvedClass returned for missing types and None for Object superclass."""
        collection = dexbuf.load(self.dex1_bytes)

        # ParentActivity extends android.app.Activity (external framework class)
        parent_activity = collection.classes["com.example.ParentActivity"]
        super_cls = parent_activity.super_class

        self.assertIsInstance(super_cls, UnresolvedClass)
        self.assertEqual(super_cls.name, "android.app.Activity")  # type: ignore[union-attr]
        self.assertEqual(super_cls.descriptor, "Landroid/app/Activity;")  # type: ignore[union-attr]
        self.assertEqual(super_cls.package, "android.app")  # type: ignore[union-attr]
        self.assertEqual(super_cls.simple_name, "Activity")  # type: ignore[union-attr]
        self.assertFalse(super_cls.is_resolved)  # type: ignore[union-attr]
        self.assertEqual(repr(super_cls), "<UnresolvedClass 'android.app.Activity'>")

        # java.lang.Object has superclass_idx == None or superclass is None -> returns None
        obj_cls = collection.classes["java.lang.Object"]
        self.assertIsNone(obj_cls.super_class)

    def test_class_properties_and_access_flags(self) -> None:
        """Verify properties and AccessFlags boolean properties on Class."""
        collection = dexbuf.load(self.dex1_bytes)

        cls_obj = collection.classes["com.example.ParentActivity"]
        self.assertEqual(cls_obj.name, "com.example.ParentActivity")
        self.assertEqual(cls_obj.descriptor, "Lcom/example/ParentActivity;")
        self.assertEqual(cls_obj.package, "com.example")
        self.assertEqual(cls_obj.simple_name, "ParentActivity")
        self.assertEqual(cls_obj.source_file, "ParentActivity.java")
        self.assertTrue(cls_obj.is_resolved)
        self.assertEqual(repr(cls_obj), "<Class 'com.example.ParentActivity'>")

        self.assertTrue(cls_obj.is_public)
        self.assertTrue(cls_obj.is_abstract)
        self.assertFalse(cls_obj.is_final)
        self.assertFalse(cls_obj.is_interface)
        self.assertFalse(cls_obj.is_enum)
        self.assertFalse(cls_obj.is_annotation)
        self.assertFalse(cls_obj.is_synthetic)

        iface_obj = collection.classes["com.example.IInterface"]
        self.assertTrue(iface_obj.is_interface)
        self.assertTrue(iface_obj.is_abstract)

    def test_class_collection_find(self) -> None:
        """Verify ClassCollection.find() fnmatch pattern search."""
        zip_bytes = create_test_zip(
            [
                ("classes.dex", self.dex1_bytes, 0),
                ("classes2.dex", self.dex2_bytes, 0),
            ]
        )
        collection = dexbuf.load(zip_bytes)

        activities = collection.classes.find("*Activity")
        activity_names = {c.name for c in activities}
        self.assertEqual(activity_names, {"com.example.ParentActivity", "com.example.MainActivity"})

        interfaces = collection.classes.find("com.example.I*")
        self.assertEqual(len(interfaces), 1)
        self.assertEqual(interfaces[0].name, "com.example.IInterface")

    def test_context_manager_and_close_lifecycle(self) -> None:
        """Verify DexCollection context manager and close lifecycle."""
        with dexbuf.load(self.dex1_bytes) as collection:
            self.assertEqual(len(collection.classes), 3)

        collection2 = dexbuf.load(self.dex1_bytes)
        collection2.close()

    def test_unrecognized_format_raises_value_error(self) -> None:
        """Verify passing unrecognized format buffer raises ValueError."""
        with self.assertRaises(ValueError):
            dexbuf.load(b"invalid magic bytes")


if __name__ == "__main__":
    unittest.main()
