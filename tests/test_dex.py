"""Comprehensive test suite for DexFile and TableSequence."""

import hashlib
import tempfile
import unittest
import zlib
from typing import Any

from dexbuf import (
    DEX_FILE_MAGIC,
    ENDIAN_CONSTANT,
    NO_INDEX,
    NO_OFFSET,
    AnnotationElement,
    AnnotationItem,
    AnnotationOffItem,
    AnnotationsDirectoryItem,
    AnnotationSetItem,
    AnnotationVisibility,
    CallSiteIdItem,
    ClassDataItem,
    ClassDefItem,
    CodeItem,
    Count,
    DexFile,
    EncodedAnnotation,
    EncodedArray,
    EncodedArrayItem,
    EncodedField,
    EncodedMethod,
    EncodedValue,
    FieldAnnotation,
    FieldIdItem,
    HeaderItem,
    Idx,
    ItemType,
    MapItem,
    MapList,
    MethodAnnotation,
    MethodHandleItem,
    MethodIdItem,
    Offset,
    ParameterAnnotation,
    ProtoIdItem,
    StaticItem,
    StringDataItem,
    StringIdItem,
    TryItem,
    TypeIdItem,
    TypeList,
    ValueType,
)
from dexbuf.dex import TableSequence


def create_sample_dex() -> bytes:
    """Construct a valid minimal DEX buffer in memory with complete tables and data sections."""
    header_size = 0x70

    # 1. String Data Items
    strings = [
        "Ljava/lang/Object;",  # 0
        "LTestClass;",  # 1
        "testMethod",  # 2
        "testField",  # 3
        "V",  # 4
        "I",  # 5
        "V",  # 6 (shorty)
    ]
    string_data_bytes = bytearray()
    string_data_offsets: list[int] = []

    # 2. Type List
    type_list = TypeList(list=(TypeList.Item(type_idx=Idx[TypeIdItem](3)),))  # parameter: I
    type_list_bytes = type_list.to_bytes()

    # 3. Code Item
    bytecode = b"\x0e\x00"  # return-void
    code_item = CodeItem(
        registers_size=1,
        ins_size=0,
        outs_size=0,
        debug_info_off=NO_OFFSET,
        insns=memoryview(bytecode),
        tries=(),
        handlers=None,
    )
    code_item_bytes = code_item.to_bytes()

    # 4. Class Data Item
    encoded_field = EncodedField(field_idx_diff=0, access_flags=0x0001)
    encoded_method = EncodedMethod(
        method_idx_diff=0,
        access_flags=0x0001,
        code_off=Offset[CodeItem](0),  # will patch offset
    )
    class_data = ClassDataItem(
        static_fields=(),
        instance_fields=(encoded_field,),
        direct_methods=(encoded_method,),
        virtual_methods=(),
    )

    # 5. Encoded Array Item (Static Values)
    encoded_val = EncodedValue(value_arg=0, value_type=ValueType.INT, value=42)
    encoded_array = EncodedArray(values=(encoded_val,))
    encoded_array_item = EncodedArrayItem(value=encoded_array)
    static_values_bytes = encoded_array_item.to_bytes()

    # 6. Annotations Directory Item
    ann_val = EncodedValue(value_arg=0, value_type=ValueType.INT, value=1)
    ann_elem = AnnotationElement(name_idx=Idx[Any](2), value=ann_val)
    ann = EncodedAnnotation(type_idx=Idx[Any](1), elements=(ann_elem,))
    ann_item = AnnotationItem(visibility=AnnotationVisibility.RUNTIME, annotation=ann)
    ann_item_bytes = ann_item.to_bytes()

    ann_off_item = AnnotationOffItem(annotation_off=Offset[AnnotationItem](0))  # will patch
    ann_set_item = AnnotationSetItem(entries=(ann_off_item,))
    ann_set_item_bytes = ann_set_item.to_bytes()

    field_ann = FieldAnnotation(
        field_idx=Idx[FieldIdItem](0),
        annotations_off=Offset[AnnotationSetItem](0),  # will patch
    )
    method_ann = MethodAnnotation(
        method_idx=Idx[MethodIdItem](0),
        annotations_off=Offset[AnnotationSetItem](0),  # will patch
    )

    # Layout Data Section
    data_start_off = (
        header_size + 4 * 7 + 4 * 4 + 12 * 1 + 8 * 1 + 8 * 1 + 32 * 1
    )  # header + tables
    data_off = data_start_off

    # Serialize string data
    for s in strings:
        item = StringDataItem.from_str(s)
        string_data_offsets.append(data_off)
        b = item.to_bytes()
        string_data_bytes.extend(b)
        data_off += len(b)

    type_list_off = data_off
    data_off += len(type_list_bytes)

    code_item_off = data_off
    data_off += len(code_item_bytes)

    # Re-build class data with patched code_off
    class_data = ClassDataItem(
        static_fields=(),
        instance_fields=(encoded_field,),
        direct_methods=(
            EncodedMethod(
                method_idx_diff=0,
                access_flags=0x0001,
                code_off=Offset[CodeItem](code_item_off),
            ),
        ),
        virtual_methods=(),
    )
    class_data_bytes = class_data.to_bytes()
    class_data_off = data_off
    data_off += len(class_data_bytes)

    static_values_off = data_off
    data_off += len(static_values_bytes)

    ann_item_off = data_off
    data_off += len(ann_item_bytes)

    ann_off_item = AnnotationOffItem(annotation_off=Offset[AnnotationItem](ann_item_off))
    ann_set_item = AnnotationSetItem(entries=(ann_off_item,))
    ann_set_item_bytes = ann_set_item.to_bytes()
    ann_set_item_off = data_off
    data_off += len(ann_set_item_bytes)

    field_ann = FieldAnnotation(
        field_idx=Idx[FieldIdItem](0),
        annotations_off=Offset[AnnotationSetItem](ann_set_item_off),
    )
    method_ann = MethodAnnotation(
        method_idx=Idx[MethodIdItem](0),
        annotations_off=Offset[AnnotationSetItem](ann_set_item_off),
    )
    ann_dir = AnnotationsDirectoryItem(
        class_annotations_off=Offset[AnnotationSetItem](ann_set_item_off),
        field_annotations=(field_ann,),
        method_annotations=(method_ann,),
        parameter_annotations=(),
    )
    ann_dir_bytes = ann_dir.to_bytes()
    ann_dir_off = data_off
    data_off += len(ann_dir_bytes)

    # Tables setup
    string_ids_off = header_size
    string_ids_bytes = b"".join(
        StringIdItem(string_data_off=Offset[StringDataItem](off)).to_bytes()
        for off in string_data_offsets
    )

    type_ids_off = string_ids_off + len(string_ids_bytes)
    type_ids = [
        TypeIdItem(descriptor_idx=Idx[StringIdItem](0)),  # 0: Object
        TypeIdItem(descriptor_idx=Idx[StringIdItem](1)),  # 1: TestClass
        TypeIdItem(descriptor_idx=Idx[StringIdItem](4)),  # 2: V
        TypeIdItem(descriptor_idx=Idx[StringIdItem](5)),  # 3: I
    ]
    type_ids_bytes = b"".join(t.to_bytes() for t in type_ids)

    proto_ids_off = type_ids_off + len(type_ids_bytes)
    proto_ids = [
        ProtoIdItem(
            shorty_idx=Idx[StringIdItem](6),
            return_type_idx=Idx[TypeIdItem](2),
            parameters_off=Offset[TypeList](type_list_off),
        ),
    ]
    proto_ids_bytes = b"".join(p.to_bytes() for p in proto_ids)

    field_ids_off = proto_ids_off + len(proto_ids_bytes)
    field_ids = [
        FieldIdItem(
            class_idx=Idx[TypeIdItem](1),
            type_idx=Idx[TypeIdItem](3),
            name_idx=Idx[StringIdItem](3),
        ),
    ]
    field_ids_bytes = b"".join(f.to_bytes() for f in field_ids)

    method_ids_off = field_ids_off + len(field_ids_bytes)
    method_ids = [
        MethodIdItem(
            class_idx=Idx[TypeIdItem](1),
            proto_idx=Idx[ProtoIdItem](0),
            name_idx=Idx[StringIdItem](2),
        ),
    ]
    method_ids_bytes = b"".join(m.to_bytes() for m in method_ids)

    class_defs_off = method_ids_off + len(method_ids_bytes)
    class_defs = [
        ClassDefItem(
            class_idx=Idx[TypeIdItem](1),
            access_flags=0x0001,
            superclass_idx=Idx[TypeIdItem](0),
            interfaces_off=NO_OFFSET,
            source_file_idx=NO_INDEX,
            annotations_off=Offset[AnnotationsDirectoryItem](ann_dir_off),
            class_data_off=Offset[ClassDataItem](class_data_off),
            static_values_off=Offset[EncodedArrayItem](static_values_off),
        ),
    ]
    class_defs_bytes = b"".join(c.to_bytes() for c in class_defs)

    map_list_off = data_off
    map_items = [
        MapItem(item_type=ItemType.HEADER_ITEM, size=1, offset=Offset[Any](0)),
        MapItem(
            item_type=ItemType.STRING_ID_ITEM,
            size=len(strings),
            offset=Offset[Any](string_ids_off),
        ),
        MapItem(
            item_type=ItemType.TYPE_ID_ITEM,
            size=len(type_ids),
            offset=Offset[Any](type_ids_off),
        ),
        MapItem(
            item_type=ItemType.PROTO_ID_ITEM,
            size=len(proto_ids),
            offset=Offset[Any](proto_ids_off),
        ),
        MapItem(
            item_type=ItemType.FIELD_ID_ITEM,
            size=len(field_ids),
            offset=Offset[Any](field_ids_off),
        ),
        MapItem(
            item_type=ItemType.METHOD_ID_ITEM,
            size=len(method_ids),
            offset=Offset[Any](method_ids_off),
        ),
        MapItem(
            item_type=ItemType.CLASS_DEF_ITEM,
            size=len(class_defs),
            offset=Offset[Any](class_defs_off),
        ),
        MapItem(item_type=ItemType.MAP_LIST, size=1, offset=Offset[Any](map_list_off)),
    ]
    map_list = MapList(list=tuple(map_items))
    map_list_bytes = map_list.to_bytes()
    data_off += len(map_list_bytes)

    total_file_size = data_off

    # Construct HeaderItem
    header = HeaderItem(
        magic=DEX_FILE_MAGIC,
        checksum=0,  # placeholder
        signature=b"\x00" * 20,  # placeholder
        file_size=total_file_size,
        header_size=header_size,
        endian_tag=ENDIAN_CONSTANT,
        link_size=0,
        link_off=NO_OFFSET,
        map_off=Offset[MapList](map_list_off),
        string_ids_size=Count[StringIdItem](len(strings)),
        string_ids_off=Offset[StringIdItem](string_ids_off),
        type_ids_size=Count[TypeIdItem](len(type_ids)),
        type_ids_off=Offset[TypeIdItem](type_ids_off),
        proto_ids_size=Count[ProtoIdItem](len(proto_ids)),
        proto_ids_off=Offset[ProtoIdItem](proto_ids_off),
        field_ids_size=Count[FieldIdItem](len(field_ids)),
        field_ids_off=Offset[FieldIdItem](field_ids_off),
        method_ids_size=Count[MethodIdItem](len(method_ids)),
        method_ids_off=Offset[MethodIdItem](method_ids_off),
        class_defs_size=Count[ClassDefItem](len(class_defs)),
        class_defs_off=Offset[ClassDefItem](class_defs_off),
        data_size=total_file_size - data_start_off,
        data_off=Offset[Any](data_start_off),
    )

    buf = bytearray(header.to_bytes())
    buf.extend(string_ids_bytes)
    buf.extend(type_ids_bytes)
    buf.extend(proto_ids_bytes)
    buf.extend(field_ids_bytes)
    buf.extend(method_ids_bytes)
    buf.extend(class_defs_bytes)
    buf.extend(string_data_bytes)
    buf.extend(type_list_bytes)
    buf.extend(code_item_bytes)
    buf.extend(class_data_bytes)
    buf.extend(static_values_bytes)
    buf.extend(ann_item_bytes)
    buf.extend(ann_set_item_bytes)
    buf.extend(ann_dir_bytes)
    buf.extend(map_list_bytes)

    # Calculate SHA-1 signature (bytes from offset 32 to end)
    sig = hashlib.sha1(buf[32:]).digest()
    buf[12:32] = sig

    # Calculate Adler-32 checksum (bytes from offset 12 to end)
    chk = zlib.adler32(buf[12:]) & 0xFFFF_FFFF
    buf[8:12] = chk.to_bytes(4, "little")

    return bytes(buf)


class TestDexFile(unittest.TestCase):
    def setUp(self) -> None:
        self.dex_bytes = create_sample_dex()
        self.dex = DexFile(self.dex_bytes)

    def test_header_and_map_list(self) -> None:
        """Verify header item parsing and lazy map_list property access."""
        self.assertEqual(self.dex.header.magic, DEX_FILE_MAGIC)
        self.assertEqual(self.dex.header.file_size, len(self.dex_bytes))
        self.assertEqual(self.dex.header.string_ids_size, 7)
        self.assertEqual(self.dex.header.type_ids_size, 4)
        self.assertEqual(self.dex.header.proto_ids_size, 1)
        self.assertEqual(self.dex.header.field_ids_size, 1)
        self.assertEqual(self.dex.header.method_ids_size, 1)
        self.assertEqual(self.dex.header.class_defs_size, 1)

        map_list = self.dex.map_list
        self.assertIsInstance(map_list, MapList)
        self.assertGreaterEqual(len(map_list), 8)
        self.assertEqual(map_list.get(ItemType.HEADER_ITEM).offset, 0)  # type: ignore[union-attr]

    def test_lazy_table_sequences_indexing_and_iteration(self) -> None:
        """Verify TableSequence len, indexing, bounds, negative indices, slices, and iter."""
        # string_ids sequence
        self.assertEqual(len(self.dex.string_ids), 7)
        first_string_id = self.dex.string_ids[0]
        last_string_id = self.dex.string_ids[-1]
        self.assertIsInstance(first_string_id, StringIdItem)
        self.assertIsInstance(last_string_id, StringIdItem)

        # Slice
        slice_ids = self.dex.string_ids[0:3]
        self.assertEqual(len(slice_ids), 3)
        self.assertIsInstance(slice_ids, tuple)
        self.assertEqual(slice_ids[0], first_string_id)

        # Iteration
        iter_ids = list(self.dex.string_ids)
        self.assertEqual(len(iter_ids), 7)
        self.assertEqual(iter_ids[0], first_string_id)

        # Bounds error
        with self.assertRaises(IndexError):
            _ = self.dex.string_ids[10]
        with self.assertRaises(IndexError):
            _ = self.dex.string_ids[-10]

        # Verify type_ids, proto_ids, field_ids, method_ids, class_defs sequences
        self.assertEqual(len(self.dex.type_ids), 4)
        self.assertEqual(len(self.dex.proto_ids), 1)
        self.assertEqual(len(self.dex.field_ids), 1)
        self.assertEqual(len(self.dex.method_ids), 1)
        self.assertEqual(len(self.dex.class_defs), 1)

        self.assertEqual(self.dex.type_ids[0].descriptor_idx, Idx[StringIdItem](0))
        self.assertEqual(self.dex.proto_ids[0].shorty_idx, Idx[StringIdItem](6))
        self.assertEqual(self.dex.field_ids[0].name_idx, Idx[StringIdItem](3))
        self.assertEqual(self.dex.method_ids[0].name_idx, Idx[StringIdItem](2))
        self.assertEqual(self.dex.class_defs[0].class_idx, Idx[TypeIdItem](1))

    def test_dereferencing_getters(self) -> None:
        """Verify dereferencing getters for string, type descriptor, and item structs."""
        # get_string and get_string_id
        self.assertEqual(self.dex.get_string(Idx[StringIdItem](0)), "Ljava/lang/Object;")
        self.assertEqual(self.dex.get_string(Idx[StringIdItem](1)), "LTestClass;")
        self.assertEqual(self.dex.get_string_id(Idx[StringIdItem](0)), self.dex.string_ids[0])

        # get_type_descriptor and get_type_id
        self.assertEqual(self.dex.get_type_descriptor(Idx[TypeIdItem](0)), "Ljava/lang/Object;")
        self.assertEqual(self.dex.get_type_descriptor(Idx[TypeIdItem](1)), "LTestClass;")
        self.assertEqual(self.dex.get_type_id(Idx[TypeIdItem](0)), self.dex.type_ids[0])

        # get_proto_id, get_field_id, get_method_id, get_class_def
        proto = self.dex.get_proto_id(Idx[ProtoIdItem](0))
        self.assertEqual(proto, self.dex.proto_ids[0])

        field = self.dex.get_field_id(Idx[FieldIdItem](0))
        self.assertEqual(field, self.dex.field_ids[0])

        method = self.dex.get_method_id(Idx[MethodIdItem](0))
        self.assertEqual(method, self.dex.method_ids[0])

        class_def = self.dex.get_class_def(Idx[ClassDefItem](0))
        self.assertEqual(class_def, self.dex.class_defs[0])

        # get_class_data
        class_data = self.dex.get_class_data(class_def.class_data_off)
        self.assertIsInstance(class_data, ClassDataItem)
        self.assertEqual(class_data.direct_methods_size, 1)

        # get_code_item
        code_item = self.dex.get_code_item(class_data.direct_methods[0].code_off)
        self.assertIsInstance(code_item, CodeItem)
        self.assertEqual(code_item.registers_size, 1)

        # get_type_list
        type_list = self.dex.get_type_list(proto.parameters_off)
        self.assertIsInstance(type_list, TypeList)
        self.assertEqual(len(type_list), 1)
        self.assertEqual(type_list[0].type_idx, Idx[TypeIdItem](3))

        # get_annotations_directory
        ann_dir = self.dex.get_annotations_directory(class_def.annotations_off)
        self.assertIsInstance(ann_dir, AnnotationsDirectoryItem)
        self.assertEqual(ann_dir.fields_size, 1)

        # get_static_values
        static_values = self.dex.get_static_values(class_def.static_values_off)
        self.assertIsInstance(static_values, EncodedArray)
        self.assertEqual(len(static_values.values), 1)
        self.assertEqual(static_values.values[0].value, 42)

    def test_precondition_validation_raises_value_error(self) -> None:
        """Verify that passing NO_INDEX or NO_OFFSET to dereferencing getters raises ValueError."""
        # NO_INDEX checks
        with self.assertRaises(ValueError):
            self.dex.get_string(NO_INDEX)
        with self.assertRaises(ValueError):
            self.dex.get_string(Idx[StringIdItem](0xFFFF_FFFF))
        with self.assertRaises(ValueError):
            self.dex.get_string_id(NO_INDEX)
        with self.assertRaises(ValueError):
            self.dex.get_type_descriptor(NO_INDEX)
        with self.assertRaises(ValueError):
            self.dex.get_type_id(NO_INDEX)
        with self.assertRaises(ValueError):
            self.dex.get_proto_id(NO_INDEX)
        with self.assertRaises(ValueError):
            self.dex.get_field_id(NO_INDEX)
        with self.assertRaises(ValueError):
            self.dex.get_method_id(NO_INDEX)
        with self.assertRaises(ValueError):
            self.dex.get_class_def(NO_INDEX)

        # NO_OFFSET checks
        with self.assertRaises(ValueError):
            self.dex.get_class_data(NO_OFFSET)
        with self.assertRaises(ValueError):
            self.dex.get_class_data(Offset[ClassDataItem](0))
        with self.assertRaises(ValueError):
            self.dex.get_code_item(NO_OFFSET)
        with self.assertRaises(ValueError):
            self.dex.get_type_list(NO_OFFSET)
        with self.assertRaises(ValueError):
            self.dex.get_annotations_directory(NO_OFFSET)
        with self.assertRaises(ValueError):
            self.dex.get_static_values(NO_OFFSET)

    def test_integrity_validation(self) -> None:
        """Verify verify_checksum and verify_signature on valid and corrupted DEX buffers."""
        self.assertTrue(self.dex.verify_checksum())
        self.assertTrue(self.dex.verify_signature())

        # Corrupt byte in signature region
        corrupted = bytearray(self.dex_bytes)
        corrupted[35] ^= 0xFF
        corrupt_dex = DexFile(corrupted)

        self.assertFalse(corrupt_dex.verify_checksum())
        self.assertFalse(corrupt_dex.verify_signature())

        # Corrupt byte in header checksum field (offset 8..12)
        corrupted2 = bytearray(self.dex_bytes)
        corrupted2[8] ^= 0xFF
        corrupt_dex2 = DexFile(corrupted2)

        self.assertFalse(corrupt_dex2.verify_checksum())
        self.assertTrue(corrupt_dex2.verify_signature())

    def test_buffer_protocol_support(self) -> None:
        """Verify DexFile works on bytes, bytearray, and memoryview objects."""
        # bytes
        dex_bytes = DexFile(self.dex_bytes)
        self.assertTrue(dex_bytes.verify_checksum())

        # bytearray
        dex_array = DexFile(bytearray(self.dex_bytes))
        self.assertTrue(dex_array.verify_checksum())

        # memoryview
        dex_mv = DexFile(memoryview(self.dex_bytes))
        self.assertTrue(dex_mv.verify_checksum())

    def test_static_item_protocol(self) -> None:
        """Verify that all fixed-size DEX specification items satisfy StaticItem protocol."""
        static_classes = [
            StringIdItem,
            TypeIdItem,
            ProtoIdItem,
            FieldIdItem,
            MethodIdItem,
            ClassDefItem,
            CallSiteIdItem,
            MethodHandleItem,
            TypeList.Item,
            TryItem,
            AnnotationOffItem,
            FieldAnnotation,
            MethodAnnotation,
            ParameterAnnotation,
        ]
        for cls in static_classes:
            self.assertTrue(hasattr(cls, "STRUCT"))
            dummy_item = cls.from_buffer(b"\x00" * cls.STRUCT.size)
            self.assertTrue(
                isinstance(dummy_item, StaticItem),
                f"{cls.__name__} instance does not conform to StaticItem protocol",
            )

    def test_table_sequence_properties(self) -> None:
        """Verify TableSequence offset and size properties."""
        seq = TableSequence(
            memoryview(self.dex_bytes),
            self.dex.header.string_ids_off,
            self.dex.header.string_ids_size,
            StringIdItem,
        )
        self.assertEqual(seq.offset, self.dex.header.string_ids_off)
        self.assertEqual(seq.size, self.dex.header.string_ids_size)

    def test_table_sequence_get_method(self) -> None:
        """Verify TableSequence.get() method behavior, NO_INDEX checks, and bounds validation."""
        seq = TableSequence(
            memoryview(self.dex_bytes),
            self.dex.header.string_ids_off,
            self.dex.header.string_ids_size,
            StringIdItem,
        )

        item0 = seq.get(Idx[StringIdItem](0))
        self.assertIsInstance(item0, StringIdItem)
        self.assertEqual(item0, seq[0])

        with self.assertRaises(ValueError):
            seq.get(NO_INDEX)
        with self.assertRaises(ValueError):
            seq.get(Idx[StringIdItem](0xFFFF_FFFF))

        with self.assertRaises(IndexError):
            seq.get(Idx[StringIdItem](100))
        with self.assertRaises(IndexError):
            seq.get(Idx[StringIdItem](-1))

    def test_open_convenience_method(self) -> None:
        """Verify DexFile.open reads DEX file from filesystem."""
        with tempfile.NamedTemporaryFile(suffix=".dex", delete=True) as tmp:
            tmp.write(self.dex_bytes)
            tmp.flush()

            opened_dex = DexFile.open(tmp.name)
            self.assertTrue(opened_dex.verify_checksum())
            self.assertTrue(opened_dex.verify_signature())
            self.assertEqual(opened_dex.get_string(Idx[StringIdItem](0)), "Ljava/lang/Object;")

    def test_find_string_id_sorted(self) -> None:
        """Verify find_string_id on strictly sorted strings table."""
        sorted_strings = ["A", "B", "C", "D", "E"]
        dex_buf = create_dex_with_strings_and_types(sorted_strings, sorted_strings)
        dex = DexFile(dex_buf)

        # First, middle, last
        self.assertEqual(dex.find_string_id("A"), Idx[StringIdItem](0))
        self.assertEqual(dex.find_string_id("C"), Idx[StringIdItem](2))
        self.assertEqual(dex.find_string_id("E"), Idx[StringIdItem](4))

        # Missing: before first, between, after last
        self.assertIsNone(dex.find_string_id("@"))
        self.assertIsNone(dex.find_string_id("BB"))
        self.assertIsNone(dex.find_string_id("Z"))

        # Empty string table
        empty_dex = DexFile(create_dex_with_strings_and_types([], []))
        self.assertIsNone(empty_dex.find_string_id("A"))

    def test_find_type_id_sorted(self) -> None:
        """Verify find_type_id on strictly sorted type_ids table."""
        types = ["LA;", "LB;", "LC;", "LD;", "LE;"]
        dex_buf = create_dex_with_strings_and_types(types, types)
        dex = DexFile(dex_buf)

        # First, middle, last
        self.assertEqual(dex.find_type_id("LA;"), Idx[TypeIdItem](0))
        self.assertEqual(dex.find_type_id("LC;"), Idx[TypeIdItem](2))
        self.assertEqual(dex.find_type_id("LE;"), Idx[TypeIdItem](4))

        # Missing: before first, between, after last
        self.assertIsNone(dex.find_type_id("L@;"))
        self.assertIsNone(dex.find_type_id("LBB;"))
        self.assertIsNone(dex.find_type_id("LZ;"))

        # Empty type table
        empty_dex = DexFile(create_dex_with_strings_and_types([], []))
        self.assertIsNone(empty_dex.find_type_id("LA;"))

    def test_find_class_def(self) -> None:
        """Verify find_class_def lookup by descriptor or Idx[TypeIdItem]."""
        self.assertIsNone(self.dex._class_defs_by_type)

        # Lookup by Idx[TypeIdItem]
        class_def = self.dex.find_class_def(Idx[TypeIdItem](1))
        self.assertIsNotNone(class_def)
        self.assertEqual(class_def.class_idx, Idx[TypeIdItem](1))  # type: ignore[union-attr]
        self.assertIsNotNone(self.dex._class_defs_by_type)

        # Lookup by descriptor str
        class_def_str = self.dex.find_class_def("LTestClass;")
        self.assertEqual(class_def_str, class_def)

        # Non-existent class def lookup
        self.assertIsNone(self.dex.find_class_def(Idx[TypeIdItem](0)))
        self.assertIsNone(self.dex.find_class_def("Ljava/lang/Object;"))
        self.assertIsNone(self.dex.find_class_def("LNonExistent;"))


def create_dex_with_strings_and_types(strings: list[str], types: list[str]) -> bytes:
    """Helper to create minimal DEX file with specific sorted string and type tables."""
    header_size = 0x70
    string_data_bytes = bytearray()
    string_data_offsets: list[int] = []

    # Calculate data section start
    data_start_off = header_size + 4 * len(strings) + 4 * len(types)
    data_off = data_start_off

    for s in strings:
        item = StringDataItem.from_str(s)
        string_data_offsets.append(data_off)
        b = item.to_bytes()
        string_data_bytes.extend(b)
        data_off += len(b)

    string_ids_bytes = b"".join(
        StringIdItem(string_data_off=Offset[StringDataItem](off)).to_bytes()
        for off in string_data_offsets
    )

    # For types, map type string to its index in strings
    type_ids: list[TypeIdItem] = []
    for t in types:
        s_idx = strings.index(t)
        type_ids.append(TypeIdItem(descriptor_idx=Idx[StringIdItem](s_idx)))

    type_ids_bytes = b"".join(tid.to_bytes() for tid in type_ids)

    total_file_size = data_off
    header = HeaderItem(
        magic=DEX_FILE_MAGIC,
        checksum=0,
        signature=b"\x00" * 20,
        file_size=total_file_size,
        header_size=header_size,
        endian_tag=ENDIAN_CONSTANT,
        link_size=0,
        link_off=NO_OFFSET,
        map_off=NO_OFFSET,
        string_ids_size=Count[StringIdItem](len(strings)),
        string_ids_off=Offset[StringIdItem](header_size if strings else 0),
        type_ids_size=Count[TypeIdItem](len(types)),
        type_ids_off=Offset[TypeIdItem]((header_size + len(string_ids_bytes)) if types else 0),
        proto_ids_size=Count[ProtoIdItem](0),
        proto_ids_off=NO_OFFSET,
        field_ids_size=Count[FieldIdItem](0),
        field_ids_off=NO_OFFSET,
        method_ids_size=Count[MethodIdItem](0),
        method_ids_off=NO_OFFSET,
        class_defs_size=Count[ClassDefItem](0),
        class_defs_off=NO_OFFSET,
        data_size=total_file_size - data_start_off,
        data_off=Offset[Any](data_start_off),
    )

    buf = bytearray(header.to_bytes())
    buf.extend(string_ids_bytes)
    buf.extend(type_ids_bytes)
    buf.extend(string_data_bytes)

    sig = hashlib.sha1(buf[32:]).digest()
    buf[12:32] = sig
    chk = zlib.adler32(buf[12:]) & 0xFFFF_FFFF
    buf[8:12] = chk.to_bytes(4, "little")

    return bytes(buf)


if __name__ == "__main__":
    unittest.main()
