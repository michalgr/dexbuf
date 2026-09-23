"""Unit tests for DEX spec items."""

import dataclasses
import struct
import unittest
from dataclasses import FrozenInstanceError
from typing import Any

from dexbuf import (
    DEX_FILE_MAGIC,
    ENDIAN_CONSTANT,
    HEADER_SIZE_V40,
    HEADER_SIZE_V41,
    NO_INDEX,
    NO_OFFSET,
    REVERSE_ENDIAN_CONSTANT,
    SUPPORTED_DEX_VERSIONS,
    AnnotationElement,
    AnnotationItem,
    AnnotationOffItem,
    AnnotationsDirectoryItem,
    AnnotationSetItem,
    AnnotationSetRefItem,
    AnnotationSetRefList,
    AnnotationVisibility,
    CallSiteIdItem,
    CatchHandlerMap,
    ClassDataItem,
    ClassDefItem,
    CodeItem,
    Count,
    EncodedAnnotation,
    EncodedArray,
    EncodedArrayItem,
    EncodedCatchHandler,
    EncodedField,
    EncodedMethod,
    EncodedTypeAddrPair,
    EncodedValue,
    FieldAnnotation,
    FieldIdItem,
    HeaderItem,
    HiddenapiClassDataItem,
    HiddenapiRestrictionFlag,
    Idx,
    Instruction,
    ItemType,
    MapItem,
    MapItemType,
    MapList,
    MethodAnnotation,
    MethodIdItem,
    Offset,
    Opcode,
    ParameterAnnotation,
    ProtoIdItem,
    StringDataItem,
    StringIdItem,
    TryItem,
    TryTable,
    TypeIdItem,
    TypeList,
    ValueType,
)
from dexbuf.cursor import Cursor
from dexbuf.debug import (
    DbgAdvanceLine,
    DbgAdvancePc,
    DbgEndSequence,
    DbgSetEpilogueBegin,
    DbgSetFile,
    DbgSetPrologueEnd,
    DbgSpecial,
    DebugPosition,
)
from dexbuf.items import DebugInfoItem


class TestHeaderItemAndConstants(unittest.TestCase):
    def test_header_constants(self) -> None:
        """Verify header constant values."""
        self.assertEqual(ENDIAN_CONSTANT, 0x1234_5678)
        self.assertEqual(REVERSE_ENDIAN_CONSTANT, 0x7856_3412)
        self.assertEqual(DEX_FILE_MAGIC, b"dex\n035\x00")
        self.assertEqual(SUPPORTED_DEX_VERSIONS, ("035", "037", "038", "039", "040", "041"))
        self.assertEqual(HEADER_SIZE_V40, 0x70)
        self.assertEqual(HEADER_SIZE_V41, 0x78)

    def test_header_item_class_attributes_and_slots(self) -> None:
        """Verify HeaderItem padding, struct formats, slots, and field metadata."""
        self.assertEqual(HeaderItem.PADDING, 4)
        self.assertEqual(HeaderItem.STRUCT.format, "<8sI20s20I")
        self.assertEqual(HeaderItem.STRUCT.size, 112)
        self.assertEqual(HeaderItem.CONTAINER_STRUCT.format, "<II")
        self.assertEqual(HeaderItem.CONTAINER_STRUCT.size, 8)

        field_names = [f.name for f in dataclasses.fields(HeaderItem)]
        self.assertIn("magic", field_names)
        self.assertIn("checksum", field_names)
        self.assertIn("container_size", field_names)
        self.assertIn("header_offset", field_names)
        self.assertNotIn("PADDING", field_names)
        self.assertNotIn("STRUCT", field_names)
        self.assertNotIn("CONTAINER_STRUCT", field_names)

    def test_header_item_immutability(self) -> None:
        """Verify HeaderItem frozen immutability and slots."""
        hdr = HeaderItem(
            magic=b"dex\n035\x00",
            checksum=12345,
            signature=b"\x00" * 20,
            file_size=112,
            header_size=0x70,
            endian_tag=ENDIAN_CONSTANT,
            link_size=0,
            link_off=NO_OFFSET,
            map_off=Offset[MapList](0x70),
            string_ids_size=Count[StringIdItem](0),
            string_ids_off=NO_OFFSET,
            type_ids_size=Count[TypeIdItem](0),
            type_ids_off=NO_OFFSET,
            proto_ids_size=Count[ProtoIdItem](0),
            proto_ids_off=NO_OFFSET,
            field_ids_size=Count[FieldIdItem](0),
            field_ids_off=NO_OFFSET,
            method_ids_size=Count[MethodIdItem](0),
            method_ids_off=NO_OFFSET,
            class_defs_size=Count[ClassDefItem](0),
            class_defs_off=NO_OFFSET,
            data_size=0,
            data_off=NO_OFFSET,
        )

        with self.assertRaises(FrozenInstanceError):
            hdr.checksum = 54321  # type: ignore[misc]

        with self.assertRaises((TypeError, AttributeError)):
            hdr.version = "039"  # type: ignore[misc]

        self.assertIsInstance(hdr.__slots__, tuple)

    def test_header_item_properties(self) -> None:
        """Verify version and is_valid_endian read-only properties."""
        hdr_v35 = HeaderItem(
            magic=b"dex\n035\x00",
            checksum=0,
            signature=b"\x00" * 20,
            file_size=112,
            header_size=0x70,
            endian_tag=ENDIAN_CONSTANT,
            link_size=0,
            link_off=NO_OFFSET,
            map_off=NO_OFFSET,
            string_ids_size=Count[StringIdItem](0),
            string_ids_off=NO_OFFSET,
            type_ids_size=Count[TypeIdItem](0),
            type_ids_off=NO_OFFSET,
            proto_ids_size=Count[ProtoIdItem](0),
            proto_ids_off=NO_OFFSET,
            field_ids_size=Count[FieldIdItem](0),
            field_ids_off=NO_OFFSET,
            method_ids_size=Count[MethodIdItem](0),
            method_ids_off=NO_OFFSET,
            class_defs_size=Count[ClassDefItem](0),
            class_defs_off=NO_OFFSET,
            data_size=0,
            data_off=NO_OFFSET,
        )
        self.assertEqual(hdr_v35.version, "035")
        self.assertTrue(hdr_v35.is_valid_endian)

        hdr_v39_bad_endian = HeaderItem(
            magic=b"dex\n039\x00",
            checksum=0,
            signature=b"\x00" * 20,
            file_size=112,
            header_size=0x70,
            endian_tag=REVERSE_ENDIAN_CONSTANT,
            link_size=0,
            link_off=NO_OFFSET,
            map_off=NO_OFFSET,
            string_ids_size=Count[StringIdItem](0),
            string_ids_off=NO_OFFSET,
            type_ids_size=Count[TypeIdItem](0),
            type_ids_off=NO_OFFSET,
            proto_ids_size=Count[ProtoIdItem](0),
            proto_ids_off=NO_OFFSET,
            field_ids_size=Count[FieldIdItem](0),
            field_ids_off=NO_OFFSET,
            method_ids_size=Count[MethodIdItem](0),
            method_ids_off=NO_OFFSET,
            class_defs_size=Count[ClassDefItem](0),
            class_defs_off=NO_OFFSET,
            data_size=0,
            data_off=NO_OFFSET,
        )
        self.assertEqual(hdr_v39_bad_endian.version, "039")
        self.assertFalse(hdr_v39_bad_endian.is_valid_endian)

    def test_standard_112_byte_header_roundtrip_and_typed_fields(self) -> None:
        """Verify standard 112-byte header parsing, serialization, and typed field wrappers."""
        hdr = HeaderItem(
            magic=b"dex\n038\x00",
            checksum=0x12345678,
            signature=b"\x01" * 20,
            file_size=1024,
            header_size=0x70,
            endian_tag=ENDIAN_CONSTANT,
            link_size=0,
            link_off=NO_OFFSET,
            map_off=Offset[MapList](0x200),
            string_ids_size=Count[StringIdItem](10),
            string_ids_off=Offset[StringIdItem](0x70),
            type_ids_size=Count[TypeIdItem](5),
            type_ids_off=Offset[TypeIdItem](0x98),
            proto_ids_size=Count[ProtoIdItem](3),
            proto_ids_off=Offset[ProtoIdItem](0xAC),
            field_ids_size=Count[FieldIdItem](2),
            field_ids_off=Offset[FieldIdItem](0xD0),
            method_ids_size=Count[MethodIdItem](4),
            method_ids_off=Offset[MethodIdItem](0xE0),
            class_defs_size=Count[ClassDefItem](1),
            class_defs_off=Offset[ClassDefItem](0x100),
            data_size=512,
            data_off=Offset[Any](0x200),
        )

        raw = hdr.to_bytes()
        self.assertEqual(len(raw), 112)

        cursor = Cursor(raw)
        parsed = HeaderItem.from_cursor(cursor)

        self.assertEqual(parsed, hdr)
        self.assertIsNone(parsed.container_size)
        self.assertIsNone(parsed.header_offset)

        # Confirm typed Offsets and Counts
        self.assertEqual(parsed.string_ids_size, Count[StringIdItem](10))
        self.assertEqual(parsed.string_ids_off, Offset[StringIdItem](0x70))
        self.assertEqual(parsed.map_off, Offset[MapList](0x200))

        # from_buffer test
        buf = b"\x00" * 16 + raw
        from_buf = HeaderItem.from_buffer(buf, Offset[HeaderItem](16))
        self.assertEqual(from_buf, hdr)

    def test_v41_container_header_roundtrip(self) -> None:
        """Verify v41+ 120-byte container header parsing and roundtrip."""
        hdr_v41 = HeaderItem(
            magic=b"dex\n041\x00",
            checksum=0xABCDEF01,
            signature=b"\x02" * 20,
            file_size=4096,
            header_size=0x78,
            endian_tag=ENDIAN_CONSTANT,
            link_size=0,
            link_off=NO_OFFSET,
            map_off=Offset[MapList](0x300),
            string_ids_size=Count[StringIdItem](20),
            string_ids_off=Offset[StringIdItem](0x78),
            type_ids_size=Count[TypeIdItem](10),
            type_ids_off=Offset[TypeIdItem](0xC8),
            proto_ids_size=Count[ProtoIdItem](5),
            proto_ids_off=Offset[ProtoIdItem](0xF0),
            field_ids_size=Count[FieldIdItem](8),
            field_ids_off=Offset[FieldIdItem](0x12C),
            method_ids_size=Count[MethodIdItem](15),
            method_ids_off=Offset[MethodIdItem](0x16C),
            class_defs_size=Count[ClassDefItem](2),
            class_defs_off=Offset[ClassDefItem](0x1E4),
            data_size=2048,
            data_off=Offset[Any](0x224),
            container_size=8192,
            header_offset=Offset[Any](0x1000),
        )

        self.assertEqual(hdr_v41.version, "041")

        raw = hdr_v41.to_bytes()
        self.assertEqual(len(raw), 120)

        cursor = Cursor(raw)
        parsed = HeaderItem.from_cursor(cursor)

        self.assertEqual(parsed, hdr_v41)
        self.assertEqual(parsed.container_size, 8192)
        self.assertEqual(parsed.header_offset, Offset[Any](0x1000))
        self.assertTrue(cursor.is_eof)


class TestStringDataItem(unittest.TestCase):
    def test_from_str(self) -> None:
        """Test StringDataItem creation from string."""
        item = StringDataItem.from_str("Hello, DEX!")
        self.assertEqual(item.utf16_size, 11)
        self.assertIsInstance(item.data, memoryview)
        self.assertEqual(bytes(item.data), b"Hello, DEX!")
        self.assertEqual(item.decode(), "Hello, DEX!")
        self.assertEqual(str(item), "Hello, DEX!")

        supp_item = StringDataItem.from_str("𐀀World")
        self.assertEqual(supp_item.utf16_size, 7)
        self.assertEqual(supp_item.decode(), "𐀀World")

    def test_padding_attribute(self) -> None:
        """Test StringDataItem PADDING class attribute and fields metadata."""
        self.assertEqual(StringDataItem.PADDING, 1)

        # Verify PADDING is not in dataclasses.fields
        field_names = [f.name for f in dataclasses.fields(StringDataItem)]
        self.assertEqual(field_names, ["data", "utf16_size"])
        self.assertNotIn("PADDING", field_names)

    def test_immutability(self) -> None:
        """Test that StringDataItem is frozen and slotted."""
        item = StringDataItem.from_str("Frozen")
        with self.assertRaises(FrozenInstanceError):
            item.data = memoryview(b"Modified")  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            item.utf16_size = 10  # type: ignore[misc]

        # Verify __slots__ is set on the class
        self.assertEqual(item.__slots__, ("data", "utf16_size"))

    def test_to_bytes_and_from_cursor(self) -> None:
        """Test encoding StringDataItem to bytes and parsing via Cursor."""
        original = StringDataItem.from_str("Café 𐀀")
        raw = original.to_bytes()

        cursor = Cursor(raw)
        parsed = StringDataItem.from_cursor(cursor)

        self.assertEqual(parsed, original)
        self.assertEqual(parsed.utf16_size, 7)
        self.assertEqual(parsed.decode(), "Café 𐀀")
        self.assertTrue(cursor.is_eof)

    def test_conversion_methods(self) -> None:
        """Test on-demand conversion methods on StringDataItem."""
        item = StringDataItem.from_str("Café 𐀀")

        # raw_bytes & to_raw_bytes
        self.assertEqual(item.raw_bytes, b"Caf\xc3\xa9 \xed\xa0\x80\xed\xb0\x80")
        self.assertEqual(item.to_raw_bytes(), b"Caf\xc3\xa9 \xed\xa0\x80\xed\xb0\x80")

        # decode & __str__
        self.assertEqual(item.decode(), "Café 𐀀")
        self.assertEqual(str(item), "Café 𐀀")

        # to_utf16 & utf16_code_units
        expected_utf16 = (67, 97, 102, 0x00E9, 32, 0xD800, 0xDC00)
        self.assertEqual(item.to_utf16(), expected_utf16)
        self.assertEqual(item.utf16_code_units(), expected_utf16)

        # code_points
        expected_cp = (67, 97, 102, 0x00E9, 32, 0x10000)
        self.assertEqual(item.code_points(), expected_cp)

    def test_from_buffer_with_typed_offset(self) -> None:
        """Test parsing StringDataItem from buffer with typed Offset."""
        item1 = StringDataItem.from_str("First")
        item2 = StringDataItem.from_str("Second")

        buf = item1.to_bytes() + item2.to_bytes()
        offset_item2 = Offset[StringDataItem](len(item1.to_bytes()))

        # Parse first item with NO_OFFSET
        parsed1 = StringDataItem.from_buffer(buf, NO_OFFSET)
        self.assertEqual(parsed1, item1)

        # Parse second item with typed Offset[StringDataItem]
        parsed2 = StringDataItem.from_buffer(buf, offset_item2)
        self.assertEqual(parsed2, item2)

    def test_roundtrip(self) -> None:
        """Test roundtrip conversion for various string inputs."""
        test_strings = [
            "",
            "A",
            "Hello, World!",
            "a\x00b",
            "Café",
            "中文",
            "𐀀𐀁𐀂",
            "\ud800",
        ]

        for s in test_strings:
            item = StringDataItem.from_str(s)
            encoded = item.to_bytes()
            decoded = StringDataItem.from_buffer(encoded)
            self.assertEqual(decoded, item)
            self.assertEqual(decoded.decode(), s)


class TestStringIdItem(unittest.TestCase):
    def test_padding_and_struct(self) -> None:
        self.assertEqual(StringIdItem.PADDING, 4)
        self.assertEqual(StringIdItem.STRUCT.format, "<I")

        field_names = [f.name for f in dataclasses.fields(StringIdItem)]
        self.assertEqual(field_names, ["string_data_off"])
        self.assertNotIn("PADDING", field_names)
        self.assertNotIn("STRUCT", field_names)

    def test_immutability_and_slots(self) -> None:
        item = StringIdItem(string_data_off=Offset[StringDataItem](0x1000))
        with self.assertRaises(FrozenInstanceError):
            item.string_data_off = Offset[StringDataItem](0x2000)  # type: ignore[misc]

        self.assertEqual(item.__slots__, ("string_data_off",))

    def test_parsing_and_encoding_roundtrip(self) -> None:
        item = StringIdItem(string_data_off=Offset[StringDataItem](0x00123456))
        raw = item.to_bytes()
        self.assertEqual(len(raw), 4)

        cursor = Cursor(raw)
        parsed = StringIdItem.from_cursor(cursor)
        self.assertEqual(parsed, item)
        self.assertEqual(parsed.string_data_off, Offset[StringDataItem](0x00123456))

        buf = b"\x00" * 16 + raw
        offset = Offset[StringIdItem](16)
        from_buf = StringIdItem.from_buffer(buf, offset)
        self.assertEqual(from_buf, item)


class TestTypeIdItem(unittest.TestCase):
    def test_padding_and_struct(self) -> None:
        self.assertEqual(TypeIdItem.PADDING, 4)
        self.assertEqual(TypeIdItem.STRUCT.format, "<I")

        field_names = [f.name for f in dataclasses.fields(TypeIdItem)]
        self.assertEqual(field_names, ["descriptor_idx"])
        self.assertNotIn("PADDING", field_names)
        self.assertNotIn("STRUCT", field_names)

    def test_immutability_and_slots(self) -> None:
        item = TypeIdItem(descriptor_idx=Idx[StringIdItem](42))
        with self.assertRaises(FrozenInstanceError):
            item.descriptor_idx = Idx[StringIdItem](100)  # type: ignore[misc]

        self.assertEqual(item.__slots__, ("descriptor_idx",))

    def test_parsing_and_encoding_roundtrip(self) -> None:
        item = TypeIdItem(descriptor_idx=Idx[StringIdItem](0x00ABCDEF))
        raw = item.to_bytes()
        self.assertEqual(len(raw), 4)

        cursor = Cursor(raw)
        parsed = TypeIdItem.from_cursor(cursor)
        self.assertEqual(parsed, item)

        buf = b"HEADER_DEX_BYTES" + raw
        offset = Offset[TypeIdItem](16)
        from_buf = TypeIdItem.from_buffer(buf, offset)
        self.assertEqual(from_buf, item)


class TestProtoIdItem(unittest.TestCase):
    def test_padding_and_struct(self) -> None:
        self.assertEqual(ProtoIdItem.PADDING, 4)
        self.assertEqual(ProtoIdItem.STRUCT.format, "<III")

        field_names = [f.name for f in dataclasses.fields(ProtoIdItem)]
        self.assertEqual(field_names, ["shorty_idx", "return_type_idx", "parameters_off"])
        self.assertNotIn("PADDING", field_names)
        self.assertNotIn("STRUCT", field_names)

    def test_immutability_and_slots(self) -> None:
        item = ProtoIdItem(
            shorty_idx=Idx[StringIdItem](1),
            return_type_idx=Idx[TypeIdItem](2),
            parameters_off=NO_OFFSET,
        )
        with self.assertRaises(FrozenInstanceError):
            item.shorty_idx = Idx[StringIdItem](5)  # type: ignore[misc]

        self.assertEqual(item.__slots__, ("shorty_idx", "return_type_idx", "parameters_off"))

    def test_no_offset_parameters(self) -> None:
        item = ProtoIdItem(
            shorty_idx=Idx[StringIdItem](10),
            return_type_idx=Idx[TypeIdItem](20),
            parameters_off=NO_OFFSET,
        )
        raw = item.to_bytes()
        self.assertEqual(len(raw), 12)

        cursor = Cursor(raw)
        parsed = ProtoIdItem.from_cursor(cursor)
        self.assertEqual(parsed, item)
        self.assertEqual(parsed.parameters_off, NO_OFFSET)

    def test_valid_offset_parameters(self) -> None:
        item = ProtoIdItem(
            shorty_idx=Idx[StringIdItem](100),
            return_type_idx=Idx[TypeIdItem](200),
            parameters_off=Offset[TypeList](0x1234),
        )
        raw = item.to_bytes()
        self.assertEqual(len(raw), 12)

        cursor = Cursor(raw)
        parsed = ProtoIdItem.from_cursor(cursor)
        self.assertEqual(parsed, item)
        self.assertEqual(parsed.parameters_off, Offset[TypeList](0x1234))

        buf = b"\xff" * 8 + raw
        offset = Offset[ProtoIdItem](8)
        from_buf = ProtoIdItem.from_buffer(buf, offset)
        self.assertEqual(from_buf, item)


class TestFieldIdItem(unittest.TestCase):
    def test_padding_and_struct(self) -> None:
        self.assertEqual(FieldIdItem.PADDING, 4)
        self.assertEqual(FieldIdItem.STRUCT.format, "<HHI")

        field_names = [f.name for f in dataclasses.fields(FieldIdItem)]
        self.assertEqual(field_names, ["class_idx", "type_idx", "name_idx"])
        self.assertNotIn("PADDING", field_names)
        self.assertNotIn("STRUCT", field_names)

    def test_immutability_and_slots(self) -> None:
        item = FieldIdItem(
            class_idx=Idx[TypeIdItem](1),
            type_idx=Idx[TypeIdItem](2),
            name_idx=Idx[StringIdItem](3),
        )
        with self.assertRaises(FrozenInstanceError):
            item.class_idx = Idx[TypeIdItem](10)  # type: ignore[misc]

        self.assertEqual(item.__slots__, ("class_idx", "type_idx", "name_idx"))

    def test_parsing_and_encoding_roundtrip(self) -> None:
        item = FieldIdItem(
            class_idx=Idx[TypeIdItem](0x1234),
            type_idx=Idx[TypeIdItem](0x5678),
            name_idx=Idx[StringIdItem](0x9ABCDEF0),
        )
        raw = item.to_bytes()
        self.assertEqual(len(raw), 8)

        cursor = Cursor(raw)
        parsed = FieldIdItem.from_cursor(cursor)
        self.assertEqual(parsed, item)

        buf = b"PADDING_" + raw
        offset = Offset[FieldIdItem](8)
        from_buf = FieldIdItem.from_buffer(buf, offset)
        self.assertEqual(from_buf, item)


class TestMethodIdItem(unittest.TestCase):
    def test_padding_and_struct(self) -> None:
        self.assertEqual(MethodIdItem.PADDING, 4)
        self.assertEqual(MethodIdItem.STRUCT.format, "<HHI")

        field_names = [f.name for f in dataclasses.fields(MethodIdItem)]
        self.assertEqual(field_names, ["class_idx", "proto_idx", "name_idx"])
        self.assertNotIn("PADDING", field_names)
        self.assertNotIn("STRUCT", field_names)

    def test_immutability_and_slots(self) -> None:
        item = MethodIdItem(
            class_idx=Idx[TypeIdItem](1),
            proto_idx=Idx[ProtoIdItem](2),
            name_idx=Idx[StringIdItem](3),
        )
        with self.assertRaises(FrozenInstanceError):
            item.class_idx = Idx[TypeIdItem](10)  # type: ignore[misc]

        self.assertEqual(item.__slots__, ("class_idx", "proto_idx", "name_idx"))

    def test_parsing_and_encoding_roundtrip(self) -> None:
        item = MethodIdItem(
            class_idx=Idx[TypeIdItem](0x0102),
            proto_idx=Idx[ProtoIdItem](0x0304),
            name_idx=Idx[StringIdItem](0x05060708),
        )
        raw = item.to_bytes()
        self.assertEqual(len(raw), 8)

        cursor = Cursor(raw)
        parsed = MethodIdItem.from_cursor(cursor)
        self.assertEqual(parsed, item)

        buf = b"\x00" * 4 + raw
        offset = Offset[MethodIdItem](4)
        from_buf = MethodIdItem.from_buffer(buf, offset)
        self.assertEqual(from_buf, item)


class TestTypeList(unittest.TestCase):
    def test_padding_and_headers(self) -> None:
        self.assertEqual(TypeList.PADDING, 4)
        self.assertEqual(TypeList.HEADER.format, "<I")
        self.assertEqual(TypeList.Item.STRUCT.format, "<H")

        type_list_fields = [f.name for f in dataclasses.fields(TypeList)]
        self.assertEqual(type_list_fields, ["list"])
        self.assertNotIn("PADDING", type_list_fields)
        self.assertNotIn("HEADER", type_list_fields)

        item_fields = [f.name for f in dataclasses.fields(TypeList.Item)]
        self.assertEqual(item_fields, ["type_idx"])
        self.assertNotIn("STRUCT", item_fields)

    def test_immutability_and_slots(self) -> None:
        item = TypeList.Item(type_idx=Idx[TypeIdItem](1))
        with self.assertRaises(FrozenInstanceError):
            item.type_idx = Idx[TypeIdItem](2)  # type: ignore[misc]
        self.assertEqual(item.__slots__, ("type_idx",))

        type_list = TypeList(list=(item,))
        with self.assertRaises((TypeError, AttributeError)):
            type_list.size = 2  # type: ignore[misc]
        self.assertEqual(type_list.__slots__, ("list",))

    def test_empty_list(self) -> None:
        empty = TypeList(list=())
        raw = empty.to_bytes()
        self.assertEqual(raw, struct.pack("<I", 0))
        self.assertEqual(len(empty), 0)
        self.assertEqual(list(empty), [])

        parsed = TypeList.from_buffer(raw)
        self.assertEqual(parsed, empty)

    def test_multi_item_list_indexing_and_iteration(self) -> None:
        items = (
            TypeList.Item(type_idx=Idx[TypeIdItem](10)),
            TypeList.Item(type_idx=Idx[TypeIdItem](20)),
            TypeList.Item(type_idx=Idx[TypeIdItem](30)),
        )
        type_list = TypeList(list=items)

        # Test container methods
        self.assertEqual(len(type_list), 3)
        self.assertEqual(type_list[0], items[0])
        self.assertEqual(type_list[1], items[1])
        self.assertEqual(type_list[1:], items[1:])
        self.assertEqual(list(type_list), list(items))

        # Test roundtrip encoding/decoding
        raw = type_list.to_bytes()
        self.assertEqual(len(raw), 4 + 3 * 2)  # 4 header + 6 items

        cursor = Cursor(raw)
        parsed = TypeList.from_cursor(cursor)
        self.assertEqual(parsed, type_list)
        self.assertEqual(parsed.size, 3)
        self.assertEqual(len(parsed.list), 3)

        buf = b"\x00\x00\x00\x00" + raw
        from_buf = TypeList.from_buffer(buf, Offset[TypeList](4))
        self.assertEqual(from_buf, type_list)


class TestClassDefItem(unittest.TestCase):
    def test_padding_and_struct(self) -> None:
        self.assertEqual(ClassDefItem.PADDING, 4)
        self.assertEqual(ClassDefItem.STRUCT.format, "<8I")

        field_names = [f.name for f in dataclasses.fields(ClassDefItem)]
        expected_fields = [
            "class_idx",
            "access_flags",
            "superclass_idx",
            "interfaces_off",
            "source_file_idx",
            "annotations_off",
            "class_data_off",
            "static_values_off",
        ]
        self.assertEqual(field_names, expected_fields)
        self.assertNotIn("PADDING", field_names)
        self.assertNotIn("STRUCT", field_names)

    def test_immutability_and_slots(self) -> None:
        item = ClassDefItem(
            class_idx=Idx[TypeIdItem](1),
            access_flags=1,
            superclass_idx=Idx[TypeIdItem](2),
            interfaces_off=NO_OFFSET,
            source_file_idx=Idx[StringIdItem](3),
            annotations_off=NO_OFFSET,
            class_data_off=NO_OFFSET,
            static_values_off=NO_OFFSET,
        )
        with self.assertRaises(FrozenInstanceError):
            item.access_flags = 2  # type: ignore[misc]

        expected_slots = (
            "class_idx",
            "access_flags",
            "superclass_idx",
            "interfaces_off",
            "source_file_idx",
            "annotations_off",
            "class_data_off",
            "static_values_off",
        )
        self.assertEqual(item.__slots__, expected_slots)

    def test_parsing_and_encoding_roundtrip(self) -> None:
        item = ClassDefItem(
            class_idx=Idx[TypeIdItem](10),
            access_flags=0x0001,  # ACC_PUBLIC
            superclass_idx=Idx[TypeIdItem](11),
            interfaces_off=Offset[TypeList](0x0100),
            source_file_idx=Idx[StringIdItem](12),
            annotations_off=Offset[None](0x0200),  # type: ignore[type-arg]
            class_data_off=Offset[ClassDataItem](0x0300),
            static_values_off=Offset[None](0x0400),  # type: ignore[type-arg]
        )
        raw = item.to_bytes()
        self.assertEqual(len(raw), 32)

        cursor = Cursor(raw)
        parsed = ClassDefItem.from_cursor(cursor)
        self.assertEqual(parsed, item)

        buf = b"\x00" * 8 + raw
        offset = Offset[ClassDefItem](8)
        from_buf = ClassDefItem.from_buffer(buf, offset)
        self.assertEqual(from_buf, item)

    def test_typed_static_values_off(self) -> None:
        """Verify static_values_off is typed as Offset[EncodedArrayItem]."""
        item = ClassDefItem(
            class_idx=Idx[TypeIdItem](1),
            access_flags=1,
            superclass_idx=Idx[TypeIdItem](2),
            interfaces_off=NO_OFFSET,
            source_file_idx=Idx[StringIdItem](3),
            annotations_off=NO_OFFSET,
            class_data_off=NO_OFFSET,
            static_values_off=Offset[EncodedArrayItem](0x1234),
        )
        self.assertEqual(item.static_values_off, Offset[EncodedArrayItem](0x1234))

    def test_typed_annotations_off(self) -> None:
        """Verify annotations_off is typed as Offset[AnnotationsDirectoryItem]."""
        item = ClassDefItem(
            class_idx=Idx[TypeIdItem](1),
            access_flags=1,
            superclass_idx=Idx[TypeIdItem](2),
            interfaces_off=NO_OFFSET,
            source_file_idx=Idx[StringIdItem](3),
            annotations_off=Offset[AnnotationsDirectoryItem](0x5678),
            class_data_off=NO_OFFSET,
            static_values_off=NO_OFFSET,
        )
        self.assertEqual(item.annotations_off, Offset[AnnotationsDirectoryItem](0x5678))

    def test_no_index_and_no_offset_handling(self) -> None:
        item = ClassDefItem(
            class_idx=Idx[TypeIdItem](0),  # Root class
            access_flags=0x0001,
            superclass_idx=NO_INDEX,  # java.lang.Object has no superclass
            interfaces_off=NO_OFFSET,
            source_file_idx=NO_INDEX,
            annotations_off=NO_OFFSET,
            class_data_off=NO_OFFSET,
            static_values_off=NO_OFFSET,
        )
        raw = item.to_bytes()
        self.assertEqual(len(raw), 32)

        parsed = ClassDefItem.from_buffer(raw)
        self.assertEqual(parsed, item)
        self.assertEqual(parsed.superclass_idx, NO_INDEX)
        self.assertEqual(parsed.interfaces_off, NO_OFFSET)
        self.assertEqual(parsed.source_file_idx, NO_INDEX)
        self.assertEqual(parsed.annotations_off, NO_OFFSET)
        self.assertEqual(parsed.class_data_off, NO_OFFSET)
        self.assertEqual(parsed.static_values_off, NO_OFFSET)


class TestEncodedFieldAndMethod(unittest.TestCase):
    def test_encoded_field_immutability_and_slots(self) -> None:
        field = EncodedField(field_idx_diff=5, access_flags=0x0001)
        with self.assertRaises(FrozenInstanceError):
            field.access_flags = 0x0002  # type: ignore[misc]

        self.assertEqual(field.__slots__, ("field_idx_diff", "access_flags"))

    def test_encoded_field_roundtrip(self) -> None:
        field = EncodedField(field_idx_diff=128, access_flags=8)
        raw = field.to_bytes()
        cursor = Cursor(raw)
        parsed = EncodedField.from_cursor(cursor)
        self.assertEqual(parsed, field)
        self.assertTrue(cursor.is_eof)

    def test_encoded_method_immutability_and_slots(self) -> None:
        method = EncodedMethod(
            method_idx_diff=10, access_flags=0x0001, code_off=Offset[Any](0x1000)
        )
        with self.assertRaises(FrozenInstanceError):
            method.access_flags = 0x0002  # type: ignore[misc]

        self.assertEqual(method.__slots__, ("method_idx_diff", "access_flags", "code_off"))

    def test_encoded_method_roundtrip(self) -> None:
        method = EncodedMethod(
            method_idx_diff=3, access_flags=0x0008, code_off=Offset[CodeItem](0x2000)
        )
        raw = method.to_bytes()
        cursor = Cursor(raw)
        parsed = EncodedMethod.from_cursor(cursor)
        self.assertEqual(parsed, method)
        self.assertEqual(parsed.code_off, Offset[CodeItem](0x2000))
        self.assertTrue(cursor.is_eof)


class TestTryAndCatchHandlers(unittest.TestCase):
    def test_try_item(self) -> None:
        self.assertEqual(TryItem.PADDING, 4)
        self.assertEqual(TryItem.STRUCT.format, "<IHH")

        item = TryItem(start_addr=0x10, insn_count=5, handler_off=0x20)
        with self.assertRaises(FrozenInstanceError):
            item.start_addr = 0x20  # type: ignore[misc]

        self.assertEqual(item.__slots__, ("start_addr", "insn_count", "handler_off"))
        self.assertEqual(item.end_addr, 0x15)
        self.assertTrue(item.covers(0x10))
        self.assertTrue(item.covers(0x14))
        self.assertFalse(item.covers(0x0F))
        self.assertFalse(item.covers(0x15))

        raw = item.to_bytes()
        self.assertEqual(len(raw), 8)

        parsed = TryItem.from_buffer(raw)
        self.assertEqual(parsed, item)

    def test_try_table(self) -> None:
        t1 = TryItem(start_addr=0x00, insn_count=5, handler_off=0x00)
        t2 = TryItem(start_addr=0x0A, insn_count=8, handler_off=0x0C)
        table = TryTable.from_tries([t1, t2])

        self.assertEqual(len(table), 2)
        self.assertEqual(table[0], t1)
        self.assertEqual(table[1], t2)
        self.assertEqual(table[-1], t2)
        self.assertEqual(table[0:2], (t1, t2))
        self.assertEqual(list(table), [t1, t2])
        self.assertEqual(table.to_bytes(), t1.to_bytes() + t2.to_bytes())

        with self.assertRaises(IndexError):
            _ = table[2]
        with self.assertRaises(IndexError):
            _ = table[-3]

    def test_catch_handler_map(self) -> None:
        h1 = EncodedCatchHandler(
            handlers=(EncodedTypeAddrPair(type_idx=Idx[TypeIdItem](1), addr=0x10),),
            catch_all_addr=None,
        )
        h2 = EncodedCatchHandler(
            handlers=(EncodedTypeAddrPair(type_idx=Idx[TypeIdItem](2), addr=0x20),),
            catch_all_addr=0x30,
        )
        handler_map = CatchHandlerMap.from_handlers([h1, h2])

        self.assertEqual(len(handler_map), 2)
        offsets = list(handler_map)
        self.assertEqual(len(offsets), 2)

        off1, off2 = offsets
        self.assertEqual(handler_map[off1], h1)
        self.assertEqual(handler_map[off2], h2)

        with self.assertRaises(KeyError):
            _ = handler_map[-1]
        with self.assertRaises(KeyError):
            _ = handler_map[9999]

    def test_encoded_type_addr_pair(self) -> None:
        pair = EncodedTypeAddrPair(type_idx=Idx[TypeIdItem](3), addr=0x100)
        with self.assertRaises(FrozenInstanceError):
            pair.addr = 0x200  # type: ignore[misc]

        self.assertEqual(pair.__slots__, ("type_idx", "addr"))

        raw = pair.to_bytes()
        parsed = EncodedTypeAddrPair.from_cursor(Cursor(raw))
        self.assertEqual(parsed, pair)

    def test_encoded_catch_handler(self) -> None:
        pair1 = EncodedTypeAddrPair(type_idx=Idx[TypeIdItem](1), addr=0x10)
        pair2 = EncodedTypeAddrPair(type_idx=Idx[TypeIdItem](2), addr=0x20)

        # Handler with catch-all (size <= 0)
        handler_catch_all = EncodedCatchHandler(handlers=(pair1, pair2), catch_all_addr=0x30)
        self.assertEqual(handler_catch_all.size, -2)
        with self.assertRaises((TypeError, AttributeError)):
            handler_catch_all.size = 1  # type: ignore[misc]

        self.assertEqual(handler_catch_all.__slots__, ("handlers", "catch_all_addr"))

        raw1 = handler_catch_all.to_bytes()
        parsed1 = EncodedCatchHandler.from_cursor(Cursor(raw1))
        self.assertEqual(parsed1, handler_catch_all)

        # Handler without catch-all (size > 0)
        handler_no_catch_all = EncodedCatchHandler(handlers=(pair1, pair2), catch_all_addr=None)
        self.assertEqual(handler_no_catch_all.size, 2)
        raw2 = handler_no_catch_all.to_bytes()
        parsed2 = EncodedCatchHandler.from_cursor(Cursor(raw2))
        self.assertEqual(parsed2, handler_no_catch_all)

    def test_encoded_catch_handler_list(self) -> None:
        handler = EncodedCatchHandler(
            handlers=(EncodedTypeAddrPair(type_idx=Idx[TypeIdItem](5), addr=0x50),),
            catch_all_addr=None,
        )
        handler_map = CatchHandlerMap.from_handlers([handler])

        self.assertEqual(len(handler_map), 1)
        self.assertEqual(handler_map.__slots__, ("_buffer",))

        raw = handler_map.to_bytes()
        parsed = CatchHandlerMap(memoryview(raw))
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed.to_bytes(), raw)


class TestCodeItem(unittest.TestCase):
    def test_padding_and_struct(self) -> None:
        self.assertEqual(CodeItem.PADDING, 4)
        self.assertEqual(CodeItem.HEADER.format, "<4H2I")

        field_names = [f.name for f in dataclasses.fields(CodeItem)]
        expected_fields = [
            "registers_size",
            "ins_size",
            "outs_size",
            "debug_info_off",
            "insns",
            "tries",
            "handlers",
        ]
        self.assertEqual(field_names, expected_fields)

    def test_immutability_and_slots(self) -> None:
        item = CodeItem(
            registers_size=2,
            ins_size=1,
            outs_size=0,
            debug_info_off=NO_OFFSET,
            insns=memoryview(b"\x0e\x00"),  # return-void
            tries=(),
            handlers=None,
        )
        with self.assertRaises(FrozenInstanceError):
            item.registers_size = 4  # type: ignore[misc]
        with self.assertRaises((TypeError, AttributeError)):
            item.insns_size = 5  # type: ignore[misc]
        with self.assertRaises((TypeError, AttributeError)):
            item.tries_size = 2  # type: ignore[misc]

        expected_slots = (
            "registers_size",
            "ins_size",
            "outs_size",
            "debug_info_off",
            "insns",
            "tries",
            "handlers",
        )
        self.assertEqual(item.__slots__, expected_slots)

    def test_zero_copy_and_lazy_iop_parsing(self) -> None:
        # nop (0x0000), return-void (0x000e) -> 2 code units = 4 bytes
        bytecode = b"\x00\x00\x0e\x00"
        item_no_tries = CodeItem(
            registers_size=1,
            ins_size=0,
            outs_size=0,
            debug_info_off=NO_OFFSET,
            insns=memoryview(bytecode),
            tries=(),
            handlers=None,
        )
        self.assertEqual(item_no_tries.insns_size, 2)
        self.assertEqual(item_no_tries.tries_size, 0)

        raw = item_no_tries.to_bytes()
        cursor = Cursor(raw)
        parsed = CodeItem.from_cursor(cursor)

        # Confirm insns is a zero-copy memoryview slice
        self.assertIsInstance(parsed.insns, memoryview)
        self.assertEqual(bytes(parsed.insns), bytecode)

        # Lazy instruction parsing
        iops = list(parsed.iter_iops())
        self.assertEqual(len(iops), 2)
        self.assertIsInstance(iops[0], Instruction)
        self.assertEqual(iops[0].OPCODE, Opcode.NOP)
        self.assertIsInstance(iops[1], Instruction)
        self.assertEqual(iops[1].OPCODE, Opcode.RETURN_VOID)

        # Check __iter__ and parse_iops
        self.assertEqual(list(parsed), iops)
        self.assertEqual(parsed.parse_iops(), tuple(iops))

    def test_tries_and_padding_even_insns_size(self) -> None:
        # 2 code units (even) -> no padding before tries
        bytecode = b"\x00\x00\x0e\x00"
        handler = EncodedCatchHandler(
            handlers=(EncodedTypeAddrPair(type_idx=Idx[TypeIdItem](0), addr=2),),
            catch_all_addr=4,
        )
        handlers = CatchHandlerMap.from_handlers([handler])
        handler_off = next(iter(handlers))
        try_item = TryItem(start_addr=0, insn_count=1, handler_off=handler_off)

        item = CodeItem(
            registers_size=1,
            ins_size=0,
            outs_size=0,
            debug_info_off=NO_OFFSET,
            insns=memoryview(bytecode),
            tries=TryTable.from_tries([try_item]),
            handlers=handlers,
        )

        raw = item.to_bytes()
        parsed = CodeItem.from_buffer(raw)
        self.assertEqual(parsed.tries_size, 1)
        self.assertEqual(parsed.tries[0], try_item)
        self.assertEqual(parsed.get_catch_handler(try_item), handler)
        self.assertEqual(parsed.find_try_item(0), try_item)
        self.assertEqual(parsed.find_catch_handler(0), handler)
        self.assertIsNone(parsed.find_try_item(5))
        self.assertIsNone(parsed.find_catch_handler(5))

    def test_tries_and_padding_odd_insns_size(self) -> None:
        # 1 code unit (odd) -> 2 bytes padding required before tries
        bytecode = b"\x0e\x00"  # return-void
        handler = EncodedCatchHandler(
            handlers=(EncodedTypeAddrPair(type_idx=Idx[TypeIdItem](1), addr=10),),
            catch_all_addr=None,
        )
        handlers = CatchHandlerMap.from_handlers([handler])
        handler_off = next(iter(handlers))
        try_item = TryItem(start_addr=0, insn_count=1, handler_off=handler_off)

        item = CodeItem(
            registers_size=1,
            ins_size=0,
            outs_size=0,
            debug_info_off=NO_OFFSET,
            insns=memoryview(bytecode),
            tries=TryTable.from_tries([try_item]),
            handlers=handlers,
        )

        raw = item.to_bytes()
        # Verify padding bytes exist in raw serialized output
        # Header size = 16 bytes. insns = 2 bytes. Total = 18 bytes.
        # Padding = 2 bytes (offsets 18..20)
        self.assertEqual(raw[18:20], b"\x00\x00")

        parsed = CodeItem.from_buffer(raw)
        self.assertEqual(parsed.tries_size, 1)
        self.assertEqual(parsed.tries[0], try_item)
        self.assertEqual(parsed.get_catch_handler(try_item), handler)


class TestClassDataItem(unittest.TestCase):
    def test_padding_attribute_and_nested_aliases(self) -> None:
        self.assertEqual(ClassDataItem.PADDING, 1)
        self.assertIs(ClassDataItem.EncodedField, EncodedField)
        self.assertIs(ClassDataItem.EncodedMethod, EncodedMethod)

        field_names = [f.name for f in dataclasses.fields(ClassDataItem)]
        expected_fields = [
            "static_fields",
            "instance_fields",
            "direct_methods",
            "virtual_methods",
        ]
        self.assertEqual(field_names, expected_fields)
        self.assertNotIn("PADDING", field_names)
        self.assertNotIn("EncodedField", field_names)
        self.assertNotIn("EncodedMethod", field_names)

    def test_immutability_and_slots(self) -> None:
        item = ClassDataItem(
            static_fields=(),
            instance_fields=(),
            direct_methods=(),
            virtual_methods=(),
        )
        with self.assertRaises((TypeError, AttributeError)):
            item.static_fields_size = 1  # type: ignore[misc]

        expected_slots = (
            "static_fields",
            "instance_fields",
            "direct_methods",
            "virtual_methods",
        )
        self.assertEqual(item.__slots__, expected_slots)

    def test_empty_class_data(self) -> None:
        empty = ClassDataItem(
            static_fields=(),
            instance_fields=(),
            direct_methods=(),
            virtual_methods=(),
        )
        self.assertEqual(empty.static_fields_size, 0)
        self.assertEqual(empty.instance_fields_size, 0)
        self.assertEqual(empty.direct_methods_size, 0)
        self.assertEqual(empty.virtual_methods_size, 0)

        raw = empty.to_bytes()
        self.assertEqual(raw, b"\x00\x00\x00\x00")

        parsed = ClassDataItem.from_buffer(raw)
        self.assertEqual(parsed, empty)

    def test_non_empty_class_data_roundtrip(self) -> None:
        sf1 = EncodedField(field_idx_diff=1, access_flags=0x0008)
        sf2 = EncodedField(field_idx_diff=2, access_flags=0x0018)
        if1 = EncodedField(field_idx_diff=5, access_flags=0x0002)

        dm1 = EncodedMethod(method_idx_diff=1, access_flags=0x10008, code_off=Offset[Any](0x1234))
        vm1 = EncodedMethod(method_idx_diff=2, access_flags=0x0001, code_off=Offset[Any](0x5678))
        vm2 = EncodedMethod(method_idx_diff=1, access_flags=0x0001, code_off=NO_OFFSET)

        item = ClassDataItem(
            static_fields=(sf1, sf2),
            instance_fields=(if1,),
            direct_methods=(dm1,),
            virtual_methods=(vm1, vm2),
        )
        self.assertEqual(item.static_fields_size, 2)
        self.assertEqual(item.instance_fields_size, 1)
        self.assertEqual(item.direct_methods_size, 1)
        self.assertEqual(item.virtual_methods_size, 2)

        raw = item.to_bytes()
        cursor = Cursor(raw)
        parsed = ClassDataItem.from_cursor(cursor)

        self.assertEqual(parsed, item)
        self.assertEqual(parsed.static_fields, (sf1, sf2))
        self.assertEqual(parsed.instance_fields, (if1,))
        self.assertEqual(parsed.direct_methods, (dm1,))
        self.assertEqual(parsed.virtual_methods, (vm1, vm2))
        self.assertTrue(cursor.is_eof)

        buf = b"HEADER" + raw
        from_buf = ClassDataItem.from_buffer(buf, Offset[ClassDataItem](6))
        self.assertEqual(from_buf, item)

    def test_delta_decoding_iterators(self) -> None:
        """Verify delta-decoding iterators on ClassDataItem."""
        # 1. Empty tuples
        empty_item = ClassDataItem(
            static_fields=(),
            instance_fields=(),
            direct_methods=(),
            virtual_methods=(),
        )
        self.assertEqual(list(empty_item.iter_static_fields()), [])
        self.assertEqual(list(empty_item.iter_instance_fields()), [])
        self.assertEqual(list(empty_item.iter_direct_methods()), [])
        self.assertEqual(list(empty_item.iter_virtual_methods()), [])

        # 2. Single-item tuples with non-zero diff
        sf_single = EncodedField(field_idx_diff=15, access_flags=0x0001)
        if_single = EncodedField(field_idx_diff=42, access_flags=0x0002)
        dm_single = EncodedMethod(
            method_idx_diff=100, access_flags=0x0008, code_off=Offset[CodeItem](0x1000)
        )
        vm_single = EncodedMethod(
            method_idx_diff=200, access_flags=0x0001, code_off=Offset[CodeItem](0x2000)
        )

        single_item = ClassDataItem(
            static_fields=(sf_single,),
            instance_fields=(if_single,),
            direct_methods=(dm_single,),
            virtual_methods=(vm_single,),
        )

        self.assertEqual(
            list(single_item.iter_static_fields()),
            [(Idx[FieldIdItem](15), sf_single)],
        )
        self.assertEqual(
            list(single_item.iter_instance_fields()),
            [(Idx[FieldIdItem](42), if_single)],
        )
        self.assertEqual(
            list(single_item.iter_direct_methods()),
            [(Idx[MethodIdItem](100), dm_single)],
        )
        self.assertEqual(
            list(single_item.iter_virtual_methods()),
            [(Idx[MethodIdItem](200), vm_single)],
        )

        # 3. Multi-item tuples verifying correct cumulative calculations and reset across categories
        sf1 = EncodedField(field_idx_diff=10, access_flags=1)
        sf2 = EncodedField(field_idx_diff=5, access_flags=2)
        sf3 = EncodedField(field_idx_diff=0, access_flags=3)

        if1 = EncodedField(field_idx_diff=3, access_flags=1)
        if2 = EncodedField(field_idx_diff=7, access_flags=2)

        dm1 = EncodedMethod(method_idx_diff=100, access_flags=1, code_off=NO_OFFSET)
        dm2 = EncodedMethod(method_idx_diff=20, access_flags=2, code_off=NO_OFFSET)

        vm1 = EncodedMethod(method_idx_diff=5, access_flags=1, code_off=NO_OFFSET)
        vm2 = EncodedMethod(method_idx_diff=15, access_flags=2, code_off=NO_OFFSET)

        multi_item = ClassDataItem(
            static_fields=(sf1, sf2, sf3),
            instance_fields=(if1, if2),
            direct_methods=(dm1, dm2),
            virtual_methods=(vm1, vm2),
        )

        # Static fields accum: 10, 10+5=15, 15+0=15
        self.assertEqual(
            list(multi_item.iter_static_fields()),
            [
                (Idx[FieldIdItem](10), sf1),
                (Idx[FieldIdItem](15), sf2),
                (Idx[FieldIdItem](15), sf3),
            ],
        )

        # Instance fields accum: resets to 0 -> 3, 3+7=10
        self.assertEqual(
            list(multi_item.iter_instance_fields()),
            [
                (Idx[FieldIdItem](3), if1),
                (Idx[FieldIdItem](10), if2),
            ],
        )

        # Direct methods accum: 100, 100+20=120
        self.assertEqual(
            list(multi_item.iter_direct_methods()),
            [
                (Idx[MethodIdItem](100), dm1),
                (Idx[MethodIdItem](120), dm2),
            ],
        )

        # Virtual methods accum: resets to 0 -> 5, 5+15=20
        self.assertEqual(
            list(multi_item.iter_virtual_methods()),
            [
                (Idx[MethodIdItem](5), vm1),
                (Idx[MethodIdItem](20), vm2),
            ],
        )


class TestDebugInfoItem(unittest.TestCase):
    def test_padding_and_fields(self) -> None:
        self.assertEqual(DebugInfoItem.PADDING, 1)

        field_names = [f.name for f in dataclasses.fields(DebugInfoItem)]
        expected_fields = ["line_start", "parameter_names", "bytecode"]
        self.assertEqual(field_names, expected_fields)
        self.assertNotIn("PADDING", field_names)

    def test_immutability_and_slots(self) -> None:
        item = DebugInfoItem(
            line_start=1,
            parameter_names=(),
            bytecode=memoryview(b"\x00"),
        )
        with self.assertRaises(FrozenInstanceError):
            item.line_start = 2  # type: ignore[misc]
        with self.assertRaises((TypeError, AttributeError)):
            item.parameters_size = 5  # type: ignore[misc]

        self.assertEqual(item.__slots__, ("line_start", "parameter_names", "bytecode"))

    def test_zero_copy_bytecode_and_roundtrip(self) -> None:
        # line_start=1, parameters_size=2 (param1=Idx(0), param2=None)
        # bytecode: DBG_SET_FILE(1), DBG_ADVANCE_PC(2), DBG_ADVANCE_LINE(1)
        # DBG_SET_PROLOGUE_END, DBG_SPECIAL(0x0a), DBG_END_SEQUENCE
        # DBG_SET_FILE = 0x09 + encode_uleb128p1(1) [0x02]
        # DBG_ADVANCE_PC = 0x01 + uleb128(2) [0x02]
        # DBG_ADVANCE_LINE = 0x02 + sleb128(1) [0x01]
        # DBG_SET_PROLOGUE_END = 0x07
        # DBG_SPECIAL(0x0a) = 0x0a
        # DBG_END_SEQUENCE = 0x00
        bytecode_raw = b"\x09\x02\x01\x02\x02\x01\x07\x0a\x00"

        item = DebugInfoItem(
            line_start=10,
            parameter_names=(Idx[StringIdItem](0), None),
            bytecode=memoryview(bytecode_raw),
        )

        raw = item.to_bytes()
        cursor = Cursor(raw)
        parsed = DebugInfoItem.from_cursor(cursor)

        self.assertEqual(parsed.line_start, 10)
        self.assertEqual(parsed.parameters_size, 2)
        self.assertEqual(parsed.parameter_names, (Idx[StringIdItem](0), None))
        self.assertIsInstance(parsed.bytecode, memoryview)
        self.assertEqual(bytes(parsed.bytecode), bytecode_raw)
        self.assertTrue(cursor.is_eof)

        # Buffer roundtrip with offset
        buf = b"\xff\xff" + raw
        from_buf = DebugInfoItem.from_buffer(buf, Offset[DebugInfoItem](2))
        self.assertEqual(from_buf.line_start, parsed.line_start)
        self.assertEqual(from_buf.parameter_names, parsed.parameter_names)
        self.assertEqual(bytes(from_buf.bytecode), bytecode_raw)

    def test_iter_instructions_and_positions(self) -> None:
        # line_start=100
        # Bytecode ops:
        # DBG_SET_FILE(Idx(5)) -> source_file_idx = 5
        # DBG_SET_PROLOGUE_END -> prologue_end = True
        # DBG_ADVANCE_PC(4) -> address += 4
        # DBG_ADVANCE_LINE(2) -> line += 2
        # DBG_SPECIAL(0x0a) -> line += (-4), address += 0 -> yields position
        # DBG_SET_EPILOGUE_BEGIN -> epilogue_begin = True
        # DBG_SPECIAL(0x19) -> line += -4, address += 1 -> yields position
        # DBG_END_SEQUENCE -> finish
        bytecode_raw = (
            b"\x09\x06"  # DBG_SET_FILE (5 + 1 = 6)
            b"\x07"  # DBG_SET_PROLOGUE_END
            b"\x01\x04"  # DBG_ADVANCE_PC (4)
            b"\x02\x02"  # DBG_ADVANCE_LINE (2)
            b"\x0a"  # DBG_SPECIAL (line -4, addr 0) -> line: 100 + 2 - 4 = 98, addr: 0 + 4 + 0 = 4
            b"\x08"  # DBG_SET_EPILOGUE_BEGIN
            b"\x19"  # DBG_SPECIAL (line -4, addr 1) -> line: 98 - 4 = 94, addr: 4 + 1 = 5
            b"\x00"  # DBG_END_SEQUENCE
        )

        item = DebugInfoItem(
            line_start=100,
            parameter_names=(),
            bytecode=memoryview(bytecode_raw),
        )

        instructions = list(item.iter_instructions())
        self.assertEqual(len(instructions), 8)
        self.assertIsInstance(instructions[0], DbgSetFile)
        self.assertIsInstance(instructions[1], DbgSetPrologueEnd)
        self.assertIsInstance(instructions[2], DbgAdvancePc)
        self.assertIsInstance(instructions[3], DbgAdvanceLine)
        self.assertIsInstance(instructions[4], DbgSpecial)
        self.assertIsInstance(instructions[5], DbgSetEpilogueBegin)
        self.assertIsInstance(instructions[6], DbgSpecial)
        self.assertIsInstance(instructions[7], DbgEndSequence)

        positions = list(item.iter_positions(initial_source_file=None))
        self.assertEqual(len(positions), 2)

        self.assertEqual(
            positions[0],
            DebugPosition(
                address=4,
                line=98,
                source_file_idx=Idx[StringIdItem](5),
                prologue_end=True,
                epilogue_begin=False,
            ),
        )
        self.assertEqual(
            positions[1],
            DebugPosition(
                address=5,
                line=94,
                source_file_idx=Idx[StringIdItem](5),
                prologue_end=False,
                epilogue_begin=True,
            ),
        )


class TestEncodedArrayItemAndCallSiteIdItem(unittest.TestCase):
    def test_encoded_array_item(self) -> None:
        """Verify EncodedArrayItem PADDING, immutability, parsing, and serialization."""
        self.assertEqual(EncodedArrayItem.PADDING, 1)

        val = EncodedValue(value_arg=0, value_type=ValueType.INT, value=100)
        arr = EncodedArray(values=(val,))
        item = EncodedArrayItem(value=arr)

        with self.assertRaises(FrozenInstanceError):
            item.value = arr  # type: ignore[misc]

        self.assertEqual(item.__slots__, ("value",))

        raw = item.to_bytes()
        parsed = EncodedArrayItem.from_buffer(raw)
        self.assertEqual(parsed, item)
        self.assertEqual(parsed.value.values[0].value, 100)

    def test_call_site_id_item(self) -> None:
        """Verify CallSiteIdItem call_site_off typed as Offset[EncodedArrayItem]."""
        self.assertEqual(CallSiteIdItem.PADDING, 4)

        item = CallSiteIdItem(call_site_off=Offset[EncodedArrayItem](0x001000))
        with self.assertRaises(FrozenInstanceError):
            item.call_site_off = Offset[EncodedArrayItem](0x2000)  # type: ignore[misc]

        raw = item.to_bytes()
        parsed = CallSiteIdItem.from_buffer(raw)
        self.assertEqual(parsed, item)
        self.assertEqual(parsed.call_site_off, Offset[EncodedArrayItem](0x001000))


class TestAnnotationItems(unittest.TestCase):
    def test_annotation_visibility_enum(self) -> None:
        """Verify AnnotationVisibility values."""
        self.assertEqual(AnnotationVisibility.BUILD, 0x00)
        self.assertEqual(AnnotationVisibility.RUNTIME, 0x01)
        self.assertEqual(AnnotationVisibility.SYSTEM, 0x02)

    def test_annotation_item(self) -> None:
        """Verify AnnotationItem padding, immutability, parsing, and serialization."""
        self.assertEqual(AnnotationItem.PADDING, 1)

        val = EncodedValue(value_arg=0, value_type=ValueType.INT, value=42)
        elem = AnnotationElement(name_idx=Idx[Any](1), value=val)
        ann = EncodedAnnotation(type_idx=Idx[Any](10), elements=(elem,))
        item = AnnotationItem(visibility=AnnotationVisibility.RUNTIME, annotation=ann)

        with self.assertRaises(FrozenInstanceError):
            item.visibility = AnnotationVisibility.BUILD  # type: ignore[misc]

        self.assertEqual(item.__slots__, ("visibility", "annotation"))

        raw = item.to_bytes()
        parsed = AnnotationItem.from_buffer(raw)
        self.assertEqual(parsed, item)
        self.assertEqual(parsed.visibility, AnnotationVisibility.RUNTIME)

    def test_annotation_off_item(self) -> None:
        """Verify AnnotationOffItem struct, immutability, and roundtrip."""
        self.assertEqual(AnnotationOffItem.STRUCT.format, "<I")

        item = AnnotationOffItem(annotation_off=Offset[AnnotationItem](0x1234))
        with self.assertRaises(FrozenInstanceError):
            item.annotation_off = Offset[AnnotationItem](0x5678)  # type: ignore[misc]

        self.assertEqual(item.__slots__, ("annotation_off",))

        raw = item.to_bytes()
        self.assertEqual(len(raw), 4)

        parsed = AnnotationOffItem.from_buffer(raw)
        self.assertEqual(parsed, item)

    def test_annotation_set_item(self) -> None:
        """Verify AnnotationSetItem padding, sequence protocol, immutability, and roundtrip."""
        self.assertEqual(AnnotationSetItem.PADDING, 4)
        self.assertEqual(AnnotationSetItem.HEADER.format, "<I")

        entry1 = AnnotationOffItem(annotation_off=Offset[AnnotationItem](0x100))
        entry2 = AnnotationOffItem(annotation_off=Offset[AnnotationItem](0x200))
        set_item = AnnotationSetItem(entries=(entry1, entry2))

        with self.assertRaises((TypeError, AttributeError)):
            set_item.size = 1  # type: ignore[misc]

        self.assertEqual(set_item.__slots__, ("entries",))
        self.assertEqual(len(set_item), 2)
        self.assertEqual(set_item[0], entry1)
        self.assertEqual(set_item[1], entry2)
        self.assertEqual(set_item[0:], (entry1, entry2))
        self.assertEqual(list(set_item), [entry1, entry2])

        raw = set_item.to_bytes()
        self.assertEqual(len(raw), 4 + 2 * 4)

        parsed = AnnotationSetItem.from_buffer(raw)
        self.assertEqual(parsed, set_item)

    def test_annotation_set_ref_item(self) -> None:
        """Verify AnnotationSetRefItem struct, immutability, and roundtrip."""
        self.assertEqual(AnnotationSetRefItem.STRUCT.format, "<I")

        item = AnnotationSetRefItem(annotations_off=Offset[AnnotationSetItem](0x300))
        with self.assertRaises(FrozenInstanceError):
            item.annotations_off = Offset[AnnotationSetItem](0x400)  # type: ignore[misc]

        self.assertEqual(item.__slots__, ("annotations_off",))

        raw = item.to_bytes()
        self.assertEqual(len(raw), 4)

        parsed = AnnotationSetRefItem.from_buffer(raw)
        self.assertEqual(parsed, item)

    def test_annotation_set_ref_list(self) -> None:
        """Verify AnnotationSetRefList padding, sequence protocol, immutability, and roundtrip."""
        self.assertEqual(AnnotationSetRefList.PADDING, 4)
        self.assertEqual(AnnotationSetRefList.HEADER.format, "<I")

        ref1 = AnnotationSetRefItem(annotations_off=Offset[AnnotationSetItem](0x1000))
        ref2 = AnnotationSetRefItem(annotations_off=Offset[AnnotationSetItem](0x2000))
        ref_list = AnnotationSetRefList(list=(ref1, ref2))

        with self.assertRaises((TypeError, AttributeError)):
            ref_list.size = 3  # type: ignore[misc]

        self.assertEqual(ref_list.__slots__, ("list",))
        self.assertEqual(len(ref_list), 2)
        self.assertEqual(ref_list[0], ref1)
        self.assertEqual(ref_list[1], ref2)
        self.assertEqual(ref_list[0:1], (ref1,))
        self.assertEqual(list(ref_list), [ref1, ref2])

        raw = ref_list.to_bytes()
        self.assertEqual(len(raw), 4 + 2 * 4)

        parsed = AnnotationSetRefList.from_buffer(raw)
        self.assertEqual(parsed, ref_list)

    def test_field_method_parameter_annotation(self) -> None:
        """Verify FieldAnnotation, MethodAnnotation, ParameterAnnotation structs and roundtrip."""
        self.assertEqual(FieldAnnotation.STRUCT.format, "<II")
        self.assertEqual(MethodAnnotation.STRUCT.format, "<II")
        self.assertEqual(ParameterAnnotation.STRUCT.format, "<II")

        fa = FieldAnnotation(
            field_idx=Idx[FieldIdItem](1),
            annotations_off=Offset[AnnotationSetItem](0x100),
        )
        ma = MethodAnnotation(
            method_idx=Idx[MethodIdItem](2),
            annotations_off=Offset[AnnotationSetItem](0x200),
        )
        pa = ParameterAnnotation(
            method_idx=Idx[MethodIdItem](3),
            annotations_off=Offset[AnnotationSetRefList](0x300),
        )

        with self.assertRaises(FrozenInstanceError):
            fa.field_idx = Idx[FieldIdItem](10)  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            ma.method_idx = Idx[MethodIdItem](20)  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            pa.method_idx = Idx[MethodIdItem](30)  # type: ignore[misc]

        self.assertEqual(fa.__slots__, ("field_idx", "annotations_off"))
        self.assertEqual(ma.__slots__, ("method_idx", "annotations_off"))
        self.assertEqual(pa.__slots__, ("method_idx", "annotations_off"))

        self.assertEqual(FieldAnnotation.from_buffer(fa.to_bytes()), fa)
        self.assertEqual(MethodAnnotation.from_buffer(ma.to_bytes()), ma)
        self.assertEqual(ParameterAnnotation.from_buffer(pa.to_bytes()), pa)

    def test_annotations_directory_item(self) -> None:
        """Verify AnnotationsDirectoryItem padding, struct, immutability, and roundtrip."""
        self.assertEqual(AnnotationsDirectoryItem.PADDING, 4)
        self.assertEqual(AnnotationsDirectoryItem.HEADER.format, "<4I")

        fa = FieldAnnotation(
            field_idx=Idx[FieldIdItem](1),
            annotations_off=Offset[AnnotationSetItem](0x100),
        )
        ma = MethodAnnotation(
            method_idx=Idx[MethodIdItem](2),
            annotations_off=Offset[AnnotationSetItem](0x200),
        )
        pa = ParameterAnnotation(
            method_idx=Idx[MethodIdItem](3),
            annotations_off=Offset[AnnotationSetRefList](0x300),
        )

        dir_item = AnnotationsDirectoryItem(
            class_annotations_off=Offset[AnnotationSetItem](0x500),
            field_annotations=(fa,),
            method_annotations=(ma,),
            parameter_annotations=(pa,),
        )

        self.assertEqual(dir_item.fields_size, 1)
        self.assertEqual(dir_item.annotated_methods_size, 1)
        self.assertEqual(dir_item.annotated_parameters_size, 1)

        with self.assertRaises((TypeError, AttributeError)):
            dir_item.fields_size = 2  # type: ignore[misc]

        self.assertEqual(
            dir_item.__slots__,
            (
                "class_annotations_off",
                "field_annotations",
                "method_annotations",
                "parameter_annotations",
            ),
        )

        raw = dir_item.to_bytes()
        self.assertEqual(len(raw), 16 + 8 + 8 + 8)

        parsed = AnnotationsDirectoryItem.from_buffer(raw)
        self.assertEqual(parsed, dir_item)


class TestHiddenapiClassDataItem(unittest.TestCase):
    def test_restriction_flag_enum(self) -> None:
        """Verify HiddenapiRestrictionFlag enum values."""
        self.assertEqual(HiddenapiRestrictionFlag.WHITELIST, 0)
        self.assertEqual(HiddenapiRestrictionFlag.GREYLIST, 1)
        self.assertEqual(HiddenapiRestrictionFlag.BLACKLIST, 2)
        self.assertEqual(HiddenapiRestrictionFlag.GREYLIST_MAX_O, 3)
        self.assertEqual(HiddenapiRestrictionFlag.GREYLIST_MAX_P, 4)
        self.assertEqual(HiddenapiRestrictionFlag.GREYLIST_MAX_Q, 5)
        self.assertEqual(HiddenapiRestrictionFlag.GREYLIST_MAX_R, 6)

    def test_padding_and_fields(self) -> None:
        """Verify PADDING class attribute, slots, and frozen immutability."""
        self.assertEqual(HiddenapiClassDataItem.PADDING, 4)

        item = HiddenapiClassDataItem(data=memoryview(b"\x00" * 8))
        with self.assertRaises(FrozenInstanceError):
            item.data = memoryview(b"")  # type: ignore[misc]

        with self.assertRaises((TypeError, AttributeError)):
            item.size = 10  # type: ignore[misc]

        self.assertEqual(item.__slots__, ("data",))

        field_names = [f.name for f in dataclasses.fields(HiddenapiClassDataItem)]
        self.assertEqual(field_names, ["data"])

    def test_from_class_flags_factory_and_access_api(self) -> None:
        """Verify creation via from_class_flags and query methods."""
        class_flags_input = [
            None,  # class 0: default 0 offset
            [0, 0],  # class 1: all zeros -> offset 0
            [
                HiddenapiRestrictionFlag.GREYLIST,
                HiddenapiRestrictionFlag.GREYLIST_MAX_P,
            ],  # class 2: non-zero flags (1, 4)
            [
                HiddenapiRestrictionFlag.WHITELIST,
                HiddenapiRestrictionFlag.BLACKLIST,
                HiddenapiRestrictionFlag.GREYLIST_MAX_R,
            ],  # class 3: flags (0, 2, 6)
        ]

        item = HiddenapiClassDataItem.from_class_flags(class_flags_input)

        # Offsets table size = 4 classes * 4 bytes = 16 bytes.
        # Header = 4 bytes. Total section size = 4 + len(item.data)
        self.assertEqual(item.size, 4 + len(item.data))

        # Class 0: offset 0 -> whitelist defaults
        self.assertEqual(item.get_offset(0), 0)
        self.assertEqual(item.get_flags(0, count=3), (0, 0, 0))

        # Class 1: offset 0 (all zeros input)
        self.assertEqual(item.get_offset(1), 0)
        self.assertEqual(item.get_flags(1, count=2), (0, 0))

        # Class 2: non-zero offset
        off2 = item.get_offset(2)
        self.assertGreater(off2, 0)
        self.assertEqual(item.get_flags(2, count=2), (1, 4))
        self.assertEqual(
            list(item.iter_flags(2, count=2)),
            [HiddenapiRestrictionFlag.GREYLIST, HiddenapiRestrictionFlag.GREYLIST_MAX_P],
        )

        # Class 3: non-zero offset
        off3 = item.get_offset(3)
        self.assertGreater(off3, off2)
        self.assertEqual(item.get_flags(3, count=3), (0, 2, 6))

    def test_parsing_serialization_roundtrip(self) -> None:
        """Verify from_cursor, from_buffer, and to_bytes roundtrip."""
        item = HiddenapiClassDataItem.from_class_flags(
            [
                [HiddenapiRestrictionFlag.BLACKLIST],
                [HiddenapiRestrictionFlag.GREYLIST_MAX_O, HiddenapiRestrictionFlag.WHITELIST],
            ]
        )

        raw = item.to_bytes()
        self.assertEqual(len(raw), item.size)

        parsed_cursor = HiddenapiClassDataItem.from_cursor(Cursor(raw))
        self.assertEqual(bytes(parsed_cursor.data), bytes(item.data))
        self.assertEqual(parsed_cursor.size, item.size)
        self.assertEqual(parsed_cursor.get_flags(0, count=1), (2,))
        self.assertEqual(parsed_cursor.get_flags(1, count=2), (3, 0))

        buf = b"\x00" * 12 + raw
        parsed_buf = HiddenapiClassDataItem.from_buffer(buf, Offset[HiddenapiClassDataItem](12))
        self.assertEqual(bytes(parsed_buf.data), bytes(item.data))

    def test_index_error_handling(self) -> None:
        """Verify IndexError raised for invalid class_idx."""
        item = HiddenapiClassDataItem.from_class_flags([[1], [2]])

        with self.assertRaises(IndexError):
            item.get_offset(-1)

        with self.assertRaises(IndexError):
            item.get_offset(2)  # Only classes 0 and 1 exist

        with self.assertRaises(IndexError):
            item.get_flags(10, count=1)

    def test_invalid_cursor_size(self) -> None:
        """Verify ValueError raised when size header < 4."""
        invalid_bytes = struct.pack("<I", 2)
        cursor = Cursor(invalid_bytes)
        with self.assertRaises(ValueError):
            HiddenapiClassDataItem.from_cursor(cursor)


class TestMapListAndItems(unittest.TestCase):
    def test_item_type_enum_and_alias(self) -> None:
        """Verify ItemType DEX section type codes and MapItemType alias."""
        self.assertIs(MapItemType, ItemType)

        expected_values = {
            "HEADER_ITEM": 0x0000,
            "STRING_ID_ITEM": 0x0001,
            "TYPE_ID_ITEM": 0x0002,
            "PROTO_ID_ITEM": 0x0003,
            "FIELD_ID_ITEM": 0x0004,
            "METHOD_ID_ITEM": 0x0005,
            "CLASS_DEF_ITEM": 0x0006,
            "CALL_SITE_ID_ITEM": 0x0007,
            "METHOD_HANDLE_ITEM": 0x0008,
            "MAP_LIST": 0x1000,
            "TYPE_LIST": 0x1001,
            "ANNOTATION_SET_REF_LIST": 0x1002,
            "ANNOTATION_SET_ITEM": 0x1003,
            "CLASS_DATA_ITEM": 0x2000,
            "CODE_ITEM": 0x2001,
            "STRING_DATA_ITEM": 0x2002,
            "DEBUG_INFO_ITEM": 0x2003,
            "ANNOTATION_ITEM": 0x2004,
            "ENCODED_ARRAY_ITEM": 0x2005,
            "ANNOTATIONS_DIRECTORY_ITEM": 0x2006,
            "HIDDENAPI_CLASS_DATA_ITEM": 0xF000,
        }

        self.assertEqual(len(ItemType), 21)
        for name, expected_val in expected_values.items():
            member = getattr(ItemType, name)
            self.assertEqual(member, expected_val)
            self.assertEqual(member.value, expected_val)

    def test_map_item_attributes_slots_immutability(self) -> None:
        """Verify MapItem padding, struct format, slots, default unused, and immutability."""
        self.assertEqual(MapItem.PADDING, 4)
        self.assertEqual(MapItem.STRUCT.format, "<HHII")

        item = MapItem(item_type=ItemType.HEADER_ITEM, size=1, offset=Offset[Any](0))
        self.assertEqual(item.item_type, 0x0000)
        self.assertEqual(item.size, 1)
        self.assertEqual(item.offset, Offset[Any](0))
        self.assertEqual(item.unused, 0)

        with self.assertRaises(FrozenInstanceError):
            item.item_type = ItemType.STRING_ID_ITEM  # type: ignore[misc]

        self.assertEqual(item.__slots__, ("item_type", "size", "offset", "unused"))

    def test_map_item_roundtrip_and_buffer(self) -> None:
        """Verify MapItem serialization roundtrip and buffer parsing."""
        item = MapItem(
            item_type=ItemType.STRING_ID_ITEM,
            size=10,
            offset=Offset[Any](0x100),
            unused=0,
        )
        raw = item.to_bytes()
        self.assertEqual(len(raw), 12)

        cursor = Cursor(raw)
        parsed = MapItem.from_cursor(cursor)
        self.assertEqual(parsed, item)

        buf = b"\x00" * 8 + raw
        from_buf = MapItem.from_buffer(buf, Offset[MapItem](8))
        self.assertEqual(from_buf, item)

    def test_map_list(self) -> None:
        """Verify MapList padding, header, size property, collection interface, and get lookup."""
        self.assertEqual(MapList.PADDING, 4)
        self.assertEqual(MapList.HEADER.format, "<I")
        self.assertIs(MapList.Item, MapItem)

        # Empty MapList
        empty = MapList(list=())
        self.assertEqual(empty.size, 0)
        self.assertEqual(len(empty), 0)
        self.assertEqual(list(empty), [])
        self.assertIsNone(empty.get(ItemType.HEADER_ITEM))

        raw_empty = empty.to_bytes()
        self.assertEqual(raw_empty, struct.pack("<I", 0))
        self.assertEqual(MapList.from_buffer(raw_empty), empty)

        # Multi-item MapList
        item1 = MapItem(item_type=ItemType.HEADER_ITEM, size=1, offset=Offset[Any](0))
        item2 = MapItem(item_type=ItemType.STRING_ID_ITEM, size=5, offset=Offset[Any](0x70))
        item3 = MapItem(item_type=ItemType.TYPE_ID_ITEM, size=2, offset=Offset[Any](0x84))

        map_list = MapList(list=(item1, item2, item3))

        self.assertEqual(map_list.size, 3)
        self.assertEqual(len(map_list), 3)
        self.assertEqual(map_list[0], item1)
        self.assertEqual(map_list[1], item2)
        self.assertEqual(map_list[1:], (item2, item3))
        self.assertEqual(list(map_list), [item1, item2, item3])

        # Property immutability
        with self.assertRaises((TypeError, AttributeError)):
            map_list.size = 10  # type: ignore[misc]

        # Get lookup by ItemType and int
        self.assertEqual(map_list.get(ItemType.HEADER_ITEM), item1)
        self.assertEqual(map_list.get(0x0001), item2)
        self.assertEqual(map_list.get(ItemType.STRING_ID_ITEM), item2)
        self.assertIsNone(map_list.get(ItemType.CLASS_DEF_ITEM))

        # Roundtrip
        raw = map_list.to_bytes()
        self.assertEqual(len(raw), 4 + 3 * 12)

        cursor = Cursor(raw)
        parsed = MapList.from_cursor(cursor)
        self.assertEqual(parsed, map_list)

        buf = b"PADDING_" + raw
        from_buf = MapList.from_buffer(buf, Offset[MapList](8))
        self.assertEqual(from_buf, map_list)


if __name__ == "__main__":
    unittest.main()
