"""Unit tests for DEX spec items."""

import dataclasses
import struct
import unittest
from dataclasses import FrozenInstanceError

from dexbuf import (
    NO_OFFSET,
    FieldIdItem,
    Idx,
    MethodIdItem,
    Offset,
    ProtoIdItem,
    StringDataItem,
    StringIdItem,
    TypeIdItem,
    TypeList,
)
from dexbuf.cursor import Cursor


class TestStringDataItem(unittest.TestCase):
    def test_from_str(self) -> None:
        """Test StringDataItem creation from string."""
        item = StringDataItem.from_str("Hello, DEX!")
        self.assertEqual(item.utf16_size, 11)
        self.assertEqual(item.data, "Hello, DEX!")

        supp_item = StringDataItem.from_str("𐀀World")
        self.assertEqual(supp_item.utf16_size, 7)
        self.assertEqual(supp_item.data, "𐀀World")

    def test_padding_attribute(self) -> None:
        """Test StringDataItem PADDING class attribute and fields metadata."""
        self.assertEqual(StringDataItem.PADDING, 1)

        # Verify PADDING is not in dataclasses.fields
        field_names = [f.name for f in dataclasses.fields(StringDataItem)]
        self.assertEqual(field_names, ["utf16_size", "data"])
        self.assertNotIn("PADDING", field_names)

    def test_immutability(self) -> None:
        """Test that StringDataItem is frozen and slotted."""
        item = StringDataItem.from_str("Frozen")
        with self.assertRaises(FrozenInstanceError):
            item.data = "Modified"  # type: ignore[misc]

        # Verify __slots__ is set on the class
        self.assertEqual(item.__slots__, ("utf16_size", "data"))

    def test_to_bytes_and_from_cursor(self) -> None:
        """Test encoding StringDataItem to bytes and parsing via Cursor."""
        original = StringDataItem.from_str("Café 𐀀")
        raw = original.to_bytes()

        cursor = Cursor(raw)
        parsed = StringDataItem.from_cursor(cursor)

        self.assertEqual(parsed, original)
        self.assertEqual(parsed.utf16_size, 7)
        self.assertEqual(parsed.data, "Café 𐀀")
        self.assertTrue(cursor.is_eof)

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
            self.assertEqual(decoded.data, s)


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
        self.assertEqual(type_list_fields, ["size", "list"])
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

        type_list = TypeList(size=1, list=(item,))
        with self.assertRaises(FrozenInstanceError):
            type_list.size = 2  # type: ignore[misc]
        self.assertEqual(type_list.__slots__, ("size", "list"))

    def test_empty_list(self) -> None:
        empty = TypeList(size=0, list=())
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
        type_list = TypeList(size=3, list=items)

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


if __name__ == "__main__":
    unittest.main()
