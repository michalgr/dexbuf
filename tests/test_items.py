"""Unit tests for StringDataItem and DEX spec items."""

import dataclasses
import struct
import unittest
from dataclasses import FrozenInstanceError

from dexbuf import (
    NO_OFFSET,
    FieldIdItem,
    MethodIdItem,
    Offset,
    StringDataItem,
    StringIdItem,
    TypeIdItem,
    TypeList,
)
from dexbuf.cursor import Cursor
from dexbuf.items import ProtoIdItem
from dexbuf.types import Idx


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
    def test_class_attributes_and_fields(self) -> None:
        self.assertEqual(StringIdItem.PADDING, 4)
        self.assertEqual(StringIdItem.STRUCT.format, "<I")

        field_names = [f.name for f in dataclasses.fields(StringIdItem)]
        self.assertEqual(field_names, ["string_data_off"])
        self.assertNotIn("PADDING", field_names)
        self.assertNotIn("STRUCT", field_names)

    def test_immutability(self) -> None:
        item = StringIdItem(string_data_off=Offset[StringDataItem](0x100))
        with self.assertRaises(FrozenInstanceError):
            item.string_data_off = Offset[StringDataItem](0x200)  # type: ignore[misc]

        self.assertEqual(item.__slots__, ("string_data_off",))

    def test_to_bytes_and_from_cursor(self) -> None:
        original = StringIdItem(string_data_off=Offset[StringDataItem](0x12345678))
        raw = original.to_bytes()
        self.assertEqual(raw, struct.pack("<I", 0x12345678))

        cursor = Cursor(raw)
        parsed = StringIdItem.from_cursor(cursor)
        self.assertEqual(parsed, original)
        self.assertEqual(parsed.string_data_off, Offset[StringDataItem](0x12345678))
        self.assertTrue(cursor.is_eof)

    def test_from_buffer_with_typed_offset(self) -> None:
        item1 = StringIdItem(string_data_off=Offset[StringDataItem](0x10))
        item2 = StringIdItem(string_data_off=Offset[StringDataItem](0x20))
        buf = item1.to_bytes() + item2.to_bytes()

        parsed1 = StringIdItem.from_buffer(buf, NO_OFFSET)
        self.assertEqual(parsed1, item1)

        offset2 = Offset[StringIdItem](len(item1.to_bytes()))
        parsed2 = StringIdItem.from_buffer(buf, offset2)
        self.assertEqual(parsed2, item2)


class TestTypeIdItem(unittest.TestCase):
    def test_class_attributes_and_fields(self) -> None:
        self.assertEqual(TypeIdItem.PADDING, 4)
        self.assertEqual(TypeIdItem.STRUCT.format, "<I")

        field_names = [f.name for f in dataclasses.fields(TypeIdItem)]
        self.assertEqual(field_names, ["descriptor_idx"])
        self.assertNotIn("PADDING", field_names)
        self.assertNotIn("STRUCT", field_names)

    def test_immutability(self) -> None:
        item = TypeIdItem(descriptor_idx=Idx[StringIdItem](5))
        with self.assertRaises(FrozenInstanceError):
            item.descriptor_idx = Idx[StringIdItem](10)  # type: ignore[misc]

        self.assertEqual(item.__slots__, ("descriptor_idx",))

    def test_to_bytes_and_from_cursor(self) -> None:
        original = TypeIdItem(descriptor_idx=Idx[StringIdItem](42))
        raw = original.to_bytes()
        self.assertEqual(raw, struct.pack("<I", 42))

        cursor = Cursor(raw)
        parsed = TypeIdItem.from_cursor(cursor)
        self.assertEqual(parsed, original)
        self.assertEqual(parsed.descriptor_idx, Idx[StringIdItem](42))
        self.assertTrue(cursor.is_eof)

    def test_from_buffer_with_typed_offset(self) -> None:
        item1 = TypeIdItem(descriptor_idx=Idx[StringIdItem](1))
        item2 = TypeIdItem(descriptor_idx=Idx[StringIdItem](2))
        buf = item1.to_bytes() + item2.to_bytes()

        parsed1 = TypeIdItem.from_buffer(buf, NO_OFFSET)
        self.assertEqual(parsed1, item1)

        offset2 = Offset[TypeIdItem](len(item1.to_bytes()))
        parsed2 = TypeIdItem.from_buffer(buf, offset2)
        self.assertEqual(parsed2, item2)


class TestFieldIdItem(unittest.TestCase):
    def test_class_attributes_and_fields(self) -> None:
        self.assertEqual(FieldIdItem.PADDING, 4)
        self.assertEqual(FieldIdItem.STRUCT.format, "<HHI")

        field_names = [f.name for f in dataclasses.fields(FieldIdItem)]
        self.assertEqual(field_names, ["class_idx", "type_idx", "name_idx"])
        self.assertNotIn("PADDING", field_names)
        self.assertNotIn("STRUCT", field_names)

    def test_immutability(self) -> None:
        item = FieldIdItem(
            class_idx=Idx[TypeIdItem](1),
            type_idx=Idx[TypeIdItem](2),
            name_idx=Idx[StringIdItem](3),
        )
        with self.assertRaises(FrozenInstanceError):
            item.class_idx = Idx[TypeIdItem](4)  # type: ignore[misc]

        self.assertEqual(item.__slots__, ("class_idx", "type_idx", "name_idx"))

    def test_to_bytes_and_from_cursor(self) -> None:
        original = FieldIdItem(
            class_idx=Idx[TypeIdItem](10),
            type_idx=Idx[TypeIdItem](20),
            name_idx=Idx[StringIdItem](300),
        )
        raw = original.to_bytes()
        self.assertEqual(raw, struct.pack("<HHI", 10, 20, 300))

        cursor = Cursor(raw)
        parsed = FieldIdItem.from_cursor(cursor)
        self.assertEqual(parsed, original)
        self.assertTrue(cursor.is_eof)

    def test_from_buffer_with_typed_offset(self) -> None:
        item1 = FieldIdItem(
            class_idx=Idx[TypeIdItem](1),
            type_idx=Idx[TypeIdItem](2),
            name_idx=Idx[StringIdItem](3),
        )
        item2 = FieldIdItem(
            class_idx=Idx[TypeIdItem](4),
            type_idx=Idx[TypeIdItem](5),
            name_idx=Idx[StringIdItem](6),
        )
        buf = item1.to_bytes() + item2.to_bytes()

        parsed1 = FieldIdItem.from_buffer(buf, NO_OFFSET)
        self.assertEqual(parsed1, item1)

        offset2 = Offset[FieldIdItem](len(item1.to_bytes()))
        parsed2 = FieldIdItem.from_buffer(buf, offset2)
        self.assertEqual(parsed2, item2)


class TestMethodIdItem(unittest.TestCase):
    def test_class_attributes_and_fields(self) -> None:
        self.assertEqual(MethodIdItem.PADDING, 4)
        self.assertEqual(MethodIdItem.STRUCT.format, "<HHI")

        field_names = [f.name for f in dataclasses.fields(MethodIdItem)]
        self.assertEqual(field_names, ["class_idx", "proto_idx", "name_idx"])
        self.assertNotIn("PADDING", field_names)
        self.assertNotIn("STRUCT", field_names)

    def test_immutability(self) -> None:
        item = MethodIdItem(
            class_idx=Idx[TypeIdItem](1),
            proto_idx=Idx[ProtoIdItem](2),
            name_idx=Idx[StringIdItem](3),
        )
        with self.assertRaises(FrozenInstanceError):
            item.class_idx = Idx[TypeIdItem](4)  # type: ignore[misc]

        self.assertEqual(item.__slots__, ("class_idx", "proto_idx", "name_idx"))

    def test_to_bytes_and_from_cursor(self) -> None:
        original = MethodIdItem(
            class_idx=Idx[TypeIdItem](15),
            proto_idx=Idx[ProtoIdItem](25),
            name_idx=Idx[StringIdItem](350),
        )
        raw = original.to_bytes()
        self.assertEqual(raw, struct.pack("<HHI", 15, 25, 350))

        cursor = Cursor(raw)
        parsed = MethodIdItem.from_cursor(cursor)
        self.assertEqual(parsed, original)
        self.assertTrue(cursor.is_eof)

    def test_from_buffer_with_typed_offset(self) -> None:
        item1 = MethodIdItem(
            class_idx=Idx[TypeIdItem](1),
            proto_idx=Idx[ProtoIdItem](2),
            name_idx=Idx[StringIdItem](3),
        )
        item2 = MethodIdItem(
            class_idx=Idx[TypeIdItem](4),
            proto_idx=Idx[ProtoIdItem](5),
            name_idx=Idx[StringIdItem](6),
        )
        buf = item1.to_bytes() + item2.to_bytes()

        parsed1 = MethodIdItem.from_buffer(buf, NO_OFFSET)
        self.assertEqual(parsed1, item1)

        offset2 = Offset[MethodIdItem](len(item1.to_bytes()))
        parsed2 = MethodIdItem.from_buffer(buf, offset2)
        self.assertEqual(parsed2, item2)


class TestTypeList(unittest.TestCase):
    def test_class_attributes_and_fields(self) -> None:
        self.assertEqual(TypeList.PADDING, 4)
        self.assertEqual(TypeList.HEADER.format, "<I")
        self.assertEqual(TypeList.Item.STRUCT.format, "<H")

        field_names = [f.name for f in dataclasses.fields(TypeList)]
        self.assertEqual(field_names, ["size", "list"])
        self.assertNotIn("PADDING", field_names)
        self.assertNotIn("HEADER", field_names)

        item_field_names = [f.name for f in dataclasses.fields(TypeList.Item)]
        self.assertEqual(item_field_names, ["type_idx"])
        self.assertNotIn("STRUCT", item_field_names)

    def test_immutability(self) -> None:
        item = TypeList.Item(type_idx=Idx[TypeIdItem](1))
        with self.assertRaises(FrozenInstanceError):
            item.type_idx = Idx[TypeIdItem](2)  # type: ignore[misc]
        self.assertEqual(item.__slots__, ("type_idx",))

        type_list = TypeList(size=1, list=(item,))
        with self.assertRaises(FrozenInstanceError):
            type_list.size = 2  # type: ignore[misc]
        self.assertEqual(type_list.__slots__, ("size", "list"))

    def test_empty_typelist(self) -> None:
        empty = TypeList(size=0, list=())
        self.assertEqual(len(empty), 0)
        self.assertEqual(list(empty), [])
        self.assertEqual(empty.to_bytes(), struct.pack("<I", 0))

        parsed = TypeList.from_buffer(empty.to_bytes())
        self.assertEqual(parsed, empty)

    def test_multi_item_typelist_and_container_ergonomics(self) -> None:
        item1 = TypeList.Item(type_idx=Idx[TypeIdItem](10))
        item2 = TypeList.Item(type_idx=Idx[TypeIdItem](20))
        item3 = TypeList.Item(type_idx=Idx[TypeIdItem](30))

        tl = TypeList(size=3, list=(item1, item2, item3))

        # __len__
        self.assertEqual(len(tl), 3)

        # __iter__
        self.assertEqual(list(tl), [item1, item2, item3])

        # __getitem__
        self.assertEqual(tl[0], item1)
        self.assertEqual(tl[1], item2)
        self.assertEqual(tl[2], item3)
        self.assertEqual(tl[0:2], (item1, item2))

        # to_bytes & from_cursor/from_buffer roundtrip
        raw = tl.to_bytes()
        expected_raw = struct.pack("<I", 3) + struct.pack("<HHH", 10, 20, 30)
        self.assertEqual(raw, expected_raw)

        cursor = Cursor(raw)
        parsed = TypeList.from_cursor(cursor)
        self.assertEqual(parsed, tl)
        self.assertTrue(cursor.is_eof)

    def test_from_buffer_with_typed_offset(self) -> None:
        tl1 = TypeList(size=1, list=(TypeList.Item(type_idx=Idx[TypeIdItem](1)),))
        tl2 = TypeList(
            size=2,
            list=(
                TypeList.Item(type_idx=Idx[TypeIdItem](2)),
                TypeList.Item(type_idx=Idx[TypeIdItem](3)),
            ),
        )
        buf = tl1.to_bytes() + tl2.to_bytes()

        parsed1 = TypeList.from_buffer(buf, NO_OFFSET)
        self.assertEqual(parsed1, tl1)

        offset2 = Offset[TypeList](len(tl1.to_bytes()))
        parsed2 = TypeList.from_buffer(buf, offset2)
        self.assertEqual(parsed2, tl2)


if __name__ == "__main__":
    unittest.main()
