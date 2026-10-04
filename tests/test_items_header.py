"""Unit tests for DEX header items, constants, map lists, and map items."""

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
    NO_OFFSET,
    REVERSE_ENDIAN_CONSTANT,
    SUPPORTED_DEX_VERSIONS,
    ClassDefItem,
    Count,
    FieldIdItem,
    HeaderItem,
    ItemType,
    MapItem,
    MapItemType,
    MapList,
    MethodIdItem,
    Offset,
    ProtoIdItem,
    StringIdItem,
    TypeIdItem,
)
from dexbuf.cursor import Cursor


class TestHeaderItemAndConstants(unittest.TestCase):
    def test_header_constants(self) -> None:
        """Verify header constant values."""
        self.assertEqual(ENDIAN_CONSTANT, 0x1234_5678)
        self.assertEqual(REVERSE_ENDIAN_CONSTANT, 0x7856_3412)
        self.assertEqual(DEX_FILE_MAGIC, b"dex\n035\x00")
        self.assertEqual(SUPPORTED_DEX_VERSIONS, ("035", "037", "038", "039", "040", "041"))
        self.assertEqual(HEADER_SIZE_V40, 0x70)
        self.assertEqual(HEADER_SIZE_V41, 0x78)

    def test_header_item_fields_metadata(self) -> None:
        """Verify HeaderItem field metadata."""
        field_names = [f.name for f in dataclasses.fields(HeaderItem)]
        self.assertIn("magic", field_names)
        self.assertIn("checksum", field_names)
        self.assertIn("container_size", field_names)
        self.assertIn("header_offset", field_names)

    def test_header_item_immutability(self) -> None:
        """Verify HeaderItem frozen immutability."""
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

    def test_map_item_attributes_and_immutability(self) -> None:
        """Verify MapItem attributes, default unused, and immutability."""
        item = MapItem(item_type=ItemType.HEADER_ITEM, size=1, offset=Offset[Any](0))
        self.assertEqual(item.item_type, 0x0000)
        self.assertEqual(item.size, 1)
        self.assertEqual(item.offset, Offset[Any](0))
        self.assertEqual(item.unused, 0)

        with self.assertRaises(FrozenInstanceError):
            item.item_type = ItemType.STRING_ID_ITEM  # type: ignore[misc]

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
        """Verify MapList size property, collection interface, and get lookup."""
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
