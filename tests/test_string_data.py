"""Unit tests for StringDataItem spec record in dexbuf.string_data."""

import unittest
from dataclasses import FrozenInstanceError

from dexbuf.string_data import StringDataItem


class TestStringDataItem(unittest.TestCase):
    def test_properties_and_from_str(self) -> None:
        item = StringDataItem.from_str("Hello 😀")
        self.assertEqual(item.data, "Hello 😀")
        self.assertEqual(item.utf16_size, 8)  # 6 ASCII/space + 2 for 😀

    def test_immutability(self) -> None:
        item = StringDataItem.from_str("Test")
        with self.assertRaises(FrozenInstanceError):
            item.data = "Changed"  # type: ignore[misc]

    def test_to_bytes_and_from_buffer(self) -> None:
        strings = [
            "",
            "Ljava/lang/String;",
            "a\x00b",
            "Hello 😀 World!",
        ]
        for s in strings:
            item = StringDataItem.from_str(s)
            raw = item.to_bytes()
            decoded = StringDataItem.from_buffer(raw)
            self.assertEqual(decoded, item)
            self.assertEqual(decoded.data, s)
            self.assertEqual(decoded.utf16_size, item.utf16_size)

    def test_from_buffer_with_offset(self) -> None:
        item = StringDataItem.from_str("OffsetTest")
        prefix = b"\x12\x34\x56"
        buf = prefix + item.to_bytes() + b"\x78"

        decoded = StringDataItem.from_buffer(buf, offset=3)
        self.assertEqual(decoded, item)


if __name__ == "__main__":
    unittest.main()
