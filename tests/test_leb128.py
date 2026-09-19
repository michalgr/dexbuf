"""Unit tests for LEB128 encoding and Cursor LEB128 decoding."""

import unittest

from dexbuf.cursor import Cursor
from dexbuf.leb128 import encode_sleb128, encode_uleb128, encode_uleb128p1
from dexbuf.types import NO_INDEX


class TestLEB128(unittest.TestCase):
    def test_uleb128_spec_examples(self) -> None:
        """Test ULEB128 encoding and decoding with spec table examples."""
        spec_table = [
            (0, b"\x00"),
            (1, b"\x01"),
            (0x7F, b"\x7f"),
            (0x80, b"\x80\x01"),
            (0x81, b"\x81\x01"),
            (16256, b"\x80\x7f"),
            (16384, b"\x80\x80\x01"),
            (0xFFFFFFFF, b"\xff\xff\xff\xff\x0f"),
        ]

        for val, expected_bytes in spec_table:
            encoded = encode_uleb128(val)
            self.assertEqual(encoded, expected_bytes, f"ULEB128 encode mismatch for {val}")

            cursor = Cursor(expected_bytes)
            decoded = cursor.read_uleb128()
            self.assertEqual(decoded, val, f"ULEB128 decode mismatch for {expected_bytes!r}")
            self.assertTrue(cursor.is_eof)

    def test_uleb128p1_spec_examples(self) -> None:
        """Test uleb128p1 encoding and decoding."""
        test_cases = [
            (-1, b"\x00"),
            (0, b"\x01"),
            (127, b"\x80\x01"),
            (0xFFFFFFFF - 1, b"\xff\xff\xff\xff\x0f"),
        ]

        for val, expected_bytes in test_cases:
            encoded = encode_uleb128p1(val)
            self.assertEqual(encoded, expected_bytes, f"ULEB128p1 encode mismatch for {val}")

            cursor = Cursor(expected_bytes)
            decoded = cursor.read_uleb128p1()
            self.assertEqual(decoded, val, f"ULEB128p1 decode mismatch for {expected_bytes!r}")
            self.assertTrue(cursor.is_eof)

    def test_uleb128p1_no_index(self) -> None:
        """Test uleb128p1 encoding with NO_INDEX."""
        encoded = encode_uleb128p1(NO_INDEX)
        self.assertEqual(encoded, b"\x00")

        cursor = Cursor(b"\x00")
        decoded = cursor.read_uleb128p1()
        self.assertEqual(decoded, -1)

    def test_sleb128_spec_examples(self) -> None:
        """Test SLEB128 encoding and decoding with spec table examples."""
        spec_table = [
            (0, b"\x00"),
            (1, b"\x01"),
            (63, b"\x3f"),
            (-64, b"\x40"),
            (-1, b"\x7f"),
            (128, b"\x80\x01"),
            (-128, b"\x80\x7f"),
        ]

        for val, expected_bytes in spec_table:
            encoded = encode_sleb128(val)
            self.assertEqual(encoded, expected_bytes, f"SLEB128 encode mismatch for {val}")

            cursor = Cursor(expected_bytes)
            decoded = cursor.read_sleb128()
            self.assertEqual(decoded, val, f"SLEB128 decode mismatch for {expected_bytes!r}")
            self.assertTrue(cursor.is_eof)

    def test_sleb128_non_canonical_decoding(self) -> None:
        """Test decoding multi-byte sign-extended SLEB128 representations."""
        # b"\xff\x7f" is sign-extended -1 in 2 bytes
        cursor = Cursor(b"\xff\x7f")
        self.assertEqual(cursor.read_sleb128(), -1)

    def test_uleb128_negative_error(self) -> None:
        """Test that encode_uleb128 raises ValueError for negative integers."""
        with self.assertRaises(ValueError):
            encode_uleb128(-1)

    def test_leb128_exceeds_5_bytes(self) -> None:
        """Test that LEB128 reads exceeding 5 bytes raise ValueError."""
        invalid_6bytes = b"\x80\x80\x80\x80\x80\x01"

        c1 = Cursor(invalid_6bytes)
        with self.assertRaises(ValueError):
            c1.read_uleb128()

        c2 = Cursor(invalid_6bytes)
        with self.assertRaises(ValueError):
            c2.read_sleb128()

    def test_leb128_unexpected_eof(self) -> None:
        """Test that incomplete LEB128 streams raise EOFError."""
        incomplete = b"\x80\x80"

        c1 = Cursor(incomplete)
        with self.assertRaises(EOFError):
            c1.read_uleb128()

        c2 = Cursor(incomplete)
        with self.assertRaises(EOFError):
            c2.read_sleb128()


if __name__ == "__main__":
    unittest.main()
