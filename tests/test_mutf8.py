"""Unit tests for MUTF-8 encoding, decoding, and Cursor MUTF-8 operations."""

import unittest

from dexbuf.cursor import Cursor
from dexbuf.mutf8 import (
    count_mutf8_utf16_units,
    decode_mutf8,
    decode_mutf8_utf16_units,
    encode_mutf8,
    utf16_code_units,
)


class TestMUTF8(unittest.TestCase):
    def test_utf16_code_units(self) -> None:
        """Test counting UTF-16 code units for various string compositions."""
        self.assertEqual(utf16_code_units("Hello"), 5)
        self.assertEqual(utf16_code_units("Café"), 4)
        self.assertEqual(utf16_code_units("a\x00b"), 3)
        self.assertEqual(utf16_code_units("𐀀"), 2)  # U+10000 -> 2 UTF-16 code units
        self.assertEqual(utf16_code_units("𐀀Hello"), 7)
        self.assertEqual(utf16_code_units("\ud800"), 1)  # Isolated surrogate

    def test_encode_mutf8_ascii(self) -> None:
        """Test MUTF-8 encoding for standard ASCII strings."""
        encoded_null = encode_mutf8("DEX", null_terminated=True)
        self.assertEqual(encoded_null, b"DEX\x00")

        encoded_no_null = encode_mutf8("DEX", null_terminated=False)
        self.assertEqual(encoded_no_null, b"DEX")

    def test_encode_mutf8_embedded_null(self) -> None:
        """Test MUTF-8 encoding for U+0000 character (must encode as 0xC0 0x80)."""
        encoded = encode_mutf8("\x00", null_terminated=True)
        self.assertEqual(encoded, b"\xc0\x80\x00")

    def test_encode_mutf8_multabyte(self) -> None:
        """Test MUTF-8 encoding for 2-byte, 3-byte, and supplementary surrogate pairs."""
        # 'é' (U+00E9): 2-byte
        self.assertEqual(encode_mutf8("é", null_terminated=True), b"\xc3\xa9\x00")

        # '中' (U+4E2D): 3-byte
        self.assertEqual(encode_mutf8("中", null_terminated=True), b"\xe4\xb8\xad\x00")

        # '𐀀' (U+10000): surrogate pair -> 2 * 3-byte sequences = 6 bytes
        expected_supp = b"\xed\xa0\x80\xed\xb0\x80\x00"
        self.assertEqual(encode_mutf8("𐀀", null_terminated=True), expected_supp)

    def test_encode_mutf8_isolated_surrogate(self) -> None:
        """Test MUTF-8 encoding preserves isolated surrogate code units."""
        encoded = encode_mutf8("\ud800", null_terminated=True)
        self.assertEqual(encoded, b"\xed\xa0\x80\x00")

    def test_decode_mutf8_and_utf16_units(self) -> None:
        """Test decode_mutf8, decode_mutf8_utf16_units, and count_mutf8_utf16_units."""
        cases = [
            ("Hello", b"Hello", (72, 101, 108, 108, 111)),
            ("Café", b"Caf\xc3\xa9", (67, 97, 102, 0x00E9)),
            ("a\x00b", b"a\xc0\x80b", (97, 0, 98)),
            ("𐀀", b"\xed\xa0\x80\xed\xb0\x80", (0xD800, 0xDC00)),
        ]

        for s, raw, expected_units in cases:
            self.assertEqual(decode_mutf8(raw), s)
            self.assertEqual(decode_mutf8_utf16_units(raw), expected_units)
            self.assertEqual(count_mutf8_utf16_units(raw), len(expected_units))

    def test_cursor_read_mutf8_slice_size_hint(self) -> None:
        """Test Cursor.read_mutf8_slice with O(1) size hint and non-ASCII skip scanning."""
        # 1. ASCII with size_hint matching
        buf1 = b"HelloWorld\x00Extra"
        c1 = Cursor(buf1)
        slice1 = c1.read_mutf8_slice(size_hint=10)
        self.assertEqual(bytes(slice1), b"HelloWorld")
        self.assertEqual(c1.tell(), 11)

        # 2. Non-ASCII multi-byte string where size_hint skips start of scan
        # "Café" -> MUTF-8 bytes: b"Caf\xc3\xa9\x00" (5 bytes data + 1 null; utf16_size = 4)
        buf2 = b"Caf\xc3\xa9\x00Tail"
        c2 = Cursor(buf2)
        slice2 = c2.read_mutf8_slice(size_hint=4)
        self.assertEqual(bytes(slice2), b"Caf\xc3\xa9")
        self.assertEqual(c2.tell(), 6)

        # 3. size_hint is None
        c3 = Cursor(buf1)
        slice3 = c3.read_mutf8_slice(size_hint=None)
        self.assertEqual(bytes(slice3), b"HelloWorld")
        self.assertEqual(c3.tell(), 11)

    def test_cursor_read_mutf8_ascii_fast_path(self) -> None:
        """Test Cursor.read_mutf8 ASCII fast-path when expected_utf16_size is provided."""
        buf = b"HelloWorld\x00Extra"
        c = Cursor(buf)

        res = c.read_mutf8(expected_utf16_size=10)
        self.assertEqual(res, "HelloWorld")
        self.assertEqual(c.tell(), 11)

    def test_cursor_read_mutf8_full_decode(self) -> None:
        """Test Cursor.read_mutf8 for non-ASCII, embedded null, and supplementary strings."""
        cases = [
            ("Hello", 5, b"Hello\x00"),
            ("a\x00b", 3, b"a\xc0\x80b\x00"),
            ("Café", 4, b"Caf\xc3\xa9\x00"),
            ("中文", 2, b"\xe4\xb8\xad\xe6\x96\x87\x00"),
            ("𐀀", 2, b"\xed\xa0\x80\xed\xb0\x80\x00"),
            ("\ud800", 1, b"\xed\xa0\x80\x00"),
        ]

        for s, expected_len, raw in cases:
            c = Cursor(raw)
            decoded = c.read_mutf8()
            self.assertEqual(decoded, s)
            self.assertTrue(c.is_eof)

            # Test with expected_utf16_size
            c_sized = Cursor(raw)
            decoded_sized = c_sized.read_mutf8(expected_utf16_size=expected_len)
            self.assertEqual(decoded_sized, s)
            self.assertTrue(c_sized.is_eof)

    def test_cursor_read_mutf8_length_mismatch(self) -> None:
        """Test that read_mutf8 raises ValueError if expected_utf16_size does not match."""
        c = Cursor(b"Hello\x00")
        with self.assertRaises(ValueError):
            c.read_mutf8(expected_utf16_size=3)

    def test_cursor_read_mutf8_missing_null_terminator(self) -> None:
        """Test that read_mutf8 raises EOFError when null terminator is missing."""
        c = Cursor(b"Unterminated")
        with self.assertRaises(EOFError):
            c.read_mutf8()

    def test_cursor_read_mutf8_invalid_sequence(self) -> None:
        """Test that invalid byte sequences raise ValueError or EOFError."""
        # Invalid start byte (e.g. 0xF8)
        c1 = Cursor(b"\xf8\x00")
        with self.assertRaises(ValueError):
            c1.read_mutf8()

        # Invalid continuation byte in 2-byte sequence
        c2 = Cursor(b"\xc3\x00")
        with self.assertRaises(ValueError):
            c2.read_mutf8()

        # Truncated 3-byte sequence
        c3 = Cursor(b"\xe4\xb8")
        with self.assertRaises(EOFError):
            c3.read_mutf8()


if __name__ == "__main__":
    unittest.main()
