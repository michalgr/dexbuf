"""Unit tests for Cursor binary reader."""

import array
import unittest

from dexbuf.cursor import Cursor


class TestCursor(unittest.TestCase):
    def test_buffer_protocol_support(self) -> None:
        """Test Cursor initialization with various buffer protocol implementations."""
        raw = b"\x01\x02\x03\x04"

        c_bytes = Cursor(raw)
        self.assertEqual(c_bytes.remaining, 4)

        c_bytearray = Cursor(bytearray(raw))
        self.assertEqual(c_bytearray.remaining, 4)

        c_mv = Cursor(memoryview(raw))
        self.assertEqual(c_mv.remaining, 4)

        c_array = Cursor(array.array("B", raw))
        self.assertEqual(c_array.remaining, 4)

    def test_initial_offset_bounds(self) -> None:
        """Test constructor offset bounds checking."""
        raw = b"\x00\x01\x02"
        Cursor(raw, 0)
        Cursor(raw, 3)

        with self.assertRaises(ValueError):
            Cursor(raw, -1)

        with self.assertRaises(ValueError):
            Cursor(raw, 4)

    def test_navigation_and_properties(self) -> None:
        """Test offset, tell, seek, skip, is_eof, and remaining properties/methods."""
        raw = b"\x01\x02\x03\x04\x05"
        c = Cursor(raw)

        self.assertEqual(c.tell(), 0)
        self.assertEqual(c.offset, 0)
        self.assertFalse(c.is_eof)
        self.assertEqual(c.remaining, 5)

        c.skip(2)
        self.assertEqual(c.tell(), 2)
        self.assertEqual(c.remaining, 3)

        c.seek(5)
        self.assertEqual(c.tell(), 5)
        self.assertTrue(c.is_eof)
        self.assertEqual(c.remaining, 0)

        with self.assertRaises(ValueError):
            c.offset = -1

        with self.assertRaises(ValueError):
            c.offset = 6

    def test_numeric_reads(self) -> None:
        """Test unsigned and signed little-endian numeric reads."""
        # \xfe = 254 (-2 signed u8/i8)
        # \xfe\xff = 0xfffe = 65534 (-2 signed i16)
        # \xfe\xff\xff\xff = 0xfffffffe = 4294967294 (-2 signed i32)
        data = b"\xfe\xfe\xff\xfe\xff\xff\xff"
        c = Cursor(data)

        self.assertEqual(c.read_u8(), 254)

        c.seek(0)
        self.assertEqual(c.read_i8(), -2)

        c.seek(1)
        self.assertEqual(c.read_u16(), 65534)

        c.seek(1)
        self.assertEqual(c.read_i16(), -2)

        c.seek(3)
        self.assertEqual(c.read_u32(), 4294967294)

        c.seek(3)
        self.assertEqual(c.read_i32(), -2)

    def test_slice_operations(self) -> None:
        """Test read_bytes, read_slice, and subcursor."""
        data = b"Hello, DEX Buffer!"
        c = Cursor(data)

        b = c.read_bytes(5)
        self.assertEqual(b, b"Hello")
        self.assertEqual(c.tell(), 5)

        c.skip(2)  # skip ", "
        sl = c.read_slice(3)
        self.assertIsInstance(sl, memoryview)
        self.assertEqual(sl.tobytes(), b"DEX")

        sub = c.subcursor(offset=11, length=6)
        self.assertEqual(sub.remaining, 6)
        self.assertEqual(sub.read_bytes(6), b"Buffer")
        self.assertEqual(c.tell(), 10)  # parent offset unchanged by subcursor

    def test_subcursor_bounds(self) -> None:
        """Test subcursor parameter validation and default behavior."""
        data = b"0123456789"
        c = Cursor(data, 2)

        # Default offset = c._offset, length = remaining
        sub_default = c.subcursor()
        self.assertEqual(sub_default.remaining, 8)
        self.assertEqual(sub_default.read_bytes(8), b"23456789")

        with self.assertRaises(ValueError):
            c.subcursor(offset=-1)

        with self.assertRaises(ValueError):
            c.subcursor(offset=11)

        with self.assertRaises(ValueError):
            c.subcursor(offset=5, length=6)

    def test_eof_exceptions(self) -> None:
        """Test EOFError when reading beyond buffer bounds."""
        data = b"\x01\x02"
        c = Cursor(data)

        c.read_u16()
        self.assertTrue(c.is_eof)

        with self.assertRaises(EOFError):
            c.read_u8()

        with self.assertRaises(EOFError):
            c.read_u16()

        with self.assertRaises(EOFError):
            c.read_u32()

        with self.assertRaises(EOFError):
            c.read_i8()

        with self.assertRaises(EOFError):
            c.read_i16()

        with self.assertRaises(EOFError):
            c.read_i32()

        with self.assertRaises(EOFError):
            c.read_bytes(1)

        with self.assertRaises(EOFError):
            c.read_slice(1)


if __name__ == "__main__":
    unittest.main()
