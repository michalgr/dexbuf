"""Unit tests for Cursor zero-copy binary reader in dexbuf.cursor."""

import mmap
import tempfile
import unittest

from dexbuf.cursor import Cursor
from dexbuf.string_data import StringDataItem


class TestCursorBufferTypes(unittest.TestCase):
    def test_buffer_protocol_types(self) -> None:
        data = b"\x01\x02\x03\x04\x05"

        # bytes
        c1 = Cursor(data)
        self.assertEqual(c1.read_u8(), 1)

        # bytearray
        ba = bytearray(data)
        c2 = Cursor(ba)
        self.assertEqual(c2.read_u8(), 1)

        # memoryview
        mv = memoryview(data)
        c3 = Cursor(mv)
        self.assertEqual(c3.read_u8(), 1)

        # mmap
        with tempfile.TemporaryFile() as f:
            f.write(data)
            f.flush()
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                c4 = Cursor(mm)
                self.assertEqual(c4.read_u8(), 1)
                del c4


class TestCursorNavigation(unittest.TestCase):
    def test_navigation(self) -> None:
        c = Cursor(b"0123456789")
        self.assertEqual(c.tell(), 0)
        self.assertEqual(c.remaining, 10)
        self.assertFalse(c.is_eof)

        c.skip(3)
        self.assertEqual(c.tell(), 3)
        self.assertEqual(c.remaining, 7)

        c.seek(8)
        self.assertEqual(c.tell(), 8)
        self.assertEqual(c.remaining, 2)

        c.seek(10)
        self.assertTrue(c.is_eof)
        self.assertEqual(c.remaining, 0)

    def test_offset_bounds(self) -> None:
        c = Cursor(b"123")
        with self.assertRaises(IndexError):
            c.offset = -1
        with self.assertRaises(IndexError):
            c.offset = 4


class TestCursorNumericReads(unittest.TestCase):
    def test_numeric_unpacking(self) -> None:
        # u8/s8: 0x80 = 128 (unsigned), -128 (signed)
        c_8 = Cursor(b"\x80")
        self.assertEqual(c_8.peek_u8(), 128)
        self.assertEqual(c_8.tell(), 0)
        self.assertEqual(c_8.read_u8(), 128)
        c_8.seek(0)
        self.assertEqual(c_8.read_s8(), -128)

        # u16/s16: 0x00 0x80 = 0x8000 = 32768 (unsigned), -32768 (signed)
        c_16 = Cursor(b"\x00\x80")
        self.assertEqual(c_16.read_u16(), 32768)
        c_16.seek(0)
        self.assertEqual(c_16.read_s16(), -32768)

        # u32/s32: 0xff 0xff 0xff 0x7f = 0x7fffffff = 2147483647
        c_32 = Cursor(b"\xff\xff\xff\x7f")
        self.assertEqual(c_32.read_u32(), 0x7FFFFFFF)
        c_32.seek(0)
        self.assertEqual(c_32.read_s32(), 0x7FFFFFFF)

        # u64/s64
        c_64 = Cursor(b"\x01\x00\x00\x00\x00\x00\x00\x80")
        self.assertEqual(c_64.read_u64(), 0x8000_0000_0000_0001)
        c_64.seek(0)
        self.assertEqual(c_64.read_s64(), -0x7FFF_FFFF_FFFF_FFFF)

    def test_eof_reading(self) -> None:
        c = Cursor(b"\x01\x02")
        c.read_u16()
        with self.assertRaises(EOFError):
            c.read_u8()


class TestCursorSlicing(unittest.TestCase):
    def test_zero_copy_slicing(self) -> None:
        data = b"Hello World"
        c = Cursor(data)

        peeked = c.peek_bytes(5)
        self.assertEqual(peeked.tobytes(), b"Hello")
        self.assertEqual(c.tell(), 0)

        read_mv = c.read_bytes(5)
        self.assertEqual(read_mv.tobytes(), b"Hello")
        self.assertEqual(c.tell(), 5)

        # Verify zero-copy: underlying buffer obj is same or slice of same
        self.assertEqual(read_mv, memoryview(data)[0:5])

    def test_slicing_out_of_bounds(self) -> None:
        c = Cursor(b"123")
        with self.assertRaises(EOFError):
            c.read_bytes(5)
        with self.assertRaises(ValueError):
            c.read_bytes(-1)


class TestCursorVariableLengthReads(unittest.TestCase):
    def test_leb128_reads(self) -> None:
        # uleb128(16256) = b"\x80\x7f", sleb128(-128) = b"\x80\x7f"
        c = Cursor(b"\x80\x7f\x80\x7f")
        self.assertEqual(c.read_uleb128(), 16256)
        self.assertEqual(c.tell(), 2)
        self.assertEqual(c.read_sleb128(), -128)
        self.assertEqual(c.tell(), 4)

    def test_string_data_reads(self) -> None:
        item = StringDataItem.from_str("Test String 😀")
        raw = item.to_bytes()
        c = Cursor(raw)

        read_item = c.read_string_data_item()
        self.assertEqual(read_item, item)
        self.assertEqual(c.tell(), len(raw))

        c.seek(0)
        str_val = c.read_string_data()
        self.assertEqual(str_val, "Test String 😀")
        self.assertEqual(c.tell(), len(raw))


class TestCursorSubcursor(unittest.TestCase):
    def test_subcursor(self) -> None:
        data = b"0123456789ABCDEF"
        c = Cursor(data)
        c.seek(4)

        # Default subcursor at current offset (4) to end
        sub1 = c.subcursor()
        self.assertEqual(sub1.tell(), 0)
        self.assertEqual(sub1.remaining, 12)
        self.assertEqual(sub1.read_bytes(4).tobytes(), b"4567")

        # Specific offset and length
        sub2 = c.subcursor(offset=10, length=4)
        self.assertEqual(sub2.remaining, 4)
        self.assertEqual(sub2.read_bytes(4).tobytes(), b"ABCD")

    def test_subcursor_bounds(self) -> None:
        c = Cursor(b"12345")
        with self.assertRaises(IndexError):
            c.subcursor(offset=10)
        with self.assertRaises(IndexError):
            c.subcursor(offset=2, length=10)


if __name__ == "__main__":
    unittest.main()
