"""Unit tests for LEB128 encoding and decoding in dexbuf.leb128."""

import unittest

from dexbuf.leb128 import (
    decode_sleb128,
    decode_uleb128,
    decode_uleb128p1,
    encode_sleb128,
    encode_uleb128,
    encode_uleb128p1,
)


class TestLEB128SpecTable(unittest.TestCase):
    def test_spec_table_00(self) -> None:
        buf = bytes.fromhex("00")
        self.assertEqual(decode_sleb128(buf), (0, 1))
        self.assertEqual(decode_uleb128(buf), (0, 1))
        self.assertEqual(decode_uleb128p1(buf), (-1, 1))

        self.assertEqual(encode_sleb128(0), buf)
        self.assertEqual(encode_uleb128(0), buf)
        self.assertEqual(encode_uleb128p1(-1), buf)

    def test_spec_table_01(self) -> None:
        buf = bytes.fromhex("01")
        self.assertEqual(decode_sleb128(buf), (1, 1))
        self.assertEqual(decode_uleb128(buf), (1, 1))
        self.assertEqual(decode_uleb128p1(buf), (0, 1))

        self.assertEqual(encode_sleb128(1), buf)
        self.assertEqual(encode_uleb128(1), buf)
        self.assertEqual(encode_uleb128p1(0), buf)

    def test_spec_table_7f(self) -> None:
        buf = bytes.fromhex("7f")
        self.assertEqual(decode_sleb128(buf), (-1, 1))
        self.assertEqual(decode_uleb128(buf), (127, 1))
        self.assertEqual(decode_uleb128p1(buf), (126, 1))

        self.assertEqual(encode_sleb128(-1), buf)
        self.assertEqual(encode_uleb128(127), buf)
        self.assertEqual(encode_uleb128p1(126), buf)

    def test_spec_table_80_7f(self) -> None:
        buf = bytes.fromhex("807f")
        self.assertEqual(decode_sleb128(buf), (-128, 2))
        self.assertEqual(decode_uleb128(buf), (16256, 2))
        self.assertEqual(decode_uleb128p1(buf), (16255, 2))

        self.assertEqual(encode_sleb128(-128), buf)
        self.assertEqual(encode_uleb128(16256), buf)
        self.assertEqual(encode_uleb128p1(16255), buf)


class TestLEB128Roundtrips(unittest.TestCase):
    def test_uleb128_roundtrip(self) -> None:
        test_values = [
            0,
            1,
            127,
            128,
            16383,
            16384,
            2097151,
            2097152,
            268435455,
            0x7FFFFFFF,
            0xFFFFFFFF,
        ]
        for val in test_values:
            encoded = encode_uleb128(val)
            decoded, count = decode_uleb128(encoded)
            self.assertEqual(decoded, val)
            self.assertEqual(count, len(encoded))

    def test_uleb128p1_roundtrip(self) -> None:
        test_values = [-1, 0, 1, 126, 127, 16255, 16256, 0x7FFFFFFE]
        for val in test_values:
            encoded = encode_uleb128p1(val)
            decoded, count = decode_uleb128p1(encoded)
            self.assertEqual(decoded, val)
            self.assertEqual(count, len(encoded))

    def test_sleb128_roundtrip(self) -> None:
        test_values = [
            0,
            1,
            -1,
            63,
            -64,
            64,
            -65,
            127,
            -128,
            8191,
            -8192,
            0x7FFFFFFF,
            -0x80000000,
        ]
        for val in test_values:
            encoded = encode_sleb128(val)
            decoded, count = decode_sleb128(encoded)
            self.assertEqual(decoded, val)
            self.assertEqual(count, len(encoded))


class TestLEB128Errors(unittest.TestCase):
    def test_uleb128_negative(self) -> None:
        with self.assertRaises(ValueError):
            encode_uleb128(-1)

    def test_truncated_buffer(self) -> None:
        truncated = b"\x80\x80\x80"
        with self.assertRaises(ValueError):
            decode_uleb128(truncated)
        with self.assertRaises(ValueError):
            decode_sleb128(truncated)

    def test_exceeds_max_bytes(self) -> None:
        too_long = b"\x80\x80\x80\x80\x80\x80\x00"
        with self.assertRaises(ValueError):
            decode_uleb128(too_long)
        with self.assertRaises(ValueError):
            decode_sleb128(too_long)

    def test_offset_decoding(self) -> None:
        data = b"\xff\xff\x80\x7f\xff"
        val, count = decode_uleb128(data, offset=2)
        self.assertEqual(val, 16256)
        self.assertEqual(count, 2)


if __name__ == "__main__":
    unittest.main()
