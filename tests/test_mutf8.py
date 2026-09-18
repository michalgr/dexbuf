"""Unit tests for Modified UTF-8 (MUTF-8) encoding and decoding in dexbuf.mutf8."""

import unittest

from dexbuf.mutf8 import decode_mutf8, encode_mutf8, utf16_code_units


class TestMUTF8(unittest.TestCase):
    def test_utf16_code_units(self) -> None:
        self.assertEqual(utf16_code_units(""), 0)
        self.assertEqual(utf16_code_units("hello"), 5)
        self.assertEqual(utf16_code_units("Hello, World!"), 13)
        self.assertEqual(utf16_code_units("😀"), 2)
        self.assertEqual(utf16_code_units("Hello 😀 World!"), 15)

    def test_ascii(self) -> None:
        s = "Hello, DEX!"
        encoded = encode_mutf8(s)
        self.assertEqual(encoded, b"Hello, DEX!\x00")

        # Fast path with expected_utf16_size
        decoded, count = decode_mutf8(encoded, expected_utf16_size=len(s))
        self.assertEqual(decoded, s)
        self.assertEqual(count, len(encoded))

        # Standard path without expected_utf16_size
        decoded_no_exp, count_no_exp = decode_mutf8(encoded)
        self.assertEqual(decoded_no_exp, s)
        self.assertEqual(count_no_exp, len(encoded))

    def test_embedded_null(self) -> None:
        s = "a\x00b"
        encoded = encode_mutf8(s)
        self.assertEqual(encoded, b"a\xc0\x80b\x00")

        # Confirm 0x00 is not inside the data bytes before the end
        self.assertNotIn(0, encoded[:-1])

        decoded, count = decode_mutf8(encoded)
        self.assertEqual(decoded, s)
        self.assertEqual(count, len(encoded))

    def test_2_byte_sequences(self) -> None:
        # U+00A2 (CENT SIGN), U+00F9 (LATIN SMALL LETTER U WITH GRAVE)
        s = "¢ù"
        encoded = encode_mutf8(s)
        self.assertEqual(encoded, b"\xc2\xa2\xc3\xb9\x00")

        decoded, count = decode_mutf8(encoded)
        self.assertEqual(decoded, s)
        self.assertEqual(count, len(encoded))

    def test_3_byte_sequences(self) -> None:
        # U+0950 (DEVANAGARI OM), U+4E2D (CJK UNIFIED IDEOGRAPH-4E2D)
        s = "ॐ中"
        encoded = encode_mutf8(s)
        self.assertEqual(encoded, b"\xe0\xa5\x90\xe4\xb8\xad\x00")

        decoded, count = decode_mutf8(encoded)
        self.assertEqual(decoded, s)
        self.assertEqual(count, len(encoded))

    def test_supplementary_characters(self) -> None:
        # U+1F600 (GRINNING FACE 😀)
        s = "😀"
        self.assertEqual(utf16_code_units(s), 2)

        encoded = encode_mutf8(s)
        # 😀 high surrogate U+D83D (ED A0 BD), low surrogate U+DE00 (ED B8 80)
        self.assertEqual(encoded, b"\xed\xa0\xbd\xed\xb8\x80\x00")
        self.assertEqual(len(encoded), 7)

        decoded, count = decode_mutf8(encoded)
        self.assertEqual(decoded, s)
        self.assertEqual(count, 7)

        # Fast path bypass check with expected_utf16_size
        decoded_exp, count_exp = decode_mutf8(encoded, expected_utf16_size=2)
        self.assertEqual(decoded_exp, s)
        self.assertEqual(count_exp, 7)

    def test_isolated_surrogates(self) -> None:
        # Isolated high surrogate U+D800
        s_high = "\ud800"
        encoded_high = encode_mutf8(s_high)
        self.assertEqual(encoded_high, b"\xed\xa0\x80\x00")

        decoded_high, _ = decode_mutf8(encoded_high)
        self.assertEqual(decoded_high, s_high)

        # Isolated low surrogate U+DFFF
        s_low = "\udfff"
        encoded_low = encode_mutf8(s_low)
        self.assertEqual(encoded_low, b"\xed\xbf\xbf\x00")

        decoded_low, _ = decode_mutf8(encoded_low)
        self.assertEqual(decoded_low, s_low)

    def test_validation_utf16_size_mismatch(self) -> None:
        s = "Hello"
        encoded = encode_mutf8(s)
        # Pass incorrect expected_utf16_size = 10 (fast path won't match, standard path validates)
        with self.assertRaises(ValueError):
            decode_mutf8(encoded, expected_utf16_size=10)

    def test_validation_errors(self) -> None:
        # Missing null terminator
        with self.assertRaises(ValueError):
            decode_mutf8(b"Hello")

        # Invalid continuation byte in 2-byte sequence
        with self.assertRaises(ValueError):
            decode_mutf8(b"\xc2\x00")

        # Invalid start byte
        with self.assertRaises(ValueError):
            decode_mutf8(b"\xf8\x00")


if __name__ == "__main__":
    unittest.main()
