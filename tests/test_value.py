"""Unit tests for dexbuf.value encoded value structures."""

import unittest
from dataclasses import FrozenInstanceError

from dexbuf.cursor import Cursor
from dexbuf.types import Idx
from dexbuf.value import (
    AnnotationElement,
    EncodedAnnotation,
    EncodedArray,
    EncodedValue,
    ValueType,
)


class TestValueType(unittest.TestCase):
    def test_value_type_values(self) -> None:
        """Verify ValueType enum integer values according to DEX format spec."""
        self.assertEqual(ValueType.BYTE, 0x00)
        self.assertEqual(ValueType.SHORT, 0x02)
        self.assertEqual(ValueType.CHAR, 0x03)
        self.assertEqual(ValueType.INT, 0x04)
        self.assertEqual(ValueType.LONG, 0x06)
        self.assertEqual(ValueType.FLOAT, 0x10)
        self.assertEqual(ValueType.DOUBLE, 0x11)
        self.assertEqual(ValueType.METHOD_TYPE, 0x15)
        self.assertEqual(ValueType.METHOD_HANDLE, 0x16)
        self.assertEqual(ValueType.STRING, 0x17)
        self.assertEqual(ValueType.TYPE, 0x18)
        self.assertEqual(ValueType.FIELD, 0x19)
        self.assertEqual(ValueType.METHOD, 0x1A)
        self.assertEqual(ValueType.ENUM, 0x1B)
        self.assertEqual(ValueType.ARRAY, 0x1C)
        self.assertEqual(ValueType.ANNOTATION, 0x1D)
        self.assertEqual(ValueType.NULL, 0x1E)
        self.assertEqual(ValueType.BOOLEAN, 0x1F)


class TestEncodedValue(unittest.TestCase):
    def test_immutability(self) -> None:
        """Verify EncodedValue is frozen and uses slots."""
        val = EncodedValue(value_arg=0, value_type=ValueType.BYTE, value=42)
        with self.assertRaises(FrozenInstanceError):
            val.value = 100  # type: ignore[misc]

    def test_byte_roundtrip(self) -> None:
        """Verify BYTE decoding and encoding."""
        v = EncodedValue(value_arg=0, value_type=ValueType.BYTE, value=-5)
        raw = v.to_bytes()
        self.assertEqual(raw, bytes([0x00, 0xFB]))
        parsed = EncodedValue.from_cursor(Cursor(raw))
        self.assertEqual(parsed.value_type, ValueType.BYTE)
        self.assertEqual(parsed.value, -5)

    def test_short_roundtrip(self) -> None:
        """Verify SHORT decoding and encoding across byte sizes."""
        for num in [0, 100, -128, 500, -3000]:
            v = EncodedValue(value_arg=0, value_type=ValueType.SHORT, value=num)
            raw = v.to_bytes()
            parsed = EncodedValue.from_cursor(Cursor(raw))
            self.assertEqual(parsed.value_type, ValueType.SHORT)
            self.assertEqual(parsed.value, num)

    def test_char_roundtrip(self) -> None:
        """Verify CHAR decoding and encoding."""
        for num in [0, 65, 0xFFFF]:
            v = EncodedValue(value_arg=0, value_type=ValueType.CHAR, value=num)
            raw = v.to_bytes()
            parsed = EncodedValue.from_cursor(Cursor(raw))
            self.assertEqual(parsed.value_type, ValueType.CHAR)
            self.assertEqual(parsed.value, num)

    def test_int_roundtrip(self) -> None:
        """Verify INT decoding and encoding."""
        for num in [0, 127, -128, 30000, -100000, 0x12345678]:
            v = EncodedValue(value_arg=0, value_type=ValueType.INT, value=num)
            raw = v.to_bytes()
            parsed = EncodedValue.from_cursor(Cursor(raw))
            self.assertEqual(parsed.value_type, ValueType.INT)
            self.assertEqual(parsed.value, num)

    def test_long_roundtrip(self) -> None:
        """Verify LONG decoding and encoding."""
        for num in [0, -1, 0x123456789ABCDEF]:
            v = EncodedValue(value_arg=0, value_type=ValueType.LONG, value=num)
            raw = v.to_bytes()
            parsed = EncodedValue.from_cursor(Cursor(raw))
            self.assertEqual(parsed.value_type, ValueType.LONG)
            self.assertEqual(parsed.value, num)

    def test_float_roundtrip(self) -> None:
        """Verify FLOAT decoding and encoding."""
        for f in [0.0, 3.14159, -12.5]:
            v = EncodedValue(value_arg=0, value_type=ValueType.FLOAT, value=f)
            raw = v.to_bytes()
            parsed = EncodedValue.from_cursor(Cursor(raw))
            self.assertEqual(parsed.value_type, ValueType.FLOAT)
            self.assertAlmostEqual(parsed.value, f, places=4)

    def test_double_roundtrip(self) -> None:
        """Verify DOUBLE decoding and encoding."""
        for d in [0.0, 3.141592653589793, -123456.789]:
            v = EncodedValue(value_arg=0, value_type=ValueType.DOUBLE, value=d)
            raw = v.to_bytes()
            parsed = EncodedValue.from_cursor(Cursor(raw))
            self.assertEqual(parsed.value_type, ValueType.DOUBLE)
            self.assertAlmostEqual(parsed.value, d, places=8)

    def test_index_types_roundtrip(self) -> None:
        """Verify index value types (STRING, TYPE, FIELD, METHOD, ENUM, etc.)."""
        index_types = [
            ValueType.STRING,
            ValueType.TYPE,
            ValueType.FIELD,
            ValueType.METHOD,
            ValueType.ENUM,
            ValueType.METHOD_TYPE,
            ValueType.METHOD_HANDLE,
        ]
        for vt in index_types:
            v = EncodedValue(value_arg=0, value_type=vt, value=Idx(1234))
            raw = v.to_bytes()
            parsed = EncodedValue.from_cursor(Cursor(raw))
            self.assertEqual(parsed.value_type, vt)
            self.assertEqual(parsed.value, 1234)

    def test_null_and_boolean(self) -> None:
        """Verify NULL and BOOLEAN decoding and encoding."""
        # NULL
        null_val = EncodedValue(value_arg=0, value_type=ValueType.NULL, value=None)
        raw_null = null_val.to_bytes()
        self.assertEqual(raw_null, bytes([ValueType.NULL]))
        parsed_null = EncodedValue.from_cursor(Cursor(raw_null))
        self.assertEqual(parsed_null.value_type, ValueType.NULL)
        self.assertIsNone(parsed_null.value)

        # BOOLEAN False
        bool_false = EncodedValue(value_arg=0, value_type=ValueType.BOOLEAN, value=False)
        raw_false = bool_false.to_bytes()
        self.assertEqual(raw_false, bytes([ValueType.BOOLEAN]))
        parsed_false = EncodedValue.from_cursor(Cursor(raw_false))
        self.assertFalse(parsed_false.value)

        # BOOLEAN True
        bool_true = EncodedValue(value_arg=1, value_type=ValueType.BOOLEAN, value=True)
        raw_true = bool_true.to_bytes()
        self.assertEqual(raw_true, bytes([(1 << 5) | ValueType.BOOLEAN]))
        parsed_true = EncodedValue.from_cursor(Cursor(raw_true))
        self.assertTrue(parsed_true.value)


class TestEncodedArrayAndAnnotation(unittest.TestCase):
    def test_encoded_array(self) -> None:
        """Verify EncodedArray sequence methods, parsing, and encoding."""
        v1 = EncodedValue(value_arg=0, value_type=ValueType.INT, value=10)
        v2 = EncodedValue(value_arg=0, value_type=ValueType.BOOLEAN, value=True)
        arr = EncodedArray(values=(v1, v2))

        self.assertEqual(arr.size, 2)
        with self.assertRaises((TypeError, AttributeError)):
            arr.size = 10  # type: ignore[misc]

        self.assertEqual(arr.__slots__, ("values",))
        self.assertEqual(len(arr), 2)
        self.assertEqual(list(iter(arr)), [v1, v2])
        self.assertEqual(arr[0], v1)
        self.assertEqual(arr[1], v2)

        raw = arr.to_bytes()
        parsed = EncodedArray.from_cursor(Cursor(raw))
        self.assertEqual(parsed.size, 2)
        self.assertEqual(len(parsed.values), 2)
        self.assertEqual(parsed.values[0].value, 10)
        self.assertTrue(parsed.values[1].value)

    def test_encoded_annotation(self) -> None:
        """Verify AnnotationElement and EncodedAnnotation serialization and sequence methods."""
        v = EncodedValue(value_arg=0, value_type=ValueType.INT, value=42)
        elem = AnnotationElement(name_idx=Idx(1), value=v)
        annotation = EncodedAnnotation(type_idx=Idx(5), elements=(elem,))

        self.assertEqual(annotation.size, 1)
        with self.assertRaises((TypeError, AttributeError)):
            annotation.size = 10  # type: ignore[misc]

        self.assertEqual(annotation.__slots__, ("type_idx", "elements"))
        self.assertEqual(len(annotation), 1)
        self.assertEqual(annotation[0], elem)
        self.assertEqual(list(iter(annotation)), [elem])

        raw = annotation.to_bytes()
        parsed = EncodedAnnotation.from_cursor(Cursor(raw))
        self.assertEqual(parsed.type_idx, 5)
        self.assertEqual(parsed.size, 1)
        self.assertEqual(parsed.elements[0].name_idx, 1)
        self.assertEqual(parsed.elements[0].value.value, 42)


if __name__ == "__main__":
    unittest.main()
