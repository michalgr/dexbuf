"""Unit tests for DEX value, array, and annotation helper structures."""

import struct
import unittest
from dataclasses import FrozenInstanceError

from dexbuf import (
    AnnotationElement,
    EncodedAnnotation,
    EncodedArray,
    EncodedValue,
    FieldIdItem,
    Idx,
    MethodHandleItem,
    MethodIdItem,
    ProtoIdItem,
    StringIdItem,
    TypeIdItem,
    ValueType,
)
from dexbuf.cursor import Cursor


class TestValueType(unittest.TestCase):
    def test_enum_values(self) -> None:
        """Verify ValueType enum constants against DEX specification."""
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
        val = EncodedValue(value_arg=0, value_type=ValueType.INT, value=42)
        with self.assertRaises(FrozenInstanceError):
            val.value = 100  # type: ignore[misc]

        self.assertEqual(val.__slots__, ("value_arg", "value_type", "value"))

    def test_byte_roundtrip(self) -> None:
        for b in (-128, -1, 0, 1, 127):
            enc = EncodedValue(value_arg=0, value_type=ValueType.BYTE, value=b)
            raw = enc.to_bytes()
            parsed = EncodedValue.from_cursor(Cursor(raw))
            self.assertEqual(parsed, enc)
            self.assertEqual(parsed.value, b)

    def test_short_roundtrip(self) -> None:
        for val in (-32768, -100, 0, 100, 32767):
            enc = EncodedValue(
                value_arg=1 if abs(val) > 127 else 0, value_type=ValueType.SHORT, value=val
            )
            raw = enc.to_bytes()
            parsed = EncodedValue.from_cursor(Cursor(raw))
            self.assertEqual(parsed.value, val)
            self.assertEqual(parsed.value_type, ValueType.SHORT)

    def test_char_roundtrip(self) -> None:
        for val in (0, 65, 255, 1000, 65535):
            enc = EncodedValue(
                value_arg=1 if val > 255 else 0, value_type=ValueType.CHAR, value=val
            )
            raw = enc.to_bytes()
            parsed = EncodedValue.from_cursor(Cursor(raw))
            self.assertEqual(parsed.value, val)
            self.assertEqual(parsed.value_type, ValueType.CHAR)

    def test_int_roundtrip(self) -> None:
        for val in (-2147483648, -0x123456, -100, 0, 100, 0x123456, 2147483647):
            enc = EncodedValue(value_arg=3, value_type=ValueType.INT, value=val)
            raw = enc.to_bytes()
            parsed = EncodedValue.from_cursor(Cursor(raw))
            self.assertEqual(parsed.value, val)
            self.assertEqual(parsed.value_type, ValueType.INT)

    def test_long_roundtrip(self) -> None:
        for val in (-0x123456789ABC, -100, 0, 100, 0x123456789ABC):
            enc = EncodedValue(value_arg=7, value_type=ValueType.LONG, value=val)
            raw = enc.to_bytes()
            parsed = EncodedValue.from_cursor(Cursor(raw))
            self.assertEqual(parsed.value, val)
            self.assertEqual(parsed.value_type, ValueType.LONG)

    def test_float_roundtrip(self) -> None:
        for fval in (0.0, 1.0, -2.5, 3.1415925):
            packed = struct.pack("<f", fval)
            enc = EncodedValue(
                value_arg=3, value_type=ValueType.FLOAT, value=struct.unpack("<f", packed)[0]
            )
            raw = enc.to_bytes()
            parsed = EncodedValue.from_cursor(Cursor(raw))
            self.assertAlmostEqual(parsed.value, fval, places=5)
            self.assertEqual(parsed.value_type, ValueType.FLOAT)

    def test_double_roundtrip(self) -> None:
        for dval in (0.0, 1.0, -2.5, 3.141592653589793):
            packed = struct.pack("<d", dval)
            enc = EncodedValue(
                value_arg=7, value_type=ValueType.DOUBLE, value=struct.unpack("<d", packed)[0]
            )
            raw = enc.to_bytes()
            parsed = EncodedValue.from_cursor(Cursor(raw))
            self.assertAlmostEqual(parsed.value, dval, places=12)
            self.assertEqual(parsed.value_type, ValueType.DOUBLE)

    def test_index_types_roundtrip(self) -> None:
        cases = [
            (ValueType.STRING, Idx[StringIdItem](0x1234)),
            (ValueType.TYPE, Idx[TypeIdItem](0x5678)),
            (ValueType.FIELD, Idx[FieldIdItem](0x01)),
            (ValueType.METHOD, Idx[MethodIdItem](0xABCD)),
            (ValueType.ENUM, Idx[FieldIdItem](0x02)),
            (ValueType.METHOD_TYPE, Idx[ProtoIdItem](0x03)),
            (ValueType.METHOD_HANDLE, Idx[MethodHandleItem](0x04)),
        ]
        for vtype, idx_val in cases:
            enc = EncodedValue(value_arg=1, value_type=vtype, value=idx_val)
            raw = enc.to_bytes()
            parsed = EncodedValue.from_cursor(Cursor(raw))
            self.assertEqual(parsed.value, idx_val)
            self.assertEqual(parsed.value_type, vtype)

    def test_boolean_null_roundtrip(self) -> None:
        enc_true = EncodedValue(value_arg=1, value_type=ValueType.BOOLEAN, value=True)
        raw_true = enc_true.to_bytes()
        self.assertEqual(raw_true, b"\x3f")
        parsed_true = EncodedValue.from_cursor(Cursor(raw_true))
        self.assertEqual(parsed_true, enc_true)
        self.assertTrue(parsed_true.value)

        enc_false = EncodedValue(value_arg=0, value_type=ValueType.BOOLEAN, value=False)
        raw_false = enc_false.to_bytes()
        self.assertEqual(raw_false, b"\x1f")
        parsed_false = EncodedValue.from_cursor(Cursor(raw_false))
        self.assertEqual(parsed_false, enc_false)
        self.assertFalse(parsed_false.value)

        enc_null = EncodedValue(value_arg=0, value_type=ValueType.NULL, value=None)
        raw_null = enc_null.to_bytes()
        self.assertEqual(raw_null, b"\x1e")
        parsed_null = EncodedValue.from_cursor(Cursor(raw_null))
        self.assertEqual(parsed_null, enc_null)
        self.assertIsNone(parsed_null.value)


class TestEncodedArrayAndAnnotation(unittest.TestCase):
    def test_encoded_array(self) -> None:
        v1 = EncodedValue(value_arg=0, value_type=ValueType.INT, value=10)
        v2 = EncodedValue(value_arg=1, value_type=ValueType.BOOLEAN, value=True)
        arr = EncodedArray(size=2, values=(v1, v2))

        self.assertEqual(len(arr), 2)
        self.assertEqual(arr[0], v1)
        self.assertEqual(arr[1], v2)
        self.assertEqual(list(arr), [v1, v2])

        enc_val = EncodedValue(value_arg=0, value_type=ValueType.ARRAY, value=arr)
        raw = enc_val.to_bytes()
        parsed = EncodedValue.from_cursor(Cursor(raw))
        self.assertEqual(parsed, enc_val)

    def test_encoded_annotation(self) -> None:
        elem1 = AnnotationElement(
            name_idx=Idx[StringIdItem](1),
            value=EncodedValue(value_arg=0, value_type=ValueType.INT, value=100),
        )
        annotation = EncodedAnnotation(
            type_idx=Idx[TypeIdItem](5),
            size=1,
            elements=(elem1,),
        )

        self.assertEqual(len(annotation), 1)
        self.assertEqual(annotation[0], elem1)
        self.assertEqual(list(annotation), [elem1])

        enc_val = EncodedValue(value_arg=0, value_type=ValueType.ANNOTATION, value=annotation)
        raw = enc_val.to_bytes()
        parsed = EncodedValue.from_cursor(Cursor(raw))
        self.assertEqual(parsed, enc_val)


if __name__ == "__main__":
    unittest.main()
