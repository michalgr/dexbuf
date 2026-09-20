"""DEX encoded value structures and helpers.

See https://source.android.com/docs/core/runtime/dex-format#encoded-value-encoding
"""

import struct
from collections.abc import Iterator
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Self, overload

from dexbuf.cursor import Cursor
from dexbuf.leb128 import encode_uleb128
from dexbuf.types import Idx


class ValueType(IntEnum):
    """Encoded value type enumeration.

    See https://source.android.com/docs/core/runtime/dex-format#value-formats
    """

    BYTE = 0x00
    SHORT = 0x02
    CHAR = 0x03
    INT = 0x04
    LONG = 0x06
    FLOAT = 0x10
    DOUBLE = 0x11
    METHOD_TYPE = 0x15
    METHOD_HANDLE = 0x16
    STRING = 0x17
    TYPE = 0x18
    FIELD = 0x19
    METHOD = 0x1A
    ENUM = 0x1B
    ARRAY = 0x1C
    ANNOTATION = 0x1D
    NULL = 0x1E
    BOOLEAN = 0x1F


def _encode_signed_int(value: int, max_bytes: int) -> bytes:
    """Encode a signed integer into minimal little-endian bytes up to max_bytes."""
    for size in range(1, max_bytes + 1):
        min_val = -(1 << (8 * size - 1))
        max_val = (1 << (8 * size - 1)) - 1
        if min_val <= value <= max_val:
            return value.to_bytes(size, "little", signed=True)
    raise ValueError(f"Value {value} out of range for signed integer up to {max_bytes} bytes")


def _encode_unsigned_int(value: int, max_bytes: int) -> bytes:
    """Encode an unsigned integer into minimal little-endian bytes up to max_bytes."""
    for size in range(1, max_bytes + 1):
        max_val = (1 << (8 * size)) - 1
        if 0 <= value <= max_val:
            return value.to_bytes(size, "little", signed=False)
    raise ValueError(f"Value {value} out of range for unsigned integer up to {max_bytes} bytes")


@dataclass(slots=True, frozen=True)
class AnnotationElement:
    """Annotation element structure.

    See https://source.android.com/docs/core/runtime/dex-format#annotation-element
    """

    name_idx: Idx[Any]
    value: EncodedValue

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Parse an AnnotationElement from a Cursor."""
        name_idx = cursor.read_uleb128()
        value = EncodedValue.from_cursor(cursor)
        return cls(name_idx=Idx[Any](name_idx), value=value)

    def to_bytes(self) -> bytes:
        """Encode this AnnotationElement to raw DEX bytes."""
        return encode_uleb128(self.name_idx) + self.value.to_bytes()


@dataclass(slots=True, frozen=True)
class EncodedAnnotation:
    """Encoded annotation structure.

    See https://source.android.com/docs/core/runtime/dex-format#encoded-annotation
    """

    type_idx: Idx[Any]
    elements: tuple[AnnotationElement, ...]

    @property
    def size(self) -> int:
        """Number of annotation elements."""
        return len(self.elements)

    def __len__(self) -> int:
        return len(self.elements)

    def __iter__(self) -> Iterator[AnnotationElement]:
        return iter(self.elements)

    @overload
    def __getitem__(self, index: int) -> AnnotationElement: ...

    @overload
    def __getitem__(self, index: slice) -> tuple[AnnotationElement, ...]: ...

    def __getitem__(self, index: int | slice) -> AnnotationElement | tuple[AnnotationElement, ...]:
        return self.elements[index]

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Parse an EncodedAnnotation from a Cursor."""
        type_idx = cursor.read_uleb128()
        size = cursor.read_uleb128()
        elements = tuple(AnnotationElement.from_cursor(cursor) for _ in range(size))
        return cls(type_idx=Idx[Any](type_idx), elements=elements)

    def to_bytes(self) -> bytes:
        """Encode this EncodedAnnotation to raw DEX bytes."""
        return (
            encode_uleb128(self.type_idx)
            + encode_uleb128(self.size)
            + b"".join(elem.to_bytes() for elem in self.elements)
        )


@dataclass(slots=True, frozen=True)
class EncodedArray:
    """Encoded array structure.

    See https://source.android.com/docs/core/runtime/dex-format#encoded-array
    """

    values: tuple[EncodedValue, ...]

    @property
    def size(self) -> int:
        """Number of values in array."""
        return len(self.values)

    def __len__(self) -> int:
        return len(self.values)

    def __iter__(self) -> Iterator[EncodedValue]:
        return iter(self.values)

    @overload
    def __getitem__(self, index: int) -> EncodedValue: ...

    @overload
    def __getitem__(self, index: slice) -> tuple[EncodedValue, ...]: ...

    def __getitem__(self, index: int | slice) -> EncodedValue | tuple[EncodedValue, ...]:
        return self.values[index]

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Parse an EncodedArray from a Cursor."""
        size = cursor.read_uleb128()
        values = tuple(EncodedValue.from_cursor(cursor) for _ in range(size))
        return cls(values=values)

    def to_bytes(self) -> bytes:
        """Encode this EncodedArray to raw DEX bytes."""
        return encode_uleb128(self.size) + b"".join(v.to_bytes() for v in self.values)


@dataclass(slots=True, frozen=True)
class EncodedValue:
    """Encoded value structure.

    See https://source.android.com/docs/core/runtime/dex-format#encoded-value-encoding
    """

    value_arg: int
    value_type: ValueType
    value: Any

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Parse an EncodedValue from a Cursor."""
        header = cursor.read_u8()
        value_arg = header >> 5
        value_type = ValueType(header & 0x1F)

        value: Any
        match value_type:
            case ValueType.BYTE:
                value = int.from_bytes(cursor.read_bytes(value_arg + 1), "little", signed=True)
            case ValueType.SHORT | ValueType.INT | ValueType.LONG:
                value = int.from_bytes(cursor.read_bytes(value_arg + 1), "little", signed=True)
            case ValueType.CHAR:
                value = int.from_bytes(cursor.read_bytes(value_arg + 1), "little", signed=False)
            case ValueType.FLOAT:
                raw = cursor.read_bytes(value_arg + 1)
                padded = b"\x00" * (4 - (value_arg + 1)) + raw
                value = struct.unpack("<f", padded)[0]
            case ValueType.DOUBLE:
                raw = cursor.read_bytes(value_arg + 1)
                padded = b"\x00" * (8 - (value_arg + 1)) + raw
                value = struct.unpack("<d", padded)[0]
            case (
                ValueType.STRING
                | ValueType.TYPE
                | ValueType.FIELD
                | ValueType.METHOD
                | ValueType.ENUM
                | ValueType.METHOD_TYPE
                | ValueType.METHOD_HANDLE
            ):
                value = Idx[Any](
                    int.from_bytes(cursor.read_bytes(value_arg + 1), "little", signed=False)
                )
            case ValueType.ARRAY:
                value = EncodedArray.from_cursor(cursor)
            case ValueType.ANNOTATION:
                value = EncodedAnnotation.from_cursor(cursor)
            case ValueType.NULL:
                value = None
            case ValueType.BOOLEAN:
                value = bool(value_arg)

        return cls(value_arg=value_arg, value_type=value_type, value=value)

    def to_bytes(self) -> bytes:
        """Encode this EncodedValue to raw DEX bytes."""
        payload: bytes
        arg: int

        match self.value_type:
            case ValueType.BYTE:
                payload = self.value.to_bytes(1, "little", signed=True)
                arg = 0
            case ValueType.SHORT:
                payload = _encode_signed_int(self.value, 2)
                arg = len(payload) - 1
            case ValueType.INT:
                payload = _encode_signed_int(self.value, 4)
                arg = len(payload) - 1
            case ValueType.LONG:
                payload = _encode_signed_int(self.value, 8)
                arg = len(payload) - 1
            case ValueType.CHAR:
                payload = _encode_unsigned_int(self.value, 2)
                arg = len(payload) - 1
            case (
                ValueType.STRING
                | ValueType.TYPE
                | ValueType.FIELD
                | ValueType.METHOD
                | ValueType.ENUM
                | ValueType.METHOD_TYPE
                | ValueType.METHOD_HANDLE
            ):
                payload = _encode_unsigned_int(self.value, 4)
                arg = len(payload) - 1
            case ValueType.FLOAT:
                raw = struct.pack("<f", self.value)
                i = 0
                while i < len(raw) - 1 and raw[i] == 0:
                    i += 1
                payload = raw[i:]
                arg = len(payload) - 1
            case ValueType.DOUBLE:
                raw = struct.pack("<d", self.value)
                i = 0
                while i < len(raw) - 1 and raw[i] == 0:
                    i += 1
                payload = raw[i:]
                arg = len(payload) - 1
            case ValueType.ARRAY:
                payload = self.value.to_bytes()
                arg = 0
            case ValueType.ANNOTATION:
                payload = self.value.to_bytes()
                arg = 0
            case ValueType.NULL:
                payload = b""
                arg = 0
            case ValueType.BOOLEAN:
                payload = b""
                arg = 1 if self.value else 0

        header = (arg << 5) | self.value_type.value
        return bytes([header]) + payload
