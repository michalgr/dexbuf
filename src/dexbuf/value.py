"""DEX encoded value, array, and annotation helper structures.

See https://source.android.com/docs/core/runtime/dex-format#encoded-value-encoding
"""

import struct
from collections.abc import Iterator
from dataclasses import dataclass
from enum import IntEnum
from typing import TYPE_CHECKING, Any, Self, overload

from dexbuf.cursor import Cursor
from dexbuf.leb128 import encode_uleb128
from dexbuf.types import Idx

if TYPE_CHECKING:
    from dexbuf.items import (
        StringIdItem,
        TypeIdItem,
    )

__all__ = [
    "AnnotationElement",
    "EncodedAnnotation",
    "EncodedArray",
    "EncodedValue",
    "ValueType",
]


class ValueType(IntEnum):
    """Encoded value type constants.

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


@dataclass(slots=True, frozen=True)
class AnnotationElement:
    """Element of an encoded annotation structure.

    See https://source.android.com/docs/core/runtime/dex-format#annotation-element-format
    """

    name_idx: Idx[StringIdItem]
    value: EncodedValue

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Parse an AnnotationElement from a Cursor."""
        name_idx = Idx[Any](cursor.read_uleb128())
        value = EncodedValue.from_cursor(cursor)
        return cls(name_idx=name_idx, value=value)

    def to_bytes(self) -> bytes:
        """Encode this AnnotationElement to raw DEX bytes."""
        return encode_uleb128(self.name_idx) + self.value.to_bytes()


@dataclass(slots=True, frozen=True)
class EncodedAnnotation:
    """Encoded annotation structure.

    See https://source.android.com/docs/core/runtime/dex-format#encoded-annotation-format
    """

    type_idx: Idx[TypeIdItem]
    size: int
    elements: tuple[AnnotationElement, ...]

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
        type_idx = Idx[Any](cursor.read_uleb128())
        size = cursor.read_uleb128()
        elements = tuple(AnnotationElement.from_cursor(cursor) for _ in range(size))
        return cls(type_idx=type_idx, size=size, elements=elements)

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

    See https://source.android.com/docs/core/runtime/dex-format#encoded-array-format
    """

    size: int
    values: tuple[EncodedValue, ...]

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
        return cls(size=size, values=values)

    def to_bytes(self) -> bytes:
        """Encode this EncodedArray to raw DEX bytes."""
        return encode_uleb128(self.size) + b"".join(v.to_bytes() for v in self.values)


@dataclass(slots=True, frozen=True)
class EncodedValue:
    """Encoded value structure representing single value entry in DEX.

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
        if value_type == ValueType.BYTE:
            value = int.from_bytes(cursor.read_bytes(value_arg + 1), "little", signed=True)
        elif value_type in (ValueType.SHORT, ValueType.INT, ValueType.LONG):
            value = int.from_bytes(cursor.read_bytes(value_arg + 1), "little", signed=True)
        elif value_type == ValueType.CHAR:
            value = int.from_bytes(cursor.read_bytes(value_arg + 1), "little", signed=False)
        elif value_type == ValueType.FLOAT:
            raw = cursor.read_bytes(value_arg + 1)
            padded = b"\x00" * (4 - (value_arg + 1)) + raw
            value = struct.unpack("<f", padded)[0]
        elif value_type == ValueType.DOUBLE:
            raw = cursor.read_bytes(value_arg + 1)
            padded = b"\x00" * (8 - (value_arg + 1)) + raw
            value = struct.unpack("<d", padded)[0]
        elif value_type == ValueType.METHOD_TYPE:
            value = Idx[Any](
                int.from_bytes(cursor.read_bytes(value_arg + 1), "little", signed=False)
            )
        elif value_type == ValueType.METHOD_HANDLE:
            value = Idx[Any](
                int.from_bytes(cursor.read_bytes(value_arg + 1), "little", signed=False)
            )
        elif value_type == ValueType.STRING:
            value = Idx[Any](
                int.from_bytes(cursor.read_bytes(value_arg + 1), "little", signed=False)
            )
        elif value_type == ValueType.TYPE:
            value = Idx[Any](
                int.from_bytes(cursor.read_bytes(value_arg + 1), "little", signed=False)
            )
        elif value_type == ValueType.FIELD:
            value = Idx[Any](
                int.from_bytes(cursor.read_bytes(value_arg + 1), "little", signed=False)
            )
        elif value_type == ValueType.METHOD:
            value = Idx[Any](
                int.from_bytes(cursor.read_bytes(value_arg + 1), "little", signed=False)
            )
        elif value_type == ValueType.ENUM:
            value = Idx[Any](
                int.from_bytes(cursor.read_bytes(value_arg + 1), "little", signed=False)
            )
        elif value_type == ValueType.ARRAY:
            value = EncodedArray.from_cursor(cursor)
        elif value_type == ValueType.ANNOTATION:
            value = EncodedAnnotation.from_cursor(cursor)
        elif value_type == ValueType.NULL:
            value = None
        elif value_type == ValueType.BOOLEAN:
            value = bool(value_arg)
        else:
            raise ValueError(f"Unknown value_type: {value_type:#x}")

        return cls(value_arg=value_arg, value_type=value_type, value=value)

    def to_bytes(self) -> bytes:
        """Encode this EncodedValue to raw DEX bytes."""
        if self.value_type == ValueType.BOOLEAN:
            header = ((1 if self.value else 0) << 5) | ValueType.BOOLEAN
            return bytes([header])

        if self.value_type == ValueType.NULL:
            header = ValueType.NULL
            return bytes([header])

        if self.value_type == ValueType.ARRAY:
            header = ValueType.ARRAY
            return bytes([header]) + self.value.to_bytes()

        if self.value_type == ValueType.ANNOTATION:
            header = ValueType.ANNOTATION
            return bytes([header]) + self.value.to_bytes()

        if self.value_type == ValueType.FLOAT:
            packed = struct.pack("<f", self.value)
            raw = packed[4 - (self.value_arg + 1) :]
            header = (self.value_arg << 5) | ValueType.FLOAT
            return bytes([header]) + raw

        if self.value_type == ValueType.DOUBLE:
            packed = struct.pack("<d", self.value)
            raw = packed[8 - (self.value_arg + 1) :]
            header = (self.value_arg << 5) | ValueType.DOUBLE
            return bytes([header]) + raw

        if self.value_type == ValueType.BYTE:
            raw = int(self.value).to_bytes(1, "little", signed=True)
            header = (0 << 5) | ValueType.BYTE
            return bytes([header]) + raw

        if self.value_type in (ValueType.SHORT, ValueType.INT, ValueType.LONG):
            max_bytes = {
                ValueType.SHORT: 2,
                ValueType.INT: 4,
                ValueType.LONG: 8,
            }[self.value_type]
            try:
                raw = int(self.value).to_bytes(self.value_arg + 1, "little", signed=True)
                arg = self.value_arg
            except OverflowError as err:
                raw = None
                arg = None
                for size in range(1, max_bytes + 1):
                    try:
                        raw = int(self.value).to_bytes(size, "little", signed=True)
                        arg = size - 1
                        break
                    except OverflowError:
                        continue
                if raw is None or arg is None:
                    msg = f"Value {self.value} does not fit in {self.value_type.name}"
                    raise OverflowError(msg) from err
            header = (arg << 5) | self.value_type
            return bytes([header]) + raw

        # Unsigned integer index types: CHAR, STRING, TYPE, FIELD, METHOD, ENUM, etc.
        max_bytes = 2 if self.value_type == ValueType.CHAR else 4
        try:
            raw = int(self.value).to_bytes(self.value_arg + 1, "little", signed=False)
            arg = self.value_arg
        except OverflowError as err:
            raw = None
            arg = None
            for size in range(1, max_bytes + 1):
                try:
                    raw = int(self.value).to_bytes(size, "little", signed=False)
                    arg = size - 1
                    break
                except OverflowError:
                    continue
            if raw is None or arg is None:
                msg = f"Value {self.value} does not fit in {self.value_type.name}"
                raise OverflowError(msg) from err
        header = (arg << 5) | self.value_type
        return bytes([header]) + raw
