"""DEX specification items and records.

See https://source.android.com/docs/core/runtime/dex-format
"""

import struct
from collections.abc import Buffer, Iterator
from dataclasses import dataclass
from typing import ClassVar, Self, overload

from dexbuf.cursor import Cursor
from dexbuf.leb128 import encode_uleb128
from dexbuf.mutf8 import encode_mutf8, utf16_code_units
from dexbuf.types import NO_OFFSET, Idx, Offset

__all__ = [
    "FieldIdItem",
    "MethodIdItem",
    "ProtoIdItem",
    "StringDataItem",
    "StringIdItem",
    "TypeIdItem",
    "TypeList",
]


@dataclass(slots=True, frozen=True)
class StringDataItem:
    """String data item record representing string content and UTF-16 code unit length.

    See https://source.android.com/docs/core/runtime/dex-format#string-data-item
    """

    PADDING: ClassVar[int] = 1

    utf16_size: int
    data: str

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Parse a StringDataItem from a Cursor."""
        utf16_size = cursor.read_uleb128()
        data = cursor.read_mutf8(expected_utf16_size=utf16_size)
        return cls(utf16_size=utf16_size, data=data)

    @classmethod
    def from_buffer(cls, buffer: Buffer, offset: Offset[Self] = NO_OFFSET) -> Self:
        """Parse a StringDataItem from a buffer starting at offset."""
        return cls.from_cursor(Cursor(buffer, offset))

    @classmethod
    def from_str(cls, s: str) -> Self:
        """Construct a StringDataItem directly from a Python string."""
        return cls(utf16_size=utf16_code_units(s), data=s)

    def to_bytes(self) -> bytes:
        """Encode this StringDataItem to raw DEX bytes."""
        return encode_uleb128(self.utf16_size) + encode_mutf8(self.data, null_terminated=True)


@dataclass(slots=True, frozen=True)
class StringIdItem:
    """String ID item record representing offset to a string_data_item.

    See https://source.android.com/docs/core/runtime/dex-format#string-item
    """

    PADDING: ClassVar[int] = 4
    STRUCT: ClassVar[struct.Struct] = struct.Struct("<I")

    string_data_off: Offset[StringDataItem]

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Parse a StringIdItem from a Cursor."""
        (string_data_off,) = cursor.unpack(cls.STRUCT)
        return cls(string_data_off=Offset[StringDataItem](string_data_off))

    @classmethod
    def from_buffer(cls, buffer: Buffer, offset: Offset[Self] = NO_OFFSET) -> Self:
        """Parse a StringIdItem from a buffer starting at offset."""
        return cls.from_cursor(Cursor(buffer, offset))

    def to_bytes(self) -> bytes:
        """Encode this StringIdItem to raw DEX bytes."""
        return self.STRUCT.pack(self.string_data_off)


@dataclass(slots=True, frozen=True)
class TypeIdItem:
    """Type ID item record representing index into the string_ids list.

    See https://source.android.com/docs/core/runtime/dex-format#type-item
    """

    PADDING: ClassVar[int] = 4
    STRUCT: ClassVar[struct.Struct] = struct.Struct("<I")

    descriptor_idx: Idx[StringIdItem]

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Parse a TypeIdItem from a Cursor."""
        (descriptor_idx,) = cursor.unpack(cls.STRUCT)
        return cls(descriptor_idx=Idx[StringIdItem](descriptor_idx))

    @classmethod
    def from_buffer(cls, buffer: Buffer, offset: Offset[Self] = NO_OFFSET) -> Self:
        """Parse a TypeIdItem from a buffer starting at offset."""
        return cls.from_cursor(Cursor(buffer, offset))

    def to_bytes(self) -> bytes:
        """Encode this TypeIdItem to raw DEX bytes."""
        return self.STRUCT.pack(self.descriptor_idx)


@dataclass(slots=True, frozen=True)
class TypeList:
    """Type list record representing list of type indices.

    See https://source.android.com/docs/core/runtime/dex-format#type-list
    """

    PADDING: ClassVar[int] = 4
    HEADER: ClassVar[struct.Struct] = struct.Struct("<I")

    @dataclass(slots=True, frozen=True)
    class Item:
        """Item element within a TypeList.

        See https://source.android.com/docs/core/runtime/dex-format#type-list
        """

        STRUCT: ClassVar[struct.Struct] = struct.Struct("<H")

        type_idx: Idx[TypeIdItem]

        @classmethod
        def from_cursor(cls, cursor: Cursor) -> Self:
            """Parse a TypeList.Item from a Cursor."""
            (type_idx,) = cursor.unpack(cls.STRUCT)
            return cls(type_idx=Idx[TypeIdItem](type_idx))

        def to_bytes(self) -> bytes:
            """Encode this TypeList.Item to raw DEX bytes."""
            return self.STRUCT.pack(self.type_idx)

    size: int
    list: tuple[Item, ...]

    def __len__(self) -> int:
        return len(self.list)

    def __iter__(self) -> Iterator[Item]:
        return iter(self.list)

    @overload
    def __getitem__(self, index: int) -> Item: ...

    @overload
    def __getitem__(self, index: slice) -> tuple[Item, ...]: ...

    def __getitem__(self, index: int | slice) -> Item | tuple[Item, ...]:
        return self.list[index]

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Parse a TypeList from a Cursor."""
        (size,) = cursor.unpack(cls.HEADER)
        items = tuple(cls.Item.from_cursor(cursor) for _ in range(size))
        return cls(size=size, list=items)

    @classmethod
    def from_buffer(cls, buffer: Buffer, offset: Offset[Self] = NO_OFFSET) -> Self:
        """Parse a TypeList from a buffer starting at offset."""
        return cls.from_cursor(Cursor(buffer, offset))

    def to_bytes(self) -> bytes:
        """Encode this TypeList to raw DEX bytes."""
        return self.HEADER.pack(self.size) + b"".join(item.to_bytes() for item in self.list)


@dataclass(slots=True, frozen=True)
class ProtoIdItem:
    """Method prototype ID item record representing signature of a prototype.

    See https://source.android.com/docs/core/runtime/dex-format#proto-item
    """

    PADDING: ClassVar[int] = 4
    STRUCT: ClassVar[struct.Struct] = struct.Struct("<III")

    shorty_idx: Idx[StringIdItem]
    return_type_idx: Idx[TypeIdItem]
    parameters_off: Offset[TypeList]

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Parse a ProtoIdItem from a Cursor."""
        shorty_idx, return_type_idx, parameters_off = cursor.unpack(cls.STRUCT)
        return cls(
            shorty_idx=Idx[StringIdItem](shorty_idx),
            return_type_idx=Idx[TypeIdItem](return_type_idx),
            parameters_off=Offset[TypeList](parameters_off),
        )

    @classmethod
    def from_buffer(cls, buffer: Buffer, offset: Offset[Self] = NO_OFFSET) -> Self:
        """Parse a ProtoIdItem from a buffer starting at offset."""
        return cls.from_cursor(Cursor(buffer, offset))

    def to_bytes(self) -> bytes:
        """Encode this ProtoIdItem to raw DEX bytes."""
        return self.STRUCT.pack(self.shorty_idx, self.return_type_idx, self.parameters_off)


@dataclass(slots=True, frozen=True)
class FieldIdItem:
    """Field ID item record representing field definition.

    See https://source.android.com/docs/core/runtime/dex-format#field-item
    """

    PADDING: ClassVar[int] = 4
    STRUCT: ClassVar[struct.Struct] = struct.Struct("<HHI")

    class_idx: Idx[TypeIdItem]
    type_idx: Idx[TypeIdItem]
    name_idx: Idx[StringIdItem]

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Parse a FieldIdItem from a Cursor."""
        class_idx, type_idx, name_idx = cursor.unpack(cls.STRUCT)
        return cls(
            class_idx=Idx[TypeIdItem](class_idx),
            type_idx=Idx[TypeIdItem](type_idx),
            name_idx=Idx[StringIdItem](name_idx),
        )

    @classmethod
    def from_buffer(cls, buffer: Buffer, offset: Offset[Self] = NO_OFFSET) -> Self:
        """Parse a FieldIdItem from a buffer starting at offset."""
        return cls.from_cursor(Cursor(buffer, offset))

    def to_bytes(self) -> bytes:
        """Encode this FieldIdItem to raw DEX bytes."""
        return self.STRUCT.pack(self.class_idx, self.type_idx, self.name_idx)


@dataclass(slots=True, frozen=True)
class MethodIdItem:
    """Method ID item record representing method definition.

    See https://source.android.com/docs/core/runtime/dex-format#method-item
    """

    PADDING: ClassVar[int] = 4
    STRUCT: ClassVar[struct.Struct] = struct.Struct("<HHI")

    class_idx: Idx[TypeIdItem]
    proto_idx: Idx[ProtoIdItem]
    name_idx: Idx[StringIdItem]

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Parse a MethodIdItem from a Cursor."""
        class_idx, proto_idx, name_idx = cursor.unpack(cls.STRUCT)
        return cls(
            class_idx=Idx[TypeIdItem](class_idx),
            proto_idx=Idx[ProtoIdItem](proto_idx),
            name_idx=Idx[StringIdItem](name_idx),
        )

    @classmethod
    def from_buffer(cls, buffer: Buffer, offset: Offset[Self] = NO_OFFSET) -> Self:
        """Parse a MethodIdItem from a buffer starting at offset."""
        return cls.from_cursor(Cursor(buffer, offset))

    def to_bytes(self) -> bytes:
        """Encode this MethodIdItem to raw DEX bytes."""
        return self.STRUCT.pack(self.class_idx, self.proto_idx, self.name_idx)
