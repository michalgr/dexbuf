"""DEX specification items and records.

See https://source.android.com/docs/core/runtime/dex-format
"""

import struct
from collections.abc import Buffer, Iterator
from dataclasses import dataclass
from typing import Any, ClassVar, Self, overload

from dexbuf.cursor import Cursor
from dexbuf.leb128 import encode_uleb128
from dexbuf.mutf8 import encode_mutf8, utf16_code_units
from dexbuf.types import NO_OFFSET, Idx, Offset

__all__ = [
    "CallSiteIdItem",
    "ClassDataItem",
    "ClassDefItem",
    "EncodedField",
    "EncodedMethod",
    "FieldIdItem",
    "MethodHandleItem",
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


@dataclass(slots=True, frozen=True)
class EncodedField:
    """Encoded field format representing field definition within class_data_item.

    See https://source.android.com/docs/core/runtime/dex-format#encoded-field-format
    """

    field_idx_diff: int
    access_flags: int

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Parse an EncodedField from a Cursor."""
        field_idx_diff = cursor.read_uleb128()
        access_flags = cursor.read_uleb128()
        return cls(field_idx_diff=field_idx_diff, access_flags=access_flags)

    def to_bytes(self) -> bytes:
        """Encode this EncodedField to raw DEX bytes."""
        return encode_uleb128(self.field_idx_diff) + encode_uleb128(self.access_flags)


@dataclass(slots=True, frozen=True)
class EncodedMethod:
    """Encoded method format representing method definition within class_data_item.

    See https://source.android.com/docs/core/runtime/dex-format#encoded-method
    """

    method_idx_diff: int
    access_flags: int
    code_off: Offset[Any]

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Parse an EncodedMethod from a Cursor."""
        method_idx_diff = cursor.read_uleb128()
        access_flags = cursor.read_uleb128()
        code_off = Offset[Any](cursor.read_uleb128())
        return cls(
            method_idx_diff=method_idx_diff,
            access_flags=access_flags,
            code_off=code_off,
        )

    def to_bytes(self) -> bytes:
        """Encode this EncodedMethod to raw DEX bytes."""
        return (
            encode_uleb128(self.method_idx_diff)
            + encode_uleb128(self.access_flags)
            + encode_uleb128(self.code_off)
        )


@dataclass(slots=True, frozen=True)
class ClassDataItem:
    """Class data item record containing field and method definitions for a class.

    See https://source.android.com/docs/core/runtime/dex-format#class-data-item
    """

    EncodedField = EncodedField
    EncodedMethod = EncodedMethod

    PADDING: ClassVar[int] = 1

    static_fields_size: int
    instance_fields_size: int
    direct_methods_size: int
    virtual_methods_size: int
    static_fields: tuple[EncodedField, ...]
    instance_fields: tuple[EncodedField, ...]
    direct_methods: tuple[EncodedMethod, ...]
    virtual_methods: tuple[EncodedMethod, ...]

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Parse a ClassDataItem from a Cursor."""
        static_fields_size = cursor.read_uleb128()
        instance_fields_size = cursor.read_uleb128()
        direct_methods_size = cursor.read_uleb128()
        virtual_methods_size = cursor.read_uleb128()
        static_fields = tuple(EncodedField.from_cursor(cursor) for _ in range(static_fields_size))
        instance_fields = tuple(
            EncodedField.from_cursor(cursor) for _ in range(instance_fields_size)
        )
        direct_methods = tuple(
            EncodedMethod.from_cursor(cursor) for _ in range(direct_methods_size)
        )
        virtual_methods = tuple(
            EncodedMethod.from_cursor(cursor) for _ in range(virtual_methods_size)
        )
        return cls(
            static_fields_size=static_fields_size,
            instance_fields_size=instance_fields_size,
            direct_methods_size=direct_methods_size,
            virtual_methods_size=virtual_methods_size,
            static_fields=static_fields,
            instance_fields=instance_fields,
            direct_methods=direct_methods,
            virtual_methods=virtual_methods,
        )

    @classmethod
    def from_buffer(cls, buffer: Buffer, offset: Offset[Self] = NO_OFFSET) -> Self:
        """Parse a ClassDataItem from a buffer starting at offset."""
        return cls.from_cursor(Cursor(buffer, offset))

    def to_bytes(self) -> bytes:
        """Encode this ClassDataItem to raw DEX bytes."""
        return (
            encode_uleb128(self.static_fields_size)
            + encode_uleb128(self.instance_fields_size)
            + encode_uleb128(self.direct_methods_size)
            + encode_uleb128(self.virtual_methods_size)
            + b"".join(f.to_bytes() for f in self.static_fields)
            + b"".join(f.to_bytes() for f in self.instance_fields)
            + b"".join(m.to_bytes() for m in self.direct_methods)
            + b"".join(m.to_bytes() for m in self.virtual_methods)
        )


@dataclass(slots=True, frozen=True)
class ClassDefItem:
    """Class definition item record representing class definition.

    See https://source.android.com/docs/core/runtime/dex-format#class-def-item
    """

    PADDING: ClassVar[int] = 4
    STRUCT: ClassVar[struct.Struct] = struct.Struct("<8I")

    class_idx: Idx[TypeIdItem]
    access_flags: int
    superclass_idx: Idx[TypeIdItem]
    interfaces_off: Offset[TypeList]
    source_file_idx: Idx[StringIdItem]
    annotations_off: Offset[Any]
    class_data_off: Offset[ClassDataItem]
    static_values_off: Offset[Any]

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Parse a ClassDefItem from a Cursor."""
        (
            class_idx,
            access_flags,
            superclass_idx,
            interfaces_off,
            source_file_idx,
            annotations_off,
            class_data_off,
            static_values_off,
        ) = cursor.unpack(cls.STRUCT)
        return cls(
            class_idx=Idx[TypeIdItem](class_idx),
            access_flags=access_flags,
            superclass_idx=Idx[TypeIdItem](superclass_idx),
            interfaces_off=Offset[TypeList](interfaces_off),
            source_file_idx=Idx[StringIdItem](source_file_idx),
            annotations_off=Offset[Any](annotations_off),
            class_data_off=Offset[ClassDataItem](class_data_off),
            static_values_off=Offset[Any](static_values_off),
        )

    @classmethod
    def from_buffer(cls, buffer: Buffer, offset: Offset[Self] = NO_OFFSET) -> Self:
        """Parse a ClassDefItem from a buffer starting at offset."""
        return cls.from_cursor(Cursor(buffer, offset))

    def to_bytes(self) -> bytes:
        """Encode this ClassDefItem to raw DEX bytes."""
        return self.STRUCT.pack(
            self.class_idx,
            self.access_flags,
            self.superclass_idx,
            self.interfaces_off,
            self.source_file_idx,
            self.annotations_off,
            self.class_data_off,
            self.static_values_off,
        )


@dataclass(slots=True, frozen=True)
class CallSiteIdItem:
    """Call site ID item record representing offset to a call_site_item.

    See https://source.android.com/docs/core/runtime/dex-format#call-site-id-item
    """

    PADDING: ClassVar[int] = 4
    STRUCT: ClassVar[struct.Struct] = struct.Struct("<I")

    call_site_off: Offset[Any]

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Parse a CallSiteIdItem from a Cursor."""
        (call_site_off,) = cursor.unpack(cls.STRUCT)
        return cls(call_site_off=Offset[Any](call_site_off))

    @classmethod
    def from_buffer(cls, buffer: Buffer, offset: Offset[Self] = NO_OFFSET) -> Self:
        """Parse a CallSiteIdItem from a buffer starting at offset."""
        return cls.from_cursor(Cursor(buffer, offset))

    def to_bytes(self) -> bytes:
        """Encode this CallSiteIdItem to raw DEX bytes."""
        return self.STRUCT.pack(self.call_site_off)


@dataclass(slots=True, frozen=True)
class MethodHandleItem:
    """Method handle item record representing method handle definition.

    See https://source.android.com/docs/core/runtime/dex-format#method-handle-item
    """

    PADDING: ClassVar[int] = 4
    STRUCT: ClassVar[struct.Struct] = struct.Struct("<HHHH")

    method_handle_type: int
    unused1: int
    field_or_method_id: int
    unused2: int

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Parse a MethodHandleItem from a Cursor."""
        method_handle_type, unused1, field_or_method_id, unused2 = cursor.unpack(cls.STRUCT)
        return cls(
            method_handle_type=method_handle_type,
            unused1=unused1,
            field_or_method_id=field_or_method_id,
            unused2=unused2,
        )

    @classmethod
    def from_buffer(cls, buffer: Buffer, offset: Offset[Self] = NO_OFFSET) -> Self:
        """Parse a MethodHandleItem from a buffer starting at offset."""
        return cls.from_cursor(Cursor(buffer, offset))

    def to_bytes(self) -> bytes:
        """Encode this MethodHandleItem to raw DEX bytes."""
        return self.STRUCT.pack(
            self.method_handle_type, self.unused1, self.field_or_method_id, self.unused2
        )
