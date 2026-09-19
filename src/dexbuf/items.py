"""DEX specification items and records.

See https://source.android.com/docs/core/runtime/dex-format
"""

import struct
from collections.abc import Buffer, Iterator
from dataclasses import dataclass
from enum import IntEnum
from typing import TYPE_CHECKING, ClassVar, Self, overload

from dexbuf.cursor import Cursor
from dexbuf.debug import skip_debug_instruction
from dexbuf.leb128 import encode_sleb128, encode_uleb128, encode_uleb128p1
from dexbuf.mutf8 import encode_mutf8, utf16_code_units
from dexbuf.types import NO_OFFSET, Idx, Offset
from dexbuf.value import EncodedAnnotation, EncodedArray

if TYPE_CHECKING:
    from dexbuf.debug import DebugInstruction, DebugPosition
    from dexbuf.instructions import IOP

__all__ = [
    "AnnotationItem",
    "AnnotationOffItem",
    "AnnotationSetItem",
    "AnnotationSetRefItem",
    "AnnotationSetRefList",
    "AnnotationVisibility",
    "AnnotationsDirectoryItem",
    "CallSiteIdItem",
    "ClassDataItem",
    "ClassDefItem",
    "CodeItem",
    "DebugInfoItem",
    "EncodedArrayItem",
    "EncodedCatchHandler",
    "EncodedCatchHandlerList",
    "EncodedField",
    "EncodedMethod",
    "EncodedTypeAddrPair",
    "FieldAnnotation",
    "FieldIdItem",
    "MethodAnnotation",
    "MethodHandleItem",
    "MethodIdItem",
    "ParameterAnnotation",
    "ProtoIdItem",
    "StringDataItem",
    "StringIdItem",
    "TryItem",
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
    code_off: Offset[CodeItem]

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Parse an EncodedMethod from a Cursor."""
        method_idx_diff = cursor.read_uleb128()
        access_flags = cursor.read_uleb128()
        code_off = Offset[CodeItem](cursor.read_uleb128())
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
class TryItem:
    """Try item record representing a block of code covered by try/catch.

    See https://source.android.com/docs/core/runtime/dex-format#try-item
    """

    PADDING: ClassVar[int] = 4
    STRUCT: ClassVar[struct.Struct] = struct.Struct("<IHH")

    start_addr: int
    insn_count: int
    handler_off: int

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Parse a TryItem from a Cursor."""
        start_addr, insn_count, handler_off = cursor.unpack(cls.STRUCT)
        return cls(
            start_addr=start_addr,
            insn_count=insn_count,
            handler_off=handler_off,
        )

    @classmethod
    def from_buffer(cls, buffer: Buffer, offset: Offset[Self] = NO_OFFSET) -> Self:
        """Parse a TryItem from a buffer starting at offset."""
        return cls.from_cursor(Cursor(buffer, offset))

    def to_bytes(self) -> bytes:
        """Encode this TryItem to raw DEX bytes."""
        return self.STRUCT.pack(self.start_addr, self.insn_count, self.handler_off)


@dataclass(slots=True, frozen=True)
class EncodedTypeAddrPair:
    """Encoded type address pair representing exception type and catch handler address.

    See https://source.android.com/docs/core/runtime/dex-format#encoded-type-addr-pair
    """

    type_idx: Idx[TypeIdItem]
    addr: int

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Parse an EncodedTypeAddrPair from a Cursor."""
        type_idx = cursor.read_uleb128()
        addr = cursor.read_uleb128()
        return cls(type_idx=Idx[TypeIdItem](type_idx), addr=addr)

    def to_bytes(self) -> bytes:
        """Encode this EncodedTypeAddrPair to raw DEX bytes."""
        return encode_uleb128(self.type_idx) + encode_uleb128(self.addr)


@dataclass(slots=True, frozen=True)
class EncodedCatchHandler:
    """Encoded catch handler structure representing list of catch pairs and optional catch-all.

    See https://source.android.com/docs/core/runtime/dex-format#encoded-catch-handler
    """

    size: int
    handlers: tuple[EncodedTypeAddrPair, ...]
    catch_all_addr: int | None

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Parse an EncodedCatchHandler from a Cursor."""
        size = cursor.read_sleb128()
        count = abs(size)
        handlers = tuple(EncodedTypeAddrPair.from_cursor(cursor) for _ in range(count))
        if size <= 0:
            catch_all_addr = cursor.read_uleb128()
        else:
            catch_all_addr = None
        return cls(size=size, handlers=handlers, catch_all_addr=catch_all_addr)

    def to_bytes(self) -> bytes:
        """Encode this EncodedCatchHandler to raw DEX bytes."""
        res = encode_sleb128(self.size) + b"".join(h.to_bytes() for h in self.handlers)
        if self.size <= 0:
            if self.catch_all_addr is None:
                raise ValueError("catch_all_addr required when size <= 0")
            res += encode_uleb128(self.catch_all_addr)
        return res


@dataclass(slots=True, frozen=True)
class EncodedCatchHandlerList:
    """Encoded catch handler list structure.

    See https://source.android.com/docs/core/runtime/dex-format#encoded-catch-handler-list
    """

    size: int
    list: tuple[EncodedCatchHandler, ...]

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Parse an EncodedCatchHandlerList from a Cursor."""
        size = cursor.read_uleb128()
        handlers = tuple(EncodedCatchHandler.from_cursor(cursor) for _ in range(size))
        return cls(size=size, list=handlers)

    @classmethod
    def from_buffer(cls, buffer: Buffer, offset: Offset[Self] = NO_OFFSET) -> Self:
        """Parse an EncodedCatchHandlerList from a buffer starting at offset."""
        return cls.from_cursor(Cursor(buffer, offset))

    def to_bytes(self) -> bytes:
        """Encode this EncodedCatchHandlerList to raw DEX bytes."""
        return encode_uleb128(self.size) + b"".join(h.to_bytes() for h in self.list)


@dataclass(slots=True, frozen=True)
class DebugInfoItem:
    """Debug info item record containing position and local variable debug bytecode.

    See https://source.android.com/docs/core/runtime/dex-format#debug-info-item
    """

    PADDING: ClassVar[int] = 1

    line_start: int
    parameters_size: int
    parameter_names: tuple[Idx[StringIdItem] | None, ...]
    bytecode: memoryview

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Parse a DebugInfoItem from a Cursor using zero-allocation bytecode scanning."""
        line_start = cursor.read_uleb128()
        parameters_size = cursor.read_uleb128()
        parameter_names = tuple(
            None if (val := cursor.read_uleb128p1()) == -1 else Idx[StringIdItem](val)
            for _ in range(parameters_size)
        )

        bytecode_start = cursor.tell()
        while True:
            opcode = skip_debug_instruction(cursor)
            if opcode == 0x00:  # DBG_END_SEQUENCE
                break
        bytecode_end = cursor.tell()
        bytecode = cursor.subcursor(bytecode_start, bytecode_end - bytecode_start)._buffer

        return cls(
            line_start=line_start,
            parameters_size=parameters_size,
            parameter_names=parameter_names,
            bytecode=bytecode,
        )

    @classmethod
    def from_buffer(cls, buffer: Buffer, offset: Offset[Self] = NO_OFFSET) -> Self:
        """Parse a DebugInfoItem from a buffer starting at offset."""
        return cls.from_cursor(Cursor(buffer, offset))

    def to_bytes(self) -> bytes:
        """Encode this DebugInfoItem to raw DEX bytes."""
        return (
            encode_uleb128(self.line_start)
            + encode_uleb128(self.parameters_size)
            + b"".join(encode_uleb128p1(-1 if p is None else p) for p in self.parameter_names)
            + bytes(self.bytecode)
        )

    def iter_instructions(self) -> Iterator[DebugInstruction]:
        """Iterate over parsed Dalvik debug instructions lazily."""
        from dexbuf.debug import parse_debug_instruction

        cursor = Cursor(self.bytecode)
        while not cursor.is_eof:
            yield parse_debug_instruction(cursor)

    def iter_positions(
        self, initial_source_file: Idx[StringIdItem] | None = None
    ) -> Iterator[DebugPosition]:
        """Evaluate debug bytecode state machine and yield DebugPosition entries."""
        from dexbuf.debug import iter_debug_positions

        return iter_debug_positions(
            self.iter_instructions(),
            line_start=self.line_start,
            initial_source_file=initial_source_file,
        )


@dataclass(slots=True, frozen=True)
class CodeItem:
    """Code item record representing method execution header, bytecode, and try/catch data.

    See https://source.android.com/docs/core/runtime/dex-format#code-item
    """

    PADDING: ClassVar[int] = 4
    HEADER: ClassVar[struct.Struct] = struct.Struct("<4H2I")

    registers_size: int
    ins_size: int
    outs_size: int
    tries_size: int
    debug_info_off: Offset[DebugInfoItem]
    insns_size: int
    insns: memoryview
    tries: tuple[TryItem, ...]
    handlers: EncodedCatchHandlerList | None

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Parse a CodeItem from a Cursor."""
        (
            registers_size,
            ins_size,
            outs_size,
            tries_size,
            debug_info_off,
            insns_size,
        ) = cursor.unpack(cls.HEADER)

        insns = cursor.read_slice(insns_size * 2)

        if tries_size > 0:
            if insns_size % 2 != 0:
                cursor.skip(2)
            tries = tuple(TryItem.from_cursor(cursor) for _ in range(tries_size))
            handlers = EncodedCatchHandlerList.from_cursor(cursor)
        else:
            tries = ()
            handlers = None

        return cls(
            registers_size=registers_size,
            ins_size=ins_size,
            outs_size=outs_size,
            tries_size=tries_size,
            debug_info_off=Offset[DebugInfoItem](debug_info_off),
            insns_size=insns_size,
            insns=insns,
            tries=tries,
            handlers=handlers,
        )

    @classmethod
    def from_buffer(cls, buffer: Buffer, offset: Offset[Self] = NO_OFFSET) -> Self:
        """Parse a CodeItem from a buffer starting at offset."""
        return cls.from_cursor(Cursor(buffer, offset))

    def iter_iops(self) -> Iterator[IOP]:
        """Iterate over Dalvik instructions and payloads in bytecode lazily."""
        from dexbuf.instructions import parse_iop

        cursor = Cursor(self.insns)
        while not cursor.is_eof:
            yield parse_iop(cursor)

    def __iter__(self) -> Iterator[IOP]:
        return self.iter_iops()

    def parse_iops(self) -> tuple[IOP, ...]:
        """Parse all Dalvik instructions and payloads into a tuple."""
        return tuple(self.iter_iops())

    def to_bytes(self) -> bytes:
        """Encode this CodeItem to raw DEX bytes."""
        header_bytes = self.HEADER.pack(
            self.registers_size,
            self.ins_size,
            self.outs_size,
            self.tries_size,
            self.debug_info_off,
            self.insns_size,
        )
        insns_bytes = bytes(self.insns)
        padding_bytes = b"\x00\x00" if (self.tries_size > 0 and self.insns_size % 2 != 0) else b""
        tries_bytes = b"".join(t.to_bytes() for t in self.tries)
        handlers_bytes = self.handlers.to_bytes() if self.handlers is not None else b""

        return header_bytes + insns_bytes + padding_bytes + tries_bytes + handlers_bytes


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


class AnnotationVisibility(IntEnum):
    """Annotation visibility levels.

    See https://source.android.com/docs/core/runtime/dex-format#visibility-values
    """

    BUILD = 0x00
    RUNTIME = 0x01
    SYSTEM = 0x02


@dataclass(slots=True, frozen=True)
class AnnotationItem:
    """Annotation item record.

    See https://source.android.com/docs/core/runtime/dex-format#annotation-item
    """

    PADDING: ClassVar[int] = 1

    visibility: int
    annotation: EncodedAnnotation

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Parse an AnnotationItem from a Cursor."""
        visibility = cursor.read_u8()
        annotation = EncodedAnnotation.from_cursor(cursor)
        return cls(visibility=visibility, annotation=annotation)

    @classmethod
    def from_buffer(cls, buffer: Buffer, offset: Offset[Self] = NO_OFFSET) -> Self:
        """Parse an AnnotationItem from a buffer starting at offset."""
        return cls.from_cursor(Cursor(buffer, offset))

    def to_bytes(self) -> bytes:
        """Encode this AnnotationItem to raw DEX bytes."""
        return bytes([self.visibility]) + self.annotation.to_bytes()


@dataclass(slots=True, frozen=True)
class AnnotationOffItem:
    """Annotation offset item record.

    See https://source.android.com/docs/core/runtime/dex-format#annotation-off-item
    """

    STRUCT: ClassVar[struct.Struct] = struct.Struct("<I")

    annotation_off: Offset[AnnotationItem]

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Parse an AnnotationOffItem from a Cursor."""
        (annotation_off,) = cursor.unpack(cls.STRUCT)
        return cls(annotation_off=Offset[AnnotationItem](annotation_off))

    @classmethod
    def from_buffer(cls, buffer: Buffer, offset: Offset[Self] = NO_OFFSET) -> Self:
        """Parse an AnnotationOffItem from a buffer starting at offset."""
        return cls.from_cursor(Cursor(buffer, offset))

    def to_bytes(self) -> bytes:
        """Encode this AnnotationOffItem to raw DEX bytes."""
        return self.STRUCT.pack(self.annotation_off)


@dataclass(slots=True, frozen=True)
class AnnotationSetItem:
    """Annotation set item record.

    See https://source.android.com/docs/core/runtime/dex-format#annotation-set-item
    """

    PADDING: ClassVar[int] = 4
    HEADER: ClassVar[struct.Struct] = struct.Struct("<I")

    size: int
    entries: tuple[AnnotationOffItem, ...]

    def __len__(self) -> int:
        return len(self.entries)

    def __iter__(self) -> Iterator[AnnotationOffItem]:
        return iter(self.entries)

    @overload
    def __getitem__(self, index: int) -> AnnotationOffItem: ...

    @overload
    def __getitem__(self, index: slice) -> tuple[AnnotationOffItem, ...]: ...

    def __getitem__(self, index: int | slice) -> AnnotationOffItem | tuple[AnnotationOffItem, ...]:
        return self.entries[index]

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Parse an AnnotationSetItem from a Cursor."""
        (size,) = cursor.unpack(cls.HEADER)
        entries = tuple(AnnotationOffItem.from_cursor(cursor) for _ in range(size))
        return cls(size=size, entries=entries)

    @classmethod
    def from_buffer(cls, buffer: Buffer, offset: Offset[Self] = NO_OFFSET) -> Self:
        """Parse an AnnotationSetItem from a buffer starting at offset."""
        return cls.from_cursor(Cursor(buffer, offset))

    def to_bytes(self) -> bytes:
        """Encode this AnnotationSetItem to raw DEX bytes."""
        return self.HEADER.pack(self.size) + b"".join(entry.to_bytes() for entry in self.entries)


@dataclass(slots=True, frozen=True)
class AnnotationSetRefItem:
    """Annotation set reference item record.

    See https://source.android.com/docs/core/runtime/dex-format#annotation-set-ref-item
    """

    STRUCT: ClassVar[struct.Struct] = struct.Struct("<I")

    annotations_off: Offset[AnnotationSetItem]

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Parse an AnnotationSetRefItem from a Cursor."""
        (annotations_off,) = cursor.unpack(cls.STRUCT)
        return cls(annotations_off=Offset[AnnotationSetItem](annotations_off))

    @classmethod
    def from_buffer(cls, buffer: Buffer, offset: Offset[Self] = NO_OFFSET) -> Self:
        """Parse an AnnotationSetRefItem from a buffer starting at offset."""
        return cls.from_cursor(Cursor(buffer, offset))

    def to_bytes(self) -> bytes:
        """Encode this AnnotationSetRefItem to raw DEX bytes."""
        return self.STRUCT.pack(self.annotations_off)


@dataclass(slots=True, frozen=True)
class AnnotationSetRefList:
    """Annotation set ref list record.

    See https://source.android.com/docs/core/runtime/dex-format#annotation-set-ref-list
    """

    PADDING: ClassVar[int] = 4
    HEADER: ClassVar[struct.Struct] = struct.Struct("<I")

    size: int
    list: tuple[AnnotationSetRefItem, ...]

    def __len__(self) -> int:
        return len(self.list)

    def __iter__(self) -> Iterator[AnnotationSetRefItem]:
        return iter(self.list)

    @overload
    def __getitem__(self, index: int) -> AnnotationSetRefItem: ...

    @overload
    def __getitem__(self, index: slice) -> tuple[AnnotationSetRefItem, ...]: ...

    def __getitem__(
        self, index: int | slice
    ) -> AnnotationSetRefItem | tuple[AnnotationSetRefItem, ...]:
        return self.list[index]

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Parse an AnnotationSetRefList from a Cursor."""
        (size,) = cursor.unpack(cls.HEADER)
        items = tuple(AnnotationSetRefItem.from_cursor(cursor) for _ in range(size))
        return cls(size=size, list=items)

    @classmethod
    def from_buffer(cls, buffer: Buffer, offset: Offset[Self] = NO_OFFSET) -> Self:
        """Parse an AnnotationSetRefList from a buffer starting at offset."""
        return cls.from_cursor(Cursor(buffer, offset))

    def to_bytes(self) -> bytes:
        """Encode this AnnotationSetRefList to raw DEX bytes."""
        return self.HEADER.pack(self.size) + b"".join(item.to_bytes() for item in self.list)


@dataclass(slots=True, frozen=True)
class FieldAnnotation:
    """Field annotation record.

    See https://source.android.com/docs/core/runtime/dex-format#field-annotation
    """

    STRUCT: ClassVar[struct.Struct] = struct.Struct("<II")

    field_idx: Idx[FieldIdItem]
    annotations_off: Offset[AnnotationSetItem]

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Parse a FieldAnnotation from a Cursor."""
        field_idx, annotations_off = cursor.unpack(cls.STRUCT)
        return cls(
            field_idx=Idx[FieldIdItem](field_idx),
            annotations_off=Offset[AnnotationSetItem](annotations_off),
        )

    @classmethod
    def from_buffer(cls, buffer: Buffer, offset: Offset[Self] = NO_OFFSET) -> Self:
        """Parse a FieldAnnotation from a buffer starting at offset."""
        return cls.from_cursor(Cursor(buffer, offset))

    def to_bytes(self) -> bytes:
        """Encode this FieldAnnotation to raw DEX bytes."""
        return self.STRUCT.pack(self.field_idx, self.annotations_off)


@dataclass(slots=True, frozen=True)
class MethodAnnotation:
    """Method annotation record.

    See https://source.android.com/docs/core/runtime/dex-format#method-annotation
    """

    STRUCT: ClassVar[struct.Struct] = struct.Struct("<II")

    method_idx: Idx[MethodIdItem]
    annotations_off: Offset[AnnotationSetItem]

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Parse a MethodAnnotation from a Cursor."""
        method_idx, annotations_off = cursor.unpack(cls.STRUCT)
        return cls(
            method_idx=Idx[MethodIdItem](method_idx),
            annotations_off=Offset[AnnotationSetItem](annotations_off),
        )

    @classmethod
    def from_buffer(cls, buffer: Buffer, offset: Offset[Self] = NO_OFFSET) -> Self:
        """Parse a MethodAnnotation from a buffer starting at offset."""
        return cls.from_cursor(Cursor(buffer, offset))

    def to_bytes(self) -> bytes:
        """Encode this MethodAnnotation to raw DEX bytes."""
        return self.STRUCT.pack(self.method_idx, self.annotations_off)


@dataclass(slots=True, frozen=True)
class ParameterAnnotation:
    """Parameter annotation record.

    See https://source.android.com/docs/core/runtime/dex-format#parameter-annotation
    """

    STRUCT: ClassVar[struct.Struct] = struct.Struct("<II")

    method_idx: Idx[MethodIdItem]
    annotations_off: Offset[AnnotationSetRefList]

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Parse a ParameterAnnotation from a Cursor."""
        method_idx, annotations_off = cursor.unpack(cls.STRUCT)
        return cls(
            method_idx=Idx[MethodIdItem](method_idx),
            annotations_off=Offset[AnnotationSetRefList](annotations_off),
        )

    @classmethod
    def from_buffer(cls, buffer: Buffer, offset: Offset[Self] = NO_OFFSET) -> Self:
        """Parse a ParameterAnnotation from a buffer starting at offset."""
        return cls.from_cursor(Cursor(buffer, offset))

    def to_bytes(self) -> bytes:
        """Encode this ParameterAnnotation to raw DEX bytes."""
        return self.STRUCT.pack(self.method_idx, self.annotations_off)


@dataclass(slots=True, frozen=True)
class AnnotationsDirectoryItem:
    """Annotations directory item record.

    See https://source.android.com/docs/core/runtime/dex-format#annotations-directory-item
    """

    PADDING: ClassVar[int] = 4
    HEADER: ClassVar[struct.Struct] = struct.Struct("<4I")

    class_annotations_off: Offset[AnnotationSetItem]
    fields_size: int
    annotated_methods_size: int
    annotated_parameters_size: int
    field_annotations: tuple[FieldAnnotation, ...]
    method_annotations: tuple[MethodAnnotation, ...]
    parameter_annotations: tuple[ParameterAnnotation, ...]

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Parse an AnnotationsDirectoryItem from a Cursor."""
        (
            class_annotations_off,
            fields_size,
            annotated_methods_size,
            annotated_parameters_size,
        ) = cursor.unpack(cls.HEADER)

        field_annotations = tuple(FieldAnnotation.from_cursor(cursor) for _ in range(fields_size))
        method_annotations = tuple(
            MethodAnnotation.from_cursor(cursor) for _ in range(annotated_methods_size)
        )
        parameter_annotations = tuple(
            ParameterAnnotation.from_cursor(cursor) for _ in range(annotated_parameters_size)
        )

        return cls(
            class_annotations_off=Offset[AnnotationSetItem](class_annotations_off),
            fields_size=fields_size,
            annotated_methods_size=annotated_methods_size,
            annotated_parameters_size=annotated_parameters_size,
            field_annotations=field_annotations,
            method_annotations=method_annotations,
            parameter_annotations=parameter_annotations,
        )

    @classmethod
    def from_buffer(cls, buffer: Buffer, offset: Offset[Self] = NO_OFFSET) -> Self:
        """Parse an AnnotationsDirectoryItem from a buffer starting at offset."""
        return cls.from_cursor(Cursor(buffer, offset))

    def to_bytes(self) -> bytes:
        """Encode this AnnotationsDirectoryItem to raw DEX bytes."""
        return (
            self.HEADER.pack(
                self.class_annotations_off,
                self.fields_size,
                self.annotated_methods_size,
                self.annotated_parameters_size,
            )
            + b"".join(f.to_bytes() for f in self.field_annotations)
            + b"".join(m.to_bytes() for m in self.method_annotations)
            + b"".join(p.to_bytes() for p in self.parameter_annotations)
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
    annotations_off: Offset[AnnotationsDirectoryItem]
    class_data_off: Offset[ClassDataItem]
    static_values_off: Offset[EncodedArrayItem]

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
            annotations_off=Offset[AnnotationsDirectoryItem](annotations_off),
            class_data_off=Offset[ClassDataItem](class_data_off),
            static_values_off=Offset[EncodedArrayItem](static_values_off),
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
class EncodedArrayItem:
    """Encoded array item record.

    See https://source.android.com/docs/core/runtime/dex-format#encoded-array-item
    """

    PADDING: ClassVar[int] = 1

    value: EncodedArray

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Parse an EncodedArrayItem from a Cursor."""
        return cls(value=EncodedArray.from_cursor(cursor))

    @classmethod
    def from_buffer(cls, buffer: Buffer, offset: Offset[Self] = NO_OFFSET) -> Self:
        """Parse an EncodedArrayItem from a buffer starting at offset."""
        return cls.from_cursor(Cursor(buffer, offset))

    def to_bytes(self) -> bytes:
        """Encode this EncodedArrayItem to raw DEX bytes."""
        return self.value.to_bytes()


@dataclass(slots=True, frozen=True)
class CallSiteIdItem:
    """Call site ID item record representing offset to a call_site_item.

    See https://source.android.com/docs/core/runtime/dex-format#call-site-id-item
    """

    PADDING: ClassVar[int] = 4
    STRUCT: ClassVar[struct.Struct] = struct.Struct("<I")

    call_site_off: Offset[EncodedArrayItem]

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Parse a CallSiteIdItem from a Cursor."""
        (call_site_off,) = cursor.unpack(cls.STRUCT)
        return cls(call_site_off=Offset[EncodedArrayItem](call_site_off))

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
