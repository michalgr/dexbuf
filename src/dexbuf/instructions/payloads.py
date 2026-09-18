"""Dalvik instruction payload representations and IOP union type.

See https://source.android.com/docs/core/runtime/dex-format#packed-switch-format
"""

import struct
from collections.abc import Buffer
from dataclasses import dataclass
from typing import ClassVar, Self

from dexbuf.cursor import Cursor
from dexbuf.instructions.definitions import parse_instruction
from dexbuf.instructions.formats import Instruction
from dexbuf.instructions.opcodes import Opcode
from dexbuf.types import NO_OFFSET, BranchOffset, Offset

__all__ = [
    "IOP",
    "FillArrayDataPayload",
    "PackedSwitchPayload",
    "Payload",
    "SparseSwitchPayload",
    "parse_iop",
]


@dataclass(slots=True, frozen=True)
class PackedSwitchPayload:
    """Packed-switch payload record.

    See https://source.android.com/docs/core/runtime/dex-format#packed-switch-format
    """

    OPCODE: ClassVar[Opcode] = Opcode.PACKED_SWITCH_PAYLOAD
    HEADER_STRUCT: ClassVar[struct.Struct] = struct.Struct("<HHi")

    first_key: int
    targets: tuple[BranchOffset, ...]

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Parse a PackedSwitchPayload from a Cursor."""
        ident, size, first_key = cursor.unpack(cls.HEADER_STRUCT)
        if ident != cls.OPCODE:
            raise ValueError(
                f"Invalid packed-switch payload magic: 0x{ident:04x} (expected 0x{cls.OPCODE:04x})"
            )
        targets = tuple(BranchOffset(cursor.read_i32()) for _ in range(size))
        return cls(first_key=first_key, targets=targets)

    @classmethod
    def from_buffer(cls, buffer: Buffer, offset: Offset[Self] = NO_OFFSET) -> Self:
        """Parse a PackedSwitchPayload from a buffer starting at offset."""
        return cls.from_cursor(Cursor(buffer, offset))

    def to_bytes(self) -> bytes:
        """Encode this PackedSwitchPayload to raw DEX bytes."""
        hdr = self.HEADER_STRUCT.pack(self.OPCODE, len(self.targets), self.first_key)
        targets_bytes = b"".join(struct.pack("<i", target) for target in self.targets)
        return hdr + targets_bytes


@dataclass(slots=True, frozen=True)
class SparseSwitchPayload:
    """Sparse-switch payload record.

    See https://source.android.com/docs/core/runtime/dex-format#sparse-switch-format
    """

    OPCODE: ClassVar[Opcode] = Opcode.SPARSE_SWITCH_PAYLOAD
    HEADER_STRUCT: ClassVar[struct.Struct] = struct.Struct("<HH")

    keys: tuple[int, ...]
    targets: tuple[BranchOffset, ...]

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Parse a SparseSwitchPayload from a Cursor."""
        ident, size = cursor.unpack(cls.HEADER_STRUCT)
        if ident != cls.OPCODE:
            raise ValueError(
                f"Invalid sparse-switch payload magic: 0x{ident:04x} (expected 0x{cls.OPCODE:04x})"
            )
        keys = tuple(cursor.read_i32() for _ in range(size))
        targets = tuple(BranchOffset(cursor.read_i32()) for _ in range(size))
        return cls(keys=keys, targets=targets)

    @classmethod
    def from_buffer(cls, buffer: Buffer, offset: Offset[Self] = NO_OFFSET) -> Self:
        """Parse a SparseSwitchPayload from a buffer starting at offset."""
        return cls.from_cursor(Cursor(buffer, offset))

    def to_bytes(self) -> bytes:
        """Encode this SparseSwitchPayload to raw DEX bytes."""
        hdr = self.HEADER_STRUCT.pack(self.OPCODE, len(self.keys))
        keys_bytes = b"".join(struct.pack("<i", key) for key in self.keys)
        targets_bytes = b"".join(struct.pack("<i", target) for target in self.targets)
        return hdr + keys_bytes + targets_bytes


@dataclass(slots=True, frozen=True)
class FillArrayDataPayload:
    """Fill-array-data payload record.

    See https://source.android.com/docs/core/runtime/dex-format#fill-array-data-format
    """

    OPCODE: ClassVar[Opcode] = Opcode.FILL_ARRAY_DATA_PAYLOAD
    HEADER_STRUCT: ClassVar[struct.Struct] = struct.Struct("<HHI")

    element_width: int
    size: int
    data: bytes

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Parse a FillArrayDataPayload from a Cursor."""
        ident, element_width, size = cursor.unpack(cls.HEADER_STRUCT)
        if ident != cls.OPCODE:
            raise ValueError(
                f"Invalid fill-array-data payload magic: 0x{ident:04x} "
                f"(expected 0x{cls.OPCODE:04x})"
            )
        data_len = element_width * size
        data = cursor.read_bytes(data_len)
        if data_len % 2 != 0:
            cursor.skip(1)
        return cls(element_width=element_width, size=size, data=data)

    @classmethod
    def from_buffer(cls, buffer: Buffer, offset: Offset[Self] = NO_OFFSET) -> Self:
        """Parse a FillArrayDataPayload from a buffer starting at offset."""
        return cls.from_cursor(Cursor(buffer, offset))

    def to_bytes(self) -> bytes:
        """Encode this FillArrayDataPayload to raw DEX bytes."""
        hdr = self.HEADER_STRUCT.pack(self.OPCODE, self.element_width, self.size)
        padding = b"\x00" if (len(self.data) % 2 != 0) else b""
        return hdr + self.data + padding


type Payload = PackedSwitchPayload | SparseSwitchPayload | FillArrayDataPayload
type IOP = Instruction | Payload


def parse_iop(cursor: Cursor) -> IOP:
    """Parse an Instruction or Payload (IOP) from a Cursor."""
    word0 = cursor.subcursor().read_u16()
    if word0 == Opcode.PACKED_SWITCH_PAYLOAD:
        return PackedSwitchPayload.from_cursor(cursor)
    elif word0 == Opcode.SPARSE_SWITCH_PAYLOAD:
        return SparseSwitchPayload.from_cursor(cursor)
    elif word0 == Opcode.FILL_ARRAY_DATA_PAYLOAD:
        return FillArrayDataPayload.from_cursor(cursor)
    else:
        return parse_instruction(cursor)
