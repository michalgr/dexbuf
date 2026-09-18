"""Dalvik instruction payload representations (PackedSwitch, SparseSwitch, FillArrayData).

See https://source.android.com/docs/core/runtime/dex-format#packed-switch-payload
"""

import struct
from collections.abc import Buffer
from dataclasses import dataclass
from typing import ClassVar, Self

from dexbuf.cursor import Cursor
from dexbuf.instructions.opcodes import Opcode
from dexbuf.types import NO_OFFSET, BranchOffset, Offset

__all__ = [
    "FillArrayDataPayload",
    "PackedSwitchPayload",
    "Payload",
    "SparseSwitchPayload",
]


@dataclass(slots=True, frozen=True)
class PackedSwitchPayload:
    """Packed switch payload pseudo-instruction.

    See https://source.android.com/docs/core/runtime/dex-format#packed-switch-payload
    """

    IDENT: ClassVar[int] = Opcode.PACKED_SWITCH_PAYLOAD
    HEADER_STRUCT: ClassVar[struct.Struct] = struct.Struct("<HHi")

    first_key: int
    targets: tuple[BranchOffset, ...]

    @property
    def code_units(self) -> int:
        """Size in 16-bit code units."""
        return 4 + len(self.targets) * 2

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Parse a PackedSwitchPayload from a Cursor."""
        ident, size, first_key = cursor.unpack(cls.HEADER_STRUCT)
        if ident != cls.IDENT:
            raise ValueError(
                f"Invalid PackedSwitchPayload ident: expected 0x{cls.IDENT:04x}, got 0x{ident:04x}"
            )
        targets = tuple(BranchOffset(cursor.read_i32()) for _ in range(size))
        return cls(first_key=first_key, targets=targets)

    @classmethod
    def from_buffer(cls, buffer: Buffer, offset: Offset[Self] = NO_OFFSET) -> Self:
        """Parse a PackedSwitchPayload from a buffer starting at offset."""
        return cls.from_cursor(Cursor(buffer, offset))

    def to_bytes(self) -> bytes:
        """Encode this PackedSwitchPayload to raw DEX bytes."""
        header = self.HEADER_STRUCT.pack(self.IDENT, len(self.targets), self.first_key)
        return header + b"".join(struct.pack("<i", int(t)) for t in self.targets)


@dataclass(slots=True, frozen=True)
class SparseSwitchPayload:
    """Sparse switch payload pseudo-instruction.

    See https://source.android.com/docs/core/runtime/dex-format#sparse-switch-payload
    """

    IDENT: ClassVar[int] = Opcode.SPARSE_SWITCH_PAYLOAD
    HEADER_STRUCT: ClassVar[struct.Struct] = struct.Struct("<HH")

    keys: tuple[int, ...]
    targets: tuple[BranchOffset, ...]

    @property
    def code_units(self) -> int:
        """Size in 16-bit code units."""
        return 2 + len(self.keys) * 2 + len(self.targets) * 2

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Parse a SparseSwitchPayload from a Cursor."""
        ident, size = cursor.unpack(cls.HEADER_STRUCT)
        if ident != cls.IDENT:
            raise ValueError(
                f"Invalid SparseSwitchPayload ident: expected 0x{cls.IDENT:04x}, got 0x{ident:04x}"
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
        if len(self.keys) != len(self.targets):
            raise ValueError(
                f"Keys count ({len(self.keys)}) does not match targets count ({len(self.targets)})"
            )
        header = self.HEADER_STRUCT.pack(self.IDENT, len(self.keys))
        keys_bytes = b"".join(struct.pack("<i", k) for k in self.keys)
        targets_bytes = b"".join(struct.pack("<i", int(t)) for t in self.targets)
        return header + keys_bytes + targets_bytes


@dataclass(slots=True, frozen=True)
class FillArrayDataPayload:
    """Fill array data payload pseudo-instruction.

    See https://source.android.com/docs/core/runtime/dex-format#fill-array-data-payload
    """

    IDENT: ClassVar[int] = Opcode.FILL_ARRAY_DATA_PAYLOAD
    HEADER_STRUCT: ClassVar[struct.Struct] = struct.Struct("<HHI")

    element_width: int
    size: int
    data: bytes

    @property
    def code_units(self) -> int:
        """Size in 16-bit code units."""
        return 4 + (len(self.data) + 1) // 2

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Parse a FillArrayDataPayload from a Cursor."""
        ident, element_width, size = cursor.unpack(cls.HEADER_STRUCT)
        if ident != cls.IDENT:
            raise ValueError(
                f"Invalid FillArrayDataPayload ident: expected 0x{cls.IDENT:04x}, got 0x{ident:04x}"
            )
        data_byte_count = element_width * size
        data = cursor.read_bytes(data_byte_count)
        if data_byte_count % 2 != 0:
            cursor.skip(1)
        return cls(element_width=element_width, size=size, data=data)

    @classmethod
    def from_buffer(cls, buffer: Buffer, offset: Offset[Self] = NO_OFFSET) -> Self:
        """Parse a FillArrayDataPayload from a buffer starting at offset."""
        return cls.from_cursor(Cursor(buffer, offset))

    def to_bytes(self) -> bytes:
        """Encode this FillArrayDataPayload to raw DEX bytes."""
        header = self.HEADER_STRUCT.pack(self.IDENT, self.element_width, self.size)
        raw = header + self.data
        if len(self.data) % 2 != 0:
            raw += b"\x00"
        return raw


type Payload = PackedSwitchPayload | SparseSwitchPayload | FillArrayDataPayload
