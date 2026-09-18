"""Dalvik instruction abstract base class and format representations.

See https://source.android.com/docs/core/runtime/dex-format#instruction-formats
"""

import struct
from abc import ABC
from collections.abc import Buffer
from dataclasses import dataclass
from typing import ClassVar, Self

from dexbuf.cursor import Cursor
from dexbuf.instructions.opcodes import Opcode
from dexbuf.types import (
    NO_OFFSET,
    ArgumentCount,
    BranchOffset,
    Hat,
    Idx,
    Literal,
    Offset,
    Reg,
)

__all__ = [
    "Format3rc",
    "Format10t",
    "Format10x",
    "Format11n",
    "Format11x",
    "Format12x",
    "Format20t",
    "Format21c",
    "Format21h",
    "Format21s",
    "Format21t",
    "Format22b",
    "Format22c",
    "Format22s",
    "Format22t",
    "Format22x",
    "Format23x",
    "Format30t",
    "Format31c",
    "Format31i",
    "Format31t",
    "Format32x",
    "Format35c",
    "Format51l",
    "Instruction",
]


@dataclass(slots=True, frozen=True)
class Instruction(ABC):
    """Abstract base class for all Dalvik instructions.

    See https://source.android.com/docs/core/runtime/dex-format#instruction-formats
    """

    OPCODE: ClassVar[Opcode]
    SIZE: ClassVar[int]  # Size in 16-bit code units
    STRUCT: ClassVar[struct.Struct]

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Parse an instruction instance from a Cursor."""
        raise NotImplementedError

    @classmethod
    def from_buffer(cls, buffer: Buffer, offset: Offset[Self] = NO_OFFSET) -> Self:
        """Parse an instruction instance from a buffer starting at offset."""
        return cls.from_cursor(Cursor(buffer, offset))

    def to_bytes(self) -> bytes:
        """Encode this instruction to raw DEX bytes."""
        raise NotImplementedError


# --- 1-Code-Unit Formats ---


@dataclass(slots=True, frozen=True)
class Format10x(Instruction):
    """Format 10x: ØØ|op."""

    SIZE: ClassVar[int] = 1
    STRUCT: ClassVar[struct.Struct] = struct.Struct("<BB")

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        _op, _unused = cursor.unpack(cls.STRUCT)
        return cls()

    def to_bytes(self) -> bytes:
        return self.STRUCT.pack(self.OPCODE, 0)


@dataclass(slots=True, frozen=True)
class Format12x(Instruction):
    """Format 12x: B|A|op."""

    SIZE: ClassVar[int] = 1
    STRUCT: ClassVar[struct.Struct] = struct.Struct("<BB")

    a: Reg
    b: Reg

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        _op, ba = cursor.unpack(cls.STRUCT)
        a = Reg(ba & 0x0F)
        b = Reg((ba >> 4) & 0x0F)
        return cls(a=a, b=b)

    def to_bytes(self) -> bytes:
        ba = ((int(self.b) & 0x0F) << 4) | (int(self.a) & 0x0F)
        return self.STRUCT.pack(self.OPCODE, ba)


@dataclass(slots=True, frozen=True)
class Format11n(Instruction):
    """Format 11n: B|A|op (4-bit signed literal in B)."""

    SIZE: ClassVar[int] = 1
    STRUCT: ClassVar[struct.Struct] = struct.Struct("<BB")

    a: Reg
    b: Literal

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        _op, ba = cursor.unpack(cls.STRUCT)
        a = Reg(ba & 0x0F)
        raw_b = (ba >> 4) & 0x0F
        if raw_b >= 8:
            raw_b -= 16
        return cls(a=a, b=Literal(raw_b))

    def to_bytes(self) -> bytes:
        ba = ((int(self.b) & 0x0F) << 4) | (int(self.a) & 0x0F)
        return self.STRUCT.pack(self.OPCODE, ba)


@dataclass(slots=True, frozen=True)
class Format11x(Instruction):
    """Format 11x: AA|op."""

    SIZE: ClassVar[int] = 1
    STRUCT: ClassVar[struct.Struct] = struct.Struct("<BB")

    a: Reg

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        _op, a = cursor.unpack(cls.STRUCT)
        return cls(a=Reg(a))

    def to_bytes(self) -> bytes:
        return self.STRUCT.pack(self.OPCODE, self.a)


@dataclass(slots=True, frozen=True)
class Format10t(Instruction):
    """Format 10t: AA|op (8-bit signed branch offset in AA)."""

    SIZE: ClassVar[int] = 1
    STRUCT: ClassVar[struct.Struct] = struct.Struct("<Bb")

    a: BranchOffset

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        _op, a = cursor.unpack(cls.STRUCT)
        return cls(a=BranchOffset(a))

    def to_bytes(self) -> bytes:
        return self.STRUCT.pack(self.OPCODE, self.a)


# --- 2-Code-Unit Formats ---


@dataclass(slots=True, frozen=True)
class Format20t(Instruction):
    """Format 20t: ØØ|op AAAA (16-bit signed branch offset)."""

    SIZE: ClassVar[int] = 2
    STRUCT: ClassVar[struct.Struct] = struct.Struct("<BBh")

    a: BranchOffset

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        _op, _unused, a = cursor.unpack(cls.STRUCT)
        return cls(a=BranchOffset(a))

    def to_bytes(self) -> bytes:
        return self.STRUCT.pack(self.OPCODE, 0, self.a)


@dataclass(slots=True, frozen=True)
class Format21t(Instruction):
    """Format 21t: AA|op AAAA."""

    SIZE: ClassVar[int] = 2
    STRUCT: ClassVar[struct.Struct] = struct.Struct("<BBh")

    a: Reg
    b: BranchOffset

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        _op, a, b = cursor.unpack(cls.STRUCT)
        return cls(a=Reg(a), b=BranchOffset(b))

    def to_bytes(self) -> bytes:
        return self.STRUCT.pack(self.OPCODE, self.a, self.b)


@dataclass(slots=True, frozen=True)
class Format21s(Instruction):
    """Format 21s: AA|op BBBBs."""

    SIZE: ClassVar[int] = 2
    STRUCT: ClassVar[struct.Struct] = struct.Struct("<BBh")

    a: Reg
    b: Literal

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        _op, a, b = cursor.unpack(cls.STRUCT)
        return cls(a=Reg(a), b=Literal(b))

    def to_bytes(self) -> bytes:
        return self.STRUCT.pack(self.OPCODE, self.a, self.b)


@dataclass(slots=True, frozen=True)
class Format21h(Instruction):
    """Format 21h: AA|op BBBB (shifted high-bits constant)."""

    SIZE: ClassVar[int] = 2
    STRUCT: ClassVar[struct.Struct] = struct.Struct("<BBH")
    SHIFT: ClassVar[int]

    a: Reg
    b: Hat

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        _op, a, val = cursor.unpack(cls.STRUCT)
        hat = Hat(val << (cls.SHIFT * 8))
        return cls(a=Reg(a), b=hat)

    def to_bytes(self) -> bytes:
        val = (int(self.b) >> (self.SHIFT * 8)) & 0xFFFF
        return self.STRUCT.pack(self.OPCODE, self.a, val)


@dataclass(slots=True, frozen=True)
class Format21c[RefT](Instruction):
    """Format 21c: AA|op BBBB."""

    SIZE: ClassVar[int] = 2
    STRUCT: ClassVar[struct.Struct] = struct.Struct("<BBH")

    a: Reg
    b: Idx[RefT]

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        _op, a, b = cursor.unpack(cls.STRUCT)
        return cls(a=Reg(a), b=Idx[RefT](b))

    def to_bytes(self) -> bytes:
        return self.STRUCT.pack(self.OPCODE, self.a, self.b)


@dataclass(slots=True, frozen=True)
class Format23x(Instruction):
    """Format 23x: AA|op CC|BB."""

    SIZE: ClassVar[int] = 2
    STRUCT: ClassVar[struct.Struct] = struct.Struct("<BBBB")

    a: Reg
    b: Reg
    c: Reg

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        _op, a, b, c = cursor.unpack(cls.STRUCT)
        return cls(a=Reg(a), b=Reg(b), c=Reg(c))

    def to_bytes(self) -> bytes:
        return self.STRUCT.pack(self.OPCODE, self.a, self.b, self.c)


@dataclass(slots=True, frozen=True)
class Format22x(Instruction):
    """Format 22x: AA|op BBBB."""

    SIZE: ClassVar[int] = 2
    STRUCT: ClassVar[struct.Struct] = struct.Struct("<BBH")

    a: Reg
    b: Reg

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        _op, a, b = cursor.unpack(cls.STRUCT)
        return cls(a=Reg(a), b=Reg(b))

    def to_bytes(self) -> bytes:
        return self.STRUCT.pack(self.OPCODE, self.a, self.b)


@dataclass(slots=True, frozen=True)
class Format22b(Instruction):
    """Format 22b: AA|op CC|BB (signed 8-bit literal in CC)."""

    SIZE: ClassVar[int] = 2
    STRUCT: ClassVar[struct.Struct] = struct.Struct("<BBBb")

    a: Reg
    b: Reg
    c: Literal

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        _op, a, b, c = cursor.unpack(cls.STRUCT)
        return cls(a=Reg(a), b=Reg(b), c=Literal(c))

    def to_bytes(self) -> bytes:
        return self.STRUCT.pack(self.OPCODE, self.a, self.b, self.c)


@dataclass(slots=True, frozen=True)
class Format22t(Instruction):
    """Format 22t: B|A|op CCCC."""

    SIZE: ClassVar[int] = 2
    STRUCT: ClassVar[struct.Struct] = struct.Struct("<BBh")

    a: Reg
    b: Reg
    c: BranchOffset

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        _op, ba, c = cursor.unpack(cls.STRUCT)
        a = Reg(ba & 0x0F)
        b = Reg((ba >> 4) & 0x0F)
        return cls(a=a, b=b, c=BranchOffset(c))

    def to_bytes(self) -> bytes:
        ba = ((int(self.b) & 0x0F) << 4) | (int(self.a) & 0x0F)
        return self.STRUCT.pack(self.OPCODE, ba, self.c)


@dataclass(slots=True, frozen=True)
class Format22s(Instruction):
    """Format 22s: B|A|op CCCC."""

    SIZE: ClassVar[int] = 2
    STRUCT: ClassVar[struct.Struct] = struct.Struct("<BBh")

    a: Reg
    b: Reg
    c: Literal

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        _op, ba, c = cursor.unpack(cls.STRUCT)
        a = Reg(ba & 0x0F)
        b = Reg((ba >> 4) & 0x0F)
        return cls(a=a, b=b, c=Literal(c))

    def to_bytes(self) -> bytes:
        ba = ((int(self.b) & 0x0F) << 4) | (int(self.a) & 0x0F)
        return self.STRUCT.pack(self.OPCODE, ba, self.c)


@dataclass(slots=True, frozen=True)
class Format22c[RefT](Instruction):
    """Format 22c: B|A|op CCCC."""

    SIZE: ClassVar[int] = 2
    STRUCT: ClassVar[struct.Struct] = struct.Struct("<BBH")

    a: Reg
    b: Reg
    c: Idx[RefT]

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        _op, ba, c = cursor.unpack(cls.STRUCT)
        a = Reg(ba & 0x0F)
        b = Reg((ba >> 4) & 0x0F)
        return cls(a=a, b=b, c=Idx[RefT](c))

    def to_bytes(self) -> bytes:
        ba = ((int(self.b) & 0x0F) << 4) | (int(self.a) & 0x0F)
        return self.STRUCT.pack(self.OPCODE, ba, self.c)


# --- 3-Code-Unit Formats ---


@dataclass(slots=True, frozen=True)
class Format30t(Instruction):
    """Format 30t: ØØ|op AAAA_AAAA (32-bit signed branch offset)."""

    SIZE: ClassVar[int] = 3
    STRUCT: ClassVar[struct.Struct] = struct.Struct("<BBi")

    a: BranchOffset

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        _op, _unused, a = cursor.unpack(cls.STRUCT)
        return cls(a=BranchOffset(a))

    def to_bytes(self) -> bytes:
        return self.STRUCT.pack(self.OPCODE, 0, self.a)


@dataclass(slots=True, frozen=True)
class Format32x(Instruction):
    """Format 32x: ØØ|op AAAA BBBB."""

    SIZE: ClassVar[int] = 3
    STRUCT: ClassVar[struct.Struct] = struct.Struct("<BBHH")

    a: Reg
    b: Reg

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        _op, _unused, a, b = cursor.unpack(cls.STRUCT)
        return cls(a=Reg(a), b=Reg(b))

    def to_bytes(self) -> bytes:
        return self.STRUCT.pack(self.OPCODE, 0, self.a, self.b)


@dataclass(slots=True, frozen=True)
class Format31i(Instruction):
    """Format 31i: AA|op BBBBBBBB."""

    SIZE: ClassVar[int] = 3
    STRUCT: ClassVar[struct.Struct] = struct.Struct("<BBi")

    a: Reg
    b: Literal

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        _op, a, b = cursor.unpack(cls.STRUCT)
        return cls(a=Reg(a), b=Literal(b))

    def to_bytes(self) -> bytes:
        return self.STRUCT.pack(self.OPCODE, self.a, self.b)


@dataclass(slots=True, frozen=True)
class Format31t(Instruction):
    """Format 31t: AA|op BBBBBBBB."""

    SIZE: ClassVar[int] = 3
    STRUCT: ClassVar[struct.Struct] = struct.Struct("<BBi")

    a: Reg
    b: BranchOffset

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        _op, a, b = cursor.unpack(cls.STRUCT)
        return cls(a=Reg(a), b=BranchOffset(b))

    def to_bytes(self) -> bytes:
        return self.STRUCT.pack(self.OPCODE, self.a, self.b)


@dataclass(slots=True, frozen=True)
class Format31c[RefT](Instruction):
    """Format 31c: AA|op BBBBBBBB (32-bit reference index)."""

    SIZE: ClassVar[int] = 3
    STRUCT: ClassVar[struct.Struct] = struct.Struct("<BBI")

    a: Reg
    b: Idx[RefT]

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        _op, a, b = cursor.unpack(cls.STRUCT)
        return cls(a=Reg(a), b=Idx[RefT](b))

    def to_bytes(self) -> bytes:
        return self.STRUCT.pack(self.OPCODE, self.a, self.b)


@dataclass(slots=True, frozen=True)
class Format35c[RefT](Instruction):
    """Format 35c: A|G|op BBBB F|E|D|C."""

    SIZE: ClassVar[int] = 3
    STRUCT: ClassVar[struct.Struct] = struct.Struct("<BBHBB")

    a: ArgumentCount
    b: Idx[RefT]
    c: Reg
    d: Reg
    e: Reg
    f: Reg
    g: Reg

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        _op, ag, b, dc, fe = cursor.unpack(cls.STRUCT)
        a = ArgumentCount((ag >> 4) & 0x0F)
        g = Reg(ag & 0x0F)
        c = Reg(dc & 0x0F)
        d = Reg((dc >> 4) & 0x0F)
        e = Reg(fe & 0x0F)
        f = Reg((fe >> 4) & 0x0F)
        return cls(a=a, b=Idx[RefT](b), c=c, d=d, e=e, f=f, g=g)

    def to_bytes(self) -> bytes:
        ag = ((int(self.a) & 0x0F) << 4) | (int(self.g) & 0x0F)
        dc = ((int(self.d) & 0x0F) << 4) | (int(self.c) & 0x0F)
        fe = ((int(self.f) & 0x0F) << 4) | (int(self.e) & 0x0F)
        return self.STRUCT.pack(self.OPCODE, ag, self.b, dc, fe)


@dataclass(slots=True, frozen=True)
class Format3rc[RefT](Instruction):
    """Format 3rc: AA|op BBBB CCCC."""

    SIZE: ClassVar[int] = 3
    STRUCT: ClassVar[struct.Struct] = struct.Struct("<BBHH")

    a: ArgumentCount
    b: Idx[RefT]
    c: Reg

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        _op, a, b, c = cursor.unpack(cls.STRUCT)
        return cls(a=ArgumentCount(a), b=Idx[RefT](b), c=Reg(c))

    def to_bytes(self) -> bytes:
        return self.STRUCT.pack(self.OPCODE, self.a, self.b, self.c)


# --- 5-Code-Unit Formats ---


@dataclass(slots=True, frozen=True)
class Format51l(Instruction):
    """Format 51l: AA|op BBBBBBBB_BBBBBBBB (64-bit literal)."""

    SIZE: ClassVar[int] = 5
    STRUCT: ClassVar[struct.Struct] = struct.Struct("<BBq")

    a: Reg
    b: Literal

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        _op, a, b = cursor.unpack(cls.STRUCT)
        return cls(a=Reg(a), b=Literal(b))

    def to_bytes(self) -> bytes:
        return self.STRUCT.pack(self.OPCODE, self.a, self.b)
