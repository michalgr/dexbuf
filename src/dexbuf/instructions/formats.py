"""Dalvik instruction base class and format representations.

See https://source.android.com/docs/core/runtime/dex-format#dalvik-opcodes
"""

import struct
from abc import ABC
from dataclasses import dataclass
from typing import ClassVar, Self

from dexbuf.cursor import Cursor
from dexbuf.instructions.opcodes import Opcode
from dexbuf.items import (
    CallSiteIdItem,
    FieldIdItem,
    MethodHandleItem,
    MethodIdItem,
    ProtoIdItem,
    StringIdItem,
    TypeIdItem,
)
from dexbuf.types import ArgumentCount, BranchOffset, Hat, Idx, Literal, Reg

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
    "RefItem",
]

type RefItem = (
    StringIdItem
    | TypeIdItem
    | FieldIdItem
    | MethodIdItem
    | ProtoIdItem
    | CallSiteIdItem
    | MethodHandleItem
)


@dataclass(slots=True, frozen=True)
class Instruction(ABC):
    """Abstract base class for all Dalvik instructions.

    See https://source.android.com/docs/core/runtime/dex-format#dalvik-opcodes
    """

    OPCODE: ClassVar[Opcode]
    STRUCT: ClassVar[struct.Struct]

    @property
    def code_units(self) -> int:
        """Size in 16-bit code units, derived directly from STRUCT."""
        return self.STRUCT.size // 2

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Parse an instruction from a Cursor."""
        raise NotImplementedError

    def to_bytes(self) -> bytes:
        """Encode this instruction to raw DEX bytes."""
        raise NotImplementedError


@dataclass(slots=True, frozen=True)
class Format10x(Instruction):
    """Format 10x: op (e.g. nop, return-void)."""

    STRUCT: ClassVar[struct.Struct] = struct.Struct("<BB")

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        _, _ = cursor.unpack(cls.STRUCT)
        return cls()

    def to_bytes(self) -> bytes:
        return self.STRUCT.pack(self.OPCODE, 0)


@dataclass(slots=True, frozen=True)
class Format12x(Instruction):
    """Format 12x: op vA, vB (4-bit registers)."""

    STRUCT: ClassVar[struct.Struct] = struct.Struct("<BB")

    a: Reg
    b: Reg

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        _, ba = cursor.unpack(cls.STRUCT)
        return cls(a=Reg(ba & 0x0F), b=Reg((ba >> 4) & 0x0F))

    def to_bytes(self) -> bytes:
        return self.STRUCT.pack(self.OPCODE, ((int(self.b) & 0x0F) << 4) | (int(self.a) & 0x0F))


@dataclass(slots=True, frozen=True)
class Format11n(Instruction):
    """Format 11n: op vA, #+B (4-bit reg, 4-bit signed literal)."""

    STRUCT: ClassVar[struct.Struct] = struct.Struct("<BB")

    a: Reg
    b: Literal

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        _, ba = cursor.unpack(cls.STRUCT)
        a = Reg(ba & 0x0F)
        b_raw = (ba >> 4) & 0x0F
        b_val = b_raw - 16 if b_raw >= 8 else b_raw
        return cls(a=a, b=Literal(b_val))

    def to_bytes(self) -> bytes:
        return self.STRUCT.pack(self.OPCODE, ((int(self.b) & 0x0F) << 4) | (int(self.a) & 0x0F))


@dataclass(slots=True, frozen=True)
class Format11x(Instruction):
    """Format 11x: op vAA (8-bit register)."""

    STRUCT: ClassVar[struct.Struct] = struct.Struct("<BB")

    a: Reg

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        _, a = cursor.unpack(cls.STRUCT)
        return cls(a=Reg(a))

    def to_bytes(self) -> bytes:
        return self.STRUCT.pack(self.OPCODE, int(self.a))


@dataclass(slots=True, frozen=True)
class Format10t(Instruction):
    """Format 10t: op +AA (8-bit signed branch offset)."""

    STRUCT: ClassVar[struct.Struct] = struct.Struct("<Bb")

    a: BranchOffset

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        _, a = cursor.unpack(cls.STRUCT)
        return cls(a=BranchOffset(a))

    def to_bytes(self) -> bytes:
        return self.STRUCT.pack(self.OPCODE, int(self.a))


@dataclass(slots=True, frozen=True)
class Format20t(Instruction):
    """Format 20t: op +AAAA (16-bit signed branch offset)."""

    STRUCT: ClassVar[struct.Struct] = struct.Struct("<BBh")

    a: BranchOffset

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        _, _, a = cursor.unpack(cls.STRUCT)
        return cls(a=BranchOffset(a))

    def to_bytes(self) -> bytes:
        return self.STRUCT.pack(self.OPCODE, 0, int(self.a))


@dataclass(slots=True, frozen=True)
class Format22x(Instruction):
    """Format 22x: op vAA, vBBBB (8-bit reg, 16-bit reg)."""

    STRUCT: ClassVar[struct.Struct] = struct.Struct("<BBH")

    a: Reg
    b: Reg

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        _, a, b = cursor.unpack(cls.STRUCT)
        return cls(a=Reg(a), b=Reg(b))

    def to_bytes(self) -> bytes:
        return self.STRUCT.pack(self.OPCODE, int(self.a), int(self.b))


@dataclass(slots=True, frozen=True)
class Format21t(Instruction):
    """Format 21t: op vAA, +BBBB (8-bit reg, 16-bit signed branch offset)."""

    STRUCT: ClassVar[struct.Struct] = struct.Struct("<BBh")

    a: Reg
    b: BranchOffset

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        _, a, b = cursor.unpack(cls.STRUCT)
        return cls(a=Reg(a), b=BranchOffset(b))

    def to_bytes(self) -> bytes:
        return self.STRUCT.pack(self.OPCODE, int(self.a), int(self.b))


@dataclass(slots=True, frozen=True)
class Format21s(Instruction):
    """Format 21s: op vAA, #+BBBB (8-bit reg, 16-bit signed literal)."""

    STRUCT: ClassVar[struct.Struct] = struct.Struct("<BBh")

    a: Reg
    b: Literal

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        _, a, b = cursor.unpack(cls.STRUCT)
        return cls(a=Reg(a), b=Literal(b))

    def to_bytes(self) -> bytes:
        return self.STRUCT.pack(self.OPCODE, int(self.a), int(self.b))


@dataclass(slots=True, frozen=True)
class Format21h(Instruction):
    """Format 21h: op vAA, #+BBBB0000... (8-bit reg, shifted high-bits literal)."""

    SHIFT: ClassVar[int]
    STRUCT: ClassVar[struct.Struct] = struct.Struct("<BBH")

    a: Reg
    b: Hat

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        _, a, val = cursor.unpack(cls.STRUCT)
        return cls(a=Reg(a), b=Hat(val << (cls.SHIFT * 8)))

    def to_bytes(self) -> bytes:
        val = (int(self.b) >> (self.SHIFT * 8)) & 0xFFFF
        return self.STRUCT.pack(self.OPCODE, int(self.a), val)


@dataclass(slots=True, frozen=True)
class Format21c[RefT: RefItem](Instruction):
    """Format 21c: op vAA, ref@BBBB (8-bit reg, 16-bit reference index)."""

    STRUCT: ClassVar[struct.Struct] = struct.Struct("<BBH")

    a: Reg
    b: Idx[RefT]

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        _, a, b = cursor.unpack(cls.STRUCT)
        return cls(a=Reg(a), b=Idx[RefT](b))

    def to_bytes(self) -> bytes:
        return self.STRUCT.pack(self.OPCODE, int(self.a), int(self.b))


@dataclass(slots=True, frozen=True)
class Format23x(Instruction):
    """Format 23x: op vAA, vBB, vCC (8-bit registers)."""

    STRUCT: ClassVar[struct.Struct] = struct.Struct("<BBBB")

    a: Reg
    b: Reg
    c: Reg

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        _, a, b, c = cursor.unpack(cls.STRUCT)
        return cls(a=Reg(a), b=Reg(b), c=Reg(c))

    def to_bytes(self) -> bytes:
        return self.STRUCT.pack(self.OPCODE, int(self.a), int(self.b), int(self.c))


@dataclass(slots=True, frozen=True)
class Format22b(Instruction):
    """Format 22b: op vAA, vBB, #+CC (8-bit regs, 8-bit signed literal)."""

    STRUCT: ClassVar[struct.Struct] = struct.Struct("<BBBb")

    a: Reg
    b: Reg
    c: Literal

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        _, a, b, c = cursor.unpack(cls.STRUCT)
        return cls(a=Reg(a), b=Reg(b), c=Literal(c))

    def to_bytes(self) -> bytes:
        return self.STRUCT.pack(self.OPCODE, int(self.a), int(self.b), int(self.c))


@dataclass(slots=True, frozen=True)
class Format22t(Instruction):
    """Format 22t: op vA, vB, +CCCC (4-bit regs, 16-bit signed branch offset)."""

    STRUCT: ClassVar[struct.Struct] = struct.Struct("<BBh")

    a: Reg
    b: Reg
    c: BranchOffset

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        _, ba, c = cursor.unpack(cls.STRUCT)
        return cls(a=Reg(ba & 0x0F), b=Reg((ba >> 4) & 0x0F), c=BranchOffset(c))

    def to_bytes(self) -> bytes:
        return self.STRUCT.pack(
            self.OPCODE, ((int(self.b) & 0x0F) << 4) | (int(self.a) & 0x0F), int(self.c)
        )


@dataclass(slots=True, frozen=True)
class Format22s(Instruction):
    """Format 22s: op vA, vB, #+CCCC (4-bit regs, 16-bit signed literal)."""

    STRUCT: ClassVar[struct.Struct] = struct.Struct("<BBh")

    a: Reg
    b: Reg
    c: Literal

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        _, ba, c = cursor.unpack(cls.STRUCT)
        return cls(a=Reg(ba & 0x0F), b=Reg((ba >> 4) & 0x0F), c=Literal(c))

    def to_bytes(self) -> bytes:
        return self.STRUCT.pack(
            self.OPCODE, ((int(self.b) & 0x0F) << 4) | (int(self.a) & 0x0F), int(self.c)
        )


@dataclass(slots=True, frozen=True)
class Format22c[RefT: RefItem](Instruction):
    """Format 22c: op vA, vB, ref@CCCC (4-bit regs, 16-bit reference index)."""

    STRUCT: ClassVar[struct.Struct] = struct.Struct("<BBH")

    a: Reg
    b: Reg
    c: Idx[RefT]

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        _, ba, c = cursor.unpack(cls.STRUCT)
        return cls(a=Reg(ba & 0x0F), b=Reg((ba >> 4) & 0x0F), c=Idx[RefT](c))

    def to_bytes(self) -> bytes:
        return self.STRUCT.pack(
            self.OPCODE, ((int(self.b) & 0x0F) << 4) | (int(self.a) & 0x0F), int(self.c)
        )


@dataclass(slots=True, frozen=True)
class Format30t(Instruction):
    """Format 30t: op +AAAAAAAA (32-bit signed branch offset)."""

    STRUCT: ClassVar[struct.Struct] = struct.Struct("<BBi")

    a: BranchOffset

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        _, _, a = cursor.unpack(cls.STRUCT)
        return cls(a=BranchOffset(a))

    def to_bytes(self) -> bytes:
        return self.STRUCT.pack(self.OPCODE, 0, int(self.a))


@dataclass(slots=True, frozen=True)
class Format32x(Instruction):
    """Format 32x: op vAAAA, vBBBB (16-bit registers)."""

    STRUCT: ClassVar[struct.Struct] = struct.Struct("<BBHH")

    a: Reg
    b: Reg

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        _, _, a, b = cursor.unpack(cls.STRUCT)
        return cls(a=Reg(a), b=Reg(b))

    def to_bytes(self) -> bytes:
        return self.STRUCT.pack(self.OPCODE, 0, int(self.a), int(self.b))


@dataclass(slots=True, frozen=True)
class Format31i(Instruction):
    """Format 31i: op vAA, #+BBBBBBBB (8-bit reg, 32-bit signed literal)."""

    STRUCT: ClassVar[struct.Struct] = struct.Struct("<BBi")

    a: Reg
    b: Literal

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        _, a, b = cursor.unpack(cls.STRUCT)
        return cls(a=Reg(a), b=Literal(b))

    def to_bytes(self) -> bytes:
        return self.STRUCT.pack(self.OPCODE, int(self.a), int(self.b))


@dataclass(slots=True, frozen=True)
class Format31t(Instruction):
    """Format 31t: op vAA, +BBBBBBBB (8-bit reg, 32-bit signed branch offset)."""

    STRUCT: ClassVar[struct.Struct] = struct.Struct("<BBi")

    a: Reg
    b: BranchOffset

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        _, a, b = cursor.unpack(cls.STRUCT)
        return cls(a=Reg(a), b=BranchOffset(b))

    def to_bytes(self) -> bytes:
        return self.STRUCT.pack(self.OPCODE, int(self.a), int(self.b))


@dataclass(slots=True, frozen=True)
class Format31c[RefT: RefItem](Instruction):
    """Format 31c: op vAA, string@BBBBBBBB (8-bit reg, 32-bit reference index)."""

    STRUCT: ClassVar[struct.Struct] = struct.Struct("<BBI")

    a: Reg
    b: Idx[RefT]

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        _, a, b = cursor.unpack(cls.STRUCT)
        return cls(a=Reg(a), b=Idx[RefT](b))

    def to_bytes(self) -> bytes:
        return self.STRUCT.pack(self.OPCODE, int(self.a), int(self.b))


@dataclass(slots=True, frozen=True)
class Format35c[RefT: RefItem](Instruction):
    """Format 35c: op {vC, vD, vE, vF, vG}, ref@BBBB (0..5 reg operands, 16-bit ref index)."""

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
        _, ag, bbbb, dc, fe = cursor.unpack(cls.STRUCT)
        a = ArgumentCount((ag >> 4) & 0x0F)
        g = Reg(ag & 0x0F)
        b = Idx[RefT](bbbb)
        c = Reg(dc & 0x0F)
        d = Reg((dc >> 4) & 0x0F)
        e = Reg(fe & 0x0F)
        f = Reg((fe >> 4) & 0x0F)
        return cls(a=a, b=b, c=c, d=d, e=e, f=f, g=g)

    def to_bytes(self) -> bytes:
        ag = ((int(self.a) & 0x0F) << 4) | (int(self.g) & 0x0F)
        dc = ((int(self.d) & 0x0F) << 4) | (int(self.c) & 0x0F)
        fe = ((int(self.f) & 0x0F) << 4) | (int(self.e) & 0x0F)
        return self.STRUCT.pack(self.OPCODE, ag, int(self.b), dc, fe)


@dataclass(slots=True, frozen=True)
class Format3rc[RefT: RefItem](Instruction):
    """Format 3rc: op {vCCCC .. vNNNN}, ref@BBBB.

    Operands: reg range count A, 16-bit ref index B, start reg C.
    """

    STRUCT: ClassVar[struct.Struct] = struct.Struct("<BBHH")

    a: ArgumentCount
    b: Idx[RefT]
    c: Reg

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        _, a, b, c = cursor.unpack(cls.STRUCT)
        return cls(a=ArgumentCount(a), b=Idx[RefT](b), c=Reg(c))

    def to_bytes(self) -> bytes:
        return self.STRUCT.pack(self.OPCODE, int(self.a), int(self.b), int(self.c))


@dataclass(slots=True, frozen=True)
class Format51l(Instruction):
    """Format 51l: op vAA, #+BBBBBBBBBBBBBBBB (8-bit reg, 64-bit signed literal)."""

    STRUCT: ClassVar[struct.Struct] = struct.Struct("<BBq")

    a: Reg
    b: Literal

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        _, a, b = cursor.unpack(cls.STRUCT)
        return cls(a=Reg(a), b=Literal(b))

    def to_bytes(self) -> bytes:
        return self.STRUCT.pack(self.OPCODE, int(self.a), int(self.b))
