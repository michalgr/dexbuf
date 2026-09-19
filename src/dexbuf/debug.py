"""Dalvik debug bytecode instruction dataclasses and state machine helpers.

See https://source.android.com/docs/core/runtime/dex-format#debug-info-item
"""

from dataclasses import dataclass
from enum import IntEnum
from typing import TYPE_CHECKING, Any, Self

from dexbuf.cursor import Cursor
from dexbuf.leb128 import encode_sleb128, encode_uleb128, encode_uleb128p1
from dexbuf.types import NO_INDEX, Idx

if TYPE_CHECKING:
    from dexbuf.items import StringIdItem, TypeIdItem

__all__ = [
    "DbgAdvanceLine",
    "DbgAdvancePc",
    "DbgEndLocal",
    "DbgEndSequence",
    "DbgRestartLocal",
    "DbgSetEpilogueBegin",
    "DbgSetFile",
    "DbgSetPrologueEnd",
    "DbgSpecial",
    "DbgStartLocal",
    "DbgStartLocalExtended",
    "DebugInstruction",
    "DebugOpcode",
    "DebugPosition",
    "parse_debug_instruction",
    "skip_debug_instruction",
]


class DebugOpcode(IntEnum):
    """Dalvik debug bytecode opcodes."""

    DBG_END_SEQUENCE = 0x00
    DBG_ADVANCE_PC = 0x01
    DBG_ADVANCE_LINE = 0x02
    DBG_START_LOCAL = 0x03
    DBG_START_LOCAL_EXTENDED = 0x04
    DBG_END_LOCAL = 0x05
    DBG_RESTART_LOCAL = 0x06
    DBG_SET_PROLOGUE_END = 0x07
    DBG_SET_EPILOGUE_BEGIN = 0x08
    DBG_SET_FILE = 0x09


@dataclass(slots=True, frozen=True)
class DbgEndSequence:
    """Terminates a debug info sequence.

    Opcode: 0x00
    """

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Construct a DbgEndSequence instance."""
        return cls()

    @staticmethod
    def skip(cursor: Cursor) -> None:
        """Skip DbgEndSequence operands in cursor."""

    def to_bytes(self) -> bytes:
        """Encode DbgEndSequence to DEX debug bytecode."""
        return b"\x00"


@dataclass(slots=True, frozen=True)
class DbgAdvancePc:
    """Advances the address register by addr_diff.

    Opcode: 0x01
    """

    addr_diff: int

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Parse DbgAdvancePc from cursor."""
        return cls(addr_diff=cursor.read_uleb128())

    @staticmethod
    def skip(cursor: Cursor) -> None:
        """Skip DbgAdvancePc operands in cursor."""
        cursor.read_uleb128()

    def to_bytes(self) -> bytes:
        """Encode DbgAdvancePc to DEX debug bytecode."""
        return b"\x01" + encode_uleb128(self.addr_diff)


@dataclass(slots=True, frozen=True)
class DbgAdvanceLine:
    """Advances the line register by line_diff.

    Opcode: 0x02
    """

    line_diff: int

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Parse DbgAdvanceLine from cursor."""
        return cls(line_diff=cursor.read_sleb128())

    @staticmethod
    def skip(cursor: Cursor) -> None:
        """Skip DbgAdvanceLine operands in cursor."""
        cursor.read_sleb128()

    def to_bytes(self) -> bytes:
        """Encode DbgAdvanceLine to DEX debug bytecode."""
        return b"\x02" + encode_sleb128(self.line_diff)


@dataclass(slots=True, frozen=True)
class DbgStartLocal:
    """Starts local variable tracking.

    Opcode: 0x03
    """

    register_num: int
    name_idx: Idx[StringIdItem]
    type_idx: Idx[TypeIdItem]

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Parse DbgStartLocal from cursor."""
        register_num = cursor.read_uleb128()
        raw_name = cursor.read_uleb128p1()
        name_idx = NO_INDEX if raw_name == -1 else Idx[Any](raw_name)
        raw_type = cursor.read_uleb128p1()
        type_idx = NO_INDEX if raw_type == -1 else Idx[Any](raw_type)
        return cls(register_num=register_num, name_idx=name_idx, type_idx=type_idx)

    @staticmethod
    def skip(cursor: Cursor) -> None:
        """Skip DbgStartLocal operands in cursor."""
        cursor.read_uleb128()
        cursor.read_uleb128()
        cursor.read_uleb128()

    def to_bytes(self) -> bytes:
        """Encode DbgStartLocal to DEX debug bytecode."""
        return (
            b"\x03"
            + encode_uleb128(self.register_num)
            + encode_uleb128p1(self.name_idx)
            + encode_uleb128p1(self.type_idx)
        )


@dataclass(slots=True, frozen=True)
class DbgStartLocalExtended:
    """Starts local variable tracking with type signature.

    Opcode: 0x04
    """

    register_num: int
    name_idx: Idx[StringIdItem]
    type_idx: Idx[TypeIdItem]
    sig_idx: Idx[StringIdItem]

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Parse DbgStartLocalExtended from cursor."""
        register_num = cursor.read_uleb128()
        raw_name = cursor.read_uleb128p1()
        name_idx = NO_INDEX if raw_name == -1 else Idx[Any](raw_name)
        raw_type = cursor.read_uleb128p1()
        type_idx = NO_INDEX if raw_type == -1 else Idx[Any](raw_type)
        raw_sig = cursor.read_uleb128p1()
        sig_idx = NO_INDEX if raw_sig == -1 else Idx[Any](raw_sig)
        return cls(
            register_num=register_num,
            name_idx=name_idx,
            type_idx=type_idx,
            sig_idx=sig_idx,
        )

    @staticmethod
    def skip(cursor: Cursor) -> None:
        """Skip DbgStartLocalExtended operands in cursor."""
        cursor.read_uleb128()
        cursor.read_uleb128()
        cursor.read_uleb128()
        cursor.read_uleb128()

    def to_bytes(self) -> bytes:
        """Encode DbgStartLocalExtended to DEX debug bytecode."""
        return (
            b"\x04"
            + encode_uleb128(self.register_num)
            + encode_uleb128p1(self.name_idx)
            + encode_uleb128p1(self.type_idx)
            + encode_uleb128p1(self.sig_idx)
        )


@dataclass(slots=True, frozen=True)
class DbgEndLocal:
    """Ends local variable tracking.

    Opcode: 0x05
    """

    register_num: int

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Parse DbgEndLocal from cursor."""
        return cls(register_num=cursor.read_uleb128())

    @staticmethod
    def skip(cursor: Cursor) -> None:
        """Skip DbgEndLocal operands in cursor."""
        cursor.read_uleb128()

    def to_bytes(self) -> bytes:
        """Encode DbgEndLocal to DEX debug bytecode."""
        return b"\x05" + encode_uleb128(self.register_num)


@dataclass(slots=True, frozen=True)
class DbgRestartLocal:
    """Restores tracking for a local variable previously in scope.

    Opcode: 0x06
    """

    register_num: int

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Parse DbgRestartLocal from cursor."""
        return cls(register_num=cursor.read_uleb128())

    @staticmethod
    def skip(cursor: Cursor) -> None:
        """Skip DbgRestartLocal operands in cursor."""
        cursor.read_uleb128()

    def to_bytes(self) -> bytes:
        """Encode DbgRestartLocal to DEX debug bytecode."""
        return b"\x06" + encode_uleb128(self.register_num)


@dataclass(slots=True, frozen=True)
class DbgSetPrologueEnd:
    """Sets prologue_end flag.

    Opcode: 0x07
    """

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Construct a DbgSetPrologueEnd instance."""
        return cls()

    @staticmethod
    def skip(cursor: Cursor) -> None:
        """Skip DbgSetPrologueEnd operands in cursor."""

    def to_bytes(self) -> bytes:
        """Encode DbgSetPrologueEnd to DEX debug bytecode."""
        return b"\x07"


@dataclass(slots=True, frozen=True)
class DbgSetEpilogueBegin:
    """Sets epilogue_begin flag.

    Opcode: 0x08
    """

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Construct a DbgSetEpilogueBegin instance."""
        return cls()

    @staticmethod
    def skip(cursor: Cursor) -> None:
        """Skip DbgSetEpilogueBegin operands in cursor."""

    def to_bytes(self) -> bytes:
        """Encode DbgSetEpilogueBegin to DEX debug bytecode."""
        return b"\x08"


@dataclass(slots=True, frozen=True)
class DbgSetFile:
    """Sets current source file name.

    Opcode: 0x09
    """

    name_idx: Idx[StringIdItem]

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Parse DbgSetFile from cursor."""
        raw_name = cursor.read_uleb128p1()
        name_idx = NO_INDEX if raw_name == -1 else Idx[Any](raw_name)
        return cls(name_idx=name_idx)

    @staticmethod
    def skip(cursor: Cursor) -> None:
        """Skip DbgSetFile operands in cursor."""
        cursor.read_uleb128()

    def to_bytes(self) -> bytes:
        """Encode DbgSetFile to DEX debug bytecode."""
        return b"\x09" + encode_uleb128p1(self.name_idx)


@dataclass(slots=True, frozen=True)
class DbgSpecial:
    """Advances line and address registers simultaneously.

    Opcodes: 0x0a..0xff
    """

    opcode: int

    @property
    def line_diff(self) -> int:
        """Calculate line difference encoded by opcode."""
        adjusted = self.opcode - 0x0A
        return -4 + (adjusted % 15)

    @property
    def addr_diff(self) -> int:
        """Calculate address difference encoded by opcode."""
        adjusted = self.opcode - 0x0A
        return adjusted // 15

    @classmethod
    def from_cursor(cls, cursor: Cursor, opcode: int = 0x0A) -> Self:
        """Construct DbgSpecial from cursor and opcode byte."""
        return cls(opcode=opcode)

    @staticmethod
    def skip(cursor: Cursor, opcode: int | None = None) -> None:
        """Skip DbgSpecial operands in cursor."""

    def to_bytes(self) -> bytes:
        """Encode DbgSpecial to DEX debug bytecode."""
        return bytes([self.opcode])


type DebugInstruction = (
    DbgEndSequence
    | DbgAdvancePc
    | DbgAdvanceLine
    | DbgStartLocal
    | DbgStartLocalExtended
    | DbgEndLocal
    | DbgRestartLocal
    | DbgSetPrologueEnd
    | DbgSetEpilogueBegin
    | DbgSetFile
    | DbgSpecial
)


@dataclass(slots=True, frozen=True)
class DebugPosition:
    """Positions table entry evaluating debug bytecode state machine."""

    address: int
    line: int
    source_file_idx: Idx[StringIdItem]
    prologue_end: bool
    epilogue_begin: bool


def skip_debug_instruction(cursor: Cursor) -> int:
    """Read next opcode u8 and advance cursor past its operands without allocation.

    Returns the opcode byte.
    """
    opcode = cursor.read_u8()
    if opcode == DebugOpcode.DBG_END_SEQUENCE:
        DbgEndSequence.skip(cursor)
    elif opcode == DebugOpcode.DBG_ADVANCE_PC:
        DbgAdvancePc.skip(cursor)
    elif opcode == DebugOpcode.DBG_ADVANCE_LINE:
        DbgAdvanceLine.skip(cursor)
    elif opcode == DebugOpcode.DBG_START_LOCAL:
        DbgStartLocal.skip(cursor)
    elif opcode == DebugOpcode.DBG_START_LOCAL_EXTENDED:
        DbgStartLocalExtended.skip(cursor)
    elif opcode == DebugOpcode.DBG_END_LOCAL:
        DbgEndLocal.skip(cursor)
    elif opcode == DebugOpcode.DBG_RESTART_LOCAL:
        DbgRestartLocal.skip(cursor)
    elif opcode == DebugOpcode.DBG_SET_PROLOGUE_END:
        DbgSetPrologueEnd.skip(cursor)
    elif opcode == DebugOpcode.DBG_SET_EPILOGUE_BEGIN:
        DbgSetEpilogueBegin.skip(cursor)
    elif opcode == DebugOpcode.DBG_SET_FILE:
        DbgSetFile.skip(cursor)
    else:
        DbgSpecial.skip(cursor, opcode)
    return opcode


def parse_debug_instruction(cursor: Cursor) -> DebugInstruction:
    """Read next opcode u8 and parse full DebugInstruction dataclass from cursor."""
    opcode = cursor.read_u8()
    if opcode == DebugOpcode.DBG_END_SEQUENCE:
        return DbgEndSequence.from_cursor(cursor)
    elif opcode == DebugOpcode.DBG_ADVANCE_PC:
        return DbgAdvancePc.from_cursor(cursor)
    elif opcode == DebugOpcode.DBG_ADVANCE_LINE:
        return DbgAdvanceLine.from_cursor(cursor)
    elif opcode == DebugOpcode.DBG_START_LOCAL:
        return DbgStartLocal.from_cursor(cursor)
    elif opcode == DebugOpcode.DBG_START_LOCAL_EXTENDED:
        return DbgStartLocalExtended.from_cursor(cursor)
    elif opcode == DebugOpcode.DBG_END_LOCAL:
        return DbgEndLocal.from_cursor(cursor)
    elif opcode == DebugOpcode.DBG_RESTART_LOCAL:
        return DbgRestartLocal.from_cursor(cursor)
    elif opcode == DebugOpcode.DBG_SET_PROLOGUE_END:
        return DbgSetPrologueEnd.from_cursor(cursor)
    elif opcode == DebugOpcode.DBG_SET_EPILOGUE_BEGIN:
        return DbgSetEpilogueBegin.from_cursor(cursor)
    elif opcode == DebugOpcode.DBG_SET_FILE:
        return DbgSetFile.from_cursor(cursor)
    else:
        return DbgSpecial.from_cursor(cursor, opcode)
