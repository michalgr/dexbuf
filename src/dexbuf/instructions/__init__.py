"""Dalvik bytecode instruction and payload representations.

See https://source.android.com/docs/core/runtime/dex-format#dalvik-opcodes
"""

from dexbuf.cursor import Cursor
from dexbuf.instructions import definitions as _defs
from dexbuf.instructions import formats as _formats
from dexbuf.instructions import opcodes as _opcodes
from dexbuf.instructions import payloads as _payloads
from dexbuf.instructions.definitions import *  # noqa: F403
from dexbuf.instructions.definitions import parse_instruction
from dexbuf.instructions.formats import *  # noqa: F403
from dexbuf.instructions.formats import Instruction
from dexbuf.instructions.opcodes import Opcode
from dexbuf.instructions.payloads import (
    FillArrayDataPayload,
    PackedSwitchPayload,
    Payload,
    SparseSwitchPayload,
)

type IOP = Instruction | Payload


def parse_iop(cursor: Cursor) -> IOP:
    """Parse a Dalvik instruction or payload (IOP) from cursor."""
    word0 = cursor.subcursor().read_u16()
    if word0 == Opcode.PACKED_SWITCH_PAYLOAD:
        return PackedSwitchPayload.from_cursor(cursor)
    if word0 == Opcode.SPARSE_SWITCH_PAYLOAD:
        return SparseSwitchPayload.from_cursor(cursor)
    if word0 == Opcode.FILL_ARRAY_DATA_PAYLOAD:
        return FillArrayDataPayload.from_cursor(cursor)
    return parse_instruction(cursor)


__all__ = sorted(
    {
        "IOP",
        "Opcode",
        "Payload",
        "parse_iop",
        *_formats.__all__,
        *_opcodes.__all__,
        *_payloads.__all__,
        *_defs.__all__,
    }
)
