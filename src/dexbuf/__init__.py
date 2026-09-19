"""dexbuf: Fast, 0-copy, and complete Dalvik Executable (DEX) reader.

Built on Python's Buffer protocol (collections.abc.Buffer) and typed dataclasses.
Provides low-level spec representations and a tiered, REPL-friendly API.
"""

from dexbuf.debug import (
    DebugInstruction,
    DebugOpcode,
    DebugPosition,
)
from dexbuf.instructions import IOP, Instruction, Opcode, Payload
from dexbuf.items import (
    CallSiteIdItem,
    ClassDataItem,
    ClassDefItem,
    CodeItem,
    DebugInfoItem,
    EncodedCatchHandler,
    EncodedCatchHandlerList,
    EncodedField,
    EncodedMethod,
    EncodedTypeAddrPair,
    FieldIdItem,
    MethodHandleItem,
    MethodIdItem,
    ProtoIdItem,
    StringDataItem,
    StringIdItem,
    TryItem,
    TypeIdItem,
    TypeList,
)
from dexbuf.types import (
    NO_INDEX,
    NO_OFFSET,
    ArgumentCount,
    BranchOffset,
    Count,
    Hat,
    Idx,
    Literal,
    Offset,
    Reg,
)

__version__ = "0.1.0.dev0"

__all__ = [
    "IOP",
    "NO_INDEX",
    "NO_OFFSET",
    "ArgumentCount",
    "BranchOffset",
    "CallSiteIdItem",
    "ClassDataItem",
    "ClassDefItem",
    "CodeItem",
    "Count",
    "DebugInfoItem",
    "DebugInstruction",
    "DebugOpcode",
    "DebugPosition",
    "EncodedCatchHandler",
    "EncodedCatchHandlerList",
    "EncodedField",
    "EncodedMethod",
    "EncodedTypeAddrPair",
    "FieldIdItem",
    "Hat",
    "Idx",
    "Instruction",
    "Literal",
    "MethodHandleItem",
    "MethodIdItem",
    "Offset",
    "Opcode",
    "Payload",
    "ProtoIdItem",
    "Reg",
    "StringDataItem",
    "StringIdItem",
    "TryItem",
    "TypeIdItem",
    "TypeList",
    "__version__",
]
