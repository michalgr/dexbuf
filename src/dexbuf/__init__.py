"""dexbuf: Fast, 0-copy, and complete Dalvik Executable (DEX) reader.

Built on Python's Buffer protocol (collections.abc.Buffer) and typed dataclasses.
Provides low-level spec representations and a tiered, REPL-friendly API.
"""

from dexbuf.instructions import IOP, Instruction, Opcode, Payload
from dexbuf.items import (
    ClassDataItem,
    ClassDefItem,
    EncodedField,
    EncodedMethod,
    FieldIdItem,
    MethodIdItem,
    ProtoIdItem,
    StringDataItem,
    StringIdItem,
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
    "ClassDataItem",
    "ClassDefItem",
    "Count",
    "EncodedField",
    "EncodedMethod",
    "FieldIdItem",
    "Hat",
    "Idx",
    "Instruction",
    "Literal",
    "MethodIdItem",
    "Offset",
    "Opcode",
    "Payload",
    "ProtoIdItem",
    "Reg",
    "StringDataItem",
    "StringIdItem",
    "TypeIdItem",
    "TypeList",
    "__version__",
]
