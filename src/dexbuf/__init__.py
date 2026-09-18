"""dexbuf: Fast, 0-copy, and complete Dalvik Executable (DEX) reader.

Built on Python's Buffer protocol (collections.abc.Buffer) and typed dataclasses.
Provides low-level spec representations and a tiered, REPL-friendly API.
"""

from dexbuf.items import (
    FieldIdItem,
    MethodIdItem,
    ProtoIdItem,
    StringDataItem,
    StringIdItem,
    TypeIdItem,
    TypeList,
)
from dexbuf.types import NO_INDEX, NO_OFFSET, Count, Idx, Offset

__version__ = "0.1.0.dev0"

__all__ = [
    "NO_INDEX",
    "NO_OFFSET",
    "Count",
    "FieldIdItem",
    "Idx",
    "MethodIdItem",
    "Offset",
    "ProtoIdItem",
    "StringDataItem",
    "StringIdItem",
    "TypeIdItem",
    "TypeList",
    "__version__",
]
