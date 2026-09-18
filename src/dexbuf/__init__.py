"""dexbuf: Fast, 0-copy, and complete Dalvik Executable (DEX) reader.

Built on Python's Buffer protocol (collections.abc.Buffer) and typed dataclasses.
Provides low-level spec representations and a tiered, REPL-friendly API.
"""

from dexbuf.items import StringDataItem
from dexbuf.types import NO_INDEX, NO_OFFSET, Count, Id, Offset

__version__ = "0.1.0.dev0"

__all__ = [
    "NO_INDEX",
    "NO_OFFSET",
    "Count",
    "Id",
    "Offset",
    "StringDataItem",
    "__version__",
]
