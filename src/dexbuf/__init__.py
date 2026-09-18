"""dexbuf: Fast, 0-copy, and complete Dalvik Executable (DEX) reader.

Built on Python's Buffer protocol (collections.abc.Buffer) and typed dataclasses.
Provides low-level spec representations and a tiered, REPL-friendly API.
"""

from dexbuf.cursor import Cursor
from dexbuf.items import StringDataItem
from dexbuf.leb128 import encode_sleb128, encode_uleb128, encode_uleb128p1
from dexbuf.mutf8 import encode_mutf8, utf16_code_units
from dexbuf.types import NO_INDEX, NO_OFFSET, Count, Id, Offset

__version__ = "0.1.0.dev0"

__all__ = [
    "NO_INDEX",
    "NO_OFFSET",
    "Count",
    "Cursor",
    "Id",
    "Offset",
    "StringDataItem",
    "__version__",
    "encode_mutf8",
    "encode_sleb128",
    "encode_uleb128",
    "encode_uleb128p1",
    "utf16_code_units",
]
