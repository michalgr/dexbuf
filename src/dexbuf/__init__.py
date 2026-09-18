"""dexbuf: Fast, 0-copy, and complete Dalvik Executable (DEX) reader.

Built on Python's Buffer protocol (collections.abc.Buffer) and typed dataclasses.
Provides low-level spec representations and a tiered, REPL-friendly API.
"""

from dexbuf.cursor import Cursor
from dexbuf.leb128 import (
    decode_sleb128,
    decode_uleb128,
    decode_uleb128p1,
    encode_sleb128,
    encode_uleb128,
    encode_uleb128p1,
)
from dexbuf.mutf8 import decode_mutf8, encode_mutf8, utf16_code_units
from dexbuf.string_data import StringDataItem
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
    "decode_mutf8",
    "decode_sleb128",
    "decode_uleb128",
    "decode_uleb128p1",
    "encode_mutf8",
    "encode_sleb128",
    "encode_uleb128",
    "encode_uleb128p1",
    "utf16_code_units",
]
