"""StringDataItem spec record according to Android DEX format specification.

Reference: https://source.android.com/docs/core/runtime/dex-format#string-data-item
"""

from collections.abc import Buffer
from dataclasses import dataclass
from typing import Self

from dexbuf.leb128 import decode_uleb128, encode_uleb128
from dexbuf.mutf8 import decode_mutf8, encode_mutf8, utf16_code_units
from dexbuf.types import Offset

__all__ = ["StringDataItem"]


@dataclass(slots=True, frozen=True)
class StringDataItem:
    """StringDataItem structure representing string content in the DEX data section.

    utf16_size: Size of the string in UTF-16 code units (decoded length).
    data: Decoded string content.
    """

    utf16_size: int
    data: str

    @classmethod
    def from_buffer(cls, buffer: Buffer, offset: Offset[Self] | int = 0) -> Self:
        """Decode a StringDataItem from buffer at the given byte offset."""
        utf16_size, uleb_len = decode_uleb128(buffer, offset)
        data_str, _ = decode_mutf8(buffer, offset + uleb_len, expected_utf16_size=utf16_size)
        return cls(utf16_size=utf16_size, data=data_str)

    @classmethod
    def from_str(cls, s: str) -> Self:
        """Create a StringDataItem record from a Python string."""
        return cls(utf16_size=utf16_code_units(s), data=s)

    def to_bytes(self) -> bytes:
        """Encode this StringDataItem to bytes (uleb128 utf16_size followed by MUTF-8 data)."""
        return encode_uleb128(self.utf16_size) + encode_mutf8(self.data, null_terminated=True)
