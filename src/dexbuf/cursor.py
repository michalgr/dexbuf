"""In-place zero-copy binary buffer reader (Cursor).

Operates directly on Python Buffer objects (memoryview, bytes, bytearray, mmap).
"""

from collections.abc import Buffer
from typing import Self

from dexbuf.leb128 import decode_sleb128, decode_uleb128, decode_uleb128p1
from dexbuf.mutf8 import decode_mutf8
from dexbuf.string_data import StringDataItem

__all__ = ["Cursor"]


class Cursor:
    """In-place, 0-copy binary cursor operating on collections.abc.Buffer."""

    __slots__ = ("_buffer", "_offset")

    def __init__(self, buffer: Buffer, offset: int = 0) -> None:
        self._buffer: memoryview = memoryview(buffer).cast("B")
        self._offset: int = 0
        self.offset = offset

    @property
    def buffer(self) -> memoryview:
        """Return the underlying byte memoryview of this cursor."""
        return self._buffer

    @property
    def offset(self) -> int:
        """Get the current byte offset."""
        return self._offset

    @offset.setter
    def offset(self, value: int) -> None:
        """Set the byte offset with bounds checking."""
        if not (0 <= value <= len(self._buffer)):
            raise IndexError(f"Offset {value} out of bounds for buffer of size {len(self._buffer)}")
        self._offset = value

    def seek(self, offset: int) -> Self:
        """Seek to a specific byte offset."""
        self.offset = offset
        return self

    def skip(self, n: int) -> Self:
        """Advance cursor offset by n bytes."""
        self.offset = self._offset + n
        return self

    def tell(self) -> int:
        """Return current offset in bytes."""
        return self._offset

    @property
    def remaining(self) -> int:
        """Number of remaining bytes to read."""
        return len(self._buffer) - self._offset

    @property
    def is_eof(self) -> bool:
        """Return True if cursor is at or past end of buffer."""
        return self._offset >= len(self._buffer)

    def _require_bytes(self, n: int) -> None:
        if self._offset + n > len(self._buffer):
            raise EOFError(
                f"Cannot read {n} bytes at offset {self._offset}; {self.remaining} bytes remaining"
            )

    # --- Numeric Reads ---

    def read_u8(self) -> int:
        """Read an unsigned 8-bit integer."""
        self._require_bytes(1)
        val = self._buffer[self._offset]
        self._offset += 1
        return val

    def read_s8(self) -> int:
        """Read a signed 8-bit integer."""
        self._require_bytes(1)
        val = int.from_bytes(self._buffer[self._offset : self._offset + 1], "little", signed=True)
        self._offset += 1
        return val

    def peek_u8(self) -> int:
        """Peek an unsigned 8-bit integer without advancing offset."""
        self._require_bytes(1)
        return self._buffer[self._offset]

    def read_u16(self) -> int:
        """Read an unsigned 16-bit little-endian integer."""
        self._require_bytes(2)
        val = int.from_bytes(self._buffer[self._offset : self._offset + 2], "little", signed=False)
        self._offset += 2
        return val

    def read_s16(self) -> int:
        """Read a signed 16-bit little-endian integer."""
        self._require_bytes(2)
        val = int.from_bytes(self._buffer[self._offset : self._offset + 2], "little", signed=True)
        self._offset += 2
        return val

    def read_u32(self) -> int:
        """Read an unsigned 32-bit little-endian integer."""
        self._require_bytes(4)
        val = int.from_bytes(self._buffer[self._offset : self._offset + 4], "little", signed=False)
        self._offset += 4
        return val

    def read_s32(self) -> int:
        """Read a signed 32-bit little-endian integer."""
        self._require_bytes(4)
        val = int.from_bytes(self._buffer[self._offset : self._offset + 4], "little", signed=True)
        self._offset += 4
        return val

    def read_u64(self) -> int:
        """Read an unsigned 64-bit little-endian integer."""
        self._require_bytes(8)
        val = int.from_bytes(self._buffer[self._offset : self._offset + 8], "little", signed=False)
        self._offset += 8
        return val

    def read_s64(self) -> int:
        """Read a signed 64-bit little-endian integer."""
        self._require_bytes(8)
        val = int.from_bytes(self._buffer[self._offset : self._offset + 8], "little", signed=True)
        self._offset += 8
        return val

    # --- Zero-Copy Slicing ---

    def read_bytes(self, n: int) -> memoryview:
        """Read n bytes as a zero-copy memoryview slice and advance offset."""
        if n < 0:
            raise ValueError(f"Byte count cannot be negative: {n}")
        self._require_bytes(n)
        slice_mv = self._buffer[self._offset : self._offset + n]
        self._offset += n
        return slice_mv

    def peek_bytes(self, n: int) -> memoryview:
        """Peek n bytes as a zero-copy memoryview slice without advancing offset."""
        if n < 0:
            raise ValueError(f"Byte count cannot be negative: {n}")
        self._require_bytes(n)
        return self._buffer[self._offset : self._offset + n]

    # --- Variable-Length Reads ---

    def read_uleb128(self) -> int:
        """Read an unsigned LEB128 integer and advance offset."""
        val, count = decode_uleb128(self._buffer, self._offset)
        self._offset += count
        return val

    def read_uleb128p1(self) -> int:
        """Read a uleb128p1 integer and advance offset."""
        val, count = decode_uleb128p1(self._buffer, self._offset)
        self._offset += count
        return val

    def read_sleb128(self) -> int:
        """Read a signed LEB128 integer and advance offset."""
        val, count = decode_sleb128(self._buffer, self._offset)
        self._offset += count
        return val

    def read_mutf8(self, expected_utf16_size: int | None = None) -> str:
        """Read a MUTF-8 string and advance offset."""
        s, count = decode_mutf8(self._buffer, self._offset, expected_utf16_size=expected_utf16_size)
        self._offset += count
        return s

    def read_string_data_item(self) -> StringDataItem:
        """Read a StringDataItem structure and advance offset past it."""
        utf16_size = self.read_uleb128()
        data = self.read_mutf8(expected_utf16_size=utf16_size)
        return StringDataItem(utf16_size=utf16_size, data=data)

    def read_string_data(self) -> str:
        """Read the string content of a StringDataItem and advance offset past it."""
        return self.read_string_data_item().data

    # --- Subcursor Creation ---

    def subcursor(self, offset: int | None = None, length: int | None = None) -> Self:
        """Create a subcursor referencing a slice of this cursor's buffer."""
        base_offset = self._offset if offset is None else offset
        if not (0 <= base_offset <= len(self._buffer)):
            raise IndexError(
                f"Subcursor offset {base_offset} out of bounds "
                f"for buffer of size {len(self._buffer)}"
            )

        max_len = len(self._buffer) - base_offset
        sub_len = max_len if length is None else length

        if not (0 <= sub_len <= max_len):
            raise IndexError(
                f"Subcursor length {sub_len} out of bounds for available bytes {max_len}"
            )

        sub_slice = self._buffer[base_offset : base_offset + sub_len]
        return self.__class__(sub_slice)
