"""Fast, 0-copy binary reader (Cursor) with LEB128 and MUTF-8 decoding.

See https://source.android.com/docs/core/runtime/dex-format
"""

import struct
from collections.abc import Buffer
from typing import Any, Self

from dexbuf.mutf8 import decode_mutf8

__all__ = ["Cursor"]


class Cursor:
    """A zero-copy binary reader navigating a DEX buffer.

    Underlying storage is held in a 1D unsigned byte memoryview (`cast("B")`).
    Supports numeric reads, slicing, subcursor creation, LEB128, and MUTF-8 string decoding.
    """

    __slots__ = ("_buffer", "_offset")

    def __init__(self, buffer: Buffer, offset: int = 0) -> None:
        self._buffer: memoryview = memoryview(buffer).cast("B")
        if not (0 <= offset <= len(self._buffer)):
            raise ValueError(f"Initial offset {offset} out of bounds [0, {len(self._buffer)}]")
        self._offset: int = offset

    @property
    def offset(self) -> int:
        """Get current byte offset in the buffer."""
        return self._offset

    @offset.setter
    def offset(self, value: int) -> None:
        """Set current byte offset in the buffer (bounds checked)."""
        if not (0 <= value <= len(self._buffer)):
            raise ValueError(f"Offset {value} out of bounds [0, {len(self._buffer)}]")
        self._offset = value

    def tell(self) -> int:
        """Return the current byte offset."""
        return self._offset

    def seek(self, offset: int) -> Self:
        """Set byte offset to target location and return self."""
        self.offset = offset
        return self

    def skip(self, count: int) -> Self:
        """Advance byte offset by count and return self."""
        self.offset = self._offset + count
        return self

    @property
    def is_eof(self) -> bool:
        """Return True if cursor offset is at or past end of buffer."""
        return self._offset >= len(self._buffer)

    @property
    def remaining(self) -> int:
        """Return number of remaining unread bytes in buffer."""
        return len(self._buffer) - self._offset

    def unpack(self, s: struct.Struct) -> tuple[Any, ...]:
        """Unpack a struct.Struct directly from buffer at current offset and advance offset."""
        if self._offset + s.size > len(self._buffer):
            raise EOFError(
                f"Unexpected EOF while unpacking {s.format} "
                f"(need {s.size} bytes; remaining: {self.remaining})"
            )
        val = s.unpack_from(self._buffer, self._offset)
        self._offset += s.size
        return val

    # --- Numeric reads (little-endian) ---

    def read_u8(self) -> int:
        """Read an unsigned 8-bit integer."""
        if self._offset + 1 > len(self._buffer):
            raise EOFError("Unexpected EOF while reading u8")
        val = self._buffer[self._offset]
        self._offset += 1
        return val

    def read_u16(self) -> int:
        """Read an unsigned 16-bit integer (little-endian)."""
        if self._offset + 2 > len(self._buffer):
            raise EOFError("Unexpected EOF while reading u16")
        val = struct.unpack_from("<H", self._buffer, self._offset)[0]
        self._offset += 2
        return val

    def read_u32(self) -> int:
        """Read an unsigned 32-bit integer (little-endian)."""
        if self._offset + 4 > len(self._buffer):
            raise EOFError("Unexpected EOF while reading u32")
        val = struct.unpack_from("<I", self._buffer, self._offset)[0]
        self._offset += 4
        return val

    def read_i8(self) -> int:
        """Read a signed 8-bit integer."""
        if self._offset + 1 > len(self._buffer):
            raise EOFError("Unexpected EOF while reading i8")
        val = struct.unpack_from("<b", self._buffer, self._offset)[0]
        self._offset += 1
        return val

    def read_i16(self) -> int:
        """Read a signed 16-bit integer (little-endian)."""
        if self._offset + 2 > len(self._buffer):
            raise EOFError("Unexpected EOF while reading i16")
        val = struct.unpack_from("<h", self._buffer, self._offset)[0]
        self._offset += 2
        return val

    def read_i32(self) -> int:
        """Read a signed 32-bit integer (little-endian)."""
        if self._offset + 4 > len(self._buffer):
            raise EOFError("Unexpected EOF while reading i32")
        val = struct.unpack_from("<i", self._buffer, self._offset)[0]
        self._offset += 4
        return val

    # --- Slice operations ---

    def read_bytes(self, count: int) -> bytes:
        """Read count bytes as a new bytes object and advance offset."""
        if count < 0 or count > self.remaining:
            raise EOFError(f"Cannot read {count} bytes; remaining: {self.remaining}")
        data = bytes(self._buffer[self._offset : self._offset + count])
        self._offset += count
        return data

    def read_slice(self, count: int) -> memoryview:
        """Read count bytes as a zero-copy memoryview slice and advance offset."""
        if count < 0 or count > self.remaining:
            raise EOFError(f"Cannot read slice of {count} bytes; remaining: {self.remaining}")
        mv = self._buffer[self._offset : self._offset + count]
        self._offset += count
        return mv

    def subcursor(self, offset: int | None = None, length: int | None = None) -> Cursor:
        """Create a child Cursor slice without advancing self._offset."""
        sub_offset = self._offset if offset is None else offset
        if not (0 <= sub_offset <= len(self._buffer)):
            raise ValueError(
                f"Subcursor offset {sub_offset} out of bounds [0, {len(self._buffer)}]"
            )

        if length is None:
            sub_length = len(self._buffer) - sub_offset
        else:
            sub_length = length

        if sub_length < 0 or sub_offset + sub_length > len(self._buffer):
            raise ValueError(
                f"Subcursor length {sub_length} invalid for offset {sub_offset} in "
                f"buffer length {len(self._buffer)}"
            )

        return Cursor(self._buffer[sub_offset : sub_offset + sub_length])

    # --- Variable-length entity decoding ---

    def read_uleb128(self) -> int:
        """Read an unsigned LEB128 (1 to 5 bytes).

        Advances internal offset automatically.

        See https://source.android.com/docs/core/runtime/dex-format#leb128
        """
        result = 0
        shift = 0
        for _ in range(5):
            if self._offset >= len(self._buffer):
                raise EOFError("Unexpected EOF while reading ULEB128")
            b = self._buffer[self._offset]
            self._offset += 1
            result |= (b & 0x7F) << shift
            if not (b & 0x80):
                return result
            shift += 7
        raise ValueError("Invalid ULEB128 sequence: exceeds 5 bytes")

    def read_uleb128p1(self) -> int:
        """Read uleb128p1 (uleb128 minus 1).

        Advances internal offset automatically.

        See https://source.android.com/docs/core/runtime/dex-format#leb128
        """
        return self.read_uleb128() - 1

    def read_sleb128(self) -> int:
        """Read a signed LEB128 (1 to 5 bytes).

        Advances internal offset automatically.

        See https://source.android.com/docs/core/runtime/dex-format#leb128
        """
        result = 0
        shift = 0
        for _ in range(5):
            if self._offset >= len(self._buffer):
                raise EOFError("Unexpected EOF while reading SLEB128")
            b = self._buffer[self._offset]
            self._offset += 1
            result |= (b & 0x7F) << shift
            shift += 7
            if not (b & 0x80):
                if b & 0x40:
                    result |= -1 << shift
                return result
        raise ValueError("Invalid SLEB128 sequence: exceeds 5 bytes")

    def read_mutf8_slice(self, size_hint: int | None = None) -> memoryview:
        """Scan to the terminating null byte 0x00 and return a zero-copy MUTF-8 slice.

        Advances internal offset past the terminating null byte.
        Uses size_hint (UTF-16 code unit size) for fast O(1) ASCII check and skip optimization.

        See https://source.android.com/docs/core/runtime/dex-format#mutf-8
        """
        buf = self._buffer
        buf_len = len(buf)
        scan_start = self._offset

        if size_hint is not None and size_hint >= 0:
            hint_pos = self._offset + size_hint
            if hint_pos < buf_len:
                if buf[hint_pos] == 0:
                    slice_mv = buf[self._offset : hint_pos]
                    self._offset = hint_pos + 1
                    return slice_mv
                scan_start = hint_pos + 1

        null_idx = -1
        for i in range(scan_start, buf_len):
            if buf[i] == 0:
                null_idx = i
                break

        if null_idx == -1:
            raise EOFError("Unterminated MUTF-8 string: reached EOF before null terminator")

        slice_mv = buf[self._offset : null_idx]
        self._offset = null_idx + 1
        return slice_mv

    def read_mutf8(self, expected_utf16_size: int | None = None) -> str:
        """Read a null-terminated Modified UTF-8 (MUTF-8) string.

        Advances self._offset past the terminating 0x00.
        Validates UTF-16 code unit count against expected_utf16_size if provided.

        See https://source.android.com/docs/core/runtime/dex-format#mutf-8
        """
        slice_mv = self.read_mutf8_slice(size_hint=expected_utf16_size)
        return decode_mutf8(slice_mv, expected_utf16_size=expected_utf16_size)
