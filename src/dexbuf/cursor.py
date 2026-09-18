"""Fast, 0-copy binary reader (Cursor) with LEB128 and MUTF-8 decoding.

See https://source.android.com/docs/core/runtime/dex-format
"""

import struct
from collections.abc import Buffer
from typing import Self

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

    def read_mutf8(self, expected_utf16_size: int | None = None) -> str:
        """Read a null-terminated Modified UTF-8 (MUTF-8) string.

        Advances self._offset past the terminating 0x00.
        Validates UTF-16 code unit count against expected_utf16_size if provided.

        See https://source.android.com/docs/core/runtime/dex-format#mutf-8
        """
        # ASCII fast-path
        if expected_utf16_size is not None:
            cand_len = expected_utf16_size
            if cand_len >= 0 and self._offset + cand_len < len(self._buffer):
                if self._buffer[self._offset + cand_len] == 0:
                    cand_bytes = bytes(self._buffer[self._offset : self._offset + cand_len])
                    if all(1 <= b <= 0x7F for b in cand_bytes):
                        self._offset += cand_len + 1
                        return cand_bytes.decode("ascii")

        units: list[int] = []
        buf = self._buffer
        buf_len = len(buf)

        while True:
            if self._offset >= buf_len:
                raise EOFError("Unterminated MUTF-8 string: reached EOF before null terminator")

            b1 = buf[self._offset]
            self._offset += 1

            if b1 == 0:
                # Null terminator
                break

            if (b1 & 0x80) == 0:
                # 1-byte ASCII (0x01..0x7F)
                units.append(b1)
            elif (b1 & 0xE0) == 0xC0:
                # 2-byte sequence
                if self._offset >= buf_len:
                    raise EOFError("Unterminated 2-byte MUTF-8 sequence at EOF")
                b2 = buf[self._offset]
                self._offset += 1
                if (b2 & 0xC0) != 0x80:
                    raise ValueError(
                        f"Invalid MUTF-8 continuation byte 0x{b2:02x} at offset {self._offset - 1}"
                    )
                u = ((b1 & 0x1F) << 6) | (b2 & 0x3F)
                units.append(u)
            elif (b1 & 0xF0) == 0xE0:
                # 3-byte sequence
                if self._offset + 2 > buf_len:
                    raise EOFError("Unterminated 3-byte MUTF-8 sequence at EOF")
                b2 = buf[self._offset]
                b3 = buf[self._offset + 1]
                self._offset += 2
                if (b2 & 0xC0) != 0x80 or (b3 & 0xC0) != 0x80:
                    raise ValueError(
                        f"Invalid MUTF-8 continuation bytes at offset {self._offset - 2}"
                    )
                u = ((b1 & 0x0F) << 12) | ((b2 & 0x3F) << 6) | (b3 & 0x3F)
                units.append(u)
            else:
                raise ValueError(
                    f"Invalid MUTF-8 start byte 0x{b1:02x} at offset {self._offset - 1}"
                )

        if expected_utf16_size is not None and len(units) != expected_utf16_size:
            raise ValueError(
                f"MUTF-8 string length mismatch: expected {expected_utf16_size} "
                f"UTF-16 code units, got {len(units)}"
            )

        if not units:
            return ""

        raw_utf16 = struct.pack(f"<{len(units)}H", *units)
        return raw_utf16.decode("utf-16le", errors="surrogatepass")
