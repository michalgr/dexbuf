"""Modified UTF-8 (MUTF-8) encoding and decoding.

Reference: https://source.android.com/docs/core/runtime/dex-format#mutf-8
"""

from collections.abc import Buffer

__all__ = [
    "decode_mutf8",
    "encode_mutf8",
    "utf16_code_units",
]


def utf16_code_units(s: str) -> int:
    """Return the number of UTF-16 code units required to represent a Python string.

    Characters outside the BMP (> U+FFFF) require 2 UTF-16 code units (surrogate pairs).
    """
    return sum(2 if ord(ch) > 0xFFFF else 1 for ch in s)


def encode_mutf8(s: str, *, null_terminated: bool = True) -> bytes:
    """Encode a Python string to Modified UTF-8 (MUTF-8) bytes.

    Reference: https://source.android.com/docs/core/runtime/dex-format#mutf-8
    """
    out = bytearray()
    for ch in s:
        cp = ord(ch)
        if cp == 0:
            out.extend(b"\xc0\x80")
        elif cp <= 0x7F:
            out.append(cp)
        elif cp <= 0x7FF:
            out.append(0xC0 | (cp >> 6))
            out.append(0x80 | (cp & 0x3F))
        elif cp <= 0xFFFF:
            out.append(0xE0 | (cp >> 12))
            out.append(0x80 | ((cp >> 6) & 0x3F))
            out.append(0x80 | (cp & 0x3F))
        else:
            cp -= 0x10000
            high = 0xD800 + (cp >> 10)
            low = 0xDC00 + (cp & 0x3FF)
            out.append(0xE0 | (high >> 12))
            out.append(0x80 | ((high >> 6) & 0x3F))
            out.append(0x80 | (high & 0x3F))
            out.append(0xE0 | (low >> 12))
            out.append(0x80 | ((low >> 6) & 0x3F))
            out.append(0x80 | (low & 0x3F))

    if null_terminated:
        out.append(0)

    return bytes(out)


def decode_mutf8(
    buffer: Buffer, offset: int = 0, *, expected_utf16_size: int | None = None
) -> tuple[str, int]:
    """Decode a Modified UTF-8 (MUTF-8) string from buffer starting at offset.

    Returns a tuple of (decoded_str, bytes_consumed).
    Reference: https://source.android.com/docs/core/runtime/dex-format#mutf-8
    """
    mv = memoryview(buffer).cast("B")
    buf_len = len(mv)

    if expected_utf16_size is not None:
        end = offset + expected_utf16_size
        if end < buf_len and mv[end] == 0:
            cand_bytes = mv[offset:end].tobytes()
            if cand_bytes.isascii() and b"\x00" not in cand_bytes:
                return cand_bytes.decode("ascii"), expected_utf16_size + 1

    chars: list[str] = []
    curr = offset

    while curr < buf_len:
        b1 = mv[curr]
        if b1 == 0:
            curr += 1
            res_str = "".join(chars)
            if expected_utf16_size is not None and utf16_code_units(res_str) != expected_utf16_size:
                actual_size = utf16_code_units(res_str)
                raise ValueError(
                    f"MUTF-8 string UTF-16 code unit size mismatch: "
                    f"expected {expected_utf16_size}, got {actual_size}"
                )
            return res_str, curr - offset

        if (b1 & 0x80) == 0:
            chars.append(chr(b1))
            curr += 1
        elif (b1 & 0xE0) == 0xC0:
            if curr + 1 >= buf_len:
                raise ValueError("Truncated MUTF-8 2-byte sequence")
            b2 = mv[curr + 1]
            if (b2 & 0xC0) != 0x80:
                raise ValueError(
                    f"Invalid MUTF-8 continuation byte 0x{b2:02x} at offset {curr + 1}"
                )
            cp = ((b1 & 0x1F) << 6) | (b2 & 0x3F)
            chars.append(chr(cp))
            curr += 2
        elif (b1 & 0xF0) == 0xE0:
            if curr + 2 >= buf_len:
                raise ValueError("Truncated MUTF-8 3-byte sequence")
            b2 = mv[curr + 1]
            b3 = mv[curr + 2]
            if (b2 & 0xC0) != 0x80 or (b3 & 0xC0) != 0x80:
                raise ValueError(f"Invalid MUTF-8 continuation byte at offset {curr}")
            cp = ((b1 & 0x0F) << 12) | ((b2 & 0x3F) << 6) | (b3 & 0x3F)

            if 0xD800 <= cp <= 0xDBFF:
                if (
                    curr + 5 < buf_len
                    and (mv[curr + 3] & 0xF0) == 0xE0
                    and (mv[curr + 4] & 0xC0) == 0x80
                    and (mv[curr + 5] & 0xC0) == 0x80
                ):
                    next_b1 = mv[curr + 3]
                    next_b2 = mv[curr + 4]
                    next_b3 = mv[curr + 5]
                    next_cp = ((next_b1 & 0x0F) << 12) | ((next_b2 & 0x3F) << 6) | (next_b3 & 0x3F)
                    if 0xDC00 <= next_cp <= 0xDFFF:
                        combined_cp = 0x10000 + ((cp - 0xD800) << 10) + (next_cp - 0xDC00)
                        chars.append(chr(combined_cp))
                        curr += 6
                        continue

            chars.append(chr(cp))
            curr += 3
        else:
            raise ValueError(f"Invalid MUTF-8 start byte 0x{b1:02x} at offset {curr}")

    raise ValueError("Unterminated MUTF-8 string (missing 0x00 byte)")
