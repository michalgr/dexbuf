"""Modified UTF-8 (MUTF-8) string encoder, decoder, and utilities.

See https://source.android.com/docs/core/runtime/dex-format#mutf-8
"""

import struct
from collections.abc import Buffer

__all__ = [
    "compare_mutf8",
    "count_mutf8_utf16_units",
    "decode_mutf8",
    "decode_mutf8_utf16_units",
    "encode_mutf8",
    "utf16_code_units",
]


def compare_mutf8(b1: Buffer, b2: Buffer) -> int:
    """Compare two MUTF-8 byte buffers in UTF-16 code unit order.

    See https://source.android.com/docs/core/runtime/dex-format#mutf-8
    """
    mv1 = bytes(b1)
    mv2 = bytes(b2)
    if 0xC0 in mv1:
        mv1 = mv1.replace(b"\xc0\x80", b"\x00")
    if 0xC0 in mv2:
        mv2 = mv2.replace(b"\xc0\x80", b"\x00")
    if mv1 < mv2:
        return -1
    if mv1 > mv2:
        return 1
    return 0


def utf16_code_units(s: str) -> int:
    """Calculate the number of UTF-16 code units in a Python string.

    See https://source.android.com/docs/core/runtime/dex-format#mutf-8
    """
    if s.isascii():
        return len(s)
    return len(s.encode("utf-16le", errors="surrogatepass")) // 2


def encode_mutf8(s: str, null_terminated: bool = True) -> bytes:
    """Encode a Python string into Modified UTF-8 (MUTF-8) bytes.

    See https://source.android.com/docs/core/runtime/dex-format#mutf-8
    """
    res = bytearray()
    for ch in s:
        cp = ord(ch)
        if cp == 0:
            res.extend((0xC0, 0x80))
        elif 1 <= cp <= 0x7F:
            res.append(cp)
        elif 0x80 <= cp <= 0x07FF:
            res.append(0xC0 | (cp >> 6))
            res.append(0x80 | (cp & 0x3F))
        elif 0x0800 <= cp <= 0xFFFF:
            res.append(0xE0 | (cp >> 12))
            res.append(0x80 | ((cp >> 6) & 0x3F))
            res.append(0x80 | (cp & 0x3F))
        else:
            # Supplementary code point U+10000 to U+10FFFF
            # Encoded as UTF-16 surrogate pair, each surrogate as a 3-byte MUTF-8 sequence.
            high = 0xD800 + ((cp - 0x10000) >> 10)
            low = 0xDC00 + ((cp - 0x10000) & 0x3FF)
            for surrogate in (high, low):
                res.append(0xE0 | (surrogate >> 12))
                res.append(0x80 | ((surrogate >> 6) & 0x3F))
                res.append(0x80 | (surrogate & 0x3F))

    if null_terminated:
        res.append(0x00)

    return bytes(res)


def _is_ascii_mutf8(buf: memoryview) -> bool:
    b = bytes(buf)
    return b.isascii() and b"\x00" not in b


def _decode_mutf8_units_body(buf: memoryview, expected_utf16_size: int | None = None) -> list[int]:
    buf_len = len(buf)
    units: list[int] = []
    idx = 0
    while idx < buf_len:
        b1 = buf[idx]
        idx += 1

        if (b1 & 0x80) == 0:
            if b1 == 0:
                raise ValueError(f"Unexpected null byte at offset {idx - 1} in MUTF-8 data")
            units.append(b1)
        elif (b1 & 0xE0) == 0xC0:
            if idx >= buf_len:
                raise ValueError(f"Truncated 2-byte MUTF-8 sequence at offset {idx - 1}")
            b2 = buf[idx]
            idx += 1
            if (b2 & 0xC0) != 0x80:
                raise ValueError(f"Invalid MUTF-8 continuation byte 0x{b2:02x} at offset {idx - 1}")
            u = ((b1 & 0x1F) << 6) | (b2 & 0x3F)
            units.append(u)
        elif (b1 & 0xF0) == 0xE0:
            if idx + 2 > buf_len:
                raise ValueError(f"Truncated 3-byte MUTF-8 sequence at offset {idx - 1}")
            b2 = buf[idx]
            b3 = buf[idx + 1]
            idx += 2
            if (b2 & 0xC0) != 0x80 or (b3 & 0xC0) != 0x80:
                raise ValueError(f"Invalid MUTF-8 continuation bytes at offset {idx - 2}")
            u = ((b1 & 0x0F) << 12) | ((b2 & 0x3F) << 6) | (b3 & 0x3F)
            units.append(u)
        else:
            raise ValueError(f"Invalid MUTF-8 start byte 0x{b1:02x} at offset {idx - 1}")

    if expected_utf16_size is not None and len(units) != expected_utf16_size:
        raise ValueError(
            f"MUTF-8 string length mismatch: expected {expected_utf16_size} "
            f"UTF-16 code units, got {len(units)}"
        )

    return units


def decode_mutf8_utf16_units(
    data: Buffer, expected_utf16_size: int | None = None
) -> tuple[int, ...]:
    """Decode MUTF-8 bytes into a sequence of UTF-16 code units (tuple[int, ...]).

    See https://source.android.com/docs/core/runtime/dex-format#mutf-8
    """
    buf = memoryview(data).cast("B")
    buf_len = len(buf)

    if (expected_utf16_size is None or expected_utf16_size == buf_len) and _is_ascii_mutf8(buf):
        return tuple(buf)

    return tuple(_decode_mutf8_units_body(buf, expected_utf16_size=expected_utf16_size))


def decode_mutf8(data: Buffer, expected_utf16_size: int | None = None) -> str:
    """Decode MUTF-8 bytes into a Python string.

    See https://source.android.com/docs/core/runtime/dex-format#mutf-8
    """
    buf = memoryview(data).cast("B")
    buf_len = len(buf)

    if (expected_utf16_size is None or expected_utf16_size == buf_len) and _is_ascii_mutf8(buf):
        return bytes(buf).decode("ascii")

    units = _decode_mutf8_units_body(buf, expected_utf16_size=expected_utf16_size)
    if not units:
        return ""

    raw_utf16 = struct.pack(f"<{len(units)}H", *units)
    return raw_utf16.decode("utf-16le", errors="surrogatepass")


def count_mutf8_utf16_units(data: Buffer) -> int:
    """Calculate the number of UTF-16 code units in a MUTF-8 buffer.

    See https://source.android.com/docs/core/runtime/dex-format#mutf-8
    """
    buf = memoryview(data).cast("B")
    return sum(1 for b in buf if (b & 0xC0) != 0x80)
