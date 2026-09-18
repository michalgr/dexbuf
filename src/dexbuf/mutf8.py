"""Modified UTF-8 (MUTF-8) string encoder and utilities.

See https://source.android.com/docs/core/runtime/dex-format#mutf-8
"""

__all__ = [
    "encode_mutf8",
    "utf16_code_units",
]


def utf16_code_units(s: str) -> int:
    """Calculate the number of UTF-16 code units in a Python string.

    See https://source.android.com/docs/core/runtime/dex-format#mutf-8
    """
    return sum(2 if ord(ch) > 0xFFFF else 1 for ch in s)


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
