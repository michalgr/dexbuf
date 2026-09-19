"""LEB128 variable-length integer encoders.

See https://source.android.com/docs/core/runtime/dex-format#leb128
"""

from dexbuf.types import NO_INDEX

__all__ = [
    "encode_sleb128",
    "encode_uleb128",
    "encode_uleb128p1",
]


def encode_uleb128(value: int) -> bytes:
    """Encode an integer as unsigned LEB128.

    See https://source.android.com/docs/core/runtime/dex-format#leb128
    """
    if value < 0:
        raise ValueError(f"Cannot encode negative integer {value} as uleb128")
    res = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value != 0:
            byte |= 0x80
            res.append(byte)
        else:
            res.append(byte)
            break
    return bytes(res)


def encode_uleb128p1(value: int) -> bytes:
    """Encode an integer as uleb128p1 (value + 1 encoded as uleb128).

    See https://source.android.com/docs/core/runtime/dex-format#leb128
    """
    if value in (-1, NO_INDEX):
        return encode_uleb128(0)
    return encode_uleb128(value + 1)


def encode_sleb128(value: int) -> bytes:
    """Encode a signed integer as LEB128.

    See https://source.android.com/docs/core/runtime/dex-format#leb128
    """
    res = bytearray()
    more = True
    while more:
        byte = value & 0x7F
        value >>= 7
        if (value == 0 and (byte & 0x40) == 0) or (value == -1 and (byte & 0x40) != 0):
            more = False
        else:
            byte |= 0x80
        res.append(byte)
    return bytes(res)
