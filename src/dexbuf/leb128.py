"""LEB128 variable-length integer encoding and decoding.

Reference: https://source.android.com/docs/core/runtime/dex-format#leb128
In .dex files, LEB128 is only ever used to encode 32-bit quantities (1 to 5 bytes).
"""

from collections.abc import Buffer

__all__ = [
    "decode_sleb128",
    "decode_uleb128",
    "decode_uleb128p1",
    "encode_sleb128",
    "encode_uleb128",
    "encode_uleb128p1",
]


def decode_uleb128(buffer: Buffer, offset: int = 0) -> tuple[int, int]:
    """Decode an unsigned LEB128 (uleb128) integer from buffer.

    Returns a tuple of (value, bytes_consumed).
    """
    mv = memoryview(buffer).cast("B")
    result = 0
    shift = 0
    count = 0
    buf_len = len(mv)

    while True:
        if offset + count >= buf_len:
            raise ValueError("Unexpected end of buffer while decoding uleb128")
        byte = mv[offset + count]
        count += 1
        result |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            break
        shift += 7
        if count > 5:
            raise ValueError("uleb128 sequence exceeds maximum length of 5 bytes")

    return result, count


def decode_uleb128p1(buffer: Buffer, offset: int = 0) -> tuple[int, int]:
    """Decode a uleb128p1 integer (uleb128 value - 1) from buffer.

    Returns a tuple of (value, bytes_consumed).
    """
    val, count = decode_uleb128(buffer, offset)
    return val - 1, count


def decode_sleb128(buffer: Buffer, offset: int = 0) -> tuple[int, int]:
    """Decode a signed LEB128 (sleb128) integer from buffer.

    Returns a tuple of (value, bytes_consumed).
    """
    mv = memoryview(buffer).cast("B")
    result = 0
    shift = 0
    count = 0
    buf_len = len(mv)
    byte = 0

    while True:
        if offset + count >= buf_len:
            raise ValueError("Unexpected end of buffer while decoding sleb128")
        byte = mv[offset + count]
        count += 1
        result |= (byte & 0x7F) << shift
        shift += 7
        if (byte & 0x80) == 0:
            break
        if count > 5:
            raise ValueError("sleb128 sequence exceeds maximum length of 5 bytes")

    if (byte & 0x40) != 0:
        result |= ~0 << shift

    return result, count


def encode_uleb128(val: int) -> bytes:
    """Encode a non-negative 32-bit integer as unsigned LEB128 (uleb128)."""
    if val < 0:
        raise ValueError(f"uleb128 value must be non-negative, got {val}")
    out = bytearray()
    num = val
    while True:
        byte = num & 0x7F
        num >>= 7
        if num != 0:
            byte |= 0x80
            out.append(byte)
        else:
            out.append(byte)
            break
    return bytes(out)


def encode_uleb128p1(val: int) -> bytes:
    """Encode a 32-bit integer as uleb128p1 (uleb128(val + 1))."""
    return encode_uleb128(val + 1)


def encode_sleb128(val: int) -> bytes:
    """Encode a signed 32-bit integer as signed LEB128 (sleb128)."""
    out = bytearray()
    num = val
    while True:
        byte = num & 0x7F
        num >>= 7
        has_more = True
        sign_bit = (byte & 0x40) != 0
        if (num == 0 and not sign_bit) or (num == -1 and sign_bit):
            has_more = False

        if has_more:
            byte |= 0x80
            out.append(byte)
        else:
            out.append(byte)
            break
    return bytes(out)
