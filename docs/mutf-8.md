# Modified UTF-8 (MUTF-8) and UTF-16 Code Unit Ordering

## Overview

The Android DEX specification requires `string_ids` to be ordered according to UTF-16 code unit values (matching `java.lang.String.compareTo()` and Android Runtime's `CompareModifiedUtf8ToModifiedUtf8AsUtf16CodePointValues`).

In MUTF-8:
- Supplementary characters ($U+10000 \dots U+10FFFF$) are encoded as UTF-16 surrogate pairs (lead surrogate $0xD800 \dots 0xDBFF$, trail surrogate $0xDC00 \dots 0xDFFF$).
- Each surrogate code unit is encoded as a 3-byte MUTF-8 sequence starting with `0xED`.
- High-BMP characters ($U+E000 \dots U+FFFF$) are encoded as 3-byte sequences starting with `0xEE` or `0xEF`.

Because `0xED < 0xEE`, MUTF-8 byte comparison naturally preserves UTF-16 code unit ordering across BMP and supplementary characters. The only point of divergence between MUTF-8 byte ordering and UTF-16 code unit ordering is the null character ($U+0000$), which is encoded as `0xC0 0x80` in MUTF-8 rather than `0x00`.

By transforming MUTF-8 byte sequences $M \to M^*$ by replacing `b"\xc0\x80"` with `b"\x00"`, direct byte comparison on $M^*$ becomes strictly identical to UTF-16 code unit ordering.

---

## Sub-Range Mapping Table

| Range Description | UTF-16 Code Unit(s) | Original MUTF-8 Bytes | Transformed $M^*$ Bytes (`b"\xc0\x80"` -> `b"\x00"`) | $M^*$ Length | Byte 1 in $M^*$ | Byte 2 in $M^*$ (when needed) |
| --- | --- | --- | --- | --- | --- | --- |
| Null Character | 0x0000 | C0 80 | 00 | 1 | 0x00 | — |
| ASCII | 0x0001..0x007F | 01..7F | 01..7F | 1 | 0x01..0x7F | — |
| 2-Byte Multilingual | 0x0080..0x07FF | C2 80..DF BF | C2 80..DF BF | 2 | 0xC2..0xDF | 0x80..0xBF |
| 3-Byte BMP (pre-surrogates) | 0x0800..0xD7FF | E0 A0 80..ED 9F BF | E0 A0 80..ED 9F BF | 3 | 0xE0..0xED | 0x80..0x9F (if byte 1 is 0xED) |
| Lead Surrogates (Supplementary) | 0xD800..0xDBFF | ED A0 80..ED AF BF | ED A0 80..ED AF BF | 3 | 0xED | 0xA0..0xAF |
| Trail Surrogates | 0xDC00..0xDFFF | ED B0 80..ED BF BF | ED B0 80..ED BF BF | 3 | 0xED | 0xB0..0xBF |
| 3-Byte BMP (post-surrogates) | 0xE000..0xFFFF | EE 80 80..EF BF BF | EE 80 80..EF BF BF | 3 | 0xEE..0xEF | 0x80..0xBF |

---

## Safety Justification for `b"\xc0\x80"` Replacement

Replacing `b"\xc0\x80"` with `b"\x00"` in MUTF-8 byte sequences is completely collision-free and structurally safe for the following reasons:

1. **Lead Byte Uniqueness (`0xC0`)**: In UTF-8 / MUTF-8 encoding rules, all continuation bytes must match `10xxxxxx` (`0x80`..`0xBF`). Because `0xC0` has the bit pattern `11000000`, it is strictly a leading byte for a 2-byte sequence and can **never** appear as a trailing continuation byte of any character.
2. **Continuation Byte Uniqueness (`0x80`)**: Conversely, `0x80` has the bit pattern `10000000`, so it is strictly a continuation byte and can **never** appear as the leading byte of any character sequence.
3. **Boundary Impassability**: Consequently, the byte sequence `0xC0 0x80` can never occur across the boundary between two adjacent characters (i.e., one character ending in `0xC0` and the next character starting with `0x80` is structurally impossible).
4. **Exact Equivalence**: Within valid MUTF-8 data, `0xC0` is only ever followed by `0x80`, uniquely representing $U+0000$. Thus, `b"\xc0\x80"` only and exclusively occurs as the complete encoding of the null character.
