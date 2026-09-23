# MUTF-8 and UTF-16 Binary Search Ordering in Dalvik Executable (DEX)

This document provides a detailed technical explanation of the string ordering guarantees in the Dalvik Executable (DEX) specification, how Modified UTF-8 (MUTF-8) interacts with UTF-16 code unit ordering, and the mathematical and structural safety rationale behind zero-copy MUTF-8 binary search.

---

## 1. Core Argument: UTF-8 Encoding Preserves Lexicographical Order

Standard UTF-8 (RFC 3629) maps Unicode scalar values (code points) to variable-length byte sequences (1 to 4 bytes) such that byte-by-byte lexicographical comparison of UTF-8 encoded bytes yields the exact same ordering as numerical comparison of Unicode code points.

The encoding format for standard UTF-8 code point ranges is structured as follows:

| Code Point Range | UTF-8 Byte Format | Lead Byte Range |
| :--- | :--- | :--- |
| `U+0000..U+007F` | `0xxxxxxx` | `0x00..0x7F` |
| `U+0080..U+07FF` | `110xxxxx 10xxxxxx` | `0xC2..0xDF` |
| `U+0800..U+FFFF` | `1110xxxx 10xxxxxx 10xxxxxx` | `0xE0..0xEF` |
| `U+10000..U+10FFFF` | `11110xxx 10xxxxxx 10xxxxxx 10xxxxxx` | `0xF0..0xF4` |

Order preservation holds due to three design properties:

1. **Disjoint, Strictly Increasing Lead Byte Ranges:** The lead byte ranges for higher code point intervals are strictly greater than those for lower intervals (`0x00..0x7F < 0xC2..0xDF < 0xE0..0xEF < 0xF0..0xF4`).
2. **Big-Endian Payload Packing & Uniform Continuation Prefix:** Continuation bytes always begin with the bit pattern `10xxxxxx` (`0x80..0xBF`). Because payload bits are packed in big-endian order across continuation bytes, byte-by-byte unsigned comparison matches the numerical ordering of code points within each sub-range.
3. **Prefix-Free Structure:** UTF-8 is a self-synchronizing prefix code; no validly encoded character is a prefix of another character.

---

## 2. MUTF-8 Differences from Standard UTF-8

Modified UTF-8 (MUTF-8), used in Android DEX files and JVM class files, departs from standard UTF-8 in two specific ways:

1. **Null Byte Encoding ($U+0000$):** The code point $U+0000$ is encoded as the 2-byte sequence `0xC0 0x80` (`11000000 10000000`) instead of the single byte `0x00`. This allows strings containing embedded null characters to be safely processed by standard C string functions as C-style null-terminated byte arrays.
2. **Supplementary Characters ($U+10000..U+10FFFF$):** Supplementary characters are encoded by first converting the character into a UTF-16 surrogate pair (a high surrogate in `U+D800..U+DBFF` followed by a low surrogate in `U+DC00..U+DFFF`), and then encoding each 16-bit surrogate as an independent 3-byte MUTF-8 sequence (`1110xxxx 10xxxxxx 10xxxxxx`). As a result, a supplementary character occupies 6 MUTF-8 bytes rather than 4 standard UTF-8 bytes.

---

## 3. UTF-16 Surrogate Pairs and Lexicographic Ordering

The Android DEX specification requires entries in the `string_ids` table to be sorted lexicographically by **UTF-16 code unit values**, matching Java's `String.compareTo()` and Android Runtime's `CompareModifiedUtf8ToModifiedUtf8AsUtf16CodePointValues`.

In standard UTF-8, supplementary code points ($U+10000..U+10FFFF$) start with lead bytes `0xF0..0xF4`, placing them after all Basic Multilingual Plane (BMP) characters (`0xE0..0xEF`). In Python str comparison (which compares scalar code points), $U+10000 > U+E000$.

However, under UTF-16 code unit ordering, supplementary characters are represented as surrogate pairs where the high surrogate lies in `0xD800..0xDBFF`. Numerically, in UTF-16 code units:

$$0xD800 \le \text{High Surrogate} \le 0xDBFF < 0xE000 \le \text{BMP High Characters}$$

Therefore, in UTF-16, supplementary characters ($U+10000..U+10FFFF$) **must sort before** BMP characters in $U+E000..U+FFFF$.

MUTF-8's surrogate pair encoding naturally preserves this requirement:
- High surrogates ($U+D800..U+DBFF$) are encoded as 3 MUTF-8 bytes starting with `0xED` (specifically `0xED` followed by `0xA0..0xAF`).
- BMP characters in $U+E000..U+FFFF$ are encoded as 3 MUTF-8 bytes starting with `0xEE..0xEF`.

Since `0xED < 0xEE`, the MUTF-8 byte sequence for high surrogates naturally sorts before MUTF-8 byte sequences for $U+E000..U+FFFF$. Thus, MUTF-8 byte sequences for supplementary characters inherently reflect UTF-16 code unit ordering.

---

## 4. The Null Byte Exception and Structural Safety

The only point of divergence between raw MUTF-8 byte comparison and UTF-16 code unit ordering is $U+0000$:
- In UTF-16, $U+0000$ has code unit value `0x0000`, which is smaller than all ASCII characters (`0x0001..0x007F`).
- In raw MUTF-8, $U+0000$ is encoded as `0xC0 0x80`. Since `0xC0 > 0x7F`, raw MUTF-8 places $U+0000$ after ASCII characters (`0x01..0x7F`).

Translating the byte sequence `b"\xc0\x80"` to `b"\x00"` (forming a transformed sequence $M^*$) completely restores UTF-16 code unit ordering.

### Structural Safety Proof for `b"\xc0\x80"` $\to$ `b"\x00"` Replacement

Replacing `b"\xc0\x80"` with `b"\x00"` in MUTF-8 data is guaranteed not to produce false matches or corrupt multi-character boundaries due to MUTF-8 byte structural invariants:

1. **Lead Byte Property:** `0xC0` (`11000000`) is strictly a 2-byte sequence lead byte in MUTF-8. It can only appear at the start of a multi-byte character sequence and can never occur as a continuation byte or at the end of a character.
2. **Continuation Byte Property:** `0x80` (`10000000`) is strictly a continuation byte (`10xxxxxx`). It can only appear following a lead byte and can never occur at the start of a character sequence.
3. **Uniqueness:** The byte pair `0xC0 0x80` can never span across two adjacent characters because no character can end with `0xC0` and no character can start with `0x80`. Therefore, in valid MUTF-8 data, the byte pair `0xC0 0x80` uniquely and unambiguously identifies $U+0000$.

Replacing `b"\xc0\x80"` with `b"\x00"` converts $U+0000$ into a single `0x00` byte, which sorts before `0x01..0x7F`, matching UTF-16 code unit `0x0000`.

---

## 5. Summary Reference Table

The table below summarizes all sub-ranges, UTF-16 code unit values, MUTF-8 byte encodings, transformed $M^*$ byte encodings, and byte boundaries.

| Character Range | UTF-16 Code Unit(s) | MUTF-8 Encodings (Bytes) | Transformed $M^*$ Encodings | First Byte Boundary |
| :--- | :--- | :--- | :--- | :--- |
| **Null Byte ($U+0000$)** | `0x0000` | `0xC0 0x80` | `0x00` | `0x00` |
| **ASCII ($U+0001..U+007F$)** | `0x0001..0x007F` | `0x01..0x7F` | `0x01..0x7F` | `0x01..0x7F` |
| **2-Byte BMP ($U+0080..U+07FF$)** | `0x0080..0x07FF` | `0xC2..0xDF`, `0x80..0xBF` | Same as MUTF-8 | `0xC2..0xDF` |
| **3-Byte BMP ($U+0800..U+D7FF$)** | `0x0800..0xD7FF` | `0xE0..0xEC`, `0x80..0xBF`, `0x80..0xBF` | Same as MUTF-8 | `0xE0..0xEC` |
| **Supplementary ($U+10000..U+10FFFF$)** | `0xD800..0xDBFF` (High)<br>`0xDC00..0xDFFF` (Low) | `0xED` `0xA0..0xAF` `0x80..0xBF`<br>`0xED` `0xB0..0xBF` `0x80..0xBF` | Same as MUTF-8 | `0xED` |
| **High BMP ($U+E000..U+FFFF$)** | `0xE000..0xFFFF` | `0xEE..0xEF`, `0x80..0xBF`, `0x80..0xBF` | Same as MUTF-8 | `0xEE..0xEF` |

As shown in the transformed $M^*$ column, the leading byte ranges are strictly monotonic and disjoint:

$$0x00 < 0x01..0x7F < 0xC2..0xDF < 0xE0..0xEC < 0xED < 0xEE..0xEF$$

This guarantees that byte-by-byte lexicographical comparison of transformed $M^*$ bytes yields exact UTF-16 code unit ordering without string decoding overhead.
