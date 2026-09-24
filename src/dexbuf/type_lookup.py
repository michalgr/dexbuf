"""Zero-copy hash-based lookup table for fast DEX class definition resolution.

See https://source.android.com/docs/core/runtime/dex-format
"""

import struct
from collections.abc import Buffer, Sequence
from dataclasses import dataclass
from typing import ClassVar, Self, overload

from dexbuf.cursor import Cursor
from dexbuf.dex import DexFile
from dexbuf.mutf8 import compute_mutf8_hash, encode_mutf8

__all__ = [
    "TypeLookupTable",
    "TypeLookupTableEntry",
]


@dataclass(slots=True, frozen=True)
class TypeLookupTableEntry:
    """Entry in a DEX TypeLookupTable (8 bytes).

    See https://source.android.com/docs/core/runtime/dex-format
    """

    STRUCT: ClassVar[struct.Struct] = struct.Struct("<2I")

    str_offset: int
    data: int

    @property
    def is_empty(self) -> bool:
        """Return True if this entry represents an empty slot."""
        return self.str_offset == 0

    def next_pos_delta(self, mask_bits: int) -> int:
        """Extract next_pos_delta from data given mask_bits."""
        mask = (1 << mask_bits) - 1
        return self.data & mask

    def class_def_idx(self, mask_bits: int) -> int:
        """Extract class_def_idx from data given mask_bits."""
        mask = (1 << mask_bits) - 1
        return (self.data >> mask_bits) & mask

    def hash_bits(self, mask_bits: int) -> int:
        """Extract high hash_bits from data given mask_bits."""
        return self.data >> (2 * mask_bits)

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Parse a TypeLookupTableEntry from cursor."""
        str_offset, data = cursor.unpack(cls.STRUCT)
        return cls(str_offset=str_offset, data=data)

    @classmethod
    def from_buffer(cls, buffer: Buffer, offset: int = 0) -> Self:
        """Parse a TypeLookupTableEntry from buffer at offset."""
        return cls.from_cursor(Cursor(buffer, offset))

    def to_bytes(self) -> bytes:
        """Encode entry to raw bytes."""
        return self.STRUCT.pack(self.str_offset, self.data)


class TypeLookupTable(Sequence[TypeLookupTableEntry]):
    """Zero-copy hash-based lookup table for fast DEX class definition resolution."""

    __slots__ = ("_dex_buffer", "_mask_bits", "_raw_data", "_size_entries")

    def __init__(self, dex_buffer: Buffer, raw_data: Buffer) -> None:
        """Initialize TypeLookupTable from DEX file buffer and raw table entry data."""
        self._dex_buffer: memoryview = memoryview(dex_buffer).cast("B")
        self._raw_data: memoryview = memoryview(raw_data).cast("B")

        if len(self._raw_data) % 8 != 0:
            raise ValueError(
                f"TypeLookupTable raw_data size must be a multiple of 8, got {len(self._raw_data)}"
            )

        self._size_entries: int = len(self._raw_data) // 8
        if self._size_entries > 0:
            if (self._size_entries & (self._size_entries - 1)) != 0:
                raise ValueError(
                    f"TypeLookupTable entry count must be a power of two, got {self._size_entries}"
                )
            self._mask_bits: int = (self._size_entries - 1).bit_length()
        else:
            self._mask_bits = 0

    @property
    def raw_data(self) -> memoryview:
        """Return zero-copy memoryview slice of the raw table data."""
        return self._raw_data

    @property
    def mask_bits(self) -> int:
        """Return mask_bits (log2 of entry count)."""
        return self._mask_bits

    def __len__(self) -> int:
        """Return total number of entry slots in table."""
        return self._size_entries

    @overload
    def __getitem__(self, index: int) -> TypeLookupTableEntry: ...

    @overload
    def __getitem__(self, index: slice) -> tuple[TypeLookupTableEntry, ...]: ...

    def __getitem__(
        self, index: int | slice
    ) -> TypeLookupTableEntry | tuple[TypeLookupTableEntry, ...]:
        """Return the i-th TypeLookupTableEntry or slice of entries."""
        if isinstance(index, slice):
            return tuple(self[i] for i in range(*index.indices(self._size_entries)))

        if index < 0:
            index += self._size_entries
        if index < 0 or index >= self._size_entries:
            raise IndexError(f"Index {index} out of bounds for table of size {self._size_entries}")
        return TypeLookupTableEntry.from_buffer(self._raw_data, index * 8)

    def lookup(self, descriptor: str | bytes | Buffer) -> int | None:
        """Fast O(1) class definition lookup by class descriptor.

        Returns class_def_idx if found, or None if not found.
        """
        if self._size_entries == 0:
            return None

        if isinstance(descriptor, str):
            target_bytes = encode_mutf8(descriptor, null_terminated=False)
            target_hash = compute_mutf8_hash(target_bytes)
        elif isinstance(descriptor, (bytes, bytearray, memoryview)):
            target_bytes = bytes(descriptor)
            target_hash = compute_mutf8_hash(target_bytes)
        else:
            target_bytes = bytes(memoryview(descriptor))
            target_hash = compute_mutf8_hash(target_bytes)

        mask_bits = self._mask_bits
        mask = self._size_entries - 1
        pos = target_hash & mask if mask_bits > 0 else 0
        target_hash_bits = target_hash >> (2 * mask_bits)
        class_def_idx_mask = (1 << mask_bits) - 1

        for _ in range(self._size_entries):
            str_offset, data = struct.unpack_from("<2I", self._raw_data, pos * 8)
            if str_offset == 0:
                return None

            entry_hash_bits = data >> (2 * mask_bits)
            if entry_hash_bits == target_hash_bits:
                try:
                    cursor = Cursor(self._dex_buffer, str_offset)
                    utf16_size = cursor.read_uleb128()
                    cand_mutf8 = cursor.read_mutf8_slice(size_hint=utf16_size)
                    if bytes(cand_mutf8) == target_bytes:
                        return (data >> mask_bits) & class_def_idx_mask
                except EOFError, ValueError:
                    pass

            next_pos_delta = data & ((1 << mask_bits) - 1)
            if next_pos_delta == 0:
                return None

            pos = (pos + next_pos_delta) & mask

        return None

    @classmethod
    def create(cls, dex: DexFile) -> Self:
        """Construct a TypeLookupTable for the given DexFile."""
        num_class_defs = len(dex.class_defs)
        if num_class_defs == 0:
            mask_bits = 0
            size_entries = 1
        else:
            mask_bits = (num_class_defs - 1).bit_length()
            size_entries = 1 << mask_bits

        mask = size_entries - 1

        # Collect info for all class defs: (class_def_idx, str_offset, hash_val)
        buckets: list[list[tuple[int, int, int]]] = [[] for _ in range(size_entries)]

        for i in range(num_class_defs):
            cd = dex.class_defs[i]
            type_id = dex.get_type_id(cd.class_idx)
            string_id = dex.get_string_id(type_id.descriptor_idx)
            str_offset = string_id.string_data_off
            string_data = dex.get_string_data(type_id.descriptor_idx)
            descriptor_bytes = string_data.raw_bytes
            hash_val = compute_mutf8_hash(descriptor_bytes)
            b_idx = hash_val & mask if mask_bits > 0 else 0
            buckets[b_idx].append((i, str_offset, hash_val))

        # Build table entries: (class_def_idx, str_offset, hash_val, next_pos_delta) or None
        table_slots: list[tuple[int, int, int, int] | None] = [None] * size_entries

        # Pass 1: Place primary items at home bucket
        for b in range(size_entries):
            if buckets[b]:
                primary = buckets[b][0]
                table_slots[b] = (primary[0], primary[1], primary[2], 0)

        # Pass 2: Place secondary items and build collision chains
        for b in range(size_entries):
            chain = buckets[b]
            if len(chain) > 1:
                prev_slot = b
                for item in chain[1:]:
                    empty_slot = (prev_slot + 1) & mask if mask_bits > 0 else 0
                    while table_slots[empty_slot] is not None:
                        empty_slot = (empty_slot + 1) & mask if mask_bits > 0 else 0

                    table_slots[empty_slot] = (item[0], item[1], item[2], 0)

                    delta = (empty_slot - prev_slot) & mask if mask_bits > 0 else 0
                    p_slot = table_slots[prev_slot]
                    assert p_slot is not None
                    p_idx, p_off, p_hash, _ = p_slot
                    table_slots[prev_slot] = (p_idx, p_off, p_hash, delta)

                    prev_slot = empty_slot

        # Pack into raw binary bytes
        raw_bytes = bytearray()
        for slot in table_slots:
            if slot is None:
                raw_bytes.extend(b"\x00" * 8)
            else:
                c_idx, s_off, h_val, delta = slot
                hash_bits = h_val >> (2 * mask_bits)
                data = (hash_bits << (2 * mask_bits)) | (c_idx << mask_bits) | delta
                raw_bytes.extend(struct.pack("<2I", s_off, data))

        return cls(dex._buffer, bytes(raw_bytes))
