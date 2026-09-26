"""Zero-copy hash-based lookup table for fast DEX class definition resolution.

See https://source.android.com/docs/core/runtime/dex-format
"""

import struct
from collections.abc import Buffer, Sequence
from dataclasses import dataclass
from typing import ClassVar, Self, overload

from dexbuf.cursor import Cursor
from dexbuf.dex import DexFile
from dexbuf.items import StringDataItem
from dexbuf.mutf8 import compute_mutf8_hash, encode_mutf8
from dexbuf.types import Offset

__all__ = [
    "TypeLookupTable",
    "TypeLookupTableBuilder",
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

    @staticmethod
    def pack(
        str_offset: int,
        class_def_idx: int,
        hash_val: int,
        next_pos_delta: int,
        mask_bits: int,
    ) -> bytes:
        """Pack entry components into 8 raw binary bytes."""
        hash_bits = hash_val >> (2 * mask_bits)
        data = (hash_bits << (2 * mask_bits)) | (class_def_idx << mask_bits) | next_pos_delta
        return TypeLookupTableEntry.STRUCT.pack(str_offset, data)


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
        """Fast O(1) class definition lookup by class descriptor."""
        if self._size_entries == 0:
            return None

        if isinstance(descriptor, str):
            target_bytes = encode_mutf8(descriptor, null_terminated=False)
        elif isinstance(descriptor, (bytes, bytearray, memoryview)):
            target_bytes = bytes(descriptor)
        else:
            target_bytes = bytes(memoryview(descriptor))

        target_hash = compute_mutf8_hash(target_bytes)
        mask_bits = self._mask_bits
        mask = self._size_entries - 1
        pos = target_hash & mask
        target_hash_bits = target_hash >> (2 * mask_bits)

        for _ in range(self._size_entries):
            entry = self[pos]
            if entry.is_empty:
                return None

            if entry.hash_bits(mask_bits) == target_hash_bits:
                str_item = StringDataItem.from_buffer(
                    self._dex_buffer, Offset[StringDataItem](entry.str_offset)
                )
                if str_item.raw_bytes == target_bytes:
                    return entry.class_def_idx(mask_bits)

            delta = entry.next_pos_delta(mask_bits)
            if delta == 0:
                return None
            pos = (pos + delta) & mask

        return None

    @classmethod
    def create(cls, dex: DexFile) -> Self:
        """Construct a TypeLookupTable for the given DexFile using TypeLookupTableBuilder."""
        table = TypeLookupTableBuilder(dex).build()
        assert isinstance(table, cls)
        return table


@dataclass(slots=True)
class _BuilderEntry:
    """Internal mutable entry used during TypeLookupTable construction."""

    class_def_idx: int
    str_offset: int
    hash_val: int
    next_pos_delta: int = 0


class TypeLookupTableBuilder:
    """Builder for constructing DEX TypeLookupTable binary layouts."""

    __slots__ = ("buckets", "dex", "mask", "mask_bits", "size_entries", "table_slots")

    def __init__(self, dex: DexFile) -> None:
        """Initialize TypeLookupTableBuilder for a given DexFile."""
        self.dex: DexFile = dex
        num_class_defs = len(dex.class_defs)
        if num_class_defs == 0:
            self.mask_bits: int = 0
            self.size_entries: int = 0
        else:
            self.mask_bits = (num_class_defs - 1).bit_length()
            self.size_entries = 1 << self.mask_bits

        self.mask: int = max(0, self.size_entries - 1)
        self.buckets: list[list[_BuilderEntry]] = [[] for _ in range(self.size_entries)]
        self.table_slots: list[_BuilderEntry | None] = [None] * self.size_entries

    def collect_buckets(self) -> None:
        """Iterate over dex.class_defs, compute MUTF-8 hashes, and bucket them."""
        for bucket in self.buckets:
            bucket.clear()
        num_class_defs = len(self.dex.class_defs)
        for i in range(num_class_defs):
            cd = self.dex.class_defs[i]
            str_offset = self.dex.get_class_def_string_data_offset(cd)
            string_data = StringDataItem.from_buffer(self.dex._buffer, str_offset)
            hash_val = compute_mutf8_hash(string_data.raw_bytes)
            b_idx = hash_val & self.mask
            self.buckets[b_idx].append(
                _BuilderEntry(class_def_idx=i, str_offset=str_offset, hash_val=hash_val)
            )

    def place_primary_entries(self) -> None:
        """Pass 1: Place first element of each non-empty bucket at its home slot."""
        for b in range(self.size_entries):
            if self.buckets[b]:
                self.table_slots[b] = self.buckets[b][0]

    def resolve_collisions(self) -> None:
        """Pass 2: Place secondary elements in nearest free slots and update links."""
        for b in range(self.size_entries):
            chain = self.buckets[b]
            if len(chain) > 1:
                prev_slot = b
                for item in chain[1:]:
                    empty_slot = (prev_slot + 1) & self.mask
                    while self.table_slots[empty_slot] is not None:
                        empty_slot = (empty_slot + 1) & self.mask

                    self.table_slots[empty_slot] = item

                    prev_entry = self.table_slots[prev_slot]
                    assert prev_entry is not None
                    prev_entry.next_pos_delta = (empty_slot - prev_slot) & self.mask

                    prev_slot = empty_slot

    def pack_entries(self) -> bytes:
        """Serialize table slots into raw binary bytes."""
        raw_bytes = bytearray()
        for slot in self.table_slots:
            if slot is None:
                raw_bytes.extend(b"\x00" * 8)
            else:
                raw_bytes.extend(
                    TypeLookupTableEntry.pack(
                        str_offset=slot.str_offset,
                        class_def_idx=slot.class_def_idx,
                        hash_val=slot.hash_val,
                        next_pos_delta=slot.next_pos_delta,
                        mask_bits=self.mask_bits,
                    )
                )

        return bytes(raw_bytes)

    def build(self) -> TypeLookupTable:
        """Coordinate creation steps and return an instantiated TypeLookupTable."""
        if self.size_entries == 0:
            return TypeLookupTable(self.dex._buffer, b"")
        self.collect_buckets()
        self.place_primary_entries()
        self.resolve_collisions()
        raw_data = self.pack_entries()
        return TypeLookupTable(self.dex._buffer, raw_data)
