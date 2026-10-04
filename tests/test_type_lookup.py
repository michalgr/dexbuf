"""Unit tests for TypeLookupTable and TypeLookupTableEntry."""

import unittest

from dexbuf.cursor import Cursor
from dexbuf.dex import DexFile
from dexbuf.type_lookup import (
    TypeLookupTable,
    TypeLookupTableBuilder,
    TypeLookupTableEntry,
    _BuilderEntry,
)
from tests.builders import build_dex_bytes  # type: ignore[import-not-found, missing-import]


def _make_dex(class_descriptors: list[str]) -> bytes:
    return build_dex_bytes([{"name": c, "super": "Ljava/lang/Object;"} for c in class_descriptors])


class TestTypeLookupTable(unittest.TestCase):
    def test_entry_properties_and_serialization(self) -> None:
        """Verify TypeLookupTableEntry bitfields, packing, unpacking, and helper properties."""
        # Test empty entry
        empty_entry = TypeLookupTableEntry(str_offset=0, data=0)
        self.assertTrue(empty_entry.is_empty)
        self.assertEqual(empty_entry.next_pos_delta(2), 0)
        self.assertEqual(empty_entry.class_def_idx(2), 0)
        self.assertEqual(empty_entry.hash_bits(2), 0)

        # Pack entry with known data
        # mask_bits = 3 (8 entries table)
        # next_pos_delta = 2
        # class_def_idx = 5
        # hash_bits = 0x1234
        mask_bits = 3
        delta = 2
        class_def_idx = 5
        hash_bits = 0x1234
        packed_data = (hash_bits << (2 * mask_bits)) | (class_def_idx << mask_bits) | delta
        str_offset = 0x100

        entry = TypeLookupTableEntry(str_offset=str_offset, data=packed_data)
        self.assertFalse(entry.is_empty)
        self.assertEqual(entry.next_pos_delta(mask_bits), delta)
        self.assertEqual(entry.class_def_idx(mask_bits), class_def_idx)
        self.assertEqual(entry.hash_bits(mask_bits), hash_bits)

        # to_bytes and from_buffer / from_cursor
        raw = entry.to_bytes()
        self.assertEqual(len(raw), 8)

        parsed_buf = TypeLookupTableEntry.from_buffer(raw, 0)
        self.assertEqual(parsed_buf, entry)

        parsed_cur = TypeLookupTableEntry.from_cursor(Cursor(raw, 0))
        self.assertEqual(parsed_cur, entry)

    def test_entry_encode_and_round_trip(self) -> None:
        """Verify _BuilderEntry.encode method and round-trip parsing."""
        import struct

        str_offset = 0x200
        class_def_idx = 7
        hash_val = 0xABCD1234
        next_pos_delta = 3
        mask_bits = 4

        expected_hash_bits = hash_val >> (2 * mask_bits)
        expected_data = (
            (expected_hash_bits << (2 * mask_bits)) | (class_def_idx << mask_bits) | next_pos_delta
        )

        builder_entry = _BuilderEntry(
            str_offset=str_offset,
            class_def_idx=class_def_idx,
            hash_val=hash_val,
            next_pos_delta=next_pos_delta,
        )
        packed_bytes = builder_entry.encode(mask_bits)

        self.assertEqual(len(packed_bytes), 8)

        expected_bytes = struct.pack("<2I", str_offset, expected_data)
        self.assertEqual(packed_bytes, expected_bytes)

        parsed_entry = TypeLookupTableEntry.from_buffer(packed_bytes, 0)
        self.assertEqual(parsed_entry.str_offset, str_offset)
        self.assertEqual(parsed_entry.data, expected_data)
        self.assertEqual(parsed_entry.class_def_idx(mask_bits), class_def_idx)
        self.assertEqual(parsed_entry.hash_bits(mask_bits), expected_hash_bits)
        self.assertEqual(parsed_entry.next_pos_delta(mask_bits), next_pos_delta)

    def test_create_and_lookup_zero_class_dex(self) -> None:
        """Verify TypeLookupTable.create and lookup on a DEX file with 0 class definitions."""
        dex_bytes = _make_dex([])
        dex = DexFile(dex_bytes)

        table = TypeLookupTable.create(dex)
        self.assertIsInstance(table, TypeLookupTable)
        self.assertEqual(len(table), 0)
        self.assertEqual(table.raw_data, b"")
        self.assertEqual(table.mask_bits, 0)

        # Lookups on 0-class DEX table should return None
        self.assertIsNone(table.lookup("LTestClass;"))
        self.assertIsNone(table.lookup("Ljava/lang/Object;"))

    def test_create_and_lookup_single_class_dex(self) -> None:
        """Verify TypeLookupTable.create and lookup on a single-class DEX file."""
        dex_bytes = _make_dex(["LTestClass;"])
        dex = DexFile(dex_bytes)

        table = TypeLookupTable.create(dex)
        self.assertIsInstance(table, TypeLookupTable)
        self.assertEqual(len(table), 1)
        self.assertEqual(table.mask_bits, 0)

        # Lookups
        self.assertEqual(table.lookup("LTestClass;"), 0)
        self.assertEqual(table.lookup(b"LTestClass;"), 0)
        self.assertEqual(table.lookup(memoryview(b"LTestClass;")), 0)
        self.assertIsNone(table.lookup("Ljava/lang/Object;"))
        self.assertIsNone(table.lookup("LNonExistent;"))

    def test_builder_step_by_step(self) -> None:
        """Verify TypeLookupTableBuilder steps and output."""
        dex_bytes = _make_dex(["LClassA;", "LClassB;"])
        dex = DexFile(dex_bytes)

        builder = TypeLookupTableBuilder(dex)
        self.assertEqual(builder.size_entries, 2)
        self.assertEqual(builder.mask_bits, 1)

        builder.collect_buckets()
        self.assertEqual(len(builder.buckets), 2)

        builder.place_primary_entries()
        builder.resolve_collisions()

        raw = builder.pack_entries()
        self.assertEqual(len(raw), 16)

        table = builder.build()
        self.assertIsInstance(table, TypeLookupTable)
        self.assertEqual(table.lookup("LClassA;"), 0)
        self.assertEqual(table.lookup("LClassB;"), 1)

    def test_builder_buckets_reuse_and_clearing(self) -> None:
        """Verify TypeLookupTableBuilder reuses self.buckets list and clears bucket contents."""
        dex_bytes = _make_dex(["LClassA;", "LClassB;"])
        dex = DexFile(dex_bytes)

        builder = TypeLookupTableBuilder(dex)
        buckets_id = id(builder.buckets)
        bucket_sublist_ids = [id(b) for b in builder.buckets]

        builder.collect_buckets()
        self.assertEqual(id(builder.buckets), buckets_id)
        self.assertEqual([id(b) for b in builder.buckets], bucket_sublist_ids)

        # Call collect_buckets a second time to verify clearing works without accumulating entries
        builder.collect_buckets()
        self.assertEqual(id(builder.buckets), buckets_id)
        self.assertEqual([id(b) for b in builder.buckets], bucket_sublist_ids)
        total_bucketed_items = sum(len(b) for b in builder.buckets)
        self.assertEqual(total_bucketed_items, 2)

    def test_create_and_lookup_multi_class_dex(self) -> None:
        """Verify TypeLookupTable.create and lookup on a multi-class DEX file."""
        classes = [
            "Lcom/example/ClassA;",
            "Lcom/example/ClassB;",
            "Lcom/example/ClassC;",
            "Lcom/example/ClassD;",
            "Lcom/example/ClassE;",
        ]
        dex_bytes = _make_dex(classes)
        dex = DexFile(dex_bytes)

        table = TypeLookupTable.create(dex)
        self.assertEqual(len(table), 8)  # 5 classes -> 2^3 = 8
        self.assertEqual(table.mask_bits, 3)

        # Lookups for each class
        for expected_idx, c_desc in enumerate(classes):
            idx = table.lookup(c_desc)
            self.assertEqual(idx, expected_idx, f"Failed lookup for {c_desc}")
            # Also test bytes input
            idx_bytes = table.lookup(c_desc.encode("ascii"))
            self.assertEqual(idx_bytes, expected_idx)

        # Lookups for non-existent classes
        self.assertIsNone(table.lookup("Lcom/example/NonExistent;"))
        self.assertIsNone(table.lookup("Ljava/lang/Object;"))

    def test_hash_collision_chaining(self) -> None:
        """Verify collision chaining and resolution in TypeLookupTable."""
        # Construct synthetic multi-class descriptors
        classes = [f"Lcom/example/TestClass{i};" for i in range(16)]
        dex_bytes = _make_dex(classes)
        dex = DexFile(dex_bytes)

        table = TypeLookupTable.create(dex)
        self.assertEqual(len(table), 16)
        self.assertEqual(table.mask_bits, 4)

        for expected_idx, c_desc in enumerate(classes):
            self.assertEqual(table.lookup(c_desc), expected_idx)

        self.assertIsNone(table.lookup("Lcom/example/TestClass99;"))

    def test_lookup_in_empty_table(self) -> None:
        """Verify lookup on an empty TypeLookupTable returns None."""
        raw_empty = b"\x00" * 8
        dex_bytes = _make_dex(["LTestClass;"])
        table = TypeLookupTable(dex_bytes, raw_empty)

        self.assertEqual(len(table), 1)
        self.assertIsNone(table.lookup("LTestClass;"))

    def test_type_lookup_table_sequence_protocol(self) -> None:
        """Verify TypeLookupTable Sequence protocol, indexing, slicing, and errors."""
        dex_bytes = _make_dex(["LTestClass;"])
        dex = DexFile(dex_bytes)
        table = TypeLookupTable.create(dex)

        self.assertEqual(len(table), 1)
        entry0 = table[0]
        self.assertIsInstance(entry0, TypeLookupTableEntry)

        # Negative index
        entry_neg = table[-1]
        self.assertEqual(entry_neg, entry0)

        # Slicing
        slice_tuple = table[:]
        self.assertIsInstance(slice_tuple, tuple)
        self.assertEqual(len(slice_tuple), 1)

        # Index out of bounds
        with self.assertRaises(IndexError):
            _ = table[1]
        with self.assertRaises(IndexError):
            _ = table[-2]

        # Invalid raw_data size (not multiple of 8)
        with self.assertRaises(ValueError) as ctx:
            TypeLookupTable(dex_bytes, b"\x00" * 7)
        self.assertIn("multiple of 8", str(ctx.exception))

        # Invalid entry count (not a power of two)
        # 24 bytes = 3 entries (not power of 2)
        with self.assertRaises(ValueError) as ctx:
            TypeLookupTable(dex_bytes, b"\x00" * 24)
        self.assertIn("power of two", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
