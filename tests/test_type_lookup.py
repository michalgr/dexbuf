"""Unit tests for TypeLookupTable and TypeLookupTableEntry."""

import unittest
from typing import Any

from dexbuf.cursor import Cursor
from dexbuf.dex import DexFile
from dexbuf.type_lookup import TypeLookupTable, TypeLookupTableBuilder, TypeLookupTableEntry


def create_multi_class_dex(class_descriptors: list[str]) -> bytes:
    """Helper to construct a DEX file with specified class descriptors."""
    from dexbuf import (
        DEX_FILE_MAGIC,
        ENDIAN_CONSTANT,
        NO_INDEX,
        NO_OFFSET,
        ClassDefItem,
        Count,
        FieldIdItem,
        HeaderItem,
        Idx,
        MethodIdItem,
        Offset,
        ProtoIdItem,
        StringDataItem,
        StringIdItem,
        TypeIdItem,
    )

    header_size = 0x70

    # Collect unique string list sorted
    strings = sorted({*class_descriptors, "Ljava/lang/Object;"})

    string_data_bytes = bytearray()
    string_data_offsets: list[int] = []

    # Calculate offset for string data
    type_ids_size = len(strings)
    class_defs_size = len(class_descriptors)

    data_start_off = header_size + 4 * len(strings) + 4 * type_ids_size + 32 * class_defs_size
    data_off = data_start_off

    for s in strings:
        item = StringDataItem.from_str(s)
        string_data_offsets.append(data_off)
        b = item.to_bytes()
        string_data_bytes.extend(b)
        data_off += len(b)

    string_ids_off = header_size
    string_ids_bytes = b"".join(
        StringIdItem(string_data_off=Offset[StringDataItem](off)).to_bytes()
        for off in string_data_offsets
    )

    type_ids_off = string_ids_off + len(string_ids_bytes)
    type_ids = [TypeIdItem(descriptor_idx=Idx[StringIdItem](i)) for i in range(len(strings))]
    type_ids_bytes = b"".join(t.to_bytes() for t in type_ids)

    class_defs_off = type_ids_off + len(type_ids_bytes)

    # Class defs
    object_type_idx = strings.index("Ljava/lang/Object;")
    class_defs = []
    for c_desc in class_descriptors:
        c_type_idx = strings.index(c_desc)
        class_defs.append(
            ClassDefItem(
                class_idx=Idx[TypeIdItem](c_type_idx),
                access_flags=0x0001,
                superclass_idx=Idx[TypeIdItem](object_type_idx),
                interfaces_off=NO_OFFSET,
                source_file_idx=NO_INDEX,
                annotations_off=NO_OFFSET,
                class_data_off=NO_OFFSET,
                static_values_off=NO_OFFSET,
            )
        )
    class_defs_bytes = b"".join(cd.to_bytes() for cd in class_defs)

    total_file_size = data_off

    header = HeaderItem(
        magic=DEX_FILE_MAGIC,
        checksum=0,
        signature=b"\x00" * 20,
        file_size=total_file_size,
        header_size=header_size,
        endian_tag=ENDIAN_CONSTANT,
        link_size=0,
        link_off=NO_OFFSET,
        map_off=NO_OFFSET,
        string_ids_size=Count[StringIdItem](len(strings)),
        string_ids_off=Offset[StringIdItem](string_ids_off),
        type_ids_size=Count[TypeIdItem](type_ids_size),
        type_ids_off=Offset[TypeIdItem](type_ids_off),
        proto_ids_size=Count[ProtoIdItem](0),
        proto_ids_off=NO_OFFSET,
        field_ids_size=Count[FieldIdItem](0),
        field_ids_off=NO_OFFSET,
        method_ids_size=Count[MethodIdItem](0),
        method_ids_off=NO_OFFSET,
        class_defs_size=Count[ClassDefItem](class_defs_size),
        class_defs_off=Offset[ClassDefItem](class_defs_off),
        data_size=total_file_size - data_start_off,
        data_off=Offset[Any](data_start_off),
    )

    buf = bytearray(header.to_bytes())
    buf.extend(string_ids_bytes)
    buf.extend(type_ids_bytes)
    buf.extend(class_defs_bytes)
    buf.extend(string_data_bytes)

    return bytes(buf)


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

    def test_entry_pack_and_round_trip(self) -> None:
        """Verify TypeLookupTableEntry.pack static method and round-trip parsing."""
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

        packed_bytes = TypeLookupTableEntry.pack(
            str_offset=str_offset,
            class_def_idx=class_def_idx,
            hash_val=hash_val,
            next_pos_delta=next_pos_delta,
            mask_bits=mask_bits,
        )

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
        dex_bytes = create_multi_class_dex([])
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
        dex_bytes = create_multi_class_dex(["LTestClass;"])
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
        dex_bytes = create_multi_class_dex(["LClassA;", "LClassB;"])
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
        dex_bytes = create_multi_class_dex(["LClassA;", "LClassB;"])
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
        dex_bytes = create_multi_class_dex(classes)
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
        dex_bytes = create_multi_class_dex(classes)
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
        dex_bytes = create_multi_class_dex(["LTestClass;"])
        table = TypeLookupTable(dex_bytes, raw_empty)

        self.assertEqual(len(table), 1)
        self.assertIsNone(table.lookup("LTestClass;"))

    def test_type_lookup_table_sequence_protocol(self) -> None:
        """Verify TypeLookupTable Sequence protocol, indexing, slicing, and errors."""
        dex_bytes = create_multi_class_dex(["LTestClass;"])
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
