"""Unit tests for generic integer types and sentinels in dexbuf.types."""

import unittest
from typing import Any

from dexbuf import NO_INDEX, NO_OFFSET, Count, Idx, Offset
from dexbuf.types import NO_INDEX as TypesNO_INDEX
from dexbuf.types import NO_OFFSET as TypesNO_OFFSET
from dexbuf.types import Count as TypesCount
from dexbuf.types import Idx as TypesIdx
from dexbuf.types import Offset as TypesOffset


class DummyItem:
    """Dummy class used as a type parameter in tests."""


class TestTypesRuntime(unittest.TestCase):
    def test_reexports(self) -> None:
        """Verify exports match between dexbuf and dexbuf.types."""
        self.assertIs(Idx, TypesIdx)
        self.assertIs(Offset, TypesOffset)
        self.assertIs(Count, TypesCount)
        self.assertIs(NO_INDEX, TypesNO_INDEX)
        self.assertIs(NO_OFFSET, TypesNO_OFFSET)

    def test_native_int_type(self) -> None:
        """Verify that instances evaluate directly to native Python ints."""
        id_val = Idx(42)
        offset_val = Offset(0x10)
        count_val = Count(5)

        self.assertIs(type(id_val), int)
        self.assertIs(type(offset_val), int)
        self.assertIs(type(count_val), int)

    def test_generic_subscripting(self) -> None:
        """Verify generic subscripting Idx[T](val) returns native int directly."""
        id_typed = Idx[DummyItem](100)
        offset_typed = Offset[DummyItem](0x200)
        count_typed = Count[DummyItem](10)

        self.assertIs(type(id_typed), int)
        self.assertIs(type(offset_typed), int)
        self.assertIs(type(count_typed), int)

        self.assertEqual(id_typed, 100)
        self.assertEqual(offset_typed, 0x200)
        self.assertEqual(count_typed, 10)

    def test_buffer_slicing(self) -> None:
        """Verify buffer slicing protocol works without type conversion."""
        buf = b"Hello, DEX Buffer protocol!"
        offset = Offset[DummyItem](7)
        count = Count[DummyItem](10)

        # Direct slicing with Offset and Count
        slice_result = buf[offset : offset + count]
        self.assertEqual(slice_result, b"DEX Buffer")

        # Memoryview slicing
        mv = memoryview(buf)
        mv_slice = mv[offset : offset + count]
        self.assertEqual(mv_slice.tobytes(), b"DEX Buffer")

    def test_sentinels(self) -> None:
        """Verify sentinel values match expected integer values and types."""
        self.assertEqual(NO_INDEX, 0xFFFF_FFFF)
        self.assertEqual(NO_OFFSET, 0)

        self.assertIs(type(NO_INDEX), int)
        self.assertIs(type(NO_OFFSET), int)

    def test_union_with_none(self) -> None:
        """Verify Idx[T] | None, Offset[T] | None, Count[T] | None compatibility."""
        maybe_id: Idx[DummyItem] | None = Idx[DummyItem](1) if True else None
        maybe_offset: Offset[Any] | None = None
        maybe_count: Count[DummyItem] | None = Count(0)

        self.assertEqual(maybe_id, 1)
        self.assertIsNone(maybe_offset)
        self.assertEqual(maybe_count, 0)


if __name__ == "__main__":
    unittest.main()
