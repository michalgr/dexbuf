"""Unit tests for Dalvik instruction payloads (dexbuf.instructions.payloads)."""

import unittest
from dataclasses import FrozenInstanceError

from dexbuf.cursor import Cursor
from dexbuf.instructions import parse_iop
from dexbuf.instructions.payloads import (
    FillArrayDataPayload,
    PackedSwitchPayload,
    SparseSwitchPayload,
)
from dexbuf.types import BranchOffset


class TestInstructionPayloads(unittest.TestCase):
    def test_packed_switch_payload(self) -> None:
        targets = (BranchOffset(10), BranchOffset(20), BranchOffset(-30))
        payload = PackedSwitchPayload(first_key=100, targets=targets)
        self.assertEqual(payload.code_units, 4 + 3 * 2)

        raw = payload.to_bytes()
        self.assertEqual(len(raw), payload.code_units * 2)

        parsed = PackedSwitchPayload.from_cursor(Cursor(raw))
        self.assertEqual(parsed.first_key, 100)
        self.assertEqual(parsed.targets, targets)
        self.assertEqual(parsed, payload)

    def test_packed_switch_payload_invalid_ident(self) -> None:
        raw = b"\x00\x00\x01\x00\x00\x00\x00\x00"
        with self.assertRaises(ValueError):
            PackedSwitchPayload.from_cursor(Cursor(raw))

    def test_sparse_switch_payload(self) -> None:
        keys = (10, 50, 100)
        targets = (BranchOffset(1000), BranchOffset(2000), BranchOffset(-500))
        payload = SparseSwitchPayload(keys=keys, targets=targets)
        self.assertEqual(payload.code_units, 2 + 3 * 2 + 3 * 2)

        raw = payload.to_bytes()
        self.assertEqual(len(raw), payload.code_units * 2)

        parsed = SparseSwitchPayload.from_cursor(Cursor(raw))
        self.assertEqual(parsed.keys, keys)
        self.assertEqual(parsed.targets, targets)
        self.assertEqual(parsed, payload)

    def test_sparse_switch_mismatch(self) -> None:
        payload = SparseSwitchPayload(keys=(1, 2), targets=(BranchOffset(10),))
        with self.assertRaises(ValueError):
            payload.to_bytes()

    def test_fill_array_data_payload_even(self) -> None:
        data = b"\x01\x02\x03\x04"
        payload = FillArrayDataPayload(element_width=1, size=4, data=data)
        self.assertEqual(payload.code_units, 4 + 2)

        raw = payload.to_bytes()
        self.assertEqual(len(raw), payload.code_units * 2)

        parsed = FillArrayDataPayload.from_cursor(Cursor(raw))
        self.assertEqual(parsed.element_width, 1)
        self.assertEqual(parsed.size, 4)
        self.assertEqual(parsed.data, data)
        self.assertEqual(parsed, payload)

    def test_fill_array_data_payload_odd_padding(self) -> None:
        # Odd byte count: 3 elements of width 1 = 3 bytes -> needs 1 alignment byte
        data = b"\x01\x02\x03"
        payload = FillArrayDataPayload(element_width=1, size=3, data=data)
        self.assertEqual(payload.code_units, 4 + 2)  # (3 + 1)//2 = 2

        raw = payload.to_bytes()
        self.assertEqual(len(raw), 12)  # 8 header + 3 data + 1 padding = 12 bytes

        cursor = Cursor(raw)
        parsed = FillArrayDataPayload.from_cursor(cursor)
        self.assertEqual(parsed.element_width, 1)
        self.assertEqual(parsed.size, 3)
        self.assertEqual(parsed.data, data)
        self.assertEqual(cursor.tell(), 12)  # verified cursor advanced past padding

    def test_parse_iop_payloads(self) -> None:
        packed = PackedSwitchPayload(first_key=0, targets=(BranchOffset(4),))
        raw_packed = packed.to_bytes()
        iop_packed = parse_iop(Cursor(raw_packed))
        self.assertIsInstance(iop_packed, PackedSwitchPayload)
        self.assertEqual(iop_packed, packed)

        sparse = SparseSwitchPayload(keys=(1,), targets=(BranchOffset(8),))
        raw_sparse = sparse.to_bytes()
        iop_sparse = parse_iop(Cursor(raw_sparse))
        self.assertIsInstance(iop_sparse, SparseSwitchPayload)
        self.assertEqual(iop_sparse, sparse)

        fill = FillArrayDataPayload(element_width=2, size=1, data=b"\x01\x02")
        raw_fill = fill.to_bytes()
        iop_fill = parse_iop(Cursor(raw_fill))
        self.assertIsInstance(iop_fill, FillArrayDataPayload)
        self.assertEqual(iop_fill, fill)

    def test_immutability(self) -> None:
        payload = PackedSwitchPayload(first_key=0, targets=())
        with self.assertRaises(FrozenInstanceError):
            payload.first_key = 10  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
