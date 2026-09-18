"""Unit tests for instruction payloads and IOP parsing in dexbuf."""

import unittest

from dexbuf.cursor import Cursor
from dexbuf.instructions import (
    FillArrayDataPayload,
    Move,
    PackedSwitchPayload,
    SparseSwitchPayload,
    parse_iop,
)
from dexbuf.types import BranchOffset, Reg


class TestInstructionPayloads(unittest.TestCase):
    def test_packed_switch_payload(self) -> None:
        targets = (BranchOffset(10), BranchOffset(20), BranchOffset(-5))
        payload = PackedSwitchPayload(first_key=-1, targets=targets)
        raw = payload.to_bytes()
        self.assertEqual(len(raw), 8 + len(targets) * 4)

        parsed = PackedSwitchPayload.from_cursor(Cursor(raw))
        self.assertEqual(parsed.first_key, -1)
        self.assertEqual(parsed.targets, targets)
        self.assertEqual(parsed, payload)

    def test_sparse_switch_payload(self) -> None:
        keys = (10, 20, 30, 100)
        targets = (BranchOffset(5), BranchOffset(15), BranchOffset(25), BranchOffset(35))
        payload = SparseSwitchPayload(keys=keys, targets=targets)
        raw = payload.to_bytes()
        self.assertEqual(len(raw), 4 + len(keys) * 8)

        parsed = SparseSwitchPayload.from_cursor(Cursor(raw))
        self.assertEqual(parsed.keys, keys)
        self.assertEqual(parsed.targets, targets)
        self.assertEqual(parsed, payload)

    def test_fill_array_data_payload_even_bytes(self) -> None:
        data = b"\x01\x02\x03\x04"  # 4 bytes (even)
        payload = FillArrayDataPayload(element_width=2, size=2, data=data)
        raw = payload.to_bytes()
        self.assertEqual(len(raw), 8 + 4)

        parsed = FillArrayDataPayload.from_cursor(Cursor(raw))
        self.assertEqual(parsed.element_width, 2)
        self.assertEqual(parsed.size, 2)
        self.assertEqual(parsed.data, data)
        self.assertEqual(parsed, payload)

    def test_fill_array_data_payload_odd_bytes_alignment(self) -> None:
        data = b"\x01\x02\x03"  # 3 bytes (odd)
        payload = FillArrayDataPayload(element_width=1, size=3, data=data)
        raw = payload.to_bytes()
        # Header (8) + data (3) + padding (1) = 12 bytes
        self.assertEqual(len(raw), 12)
        self.assertTrue(raw.endswith(b"\x00"))

        cursor = Cursor(raw)
        parsed = FillArrayDataPayload.from_cursor(cursor)
        self.assertEqual(parsed.element_width, 1)
        self.assertEqual(parsed.size, 3)
        self.assertEqual(parsed.data, data)
        self.assertEqual(cursor.offset, len(raw))

    def test_parse_iop_dispatch(self) -> None:
        # Instruction
        move = Move(a=Reg(1), b=Reg(2))
        iop_instr = parse_iop(Cursor(move.to_bytes()))
        self.assertIsInstance(iop_instr, Move)
        self.assertEqual(iop_instr, move)

        # Packed switch payload
        ps = PackedSwitchPayload(first_key=0, targets=(BranchOffset(12),))
        iop_ps = parse_iop(Cursor(ps.to_bytes()))
        self.assertIsInstance(iop_ps, PackedSwitchPayload)
        self.assertEqual(iop_ps, ps)

        # Sparse switch payload
        ss = SparseSwitchPayload(keys=(1,), targets=(BranchOffset(4),))
        iop_ss = parse_iop(Cursor(ss.to_bytes()))
        self.assertIsInstance(iop_ss, SparseSwitchPayload)
        self.assertEqual(iop_ss, ss)

        # Fill array data payload
        fad = FillArrayDataPayload(element_width=4, size=1, data=b"\x00\x00\x00\x00")
        iop_fad = parse_iop(Cursor(fad.to_bytes()))
        self.assertIsInstance(iop_fad, FillArrayDataPayload)
        self.assertEqual(iop_fad, fad)


if __name__ == "__main__":
    unittest.main()
