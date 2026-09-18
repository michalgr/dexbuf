"""Unit tests for Dalvik instruction formats in dexbuf.instructions.formats."""

import unittest
from dataclasses import FrozenInstanceError

from dexbuf.cursor import Cursor
from dexbuf.instructions.definitions import (
    CheckCast,
    Const4,
    Const16,
    ConstHigh16,
    ConstString,
    ConstStringJumbo,
    ConstWide,
    ConstWideHigh16,
    FilledNewArray,
    Goto,
    Goto16,
    Goto32,
    IfEq,
    InvokeVirtualRange,
    Move,
    MoveResult,
    Nop,
)
from dexbuf.items import MethodIdItem, StringIdItem, TypeIdItem
from dexbuf.types import ArgumentCount, BranchOffset, Hat, Idx, Literal, Reg


class TestInstructionFormats(unittest.TestCase):
    def test_format_10x(self) -> None:
        nop = Nop()
        raw = nop.to_bytes()
        self.assertEqual(raw, b"\x00\x00")
        parsed = Nop.from_cursor(Cursor(raw))
        self.assertEqual(parsed, nop)

    def test_format_12x_nibble_splitting(self) -> None:
        # op=MOVE (0x01), a=v3, b=v7 -> high byte = (7 << 4) | 3 = 0x73
        move = Move(a=Reg(3), b=Reg(7))
        raw = move.to_bytes()
        self.assertEqual(raw, b"\x01\x73")
        parsed = Move.from_cursor(Cursor(raw))
        self.assertEqual(parsed.a, 3)
        self.assertEqual(parsed.b, 7)
        self.assertEqual(parsed, move)

    def test_format_11n_sign_extension(self) -> None:
        # Test positive literal: b = 5 (+5), a = 2
        c4_pos = Const4(a=Reg(2), b=Literal(5))
        raw_pos = c4_pos.to_bytes()
        self.assertEqual(raw_pos, b"\x12\x52")
        parsed_pos = Const4.from_cursor(Cursor(raw_pos))
        self.assertEqual(parsed_pos.a, 2)
        self.assertEqual(parsed_pos.b, 5)

        # Test negative literal: b = -3 (4-bit binary 0xD = 13), a = 1
        c4_neg = Const4(a=Reg(1), b=Literal(-3))
        raw_neg = c4_neg.to_bytes()
        self.assertEqual(raw_neg, b"\x12\xd1")
        parsed_neg = Const4.from_cursor(Cursor(raw_neg))
        self.assertEqual(parsed_neg.a, 1)
        self.assertEqual(parsed_neg.b, -3)

    def test_format_11x(self) -> None:
        mr = MoveResult(a=Reg(15))
        raw = mr.to_bytes()
        self.assertEqual(raw, b"\x0a\x0f")
        parsed = MoveResult.from_cursor(Cursor(raw))
        self.assertEqual(parsed.a, 15)

    def test_format_10t(self) -> None:
        goto = Goto(a=BranchOffset(-5))
        raw = goto.to_bytes()
        self.assertEqual(raw, b"\x28\xfb")
        parsed = Goto.from_cursor(Cursor(raw))
        self.assertEqual(parsed.a, -5)

    def test_format_20t(self) -> None:
        goto16 = Goto16(a=BranchOffset(0x1234))
        raw = goto16.to_bytes()
        parsed = Goto16.from_cursor(Cursor(raw))
        self.assertEqual(parsed.a, 0x1234)
        self.assertEqual(raw, goto16.to_bytes())

    def test_format_21s(self) -> None:
        c16 = Const16(a=Reg(4), b=Literal(-1234))
        raw = c16.to_bytes()
        parsed = Const16.from_cursor(Cursor(raw))
        self.assertEqual(parsed.a, 4)
        self.assertEqual(parsed.b, -1234)

    def test_format_21h_shift(self) -> None:
        # ConstHigh16: SHIFT = 2
        ch16 = ConstHigh16(a=Reg(1), b=Hat(0x1234_0000))
        raw16 = ch16.to_bytes()
        parsed16 = ConstHigh16.from_cursor(Cursor(raw16))
        self.assertEqual(parsed16.a, 1)
        self.assertEqual(parsed16.b, 0x1234_0000)

        # ConstWideHigh16: SHIFT = 6
        cwh16 = ConstWideHigh16(a=Reg(2), b=Hat(0x1234_0000_0000_0000))
        raw_wide = cwh16.to_bytes()
        parsed_wide = ConstWideHigh16.from_cursor(Cursor(raw_wide))
        self.assertEqual(parsed_wide.a, 2)
        self.assertEqual(parsed_wide.b, 0x1234_0000_0000_0000)

    def test_format_21c(self) -> None:
        cs = ConstString(a=Reg(5), b=Idx[StringIdItem](0x1234))
        raw = cs.to_bytes()
        parsed = ConstString.from_cursor(Cursor(raw))
        self.assertEqual(parsed.a, 5)
        self.assertEqual(parsed.b, 0x1234)

        cc = CheckCast(a=Reg(1), b=Idx[TypeIdItem](0x00A0))
        parsed_cc = CheckCast.from_cursor(Cursor(cc.to_bytes()))
        self.assertEqual(parsed_cc.a, 1)
        self.assertEqual(parsed_cc.b, 0x00A0)

    def test_format_22t(self) -> None:
        ifeq = IfEq(a=Reg(1), b=Reg(2), c=BranchOffset(-10))
        raw = ifeq.to_bytes()
        parsed = IfEq.from_cursor(Cursor(raw))
        self.assertEqual(parsed.a, 1)
        self.assertEqual(parsed.b, 2)
        self.assertEqual(parsed.c, -10)

    def test_format_30t(self) -> None:
        g32 = Goto32(a=BranchOffset(0x1234_5678))
        raw = g32.to_bytes()
        parsed = Goto32.from_cursor(Cursor(raw))
        self.assertEqual(parsed.a, 0x1234_5678)

    def test_format_31c(self) -> None:
        csj = ConstStringJumbo(a=Reg(0), b=Idx[StringIdItem](0x1234_5678))
        raw = csj.to_bytes()
        parsed = ConstStringJumbo.from_cursor(Cursor(raw))
        self.assertEqual(parsed.a, 0)
        self.assertEqual(parsed.b, 0x1234_5678)

    def test_format_35c_nibbles(self) -> None:
        fna = FilledNewArray(
            a=ArgumentCount(3),
            b=Idx[TypeIdItem](0x4321),
            c=Reg(1),
            d=Reg(2),
            e=Reg(3),
            f=Reg(0),
            g=Reg(0),
        )
        raw = fna.to_bytes()
        parsed = FilledNewArray.from_cursor(Cursor(raw))
        self.assertEqual(parsed.a, 3)
        self.assertEqual(parsed.b, 0x4321)
        self.assertEqual(parsed.c, 1)
        self.assertEqual(parsed.d, 2)
        self.assertEqual(parsed.e, 3)
        self.assertEqual(parsed.f, 0)
        self.assertEqual(parsed.g, 0)

    def test_format_3rc(self) -> None:
        ivr = InvokeVirtualRange(a=ArgumentCount(10), b=Idx[MethodIdItem](0x0100), c=Reg(4))
        raw = ivr.to_bytes()
        parsed = InvokeVirtualRange.from_cursor(Cursor(raw))
        self.assertEqual(parsed.a, 10)
        self.assertEqual(parsed.b, 0x0100)
        self.assertEqual(parsed.c, 4)

    def test_format_51l(self) -> None:
        cw = ConstWide(a=Reg(2), b=Literal(-0x1234_5678_9ABC_DEF0))
        raw = cw.to_bytes()
        parsed = ConstWide.from_cursor(Cursor(raw))
        self.assertEqual(parsed.a, 2)
        self.assertEqual(parsed.b, -0x1234_5678_9ABC_DEF0)

    def test_immutability(self) -> None:
        move = Move(a=Reg(1), b=Reg(2))
        with self.assertRaises(FrozenInstanceError):
            move.a = Reg(3)  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
