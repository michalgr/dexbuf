"""Unit tests for Dalvik instruction formats (dexbuf.instructions.formats)."""

import unittest

from dexbuf.cursor import Cursor
from dexbuf.instructions.definitions import (
    AddInt,
    AddIntLit8,
    Const,
    Const4,
    ConstHigh16,
    ConstString,
    ConstWide,
    ConstWide16,
    ConstWideHigh16,
    Goto,
    Goto16,
    Goto32,
    IfEq,
    IfEqz,
    Iget,
    InvokePolymorphic,
    InvokePolymorphicRange,
    InvokeVirtual,
    InvokeVirtualRange,
    Move,
    Move16,
    MoveFrom16,
    Nop,
    Return,
)
from dexbuf.instructions.formats import (
    Format4rcc,
    Format45cc,
    HasId,
    HasLiteral,
    HasTarget,
)
from dexbuf.items import FieldIdItem, StringIdItem
from dexbuf.types import ArgumentCount, BranchOffset, Hat, Idx, Literal, Reg


class TestInstructionFormats(unittest.TestCase):
    def test_format10x(self) -> None:
        inst = Nop()
        self.assertEqual(inst.code_units, 1)
        raw = inst.to_bytes()
        self.assertEqual(raw, b"\x00\x00")
        parsed = Nop.from_cursor(Cursor(raw))
        self.assertEqual(parsed, inst)

    def test_format12x(self) -> None:
        inst = Move(a=Reg(3), b=Reg(15))
        self.assertEqual(inst.code_units, 1)
        raw = inst.to_bytes()
        self.assertEqual(raw, b"\x01\xf3")
        parsed = Move.from_cursor(Cursor(raw))
        self.assertEqual(parsed.a, 3)
        self.assertEqual(parsed.b, 15)
        self.assertIsInstance(parsed.a, int)
        self.assertEqual(parsed, inst)

    def test_format11n_sign_extension(self) -> None:
        # Positive 4-bit literal
        pos = Const4(a=Reg(2), b=Literal(7))
        self.assertEqual(pos.code_units, 1)
        raw_pos = pos.to_bytes()
        self.assertEqual(raw_pos, b"\x12\x72")
        parsed_pos = Const4.from_cursor(Cursor(raw_pos))
        self.assertEqual(parsed_pos.a, 2)
        self.assertEqual(parsed_pos.b, 7)

        # Negative 4-bit literal (-5)
        neg = Const4(a=Reg(1), b=Literal(-5))
        raw_neg = neg.to_bytes()
        self.assertEqual(raw_neg, b"\x12\xb1")  # -5 in 4-bit is 0xB (11)
        parsed_neg = Const4.from_cursor(Cursor(raw_neg))
        self.assertEqual(parsed_neg.a, 1)
        self.assertEqual(parsed_neg.b, -5)

    def test_format11x(self) -> None:
        inst = Return(a=Reg(254))
        self.assertEqual(inst.code_units, 1)
        raw = inst.to_bytes()
        self.assertEqual(raw, b"\x0f\xfe")
        parsed = Return.from_cursor(Cursor(raw))
        self.assertEqual(parsed.a, 254)
        self.assertEqual(parsed, inst)

    def test_format10t(self) -> None:
        inst = Goto(a=BranchOffset(-10))
        self.assertEqual(inst.code_units, 1)
        raw = inst.to_bytes()
        parsed = Goto.from_cursor(Cursor(raw))
        self.assertEqual(parsed.a, -10)
        self.assertEqual(parsed, inst)

    def test_format20t(self) -> None:
        inst = Goto16(a=BranchOffset(-1000))
        self.assertEqual(inst.code_units, 2)
        raw = inst.to_bytes()
        parsed = Goto16.from_cursor(Cursor(raw))
        self.assertEqual(parsed.a, -1000)
        self.assertEqual(parsed, inst)

    def test_format22x(self) -> None:
        inst = MoveFrom16(a=Reg(12), b=Reg(3000))
        self.assertEqual(inst.code_units, 2)
        raw = inst.to_bytes()
        parsed = MoveFrom16.from_cursor(Cursor(raw))
        self.assertEqual(parsed.a, 12)
        self.assertEqual(parsed.b, 3000)
        self.assertEqual(parsed, inst)

    def test_format21t(self) -> None:
        inst = IfEqz(a=Reg(5), b=BranchOffset(-200))
        self.assertEqual(inst.code_units, 2)
        raw = inst.to_bytes()
        parsed = IfEqz.from_cursor(Cursor(raw))
        self.assertEqual(parsed.a, 5)
        self.assertEqual(parsed.b, -200)
        self.assertEqual(parsed, inst)

    def test_format21h(self) -> None:
        # ConstHigh16 (SHIFT = 2)
        inst_h16 = ConstHigh16(a=Reg(4), b=Hat(0x1234_0000))
        self.assertEqual(inst_h16.code_units, 2)
        raw_h16 = inst_h16.to_bytes()
        parsed_h16 = ConstHigh16.from_cursor(Cursor(raw_h16))
        self.assertEqual(parsed_h16.a, 4)
        self.assertEqual(parsed_h16.b, 0x1234_0000)
        self.assertEqual(parsed_h16, inst_h16)

        # ConstWideHigh16 (SHIFT = 6)
        inst_wh16 = ConstWideHigh16(a=Reg(7), b=Hat(0x5678_0000_0000_0000))
        self.assertEqual(inst_wh16.code_units, 2)
        raw_wh16 = inst_wh16.to_bytes()
        parsed_wh16 = ConstWideHigh16.from_cursor(Cursor(raw_wh16))
        self.assertEqual(parsed_wh16.a, 7)
        self.assertEqual(parsed_wh16.b, 0x5678_0000_0000_0000)
        self.assertEqual(parsed_wh16, inst_wh16)

    def test_format21c(self) -> None:
        inst = ConstString(a=Reg(2), b=Idx[StringIdItem](0x1234))
        self.assertEqual(inst.code_units, 2)
        raw = inst.to_bytes()
        parsed = ConstString.from_cursor(Cursor(raw))
        self.assertEqual(parsed.a, 2)
        self.assertEqual(parsed.b, 0x1234)
        self.assertEqual(parsed, inst)

    def test_format23x(self) -> None:
        inst = AddInt(a=Reg(1), b=Reg(2), c=Reg(3))
        self.assertEqual(inst.code_units, 2)
        raw = inst.to_bytes()
        parsed = AddInt.from_cursor(Cursor(raw))
        self.assertEqual(parsed.a, 1)
        self.assertEqual(parsed.b, 2)
        self.assertEqual(parsed.c, 3)
        self.assertEqual(parsed, inst)

    def test_format22b(self) -> None:
        inst = AddIntLit8(a=Reg(10), b=Reg(11), c=Literal(-42))
        self.assertEqual(inst.code_units, 2)
        raw = inst.to_bytes()
        parsed = AddIntLit8.from_cursor(Cursor(raw))
        self.assertEqual(parsed.a, 10)
        self.assertEqual(parsed.b, 11)
        self.assertEqual(parsed.c, -42)
        self.assertEqual(parsed, inst)

    def test_format22t(self) -> None:
        inst = IfEq(a=Reg(3), b=Reg(4), c=BranchOffset(50))
        self.assertEqual(inst.code_units, 2)
        raw = inst.to_bytes()
        parsed = IfEq.from_cursor(Cursor(raw))
        self.assertEqual(parsed.a, 3)
        self.assertEqual(parsed.b, 4)
        self.assertEqual(parsed.c, 50)
        self.assertEqual(parsed, inst)

    def test_format22c(self) -> None:
        inst = Iget(a=Reg(1), b=Reg(2), c=Idx[FieldIdItem](0x00FF))
        self.assertEqual(inst.code_units, 2)
        raw = inst.to_bytes()
        parsed = Iget.from_cursor(Cursor(raw))
        self.assertEqual(parsed.a, 1)
        self.assertEqual(parsed.b, 2)
        self.assertEqual(parsed.c, 0x00FF)
        self.assertEqual(parsed, inst)

    def test_format30t(self) -> None:
        inst = Goto32(a=BranchOffset(-100000))
        self.assertEqual(inst.code_units, 3)
        raw = inst.to_bytes()
        parsed = Goto32.from_cursor(Cursor(raw))
        self.assertEqual(parsed.a, -100000)
        self.assertEqual(parsed, inst)

    def test_format32x(self) -> None:
        inst = Move16(a=Reg(1000), b=Reg(2000))
        self.assertEqual(inst.code_units, 3)
        raw = inst.to_bytes()
        parsed = Move16.from_cursor(Cursor(raw))
        self.assertEqual(parsed.a, 1000)
        self.assertEqual(parsed.b, 2000)
        self.assertEqual(parsed, inst)

    def test_format31i(self) -> None:
        inst = Const(a=Reg(5), b=Literal(-12345678))
        self.assertEqual(inst.code_units, 3)
        raw = inst.to_bytes()
        parsed = Const.from_cursor(Cursor(raw))
        self.assertEqual(parsed.a, 5)
        self.assertEqual(parsed.b, -12345678)
        self.assertEqual(parsed, inst)

    def test_format35c(self) -> None:
        inst = InvokeVirtual(
            a=ArgumentCount(4),
            b=Idx(0x1000),
            c=Reg(1),
            d=Reg(2),
            e=Reg(3),
            f=Reg(4),
            g=Reg(0),
        )
        self.assertEqual(inst.code_units, 3)
        raw = inst.to_bytes()
        parsed = InvokeVirtual.from_cursor(Cursor(raw))
        self.assertEqual(parsed.a, 4)
        self.assertEqual(parsed.b, 0x1000)
        self.assertEqual(parsed.c, 1)
        self.assertEqual(parsed.d, 2)
        self.assertEqual(parsed.e, 3)
        self.assertEqual(parsed.f, 4)
        self.assertEqual(parsed.g, 0)
        self.assertEqual(parsed, inst)

    def test_format3rc(self) -> None:
        inst = InvokeVirtualRange(
            a=ArgumentCount(10),
            b=Idx(0x0500),
            c=Reg(12),
        )
        self.assertEqual(inst.code_units, 3)
        raw = inst.to_bytes()
        parsed = InvokeVirtualRange.from_cursor(Cursor(raw))
        self.assertEqual(parsed.a, 10)
        self.assertEqual(parsed.b, 0x0500)
        self.assertEqual(parsed.c, 12)
        self.assertEqual(parsed, inst)

    def test_format51l(self) -> None:
        inst = ConstWide(a=Reg(8), b=Literal(-0x1234_5678_9ABC_DEF0))
        self.assertEqual(inst.code_units, 5)
        raw = inst.to_bytes()
        parsed = ConstWide.from_cursor(Cursor(raw))
        self.assertEqual(parsed.a, 8)
        self.assertEqual(parsed.b, -0x1234_5678_9ABC_DEF0)
        self.assertEqual(parsed, inst)

    def test_format45cc(self) -> None:
        inst = InvokePolymorphic(
            a=ArgumentCount(3),
            b=Idx(0x1234),
            c=Reg(1),
            d=Reg(2),
            e=Reg(3),
            f=Reg(0),
            g=Reg(0),
            proto=Idx(0x5678),
        )
        self.assertIsInstance(inst, Format45cc)
        self.assertEqual(inst.code_units, 4)
        raw = inst.to_bytes()
        self.assertEqual(len(raw), 8)
        parsed = InvokePolymorphic.from_cursor(Cursor(raw))
        self.assertEqual(parsed.a, 3)
        self.assertEqual(parsed.b, 0x1234)
        self.assertEqual(parsed.c, 1)
        self.assertEqual(parsed.d, 2)
        self.assertEqual(parsed.e, 3)
        self.assertEqual(parsed.f, 0)
        self.assertEqual(parsed.g, 0)
        self.assertEqual(parsed.proto, 0x5678)
        self.assertEqual(parsed, inst)

    def test_format4rcc(self) -> None:
        inst = InvokePolymorphicRange(
            a=ArgumentCount(8),
            b=Idx(0x1234),
            c=Reg(4),
            proto=Idx(0x5678),
        )
        self.assertIsInstance(inst, Format4rcc)
        self.assertEqual(inst.code_units, 4)
        raw = inst.to_bytes()
        self.assertEqual(len(raw), 8)
        parsed = InvokePolymorphicRange.from_cursor(Cursor(raw))
        self.assertEqual(parsed.a, 8)
        self.assertEqual(parsed.b, 0x1234)
        self.assertEqual(parsed.c, 4)
        self.assertEqual(parsed.proto, 0x5678)
        self.assertEqual(parsed, inst)

    def test_protocols_has_id(self) -> None:
        inst_21c = ConstString(a=Reg(2), b=Idx[StringIdItem](0x1234))
        self.assertIsInstance(inst_21c, HasId)
        self.assertEqual(inst_21c.item_id, 0x1234)

        inst_22c = Iget(a=Reg(1), b=Reg(2), c=Idx[FieldIdItem](0x00FF))
        self.assertIsInstance(inst_22c, HasId)
        self.assertEqual(inst_22c.item_id, 0x00FF)

        inst_35c = InvokeVirtual(
            a=ArgumentCount(1),
            b=Idx(0x1000),
            c=Reg(1),
            d=Reg(0),
            e=Reg(0),
            f=Reg(0),
            g=Reg(0),
        )
        self.assertIsInstance(inst_35c, HasId)
        self.assertEqual(inst_35c.item_id, 0x1000)

        inst_3rc = InvokeVirtualRange(
            a=ArgumentCount(10),
            b=Idx(0x0500),
            c=Reg(12),
        )
        self.assertIsInstance(inst_3rc, HasId)
        self.assertEqual(inst_3rc.item_id, 0x0500)

        inst_45cc = InvokePolymorphic(
            a=ArgumentCount(1),
            b=Idx(0x1234),
            c=Reg(1),
            d=Reg(0),
            e=Reg(0),
            f=Reg(0),
            g=Reg(0),
            proto=Idx(0x5678),
        )
        self.assertIsInstance(inst_45cc, HasId)
        self.assertEqual(inst_45cc.item_id, 0x1234)

        inst_4rcc = InvokePolymorphicRange(
            a=ArgumentCount(8),
            b=Idx(0x1234),
            c=Reg(4),
            proto=Idx(0x5678),
        )
        self.assertIsInstance(inst_4rcc, HasId)
        self.assertEqual(inst_4rcc.item_id, 0x1234)

        self.assertNotIsInstance(Nop(), HasId)

    def test_protocols_has_target(self) -> None:
        inst_10t = Goto(a=BranchOffset(-10))
        self.assertIsInstance(inst_10t, HasTarget)
        self.assertEqual(inst_10t.target, -10)

        inst_20t = Goto16(a=BranchOffset(-1000))
        self.assertIsInstance(inst_20t, HasTarget)
        self.assertEqual(inst_20t.target, -1000)

        inst_30t = Goto32(a=BranchOffset(-100000))
        self.assertIsInstance(inst_30t, HasTarget)
        self.assertEqual(inst_30t.target, -100000)

        inst_21t = IfEqz(a=Reg(5), b=BranchOffset(-200))
        self.assertIsInstance(inst_21t, HasTarget)
        self.assertEqual(inst_21t.target, -200)

        inst_22t = IfEq(a=Reg(3), b=Reg(4), c=BranchOffset(50))
        self.assertIsInstance(inst_22t, HasTarget)
        self.assertEqual(inst_22t.target, 50)

        self.assertNotIsInstance(Nop(), HasTarget)

    def test_protocols_has_literal(self) -> None:
        inst_11n = Const4(a=Reg(2), b=Literal(7))
        self.assertIsInstance(inst_11n, HasLiteral)
        self.assertEqual(inst_11n.literal, 7)

        inst_21s = ConstWide16(a=Reg(1), b=Literal(-500))
        self.assertIsInstance(inst_21s, HasLiteral)
        self.assertEqual(inst_21s.literal, -500)

        inst_21h = ConstHigh16(a=Reg(4), b=Hat(0x1234_0000))
        self.assertIsInstance(inst_21h, HasLiteral)
        self.assertEqual(inst_21h.literal, 0x1234_0000)

        inst_31i = Const(a=Reg(5), b=Literal(-12345678))
        self.assertIsInstance(inst_31i, HasLiteral)
        self.assertEqual(inst_31i.literal, -12345678)

        inst_51l = ConstWide(a=Reg(8), b=Literal(-100000000000))
        self.assertIsInstance(inst_51l, HasLiteral)
        self.assertEqual(inst_51l.literal, -100000000000)

        inst_22b = AddIntLit8(a=Reg(10), b=Reg(11), c=Literal(-42))
        self.assertIsInstance(inst_22b, HasLiteral)
        self.assertEqual(inst_22b.literal, -42)

        self.assertNotIsInstance(Nop(), HasLiteral)


if __name__ == "__main__":
    unittest.main()
