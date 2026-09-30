"""Unit tests for concrete Dalvik instructions and dispatch table."""

import unittest
from dataclasses import FrozenInstanceError

from dexbuf import Opcode
from dexbuf.cursor import Cursor
from dexbuf.instructions import parse_iop
from dexbuf.instructions.definitions import (
    OPCODE_MAP,
    AddInt,
    Const,
    Const4,
    ConstClass,
    ConstString,
    Goto,
    IfEq,
    InvokePolymorphic,
    InvokePolymorphicRange,
    Nop,
    PackedSwitch,
    Return,
    ReturnObject,
    ReturnVoid,
    ReturnWide,
    SparseSwitch,
    Throw,
    get_id,
    get_literal,
    has_id,
    has_literal,
    is_branch,
    is_conditional_branch,
    is_return,
    is_switch,
    is_throw,
    is_unconditional_branch,
    parse_instruction,
)
from dexbuf.items import StringIdItem, TypeIdItem
from dexbuf.types import ArgumentCount, BranchOffset, Idx, Literal, Reg


class TestInstructionDefinitions(unittest.TestCase):
    def test_opcode_map_coverage(self) -> None:
        """Verify OPCODE_MAP maps expected opcodes to concrete instruction classes."""
        self.assertIn(Opcode.NOP, OPCODE_MAP)
        self.assertIs(OPCODE_MAP[Opcode.NOP], Nop)
        self.assertIs(OPCODE_MAP[Opcode.RETURN_VOID], ReturnVoid)
        self.assertIs(OPCODE_MAP[Opcode.CONST_STRING], ConstString)
        self.assertIs(OPCODE_MAP[Opcode.ADD_INT], AddInt)
        self.assertIs(OPCODE_MAP[Opcode.INVOKE_POLYMORPHIC], InvokePolymorphic)
        self.assertIs(OPCODE_MAP[Opcode.INVOKE_POLYMORPHIC_RANGE], InvokePolymorphicRange)

    def test_immutability(self) -> None:
        """Verify concrete instructions are frozen dataclasses."""
        inst = Const4(a=Reg(1), b=Literal(5))
        with self.assertRaises(FrozenInstanceError):
            inst.a = Reg(2)  # type: ignore[misc]

    def test_parse_instruction(self) -> None:
        """Verify parse_instruction correctly parses raw bytes using OPCODE_MAP."""
        # Nop
        raw_nop = Nop().to_bytes()
        parsed_nop = parse_instruction(Cursor(raw_nop))
        self.assertIsInstance(parsed_nop, Nop)
        self.assertEqual(parsed_nop.OPCODE, Opcode.NOP)

        # Const
        raw_const = Const(a=Reg(3), b=Literal(42)).to_bytes()
        parsed_const = parse_instruction(Cursor(raw_const))
        self.assertIsInstance(parsed_const, Const)
        self.assertEqual(parsed_const.a, 3)
        self.assertEqual(parsed_const.b, 42)

        # InvokePolymorphic
        inst_poly = InvokePolymorphic(
            a=ArgumentCount(2),
            b=Idx(10),
            c=Reg(1),
            d=Reg(2),
            e=Reg(0),
            f=Reg(0),
            g=Reg(0),
            proto=Idx(20),
        )
        raw_poly = inst_poly.to_bytes()
        parsed_poly = parse_instruction(Cursor(raw_poly))
        self.assertIsInstance(parsed_poly, InvokePolymorphic)
        self.assertEqual(parsed_poly, inst_poly)

        # InvokePolymorphicRange
        inst_poly_range = InvokePolymorphicRange(
            a=ArgumentCount(5),
            b=Idx(100),
            c=Reg(2),
            proto=Idx(200),
        )
        raw_poly_range = inst_poly_range.to_bytes()
        parsed_poly_range = parse_instruction(Cursor(raw_poly_range))
        self.assertIsInstance(parsed_poly_range, InvokePolymorphicRange)
        self.assertEqual(parsed_poly_range, inst_poly_range)

    def test_parse_instruction_invalid_opcode(self) -> None:
        """Verify parse_instruction raises ValueError on unknown opcode."""
        # 0xE3 is unallocated in standard Dalvik
        raw = b"\xe3\x00"
        with self.assertRaises(ValueError):
            parse_instruction(Cursor(raw))

    def test_parse_iop_with_instruction(self) -> None:
        """Verify parse_iop delegates to parse_instruction for standard instructions."""
        raw_ret = ReturnVoid().to_bytes()
        iop = parse_iop(Cursor(raw_ret))
        self.assertIsInstance(iop, ReturnVoid)
        self.assertEqual(iop, ReturnVoid())

    def test_has_id_and_get_id(self) -> None:
        cs = ConstString(a=Reg(1), b=Idx[StringIdItem](42))
        cc = ConstClass(a=Reg(2), b=Idx[TypeIdItem](99))
        nop = Nop()

        self.assertTrue(has_id(cs))
        self.assertTrue(has_id(cs, StringIdItem))
        self.assertFalse(has_id(cs, TypeIdItem))
        self.assertEqual(get_id(cs), 42)
        self.assertEqual(get_id(cs, StringIdItem), 42)
        self.assertIsNone(get_id(cs, TypeIdItem))

        self.assertTrue(has_id(cc))
        self.assertTrue(has_id(cc, TypeIdItem))
        self.assertFalse(has_id(cc, StringIdItem))
        self.assertEqual(get_id(cc), 99)
        self.assertEqual(get_id(cc, TypeIdItem), 99)
        self.assertIsNone(get_id(cc, StringIdItem))

        self.assertFalse(has_id(nop))
        self.assertFalse(has_id(nop, StringIdItem))
        self.assertIsNone(get_id(nop))
        self.assertIsNone(get_id(nop, StringIdItem))

    def test_branch_guards(self) -> None:
        goto = Goto(a=BranchOffset(-5))
        ifeq = IfEq(a=Reg(1), b=Reg(2), c=BranchOffset(10))
        nop = Nop()

        self.assertTrue(is_branch(goto))
        self.assertTrue(is_branch(ifeq))
        self.assertFalse(is_branch(nop))

        self.assertTrue(is_unconditional_branch(goto))
        self.assertFalse(is_unconditional_branch(ifeq))
        self.assertFalse(is_unconditional_branch(nop))

        self.assertTrue(is_conditional_branch(ifeq))
        self.assertFalse(is_conditional_branch(goto))
        self.assertFalse(is_conditional_branch(nop))

    def test_literal_guards(self) -> None:
        c4 = Const4(a=Reg(1), b=Literal(3))
        nop = Nop()

        self.assertTrue(has_literal(c4))
        self.assertEqual(get_literal(c4), 3)

        self.assertFalse(has_literal(nop))
        self.assertIsNone(get_literal(nop))

    def test_control_flow_guards(self) -> None:
        rv = ReturnVoid()
        ret = Return(a=Reg(1))
        rw = ReturnWide(a=Reg(1))
        ro = ReturnObject(a=Reg(1))
        th = Throw(a=Reg(1))
        ps = PackedSwitch(a=Reg(1), b=BranchOffset(20))
        ss = SparseSwitch(a=Reg(1), b=BranchOffset(20))
        nop = Nop()

        self.assertTrue(is_return(rv))
        self.assertTrue(is_return(ret))
        self.assertTrue(is_return(rw))
        self.assertTrue(is_return(ro))
        self.assertFalse(is_return(nop))

        self.assertTrue(is_throw(th))
        self.assertFalse(is_throw(nop))

        self.assertTrue(is_switch(ps))
        self.assertTrue(is_switch(ss))
        self.assertFalse(is_switch(nop))


if __name__ == "__main__":
    unittest.main()
