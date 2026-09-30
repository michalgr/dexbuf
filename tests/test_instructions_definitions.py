"""Unit tests for concrete Dalvik instructions and dispatch table."""

import unittest
from dataclasses import FrozenInstanceError

from dexbuf import Opcode
from dexbuf.cursor import Cursor
from dexbuf.instructions import parse_iop
from dexbuf.instructions.definitions import (
    OPCODE_MAP,
    AddInt,
    AgetWide,
    AputWide,
    CmpLong,
    Const,
    Const4,
    ConstClass,
    ConstString,
    ConstWide,
    Goto,
    IfEq,
    IgetWide,
    InvokeCustom,
    InvokePolymorphic,
    InvokePolymorphicRange,
    InvokeVirtual,
    IputWide,
    LongToInt,
    MoveWide,
    Nop,
    PackedSwitch,
    Return,
    ReturnObject,
    ReturnVoid,
    ReturnWide,
    SgetWide,
    SparseSwitch,
    SputWide,
    Throw,
    get_id,
    has_id,
    is_branch,
    is_conditional_branch,
    is_return,
    is_switch,
    is_throw,
    is_unconditional_branch,
    parse_instruction,
)
from dexbuf.items import (
    CallSiteIdItem,
    FieldIdItem,
    MethodIdItem,
    StringIdItem,
    TypeIdItem,
)
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
        cs = ConstString(a=Reg(1), b=Idx[StringIdItem](10))
        cc = ConstClass(a=Reg(2), b=Idx[TypeIdItem](20))
        iv = InvokeVirtual(
            a=ArgumentCount(1),
            b=Idx[MethodIdItem](30),
            c=Reg(1),
            d=Reg(0),
            e=Reg(0),
            f=Reg(0),
            g=Reg(0),
        )
        ic = InvokeCustom(
            a=ArgumentCount(1),
            b=Idx[CallSiteIdItem](40),
            c=Reg(1),
            d=Reg(0),
            e=Reg(0),
            f=Reg(0),
            g=Reg(0),
        )
        nop = Nop()

        # StringIdItem
        self.assertTrue(has_id(cs, StringIdItem))
        self.assertEqual(get_id(cs, StringIdItem), 10)
        self.assertFalse(has_id(cs, TypeIdItem))
        self.assertIsNone(get_id(cs, TypeIdItem))

        # TypeIdItem
        self.assertTrue(has_id(cc, TypeIdItem))
        self.assertEqual(get_id(cc, TypeIdItem), 20)

        # MethodIdItem
        self.assertTrue(has_id(iv, MethodIdItem))
        self.assertEqual(get_id(iv, MethodIdItem), 30)

        # CallSiteIdItem
        self.assertTrue(has_id(ic, CallSiteIdItem))
        self.assertEqual(get_id(ic, CallSiteIdItem), 40)

        # Non-item instruction
        self.assertFalse(has_id(nop, StringIdItem))
        self.assertIsNone(get_id(nop, StringIdItem))

    def test_wide_register_expansions_across_families(self) -> None:
        # MoveWide
        mw = MoveWide(a=Reg(0), b=Reg(2))
        self.assertEqual(mw.wide_registers, (0, 2))
        self.assertEqual(mw.physical_read_registers, (2, 3))
        self.assertEqual(mw.physical_written_registers, (0, 1))

        # ConstWide
        cw = ConstWide(a=Reg(4), b=Literal(100))
        self.assertEqual(cw.wide_registers, (4,))
        self.assertEqual(cw.physical_written_registers, (4, 5))

        # CmpLong
        cmpl = CmpLong(a=Reg(0), b=Reg(2), c=Reg(4))
        self.assertEqual(cmpl.wide_registers, (2, 4))
        self.assertEqual(cmpl.physical_read_registers, (2, 3, 4, 5))
        self.assertEqual(cmpl.physical_written_registers, (0,))

        # LongToInt
        l2i = LongToInt(a=Reg(0), b=Reg(2))
        self.assertEqual(l2i.wide_registers, (2,))
        self.assertEqual(l2i.physical_read_registers, (2, 3))
        self.assertEqual(l2i.physical_written_registers, (0,))

        # AgetWide / AputWide
        agw = AgetWide(a=Reg(0), b=Reg(2), c=Reg(3))
        self.assertEqual(agw.wide_registers, (0,))
        self.assertEqual(agw.physical_written_registers, (0, 1))

        apw = AputWide(a=Reg(0), b=Reg(2), c=Reg(3))
        self.assertEqual(apw.wide_registers, (0,))
        self.assertEqual(apw.physical_read_registers, (0, 1, 2, 3))

        # IgetWide / IputWide
        igw = IgetWide(a=Reg(0), b=Reg(2), c=Idx[FieldIdItem](1))
        self.assertEqual(igw.wide_registers, (0,))
        self.assertEqual(igw.physical_written_registers, (0, 1))

        ipw = IputWide(a=Reg(0), b=Reg(2), c=Idx[FieldIdItem](1))
        self.assertEqual(ipw.wide_registers, (0,))
        self.assertEqual(ipw.physical_read_registers, (0, 1, 2))

        # SgetWide / SputWide
        sgw = SgetWide(a=Reg(0), b=Idx[FieldIdItem](1))
        self.assertEqual(sgw.wide_registers, (0,))
        self.assertEqual(sgw.physical_written_registers, (0, 1))

        spw = SputWide(a=Reg(0), b=Idx[FieldIdItem](1))
        self.assertEqual(spw.wide_registers, (0,))
        self.assertEqual(spw.physical_read_registers, (0, 1))

        # ReturnWide
        rw = ReturnWide(a=Reg(0))
        self.assertEqual(rw.wide_registers, (0,))
        self.assertEqual(rw.physical_read_registers, (0, 1))

    def test_branch_and_control_flow_guards(self) -> None:
        goto = Goto(a=BranchOffset(5))
        ifeq = IfEq(a=Reg(0), b=Reg(1), c=BranchOffset(10))
        ret = Return(a=Reg(0))
        ret_void = ReturnVoid()
        ret_wide = ReturnWide(a=Reg(0))
        ret_obj = ReturnObject(a=Reg(0))
        throw = Throw(a=Reg(1))
        packed_sw = PackedSwitch(a=Reg(0), b=BranchOffset(20))
        sparse_sw = SparseSwitch(a=Reg(0), b=BranchOffset(30))
        nop = Nop()

        # is_branch
        self.assertTrue(is_branch(goto))
        self.assertTrue(is_branch(ifeq))
        self.assertFalse(is_branch(ret))

        # is_conditional_branch & is_unconditional_branch
        self.assertTrue(is_conditional_branch(ifeq))
        self.assertFalse(is_conditional_branch(goto))
        self.assertTrue(is_unconditional_branch(goto))
        self.assertFalse(is_unconditional_branch(ifeq))

        # is_return
        self.assertTrue(is_return(ret))
        self.assertTrue(is_return(ret_void))
        self.assertTrue(is_return(ret_wide))
        self.assertTrue(is_return(ret_obj))
        self.assertFalse(is_return(throw))

        # is_throw
        self.assertTrue(is_throw(throw))
        self.assertFalse(is_throw(ret))

        # is_switch
        self.assertTrue(is_switch(packed_sw))
        self.assertTrue(is_switch(sparse_sw))
        self.assertFalse(is_switch(nop))


if __name__ == "__main__":
    unittest.main()
