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
    Instruction,
    InvokePolymorphic,
    InvokePolymorphicRange,
    InvokeVirtual,
    InvokeVirtualRange,
    Move,
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
    get_registers,
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
        """Verify has_id and get_id with and without item_type filter."""
        const_str = ConstString(a=Reg(1), b=Idx[StringIdItem](10))
        const_cls = ConstClass(a=Reg(2), b=Idx[TypeIdItem](20))
        nop = Nop()

        # Without item_type filter
        self.assertTrue(has_id(const_str))
        self.assertEqual(get_id(const_str), 10)
        self.assertTrue(has_id(const_cls))
        self.assertEqual(get_id(const_cls), 20)
        self.assertFalse(has_id(nop))
        self.assertIsNone(get_id(nop))

        # With item_type filter
        self.assertTrue(has_id(const_str, StringIdItem))
        self.assertEqual(get_id(const_str, StringIdItem), 10)
        self.assertFalse(has_id(const_str, TypeIdItem))
        self.assertIsNone(get_id(const_str, TypeIdItem))

        self.assertTrue(has_id(const_cls, TypeIdItem))
        self.assertEqual(get_id(const_cls, TypeIdItem), 20)
        self.assertFalse(has_id(const_cls, StringIdItem))
        self.assertIsNone(get_id(const_cls, StringIdItem))

    def test_branch_type_guards_and_negative_narrowing(self) -> None:
        """Verify is_branch, is_conditional_branch, is_unconditional_branch and chained if/elif."""
        goto = Goto(a=BranchOffset(-10))
        ifeq = IfEq(a=Reg(1), b=Reg(2), c=BranchOffset(15))
        nop = Nop()

        self.assertTrue(is_branch(goto))
        self.assertTrue(is_branch(ifeq))
        self.assertFalse(is_branch(nop))

        self.assertFalse(is_conditional_branch(goto))
        self.assertTrue(is_unconditional_branch(goto))

        self.assertTrue(is_conditional_branch(ifeq))
        self.assertFalse(is_unconditional_branch(ifeq))

        # Verify chained if / elif pattern
        def classify_branch(inst: Instruction) -> str:
            if is_conditional_branch(inst):
                return f"conditional:{inst.target}"
            elif is_unconditional_branch(inst):
                return f"unconditional:{inst.target}"
            else:
                return "not_branch"

        self.assertEqual(classify_branch(ifeq), "conditional:15")
        self.assertEqual(classify_branch(goto), "unconditional:-10")
        self.assertEqual(classify_branch(nop), "not_branch")

    def test_has_literal_and_get_literal(self) -> None:
        """Verify has_literal and get_literal helpers."""
        const4 = Const4(a=Reg(1), b=Literal(-5))
        nop = Nop()

        self.assertTrue(has_literal(const4))
        self.assertEqual(get_literal(const4), -5)

        self.assertFalse(has_literal(nop))
        self.assertIsNone(get_literal(nop))

    def test_control_flow_guards(self) -> None:
        """Verify is_return, is_throw, is_switch type guards."""
        ret_void = ReturnVoid()
        ret = Return(a=Reg(1))
        ret_wide = ReturnWide(a=Reg(2))
        ret_obj = ReturnObject(a=Reg(3))

        throw_insn = Throw(a=Reg(1))
        packed_sw = PackedSwitch(a=Reg(1), b=BranchOffset(10))
        sparse_sw = SparseSwitch(a=Reg(1), b=BranchOffset(20))
        nop = Nop()

        # is_return
        self.assertTrue(is_return(ret_void))
        self.assertTrue(is_return(ret))
        self.assertTrue(is_return(ret_wide))
        self.assertTrue(is_return(ret_obj))
        self.assertFalse(is_return(nop))

        # is_throw
        self.assertTrue(is_throw(throw_insn))
        self.assertFalse(is_throw(nop))

        # is_switch
        self.assertTrue(is_switch(packed_sw))
        self.assertTrue(is_switch(sparse_sw))
        self.assertFalse(is_switch(nop))

    def test_get_registers(self) -> None:
        """Verify get_registers helper extracts correct registers across instruction formats."""
        inv_35c = InvokeVirtual(
            a=ArgumentCount(3),
            b=Idx(0),
            c=Reg(1),
            d=Reg(2),
            e=Reg(3),
            f=Reg(0),
            g=Reg(0),
        )
        self.assertEqual(get_registers(inv_35c), (Reg(1), Reg(2), Reg(3)))

        inv_3rc = InvokeVirtualRange(
            a=ArgumentCount(4),
            b=Idx(0),
            c=Reg(5),
        )
        self.assertEqual(get_registers(inv_3rc), (Reg(5), Reg(6), Reg(7), Reg(8)))

        add_23x = AddInt(a=Reg(1), b=Reg(2), c=Reg(3))
        self.assertEqual(get_registers(add_23x), (Reg(1), Reg(2), Reg(3)))

        move_12x = Move(a=Reg(4), b=Reg(5))
        self.assertEqual(get_registers(move_12x), (Reg(4), Reg(5)))

        ret_11x = Return(a=Reg(7))
        self.assertEqual(get_registers(ret_11x), (Reg(7),))

        nop = Nop()
        self.assertEqual(get_registers(nop), ())


if __name__ == "__main__":
    unittest.main()
