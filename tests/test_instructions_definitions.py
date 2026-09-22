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
    ConstString,
    InvokePolymorphic,
    InvokePolymorphicRange,
    Nop,
    ReturnVoid,
    parse_instruction,
)
from dexbuf.types import ArgumentCount, Idx, Literal, Reg


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


if __name__ == "__main__":
    unittest.main()
