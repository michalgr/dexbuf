"""Unit tests for concrete instruction definitions and OPCODE_MAP dispatch in dexbuf."""

import unittest
from unittest.mock import patch

from dexbuf.cursor import Cursor
from dexbuf.instructions import (
    OPCODE_MAP,
    AddInt,
    CheckCast,
    ConstString,
    Iget,
    InvokeVirtual,
    Move,
    Nop,
    Opcode,
    ReturnVoid,
    Sget,
    parse_instruction,
)
from dexbuf.items import FieldIdItem, MethodIdItem, StringIdItem, TypeIdItem
from dexbuf.types import ArgumentCount, Idx, Reg


class TestInstructionDefinitions(unittest.TestCase):
    def test_opcode_map_coverage(self) -> None:
        """Verify OPCODE_MAP contains mappings for standard opcodes."""
        self.assertIn(Opcode.NOP.value, OPCODE_MAP)
        self.assertIs(OPCODE_MAP[Opcode.NOP.value], Nop)
        self.assertIs(OPCODE_MAP[Opcode.MOVE.value], Move)
        self.assertIs(OPCODE_MAP[Opcode.CONST_STRING.value], ConstString)

    def test_parse_instruction_dispatch(self) -> None:
        nop = Nop()
        nop_bytes = nop.to_bytes()
        parsed_nop = parse_instruction(Cursor(nop_bytes))
        self.assertIsInstance(parsed_nop, Nop)

        ret = ReturnVoid()
        ret_bytes = ret.to_bytes()
        parsed_ret = parse_instruction(Cursor(ret_bytes))
        self.assertIsInstance(parsed_ret, ReturnVoid)

    def test_concrete_instruction_typing(self) -> None:
        cs = ConstString(a=Reg(1), b=Idx[StringIdItem](42))
        self.assertEqual(cs.OPCODE, Opcode.CONST_STRING)
        self.assertIsInstance(cs.b, int)
        self.assertEqual(cs.b, 42)

        cc = CheckCast(a=Reg(2), b=Idx[TypeIdItem](10))
        self.assertEqual(cc.OPCODE, Opcode.CHECK_CAST)
        self.assertEqual(cc.b, 10)

        ig = Iget(a=Reg(0), b=Reg(1), c=Idx[FieldIdItem](5))
        self.assertEqual(ig.OPCODE, Opcode.IGET)
        self.assertEqual(ig.c, 5)

        sg = Sget(a=Reg(0), b=Idx[FieldIdItem](8))
        self.assertEqual(sg.OPCODE, Opcode.SGET)
        self.assertEqual(sg.b, 8)

        iv = InvokeVirtual(
            a=ArgumentCount(2),
            b=Idx[MethodIdItem](100),
            c=Reg(0),
            d=Reg(1),
            e=Reg(0),
            f=Reg(0),
            g=Reg(0),
        )
        self.assertEqual(iv.OPCODE, Opcode.INVOKE_VIRTUAL)
        self.assertEqual(iv.b, 100)

        ai = AddInt(a=Reg(0), b=Reg(1), c=Reg(2))
        self.assertEqual(ai.OPCODE, Opcode.ADD_INT)
        parsed_ai = parse_instruction(Cursor(ai.to_bytes()))
        self.assertEqual(parsed_ai, ai)

    def test_unknown_opcode_raises(self) -> None:
        invalid_bytes = b"\x3e\x00"  # AGET
        # Override opcode map test
        with patch.dict(OPCODE_MAP, clear=True):
            with self.assertRaises(ValueError):
                parse_instruction(Cursor(invalid_bytes))


if __name__ == "__main__":
    unittest.main()
