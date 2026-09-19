"""Unit tests for Dalvik debug bytecode instructions and state machine helpers."""

import unittest

from dexbuf.cursor import Cursor
from dexbuf.debug import (
    DbgAdvanceLine,
    DbgAdvancePc,
    DbgEndLocal,
    DbgEndSequence,
    DbgRestartLocal,
    DbgSetEpilogueBegin,
    DbgSetFile,
    DbgSetPrologueEnd,
    DbgSpecial,
    DbgStartLocal,
    DbgStartLocalExtended,
    DebugOpcode,
    DebugPosition,
    parse_debug_instruction,
    skip_debug_instruction,
)
from dexbuf.types import NO_INDEX, Idx


class TestDebugInstructions(unittest.TestCase):
    def test_special_opcode_math(self) -> None:
        """Test line_diff and addr_diff math for special opcodes 0x0a..0xff."""
        # 0x0A: adjusted = 0 -> line_diff = -4 + (0 % 15) = -4, addr_diff = 0 // 15 = 0
        s1 = DbgSpecial(0x0A)
        self.assertEqual(s1.line_diff, -4)
        self.assertEqual(s1.addr_diff, 0)

        # 0x0E: adjusted = 4 -> line_diff = -4 + 4 = 0, addr_diff = 0
        s2 = DbgSpecial(0x0E)
        self.assertEqual(s2.line_diff, 0)
        self.assertEqual(s2.addr_diff, 0)

        # 0x19: adjusted = 15 -> line_diff = -4 + 0 = -4, addr_diff = 15 // 15 = 1
        s3 = DbgSpecial(0x19)
        self.assertEqual(s3.line_diff, -4)
        self.assertEqual(s3.addr_diff, 1)

    def test_parse_and_skip_all_opcodes(self) -> None:
        """Verify parse, skip, and roundtrip serialization for all debug opcodes."""
        test_cases = [
            (b"\x00", DbgEndSequence(), DebugOpcode.DBG_END_SEQUENCE),
            (b"\x01\x05", DbgAdvancePc(5), DebugOpcode.DBG_ADVANCE_PC),
            (b"\x02\x7f", DbgAdvanceLine(-1), DebugOpcode.DBG_ADVANCE_LINE),
            (
                b"\x03\x02\x05\x0a",
                DbgStartLocal(2, Idx(4), Idx(9)),
                DebugOpcode.DBG_START_LOCAL,
            ),
            (
                b"\x04\x02\x05\x0a\x03",
                DbgStartLocalExtended(2, Idx(4), Idx(9), Idx(2)),
                DebugOpcode.DBG_START_LOCAL_EXTENDED,
            ),
            (b"\x05\x03", DbgEndLocal(3), DebugOpcode.DBG_END_LOCAL),
            (b"\x06\x03", DbgRestartLocal(3), DebugOpcode.DBG_RESTART_LOCAL),
            (b"\x07", DbgSetPrologueEnd(), DebugOpcode.DBG_SET_PROLOGUE_END),
            (b"\x08", DbgSetEpilogueBegin(), DebugOpcode.DBG_SET_EPILOGUE_BEGIN),
            (b"\x09\x04", DbgSetFile(Idx(3)), DebugOpcode.DBG_SET_FILE),
            (b"\x0a", DbgSpecial(0x0A), 0x0A),
            (b"\xff", DbgSpecial(0xFF), 0xFF),
        ]

        for raw, expected_inst, expected_op in test_cases:
            # 1. parse
            c_parse = Cursor(raw)
            inst = parse_debug_instruction(c_parse)
            self.assertEqual(inst, expected_inst)
            self.assertTrue(c_parse.is_eof)

            # 2. skip
            c_skip = Cursor(raw)
            opcode = skip_debug_instruction(c_skip)
            self.assertEqual(opcode, expected_op)
            self.assertTrue(c_skip.is_eof)

            # 3. to_bytes roundtrip
            encoded = inst.to_bytes()
            self.assertEqual(encoded, raw)

    def test_no_index_handling(self) -> None:
        """Verify NO_INDEX handling when string/type index is encoded as 0 (uleb128p1 value -1)."""
        # DbgStartLocal with NO_INDEX for name and type
        raw = b"\x03\x01\x00\x00"
        c = Cursor(raw)
        inst = parse_debug_instruction(c)
        self.assertEqual(inst, DbgStartLocal(register_num=1, name_idx=NO_INDEX, type_idx=NO_INDEX))
        self.assertEqual(inst.to_bytes(), raw)

        # DbgStartLocalExtended with NO_INDEX for sig
        raw_ext = b"\x04\x01\x02\x03\x00"
        c_ext = Cursor(raw_ext)
        inst_ext = parse_debug_instruction(c_ext)
        self.assertEqual(
            inst_ext,
            DbgStartLocalExtended(
                register_num=1, name_idx=Idx(1), type_idx=Idx(2), sig_idx=NO_INDEX
            ),
        )
        self.assertEqual(inst_ext.to_bytes(), raw_ext)

        # DbgSetFile with NO_INDEX
        raw_file = b"\x09\x00"
        c_file = Cursor(raw_file)
        inst_file = parse_debug_instruction(c_file)
        self.assertEqual(inst_file, DbgSetFile(name_idx=NO_INDEX))
        self.assertEqual(inst_file.to_bytes(), raw_file)

    def test_dataclasses_slots_and_frozen(self) -> None:
        """Verify instruction dataclasses are slotted and immutable (frozen)."""
        inst = DbgAdvancePc(10)
        self.assertTrue(hasattr(inst, "__slots__"))
        with self.assertRaises(AttributeError):
            inst.addr_diff = 20  # type: ignore[misc]

        pos = DebugPosition(
            address=0,
            line=1,
            source_file_idx=NO_INDEX,
            prologue_end=False,
            epilogue_begin=False,
        )
        self.assertTrue(hasattr(pos, "__slots__"))
        with self.assertRaises(AttributeError):
            pos.address = 5  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
