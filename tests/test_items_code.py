"""Unit tests for DEX try-catch handlers, instruction buffers, code items, and debug info items."""

import dataclasses
import unittest
from dataclasses import FrozenInstanceError

from dexbuf import (
    NO_OFFSET,
    CatchHandlerMap,
    CodeItem,
    EncodedCatchHandler,
    EncodedCatchHandlerList,
    EncodedTypeAddrPair,
    Idx,
    Instruction,
    InstructionBuffer,
    Offset,
    Opcode,
    StringIdItem,
    TryItem,
    TryTable,
    TypeIdItem,
)
from dexbuf.cursor import Cursor
from dexbuf.debug import (
    DbgAdvanceLine,
    DbgAdvancePc,
    DbgEndSequence,
    DbgSetEpilogueBegin,
    DbgSetFile,
    DbgSetPrologueEnd,
    DbgSpecial,
    DebugPosition,
)
from dexbuf.items import DebugInfoItem


class TestTryAndCatchHandlers(unittest.TestCase):
    def test_try_item(self) -> None:
        item = TryItem(start_addr=0x10, insn_count=5, handler_off=0x20)
        with self.assertRaises(FrozenInstanceError):
            item.start_addr = 0x20  # type: ignore[misc]

        raw = item.to_bytes()
        self.assertEqual(len(raw), 8)

        parsed = TryItem.from_buffer(raw)
        self.assertEqual(parsed, item)

        # Range methods
        self.assertEqual(item.end_addr, 0x15)
        self.assertFalse(item.covers(0x0F))
        self.assertTrue(item.covers(0x10))
        self.assertTrue(item.covers(0x12))
        self.assertTrue(item.covers(0x14))
        self.assertFalse(item.covers(0x15))
        self.assertFalse(item.covers(0x20))

    def test_try_table(self) -> None:
        # Default initialization
        empty_table = TryTable()
        self.assertEqual(len(empty_table), 0)
        self.assertEqual(empty_table.to_bytes(), b"")

        # from_tries classmethod
        t1 = TryItem(start_addr=0x10, insn_count=5, handler_off=0x00)
        t2 = TryItem(start_addr=0x20, insn_count=10, handler_off=0x08)
        t3 = TryItem(start_addr=0x40, insn_count=4, handler_off=0x10)

        table = TryTable.from_tries([t1, t2, t3])
        self.assertEqual(len(table), 3)
        self.assertEqual(table.to_bytes(), t1.to_bytes() + t2.to_bytes() + t3.to_bytes())

        # Indexing & Negative Indexing
        self.assertEqual(table[0], t1)
        self.assertEqual(table[1], t2)
        self.assertEqual(table[2], t3)
        self.assertEqual(table[-1], t3)
        self.assertEqual(table[-2], t2)
        self.assertEqual(table[-3], t1)

        # Index Out of Bounds
        with self.assertRaises(IndexError):
            _ = table[3]
        with self.assertRaises(IndexError):
            _ = table[-4]

        # Slicing
        self.assertEqual(table[0:2], (t1, t2))
        self.assertEqual(table[1:], (t2, t3))
        self.assertEqual(table[:], (t1, t2, t3))

        # Iteration
        self.assertEqual(list(table), [t1, t2, t3])

        # Equality (__eq__)
        table_same_bytes = TryTable(memoryview(table.to_bytes()))
        self.assertEqual(table, table_same_bytes)
        self.assertEqual(table, (t1, t2, t3))
        self.assertEqual(table, [t1, t2, t3])

        # Unequal cases
        self.assertNotEqual(table, TryTable.from_tries([t1, t2]))
        self.assertNotEqual(table, (t1, t2))
        self.assertNotEqual(table, "not a sequence")

    def test_encoded_type_addr_pair(self) -> None:
        pair = EncodedTypeAddrPair(type_idx=Idx[TypeIdItem](3), addr=0x100)
        with self.assertRaises(FrozenInstanceError):
            pair.addr = 0x200  # type: ignore[misc]

        raw = pair.to_bytes()
        parsed = EncodedTypeAddrPair.from_cursor(Cursor(raw))
        self.assertEqual(parsed, pair)

    def test_cursor_skip_leb128(self) -> None:
        """Test Cursor.skip_leb128 method."""
        # 1-byte LEB128 (0x05)
        # 2-byte LEB128 (0x80, 0x01 = 128)
        # 5-byte LEB128 (0x80, 0x80, 0x80, 0x80, 0x01)
        # Trailing byte 0x42
        buf = bytes([0x05, 0x80, 0x01, 0x80, 0x80, 0x80, 0x80, 0x01, 0x42])
        cursor = Cursor(buf)

        # Skip 1-byte
        cursor.skip_leb128()
        self.assertEqual(cursor.tell(), 1)

        # Skip 2-byte
        cursor.skip_leb128()
        self.assertEqual(cursor.tell(), 3)

        # Skip 5-byte
        cursor.skip_leb128()
        self.assertEqual(cursor.tell(), 8)

        # Read remaining 1 byte u8
        self.assertEqual(cursor.read_u8(), 0x42)

        # EOFError test
        truncated_cursor = Cursor(bytes([0x80, 0x80]))
        with self.assertRaises(EOFError):
            truncated_cursor.skip_leb128()

        # ValueError test (exceeds 5 bytes)
        overflow_cursor = Cursor(bytes([0x80, 0x80, 0x80, 0x80, 0x80, 0x01]))
        with self.assertRaises(ValueError):
            overflow_cursor.skip_leb128()

    def test_encoded_catch_handler(self) -> None:
        pair1 = EncodedTypeAddrPair(type_idx=Idx[TypeIdItem](1), addr=0x10)
        pair2 = EncodedTypeAddrPair(type_idx=Idx[TypeIdItem](2), addr=0x20)

        # Handler with catch-all (size <= 0)
        handler_catch_all = EncodedCatchHandler(handlers=(pair1, pair2), catch_all_addr=0x30)
        self.assertEqual(handler_catch_all.size, -2)
        self.assertTrue(handler_catch_all.catches_all)
        self.assertEqual(handler_catch_all.get_target(Idx[TypeIdItem](1)), 0x10)
        self.assertEqual(handler_catch_all.get_target(Idx[TypeIdItem](2)), 0x20)
        self.assertEqual(handler_catch_all.get_target(Idx[TypeIdItem](3)), 0x30)

        with self.assertRaises((TypeError, AttributeError)):
            handler_catch_all.size = 1  # type: ignore[misc]

        raw1 = handler_catch_all.to_bytes()
        parsed1 = EncodedCatchHandler.from_cursor(Cursor(raw1))
        self.assertEqual(parsed1, handler_catch_all)

        # Handler without catch-all (size > 0)
        handler_no_catch_all = EncodedCatchHandler(handlers=(pair1, pair2), catch_all_addr=None)
        self.assertEqual(handler_no_catch_all.size, 2)
        self.assertFalse(handler_no_catch_all.catches_all)
        self.assertEqual(handler_no_catch_all.get_target(Idx[TypeIdItem](1)), 0x10)
        self.assertIsNone(handler_no_catch_all.get_target(Idx[TypeIdItem](3)))

        raw2 = handler_no_catch_all.to_bytes()
        parsed2 = EncodedCatchHandler.from_cursor(Cursor(raw2))
        self.assertEqual(parsed2, handler_no_catch_all)

        # Test skip advances cursor offset identically to from_cursor
        c_skip1 = Cursor(raw1)
        EncodedCatchHandler.skip(c_skip1)
        c_parse1 = Cursor(raw1)
        _ = EncodedCatchHandler.from_cursor(c_parse1)
        self.assertEqual(c_skip1.tell(), c_parse1.tell())

        c_skip2 = Cursor(raw2)
        EncodedCatchHandler.skip(c_skip2)
        c_parse2 = Cursor(raw2)
        _ = EncodedCatchHandler.from_cursor(c_parse2)
        self.assertEqual(c_skip2.tell(), c_parse2.tell())

    def test_encoded_catch_handler_list(self) -> None:
        # Test empty buffer initialization raises ValueError
        with self.assertRaises(ValueError):
            EncodedCatchHandlerList(memoryview(b""))

        # Test from_handlers with empty handlers sequence creates valid 1-byte wire structure
        empty_handler_list = EncodedCatchHandlerList.from_handlers([])
        self.assertEqual(empty_handler_list.size, 0)
        self.assertEqual(len(empty_handler_list), 0)
        self.assertEqual(bytes(empty_handler_list._buffer), b"\x00")

        h1 = EncodedCatchHandler(
            handlers=(EncodedTypeAddrPair(type_idx=Idx[TypeIdItem](5), addr=0x50),),
            catch_all_addr=None,
        )
        h2 = EncodedCatchHandler(
            handlers=(),
            catch_all_addr=0x100,
        )

        handler_list = EncodedCatchHandlerList.from_handlers([h1, h2])

        self.assertEqual(handler_list.size, 2)
        self.assertEqual(len(handler_list), 2)
        self.assertIs(CatchHandlerMap, EncodedCatchHandlerList)

        # Iteration yields relative byte offsets of handlers
        offsets = list(handler_list)
        self.assertEqual(len(offsets), 2)
        off1, off2 = offsets[0], offsets[1]
        self.assertGreater(off1, 0)
        self.assertGreater(off2, off1)

        # Direct O(1) indexing by offset
        self.assertEqual(handler_list[off1], h1)
        self.assertEqual(handler_list[off2], h2)

        # Mapping methods: keys, values, items, get
        self.assertEqual(list(handler_list.keys()), [off1, off2])
        self.assertEqual(list(handler_list.values()), [h1, h2])
        self.assertEqual(list(handler_list.items()), [(off1, h1), (off2, h2)])
        self.assertEqual(handler_list.get(off1), h1)
        self.assertIsNone(handler_list.get(999))

        # Invalid offset access raises KeyError
        with self.assertRaises(KeyError):
            _ = handler_list[0]
        with self.assertRaises(KeyError):
            _ = handler_list[-1]
        with self.assertRaises(KeyError):
            _ = handler_list[1000]

        # Serialization & roundtrip
        raw = handler_list.to_bytes()
        parsed = EncodedCatchHandlerList.from_buffer(raw)
        self.assertEqual(parsed, handler_list)
        self.assertEqual(parsed, {off1: h1, off2: h2})
        self.assertNotEqual(parsed, {off1: h1})
        self.assertNotEqual(parsed, "not a mapping")


class TestInstructionBuffer(unittest.TestCase):
    def test_instruction_buffer_empty(self) -> None:
        buf = InstructionBuffer(b"")
        self.assertEqual(len(buf), 0)
        self.assertEqual(buf.code_units, 0)
        self.assertEqual(buf.to_bytes(), b"")
        self.assertEqual(list(buf), [])
        self.assertEqual(buf.parse(), ())

    def test_instruction_buffer_indexing_and_iteration(self) -> None:
        # nop (0x0000), return-void (0x000e) -> 2 code units = 4 bytes
        bytecode = b"\x00\x00\x0e\x00"
        buf = InstructionBuffer(bytecode)

        self.assertEqual(len(buf), 2)
        self.assertEqual(buf.code_units, 2)

        # Indexing via [] and .at()
        nop_insn = buf[0]
        self.assertEqual(nop_insn, buf.at(0))
        self.assertIsInstance(nop_insn, Instruction)
        self.assertEqual(nop_insn.OPCODE, Opcode.NOP)

        ret_insn = buf[1]
        self.assertEqual(ret_insn, buf.at(1))
        self.assertIsInstance(ret_insn, Instruction)
        self.assertEqual(ret_insn.OPCODE, Opcode.RETURN_VOID)

        # Negative indexing
        self.assertEqual(buf[-1], ret_insn)
        self.assertEqual(buf[-2], nop_insn)

        # Out-of-bounds indexing
        with self.assertRaises(IndexError):
            _ = buf[2]
        with self.assertRaises(IndexError):
            _ = buf[-3]
        with self.assertRaises(IndexError):
            _ = buf[100]

        # Iteration & parse()
        iops = list(buf)
        self.assertEqual(len(iops), 2)
        self.assertEqual(iops[0], nop_insn)
        self.assertEqual(iops[1], ret_insn)
        self.assertEqual(buf.parse(), (nop_insn, ret_insn))

    def test_instruction_buffer_to_bytes_and_buffer_protocol(self) -> None:
        bytecode = b"\x0e\x00"
        buf = InstructionBuffer(bytecode)

        self.assertEqual(buf.to_bytes(), bytecode)
        self.assertEqual(bytes(buf), bytecode)
        self.assertEqual(memoryview(buf), memoryview(bytecode))

    def test_instruction_buffer_equality(self) -> None:
        bytecode = b"\x0e\x00"
        buf1 = InstructionBuffer(bytecode)
        buf2 = InstructionBuffer(bytearray(bytecode))
        buf_diff = InstructionBuffer(b"\x00\x00")

        self.assertEqual(buf1, buf2)
        self.assertEqual(buf1, bytecode)
        self.assertEqual(buf1, memoryview(bytecode))
        self.assertNotEqual(buf1, buf_diff)
        self.assertNotEqual(buf1, b"\x00\x00")
        self.assertNotEqual(buf1, "not a buffer")


class TestCodeItem(unittest.TestCase):
    def test_fields_metadata(self) -> None:
        field_names = [f.name for f in dataclasses.fields(CodeItem)]
        expected_fields = [
            "registers_size",
            "ins_size",
            "outs_size",
            "debug_info_off",
            "insns",
            "tries",
            "handlers",
        ]
        self.assertEqual(field_names, expected_fields)

    def test_immutability(self) -> None:
        item = CodeItem(
            registers_size=2,
            ins_size=1,
            outs_size=0,
            debug_info_off=NO_OFFSET,
            insns=InstructionBuffer(b"\x0e\x00"),  # return-void
            tries=TryTable(),
            handlers=None,
        )
        with self.assertRaises(FrozenInstanceError):
            item.registers_size = 4  # type: ignore[misc]
        with self.assertRaises((TypeError, AttributeError)):
            item.insns_size = 5  # type: ignore[misc]
        with self.assertRaises((TypeError, AttributeError)):
            item.tries_size = 2  # type: ignore[misc]

    def test_zero_copy_and_lazy_iop_parsing(self) -> None:
        # nop (0x0000), return-void (0x000e) -> 2 code units = 4 bytes
        bytecode = b"\x00\x00\x0e\x00"
        item_no_tries = CodeItem(
            registers_size=1,
            ins_size=0,
            outs_size=0,
            debug_info_off=NO_OFFSET,
            insns=InstructionBuffer(bytecode),
            tries=TryTable(),
            handlers=None,
        )
        self.assertEqual(item_no_tries.insns_size, 2)
        self.assertEqual(item_no_tries.tries_size, 0)
        self.assertIsNone(item_no_tries.handlers)
        self.assertIsNone(item_no_tries.find_catch_handler(0))
        with self.assertRaises(ValueError):
            item_no_tries.get_catch_handler(TryItem(0, 1, 0))

        raw = item_no_tries.to_bytes()
        cursor = Cursor(raw)
        parsed = CodeItem.from_cursor(cursor)
        self.assertIsNone(parsed.handlers)

        # Confirm insns is an InstructionBuffer
        self.assertIsInstance(parsed.insns, InstructionBuffer)
        self.assertEqual(bytes(parsed.insns), bytecode)

        # Lazy instruction parsing via insns
        iops = list(parsed.insns)
        self.assertEqual(len(iops), 2)
        self.assertIsInstance(iops[0], Instruction)
        self.assertEqual(iops[0].OPCODE, Opcode.NOP)
        self.assertIsInstance(iops[1], Instruction)
        self.assertEqual(iops[1].OPCODE, Opcode.RETURN_VOID)
        self.assertEqual(parsed.insns.parse(), tuple(iops))

    def test_tries_and_padding_even_insns_size(self) -> None:
        # 2 code units (even) -> no padding before tries
        bytecode = b"\x00\x00\x0e\x00"
        handler = EncodedCatchHandler(
            handlers=(EncodedTypeAddrPair(type_idx=Idx[TypeIdItem](0), addr=2),),
            catch_all_addr=4,
        )
        handlers = EncodedCatchHandlerList.from_handlers([handler])
        handler_off = next(iter(handlers))
        try_item = TryItem(start_addr=0, insn_count=1, handler_off=handler_off)

        item = CodeItem(
            registers_size=1,
            ins_size=0,
            outs_size=0,
            debug_info_off=NO_OFFSET,
            insns=InstructionBuffer(bytecode),
            tries=TryTable.from_tries((try_item,)),
            handlers=handlers,
        )

        raw = item.to_bytes()
        parsed = CodeItem.from_buffer(raw)
        self.assertEqual(parsed, item)
        self.assertEqual(parsed.get_catch_handler(try_item), handler)
        self.assertEqual(parsed.find_catch_handler(0), handler)

    def test_tries_and_padding_odd_insns_size(self) -> None:
        # 1 code unit (odd) -> 2 bytes padding required before tries
        bytecode = b"\x0e\x00"  # return-void
        handler = EncodedCatchHandler(
            handlers=(EncodedTypeAddrPair(type_idx=Idx[TypeIdItem](1), addr=10),),
            catch_all_addr=None,
        )
        handlers = EncodedCatchHandlerList.from_handlers([handler])
        handler_off = next(iter(handlers))
        try_item = TryItem(start_addr=0, insn_count=1, handler_off=handler_off)

        item = CodeItem(
            registers_size=1,
            ins_size=0,
            outs_size=0,
            debug_info_off=NO_OFFSET,
            insns=InstructionBuffer(bytecode),
            tries=TryTable.from_tries((try_item,)),
            handlers=handlers,
        )

        raw = item.to_bytes()
        # Verify padding bytes exist in raw serialized output
        # Header size = 16 bytes. insns = 2 bytes. Total = 18 bytes.
        # Padding = 2 bytes (offsets 18..20)
        self.assertEqual(raw[18:20], b"\x00\x00")

        parsed = CodeItem.from_buffer(raw)
        self.assertEqual(parsed, item)

    def test_find_try_item(self) -> None:
        # Empty tries
        code_empty = CodeItem(
            registers_size=1,
            ins_size=0,
            outs_size=0,
            debug_info_off=NO_OFFSET,
            insns=InstructionBuffer(b"\x00\x00"),
            tries=TryTable(),
            handlers=None,
        )
        self.assertIsNone(code_empty.find_try_item(10))
        self.assertIsNone(code_empty.find_catch_handler(10))

        # Multiple tries
        h1 = EncodedCatchHandler(handlers=(), catch_all_addr=0x10)
        h2 = EncodedCatchHandler(handlers=(), catch_all_addr=0x20)
        handlers = EncodedCatchHandlerList.from_handlers([h1, h2])
        off1, off2 = list(handlers)

        t1 = TryItem(start_addr=10, insn_count=5, handler_off=off1)  # 10..15
        t2 = TryItem(start_addr=20, insn_count=10, handler_off=off2)  # 20..30
        t3 = TryItem(start_addr=35, insn_count=5, handler_off=off1)  # 35..40

        code = CodeItem(
            registers_size=1,
            ins_size=0,
            outs_size=0,
            debug_info_off=NO_OFFSET,
            insns=InstructionBuffer(b"\x00\x00"),
            tries=TryTable.from_tries([t1, t2, t3]),
            handlers=handlers,
        )

        # Lookups before, inside, gap, after
        self.assertIsNone(code.find_try_item(5))
        self.assertEqual(code.find_try_item(10), t1)
        self.assertEqual(code.find_try_item(14), t1)
        self.assertIsNone(code.find_try_item(15))
        self.assertIsNone(code.find_try_item(18))
        self.assertEqual(code.find_try_item(20), t2)
        self.assertEqual(code.find_try_item(25), t2)
        self.assertEqual(code.find_try_item(29), t2)
        self.assertIsNone(code.find_try_item(30))
        self.assertEqual(code.find_try_item(35), t3)
        self.assertEqual(code.find_try_item(39), t3)
        self.assertIsNone(code.find_try_item(40))
        self.assertIsNone(code.find_try_item(100))


class TestDebugInfoItem(unittest.TestCase):
    def test_fields_metadata(self) -> None:
        field_names = [f.name for f in dataclasses.fields(DebugInfoItem)]
        expected_fields = ["line_start", "parameter_names", "bytecode"]
        self.assertEqual(field_names, expected_fields)

    def test_immutability(self) -> None:
        item = DebugInfoItem(
            line_start=1,
            parameter_names=(),
            bytecode=memoryview(b"\x00"),
        )
        with self.assertRaises(FrozenInstanceError):
            item.line_start = 2  # type: ignore[misc]
        with self.assertRaises((TypeError, AttributeError)):
            item.parameters_size = 5  # type: ignore[misc]

    def test_zero_copy_bytecode_and_roundtrip(self) -> None:
        # line_start=1, parameters_size=2 (param1=Idx(0), param2=None)
        # bytecode: DBG_SET_FILE(1), DBG_ADVANCE_PC(2), DBG_ADVANCE_LINE(1)
        # DBG_SET_PROLOGUE_END, DBG_SPECIAL(0x0a), DBG_END_SEQUENCE
        # DBG_SET_FILE = 0x09 + encode_uleb128p1(1) [0x02]
        # DBG_ADVANCE_PC = 0x01 + uleb128(2) [0x02]
        # DBG_ADVANCE_LINE = 0x02 + sleb128(1) [0x01]
        # DBG_SET_PROLOGUE_END = 0x07
        # DBG_SPECIAL(0x0a) = 0x0a
        # DBG_END_SEQUENCE = 0x00
        bytecode_raw = b"\x09\x02\x01\x02\x02\x01\x07\x0a\x00"

        item = DebugInfoItem(
            line_start=10,
            parameter_names=(Idx[StringIdItem](0), None),
            bytecode=memoryview(bytecode_raw),
        )

        raw = item.to_bytes()
        cursor = Cursor(raw)
        parsed = DebugInfoItem.from_cursor(cursor)

        self.assertEqual(parsed.line_start, 10)
        self.assertEqual(parsed.parameters_size, 2)
        self.assertEqual(parsed.parameter_names, (Idx[StringIdItem](0), None))
        self.assertIsInstance(parsed.bytecode, memoryview)
        self.assertEqual(bytes(parsed.bytecode), bytecode_raw)
        self.assertTrue(cursor.is_eof)

        # Buffer roundtrip with offset
        buf = b"\xff\xff" + raw
        from_buf = DebugInfoItem.from_buffer(buf, Offset[DebugInfoItem](2))
        self.assertEqual(from_buf.line_start, parsed.line_start)
        self.assertEqual(from_buf.parameter_names, parsed.parameter_names)
        self.assertEqual(bytes(from_buf.bytecode), bytecode_raw)

    def test_iter_instructions_and_positions(self) -> None:
        # line_start=100
        # Bytecode ops:
        # DBG_SET_FILE(Idx(5)) -> source_file_idx = 5
        # DBG_SET_PROLOGUE_END -> prologue_end = True
        # DBG_ADVANCE_PC(4) -> address += 4
        # DBG_ADVANCE_LINE(2) -> line += 2
        # DBG_SPECIAL(0x0a) -> line += (-4), address += 0 -> yields position
        # DBG_SET_EPILOGUE_BEGIN -> epilogue_begin = True
        # DBG_SPECIAL(0x19) -> line += -4, address += 1 -> yields position
        # DBG_END_SEQUENCE -> finish
        bytecode_raw = (
            b"\x09\x06"  # DBG_SET_FILE (5 + 1 = 6)
            b"\x07"  # DBG_SET_PROLOGUE_END
            b"\x01\x04"  # DBG_ADVANCE_PC (4)
            b"\x02\x02"  # DBG_ADVANCE_LINE (2)
            b"\x0a"  # DBG_SPECIAL (line -4, addr 0) -> line: 100 + 2 - 4 = 98, addr: 0 + 4 + 0 = 4
            b"\x08"  # DBG_SET_EPILOGUE_BEGIN
            b"\x19"  # DBG_SPECIAL (line -4, addr 1) -> line: 98 - 4 = 94, addr: 4 + 1 = 5
            b"\x00"  # DBG_END_SEQUENCE
        )

        item = DebugInfoItem(
            line_start=100,
            parameter_names=(),
            bytecode=memoryview(bytecode_raw),
        )

        instructions = list(item.iter_instructions())
        self.assertEqual(len(instructions), 8)
        self.assertIsInstance(instructions[0], DbgSetFile)
        self.assertIsInstance(instructions[1], DbgSetPrologueEnd)
        self.assertIsInstance(instructions[2], DbgAdvancePc)
        self.assertIsInstance(instructions[3], DbgAdvanceLine)
        self.assertIsInstance(instructions[4], DbgSpecial)
        self.assertIsInstance(instructions[5], DbgSetEpilogueBegin)
        self.assertIsInstance(instructions[6], DbgSpecial)
        self.assertIsInstance(instructions[7], DbgEndSequence)

        positions = list(item.iter_positions(initial_source_file=None))
        self.assertEqual(len(positions), 2)

        self.assertEqual(
            positions[0],
            DebugPosition(
                address=4,
                line=98,
                source_file_idx=Idx[StringIdItem](5),
                prologue_end=True,
                epilogue_begin=False,
            ),
        )
        self.assertEqual(
            positions[1],
            DebugPosition(
                address=5,
                line=94,
                source_file_idx=Idx[StringIdItem](5),
                prologue_end=False,
                epilogue_begin=True,
            ),
        )


if __name__ == "__main__":
    unittest.main()
