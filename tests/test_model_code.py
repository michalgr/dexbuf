"""Tests for bytecode instructions, register mapping, basic block CFG, and disassembly."""

import struct
import unittest

from dexbuf import (
    AccessFlags,
    CatchEdge,
    CatchHandler,
    ClassLoader,
    DexFile,
    EncodedValue,
    Opcode,
    TryCatch,
    ValueType,
)
from dexbuf.instructions import (
    Const4,
    ConstString,
    Goto,
    InvokeStaticRange,
    PackedSwitch,
    ReturnVoid,
    Sget,
)
from dexbuf.instructions.payloads import PackedSwitchPayload
from dexbuf.items import FieldIdItem, MethodIdItem, StringIdItem
from dexbuf.types import ArgumentCount, BranchOffset, Idx, Literal, Reg
from tests.builders import build_dex_bytes


class TestCodeAndCFGDomainModel(unittest.TestCase):
    def test_code_instruction_properties_and_resolutions(self) -> None:
        # const-string v0, "Hello" (op=0x1a, v0, str@0)
        # const/4 v1, #1 (op=0x12, v1, #1)
        # if-eqz v1, +4 (op=0x38, v1, +4 code units -> pc 0x0002 + 4 = 0x0006)
        # return-void (op=0x0e)
        code_bytes = (
            b"\x1a\x00\x00\x00"  # 0000: const-string v0, string@0
            b"\x12\x10"  # 0002: const/4 v1, #1
            b"\x38\x01\x04\x00"  # 0003: if-eqz v1, +4 -> target_pc 0x0007
            b"\x0e\x00"  # 0005: return-void
            b"\x0e\x00"  # 0006: return-void
            b"\x0e\x00"  # 0007: return-void
        )

        dex_bytes = build_dex_bytes(
            [
                {
                    "name": "Lcom/example/CFGTest;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": 1,
                    "direct_methods": [
                        {
                            "name": "testMethod",
                            "return_type": "V",
                            "params": ["I"],
                            "access_flags": int(AccessFlags.PUBLIC | AccessFlags.STATIC),
                            "registers_size": 2,
                            "ins_size": 1,
                            "outs_size": 0,
                            "code": code_bytes,
                        }
                    ],
                }
            ],
            extra_strings=["Hello"],
        )
        loader = ClassLoader.from_elements([DexFile(dex_bytes)])
        cls = loader["com.example.CFGTest"]
        m = cls.get_method("testMethod")
        assert m is not None

        code = m.code
        self.assertIsNotNone(code)
        assert code is not None

        self.assertEqual(code.registers_size, 2)
        self.assertEqual(code.ins_size, 1)
        self.assertEqual(code.locals_size, 1)
        self.assertEqual(code.register_name(0), "v0")
        self.assertEqual(code.register_name(1), "p0")

        # Instruction queries
        self.assertIn(0, code)
        self.assertIn(2, code)
        self.assertNotIn(1, code)  # 1 is middle of 2-unit instruction
        self.assertNotIn("invalid", code)

        inst0 = code.at(0)
        self.assertEqual(inst0.pc, 0)
        self.assertEqual(inst0.next_pc, 2)
        self.assertEqual(inst0.code_units, 2)
        self.assertEqual(inst0.opcode, Opcode.CONST_STRING)
        self.assertEqual(inst0.mnemonic, "const-string")
        self.assertEqual(inst0.register_names, ("v0",))
        self.assertEqual(inst0.string_value, "Hello")

        inst1 = code.at(2)
        self.assertEqual(inst1.literal, 1)

        inst2 = code.at(3)
        self.assertTrue(inst2.is_branch)
        self.assertTrue(inst2.is_conditional_branch)
        self.assertFalse(inst2.is_unconditional_branch)
        self.assertEqual(inst2.branch_offset, 4)
        self.assertEqual(inst2.target_pc, 7)

        # Basic Block CFG verification
        blocks = code.blocks
        self.assertEqual(len(blocks), 4)
        entry = code.entry_block
        self.assertTrue(entry.is_entry)
        self.assertEqual(entry.start_pc, 0)
        self.assertEqual(entry.end_pc, 5)
        self.assertEqual(len(entry), 3)
        self.assertEqual(entry.terminator.pc, 3)
        self.assertEqual(entry.terminator.opcode, Opcode.IF_EQZ)
        self.assertEqual(tuple(b.start_pc for b in entry.successors), (5, 7))

        # Disassembly string
        dis = code.disassemble()
        self.assertIn(".method", dis)
        self.assertIn("const-string", dis)

    def test_payload_decoupling_next_pcs_and_switch_cfg(self) -> None:
        # Build code stream with packed-switch, return-void, packed-switch-payload
        # PC 0: packed-switch v0, +4 (target payload is at PC 4)
        sw_insn = PackedSwitch(a=Reg(0), b=BranchOffset(4))
        ret_insn = ReturnVoid()
        payload = PackedSwitchPayload(first_key=0, targets=(BranchOffset(3), BranchOffset(12)))

        code_stream = (
            sw_insn.to_bytes()
            + ret_insn.to_bytes()
            + payload.to_bytes()
            + ret_insn.to_bytes()
            + ret_insn.to_bytes()
        )

        dex_bytes = build_dex_bytes(
            [
                {
                    "name": "Lcom/example/SwitchTest;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": 1,
                    "direct_methods": [
                        {
                            "name": "run",
                            "return_type": "V",
                            "params": [],
                            "access_flags": 1,
                            "code": code_stream,
                        }
                    ],
                }
            ]
        )
        loader = ClassLoader.from_elements([DexFile(dex_bytes)])
        m = loader["com.example.SwitchTest"].get_method("run")
        assert m is not None and m.code is not None
        code = m.code

        # Verify instructions contains zero payloads
        self.assertTrue(all(not isinstance(inst.raw, PackedSwitchPayload) for inst in code))

        # Verify CodeInstruction.payload linking on referring switch instruction
        sw_code_inst = code.at(0)
        self.assertEqual(sw_code_inst.payload, payload)
        self.assertEqual(sw_code_inst.raw, sw_insn)

        # Verify CodeInstruction.next_pcs
        self.assertEqual(sw_code_inst.next_pcs, (3, 3, 12))
        ret_code_inst = code.at(3)
        self.assertEqual(ret_code_inst.next_pcs, ())

        # Verify basic block successors
        entry_block = code.entry_block
        succ_pcs = {succ.start_pc for succ in entry_block.successors}
        self.assertIn(3, succ_pcs)
        self.assertIn(12, succ_pcs)

    def test_straight_line_code_single_basic_block(self) -> None:
        # const-string v0, "Hello" (2 code units)
        # const/4 v1, #1 (1 code unit)
        # add-int v0, v0, v1 (1 code unit)
        # return-void (1 code unit)
        code_bytes = (
            b"\x1a\x00\x00\x00"  # 0000: const-string v0, string@0
            b"\x12\x10"  # 0002: const/4 v1, #1
            b"\x90\x00\x00\x01"  # 0003: add-int v0, v0, v1
            b"\x0e\x00"  # 0005: return-void
        )
        dex_bytes = build_dex_bytes(
            [
                {
                    "name": "Lcom/example/StraightLineTest;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": 1,
                    "direct_methods": [
                        {
                            "name": "run",
                            "return_type": "V",
                            "params": [],
                            "access_flags": 1,
                            "code": code_bytes,
                        }
                    ],
                }
            ]
        )
        loader = ClassLoader.from_elements([DexFile(dex_bytes)])
        m = loader["com.example.StraightLineTest"].get_method("run")
        assert m is not None and m.code is not None
        code = m.code

        # Entire method must form exactly 1 basic block containing all 4 instructions
        self.assertEqual(len(code.blocks), 1)
        block = code.entry_block
        self.assertTrue(block.is_entry)
        self.assertTrue(block.is_exit)
        self.assertEqual(block.start_pc, 0)
        self.assertEqual(block.end_pc, 6)
        self.assertEqual(len(block.instructions), 4)
        self.assertEqual(block.terminator.opcode, Opcode.RETURN_VOID)
        self.assertEqual(block.predecessors, ())
        self.assertEqual(block.successors, ())

    def test_unconditional_branch_and_catch_leaders(self) -> None:
        # PC 0: const/4 v0, #0
        # PC 1: goto +3 -> PC 4
        # PC 3: return-void (unreachable/dead or target of jump)
        # PC 4: return-void
        goto_insn = Goto(a=BranchOffset(3))  # 1 unit, target_pc = 1 + 3 = 4
        ret_insn = ReturnVoid()  # 1 unit

        code_stream = (
            b"\x12\x00"  # 0000: const/4 v0, #0
            + goto_insn.to_bytes()  # 0001: goto +3 -> 0004
            + ret_insn.to_bytes()  # 0002: return-void
            + ret_insn.to_bytes()  # 0003: return-void
            + ret_insn.to_bytes()  # 0004: return-void
        )

        dex_bytes = build_dex_bytes(
            [
                {
                    "name": "Lcom/example/BranchTest;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": 1,
                    "direct_methods": [
                        {
                            "name": "run",
                            "return_type": "V",
                            "params": [],
                            "access_flags": 1,
                            "code": code_stream,
                        }
                    ],
                }
            ]
        )
        loader = ClassLoader.from_elements([DexFile(dex_bytes)])
        m = loader["com.example.BranchTest"].get_method("run")
        assert m is not None and m.code is not None
        code = m.code

        # Leaders should be:
        # PC 0 (entry)
        # PC 2 (follower of goto)
        # PC 4 (target of goto)
        # PC 3 is follower of return-void at PC 2
        block0 = code.get_block_at(0)
        assert block0 is not None
        self.assertEqual(block0.start_pc, 0)
        self.assertEqual(block0.end_pc, 2)
        self.assertEqual(len(block0.instructions), 2)
        self.assertEqual(block0.terminator.mnemonic, "goto")

        succ_start_pcs = [b.start_pc for b in block0.successors]
        self.assertEqual(succ_start_pcs, [4])

    def test_field_and_method_disassemble(self) -> None:
        dex_bytes = build_dex_bytes(
            [
                {
                    "name": "Lcom/example/DisasmTest;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": int(AccessFlags.PUBLIC),
                    "static_fields": [
                        {
                            "name": "TAG",
                            "type": "Ljava/lang/String;",
                            "access_flags": int(
                                AccessFlags.PUBLIC | AccessFlags.STATIC | AccessFlags.FINAL
                            ),
                            "value": EncodedValue(
                                value_arg=0, value_type=ValueType.STRING, value="MyTag"
                            ),
                        }
                    ],
                    "instance_fields": [
                        {
                            "name": "counter",
                            "type": "I",
                            "access_flags": int(AccessFlags.PRIVATE),
                        }
                    ],
                    "direct_methods": [
                        {
                            "name": "<init>",
                            "return_type": "V",
                            "params": [],
                            "access_flags": int(AccessFlags.PUBLIC | AccessFlags.CONSTRUCTOR),
                            "code": b"\x0e\x00",  # return-void
                        }
                    ],
                    "virtual_methods": [
                        {
                            "name": "abstractMethod",
                            "return_type": "I",
                            "params": [],
                            "access_flags": int(AccessFlags.PUBLIC | AccessFlags.ABSTRACT),
                        }
                    ],
                }
            ]
        )
        loader = ClassLoader.from_elements([DexFile(dex_bytes)])
        cls = loader["com.example.DisasmTest"]

        f_tag = cls.get_field("TAG")
        self.assertIsNotNone(f_tag)
        assert f_tag is not None
        self.assertEqual(
            f_tag.disassemble(),
            ".field public static final TAG:Ljava/lang/String; = 5",
        )

        f_counter = cls.get_field("counter")
        self.assertIsNotNone(f_counter)
        assert f_counter is not None
        self.assertEqual(f_counter.disassemble(), ".field private counter:I")

        m_init = cls.get_method("<init>")
        self.assertIsNotNone(m_init)
        assert m_init is not None
        m_init_dis = m_init.disassemble()
        self.assertTrue(m_init_dis.startswith(".method public constructor <init>()V"))
        self.assertIn(".registers", m_init_dis)
        self.assertIn("return-void", m_init_dis)

        m_abstract = cls.get_method("abstractMethod")
        self.assertIsNotNone(m_abstract)
        assert m_abstract is not None
        self.assertEqual(
            m_abstract.disassemble(),
            ".method public abstract abstractMethod()I",
        )

    def test_code_instruction_target_field_and_method_descriptors(self) -> None:
        code_bytes = (
            Sget(a=Reg(0), b=Idx[FieldIdItem](0)).to_bytes()
            + InvokeStaticRange(a=ArgumentCount(1), b=Idx[MethodIdItem](0), c=Reg(0)).to_bytes()
            + ReturnVoid().to_bytes()
        )

        dex_bytes = build_dex_bytes(
            [
                {
                    "name": "Lcom/example/TargetTest;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": int(AccessFlags.PUBLIC),
                    "static_fields": [
                        {
                            "name": "TAG",
                            "type": "Ljava/lang/String;",
                            "access_flags": int(
                                AccessFlags.PUBLIC | AccessFlags.STATIC | AccessFlags.FINAL
                            ),
                        }
                    ],
                    "direct_methods": [
                        {
                            "name": "helper",
                            "return_type": "V",
                            "params": ["I"],
                            "access_flags": int(AccessFlags.PUBLIC | AccessFlags.STATIC),
                            "code": code_bytes,
                        }
                    ],
                }
            ]
        )
        loader = ClassLoader.from_elements([DexFile(dex_bytes)])
        m = loader["com.example.TargetTest"].get_method("helper")
        self.assertIsNotNone(m)
        assert m is not None and m.code is not None

        inst0 = m.code.at(0)
        self.assertEqual(inst0.target_field_class_descriptor, "Lcom/example/TargetTest;")
        self.assertEqual(inst0.target_field_name, "TAG")
        self.assertEqual(inst0.target_field_type_descriptor, "Ljava/lang/String;")
        self.assertEqual(
            inst0.target_field_full_descriptor,
            "Lcom/example/TargetTest;->TAG:Ljava/lang/String;",
        )

        inst1 = m.code.at(2)
        self.assertEqual(inst1.target_method_class_descriptor, "Lcom/example/TargetTest;")
        self.assertEqual(inst1.target_method_name, "helper")
        self.assertEqual(inst1.target_method_descriptor, "(I)V")
        self.assertEqual(
            inst1.target_method_full_descriptor,
            "Lcom/example/TargetTest;->helper(I)V",
        )

        dis = m.code.disassemble()
        self.assertIn("sget v0, Lcom/example/TargetTest;->TAG:Ljava/lang/String;", dis)
        self.assertIn("invoke-static-range v0, Lcom/example/TargetTest;->helper(I)V", dis)

    def test_code_instruction_disassemble_forms(self) -> None:
        c_str = ConstString(a=Reg(0), b=Idx[StringIdItem](0)).to_bytes()
        c_4 = Const4(a=Reg(1), b=Literal(1)).to_bytes()
        g_to = Goto(a=BranchOffset(2)).to_bytes()
        r_void = ReturnVoid().to_bytes()

        code_bytes = c_str + c_4 + g_to + r_void + r_void

        dex_bytes = build_dex_bytes(
            [
                {
                    "name": "Lcom/example/InstDisasm;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": 1,
                    "direct_methods": [
                        {
                            "name": "test",
                            "return_type": "V",
                            "params": [],
                            "access_flags": 1,
                            "code": code_bytes,
                        }
                    ],
                }
            ]
        )
        loader = ClassLoader.from_elements([DexFile(dex_bytes)])
        m = loader["com.example.InstDisasm"].get_method("test")
        assert m is not None and m.code is not None

        # String instruction
        inst0 = m.code.at(0)
        self.assertEqual(inst0.disassemble(), '0000: const-string v0, "Lcom/example/InstDisasm;"')

        # Literal instruction
        inst2 = m.code.at(2)
        self.assertEqual(inst2.disassemble(), "0002: const-4 p0, #1")

        # Branch instruction with target_pc
        inst3 = m.code.at(3)
        self.assertEqual(inst3.disassemble(), "0003: goto # 0005")

        # Return void instruction
        inst5 = m.code.at(5)
        self.assertEqual(inst5.disassemble(), "0005: return-void")

    def test_exception_edges_and_handlers(self) -> None:
        # Build full code item with try/catch blocks using raw bytes
        # Try item covering PC 0000..0002 with handler at PC 0003
        # PC 0000: const/4 v0, #0
        # PC 0001: return-void
        # PC 0002: const/4 v0, #1
        # PC 0003: move-exception v0
        # PC 0004: return-void
        insns = b"\x12\x00\x0e\x00\x12\x10\x0d\x00\x0e\x00"

        # CodeItem header (16 bytes):
        # registers_size=2, ins_size=0, outs_size=0, tries_size=1, debug_info_off=0, insns_size=5
        header = struct.pack("<4H2I", 2, 0, 0, 1, 0, 5)
        # padding to 4 bytes offset: 16 + 10 = 26 -> 2 bytes padding to 28
        padding = b"\x00\x00"
        # TryItem (8 bytes): start_addr=0, insn_count=2, handler_off=1
        try_item = struct.pack("<IHH", 0, 2, 1)
        # CatchHandlerList:
        # encoded_catch_handler_list size = 1 (ULEB128 0x01)
        # handler at offset 1:
        # size = 1 (ULEB128 0x01) -> 1 typed handler
        # handler pair: type_idx=0 (ULEB128 0x00), addr=3 (ULEB128 0x03)
        # catch_all_addr: none (since size > 0 and no catch all)
        handlers = b"\x01\x01\x00\x03"

        full_code_bytes = header + insns + padding + try_item + handlers

        dex_bytes = build_dex_bytes(
            [
                {
                    "name": "Lcom/example/TryCatchTest;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": 1,
                    "direct_methods": [
                        {
                            "name": "run",
                            "return_type": "V",
                            "params": [],
                            "access_flags": 1,
                            "code": full_code_bytes,
                            "is_full_code_item": True,
                        }
                    ],
                }
            ]
        )
        loader = ClassLoader.from_elements([DexFile(dex_bytes)])
        m = loader["com.example.TryCatchTest"].get_method("run")
        assert m is not None and m.code is not None
        code = m.code

        # Basic blocks:
        # Block #0 [0..2] - protected block
        # Block #1 [2..3]
        # Block #2 [3..5] - catch handler block
        self.assertGreaterEqual(len(code.blocks), 3)

        block0 = code.get_block_at(0)
        assert block0 is not None
        self.assertEqual(len(block0.catch_edges), 1)

        edge = block0.catch_edges[0]
        self.assertIsInstance(edge, CatchEdge)
        self.assertIsInstance(edge.handler, CatchHandler)
        self.assertIs(edge.source_block, block0)
        self.assertEqual(edge.target_block.start_pc, 3)
        self.assertIsInstance(edge.try_catch, TryCatch)
        self.assertEqual(edge.try_catch.start_pc, 0)
        self.assertEqual(edge.try_catch.end_pc, 2)
        self.assertEqual(edge.target_pc, 3)
        self.assertEqual(edge.type_name, "com.example.TryCatchTest")

        self.assertEqual(block0.exception_successors, (edge.target_block,))
        self.assertEqual(block0.exception_handlers, (edge.handler,))

        handler_block = block0.exception_successors[0]
        self.assertTrue(handler_block.is_catch_handler)
        self.assertEqual(handler_block.incoming_catch_edges, (edge,))
        self.assertEqual(handler_block.exception_predecessors, (block0,))
        self.assertEqual(len(handler_block.handled_catches), 1)
        self.assertEqual(handler_block.handled_catches[0], edge.handler)
        self.assertEqual(handler_block.protected_blocks, (block0,))

        # Block disassembly formatting check with CFG comments
        dis = code.disassemble()
        self.assertIn("; preds:", dis)
        self.assertIn("; succs:", dis)
        self.assertNotIn("; preds: none", dis)
        self.assertNotIn("; succs: none", dis)

        # Block 0 has no normal predecessors or successors,
        # so neither ; preds: nor ; succs: should appear
        self.assertNotIn("; preds:", block0.disassemble())
        self.assertNotIn("; succs:", block0.disassemble())
        self.assertIn("; handler for: Lcom/example/TryCatchTest;", dis)
        self.assertIn("; catches: Lcom/example/TryCatchTest; -> #2", dis)

    def test_get_block_at_binary_search_and_boundaries(self) -> None:
        # const-string v0, "Hello" (op=0x1a, 2 code units: PC 0..2)
        # const/4 v1, #1          (op=0x12, 1 code unit:  PC 2..3)
        # if-eqz v1, +4           (op=0x38, 2 code units: PC 3..5, branch target PC 7)
        # return-void             (op=0x0e, 1 code unit:  PC 5..6)
        # const/4 v0, #2          (op=0x12, 1 code unit:  PC 6..7)
        # return-void             (op=0x0e, 1 code unit:  PC 7..8)
        code_bytes = (
            b"\x1a\x00\x00\x00"  # 0000..0002
            b"\x12\x10"  # 0002..0003
            b"\x38\x01\x04\x00"  # 0003..0005 (target 0007)
            b"\x0e\x00"  # 0005..0006
            b"\x12\x20"  # 0006..0007
            b"\x0e\x00"  # 0007..0008
        )

        dex_bytes = build_dex_bytes(
            [
                {
                    "name": "Lcom/example/GetBlockAtTest;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": 1,
                    "direct_methods": [
                        {
                            "name": "testMethod",
                            "return_type": "V",
                            "params": [],
                            "access_flags": 1,
                            "code": code_bytes,
                        }
                    ],
                }
            ]
        )
        loader = ClassLoader.from_elements([DexFile(dex_bytes)])
        m = loader["com.example.GetBlockAtTest"].get_method("testMethod")
        assert m is not None and m.code is not None
        code = m.code

        # Verify block partitioning:
        # Leaders: 0 (entry), 5 (if-eqz fallthrough), 6 (return-void follower), 7 (if-eqz target)
        # Block #0: PC 0..5
        # Block #1: PC 5..6
        # Block #2: PC 6..7
        # Block #3: PC 7..8
        self.assertEqual(len(code.blocks), 4)
        b0, b1, b2, b3 = code.blocks
        self.assertEqual((b0.start_pc, b0.end_pc), (0, 5))
        self.assertEqual((b1.start_pc, b1.end_pc), (5, 6))
        self.assertEqual((b2.start_pc, b2.end_pc), (6, 7))
        self.assertEqual((b3.start_pc, b3.end_pc), (7, 8))

        # Boundary checks for Block #0 [0..5)
        self.assertIs(code.get_block_at(0), b0)  # start_pc
        self.assertIs(code.get_block_at(2), b0)  # middle PC (start of instruction)
        self.assertIs(code.get_block_at(4), b0)  # end_pc - 1

        # Boundary checks for Block #1 [5..6)
        self.assertIs(code.get_block_at(5), b1)  # start_pc and end_pc - 1

        # Boundary checks for Block #2 [6..7)
        self.assertIs(code.get_block_at(6), b2)  # start_pc and end_pc - 1

        # Boundary checks for Block #3 [7..8)
        self.assertIs(code.get_block_at(7), b3)  # start_pc and end_pc - 1

        # Out-of-bounds checks
        self.assertIsNone(code.get_block_at(-1))  # negative PC
        self.assertIsNone(code.get_block_at(8))  # at method end PC
        self.assertIsNone(code.get_block_at(100))  # far out-of-bounds PC

    def test_code_delegation_and_basicblock_get(self) -> None:
        # const-string v0, "Hello" (2 code units: PC 0..2)
        # const/4 v1, #1          (1 code unit:  PC 2..3)
        # if-eqz v1, +4           (2 code units: PC 3..5, branch target PC 7)
        # return-void             (1 code unit:  PC 5..6)
        # const/4 v0, #2          (1 code unit:  PC 6..7)
        # return-void             (1 code unit:  PC 7..8)
        code_bytes = (
            b"\x1a\x00\x00\x00"  # 0000..0002
            b"\x12\x10"  # 0002..0003
            b"\x38\x01\x04\x00"  # 0003..0005 (target 0007)
            b"\x0e\x00"  # 0005..0006
            b"\x12\x20"  # 0006..0007
            b"\x0e\x00"  # 0007..0008
        )

        dex_bytes = build_dex_bytes(
            [
                {
                    "name": "Lcom/example/CodeDelegationTest;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": 1,
                    "direct_methods": [
                        {
                            "name": "testMethod",
                            "return_type": "V",
                            "params": [],
                            "access_flags": 1,
                            "code": code_bytes,
                        }
                    ],
                }
            ]
        )
        loader = ClassLoader.from_elements([DexFile(dex_bytes)])
        m = loader["com.example.CodeDelegationTest"].get_method("testMethod")
        assert m is not None and m.code is not None
        code = m.code

        # Iteration across block boundaries in execution order
        insts = list(code)
        self.assertEqual(len(insts), 6)
        self.assertEqual(len(code), 6)
        pcs = [inst.pc for inst in insts]
        self.assertEqual(pcs, [0, 2, 3, 5, 6, 7])

        # Test code.at(pc), code.get(pc), pc in code
        for expected_pc in [0, 2, 3, 5, 6, 7]:
            self.assertIn(expected_pc, code)
            inst = code.at(expected_pc)
            self.assertEqual(inst.pc, expected_pc)
            self.assertEqual(code.get(expected_pc), inst)

        # Missing PCs
        self.assertNotIn(1, code)
        self.assertNotIn(4, code)
        self.assertNotIn(8, code)
        self.assertNotIn(-1, code)
        self.assertNotIn("invalid", code)

        self.assertIsNone(code.get(1))
        self.assertIsNone(code.get(8))
        with self.assertRaises(KeyError):
            code.at(1)

        # BasicBlock.get(pc) tests
        b0 = code.get_block_at(0)
        assert b0 is not None
        inst_0 = b0.get(0)
        inst_2 = b0.get(2)
        inst_3 = b0.get(3)
        self.assertIsNotNone(inst_0)
        self.assertIsNotNone(inst_2)
        self.assertIsNotNone(inst_3)
        assert inst_0 is not None
        assert inst_2 is not None
        assert inst_3 is not None
        self.assertEqual(inst_0.pc, 0)
        self.assertEqual(inst_2.pc, 2)
        self.assertEqual(inst_3.pc, 3)

        # Invalid PC within block range or outside block range
        self.assertIsNone(b0.get(1))
        self.assertIsNone(b0.get(5))


if __name__ == "__main__":
    unittest.main()
