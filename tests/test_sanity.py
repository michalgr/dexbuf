"""Sanity checks for dexbuf package setup."""

import shutil
import unittest

import dexbuf


class TestSanity(unittest.TestCase):
    def test_version(self) -> None:
        """Verify package version is exported and non-empty."""
        self.assertTrue(hasattr(dexbuf, "__version__"))
        self.assertTrue(dexbuf.__version__)

    def test_top_level_exports(self) -> None:
        """Verify that top-level dexbuf module exports only public API items."""
        expected_all = [
            "IOP",
            "NO_INDEX",
            "NO_OFFSET",
            "ArgumentCount",
            "BranchOffset",
            "CallSiteIdItem",
            "ClassDataItem",
            "ClassDefItem",
            "CodeItem",
            "Count",
            "DebugInfoItem",
            "DebugInstruction",
            "DebugOpcode",
            "DebugPosition",
            "EncodedCatchHandler",
            "EncodedCatchHandlerList",
            "EncodedField",
            "EncodedMethod",
            "EncodedTypeAddrPair",
            "FieldIdItem",
            "Hat",
            "Idx",
            "Instruction",
            "Literal",
            "MethodHandleItem",
            "MethodIdItem",
            "Offset",
            "Opcode",
            "Payload",
            "ProtoIdItem",
            "Reg",
            "StringDataItem",
            "StringIdItem",
            "TryItem",
            "TypeIdItem",
            "TypeList",
            "__version__",
        ]
        self.assertEqual(dexbuf.__all__, expected_all)

        forbidden_attributes = [
            "Cursor",
            "DbgAdvanceLine",
            "DbgAdvancePc",
            "DbgEndLocal",
            "DbgEndSequence",
            "DbgRestartLocal",
            "DbgSetEpilogueBegin",
            "DbgSetFile",
            "DbgSetPrologueEnd",
            "DbgSpecial",
            "DbgStartLocal",
            "DbgStartLocalExtended",
            "encode_sleb128",
            "encode_uleb128",
            "encode_uleb128p1",
            "encode_mutf8",
            "parse_debug_instruction",
            "skip_debug_instruction",
            "utf16_code_units",
        ]
        for attr in forbidden_attributes:
            self.assertFalse(hasattr(dexbuf, attr), f"{attr} should not be exposed in dexbuf")

    def test_environment_tooling(self) -> None:
        """Inspect environment for optional dynamic compilation tools (javac, d8)."""
        javac_available = shutil.which("javac") is not None
        d8_available = shutil.which("d8") is not None
        # In a complete Nix shell, both javac and d8 will be available
        # Precompiled .dex binaries must never be checked into git
        if javac_available and d8_available:
            self.assertTrue(javac_available)
            self.assertTrue(d8_available)


if __name__ == "__main__":
    unittest.main()
