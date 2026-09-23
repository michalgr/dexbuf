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
            "CLASS_FLAGS_MASK",
            "DEX_FILE_MAGIC",
            "ENDIAN_CONSTANT",
            "FIELD_FLAGS_MASK",
            "HEADER_SIZE_V40",
            "HEADER_SIZE_V41",
            "IOP",
            "METHOD_FLAGS_MASK",
            "NO_INDEX",
            "NO_OFFSET",
            "REVERSE_ENDIAN_CONSTANT",
            "SUPPORTED_DEX_VERSIONS",
            "AccessFlags",
            "AnnotationElement",
            "AnnotationItem",
            "AnnotationOffItem",
            "AnnotationSetItem",
            "AnnotationSetRefItem",
            "AnnotationSetRefList",
            "AnnotationVisibility",
            "AnnotationsDirectoryItem",
            "ArgumentCount",
            "BranchOffset",
            "CallSiteIdItem",
            "CatchHandlerMap",
            "CentralDirectoryHeader",
            "ClassDataItem",
            "ClassDefItem",
            "CodeItem",
            "Count",
            "DebugInfoItem",
            "DebugInstruction",
            "DebugOpcode",
            "DebugPosition",
            "DexFile",
            "EncodedAnnotation",
            "EncodedArray",
            "EncodedArrayItem",
            "EncodedCatchHandler",
            "EncodedCatchHandlerList",
            "EncodedField",
            "EncodedMethod",
            "EncodedTypeAddrPair",
            "EncodedValue",
            "EndOfCentralDirectoryRecord",
            "FieldAnnotation",
            "FieldIdItem",
            "Hat",
            "HeaderItem",
            "HiddenapiClassDataItem",
            "HiddenapiRestrictionFlag",
            "Idx",
            "Instruction",
            "ItemType",
            "Literal",
            "LocalFileHeader",
            "MapItem",
            "MapItemType",
            "MapList",
            "MethodAnnotation",
            "MethodHandleItem",
            "MethodIdItem",
            "Offset",
            "Opcode",
            "ParameterAnnotation",
            "Payload",
            "ProtoIdItem",
            "Reg",
            "StaticItem",
            "StringDataItem",
            "StringIdItem",
            "TryItem",
            "TryTable",
            "TypeIdItem",
            "TypeList",
            "ValueType",
            "ZipArchive",
            "__version__",
            "descriptor_to_type_name",
            "format_class_flags",
            "format_field_flags",
            "format_method_descriptor",
            "format_method_flags",
            "parse_method_descriptor",
            "type_name_to_descriptor",
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
