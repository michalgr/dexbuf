"""Unit tests for dexbuf descriptor and type name utilities."""

import unittest

from dexbuf.descriptors import (
    descriptor_to_type_name,
    format_method_descriptor,
    parse_method_descriptor,
    type_name_to_descriptor,
)


class TestDescriptors(unittest.TestCase):
    def test_primitive_descriptor_to_type_name(self) -> None:
        primitives = {
            "Z": "boolean",
            "B": "byte",
            "S": "short",
            "C": "char",
            "I": "int",
            "J": "long",
            "F": "float",
            "D": "double",
            "V": "void",
        }
        for desc, name in primitives.items():
            self.assertEqual(descriptor_to_type_name(desc), name)

    def test_primitive_type_name_to_descriptor(self) -> None:
        primitives = {
            "boolean": "Z",
            "byte": "B",
            "short": "S",
            "char": "C",
            "int": "I",
            "long": "J",
            "float": "F",
            "double": "D",
            "void": "V",
        }
        for name, desc in primitives.items():
            self.assertEqual(type_name_to_descriptor(name), desc)

    def test_class_descriptor_conversions(self) -> None:
        self.assertEqual(descriptor_to_type_name("Lcom/example/MyClass;"), "com.example.MyClass")
        self.assertEqual(type_name_to_descriptor("com.example.MyClass"), "Lcom/example/MyClass;")
        self.assertEqual(descriptor_to_type_name("Ljava/lang/String;"), "java.lang.String")
        self.assertEqual(type_name_to_descriptor("java.lang.String"), "Ljava/lang/String;")

    def test_array_descriptor_conversions(self) -> None:
        self.assertEqual(descriptor_to_type_name("[I"), "int[]")
        self.assertEqual(type_name_to_descriptor("int[]"), "[I")
        self.assertEqual(descriptor_to_type_name("[[Ljava/lang/String;"), "java.lang.String[][]")
        self.assertEqual(type_name_to_descriptor("java.lang.String[][]"), "[[Ljava/lang/String;")
        self.assertEqual(descriptor_to_type_name("[[[Z"), "boolean[][][]")
        self.assertEqual(type_name_to_descriptor("boolean[][][]"), "[[[Z")

    def test_roundtrip_conversions(self) -> None:
        descriptors = [
            "Z",
            "B",
            "S",
            "C",
            "I",
            "J",
            "F",
            "D",
            "V",
            "Ljava/lang/Object;",
            "Lcom/foo/Bar$Baz;",
            "[I",
            "[[Ljava/lang/String;",
            "[[[D",
        ]
        for desc in descriptors:
            name = descriptor_to_type_name(desc)
            res = type_name_to_descriptor(name)
            self.assertEqual(res, desc)

    def test_parse_method_descriptor(self) -> None:
        self.assertEqual(
            parse_method_descriptor("(ILjava/lang/String;)V"),
            (("I", "Ljava/lang/String;"), "V"),
        )
        self.assertEqual(parse_method_descriptor("()V"), ((), "V"))
        self.assertEqual(
            parse_method_descriptor("([I[Ljava/lang/Object;)Z"),
            (("[I", "[Ljava/lang/Object;"), "Z"),
        )

    def test_format_method_descriptor(self) -> None:
        self.assertEqual(
            format_method_descriptor(["I", "Ljava/lang/String;"], "V"),
            "(ILjava/lang/String;)V",
        )
        self.assertEqual(format_method_descriptor([], "V"), "()V")
        self.assertEqual(
            format_method_descriptor(["[I", "[Ljava/lang/Object;"], "Z"),
            "([I[Ljava/lang/Object;)Z",
        )

    def test_invalid_descriptor_to_type_name(self) -> None:
        invalid_descriptors = [
            "",
            "X",
            "Lcom/example/MyClass",
            "L;",
            "[",
            "[V",
            "I;",
            "Lcom.example.MyClass;",
            "Lcom/example/MyClass;extra",
        ]
        for desc in invalid_descriptors:
            with self.subTest(desc=desc):
                with self.assertRaises(ValueError):
                    descriptor_to_type_name(desc)

    def test_invalid_type_name_to_descriptor(self) -> None:
        invalid_names = [
            "",
            "void[]",
            "int[",
            "com/example/MyClass",
            "invalid name",
            "com..example",
            "[]int",
        ]
        for name in invalid_names:
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    type_name_to_descriptor(name)

    def test_invalid_method_descriptors(self) -> None:
        invalid_method_descs = [
            "",
            "ILjava/lang/String;)V",
            "(ILjava/lang/String;",
            "(V)V",
            "(I)X",
            "(I)Vextra",
            "((I))V",
        ]
        for desc in invalid_method_descs:
            with self.subTest(desc=desc):
                with self.assertRaises(ValueError):
                    parse_method_descriptor(desc)

    def test_format_method_descriptor_void_param(self) -> None:
        with self.assertRaises(ValueError):
            format_method_descriptor(["I", "V"], "V")


if __name__ == "__main__":
    unittest.main()
