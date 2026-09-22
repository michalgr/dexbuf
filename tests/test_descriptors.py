"""Unit tests for Dalvik descriptor and Java type conversion utilities."""

import unittest

from dexbuf.descriptors import (
    descriptor_to_type_name,
    format_method_descriptor,
    parse_method_descriptor,
    type_name_to_descriptor,
)


class TestDescriptors(unittest.TestCase):
    def test_descriptor_to_type_name_primitives(self) -> None:
        """Verify converting primitive type descriptors to Java type names."""
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
        for desc, expected in primitives.items():
            self.assertEqual(descriptor_to_type_name(desc), expected)

    def test_descriptor_to_type_name_classes(self) -> None:
        """Verify converting class descriptors to canonical Java class names."""
        classes = {
            "Ljava/lang/String;": "java.lang.String",
            "Lcom/example/MyClass;": "com.example.MyClass",
            "Lcom/example/Outer$Inner;": "com.example.Outer$Inner",
            "LSimpleClass;": "SimpleClass",
        }
        for desc, expected in classes.items():
            self.assertEqual(descriptor_to_type_name(desc), expected)

    def test_descriptor_to_type_name_arrays(self) -> None:
        """Verify converting array descriptors to Java array type names."""
        arrays = {
            "[I": "int[]",
            "[[Ljava/lang/String;": "java.lang.String[][]",
            "[[[Z": "boolean[][][]",
            "[[[Lcom/example/MyClass;": "com.example.MyClass[][][]",
        }
        for desc, expected in arrays.items():
            self.assertEqual(descriptor_to_type_name(desc), expected)

    def test_descriptor_to_type_name_errors(self) -> None:
        """Verify that malformed descriptors raise ValueError."""
        invalid_descriptors = [
            "",
            "X",
            "[V",
            "[[V",
            "Ljava/lang/String",
            "L;",
            "L/Foo;",
            "LFoo/;",
            "LFoo//Bar;",
            "Lcom.example.Foo;",
            "Iextra",
            "Ljava/lang/String;I",
            "[",
            "[[",
        ]
        for desc in invalid_descriptors:
            with self.assertRaises(ValueError, msg=f"Expected ValueError for descriptor: {desc!r}"):
                descriptor_to_type_name(desc)

        # Non-string input
        with self.assertRaises(ValueError):
            descriptor_to_type_name(123)  # type: ignore[arg-type]

    def test_type_name_to_descriptor_primitives(self) -> None:
        """Verify converting Java primitive type names to descriptors."""
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
        for name, expected in primitives.items():
            self.assertEqual(type_name_to_descriptor(name), expected)

    def test_type_name_to_descriptor_classes(self) -> None:
        """Verify converting Java class names to class descriptors."""
        classes = {
            "java.lang.String": "Ljava/lang/String;",
            "com.example.MyClass": "Lcom/example/MyClass;",
            "com.example.Outer$Inner": "Lcom/example/Outer$Inner;",
            "SimpleClass": "LSimpleClass;",
        }
        for name, expected in classes.items():
            self.assertEqual(type_name_to_descriptor(name), expected)

    def test_type_name_to_descriptor_arrays(self) -> None:
        """Verify converting Java array type names to array descriptors."""
        arrays = {
            "int[]": "[I",
            "java.lang.String[][]": "[[Ljava/lang/String;",
            "boolean[][][]": "[[[Z",
            "com.example.MyClass[][][]": "[[[Lcom/example/MyClass;",
        }
        for name, expected in arrays.items():
            self.assertEqual(type_name_to_descriptor(name), expected)

    def test_type_name_to_descriptor_errors(self) -> None:
        """Verify that malformed type names raise ValueError."""
        invalid_names = [
            "",
            "void[]",
            "void[][]",
            "int[",
            "int[]extra",
            "int][",
            "com..example.MyClass",
            ".com.example.MyClass",
            "com.example.",
            "123Class",
            "com/example/MyClass",
            "com.example.My Class",
            "[]",
        ]
        for name in invalid_names:
            with self.assertRaises(ValueError, msg=f"Expected ValueError for type name: {name!r}"):
                type_name_to_descriptor(name)

        # Non-string input
        with self.assertRaises(ValueError):
            type_name_to_descriptor(None)  # type: ignore[arg-type]

    def test_parse_method_descriptor(self) -> None:
        """Verify parsing method descriptors into parameter tuples and return descriptors."""
        test_cases = [
            ("(ILjava/lang/String;)V", (("I", "Ljava/lang/String;"), "V")),
            ("()V", ((), "V")),
            ("(ZBCIJFD)I", (("Z", "B", "C", "I", "J", "F", "D"), "I")),
            (
                "([[I[Ljava/lang/String;)Ljava/lang/Object;",
                (("[[I", "[Ljava/lang/String;"), "Ljava/lang/Object;"),
            ),
        ]
        for desc, (expected_params, expected_ret) in test_cases:
            params, ret = parse_method_descriptor(desc)
            self.assertEqual(params, expected_params)
            self.assertEqual(ret, expected_ret)

    def test_parse_method_descriptor_errors(self) -> None:
        """Verify error handling for malformed method descriptors."""
        invalid_descriptors = [
            "",
            "ILjava/lang/String;)V",
            "(ILjava/lang/String;V",
            "(V)V",
            "(IV)V",
            "()",
            "()Vextra",
            "(X)V",
            "(I)Ljava/lang/String",
        ]
        for desc in invalid_descriptors:
            with self.assertRaises(
                ValueError, msg=f"Expected ValueError for method descriptor: {desc!r}"
            ):
                parse_method_descriptor(desc)

        # Non-string input
        with self.assertRaises(ValueError):
            parse_method_descriptor(123)  # type: ignore[arg-type]

    def test_format_method_descriptor(self) -> None:
        """Verify formatting parameter descriptors and return descriptor into method descriptor."""
        test_cases = [
            ((("I", "Ljava/lang/String;"), "V"), "(ILjava/lang/String;)V"),
            (((), "V"), "()V"),
            ((("[I", "[[Ljava/lang/Object;"), "Z"), "([I[[Ljava/lang/Object;)Z"),
        ]
        for (params, ret), expected in test_cases:
            self.assertEqual(format_method_descriptor(params, ret), expected)

    def test_format_method_descriptor_errors(self) -> None:
        """Verify error handling for invalid parameters in format_method_descriptor."""
        with self.assertRaises(ValueError):
            format_method_descriptor(["V"], "V")  # void parameter
        with self.assertRaises(ValueError):
            format_method_descriptor(["invalid"], "V")  # malformed param
        with self.assertRaises(ValueError):
            format_method_descriptor(["I"], "invalid")  # malformed return
        with self.assertRaises(ValueError):
            format_method_descriptor([123], "V")  # type: ignore[list-item]
        with self.assertRaises(ValueError):
            format_method_descriptor(["I"], 123)  # type: ignore[arg-type]

    def test_roundtrip_conversions(self) -> None:
        """Verify roundtrip bidirectional conversions for type and method descriptors."""
        type_descriptors = [
            "Z",
            "B",
            "S",
            "C",
            "I",
            "J",
            "F",
            "D",
            "V",
            "Ljava/lang/String;",
            "Lcom/example/MyClass$Inner;",
            "[I",
            "[[Ljava/lang/String;",
            "[[[Z",
        ]
        for desc in type_descriptors:
            name = descriptor_to_type_name(desc)
            reconverted = type_name_to_descriptor(name)
            self.assertEqual(desc, reconverted)

        method_descriptors = [
            "()V",
            "(ILjava/lang/String;)V",
            "([[I[Ljava/lang/String;)Ljava/lang/Object;",
            "(ZBCIJFD)I",
        ]
        for mdesc in method_descriptors:
            params, ret = parse_method_descriptor(mdesc)
            formatted = format_method_descriptor(params, ret)
            self.assertEqual(mdesc, formatted)


if __name__ == "__main__":
    unittest.main()
