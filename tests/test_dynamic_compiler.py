"""Integration tests verifying dexbuf using dynamic Java-to-DEX compilation."""

import unittest

import dexbuf
from dexbuf.instructions import PackedSwitchPayload, SparseSwitchPayload
from dexbuf.model import ResolvedClass, UnresolvedClass
from tests.helpers import compile_java_to_dex, skip_unless_dex_compiler


@skip_unless_dex_compiler()
class TestDynamicCompilerIntegration(unittest.TestCase):
    """Integration test suite utilizing dynamic javac + d8 compilation."""

    def test_basic_class_and_members(self) -> None:
        """Verify class, field, constructor, and method parsing on compiler-emitted DEX."""
        java_source = """
        package com.example;

        public class SampleCalculator {
            public static final int MAX_VALUE = 1000;
            private int initialValue;

            public SampleCalculator(int initialValue) {
                this.initialValue = initialValue;
            }

            public int add(int x) {
                return this.initialValue + x;
            }

            public static int multiply(int a, int b) {
                return a * b;
            }
        }
        """
        dex_bytes = compile_java_to_dex(java_source, "com.example.SampleCalculator")

        # Low-level DexFile validation
        dex_file = dexbuf.DexFile(dex_bytes)
        self.assertEqual(len(dex_file.class_defs), 1)

        # High-level ClassLoader model validation
        with dexbuf.load(dex_bytes) as loader:
            self.assertIn("com.example.SampleCalculator", loader)
            cls = loader["com.example.SampleCalculator"]
            self.assertIsInstance(cls, ResolvedClass)
            self.assertEqual(cls.name, "com.example.SampleCalculator")
            self.assertEqual(cls.package, "com.example")
            self.assertEqual(cls.simple_name, "SampleCalculator")
            self.assertTrue(cls.is_public)
            self.assertFalse(cls.is_interface)

            # Super class resolution (java.lang.Object)
            self.assertIsNotNone(cls.super_class)
            self.assertIsInstance(cls.super_class, UnresolvedClass)
            self.assertEqual(cls.super_class.name, "java.lang.Object")

            # Field inspections
            self.assertEqual(len(cls.fields), 2)
            max_field = cls.get_field("MAX_VALUE")
            self.assertIsNotNone(max_field)
            self.assertTrue(max_field.is_static)
            self.assertTrue(max_field.is_public)
            self.assertTrue(max_field.is_final)
            self.assertEqual(max_field.type_name, "int")

            init_field = cls.get_field("initialValue")
            self.assertIsNotNone(init_field)
            self.assertFalse(init_field.is_static)
            self.assertTrue(init_field.is_private)
            self.assertEqual(init_field.type_name, "int")

            # Method inspections
            add_method = cls.get_method("add")
            self.assertIsNotNone(add_method)
            self.assertEqual(add_method.descriptor, "(I)I")
            self.assertTrue(add_method.is_public)
            self.assertTrue(add_method.has_code)

            multiply_method = cls.get_method("multiply")
            self.assertIsNotNone(multiply_method)
            self.assertTrue(multiply_method.is_static)
            self.assertTrue(multiply_method.is_public)
            self.assertEqual(multiply_method.descriptor, "(II)I")

            # Disassembly verification
            dump = add_method.disassemble()
            self.assertIn(".method public add(I)I", dump)
            self.assertIn("return", dump)

    def test_try_catch_finally_exception_handling(self) -> None:
        """Verify try-catch exception structure and basic block catch edges."""
        java_source = """
        package com.example;

        public class ExceptionHandler {
            public int parseAndProcess(String input) {
                try {
                    int val = Integer.parseInt(input);
                    return val * 2;
                } catch (NumberFormatException e) {
                    return -1;
                } catch (Exception e) {
                    return -2;
                }
            }
        }
        """
        dex_bytes = compile_java_to_dex(java_source, "com.example.ExceptionHandler")

        with dexbuf.load(dex_bytes) as loader:
            cls = loader["com.example.ExceptionHandler"]
            method = cls.get_method("parseAndProcess")
            self.assertIsNotNone(method)
            self.assertTrue(method.has_code)
            self.assertIsNotNone(method.code)

            code = method.code
            # Underlying raw CodeItem has non-empty try items
            self.assertIsNotNone(code.raw.tries)
            self.assertGreater(len(code.raw.tries), 0)

            # Check that at least one basic block has exception catch edges
            protected_blocks = [b for b in code.blocks if b.catch_edges]
            self.assertGreater(len(protected_blocks), 0)

            catch_descriptors = {
                ce.type_descriptor for block in protected_blocks for ce in block.catch_edges
            }
            self.assertIn("Ljava/lang/NumberFormatException;", catch_descriptors)
            self.assertIn("Ljava/lang/Exception;", catch_descriptors)

            catch_type_names = {
                ce.type_name for block in protected_blocks for ce in block.catch_edges
            }
            self.assertIn("java.lang.NumberFormatException", catch_type_names)
            self.assertIn("java.lang.Exception", catch_type_names)

    def test_packed_and_sparse_switch_payloads(self) -> None:
        """Verify packed-switch and sparse-switch instructions and payloads."""
        java_source = """
        package com.example;

        public class SwitchHandler {
            public int testPacked(int val) {
                switch (val) {
                    case 10: return 100;
                    case 11: return 200;
                    case 12: return 300;
                    default: return -1;
                }
            }

            public int testSparse(int val) {
                switch (val) {
                    case 100: return 1;
                    case 500: return 2;
                    case 1000: return 3;
                    default: return -1;
                }
            }
        }
        """
        dex_bytes = compile_java_to_dex(java_source, "com.example.SwitchHandler")

        with dexbuf.load(dex_bytes) as loader:
            cls = loader["com.example.SwitchHandler"]

            # Packed switch test
            packed_method = cls.get_method("testPacked")
            self.assertIsNotNone(packed_method)
            self.assertIsNotNone(packed_method.code)

            packed_payloads = [
                inst.payload
                for inst in packed_method.code
                if isinstance(inst.payload, PackedSwitchPayload)
            ]
            self.assertEqual(len(packed_payloads), 1)
            packed_payload = packed_payloads[0]
            self.assertEqual(packed_payload.first_key, 10)
            self.assertEqual(len(packed_payload.targets), 3)

            # Sparse switch test
            sparse_method = cls.get_method("testSparse")
            self.assertIsNotNone(sparse_method)
            self.assertIsNotNone(sparse_method.code)

            sparse_payloads = [
                inst.payload
                for inst in sparse_method.code
                if isinstance(inst.payload, SparseSwitchPayload)
            ]
            self.assertEqual(len(sparse_payloads), 1)
            sparse_payload = sparse_payloads[0]
            self.assertEqual(sparse_payload.keys, (100, 500, 1000))
            self.assertEqual(len(sparse_payload.targets), 3)

    def test_interface_definition_and_default_methods(self) -> None:
        """Verify interface class definition with abstract and default methods."""
        java_source = """
        package com.example;

        public interface ServiceInterface {
            String process(String data);

            default String processWithPrefix(String prefix, String data) {
                return prefix + ":" + process(data);
            }
        }
        """
        dex_bytes = compile_java_to_dex(java_source, "com.example.ServiceInterface")

        with dexbuf.load(dex_bytes) as loader:
            cls = loader["com.example.ServiceInterface"]
            self.assertTrue(cls.is_interface)
            self.assertTrue(cls.is_abstract)

            # Abstract method has no code
            process_method = cls.get_method("process")
            self.assertIsNotNone(process_method)
            self.assertTrue(process_method.is_abstract)
            self.assertFalse(process_method.has_code)
            self.assertIsNone(process_method.code)

            # Default method in interface has code
            default_method = cls.get_method("processWithPrefix")
            self.assertIsNotNone(default_method)
            self.assertFalse(default_method.is_abstract)
            self.assertTrue(default_method.has_code)
            self.assertIsNotNone(default_method.code)


if __name__ == "__main__":
    unittest.main()
