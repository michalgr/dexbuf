"""Tests for field, method, and annotation domain models in dexbuf.model."""

import unittest
from collections.abc import Mapping
from types import MappingProxyType

from dexbuf import (
    AccessFlags,
    Annotation,
    AnnotationVisibility,
    ClassLoader,
    CodeItem,
    DexFile,
    EncodedValue,
    ResolvedClass,
    UnresolvedClass,
    ValueType,
)
from tests.builders import build_dex_bytes


class TestFieldDomainModel(unittest.TestCase):
    def test_class_without_fields(self) -> None:
        dex_bytes = build_dex_bytes(
            [{"name": "Lcom/example/NoFields;", "super": "Ljava/lang/Object;", "access_flags": 1}]
        )
        loader = ClassLoader.from_elements([DexFile(dex_bytes)])
        cls = loader["com.example.NoFields"]

        self.assertEqual(cls.fields, ())
        self.assertEqual(cls.static_fields, ())
        self.assertEqual(cls.instance_fields, ())
        self.assertIsNone(cls.get_field("any"))

    def test_static_and_instance_fields(self) -> None:
        dex_bytes = build_dex_bytes(
            [
                {
                    "name": "Lcom/example/Foo;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": 1,
                    "static_fields": [
                        {
                            "name": "TAG",
                            "type": "Ljava/lang/String;",
                            "access_flags": int(
                                AccessFlags.PUBLIC
                                | AccessFlags.STATIC
                                | AccessFlags.FINAL
                                | AccessFlags.SYNTHETIC
                            ),
                            "value": EncodedValue(
                                value_arg=0, value_type=ValueType.STRING, value="FOO_TAG"
                            ),
                        }
                    ],
                    "instance_fields": [
                        {
                            "name": "count",
                            "type": "I",
                            "access_flags": int(
                                AccessFlags.PRIVATE | AccessFlags.VOLATILE | AccessFlags.TRANSIENT
                            ),
                        }
                    ],
                }
            ]
        )
        loader = ClassLoader.from_elements([DexFile(dex_bytes)])
        cls = loader["com.example.Foo"]

        self.assertEqual(len(cls.fields), 2)
        self.assertEqual(len(cls.static_fields), 1)
        self.assertEqual(len(cls.instance_fields), 1)

        f_tag = cls.get_field("TAG")
        self.assertIsNotNone(f_tag)
        assert f_tag is not None

        self.assertEqual(f_tag.defining_class, cls)
        self.assertEqual(f_tag.name, "TAG")
        self.assertEqual(f_tag.type_descriptor, "Ljava/lang/String;")
        self.assertEqual(f_tag.type_name, "java.lang.String")
        self.assertTrue(f_tag.is_static)
        self.assertTrue(f_tag.is_public)
        self.assertFalse(f_tag.is_private)
        self.assertFalse(f_tag.is_protected)
        self.assertTrue(f_tag.is_final)
        self.assertFalse(f_tag.is_volatile)
        self.assertFalse(f_tag.is_transient)
        self.assertTrue(f_tag.is_synthetic)
        self.assertFalse(f_tag.is_enum)
        self.assertIsInstance(f_tag.initial_value, EncodedValue)
        assert f_tag.initial_value is not None
        self.assertEqual(f_tag.initial_value.value_type, ValueType.STRING)
        self.assertIsInstance(f_tag.initial_value.value, int)
        self.assertEqual(repr(f_tag), "<Field 'com.example.Foo.TAG: java.lang.String'>")
        self.assertEqual(str(f_tag), "com.example.Foo.TAG: java.lang.String")

        f_count = cls.get_field("count")
        self.assertIsNotNone(f_count)
        assert f_count is not None

        self.assertEqual(f_count.name, "count")
        self.assertEqual(f_count.type_descriptor, "I")
        self.assertEqual(f_count.type_name, "int")
        self.assertFalse(f_count.is_static)
        self.assertTrue(f_count.is_private)
        self.assertTrue(f_count.is_volatile)
        self.assertTrue(f_count.is_transient)
        self.assertIsNone(f_count.initial_value)

    def test_field_type_resolution(self) -> None:
        dex_bytes = build_dex_bytes(
            [
                {
                    "name": "Lcom/example/Holder;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": 1,
                    "instance_fields": [
                        {"name": "resolvedRef", "type": "Lcom/example/Target;", "access_flags": 1},
                        {
                            "name": "unresolvedRef",
                            "type": "Landroid/app/Activity;",
                            "access_flags": 1,
                        },
                        {"name": "primitiveInt", "type": "I", "access_flags": 1},
                    ],
                },
                {
                    "name": "Lcom/example/Target;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": 1,
                },
            ]
        )
        loader = ClassLoader.from_elements([DexFile(dex_bytes)])
        holder = loader["com.example.Holder"]

        f_res = holder.get_field("resolvedRef")
        assert f_res is not None
        self.assertIsInstance(f_res.type_class, ResolvedClass)
        self.assertEqual(f_res.type_class.name, "com.example.Target")
        self.assertIs(f_res.type, f_res.type_class)

        f_unres = holder.get_field("unresolvedRef")
        assert f_unres is not None
        self.assertIsInstance(f_unres.type_class, UnresolvedClass)
        self.assertEqual(f_unres.type_class.name, "android.app.Activity")

        f_prim = holder.get_field("primitiveInt")
        assert f_prim is not None
        self.assertIsInstance(f_prim.type_class, UnresolvedClass)
        self.assertEqual(f_prim.type_class.name, "int")

    def test_static_initial_values(self) -> None:
        ev_ival = EncodedValue(value_arg=3, value_type=ValueType.INT, value=42)
        ev_sval = EncodedValue(value_arg=0, value_type=ValueType.STRING, value="hello")
        ev_fval = EncodedValue(value_arg=3, value_type=ValueType.FLOAT, value=3.14)
        ev_bval = EncodedValue(value_arg=1, value_type=ValueType.BOOLEAN, value=True)
        ev_tval = EncodedValue(value_arg=0, value_type=ValueType.TYPE, value="Lcom/example/Values;")

        dex_bytes = build_dex_bytes(
            [
                {
                    "name": "Lcom/example/Values;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": 1,
                    "static_fields": [
                        {
                            "name": "iVal",
                            "type": "I",
                            "access_flags": 0x8,
                            "value": ev_ival,
                        },
                        {
                            "name": "sVal",
                            "type": "Ljava/lang/String;",
                            "access_flags": 0x8,
                            "value": ev_sval,
                        },
                        {
                            "name": "fVal",
                            "type": "F",
                            "access_flags": 0x8,
                            "value": ev_fval,
                        },
                        {
                            "name": "bVal",
                            "type": "Z",
                            "access_flags": 0x8,
                            "value": ev_bval,
                        },
                        {
                            "name": "tVal",
                            "type": "Ljava/lang/Class;",
                            "access_flags": 0x8,
                            "value": ev_tval,
                        },
                        {
                            "name": "uninitVal",
                            "type": "I",
                            "access_flags": 0x8,
                        },
                    ],
                }
            ]
        )
        loader = ClassLoader.from_elements([DexFile(dex_bytes)])
        cls = loader["com.example.Values"]

        f_ival = cls.get_field("iVal")
        assert f_ival is not None
        self.assertIsInstance(f_ival.initial_value, EncodedValue)
        self.assertEqual(f_ival.initial_value.value_type, ValueType.INT)
        self.assertEqual(f_ival.initial_value.value, 42)

        f_sval = cls.get_field("sVal")
        assert f_sval is not None
        self.assertIsInstance(f_sval.initial_value, EncodedValue)
        self.assertEqual(f_sval.initial_value.value_type, ValueType.STRING)

        f_fval = cls.get_field("fVal")
        assert f_fval is not None
        self.assertIsInstance(f_fval.initial_value, EncodedValue)
        self.assertEqual(f_fval.initial_value.value_type, ValueType.FLOAT)

        f_bval = cls.get_field("bVal")
        assert f_bval is not None
        self.assertIsInstance(f_bval.initial_value, EncodedValue)
        self.assertEqual(f_bval.initial_value.value_type, ValueType.BOOLEAN)

        f_tval = cls.get_field("tVal")
        assert f_tval is not None
        self.assertIsInstance(f_tval.initial_value, EncodedValue)
        self.assertEqual(f_tval.initial_value.value_type, ValueType.TYPE)

        f_uninit = cls.get_field("uninitVal")
        assert f_uninit is not None
        self.assertIsNone(f_uninit.initial_value)

    def test_field_equality_and_hash(self) -> None:
        dex_bytes = build_dex_bytes(
            [
                {
                    "name": "Lcom/example/Foo;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": 1,
                    "instance_fields": [
                        {"name": "fieldA", "type": "I", "access_flags": 1},
                        {"name": "fieldB", "type": "I", "access_flags": 1},
                    ],
                }
            ]
        )
        loader1 = ClassLoader.from_elements([DexFile(dex_bytes)])
        loader2 = ClassLoader.from_elements([DexFile(dex_bytes)])

        cls1 = loader1["com.example.Foo"]
        cls2 = loader2["com.example.Foo"]

        f1_a = cls1.get_field("fieldA")
        f1_a_again = cls1.get_field("fieldA")
        f1_b = cls1.get_field("fieldB")
        f2_a = cls2.get_field("fieldA")

        assert f1_a is not None and f1_a_again is not None and f1_b is not None and f2_a is not None

        self.assertEqual(f1_a, f1_a_again)
        self.assertEqual(hash(f1_a), hash(f1_a_again))

        self.assertNotEqual(f1_a, f1_b)
        self.assertNotEqual(f1_a, f2_a)  # Different loader identity on defining class
        self.assertNotEqual(f1_a, "not_a_field")


class TestMethodDomainModel(unittest.TestCase):
    def test_class_without_methods(self) -> None:
        dex_bytes = build_dex_bytes(
            [{"name": "Lcom/example/NoMethods;", "super": "Ljava/lang/Object;", "access_flags": 1}]
        )
        loader = ClassLoader.from_elements([DexFile(dex_bytes)])
        cls = loader["com.example.NoMethods"]

        self.assertEqual(cls.methods, ())
        self.assertEqual(cls.direct_methods, ())
        self.assertEqual(cls.virtual_methods, ())
        self.assertEqual(cls.constructors, ())
        self.assertIsNone(cls.get_method("any"))
        self.assertEqual(cls.find_methods("any"), [])

    def test_direct_virtual_methods_and_constructors(self) -> None:
        dex_bytes = build_dex_bytes(
            [
                {
                    "name": "Lcom/example/Foo;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": 1,
                    "direct_methods": [
                        {
                            "name": "<init>",
                            "return_type": "V",
                            "params": ["I"],
                            "access_flags": int(AccessFlags.PUBLIC | AccessFlags.CONSTRUCTOR),
                            "code": b"\x0e\x00\x0e\x00",
                        },
                        {
                            "name": "<clinit>",
                            "return_type": "V",
                            "params": [],
                            "access_flags": int(
                                AccessFlags.STATIC | AccessFlags.CONSTRUCTOR | AccessFlags.SYNTHETIC
                            ),
                            "code": b"\x0e\x00\x0e\x00",
                        },
                        {
                            "name": "privateHelper",
                            "return_type": "Z",
                            "params": ["Ljava/lang/String;"],
                            "access_flags": int(AccessFlags.PRIVATE | AccessFlags.FINAL),
                            "code": b"\x0e\x00\x0e\x00",
                        },
                    ],
                    "virtual_methods": [
                        {
                            "name": "doStuff",
                            "return_type": "I",
                            "params": ["I", "Ljava/lang/String;"],
                            "access_flags": int(AccessFlags.PUBLIC | AccessFlags.SYNCHRONIZED),
                            "code": b"\x0e\x00\x0e\x00",
                        },
                        {
                            "name": "doStuff",
                            "return_type": "V",
                            "params": [],
                            "access_flags": int(AccessFlags.PUBLIC | AccessFlags.VARARGS),
                            "code": b"\x0e\x00\x0e\x00",
                        },
                    ],
                }
            ]
        )
        loader = ClassLoader.from_elements([DexFile(dex_bytes)])
        cls = loader["com.example.Foo"]

        self.assertEqual(len(cls.direct_methods), 3)
        self.assertEqual(len(cls.virtual_methods), 2)
        self.assertEqual(len(cls.methods), 5)

        # constructors
        ctors = cls.constructors
        self.assertEqual(len(ctors), 2)
        ctor_names = {c.name for c in ctors}
        self.assertEqual(ctor_names, {"<init>", "<clinit>"})

        init_m = cls.get_method("<init>")
        self.assertIsNotNone(init_m)
        assert init_m is not None
        self.assertTrue(init_m.is_direct)
        self.assertFalse(init_m.is_virtual)
        self.assertTrue(init_m.is_constructor)
        self.assertTrue(init_m.is_public)
        self.assertEqual(init_m.defining_class, cls)

    def test_method_signatures_and_type_resolution(self) -> None:
        dex_bytes = build_dex_bytes(
            [
                {
                    "name": "Lcom/example/Service;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": 1,
                    "virtual_methods": [
                        {
                            "name": "process",
                            "return_type": "Lcom/example/Result;",
                            "params": ["Lcom/example/Param;", "Landroid/content/Context;", "I"],
                            "access_flags": int(AccessFlags.PUBLIC),
                        }
                    ],
                },
                {
                    "name": "Lcom/example/Result;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": 1,
                },
                {
                    "name": "Lcom/example/Param;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": 1,
                },
            ]
        )
        loader = ClassLoader.from_elements([DexFile(dex_bytes)])
        service_cls = loader["com.example.Service"]

        m = service_cls.get_method("process")
        self.assertIsNotNone(m)
        assert m is not None

        self.assertEqual(m.name, "process")
        self.assertEqual(m.shorty, "LLLI")
        self.assertEqual(m.return_type_descriptor, "Lcom/example/Result;")
        self.assertEqual(m.return_type_name, "com.example.Result")
        self.assertIsInstance(m.return_type_class, ResolvedClass)
        self.assertEqual(m.return_type_class.name, "com.example.Result")
        self.assertIs(m.return_type, m.return_type_class)

        self.assertEqual(
            m.parameter_type_descriptors,
            ("Lcom/example/Param;", "Landroid/content/Context;", "I"),
        )
        self.assertEqual(
            m.parameter_type_names,
            ("com.example.Param", "android.content.Context", "int"),
        )

        ptypes = m.parameter_types
        self.assertEqual(len(ptypes), 3)
        self.assertIsInstance(ptypes[0], ResolvedClass)
        self.assertEqual(ptypes[0].name, "com.example.Param")
        self.assertIsInstance(ptypes[1], UnresolvedClass)
        self.assertEqual(ptypes[1].name, "android.content.Context")
        self.assertIsInstance(ptypes[2], UnresolvedClass)
        self.assertEqual(ptypes[2].name, "int")

        self.assertEqual(
            m.descriptor, "(Lcom/example/Param;Landroid/content/Context;I)Lcom/example/Result;"
        )
        expected_str = (
            "com.example.Result com.example.Service.process"
            "(com.example.Param, android.content.Context, int)"
        )
        self.assertEqual(str(m), expected_str)

        expected_repr = (
            "<Method 'com.example.Service.process"
            "(Lcom/example/Param;Landroid/content/Context;I)Lcom/example/Result;'>"
        )
        self.assertEqual(repr(m), expected_repr)

    def test_has_code_and_code_item_access(self) -> None:
        dex_bytes = build_dex_bytes(
            [
                {
                    "name": "Lcom/example/NativeClass;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": 1,
                    "direct_methods": [
                        {
                            "name": "concreteMethod",
                            "return_type": "V",
                            "params": [],
                            "access_flags": int(AccessFlags.PUBLIC),
                            "code": b"\x0e\x00\x0e\x00",
                        },
                        {
                            "name": "nativeMethod",
                            "return_type": "V",
                            "params": [],
                            "access_flags": int(AccessFlags.PUBLIC | AccessFlags.NATIVE),
                        },
                    ],
                }
            ]
        )
        loader = ClassLoader.from_elements([DexFile(dex_bytes)])
        cls = loader["com.example.NativeClass"]

        m_concrete = cls.get_method("concreteMethod")
        assert m_concrete is not None
        self.assertTrue(m_concrete.has_code)
        self.assertIsNotNone(m_concrete.code)
        assert m_concrete.code is not None
        from dexbuf.model import Code

        self.assertIsInstance(m_concrete.code, Code)
        self.assertIsInstance(m_concrete.code.raw, CodeItem)

        m_native = cls.get_method("nativeMethod")
        assert m_native is not None
        self.assertFalse(m_native.has_code)
        self.assertIsNone(m_native.code)
        self.assertTrue(m_native.is_native)

    def test_lookups_get_method_and_find_methods(self) -> None:
        dex_bytes = build_dex_bytes(
            [
                {
                    "name": "Lcom/example/Overload;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": 1,
                    "virtual_methods": [
                        {
                            "name": "compute",
                            "return_type": "I",
                            "params": ["I"],
                            "access_flags": int(AccessFlags.PUBLIC),
                        },
                        {
                            "name": "compute",
                            "return_type": "Ljava/lang/String;",
                            "params": ["Ljava/lang/String;"],
                            "access_flags": int(AccessFlags.PUBLIC),
                        },
                    ],
                }
            ]
        )
        loader = ClassLoader.from_elements([DexFile(dex_bytes)])
        cls = loader["com.example.Overload"]

        # find_methods
        matches = cls.find_methods("compute")
        self.assertEqual(len(matches), 2)

        # get_method without descriptor returns first match
        m1 = cls.get_method("compute")
        self.assertIsNotNone(m1)
        assert m1 is not None
        self.assertEqual(m1, matches[0])

        # get_method with descriptor
        m_int = cls.get_method("compute", "(I)I")
        self.assertIsNotNone(m_int)
        assert m_int is not None
        self.assertEqual(m_int.descriptor, "(I)I")

        m_str = cls.get_method("compute", "(Ljava/lang/String;)Ljava/lang/String;")
        self.assertIsNotNone(m_str)
        assert m_str is not None
        self.assertEqual(m_str.descriptor, "(Ljava/lang/String;)Ljava/lang/String;")

        # non-existent
        self.assertIsNone(cls.get_method("compute", "(F)V"))
        self.assertIsNone(cls.get_method("nonExistent"))

    def test_method_flags_convenience(self) -> None:
        dex_bytes = build_dex_bytes(
            [
                {
                    "name": "Lcom/example/FlagsTest;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": 1,
                    "virtual_methods": [
                        {
                            "name": "allFlagsMethod",
                            "return_type": "V",
                            "params": [],
                            "access_flags": int(
                                AccessFlags.PROTECTED
                                | AccessFlags.STATIC
                                | AccessFlags.FINAL
                                | AccessFlags.SYNTHETIC
                                | AccessFlags.BRIDGE
                                | AccessFlags.VARARGS
                                | AccessFlags.ABSTRACT
                                | AccessFlags.STRICTFP
                            ),
                        }
                    ],
                }
            ]
        )
        loader = ClassLoader.from_elements([DexFile(dex_bytes)])
        cls = loader["com.example.FlagsTest"]

        m = cls.get_method("allFlagsMethod")
        assert m is not None

        self.assertTrue(m.is_protected)
        self.assertTrue(m.is_static)
        self.assertTrue(m.is_final)
        self.assertTrue(m.is_synthetic)
        self.assertTrue(m.is_bridge)
        self.assertTrue(m.is_varargs)
        self.assertTrue(m.is_abstract)
        self.assertTrue(m.is_strictfp)
        self.assertFalse(m.is_public)
        self.assertFalse(m.is_private)
        self.assertFalse(m.is_synchronized)
        self.assertFalse(m.is_native)

    def test_method_equality_and_hash(self) -> None:
        dex_bytes = build_dex_bytes(
            [
                {
                    "name": "Lcom/example/Foo;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": 1,
                    "virtual_methods": [
                        {"name": "m1", "return_type": "V", "params": [], "access_flags": 1},
                        {"name": "m2", "return_type": "V", "params": [], "access_flags": 1},
                    ],
                }
            ]
        )
        loader1 = ClassLoader.from_elements([DexFile(dex_bytes)])
        loader2 = ClassLoader.from_elements([DexFile(dex_bytes)])

        cls1 = loader1["com.example.Foo"]
        cls2 = loader2["com.example.Foo"]

        m1_a = cls1.get_method("m1")
        m1_a_again = cls1.get_method("m1")
        m1_b = cls1.get_method("m2")
        m2_a = cls2.get_method("m1")

        assert m1_a is not None and m1_a_again is not None and m1_b is not None and m2_a is not None

        self.assertEqual(m1_a, m1_a_again)
        self.assertEqual(hash(m1_a), hash(m1_a_again))

        self.assertNotEqual(m1_a, m1_b)
        self.assertNotEqual(m1_a, m2_a)  # Different loader identity on defining class
        self.assertNotEqual(m1_a, "not_a_method")


class TestAnnotationDomainModel(unittest.TestCase):
    def test_empty_class_and_items_no_annotations(self) -> None:
        dex_bytes = build_dex_bytes(
            [
                {
                    "name": "Lcom/example/Unannotated;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": 1,
                    "instance_fields": [{"name": "myField", "type": "I", "access_flags": 1}],
                    "virtual_methods": [
                        {
                            "name": "myMethod",
                            "return_type": "V",
                            "params": ["I", "Ljava/lang/String;"],
                            "access_flags": 1,
                        }
                    ],
                }
            ]
        )
        loader = ClassLoader.from_elements([DexFile(dex_bytes)])
        cls = loader["com.example.Unannotated"]

        self.assertEqual(cls.annotations, ())
        self.assertIsNone(cls.get_annotation("com.example.SomeAnn"))
        self.assertIsNone(cls.get_annotation("Lcom/example/SomeAnn;"))

        f = cls.get_field("myField")
        assert f is not None
        self.assertEqual(f.annotations, ())
        self.assertIsNone(f.get_annotation("com.example.SomeAnn"))

        m = cls.get_method("myMethod")
        assert m is not None
        self.assertEqual(m.annotations, ())
        self.assertEqual(m.parameter_annotations, ((), ()))
        self.assertIsNone(m.get_annotation("com.example.SomeAnn"))

    def test_class_annotations_visibility_types_and_elements(self) -> None:
        str_val = EncodedValue(value_arg=0, value_type=ValueType.STRING, value="hello")
        int_val = EncodedValue(value_arg=3, value_type=ValueType.INT, value=100)

        dex_bytes = build_dex_bytes(
            [
                {
                    "name": "Lcom/example/AnnotatedClass;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": 1,
                    "annotations": [
                        {
                            "type": "Lcom/example/RuntimeAnn;",
                            "visibility": AnnotationVisibility.RUNTIME,
                            "elements": {"val": str_val, "num": int_val},
                        },
                        {
                            "type": "Lcom/example/BuildAnn;",
                            "visibility": AnnotationVisibility.BUILD,
                            "elements": {},
                        },
                        {
                            "type": "Lcom/example/SystemAnn;",
                            "visibility": AnnotationVisibility.SYSTEM,
                            "elements": {},
                        },
                    ],
                },
                {
                    "name": "Lcom/example/RuntimeAnn;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": 1,
                },
            ]
        )
        loader = ClassLoader.from_elements([DexFile(dex_bytes)])
        cls = loader["com.example.AnnotatedClass"]

        self.assertEqual(len(cls.annotations), 3)

        ann_runtime = cls.get_annotation("com.example.RuntimeAnn")
        self.assertIsNotNone(ann_runtime)
        assert ann_runtime is not None
        self.assertIsInstance(ann_runtime, Annotation)

        self.assertEqual(ann_runtime.type_descriptor, "Lcom/example/RuntimeAnn;")
        self.assertEqual(ann_runtime.type_name, "com.example.RuntimeAnn")

        self.assertEqual(ann_runtime.visibility, AnnotationVisibility.RUNTIME)
        self.assertTrue(ann_runtime.is_runtime)
        self.assertFalse(ann_runtime.is_build)
        self.assertFalse(ann_runtime.is_system)

        # Raw item access
        self.assertEqual(ann_runtime.raw.visibility, AnnotationVisibility.RUNTIME)

        # Mapping and MappingProxyType type conformity
        self.assertIsInstance(ann_runtime.elements, Mapping)
        self.assertIsInstance(ann_runtime.elements, MappingProxyType)

        # Immutability verification
        with self.assertRaises(TypeError):
            ann_runtime.elements["new_key"] = int_val  # type: ignore[index]

        with self.assertRaises(TypeError):
            del ann_runtime.elements["val"]  # type: ignore[index]

        # Element access
        self.assertEqual(len(ann_runtime), 2)
        self.assertIn("val", ann_runtime)
        self.assertIn("num", ann_runtime)
        self.assertNotIn("missing", ann_runtime)

        self.assertEqual(ann_runtime["val"].value_type, ValueType.STRING)
        num_val = ann_runtime.get("num")
        assert num_val is not None
        self.assertEqual(num_val.value, 100)
        self.assertIsNone(ann_runtime.get("missing"))
        default_ev = EncodedValue(value_arg=3, value_type=ValueType.INT, value=42)
        self.assertEqual(ann_runtime.get("missing", default_ev), default_ev)

        elem_keys = set(ann_runtime)
        self.assertEqual(elem_keys, {"val", "num"})

        self.assertEqual(str(ann_runtime), "@com.example.RuntimeAnn")
        self.assertEqual(repr(ann_runtime), "<Annotation '@com.example.RuntimeAnn'>")

        # Build & System annotations
        ann_build = cls.get_annotation("Lcom/example/BuildAnn;")
        assert ann_build is not None
        self.assertTrue(ann_build.is_build)
        self.assertFalse(ann_build.is_runtime)
        self.assertFalse(ann_build.is_system)

        ann_system = cls.get_annotation("com.example.SystemAnn")
        assert ann_system is not None
        self.assertTrue(ann_system.is_system)

    def test_field_annotations(self) -> None:
        dex_bytes = build_dex_bytes(
            [
                {
                    "name": "Lcom/example/FieldClass;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": 1,
                    "instance_fields": [
                        {
                            "name": "annotatedField",
                            "type": "I",
                            "access_flags": 1,
                            "annotations": [
                                {
                                    "type": "Lcom/example/FieldAnn;",
                                    "visibility": AnnotationVisibility.RUNTIME,
                                    "elements": {
                                        "name": EncodedValue(
                                            value_arg=0, value_type=ValueType.STRING, value="test"
                                        )
                                    },
                                }
                            ],
                        },
                        {"name": "plainField", "type": "I", "access_flags": 1},
                    ],
                }
            ]
        )
        loader = ClassLoader.from_elements([DexFile(dex_bytes)])
        cls = loader["com.example.FieldClass"]

        f_ann = cls.get_field("annotatedField")
        assert f_ann is not None
        self.assertEqual(len(f_ann.annotations), 1)
        ann = f_ann.get_annotation("com.example.FieldAnn")
        self.assertIsNotNone(ann)
        assert ann is not None
        self.assertEqual(ann.type_name, "com.example.FieldAnn")

        f_plain = cls.get_field("plainField")
        assert f_plain is not None
        self.assertEqual(f_plain.annotations, ())
        self.assertIsNone(f_plain.get_annotation("com.example.FieldAnn"))

    def test_method_and_parameter_annotations(self) -> None:
        dex_bytes = build_dex_bytes(
            [
                {
                    "name": "Lcom/example/MethodClass;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": 1,
                    "virtual_methods": [
                        {
                            "name": "annotatedMethod",
                            "return_type": "V",
                            "params": ["I", "Ljava/lang/String;"],
                            "access_flags": 1,
                            "annotations": [
                                {
                                    "type": "Lcom/example/MethodAnn;",
                                    "visibility": AnnotationVisibility.RUNTIME,
                                    "elements": {},
                                }
                            ],
                            "parameter_annotations": [
                                [
                                    {
                                        "type": "Lcom/example/ParamAnn;",
                                        "visibility": AnnotationVisibility.RUNTIME,
                                        "elements": {},
                                    }
                                ],
                                [],
                            ],
                        }
                    ],
                }
            ]
        )
        loader = ClassLoader.from_elements([DexFile(dex_bytes)])
        cls = loader["com.example.MethodClass"]

        m = cls.get_method("annotatedMethod")
        assert m is not None

        # Method annotations
        self.assertEqual(len(m.annotations), 1)
        m_ann = m.get_annotation("com.example.MethodAnn")
        self.assertIsNotNone(m_ann)

        # Parameter annotations
        param_anns = m.parameter_annotations
        self.assertEqual(len(param_anns), 2)
        self.assertEqual(len(param_anns[0]), 1)
        self.assertEqual(param_anns[0][0].type_name, "com.example.ParamAnn")
        self.assertEqual(param_anns[1], ())

    def test_annotation_equality_and_hashing(self) -> None:
        dex_bytes = build_dex_bytes(
            [
                {
                    "name": "Lcom/example/Foo;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": 1,
                    "annotations": [
                        {
                            "type": "Lcom/example/Ann;",
                            "visibility": AnnotationVisibility.RUNTIME,
                            "elements": {
                                "v": EncodedValue(value_arg=3, value_type=ValueType.INT, value=1)
                            },
                        }
                    ],
                }
            ]
        )
        loader1 = ClassLoader.from_elements([DexFile(dex_bytes)])
        loader2 = ClassLoader.from_elements([DexFile(dex_bytes)])

        cls1 = loader1["com.example.Foo"]
        cls2 = loader2["com.example.Foo"]

        ann1 = cls1.annotations[0]
        ann1_again = cls1.annotations[0]
        ann2 = cls2.annotations[0]

        self.assertEqual(ann1, ann1_again)
        self.assertEqual(hash(ann1), hash(ann1_again))

        self.assertEqual(ann1, ann2)  # Identical annotations across loaders compare equal
        self.assertEqual(hash(ann1), hash(ann2))
        self.assertNotEqual(ann1, "not_an_annotation")


if __name__ == "__main__":
    unittest.main()
