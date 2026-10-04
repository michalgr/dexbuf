"""Tests for class hierarchy, interface resolution, superclass chain, and type guards."""

import unittest

from dexbuf import (
    AccessFlags,
    Class,
    ClassLoader,
    DexFile,
    ResolvedClass,
    UnresolvedClass,
    is_resolved,
)
from tests.builders import build_dex_bytes


class TestClassHierarchy(unittest.TestCase):
    def test_is_resolved_type_guard(self) -> None:
        dex_bytes = build_dex_bytes(
            [{"name": "Lcom/example/Foo;", "super": "Ljava/lang/Object;", "access_flags": 1}]
        )
        loader = ClassLoader.from_elements([DexFile(dex_bytes)])
        resolved_cls = loader["com.example.Foo"]
        unresolved_cls = UnresolvedClass("Landroid/app/Activity;")

        self.assertTrue(is_resolved(resolved_cls))
        self.assertFalse(is_resolved(unresolved_cls))

        # Test type narrowing behavior in conditional branch
        def check_narrowing(c: Class) -> str:
            if is_resolved(c):
                # c is narrowed to ResolvedClass
                return f"Resolved: {c.dex_file!r}"
            else:
                # c is narrowed to UnresolvedClass
                return f"Unresolved: {c.name}"

        self.assertTrue(check_narrowing(resolved_cls).startswith("Resolved:"))
        self.assertEqual(check_narrowing(unresolved_cls), "Unresolved: android.app.Activity")

    def test_unresolved_class_properties_and_normalization(self) -> None:
        unresolved1 = UnresolvedClass.from_name_or_descriptor("android.app.Activity")
        self.assertFalse(unresolved1.is_resolved)
        self.assertEqual(unresolved1.descriptor, "Landroid/app/Activity;")
        self.assertEqual(unresolved1.name, "android.app.Activity")
        self.assertEqual(unresolved1.package, "android.app")
        self.assertEqual(unresolved1.simple_name, "Activity")
        self.assertEqual(str(unresolved1), "android.app.Activity")
        self.assertEqual(repr(unresolved1), "<UnresolvedClass 'android.app.Activity'>")

        unresolved2 = UnresolvedClass("Landroid/app/Activity;")
        self.assertEqual(unresolved1, unresolved2)
        self.assertEqual(hash(unresolved1), hash(unresolved2))

        unresolved3 = UnresolvedClass.from_name_or_descriptor("Landroid/app/Activity;")
        self.assertEqual(unresolved1, unresolved3)

        unresolved_arr = UnresolvedClass("[Landroid/app/Activity;")
        self.assertEqual(unresolved_arr.descriptor, "[Landroid/app/Activity;")
        self.assertEqual(unresolved_arr.name, "android.app.Activity[]")

        unresolved_arr2 = UnresolvedClass.from_name_or_descriptor("[Landroid/app/Activity;")
        self.assertEqual(unresolved_arr, unresolved_arr2)

        default_pkg = UnresolvedClass.from_name_or_descriptor("GlobalClass")
        self.assertEqual(default_pkg.descriptor, "LGlobalClass;")
        self.assertEqual(default_pkg.package, "")
        self.assertEqual(default_pkg.simple_name, "GlobalClass")

    def test_resolved_class_properties_and_flags(self) -> None:
        dex_bytes = build_dex_bytes(
            [
                {
                    "name": "Lcom/example/Foo;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": int(
                        AccessFlags.PUBLIC
                        | AccessFlags.FINAL
                        | AccessFlags.SYNTHETIC
                        | AccessFlags.ENUM
                    ),
                    "source_file": "Foo.java",
                }
            ]
        )
        dex = DexFile(dex_bytes)
        loader = ClassLoader.from_elements([dex])

        cls = loader.load_class("com.example.Foo")
        self.assertIsNotNone(cls)
        assert cls is not None
        self.assertTrue(cls.is_resolved)
        self.assertEqual(cls.descriptor, "Lcom/example/Foo;")
        self.assertEqual(cls.name, "com.example.Foo")
        self.assertEqual(cls.package, "com.example")
        self.assertEqual(cls.simple_name, "Foo")
        self.assertEqual(cls.loader, loader)
        self.assertEqual(cls.dex_file, dex)
        self.assertEqual(cls.source_file, "Foo.java")
        self.assertTrue(cls.is_public)
        self.assertTrue(cls.is_final)
        self.assertFalse(cls.is_interface)
        self.assertFalse(cls.is_abstract)
        self.assertTrue(cls.is_synthetic)
        self.assertFalse(cls.is_annotation)
        self.assertTrue(cls.is_enum)
        self.assertEqual(str(cls), "com.example.Foo")
        self.assertEqual(repr(cls), "<Class 'com.example.Foo'>")

    def test_resolved_class_superclass_and_interfaces(self) -> None:
        dex_bytes = build_dex_bytes(
            [
                {
                    "name": "Lcom/example/Child;",
                    "super": "Lcom/example/Parent;",
                    "interfaces": ["Lcom/example/Iface;", "Landroid/view/View;"],
                    "access_flags": int(AccessFlags.PUBLIC),
                },
                {
                    "name": "Lcom/example/Parent;",
                    "super": "Ljava/lang/Object;",
                    "access_flags": int(AccessFlags.PUBLIC),
                },
                {
                    "name": "Lcom/example/Iface;",
                    "super": None,
                    "access_flags": int(AccessFlags.PUBLIC | AccessFlags.INTERFACE),
                },
            ]
        )
        dex = DexFile(dex_bytes)
        loader = ClassLoader.from_elements([dex])

        child = loader["com.example.Child"]
        parent = child.super_class
        self.assertIsInstance(parent, ResolvedClass)
        assert parent is not None
        self.assertEqual(parent.name, "com.example.Parent")

        # Parent's superclass is java.lang.Object which is external to loader
        obj_super = parent.super_class
        self.assertIsInstance(obj_super, UnresolvedClass)
        assert obj_super is not None
        self.assertEqual(obj_super.name, "java.lang.Object")

        ifaces = child.interfaces
        self.assertEqual(len(ifaces), 2)
        self.assertIsInstance(ifaces[0], ResolvedClass)
        self.assertEqual(ifaces[0].name, "com.example.Iface")
        self.assertIsInstance(ifaces[1], UnresolvedClass)
        self.assertEqual(ifaces[1].name, "android.view.View")

    def test_java_lang_object_superclass_none(self) -> None:
        dex_bytes = build_dex_bytes(
            [
                {
                    "name": "Ljava/lang/Object;",
                    "super": None,
                    "access_flags": int(AccessFlags.PUBLIC),
                }
            ]
        )
        loader = ClassLoader.from_elements([DexFile(dex_bytes)])
        obj_cls = loader["java.lang.Object"]
        self.assertIsNone(obj_cls.super_class)

    def test_equality_and_hashing(self) -> None:
        dex_bytes = build_dex_bytes(
            [{"name": "Lcom/example/Foo;", "super": "Ljava/lang/Object;", "access_flags": 1}]
        )
        dex1 = DexFile(dex_bytes)
        loader1 = ClassLoader.from_elements([dex1])
        cls1 = loader1["com.example.Foo"]
        cls2 = loader1["com.example.Foo"]

        dex2 = DexFile(dex_bytes)
        loader2 = ClassLoader.from_elements([dex2])
        cls_other_loader = loader2["com.example.Foo"]

        unresolved1 = UnresolvedClass.from_name_or_descriptor("com.example.Foo")
        unresolved2 = UnresolvedClass("Lcom/example/Foo;")

        # UnresolvedClass equality and hash
        self.assertEqual(unresolved1, unresolved2)
        self.assertEqual(hash(unresolved1), hash(unresolved2))
        self.assertNotEqual(unresolved1, "com.example.Foo")

        # ResolvedClass equality and hash within same ClassLoader
        self.assertEqual(cls1, cls2)
        self.assertEqual(hash(cls1), hash(cls2))

        # ResolvedClass equality and hash across different ClassLoaders
        self.assertNotEqual(cls1, cls_other_loader)

        # Cross type comparisons
        self.assertNotEqual(cls1, unresolved1)
        self.assertNotEqual(unresolved1, cls1)
        self.assertNotEqual(cls1, "com.example.Foo")


if __name__ == "__main__":
    unittest.main()
