"""Integration tests validating dexbuf against production multi-DEX K-9 Mail APK."""

import unittest

import dexbuf
from dexbuf.items import AnnotationVisibility, CodeItem
from dexbuf.model import ResolvedClass, UnresolvedClass, ZipAdapter
from tests.helpers import get_k9mail_apk_path  # type: ignore[import-not-found]


class TestK9MailIntegration(unittest.TestCase):
    """Integration test suite for K-9 Mail APK (k9mail-23.1.apk)."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.apk_path = get_k9mail_apk_path()

    def test_archive_and_container_loading(self) -> None:
        """Verify opening APK loads all DEX files and populates ClassLoader."""
        loader = dexbuf.open(self.apk_path)
        try:
            self.assertIsInstance(loader, dexbuf.ClassLoader)
            self.assertEqual(len(loader.elements), 1)

            zip_adapter = loader.elements[0]
            self.assertIsInstance(zip_adapter, ZipAdapter)
            self.assertEqual(len(zip_adapter._dex_files), 2)

            # Assert total class count matches expectations (> 10,000; ~11,635 in K-9 23.1)
            total_classes = len(loader)
            self.assertGreater(total_classes, 10000)
            self.assertEqual(total_classes, 11635)
        finally:
            loader.close()

    def test_class_loader_collection_semantics(self) -> None:
        """Verify ClassLoader iteration, find, contains, and dictionary access."""
        with dexbuf.open(self.apk_path) as loader:
            # Iteration yields ResolvedClass instances
            yielded_count = 0
            for cls in loader:
                self.assertIsInstance(cls, ResolvedClass)
                yielded_count += 1
            self.assertEqual(yielded_count, len(loader))

            # Glob searching
            k9_classes = loader.find("com.fsck.k9.*")
            self.assertGreater(len(k9_classes), 0)
            for cls in k9_classes:
                self.assertIsInstance(cls, ResolvedClass)
                self.assertTrue(cls.name.startswith("com.fsck.k9."))

            # Membership check
            self.assertIn("com.fsck.k9.K9", loader)
            self.assertNotIn("com.nonexistent.FakeClass", loader)

            # Dictionary-like access
            k9_cls = loader["com.fsck.k9.K9"]
            self.assertIsInstance(k9_cls, ResolvedClass)
            self.assertEqual(k9_cls.name, "com.fsck.k9.K9")

            # .get() access
            get_cls = loader.get("com.fsck.k9.K9")
            self.assertEqual(get_cls, k9_cls)
            self.assertIsNone(loader.get("com.nonexistent.FakeClass"))

            # Key error on missing class
            with self.assertRaises(KeyError):
                _ = loader["com.nonexistent.FakeClass"]

    def test_cross_dex_class_resolution_and_type_hierarchy(self) -> None:
        """Verify super_class and interface resolution across DEX files and platform types."""
        with dexbuf.open(self.apk_path) as loader:
            # Platform base class resolves to UnresolvedClass
            k9_cls = loader["com.fsck.k9.K9"]
            self.assertIsNotNone(k9_cls.super_class)
            self.assertIsInstance(k9_cls.super_class, UnresolvedClass)
            self.assertFalse(k9_cls.super_class.is_resolved)

            # Internal hierarchy resolves to ResolvedClass
            activity_cls = loader["com.fsck.k9.activity.BaseListActivity"]
            super_activity = activity_cls.super_class
            self.assertIsNotNone(super_activity)
            self.assertIsInstance(super_activity, ResolvedClass)
            self.assertTrue(super_activity.is_resolved)
            self.assertEqual(super_activity.name, "com.fsck.k9.ui.base.BaseActivity")

            # External platform interface resolves to UnresolvedClass
            addr_cls = loader["com.fsck.k9.mail.Address"]
            self.assertEqual(len(addr_cls.interfaces), 1)
            unresolved_iface = addr_cls.interfaces[0]
            self.assertIsInstance(unresolved_iface, UnresolvedClass)
            self.assertEqual(unresolved_iface.name, "java.io.Serializable")

            # Cross-DEX interface implementation resolves to ResolvedClass in second DEX file
            flis_cls = loader["com.fsck.k9.mail.filter.FixedLengthInputStream"]
            self.assertGreaterEqual(len(flis_cls.interfaces), 1)
            resolved_iface = flis_cls.interfaces[0]
            self.assertIsInstance(resolved_iface, ResolvedClass)
            self.assertTrue(resolved_iface.is_resolved)
            self.assertEqual(resolved_iface.name, "j$.io.InputStreamRetargetInterface")

    def test_field_domain_model(self) -> None:
        """Verify field properties, access flags, and initial values on resolved classes."""
        with dexbuf.open(self.apk_path) as loader:
            addr_cls = loader["com.fsck.k9.mail.Address"]

            # Inspect static and instance fields
            self.assertEqual(len(addr_cls.static_fields), 2)
            self.assertEqual(len(addr_cls.instance_fields), 2)
            self.assertEqual(len(addr_cls.fields), 4)

            # Check static field properties
            atom_field = addr_cls.get_field("ATOM")
            self.assertIsNotNone(atom_field)
            self.assertEqual(atom_field.name, "ATOM")
            self.assertEqual(atom_field.type_name, "java.util.regex.Pattern")
            self.assertEqual(atom_field.type_descriptor, "Ljava/util/regex/Pattern;")
            self.assertTrue(atom_field.is_static)
            self.assertTrue(atom_field.is_public)
            self.assertTrue(atom_field.is_final)
            self.assertEqual(atom_field.defining_class, addr_cls)
            self.assertIsInstance(atom_field.type_class, UnresolvedClass)

            # Check instance field properties
            address_field = addr_cls.get_field("address")
            self.assertIsNotNone(address_field)
            self.assertEqual(address_field.name, "address")
            self.assertEqual(address_field.type_name, "java.lang.String")
            self.assertEqual(address_field.type_descriptor, "Ljava/lang/String;")
            self.assertFalse(address_field.is_static)
            self.assertTrue(address_field.is_public)
            self.assertEqual(address_field.defining_class, addr_cls)

            # Check domain class fields
            pref_cls = loader["com.fsck.k9.Preferences"]
            self.assertGreater(len(pref_cls.instance_fields), 0)
            storage_field = pref_cls.get_field("storagePersister")
            self.assertIsNotNone(storage_field)
            self.assertEqual(storage_field.type_name, "com.fsck.k9.preferences.K9StoragePersister")
            self.assertFalse(storage_field.is_static)
            self.assertTrue(storage_field.is_public)

    def test_method_domain_model(self) -> None:
        """Verify method domain model, signatures, modifiers, and code presence."""
        with dexbuf.open(self.apk_path) as loader:
            addr_cls = loader["com.fsck.k9.mail.Address"]

            # Method collections
            self.assertEqual(len(addr_cls.methods), 8)
            self.assertEqual(len(addr_cls.direct_methods), 3)
            self.assertEqual(len(addr_cls.virtual_methods), 5)
            self.assertEqual(len(addr_cls.constructors), 3)

            # Constructors
            clinit = next(m for m in addr_cls.constructors if m.name == "<clinit>")
            self.assertTrue(clinit.is_static)
            self.assertTrue(clinit.is_constructor)

            inits = [m for m in addr_cls.constructors if m.name == "<init>"]
            self.assertEqual(len(inits), 2)
            for init in inits:
                self.assertFalse(init.is_static)
                self.assertTrue(init.is_constructor)

            # Virtual method properties
            hostname_method = addr_cls.get_method("getHostname")
            self.assertIsNotNone(hostname_method)
            self.assertEqual(hostname_method.name, "getHostname")
            self.assertEqual(hostname_method.descriptor, "()Ljava/lang/String;")
            self.assertEqual(hostname_method.return_type_name, "java.lang.String")
            self.assertEqual(hostname_method.parameter_type_names, ())
            self.assertEqual(hostname_method.parameter_types, ())
            self.assertTrue(hostname_method.is_public)
            self.assertTrue(hostname_method.is_virtual)

            # get_method and find_methods lookup
            self.assertEqual(
                addr_cls.get_method("getHostname", "()Ljava/lang/String;"), hostname_method
            )
            found_to_string = addr_cls.find_methods("toString")
            self.assertEqual(len(found_to_string), 1)
            self.assertEqual(found_to_string[0].name, "toString")

            # Code item presence on concrete method
            self.assertTrue(hostname_method.has_code)
            self.assertIsNotNone(hostname_method.code)
            self.assertIsInstance(hostname_method.code, dexbuf.Code)
            self.assertIsInstance(hostname_method.code.raw, CodeItem)

            # Abstract interface method
            iface_cls = loader["j$.io.InputStreamRetargetInterface"]
            abstract_method = iface_cls.get_method("transferTo")
            self.assertIsNotNone(abstract_method)
            self.assertTrue(abstract_method.is_abstract)
            self.assertFalse(abstract_method.has_code)
            self.assertIsNone(abstract_method.code)

    def test_annotation_domain_model(self) -> None:
        """Verify class, field, and method annotations and element immutability."""
        with dexbuf.open(self.apk_path) as loader:
            # Class runtime annotations
            keep_cls = loader["androidx.annotation.Keep"]
            retention_ann = keep_cls.get_annotation("java.lang.annotation.Retention")
            target_ann = keep_cls.get_annotation("Ljava/lang/annotation/Target;")
            self.assertIsNotNone(retention_ann)
            self.assertIsNotNone(target_ann)
            self.assertTrue(retention_ann.is_runtime)
            self.assertTrue(target_ann.is_runtime)
            self.assertEqual(retention_ann.visibility, AnnotationVisibility.RUNTIME)
            self.assertEqual(target_ann.visibility, AnnotationVisibility.RUNTIME)

            # Class system annotations
            factory_cls = loader["coil3.EventListener$Factory"]
            inner_ann = factory_cls.get_annotation("dalvik.annotation.InnerClass")
            self.assertIsNotNone(inner_ann)
            self.assertTrue(inner_ann.is_system)
            self.assertEqual(inner_ann.visibility, AnnotationVisibility.SYSTEM)

            # Field annotations
            bci_cls = loader["kotlin.coroutines.jvm.internal.BaseContinuationImpl"]
            completion_field = bci_cls.get_field("completion")
            self.assertIsNotNone(completion_field)
            sig_ann = completion_field.get_annotation("dalvik.annotation.Signature")
            self.assertIsNotNone(sig_ann)
            self.assertEqual(sig_ann.type_name, "dalvik.annotation.Signature")

            # Method annotations
            rv_cls = loader["androidx.recyclerview.widget.RecyclerView"]
            scroll_method = rv_cls.get_method("setOnScrollListener")
            self.assertIsNotNone(scroll_method)
            dep_ann = scroll_method.get_annotation("java.lang.Deprecated")
            self.assertIsNotNone(dep_ann)
            self.assertEqual(dep_ann.type_name, "java.lang.Deprecated")

            # get_annotation with Java type names and Dalvik descriptors
            self.assertEqual(
                keep_cls.get_annotation("java.lang.annotation.Retention"),
                keep_cls.get_annotation("Ljava/lang/annotation/Retention;"),
            )
            self.assertEqual(
                completion_field.get_annotation("dalvik.annotation.Signature"),
                completion_field.get_annotation("Ldalvik/annotation/Signature;"),
            )
            self.assertEqual(
                scroll_method.get_annotation("java.lang.Deprecated"),
                scroll_method.get_annotation("Ljava/lang/Deprecated;"),
            )

            # Element access and immutability
            self.assertIn("value", retention_ann.elements)
            with self.assertRaises(TypeError):
                retention_ann.elements["value"] = "mutation_test"  # type: ignore[index]

            # Parameter annotations length matches parameter count
            for method in rv_cls.methods:
                param_count = len(method.parameter_type_names)
                self.assertEqual(len(method.parameter_annotations), param_count)

    def test_resource_management(self) -> None:
        """Verify context manager and explicit close clean up resources properly."""
        # Test context manager
        with dexbuf.open(self.apk_path) as loader:
            self.assertIn("com.fsck.k9.K9", loader)

        # Explicit close on opened loader
        loader2 = dexbuf.open(self.apk_path)
        self.assertIn("com.fsck.k9.K9", loader2)
        loader2.close()
        # Closing multiple times should be safe
        loader2.close()

    def test_disassemble_account_remover_class_full_dump(self) -> None:
        """Verify full disassembly dump of AccountRemover matches golden snapshot."""
        from pathlib import Path

        fixture_path = Path(__file__).parent / "fixtures" / "k9_account_remover_disassembly.smali"
        self.assertTrue(fixture_path.exists(), f"Fixture file not found: {fixture_path}")
        expected_dump = fixture_path.read_text(encoding="utf-8").strip()

        with dexbuf.open(self.apk_path) as loader:
            remover_cls = loader["com.fsck.k9.account.AccountRemover"]
            dump = remover_cls.disassemble()

            self.assertEqual(dump, expected_dump)
            self.assertEqual(len(dump.splitlines()), 64)


if __name__ == "__main__":
    unittest.main()
