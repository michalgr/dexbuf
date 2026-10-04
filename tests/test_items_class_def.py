"""Unit tests for DEX class definitions, encoded members, class data, and HiddenAPI."""

import dataclasses
import struct
import unittest
from dataclasses import FrozenInstanceError
from typing import Any

from dexbuf import (
    NO_INDEX,
    NO_OFFSET,
    AnnotationsDirectoryItem,
    ClassDataItem,
    ClassDefItem,
    CodeItem,
    EncodedArrayItem,
    EncodedField,
    EncodedMethod,
    FieldIdItem,
    HiddenapiClassDataItem,
    HiddenapiRestrictionFlag,
    Idx,
    MethodIdItem,
    Offset,
    StringIdItem,
    TypeIdItem,
    TypeList,
)
from dexbuf.cursor import Cursor


class TestClassDefItem(unittest.TestCase):
    def test_fields_metadata(self) -> None:
        field_names = [f.name for f in dataclasses.fields(ClassDefItem)]
        expected_fields = [
            "class_idx",
            "access_flags",
            "superclass_idx",
            "interfaces_off",
            "source_file_idx",
            "annotations_off",
            "class_data_off",
            "static_values_off",
        ]
        self.assertEqual(field_names, expected_fields)

    def test_immutability(self) -> None:
        item = ClassDefItem(
            class_idx=Idx[TypeIdItem](1),
            access_flags=1,
            superclass_idx=Idx[TypeIdItem](2),
            interfaces_off=NO_OFFSET,
            source_file_idx=Idx[StringIdItem](3),
            annotations_off=NO_OFFSET,
            class_data_off=NO_OFFSET,
            static_values_off=NO_OFFSET,
        )
        with self.assertRaises(FrozenInstanceError):
            item.access_flags = 2  # type: ignore[misc]

    def test_parsing_and_encoding_roundtrip(self) -> None:
        item = ClassDefItem(
            class_idx=Idx[TypeIdItem](10),
            access_flags=0x0001,  # ACC_PUBLIC
            superclass_idx=Idx[TypeIdItem](11),
            interfaces_off=Offset[TypeList](0x0100),
            source_file_idx=Idx[StringIdItem](12),
            annotations_off=Offset[None](0x0200),  # type: ignore[type-arg]
            class_data_off=Offset[ClassDataItem](0x0300),
            static_values_off=Offset[None](0x0400),  # type: ignore[type-arg]
        )
        raw = item.to_bytes()
        self.assertEqual(len(raw), 32)

        cursor = Cursor(raw)
        parsed = ClassDefItem.from_cursor(cursor)
        self.assertEqual(parsed, item)

        buf = b"\x00" * 8 + raw
        offset = Offset[ClassDefItem](8)
        from_buf = ClassDefItem.from_buffer(buf, offset)
        self.assertEqual(from_buf, item)

    def test_typed_static_values_off(self) -> None:
        """Verify static_values_off is typed as Offset[EncodedArrayItem]."""
        item = ClassDefItem(
            class_idx=Idx[TypeIdItem](1),
            access_flags=1,
            superclass_idx=Idx[TypeIdItem](2),
            interfaces_off=NO_OFFSET,
            source_file_idx=Idx[StringIdItem](3),
            annotations_off=NO_OFFSET,
            class_data_off=NO_OFFSET,
            static_values_off=Offset[EncodedArrayItem](0x1234),
        )
        self.assertEqual(item.static_values_off, Offset[EncodedArrayItem](0x1234))

    def test_typed_annotations_off(self) -> None:
        """Verify annotations_off is typed as Offset[AnnotationsDirectoryItem]."""
        item = ClassDefItem(
            class_idx=Idx[TypeIdItem](1),
            access_flags=1,
            superclass_idx=Idx[TypeIdItem](2),
            interfaces_off=NO_OFFSET,
            source_file_idx=Idx[StringIdItem](3),
            annotations_off=Offset[AnnotationsDirectoryItem](0x5678),
            class_data_off=NO_OFFSET,
            static_values_off=NO_OFFSET,
        )
        self.assertEqual(item.annotations_off, Offset[AnnotationsDirectoryItem](0x5678))

    def test_no_index_and_no_offset_handling(self) -> None:
        item = ClassDefItem(
            class_idx=Idx[TypeIdItem](0),  # Root class
            access_flags=0x0001,
            superclass_idx=NO_INDEX,  # java.lang.Object has no superclass
            interfaces_off=NO_OFFSET,
            source_file_idx=NO_INDEX,
            annotations_off=NO_OFFSET,
            class_data_off=NO_OFFSET,
            static_values_off=NO_OFFSET,
        )
        raw = item.to_bytes()
        self.assertEqual(len(raw), 32)

        parsed = ClassDefItem.from_buffer(raw)
        self.assertEqual(parsed, item)
        self.assertEqual(parsed.superclass_idx, NO_INDEX)
        self.assertEqual(parsed.interfaces_off, NO_OFFSET)
        self.assertEqual(parsed.source_file_idx, NO_INDEX)
        self.assertEqual(parsed.annotations_off, NO_OFFSET)
        self.assertEqual(parsed.class_data_off, NO_OFFSET)
        self.assertEqual(parsed.static_values_off, NO_OFFSET)


class TestEncodedFieldAndMethod(unittest.TestCase):
    def test_encoded_field_immutability(self) -> None:
        field = EncodedField(field_idx_diff=5, access_flags=0x0001)
        with self.assertRaises(FrozenInstanceError):
            field.access_flags = 0x0002  # type: ignore[misc]

    def test_encoded_field_roundtrip(self) -> None:
        field = EncodedField(field_idx_diff=128, access_flags=8)
        raw = field.to_bytes()
        cursor = Cursor(raw)
        parsed = EncodedField.from_cursor(cursor)
        self.assertEqual(parsed, field)
        self.assertTrue(cursor.is_eof)

    def test_encoded_method_immutability(self) -> None:
        method = EncodedMethod(
            method_idx_diff=10, access_flags=0x0001, code_off=Offset[Any](0x1000)
        )
        with self.assertRaises(FrozenInstanceError):
            method.access_flags = 0x0002  # type: ignore[misc]

    def test_encoded_method_roundtrip(self) -> None:
        method = EncodedMethod(
            method_idx_diff=3, access_flags=0x0008, code_off=Offset[CodeItem](0x2000)
        )
        raw = method.to_bytes()
        cursor = Cursor(raw)
        parsed = EncodedMethod.from_cursor(cursor)
        self.assertEqual(parsed, method)
        self.assertEqual(parsed.code_off, Offset[CodeItem](0x2000))
        self.assertTrue(cursor.is_eof)


class TestClassDataItem(unittest.TestCase):
    def test_nested_aliases_and_fields(self) -> None:
        self.assertIs(ClassDataItem.EncodedField, EncodedField)
        self.assertIs(ClassDataItem.EncodedMethod, EncodedMethod)

        field_names = [f.name for f in dataclasses.fields(ClassDataItem)]
        expected_fields = [
            "static_fields",
            "instance_fields",
            "direct_methods",
            "virtual_methods",
        ]
        self.assertEqual(field_names, expected_fields)

    def test_immutability(self) -> None:
        item = ClassDataItem(
            static_fields=(),
            instance_fields=(),
            direct_methods=(),
            virtual_methods=(),
        )
        with self.assertRaises((TypeError, AttributeError)):
            item.static_fields_size = 1  # type: ignore[misc]

    def test_empty_class_data(self) -> None:
        empty = ClassDataItem(
            static_fields=(),
            instance_fields=(),
            direct_methods=(),
            virtual_methods=(),
        )
        self.assertEqual(empty.static_fields_size, 0)
        self.assertEqual(empty.instance_fields_size, 0)
        self.assertEqual(empty.direct_methods_size, 0)
        self.assertEqual(empty.virtual_methods_size, 0)

        raw = empty.to_bytes()
        self.assertEqual(raw, b"\x00\x00\x00\x00")

        parsed = ClassDataItem.from_buffer(raw)
        self.assertEqual(parsed, empty)

    def test_non_empty_class_data_roundtrip(self) -> None:
        sf1 = EncodedField(field_idx_diff=1, access_flags=0x0008)
        sf2 = EncodedField(field_idx_diff=2, access_flags=0x0018)
        if1 = EncodedField(field_idx_diff=5, access_flags=0x0002)

        dm1 = EncodedMethod(method_idx_diff=1, access_flags=0x10008, code_off=Offset[Any](0x1234))
        vm1 = EncodedMethod(method_idx_diff=2, access_flags=0x0001, code_off=Offset[Any](0x5678))
        vm2 = EncodedMethod(method_idx_diff=1, access_flags=0x0001, code_off=NO_OFFSET)

        item = ClassDataItem(
            static_fields=(sf1, sf2),
            instance_fields=(if1,),
            direct_methods=(dm1,),
            virtual_methods=(vm1, vm2),
        )
        self.assertEqual(item.static_fields_size, 2)
        self.assertEqual(item.instance_fields_size, 1)
        self.assertEqual(item.direct_methods_size, 1)
        self.assertEqual(item.virtual_methods_size, 2)

        raw = item.to_bytes()
        cursor = Cursor(raw)
        parsed = ClassDataItem.from_cursor(cursor)

        self.assertEqual(parsed, item)
        self.assertEqual(parsed.static_fields, (sf1, sf2))
        self.assertEqual(parsed.instance_fields, (if1,))
        self.assertEqual(parsed.direct_methods, (dm1,))
        self.assertEqual(parsed.virtual_methods, (vm1, vm2))
        self.assertTrue(cursor.is_eof)

        buf = b"HEADER" + raw
        from_buf = ClassDataItem.from_buffer(buf, Offset[ClassDataItem](6))
        self.assertEqual(from_buf, item)

    def test_delta_decoding_iterators(self) -> None:
        """Verify delta-decoding iterators on ClassDataItem."""
        # 1. Empty tuples
        empty_item = ClassDataItem(
            static_fields=(),
            instance_fields=(),
            direct_methods=(),
            virtual_methods=(),
        )
        self.assertEqual(list(empty_item.iter_static_fields()), [])
        self.assertEqual(list(empty_item.iter_instance_fields()), [])
        self.assertEqual(list(empty_item.iter_direct_methods()), [])
        self.assertEqual(list(empty_item.iter_virtual_methods()), [])

        # 2. Single-item tuples with non-zero diff
        sf_single = EncodedField(field_idx_diff=15, access_flags=0x0001)
        if_single = EncodedField(field_idx_diff=42, access_flags=0x0002)
        dm_single = EncodedMethod(
            method_idx_diff=100, access_flags=0x0008, code_off=Offset[CodeItem](0x1000)
        )
        vm_single = EncodedMethod(
            method_idx_diff=200, access_flags=0x0001, code_off=Offset[CodeItem](0x2000)
        )

        single_item = ClassDataItem(
            static_fields=(sf_single,),
            instance_fields=(if_single,),
            direct_methods=(dm_single,),
            virtual_methods=(vm_single,),
        )

        self.assertEqual(
            list(single_item.iter_static_fields()),
            [(Idx[FieldIdItem](15), sf_single)],
        )
        self.assertEqual(
            list(single_item.iter_instance_fields()),
            [(Idx[FieldIdItem](42), if_single)],
        )
        self.assertEqual(
            list(single_item.iter_direct_methods()),
            [(Idx[MethodIdItem](100), dm_single)],
        )
        self.assertEqual(
            list(single_item.iter_virtual_methods()),
            [(Idx[MethodIdItem](200), vm_single)],
        )

        # 3. Multi-item tuples verifying correct cumulative calculations and reset across categories
        sf1 = EncodedField(field_idx_diff=10, access_flags=1)
        sf2 = EncodedField(field_idx_diff=5, access_flags=2)
        sf3 = EncodedField(field_idx_diff=0, access_flags=3)

        if1 = EncodedField(field_idx_diff=3, access_flags=1)
        if2 = EncodedField(field_idx_diff=7, access_flags=2)

        dm1 = EncodedMethod(method_idx_diff=100, access_flags=1, code_off=NO_OFFSET)
        dm2 = EncodedMethod(method_idx_diff=20, access_flags=2, code_off=NO_OFFSET)

        vm1 = EncodedMethod(method_idx_diff=5, access_flags=1, code_off=NO_OFFSET)
        vm2 = EncodedMethod(method_idx_diff=15, access_flags=2, code_off=NO_OFFSET)

        multi_item = ClassDataItem(
            static_fields=(sf1, sf2, sf3),
            instance_fields=(if1, if2),
            direct_methods=(dm1, dm2),
            virtual_methods=(vm1, vm2),
        )

        # Static fields accum: 10, 10+5=15, 15+0=15
        self.assertEqual(
            list(multi_item.iter_static_fields()),
            [
                (Idx[FieldIdItem](10), sf1),
                (Idx[FieldIdItem](15), sf2),
                (Idx[FieldIdItem](15), sf3),
            ],
        )

        # Instance fields accum: resets to 0 -> 3, 3+7=10
        self.assertEqual(
            list(multi_item.iter_instance_fields()),
            [
                (Idx[FieldIdItem](3), if1),
                (Idx[FieldIdItem](10), if2),
            ],
        )

        # Direct methods accum: 100, 100+20=120
        self.assertEqual(
            list(multi_item.iter_direct_methods()),
            [
                (Idx[MethodIdItem](100), dm1),
                (Idx[MethodIdItem](120), dm2),
            ],
        )

        # Virtual methods accum: resets to 0 -> 5, 5+15=20
        self.assertEqual(
            list(multi_item.iter_virtual_methods()),
            [
                (Idx[MethodIdItem](5), vm1),
                (Idx[MethodIdItem](20), vm2),
            ],
        )


class TestHiddenapiClassDataItem(unittest.TestCase):
    def test_restriction_flag_enum(self) -> None:
        """Verify HiddenapiRestrictionFlag enum values."""
        self.assertEqual(HiddenapiRestrictionFlag.WHITELIST, 0)
        self.assertEqual(HiddenapiRestrictionFlag.GREYLIST, 1)
        self.assertEqual(HiddenapiRestrictionFlag.BLACKLIST, 2)
        self.assertEqual(HiddenapiRestrictionFlag.GREYLIST_MAX_O, 3)
        self.assertEqual(HiddenapiRestrictionFlag.GREYLIST_MAX_P, 4)
        self.assertEqual(HiddenapiRestrictionFlag.GREYLIST_MAX_Q, 5)
        self.assertEqual(HiddenapiRestrictionFlag.GREYLIST_MAX_R, 6)

    def test_immutability_and_fields(self) -> None:
        """Verify frozen immutability and fields."""
        item = HiddenapiClassDataItem(data=memoryview(b"\x00" * 8))
        with self.assertRaises(FrozenInstanceError):
            item.data = memoryview(b"")  # type: ignore[misc]

        with self.assertRaises((TypeError, AttributeError)):
            item.size = 10  # type: ignore[misc]

        field_names = [f.name for f in dataclasses.fields(HiddenapiClassDataItem)]
        self.assertEqual(field_names, ["data"])

    def test_from_class_flags_factory_and_access_api(self) -> None:
        """Verify creation via from_class_flags and query methods."""
        class_flags_input = [
            None,  # class 0: default 0 offset
            [0, 0],  # class 1: all zeros -> offset 0
            [
                HiddenapiRestrictionFlag.GREYLIST,
                HiddenapiRestrictionFlag.GREYLIST_MAX_P,
            ],  # class 2: non-zero flags (1, 4)
            [
                HiddenapiRestrictionFlag.WHITELIST,
                HiddenapiRestrictionFlag.BLACKLIST,
                HiddenapiRestrictionFlag.GREYLIST_MAX_R,
            ],  # class 3: flags (0, 2, 6)
        ]

        item = HiddenapiClassDataItem.from_class_flags(class_flags_input)

        # Offsets table size = 4 classes * 4 bytes = 16 bytes.
        # Header = 4 bytes. Total section size = 4 + len(item.data)
        self.assertEqual(item.size, 4 + len(item.data))

        # Class 0: offset 0 -> whitelist defaults
        self.assertEqual(item.get_offset(0), 0)
        self.assertEqual(item.get_flags(0, count=3), (0, 0, 0))

        # Class 1: offset 0 (all zeros input)
        self.assertEqual(item.get_offset(1), 0)
        self.assertEqual(item.get_flags(1, count=2), (0, 0))

        # Class 2: non-zero offset
        off2 = item.get_offset(2)
        self.assertGreater(off2, 0)
        self.assertEqual(item.get_flags(2, count=2), (1, 4))
        self.assertEqual(
            list(item.iter_flags(2, count=2)),
            [HiddenapiRestrictionFlag.GREYLIST, HiddenapiRestrictionFlag.GREYLIST_MAX_P],
        )

        # Class 3: non-zero offset
        off3 = item.get_offset(3)
        self.assertGreater(off3, off2)
        self.assertEqual(item.get_flags(3, count=3), (0, 2, 6))

    def test_parsing_serialization_roundtrip(self) -> None:
        """Verify from_cursor, from_buffer, and to_bytes roundtrip."""
        item = HiddenapiClassDataItem.from_class_flags(
            [
                [HiddenapiRestrictionFlag.BLACKLIST],
                [HiddenapiRestrictionFlag.GREYLIST_MAX_O, HiddenapiRestrictionFlag.WHITELIST],
            ]
        )

        raw = item.to_bytes()
        self.assertEqual(len(raw), item.size)

        parsed_cursor = HiddenapiClassDataItem.from_cursor(Cursor(raw))
        self.assertEqual(bytes(parsed_cursor.data), bytes(item.data))
        self.assertEqual(parsed_cursor.size, item.size)
        self.assertEqual(parsed_cursor.get_flags(0, count=1), (2,))
        self.assertEqual(parsed_cursor.get_flags(1, count=2), (3, 0))

        buf = b"\x00" * 12 + raw
        parsed_buf = HiddenapiClassDataItem.from_buffer(buf, Offset[HiddenapiClassDataItem](12))
        self.assertEqual(bytes(parsed_buf.data), bytes(item.data))

    def test_index_error_handling(self) -> None:
        """Verify IndexError raised for invalid class_idx."""
        item = HiddenapiClassDataItem.from_class_flags([[1], [2]])

        with self.assertRaises(IndexError):
            item.get_offset(-1)

        with self.assertRaises(IndexError):
            item.get_offset(2)  # Only classes 0 and 1 exist

        with self.assertRaises(IndexError):
            item.get_flags(10, count=1)

    def test_invalid_cursor_size(self) -> None:
        """Verify ValueError raised when size header < 4."""
        invalid_bytes = struct.pack("<I", 2)
        cursor = Cursor(invalid_bytes)
        with self.assertRaises(ValueError):
            HiddenapiClassDataItem.from_cursor(cursor)


if __name__ == "__main__":
    unittest.main()
