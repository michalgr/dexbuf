"""Unit tests for DEX call site, encoded array, and annotation items."""

import unittest
from dataclasses import FrozenInstanceError
from typing import Any

from dexbuf import (
    AnnotationElement,
    AnnotationItem,
    AnnotationOffItem,
    AnnotationsDirectoryItem,
    AnnotationSetItem,
    AnnotationSetRefItem,
    AnnotationSetRefList,
    AnnotationVisibility,
    CallSiteIdItem,
    EncodedAnnotation,
    EncodedArray,
    EncodedArrayItem,
    EncodedValue,
    FieldAnnotation,
    FieldIdItem,
    Idx,
    MethodAnnotation,
    MethodIdItem,
    Offset,
    ParameterAnnotation,
    ValueType,
)


class TestEncodedArrayItemAndCallSiteIdItem(unittest.TestCase):
    def test_encoded_array_item(self) -> None:
        """Verify EncodedArrayItem immutability, parsing, and serialization."""
        val = EncodedValue(value_arg=0, value_type=ValueType.INT, value=100)
        arr = EncodedArray(values=(val,))
        item = EncodedArrayItem(value=arr)

        with self.assertRaises(FrozenInstanceError):
            item.value = arr  # type: ignore[misc]

        raw = item.to_bytes()
        parsed = EncodedArrayItem.from_buffer(raw)
        self.assertEqual(parsed, item)
        self.assertEqual(parsed.value.values[0].value, 100)

    def test_call_site_id_item(self) -> None:
        """Verify CallSiteIdItem call_site_off typed as Offset[EncodedArrayItem]."""
        item = CallSiteIdItem(call_site_off=Offset[EncodedArrayItem](0x001000))
        with self.assertRaises(FrozenInstanceError):
            item.call_site_off = Offset[EncodedArrayItem](0x2000)  # type: ignore[misc]

        raw = item.to_bytes()
        parsed = CallSiteIdItem.from_buffer(raw)
        self.assertEqual(parsed, item)
        self.assertEqual(parsed.call_site_off, Offset[EncodedArrayItem](0x001000))


class TestAnnotationItems(unittest.TestCase):
    def test_annotation_visibility_enum(self) -> None:
        """Verify AnnotationVisibility values."""
        self.assertEqual(AnnotationVisibility.BUILD, 0x00)
        self.assertEqual(AnnotationVisibility.RUNTIME, 0x01)
        self.assertEqual(AnnotationVisibility.SYSTEM, 0x02)

    def test_annotation_item(self) -> None:
        """Verify AnnotationItem immutability, parsing, and serialization."""
        val = EncodedValue(value_arg=0, value_type=ValueType.INT, value=42)
        elem = AnnotationElement(name_idx=Idx[Any](1), value=val)
        ann = EncodedAnnotation(type_idx=Idx[Any](10), elements=(elem,))
        item = AnnotationItem(visibility=AnnotationVisibility.RUNTIME, annotation=ann)

        with self.assertRaises(FrozenInstanceError):
            item.visibility = AnnotationVisibility.BUILD  # type: ignore[misc]

        raw = item.to_bytes()
        parsed = AnnotationItem.from_buffer(raw)
        self.assertEqual(parsed, item)
        self.assertEqual(parsed.visibility, AnnotationVisibility.RUNTIME)

    def test_annotation_off_item(self) -> None:
        """Verify AnnotationOffItem immutability and roundtrip."""
        item = AnnotationOffItem(annotation_off=Offset[AnnotationItem](0x1234))
        with self.assertRaises(FrozenInstanceError):
            item.annotation_off = Offset[AnnotationItem](0x5678)  # type: ignore[misc]

        raw = item.to_bytes()
        self.assertEqual(len(raw), 4)

        parsed = AnnotationOffItem.from_buffer(raw)
        self.assertEqual(parsed, item)

    def test_annotation_set_item(self) -> None:
        """Verify AnnotationSetItem sequence protocol, immutability, and roundtrip."""
        entry1 = AnnotationOffItem(annotation_off=Offset[AnnotationItem](0x100))
        entry2 = AnnotationOffItem(annotation_off=Offset[AnnotationItem](0x200))
        set_item = AnnotationSetItem(entries=(entry1, entry2))

        with self.assertRaises((TypeError, AttributeError)):
            set_item.size = 1  # type: ignore[misc]

        self.assertEqual(len(set_item), 2)
        self.assertEqual(set_item[0], entry1)
        self.assertEqual(set_item[1], entry2)
        self.assertEqual(set_item[0:], (entry1, entry2))
        self.assertEqual(list(set_item), [entry1, entry2])

        raw = set_item.to_bytes()
        self.assertEqual(len(raw), 4 + 2 * 4)

        parsed = AnnotationSetItem.from_buffer(raw)
        self.assertEqual(parsed, set_item)

    def test_annotation_set_ref_item(self) -> None:
        """Verify AnnotationSetRefItem immutability and roundtrip."""
        item = AnnotationSetRefItem(annotations_off=Offset[AnnotationSetItem](0x300))
        with self.assertRaises(FrozenInstanceError):
            item.annotations_off = Offset[AnnotationSetItem](0x400)  # type: ignore[misc]

        raw = item.to_bytes()
        self.assertEqual(len(raw), 4)

        parsed = AnnotationSetRefItem.from_buffer(raw)
        self.assertEqual(parsed, item)

    def test_annotation_set_ref_list(self) -> None:
        """Verify AnnotationSetRefList sequence protocol, immutability, and roundtrip."""
        ref1 = AnnotationSetRefItem(annotations_off=Offset[AnnotationSetItem](0x1000))
        ref2 = AnnotationSetRefItem(annotations_off=Offset[AnnotationSetItem](0x2000))
        ref_list = AnnotationSetRefList(list=(ref1, ref2))

        with self.assertRaises((TypeError, AttributeError)):
            ref_list.size = 3  # type: ignore[misc]

        self.assertEqual(len(ref_list), 2)
        self.assertEqual(ref_list[0], ref1)
        self.assertEqual(ref_list[1], ref2)
        self.assertEqual(ref_list[0:1], (ref1,))
        self.assertEqual(list(ref_list), [ref1, ref2])

        raw = ref_list.to_bytes()
        self.assertEqual(len(raw), 4 + 2 * 4)

        parsed = AnnotationSetRefList.from_buffer(raw)
        self.assertEqual(parsed, ref_list)

    def test_field_method_parameter_annotation(self) -> None:
        """Verify annotation immutability and roundtrip."""
        fa = FieldAnnotation(
            field_idx=Idx[FieldIdItem](1),
            annotations_off=Offset[AnnotationSetItem](0x100),
        )
        ma = MethodAnnotation(
            method_idx=Idx[MethodIdItem](2),
            annotations_off=Offset[AnnotationSetItem](0x200),
        )
        pa = ParameterAnnotation(
            method_idx=Idx[MethodIdItem](3),
            annotations_off=Offset[AnnotationSetRefList](0x300),
        )

        with self.assertRaises(FrozenInstanceError):
            fa.field_idx = Idx[FieldIdItem](10)  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            ma.method_idx = Idx[MethodIdItem](20)  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            pa.method_idx = Idx[MethodIdItem](30)  # type: ignore[misc]

        self.assertEqual(FieldAnnotation.from_buffer(fa.to_bytes()), fa)
        self.assertEqual(MethodAnnotation.from_buffer(ma.to_bytes()), ma)
        self.assertEqual(ParameterAnnotation.from_buffer(pa.to_bytes()), pa)

    def test_annotations_directory_item(self) -> None:
        """Verify AnnotationsDirectoryItem immutability and roundtrip."""
        fa = FieldAnnotation(
            field_idx=Idx[FieldIdItem](1),
            annotations_off=Offset[AnnotationSetItem](0x100),
        )
        ma = MethodAnnotation(
            method_idx=Idx[MethodIdItem](2),
            annotations_off=Offset[AnnotationSetItem](0x200),
        )
        pa = ParameterAnnotation(
            method_idx=Idx[MethodIdItem](3),
            annotations_off=Offset[AnnotationSetRefList](0x300),
        )

        dir_item = AnnotationsDirectoryItem(
            class_annotations_off=Offset[AnnotationSetItem](0x500),
            field_annotations=(fa,),
            method_annotations=(ma,),
            parameter_annotations=(pa,),
        )

        self.assertEqual(dir_item.fields_size, 1)
        self.assertEqual(dir_item.annotated_methods_size, 1)
        self.assertEqual(dir_item.annotated_parameters_size, 1)

        with self.assertRaises((TypeError, AttributeError)):
            dir_item.fields_size = 2  # type: ignore[misc]

        raw = dir_item.to_bytes()
        self.assertEqual(len(raw), 16 + 8 + 8 + 8)

        parsed = AnnotationsDirectoryItem.from_buffer(raw)
        self.assertEqual(parsed, dir_item)


if __name__ == "__main__":
    unittest.main()
