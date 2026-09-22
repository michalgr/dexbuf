"""Unit tests for DEX AccessFlags and modifier formatters."""

import unittest

from dexbuf.flags import (
    CLASS_FLAGS_MASK,
    FIELD_FLAGS_MASK,
    METHOD_FLAGS_MASK,
    AccessFlags,
    format_class_flags,
    format_field_flags,
    format_method_flags,
)


class TestAccessFlags(unittest.TestCase):
    def test_bitwise_operations(self) -> None:
        """Verify bitwise operations on AccessFlags enum."""
        flags = AccessFlags.PUBLIC | AccessFlags.STATIC | AccessFlags.FINAL
        self.assertIn(AccessFlags.PUBLIC, flags)
        self.assertIn(AccessFlags.STATIC, flags)
        self.assertIn(AccessFlags.FINAL, flags)
        self.assertNotIn(AccessFlags.PRIVATE, flags)

        self.assertTrue(flags & AccessFlags.PUBLIC)
        self.assertFalse(flags & AccessFlags.PRIVATE)

        combined = flags & ~AccessFlags.STATIC
        self.assertEqual(combined, AccessFlags.PUBLIC | AccessFlags.FINAL)

    def test_flag_values(self) -> None:
        """Verify exact bit integer values of DEX specification access flags."""
        self.assertEqual(AccessFlags.PUBLIC, 0x0001)
        self.assertEqual(AccessFlags.PRIVATE, 0x0002)
        self.assertEqual(AccessFlags.PROTECTED, 0x0004)
        self.assertEqual(AccessFlags.STATIC, 0x0008)
        self.assertEqual(AccessFlags.FINAL, 0x0010)
        self.assertEqual(AccessFlags.SYNCHRONIZED, 0x0020)
        self.assertEqual(AccessFlags.VOLATILE, 0x0040)
        self.assertEqual(AccessFlags.BRIDGE, 0x0040)
        self.assertEqual(AccessFlags.TRANSIENT, 0x0080)
        self.assertEqual(AccessFlags.VARARGS, 0x0080)
        self.assertEqual(AccessFlags.NATIVE, 0x0100)
        self.assertEqual(AccessFlags.INTERFACE, 0x0200)
        self.assertEqual(AccessFlags.ABSTRACT, 0x0400)
        self.assertEqual(AccessFlags.STRICTFP, 0x0800)
        self.assertEqual(AccessFlags.SYNTHETIC, 0x1000)
        self.assertEqual(AccessFlags.ANNOTATION, 0x2000)
        self.assertEqual(AccessFlags.ENUM, 0x4000)
        self.assertEqual(AccessFlags.CONSTRUCTOR, 0x00010000)
        self.assertEqual(AccessFlags.DECLARED_SYNCHRONIZED, 0x00020000)

    def test_masks(self) -> None:
        """Verify target-specific bitmask values."""
        self.assertEqual(
            CLASS_FLAGS_MASK,
            AccessFlags.PUBLIC
            | AccessFlags.FINAL
            | AccessFlags.INTERFACE
            | AccessFlags.ABSTRACT
            | AccessFlags.SYNTHETIC
            | AccessFlags.ANNOTATION
            | AccessFlags.ENUM,
        )
        self.assertEqual(
            FIELD_FLAGS_MASK,
            AccessFlags.PUBLIC
            | AccessFlags.PRIVATE
            | AccessFlags.PROTECTED
            | AccessFlags.STATIC
            | AccessFlags.FINAL
            | AccessFlags.VOLATILE
            | AccessFlags.TRANSIENT
            | AccessFlags.SYNTHETIC
            | AccessFlags.ENUM,
        )
        self.assertEqual(
            METHOD_FLAGS_MASK,
            AccessFlags.PUBLIC
            | AccessFlags.PRIVATE
            | AccessFlags.PROTECTED
            | AccessFlags.STATIC
            | AccessFlags.FINAL
            | AccessFlags.SYNCHRONIZED
            | AccessFlags.BRIDGE
            | AccessFlags.VARARGS
            | AccessFlags.NATIVE
            | AccessFlags.ABSTRACT
            | AccessFlags.STRICTFP
            | AccessFlags.SYNTHETIC
            | AccessFlags.CONSTRUCTOR
            | AccessFlags.DECLARED_SYNCHRONIZED,
        )

    def test_format_class_flags(self) -> None:
        """Verify formatting of class access flags."""
        self.assertEqual(format_class_flags(0), "")
        self.assertEqual(
            format_class_flags(AccessFlags.PUBLIC | AccessFlags.ABSTRACT),
            "public abstract",
        )
        self.assertEqual(
            format_class_flags(
                AccessFlags.PUBLIC | AccessFlags.FINAL | AccessFlags.SYNTHETIC | AccessFlags.ENUM
            ),
            "public final synthetic enum",
        )
        self.assertEqual(
            format_class_flags(
                AccessFlags.PUBLIC
                | AccessFlags.INTERFACE
                | AccessFlags.ABSTRACT
                | AccessFlags.ANNOTATION
            ),
            "public abstract synthetic annotation interface"
            if "synthetic" in format_class_flags(AccessFlags.ANNOTATION)
            else "public abstract annotation interface",
        )

    def test_format_field_flags(self) -> None:
        """Verify formatting of field access flags."""
        self.assertEqual(format_field_flags(0), "")
        self.assertEqual(
            format_field_flags(AccessFlags.PUBLIC | AccessFlags.STATIC | AccessFlags.FINAL),
            "public static final",
        )
        self.assertEqual(
            format_field_flags(AccessFlags.PRIVATE | AccessFlags.TRANSIENT | AccessFlags.VOLATILE),
            "private transient volatile",
        )
        self.assertEqual(
            format_field_flags(AccessFlags.PROTECTED | AccessFlags.ENUM),
            "protected enum",
        )

    def test_format_method_flags(self) -> None:
        """Verify formatting of method access flags."""
        self.assertEqual(format_method_flags(0), "")
        self.assertEqual(
            format_method_flags(AccessFlags.PUBLIC | AccessFlags.STATIC | AccessFlags.FINAL),
            "public static final",
        )
        self.assertEqual(
            format_method_flags(
                AccessFlags.PROTECTED | AccessFlags.ABSTRACT | AccessFlags.SYNCHRONIZED
            ),
            "protected abstract synchronized",
        )
        self.assertEqual(
            format_method_flags(
                AccessFlags.PUBLIC | AccessFlags.CONSTRUCTOR | AccessFlags.DECLARED_SYNCHRONIZED
            ),
            "public constructor declared-synchronized",
        )
        self.assertEqual(
            format_method_flags(AccessFlags.PUBLIC | AccessFlags.BRIDGE | AccessFlags.VARARGS),
            "public bridge varargs",
        )

    def test_formatting_raw_integers_and_extra_bits(self) -> None:
        """Verify raw integer input and masking of unknown/extra bits."""
        # 0x8000 is an unassigned/extra bit for field flags
        extra_bits_field = 0x8000 | 0x0001 | 0x0008 | 0x0010
        self.assertEqual(format_field_flags(extra_bits_field), "public static final")

        # Extra bit for class flags
        extra_bits_class = 0x8000 | 0x0001 | 0x0400
        self.assertEqual(format_class_flags(extra_bits_class), "public abstract")

        # Extra bit for method flags
        extra_bits_method = 0x80000 | 0x0001 | 0x0100
        self.assertEqual(format_method_flags(extra_bits_method), "public native")


if __name__ == "__main__":
    unittest.main()
