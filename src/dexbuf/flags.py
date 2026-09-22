"""Dalvik Executable (DEX) access flags and modifier string formatters.

See https://source.android.com/docs/core/runtime/dex-format#access-flags
"""

from enum import IntFlag

__all__ = [
    "CLASS_FLAGS_MASK",
    "FIELD_FLAGS_MASK",
    "METHOD_FLAGS_MASK",
    "AccessFlags",
    "format_class_flags",
    "format_field_flags",
    "format_method_flags",
]


class AccessFlags(IntFlag):
    """Bit flags used to indicate accessibility and properties of classes, fields, and methods.

    See https://source.android.com/docs/core/runtime/dex-format#access-flags
    """

    PUBLIC = 0x0001
    PRIVATE = 0x0002
    PROTECTED = 0x0004
    STATIC = 0x0008
    FINAL = 0x0010
    SYNCHRONIZED = 0x0020
    VOLATILE = 0x0040
    BRIDGE = 0x0040
    TRANSIENT = 0x0080
    VARARGS = 0x0080
    NATIVE = 0x0100
    INTERFACE = 0x0200
    ABSTRACT = 0x0400
    STRICTFP = 0x0800
    SYNTHETIC = 0x1000
    ANNOTATION = 0x2000
    ENUM = 0x4000
    CONSTRUCTOR = 0x00010000
    DECLARED_SYNCHRONIZED = 0x00020000


CLASS_FLAGS_MASK: int = (
    AccessFlags.PUBLIC
    | AccessFlags.FINAL
    | AccessFlags.INTERFACE
    | AccessFlags.ABSTRACT
    | AccessFlags.SYNTHETIC
    | AccessFlags.ANNOTATION
    | AccessFlags.ENUM
)

FIELD_FLAGS_MASK: int = (
    AccessFlags.PUBLIC
    | AccessFlags.PRIVATE
    | AccessFlags.PROTECTED
    | AccessFlags.STATIC
    | AccessFlags.FINAL
    | AccessFlags.VOLATILE
    | AccessFlags.TRANSIENT
    | AccessFlags.SYNTHETIC
    | AccessFlags.ENUM
)

METHOD_FLAGS_MASK: int = (
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
    | AccessFlags.DECLARED_SYNCHRONIZED
)

_CLASS_MODIFIERS: tuple[tuple[int, str], ...] = (
    (AccessFlags.PUBLIC, "public"),
    (AccessFlags.ABSTRACT, "abstract"),
    (AccessFlags.FINAL, "final"),
    (AccessFlags.SYNTHETIC, "synthetic"),
    (AccessFlags.ANNOTATION, "annotation"),
    (AccessFlags.ENUM, "enum"),
    (AccessFlags.INTERFACE, "interface"),
)

_FIELD_MODIFIERS: tuple[tuple[int, str], ...] = (
    (AccessFlags.PUBLIC, "public"),
    (AccessFlags.PROTECTED, "protected"),
    (AccessFlags.PRIVATE, "private"),
    (AccessFlags.STATIC, "static"),
    (AccessFlags.FINAL, "final"),
    (AccessFlags.TRANSIENT, "transient"),
    (AccessFlags.VOLATILE, "volatile"),
    (AccessFlags.SYNTHETIC, "synthetic"),
    (AccessFlags.ENUM, "enum"),
)

_METHOD_MODIFIERS: tuple[tuple[int, str], ...] = (
    (AccessFlags.PUBLIC, "public"),
    (AccessFlags.PROTECTED, "protected"),
    (AccessFlags.PRIVATE, "private"),
    (AccessFlags.ABSTRACT, "abstract"),
    (AccessFlags.STATIC, "static"),
    (AccessFlags.FINAL, "final"),
    (AccessFlags.SYNCHRONIZED, "synchronized"),
    (AccessFlags.BRIDGE, "bridge"),
    (AccessFlags.VARARGS, "varargs"),
    (AccessFlags.NATIVE, "native"),
    (AccessFlags.STRICTFP, "strictfp"),
    (AccessFlags.SYNTHETIC, "synthetic"),
    (AccessFlags.CONSTRUCTOR, "constructor"),
    (AccessFlags.DECLARED_SYNCHRONIZED, "declared-synchronized"),
)


def format_class_flags(flags: int | AccessFlags) -> str:
    """Format class access flags into space-separated Java modifier string."""
    masked = int(flags) & CLASS_FLAGS_MASK
    return " ".join(name for bit, name in _CLASS_MODIFIERS if masked & bit)


def format_field_flags(flags: int | AccessFlags) -> str:
    """Format field access flags into space-separated Java modifier string."""
    masked = int(flags) & FIELD_FLAGS_MASK
    return " ".join(name for bit, name in _FIELD_MODIFIERS if masked & bit)


def format_method_flags(flags: int | AccessFlags) -> str:
    """Format method access flags into space-separated Java modifier string."""
    masked = int(flags) & METHOD_FLAGS_MASK
    return " ".join(name for bit, name in _METHOD_MODIFIERS if masked & bit)
