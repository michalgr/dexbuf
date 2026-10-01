"""Command-line interface for dexdump tool in dexbuf."""

import argparse
import os
import sys
from collections.abc import Sequence

import dexbuf
from dexbuf.flags import format_class_flags, format_field_flags, format_method_flags
from dexbuf.model import ResolvedClass

__all__ = ["disassemble_class", "main"]


def disassemble_class(cls: ResolvedClass) -> str:
    """Format the full disassembly for a ResolvedClass."""
    lines: list[str] = []

    cflags = format_class_flags(cls.access_flags)
    if cflags:
        lines.append(f".class {cflags} {cls.descriptor}")
    else:
        lines.append(f".class {cls.descriptor}")

    if cls.super_class is not None:
        lines.append(f".super {cls.super_class.descriptor}")

    for iface in cls.interfaces:
        lines.append(f".implements {iface.descriptor}")

    for field in cls.fields:
        fflags = format_field_flags(field.access_flags)
        fhead = f".field {fflags} " if fflags else ".field "
        fval = ""
        if field.initial_value is not None:
            fval = f" = {field.initial_value.value}"
        lines.append(f"{fhead}{field.name}:{field.type_descriptor}{fval}")

    for method in cls.methods:
        if method.has_code and method.code is not None:
            lines.append(method.code.disassemble())
        else:
            mflags = format_method_flags(method.access_flags)
            mhead = f".method {mflags} " if mflags else ".method "
            lines.append(f"{mhead}{method.name}{method.descriptor}")

    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point for dexdump tool."""
    parser = argparse.ArgumentParser(
        prog="dexdump",
        description="Dexdump CLI tool for DEX, APK, JAR, ZIP, or VDEX containers.",
    )
    parser.add_argument(
        "container",
        help="Path to DEX, APK, JAR, ZIP, or VDEX container file.",
    )
    parser.add_argument(
        "-l",
        "--list",
        action="store_true",
        help="List all defined class names in the container.",
    )
    parser.add_argument(
        "-d",
        "--disassemble",
        metavar="CLASS",
        help="Disassemble the specified class name or descriptor.",
    )

    args = parser.parse_args(argv)

    try:
        loader = dexbuf.open(args.container)
    except (FileNotFoundError, OSError, ValueError) as exc:
        sys.stderr.write(f"Error opening container {args.container!r}: {exc}\n")
        return 1

    try:
        with loader:
            if args.disassemble is not None:
                cls = loader.load_class(args.disassemble)
                if cls is None:
                    sys.stderr.write(
                        f"Error: Class {args.disassemble!r} not found in "
                        f"container {args.container!r}.\n"
                    )
                    return 1
                sys.stdout.write(disassemble_class(cls) + "\n")
                return 0

            # Default action or --list: list defined classes
            for cls in loader:
                sys.stdout.write(f"{cls.name}\n")
    except BrokenPipeError:
        try:
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, sys.stdout.fileno())
            os.close(devnull)
        except Exception:
            pass
        return 0

    return 0
