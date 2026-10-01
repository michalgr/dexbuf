"""Command-line interface for dexdump tool in dexbuf."""

import argparse
import os
import sys
from collections.abc import Sequence

import dexbuf
from dexbuf.model import ResolvedClass

__all__ = ["disassemble_class", "main"]


def disassemble_class(cls: ResolvedClass) -> str:
    """Format the full disassembly for a ResolvedClass."""
    return cls.disassemble()


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
