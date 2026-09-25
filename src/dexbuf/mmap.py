"""Standalone memory-mapping utilities for dexbuf readers."""

import contextlib
import mmap
import os
from collections.abc import Iterator

__all__ = ["open_mmap", "scoped_mmap"]


def open_mmap(path: str | os.PathLike[str]) -> mmap.mmap:
    """Open path and return a read-only memory-mapping with unscoped, GC-managed lifetime.

    The underlying OS file descriptor is closed immediately upon exiting the function,
    leaving the memory mapping active.
    """
    with open(path, "rb") as f:
        return mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)


@contextlib.contextmanager
def scoped_mmap(path: str | os.PathLike[str]) -> Iterator[mmap.mmap]:
    """Context manager yielding a read-only memory-mapping of path.

    The underlying OS file descriptor is closed immediately after creating the mmap object.
    When exiting the context, attempts mm.close(), safely catching BufferError if active
    child slices or pointers outlive the block.
    """
    with open(path, "rb") as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    try:
        yield mm
    finally:
        try:
            mm.close()
        except BufferError:
            pass
