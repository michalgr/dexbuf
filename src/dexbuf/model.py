"""High-level domain models and top-level DEX collection interfaces.

See https://source.android.com/docs/core/runtime/dex-format
"""

import builtins
import fnmatch
import os
from collections.abc import Buffer, Iterator, Mapping, Sequence
from types import TracebackType
from typing import Self, TypeVar, overload

from dexbuf.descriptors import descriptor_to_type_name, type_name_to_descriptor
from dexbuf.dex import DexFile
from dexbuf.flags import AccessFlags
from dexbuf.items import ClassDefItem
from dexbuf.mmap import open_mmap
from dexbuf.types import NO_INDEX, NO_OFFSET
from dexbuf.vdex import VdexFile
from dexbuf.zip import ZipArchive

__all__ = [
    "Class",
    "ClassCollection",
    "DexCollection",
    "UnresolvedClass",
    "load",
    "open",
]

T = TypeVar("T")


class UnresolvedClass:
    """Slotted representation for external framework or missing classes."""

    __slots__ = ("_descriptor", "_name", "_package", "_simple_name")

    def __init__(self, name_or_descriptor: str, descriptor: str | None = None) -> None:
        if descriptor is not None:
            self._name = name_or_descriptor
            self._descriptor = descriptor
        elif name_or_descriptor.startswith("L") and name_or_descriptor.endswith(";"):
            self._descriptor = name_or_descriptor
            self._name = descriptor_to_type_name(name_or_descriptor)
        else:
            self._name = name_or_descriptor
            self._descriptor = type_name_to_descriptor(name_or_descriptor)

        if "." in self._name:
            self._package, _, self._simple_name = self._name.rpartition(".")
        else:
            self._package = ""
            self._simple_name = self._name

    @property
    def name(self) -> str:
        """Canonical Java name (e.g. 'android.app.Activity')."""
        return self._name

    @property
    def descriptor(self) -> str:
        """Dalvik descriptor (e.g. 'Landroid/app/Activity;')."""
        return self._descriptor

    @property
    def package(self) -> str:
        """Package name (e.g. 'android.app')."""
        return self._package

    @property
    def simple_name(self) -> str:
        """Simple class name (e.g. 'Activity')."""
        return self._simple_name

    @property
    def is_resolved(self) -> bool:
        """Return False for UnresolvedClass."""
        return False

    def __repr__(self) -> str:
        return f"<UnresolvedClass {self._name!r}>"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, UnresolvedClass):
            return self._name == other._name and self._descriptor == other._descriptor
        return False


class Class:
    """Slotted lightweight wrapper over defined DEX class."""

    __slots__ = (
        "_collection",
        "_def",
        "_descriptor",
        "_dex",
        "_name",
        "_package",
        "_simple_name",
    )

    def __init__(
        self,
        collection: DexCollection,
        dex_file: DexFile,
        class_def: ClassDefItem,
    ) -> None:
        self._collection = collection
        self._dex = dex_file
        self._def = class_def

        self._descriptor = dex_file.get_type_descriptor(class_def.class_idx)
        self._name = descriptor_to_type_name(self._descriptor)
        if "." in self._name:
            self._package, _, self._simple_name = self._name.rpartition(".")
        else:
            self._package = ""
            self._simple_name = self._name

    @property
    def name(self) -> str:
        """Canonical Java name (e.g. 'com.example.MainActivity')."""
        return self._name

    @property
    def descriptor(self) -> str:
        """Dalvik descriptor (e.g. 'Lcom/example/MainActivity;')."""
        return self._descriptor

    @property
    def package(self) -> str:
        """Package name (e.g. 'com.example')."""
        return self._package

    @property
    def simple_name(self) -> str:
        """Class simple name (e.g. 'MainActivity')."""
        return self._simple_name

    @property
    def access_flags(self) -> AccessFlags:
        """DEX access flags for this class."""
        return AccessFlags(self._def.access_flags)

    @property
    def is_public(self) -> bool:
        """Return True if class is public."""
        return bool(self._def.access_flags & AccessFlags.PUBLIC)

    @property
    def is_final(self) -> bool:
        """Return True if class is final."""
        return bool(self._def.access_flags & AccessFlags.FINAL)

    @property
    def is_interface(self) -> bool:
        """Return True if class is an interface."""
        return bool(self._def.access_flags & AccessFlags.INTERFACE)

    @property
    def is_abstract(self) -> bool:
        """Return True if class is abstract."""
        return bool(self._def.access_flags & AccessFlags.ABSTRACT)

    @property
    def is_synthetic(self) -> bool:
        """Return True if class is synthetic."""
        return bool(self._def.access_flags & AccessFlags.SYNTHETIC)

    @property
    def is_annotation(self) -> bool:
        """Return True if class is an annotation."""
        return bool(self._def.access_flags & AccessFlags.ANNOTATION)

    @property
    def is_enum(self) -> bool:
        """Return True if class is an enum."""
        return bool(self._def.access_flags & AccessFlags.ENUM)

    @property
    def super_class(self) -> Class | UnresolvedClass | None:
        """Resolved superclass Class, UnresolvedClass, or None if no superclass."""
        if (
            self._def.superclass_idx == NO_INDEX
            or self._def.superclass_idx == 0xFFFF_FFFF
            or self._descriptor == "Ljava/lang/Object;"
        ):
            return None

        super_desc = self._dex.get_type_descriptor(self._def.superclass_idx)
        resolved = self._collection.classes.get(super_desc)
        if resolved is not None:
            return resolved
        return UnresolvedClass(super_desc)

    @property
    def interfaces(self) -> tuple[Class | UnresolvedClass, ...]:
        """Resolved tuple of interface Class or UnresolvedClass instances."""
        if self._def.interfaces_off == NO_OFFSET or self._def.interfaces_off == 0:
            return ()

        type_list = self._dex.get_type_list(self._def.interfaces_off)
        result: list[Class | UnresolvedClass] = []
        for item in type_list:
            iface_desc = self._dex.get_type_descriptor(item.type_idx)
            resolved = self._collection.classes.get(iface_desc)
            if resolved is not None:
                result.append(resolved)
            else:
                result.append(UnresolvedClass(iface_desc))
        return tuple(result)

    @property
    def source_file(self) -> str | None:
        """Source file name or None if not set."""
        if self._def.source_file_idx == NO_INDEX or self._def.source_file_idx == 0xFFFF_FFFF:
            return None
        return self._dex.get_string(self._def.source_file_idx)

    @property
    def is_resolved(self) -> bool:
        """Return True for defined Class."""
        return True

    @property
    def dex_file(self) -> DexFile:
        """Reference to the DexFile where this class is defined."""
        return self._dex

    def __repr__(self) -> str:
        return f"<Class {self._name!r}>"


class ClassCollection(Sequence[Class], Mapping[str, Class]):  # type: ignore[invalid-inheritance]
    """Lazy, indexed sequence and mapping over all classes across a DexCollection."""

    __slots__ = ("_by_descriptor", "_by_name", "_classes", "_collection")

    def __init__(self, dex_collection: DexCollection) -> None:
        self._collection = dex_collection
        self._classes: list[Class] = []
        self._by_name: dict[str, Class] = {}
        self._by_descriptor: dict[str, Class] = {}

        for dex in dex_collection.dex_files:
            for class_def in dex.class_defs:
                cls_obj = Class(dex_collection, dex, class_def)
                self._classes.append(cls_obj)
                if cls_obj.name not in self._by_name:
                    self._by_name[cls_obj.name] = cls_obj
                if cls_obj.descriptor not in self._by_descriptor:
                    self._by_descriptor[cls_obj.descriptor] = cls_obj

    def __len__(self) -> int:
        return len(self._classes)

    @overload
    def __getitem__(self, key: int) -> Class: ...

    @overload
    def __getitem__(self, key: slice) -> tuple[Class, ...]: ...

    @overload
    def __getitem__(self, key: str) -> Class: ...

    def __getitem__(self, key: int | str | slice) -> Class | tuple[Class, ...]:
        if isinstance(key, int):
            return self._classes[key]
        elif isinstance(key, slice):
            return tuple(self._classes[key])
        elif isinstance(key, str):
            if key in self._by_name:
                return self._by_name[key]
            if key in self._by_descriptor:
                return self._by_descriptor[key]
            raise KeyError(key)
        else:
            raise TypeError(f"Invalid key type: {type(key).__name__}")

    def __iter__(self) -> Iterator[Class]:  # type: ignore[bad-override]
        return iter(self._classes)

    def get(self, key: str, default: T = None) -> Class | T:  # type: ignore[override]
        """Safe lookup by class name or descriptor."""
        try:
            return self[key]
        except KeyError:
            return default

    def find(self, pattern: str) -> list[Class]:
        """Wildcard/fnmatch pattern match on class names or descriptors."""
        return [
            cls
            for cls in self._classes
            if fnmatch.fnmatch(cls.name, pattern) or fnmatch.fnmatch(cls.descriptor, pattern)
        ]


def _multidex_sort_key(filename: str) -> tuple[int, int]:
    """Helper to generate canonical sorting keys for multi-DEX APK entry names."""
    if "/" in filename or "\\" in filename:
        return (1, 0)
    if filename == "classes.dex":
        return (0, 1)
    if filename.startswith("classes") and filename.endswith(".dex"):
        middle = filename[7:-4]
        if middle.isdigit():
            return (0, int(middle))
    return (1, 0)


class DexCollection:
    """Aggregated container for one or more DexFile instances (single DEX, MultiDEX APK, VDEX)."""

    __slots__ = ("_buffer", "classes", "dex_files")

    def __init__(self, dex_files: Sequence[DexFile], *, buffer: Buffer | None = None) -> None:
        self.dex_files: tuple[DexFile, ...] = tuple(dex_files)
        self._buffer: Buffer | None = buffer
        self.classes: ClassCollection = ClassCollection(self)

    def get_class(self, name_or_descriptor: str) -> Class | None:
        """Lookup defined class by name or descriptor."""
        return self.classes.get(name_or_descriptor)

    @classmethod
    def open(cls, path: str | os.PathLike[str], *, mmap: bool = True) -> DexCollection:
        """Open DEX, APK, or VDEX file at path."""
        if mmap:
            buf = open_mmap(path)
        else:
            with builtins.open(path, "rb") as f:
                buf = f.read()
        return cls.from_buffer(buf)

    @classmethod
    def from_buffer(cls, buffer: Buffer) -> DexCollection:
        """Construct DexCollection from buffer autodetecting container format."""
        mv = memoryview(buffer)
        if len(mv) < 4:
            raise ValueError("Buffer too small to detect container format")

        magic = bytes(mv[:4])
        if magic.startswith(b"dex\n"):
            dex = DexFile(buffer)
            return cls((dex,), buffer=buffer)
        elif magic.startswith(b"PK"):
            zip_arch = ZipArchive(buffer)
            entries: list[tuple[int, str]] = []
            for name in zip_arch.namelist():
                key = _multidex_sort_key(name)
                if key[0] == 0:
                    entries.append((key[1], name))
            entries.sort()
            dex_files = tuple(DexFile(zip_arch.read(name)) for _, name in entries)
            return cls(dex_files, buffer=buffer)
        elif magic == b"vdex":
            vdex = VdexFile(buffer)
            return cls(tuple(vdex.dex_files), buffer=buffer)
        else:
            raise ValueError(f"Unrecognized container format magic: {magic!r}")

    def close(self) -> None:
        """Release underlying buffer resources."""
        if self._buffer is not None:
            if hasattr(self._buffer, "close") and callable(self._buffer.close):
                try:
                    self._buffer.close()
                except BufferError:
                    pass
            elif hasattr(self._buffer, "release") and callable(self._buffer.release):
                try:
                    self._buffer.release()
                except BufferError:
                    pass

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.close()


def open(path: str | os.PathLike[str], *, mmap: bool = True) -> DexCollection:
    """Open DEX, MultiDEX APK, or VDEX container from file path."""
    return DexCollection.open(path, mmap=mmap)


def load(buffer: Buffer) -> DexCollection:
    """Load DEX, MultiDEX APK, or VDEX container from buffer."""
    return DexCollection.from_buffer(buffer)
