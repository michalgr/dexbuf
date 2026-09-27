"""High-level domain layer ClassLoader architecture and Class hierarchy.

See https://source.android.com/docs/core/runtime/dex-format
"""

import builtins
import fnmatch
import os
from abc import ABC, abstractmethod
from collections.abc import Buffer, Iterator, Sequence
from typing import Any, Self

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
    "ClassLoader",
    "ClassLoaderElement",
    "ResolvedClass",
    "UnresolvedClass",
    "load",
    "open",
]


class Class(ABC):
    """Abstract base class representing a Java / Dalvik class or interface."""

    __slots__ = ()

    @property
    @abstractmethod
    def descriptor(self) -> str:
        """Dalvik type descriptor (e.g. 'Lcom/example/Foo;')."""

    @property
    @abstractmethod
    def is_resolved(self) -> bool:
        """True for ResolvedClass, False for UnresolvedClass."""

    @property
    def name(self) -> str:
        """Canonical Java type name (e.g. 'com.example.Foo')."""
        return descriptor_to_type_name(self.descriptor)

    @property
    def package(self) -> str:
        """Package part of Java type name (e.g. 'com.example')."""
        name = self.name
        return name.rpartition(".")[0] if "." in name else ""

    @property
    def simple_name(self) -> str:
        """Unqualified simple class name (e.g. 'Foo')."""
        name = self.name
        return name.rpartition(".")[2] if "." in name else name

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Class):
            return NotImplemented
        return type(self) is type(other) and self.descriptor == other.descriptor

    def __hash__(self) -> int:
        return hash((type(self), self.descriptor))

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return f"<Class {self.name!r}>"


class UnresolvedClass(Class):
    """Represents an external Android SDK, Java runtime, or unprovided library class."""

    __slots__ = ("_descriptor",)

    def __init__(self, descriptor_or_name: str) -> None:
        if not (descriptor_or_name.startswith("L") or descriptor_or_name.startswith("[")):
            descriptor = type_name_to_descriptor(descriptor_or_name)
        else:
            descriptor = descriptor_or_name
        self._descriptor: str = descriptor

    @property
    def descriptor(self) -> str:
        return self._descriptor

    @property
    def is_resolved(self) -> bool:
        return False

    def __repr__(self) -> str:
        return f"<UnresolvedClass {self.name!r}>"


class ResolvedClass(Class):
    """Represents a class definition found in a DEX file."""

    __slots__ = ("_def", "_dex", "_loader")

    def __init__(self, loader: ClassLoader, dex: DexFile, class_def: ClassDefItem) -> None:
        self._loader: ClassLoader = loader
        self._dex: DexFile = dex
        self._def: ClassDefItem = class_def

    @property
    def is_resolved(self) -> bool:
        return True

    @property
    def descriptor(self) -> str:
        return self._dex.get_type_descriptor(self._def.class_idx)

    @property
    def loader(self) -> ClassLoader:
        return self._loader

    @property
    def dex_file(self) -> DexFile:
        return self._dex

    @property
    def class_def(self) -> ClassDefItem:
        return self._def

    @property
    def access_flags(self) -> AccessFlags:
        return AccessFlags(self._def.access_flags)

    @property
    def is_public(self) -> bool:
        return bool(self.access_flags & AccessFlags.PUBLIC)

    @property
    def is_final(self) -> bool:
        return bool(self.access_flags & AccessFlags.FINAL)

    @property
    def is_interface(self) -> bool:
        return bool(self.access_flags & AccessFlags.INTERFACE)

    @property
    def is_abstract(self) -> bool:
        return bool(self.access_flags & AccessFlags.ABSTRACT)

    @property
    def is_synthetic(self) -> bool:
        return bool(self.access_flags & AccessFlags.SYNTHETIC)

    @property
    def is_annotation(self) -> bool:
        return bool(self.access_flags & AccessFlags.ANNOTATION)

    @property
    def is_enum(self) -> bool:
        return bool(self.access_flags & AccessFlags.ENUM)

    @property
    def source_file(self) -> str | None:
        if self._def.source_file_idx == NO_INDEX:
            return None
        return self._dex.get_string(self._def.source_file_idx)

    @property
    def super_class(self) -> Class | None:
        if self._def.superclass_idx == NO_INDEX:
            return None
        super_desc = self._dex.get_type_descriptor(self._def.superclass_idx)
        resolved = self._loader.load_class(super_desc)
        if resolved is not None:
            return resolved
        return UnresolvedClass(super_desc)

    @property
    def interfaces(self) -> tuple[Class, ...]:
        if self._def.interfaces_off == NO_OFFSET or self._def.interfaces_off == 0:
            return ()
        type_list = self._dex.get_type_list(self._def.interfaces_off)
        result: list[Class] = []
        for item in type_list.list:
            desc = self._dex.get_type_descriptor(item.type_idx)
            resolved = self._loader.load_class(desc)
            if resolved is not None:
                result.append(resolved)
            else:
                result.append(UnresolvedClass(desc))
        return tuple(result)

    def __repr__(self) -> str:
        return f"<Class {self.name!r}>"


type ClassLoaderElement = ClassLoader | DexFile | VdexFile | ZipArchive


def _get_multidex_names(zip_archive: ZipArchive) -> list[str]:
    names: list[tuple[int, str]] = []
    for name in zip_archive.namelist():
        if name == "classes.dex":
            names.append((1, name))
        elif name.startswith("classes") and name.endswith(".dex"):
            num_str = name[7:-4]
            if num_str.isdigit():
                names.append((int(num_str), name))
    names.sort(key=lambda item: item[0])
    return [name for _, name in names]


class ClassLoader:
    """Interleaved ordered container mirroring Android class-loading semantics."""

    __slots__ = ("_cache", "_resources", "elements")

    def __init__(self, elements: Sequence[ClassLoaderElement] | None = None) -> None:
        if elements is not None:
            for elem in elements:
                if not isinstance(elem, (ClassLoader, DexFile, VdexFile, ZipArchive)):
                    raise TypeError(f"Invalid ClassLoaderElement type: {type(elem).__name__}")
            self.elements: tuple[ClassLoaderElement, ...] = tuple(elements)
        else:
            self.elements = ()

        self._cache: dict[str, ResolvedClass | None] = {}
        self._resources: list[Any] = []

    def load_class(self, descriptor_or_name: str) -> ResolvedClass | None:
        """Resolve a class definition by descriptor or Java type name."""
        if not (descriptor_or_name.startswith("L") or descriptor_or_name.startswith("[")):
            descriptor = type_name_to_descriptor(descriptor_or_name)
        else:
            descriptor = descriptor_or_name

        if descriptor in self._cache:
            return self._cache[descriptor]

        resolved = self._find_first(descriptor)
        self._cache[descriptor] = resolved
        return resolved

    def _find_first(self, descriptor: str) -> ResolvedClass | None:
        for element in self.elements:
            if isinstance(element, ClassLoader):
                res = element.load_class(descriptor)
                if res is not None:
                    return res
            elif isinstance(element, DexFile):
                cdef = element.find_class_def(descriptor)
                if cdef is not None:
                    return ResolvedClass(self, element, cdef)
            elif isinstance(element, VdexFile):
                for dex in element.dex_files:
                    cdef = dex.find_class_def(descriptor)
                    if cdef is not None:
                        return ResolvedClass(self, dex, cdef)
            elif isinstance(element, ZipArchive):
                for entry_name in _get_multidex_names(element):
                    dex = DexFile(element.read(entry_name))
                    cdef = dex.find_class_def(descriptor)
                    if cdef is not None:
                        return ResolvedClass(self, dex, cdef)
        return None

    def find_all(self, descriptor_or_name: str) -> list[ResolvedClass]:
        """Find all matching class definitions across all elements without early stopping."""
        if not (descriptor_or_name.startswith("L") or descriptor_or_name.startswith("[")):
            descriptor = type_name_to_descriptor(descriptor_or_name)
        else:
            descriptor = descriptor_or_name

        results: list[ResolvedClass] = []
        for element in self.elements:
            if isinstance(element, ClassLoader):
                results.extend(element.find_all(descriptor))
            elif isinstance(element, DexFile):
                cdef = element.find_class_def(descriptor)
                if cdef is not None:
                    results.append(ResolvedClass(self, element, cdef))
            elif isinstance(element, VdexFile):
                for dex in element.dex_files:
                    cdef = dex.find_class_def(descriptor)
                    if cdef is not None:
                        results.append(ResolvedClass(self, dex, cdef))
            elif isinstance(element, ZipArchive):
                for entry_name in _get_multidex_names(element):
                    dex = DexFile(element.read(entry_name))
                    cdef = dex.find_class_def(descriptor)
                    if cdef is not None:
                        results.append(ResolvedClass(self, dex, cdef))
        return results

    def find(self, pattern: str) -> list[ResolvedClass]:
        """Find classes matching glob pattern on canonical Java class name."""
        return [cls for cls in self if fnmatch.fnmatch(cls.name, pattern)]

    def __getitem__(self, key: str) -> ResolvedClass:
        cls = self.load_class(key)
        if cls is None:
            raise KeyError(key)
        return cls

    def get(self, key: str) -> ResolvedClass | None:
        return self.load_class(key)

    def __contains__(self, key: object) -> bool:
        if isinstance(key, Class):
            key = key.descriptor
        if not isinstance(key, str):
            return False
        try:
            return self.load_class(key) is not None
        except ValueError:
            return False

    def __iter__(self) -> Iterator[ResolvedClass]:
        seen: set[str] = set()
        for element in self.elements:
            if isinstance(element, ClassLoader):
                for cls in element:
                    if cls.descriptor not in seen:
                        seen.add(cls.descriptor)
                        yield cls
            elif isinstance(element, DexFile):
                for cdef in element.class_defs:
                    desc = element.get_type_descriptor(cdef.class_idx)
                    if desc not in seen:
                        seen.add(desc)
                        yield ResolvedClass(self, element, cdef)
            elif isinstance(element, VdexFile):
                for dex in element.dex_files:
                    for cdef in dex.class_defs:
                        desc = dex.get_type_descriptor(cdef.class_idx)
                        if desc not in seen:
                            seen.add(desc)
                            yield ResolvedClass(self, dex, cdef)
            elif isinstance(element, ZipArchive):
                for entry_name in _get_multidex_names(element):
                    dex = DexFile(element.read(entry_name))
                    for cdef in dex.class_defs:
                        desc = dex.get_type_descriptor(cdef.class_idx)
                        if desc not in seen:
                            seen.add(desc)
                            yield ResolvedClass(self, dex, cdef)

    def __len__(self) -> int:
        return sum(1 for _ in self)

    def close(self) -> None:
        """Close tracked resources and child elements."""
        for res in self._resources:
            if hasattr(res, "close"):
                try:
                    res.close()
                except Exception:
                    pass
            elif isinstance(res, memoryview):
                try:
                    res.release()
                except BufferError:
                    pass
        self._resources.clear()

        for elem in self.elements:
            if isinstance(elem, ClassLoader):
                elem.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


def load(buffer: Buffer) -> ClassLoader:
    """Detect binary format of buffer and return a ClassLoader wrapping it."""
    view = memoryview(buffer)
    if len(view) >= 4 and view[:4] == b"dex\n":
        container: ClassLoaderElement = DexFile(buffer)
    elif len(view) >= 2 and view[:2] == b"PK":
        container = ZipArchive(buffer)
    elif len(view) >= 4 and view[:4] == b"vdex":
        container = VdexFile(buffer)
    else:
        magic = bytes(view[:8])
        raise ValueError(f"Unrecognized binary format (magic: {magic!r})")

    return ClassLoader([container])


def open(path: str | os.PathLike[str], *, mmap: bool = True) -> ClassLoader:
    """Open a DEX, APK/ZIP, or VDEX container file and return a ClassLoader."""
    if mmap:
        buf: Buffer = open_mmap(path)
    else:
        with builtins.open(path, "rb") as f:
            buf = f.read()

    loader = load(buf)
    loader._resources.append(buf)
    return loader
