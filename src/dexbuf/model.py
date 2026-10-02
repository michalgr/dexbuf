"""High-level domain layer ClassLoader architecture and Class hierarchy.

See https://source.android.com/docs/core/runtime/dex-format
"""

import builtins
import fnmatch
import os
from abc import ABC, abstractmethod
from collections.abc import Buffer, Iterator, Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Protocol, Self, TypeIs, runtime_checkable

from dexbuf.descriptors import (
    Descriptor,
    descriptor_to_type_name,
    format_method_descriptor,
    to_descriptor,
)
from dexbuf.dex import DexFile
from dexbuf.flags import (
    AccessFlags,
    format_class_flags,
    format_field_flags,
    format_method_flags,
)
from dexbuf.instructions import (
    Opcode,
    PackedSwitchPayload,
    Payload,
    SparseSwitchPayload,
    get_id,
    get_literal,
    has_id,
    is_branch,
    is_conditional_branch,
    is_return,
    is_switch,
    is_throw,
    is_unconditional_branch,
)
from dexbuf.instructions.formats import (
    HasTarget,
    Instruction,
)
from dexbuf.items import (
    AnnotationItem,
    AnnotationSetItem,
    AnnotationVisibility,
    ClassDefItem,
    CodeItem,
    EncodedField,
    EncodedMethod,
    EncodedTypeAddrPair,
    FieldIdItem,
    MethodIdItem,
    ProtoIdItem,
    StringIdItem,
    TryItem,
    TypeIdItem,
)
from dexbuf.mmap import open_mmap
from dexbuf.types import NO_INDEX, NO_OFFSET, Offset, Reg
from dexbuf.value import EncodedValue
from dexbuf.vdex import VdexFile
from dexbuf.zip import ZipArchive

type ClassLoaderElementInput = ClassLoaderElement | DexFile | VdexFile | ZipArchive

__all__ = [
    "Annotation",
    "BasicBlock",
    "CatchEdge",
    "CatchHandler",
    "Class",
    "ClassLoader",
    "ClassLoaderElement",
    "ClassLoaderElementInput",
    "Code",
    "CodeInstruction",
    "DexAdapter",
    "Field",
    "Method",
    "ResolvedClass",
    "TryCatch",
    "UnresolvedClass",
    "VdexAdapter",
    "ZipAdapter",
    "is_resolved",
    "load",
    "open",
]


class Annotation:
    """Represents an annotation attached to a class, field, or method."""

    __slots__ = ("_dex", "_elements", "_item")

    def __init__(self, dex: DexFile, item: AnnotationItem) -> None:
        self._dex: DexFile = dex
        self._item: AnnotationItem = item
        self._elements: Mapping[str, EncodedValue] = MappingProxyType(
            {dex.get_string(elem.name_idx): elem.value for elem in item.annotation.elements}
        )

    @property
    def type_descriptor(self) -> Descriptor:
        return self._dex.get_type_descriptor(self._item.annotation.type_idx)

    @property
    def type_name(self) -> str:
        return descriptor_to_type_name(self.type_descriptor)

    @property
    def visibility(self) -> AnnotationVisibility:
        return AnnotationVisibility(self._item.visibility)

    @property
    def is_runtime(self) -> bool:
        return self.visibility == AnnotationVisibility.RUNTIME

    @property
    def is_build(self) -> bool:
        return self.visibility == AnnotationVisibility.BUILD

    @property
    def is_system(self) -> bool:
        return self.visibility == AnnotationVisibility.SYSTEM

    @property
    def elements(self) -> Mapping[str, EncodedValue]:
        return self._elements

    @property
    def raw(self) -> AnnotationItem:
        return self._item

    def __getitem__(self, name: str) -> EncodedValue:
        return self._elements[name]

    def get(self, name: str, default: EncodedValue | None = None) -> EncodedValue | None:
        return self._elements.get(name, default)

    def __contains__(self, name: object) -> bool:
        return name in self._elements

    def __iter__(self) -> Iterator[str]:
        return iter(self._elements)

    def __len__(self) -> int:
        return len(self._elements)

    def __repr__(self) -> str:
        return f"<Annotation '@{self.type_name}'>"

    def __str__(self) -> str:
        return f"@{self.type_name}"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Annotation):
            return NotImplemented
        return (
            type(self) is type(other)
            and self.type_descriptor == other.type_descriptor
            and self.visibility == other.visibility
            and self.elements == other.elements
        )

    def __hash__(self) -> int:
        return hash(
            (
                type(self),
                self.type_descriptor,
                self.visibility,
                tuple(sorted(self.elements.items())),
            )
        )


class Method:
    """Represents a method definition in a ResolvedClass."""

    __slots__ = (
        "_annotations",
        "_cls",
        "_code",
        "_encoded",
        "_is_direct",
        "_method_id",
        "_method_idx",
        "_parameter_annotations",
    )

    def __init__(
        self,
        cls: ResolvedClass,
        encoded: EncodedMethod,
        method_idx: int,
        method_id: MethodIdItem,
        is_direct: bool,
    ) -> None:
        self._cls: ResolvedClass = cls
        self._encoded: EncodedMethod = encoded
        self._method_idx: int = method_idx
        self._method_id: MethodIdItem = method_id
        self._is_direct: bool = is_direct
        self._code: Code | None = None
        self._annotations: tuple[Annotation, ...] | None = None
        self._parameter_annotations: tuple[tuple[Annotation, ...], ...] | None = None

    @property
    def defining_class(self) -> ResolvedClass:
        return self._cls

    @property
    def name(self) -> str:
        return self._cls.dex_file.get_string(self._method_id.name_idx)

    @property
    def method_idx(self) -> int:
        return self._method_idx

    @property
    def encoded_method(self) -> EncodedMethod:
        return self._encoded

    @property
    def method_id(self) -> MethodIdItem:
        return self._method_id

    @property
    def is_direct(self) -> bool:
        return self._is_direct

    @property
    def is_virtual(self) -> bool:
        return not self._is_direct

    @property
    def access_flags(self) -> AccessFlags:
        return AccessFlags(self._encoded.access_flags)

    @property
    def proto(self) -> ProtoIdItem:
        return self._cls.dex_file.get_proto_id(self._method_id.proto_idx)

    @property
    def shorty(self) -> str:
        return self._cls.dex_file.get_string(self.proto.shorty_idx)

    @property
    def return_type_descriptor(self) -> Descriptor:
        return self._cls.dex_file.get_type_descriptor(self.proto.return_type_idx)

    @property
    def return_type_name(self) -> str:
        return descriptor_to_type_name(self.return_type_descriptor)

    @property
    def return_type_class(self) -> Class:
        resolved = self._cls.loader.load_class(self.return_type_descriptor)
        if resolved is not None:
            return resolved
        return UnresolvedClass(self.return_type_descriptor)

    @property
    def return_type(self) -> Class:
        return self.return_type_class

    @property
    def parameter_type_descriptors(self) -> tuple[Descriptor, ...]:
        if self.proto.parameters_off == NO_OFFSET:
            return ()
        type_list = self._cls.dex_file.get_type_list(self.proto.parameters_off)
        return tuple(
            self._cls.dex_file.get_type_descriptor(item.type_idx) for item in type_list.list
        )

    @property
    def parameter_type_names(self) -> tuple[str, ...]:
        return tuple(descriptor_to_type_name(d) for d in self.parameter_type_descriptors)

    @property
    def parameter_types(self) -> tuple[Class, ...]:
        result: list[Class] = []
        for desc in self.parameter_type_descriptors:
            resolved = self._cls.loader.load_class(desc)
            if resolved is not None:
                result.append(resolved)
            else:
                result.append(UnresolvedClass(desc))
        return tuple(result)

    @property
    def descriptor(self) -> str:
        return format_method_descriptor(
            self.parameter_type_descriptors, self.return_type_descriptor
        )

    @property
    def has_code(self) -> bool:
        return self._encoded.code_off != NO_OFFSET

    @property
    def code(self) -> Code | None:
        if self._code is not None:
            return self._code
        if self.has_code:
            code_item = self._cls.dex_file.get_code_item(self._encoded.code_off)
            self._code = Code(self, code_item)
            return self._code
        return None

    @property
    def is_public(self) -> bool:
        return bool(self.access_flags & AccessFlags.PUBLIC)

    @property
    def is_private(self) -> bool:
        return bool(self.access_flags & AccessFlags.PRIVATE)

    @property
    def is_protected(self) -> bool:
        return bool(self.access_flags & AccessFlags.PROTECTED)

    @property
    def is_static(self) -> bool:
        return bool(self.access_flags & AccessFlags.STATIC)

    @property
    def is_final(self) -> bool:
        return bool(self.access_flags & AccessFlags.FINAL)

    @property
    def is_synchronized(self) -> bool:
        return bool(self.access_flags & AccessFlags.SYNCHRONIZED)

    @property
    def is_bridge(self) -> bool:
        return bool(self.access_flags & AccessFlags.BRIDGE)

    @property
    def is_varargs(self) -> bool:
        return bool(self.access_flags & AccessFlags.VARARGS)

    @property
    def is_native(self) -> bool:
        return bool(self.access_flags & AccessFlags.NATIVE)

    @property
    def is_abstract(self) -> bool:
        return bool(self.access_flags & AccessFlags.ABSTRACT)

    @property
    def is_strictfp(self) -> bool:
        return bool(self.access_flags & AccessFlags.STRICTFP)

    @property
    def is_synthetic(self) -> bool:
        return bool(self.access_flags & AccessFlags.SYNTHETIC)

    @property
    def is_constructor(self) -> bool:
        return bool(self.access_flags & AccessFlags.CONSTRUCTOR) or self.name in (
            "<init>",
            "<clinit>",
        )

    @property
    def annotations(self) -> tuple[Annotation, ...]:
        if self._annotations is not None:
            return self._annotations
        self._annotations = self._cls._get_method_annotations(self._method_idx)
        return self._annotations

    @property
    def parameter_annotations(self) -> tuple[tuple[Annotation, ...], ...]:
        if self._parameter_annotations is not None:
            return self._parameter_annotations
        param_count = len(self.parameter_type_descriptors)
        self._parameter_annotations = self._cls._get_method_parameter_annotations(
            self._method_idx, param_count
        )
        return self._parameter_annotations

    def get_annotation(self, name_or_descriptor: str) -> Annotation | None:
        desc = to_descriptor(name_or_descriptor)
        for ann in self.annotations:
            if ann.type_descriptor == desc:
                return ann
        return None

    def disassemble(self) -> str:
        """Format the smali disassembly for this method."""
        if self.has_code and self.code is not None:
            return self.code.disassemble()
        mflags = format_method_flags(self.access_flags)
        mhead = f".method {mflags} " if mflags else ".method "
        return f"{mhead}{self.name}{self.descriptor}"

    def __repr__(self) -> str:
        return f"<Method '{self._cls.name}.{self.name}{self.descriptor}'>"

    def __str__(self) -> str:
        params_str = ", ".join(self.parameter_type_names)
        return f"{self.return_type_name} {self._cls.name}.{self.name}({params_str})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Method):
            return NotImplemented
        return (
            self._cls == other._cls
            and self.name == other.name
            and self.descriptor == other.descriptor
        )

    def __hash__(self) -> int:
        return hash((type(self), self._cls, self.name, self.descriptor))


class Field:
    """Represents a field definition in a ResolvedClass."""

    __slots__ = ("_annotations", "_cls", "_encoded", "_field_id", "_field_idx", "_initial_value")

    def __init__(
        self,
        cls: ResolvedClass,
        encoded: EncodedField,
        field_idx: int,
        field_id: FieldIdItem,
        initial_value: EncodedValue | None = None,
    ) -> None:
        self._cls: ResolvedClass = cls
        self._encoded: EncodedField = encoded
        self._field_idx: int = field_idx
        self._field_id: FieldIdItem = field_id
        self._initial_value: EncodedValue | None = initial_value
        self._annotations: tuple[Annotation, ...] | None = None

    @property
    def defining_class(self) -> ResolvedClass:
        return self._cls

    @property
    def name(self) -> str:
        return self._cls.dex_file.get_string(self._field_id.name_idx)

    @property
    def type_descriptor(self) -> Descriptor:
        return self._cls.dex_file.get_type_descriptor(self._field_id.type_idx)

    @property
    def type_name(self) -> str:
        return descriptor_to_type_name(self.type_descriptor)

    @property
    def type_class(self) -> Class:
        resolved = self._cls.loader.load_class(self.type_descriptor)
        if resolved is not None:
            return resolved
        return UnresolvedClass(self.type_descriptor)

    @property
    def type(self) -> Class:
        return self.type_class

    @property
    def access_flags(self) -> AccessFlags:
        return AccessFlags(self._encoded.access_flags)

    @property
    def initial_value(self) -> EncodedValue | None:
        return self._initial_value

    @property
    def field_idx(self) -> int:
        return self._field_idx

    @property
    def encoded_field(self) -> EncodedField:
        return self._encoded

    @property
    def is_static(self) -> bool:
        return bool(self.access_flags & AccessFlags.STATIC)

    @property
    def is_public(self) -> bool:
        return bool(self.access_flags & AccessFlags.PUBLIC)

    @property
    def is_private(self) -> bool:
        return bool(self.access_flags & AccessFlags.PRIVATE)

    @property
    def is_protected(self) -> bool:
        return bool(self.access_flags & AccessFlags.PROTECTED)

    @property
    def is_final(self) -> bool:
        return bool(self.access_flags & AccessFlags.FINAL)

    @property
    def is_volatile(self) -> bool:
        return bool(self.access_flags & AccessFlags.VOLATILE)

    @property
    def is_transient(self) -> bool:
        return bool(self.access_flags & AccessFlags.TRANSIENT)

    @property
    def is_synthetic(self) -> bool:
        return bool(self.access_flags & AccessFlags.SYNTHETIC)

    @property
    def is_enum(self) -> bool:
        return bool(self.access_flags & AccessFlags.ENUM)

    @property
    def annotations(self) -> tuple[Annotation, ...]:
        if self._annotations is not None:
            return self._annotations
        self._annotations = self._cls._get_field_annotations(self._field_idx)
        return self._annotations

    def get_annotation(self, name_or_descriptor: str) -> Annotation | None:
        desc = to_descriptor(name_or_descriptor)
        for ann in self.annotations:
            if ann.type_descriptor == desc:
                return ann
        return None

    def disassemble(self) -> str:
        """Format the smali disassembly directive for this field."""
        fflags = format_field_flags(self.access_flags)
        fhead = f".field {fflags} " if fflags else ".field "
        fval = ""
        if self.initial_value is not None:
            fval = f" = {self.initial_value.value}"
        return f"{fhead}{self.name}:{self.type_descriptor}{fval}"

    def __repr__(self) -> str:
        return f"<Field '{self._cls.name}.{self.name}: {self.type_name}'>"

    def __str__(self) -> str:
        return f"{self._cls.name}.{self.name}: {self.type_name}"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Field):
            return NotImplemented
        return (
            self._cls == other._cls
            and self.name == other.name
            and self.type_descriptor == other.type_descriptor
        )

    def __hash__(self) -> int:
        return hash((type(self), self._cls, self.name, self.type_descriptor))


class Class(ABC):
    """Abstract base class representing a Java / Dalvik class or interface."""

    descriptor: Descriptor
    __slots__ = ("descriptor",)

    def __init__(self, descriptor: str) -> None:
        self.descriptor: Descriptor = to_descriptor(descriptor)

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

    __slots__ = ()

    def __init__(self, descriptor: str) -> None:
        super().__init__(descriptor)

    @classmethod
    def from_name_or_descriptor(cls, name_or_descriptor: str) -> Self:
        """Create an UnresolvedClass from either a Java type name or Dalvik descriptor."""
        return cls(to_descriptor(name_or_descriptor))

    @property
    def is_resolved(self) -> bool:
        return False

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, UnresolvedClass):
            return NotImplemented
        return self.descriptor == other.descriptor

    def __hash__(self) -> int:
        return hash((type(self), self.descriptor))

    def __repr__(self) -> str:
        return f"<UnresolvedClass {self.name!r}>"


class ResolvedClass(Class):
    """Represents a class definition found in a DEX file."""

    __slots__ = (
        "_annotations",
        "_def",
        "_dex",
        "_direct_methods",
        "_fields",
        "_instance_fields",
        "_loader",
        "_methods",
        "_static_fields",
        "_virtual_methods",
    )

    def __init__(self, loader: ClassLoader, dex: DexFile, class_def: ClassDefItem) -> None:
        super().__init__(dex.get_type_descriptor(class_def.class_idx))
        self._loader: ClassLoader = loader
        self._dex: DexFile = dex
        self._def: ClassDefItem = class_def
        self._fields: tuple[Field, ...] | None = None
        self._static_fields: tuple[Field, ...] | None = None
        self._instance_fields: tuple[Field, ...] | None = None
        self._direct_methods: tuple[Method, ...] | None = None
        self._virtual_methods: tuple[Method, ...] | None = None
        self._methods: tuple[Method, ...] | None = None
        self._annotations: tuple[Annotation, ...] | None = None

    @property
    def is_resolved(self) -> bool:
        return True

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ResolvedClass):
            return NotImplemented
        return self._loader is other._loader and self.descriptor == other.descriptor

    def __hash__(self) -> int:
        return hash((type(self), self._loader, self.descriptor))

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
        if self._def.interfaces_off == NO_OFFSET:
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

    @property
    def static_fields(self) -> tuple[Field, ...]:
        if self._static_fields is not None:
            return self._static_fields

        if self._def.class_data_off == NO_OFFSET:
            self._static_fields = ()
            return self._static_fields

        cdata = self._dex.get_class_data(self._def.class_data_off)

        static_values: tuple[EncodedValue, ...] = ()
        if self._def.static_values_off != NO_OFFSET:
            encoded_array = self._dex.get_static_values(self._def.static_values_off)
            static_values = encoded_array.values

        fields: list[Field] = []
        for idx, (f_idx, encoded) in enumerate(cdata.iter_static_fields()):
            val = static_values[idx] if idx < len(static_values) else None
            f_id = self._dex.get_field_id(f_idx)
            fields.append(Field(self, encoded, f_idx, f_id, val))

        self._static_fields = tuple(fields)
        return self._static_fields

    @property
    def instance_fields(self) -> tuple[Field, ...]:
        if self._instance_fields is not None:
            return self._instance_fields

        if self._def.class_data_off == NO_OFFSET:
            self._instance_fields = ()
            return self._instance_fields

        cdata = self._dex.get_class_data(self._def.class_data_off)
        fields: list[Field] = []
        for f_idx, encoded in cdata.iter_instance_fields():
            f_id = self._dex.get_field_id(f_idx)
            fields.append(Field(self, encoded, f_idx, f_id, None))

        self._instance_fields = tuple(fields)
        return self._instance_fields

    @property
    def fields(self) -> tuple[Field, ...]:
        if self._fields is not None:
            return self._fields
        self._fields = self.static_fields + self.instance_fields
        return self._fields

    def get_field(self, name: str) -> Field | None:
        """Find the first field in self.fields with matching name."""
        for field in self.fields:
            if field.name == name:
                return field
        return None

    @property
    def direct_methods(self) -> tuple[Method, ...]:
        if self._direct_methods is not None:
            return self._direct_methods

        if self._def.class_data_off == NO_OFFSET:
            self._direct_methods = ()
            return self._direct_methods

        cdata = self._dex.get_class_data(self._def.class_data_off)
        methods: list[Method] = []
        for m_idx, encoded in cdata.iter_direct_methods():
            m_id = self._dex.get_method_id(m_idx)
            methods.append(Method(self, encoded, m_idx, m_id, is_direct=True))

        self._direct_methods = tuple(methods)
        return self._direct_methods

    @property
    def virtual_methods(self) -> tuple[Method, ...]:
        if self._virtual_methods is not None:
            return self._virtual_methods

        if self._def.class_data_off == NO_OFFSET:
            self._virtual_methods = ()
            return self._virtual_methods

        cdata = self._dex.get_class_data(self._def.class_data_off)
        methods: list[Method] = []
        for m_idx, encoded in cdata.iter_virtual_methods():
            m_id = self._dex.get_method_id(m_idx)
            methods.append(Method(self, encoded, m_idx, m_id, is_direct=False))

        self._virtual_methods = tuple(methods)
        return self._virtual_methods

    @property
    def methods(self) -> tuple[Method, ...]:
        if self._methods is not None:
            return self._methods
        self._methods = self.direct_methods + self.virtual_methods
        return self._methods

    @property
    def constructors(self) -> tuple[Method, ...]:
        return tuple(m for m in self.direct_methods if m.is_constructor)

    def get_method(self, name: str, descriptor: str | None = None) -> Method | None:
        """Find the first method in self.methods matching name and optional descriptor."""
        if descriptor is not None:
            for m in self.methods:
                if m.name == name and m.descriptor == descriptor:
                    return m
        else:
            for m in self.methods:
                if m.name == name:
                    return m
        return None

    def find_methods(self, name: str) -> list[Method]:
        """Find all methods in self.methods with matching name."""
        return [m for m in self.methods if m.name == name]

    def _parse_annotation_set(self, offset: Offset[AnnotationSetItem]) -> tuple[Annotation, ...]:
        if offset == NO_OFFSET:
            return ()
        set_item = self._dex.get_annotation_set(offset)
        result: list[Annotation] = []
        for entry in set_item.entries:
            if entry.annotation_off != NO_OFFSET:
                item = self._dex.get_annotation_item(entry.annotation_off)
                result.append(Annotation(self._dex, item))
        return tuple(result)

    @property
    def annotations(self) -> tuple[Annotation, ...]:
        if self._annotations is not None:
            return self._annotations

        if self._def.annotations_off == NO_OFFSET:
            self._annotations = ()
            return self._annotations

        dir_item = self._dex.get_annotations_directory(self._def.annotations_off)
        self._annotations = self._parse_annotation_set(dir_item.class_annotations_off)
        return self._annotations

    def get_annotation(self, name_or_descriptor: str) -> Annotation | None:
        desc = to_descriptor(name_or_descriptor)
        for ann in self.annotations:
            if ann.type_descriptor == desc:
                return ann
        return None

    def _get_field_annotations(self, field_idx: int) -> tuple[Annotation, ...]:
        if self._def.annotations_off == NO_OFFSET:
            return ()
        dir_item = self._dex.get_annotations_directory(self._def.annotations_off)
        for fa in dir_item.field_annotations:
            if fa.field_idx == field_idx:
                return self._parse_annotation_set(fa.annotations_off)
        return ()

    def _get_method_annotations(self, method_idx: int) -> tuple[Annotation, ...]:
        if self._def.annotations_off == NO_OFFSET:
            return ()
        dir_item = self._dex.get_annotations_directory(self._def.annotations_off)
        for ma in dir_item.method_annotations:
            if ma.method_idx == method_idx:
                return self._parse_annotation_set(ma.annotations_off)
        return ()

    def _get_method_parameter_annotations(
        self, method_idx: int, param_count: int
    ) -> tuple[tuple[Annotation, ...], ...]:
        if self._def.annotations_off == NO_OFFSET or param_count == 0:
            return tuple(() for _ in range(param_count))
        dir_item = self._dex.get_annotations_directory(self._def.annotations_off)
        for pa in dir_item.parameter_annotations:
            if pa.method_idx == method_idx:
                if pa.annotations_off == NO_OFFSET:
                    break
                ref_list = self._dex.get_annotation_set_ref_list(pa.annotations_off)
                result: list[tuple[Annotation, ...]] = []
                for i in range(param_count):
                    if i < len(ref_list.list):
                        ref_item = ref_list.list[i]
                        result.append(self._parse_annotation_set(ref_item.annotations_off))
                    else:
                        result.append(())
                return tuple(result)
        return tuple(() for _ in range(param_count))

    def disassemble(self) -> str:
        """Format the full disassembly for this ResolvedClass."""
        lines: list[str] = []

        cflags = format_class_flags(self.access_flags)
        if cflags:
            lines.append(f".class {cflags} {self.descriptor}")
        else:
            lines.append(f".class {self.descriptor}")

        if self.super_class is not None:
            lines.append(f".super {self.super_class.descriptor}")

        for iface in self.interfaces:
            lines.append(f".implements {iface.descriptor}")

        for field in self.fields:
            lines.append(field.disassemble())

        for method in self.methods:
            lines.append(method.disassemble())

        return "\n".join(lines)

    def __repr__(self) -> str:
        return f"<Class {self.name!r}>"


def is_resolved(cls: Class) -> TypeIs[ResolvedClass]:
    """Type guard narrowing Class to ResolvedClass (and UnresolvedClass in else branch)."""
    return isinstance(cls, ResolvedClass)


@runtime_checkable
class ClassLoaderElement(Protocol):
    """Protocol for class loader elements providing class resolution and iteration."""

    def load_class(self, descriptor: str) -> ResolvedClass | None: ...

    def find_all(self, descriptor: str) -> Sequence[ResolvedClass]: ...

    def __iter__(self) -> Iterator[ResolvedClass]: ...

    def __len__(self) -> int: ...


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


class DexAdapter:
    """Adapter for wrapping a DexFile into a ClassLoaderElement."""

    __slots__ = ("_dex", "_loader")

    def __init__(self, dex: DexFile, loader: ClassLoader) -> None:
        self._dex: DexFile = dex
        self._loader: ClassLoader = loader

    @property
    def dex_file(self) -> DexFile:
        return self._dex

    def load_class(self, descriptor: str) -> ResolvedClass | None:
        cdef = self._dex.find_class_def(descriptor)
        if cdef is not None:
            return ResolvedClass(self._loader, self._dex, cdef)
        return None

    def find_all(self, descriptor: str) -> Sequence[ResolvedClass]:
        cdef = self._dex.find_class_def(descriptor)
        if cdef is not None:
            return [ResolvedClass(self._loader, self._dex, cdef)]
        return []

    def __iter__(self) -> Iterator[ResolvedClass]:
        for cdef in self._dex.class_defs:
            yield ResolvedClass(self._loader, self._dex, cdef)

    def __len__(self) -> int:
        return len(self._dex.class_defs)


class VdexAdapter:
    """Adapter for wrapping a VdexFile into a ClassLoaderElement."""

    __slots__ = ("_loader", "_vdex")

    def __init__(self, vdex: VdexFile, loader: ClassLoader) -> None:
        self._loader: ClassLoader = loader
        self._vdex: VdexFile = vdex

    @property
    def vdex_file(self) -> VdexFile:
        return self._vdex

    def load_class(self, descriptor: str) -> ResolvedClass | None:
        for dex in self._vdex.dex_files:
            cdef = dex.find_class_def(descriptor)
            if cdef is not None:
                return ResolvedClass(self._loader, dex, cdef)
        return None

    def find_all(self, descriptor: str) -> Sequence[ResolvedClass]:
        results: list[ResolvedClass] = []
        for dex in self._vdex.dex_files:
            cdef = dex.find_class_def(descriptor)
            if cdef is not None:
                results.append(ResolvedClass(self._loader, dex, cdef))
        return results

    def __iter__(self) -> Iterator[ResolvedClass]:
        for dex in self._vdex.dex_files:
            for cdef in dex.class_defs:
                yield ResolvedClass(self._loader, dex, cdef)

    def __len__(self) -> int:
        return sum(len(dex.class_defs) for dex in self._vdex.dex_files)


class ZipAdapter:
    """Adapter for wrapping a ZipArchive into a ClassLoaderElement."""

    __slots__ = ("_archive", "_dex_files", "_loader")

    def __init__(self, archive: ZipArchive, loader: ClassLoader) -> None:
        self._archive: ZipArchive = archive
        self._loader: ClassLoader = loader
        self._dex_files: tuple[DexFile, ...] = tuple(
            DexFile(archive.read(entry_name)) for entry_name in _get_multidex_names(archive)
        )

    @property
    def archive(self) -> ZipArchive:
        return self._archive

    def load_class(self, descriptor: str) -> ResolvedClass | None:
        for dex in self._dex_files:
            cdef = dex.find_class_def(descriptor)
            if cdef is not None:
                return ResolvedClass(self._loader, dex, cdef)
        return None

    def find_all(self, descriptor: str) -> Sequence[ResolvedClass]:
        results: list[ResolvedClass] = []
        for dex in self._dex_files:
            cdef = dex.find_class_def(descriptor)
            if cdef is not None:
                results.append(ResolvedClass(self._loader, dex, cdef))
        return results

    def __iter__(self) -> Iterator[ResolvedClass]:
        for dex in self._dex_files:
            for cdef in dex.class_defs:
                yield ResolvedClass(self._loader, dex, cdef)

    def __len__(self) -> int:
        return sum(len(dex.class_defs) for dex in self._dex_files)


class ClassLoader:
    """Interleaved ordered container mirroring Android class-loading semantics."""

    __slots__ = ("_cache", "_resources", "elements")

    def __init__(self, elements: Sequence[ClassLoaderElement] | None = None) -> None:
        if elements is not None:
            for elem in elements:
                if not isinstance(elem, ClassLoaderElement):
                    raise TypeError(f"Invalid ClassLoaderElement type: {type(elem).__name__}")
            self.elements: tuple[ClassLoaderElement, ...] = tuple(elements)
        else:
            self.elements = ()

        self._cache: dict[str, ResolvedClass | None] = {}
        self._resources: list[object] = []

    @classmethod
    def from_elements(cls, elements: Sequence[ClassLoaderElementInput] | None = None) -> Self:
        """Create a ClassLoader wrapping raw container objects into adapters where needed."""
        if elements is None:
            return cls()
        loader = cls()
        adapted: list[ClassLoaderElement] = []
        for elem in elements:
            if isinstance(elem, DexFile):
                adapted.append(DexAdapter(elem, loader))
            elif isinstance(elem, VdexFile):
                adapted.append(VdexAdapter(elem, loader))
            elif isinstance(elem, ZipArchive):
                adapted.append(ZipAdapter(elem, loader))
            elif isinstance(elem, ClassLoaderElement):
                adapted.append(elem)
            else:
                raise TypeError(f"Invalid ClassLoaderElement type: {type(elem).__name__}")
        loader.elements = tuple(adapted)
        return loader

    def load_class(self, descriptor: str) -> ResolvedClass | None:
        """Resolve a class definition by descriptor or Java type name."""
        desc = to_descriptor(descriptor)

        if desc in self._cache:
            return self._cache[desc]

        resolved: ResolvedClass | None = None
        for element in self.elements:
            res = element.load_class(desc)
            if res is not None:
                resolved = res
                break

        self._cache[desc] = resolved
        return resolved

    def find_all(self, descriptor: str) -> list[ResolvedClass]:
        """Find all matching class definitions across all elements without early stopping."""
        desc = to_descriptor(descriptor)

        results: list[ResolvedClass] = []
        for element in self.elements:
            results.extend(element.find_all(desc))
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
        for element in self.elements:
            yield from element

    def __len__(self) -> int:
        return sum(len(element) for element in self.elements)

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

        for element in self.elements:
            if hasattr(element, "close"):
                try:
                    element.close()  # type: ignore[attr-defined]
                except Exception:
                    pass

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


def load(buffer: Buffer) -> ClassLoader:
    """Detect binary format of buffer and return a ClassLoader wrapping it."""
    view = memoryview(buffer)
    elem: ClassLoaderElementInput
    if len(view) >= 4 and view[:4] == b"dex\n":
        elem = DexFile(buffer)
    elif len(view) >= 2 and view[:2] == b"PK":
        elem = ZipArchive(buffer)
    elif len(view) >= 4 and view[:4] == b"vdex":
        elem = VdexFile(buffer)
    else:
        magic = bytes(view[:8])
        raise ValueError(f"Unrecognized binary format (magic: {magic!r})")

    return ClassLoader.from_elements([elem])


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


class CodeInstruction:
    """High-level Dalvik bytecode instruction model wrapping an Instruction with PC context."""

    __slots__ = ("_insn", "_method", "_next_pc", "_payload", "_pc")

    def __init__(self, method: Method, pc: int, insn: Instruction, next_pc: int) -> None:
        self._method: Method = method
        self._pc: int = pc
        self._insn: Instruction = insn
        self._next_pc: int = next_pc
        self._payload: Payload | None = None

    @property
    def pc(self) -> int:
        return self._pc

    @property
    def next_pc(self) -> int:
        return self._next_pc

    @property
    def code_units(self) -> int:
        return self._insn.code_units

    @property
    def opcode(self) -> Opcode:
        return self._insn.OPCODE

    @property
    def mnemonic(self) -> str:
        return self.opcode.name.lower().replace("_", "-")

    @property
    def registers(self) -> tuple[Reg, ...]:
        return self._insn.registers

    @property
    def register_names(self) -> tuple[str, ...]:
        code = self._method.code
        if code is None:
            return ()
        return tuple(code.register_name(r) for r in self.registers)

    @property
    def is_branch(self) -> bool:
        return is_branch(self._insn)

    @property
    def is_conditional_branch(self) -> bool:
        return is_conditional_branch(self._insn)

    @property
    def is_unconditional_branch(self) -> bool:
        return is_unconditional_branch(self._insn)

    @property
    def is_switch(self) -> bool:
        return is_switch(self._insn)

    @property
    def is_return(self) -> bool:
        return is_return(self._insn)

    @property
    def is_throw(self) -> bool:
        return is_throw(self._insn)

    @property
    def branch_offset(self) -> int | None:
        if isinstance(self._insn, HasTarget):
            return int(self._insn.target)
        return None

    @property
    def target_pc(self) -> int | None:
        offset = self.branch_offset
        if offset is not None:
            return self._pc + offset
        return None

    @property
    def payload(self) -> Payload | None:
        """Associated payload for switch or fill-array-data instructions, or None."""
        return self._payload

    @property
    def next_pcs(self) -> tuple[int, ...]:
        """Control flow successor program counters for this instruction."""
        if self.is_return or self.is_throw:
            return ()
        if self.is_unconditional_branch:
            return (self.target_pc,) if self.target_pc is not None else ()
        if self.is_conditional_branch:
            return (self.next_pc, self.target_pc) if self.target_pc is not None else (self.next_pc,)
        if self.is_switch:
            targets: list[int] = [self.next_pc]
            if isinstance(self._payload, (PackedSwitchPayload, SparseSwitchPayload)):
                for target_offset in self._payload.targets:
                    targets.append(self._pc + int(target_offset))
            return tuple(targets)
        return (self.next_pc,)

    @property
    def string_value(self) -> str | None:
        if has_id(self._insn, StringIdItem):
            id_val = get_id(self._insn, StringIdItem)
            if id_val is not None:
                return self._method.defining_class.dex_file.get_string(id_val)
        return None

    @property
    def type_descriptor(self) -> Descriptor | None:
        if has_id(self._insn, TypeIdItem):
            id_val = get_id(self._insn, TypeIdItem)
            if id_val is not None:
                return self._method.defining_class.dex_file.get_type_descriptor(id_val)
        return None

    @property
    def type_class(self) -> Class | None:
        desc = self.type_descriptor
        if desc is not None:
            cls = self._method.defining_class.loader.load_class(desc)
            return cls if cls is not None else UnresolvedClass(desc)
        return None

    @property
    def field_id(self) -> FieldIdItem | None:
        if has_id(self._insn, FieldIdItem):
            id_val = get_id(self._insn, FieldIdItem)
            if id_val is not None:
                return self._method.defining_class.dex_file.get_field_id(id_val)
        return None

    @property
    def target_field_class_descriptor(self) -> Descriptor | None:
        fid = self.field_id
        if fid is not None:
            return self._method.defining_class.dex_file.get_type_descriptor(fid.class_idx)
        return None

    @property
    def target_field_name(self) -> str | None:
        fid = self.field_id
        if fid is not None:
            return self._method.defining_class.dex_file.get_string(fid.name_idx)
        return None

    @property
    def target_field_type_descriptor(self) -> Descriptor | None:
        fid = self.field_id
        if fid is not None:
            return self._method.defining_class.dex_file.get_type_descriptor(fid.type_idx)
        return None

    @property
    def target_field_full_descriptor(self) -> str | None:
        cls_desc = self.target_field_class_descriptor
        name = self.target_field_name
        type_desc = self.target_field_type_descriptor
        if cls_desc is not None and name is not None and type_desc is not None:
            return f"{cls_desc}->{name}:{type_desc}"
        return None

    @property
    def method_id(self) -> MethodIdItem | None:
        if has_id(self._insn, MethodIdItem):
            id_val = get_id(self._insn, MethodIdItem)
            if id_val is not None:
                return self._method.defining_class.dex_file.get_method_id(id_val)
        return None

    @property
    def target_method_class_descriptor(self) -> Descriptor | None:
        mid = self.method_id
        if mid is not None:
            return self._method.defining_class.dex_file.get_type_descriptor(mid.class_idx)
        return None

    @property
    def target_method_name(self) -> str | None:
        mid = self.method_id
        if mid is not None:
            return self._method.defining_class.dex_file.get_string(mid.name_idx)
        return None

    @property
    def target_method_descriptor(self) -> str | None:
        mid = self.method_id
        if mid is not None:
            dex = self._method.defining_class.dex_file
            proto = dex.get_proto_id(mid.proto_idx)
            ret_desc = dex.get_type_descriptor(proto.return_type_idx)
            param_descs: list[Descriptor] = []
            if proto.parameters_off != NO_OFFSET:
                tlist = dex.get_type_list(proto.parameters_off)
                param_descs = [dex.get_type_descriptor(item.type_idx) for item in tlist.list]
            return format_method_descriptor(param_descs, ret_desc)
        return None

    @property
    def target_method_full_descriptor(self) -> str | None:
        cls_desc = self.target_method_class_descriptor
        name = self.target_method_name
        method_desc = self.target_method_descriptor
        if cls_desc is not None and name is not None and method_desc is not None:
            return f"{cls_desc}->{name}{method_desc}"
        return None

    @property
    def literal(self) -> int | None:
        return get_literal(self._insn)

    @property
    def raw(self) -> Instruction:
        return self._insn

    @property
    def raw_instruction(self) -> Instruction:
        return self._insn

    def disassemble(self) -> str:
        """Format the smali disassembly for this instruction."""
        parts: list[str] = [f"{self.pc:04x}: {self.mnemonic}"]
        details: list[str] = []
        if self.register_names:
            details.append(", ".join(self.register_names))
        if self.string_value is not None:
            details.append(f'"{self.string_value}"')
        elif self.type_descriptor is not None:
            details.append(f"{self.type_descriptor}")
        elif self.target_field_full_descriptor is not None:
            details.append(f"{self.target_field_full_descriptor}")
        elif self.target_method_full_descriptor is not None:
            details.append(f"{self.target_method_full_descriptor}")
        elif self.literal is not None:
            details.append(f"#{self.literal}")

        if self.target_pc is not None:
            details.append(f"# {self.target_pc:04x}")

        if details:
            parts.append(" " + ", ".join(details))
        return "".join(parts)

    def __repr__(self) -> str:
        return f"<CodeInstruction 0x{self._pc:04x}: {self.mnemonic}>"


class CatchHandler:
    """Represents an exception catch handler target in a method."""

    __slots__ = ("_cls", "_is_catch_all", "_pair", "_target_pc")

    def __init__(
        self,
        cls: ResolvedClass,
        target_pc: int,
        pair: EncodedTypeAddrPair | None = None,
    ) -> None:
        self._cls: ResolvedClass = cls
        self._target_pc: int = target_pc
        self._pair: EncodedTypeAddrPair | None = pair

    @property
    def target_pc(self) -> int:
        return self._target_pc

    @property
    def is_catch_all(self) -> bool:
        return self._pair is None

    @property
    def type_descriptor(self) -> Descriptor | None:
        if self._pair is not None:
            return self._cls.dex_file.get_type_descriptor(self._pair.type_idx)
        return None

    @property
    def type_name(self) -> str | None:
        desc = self.type_descriptor
        if desc is not None:
            return descriptor_to_type_name(desc)
        return None

    @property
    def type_class(self) -> Class | None:
        desc = self.type_descriptor
        if desc is not None:
            cls = self._cls.loader.load_class(desc)
            return cls if cls is not None else UnresolvedClass(desc)
        return None

    @property
    def raw(self) -> EncodedTypeAddrPair | None:
        return self._pair

    def __repr__(self) -> str:
        target = f"0x{self._target_pc:04x}"
        tname = self.type_name if self.type_name is not None else "catch-all"
        return f"<CatchHandler target={target} type={tname!r}>"


@dataclass(slots=True, frozen=True)
class CatchEdge:
    """Represents an exception handling transition from a protected block to a handler block."""

    handler: CatchHandler
    target_block: BasicBlock

    @property
    def type_descriptor(self) -> Descriptor | None:
        return self.handler.type_descriptor

    @property
    def is_catch_all(self) -> bool:
        return self.handler.is_catch_all


class TryCatch:
    """Represents a try block and its associated catch handlers in a method."""

    __slots__ = ("_handlers", "_try_item")

    def __init__(self, try_item: TryItem, handlers: tuple[CatchHandler, ...]) -> None:
        self._try_item: TryItem = try_item
        self._handlers: tuple[CatchHandler, ...] = handlers

    @property
    def start_pc(self) -> int:
        return self._try_item.start_addr

    @property
    def end_pc(self) -> int:
        return self._try_item.end_addr

    @property
    def handlers(self) -> tuple[CatchHandler, ...]:
        return self._handlers

    @property
    def raw(self) -> TryItem:
        return self._try_item

    def covers(self, pc: int) -> bool:
        return self._try_item.covers(pc)

    def __repr__(self) -> str:
        spc = f"0x{self.start_pc:04x}"
        epc = f"0x{self.end_pc:04x}"
        return f"<TryCatch {spc}..{epc} handlers={len(self._handlers)}>"


class BasicBlock:
    """Represents a basic block in the control flow graph (CFG)."""

    __slots__ = (
        "_catch_edges",
        "_end_pc",
        "_exception_handlers",
        "_handled_catches",
        "_id",
        "_instructions",
        "_predecessors",
        "_protected_blocks",
        "_start_pc",
        "_successors",
        "_terminator",
    )

    def __init__(
        self,
        id: int,
        start_pc: int,
        end_pc: int,
        instructions: tuple[CodeInstruction, ...],
        terminator: CodeInstruction,
        exception_handlers: tuple[CatchHandler, ...] = (),
    ) -> None:
        self._id: int = id
        self._start_pc: int = start_pc
        self._end_pc: int = end_pc
        self._instructions: tuple[CodeInstruction, ...] = instructions
        self._terminator: CodeInstruction = terminator
        self._exception_handlers: tuple[CatchHandler, ...] = exception_handlers
        self._predecessors: tuple[BasicBlock, ...] = ()
        self._successors: tuple[BasicBlock, ...] = ()
        self._catch_edges: tuple[CatchEdge, ...] = ()
        self._handled_catches: tuple[CatchHandler, ...] = ()
        self._protected_blocks: tuple[BasicBlock, ...] = ()

    @property
    def catch_edges(self) -> tuple[CatchEdge, ...]:
        return self._catch_edges

    @property
    def exception_successors(self) -> tuple[BasicBlock, ...]:
        return tuple(edge.target_block for edge in self._catch_edges)

    @property
    def is_catch_handler(self) -> bool:
        return bool(self._handled_catches)

    @property
    def handled_catches(self) -> tuple[CatchHandler, ...]:
        return self._handled_catches

    @property
    def protected_blocks(self) -> tuple[BasicBlock, ...]:
        return self._protected_blocks

    @property
    def id(self) -> int:
        return self._id

    @property
    def start_pc(self) -> int:
        return self._start_pc

    @property
    def end_pc(self) -> int:
        return self._end_pc

    @property
    def instructions(self) -> tuple[CodeInstruction, ...]:
        return self._instructions

    @property
    def terminator(self) -> CodeInstruction:
        return self._terminator

    @property
    def predecessors(self) -> tuple[BasicBlock, ...]:
        return self._predecessors

    @property
    def successors(self) -> tuple[BasicBlock, ...]:
        return self._successors

    @property
    def exception_handlers(self) -> tuple[CatchHandler, ...]:
        return self._exception_handlers

    @property
    def is_entry(self) -> bool:
        return self._start_pc == 0

    @property
    def is_exit(self) -> bool:
        return len(self._successors) == 0 or self._terminator.is_return or self._terminator.is_throw

    def disassemble(self) -> str:
        """Format the smali disassembly for this basic block."""
        lines: list[str] = [f"  [Block #{self._id}]"]

        preds_str = ", ".join(f"#{p.id}" for p in self._predecessors) or "none"
        succs_str = ", ".join(f"#{s.id}" for s in self._successors) or "none"
        lines.append(f"    ; preds: {preds_str}")
        lines.append(f"    ; succs: {succs_str}")

        if self.is_catch_handler:
            types = [
                h.type_descriptor if h.type_descriptor is not None else "catch-all"
                for h in self._handled_catches
            ]
            # preserve order, unique
            unique_types = list(dict.fromkeys(types))
            lines.append(f"    ; handler for: {', '.join(unique_types)}")

        if self.catch_edges:
            catches_parts: list[str] = []
            for edge in self._catch_edges:
                htype = edge.type_descriptor if edge.type_descriptor is not None else "catch-all"
                entry = f"{htype} -> #{edge.target_block.id}"
                if entry not in catches_parts:
                    catches_parts.append(entry)
            if catches_parts:
                lines.append(f"    ; catches: {', '.join(catches_parts)}")

        for inst in self._instructions:
            lines.append(f"    {inst.disassemble()}")

        return "\n".join(lines)

    def covers(self, pc: int) -> bool:
        return self._start_pc <= pc < self._end_pc

    def __contains__(self, pc: object) -> bool:
        if isinstance(pc, int):
            return self.covers(pc)
        return False

    def __iter__(self) -> Iterator[CodeInstruction]:
        return iter(self._instructions)

    def __len__(self) -> int:
        return len(self._instructions)

    def __repr__(self) -> str:
        return f"<BasicBlock {self._id} [0x{self._start_pc:04x}..0x{self._end_pc:04x}]>"


class Code:
    """High-level domain model wrapping CodeItem with CFG basic blocks and instruction lookup."""

    __slots__ = (
        "_blocks",
        "_instructions",
        "_item",
        "_method",
        "_payload_map",
        "_payloads",
        "_pc_map",
        "_try_catches",
    )

    def __init__(self, method: Method, item: CodeItem) -> None:
        self._method: Method = method
        self._item: CodeItem = item

        # Parse instructions and payloads
        instructions: list[CodeInstruction] = []
        payload_map: dict[int, Payload] = {}
        cursor_pc = 0
        for iop in item.insns:
            next_pc = cursor_pc + iop.code_units
            if isinstance(iop, Instruction):
                inst = CodeInstruction(method, cursor_pc, iop, next_pc)
                instructions.append(inst)
            else:
                payload_map[cursor_pc] = iop
            cursor_pc = next_pc

        for inst in instructions:
            if inst.is_switch or inst.opcode == Opcode.FILL_ARRAY_DATA:
                if inst.target_pc is not None and inst.target_pc in payload_map:
                    inst._payload = payload_map[inst.target_pc]

        self._instructions: tuple[CodeInstruction, ...] = tuple(instructions)
        self._pc_map: dict[int, CodeInstruction] = {inst.pc: inst for inst in instructions}
        self._payloads: tuple[Payload, ...] = tuple(payload_map.values())
        self._payload_map: dict[int, Payload] = payload_map

        # Parse TryCatches
        tc_list: list[TryCatch] = []
        if item.tries_size > 0 and item.handlers is not None:
            for try_item in item.tries:
                encoded_handler = item.get_catch_handler(try_item)
                handlers_list: list[CatchHandler] = []
                for pair in encoded_handler.handlers:
                    handlers_list.append(CatchHandler(method.defining_class, pair.addr, pair))
                if encoded_handler.catches_all and encoded_handler.catch_all_addr is not None:
                    handlers_list.append(
                        CatchHandler(method.defining_class, encoded_handler.catch_all_addr, None)
                    )
                tc_list.append(TryCatch(try_item, tuple(handlers_list)))

        self._try_catches: tuple[TryCatch, ...] = tuple(tc_list)

        # Build CFG Basic Blocks
        self._blocks: tuple[BasicBlock, ...] = self._build_basic_blocks(
            self._instructions, self._pc_map, self._try_catches
        )

    @staticmethod
    def _build_basic_blocks(
        instructions: tuple[CodeInstruction, ...],
        pc_map: dict[int, CodeInstruction],
        try_catches: tuple[TryCatch, ...],
    ) -> tuple[BasicBlock, ...]:
        if not instructions:
            return ()

        leaders: set[int] = {0}
        for inst in instructions:
            if inst.is_conditional_branch or inst.is_unconditional_branch or inst.is_switch:
                for pc in inst.next_pcs:
                    if pc in pc_map:
                        leaders.add(pc)
                if inst.is_unconditional_branch and inst.next_pc in pc_map:
                    leaders.add(inst.next_pc)
            elif inst.is_return or inst.is_throw:
                if inst.next_pc in pc_map:
                    leaders.add(inst.next_pc)

        for tc in try_catches:
            if tc.start_pc in pc_map:
                leaders.add(tc.start_pc)
            if tc.end_pc in pc_map:
                leaders.add(tc.end_pc)
            for handler in tc.handlers:
                if handler.target_pc in pc_map:
                    leaders.add(handler.target_pc)

        sorted_leaders = sorted(leaders)
        blocks_list: list[BasicBlock] = []
        block_by_start_pc: dict[int, BasicBlock] = {}

        for idx, start_pc in enumerate(sorted_leaders):
            end_pc = (
                sorted_leaders[idx + 1]
                if idx + 1 < len(sorted_leaders)
                else instructions[-1].next_pc
            )
            block_insts = [inst for inst in instructions if start_pc <= inst.pc < end_pc]
            if not block_insts:
                continue
            terminator = block_insts[-1]

            block_handlers: list[CatchHandler] = []
            for tc in try_catches:
                if tc.covers(start_pc):
                    block_handlers.extend(tc.handlers)

            block = BasicBlock(
                id=len(blocks_list),
                start_pc=start_pc,
                end_pc=end_pc,
                instructions=tuple(block_insts),
                terminator=terminator,
                exception_handlers=tuple(block_handlers),
            )
            blocks_list.append(block)
            block_by_start_pc[start_pc] = block

        preds_map: dict[int, list[BasicBlock]] = {b.id: [] for b in blocks_list}
        succs_map: dict[int, list[BasicBlock]] = {b.id: [] for b in blocks_list}

        for block in blocks_list:
            term = block.terminator
            succ_blocks = [block_by_start_pc[pc] for pc in term.next_pcs if pc in block_by_start_pc]
            for target_block in succ_blocks:
                if target_block not in succs_map[block.id]:
                    succs_map[block.id].append(target_block)
                if block not in preds_map[target_block.id]:
                    preds_map[target_block.id].append(block)

        for block in blocks_list:
            block._predecessors = tuple(preds_map[block.id])
            block._successors = tuple(succs_map[block.id])

        for block in blocks_list:
            catch_edges: list[CatchEdge] = []
            for handler in block.exception_handlers:
                if handler.target_pc in block_by_start_pc:
                    target_block = block_by_start_pc[handler.target_pc]
                    catch_edges.append(CatchEdge(handler=handler, target_block=target_block))
            block._catch_edges = tuple(catch_edges)

        handled_catches_map: dict[int, list[CatchHandler]] = {b.id: [] for b in blocks_list}
        protected_blocks_map: dict[int, list[BasicBlock]] = {b.id: [] for b in blocks_list}

        for block in blocks_list:
            for edge in block.catch_edges:
                target_id = edge.target_block.id
                if edge.handler not in handled_catches_map[target_id]:
                    handled_catches_map[target_id].append(edge.handler)
                if block not in protected_blocks_map[target_id]:
                    protected_blocks_map[target_id].append(block)

        for block in blocks_list:
            block._handled_catches = tuple(handled_catches_map[block.id])
            block._protected_blocks = tuple(protected_blocks_map[block.id])

        return tuple(blocks_list)

    @property
    def method(self) -> Method:
        return self._method

    @property
    def raw(self) -> CodeItem:
        return self._item

    @property
    def registers_size(self) -> int:
        return self._item.registers_size

    @property
    def ins_size(self) -> int:
        return self._item.ins_size

    @property
    def outs_size(self) -> int:
        return self._item.outs_size

    @property
    def locals_size(self) -> int:
        return self._item.registers_size - self._item.ins_size

    def register_name(self, reg: Reg | int) -> str:
        reg_int = int(reg)
        locals_sz = self.locals_size
        if reg_int < locals_sz:
            return f"v{reg_int}"
        return f"p{reg_int - locals_sz}"

    @property
    def instructions(self) -> tuple[CodeInstruction, ...]:
        return self._instructions

    @property
    def payloads(self) -> tuple[Payload, ...]:
        return self._payloads

    def get_payload(self, pc: int, default: Payload | None = None) -> Payload | None:
        return self._payload_map.get(pc, default)

    def at(self, pc: int) -> CodeInstruction:
        inst = self._pc_map.get(pc)
        if inst is None:
            raise KeyError(f"No instruction at program counter {pc}")
        return inst

    def get(self, pc: int, default: CodeInstruction | None = None) -> CodeInstruction | None:
        return self._pc_map.get(pc, default)

    def __contains__(self, pc: object) -> bool:
        if isinstance(pc, int):
            return pc in self._pc_map
        return False

    def __iter__(self) -> Iterator[CodeInstruction]:
        return iter(self._instructions)

    def __len__(self) -> int:
        return len(self._instructions)

    @property
    def blocks(self) -> tuple[BasicBlock, ...]:
        return self._blocks

    @property
    def entry_block(self) -> BasicBlock:
        return self._blocks[0]

    def get_block_at(self, pc: int) -> BasicBlock | None:
        for block in self._blocks:
            if block.covers(pc):
                return block
        return None

    @property
    def try_catches(self) -> tuple[TryCatch, ...]:
        return self._try_catches

    def find_try_catch(self, pc: int) -> TryCatch | None:
        for tc in self._try_catches:
            if tc.covers(pc):
                return tc
        return None

    def disassemble(self) -> str:
        mflags = format_method_flags(self._method.access_flags)
        mhead = f".method {mflags} " if mflags else ".method "
        lines: list[str] = [
            f"{mhead}{self._method.name}{self._method.descriptor}",
            f"  .registers {self.registers_size}",
        ]
        for block in self._blocks:
            lines.append(block.disassemble())
        return "\n".join(lines)

    def __repr__(self) -> str:
        mname = f"{self._method.defining_class.name}.{self._method.name}"
        return f"<Code {mname!r} insns={len(self._instructions)} blocks={len(self._blocks)}>"
