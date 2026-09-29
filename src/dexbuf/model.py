"""High-level domain layer ClassLoader architecture and Class hierarchy.

See https://source.android.com/docs/core/runtime/dex-format
"""

import builtins
import fnmatch
import os
from abc import ABC, abstractmethod
from collections.abc import Buffer, Iterator, Mapping, Sequence
from types import MappingProxyType
from typing import Protocol, Self, TypeIs, runtime_checkable

from dexbuf.descriptors import (
    Descriptor,
    descriptor_to_type_name,
    format_method_descriptor,
    to_descriptor,
)
from dexbuf.dex import DexFile
from dexbuf.flags import AccessFlags
from dexbuf.instructions import IOP, Instruction, Opcode
from dexbuf.instructions.definitions import (
    CheckCast,
    ConstClass,
    ConstString,
    ConstStringJumbo,
    FilledNewArray,
    FilledNewArrayRange,
    Iget,
    IgetBoolean,
    IgetByte,
    IgetChar,
    IgetObject,
    IgetShort,
    IgetWide,
    InstanceOf,
    InvokeDirect,
    InvokeDirectRange,
    InvokeInterface,
    InvokeInterfaceRange,
    InvokePolymorphic,
    InvokePolymorphicRange,
    InvokeStatic,
    InvokeStaticRange,
    InvokeSuper,
    InvokeSuperRange,
    InvokeVirtual,
    InvokeVirtualRange,
    Iput,
    IputBoolean,
    IputByte,
    IputChar,
    IputObject,
    IputShort,
    IputWide,
    NewArray,
    NewInstance,
    Sget,
    SgetBoolean,
    SgetByte,
    SgetChar,
    SgetObject,
    SgetShort,
    SgetWide,
    Sput,
    SputBoolean,
    SputByte,
    SputChar,
    SputObject,
    SputShort,
    SputWide,
)
from dexbuf.instructions.formats import (
    Format3rc,
    Format4rcc,
    Format10t,
    Format11n,
    Format11x,
    Format12x,
    Format20t,
    Format21c,
    Format21h,
    Format21s,
    Format21t,
    Format22b,
    Format22c,
    Format22s,
    Format22t,
    Format22x,
    Format23x,
    Format30t,
    Format31c,
    Format31i,
    Format31t,
    Format32x,
    Format35c,
    Format45cc,
    Format51l,
)
from dexbuf.instructions.payloads import (
    FillArrayDataPayload,
    PackedSwitchPayload,
    SparseSwitchPayload,
)
from dexbuf.items import (
    AnnotationItem,
    AnnotationSetItem,
    AnnotationVisibility,
    ClassDefItem,
    CodeItem,
    EncodedCatchHandler,
    EncodedField,
    EncodedMethod,
    EncodedTypeAddrPair,
    FieldIdItem,
    MethodIdItem,
    ProtoIdItem,
    TryItem,
    TypeIdItem,
)
from dexbuf.mmap import open_mmap
from dexbuf.types import NO_INDEX, NO_OFFSET, Idx, Offset
from dexbuf.value import EncodedValue
from dexbuf.vdex import VdexFile
from dexbuf.zip import ZipArchive

type ClassLoaderElementInput = ClassLoaderElement | DexFile | VdexFile | ZipArchive

__all__ = [
    "Annotation",
    "BasicBlock",
    "CatchHandler",
    "CatchPair",
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


class CatchPair:
    """Pair of caught exception type descriptor/class and bytecode target PC."""

    __slots__ = ("_addr", "_dex", "_loader", "_type_idx")

    def __init__(self, dex: DexFile, loader: ClassLoader, pair: EncodedTypeAddrPair) -> None:
        self._dex: DexFile = dex
        self._loader: ClassLoader = loader
        self._type_idx: Idx[TypeIdItem] = pair.type_idx
        self._addr: int = pair.addr

    @property
    def type_idx(self) -> Idx[TypeIdItem]:
        return self._type_idx

    @property
    def target_pc(self) -> int:
        return self._addr

    @property
    def type_descriptor(self) -> Descriptor:
        return self._dex.get_type_descriptor(self._type_idx)

    @property
    def type_name(self) -> str:
        return descriptor_to_type_name(self.type_descriptor)

    @property
    def type_class(self) -> Class:
        resolved = self._loader.load_class(self.type_descriptor)
        if resolved is not None:
            return resolved
        return UnresolvedClass(self.type_descriptor)

    def __repr__(self) -> str:
        return f"<CatchPair '{self.type_name}' -> PC {self._addr}>"


class CatchHandler:
    """Represents exception catch handlers associated with a try block."""

    __slots__ = ("_dex", "_handlers", "_loader", "_raw")

    def __init__(self, dex: DexFile, loader: ClassLoader, handler: EncodedCatchHandler) -> None:
        self._dex: DexFile = dex
        self._loader: ClassLoader = loader
        self._raw: EncodedCatchHandler = handler
        self._handlers: tuple[CatchPair, ...] = tuple(
            CatchPair(dex, loader, p) for p in handler.handlers
        )

    @property
    def raw(self) -> EncodedCatchHandler:
        return self._raw

    @property
    def handlers(self) -> tuple[CatchPair, ...]:
        return self._handlers

    @property
    def catch_all_pc(self) -> int | None:
        return self._raw.catch_all_addr

    @property
    def catches_all(self) -> bool:
        return self._raw.catches_all

    @property
    def all_targets(self) -> tuple[int, ...]:
        targets = [p.target_pc for p in self._handlers]
        if self.catch_all_pc is not None:
            targets.append(self.catch_all_pc)
        return tuple(targets)

    def __repr__(self) -> str:
        return f"<CatchHandler handlers={len(self._handlers)} catch_all={self.catch_all_pc}>"


class TryCatch:
    """Represents a try block and its associated exception CatchHandler."""

    __slots__ = ("_handler", "_raw")

    def __init__(self, item: TryItem, handler: CatchHandler) -> None:
        self._raw: TryItem = item
        self._handler: CatchHandler = handler

    @property
    def raw(self) -> TryItem:
        return self._raw

    @property
    def start_pc(self) -> int:
        return self._raw.start_addr

    @property
    def end_pc(self) -> int:
        return self._raw.end_addr

    @property
    def code_unit_count(self) -> int:
        return self._raw.insn_count

    @property
    def handler(self) -> CatchHandler:
        return self._handler

    def covers(self, pc: int) -> bool:
        return self.start_pc <= pc < self.end_pc

    def __repr__(self) -> str:
        return f"<TryCatch [{self.start_pc}..{self.end_pc}) -> {self._handler!r}>"


_CONDITIONAL_BRANCH_OPCODES: set[Opcode] = {
    Opcode.IF_EQ,
    Opcode.IF_NE,
    Opcode.IF_LT,
    Opcode.IF_GE,
    Opcode.IF_GT,
    Opcode.IF_LE,
    Opcode.IF_EQZ,
    Opcode.IF_NEZ,
    Opcode.IF_LTZ,
    Opcode.IF_GEZ,
    Opcode.IF_GTZ,
    Opcode.IF_LEZ,
}

_UNCONDITIONAL_BRANCH_OPCODES: set[Opcode] = {
    Opcode.GOTO,
    Opcode.GOTO_16,
    Opcode.GOTO_32,
}

_SWITCH_OPCODES: set[Opcode] = {
    Opcode.PACKED_SWITCH,
    Opcode.SPARSE_SWITCH,
}

_RETURN_OPCODES: set[Opcode] = {
    Opcode.RETURN_VOID,
    Opcode.RETURN,
    Opcode.RETURN_WIDE,
    Opcode.RETURN_OBJECT,
}


def _format_mnemonic(opcode: Opcode) -> str:
    name = opcode.name.lower()
    suffixes = (
        "_2addr",
        "_lit16",
        "_lit8",
        "_from16",
        "_16",
        "_32",
        "_4",
        "_high16",
        "_jumbo",
        "_range",
    )
    for suffix in suffixes:
        if name.endswith(suffix):
            base = name[: -len(suffix)].replace("_", "-")
            return f"{base}/{suffix[1:]}"
    return name.replace("_", "-")


def _extract_registers(iop: IOP) -> tuple[int, ...]:
    if isinstance(
        iop,
        (
            Format11n,
            Format11x,
            Format21t,
            Format21s,
            Format21h,
            Format21c,
            Format31i,
            Format31t,
            Format31c,
            Format51l,
        ),
    ):
        return (int(iop.a),)
    if isinstance(iop, (Format12x, Format22x, Format22t, Format22s, Format22c, Format32x)):
        return (int(iop.a), int(iop.b))
    if isinstance(iop, (Format23x, Format22b)):
        return (int(iop.a), int(iop.b), int(iop.c))
    if isinstance(iop, (Format35c, Format45cc)):
        regs = (int(iop.c), int(iop.d), int(iop.e), int(iop.f), int(iop.g))
        return regs[: int(iop.a)]
    if isinstance(iop, (Format3rc, Format4rcc)):
        start = int(iop.c)
        count = int(iop.a)
        return tuple(range(start, start + count))
    return ()


def _extract_opcode(iop: IOP) -> Opcode:
    if isinstance(iop, Instruction):
        return iop.OPCODE
    if isinstance(iop, PackedSwitchPayload):
        return Opcode.PACKED_SWITCH_PAYLOAD
    if isinstance(iop, SparseSwitchPayload):
        return Opcode.SPARSE_SWITCH_PAYLOAD
    if isinstance(iop, FillArrayDataPayload):
        return Opcode.FILL_ARRAY_DATA_PAYLOAD
    raise TypeError(f"Unknown IOP type: {type(iop).__name__}")


class CodeInstruction:
    """Represents a high-level bytecode instruction or payload with resolved metadata."""

    __slots__ = ("_code", "_iop", "_pc")

    def __init__(self, code: Code, iop: IOP, pc: int) -> None:
        self._code: Code = code
        self._iop: IOP = iop
        self._pc: int = pc

    @property
    def pc(self) -> int:
        return self._pc

    @property
    def code_units(self) -> int:
        return self._iop.code_units

    @property
    def next_pc(self) -> int:
        return self._pc + self._iop.code_units

    @property
    def raw(self) -> IOP:
        return self._iop

    @property
    def opcode(self) -> Opcode:
        return _extract_opcode(self._iop)

    @property
    def mnemonic(self) -> str:
        return _format_mnemonic(self.opcode)

    @property
    def registers(self) -> tuple[int, ...]:
        return _extract_registers(self._iop)

    @property
    def register_names(self) -> tuple[str, ...]:
        return tuple(self._code.register_name(r) for r in self.registers)

    @property
    def is_conditional_branch(self) -> bool:
        return self.opcode in _CONDITIONAL_BRANCH_OPCODES

    @property
    def is_unconditional_branch(self) -> bool:
        return self.opcode in _UNCONDITIONAL_BRANCH_OPCODES

    @property
    def is_switch(self) -> bool:
        return self.opcode in _SWITCH_OPCODES

    @property
    def is_branch(self) -> bool:
        return self.is_conditional_branch or self.is_unconditional_branch or self.is_switch

    @property
    def is_return(self) -> bool:
        return self.opcode in _RETURN_OPCODES

    @property
    def is_throw(self) -> bool:
        return self.opcode == Opcode.THROW

    @property
    def branch_offset(self) -> int | None:
        raw = self._iop
        if isinstance(raw, (Format10t, Format20t, Format30t)):
            return int(raw.a)
        if isinstance(raw, Format21t):
            return int(raw.b)
        if isinstance(raw, Format22t):
            return int(raw.c)
        if isinstance(raw, Format31t):
            return int(raw.b)
        return None

    @property
    def target_pc(self) -> int | None:
        off = self.branch_offset
        return (self._pc + off) if off is not None else None

    @property
    def string_value(self) -> str | None:
        raw = self._iop
        if isinstance(raw, (ConstString, ConstStringJumbo)):
            return self._code.method.defining_class.dex_file.get_string(raw.b)
        return None

    @property
    def type_descriptor(self) -> Descriptor | None:
        raw = self._iop
        dex = self._code.method.defining_class.dex_file
        if isinstance(raw, (ConstClass, CheckCast, NewInstance)):
            return dex.get_type_descriptor(raw.b)
        if isinstance(raw, (InstanceOf, NewArray)):
            return dex.get_type_descriptor(raw.c)
        if isinstance(raw, (FilledNewArray, FilledNewArrayRange)):
            return dex.get_type_descriptor(raw.b)
        return None

    @property
    def type_class(self) -> Class | None:
        desc = self.type_descriptor
        if desc is not None:
            resolved = self._code.method.defining_class.loader.load_class(desc)
            if resolved is not None:
                return resolved
            return UnresolvedClass(desc)
        return None

    @property
    def field_id(self) -> FieldIdItem | None:
        raw = self._iop
        dex = self._code.method.defining_class.dex_file
        if isinstance(
            raw,
            (
                Iget,
                IgetWide,
                IgetObject,
                IgetBoolean,
                IgetByte,
                IgetChar,
                IgetShort,
                Iput,
                IputWide,
                IputObject,
                IputBoolean,
                IputByte,
                IputChar,
                IputShort,
            ),
        ):
            return dex.get_field_id(raw.c)
        if isinstance(
            raw,
            (
                Sget,
                SgetWide,
                SgetObject,
                SgetBoolean,
                SgetByte,
                SgetChar,
                SgetShort,
                Sput,
                SputWide,
                SputObject,
                SputBoolean,
                SputByte,
                SputChar,
                SputShort,
            ),
        ):
            return dex.get_field_id(raw.b)
        return None

    @property
    def target_field_name(self) -> str | None:
        fid = self.field_id
        if fid is not None:
            return self._code.method.defining_class.dex_file.get_string(fid.name_idx)
        return None

    @property
    def target_field_type_descriptor(self) -> Descriptor | None:
        fid = self.field_id
        if fid is not None:
            return self._code.method.defining_class.dex_file.get_type_descriptor(fid.type_idx)
        return None

    @property
    def method_id(self) -> MethodIdItem | None:
        raw = self._iop
        dex = self._code.method.defining_class.dex_file
        if isinstance(
            raw,
            (
                InvokeVirtual,
                InvokeSuper,
                InvokeDirect,
                InvokeStatic,
                InvokeInterface,
                InvokeVirtualRange,
                InvokeSuperRange,
                InvokeDirectRange,
                InvokeStaticRange,
                InvokeInterfaceRange,
                InvokePolymorphic,
                InvokePolymorphicRange,
            ),
        ):
            return dex.get_method_id(raw.b)
        return None

    @property
    def target_method_name(self) -> str | None:
        mid = self.method_id
        if mid is not None:
            return self._code.method.defining_class.dex_file.get_string(mid.name_idx)
        return None

    @property
    def target_method_descriptor(self) -> str | None:
        mid = self.method_id
        if mid is not None:
            dex = self._code.method.defining_class.dex_file
            proto = dex.get_proto_id(mid.proto_idx)
            ret_desc = dex.get_type_descriptor(proto.return_type_idx)
            if proto.parameters_off != NO_OFFSET:
                param_descs = tuple(
                    dex.get_type_descriptor(item.type_idx)
                    for item in dex.get_type_list(proto.parameters_off).list
                )
            else:
                param_descs = ()
            return format_method_descriptor(param_descs, ret_desc)
        return None

    def __repr__(self) -> str:
        return f"<CodeInstruction {self._pc:04x}: {self.mnemonic}>"

    def __str__(self) -> str:
        operands: list[str] = []
        if self.register_names:
            operands.append(", ".join(self.register_names))
        if self.string_value is not None:
            operands.append(f'"{self.string_value}"')
        elif self.type_descriptor is not None:
            operands.append(self.type_descriptor)
        elif self.target_field_name is not None:
            fid = self.field_id
            if fid is not None:
                cname = self._code.method.defining_class.dex_file.get_type_descriptor(fid.class_idx)
                operands.append(
                    f"{cname}->{self.target_field_name}:{self.target_field_type_descriptor}"
                )
        elif self.target_method_name is not None:
            mid = self.method_id
            if mid is not None:
                cname = self._code.method.defining_class.dex_file.get_type_descriptor(mid.class_idx)
                operands.append(
                    f"{cname}->{self.target_method_name}{self.target_method_descriptor}"
                )
        elif self.target_pc is not None:
            operands.append(f"+{self.branch_offset} (-> {self.target_pc:04x})")

        ops_str = f" {' '.join(operands)}" if operands else ""
        return f"{self._pc:04x}: {self.mnemonic}{ops_str}"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CodeInstruction):
            return NotImplemented
        return self._code is other._code and self._pc == other._pc

    def __hash__(self) -> int:
        return hash((type(self), self._code, self._pc))


class BasicBlock:
    """Represents a basic block in the method control flow graph."""

    __slots__ = (
        "_exception_handlers",
        "_id",
        "_instructions",
        "_predecessors",
        "_successors",
    )

    def __init__(
        self,
        id: int,
        instructions: tuple[CodeInstruction, ...],
        predecessors: tuple[Self, ...] | None = None,
        successors: tuple[Self, ...] | None = None,
        exception_handlers: tuple[CatchHandler, ...] = (),
    ) -> None:
        if not instructions:
            raise ValueError("BasicBlock must contain at least one instruction")
        self._id: int = id
        self._instructions: tuple[CodeInstruction, ...] = instructions
        self._predecessors: tuple[Self, ...] = predecessors if predecessors is not None else ()
        self._successors: tuple[Self, ...] = successors if successors is not None else ()
        self._exception_handlers: tuple[CatchHandler, ...] = exception_handlers

    @property
    def id(self) -> int:
        return self._id

    @property
    def start_pc(self) -> int:
        return self._instructions[0].pc

    @property
    def end_pc(self) -> int:
        return self._instructions[-1].next_pc

    @property
    def instructions(self) -> tuple[CodeInstruction, ...]:
        return self._instructions

    @property
    def terminator(self) -> CodeInstruction:
        return self._instructions[-1]

    @property
    def predecessors(self) -> tuple[Self, ...]:
        return self._predecessors

    @property
    def successors(self) -> tuple[Self, ...]:
        return self._successors

    @property
    def exception_handlers(self) -> tuple[CatchHandler, ...]:
        return self._exception_handlers

    @property
    def is_entry(self) -> bool:
        return self._id == 0 or self.start_pc == 0

    @property
    def is_exit(self) -> bool:
        return self.terminator.is_return or self.terminator.is_throw or len(self._successors) == 0

    def covers(self, pc: int) -> bool:
        return self.start_pc <= pc < self.end_pc

    def __repr__(self) -> str:
        return f"<BasicBlock id={self._id} start_pc={self.start_pc} end_pc={self.end_pc}>"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, BasicBlock):
            return NotImplemented
        return (
            self._id == other._id
            and self.start_pc == other.start_pc
            and self.end_pc == other.end_pc
        )

    def __hash__(self) -> int:
        return hash((type(self), self._id, self.start_pc, self.end_pc))


class Code:
    """High-level control flow graph and instruction container for a Method."""

    __slots__ = (
        "_blocks",
        "_code_item",
        "_insns_by_pc",
        "_instructions",
        "_method",
        "_pc_to_block",
        "_try_catches",
    )

    def __init__(self, method: Method, code_item: CodeItem) -> None:
        self._method: Method = method
        self._code_item: CodeItem = code_item

        insns_list: list[CodeInstruction] = []
        insns_by_pc: dict[int, CodeInstruction] = {}
        curr_pc = 0
        for iop in code_item.insns:
            code_insn = CodeInstruction(self, iop, curr_pc)
            insns_list.append(code_insn)
            insns_by_pc[curr_pc] = code_insn
            curr_pc += code_insn.code_units

        self._instructions: tuple[CodeInstruction, ...] = tuple(insns_list)
        self._insns_by_pc: dict[int, CodeInstruction] = insns_by_pc

        try_catches: list[TryCatch] = []
        if code_item.tries_size > 0 and code_item.handlers is not None:
            dex = method.defining_class.dex_file
            loader = method.defining_class.loader
            for try_item in code_item.tries:
                enc_handler = code_item.get_catch_handler(try_item)
                handler = CatchHandler(dex, loader, enc_handler)
                try_catches.append(TryCatch(try_item, handler))
        self._try_catches: tuple[TryCatch, ...] = tuple(try_catches)

        self._build_cfg()

    def _build_cfg(self) -> None:
        if not self._instructions:
            self._blocks = ()
            self._pc_to_block = {}
            return

        leaders: set[int] = {0}

        for insn in self._instructions:
            if insn.is_branch:
                if insn.target_pc is not None and insn.target_pc in self._insns_by_pc:
                    leaders.add(insn.target_pc)
                if insn.next_pc in self._insns_by_pc:
                    leaders.add(insn.next_pc)
                if insn.is_switch and insn.target_pc in self._insns_by_pc:
                    payload = self._insns_by_pc[insn.target_pc].raw
                    if isinstance(payload, (PackedSwitchPayload, SparseSwitchPayload)):
                        for t in payload.targets:
                            target_pc = insn.pc + int(t)
                            if target_pc in self._insns_by_pc:
                                leaders.add(target_pc)
            elif insn.is_return or insn.is_throw:
                if insn.next_pc in self._insns_by_pc:
                    leaders.add(insn.next_pc)

        for tc in self._try_catches:
            if tc.start_pc in self._insns_by_pc:
                leaders.add(tc.start_pc)
            if tc.end_pc in self._insns_by_pc:
                leaders.add(tc.end_pc)
            for target_pc in tc.handler.all_targets:
                if target_pc in self._insns_by_pc:
                    leaders.add(target_pc)

        block_instructions: list[list[CodeInstruction]] = []
        current_block: list[CodeInstruction] = []
        for insn in self._instructions:
            if current_block and insn.pc in leaders:
                block_instructions.append(current_block)
                current_block = [insn]
            else:
                current_block.append(insn)
        if current_block:
            block_instructions.append(current_block)

        blocks_list: list[BasicBlock] = []
        pc_to_block_start: dict[int, BasicBlock] = {}
        pc_to_block: dict[int, BasicBlock] = {}

        for idx, insn_group in enumerate(block_instructions):
            b = BasicBlock(idx, tuple(insn_group))
            blocks_list.append(b)
            pc_to_block_start[b.start_pc] = b
            for insn in insn_group:
                pc_to_block[insn.pc] = b

        succs_map: dict[int, list[BasicBlock]] = {b.id: [] for b in blocks_list}
        preds_map: dict[int, list[BasicBlock]] = {b.id: [] for b in blocks_list}

        for b in blocks_list:
            term = b.terminator
            succs = succs_map[b.id]

            if term.is_unconditional_branch:
                if term.target_pc is not None and term.target_pc in pc_to_block_start:
                    succs.append(pc_to_block_start[term.target_pc])
            elif term.is_conditional_branch:
                if term.next_pc in pc_to_block_start:
                    succs.append(pc_to_block_start[term.next_pc])
                if term.target_pc is not None and term.target_pc in pc_to_block_start:
                    target_b = pc_to_block_start[term.target_pc]
                    if target_b not in succs:
                        succs.append(target_b)
            elif term.is_switch:
                if term.next_pc in pc_to_block_start:
                    succs.append(pc_to_block_start[term.next_pc])
                if term.target_pc is not None and term.target_pc in self._insns_by_pc:
                    payload = self._insns_by_pc[term.target_pc].raw
                    if isinstance(payload, (PackedSwitchPayload, SparseSwitchPayload)):
                        for t in payload.targets:
                            target_pc = term.pc + int(t)
                            if target_pc in pc_to_block_start:
                                target_b = pc_to_block_start[target_pc]
                                if target_b not in succs:
                                    succs.append(target_b)
            elif term.is_return or term.is_throw:
                pass
            else:
                if term.next_pc in pc_to_block_start:
                    succs.append(pc_to_block_start[term.next_pc])

            for succ in succs:
                preds_map[succ.id].append(b)

        for b in blocks_list:
            b._successors = tuple(succs_map[b.id])
            b._predecessors = tuple(preds_map[b.id])

            handlers_for_b: list[CatchHandler] = []
            for tc in self._try_catches:
                if tc.covers(b.start_pc):
                    handlers_for_b.append(tc.handler)
            b._exception_handlers = tuple(handlers_for_b)

        self._blocks = tuple(blocks_list)
        self._pc_to_block = pc_to_block

    @property
    def method(self) -> Method:
        return self._method

    @property
    def raw(self) -> CodeItem:
        return self._code_item

    @property
    def registers_size(self) -> int:
        return self._code_item.registers_size

    @property
    def ins_size(self) -> int:
        return self._code_item.ins_size

    @property
    def outs_size(self) -> int:
        return self._code_item.outs_size

    @property
    def locals_size(self) -> int:
        return self._code_item.registers_size - self._code_item.ins_size

    def register_name(self, reg: int) -> str:
        loc_sz = self.locals_size
        if reg >= loc_sz:
            return f"p{reg - loc_sz}"
        return f"v{reg}"

    @property
    def instructions(self) -> tuple[CodeInstruction, ...]:
        return self._instructions

    def at(self, pc: int) -> CodeInstruction:
        if pc in self._insns_by_pc:
            return self._insns_by_pc[pc]
        raise KeyError(f"No instruction at program counter {pc}")

    def get(self, pc: int, default: CodeInstruction | None = None) -> CodeInstruction | None:
        return self._insns_by_pc.get(pc, default)

    def __contains__(self, pc: object) -> bool:
        return pc in self._insns_by_pc

    @property
    def blocks(self) -> tuple[BasicBlock, ...]:
        return self._blocks

    @property
    def entry_block(self) -> BasicBlock:
        return self._blocks[0]

    def get_block_at(self, pc: int) -> BasicBlock | None:
        if pc in self._pc_to_block:
            return self._pc_to_block[pc]
        for b in self._blocks:
            if b.covers(pc):
                return b
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
        lines = [
            f".registers {self.registers_size} (.locals {self.locals_size}, .ins {self.ins_size})"
        ]
        for b in self._blocks:
            lines.append(f"  block_{b.id} [{b.start_pc:04x}..{b.end_pc:04x}]:")
            for insn in b.instructions:
                lines.append(f"    {insn}")
        return "\n".join(lines)

    def __repr__(self) -> str:
        return f"<Code '{self._method}' insns={len(self._instructions)} blocks={len(self._blocks)}>"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Code):
            return NotImplemented
        return self._method == other._method and self._code_item == other._code_item

    def __hash__(self) -> int:
        return hash((type(self), self._method, self._code_item))


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
        if not self.has_code:
            return None
        if self._code is None:
            code_item = self._cls.dex_file.get_code_item(self._encoded.code_off)
            self._code = Code(self, code_item)
        return self._code

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
