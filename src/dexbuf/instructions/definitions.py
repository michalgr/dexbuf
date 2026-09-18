"""Concrete Dalvik instruction class definitions and opcode dispatch table.

See https://source.android.com/docs/core/runtime/dex-format#bytecode
"""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import ClassVar

from dexbuf.cursor import Cursor
from dexbuf.instructions.formats import (
    Format3rc,
    Format10t,
    Format10x,
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
    Format51l,
    Instruction,
)
from dexbuf.instructions.opcodes import Opcode
from dexbuf.items import FieldIdItem, MethodIdItem, ProtoIdItem, StringIdItem, TypeIdItem

__all__ = [
    "OPCODE_MAP",
    "AddDouble",
    "AddDouble2Addr",
    "AddFloat",
    "AddFloat2Addr",
    "AddInt",
    "AddInt2Addr",
    "AddIntLit8",
    "AddIntLit16",
    "AddLong",
    "AddLong2Addr",
    "Aget",
    "AgetBoolean",
    "AgetByte",
    "AgetChar",
    "AgetObject",
    "AgetShort",
    "AgetWide",
    "AndInt",
    "AndInt2Addr",
    "AndIntLit8",
    "AndIntLit16",
    "AndLong",
    "AndLong2Addr",
    "Aput",
    "AputBoolean",
    "AputByte",
    "AputChar",
    "AputObject",
    "AputShort",
    "AputWide",
    "ArrayLength",
    "CheckCast",
    "CmpLong",
    "CmpgDouble",
    "CmpgFloat",
    "CmplDouble",
    "CmplFloat",
    "Const",
    "Const4",
    "Const16",
    "ConstClass",
    "ConstHigh16",
    "ConstMethodHandle",
    "ConstMethodType",
    "ConstString",
    "ConstStringJumbo",
    "ConstWide",
    "ConstWide16",
    "ConstWide32",
    "ConstWideHigh16",
    "DivDouble",
    "DivDouble2Addr",
    "DivFloat",
    "DivFloat2Addr",
    "DivInt",
    "DivInt2Addr",
    "DivIntLit8",
    "DivIntLit16",
    "DivLong",
    "DivLong2Addr",
    "DoubleToFloat",
    "DoubleToInt",
    "DoubleToLong",
    "FillArrayData",
    "FilledNewArray",
    "FilledNewArrayRange",
    "FloatToDouble",
    "FloatToInt",
    "FloatToLong",
    "Goto",
    "Goto16",
    "Goto32",
    "IfEq",
    "IfEqz",
    "IfGe",
    "IfGez",
    "IfGt",
    "IfGtz",
    "IfLe",
    "IfLez",
    "IfLt",
    "IfLtz",
    "IfNe",
    "IfNez",
    "Iget",
    "IgetBoolean",
    "IgetByte",
    "IgetChar",
    "IgetObject",
    "IgetShort",
    "IgetWide",
    "InstanceOf",
    "IntToByte",
    "IntToChar",
    "IntToDouble",
    "IntToFloat",
    "IntToLong",
    "IntToShort",
    "InvokeCustom",
    "InvokeCustomRange",
    "InvokeDirect",
    "InvokeDirectRange",
    "InvokeInterface",
    "InvokeInterfaceRange",
    "InvokePolymorphic",
    "InvokePolymorphicRange",
    "InvokeStatic",
    "InvokeStaticRange",
    "InvokeSuper",
    "InvokeSuperRange",
    "InvokeVirtual",
    "InvokeVirtualRange",
    "Iput",
    "IputBoolean",
    "IputByte",
    "IputChar",
    "IputObject",
    "IputShort",
    "IputWide",
    "LongToDouble",
    "LongToFloat",
    "LongToInt",
    "MonitorEnter",
    "MonitorExit",
    "Move",
    "Move16",
    "MoveException",
    "MoveFrom16",
    "MoveObject",
    "MoveObject16",
    "MoveObjectFrom16",
    "MoveResult",
    "MoveResultObject",
    "MoveResultWide",
    "MoveWide",
    "MoveWide16",
    "MoveWideFrom16",
    "MulDouble",
    "MulDouble2Addr",
    "MulFloat",
    "MulFloat2Addr",
    "MulInt",
    "MulInt2Addr",
    "MulIntLit8",
    "MulIntLit16",
    "MulLong",
    "MulLong2Addr",
    "NegDouble",
    "NegFloat",
    "NegInt",
    "NegLong",
    "NewArray",
    "NewInstance",
    "Nop",
    "NotInt",
    "NotLong",
    "OrInt",
    "OrInt2Addr",
    "OrIntLit8",
    "OrIntLit16",
    "OrLong",
    "OrLong2Addr",
    "PackedSwitch",
    "RemDouble",
    "RemDouble2Addr",
    "RemFloat",
    "RemFloat2Addr",
    "RemInt",
    "RemInt2Addr",
    "RemIntLit8",
    "RemIntLit16",
    "RemLong",
    "RemLong2Addr",
    "Return",
    "ReturnObject",
    "ReturnVoid",
    "ReturnWide",
    "RsubInt",
    "RsubIntLit8",
    "Sget",
    "SgetBoolean",
    "SgetByte",
    "SgetChar",
    "SgetObject",
    "SgetShort",
    "SgetWide",
    "ShlInt",
    "ShlInt2Addr",
    "ShlIntLit8",
    "ShlLong",
    "ShlLong2Addr",
    "ShrInt",
    "ShrInt2Addr",
    "ShrIntLit8",
    "ShrLong",
    "ShrLong2Addr",
    "SparseSwitch",
    "Sput",
    "SputBoolean",
    "SputByte",
    "SputChar",
    "SputObject",
    "SputShort",
    "SputWide",
    "SubDouble",
    "SubDouble2Addr",
    "SubFloat",
    "SubFloat2Addr",
    "SubInt",
    "SubInt2Addr",
    "SubLong",
    "SubLong2Addr",
    "Throw",
    "UshrInt",
    "UshrInt2Addr",
    "UshrIntLit8",
    "UshrLong",
    "UshrLong2Addr",
    "XorInt",
    "XorInt2Addr",
    "XorIntLit8",
    "XorIntLit16",
    "XorLong",
    "XorLong2Addr",
    "parse_instruction",
]


@dataclass(slots=True, frozen=True)
class Nop(Format10x):
    OPCODE: ClassVar[Opcode] = Opcode.NOP


@dataclass(slots=True, frozen=True)
class Move(Format12x):
    OPCODE: ClassVar[Opcode] = Opcode.MOVE


@dataclass(slots=True, frozen=True)
class MoveFrom16(Format22x):
    OPCODE: ClassVar[Opcode] = Opcode.MOVE_FROM16


@dataclass(slots=True, frozen=True)
class Move16(Format32x):
    OPCODE: ClassVar[Opcode] = Opcode.MOVE_16


@dataclass(slots=True, frozen=True)
class MoveWide(Format12x):
    OPCODE: ClassVar[Opcode] = Opcode.MOVE_WIDE


@dataclass(slots=True, frozen=True)
class MoveWideFrom16(Format22x):
    OPCODE: ClassVar[Opcode] = Opcode.MOVE_WIDE_FROM16


@dataclass(slots=True, frozen=True)
class MoveWide16(Format32x):
    OPCODE: ClassVar[Opcode] = Opcode.MOVE_WIDE_16


@dataclass(slots=True, frozen=True)
class MoveObject(Format12x):
    OPCODE: ClassVar[Opcode] = Opcode.MOVE_OBJECT


@dataclass(slots=True, frozen=True)
class MoveObjectFrom16(Format22x):
    OPCODE: ClassVar[Opcode] = Opcode.MOVE_OBJECT_FROM16


@dataclass(slots=True, frozen=True)
class MoveObject16(Format32x):
    OPCODE: ClassVar[Opcode] = Opcode.MOVE_OBJECT_16


@dataclass(slots=True, frozen=True)
class MoveResult(Format11x):
    OPCODE: ClassVar[Opcode] = Opcode.MOVE_RESULT


@dataclass(slots=True, frozen=True)
class MoveResultWide(Format11x):
    OPCODE: ClassVar[Opcode] = Opcode.MOVE_RESULT_WIDE


@dataclass(slots=True, frozen=True)
class MoveResultObject(Format11x):
    OPCODE: ClassVar[Opcode] = Opcode.MOVE_RESULT_OBJECT


@dataclass(slots=True, frozen=True)
class MoveException(Format11x):
    OPCODE: ClassVar[Opcode] = Opcode.MOVE_EXCEPTION


@dataclass(slots=True, frozen=True)
class ReturnVoid(Format10x):
    OPCODE: ClassVar[Opcode] = Opcode.RETURN_VOID


@dataclass(slots=True, frozen=True)
class Return(Format11x):
    OPCODE: ClassVar[Opcode] = Opcode.RETURN


@dataclass(slots=True, frozen=True)
class ReturnWide(Format11x):
    OPCODE: ClassVar[Opcode] = Opcode.RETURN_WIDE


@dataclass(slots=True, frozen=True)
class ReturnObject(Format11x):
    OPCODE: ClassVar[Opcode] = Opcode.RETURN_OBJECT


@dataclass(slots=True, frozen=True)
class Const4(Format11n):
    OPCODE: ClassVar[Opcode] = Opcode.CONST_4


@dataclass(slots=True, frozen=True)
class Const16(Format21s):
    OPCODE: ClassVar[Opcode] = Opcode.CONST_16


@dataclass(slots=True, frozen=True)
class Const(Format31i):
    OPCODE: ClassVar[Opcode] = Opcode.CONST


@dataclass(slots=True, frozen=True)
class ConstHigh16(Format21h):
    OPCODE: ClassVar[Opcode] = Opcode.CONST_HIGH16
    SHIFT: ClassVar[int] = 2


@dataclass(slots=True, frozen=True)
class ConstWide16(Format21s):
    OPCODE: ClassVar[Opcode] = Opcode.CONST_WIDE_16


@dataclass(slots=True, frozen=True)
class ConstWide32(Format31i):
    OPCODE: ClassVar[Opcode] = Opcode.CONST_WIDE_32


@dataclass(slots=True, frozen=True)
class ConstWide(Format51l):
    OPCODE: ClassVar[Opcode] = Opcode.CONST_WIDE


@dataclass(slots=True, frozen=True)
class ConstWideHigh16(Format21h):
    OPCODE: ClassVar[Opcode] = Opcode.CONST_WIDE_HIGH16
    SHIFT: ClassVar[int] = 6


@dataclass(slots=True, frozen=True)
class ConstString(Format21c[StringIdItem]):
    OPCODE: ClassVar[Opcode] = Opcode.CONST_STRING


@dataclass(slots=True, frozen=True)
class ConstStringJumbo(Format31c[StringIdItem]):
    OPCODE: ClassVar[Opcode] = Opcode.CONST_STRING_JUMBO


@dataclass(slots=True, frozen=True)
class ConstClass(Format21c[TypeIdItem]):
    OPCODE: ClassVar[Opcode] = Opcode.CONST_CLASS


@dataclass(slots=True, frozen=True)
class MonitorEnter(Format11x):
    OPCODE: ClassVar[Opcode] = Opcode.MONITOR_ENTER


@dataclass(slots=True, frozen=True)
class MonitorExit(Format11x):
    OPCODE: ClassVar[Opcode] = Opcode.MONITOR_EXIT


@dataclass(slots=True, frozen=True)
class CheckCast(Format21c[TypeIdItem]):
    OPCODE: ClassVar[Opcode] = Opcode.CHECK_CAST


@dataclass(slots=True, frozen=True)
class InstanceOf(Format22c[TypeIdItem]):
    OPCODE: ClassVar[Opcode] = Opcode.INSTANCE_OF


@dataclass(slots=True, frozen=True)
class ArrayLength(Format12x):
    OPCODE: ClassVar[Opcode] = Opcode.ARRAY_LENGTH


@dataclass(slots=True, frozen=True)
class NewInstance(Format21c[TypeIdItem]):
    OPCODE: ClassVar[Opcode] = Opcode.NEW_INSTANCE


@dataclass(slots=True, frozen=True)
class NewArray(Format22c[TypeIdItem]):
    OPCODE: ClassVar[Opcode] = Opcode.NEW_ARRAY


@dataclass(slots=True, frozen=True)
class FilledNewArray(Format35c[TypeIdItem]):
    OPCODE: ClassVar[Opcode] = Opcode.FILLED_NEW_ARRAY


@dataclass(slots=True, frozen=True)
class FilledNewArrayRange(Format3rc[TypeIdItem]):
    OPCODE: ClassVar[Opcode] = Opcode.FILLED_NEW_ARRAY_RANGE


@dataclass(slots=True, frozen=True)
class FillArrayData(Format31t):
    OPCODE: ClassVar[Opcode] = Opcode.FILL_ARRAY_DATA


@dataclass(slots=True, frozen=True)
class Throw(Format11x):
    OPCODE: ClassVar[Opcode] = Opcode.THROW


@dataclass(slots=True, frozen=True)
class Goto(Format10t):
    OPCODE: ClassVar[Opcode] = Opcode.GOTO


@dataclass(slots=True, frozen=True)
class Goto16(Format20t):
    OPCODE: ClassVar[Opcode] = Opcode.GOTO_16


@dataclass(slots=True, frozen=True)
class Goto32(Format30t):
    OPCODE: ClassVar[Opcode] = Opcode.GOTO_32


@dataclass(slots=True, frozen=True)
class PackedSwitch(Format31t):
    OPCODE: ClassVar[Opcode] = Opcode.PACKED_SWITCH


@dataclass(slots=True, frozen=True)
class SparseSwitch(Format31t):
    OPCODE: ClassVar[Opcode] = Opcode.SPARSE_SWITCH


@dataclass(slots=True, frozen=True)
class CmplFloat(Format23x):
    OPCODE: ClassVar[Opcode] = Opcode.CMPL_FLOAT


@dataclass(slots=True, frozen=True)
class CmpgFloat(Format23x):
    OPCODE: ClassVar[Opcode] = Opcode.CMPG_FLOAT


@dataclass(slots=True, frozen=True)
class CmplDouble(Format23x):
    OPCODE: ClassVar[Opcode] = Opcode.CMPL_DOUBLE


@dataclass(slots=True, frozen=True)
class CmpgDouble(Format23x):
    OPCODE: ClassVar[Opcode] = Opcode.CMPG_DOUBLE


@dataclass(slots=True, frozen=True)
class CmpLong(Format23x):
    OPCODE: ClassVar[Opcode] = Opcode.CMP_LONG


@dataclass(slots=True, frozen=True)
class IfEq(Format22t):
    OPCODE: ClassVar[Opcode] = Opcode.IF_EQ


@dataclass(slots=True, frozen=True)
class IfNe(Format22t):
    OPCODE: ClassVar[Opcode] = Opcode.IF_NE


@dataclass(slots=True, frozen=True)
class IfLt(Format22t):
    OPCODE: ClassVar[Opcode] = Opcode.IF_LT


@dataclass(slots=True, frozen=True)
class IfGe(Format22t):
    OPCODE: ClassVar[Opcode] = Opcode.IF_GE


@dataclass(slots=True, frozen=True)
class IfGt(Format22t):
    OPCODE: ClassVar[Opcode] = Opcode.IF_GT


@dataclass(slots=True, frozen=True)
class IfLe(Format22t):
    OPCODE: ClassVar[Opcode] = Opcode.IF_LE


@dataclass(slots=True, frozen=True)
class IfEqz(Format21t):
    OPCODE: ClassVar[Opcode] = Opcode.IF_EQZ


@dataclass(slots=True, frozen=True)
class IfNez(Format21t):
    OPCODE: ClassVar[Opcode] = Opcode.IF_NEZ


@dataclass(slots=True, frozen=True)
class IfLtz(Format21t):
    OPCODE: ClassVar[Opcode] = Opcode.IF_LTZ


@dataclass(slots=True, frozen=True)
class IfGez(Format21t):
    OPCODE: ClassVar[Opcode] = Opcode.IF_GEZ


@dataclass(slots=True, frozen=True)
class IfGtz(Format21t):
    OPCODE: ClassVar[Opcode] = Opcode.IF_GTZ


@dataclass(slots=True, frozen=True)
class IfLez(Format21t):
    OPCODE: ClassVar[Opcode] = Opcode.IF_LEZ


@dataclass(slots=True, frozen=True)
class Aget(Format23x):
    OPCODE: ClassVar[Opcode] = Opcode.AGET


@dataclass(slots=True, frozen=True)
class AgetWide(Format23x):
    OPCODE: ClassVar[Opcode] = Opcode.AGET_WIDE


@dataclass(slots=True, frozen=True)
class AgetObject(Format23x):
    OPCODE: ClassVar[Opcode] = Opcode.AGET_OBJECT


@dataclass(slots=True, frozen=True)
class AgetBoolean(Format23x):
    OPCODE: ClassVar[Opcode] = Opcode.AGET_BOOLEAN


@dataclass(slots=True, frozen=True)
class AgetByte(Format23x):
    OPCODE: ClassVar[Opcode] = Opcode.AGET_BYTE


@dataclass(slots=True, frozen=True)
class AgetChar(Format23x):
    OPCODE: ClassVar[Opcode] = Opcode.AGET_CHAR


@dataclass(slots=True, frozen=True)
class AgetShort(Format23x):
    OPCODE: ClassVar[Opcode] = Opcode.AGET_SHORT


@dataclass(slots=True, frozen=True)
class Aput(Format23x):
    OPCODE: ClassVar[Opcode] = Opcode.APUT


@dataclass(slots=True, frozen=True)
class AputWide(Format23x):
    OPCODE: ClassVar[Opcode] = Opcode.APUT_WIDE


@dataclass(slots=True, frozen=True)
class AputObject(Format23x):
    OPCODE: ClassVar[Opcode] = Opcode.APUT_OBJECT


@dataclass(slots=True, frozen=True)
class AputBoolean(Format23x):
    OPCODE: ClassVar[Opcode] = Opcode.APUT_BOOLEAN


@dataclass(slots=True, frozen=True)
class AputByte(Format23x):
    OPCODE: ClassVar[Opcode] = Opcode.APUT_BYTE


@dataclass(slots=True, frozen=True)
class AputChar(Format23x):
    OPCODE: ClassVar[Opcode] = Opcode.APUT_CHAR


@dataclass(slots=True, frozen=True)
class AputShort(Format23x):
    OPCODE: ClassVar[Opcode] = Opcode.APUT_SHORT


@dataclass(slots=True, frozen=True)
class Iget(Format22c[FieldIdItem]):
    OPCODE: ClassVar[Opcode] = Opcode.IGET


@dataclass(slots=True, frozen=True)
class IgetWide(Format22c[FieldIdItem]):
    OPCODE: ClassVar[Opcode] = Opcode.IGET_WIDE


@dataclass(slots=True, frozen=True)
class IgetObject(Format22c[FieldIdItem]):
    OPCODE: ClassVar[Opcode] = Opcode.IGET_OBJECT


@dataclass(slots=True, frozen=True)
class IgetBoolean(Format22c[FieldIdItem]):
    OPCODE: ClassVar[Opcode] = Opcode.IGET_BOOLEAN


@dataclass(slots=True, frozen=True)
class IgetByte(Format22c[FieldIdItem]):
    OPCODE: ClassVar[Opcode] = Opcode.IGET_BYTE


@dataclass(slots=True, frozen=True)
class IgetChar(Format22c[FieldIdItem]):
    OPCODE: ClassVar[Opcode] = Opcode.IGET_CHAR


@dataclass(slots=True, frozen=True)
class IgetShort(Format22c[FieldIdItem]):
    OPCODE: ClassVar[Opcode] = Opcode.IGET_SHORT


@dataclass(slots=True, frozen=True)
class Iput(Format22c[FieldIdItem]):
    OPCODE: ClassVar[Opcode] = Opcode.IPUT


@dataclass(slots=True, frozen=True)
class IputWide(Format22c[FieldIdItem]):
    OPCODE: ClassVar[Opcode] = Opcode.IPUT_WIDE


@dataclass(slots=True, frozen=True)
class IputObject(Format22c[FieldIdItem]):
    OPCODE: ClassVar[Opcode] = Opcode.IPUT_OBJECT


@dataclass(slots=True, frozen=True)
class IputBoolean(Format22c[FieldIdItem]):
    OPCODE: ClassVar[Opcode] = Opcode.IPUT_BOOLEAN


@dataclass(slots=True, frozen=True)
class IputByte(Format22c[FieldIdItem]):
    OPCODE: ClassVar[Opcode] = Opcode.IPUT_BYTE


@dataclass(slots=True, frozen=True)
class IputChar(Format22c[FieldIdItem]):
    OPCODE: ClassVar[Opcode] = Opcode.IPUT_CHAR


@dataclass(slots=True, frozen=True)
class IputShort(Format22c[FieldIdItem]):
    OPCODE: ClassVar[Opcode] = Opcode.IPUT_SHORT


@dataclass(slots=True, frozen=True)
class Sget(Format21c[FieldIdItem]):
    OPCODE: ClassVar[Opcode] = Opcode.SGET


@dataclass(slots=True, frozen=True)
class SgetWide(Format21c[FieldIdItem]):
    OPCODE: ClassVar[Opcode] = Opcode.SGET_WIDE


@dataclass(slots=True, frozen=True)
class SgetObject(Format21c[FieldIdItem]):
    OPCODE: ClassVar[Opcode] = Opcode.SGET_OBJECT


@dataclass(slots=True, frozen=True)
class SgetBoolean(Format21c[FieldIdItem]):
    OPCODE: ClassVar[Opcode] = Opcode.SGET_BOOLEAN


@dataclass(slots=True, frozen=True)
class SgetByte(Format21c[FieldIdItem]):
    OPCODE: ClassVar[Opcode] = Opcode.SGET_BYTE


@dataclass(slots=True, frozen=True)
class SgetChar(Format21c[FieldIdItem]):
    OPCODE: ClassVar[Opcode] = Opcode.SGET_CHAR


@dataclass(slots=True, frozen=True)
class SgetShort(Format21c[FieldIdItem]):
    OPCODE: ClassVar[Opcode] = Opcode.SGET_SHORT


@dataclass(slots=True, frozen=True)
class Sput(Format21c[FieldIdItem]):
    OPCODE: ClassVar[Opcode] = Opcode.SPUT


@dataclass(slots=True, frozen=True)
class SputWide(Format21c[FieldIdItem]):
    OPCODE: ClassVar[Opcode] = Opcode.SPUT_WIDE


@dataclass(slots=True, frozen=True)
class SputObject(Format21c[FieldIdItem]):
    OPCODE: ClassVar[Opcode] = Opcode.SPUT_OBJECT


@dataclass(slots=True, frozen=True)
class SputBoolean(Format21c[FieldIdItem]):
    OPCODE: ClassVar[Opcode] = Opcode.SPUT_BOOLEAN


@dataclass(slots=True, frozen=True)
class SputByte(Format21c[FieldIdItem]):
    OPCODE: ClassVar[Opcode] = Opcode.SPUT_BYTE


@dataclass(slots=True, frozen=True)
class SputChar(Format21c[FieldIdItem]):
    OPCODE: ClassVar[Opcode] = Opcode.SPUT_CHAR


@dataclass(slots=True, frozen=True)
class SputShort(Format21c[FieldIdItem]):
    OPCODE: ClassVar[Opcode] = Opcode.SPUT_SHORT


@dataclass(slots=True, frozen=True)
class InvokeVirtual(Format35c[MethodIdItem]):
    OPCODE: ClassVar[Opcode] = Opcode.INVOKE_VIRTUAL


@dataclass(slots=True, frozen=True)
class InvokeSuper(Format35c[MethodIdItem]):
    OPCODE: ClassVar[Opcode] = Opcode.INVOKE_SUPER


@dataclass(slots=True, frozen=True)
class InvokeDirect(Format35c[MethodIdItem]):
    OPCODE: ClassVar[Opcode] = Opcode.INVOKE_DIRECT


@dataclass(slots=True, frozen=True)
class InvokeStatic(Format35c[MethodIdItem]):
    OPCODE: ClassVar[Opcode] = Opcode.INVOKE_STATIC


@dataclass(slots=True, frozen=True)
class InvokeInterface(Format35c[MethodIdItem]):
    OPCODE: ClassVar[Opcode] = Opcode.INVOKE_INTERFACE


@dataclass(slots=True, frozen=True)
class InvokeVirtualRange(Format3rc[MethodIdItem]):
    OPCODE: ClassVar[Opcode] = Opcode.INVOKE_VIRTUAL_RANGE


@dataclass(slots=True, frozen=True)
class InvokeSuperRange(Format3rc[MethodIdItem]):
    OPCODE: ClassVar[Opcode] = Opcode.INVOKE_SUPER_RANGE


@dataclass(slots=True, frozen=True)
class InvokeDirectRange(Format3rc[MethodIdItem]):
    OPCODE: ClassVar[Opcode] = Opcode.INVOKE_DIRECT_RANGE


@dataclass(slots=True, frozen=True)
class InvokeStaticRange(Format3rc[MethodIdItem]):
    OPCODE: ClassVar[Opcode] = Opcode.INVOKE_STATIC_RANGE


@dataclass(slots=True, frozen=True)
class InvokeInterfaceRange(Format3rc[MethodIdItem]):
    OPCODE: ClassVar[Opcode] = Opcode.INVOKE_INTERFACE_RANGE


@dataclass(slots=True, frozen=True)
class NegInt(Format12x):
    OPCODE: ClassVar[Opcode] = Opcode.NEG_INT


@dataclass(slots=True, frozen=True)
class NotInt(Format12x):
    OPCODE: ClassVar[Opcode] = Opcode.NOT_INT


@dataclass(slots=True, frozen=True)
class NegLong(Format12x):
    OPCODE: ClassVar[Opcode] = Opcode.NEG_LONG


@dataclass(slots=True, frozen=True)
class NotLong(Format12x):
    OPCODE: ClassVar[Opcode] = Opcode.NOT_LONG


@dataclass(slots=True, frozen=True)
class NegFloat(Format12x):
    OPCODE: ClassVar[Opcode] = Opcode.NEG_FLOAT


@dataclass(slots=True, frozen=True)
class NegDouble(Format12x):
    OPCODE: ClassVar[Opcode] = Opcode.NEG_DOUBLE


@dataclass(slots=True, frozen=True)
class IntToLong(Format12x):
    OPCODE: ClassVar[Opcode] = Opcode.INT_TO_LONG


@dataclass(slots=True, frozen=True)
class IntToFloat(Format12x):
    OPCODE: ClassVar[Opcode] = Opcode.INT_TO_FLOAT


@dataclass(slots=True, frozen=True)
class IntToDouble(Format12x):
    OPCODE: ClassVar[Opcode] = Opcode.INT_TO_DOUBLE


@dataclass(slots=True, frozen=True)
class LongToInt(Format12x):
    OPCODE: ClassVar[Opcode] = Opcode.LONG_TO_INT


@dataclass(slots=True, frozen=True)
class LongToFloat(Format12x):
    OPCODE: ClassVar[Opcode] = Opcode.LONG_TO_FLOAT


@dataclass(slots=True, frozen=True)
class LongToDouble(Format12x):
    OPCODE: ClassVar[Opcode] = Opcode.LONG_TO_DOUBLE


@dataclass(slots=True, frozen=True)
class FloatToInt(Format12x):
    OPCODE: ClassVar[Opcode] = Opcode.FLOAT_TO_INT


@dataclass(slots=True, frozen=True)
class FloatToLong(Format12x):
    OPCODE: ClassVar[Opcode] = Opcode.FLOAT_TO_LONG


@dataclass(slots=True, frozen=True)
class FloatToDouble(Format12x):
    OPCODE: ClassVar[Opcode] = Opcode.FLOAT_TO_DOUBLE


@dataclass(slots=True, frozen=True)
class DoubleToInt(Format12x):
    OPCODE: ClassVar[Opcode] = Opcode.DOUBLE_TO_INT


@dataclass(slots=True, frozen=True)
class DoubleToLong(Format12x):
    OPCODE: ClassVar[Opcode] = Opcode.DOUBLE_TO_LONG


@dataclass(slots=True, frozen=True)
class DoubleToFloat(Format12x):
    OPCODE: ClassVar[Opcode] = Opcode.DOUBLE_TO_FLOAT


@dataclass(slots=True, frozen=True)
class IntToByte(Format12x):
    OPCODE: ClassVar[Opcode] = Opcode.INT_TO_BYTE


@dataclass(slots=True, frozen=True)
class IntToChar(Format12x):
    OPCODE: ClassVar[Opcode] = Opcode.INT_TO_CHAR


@dataclass(slots=True, frozen=True)
class IntToShort(Format12x):
    OPCODE: ClassVar[Opcode] = Opcode.INT_TO_SHORT


@dataclass(slots=True, frozen=True)
class AddInt(Format23x):
    OPCODE: ClassVar[Opcode] = Opcode.ADD_INT


@dataclass(slots=True, frozen=True)
class SubInt(Format23x):
    OPCODE: ClassVar[Opcode] = Opcode.SUB_INT


@dataclass(slots=True, frozen=True)
class MulInt(Format23x):
    OPCODE: ClassVar[Opcode] = Opcode.MUL_INT


@dataclass(slots=True, frozen=True)
class DivInt(Format23x):
    OPCODE: ClassVar[Opcode] = Opcode.DIV_INT


@dataclass(slots=True, frozen=True)
class RemInt(Format23x):
    OPCODE: ClassVar[Opcode] = Opcode.REM_INT


@dataclass(slots=True, frozen=True)
class AndInt(Format23x):
    OPCODE: ClassVar[Opcode] = Opcode.AND_INT


@dataclass(slots=True, frozen=True)
class OrInt(Format23x):
    OPCODE: ClassVar[Opcode] = Opcode.OR_INT


@dataclass(slots=True, frozen=True)
class XorInt(Format23x):
    OPCODE: ClassVar[Opcode] = Opcode.XOR_INT


@dataclass(slots=True, frozen=True)
class ShlInt(Format23x):
    OPCODE: ClassVar[Opcode] = Opcode.SHL_INT


@dataclass(slots=True, frozen=True)
class ShrInt(Format23x):
    OPCODE: ClassVar[Opcode] = Opcode.SHR_INT


@dataclass(slots=True, frozen=True)
class UshrInt(Format23x):
    OPCODE: ClassVar[Opcode] = Opcode.USHR_INT


@dataclass(slots=True, frozen=True)
class AddLong(Format23x):
    OPCODE: ClassVar[Opcode] = Opcode.ADD_LONG


@dataclass(slots=True, frozen=True)
class SubLong(Format23x):
    OPCODE: ClassVar[Opcode] = Opcode.SUB_LONG


@dataclass(slots=True, frozen=True)
class MulLong(Format23x):
    OPCODE: ClassVar[Opcode] = Opcode.MUL_LONG


@dataclass(slots=True, frozen=True)
class DivLong(Format23x):
    OPCODE: ClassVar[Opcode] = Opcode.DIV_LONG


@dataclass(slots=True, frozen=True)
class RemLong(Format23x):
    OPCODE: ClassVar[Opcode] = Opcode.REM_LONG


@dataclass(slots=True, frozen=True)
class AndLong(Format23x):
    OPCODE: ClassVar[Opcode] = Opcode.AND_LONG


@dataclass(slots=True, frozen=True)
class OrLong(Format23x):
    OPCODE: ClassVar[Opcode] = Opcode.OR_LONG


@dataclass(slots=True, frozen=True)
class XorLong(Format23x):
    OPCODE: ClassVar[Opcode] = Opcode.XOR_LONG


@dataclass(slots=True, frozen=True)
class ShlLong(Format23x):
    OPCODE: ClassVar[Opcode] = Opcode.SHL_LONG


@dataclass(slots=True, frozen=True)
class ShrLong(Format23x):
    OPCODE: ClassVar[Opcode] = Opcode.SHR_LONG


@dataclass(slots=True, frozen=True)
class UshrLong(Format23x):
    OPCODE: ClassVar[Opcode] = Opcode.USHR_LONG


@dataclass(slots=True, frozen=True)
class AddFloat(Format23x):
    OPCODE: ClassVar[Opcode] = Opcode.ADD_FLOAT


@dataclass(slots=True, frozen=True)
class SubFloat(Format23x):
    OPCODE: ClassVar[Opcode] = Opcode.SUB_FLOAT


@dataclass(slots=True, frozen=True)
class MulFloat(Format23x):
    OPCODE: ClassVar[Opcode] = Opcode.MUL_FLOAT


@dataclass(slots=True, frozen=True)
class DivFloat(Format23x):
    OPCODE: ClassVar[Opcode] = Opcode.DIV_FLOAT


@dataclass(slots=True, frozen=True)
class RemFloat(Format23x):
    OPCODE: ClassVar[Opcode] = Opcode.REM_FLOAT


@dataclass(slots=True, frozen=True)
class AddDouble(Format23x):
    OPCODE: ClassVar[Opcode] = Opcode.ADD_DOUBLE


@dataclass(slots=True, frozen=True)
class SubDouble(Format23x):
    OPCODE: ClassVar[Opcode] = Opcode.SUB_DOUBLE


@dataclass(slots=True, frozen=True)
class MulDouble(Format23x):
    OPCODE: ClassVar[Opcode] = Opcode.MUL_DOUBLE


@dataclass(slots=True, frozen=True)
class DivDouble(Format23x):
    OPCODE: ClassVar[Opcode] = Opcode.DIV_DOUBLE


@dataclass(slots=True, frozen=True)
class RemDouble(Format23x):
    OPCODE: ClassVar[Opcode] = Opcode.REM_DOUBLE


@dataclass(slots=True, frozen=True)
class AddInt2Addr(Format12x):
    OPCODE: ClassVar[Opcode] = Opcode.ADD_INT_2ADDR


@dataclass(slots=True, frozen=True)
class SubInt2Addr(Format12x):
    OPCODE: ClassVar[Opcode] = Opcode.SUB_INT_2ADDR


@dataclass(slots=True, frozen=True)
class MulInt2Addr(Format12x):
    OPCODE: ClassVar[Opcode] = Opcode.MUL_INT_2ADDR


@dataclass(slots=True, frozen=True)
class DivInt2Addr(Format12x):
    OPCODE: ClassVar[Opcode] = Opcode.DIV_INT_2ADDR


@dataclass(slots=True, frozen=True)
class RemInt2Addr(Format12x):
    OPCODE: ClassVar[Opcode] = Opcode.REM_INT_2ADDR


@dataclass(slots=True, frozen=True)
class AndInt2Addr(Format12x):
    OPCODE: ClassVar[Opcode] = Opcode.AND_INT_2ADDR


@dataclass(slots=True, frozen=True)
class OrInt2Addr(Format12x):
    OPCODE: ClassVar[Opcode] = Opcode.OR_INT_2ADDR


@dataclass(slots=True, frozen=True)
class XorInt2Addr(Format12x):
    OPCODE: ClassVar[Opcode] = Opcode.XOR_INT_2ADDR


@dataclass(slots=True, frozen=True)
class ShlInt2Addr(Format12x):
    OPCODE: ClassVar[Opcode] = Opcode.SHL_INT_2ADDR


@dataclass(slots=True, frozen=True)
class ShrInt2Addr(Format12x):
    OPCODE: ClassVar[Opcode] = Opcode.SHR_INT_2ADDR


@dataclass(slots=True, frozen=True)
class UshrInt2Addr(Format12x):
    OPCODE: ClassVar[Opcode] = Opcode.USHR_INT_2ADDR


@dataclass(slots=True, frozen=True)
class AddLong2Addr(Format12x):
    OPCODE: ClassVar[Opcode] = Opcode.ADD_LONG_2ADDR


@dataclass(slots=True, frozen=True)
class SubLong2Addr(Format12x):
    OPCODE: ClassVar[Opcode] = Opcode.SUB_LONG_2ADDR


@dataclass(slots=True, frozen=True)
class MulLong2Addr(Format12x):
    OPCODE: ClassVar[Opcode] = Opcode.MUL_LONG_2ADDR


@dataclass(slots=True, frozen=True)
class DivLong2Addr(Format12x):
    OPCODE: ClassVar[Opcode] = Opcode.DIV_LONG_2ADDR


@dataclass(slots=True, frozen=True)
class RemLong2Addr(Format12x):
    OPCODE: ClassVar[Opcode] = Opcode.REM_LONG_2ADDR


@dataclass(slots=True, frozen=True)
class AndLong2Addr(Format12x):
    OPCODE: ClassVar[Opcode] = Opcode.AND_LONG_2ADDR


@dataclass(slots=True, frozen=True)
class OrLong2Addr(Format12x):
    OPCODE: ClassVar[Opcode] = Opcode.OR_LONG_2ADDR


@dataclass(slots=True, frozen=True)
class XorLong2Addr(Format12x):
    OPCODE: ClassVar[Opcode] = Opcode.XOR_LONG_2ADDR


@dataclass(slots=True, frozen=True)
class ShlLong2Addr(Format12x):
    OPCODE: ClassVar[Opcode] = Opcode.SHL_LONG_2ADDR


@dataclass(slots=True, frozen=True)
class ShrLong2Addr(Format12x):
    OPCODE: ClassVar[Opcode] = Opcode.SHR_LONG_2ADDR


@dataclass(slots=True, frozen=True)
class UshrLong2Addr(Format12x):
    OPCODE: ClassVar[Opcode] = Opcode.USHR_LONG_2ADDR


@dataclass(slots=True, frozen=True)
class AddFloat2Addr(Format12x):
    OPCODE: ClassVar[Opcode] = Opcode.ADD_FLOAT_2ADDR


@dataclass(slots=True, frozen=True)
class SubFloat2Addr(Format12x):
    OPCODE: ClassVar[Opcode] = Opcode.SUB_FLOAT_2ADDR


@dataclass(slots=True, frozen=True)
class MulFloat2Addr(Format12x):
    OPCODE: ClassVar[Opcode] = Opcode.MUL_FLOAT_2ADDR


@dataclass(slots=True, frozen=True)
class DivFloat2Addr(Format12x):
    OPCODE: ClassVar[Opcode] = Opcode.DIV_FLOAT_2ADDR


@dataclass(slots=True, frozen=True)
class RemFloat2Addr(Format12x):
    OPCODE: ClassVar[Opcode] = Opcode.REM_FLOAT_2ADDR


@dataclass(slots=True, frozen=True)
class AddDouble2Addr(Format12x):
    OPCODE: ClassVar[Opcode] = Opcode.ADD_DOUBLE_2ADDR


@dataclass(slots=True, frozen=True)
class SubDouble2Addr(Format12x):
    OPCODE: ClassVar[Opcode] = Opcode.SUB_DOUBLE_2ADDR


@dataclass(slots=True, frozen=True)
class MulDouble2Addr(Format12x):
    OPCODE: ClassVar[Opcode] = Opcode.MUL_DOUBLE_2ADDR


@dataclass(slots=True, frozen=True)
class DivDouble2Addr(Format12x):
    OPCODE: ClassVar[Opcode] = Opcode.DIV_DOUBLE_2ADDR


@dataclass(slots=True, frozen=True)
class RemDouble2Addr(Format12x):
    OPCODE: ClassVar[Opcode] = Opcode.REM_DOUBLE_2ADDR


@dataclass(slots=True, frozen=True)
class AddIntLit16(Format22s):
    OPCODE: ClassVar[Opcode] = Opcode.ADD_INT_LIT16


@dataclass(slots=True, frozen=True)
class RsubInt(Format22s):
    OPCODE: ClassVar[Opcode] = Opcode.RSUB_INT


@dataclass(slots=True, frozen=True)
class MulIntLit16(Format22s):
    OPCODE: ClassVar[Opcode] = Opcode.MUL_INT_LIT16


@dataclass(slots=True, frozen=True)
class DivIntLit16(Format22s):
    OPCODE: ClassVar[Opcode] = Opcode.DIV_INT_LIT16


@dataclass(slots=True, frozen=True)
class RemIntLit16(Format22s):
    OPCODE: ClassVar[Opcode] = Opcode.REM_INT_LIT16


@dataclass(slots=True, frozen=True)
class AndIntLit16(Format22s):
    OPCODE: ClassVar[Opcode] = Opcode.AND_INT_LIT16


@dataclass(slots=True, frozen=True)
class OrIntLit16(Format22s):
    OPCODE: ClassVar[Opcode] = Opcode.OR_INT_LIT16


@dataclass(slots=True, frozen=True)
class XorIntLit16(Format22s):
    OPCODE: ClassVar[Opcode] = Opcode.XOR_INT_LIT16


@dataclass(slots=True, frozen=True)
class AddIntLit8(Format22b):
    OPCODE: ClassVar[Opcode] = Opcode.ADD_INT_LIT8


@dataclass(slots=True, frozen=True)
class RsubIntLit8(Format22b):
    OPCODE: ClassVar[Opcode] = Opcode.RSUB_INT_LIT8


@dataclass(slots=True, frozen=True)
class MulIntLit8(Format22b):
    OPCODE: ClassVar[Opcode] = Opcode.MUL_INT_LIT8


@dataclass(slots=True, frozen=True)
class DivIntLit8(Format22b):
    OPCODE: ClassVar[Opcode] = Opcode.DIV_INT_LIT8


@dataclass(slots=True, frozen=True)
class RemIntLit8(Format22b):
    OPCODE: ClassVar[Opcode] = Opcode.REM_INT_LIT8


@dataclass(slots=True, frozen=True)
class AndIntLit8(Format22b):
    OPCODE: ClassVar[Opcode] = Opcode.AND_INT_LIT8


@dataclass(slots=True, frozen=True)
class OrIntLit8(Format22b):
    OPCODE: ClassVar[Opcode] = Opcode.OR_INT_LIT8


@dataclass(slots=True, frozen=True)
class XorIntLit8(Format22b):
    OPCODE: ClassVar[Opcode] = Opcode.XOR_INT_LIT8


@dataclass(slots=True, frozen=True)
class ShlIntLit8(Format22b):
    OPCODE: ClassVar[Opcode] = Opcode.SHL_INT_LIT8


@dataclass(slots=True, frozen=True)
class ShrIntLit8(Format22b):
    OPCODE: ClassVar[Opcode] = Opcode.SHR_INT_LIT8


@dataclass(slots=True, frozen=True)
class UshrIntLit8(Format22b):
    OPCODE: ClassVar[Opcode] = Opcode.USHR_INT_LIT8


@dataclass(slots=True, frozen=True)
class InvokePolymorphic(Format35c[MethodIdItem]):
    OPCODE: ClassVar[Opcode] = Opcode.INVOKE_POLYMORPHIC


@dataclass(slots=True, frozen=True)
class InvokePolymorphicRange(Format3rc[MethodIdItem]):
    OPCODE: ClassVar[Opcode] = Opcode.INVOKE_POLYMORPHIC_RANGE


@dataclass(slots=True, frozen=True)
class InvokeCustom(Format35c[MethodIdItem]):
    OPCODE: ClassVar[Opcode] = Opcode.INVOKE_CUSTOM


@dataclass(slots=True, frozen=True)
class InvokeCustomRange(Format3rc[MethodIdItem]):
    OPCODE: ClassVar[Opcode] = Opcode.INVOKE_CUSTOM_RANGE


@dataclass(slots=True, frozen=True)
class ConstMethodHandle(Format21c[MethodIdItem]):
    OPCODE: ClassVar[Opcode] = Opcode.CONST_METHOD_HANDLE


@dataclass(slots=True, frozen=True)
class ConstMethodType(Format21c[ProtoIdItem]):
    OPCODE: ClassVar[Opcode] = Opcode.CONST_METHOD_TYPE


# --- Opcode Mapping Table ---

OPCODE_MAP: Mapping[int, type[Instruction]] = {
    Opcode.NOP.value: Nop,
    Opcode.MOVE.value: Move,
    Opcode.MOVE_FROM16.value: MoveFrom16,
    Opcode.MOVE_16.value: Move16,
    Opcode.MOVE_WIDE.value: MoveWide,
    Opcode.MOVE_WIDE_FROM16.value: MoveWideFrom16,
    Opcode.MOVE_WIDE_16.value: MoveWide16,
    Opcode.MOVE_OBJECT.value: MoveObject,
    Opcode.MOVE_OBJECT_FROM16.value: MoveObjectFrom16,
    Opcode.MOVE_OBJECT_16.value: MoveObject16,
    Opcode.MOVE_RESULT.value: MoveResult,
    Opcode.MOVE_RESULT_WIDE.value: MoveResultWide,
    Opcode.MOVE_RESULT_OBJECT.value: MoveResultObject,
    Opcode.MOVE_EXCEPTION.value: MoveException,
    Opcode.RETURN_VOID.value: ReturnVoid,
    Opcode.RETURN.value: Return,
    Opcode.RETURN_WIDE.value: ReturnWide,
    Opcode.RETURN_OBJECT.value: ReturnObject,
    Opcode.CONST_4.value: Const4,
    Opcode.CONST_16.value: Const16,
    Opcode.CONST.value: Const,
    Opcode.CONST_HIGH16.value: ConstHigh16,
    Opcode.CONST_WIDE_16.value: ConstWide16,
    Opcode.CONST_WIDE_32.value: ConstWide32,
    Opcode.CONST_WIDE.value: ConstWide,
    Opcode.CONST_WIDE_HIGH16.value: ConstWideHigh16,
    Opcode.CONST_STRING.value: ConstString,
    Opcode.CONST_STRING_JUMBO.value: ConstStringJumbo,
    Opcode.CONST_CLASS.value: ConstClass,
    Opcode.MONITOR_ENTER.value: MonitorEnter,
    Opcode.MONITOR_EXIT.value: MonitorExit,
    Opcode.CHECK_CAST.value: CheckCast,
    Opcode.INSTANCE_OF.value: InstanceOf,
    Opcode.ARRAY_LENGTH.value: ArrayLength,
    Opcode.NEW_INSTANCE.value: NewInstance,
    Opcode.NEW_ARRAY.value: NewArray,
    Opcode.FILLED_NEW_ARRAY.value: FilledNewArray,
    Opcode.FILLED_NEW_ARRAY_RANGE.value: FilledNewArrayRange,
    Opcode.FILL_ARRAY_DATA.value: FillArrayData,
    Opcode.THROW.value: Throw,
    Opcode.GOTO.value: Goto,
    Opcode.GOTO_16.value: Goto16,
    Opcode.GOTO_32.value: Goto32,
    Opcode.PACKED_SWITCH.value: PackedSwitch,
    Opcode.SPARSE_SWITCH.value: SparseSwitch,
    Opcode.CMPL_FLOAT.value: CmplFloat,
    Opcode.CMPG_FLOAT.value: CmpgFloat,
    Opcode.CMPL_DOUBLE.value: CmplDouble,
    Opcode.CMPG_DOUBLE.value: CmpgDouble,
    Opcode.CMP_LONG.value: CmpLong,
    Opcode.IF_EQ.value: IfEq,
    Opcode.IF_NE.value: IfNe,
    Opcode.IF_LT.value: IfLt,
    Opcode.IF_GE.value: IfGe,
    Opcode.IF_GT.value: IfGt,
    Opcode.IF_LE.value: IfLe,
    Opcode.IF_EQZ.value: IfEqz,
    Opcode.IF_NEZ.value: IfNez,
    Opcode.IF_LTZ.value: IfLtz,
    Opcode.IF_GEZ.value: IfGez,
    Opcode.IF_GTZ.value: IfGtz,
    Opcode.IF_LEZ.value: IfLez,
    Opcode.AGET.value: Aget,
    Opcode.AGET_WIDE.value: AgetWide,
    Opcode.AGET_OBJECT.value: AgetObject,
    Opcode.AGET_BOOLEAN.value: AgetBoolean,
    Opcode.AGET_BYTE.value: AgetByte,
    Opcode.AGET_CHAR.value: AgetChar,
    Opcode.AGET_SHORT.value: AgetShort,
    Opcode.APUT.value: Aput,
    Opcode.APUT_WIDE.value: AputWide,
    Opcode.APUT_OBJECT.value: AputObject,
    Opcode.APUT_BOOLEAN.value: AputBoolean,
    Opcode.APUT_BYTE.value: AputByte,
    Opcode.APUT_CHAR.value: AputChar,
    Opcode.APUT_SHORT.value: AputShort,
    Opcode.IGET.value: Iget,
    Opcode.IGET_WIDE.value: IgetWide,
    Opcode.IGET_OBJECT.value: IgetObject,
    Opcode.IGET_BOOLEAN.value: IgetBoolean,
    Opcode.IGET_BYTE.value: IgetByte,
    Opcode.IGET_CHAR.value: IgetChar,
    Opcode.IGET_SHORT.value: IgetShort,
    Opcode.IPUT.value: Iput,
    Opcode.IPUT_WIDE.value: IputWide,
    Opcode.IPUT_OBJECT.value: IputObject,
    Opcode.IPUT_BOOLEAN.value: IputBoolean,
    Opcode.IPUT_BYTE.value: IputByte,
    Opcode.IPUT_CHAR.value: IputChar,
    Opcode.IPUT_SHORT.value: IputShort,
    Opcode.SGET.value: Sget,
    Opcode.SGET_WIDE.value: SgetWide,
    Opcode.SGET_OBJECT.value: SgetObject,
    Opcode.SGET_BOOLEAN.value: SgetBoolean,
    Opcode.SGET_BYTE.value: SgetByte,
    Opcode.SGET_CHAR.value: SgetChar,
    Opcode.SGET_SHORT.value: SgetShort,
    Opcode.SPUT.value: Sput,
    Opcode.SPUT_WIDE.value: SputWide,
    Opcode.SPUT_OBJECT.value: SputObject,
    Opcode.SPUT_BOOLEAN.value: SputBoolean,
    Opcode.SPUT_BYTE.value: SputByte,
    Opcode.SPUT_CHAR.value: SputChar,
    Opcode.SPUT_SHORT.value: SputShort,
    Opcode.INVOKE_VIRTUAL.value: InvokeVirtual,
    Opcode.INVOKE_SUPER.value: InvokeSuper,
    Opcode.INVOKE_DIRECT.value: InvokeDirect,
    Opcode.INVOKE_STATIC.value: InvokeStatic,
    Opcode.INVOKE_INTERFACE.value: InvokeInterface,
    Opcode.INVOKE_VIRTUAL_RANGE.value: InvokeVirtualRange,
    Opcode.INVOKE_SUPER_RANGE.value: InvokeSuperRange,
    Opcode.INVOKE_DIRECT_RANGE.value: InvokeDirectRange,
    Opcode.INVOKE_STATIC_RANGE.value: InvokeStaticRange,
    Opcode.INVOKE_INTERFACE_RANGE.value: InvokeInterfaceRange,
    Opcode.NEG_INT.value: NegInt,
    Opcode.NOT_INT.value: NotInt,
    Opcode.NEG_LONG.value: NegLong,
    Opcode.NOT_LONG.value: NotLong,
    Opcode.NEG_FLOAT.value: NegFloat,
    Opcode.NEG_DOUBLE.value: NegDouble,
    Opcode.INT_TO_LONG.value: IntToLong,
    Opcode.INT_TO_FLOAT.value: IntToFloat,
    Opcode.INT_TO_DOUBLE.value: IntToDouble,
    Opcode.LONG_TO_INT.value: LongToInt,
    Opcode.LONG_TO_FLOAT.value: LongToFloat,
    Opcode.LONG_TO_DOUBLE.value: LongToDouble,
    Opcode.FLOAT_TO_INT.value: FloatToInt,
    Opcode.FLOAT_TO_LONG.value: FloatToLong,
    Opcode.FLOAT_TO_DOUBLE.value: FloatToDouble,
    Opcode.DOUBLE_TO_INT.value: DoubleToInt,
    Opcode.DOUBLE_TO_LONG.value: DoubleToLong,
    Opcode.DOUBLE_TO_FLOAT.value: DoubleToFloat,
    Opcode.INT_TO_BYTE.value: IntToByte,
    Opcode.INT_TO_CHAR.value: IntToChar,
    Opcode.INT_TO_SHORT.value: IntToShort,
    Opcode.ADD_INT.value: AddInt,
    Opcode.SUB_INT.value: SubInt,
    Opcode.MUL_INT.value: MulInt,
    Opcode.DIV_INT.value: DivInt,
    Opcode.REM_INT.value: RemInt,
    Opcode.AND_INT.value: AndInt,
    Opcode.OR_INT.value: OrInt,
    Opcode.XOR_INT.value: XorInt,
    Opcode.SHL_INT.value: ShlInt,
    Opcode.SHR_INT.value: ShrInt,
    Opcode.USHR_INT.value: UshrInt,
    Opcode.ADD_LONG.value: AddLong,
    Opcode.SUB_LONG.value: SubLong,
    Opcode.MUL_LONG.value: MulLong,
    Opcode.DIV_LONG.value: DivLong,
    Opcode.REM_LONG.value: RemLong,
    Opcode.AND_LONG.value: AndLong,
    Opcode.OR_LONG.value: OrLong,
    Opcode.XOR_LONG.value: XorLong,
    Opcode.SHL_LONG.value: ShlLong,
    Opcode.SHR_LONG.value: ShrLong,
    Opcode.USHR_LONG.value: UshrLong,
    Opcode.ADD_FLOAT.value: AddFloat,
    Opcode.SUB_FLOAT.value: SubFloat,
    Opcode.MUL_FLOAT.value: MulFloat,
    Opcode.DIV_FLOAT.value: DivFloat,
    Opcode.REM_FLOAT.value: RemFloat,
    Opcode.ADD_DOUBLE.value: AddDouble,
    Opcode.SUB_DOUBLE.value: SubDouble,
    Opcode.MUL_DOUBLE.value: MulDouble,
    Opcode.DIV_DOUBLE.value: DivDouble,
    Opcode.REM_DOUBLE.value: RemDouble,
    Opcode.ADD_INT_2ADDR.value: AddInt2Addr,
    Opcode.SUB_INT_2ADDR.value: SubInt2Addr,
    Opcode.MUL_INT_2ADDR.value: MulInt2Addr,
    Opcode.DIV_INT_2ADDR.value: DivInt2Addr,
    Opcode.REM_INT_2ADDR.value: RemInt2Addr,
    Opcode.AND_INT_2ADDR.value: AndInt2Addr,
    Opcode.OR_INT_2ADDR.value: OrInt2Addr,
    Opcode.XOR_INT_2ADDR.value: XorInt2Addr,
    Opcode.SHL_INT_2ADDR.value: ShlInt2Addr,
    Opcode.SHR_INT_2ADDR.value: ShrInt2Addr,
    Opcode.USHR_INT_2ADDR.value: UshrInt2Addr,
    Opcode.ADD_LONG_2ADDR.value: AddLong2Addr,
    Opcode.SUB_LONG_2ADDR.value: SubLong2Addr,
    Opcode.MUL_LONG_2ADDR.value: MulLong2Addr,
    Opcode.DIV_LONG_2ADDR.value: DivLong2Addr,
    Opcode.REM_LONG_2ADDR.value: RemLong2Addr,
    Opcode.AND_LONG_2ADDR.value: AndLong2Addr,
    Opcode.OR_LONG_2ADDR.value: OrLong2Addr,
    Opcode.XOR_LONG_2ADDR.value: XorLong2Addr,
    Opcode.SHL_LONG_2ADDR.value: ShlLong2Addr,
    Opcode.SHR_LONG_2ADDR.value: ShrLong2Addr,
    Opcode.USHR_LONG_2ADDR.value: UshrLong2Addr,
    Opcode.ADD_FLOAT_2ADDR.value: AddFloat2Addr,
    Opcode.SUB_FLOAT_2ADDR.value: SubFloat2Addr,
    Opcode.MUL_FLOAT_2ADDR.value: MulFloat2Addr,
    Opcode.DIV_FLOAT_2ADDR.value: DivFloat2Addr,
    Opcode.REM_FLOAT_2ADDR.value: RemFloat2Addr,
    Opcode.ADD_DOUBLE_2ADDR.value: AddDouble2Addr,
    Opcode.SUB_DOUBLE_2ADDR.value: SubDouble2Addr,
    Opcode.MUL_DOUBLE_2ADDR.value: MulDouble2Addr,
    Opcode.DIV_DOUBLE_2ADDR.value: DivDouble2Addr,
    Opcode.REM_DOUBLE_2ADDR.value: RemDouble2Addr,
    Opcode.ADD_INT_LIT16.value: AddIntLit16,
    Opcode.RSUB_INT.value: RsubInt,
    Opcode.MUL_INT_LIT16.value: MulIntLit16,
    Opcode.DIV_INT_LIT16.value: DivIntLit16,
    Opcode.REM_INT_LIT16.value: RemIntLit16,
    Opcode.AND_INT_LIT16.value: AndIntLit16,
    Opcode.OR_INT_LIT16.value: OrIntLit16,
    Opcode.XOR_INT_LIT16.value: XorIntLit16,
    Opcode.ADD_INT_LIT8.value: AddIntLit8,
    Opcode.RSUB_INT_LIT8.value: RsubIntLit8,
    Opcode.MUL_INT_LIT8.value: MulIntLit8,
    Opcode.DIV_INT_LIT8.value: DivIntLit8,
    Opcode.REM_INT_LIT8.value: RemIntLit8,
    Opcode.AND_INT_LIT8.value: AndIntLit8,
    Opcode.OR_INT_LIT8.value: OrIntLit8,
    Opcode.XOR_INT_LIT8.value: XorIntLit8,
    Opcode.SHL_INT_LIT8.value: ShlIntLit8,
    Opcode.SHR_INT_LIT8.value: ShrIntLit8,
    Opcode.USHR_INT_LIT8.value: UshrIntLit8,
    Opcode.INVOKE_POLYMORPHIC.value: InvokePolymorphic,
    Opcode.INVOKE_POLYMORPHIC_RANGE.value: InvokePolymorphicRange,
    Opcode.INVOKE_CUSTOM.value: InvokeCustom,
    Opcode.INVOKE_CUSTOM_RANGE.value: InvokeCustomRange,
    Opcode.CONST_METHOD_HANDLE.value: ConstMethodHandle,
    Opcode.CONST_METHOD_TYPE.value: ConstMethodType,
}


def parse_instruction(cursor: Cursor) -> Instruction:
    """Parse a single Dalvik instruction from a Cursor at its current position."""
    opcode_byte = cursor.subcursor().read_u8()
    cls = OPCODE_MAP.get(opcode_byte)
    if cls is None:
        raise ValueError(f"Unknown or unsupported opcode: 0x{opcode_byte:02x}")
    return cls.from_cursor(cursor)
