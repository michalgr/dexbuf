"""Generic, distinct integer types with zero runtime overhead."""

from typing import TYPE_CHECKING, Any

__all__ = [
    "NO_INDEX",
    "NO_OFFSET",
    "ArgumentCount",
    "BranchOffset",
    "Count",
    "Hat",
    "Idx",
    "Literal",
    "Offset",
    "Reg",
]

if TYPE_CHECKING:

    class Idx[T](int):
        """Distinct integer type representing an item identifier or table index."""

    class Offset[T](int):
        """Distinct integer type representing a byte offset within a DEX buffer."""

    class Count[T](int):
        """Distinct integer type representing an item count or length."""

    class Reg(int):
        """Distinct integer type representing a virtual register index."""

    class BranchOffset(int):
        """Distinct integer type representing a relative branch offset in code units."""

    class Literal(int):
        """Distinct integer type representing an immediate integer constant."""

    class ArgumentCount(int):
        """Distinct integer type representing an operand register count."""

    class Hat(int):
        """Distinct integer type representing a shifted high-bits constant."""

else:

    class _PhantomInt(int):
        __slots__ = ()

        def __new__(cls, val: int) -> int:
            return val

        def __class_getitem__(cls, item: Any) -> type:
            return cls

    class Idx(_PhantomInt):
        """Distinct integer type representing an item identifier or table index."""

    class Offset(_PhantomInt):
        """Distinct integer type representing a byte offset within a DEX buffer."""

    class Count(_PhantomInt):
        """Distinct integer type representing an item count or length."""

    class Reg(_PhantomInt):
        """Distinct integer type representing a virtual register index."""

    class BranchOffset(_PhantomInt):
        """Distinct integer type representing a relative branch offset in code units."""

    class Literal(_PhantomInt):
        """Distinct integer type representing an immediate integer constant."""

    class ArgumentCount(_PhantomInt):
        """Distinct integer type representing an operand register count."""

    class Hat(_PhantomInt):
        """Distinct integer type representing a shifted high-bits constant."""


NO_INDEX: Idx[Any] = Idx(0xFFFF_FFFF)
NO_OFFSET: Offset[Any] = Offset(0)
