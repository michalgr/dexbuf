"""Generic, distinct integer types with zero runtime overhead."""

from typing import TYPE_CHECKING, Any

__all__ = [
    "NO_INDEX",
    "NO_OFFSET",
    "Count",
    "Idx",
    "Offset",
]

if TYPE_CHECKING:

    class Idx[T](int):
        """Distinct integer type representing an item identifier or table index."""

    class Offset[T](int):
        """Distinct integer type representing a byte offset within a DEX buffer."""

    class Count[T](int):
        """Distinct integer type representing an item count or length."""

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


NO_INDEX: Idx[Any] = Idx(0xFFFF_FFFF)
NO_OFFSET: Offset[Any] = Offset(0)
