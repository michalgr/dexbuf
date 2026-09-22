"""Top-level zero-copy DEX file reader and table sequence views.

See https://source.android.com/docs/core/runtime/dex-format
"""

import hashlib
import os
import zlib
from collections.abc import Buffer, Iterator, Sequence
from typing import Any, Self, overload

from dexbuf.items import (
    AnnotationsDirectoryItem,
    ClassDataItem,
    ClassDefItem,
    CodeItem,
    EncodedArray,
    EncodedArrayItem,
    FieldIdItem,
    HeaderItem,
    MapList,
    MethodIdItem,
    ProtoIdItem,
    StaticItem,
    StringDataItem,
    StringIdItem,
    TypeIdItem,
    TypeList,
)
from dexbuf.types import NO_INDEX, NO_OFFSET, Count, Idx, Offset

__all__ = ["DexFile", "TableSequence"]


class TableSequence[T: StaticItem](Sequence[T]):
    """Lazy zero-allocation indexed view over a contiguous table of DEX items.

    See https://source.android.com/docs/core/runtime/dex-format
    """

    __slots__ = ("_buffer", "_item_cls", "_offset", "_size")

    def __init__(
        self,
        buffer: memoryview,
        offset: Offset[T],
        size: Count[T],
        item_cls: type[T],
    ) -> None:
        self._buffer = buffer
        self._offset = offset
        self._size = size
        self._item_cls = item_cls

    def __len__(self) -> int:
        return self._size

    @property
    def offset(self) -> Offset[T]:
        return self._offset

    @property
    def size(self) -> Count[T]:
        return self._size

    @overload
    def __getitem__(self, index: int) -> T: ...

    @overload
    def __getitem__(self, index: slice) -> tuple[T, ...]: ...

    def __getitem__(self, index: int | slice) -> T | tuple[T, ...]:
        if isinstance(index, slice):
            return tuple(self[i] for i in range(*index.indices(self._size)))

        if index < 0:
            index += self._size
        if index < 0 or index >= self._size:
            raise IndexError(f"Index {index} out of bounds for table of size {self._size}")

        item_offset = self._offset + index * self._item_cls.STRUCT.size
        return self._item_cls.from_buffer(self._buffer, Offset[Any](item_offset))

    def __iter__(self) -> Iterator[T]:
        for i in range(self._size):
            yield self[i]

    def get(self, idx: Idx[T]) -> T:
        if idx == NO_INDEX or idx == 0xFFFF_FFFF:
            raise ValueError(f"Invalid index: {idx}")
        if idx < 0 or idx >= self._size:
            raise IndexError(f"Index {idx} out of bounds for table of size {self._size}")
        return self[idx]


class DexFile:
    """Zero-copy Dalvik Executable (DEX) file reader.

    See https://source.android.com/docs/core/runtime/dex-format
    """

    def __init__(self, buffer: Buffer) -> None:
        self._buffer: memoryview = memoryview(buffer)
        self.header: HeaderItem = HeaderItem.from_buffer(self._buffer, Offset[HeaderItem](0))
        self._map_list: MapList | None = None

        self.string_ids: TableSequence[StringIdItem] = TableSequence(
            self._buffer,
            self.header.string_ids_off,
            self.header.string_ids_size,
            StringIdItem,
        )
        self.type_ids: TableSequence[TypeIdItem] = TableSequence(
            self._buffer,
            self.header.type_ids_off,
            self.header.type_ids_size,
            TypeIdItem,
        )
        self.proto_ids: TableSequence[ProtoIdItem] = TableSequence(
            self._buffer,
            self.header.proto_ids_off,
            self.header.proto_ids_size,
            ProtoIdItem,
        )
        self.field_ids: TableSequence[FieldIdItem] = TableSequence(
            self._buffer,
            self.header.field_ids_off,
            self.header.field_ids_size,
            FieldIdItem,
        )
        self.method_ids: TableSequence[MethodIdItem] = TableSequence(
            self._buffer,
            self.header.method_ids_off,
            self.header.method_ids_size,
            MethodIdItem,
        )
        self.class_defs: TableSequence[ClassDefItem] = TableSequence(
            self._buffer,
            self.header.class_defs_off,
            self.header.class_defs_size,
            ClassDefItem,
        )
        self._class_defs_by_type: dict[Idx[TypeIdItem], ClassDefItem] | None = None

    @property
    def map_list(self) -> MapList:
        """Parse and return MapList lazily from header map_off."""
        if self._map_list is None:
            self._map_list = MapList.from_buffer(self._buffer, self.header.map_off)
        return self._map_list

    def verify_checksum(self) -> bool:
        """Compute Adler-32 checksum from offset 12 to EOF and verify header."""
        return (zlib.adler32(self._buffer[12:]) & 0xFFFF_FFFF) == self.header.checksum

    def verify_signature(self) -> bool:
        """Compute SHA-1 hash from offset 32 to EOF and verify header signature."""
        return hashlib.sha1(self._buffer[32:]).digest() == self.header.signature

    def get_string(self, idx: Idx[StringIdItem]) -> str:
        """Resolve StringIdItem index to string data."""
        string_id = self.string_ids.get(idx)
        return StringDataItem.from_buffer(self._buffer, string_id.string_data_off).data

    def get_string_id(self, idx: Idx[StringIdItem]) -> StringIdItem:
        """Fetch StringIdItem by index."""
        return self.string_ids.get(idx)

    def get_type_descriptor(self, idx: Idx[TypeIdItem]) -> str:
        """Resolve TypeIdItem index to type descriptor string."""
        type_id = self.type_ids.get(idx)
        return self.get_string(type_id.descriptor_idx)

    def get_type_id(self, idx: Idx[TypeIdItem]) -> TypeIdItem:
        """Fetch TypeIdItem by index."""
        return self.type_ids.get(idx)

    def get_proto_id(self, idx: Idx[ProtoIdItem]) -> ProtoIdItem:
        """Fetch ProtoIdItem by index."""
        return self.proto_ids.get(idx)

    def get_field_id(self, idx: Idx[FieldIdItem]) -> FieldIdItem:
        """Fetch FieldIdItem by index."""
        return self.field_ids.get(idx)

    def get_method_id(self, idx: Idx[MethodIdItem]) -> MethodIdItem:
        """Fetch MethodIdItem by index."""
        return self.method_ids.get(idx)

    def get_class_def(self, idx: Idx[ClassDefItem]) -> ClassDefItem:
        """Fetch ClassDefItem by index."""
        return self.class_defs.get(idx)

    def get_class_data(self, offset: Offset[ClassDataItem]) -> ClassDataItem:
        """Parse and return ClassDataItem from non-zero offset."""
        if offset == NO_OFFSET or offset == 0:
            raise ValueError(f"Invalid class_data offset: {offset}")
        return ClassDataItem.from_buffer(self._buffer, offset)

    def get_code_item(self, offset: Offset[CodeItem]) -> CodeItem:
        """Parse and return CodeItem from non-zero offset."""
        if offset == NO_OFFSET or offset == 0:
            raise ValueError(f"Invalid code_item offset: {offset}")
        return CodeItem.from_buffer(self._buffer, offset)

    def get_type_list(self, offset: Offset[TypeList]) -> TypeList:
        """Parse and return TypeList from non-zero offset."""
        if offset == NO_OFFSET or offset == 0:
            raise ValueError(f"Invalid type_list offset: {offset}")
        return TypeList.from_buffer(self._buffer, offset)

    def get_annotations_directory(
        self, offset: Offset[AnnotationsDirectoryItem]
    ) -> AnnotationsDirectoryItem:
        """Parse and return AnnotationsDirectoryItem from non-zero offset."""
        if offset == NO_OFFSET or offset == 0:
            raise ValueError(f"Invalid annotations_directory offset: {offset}")
        return AnnotationsDirectoryItem.from_buffer(self._buffer, offset)

    def get_static_values(self, offset: Offset[EncodedArrayItem]) -> EncodedArray:
        """Parse and return EncodedArray from non-zero offset of EncodedArrayItem."""
        if offset == NO_OFFSET or offset == 0:
            raise ValueError(f"Invalid static_values offset: {offset}")
        return EncodedArrayItem.from_buffer(self._buffer, offset).value

    def find_string_id(self, s: str) -> Idx[StringIdItem] | None:
        """Find StringIdItem index by string content using binary search."""
        low = 0
        high = len(self.string_ids) - 1
        while low <= high:
            mid = (low + high) // 2
            candidate = self.get_string(Idx[StringIdItem](mid))
            if candidate == s:
                return Idx[StringIdItem](mid)
            if candidate < s:
                low = mid + 1
            else:
                high = mid - 1
        return None

    def find_type_id(self, descriptor: str) -> Idx[TypeIdItem] | None:
        """Find TypeIdItem index by type descriptor using binary search."""
        low = 0
        high = len(self.type_ids) - 1
        while low <= high:
            mid = (low + high) // 2
            candidate = self.get_type_descriptor(Idx[TypeIdItem](mid))
            if candidate == descriptor:
                return Idx[TypeIdItem](mid)
            if candidate < descriptor:
                low = mid + 1
            else:
                high = mid - 1
        return None

    def find_class_def(self, target: Idx[TypeIdItem] | str) -> ClassDefItem | None:
        """Find ClassDefItem by type descriptor string or TypeIdItem index."""
        if isinstance(target, str):
            type_idx = self.find_type_id(target)
            if type_idx is None:
                return None
        else:
            type_idx = target

        if self._class_defs_by_type is None:
            self._class_defs_by_type = {cd.class_idx: cd for cd in self.class_defs}

        return self._class_defs_by_type.get(type_idx)

    @classmethod
    def open(cls, path: str | os.PathLike[str]) -> Self:
        """Open a DEX file from filesystem."""
        with open(path, "rb") as f:
            data = f.read()
        return cls(data)
