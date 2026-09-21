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
    StringDataItem,
    StringIdItem,
    TypeIdItem,
    TypeList,
)
from dexbuf.types import NO_INDEX, NO_OFFSET, Idx, Offset

__all__ = ["DexFile", "TableSequence"]


class TableSequence[T](Sequence[T]):
    """Lazy zero-allocation indexed view over a contiguous table of DEX items.

    See https://source.android.com/docs/core/runtime/dex-format
    """

    __slots__ = ("_buffer", "_count", "_item_cls", "_offset", "_stride")

    def __init__(
        self,
        buffer: memoryview,
        offset: int,
        count: int,
        stride: int,
        item_cls: Any,
    ) -> None:
        self._buffer = buffer
        self._offset = offset
        self._count = count
        self._stride = stride
        self._item_cls = item_cls

    def __len__(self) -> int:
        return self._count

    @overload
    def __getitem__(self, index: int) -> T: ...

    @overload
    def __getitem__(self, index: slice) -> tuple[T, ...]: ...

    def __getitem__(self, index: int | slice) -> T | tuple[T, ...]:
        if isinstance(index, slice):
            return tuple(self[i] for i in range(*index.indices(self._count)))

        if index < 0:
            index += self._count
        if index < 0 or index >= self._count:
            raise IndexError(f"Index {index} out of bounds for table of size {self._count}")

        item_offset = self._offset + index * self._stride
        return self._item_cls.from_buffer(self._buffer, Offset[T](item_offset))

    def __iter__(self) -> Iterator[T]:
        for i in range(self._count):
            yield self[i]


class DexFile:
    """Zero-copy Dalvik Executable (DEX) file reader.

    See https://source.android.com/docs/core/runtime/dex-format
    """

    def __init__(self, buffer: Buffer) -> None:
        self._buffer: memoryview = memoryview(buffer)
        self.header: HeaderItem = HeaderItem.from_buffer(self._buffer, Offset[HeaderItem](0))
        self._map_list: MapList | None = None

        self.string_ids: Sequence[StringIdItem] = TableSequence(
            self._buffer,
            self.header.string_ids_off,
            self.header.string_ids_size,
            4,
            StringIdItem,
        )
        self.type_ids: Sequence[TypeIdItem] = TableSequence(
            self._buffer,
            self.header.type_ids_off,
            self.header.type_ids_size,
            4,
            TypeIdItem,
        )
        self.proto_ids: Sequence[ProtoIdItem] = TableSequence(
            self._buffer,
            self.header.proto_ids_off,
            self.header.proto_ids_size,
            12,
            ProtoIdItem,
        )
        self.field_ids: Sequence[FieldIdItem] = TableSequence(
            self._buffer,
            self.header.field_ids_off,
            self.header.field_ids_size,
            8,
            FieldIdItem,
        )
        self.method_ids: Sequence[MethodIdItem] = TableSequence(
            self._buffer,
            self.header.method_ids_off,
            self.header.method_ids_size,
            8,
            MethodIdItem,
        )
        self.class_defs: Sequence[ClassDefItem] = TableSequence(
            self._buffer,
            self.header.class_defs_off,
            self.header.class_defs_size,
            32,
            ClassDefItem,
        )

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
        if idx == NO_INDEX or idx == 0xFFFF_FFFF:
            raise ValueError(f"Invalid string index: {idx}")
        string_id = self.get_string_id(idx)
        return StringDataItem.from_buffer(self._buffer, string_id.string_data_off).data

    def get_string_id(self, idx: Idx[StringIdItem]) -> StringIdItem:
        """Fetch StringIdItem by index."""
        if idx == NO_INDEX or idx == 0xFFFF_FFFF:
            raise ValueError(f"Invalid string_id index: {idx}")
        return self.string_ids[idx]

    def get_type_descriptor(self, idx: Idx[TypeIdItem]) -> str:
        """Resolve TypeIdItem index to type descriptor string."""
        if idx == NO_INDEX or idx == 0xFFFF_FFFF:
            raise ValueError(f"Invalid type_id index: {idx}")
        type_id = self.get_type_id(idx)
        return self.get_string(type_id.descriptor_idx)

    def get_type_id(self, idx: Idx[TypeIdItem]) -> TypeIdItem:
        """Fetch TypeIdItem by index."""
        if idx == NO_INDEX or idx == 0xFFFF_FFFF:
            raise ValueError(f"Invalid type_id index: {idx}")
        return self.type_ids[idx]

    def get_proto_id(self, idx: Idx[ProtoIdItem]) -> ProtoIdItem:
        """Fetch ProtoIdItem by index."""
        if idx == NO_INDEX or idx == 0xFFFF_FFFF:
            raise ValueError(f"Invalid proto_id index: {idx}")
        return self.proto_ids[idx]

    def get_field_id(self, idx: Idx[FieldIdItem]) -> FieldIdItem:
        """Fetch FieldIdItem by index."""
        if idx == NO_INDEX or idx == 0xFFFF_FFFF:
            raise ValueError(f"Invalid field_id index: {idx}")
        return self.field_ids[idx]

    def get_method_id(self, idx: Idx[MethodIdItem]) -> MethodIdItem:
        """Fetch MethodIdItem by index."""
        if idx == NO_INDEX or idx == 0xFFFF_FFFF:
            raise ValueError(f"Invalid method_id index: {idx}")
        return self.method_ids[idx]

    def get_class_def(self, idx: Idx[ClassDefItem]) -> ClassDefItem:
        """Fetch ClassDefItem by index."""
        if idx == NO_INDEX or idx == 0xFFFF_FFFF:
            raise ValueError(f"Invalid class_def index: {idx}")
        return self.class_defs[idx]

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

    @classmethod
    def open(cls, path: str | os.PathLike[str]) -> Self:
        """Open a DEX file from filesystem."""
        with open(path, "rb") as f:
            data = f.read()
        return cls(data)
