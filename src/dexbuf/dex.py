"""Top-level zero-copy DEX file reader and table sequence views.

See https://source.android.com/docs/core/runtime/dex-format
"""

import hashlib
import zlib
from collections.abc import Buffer, Iterator, Sequence
from typing import Any, overload

from dexbuf.items import (
    REVERSE_ENDIAN_CONSTANT,
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
from dexbuf.mutf8 import encode_mutf8
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

    def __init__(self, buffer: Buffer, *, verify: bool = True) -> None:
        self._buffer: memoryview = memoryview(buffer)
        try:
            self.header: HeaderItem = HeaderItem.from_buffer(self._buffer, Offset[HeaderItem](0))
            if verify:
                self._verify_header()
        except Exception:
            try:
                self._buffer.release()
            except BufferError:
                pass
            raise
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

    def verify_magic(self) -> bool:
        """Return True if header.magic is valid DEX magic with supported version."""
        return self.header.is_supported_version

    def verify_endian(self) -> bool:
        """Return True if header.endian_tag matches ENDIAN_CONSTANT."""
        return self.header.is_valid_endian

    def verify_header(self) -> bool:
        """Return True if header magic and endianness are valid."""
        return self.verify_magic() and self.verify_endian()

    def _verify_header(self) -> None:
        if not self.header.is_valid_magic:
            raise ValueError(f"Invalid DEX magic: {self.header.magic!r}")
        if not self.header.is_supported_version:
            raise ValueError(f"Unsupported DEX version: {self.header.version!r}")
        if self.header.endian_tag == REVERSE_ENDIAN_CONSTANT:
            raise ValueError("Reverse-endian DEX files are not supported")
        if not self.header.is_valid_endian:
            raise ValueError(f"Invalid DEX endian tag: {hex(self.header.endian_tag)}")

    @property
    def map_list(self) -> MapList:
        """Parse and return MapList lazily from header map_off."""
        if self._map_list is None:
            self._map_list = MapList.from_buffer(self._buffer, self.header.map_off)
        return self._map_list

    def verify_checksum(self) -> bool:
        """Compute Adler-32 checksum from offset 12 to header.file_size and verify header."""
        return (
            zlib.adler32(self._buffer[12 : self.header.file_size]) & 0xFFFF_FFFF
        ) == self.header.checksum

    def verify_signature(self) -> bool:
        """Compute SHA-1 hash from offset 32 to header.file_size and verify header signature."""
        return (
            hashlib.sha1(self._buffer[32 : self.header.file_size]).digest() == self.header.signature
        )

    def get_string(self, idx: Idx[StringIdItem]) -> str:
        """Resolve StringIdItem index to string data."""
        string_id = self.string_ids.get(idx)
        return StringDataItem.from_buffer(self._buffer, string_id.string_data_off).decode()

    def get_string_data(self, idx: Idx[StringIdItem]) -> StringDataItem:
        """Resolve StringIdItem index to lazy StringDataItem."""
        string_id = self.string_ids.get(idx)
        return StringDataItem.from_buffer(self._buffer, string_id.string_data_off)

    def get_string_id(self, idx: Idx[StringIdItem]) -> StringIdItem:
        """Fetch StringIdItem by index."""
        return self.string_ids.get(idx)

    def find_string_id(self, s: str) -> Idx[StringIdItem] | None:
        """Find StringIdItem index by string value using binary search."""
        target_bytes = encode_mutf8(s, null_terminated=False)
        if 0xC0 in target_bytes:
            target_bytes = target_bytes.replace(b"\xc0\x80", b"\x00")

        low = 0
        high = len(self.string_ids) - 1
        while low <= high:
            mid = (low + high) // 2
            cand_data = self.get_string_data(Idx[StringIdItem](mid)).data
            cand_bytes = bytes(cand_data)
            if 0xC0 in cand_bytes:
                cand_bytes = cand_bytes.replace(b"\xc0\x80", b"\x00")

            if cand_bytes == target_bytes:
                return Idx[StringIdItem](mid)
            if cand_bytes < target_bytes:
                low = mid + 1
            else:
                high = mid - 1
        return None

    def get_type_descriptor(self, idx: Idx[TypeIdItem]) -> str:
        """Resolve TypeIdItem index to type descriptor string."""
        type_id = self.type_ids.get(idx)
        return self.get_string(type_id.descriptor_idx)

    def get_type_id(self, idx: Idx[TypeIdItem]) -> TypeIdItem:
        """Fetch TypeIdItem by index."""
        return self.type_ids.get(idx)

    def find_type_id(self, descriptor: str) -> Idx[TypeIdItem] | None:
        """Find TypeIdItem index by type descriptor string using binary search."""
        string_idx = self.find_string_id(descriptor)
        if string_idx is None:
            return None

        low = 0
        high = len(self.type_ids) - 1
        while low <= high:
            mid = (low + high) // 2
            type_id = self.get_type_id(Idx[TypeIdItem](mid))
            if type_id.descriptor_idx == string_idx:
                return Idx[TypeIdItem](mid)
            if type_id.descriptor_idx < string_idx:
                low = mid + 1
            else:
                high = mid - 1
        return None

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

    def find_class_def(self, target: Idx[TypeIdItem] | str) -> ClassDefItem | None:
        """Find ClassDefItem by type descriptor or type index via stateless linear scan."""
        if isinstance(target, str):
            type_idx = self.find_type_id(target)
            if type_idx is None:
                return None
        else:
            type_idx = target

        for cd in self.class_defs:
            if cd.class_idx == type_idx:
                return cd
        return None

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
