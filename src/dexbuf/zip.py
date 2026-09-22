"""Stateless, zero-copy ZIP archive reader and specification structures."""

import mmap as mmap_module
import os
import struct
import zlib
from collections.abc import Buffer, Iterator
from dataclasses import dataclass
from types import TracebackType
from typing import BinaryIO, ClassVar, Self

from dexbuf.cursor import Cursor

__all__ = [
    "CentralDirectoryHeader",
    "EndOfCentralDirectoryRecord",
    "LocalFileHeader",
    "ZipArchive",
]


@dataclass(slots=True, frozen=True)
class EndOfCentralDirectoryRecord:
    """End of Central Directory (EOCD) record."""

    SIGNATURE: ClassVar[bytes] = b"PK\x05\x06"
    STRUCT: ClassVar[struct.Struct] = struct.Struct("<4s4H2IH")

    disk_num: int
    cd_start_disk: int
    disk_entries: int
    total_entries: int
    cd_size: int
    cd_offset: int
    comment: str

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Parse an EndOfCentralDirectoryRecord from cursor."""
        (
            sig,
            disk_num,
            cd_start_disk,
            disk_entries,
            total_entries,
            cd_size,
            cd_offset,
            comment_len,
        ) = cursor.unpack(cls.STRUCT)

        if sig != cls.SIGNATURE:
            raise ValueError(
                f"Invalid EndOfCentralDirectoryRecord signature: "
                f"expected {cls.SIGNATURE!r}, got {sig!r}"
            )

        comment_bytes = cursor.read_bytes(comment_len)
        comment = comment_bytes.decode("utf-8", errors="replace")

        return cls(
            disk_num=disk_num,
            cd_start_disk=cd_start_disk,
            disk_entries=disk_entries,
            total_entries=total_entries,
            cd_size=cd_size,
            cd_offset=cd_offset,
            comment=comment,
        )

    @classmethod
    def from_buffer(cls, buffer: Buffer, offset: int = 0) -> Self:
        """Parse an EndOfCentralDirectoryRecord from buffer at offset."""
        return cls.from_cursor(Cursor(buffer, offset))


@dataclass(slots=True, frozen=True)
class CentralDirectoryHeader:
    """Central Directory file header record."""

    SIGNATURE: ClassVar[bytes] = b"PK\x01\x02"
    STRUCT: ClassVar[struct.Struct] = struct.Struct("<4s6H3I5H2I")

    version_made_by: int
    version_needed: int
    flag_bits: int
    compress_type: int
    last_mod_time: int
    last_mod_date: int
    crc32: int
    compress_size: int
    file_size: int
    disk_num_start: int
    internal_attr: int
    external_attr: int
    local_header_offset: int
    filename: str
    extra: bytes
    comment: str

    @property
    def is_stored(self) -> bool:
        """Return True if entry is uncompressed (ZIP_STORED)."""
        return self.compress_type == 0

    @property
    def is_deflated(self) -> bool:
        """Return True if entry is compressed using deflate (ZIP_DEFLATED)."""
        return self.compress_type == 8

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Parse a CentralDirectoryHeader from cursor."""
        (
            sig,
            version_made_by,
            version_needed,
            flag_bits,
            compress_type,
            last_mod_time,
            last_mod_date,
            crc32,
            compress_size,
            file_size,
            filename_len,
            extra_len,
            comment_len,
            disk_num_start,
            internal_attr,
            external_attr,
            local_header_offset,
        ) = cursor.unpack(cls.STRUCT)

        if sig != cls.SIGNATURE:
            raise ValueError(
                f"Invalid CentralDirectoryHeader signature: expected {cls.SIGNATURE!r}, got {sig!r}"
            )

        filename_bytes = cursor.read_bytes(filename_len)
        extra = cursor.read_bytes(extra_len)
        comment_bytes = cursor.read_bytes(comment_len)

        filename = filename_bytes.decode("utf-8", errors="replace")
        comment = comment_bytes.decode("utf-8", errors="replace")

        return cls(
            version_made_by=version_made_by,
            version_needed=version_needed,
            flag_bits=flag_bits,
            compress_type=compress_type,
            last_mod_time=last_mod_time,
            last_mod_date=last_mod_date,
            crc32=crc32,
            compress_size=compress_size,
            file_size=file_size,
            disk_num_start=disk_num_start,
            internal_attr=internal_attr,
            external_attr=external_attr,
            local_header_offset=local_header_offset,
            filename=filename,
            extra=extra,
            comment=comment,
        )

    @classmethod
    def from_buffer(cls, buffer: Buffer, offset: int = 0) -> Self:
        """Parse a CentralDirectoryHeader from buffer at offset."""
        return cls.from_cursor(Cursor(buffer, offset))


@dataclass(slots=True, frozen=True)
class LocalFileHeader:
    """Local file header preceding file data."""

    SIGNATURE: ClassVar[bytes] = b"PK\x03\x04"
    STRUCT: ClassVar[struct.Struct] = struct.Struct("<4s5H3I2H")

    version_needed: int
    flag_bits: int
    compress_type: int
    last_mod_time: int
    last_mod_date: int
    crc32: int
    compress_size: int
    file_size: int
    filename: str
    extra: bytes

    @property
    def header_size(self) -> int:
        """Total size of local file header in bytes including variable fields."""
        return self.STRUCT.size + len(self.filename.encode("utf-8")) + len(self.extra)

    def data_offset(self, local_header_offset: int) -> int:
        """Return start byte offset of file payload data."""
        return local_header_offset + self.header_size

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Parse a LocalFileHeader from cursor."""
        (
            sig,
            version_needed,
            flag_bits,
            compress_type,
            last_mod_time,
            last_mod_date,
            crc32,
            compress_size,
            file_size,
            filename_len,
            extra_len,
        ) = cursor.unpack(cls.STRUCT)

        if sig != cls.SIGNATURE:
            raise ValueError(
                f"Invalid LocalFileHeader signature: expected {cls.SIGNATURE!r}, got {sig!r}"
            )

        filename_bytes = cursor.read_bytes(filename_len)
        extra = cursor.read_bytes(extra_len)

        filename = filename_bytes.decode("utf-8", errors="replace")

        return cls(
            version_needed=version_needed,
            flag_bits=flag_bits,
            compress_type=compress_type,
            last_mod_time=last_mod_time,
            last_mod_date=last_mod_date,
            crc32=crc32,
            compress_size=compress_size,
            file_size=file_size,
            filename=filename,
            extra=extra,
        )

    @classmethod
    def from_buffer(cls, buffer: Buffer, offset: int = 0) -> Self:
        """Parse a LocalFileHeader from buffer at offset."""
        return cls.from_cursor(Cursor(buffer, offset))


class ZipArchive:
    """Zero-copy, stateless ZIP archive reader operating on a Buffer."""

    __slots__ = ("_buffer", "_file", "_mmap", "eocd")

    def __init__(self, buffer: Buffer) -> None:
        self._buffer: memoryview = memoryview(buffer).cast("B")
        self._file: BinaryIO | None = None
        self._mmap: mmap_module.mmap | None = None

        buf_len = len(self._buffer)
        if buf_len < 22:
            raise ValueError("Invalid ZIP file: buffer too small for EOCD record")

        search_start = max(0, buf_len - 65557)
        search_bytes = bytes(self._buffer[search_start:])

        found_offset = -1
        pos = search_bytes.rfind(EndOfCentralDirectoryRecord.SIGNATURE)
        while pos != -1:
            candidate_offset = search_start + pos
            if candidate_offset + 22 <= buf_len:
                comment_len = struct.unpack_from("<H", self._buffer, candidate_offset + 20)[0]
                if candidate_offset + 22 + comment_len == buf_len:
                    found_offset = candidate_offset
                    break
            pos = search_bytes.rfind(EndOfCentralDirectoryRecord.SIGNATURE, 0, pos)

        if found_offset == -1:
            raise ValueError(
                "Invalid ZIP file: End of Central Directory (EOCD) signature not found"
            )

        self.eocd: EndOfCentralDirectoryRecord = EndOfCentralDirectoryRecord.from_buffer(
            self._buffer, found_offset
        )

    @classmethod
    def open(cls, path: str | os.PathLike[str], *, mmap: bool = True) -> Self:
        """Open a ZIP file from disk with optional memory-mapping."""
        if mmap:
            f = open(path, "rb")
            try:
                mm = mmap_module.mmap(f.fileno(), 0, access=mmap_module.ACCESS_READ)
            except Exception:
                f.close()
                raise
            archive = cls(mm)
            archive._file = f
            archive._mmap = mm
            return archive
        else:
            with open(path, "rb") as f:
                data = f.read()
            return cls(data)

    def close(self) -> None:
        """Close underlying file or memory-mapping resources if opened via open()."""
        if self._mmap is not None:
            if hasattr(self, "_buffer"):
                try:
                    self._buffer.release()
                except BufferError:
                    pass
            self._mmap.close()
            self._mmap = None
        if self._file is not None:
            self._file.close()
            self._file = None

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.close()

    def iter_entries(self) -> Iterator[CentralDirectoryHeader]:
        """Stream Central Directory entries lazily without caching."""
        cursor = Cursor(self._buffer, self.eocd.cd_offset)
        for _ in range(self.eocd.total_entries):
            yield CentralDirectoryHeader.from_cursor(cursor)

    def infolist(self) -> list[CentralDirectoryHeader]:
        """Return a list of all Central Directory headers."""
        return list(self.iter_entries())

    def namelist(self) -> list[str]:
        """Return a list of filenames in the archive."""
        return [e.filename for e in self.iter_entries()]

    def getinfo(self, name: str) -> CentralDirectoryHeader:
        """Return CentralDirectoryHeader for entry matching name."""
        for entry in self.iter_entries():
            if entry.filename == name:
                return entry
        raise KeyError(f"There is no item named '{name}' in the archive")

    def __contains__(self, name: object) -> bool:
        if not isinstance(name, str):
            return False
        return any(e.filename == name for e in self.iter_entries())

    def __len__(self) -> int:
        return self.eocd.total_entries

    def __iter__(self) -> Iterator[str]:
        for entry in self.iter_entries():
            yield entry.filename

    def is_stored(self, name: str | CentralDirectoryHeader) -> bool:
        """Return True if specified entry is uncompressed (ZIP_STORED)."""
        cd_header = self.getinfo(name) if isinstance(name, str) else name
        return cd_header.is_stored

    def read(self, name: str | CentralDirectoryHeader) -> memoryview | bytes:
        """Read data for specified entry name or header.

        Returns a zero-copy memoryview slice for STORED entries,
        or decompressed bytes for DEFLATED entries.
        """
        cd_header = self.getinfo(name) if isinstance(name, str) else name
        local_header = LocalFileHeader.from_buffer(self._buffer, cd_header.local_header_offset)
        data_offset = local_header.data_offset(cd_header.local_header_offset)

        if cd_header.is_stored:
            return self._buffer[data_offset : data_offset + cd_header.file_size]
        elif cd_header.is_deflated:
            raw_data = self._buffer[data_offset : data_offset + cd_header.compress_size]
            return zlib.decompress(raw_data, -15)
        else:
            raise ValueError(
                f"Unsupported compression method {cd_header.compress_type} "
                f"for entry '{cd_header.filename}'"
            )

    def __getitem__(self, name: str) -> memoryview | bytes:
        return self.read(name)
