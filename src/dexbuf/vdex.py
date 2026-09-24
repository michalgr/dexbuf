"""Stateless, zero-copy Android 12+ VDEX container reader and specification structures."""

import enum
import mmap as mmap_module
import os
import struct
from collections.abc import Buffer, Iterator
from dataclasses import dataclass
from types import TracebackType
from typing import BinaryIO, ClassVar, Final, Self

from dexbuf.cursor import Cursor
from dexbuf.dex import DexFile

VDEX_FILE_MAGIC: Final[bytes] = b"vdex"
SUPPORTED_VDEX_VERSIONS: Final[frozenset[str]] = frozenset({"027"})


class VdexSectionKind(enum.IntEnum):
    """Section kind enumeration for Android 12+ VDEX containers."""

    CHECKSUM = 0
    DEX_FILE = 1
    VERIFIER_DEPS = 2
    TYPE_LOOKUP_TABLE = 3


@dataclass(slots=True, frozen=True)
class VdexHeader:
    """Header structure for Android 12+ VDEX files."""

    STRUCT: ClassVar[struct.Struct] = struct.Struct("<4s4sI")

    magic: bytes
    version: str
    number_of_sections: int

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Parse a VdexHeader from cursor."""
        magic, version_bytes, number_of_sections = cursor.unpack(cls.STRUCT)

        if magic != VDEX_FILE_MAGIC:
            raise ValueError(
                f"Invalid VDEX file magic: expected {VDEX_FILE_MAGIC!r}, got {magic!r}"
            )

        version = version_bytes.decode("utf-8", errors="replace").rstrip("\x00")
        if version not in SUPPORTED_VDEX_VERSIONS:
            raise ValueError(f"Unsupported VDEX format version: {version!r}")

        return cls(
            magic=magic,
            version=version,
            number_of_sections=number_of_sections,
        )

    @classmethod
    def from_buffer(cls, buffer: Buffer, offset: int = 0) -> Self:
        """Parse a VdexHeader from buffer at offset."""
        return cls.from_cursor(Cursor(buffer, offset))


@dataclass(slots=True, frozen=True)
class VdexSectionHeader:
    """Section header structure for Android 12+ VDEX files."""

    STRUCT: ClassVar[struct.Struct] = struct.Struct("<3I")

    kind: VdexSectionKind
    offset: int
    size: int

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Parse a VdexSectionHeader from cursor."""
        kind_val, offset, size = cursor.unpack(cls.STRUCT)
        try:
            kind = VdexSectionKind(kind_val)
        except ValueError as err:
            raise ValueError(f"Unknown VDEX section kind: {kind_val}") from err

        return cls(
            kind=kind,
            offset=offset,
            size=size,
        )

    @classmethod
    def from_buffer(cls, buffer: Buffer, offset: int = 0) -> Self:
        """Parse a VdexSectionHeader from buffer at offset."""
        return cls.from_cursor(Cursor(buffer, offset))


class VdexFile:
    """Zero-copy, stateless Android 12+ VDEX container reader operating on a Buffer."""

    __slots__ = (
        "_buffer",
        "_checksums",
        "_dex_offsets",
        "_file",
        "_mmap",
        "_sections",
        "header",
    )

    def __init__(self, buffer: Buffer) -> None:
        self._buffer: memoryview = memoryview(buffer).cast("B")
        self._file: BinaryIO | None = None
        self._mmap: mmap_module.mmap | None = None

        if len(self._buffer) < VdexHeader.STRUCT.size:
            raise ValueError("Invalid VDEX file: buffer too small for header")

        self.header: VdexHeader = VdexHeader.from_buffer(self._buffer, 0)

        sections_offset = VdexHeader.STRUCT.size
        sections_end = (
            sections_offset + self.header.number_of_sections * VdexSectionHeader.STRUCT.size
        )
        if sections_end > len(self._buffer):
            raise ValueError("Invalid VDEX file: section headers extend past buffer end")

        cursor = Cursor(self._buffer, sections_offset)
        sections_list: list[VdexSectionHeader] = []
        for _ in range(self.header.number_of_sections):
            sec = VdexSectionHeader.from_cursor(cursor)
            if sec.offset + sec.size > len(self._buffer):
                raise ValueError(
                    f"Invalid VDEX section {sec.kind.name}: section payload extends past buffer end"
                )
            sections_list.append(sec)

        self._sections: tuple[VdexSectionHeader, ...] = tuple(sections_list)

        # Parse checksums section
        checksum_sec = self.get_section(VdexSectionKind.CHECKSUM)
        checksums_list: list[int] = []
        if checksum_sec is not None and checksum_sec.size > 0:
            if checksum_sec.size % 4 != 0:
                raise ValueError("Invalid CHECKSUM section size: not a multiple of 4")
            count = checksum_sec.size // 4
            fmt = f"<{count}I"
            checksums_list = list(struct.unpack_from(fmt, self._buffer, checksum_sec.offset))
        self._checksums: tuple[int, ...] = tuple(checksums_list)

        # Index DEX files in DEX_FILE section
        dex_sec = self.get_section(VdexSectionKind.DEX_FILE)
        dex_offsets: list[tuple[int, int]] = []
        if dex_sec is not None and dex_sec.size > 0:
            curr = dex_sec.offset
            sec_end = dex_sec.offset + dex_sec.size
            while curr < sec_end:
                if curr + 112 > sec_end:
                    raise ValueError("Invalid DEX_FILE section: truncated DEX header")
                file_size = struct.unpack_from("<I", self._buffer, curr + 32)[0]
                if file_size < 112:
                    raise ValueError(f"Invalid DEX file size in VDEX: {file_size}")
                if curr + file_size > sec_end:
                    raise ValueError(
                        "Invalid DEX_FILE section: DEX payload extends past section end"
                    )
                dex_offsets.append((curr, file_size))
                curr = (curr + file_size + 3) & ~3

        self._dex_offsets: tuple[tuple[int, int], ...] = tuple(dex_offsets)

        if (
            checksum_sec is not None
            and checksum_sec.size > 0
            and dex_sec is not None
            and dex_sec.size > 0
        ):
            if len(self._checksums) != len(self._dex_offsets):
                raise ValueError(
                    f"Mismatch between location checksum count ({len(self._checksums)}) "
                    f"and DEX file count ({len(self._dex_offsets)})"
                )

    @classmethod
    def open(cls, path: str | os.PathLike[str], *, mmap: bool = True) -> Self:
        """Open a VDEX file from disk with optional memory-mapping."""
        if mmap:
            f = open(path, "rb")
            try:
                mm = mmap_module.mmap(f.fileno(), 0, access=mmap_module.ACCESS_READ)
            except Exception:
                f.close()
                raise
            vdex = cls(mm)
            vdex._file = f
            vdex._mmap = mm
            return vdex
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

    @property
    def has_dex_section(self) -> bool:
        """Return True if DEX file section is present and non-empty."""
        sec = self.get_section(VdexSectionKind.DEX_FILE)
        return sec is not None and sec.size > 0

    @property
    def checksums(self) -> tuple[int, ...]:
        """Return tuple of uint32 location checksums for each DEX file."""
        return self._checksums

    def get_section(self, kind: VdexSectionKind) -> VdexSectionHeader | None:
        """Return VdexSectionHeader for the given section kind, or None if missing."""
        for sec in self._sections:
            if sec.kind == kind:
                return sec
        return None

    def get_section_data(self, kind: VdexSectionKind) -> memoryview | None:
        """Return zero-copy memoryview slice of section payload, or None if missing."""
        sec = self.get_section(kind)
        if sec is None:
            return None
        return self._buffer[sec.offset : sec.offset + sec.size]

    def __len__(self) -> int:
        return len(self._dex_offsets)

    def __iter__(self) -> Iterator[memoryview]:
        for offset, size in self._dex_offsets:
            yield self._buffer[offset : offset + size]

    def __getitem__(self, index: int) -> memoryview:
        return self.get_dex_data(index)

    def get_dex_data(self, index: int) -> memoryview:
        """Return zero-copy memoryview slice for the i-th DEX file."""
        if index < 0:
            index += len(self._dex_offsets)
        if index < 0 or index >= len(self._dex_offsets):
            raise IndexError(f"Index {index} out of bounds for {len(self._dex_offsets)} DEX files")
        offset, size = self._dex_offsets[index]
        return self._buffer[offset : offset + size]

    def get_dex_file(self, index: int) -> DexFile:
        """Directly construct and return DexFile for the i-th DEX file."""
        return DexFile(self.get_dex_data(index))

    def iter_dex_files(self) -> Iterator[DexFile]:
        """Yield DexFile instances for each DEX file in the container."""
        for offset, size in self._dex_offsets:
            yield DexFile(self._buffer[offset : offset + size])
