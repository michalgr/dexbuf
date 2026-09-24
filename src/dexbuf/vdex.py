"""Zero-copy, stateless Android 12+ (v027+) VDEX container parser and specification structures."""

import enum
import mmap as mmap_module
import os
import struct
from collections.abc import Buffer, Iterator, Sequence
from dataclasses import dataclass
from types import TracebackType
from typing import BinaryIO, ClassVar, Final, Self, overload

from dexbuf.cursor import Cursor
from dexbuf.dex import DexFile
from dexbuf.type_lookup import TypeLookupTable, TypeLookupTableEntry
from dexbuf.zip import ZipArchive

__all__ = [
    "SUPPORTED_VDEX_VERSIONS",
    "VDEX_FILE_MAGIC",
    "VDEX_INVALID_MAGIC",
    "TypeLookupTable",
    "TypeLookupTableEntry",
    "VdexFile",
    "VdexHeader",
    "VdexSectionHeader",
    "VdexSectionKind",
]

VDEX_FILE_MAGIC: Final[bytes] = b"vdex"
VDEX_INVALID_MAGIC: Final[bytes] = b"wdex"
SUPPORTED_VDEX_VERSIONS: Final[frozenset[str]] = frozenset({"027"})


class VdexSectionKind(enum.IntEnum):
    """Section kind enumeration for Android 12+ (v027+) VDEX files."""

    CHECKSUM = 0
    DEX_FILE = 1
    VERIFIER_DEPS = 2
    TYPE_LOOKUP_TABLE = 3


@dataclass(slots=True, frozen=True)
class VdexHeader:
    """Header structure for Android 12+ (v027+) VDEX container files."""

    STRUCT: ClassVar[struct.Struct] = struct.Struct("<4s4sI")

    magic: bytes
    version: str
    number_of_sections: int

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Parse a VdexHeader from cursor."""
        magic, version_bytes, number_of_sections = cursor.unpack(cls.STRUCT)

        if magic == VDEX_INVALID_MAGIC:
            raise ValueError(
                f"VDEX file is marked invalid / incompletely written: magic is {magic!r}"
            )

        if magic != VDEX_FILE_MAGIC:
            raise ValueError(
                f"Invalid VDEX file magic: expected {VDEX_FILE_MAGIC!r}, got {magic!r}"
            )

        version = version_bytes.decode("ascii", errors="replace").rstrip("\x00")
        if version not in SUPPORTED_VDEX_VERSIONS:
            versions = sorted(SUPPORTED_VDEX_VERSIONS)
            raise ValueError(
                f"Unsupported VDEX version: expected one of {versions}, got {version!r}"
            )

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
    """Section header structure in Android 12+ (v027+) VDEX container table."""

    STRUCT: ClassVar[struct.Struct] = struct.Struct("<3I")

    kind: VdexSectionKind
    offset: int
    size: int

    @classmethod
    def from_cursor(cls, cursor: Cursor) -> Self:
        """Parse a VdexSectionHeader from cursor."""
        raw_kind, offset, size = cursor.unpack(cls.STRUCT)

        try:
            kind = VdexSectionKind(raw_kind)
        except ValueError:
            raise ValueError(f"Invalid VdexSectionKind value: {raw_kind}") from None

        return cls(
            kind=kind,
            offset=offset,
            size=size,
        )

    @classmethod
    def from_buffer(cls, buffer: Buffer, offset: int = 0) -> Self:
        """Parse a VdexSectionHeader from buffer at offset."""
        return cls.from_cursor(Cursor(buffer, offset))


class VdexFile(Sequence[VdexSectionHeader]):
    """Zero-copy, stateless Android 12+ (v027+) VDEX container file reader."""

    __slots__ = ("_buffer", "_file", "_mmap", "header")

    def __init__(self, buffer: Buffer) -> None:
        """Initialize VdexFile lazily.

        Validates minimum size for VdexHeader, parses self.header, and validates that
        the section header table bounds fit within buffer.
        Does NOT pre-allocate cached lists or tuples of sections, checksums, or DEX offsets.
        """
        self._buffer: memoryview = memoryview(buffer).cast("B")
        self._file: BinaryIO | None = None
        self._mmap: mmap_module.mmap | None = None

        if len(self._buffer) < VdexHeader.STRUCT.size:
            expected = VdexHeader.STRUCT.size
            raise ValueError(
                f"Buffer too small for VdexHeader: expected at least {expected} bytes, "
                f"got {len(self._buffer)}"
            )

        self.header: VdexHeader = VdexHeader.from_buffer(self._buffer, 0)

        section_table_size = self.header.number_of_sections * VdexSectionHeader.STRUCT.size
        required_size = VdexHeader.STRUCT.size + section_table_size
        if len(self._buffer) < required_size:
            raise ValueError(
                f"Buffer too small for section header table: expected at least "
                f"{required_size} bytes, got {len(self._buffer)}"
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

    # Section Streaming & Inspection
    def iter_sections(self) -> Iterator[VdexSectionHeader]:
        """Stream VdexSectionHeader instances lazily on the fly using Cursor."""
        cursor = Cursor(self._buffer, VdexHeader.STRUCT.size)
        for _ in range(self.header.number_of_sections):
            yield VdexSectionHeader.from_cursor(cursor)

    def infolist(self) -> list[VdexSectionHeader]:
        """Return list of all section headers (mirrors ZipArchive.infolist())."""
        return list(self.iter_sections())

    def sections(self) -> list[VdexSectionHeader]:
        """Alias for infolist()."""
        return self.infolist()

    def getinfo(self, kind: VdexSectionKind) -> VdexSectionHeader:
        """Return VdexSectionHeader matching kind, or raise KeyError if missing."""
        sec = self.get_section(kind)
        if sec is None:
            raise KeyError(f"Section of kind {kind!r} not found in VDEX file")
        return sec

    def get_section(self, kind: VdexSectionKind) -> VdexSectionHeader | None:
        """Return VdexSectionHeader matching kind, or None if missing."""
        for section in self.iter_sections():
            if section.kind == kind:
                return section
        return None

    def __contains__(self, kind: object) -> bool:
        """Return True if section of kind exists."""
        if isinstance(kind, (VdexSectionKind, int)):
            return any(s.kind == kind for s in self.iter_sections())
        if isinstance(kind, VdexSectionHeader):
            return any(s == kind for s in self.iter_sections())
        return False

    def __len__(self) -> int:
        """Return number of sections (self.header.number_of_sections)."""
        return self.header.number_of_sections

    def __iter__(self) -> Iterator[VdexSectionHeader]:
        """Iterate over section headers (yields VdexSectionHeader)."""
        return self.iter_sections()

    # Section Data Retrieval (Zero-copy slice)
    def get_section_data(self, section: VdexSectionHeader | VdexSectionKind) -> memoryview:
        """Return a zero-copy memoryview slice of the given section's payload.

        Accepts either a VdexSectionHeader or VdexSectionKind.
        Raises KeyError if VdexSectionKind is not present.
        Raises ValueError if section payload extends past the buffer end.
        """
        if isinstance(section, VdexSectionKind):
            sec_header = self.getinfo(section)
        elif isinstance(section, VdexSectionHeader):
            sec_header = section
        else:
            raise TypeError(f"Expected VdexSectionHeader or VdexSectionKind, got {type(section)}")

        if sec_header.offset < 0 or sec_header.offset + sec_header.size > len(self._buffer):
            raise ValueError(
                f"Section bounds [{sec_header.offset}, {sec_header.offset + sec_header.size}] "
                f"extend past buffer length {len(self._buffer)}"
            )

        return self._buffer[sec_header.offset : sec_header.offset + sec_header.size]

    @overload
    def __getitem__(self, index: int) -> VdexSectionHeader: ...

    @overload
    def __getitem__(self, index: slice) -> tuple[VdexSectionHeader, ...]: ...

    def __getitem__(self, index: int | slice) -> VdexSectionHeader | tuple[VdexSectionHeader, ...]:
        """Return the i-th VdexSectionHeader (supports negative indices and slices)."""
        num = self.header.number_of_sections
        if isinstance(index, slice):
            return tuple(self[i] for i in range(*index.indices(num)))

        if type(index) is not int:
            raise TypeError(f"Index must be an integer or slice, got {type(index).__name__}")

        idx = index
        if idx < 0:
            idx += num
        if idx < 0 or idx >= num:
            raise IndexError(f"Section index {index} out of range (total {num})")
        offset = VdexHeader.STRUCT.size + idx * VdexSectionHeader.STRUCT.size
        return VdexSectionHeader.from_buffer(self._buffer, offset)

    # Section Presence Properties
    @property
    def has_checksum_section(self) -> bool:
        """Return True if CHECKSUM section is present and non-empty."""
        sec = self.get_section(VdexSectionKind.CHECKSUM)
        return sec is not None and sec.size > 0

    @property
    def has_verifier_deps_section(self) -> bool:
        """Return True if VERIFIER_DEPS section is present and non-empty."""
        sec = self.get_section(VdexSectionKind.VERIFIER_DEPS)
        return sec is not None and sec.size > 0

    @property
    def has_type_lookup_table_section(self) -> bool:
        """Return True if TYPE_LOOKUP_TABLE section is present and non-empty."""
        sec = self.get_section(VdexSectionKind.TYPE_LOOKUP_TABLE)
        return sec is not None and sec.size > 0

    @property
    def computed_file_size(self) -> int:
        """Compute expected minimum VDEX file size based on header and section extents."""
        hdr_size = VdexHeader.STRUCT.size
        sec_table_size = self.header.number_of_sections * VdexSectionHeader.STRUCT.size
        min_size = hdr_size + sec_table_size
        for sec in self:
            min_size = max(min_size, sec.offset + sec.size)
        return min_size

    @property
    def is_valid(self) -> bool:
        """Return True if buffer is large enough to contain all section payloads."""
        return len(self._buffer) >= self.computed_file_size

    # DEX File Streaming & Interoperability
    @property
    def has_dex_section(self) -> bool:
        """Return True if DEX_FILE section is present and non-empty."""
        sec = self.get_section(VdexSectionKind.DEX_FILE)
        return sec is not None and sec.size > 0

    @property
    def checksums(self) -> tuple[int, ...]:
        """Return tuple of uint32 location checksums evaluated on demand from CHECKSUM section."""
        sec = self.get_section(VdexSectionKind.CHECKSUM)
        if sec is None or sec.size == 0:
            return ()
        data = self.get_section_data(sec)
        count = len(data) // 4
        if count == 0:
            return ()
        return struct.unpack_from(f"<{count}I", data, 0)

    @property
    def number_of_dex_files(self) -> int:
        """Return count of DEX files based on CHECKSUM section size or iter_dex_data()."""
        sec = self.get_section(VdexSectionKind.CHECKSUM)
        if sec is not None and sec.size > 0:
            return sec.size // 4
        return sum(1 for _ in self.iter_dex_data())

    @property
    def dex_files(self) -> tuple[DexFile, ...]:
        """Return tuple of DexFile instances parsed from DEX_FILE section."""
        return tuple(self.iter_dex_files())

    def iter_dex_data(self) -> Iterator[memoryview]:
        """Stream zero-copy memoryview slices for each contained DEX file on the fly
        by reading file_size from offset 32 of each DEX header and advancing with 4-byte alignment.
        """
        sec = self.get_section(VdexSectionKind.DEX_FILE)
        if sec is None or sec.size == 0:
            return

        checksum_sec = self.get_section(VdexSectionKind.CHECKSUM)
        expected_count: int | None = None
        if checksum_sec is not None and checksum_sec.size > 0:
            expected_count = checksum_sec.size // 4

        dex_section_data = self.get_section_data(sec)
        sec_len = len(dex_section_data)
        pos = 0
        count = 0

        while pos < sec_len:
            if expected_count is not None and count >= expected_count:
                break

            if not any(dex_section_data[pos:]):
                break

            if pos + 36 > sec_len:
                raise ValueError("Truncated DEX header in DEX_FILE section")

            file_size = struct.unpack_from("<I", dex_section_data, pos + 32)[0]
            if file_size < 112 or pos + file_size > sec_len:
                raise ValueError(
                    f"Invalid DEX file size {file_size} at relative offset {pos} in DEX section"
                )

            yield dex_section_data[pos : pos + file_size]
            count += 1

            next_pos = pos + file_size
            pos = (next_pos + 3) & ~3

    def iter_dex_files(self) -> Iterator[DexFile]:
        """Yield DexFile instances for each DEX file on the fly."""
        for data in self.iter_dex_data():
            yield DexFile(data)

    def get_dex_file(self, index: int) -> DexFile:
        """Return DexFile for the index-th DEX file."""
        if type(index) is not int:
            raise TypeError(f"Index must be an integer, got {type(index).__name__}")

        num = self.number_of_dex_files
        idx = index
        if idx < 0:
            idx += num
        if idx < 0 or idx >= num:
            raise IndexError(f"DEX file index {index} out of range (total {num})")

        for i, dex_data in enumerate(self.iter_dex_data()):
            if i == idx:
                return DexFile(dex_data)
        raise IndexError(f"DEX file index {index} out of range (total {num})")

    # TypeLookupTable Integration
    def iter_type_lookup_table_data(self) -> Iterator[memoryview]:
        """Stream raw table slices for each DEX file from TYPE_LOOKUP_TABLE section on the fly."""
        sec = self.get_section(VdexSectionKind.TYPE_LOOKUP_TABLE)
        if sec is None or sec.size == 0:
            return

        table_sec_data = self.get_section_data(sec)
        sec_len = len(table_sec_data)
        pos = 0

        checksum_sec = self.get_section(VdexSectionKind.CHECKSUM)
        expected_count: int | None = None
        if checksum_sec is not None and checksum_sec.size > 0:
            expected_count = checksum_sec.size // 4

        count = 0
        while pos < sec_len:
            if expected_count is not None and count >= expected_count:
                break

            if pos + 4 > sec_len:
                raise ValueError("Truncated table size in TYPE_LOOKUP_TABLE section")

            table_size = struct.unpack_from("<I", table_sec_data, pos)[0]
            pos += 4

            if pos + table_size > sec_len:
                raise ValueError(
                    f"Invalid table size {table_size} at offset {pos - 4} "
                    "in TYPE_LOOKUP_TABLE section"
                )

            yield table_sec_data[pos : pos + table_size]
            pos += table_size
            count += 1

    def get_type_lookup_table(
        self, dex_index: int, dex_buffer: Buffer | None = None
    ) -> TypeLookupTable | None:
        """Return TypeLookupTable for the dex_index-th DEX file, or None if absent."""
        if type(dex_index) is not int:
            raise TypeError(f"Index must be an integer, got {type(dex_index).__name__}")

        if not self.has_type_lookup_table_section:
            return None

        num = self.number_of_dex_files
        idx = dex_index
        if idx < 0:
            idx += num
        if idx < 0 or idx >= num:
            raise IndexError(f"DEX file index {dex_index} out of range (total {num})")

        tables = list(self.iter_type_lookup_table_data())
        if idx >= len(tables):
            return None

        raw_table_data = tables[idx]

        if dex_buffer is None:
            if self.has_dex_section:
                dex_file = self.get_dex_file(idx)
                dex_buffer = dex_file._buffer
            else:
                raise ValueError("dex_buffer must be provided when VDEX has no DEX_FILE section")

        return TypeLookupTable(dex_buffer, raw_table_data)

    def verify_checksums(self, apk: ZipArchive | None = None) -> bool:
        """Verify DEX checksums against the CHECKSUM section.

        - If VDEX contains DEX files (self.has_dex_section is True):
            apk must be None. Compares the checksum in each contained DEX header
            against the checksums in the VDEX.
            Raises ValueError if apk is not None.
        - If VDEX does not contain DEX files (self.has_dex_section is False):
            apk must be provided (ZipArchive). Compares the checksums in the VDEX
            against the CRC-32 of each multidex entry in the APK.
            Raises ValueError if apk is None.

        Returns:
            True if all checksums match and counts match.
            False if the CHECKSUM section is absent/empty or if any checksum/count mismatches.
        """
        if not self.has_checksum_section:
            return False

        checksums = self.checksums
        if len(checksums) == 0:
            return False

        if self.has_dex_section:
            if apk is not None:
                raise ValueError("APK must be None when DEX files are present in VDEX")
            dex_files = self.dex_files
            if len(dex_files) != len(checksums):
                return False
            return all(
                dex.header.checksum == expected_chk
                for dex, expected_chk in zip(dex_files, checksums, strict=True)
            )
        else:
            if apk is None:
                raise ValueError("APK must be provided when DEX files are not present in VDEX")
            for i, expected_crc in enumerate(checksums):
                entry_name = "classes.dex" if i == 0 else f"classes{i + 1}.dex"
                if entry_name not in apk:
                    return False
                if apk.getinfo(entry_name).crc32 != expected_crc:
                    return False
            extra_entry = f"classes{len(checksums) + 1}.dex"
            if extra_entry in apk:
                return False
            return True
