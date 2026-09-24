"""Tests for Android 12+ (v027+) VdexFile container reader and spec structures."""

import io
import os
import struct
import tempfile
import unittest
import zipfile
from collections.abc import Sequence
from typing import Any, cast

from dexbuf.dex import DexFile
from dexbuf.items import (
    DEX_FILE_MAGIC,
    ClassDefItem,
    FieldIdItem,
    HeaderItem,
    MapList,
    MethodIdItem,
    ProtoIdItem,
    StringIdItem,
    TypeIdItem,
)
from dexbuf.types import Count, Offset
from dexbuf.vdex import (
    VDEX_FILE_MAGIC,
    VDEX_INVALID_MAGIC,
    VdexFile,
    VdexHeader,
    VdexSectionHeader,
    VdexSectionKind,
)
from dexbuf.zip import ZipArchive


def create_minimal_dex_bytes() -> bytes:
    """Helper to construct minimal valid DEX header bytes (v035)."""
    magic = b"dex\n035\x00"
    checksum = 0x12345678
    signature = b"\x00" * 20
    file_size = HeaderItem.STRUCT.size  # 112 bytes
    header_size = HeaderItem.STRUCT.size
    endian_tag = 0x12345678

    header = HeaderItem(
        magic=magic,
        checksum=checksum,
        signature=signature,
        file_size=file_size,
        header_size=header_size,
        endian_tag=endian_tag,
        link_size=0,
        link_off=Offset[Any](0),
        map_off=Offset[MapList](0),
        string_ids_size=Count[StringIdItem](0),
        string_ids_off=Offset[StringIdItem](0),
        type_ids_size=Count[TypeIdItem](0),
        type_ids_off=Offset[TypeIdItem](0),
        proto_ids_size=Count[ProtoIdItem](0),
        proto_ids_off=Offset[ProtoIdItem](0),
        field_ids_size=Count[FieldIdItem](0),
        field_ids_off=Offset[FieldIdItem](0),
        method_ids_size=Count[MethodIdItem](0),
        method_ids_off=Offset[MethodIdItem](0),
        class_defs_size=Count[ClassDefItem](0),
        class_defs_off=Offset[ClassDefItem](0),
        data_size=0,
        data_off=Offset[Any](0),
    )

    buf = bytearray(header_size)
    struct_format = HeaderItem.STRUCT
    struct_format.pack_into(
        buf,
        0,
        header.magic,
        header.checksum,
        header.signature,
        header.file_size,
        header.header_size,
        header.endian_tag,
        header.link_size,
        header.link_off,
        header.map_off,
        header.string_ids_size,
        header.string_ids_off,
        header.type_ids_size,
        header.type_ids_off,
        header.proto_ids_size,
        header.proto_ids_off,
        header.field_ids_size,
        header.field_ids_off,
        header.method_ids_size,
        header.method_ids_off,
        header.class_defs_size,
        header.class_defs_off,
        header.data_size,
        header.data_off,
    )
    return bytes(buf)


def create_test_vdex(
    sections: list[tuple[VdexSectionKind, bytes]],
    magic: bytes = b"vdex",
    version: bytes = b"027\x00",
) -> bytes:
    """Helper to construct a VDEX binary buffer with given sections."""
    num_sections = len(sections)
    header_size = VdexHeader.STRUCT.size  # 12 bytes
    table_size = num_sections * VdexSectionHeader.STRUCT.size  # num_sections * 12 bytes
    data_offset = header_size + table_size

    buf = bytearray()

    # VdexHeader
    buf.extend(struct.pack("<4s4sI", magic, version, num_sections))

    # Section headers placeholder
    curr_offset = data_offset
    for kind, payload in sections:
        buf.extend(struct.pack("<3I", int(kind), curr_offset, len(payload)))
        curr_offset += len(payload)

    # Section payloads
    for _, payload in sections:
        buf.extend(payload)

    return bytes(buf)


def create_test_apk_bytes(entries: dict[str, bytes]) -> bytes:
    """Helper to construct a ZIP archive binary buffer with given filename->data entries."""
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", compression=zipfile.ZIP_STORED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return bio.getvalue()


class TestVdexFile(unittest.TestCase):
    def test_header_and_lazy_initialization(self) -> None:
        """Verify VdexHeader parsing and that VdexFile __init__ does not pre-cache attributes."""
        vdex_bytes = create_test_vdex([(VdexSectionKind.VERIFIER_DEPS, b"verifier_deps_data")])
        vdex = VdexFile(vdex_bytes)

        # Assert no pre-cached attributes
        self.assertFalse(hasattr(vdex, "_sections"))
        self.assertFalse(hasattr(vdex, "_checksums"))
        self.assertFalse(hasattr(vdex, "_dex_offsets"))

        # Verify header attributes
        self.assertIsInstance(vdex.header, VdexHeader)
        self.assertEqual(vdex.header.magic, VDEX_FILE_MAGIC)
        self.assertEqual(vdex.header.version, "027")
        self.assertEqual(vdex.header.number_of_sections, 1)
        self.assertEqual(len(vdex), 1)

    def test_section_streaming_and_container_protocol(self) -> None:
        """Verify section iteration, infolist, getinfo, and container methods."""
        sections_def = [
            (VdexSectionKind.CHECKSUM, b"\x78\x56\x34\x12"),
            (VdexSectionKind.DEX_FILE, b"dex_payload_data"),
            (VdexSectionKind.VERIFIER_DEPS, b"verifier_deps"),
            (VdexSectionKind.TYPE_LOOKUP_TABLE, b"type_lookup"),
        ]
        vdex_bytes = create_test_vdex(sections_def)
        vdex = VdexFile(vdex_bytes)

        # iter_sections & container protocol
        sections_list = list(vdex.iter_sections())
        self.assertEqual(len(sections_list), 4)

        for i, (kind, payload) in enumerate(sections_def):
            sec = sections_list[i]
            self.assertIsInstance(sec, VdexSectionHeader)
            self.assertEqual(sec.kind, kind)
            self.assertEqual(sec.size, len(payload))

        # infolist & sections
        self.assertEqual(len(vdex.infolist()), 4)
        self.assertEqual(len(vdex.sections()), 4)

        # __len__ and __iter__
        self.assertEqual(len(vdex), 4)
        self.assertEqual([s.kind for s in vdex], [k for k, _ in sections_def])

        # getinfo & get_section
        sec_dex = vdex.getinfo(VdexSectionKind.DEX_FILE)
        self.assertEqual(sec_dex.kind, VdexSectionKind.DEX_FILE)
        self.assertEqual(sec_dex.size, len(b"dex_payload_data"))

        vdex_partial = VdexFile(create_test_vdex([(VdexSectionKind.DEX_FILE, b"dex")]))
        self.assertIsNone(vdex_partial.get_section(VdexSectionKind.VERIFIER_DEPS))

        # __contains__
        self.assertTrue(VdexSectionKind.DEX_FILE in vdex)
        self.assertTrue(1 in vdex)  # DEX_FILE int value
        self.assertTrue(sec_dex in vdex)
        self.assertFalse(99 in vdex)
        self.assertFalse("invalid_type" in vdex)

        # Missing getinfo
        with self.assertRaises(KeyError) as ctx:
            vdex_partial.getinfo(VdexSectionKind.VERIFIER_DEPS)
        self.assertIn("VERIFIER_DEPS", str(ctx.exception))

    def test_get_section_data_zero_copy_and_getitem(self) -> None:
        """Verify zero-copy memoryview slices and O(1) __getitem__ access."""
        deps_data = b"Verifier deps binary payload content"
        vdex_bytes = create_test_vdex([(VdexSectionKind.VERIFIER_DEPS, deps_data)])
        vdex = VdexFile(vdex_bytes)

        # get_section_data with VdexSectionKind -> zero-copy memoryview
        data_kind = vdex.get_section_data(VdexSectionKind.VERIFIER_DEPS)
        self.assertIsInstance(data_kind, memoryview)
        self.assertEqual(bytes(data_kind), deps_data)

        # get_section_data with VdexSectionHeader -> zero-copy memoryview
        sec_hdr = vdex.getinfo(VdexSectionKind.VERIFIER_DEPS)
        data_hdr = vdex.get_section_data(sec_hdr)
        self.assertIsInstance(data_hdr, memoryview)
        self.assertEqual(bytes(data_hdr), deps_data)

        # __getitem__ with int -> VdexSectionHeader O(1)
        sec_0 = vdex[0]
        self.assertIsInstance(sec_0, VdexSectionHeader)
        self.assertEqual(sec_0.kind, VdexSectionKind.VERIFIER_DEPS)
        self.assertEqual(sec_0, sec_hdr)

        sec_neg1 = vdex[-1]
        self.assertIsInstance(sec_neg1, VdexSectionHeader)
        self.assertEqual(sec_neg1.kind, VdexSectionKind.VERIFIER_DEPS)
        self.assertEqual(sec_neg1, sec_hdr)

        # Out of bounds and invalid key types
        with self.assertRaises(IndexError):
            _ = vdex[1]
        with self.assertRaises(IndexError):
            _ = vdex[-2]

        # Non-integer keys raise TypeError
        with self.assertRaises(TypeError):
            _ = vdex[cast(Any, VdexSectionKind.VERIFIER_DEPS)]
        with self.assertRaises(TypeError):
            _ = vdex[cast(Any, sec_hdr)]
        with self.assertRaises(TypeError):
            _ = vdex[cast(Any, 3.14)]
        with self.assertRaises(TypeError):
            _ = vdex[cast(Any, "0")]
        with self.assertRaises(TypeError):
            _ = vdex[cast(Any, True)]

    def test_sequence_protocol_and_slicing(self) -> None:
        """Verify Sequence inheritance, slice access, and Sequence mixin methods."""
        sections_def = [
            (VdexSectionKind.CHECKSUM, b"\x78\x56\x34\x12"),
            (VdexSectionKind.DEX_FILE, b"dex_payload_data"),
            (VdexSectionKind.VERIFIER_DEPS, b"verifier_deps"),
            (VdexSectionKind.TYPE_LOOKUP_TABLE, b"type_lookup"),
        ]
        vdex = VdexFile(create_test_vdex(sections_def))

        # Sequence protocol inheritance
        self.assertTrue(isinstance(vdex, Sequence))

        # Slicing tests
        sec_all = vdex[:]
        self.assertIsInstance(sec_all, tuple)
        self.assertEqual(len(sec_all), 4)
        self.assertEqual([s.kind for s in sec_all], [k for k, _ in sections_def])

        sec_slice = vdex[0:2]
        self.assertIsInstance(sec_slice, tuple)
        self.assertEqual(len(sec_slice), 2)
        self.assertEqual(sec_slice[0].kind, VdexSectionKind.CHECKSUM)
        self.assertEqual(sec_slice[1].kind, VdexSectionKind.DEX_FILE)

        sec_rev = vdex[::-1]
        self.assertIsInstance(sec_rev, tuple)
        self.assertEqual([s.kind for s in sec_rev], [k for k, _ in reversed(sections_def)])

        sec_oob = vdex[10:20]
        self.assertEqual(sec_oob, ())

        # Sequence mixin methods: reversed(), index(), count()
        reversed_kinds = [s.kind for s in reversed(vdex)]
        self.assertEqual(reversed_kinds, [k for k, _ in reversed(sections_def)])

        target_sec = vdex[1]
        self.assertEqual(vdex.index(target_sec), 1)
        self.assertEqual(vdex.count(target_sec), 1)

    def test_multi_dex_file_streaming_and_interoperability(self) -> None:
        """Verify multi-DEX file parsing, alignment, location checksums, and DexFile integration."""
        dex1_bytes = create_minimal_dex_bytes()
        dex2_bytes = create_minimal_dex_bytes()

        # Construct DEX section bytes with 4-byte alignment
        dex_section_bytes = bytearray(dex1_bytes)
        # Pad to 4-byte boundary
        while len(dex_section_bytes) % 4 != 0:
            dex_section_bytes.append(0)
        dex_section_bytes.extend(dex2_bytes)

        checksum_data = struct.pack("<2I", 0x11223344, 0x55667788)

        vdex_bytes = create_test_vdex(
            [
                (VdexSectionKind.CHECKSUM, checksum_data),
                (VdexSectionKind.DEX_FILE, bytes(dex_section_bytes)),
            ]
        )
        vdex = VdexFile(vdex_bytes)

        # Check properties
        self.assertTrue(vdex.has_dex_section)
        self.assertEqual(vdex.checksums, (0x11223344, 0x55667788))
        self.assertEqual(vdex.number_of_dex_files, 2)

        # iter_dex_data -> zero-copy memoryview slices
        dex_data_list = list(vdex.iter_dex_data())
        self.assertEqual(len(dex_data_list), 2)
        self.assertIsInstance(dex_data_list[0], memoryview)
        self.assertIsInstance(dex_data_list[1], memoryview)
        self.assertEqual(bytes(dex_data_list[0]), dex1_bytes)
        self.assertEqual(bytes(dex_data_list[1]), dex2_bytes)

        # iter_dex_files -> DexFile instances
        dex_files = list(vdex.iter_dex_files())
        self.assertEqual(len(dex_files), 2)
        self.assertIsInstance(dex_files[0], DexFile)
        self.assertEqual(dex_files[0].header.magic, DEX_FILE_MAGIC)

        # get_dex_file
        df0 = vdex.get_dex_file(0)
        df1 = vdex.get_dex_file(1)
        df_last = vdex.get_dex_file(-1)

        self.assertEqual(df0.header.magic, DEX_FILE_MAGIC)
        self.assertEqual(df1.header.magic, DEX_FILE_MAGIC)
        self.assertEqual(df_last.header.magic, df1.header.magic)

        with self.assertRaises(IndexError):
            vdex.get_dex_file(2)
        with self.assertRaises(IndexError):
            vdex.get_dex_file(-3)

    def test_vdex_without_checksum_section(self) -> None:
        """Verify checksums and number_of_dex_files when CHECKSUM section is absent."""
        dex_bytes = create_minimal_dex_bytes()
        vdex_bytes = create_test_vdex([(VdexSectionKind.DEX_FILE, dex_bytes)])
        vdex = VdexFile(vdex_bytes)

        self.assertEqual(vdex.checksums, ())
        self.assertEqual(vdex.number_of_dex_files, 1)

    def test_trailing_alignment_padding_with_checksum_section(self) -> None:
        """Verify iter_dex_data handles trailing zero padding with CHECKSUM section."""
        dex1 = create_minimal_dex_bytes()
        dex2 = create_minimal_dex_bytes()
        checksum_data = struct.pack("<2I", 0x11111111, 0x22222222)

        for pad_len in (1, 2, 3, 16):
            dex_sec = bytearray(dex1)
            while len(dex_sec) % 4 != 0:
                dex_sec.append(0)
            dex_sec.extend(dex2)
            dex_sec.extend(b"\x00" * pad_len)

            vdex = VdexFile(
                create_test_vdex(
                    [
                        (VdexSectionKind.CHECKSUM, checksum_data),
                        (VdexSectionKind.DEX_FILE, bytes(dex_sec)),
                    ]
                )
            )

            self.assertEqual(vdex.number_of_dex_files, 2)
            parsed_data = list(vdex.iter_dex_data())
            self.assertEqual(len(parsed_data), 2)
            self.assertEqual(bytes(parsed_data[0]), dex1)
            self.assertEqual(bytes(parsed_data[1]), dex2)
            self.assertEqual(len(vdex.dex_files), 2)

    def test_trailing_alignment_padding_without_checksum_section(self) -> None:
        """Verify iter_dex_data stops at trailing zero padding without CHECKSUM section."""
        dex = create_minimal_dex_bytes()
        for pad_len in (1, 2, 3, 16):
            dex_sec = dex + b"\x00" * pad_len
            vdex = VdexFile(create_test_vdex([(VdexSectionKind.DEX_FILE, dex_sec)]))

            self.assertEqual(vdex.number_of_dex_files, 1)
            parsed_data = list(vdex.iter_dex_data())
            self.assertEqual(len(parsed_data), 1)
            self.assertEqual(bytes(parsed_data[0]), dex)

    def test_genuinely_truncated_or_corrupt_dex_header_raises_value_error(self) -> None:
        """Verify non-zero corrupt bytes or truncated headers still raise ValueError."""
        dex = create_minimal_dex_bytes()
        # Truncated header with non-zero trailing bytes (e.g. 10 non-zero bytes remaining)
        bad_sec = dex + b"\x01" * 10
        vdex = VdexFile(create_test_vdex([(VdexSectionKind.DEX_FILE, bad_sec)]))
        with self.assertRaises(ValueError) as ctx:
            list(vdex.iter_dex_data())
        self.assertIn("Truncated DEX header", str(ctx.exception))

        # Corrupt file_size field with non-zero header
        corrupt_hdr = bytearray(b"\x01" * 36)
        struct.pack_into("<I", corrupt_hdr, 32, 200)  # file_size = 200 > len(bad_sec)
        vdex_corrupt = VdexFile(create_test_vdex([(VdexSectionKind.DEX_FILE, bytes(corrupt_hdr))]))
        with self.assertRaises(ValueError) as ctx:
            list(vdex_corrupt.iter_dex_data())
        self.assertIn("Invalid DEX file size", str(ctx.exception))

    def test_dex_files_property(self) -> None:
        """Verify vdex.dex_files property returns tuple[DexFile, ...]."""
        # Absent/empty DEX section -> empty tuple
        vdex_empty = VdexFile(create_test_vdex([(VdexSectionKind.VERIFIER_DEPS, b"deps")]))
        self.assertEqual(vdex_empty.dex_files, ())

        # Present DEX section -> tuple of DexFiles
        dex1 = create_minimal_dex_bytes()
        vdex_has_dex = VdexFile(create_test_vdex([(VdexSectionKind.DEX_FILE, dex1)]))
        dfs = vdex_has_dex.dex_files
        self.assertIsInstance(dfs, tuple)
        self.assertEqual(len(dfs), 1)
        self.assertIsInstance(dfs[0], DexFile)
        self.assertEqual(dfs[0].header.magic, DEX_FILE_MAGIC)

    def test_get_dex_file_type_and_bounds_validation(self) -> None:
        """Verify get_dex_file raises TypeError for non-int index and IndexError for OOB."""
        dex = create_minimal_dex_bytes()
        vdex = VdexFile(create_test_vdex([(VdexSectionKind.DEX_FILE, dex)]))

        # TypeError for non-integers
        with self.assertRaises(TypeError):
            vdex.get_dex_file(cast(Any, "0"))
        with self.assertRaises(TypeError):
            vdex.get_dex_file(cast(Any, 1.5))
        with self.assertRaises(TypeError):
            vdex.get_dex_file(cast(Any, True))

        # IndexError for out-of-bounds
        with self.assertRaises(IndexError):
            vdex.get_dex_file(1)
        with self.assertRaises(IndexError):
            vdex.get_dex_file(-2)

    def test_error_handling(self) -> None:
        """Verify exceptions for truncated headers, invalid magic/versions, and corrupt bounds."""
        # Buffer too small for header (<12 bytes)
        with self.assertRaises(ValueError) as ctx:
            VdexFile(b"too_short")
        self.assertIn("Buffer too small for VdexHeader", str(ctx.exception))

        # Invalid magic
        bad_magic_bytes = create_test_vdex([], magic=b"BADM")
        with self.assertRaises(ValueError) as ctx:
            VdexFile(bad_magic_bytes)
        self.assertIn("Invalid VDEX file magic", str(ctx.exception))

        # Invalid magic b"wdex" (kVdexInvalidMagic)
        invalid_wdex_bytes = create_test_vdex([], magic=VDEX_INVALID_MAGIC)
        with self.assertRaises(ValueError) as ctx:
            VdexFile(invalid_wdex_bytes)
        self.assertIn("marked invalid / incompletely written", str(ctx.exception))

        # Unsupported version
        bad_ver_bytes = create_test_vdex([], version=b"021\x00")
        with self.assertRaises(ValueError) as ctx:
            VdexFile(bad_ver_bytes)
        self.assertIn("Unsupported VDEX version", str(ctx.exception))

        # Buffer too small for section header table
        # Claim 5 sections, but buffer has only 12 bytes
        truncated_table_bytes = struct.pack("<4s4sI", b"vdex", b"027\x00", 5)
        with self.assertRaises(ValueError) as ctx:
            VdexFile(truncated_table_bytes)
        self.assertIn("Buffer too small for section header table", str(ctx.exception))

        # Invalid VdexSectionKind enum value
        bad_kind_table = bytearray(struct.pack("<4s4sI", b"vdex", b"027\x00", 1))
        bad_kind_table.extend(struct.pack("<3I", 999, 24, 0))  # Raw kind 999
        with self.assertRaises(ValueError) as ctx:
            _ = list(VdexFile(bad_kind_table).iter_sections())
        self.assertIn("Invalid VdexSectionKind value: 999", str(ctx.exception))

        # Section payload out of buffer bounds
        out_of_bounds_bytes = bytearray(struct.pack("<4s4sI", b"vdex", b"027\x00", 1))
        out_of_bounds_bytes.extend(struct.pack("<3I", 0, 1000, 500))  # Offset 1000 past end
        vdex_oob = VdexFile(out_of_bounds_bytes)
        with self.assertRaises(ValueError) as ctx:
            vdex_oob.get_section_data(VdexSectionKind.CHECKSUM)
        self.assertIn("extend past buffer length", str(ctx.exception))

        # Truncated DEX header in DEX section
        short_dex_section = create_test_vdex([(VdexSectionKind.DEX_FILE, b"short_header_bytes")])
        vdex_short_dex = VdexFile(short_dex_section)
        with self.assertRaises(ValueError) as ctx:
            list(vdex_short_dex.iter_dex_data())
        self.assertIn("Truncated DEX header", str(ctx.exception))

        # Invalid DEX file size in DEX section
        corrupt_size_dex = bytearray(b"\x00" * 36)
        struct.pack_into("<I", corrupt_size_dex, 32, 10)  # file_size = 10 (< 112)
        vdex_corrupt_size = VdexFile(
            create_test_vdex([(VdexSectionKind.DEX_FILE, bytes(corrupt_size_dex))])
        )
        with self.assertRaises(ValueError) as ctx:
            list(vdex_corrupt_size.iter_dex_data())
        self.assertIn("Invalid DEX file size 10", str(ctx.exception))

    def test_section_presence_properties(self) -> None:
        """Verify section presence properties (has_checksum_section, etc.)."""
        # Section present and size > 0
        vdex_full = VdexFile(
            create_test_vdex(
                [
                    (VdexSectionKind.CHECKSUM, b"\x01\x00\x00\x00"),
                    (VdexSectionKind.VERIFIER_DEPS, b"deps"),
                    (VdexSectionKind.TYPE_LOOKUP_TABLE, b"table"),
                ]
            )
        )
        self.assertTrue(vdex_full.has_checksum_section)
        self.assertTrue(vdex_full.has_verifier_deps_section)
        self.assertTrue(vdex_full.has_type_lookup_table_section)

        # Section empty (size == 0) or absent
        vdex_empty_sec = VdexFile(
            create_test_vdex(
                [
                    (VdexSectionKind.CHECKSUM, b""),
                    (VdexSectionKind.VERIFIER_DEPS, b""),
                ]
            )
        )
        self.assertFalse(vdex_empty_sec.has_checksum_section)
        self.assertFalse(vdex_empty_sec.has_verifier_deps_section)
        self.assertFalse(vdex_empty_sec.has_type_lookup_table_section)

    def test_computed_file_size_and_is_valid(self) -> None:
        """Verify computed_file_size calculation and is_valid property."""
        deps_data = b"verifier_deps_payload_12345"
        vdex_bytes = create_test_vdex([(VdexSectionKind.VERIFIER_DEPS, deps_data)])
        vdex = VdexFile(vdex_bytes)

        expected_size = len(vdex_bytes)
        self.assertEqual(vdex.computed_file_size, expected_size)
        self.assertTrue(vdex.is_valid)

        # Truncated buffer past header table
        truncated_bytes = vdex_bytes[: expected_size - 5]
        vdex_trunc = VdexFile(truncated_bytes)
        self.assertEqual(vdex_trunc.computed_file_size, expected_size)
        self.assertFalse(vdex_trunc.is_valid)

    def test_verify_checksums_with_contained_dex(self) -> None:
        """Verify verify_checksums when DEX files are present in VDEX."""
        dex1 = create_minimal_dex_bytes()
        # dex1 checksum in create_minimal_dex_bytes is 0x12345678
        checksum_data = struct.pack("<I", 0x12345678)

        vdex_bytes = create_test_vdex(
            [
                (VdexSectionKind.CHECKSUM, checksum_data),
                (VdexSectionKind.DEX_FILE, dex1),
            ]
        )
        vdex = VdexFile(vdex_bytes)

        # Valid checksum verification
        self.assertTrue(vdex.verify_checksums())

        # Passing apk when DEX files are present raises ValueError
        dummy_apk = ZipArchive(create_test_apk_bytes({"classes.dex": b"dummy"}))
        with self.assertRaises(ValueError) as ctx:
            vdex.verify_checksums(apk=dummy_apk)
        self.assertIn("APK must be None", str(ctx.exception))

        # Checksum mismatch
        bad_checksum_vdex = VdexFile(
            create_test_vdex(
                [
                    (VdexSectionKind.CHECKSUM, struct.pack("<I", 0x99999999)),
                    (VdexSectionKind.DEX_FILE, dex1),
                ]
            )
        )
        self.assertFalse(bad_checksum_vdex.verify_checksums())

        # Count mismatch (e.g. 2 checksums for 1 DEX file)
        mismatch_count_vdex = VdexFile(
            create_test_vdex(
                [
                    (VdexSectionKind.CHECKSUM, struct.pack("<2I", 0x12345678, 0x87654321)),
                    (VdexSectionKind.DEX_FILE, dex1),
                ]
            )
        )
        self.assertFalse(mismatch_count_vdex.verify_checksums())

    def test_verify_checksums_without_contained_dex(self) -> None:
        """Verify verify_checksums when DEX files are NOT present in VDEX (using APK)."""
        content1 = b"classes.dex content"
        content2 = b"classes2.dex content"
        apk_bytes = create_test_apk_bytes(
            {
                "classes.dex": content1,
                "classes2.dex": content2,
            }
        )
        apk = ZipArchive(apk_bytes)
        crc1 = apk.getinfo("classes.dex").crc32
        crc2 = apk.getinfo("classes2.dex").crc32

        vdex = VdexFile(
            create_test_vdex(
                [
                    (VdexSectionKind.CHECKSUM, struct.pack("<2I", crc1, crc2)),
                    (VdexSectionKind.VERIFIER_DEPS, b"deps"),
                ]
            )
        )

        # apk=None when no DEX files present raises ValueError
        with self.assertRaises(ValueError) as ctx:
            vdex.verify_checksums(apk=None)
        self.assertIn("APK must be provided", str(ctx.exception))

        # Valid checksum match with APK
        self.assertTrue(vdex.verify_checksums(apk=apk))

        # Checksum mismatch
        bad_crc_vdex = VdexFile(
            create_test_vdex(
                [
                    (VdexSectionKind.CHECKSUM, struct.pack("<2I", crc1, 0xDEADBEEF)),
                    (VdexSectionKind.VERIFIER_DEPS, b"deps"),
                ]
            )
        )
        self.assertFalse(bad_crc_vdex.verify_checksums(apk=apk))

        # Missing expected multidex entry in APK
        apk_missing = ZipArchive(create_test_apk_bytes({"classes.dex": content1}))
        self.assertFalse(vdex.verify_checksums(apk=apk_missing))

        # Extra multidex entry in APK (classes3.dex)
        apk_extra = ZipArchive(
            create_test_apk_bytes(
                {
                    "classes.dex": content1,
                    "classes2.dex": content2,
                    "classes3.dex": b"extra",
                }
            )
        )
        self.assertFalse(vdex.verify_checksums(apk=apk_extra))

    def test_verify_checksums_missing_checksum_section(self) -> None:
        """Verify verify_checksums returns False when CHECKSUM section is missing or empty."""
        vdex = VdexFile(create_test_vdex([(VdexSectionKind.VERIFIER_DEPS, b"deps")]))
        self.assertFalse(vdex.verify_checksums())

    def test_open_mmap_and_context_manager(self) -> None:
        """Verify open() with mmap and context manager lifecycle."""
        deps_data = b"verifier_deps_payload"
        vdex_bytes = create_test_vdex([(VdexSectionKind.VERIFIER_DEPS, deps_data)])

        with tempfile.NamedTemporaryFile("wb", delete=False) as tf:
            tf.write(vdex_bytes)
            tmp_path = tf.name

        try:
            # open with mmap=True
            with VdexFile.open(tmp_path, mmap=True) as vdex:
                self.assertEqual(len(vdex), 1)
                self.assertEqual(
                    bytes(vdex.get_section_data(VdexSectionKind.VERIFIER_DEPS)), deps_data
                )

            # open with mmap=False
            with VdexFile.open(tmp_path, mmap=False) as vdex:
                self.assertEqual(len(vdex), 1)
                self.assertEqual(
                    bytes(vdex.get_section_data(VdexSectionKind.VERIFIER_DEPS)), deps_data
                )
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)


if __name__ == "__main__":
    unittest.main()
