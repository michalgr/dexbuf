"""Tests for stateless zero-copy VdexFile reader and VDEX specification dataclasses."""

import os
import struct
import tempfile
import unittest
from typing import Any

from dexbuf import (
    VDEX_FILE_MAGIC,
    DexFile,
    VdexFile,
    VdexHeader,
    VdexSectionHeader,
    VdexSectionKind,
)
from dexbuf.items import (
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


def create_minimal_dex_bytes() -> bytes:
    """Helper to construct minimal valid DEX header bytes (v035)."""
    magic = b"dex\n035\x00"
    checksum = 0
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
    dex_files: list[bytes] | None = None,
    checksums: list[int] | None = None,
    extra_sections: dict[VdexSectionKind, bytes] | None = None,
    version: bytes = b"027\x00",
    magic: bytes = b"vdex",
) -> bytes:
    """Helper to construct a valid synthetic v027 VDEX container buffer."""
    sections: list[tuple[VdexSectionKind, bytes]] = []

    if checksums is not None:
        checksum_bytes = struct.pack(f"<{len(checksums)}I", *checksums)
        sections.append((VdexSectionKind.CHECKSUM, checksum_bytes))

    if dex_files is not None:
        dex_sec_data = bytearray()
        for dex in dex_files:
            dex_sec_data.extend(dex)
            padding = (4 - (len(dex_sec_data) % 4)) % 4
            dex_sec_data.extend(b"\x00" * padding)
        sections.append((VdexSectionKind.DEX_FILE, bytes(dex_sec_data)))

    if extra_sections is not None:
        for kind, data in extra_sections.items():
            sections.append((kind, data))

    num_sections = len(sections)
    section_headers_size = num_sections * VdexSectionHeader.STRUCT.size

    buf = bytearray()
    # Write VdexHeader
    buf.extend(struct.pack("<4s4sI", magic, version, num_sections))

    # Reserve section headers space
    sec_header_offset = len(buf)
    buf.extend(b"\x00" * section_headers_size)

    # Append section payloads and update section headers
    for idx, (kind, data) in enumerate(sections):
        sec_offset = len(buf)
        sec_size = len(data)
        buf.extend(data)
        struct.pack_into(
            "<3I",
            buf,
            sec_header_offset + idx * VdexSectionHeader.STRUCT.size,
            kind,
            sec_offset,
            sec_size,
        )

    return bytes(buf)


class TestVdexFile(unittest.TestCase):
    def test_header_and_section_parsing(self) -> None:
        """Verify VdexHeader and VdexSectionHeader parsing and properties."""
        dex_bytes = create_minimal_dex_bytes()
        vdex_bytes = create_test_vdex(dex_files=[dex_bytes], checksums=[0x12345678])

        vdex = VdexFile(vdex_bytes)

        self.assertIsInstance(vdex.header, VdexHeader)
        self.assertEqual(vdex.header.magic, VDEX_FILE_MAGIC)
        self.assertEqual(vdex.header.version, "027")
        self.assertEqual(vdex.header.number_of_sections, 2)

        self.assertTrue(vdex.has_dex_section)
        self.assertEqual(vdex.checksums, (0x12345678,))

        # Directly test VdexHeader and VdexSectionHeader from_buffer
        hdr = VdexHeader.from_buffer(vdex_bytes, 0)
        self.assertEqual(hdr.magic, VDEX_FILE_MAGIC)
        self.assertEqual(hdr.version, "027")

        sec_hdr = VdexSectionHeader.from_buffer(vdex_bytes, VdexHeader.STRUCT.size)
        self.assertEqual(sec_hdr.kind, VdexSectionKind.CHECKSUM)
        self.assertEqual(sec_hdr.size, 4)

    def test_multi_dex_and_indexing(self) -> None:
        """Verify multi-DEX indexing, slicing, and iteration."""
        dex0 = create_minimal_dex_bytes()
        dex1 = create_minimal_dex_bytes()
        dex2 = create_minimal_dex_bytes()

        checksums = [0x11111111, 0x22222222, 0x33333333]
        vdex_bytes = create_test_vdex(dex_files=[dex0, dex1, dex2], checksums=checksums)

        vdex = VdexFile(vdex_bytes)

        self.assertEqual(len(vdex), 3)
        self.assertEqual(vdex.checksums, (0x11111111, 0x22222222, 0x33333333))

        # Test indexing & zero-copy memoryview slices
        slice0 = vdex[0]
        self.assertIsInstance(slice0, memoryview)
        self.assertEqual(bytes(slice0), dex0)

        self.assertEqual(bytes(vdex[1]), dex1)
        self.assertEqual(bytes(vdex[2]), dex2)

        # Test negative indexing
        self.assertEqual(bytes(vdex[-1]), dex2)
        self.assertEqual(bytes(vdex[-3]), dex0)

        # Test iteration over memoryview slices
        slices = list(vdex)
        self.assertEqual(len(slices), 3)
        self.assertEqual(bytes(slices[0]), dex0)

        # Test get_dex_file and iter_dex_files
        dex_file0 = vdex.get_dex_file(0)
        self.assertIsInstance(dex_file0, DexFile)
        self.assertEqual(dex_file0.header.header_size, 112)

        dex_files = list(vdex.iter_dex_files())
        self.assertEqual(len(dex_files), 3)
        self.assertIsInstance(dex_files[1], DexFile)

    def test_section_accessors(self) -> None:
        """Verify get_section and get_section_data accessors."""
        dex_bytes = create_minimal_dex_bytes()
        verifier_data = b"VerifierDependenciesPayload"
        vdex_bytes = create_test_vdex(
            dex_files=[dex_bytes],
            checksums=[0xABCD1234],
            extra_sections={VdexSectionKind.VERIFIER_DEPS: verifier_data},
        )

        vdex = VdexFile(vdex_bytes)

        sec_deps = vdex.get_section(VdexSectionKind.VERIFIER_DEPS)
        self.assertIsNotNone(sec_deps)
        self.assertEqual(sec_deps.kind, VdexSectionKind.VERIFIER_DEPS)

        deps_data = vdex.get_section_data(VdexSectionKind.VERIFIER_DEPS)
        self.assertIsInstance(deps_data, memoryview)
        self.assertEqual(bytes(deps_data), verifier_data)

        # Non-existent section
        self.assertIsNone(vdex.get_section(VdexSectionKind.TYPE_LOOKUP_TABLE))
        self.assertIsNone(vdex.get_section_data(VdexSectionKind.TYPE_LOOKUP_TABLE))

    def test_no_dex_section(self) -> None:
        """Verify behavior when DEX_FILE section is omitted or empty."""
        vdex_bytes = create_test_vdex(extra_sections={VdexSectionKind.VERIFIER_DEPS: b"some data"})

        vdex = VdexFile(vdex_bytes)

        self.assertFalse(vdex.has_dex_section)
        self.assertEqual(len(vdex), 0)
        self.assertEqual(vdex.checksums, ())

        with self.assertRaises(IndexError):
            _ = vdex[0]

    def test_open_mmap_and_context_manager(self) -> None:
        """Verify VdexFile.open() with mmap=True and mmap=False."""
        dex_bytes = create_minimal_dex_bytes()
        vdex_bytes = create_test_vdex(dex_files=[dex_bytes], checksums=[0x99999999])

        with tempfile.NamedTemporaryFile("wb", delete=False) as tf:
            tf.write(vdex_bytes)
            tmp_path = tf.name

        try:
            # mmap=True
            with VdexFile.open(tmp_path, mmap=True) as vdex:
                self.assertEqual(len(vdex), 1)
                self.assertEqual(vdex.checksums, (0x99999999,))
                self.assertEqual(bytes(vdex[0]), dex_bytes)

            # mmap=False
            with VdexFile.open(tmp_path, mmap=False) as vdex:
                self.assertEqual(len(vdex), 1)
                self.assertEqual(vdex.checksums, (0x99999999,))
                self.assertEqual(bytes(vdex[0]), dex_bytes)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_dex_file_interoperability(self) -> None:
        """Verify passing extracted DEX memoryview slice directly to DexFile."""
        dex_bytes = create_minimal_dex_bytes()
        vdex_bytes = create_test_vdex(dex_files=[dex_bytes], checksums=[0x12345678])

        vdex = VdexFile(vdex_bytes)
        dex_view = vdex.get_dex_data(0)

        # Directly pass zero-copy slice to DexFile
        dex_file = DexFile(dex_view)
        self.assertEqual(dex_file.header.magic, b"dex\n035\x00")
        self.assertEqual(dex_file.header.file_size, len(dex_bytes))

    def test_error_handling_and_validations(self) -> None:
        """Verify error handling for invalid/corrupt VDEX files."""
        # Buffer too small for header
        with self.assertRaises(ValueError) as ctx:
            VdexFile(b"vdex")
        self.assertIn("buffer too small", str(ctx.exception))

        # Invalid magic
        bad_magic_bytes = create_test_vdex(magic=b"BAD!")
        with self.assertRaises(ValueError) as ctx:
            VdexFile(bad_magic_bytes)
        self.assertIn("Invalid VDEX file magic", str(ctx.exception))

        # Unsupported version
        bad_ver_bytes = create_test_vdex(version=b"021\x00")
        with self.assertRaises(ValueError) as ctx:
            VdexFile(bad_ver_bytes)
        self.assertIn("Unsupported VDEX format version", str(ctx.exception))

        # Truncated section headers
        buf = bytearray(create_test_vdex(dex_files=[create_minimal_dex_bytes()], checksums=[1]))
        trunc_sec_headers = bytes(buf[: VdexHeader.STRUCT.size + 4])
        with self.assertRaises(ValueError) as ctx:
            VdexFile(trunc_sec_headers)
        self.assertIn("section headers extend past buffer end", str(ctx.exception))

        # Section payload extends past buffer end
        buf = bytearray(create_test_vdex(dex_files=[create_minimal_dex_bytes()], checksums=[1]))
        trunc_sec_payload = bytes(buf[:-10])
        with self.assertRaises(ValueError) as ctx:
            VdexFile(trunc_sec_payload)
        self.assertIn("section payload extends past buffer end", str(ctx.exception))

        # Invalid CHECKSUM section size (not a multiple of 4)
        bad_checksum_sec = create_test_vdex(
            extra_sections={VdexSectionKind.CHECKSUM: b"\x01\x02\x03"},  # 3 bytes
        )
        with self.assertRaises(ValueError) as ctx:
            VdexFile(bad_checksum_sec)
        self.assertIn("not a multiple of 4", str(ctx.exception))

        # Truncated DEX file header in DEX_FILE section
        trunc_dex_sec = create_test_vdex(
            checksums=[1],
            extra_sections={VdexSectionKind.DEX_FILE: b"dex\n035\x00" + b"\x00" * 10},  # <112 bytes
        )
        with self.assertRaises(ValueError) as ctx:
            VdexFile(trunc_dex_sec)
        self.assertIn("truncated DEX header", str(ctx.exception))

        # Invalid DEX file size in DEX_FILE section (<112 bytes)
        small_dex_hdr = bytearray(112)
        small_dex_hdr[:8] = b"dex\n035\x00"
        struct.pack_into("<I", small_dex_hdr, 32, 50)  # file_size = 50 (<112)
        invalid_dex_size_vdex = create_test_vdex(
            checksums=[1],
            extra_sections={VdexSectionKind.DEX_FILE: bytes(small_dex_hdr)},
        )
        with self.assertRaises(ValueError) as ctx:
            VdexFile(invalid_dex_size_vdex)
        self.assertIn("Invalid DEX file size in VDEX", str(ctx.exception))

        # Mismatch between checksum count and DEX file count
        dex0 = create_minimal_dex_bytes()
        mismatch_vdex = create_test_vdex(
            dex_files=[dex0],
            checksums=[1, 2],  # 2 checksums, 1 DEX file
        )
        with self.assertRaises(ValueError) as ctx:
            VdexFile(mismatch_vdex)
        self.assertIn("Mismatch between location checksum count", str(ctx.exception))

        # Out-of-bounds indexing
        valid_vdex = VdexFile(create_test_vdex(dex_files=[dex0], checksums=[1]))
        with self.assertRaises(IndexError):
            _ = valid_vdex[1]
        with self.assertRaises(IndexError):
            _ = valid_vdex[-2]

        # Unknown section kind
        unknown_sec_header = bytearray(VdexSectionHeader.STRUCT.size)
        struct.pack_into("<3I", unknown_sec_header, 0, 999, 0, 0)
        with self.assertRaises(ValueError) as ctx:
            VdexSectionHeader.from_buffer(unknown_sec_header)
        self.assertIn("Unknown VDEX section kind: 999", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
