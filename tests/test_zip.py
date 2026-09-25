"""Tests for stateless zero-copy ZipArchive reader and ZIP specification dataclasses."""

import io
import tempfile
import unittest
import zipfile
from typing import Any

from dexbuf import open_mmap, scoped_mmap
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
from dexbuf.zip import (
    CentralDirectoryHeader,
    EndOfCentralDirectoryRecord,
    LocalFileHeader,
    ZipArchive,
)


def create_test_zip(entries: list[tuple[str, bytes, int]], comment: bytes = b"") -> bytes:
    """Helper to create a ZIP file buffer with specified entries and EOCD comment.

    entries is a list of (filename, data, compress_type) tuples.
    compress_type should be zipfile.ZIP_STORED or zipfile.ZIP_DEFLATED.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.comment = comment
        for filename, data, compress_type in entries:
            zf.writestr(filename, data, compress_type=compress_type)
    return buf.getvalue()


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


class TestZipArchive(unittest.TestCase):
    def test_eocd_record_and_lazy_initialization(self) -> None:
        """Verify __init__ locates EOCD record and does not create _entries dict."""
        zip_bytes = create_test_zip(
            [("hello.txt", b"Hello World!", zipfile.ZIP_STORED)],
            comment=b"Archive Comment",
        )
        archive = ZipArchive(zip_bytes)

        # Ensure no _entries cache dictionary was created
        self.assertFalse(hasattr(archive, "_entries"))

        # Verify EOCD record values
        self.assertIsInstance(archive.eocd, EndOfCentralDirectoryRecord)
        self.assertEqual(archive.eocd.total_entries, 1)
        self.assertEqual(archive.eocd.comment, "Archive Comment")
        self.assertEqual(len(archive), 1)

    def test_streaming_central_directory(self) -> None:
        """Verify Central Directory streaming traversal methods."""
        entries_data = [
            ("file1.txt", b"Data 1", zipfile.ZIP_STORED),
            ("file2.txt", b"Data 2 compressed payload", zipfile.ZIP_DEFLATED),
            ("folder/file3.txt", b"Data 3", zipfile.ZIP_STORED),
        ]
        zip_bytes = create_test_zip(entries_data)
        archive = ZipArchive(zip_bytes)

        # iter_entries returns iterator
        entries_iter = archive.iter_entries()
        first_entry = next(entries_iter)
        self.assertIsInstance(first_entry, CentralDirectoryHeader)
        self.assertEqual(first_entry.filename, "file1.txt")

        # infolist and namelist
        headers = archive.infolist()
        self.assertEqual(len(headers), 3)
        self.assertEqual(archive.namelist(), ["file1.txt", "file2.txt", "folder/file3.txt"])

        # __iter__ and __len__
        self.assertEqual(list(archive), ["file1.txt", "file2.txt", "folder/file3.txt"])
        self.assertEqual(len(archive), 3)

        # getinfo and __contains__
        self.assertTrue("file2.txt" in archive)
        self.assertFalse("nonexistent.txt" in archive)
        self.assertFalse(123 in archive)  # Non-string check

        cd2 = archive.getinfo("file2.txt")
        self.assertEqual(cd2.filename, "file2.txt")

    def test_zero_copy_stored_and_deflated_read(self) -> None:
        """Verify zero-copy memoryview slice for STORED entries and decompression for DEFLATED."""
        stored_payload = b"Uncompressed STORED entry payload"
        deflated_payload = b"DEFLATED compressed entry payload " * 20

        zip_bytes = create_test_zip(
            [
                ("stored.bin", stored_payload, zipfile.ZIP_STORED),
                ("deflated.bin", deflated_payload, zipfile.ZIP_DEFLATED),
            ]
        )
        archive = ZipArchive(zip_bytes)

        # STORED entry read -> zero-copy memoryview
        self.assertTrue(archive.is_stored("stored.bin"))
        stored_res = archive.read("stored.bin")
        self.assertIsInstance(stored_res, memoryview)
        self.assertEqual(bytes(stored_res), stored_payload)

        # __getitem__ shortcut with string name
        self.assertEqual(bytes(archive["stored.bin"]), stored_payload)

        # STORED entry read with CentralDirectoryHeader
        cd_stored = archive.getinfo("stored.bin")
        stored_res_hdr = archive.read(cd_stored)
        self.assertIsInstance(stored_res_hdr, memoryview)
        self.assertEqual(bytes(stored_res_hdr), stored_payload)

        # DEFLATED entry read -> bytes
        self.assertFalse(archive.is_stored("deflated.bin"))
        deflated_res = archive.read("deflated.bin")
        self.assertIsInstance(deflated_res, bytes)
        self.assertEqual(deflated_res, deflated_payload)

    def test_local_file_header_properties(self) -> None:
        """Verify LocalFileHeader parsing, header_size, and data_offset."""
        zip_bytes = create_test_zip([("test.txt", b"ABC", zipfile.ZIP_STORED)])
        archive = ZipArchive(zip_bytes)
        cd_header = archive.getinfo("test.txt")

        local_header = LocalFileHeader.from_buffer(archive._buffer, cd_header.local_header_offset)
        self.assertEqual(local_header.filename, "test.txt")
        self.assertEqual(local_header.header_size, 30 + len("test.txt"))
        self.assertEqual(
            local_header.data_offset(cd_header.local_header_offset),
            cd_header.local_header_offset + local_header.header_size,
        )

    def test_error_handling(self) -> None:
        """Verify KeyError for missing item and ValueError for invalid ZIP or unsupported method."""
        zip_bytes = create_test_zip([("a.txt", b"A", zipfile.ZIP_STORED)])
        archive = ZipArchive(zip_bytes)

        # Missing entry
        with self.assertRaises(KeyError) as ctx:
            archive.getinfo("b.txt")
        self.assertIn("b.txt", str(ctx.exception))

        with self.assertRaises(KeyError):
            archive.read("b.txt")

        # Invalid ZIP files
        with self.assertRaises(ValueError):
            ZipArchive(b"too small")

        with self.assertRaises(ValueError):
            ZipArchive(b"A" * 100)  # Valid length but missing EOCD signature

        # Mock header with unsupported compression method
        unsupported_cd = CentralDirectoryHeader(
            version_made_by=20,
            version_needed=20,
            flag_bits=0,
            compress_type=99,  # Unsupported
            last_mod_time=0,
            last_mod_date=0,
            crc32=0,
            compress_size=1,
            file_size=1,
            disk_num_start=0,
            internal_attr=0,
            external_attr=0,
            local_header_offset=0,
            filename="a.txt",
            extra=b"",
            comment="",
        )
        with self.assertRaises(ValueError) as ctx:
            archive.read(unsupported_cd)
        self.assertIn("Unsupported compression method 99", str(ctx.exception))

    def test_zip_with_scoped_and_open_mmap(self) -> None:
        """Verify initializing ZipArchive with scoped_mmap, open_mmap, and bytes."""
        zip_bytes = create_test_zip([("file.txt", b"Content", zipfile.ZIP_STORED)])

        with tempfile.NamedTemporaryFile("wb", delete=False) as tf:
            tf.write(zip_bytes)
            tmp_path = tf.name

        try:
            # scoped_mmap
            with scoped_mmap(tmp_path) as mm:
                archive = ZipArchive(mm)
                self.assertEqual(archive.namelist(), ["file.txt"])
                self.assertEqual(bytes(archive["file.txt"]), b"Content")

            # open_mmap
            mm = open_mmap(tmp_path)
            archive = ZipArchive(mm)
            self.assertEqual(archive.namelist(), ["file.txt"])
            self.assertEqual(bytes(archive["file.txt"]), b"Content")
            del archive
            mm.close()
            self.assertTrue(mm.closed)

            # bytes
            archive_b = ZipArchive(zip_bytes)
            self.assertEqual(archive_b.namelist(), ["file.txt"])
            self.assertEqual(bytes(archive_b["file.txt"]), b"Content")
        finally:
            import os

            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_dex_file_interoperability(self) -> None:
        """Verify feeding extracted zero-copy .dex memoryview directly into DexFile."""
        dex_bytes = create_minimal_dex_bytes()
        zip_bytes = create_test_zip([("classes.dex", dex_bytes, zipfile.ZIP_STORED)])

        archive = ZipArchive(zip_bytes)
        dex_view = archive.read("classes.dex")

        # Ensure dex_view is a zero-copy memoryview
        self.assertIsInstance(dex_view, memoryview)

        # Pass directly into DexFile
        dex_file = DexFile(dex_view)
        self.assertEqual(dex_file.header.magic, DEX_FILE_MAGIC)
        self.assertEqual(dex_file.header.header_size, HeaderItem.STRUCT.size)


if __name__ == "__main__":
    unittest.main()
