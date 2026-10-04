"""Comprehensive negative and malformed DEX tests."""

import io
import struct
import zipfile

import pytest

import dexbuf
from dexbuf import ClassLoader, DexFile, ZipArchive, load
from dexbuf.cursor import Cursor
from dexbuf.items import ClassDataItem, CodeItem, StringIdItem
from tests.builders import build_dex_bytes, create_minimal_dex_bytes


class TestMalformedDexHeader:
    """Test malformed, truncated, and corrupted DEX headers."""

    def test_empty_and_sub_header_buffers(self) -> None:
        """Buffers smaller than 112 bytes raise ValueError on DexFile and dexbuf.load."""
        short_buffers = [b"", b"short", b"dex\n035\x00", b"\x00" * 111]
        for buf in short_buffers:
            with pytest.raises(ValueError):
                DexFile(buf)
            with pytest.raises(ValueError):
                load(buf)

    def test_invalid_magic_and_unsupported_version(self) -> None:
        """Invalid magic or version strings raise ValueError when verify=True."""
        minimal = create_minimal_dex_bytes()

        # Invalid magic
        bad_magic = bytearray(minimal)
        bad_magic[0:8] = b"badmagic"
        with pytest.raises(ValueError, match="Invalid DEX magic"):
            DexFile(bytes(bad_magic), verify=True)

        # Unsupported version
        bad_version = bytearray(minimal)
        bad_version[0:8] = b"dex\n999\x00"
        with pytest.raises(ValueError, match="Unsupported DEX version"):
            DexFile(bytes(bad_version), verify=True)

    def test_invalid_and_reverse_endian_tags(self) -> None:
        """Invalid or reverse endian tags raise ValueError when verify=True."""
        minimal = create_minimal_dex_bytes()

        # Reverse-endian tag
        rev_endian = bytearray(minimal)
        struct.pack_into("<I", rev_endian, 0x28, 0x78563412)
        with pytest.raises(ValueError, match="Reverse-endian DEX files are not supported"):
            DexFile(bytes(rev_endian), verify=True)

        # Invalid endian tag
        inv_endian = bytearray(minimal)
        struct.pack_into("<I", inv_endian, 0x28, 0x12341234)
        with pytest.raises(ValueError, match="Invalid DEX endian tag"):
            DexFile(bytes(inv_endian), verify=True)

    def test_file_size_mismatch(self) -> None:
        """Header file_size mismatch raises ValueError when verify=True."""
        minimal = create_minimal_dex_bytes()
        mismatch = bytearray(minimal)
        struct.pack_into("<I", mismatch, 0x20, len(minimal) + 100)
        with pytest.raises(ValueError, match="File size mismatch"):
            DexFile(bytes(mismatch), verify=True)

    def test_checksum_and_signature_corruption(self) -> None:
        """Adler32 checksum and SHA-1 signature corruption properly invalidate verification."""
        valid_dex = build_dex_bytes([{"name": "Lcom/example/Foo;", "super": "Ljava/lang/Object;"}])
        dex = DexFile(valid_dex)
        assert dex.verify_checksum() is True
        assert dex.verify_signature() is True

        # Corrupt signature byte (offset 20)
        corrupt_sig = bytearray(valid_dex)
        corrupt_sig[20] ^= 0xFF
        corrupt_dex_sig = DexFile(bytes(corrupt_sig), verify=False)
        assert corrupt_dex_sig.verify_checksum() is False
        assert corrupt_dex_sig.verify_signature() is False

        # Corrupt checksum byte (offset 8)
        corrupt_chk = bytearray(valid_dex)
        corrupt_chk[8] ^= 0xFF
        corrupt_dex_chk = DexFile(bytes(corrupt_chk), verify=False)
        assert corrupt_dex_chk.verify_checksum() is False
        assert corrupt_dex_chk.verify_signature() is True


class TestOutOfBoundsOffsets:
    """Test out-of-bounds section and item offsets."""

    def test_section_offsets_beyond_buffer_size(self) -> None:
        """Offsets beyond buffer raise ValueError, IndexError, or EOFError when accessed."""
        valid_dex = build_dex_bytes([{"name": "Lcom/example/Foo;", "super": "Ljava/lang/Object;"}])

        # string_ids_off out of bounds
        b_str = bytearray(valid_dex)
        struct.pack_into("<I", b_str, 0x3C, 99999)
        d_str = DexFile(bytes(b_str), verify=False)
        with pytest.raises((ValueError, IndexError, EOFError)):
            _ = d_str.string_ids[0]

        # type_ids_off out of bounds
        b_type = bytearray(valid_dex)
        struct.pack_into("<I", b_type, 0x44, 99999)
        d_type = DexFile(bytes(b_type), verify=False)
        with pytest.raises((ValueError, IndexError, EOFError)):
            _ = d_type.type_ids[0]

        # class_defs_off out of bounds
        b_cls = bytearray(valid_dex)
        struct.pack_into("<I", b_cls, 0x64, 99999)
        d_cls = DexFile(bytes(b_cls), verify=False)
        with pytest.raises((ValueError, IndexError, EOFError)):
            _ = d_cls.class_defs[0]

        # data_off out of bounds
        b_data = bytearray(valid_dex)
        struct.pack_into("<I", b_data, 0x6C, 99999)
        d_data = DexFile(bytes(b_data), verify=False)
        assert d_data.header.data_off == 99999

    def test_string_data_off_beyond_buffer_size(self) -> None:
        """StringIdItem with string_data_off beyond buffer size raises on string dereference."""
        valid_dex = build_dex_bytes([{"name": "Lcom/example/Foo;", "super": "Ljava/lang/Object;"}])
        str_ids_off = struct.unpack_from("<I", valid_dex, 0x3C)[0]

        b = bytearray(valid_dex)
        struct.pack_into("<I", b, str_ids_off, 99999)  # Corrupt first StringIdItem
        d = DexFile(bytes(b), verify=False)

        with pytest.raises((ValueError, IndexError, EOFError)):
            _ = d.get_string(dexbuf.Idx[StringIdItem](0))

    def test_class_data_off_beyond_buffer_size(self) -> None:
        """ClassDefItem with class_data_off beyond buffer size raises on data dereference."""
        valid_dex = build_dex_bytes([{"name": "Lcom/example/Foo;", "super": "Ljava/lang/Object;"}])
        class_defs_off = struct.unpack_from("<I", valid_dex, 0x64)[0]

        b = bytearray(valid_dex)
        # ClassDefItem field offset for class_data_off is +24
        struct.pack_into("<I", b, class_defs_off + 24, 99999)
        d = DexFile(bytes(b), verify=False)

        with pytest.raises((ValueError, IndexError, EOFError)):
            cdef = d.class_defs[0]
            _ = d.get_class_data(cdef.class_data_off)


class TestCorruptClassDataAndCode:
    """Test corrupt LEB128 streams, class data, and bytecode instructions."""

    def test_truncated_uleb128_streams(self) -> None:
        """Truncated ULEB128 streams raise EOFError or ValueError."""
        # Unclosed ULEB128 sequence (high bit set without final byte)
        cursor = Cursor(b"\x80\x80\x80")
        with pytest.raises((EOFError, ValueError)):
            cursor.read_uleb128()

        # ClassDataItem parsing on truncated buffer
        with pytest.raises((EOFError, ValueError)):
            ClassDataItem.from_buffer(b"\x80\x80")

    def test_code_item_extending_beyond_file_size(self) -> None:
        """CodeItem with insns_size extending beyond file size raises EOFError or ValueError."""
        # CodeItem header layout:
        # registers_size, ins_size, outs_size, tries_size, debug_info_off, insns_size
        header = struct.pack("<4H2I", 2, 0, 0, 0, 0, 10000) + b"\x00" * 4
        with pytest.raises((EOFError, ValueError)):
            CodeItem.from_buffer(header)


class TestContainerErrorHandling:
    """Test error handling in load, ZipArchive, and ClassLoader."""

    def test_arbitrary_binary_garbage_load(self) -> None:
        """Arbitrary binary garbage passed to dexbuf.load() raises ValueError."""
        garbage_inputs = [
            b"SOME_GARBAGE_BINARY_DATA_12345",
            b"\xff\xfe\xfd\xfc\xfb\xfa\xf9\xf8",
            b"INVALID_MAGIC_DATA",
        ]
        for buf in garbage_inputs:
            with pytest.raises(ValueError, match="Unrecognized binary format"):
                load(buf)

    def test_zip_without_dex_files_load(self) -> None:
        """Valid ZIP archive without any .dex files passed to dexbuf.load() raises ValueError."""
        mem_zip = io.BytesIO()
        with zipfile.ZipFile(mem_zip, "w") as zf:
            zf.writestr("hello.txt", "world")
        zip_bytes = mem_zip.getvalue()

        with pytest.raises(ValueError, match=r"ZIP archive contains no \.dex files"):
            load(zip_bytes)

    def test_corrupt_zip_magic_or_truncated_central_directory(self) -> None:
        """Corrupt ZIP magic or truncated central directory raises ValueError."""
        corrupt_zips = [
            b"PK_NOT_A_VALID_ZIP_ARCHIVE",
            b"PK\x03\x04" + b"\x00" * 10,
            b"PK\x05\x06" + b"\x00" * 5,
        ]
        for buf in corrupt_zips:
            with pytest.raises(ValueError):
                ZipArchive(buf)

    def test_missing_class_lookups_in_class_loader(self) -> None:
        """Missing class lookups in ClassLoader raise KeyError on [] and return None on get()."""
        loader = ClassLoader()

        with pytest.raises(KeyError):
            _ = loader["NonExistent"]

        with pytest.raises(KeyError):
            _ = loader["Lcom/example/NonExistent;"]

        assert loader.get("NonExistent") is None
        assert loader.get("Lcom/example/NonExistent;") is None
