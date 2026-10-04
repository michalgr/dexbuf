"""Tests for standalone memory-mapping utilities in dexbuf.mmap."""

from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from dexbuf.mmap import open_mmap, scoped_mmap


def test_open_mmap_normal_operation(tmp_path: Path) -> None:
    """Verify open_mmap opens a file, maps it, and returns active mmap object."""
    test_data = b"Hello, dexbuf open_mmap!"
    file_path = tmp_path / "test.bin"
    file_path.write_bytes(test_data)

    mm = open_mmap(file_path)
    try:
        assert not mm.closed
        assert bytes(mm) == test_data
    finally:
        mm.close()

    assert mm.closed


def test_open_mmap_fd_closed_immediately(tmp_path: Path) -> None:
    """Verify open_mmap closes the underlying OS file descriptor immediately."""
    test_data = b"FD leak test data for open_mmap"
    file_path = tmp_path / "test.bin"
    file_path.write_bytes(test_data)

    opened_files = []
    real_open = open

    def tracking_open(*args: Any, **kwargs: Any) -> Any:
        f = real_open(*args, **kwargs)
        opened_files.append(f)
        return f

    with patch("builtins.open", side_effect=tracking_open):
        mm = open_mmap(file_path)

    assert len(opened_files) == 1
    assert opened_files[0].closed
    assert not mm.closed

    mm.close()


def test_scoped_mmap_closes_mapping_on_exit(tmp_path: Path) -> None:
    """Verify scoped_mmap context manager closes mapping on normal exit."""
    test_data = b"Scoped mmap normal exit test"
    file_path = tmp_path / "test.bin"
    file_path.write_bytes(test_data)

    with scoped_mmap(file_path) as mm:
        assert not mm.closed
        assert bytes(mm) == test_data

    assert mm.closed


def test_scoped_mmap_fd_closed_immediately(tmp_path: Path) -> None:
    """Verify scoped_mmap closes the underlying OS file descriptor immediately."""
    test_data = b"FD leak test data for scoped_mmap"
    file_path = tmp_path / "test.bin"
    file_path.write_bytes(test_data)

    opened_files = []
    real_open = open

    def tracking_open(*args: Any, **kwargs: Any) -> Any:
        f = real_open(*args, **kwargs)
        opened_files.append(f)
        return f

    with patch("builtins.open", side_effect=tracking_open):
        with scoped_mmap(file_path) as mm:
            assert len(opened_files) == 1
            assert opened_files[0].closed
            assert not mm.closed

    assert mm.closed


def test_scoped_mmap_handles_exported_slices_gracefully(tmp_path: Path) -> None:
    """Verify scoped_mmap safely catches BufferError when exported slices exist on exit."""
    test_data = b"Exported slice lifetime test data"
    file_path = tmp_path / "test.bin"
    file_path.write_bytes(test_data)

    with scoped_mmap(file_path) as mm:
        slice_view = memoryview(mm)[0:14]

    # Context exit caught BufferError because slice_view is alive
    assert not mm.closed
    assert bytes(slice_view) == b"Exported slice"

    # Cleaning up slice allows mm to close
    del slice_view
    mm.close()
    assert mm.closed


def test_error_propagation_missing_file() -> None:
    """Verify FileNotFoundError is raised for non-existent files."""
    non_existent = "non_existent_file_path_987654321.bin"

    with pytest.raises(FileNotFoundError):
        open_mmap(non_existent)

    with pytest.raises(FileNotFoundError):
        with scoped_mmap(non_existent):
            pass
