"""Tests for standalone memory-mapping utilities in dexbuf.mmap."""

import tempfile
import unittest
from typing import Any
from unittest.mock import patch

from dexbuf.mmap import open_mmap, scoped_mmap


class TestMmapUtilities(unittest.TestCase):
    def test_open_mmap_normal_operation(self) -> None:
        """Verify open_mmap opens a file, maps it, and returns active mmap object."""
        test_data = b"Hello, dexbuf open_mmap!"
        with tempfile.NamedTemporaryFile("wb", delete=True) as tmp:
            tmp.write(test_data)
            tmp.flush()

            mm = open_mmap(tmp.name)
            try:
                self.assertFalse(mm.closed)
                self.assertEqual(bytes(mm), test_data)
            finally:
                mm.close()

            self.assertTrue(mm.closed)

    def test_open_mmap_fd_closed_immediately(self) -> None:
        """Verify open_mmap closes the underlying OS file descriptor immediately."""
        test_data = b"FD leak test data for open_mmap"
        with tempfile.NamedTemporaryFile("wb", delete=True) as tmp:
            tmp.write(test_data)
            tmp.flush()

            opened_files = []
            real_open = open

            def tracking_open(*args: Any, **kwargs: Any) -> Any:
                f = real_open(*args, **kwargs)
                opened_files.append(f)
                return f

            with patch("builtins.open", side_effect=tracking_open):
                mm = open_mmap(tmp.name)

            self.assertEqual(len(opened_files), 1)
            self.assertTrue(opened_files[0].closed)
            self.assertFalse(mm.closed)

            mm.close()

    def test_scoped_mmap_closes_mapping_on_exit(self) -> None:
        """Verify scoped_mmap context manager closes mapping on normal exit."""
        test_data = b"Scoped mmap normal exit test"
        with tempfile.NamedTemporaryFile("wb", delete=True) as tmp:
            tmp.write(test_data)
            tmp.flush()

            with scoped_mmap(tmp.name) as mm:
                self.assertFalse(mm.closed)
                self.assertEqual(bytes(mm), test_data)

            self.assertTrue(mm.closed)

    def test_scoped_mmap_fd_closed_immediately(self) -> None:
        """Verify scoped_mmap closes the underlying OS file descriptor immediately."""
        test_data = b"FD leak test data for scoped_mmap"
        with tempfile.NamedTemporaryFile("wb", delete=True) as tmp:
            tmp.write(test_data)
            tmp.flush()

            opened_files = []
            real_open = open

            def tracking_open(*args: Any, **kwargs: Any) -> Any:
                f = real_open(*args, **kwargs)
                opened_files.append(f)
                return f

            with patch("builtins.open", side_effect=tracking_open):
                with scoped_mmap(tmp.name) as mm:
                    self.assertEqual(len(opened_files), 1)
                    self.assertTrue(opened_files[0].closed)
                    self.assertFalse(mm.closed)

            self.assertTrue(mm.closed)

    def test_scoped_mmap_handles_exported_slices_gracefully(self) -> None:
        """Verify scoped_mmap safely catches BufferError when exported slices exist on exit."""
        test_data = b"Exported slice lifetime test data"
        with tempfile.NamedTemporaryFile("wb", delete=True) as tmp:
            tmp.write(test_data)
            tmp.flush()

            with scoped_mmap(tmp.name) as mm:
                slice_view = memoryview(mm)[0:14]

            # Context exit caught BufferError because slice_view is alive
            self.assertFalse(mm.closed)
            self.assertEqual(bytes(slice_view), b"Exported slice")

            # Cleaning up slice allows mm to close
            del slice_view
            mm.close()
            self.assertTrue(mm.closed)

    def test_error_propagation_missing_file(self) -> None:
        """Verify FileNotFoundError is raised for non-existent files."""
        non_existent = "non_existent_file_path_987654321.bin"

        with self.assertRaises(FileNotFoundError):
            open_mmap(non_existent)

        with self.assertRaises(FileNotFoundError):
            with scoped_mmap(non_existent):
                pass


if __name__ == "__main__":
    unittest.main()
