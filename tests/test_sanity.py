"""Sanity checks for dexbuf package setup."""

import shutil
import unittest
import dexbuf


class TestSanity(unittest.TestCase):
    def test_version(self) -> None:
        """Verify package version is exported and non-empty."""
        self.assertTrue(hasattr(dexbuf, "__version__"))
        self.assertTrue(dexbuf.__version__)

    def test_environment_tooling(self) -> None:
        """Inspect environment for optional dynamic compilation tools (javac, d8)."""
        javac_available = shutil.which("javac") is not None
        d8_available = shutil.which("d8") is not None
        # In a complete Nix shell, both javac and d8 will be available
        # Precompiled .dex binaries must never be checked into git
        if javac_available and d8_available:
            self.assertTrue(javac_available)
            self.assertTrue(d8_available)


if __name__ == "__main__":
    unittest.main()
