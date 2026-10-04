"""Sanity checks for dexbuf package setup."""

import unittest

import dexbuf


class TestSanity(unittest.TestCase):
    def test_version(self) -> None:
        """Verify package version is exported and non-empty."""
        self.assertTrue(hasattr(dexbuf, "__version__"))
        self.assertTrue(dexbuf.__version__)

    def test_top_level_exports(self) -> None:
        """Verify top-level dexbuf module exports public API symbols cleanly."""
        self.assertIsInstance(dexbuf.__all__, (list, tuple))
        self.assertGreater(len(dexbuf.__all__), 0)

        # Verify all exported symbols in __all__ exist on dexbuf
        for name in dexbuf.__all__:
            self.assertTrue(
                hasattr(dexbuf, name), f"{name} listed in __all__ but missing on dexbuf"
            )

        # Verify core entry points are included in public exports
        core_symbols = {"open", "load", "DexFile", "ClassLoader", "Code"}
        for symbol in core_symbols:
            self.assertIn(symbol, dexbuf.__all__)


if __name__ == "__main__":
    unittest.main()
