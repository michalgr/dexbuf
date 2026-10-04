"""Helper utilities and fixtures for integration tests."""

import hashlib
import pathlib
import shutil
import subprocess
import tempfile
import unittest
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any

K9MAIL_23_1_APK_URL = "https://github.com/thunderbird/thunderbird-android/releases/download/K9MAIL_23_1/k9mail-23.1.apk"


def has_dex_compiler() -> bool:
    """Return True if both javac and d8 executables are available in PATH."""
    return shutil.which("javac") is not None and shutil.which("d8") is not None


def skip_unless_dex_compiler() -> Callable[[Any], Any]:
    """Decorator to skip tests unless both javac and d8 are available in PATH."""
    return unittest.skipUnless(has_dex_compiler(), "javac and/or d8 compiler not available in PATH")


def compile_java_to_dex(
    java_source: str, class_name: str = "TestClass", min_api: int | None = 26
) -> bytes:
    """Compile Java source code into raw DEX bytes using javac and d8.

    Raises unittest.SkipTest if javac or d8 are not available in PATH.
    """
    if not has_dex_compiler():
        raise unittest.SkipTest("javac and/or d8 compiler not available in PATH")

    simple_name = class_name.rsplit(".", 1)[-1]
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = pathlib.Path(tmp_dir)
        java_file = tmp_path / f"{simple_name}.java"
        java_file.write_text(java_source, encoding="utf-8")

        classes_dir = tmp_path / "classes"
        classes_dir.mkdir()

        subprocess.run(
            ["javac", "-d", str(classes_dir), str(java_file)],
            check=True,
            capture_output=True,
            text=True,
        )

        class_files = [str(p) for p in classes_dir.rglob("*.class")]
        if not class_files:
            raise RuntimeError("javac failed to produce any .class files")

        d8_dir = tmp_path / "d8_out"
        d8_dir.mkdir()

        d8_cmd = ["d8", "--output", str(d8_dir)]
        if min_api is not None:
            d8_cmd.extend(["--min-api", str(min_api)])
        d8_cmd.extend(class_files)

        subprocess.run(
            d8_cmd,
            check=True,
            capture_output=True,
            text=True,
        )

        dex_file = d8_dir / "classes.dex"
        return dex_file.read_bytes()


K9MAIL_23_1_SHA256 = "27751ffd6cb441918b17f41611b858e45aea9dce2f90eeacee03985614ff12ba"


def _compute_sha256(path: pathlib.Path) -> str:
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def get_k9mail_apk_path() -> pathlib.Path:
    """Return Path to cached K-9 Mail 23.1 APK file, downloading if necessary.

    Raises unittest.SkipTest if the file is not cached and download fails.
    """
    repo_root = pathlib.Path(__file__).resolve().parent.parent
    cache_dir = repo_root / ".cache" / "dexbuf" / "test_data"
    apk_path = cache_dir / "k9mail-23.1.apk"

    if apk_path.exists():
        if _compute_sha256(apk_path) == K9MAIL_23_1_SHA256:
            return apk_path
        try:
            apk_path.unlink()
        except OSError:
            pass

    cache_dir.mkdir(parents=True, exist_ok=True)
    tmp_path = cache_dir / "k9mail-23.1.apk.tmp"

    try:
        req = urllib.request.Request(
            K9MAIL_23_1_APK_URL,
            headers={"User-Agent": "dexbuf-integration-tests"},
        )
        with urllib.request.urlopen(req, timeout=30) as resp, open(tmp_path, "wb") as out:
            while chunk := resp.read(65536):
                out.write(chunk)
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass
        raise unittest.SkipTest(f"Failed to download K-9 Mail APK: {exc}") from exc

    downloaded_sha = _compute_sha256(tmp_path)
    if downloaded_sha != K9MAIL_23_1_SHA256:
        tmp_path.unlink()
        raise unittest.SkipTest(
            f"Downloaded APK SHA-256 mismatch: expected {K9MAIL_23_1_SHA256}, got {downloaded_sha}"
        )

    tmp_path.replace(apk_path)
    return apk_path
