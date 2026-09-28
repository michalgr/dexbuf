"""Helper utilities and fixtures for integration tests."""

import hashlib
import pathlib
import unittest
import urllib.error
import urllib.request

K9MAIL_23_1_APK_URL = "https://github.com/thunderbird/thunderbird-android/releases/download/K9MAIL_23_1/k9mail-23.1.apk"
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
