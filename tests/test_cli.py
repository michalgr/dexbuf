"""Unit and integration tests for dexbuf.cli CLI tool."""

import unittest
from pathlib import Path
from unittest.mock import patch

import pytest

from dexbuf.cli import main
from dexbuf.flags import AccessFlags
from tests.builders import build_dex_bytes
from tests.helpers import get_k9mail_apk_path


@pytest.fixture
def sample_dex_path(tmp_path: Path) -> Path:
    dex_bytes = build_dex_bytes(
        [
            {
                "name": "Lcom/example/Foo;",
                "super": "Ljava/lang/Object;",
                "interfaces": ["Ljava/lang/Runnable;"],
                "access_flags": int(AccessFlags.PUBLIC),
                "static_fields": [
                    {
                        "name": "TAG",
                        "type": "Ljava/lang/String;",
                        "access_flags": int(
                            AccessFlags.PUBLIC | AccessFlags.STATIC | AccessFlags.FINAL
                        ),
                    }
                ],
                "instance_fields": [
                    {
                        "name": "counter",
                        "type": "I",
                        "access_flags": int(AccessFlags.PRIVATE),
                    }
                ],
                "direct_methods": [
                    {
                        "name": "<init>",
                        "return_type": "V",
                        "params": [],
                        "access_flags": int(AccessFlags.PUBLIC | AccessFlags.CONSTRUCTOR),
                        "code": b"\x0e\x00",  # return-void
                    }
                ],
                "virtual_methods": [
                    {
                        "name": "run",
                        "return_type": "V",
                        "params": [],
                        "access_flags": int(AccessFlags.PUBLIC),
                        "code": b"\x0e\x00",  # return-void
                    },
                    {
                        "name": "abstractMethod",
                        "return_type": "I",
                        "params": [],
                        "access_flags": int(AccessFlags.PUBLIC | AccessFlags.ABSTRACT),
                    },
                ],
            },
            {
                "name": "Lcom/example/Bar;",
                "super": "Ljava/lang/Object;",
                "access_flags": int(AccessFlags.PUBLIC),
            },
        ]
    )
    dex_file = tmp_path / "sample.dex"
    dex_file.write_bytes(dex_bytes)
    return dex_file


def test_cli_help(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["--help"])
    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert "Dexdump CLI tool" in captured.out


def test_list_classes_default_and_explicit(
    sample_dex_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Default action when no -l or -d is passed
    ret = main([str(sample_dex_path)])
    assert ret == 0
    captured = capsys.readouterr()
    assert "com.example.Foo\n" in captured.out
    assert "com.example.Bar\n" in captured.out

    # Explicit -l flag
    ret = main(["-l", str(sample_dex_path)])
    assert ret == 0
    captured_explicit = capsys.readouterr()
    assert captured_explicit.out == captured.out


def test_disassemble_class_canonical_name_and_descriptor(
    sample_dex_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Canonical name
    ret = main(["-d", "com.example.Foo", str(sample_dex_path)])
    assert ret == 0
    captured = capsys.readouterr()
    out = captured.out

    assert ".class public Lcom/example/Foo;" in out
    assert ".super Ljava/lang/Object;" in out
    assert ".implements Ljava/lang/Runnable;" in out
    assert ".field public static final TAG:Ljava/lang/String;" in out
    assert ".field private counter:I" in out
    assert ".method public constructor <init>()V" in out
    assert "return-void" in out
    assert "[Block #0]" in out
    assert ".method public abstract abstractMethod()I" in out

    # Descriptor notation
    ret_desc = main(["--disassemble", "Lcom/example/Foo;", str(sample_dex_path)])
    assert ret_desc == 0
    captured_desc = capsys.readouterr()
    assert captured_desc.out == out


def test_error_non_existent_file(capsys: pytest.CaptureFixture[str]) -> None:
    ret = main(["non_existent_file.dex"])
    assert ret == 1
    captured = capsys.readouterr()
    assert "Error opening container" in captured.err


def test_error_invalid_binary_format(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    bad_file = tmp_path / "bad.dex"
    bad_file.write_bytes(b"INVALID_HEADER_DATA")

    ret = main([str(bad_file)])
    assert ret == 1
    captured = capsys.readouterr()
    assert "Error opening container" in captured.err


def test_error_class_not_found(sample_dex_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    ret = main(["-d", "com.example.MissingClass", str(sample_dex_path)])
    assert ret == 1
    captured = capsys.readouterr()
    assert "not found in container" in captured.err


def test_broken_pipe_error_handling(sample_dex_path: Path) -> None:
    def raise_broken_pipe(*args: str, **kwargs: object) -> None:
        raise BrokenPipeError()

    dex_str = str(sample_dex_path)

    with (
        patch("sys.stdout.write", side_effect=raise_broken_pipe),
        patch("os.dup2") as mock_dup2,
    ):
        ret = main([dex_str])
        assert ret == 0
        mock_dup2.assert_called_once()

    with (
        patch("sys.stdout.write", side_effect=raise_broken_pipe),
        patch("os.dup2") as mock_dup2,
    ):
        ret_dis = main(["-d", "com.example.Foo", dex_str])
        assert ret_dis == 0
        mock_dup2.assert_called_once()

    # Test exception inside BrokenPipeError handler (e.g. dup2 fails)
    with (
        patch("sys.stdout.write", side_effect=raise_broken_pipe),
        patch("os.dup2", side_effect=OSError("dup2 failed")),
    ):
        ret_err = main([dex_str])
        assert ret_err == 0


def test_k9mail_apk_integration(capsys: pytest.CaptureFixture[str]) -> None:
    try:
        apk_path = get_k9mail_apk_path()
    except unittest.SkipTest as exc:
        pytest.skip(str(exc))

    # Test listing classes from K9 Mail APK
    ret = main(["--list", str(apk_path)])
    assert ret == 0
    captured = capsys.readouterr()
    classes_output = captured.out.splitlines()
    assert len(classes_output) > 100

    # Pick a class from output and disassemble it
    sample_class = classes_output[0]
    ret_dis = main(["-d", sample_class, str(apk_path)])
    assert ret_dis == 0
    captured_dis = capsys.readouterr()
    dis_output = captured_dis.out
    assert ".class" in dis_output
