"""Unit and integration tests for dexbuf.cli CLI tool."""

import io
import os
import tempfile
import unittest
from unittest.mock import patch

from dexbuf.cli import main
from dexbuf.flags import AccessFlags
from tests.builders import build_dex_bytes
from tests.helpers import get_k9mail_apk_path


class TestCLI(unittest.TestCase):
    def setUp(self) -> None:
        self.dex_bytes = build_dex_bytes(
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
        self.temp_file = tempfile.NamedTemporaryFile(suffix=".dex", delete=False)
        self.temp_file.write(self.dex_bytes)
        self.temp_file.close()

    def tearDown(self) -> None:
        if os.path.exists(self.temp_file.name):
            os.remove(self.temp_file.name)

    def test_cli_help(self) -> None:
        stdout_buf = io.StringIO()
        stderr_buf = io.StringIO()
        with (
            patch("sys.stdout", stdout_buf),
            patch("sys.stderr", stderr_buf),
            self.assertRaises(SystemExit) as cm,
        ):
            main(["--help"])
        self.assertEqual(cm.exception.code, 0)
        self.assertIn("Dexdump CLI tool", stdout_buf.getvalue())

    def test_list_classes_default_and_explicit(self) -> None:
        # Default action when no -l or -d is passed
        stdout_buf = io.StringIO()
        stderr_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf), patch("sys.stderr", stderr_buf):
            ret = main([self.temp_file.name])
        self.assertEqual(ret, 0)
        output = stdout_buf.getvalue()
        self.assertIn("com.example.Foo\n", output)
        self.assertIn("com.example.Bar\n", output)

        # Explicit -l flag
        stdout_buf = io.StringIO()
        stderr_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf), patch("sys.stderr", stderr_buf):
            ret = main(["-l", self.temp_file.name])
        self.assertEqual(ret, 0)
        output_explicit = stdout_buf.getvalue()
        self.assertEqual(output_explicit, output)

    def test_disassemble_class_canonical_name_and_descriptor(self) -> None:
        # Canonical name
        stdout_buf = io.StringIO()
        stderr_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf), patch("sys.stderr", stderr_buf):
            ret = main(["-d", "com.example.Foo", self.temp_file.name])
        self.assertEqual(ret, 0)
        out = stdout_buf.getvalue()

        self.assertIn(".class public Lcom/example/Foo;", out)
        self.assertIn(".super Ljava/lang/Object;", out)
        self.assertIn(".implements Ljava/lang/Runnable;", out)
        self.assertIn(".field public static final TAG:Ljava/lang/String;", out)
        self.assertIn(".field private counter:I", out)
        self.assertIn(".method public constructor <init>()V", out)
        self.assertIn("return-void", out)
        self.assertIn("[Block #0]", out)
        self.assertIn(".method public abstract abstractMethod()I", out)

        # Descriptor notation
        stdout_desc = io.StringIO()
        stderr_desc = io.StringIO()
        with patch("sys.stdout", stdout_desc), patch("sys.stderr", stderr_desc):
            ret_desc = main(["--disassemble", "Lcom/example/Foo;", self.temp_file.name])
        self.assertEqual(ret_desc, 0)
        self.assertEqual(stdout_desc.getvalue(), out)

    def test_error_non_existent_file(self) -> None:
        stderr_buf = io.StringIO()
        with patch("sys.stderr", stderr_buf):
            ret = main(["non_existent_file.dex"])
        self.assertEqual(ret, 1)
        self.assertIn("Error opening container", stderr_buf.getvalue())

    def test_error_invalid_binary_format(self) -> None:
        bad_file = tempfile.NamedTemporaryFile(suffix=".dex", delete=False)
        bad_file.write(b"INVALID_HEADER_DATA")
        bad_file.close()

        try:
            stderr_buf = io.StringIO()
            with patch("sys.stderr", stderr_buf):
                ret = main([bad_file.name])
            self.assertEqual(ret, 1)
            self.assertIn("Error opening container", stderr_buf.getvalue())
        finally:
            if os.path.exists(bad_file.name):
                os.remove(bad_file.name)

    def test_error_class_not_found(self) -> None:
        stderr_buf = io.StringIO()
        with patch("sys.stderr", stderr_buf):
            ret = main(["-d", "com.example.MissingClass", self.temp_file.name])
        self.assertEqual(ret, 1)
        self.assertIn("not found in container", stderr_buf.getvalue())

    def test_broken_pipe_error_handling(self) -> None:
        def raise_broken_pipe(*args: str, **kwargs: object) -> None:
            raise BrokenPipeError()

        with (
            patch("sys.stdout.write", side_effect=raise_broken_pipe),
            patch("os.dup2") as mock_dup2,
        ):
            ret = main([self.temp_file.name])
            self.assertEqual(ret, 0)
            mock_dup2.assert_called_once()

        with (
            patch("sys.stdout.write", side_effect=raise_broken_pipe),
            patch("os.dup2") as mock_dup2,
        ):
            ret_dis = main(["-d", "com.example.Foo", self.temp_file.name])
            self.assertEqual(ret_dis, 0)
            mock_dup2.assert_called_once()

        # Test exception inside BrokenPipeError handler (e.g. dup2 fails)
        with (
            patch("sys.stdout.write", side_effect=raise_broken_pipe),
            patch("os.dup2", side_effect=OSError("dup2 failed")),
        ):
            ret_err = main([self.temp_file.name])
            self.assertEqual(ret_err, 0)

    def test_k9mail_apk_integration(self) -> None:
        try:
            apk_path = get_k9mail_apk_path()
        except unittest.SkipTest as exc:
            self.skipTest(str(exc))

        # Test listing classes from K9 Mail APK
        stdout_buf = io.StringIO()
        stderr_buf = io.StringIO()
        with patch("sys.stdout", stdout_buf), patch("sys.stderr", stderr_buf):
            ret = main(["--list", str(apk_path)])
        self.assertEqual(ret, 0)
        classes_output = stdout_buf.getvalue().splitlines()
        self.assertGreater(len(classes_output), 100)

        # Pick a class from output and disassemble it
        sample_class = classes_output[0]
        stdout_dis = io.StringIO()
        stderr_dis = io.StringIO()
        with patch("sys.stdout", stdout_dis), patch("sys.stderr", stderr_dis):
            ret_dis = main(["-d", sample_class, str(apk_path)])
        self.assertEqual(ret_dis, 0)
        dis_output = stdout_dis.getvalue()
        self.assertIn(".class", dis_output)


if __name__ == "__main__":
    unittest.main()
