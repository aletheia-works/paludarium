import pathlib
import stat
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "tests/guests/u13"))
sys.path.insert(1, str(ROOT / "tests/guests/u10"))
import fixture  # noqa: E402
from comparison import compare  # noqa: E402
from host_comparison import comparison_root, validate_stop  # noqa: E402


class Directory:
    def __init__(self, mode):
        self.mode = mode

    def __truediv__(self, _):
        return self

    def stat(self):
        return SimpleNamespace(st_mode=self.mode)


class Boundaries(unittest.TestCase):
    def test_linux_oracle_root_on_windows(self):
        with patch.object(pathlib, "Path", pathlib.PureWindowsPath):
            self.assertEqual(comparison_root("/tmp/native", "list"), "/tmp/native/fixture/app")
            self.assertEqual(comparison_root("/tmp/native", "probe-all"), "/tmp/native")

    def test_linux_root_matches_guest_without_new_mask(self):
        expected = {
            "stdout": "app@1.0.0 /tmp/native/fixture/app\nfiledep 0.0.0\n",
            "stderr": "",
            "exit": 0,
            "timed_out": False,
        }
        actual = dict(expected, stdout="app@1.0.0 /\nfiledep 0.0.0\n")
        compare(expected, actual, comparison_root("/tmp/native", "list"), "/")
        with self.assertRaises(ValueError):
            compare(
                expected, actual, str(pathlib.PureWindowsPath("/tmp/native") / "fixture/app"), "/"
            )

    def test_root_binding_preserves_strict_comparison(self):
        expected = {
            "stdout": "app@1.0.0 /tmp/native/fixture/app\nfiledep 0.0.0\n",
            "stderr": "",
            "exit": 0,
            "timed_out": False,
        }
        for text in ["app@1.0.0 /\nfiledep 1.0.0\n", "app@1.0.0 /different\nfiledep 0.0.0\n"]:
            with self.assertRaises(ValueError):
                compare(
                    expected,
                    dict(expected, stdout=text),
                    comparison_root("/tmp/native", "list"),
                    "/",
                )

    def test_guest_stop_success(self):
        validate_stop(
            {"wall_seconds": 30, "exit": 0, "timed_out": False, "stop": "None\nOk(Exited(0))"}
        )

    def test_guest_stop_failure(self):
        for field, value in [
            ("exit", 1),
            ("exit", False),
            ("timed_out", True),
            ("stop", "trap"),
            ("wall_seconds", True),
            ("wall_seconds", -1),
            ("wall_seconds", 31),
            ("wall_seconds", float("inf")),
            ("wall_seconds", float("nan")),
        ]:
            row = {"wall_seconds": 1, "exit": 0, "timed_out": False, "stop": "None\nOk(Exited(0))"}
            row[field] = value
            with self.assertRaises(ValueError):
                validate_stop(row)

    def test_fixture_unix_exact(self):
        with patch.object(fixture.os, "name", "posix"):
            self.assertEqual(
                set(fixture.fixture_inputs(Directory(stat.S_IFREG | 0o644)).values()), {0o644}
            )

    def test_fixture_unix_wrong_mode(self):
        with patch.object(fixture.os, "name", "posix"), self.assertRaises(ValueError):
            fixture.fixture_inputs(Directory(stat.S_IFREG | 0o755))

    def test_fixture_windows_writable_guest_mode(self):
        with patch.object(fixture.os, "name", "nt"):
            self.assertEqual(
                set(fixture.fixture_inputs(Directory(stat.S_IFREG | 0o666)).values()), {0o644}
            )

    def test_fixture_windows_readonly(self):
        with patch.object(fixture.os, "name", "nt"), self.assertRaises(ValueError):
            fixture.fixture_inputs(Directory(stat.S_IFREG | 0o444))

    def test_fixture_nonregular(self):
        with self.assertRaises(ValueError):
            fixture.fixture_inputs(Directory(stat.S_IFDIR | 0o755))
