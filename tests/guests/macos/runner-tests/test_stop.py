import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "tests/guests/macos"))
sys.path.insert(1, str(ROOT / "tests/guests/programs"))
from host_comparison import validate_stop  # noqa: E402


class StopTests(unittest.TestCase):
    def row(self):
        return {"wall_seconds": 0.1, "exit": 0, "timed_out": False, "stop": "None\nOk(Exited(0))"}

    def test_exact_normal_exit(self):
        validate_stop(self.row())

    def test_bad_stop(self):
        for stop in (
            "None\nOk(Exited(1))",
            "None\nOk(Signaled(9))",
            "Some(Timeout)\nOk(Exited(0))",
            "None\nOk(Exited(0))\nextra",
            "",
        ):
            row = self.row()
            row["stop"] = stop
            with self.assertRaises(ValueError):
                validate_stop(row)

    def test_timeout_exit_and_duration(self):
        for key, value in (
            ("timed_out", True),
            ("exit", 1),
            ("exit", False),
            ("wall_seconds", 30.01),
            ("wall_seconds", -1),
            ("wall_seconds", float("nan")),
        ):
            row = self.row()
            row[key] = value
            with self.assertRaises(ValueError):
                validate_stop(row)
