"""The shared ripgrep comparison accepts only exact rows from the same binary."""

import contextlib
import copy
import io
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from evidence import digest
from ripgrep import cases, compare_ripgrep


def row(exit_code, stdout="", stderr=""):
    return {
        "exit": exit_code,
        "timed_out": False,
        "stdout": stdout,
        "stderr": stderr,
        "wall_seconds": 0.1,
        "stop": f"None\nOk(Exited({exit_code}))",
    }


class RipgrepTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.guests = pathlib.Path(self.directory.name)
        (self.guests / "ripgrep").write_bytes(b"rg")
        rows = {
            case["name"]: row(index % 3, f"out {index}\n") for index, case in enumerate(cases())
        }
        self.native = {"ripgrep": {"binary_sha256": digest(self.guests / "ripgrep"), "rows": rows}}

    def tearDown(self):
        self.directory.cleanup()

    def run_with(self, native, change=lambda name, row: row):
        recorded = {}

        def run_case(case):
            return change(case["name"], copy.deepcopy(self.native["ripgrep"]["rows"][case["name"]]))

        with contextlib.redirect_stdout(io.StringIO()):
            compare_ripgrep(native, self.guests, run_case, recorded.__setitem__)
        self.assertEqual(list(recorded), list(native["ripgrep"]["rows"]))
        return recorded

    def test_exact_rows_pass(self):
        self.run_with(self.native)

    def test_other_bytes_rejected(self):
        native = copy.deepcopy(self.native)
        native["ripgrep"]["binary_sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            self.run_with(native)
        with self.assertRaises(ValueError):
            self.run_with({})

    def test_missing_or_reordered_rows_rejected(self):
        native = copy.deepcopy(self.native)
        rows = native["ripgrep"]["rows"]
        native["ripgrep"]["rows"] = dict(reversed(list(rows.items())))
        with self.assertRaises(ValueError):
            self.run_with(native)
        native["ripgrep"]["rows"] = dict(list(rows.items())[1:])
        with self.assertRaises(ValueError):
            self.run_with(native)

    def test_mismatch_rejected(self):
        for field, value in [
            ("exit", 7),
            ("timed_out", True),
            ("stdout", "other\n"),
            ("stderr", "rg: other\n"),
            ("stop", "None\nErr(Timeout)"),
        ]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.run_with(
                    self.native, lambda name, row, field=field, value=value: {**row, field: value}
                )


if __name__ == "__main__":
    unittest.main()
