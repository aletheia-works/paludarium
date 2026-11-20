"""The coreutils comparison accepts only exact rows from the same binary."""

import contextlib
import copy
import io
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from coreutils import cases, compare_coreutils, environment, fresh_fixture, inputs, stdin_of
from evidence import digest


def row(exit_code, stdout="", stderr="", filesystem=None):
    result = {
        "exit": exit_code,
        "timed_out": False,
        "stdout": stdout,
        "stderr": stderr,
        "wall_seconds": 0.1,
        "stop": f"None\nOk(Exited({exit_code}))",
    }
    if filesystem is not None:
        result["filesystem"] = filesystem
    return result


class CoreutilsTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.guests = pathlib.Path(self.directory.name)
        (self.guests / "coreutils").write_bytes(b"coreutils")
        rows = {
            case["name"]: row(
                index % 3,
                f"out {index}\n",
                filesystem={"app/x": str(index)} if case.get("writes") else None,
            )
            for index, case in enumerate(cases())
        }
        self.native = {
            "coreutils": {"binary_sha256": digest(self.guests / "coreutils"), "rows": rows}
        }

    def tearDown(self):
        self.directory.cleanup()

    def run_with(self, native, change=lambda name, row: row):
        recorded = {}

        def run_case(case):
            expected = self.native["coreutils"]["rows"][case["name"]]
            return change(case["name"], copy.deepcopy(expected))

        with contextlib.redirect_stdout(io.StringIO()):
            compare_coreutils(native, self.guests, run_case, recorded.__setitem__)
        self.assertEqual(list(recorded), list(native["coreutils"]["rows"]))
        return recorded

    def test_exact_rows_pass(self):
        self.run_with(self.native)

    def test_other_bytes_rejected(self):
        native = copy.deepcopy(self.native)
        native["coreutils"]["binary_sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            self.run_with(native)
        with self.assertRaises(ValueError):
            self.run_with({})

    def test_missing_or_reordered_rows_rejected(self):
        native = copy.deepcopy(self.native)
        rows = native["coreutils"]["rows"]
        native["coreutils"]["rows"] = dict(reversed(list(rows.items())))
        with self.assertRaises(ValueError):
            self.run_with(native)
        native["coreutils"]["rows"] = dict(list(rows.items())[1:])
        with self.assertRaises(ValueError):
            self.run_with(native)

    def test_mismatch_rejected_after_every_case_ran(self):
        for field, value in [
            ("exit", 7),
            ("timed_out", True),
            ("stdout", "other\n"),
            ("stderr", "cat: other\n"),
            ("stop", "None\nErr(Timeout)"),
        ]:
            with self.subTest(field=field):
                ran = []

                def change(name, row, field=field, value=value, ran=ran):
                    ran.append(name)
                    return {**row, field: value}

                with self.assertRaises(ValueError):
                    self.run_with(self.native, change)
                self.assertEqual(ran, [case["name"] for case in cases()])

    def test_files_compared_only_after_cases_that_write(self):
        writes = {case["name"] for case in cases() if case.get("writes")}
        self.assertTrue(writes)
        with self.assertRaisesRegex(ValueError, "filesystem mismatch"):
            self.run_with(
                self.native,
                lambda name, row: {**row, "filesystem": {}} if name in writes else row,
            )
        self.run_with(
            self.native,
            lambda name, row: row if name in writes else {**row, "filesystem": {"app/y": "1"}},
        )

    def test_cases_are_unique_and_run_utilities(self):
        names = [case["name"] for case in cases()]
        self.assertEqual(len(names), len(set(names)))
        for case in cases():
            self.assertTrue(case["args"], case["name"])
            self.assertLessEqual(set(case), {"name", "args", "writes", "env", "stdin"})

    def test_fixture_inputs_and_stdin(self):
        with tempfile.TemporaryDirectory() as temporary:
            copy_ = fresh_fixture(pathlib.Path(temporary) / "fixture")
            modes = inputs(copy_)
            self.assertIn("/fruits.txt", modes)
            self.assertIn("/outside/far.txt", modes)
            self.assertEqual(set(modes.values()), {0o644})
            case = next(case for case in cases() if case.get("stdin"))
            self.assertEqual(stdin_of(case, copy_), (copy_ / "app" / case["stdin"]).read_bytes())
            self.assertIsNone(stdin_of({"args": ["true"]}, copy_))
            (copy_ / "app/fruits.txt").chmod(0o600)
            with self.assertRaises(ValueError):
                inputs(copy_)

    def test_case_environment_overrides_the_base(self):
        base = {"TZ": "UTC", "LANG": "C"}
        self.assertEqual(environment(base, {"env": {"TZ": "JST-9"}}), {"TZ": "JST-9", "LANG": "C"})
        self.assertEqual(environment(base, {}), base)


if __name__ == "__main__":
    unittest.main()
