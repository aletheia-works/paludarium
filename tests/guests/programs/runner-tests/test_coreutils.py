"""The coreutils comparison accepts only exact rows from the same binary."""

import contextlib
import copy
import io
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import coreutils
from coreutils import (
    cases,
    compare_coreutils,
    environment,
    fixture_files,
    fresh_fixture,
    inputs,
    runner,
    stdin_of,
)
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

    def test_runner_gives_each_case_a_fresh_copy_through_the_host_operation(self):
        calls = []

        def operation(executable, binary, args, directory, env, fixture, mounted, **options):
            # A case that writes changes only its own copy.
            (fixture / "app/fruits.txt").write_text("changed")
            calls.append((executable, binary, args, directory, env, fixture, mounted, options))
            return {"ran": len(calls)}

        scratch = self.guests / "scratch"
        run_case = runner(
            operation, "emulator", self.guests, scratch, self.guests / "ops", {"A": "1"}
        )
        writes = {"name": "w", "args": ["touch", "x"], "writes": True}
        reads = {
            "name": "r",
            "args": ["tr", "a", "b"],
            "stdin": "fruits.txt",
            "env": {"TZ": "JST-9"},
        }
        self.assertEqual(run_case(writes), {"ran": 1})
        self.assertEqual(run_case(reads), {"ran": 2})
        first, second = calls
        self.assertEqual(
            first[:4],
            (
                "emulator",
                self.guests / "coreutils",
                ["touch", "x"],
                self.guests / "ops/coreutils-w",
            ),
        )
        self.assertEqual(first[5], scratch / "coreutils/w")
        self.assertTrue(first[6])
        self.assertTrue((scratch / "coreutils/w/app/tmp").is_dir())
        self.assertTrue((scratch / "coreutils/w/app/home/guest").is_dir())
        self.assertEqual(first[7], {"stdin": None, "inputs": inputs, "program": "/coreutils"})
        self.assertFalse(second[6])
        self.assertEqual(second[4], {"A": "1", "TZ": "JST-9"})
        self.assertFalse((scratch / "coreutils/r/app/tmp").exists())
        # Read before the operation ran, from the case's untouched copy.
        self.assertEqual(second[7]["stdin"], (coreutils.FIXTURE / "app/fruits.txt").read_bytes())

    def test_fixture_files_name_each_file_with_its_guest_path(self):
        copy_ = fresh_fixture(self.guests / "copy")
        listed = fixture_files(copy_)
        self.assertIn(("app/docs/notes.txt", "/docs/notes.txt"), listed)
        self.assertIn(("outside/far.txt", "/outside/far.txt"), listed)
        self.assertEqual([guest for _, guest in listed], list(inputs(copy_)))

    def test_windows_modes_are_the_hosts_0644_for_writable_files(self):
        copy_ = fresh_fixture(self.guests / "copy")
        path = copy_ / "app/fruits.txt"
        with mock.patch.object(coreutils.os, "name", "nt"):
            path.chmod(0o666)
            self.assertEqual(coreutils.mode(path), 0o644)
            path.chmod(0o444)
            with self.assertRaises(ValueError):
                coreutils.mode(path)
        path.chmod(0o666)
        with self.assertRaises(ValueError):
            inputs(copy_)


if __name__ == "__main__":
    unittest.main()
