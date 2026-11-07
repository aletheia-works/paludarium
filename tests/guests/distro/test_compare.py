"""The comparison's own logic, without running any program."""

import contextlib
import io
import json
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import compare


def result(status, stdout=b"", stderr=b""):
    return {"status": status, "stdout": stdout, "stderr": stderr, "seconds": 0.1}


class CompareTest(unittest.TestCase):
    def test_native_command_is_the_case_with_its_directory(self):
        self.assertEqual(
            compare.command(["/bin/ls", "{O}/x"], "/w/o", None, {}), ["/bin/ls", "/w/o/x"]
        )

    def test_emulated_command_mounts_the_root_and_passes_the_environment(self):
        argv = compare.command(["/bin/true"], "/w/o", "/e/paludarium", {"LANG": "C", "TZ": "UTC"})
        self.assertEqual(
            argv,
            [
                "/e/paludarium",
                "--report-enosys",
                "--mount",
                "/:/",
                "--env",
                "LANG=C",
                "--env",
                "TZ=UTC",
                "/bin/true",
            ],
        )

    def test_same_needs_equal_status_and_stdout(self):
        self.assertTrue(compare.outcome("a", result(0, b"x"), result(0, b"x", b"noise"))["same"])
        self.assertFalse(compare.outcome("a", result(0, b"x"), result(1, b"x"))["same"])
        self.assertFalse(compare.outcome("a", result(0, b"x"), result("timeout", b"x"))["same"])
        self.assertFalse(compare.outcome("a", result(0, b"x"), result(0, b"y"))["same"])

    def test_a_timeout_never_matches(self):
        self.assertFalse(compare.outcome("a", result("timeout"), result("timeout"))["same"])

    def test_a_case_failing_natively_never_matches(self):
        self.assertFalse(compare.outcome("a", result(1, b"x"), result(1, b"x"))["same"])

    def test_enosys_lines_are_counted_over_cases(self):
        records = [
            compare.outcome("a", result(0), result(0, stderr=b"paludarium: ENOSYS 444\nok\n")),
            compare.outcome("b", result(0), result(0, stderr=b"paludarium: ENOSYS 444\n")),
        ]
        self.assertEqual(compare.enosys(records), {"paludarium: ENOSYS 444": 2})

    def test_cases_use_their_fixtures(self):
        with tempfile.TemporaryDirectory() as work:
            fx = compare.fixtures(work)
            table = compare.cases(fx)
            self.assertGreaterEqual(len(table), 50)
            for name in ("sort", "gcc", "python3", "make", "bc", "tclsh"):
                files = [part for part in table[name] if fx in part]
                self.assertTrue(files, name)
            self.assertTrue(pathlib.Path(fx, "words").read_text().startswith("0 word0\n"))

    def test_results_are_replaced_whole(self):
        with tempfile.TemporaryDirectory() as output:
            compare.save([{"name": "a"}], output)
            compare.save([{"name": "a"}, {"name": "b"}], output)
            saved = json.loads(pathlib.Path(output, "results.json").read_text())
            self.assertEqual([record["name"] for record in saved], ["a", "b"])
            self.assertEqual(
                sorted(p.name for p in pathlib.Path(output).iterdir()), ["results.json"]
            )

    def test_an_unknown_case_is_an_error(self):
        with (
            tempfile.TemporaryDirectory() as work,
            contextlib.redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit),
        ):
            compare.main(
                ["--emulator", "/bin/true", "--work", work, "--output", work, "no-such-case"]
            )


if __name__ == "__main__":
    unittest.main()
