import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("u9_producer", ROOT / "scripts/coverage-evidence.py")
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)


def result(passed, ignored=0, filtered=0):
    return f"test result: ok. {passed} passed; 0 failed; {ignored} ignored; 0 measured; {filtered} filtered out; finished in 0.01s\n"


def suite(passed, ignored=0):
    return (
        f" Running tests/diff_terminal.rs (target/x)\nrunning {passed + ignored} tests\n"
        + result(passed, ignored)
    )


class Evidence(unittest.TestCase):
    def capture(self):
        tmp = tempfile.TemporaryDirectory(dir=ROOT / "target", prefix="u9-capture-")
        self.addCleanup(tmp.cleanup)
        return P.Capture(Path(tmp.name) / "fresh")

    def test_diff_counts(self):
        self.assertEqual(P.diff_counts(suite(7)), (7, 0))

    def test_zero_diff(self):
        with self.assertRaises(ValueError):
            P.diff_counts(suite(0))

    def test_ignored_diff(self):
        with self.assertRaises(ValueError):
            P.diff_counts(suite(7, 1))

    def test_other_suite_not_diff(self):
        with self.assertRaises(ValueError):
            P.diff_counts(
                " Running unittests lib.rs (x)\ntest result: ok. 70 passed; 0 failed; 0 ignored;"
            )

    def test_separate_stream_concatenation_reproduces_missing_result(self):
        stdout = b"test result: ok. 70 passed; 0 failed; 0 ignored;\ntest result: ok. 7 passed; 0 failed; 0 ignored;\n"
        stderr = b" Running unittests lib.rs (x)\n Running tests/diff_terminal.rs (x)\n"
        with self.assertRaisesRegex(ValueError, "diff_terminal result absent/ambiguous"):
            P.diff_counts((stdout + stderr).decode())

    def test_merged_stream_preserves_suite_identity(self):
        merged = (
            " Running unittests lib.rs (x)\nrunning 70 tests\n"
            + result(70)
            + suite(7)
            + " Running tests/command.rs (x)\nrunning 8 tests\n"
            + result(8)
        ).encode()
        c = self.capture()
        with patch.object(
            P.subprocess, "run", return_value=subprocess.CompletedProcess(["tool"], 0, merged, None)
        ) as run:
            out, err, row = c.run("merged", ["tool"], merge=True)
        self.assertEqual(run.call_args.kwargs["stdout"], subprocess.PIPE)
        self.assertEqual(run.call_args.kwargs["stderr"], subprocess.STDOUT)
        self.assertNotIn("capture_output", run.call_args.kwargs)
        self.assertEqual(err, b"")
        self.assertEqual(P.diff_counts(out.decode()), (7, 0))
        self.assertEqual(row["stream_mode"], "stderr-merged-into-stdout")
        self.assertEqual((c.output / "merged.stdout").read_bytes(), merged)

    def test_duplicate_diff_suite_remains_ambiguous(self):
        section = suite(7)
        with self.assertRaises(ValueError):
            P.diff_counts(section + section)

    def test_actual_child_merged_stream_has_original_order(self):
        import sys

        stdout = ("running 7 tests\n" + result(7)).encode()
        code = (
            'import os;os.write(2,b" Running tests/diff_terminal.rs (x)\\n");os.write(1,'
            + repr(stdout)
            + ")"
        )
        out, err, _row = self.capture().run(
            "actual-merged", [sys.executable, "-c", code], merge=True
        )
        self.assertEqual(P.diff_counts(out.decode()), (7, 0))
        self.assertEqual(err, b"")

    def test_merged_failure_keeps_raw(self):
        c = self.capture()
        with (
            patch.object(
                P.subprocess,
                "run",
                return_value=subprocess.CompletedProcess(["tool"], 7, b"ordered failure", None),
            ),
            self.assertRaises(ValueError),
        ):
            c.run("merged-failure", ["tool"], merge=True)
        self.assertEqual((c.output / "merged-failure.stdout").read_bytes(), b"ordered failure")
        self.assertEqual(c.commands[0]["exit"], 7)

    def test_merged_timeout_keeps_raw(self):
        c = self.capture()
        with (
            patch.object(
                P.subprocess,
                "run",
                side_effect=subprocess.TimeoutExpired(["tool"], 1, output=b"partial merged"),
            ),
            self.assertRaises(subprocess.TimeoutExpired),
        ):
            c.run("merged-timeout", ["tool"], 1, merge=True)
        self.assertEqual((c.output / "merged-timeout.stdout").read_bytes(), b"partial merged")
        self.assertEqual(c.commands[0]["stream_mode"], "stderr-merged-into-stdout")

    def test_nested_14_children_and_host84_keep_only_diff_outer(self):
        child = "running 1 test\ntest u9_case ... ok\n" + result(1, filtered=13) + "ok\n"
        diff = (
            " Running tests/diff_terminal.rs (target/diff_terminal)\nrunning 14 tests\n"
            + child * 14
            + result(14)
        )
        host = (
            " Running unittests src/lib.rs (target/paludarium_host)\nrunning 84 tests\nrunning 1 test\n"
            + result(1, filtered=83)
            + result(84)
        )
        self.assertEqual(P.diff_counts(diff + host), (14, 0))

    def test_nested_child_without_outer_summary_rejected(self):
        text = " Running tests/diff_terminal.rs (x)\nrunning 14 tests\nrunning 1 test\n" + result(
            1, filtered=13
        )
        with self.assertRaises(ValueError):
            P.diff_counts(text)

    def test_outer_filtered_rejected(self):
        text = " Running tests/diff_terminal.rs (x)\nrunning 1 test\n" + result(1, filtered=13)
        with self.assertRaises(ValueError):
            P.diff_counts(text)

    def test_outer_declared_population_mismatch_rejected(self):
        text = " Running tests/diff_terminal.rs (x)\nrunning 14 tests\n" + result(1)
        with self.assertRaises(ValueError):
            P.diff_counts(text)

    def test_duplicate_outer_in_same_executable_rejected(self):
        text = suite(14) + "running 14 tests\n" + result(14)
        with self.assertRaises(ValueError):
            P.diff_counts(text)

    def test_exact_success_bytes(self):
        c = self.capture()
        with patch.object(
            P.subprocess,
            "run",
            return_value=subprocess.CompletedProcess(["tool"], 0, b"\x00out", b"err"),
        ):
            out, err, row = c.run("success", ["tool"])
        self.assertEqual(out, b"\x00out")
        self.assertEqual(err, b"err")
        self.assertEqual((c.output / "success.stdout").read_bytes(), out)
        self.assertEqual(row["exit"], 0)

    def test_failure_keeps_raw(self):
        c = self.capture()
        with (
            patch.object(
                P.subprocess,
                "run",
                return_value=subprocess.CompletedProcess(["tool"], 3, b"out", b"full stderr"),
            ),
            self.assertRaises(ValueError),
        ):
            c.run("failure", ["tool"])
        self.assertEqual((c.output / "failure.stderr").read_bytes(), b"full stderr")
        self.assertEqual(c.commands[0]["exit"], 3)

    def test_timeout_keeps_raw_and_rethrows(self):
        c = self.capture()
        error = subprocess.TimeoutExpired(["tool"], 1, output=b"out", stderr=b"partial err")
        with (
            patch.object(P.subprocess, "run", side_effect=error),
            self.assertRaises(subprocess.TimeoutExpired),
        ):
            c.run("timeout", ["tool"], 1)
        self.assertEqual((c.output / "timeout.stderr").read_bytes(), b"partial err")
        self.assertTrue(c.commands[0]["timed_out"])

    def test_reuse_directory_rejected(self):
        c = self.capture()
        with self.assertRaises(FileExistsError):
            P.Capture(c.output)

    def test_raw_overwrite_rejected(self):
        c = self.capture()
        c.save("x", b"old")
        with self.assertRaises(FileExistsError):
            c.save("x", b"new")
        self.assertEqual((c.output / "x").read_bytes(), b"old")

    def test_lcov_report_uses_file_mode(self):
        c = self.capture()
        args = P.export_command(Path("/actual/cargo"), "lcov", c.output)
        self.assertIn("--lcov", args)
        self.assertEqual(args[args.index("--output-path") + 1], str(c.output / "reexport.lcov"))

    def test_other_exports_keep_stdout_mode(self):
        c = self.capture()
        for kind in ("json", "report"):
            self.assertNotIn(
                "--output-path", P.export_command(Path("/actual/cargo"), kind, c.output)
            )

    def test_lcov_report_output_cannot_overwrite(self):
        c = self.capture()
        (c.output / "reexport.lcov").write_bytes(b"old")
        with self.assertRaises(ValueError):
            P.export_command(Path("/actual/cargo"), "lcov", c.output)
        self.assertEqual((c.output / "reexport.lcov").read_bytes(), b"old")

    def test_file_export_compares_exact_bytes(self):
        c = self.capture()
        path = c.output / "reexport.lcov"
        raw = b"SF:x\nLF:1\nLH:1\nend_of_record"
        path.write_bytes(raw)
        self.assertEqual(P.verify_lcov_file(path, raw)["sha256"], P.sha(raw))

    def test_terminal_lf_is_not_silently_normalized(self):
        c = self.capture()
        path = c.output / "reexport.lcov"
        path.write_bytes(b"end_of_record\n")
        with self.assertRaises(ValueError):
            P.verify_lcov_file(path, b"end_of_record")

    def test_lcov_count_change_rejected(self):
        c = self.capture()
        path = c.output / "reexport.lcov"
        path.write_bytes(b"DA:1,2")
        with self.assertRaises(ValueError):
            P.verify_lcov_file(path, b"DA:1,1")

    def test_missing_lcov_output_rejected(self):
        c = self.capture()
        with self.assertRaises(ValueError):
            P.verify_lcov_file(c.output / "missing", b"")

    def identity_fixture(self):
        c = self.capture()
        cov = c.output / "cov"
        binary = cov / "debug/program"
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b"\x7fELFinstrumented")
        binary.chmod(0o755)
        profile = cov / "coverage.profdata"
        profile.write_bytes(b"indexed fixture")
        rows = [dict(original_path="debug/program", sha256=P.sha(binary.read_bytes()))]
        return cov, profile, rows, binary

    def test_export_profile_and_binary_identity_exact(self):
        cov, profile, rows, _ = self.identity_fixture()
        self.assertEqual(
            P.verify_export_identity(cov, profile, P.sha(profile.read_bytes()), rows)[
                "profdata_sha256"
            ],
            P.sha(profile.read_bytes()),
        )

    def test_remerged_profile_change_rejected(self):
        cov, profile, rows, _ = self.identity_fixture()
        expected = P.sha(profile.read_bytes())
        profile.write_bytes(b"changed merge")
        with self.assertRaises(ValueError):
            P.verify_export_identity(cov, profile, expected, rows)

    def test_original_binary_byte_change_rejected(self):
        cov, profile, rows, binary = self.identity_fixture()
        binary.write_bytes(b"\x7fELFchanged")
        with self.assertRaises(ValueError):
            P.verify_export_identity(cov, profile, P.sha(profile.read_bytes()), rows)

    def test_extra_report_binary_rejected(self):
        cov, profile, rows, _ = self.identity_fixture()
        extra = cov / "debug/extra"
        extra.write_bytes(b"\x7fELFextra")
        extra.chmod(0o755)
        with self.assertRaises(ValueError):
            P.verify_export_identity(cov, profile, P.sha(profile.read_bytes()), rows)

    def test_missing_report_binary_rejected(self):
        cov, profile, rows, binary = self.identity_fixture()
        binary.unlink()
        with self.assertRaises(ValueError):
            P.verify_export_identity(cov, profile, P.sha(profile.read_bytes()), rows)


if __name__ == "__main__":
    unittest.main()
