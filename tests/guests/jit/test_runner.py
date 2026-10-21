"""Fail-closed JIT acceptance report regression cases."""

import copy
import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "jit_runner", Path(__file__).resolve().parents[3] / "scripts/jit-run.py"
)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
NAMES = [
    "probe-" + x
    for x in (
        "tokio-timer",
        "unix-stream-pair",
        "rayon",
        "mutex-condvar",
        "fs-basic",
        "fs-hardlink",
        "fs-symlink",
        "fs-flock",
        "all",
        "environment",
    )
] + ["version", "install", "frozen", "list"]


def valid():
    row = dict(
        seconds=1.0,
        exit=0,
        timed_out=False,
        pass_=True,
        errors=[],
        jit=dict(executedBlocks="1", executedInstructions="2"),
    )
    row["pass"] = row.pop("pass_")
    return dict(
        complete=True,
        passed=True,
        caseCount=28,
        rows={
            mode: {name: copy.deepcopy(row) for name in NAMES} for mode in ("interpreter", "jit")
        },
    )


class RunnerTests(unittest.TestCase):
    def test_valid(self):
        runner.validate(valid())

    def rejected(self, change):
        report = valid()
        change(report)
        with self.assertRaises(ValueError):
            runner.validate(report)

    def test_modes(self):
        for mode in ("extra", "jit"):
            with self.subTest(mode=mode):
                self.rejected(
                    lambda r, mode=mode: (
                        r["rows"].update(extra={}) if mode == "extra" else r["rows"].pop(mode)
                    )
                )

    def test_inventory(self):
        for variant in ("missing", "extra", "order"):

            def change(r, variant=variant):
                rows = r["rows"]["jit"]
                if variant == "missing":
                    rows.pop(NAMES[0])
                elif variant == "extra":
                    rows["extra"] = rows[NAMES[0]]
                else:
                    rows[NAMES[0]] = rows.pop(NAMES[0])

            with self.subTest(variant=variant):
                self.rejected(change)

    def test_time(self):
        for value in (float("nan"), float("inf"), True, -1, 30.01, "1"):
            with self.subTest(value=value):
                self.rejected(
                    lambda r, value=value: r["rows"]["jit"][NAMES[0]].update(seconds=value)
                )

    def test_failures(self):
        for field, value in (
            ("exit", True),
            ("exit", 1),
            ("timed_out", True),
            ("pass", False),
            ("errors", ["failure"]),
            ("errors", None),
        ):
            with self.subTest(field=field, value=value):
                self.rejected(
                    lambda r, field=field, value=value: r["rows"]["jit"][NAMES[0]].update(
                        {field: value}
                    )
                )

    def test_counts(self):
        for key in ("executedBlocks", "executedInstructions"):
            for value in ("0", "-1", "1.0", "１", 1, None):  # noqa: RUF001 (a full-width digit must be rejected)
                with self.subTest(key=key, value=value):
                    self.rejected(
                        lambda r, key=key, value=value: r["rows"]["jit"][NAMES[0]]["jit"].update(
                            {key: value}
                        )
                    )

    def test_completion(self):
        for field, value in (("complete", False), ("passed", False), ("caseCount", 27)):
            with self.subTest(field=field):
                self.rejected(lambda r, field=field, value=value: r.update({field: value}))


if __name__ == "__main__":
    unittest.main()


class MainTests(unittest.TestCase):
    def test_main_success_and_supervised_failure_keep_receipt(self):
        import json
        import tempfile
        from unittest.mock import patch

        for failure in (False, True):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                output = Path(directory)
                (output / "observations.json").write_text(json.dumps(valid()))
                args = [
                    "jit-run",
                    "--environment",
                    "node",
                    "--wasm",
                    directory,
                    "--native",
                    directory,
                    "--guests",
                    directory,
                    "--output",
                    directory,
                ]
                result = dict(
                    stdout="",
                    stderr="",
                    exit=int(failure),
                    timed_out=False,
                    process_group_cleaned=True,
                )
                with (
                    patch.object(runner.sys, "argv", args),
                    patch.object(runner, "supervise", return_value=result),
                ):
                    if failure:
                        with self.assertRaises(RuntimeError):
                            runner.main()
                    else:
                        runner.main()
                self.assertEqual(json.loads((output / "suite-supervisor.json").read_text()), result)
