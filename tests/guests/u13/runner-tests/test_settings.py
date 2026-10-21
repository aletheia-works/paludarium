"""U13比較条件と実装前runner準備の境界。"""

import pathlib
import runpy
import sys
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[4]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "tests/guests/u13"))
sys.path.insert(1, str(ROOT / "tests/guests/u10"))
from runner import run  # noqa: E402
from settings import PROBE_ITEMS, configuration  # noqa: E402


class SettingsTests(unittest.TestCase):
    def test_probe_inventory(self):
        self.assertEqual(tuple(configuration(ROOT)["probe"]), PROBE_ITEMS)

    def test_deadline(self):
        self.assertEqual(configuration(ROOT)["deadline_seconds"], 30)

    def test_primary_reporter(self):
        config = configuration(ROOT)
        self.assertEqual(config["aube"][1]["args"], ["install", "--reporter=append-only"])

    def test_original_arguments(self):
        self.assertEqual(configuration(ROOT, original=True)["aube"][1]["args"], ["install"])

    def test_no_node(self):
        self.assertEqual(configuration(ROOT)["environment"]["PATH"], "/u10-no-node")

    def test_runner_ready(self):
        row = run([sys.executable, "-c", "pass"], cwd=ROOT, env={})
        self.assertEqual(row["exit"], 0)
        self.assertFalse(row["timed_out"])

    def test_runner_rejects_extended_deadline(self):
        with self.assertRaises(ValueError):
            run([], cwd=ROOT, env={}, timeout=31)

    def test_native_primary_cli_arguments(self):
        self.check_native_cli(False)

    def test_native_original_cli_arguments(self):
        self.check_native_cli(True)

    def check_native_cli(self, original):
        args = [
            "u13-run.py",
            "--native-only",
            "--guests",
            "target/guests/u10",
            "--output",
            "target/u13/native",
        ]
        if original:
            args.append("--original-argv")
        with mock.patch.object(sys, "argv", args), mock.patch("native.observe") as observe:
            runpy.run_path(str(ROOT / "scripts/u13-run.py"), run_name="__main__")
        observe.assert_called_once()
        actual = observe.call_args.args
        self.assertEqual(actual[0], (ROOT / "target/guests/u10").resolve())
        self.assertEqual(actual[2], configuration(ROOT, original=original))


if __name__ == "__main__":
    unittest.main()
