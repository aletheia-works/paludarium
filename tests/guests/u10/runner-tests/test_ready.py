import pathlib
import subprocess
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[4]


class RunnerReadiness(unittest.TestCase):
    def test_self_test_runs(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts/u10-run.py"), "--self-test"],
            capture_output=True,
            timeout=5,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b"30-second", result.stdout)

    def test_missing_mode_is_rejected(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts/u10-run.py")], capture_output=True, timeout=5
        )
        self.assertEqual(result.returncode, 2)
