import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "tests/guests/wasm"))
from supervisor import supervise  # noqa: E402


class SupervisorTests(unittest.TestCase):
    def execute(self, code, **kwargs):
        return supervise([sys.executable, "-c", code], cwd=ROOT, **kwargs)

    def test_success(self):
        self.assertEqual(self.execute("pass")["exit"], 0)

    def test_nonzero_retained(self):
        self.assertEqual(self.execute("raise SystemExit(3)")["exit"], 3)

    def test_stdout(self):
        self.assertEqual(self.execute('print("hello")')["stdout"], "hello\n")

    def test_stderr(self):
        self.assertIn(
            "failure", self.execute('import sys; print("failure", file=sys.stderr)')["stderr"]
        )

    def test_timeout_cleans_group(self):
        row = self.execute("import time; time.sleep(10)", seconds=0.05)
        self.assertTrue(row["timed_out"])
        self.assertTrue(row["process_group_cleaned"])
        self.assertNotEqual(row["exit"], 0)

    def test_unbounded_deadline_rejected(self):
        with self.assertRaises(ValueError):
            self.execute("pass", seconds=0)

    def test_empty_command_rejected(self):
        with self.assertRaises(ValueError):
            supervise([], cwd=ROOT)
