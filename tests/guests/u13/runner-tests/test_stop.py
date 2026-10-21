"""Supervisorの終了・期限・子孫回収。Windowsでは実job経路を走る。"""

import os
import pathlib
import sys
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[4]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "tests/guests/u13"))
from runner import run  # noqa: E402


class StopTests(unittest.TestCase):
    def child(self, code, timeout=30):
        return run([sys.executable, "-c", code], cwd=ROOT, env=dict(os.environ), timeout=timeout)

    def test_success(self):
        self.assertEqual(self.child("pass")["exit"], 0)

    def test_nonzero_is_preserved(self):
        self.assertEqual(self.child("raise SystemExit(7)")["exit"], 7)

    def test_both_streams(self):
        row = self.child('import sys;print("out");print("err",file=sys.stderr)')
        self.assertEqual(row["stdout"].strip(), "out")
        self.assertEqual(row["stderr"].strip(), "err")

    def test_unicode(self):
        row = self.child('import sys;sys.stdout.buffer.write("日本語".encode())')
        self.assertEqual(row["stdout"], "日本語")

    def test_invalid_deadlines(self):
        for value in (0, -1, 31, float("nan"), float("inf"), True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.child("pass", value)

    def test_timeout(self):
        row = self.child("import time;time.sleep(20)", 0.2)
        self.assertTrue(row["timed_out"])
        self.assertNotEqual(row["exit"], 0)

    def test_descendant_holds_pipe(self):
        code = (
            'import subprocess,sys;subprocess.Popen([sys.executable,"-c",'
            '"import time;time.sleep(20)"]);print("parent",flush=True)'
        )
        started = time.monotonic()
        row = self.child(code, 0.2)
        self.assertTrue(row["timed_out"])
        self.assertIn("parent", row["stdout"])
        self.assertLess(time.monotonic() - started, 5)


if __name__ == "__main__":
    unittest.main()
