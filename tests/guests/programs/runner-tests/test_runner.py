"""Fixture/runner boundary tests; no emulator success is mocked."""

import json
import os
import pathlib
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from evidence import snapshot
from runner import run

HERE = pathlib.Path(__file__).resolve().parents[1]


class RunnerTests(unittest.TestCase):
    def execute(self, source, **options):
        return run([sys.executable, "-c", source], cwd=HERE, env={}, **options)

    def test_output_streams_separate(self):
        row = self.execute('import sys; print("out"); print("err", file=sys.stderr)')
        self.assertEqual((row["stdout"], row["stderr"], row["exit"]), ("out\n", "err\n", 0))

    def test_nonzero_preserved(self):
        self.assertEqual(self.execute("raise SystemExit(7)")["exit"], 7)

    def test_deadline_bounds(self):
        for timeout in (0, -1, 31):
            with self.assertRaises(ValueError):
                self.execute("pass", timeout=timeout)

    def test_timeout_kills_process(self):
        row = self.execute("import time; time.sleep(60)", timeout=0.05)
        self.assertTrue(row["timed_out"])
        self.assertLess(row["exit"], 0)

    def test_descendants_stopped_and_reaped(self):
        row = self.execute(
            'import subprocess,sys,time; p=subprocess.Popen([sys.executable,"-c","import time; time.sleep(60)"]); print(p.pid,flush=True); time.sleep(60)',
            timeout=0.1,
        )
        self.assertTrue(row["timed_out"])
        pid = int(row["stdout"])
        if sys.platform == "linux":
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)

    def test_fixture_copy_does_not_pollute_source(self):
        before = snapshot(HERE / "fixtures")
        with tempfile.TemporaryDirectory() as temporary:
            destination = pathlib.Path(temporary) / "fixture"
            shutil.copytree(HERE / "fixtures", destination)
            (destination / "app/package.json").write_text("{}")
        self.assertEqual(before, snapshot(HERE / "fixtures"))

    def test_guest_environment_has_no_node_or_network_config(self):
        config = json.loads((HERE / "cases.json").read_text())
        self.assertEqual(config["environment"]["PATH"], "/no-node")
        self.assertEqual(config["deadline_seconds"], 30)
        self.assertIn("network namespace", config["network"])
        row = self.execute('import os; print(os.environ.get("PATH","absent"))')
        self.assertEqual(row["stdout"], "absent\n")


if __name__ == "__main__":
    unittest.main()
