"""Expose diagnostic collector/runner rejection regressions in the U14 suite."""

import os
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


class CostProfileRegression(unittest.TestCase):
    def test_node_cost_collector_and_runner_boundaries(self):
        node = os.environ.get("PALUDARIUM_TEST_NODE") or shutil.which("node")
        if not node or "/shims/" in node:
            self.fail("actual Node executable required via PALUDARIUM_TEST_NODE")
        result = subprocess.run(
            [node, "--test", "packages/paludarium-wasm/tests/jit-cost-profile.test.mjs"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=180,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("tests 32", result.stdout)


if __name__ == "__main__":
    unittest.main()
