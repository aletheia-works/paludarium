"""The official reporter applies equally, without rewriting original argv."""

import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from comparison import compare
from comparison_args import compare_original, comparison_config


class ComparisonArgumentTests(unittest.TestCase):
    def setUp(self):
        self.original = json.loads(
            (pathlib.Path(__file__).resolve().parents[1] / "cases.json").read_text()
        )

    def test_install_and_frozen_exact_reporter(self):
        cases = comparison_config(self.original)["aube"]
        self.assertEqual(cases[1]["args"], ["install", "--reporter=append-only"])
        self.assertEqual(
            cases[2]["args"], ["install", "--frozen-lockfile", "--reporter=append-only"]
        )

    def test_original_is_not_mutated(self):
        before = json.dumps(self.original, sort_keys=True)
        result = comparison_config(self.original)
        result["environment"]["HOME"] = "changed"
        self.assertEqual(json.dumps(self.original, sort_keys=True), before)

    def test_other_operations_and_limits_preserved(self):
        result = comparison_config(self.original)
        self.assertEqual(result["aube"][0], self.original["aube"][0])
        self.assertEqual(result["aube"][3], self.original["aube"][3])
        self.assertEqual(result["deadline_seconds"], 30)
        self.assertEqual(result["aube"][2]["before"], "remove-node-modules")

    def test_unexpected_install_args_rejected(self):
        self.original["aube"][1]["args"] = ["list"]
        with self.assertRaises(ValueError):
            comparison_config(self.original)

    def test_duplicate_reporter_rejected(self):
        self.original["aube"][1]["args"].append("--reporter=ndjson")
        with self.assertRaises(ValueError):
            comparison_config(self.original)

    def test_primary_still_rejects_progress_stderr(self):
        expected = dict(exit=0, timed_out=False, stdout="", stderr="summary in 33ms\n")
        actual = dict(expected, stderr="resolving progress\nsummary in 3s\n")
        with self.assertRaisesRegex(ValueError, "stderr mismatch"):
            compare(expected, actual, "/native", "/")
        compare_original(expected, actual, "/native", "/")

    def test_original_failures_remain_gating(self):
        expected = dict(exit=0, timed_out=False, stdout="ok", stderr="raw")
        for changed in (dict(exit=1), dict(timed_out=True), dict(stdout="bad")):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                compare_original(expected, dict(expected, **changed), "/native", "/")


if __name__ == "__main__":
    unittest.main()
