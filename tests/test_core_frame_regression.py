"""Reject invalid measurements and mismatched differential results."""

import importlib.util
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/core-frame-regression.py"
SPEC = importlib.util.spec_from_file_location("frame_regression", SCRIPT)
regression = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(regression)


def outcome(**updates):
    row = {"exit": 0, "timeout": False, "seconds": 0.5}
    row.update(updates)
    return row, b"same stdout", b""


class ComparisonTests(unittest.TestCase):
    def test_equal_results_and_deadline_boundaries(self):
        for seconds in (0, 0.5, 30):
            regression.compare(outcome(seconds=seconds), outcome())

    def test_nonzero_exit_in_either_execution(self):
        for code in (1, -11, 127):
            for pair in ((outcome(exit=code), outcome()), (outcome(), outcome(exit=code))):
                with self.assertRaises(ValueError):
                    regression.compare(*pair)

    def test_timeout_in_either_execution(self):
        for pair in ((outcome(timeout=True), outcome()), (outcome(), outcome(timeout=True))):
            with self.assertRaises(ValueError):
                regression.compare(*pair)

    def test_invalid_times_are_rejected(self):
        for seconds in (-1, 30.001, float("nan"), float("inf"), float("-inf"), True, "0.5", None):
            for pair in (
                (outcome(seconds=seconds), outcome()),
                (outcome(), outcome(seconds=seconds)),
            ):
                with self.assertRaises(ValueError):
                    regression.compare(*pair)

    def test_boolean_exit_is_not_exit_zero(self):
        with self.assertRaises(ValueError):
            regression.compare(outcome(exit=False), outcome())

    def test_timeout_type_must_be_boolean(self):
        for value in (0, None, "false"):
            with self.assertRaises(ValueError):
                regression.compare(outcome(timeout=value), outcome())

    def test_stdout_mismatch_is_rejected(self):
        row, _, stderr = outcome()
        with self.assertRaises(ValueError):
            regression.compare((row, b"different", stderr), outcome())

    def test_stderr_mismatch_is_rejected(self):
        row, stdout, _ = outcome()
        with self.assertRaises(ValueError):
            regression.compare(outcome(), (row, stdout, b"unexpected error"))


if __name__ == "__main__":
    unittest.main()
