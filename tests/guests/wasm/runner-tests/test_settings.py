import copy
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "tests/guests/wasm"))
from settings import configuration, validate  # noqa: E402


class SettingsTests(unittest.TestCase):
    def setUp(self):
        self.config = copy.deepcopy(configuration(ROOT))

    def test_fixed_fourteen_case_inventory(self):
        self.assertEqual(len(validate(self.config)["probe"]) + 2 + len(self.config["aube"]), 14)

    def test_bad_schema_rejected(self):
        self.config["schema"] = 2
        with self.assertRaises(ValueError):
            validate(self.config)

    def test_unbounded_deadline_rejected(self):
        self.config["deadline_seconds"] = 0
        with self.assertRaises(ValueError):
            validate(self.config)

    def test_probe_substitution_rejected(self):
        self.config["probe"][0] = "mock"
        with self.assertRaises(ValueError):
            validate(self.config)

    def test_aube_reordering_rejected(self):
        self.config["aube"].reverse()
        with self.assertRaises(ValueError):
            validate(self.config)

    def test_missing_cleanup_rejected(self):
        del self.config["aube"][2]["before"]
        with self.assertRaises(ValueError):
            validate(self.config)

    def test_missing_stderr_comparison_rejected(self):
        self.config["comparison"]["stderr"] = False
        with self.assertRaises(ValueError):
            validate(self.config)

    def test_reporter_is_exact_and_u10_is_unchanged(self):
        import json

        self.assertEqual(self.config["aube"][1]["args"], ["install", "--reporter=append-only"])
        self.assertEqual(
            self.config["aube"][2]["args"],
            ["install", "--frozen-lockfile", "--reporter=append-only"],
        )
        self.assertEqual(
            json.loads((ROOT / "tests/guests/programs/cases.json").read_text())["aube"][1]["args"],
            ["install"],
        )


if __name__ == "__main__":
    unittest.main()
