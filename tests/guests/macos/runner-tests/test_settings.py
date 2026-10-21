"""U12 fixed comparison contract regressions; fixtures stay immutable."""

import copy
import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[4]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "tests/guests/macos"))
from settings import configuration  # noqa: E402


class Root:
    def __init__(self, value):
        self.value = value

    def __truediv__(self, path):
        if path != "tests/guests/programs/cases.json":
            raise ValueError("unexpected fixture path")
        return self

    def read_text(self):
        return json.dumps(self.value)


class SettingsTests(unittest.TestCase):
    def setUp(self):
        self.config = json.loads((ROOT / "tests/guests/programs/cases.json").read_text())

    def rejects(self, change):
        change(self.config)
        with self.assertRaises(ValueError):
            configuration(Root(self.config))

    def test_same_official_reporter_without_mutating_source(self):
        original = copy.deepcopy(self.config)
        config = configuration(Root(self.config))
        self.assertEqual(self.config, original)
        self.assertEqual(config["aube"][1]["args"], ["install", "--reporter=append-only"])
        self.assertEqual(
            config["aube"][2]["args"], ["install", "--frozen-lockfile", "--reporter=append-only"]
        )

    def test_schema_rejected(self):
        self.rejects(lambda c: c.update(schema=2))

    def test_original_arguments_preserved(self):
        self.assertEqual(configuration(Root(self.config), original=True), self.config)

    def test_deadline_rejected(self):
        self.rejects(lambda c: c.update(deadline_seconds=31))

    def test_probe_missing_rejected(self):
        self.rejects(lambda c: c["probe"].pop())

    def test_probe_order_rejected(self):
        self.rejects(lambda c: c["probe"].reverse())

    def test_aube_argument_rejected(self):
        self.rejects(lambda c: c["aube"][1]["args"].append("--silent"))

    def test_cleanup_rejected(self):
        self.rejects(lambda c: c["aube"][2].update(before="keep-node-modules"))

    def test_node_boundary_rejected(self):
        self.rejects(lambda c: c["environment"].update(PATH="/usr/bin"))

    def test_stderr_comparison_required(self):
        self.rejects(lambda c: c["comparison"].update(stderr=False))


if __name__ == "__main__":
    unittest.main()
