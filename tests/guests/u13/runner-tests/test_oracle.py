import copy
import json
import pathlib
import sys
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "tests/guests/u13"))
sys.path.insert(1, str(ROOT / "tests/guests/u10"))
import oracle  # noqa: E402
from settings import configuration  # noqa: E402


class Text:
    def __init__(self, value):
        self.value = value

    def read_text(self):
        return json.dumps(self.value)


class Guests:
    def __truediv__(self, name):
        return Text({}) if name == "build-receipt.json" else name


class OracleTests(unittest.TestCase):
    def setUp(self):
        config = configuration(ROOT)
        names = ["probe-" + name for name in config["probe"] + ["all", "environment"]]
        names += [case["name"] for case in config["aube"]]
        self.data = {
            "schema": 1,
            "native_complete": True,
            "machine": "Linux-test-x86_64",
            "network_namespace": "net:[isolated]",
            "route": "header\n",
            "binary_hashes": {"probe": "probe", "aube": "aube"},
            "case_config": config,
            "rows": {name: {"wall_seconds": 0.1, "exit": 0, "timed_out": False} for name in names},
        }

    def load(self, data):
        with (
            patch.object(oracle, "validate"),
            patch.object(oracle, "digest", side_effect=lambda path: path),
        ):
            return oracle.load(Text(data), Guests(), ROOT)

    def test_complete_exact_fourteen(self):
        self.assertEqual(len(self.load(self.data)["rows"]), 14)

    def test_reporter_configuration_mismatch(self):
        self.data["case_config"] = configuration(ROOT, original=True)
        with self.assertRaises(ValueError):
            self.load(self.data)

    def test_incomplete(self):
        self.data["native_complete"] = False
        with self.assertRaises(ValueError):
            self.load(self.data)

    def test_wrong_machine(self):
        self.data["machine"] = "Darwin-test"
        with self.assertRaises(ValueError):
            self.load(self.data)

    def test_network_route(self):
        self.data["route"] += "00000000 route\n"
        with self.assertRaises(ValueError):
            self.load(self.data)

    def test_guest_hash(self):
        self.data["binary_hashes"]["probe"] = "other"
        with self.assertRaises(ValueError):
            self.load(self.data)

    def test_missing_and_reordered(self):
        for names in (list(self.data["rows"])[1:], list(reversed(self.data["rows"]))):
            data = copy.deepcopy(self.data)
            data["rows"] = {name: data["rows"][name] for name in names}
            with self.assertRaises(ValueError):
                self.load(data)

    def test_duration_boundaries(self):
        for duration in (True, -1, 30.01, float("inf"), float("nan"), "1"):
            data = copy.deepcopy(self.data)
            data["rows"]["probe-tokio-timer"]["wall_seconds"] = duration
            with self.assertRaises(ValueError):
                self.load(data)

    def test_failure_and_timeout(self):
        for field, value in (("exit", 1), ("exit", False), ("timed_out", True)):
            data = copy.deepcopy(self.data)
            data["rows"]["probe-tokio-timer"][field] = value
            with self.assertRaises(ValueError):
                self.load(data)
