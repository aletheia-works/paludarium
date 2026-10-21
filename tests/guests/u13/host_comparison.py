"""Identical static Linux ELF bytes run through the native Windows host emulator."""

import json
import math
import pathlib
import shutil
import tempfile

from comparison import compare, probe_pass
from comparison_args import compare_original
from fixture import fixture_inputs
from operation import operation as guest_operation
from oracle import load
from settings import configuration


def validate_stop(row):
    duration = row.get("wall_seconds")
    if (
        type(duration) not in (int, float)
        or not math.isfinite(duration)
        or not 0 <= duration <= 30
        or type(row.get("exit")) is not int
        or row["exit"] != 0
        or row.get("timed_out") is not False
        or row.get("stop") != "None\nOk(Exited(0))"
    ):
        raise ValueError("guest did not exit within the boundary")


def comparison_root(native_root, name):
    # The oracle ran on Linux, even when this comparator runs on Windows.
    return (
        native_root
        if name.startswith("probe-")
        else str(pathlib.PurePosixPath(native_root) / "fixture/app")
    )


def observe(executable, guests, native_path, output, root, *, original=False):
    config = configuration(root, original=original)
    native = load(native_path, guests, root, original=original)
    output.mkdir(parents=True, exist_ok=True)
    data = {
        "schema": 1,
        "binary_hashes": native["binary_hashes"],
        "rows": {},
        "case_config": config,
        "oracle": str(native_path),
        "default_rows": {},
        "network": "guest sockets limited to kernel socketpair; no native networking",
    }
    operations = pathlib.Path(tempfile.mkdtemp(prefix="operations-", dir=output))

    def store(name, row, *, default=False):
        data["default_rows" if default else "rows"][name] = row
        (output / "observations.json").write_text(json.dumps(data, indent=2) + "\n")
        expected = native["rows"][name]
        expected_root = comparison_root(native["fixture_root"], name)
        if original and name in ("install", "frozen"):
            compare_original(expected, row, expected_root, "/")
        else:
            compare(expected, row, expected_root, "/")
        validate_stop(row)

    for name in config["probe"] + ["all", "environment"]:
        key = "probe-" + name
        args = [] if name == "all" else [name]
        row = guest_operation(
            executable, guests / "probe", args, operations / key, config["environment"]
        )
        store(key, row)
        if name != "environment":
            probe_pass(row, config["probe"] if name == "all" else [name])
    with tempfile.TemporaryDirectory(prefix="paludarium-u12-") as scratch:
        fixture = pathlib.Path(scratch) / "fixture"
        shutil.copytree(root / "tests/guests/u10/fixtures", fixture)
        if fixture_inputs(fixture) != native["fixture_input_modes"]:
            raise ValueError("native/emulated fixture mode mismatch")
        for case in config["aube"][:2]:
            row = guest_operation(
                executable,
                guests / "aube",
                case["args"],
                operations / ("default-" + case["name"]),
                config["environment"],
                fixture,
            )
            store(case["name"], row, default=True)
        (fixture / "app/tmp").mkdir()
        (fixture / "app/home/u10").mkdir(parents=True)
        for case in config["aube"]:
            if case.get("before") == "remove-node-modules":
                shutil.rmtree(fixture / "app/node_modules")
            row = guest_operation(
                executable,
                guests / "aube",
                case["args"],
                operations / case["name"],
                config["environment"],
                fixture,
                mounted=True,
            )
            store(case["name"], row)
    if len(data["rows"]) != 14 or len(data["default_rows"]) != 2:
        raise ValueError("incomplete U13 inventory")
    data["differential_complete"] = True
    (output / "observations.json").write_text(json.dumps(data, indent=2) + "\n")
    print("U13 native host: fourteen Linux comparisons and two default VFS cases passed")
