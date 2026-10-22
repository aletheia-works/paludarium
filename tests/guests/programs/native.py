"""Fresh network-isolated native oracle, generated before differential code."""

import json
import os
import pathlib
import platform
import shutil
import tempfile

from comparison import probe_pass
from evidence import digest, snapshot, validate
from metadata import fixture_inputs
from runner import run

HERE = pathlib.Path(__file__).resolve().parent


def observe_ripgrep(guests, app, env):
    """ripgrep's rows, kept apart from the probe and aube rows other hosts check."""
    cases = json.loads((HERE / "ripgrep-cases.json").read_text())["cases"]
    rows = {}
    for case in cases:
        row = run([str(guests / "ripgrep"), *case["args"]], cwd=app, env=env)
        if row["timed_out"]:
            raise ValueError("native ripgrep timed out: " + case["name"])
        rows[case["name"]] = row
    return {"binary_sha256": digest(guests / "ripgrep"), "rows": rows}


def observe_coreutils(guests, root, env):
    """coreutils' commands in order in one copy of their fixture."""
    shutil.copytree(HERE / "coreutils-fixture", root / "coreutils")
    app = root / "coreutils/app"
    rows = []
    for case in json.loads((HERE / "coreutils-cases.json").read_text())["cases"]:
        row = run([str(guests / "coreutils"), *case], cwd=app, env=env)
        if row["timed_out"]:
            raise ValueError("native coreutils timed out: " + " ".join(case))
        rows.append(row)
    return {
        "binary_sha256": digest(guests / "coreutils"),
        "rows": rows,
        "filesystem": snapshot(app),
    }


def observe(guests, output, config, *, extra_snapshot=None, prepare_fixture=None):
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise RuntimeError("native oracle requires x86-64 Linux")
    if os.readlink("/proc/self/ns/net") == os.readlink("/proc/1/ns/net"):
        raise RuntimeError("run through sudo unshare --net; host network forbidden")
    receipt = json.loads((guests / "build-receipt.json").read_text())
    validate(guests, receipt)
    output.mkdir(parents=True, exist_ok=True)
    observations = {
        "schema": 1,
        "machine": platform.platform(),
        "network_namespace": os.readlink("/proc/self/ns/net"),
        "route": pathlib.Path("/proc/net/route").read_text(),
        "binary_hashes": {n: digest(guests / n) for n in ("probe", "aube")},
        "rows": {},
    }
    with tempfile.TemporaryDirectory(prefix="paludarium-programs-") as scratch:
        root = pathlib.Path(scratch)
        env = dict(config["environment"], HOME=str(root / "home"), TMPDIR=str(root / "tmp"))
        (root / "home").mkdir()
        (root / "tmp").mkdir()
        observations["fixture_root"] = str(root)
        if prepare_fixture is not None:
            observations["guest_environment"] = env
            observations["case_config"] = config
        for name in config["probe"] + ["all", "environment"]:
            args = [] if name == "all" else [name]
            row = run([str(guests / "probe"), *args], cwd=root, env=env)
            observations["rows"]["probe-" + name] = row
            (output / "observations.json").write_text(json.dumps(observations, indent=2) + "\n")
            if name == "environment":
                if row["exit"] != 0 or row["stdout"] != "PASS node-absent ENOENT\n":
                    raise ValueError("node absence not observed")
            else:
                probe_pass(row, config["probe"] if name == "all" else [name])
        shutil.copytree(HERE / "fixtures", root / "fixture")
        if prepare_fixture is not None:
            observations["fixture_preparation"] = prepare_fixture(root / "fixture")
        app = root / "fixture/app"
        observations["fixture_input_modes"] = fixture_inputs(root / "fixture")
        observations["ripgrep"] = observe_ripgrep(guests, app, env)
        observations["coreutils"] = observe_coreutils(guests, root, env)
        (output / "observations.json").write_text(json.dumps(observations, indent=2) + "\n")
        for case in config["aube"]:
            if case.get("before") == "remove-node-modules":
                shutil.rmtree(app / "node_modules")
            row = run([str(guests / "aube")] + case["args"], cwd=app, env=env)
            row["filesystem"] = snapshot(root / "fixture")
            if extra_snapshot is not None:
                row["filesystem_metadata"] = extra_snapshot(root / "fixture")
            observations["rows"][case["name"]] = row
            (output / "observations.json").write_text(json.dumps(observations, indent=2) + "\n")
            if row["exit"] != 0 or row["timed_out"]:
                raise ValueError("native aube failed: " + case["name"])
        observations["native_complete"] = True
        (output / "observations.json").write_text(json.dumps(observations, indent=2) + "\n")
    print(
        "fixed guest programs native: probe eight items + standard run; aube four commands; node ENOENT"
    )
