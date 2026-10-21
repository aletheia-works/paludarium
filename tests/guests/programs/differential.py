"""Fresh native oracle and identical guest bytes executed through C10."""

import json
import os
import pathlib
import shutil
import sys
import tempfile

from comparison import compare, probe_pass
from comparison_args import compare_original, comparison_config
from evidence import snapshot
from metadata import fixture_inputs
from native import observe
from runner import run

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def operation(executable, binary, args, directory, environment, fixture=None, mounted=False):
    directory.mkdir(parents=True)
    (directory / "args").write_text("\n".join(args) + ("\n" if args else ""))
    (directory / "environment").write_text(
        "".join(k + "=" + v + "\n" for k, v in environment.items())
    )
    env = dict(
        os.environ,
        PALUDARIUM_PROGRAMS_OPERATION=str(directory),
        PALUDARIUM_PROGRAMS_BINARY=str(binary),
    )
    env.pop("PALUDARIUM_PROGRAMS_FIXTURE", None)
    env.pop("PALUDARIUM_PROGRAMS_MOUNTED", None)
    if fixture is not None:
        env["PALUDARIUM_PROGRAMS_FIXTURE"] = str(fixture)
    if mounted:
        env["PALUDARIUM_PROGRAMS_MOUNTED"] = "1"
    child = run(
        [str(executable), "--exact", "programs_guest_operation", "--nocapture"], cwd=ROOT, env=env
    )
    (directory / "runner.json").write_text(json.dumps(child, indent=2) + "\n")
    if child["timed_out"] or child["exit"] != 0:
        print(
            json.dumps({"case": directory.name, "runner_failure": child}, ensure_ascii=False),
            flush=True,
        )
        raise ValueError("emulator operation failed/timed out: " + str(directory))
    row = {
        "stdout": (directory / "stdout").read_text(),
        "stderr": (directory / "stderr").read_text(),
        "exit": int((directory / "exit").read_text()),
        "timed_out": False,
        "wall_seconds": float((directory / "seconds").read_text()),
        "stop": (directory / "stop").read_text(),
    }
    if fixture is not None:
        row["filesystem"] = snapshot(fixture)
        recorded = (directory / "fixture-modes").read_text()
        row["fixture_input_modes"] = (
            fixture_inputs(fixture)
            if mounted
            else {line.split("\t")[0]: int(line.split("\t")[1]) for line in recorded.splitlines()}
        )
        if not mounted and row["fixture_input_modes"] != fixture_inputs(fixture):
            raise ValueError("private VFS fixture metadata differs from native input")
    return row


def differential(executable, *, original_argv=False):
    original = json.loads((HERE / "cases.json").read_text())
    config = original if original_argv else comparison_config(original)
    compare_rows = compare_original if original_argv else compare
    guests = pathlib.Path(
        os.environ.get("PALUDARIUM_PROGRAMS_GUEST_DIR", ROOT / "target/guests/programs")
    ).resolve()
    output = ROOT / "target/programs/differential"
    if original_argv:
        output = output / "original-argv"
    output.mkdir(parents=True, exist_ok=True)
    observe(guests, output / "native", config)
    native = json.loads((output / "native/observations.json").read_text())
    observations = {
        "schema": 1,
        "binary_hashes": native["binary_hashes"],
        "rows": {},
        "native_complete": native["native_complete"],
        "case_config": config,
        "comparison": "original-argv stable outcomes; raw stderr retained"
        if original_argv
        else "same append-only reporter; stdout/stderr/exit",
        "mount_scope": "temporary fixture/app and fixture/outside only",
    }
    operations = pathlib.Path(tempfile.mkdtemp(prefix="operations-", dir=output))
    observations["operation_records"] = str(operations)

    def store(name, row):
        observations["rows"][name] = row
        (output / "observations.json").write_text(json.dumps(observations, indent=2) + "\n")
        expected = native["rows"][name.removeprefix("default-")]
        fields = ("exit", "timed_out", "stdout", "stderr", "stop", "wall_seconds")
        print(
            json.dumps(
                {
                    "case": name,
                    "native": {k: expected[k] for k in fields if k in expected},
                    "emulated": {k: row[k] for k in fields if k in row},
                },
                ensure_ascii=False,
            ),
            flush=True,
        )

    with tempfile.TemporaryDirectory(prefix="paludarium-programs-emulated-") as temporary:
        scratch = pathlib.Path(temporary)
        for name in config["probe"] + ["all", "environment"]:
            args = [] if name == "all" else [name]
            row = operation(
                executable,
                guests / "probe",
                args,
                operations / ("probe-" + name),
                config["environment"],
            )
            store("probe-" + name, row)
            compare(native["rows"]["probe-" + name], row, native["fixture_root"], "/")
            if name != "environment":
                probe_pass(row, config["probe"] if name == "all" else [name])
        fixture = scratch / "fixture"
        shutil.copytree(HERE / "fixtures", fixture)
        if fixture_inputs(fixture) != native["fixture_input_modes"]:
            raise ValueError("native/emulated fixture input mode mismatch")
        for case in config["aube"][:2]:
            name = "default-" + case["name"]
            row = operation(
                executable,
                guests / "aube",
                case["args"],
                operations / name,
                config["environment"],
                fixture,
            )
            store(name, row)
            compare_rows(
                native["rows"][case["name"]],
                row,
                str(pathlib.Path(native["fixture_root"]) / "fixture/app"),
                "/",
            )
        rows = {}
        # A root mount routes /tmp and /home descendants into this bounded
        # fixture. Prepare the same runtime directories as the native oracle.
        (fixture / "app/tmp").mkdir()
        (fixture / "app/home/guest").mkdir(parents=True)
        for case in config["aube"]:
            if case.get("before") == "remove-node-modules":
                shutil.rmtree(fixture / "app/node_modules")
            row = operation(
                executable,
                guests / "aube",
                case["args"],
                operations / case["name"],
                config["environment"],
                fixture,
                mounted=True,
            )
            store(case["name"], row)
            rows[case["name"]] = row
            compare_rows(
                native["rows"][case["name"]],
                row,
                str(pathlib.Path(native["fixture_root"]) / "fixture/app"),
                "/",
            )
        observations["differential_complete"] = True
        (output / "observations.json").write_text(json.dumps(observations, indent=2) + "\n")
    print("U10 differential: eight probe items and four aube commands passed")


if __name__ == "__main__":
    differential(pathlib.Path(sys.argv[1]).resolve())
    differential(pathlib.Path(sys.argv[1]).resolve(), original_argv=True)
