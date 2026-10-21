"""One fixed Linux ELF operation in a Windows/native emulator process."""

import json
import os
import pathlib

from evidence import digest
from fixture import fixture_inputs
from runner import run

ROOT = pathlib.Path(__file__).resolve().parents[3]


def operation(executable, binary, args, directory, environment, fixture=None, mounted=False):
    directory.mkdir(parents=True)
    (directory / "args").write_text("\n".join(args) + ("\n" if args else ""), encoding="utf-8")
    (directory / "environment").write_text(
        "".join(k + "=" + v + "\n" for k, v in environment.items()), encoding="utf-8"
    )
    env = dict(
        os.environ, PALUDARIUM_U13_OPERATION=str(directory), PALUDARIUM_U13_BINARY=str(binary)
    )
    env.pop("PALUDARIUM_U13_FIXTURE", None)
    env.pop("PALUDARIUM_U13_MOUNTED", None)
    if fixture is not None:
        env["PALUDARIUM_U13_FIXTURE"] = str(fixture)
    if mounted:
        env["PALUDARIUM_U13_MOUNTED"] = "1"
    child = run(
        [str(executable), "--exact", "windows_guest_operation", "--nocapture"], cwd=ROOT, env=env
    )
    (directory / "runner.json").write_text(json.dumps(child, indent=2) + "\n", encoding="utf-8")
    if child["timed_out"] or child["exit"] != 0:
        print(
            json.dumps({"case": directory.name, "runner_failure": child}, ensure_ascii=False),
            flush=True,
        )
        raise ValueError("emulator operation failed/timed out: " + str(directory))
    row = {
        "stdout": (directory / "stdout").read_text(encoding="utf-8"),
        "stderr": (directory / "stderr").read_text(encoding="utf-8"),
        "exit": int((directory / "exit").read_text()),
        "timed_out": False,
        "wall_seconds": float((directory / "seconds").read_text()),
        "stop": (directory / "stop").read_text(encoding="utf-8"),
    }
    if fixture is not None:
        # Canonical guest paths use '/', including on Windows. Content hashes
        # remain unmasked and complete; this is a path representation conversion.
        row["filesystem"] = {
            p.relative_to(fixture).as_posix(): digest(p)
            for p in sorted(fixture.rglob("*"))
            if p.is_file()
        }
        recorded = (directory / "fixture-modes").read_text(encoding="utf-8")
        pairs = [line.split("\t") for line in recorded.splitlines()]
        modes = {path: int(mode) for path, mode in pairs}
        if len(pairs) != len(modes) or modes != fixture_inputs(fixture):
            raise ValueError("Rust Host/private VFS fixture metadata differs from Linux inputs")
        row["fixture_input_modes"] = modes
    return row
