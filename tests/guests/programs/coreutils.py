"""uutils coreutils' utilities, compared exactly with fresh Linux rows on x86-64 Linux."""

import json
import os
import pathlib
import shutil
import stat

from evidence import digest, snapshot
from runner import run

HERE = pathlib.Path(__file__).resolve().parent
FIXTURE = HERE / "coreutils-fixture"


def cases():
    return json.loads((HERE / "coreutils-cases.json").read_text())["cases"]


def fresh_fixture(directory):
    """A new copy of the fixture at `directory`, with every file 0644 as checked in."""
    shutil.copytree(FIXTURE, directory)
    inputs(directory)
    return directory


def inputs(directory):
    """Each fixture file's guest path and mode, as the emulator is given them."""
    result = {}
    for part, guest in (("app", ""), ("outside", "/outside")):
        for path in sorted((directory / part).rglob("*")):
            if path.is_file() and not path.is_symlink():
                result[guest + "/" + path.relative_to(directory / part).as_posix()] = mode(path)
    if any(mode != 0o644 for mode in result.values()):
        raise ValueError("coreutils fixture files are not 0644")
    return result


def mode(path):
    info = path.stat()
    if os.name != "nt":
        return stat.S_IMODE(info.st_mode)
    if not info.st_mode & stat.S_IWRITE:
        raise ValueError("Windows coreutils fixture file is read-only")
    # The Windows host shows a writable regular file as 0644; the Rust side
    # checks that it does.
    return 0o644


def fixture_files(directory):
    """Each fixture file's path under `directory` and guest path, for a host
    that reads the modes back itself."""
    return [
        (
            (part + "/" + path.relative_to(directory / part).as_posix()),
            guest + "/" + path.relative_to(directory / part).as_posix(),
        )
        for part, guest in (("app", ""), ("outside", "/outside"))
        for path in sorted((directory / part).rglob("*"))
        if path.is_file() and not path.is_symlink()
    ]


def stdin_of(case, directory):
    name = case.get("stdin")
    return None if name is None else (directory / "app" / name).read_bytes()


def environment(base, case):
    return dict(base, **case.get("env", {}))


def runner(operation, executable, guests, scratch, operations, base):
    """`run_case(case)` for compare_coreutils, through a host's `operation`:
    a fresh fixture copy per case, and one that writes runs on the copy
    mounted at /, so its files can be compared with Linux's afterwards."""

    def run_case(case):
        copy = fresh_fixture(scratch / "coreutils" / case["name"])
        if case.get("writes"):
            (copy / "app/tmp").mkdir()
            (copy / "app/home/guest").mkdir(parents=True)
        return operation(
            executable,
            guests / "coreutils",
            case["args"],
            operations / ("coreutils-" + case["name"]),
            environment(base, case),
            copy,
            mounted=bool(case.get("writes")),
            stdin=stdin_of(case, copy),
            inputs=inputs,
            program="/coreutils",
        )

    return run_case


def observe_coreutils(guests, root, env):
    """Native rows, each from a fresh fixture copy under `root`."""
    rows = {}
    for case in cases():
        directory = fresh_fixture(root / case["name"])
        row = run(
            [str(guests / "coreutils"), *case["args"]],
            cwd=directory / "app",
            env=environment(env, case),
            stdin=stdin_of(case, directory),
        )
        if row["timed_out"]:
            raise ValueError("native coreutils timed out: " + case["name"])
        if case.get("writes"):
            row["filesystem"] = snapshot(directory)
        rows[case["name"]] = row
    return {"binary_sha256": digest(guests / "coreutils"), "rows": rows}


def compare_coreutils(native, guests, run_case, record):
    """Runs every case through `run_case(case)` and passes each row to
    `record(name, row)` before checking it."""
    coreutils = native.get("coreutils")
    if coreutils is None or coreutils.get("binary_sha256") != digest(guests / "coreutils"):
        raise ValueError("native coreutils observed different bytes")
    names = [case["name"] for case in cases()]
    if list(coreutils.get("rows", {})) != names:
        raise ValueError("native coreutils rows missing, duplicated or reordered")
    failures = []
    for case in cases():
        row = run_case(case)
        record(case["name"], row)
        expected = coreutils["rows"][case["name"]]
        fields = ("exit", "timed_out", "stdout", "stderr", "wall_seconds")
        print(
            json.dumps(
                {
                    "case": "coreutils-" + case["name"],
                    "native": {k: expected[k] for k in fields},
                    "emulated": {k: row[k] for k in fields},
                }
            ),
            flush=True,
        )
        # The utilities print only the relative paths they are given, so
        # rows match exactly, with no root normalization.
        checked = ["timed_out", "exit", "stdout", "stderr"]
        if case.get("writes"):
            checked.append("filesystem")
        for field in checked:
            if expected.get(field) != row.get(field):
                failures.append(f"coreutils-{case['name']}: {field} mismatch")
        if row.get("stop") != f"None\nOk(Exited({expected['exit']}))":
            failures.append(f"coreutils-{case['name']}: guest did not exit by itself")
    # Every case runs before the first mismatch is raised, so one run lists
    # every difference.
    if failures:
        raise ValueError("; ".join(failures))
