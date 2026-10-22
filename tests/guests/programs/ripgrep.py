"""ripgrep's searches, compared exactly with the fresh Linux rows on every native host."""

import json
import pathlib

from evidence import digest

HERE = pathlib.Path(__file__).resolve().parent


def cases():
    return json.loads((HERE / "ripgrep-cases.json").read_text())["cases"]


def compare_ripgrep(native, guests, run_case, record):
    """Runs every case through `run_case(case)` in the unchanged fixture, before
    aube changes it, and passes each row to `record(name, row)` before checking it.
    """
    ripgrep = native.get("ripgrep")
    if ripgrep is None or ripgrep.get("binary_sha256") != digest(guests / "ripgrep"):
        raise ValueError("native ripgrep observed different bytes")
    names = [case["name"] for case in cases()]
    if list(ripgrep.get("rows", {})) != names:
        raise ValueError("native ripgrep rows missing, duplicated or reordered")
    for case in cases():
        row = run_case(case)
        record(case["name"], row)
        expected = ripgrep["rows"][case["name"]]
        fields = ("exit", "timed_out", "stdout", "stderr", "wall_seconds")
        print(
            json.dumps(
                {
                    "case": "ripgrep-" + case["name"],
                    "native": {k: expected[k] for k in fields},
                    "emulated": {k: row[k] for k in fields},
                }
            ),
            flush=True,
        )
        # ripgrep prints only the relative paths it is given, so its rows
        # match exactly; the root normalization aube needs would rewrite
        # every "/" of the emulated output.
        for field in ("timed_out", "exit", "stdout", "stderr"):
            if expected[field] != row[field]:
                raise ValueError(f"ripgrep-{case['name']}: {field} mismatch")
        if row.get("stop") != f"None\nOk(Exited({expected['exit']}))":
            raise ValueError(f"ripgrep-{case['name']}: guest did not exit by itself")
