#!/usr/bin/env python3
"""Bounded real on/off guest acceptance; raw partial failures always retained."""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "tests/guests/wasm"))
from supervisor import supervise  # noqa: E402


def validate(report):
    if (
        report.get("complete") is not True
        or report.get("passed") is not True
        or report.get("caseCount") != 28
    ):
        raise ValueError("U14 suite incomplete or failed")
    if set(report.get("rows", {})) != {"interpreter", "jit"}:
        raise ValueError("U14 execution mode inventory changed")
    expected = [
        "probe-" + name
        for name in (
            "tokio-timer",
            "unix-stream-pair",
            "rayon",
            "mutex-condvar",
            "fs-basic",
            "fs-hardlink",
            "fs-symlink",
            "fs-flock",
            "all",
            "environment",
        )
    ] + ["version", "install", "frozen", "list"]
    for mode in ("interpreter", "jit"):
        rows = report.get("rows", {}).get(mode, {})
        if list(rows) != expected:
            raise ValueError("U14 case inventory changed")
        for row in rows.values():
            seconds = row.get("seconds")
            if (
                type(seconds) not in (int, float)
                or not 0 <= seconds <= 30
                or type(row.get("exit")) is not int
                or row.get("exit") != 0
                or row.get("timed_out") is not False
                or row.get("pass") is not True
                or not isinstance(row.get("errors"), list)
                or row.get("errors")
            ):
                raise ValueError("U14 guest failure or deadline")
            if mode == "jit":
                for key in ("executedBlocks", "executedInstructions"):
                    value = row.get("jit", {}).get(key)
                    if (
                        not isinstance(value, str)
                        or not value.isascii()
                        or not value.isdecimal()
                        or int(value) <= 0
                    ):
                        raise ValueError("U14 real translation execution missing")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--environment", required=True, choices=("node", "chromium", "firefox", "safari")
    )
    for name in ("wasm", "native", "guests", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    result = supervise(
        [
            "node",
            str(ROOT / "packages/paludarium-wasm/tests/jit-check.mjs"),
            args.environment,
            str(args.wasm.resolve()),
            str(args.native.resolve()),
            str(args.guests.resolve()),
            str(args.output.resolve()),
        ],
        cwd=ROOT,
    )
    (args.output / "suite-supervisor.json").write_text(json.dumps(result, indent=2) + "\n")
    print(result["stdout"])
    print(result["stderr"], file=sys.stderr)
    if result["exit"] != 0 or result["timed_out"] or not result["process_group_cleaned"]:
        raise RuntimeError("U14 supervised acceptance failed; partial rows retained")
    validate(json.loads((args.output / "observations.json").read_text()))


if __name__ == "__main__":
    main()
