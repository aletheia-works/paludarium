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


def translated(row):
    for key in ("executedBlocks", "executedInstructions"):
        value = row.get("jit", {}).get(key)
        if (
            not isinstance(value, str)
            or not value.isascii()
            or not value.isdecimal()
            or int(value) <= 0
        ):
            raise ValueError("JIT real translation execution missing")


def finished(row, exit_ok):
    seconds = row.get("seconds")
    if (
        type(seconds) not in (int, float)
        or not 0 <= seconds <= 30
        or type(row.get("exit")) is not int
        or not exit_ok(row["exit"])
        or row.get("timed_out") is not False
        or row.get("pass") is not True
        or not isinstance(row.get("errors"), list)
        or row.get("errors")
    ):
        raise ValueError("JIT guest failure or deadline")


def validate(report):
    if (
        report.get("complete") is not True
        or report.get("passed") is not True
        or report.get("caseCount") != 28
    ):
        raise ValueError("JIT suite incomplete or failed")
    if set(report.get("rows", {})) != {"interpreter", "jit"}:
        raise ValueError("JIT execution mode inventory changed")
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
            raise ValueError("JIT case inventory changed")
        for row in rows.values():
            finished(row, lambda code: code == 0)
            if mode == "jit":
                translated(row)
    # The aube steps again, each on a filesystem rebuilt from its snapshot.
    if set(report.get("restored", {})) != {"interpreter", "jit"}:
        raise ValueError("JIT restored mode inventory changed")
    for mode in ("interpreter", "jit"):
        rows = report["restored"][mode]
        if sorted(rows) != sorted(expected[-4:]):
            raise ValueError("JIT restored case inventory changed")
        for row in rows.values():
            finished(row, lambda code: code == 0)
            if mode == "jit":
                translated(row)
    # The ripgrep searches, kept apart from the 28 cases; some end with 1 or 2.
    cases = json.loads((ROOT / "tests/guests/programs/ripgrep-cases.json").read_text())["cases"]
    if set(report.get("ripgrep", {})) != {"interpreter", "jit"}:
        raise ValueError("JIT ripgrep mode inventory changed")
    for mode in ("interpreter", "jit"):
        rows = report["ripgrep"][mode]
        # Safari's WebDriver returns the report without its key order.
        if sorted(rows) != sorted(case["name"] for case in cases):
            raise ValueError("JIT ripgrep case inventory changed")
        for row in rows.values():
            finished(row, lambda code: code in (0, 1, 2))
            if mode == "jit":
                translated(row)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--environment", required=True, choices=("node", "chromium", "firefox", "safari", "webkit")
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
        raise RuntimeError("JIT supervised acceptance failed; partial rows retained")
    validate(json.loads((args.output / "observations.json").read_text()))


if __name__ == "__main__":
    main()
