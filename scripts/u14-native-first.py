#!/usr/bin/env python3
"""Named U14 Linux oracle generator: observations are CI outputs, never fixtures."""

import argparse
import hashlib
import json
import os
import pathlib
import platform
import signal
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "tests/guests/u14"))
from validation import validate  # noqa: E402


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()
    if platform.system() != "Linux" or platform.machine() not in ("x86_64", "amd64"):
        parser.error("native expectations require real x86-64 Linux")
    started = time.monotonic()
    with subprocess.Popen(
        [str(args.binary.resolve())],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    ) as process:
        try:
            stdout, stderr = process.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
            raise RuntimeError("native process group exceeded thirty seconds") from None
        exit_code = process.returncode
    seconds = time.monotonic() - started
    rows = validate(stdout, seconds=seconds, exit_code=exit_code)
    if stderr:
        raise ValueError("native oracle emitted unexpected stderr")
    source = ROOT / "tests/guests/u14/native.c"
    report = {
        "schema": 1,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "seconds": seconds,
        "exit": exit_code,
        "rows": rows,
        "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "binary_sha256": hashlib.sha256(args.binary.read_bytes()).hexdigest(),
        "stdout": stdout,
        "stderr": stderr,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"cases": len(rows), "exit": exit_code, "seconds": seconds}))


if __name__ == "__main__":
    main()
