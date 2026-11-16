#!/usr/bin/env python3
"""Builds the x87 guest of the process cases and writes what it prints on
this x86-64 Linux CPU, which the wasm environments are then compared with.

    python3 tests/guests/wasm/x87.py <output directory>

The guest is built by the very line of tests/guests/processes/build.sh that
builds it for the differential process cases, and each case is the guest run
with its name, as those cases run it.
"""

import hashlib
import json
import pathlib
import platform
import shlex
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[3]
CASES = pathlib.Path(__file__).resolve().parent / "x87-cases.json"
BUILD = ROOT / "tests/guests/processes/build.sh"


def build_command(output):
    """build.sh's command for the x87 guest, writing it into output."""
    lines = [line for line in BUILD.read_text().splitlines() if '-o "$out/x87" ' in line]
    if len(lines) != 1:
        raise SystemExit("build.sh must build the x87 guest on exactly one line")
    here = str(BUILD.parent)
    return [
        word.replace("$out", str(output)).replace("$here", here) for word in shlex.split(lines[0])
    ]


def cpu():
    for line in pathlib.Path("/proc/cpuinfo").read_text().splitlines():
        if line.startswith("model name"):
            return line.split(":", 1)[1].strip()
    return "unknown"


def main():
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise SystemExit("the x87 results must come from x86-64 Linux")
    output = pathlib.Path(sys.argv[1]).resolve()
    output.mkdir(parents=True, exist_ok=True)
    config = json.loads(CASES.read_text())
    binary = output / config["binary"]
    if binary.name != "x87":
        raise SystemExit("build.sh writes the x87 guest as x87")
    subprocess.run(build_command(output), check=True)
    rows = {}
    for name in config["cases"]:
        started = time.monotonic()
        result = subprocess.run(
            [str(binary), name],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=30,
            env={},
        )
        rows[name] = {
            "stdout": result.stdout.decode(),
            "stderr": result.stderr.decode(),
            "exit": result.returncode,
            "seconds": time.monotonic() - started,
        }
        if result.returncode != 0:
            raise SystemExit(f"{name} exited with {result.returncode} natively")
    native = {
        "schema": 1,
        "cpu": cpu(),
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "rows": rows,
    }
    (output / "native.json").write_text(json.dumps(native, indent=2) + "\n")
    print(json.dumps({"cpu": native["cpu"], "cases": list(rows)}))


if __name__ == "__main__":
    main()
