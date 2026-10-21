"""Fresh Linux native first, then strict CLI comparison of both frame fixtures."""

import argparse
import hashlib
import json
import math
import os
import platform
import resource
import signal
import subprocess
import time
from pathlib import Path


def execute(command):
    started = time.monotonic()
    child = subprocess.Popen(
        command,
        env={},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    timeout = False
    try:
        stdout, stderr = child.communicate(timeout=30)
    except subprocess.TimeoutExpired:
        timeout = True
        os.killpg(child.pid, signal.SIGKILL)
        stdout, stderr = child.communicate()
    return (
        {"exit": child.returncode, "timeout": timeout, "seconds": time.monotonic() - started},
        stdout,
        stderr,
    )


def compare(native, emulated):
    for result in (native, emulated):
        row = result[0]
        seconds = row["seconds"]
        if (
            type(row["timeout"]) is not bool
            or row["timeout"]
            or type(row["exit"]) is not int
            or row["exit"] != 0
            or type(seconds) not in (int, float)
            or not math.isfinite(seconds)
            or not 0 <= seconds <= 30
        ):
            raise ValueError("nonzero exit, signal or deadline violation")
    if native[1:] != emulated[1:]:
        raise ValueError("native/emulated stdout or stderr differs")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--guests", type=Path, required=True)
    parser.add_argument("--emulator", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--runs", type=int, default=100)
    args = parser.parse_args()
    if not 1 <= args.runs <= 100:
        parser.error("runs must be 1..100")
    args.output.mkdir(parents=True, exist_ok=False)
    receipt = {
        "schemaVersion": 1,
        "head": os.environ.get("GITHUB_SHA"),
        "runs": [],
        "fixtures": {},
        "environment": {},
        "native_first": True,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "compiler": subprocess.check_output(["rustc", "-Vv"], text=True),
        "guest_compiler": subprocess.check_output(["musl-gcc", "--version"], text=True),
        "stack_limits": list(resource.getrlimit(resource.RLIMIT_STACK)),
        "emulator_sha256": hashlib.sha256(args.emulator.read_bytes()).hexdigest(),
    }
    try:
        for name in ("insn-u2-frame", "insn-u2-frame-boundary"):
            program = (args.guests / name).resolve()
            receipt["fixtures"][name] = hashlib.sha256(program.read_bytes()).hexdigest()
            for index in range(args.runs):
                native = execute([str(program)])
                emulated = execute([str(args.emulator.resolve()), "--no-jit", str(program)])
                for kind, result in (("native", native), ("emulated", emulated)):
                    (args.output / f"{name}-{index:03}-{kind}.stdout").write_bytes(result[1])
                    (args.output / f"{name}-{index:03}-{kind}.stderr").write_bytes(result[2])
                receipt["runs"].append(
                    {
                        "fixture": name,
                        "index": index,
                        "argv0": str(program),
                        "native": native[0],
                        "emulated": emulated[0],
                    }
                )
                compare(native, emulated)
    finally:
        (args.output / "result.json").write_text(json.dumps(receipt, indent=2) + "\n")


if __name__ == "__main__":
    main()
