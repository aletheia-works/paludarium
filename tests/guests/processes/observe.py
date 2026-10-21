"""Fresh x86-64 Linux processes oracle; never read checked-in expectations."""

import argparse
import hashlib
import json
import os
import platform
import signal
import subprocess
import sys
import time
from pathlib import Path


def run(command, timeout=30):
    started = time.monotonic()
    process = subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True, env={}
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        os.killpg(process.pid, signal.SIGKILL)
        process.communicate()
        raise RuntimeError(f"Timed out: {command}") from error
    return {
        "stdout": stdout.hex(),
        "stderr": stderr.hex(),
        "status": process.returncode,
        "timeout": False,
        "elapsed": time.monotonic() - started,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--native-only", action="store_true", required=True)
    parser.add_argument("--cases", type=Path, required=True)
    parser.add_argument("--guest-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--trace", action="store_true")
    args = parser.parse_args()
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise RuntimeError("Native expectations require an x86-64 Linux runner")
    rows = []
    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
    for case in json.loads(args.cases.read_text())["cases"]:
        binary = (args.guest_dir / case["binary"]).resolve()
        command = [str(binary), case["name"], str(binary)]
        result = run(command)
        if result["status"] != 0:
            raise RuntimeError(f"{case['name']}: unsuccessful oracle {result}")
        row = {
            **case,
            "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "native": result,
        }
        rows.append(row)
        print(json.dumps(row), flush=True)
        if args.out:
            (args.out / f"{case['name']}.json").write_text(json.dumps(row, indent=2))
            if args.trace:
                traced = run(
                    [
                        "/usr/bin/strace",
                        "-f",
                        "-o",
                        str(args.out.resolve() / f"{case['name']}.strace"),
                        *command,
                    ]
                )
                if traced["status"] != 0:
                    raise RuntimeError(f"Trace failed: {case['name']}: {traced}")
    if args.out:
        (args.out / "manifest.json").write_text(
            json.dumps(
                {"platform": platform.platform(), "machine": platform.machine(), "cases": rows},
                indent=2,
            )
        )
    print(f"processes native oracle: {len(rows)} cases passed")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from None
