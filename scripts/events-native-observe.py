"""Events native-first/differential runner with independent process-group watchdogs."""

import argparse
import contextlib
import hashlib
import json
import os
import platform
import signal
import struct
import subprocess
from pathlib import Path


def run(command, prefix, timeout=30):
    child = subprocess.Popen(
        command,
        start_new_session=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    timed_out = False
    try:
        stdout, stderr = child.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        os.killpg(child.pid, signal.SIGKILL)
        stdout, stderr = child.communicate()
    # Reap every member of this group, even when the leader exited first.
    with contextlib.suppress(ProcessLookupError):
        os.killpg(child.pid, signal.SIGKILL)
    prefix.with_suffix(".stdout").write_bytes(stdout)
    prefix.with_suffix(".stderr").write_bytes(stderr)
    result = dict(
        exit=child.returncode, timeout=timed_out, stdout=stdout.hex(), stderr=stderr.hex()
    )
    prefix.with_suffix(".json").write_text(json.dumps(result, indent=2) + "\n")
    if timed_out:
        raise RuntimeError(f"{command}: 30-second process-group watchdog expired")
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--guests", type=Path, default=Path("target/guests/events"))
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--emulator", type=Path)
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument("--case", choices=[str(n) for n in range(82)] + ["timer", "unix"])
    args = parser.parse_args()
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise RuntimeError("Native expectations require an x86-64 Linux runner")
    args.out.mkdir(parents=True, exist_ok=True)
    results = []
    cases = (
        [args.case]
        if args.case is not None
        else ([0] if args.smoke else [*list(range(82)), "timer", "unix"])
    )
    for case in cases:
        case = int(case) if str(case).isdigit() else case
        guest = args.guests / (f"event-{case}" if isinstance(case, int) else f"events-{case}")
        native = run([str(guest.resolve())], args.out / f"native-{case}")
        if native["exit"] != (-9 if case == 60 else 0) or native["stderr"]:
            raise RuntimeError(f"Unexpected native case {case}: {native}")
        result = dict(
            case=case, binary_sha256=hashlib.sha256(guest.read_bytes()).hexdigest(), native=native
        )
        if args.emulator:
            emulated = run(
                [str(args.emulator.resolve()), str(guest.resolve())], args.out / f"emulated-{case}"
            )
            result["emulated"] = emulated
            if case in (52, 53, 54):
                expected = dict(
                    exit=0,
                    timeout=False,
                    stdout=struct.pack("<qqqq", -97, 0, 0, 0).hex(),
                    stderr="",
                )
                if emulated != expected:
                    raise RuntimeError(f"Network policy case {case}: {emulated}")
                result["policy_exception"] = "AF_INET/AF_INET6 unavailable: EAFNOSUPPORT"
            elif case == 60:
                expected = dict(native, exit=137)
                if emulated != expected:
                    raise RuntimeError(f"SIGKILL CLI exit mapping: {emulated}")
                result["normalization"] = "native -9 => CLI 128+9"
            elif native != emulated:
                raise RuntimeError(f"Differential mismatch case {case}: {result}")
        results.append(result)
        data = bytes.fromhex(native["stdout"])
        words = (
            struct.unpack("<" + "q" * (len(data) // 8), data) if len(data) % 8 == 0 else data.hex()
        )
        print(f"case {case}: exit={native['exit']} words={words}", flush=True)
    (args.out / "manifest.json").write_text(json.dumps(results, indent=2) + "\n")


if __name__ == "__main__":
    main()
