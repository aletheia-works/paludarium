"""Bounded Linux investigation of the saved native frame fixture, never a gate."""

import argparse
import hashlib
import json
import os
import shutil
import signal
import subprocess
import time
import zipfile
from pathlib import Path

ARCHIVE_SHA = "2cc5ed39794b4843a135f53973b8e4bb459897f3ac7ecb5abd067560d66b04c0"
ELF_SHA = "dfedbf0f55cf178e8ffce037fd706100ad05b0f1051a01a2ab787c37c1b8481b"


def capture_commands():
    # Execute the original ELF directly. The previous env wrapper combined with
    # disabled shell startup reported exit during startup in every observation.
    # GDB itself receives an empty environment instead of wrapping the inferior.
    return (
        "set pagination off\nset confirm off\nset disable-randomization off\n"
        "set startup-with-shell off\n"
        "handle SIGSEGV stop print nopass\nrun\npython\n"
        "if gdb.selected_inferior().threads():\n"
        "    for command in ('info registers', 'x/32gx $rsp', 'x/16i $rip', 'bt'):\n"
        "        gdb.execute(command)\n"
        "else:\n"
        "    print('DIAGNOSTIC_NORMAL_EXIT_NO_REGISTERS')\n"
        "end\nquit\n"
    )


def original(archive):
    raw = archive.read_bytes()
    if hashlib.sha256(raw).hexdigest() != ARCHIVE_SHA:
        raise ValueError("initial artifact archive digest mismatch")
    with zipfile.ZipFile(archive) as saved:
        elf = saved.read("guests/insn-forms-frame")
    if hashlib.sha256(elf).hexdigest() != ELF_SHA:
        raise ValueError("initial native ELF digest mismatch")
    return elf


def bounded(command, *, environment=None, executable=None):
    started = time.monotonic()
    child = subprocess.Popen(
        command,
        env=environment,
        executable=executable,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        out, err = child.communicate(timeout=30)
        return out, err, child.returncode, False, time.monotonic() - started
    except subprocess.TimeoutExpired:
        os.killpg(child.pid, signal.SIGKILL)
        out, err = child.communicate()
        return out, err, None, True, time.monotonic() - started


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--runs", type=int, default=50)
    args = parser.parse_args()
    if not 1 <= args.runs <= 100:
        parser.error("runs must be 1..100")
    elf = original(args.archive)
    args.output.mkdir(parents=True, exist_ok=False)
    binary = (args.output / "insn-forms-frame").resolve()
    binary.write_bytes(elf)
    binary.chmod(0o755)
    metadata = {
        "archive_sha256": ARCHIVE_SHA,
        "elf_sha256": ELF_SHA,
        "environment": {},
        "stdin": "null",
        "stdout": "pipe",
        "stderr": "pipe",
        "argv0": "insn-forms-frame",
        "historical_coverage_parent": "not reconstructed",
        "cause": "unresolved",
        "runs": [],
    }
    for label, command in (
        ("uname", ["uname", "-a"]),
        ("cpu", ["lscpu"]),
        ("gdb-version", ["gdb", "--version"]),
        ("readelf", ["readelf", "-a", str(binary)]),
        ("disassembly", ["objdump", "-d", str(binary)]),
        (
            "kernel-settings",
            [
                "sh",
                "-c",
                "ulimit -a; cat /proc/sys/kernel/randomize_va_space /proc/sys/kernel/core_pattern",
            ],
        ),
    ):
        out, err, code, timeout, elapsed = bounded(command)
        (args.output / f"{label}.stdout").write_bytes(out)
        (args.output / f"{label}.stderr").write_bytes(err)
        metadata[label] = {"exit": code, "timeout": timeout, "seconds": elapsed}
        if code != 0 or timeout:
            (args.output / "result.json").write_text(json.dumps(metadata, indent=2) + "\n")
            raise RuntimeError(f"diagnostic prerequisite {label} failed")
    # Normal ASLR first, identical environment clearing/pipes to run_native.
    # The debugger phase is explicitly auxiliary: observer effects are not parity.
    for index in range(args.runs):
        out, err, code, timeout, elapsed = bounded(
            ["insn-forms-frame"], environment={}, executable=str(binary)
        )
        (args.output / f"native-{index:03}.stdout").write_bytes(out)
        (args.output / f"native-{index:03}.stderr").write_bytes(err)
        metadata["runs"].append(
            {"index": index, "exit": code, "timeout": timeout, "seconds": elapsed}
        )
        if timeout:
            break
    gdb_script = args.output / "capture.gdb"
    gdb_script.write_text(capture_commands())
    gdb_binary = shutil.which("gdb")
    if gdb_binary is None:
        raise RuntimeError("GDB executable missing after prerequisite check")
    # Use the remaining budget for debugger fault capture even if these native
    # runs did not signal. No initial core was saved; no reproduction resolves nothing.
    metadata["initial_core_available"] = False
    budget = 100 - len(metadata["runs"])
    attempts = budget
    metadata["debugger"] = []
    for index in range(attempts):
        out, err, code, timeout, elapsed = bounded(
            [gdb_binary, "--batch", "-x", str(gdb_script), str(binary)], environment={}
        )
        (args.output / f"debugger-{index:03}.stdout").write_bytes(out)
        (args.output / f"debugger-{index:03}.stderr").write_bytes(err)
        metadata["debugger"].append(
            {"exit": code, "timeout": timeout, "seconds": elapsed, "auxiliary": True}
        )
        if timeout or b"Program received signal SIGSEGV" in out:
            break
    (args.output / "result.json").write_text(json.dumps(metadata, indent=2) + "\n")


if __name__ == "__main__":
    main()
