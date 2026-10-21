"""Whole-suite process boundary, separate from each guest's 30-second deadline."""

import contextlib
import os
import signal
import subprocess
import time


def supervise(command, *, cwd, seconds=600):
    if not command or not 0 < seconds <= 1200:
        raise ValueError("invalid suite command or bounded suite deadline")
    started = time.monotonic()
    child = subprocess.Popen(
        command,
        cwd=cwd,
        start_new_session=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    timed_out = False
    try:
        try:
            stdout, stderr = child.communicate(timeout=seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(child.pid, signal.SIGKILL)
            stdout, stderr = child.communicate(timeout=5)
    finally:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(child.pid, signal.SIGKILL)
        child.wait(timeout=5)
    return {
        "exit": child.returncode,
        "timed_out": timed_out,
        "stdout": stdout.decode("utf8", errors="replace"),
        "stderr": stderr.decode("utf8", errors="replace"),
        "seconds": time.monotonic() - started,
        "process_group_cleaned": True,
    }
