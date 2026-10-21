"""Bounded guest process management, with Linux descendant reaping."""

import contextlib
import ctypes
import os
import signal
import subprocess
import sys
import time


def enable_reaping():
    if sys.platform == "linux":
        # PR_SET_CHILD_SUBREAPER makes orphaned grandchildren waitable here.
        if ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "cannot enable descendant reaping")


def cleanup_group(pid):
    with contextlib.suppress(ProcessLookupError):
        os.killpg(pid, signal.SIGKILL)


def reap_group(pid):
    if sys.platform != "linux":
        return
    deadline = time.monotonic() + 2
    while True:
        try:
            child, _ = os.waitpid(-pid, os.WNOHANG)
        except ChildProcessError:
            return
        if child == 0:
            if time.monotonic() >= deadline:
                raise RuntimeError("descendants were not reaped")
            time.sleep(0.005)


def run(command, *, cwd, env, timeout=30):
    if not 0 < timeout <= 30:
        raise ValueError("guest deadline must be at most 30 seconds")
    enable_reaping()
    started = time.monotonic()
    child = subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
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
        cleanup_group(child.pid)
        stdout, stderr = child.communicate(timeout=2)
    finally:
        cleanup_group(child.pid)
        child.wait()
        reap_group(child.pid)
    return {
        "stdout": stdout.decode("utf-8", errors="strict"),
        "stderr": stderr.decode("utf-8", errors="strict"),
        "exit": child.returncode,
        "timed_out": timed_out,
        "wall_seconds": time.monotonic() - started,
    }
