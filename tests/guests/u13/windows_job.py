"""停止中にjobへ割り当て、子孫を含めて停止・回収するWindows supervisor。"""

import ctypes
import os
import subprocess
import time

DWORD = ctypes.c_uint32
HANDLE = ctypes.c_void_p


class Limits(ctypes.Structure):
    _fields_ = [
        ("process_time", ctypes.c_int64),
        ("job_time", ctypes.c_int64),
        ("flags", DWORD),
        ("minimum", ctypes.c_size_t),
        ("maximum", ctypes.c_size_t),
        ("active_limit", DWORD),
        ("affinity", ctypes.c_size_t),
        ("priority", DWORD),
        ("scheduling", DWORD),
    ]


class Io(ctypes.Structure):
    _fields_ = [
        (name, ctypes.c_uint64)
        for name in (
            "read_ops",
            "write_ops",
            "other_ops",
            "read_bytes",
            "write_bytes",
            "other_bytes",
        )
    ]


class ExtendedLimits(ctypes.Structure):
    _fields_ = [
        ("basic", Limits),
        ("io", Io),
        ("process_memory", ctypes.c_size_t),
        ("job_memory", ctypes.c_size_t),
        ("peak_process", ctypes.c_size_t),
        ("peak_job", ctypes.c_size_t),
    ]


class Accounting(ctypes.Structure):
    _fields_ = [
        ("user", ctypes.c_int64),
        ("kernel", ctypes.c_int64),
        ("period_user", ctypes.c_int64),
        ("period_kernel", ctypes.c_int64),
        ("faults", DWORD),
        ("total", DWORD),
        ("active", DWORD),
        ("terminated", DWORD),
    ]


class ThreadEntry(ctypes.Structure):
    _fields_ = [
        ("size", DWORD),
        ("usage", DWORD),
        ("thread", DWORD),
        ("process", DWORD),
        ("base", ctypes.c_int32),
        ("delta", ctypes.c_int32),
        ("flags", DWORD),
    ]


def api():
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    declarations = {
        "CreateJobObjectW": ([HANDLE, ctypes.c_wchar_p], HANDLE),
        "SetInformationJobObject": ([HANDLE, ctypes.c_int, HANDLE, DWORD], ctypes.c_int),
        "AssignProcessToJobObject": ([HANDLE, HANDLE], ctypes.c_int),
        "TerminateJobObject": ([HANDLE, ctypes.c_uint], ctypes.c_int),
        "QueryInformationJobObject": ([HANDLE, ctypes.c_int, HANDLE, DWORD, HANDLE], ctypes.c_int),
        "CreateToolhelp32Snapshot": ([DWORD, DWORD], HANDLE),
        "Thread32First": ([HANDLE, ctypes.POINTER(ThreadEntry)], ctypes.c_int),
        "Thread32Next": ([HANDLE, ctypes.POINTER(ThreadEntry)], ctypes.c_int),
        "OpenThread": ([DWORD, ctypes.c_int, DWORD], HANDLE),
        "ResumeThread": ([HANDLE], DWORD),
        "CloseHandle": ([HANDLE], ctypes.c_int),
    }
    for name, (args, result) in declarations.items():
        function = getattr(kernel, name)
        function.argtypes, function.restype = args, result
    return kernel


def checked(value, operation):
    if not value:
        raise ctypes.WinError(ctypes.get_last_error(), operation)
    return value


def resume_primary(kernel, pid):
    snapshot = kernel.CreateToolhelp32Snapshot(4, 0)
    if snapshot in (None, ctypes.c_void_p(-1).value):
        raise ctypes.WinError(ctypes.get_last_error(), "thread snapshot")
    try:
        row = ThreadEntry()
        row.size = ctypes.sizeof(row)
        present = kernel.Thread32First(snapshot, ctypes.byref(row))
        threads = []
        while present:
            if row.process == pid:
                threads.append(row.thread)
            row.size = ctypes.sizeof(row)
            present = kernel.Thread32Next(snapshot, ctypes.byref(row))
        if ctypes.get_last_error() != 18 or len(threads) != 1:
            raise RuntimeError("suspended child must have exactly one primary thread")
        thread = checked(kernel.OpenThread(2, False, threads[0]), "open primary thread")
        try:
            if kernel.ResumeThread(thread) != 1:
                raise RuntimeError("unexpected primary suspension count")
        finally:
            checked(kernel.CloseHandle(thread), "close primary thread")
    finally:
        checked(kernel.CloseHandle(snapshot), "close thread snapshot")


def drain_job(kernel, job):
    checked(kernel.TerminateJobObject(job, 1), "stop descendants")
    deadline = time.monotonic() + 2
    while True:
        counts = Accounting()
        checked(
            kernel.QueryInformationJobObject(
                job, 1, ctypes.byref(counts), ctypes.sizeof(counts), None
            ),
            "query descendants",
        )
        if counts.active == 0:
            return
        if time.monotonic() >= deadline:
            raise RuntimeError("Windows job descendants were not reaped")
        time.sleep(0.005)


def run(command, *, cwd, env, timeout=30):
    if type(timeout) not in (int, float) or not 0 < timeout <= 30:
        raise ValueError("guest deadline must be at most thirty seconds")
    started = time.monotonic()
    kernel = api()
    job = checked(kernel.CreateJobObjectW(None, None), "create bounded job")
    child = None
    assigned = False
    timed_out = False
    environment = dict(env)
    # Windows process loading requires SystemRoot for side-by-side assemblies.
    # This is the host supervisor environment, separate from the guest Config.
    if not any(key.casefold() == "systemroot" for key in environment):
        environment["SystemRoot"] = os.environ["SystemRoot"]  # noqa: SIM112 (the Windows name)
    try:
        limits = ExtendedLimits()
        limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE; no breakaway.
        checked(
            kernel.SetInformationJobObject(job, 9, ctypes.byref(limits), ctypes.sizeof(limits)),
            "set job lifetime",
        )
        child = subprocess.Popen(
            command,
            cwd=cwd,
            env=environment,
            creationflags=4,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        checked(kernel.AssignProcessToJobObject(job, int(child._handle)), "assign suspended child")
        assigned = True
        resume_primary(kernel, child.pid)
        remaining = timeout - (time.monotonic() - started)
        if remaining <= 0:
            raise subprocess.TimeoutExpired(command, timeout)
        try:
            stdout, stderr = child.communicate(timeout=remaining)
        except subprocess.TimeoutExpired:
            timed_out = True
            drain_job(kernel, job)
            stdout, stderr = child.communicate(timeout=2)
    finally:
        try:
            if child is not None:
                if assigned:
                    drain_job(kernel, job)
                elif child.poll() is None:
                    child.kill()
                child.wait(timeout=2)
                if child.stdout is not None:
                    child.stdout.close()
                if child.stderr is not None:
                    child.stderr.close()
        finally:
            checked(kernel.CloseHandle(job), "close bounded job")
    return {
        "stdout": stdout.decode("utf-8", errors="strict"),
        "stderr": stderr.decode("utf-8", errors="strict"),
        "exit": child.returncode,
        "timed_out": timed_out,
        "wall_seconds": time.monotonic() - started,
    }
