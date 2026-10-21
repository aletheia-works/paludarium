"""U13の30秒supervisor。Windowsのjobと既存Unix process groupを分ける。"""

import importlib.util
import math
import pathlib
import sys


def run(command, *, cwd, env, timeout=30):
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 30:
        raise ValueError("guest deadline must be finite and at most thirty seconds")
    if sys.platform == "win32":
        from windows_job import run as supervise
    else:
        path = pathlib.Path(__file__).resolve().parents[1] / "u10/runner.py"
        spec = importlib.util.spec_from_file_location("u13_unix_supervisor", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        supervise = module.run
    return supervise(command, cwd=cwd, env=env, timeout=timeout)
