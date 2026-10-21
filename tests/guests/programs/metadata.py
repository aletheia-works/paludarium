"""Short native Linux stat oracle before the C10 bootstrap mode change."""

import json
import os
import pathlib
import platform
import shutil
import stat
import sys
import tempfile

from runner import run

HERE = pathlib.Path(__file__).resolve().parent


def fixture_inputs(directory):
    result = {}
    for source, guest in [
        ("app/package.json", "/package.json"),
        ("app/filedep/package.json", "/filedep/package.json"),
        ("outside/linked/package.json", "/outside/linked/package.json"),
    ]:
        result[guest] = stat.S_IMODE((directory / source).stat().st_mode)
    if len(result) != 3 or any(mode != 0o644 for mode in result.values()):
        raise ValueError("fixture metadata changed from native 0644 inputs")
    return result


def child(directory):
    fixture_modes = {
        str(p.relative_to(directory)): p.stat().st_mode
        for p in sorted(directory.rglob("package.json"))
    }
    if len(fixture_modes) != 3 or any(
        mode != stat.S_IFREG | 0o644 for mode in fixture_modes.values()
    ):
        raise ValueError("native fixture files are not regular 0644 files")
    target = directory / "mode-boundary"
    target.write_bytes(b"unchanged bytes")
    boundaries = {}
    for mode in (0o755, 0o644, 0):
        target.chmod(mode)
        actual = target.stat().st_mode
        if actual != stat.S_IFREG | mode:
            raise ValueError("native stat type/permission mismatch")
        boundaries[str(mode)] = actual
    print(json.dumps({"fixture_modes": fixture_modes, "mode_boundaries": boundaries}))


def observe(output):
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise RuntimeError("metadata oracle requires x86-64 Linux")
    if os.readlink("/proc/self/ns/net") == os.readlink("/proc/1/ns/net"):
        raise RuntimeError("metadata oracle requires isolated network namespace")
    with tempfile.TemporaryDirectory(prefix="u10-native-metadata-") as temporary:
        directory = pathlib.Path(temporary) / "fixture"
        shutil.copytree(HERE / "fixtures", directory)
        result = run(
            [sys.executable, str(HERE / "metadata.py"), "--child", str(directory)],
            cwd=directory,
            env={"PATH": "/no-node"},
            timeout=30,
        )
        output.parent.mkdir(parents=True, exist_ok=True)
        receipt = {"machine": platform.platform(), "result": result}
        if result["exit"] == 0 and not result["timed_out"]:
            receipt["native_stat"] = json.loads(result["stdout"])
        output.write_text(json.dumps(receipt, indent=2) + "\n")
        print(json.dumps(receipt), flush=True)
        if result["exit"] != 0 or result["timed_out"]:
            raise ValueError("native metadata oracle failed")


if __name__ == "__main__":
    if sys.argv[1] == "--child":
        child(pathlib.Path(sys.argv[2]))
    else:
        observe(pathlib.Path(sys.argv[1]))
