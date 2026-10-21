"""Acquire fresh native x86-64 results for the production wasm fixtures."""

import hashlib
import json
import pathlib
import platform
import subprocess
import time

assert platform.system() == "Linux" and platform.machine() == "x86_64"
root = pathlib.Path(__file__).resolve().parents[1] / "packages/paludarium-wasm/tests/guests"
rows = []
for name in (
    "atomic",
    "divide_fault",
    "hello",
    "infinite",
    "integer",
    "stdin",
    *sorted(path.name for path in root.iterdir() if path.name.startswith("encodings-")),
):
    guest = root / name
    guest.chmod(0o755)
    if name == "infinite":
        process = subprocess.Popen([str(guest)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            time.sleep(0.05)
            process.kill()
            stdout, stderr = process.communicate(timeout=30)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=1)
        code = process.returncode
    else:
        result = subprocess.run(
            [str(guest)],
            input=b"input\n" if name == "stdin" else b"",
            capture_output=True,
            timeout=30,
            check=False,
        )
        stdout, stderr, code = result.stdout, result.stderr, result.returncode
    if name.startswith("encodings-"):
        assert code == (-8 if name == "encodings-fault" else 0), (
            f"{name}: native feature/fixture failed, exit {code}"
        )
    rows.append(
        dict(
            name=name,
            sha256=hashlib.sha256(guest.read_bytes()).hexdigest(),
            returncode=code,
            stdout=stdout.hex(),
            stderr=stderr.hex(),
            timed_out=False,
        )
    )
print(json.dumps(rows, indent=2))
