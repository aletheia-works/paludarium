"""Thirty-second whole-test boundary including compiler and Node descendants."""

import json
import os
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tests/guests/wasm"))
from supervisor import supervise  # noqa: E402

os.environ["PALUDARIUM_U14_INSTRUCTION_CHILD"] = "1"
result = supervise(
    [sys.argv[1], "--exact", "u14_fresh_linux_instruction_differential", "--nocapture"],
    cwd=ROOT,
    seconds=30,
)
print(result["stdout"], end="")
print(result["stderr"], end="", file=sys.stderr)
print(
    json.dumps(
        {key: result[key] for key in ("exit", "seconds", "timed_out", "process_group_cleaned")}
    )
)
if result["exit"] != 0 or result["timed_out"] or not result["process_group_cleaned"]:
    raise SystemExit(1)
