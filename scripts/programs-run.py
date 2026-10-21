#!/usr/bin/env python3
"""Fixed guest programs entry point; observations are generated anew, never used as golden files."""

import argparse
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests/guests/programs"))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--native-only", action="store_true")
    parser.add_argument("--guest-dir", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()
    config = json.loads((ROOT / "tests/guests/programs/cases.json").read_text())
    if config["deadline_seconds"] != 30 or config["schema"] != 1:
        raise ValueError("invalid fixed guest programs runner contract")
    if args.self_test:
        from runner import run

        result = run([sys.executable, "-c", "pass"], cwd=ROOT, env={})
        if result["exit"] != 0 or result["timed_out"]:
            raise RuntimeError("bounded runner is not ready")
        print("fixed guest programs runner ready: schema 1, 30-second operation deadline")
        return
    if not args.native_only or args.guest_dir is None or args.output is None:
        parser.error("provide --native-only --guest-dir --output")
    from native import observe

    observe(args.guest_dir.resolve(), args.output.resolve(), config)


if __name__ == "__main__":
    main()
