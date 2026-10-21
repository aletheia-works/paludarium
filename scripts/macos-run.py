#!/usr/bin/env python3
"""macOS native-host entry point; Linux expectations are built before host changes."""

import argparse
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "tests/guests/macos"))
sys.path.insert(1, str(ROOT / "tests/guests/programs"))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--native-only", action="store_true")
    parser.add_argument("--original-argv", action="store_true")
    parser.add_argument("--guest-dir", type=pathlib.Path)
    parser.add_argument("--native", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path)
    parser.add_argument("--emulator", type=pathlib.Path)
    args = parser.parse_args()
    if args.self_test:
        from runner import run

        row = run([sys.executable, "-c", "pass"], cwd=ROOT, env={})
        if row["exit"] != 0 or row["timed_out"]:
            raise RuntimeError("macOS bounded runner not ready")
        print("macOS runner ready: fixed fourteen cases, external thirty-second deadline")
        return
    if args.native_only:
        if args.guest_dir is None or args.output is None or args.native is not None:
            parser.error("native-only requires --guest-dir --output; no --native")
        from native import observe
        from settings import configuration

        observe(
            args.guest_dir.resolve(),
            args.output.resolve(),
            configuration(ROOT, original=args.original_argv),
            prepare_fixture=lambda fixture: {},
        )
        return
    if (
        args.guest_dir is None
        or args.native is None
        or args.output is None
        or args.emulator is None
    ):
        parser.error("comparison requires --guest-dir --native --output --emulator")
    from host_comparison import observe

    observe(
        args.emulator.resolve(),
        args.guest_dir.resolve(),
        args.native.resolve(),
        args.output.resolve(),
        ROOT,
        original=args.original_argv,
    )


if __name__ == "__main__":
    main()
