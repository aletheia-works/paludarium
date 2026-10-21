#!/usr/bin/env python3
"""Windows Host用入口。製品変更前のLinux期待値を先に取得する。"""

import argparse
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "tests/guests/windows"))
sys.path.insert(1, str(ROOT / "tests/guests/programs"))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--native-only", action="store_true")
    parser.add_argument("--original-argv", action="store_true")
    parser.add_argument("--guests", type=pathlib.Path)
    parser.add_argument("--native-report", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path)
    parser.add_argument("--emulator", type=pathlib.Path)
    args = parser.parse_args()
    if args.self_test:
        from runner import run

        row = run([sys.executable, "-c", "pass"], cwd=ROOT, env={})
        if row["exit"] != 0 or row["timed_out"]:
            raise RuntimeError("Windows bounded runner not ready")
        print("Windows Linux runner ready: fixed fourteen cases, thirty-second deadline")
        return
    if args.native_only:
        if args.guests is None or args.output is None or args.native_report is not None:
            parser.error("native-only requires --guests --output; no --native-report")
        from native import observe
        from settings import configuration

        observe(
            args.guests.resolve(),
            args.output.resolve(),
            configuration(ROOT, original=args.original_argv),
            prepare_fixture=lambda fixture: {},
        )
        return
    if (
        args.guests is None
        or args.native_report is None
        or args.output is None
        or args.emulator is None
    ):
        parser.error("comparison requires --guests --native-report --output --emulator")
    from host_comparison import observe

    observe(
        args.emulator.resolve(),
        args.guests.resolve(),
        args.native_report.resolve(),
        args.output.resolve(),
        ROOT,
        original=args.original_argv,
    )


if __name__ == "__main__":
    main()
