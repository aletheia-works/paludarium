#!/usr/bin/env python3
"""Wasm bounded test entry point; native oracle is generated afresh on Linux."""

import argparse
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "tests/guests/wasm"))
sys.path.insert(1, str(ROOT / "tests/guests/programs"))


def main():
    from settings import configuration

    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--native-only", action="store_true")
    parser.add_argument("--guest-dir", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path)
    parser.add_argument("--browser", choices=("chromium", "firefox", "safari", "webkit"))
    parser.add_argument("--wasm", type=pathlib.Path)
    parser.add_argument("--native", type=pathlib.Path)
    parser.add_argument("--baseline", action="store_true")
    parser.add_argument("--node", type=pathlib.Path)
    args = parser.parse_args()
    config = configuration(ROOT)
    if args.self_test:
        from runner import run

        row = run([sys.executable, "-c", "pass"], cwd=ROOT, env={})
        if row["exit"] != 0 or row["timed_out"]:
            raise RuntimeError("bounded test runner failed readiness")
        print("wasm runner ready: fresh native fourteen cases, 30-second external deadline")
        return
    if args.native_only:
        if args.guest_dir is None or args.output is None or args.browser:
            parser.error("native-only requires --guest-dir --output and no --browser")
        from evidence import digest
        from native import observe

        output = args.output.resolve()
        from fixture_metadata import prepare_epoch_fixture, snapshot_metadata

        observe(
            args.guest_dir.resolve(),
            output,
            config,
            extra_snapshot=snapshot_metadata,
            prepare_fixture=prepare_epoch_fixture,
        )
        receipt = {
            "unit": "wasm-launcher",
            "native_oracle_sha256": digest(output / "observations.json"),
            "cases_sha256": digest(ROOT / "tests/guests/programs/cases.json"),
            "source_lock_sha256": digest(ROOT / "tests/guests/programs/source-lock.json"),
            "production_source_sha256": {
                path: digest(ROOT / path)
                for path in (
                    "crates/paludarium-runtime/src/lib.rs",
                    "crates/paludarium-runtime/src/workers.rs",
                    "crates/paludarium-host/src/wasm.rs",
                    "crates/paludarium-wasm/src/abi.rs",
                    "packages/paludarium-wasm/index.mjs",
                    "packages/paludarium-wasm/coordinator.mjs",
                    "packages/paludarium-wasm/relay-protocol.mjs",
                    "packages/paludarium-wasm/execution.mjs",
                    "packages/paludarium-wasm/worker-support.mjs",
                )
            },
        }
        (output / "wasm-oracle-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
        return
    if args.baseline:
        if (
            not all((args.node, args.wasm, args.native, args.guest_dir, args.output))
            or args.browser
        ):
            parser.error("baseline requires --node --wasm --native --guest-dir --output")
        from supervisor import supervise

        output = args.output.resolve()
        output.mkdir(parents=True, exist_ok=True)
        result = supervise(
            [
                str(args.node.resolve()),
                str(ROOT / "packages/paludarium-wasm/tests/wasm-baseline.mjs"),
                str(args.wasm.resolve()),
                str(args.native.resolve()),
                str(args.guest_dir.resolve()),
                str(output),
            ],
            cwd=ROOT,
        )
        (output / "suite-supervisor.json").write_text(json.dumps(result, indent=2) + "\n")
        print(
            json.dumps(
                {
                    key: result[key]
                    for key in ("exit", "timed_out", "seconds", "process_group_cleaned")
                }
            )
        )
        if result["exit"] != 0 or result["timed_out"]:
            raise RuntimeError("pre-U11 baseline suite failed; raw partial observations retained")
        return
    parser.error("browser runner is not implemented yet; no browser result is claimed")


if __name__ == "__main__":
    main()
