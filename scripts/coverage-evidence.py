"""Capture dedicated U9 raw coverage before a later clean replaces profiles.

This internal receipt deliberately has NO artifact ID/digest. The host joins
official GitHub metadata after upload; artifact self-digests are circular.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IGNORE = "paludarium-(cpu|decoder|mmu|loader|types|vfs|jit|harness)/"
PACKAGES = [
    "paludarium-host",
    "paludarium-kernel",
    "paludarium-runtime",
    "paludarium",
    "paludarium-harness",
]


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def need(value, message):
    if not value:
        raise ValueError(message)


def diff_counts(output):
    clean = re.sub(r"\x1b\[[0-9;]*m", "", output)
    sections = re.split(r"(?m)^[ \t]*Running[ \t]+", clean)
    matches = []
    for section in sections:
        first = section.splitlines()[0] if section.splitlines() else ""
        if not re.match(r"tests/diff_terminal\.rs \(", first):
            continue
        stack, outer = [], []
        for line in section.splitlines()[1:]:
            start = re.fullmatch(r"running (\d+) tests?", line)
            if start:
                need(stack or not outer, "duplicate diff_terminal outer harness")
                stack.append(int(start[1]))
                continue
            if not line.startswith("test result:"):
                continue
            summary = re.match(
                r"test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;",
                line,
            )
            need(summary and stack, "unmatched diff_terminal harness summary")
            passed, failed, ignored, measured, filtered = map(int, summary.groups()[1:])
            need(
                summary[1] == "ok"
                and failed == 0
                and ignored == 0
                and measured == 0
                and passed + failed + ignored + measured == stack.pop(),
                "diff_terminal harness failed/incomplete",
            )
            if not stack:
                need(filtered == 0, "outer diff_terminal filtered tests")
                outer.append((passed, ignored))
        need(not stack and len(outer) == 1, "diff_terminal result absent/ambiguous")
        matches.append(outer[0])
    need(
        len(matches) == 1 and matches[0][0] > 0 and matches[0][1] == 0,
        "diff_terminal zero/ignored/not executed",
    )
    return matches[0]


class Capture:
    def __init__(self, output):
        output.mkdir(parents=True, exist_ok=False)
        self.output = output
        self.commands = []

    def save(self, name, raw):
        with (self.output / name).open("xb") as stream:
            stream.write(raw)
        return dict(path=name, sha256=sha(raw), bytes=len(raw))

    def run(self, stage, argv, timeout=1800, merge=False):
        started = time.time()
        # Cargo writes suite identity to stderr and the test binary writes
        # its summary to stdout. Concatenating separately captured streams
        # destroys that ordering. Only the measured multi-suite invocation
        # uses one OS pipe; its exact merged bytes are retained as stdout.
        streams = (
            dict(stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            if merge
            else dict(capture_output=True)
        )
        try:
            r = subprocess.run(
                argv,
                cwd=ROOT,
                env={**os.environ, "RUST_TEST_THREADS": "1"},
                **streams,
                timeout=timeout,
                check=False,
            )
            row = dict(
                stage=stage,
                argv=argv,
                cwd=str(ROOT),
                started=started,
                ended=time.time(),
                exit=r.returncode,
                timed_out=False,
            )
            out, err = r.stdout, r.stderr or b""
        except subprocess.TimeoutExpired as error:
            out, err = error.stdout or b"", error.stderr or b""
            row = dict(
                stage=stage,
                argv=argv,
                cwd=str(ROOT),
                started=started,
                ended=time.time(),
                exit=None,
                timed_out=True,
            )
            row["stream_mode"] = "stderr-merged-into-stdout" if merge else "separate"
            row["stdout"] = self.save(stage + ".stdout", out)
            row["stderr"] = self.save(stage + ".stderr", err)
            self.commands.append(row)
            self.receipt()
            raise
        row["stream_mode"] = "stderr-merged-into-stdout" if merge else "separate"
        row["stdout"] = self.save(stage + ".stdout", out)
        row["stderr"] = self.save(stage + ".stderr", err)
        self.commands.append(row)
        self.receipt()
        need(r.returncode == 0, stage + " failed: " + str(r.returncode))
        return out, err, row

    def receipt(self, **extra):
        # Each immutable revision is exclusive; failure cannot erase earlier logs.
        self.save(
            "receipt-{:03d}.json".format(len(list(self.output.glob("receipt-*.json")))),
            (json.dumps(dict(schema=1, commands=self.commands, **extra), indent=2) + "\n").encode(),
        )


def source_snapshot(scope):
    names = [name for group in scope["groups"].values() for name in group]
    return {name: sha((ROOT / name).read_bytes()) for name in names}


def export_command(cargo, kind, output):
    argv = [str(cargo), "llvm-cov", "report", "--ignore-filename-regex", IGNORE]
    if kind != "report":
        argv += ["--" + kind]
    if kind == "lcov":
        # cargo-llvm-cov file and stdout modes differ in terminal framing.
        # Use the same file mode as the initial LCOV, retaining exact bytes.
        need(not (output / "reexport.lcov").exists(), "LCOV reexport output exists")
        argv += ["--output-path", str(output / "reexport.lcov")]
    return argv


def verify_lcov_file(path, expected):
    need(path.is_file() and not path.is_symlink(), "LCOV reexport file missing/linked")
    raw = path.read_bytes()
    need(raw == expected, "same-profile LCOV reexport differs")
    return dict(path=path.name, sha256=sha(raw), bytes=len(raw))


def verify_export_identity(covdir, profile_path, expected_profile, binaries):
    need(
        not profile_path.is_symlink() and sha(profile_path.read_bytes()) == expected_profile,
        "merged profdata changed during reexport",
    )
    actual = {}
    for path in sorted((covdir / "debug").rglob("*")):
        if not path.is_file() or path.is_symlink() or not os.access(path, os.X_OK):
            continue
        with path.open("rb") as stream:
            magic = stream.read(4)
        if magic in (b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf"):
            actual[path.relative_to(covdir).as_posix()] = sha(path.read_bytes())
    expected = {row["original_path"]: row["sha256"] for row in binaries}
    need(
        len(expected) == len(binaries) and actual == expected,
        "instrumented binary set/bytes changed during reexport",
    )
    return dict(profdata_sha256=expected_profile, binaries=actual)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--cargo", required=True, type=Path)
    p.add_argument("--rustc", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    args = p.parse_args()
    for tool in (args.cargo, args.rustc):
        need(
            tool.is_absolute() and tool.is_file() and os.access(tool, os.X_OK),
            "actual tool executable required",
        )
    scope = json.loads((ROOT / "tests/guests/terminal/coverage-scope.json").read_bytes())
    capture = Capture(args.output)
    before = source_snapshot(scope)
    locks = {n: sha((ROOT / n).read_bytes()) for n in ("Cargo.lock", "fuzz/Cargo.lock")}
    compiler, _, _ = capture.run("rustc-version", [str(args.rustc), "--version", "--verbose"])
    cov_version, _, _ = capture.run("coverage-version", [str(args.cargo), "llvm-cov", "--version"])
    command = [str(args.cargo), "llvm-cov", "--locked"]
    for package in PACKAGES:
        command += ["-p", package]
    original_lcov = ROOT / "target/u9-coverage.lcov"
    command += [
        "--lib",
        "--test",
        "diff_terminal",
        "--test",
        "command",
        "--ignore-filename-regex",
        IGNORE,
        "--fail-under-lines",
        "80",
        "--lcov",
        "--output-path",
        str(original_lcov),
    ]
    out, err, measured = capture.run("dedicated-u9", command, merge=True)
    tests, ignored = diff_counts((out + err).decode("utf-8", "replace"))
    measured.update(tests=tests, ignored=ignored)
    covdir = ROOT / "target/llvm-cov-target"
    profiles = list(covdir.glob("*.profdata"))
    need(len(profiles) == 1, "one merged profdata required")
    profile = capture.save("coverage.profdata", profiles[0].read_bytes())
    binaries = []
    # Preserve all instrumented executables consulted by this target directory,
    # including the CLI prepared in the surrounding coverage job.
    for path in sorted((covdir / "debug").rglob("*")):
        if not path.is_file() or path.is_symlink() or not os.access(path, os.X_OK):
            continue
        with path.open("rb") as stream:
            magic = stream.read(4)
        if magic not in (b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf"):
            continue
        relative = path.relative_to(covdir).as_posix()
        dest = args.output / "binaries" / relative
        dest.parent.mkdir(parents=True, exist_ok=True)
        with dest.open("xb") as stream:
            stream.write(path.read_bytes())
        binaries.append(
            dict(
                path=str(dest.relative_to(args.output)),
                sha256=sha(dest.read_bytes()),
                original_path=relative,
            )
        )
    need(binaries, "instrumented binaries absent")
    files = {"profdata": profile}
    files["lcov"] = capture.save("coverage.lcov", original_lcov.read_bytes())
    export_rows = []
    for kind in ("lcov", "json", "report"):
        identity_before = verify_export_identity(covdir, profiles[0], profile["sha256"], binaries)
        argv = export_command(args.cargo, kind, args.output)
        stdout, _, row = capture.run("export-" + kind, argv)
        identity_after = verify_export_identity(covdir, profiles[0], profile["sha256"], binaries)
        row.update(
            export=kind,
            profdata_sha256=profile["sha256"],
            binary_hashes=[x["sha256"] for x in binaries],
        )
        row.update(identity_before=identity_before, identity_after=identity_after)
        export_rows.append(row)
        if kind == "lcov":
            row["lcov_output"] = verify_lcov_file(
                args.output / "reexport.lcov", (args.output / "coverage.lcov").read_bytes()
            )
        else:
            files[kind] = capture.save(
                "coverage." + ("json" if kind == "json" else "report.txt"), stdout
            )
        capture.receipt()
    after = source_snapshot(scope)
    need(
        before == after and locks == {n: sha((ROOT / n).read_bytes()) for n in locks},
        "source/locks changed",
    )
    head = os.environ.get("GITHUB_SHA", "")
    need(re.fullmatch(r"[0-9a-f]{40}", head), "real CI head required")
    capture.save(
        "internal-receipt.json",
        (
            json.dumps(
                dict(
                    schema=1,
                    head=head,
                    source_prefix=str(ROOT) + "/",
                    source_before=before,
                    source_after=after,
                    locks=locks,
                    compiler=dict(
                        rustc_verbose=compiler.decode(),
                        llvm=re.search(r"LLVM version: (\S+)", compiler.decode()).group(1),
                        cargo_llvm_cov=cov_version.decode(),
                        flags=dict(
                            RUSTFLAGS=os.environ.get("RUSTFLAGS"),
                            RUST_TEST_THREADS="1",
                            ignore=IGNORE,
                        ),
                    ),
                    commands=capture.commands,
                    files=files,
                    binaries=binaries,
                ),
                indent=2,
            )
            + "\n"
        ).encode(),
    )
    print(
        json.dumps(
            dict(
                head=head,
                tests=tests,
                ignored=ignored,
                binaries=len(binaries),
                raw=str(args.output),
            )
        )
    )


if __name__ == "__main__":
    main()
