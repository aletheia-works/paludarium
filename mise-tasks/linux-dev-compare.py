#!/usr/bin/env python3
# MISE description="Differential tests in the Linux container, reported against main's results there"
"""Run the differential tests in the x86-64 Linux development container
(`mise run linux-dev`) for this checkout and for a base revision, and report
only the cases whose result differs between the two.

On an Arm Mac the container runs the native side under QEMU's user-mode
emulation, so some cases fail there on main too (docs/design/quality.md).
Those stay listed as known. A case that fails here and passes on the base is
run once more here: if it passes, it is listed as flaky, else it is new and
fails this task, as does a case that fails here and is not on the base, or
one the base ran that did not run here. Neither run is evidence: only
x86-64 Linux CI is.

    mise run linux-dev-compare
    mise run linux-dev-compare -- --test diff_network
    mise run linux-dev-compare -- --base upstream/main --test diff_processes

The base is checked out with `git worktree` under
target/linux-dev-compare/base, which keeps its own container volume. Its
failing cases run once more, and those that pass then count as passing; its
results are then kept per commit and test selection in that directory, so a
later run against the same base only runs this checkout. Delete
target/linux-dev-compare/<commit>-*.json to run the base again.
"""

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORK = ROOT / "target" / "linux-dev-compare"
# The suites `mise run test:diff` runs, read from its command.
SUITES = tuple(
    re.findall(
        r"--test (\S+)",
        tomllib.loads((ROOT / "mise.toml").read_text())["tasks"]["test:diff"]["run"],
    )
)
RUNNING = re.compile(r"^\s*Running (?:unittests )?(\S+)")
RESULT = re.compile(r"^test (\S+) \.\.\. (?:.*?)(ok|FAILED|ignored)\s*$")


def results(log):
    """Each test's outcome by `suite::name`, from cargo test's output.

    A suite that runs its cases in child processes prints their lines too;
    a case counts as failed when any line for it says so."""
    suite = "?"
    seen = {}
    for line in log.splitlines():
        running = RUNNING.match(line)
        if running:
            suite = Path(running.group(1)).stem.split("-")[0]
            continue
        found = RESULT.match(line)
        if not found:
            continue
        key = f"{suite}::{found.group(1)}"
        outcome = found.group(2)
        if seen.get(key) != "FAILED":
            seen[key] = outcome
    return seen


def compare(base, head):
    """New failures (also of cases the base does not have), fixes, known
    failures, cases the base ran that did not run here (a suite that
    stopped), and cases only this checkout has that did not fail."""
    new = sorted(k for k, v in head.items() if v == "FAILED" and base.get(k) != "FAILED")
    fixed = sorted(k for k, v in head.items() if v == "ok" and base.get(k) == "FAILED")
    known = sorted(k for k, v in head.items() if v == "FAILED" and base.get(k) == "FAILED")
    missing = sorted(set(base) - set(head))
    added = sorted(k for k in set(head) - set(base) if head[k] != "FAILED")
    return new, fixed, known, missing, added


def run(checkout, tests, names=()):
    """Runs the selected suites, or only the cases `names` of them, in the
    container for `checkout`; returns its log."""
    command = [
        "bash",
        str(checkout / "mise-tasks" / "linux-dev.sh"),
        "cargo",
        "test",
        "--locked",
        "--no-fail-fast",
        "-p",
        "paludarium-harness",
        *[arg for suite in tests for arg in ("--test", suite)],
        *(("--", "--exact", *names) if names else ()),
    ]
    print(f"running {' '.join(tests)} in {checkout}", file=sys.stderr, flush=True)
    # One stream, so that cargo's "Running" lines stay before their tests.
    done = subprocess.run(
        command,
        cwd=checkout,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        errors="replace",
        check=False,
    )
    return done.stdout


def git(*args, cwd=ROOT):
    return subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True, check=True
    ).stdout.strip()


def default_base():
    for ref in ("upstream/main", "origin/main", "main"):
        if (
            subprocess.run(
                ["git", "rev-parse", "--verify", "--quiet", ref],
                cwd=ROOT,
                capture_output=True,
                check=False,
            ).returncode
            == 0
        ):
            return ref
    sys.exit("no base: pass --base")


def base_results(commit, tests):
    """The base's outcomes, from the cache or a run in its worktree."""
    # The commit pins the toolchain, which names the container's image; the
    # image itself is whichever linux-dev built first for that toolchain, the
    # same for both sides.
    key = hashlib.sha256(" ".join(sorted(set(tests))).encode()).hexdigest()[:12]
    cache = WORK / f"{commit}-{key}.json"
    if cache.exists():
        return json.loads(cache.read_text())
    tree = WORK / "base"
    if not (tree / ".git").exists():
        WORK.mkdir(parents=True, exist_ok=True)
        git("worktree", "add", "--detach", str(tree), commit)
    else:
        git("checkout", "--detach", "--quiet", commit, cwd=tree)
    log = run(tree, tests)
    (WORK / f"{commit}-{key}.log").write_text(log)
    found = results(log)
    if not found:
        sys.exit(f"the base ran no tests; see {WORK / f'{commit}-{key}.log'}")
    # A case that failed only by chance would hide a real failure here as a
    # known one for as long as the cache lasts.
    for flake in rerun([k for k, v in found.items() if v == "FAILED"], tree):
        found[flake] = "ok"
    cache.write_text(json.dumps(found, indent=1, sort_keys=True))
    return found


def rerun(failed, checkout=ROOT):
    """The failed cases that pass when run once more in `checkout`: Docker's
    timing makes some cases flaky (docs/design/quality.md)."""
    flaky = []
    for suite in sorted({key.split("::", 1)[0] for key in failed}):
        names = [key.split("::", 1)[1] for key in failed if key.startswith(f"{suite}::")]
        again = results(run(checkout, [suite], names))
        flaky += [f"{suite}::{name}" for name in names if again.get(f"{suite}::{name}") == "ok"]
    return sorted(flaky)


def report(new, flaky, missing, fixed, known, added):
    for title, keys in (
        ("New failures (do not fail on the base, and failed again here)", new),
        ("Flaky (failed here, then passed when run again)", flaky),
        ("Missing here (ran on the base; did a suite stop?)", missing),
        ("Fixed (fail on the base)", fixed),
        ("Known failures (fail on the base too)", known),
        ("Only here, not failing", added),
    ):
        print(f"{title}: {len(keys)}")
        for key in keys:
            print(f"  {key}")


def self_test():
    log = "\n".join(
        (
            "     Running tests/diff_network.rs (target/debug/deps/diff_network-0123abcd)",
            "test linux::network_udp ... ok",
            "test linux::network_udp_rcvbuf ... FAILED",
            "     Running tests/diff_processes.rs (target/debug/deps/diff_processes-4567ef01)",
            "test linux::processes_select ... ok",
            "test linux::processes_select ... select: native Exited(0) [1]; stop None",
            "test linux::processes_select ... FAILED",
            "test linux::clone_vm ... ignored",
        )
    )
    found = results(log)
    assert found == {
        "diff_network::linux::network_udp": "ok",
        "diff_network::linux::network_udp_rcvbuf": "FAILED",
        "diff_processes::linux::processes_select": "FAILED",
        "diff_processes::linux::clone_vm": "ignored",
    }, found
    base = {"a": "ok", "b": "FAILED", "c": "FAILED", "d": "ok"}
    head = {"a": "FAILED", "b": "ok", "c": "FAILED", "e": "ok", "f": "FAILED"}
    assert compare(base, head) == (["a", "f"], ["b"], ["c"], ["d"], ["e"])
    assert "diff_network" in SUITES and "diff_processes" in SUITES, SUITES
    print("self-test passed")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--base", help="revision to compare with (default: upstream/main)")
    parser.add_argument("--test", action="append", choices=SUITES, help="a suite to run")
    parser.add_argument("--self-test", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    tests = args.test or list(SUITES)
    commit = git("rev-parse", args.base or default_base())
    base = base_results(commit, tests)
    log = run(ROOT, tests)
    WORK.mkdir(parents=True, exist_ok=True)
    (WORK / "head.log").write_text(log)
    head = results(log)
    if not head:
        sys.exit(f"this checkout ran no tests; see {WORK / 'head.log'}")
    new, fixed, known, missing, added = compare(base, head)
    flaky = rerun(new) if new else []
    new = [key for key in new if key not in flaky]
    print(f"base {commit[:12]}, {len(head)} cases here; logs in {WORK}")
    report(new, flaky, missing, fixed, known, added)
    return 1 if new or missing else 0


if __name__ == "__main__":
    sys.exit(main())
