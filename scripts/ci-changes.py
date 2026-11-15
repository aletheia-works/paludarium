#!/usr/bin/env python3
"""Which CI job groups a pull request's changed files need; unknown paths need every group."""

import argparse
import os
import re
import sys
from pathlib import Path

GROUPS = (
    "rust",
    "dependencies",
    "fuzz",
    "wasm",
    "programs",
    "production_wasm",
    "docs",
    "release_check",
)
ALL = frozenset(GROUPS)
NONE = frozenset()
# The pull-request files API lists at most 3000 files; a longer list may be cut.
API_LIMIT = 3000
WORKFLOW = Path(__file__).resolve().parent.parent / ".github/workflows/ci.yml"
# The jobs that start only after the quick stage passed.
EXPENSIVE = frozenset(
    {
        "wasm-programs",
        "fuzz",
        "programs",
        "production-wasm",
        "differential",
        "differential-jit",
        "coverage",
    }
)

# First match wins. "dir/" matches everything below dir, "*.ext" any file
# with that extension, anything else the exact path.
RULES = (
    # What every job builds or runs with.
    (
        ALL,
        (
            ".github/workflows/ci.yml",
            ".github/actions/",
            "scripts/ci-changes.py",
            "scripts/rust-toolchain.sh",
            "scripts/rustup-retry.sh",
            "rust-toolchain.toml",
            "Cargo.toml",
            "Cargo.lock",
            "mise.toml",
            "crates/",
        ),
    ),
    ({"fuzz"}, (".github/workflows/fuzz-pr.yml",)),
    (
        {"wasm"},
        (".github/workflows/wasm-programs.yml", "scripts/wasm-run.py", "tests/guests/wasm/"),
    ),
    (
        {"programs", "wasm"},
        (".github/workflows/programs.yml", "scripts/programs-run.py", "tests/guests/programs/"),
    ),
    (
        {"wasm", "production_wasm", "release_check"},
        ("packages/paludarium-wasm/", "mise-tasks/wasm/"),
    ),
    ({"production_wasm"}, ("scripts/wasm-native-guests.py",)),
    ({"rust", "dependencies", "fuzz"}, ("fuzz/",)),
    ({"dependencies"}, ("deny.toml",)),
    ({"rust"}, ("clippy.toml",)),
    # The release package check: its scripts and tests, and the files every
    # package ships.
    (
        {"release_check"},
        (
            ".github/workflows/release-check.yml",
            "scripts/release/",
            "tests/release/",
            "README.md",
            "LICENSE",
        ),
    ),
    ({"docs"}, ("docs/", ".github/workflows/docs.yml", ".github/workflows/docs-build.yml")),
    # Run by the polyglot lint, which every pull request runs.
    (NONE, ("scripts/syscall-docs.py", "scripts/interface-docs.py")),
    # Guests, coverage scripts and their tests are used by the Rust jobs.
    ({"rust"}, ("tests/", "scripts/", "tools/")),
    # Documentation, infrastructure, the other workflows, lint settings and
    # local development helpers.
    (
        NONE,
        (
            "infra/",
            "spikes/",
            ".github/",
            "*.md",
            ".gitignore",
            ".rumdl.toml",
            "ruff.toml",
            "tombi.toml",
            "ci/linux-dev/",
            "mise-tasks/",
        ),
    ),
)


def matches(path, pattern):
    if pattern.endswith("/"):
        return path.startswith(pattern)
    if pattern.startswith("*."):
        return path.endswith(pattern[1:])
    return path == pattern


def groups_for(path):
    for groups, patterns in RULES:
        if any(matches(path, p) for p in patterns):
            return frozenset(groups)
    return ALL


def needed(paths):
    paths = [p for p in paths if p]
    if not paths or len(paths) >= API_LIMIT:
        return ALL
    return frozenset().union(*(groups_for(p) for p in paths))


def workflow_jobs(text):
    """Each job of a workflow with the jobs it needs and its condition."""
    jobs = {}
    body = text.split("\njobs:\n", 1)[1]
    for block in re.split(r"\n(?=  [A-Za-z0-9_-]+:\n)", "\n" + body):
        head = re.match(r"\n?  ([A-Za-z0-9_-]+):\n", block)
        if not head:
            continue
        needs = re.search(r"^    needs:(.*)$((?:\n      - .*)*)", block, re.M)
        names = []
        if needs:
            inline = needs.group(1).strip().strip("[]")
            names = [n.strip() for n in inline.split(",") if n.strip()]
            names += re.findall(r"^      - (\S+)", needs.group(2), re.M)
        cond = re.search(r"^    if: (.*)$", block, re.M)
        jobs[head.group(1)] = (frozenset(names), cond.group(1).strip() if cond else "")
    return jobs


def check_gates(text, expensive=EXPENSIVE):
    """ci-ok needs every job and the expensive jobs wait for the quick stage.

    A job whose needed job failed is skipped, and ci-ok accepts a skipped job,
    so ci-ok must need every job itself to see the failure.
    """
    jobs = workflow_jobs(text)
    # Both gates run when a job they need failed.
    for gate, cond in (("ci-ok", "always()"), ("quick", "${{ !cancelled() }}")):
        if jobs[gate][1] != cond:
            raise AssertionError(f"{gate} must run with if: {cond}")
    missing = set(jobs) - {"ci-ok"} - jobs["ci-ok"][0]
    if missing:
        raise AssertionError(f"ci-ok does not need {sorted(missing)}")
    for job in expensive:
        if "quick" not in jobs[job][0]:
            raise AssertionError(f"{job} must need the quick stage")
        if "always()" in jobs[job][1] or "cancelled()" in jobs[job][1]:
            raise AssertionError(f"{job} must be skipped when the quick stage fails")
    return jobs


def self_test():
    cases = {
        "docs/release.md": {"docs"},
        "README.md": {"release_check"},
        "CONTRIBUTING.md": NONE,
        "infra/github/main.tf": NONE,
        ".github/workflows/release.yml": NONE,
        "scripts/release/acceptance.py": {"release_check"},
        "tests/release/test_acceptance.py": {"release_check"},
        "crates/paludarium-cpu/src/lib.rs": ALL,
        "crates/paludarium-cpu/README.md": ALL,
        "Cargo.lock": ALL,
        ".github/workflows/ci.yml": ALL,
        ".github/actions/rust-toolchain/action.yml": ALL,
        "scripts/rust-toolchain.sh": ALL,
        "scripts/bump-pins.py": {"rust"},
        ".github/workflows/bump-pins.yml": NONE,
        "fuzz/fuzz_targets/load_elf.rs": {"rust", "dependencies", "fuzz"},
        "packages/paludarium-wasm/index.mjs": {"wasm", "production_wasm", "release_check"},
        "tests/guests/programs/cases.json": {"programs", "wasm"},
        "tests/guests/encodings/observe.c": {"rust"},
        "tests/guests/distro/compare.py": {"rust"},
        ".github/workflows/distro-programs.yml": NONE,
        "scripts/coverage-check.py": {"rust"},
        "scripts/syscall-docs.py": NONE,
        "scripts/interface-docs.py": NONE,
        "deny.toml": {"dependencies"},
        "clippy.toml": {"rust"},
        "mise-tasks/linux-dev.sh": NONE,
        "unknown-top-level-file": ALL,
    }
    for path, expected in cases.items():
        got = groups_for(path)
        if got != frozenset(expected):
            raise AssertionError(f"{path}: {sorted(got)} != {sorted(expected)}")
    if needed([]) != ALL or needed(["docs/a.md"] * API_LIMIT) != ALL:
        raise AssertionError("an empty or possibly cut file list must need every group")
    if needed(["infra/github/main.tf", ".github/labeler.yml"]) != NONE:
        raise AssertionError("infrastructure and bot settings need no group")
    if needed(["docs/a.md", "deny.toml"]) != {"docs", "dependencies"}:
        raise AssertionError("groups of several files must be joined")
    jobs = check_gates(WORKFLOW.read_text(encoding="utf-8"))
    good = (
        "on: push\njobs:\n  a:\n    runs-on: x\n  b:\n    needs: [a, quick]\n"
        "  quick:\n    if: ${{ !cancelled() }}\n    needs:\n      - a\n"
        "  ci-ok:\n    if: always()\n    needs:\n      - a\n      - b\n      - quick\n"
    )
    check_gates(good, {"b"})
    for text, refusal in (
        (good.replace("      - b\n", ""), "ci-ok does not need ['b']"),
        (good.replace("[a, quick]", "a"), "b must need the quick stage"),
        (good.replace("[a, quick]\n", "[a, quick]\n    if: always()\n"), "b must be skipped"),
        (good.replace("  quick:\n    if: ${{ !cancelled() }}", "  quick:"), "quick must run"),
    ):
        try:
            check_gates(text, {"b"})
        except AssertionError as e:
            if refusal not in str(e):
                raise
        else:
            raise AssertionError(f"not refused: {refusal}")
    print(f"ci-changes ready: {len(cases)} paths and {len(jobs)} jobs checked")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--all", action="store_true", help="need every group (push to main)")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    groups = ALL if args.all else needed(sys.stdin.read().splitlines())
    lines = [f"{g}={'true' if g in groups else 'false'}" for g in GROUPS]
    print("\n".join(lines))
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
