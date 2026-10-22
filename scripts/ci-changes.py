#!/usr/bin/env python3
"""Which CI job groups a pull request's changed files need; unknown paths need every group."""

import argparse
import os
import sys

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
        "fuzz/fuzz_targets/load_elf.rs": {"rust", "dependencies", "fuzz"},
        "packages/paludarium-wasm/index.mjs": {"wasm", "production_wasm", "release_check"},
        "tests/guests/programs/cases.json": {"programs", "wasm"},
        "tests/guests/encodings/observe.c": {"rust"},
        "scripts/coverage-check.py": {"rust"},
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
    print(f"ci-changes ready: {len(cases)} paths checked")


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
