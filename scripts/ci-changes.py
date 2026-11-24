#!/usr/bin/env python3
"""Which CI job groups a pull request's changed files need; unknown paths need every group.

It also picks the pull-request fuzz targets the changes can affect: a target
runs when a changed crate is one its source names or one of their Cargo
dependencies (from cargo metadata). Any other change the fuzz group needs
runs every target.

Two groups narrow the jobs that run on scarce runners. "unit" is the unit
test jobs: a crate they test, or a file outside the crates their sources name
by a relative path. "safari" is the Safari row of the wasm programs: the
"wasm" group without the changes that only reach crates the Wasm module does
not link.
"""

import argparse
import json
import os
import posixpath
import re
import subprocess
import sys
from pathlib import Path

GROUPS = (
    "rust",
    "unit",
    "dependencies",
    "fuzz",
    "wasm",
    "safari",
    "programs",
    "production_wasm",
    "docs",
    "release_check",
)
ALL = frozenset(GROUPS)
NONE = frozenset()
# The pull-request files API lists at most 3000 files; a longer list may be cut.
API_LIMIT = 3000
ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github/workflows/ci.yml"
FUZZ_WORKFLOW = ROOT / ".github/workflows/fuzz-pr.yml"
FUZZ_TARGETS = ROOT / "fuzz/fuzz_targets"
# The package the Wasm module is built from (mise-tasks/wasm/build.sh).
WASM_PACKAGE = "paludarium-wasm"
# The unit test jobs run its library's tests only (cargo test --lib).
LIB_ONLY = "paludarium-harness"
# What the unit test jobs run; self_test checks that ci.yml still does.
UNIT_COMMANDS = (
    'cargo test --locked "${packages[@]}" -- --nocapture',
    "cargo test --locked -p paludarium-harness --lib",
)
# A relative path in a Rust source: #[path], include_str!, a joined path.
RELATIVE = re.compile(r'"((?:\.\./)+[^"\s\\]+)"')
# Unit test sources that build a path at run time; each read is listed in
# dynamic_reads, so a new one must be added there.
DYNAMIC = re.compile(r"CARGO_MANIFEST_DIR|workspace_root\(\)|current_dir\(")
DYNAMIC_SOURCES = frozenset(
    {
        # The literal joined to it is a relative path RELATIVE finds.
        "crates/paludarium-host/src/terminal_tests.rs",
        # workspace_root() and the guest build only the differential tests use.
        "crates/paludarium-harness/src/lib.rs",
        # The guest sources CORE_INSTRUCTIONS names, under tests/guests.
        "crates/paludarium-harness/src/coverage.rs",
    }
)
# The jobs the quick stage waits for.
QUICK = frozenset({"changes", "polyglot-lint", "test-linux", "lint", "stable-clippy"})
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
    # The x87 guest, and the script that builds it, also run in the wasm
    # programs' x87 step.
    ({"rust", "wasm"}, ("tests/guests/processes/x87.c", "tests/guests/processes/build.sh")),
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


def groups_for(path, reach=None):
    for groups, patterns in RULES:
        if any(matches(path, p) for p in patterns):
            return narrow(path, frozenset(groups), reach)
    return ALL


def narrow(path, groups, reach=None):
    """Adds "unit" and "safari" to a path's groups when those jobs can be affected."""
    crate = re.match(r"(crates/[^/]+)/(.+)$", path)
    if groups == ALL and not crate:
        return ALL
    reach = reach or crate_reach()
    if groups == ALL:
        owner = reach["owners"].get(crate.group(1))
        # A manifest changes what links what; an unknown crate is not in the graph.
        if owner is None or crate.group(2) == "Cargo.toml":
            return ALL
        groups = ALL - {"unit", "safari"}
        tested = owner in reach["unit"] and (owner != LIB_ONLY or crate.group(2).startswith("src/"))
        if tested or path in reach["unit_reads"]:
            groups |= {"unit"}
        if owner in reach["wasm"] or path in reach["wasm_reads"]:
            groups |= {"safari"}
        return groups
    if path in reach["unit_reads"]:
        groups |= {"unit"}
    # Outside the crates, the wasm group's rules already name what the Wasm
    # programs read, Safari's row included.
    if "wasm" in groups:
        groups |= {"safari"}
    return groups


def needed(paths):
    paths = [p for p in paths if p]
    if not paths or len(paths) >= API_LIMIT:
        return ALL
    return frozenset().union(*(groups_for(p) for p in paths))


def pr_fuzz_targets(text=None):
    """The pull-request fuzz targets: the default of fuzz-pr.yml's targets input."""
    text = FUZZ_WORKFLOW.read_text(encoding="utf-8") if text is None else text
    lists = {tuple(json.loads(d)) for d in re.findall(r"^ +default: '(\[.*\])'$", text, re.M)}
    if len(lists) != 1:
        raise AssertionError("fuzz-pr.yml must give one default list of targets")
    return list(lists.pop())


def crate_graph(metadata, dev=False):
    """Each workspace package: its directory and the path packages it links.

    With dev, also the packages its tests link.
    """
    root = Path(metadata["workspace_root"])
    graph = {}
    for package in metadata["packages"]:
        links = {
            d["name"]
            for d in package["dependencies"]
            if d.get("path") and (dev or d["kind"] != "dev")
        }
        directory = Path(package["manifest_path"]).parent.relative_to(root).as_posix()
        graph[package["name"]] = (directory, frozenset(links))
    return graph


_METADATA = []


def load_metadata():
    # cargo honours RUSTUP_TOOLCHAIN; CI sets it to the runner's stable so the
    # pinned nightly is not installed for this.
    if not _METADATA:
        command = [os.environ.get("CARGO", "cargo"), "metadata", "--no-deps", "--locked"]
        command += ["--format-version", "1", "--manifest-path", str(ROOT / "Cargo.toml")]
        out = subprocess.run(command, check=True, capture_output=True, text=True).stdout
        _METADATA.append(json.loads(out[out.index("{") :]))
    return _METADATA[0]


def load_crate_graph():
    return crate_graph(load_metadata())


def closure(names, graph):
    seen, todo = set(), list(names)
    while todo:
        name = todo.pop()
        if name not in seen:
            seen.add(name)
            todo.extend(graph[name][1])
    return frozenset(seen)


def core_packages(text=None):
    """The packages of ci.yml's CORE_PACKAGES, which the unit test jobs test."""
    text = WORKFLOW.read_text(encoding="utf-8") if text is None else text
    block = re.search(r"^  CORE_PACKAGES: >-\n((?:    .*\n)+)", text, re.M)
    if not block:
        raise AssertionError("ci.yml must set CORE_PACKAGES")
    return re.findall(r"-p (\S+)", block.group(1))


def rust_sources(directory, only=""):
    base = ROOT / directory / only
    return sorted(p.relative_to(ROOT).as_posix() for p in base.rglob("*.rs"))


def relative_reads(sources):
    """Files that Rust sources name by a relative path, followed through the Rust ones.

    A path resolves against the source's directory (#[path], include_str!) or
    its crate's (a path joined to CARGO_MANIFEST_DIR, the tests' directory).
    """
    found, seen, todo = set(), set(), list(sources)
    while todo:
        source, crate_dir = todo.pop()
        if source in seen:
            continue
        seen.add(source)
        text = (ROOT / source).read_text(encoding="utf-8")
        for literal in RELATIVE.findall(text):
            for base in {posixpath.dirname(source), crate_dir}:
                path = posixpath.normpath(posixpath.join(base, literal))
                if not path.startswith("../") and (ROOT / path).is_file():
                    found.add(path)
                    if path.endswith(".rs"):
                        todo.append((path, crate_dir))
    return found


def dynamic_reads():
    """The files DYNAMIC_SOURCES read by a path built at run time."""
    text = (ROOT / "crates/paludarium-harness/src/coverage.rs").read_text(encoding="utf-8")
    if 'workspace_root().join("tests").join("guests")' not in text:
        raise AssertionError("coverage.rs no longer reads tests/guests: update dynamic_reads")
    return {f"tests/guests/{f}" for f in re.findall(r'^    \("[^"]+", "([^"]+)", ', text, re.M)}


_REACH = []


def crate_reach():
    """Which packages, and files outside them, the unit tests and the Wasm module reach."""
    if _REACH:
        return _REACH[0]
    metadata = load_metadata()
    graph, tests = crate_graph(metadata), crate_graph(metadata, dev=True)
    unit = closure([*core_packages(), LIB_ONLY], tests)
    wasm = closure([WASM_PACKAGE], graph)

    def sources(names):
        out = []
        for name in sorted(names):
            directory = graph[name][0]
            only = "src" if name == LIB_ONLY else ""
            out += [(s, directory) for s in rust_sources(directory, only)]
        return out

    unit_sources = sources(unit)
    reach = {
        "owners": {d: name for name, (d, _) in graph.items()},
        "unit": unit,
        "wasm": wasm,
        "unit_reads": frozenset(relative_reads(unit_sources) | dynamic_reads()),
        "wasm_reads": frozenset(relative_reads(sources(wasm))),
        "unit_sources": [s for s, _ in unit_sources],
    }
    _REACH.append(reach)
    return reach


def linked_crates(target, graph, read=None):
    """The workspace packages a fuzz target's source names, with their dependencies."""
    read = read or (lambda path: (FUZZ_TARGETS / path).read_text(encoding="utf-8"))
    files, seen, named = [f"{target}.rs"], set(), set()
    while files:
        path = files.pop()
        if path in seen:
            continue
        seen.add(path)
        text = read(path)
        named |= {n.replace("_", "-") for n in re.findall(r"\b(paludarium_[a-z0-9_]+)", text)}
        base = path.rpartition("/")[0]
        for module in re.findall(r'#\[path = "([^"]+)"\]', text):
            files.append(f"{base}/{module}" if base else module)
    unknown = named - set(graph)
    if unknown:
        raise AssertionError(
            f"{target} names packages cargo metadata does not list: {sorted(unknown)}"
        )
    linked, todo = set(), list(named)
    while todo:
        name = todo.pop()
        if name not in linked:
            linked.add(name)
            todo.extend(graph[name][1])
    return frozenset(linked)


def fuzz_selection(paths, targets, graph=None, read=None):
    """The fuzz targets that the changed paths can affect, in fuzz-pr.yml's order."""
    paths = [p for p in paths if p]
    if not paths or len(paths) >= API_LIMIT:
        return list(targets)
    fuzzed = [p for p in paths if "fuzz" in groups_for(p)]
    if not fuzzed:
        return []
    changed = set()
    for path in fuzzed:
        crate = re.match(r"(crates/[^/]+)/(.+)$", path)
        # Only a crate's own files narrow the choice; a manifest, the lockfile,
        # the toolchain, fuzz/, the workflows and this script run every target.
        if not crate or crate.group(2) == "Cargo.toml":
            return list(targets)
        if graph is None:
            graph = load_crate_graph()
        owners = [name for name, (d, _) in graph.items() if d == crate.group(1)]
        if not owners:
            return list(targets)
        changed.update(owners)
    return [t for t in targets if linked_crates(t, graph, read) & changed]


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


def check_gates(text, expensive=EXPENSIVE, quick=QUICK):
    """ci-ok needs every job and the expensive jobs wait for the quick stage.

    A job whose needed job failed is skipped, and ci-ok accepts a skipped job,
    so ci-ok must need every job itself to see the failure.
    """
    jobs = workflow_jobs(text)
    # Both gates run when a job they need failed.
    for gate, cond in (("ci-ok", "always()"), ("quick", "${{ !cancelled() }}")):
        if jobs[gate][1] != cond:
            raise AssertionError(f"{gate} must run with if: {cond}")
    if jobs["quick"][0] != quick:
        raise AssertionError(f"quick must need exactly {sorted(quick)}")
    missing = set(jobs) - {"ci-ok"} - jobs["ci-ok"][0]
    if missing:
        raise AssertionError(f"ci-ok does not need {sorted(missing)}")
    # A skip passes down the needs too: polyglot-lint runs only on pull
    # requests and lint only on Rust changes, so with the implicit success()
    # an expensive job would be skipped whenever one of them was, although
    # quick passed. The expensive jobs check quick's own result instead.
    guard = "${{ !cancelled() && needs.quick.result == 'success' && "
    for job in expensive:
        if "quick" not in jobs[job][0]:
            raise AssertionError(f"{job} must need the quick stage")
        cond = jobs[job][1]
        if not cond.startswith(guard) or not cond.endswith(" }}") or "always()" in cond:
            raise AssertionError(f"{job} must run if and only if quick passed: if: {guard}...")
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
        "packages/paludarium-wasm/index.mjs": {
            "wasm",
            "safari",
            "production_wasm",
            "release_check",
        },
        "tests/guests/programs/cases.json": {"programs", "wasm", "safari"},
        "tests/guests/processes/x87.c": {"rust", "wasm", "safari"},
        "tests/guests/processes/build.sh": {"rust", "wasm", "safari"},
        "tests/guests/processes/process.c": {"rust"},
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
        # What the unit test jobs read outside the crates they test.
        "tests/guests/insn/alu.c": {"rust", "unit"},
        "tests/guests/processes/x87_transcendental.h": {"rust", "unit"},
        "tests/guests/encodings/native-contract.rs": {"rust", "unit"},
        "tests/guests/terminal/host-pty.py": {"rust", "unit"},
        "fuzz/fuzz_targets/support/syscall_host.rs": {"rust", "unit", "dependencies", "fuzz"},
        "packages/paludarium-wasm/jit-support.mjs": {
            "unit",
            "wasm",
            "safari",
            "production_wasm",
            "release_check",
        },
        "crates/paludarium-wasm/src/abi.rs": ALL,
        # Crates the Wasm module does not link, and files the unit tests do not build.
        "crates/paludarium-wasm/src/lib.rs": ALL - {"unit"},
        "crates/paludarium-harness/src/lib.rs": ALL - {"safari"},
        "crates/paludarium-harness/tests/diff_core.rs": ALL - {"unit", "safari"},
        "crates/paludarium-jit-native/src/lib.rs": ALL - {"safari"},
        "crates/paludarium/src/main.rs": ALL - {"safari"},
        "crates/paludarium-kernel/tests/fuzz_wait.rs": ALL,
        "crates/paludarium-harness/Cargo.toml": ALL,
        "crates/paludarium-new/src/lib.rs": ALL,
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
    workflow = WORKFLOW.read_text(encoding="utf-8")
    jobs = check_gates(workflow)
    check_narrowing(workflow)
    check_differential_lists()
    good = (
        "on: push\njobs:\n  a:\n    runs-on: x\n  b:\n    needs: [a, quick]\n"
        "    if: ${{ !cancelled() && needs.quick.result == 'success' && true }}\n"
        "  quick:\n    if: ${{ !cancelled() }}\n    needs:\n      - a\n"
        "  ci-ok:\n    if: always()\n    needs:\n      - a\n      - b\n      - quick\n"
    )
    check_gates(good, {"b"}, {"a"})
    for text, refusal in (
        (good.replace("      - b\n", ""), "ci-ok does not need ['b']"),
        (
            good.replace("    needs:\n      - a\n  ci-ok:", "    needs: []\n  ci-ok:"),
            "quick must need exactly",
        ),
        (good.replace("[a, quick]", "a"), "b must need the quick stage"),
        (
            good.replace("${{ !cancelled() && needs.quick.result == 'success' && true }}", "true"),
            "b must run if",
        ),
        (good.replace("&& true }}", "&& always() }}"), "b must run if"),
        (good.replace("  quick:\n    if: ${{ !cancelled() }}", "  quick:"), "quick must run"),
    ):
        try:
            check_gates(text, {"b"}, {"a"})
        except AssertionError as e:
            if refusal not in str(e):
                raise
        else:
            raise AssertionError(f"not refused: {refusal}")
    fuzz_cases = fuzz_self_test()
    print(
        f"ci-changes ready: {len(cases)} paths, {len(jobs)} jobs and {fuzz_cases} fuzz selections checked"
    )


# The harness's differential tests that a workflow of their own runs: the
# fixed programs, the Windows and macOS hosts, and the native JIT's cases.
OWN_WORKFLOWS = {
    "diff_programs": ".github/workflows/programs.yml",
    "diff_windows": ".github/workflows/quality.yml",
    "diff_macos": ".github/workflows/macos-quality.yml",
    "diff_jit": ".github/workflows/quality.yml",
}
# Where each of the others runs: mise's test:diff and the differential jobs
# of ci.yml (every pull request) and quality.yml (nightly), each read up to
# the next task or job.
DIFFERENTIAL_LISTS = (
    ("mise.toml", r'(?ms)^\[tasks\."test:diff"\]\n(.*?)(?=^\[|\Z)'),
    (".github/workflows/ci.yml", r"(?ms)^  differential:\n(.*?)(?=^  \S|\Z)"),
    (".github/workflows/quality.yml", r"(?ms)^  differential:\n(.*?)(?=^  \S|\Z)"),
)


def differential_gaps(tests, read):
    """Each of the harness's differential `tests` and a list that does not run it."""
    gaps = []
    for name in sorted(tests):
        if name in OWN_WORKFLOWS:
            lists = [(OWN_WORKFLOWS[name], r"(?s)(.*)")]
        else:
            lists = DIFFERENTIAL_LISTS
        for path, part in lists:
            found = re.search(part, read(path))
            if not found or not re.search(rf"--test {re.escape(name)}(?!\w)", found.group(1)):
                gaps.append(f"{name} in {path}")
    return gaps


def check_differential_lists():
    """Every differential test of the harness runs somewhere: one missing
    from every list compares nothing, as diff_events, diff_threads and
    diff_files did from October to November 2026."""
    tests = {
        p.stem
        for p in (ROOT / "crates/paludarium-harness/tests").glob("*.rs")
        if p.stem.startswith(("diff_", "parallel_"))
    }
    gaps = differential_gaps(tests, lambda path: (ROOT / path).read_text(encoding="utf-8"))
    if gaps:
        raise AssertionError("differential tests no job runs: " + ", ".join(gaps))
    lists = {
        "mise.toml": '[tasks."test:diff"]\nrun = "cargo test --test diff_a --test diff_ab"\n[tasks.x]\n',
        ".github/workflows/ci.yml": "  differential:\n    run: cargo test --test diff_a\n  later:\n    --test diff_b\n",
        ".github/workflows/quality.yml": "  differential:\n    --test diff_a --test diff_b\n",
    }
    if differential_gaps({"diff_a"}, lists.__getitem__) != []:
        raise AssertionError("a test every list runs must pass")
    if differential_gaps({"diff_b"}, lists.__getitem__) != [
        "diff_b in mise.toml",
        "diff_b in .github/workflows/ci.yml",
    ]:
        raise AssertionError("a test missing from a list, or only in another job, must be refused")


def check_narrowing(workflow):
    """ci.yml and wasm-programs.yml still run what "unit" and "safari" assume."""
    for group in GROUPS:
        if f"      {group}: ${{{{ steps.groups.outputs.{group} }}}}\n" not in workflow:
            raise AssertionError(f"changes must output {group}")
    jobs = workflow_jobs(workflow)
    for job in ("test-linux", "test"):
        if jobs[job][1] != "needs.changes.outputs.unit == 'true'":
            raise AssertionError(f"{job} must run if and only if the unit group is needed")
    for command in UNIT_COMMANDS:
        if command not in workflow:
            raise AssertionError(f"the unit test steps no longer run {command}: update UNIT_*")
    if "      safari: ${{ needs.changes.outputs.safari == 'true' }}\n" not in workflow:
        raise AssertionError("wasm-programs must get the safari group as its safari input")
    wasm = (ROOT / ".github/workflows/wasm-programs.yml").read_text(encoding="utf-8")
    if wasm.count("      safari:\n        type: boolean\n        default: true\n") != 2:
        raise AssertionError("wasm-programs.yml must declare safari for a call and a dispatch")
    rows = re.findall(r"fromJSON\(inputs\.safari == false && '(\[.*?\])' \|\| '(\[.*?\])'\)", wasm)
    if len(rows) != 1 or [*json.loads(rows[0][0]), "safari"] != sorted(
        json.loads(rows[0][1]), key=[*json.loads(rows[0][0]), "safari"].index
    ):
        raise AssertionError("wasm-programs.yml must drop only the Safari row on safari: false")
    reach = crate_reach()
    if not reach["wasm"] < reach["unit"] | {WASM_PACKAGE} or WASM_PACKAGE in reach["unit"]:
        raise AssertionError(f"the unit and wasm packages changed: {sorted(reach['wasm'])}")
    for source in reach["unit_sources"]:
        text = (ROOT / source).read_text(encoding="utf-8")
        if DYNAMIC.search(text) and source not in DYNAMIC_SOURCES:
            raise AssertionError(f"{source} builds a path at run time: add what it reads")


def fuzz_self_test():
    targets = pr_fuzz_targets()
    bins = re.findall(r'^name = "([a-z0-9_]+)"$', (ROOT / "fuzz/Cargo.toml").read_text(), re.M)
    if not set(targets) <= set(bins) or len(targets) != len(set(targets)):
        raise AssertionError(f"fuzz-pr.yml lists targets fuzz/Cargo.toml does not: {targets}")
    # The real targets' sources and the real graph resolve.
    graph = load_crate_graph()
    for target in targets:
        if not linked_crates(target, graph):
            raise AssertionError(f"{target} names no workspace package")
    # The selection on a fixed graph, shaped like the workspace's.
    deps = {
        "types": "",
        "host": "types",
        "mmu": "types",
        "decoder": "types",
        "vfs": "host types",
        "cpu": "decoder mmu types",
        "loader": "mmu types vfs",
        "kernel": "cpu host loader mmu types vfs",
        "jit": "cpu decoder mmu types",
        "runtime": "cpu host jit kernel loader mmu types vfs",
    }
    fixed = {
        f"paludarium-{n}": (
            f"crates/paludarium-{n}",
            frozenset(f"paludarium-{d}" for d in ds.split()),
        )
        for n, ds in deps.items()
    }
    sources = {
        "vfs_paths.rs": "use paludarium_vfs::Vfs;",
        "load_elf.rs": "use paludarium_loader::load; use paludarium_mmu::Mmu;",
        "syscall_args.rs": '#[path = "support/host.rs"]\nmod host;\nuse paludarium_kernel::K;',
        "support/host.rs": "use paludarium_host::Host;",
        "kernel_threads.rs": "use paludarium_kernel::K;",
        "kernel_futex.rs": "use paludarium_kernel::K;",
    }
    names = [n.removesuffix(".rs") for n in sources if "/" not in n]
    cases = {
        ("crates/paludarium-kernel/src/lib.rs",): [
            "syscall_args",
            "kernel_threads",
            "kernel_futex",
        ],
        ("crates/paludarium-vfs/src/path.rs",): names,
        ("crates/paludarium-jit/src/lib.rs",): [],
        ("crates/paludarium-runtime/src/lib.rs", "docs/a.md"): [],
        ("Cargo.lock",): names,
        ("crates/paludarium-jit/Cargo.toml",): names,
        ("rust-toolchain.toml",): names,
        ("fuzz/lsan.supp",): names,
        (".github/workflows/fuzz-pr.yml",): names,
        ("scripts/ci-changes.py",): names,
        ("crates/paludarium-new/src/lib.rs",): names,
        ("docs/a.md",): [],
        (): names,
    }
    for paths, expected in cases.items():
        got = fuzz_selection(paths, names, fixed, sources.__getitem__)
        if got != expected:
            raise AssertionError(f"{paths}: fuzz {got} != {expected}")
    try:
        linked_crates("x", fixed, {"x.rs": "use paludarium_gone::X;"}.__getitem__)
    except AssertionError:
        pass
    else:
        raise AssertionError("a package cargo metadata does not list must be refused")
    return len(cases)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--all", action="store_true", help="need every group (push to main)")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    paths = None if args.all else sys.stdin.read().splitlines()
    groups = ALL if args.all else needed(paths)
    targets = pr_fuzz_targets()
    fuzz = targets if args.all else fuzz_selection(paths, targets)
    lines = [f"{g}={'true' if g in groups else 'false'}" for g in GROUPS]
    lines.append(f"fuzz_targets={json.dumps(fuzz, separators=(',', ':'))}")
    print("\n".join(lines))
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
