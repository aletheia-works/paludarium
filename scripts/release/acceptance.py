"""Same-head acceptance evidence producer for the release-acceptance artifact.

It reads official GitHub run, job and artifact metadata and artifact ZIPs of
the authorized upstream repository only, through the GitHubApi adapter, and
writes release-evidence.json in the shape that check.fetch_acceptance and
policy.release_gate consume. It never tags, approves, publishes or reruns
anything. A missing, failed, unfinished, ambiguous or mismatched input stops
it with ValueError; no partial document is written.

Publication is by Trusted Publishing (OIDC) only, so the document carries no
authentication declaration: the publish job's OIDC token exchange is what
proves the registry side.
"""

import argparse
import hashlib
import io
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

import policy

MAX_ARCHIVE = 256 * 1024 * 1024
LISTING_LIMIT = 100
HEAD = re.compile("[0-9a-f]{40}")
ANSI = re.compile(r"\x1b\[[0-9;]*m")

CI = ".github/workflows/ci.yml"
U12 = ".github/workflows/macos-quality.yml"
U14 = ".github/workflows/quality.yml"
RELEASE_CHECK = ".github/workflows/release-check.yml"
U10_JOB = "fixed guest programs / differential"
NODE_JOB = "wasm-programs / differential (ubuntu-latest, node)"
EVIDENCE_EVENTS = ("push", "workflow_dispatch")

# Quality purpose -> (official workflow, jobs that must exist and succeed).
QUALITY = {
    "three-os": (
        CI,
        ("unit tests (ubuntu-latest)", "unit tests (macos-latest)", "unit tests (windows-latest)"),
    ),
    "lint": (CI, ("lint",)),
    "dependencies": (CI, ("dependencies",)),
    "linux-differential": (CI, ("differential tests (x86-64 Linux)", U10_JOB)),
    "rust-coverage": (CI, ("line coverage >= 80%",)),
    "js-coverage": (U14, (NODE_JOB,)),
    "u9-coverage": (CI, ("line coverage >= 80%",)),
    "package-check": (RELEASE_CHECK, ("packages",)),
}

PROBE_ITEMS = (
    "tokio-timer",
    "unix-stream-pair",
    "rayon",
    "mutex-condvar",
    "fs-basic",
    "fs-hardlink",
    "fs-symlink",
    "fs-flock",
)
PROBE_ROWS = (*tuple("probe-" + n for n in PROBE_ITEMS), "probe-all", "probe-environment")
AUBE_ROWS = ("version", "install", "frozen", "list")
ROWS = PROBE_ROWS + AUBE_ROWS
WASM_OS = {
    "node": "ubuntu-latest",
    "chromium": "ubuntu-latest",
    "firefox": "ubuntu-latest",
    "safari": "macos-latest",
}

# Evidence source -> (workflow, consuming job, {artifact: members read}).
# Guests are rebuilt in every job (aube embeds its build date), so each
# environment is checked against the fresh native oracle of its own run,
# with equal guest bytes; guests are never compared across runs.
U11_INPUTS = {"wasm-acceptance-inputs": ("target/wasm/native/observations.json",)}
SOURCES = {
    "linux-native": (
        CI,
        U10_JOB,
        {"programs-differential": ("observations.json", "native/observations.json")},
    ),
    "macos-native": (
        U12,
        "macos-host",
        {
            "macos-host": (
                "comparison/observations.json",
                "comparison-original/observations.json",
            ),
            "macos-native-first": (
                "macos/native/observations.json",
                "macos/native-original/observations.json",
            ),
        },
    ),
    "windows-native": (
        U14,
        "windows-host",
        {
            "windows-host": (
                "windows/comparison/observations.json",
                "windows/comparison-original/observations.json",
            ),
            "windows-native-first": (
                "windows/native/observations.json",
                "windows/native-original/observations.json",
            ),
        },
    ),
    "performance": (U14, NODE_JOB, {"wasm-node": ("performance/observations.json",)}),
}
for _env, _os in WASM_OS.items():
    SOURCES["wasm-" + _env] = (
        U14,
        f"wasm-programs / differential ({_os}, {_env})",
        {"wasm-" + _env: ("observations.json",), **U11_INPUTS},
    )
# Emulated document -> its native oracle, per host source.
HOST_PAIRS = {
    "macos-native": (
        ("comparison/observations.json", "macos/native/observations.json"),
        ("comparison-original/observations.json", "macos/native-original/observations.json"),
    ),
    "windows-native": (
        ("windows/comparison/observations.json", "windows/native/observations.json"),
        (
            "windows/comparison-original/observations.json",
            "windows/native-original/observations.json",
        ),
    ),
}
NATIVE_SOURCES = ("linux-native", "macos-native", "windows-native")
WASM_SOURCES = tuple("wasm-" + e for e in WASM_OS)
ACCEPTANCE_SOURCES = {
    "FR6.3": NATIVE_SOURCES + WASM_SOURCES,
    "FR7.2": NATIVE_SOURCES + WASM_SOURCES,
    "FR8.2": WASM_SOURCES,
    "FR8.3": ("performance",),
}
DIGEST_DEFINITION = (
    "artifact_sha256 is the SHA-256 of the canonical JSON list of "
    "[source, artifact name, artifact id, official artifact digest] rows of every "
    "artifact the condition was checked against, sorted"
)


def sha(data):
    return hashlib.sha256(data).hexdigest()


class _DropAuthorizationOnRedirect(urllib.request.HTTPRedirectHandler):
    """Artifact downloads redirect to storage on another host; never forward the token there."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if (
            new is not None
            and urllib.parse.urlsplit(newurl).netloc != urllib.parse.urlsplit(req.full_url).netloc
        ):
            new.remove_header("Authorization")
        return new


class GitHubApi:
    """Read-only adapter boundary; tests substitute it and never reach the network."""

    def __init__(self, token, opener=None):
        policy.require(bool(token), "GitHub read token unavailable")
        self.token = token
        self.opener = opener or urllib.request.build_opener(_DropAuthorizationOnRedirect)

    def _open(self, url, limit):
        request = urllib.request.Request(
            url,
            headers={
                "Authorization": "Bearer " + self.token,
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with self.opener.open(request, timeout=60) as response:
                data = response.read(limit + 1)
        except urllib.error.HTTPError as error:
            raise ValueError(f"GitHub evidence unavailable: {error.code:d} {url}") from error
        except urllib.error.URLError as error:
            raise ValueError(f"GitHub unreachable: {url}") from error
        policy.require(len(data) <= limit, "GitHub response too large: " + url)
        return data

    def get(self, route):
        return json.loads(
            self._open(
                "https://api.github.com/repos/" + policy.REPOSITORY + "/" + route, 64 * 1024 * 1024
            )
        )

    def download(self, url):
        policy.require(
            url.startswith("https://api.github.com/repos/" + policy.REPOSITORY + "/"),
            "artifact URL outside repository",
        )
        return self._open(url, MAX_ARCHIVE)


def listing(api, route, key):
    body = api.get(route + ("&" if "?" in route else "?") + f"per_page={LISTING_LIMIT:d}")
    rows = body.get(key)
    policy.require(
        isinstance(rows, list)
        and body.get("total_count") == len(rows)
        and len(rows) <= LISTING_LIMIT,
        "incomplete or paginated listing refused: " + route,
    )
    return rows


def official(run, head):
    return (
        run.get("head_sha") == head
        and run["repository"]["full_name"] == policy.REPOSITORY
        and (run.get("head_repository") or {}).get("full_name") == policy.REPOSITORY
        and run.get("event") in EVIDENCE_EVENTS
        and run.get("head_branch") == "main"
    )


def select_run(runs, workflow, head):
    """Exactly one official main run of the workflow at head; it must have completed successfully."""
    found = [r for r in runs if r.get("path") == workflow and official(r, head)]
    policy.require(
        len(found) == 1,
        f"{workflow}: {len(found):d} official same-head main runs (exactly one required)",
    )
    run = found[0]
    policy.require(
        run["status"] == "completed" and run["conclusion"] == "success",
        workflow + ": run unfinished or not successful",
    )
    policy.require(type(run["id"]) is int and run["id"] > 0, workflow + ": invalid run identity")
    return run


class Collector:
    def __init__(self, api, head):
        policy.require(bool(HEAD.fullmatch(head)), "invalid head")
        self.api, self.head = api, head
        self.runs = listing(api, "actions/runs?head_sha=" + head, "workflow_runs")
        self._jobs, self._artifacts, self._downloads = {}, {}, {}

    def run(self, workflow):
        return select_run(self.runs, workflow, self.head)

    def jobs(self, run):
        if run["id"] not in self._jobs:
            self._jobs[run["id"]] = listing(
                self.api, "actions/runs/{:d}/jobs?filter=latest".format(run["id"]), "jobs"
            )
        return self._jobs[run["id"]]

    def job(self, run, name):
        found = [j for j in self.jobs(run) if j.get("name") == name]
        policy.require(
            len(found) == 1, "{}: job {!r} absent or duplicated".format(run["path"], name)
        )
        job = found[0]
        policy.require(
            job.get("head_sha") == self.head
            and job.get("status") == "completed"
            and job.get("conclusion") == "success",
            "{}: job {!r} not successful at head".format(run["path"], name),
        )
        return dict(id=job["id"], name=name, conclusion=job["conclusion"])

    def artifact(self, run, name):
        key = (run["id"], name)
        if key in self._downloads:
            return self._downloads[key]
        if run["id"] not in self._artifacts:
            self._artifacts[run["id"]] = listing(
                self.api, "actions/runs/{:d}/artifacts".format(run["id"]), "artifacts"
            )
        found = [a for a in self._artifacts[run["id"]] if a.get("name") == name]
        policy.require(
            len(found) == 1, "{}: artifact {} absent or duplicated".format(run["path"], name)
        )
        item = found[0]
        policy.require(
            item.get("expired") is False
            and item["workflow_run"]["id"] == run["id"]
            and item["workflow_run"]["head_sha"] == self.head,
            name + ": expired or from another run/head",
        )
        raw = self.api.download(item["archive_download_url"])
        policy.require(
            item.get("digest") == "sha256:" + sha(raw) and item.get("size_in_bytes") == len(raw),
            name + ": official artifact digest/size differs",
        )
        self._downloads[key] = (item, raw)
        return item, raw


def read_members(raw, names, label):
    """Parsed JSON members and the SHA-256 of their exact bytes."""
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            listed = archive.namelist()
            policy.require(len(listed) == len(set(listed)), label + ": duplicate archive member")
            documents, digests = {}, {}
            for name in names:
                policy.require(name in listed, label + ": member missing: " + name)
                data = archive.read(name)
                documents[name], digests[name] = json.loads(data), sha(data)
            return documents, digests
    except (zipfile.BadZipFile, json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ValueError(label + ": unreadable artifact: " + str(error)) from error


# ------------------------------------------------------------------ content predicates


def row_ok(row):
    return (
        isinstance(row, dict)
        and row.get("timed_out") is not True
        and isinstance(row.get("exit"), int)
    )


def probe_passed(rows):
    """FR6.3: every probe item prints exactly its PASS line, exit 0."""
    for item in PROBE_ITEMS:
        row = rows["probe-" + item]
        if row["exit"] != 0 or row["stdout"].splitlines() != ["PASS " + item]:
            return False
    whole, environment = rows["probe-all"], rows["probe-environment"]
    return (
        whole["exit"] == 0
        and whole["stdout"].splitlines() == ["PASS " + i for i in PROBE_ITEMS]
        and environment["exit"] == 0
        and environment["stdout"].startswith("PASS ")
    )


def aube_matches(rows, native):
    """FR7.2 bound check: same exit for all four commands and identical --version stdout."""
    return (
        all(rows[n]["exit"] == native[n]["exit"] for n in AUBE_ROWS)
        and rows["version"]["stdout"] == native["version"]["stdout"]
    )


def rows_of(document, key, label):
    rows = document.get(key)
    policy.require(
        isinstance(rows, dict) and all(n in rows and row_ok(rows[n]) for n in ROWS),
        label + ": row population incomplete or timed out",
    )
    return rows


def guest_hashes(document, key, label):
    value = document.get(key)
    policy.require(
        isinstance(value, dict)
        and set(value) == {"probe", "aube"}
        and all(isinstance(v, str) and re.fullmatch("[0-9a-f]{64}", v) for v in value.values()),
        label + ": guest hashes absent",
    )
    return value


def verdicts(rows, native):
    return {"FR6.3": probe_passed(rows), "FR7.2": aube_matches(rows, native)}


def native_oracle(document, label):
    """A fresh native x86-64 Linux oracle that itself shows the expected probe results."""
    policy.require(document.get("native_complete") is True, label + ": native oracle incomplete")
    rows = rows_of(document, "rows", label)
    policy.require(probe_passed(rows), label + ": native oracle does not show the expected results")
    return guest_hashes(document, "binary_hashes", label), rows


def compared(label, emulated, oracle_document):
    hashes, oracle = native_oracle(oracle_document, label + " oracle")
    policy.require(
        emulated.get("differential_complete") is True, label + ": differential incomplete"
    )
    policy.require(
        guest_hashes(emulated, "binary_hashes", label) == hashes,
        label + ": guest bytes differ from its oracle",
    )
    return verdicts(rows_of(emulated, "rows", label), oracle)


def native_result(label, documents):
    pairs = HOST_PAIRS.get(label, (("observations.json", "native/observations.json"),))
    return dict(
        modes={
            emulated: compared(f"{label} {emulated}", documents[emulated], documents[oracle])
            for emulated, oracle in pairs
        }
    )


def wasm(label, documents, digests):
    environment = label.removeprefix("wasm-")
    document, oracle_name = documents["observations.json"], U11_INPUTS["wasm-acceptance-inputs"][0]
    hashes, oracle = native_oracle(documents[oracle_name], label + " oracle")
    policy.require(
        document.get("environment") == environment
        and document.get("complete") is True
        and document.get("passed") is True
        and document.get("caseCount") == 28,
        label + ": not complete/passed",
    )
    policy.require(
        guest_hashes(document, "guest_hashes", label) == hashes,
        label + ": guest bytes differ from its oracle",
    )
    policy.require(
        document.get("oracle_sha256") == digests[oracle_name],
        label + ": compared with a different oracle",
    )
    modes = document.get("modes") or {}
    result = {}
    for mode in ("interpreter", "jit"):
        state = modes.get(mode) or {}
        rows = rows_of(document.get("rows", {}), mode, label + " " + mode)
        mode_ok = (
            state.get("complete") is True
            and state.get("passed") is True
            and all(rows[n].get("pass") is True for n in ROWS)
        )
        result[mode] = dict(verdicts(rows, oracle), mode_passed=mode_ok)
    module = document.get("module_sha256")
    policy.require(
        isinstance(module, str) and bool(re.fullmatch("[0-9a-f]{64}", module)),
        label + ": module digest absent",
    )
    return dict(module=module, oracle=digests[oracle_name], probe=hashes["probe"], modes=result)


def performance(document, head):
    result = document.get("result") or {}
    rows = document.get("rows") or []
    ok = (
        document.get("head") == head
        and document.get("complete") is True
        and document.get("passed") is True
        and document.get("warmupsPassed") is True
        and result.get("pass") is True
        and isinstance(result.get("p"), (int, float))
        and result["p"] < 0.05
        and result.get("meanJit", 1) < result.get("meanInterpreter", 0)
        and len(rows) == 20
        and all(r.get("exit") == 0 and r.get("pass") is True for r in rows)
    )
    return dict(
        passed=ok,
        head=document.get("head"),
        p=result.get("p"),
        meanJit=result.get("meanJit"),
        meanInterpreter=result.get("meanInterpreter"),
        module=document.get("moduleSha256"),
        oracle=document.get("oracleSha256"),
        probe=document.get("probeSha256"),
    )


# ------------------------------------------------------------------ assembly


def quality_rows(collector):
    rows = []
    for purpose in sorted(QUALITY):
        workflow, names = QUALITY[purpose]
        run = collector.run(workflow)
        jobs = [collector.job(run, n) for n in names]
        rows.append(
            dict(
                purpose=purpose,
                repository=policy.REPOSITORY,
                head_sha=run["head_sha"],
                status=run["status"],
                conclusion=run["conclusion"],
                id=run["id"],
                workflow=workflow,
                run_attempt=run.get("run_attempt"),
                jobs=jobs,
            )
        )
    return rows


def fetch_source(collector, label):
    workflow, job_name, artifacts = SOURCES[label]
    run = collector.run(workflow)
    job = collector.job(run, job_name)
    documents, digests, rows = {}, {}, []
    for name in sorted(artifacts):
        item, data = collector.artifact(run, name)
        parsed, hashed = read_members(data, artifacts[name], label + " " + name)
        documents.update(parsed)
        digests.update(hashed)
        rows.append(
            dict(
                name=name,
                id=item["id"],
                digest=item["digest"],
                members={m: hashed[m] for m in artifacts[name]},
            )
        )
    return dict(workflow=workflow, run_id=run["id"], job=job, artifacts=rows), documents, digests


def checked_sources(collector):
    checked, results = {}, {}
    for label in sorted(SOURCES):
        checked[label], documents, digests = fetch_source(collector, label)
        if label in NATIVE_SOURCES:
            results[label] = native_result(label, documents)
        elif label in WASM_SOURCES:
            results[label] = wasm(label, documents, digests)
        else:
            results[label] = performance(documents["performance/observations.json"], collector.head)
    bind(results)
    for label in checked:
        checked[label]["result"] = results[label]
    return checked


def bind(results):
    """The four wasm environments and the measurement share one run, module, oracle and probe."""
    modules = {results[s]["module"] for s in WASM_SOURCES}
    oracles = {results[s]["oracle"] for s in WASM_SOURCES}
    policy.require(
        len(modules) == 1 and len(oracles) == 1, "wasm environments ran different modules/oracles"
    )
    measured = results["performance"]
    policy.require(
        measured["module"] in modules
        and measured["oracle"] in oracles
        and measured["probe"] == results["wasm-node"]["probe"],
        "performance measured a different module/oracle/probe",
    )


def condition_passed(condition, checked):
    for label in ACCEPTANCE_SOURCES[condition]:
        result = checked[label]["result"]
        if condition == "FR8.3":
            ok = result["passed"]
        elif condition == "FR8.2":
            ok = all(
                m["mode_passed"] and m["FR6.3"] and m["FR7.2"] for m in result["modes"].values()
            )
        elif label in WASM_SOURCES:
            ok = (
                result["modes"]["interpreter"]["mode_passed"]
                and result["modes"]["interpreter"][condition]
            )
        else:
            ok = all(m[condition] for m in result["modes"].values())
        if not ok:
            return False, label
    return True, None


def acceptance_rows(checked, head):
    rows = []
    for condition in sorted(ACCEPTANCE_SOURCES):
        passed, failed = condition_passed(condition, checked)
        policy.require(passed, f"{condition} not met by {failed}")
        binding = sorted(
            [label, a["name"], a["id"], a["digest"]]
            for label in ACCEPTANCE_SOURCES[condition]
            for a in checked[label]["artifacts"]
        )
        rows.append(
            dict(
                id=condition,
                head=head,
                passed=True,
                artifact_sha256=sha(json.dumps(binding, separators=(",", ":")).encode()),
                sources=list(ACCEPTANCE_SOURCES[condition]),
            )
        )
    return rows


def produce(api, head):
    collector = Collector(api, head)
    quality = quality_rows(collector)
    checked = checked_sources(collector)
    return dict(
        schema=1,
        producer="scripts/release/acceptance.py",
        repository=policy.REPOSITORY,
        head=head,
        quality=quality,
        acceptance=acceptance_rows(checked, head),
        evidence=checked,
        artifact_sha256_definition=DIGEST_DEFINITION,
        published=False,
    )


def main(argv=None, environ=None, api=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    env = os.environ if environ is None else environ
    policy.require(
        env.get("GITHUB_REPOSITORY") == policy.REPOSITORY,
        "acceptance evidence is produced only in " + policy.REPOSITORY,
    )
    policy.require(
        env.get("GITHUB_REF") == "refs/heads/main", "acceptance evidence is produced only for main"
    )
    head = env.get("GITHUB_SHA", "")
    api = api or GitHubApi(env.get("GH_TOKEN") or env.get("GITHUB_TOKEN"))
    document = produce(api, head)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as f:
        json.dump(document, f, indent=2, sort_keys=True)
    summary = dict(
        head=head,
        quality=len(document["quality"]),
        acceptance=[a["id"] for a in document["acceptance"]],
        output=str(args.output),
    )
    print(json.dumps(summary))
    return summary


if __name__ == "__main__":
    main()
