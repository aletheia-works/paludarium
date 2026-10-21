"""release-acceptance producer tests. The GitHub adapter is replaced by an in-memory
world built from the real artifact schemas; nothing reaches the network, and a
passing test is not evidence that any real run, registry or approval exists."""

import copy
import io
import json
import os
import re
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/release"))
sys.path.insert(0, str(ROOT / "tests/release"))  # also importable as tests.release.test_acceptance
import acceptance as A  # noqa: E402
import check  # noqa: E402
import policy  # noqa: E402
from test_policy import valid  # noqa: E402

HEAD = "a" * 40
OTHER = "c" * 40
GUESTS = {"probe": "1" * 64, "aube": "2" * 64}
MODULE = "3" * 64
API = "https://api.github.com/repos/" + policy.REPOSITORY + "/"


def row(stdout="", stderr="", exit=0):
    return dict(stdout=stdout, stderr=stderr, exit=exit, timed_out=False, wall_seconds=0.1)


def guest_rows(passing=False):
    rows = {"probe-" + i: row(f"PASS {i}\n") for i in A.PROBE_ITEMS}
    rows["probe-all"] = row("".join(f"PASS {i}\n" for i in A.PROBE_ITEMS))
    rows["probe-environment"] = row("PASS environment linux x86_64\n")
    rows["version"] = row("2.8.1 linux-x64 (2026-10-20)\n")
    rows["install"] = row("Packages: +2\n")
    rows["frozen"] = row(stderr="\x1b[32m+ filedep@1.0.0\x1b[0m\n+ linked@2.0.0\n")
    rows["list"] = row("app\n├── filedep 1.0.0\n└── linked 2.0.0\n")
    if passing:
        for value in rows.values():
            value["pass"] = True
    return rows


def native(**extra):
    return dict(
        schema=1, binary_hashes=dict(GUESTS), rows=guest_rows(), native_complete=True, **extra
    )


def emulated():
    return dict(schema=1, binary_hashes=dict(GUESTS), rows=guest_rows(), differential_complete=True)


def encode(document):
    return json.dumps(document, indent=2).encode()


class World:
    """Official runs/jobs/artifacts of one head, shaped like the GitHub REST responses."""

    def __init__(self):
        self.oracle = encode(native())
        oracle_sha = A.sha(self.oracle)
        self.runs = {}
        workflows = sorted({w for w, _ in A.QUALITY.values()} | {s[0] for s in A.SOURCES.values()})
        for number, workflow in enumerate(workflows, 1):
            self.runs[workflow] = dict(
                id=100 + number,
                path=workflow,
                head_sha=HEAD,
                event="workflow_dispatch",
                head_branch="main",
                status="completed",
                conclusion="success",
                run_attempt=1,
                repository=dict(full_name=policy.REPOSITORY),
                head_repository=dict(full_name=policy.REPOSITORY),
            )
        self.runs[A.CI]["event"] = "push"
        self.extra_runs = []
        self.jobs = {w: {} for w in self.runs}
        for workflow, names in A.QUALITY.values():
            for name in names:
                self.add_job(workflow, name)
        for workflow, name, _ in A.SOURCES.values():
            self.add_job(workflow, name)
        self.members = {w: {} for w in self.runs}
        self.members[A.CI]["programs-differential"] = {
            "observations.json": encode(emulated()),
            "native/observations.json": encode(native()),
        }
        self.members[A.U12]["macos-host"] = {
            "comparison/observations.json": encode(emulated()),
            "comparison-original/observations.json": encode(emulated()),
        }
        self.members[A.U12]["macos-native-first"] = {
            "macos/native/observations.json": encode(native()),
            "macos/native-original/observations.json": encode(native()),
        }
        self.members[A.U14]["windows-host"] = {
            "windows/comparison/observations.json": encode(emulated()),
            "windows/comparison-original/observations.json": encode(emulated()),
        }
        self.members[A.U14]["windows-native-first"] = {
            "windows/native/observations.json": encode(native()),
            "windows/native-original/observations.json": encode(native()),
        }
        self.members[A.U14]["wasm-acceptance-inputs"] = {
            "target/wasm/native/observations.json": self.oracle
        }
        for environment in A.WASM_OS:
            document = dict(
                schema=1,
                environment=environment,
                module_sha256=MODULE,
                oracle_sha256=oracle_sha,
                guest_hashes=dict(GUESTS),
                complete=True,
                passed=True,
                caseCount=28,
                rows={"interpreter": guest_rows(True), "jit": guest_rows(True)},
                modes={
                    m: dict(rows={}, complete=True, passed=True) for m in ("interpreter", "jit")
                },
            )
            members = {"observations.json": encode(document)}
            if environment == "node":
                members["performance/observations.json"] = encode(
                    {
                        "schema": 1,
                        "head": HEAD,
                        "moduleSha256": MODULE,
                        "oracleSha256": oracle_sha,
                        "probeSha256": GUESTS["probe"],
                        "complete": True,
                        "passed": True,
                        "warmupsPassed": True,
                        "rows": [
                            {
                                "exit": 0,
                                "timed_out": False,
                                "pass": True,
                                "pair": i // 2,
                                "jit": bool(i % 2),
                            }
                            for i in range(20)
                        ],
                        "result": {
                            "meanInterpreter": 4.5277,
                            "meanJit": 3.6349,
                            "p": 1 / 1024,
                            "pass": True,
                        },
                    }
                )
            self.members[A.U14]["wasm-" + environment] = members
        self.tamper = {}

    def add_job(self, workflow, name):
        self.jobs[workflow].setdefault(
            name,
            dict(
                id=len(self.jobs[workflow]) + 1000 * self.runs[workflow]["id"],
                name=name,
                head_sha=HEAD,
                status="completed",
                conclusion="success",
            ),
        )

    def edit(self, workflow, artifact, member, change):
        document = json.loads(self.members[workflow][artifact][member])
        change(document)
        self.members[workflow][artifact][member] = encode(document)

    def api(self):
        return FakeApi(self)


class FakeApi:
    def __init__(self, world):
        self.world, self.routes, self.archives, self.listings = world, [], {}, {}
        runs = list(world.runs.values()) + world.extra_runs
        self.listings["runs"] = runs
        for workflow, run in world.runs.items():
            self.listings[("jobs", run["id"])] = list(world.jobs[workflow].values())
            items = []
            for number, (name, members) in enumerate(sorted(world.members[workflow].items()), 1):
                buffer = io.BytesIO()
                with zipfile.ZipFile(buffer, "w") as archive:
                    for member, data in members.items():
                        archive.writestr(member, data)
                raw = buffer.getvalue()
                artifact_id = run["id"] * 100 + number
                url = API + f"actions/artifacts/{artifact_id:d}/zip"
                self.archives[url] = raw
                item = dict(
                    id=artifact_id,
                    name=name,
                    expired=False,
                    size_in_bytes=len(raw),
                    digest="sha256:" + A.sha(raw),
                    archive_download_url=url,
                    workflow_run=dict(id=run["id"], head_sha=run["head_sha"]),
                )
                item.update(world.tamper.get(name, {}))
                items.append(item)
            self.listings[("artifacts", run["id"])] = items

    def get(self, route):
        self.routes.append(route)
        if route.startswith("actions/runs?head_sha=" + HEAD):
            rows = self.listings["runs"]
            return dict(total_count=len(rows), workflow_runs=copy.deepcopy(rows))
        found = re.fullmatch(r"actions/runs/(\d+)/(jobs|artifacts)\?.*", route)
        if not found:
            raise AssertionError("unexpected route " + route)
        rows = self.listings[(found.group(2), int(found.group(1)))]
        return {"total_count": len(rows), found.group(2): copy.deepcopy(rows)}

    def download(self, url):
        return self.archives[url]


class AcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.world = World()

    def produce(self):
        return A.produce(self.world.api(), HEAD)

    def rejected(self, pattern):
        with self.assertRaisesRegex(ValueError, pattern):
            self.produce()

    def test_success_document_shape(self):
        api = self.world.api()
        document = A.produce(api, HEAD)
        self.assertTrue(all(r.startswith("actions/runs") for r in api.routes))
        self.assertEqual({r["purpose"] for r in document["quality"]}, policy.REQUIRED)
        self.assertEqual(len(document["quality"]), len(policy.REQUIRED))
        self.assertTrue(
            all(
                r["head_sha"] == HEAD
                and r["conclusion"] == "success"
                and r["repository"] == policy.REPOSITORY
                for r in document["quality"]
            )
        )
        self.assertEqual({r["id"] for r in document["acceptance"]}, policy.ACCEPTANCE)
        self.assertTrue(
            all(
                r["passed"] is True
                and r["head"] == HEAD
                and re.fullmatch("[0-9a-f]{64}", r["artifact_sha256"])
                for r in document["acceptance"]
            )
        )
        for key in (
            "trusted_publishers_registered",
            "first_publication",
            "registries_absent",
            "registry_resume_verified",
        ):
            self.assertNotIn(key, document)
        self.assertFalse([key for key in document if key.endswith("_basis")])
        self.assertEqual(document["evidence"]["performance"]["result"]["p"], 1 / 1024)
        self.assertIs(document["published"], False)

    def test_purpose_workflow_missing(self):
        del self.world.runs[A.RELEASE_CHECK]
        self.rejected("release-check.yml: 0 official")

    def test_failed_run(self):
        self.world.runs[A.CI]["conclusion"] = "failure"
        self.rejected("ci.yml: run unfinished or not successful")

    def test_unfinished_run(self):
        self.world.runs[A.U14].update(status="in_progress", conclusion=None)
        self.rejected("quality.yml: run unfinished")

    def test_failed_job(self):
        self.world.jobs[A.CI]["lint"]["conclusion"] = "failure"
        self.rejected("job 'lint' not successful")

    def test_other_head(self):
        with self.subTest("run"):
            self.world.runs[A.U12]["head_sha"] = OTHER
            self.rejected("macos-quality.yml: 0 official")
        with self.subTest("artifact"):
            self.world = World()
            self.world.tamper["macos-host"] = dict(workflow_run=dict(id=0, head_sha=OTHER))
            self.rejected("macos-host: expired or from another run/head")
        with self.subTest("performance document"):
            self.world = World()
            self.world.edit(
                A.U14, "wasm-node", "performance/observations.json", lambda d: d.update(head=OTHER)
            )
            self.rejected("FR8.3 not met by performance")

    def test_other_repository(self):
        with self.subTest("fork pull request run is not official"):
            self.world.runs[A.U12]["head_repository"] = dict(full_name="attacker/paludarium")
            self.rejected("macos-quality.yml: 0 official")
        with self.subTest("fork workflow run"):
            environ = dict(
                GITHUB_REPOSITORY="Marukome0743/paludarium",
                GITHUB_REF="refs/heads/main",
                GITHUB_SHA=HEAD,
            )
            with self.assertRaisesRegex(ValueError, "only in aletheia-works"):
                A.main(["--output", "unused.json"], environ, self.world.api())

    def test_artifact_digest_differs(self):
        self.world.tamper["macos-host"] = dict(digest="sha256:" + "0" * 64)
        self.rejected("macos-host: official artifact digest/size differs")

    def test_fr83_not_passed(self):
        def failed(document):
            document.update(passed=False)
            document["result"].update(p=529 / 1024, meanJit=5.4987, meanInterpreter=5.4972)
            document["result"]["pass"] = False

        self.world.edit(A.U14, "wasm-node", "performance/observations.json", failed)
        self.rejected("FR8.3 not met by performance")

    def test_duplicate_purpose_runs(self):
        second = dict(copy.deepcopy(self.world.runs[A.CI]), id=999, event="workflow_dispatch")
        self.world.extra_runs.append(second)
        self.rejected("ci.yml: 2 official same-head main runs")

    def test_pull_request_run_ignored(self):
        self.world.extra_runs.append(
            dict(
                copy.deepcopy(self.world.runs[A.CI]),
                id=998,
                event="pull_request",
                head_branch="codex/build-and-test",
                conclusion="failure",
            )
        )
        self.assertEqual(len(self.produce()["quality"]), 8)

    def test_probe_failure_in_one_environment(self):
        def fail(document):
            document["rows"]["probe-rayon"]["stdout"] = "FAIL rayon\n"

        self.world.edit(A.U14, "windows-host", "windows/comparison/observations.json", fail)
        self.rejected("FR6.3 not met by windows-native")

    def test_jit_mode_failure(self):
        self.world.edit(
            A.U14,
            "wasm-firefox",
            "observations.json",
            lambda d: d["modes"]["jit"].update(passed=False),
        )
        self.rejected("FR8.2 not met by wasm-firefox")

    def test_guest_bytes_differ_from_oracle(self):
        self.world.edit(
            A.U14,
            "windows-host",
            "windows/comparison/observations.json",
            lambda d: d["binary_hashes"].update(aube="9" * 64),
        )
        self.rejected("guest bytes differ from its oracle")

    def test_wasm_module_differs(self):
        self.world.edit(
            A.U14, "wasm-safari", "observations.json", lambda d: d.update(module_sha256="4" * 64)
        )
        self.rejected("wasm environments ran different modules")

    def test_incomplete_rows(self):
        self.world.edit(
            A.CI, "programs-differential", "observations.json", lambda d: d["rows"].pop("frozen")
        )
        self.rejected("row population incomplete")

    def test_paginated_listing_refused(self):
        api = self.world.api()
        api.listings["runs"] = api.listings["runs"] * 30
        with self.assertRaisesRegex(ValueError, "paginated listing refused"):
            A.produce(api, HEAD)

    def test_unreadable_artifact(self):
        # A ZIP whose official digest matches but whose bytes are not an archive.
        api = self.world.api()
        item = next(
            i
            for i in api.listings[("artifacts", self.world.runs[A.U12]["id"])]
            if i["name"] == "macos-host"
        )
        api.archives[item["archive_download_url"]] = b"not a zip"
        item.update(digest="sha256:" + A.sha(b"not a zip"), size_in_bytes=9)
        with self.assertRaisesRegex(ValueError, "macos-host: unreadable artifact"):
            A.produce(api, HEAD)

    def test_main_writes_exclusive_output(self):
        environ = dict(
            GITHUB_REPOSITORY=policy.REPOSITORY, GITHUB_REF="refs/heads/main", GITHUB_SHA=HEAD
        )
        with tempfile.TemporaryDirectory(dir=ROOT / "target/release-evidence") as directory:
            output = Path(directory) / "out/release-evidence.json"
            with patch("builtins.print"):
                summary = A.main(["--output", str(output)], environ, self.world.api())
            self.assertEqual(summary["quality"], 8)
            self.assertEqual(set(summary), {"head", "quality", "acceptance", "output"})
            self.assertEqual(json.loads(output.read_bytes())["head"], HEAD)
            with patch("builtins.print"), self.assertRaises(FileExistsError):
                A.main(["--output", str(output)], environ, self.world.api())

    def test_main_rejects_non_main_ref_and_bad_head(self):
        base = dict(
            GITHUB_REPOSITORY=policy.REPOSITORY, GITHUB_REF="refs/heads/main", GITHUB_SHA=HEAD
        )
        with self.assertRaisesRegex(ValueError, "only for main"):
            A.main(
                ["--output", "unused.json"],
                dict(base, GITHUB_REF="refs/heads/codex/build-and-test"),
                self.world.api(),
            )
        with self.assertRaisesRegex(ValueError, "invalid head"):
            A.main(["--output", "unused.json"], dict(base, GITHUB_SHA="v0.1.0"), self.world.api())


class AdapterTests(unittest.TestCase):
    class Opener:
        def __init__(self, body=b'{"total_count":0}', error=None):
            self.body, self.error, self.requests = body, error, []

        def open(self, request, timeout):
            self.requests.append((request, timeout))
            if self.error:
                raise self.error
            return io.BytesIO(self.body)

    def test_get_and_download_are_read_only(self):
        opener = self.Opener()
        api = A.GitHubApi("not-a-real-token", opener)
        self.assertEqual(api.get("actions/runs?head_sha=" + HEAD), {"total_count": 0})
        request, timeout = opener.requests[0]
        self.assertEqual(request.get_method(), "GET")
        self.assertEqual(timeout, 60)
        self.assertTrue(request.full_url.startswith(API))
        self.assertEqual(api.download(API + "actions/artifacts/1/zip"), b'{"total_count":0}')
        with self.assertRaisesRegex(ValueError, "outside repository"):
            api.download("https://example.invalid/artifact.zip")

    def test_errors_are_not_success(self):
        error = urllib.error.HTTPError(API, 503, "unavailable", {}, io.BytesIO(b""))
        with self.assertRaisesRegex(ValueError, "503"):
            A.GitHubApi("t", self.Opener(error=error)).get("actions/runs/1/jobs")
        with self.assertRaisesRegex(ValueError, "unreachable"):
            A.GitHubApi("t", self.Opener(error=urllib.error.URLError("down"))).get(
                "actions/runs/1/jobs"
            )
        with patch.object(A, "MAX_ARCHIVE", 4), self.assertRaisesRegex(ValueError, "too large"):
            A.GitHubApi("t", self.Opener(body=b"12345")).download(API + "actions/artifacts/1/zip")
        with self.assertRaisesRegex(ValueError, "token unavailable"):
            A.GitHubApi(None)

    def test_redirect_to_storage_drops_token(self):
        handler = A._DropAuthorizationOnRedirect()
        request = urllib.request.Request(
            API + "actions/artifacts/1/zip", headers={"Authorization": "Bearer t"}
        )
        moved = handler.redirect_request(
            request, None, 302, "Found", {}, "https://storage.example.invalid/blob?sig=x"
        )
        self.assertFalse(moved.has_header("Authorization"))
        same = handler.redirect_request(
            request, None, 302, "Found", {}, API + "actions/artifacts/2/zip"
        )
        self.assertTrue(same.has_header("Authorization"))
        self.assertIsInstance(A.GitHubApi("t").opener, urllib.request.OpenerDirector)

    def test_workflow_contract(self):
        text = (ROOT / ".github/workflows/release-acceptance.yml").read_text()
        trigger = text.split("\non:\n", 1)[1].split("\npermissions:", 1)[0]
        self.assertIn("workflow_dispatch:", trigger)
        self.assertNotRegex(trigger, r"\n  (push|pull_request|schedule|workflow_call):")
        permissions = text.split("\npermissions:\n", 1)[1].split("\n", 3)[:2]
        self.assertEqual(permissions, ["  contents: read", "  actions: read"])
        self.assertNotIn("write", text.split("\njobs:", 1)[1].replace("if-no-files-found", ""))
        actions = re.findall(r"uses:\s+([^\s#]+)", text)
        self.assertEqual(len(actions), 3)
        self.assertTrue(all(re.fullmatch(r"[^@]+@[0-9a-f]{40}", a) for a in actions))
        self.assertIn("persist-credentials: false", text)
        self.assertIn("timeout-minutes:", text)
        self.assertEqual(
            re.findall(r"\n\s+name: (release-[a-z-]+)\n", text), ["release-acceptance"]
        )
        self.assertEqual(
            re.findall(r"\n\s+path: (\S+)\n", text),
            ["target/release-evidence/release-evidence.json"],
        )
        # Trusted Publishing only: dispatched with no inputs and no declaration.
        self.assertEqual(trigger.strip(), "workflow_dispatch:")
        for name in ("inputs", "U15_TRUSTED_PUBLISHERS_REGISTERED", "U15_FIRST_PUBLICATION"):
            self.assertNotIn(name, text)


class AcceptanceIntegrationTests(unittest.TestCase):
    """Produced document -> check.fetch_acceptance -> policy.release_gate (mocked GitHub only)."""

    def gate_state(self):
        document = A.produce(World().api(), HEAD)
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("release-evidence.json", json.dumps(document))
        raw = buffer.getvalue()
        artifact = dict(
            name="release-acceptance",
            expired=False,
            workflow_run=dict(head_sha=HEAD),
            digest="sha256:" + A.sha(raw),
            archive_download_url=API + "actions/artifacts/7/zip",
        )

        def github(route):
            if route.startswith("actions/runs?"):
                return dict(
                    total_count=1,
                    workflow_runs=[
                        dict(id=7, head_sha=HEAD, repository=dict(full_name=policy.REPOSITORY))
                    ],
                )
            return dict(total_count=1, artifacts=[artifact])

        env = dict(GITHUB_SHA=HEAD, GH_TOKEN="not-a-real-token")
        with (
            patch.dict(os.environ, env),
            patch.object(check, "github", side_effect=github),
            patch.object(check.urllib.request, "urlopen", return_value=io.BytesIO(raw)),
        ):
            data = check.fetch_acceptance(ROOT)
        fixture, inventory = valid()
        state = dict(
            data,
            repository=policy.REPOSITORY,
            tag="v" + inventory["version"],
            commit=fixture["commit"],
            main_compare=fixture["main_compare"],
            environment=fixture["environment"],
        )
        return state, inventory

    def test_document_passes_fetch_and_release_gate(self):
        state, inventory = self.gate_state()
        result = policy.release_gate(state, inventory)
        self.assertTrue(result["eligible"])
        self.assertEqual(result["head"], HEAD)
        self.assertNotIn("authentication", result)


if __name__ == "__main__":
    unittest.main()
