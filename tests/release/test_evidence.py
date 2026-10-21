"""Release evidence driver tests (the evidence and tag jobs of publish.yml). The GitHub API and the registries are
replaced by in-memory fakes; nothing reaches the network, and a passing test
is not evidence that any real run, tag or registry state exists."""

import itertools
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/release"))
import check  # noqa: E402
import evidence as E  # noqa: E402
import policy  # noqa: E402

HEAD = "a" * 40
OTHER = "c" * 40
VERSION = policy.inventory(ROOT)["version"]


class FakeGitHub:
    def __init__(self, conclusion="success"):
        self.main = HEAD
        self.tags = []
        self.runs = []
        self.posts = []
        self.conclusion = conclusion
        self.ids = itertools.count(1)
        self.add("ci.yml", "push")

    def add(self, workflow, event, head=HEAD, status="queued"):
        run = dict(
            id=next(self.ids),
            path=".github/workflows/" + workflow,
            head_sha=head,
            event=event,
            head_branch="main",
            status=status,
            conclusion=None,
            repository=dict(full_name=policy.REPOSITORY),
            head_repository=dict(full_name=policy.REPOSITORY),
        )
        self.runs.append(run)
        return run

    def get(self, route):
        if route == "commits/main":
            return dict(sha=self.main)
        if route.startswith("git/matching-refs/tags/"):
            return [
                dict(ref="refs/tags/" + t)
                for t in self.tags
                if t.startswith(route.rsplit("/", 1)[1])
            ]
        match = re.fullmatch(
            r"actions/workflows/([^/]+)/runs\?head_sha=(\w+)&event=(\w+)&per_page=100", route
        )
        if match:
            rows = [
                r
                for r in self.runs
                if r["path"].endswith("/" + match[1])
                and r["head_sha"] == match[2]
                and r["event"] == match[3]
            ]
            return dict(total_count=len(rows), workflow_runs=[dict(r) for r in rows])
        match = re.fullmatch(r"actions/runs/(\d+)", route)
        if match:
            run = next(r for r in self.runs if r["id"] == int(match[1]))
            run.update(status="completed", conclusion=self.conclusion)
            return dict(run)
        raise AssertionError("unexpected route " + route)

    def post(self, route, body):
        self.posts.append((route, body))
        workflow = re.fullmatch(r"actions/workflows/([^/]+)/dispatches", route)[1]
        self.add(workflow, "workflow_dispatch", head=self.main)


class Clock:
    def __init__(self):
        self.now = 0

    def sleep(self, seconds):
        self.now += seconds

    def __call__(self):
        return self.now


INVENTORY = policy.inventory(ROOT)
CHECKED = sorted(INVENTORY["order"] + [check.NPM_NAME])


def published(order):
    return dict(present=CHECKED, checked=CHECKED)


def never(name, version):
    return False


def produce(api, presence=published, present=never):
    clock = Clock()
    return E.produce(
        api, ROOT, HEAD, presence=presence, present=present, sleep=clock.sleep, clock=clock
    )


class Evidence(unittest.TestCase):
    def test_untagged_head_dispatches_each_run_once_then_is_ready(self):
        api = FakeGitHub()
        self.assertEqual(produce(api), dict(ready="true", version=VERSION, head=HEAD))
        self.assertEqual(
            [p[0] for p in api.posts],
            [
                f"actions/workflows/{w}/dispatches"
                for w in (
                    "macos-quality.yml",
                    "quality.yml",
                    "release-check.yml",
                    "release-acceptance.yml",
                )
            ],
        )
        self.assertEqual(api.posts[-1][1], dict(ref="main", inputs={}))
        self.assertTrue(all(p[1]["ref"] == "main" for p in api.posts))

    def test_tagged_version_does_nothing(self):
        api = FakeGitHub()
        api.tags.append("v" + VERSION)
        with self.assertRaisesRegex(E.Stop, "already tagged"):
            produce(api)
        self.assertEqual(api.posts, [])

    def test_a_longer_tag_with_the_same_prefix_is_not_the_version_tag(self):
        api = FakeGitHub()
        api.tags.append("v" + VERSION + "1")
        self.assertFalse(E.tag_exists(api, VERSION))

    def test_head_that_is_no_longer_main_does_nothing(self):
        api = FakeGitHub()
        api.main = OTHER
        with self.assertRaisesRegex(E.Stop, "no longer the main head"):
            produce(api)
        self.assertEqual(api.posts, [])

    def test_a_package_not_on_a_registry_yet_stops_before_any_dispatch(self):
        for present in (CHECKED[1:], [n for n in CHECKED if n != check.NPM_NAME], []):
            with self.subTest(present=present):
                api = FakeGitHub()
                missing = sorted(set(CHECKED) - set(present))

                def some(order, present=present):
                    return dict(present=present, checked=CHECKED)

                with self.assertRaisesRegex(
                    ValueError, "not on a registry yet: " + re.escape(", ".join(missing)) + ";"
                ):
                    produce(api, some)
                self.assertEqual(api.posts, [])

    def test_version_already_partly_published_stops(self):
        api = FakeGitHub()

        def partly(name, version):
            return name in ("paludarium-types", check.NPM_NAME)

        with self.assertRaisesRegex(
            ValueError,
            VERSION
            + " already on a registry: "
            + re.escape(", ".join(n for n in CHECKED if partly(n, VERSION)))
            + "; re-run the stopped publish job instead",
        ):
            produce(api, present=partly)
        self.assertEqual(api.posts, [])

    def test_publishable_checks_every_name_at_this_version(self):
        orders, asked = [], []
        E.publishable(
            INVENTORY,
            lambda order: orders.append(order) or published(order),
            lambda name, version: asked.append((name, version)) or False,
        )
        self.assertEqual(orders, [INVENTORY["order"]])
        self.assertEqual(asked, [(n, VERSION) for n in CHECKED])

    def test_version_present_asks_the_version_url(self):
        asked = []
        with patch.object(
            check, "registry_present", side_effect=lambda url: asked.append(url) or True
        ):
            self.assertTrue(E.version_present("paludarium-cpu", "0.2.0"))
            self.assertTrue(E.version_present(check.NPM_NAME, "0.2.0"))
        self.assertEqual(
            asked, [check.CRATES_API + "paludarium-cpu/0.2.0", check.NPM_PACKAGE_URL + "/0.2.0"]
        )

    def test_a_run_a_person_already_dispatched_is_reused(self):
        api = FakeGitHub()
        api.add("macos-quality.yml", "workflow_dispatch")
        produce(api)
        self.assertNotIn(
            "actions/workflows/macos-quality.yml/dispatches", [p[0] for p in api.posts]
        )
        self.assertEqual(len([r for r in api.runs if r["path"].endswith("/macos-quality.yml")]), 1)

    def test_two_runs_of_one_workflow_are_refused(self):
        api = FakeGitHub()
        api.add("quality.yml", "workflow_dispatch")
        api.add("quality.yml", "workflow_dispatch")
        with self.assertRaisesRegex(ValueError, "exactly one allowed"):
            produce(api)

    def test_failed_run_stops_without_acceptance_or_redispatch(self):
        api = FakeGitHub(conclusion="failure")
        with self.assertRaisesRegex(ValueError, "concluded failure; not dispatched again"):
            produce(api)
        self.assertNotIn(
            "actions/workflows/release-acceptance.yml/dispatches", [p[0] for p in api.posts]
        )
        self.assertEqual(len(api.posts), 3)

    def test_run_that_never_appears_is_refused(self):
        api = FakeGitHub()
        api.runs.clear()
        with self.assertRaisesRegex(ValueError, "ci.yml: no push run"):
            produce(api)

    def test_main_moving_before_a_dispatch_is_refused(self):
        api = FakeGitHub()
        original = api.get

        def moving(route):
            if route.startswith("actions/workflows/quality.yml/"):
                api.main = OTHER
            return original(route)

        api.get = moving
        with self.assertRaisesRegex(ValueError, "main moved before dispatching quality.yml"):
            produce(api)

    def test_run_that_never_completes_is_refused(self):
        api = FakeGitHub()
        api.get = lambda route, original=api.get: (
            dict(original(route), status="in_progress")
            if route.startswith("actions/runs/")
            else original(route)
        )
        with self.assertRaisesRegex(ValueError, "did not complete in time"):
            produce(api)

    def test_main_writes_outputs_and_refuses_forks_and_other_refs(self):
        env = dict(
            GITHUB_REPOSITORY=policy.REPOSITORY, GITHUB_REF="refs/heads/main", GITHUB_SHA=HEAD
        )
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "out"
            api = FakeGitHub()
            api.tags.append("v" + VERSION)
            self.assertEqual(E.main(dict(env, GITHUB_OUTPUT=str(output)), api), dict(ready="false"))
            self.assertEqual(output.read_text(), "ready=false\n")
            clock = Clock()
            E.main(
                dict(env, GITHUB_OUTPUT=str(output)),
                FakeGitHub(),
                presence=published,
                present=never,
                sleep=clock.sleep,
                clock=clock,
            )
            self.assertEqual(
                output.read_text().splitlines()[1:],
                ["head=" + HEAD, "ready=true", "version=" + VERSION],
            )
        for bad in (
            dict(GITHUB_REPOSITORY="Marukome0743/paludarium"),
            dict(GITHUB_REF="refs/heads/other"),
            dict(GITHUB_SHA="x"),
        ):
            with self.assertRaises(ValueError):
                E.main(dict(env, **bad), FakeGitHub())


BODY = """Release Please calculated this version from Conventional Commits.
---


## [0.1.1](https://github.com/aletheia-works/paludarium/compare/v0.1.0...v0.1.1) (2026-10-20)


### Bug Fixes

* **harness:** run ignored encodings tests in the bounded child

---
This PR was generated with [Release Please](https://github.com/googleapis/release-please).
"""
FIRST = """Release Please calculated this version from Conventional Commits.
---


## 0.1.0 (2026-10-20)


### Features

* **wasm:** publish the npm package as @aletheia-works/paludarium-wasm

---
This PR was generated with [Release Please](https://github.com/googleapis/release-please).
"""
MERGE = "b" * 40


def release_pr(
    number=25,
    merged=True,
    login=E.RELEASE_BOT,
    repository=policy.REPOSITORY,
    labels=(E.PENDING,),
    merge=MERGE,
    body=BODY,
):
    return dict(
        number=number,
        merged_at="2026-10-20T11:47:24Z" if merged else None,
        user=dict(login=login),
        head=dict(ref=E.RELEASE_BRANCH, repo=dict(full_name=repository)),
        labels=[dict(name=n) for n in labels],
        merge_commit_sha=merge,
        body=body,
    )


class FakePulls:
    def __init__(self, pulls, status="ahead"):
        self.pulls, self.status, self.routes = pulls, status, []

    def get(self, route):
        self.routes.append(route)
        if route.startswith("pulls?"):
            return self.pulls
        return dict(status=self.status)


class ReleaseNotes(unittest.TestCase):
    def test_section_with_a_compare_link_stops_at_the_footer(self):
        self.assertEqual(
            E.release_notes(BODY, "0.1.1"),
            "### Bug Fixes\n\n* **harness:** run ignored encodings tests in the bounded child\n",
        )

    def test_first_release_section_without_a_link(self):
        self.assertEqual(
            E.release_notes(FIRST, "0.1.0"),
            "### Features\n\n* **wasm:** publish the npm package as @aletheia-works/paludarium-wasm\n",
        )

    def test_a_version_prefix_is_not_a_match(self):
        with self.assertRaisesRegex(ValueError, "0 sections for 0.1"):
            E.release_notes(BODY, "0.1")

    def test_missing_duplicate_or_empty_section_stops(self):
        with self.assertRaisesRegex(ValueError, "0 sections for 0.2.0"):
            E.release_notes(BODY, "0.2.0")
        with self.assertRaisesRegex(ValueError, "2 sections for 0.1.1"):
            E.release_notes(BODY + "\n## 0.1.1 (again)\n\n* x\n", "0.1.1")
        with self.assertRaisesRegex(ValueError, "section for 0.3.0 is empty"):
            E.release_notes("## [0.3.0](link) (date)\n\n\n---\nfooter\n", "0.3.0")

    def test_notes_from_the_merged_pending_release_pr(self):
        api = FakePulls(
            [
                release_pr(17, merged=False),
                release_pr(12, labels=("autorelease: tagged",), body=FIRST),
                release_pr(),
            ]
        )
        self.assertEqual(E.release_pr_notes(api, HEAD, "0.1.1"), E.release_notes(BODY, "0.1.1"))
        self.assertEqual(
            api.routes,
            [
                f"pulls?state=closed&base=main&head=aletheia-works:{E.RELEASE_BRANCH}&per_page=100",
                f"compare/{MERGE}...{HEAD}",
            ],
        )
        self.assertEqual(
            E.release_pr_notes(FakePulls([release_pr()], "identical"), HEAD, "0.1.1"),
            E.release_notes(BODY, "0.1.1"),
        )

    def test_only_the_bots_merged_pending_pr_from_this_repository_counts(self):
        for pr in (
            release_pr(merged=False),
            release_pr(login="someone"),
            release_pr(repository="fork/paludarium"),
            release_pr(labels=("autorelease: tagged",)),
        ):
            with self.assertRaisesRegex(ValueError, "0 merged release PRs are pending"):
                E.release_pr_notes(FakePulls([pr]), HEAD, "0.1.1")
        with self.assertRaisesRegex(ValueError, "2 merged release PRs are pending"):
            E.release_pr_notes(FakePulls([release_pr(), release_pr(26)]), HEAD, "0.1.1")

    def test_head_must_contain_the_release_merge_commit(self):
        for status in ("behind", "diverged"):
            with self.assertRaisesRegex(ValueError, "merge commit is not in"):
                E.release_pr_notes(FakePulls([release_pr()], status), HEAD, "0.1.1")

    def test_paginated_listing_or_missing_section_stops(self):
        with self.assertRaisesRegex(ValueError, "paginated"):
            E.release_pr_notes(FakePulls([release_pr(n) for n in range(100)]), HEAD, "0.1.1")
        with self.assertRaisesRegex(ValueError, "0 sections for 0.2.0"):
            E.release_pr_notes(FakePulls([release_pr()]), HEAD, "0.2.0")
        with self.assertRaisesRegex(ValueError, "0 sections for 0.1.1"):
            E.release_pr_notes(FakePulls([release_pr(body=None)]), HEAD, "0.1.1")

    def test_command_line_refuses_a_bad_head_or_missing_token_before_any_request(self):
        import os
        import subprocess

        env = {k: v for k, v in os.environ.items() if k not in ("GH_TOKEN", "GITHUB_TOKEN")}
        for head, message in (("x", "invalid head"), (HEAD, "GitHub read token unavailable")):
            out = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(ROOT / "scripts/release/evidence.py"),
                    "notes",
                    "0.1.1",
                    head,
                ],
                capture_output=True,
                text=True,
                env=env,
            )
            self.assertNotEqual(out.returncode, 0)
            self.assertIn(message, out.stderr)
            self.assertEqual(out.stdout, "")


class EvidenceWorkflow(unittest.TestCase):
    def test_publish_workflow_publishes_first_and_tags_last(self):
        text = (ROOT / ".github/workflows/publish.yml").read_text()
        self.assertFalse((ROOT / ".github/workflows/release-evidence.yml").exists())
        actions = re.findall(r"uses:\s+([^\s#]+)", text)
        self.assertTrue(
            actions
            and all(re.fullmatch(r"[^@]+@[0-9a-f]{40}", a) or a.startswith("./") for a in actions)
        )
        trigger = text.split("\non:\n", 1)[1].split("\npermissions:", 1)[0]
        self.assertIn("branches: [main]", trigger)
        self.assertNotIn("tags", trigger)
        parts = re.split(r"^  ([a-z]+):\n", text.split("\njobs:\n", 1)[1], flags=re.M)
        jobs = dict(zip(parts[1::2], parts[2::2], strict=True))
        self.assertEqual(list(jobs), ["evidence", "preflight", "packages", "publish", "tag"])
        self.assertIn("needs: evidence", jobs["preflight"])
        self.assertIn("needs: [evidence, preflight, packages]", jobs["publish"])
        self.assertIn("needs: [evidence, publish]", jobs["tag"])
        self.assertIn("environment: release", jobs["publish"])
        self.assertNotIn("id-token", jobs["tag"])
        self.assertIn("GH_TOKEN: ${{ github.token }}", jobs["tag"])
        self.assertEqual(text.count("persist-credentials: false"), 4)
        self.assertNotIn("RELEASE_AUTOMATION_ENABLED", text)
        self.assertNotIn("secrets.", text)
        self.assertIn('--target "$HEAD_SHA"', text)
        self.assertIn(
            'python -B scripts/release/evidence.py notes "$VERSION" "$HEAD_SHA" > target/release-notes.md',
            text,
        )
        self.assertFalse((ROOT / "CHANGELOG.md").exists())
        config = json.loads((ROOT / ".github/release-please-config.json").read_text())
        self.assertIs(config["packages"]["."]["skip-changelog"], True)
        self.assertNotIn("awk", text)
        self.assertNotIn("TRUSTED_PUBLISHERS_REGISTERED", text)
        self.assertEqual(check.validate(ROOT)["validated"], True)


if __name__ == "__main__":
    unittest.main()
