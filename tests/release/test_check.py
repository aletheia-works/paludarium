import copy
import io
import os
import re
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/release"))
import check  # noqa: E402
import policy  # noqa: E402

CANARY = {"U15_OIDC_CRATES_IO_TOKEN": "canary-oidc-0001"}
# (canary values are test strings, never real tokens)


class Registry:
    """In-memory crates.io/npm package presence; never reaches the network."""

    def __init__(self, present=(), status=None, unreachable=False):
        self.present, self.status, self.unreachable, self.requests = (
            set(present),
            status,
            unreachable,
            [],
        )

    def __call__(self, request, timeout):
        self.requests.append(request)
        url = request.full_url
        if self.unreachable:
            raise urllib.error.URLError("down")
        if self.status:
            raise urllib.error.HTTPError(url, self.status, "unavailable", {}, None)
        name = check.NPM_NAME if url == check.NPM_PACKAGE_URL else url[len(check.CRATES_API) :]
        if name not in self.present:
            raise urllib.error.HTTPError(url, 404, "absent", {}, None)
        return io.BytesIO(b"{}")


class CheckTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / "target/release-evidence")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def run_child(self, code, timeout=5):
        return check.run_command(
            [sys.executable, "-B", "-c", code], self.root, self.root / "receipt", timeout
        )

    def test_success(self):
        r = self.run_child('print("ok")')
        check.require_success(r)
        self.assertEqual((self.root / "receipt/stdout.bin").read_bytes(), b"ok\n")

    def test_failure(self):
        r = self.run_child("raise SystemExit(7)")
        with self.assertRaises(ValueError):
            check.require_success(r)
        self.assertEqual(r["exit"], 7)

    def test_timeout(self):
        r = self.run_child('import time;print("partial",flush=True);time.sleep(10)', 0.05)
        self.assertTrue(r["timeout"])
        self.assertTrue(r["reaped"])
        self.assertTrue(r["cleanup"])
        with self.assertRaises(ValueError):
            check.require_success(r)

    def test_missing_tool(self):
        r = check.run_command([str(self.root / "absent")], self.root, self.root / "receipt")
        self.assertIsNotNone(r["error"])

    def test_shim_refused(self):
        with self.assertRaises(ValueError):
            check.run_command(["/example/shims/python"], self.root, self.root / "receipt")

    def test_incomplete_receipt(self):
        with self.assertRaises(ValueError):
            check.require_success(dict(exit=0, timeout=False, error=None, reaped=False))

    def test_source_changed(self):
        (self.root / "source").write_bytes(b"before")
        with self.assertRaises(ValueError):
            check.checked_command(
                [sys.executable, "-c", 'open("source","w").write("changed")'],
                self.root,
                self.root / "receipt",
                [Path("source")],
            )

    def test_source_unchanged(self):
        (self.root / "source").write_bytes(b"before")
        self.assertEqual(
            check.checked_command(
                [sys.executable, "-c", 'print("ok")'],
                self.root,
                self.root / "receipt",
                [Path("source")],
            )["exit"],
            0,
        )

    def test_unpublished(self):
        self.assertEqual(check.registry_state(404, {}, "1", "x")["state"], "UNPUBLISHED")

    def test_published(self):
        self.assertFalse(
            check.registry_state(200, dict(version="1", digest="x"), "1", "x")["upload_allowed"]
        )

    def test_query_unknown(self):
        with self.assertRaises(ValueError):
            check.registry_state(503, {}, "1", "x")

    def test_digest_mismatch(self):
        with self.assertRaises(ValueError):
            check.registry_state(200, dict(version="1", digest="other"), "1", "x")

    def test_version_mismatch(self):
        with self.assertRaises(ValueError):
            check.registry_state(200, dict(version="2", digest="x"), "1", "x")

    def test_bad_timeout(self):
        with self.assertRaises(ValueError):
            self.run_child("pass", 0)

    def test_secret_environment_not_dumped(self):
        env = dict(os.environ, SECRET_CANARY="never-log-this", RUSTFLAGS="")
        receipt = check.run_command(
            [sys.executable, "-c", "pass"], self.root, self.root / "receipt", env=env
        )
        self.assertEqual(receipt["tool_environment"]["RUSTFLAGS"], "")
        self.assertNotIn("never-log-this", (self.root / "receipt/receipt.json").read_text())

    # Step14b (Q2): a decided version is no longer reported as outstanding.
    def test_validate_outstanding_follows_version(self):
        decided = check.validate(ROOT)
        self.assertEqual(decided["version"], policy.inventory(ROOT)["version"])
        self.assertNotEqual(decided["version"], "0.0.0")
        self.assertNotIn("release version", decided["outstanding"])
        self.assertIn("Trusted Publishers", decided["outstanding"])
        undecided = copy.deepcopy(policy.inventory(ROOT))
        undecided["version"] = "0.0.0"
        with patch.object(policy, "inventory", return_value=undecided):
            self.assertEqual(check.validate(ROOT)["outstanding"][0], "release version")

    # Trusted Publishing only: which package names already exist on their registry.
    def presence(self, registry):
        with patch.object(check.urllib.request, "urlopen", side_effect=registry):
            return check.registry_presence(policy.inventory(ROOT)["order"])

    def test_registry_presence_none(self):
        registry = Registry()
        result = self.presence(registry)
        order = policy.inventory(ROOT)["order"]
        self.assertEqual(result, dict(present=[], checked=sorted([*order, check.NPM_NAME])))
        self.assertEqual(len(registry.requests), 12)
        self.assertTrue(
            all(
                r.get_method() == "GET" and r.get_header("User-agent") == check.REGISTRY_USER_AGENT
                for r in registry.requests
            )
        )
        self.assertEqual(
            sorted(r.full_url for r in registry.requests),
            sorted([check.CRATES_API + n for n in order] + [check.NPM_PACKAGE_URL]),
        )

    def test_registry_name_present(self):
        for name in ("paludarium-types", "@aletheia-works/paludarium-wasm"):
            with self.subTest(name):
                result = self.presence(Registry(present=[name]))
                self.assertEqual(result["present"], [name])
                self.assertEqual(len(result["checked"]), 12)
                self.assertIn(check.NPM_NAME, result["checked"])

    def test_registry_presence_all(self):
        order = policy.inventory(ROOT)["order"]
        result = self.presence(Registry(present=[*order, check.NPM_NAME]))
        self.assertEqual(result["present"], result["checked"])
        self.assertEqual(len(result["present"]), 12)

    def test_registry_presence_unknown(self):
        with self.assertRaisesRegex(ValueError, "503"):
            self.presence(Registry(status=503))
        with self.assertRaisesRegex(ValueError, "unreachable"):
            self.presence(Registry(unreachable=True))

    def test_oidc_environments(self):
        env = dict(
            PATH="/bin",
            U15_OIDC_CRATES_IO_TOKEN=CANARY["U15_OIDC_CRATES_IO_TOKEN"],
            CARGO_REGISTRY_TOKEN="stale",
        )
        dry, cargo, npm = check.publication_environments(env)
        self.assertEqual(cargo["CARGO_REGISTRY_TOKEN"], CANARY["U15_OIDC_CRATES_IO_TOKEN"])
        self.assertNotIn("U15_OIDC_CRATES_IO_TOKEN", cargo)
        for e in (dry, npm):
            self.assertFalse(set(e) & {"CARGO_REGISTRY_TOKEN", "U15_OIDC_CRATES_IO_TOKEN"})
            self.assertNotIn(CANARY["U15_OIDC_CRATES_IO_TOKEN"], e.values())
        with self.assertRaisesRegex(ValueError, "OIDC token absent"):
            check.publication_environments(dict(PATH="/bin"))
        with self.assertRaisesRegex(ValueError, "OIDC token absent"):
            check.publication_environments(dict(PATH="/bin", U15_OIDC_CRATES_IO_TOKEN=""))

    def test_upload_tokens_not_in_receipt(self):
        env = dict(
            os.environ,
            CARGO_REGISTRY_TOKEN=CANARY["U15_OIDC_CRATES_IO_TOKEN"],
            NODE_AUTH_TOKEN="canary-npm-0003",
        )
        check.run_command([sys.executable, "-c", "pass"], self.root, self.root / "receipt", env=env)
        text = (self.root / "receipt/receipt.json").read_text()
        self.assertFalse(
            [v for v in (CANARY["U15_OIDC_CRATES_IO_TOKEN"], "canary-npm-0003") if v in text]
        )

    def test_release_workflow_secret_scope(self):
        text = (ROOT / ".github/workflows/publish.yml").read_text()
        publish = text.split("\n  publish:\n", 1)[1]
        # Trusted Publishing only: no stored registry token, owner variable or authentication mode output.
        self.assertEqual(re.findall(r"secrets\.(\w+)", text), [])
        self.assertNotIn("U15_FIRST_", text)
        self.assertIn("    environment: release\n", publish)
        for name in (
            "U15_CRATES_IO_OWNERS",
            "U15_NPM_MAINTAINERS",
            "steps.authorize.outputs",
            "NODE_AUTH_TOKEN:",
        ):
            self.assertNotIn(name, text)
        step = publish.split("      - name: Temporary crates.io OIDC token", 1)[1].split(
            "\n      - ", 1
        )[0]
        self.assertIn("        id: crates\n", step)
        self.assertIn("uses: rust-lang/crates-io-auth-action@", step)
        self.assertNotRegex(step, r"\n\s+if:")
        self.assertIn("U15_OIDC_CRATES_IO_TOKEN: ${{ steps.crates.outputs.token }}", publish)
        for name in ("publish.yml", "release-acceptance.yml", "release-check.yml"):
            self.assertNotRegex(
                (ROOT / ".github/workflows" / name).read_text(), r"(?i)echo[^\n]*(token|secret)"
            )

    # Step17 (R-17): allow-listed child environments.
    def job_environment(self):
        return dict(
            PATH="/bin",
            HOME="/home/runner",
            CI="true",
            GITHUB_ACTIONS="true",
            GH_TOKEN="canary-gh-0004",
            GITHUB_TOKEN="canary-gh-0005",
            ACTIONS_ID_TOKEN_REQUEST_URL="https://oidc.example.invalid",
            ACTIONS_ID_TOKEN_REQUEST_TOKEN="canary-oidc-request-0006",
            GITHUB_REPOSITORY=policy.REPOSITORY,
            GITHUB_SHA="a" * 40,
            GITHUB_WORKFLOW_REF=policy.REPOSITORY
            + "/.github/workflows/publish.yml@refs/tags/v0.1.0",
            RUNNER_ENVIRONMENT="github-hosted",
            NPM_CONFIG_USERCONFIG="/tmp/.npmrc",
            RUSTC="/toolchain/rustc",
            UNRELATED_SECRET="canary-other-0007",
            PALUDARIUM_RELEASE_NPM="/npm-cli.js",
        )

    def test_cargo_children_get_no_github_or_oidc_request_variables(self):
        dry, cargo, _ = check.publication_environments(
            dict(
                self.job_environment(), U15_OIDC_CRATES_IO_TOKEN=CANARY["U15_OIDC_CRATES_IO_TOKEN"]
            )
        )
        for env in (dry, cargo):
            self.assertFalse([k for k in env if k.startswith(("GH_", "GITHUB_", "ACTIONS_"))])
            self.assertNotIn("UNRELATED_SECRET", env)
            self.assertLessEqual(set(env), set(check.CARGO_ENVIRONMENT) | {"CARGO_REGISTRY_TOKEN"})
        self.assertEqual((dry["PATH"], dry["RUSTC"]), ("/bin", "/toolchain/rustc"))
        self.assertNotIn("CARGO_REGISTRY_TOKEN", dry)

    def test_npm_child_gets_only_provenance_variables(self):
        npm = check.publication_environments(
            dict(
                self.job_environment(),
                U15_OIDC_CRATES_IO_TOKEN=CANARY["U15_OIDC_CRATES_IO_TOKEN"],
                NODE_AUTH_TOKEN="XXXXX-XXXXX-XXXXX-XXXXX",
            )
        )[2]
        self.assertLessEqual(set(npm), set(check.NPM_ENVIRONMENT))
        for name in (
            "ACTIONS_ID_TOKEN_REQUEST_URL",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
            "GITHUB_WORKFLOW_REF",
            "GITHUB_SHA",
            "RUNNER_ENVIRONMENT",
            "NPM_CONFIG_USERCONFIG",
            "CI",
        ):
            self.assertIn(name, npm)
        for name in (
            "GH_TOKEN",
            "GITHUB_TOKEN",
            "UNRELATED_SECRET",
            "RUSTC",
            "PALUDARIUM_RELEASE_NPM",
            "CARGO_REGISTRY_TOKEN",
            "U15_OIDC_CRATES_IO_TOKEN",
        ):
            self.assertNotIn(name, npm)
        self.assertEqual(npm["NODE_AUTH_TOKEN"], "XXXXX-XXXXX-XXXXX-XXXXX")


if __name__ == "__main__":
    unittest.main()
