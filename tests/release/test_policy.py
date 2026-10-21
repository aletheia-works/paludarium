import shutil
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/release"))
import policy  # noqa: E402


def valid():
    inv = policy.inventory(ROOT)
    inv["version"] = "0.1.0"
    head = "a" * 40
    state = dict(
        repository=policy.REPOSITORY,
        tag="v0.1.0",
        commit=dict(sha=head, commit=dict(verification=dict(verified=True))),
        main_compare=dict(base_commit=dict(sha=head), status="ahead"),
        quality=[
            dict(
                purpose=k,
                repository=policy.REPOSITORY,
                head_sha=head,
                status="completed",
                conclusion="success",
                id=i + 1,
            )
            for i, k in enumerate(sorted(policy.REQUIRED))
        ],
        acceptance=[
            dict(id=k, head=head, passed=True, artifact_sha256="b" * 64)
            for k in sorted(policy.ACCEPTANCE)
        ],
        environment=dict(
            name="release",
            can_admins_bypass=False,
            protection_rules=[
                dict(
                    type="required_reviewers",
                    prevent_self_review=True,
                    reviewers=[dict(type="User", reviewer=dict(id=1))],
                )
            ],
        ),
    )
    return state, inv


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.s, self.i = valid()

    def reject(self):
        with self.assertRaises(ValueError):
            policy.release_gate(self.s, self.i)

    def test_valid_schema(self):
        self.assertTrue(policy.release_gate(self.s, self.i)["eligible"])

    def test_actual_inventory(self):
        self.assertEqual(len(self.i["packages"]), 11)
        self.assertEqual(len(self.i["private"]), 2)
        self.assertLess(
            self.i["order"].index("paludarium-types"), self.i["order"].index("paludarium-runtime")
        )

    def test_shell_tag(self):
        self.s["tag"] = "v0.1.0;evil"
        self.reject()

    def test_undecided_version(self):
        self.i["version"] = "0.0.0"
        self.reject()

    def test_version_mismatch(self):
        self.s["tag"] = "v0.2.0"
        self.reject()

    def test_wrong_repo(self):
        self.s["repository"] = "attacker/paludarium"
        self.reject()

    def test_wrong_head(self):
        self.s["quality"][0]["head_sha"] = "c" * 40
        self.reject()

    def test_unfinished(self):
        self.s["quality"][0]["status"] = "in_progress"
        self.reject()

    def test_failed(self):
        self.s["quality"][0]["conclusion"] = "failure"
        self.reject()

    def test_missing(self):
        self.s["quality"].pop()
        self.reject()

    def test_unsigned(self):
        self.s["commit"]["commit"]["verification"]["verified"] = False
        self.reject()

    def test_no_environment(self):
        self.s["environment"] = {}
        self.reject()

    def test_admin_bypass(self):
        self.s["environment"]["can_admins_bypass"] = True
        self.reject()

    def test_cycle(self):
        with self.assertRaises(ValueError):
            policy.dependency_order(
                {"a": dict(dependencies={"b": "1"}), "b": dict(dependencies={"a": "1"})}
            )

    def test_unknown_dependency(self):
        with self.assertRaises(ValueError):
            policy.dependency_order({"a": dict(dependencies={"missing": "1"})})

    def test_main_unreachable(self):
        self.s["main_compare"]["status"] = "diverged"
        self.reject()

    def test_acceptance_missing(self):
        self.s["acceptance"].pop()
        self.reject()

    # Step14b (Q3): self-review prevention is no longer required.
    def test_self_review_allowed(self):
        rule = self.s["environment"]["protection_rules"][0]
        for value in (False, None):
            with self.subTest(value):
                rule["prevent_self_review"] = value
                self.assertTrue(policy.release_gate(self.s, self.i)["eligible"])
        del rule["prevent_self_review"]
        self.assertTrue(policy.protected_environment(self.s["environment"]))

    def test_no_reviewers_required(self):
        for rules in (
            [dict(type="required_reviewers", reviewers=[])],
            [dict(type="wait_timer", wait_timer=5)],
            [],
        ):
            with self.subTest(rules):
                self.s["environment"]["protection_rules"] = rules
                self.assertTrue(policy.release_gate(self.s, self.i)["eligible"])

    def test_admin_bypass_unknown(self):
        del self.s["environment"]["can_admins_bypass"]
        self.reject()

    # Trusted Publishing only: no declaration, no authentication mode.
    def test_oidc_only_without_declaration(self):
        result = policy.release_gate(self.s, self.i)
        self.assertEqual(
            result, dict(eligible=True, head="a" * 40, version="0.1.0", order=self.i["order"])
        )
        self.assertNotIn("authentication", result)
        for key in (
            "trusted_publishers_registered",
            "first_publication",
            "registries_absent",
            "registry_resume_verified",
        ):
            self.assertNotIn(key, self.s)

    def inherited_dependency(self, field):
        with tempfile.TemporaryDirectory(dir=ROOT / "target/u15") as directory:
            root = Path(directory)
            workspace = (ROOT / "Cargo.toml").read_text()
            workspace = workspace.replace(
                "paludarium-types = { path =", "paludarium-types = { " + field + ", path =", 1
            )
            (root / "Cargo.toml").write_text(workspace)
            members = tomllib.loads(workspace)["workspace"]["members"]
            for member in members:
                p = root / member
                p.mkdir(parents=True)
                shutil.copyfile(ROOT / member / "Cargo.toml", p / "Cargo.toml")
            p = root / "packages/paludarium-wasm"
            p.mkdir(parents=True)
            shutil.copyfile(ROOT / "packages/paludarium-wasm/package.json", p / "package.json")
            with self.assertRaisesRegex(ValueError, "non-crates.io"):
                policy.inventory(root)

    def test_inherited_git_rejected(self):
        self.inherited_dependency('git = "https://example.invalid/repo"')

    def test_inherited_registry_rejected(self):
        self.inherited_dependency('registry = "untrusted"')

    def test_real_manifests_share_release_version(self):
        # The real manifests, not the valid() fixture, all carry the one decided release version.
        inv = policy.inventory(ROOT)
        workspace = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]
        internal = {k: v for k, v in workspace["dependencies"].items() if "path" in v}
        version = inv["version"]
        self.assertRegex(version, r"^\d+\.\d+\.\d+$")
        self.assertNotEqual(version, "0.0.0")
        self.assertEqual(workspace["package"]["version"], version)
        self.assertEqual(sorted(internal), sorted(policy.PUBLIC))
        self.assertEqual({v["version"] for v in internal.values()}, {version})
        self.assertEqual(len(inv["packages"]), 11)
        self.assertEqual({r["version"] for r in inv["packages"].values()}, {version})
        self.assertEqual(
            {v for r in inv["packages"].values() for v in r["dependencies"].values()}, {version}
        )
        self.assertEqual(inv["npm"]["version"], version)
        self.assertEqual(inv["npm"]["name"], "@aletheia-works/paludarium-wasm")

    def test_single_version_drift_rejected(self):
        version = policy.inventory(ROOT)["version"]
        major, minor, patch = map(int, version.split("."))
        other = f"{major:d}.{minor:d}.{patch + 1:d}"
        drifts = {
            "workspace dependency": (
                "Cargo.toml",
                f'paludarium-mmu = {{ path = "crates/paludarium-mmu", version = "{version}" }}',
                f'paludarium-mmu = {{ path = "crates/paludarium-mmu", version = "{other}" }}',
            ),
            "npm package": (
                "packages/paludarium-wasm/package.json",
                f'"version":"{version}"',
                f'"version":"{other}"',
            ),
            "crate package": (
                "crates/paludarium-vfs/Cargo.toml",
                "\nversion.workspace = true",
                f'\nversion = "{other}"',
            ),
        }
        for label, (path, old, new) in drifts.items():
            with (
                self.subTest(label),
                tempfile.TemporaryDirectory(dir=ROOT / "target/u15") as directory,
            ):
                root = Path(directory)
                members = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["members"]
                for name in ["Cargo.toml", "packages/paludarium-wasm/package.json"] + [
                    m + "/Cargo.toml" for m in members
                ]:
                    p = root / name
                    p.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(ROOT / name, p)
                text = (root / path).read_text()
                self.assertEqual(text.count(old), 1, label)
                (root / path).write_text(text.replace(old, new))
                with self.assertRaisesRegex(ValueError, "version"):
                    policy.inventory(root)


if __name__ == "__main__":
    unittest.main()
