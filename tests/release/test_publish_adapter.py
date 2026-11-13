"""Real archive fixtures with mocked network/upload adapters, never a publication."""

import base64
import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

import check
import package
import policy
from test_check import CANARY
from test_package import deno_listing, jsr_fixture, tar
from test_policy import ROOT

# The real manifests' release version; Release Please bumps it on every release.
VERSION = policy.inventory(ROOT)["version"]
# The package check's build directory, as the Wasm keeps it before its time_ns.
BUILT_IN = b"/home/runner/work/paludarium/paludarium/target/release-evidence/package-"
# The uploads that authenticate by their own OIDC exchange, not the crates.io token.
OIDC = ("publish-npm", "publish-jsr")


class PublishAdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / "target/release-evidence")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.head = "a" * 40
        sourcefiles = {}
        sourcefiles["Cargo.toml"] = (ROOT / "Cargo.toml").read_bytes()
        sourcefiles["rust-toolchain.toml"] = (ROOT / "rust-toolchain.toml").read_bytes()
        for member in __import__("tomllib").loads(sourcefiles["Cargo.toml"].decode())["workspace"][
            "members"
        ]:
            sourcefiles[member + "/Cargo.toml"] = (ROOT / member / "Cargo.toml").read_bytes()
        for name in ("package.json", "jsr.json"):
            sourcefiles["packages/paludarium-wasm/" + name] = (
                ROOT / "packages/paludarium-wasm" / name
            ).read_bytes()
        for n, b in sourcefiles.items():
            p = self.root / n
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(b)
        self.inv = policy.inventory(self.root)
        self.out = self.root / "target/release-evidence"
        self.art = self.out / "package-test"
        self.art.mkdir(parents=True)
        self.crates = []
        for name in self.inv["order"]:
            dep = "\n".join(
                "[dependencies." + d + ']\nversion="' + v + '"'
                for d, v in self.inv["packages"][name]["dependencies"].items()
            )
            m = (
                '[package]\nname="'
                + name
                + '"\nversion="'
                + VERSION
                + '"\nlicense="Apache-2.0"\n'
                + dep
            )
            p = self.art / "source/target/package" / (name + "-" + VERSION + ".crate")
            p.parent.mkdir(parents=True, exist_ok=True)
            tar(
                p,
                {"Cargo.toml": m.encode(), "LICENSE": b"Apache", "README.md": b"usage"},
                name + "-" + VERSION,
            )
            self.crates.append(p)
        files, config, _ = jsr_fixture()
        # The Wasm keeps the dependency paths under the package check's build directory.
        files["paludarium.wasm"] += BUILT_IN + b"1794555614340074887/cargo-home/registry/x.rs"
        self.files, self.config = files, config
        self.jsr_files = package.jsr_files(files, config, VERSION)
        self.npm = self.art / "wasm.tgz"
        tar(self.npm, files)
        # The npm tarball on the registry, once uploaded; another package check's
        # build has other bytes.
        self.published = self.npm.read_bytes()
        with zipfile.ZipFile(self.art / "source-snapshot.zip", "x") as z:
            for n, b in sourcefiles.items():
                z.writestr(n, b)
        sourcehash = package.sha(
            json.dumps({n: package.sha(b) for n, b in sourcefiles.items()}, sort_keys=True).encode()
        )
        expected = dict(
            version=VERSION,
            head=self.head,
            source_sha256=sourcehash,
            tar_sha256=package.sha(self.npm.read_bytes()),
            wasm_sha256=package.sha(files["paludarium.wasm"]),
            source_files={},
        )
        self.result = dict(
            passed=True,
            head=self.head,
            local_snapshot=False,
            source_sha256=sourcehash,
            crates=package.inspect_crates(self.crates, self.inv),
            npm=package.inspect_npm(self.npm, expected),
            jsr=dict(files=package.jsr_manifest(self.jsr_files)),
        )
        (self.out / "package-result.json").write_text(json.dumps(self.result))
        self.uploaded = set()
        self.env = dict(
            PALUDARIUM_TEST_NODE=sys.executable,
            PALUDARIUM_RELEASE_NPM=__file__,
            PALUDARIUM_RELEASE_DENO=sys.executable,
            RELEASE_OIDC_CRATES_IO_TOKEN=CANARY["RELEASE_OIDC_CRATES_IO_TOKEN"],
        )
        self.envs = []
        self.yanked = set()
        self.dry_dir = "target/package/tmp-crate"
        self.jsr_staged = []
        self.jsr_yanked = False
        self.deno_version = "deno " + package.JSR_DENO_VERSION + " (stable, release, x86_64)"
        self.deno_versions = []

    def request(self, request, timeout):
        # jsr.io answers 403 to urllib's own User-Agent, so every query must name ours.
        self.assertEqual(request.get_header("User-agent"), check.REGISTRY_USER_AGENT)
        url = request.full_url
        if url.startswith(check.JSR_PACKAGE_URL + "/"):
            # The CDN in front of jsr.io keeps a version's metadata for a year, so
            # every JSR query must reach jsr.io itself.
            self.assertRegex(url, r"\?uncached=[0-9]+$")
            url = url.split("?")[0]
        if "crates.io/" in url:
            name = url.split("/")[-2]
            if name not in self.uploaded:
                raise check.urllib.error.HTTPError(url, 404, "absent", {}, None)
            return io.BytesIO(
                json.dumps(
                    dict(
                        version=dict(
                            num=VERSION,
                            checksum=self.result["crates"][name]["sha256"],
                            yanked=name in self.yanked,
                        )
                    )
                ).encode()
            )
        if url == check.JSR_PACKAGE_URL + "/meta.json":
            versions = {VERSION: dict(yanked=True) if self.jsr_yanked else {}}
            return io.BytesIO(json.dumps(dict(versions=versions)).encode())
        if url.startswith(check.JSR_PACKAGE_URL + "/"):
            if "jsr" not in self.uploaded:
                raise check.urllib.error.HTTPError(url, 404, "absent", {}, None)
            manifest = package.jsr_manifest(self.jsr_files)
            return io.BytesIO(json.dumps(dict(manifest=manifest)).encode())
        if "npm" not in self.uploaded:
            raise check.urllib.error.HTTPError(url, 404, "absent", {}, None)
        if url == check.NPM_TARBALL_URL.format(VERSION):
            return io.BytesIO(self.published)
        digest = "sha512-" + base64.b64encode(hashlib.sha512(self.published).digest()).decode()
        return io.BytesIO(json.dumps(dict(version=VERSION, dist=dict(integrity=digest))).encode())

    def command(self, argv, cwd, output, *args, **kwargs):
        if argv[-1] == "--version":
            self.deno_versions.append(Path(output).name)
            Path(output).mkdir()
            (Path(output) / "stdout.bin").write_text(self.deno_version + "\n")
            return dict(exit=0, timeout=False, error=None, reaped=True)
        self.envs.append((Path(output).name, args[-1]))  # both adapters receive env last
        if "-p" in argv:
            name = argv[argv.index("-p") + 1]
            if "--dry-run" in argv:
                target = Path(cwd) / self.dry_dir / (name + "-" + VERSION + ".crate")
                target.parent.mkdir(parents=True, exist_ok=True)
                original = next(p for p in self.crates if p.name == target.name)
                shutil.copyfile(original, target)
            else:
                self.uploaded.add(name)
        elif Path(output).name == "dry-jsr":
            deno_listing(cwd, output)
        elif Path(output).name == "publish-jsr":
            self.jsr_staged.append(
                {f.name: f.read_bytes() for f in Path(cwd).iterdir() if f.is_file()}
            )
            self.uploaded.add("jsr")
        else:
            self.uploaded.add("npm")
        return dict(exit=0, timeout=False, error=None, reaped=True)

    def execute(self):
        approved = dict(eligible=True, head=self.head, version=VERSION, order=self.inv["order"])
        with (
            patch.dict(os.environ, self.env),
            patch.object(check, "authorize", return_value=approved),
            patch.object(check, "checked_command", side_effect=self.command),
            patch.object(check, "run_command", side_effect=self.command),
            patch.object(check.urllib.request, "urlopen", side_effect=self.request),
        ):
            return check.publish_artifacts(self.root, None)

    def test_mocked_upload_transport(self):
        self.assertEqual(len(self.execute()["published"]), 14)

    def publish_npm_built_as(self, wasm=None, **changed):
        """Put on the registry an npm version of these files built elsewhere."""
        files = dict(self.files, **changed)
        if wasm is not None:
            files["paludarium.wasm"] = wasm
        path = self.root / "published.tgz"
        tar(path, files)
        self.published = path.read_bytes()
        self.uploaded = set(self.inv["order"]) | {"npm"}
        return files

    # 0.15.0: a later head finished a publication that stopped at JSR, and its
    # package check built the Wasm in another directory than the published one.
    def test_npm_built_in_another_directory_gives_jsr_its_published_files(self):
        files = self.publish_npm_built_as(
            wasm=self.files["paludarium.wasm"].replace(
                b"1794555614340074887", b"1794553343902493250"
            )
        )
        self.jsr_files = package.jsr_files(files, self.config, VERSION)
        self.assertNotEqual(self.jsr_files, package.jsr_files(self.files, self.config, VERSION))
        self.assertEqual(len(self.execute()["published"]), 14)
        self.assertEqual(self.jsr_staged, [self.jsr_files])
        self.assertEqual([n for n, _ in self.envs], ["dry-jsr", "publish-jsr"])

    def test_npm_version_with_other_bytes_stops_before_any_upload(self):
        for changed in (
            dict(wasm=self.files["paludarium.wasm"] + b"\0"),
            dict(wasm=self.files["paludarium.wasm"].replace(b"cargo-home", b"cargo-HOME")),
            {"index.mjs": self.files["index.mjs"] + b"\n"},
        ):
            with self.subTest(changed=sorted(changed)):
                self.publish_npm_built_as(**changed)
                self.envs = []
                shutil.rmtree(self.out / "publish-source", ignore_errors=True)
                (self.out / "publication-progress.json").unlink(missing_ok=True)
                with self.assertRaisesRegex(ValueError, "existing version digest mismatch"):
                    self.execute()
                self.assertEqual(self.envs, [])
                self.assertNotIn("jsr", self.uploaded)

    def test_npm_version_without_integrity_stops_before_any_upload(self):
        self.uploaded = set(self.inv["order"]) | {"npm"}
        request = self.request

        def bare(req, timeout):
            if req.full_url == check.NPM_PACKAGE_URL + "/" + VERSION:
                return io.BytesIO(json.dumps(dict(version=VERSION, dist={})).encode())
            return request(req, timeout)

        self.request = bare
        with self.assertRaisesRegex(ValueError, "existing version digest mismatch"):
            self.execute()
        self.assertEqual(self.envs, [])
        self.assertNotIn("jsr", self.uploaded)

    def test_published_npm_tarball_must_have_the_registry_integrity(self):
        self.publish_npm_built_as(wasm=self.files["paludarium.wasm"].replace(b"1794", b"1795"))
        published = self.published
        request = self.request

        def swapped(req, timeout):
            if req.full_url == check.NPM_TARBALL_URL.format(VERSION):
                return io.BytesIO(self.npm.read_bytes())
            self.published = published
            return request(req, timeout)

        self.request = swapped
        with self.assertRaisesRegex(ValueError, "published npm tarball differs from its integrity"):
            self.execute()
        self.assertEqual(self.envs, [])

    def test_older_cargo_dry_run_location(self):
        self.dry_dir = "target/package"
        self.assertEqual(len(self.execute()["published"]), 14)

    def test_upload_that_shows_up_late_is_waited_for(self):
        request = self.request
        misses = {"npm": 3, "paludarium": 2}
        sleeps = []

        def late(req, timeout):
            url = req.full_url
            key = "npm" if "npmjs" in url else url.split("/")[-2]
            if key in self.uploaded and misses.get(key):
                misses[key] -= 1
                raise check.urllib.error.HTTPError(url, 404, "not yet", {}, None)
            return request(req, timeout)

        self.request = late
        with patch.object(check.time, "sleep", side_effect=sleeps.append):
            self.assertEqual(len(self.execute()["published"]), 14)
        self.assertEqual(sleeps, [check.UPLOAD_POLL_SECONDS] * 5)

    def test_upload_that_never_shows_up_stops(self):
        request = self.request
        now = [0]

        def never(req, timeout):
            url = req.full_url
            if "npmjs" in url and "npm" in self.uploaded:
                raise check.urllib.error.HTTPError(url, 404, "absent", {}, None)
            return request(req, timeout)

        self.request = never

        def sleep(seconds):
            now[0] += seconds

        with (
            patch.object(check.time, "sleep", side_effect=sleep),
            patch.object(check.time, "monotonic", side_effect=lambda: now[0]),
            self.assertRaises(check.urllib.error.HTTPError),
        ):
            self.execute()
        self.assertGreaterEqual(now[0], check.UPLOAD_VISIBLE_SECONDS)
        progress = json.loads((self.out / "publication-progress.json").read_text())
        self.assertIn(
            "@aletheia-works/paludarium-wasm", progress["uploaded_but_possibly_unverified"]
        )
        self.assertNotIn("@aletheia-works/paludarium-wasm", progress["completed"])

    def test_missing_dry_run_crate_stops_before_upload(self):
        self.dry_dir = "target/elsewhere"
        with self.assertRaisesRegex(ValueError, "dry-run crate absent or ambiguous"):
            self.execute()
        self.assertEqual(self.uploaded, set())

    def test_existing_versions_are_not_uploaded(self):
        self.uploaded = set(self.inv["order"]) | {"npm", "jsr"}
        self.assertEqual(len(self.execute()["published"]), 14)
        self.assertEqual(self.envs, [])

    # JSR gets exactly the verified npm files, without package.json, plus jsr.json.
    def test_jsr_upload_is_the_verified_files(self):
        result = self.execute()
        self.assertEqual(result["published"][-2:], [check.NPM_NAME, check.JSR_KEY])
        self.assertEqual(self.jsr_staged, [self.jsr_files])
        [env] = [e for n, e in self.envs if n == "publish-jsr"]
        self.assertLessEqual(set(env), set(check.JSR_ENVIRONMENT))
        self.assertEqual(env["DENO_DIR"], str(self.out / "deno-dir"))

    # Each deno publish, the dry run and the upload, first checks the Deno version.
    def test_jsr_needs_the_pinned_deno_before_each_publish(self):
        self.assertEqual(len(self.execute()["published"]), 14)
        self.assertEqual(self.deno_versions, ["dry-jsr-version", "publish-jsr-version"])

    # Deno 2.8.2 and later rewrite paludarium.wasm's import module names, as
    # JSR 0.15.0 showed (denoland/deno#37171).
    def test_other_deno_stops_before_any_jsr_command(self):
        self.deno_version = "deno 2.9.8 (long term support, release, x86_64)"
        with self.assertRaisesRegex(ValueError, "needs Deno " + package.JSR_DENO_VERSION):
            self.execute()
        self.assertEqual([n for n, _ in self.envs if "jsr" in n], [])
        self.assertNotIn("jsr", self.uploaded)

    def test_prepared_jsr_files_changed_stops_before_any_upload(self):
        self.result["jsr"]["files"]["/README.md"]["size"] += 1
        (self.out / "package-result.json").write_text(json.dumps(self.result))
        with self.assertRaisesRegex(ValueError, "prepared JSR files changed"):
            self.execute()
        self.assertEqual(self.uploaded, set())
        self.assertEqual(self.envs, [])

    def test_jsr_version_with_other_files_stops(self):
        request = self.request

        def other(req, timeout):
            url = req.full_url.split("?")[0]
            if url.endswith("_meta.json") and "jsr" in self.uploaded:
                return io.BytesIO(json.dumps(dict(manifest={})).encode())
            return request(req, timeout)

        self.request = other
        with self.assertRaisesRegex(ValueError, "JSR version files differ"):
            self.execute()
        progress = json.loads((self.out / "publication-progress.json").read_text())
        self.assertIn(check.JSR_KEY, progress["uploaded_but_possibly_unverified"])
        self.assertNotIn(check.JSR_KEY, progress["completed"])

    def test_yanked_jsr_version_is_not_published(self):
        self.uploaded = set(self.inv["order"]) | {"npm", "jsr"}
        self.jsr_yanked = True
        with self.assertRaisesRegex(ValueError, "existing version is yanked"):
            self.execute()

    def test_artifact_head_changed_before_upload(self):
        self.result["head"] = "b" * 40
        (self.out / "package-result.json").write_text(json.dumps(self.result))
        with self.assertRaises(ValueError):
            self.execute()
        self.assertEqual(self.uploaded, set())

    def test_npm_digest_changed_before_upload(self):
        self.npm.write_bytes(self.npm.read_bytes() + b"changed")
        with self.assertRaises(ValueError):
            self.execute()
        self.assertEqual(self.uploaded, set())

    # Trusted Publishing only: the OIDC token reaches the cargo uploads only and is never recorded.
    def test_oidc_token_reaches_uploads_only(self):
        result = self.execute()
        self.assertNotIn("authentication", result)
        token = CANARY["RELEASE_OIDC_CRATES_IO_TOKEN"]
        dry = [e for n, e in self.envs if n.startswith("dry-")]
        uploads = [e for n, e in self.envs if n.startswith("publish-") and n not in OIDC]
        own = [e for n, e in self.envs if n in OIDC]
        self.assertEqual((len(dry), len(uploads), len(own)), (13, 12, 2))
        self.assertTrue(all(token not in e.values() for e in dry + own))
        self.assertTrue(all(e["CARGO_REGISTRY_TOKEN"] == token for e in uploads))
        recorded = json.dumps(result) + (self.out / "publication-progress.json").read_text()
        self.assertNotIn(token, recorded)

    def test_missing_oidc_token_stops_before_any_command(self):
        del self.env["RELEASE_OIDC_CRATES_IO_TOKEN"]
        with (
            patch.dict(os.environ, {"RELEASE_OIDC_CRATES_IO_TOKEN": ""}),
            self.assertRaisesRegex(ValueError, "OIDC token absent"),
        ):
            self.execute()
        self.assertEqual(self.uploaded, set())
        self.assertEqual(self.envs, [])

    # Resuming a stopped publication uploads only what is missing.
    def test_resume_uploads_only_remaining(self):
        done = self.inv["order"][:3]
        self.uploaded = set(done)
        result = self.execute()
        self.assertEqual(result["published"], [*self.inv["order"], check.NPM_NAME, check.JSR_KEY])
        names = [n for n, _ in self.envs]
        self.assertFalse([n for n in names if any(n.endswith("-" + d) for d in done)])
        self.assertEqual(len([n for n in names if n.startswith("publish-") and n not in OIDC]), 9)
        self.assertIn("publish-npm", names)
        self.assertIn("publish-jsr", names)
        progress = json.loads((self.out / "publication-progress.json").read_text())
        self.assertEqual(
            progress["attempted"], [*self.inv["order"][3:], check.NPM_NAME, check.JSR_KEY]
        )
        self.assertFalse(progress["automatic_retry"])

    # `authorize` is replaced here, so what stops this run is the
    # publish loop's own registry_state check of a present version.
    def test_publish_loop_registry_state_refuses_different_present_digest(self):
        first = self.inv["order"][0]
        self.uploaded = {first}
        request = self.request

        def tampered(req, timeout):
            url = req.full_url
            body = request(req, timeout)
            if url.endswith("/" + first + "/" + VERSION):
                return io.BytesIO(
                    json.dumps(
                        dict(version=dict(num=VERSION, checksum="0" * 64, yanked=False))
                    ).encode()
                )
            return body

        self.request = tampered
        with self.assertRaisesRegex(ValueError, "existing version digest mismatch"):
            self.execute()
        self.assertEqual(self.uploaded, {first})
        self.assertEqual(self.envs, [])

    # The publish loop never takes a yanked present version as published.
    def test_publish_loop_refuses_yanked_present_version(self):
        first = self.inv["order"][0]
        self.uploaded = {first}
        self.yanked = {first}
        with self.assertRaisesRegex(ValueError, "existing version is yanked"):
            self.execute()
        self.assertEqual(self.uploaded, {first})
        self.assertEqual(self.envs, [])

    # The job's GitHub token and OIDC request variables never reach cargo.
    def test_cargo_uploads_never_see_github_or_oidc_request_variables(self):
        self.env.update(
            GH_TOKEN="canary-gh-0004",
            ACTIONS_ID_TOKEN_REQUEST_URL="https://oidc.example.invalid",
            ACTIONS_ID_TOKEN_REQUEST_TOKEN="canary-oidc-request-0006",
            GITHUB_ACTIONS="true",
        )
        self.execute()
        cargo = [e for n, e in self.envs if n not in OIDC]
        npm = next(e for n, e in self.envs if n == "publish-npm")
        jsr = next(e for n, e in self.envs if n == "publish-jsr")
        # The 12 cargo dry runs and uploads, and JSR's dry run with the same environment.
        self.assertEqual(len(cargo), 25)
        self.assertTrue(
            all(
                not {
                    "GH_TOKEN",
                    "ACTIONS_ID_TOKEN_REQUEST_URL",
                    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
                    "GITHUB_ACTIONS",
                }
                & set(e)
                for e in cargo
            )
        )
        self.assertEqual(
            (npm["ACTIONS_ID_TOKEN_REQUEST_URL"], npm["GITHUB_ACTIONS"]),
            ("https://oidc.example.invalid", "true"),
        )
        self.assertNotIn("GH_TOKEN", npm)
        self.assertEqual(
            (jsr["ACTIONS_ID_TOKEN_REQUEST_URL"], jsr["GITHUB_ACTIONS"]),
            ("https://oidc.example.invalid", "true"),
        )
        self.assertNotIn("GH_TOKEN", jsr)

    def test_oidc_mode_uses_oidc_token(self):
        self.execute()
        self.assertTrue(
            all(
                e["CARGO_REGISTRY_TOKEN"] == CANARY["RELEASE_OIDC_CRATES_IO_TOKEN"]
                for n, e in self.envs
                if n.startswith("publish-") and n not in OIDC
            )
        )
        self.assertTrue(
            all(
                "CARGO_REGISTRY_TOKEN" not in e
                for n, e in self.envs
                if n.startswith("dry-") or n in OIDC
            )
        )


if __name__ == "__main__":
    unittest.main()
