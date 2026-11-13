import io
import json
import sys
import tarfile
import tempfile
import unittest
import unittest.mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/release"))
import package  # noqa: E402
import policy  # noqa: E402


def tar(path, files, prefix="package", extra=None):
    with tarfile.open(path, "w:gz") as a:
        for name, raw in files.items():
            info = tarfile.TarInfo(prefix + "/" + name)
            info.size = len(raw)
            a.addfile(info, io.BytesIO(raw))
        if extra:
            info, raw = extra
            a.addfile(info, io.BytesIO(raw))


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / "target/release-evidence")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / "npm.tgz"
        self.files = {n: b"export {};" for n in package.REQUIRED_JS}
        self.files.update(
            {
                "package.json": json.dumps(
                    dict(name="@aletheia-works/paludarium-wasm", version="0.0.0")
                ).encode(),
                "index.d.ts": b"export {};",
                "relay.d.ts": b"export {};",
                "paludarium.wasm": b"\0asm\x01\0\0\0",
                "LICENSE": b"Apache-2.0",
                "THIRD-PARTY-NOTICES.txt": b"notices",
                "README.md": b"usage",
            }
        )

    def inspect(self, extra=None, expected_change=None):
        tar(self.path, self.files, extra=extra)
        expected = dict(
            tar_sha256=package.sha(self.path.read_bytes()),
            wasm_sha256=package.sha(b"\0asm\x01\0\0\0"),
            version="0.0.0",
            head="a" * 40,
            source_sha256="b" * 64,
            source_files={},
        )
        if expected_change:
            expected.update(expected_change)
        return package.inspect_npm(self.path, expected)

    def test_valid_npm(self):
        self.assertEqual(len(self.inspect()["files"]), 15)

    def test_jit_support_missing(self):
        del self.files["jit-support.mjs"]
        with self.assertRaises(ValueError):
            self.inspect()

    def test_wasm_missing(self):
        del self.files["paludarium.wasm"]
        with self.assertRaises(ValueError):
            self.inspect()

    def test_wasm_changed(self):
        self.files["paludarium.wasm"] += b"changed"
        with self.assertRaises(ValueError):
            self.inspect()

    def test_second_wasm(self):
        self.files["diagnostic.wasm"] = b"\0asm\x01\0\0\0"
        with self.assertRaises(ValueError):
            self.inspect()

    def test_missing_import(self):
        self.files["index.mjs"] = b'import "./absent.mjs";'
        with self.assertRaises(ValueError):
            self.inspect()

    def test_duplicate(self):
        item = tarfile.TarInfo("package/index.mjs")
        item.size = 1
        with self.assertRaises(ValueError):
            self.inspect((item, b"x"))

    def test_escape(self):
        item = tarfile.TarInfo("package/../escape")
        item.size = 1
        with self.assertRaises(ValueError):
            self.inspect((item, b"x"))

    def test_link(self):
        item = tarfile.TarInfo("package/link")
        item.type = tarfile.SYMTYPE
        item.linkname = "/outside"
        with self.assertRaises(ValueError):
            self.inspect((item, b""))

    def test_source_changed(self):
        with self.assertRaises(ValueError):
            self.inspect(expected_change=dict(source_files={"index.mjs": "0" * 64}))

    def test_tar_changed(self):
        with self.assertRaises(ValueError):
            self.inspect(expected_change=dict(tar_sha256="0" * 64))

    def test_wrong_version(self):
        with self.assertRaises(ValueError):
            self.inspect(expected_change=dict(version="1.0.0"))

    def crates(self, change=None):
        # Fixtures follow the real manifest version, so a version change cannot
        # make the rejection cases pass for an unrelated file-name reason.
        inventory = policy.inventory(ROOT)
        paths = []
        version = inventory["version"]
        for name in inventory["order"]:
            row = inventory["packages"][name]
            deps = "\n".join(
                "[dependencies." + d + ']\nversion = "' + v + '"'
                for d, v in row["dependencies"].items()
            )
            metadata = (
                '[package]\nname="'
                + name
                + '"\nversion="'
                + version
                + '"\nlicense="Apache-2.0"\n'
                + deps
            )
            files = {"Cargo.toml": metadata.encode(), "LICENSE": b"Apache", "README.md": b"usage"}
            if change:
                change(name, files)
            p = self.root / (name + "-" + version + ".crate")
            tar(p, files, name + "-" + version)
            paths.append(p)
        return paths, inventory

    def test_twelve_crates(self):
        paths, inv = self.crates()
        self.assertEqual(len(package.inspect_crates(paths, inv)), 12)

    def test_dependency_version(self):
        def change(name, files):
            if name == "paludarium-decoder":
                text = files["Cargo.toml"].decode()
                line = 'version = "' + policy.inventory(ROOT)["version"] + '"'
                self.assertIn(line, text)
                files["Cargo.toml"] = text.replace(line, 'version = "9.0.0"').encode()

        paths, inv = self.crates(change)
        with self.assertRaisesRegex(ValueError, "dependency missing/version mismatch"):
            package.inspect_crates(paths, inv)

    def test_private_crate(self):
        paths, inv = self.crates()
        paths[-1] = self.root / ("paludarium-harness-" + inv["version"] + ".crate")
        with self.assertRaises(ValueError):
            package.inspect_crates(paths, inv)

    def test_missing_crate(self):
        paths, inv = self.crates()
        with self.assertRaises(ValueError):
            package.inspect_crates(paths[:-1], inv)


def jsr_fixture():
    """The real package.json and jsr.json with small stand-ins for the other npm files."""
    manifest = (ROOT / "packages/paludarium-wasm/package.json").read_bytes()
    config = (ROOT / "packages/paludarium-wasm/jsr.json").read_bytes()
    files = {n: b"export {};" for n in package.REQUIRED_JS}
    files.update(
        {
            "index.mjs": b'// @ts-self-types="./index.d.ts"\nexport {};',
            "relay.mjs": b'// @ts-self-types="./relay.d.ts"\nexport {};',
            "package.json": manifest,
            "index.d.ts": b"export {};",
            "relay.d.ts": b"export {};",
            "paludarium.wasm": b"\0asm\x01\0\0\0",
            "LICENSE": b"Apache-2.0",
            "THIRD-PARTY-NOTICES.txt": b"notices",
            "README.md": b"usage",
        }
    )
    return files, config, json.loads(manifest)["version"]


def deno_listing(cwd, output, skip=()):
    """What `deno publish --dry-run` prints for the files staged in cwd."""
    rows = "".join(
        f"   \x1b[0m{Path(cwd).resolve().as_uri()}/{f.name} ({f.stat().st_size}B)\n"
        for f in sorted(Path(cwd).iterdir())
        if f.name not in skip
    )
    Path(output).mkdir()
    (Path(output) / "stdout.bin").write_text("Simulating publish of x with files:\n" + rows)
    (Path(output) / "stderr.bin").write_text("Success Dry run complete\n")


class JsrTests(unittest.TestCase):
    def setUp(self):
        self.files, self.config, self.version = jsr_fixture()

    def edited(self, **change):
        settings = json.loads(self.config)
        settings.update(change)
        return json.dumps(settings).encode()

    def test_the_npm_files_without_package_json_plus_jsr_json(self):
        files = package.jsr_files(self.files, self.config, self.version)
        self.assertEqual(set(files), (set(self.files) - {"package.json"}) | {"jsr.json"})
        self.assertEqual(files["jsr.json"], self.config)
        self.assertEqual(
            package.jsr_manifest(files)["/jsr.json"],
            dict(size=len(self.config), checksum="sha256-" + package.sha(self.config)),
        )

    def test_the_real_jsr_json_matches_the_real_package_json(self):
        settings = json.loads(self.config)
        manifest = json.loads(self.files["package.json"])
        self.assertEqual(settings["version"], manifest["version"])
        self.assertEqual(
            sorted(settings["publish"]["include"]),
            sorted([*manifest["files"], "jsr.json"]),
        )

    def test_identity_version_and_license(self):
        for change in (
            dict(name="@aletheia-works/other"),
            dict(version="0.0.0"),
            dict(license="MIT"),
        ):
            with self.subTest(change), self.assertRaisesRegex(ValueError, "identity"):
                package.jsr_files(self.files, self.edited(**change), self.version)

    def test_exports_follow_package_json(self):
        with self.assertRaisesRegex(ValueError, "exports"):
            package.jsr_files(self.files, self.edited(exports={".": "./index.mjs"}), self.version)

    def test_include_must_be_exactly_the_files(self):
        settings = json.loads(self.config)
        for publish in (
            dict(include=settings["publish"]["include"][1:]),
            dict(include=[*settings["publish"]["include"], "package.json"]),
            dict(include=settings["publish"]["include"], exclude=["README.md"]),
        ):
            with self.subTest(publish), self.assertRaisesRegex(ValueError, "publish.include"):
                package.jsr_files(self.files, self.edited(publish=publish), self.version)

    def test_size_limit(self):
        self.files["paludarium.wasm"] = b"\0" * package.JSR_MAX_BYTES
        with self.assertRaisesRegex(ValueError, "20 MiB"):
            package.jsr_files(self.files, self.config, self.version)

    def test_entry_points_name_their_types(self):
        for name in ("index.mjs", "relay.mjs"):
            with self.subTest(name):
                files = dict(self.files, **{name: b"export {};"})
                with self.assertRaisesRegex(ValueError, "types for JSR"):
                    package.jsr_files(files, self.config, self.version)

    def test_dry_run_of_exactly_those_files(self):
        import check

        temp = tempfile.TemporaryDirectory(dir=ROOT / "target/release-evidence")
        self.addCleanup(temp.cleanup)
        out = Path(temp.name)
        tarball = out / "npm.tgz"
        tar(tarball, self.files)
        seen = []
        versions = []
        self.deno = "deno " + package.JSR_DENO_VERSION

        def command(argv, cwd, output, timeout, env):
            if argv[-1] == "--version":
                versions.append((argv, Path(output).name, env))
                Path(output).mkdir()
                (Path(output) / "stdout.bin").write_text(self.deno + " (stable, release)\n")
                return dict(exit=0, timeout=False, error=None, reaped=True)
            seen.append((argv, sorted(p.name for p in Path(cwd).iterdir()), Path(output).name, env))
            self.assertFalse(Path(cwd).resolve().is_relative_to(ROOT))
            deno_listing(cwd, output, self.unlisted)
            return dict(exit=0, timeout=False, error=None, reaped=True)

        self.unlisted = ()

        with unittest.mock.patch.object(check, "run_command", side_effect=command):
            result = package.jsr_check(
                out, tarball, self.config, self.version, Path("/deno"), {"PATH": "/bin"}
            )
        files = package.jsr_files(self.files, self.config, self.version)
        self.assertEqual(result["files"], package.jsr_manifest(files))
        self.assertEqual(result["bytes"], sum(len(b) for b in files.values()))
        [(argv, listed, output, env)] = seen
        self.assertEqual(argv, [str(Path("/deno")), "publish", "--dry-run", "--allow-dirty"])
        self.assertEqual(listed, sorted(files))
        self.assertEqual(output, "jsr-dry-run")
        self.assertEqual(env["DENO_DIR"], str(out / "deno-dir"))
        self.assertEqual(env["PATH"], "/bin")
        # The Deno version is checked first, with no other environment than PATH.
        self.assertEqual(
            versions,
            [
                (
                    [str(Path("/deno")), "--version"],
                    "jsr-dry-run-version",
                    {"PATH": "/bin", "DENO_NO_UPDATE_CHECK": "1"},
                )
            ],
        )
        # Deno 2.8.2 and later rewrite paludarium.wasm's import module names
        # (denoland/deno#37171): no dry run with them.
        self.deno = "deno 2.9.8"
        for name in ("jsr-dry-run", "jsr-dry-run-version"):
            (out / name).rename(out / ("old-" + name))
        with (
            unittest.mock.patch.object(check, "run_command", side_effect=command),
            self.assertRaisesRegex(ValueError, "needs Deno " + package.JSR_DENO_VERSION),
        ):
            package.jsr_check(
                out, tarball, self.config, self.version, Path("/deno"), {"PATH": "/bin"}
            )
        self.assertEqual(len(seen), 1)
        self.deno = "deno " + package.JSR_DENO_VERSION
        (out / "jsr-dry-run-version").rename(out / "older-jsr-dry-run-version")
        self.unlisted = ("paludarium.wasm",)
        with (
            unittest.mock.patch.object(check, "run_command", side_effect=command),
            self.assertRaisesRegex(ValueError, "does not list exactly the files"),
        ):
            package.jsr_check(
                out, tarball, self.config, self.version, Path("/deno"), {"PATH": "/bin"}
            )


if __name__ == "__main__":
    unittest.main()
