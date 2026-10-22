"""Fake external tools only; exercise the real receipt, license and ELF gates."""

import importlib.util
import json
import pathlib
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

HERE = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
import evidence  # noqa: E402

spec = importlib.util.spec_from_file_location("programs_build_tests", HERE / "build.py")
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)

LICENSE_FIXTURES = {
    "webpki-root-certs": (
        "CDLA-Permissive-2.0",
        "LICENSE",
        "Community Data License Agreement full fixture 2.1.",
    ),
    "option-ext": ("MPL-2.0", "LICENSE.txt", "Mozilla Public License Version 2.0 full fixture"),
    "notify": ("CC0-1.0", "LICENSE-CC0", "CC0 1.0 Universal fixture Statement of Purpose"),
    "tiny-keccak": ("CC0-1.0", "LICENSE", "CC0 1.0 Universal fixture Statement of Purpose"),
}


def elf():
    data = bytearray(512)
    data[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HH", data, 16, 2, 62)
    struct.pack_into("<Q", data, 32, 64)
    struct.pack_into("<HH", data, 54, 56, 1)
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 0, 0, 0, 512, 512, 4096)
    return data


class BuildIntegration(unittest.TestCase):
    def setUp(self):
        self.directory = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.upstream = self.directory / "source/aube"
        self.upstream.mkdir(parents=True)
        (self.upstream / "Cargo.lock").write_text("version = 4\n")
        (self.upstream / "Cargo.toml").write_text('[package]\nname="fixture"\nversion="1.0.0"\n')
        self.ripgrep = self.directory / "source/ripgrep"
        self.ripgrep.mkdir(parents=True)
        (self.ripgrep / "Cargo.lock").write_text("version = 4 # ripgrep\n")
        (self.ripgrep / "Cargo.toml").write_text('[package]\nname="ripgrep"\nversion="1.0.0"\n')
        self.lock = evidence.json_source_lock()
        self.lock["aube"] = dict(
            self.lock["aube"], lock_sha256=evidence.digest(self.upstream / "Cargo.lock")
        )
        self.lock["ripgrep"] = dict(
            self.lock["ripgrep"], lock_sha256=evidence.digest(self.ripgrep / "Cargo.lock")
        )
        self.coreutils = self.directory / "source/coreutils"
        self.coreutils.mkdir(parents=True)
        (self.coreutils / "Cargo.lock").write_text("version = 4 # coreutils\n")
        (self.coreutils / "Cargo.toml").write_text('[package]\nname="coreutils"\nversion="1.0.0"\n')
        self.lock["coreutils"] = dict(
            self.lock["coreutils"], lock_sha256=evidence.digest(self.coreutils / "Cargo.lock")
        )
        self.metadata = {"packages": []}
        exceptions = [
            *self.lock["guest_license_exceptions"],
            *self.lock["coreutils"]["license_exceptions"],
        ]
        for exception in exceptions:
            name, version = exception["crate"].split("@")
            license, file_name, text = LICENSE_FIXTURES[name]
            package = self.directory / "registry" / f"{name}-{version}"
            package.mkdir(parents=True)
            (package / file_name).write_text(text)
            self.metadata["packages"].append(
                {
                    "name": name,
                    "version": version,
                    "license": license,
                    "source": evidence.REGISTRY,
                    "manifest_path": str(package / "Cargo.toml"),
                }
            )

    def run_build(self, failure=None, mutate=False, hook=None):
        commands = []

        def command(args, cwd, log, env=None):
            commands.append(args)
            if hook:
                hook(args)
            if failure and failure in str(log):
                raise subprocess.CalledProcessError(1, args)
            if "build" in args:
                outputs = {"aube": "aube", "ripgrep": "rg", "coreutils": "coreutils"}
                name = next((n for n in outputs if n in args), "probe")
                output = outputs.get(name, "paludarium-probe")
                binary = (
                    self.directory / "targets" / name / self.lock["target"] / "release" / output
                )
                binary.parent.mkdir(parents=True)
                binary.write_bytes(elf())
                if mutate and name == "aube":
                    (self.upstream / "Cargo.toml").write_text("changed")

        with (
            patch.object(builder, "command", side_effect=command),
            patch.object(
                builder.json,
                "loads",
                side_effect=lambda data: self.metadata if "packages" in data else self.lock,
            ),
            patch.object(
                builder.subprocess,
                "check_output",
                side_effect=lambda args, **kw: (
                    json.dumps(self.metadata) if "metadata" in args else "fixture tool"
                ),
            ),
            patch.object(builder.subprocess, "run"),
        ):
            builder.build(self.directory)
        return json.loads((self.directory / "build-receipt.json").read_text()), commands

    def receipt(self):
        return json.loads((self.directory / "build-receipt.json").read_text())

    def test_successful_build_receipt_validates(self):
        receipt, commands = self.run_build()
        self.assertEqual(receipt["exit"], 0)
        evidence.validate(self.directory, receipt)
        self.assertEqual(
            receipt["binaries"]["aube"]["lock_sha256"], self.lock["aube"]["lock_sha256"]
        )
        self.assertEqual(
            sorted(receipt["license_policy"]["licenses"]),
            ["option-ext@0.2.0", "webpki-root-certs@1.0.10"],
        )
        self.assertEqual(
            (self.directory / "licenses/option-ext-0.2.0-MPL-2.0.txt").read_text(),
            LICENSE_FIXTURES["option-ext"][2],
        )
        aube_commands = [args for args in commands if str(self.upstream / "Cargo.toml") in args]
        self.assertEqual(len(aube_commands), 2)
        self.assertTrue(all("--locked" in args for args in aube_commands))
        ripgrep_commands = [args for args in commands if str(self.ripgrep / "Cargo.toml") in args]
        self.assertEqual(len(ripgrep_commands), 2)
        self.assertIn(str(HERE.parents[2] / "deny.toml"), ripgrep_commands[0])
        self.assertEqual(receipt["audits"], {"probe": 0, "aube": 0, "ripgrep": 0, "coreutils": 0})
        self.assertEqual(receipt["ripgrep_source_before"], evidence.snapshot(self.ripgrep))
        coreutils_commands = [
            args for args in commands if str(self.coreutils / "Cargo.toml") in args
        ]
        self.assertEqual(len(coreutils_commands), 2)
        for args in coreutils_commands:
            self.assertIn("--no-default-features", args)
            self.assertEqual(args[args.index("--features") + 1], "feat_os_unix_musl")
        self.assertIn(str(self.directory / "coreutils-deny.toml"), coreutils_commands[0])
        self.assertEqual(
            sorted(receipt["coreutils_license_policy"]["licenses"]),
            ["notify@8.2.0", "tiny-keccak@2.0.2"],
        )
        self.assertEqual(
            (self.directory / "coreutils-deny.toml").read_bytes(),
            (HERE.parents[2] / "deny.toml").read_bytes()
            + evidence.exception_suffix(evidence.COREUTILS_LICENSE_EXCEPTIONS),
        )
        # Every audit runs before any guest is compiled.
        kinds = ["deny" if "deny" in args else "build" for args in commands[1:]]
        self.assertEqual(kinds, ["deny"] * 4 + ["build"] * 4)

    def test_no_advisory_exception_is_added(self):
        self.run_build()
        config = (self.directory / "aube-deny.toml").read_bytes()
        root = (HERE.parents[2] / "deny.toml").read_bytes()
        self.assertEqual(config, root + evidence.LICENSE_SUFFIX)

    def test_audit_failure_propagates_before_any_build(self):
        with self.assertRaises(subprocess.CalledProcessError):
            self.run_build(failure="aube-dependencies")
        receipt = self.receipt()
        self.assertEqual(receipt["exit"], 1)
        self.assertNotIn("aube", receipt["audits"])
        self.assertEqual(receipt["binaries"], {})

    def test_source_mutation_invalidates_success(self):
        with self.assertRaises(ValueError):
            self.run_build(mutate=True)
        receipt = self.receipt()
        self.assertEqual(receipt["exit"], 1)
        self.assertFalse(receipt["source_unchanged"])

    def test_license_identity_mismatch_rejected(self):
        for field, value in [
            ("license", "MIT"),
            ("source", "git+https://example.invalid"),
            ("version", "0.2.1"),
        ]:
            with self.subTest(field=field):
                self.setUp()
                self.metadata["packages"][1][field] = value
                with self.assertRaises(ValueError):
                    self.run_build()
                self.assertEqual(self.receipt()["exit"], 1)

    def test_incomplete_license_text_rejected(self):
        license_file = pathlib.Path(self.metadata["packages"][1]["manifest_path"]).with_name(
            "LICENSE.txt"
        )
        license_file.write_text("truncated")
        with self.assertRaisesRegex(ValueError, "full license text missing"):
            self.run_build()

    def test_lock_digest_mismatch_rejected(self):
        for name in ("aube", "ripgrep", "coreutils"):
            with self.subTest(name=name):
                self.setUp()
                self.lock[name]["lock_sha256"] = "0" * 64
                with self.assertRaisesRegex(ValueError, f"fixed {name} Cargo.lock mismatch"):
                    self.run_build()

    def test_ripgrep_source_mutation_invalidates_success(self):
        def hook(args):
            if "build" in args and "ripgrep" in args:
                (self.ripgrep / "Cargo.toml").write_text("changed")

        with self.assertRaises(ValueError):
            self.run_build(hook=hook)
        receipt = self.receipt()
        self.assertEqual(receipt["exit"], 1)
        self.assertFalse(receipt["source_unchanged"])

    def test_download_extracts_fixed_revision(self):
        revision = self.lock["aube"]["revision"]
        staged = self.directory / "staged"
        self.upstream.rename(staged)
        fetched = []

        def urlretrieve(url, archive):
            fetched.append(url)
            with tarfile.open(archive, "w:gz") as tar:
                tar.add(staged, arcname=f"aube-{revision}")

        with patch.object(builder.urllib.request, "urlretrieve", side_effect=urlretrieve):
            receipt, _ = self.run_build()
        self.assertEqual(fetched, [f"https://codeload.github.com/aubepkg/aube/tar.gz/{revision}"])
        self.assertEqual(receipt["exit"], 0)
        self.assertEqual(receipt["source_before"], evidence.snapshot(self.upstream))

    def test_root_policy_change_during_build_invalidates(self):
        root = self.directory / "root"
        root.mkdir()
        (root / "deny.toml").write_bytes((HERE.parents[2] / "deny.toml").read_bytes())

        def change_policy(args):
            if "build" in args:
                (root / "deny.toml").write_text("changed")

        with (
            patch.object(builder, "ROOT", root),
            self.assertRaisesRegex(ValueError, "guest build failed"),
        ):
            self.run_build(hook=change_policy)
        receipt = self.receipt()
        self.assertEqual(receipt["exit"], 1)
        self.assertEqual(receipt["error"], "root license policy changed during build")

    def test_source_snapshot_error_invalidates_success(self):
        with (
            patch.object(builder, "record_source_after", side_effect=OSError("unreadable source")),
            self.assertRaisesRegex(ValueError, "unreadable source"),
        ):
            self.run_build()
        receipt = self.receipt()
        self.assertEqual(receipt["exit"], 1)
        self.assertFalse(receipt["source_unchanged"])

    def test_command_logs_and_propagates_failure(self):
        log = self.directory / "tool.log"
        builder.command([sys.executable, "-c", 'print("fixture output")'], self.directory, log)
        with self.assertRaises(subprocess.CalledProcessError):
            builder.command([sys.executable, "-c", "raise SystemExit(3)"], self.directory, log)
        text = log.read_text()
        self.assertEqual(text.count("COMMAND "), 2)
        self.assertIn("fixture output\n", text)


if __name__ == "__main__":
    unittest.main()
