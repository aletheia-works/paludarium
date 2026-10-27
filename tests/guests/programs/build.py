"""Isolated fixed-revision guest build; no Git repository mutation."""

import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import tarfile
import urllib.request

from evidence import (
    LICENSE_TEXTS,
    REGISTRY,
    digest,
    guest_policy,
    license_file_name,
    record_source_after,
    snapshot,
    static_elf,
)

ROOT = pathlib.Path(__file__).resolve().parents[3]
HERE = pathlib.Path(__file__).resolve().parent


def command(args, cwd, log, env=None):
    with log.open("ab") as out:
        out.write(("COMMAND " + repr(args) + "\n").encode())
        subprocess.run(args, cwd=cwd, env=env, stdout=out, stderr=subprocess.STDOUT, check=True)


def retain_licenses(metadata, exceptions, directory):
    """Copy each excepted crate's full license text from its crates.io package."""
    licenses = directory / "licenses"
    licenses.mkdir(exist_ok=True)
    retained = {}
    for exception in exceptions:
        name, version = exception["crate"].split("@")
        packages = [
            p for p in metadata["packages"] if p["name"] == name and p["version"] == version
        ]
        if len(packages) != 1 or packages[0]["license"] != " OR ".join(exception["allow"]):
            raise ValueError(
                f"license exception crate identity/license mismatch: {exception['crate']}"
            )
        package = packages[0]
        if package["source"] != REGISTRY:
            raise ValueError(
                f"license exception crate not sourced from crates.io: {exception['crate']}"
            )
        file_name, required = LICENSE_TEXTS[exception["crate"]]
        text = (pathlib.Path(package["manifest_path"]).parent / file_name).read_bytes()
        if not all(part in text for part in required):
            raise ValueError(f"full license text missing: {exception['crate']}")
        license_file = licenses / license_file_name(exception)
        license_file.write_bytes(text)
        retained[exception["crate"]] = {"source": package["source"], "sha256": digest(license_file)}
    return retained


def fetch(source, name, repository, revision, directory):
    """Extract `repository` at `revision` to source/name, unless it is there."""
    upstream = source / name
    if not upstream.exists():
        archive = directory / f"{name}-source.tar.gz"
        urllib.request.urlretrieve(
            f"https://codeload.github.com/{repository}/tar.gz/{revision}", archive
        )
        with tarfile.open(archive) as tar:
            tar.extractall(source, filter="data")
        (source / f"{repository.split('/')[1]}-{revision}").rename(upstream)
    return upstream


def build(directory):
    directory.mkdir(parents=True, exist_ok=True)
    lock = json.loads((HERE / "source-lock.json").read_text())
    receipt = {
        "schema": 1,
        "exit": None,
        "toolchain": lock["toolchain"],
        "target": lock["target"],
        "aube": lock["aube"],
        "ripgrep": lock["ripgrep"],
        "binaries": {},
        "audits": {},
    }
    receipt_file = directory / "build-receipt.json"
    source = directory / "source"
    source.mkdir(exist_ok=True)
    upstream = source / "aube"
    ripgrep = source / "ripgrep"
    try:
        # cargo-deny 0.20.2 graph/config arguments are top-level options,
        # before `check`. Validate parsing before downloading/building guests.
        command(
            [
                "cargo",
                "deny",
                "--manifest-path",
                str(HERE / "probe/Cargo.toml"),
                "--config",
                str(ROOT / "deny.toml"),
                "--locked",
                "check",
                "--help",
            ],
            ROOT,
            directory / "cli-dependencies.log",
        )
        fetch(source, "aube", "aubepkg/aube", lock["aube"]["revision"], directory)
        if digest(upstream / "Cargo.lock") != lock["aube"]["lock_sha256"]:
            raise ValueError("fixed aube Cargo.lock mismatch")
        fetch(source, "ripgrep", "BurntSushi/ripgrep", lock["ripgrep"]["revision"], directory)
        if digest(ripgrep / "Cargo.lock") != lock["ripgrep"]["lock_sha256"]:
            raise ValueError("fixed ripgrep Cargo.lock mismatch")
        receipt["source_before"] = snapshot(upstream)
        receipt["ripgrep_source_before"] = snapshot(ripgrep)
        root_policy = (ROOT / "deny.toml").read_bytes()
        guest_config = directory / "aube-deny.toml"
        guest_config.write_bytes(
            guest_policy(
                root_policy,
                lock["guest_license_exceptions"],
                lock["guest_advisory_exceptions"],
            )
        )
        # Metadata fetches crates.io sources but does not compile or mutate
        # the upstream project. Retain each excepted crate's full license text.
        metadata = json.loads(
            subprocess.check_output(
                [
                    "cargo",
                    "+" + lock["toolchain"],
                    "metadata",
                    "--locked",
                    "--all-features",
                    "--manifest-path",
                    str(upstream / "Cargo.toml"),
                    "--format-version",
                    "1",
                ],
                text=True,
            )
        )
        receipt["license_policy"] = {
            "exceptions": lock["guest_license_exceptions"],
            "advisories": lock["guest_advisory_exceptions"],
            "root_config_sha256": hashlib.sha256(root_policy).hexdigest(),
            "guest_config_sha256": digest(guest_config),
            "licenses": retain_licenses(metadata, lock["guest_license_exceptions"], directory),
        }
        primer = directory / "empty-primer.rkyv.zst"
        primer.write_bytes(b"")
        cargo = ["cargo", "+" + lock["toolchain"]]
        subprocess.run([*cargo, "--version"], check=True)
        receipt["rustc"] = subprocess.check_output(
            ["rustc", "+" + lock["toolchain"], "--version"], text=True
        ).strip()
        receipt["cargo"] = subprocess.check_output([*cargo, "--version"], text=True).strip()
        # Audit every guest before any cross-compilation can fail on the host
        # linker; every advisory category remains mandatory. ripgrep needs no
        # license exception, so it is held to the root policy itself.
        for name, manifest, config in [
            ("probe", HERE / "probe/Cargo.toml", ROOT / "deny.toml"),
            ("aube", upstream / "Cargo.toml", guest_config),
            ("ripgrep", ripgrep / "Cargo.toml", ROOT / "deny.toml"),
        ]:
            command(
                [
                    "cargo",
                    "deny",
                    "--manifest-path",
                    str(manifest),
                    "--config",
                    str(config),
                    "--locked",
                    "check",
                ],
                ROOT,
                directory / f"{name}-dependencies.log",
            )
            receipt["audits"][name] = 0
        for name, manifest, extra, binary_name in [
            ("probe", HERE / "probe/Cargo.toml", [], "paludarium-probe"),
            ("aube", upstream / "Cargo.toml", ["-p", "aube", "--bin", "aube"], "aube"),
            ("ripgrep", ripgrep / "Cargo.toml", ["-p", "ripgrep", "--bin", "rg"], "rg"),
        ]:
            args = [
                *cargo,
                "build",
                "--release",
                "--locked",
                "--target",
                lock["target"],
                "--manifest-path",
                str(manifest),
                "--target-dir",
                str(directory / "targets" / name),
                *extra,
            ]
            env = dict(os.environ, AUBE_PRIMER_PATH=str(primer))
            command(args, ROOT, directory / f"{name}-build.log", env)
            shutil.copy2(
                directory / "targets" / name / lock["target"] / "release" / binary_name,
                directory / name,
            )
            static_elf((directory / name).read_bytes())
            receipt["binaries"][name] = {
                "sha256": digest(directory / name),
                "static_elf": True,
                "lock_sha256": digest(manifest.parent / "Cargo.lock"),
                "command": args,
            }
        receipt["exit"] = 0
    except Exception as error:
        receipt["exit"] = 1
        receipt["error"] = str(error)
        raise
    finally:
        try:
            record_source_after(upstream, receipt)
            record_source_after(ripgrep, receipt, "ripgrep_source")
        except Exception as error:
            receipt["exit"] = 1
            receipt["source_unchanged"] = False
            receipt["source_error"] = str(error)
        if (
            "license_policy" in receipt
            and digest(ROOT / "deny.toml") != receipt["license_policy"]["root_config_sha256"]
        ):
            receipt["exit"] = 1
            receipt["error"] = "root license policy changed during build"
        receipt_file.write_text(json.dumps(receipt, indent=2) + "\n")
    if receipt["exit"] != 0:
        raise ValueError(receipt.get("source_error", "guest build failed"))


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("directory")
    arguments = parser.parse_args()
    build(pathlib.Path(arguments.directory).resolve())
