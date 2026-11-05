#!/usr/bin/env python3
"""Write the notices of what paludarium.wasm is built from, as Cargo's unit graph lists it.

Every crate the wasm build compiles for its target is listed, whether or not the linker kept any
of it: that is the standard library's own crates as well as the crates of Cargo.lock. Each crate's
license files go in as they are. A crate with no license file stops this script, so a new
dependency cannot be left out unnoticed.
"""

import argparse
import hashlib
import html
import json
import os
import re
import subprocess
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGET = "wasm32-unknown-unknown"
DEFAULT_OUTPUT = ROOT / "packages/paludarium-wasm/THIRD-PARTY-NOTICES.txt"
LICENSE_FILE = re.compile(r"^(licen[sc]e|copying|unlicense|notice)", re.IGNORECASE)
# Texts of the standard library's in-tree licenses, in the toolchain's share/doc/rust/licenses.
LIBRARY_LICENSES = ("MIT", "Apache-2.0", "LLVM-exception", "Unicode-3.0", "BSD-2-Clause")
# The standard library's crates that keep license files of their own, under library/.
LIBRARY_FILES = ("compiler-builtins/LICENSE.txt",)
# iced-x86 packages no license file. This is LICENSE.txt of its repository, icedland/iced, at the
# commit its .cargo_vcs_info.json names for 1.22.0 (cae65b1e90451f22c65f580d4acc752c8a486754).
OVERRIDES = {
    "iced-x86": """https://github.com/icedland/iced
Copyright (C) 2018-present iced project and contributors

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.""",
}


def run(*command: str) -> str:
    return subprocess.run(command, cwd=ROOT, check=True, capture_output=True, text=True).stdout


def units() -> list[dict]:
    graph = run(
        os.environ.get("CARGO", "cargo"),
        "build",
        "--locked",
        "-Z",
        "build-std=std,panic_abort",
        "--release",
        "--target",
        TARGET,
        "-p",
        "paludarium-wasm",
        "--unit-graph",
        "-Z",
        "unstable-options",
    )
    return [unit for unit in json.loads(graph)["units"] if unit.get("platform") == TARGET]


def package_id(pkg_id: str) -> tuple[str, str]:
    """The name and version in a Cargo package ID, which leaves the name out when its path ends so."""
    location, _, fragment = pkg_id.rpartition("#")
    if "@" in fragment:
        name, version = fragment.split("@")
        return name, version
    return location.rsplit("/", 1)[1], fragment


def registry_directories() -> dict[tuple[str, str], Path]:
    metadata = json.loads(
        run(os.environ.get("CARGO", "cargo"), "metadata", "--locked", "--format-version", "1")
    )
    return {
        (package["name"], package["version"]): Path(package["manifest_path"]).parent
        for package in metadata["packages"]
    }


def manifest_field(directory: Path, field: str) -> str:
    text = (directory / "Cargo.toml").read_text(encoding="utf-8")
    package = text.split("[package]", 1)[1].split("\n[", 1)[0]
    match = re.search(rf'^{field}\s*=\s*(\[.*?\]|".*?")', package, re.MULTILINE | re.DOTALL)
    if not match:
        return ""
    return ", ".join(re.findall(r'"([^"]*)"', match.group(1)))


def source_notice(directory: Path) -> str:
    """A copyright line at the top of the crate's source, for license files that hold none."""
    source = directory / "src/lib.rs"
    if source.exists():
        for line in source.read_text(encoding="utf-8", errors="replace").splitlines()[:8]:
            if "Copyright" in line and "[yyyy]" not in line:
                return line.lstrip("/ !").strip()
    return ""


def library_notice(documents: Path) -> str:
    """The part of the Rust project's own notice that covers the library's in-tree files."""
    page = (documents / "COPYRIGHT-library.html").read_text(encoding="utf-8")
    text = html.unescape(re.sub(r"<[^>]+>", "", page))
    # Each heading comes first in the table of contents.
    start = text.index("In-tree files", text.index("In-tree files") + 1)
    end = text.index("Out-of-tree dependencies", start)
    return "\n".join(line.strip() for line in text[start:end].splitlines() if line.strip())


def clean(text: str) -> str:
    return "\n".join(line.rstrip() for line in text.strip().splitlines())


def render() -> str:
    toolchain = tomllib.loads((ROOT / "rust-toolchain.toml").read_text(encoding="utf-8"))
    toolchain = toolchain["toolchain"]["channel"]
    os.environ["RUSTUP_TOOLCHAIN"] = toolchain
    sysroot = Path(run(os.environ.get("RUSTC", "rustc"), "--print", "sysroot").strip())
    library = sysroot / "lib/rustlib/src/rust/library"
    documents = sysroot / "share/doc/rust"
    needed = [documents / "COPYRIGHT-library.html"]
    needed += [documents / "licenses" / f"{name}.txt" for name in LIBRARY_LICENSES]
    needed += [library / name for name in LIBRARY_FILES]
    missing = [str(path) for path in needed if not path.is_file()]
    if missing:
        raise SystemExit(f"toolchain {toolchain} lacks files the notices need: {missing}")
    registry = registry_directories()
    texts: dict[str, tuple[str, list[str]]] = {}

    def keep(text: str, label: str, user: str) -> str:
        body = clean(text)
        digest = hashlib.sha256(body.encode()).hexdigest()
        kept = texts.setdefault(digest, (body, []))
        kept[1].append(f"{user} ({label})")
        return digest

    crates = []
    standard = set()
    for name, version in sorted({package_id(unit["pkg_id"]) for unit in units()}):
        if name.startswith("paludarium"):
            continue
        vendored = library / "vendor" / f"{name}-{version}"
        directory = vendored if vendored.is_dir() else registry.get((name, version))
        if directory is None:
            standard.add(f"{name} {version}")
            continue
        files = sorted(p for p in directory.iterdir() if p.is_file() and LICENSE_FILE.match(p.name))
        user = f"{name} {version}"
        found = [keep(p.read_text(encoding="utf-8", errors="replace"), p.name, user) for p in files]
        if name in OVERRIDES:
            found.append(keep(OVERRIDES[name], "LICENSE.txt of its repository", user))
        if not found:
            raise SystemExit(f"{name} {version} has no license file: add it to OVERRIDES")
        crates.append((name, version, directory, found))

    for name in LIBRARY_LICENSES:
        keep((documents / "licenses" / f"{name}.txt").read_text(), name, "Rust standard library")
    for name in LIBRARY_FILES:
        keep((library / name).read_text(), name, "Rust standard library")

    numbers = {digest: index + 1 for index, digest in enumerate(texts)}
    lines = [
        "Third-party notices for paludarium.wasm",
        "",
        "paludarium itself is under the Apache License 2.0 (see LICENSE). paludarium.wasm also",
        "holds code built from the crates below. Where a crate offers a choice of licenses, the",
        "texts of all of them are here.",
        "",
        f"Built with Rust {toolchain} for {TARGET}. Generated by scripts/third-party-notices.py.",
        "",
        "=" * 78,
        "Crates",
        "=" * 78,
        "",
    ]
    for name, version, directory, found in crates:
        lines.append(f"{name} {version}")
        lines.append(f"  License: {manifest_field(directory, 'license')}")
        authors = manifest_field(directory, "authors")
        if authors:
            lines.append(f"  Authors: {authors}")
        notice = source_notice(directory)
        if notice:
            lines.append(f"  In its source: {notice}")
        references = ", ".join(f"[{numbers[digest]}]" for digest in found)
        lines.append(f"  License texts: {references}")
        lines.append("")
    lines += [
        "=" * 78,
        "The Rust standard library",
        "=" * 78,
        "",
        ", ".join(sorted(standard)),
        "",
        "From the Rust project's notice for this toolchain (share/doc/rust/COPYRIGHT-library.html):",
        "",
        library_notice(documents),
        "",
        "License texts: "
        + ", ".join(
            f"[{numbers[digest]}]"
            for digest, (_, users) in texts.items()
            if any(user.startswith("Rust standard library") for user in users)
        ),
        "",
        "=" * 78,
        "License texts",
        "=" * 78,
    ]
    for digest, (body, _) in texts.items():
        lines += ["", "-" * 78, f"[{numbers[digest]}]", "-" * 78, "", body]
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    arguments = parser.parse_args()
    arguments.output.write_text(render(), encoding="utf-8")


if __name__ == "__main__":
    main()
