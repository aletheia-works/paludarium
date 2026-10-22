#!/usr/bin/env python3
"""Move a pin to its latest release: the nightly Rust, or the aube or ripgrep guest.

    bump-pins.py toolchain --body body.md   # rust-toolchain.toml, source-lock.json
    bump-pins.py aube --body body.md        # source-lock.json, the feature pages
    bump-pins.py ripgrep --body body.md     # the same for ripgrep
    bump-pins.py --self-test

When the pin moves, the pull request title goes to stdout and its body to
--body; when the pin is already the latest, nothing is printed.
.github/workflows/bump-pins.yml runs it every week and opens the pull request.
"""

import argparse
import datetime
import hashlib
import json
import os
import re
import sys
import tomllib
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLCHAIN_FILE = "rust-toolchain.toml"
SOURCE_LOCK = "tests/guests/programs/source-lock.json"
FEATURE_PAGES = ("docs/guide/features.md", "docs/ja/guide/features.md")
DIST = "https://static.rust-lang.org/dist"
# The guests built from a fixed release: their GitHub repositories.
GUESTS = {
    "aube": "aubepkg/aube",
    "ripgrep": "BurntSushi/ripgrep",
    "coreutils": "uutils/coreutils",
}
# The hosts CI and contributors build on; each needs the whole toolchain.
HOSTS = ("x86_64-unknown-linux-gnu", "aarch64-apple-darwin", "x86_64-pc-windows-msvc")
# A nightly with a missing component is skipped; give up after this many days.
LOOKBACK_DAYS = 14


def fetch(url):
    request = urllib.request.Request(url, headers={"User-Agent": "paludarium-bump-pins"})
    token = os.environ.get("GH_TOKEN")
    if token and url.startswith("https://api.github.com/"):
        request.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read()


def replace_once(text, old, new, where):
    if text.count(old) != 1:
        raise SystemExit(f"{where}: expected exactly one {old!r}, found {text.count(old)}")
    return text.replace(old, new)


def edit(path, old, new):
    file = ROOT / path
    file.write_text(replace_once(file.read_text(), old, new, path))


def nightly_complete(manifest, components, targets):
    """Whether every host has rustc, cargo, the components and the targets' std."""
    renames = {name: value["to"] for name, value in manifest.get("renames", {}).items()}
    packages = manifest["pkg"]

    def available(name, target):
        entry = packages.get(renames.get(name, name), {}).get("target", {})
        return entry.get(target, entry.get("*", {})).get("available", False)

    return all(
        available(name, host) for host in HOSTS for name in ("rustc", "cargo", *components)
    ) and all(available("rust-std", target) for target in targets)


def rustc_commit(manifest):
    match = re.search(r"\(([0-9a-f]{7,40}) ", manifest["pkg"]["rustc"]["version"])
    return match.group(1) if match else None


def bump_toolchain(get=fetch):
    pinned = tomllib.loads((ROOT / TOOLCHAIN_FILE).read_text())["toolchain"]
    channel = pinned["channel"]
    current = datetime.date.fromisoformat(channel.removeprefix("nightly-"))
    latest = tomllib.loads(get(f"{DIST}/channel-rust-nightly.toml").decode())
    day = datetime.date.fromisoformat(latest["date"])
    manifest = latest
    for _ in range(LOOKBACK_DAYS):
        if day <= current:
            return None
        if manifest is None:
            manifest = tomllib.loads(get(f"{DIST}/{day}/channel-rust-nightly.toml").decode())
        if nightly_complete(manifest, pinned.get("components", []), pinned.get("targets", [])):
            break
        print(f"nightly-{day} lacks a component or target; trying the day before", file=sys.stderr)
        day -= datetime.timedelta(days=1)
        manifest = None
    else:
        raise SystemExit(f"no complete nightly in the last {LOOKBACK_DAYS} days")
    new = f"nightly-{day}"
    old_manifest = tomllib.loads(get(f"{DIST}/{current}/channel-rust-nightly.toml").decode())
    edit(TOOLCHAIN_FILE, f'channel = "{channel}"', f'channel = "{new}"')
    edit(SOURCE_LOCK, f'"toolchain": "{channel}"', f'"toolchain": "{new}"')
    old_commit, new_commit = rustc_commit(old_manifest), rustc_commit(manifest)
    lines = [
        f"Moves the pinned Rust toolchain from `{channel}` to `{new}`, the latest nightly",
        f"with {', '.join(pinned.get('components', []))} and the "
        f"{', '.join(pinned.get('targets', []))} targets on {', '.join(HOSTS)}.",
        "",
        f"- Before: `{old_manifest['pkg']['rustc']['version']}`",
        f"- After: `{manifest['pkg']['rustc']['version']}`",
    ]
    if old_commit and new_commit:
        lines.append(
            f"- Changes: https://github.com/rust-lang/rust/compare/{old_commit}...{new_commit}"
        )
    return f"chore(toolchain): bump the pinned nightly to {new}", "\n".join(lines)


def version(tag):
    return tuple(int(part) for part in re.findall(r"\d+", tag))


def edit_line(path, marker, old, new):
    """Replaces `old` with `new` on the one line of `path` that has `marker` and `old`."""
    file = ROOT / path
    lines = file.read_text().splitlines(keepends=True)
    hits = [i for i, line in enumerate(lines) if marker in line and old in line]
    if len(hits) != 1:
        raise SystemExit(f"{path}: expected one {marker} line naming {old}, found {len(hits)}")
    lines[hits[0]] = replace_once(lines[hits[0]], old, new, path)
    file.write_text("".join(lines))


def bump_guest(name, get=fetch):
    repository = GUESTS[name]
    lock = json.loads((ROOT / SOURCE_LOCK).read_text())[name]
    release = json.loads(get(f"https://api.github.com/repos/{repository}/releases/latest"))
    tag = release["tag_name"]
    if version(tag) <= version(lock["tag"]):
        return None
    commit = json.loads(get(f"https://api.github.com/repos/{repository}/commits/{tag}"))["sha"]
    cargo_lock = get(f"https://raw.githubusercontent.com/{repository}/{commit}/Cargo.lock")
    lock_sha256 = hashlib.sha256(cargo_lock).hexdigest()
    # source-lock.json holds each guest on one line.
    marker = f'"{name}": {{'
    edit_line(SOURCE_LOCK, marker, f'"tag": "{lock["tag"]}"', f'"tag": "{tag}"')
    edit_line(SOURCE_LOCK, marker, lock["revision"], commit)
    edit_line(SOURCE_LOCK, marker, lock["lock_sha256"], lock_sha256)
    for page in FEATURE_PAGES:
        edit_line(page, f"**{name}**", lock["tag"], tag)
    body = "\n".join(
        [
            f"Moves the {name} guest from {lock['tag']} to {tag} ({commit}), its latest release.",
            "",
            f"- Release notes: {release['html_url']}",
            f"- Changes: https://github.com/{repository}/compare/{lock['tag']}...{tag}",
            f"- Cargo.lock SHA-256: `{lock_sha256}`",
            "",
            "If the guest build, its audit or the differential tests fail, fix the cause",
            f"in {name} itself rather than adding an exception here.",
        ]
    )
    return f"chore(guests): bump {name} to {tag}", body


def self_test():
    import tempfile

    global ROOT

    def manifest(day, missing=()):
        def package(name, *targets):
            return {"target": {t: {"available": name not in missing} for t in targets}}

        return {
            "date": day,
            "renames": {"clippy": {"to": "clippy-preview"}},
            "pkg": {
                "rustc": {
                    "version": f"1.0.0-nightly (abcdef{day[-1]}0 {day})",
                    **package("rustc", *HOSTS),
                },
                "cargo": package("cargo", *HOSTS),
                "clippy-preview": package("clippy-preview", *HOSTS),
                "rust-src": package("rust-src", "*"),
                "rust-std": package("rust-std", *HOSTS, "wasm32-unknown-unknown"),
            },
        }

    def fake(manifests):
        def get(url):
            key = (
                "latest" if url.endswith("/dist/channel-rust-nightly.toml") else url.split("/")[-2]
            )
            return toml(manifests[key]).encode()

        return get

    def toml(value):
        # Just enough TOML for the fake manifests: tables of strings and booleans.
        out = []

        def walk(prefix, table):
            scalars = {k: v for k, v in table.items() if not isinstance(v, dict)}
            if prefix:
                out.append(f"[{prefix}]")
            for key, item in scalars.items():
                out.append(f"{json.dumps(key)} = {json.dumps(item)}")
            for key, item in table.items():
                if isinstance(item, dict):
                    walk(f"{prefix}.{json.dumps(key)}" if prefix else json.dumps(key), item)

        walk("", value)
        return "\n".join(out) + "\n"

    with tempfile.TemporaryDirectory() as tmp:
        ROOT = Path(tmp)
        (ROOT / SOURCE_LOCK).parent.mkdir(parents=True)

        def reset():
            (ROOT / TOOLCHAIN_FILE).write_text(
                '[toolchain]\nchannel = "nightly-2026-10-11"\ncomponents = ["clippy", "rust-src"]\n'
                'targets = ["wasm32-unknown-unknown"]\n'
            )
            (ROOT / SOURCE_LOCK).write_text('{\n  "toolchain": "nightly-2026-10-11"\n}\n')

        # The latest nightly is complete: take it.
        reset()
        title, body = bump_toolchain(
            fake({"latest": manifest("2026-10-22"), "2026-10-11": manifest("2026-10-11")})
        )
        assert title == "chore(toolchain): bump the pinned nightly to nightly-2026-10-22", title
        assert 'channel = "nightly-2026-10-22"' in (ROOT / TOOLCHAIN_FILE).read_text()
        assert '"toolchain": "nightly-2026-10-22"' in (ROOT / SOURCE_LOCK).read_text()
        assert "compare/abcdef10...abcdef20" in body, body
        # Missing clippy on the latest and rust-src the day before: step back two days.
        reset()
        title, _ = bump_toolchain(
            fake(
                {
                    "latest": manifest("2026-10-22", missing=("clippy-preview",)),
                    "2026-10-21": manifest("2026-10-21", missing=("rust-src",)),
                    "2026-10-20": manifest("2026-10-20"),
                    "2026-10-11": manifest("2026-10-11"),
                }
            )
        )
        assert title.endswith("nightly-2026-10-20"), title
        # Only incomplete nightlies newer than the pin: keep the pin.
        reset()
        assert (
            bump_toolchain(
                fake(
                    {
                        "latest": manifest("2026-10-12", missing=("rust-std",)),
                        "2026-10-11": manifest("2026-10-11"),
                    }
                )
            )
            is None
        )
        assert 'channel = "nightly-2026-10-11"' in (ROOT / TOOLCHAIN_FILE).read_text()
        # Already the latest.
        assert bump_toolchain(fake({"latest": manifest("2026-10-11")})) is None

        # A newer release moves the guest's tag, revision, lock digest and both
        # pages, and leaves the other guest alone.
        def guest_line(name, tag, revision, digest):
            return (
                f'  "{name}": {{"tag": "{tag}", "revision": "{revision}", '
                f'"lock_sha256": "{digest}"}}'
            )

        (ROOT / SOURCE_LOCK).write_text(
            "{\n"
            + guest_line("aube", "v2.8.1", "a" * 40, "b" * 64)
            + ",\n"
            + guest_line("ripgrep", "15.2.0", "d" * 40, "e" * 64)
            + "\n}\n"
        )
        for page in FEATURE_PAGES:
            (ROOT / page).parent.mkdir(parents=True, exist_ok=True)
            (ROOT / page).write_text(
                "- **probe**: x\n- **aube**: a package manager (v2.8.1).\n"
                "- **ripgrep**: a search tool (15.2.0).\n"
            )

        def aube_get(tag):
            def get(url):
                if url.endswith("/releases/latest"):
                    return json.dumps(
                        {"tag_name": tag, "html_url": "https://example.invalid"}
                    ).encode()
                if "/commits/" in url:
                    return json.dumps({"sha": "c" * 40}).encode()
                return b"lock"

            return get

        assert bump_guest("aube", aube_get("v2.8.1")) is None
        assert bump_guest("aube", aube_get("v2.7.9")) is None
        title, _ = bump_guest("aube", aube_get("v2.10.0"))
        assert title == "chore(guests): bump aube to v2.10.0", title
        lock = json.loads((ROOT / SOURCE_LOCK).read_text())["aube"]
        assert lock == {
            "tag": "v2.10.0",
            "revision": "c" * 40,
            "lock_sha256": hashlib.sha256(b"lock").hexdigest(),
        }, lock
        for page in FEATURE_PAGES:
            assert "(v2.10.0)" in (ROOT / page).read_text()
        title, _ = bump_guest("ripgrep", aube_get("15.10.0"))
        assert title == "chore(guests): bump ripgrep to 15.10.0", title
        locks = json.loads((ROOT / SOURCE_LOCK).read_text())
        assert locks["ripgrep"]["tag"] == "15.10.0" and locks["aube"] == lock, locks
        for page in FEATURE_PAGES:
            text = (ROOT / page).read_text()
            assert "(15.10.0)" in text and "(v2.10.0)" in text, text

        # A value that is not there exactly once stops the bump.
        try:
            replace_once("a a", "a", "b", "x")
        except SystemExit:
            pass
        else:
            raise AssertionError("replace_once accepted two matches")
    print("bump-pins: all tests passed")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("pin", nargs="?", choices=("toolchain", *GUESTS))
    parser.add_argument("--body", type=Path, help="where to write the pull request body")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if not args.pin:
        parser.error("name a pin, or pass --self-test")
    result = bump_toolchain() if args.pin == "toolchain" else bump_guest(args.pin)
    if result is None:
        print(f"{args.pin} is already the latest", file=sys.stderr)
        return
    title, body = result
    if args.body:
        args.body.write_text(body + "\n")
    print(title)


if __name__ == "__main__":
    main()
