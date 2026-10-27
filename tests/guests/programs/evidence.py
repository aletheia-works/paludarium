"""Build receipt checks shared by observations and unit tests."""

import hashlib
import pathlib
import struct

REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
# The guest binaries every build produces.
GUESTS = ("probe", "aube", "ripgrep")
# Guest-only license exceptions for the fixed aube source. Each crate's full
# license text is retained from its crates.io package: (file, required text).
LICENSE_EXCEPTIONS = [
    {"crate": "webpki-root-certs@1.0.10", "allow": ["CDLA-Permissive-2.0"]},
    {"crate": "option-ext@0.2.0", "allow": ["MPL-2.0"]},
]
LICENSE_TEXTS = {
    "webpki-root-certs@1.0.10": ("LICENSE", (b"Community Data License Agreement", b"2.1.")),
    "option-ext@0.2.0": ("LICENSE.txt", (b"Mozilla Public License Version 2.0",)),
}
# RustSec advisories aube's audit ignores for now: the zstd 0.13 ones, which
# aube gets through decmpfs's exact `zstd = "=0.13.3"` pin and cannot update.
# Remove them once a decmpfs release takes zstd 0.14 (SocketDev/decmpfs#16).
ADVISORY_EXCEPTIONS = [
    {"id": "RUSTSEC-2026-0391", "crate": "zstd@0.13.3"},
    {"id": "RUSTSEC-2026-0398", "crate": "zstd-safe@7.3.0"},
    {"id": "RUSTSEC-2026-0403", "crate": "zstd-safe@7.3.0"},
]
# The root policy's empty advisory ignore list, which the guest policy fills.
ROOT_IGNORE = b"ignore = []\n"
LICENSE_SUFFIX = (
    b'\n[[licenses.exceptions]]\ncrate = "webpki-root-certs@1.0.10"\nallow = ["CDLA-Permissive-2.0"]\n'
    b'\n[[licenses.exceptions]]\ncrate = "option-ext@0.2.0"\nallow = ["MPL-2.0"]\n'
)


def advisory_ignore(advisories):
    """The ignore list of `advisories`. One that no crate matches any more
    fails the audit, so that a guest bump cannot leave a stale exception."""
    entries = "".join(
        f'  {{ id = "{a["id"]}", reason = "{a["crate"]} through decmpfs (SocketDev/decmpfs#16)" }},\n'
        for a in advisories
    )
    return f'unused-ignored-advisory = "deny"\nignore = [\n{entries}]\n'.encode()


def guest_policy(root_bytes, exceptions, advisories):
    """The root policy with the approved guest exceptions, and nothing else."""
    if exceptions != LICENSE_EXCEPTIONS:
        raise ValueError("unapproved guest license exception")
    if advisories != ADVISORY_EXCEPTIONS:
        raise ValueError("unapproved guest advisory exception")
    if root_bytes.count(ROOT_IGNORE) != 1:
        raise ValueError("root policy lacks one empty advisory ignore list")
    return root_bytes.replace(ROOT_IGNORE, advisory_ignore(advisories)) + LICENSE_SUFFIX


def license_file_name(exception):
    name, version = exception["crate"].split("@")
    return f"{name}-{version}-{exception['allow'][0]}.txt"


def policy_receipt_valid(directory, receipt, root_bytes):
    policy = receipt["license_policy"]
    if policy["exceptions"] != LICENSE_EXCEPTIONS:
        raise ValueError("unapproved guest license exception")
    if policy["advisories"] != ADVISORY_EXCEPTIONS:
        raise ValueError("unapproved guest advisory exception")
    if hashlib.sha256(root_bytes).hexdigest() != policy["root_config_sha256"]:
        raise ValueError("root policy changed")
    config = directory / "aube-deny.toml"
    if config.read_bytes() != guest_policy(root_bytes, policy["exceptions"], policy["advisories"]):
        raise ValueError("guest config does not inherit exact root policy")
    if digest(config) != policy["guest_config_sha256"]:
        raise ValueError("guest config hash differs")
    if set(policy["licenses"]) != {e["crate"] for e in LICENSE_EXCEPTIONS}:
        raise ValueError("license text set differs")
    for exception in LICENSE_EXCEPTIONS:
        retained = policy["licenses"][exception["crate"]]
        if digest(directory / "licenses" / license_file_name(exception)) != retained["sha256"]:
            raise ValueError("license text hash differs")
        if retained["source"] != REGISTRY:
            raise ValueError("license exception crate is not from crates.io")
    if receipt["audits"] != {"probe": 0, "aube": 0, "ripgrep": 0}:
        raise ValueError("full guest dependency audits did not pass")


def digest(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def json_source_lock():
    import json

    return json.loads(pathlib.Path(__file__).with_name("source-lock.json").read_text())


def static_elf(data):
    if len(data) < 64 or data[:7] != b"\x7fELF\x02\x01\x01":
        raise ValueError("not ELF64 little endian")
    if struct.unpack_from("<H", data, 18)[0] != 62:
        raise ValueError("not x86-64")
    if struct.unpack_from("<H", data, 16)[0] not in (2, 3):
        raise ValueError("not executable or static PIE")
    offset = struct.unpack_from("<Q", data, 32)[0]
    size, count = struct.unpack_from("<HH", data, 54)
    if size < 56 or count == 0 or offset + size * count > len(data):
        raise ValueError("invalid program headers")
    headers = [struct.unpack_from("<IIQQQQQQ", data, offset + i * size) for i in range(count)]
    types = [header[0] for header in headers]
    if 3 in types or 1 not in types:
        raise ValueError("interpreter or missing load segment")
    # Rust/musl static PIE uses PT_DYNAMIC for its own relocations. It is
    # static iff no external interpreter or DT_NEEDED library is required.
    for header in headers:
        if header[2] + header[5] > len(data):
            raise ValueError("segment extends outside binary")
        if header[0] != 2:
            continue
        start, length = header[2], header[5]
        if length == 0 or length % 16:
            raise ValueError("malformed dynamic table")
        terminated = False
        for position in range(start, start + length, 16):
            tag, _ = struct.unpack_from("<qQ", data, position)
            if tag == 1:
                raise ValueError("DT_NEEDED external library")
            if tag == 0:
                terminated = True
                break
        if not terminated:
            raise ValueError("unterminated dynamic table")
    return True


def validate(directory, receipt):
    if receipt["exit"] != 0 or not receipt["source_unchanged"]:
        raise ValueError("build failure or modified upstream source")
    for name in GUESTS:
        binary = directory / name
        if digest(binary) != receipt["binaries"][name]["sha256"]:
            raise ValueError("binary hash differs")
        static_elf(binary.read_bytes())
    root_bytes = (pathlib.Path(__file__).resolve().parents[3] / "deny.toml").read_bytes()
    policy_receipt_valid(directory, receipt, root_bytes)


def record_source_after(upstream, receipt, key="source"):
    if f"{key}_before" not in receipt:
        return
    receipt[f"{key}_after"] = snapshot(upstream)
    unchanged = receipt[f"{key}_after"] == receipt[f"{key}_before"]
    receipt["source_unchanged"] = receipt.get("source_unchanged", True) and unchanged
    if not unchanged:
        receipt["exit"] = 1
        receipt["source_error"] = "upstream source changed during build or audit"


def snapshot(directory):
    return {
        str(p.relative_to(directory)): digest(p)
        for p in sorted(directory.rglob("*"))
        if p.is_file()
    }
