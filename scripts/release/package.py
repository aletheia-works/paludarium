"""Byte-exact distribution inspection, independent of registry upload."""

import contextlib
import hashlib
import json
import re
import tarfile
import tomllib
from pathlib import PurePosixPath

import policy


def sha(b):
    return hashlib.sha256(b).hexdigest()


REQUIRED_JS = {
    "index.mjs",
    "coordinator.mjs",
    "execution.mjs",
    "worker-support.mjs",
    "jit-support.mjs",
    "filesystem-snapshot.mjs",
}


def members(path, prefix):
    result = {}
    with tarfile.open(path, "r:gz") as archive:
        rows = archive.getmembers()
        policy.require(0 < len(rows) <= 10000, "empty/oversize archive")
        total = 0
        for row in rows:
            p = PurePosixPath(row.name)
            policy.require(
                not p.is_absolute() and ".." not in p.parts and "\\" not in row.name,
                "unsafe archive path",
            )
            policy.require(p.parts and p.parts[0] == prefix, "wrong archive prefix")
            if row.isdir():
                continue
            policy.require(
                row.isfile() and row.size <= 128 * 1024 * 1024, "linked/special/oversize member"
            )
            name = "/".join(p.parts[1:])
            policy.require(bool(name) and name not in result, "empty/duplicate member")
            total += row.size
            policy.require(total <= 256 * 1024 * 1024, "archive total too large")
            data = archive.extractfile(row).read()
            policy.require(len(data) == row.size, "truncated member")
            result[name] = data
    return result


def inspect_npm(path, expected):
    policy.require(sha(path.read_bytes()) == expected["tar_sha256"], "tarball digest mismatch")
    files = members(path, "package")
    metadata = json.loads(files["package.json"])
    policy.require(
        metadata["name"] == "@aletheia-works/paludarium-wasm"
        and metadata["version"] == expected["version"],
        "npm metadata mismatch",
    )
    required = REQUIRED_JS | {
        "index.d.ts",
        "paludarium.wasm",
        "LICENSE",
        "README.md",
        "package.json",
    }
    policy.require(required <= set(files), "required npm file missing")
    policy.require(
        [n for n in files if n.endswith(".wasm")] == ["paludarium.wasm"],
        "exactly one production Wasm required",
    )
    wasm = files["paludarium.wasm"]
    policy.require(
        wasm.startswith(b"\0asm\x01\0\0\0") and sha(wasm) == expected["wasm_sha256"],
        "production Wasm changed",
    )
    for name in REQUIRED_JS:
        text = files[name].decode()
        for ref in re.findall(r"""["']((?:\./|\.\./)[^"']+\.mjs)["']""", text):
            base = PurePosixPath(name).parent / ref
            policy.require(
                ".." not in base.parts and str(base) in files, "relative JS import missing/unsafe"
            )
    for name, pin in expected["source_files"].items():
        policy.require(name in files and sha(files[name]) == pin, "packed source file mismatch")
    policy.require(
        re.fullmatch(r"(?:[0-9a-f]{40}|local:[0-9a-f]{64})", expected["head"])
        and re.fullmatch("[0-9a-f]{64}", expected["source_sha256"]),
        "missing source/head binding",
    )
    return dict(
        head=expected["head"],
        version=metadata["version"],
        files={n: dict(bytes=len(b), sha256=sha(b)) for n, b in files.items()},
        tar_sha256=expected["tar_sha256"],
        wasm_sha256=sha(wasm),
        source_sha256=expected["source_sha256"],
    )


def inspect_crates(paths, inventory):
    expected = inventory["packages"]
    policy.require(len(paths) == 11, "eleven crates required")
    seen = {}
    for path in paths:
        name = next(
            (n for n in expected if path.name == n + "-" + inventory["version"] + ".crate"), None
        )
        policy.require(name is not None and name not in seen, "private/unknown/duplicate crate")
        files = members(path, name + "-" + inventory["version"])
        policy.require(
            "Cargo.toml" in files and "LICENSE" in files and "README.md" in files,
            "crate metadata/license/readme missing",
        )
        manifest = tomllib.loads(files["Cargo.toml"].decode())
        package = manifest["package"]
        policy.require(
            package["name"] == name and package["version"] == inventory["version"],
            "crate identity mismatch",
        )
        policy.require(
            package.get("publish", True) is not False and package.get("license") == "Apache-2.0",
            "private or unlicensed crate",
        )
        actual = {}
        tables = [manifest.get("dependencies", {}), manifest.get("build-dependencies", {})]
        for target in manifest.get("target", {}).values():
            tables.extend([target.get("dependencies", {}), target.get("build-dependencies", {})])
        for table in tables:
            for alias, dep in table.items():
                dep = {"version": dep} if isinstance(dep, str) else dep
                target = dep.get("package", alias)
                policy.require(
                    "path" not in dep and "git" not in dep, "unresolved source dependency"
                )
                if target in policy.PUBLIC:
                    actual[target] = dep["version"].lstrip("=^")
        policy.require(
            actual == expected[name]["dependencies"], "packaged dependency missing/version mismatch"
        )
        seen[name] = dict(
            sha256=sha(path.read_bytes()), files={n: sha(b) for n, b in files.items()}
        )
    policy.require(set(seen) == set(expected), "crate population mismatch")
    return seen


def package_check(root):
    """Build/check actual distributions in an exclusive project-local copy."""
    import os
    import shutil
    import time
    import traceback
    import zipfile
    from pathlib import Path

    import check

    root = Path(root)
    out = root / "target/release-evidence" / ("package-" + str(time.time_ns()))
    out.mkdir(parents=True)
    paths = [
        Path(n)
        for n in (
            "Cargo.toml",
            "Cargo.lock",
            "rust-toolchain.toml",
            "README.md",
            "LICENSE",
            "deny.toml",
            "fuzz/Cargo.lock",
            "tests/guests/programs/probe/Cargo.lock",
            "tests/guests/programs/source-lock.json",
        )
    ]
    for folder in ("crates", "packages", "scripts", "tests"):
        paths.extend(
            p.relative_to(root)
            for p in (root / folder).rglob("*")
            if p.is_file()
            and not p.is_symlink()
            and not any(
                s in ("target", "node_modules", "__pycache__") for s in p.relative_to(root).parts
            )
            # Each published crate carries its own LICENSE (no suffix).
            and (p.suffix in (".rs", ".toml", ".mjs", ".json", ".py", ".ts") or p.name == "LICENSE")
        )
    paths = sorted(set(paths))
    before = check.snapshot(root, paths)
    copy = out / "source"
    copy.mkdir()
    for path in paths:
        destination = copy / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / path, destination)
    with zipfile.ZipFile(
        out / "source-snapshot.zip", "x", compression=zipfile.ZIP_DEFLATED
    ) as archive:
        for path in paths:
            archive.writestr(path.as_posix(), (copy / path).read_bytes())
    inv = policy.inventory(copy)
    pin = tomllib.loads((copy / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    tools = list(check.rustup_toolchains().glob(pin + "-*/bin/cargo"))
    policy.require(len(tools) == 1, "one actual pinned Cargo required")
    cargo = tools[0]
    env = dict(
        os.environ,
        RUSTC=str(cargo.with_name("rustc")),
        RUSTDOC=str(cargo.with_name("rustdoc")),
        RUSTC_WRAPPER="",
        RUSTFLAGS="",
        CARGO_HOME=str(out / "cargo-home"),
        PATH=str(cargo.parent) + os.pathsep + os.environ["PATH"],
    )
    for key in ("CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_RUSTFLAGS", "CARGO_BUILD_TARGET"):
        env.pop(key, None)
    stage = "cargo-package"
    try:
        command = [
            str(cargo),
            "package",
            "--locked",
            "--allow-dirty",
            "--no-verify",
            "--workspace",
            "--exclude",
            "paludarium-harness",
            "--exclude",
            "paludarium-wasm",
        ]
        result = check.run_command(command, copy, out / "cargo-package", 900, env)
        check.require_success(result)
        archives = [
            copy / "target/package" / (n + "-" + inv["version"] + ".crate") for n in inv["order"]
        ]
        crate_result = inspect_crates(archives, inv)
        stage = "external-consumer"
        consumer = out / "consumer"
        (consumer / "src").mkdir(parents=True)
        # Registry wiring is generated below from exactly these .crate bytes.
        consumer_manifest = (
            '[package]\nname="u15-external-consumer"\nversion="0.0.0"\nedition="2024"\n[workspace]\n[dependencies]\npaludarium = { version="='
            + inv["version"]
            + '", registry="u15" }\n'
        )
        (consumer / "Cargo.toml").write_text(consumer_manifest)
        (consumer / "src/main.rs").write_text(
            "fn main() { let _ = core::mem::size_of::<paludarium::Config>(); }\n"
        )
        with make_registry(out, archives) as registry:
            (consumer / ".cargo").mkdir()
            (consumer / ".cargo/config.toml").write_text(
                '[registries.u15]\nindex="' + registry + '"\n'
            )
            check.require_success(
                check.run_command(
                    [str(cargo), "build", "--manifest-path", str(consumer / "Cargo.toml")],
                    consumer,
                    out / "consumer-nightly",
                    900,
                    env,
                )
            )
            stable = list(check.rustup_toolchains().glob("1.99.1-*/bin/cargo"))
            policy.require(len(stable) == 1, "actual verified stable1.99.1 Cargo required")
            stableenv = dict(
                env,
                RUSTC=str(stable[0].with_name("rustc")),
                RUSTDOC=str(stable[0].with_name("rustdoc")),
            )
            stable_result = check.run_command(
                [
                    str(stable[0]),
                    "build",
                    "--manifest-path",
                    str(consumer / "Cargo.toml"),
                    "--target-dir",
                    str(out / "stable-target"),
                ],
                consumer,
                out / "consumer-stable",
                900,
                stableenv,
            )
        stage = "production-wasm"
        env["RUSTFLAGS"] = (
            "-C target-feature=+atomics,+bulk-memory,+mutable-globals -C link-arg=--import-memory -C link-arg=--shared-memory -C link-arg=--max-memory=1073741824 -C link-arg=--export=__stack_pointer -C link-arg=--export=__wasm_init_tls -C link-arg=--export=__tls_size -C link-arg=--export=__tls_align -C link-arg=--export=__tls_base"
        )
        check.require_success(
            check.run_command(
                [
                    str(cargo),
                    "build",
                    "--locked",
                    "-Z",
                    "build-std=std,panic_abort",
                    "--release",
                    "--target",
                    "wasm32-unknown-unknown",
                    "-p",
                    "paludarium-wasm",
                ],
                copy,
                out / "wasm-build",
                900,
                env,
            )
        )
        wasm = copy / "target/wasm32-unknown-unknown/release/paludarium_wasm.wasm"
        shutil.copyfile(wasm, copy / "packages/paludarium-wasm/paludarium.wasm")
        for name in ("README.md", "LICENSE"):
            shutil.copyfile(root / name, copy / "packages/paludarium-wasm" / name)
        stage = "npm"
        node = Path(
            os.environ.get(
                "PALUDARIUM_TEST_NODE",
                "/Users/mutoakio/.local/share/mise/installs/node/26.12.0/bin/node",
            )
        )
        npm = Path(
            os.environ.get(
                "PALUDARIUM_RELEASE_NPM",
                str(
                    Path.home()
                    / ".local/share/mise/installs/npm-npm/12.2.0/node_modules/.mise/npm@12.2.0/node_modules/npm/bin/npm-cli.js"
                ),
            )
        )
        npmenv = dict(os.environ, PATH=str(node.parent) + os.pathsep + os.environ["PATH"])
        module_script = 'const fs=require("node:fs");const m=new WebAssembly.Module(fs.readFileSync(process.argv[1]));const names=WebAssembly.Module.exports(m).map(x=>x.name);if(names.some(n=>/^(cost|micro|length)_/.test(n)))throw Error("diagnostic exports in release");console.log(JSON.stringify({diagnosticExports:0,exports:names.length}));'
        check.require_success(
            check.run_command(
                [str(node), "-e", module_script, str(wasm)],
                copy,
                out / "normal-module-exports",
                30,
                npmenv,
            )
        )
        check.require_success(
            check.run_command(
                [
                    str(node),
                    str(npm),
                    "pack",
                    "--json",
                    "--ignore-scripts",
                    "--pack-destination",
                    str(out),
                    "--cache",
                    str(out / "npm-cache"),
                ],
                copy / "packages/paludarium-wasm",
                out / "npm-pack",
                120,
                npmenv,
            )
        )
        tarballs = list(out.glob("*.tgz"))
        policy.require(len(tarballs) == 1, "one npm tarball required")
        source_hash = sha(json.dumps(before, sort_keys=True).encode())
        head = os.environ.get("GITHUB_SHA", "local:" + source_hash)
        expected = dict(
            version=inv["version"],
            head=head,
            source_sha256=source_hash,
            tar_sha256=sha(tarballs[0].read_bytes()),
            wasm_sha256=sha(wasm.read_bytes()),
            source_files={
                n: sha((copy / "packages/paludarium-wasm" / n).read_bytes()) for n in REQUIRED_JS
            },
        )
        npm_result = inspect_npm(tarballs[0], expected)
        packed_cases = packed_checks(root, out, tarballs[0], node, npmenv)
        result = dict(
            passed=True,
            output=str(out),
            head=head,
            local_snapshot="GITHUB_SHA" not in os.environ,
            source_sha256=source_hash,
            crates=crate_result,
            npm=npm_result,
            packed_cases=packed_cases,
            stable_supported=stable_result["exit"] == 0,
            published=False,
        )
        return result
    except BaseException as error:
        with (out / "failure.json").open("x") as f:
            json.dump(
                dict(stage=stage, error=str(error), traceback=traceback.format_exc()), f, indent=2
            )
        raise
    finally:
        after = check.snapshot(root, paths)
        with (out / "source.json").open("x") as f:
            json.dump(dict(before=before, after=after), f, indent=2)
        policy.require(before == after, "original source/locks changed during packaging")


@contextlib.contextmanager
def make_registry(out, archives):
    import functools
    import http.server
    import shutil
    import threading

    directory = out / "registry"
    (directory / "index").mkdir(parents=True)

    class Handler(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *args):
            pass

    handler = functools.partial(Handler, directory=str(directory))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    base = "http://127.0.0.1:" + str(server.server_address[1])
    (directory / "index/config.json").write_text(
        json.dumps(dict(dl=base + "/crates/{crate}/{version}/download"))
    )
    for archive in archives:
        prefix = archive.name[:-6]
        files = members(archive, prefix)
        m = tomllib.loads(files["Cargo.toml"].decode())
        p = m["package"]
        deps = []
        tables = [
            (None, "normal", m.get("dependencies", {})),
            (None, "build", m.get("build-dependencies", {})),
        ]
        for target, data in m.get("target", {}).items():
            tables.extend(
                [
                    (target, "normal", data.get("dependencies", {})),
                    (target, "build", data.get("build-dependencies", {})),
                ]
            )
        for target, kind, table in tables:
            for alias, data in table.items():
                data = {"version": data} if isinstance(data, str) else data
                name = data.get("package", alias)
                row = dict(
                    name=alias,
                    req=data["version"],
                    features=data.get("features", []),
                    optional=data.get("optional", False),
                    default_features=data.get("default-features", True),
                    target=target,
                    kind=kind,
                    registry=None
                    if name in policy.PUBLIC
                    else "https://github.com/rust-lang/crates.io-index",
                )
                if name != alias:
                    row["package"] = name
                deps.append(row)
        name = p["name"]
        index = directory / "index" / name[:2] / name[2:4] / name
        index.parent.mkdir(parents=True, exist_ok=True)
        index.write_text(
            json.dumps(
                dict(
                    name=name,
                    vers=p["version"],
                    deps=deps,
                    cksum=sha(archive.read_bytes()),
                    features={},
                    features2=m.get("features", {}),
                    v=2,
                    yanked=False,
                    rust_version=p.get("rust-version"),
                )
            )
            + "\n"
        )
        dest = directory / "crates" / name / p["version"] / "download"
        dest.parent.mkdir(parents=True)
        shutil.copyfile(archive, dest)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield "sparse+" + base + "/index/"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        policy.require(not thread.is_alive(), "local registry did not stop")
        with (out / "registry-cleanup.json").open("x") as f:
            json.dump(dict(closed=True, loopback_only=True, uploaded=False), f)


def packed_checks(root, out, tarball, node, env):
    import shutil

    import check

    files = members(tarball, "package")
    extracted = out / "npm-extracted"
    extracted.mkdir()
    for name, raw in files.items():
        p = extracted / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(raw)
    guest = root / "packages/paludarium-wasm/tests/guests/hello"
    fixed = json.loads((root / "packages/paludarium-wasm/tests/guest-hashes.json").read_bytes())[
        "hello"
    ]
    policy.require(sha(guest.read_bytes()) == fixed, "hello guest changed")
    child = root / "packages/paludarium-wasm/tests/packed-distribution-child.mjs"
    result = [
        "production wasm and fixed hello provenance",
        "all packed relative JS dependencies exist",
    ]
    for mode in ("import", "hello", "invalid"):
        r = check.run_command(
            [str(node), str(child), str(extracted), str(guest), mode],
            root,
            out / ("packed-" + mode),
            40,
            env,
        )
        check.require_success(r)
        text = (out / ("packed-" + mode) / "stdout.bin").read_text()
        policy.require(
            ("packed import PASS" if mode == "import" else "packed dispose PASS") in text,
            "packed check result missing",
        )
        result.append(mode)
    missing = out / "npm-missing"
    shutil.copytree(extracted, missing)
    (missing / "jit-support.mjs").unlink()
    r = check.run_command(
        [str(node), str(child), str(missing), str(guest), "import"],
        root,
        out / "packed-missing",
        40,
        env,
    )
    policy.require(
        r["exit"] != 0
        and not r["timeout"]
        and "ERR_MODULE_NOT_FOUND" in (out / "packed-missing/stderr.bin").read_text(),
        "missing JS was not rejected",
    )
    result.append("missing JS rejected")
    corrupt = out / "npm-corrupt"
    shutil.copytree(extracted, corrupt)
    (corrupt / "paludarium.wasm").write_bytes(b"I")
    r = check.run_command(
        [str(node), str(child), str(corrupt), str(guest), "corrupt"],
        root,
        out / "packed-corrupt",
        40,
        env,
    )
    check.require_success(r)
    policy.require(
        "corrupt wasm rejected PASS" in (out / "packed-corrupt/stdout.bin").read_text(),
        "corrupt Wasm result absent",
    )
    result.append("corrupt Wasm rejected")
    policy.require(len(result) == 7, "packed case population changed")
    return result
