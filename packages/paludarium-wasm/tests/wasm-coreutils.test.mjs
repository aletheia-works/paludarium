import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readCoreutilsFixture } from "./coreutils-fixture.mjs";
import { fileDigests, observeCoreutils } from "./wasm-programs.mjs";

const text = value => new TextEncoder().encode(value);
const sha = value => createHash("sha256").update(value).digest("hex");
const file = (path, content) => ({ path, mode: 0o100644, content: text(content) });
const link = (path, target) => ({ path, mode: 0o120777, content: text(target) });

test("file digests list regular files and followed symlinks as Linux's snapshot does", async () => {
  const root = "/w/case";
  const entries = [
    { path: root, mode: 0o040755, content: new Uint8Array() },
    { path: root + "/app", mode: 0o040755, content: new Uint8Array() },
    file(root + "/app/b.txt", "b"),
    file(root + "/app/a.txt", "a"),
    link(root + "/app/link.txt", "a.txt"),
    link(root + "/app/up.txt", "../outside/far.txt"),
    link(root + "/app/chain.txt", "link.txt"),
    link(root + "/app/dangling.txt", "missing.txt"),
    link(root + "/app/loop.txt", "loop.txt"),
    file(root + "/outside/far.txt", "far"),
    file("/w/case-other/app/x.txt", "x"),
    file("/coreutils", "elf"),
  ];
  assert.deepEqual(await fileDigests(entries, root), {
    "app/a.txt": sha("a"), "app/b.txt": sha("b"), "app/chain.txt": sha("a"), "app/link.txt": sha("a"),
    "app/up.txt": sha("far"), "outside/far.txt": sha("far"),
  });
  assert.deepEqual(Object.keys(await fileDigests(entries, root)), ["app/a.txt", "app/b.txt", "app/chain.txt", "app/link.txt", "app/up.txt", "outside/far.txt"]);
});

test("the fixture is read with forward-slash paths in sorted order", async () => {
  const fixture = await readCoreutilsFixture();
  assert.ok(Object.keys(fixture).includes("app/docs/notes.txt"));
  assert.ok(Object.keys(fixture).includes("outside/far.txt"));
  assert.deepEqual(Object.keys(fixture), [...Object.keys(fixture)].sort());
});

function fakeLauncher(results, seen) {
  return async () => ({
    async createFileSystem(options) {
      seen.filesystems.push(options);
      return { async snapshot() { return results.snapshot ?? []; }, async dispose() { seen.disposed += 1; } };
    },
    run(options) {
      seen.runs.push(options);
      const out = results.rows[seen.runs.length - 1];
      const stream = value => new ReadableStream({ start(controller) { if (value) controller.enqueue(text(value)); controller.close(); } });
      return {
        stdin: new WritableStream({ write(chunk) { seen.stdin.push(new TextDecoder().decode(chunk)); } }),
        stdout: stream(out.stdout), stderr: stream(out.stderr), exited: Promise.resolve({ kind: "exited", code: out.exit }), kill() {},
      };
    },
    async dispose() { seen.launchersDisposed += 1; },
  });
}

test("each case gets a fresh filesystem, its stdin and environment, and exact comparison", async () => {
  const cases = [
    { name: "upper", args: ["tr", "a-z", "A-Z"], stdin: "in.txt", env: { TZ: "JST-9" } },
    { name: "touch", args: ["touch", "new.txt"], writes: true },
    { name: "wrong", args: ["cat", "in.txt"] },
  ];
  const fixture = { "app/in.txt": text("abc\n") };
  const oracle = {
    fixture_root: "/n", guest_environment: { HOME: "/n/home", TMPDIR: "/n/tmp", LANG: "C" },
    coreutils: { rows: {
      upper: { exit: 0, stdout: "ABC\n", stderr: "", timed_out: false },
      touch: { exit: 0, stdout: "", stderr: "", timed_out: false, filesystem: { "app/new.txt": sha(""), "app/in.txt": sha("abc\n") } },
      wrong: { exit: 0, stdout: "abc\n", stderr: "", timed_out: false },
    } },
  };
  const seen = { filesystems: [], runs: [], stdin: [], disposed: 0, launchersDisposed: 0 };
  const results = {
    rows: [{ exit: 0, stdout: "ABC\n" }, { exit: 0 }, { exit: 0, stdout: "abd\n" }],
    snapshot: [file("/n/coreutils/touch/app/in.txt", "abc\n"), file("/n/coreutils/touch/app/new.txt", "")],
  };
  const named = [];
  const rows = await observeCoreutils(fakeLauncher(results, seen), { coreutils: text("elf"), cases, oracle, fixture, onRow: (name, row, group) => named.push([name, group]) });
  assert.deepEqual(named, [["upper", "coreutils"], ["touch", "coreutils"], ["wrong", "coreutils"]]);
  assert.equal(rows.upper.pass, true);
  assert.equal(rows.touch.pass, true);
  assert.equal(rows.wrong.pass, false);
  assert.match(rows.wrong.comparison_error, /stdout mismatch/);
  assert.deepEqual(seen.stdin, ["abc\n"]);
  assert.equal(seen.filesystems.length, 3); assert.equal(seen.disposed, 3); assert.equal(seen.launchersDisposed, 1);
  assert.deepEqual(Object.keys(seen.filesystems[0].files).sort(), ["/coreutils", "/n/coreutils/upper/app/in.txt", "/n/home/.keep", "/n/tmp/.keep"]);
  assert.deepEqual(seen.runs[0].args, ["/coreutils", "tr", "a-z", "A-Z"]);
  assert.equal(seen.runs[0].program, "/coreutils");
  assert.equal(seen.runs[0].cwd, "/n/coreutils/upper/app");
  assert.equal(seen.runs[0].env.TZ, "JST-9"); assert.equal(seen.runs[0].env.LANG, "C");
  assert.equal("stdin" in seen.runs[0], false);
});

test("a filesystem difference or a changed inventory fails", async () => {
  const cases = [{ name: "touch", args: ["touch", "new.txt"], writes: true }];
  const oracle = { fixture_root: "/n", guest_environment: { HOME: "/h", TMPDIR: "/t" }, coreutils: { rows: { touch: { exit: 0, stdout: "", stderr: "", timed_out: false, filesystem: { "app/new.txt": sha("") } } } } };
  const seen = { filesystems: [], runs: [], stdin: [], disposed: 0, launchersDisposed: 0 };
  const rows = await observeCoreutils(fakeLauncher({ rows: [{ exit: 0 }], snapshot: [] }, seen), { coreutils: text("elf"), cases, oracle, fixture: {} });
  assert.equal(rows.touch.pass, false); assert.match(rows.touch.comparison_error, /filesystem mismatch/);
  await assert.rejects(observeCoreutils(fakeLauncher({ rows: [] }, seen), { coreutils: text("elf"), cases: [{ name: "other", args: [] }], oracle, fixture: {} }), /inventory/);
  await assert.rejects(observeCoreutils(fakeLauncher({ rows: [] }, seen), { coreutils: text("elf"), cases, oracle: { ...oracle, coreutils: undefined }, fixture: {} }), /required/);
});
