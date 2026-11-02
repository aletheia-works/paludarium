import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { compareFilesystem } from "./wasm-filesystem.mjs";
const content = new TextEncoder().encode("bytes"), hash = createHash("sha256").update(content).digest("hex");
const expected = {
  ".": { kind: "directory", mode: 0o755, mtime_ns: "0" },
  "file": { kind: "file", mode: 0o644, links: 1, identity: "file", sha256: hash, content_base64: Buffer.from(content).toString("base64"), mtime_ns: "0" },
};
const actual = () => [{ path: "/fixture", mode: 0o040755, inode: 1n, links: 2n, mtimeNs: 0n, content: new Uint8Array() }, { path: "/fixture/file", mode: 0o100644, inode: 2n, links: 1n, mtimeNs: 0n, content }];
test("fixture regular bytes and metadata match", async () => assert.equal((await compareFilesystem(expected, actual(), "/fixture")).objects, 2));
test("content difference is rejected", async () => { const rows = actual(); rows[1].content = new Uint8Array([1]); await assert.rejects(compareFilesystem(expected, rows, "/fixture"), /metadata mismatch/); });
test("mode difference is rejected", async () => { const rows = actual(); rows[1].mode = 0o100755; await assert.rejects(compareFilesystem(expected, rows, "/fixture"), /metadata mismatch/); });
test("hardlink count difference is rejected", async () => { const rows = actual(); rows[1].links = 2n; await assert.rejects(compareFilesystem(expected, rows, "/fixture"), /metadata mismatch/); });
test("unexpected fixture entry is rejected", async () => { const rows = actual(); rows.push({ ...rows[1], path: "/fixture/extra" }); await assert.rejects(compareFilesystem(expected, rows, "/fixture"), /unexpected/); });
test("outside fixture observations do not masquerade as fixture", async () => { const rows = actual(); rows.push({ ...rows[1], path: "/home/cache" }); assert.equal((await compareFilesystem(expected, rows, "/fixture")).objects, 2); });
test("missing fixture entry is rejected", async () => await assert.rejects(compareFilesystem(expected, actual().slice(0, 1), "/fixture"), /metadata mismatch/));
// An aube state naming the project's package.json "." and a link: target's,
// outside the project, by its path from there, as aube 2.8.4 and later do.
const stateFixture = state => {
  const encode = text => new TextEncoder().encode(text);
  const files = { "app/package.json": encode("{}\n"), "app/aube-lock.yaml": encode("lock\n"), "outside/linked/package.json": encode("{\"name\":\"linked\"}\n") };
  const meta = path => ({ size: files[path].length, mtime_secs: 1, mtime_nanos: 2 });
  files["app/node_modules/.aube-state/state.json"] = encode(JSON.stringify(state(meta)));
  const directories = [".", "app", "app/node_modules", "app/node_modules/.aube-state", "outside", "outside/linked"];
  const expected = {}, rows = [];
  for (const path of directories) {
    expected[path] = { kind: "directory", mode: 0o755, mtime_ns: "0" };
    rows.push({ path: path === "." ? "/fixture" : "/fixture/" + path, mode: 0o040755, inode: BigInt(rows.length + 1), links: 2n, mtimeNs: 0n, content: new Uint8Array() });
  }
  for (const [path, bytes] of Object.entries(files)) {
    expected[path] = { kind: "file", mode: 0o644, links: 1, identity: path, sha256: createHash("sha256").update(bytes).digest("hex"), content_base64: Buffer.from(bytes).toString("base64"), mtime_ns: "1000000002" };
    rows.push({ path: "/fixture/" + path, mode: 0o100644, inode: BigInt(rows.length + 1), links: 1n, mtimeNs: 1000000002n, content: bytes });
  }
  return [expected, rows];
};
const linkedState = meta => ({ lockfile_snapshot_name: "aube-lock.yaml", lockfile_meta: meta("app/aube-lock.yaml"), package_json_meta: { ".": meta("app/package.json"), "../outside/linked/package.json": meta("outside/linked/package.json") } });
test("aube state names a link: target's package.json by its path", async () => { const [expected, rows] = stateFixture(linkedState); assert.equal((await compareFilesystem(expected, rows, "/fixture")).objects, 10); });
test("aube state naming a missing package.json is rejected", async () => { const [expected, rows] = stateFixture(meta => ({ ...linkedState(meta), package_json_meta: { "../outside/linked": meta("outside/linked/package.json") } })); await assert.rejects(compareFilesystem(expected, rows, "/fixture"), /state mtime\/size does not match/); });
