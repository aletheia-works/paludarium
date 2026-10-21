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
