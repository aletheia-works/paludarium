import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { createPaludarium } from "../index.mjs";
import { checkEntries, TREE } from "./wasm-entries.mjs";
const [modulePath] = process.argv.slice(2);
if (!modulePath) throw new Error("usage: wasm-api-check.mjs module");
const wasmUrl = pathToFileURL(resolve(modulePath));
const first = await createPaludarium({ wasmUrl }), second = await createPaludarium({ wasmUrl });
const deadline = setTimeout(() => { console.error("wasm API test deadline"); process.exit(1); }, 30000);
try {
  const filesystem = await first.createFileSystem({ files: { "/file": new Uint8Array([73]) }, fileModes: { "/file": 0o644 } });
  assert.equal((await filesystem.snapshot()).find(entry => entry.path === "/file").mode, 0o100644);
  assert.throws(() => second.run({ program: "/file", filesystem }), /another launcher/);
  await assert.rejects(filesystem.remove("/", { recursive: true }), /removal/);
  await filesystem.remove("/file"); assert.equal((await filesystem.snapshot()).some(entry => entry.path === "/file"), false);
  await Promise.all([filesystem.dispose(), filesystem.dispose()]); await filesystem.dispose();
  await assert.rejects(filesystem.snapshot(), /disposed/);
  // A snapshot holds at most 272 MiB; `files` themselves have no total limit.
  const large = await first.createFileSystem({ files: {
    "/large-a": new Uint8Array(100 * 1024 * 1024),
    "/large-b": new Uint8Array(100 * 1024 * 1024),
    "/large-c": new Uint8Array(100 * 1024 * 1024),
  } });
  await assert.rejects(large.snapshot(), /snapshot/);
  await Promise.all([large.dispose(), large.dispose()]); await large.dispose();
  await assert.rejects(large.snapshot(), /disposed/);
  assert.throws(() => first.run({ program: "/file", filesystem }), /another launcher/);
  assert.throws(() => first.run({ program: "/file", tty: { columns: -1, rows: 24 } }), /terminal/);
  assert.throws(() => first.run({ program: "/file", cwd: "relative" }), /current directory/);
  assert.throws(() => first.run({ program: "/file", files: { "/file": new Uint8Array() }, fileModes: { "/file": 65536 } }), /modes/);
  for (const limits of [null, 1, { tasks: 0 }, { tasks: 1.5 }, { tasks: 2 ** 32 }, { openFiles: -1 }, { openFiles: 1048577 }])
    assert.throws(() => first.run({ program: "/file", limits }), /limits/, JSON.stringify(limits));
  const drainFailure = async stream => { const reader = stream.getReader(); try { while (!(await reader.read()).done) {} } catch {} finally { reader.releaseLock(); } };
  const invalid = first.run({ program: "/bad", files: { "/bad": new Uint8Array([73]) } });
  const invalidStreams = Promise.all([drainFailure(invalid.stdout), drainFailure(invalid.stderr)]);
  await assert.rejects(invalid.exited, error => error.kind === "invalid-program"); await invalidStreams;
  const hello = new Uint8Array(await readFile(new URL("guests/hello", import.meta.url)));
  // Limits reach the guest: a fork fails with EAGAIN (11) and an open with
  // EMFILE (24); each program exits with the negated result.
  const elf = code => {
    const bytes = new Uint8Array(120 + code.length), view = new DataView(bytes.buffer);
    bytes.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]);
    view.setUint16(16, 2, true); view.setUint16(18, 62, true); view.setUint32(20, 1, true);
    view.setBigUint64(24, 0x400078n, true); view.setBigUint64(32, 64n, true);
    view.setUint16(52, 64, true); view.setUint16(54, 56, true); view.setUint16(56, 1, true);
    view.setUint32(64, 1, true); view.setUint32(68, 5, true);
    view.setBigUint64(80, 0x400000n, true); view.setBigUint64(88, 0x400000n, true);
    view.setBigUint64(96, BigInt(bytes.length), true); view.setBigUint64(104, BigInt(bytes.length), true);
    view.setBigUint64(112, 0x1000n, true);
    bytes.set(code, 120);
    return bytes;
  };
  const exitNegated = [0xf7, 0xd8, 0x89, 0xc7, 0xb8, 60, 0, 0, 0, 0x0f, 0x05];
  const fork = elf([0xb8, 57, 0, 0, 0, 0x0f, 0x05, ...exitNegated]);
  const open = elf([0x48, 0x8d, 0x3d, 20, 0, 0, 0, 0x31, 0xf6, 0xb8, 2, 0, 0, 0, 0x0f, 0x05, ...exitNegated, 0x2f, 0x70, 0]);
  for (const [program, limits, code] of [[fork, { tasks: 1 }, 11], [open, { openFiles: 3 }, 24]]) {
    const limited = first.run({ program: "/p", files: { "/p": program }, limits });
    await Promise.all([new Response(limited.stdout).text(), new Response(limited.stderr).text()]);
    assert.deepEqual(await limited.exited, { kind: "exited", code }, JSON.stringify(limits));
  }
  for (const cwd of ["/missing", "/hello"]) {
    const invalidCwd = first.run({ program: "/hello", files: { "/hello": hello }, cwd });
    const outputs = Promise.all([drainFailure(invalidCwd.stdout), drainFailure(invalidCwd.stderr)]);
    await assert.rejects(invalidCwd.exited, error => error.kind === "invalid-program"); await outputs;
  }
  const infinite = new Uint8Array(await readFile(new URL("guests/infinite", import.meta.url)));
  const active = await first.createFileSystem({ files: { "/infinite": infinite } });
  const guest = first.run({ program: "/infinite", filesystem: active, tty: { columns: 0, rows: 65535 } });
  const drain = async stream => { const reader = stream.getReader(); while (!(await reader.read()).done) {} };
  const streams = Promise.all([drain(guest.stdout), drain(guest.stderr)]);
  await assert.rejects(active.snapshot(), /active/); await assert.rejects(active.remove("/infinite"), /removal/);
  const busyDisposals = await Promise.allSettled([active.dispose(), active.dispose()]);
  assert.ok(busyDisposals.every(result => result.status === "rejected" && /active/.test(result.reason.message)));
  guest.kill(); assert.equal((await guest.exited).kind, "signaled"); await streams;
  await active.snapshot(); await Promise.all([active.dispose(), active.dispose()]); await active.dispose();
  assert.deepEqual(await checkEntries(first), { entries: TREE.length, rebuilt: true });
  const dir = path => ({ path, mode: 0o040755 }), file = (path, extra = {}) => ({ path, mode: 0o100644, content: new Uint8Array([1]), ...extra });
  const rejected = [
    ["not an array", { "/a": dir("/a") }, /must be an array/], ["not an object", [null], /not an object/],
    ["relative", [file("a")], /not absolute/], ["NUL", [file("/a\0")], /not absolute/],
    ["dot-dot", [file("/a/../b")], /not normalized/], ["empty part", [file("//a")], /not normalized/], ["trailing slash", [file("/a/")], /not normalized/], ["dot", [file("/./a")], /not normalized/],
    ["long path", [file("/" + "a/".repeat(2048) + "a")], /too long/], ["long name", [file("/" + "a".repeat(256))], /too long/],
    ["duplicate", [file("/a"), dir("/a")], /duplicate/], ["missing parent", [file("/a/b")], /parent/], ["file parent", [file("/a"), file("/a/b")], /parent/],
    ["symlink parent", [dir("/d"), { path: "/s", mode: 0o120777, content: new Uint8Array([100]) }, file("/s/f")], /parent/],
    ["root as a file", [file("/")], /is a directory/], ["tmp as a file", [file("/tmp")], /is a directory/],
    ["device", [{ path: "/c", mode: 0o020644 }], /mode/], ["mode range", [{ path: "/a", mode: 0o200644 }], /mode/], ["fractional mode", [{ path: "/a", mode: 0.5 }], /mode/],
    ["content type", [file("/a", { content: [1] })], /Uint8Array/], ["directory content", [{ ...dir("/d"), content: new Uint8Array([1]) }], /directory has content/],
    ["symlink mode", [{ path: "/s", mode: 0o120755, content: new Uint8Array([97]) }], /symlink/], ["empty symlink", [{ path: "/s", mode: 0o120777 }], /symlink/],
    ["symlink NUL", [{ path: "/s", mode: 0o120777, content: new Uint8Array([97, 0]) }], /symlink/], ["long symlink", [{ path: "/s", mode: 0o120777, content: new Uint8Array(4096).fill(97) }], /symlink/],
    ["mtime type", [file("/a", { mtimeNs: 1.5 })], /mtimeNs/], ["mtime range", [file("/a", { mtimeNs: 1n << 127n })], /mtimeNs/],
    ["inode type", [file("/a", { inode: "1" })], /inode/], ["links type", [file("/a", { links: -0.5 })], /links/],
    ["linked directories", [{ ...dir("/d"), inode: 1n }, { ...dir("/e"), inode: 1n }], /names a directory/],
    ["mixed link kinds", [file("/a", { inode: 1n }), { path: "/s", mode: 0o120777, content: new Uint8Array([1]), inode: 1n }], /another kind/],
    ["link mode", [file("/a", { inode: 1n }), file("/b", { inode: 1n, mode: 0o100600 })], /differ/], ["link time", [file("/a", { inode: 1n }), file("/b", { inode: 1n, mtimeNs: 1n })], /differ/],
    ["link content", [file("/a", { inode: 1n }), file("/b", { inode: 1n, content: new Uint8Array([2]) })], /differ/],
  ];
  for (const [name, entries, pattern] of rejected) await assert.rejects(first.createFileSystem({ entries }), error => error.kind === "invalid-program" && pattern.test(error.message), name);
  await assert.rejects(first.createFileSystem({ entries: Array.from({ length: 1048577 }, (_, index) => file("/" + index)) }), /1048576 entries/);
  const sixty = new Uint8Array(60 * 1024 * 1024);
  await assert.rejects(first.createFileSystem({ entries: [file("/a", { content: new Uint8Array(128 * 1024 * 1024 + 1) })] }), /larger than 128 MiB/);
  // One file past the old 64 MiB limit, such as an 83.5 MB biome, goes in and
  // comes back whole.
  const big = new Uint8Array(100 * 1024 * 1024); big[big.length - 1] = 7;
  const bigFs = await first.createFileSystem({ entries: [file("/big", { content: big })] });
  const bigEntry = (await bigFs.snapshot()).find(entry => entry.path === "/big");
  assert.equal(bigEntry.content.length, big.length); assert.equal(bigEntry.content[big.length - 1], 7);
  await bigFs.dispose();
  // Creation counts a hard-link group once, a snapshot writes each link: three
  // links to 100 MiB are accepted, but their 300 MiB snapshot is refused.
  const manyLinks = await first.createFileSystem({ entries: ["/l1", "/l2", "/l3"].map(path => file(path, { inode: 9n, content: big })) });
  await assert.rejects(manyLinks.snapshot(), /snapshot/);
  await manyLinks.dispose();
  await assert.rejects(first.createFileSystem({ entries: Array.from({ length: 5 }, (_, index) => file("/" + index, { content: sixty })) }), /256 MiB/);
  await assert.rejects(first.createFileSystem({ files: { "/x/./f": new Uint8Array() }, entries: [file("/x/f")] }), /duplicate/);
  await assert.rejects(first.createFileSystem({ files: { "/x/f": new Uint8Array() }, entries: [file("/x")] }), /is a directory/);
  // A hard link group counts its content once; the parents of `files` are directories.
  await (await first.createFileSystem({ entries: Array.from({ length: 5 }, (_, index) => file("/" + index, { inode: 1n, content: sixty })) })).dispose();
  const combined = await first.createFileSystem({ files: { "/bin/hello": hello }, entries: [{ ...dir("/bin"), mode: 0o040700 }, file("/bin/a", { inode: 1n }), file("/bin/b", { inode: 1n })] });
  const combinedEntries = await combined.snapshot();
  assert.equal(combinedEntries.find(entry => entry.path === "/bin").mode, 0o040700);
  assert.equal(combinedEntries.find(entry => entry.path === "/bin/b").links, 2n);
  assert.throws(() => first.run({ program: "/bin/hello", filesystem: combined, entries: [] }), /only to a new filesystem/);
  await combined.dispose();
  const readAll = async stream => { let text = ""; const reader = stream.getReader(), decoder = new TextDecoder(); for (let chunk; !(chunk = await reader.read()).done;) text += decoder.decode(chunk.value); return text; };
  const linked = first.run({ program: "/bin/again", entries: [dir("/bin"), { path: "/bin/hello", mode: 0o100755, content: hello, inode: 1n }, { path: "/bin/again", mode: 0o100755, content: hello, inode: 1n }] });
  linked.stdin.close();
  const [linkedOutput] = await Promise.all([readAll(linked.stdout), readAll(linked.stderr)]);
  assert.deepEqual(await linked.exited, { kind: "exited", code: 0 }); assert.ok(linkedOutput.length > 0);
  const diagnostics = await first.diagnostics();
  const probe = diagnostics.sharedProbe;
  assert.equal(probe.value, "2000");
  assert.equal(probe.allocations.length, 2);
  assert.ok(probe.allocations.every(row => row.allocations === 128 && row.atomicAdds === 1000));
  assert.equal(probe.workers.length, 2);
  assert.equal(probe.notified, 1); assert.equal(probe.waited, 0);
  assert.equal(new Set(probe.workers.map(worker => worker.threadToken)).size, 2);
  assert.equal(new Set(probe.workers.map(worker => worker.tlsAfter)).size, 2);
  assert.ok(probe.workers.every(worker => worker.token === 73 && worker.tlsAfter > 0));
  console.log("wasm API: modes, entries round trip and validation, ownership, concurrent disposal, large FS, busy rejection/retry, terminal validation, kill/release PASS");
} finally { clearTimeout(deadline); await first.dispose(); await second.dispose(); }
