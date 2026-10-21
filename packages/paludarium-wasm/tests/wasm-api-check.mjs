import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { createPaludarium } from "../index.mjs";
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
  const large = await first.createFileSystem({ files: {
    "/large-a": new Uint8Array(34 * 1024 * 1024),
    "/large-b": new Uint8Array(34 * 1024 * 1024),
  } });
  await assert.rejects(large.snapshot(), /snapshot/);
  await Promise.all([large.dispose(), large.dispose()]); await large.dispose();
  await assert.rejects(large.snapshot(), /disposed/);
  assert.throws(() => first.run({ program: "/file", filesystem }), /another launcher/);
  assert.throws(() => first.run({ program: "/file", tty: { columns: -1, rows: 24 } }), /terminal/);
  assert.throws(() => first.run({ program: "/file", cwd: "relative" }), /current directory/);
  assert.throws(() => first.run({ program: "/file", files: { "/file": new Uint8Array() }, fileModes: { "/file": 65536 } }), /modes/);
  const drainFailure = async stream => { const reader = stream.getReader(); try { while (!(await reader.read()).done) {} } catch {} finally { reader.releaseLock(); } };
  const invalid = first.run({ program: "/bad", files: { "/bad": new Uint8Array([73]) } });
  const invalidStreams = Promise.all([drainFailure(invalid.stdout), drainFailure(invalid.stderr)]);
  await assert.rejects(invalid.exited, error => error.kind === "invalid-program"); await invalidStreams;
  const hello = new Uint8Array(await readFile(new URL("guests/hello", import.meta.url)));
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
  console.log("wasm API: modes, ownership, concurrent disposal, large FS, busy rejection/retry, terminal validation, kill/release PASS");
} finally { clearTimeout(deadline); await first.dispose(); await second.dispose(); }
