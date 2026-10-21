import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, request } from "node:http";
import { once } from "node:events";
import { createJitHandler } from "./jit-http.mjs";

async function withServer(t, overrides = {}) {
  const handler = createJitHandler({ root: process.cwd(), modulePath: "production.wasm", page: "page", encoded: { ok: true }, oracle: { rows: { probe: {} } }, onRow: async () => {}, ...overrides });
  const server = createServer(handler);
  server.listen(0, "127.0.0.1"); await once(server, "listening");
  t.after(() => new Promise(resolve => { server.closeAllConnections(); server.close(resolve); }));
  return `http://127.0.0.1:${server.address().port}`;
}

test("page and input retain isolation headers", async t => {
  const url = await withServer(t);
  for (const path of ["/", "/input.json"]) {
    const response = await fetch(url + path);
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("cross-origin-embedder-policy"), "require-corp");
    assert.equal(response.headers.get("cross-origin-opener-policy"), "same-origin");
    await response.text();
  }
});
test("static bytes and wasm MIME are retained", async t => {
  const url = await withServer(t, { read: async () => Buffer.from("bytes") });
  const response = await fetch(url + "/production.wasm");
  assert.equal(response.status, 200); assert.equal(await response.text(), "bytes");
  assert.equal(response.headers.get("content-type"), "application/wasm");
});
test("missing file yields one 500 response and server survives", async t => {
  const url = await withServer(t);
  const response = await fetch(url + "/missing-regression-file");
  assert.equal(response.status, 500); assert.match(await response.text(), /ENOENT/);
  assert.equal((await fetch(url + "/")).status, 200);
});
test("concurrent missing and successful requests remain independent", async t => {
  const url = await withServer(t);
  const results = await Promise.all(Array.from({ length: 20 }, (_, i) => fetch(url + (i % 2 ? "/" : "/missing-regression-file"))));
  assert.deepEqual(results.map(r => r.status), Array.from({ length: 20 }, (_, i) => i % 2 ? 200 : 500));
  await Promise.all(results.map(r => r.text()));
});
test("valid row persists before acknowledgement", async t => {
  let saved;
  const url = await withServer(t, { onRow: async (...args) => { saved = args; } });
  const response = await fetch(url + "/row", { method: "POST", body: JSON.stringify({ mode: "jit", name: "probe", row: { pass: true } }) });
  assert.equal(response.status, 200); assert.deepEqual(saved, ["jit", "probe", { pass: true }]);
});
test("invalid rows and persistence failures finish with 500", async t => {
  const url = await withServer(t, { onRow: async () => { throw Error("persist failed"); } });
  for (const body of ["invalid", JSON.stringify({ mode: "jit", name: "other" }), JSON.stringify({ mode: "jit", name: "probe", row: {} })]) {
    const response = await fetch(url + "/row", { method: "POST", body });
    assert.equal(response.status, 500); await response.text();
  }
});
test("disconnect during pending read does not send late headers", async t => {
  let finish, started;
  const reading = new Promise(resolve => { started = resolve; });
  const url = await withServer(t, { read: () => { started(); return new Promise(resolve => { finish = resolve; }); } });
  const client = request(url + "/file.mjs"); client.on("error", () => {}); client.end();
  await reading;
  const closed = new Promise(resolve => client.once("close", resolve));
  client.destroy(); await closed;
  finish(Buffer.from("late"));
  assert.equal((await fetch(url + "/")).status, 200);
});
