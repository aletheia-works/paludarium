import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { loadBytes, loadGuests, loadJson } from "./wasm-browser-load.mjs";
import { guestName, serveInputs } from "./wasm-browser-guests.mjs";

const headers = { "Cache-Control": "no-store" };
const guests = { probe: Buffer.from("probe bytes"), big: Buffer.alloc(3 * 1024 * 1024, 7) };
const input = Buffer.from(JSON.stringify({ oracle: { rows: {} } }));

async function serve(t, handler) {
  const server = createServer(handler);
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise(resolve => { server.closeAllConnections(); server.close(resolve); }));
  const base = `http://127.0.0.1:${server.address().port}`;
  return path => fetch(base + path);
}
const inputs = t => serve(t, (request, response) => { if (!serveInputs(request, response, headers, input, guests)) response.writeHead(418).end(); });

test("guest URLs name only the served guests", () => {
  assert.equal(guestName("/guest/probe", guests), "probe");
  assert.equal(guestName("/guest/other", guests), "");
  assert.equal(guestName("/guest/constructor", guests), "");
  assert.equal(guestName("/guest/probe/x", guests), null);
  assert.equal(guestName("/input.json", guests), null);
});

test("each guest arrives raw and whole, and input.json as JSON, with Content-Length", async t => {
  const get = await inputs(t);
  const response = await get("/guest/big");
  assert.equal(response.headers.get("content-type"), "application/octet-stream");
  assert.equal(response.headers.get("content-length"), String(guests.big.length));
  await response.arrayBuffer();
  const loaded = await loadGuests(["probe", "big"], get);
  assert.deepEqual(Buffer.from(loaded.probe), guests.probe);
  assert.deepEqual(Buffer.from(loaded.big), guests.big);
  assert.deepEqual(await loadJson("/input.json", get), { oracle: { rows: {} } });
  assert.equal((await get("/elsewhere")).status, 418);
});

test("a guest that is not served fails with its file, status and byte count", async t => {
  const get = await inputs(t);
  await assert.rejects(loadGuests(["probe", "other"], get), /^Error: \/guest\/other: status 404 after 0 of (\d+|unknown) bytes, \d+ ms after the request \(at \d+ ms\): no guest \/guest\/other$/);
});

test("a body cut short names the file and how many of its bytes came", async t => {
  const get = await serve(t, (request, response) => {
    response.writeHead(200, { "Content-Length": 100 });
    response.write(Buffer.alloc(10), () => setTimeout(() => response.socket.destroy(), 20));
  });
  await assert.rejects(loadBytes("/guest/aube", get), error => {
    assert.match(error.message, /^\/guest\/aube: body failed after 10 of 100 bytes, \d+ ms after the request/);
    return true;
  });
});

test("a server-side cut is logged with the file, its size and the bytes queued", async t => {
  const logged = [], error = console.error;
  console.error = line => logged.push(JSON.parse(line));
  t.after(() => { console.error = error; });
  let closed;
  const done = new Promise(resolve => { closed = resolve; });
  const get = await serve(t, (request, response) => {
    serveInputs(request, response, headers, input, guests);
    response.once("close", () => setImmediate(closed));
    setImmediate(() => response.socket.destroy());
  });
  await loadBytes("/guest/big", get).catch(() => {});
  await done;
  assert.equal(logged.length, 1);
  assert.equal(logged[0].response_cut, "guest/big");
  assert.equal(logged[0].bytes, guests.big.length);
  assert.ok(Number.isInteger(logged[0].bytes_queued));
});

test("a request that fails names the file", async () => {
  await assert.rejects(loadJson("/input.json", async () => { throw new TypeError("Load failed"); }), /^Error: \/input\.json: request failed after 0 of unknown bytes, .*: TypeError: Load failed$/);
});
