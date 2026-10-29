// The guest's network through the WebSocket relay (docs/guide/relay.md), as a
// browser has it, run here on Node.js: the guests of wasm-network.test.mjs
// reach a server through relay.mjs, and the relay's own allow list, tickets
// and window are checked with a WebSocket of its own.
import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:net";
import { request } from "node:http";
import { createPaludarium } from "../index.mjs";
import { PROTOCOL, WINDOW, canonicalIp } from "../relay-protocol.mjs";
import { parseRule, reachable, startRelay } from "../relay.mjs";
import { DNS, TCP, data, elf, hex, query } from "./wasm-network-guests.mjs";

async function run(runtime, program, network) {
  const guest = runtime.run({ program: "/guest", files: { "/guest": program }, network });
  const chunks = [];
  for await (const chunk of guest.stdout) chunks.push(chunk);
  const stdout = new Uint8Array(chunks.reduce((size, chunk) => size + chunk.length, 0));
  chunks.reduce((at, chunk) => { stdout.set(chunk, at); return at + chunk.length; }, 0);
  return { status: await guest.exited, stdout };
}
/** A TCP server on 127.0.0.1 that answers each connection with `handler`. */
async function server(t, handler) {
  const listener = createServer(handler);
  await new Promise(resolve => listener.listen(0, "127.0.0.1", resolve));
  t.after(() => listener.close());
  return listener.address().port;
}
async function relay(t, options) {
  const started = await startRelay({ host: "127.0.0.1", port: 0, ...options });
  t.after(() => started.close());
  return started;
}
async function launcher(t) {
  const runtime = await createPaludarium({ wasmUrl: new URL("../paludarium.wasm", import.meta.url) });
  t.after(() => runtime.dispose());
  return runtime;
}
/** The TCP guest, sending `text` to 127.0.0.1:`port`. */
function tcpGuest(port, text = "ehello") {
  const bytes = data(port);
  bytes.set(new TextEncoder().encode(text), 16);
  return elf(hex(TCP), bytes);
}
/** Echoes what follows the first byte, until the end of input. */
const echo = socket => {
  let first = true;
  socket.on("data", chunk => { socket.write(first ? chunk.subarray(1) : chunk); first = false; });
  socket.on("end", () => socket.end());
};
/** A WebSocket to the relay, with its messages queued for `next()`, which gives undefined after `timeout` ms. */
async function client(url, protocols) {
  const ws = new WebSocket(url, protocols);
  ws.binaryType = "arraybuffer";
  const queue = [], waiting = [];
  const push = item => { const wake = waiting.shift(); if (wake) wake(item); else queue.push(item); };
  ws.addEventListener("message", event => push(typeof event.data === "string" ? JSON.parse(event.data) : new Uint8Array(event.data)));
  ws.addEventListener("close", event => push({ closed: event.code }));
  await new Promise((resolve, reject) => { ws.addEventListener("open", resolve); ws.addEventListener("error", reject); });
  const next = timeout => {
    if (queue.length) return Promise.resolve(queue.shift());
    return new Promise(resolve => {
      const wake = item => { clearTimeout(timer); resolve(item); };
      const timer = timeout === undefined ? undefined : setTimeout(() => { waiting.splice(waiting.indexOf(wake), 1); resolve(undefined); }, timeout);
      waiting.push(wake);
    });
  };
  return { ws, next, send: value => ws.send(typeof value === "object" && !(value instanceof Uint8Array) ? JSON.stringify(value) : value) };
}

test("a guest reaches through the relay what both allow lists name", async (t) => {
  const port = await server(t, echo), other = await server(t, echo);
  const { url } = await relay(t, { allow: [`127.0.0.1:${port}`] });
  const runtime = await launcher(t);
  const reached = await run(runtime, tcpGuest(port), { allow: [`127.0.0.1:${port}`], relay: { url } });
  assert.deepEqual(reached.status, { kind: "exited", code: 0 });
  assert.equal(new TextDecoder().decode(reached.stdout), "hello");
  // The kernel's allow list has the last word, and the relay's its own.
  assert.deepEqual((await run(runtime, tcpGuest(other), { allow: [`127.0.0.1:${port}`], relay: { url } })).status, { kind: "exited", code: 101 });
  assert.deepEqual((await run(runtime, tcpGuest(other), { allow: [`127.0.0.1:${other}`], relay: { url } })).status, { kind: "exited", code: 101 });
  // A relay that is not there is ENETUNREACH too.
  assert.deepEqual((await run(runtime, tcpGuest(port), { allow: [`127.0.0.1:${port}`], relay: { url: "ws://127.0.0.1:1/" } })).status, { kind: "exited", code: 101 });
  for (const bad of [{ url: "http://127.0.0.1/" }, { url: "not a url" }, { url, protocols: ["a b"] }, { url, protocols: ["a", "a"] }, null]) {
    assert.throws(() => runtime.run({ program: "/guest", files: { "/guest": tcpGuest(port) }, network: { allow: [], relay: bad } }), { kind: "invalid-program" }, JSON.stringify(bad));
  }
});

test("a reply longer than the relay's window comes through whole", async (t) => {
  const reply = Uint8Array.from({ length: 4 * WINDOW + 12345 }, (_, index) => (index * 7) & 255);
  const port = await server(t, socket => { socket.resume(); socket.end(reply); });
  const { url } = await relay(t, { allow: [`127.0.0.1:${port}`] });
  const reached = await run(await launcher(t), tcpGuest(port), { allow: [`127.0.0.1:${port}`], relay: { url } });
  assert.deepEqual(reached.status, { kind: "exited", code: 0 });
  assert.equal(reached.stdout.length, reply.length);
  assert.ok(reached.stdout.every((byte, index) => byte === reply[index]));
});

test("the relay resolves names for the DNS stub, within both allow lists", async (t) => {
  const runtime = await launcher(t);
  const ask = async (name, url) => {
    const bytes = data(53), question = query(name);
    new DataView(bytes.buffer).setUint32(0x38, question.length, true);
    bytes.set(question, 0x40);
    const { status, stdout } = await run(runtime, elf(hex(DNS), bytes), { allow: ["localhost:80", "*.localhost"], relay: { url } });
    assert.deepEqual(status, { kind: "exited", code: 0 });
    return stdout;
  };
  const { url } = await relay(t, { allow: ["localhost"] });
  const answer = await ask("localhost", url);
  assert.deepEqual([...answer.subarray(0, 4)], [0x12, 0x34, 0x81, 0x80]);
  assert.ok(answer[7] >= 1, "at least one A record");
  assert.deepEqual([...answer.subarray(answer.length - 4)], [127, 0, 0, 1]);
  assert.equal((await ask("blocked.example", url))[3] & 15, 3, "NXDOMAIN: the kernel's list");
  assert.equal((await ask("app.localhost", url))[3] & 15, 3, "NXDOMAIN: the relay's list");
});

test("a ticket lets a client connect to what an allowed name resolved to", async (t) => {
  const port = await server(t, echo);
  const { url } = await relay(t, { allow: [`localhost:${port}`], resolve: async () => [{ address: "127.0.0.1" }, { address: "10.0.0.1" }] });
  const resolver = await client(url);
  resolver.send({ v: 1, op: "resolve", name: "LocalHost." });
  const resolved = await resolver.next();
  // The private address is left out: only the loopback, for localhost.
  assert.deepEqual(resolved.addresses.map(item => item.address), ["127.0.0.1"]);
  assert.deepEqual(await resolver.next(), { closed: 1000 });
  const open = async tickets => {
    const connection = await client(url);
    connection.send({ v: 1, op: "open", address: `127.0.0.1:${port}`, tickets });
    return { connection, reply: await connection.next() };
  };
  const { connection, reply } = await open([{ name: "localhost", ticket: resolved.addresses[0].ticket }]);
  assert.equal(reply.op, "connected");
  connection.send(new TextEncoder().encode("xping"));
  connection.send({ op: "end" });
  assert.equal(new TextDecoder().decode(await connection.next()), "ping");
  assert.deepEqual(await connection.next(), { op: "end" });
  assert.deepEqual(await connection.next(), { closed: 1000 });
  const forged = resolved.addresses[0].ticket.replace(/.$/, last => last === "A" ? "B" : "A");
  for (const tickets of [undefined, [], [{ name: "localhost", ticket: forged }], [{ name: "other.localhost", ticket: resolved.addresses[0].ticket }], [{ name: "localhost", ticket: "1.x" }]]) {
    assert.deepEqual((await open(tickets)).reply, { op: "failed", errno: 101 }, JSON.stringify(tickets));
  }
  // A request of another version is refused.
  const old = await client(url);
  old.send({ v: 2, op: "resolve", name: "localhost" });
  assert.deepEqual(await old.next(), { closed: 1008 });
});

test("the relay sends no more than its window ahead of the credit", async (t) => {
  const size = 4 * WINDOW;
  const port = await server(t, socket => { socket.resume(); socket.end(new Uint8Array(size)); });
  const { url } = await relay(t, { allow: [`127.0.0.1:${port}`] });
  const connection = await client(url);
  connection.send({ v: 1, op: "open", address: `127.0.0.1:${port}` });
  assert.equal((await connection.next()).op, "connected");
  let received = 0, item;
  const take = async until => { while (received < until && (item = await connection.next()) instanceof Uint8Array) received += item.length; };
  await take(WINDOW);
  await new Promise(resolve => setTimeout(resolve, 300));
  // What the relay had already read when it paused may follow, but nothing more.
  while ((item = await connection.next(100)) instanceof Uint8Array) received += item.length;
  assert.equal(item, undefined);
  assert.ok(received >= WINDOW && received < WINDOW + 128 * 1024, `received ${received}`);
  while (received < size) {
    connection.send({ op: "credit", bytes: received });
    const before = received;
    await take(before + 1);
  }
  assert.equal(received, size);
});

test("the relay picks a subprotocol the client offered, and checks the origin", async (t) => {
  const { url } = await relay(t, { allow: ["localhost"], origins: ["https://app.example"] });
  const handshake = (headers) => new Promise((resolve, reject) => {
    const call = request(url.replace("ws:", "http:"), { headers: { Connection: "Upgrade", Upgrade: "websocket", "Sec-WebSocket-Version": "13", "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==", ...headers } });
    call.on("upgrade", (response, socket) => { socket.destroy(); resolve(response); });
    call.on("response", response => { response.resume(); resolve(response); });
    call.on("error", reject);
    call.end();
  });
  const origin = { Origin: "https://app.example" };
  assert.equal((await handshake({ Origin: "https://evil.example" })).statusCode, 403);
  assert.equal((await handshake({})).statusCode, 403);
  const plain = await handshake(origin);
  assert.equal(plain.statusCode, 101);
  assert.equal(plain.headers["sec-websocket-accept"], "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
  assert.equal(plain.headers["sec-websocket-protocol"], undefined);
  const lambda = await handshake({ ...origin, "Sec-WebSocket-Protocol": "lambda-microvms, lambda-microvms.authentication.abc, lambda-microvms.port.8080" });
  assert.equal(lambda.headers["sec-websocket-protocol"], "lambda-microvms");
  const own = await handshake({ ...origin, "Sec-WebSocket-Protocol": `lambda-microvms, ${PROTOCOL}` });
  assert.equal(own.headers["sec-websocket-protocol"], PROTOCOL);
});

test("the relay reads its allow list as the kernel does", () => {
  assert.deepEqual(parseRule("GitHub.com:443"), { name: "github.com", subdomains: false, port: 443 });
  assert.deepEqual(parseRule("*.example.org"), { name: "example.org", subdomains: true, port: undefined });
  assert.deepEqual(parseRule("127.0.0.1:8080"), { ip: "127.0.0.1", port: 8080 });
  assert.deepEqual(parseRule("[::1]:9000"), { ip: "::1", port: 9000 });
  assert.deepEqual(parseRule("2001:db8::1"), { ip: "2001:db8::1", port: undefined });
  assert.deepEqual(parseRule("999.1.1.1"), { name: "999.1.1.1", subdomains: false, port: undefined });
  for (const bad of ["", "a:b", "a:0", "[::1", "[::1]x", "bad name", "a..b", "a:70000", "[1.2.3.4]"]) assert.throws(() => parseRule(bad), TypeError, bad);
  for (const [name, ip, ok] of [
    ["github.com", "140.82.112.3", true], ["github.com", "2606:50c0:8000::153", true],
    ["evil.example.org", "127.0.0.1", false], ["evil.example.org", "10.1.2.3", false], ["evil.example.org", "172.16.0.1", false],
    ["evil.example.org", "192.168.1.1", false], ["evil.example.org", "169.254.169.254", false], ["evil.example.org", "100.64.0.1", false],
    ["evil.example.org", "0.0.0.0", false], ["evil.example.org", "::1", false], ["evil.example.org", "fd00::1", false],
    ["evil.example.org", "fe80::1", false], ["evil.example.org", "::ffff:10.0.0.1", false], ["evil.example.org", "64:ff9b::7f00:1", false],
    ["evil.example.org", "64:ff9b::c0a8:101", false], ["github.com", "64:ff9b::8c52:7003", true], ["evil.example.org", "2002:a00:1::1", false],
    ["github.com", "2002:8c52:7003::1", true], ["localhost", "127.0.0.1", true], ["localhost", "::1", true],
    ["app.localhost", "127.0.0.2", true], ["localhost", "10.0.0.1", false],
  ]) assert.equal(reachable(name, canonicalIp(ip)), ok, `${name} ${ip}`);
});
