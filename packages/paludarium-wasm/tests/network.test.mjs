// The guest's network on Node.js: the coordinator connects for the guest
// to what `network.allow` names, and its DNS stub answers allowed names from
// Node's resolver. Two freestanding guests talk to a server this test runs.
import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:net";
import { createPaludarium } from "../index.mjs";

// socket, connect to the sockaddr_in at 0x402000, send the 6 bytes at
// 0x402010, shutdown(SHUT_WR), copy what comes back to stdout, exit 0; a
// failed call exits with its errno. Built from x86-64 assembly (GNU as).
const TCP = "b829000000bf02000000be0100000031d20f054885c0787b4989c4b82a0000004c89e7be00204000ba100000000f054885c0785fb8010000004c89e7be10204000ba060000000f054885c07846b8300000004c89e7be010000000f0531c04c89e7be20204000ba400000000f054885c0782174164889c2b801000000bf01000000be202040000f05ebd2b83c00000031ff0f0548f7d889c7b83c0000000f05";
// A UDP socket sends the query at 0x402040 (its length at 0x402038) to the
// sockaddr_in at 0x402000 and writes the answer to stdout.
const DNS = "b829000000bf02000000be0200000031d20f054885c0786c4989c4b82c0000004c89e7be402040008b1425382040004531d241b80020400041b9100000000f054885c0783fb82d0000004c89e7be00224000ba000200004531d24531c04531c90f054885c0781d4889c2b801000000bf01000000be002240000f05b83c00000031ff0f0548f7d889c7b83c0000000f05";

/** A static x86-64 ELF with `code` at 0x401000 and `data` at 0x402000. */
function elf(code, data) {
  const image = new Uint8Array(8192 + data.length);
  const view = new DataView(image.buffer);
  image.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]);
  const header = [[16, 2, 2], [18, 62, 2], [20, 1, 4], [24, 0x401000, 8], [32, 64, 8], [52, 64, 2], [54, 56, 2], [56, 2, 2]];
  for (const [at, value, size] of header) write(view, at, value, size);
  for (const [base, flags, offset, address, size] of [[64, 5, 4096, 0x401000, code.length], [120, 6, 8192, 0x402000, data.length]]) {
    for (const [at, value, width] of [[0, 1, 4], [4, flags, 4], [8, offset, 8], [16, address, 8], [24, address, 8], [32, size, 8], [40, size, 8], [48, 4096, 8]]) {
      write(view, base + at, value, width);
    }
  }
  image.set(code, 4096);
  image.set(data, 8192);
  return image;
}
function write(view, at, value, size) {
  if (size === 2) view.setUint16(at, value, true);
  else if (size === 4) view.setUint32(at, value, true);
  else view.setBigUint64(at, BigInt(value), true);
}
const hex = (text) => Uint8Array.from(text.match(/../g), (byte) => parseInt(byte, 16));
/** 1 KiB of data with a sockaddr_in for 127.0.0.1:`port` at its start. */
function data(port) {
  const bytes = new Uint8Array(1024);
  bytes.set([2, 0, port >> 8, port & 255, 127, 0, 0, 1]);
  return bytes;
}
/** A DNS query for `name`'s A record. */
function query(name) {
  const bytes = [0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
  for (const label of name.split(".")) bytes.push(label.length, ...new TextEncoder().encode(label));
  bytes.push(0, 0, 1, 0, 1);
  return bytes;
}
async function run(runtime, program, network) {
  const guest = runtime.run({ program: "/guest", files: { "/guest": program }, network });
  const chunks = [];
  for await (const chunk of guest.stdout) chunks.push(...chunk);
  return { status: await guest.exited, stdout: Uint8Array.from(chunks) };
}

test("a guest connects only to what network.allow names", async (t) => {
  // Echoes what follows the first byte, until the end of input.
  const server = createServer(socket => {
    let first = true;
    socket.on("data", chunk => { socket.write(first ? chunk.subarray(1) : chunk); first = false; });
    socket.on("end", () => socket.end());
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  t.after(() => server.close());
  const { port } = server.address();
  const runtime = await createPaludarium({ wasmUrl: new URL("../paludarium.wasm", import.meta.url) });
  t.after(() => runtime.dispose());
  const bytes = data(port);
  bytes.set(new TextEncoder().encode("ehello"), 16);
  const program = elf(hex(TCP), bytes);
  const allowed = await run(runtime, program, { allow: [`127.0.0.1:${port}`] });
  assert.deepEqual(allowed.status, { kind: "exited", code: 0 });
  assert.equal(new TextDecoder().decode(allowed.stdout), "hello");
  // Another port is unreachable, and without network.allow there is no network.
  assert.deepEqual((await run(runtime, program, { allow: [`127.0.0.1:${port + 1}`] })).status, { kind: "exited", code: 101 });
  assert.deepEqual((await run(runtime, program)).status, { kind: "exited", code: 97 });
  assert.throws(() => runtime.run({ program: "/guest", files: { "/guest": program }, network: { allow: ["bad name"] } }), { kind: "invalid-program" });
  assert.throws(() => runtime.run({ program: "/guest", files: { "/guest": program }, network: {} }), { kind: "invalid-program" });
  // Entries of the right shape that the kernel still refuses reject the run the same way.
  for (const entry of ["host:99999", "host:0", "a..b", "[1.2.3.4]"]) {
    await assert.rejects(runtime.run({ program: "/guest", files: { "/guest": program }, network: { allow: [entry] } }).exited, { kind: "invalid-program" }, entry);
  }
  // The launcher still runs guests after them.
  assert.deepEqual((await run(runtime, program, { allow: [`127.0.0.1:${port}`] })).status, { kind: "exited", code: 0 });
});

test("the DNS stub answers an allowed name from Node's resolver", async (t) => {
  const runtime = await createPaludarium({ wasmUrl: new URL("../paludarium.wasm", import.meta.url) });
  t.after(() => runtime.dispose());
  const ask = async (name) => {
    const bytes = data(53), question = query(name);
    new DataView(bytes.buffer).setUint32(0x38, question.length, true);
    bytes.set(question, 0x40);
    const { status, stdout } = await run(runtime, elf(hex(DNS), bytes), { allow: ["localhost:80"] });
    assert.deepEqual(status, { kind: "exited", code: 0 });
    return stdout;
  };
  const answer = await ask("localhost");
  assert.deepEqual([...answer.subarray(0, 4)], [0x12, 0x34, 0x81, 0x80]);
  assert.ok(answer[7] >= 1, "at least one A record");
  assert.deepEqual([...answer.subarray(answer.length - 4)], [127, 0, 0, 1]);
  const refused = await ask("blocked.example");
  assert.equal(refused[3] & 15, 3, "NXDOMAIN");
});
