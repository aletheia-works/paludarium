// The guest's network on Node.js: the coordinator connects for the guest
// to what `network.allow` names, and its DNS stub answers allowed names from
// Node's resolver. Two freestanding guests talk to a server this test runs.
import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:net";
import { createPaludarium } from "../index.mjs";
import { DNS, TCP, data, elf, hex, query } from "./wasm-network-guests.mjs";

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
