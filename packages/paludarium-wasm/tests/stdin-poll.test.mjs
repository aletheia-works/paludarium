// Standard input written through Guest.stdin is readable only with bytes to
// read or once it is closed, as a Linux terminal or pipe is: poll waits out
// its timeout while there is none (formicarium's nano needs this to redraw).
// The freestanding guest hands off through stdout so that the test writes
// and closes at the moments it waits for, and needs no timing.
import test from "node:test";
import assert from "node:assert/strict";
import { createPaludarium } from "../index.mjs";

// At 0x401000, with its data at 0x402000: a pollfd { 0, POLLIN } and the
// results. It writes poll(0) and poll(100) while idle; then, after input,
// poll(-1), read and poll(0); then, after the close, poll(-1) and read.
// Built from x86-64 assembly (clang -target x86_64-linux-gnu).
const CODE =
  "b807000000bf00204000be0100000048c7c2000000000f0588042510204000b807000000bf00204000be0100000048c7c2640000000f0588042511204000b801000000bf01000000be10204000ba020000000f05b807000000bf00204000be0100000048c7c2ffffffff0f058804251220400031c031ffbe20204000ba100000000f0588042513204000b807000000bf00204000be0100000048c7c2000000000f0588042514204000b801000000bf01000000be12204000ba030000000f05b807000000bf00204000be0100000048c7c2ffffffff0f058804251520400031c031ffbe20204000ba100000000f0588042516204000b801000000bf01000000be15204000ba020000000f05b83c00000031ff0f05";

/** A static x86-64 ELF with `code` at 0x401000 and `data` at 0x402000. */
function elf(code, data) {
  const image = new Uint8Array(8192 + data.length);
  const view = new DataView(image.buffer);
  image.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]);
  const header = [[16, 2, 2], [18, 62, 2], [20, 1, 4], [24, 0x401000, 8], [32, 64, 8], [52, 64, 2], [54, 56, 2], [56, 2, 2]];
  for (const [at, value, size] of header) write(view, at, value, size);
  // PT_LOAD r-x for the code, rw- for the data.
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

test("standard input is readable only with bytes to read or once closed", async () => {
  const data = new Uint8Array(64);
  data[4] = 1; // POLLIN
  const runtime = await createPaludarium({ wasmUrl: new URL("../paludarium.wasm", import.meta.url) });
  try {
    const run = runtime.run({ program: "/guest", files: { "/guest": elf(hex(CODE), data) }, tty: { columns: 80, rows: 24 } });
    const reader = run.stdout.getReader();
    const output = [];
    const until = async (count) => {
      while (output.length < count) {
        const { value, done } = await reader.read();
        assert.ok(!done, `stdout ended after ${output.length} bytes`);
        output.push(...value);
      }
    };
    const stdin = run.stdin.getWriter();
    // Idle: poll(0) and poll(100) find nothing to read.
    await until(2);
    assert.deepEqual(output.slice(0, 2), [0, 0]);
    // One byte: poll(-1) returns it, read takes it, and poll(0) is idle again.
    await stdin.write(new Uint8Array([0x61]));
    await until(5);
    assert.deepEqual(output.slice(2, 5), [1, 1, 0]);
    // Closed: readable, and read gives its end.
    await stdin.close();
    await until(7);
    assert.deepEqual(output.slice(5, 7), [1, 0]);
    assert.deepEqual(await run.exited, { kind: "exited", code: 0 });
  } finally {
    await runtime.dispose();
  }
});
