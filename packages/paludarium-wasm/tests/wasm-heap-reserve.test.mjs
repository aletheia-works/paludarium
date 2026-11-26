// In WebKit, the coordinator grows the memory to its maximum before any guest
// runs, since WebKit fails threads or crashes the page when a shared memory
// grows while other threads run in it. These check that the reserve takes
// smaller blocks once a whole one no longer fits, that it grows the memory to
// its maximum, that later allocations reuse it instead of growing it, and
// which browsers count as WebKit.
import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { imports, isWebKit } from "../worker-support.mjs";

const PAGE = 65536, MiB = 1 << 20, MAXIMUM = 16384 * PAGE;
const module = await WebAssembly.compile(await readFile(new URL("../paludarium.wasm", import.meta.url)));
const memory = new WebAssembly.Memory({ initial: 128, maximum: 16384, shared: true });
const e = (await WebAssembly.instantiate(module, imports(memory))).exports;

test("a limit below one page reserves nothing", () => {
  const before = memory.buffer.byteLength;
  assert.equal(e.heap_reserve(0), 0);
  assert.equal(e.heap_reserve(PAGE - 1), 0);
  assert.equal(memory.buffer.byteLength, before);
});

test("below one 64 MiB block, the reserve takes halves down to a page", () => {
  // 128 KiB, then 64 KiB: the halves that fit in three pages.
  assert.equal(e.heap_reserve(3 * PAGE), 3 * PAGE);
});

test("the reserve grows the memory to its maximum", () => {
  const reserved = e.heap_reserve(0xffffffff);
  assert.equal(reserved % PAGE, 0);
  assert.ok(reserved > MAXIMUM - 16 * MiB, `reserved ${reserved}`);
  assert.equal(memory.buffer.byteLength, MAXIMUM);
});

test("allocations after the reserve do not grow the memory", () => {
  const before = memory.buffer.byteLength;
  const ids = [e.buffer_new(128 * MiB), e.buffer_new(128 * MiB), e.buffer_new(MiB)];
  assert.ok(ids.every(id => id !== 0));
  ids.forEach(id => e.buffer_drop(id));
  assert.equal(memory.buffer.byteLength, before);
});

test("only WebKit browsers reserve the heap", () => {
  const webkit = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/27.2 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 27_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/158.0.8127.18 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 27_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/159.0 Mobile/15E148 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/27.2 Safari/605.1.15",
  ];
  const others = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36 Edg/158.0.0.0",
    "Mozilla/5.0 (Linux; Android 16; Pixel 10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:159.0) Gecko/20100101 Firefox/159.0",
    "Node.js/26",
    undefined,
  ];
  for (const agent of webkit) assert.equal(isWebKit(agent), true, agent);
  for (const agent of others) assert.equal(isWebKit(agent), false, String(agent));
});
