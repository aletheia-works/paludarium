// What the browser checks record beside a row when a Wasm Worker traps, and
// what diagnostics() says about heap_reserve. None of it is compared.
import test from "node:test";
import assert from "node:assert/strict";
import { PaludariumError, createPaludarium } from "../index.mjs";
import { WASM_PROBES } from "./wasm-contract.mjs";
import { observeProgram, trappedProbe } from "./wasm-programs.mjs";

test("a single probe row traps in its own item", () => {
  assert.equal(trappedProbe("probe-rayon", ""), "rayon");
  assert.equal(trappedProbe("probe-environment", ""), "environment");
});

test("probe-all traps in the item after the last one it passed", () => {
  assert.equal(trappedProbe("probe-all", ""), WASM_PROBES[0]);
  assert.equal(trappedProbe("probe-all", "PASS tokio-timer\n"), "unix-stream-pair");
  assert.equal(trappedProbe("probe-all", "PASS tokio-timer\nPASS unix-stream-pair\nPASS rayon\n"), "mutex-condvar");
  assert.equal(trappedProbe("probe-all", WASM_PROBES.map(name => `PASS ${name}\n`).join("")), null);
});

test("a host error keeps the memory's size when its Worker trapped", () => {
  const heapReserve = { reserved: 1006632960, bytesBefore: 8388608, bytesAfter: 1073741824 };
  const error = new PaludariumError("host", "RuntimeError: access to a null reference", { memoryBytes: 1073741824, heapReserve });
  assert.equal(error.memoryBytes, 1073741824);
  assert.deepEqual(error.heapReserve, heapReserve);
  assert.equal(new PaludariumError("host", "x").memoryBytes, undefined);
});

function trappingLauncher(error) {
  const failing = () => new ReadableStream({ start(controller) { controller.error(error); } });
  return { run: () => ({ stdin: new WritableStream(), stdout: failing(), stderr: failing(), exited: Promise.reject(error), kill() {} }) };
}

test("the row keeps the trap's memory size beside its errors, which stay as they were", async () => {
  const row = await observeProgram(trappingLauncher(new PaludariumError("host", "RuntimeError: trap", { memoryBytes: 65536, heapReserve: null })), { program: "/probe" });
  assert.deepEqual(row.host_trap, { memory_bytes: 65536, heap_reserve: null });
  assert.equal(row.errors.length, 3);
  for (const entry of row.errors) assert.deepEqual(Object.keys(entry).filter(key => key !== "stream"), ["kind", "message"]);
});

test("an error without a memory size leaves no trap record", async () => {
  const row = await observeProgram(trappingLauncher(new PaludariumError("internal", "x")), { program: "/probe" });
  assert.equal(row.host_trap, undefined);
  assert.equal(row.errors.length, 3);
});

test("diagnostics() reports the memory's size, and no heap reserve outside WebKit", async () => {
  const launcher = await createPaludarium({ wasmUrl: new URL("../paludarium.wasm", import.meta.url) });
  try {
    const diagnostics = await launcher.diagnostics();
    assert.equal(diagnostics.heapReserve, null);
    assert.ok(Number.isInteger(diagnostics.memoryBytes) && diagnostics.memoryBytes > 0 && diagnostics.memoryBytes % 65536 === 0);
  } finally { await launcher.dispose(); }
});
