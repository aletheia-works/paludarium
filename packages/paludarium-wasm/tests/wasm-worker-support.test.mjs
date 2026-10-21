import test from "node:test";
import assert from "node:assert/strict";
import { imports, putBuffer, takeBuffer } from "../worker-support.mjs";
function fixture() {
  const memory = new WebAssembly.Memory({ initial: 1, maximum: 2, shared: true }), dropped = [];
  const exports = { buffer_new: () => 1, buffer_pointer: () => 32, buffer_drop: id => dropped.push(id), buffer_len: () => 3 };
  return { memory, exports, dropped };
}
test("bulk copy writes owned memory", () => { const { memory, exports } = fixture(); assert.equal(putBuffer(exports, new Uint8Array([1, 2, 3]), memory), 1); assert.deepEqual(new Uint8Array(memory.buffer, 32, 3), new Uint8Array([1, 2, 3])); });
test("bulk copy result owns bytes after handle release", () => { const { memory, exports, dropped } = fixture(); new Uint8Array(memory.buffer, 32, 3).set([1, 2, 3]); const bytes = takeBuffer(exports, 1, memory); new Uint8Array(memory.buffer, 32, 3).fill(0); assert.deepEqual(bytes, new Uint8Array([1, 2, 3])); assert.deepEqual(dropped, [1]); });
test("invalid pointer write releases buffer", () => { const { memory, exports, dropped } = fixture(); exports.buffer_pointer = () => 0; assert.throws(() => putBuffer(exports, new Uint8Array([1]), memory), /pointer/); assert.deepEqual(dropped, [1]); });
test("invalid read length releases buffer", () => { const { memory, exports, dropped } = fixture(); exports.buffer_len = () => -1; assert.throws(() => takeBuffer(exports, 1, memory), /handle/); assert.deepEqual(dropped, [1]); });
test("zero handle is empty", () => { const { memory, exports, dropped } = fixture(); assert.equal(takeBuffer(exports, 0, memory).length, 0); assert.equal(dropped.length, 0); });
test("failed allocation does not use pointer", () => { const { memory, exports } = fixture(); exports.buffer_new = () => 0; assert.throws(() => putBuffer(exports, new Uint8Array(), memory), /allocation/); });
test("spawn task rejects absent callback and invalid handles", () => { const { memory } = fixture(); const imported = imports(memory).paludarium; assert.equal(imported.spawn_task(1), -1); const calls = [], enabled = imports(memory, { spawnTask: id => calls.push(id) }).paludarium; for (const value of [0, -1, 1.5]) assert.equal(enabled.spawn_task(value), -1); assert.equal(enabled.spawn_task(7), 0); assert.deepEqual(calls, [7]); });
