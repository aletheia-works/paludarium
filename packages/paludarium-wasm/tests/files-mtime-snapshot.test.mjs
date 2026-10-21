import test from "node:test";
import assert from "node:assert/strict";
import { decodeSnapshot } from "../filesystem-snapshot.mjs";
function encoded(ns, version = 2) {
  const bytes = new Uint8Array(version === 2 ? 57 : 41), view = new DataView(bytes.buffer); let offset = 0;
  const u32 = value => { view.setUint32(offset, value, true); offset += 4; };
  const u64 = value => { view.setBigUint64(offset, value, true); offset += 8; };
  if (version === 2) { u32(0xffffffff); u32(2); }
  u32(1); u32(1); bytes[offset++] = 47; u32(0o100644); u64(1n); u64(1n);
  u64(BigInt.asUintN(64, ns)); if (version === 2) u64(BigInt.asUintN(64, ns >> 64n));
  u32(0); return bytes;
}
test("signed snapshot preserves epoch, negative fractions, and former u64 maximum", () => {
  for (const ns of [-1000000000n, -500000000n, -1n, 0n, 1n, 1500000000n, (1n << 64n) - 1n]) assert.equal(decodeSnapshot(encoded(ns))[0].mtimeNs, ns);
});
test("legacy unsigned snapshot remains compatible", () => {
  assert.equal(decodeSnapshot(encoded((1n << 64n) - 1n, 1))[0].mtimeNs, (1n << 64n) - 1n);
});
test("snapshot rejects unsupported versions, truncated data, excess counts and trailing bytes", () => {
  const valid = encoded(-1n); for (let length = 0; length < valid.length; length++) assert.throws(() => decodeSnapshot(valid.slice(0, length)));
  const unknown = valid.slice(); new DataView(unknown.buffer).setUint32(4, 3, true); assert.throws(() => decodeSnapshot(unknown), /version/);
  const count = valid.slice(); new DataView(count.buffer).setUint32(8, 0xffffffff, true); assert.throws(() => decodeSnapshot(count), /count/);
  assert.throws(() => decodeSnapshot(new Uint8Array([...valid, 0])), /length/);
});
