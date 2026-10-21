import test from "node:test";
import assert from "node:assert/strict";
import { Worker } from "node:worker_threads";
import { JIT_STATE_BYTES, jitImports } from "../jit-support.mjs";

// Independent copy of the Rust layout (paludarium_jit::STATE_BYTES):
// GPR0..15, RFLAGS, RIP (144 bytes), then XMM0..15 (16 bytes each).
const S = 400;
const XMM = 144;
const leb = value => { const out = []; do { let byte = value & 127; value >>>= 7; if (value) byte |= 128; out.push(byte); } while (value); return out; };
const section = (id, bytes) => [id, ...leb(bytes.length), ...bytes];
const word = value => [...new TextEncoder().encode(value)];
function moduleBytes(body = [0x20, 0, 0x42, 42, 0x37, 3, 0, 0x41, 0]) {
  return Uint8Array.from([
    0, 97, 115, 109, 1, 0, 0, 0,
    ...section(1, [1, 0x60, 1, 0x7f, 1, 0x7f]),
    ...section(2, [1, 3, ...word("env"), 6, ...word("memory"), 2, 3, 1, 4]),
    ...section(3, [1, 0]),
    ...section(7, [1, 3, ...word("run"), 0, 0]),
    ...section(10, [1, ...leb(body.length + 2), 0, ...body, 0x0b]),
  ]);
}
function setup(bytes = moduleBytes()) {
  const memory = new WebAssembly.Memory({ initial: 1, maximum: 4, shared: true });
  new Uint8Array(memory.buffer, 512, bytes.length).set(bytes);
  return { memory, bridge: jitImports(memory), bytes,
    run(key = 1) { return this.bridge.prepare(key, 512, this.bytes.length) === 0
      ? this.bridge.execute(key, 512, this.bytes.length, 64, S) : -1; } };
}
test("bridge executes actual synchronous shared-memory wasm", () => {
  const s = setup();
  assert.equal(s.run(), 0);
  assert.equal(new BigUint64Array(s.memory.buffer, 64, 50)[0], 42n);
});
test("bridge reuses immutable Worker-local compiled module", () => {
  const s = setup();
  assert.equal(s.run(), 0);
  assert.equal(s.run(), 0);
});
test("bridge rejects changed bytes for an existing module ID", () => {
  const s = setup();
  assert.equal(s.run(), 0);
  new Uint8Array(s.memory.buffer)[512] = 1;
  assert.equal(s.run(), -1);
});
test("bridge malformed wasm preserves state", () => {
  const s = setup(Uint8Array.of(1, 2, 3));
  assert.equal(s.run(), -1);
  assert.equal(new BigUint64Array(s.memory.buffer, 64, 50)[0], 0n);
});
test("bridge trap rolls back scratch state and permits retry", () => {
  const s = setup(moduleBytes([0x20, 0, 0x42, 42, 0x37, 3, 0, 0]));
  assert.equal(s.run(), -1);
  assert.equal(new BigUint64Array(s.memory.buffer, 64, 50)[0], 0n);
  s.bytes = moduleBytes();
  new Uint8Array(s.memory.buffer, 512, s.bytes.length).set(s.bytes);
  assert.equal(s.run(), 0);
});
test("bridge validates buffer range and exact state ABI", () => {
  const s = setup();
  assert.equal(JIT_STATE_BYTES, S);
  assert.equal(s.bridge.execute(1, 65535, 2, 64, S), -1);
  assert.equal(s.bridge.execute(1, 512, s.bytes.length, 64, S - 1), -1);
  assert.equal(s.bridge.execute(0, 512, s.bytes.length, 64, S), -1);
});
test("bridge remains usable after shared memory growth", () => {
  const s = setup();
  assert.equal(s.run(), 0);
  s.memory.grow(1);
  assert.equal(s.run(), 0);
  assert.equal(new BigUint64Array(s.memory.buffer, 64, 50)[0], 42n);
});
test("execution cannot compile an unprepared module", () => {
  const s = setup();
  assert.equal(s.bridge.execute(1, 512, s.bytes.length, 64, S), -2);
  assert.equal(new BigUint64Array(s.memory.buffer, 64, 50)[0], 0n);
  assert.equal(s.bridge.prepare(1, 512, s.bytes.length), 0);
  assert.equal(s.bridge.execute(1, 512, s.bytes.length, 64, S), 0);
});

import { requireJitProof } from './jit-suite.mjs';
test('provisional observation survives and completed proof has no stale error', () => {
 const row={pass:false,exit:0}; requireJitProof(row);
 assert.equal(row.jit_error,undefined);
 row.jit={executedBlocks:'1',executedInstructions:'2'};row.pass=true;
 requireJitProof(row);assert.equal(row.pass,true);assert.equal(row.jit_error,undefined);
});
test('final fallback-only and original failure remain failures', () => {
 const missing={pass:true,exit:0};requireJitProof(missing);assert.equal(missing.pass,false);
 const failed={pass:false,timed_out:true,error:'original timeout'};
 requireJitProof(failed);assert.equal(failed.error,'original timeout');assert.equal(failed.pass,false);
});

// memory.fill(state pointer, 0x7f, 400) and trap.
const fillAndTrap=()=>moduleBytes([0x20,0,0x41,0x7f,0x41,0x90,3,0xfc,11,0,0,0x41,0]);
const scratch=(s,pointer=64)=>new Uint8Array(s.memory.buffer,pointer,S);
const pattern=(s,pointer=64,seed=0)=>{
  const bytes=scratch(s,pointer);for(let i=0;i<S;i++)bytes[i]=(i+seed)&255;return bytes.slice();
};
test('reused rollback restores every400byte after actual wasm fill and trap',()=>{
  const s=setup(fillAndTrap()),before=pattern(s);
  assert.equal(s.run(),-1);assert.deepEqual(scratch(s),before);
});
test('sequential trap snapshots remain independent across scratch pointers',()=>{
  const s=setup(fillAndTrap()),first=pattern(s,64,1),second=pattern(s,1024,7);
  assert.equal(s.bridge.prepare(1,512,s.bytes.length),0);
  assert.equal(s.bridge.execute(1,512,s.bytes.length,64,S),-1);
  assert.equal(s.bridge.prepare(2,512,s.bytes.length),0);
  assert.equal(s.bridge.execute(2,512,s.bytes.length,1024,S),-1);
  assert.deepEqual(scratch(s,64),first);assert.deepEqual(scratch(s,1024),second);
});
test('cost callback reentry cannot overwrite shared rollback buffer',()=>{
  const s=setup();let entered=false,inner;
  s.bridge=jitImports(s.memory,field=>{
    if(field===19&&!entered){entered=true;inner=s.bridge.execute(1,512,s.bytes.length,64,S);}
  });
  assert.equal(s.run(),0);assert.equal(inner,-1);
  assert.equal(new BigUint64Array(s.memory.buffer,64,50)[0],42n);
});
test('successful state becomes next full rollback baseline',()=>{
  const s=setup();assert.equal(s.run(),0);const before=scratch(s).slice();
  s.bytes=fillAndTrap();new Uint8Array(s.memory.buffer,512,s.bytes.length).set(s.bytes);
  assert.equal(s.run(2),-1);assert.deepEqual(scratch(s),before);
});
test('reused rollback refreshes state view after shared memory growth',()=>{
  const s=setup(fillAndTrap()),before=pattern(s,64,3);
  assert.equal(s.bridge.prepare(1,512,s.bytes.length),0);s.memory.grow(1);
  assert.equal(s.bridge.execute(1,512,s.bytes.length,64,S),-1);
  assert.deepEqual(scratch(s),before);
});
test('byte loop rejects last-byte mutation before execution',()=>{
  const s=setup(),before=pattern(s);
  assert.equal(s.bridge.prepare(1,512,s.bytes.length),0);
  new Uint8Array(s.memory.buffer)[512+s.bytes.length-1]^=1;
  assert.equal(s.bridge.execute(1,512,s.bytes.length,64,S),-1);
  assert.deepEqual(scratch(s),before);
});
test('byte loop rejects different length without touching scratch',()=>{
  const s=setup(),before=pattern(s);
  assert.equal(s.bridge.prepare(1,512,s.bytes.length),0);
  assert.equal(s.bridge.execute(1,512,s.bytes.length-1,64,S),-1);
  assert.deepEqual(scratch(s),before);
});
test('cost callback exception restores guard and remains an exception',()=>{
  const s=setup();let fail=true;
  s.bridge=jitImports(s.memory,field=>{if(field===19&&fail){fail=false;throw Error('cost callback failure');}});
  assert.equal(s.bridge.prepare(1,512,s.bytes.length),0);
  assert.throws(()=>s.bridge.execute(1,512,s.bytes.length,64,S),/cost callback failure/);
  assert.equal(s.bridge.execute(1,512,s.bytes.length,64,S),0);
});

// ----- Loop-back 1 Step33: XMM slots (bytes 144..399) at the JS boundary -----

const simd = (op, ...rest) => [0xfd, ...leb(op), ...rest];
const xmmArg = n => [3, ...leb(XMM + 16 * n)];
// xmm[n] = 16 bytes of `fill` (v128.const), as emitted for vector stores.
const storeXmm = (n, fill) => [0x20, 0, ...simd(0x0c, ...Array(16).fill(fill)), ...simd(0x0b, ...xmmArg(n))];
// xmm[d] = xmm[s] (MOVDQA register form).
const moveXmm = (d, s) => [0x20, 0, 0x20, 0, ...simd(0x00, ...xmmArg(s)), ...simd(0x0b, ...xmmArg(d))];
const gpr0 = value => [0x20, 0, 0x42, ...leb(value), 0x37, 3, 0];
const finish = [0x41, 0];
const trap = [0x00, 0x41, 0];
const words = (s, pointer = 64) => new BigUint64Array(s.memory.buffer, pointer, 50);

test('import rejects the former 144-byte and off-by-one state lengths', () => {
  const s = setup(moduleBytes([...storeXmm(0, 0xaa), ...finish])), before = pattern(s);
  assert.equal(s.bridge.prepare(1, 512, s.bytes.length), 0);
  for (const length of [144, S - 1, S + 1, 0x7fffffff]) {
    assert.equal(s.bridge.execute(1, 512, s.bytes.length, 64, length), -1, `length ${length}`);
    assert.deepEqual(scratch(s), before);
  }
  assert.equal(s.bridge.execute(1, 512, s.bytes.length, 64, S), 0);
});
test('state pointer must leave room for all 400 bytes', () => {
  const s = setup(moduleBytes([...storeXmm(15, 1), ...finish]));
  assert.equal(s.bridge.prepare(1, 512, s.bytes.length), 0);
  const end = s.memory.buffer.byteLength;
  assert.equal(s.bridge.execute(1, 512, s.bytes.length, end - S + 1, S), -1);
  assert.equal(s.bridge.execute(1, 512, s.bytes.length, end - S, S), 0);
  assert.deepEqual([...new Uint8Array(s.memory.buffer, end - 16, 16)], Array(16).fill(1));
});
test('trap after every XMM store restores the full 400 bytes', () => {
  const body = [];
  for (let n = 0; n < 16; n++) body.push(...storeXmm(n, 0x10 + n));
  const s = setup(moduleBytes([...body, ...trap])), before = pattern(s, 64, 5);
  assert.equal(s.run(), -1);
  assert.deepEqual(scratch(s), before);
});
test('rollback covers the final XMM15 byte at offset 399', () => {
  const s = setup(moduleBytes([...storeXmm(15, 0xee), ...trap])), before = pattern(s, 64, 9);
  assert.equal(s.run(), -1);
  assert.equal(scratch(s)[S - 1], before[S - 1]);
  assert.deepEqual(scratch(s), before);
});
test('partial trap after GPR and XMM writes restores both regions', () => {
  const s = setup(moduleBytes([...gpr0(42), ...storeXmm(3, 0x33), ...trap])), before = pattern(s, 64, 11);
  assert.equal(s.run(), -1);
  assert.deepEqual(scratch(s).subarray(0, XMM), before.subarray(0, XMM));
  assert.deepEqual(scratch(s).subarray(XMM), before.subarray(XMM));
});
test('XMM low and high lanes keep little-endian u128 order', () => {
  // xmm0 = xmm1; then gpr0/gpr1 = i64x2 lanes 0/1 of xmm1.
  const lane = (target, index) => [0x20, 0, 0x20, 0, ...simd(0x00, ...xmmArg(1)), ...simd(0x1d, index), 0x37, 3, target * 8];
  const s = setup(moduleBytes([...moveXmm(0, 1), ...lane(0, 0), ...lane(1, 1), ...finish]));
  const w = words(s);
  w[20] = 0x1111222233334444n; w[21] = 0xaaaabbbbccccddddn;
  assert.equal(s.run(), 0);
  assert.equal(w[18], 0x1111222233334444n); assert.equal(w[19], 0xaaaabbbbccccddddn);
  assert.equal(w[0], 0x1111222233334444n); assert.equal(w[1], 0xaaaabbbbccccddddn);
  assert.notEqual(w[18], w[19]);
});
test('successful XMM run becomes the next rollback baseline', () => {
  const s = setup(moduleBytes([...storeXmm(7, 0x77), ...finish]));
  pattern(s, 64, 13);
  assert.equal(s.run(), 0);
  const after = scratch(s).slice();
  assert.deepEqual([...after.subarray(XMM + 7 * 16, XMM + 8 * 16)], Array(16).fill(0x77));
  s.bytes = moduleBytes([...storeXmm(7, 0x01), ...storeXmm(8, 0x02), ...trap]);
  new Uint8Array(s.memory.buffer, 512, s.bytes.length).set(s.bytes);
  assert.equal(s.run(2), -1);
  assert.deepEqual(scratch(s), after);
});
test('Workers keep independent compiled modules and rollback buffers', async () => {
  const memory = new WebAssembly.Memory({ initial: 1, maximum: 4, shared: true });
  const failing = moduleBytes([...storeXmm(0, 0xf0), ...trap]);
  const passing = moduleBytes([...storeXmm(0, 0x0f), ...gpr0(42), ...finish]);
  new Uint8Array(memory.buffer, 512, failing.length).set(failing);
  new Uint8Array(memory.buffer, 1536, passing.length).set(passing);
  const left = new Uint8Array(memory.buffer, 64, S), right = new Uint8Array(memory.buffer, 2048, S);
  for (let i = 0; i < S; i++) { left[i] = i & 255; right[i] = (i * 7) & 255; }
  const leftBefore = left.slice();
  const support = new URL("../jit-support.mjs", import.meta.url).href;
  const source = `const {parentPort, workerData:d} = require('node:worker_threads');
    import(${JSON.stringify(support)}).then(({jitImports}) => {
      const jit = jitImports(d.memory), out = [];
      if (d.prepareFirst) out.push(jit.prepare(1, d.code, d.length));
      out.push(jit.execute(1, d.code, d.length, d.state, ${S}));
      if (!d.prepareFirst) { out.push(jit.prepare(1, d.code, d.length)); out.push(jit.execute(1, d.code, d.length, d.state, ${S})); }
      parentPort.postMessage(out);
    }, error => parentPort.postMessage(String(error)));`;
  const run = data => new Promise((resolve, reject) => {
    const worker = new Worker(source, { eval: true, workerData: { memory, ...data } });
    const timer = setTimeout(() => { worker.terminate(); reject(Error("worker timeout")); }, 10000);
    worker.once("message", message => { clearTimeout(timer); worker.terminate().then(() => resolve(message)); });
    worker.once("error", error => { clearTimeout(timer); reject(error); });
  });
  const [a, b] = await Promise.all([
    run({ code: 512, length: failing.length, state: 64, prepareFirst: true }),
    run({ code: 1536, length: passing.length, state: 2048, prepareFirst: false }),
  ]);
  assert.deepEqual(a, [0, -1]);
  // Same module ID 1 is unprepared in the other Worker and holds other bytes.
  assert.deepEqual(b, [-2, 0, 0]);
  assert.deepEqual(left, leftBefore);
  assert.deepEqual([...right.subarray(XMM, XMM + 16)], Array(16).fill(0x0f));
  assert.equal(new BigUint64Array(memory.buffer, 2048, 1)[0], 42n);
});
