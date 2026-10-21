import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { COST_FIELDS, costSnapshot, jitImports } from "../jit-support.mjs";
import { validateBuildReceipt, validateProfileReport } from "./jit-cost-profile-check.mjs";

const hash = bytes => createHash("sha256").update(bytes).digest("hex");
const locks = ["Cargo.lock", "fuzz/Cargo.lock", "tests/guests/programs/source-lock.json", "tests/guests/programs/probe/Cargo.lock", "rust-toolchain.toml", "deny.toml"];
function build() {
  const source_files = Object.fromEntries(locks.sort().map(name => [name, "1".repeat(64)]));
  const source_digest = hash(JSON.stringify(source_files));
  return { schema: 3, diagnostic_version: 3, purpose: "cost-profile", features: ["cost-profile"],
    source_files, source_digest, module_sha256: "2".repeat(64), locks: { ...source_files },
    local_snapshot: true, head: "local:" + source_digest };
}
const receipt = build();
const identity = { head: receipt.head, module_sha256: receipt.module_sha256,
  source_digest: receipt.source_digest, oracle_sha256: "3".repeat(64), probe_sha256: "4".repeat(64) };
function report() {
  const rows = [false, true].map(jit => {
    const counters = Object.fromEntries(COST_FIELDS.map(name => [name, "0"]));
    counters.checkpoints = "1";
    if (jit) Object.assign(counters, { executedBlocks: "1", executedInstructions: "2", compileAttempts: "1", jsTransitions: "2", blockLength2: "1", nextMissing: "1" });
    return { jit, pass: true, exit: 0, timed_out: false, errors: [], seconds: 1, cleaned: true,
      costProfile: { schema: 3, purpose: "cost-profile", overflow: false, counters, sites:{capacity:16384,retainedOnly:true,rows:[]} } };
  });
  return { schema: 3, purpose: "cost-profile", performanceAcceptance: false, ...identity, complete: true, rows };
}
const rejectReport = change => { const r = report(); change(r); assert.throws(() => validateProfileReport(r, identity)); };
test("v3 rejects v2 receipt and collector",()=>{
  const r=build();r.schema=2;r.diagnostic_version=2;assert.throws(()=>validateBuildReceipt(r,receipt.module_sha256));
  rejectReport(r=>r.rows[1].costProfile.schema=2);
});
test("v3 site rows require fixed capacity",()=>rejectReport(r=>r.rows[1].costProfile.sites.capacity=16385));
test("v3 site denominator includes dropped events",()=>{
  const r=report();r.rows[1].costProfile.counters.siteObserved="1";r.rows[1].costProfile.counters.siteDropped="1";
  assert.equal(validateProfileReport(r,identity),true);
});
test("v3 site dropped cannot invent observed events",()=>rejectReport(r=>r.rows[1].costProfile.counters.siteDropped="1"));
test("v3 site negative count rejected",()=>rejectReport(r=>r.rows[1].costProfile.sites.rows.push({space:"1",epoch:"1",rip:"1",classification:"1",count:"-1",descriptor:"x",truncated:false})));
test("v3 site classification is closed",()=>rejectReport(r=>r.rows[1].costProfile.sites.rows.push({space:"1",epoch:"1",rip:"1",classification:"6",count:"1",descriptor:"x",truncated:false})));
test("v3 site descriptor bounded",()=>rejectReport(r=>r.rows[1].costProfile.sites.rows.push({space:"1",epoch:"1",rip:"1",classification:"1",count:"1",descriptor:"x".repeat(257),truncated:false})));
test("v3 snapshot rejects site capacity overflow",()=>assert.throws(()=>costSnapshot({cost_version:()=>3,cost_fields:()=>120,cost_site_count:()=>16385,cost_site_stat:()=>0n})));
test("cost runner accepts exact two diagnostic observations without claiming performance", () => {
  validateBuildReceipt(build(), receipt.module_sha256);
  assert.equal(validateProfileReport(report(), identity), true);
});
test("cost runner rejects ordinary acceptance receipt or missing feature", () => {
  for (const change of [r => r.purpose = "acceptance-control", r => r.features = []]) {
    const r = build(); change(r); assert.throws(() => validateBuildReceipt(r, receipt.module_sha256));
  }
});
test("cost runner rejects wrong module or external CI head", () => {
  assert.throws(() => validateBuildReceipt(build(), "5".repeat(64)));
  const r = build(); r.local_snapshot = false; r.head = "a".repeat(40);
  assert.throws(() => validateBuildReceipt(r, receipt.module_sha256, "b".repeat(40)));
});
test("cost runner rejects missing/changed source closure and lock", () => {
  for (const change of [r => delete r.source_files, r => r.source_files["Cargo.lock"] = "8".repeat(64), r => r.locks["Cargo.lock"] = "9".repeat(64)]) {
    const r = build(); change(r); assert.throws(() => validateBuildReceipt(r, receipt.module_sha256));
  }
});
test("cost runner rejects unsafe source paths even when self-digest matches", () => {
  const r = build(); r.source_files["../outside"] = "1".repeat(64);
  r.source_digest = hash(JSON.stringify(Object.fromEntries(Object.entries(r.source_files).sort())));
  assert.throws(() => validateBuildReceipt(r, receipt.module_sha256));
});
test("cost runner rejects incomplete/duplicate/extra mode observations", () => {
  for (const change of [r => r.complete = false, r => r.rows.pop(), r => r.rows.push(r.rows[0]), r => r.rows.reverse()]) rejectReport(change);
});
test("cost runner rejects cross-module/head/oracle/report substitutions", () => {
  for (const key of Object.keys(identity)) rejectReport(r => r[key] = "different");
});
test("cost runner rejects missing counter, overflow and invalid integer", () => {
  for (const change of [r => delete r.rows[1].costProfile.counters.cacheHits,
    r => r.rows[1].costProfile.overflow = true, r => r.rows[1].costProfile.counters.cacheHits = "-1",
    r => r.rows[1].costProfile.counters.cacheHits = "18446744073709551616"]) rejectReport(change);
});
test("cost runner rejects guest failure/timeout/cleanup/nonfinite durations", () => {
  for (const change of [r => r.rows[0].timed_out = true, r => r.rows[1].exit = 1,
    r => r.rows[0].cleaned = false, r => r.rows[1].seconds = 30.01,
    r => r.rows[1].seconds = NaN, r => r.rows[0].errors.push("failure")]) rejectReport(change);
});
test("cost runner rejects fallback-only and inconsistent block histogram", () => {
  rejectReport(r => r.rows[1].costProfile.counters.executedBlocks = "0");
  rejectReport(r => r.rows[1].costProfile.counters.blockLength2 = "0");
});
test("cost runner rejects diagnostic/performance receipt conflation", () => {
  rejectReport(r => r.performanceAcceptance = true);
  rejectReport(r => r.purpose = "performance");
});

const bytes = Buffer.from("0061736d0100000001060160017f017f030201000707010372756e00000a0601040041000b", "hex");
function bridge(cost, now) {
  const memory = new WebAssembly.Memory({ initial: 1, maximum: 1, shared: true });
  new Uint8Array(memory.buffer, 512, bytes.length).set(bytes);
  return { memory, jit: jitImports(memory, cost, now) };
}
test("cost collector disabled path never reads clock or calls diagnostic exports", () => {
  const s = bridge(null, () => { throw Error("disabled clock"); });
  assert.equal(s.jit.prepare(1, 512, bytes.length), 0);
  assert.equal(s.jit.execute(1, 512, bytes.length, 64, 400), 0);
});
test("cost collector times only cold actual compilation and counts bytes separately", () => {
  const counters = Array(COST_FIELDS.length).fill(0), times = [10, 11];
  const s = bridge((field, value) => { counters[field] += value; }, () => times.shift());
  assert.equal(s.jit.prepare(1, 512, bytes.length), 0);
  assert.equal(s.jit.execute(1, 512, bytes.length, 64, 400), 0);
  assert.equal(s.jit.prepare(1, 512, bytes.length), 0);
  assert.equal(s.jit.execute(1, 512, bytes.length, 64, 400), 0);
  assert.equal(counters[14], 1); assert.equal(counters[15], 1000000);
  assert.equal(counters[18], bytes.length); assert.equal(counters[19], 800);
  assert.equal(times.length, 0);
});
test("cost collector records failed cold compilation while preserving state", () => {
  const counters = Array(COST_FIELDS.length).fill(0);
  const s = bridge((field, value) => counters[field] += value, () => 1);
  new Uint8Array(s.memory.buffer)[512] = 1;
  assert.equal(s.jit.prepare(1, 512, bytes.length), -1);
  assert.equal(counters[14], 1);
  assert.equal(new BigUint64Array(s.memory.buffer, 64, 18)[0], 0n);
});
test("cost snapshot refuses wrong ABI and has no ordinary-module fallback claim", () => {
  assert.equal(costSnapshot({}), null);
  assert.throws(() => costSnapshot({ cost_version: () => 1 }));
  assert.throws(() => costSnapshot({ cost_version: () => 1, cost_fields: () => 0 }));
});
test("cost snapshot retains overflow for fail-closed report validation", () => {
  const s = costSnapshot({ cost_version: () => 3, cost_fields: () => COST_FIELDS.length,
    cost_overflow: () => 1, cost_stat: () => 0n, cost_site_count:()=>0, cost_site_stat:()=>0n });
  assert.equal(s.overflow, true);
  assert.equal(Object.keys(s.counters).length, 120);
});

test("v2 refuses historical v1 build/report/collector even with matching digests", () => {
  const r = build(); r.schema = 1; assert.throws(() => validateBuildReceipt(r, receipt.module_sha256));
  const b = build(); b.diagnostic_version = 1; assert.throws(() => validateBuildReceipt(b, receipt.module_sha256));
  rejectReport(r => r.schema = 1);
  rejectReport(r => r.rows[1].costProfile.schema = 1);
});
test("v2 next and prepared populations cannot invent adjacent blocks", () => {
  rejectReport(r => r.rows[1].costProfile.counters.nextMissing = "0");
  rejectReport(r => r.rows[1].costProfile.counters.nextPrepared = "1");
  rejectReport(r => r.rows[1].costProfile.counters.extra = "0");
});
test("no-touch query missing never prepares or reads clock/scratch", () => {
  const counters = Array(COST_FIELDS.length).fill(0);
  const s = bridge((f,v) => counters[f] += v, () => { throw Error("query clock"); });
  assert.equal(s.jit.execute(1,512,bytes.length,0,0),-2);
  assert.equal(counters[88],1); assert.equal(counters[14],0); assert.equal(counters[19],0);
});
test("no-touch query prepared entry preserves scratch and compile counts", () => {
  const counters = Array(COST_FIELDS.length).fill(0);
  const s = bridge((f,v) => counters[f] += v, () => 1);
  assert.equal(s.jit.prepare(1,512,bytes.length),0);
  new Uint8Array(s.memory.buffer,64,400).fill(77);
  const before = new Uint8Array(s.memory.buffer).slice();
  for(let i=0;i<8;i++) assert.equal(s.jit.execute(1,512,bytes.length,0,0),0);
  assert.deepEqual(new Uint8Array(s.memory.buffer),before);
  assert.equal(counters[14],1); assert.equal(counters[19],0);
  assert.equal(counters[89],8*bytes.length);
});
test("no-touch query changed code rejects without deleting or repairing entry", () => {
  const s = bridge(() => {}, () => 1); s.jit.prepare(1,512,bytes.length);
  new Uint8Array(s.memory.buffer)[512]=1;
  assert.equal(s.jit.execute(1,512,bytes.length,0,0),-1);
  new Uint8Array(s.memory.buffer)[512]=bytes[0];
  assert.equal(s.jit.execute(1,512,bytes.length,0,0),0);
});
test("no-touch query does not update positive LRU eviction order", () => {
  const s = bridge(() => {}, () => 1);
  for(let key=1;key<=1024;key++) assert.equal(s.jit.prepare(key,512,bytes.length),0);
  assert.equal(s.jit.execute(1,512,bytes.length,0,0),0);
  assert.equal(s.jit.prepare(1025,512,bytes.length),0);
  assert.equal(s.jit.execute(1,512,bytes.length,0,0),-2);
  assert.equal(s.jit.execute(2,512,bytes.length,0,0),0);
});
test("no-touch query is Worker local and does not create entries", () => {
  const left=bridge(()=>{},()=>1), right=bridge(()=>{},()=>1);
  left.jit.prepare(1,512,bytes.length);
  assert.equal(left.jit.execute(1,512,bytes.length,0,0),0);
  assert.equal(right.jit.execute(1,512,bytes.length,0,0),-2);
});
test("no-touch query invalid ranges and ordinary-module sentinel are rejected", () => {
  const s=bridge(()=>{},()=>1), ordinary=bridge(null,()=>1);
  for(const args of [[0,512,bytes.length,0,0],[1,0,bytes.length,0,0],[1,65530,bytes.length,0,0], [1,512,bytes.length,64,0]]) assert.equal(s.jit.execute(...args),-1);
  ordinary.jit.prepare(1,512,bytes.length);
  assert.equal(ordinary.jit.execute(1,512,bytes.length,0,0),-1);
  assert.equal(ordinary.jit.execute(1,512,bytes.length,64,400),0);
});
