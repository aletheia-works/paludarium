import test from 'node:test';
import assert from 'node:assert/strict';
import {validateRow,runWorker,CHUNKS,OPERATIONS} from './jit-cost-microbench.mjs';
import {COST_FIELDS} from '../jit-support.mjs';
const row=()=>({kind:'loop',maximum:false,observe:false,chunks:Array(CHUNKS).fill(1),clockOnly:Array(CHUNKS).fill(.01),
 operations:CHUNKS*OPERATIONS,clockCalls:4*CHUNKS,measuredClockCalls:2*CHUNKS,clockControlCalls:2*CHUNKS,
 unit:'milliseconds per 1024 operations',executedIn:'Node Worker / actual Rust Wasm',
 cleaned:true,measurementRestored:true,warmupExcluded:true,sitesBefore:0,siteCount:0,checksum:'65536',counters:Object.fromEntries(COST_FIELDS.map(n=>[n,'0']))});
const reject=change=>{const r=row();change(r);assert.throws(()=>validateRow(r))};
test('micro finite fixture accepts exact64x1024',()=>assert.equal(validateRow(row()),true));
test('micro rejects changed chunk population',()=>reject(r=>r.chunks.pop()));
test('micro rejects changed operation denominator',()=>reject(r=>r.operations--));
test('micro rejects per-operation clock claim',()=>reject(r=>r.clockCalls=2*r.operations));
test('micro rejects nonfinite timing',()=>reject(r=>r.chunks[0]=NaN));
test('micro rejects native attribution',()=>reject(r=>r.executedIn='native Rust'));
test('micro rejects missing cleanup',()=>reject(r=>r.cleaned=false));
test('micro rejects fallback-only warm fixture',()=>reject(r=>{r.kind='warm';r.observe=true}));
test('micro rejects negative fixture with JIT execution',()=>reject(r=>{r.kind='negative';r.counters.executedBlocks='1'}));
test('micro rejects cold prepare not compiling',()=>reject(r=>{r.kind='prepare';r.observe=true}));
test('micro rejects counter overflow',()=>reject(r=>r.counters.hookAttempts='18446744073709551616'));
test('micro rejects partial negative warmup',()=>reject(r=>{r.kind='hint';r.observe=true;r.counters.decodeHintHit=String(r.operations)}));
test('micro accepts all64 negative boundaries warmed',()=>{const r=row();r.kind='hint';r.observe=true;r.counters.decodeHintHit=String(64*r.operations);assert.equal(validateRow(r),true)});
test('micro rejects collection in disabled scope',()=>reject(r=>r.counters.hookAttempts='1'));
test('micro rejects disabled site mutation',()=>reject(r=>r.siteCount=1));
test('micro rejects un-restored measurement scope',()=>reject(r=>r.measurementRestored=false));
test('micro rejects timed warmup',()=>reject(r=>r.warmupExcluded=false));
test('micro actual Worker rejects malformed module and is reaped',async()=>{await assert.rejects(runWorker(new Uint8Array([0]),{kind:'loop',maximum:false,observe:false}));});
