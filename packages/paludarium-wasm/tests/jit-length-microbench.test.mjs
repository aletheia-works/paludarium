import test from 'node:test';
import assert from 'node:assert/strict';
import {validateLengthRow,LENGTHS,KINDS,superviseLengthWorker} from './jit-length-microbench.mjs';
import {EventEmitter} from 'node:events';
import {COST_FIELDS} from '../jit-support.mjs';
const row=()=>({kind:'warm',length:3,observe:true,chunks:Array(64).fill(1),clockOnly:Array(64).fill(0),
  operations:65536,cpuBudget:3,fixtureInstructions:3,clockCalls:256,measuredClockCalls:128,clockControlCalls:128,
  cleaned:true,measurementRestored:true,warmupExcluded:true,warmupCount:64,warmupCpuVerified:true,
  warmupCounters:{executedBlocks:'64',executedInstructions:'192',interpreterSteps:'0'},
  counters:{...Object.fromEntries(COST_FIELDS.map(n=>[n,'0'])),executedBlocks:'65536',executedInstructions:'196608',warmExecutions:'65536'},
  siteCount:64,sitesBefore:64,checksum:'65536',executedIn:'Node Worker / actual Rust Wasm',
  unit:'milliseconds per 1024 complete block operations'});
test('length matrix fixed4x3x2',()=>{assert.deepEqual(LENGTHS,[2,3,6,64]);assert.deepEqual(KINDS,['interpreter','cold','warm']);});
test('length row accepts exact measured count',()=>assert.equal(validateLengthRow(row()),true));
test('length rejects unmeasured threshold length',()=>assert.throws(()=>validateLengthRow({...row(),length:4})));
test('length rejects missing64site warmup',()=>assert.throws(()=>validateLengthRow({...row(),warmupCount:1})));
test('length rejects mismatched warmup instructions',()=>assert.throws(()=>validateLengthRow({...row(),warmupCounters:{executedBlocks:'64',executedInstructions:'3',interpreterSteps:'0'}})));
test('length rejects positive but incomplete JIT execution',()=>{const r=row();r.counters.executedBlocks='1';assert.throws(()=>validateLengthRow(r));});
test('length rejects wrong actual instruction count',()=>{const r=row();r.counters.executedInstructions='65536';assert.throws(()=>validateLengthRow(r));});
test('length rejects budget crossing unsupported',()=>assert.throws(()=>validateLengthRow({...row(),cpuBudget:4})));
test('length rejects observeroff residual counters',()=>assert.throws(()=>validateLengthRow({...row(),observe:false})));
test('length rejects observeroff site mutation',()=>{const r=row();r.observe=false;r.counters=Object.fromEntries(COST_FIELDS.map(n=>[n,'0']));r.siteCount=65;assert.throws(()=>validateLengthRow(r));});
test('length rejects invalid clock denominator',()=>assert.throws(()=>validateLengthRow({...row(),clockCalls:128})));
test('length rejects worker or measurement lifetime leak',()=>assert.throws(()=>validateLengthRow({...row(),measurementRestored:false})));
test('length rejects cold without exact compilation',()=>assert.throws(()=>validateLengthRow({...row(),kind:'cold'})));
test('length rejects interpreter contamination',()=>assert.throws(()=>validateLengthRow({...row(),kind:'interpreter'})));
class FakeWorker extends EventEmitter { cleanup=0;async terminate(){this.cleanup++;return 0} }
test('length exit0 without message rejects and cleans',async()=>{
  const worker=new FakeWorker();queueMicrotask(()=>worker.emit('exit',0));
  await assert.rejects(superviseLengthWorker(worker,50),/exit before message: 0/);assert.equal(worker.cleanup,1);
});
test('length nonzero exit rejects and cleans',async()=>{
  const worker=new FakeWorker();queueMicrotask(()=>worker.emit('exit',7));
  await assert.rejects(superviseLengthWorker(worker,50),/exit before message: 7/);assert.equal(worker.cleanup,1);
});
test('length message resolves unchanged and cleans',async()=>{
  const worker=new FakeWorker(),value={complete:true};queueMicrotask(()=>worker.emit('message',value));
  assert.equal(await superviseLengthWorker(worker,50),value);assert.equal(worker.cleanup,1);
});
test('length silent worker watchdog rejects and cleans',async()=>{
  const worker=new FakeWorker();await assert.rejects(superviseLengthWorker(worker,5),/watchdog/);assert.equal(worker.cleanup,1);
});
