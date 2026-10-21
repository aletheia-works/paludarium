import test from "node:test";
import assert from "node:assert/strict";
import { evaluate, schedule, validateSchedule } from "./jit-performance.mjs";
function rows(off = 2, on = 1) {
  return Array.from({ length: 10 }, (_, pair) => [false, true].map(jit => ({ pair, jit,
    seconds: jit ? on : off, pass: true, timed_out: false, exit: 0, errors: [],
    statistics: { executedBlocks: "1", executedInstructions: "2" } }))).flat();
}
test("u14 performance schedule is deterministic and balanced", () => {
  assert.deepEqual(schedule(), schedule());
  assert.equal(schedule().filter(pair => pair.modes[0]).length, 5);
  assert.ok(schedule().every(pair => pair.modes[0] !== pair.modes[1]));
});
test("u14 exact all-positive tail is one of1024", () => {
  assert.equal(evaluate(rows()).p, 1 / 1024); assert.equal(evaluate(rows()).pass, true);
});
test("u14 ties and all-negative results cannot pass", () => {
  assert.equal(evaluate(rows(1, 1)).p, 1); assert.equal(evaluate(rows(1, 2)).pass, false);
});
test("u14 missing and duplicate observations fail closed", () => {
  assert.throws(() => evaluate(rows().slice(1)));
  const duplicate = rows(); duplicate[2] = duplicate[0]; assert.throws(() => evaluate(duplicate));
});
test("u14 timeout exit failure and zero execution are retained failures", () => {
  for (const patch of [{ timed_out: true }, { exit: 1 }, { pass: false }, { statistics: { executedBlocks: "0", executedInstructions: "0" } }]) {
    const sample = rows(); Object.assign(sample[1], patch); assert.throws(() => evaluate(sample));
  }
});
test("u14 invalid duration and mode are rejected", () => {
  for (const seconds of [NaN, Infinity, -1, 0, 30.001]) { const sample = rows(); sample[0].seconds = seconds; assert.throws(() => evaluate(sample)); }
  const sample = rows(); sample[0].jit = "false"; assert.throws(() => evaluate(sample));
});

test("u14 frozen execution order cannot be exchanged", () => {
 const planned = schedule().flatMap(pair => pair.modes.map(jit => ({pair:pair.pair,jit})));
 validateSchedule(planned);
 [planned[0],planned[1]]=[planned[1],planned[0]];
 assert.throws(()=>validateSchedule(planned));
});
test("u14 mixed signs agree with independent Cartesian oracle", () => {
 const sample=rows(); const differences=[1,-1,2,-2,0,1,0,-1,2,1];
 for(let i=0;i<10;i++) {sample[2*i].seconds=5+differences[i];sample[2*i+1].seconds=5;}
 let sums=[0];
 for(const difference of differences) sums=sums.flatMap(sum=>[sum-difference,sum+difference]);
 const observed=differences.reduce((a,b)=>a+b,0);
 assert.equal(evaluate(sample).p,sums.filter(sum=>sum>=observed).length/sums.length);
});
