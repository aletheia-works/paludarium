import test from 'node:test';
import assert from 'node:assert/strict';
import { lines, population } from './jit-coverage.mjs';
const script = ranges => ({functions: [{ranges}]});
test('fixed six-file population preserves prior denominator', () => assert.deepEqual(population, ['index.mjs','coordinator.mjs','execution.mjs','worker-support.mjs','filesystem-snapshot.mjs','jit-support.mjs']));
test('uncalled nested function overrides containing execution', () => {
 const source='a\nb\nc';
 assert.deepEqual(lines(source,[script([{startOffset:0,endOffset:5,count:1},{startOffset:2,endOffset:3,count:0}])]).map(x=>x.hit),[true,false,true]);
});
test('V8 offsets use UTF16 including surrogate pairs', () => {
 assert.deepEqual(lines('😀\nx',[script([{startOffset:3,endOffset:4,count:1}])]).map(x=>x.hit),[false,true]);
});
test('independent process execution merges', () => {
 assert.equal(lines('x',[script([{startOffset:0,endOffset:1,count:0}]),script([{startOffset:0,endOffset:1,count:1}])])[0].hit,true);
});
test('missing raw script keeps denominator and misses', () => assert.deepEqual(lines('x\n}',[]),[{line:1,hit:false},{line:2,hit:false}]));
test('comment terminator with code is measured', () => {
 const result=lines('/* start\n */ x\n// comment\n}',[]);
 assert.deepEqual(result.map(x=>x.line),[2,4]);
});
test('inline comment with code is measured', () => assert.equal(lines('/* text */ x',[]).length,1));
