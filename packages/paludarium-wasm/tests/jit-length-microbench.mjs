// Separate24-row diagnostic matrix. No acceptance timing and no legacy48 changes.
import {Worker,parentPort,workerData} from 'node:worker_threads';
import {readFile,mkdir,writeFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {imports} from '../worker-support.mjs';
import {jitImports,COST_FIELDS} from '../jit-support.mjs';
import {validateBuildReceipt} from './jit-cost-profile-check.mjs';
const SELF=fileURLToPath(import.meta.url),CHUNKS=64,OPERATIONS=1024;
const need=(value,message)=>{if(!value)throw Error(message)};
const hash=raw=>createHash('sha256').update(raw).digest('hex');
export const LENGTHS=[2,3,6,64],KINDS=['interpreter','cold','warm'];
export function validateLengthRow(row){
  need(KINDS.includes(row.kind)&&LENGTHS.includes(row.length)&&typeof row.observe==='boolean','fixed fixture identity');
  need(row.cpuBudget===row.length&&row.fixtureInstructions===row.length,'exact instruction budget');
  need(row.operations===65536&&row.chunks.length===64&&row.clockOnly.length===64,'fixed chunk population');
  need([...row.chunks,...row.clockOnly].every(v=>typeof v==='number'&&Number.isFinite(v)&&v>=0),'finite clock values');
  need(row.clockCalls===256&&row.measuredClockCalls===128&&row.clockControlCalls===128,'clock denominator');
  need(row.unit==='milliseconds per 1024 complete block operations'&&row.executedIn==='Node Worker / actual Rust Wasm','measurement identity');
  need(row.cleaned===true&&row.measurementRestored===true&&row.warmupExcluded===true,'worker/measurement lifetime');
  need(row.warmupCount===64&&row.warmupCpuVerified===true,'all64site CPU preparation');
  const instructions=String(64*row.length),measured=String(65536*row.length);
  need(row.warmupCounters.executedBlocks===(row.kind==='interpreter'?'0':'64')&&
    row.warmupCounters.executedInstructions===(row.kind==='interpreter'?'0':instructions)&&
    row.warmupCounters.interpreterSteps===(row.kind==='interpreter'?instructions:'0'),'warmup actual counters');
  need(Object.keys(row.counters).join()===COST_FIELDS.join(),'fixed120 counter population');
  for(const value of Object.values(row.counters))need(typeof value==='string'&&/^(0|[1-9][0-9]*)$/.test(value)&&BigInt(value)<=0xffffffffffffffffn,'u64 counter');
  need(row.checksum==='65536','exact completed operations');
  if(!row.observe){need(Object.values(row.counters).every(v=>v==='0')&&row.siteCount===row.sitesBefore,'disabled observations changed');return true;}
  need(row.counters.executedBlocks===(row.kind==='interpreter'?'0':'65536'),'actual JIT block count');
  need(row.counters.executedInstructions===(row.kind==='interpreter'?'0':measured),'actual JIT instruction count');
  need(row.counters.interpreterSteps===(row.kind==='interpreter'?measured:'0'),'actual interpreter instruction count');
  if(row.kind==='cold')need(row.counters.compileAttempts==='65536','cold compilation count');
  if(row.kind==='warm')need(row.counters.warmExecutions==='65536'&&row.counters.compileAttempts==='0','all64 warmed sites reused');
  return true;
}
async function child(){
  const {moduleBytes,kind,length,observe}=workerData;
  const memory=new WebAssembly.Memory({initial:128,maximum:16384,shared:true});let e,jit;
  const cost=(field,value)=>need(e.cost_add(field,BigInt(value))===0,'cost overflow');
  const base=imports(memory,{cost});jit=jitImports(memory,cost);
  base.paludarium.jit_prepare=(...args)=>{if(kind==='cold')jit=jitImports(memory,cost);return jit.prepare(...args)};
  base.paludarium.jit_execute=(...args)=>jit.execute(...args);
  e=(await WebAssembly.instantiate(moduleBytes,base)).instance.exports;
  need(e.cost_version()===3&&typeof e.length_new==='function','diagnostic length ABI missing');
  e.cost_reset();
  const handle=e.length_new({interpreter:1,cold:2,warm:4}[kind],length,Number(observe));
  need(handle>0,'all64site CPU initialization failed');
  const warmupCount=Number(e.length_stat(handle,1));
  need(warmupCount===64&&e.length_stat(handle,0)===0n,'warmup counted as timed work');
  const before=COST_FIELDS.map((_,i)=>e.cost_stat(i));
  const warmupCounters=Object.fromEntries(['executedBlocks','executedInstructions','interpreterSteps'].map(n=>[n,String(before[COST_FIELDS.indexOf(n)])]));
  const sitesBefore=e.cost_site_count();
  const previous=e.cost_measurement(Number(observe));need(previous===1,'fresh Worker measurement state');
  const chunks=[],clockOnly=[];let checksum;
  try{
    for(let i=0;i<CHUNKS;i++){
      const c=performance.now();clockOnly.push(performance.now()-c);
      const start=performance.now();checksum=e.length_chunk(handle,OPERATIONS);chunks.push(performance.now()-start);
      need(checksum===BigInt((i+1)*OPERATIONS),'exact block CPU/budget/count failed');
    }
  }finally{need(e.cost_measurement(previous)===Number(observe),'measurement scope restoration');}
  const operations=Number(e.length_stat(handle,0));
  const counters=Object.fromEntries(COST_FIELDS.map((n,i)=>[n,String(e.cost_stat(i)-before[i])]));
  const siteCount=e.cost_site_count();need(e.cost_overflow()===0,'diagnostic overflow');e.length_drop(handle);
  parentPort.postMessage({kind,length,observe,chunks,clockOnly,operations,cpuBudget:length,fixtureInstructions:length,
    clockCalls:256,measuredClockCalls:128,clockControlCalls:128,checksum:String(checksum),counters,
    warmupCount,warmupCounters,warmupCpuVerified:true,sitesBefore,siteCount,measurementRestored:true,warmupExcluded:true,
    executedIn:'Node Worker / actual Rust Wasm',unit:'milliseconds per 1024 complete block operations',
    opcodeCycle:'MOV r8d,0xffffffff; MOV ecx,0x22; MOV edx,3',sites:64,
    timingScope:'CPU reset/full CPU comparison and Rust loop included; oneJS ABI call per1024 blocks; cold JS cache reset included'});
}
export async function runLengthWorker(moduleBytes,fixture){
  const worker=new Worker(new URL(import.meta.url),{workerData:{moduleBytes,...fixture}});
  return superviseLengthWorker(worker);
}
export async function superviseLengthWorker(worker,timeout=30000){
  try{return await new Promise((resolve,reject)=>{
    let received=false;
    const timer=setTimeout(()=>reject(Error('length fixture exceeded watchdog')),timeout);
    worker.once('message',row=>{received=true;clearTimeout(timer);resolve(row)});
    worker.once('error',error=>{clearTimeout(timer);reject(error)});
    worker.once('exit',code=>{clearTimeout(timer);if(!received)reject(Error('length Worker exit before message: '+code))});
  })}finally{await worker.terminate()}
}
export async function main(args){
  need(args.length===3,'usage: diagnostic-module matching-receipt new-output');
  const [modulePath,receiptPath,output]=args;
  const bytes=await readFile(modulePath),receipt=JSON.parse(await readFile(receiptPath,'utf8'));
  validateBuildReceipt(receipt,hash(bytes),process.env.GITHUB_SHA);
  for(const [path,digest]of Object.entries(receipt.source_files))need(hash(await readFile(path))===digest,'current source changed: '+path);
  await mkdir(output,{recursive:false});
  const report={schema:1,purpose:'fixed-length-worker-microbench',performanceAcceptance:false,
    head:receipt.head,source_digest:receipt.source_digest,module_sha256:hash(bytes),lengths:LENGTHS,kinds:KINDS,
    chunks:64,operationsPerChunk:1024,tools:{node:process.version,v8:process.versions.v8},rows:[],complete:false};
  try{
    for(const length of LENGTHS)for(const kind of KINDS)for(const observe of [false,true]){
      const row=await runLengthWorker(bytes,{kind,length,observe});row.cleaned=true;validateLengthRow(row);report.rows.push(row);
      await writeFile(resolve(output,'row-'+String(report.rows.length).padStart(2,'0')+'.json'),JSON.stringify(row,null,2)+'\n',{flag:'wx'});
    }
    report.complete=true;
  }catch(error){report.error=String(error);throw error}
  finally{await writeFile(resolve(output,'observations.json'),JSON.stringify(report,null,2)+'\n',{flag:'wx'})}
  console.log(JSON.stringify({complete:report.complete,rows:report.rows.length,performanceAcceptance:false,source_digest:receipt.source_digest}));
}
if(workerData)await child();
else if(process.argv[1]&&resolve(process.argv[1])===SELF){try{await main(process.argv.slice(2))}catch(error){console.error(String(error));process.exitCode=1}}
