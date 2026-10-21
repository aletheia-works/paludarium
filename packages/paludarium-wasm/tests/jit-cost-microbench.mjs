// Actual Worker/Rust Wasm/C9 bridge chunk timing, separate from probe acceptance.
import {Worker, parentPort, workerData} from 'node:worker_threads';
import {readFile, mkdir, writeFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {imports} from '../worker-support.mjs';
import {jitImports,COST_FIELDS} from '../jit-support.mjs';
import {validateBuildReceipt} from './jit-cost-profile-check.mjs';

const SELF=fileURLToPath(import.meta.url);
const hash=b=>createHash('sha256').update(b).digest('hex');
const need=(v,m)=>{if(!v)throw Error(m)};
export const CHUNKS=64,OPERATIONS=1024;
export const KINDS=['loop','interpreter','cold','negative','warm','epoch','snapshot','extract','emit','prepare','hint','interpreter-hint'];
export function validateRow(row){
  need(KINDS.includes(row.kind)&&typeof row.maximum==='boolean'&&typeof row.observe==='boolean','fixture identity');
  need(row.chunks.length===CHUNKS&&row.operations===CHUNKS*OPERATIONS,'fixed chunk population');
  need(row.unit==='milliseconds per 1024 operations'&&row.clockCalls===4*CHUNKS
    && row.measuredClockCalls===2*CHUNKS&&row.clockControlCalls===2*CHUNKS,'timing denominator');
  need(row.chunks.every(x=>typeof x==='number'&&Number.isFinite(x)&&x>=0),'invalid chunk time');
  need(row.clockOnly.length===CHUNKS&&row.clockOnly.every(x=>Number.isFinite(x)&&x>=0),'clock control');
  need(row.executedIn==='Node Worker / actual Rust Wasm','actual Worker path');
  need(row.cleaned===true&&row.checksum!=='18446744073709551615','worker cleanup/CPU result');
  need(row.measurementRestored===true&&row.warmupExcluded===true,'measurement lifetime');
  if(!row.observe)need(row.siteCount===row.sitesBefore,'disabled site collection changed');
  need(Object.keys(row.counters).join()===COST_FIELDS.join(),'counter population');
  for(const v of Object.values(row.counters))need(typeof v==='string'&&/^(0|[1-9][0-9]*)$/.test(v)&&BigInt(v)<=0xffffffffffffffffn,'counter integer');
  if(row.observe&&['cold','warm','epoch'].includes(row.kind))need(BigInt(row.counters.executedBlocks)>=BigInt(row.operations),'no actual JIT execution');
  if(row.observe&&row.kind==='negative')need(BigInt(row.counters.executedBlocks)===0n&&BigInt(row.counters.negativeHits)>=BigInt(row.operations),'negative fixture mismatch');
  if(row.observe&&row.kind==='prepare')need(BigInt(row.counters.compileAttempts)===BigInt(row.operations),'cold prepare count');
  if(row.observe&&row.kind==='hint')need(BigInt(row.counters.decodeHintHit)===64n*BigInt(row.operations),'all 64 boundaries must hit warmed rejection hints');
  if(!row.observe)need(Object.values(row.counters).every(v=>v==='0'),'disabled aggregate collection changed');
  return true;
}

async function child(){
  const {moduleBytes,kind,maximum,observe}=workerData;
  const module=new WebAssembly.Module(moduleBytes),memory=new WebAssembly.Memory({initial:128,maximum:16384,shared:true});
  let e,jit;
  const cost=(field,value)=>{need(Number.isSafeInteger(value)&&value>=0,'cost value');need(e.u14_cost_add(field,BigInt(value))===0,'cost overflow')};
  const base=imports(memory,{cost});
  jit=jitImports(memory,cost);
  // Cold reset includes JS cache allocation/reset in the measured cost. A new
  // module ID is allocated in Rust for every cold/epoch/prepare operation.
  base.paludarium.jit_prepare=(...args)=>{if(['cold','epoch','prepare'].includes(kind))jit=jitImports(memory,cost);return jit.prepare(...args)};
  base.paludarium.jit_execute=(...args)=>jit.execute(...args);
  e=(await WebAssembly.instantiate(module,base)).exports;
  need(e.u14_cost_version()===3&&typeof e.u14_micro_new==='function','diagnostic microbench ABI missing');
  e.u14_cost_reset();
  const handle=e.u14_micro_new(KINDS.indexOf(kind),Number(maximum),Number(observe));
  need(handle>0,'fixture initialization/untimed warmup failed');
  const before=COST_FIELDS.map((_,i)=>e.u14_cost_stat(i));
  const sitesBefore=e.u14_cost_site_count();
  const previous=e.u14_cost_measurement(Number(observe));
  need(previous===1,'fresh Worker measurement state');
  const chunks=[],clockOnly=[];let checksum;
  try{
  for(let i=0;i<CHUNKS;i++){
    const c=performance.now();clockOnly.push(performance.now()-c);
    const start=performance.now();checksum=e.u14_micro_chunk(handle,OPERATIONS);chunks.push(performance.now()-start);
    need(checksum!==0xffffffffffffffffn,'CPU/bridge fixture failed');
  }
  }finally{need(e.u14_cost_measurement(previous)===Number(observe),'measurement scope restoration');}
  const operations=Number(e.u14_micro_operations(handle));
  const counters=Object.fromEntries(COST_FIELDS.map((name,i)=>[name,String(e.u14_cost_stat(i)-before[i])]));
  const siteCount=e.u14_cost_site_count();
  need(e.u14_cost_overflow()===0,'diagnostic counter overflow');
  e.u14_micro_drop(handle);
  parentPort.postMessage({kind,maximum,observe,chunks,clockOnly,operations,clockCalls:4*CHUNKS,
    measuredClockCalls:2*CHUNKS,clockControlCalls:2*CHUNKS,
    checksum:String(checksum),counters,siteCount,sitesBefore,measurementRestored:true,warmupExcluded:true,unit:'milliseconds per 1024 operations',
    executedIn:'Node Worker / actual Rust Wasm',
    bridgePath:'WorkerJit / jitImports for cold/negative/warm/epoch/prepare fixtures; CPU fixtures do not invoke JS bridge',
    fixtureInstructions:['hint','interpreter-hint'].includes(kind)?64:(maximum?64:2),
    timingScope:'Rust chunk call including CPU reset; cold/epoch/prepare JS cache reset included; constructor and one warmup excluded',
    observationControl:'aggregate and site collection jointly on/off; disabled gate/call residual remains, not a release build',cleaned:false});
}

export async function runWorker(moduleBytes,fixture){
  const worker=new Worker(new URL(import.meta.url),{execArgv:[],workerData:{moduleBytes,...fixture}});
  let timer;
  try{
    return await new Promise((ok,bad)=>{
      timer=setTimeout(()=>bad(Error('microbench fixture 30 second watchdog')),30000);
      worker.once('message',row=>ok(row));worker.once('error',bad);
      worker.once('exit',code=>{if(code!==0)bad(Error('microbench Worker exit '+code))});
    });
  }finally{clearTimeout(timer);await worker.terminate();}
}

export async function main(args,kinds=KINDS){
  need(args.length===3,'usage: diagnostic-module matching-receipt new-output-directory');
  const [modulePath,receiptPath,output]=args;
  const bytes=await readFile(modulePath),receipt=JSON.parse(await readFile(receiptPath,'utf8'));
  validateBuildReceipt(receipt,hash(bytes),process.env.GITHUB_SHA);
  for(const [path,digest]of Object.entries(receipt.source_files))need(hash(await readFile(path))===digest,'current source changed: '+path);
  await mkdir(output,{recursive:false});
  const report={schema:3,purpose:'u14-worker-cost-microbench',performanceAcceptance:false,
    head:receipt.head,source_digest:receipt.source_digest,module_sha256:hash(bytes),
    tools:{node:process.version,v8:process.versions.v8},chunks:CHUNKS,operationsPerChunk:OPERATIONS,rows:[],complete:false};
  try{
    need(kinds.length>0&&new Set(kinds).size===kinds.length&&kinds.every(k=>KINDS.includes(k)),'fixed fixture selection');
    report.fixtureKinds=kinds;
    for(const kind of kinds)for(const maximum of [false,true])for(const observe of [false,true]){
      const row=await runWorker(bytes,{kind,maximum,observe});row.cleaned=true;validateRow(row);
      report.rows.push(row);
      await writeFile(resolve(output,'row-'+String(report.rows.length).padStart(2,'0')+'.json'),JSON.stringify(row,null,2)+'\n',{flag:'wx'});
    }
    report.complete=true;
  }catch(error){report.error=String(error);throw error;}
  finally{await writeFile(resolve(output,'observations.json'),JSON.stringify(report,null,2)+'\n',{flag:'wx'});}
  console.log(JSON.stringify({complete:report.complete,rows:report.rows.length,head:report.head,module_sha256:report.module_sha256}));
}
if(workerData)await child();
else if(process.argv[1]&&resolve(process.argv[1])===SELF){try{await main(process.argv.slice(2))}catch(e){console.error(String(e));process.exitCode=1}}
