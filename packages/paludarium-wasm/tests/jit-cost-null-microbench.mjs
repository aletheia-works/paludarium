// Independent paired cost-boundary control; no acceptance timing.
import {Worker,parentPort,workerData} from 'node:worker_threads';
import {readFile,mkdir,writeFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {imports} from '../worker-support.mjs';
import {jitImports,COST_FIELDS} from '../jit-support.mjs';
import {validateBuildReceipt} from './jit-cost-profile-check.mjs';
const SELF=fileURLToPath(import.meta.url);
const need=(v,m)=>{if(!v)throw Error(m)};
const hash=b=>createHash('sha256').update(b).digest('hex');
const LENGTHS=[2,3,6,64],KINDS=['interpreter','cold','warm'];
export function matrix(){
  return LENGTHS.flatMap(length=>KINDS.map(kind=>({length,kind}))).flatMap((f,i)=>
    (i%2?['null','off']:['off','null']).map(variant=>({...f,variant})));
}
export function makeCostConnection(variant,callback,factory){
  need(['off','null'].includes(variant),'callback variant');
  const cost=variant==='null'?null:callback;
  return {cost,fresh:()=>factory(cost)};
}
export function validateNullRow(row){
  need(row.functionalOnly!==true,'untimed functional row is not measurement');
  need(['off','null'].includes(row.variant),'callback variant');
  need(row.observe===false&&row.measurementDuring===0,'measurement fixed off');
  need(row.callbackEnabled===(row.variant==='off'),'callback connection identity');
  need(Number.isSafeInteger(row.callbackCallsDuring)&&row.callbackCallsDuring>=0,'callback count');
  if(row.variant==='null')need(row.callbackCallsDuring===0,'null callback called');
  if(row.kind==='interpreter')need(row.callbackCallsDuring===0,'interpreter callback called');
  else if(row.variant==='off')need(row.callbackCallsDuring>0,'off JIT callback boundary not exercised');
  need(KINDS.includes(row.kind)&&LENGTHS.includes(row.length),'fixed fixture');
  need(row.cpuBudget===row.length&&row.fixtureInstructions===row.length,'exact CPU budget');
  need(row.operations===65536&&row.checksum==='65536','exact operations');
  need(row.chunks.length===64&&row.clockOnly.length===64&&[...row.chunks,...row.clockOnly].every(v=>typeof v==='number'&&Number.isFinite(v)&&v>=0),'finite fixed clocks');
  need(row.clockCalls===256&&row.measuredClockCalls===128&&row.clockControlCalls===128,'clock denominator');
  need(row.cleaned===true&&row.measurementRestored===true&&row.warmupExcluded===true,'worker measurement lifetime');
  need(row.warmupCount===64&&row.warmupCpuVerified===true,'all64site warmup');
  need(row.warmupCounters.executedBlocks===(row.kind==='interpreter'?'0':'64')&&row.warmupCounters.executedInstructions===(row.kind==='interpreter'?'0':String(row.length*64))&&row.warmupCounters.interpreterSteps===(row.kind==='interpreter'?String(row.length*64):'0'),'actual warmup count');
  need(Object.keys(row.counters).join()===COST_FIELDS.join()&&Object.values(row.counters).every(v=>v==='0')&&row.siteCount===row.sitesBefore,'disabled observations changed');
  need(row.executedIn==='Node Worker / actual Rust Wasm'&&row.unit==='milliseconds per 1024 complete block operations','measurement identity');
  return true;
}
export function validateNullReport(report){
  need(report.schema===1&&report.purpose==='length-js-cost-boundary-control'&&report.performanceAcceptance===false&&report.complete===true,'distinct complete control report');
  const schedule=matrix();need(report.rows.length===schedule.length,'fixed24 population');
  report.rows.forEach((r,i)=>{const f=schedule[i];need(r.length===f.length&&r.kind===f.kind&&r.variant===f.variant,'fixed alternating schedule');validateNullRow(r)});
  return true;
}
async function child(){
  const {moduleBytes,kind,length,variant,functional=false}=workerData;
  const memory=new WebAssembly.Memory({initial:128,maximum:16384,shared:true});let e,jit,calls=0;
  const callback=(field,value)=>{calls++;need(e.cost_add(field,BigInt(value))===0,'cost overflow')};
  const connection=makeCostConnection(variant,callback,cost=>jitImports(memory,cost));
  const base=imports(memory,{cost:connection.cost});jit=connection.fresh();
  base.paludarium.jit_prepare=(...args)=>{if(kind==='cold')jit=connection.fresh();return jit.prepare(...args)};
  base.paludarium.jit_execute=(...args)=>jit.execute(...args);
  e=(await WebAssembly.instantiate(moduleBytes,base)).instance.exports;
  need(e.cost_version()===3&&typeof e.length_new==='function','length diagnostic ABI');
  e.cost_reset();
  const handle=e.length_new({interpreter:1,cold:2,warm:4}[kind],length,0);
  need(handle>0,'all64site CPU initialization failed');
  const warmupCount=Number(e.length_stat(handle,1));
  need(warmupCount===64&&e.length_stat(handle,0)===0n,'warmup exact64');
  const before=COST_FIELDS.map((_,i)=>e.cost_stat(i));
  const warmupCounters=Object.fromEntries(['executedBlocks','executedInstructions','interpreterSteps'].map(n=>[n,String(before[COST_FIELDS.indexOf(n)])]));
  const sitesBefore=e.cost_site_count(),callsBefore=calls;
  const previous=e.cost_measurement(0);need(previous===1,'fresh measurement state');
  const chunks=[],clockOnly=[];let checksum,restored=false;
  try{
    for(let i=0;i<64;i++){
      if(functional){checksum=e.length_chunk(handle,1);chunks.push(0);clockOnly.push(0)}
      else{
        const c=performance.now();clockOnly.push(performance.now()-c);
        const start=performance.now();checksum=e.length_chunk(handle,1024);chunks.push(performance.now()-start);
      }
      need(checksum===BigInt((i+1)*(functional?1:1024)),'fullCPU/budget/operation assertion failed');
    }
  }finally{
    need(e.cost_measurement(previous)===0,'measurement restoration');restored=true;
  }
  const operations=Number(e.length_stat(handle,0));
  const counters=Object.fromEntries(COST_FIELDS.map((n,i)=>[n,String(e.cost_stat(i)-before[i])]));
  const siteCount=e.cost_site_count();need(e.cost_overflow()===0,'counter overflow');
  e.length_drop(handle);
  parentPort.postMessage({kind,length,variant,observe:false,chunks,clockOnly,operations,cpuBudget:length,fixtureInstructions:length,
    clockCalls:functional?0:256,measuredClockCalls:functional?0:128,clockControlCalls:functional?0:128,
    checksum:String(checksum),counters,warmupCount,warmupCounters,warmupCpuVerified:true,sitesBefore,siteCount,
    measurementRestored:restored,warmupExcluded:true,measurementDuring:0,callbackEnabled:variant==='off',callbackCallsDuring:calls-callsBefore,
    executedIn:'Node Worker / actual Rust Wasm',unit:'milliseconds per 1024 complete block operations',functionalOnly:functional,
    opcodeCycle:'MOV r8d,0xffffffff; MOV ecx,0x22; MOV edx,3',
    timingScope:'Rust diagnostic feature/gate and CPU reset/full-state comparison remain; off callback calls++ observation included; not release; no clock subtraction'});
}
export async function runNullWorker(moduleBytes,fixture){
  return superviseNullWorker(new Worker(new URL(import.meta.url),{workerData:{moduleBytes,...fixture}}));
}
export async function superviseNullWorker(worker,timeout=30000){
  try{return await new Promise((resolve,reject)=>{
    let received=false;const timer=setTimeout(()=>reject(Error('null fixture exceeded watchdog')),timeout);
    worker.once('message',row=>{received=true;clearTimeout(timer);resolve(row)});
    worker.once('error',error=>{clearTimeout(timer);reject(error)});
    worker.once('exit',code=>{clearTimeout(timer);if(!received)reject(Error('null Worker exit before message: '+code))});
  })}finally{await worker.terminate()}
}
export function validateFunctionalNullRow(row){
  need(row.functionalOnly===true&&row.operations===64&&row.checksum==='64'&&row.clockCalls===0&&row.chunks.every(x=>x===0)&&row.clockOnly.every(x=>x===0),'untimed64 functional population');
  return validateNullRow({...row,functionalOnly:false,operations:65536,checksum:'65536',clockCalls:256,measuredClockCalls:128,clockControlCalls:128});
}
export async function main(args){
  need(args.length===3,'usage: diagnostic-module matching-receipt new-output');
  const [modulePath,receiptPath,output]=args;
  const bytes=await readFile(modulePath),receipt=JSON.parse(await readFile(receiptPath,'utf8'));
  validateBuildReceipt(receipt,hash(bytes),process.env.GITHUB_SHA);
  for(const [p,d]of Object.entries(receipt.source_files))need(hash(await readFile(p))===d,'current source changed: '+p);
  await mkdir(output,{recursive:false});
  const report={schema:1,purpose:'length-js-cost-boundary-control',performanceAcceptance:false,head:receipt.head,source_digest:receipt.source_digest,
    module_sha256:hash(bytes),schedule:matrix(),tools:{node:process.version,v8:process.versions.v8},rows:[],complete:false};
  try{
    for(const f of matrix()){
      const row=await runNullWorker(bytes,f);row.cleaned=true;validateNullRow(row);report.rows.push(row);
      await writeFile(resolve(output,'row-'+String(report.rows.length).padStart(2,'0')+'.json'),JSON.stringify(row,null,2)+'\n',{flag:'wx'});
    }
    report.complete=true;validateNullReport(report);
  }catch(error){report.complete=false;report.error=String(error);throw error}
  finally{await writeFile(resolve(output,'observations.json'),JSON.stringify(report,null,2)+'\n',{flag:'wx'})}
  console.log(JSON.stringify({complete:report.complete,rows:report.rows.length,performanceAcceptance:false,source_digest:receipt.source_digest}));
}
if(workerData)await child();
else if(process.argv[1]&&resolve(process.argv[1])===SELF){try{await main(process.argv.slice(2))}catch(error){console.error(String(error));process.exitCode=1}}

