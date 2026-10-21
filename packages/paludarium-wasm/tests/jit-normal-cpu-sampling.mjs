// Finite normal-module CPU sampling. Startup/cleanup included; never acceptance.
import {readFile,writeFile,mkdir,readdir,lstat} from 'node:fs/promises';
import {resolve,dirname} from 'node:path';
import {pathToFileURL,fileURLToPath} from 'node:url';
import {spawn} from 'node:child_process';
import {createHash} from 'node:crypto';
import {createPaludarium} from '../index.mjs';
import {observeProgram,compare} from './wasm-programs.mjs';
const SELF=fileURLToPath(import.meta.url),ROOT=resolve(dirname(SELF),'../../..');
const need=(v,m)=>{if(!v)throw Error(m)},sha=b=>createHash('sha256').update(b).digest('hex');
const hex=(v,n=64)=>typeof v==='string'&&new RegExp('^[a-f0-9]{'+n+'}$').test(v);
const persist=(p,v)=>writeFile(p,JSON.stringify(v,null,2)+'\n',{flag:'wx'});
export function validateNormalIdentity(r,moduleHash,head){
 need(hex(head,40)&&r.schema===3&&r.purpose==='acceptance-control'&&r.diagnostic_version===null&&r.local_snapshot===false,'normal signed receipt required');
 need(r.head===head&&r.baseline_signed_head===head&&r.module_sha256===moduleHash&&hex(moduleHash),'normal head/module mismatch');
 need(Array.isArray(r.features)&&r.features.length===0,'normal feature mismatch');
 need(r.source_files&&typeof r.source_files==='object'&&!Array.isArray(r.source_files)&&Object.keys(r.source_files).length>0,'source missing');
 for(const [p,h]of Object.entries(r.source_files))need(!p.startsWith('/')&&!p.includes('\\')&&!p.split('/').some(v=>!v||v==='.'||v==='..')&&hex(h),'unsafe source');
 const sorted=Object.fromEntries(Object.keys(r.source_files).sort().map(p=>[p,r.source_files[p]]));
 need(sha(JSON.stringify(sorted))===r.source_digest,'source digest mismatch');
 const locks=['Cargo.lock','fuzz/Cargo.lock','tests/guests/programs/source-lock.json','tests/guests/programs/probe/Cargo.lock','rust-toolchain.toml','deny.toml'];
 need(Object.keys(r.locks).sort().join()===locks.sort().join(),'six locks required');
 for(const p of locks)need(r.locks[p]===r.source_files[p]&&hex(r.locks[p]),'lock mismatch');
 return true;
}
export function parseProfile(p){
 need(p&&Array.isArray(p.nodes)&&p.nodes.length>0&&p.nodes.length<=100000,'profile nodes missing/unbounded');
 need(Array.isArray(p.samples)&&p.samples.length>0&&p.samples.length<=250000,'profile samples missing/unbounded');
 need(Array.isArray(p.timeDeltas)&&p.timeDeltas.length===p.samples.length&&p.timeDeltas.every(v=>Number.isFinite(v)&&v>=0),'profile deltas invalid');
 need(Number.isFinite(p.startTime)&&Number.isFinite(p.endTime)&&p.endTime>=p.startTime,'profile window invalid');
 const nodes=new Map(),parents=new Map(),self=new Map(),colors=new Map(),inclusive=new Map();
 for(const n of p.nodes){need(Number.isSafeInteger(n.id)&&n.id>0&&!nodes.has(n.id),'duplicate/invalid node');need(n.callFrame&&typeof n.callFrame==='object','callFrame missing');nodes.set(n.id,n);self.set(n.id,0)}
 for(const n of p.nodes){
  need(n.children===undefined||Array.isArray(n.children),'children invalid');
  const seen=new Set();
  for(const id of n.children??[]){need(nodes.has(id)&&!seen.has(id)&&!parents.has(id),'child absent/duplicate/multiple parents');seen.add(id);parents.set(id,n.id)}
 }
 for(const id of p.samples){need(nodes.has(id),'unknown sample');self.set(id,self.get(id)+1)}
 // Iterative postorder avoids stack overflow for adversarial deep profiles.
 for(const root of nodes.keys()){
  if(colors.get(root)===2)continue;
  const stack=[[root,false]];
  while(stack.length){
   const [id,exit]=stack.pop();
   if(exit){inclusive.set(id,self.get(id)+(nodes.get(id).children??[]).reduce((s,c)=>s+inclusive.get(c),0));colors.set(id,2);continue}
   need(colors.get(id)!==1,'profile child cycle');if(colors.get(id)===2)continue;
   colors.set(id,1);stack.push([id,true]);
   for(const child of nodes.get(id).children??[])stack.push([child,false]);
  }
 }
 return {samples:p.samples.length,startTime:p.startTime,endTime:p.endTime,timeDeltasSum:p.timeDeltas.reduce((s,x)=>s+x,0),
  nodes:p.nodes.map(n=>{const f=n.callFrame,name=typeof f.functionName==='string'?f.functionName:'',url=typeof f.url==='string'?f.url:'';
   return {id:n.id,name,url,lineNumber:f.lineNumber??null,columnNumber:f.columnNumber??null,category:/wasm-function|wasm:/.test(name+' '+url)?'wasm':name&&url?'javascript':'unknown',selfSamples:self.get(n.id),inclusiveSamples:inclusive.get(n.id)}})};
}
export function validateChildResult(r,jit){
 need(r&&r.jit===jit&&r.pass===true&&r.exit===0&&r.timed_out===false&&r.cleaned===true&&r.errors.length===0,'child result/cleanup failure');
 need(Number.isFinite(r.seconds)&&r.seconds>0&&r.seconds<=30,'guest deadline');
 need(r.stdout.split('\n').filter(s=>s.startsWith('PASS ')).length===8,'eight PASS required');
 if(jit)need(BigInt(r.statistics?.executedBlocks??0)>0n&&BigInt(r.statistics?.executedInstructions??0)>0n,'actual JIT required');
 return true;
}
export function requireWasmSamples(rows){
 need(rows.some(p=>p.analysis.nodes.some(n=>n.category==='wasm'&&n.selfSamples>0)),'normal Wasm sampled execution missing');
}
export function superviseChild(child,{timeout=90000,terminate}={}){
 return new Promise(resolve=>{
  const stdout=[],stderr=[];let timed_out=false,error=null,closed=false,bytes=0,droppedBytes=0,reapTimer;
  const finish=(exit,signal,reaped)=>{if(closed)return;closed=true;clearTimeout(timer);clearTimeout(reapTimer);resolve({exit,signal,timed_out,error,stdout:Buffer.concat(stdout),stderr:Buffer.concat(stderr),reaped,droppedBytes})};
  const stop=()=>{try{terminate()}catch(e){error=String(e)}if(!reapTimer)reapTimer=setTimeout(()=>finish(null,null,false),5000)};
  const timer=setTimeout(()=>{timed_out=true;stop()},timeout);
  const data=(list,b)=>{const kept=Math.min(b.length,Math.max(0,8*1024*1024-bytes));if(kept)list.push(Buffer.from(b.subarray(0,kept)));bytes+=kept;droppedBytes+=b.length-kept;if(droppedBytes){error='child output cap';stop()}};
  child.stdout.on('data',b=>data(stdout,b));child.stderr.on('data',b=>data(stderr,b));
  child.once('error',e=>{error=String(e);stop()});
  child.once('close',(exit,signal)=>finish(exit,signal,true));
 });
}
async function cleanGroup(pid){
 try{process.kill(-pid,'SIGKILL')}catch(e){if(e.code==='ESRCH')return true;throw e}
 for(let i=0;i<100;i++){
  try{process.kill(-pid,0)}catch(e){if(e.code==='ESRCH')return true;throw e}
  await new Promise(r=>setTimeout(r,10));
 }
 return false;
}
async function inventory(directory){
 const paths=[];
 for(const entry of await readdir(directory,{withFileTypes:true})){
  const p=resolve(directory,entry.name);need(!(await lstat(p)).isSymbolicLink(),'linked profile input');
  if(entry.isDirectory())paths.push(...await inventory(p));else paths.push(p);
 }
 return paths;
}
async function identity(modulePath,receiptPath,oraclePath,probePath){
 const bytes=await readFile(modulePath),rr=await readFile(receiptPath),r=JSON.parse(rr);
 validateNormalIdentity(r,sha(bytes),process.env.GITHUB_SHA);
 const module=new WebAssembly.Module(bytes);
 need(WebAssembly.Module.exports(module).filter(e=>/^(cost|micro|length)__/.test(e.name)).length===0,'diagnostic export in normal module');
 const oracleBytes=await readFile(oraclePath),oracle=JSON.parse(oracleBytes),probe=await readFile(probePath);
 need(oracle.native_complete===true&&oracle.binary_hashes.probe===sha(probe)&&oracle.rows['probe-all']?.exit===0,'fresh oracle/probe mismatch');
 const before={};
 for(const [p,h]of Object.entries(r.source_files)){const file=resolve(ROOT,p);need(!(await lstat(file)).isSymbolicLink()&&sha(await readFile(file))===h,'current source changed: '+p);before[p]=h}
 return {r,oracle,probe,before,identity:{head:r.head,module_sha256:sha(bytes),source_digest:r.source_digest,receipt_sha256:sha(rr),oracle_sha256:sha(oracleBytes),probe_sha256:sha(probe),normalDiagnosticExports:0,wasmNameSectionBytes:WebAssembly.Module.customSections(module,'name').reduce((s,b)=>s+b.byteLength,0)}};
}
async function runGuest(args,jit){
 const [modulePath,receiptPath,oraclePath,probePath,out]=args;
 const input=await identity(modulePath,receiptPath,oraclePath,probePath);
 let launcher,row,error;
 try{
  launcher=await createPaludarium({wasmUrl:pathToFileURL(resolve(modulePath))});
  row=await observeProgram(launcher,{program:'/probe',args:['/probe'],env:input.oracle.case_config.environment,files:{'/probe':new Uint8Array(input.probe),'/home/guest/.keep':new Uint8Array()},jit});
  row.jit=jit;row.cleaned=false;
  if(jit&&!row.timed_out)row.statistics=(await launcher.diagnostics()).workers.filter(w=>!w.guestThread).at(-1)?.jit;
  compare(input.oracle.rows['probe-all'],row,input.oracle.fixture_root);row.pass=true;
 }catch(e){error=e;if(row){row.pass=false;row.error=String(e)}}
 finally{
  if(launcher){try{await launcher.dispose();if(row)row.cleaned=true}catch(e){error=e;if(row){row.cleaned=false;row.cleanup_error=String(e)}}}
  await persist(resolve(out,'child-result.json'),row??{jit,pass:false,error:String(error),cleaned:false});
 }
 if(error)throw error;validateChildResult(row,jit);
}
export async function main(args){
 need(args.length===5,'usage: normal-module receipt fresh-oracle probe exclusive-output');
 need(!process.execPath.includes('/shims/'),'actual Node required, not a version-manager shim');
 const input=await identity(...args.slice(0,4));const out=resolve(args[4]);await mkdir(out,{recursive:false});
 const inputHashes=Object.fromEntries(await Promise.all(args.slice(0,4).map(async p=>[resolve(p),sha(await readFile(p))])));
 const report={schema:1,purpose:'normal-cpu-sampling',performanceAcceptance:false,...input.identity,tools:{node:process.version,nodePath:process.execPath,v8:process.versions.v8},samplingIntervalMicroseconds:1000,scope:'full process window including startup, guest and strict cleanup; sampled counts not elapsed attribution or acceptance',rows:[],complete:false,passed:false};
 const controllerStarted=Date.now(),deadline=controllerStarted+180000;
 let activeTerminate=null,wholeTimedOut=false;
 const wholeTimer=setTimeout(()=>{wholeTimedOut=true;try{activeTerminate?.()}catch{}},180000);
 try{
  for(const jit of [false,true]){
   need(Date.now()<deadline,'whole controller deadline before child');
   const d=resolve(out,jit?'jit':'interpreter');await mkdir(d);const profiles=resolve(d,'profiles');await mkdir(profiles);
   const childArgs=['--cpu-prof','--cpu-prof-interval=1000','--cpu-prof-dir='+profiles,SELF,'--child',String(jit),...args.slice(0,4),d];
   await persist(resolve(d,'started.json'),{argv:[process.execPath,...childArgs],jit,head:input.r.head,wholeDeadlineMilliseconds:180000,childTimeoutMilliseconds:90000});
   const child=spawn(process.execPath,childArgs,{cwd:ROOT,env:process.env,detached:true,stdio:['ignore','pipe','pipe']});
   const terminate=()=>{try{process.kill(-child.pid,'SIGKILL')}catch(e){if(e.code!=='ESRCH')throw e}};
   activeTerminate=terminate;
   const result=await superviseChild(child,{timeout:Math.max(1,Math.min(90000,deadline-Date.now())),terminate});
   // Child close reaps the leader; remove any owned descendants even after exit0.
   let groupCleaned=false;try{groupCleaned=await cleanGroup(child.pid)}catch(e){result.cleanup_error=String(e)}
   await writeFile(resolve(d,'stdout.bin'),result.stdout,{flag:'wx'});await writeFile(resolve(d,'stderr.bin'),result.stderr,{flag:'wx'});
   await persist(resolve(d,'process-result.json'),{...result,stdout:undefined,stderr:undefined,stdout_sha256:sha(result.stdout),stderr_sha256:sha(result.stderr),groupCleaned});
   const files=await inventory(profiles),profileRows=[];
   await persist(resolve(d,'profile-files.json'),{files:files.map(p=>p.slice(profiles.length+1)),partial:result.exit!==0||result.timed_out});
   need(files.length>=1&&files.length<=32&&files.every(p=>p.endsWith('.cpuprofile')),'profile population');
   let totalProfileBytes=0;
   for(const p of files){const stat=await lstat(p);totalProfileBytes+=stat.size;need(stat.size<=64*1024*1024&&totalProfileBytes<=128*1024*1024,'profile file/total cap');const b=await readFile(p);profileRows.push({name:p.slice(profiles.length+1),bytes:b.length,sha256:sha(b),analysis:parseProfile(JSON.parse(b))})}
   await persist(resolve(d,'profile-analysis.json'),profileRows);
   need(!wholeTimedOut&&Date.now()<=deadline,'whole controller180s deadline');
   need(result.exit===0&&!result.signal&&!result.timed_out&&!result.error&&result.reaped&&groupCleaned,'child process/cleanup failed');
   need(files.length>=1&&files.length<=32&&files.every(p=>p.endsWith('.cpuprofile')),'profile population');
   const row=JSON.parse(await readFile(resolve(d,'child-result.json'),'utf8'));validateChildResult(row,jit);
   requireWasmSamples(profileRows);
   report.rows.push({jit,child:row,profiles:profileRows,processGroupCleaned:groupCleaned,argv:[process.execPath,...childArgs],process_stdout_sha256:sha(result.stdout),process_stderr_sha256:sha(result.stderr)});
  }
  for(const [p,h]of Object.entries(input.before))need(sha(await readFile(resolve(ROOT,p)))===h,'source changed after sampling');
  for(const [p,h]of Object.entries(inputHashes))need(sha(await readFile(p))===h,'module/receipt/oracle/probe changed after sampling');
  report.complete=true;report.passed=true;
 }catch(e){report.error=String(e);throw e}
 finally{
  clearTimeout(wholeTimer);report.wholeTimedOut=wholeTimedOut;
  report.input_before=inputHashes;report.input_after={};
  for(const p of Object.keys(inputHashes)){try{report.input_after[p]=sha(await readFile(p))}catch{report.input_after[p]=null}}
  report.source_before=input.before;report.source_after={};
  for(const p of Object.keys(input.before)){try{report.source_after[p]=sha(await readFile(resolve(ROOT,p)))}catch{report.source_after[p]=null}}
  report.raw_files=[];
  for(const p of await inventory(out)){const b=await readFile(p);report.raw_files.push({name:p.slice(out.length+1),bytes:b.length,sha256:sha(b)})}
  report.controllerElapsedMilliseconds=Date.now()-controllerStarted;report.cleanupGraceMilliseconds=5000;
  report.profileCaps={filesPerVariant:32,bytesPerFile:64*1024*1024,totalBytesPerVariant:128*1024*1024,nodesPerFile:100000,samplesPerFile:250000};
  if(wholeTimedOut||Date.now()>deadline){report.complete=false;report.passed=false;report.error='whole controller180s deadline exceeded'}
  await persist(resolve(out,'observations.json'),report);
 }
 need(report.passed,'sampling diagnostic incomplete');
 console.log(JSON.stringify({head:report.head,complete:report.complete,rows:report.rows.length,performanceAcceptance:false}));
}
if(process.argv[1]&&resolve(process.argv[1])===SELF){
 try{if(process.argv[2]==='--child'){need(['false','true'].includes(process.argv[3]),'child mode');await runGuest(process.argv.slice(4),process.argv[3]==='true')}else await main(process.argv.slice(2))}
 catch(e){console.error(String(e));process.exitCode=1}
}

