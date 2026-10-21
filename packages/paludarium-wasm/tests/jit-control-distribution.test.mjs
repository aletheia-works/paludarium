import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { cp, mkdir, mkdtemp, readFile, readdir, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
const hash = bytes => createHash("sha256").update(bytes).digest("hex");

// Dedicated module-prepared integration entry. Missing input is an error;
// native expected-results preflight loads only the separate pure cost tests.
test("same-source control packs, imports and runs real hello with natural cleanup", async () => {
  const input=process.env.PALUDARIUM_U14_CONTROL_WASM;
  assert.ok(input,"PALUDARIUM_U14_CONTROL_WASM must explicitly select the fresh control module");
  const root=resolve(dirname(fileURLToPath(import.meta.url)),"../../..");
  const pkg=resolve(root,"packages/paludarium-wasm"), module=await readFile(resolve(root,input));
  const receipt=JSON.parse(await readFile(resolve(root,input)+".receipt.json","utf8"));
  assert.equal(receipt.purpose,"u14-acceptance-control"); assert.equal(receipt.schema,3);
  assert.deepEqual(receipt.features,[]); assert.equal(receipt.module_sha256,hash(module));
  assert.equal(WebAssembly.Module.exports(new WebAssembly.Module(module)).filter(x=>["u14_cost_","u14_micro_","u14_length_"].some(prefix=>x.name.startsWith(prefix))).length,0);
  for(const[name,digest]of Object.entries(receipt.source_files)) assert.equal(hash(await readFile(resolve(root,name))),digest,"fresh control source changed: "+name);
  const manifest=JSON.parse(await readFile(resolve(pkg,"package.json"),"utf8"));
  await mkdir(resolve(root,"target/jit-v2-packed"),{recursive:true});
  const work=await mkdtemp(resolve(root,"target/jit-v2-packed/run-")), staged=resolve(work,"staged");
  await mkdir(staged); await cp(resolve(pkg,"package.json"),resolve(staged,"package.json"));
  for(const name of manifest.files) if(name!=="paludarium.wasm") await cp(resolve(pkg,name),resolve(staged,name));
  await writeFile(resolve(staged,"paludarium.wasm"),module);
  const npmRoot=resolve(homedir(),".local/share/mise/installs/npm-npm"), candidates=[];
  try {
    for(const version of await readdir(npmRoot,{withFileTypes:true})) {
      if(!version.isDirectory()) continue;
      const mise=resolve(npmRoot,version.name,"node_modules/.mise");
      for(const name of await readdir(mise)) if(name.startsWith("npm@")) candidates.push(resolve(mise,name,"node_modules/npm/bin/npm-cli.js"));
    }
  } catch(error) {
    if(error.code!=="ENOENT") throw error;
    // actions/setup-node's actual Node distribution, never a shell shim.
    candidates.push(resolve(dirname(process.execPath),"../lib/node_modules/npm/bin/npm-cli.js"));
  }
  assert.equal(candidates.length,1,"select exactly one real project npm CLI");
  const run=(command,args,cwd=root)=>execFileSync(command,args,{cwd,encoding:"utf8",timeout:60000,killSignal:"SIGKILL",env:{...process.env,PATH:dirname(process.execPath)+":"+process.env.PATH}});
  assert.equal(run(process.execPath,[candidates[0],"--version"]).trim(),"12.2.0");
  const packed=JSON.parse(run(process.execPath,[candidates[0],"pack","--json","--ignore-scripts","--pack-destination",work,"--cache",resolve(root,"target/jit-v2-npm-cache")],staged));
  const reports=Array.isArray(packed)?packed:Object.values(packed); assert.equal(reports.length,1);
  assert.ok(reports[0].files.some(x=>x.path==="jit-support.mjs"));
  run("/usr/bin/tar",["-xzf",resolve(work,reports[0].filename),"-C",work]);
  const directory=resolve(work,"package"),child=resolve(pkg,"tests/packed-distribution-child.mjs"),guest=resolve(pkg,"tests/guests/hello");
  assert.equal(hash(await readFile(resolve(directory,"paludarium.wasm"))),receipt.module_sha256);
  assert.equal(hash(await readFile(guest)),JSON.parse(await readFile(resolve(pkg,"tests/guest-hashes.json"))).hello);
  assert.match(run(process.execPath,[child,directory,guest,"import"]),/packed import PASS/);
  const output=run(process.execPath,[child,directory,guest,"hello"]);
  assert.match(output,/packed dispose PASS/);
  console.log(JSON.stringify({scope:"new same-source control distribution",module_sha256:receipt.module_sha256,tarball_sha256:hash(await readFile(resolve(work,reports[0].filename))),output}));
});
