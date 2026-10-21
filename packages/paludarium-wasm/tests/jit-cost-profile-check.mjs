import { readFile, writeFile, mkdir, lstat } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { createPaludarium } from "../index.mjs";
import { COST_FIELDS } from "../jit-support.mjs";
import { compare, observeProgram } from "./wasm-programs.mjs";

const ROOT = fileURLToPath(new URL("../../../", import.meta.url));
const hash = bytes => createHash("sha256").update(bytes).digest("hex");
const hex = value => typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
const need = (value, message) => { if (!value) throw Error(message); };
const digestMap = rows => hash(JSON.stringify(Object.fromEntries(Object.keys(rows).sort().map(name => [name, rows[name]]))));

export function validateBuildReceipt(receipt, moduleHash, expectedHead) {
  need(receipt.schema === 3 && receipt.diagnostic_version === 3 && receipt.purpose === "u14-cost-profile"
    && JSON.stringify(receipt.features) === '["u14-cost-profile"]', "Diagnostic build receipt required");
  need(receipt.module_sha256 === moduleHash && hex(moduleHash) && hex(receipt.source_digest), "Diagnostic module identity mismatch");
  need(receipt.source_files && typeof receipt.source_files === "object"
    && !Array.isArray(receipt.source_files) && Object.keys(receipt.source_files).length > 0, "Source closure missing");
  for (const [name, digest] of Object.entries(receipt.source_files)) {
    need(name && !name.startsWith("/") && !name.includes("\\") && !name.split("/").some(x => !x || x === "." || x === "..") && hex(digest), "Unsafe source closure");
  }
  need(digestMap(receipt.source_files) === receipt.source_digest, "Source closure digest mismatch");
  for (const name of ["Cargo.lock", "fuzz/Cargo.lock", "tests/guests/programs/source-lock.json", "tests/guests/programs/probe/Cargo.lock", "rust-toolchain.toml", "deny.toml"]) {
    need(receipt.locks?.[name] === receipt.source_files[name] && hex(receipt.locks[name]), "Lock/source closure mismatch");
  }
  if (expectedHead) need(receipt.head === expectedHead && receipt.local_snapshot === false, "Diagnostic CI head mismatch");
  else need(receipt.local_snapshot === true && receipt.head === "local:" + receipt.source_digest, "Local diagnostic snapshot identity missing");
}

export function validateProfileReport(report, identity) {
  need(report.schema === 3 && report.purpose === "u14-cost-profile"
    && report.performanceAcceptance === false && report.complete === true, "Not a completed diagnostic report");
  for (const key of ["head", "module_sha256", "source_digest", "oracle_sha256", "probe_sha256"]) {
    need(report[key] === identity[key], "Diagnostic receipt identity mismatch: " + key);
  }
  need(Array.isArray(report.rows) && report.rows.length === 2 && report.rows[0].jit === false && report.rows[1].jit === true, "Exactly one observation per mode required");
  for (const row of report.rows) {
    need(row.pass === true && row.exit === 0 && row.timed_out === false && Array.isArray(row.errors)
      && row.errors.length === 0 && Number.isFinite(row.seconds) && row.seconds > 0 && row.seconds <= 30
      && row.cleaned === true, "Diagnostic guest failed/deadline/cleanup");
    const cost = row.costProfile;
    need(cost?.schema === 3 && cost.purpose === "u14-cost-profile" && cost.overflow === false, "Diagnostic collector missing/overflow");
    need(JSON.stringify(Object.keys(cost.counters ?? {})) === JSON.stringify(COST_FIELDS), "Diagnostic field population mismatch");
    for (const value of Object.values(cost.counters)) need(typeof value === "string" && /^(0|[1-9][0-9]*)$/.test(value) && BigInt(value) <= 0xffffffffffffffffn, "Invalid diagnostic counter");
    need(cost.sites?.capacity === 16384 && cost.sites.retainedOnly === true && Array.isArray(cost.sites.rows)
      && cost.sites.rows.length <= 16384, "Site population invalid");
    const keys = new Set(); let retained = 0n;
    for (const site of cost.sites.rows) {
      for(const field of ["space","epoch","rip","classification","count"])
        need(typeof site[field] === "string" && /^(0|[1-9][0-9]*)$/.test(site[field]) && BigInt(site[field]) <= 0xffffffffffffffffn,"Invalid site integer");
      const key=[site.space,site.epoch,site.rip,site.classification].join(":");
      need(!keys.has(key) && BigInt(site.count)>0n && BigInt(site.classification)>=1n && BigInt(site.classification)<=5n,"Duplicate/invalid site");keys.add(key);
      need(typeof site.descriptor==="string" && site.descriptor.length<=256 && typeof site.truncated==="boolean","Invalid site descriptor");
      retained += BigInt(site.count);
    }
    need(retained + BigInt(cost.counters.siteDropped) === BigInt(cost.counters.siteObserved),"Site retained/dropped denominator mismatch");
    need(BigInt(cost.counters.checkpoints) > 0n, "No actual Runtime checkpoint");
    if (row.jit) {
      need(BigInt(cost.counters.executedBlocks) > 0n && BigInt(cost.counters.executedInstructions) > 0n
        && BigInt(cost.counters.compileAttempts) > 0n && BigInt(cost.counters.jsTransitions) > 0n, "No actual JIT/compile diagnostic");
      const histogram = COST_FIELDS.slice(24, 88).reduce((sum, name) => sum + BigInt(cost.counters[name]), 0n);
      need(histogram === BigInt(cost.counters.executedBlocks), "Block histogram incomplete");
      const sum = names => names.reduce((value, name) => value + BigInt(cost.counters[name]), 0n);
      need(sum(["nextPositive", "nextMissing", "nextNegative", "nextEpoch"]) === BigInt(cost.counters.executedBlocks), "Next boundary population incomplete");
      need(sum(["nextPrepared", "nextUnprepared", "nextUnavailable"]) === BigInt(cost.counters.nextPositive), "Prepared observation population incomplete");
    } else need(BigInt(cost.counters.executedBlocks) === 0n && BigInt(cost.counters.compileAttempts) === 0n
      && COST_FIELDS.slice(88).every(name => cost.counters[name] === "0"), "Interpreter observation contains JIT");
  }
  return true;
}

export async function collectProfile({ modulePath, oraclePath, guests, output }) {
  const moduleBytes = await readFile(modulePath), receipt = JSON.parse(await readFile(modulePath + ".receipt.json", "utf8"));
  validateBuildReceipt(receipt, hash(moduleBytes), process.env.GITHUB_SHA);
  const module = new WebAssembly.Module(moduleBytes);
  need(WebAssembly.Module.exports(module).some(x => x.name === "u14_cost_version"), "Ordinary release module is not a diagnostic module");
  for (const [name, digest] of Object.entries(receipt.source_files)) {
    const path = resolve(ROOT, name);
    need(!(await lstat(path)).isSymbolicLink() && hash(await readFile(path)) === digest, "Current source differs from diagnostic build: " + name);
  }
  const oracleBytes = await readFile(oraclePath), oracle = JSON.parse(oracleBytes), probe = await readFile(resolve(guests, "probe"));
  need(oracle.native_complete === true && hash(probe) === oracle.binary_hashes.probe && oracle.rows["probe-all"]?.exit === 0, "Fresh matching probe/native oracle required");
  const identity = { head: receipt.head, module_sha256: hash(moduleBytes), source_digest: receipt.source_digest,
    oracle_sha256: hash(oracleBytes), probe_sha256: hash(probe) };
  const report = { schema: 3, purpose: "u14-cost-profile", performanceAcceptance: false, ...identity,
    baseline_signed_head: receipt.baseline_signed_head, local_snapshot: receipt.local_snapshot, tools: { node: process.version },
    scope: "one fresh launcher/shared heap per mode; all guest Workers aggregate; times are diagnostic only",
    rows: [], complete: false, passed: false };
  await mkdir(output, { recursive: true });
  const persist = () => writeFile(resolve(output, "observations.json"), JSON.stringify(report, null, 2) + "\n");
  await persist();
  try {
    for (const jit of [false, true]) {
      const launcher = await createPaludarium({ wasmUrl: pathToFileURL(resolve(modulePath)) });
      let row;
      try {
        row = await observeProgram(launcher, { program: "/probe", args: ["/probe"], env: oracle.case_config.environment,
          files: { "/probe": new Uint8Array(probe), "/home/u10/.keep": new Uint8Array() }, jit });
        row.jit = jit; row.cleaned = false; report.rows.push(row); await persist();
        compare(oracle.rows["probe-all"], row, oracle.fixture_root);
        need(row.exit === 0 && !row.timed_out, "Diagnostic probe failed");
        const diagnostics = await launcher.diagnostics();
        row.costProfile = diagnostics.workers.filter(worker => !worker.guestThread).at(-1)?.costProfile;
        row.pass = true;
      } finally {
        await launcher.dispose();
        if (row) { row.cleaned = true; await persist(); }
      }
    }
    report.complete = true;
    validateProfileReport(report, identity);
    report.passed = true;
  } catch (error) {
    report.error = String(error);
    throw error;
  } finally { await persist(); }
  return report;
}

export async function superviseProfile(args) {
  need(args.length === 4, "usage: diagnostic-module fresh-native-oracle guests output");
  const output = resolve(args[3]);
  await mkdir(output, { recursive: true });
  const windows = process.platform === "win32";
  const child = spawn(process.execPath, [fileURLToPath(import.meta.url), ...args], {
    env: { ...process.env, U14_COST_PROFILE_CHILD: "1" }, detached: !windows, stdio: "inherit" });
  let timed_out = false, process_group_cleaned = false;
  const terminate = () => {
    try { if (windows) child.kill("SIGKILL"); else process.kill(-child.pid, "SIGKILL"); }
    catch (error) { if (error.code !== "ESRCH") throw error; }
  };
  const timer = setTimeout(() => { timed_out = true; terminate(); }, 180000);
  let code;
  try {
    code = await new Promise((resolve, reject) => { child.on("error", reject); child.on("exit", (code, signal) => resolve(signal ? -1 : code)); });
    if (windows) process_group_cleaned = true; // All guest Workers are threads of this reaped Node child.
    else {
      for (let attempt = 0; attempt < 20; attempt++) {
        try { process.kill(-child.pid, 0); terminate(); }
        catch (error) { if (error.code === "ESRCH") { process_group_cleaned = true; break; } throw error; }
        await new Promise(resolve => setTimeout(resolve, 10));
      }
    }
  } finally { clearTimeout(timer); }
  const result = { schema: 1, purpose: "u14-cost-profile-supervisor", exit: code, timed_out, process_group_cleaned };
  await writeFile(resolve(output, "supervisor.json"), JSON.stringify(result, null, 2) + "\n");
  need(code === 0 && !timed_out && process_group_cleaned, "Diagnostic child failed or leaked process group");
  return result;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  try {
    if (process.env.U14_COST_PROFILE_CHILD === "1") {
      need(args.length === 4, "usage: diagnostic-module fresh-native-oracle guests output");
      const [modulePath, oraclePath, guests, output] = args;
      const report = await collectProfile({ modulePath, oraclePath, guests, output });
      console.log(JSON.stringify({ purpose: report.purpose, head: report.head, passed: report.passed, rows: report.rows.map(row => ({ jit: row.jit, seconds: row.seconds, counters: row.costProfile.counters })) }));
    } else console.log(JSON.stringify(await superviseProfile(args)));
  } catch (error) { console.error(String(error)); process.exitCode = 1; }
}
