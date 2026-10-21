import { readFile, mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { loadavg, platform, arch, cpus } from "node:os";
import { measure, schedule, PERFORMANCE_SEED } from "./jit-performance.mjs";
const [modulePath, oraclePath, guests, output] = process.argv.slice(2);
if (!output) throw Error("usage: module native-oracle guests output");
const hash = bytes => createHash("sha256").update(bytes).digest("hex");
const moduleBytes = await readFile(modulePath), oracleBytes = await readFile(oraclePath);
if (WebAssembly.Module.exports(new WebAssembly.Module(moduleBytes)).some(item => item.name === "u14_cost_version")) throw Error("Diagnostic module cannot be used for performance acceptance");
const oracle = JSON.parse(oracleBytes);
const probe = await readFile(resolve(guests, "probe"));
if (!oracle.native_complete || hash(probe) !== oracle.binary_hashes.probe) throw Error("Fresh native probe identity mismatch");
await mkdir(output, { recursive: true });
const report = { schema: 1, seed: PERFORMANCE_SEED, schedule: schedule(), warmupPerMode: 1,
  moduleSha256: hash(moduleBytes), oracleSha256: hash(oracleBytes), probeSha256: hash(probe),
  head: process.env.GITHUB_SHA ?? execFileSync("jj", ["--ignore-working-copy", "log", "-r", "@", "--no-graph", "-T", "commit_id"], { encoding: "utf8" }).trim(),
  tools: { node: process.version, v8: process.versions.v8 }, machine: { platform: platform(), arch: arch(), cpus: cpus() },
  backgroundBefore: { loadavg: loadavg(), processes: execFileSync("ps", ["-eo", "pid,pcpu,comm"], { encoding: "utf8" }) },
  rows: [], warmups: [], complete: false, passed: false };
const persist = () => writeFile(resolve(output, "observations.json"), JSON.stringify(report, null, 2) + "\n");
await persist();
try {
  const result = await measure({ wasmUrl: pathToFileURL(resolve(modulePath)), probe: new Uint8Array(probe), oracle,
    onObservation: async ({ rows, warmups, last }) => {
      report.rows = rows; report.warmups = warmups; await persist();
      console.log(JSON.stringify({ pair: last.pair, jit: last.jit, warmup: last.warmup, seconds: last.seconds, pass: last.pass }));
    } });
  Object.assign(report, result, { complete: true, passed: result.result.pass });
} catch (error) { report.error = String(error); }
finally { report.backgroundAfter = { loadavg: loadavg() }; await persist(); }
if (!report.complete || !report.passed) process.exitCode = 1;
