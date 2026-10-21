import assert from "node:assert/strict";
import { test } from "node:test";
import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, readdir, cp, rm, writeFile } from "node:fs/promises";
import { resolve, dirname, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const packageRoot = resolve(root, "packages/paludarium-wasm");
const npm = process.env.WASM_NPM;
assert.ok(npm && npm.startsWith("/"), "WASM_NPM must name the real mise npm executable");
const hash = bytes => createHash("sha256").update(bytes).digest("hex");
const child = resolve(packageRoot, "tests/packed-distribution-child.mjs");
const guest = resolve(packageRoot, "tests/guests/hello");
await mkdir(resolve(root, "target/wasm-packed"), { recursive: true });
const workspace = await mkdtemp(resolve(root, "target/wasm-packed/run-"));
const run = (command, argv, cwd = root) => execFileSync(command, argv, {
  cwd, encoding: "utf8", timeout: 60000, killSignal: "SIGKILL", stdio: "pipe",
  env: { ...process.env, PATH: `${dirname(process.execPath)}:${process.env.PATH}` },
});
const packReport = JSON.parse(run(npm, ["pack", "--json", "--ignore-scripts", "--pack-destination", workspace, "--cache", resolve(root, "target/wasm-packaging-cache")], packageRoot));
// npm 12 uses package-name keys; npm 11 emitted an array.
const reports = Array.isArray(packReport) ? packReport : Object.values(packReport);
assert.equal(reports.length, 1, "exactly one distribution must be packed");
const packed = reports[0];
assert.equal(packed.name, "@aletheia-works/paludarium-wasm");
run("/usr/bin/tar", ["-xzf", resolve(workspace, packed.filename), "-C", workspace]);
const extracted = resolve(workspace, "package");
const invoke = (directory, mode) => run(process.execPath, [child, directory, guest, mode]);
async function closure(directory) {
  const files = new Set(await readdir(directory));
  for (const name of files) {
    if (!name.endsWith(".mjs")) continue;
    const text = await readFile(resolve(directory, name), "utf8");
    // Literal static/dynamic imports, re-exports and Worker URL references.
    for (const match of text.matchAll(/(?:from\s*|import\s*\(\s*|import\s+|new URL\(\s*)["']([^"']+)["']/g)) {
      const specifier = match[1];
      if (specifier.startsWith("node:")) continue;
      assert.ok(!specifier.startsWith("/") && !specifier.includes("://"), `${name}: external launcher reference ${specifier}`);
      const target = resolve(directory, specifier);
      assert.ok(!relative(directory, target).startsWith(".."), "reference escapes distribution");
      await readFile(target);
    }
  }
}
console.log(JSON.stringify({ workspace, node: process.version, npm, files: packed.files.map(row => row.path), tarball_sha256: hash(await readFile(resolve(workspace, packed.filename))) }));
await test("fixed hello provenance", async () => {
  assert.equal(hash(await readFile(guest)), JSON.parse(await readFile(resolve(packageRoot, "tests/guest-hashes.json"))).hello);
});
await test("all packed relative JS dependencies exist", () => closure(extracted));
await test("isolated distribution imports", () => assert.match(invoke(extracted, "import"), /packed import PASS/));
await test("actual packed production wasm hello and natural Worker cleanup", () => { const output = invoke(extracted, "hello"); console.log(output); assert.match(output, /packed dispose PASS/); });
await test("missing required JS fails closure and import", async () => {
  const broken = resolve(workspace, "missing"); await cp(extracted, broken, { recursive: true }); await rm(resolve(broken, "jit-support.mjs"));
  await assert.rejects(closure(broken), /ENOENT/);
  assert.throws(() => invoke(broken, "import"), /ERR_MODULE_NOT_FOUND/);
});
await test("corrupt packed wasm is rejected", async () => {
  const broken = resolve(workspace, "corrupt"); await cp(extracted, broken, { recursive: true }); await writeFile(resolve(broken, "paludarium.wasm"), new Uint8Array([73]));
  assert.match(invoke(broken, "corrupt"), /corrupt wasm rejected PASS/);
});
await test("invalid guest rejects streams and cleans Workers", () => assert.match(invoke(extracted, "invalid"), /packed dispose PASS/));
