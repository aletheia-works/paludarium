import test from "node:test";
import assert from "node:assert/strict";
import { WASM_DEADLINE_MS, WASM_ENVIRONMENTS, WASM_PROBES, validateOracle } from "./wasm-contract.mjs";
function fixture() {
  const names = [...WASM_PROBES.map(name => `probe-${name}`), "probe-all", "probe-environment", "version", "install", "frozen", "list"];
  return { schema: 1, native_complete: true, binary_hashes: { probe: "a".repeat(64), aube: "b".repeat(64) },
    fixture_input_modes: { a: 420, b: 420, c: 420 }, rows: Object.fromEntries(names.map(name => [name, { exit: 0, timed_out: false, stdout: "", stderr: "" }])) };
}
test("ready contract includes actual Safari and external bounded deadline", () => { assert.equal(WASM_DEADLINE_MS, 30000); assert.deepEqual(WASM_ENVIRONMENTS, ["node", "chromium", "firefox", "safari"]); assert.equal(Object.keys(validateOracle(fixture()).rows).length, 14); });
test("incomplete native result rejected", () => { const f = fixture(); f.native_complete = false; assert.throws(() => validateOracle(f)); });
test("missing hash rejected", () => { const f = fixture(); f.binary_hashes.probe = ""; assert.throws(() => validateOracle(f)); });
test("mock substitution rejected", () => { const f = fixture(); f.rows.mock = f.rows.version; assert.throws(() => validateOracle(f)); });
test("failed operation rejected", () => { const f = fixture(); f.rows.frozen.exit = 1; assert.throws(() => validateOracle(f)); });
test("timeout rejected", () => { const f = fixture(); f.rows.install.timed_out = true; assert.throws(() => validateOracle(f)); });
test("default executable fixture rejected", () => { const f = fixture(); f.fixture_input_modes.a = 0o755; assert.throws(() => validateOracle(f)); });
