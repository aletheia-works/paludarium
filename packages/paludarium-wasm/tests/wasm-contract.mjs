// Test supervision owns the operation deadline; this is not a product timeout.
export const U11_DEADLINE_MS = 30000;
export const U11_ENVIRONMENTS = Object.freeze(["node", "chromium", "firefox", "safari"]);
export const U11_PROBES = Object.freeze(["tokio-timer", "unix-stream-pair", "rayon", "mutex-condvar", "fs-basic", "fs-hardlink", "fs-symlink", "fs-flock"]);
export function validateOracle(oracle) {
  if (oracle?.schema !== 1 || oracle.native_complete !== true) throw new Error("Incomplete fresh native oracle");
  if (!oracle.binary_hashes || ["probe", "aube"].some(name => !/^[0-9a-f]{64}$/.test(oracle.binary_hashes[name]))) throw new Error("Missing guest hashes");
  const names = [...U11_PROBES.map(name => `probe-${name}`), "probe-all", "probe-environment", "version", "install", "frozen", "list"];
  if (Object.keys(oracle.rows ?? {}).sort().join() !== names.sort().join()) throw new Error("Unexpected native inventory");
  for (const row of Object.values(oracle.rows)) {
    if (row.exit !== 0 || row.timed_out !== false || typeof row.stdout !== "string" || typeof row.stderr !== "string") throw new Error("Native operation failed");
  }
  if (Object.values(oracle.fixture_input_modes ?? {}).length !== 3 || Object.values(oracle.fixture_input_modes).some(mode => mode !== 0o644)) throw new Error("Fixture must have native 0644 modes");
  return oracle;
}
