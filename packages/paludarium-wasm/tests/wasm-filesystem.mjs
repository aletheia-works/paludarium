const decoder = new TextDecoder();
const bytes = encoded => Uint8Array.from(atob(encoded), char => char.charCodeAt(0));
const hex = array => Array.from(new Uint8Array(array), value => value.toString(16).padStart(2, "0")).join("");
const sha256 = async data => hex(await crypto.subtle.digest("SHA-256", data));
function canonicalState(content, entries, appPrefix) {
  const state = JSON.parse(decoder.decode(content));
  const checkMeta = (meta, path) => {
    const entry = entries.get(path);
    if (!entry || meta.size !== entry.content.length || BigInt(meta.mtime_secs) * 1000000000n + BigInt(meta.mtime_nanos) !== BigInt(entry.mtimeNs)) throw new Error(`state mtime/size does not match actual filesystem: ${path}`);
  };
  checkMeta(state.lockfile_meta, appPrefix + "/" + state.lockfile_snapshot_name);
  for (const [path, meta] of Object.entries(state.package_json_meta)) checkMeta(meta, appPrefix + (path === "." ? "" : "/" + path) + "/package.json");
  // Only the independently observed generated lockfile timestamp varies. Its
  // value was checked against the same run's real filesystem before mapping.
  state.lockfile_meta.mtime_secs = "<GENERATED_MTIME>";
  state.lockfile_meta.mtime_nanos = "<GENERATED_MTIME>";
  return JSON.stringify(state);
}
export async function compareFilesystem(expected, actual, fixtureRoot) {
  if (!expected) throw new Error("Fresh native fixture metadata is required");
  const nativeEntries = new Map(Object.entries(expected).filter(([, entry]) => entry.kind === "file").map(([path, entry]) => [fixtureRoot + "/" + path, { content: bytes(entry.content_base64), mtimeNs: entry.mtime_ns }]));
  const all = new Map(actual.map(entry => [entry.path, { ...entry, content: typeof entry.content === "string" ? bytes(entry.content) : entry.content }]));
  const selected = [...all.values()].filter(entry => entry.path === fixtureRoot || entry.path.startsWith(fixtureRoot + "/")).sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  const identities = new Map(), metadata = {};
  for (const entry of selected) {
    const relative = entry.path === fixtureRoot ? "." : entry.path.slice(fixtureRoot.length + 1);
    const kind = entry.mode & 0o170000, row = { mode: entry.mode & 0o7777, kind: kind === 0o040000 ? "directory" : kind === 0o120000 ? "symlink" : "file" };
    if (row.kind === "symlink") row.target = decoder.decode(entry.content);
    if (row.kind === "file") {
      row.links = Number(entry.links); if (!identities.has(String(entry.inode))) identities.set(String(entry.inode), relative);
      row.identity = identities.get(String(entry.inode));
      const native = expected[relative]; if (!native) throw new Error("unexpected guest fixture file: " + relative);
      const state = ["app/node_modules/.aube-state/state.json", "app/node_modules/.aube-state/fresh.json"].includes(relative);
      if (state) {
        const left = canonicalState(bytes(native.content_base64), nativeEntries, fixtureRoot + "/app");
        const right = canonicalState(entry.content, all, fixtureRoot + "/app");
        if (left !== right) throw new Error("state contents mismatch: " + relative);
        row.sha256 = native.sha256;
      } else row.sha256 = await sha256(entry.content);
    }
    metadata[relative] = row;
  }
  const expectedComparable = Object.fromEntries(Object.entries(expected).map(([path, entry]) => {
    const { mtime_ns, content_base64, ...comparable } = entry; return [path, comparable];
  }));
  const stable = value => JSON.stringify(Object.fromEntries(Object.entries(value).sort().map(([path, entry]) => [path, Object.fromEntries(Object.entries(entry).sort())])));
  if (stable(metadata) !== stable(expectedComparable)) throw new Error("fixture mode/type/content/link metadata mismatch");
  return { complete: true, objects: selected.length, generated_mtime_checked: true };
}
