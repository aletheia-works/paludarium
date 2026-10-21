import { createPaludarium, PaludariumError } from "../index.mjs";
const encode = new TextEncoder();
async function collect(stream) {
  const reader = stream.getReader(); const chunks = []; let length = 0;
  while (true) { const { done, value } = await reader.read(); if (done) break; chunks.push(value); length += value.length; }
  const bytes = new Uint8Array(length); let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  return bytes;
}
function hex(bytes) { return [...bytes].map(value => value.toString(16).padStart(2, "0")).join(""); }
async function digest(bytes) { return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))); }
function check(condition, label) { if (!condition) throw new Error(label); }
async function observe(runtime, bytes, stdin, jit = false) {
  const run = runtime.run({ program: "/guest", files: { "/guest": bytes }, jit });
  const outputs = Promise.all([collect(run.stdout), collect(run.stderr), run.exited]);
  const writer = run.stdin.getWriter(); if (stdin) await writer.write(stdin); await writer.close();
  const [stdout, stderr, status] = await outputs;
  return { stdout: hex(stdout), stderr: hex(stderr), status };
}
export async function runChecks({ wasmUrl, readGuest, native }) {
  const runtime = await createPaludarium({ wasmUrl }); const results = [];
  try {
    const expected = new Map(native.map(row => [row.name, row]));
    for (const name of ["hello", "integer", "atomic", "divide_fault", ...native.map(row => row.name).filter(name => name.startsWith("encodings-") || name.startsWith("events-"))]) {
      const bytes = await readGuest(name), row = expected.get(name);
      check(row && !row.timed_out && await digest(bytes) === row.sha256, `${name}: native source mismatch`);
      const observed = await observe(runtime, bytes);
      const desired = row.returncode < 0 ? { kind: "signaled", signal: -row.returncode } : { kind: "exited", code: row.returncode };
      check(JSON.stringify(observed.status) === JSON.stringify(desired), `${name}: exit/signal mismatch`);
      // CPUID is a deliberately virtual identity/features contract. The native
      // host row proves fixture execution/provenance, not identity equivalence.
      let desiredStdout = name === "encodings-cpuid" ? "00".repeat(16) : row.stdout;
      if (["events-52", "events-53", "events-54"].includes(name)) {
        const policyStdout = "9fffffffffffffff" + "00".repeat(24);
        check(row.policy_exception === "AF_INET/AF_INET6 unavailable: EAFNOSUPPORT" && row.policy_stdout === policyStdout, `${name}: missing network policy boundary`);
        desiredStdout = policyStdout;
      }
      check(observed.stdout === desiredStdout && observed.stderr === row.stderr, `${name}: streams mismatch`);
      results.push({ case: name, pass: true, ...observed });
    }
    {
      const observed = await observe(runtime, await readGuest("hello"), undefined, true);
      check(observed.stdout === expected.get("hello").stdout && observed.stderr === expected.get("hello").stderr
        && observed.status.kind === "exited" && observed.status.code === expected.get("hello").returncode, "jit-enabled guest comparison failed");
      const diagnostics = await runtime.diagnostics();
      const jit = diagnostics.workers.at(-1)?.jit;
      check(jit && BigInt(jit.executedBlocks) > 0n && BigInt(jit.executedInstructions) > 0n, "jit-enabled guest executed no translated blocks");
      results.push({ case: "jit-enabled", pass: true, ...observed, jit });
    }
    {
      let error;
      try { await observe(runtime, encode.encode("not ELF")); } catch (cause) { error = cause; }
      check(error instanceof PaludariumError && error.kind === "invalid-program", "invalid ELF must reject with typed error");
      results.push({ case: "invalid-ELF", pass: true, errorKind: error.kind });
    }
    {
      const bytes = await readGuest("stdin"), row = expected.get("stdin");
      check(row && !row.timed_out && await digest(bytes) === row.sha256, "stdin native expectation missing/mismatch");
      const observed = await observe(runtime, bytes, encode.encode("input\n"));
      check(observed.stdout === row.stdout && observed.stderr === row.stderr && observed.status.kind === "exited" && observed.status.code === row.returncode, "streaming stdin mismatch");
      results.push({ case: "streaming-stdin", pass: true, ...observed });
    }
    {
      const bytes = await readGuest("infinite");
      const run = runtime.run({ program: "/guest", files: { "/guest": bytes } });
      const streams = Promise.all([collect(run.stdout), collect(run.stderr)]);
      setTimeout(() => run.kill(), 50);
      const status = await run.exited; await streams;
      check(status.kind === "signaled" && status.signal === 9, "kill did not produce SIGKILL");
      results.push({ case: "kill-shared-session", pass: true, status });
    }
    // Several simultaneous nested execution Workers use actual Arc<Session>/WasmHost objects.
    const integer = await readGuest("integer");
    const simultaneous = await Promise.all(Array.from({ length: 4 }, () => observe(runtime, integer)));
    check(simultaneous.every(result => result.status.kind === "exited" && result.status.code === expected.get("integer").returncode), "simultaneous shared Rust sessions failed");
    results.push({ case: "simultaneous-shared-Rust-sessions", pass: true, workers: simultaneous.length });
    const report = await runtime.diagnostics(), diagnostics = report.workers;
    check(diagnostics.length >= 10, "nonzero nested Worker diagnostics missing");
    check(diagnostics.every(row => row.sharedMemory && row.nestedWorker && row.token === 73 && row.tlsBefore === 0 && row.tlsAfter > 0 && row.stackTop > row.regionPointer && row.tlsAfter !== row.coordinatorTls && row.threadToken !== row.coordinatorThreadToken), "shared heap/stack/TLS initialization check failed");
    const concurrent = diagnostics.slice(-4);
    check(new Set(concurrent.map(row => row.stackTop)).size === 4 && new Set(concurrent.map(row => row.tlsAfter)).size === 4 && new Set(concurrent.map(row => row.threadToken)).size === 4, "concurrent nested Workers reused stack/TLS/thread identity");
    results.push({ case: "actual-shared-heap-nested-Worker", pass: true, diagnostics });
    const probe = report.sharedProbe;
    check(probe.value === "2000" && probe.allocations.every(row => row.allocations === 128 && row.atomicAdds === 1000), "shared AddressSpace/std allocator probe failed");
    check(probe.notified === 1 && probe.waited === 0, "Rust shared heap wait/notify failed");
    check(new Set(probe.workers.map(row => row.threadToken)).size === 2 && new Set(probe.workers.map(row => row.tlsAfter)).size === 2, "shared probe TLS reused");
    results.push({ case: "shared-Rust-allocator-AddressSpace-wait-notify", pass: true, probe });
    const second = await createPaludarium({ wasmUrl });
    try {
      const repeated = await observe(second, await readGuest("hello"));
      check(repeated.stdout === expected.get("hello").stdout && repeated.status.kind === "exited" && repeated.status.code === 0, "second independent runtime initialization failed");
      results.push({ case: "initialize-twice", pass: true, ...repeated });
    } finally { await second.dispose(); }
    const disposing = await createPaludarium({ wasmUrl });
    const blocked = disposing.run({ program: "/guest", files: { "/guest": await readGuest("stdin") } });
    const settled = Promise.allSettled([blocked.exited, collect(blocked.stdout), collect(blocked.stderr)]);
    await new Promise(resolve => setTimeout(resolve, 50));
    const started = performance.now();
    await Promise.all([disposing.dispose(), disposing.dispose()]);
    const outcomes = await settled;
    check(performance.now() - started < 2000 && outcomes.every(row => row.status === "rejected" && row.reason instanceof PaludariumError && row.reason.kind === "host"), "dispose left an active stdin guest or output stream unsettled");
    let disposedError;
    try { disposing.run({ program: "/guest" }); } catch (cause) { disposedError = cause; }
    check(disposedError instanceof PaludariumError && disposedError.kind === "host", "disposed factory accepted another guest");
    results.push({ case: "dispose-active-stdin-session", pass: true, settled: outcomes.length, elapsed_ms: performance.now() - started });
    return { pass: true, caseCount: results.length, results, productionLauncher: true, sharedMemory: true };
  } finally { await runtime.dispose(); }
}
