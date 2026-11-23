import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { EventEmitter } from "node:events";
import { createRequire, syncBuiltinESMExports } from "node:module";
import { isSafariLaunchFailure, runBrowser, safariExit, webdriverRequest } from "./wasm-browser-driver.mjs";
// The exact safaridriver answer of run 39114110570 attempt 1 (job 117638480843).
const LAUNCH_TIMEOUT = { error: "session not created", message: "Could not create a session: The session timed out while connecting to a Safari instance. The following asynchronous operation timed out: Finding or launching a compatible local Safari and waiting for its RWIApplication to appear and become ready.", stacktrace: "" };
// The exact safaridriver answer of run 43576635510 attempt 1 (job 132402449303).
const NEVER_READY = { error: "session not created", message: "Could not create a session: The host application never became ready, unable to create a WebDriver session.", stacktrace: "" };
// A stub `pgrep -x Safari` that prints `pids` and closes.
function stubPgrep(child, pids) {
  setImmediate(() => {
    if (pids.length > 0) child.stdout.emit("data", Buffer.from(pids.join("\n") + "\n"));
    child.exitCode = pids.length > 0 ? 0 : 1; child.emit("exit", child.exitCode, null); child.emit("close", child.exitCode, null);
  });
}
// Stub safaridriver/pkill/pgrep/caffeinate, process.kill, fetch, AbortSignal.timeout and console.error for one Safari
// run; everything is restored in finally. `reply(key, count)` answers a WebDriver request (count = how many times that
// key was asked) with [status, value]. `safaris` maps the pid of each Safari still running to the ms after which it
// exits (Infinity: only when killed); `caffeinate -w <pid>` exits `lagMs` after that Safari does.
async function stubbedSafari(reply, run, safaris = {}, lagMs = 0) {
  const childProcess = createRequire(import.meta.url)("node:child_process");
  const original = { spawn: childProcess.spawn, fetch: globalThis.fetch, timeout: AbortSignal.timeout, error: console.error, kill: process.kill };
  const timeouts = new WeakMap(), requests = [], spawned = [], logged = [], counts = {}, killed = [];
  const exits = Object.fromEntries(Object.entries(safaris).map(([pid, ms]) => {
    const entry = { gone: false };
    entry.exited = new Promise(resolve => { entry.done = () => { entry.gone = true; resolve(); }; });
    if (Number.isFinite(ms)) setTimeout(entry.done, ms).unref();
    return [pid, entry];
  }));
  childProcess.spawn = (command, args) => {
    const child = Object.assign(new EventEmitter(), { exitCode: null, signalCode: null, stdout: new EventEmitter(), stderr: new EventEmitter() });
    child.kill = signal => { if (child.signalCode === null && child.exitCode === null) { child.signalCode = signal; setImmediate(() => child.emit("exit", null, signal)); } return true; };
    if (command === "/usr/bin/pkill") setImmediate(() => { child.exitCode = 0; child.emit("exit", 0, null); });
    if (command === "/usr/bin/pgrep") stubPgrep(child, Object.keys(safaris).map(Number));
    if (command === "/usr/bin/caffeinate") (exits[args[1]]?.exited ?? Promise.resolve()).then(() => setTimeout(() => { if (child.signalCode === null) { child.exitCode = 0; child.emit("exit", 0, null); } }, lagMs));
    spawned.push({ command, args, child });
    return child;
  };
  process.kill = (pid, signal) => {
    if (!exits[pid] || exits[pid].gone) throw Object.assign(new Error("kill ESRCH"), { code: "ESRCH" });
    if (signal === 0) return true;
    killed.push([pid, signal]); exits[pid].done(); return true;
  };
  syncBuiltinESMExports();
  AbortSignal.timeout = ms => { const signal = original.timeout.call(AbortSignal, ms); timeouts.set(signal, ms); return signal; };
  console.error = (...args) => { logged.push(args.join(" ")); };
  globalThis.fetch = async (url, init) => {
    const key = `${init.method} ${new URL(url).pathname}`;
    counts[key] = (counts[key] ?? 0) + 1;
    requests.push({ key, timeoutMs: timeouts.get(init.signal) });
    const [status, value] = reply(key, counts[key]) ?? [404, { error: "unexpected request" }];
    return new Response(JSON.stringify({ value }), { status });
  };
  try { return { outcome: await run().then(value => ({ value }), error => ({ error })), requests, spawned, logged, killed }; }
  finally {
    process.kill = original.kill;
    childProcess.spawn = original.spawn;
    syncBuiltinESMExports();
    globalThis.fetch = original.fetch;
    AbortSignal.timeout = original.timeout;
    console.error = original.error;
  }
}
const healthy = { "GET /status": [200, { ready: true }], "POST /session": [200, { sessionId: "s1", capabilities: { browserVersion: "stub" } }], "POST /session/s1/url": [200, null],
  "POST /session/s1/execute/sync": [200, { stub: true }], "DELETE /session/s1": [200, null] };
async function endpoint(handler, run) {
  const server = createServer(handler);
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  try { await run(`http://127.0.0.1:${server.address().port}`); }
  finally { await new Promise(resolve => server.close(resolve)); }
}
test("WebDriver returns actual response value", async () => endpoint((_, response) => response.end('{"value":{"ready":true}}'), async base => assert.deepEqual(await webdriverRequest(base, "GET", "/status"), { ready: true })));
test("WebDriver POST sends exact capability payload", async () => endpoint((request, response) => { let body = ""; request.on("data", bytes => { body += bytes; }); request.on("end", () => response.end(JSON.stringify({ value: JSON.parse(body) }))); }, async base => assert.deepEqual(await webdriverRequest(base, "POST", "/session", { safari: true }), { safari: true })));
test("WebDriver HTTP failure is retained", async () => endpoint((_, response) => response.writeHead(500).end('{"value":{"message":"driver unavailable"}}'), async base => assert.rejects(webdriverRequest(base, "GET", "/status"), /driver unavailable/)));
test("WebDriver protocol failure rejects even successful HTTP status", async () => endpoint((_, response) => response.end('{"value":{"error":"invalid session id"}}'), async base => assert.rejects(webdriverRequest(base, "DELETE", "/session/stale"), /invalid session id/)));
test("WebDriver malformed response rejects", async () => endpoint((_, response) => response.end('not json'), async base => assert.rejects(webdriverRequest(base, "GET", "/status"))));
test("WebDriver missing protocol envelope rejects", async () => endpoint((_, response) => response.end('{}'), async base => assert.rejects(webdriverRequest(base, "GET", "/status"))));
test("WebDriver request honours a supplied timeout against a slow endpoint", async () => { let timer; await endpoint((_, response) => { timer = setTimeout(() => response.end('{"value":{"late":true}}'), 2000); }, async base => { try { await assert.rejects(webdriverRequest(base, "GET", "/status", undefined, 100), { name: "TimeoutError" }); } finally { clearTimeout(timer); } }); });
test("unsupported browser does not launch a substitute", async () => assert.rejects(runBrowser("edge", "http://127.0.0.1/"), /Unsupported actual browser/));
test("unbounded browser deadline rejected before launch", async () => assert.rejects(runBrowser("safari", "http://127.0.0.1/", 0), /Invalid external browser deadline/));
test("Safari session creation alone waits 60000 ms while other WebDriver requests keep 10000 ms", async () => {
  // Stub safaridriver, fetch and AbortSignal.timeout only for this test; everything is restored in finally.
  const childProcess = createRequire(import.meta.url)("node:child_process");
  const original = { spawn: childProcess.spawn, fetch: globalThis.fetch, timeout: AbortSignal.timeout };
  const timeouts = new WeakMap(), requests = [], spawned = [];
  childProcess.spawn = (command, args) => {
    const driver = Object.assign(new EventEmitter(), { exitCode: null, signalCode: null, stdout: new EventEmitter(), stderr: new EventEmitter() });
    driver.kill = signal => { if (driver.signalCode === null) { driver.signalCode = signal; setImmediate(() => driver.emit("exit", null, signal)); } return true; };
    if (command === "/usr/bin/pgrep") stubPgrep(driver, []);
    spawned.push({ command, args, driver });
    return driver;
  };
  syncBuiltinESMExports();
  AbortSignal.timeout = ms => { const signal = original.timeout.call(AbortSignal, ms); timeouts.set(signal, ms); return signal; };
  const replies = { "GET /status": { ready: true }, "POST /session": { sessionId: "s1", capabilities: { browserVersion: "stub" } }, "POST /session/s1/url": null, "POST /session/s1/execute/sync": { stub: true }, "DELETE /session/s1": null };
  globalThis.fetch = async (url, init) => {
    const key = `${init.method} ${new URL(url).pathname}`;
    requests.push({ key, timeoutMs: timeouts.get(init.signal) });
    if (!Object.hasOwn(replies, key)) return new Response('{"value":{"error":"unexpected request"}}', { status: 404 });
    return new Response(JSON.stringify({ value: replies[key] }));
  };
  try {
    const result = await runBrowser("safari", "http://127.0.0.1/page", 5000);
    assert.equal(result.safari_exit_wait.exited, true);
    assert.deepEqual(result.safari_exit_wait.pids, []);
    delete result.safari_exit_wait;
    assert.deepEqual(result, { environment: "safari", version: "stub", stub: true, session_retry: { attempts: 1, retried: false, first_failure: null } });
  } finally {
    childProcess.spawn = original.spawn;
    syncBuiltinESMExports();
    globalThis.fetch = original.fetch;
    AbortSignal.timeout = original.timeout;
  }
  assert.deepEqual(spawned.map(({ command, args }) => [command, args]), [["/usr/bin/safaridriver", ["--port", "4455"]], ["/usr/bin/pgrep", ["-x", "Safari"]]]);
  assert.equal(spawned[0].driver.signalCode, "SIGTERM");
  assert.deepEqual(requests, [
    { key: "GET /status", timeoutMs: 10000 },
    { key: "POST /session", timeoutMs: 60000 },
    { key: "POST /session/s1/url", timeoutMs: 10000 },
    { key: "POST /session/s1/execute/sync", timeoutMs: 10000 },
    { key: "DELETE /session/s1", timeoutMs: 10000 },
  ]);
});
test("only the safaridriver launch failures in session creation count as retryable", () => {
  const cause = new Error(`WebDriver POST /session: ${JSON.stringify(LAUNCH_TIMEOUT)}`);
  const failure = phase => Object.assign(new Error(`Safari ${phase}: ${cause}`, { cause }), { phase });
  assert.equal(isSafariLaunchFailure(failure("session-creation")), true);
  assert.equal(isSafariLaunchFailure(failure("navigation")), false);
  assert.equal(isSafariLaunchFailure(failure("driver-startup")), false);
  const neverReady = new Error(`WebDriver POST /session: ${JSON.stringify(NEVER_READY)}`);
  assert.equal(isSafariLaunchFailure(Object.assign(new Error(String(neverReady), { cause: neverReady }), { phase: "session-creation" })), true);
  assert.equal(isSafariLaunchFailure(Object.assign(new Error(String(neverReady), { cause: neverReady }), { phase: "navigation" })), false);
  const other = new Error(`WebDriver POST /session: ${JSON.stringify({ error: "session not created", message: "Could not create a session: Allow remote automation is off" })}`);
  assert.equal(isSafariLaunchFailure(Object.assign(new Error(String(other), { cause: other }), { phase: "session-creation" })), false);
  const unrelated = new Error(`WebDriver POST /session: ${JSON.stringify({ error: "timeout", message: "timed out while connecting to a Safari instance" })}`);
  assert.equal(isSafariLaunchFailure(Object.assign(new Error(String(unrelated), { cause: unrelated }), { phase: "session-creation" })), false);
});
test("Safari launch timeout is retried once after stopping safaridriver and Safari, and the first failure stays in the result and the log", async () => {
  const run = await stubbedSafari((key, count) => key === "POST /session" && count === 1 ? [500, LAUNCH_TIMEOUT] : healthy[key], () => runBrowser("safari", "http://127.0.0.1/page", 5000));
  assert.ok(run.outcome.value, String(run.outcome.error));
  const { session_retry: retry, safari_exit_wait: _, ...rest } = run.outcome.value;
  assert.deepEqual(rest, { environment: "safari", version: "stub", stub: true });
  assert.equal(retry.attempts, 2); assert.equal(retry.retried, true);
  assert.match(retry.first_failure, /^Safari session-creation: .*timed out while connecting to a Safari instance/);
  assert.deepEqual(retry.safari_stopped, { code: 0, signal: null });
  assert.deepEqual(run.spawned.map(({ command, args }) => [command, args]),
    [["/usr/bin/safaridriver", ["--port", "4455"]], ["/usr/bin/pgrep", ["-x", "Safari"]], ["/usr/bin/pkill", ["-x", "Safari"]],
     ["/usr/bin/safaridriver", ["--port", "4455"]], ["/usr/bin/pgrep", ["-x", "Safari"]]]);
  assert.equal(run.spawned[0].child.signalCode, "SIGTERM"); assert.equal(run.spawned[3].child.signalCode, "SIGTERM");
  assert.deepEqual(run.requests.map(r => r.key), ["GET /status", "POST /session", "GET /status", "POST /session", "POST /session/s1/url", "POST /session/s1/execute/sync", "DELETE /session/s1"]);
  assert.equal(run.logged.length, 1);
  const log = JSON.parse(run.logged[0]).safari_session_retry;
  assert.equal(log.attempt, 1); assert.match(log.failure, /timed out while connecting to a Safari instance/);
  // When the failure came and how long the attempt took, so the retries can be counted and timed from the logs.
  assert.ok(!Number.isNaN(Date.parse(log.at)));
  assert.ok(Number.isInteger(log.failed_after_ms) && log.failed_after_ms >= 0);
  assert.ok(Number.isInteger(log.session_requested_after_ms) && log.session_requested_after_ms <= log.failed_after_ms);
  assert.deepEqual(log.safari_exit_wait, { exited: true, waited_ms: log.safari_exit_wait.waited_ms, pids: [] });
  assert.equal(log.pause_ms, 2000);
  assert.equal(retry.first_failed_after_ms, log.failed_after_ms);
});
test("other Safari failures are not retried", async () => {
  const notEnabled = { error: "session not created", message: "Could not create a session: You must enable the 'Allow Remote Automation' option" };
  let run = await stubbedSafari(key => key === "POST /session" ? [500, notEnabled] : healthy[key], () => runBrowser("safari", "http://127.0.0.1/page", 5000));
  assert.match(String(run.outcome.error), /Safari session-creation: .*Allow Remote Automation/);
  assert.equal(run.spawned.length, 2); assert.equal(run.logged.length, 0);
  assert.equal(run.requests.filter(r => r.key === "POST /session").length, 1);
  // the same timed-out text outside session creation (navigation) is not retried either
  run = await stubbedSafari(key => key === "POST /session/s1/url" ? [500, LAUNCH_TIMEOUT] : healthy[key], () => runBrowser("safari", "http://127.0.0.1/page", 5000));
  assert.match(String(run.outcome.error), /Safari navigation: /);
  assert.equal(run.spawned.length, 2); assert.equal(run.logged.length, 0);
});
test("a second launch timeout stops after the single retry and keeps both failures", async () => {
  const run = await stubbedSafari(key => key === "POST /session" ? [500, LAUNCH_TIMEOUT] : healthy[key], () => runBrowser("safari", "http://127.0.0.1/page", 5000));
  const error = run.outcome.error;
  assert.ok(error, "two launch timeouts must reject");
  assert.match(error.message, /^Safari session-creation: .*; first attempt \(retried once\): Safari session-creation: .*timed out while connecting/);
  assert.equal(error.firstFailure.phase, "session-creation");
  assert.equal(run.requests.filter(r => r.key === "POST /session").length, 2);
  assert.deepEqual(run.spawned.map(({ command }) => command), ["/usr/bin/safaridriver", "/usr/bin/pgrep", "/usr/bin/pkill", "/usr/bin/safaridriver", "/usr/bin/pgrep"]);
  assert.equal(run.logged.length, 1);
});
test("Safari that never became ready is retried once like a launch timeout", async () => {
  const run = await stubbedSafari((key, count) => key === "POST /session" && count === 1 ? [500, NEVER_READY] : healthy[key], () => runBrowser("safari", "http://127.0.0.1/page", 5000));
  assert.ok(run.outcome.value, String(run.outcome.error));
  assert.equal(run.outcome.value.session_retry.attempts, 2);
  assert.match(run.outcome.value.session_retry.first_failure, /^Safari session-creation: .*The host application never became ready/);
  assert.deepEqual(run.spawned.map(({ command }) => command), ["/usr/bin/safaridriver", "/usr/bin/pgrep", "/usr/bin/pkill", "/usr/bin/safaridriver", "/usr/bin/pgrep"]);
  assert.equal(run.logged.length, 1);
});
test("a second never-ready Safari stops after the single retry and keeps both failures", async () => {
  const run = await stubbedSafari(key => key === "POST /session" ? [500, NEVER_READY] : healthy[key], () => runBrowser("safari", "http://127.0.0.1/page", 5000));
  const error = run.outcome.error;
  assert.ok(error, "two never-ready sessions must reject");
  assert.match(error.message, /^Safari session-creation: .*never became ready.*; first attempt \(retried once\): Safari session-creation: .*never became ready/);
  assert.equal(run.requests.filter(r => r.key === "POST /session").length, 2);
  assert.equal(run.logged.length, 1);
});
test("a session waits for the exit of a Safari that is still exiting, and the wait is logged", async () => {
  const run = await stubbedSafari(key => healthy[key], () => runBrowser("safari", "http://127.0.0.1/page", 5000), { 501: 30, 502: 60 });
  assert.ok(run.outcome.value, String(run.outcome.error));
  const wait = run.outcome.value.safari_exit_wait;
  assert.equal(wait.exited, true); assert.deepEqual(wait.pids, [501, 502]); assert.ok(wait.waited_ms >= 45); // timers may wake a few ms before Date.now() shows the bound
  // One pgrep, then one exit wait per pid: no polling.
  assert.deepEqual(run.spawned.map(({ command, args }) => [command, args]), [["/usr/bin/safaridriver", ["--port", "4455"]], ["/usr/bin/pgrep", ["-x", "Safari"]],
    ["/usr/bin/caffeinate", ["-w", "501"]], ["/usr/bin/caffeinate", ["-w", "502"]]]);
  // The session is asked for only after both exited.
  assert.deepEqual(run.requests.map(r => r.key).slice(0, 2), ["GET /status", "POST /session"]);
  assert.deepEqual(run.killed, []);
  assert.equal(run.logged.length, 1);
  assert.deepEqual(Object.keys(JSON.parse(run.logged[0])), ["safari_exit_wait"]);
});
for (const kill of [true, false]) test(`a Safari that never exits is logged with its pid${kill ? ", killed on CI" : " and left running off CI"}, and the session is asked for after it`, async () => {
  const saved = { ...safariExit };
  Object.assign(safariExit, { waitMs: 50, killWaitMs: 50, kill });
  try {
    const run = await stubbedSafari(key => healthy[key], () => runBrowser("safari", "http://127.0.0.1/page", 5000), { 501: 10, 502: Infinity });
    assert.ok(run.outcome.value, String(run.outcome.error));
    const wait = run.outcome.value.safari_exit_wait;
    assert.equal(wait.exited, false); assert.ok(wait.waited_ms >= 45); // timers may wake a few ms before Date.now() shows the bound assert.deepEqual(wait.pids, [501, 502]);
    assert.deepEqual(wait.never_exited, [{ pid: 502, killed: kill, exited_after_kill: kill ? true : null }]);
    // Only the Safari that never exited, and only on CI.
    assert.deepEqual(run.killed, kill ? [[502, "SIGKILL"]] : []);
    assert.equal(run.requests.filter(r => r.key === "POST /session").length, 1);
    assert.deepEqual(JSON.parse(run.logged[0]), { safari_never_exited: { pid: 502, waited_ms: wait.waited_ms, killing: kill } });
    assert.equal(JSON.parse(run.logged[1]).safari_exit_wait.exited, false);
  } finally { Object.assign(safariExit, saved); }
});
test("a Safari whose exit the deadline cut short is not taken for one that never exited", async () => {
  const saved = { ...safariExit };
  // The wait ends at 10 ms, before caffeinate reports (40 ms late) the exit of a Safari gone at 0 ms.
  Object.assign(safariExit, { waitMs: 10, killWaitMs: 50, kill: true });
  try {
    const run = await stubbedSafari(key => healthy[key], () => runBrowser("safari", "http://127.0.0.1/page", 5000), { 501: 0 }, 40);
    assert.ok(run.outcome.value, String(run.outcome.error));
    const wait = run.outcome.value.safari_exit_wait;
    assert.equal(wait.exited, true); assert.deepEqual(wait.pids, [501]);
    assert.deepEqual(run.killed, []);
    assert.ok(!run.logged.some(line => line.includes("safari_never_exited")));
  } finally { Object.assign(safariExit, saved); }
});
