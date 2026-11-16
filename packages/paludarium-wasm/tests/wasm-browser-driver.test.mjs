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
// Stub safaridriver/pkill, fetch, AbortSignal.timeout and console.error for one Safari run; everything is restored in finally.
// `reply(key, count)` answers a WebDriver request (count = how many times that key was asked) with [status, value].
// `running` is how many `pgrep -x Safari` polls still find a Safari before it has exited (default: none left).
async function stubbedSafari(reply, run, running = 0) {
  const childProcess = createRequire(import.meta.url)("node:child_process");
  const original = { spawn: childProcess.spawn, fetch: globalThis.fetch, timeout: AbortSignal.timeout, error: console.error };
  const timeouts = new WeakMap(), requests = [], spawned = [], logged = [], counts = {};
  childProcess.spawn = (command, args) => {
    const child = Object.assign(new EventEmitter(), { exitCode: null, signalCode: null, stdout: new EventEmitter(), stderr: new EventEmitter() });
    child.kill = signal => { if (child.signalCode === null && child.exitCode === null) { child.signalCode = signal; setImmediate(() => child.emit("exit", null, signal)); } return true; };
    if (command === "/usr/bin/pkill") setImmediate(() => { child.exitCode = 0; child.emit("exit", 0, null); });
    if (command === "/usr/bin/pgrep") { const code = running > 0 ? 0 : 1; running -= 1; setImmediate(() => { child.exitCode = code; child.emit("exit", code, null); }); }
    spawned.push({ command, args, child });
    return child;
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
  try { return { outcome: await run().then(value => ({ value }), error => ({ error })), requests, spawned, logged }; }
  finally {
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
    if (command === "/usr/bin/pgrep") setImmediate(() => { driver.exitCode = 1; driver.emit("exit", 1, null); });
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
    assert.equal(result.safari_exit_wait.polls, 0);
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
  assert.deepEqual(log.safari_exit_wait, { exited: true, waited_ms: log.safari_exit_wait.waited_ms, polls: 0 });
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
test("a session waits for a Safari that is still exiting, and the wait is logged", async () => {
  const run = await stubbedSafari(key => healthy[key], () => runBrowser("safari", "http://127.0.0.1/page", 5000), 2);
  assert.ok(run.outcome.value, String(run.outcome.error));
  assert.equal(run.outcome.value.safari_exit_wait.exited, true);
  assert.equal(run.outcome.value.safari_exit_wait.polls, 2);
  assert.deepEqual(run.spawned.map(({ command }) => command), ["/usr/bin/safaridriver", "/usr/bin/pgrep", "/usr/bin/pgrep", "/usr/bin/pgrep"]);
  // The session is asked for only after the last poll found no Safari.
  assert.deepEqual(run.requests.map(r => r.key).slice(0, 2), ["GET /status", "POST /session"]);
  assert.equal(run.logged.length, 1);
  assert.deepEqual(Object.keys(JSON.parse(run.logged[0])), ["safari_exit_wait"]);
});
test("the wait for Safari to exit is bounded, and the session is asked for after it", async () => {
  const saved = { ...safariExit };
  Object.assign(safariExit, { waitMs: 50, pollMs: 10 });
  try {
    const run = await stubbedSafari(key => healthy[key], () => runBrowser("safari", "http://127.0.0.1/page", 5000), 1000);
    assert.ok(run.outcome.value, String(run.outcome.error));
    const wait = run.outcome.value.safari_exit_wait;
    assert.equal(wait.exited, false);
    assert.ok(wait.waited_ms >= 50 && wait.polls >= 2);
    assert.equal(run.requests.filter(r => r.key === "POST /session").length, 1);
    assert.equal(JSON.parse(run.logged[0]).safari_exit_wait.exited, false);
  } finally { Object.assign(safariExit, saved); }
});
