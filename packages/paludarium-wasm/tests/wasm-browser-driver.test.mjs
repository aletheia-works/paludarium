import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { EventEmitter } from "node:events";
import { createRequire, syncBuiltinESMExports } from "node:module";
import { isSafariLaunchTimeout, runBrowser, webdriverRequest } from "./wasm-browser-driver.mjs";
// The exact safaridriver answer of run 39114110570 attempt 1 (job 117638480843).
const LAUNCH_TIMEOUT = { error: "session not created", message: "Could not create a session: The session timed out while connecting to a Safari instance. The following asynchronous operation timed out: Finding or launching a compatible local Safari and waiting for its RWIApplication to appear and become ready.", stacktrace: "" };
// Stub safaridriver/pkill, fetch, AbortSignal.timeout and console.error for one Safari run; everything is restored in finally.
// `reply(key, count)` answers a WebDriver request (count = how many times that key was asked) with [status, value].
async function stubbedSafari(reply, run) {
  const childProcess = createRequire(import.meta.url)("node:child_process");
  const original = { spawn: childProcess.spawn, fetch: globalThis.fetch, timeout: AbortSignal.timeout, error: console.error };
  const timeouts = new WeakMap(), requests = [], spawned = [], logged = [], counts = {};
  childProcess.spawn = (command, args) => {
    const child = Object.assign(new EventEmitter(), { exitCode: null, signalCode: null, stdout: new EventEmitter(), stderr: new EventEmitter() });
    child.kill = signal => { if (child.signalCode === null && child.exitCode === null) { child.signalCode = signal; setImmediate(() => child.emit("exit", null, signal)); } return true; };
    if (command === "/usr/bin/pkill") setImmediate(() => { child.exitCode = 0; child.emit("exit", 0, null); });
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
test("unsupported browser does not launch a substitute", async () => assert.rejects(runBrowser("webkit", "http://127.0.0.1/"), /Unsupported actual browser/));
test("unbounded browser deadline rejected before launch", async () => assert.rejects(runBrowser("safari", "http://127.0.0.1/", 0), /Invalid external browser deadline/));
test("Safari session creation alone waits 60000 ms while other WebDriver requests keep 10000 ms", async () => {
  // Stub safaridriver, fetch and AbortSignal.timeout only for this test; everything is restored in finally.
  const childProcess = createRequire(import.meta.url)("node:child_process");
  const original = { spawn: childProcess.spawn, fetch: globalThis.fetch, timeout: AbortSignal.timeout };
  const timeouts = new WeakMap(), requests = [], spawned = [];
  childProcess.spawn = (command, args) => {
    const driver = Object.assign(new EventEmitter(), { exitCode: null, signalCode: null, stdout: new EventEmitter(), stderr: new EventEmitter() });
    driver.kill = signal => { if (driver.signalCode === null) { driver.signalCode = signal; setImmediate(() => driver.emit("exit", null, signal)); } return true; };
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
    assert.deepEqual(await runBrowser("safari", "http://127.0.0.1/page", 5000), { environment: "safari", version: "stub", stub: true, session_retry: { attempts: 1, retried: false, first_failure: null } });
  } finally {
    childProcess.spawn = original.spawn;
    syncBuiltinESMExports();
    globalThis.fetch = original.fetch;
    AbortSignal.timeout = original.timeout;
  }
  assert.deepEqual(spawned.map(({ command, args }) => [command, args]), [["/usr/bin/safaridriver", ["--port", "4455"]]]);
  assert.equal(spawned[0].driver.signalCode, "SIGTERM");
  assert.deepEqual(requests, [
    { key: "GET /status", timeoutMs: 10000 },
    { key: "POST /session", timeoutMs: 60000 },
    { key: "POST /session/s1/url", timeoutMs: 10000 },
    { key: "POST /session/s1/execute/sync", timeoutMs: 10000 },
    { key: "DELETE /session/s1", timeoutMs: 10000 },
  ]);
});
test("only the safaridriver launch timeout in session creation counts as retryable", () => {
  const cause = new Error(`WebDriver POST /session: ${JSON.stringify(LAUNCH_TIMEOUT)}`);
  const failure = phase => Object.assign(new Error(`Safari ${phase}: ${cause}`, { cause }), { phase });
  assert.equal(isSafariLaunchTimeout(failure("session-creation")), true);
  assert.equal(isSafariLaunchTimeout(failure("navigation")), false);
  assert.equal(isSafariLaunchTimeout(failure("driver-startup")), false);
  const other = new Error(`WebDriver POST /session: ${JSON.stringify({ error: "session not created", message: "Could not create a session: Allow remote automation is off" })}`);
  assert.equal(isSafariLaunchTimeout(Object.assign(new Error(String(other), { cause: other }), { phase: "session-creation" })), false);
  const unrelated = new Error(`WebDriver POST /session: ${JSON.stringify({ error: "timeout", message: "timed out while connecting to a Safari instance" })}`);
  assert.equal(isSafariLaunchTimeout(Object.assign(new Error(String(unrelated), { cause: unrelated }), { phase: "session-creation" })), false);
});
test("Safari launch timeout is retried once after stopping safaridriver and Safari, and the first failure stays in the result and the log", async () => {
  const run = await stubbedSafari((key, count) => key === "POST /session" && count === 1 ? [500, LAUNCH_TIMEOUT] : healthy[key], () => runBrowser("safari", "http://127.0.0.1/page", 5000));
  assert.ok(run.outcome.value, String(run.outcome.error));
  const { session_retry: retry, ...rest } = run.outcome.value;
  assert.deepEqual(rest, { environment: "safari", version: "stub", stub: true });
  assert.equal(retry.attempts, 2); assert.equal(retry.retried, true);
  assert.match(retry.first_failure, /^Safari session-creation: .*timed out while connecting to a Safari instance/);
  assert.deepEqual(retry.safari_stopped, { code: 0, signal: null });
  assert.deepEqual(run.spawned.map(({ command, args }) => [command, args]),
    [["/usr/bin/safaridriver", ["--port", "4455"]], ["/usr/bin/pkill", ["-x", "Safari"]], ["/usr/bin/safaridriver", ["--port", "4455"]]]);
  assert.equal(run.spawned[0].child.signalCode, "SIGTERM"); assert.equal(run.spawned[2].child.signalCode, "SIGTERM");
  assert.deepEqual(run.requests.map(r => r.key), ["GET /status", "POST /session", "GET /status", "POST /session", "POST /session/s1/url", "POST /session/s1/execute/sync", "DELETE /session/s1"]);
  assert.equal(run.logged.length, 1);
  const log = JSON.parse(run.logged[0]).safari_session_retry;
  assert.equal(log.attempt, 1); assert.match(log.failure, /timed out while connecting to a Safari instance/);
});
test("other Safari failures are not retried", async () => {
  const notEnabled = { error: "session not created", message: "Could not create a session: You must enable the 'Allow Remote Automation' option" };
  let run = await stubbedSafari(key => key === "POST /session" ? [500, notEnabled] : healthy[key], () => runBrowser("safari", "http://127.0.0.1/page", 5000));
  assert.match(String(run.outcome.error), /Safari session-creation: .*Allow Remote Automation/);
  assert.equal(run.spawned.length, 1); assert.equal(run.logged.length, 0);
  assert.equal(run.requests.filter(r => r.key === "POST /session").length, 1);
  // the same timed-out text outside session creation (navigation) is not retried either
  run = await stubbedSafari(key => key === "POST /session/s1/url" ? [500, LAUNCH_TIMEOUT] : healthy[key], () => runBrowser("safari", "http://127.0.0.1/page", 5000));
  assert.match(String(run.outcome.error), /Safari navigation: /);
  assert.equal(run.spawned.length, 1); assert.equal(run.logged.length, 0);
});
test("a second launch timeout stops after the single retry and keeps both failures", async () => {
  const run = await stubbedSafari(key => key === "POST /session" ? [500, LAUNCH_TIMEOUT] : healthy[key], () => runBrowser("safari", "http://127.0.0.1/page", 5000));
  const error = run.outcome.error;
  assert.ok(error, "two launch timeouts must reject");
  assert.match(error.message, /^Safari session-creation: .*; first attempt \(retried once\): Safari session-creation: .*timed out while connecting/);
  assert.equal(error.firstFailure.phase, "session-creation");
  assert.equal(run.requests.filter(r => r.key === "POST /session").length, 2);
  assert.deepEqual(run.spawned.map(({ command }) => command), ["/usr/bin/safaridriver", "/usr/bin/pkill", "/usr/bin/safaridriver"]);
  assert.equal(run.logged.length, 1);
});
