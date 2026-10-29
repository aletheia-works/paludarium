// The reference relay for a guest's network in a browser
// (docs/guide/relay.md): a WebSocket server that resolves names and opens TCP
// connections for the coordinator, within its own allow list, so that a page
// that anyone can read does not make it an open proxy. Node.js, no
// dependencies:
//
//   node relay.mjs --listen 0.0.0.0:8080 --allow github.com:443 --allow '*.github.com:443'
import { createServer } from "node:http";
import { connect } from "node:net";
import { lookup } from "node:dns/promises";
import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { PROTOCOL, VERSION, WINDOW, ENETUNREACH, canonicalIp, errnoOf, joinAddress, splitAddress } from "./relay-protocol.mjs";

/** The largest message a client may send; the coordinator sends at most 64 KiB at a time. */
const MESSAGE = 1024 * 1024;
/** How long a connection may wait for its request. */
const REQUEST_TIMEOUT = 10_000;
/** How long a ticket lets a client connect to an address a name resolved to: the kernel's 10 minutes, and its 60-second lookup cache. */
export const TICKET_LIFETIME = 15 * 60_000;

/** A host name in lower case without its final dot, or undefined for one not made of letters, digits, hyphens, underscores and dots (the kernel's `normal`). */
function normal(name) {
  if (typeof name !== "string") return undefined;
  const lower = (name.endsWith(".") ? name.slice(0, -1) : name).toLowerCase();
  const valid = lower.length > 0 && lower.length <= 253 && lower.split(".").every(label => label.length > 0 && label.length <= 63 && /^[a-z0-9_-]+$/.test(label));
  return valid ? lower : undefined;
}
/**
 * One allow-list entry, read as the kernel's `NetworkPolicy::allow` reads it:
 * a host name (`github.com`), every subdomain of one (`*.github.com`), an IPv4
 * address or an IPv6 one (bare, or in brackets), each with a port or for every
 * port.
 */
export function parseRule(entry) {
  const invalid = () => { throw new TypeError(`invalid network rule ${JSON.stringify(entry)}: expected host, host:port, [ipv6] or [ipv6]:port`); };
  const port = text => { const value = /^\d{1,5}$/.test(text) ? Number(text) : 0; return value >= 1 && value <= 65535 ? value : invalid(); };
  if (typeof entry !== "string") invalid();
  const bare = canonicalIp(entry);
  if (bare) return { ip: bare, port: undefined };
  if (entry.startsWith("[")) {
    const close = entry.indexOf("]"), ip = close > 0 && canonicalIp(entry.slice(1, close)), tail = entry.slice(close + 1);
    if (!ip || !ip.includes(":") && !entry.slice(1, close).includes(":")) invalid();
    if (tail && !tail.startsWith(":")) invalid();
    return { ip, port: tail ? port(tail.slice(1)) : undefined };
  }
  const colon = entry.lastIndexOf(":"), host = colon < 0 ? entry : entry.slice(0, colon), given = colon < 0 ? undefined : port(entry.slice(colon + 1));
  const ip = host.includes(":") ? undefined : canonicalIp(host);
  if (ip) return { ip, port: given };
  const subdomains = host.startsWith("*."), name = normal(subdomains ? host.slice(2) : host);
  if (!name) invalid();
  return { name, subdomains, port: given };
}
/** Whether `name` is `rule`'s, or under a `*.` rule one of its subdomains (not the name itself). */
function matchesName(rule, name) {
  return rule.subdomains ? name.length > rule.name.length + 1 && name.endsWith("." + rule.name) : name === rule.name;
}
/**
 * Whether a name rule may reach `ip`, as the kernel's `reachable`: only a
 * global address, so that no allowed name reaches the relay's own machine or
 * networks (DNS rebinding); `localhost` and its subdomains may also reach the
 * loopback.
 */
export function reachable(name, ip) {
  const local = name === "localhost" || name.endsWith(".localhost");
  if (!ip.includes(":")) {
    const [a, b, c, d] = ip.split(".").map(Number);
    if (a === 127) return local;
    return !(a === 0 || a === 10 || (a === 172 && b >= 16 && b < 32) || (a === 192 && b === 168) || (a === 169 && b === 254)
      || a >= 224 || (a === 100 && b >= 64 && b < 128) || (a === 255 && b === 255 && c === 255 && d === 255));
  }
  const groups = expand(ip);
  if (groups.every((group, index) => group === (index === 7 ? 1 : 0))) return local;
  const embedded = (high, low) => [high >> 8, high & 255, low >> 8, low & 255].join(".");
  // NAT64 (64:ff9b::/96) and 6to4 (2002::/16) carry an IPv4 address, which must be reachable itself.
  if (groups[0] === 0x64 && groups[1] === 0xff9b && groups.slice(2, 6).every(group => group === 0)) return reachable(name, embedded(groups[6], groups[7]));
  if (groups[0] === 0x2002) return reachable(name, embedded(groups[1], groups[2]));
  return !(groups.every(group => group === 0) || groups[0] >= 0xff00 || (groups[0] & 0xfe00) === 0xfc00 || (groups[0] & 0xffc0) === 0xfe80);
}
/** The eight groups of a canonical IPv6 address. */
function expand(ip) {
  const [head, tail] = ip.includes("::") ? ip.split("::") : [ip, undefined];
  const parse = text => text ? text.split(":").map(group => parseInt(group, 16)) : [];
  const left = parse(head), right = parse(tail);
  return tail === undefined ? left : [...left, ...Array(8 - left.length - right.length).fill(0), ...right];
}

/**
 * A relay: its policy, and `upgrade(request, socket, head)` for a Node.js HTTP
 * server's `upgrade` event. `allow` is the relay's own allow list; `origins`,
 * when given, the page origins it serves; `secret` signs the tickets for
 * resolved addresses (every instance behind one URL needs the same one);
 * `maxConnections` caps the WebSockets open at once.
 */
export function createRelay({ allow, origins, secret = randomBytes(32), maxConnections = 1024, resolve = name => lookup(name, { all: true, verbatim: true }), now = Date.now } = {}) {
  if (!Array.isArray(allow) || allow.length === 0) throw new TypeError("a relay needs an allow list");
  if (!Number.isSafeInteger(maxConnections) || maxConnections < 1) throw new TypeError("maxConnections must be a positive integer");
  if (origins !== undefined && (!Array.isArray(origins) || origins.some(origin => typeof origin !== "string"))) throw new TypeError("origins must be an array of strings");
  const rules = allow.map(parseRule), peers = new Set();
  const sign = (name, ip, expires) => createHmac("sha256", secret).update(`${VERSION}\n${name}\n${ip}\n${expires}`).digest("base64url");
  const ticket = (name, ip) => { const expires = now() + TICKET_LIFETIME; return `${expires}.${sign(name, ip, expires)}`; };
  function valid(name, ip, given) {
    const [expires, mac] = typeof given === "string" ? given.split(".") : [];
    if (!/^\d+$/.test(expires ?? "") || Number(expires) <= now() || typeof mac !== "string") return false;
    const expected = Buffer.from(sign(name, ip, expires)), actual = Buffer.from(mac);
    return expected.length === actual.length && timingSafeEqual(expected, actual);
  }
  const relay = {
    /** Whether a name may be resolved. */
    allowsName: name => rules.some(rule => rule.name !== undefined && matchesName(rule, name)),
    /** Whether a connection to `ip:port` is allowed: by an address rule, or by a name rule and a ticket for that name's lookup. */
    permits(ip, port, tickets) {
      const fits = rule => rule.port === undefined || rule.port === port;
      if (rules.some(rule => rule.ip === ip && fits(rule))) return true;
      if (!Array.isArray(tickets)) return false;
      return tickets.some(item => {
        const name = normal(item?.name);
        return name !== undefined && reachable(name, ip) && rules.some(rule => rule.name !== undefined && fits(rule) && matchesName(rule, name)) && valid(name, ip, item.ticket);
      });
    },
    /** The addresses `name` resolves to that the relay lets it reach, each with its ticket; none for a name it does not allow. */
    async lookup(text) {
      const name = normal(text);
      if (name === undefined || !relay.allowsName(name)) return [];
      let found;
      try { found = await resolve(name); } catch (cause) { if (cause?.code === "ENOTFOUND" || cause?.code === "ENODATA") return []; throw cause; }
      const addresses = [...new Set(found.map(item => canonicalIp(item.address)).filter(ip => ip && reachable(name, ip)))];
      return addresses.map(address => ({ address, ticket: ticket(name, address) }));
    },
    upgrade(request, socket, head) {
      const headers = request.headers, key = headers["sec-websocket-key"];
      const refuse = (status, text) => { socket.end(`HTTP/1.1 ${status} ${text}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`); };
      if (headers.upgrade?.toLowerCase() !== "websocket" || headers["sec-websocket-version"] !== "13" || !/^[A-Za-z0-9+/]{22}==$/.test(key ?? "")) return refuse(400, "Bad Request");
      if (origins !== undefined && !origins.includes(headers.origin)) return refuse(403, "Forbidden");
      if (peers.size >= maxConnections) return refuse(503, "Service Unavailable");
      // The client fails a handshake that selects none of the protocols it offered: the relay's own, else the first (`lambda-microvms`, for one).
      const offered = (headers["sec-websocket-protocol"] ?? "").split(",").map(item => item.trim()).filter(Boolean);
      const chosen = offered.includes(PROTOCOL) ? PROTOCOL : offered[0];
      const accept = createHash("sha1").update(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest("base64");
      socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n${chosen ? `Sec-WebSocket-Protocol: ${chosen}\r\n` : ""}\r\n`);
      peers.add(new Peer(relay, socket, head, peers));
    },
    /** Closes every connection, without waiting for the clients' close frames. */
    close() { for (const peer of peers) { peer.close(1001); peer.socket.end(); } },
  };
  return relay;
}

/** One WebSocket: a lookup, or a connection. */
class Peer {
  constructor(relay, socket, head, peers) {
    Object.assign(this, { relay, socket, peers, buffer: Buffer.from(head ?? []), fragments: null, state: "request", tcp: null, outstanding: 0, received: 0, written: 0, closed: false, failed: false });
    socket.setNoDelay(true);
    socket.on("data", chunk => this.receive(chunk));
    socket.on("error", () => this.gone());
    // A WebSocket counts toward maxConnections until its socket closes, the 5 seconds after a close frame too.
    socket.on("close", () => { peers.delete(this); this.gone(); });
    // An HTTP server's sockets are half-open: a client that ended gets the relay's end too.
    socket.on("end", () => socket.end());
    this.timer = setTimeout(() => this.close(1008), REQUEST_TIMEOUT);
    if (this.buffer.length) this.receive(Buffer.alloc(0));
  }
  receive(chunk) {
    // After a framing error nothing more of the client's is read: not even its close frame, which cannot be found.
    if (this.garbled) return;
    this.buffer = this.buffer.length ? Buffer.concat([this.buffer, chunk]) : chunk;
    while (!this.socket.destroyed) {
      const bytes = this.buffer;
      if (bytes.length < 2) return;
      const fin = (bytes[0] & 0x80) !== 0, opcode = bytes[0] & 15;
      let length = bytes[1] & 127, at = 2;
      // A client masks every frame, and no extension was agreed.
      if (bytes[0] & 0x70 || !(bytes[1] & 0x80)) return this.close(1002);
      if (length === 126) { if (bytes.length < 4) return; length = bytes.readUInt16BE(2); at = 4; }
      else if (length === 127) { if (bytes.length < 10) return; const long = bytes.readBigUInt64BE(2); length = long > BigInt(MESSAGE) ? MESSAGE + 1 : Number(long); at = 10; }
      if (length > MESSAGE) return this.close(1009);
      if (bytes.length < at + 4 + length) return;
      const mask = bytes.subarray(at, at + 4), payload = Buffer.from(bytes.subarray(at + 4, at + 4 + length));
      for (let index = 0; index < length; index++) payload[index] ^= mask[index & 3];
      this.buffer = bytes.subarray(at + 4 + length);
      this.frame(fin, opcode, payload);
    }
  }
  frame(fin, opcode, payload) {
    // After its close frame the relay reads only the client's.
    if (opcode === 8) { this.close(1000); this.socket.end(); return; }
    if (this.closed) return;
    if (opcode >= 8) {
      if (!fin || payload.length > 125) return this.close(1002);
      if (opcode === 9) this.send(10, payload);
      return;
    }
    if (opcode === 0) {
      if (!this.fragments) return this.close(1002);
      this.fragments.parts.push(payload); this.fragments.size += payload.length;
      if (this.fragments.size > MESSAGE) return this.close(1009);
      if (!fin) return;
      ({ opcode } = this.fragments); payload = Buffer.concat(this.fragments.parts); this.fragments = null;
    } else if (this.fragments || (opcode !== 1 && opcode !== 2)) return this.close(1002);
    else if (!fin) { this.fragments = { opcode, parts: [payload], size: payload.length }; return; }
    if (opcode === 1) this.message(payload.toString());
    else if (this.state === "open") this.upload(payload);
    else if (this.state !== "done") this.close(1008);
  }
  message(text) {
    let message;
    try { message = JSON.parse(text); } catch { return this.close(1007); }
    if (this.state === "request") {
      clearTimeout(this.timer);
      if (message?.v !== VERSION) return this.close(1008);
      if (message.op === "resolve") return void this.resolve(message.name);
      if (message.op === "open") return this.open(message);
      return this.close(1008);
    }
    // What the client sends after the connection closed, before it saw that, is dropped.
    if (this.state === "done") return;
    if (this.state !== "open") return this.close(1008);
    if (message?.op === "end") this.tcp.end();
    else if (message?.op === "nodelay") this.tcp.setNoDelay(message.on === true);
    else if (message?.op === "credit" && Number.isSafeInteger(message.bytes) && message.bytes >= 0) {
      this.outstanding = Math.max(0, this.outstanding - message.bytes);
      if (this.outstanding < WINDOW) this.tcp.resume();
    } else this.close(1008);
  }
  /**
   * Writes the client's bytes to the peer, and credits them back once
   * written. The WebSocket is never paused, so that its credit messages are
   * always read: a client that sends more than its window is closed instead.
   */
  upload(payload) {
    this.received += payload.length;
    if (this.received > WINDOW + MESSAGE) return this.close(1008);
    this.tcp.write(payload, () => {
      this.received -= payload.length; this.written += payload.length;
      if (!this.closed && (this.written >= WINDOW / 4 || this.tcp.writableLength === 0)) { this.json({ op: "credit", bytes: this.written }); this.written = 0; }
    });
  }
  async resolve(name) {
    this.state = "resolving";
    let addresses, failed;
    try { addresses = await this.relay.lookup(name); } catch (cause) { failed = cause; }
    if (this.closed) return;
    this.json(addresses ? { op: "resolved", addresses } : { op: "failed", errno: errnoOf(failed) });
    this.linger(10_000);
  }
  open(message) {
    this.state = "connecting";
    const target = splitAddress(message.address);
    if (!target || !this.relay.permits(target.ip, target.port, message.tickets)) { this.json({ op: "failed", errno: ENETUNREACH }); return this.linger(10_000); }
    // Half-open, as TCP: the peer's end leaves the client able to send.
    const tcp = this.tcp = connect({ host: target.ip, port: target.port, allowHalfOpen: true });
    tcp.on("connect", () => {
      if (this.closed) return;
      this.state = "open";
      this.json({ op: "connected", local: joinAddress(canonicalIp(tcp.localAddress) ?? tcp.localAddress, tcp.localPort) });
    });
    tcp.on("data", chunk => {
      if (this.closed) return;
      this.outstanding += chunk.length;
      if (!this.send(2, chunk)) { tcp.pause(); this.socket.once("drain", () => { if (this.outstanding < WINDOW) tcp.resume(); }); }
      if (this.outstanding >= WINDOW) tcp.pause();
    });
    tcp.on("end", () => { if (!this.closed) this.json({ op: "end" }); });
    tcp.on("error", cause => { if (!this.closed && !this.failed) { this.failed = true; this.json({ op: "failed", errno: errnoOf(cause) }); } });
    tcp.on("close", () => { this.state = "done"; this.linger(30_000); });
  }
  send(opcode, payload) {
    const length = payload.length, header = Buffer.alloc(length < 126 ? 2 : length < 65536 ? 4 : 10);
    header[0] = 0x80 | opcode;
    if (length < 126) header[1] = length;
    else if (length < 65536) { header[1] = 126; header.writeUInt16BE(length, 2); }
    else { header[1] = 127; header.writeBigUInt64BE(BigInt(length), 2); }
    return this.socket.write(Buffer.concat([header, payload]));
  }
  json(value) { this.send(1, Buffer.from(JSON.stringify(value))); }
  /**
   * Leaves the closing to the client, which does it once it has the answer
   * or both ends, so that nothing the relay sent races its close frame; a
   * client that does not is closed after `ms`.
   */
  linger(ms) {
    if (!this.closed && !this.lingering) this.lingering = setTimeout(() => this.close(1000), ms);
  }
  /**
   * Sends the close frame, and ends the TCP stream to the client only once
   * the client's close frame came (or after 5 seconds): ending it at once
   * would reset a client that still sends, which drops what it had received
   * and not yet read, as the last messages before the close.
   */
  close(code) {
    if (code === 1002 || code === 1009) { this.garbled = true; this.buffer = Buffer.alloc(0); }
    if (this.closed) return;
    const payload = Buffer.alloc(2); payload.writeUInt16BE(code);
    this.send(8, payload);
    setTimeout(() => this.socket.destroy(), 5_000).unref();
    this.gone();
  }
  /** Ends the connection's TCP stream to the peer after what the client sent, and forgets the client. */
  gone() {
    this.closed = true; clearTimeout(this.timer); clearTimeout(this.lingering);
    const tcp = this.tcp;
    if (tcp && !tcp.destroyed) { tcp.end(); tcp.resume(); setTimeout(() => tcp.destroy(), 30_000).unref(); }
  }
}

/**
 * Serves a relay over HTTP at `host:port` (port 0 for any): WebSocket
 * upgrades on any path, and `GET /healthz` for a load balancer. Resolves to
 * `{ url, relay, close() }`.
 */
export async function startRelay({ host = "127.0.0.1", port = 8080, ...options } = {}) {
  const relay = createRelay(options);
  const server = createServer((request, response) => {
    if (request.method === "GET" && request.url === "/healthz") response.writeHead(200, { "Content-Type": "text/plain" }).end("ok\n");
    else response.writeHead(426, { Upgrade: "websocket", "Content-Type": "text/plain" }).end("a WebSocket relay\n");
  });
  server.on("upgrade", (request, socket, head) => relay.upgrade(request, socket, head));
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(port, host, resolve); });
  const address = server.address();
  return {
    url: `ws://${joinAddress(address.address, address.port)}/`, relay,
    close: () => new Promise(resolve => { relay.close(); server.close(() => resolve()); server.closeAllConnections?.(); }),
  };
}

// node relay.mjs --listen HOST:PORT --allow ENTRY... [--origin ORIGIN...]
// [--max-connections N]; the same settings from PALUDARIUM_RELAY_LISTEN,
// PALUDARIUM_RELAY_ALLOW, PALUDARIUM_RELAY_ORIGINS (separated by commas or
// spaces) and PALUDARIUM_RELAY_MAX_CONNECTIONS, and the ticket secret from
// PALUDARIUM_RELAY_SECRET.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const { values } = parseArgs({ options: { listen: { type: "string" }, allow: { type: "string", multiple: true }, origin: { type: "string", multiple: true }, "max-connections": { type: "string" } } });
  const list = text => (text ?? "").split(/[\s,]+/).filter(Boolean);
  const listen = splitAddress(values.listen ?? process.env.PALUDARIUM_RELAY_LISTEN ?? "127.0.0.1:8080");
  if (!listen) throw new TypeError("--listen must be ip:port or [ipv6]:port");
  const origins = [...(values.origin ?? []), ...list(process.env.PALUDARIUM_RELAY_ORIGINS)];
  const server = await startRelay({
    host: listen.ip, port: listen.port,
    allow: [...(values.allow ?? []), ...list(process.env.PALUDARIUM_RELAY_ALLOW)],
    origins: origins.length ? origins : undefined,
    secret: process.env.PALUDARIUM_RELAY_SECRET || undefined,
    maxConnections: Number(values["max-connections"] ?? process.env.PALUDARIUM_RELAY_MAX_CONNECTIONS ?? 1024),
  });
  console.log(JSON.stringify({ url: server.url }));
  for (const signal of ["SIGINT", "SIGTERM"]) process.once(signal, () => void server.close().then(() => process.exit(0)));
}
