// The relay's wire protocol (docs/guide/relay.md), shared by the coordinator,
// which speaks it for a guest's network in a browser, and relay.mjs, which
// serves it. Nothing here needs Node.js.

/** The WebSocket subprotocol the relay selects when the client offers it. */
export const PROTOCOL = "paludarium.relay.v1";
/** The `v` of every request. */
export const VERSION = 1;
/** The bytes the relay sends of a connection ahead of the client's credit. */
export const WINDOW = 256 * 1024;
/** Linux's errno for each Node.js error code a connection or lookup may fail with; any other is EIO. */
const ERRNO = { ECONNREFUSED: 111, ECONNRESET: 104, ECONNABORTED: 103, ETIMEDOUT: 110, EHOSTUNREACH: 113, ENETUNREACH: 101, ENETDOWN: 100, EPIPE: 32, EADDRNOTAVAIL: 99, EACCES: 13, EPERM: 1 };
export const ENETUNREACH = 101, ECONNRESET = 104;
export function errnoOf(cause) {
  const given = cause?.paludariumErrno;
  return Number.isInteger(given) && given > 0 && given < 4096 ? given : ERRNO[cause?.code] ?? 5;
}
const V4 = /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;
/**
 * An IP address in one spelling, so that the kernel's, the resolver's and the
 * relay's agree: IPv4 dotted, IPv6 as a URL writes it (RFC 5952), and an
 * IPv4-mapped IPv6 address as its IPv4 address; undefined for anything else.
 */
export function canonicalIp(text) {
  if (typeof text !== "string") return undefined;
  if (V4.test(text)) return text;
  if (!/^[0-9A-Fa-f:.]+$/.test(text) || !text.includes(":")) return undefined;
  let host;
  try { host = new URL(`http://[${text}]/`).hostname.slice(1, -1); } catch { return undefined; }
  const mapped = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(host);
  if (!mapped) return host;
  const [high, low] = [parseInt(mapped[1], 16), parseInt(mapped[2], 16)];
  return [high >> 8, high & 255, low >> 8, low & 255].join(".");
}
/** `{ ip, port }` of `a.b.c.d:port` or `[ipv6]:port`, the ip canonical; undefined for anything else. */
export function splitAddress(text) {
  const match = /^(?:\[([^\]]+)\]|([^:[\]]+)):(\d{1,5})$/.exec(typeof text === "string" ? text : "");
  const ip = match && canonicalIp(match[1] ?? match[2]), port = match && Number(match[3]);
  return ip && port >= 1 && port <= 65535 ? { ip, port } : undefined;
}
/** `ip:port`, with an IPv6 address in brackets. */
export function joinAddress(ip, port) { return `${ip.includes(":") ? `[${ip}]` : ip}:${port}`; }
