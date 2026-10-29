/** The relay's settings. */
export interface RelaySettings {
  /** The relay's own allow list, read as `network.allow` is; at least one entry. */
  allow: readonly string[];
  /** When given, the page origins whose WebSockets it accepts. */
  origins?: readonly string[];
  /** The key that signs the tickets for resolved addresses; every instance behind one URL needs the same one (default: random). */
  secret?: string | Uint8Array;
  /** The most WebSockets open at once; beyond it a handshake is refused with 503 (default 1024). */
  maxConnections?: number;
}
export interface Relay {
  /** For a Node.js HTTP server's `upgrade` event. */
  upgrade(request: import("node:http").IncomingMessage, socket: import("node:stream").Duplex, head: Uint8Array): void;
  /** Closes every connection. */
  close(): void;
}
/** A relay to attach to an HTTP server of one's own. */
export function createRelay(settings: RelaySettings): Relay;
/** Serves a relay at `host:port` (default 127.0.0.1:8080; port 0 for any): WebSocket upgrades on any path, and `GET /healthz`. */
export function startRelay(settings: RelaySettings & { host?: string; port?: number }): Promise<{ url: string; relay: Relay; close(): Promise<void> }>;
