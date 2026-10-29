# Network relay

A browser cannot open TCP connections or resolve names, so a guest there
reaches the [network](./features#network) through a relay: a small WebSocket
server that connects and resolves for it. The npm package includes one
(`relay.mjs`, for Node.js, with no dependencies), and its protocol is
described below so that a relay can be written in any language.

## Use it from a page

Name the relay in `network.relay`:

```js
const guest = launcher.run({
  program: "/bin/git",
  args: ["git", "clone", "https://github.com/aletheia-works/paludarium"],
  network: {
    allow: ["github.com:443"],
    relay: { url: "wss://relay.example/", protocols: ["lambda-microvms", "lambda-microvms.port.8080"] },
  },
});
```

- **`url`** is the relay's `ws:` or `wss:` URL. A page served over HTTPS
  needs `wss:`.
- **`protocols`** are the subprotocols each WebSocket offers, as
  `new WebSocket(url, protocols)` takes them. AWS Lambda MicroVMs, for one,
  take the authentication token and the port this way
  (`lambda-microvms`, `lambda-microvms.authentication.<token>`,
  `lambda-microvms.port.<n>`).
- **`network.allow` still decides** what the guest may reach and resolve:
  the kernel refuses anything else before the relay hears of it, and the DNS
  stub keeps its rules (only allowed names, and only global addresses for
  them). The relay checks its own allow list as well.

Outside Node.js, `network` without `relay` is `unimplemented`. On Node.js,
`relay` is optional: without it the coordinator connects and resolves
itself, and with it the coordinator goes through the relay, as a browser
does.

## Run the relay

```sh
node node_modules/@aletheia-works/paludarium-wasm/relay.mjs \
  --listen 0.0.0.0:8080 --allow github.com:443 --allow '*.github.com:443' \
  --origin https://app.example
```

It prints `{"url":"ws://0.0.0.0:8080/"}` once it listens. It accepts a
WebSocket on any path, and answers `GET /healthz` with `ok`.

| Option | Environment variable | Meaning |
|---|---|---|
| `--listen ip:port` | `PALUDARIUM_RELAY_LISTEN` | Where to listen (default `127.0.0.1:8080`) |
| `--allow entry` (repeated) | `PALUDARIUM_RELAY_ALLOW` | The relay's allow list, read as `network.allow` is; required |
| `--origin origin` (repeated) | `PALUDARIUM_RELAY_ORIGINS` | When given, the only page origins it accepts |
| `--max-connections n` | `PALUDARIUM_RELAY_MAX_CONNECTIONS` | The most WebSockets open at once (default 1024); beyond it a handshake is `503` |
| | `PALUDARIUM_RELAY_SECRET` | The key that signs [tickets](#names-and-tickets); random if unset |

Environment variables hold lists separated by commas or spaces, and add to
the options.

- **Its own allow list.** A token or URL in a page is readable by anyone,
  so the relay must not be an open proxy. It resolves only the names its
  list allows, connects only where its list allows, and, as the kernel does,
  never lets a name reach a loopback, private, link-local or other
  non-global address (except `localhost`, which reaches the loopback).
  List an address itself (`127.0.0.1:8080`) to reach one.
- **The origin check** is for browsers: it keeps other sites' pages from
  using the relay. It does not stop other clients, which can send any
  `Origin`; the allow list does. A handshake without an `Origin` is
  refused too, so leave `--origin` out for a relay that clients outside a
  browser use (the coordinator on Node.js sends none).
- **Limits.** The allow list bounds where the relay connects, and
  `--max-connections` how many connections it carries at once. It has no
  rate limit for each client: put one in front of a public relay if it
  needs one.
- **Several instances** behind one URL need the same
  `PALUDARIUM_RELAY_SECRET`, since a connection may reach another instance
  than the lookup before it.

The module also exports `startRelay(settings)` and `createRelay(settings)`
(`@aletheia-works/paludarium-wasm/relay`), to start one from a script or
attach one to an HTTP server of one's own.

A container image needs only Node.js and the package (name the version you
deploy in `PALUDARIUM_VERSION`):

```dockerfile
FROM node:latest
ARG PALUDARIUM_VERSION=latest
RUN npm install -g @aletheia-works/paludarium-wasm@${PALUDARIUM_VERSION}
ENV PALUDARIUM_RELAY_LISTEN=0.0.0.0:8080
EXPOSE 8080
CMD ["sh", "-c", "exec node \"$(npm root -g)/@aletheia-works/paludarium-wasm/relay.mjs\""]
```

## Protocol

Version 1. Each connection the guest makes, and each name it resolves, is a
WebSocket of its own, so the browser and the relay keep no state between
them, and a connection's flow control is its WebSocket's.

- **The handshake.** The client offers the subprotocols it was given. The
  relay selects `paludarium.relay.v1` if offered, else the first one
  offered (a browser fails a handshake that selects none of them), else
  none.
- **Messages.** Text messages are JSON objects; binary messages are the
  connection's bytes. The client's first message is its request, with
  `"v": 1`. A request of another version, a malformed message, or one the
  state does not allow closes the WebSocket with 1008 (or 1007 for invalid
  JSON); no request in 10 seconds closes it with 1008.
- **Addresses** are `a.b.c.d:port` or `[ipv6]:port`.
- **Errors** are Linux errno numbers: `ENETUNREACH` (101) for a
  destination the relay does not allow, and the connection's own error
  otherwise (`ECONNREFUSED` is 111, for one).

### Resolving a name

```json
{ "v": 1, "op": "resolve", "name": "github.com" }
```

The relay answers once, and the client then closes the WebSocket (1000):

```json
{ "op": "resolved", "addresses": [{ "address": "140.82.112.3", "ticket": "1761700000000.q5…" }] }
```

`addresses` is empty for a name that does not exist, that its allow list
does not name, or that has only addresses it does not reach. A lookup that
failed otherwise is `{ "op": "failed", "errno": n }`, with its error
(`EIO`, 5, for most).

### Names and tickets

The guest connects to an address, not a name, so a ticket shows the relay
that the address came from a name it allows. It is the expiry (milliseconds
since the epoch, 15 minutes after the lookup) and an HMAC-SHA256, in
base64url, of `1\n<name>\n<address>\n<expiry>` under the relay's secret. The
client keeps the tickets of each address it was given, and sends them with
a connection to it.

### Opening a connection

```json
{ "v": 1, "op": "open", "address": "140.82.112.3:443", "tickets": [{ "name": "github.com", "ticket": "1761700000000.q5…" }] }
```

`tickets` may be left out for an address the relay's allow list names
itself. The relay allows the connection when an address rule names it, or a
name rule with its port names a ticket's name, the ticket is valid and the
address is one the name may reach. It answers

```json
{ "op": "connected", "local": "10.0.0.5:51234" }
```

with the address of its own end (the guest's `getsockname`), or
`{ "op": "failed", "errno": 101 }`, after which the client closes it.

Once connected:

| Message | From | Meaning |
|---|---|---|
| binary | either | The connection's bytes, in order |
| `{ "op": "end" }` | client | The guest shut its sending down (`SHUT_WR`) |
| `{ "op": "end" }` | relay | The peer did: the end of input |
| `{ "op": "nodelay", "on": true }` | client | `TCP_NODELAY` |
| `{ "op": "credit", "bytes": n }` | client | The guest took `n` more bytes |
| `{ "op": "credit", "bytes": n }` | relay | The relay wrote `n` more bytes to the peer |
| `{ "op": "failed", "errno": n }` | relay | The connection failed or was reset |

- **Flow control**, the same in both directions: neither side sends more
  than 256 KiB of a connection ahead of the other's credit.
  - The relay stops reading from the peer until more credit comes. The
    client credits what the guest took, in quarters of that, and at once
    when it had stopped taking.
  - The relay credits what it wrote to the peer, in quarters of that, and
    at once when nothing is left to write. It never stops reading the
    WebSocket, so that credit always reaches it, and closes one whose
    client sent more than its window (1008).
- **Closing.** The client closes the WebSocket (1000): after an answer,
  once both sides sent `end`, after `failed`, or when the guest's run
  ends. The relay then ends its TCP stream after what the client sent.
  - The relay leaves the closing to the client, so that nothing it sent
    races its close frame (WebKit has dropped such messages). It closes
    first only for a protocol error, a timeout (10 seconds without a
    request or after an answer, 30 seconds after its TCP connection
    closed) or its shutdown (1001), and ends its TCP stream once the
    client's close frame comes, or after 5 seconds.
  - A WebSocket that closes before the client closed it is `ENETUNREACH`
    to the guest before `connected`, and a reset (`ECONNRESET`) after it,
    unless the peer's `end` came.
