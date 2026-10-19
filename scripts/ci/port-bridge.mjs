#!/usr/bin/env node
// port-bridge.mjs — the ONE host port a networked CI guest may reach
// (docs/design/testing/continuous-integration.md §9, `vm-run.sh --ollama`).
//
// A `--network` guest's qemu runs in its own network namespace behind
// slirp4netns --disable-host-loopback, so nothing on the host's loopback
// (a live arbiter, dashboard, Ollama) is reachable from it. The nightly's
// local-model env suites need exactly one of those: the host's Ollama. qemu's
// `guestfwd` maps a guest address to a command run per connection, and that
// command runs inside the namespace too, where the host's loopback is not;
// a unix socket in a private directory of the run's (mode 0700) crosses the
// namespace instead:
//
//   host:   port-bridge.mjs listen <sock> <host:port>   (outside the netns;
//           each connection on <sock> is piped to <host:port>, nothing else)
//   guest:  guestfwd=tcp:10.0.2.100:11434-cmd:node port-bridge.mjs connect <sock>
//           (per guest connection: stdin/stdout ↔ <sock>)
//
//   guest:  port-bridge.mjs relay 127.0.0.1:11434 10.0.2.100:11434
//           (pipeline.sh: the guest's own loopback port relayed to the
//           forward, so every local-model suite finds Ollama at its default
//           URL, and network-model's peer namespace reaches it through its
//           own slirp4netns as the guest's 127.0.0.1)
//
// `listen` refuses a target that is not a loopback address: the bridge is
// for a service on this host, never a way out to another machine. `relay`
// listens on loopback only.
import net from "node:net";
import fs from "node:fs";

export function parseTarget(s, { allowZero = false } = {}) {
  const m = /^(127\.0\.0\.1|localhost|\[::1\]):(\d{1,5})$/.exec(String(s ?? ""));
  if (!m) return null;
  const port = Number(m[2]);
  if (port < (allowZero ? 0 : 1) || port > 65535) return null;
  return { host: m[1] === "[::1]" ? "::1" : m[1] === "localhost" ? "127.0.0.1" : m[1], port };
}

/** host:port with any IPv4 host (the relay's target inside the guest). */
export function parseAddr(s) {
  const m = /^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$/.exec(String(s ?? ""));
  if (!m || Number(m[2]) < 1 || Number(m[2]) > 65535) return null;
  return { host: m[1], port: Number(m[2]) };
}

/**
 * Join two sockets both ways, TCP half-close included: each direction ends on
 * its own (pipe() ends the other side's WRITE half when this side's read half
 * ends) and the sockets close once both directions are done. Both sockets must
 * be allowHalfOpen: with Node's default, a socket whose peer half-closes (a
 * client that sends its request and then its FIN, waiting for the reply)
 * ends its own write half at once, and the reply is lost. That was a bug here
 * until 2026-09-29: every such exchange came back empty. An error on either
 * side tears both down.
 */
export function join(a, b) {
  a.pipe(b); b.pipe(a);
  const kill = () => { a.destroy(); b.destroy(); };
  a.on("error", kill); b.on("error", kill);
}

function pipeTo(target) {
  return (c) => join(c, net.connect({ port: target.port, host: target.host, allowHalfOpen: true }));
}

/** Listen on a unix socket; pipe each connection to target. Resolves to the server. */
export function listen(sock, target) {
  try { fs.unlinkSync(sock); } catch { /* absent */ }
  const server = net.createServer({ allowHalfOpen: true }, pipeTo(target));
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(sock, () => { try { fs.chmodSync(sock, 0o600); } catch { /* best effort */ } resolve(server); });
  });
}

/** Listen on a loopback TCP address (port 0: any free one); pipe each connection to target. Resolves to the server. */
export function relay(from, target) {
  const server = net.createServer({ allowHalfOpen: true }, pipeTo(target));
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(from.port, from.host, () => resolve(server));
  });
}

/**
 * stdin/stdout ↔ the unix socket (one guest connection; qemu gives the
 * command the connection as its stdin and stdout). The guest's FIN (stdin's
 * end) half-closes the socket; the upstream's end is the connection's end:
 * once every byte of it is flushed to stdout the process exits, and qemu
 * closes the guest's side.
 */
export function connect(sock, { stdin = process.stdin, stdout = process.stdout, exit = (code) => process.exit(code) } = {}) {
  const c = net.connect({ path: sock, allowHalfOpen: true });
  stdin.pipe(c);
  c.on("data", (d) => stdout.write(d));
  c.on("end", () => stdout.write("", () => exit(0)));
  c.on("error", () => exit(1));
  stdin.on("error", () => exit(1));
  return c;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [cmd, sock, tgt] = process.argv.slice(2);
  const bail = (m) => { console.error(`port-bridge: ${m}`); process.exit(2); };
  if (cmd === "listen") {
    const target = parseTarget(tgt);
    if (!sock || !target) bail("usage: port-bridge.mjs listen <sock> <127.0.0.1|localhost|[::1]>:<port>");
    listen(sock, target).then(
      () => { console.error(`port-bridge: ${sock} -> ${target.host}:${target.port}`); },
      (e) => bail(`cannot listen on ${sock}: ${e.message}`));
    for (const s of ["SIGTERM", "SIGINT"]) process.on(s, () => { try { fs.unlinkSync(sock); } catch { /* gone */ } process.exit(0); });
  } else if (cmd === "relay") {
    const from = parseTarget(sock, { allowZero: true }), target = parseAddr(tgt);
    if (!from || from.host !== "127.0.0.1" || !target) bail("usage: port-bridge.mjs relay 127.0.0.1:<port|0> <ipv4>:<port>");
    relay(from, target).then(
      (srv) => { console.error(`port-bridge: 127.0.0.1:${srv.address().port} -> ${target.host}:${target.port}`); },
      (e) => bail(`cannot listen on 127.0.0.1:${from.port}: ${e.message}`));
  } else if (cmd === "connect") {
    if (!sock) bail("usage: port-bridge.mjs connect <sock>");
    connect(sock);
  } else {
    bail("usage: port-bridge.mjs listen <sock> <host:port> | connect <sock> | relay 127.0.0.1:<port> <ipv4>:<port>");
  }
}
