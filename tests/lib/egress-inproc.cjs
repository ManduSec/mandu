/**
 * egress-inproc — the egress box's FALLBACK recorder (egress-box.ts, tier
 * "inproc"), loaded into every Node process of the program under test with
 * `NODE_OPTIONS=--require …` where no private network namespace can be made.
 *
 * NEW Mandu test code (no reference origin). WEAKER than the box, and the
 * box says so in its tier: it sees only what goes through Node's own `net`
 * and `dns` in processes that load it (a child that is not Node, native
 * code, or a process that clears NODE_OPTIONS is not seen), and it blocks
 * nothing (the test also points HTTPS_PROXY at a refusing recorder).
 *
 * Records one JSON line per TCP connect (`via: "inproc"`, host, port, the
 * TLS servername where one is set) and per name lookup (`via: "inproc-dns"`)
 * to $MANDU_EGRESS_RECORDS.
 */
"use strict";
const fs = require("node:fs");
const net = require("node:net");
const tls = require("node:tls");
const dns = require("node:dns");

const out = process.env.MANDU_EGRESS_RECORDS;
if (out) {
  const record = (r) => {
    try { fs.appendFileSync(out, JSON.stringify({ t: Date.now(), pid: process.pid, ...r }) + "\n"); } catch { /* best effort */ }
  };
  /** The TCP target of connect()'s arguments, or null (a unix path). */
  const target = (args) => {
    let o = args[0];
    if (Array.isArray(o)) o = o[0];
    if (o !== null && typeof o === "object") {
      // (http's agent passes the request's own `path` beside the port.)
      return o.port !== undefined && o.port !== null && typeof o.socketPath !== "string"
        ? { host: String(o.host ?? o.hostname ?? "localhost"), port: Number(o.port) } : null;
    }
    if (typeof o === "number" || (typeof o === "string" && /^\d+$/.test(o))) {
      return { host: typeof args[1] === "string" ? args[1] : "localhost", port: Number(o) };
    }
    return null;
  };
  // Both doors: the module functions (http's agent calls
  // net.createConnection, which reaches the socket's connect through a
  // captured reference) and the prototype (a socket made first, connected
  // after).
  let inside = 0;
  const doors = [[net, "connect"], [net, "createConnection"], [require("node:http").Agent.prototype, "createConnection"]];
  for (const [obj, name] of doors) {
    const orig = obj[name];
    obj[name] = function patched(...args) {
      if (inside === 0) {
        try { const tg = target(args); if (tg) record({ via: "inproc", ...tg }); } catch { /* never break the program */ }
      }
      inside++;
      try { return orig.apply(this, args); } finally { inside--; }
    };
  }
  const origConnect = net.Socket.prototype.connect;
  net.Socket.prototype.connect = function patchedConnect(...args) {
    if (inside === 0) {
      try { const tg = target(args); if (tg) record({ via: "inproc", ...tg }); } catch { /* never break the program */ }
    }
    return origConnect.apply(this, args);
  };
  const origTls = tls.connect;
  tls.connect = function patchedTlsConnect(...args) {
    if (inside === 0) {
      try {
        const o = args.find((a) => a !== null && typeof a === "object") ?? {};
        const sni = o.servername ?? o.host ?? (typeof args[1] === "string" ? args[1] : null);
        if (sni) record({ via: "inproc", sni: String(sni), host: String(o.host ?? sni), port: Number(o.port ?? args[0] ?? 443) });
      } catch { /* never break the program */ }
    }
    inside++;
    try { return origTls.apply(this, args); } finally { inside--; }
  };
  const origLookup = dns.lookup;
  dns.lookup = function patchedLookup(host, ...rest) {
    try { record({ via: "inproc-dns", name: String(host).toLowerCase() }); } catch { /* never break the program */ }
    return origLookup.call(this, host, ...rest);
  };
}
