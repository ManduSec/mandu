/**
 * egress-box-host — the process INSIDE an egress box (egress-box.ts): a
 * private network namespace with only loopback, in which a program under
 * test (an OpenClaw Gateway, its clients) runs, and from which nothing can
 * leave except through the bridges this process holds.
 *
 * NEW Mandu test code (no reference origin). Plain ESM with no dependency:
 * it runs under whatever `node` the box finds, before any package's
 * node_modules are in reach.
 *
 *   node egress-box-host.mjs <config.json>
 *
 * What it does, once the namespace is set up (egress-box.ts does that: the
 * loopback up, every IPv4 address routed to it where it may, the hosts file,
 * nsswitch.conf and resolv.conf bind-mounted):
 *   - BRIDGES: for each allowed port P (the Mandu model proxy's), listens on
 *     127.0.0.1:P inside and pipes every connection to the unix socket
 *     <dir>/out-P.sock, which the test process forwards to 127.0.0.1:P
 *     outside. Each bridged connection is recorded (`via: "bridge"`), with
 *     its first HTTP request line where it has one.
 *   - THE CATCH-ALL: for each catch port (80, 443 and the test's own: every
 *     scripted upstream's port, Ollama's and LM Studio's defaults) not
 *     bridged, listens on 0.0.0.0 and records every connection (`via:
 *     "catch"`): the address dialed, the name it stands for (the DNS stub's
 *     or the hosts file's answer), the TLS SNI or the HTTP request line and
 *     Host. It answers nothing useful: TLS is closed after the ClientHello,
 *     HTTP gets a 503. Nothing it receives goes anywhere.
 *   - THE DNS STUB (where it may bind port 53): answers every A query with an
 *     address of its own in 127.77.0.0/16, one per name, and records the
 *     query (`via: "dns"`); AAAA and the rest get an empty answer.
 *   - THE CONTROL SOCKET <dir>/ctl.sock: one JSON request line per
 *     connection, `{op: "exec", argv, env, cwd}`: the program runs inside
 *     the box, its own process group, its output streamed back as JSON lines
 *     (`{t: "o"|"e", d: <base64>}`, then `{t: "x", code, signal}`); a later
 *     `{op: "kill", signal}` line signals its group; the connection closing
 *     first kills it (SIGTERM, SIGKILL 5 s later).
 * Every record is one JSON line appended to <dir>/records.ndjson. It writes
 * <dir>/ready.json once everything listens, naming what it could and could
 * not set up (a low port refused without CAP_NET_BIND_SERVICE: the box is
 * then still closed, but a dial to that port is refused, not attributed).
 */
import { spawn } from "node:child_process";
import { createSocket } from "node:dgram";
import { appendFileSync, existsSync, readdirSync, readFileSync, readlinkSync, writeFileSync } from "node:fs";
import { connect, createServer } from "node:net";
import { join } from "node:path";
import { TLSSocket } from "node:tls";

const cfg = JSON.parse(readFileSync(process.argv[2], "utf8"));
const dir = cfg.dir;
const recordsFile = join(dir, "records.ndjson");
/** address → the name it answers for (the hosts file's, then the stub's). */
const names = new Map(Object.entries(cfg.names ?? {}));
let nextDns = 1;

function record(r) {
  try { appendFileSync(recordsFile, JSON.stringify({ t: Date.now(), ...r }) + "\n"); } catch { /* the box is going away */ }
}

/** The SNI of a TLS ClientHello, or null. Exported shape mirrored in egress-box.ts parseSni. */
function parseSni(buf) {
  try {
    if (buf.length < 43 || buf[0] !== 0x16 || buf[5] !== 0x01) return null;
    let p = 43; // record header 5 + handshake header 4 + version 2 + random 32
    p += 1 + buf[p]; // session id
    p += 2 + buf.readUInt16BE(p); // cipher suites
    p += 1 + buf[p]; // compression methods
    const end = p + 2 + buf.readUInt16BE(p);
    p += 2;
    while (p + 4 <= end && p + 4 <= buf.length) {
      const type = buf.readUInt16BE(p);
      const len = buf.readUInt16BE(p + 2);
      p += 4;
      if (type === 0) {
        // server_name list: len(2) type(1) namelen(2) name
        const nameLen = buf.readUInt16BE(p + 3);
        return buf.subarray(p + 5, p + 5 + nameLen).toString("latin1");
      }
      p += len;
    }
  } catch { /* a short or odd hello */ }
  return null;
}

/** The request line and Host of an HTTP request's first bytes, or null. */
function parseHttp(buf) {
  const text = buf.subarray(0, 4096).toString("latin1");
  const m = /^([A-Z]{3,10}) (\S+) HTTP\/1\.[01]\r?\n/.exec(text);
  if (!m) return null;
  const host = /\r?\nhost:\s*([^\r\n]+)/i.exec(text)?.[1]?.trim() ?? null;
  return { method: m[1], path: m[2], host };
}

/** Read the first bytes of a connection (at most `ms`). */
function firstBytes(sock, ms) {
  return new Promise((resolve) => {
    let buf = Buffer.alloc(0);
    const done = () => { clearTimeout(timer); sock.removeListener("data", onData); resolve(buf); };
    const onData = (d) => {
      buf = Buffer.concat([buf, d]);
      if (buf.length >= 5 && buf[0] === 0x16) {
        const need = 5 + buf.readUInt16BE(3);
        if (buf.length >= need) done();
      } else if (buf.includes("\r\n\r\n") || buf.length > 8192) done();
    };
    const timer = setTimeout(done, ms);
    sock.on("data", onData);
    sock.on("error", () => {});
    sock.on("close", done);
  });
}

const facts = { pid: process.pid, uid: process.getuid?.() ?? null, bridges: [], catch: [], refused: [], dns: null, dropTo: null };

async function listen(server, port, host) {
  return new Promise((resolve) => {
    server.once("error", (e) => resolve(e.code ?? String(e)));
    if (typeof port === "string") server.listen(port, () => resolve(null));
    else server.listen(port, host, () => resolve(null));
  });
}

// ── bridges ─────────────────────────────────────────────────────────────────
for (const port of cfg.allow ?? []) {
  const srv = createServer((inner) => {
    inner.pause();
    const outer = connect(join(dir, `out-${port}.sock`));
    let first = true;
    inner.on("data", (d) => {
      if (first) {
        first = false;
        const http = parseHttp(d);
        record({ via: "bridge", port, laddr: inner.localAddress, ...(http ? { http } : {}) });
      }
    });
    inner.pipe(outer);
    outer.pipe(inner);
    const end = () => { inner.destroy(); outer.destroy(); };
    inner.on("error", end);
    outer.on("error", end);
    inner.on("close", end);
    outer.on("close", end);
    outer.on("connect", () => inner.resume());
  });
  const err = await listen(srv, port, "127.0.0.1");
  if (err) facts.refused.push({ port, why: `bridge: ${err}` });
  else facts.bridges.push(port);
}

// ── the catch-all ────────────────────────────────────────────────────────────
const catchPorts = [...new Set([80, 443, ...(cfg.catchPorts ?? [])])].filter((p) => !(cfg.allow ?? []).includes(p));
// With a peek certificate (cfg.tls: the programs are told to accept any
// certificate, NODE_TLS_REJECT_UNAUTHORIZED=0), a TLS connection is
// terminated here and its HTTP request read too: the path and the head of
// the body say what the call was.
const TLS = cfg.tls ? { key: readFileSync(cfg.tls.key), cert: readFileSync(cfg.tls.cert) } : null;
facts.tlsPeek = TLS !== null;

/** The first HTTP request on a stream: its line, Host, and the body's head. */
function readRequest(stream, ms) {
  return new Promise((resolve) => {
    let buf = Buffer.alloc(0);
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      stream.removeListener("data", onData);
      const http = parseHttp(buf);
      const at = buf.indexOf("\r\n\r\n");
      resolve(http ? { ...http, body: at >= 0 ? buf.subarray(at + 4, at + 4 + 4096).toString("utf8") : "" } : null);
    };
    const onData = (d) => {
      buf = Buffer.concat([buf, d]);
      const at = buf.indexOf("\r\n\r\n");
      if (at < 0) { if (buf.length > 65536) finish(); return; }
      const len = Number(/\r?\ncontent-length:\s*(\d+)/i.exec(buf.subarray(0, at).toString("latin1"))?.[1] ?? 0);
      if (buf.length - at - 4 >= Math.min(len, 4096)) finish();
    };
    const timer = setTimeout(finish, ms);
    stream.on("data", onData);
    stream.on("error", finish);
    stream.on("end", finish);
    stream.on("close", finish);
  });
}


/** A process's parent pid and start time (/proc/<pid>/stat, which every
 *  process exposes), or null. */
function statOf(pid) {
  try {
    const f = readFileSync(`/proc/${pid}/stat`, "utf8").replace(/^.*\)\s+/, "").split(" ");
    return { ppid: f[1], start: f[19] };
  } catch { return null; }
}

/** The command line of every process the box has seen, by pid and start
 *  time: a process that exits or hides itself (a non-dumpable one, or one
 *  past releasing its memory on the way out, shows an empty cmdline) is
 *  still named by what it ran. Filled by a 25 ms sweep of /proc and by
 *  every lookup. */
const seen = new Map();
function cmdlineOf(pid) {
  const st = statOf(pid);
  let cmd = "";
  try { cmd = readFileSync(`/proc/${pid}/cmdline`, "utf8").split("\0").filter(Boolean).join(" ").slice(0, 300); } catch { /* gone or hidden */ }
  const key = st ? `${pid}:${st.start}` : null;
  if (cmd !== "" && key) seen.set(key, cmd);
  if (cmd === "" && key && seen.has(key)) return seen.get(key);
  return cmd;
}
function sweep() {
  try { for (const d of readdirSync("/proc")) if (/^\d+$/.test(d) && Number(d) !== process.pid) cmdlineOf(d); } catch { /* best effort */ }
}
setInterval(sweep, 25).unref();

/** A process's command line and up to three parents'. */
function chainOf(pid) {
  const chain = [];
  for (let p = String(pid), i = 0; p && p !== "0" && i < 4; i++) {
    const st = statOf(p);
    if (st === null) break;
    chain.push(cmdlineOf(p));
    p = st.ppid;
  }
  return chain;
}

/**
 * Which program dialed (or asked the DNS stub): the process holding the
 * client end of the socket, found by its inode in /proc/net/{tcp,udp} and the
 * /proc/<pid>/fd link to it, with its parents' command lines. Read while the
 * client waits on the box (before the box answers it).
 *
 * A process can hide its descriptors: one that made itself non-dumpable
 * (Claude Code's CLI does, part way through its start) has /proc/<pid>/fd
 * owned by a root this box does not hold. When no readable process holds
 * the socket, the holder is one of those whose descriptors cannot be read:
 * the answer is then that candidate set (`pid: null`, `candidates`), which
 * the judge accepts only when every candidate is a program named benign.
 * `why` says why there is no single answer.
 */
function dialerOnce(clientPort, serverPort, proto) {
  const hex = (n) => n.toString(16).toUpperCase().padStart(4, "0");
  let inode = null;
  for (const f of [`/proc/net/${proto}`, `/proc/net/${proto}6`]) {
    let text = "";
    try { text = readFileSync(f, "utf8"); } catch { continue; }
    for (const line of text.split("\n").slice(1)) {
      const c = line.trim().split(/\s+/);
      if (c.length < 10) continue;
      // (a DNS query's UDP socket is not connected: its local port alone)
      if (c[1].endsWith(`:${hex(clientPort)}`) && (serverPort === null || c[2].endsWith(`:${hex(serverPort)}`))) { inode = c[9]; break; }
    }
    if (inode) break;
  }
  if (!inode || inode === "0") return { why: `no ${proto} socket for port ${clientPort}` };
  const want = `socket:[${inode}]`;
  const hidden = [];
  for (const pid of readdirSync("/proc").filter((d) => /^\d+$/.test(d))) {
    if (Number(pid) === process.pid) continue;
    let fds;
    try { fds = readdirSync(`/proc/${pid}/fd`); } catch (e) {
      if (e && (e.code === "EACCES" || e.code === "EPERM")) hidden.push(Number(pid));
      continue;
    }
    if (fds.some((fd) => { try { return readlinkSync(`/proc/${pid}/fd/${fd}`) === want; } catch { return false; } })) {
      return { pid: Number(pid), chain: chainOf(pid) };
    }
  }
  const candidates = hidden.map((pid) => ({ pid, chain: chainOf(pid) })).filter((c) => c.chain.length > 0);
  if (candidates.length > 0) return { pid: null, chain: [], candidates, why: `socket:[${inode}] is held by a process whose descriptors cannot be read` };
  return { why: `no process holds socket:[${inode}]` };
}

const sleepMs = (ms) => new Promise((r) => setTimeout(r, ms));

/** dialerOnce, asked again a few times (a socket the kernel has not yet
 *  listed, a process mid-exec) while the client still waits. */
async function dialer(clientPort, serverPort, proto = "tcp") {
  let last = null;
  for (const wait of [0, 10, 40, 120]) {
    if (wait) await sleepMs(wait);
    try { last = dialerOnce(clientPort, serverPort, proto); } catch (e) { last = { why: String(e) }; }
    if (last.pid !== undefined) return last;
  }
  return last;
}

const DENY = "HTTP/1.1 503 Service Unavailable\r\ncontent-type: text/plain\r\nconnection: close\r\ncontent-length: 34\r\n\r\nmandu egress box: nothing leaves.\n";

for (const port of catchPorts) {
  const srv = createServer(async (sock) => {
    const laddr = (sock.localAddress ?? "").replace(/^::ffff:/, "");
    const lport = sock.localPort;
    sock.on("error", () => {});
    const who = await dialer(sock.remotePort, lport);
    const buf = await firstBytes(sock, 3000);
    const sni = parseSni(buf);
    const base = { via: "catch", laddr, lport, name: names.get(laddr) ?? null, ...(sni !== null ? { sni } : {}), bytes: buf.length, ...(who.pid !== undefined ? { dialer: who } : { dialerWhy: who.why }) };
    if (sni !== null && TLS !== null) {
      sock.pause();
      sock.unshift(buf);
      const tlsSock = new TLSSocket(sock, { isServer: true, key: TLS.key, cert: TLS.cert });
      let tlsError = null;
      tlsSock.on("error", (e) => { tlsError ??= String(e.code ?? e.message ?? e); });
      const req = await readRequest(tlsSock, 5000);
      record({ ...base, ...(req ? { http: { method: req.method, path: req.path, host: req.host }, body: req.body } : { tls: tlsError ?? "no request after the handshake" }) });
      try { if (req) tlsSock.end(DENY); else tlsSock.destroy(); } catch { /* gone */ }
      return;
    }
    const http = sni === null ? parseHttp(buf) : null;
    if (http) {
      const at = buf.indexOf("\r\n\r\n");
      record({ ...base, http, body: at >= 0 ? buf.subarray(at + 4, at + 4 + 4096).toString("utf8") : "" });
      try { sock.end(DENY); } catch { /* gone */ }
    } else {
      record(base);
      sock.destroy();
    }
  });
  const err = await listen(srv, port, "0.0.0.0");
  if (err) facts.refused.push({ port, why: err });
  else facts.catch.push(port);
}

// ── the DNS stub ─────────────────────────────────────────────────────────────
function dnsName(msg, p) {
  const labels = [];
  for (let n = 0; n < 128 && p < msg.length; n++) {
    const len = msg[p];
    if (len === 0) return { name: labels.join("."), end: p + 1 };
    labels.push(msg.subarray(p + 1, p + 1 + len).toString("latin1"));
    p += 1 + len;
  }
  return null;
}
function addressFor(name) {
  const lower = name.toLowerCase().replace(/\.$/, "");
  for (const [a, n] of names) if (n === lower) return a;
  const n = nextDns++;
  const a = `127.77.${(n >> 8) & 255}.${n & 255}`;
  names.set(a, lower);
  return a;
}
if (cfg.dns !== false) {
  const udp = createSocket("udp4");
  udp.on("message", async (msg, rinfo) => {
    if (msg.length < 12) return;
    const q = dnsName(msg, 12);
    if (!q || q.end + 4 > msg.length) return;
    const qtype = msg.readUInt16BE(q.end);
    const question = msg.subarray(12, q.end + 4);
    const isA = qtype === 1;
    const addr = isA ? addressFor(q.name) : null;
    // Who asked: a process that dials and exits at once (a CLI's probe) is
    // gone before its connection is read, but alive when it looks the name up.
    const who = await dialer(rinfo.port, null, "udp");
    record({ via: "dns", name: q.name.toLowerCase(), qtype, ...(addr ? { answer: addr } : {}), ...(who.pid !== undefined ? { dialer: who } : { dialerWhy: who.why }) });
    const head = Buffer.alloc(12);
    msg.copy(head, 0, 0, 2);
    head.writeUInt16BE(0x8180 | (msg.readUInt16BE(2) & 0x0100), 2);
    head.writeUInt16BE(1, 4);
    head.writeUInt16BE(isA ? 1 : 0, 6);
    const parts = [head, question];
    if (isA) {
      const ans = Buffer.alloc(16);
      ans.writeUInt16BE(0xc00c, 0);
      ans.writeUInt16BE(1, 2);
      ans.writeUInt16BE(1, 4);
      ans.writeUInt32BE(5, 6);
      ans.writeUInt16BE(4, 10);
      addr.split(".").forEach((o, i) => { ans[12 + i] = Number(o); });
      parts.push(ans);
    }
    udp.send(Buffer.concat(parts), rinfo.port, rinfo.address);
  });
  facts.dns = await new Promise((resolve) => {
    udp.once("error", (e) => resolve(`refused (${e.code ?? e})`));
    udp.bind(53, "127.0.0.1", () => resolve("127.0.0.1:53"));
  });
}

// ── the control socket ───────────────────────────────────────────────────────
// Where the box holds capabilities (over its own namespaces only), the
// programs it runs do not: each one starts in a nested user namespace as the
// invoking user (`unshare --map-user`), with no capability anywhere.
const UNSHARE = ["/usr/bin/unshare", "/bin/unshare"].find((p) => existsSync(p)) ?? null;
const dropTo = cfg.dropTo ?? null;
facts.dropTo = dropTo === null ? "not needed" : UNSHARE === null ? "unshare missing" : dropTo;
const wrapArgv = (argv) => (dropTo !== null && UNSHARE !== null
  ? [UNSHARE, "--user", `--map-user=${dropTo.uid}`, `--map-group=${dropTo.gid}`, "--", ...argv]
  : argv);

const ctl = createServer((conn) => {
  let buf = "";
  let child = null;
  let exited = false;
  const send = (o) => { try { conn.write(JSON.stringify(o) + "\n"); } catch { /* gone */ } };
  const killGroup = (sig) => { if (child && !exited) { try { process.kill(-child.pid, sig); } catch { /* gone */ } } };
  conn.on("data", (d) => {
    buf += d.toString("utf8");
    for (let i = buf.indexOf("\n"); i >= 0; i = buf.indexOf("\n")) {
      const line = buf.slice(0, i);
      buf = buf.slice(i + 1);
      let req;
      try { req = JSON.parse(line); } catch { continue; }
      if (req.op === "kill") { killGroup(req.signal ?? "SIGTERM"); continue; }
      if (req.op !== "exec" || child) continue;
      const argv = wrapArgv(req.argv);
      // The peek certificate is accepted only by the programs in the box.
      const env = TLS !== null ? { ...req.env, NODE_TLS_REJECT_UNAUTHORIZED: "0" } : req.env;
      try {
        child = spawn(argv[0], argv.slice(1), { cwd: req.cwd, env, stdio: ["ignore", "pipe", "pipe"], detached: true });
      } catch (e) {
        send({ t: "x", code: 127, signal: null, error: String(e) });
        conn.end();
        continue;
      }
      child.on("error", (e) => { exited = true; send({ t: "x", code: 127, signal: null, error: String(e) }); conn.end(); });
      child.stdout.on("data", (c) => send({ t: "o", d: c.toString("base64") }));
      child.stderr.on("data", (c) => send({ t: "e", d: c.toString("base64") }));
      child.on("close", (code, signal) => { exited = true; send({ t: "x", code, signal }); conn.end(); });
    }
  });
  conn.on("error", () => {});
  conn.on("close", () => {
    if (!child || exited) return;
    killGroup("SIGTERM");
    setTimeout(() => killGroup("SIGKILL"), 5000).unref();
  });
});
const ctlErr = await listen(ctl, join(dir, "ctl.sock"));
if (ctlErr) { console.error(`egress-box-host: the control socket: ${ctlErr}`); process.exit(2); }

writeFileSync(join(dir, "ready.json"), JSON.stringify(facts) + "\n");
// The box lives until the test closes it (SIGTERM to this process's group).
process.on("SIGTERM", () => process.exit(0));
