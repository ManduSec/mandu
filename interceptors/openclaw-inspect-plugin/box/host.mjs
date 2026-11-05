#!/usr/bin/env node
// host.mjs — the box host: the one process a Mandu launch confines for the
// OpenClaw sandbox backend (docs/design/agents/openclaw-plugin.md §10).
//
// Mandu-new (no reference origin). The plugin starts it as the program of a
// `mandu --target shell --no-reply-filter --require-own-confinement` launch,
// so everything it starts runs in that launch's world: labelled files read
// as their placeholder copies (the secret twins), the network guard lets a
// connection reach only Mandu's egress proxy, Mandu's own folder is hidden,
// no root. It confines nothing itself; it only runs, inside that world, what
// the plugin asks over a Unix socket:
//
//   prepare {command, cwd, env, pty}  → a one-time ticket (the plugin, from
//                                       the sandbox handle's buildExecSpec)
//   run {ticket}                      → the command, its stdin, stdout,
//                                       stderr and exit streamed (the exec
//                                       relay OpenClaw spawns, relay.mjs)
//   shell {script, args}              → a small script (the handle's
//                                       runShellCommand)
//   fs {fsOp, path, root, …}          → one file operation for OpenClaw's
//                                       file tools (the plugin's fs bridge)
//
// Usage: host.mjs --socket <path> [--probe-file <path>] [--no-stdin-lifeline]
// At start it writes one JSON line to stdout, `{"manduBox":1,"ready":true,
// …,"facts":{…}}`, and serves until its stdin closes (the plugin's lifeline:
// the Gateway gone, the box goes, and the launch with it). The facts are what
// it sees of its own world (policy.mjs boxFactsProblems): the plugin uses the
// box only when they show it confined.

import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import {
  closeSync, constants, copyFileSync, existsSync, fstatSync, lstatSync, mkdirSync, openSync, readdirSync, readFileSync,
  readSync, realpathSync, renameSync, rmSync, statSync, unlinkSync, writeSync,
} from "node:fs";
import { createServer } from "node:net";
import { basename, dirname, join, resolve } from "node:path";

import { FrameDecoder, T, encodeFrame, frameJson, CHUNK } from "./frames.mjs";
import { commandArgv, isInside, mergeCommandEnv } from "./policy.mjs";

const TICKET_TTL_MS = 60_000;
const KILL_GRACE_MS = 2_000;
/** The largest file `fs read` returns without a smaller `maxBytes`. */
const READ_MAX = 100 * 1024 * 1024;

function argOf(name) {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

const SOCKET = argOf("--socket");
const PROBE = argOf("--probe-file");
if (!SOCKET) {
  process.stderr.write("mandu box host: --socket <path> is required\n");
  process.exit(78);
}

/** The `script` program, when the box has one (a terminal for a command). */
const SCRIPT_BIN = ["/usr/bin/script", "/bin/script"].find((p) => existsSync(p)) ?? null;

/** What the host sees of its own world (policy.mjs boxFactsProblems). */
function gatherFacts() {
  let seccomp = "";
  try {
    const m = /^Seccomp:\s*(\d+)/m.exec(readFileSync("/proc/self/status", "utf8"));
    seccomp = m ? m[1] : "";
  } catch { /* no procfs: no fact */ }
  let manduHome = "absent";
  if (PROBE) {
    try {
      const fd = openSync(PROBE, constants.O_RDONLY);
      closeSync(fd);
      manduHome = "visible";
    } catch (e) {
      manduHome = e && (e.code === "ENOENT" || e.code === "EACCES" || e.code === "EPERM" || e.code === "ENOTDIR") ? "hidden" : "visible";
    }
  }
  return {
    seccomp,
    manduHome,
    egressProxy: typeof process.env.HTTPS_PROXY === "string" && process.env.HTTPS_PROXY !== "",
    guardPorts: typeof process.env.MANDU_NET_GUARD_PROXY_PORTS === "string" && process.env.MANDU_NET_GUARD_PROXY_PORTS !== "",
  };
}

/** @type {Map<string, {spec: any, at: number}>} */
const tickets = new Map();
/** Live process groups, killed when the host goes. */
const groups = new Set();

function sweepTickets() {
  const now = Date.now();
  for (const [k, v] of tickets) if (now - v.at > TICKET_TTL_MS) tickets.delete(k);
}

function send(sock, type, payload) {
  if (sock.destroyed) return true;
  return sock.write(encodeFrame(type, payload));
}

function fail(sock, error, code) {
  send(sock, T.FAIL, { error: String(error), ...(code ? { code } : {}) });
  sock.end();
}

function killGroup(pid) {
  try { process.kill(-pid, "SIGTERM"); } catch { /* gone */ }
  const t = setTimeout(() => { try { process.kill(-pid, "SIGKILL"); } catch { /* gone */ } }, KILL_GRACE_MS);
  t.unref();
}

/**
 * Run `argv` in the box with `env` and `cwd`, streaming its output to the
 * connection; the connection's own I/E/K frames feed its stdin and signals.
 * The connection closing first kills the command's whole process group.
 */
function runStreamed(sock, decoder, argv, env, cwd, pending) {
  let child;
  try {
    child = spawn(argv[0], argv.slice(1), { cwd, env, detached: true, stdio: ["pipe", "pipe", "pipe"] });
  } catch (e) {
    fail(sock, `the command could not start: ${e && e.message}`, e && e.code);
    return;
  }
  let exited = false;
  child.once("error", (e) => {
    if (exited) return;
    exited = true;
    fail(sock, `the command could not start: ${e.message}`, e.code);
  });
  if (child.pid !== undefined) groups.add(child.pid);
  const pipeOut = (stream, type) => {
    stream.on("data", (d) => {
      if (!send(sock, type, d)) {
        stream.pause();
        sock.once("drain", () => stream.resume());
      }
    });
  };
  pipeOut(child.stdout, T.STDOUT);
  pipeOut(child.stderr, T.STDERR);
  child.stdin.on("error", () => { /* the command closed its stdin */ });
  const onFrame = (f) => {
    if (f.type === T.STDIN) child.stdin.write(f.payload);
    else if (f.type === T.STDIN_END) child.stdin.end();
    else if (f.type === T.SIGNAL) {
      const sig = frameJson(f.payload)?.signal;
      if (typeof sig === "string" && /^SIG[A-Z0-9]+$/.test(sig) && child.pid !== undefined) {
        try { process.kill(-child.pid, sig); } catch { /* gone */ }
      }
    }
  };
  for (const f of pending) onFrame(f);
  sock.on("data", (chunk) => {
    let frames;
    try { frames = decoder.push(chunk); } catch { sock.destroy(); return; }
    for (const f of frames) onFrame(f);
  });
  child.once("close", (code, signal) => {
    if (child.pid !== undefined) groups.delete(child.pid);
    if (exited) return;
    exited = true;
    send(sock, T.EXIT, { code, signal });
    sock.end();
  });
  sock.once("close", () => {
    if (!exited && child.pid !== undefined) killGroup(child.pid);
  });
}

// ── file operations (the plugin's fs bridge) ────────────────────────────────

/** `p`'s canonical form: the realpath of its deepest existing ancestor, the
 *  rest appended. `exists` says whether `p` itself resolved. */
function canonical(p) {
  let head = resolve(p);
  const rest = [];
  for (;;) {
    try {
      const real = realpathSync(head);
      return { path: rest.length ? join(real, ...rest.reverse()) : real, exists: rest.length === 0 };
    } catch (e) {
      if (!e || (e.code !== "ENOENT" && e.code !== "ENOTDIR")) throw e;
      const up = dirname(head);
      if (up === head) return { path: resolve(p), exists: false };
      rest.push(basename(head));
      head = up;
    }
  }
}

function rootOf(req) {
  if (typeof req.root !== "string" || !req.root.startsWith("/")) throw Object.assign(new Error("no root given for the file operation"), { code: "EINVAL" });
  return realpathSync(req.root);
}

/** The canonical path of `p`, refused unless it lies inside `root`. */
function inRoot(root, p, what) {
  if (typeof p !== "string" || !p.startsWith("/")) throw Object.assign(new Error(`${what}: not an absolute path`), { code: "EINVAL" });
  const c = canonical(p);
  if (!isInside(root, c.path)) throw Object.assign(new Error(`${what}: ${p} is outside ${root}`), { code: "EACCES" });
  return c;
}

function statOf(st) {
  return { type: st.isDirectory() ? "directory" : st.isFile() ? "file" : "other", size: st.size, mtimeMs: Math.trunc(st.mtimeMs), nlink: st.nlink };
}

function readInto(sock, path, maxBytes) {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) throw Object.assign(new Error(`${path} is not a regular file`), { code: "EISDIR" });
    const limit = typeof maxBytes === "number" && maxBytes >= 0 ? maxBytes : READ_MAX;
    if (st.size > limit) throw Object.assign(new Error(`File exceeds ${limit} bytes`), { code: "EFBIG" });
    const buf = Buffer.alloc(CHUNK);
    let total = 0;
    for (;;) {
      const n = readSync(fd, buf, 0, buf.length, null);
      if (n === 0) break;
      total += n;
      if (total > limit) throw Object.assign(new Error(`File exceeds ${limit} bytes`), { code: "EFBIG" });
      send(sock, T.DATA, Buffer.from(buf.subarray(0, n)));
    }
    return total;
  } finally {
    closeSync(fd);
  }
}

/** Write `data` to `path` in place (truncate, then write): a placeholder copy
 *  bound over a protected file is written as itself, never replaced. */
function writeInPlace(path, data, exclusive) {
  const flags = constants.O_WRONLY | constants.O_CREAT | constants.O_NOFOLLOW | (exclusive ? constants.O_EXCL : constants.O_TRUNC);
  const fd = openSync(path, flags, 0o666);
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) throw Object.assign(new Error(`${path} is not a regular file`), { code: "EISDIR" });
    let off = 0;
    while (off < data.length) off += writeSync(fd, data, off, data.length - off);
  } finally {
    closeSync(fd);
  }
}

function fsOp(sock, decoder, req, pending) {
  const op = req.fsOp;
  const done = (answer) => { send(sock, T.ANSWER, answer ?? {}); sock.end(); };
  try {
    const root = rootOf(req);
    if (op === "realpath") {
      const c = inRoot(root, req.path, "realpath");
      return done({ path: c.path, exists: c.exists });
    }
    if (op === "stat") {
      const c = inRoot(root, req.path, "stat");
      if (!c.exists) return done({ stat: null });
      return done({ stat: statOf(statSync(c.path)), path: c.path });
    }
    if (op === "read") {
      const c = inRoot(root, req.path, "read");
      if (!c.exists) throw Object.assign(new Error(`Sandbox file not found: ${req.path}`), { code: "ENOENT" });
      const size = readInto(sock, c.path, req.maxBytes);
      return done({ path: c.path, size });
    }
    if (op === "readdir") {
      const c = inRoot(root, req.path, "list");
      const entries = readdirSync(c.path, { withFileTypes: true }).map((d) => {
        let size; let mtimeMs;
        try { const st = lstatSync(join(c.path, d.name)); size = st.size; mtimeMs = Math.trunc(st.mtimeMs); } catch { /* raced */ }
        return { name: d.name, isDirectory: d.isDirectory(), isFile: d.isFile(), ...(size !== undefined ? { size, mtimeMs } : {}) };
      });
      return done({ entries });
    }
    if (op === "mkdirp") {
      const c = inRoot(root, req.path, "create directories");
      mkdirSync(c.path, { recursive: true });
      return done({ path: c.path });
    }
    if (op === "remove") {
      const c = inRoot(root, req.path, "remove");
      if (c.path === root) throw Object.assign(new Error("refusing to remove a mount root"), { code: "EPERM" });
      if (!c.exists) {
        if (req.force === false) throw Object.assign(new Error(`Sandbox path not found: ${req.path}`), { code: "ENOENT" });
        return done({});
      }
      rmSync(c.path, { recursive: req.recursive === true, force: req.force !== false });
      return done({});
    }
    if (op === "rename") {
      const from = inRoot(root, req.path, "rename");
      const toRoot = typeof req.toRoot === "string" ? realpathSync(req.toRoot) : root;
      const to = inRoot(toRoot, req.to, "rename");
      if (from.path === root) throw Object.assign(new Error("refusing to rename a mount root"), { code: "EPERM" });
      renameSync(from.path, to.path);
      return done({});
    }
    if (op === "copy") {
      const from = inRoot(root, req.path, "copy");
      const toRoot = typeof req.toRoot === "string" ? realpathSync(req.toRoot) : root;
      const to = inRoot(toRoot, req.to, "copy");
      if (req.mkdir !== false) mkdirSync(dirname(to.path), { recursive: true });
      copyFileSync(from.path, to.path);
      return done({});
    }
    if (op === "write") {
      const c = inRoot(root, req.path, "write");
      const chunks = [];
      const finish = () => {
        try {
          if (req.mkdir !== false) mkdirSync(dirname(c.path), { recursive: true });
          if (req.exclusive === true && existsSync(c.path)) return done({ created: false });
          writeInPlace(c.path, Buffer.concat(chunks), req.exclusive === true);
          done({ created: true, path: c.path });
        } catch (e) {
          if (req.exclusive === true && e && e.code === "EEXIST") return done({ created: false });
          fail(sock, e && e.message, e && e.code);
        }
      };
      const onFrame = (f) => {
        if (f.type === T.STDIN) chunks.push(f.payload);
        else if (f.type === T.STDIN_END) finish();
      };
      let ended = false;
      const feed = (f) => { if (!ended) { if (f.type === T.STDIN_END) ended = true; onFrame(f); } };
      for (const f of pending) feed(f);
      if (!ended) {
        sock.on("data", (chunk) => {
          let frames;
          try { frames = decoder.push(chunk); } catch { sock.destroy(); return; }
          for (const f of frames) feed(f);
        });
      }
      return undefined;
    }
    throw Object.assign(new Error(`unknown file operation ${JSON.stringify(op)}`), { code: "EINVAL" });
  } catch (e) {
    fail(sock, e && e.message, e && e.code);
  }
  return undefined;
}

// ── the server ──────────────────────────────────────────────────────────────

function onRequest(sock, decoder, req, pending) {
  if (req === null || typeof req !== "object") return fail(sock, "a request is a JSON object");
  if (req.op === "prepare") {
    if (typeof req.command !== "string") return fail(sock, "prepare: no command");
    sweepTickets();
    const ticket = randomBytes(16).toString("hex");
    tickets.set(ticket, {
      spec: { command: req.command, cwd: typeof req.cwd === "string" ? req.cwd : undefined, env: req.env && typeof req.env === "object" ? req.env : {}, pty: req.pty === true },
      at: Date.now(),
    });
    send(sock, T.ANSWER, { ticket });
    sock.end();
    return undefined;
  }
  if (req.op === "run") {
    const t = typeof req.ticket === "string" ? tickets.get(req.ticket) : undefined;
    if (t === undefined || Date.now() - t.at > TICKET_TTL_MS) return fail(sock, "run: unknown or expired ticket");
    tickets.delete(req.ticket);
    const env = mergeCommandEnv(process.env, t.spec.env);
    return runStreamed(sock, decoder, commandArgv(t.spec.command, t.spec.pty, SCRIPT_BIN), env, t.spec.cwd, pending);
  }
  if (req.op === "shell") {
    if (typeof req.script !== "string") return fail(sock, "shell: no script");
    const args = Array.isArray(req.args) ? req.args.filter((a) => typeof a === "string") : [];
    return runStreamed(sock, decoder, ["/bin/sh", "-c", req.script, "mandu-box", ...args], mergeCommandEnv(process.env, {}), typeof req.cwd === "string" ? req.cwd : undefined, pending);
  }
  if (req.op === "fs") return fsOp(sock, decoder, req, pending);
  if (req.op === "ping") {
    send(sock, T.ANSWER, { pong: true, pid: process.pid });
    sock.end();
    return undefined;
  }
  return fail(sock, `unknown op ${JSON.stringify(req.op)}`);
}

const server = createServer((sock) => {
  const decoder = new FrameDecoder();
  let started = false;
  const first = (chunk) => {
    let frames;
    try { frames = decoder.push(chunk); } catch { sock.destroy(); return; }
    if (frames.length === 0) return;
    sock.off("data", first);
    started = true;
    const [head, ...rest] = frames;
    if (head.type !== T.REQUEST) { fail(sock, "the first frame must be a request"); return; }
    onRequest(sock, decoder, frameJson(head.payload), rest);
  };
  sock.on("data", first);
  sock.on("error", () => { /* the peer went away */ });
  setTimeout(() => { if (!started) sock.destroy(); }, 30_000).unref();
});

function shutdown(code) {
  for (const pid of groups) { try { process.kill(-pid, "SIGKILL"); } catch { /* gone */ } }
  try { server.close(); } catch { /* not listening */ }
  try { unlinkSync(SOCKET); } catch { /* gone */ }
  process.exit(code);
}

try { unlinkSync(SOCKET); } catch { /* none left */ }
server.on("error", (e) => {
  process.stderr.write(`mandu box host: cannot listen on ${SOCKET}: ${e.message}\n`);
  process.exit(71);
});
server.listen(SOCKET, () => {
  process.stdout.write(`${JSON.stringify({ manduBox: 1, ready: true, pid: process.pid, socket: SOCKET, facts: gatherFacts() })}\n`);
});

if (!process.argv.includes("--no-stdin-lifeline")) {
  process.stdin.on("end", () => shutdown(0));
  process.stdin.on("close", () => shutdown(0));
  process.stdin.on("error", () => shutdown(0));
  process.stdin.resume();
}
process.on("SIGTERM", () => shutdown(0));
process.on("SIGINT", () => shutdown(0));
process.on("SIGHUP", () => shutdown(0));
