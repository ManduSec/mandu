// ci-port-bridge.test.mjs — scripts/ci/port-bridge.mjs, the nightly guest's
// one link to the host's Ollama (docs/design/testing/continuous-integration.md §9.2), under
// load: many connections at once, TCP half-close both ways, payloads larger
// than a socket buffer, and the `connect` command run the way qemu's guestfwd
// runs it (a child process whose stdin/stdout are the guest connection).
//
// Until 2026-09-29 the bridge's sockets were not allowHalfOpen: a client that
// sent its request and then its FIN got an empty reply, every time (the
// ci-vm-run relay check only passed by retrying). Each case below failed on
// that code. Offline: loopback and a unix socket in a temp dir.
//
// Run: node --test scripts/test/ci-port-bridge.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { randomBytes, createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { listen, relay, parseTarget } from "../ci/port-bridge.mjs";

const PB = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "ci", "port-bridge.mjs");
const sha = (b) => createHash("sha256").update(b).digest("hex");

/** An upstream that answers `sha256:<hex of everything received>` once the client half-closes. */
async function hashServer() {
  const s = net.createServer((c) => {
    const h = createHash("sha256");
    c.on("data", (d) => h.update(d)).on("end", () => c.end(`sha256:${h.digest("hex")}`)).on("error", () => {});
  });
  await new Promise((r) => s.listen(0, "127.0.0.1", r));
  return s;
}
/** An upstream that sends `size` bytes at once and closes, whatever the client does (a server-ends-first exchange). */
async function blobServer(blob) {
  const s = net.createServer((c) => { c.on("error", () => {}); c.end(blob); });
  await new Promise((r) => s.listen(0, "127.0.0.1", r));
  return s;
}
/** A client exchange over TCP: write `payload`, half-close, collect until close. */
function tcpExchange(port, payload, { halfClose = true } = {}) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    const c = net.connect({ port, host: "127.0.0.1", allowHalfOpen: true }, () => {
      if (payload) c.write(payload);
      if (halfClose) c.end();
    });
    c.on("data", (d) => chunks.push(d)).on("close", () => resolve(Buffer.concat(chunks))).on("error", reject);
    if (!halfClose) c.on("end", () => c.end());
  });
}
/** `port-bridge.mjs connect <sock>` as qemu runs it: stdin/stdout are the connection. */
function connectExchange(sock, payload) {
  return new Promise((resolve, reject) => {
    const p = spawn(process.execPath, [PB, "connect", sock], { stdio: ["pipe", "pipe", "pipe"] });
    const out = [], err = [];
    p.stdout.on("data", (d) => out.push(d)); p.stderr.on("data", (d) => err.push(d));
    p.on("error", reject);
    p.on("close", (code) => resolve({ code, out: Buffer.concat(out), err: Buffer.concat(err).toString() }));
    p.stdin.end(payload);
  });
}
async function pool(n, width, fn) {
  let next = 0; const errors = [];
  await Promise.all(Array.from({ length: width }, async () => {
    while (next < n) { const i = next++; try { await fn(i); } catch (e) { errors.push(`#${i}: ${e.message}`); } }
  }));
  return errors;
}
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), "pb-"));

test("relay: 400 half-closing clients, 64 at once, each gets exactly its own reply", async () => {
  const up = await hashServer();
  const r = await relay({ host: "127.0.0.1", port: 0 }, { host: "127.0.0.1", port: up.address().port });
  try {
    const errors = await pool(400, 64, async (i) => {
      const payload = randomBytes(1 + (i % 7) * 1000);
      const got = (await tcpExchange(r.address().port, payload)).toString();
      assert.equal(got, `sha256:${sha(payload)}`);
    });
    assert.deepEqual(errors, []);
  } finally { r.close(); up.close(); }
});

test("relay: 4 MiB each way survives, and a server that ends first reaches a client that never half-closes", async () => {
  const up = await hashServer();
  const big = randomBytes(4 * 1024 * 1024);
  const r = await relay({ host: "127.0.0.1", port: 0 }, { host: "127.0.0.1", port: up.address().port });
  const blob = randomBytes(4 * 1024 * 1024);
  const down = await blobServer(blob);
  const r2 = await relay({ host: "127.0.0.1", port: 0 }, { host: "127.0.0.1", port: down.address().port });
  try {
    assert.equal((await tcpExchange(r.address().port, big)).toString(), `sha256:${sha(big)}`);
    const errors = await pool(40, 16, async () => {
      assert.equal(sha(await tcpExchange(r2.address().port, null, { halfClose: false })), sha(blob));
    });
    assert.deepEqual(errors, []);
  } finally { r.close(); up.close(); r2.close(); down.close(); }
});

test("listen + connect (the guestfwd path): 150 connect processes, 24 at once, each exact; exit 0; nothing on stderr", async () => {
  const up = await hashServer();
  const d = tmp(); const sock = path.join(d, "s");
  const srv = await listen(sock, { host: "127.0.0.1", port: up.address().port });
  try {
    const errors = await pool(150, 24, async (i) => {
      const payload = randomBytes(1 + (i % 5) * 70_000);
      const r = await connectExchange(sock, payload);
      assert.equal(r.code, 0, r.err);
      assert.equal(r.err, "", "the guest connection is also the command's stderr: nothing may be written there");
      assert.equal(r.out.toString(), `sha256:${sha(payload)}`);
    });
    assert.deepEqual(errors, []);
  } finally { srv.close(); up.close(); fs.rmSync(d, { recursive: true, force: true }); }
});

test("connect: an upstream that ends first ends the connection after every byte is flushed", async () => {
  const blob = randomBytes(3 * 1024 * 1024);
  const down = await blobServer(blob);
  const d = tmp(); const sock = path.join(d, "s");
  const srv = await listen(sock, { host: "127.0.0.1", port: down.address().port });
  try {
    const errors = await pool(20, 8, async () => {
      const p = spawn(process.execPath, [PB, "connect", sock], { stdio: ["pipe", "pipe", "pipe"] });
      const out = [];
      p.stdout.on("data", (x) => out.push(x));
      const code = await new Promise((r) => p.on("close", r));   // stdin left open: the upstream ends it
      assert.equal(code, 0);
      assert.equal(sha(Buffer.concat(out)), sha(blob));
    });
    assert.deepEqual(errors, []);
  } finally { srv.close(); down.close(); fs.rmSync(d, { recursive: true, force: true }); }
});

test("connect: no bridge behind the socket exits non-zero at once", async () => {
  const d = tmp();
  const r = await connectExchange(path.join(d, "absent"), Buffer.from("x"));
  assert.notEqual(r.code, 0);
  fs.rmSync(d, { recursive: true, force: true });
});

test("parseTarget: loopback only; port 0 only where asked (the relay's own listen)", () => {
  assert.deepEqual(parseTarget("127.0.0.1:11434"), { host: "127.0.0.1", port: 11434 });
  assert.deepEqual(parseTarget("localhost:1"), { host: "127.0.0.1", port: 1 });
  assert.equal(parseTarget("10.0.2.2:11434"), null);
  assert.equal(parseTarget("0.0.0.0:11434"), null);
  assert.equal(parseTarget("127.0.0.1:0"), null);
  assert.deepEqual(parseTarget("127.0.0.1:0", { allowZero: true }), { host: "127.0.0.1", port: 0 });
});
