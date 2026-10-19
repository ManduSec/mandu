/**
 * e2e — the arbiter half of reply row reservation
 * (docs/design/ui/reply-row-reservation.md §3.3, §3.6, §6, §11.5) through the
 * REAL ArbiterServer and the PRODUCTION ArbiterClient. Every op here is
 * human-plane: it is served on the human socket and refused on the data
 * socket (the socket every interceptor, and the agent's own processes, can
 * reach). The data client only mints symbols.
 * Mandu-new, no reference origin.
 *
 * The invariant half: `symbolShape` puts ONLY a line count on the wire. The
 * raw NDJSON reply is read off the socket, so a client that parsed away an
 * extra field could not hide it.
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { connect } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

const SECRET = [
  "-----BEGIN OPENSSH PRIVATE KEY-----",
  "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW",
  "QyNTUxOQAAACDzRRR_ROW_RESERVATION_CANARY_7f3a9c",
  "-----END OPENSSH PRIVATE KEY-----",
  "",
].join("\n");

let dir: string;
let sock: string;
let server: ArbiterServer;
let client: ArbiterClient;
let humanSock: string;
let human: ArbiterClient;

before(async () => {
  dir = mkdtempSync(join(tmpdir(), "mandu-rrr-e2e-"));
  sock = join(dir, "a.sock");
  server = new ArbiterServer({
    socketPath: sock, dbPath: join(dir, "symbols.db"), eventDir: join(dir, "events"),
    adminSocketPath: join(dir, "admin.sock"),
    humanSocketPath: join(dir, "human", "a.sock"),
    log: () => {}, confidentiality: true, integrity: false, policyDocument: {}, policyPollMs: 0,
  });
  await server.listen();
  client = new ArbiterClient(sock); // the DATA socket: mints symbols; refuses every op below
  await client.connect();
  humanSock = join(dir, "human", "a.sock");
  human = new ArbiterClient(humanSock); // symbolShape and the relay ops: human plane only (§5.3, §11.5)
  await human.connect();
});

after(async () => {
  client.close();
  human.close();
  await server.close();
  rmSync(dir, { recursive: true, force: true });
});

/** One raw NDJSON round trip on the human socket: the exact bytes the arbiter sends. */
function rawRequest(req: object): Promise<string> {
  return new Promise((resolve, reject) => {
    const s = connect(humanSock);
    let buf = "";
    s.on("error", reject);
    s.on("data", (d) => {
      buf += d.toString("utf8");
      const nl = buf.indexOf("\n");
      if (nl >= 0) { s.end(); resolve(buf.slice(0, nl)); }
    });
    s.write(JSON.stringify(req) + "\n");
  });
}

test("symbolShape over the production client: the count of a no-model value, never the value", async () => {
  const symbol = await client.symbolize({ tool: "Read", value: SECRET, confidentiality: "no-model" });
  assert.match(symbol, /^\$MDU:nomodel_/, "precondition: a secret-labelled symbol");
  assert.deepEqual(await human.symbolShape(symbol), { lines: 4 });

  const wire = await rawRequest({ id: "w1", op: "symbolShape", token: symbol });
  assert.deepEqual(JSON.parse(wire), { id: "w1", ok: true, result: { lines: 4 } });
  for (const line of SECRET.split("\n").filter(Boolean)) {
    for (let i = 0; i + 6 <= line.length; i++) {
      assert.ok(!wire.includes(line.slice(i, i + 6)), `the wire holds a piece of the value: ${line.slice(i, i + 6)}`);
    }
  }
  assert.ok(!wire.includes("CANARY"));
});

test("symbolShape over the production client: nested chain, field path, unknown → null", async () => {
  const inner = await client.symbolize({ tool: "Bash", value: "a\nb\n" });
  const outer = await client.symbolize({ tool: "Bash", value: `head\n${inner}`, field: "stdout" });
  assert.match(outer, /\.stdout$/);
  assert.deepEqual(await human.symbolShape(outer), { lines: 3 }, "head / a / b — deep, one trailing break dropped");
  assert.equal(await human.symbolShape("$MDU:Bash[0badc0de]"), null);
  assert.equal(await human.symbolShape(`text ${inner}`), null);
});

test("symbolShape on the DATA socket the agent's tools reach is refused (human plane only)", async () => {
  const symbol = await client.symbolize({ tool: "Bash", value: "a\nb\n" } as never);
  await assert.rejects(client.symbolShape(symbol), /human-plane/);
  assert.deepEqual(await human.symbolShape(symbol), { lines: 2 });
});

test("setSessionRelay / sessionRelay over the production client: round trip, isolation, overwrite", async () => {
  const k1 = "rrr-e2e-scope-1";
  const k2 = "rrr-e2e-scope-2";
  assert.equal(await human.sessionRelay(k1), null, "never reported ⇒ null ⇒ no expansion");

  await human.setSessionRelay({ sessionKey: k1, mode: "pty", reserve: true, cols: 80, rows: 24 });
  await human.setSessionRelay({ sessionKey: k2, mode: "pipe", reserve: false });
  const r1 = await human.sessionRelay(k1);
  assert.ok(r1);
  assert.equal(r1.mode, "pty");
  assert.equal(r1.reserve, true);
  assert.equal(r1.cols, 80);
  assert.equal(r1.rows, 24);
  assert.equal(typeof r1.updatedAt, "number");
  const r2 = await human.sessionRelay(k2);
  assert.deepEqual({ ...r2, updatedAt: 0 }, { mode: "pipe", reserve: false, updatedAt: 0 });

  // A resize re-report overwrites.
  await human.setSessionRelay({ sessionKey: k1, mode: "pty", reserve: true, cols: 160, rows: 40 });
  const r1b = await human.sessionRelay(k1);
  assert.equal(r1b?.cols, 160);
  assert.equal(r1b?.rows, 40);
  assert.ok(r1b!.updatedAt >= r1.updatedAt);
});

test("setSessionRelay over the production client: a malformed report rejects and stores nothing", async () => {
  const k = "rrr-e2e-scope-bad";
  await assert.rejects(
    human.setSessionRelay({ sessionKey: k, mode: "tty" as never, reserve: true }),
    /mode must be one of/,
  );
  await assert.rejects(
    human.setSessionRelay({ sessionKey: k, mode: "pty", reserve: true, cols: 0 }),
    /cols must be a positive integer/,
  );
  await assert.rejects(
    human.setSessionRelay({ sessionKey: k, mode: "pty", reserve: true, wrap: "yes" as never }),
    /wrap must be a boolean/,
  );
  assert.equal(await human.sessionRelay(k), null);
});

// ── v2 (§11.5) ───────────────────────────────────────────────────────────────

test("setSessionRelay / sessionRelay on the DATA socket are refused; the agent's world cannot set the wrap width", async () => {
  const k = "rrr-e2e-scope-data";
  await human.setSessionRelay({ sessionKey: k, mode: "pty", reserve: true, cols: 80, rows: 24, wrap: true });
  await assert.rejects(
    client.setSessionRelay({ sessionKey: k, mode: "pty", reserve: true, cols: 21, rows: 24, wrap: true }),
    /human-plane: 'setSessionRelay' /,
  );
  await assert.rejects(client.sessionRelay(k), /human-plane: 'sessionRelay' /);
  const r = await human.sessionRelay(k);
  assert.equal(r?.cols, 80, "the refused data-socket report changed nothing");
  assert.equal(r?.wrap, true);
});

test("setSessionRelay over the production client: wrap round trip; a v1 report carries none", async () => {
  const k = "rrr-e2e-scope-wrap";
  await human.setSessionRelay({ sessionKey: k, mode: "pty", reserve: true, cols: 80, rows: 24, wrap: true });
  const r = await human.sessionRelay(k);
  assert.deepEqual({ ...r, updatedAt: 0 }, { mode: "pty", reserve: true, cols: 80, rows: 24, wrap: true, updatedAt: 0 });
  await human.setSessionRelay({ sessionKey: k, mode: "pty", reserve: true, cols: 80, rows: 24 });
  assert.ok(!("wrap" in (await human.sessionRelay(k))!), "a v1 filter's re-report: no wrap");
});

test("symbolShape with width over the production client: rows (and the last row's width, §14) for a wrapped one-line secret; counts only on the wire", async () => {
  const oneLine = "sk-ant-api03-" + "ROWCANARY".repeat(12) + "\n"; // 121 columns, one line
  const symbol = await client.symbolize({ tool: "Read", value: oneLine, confidentiality: "no-model" });
  assert.deepEqual(await human.symbolShape(symbol), { lines: 1 }, "no width: v1's answer");
  assert.deepEqual(await human.symbolShape(symbol, { width: 78 }), { lines: 1, rows: 2, last: 43 });
  assert.deepEqual(await human.symbolShape(symbol, { width: 78, first: 0 }), { lines: 1, rows: 3, last: 43 });
  assert.deepEqual(await human.symbolShape(symbol, { width: 40, first: 20 }), { lines: 1, rows: 4, last: 21 }, "20 + 40 + 40 + 21");

  const wire = await rawRequest({ id: "w2", op: "symbolShape", token: symbol, width: 78, first: 39 });
  assert.deepEqual(Object.keys(JSON.parse(wire).result).sort(), ["last", "lines", "rows"]);
  for (let i = 0; i + 6 <= oneLine.length - 1; i++) {
    assert.ok(!wire.includes(oneLine.slice(i, i + 6)), `the wire holds a piece of the value: ${oneLine.slice(i, i + 6)}`);
  }

  // A multi-line value with one long line, through a nested chain and a field path.
  const inner = await client.symbolize({ tool: "Bash", value: "Q".repeat(90) });
  const outer = await client.symbolize({ tool: "Bash", value: `head\n${inner}\n`, field: "stdout" });
  assert.deepEqual(await human.symbolShape(outer, { width: 40 }), { lines: 2, rows: 4, last: 10 }, "head / 40 / 40 / 10");

  // Still refused on the data socket.
  await assert.rejects(client.symbolShape(symbol, { width: 78 }), /human-plane: 'symbolShape' /);
});

test("symbolShape over the production client: an out-of-range width/first rejects", async () => {
  const symbol = await client.symbolize({ tool: "Bash", value: "a\nb\n" });
  for (const [opts, re] of [
    [{ width: 19 }, /width must be an integer from 20 to 1000/],
    [{ width: 1001 }, /width must be an integer from 20 to 1000/],
    [{ width: 80.5 }, /width must be an integer from 20 to 1000/],
    [{ width: 80, first: 39 }, /first must be 0 or an integer from 40 to 80/],
    [{ width: 80, first: 81 }, /first must be 0 or an integer from 40 to 80/],
    [{ first: 40 }, /first requires width/],
  ] as Array<[{ width?: number; first?: number }, RegExp]>) {
    await assert.rejects(human.symbolShape(symbol, opts), re, JSON.stringify(opts));
  }
  assert.deepEqual(await human.symbolShape(symbol, { width: 80, first: 40 }), { lines: 2, rows: 2, last: 1 });
});

test("noteReserveBlock / reserveBlock over the production client: round trip on human, refused on data", async () => {
  const k = "rrr-e2e-scope-blocks";
  const symbol = await client.symbolize({ tool: "Read", value: SECRET, confidentiality: "no-model" });
  const hash = /\[([0-9a-f]{4,8})\]/.exec(symbol)![1]!;
  await human.noteReserveBlock({ sessionKey: k, token: symbol, n: 4, width: 78, first: 78 });
  assert.deepEqual(await human.reserveBlock(k, hash), { token: symbol, n: 4, width: 78, first: 78 });
  assert.equal(await human.reserveBlock("rrr-e2e-other", hash), null, "per-session");
  // The wire carries the token and counts, never the value.
  const wire = await rawRequest({ id: "b1", op: "reserveBlock", sessionKey: k, hash });
  for (const line of SECRET.split("\n").filter(Boolean)) {
    for (let i = 0; i + 6 <= line.length; i++) {
      assert.ok(!wire.includes(line.slice(i, i + 6)), `the wire holds a piece of the value: ${line.slice(i, i + 6)}`);
    }
  }
  await assert.rejects(client.noteReserveBlock({ sessionKey: k, token: symbol, n: 9 }), /human-plane: 'noteReserveBlock' /);
  await assert.rejects(client.reserveBlock(k, hash), /human-plane: 'reserveBlock' /);
  assert.equal((await human.reserveBlock(k, hash))?.n, 4, "the refused data-socket note changed nothing");
  await assert.rejects(human.noteReserveBlock({ sessionKey: k, token: `see ${symbol}`, n: 4 }), /exactly one symbol token/);
});
