/**
 * human-plane-ops.test — the op × channel matrix of the arbiter's three IPC
 * channels (docs/design/architecture/arbiter-human-plane.md; Mandu-new, no reference
 * origin).
 *
 * The data socket is reachable from every process the agent's tools start, so
 * the ops that hand back ORIGINALS (desymbolize, SHALLOW resolve, events,
 * subscribe, sessions, verifyEvents) are refused there and served only on the
 * human plane (the human socket) and the admin channel. The channels nest:
 * admin ⊇ human ⊇ data — the human socket still refuses every admin-only op.
 * Deep resolve stays on the data plane (the quarantined U-LLM's read), and its
 * level gate refuses a `no-model` row WHATEVER the confidentiality axis says.
 *
 * Covered here: the pure decision (channelRefusal / isHumanPlaneRequest), the
 * same matrix through server.dispatch(req, { channel }), a real data-socket
 * `subscribe` (error frame, then EOF), deep resolve with the axis OFF, and the
 * runtime-dir helpers (ensurePrivateDir, the dead-instance sweep of a human
 * socket).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { connect } from "node:net";
import {
  chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, statSync, symlinkSync, writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  ADMIN_ONLY_OPS,
  ArbiterServer,
  HUMAN_PLANE_OPS,
  adminOnlyError,
  channelRefusal,
  humanPlaneOnlyError,
  isHumanPlaneRequest,
  type IpcChannel,
} from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import {
  HUMAN_SOCK_ENV,
  createInstanceDir,
  ensurePrivateDir,
  humanSockDir,
  humanSockPath,
  resolveArbiterHumanSock,
  sweepDeadInstances,
  writeManifest,
} from "../../ipc/instance.js";
import type { ArbiterRequest } from "../../ipc/protocol.js";
import { allocateSymbol, loadSymbolMap } from "../../symbol-table/index.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

const SECRET = "AKIA-HUMAN-PLANE-SECRET-0001";
const PLAIN = "an ordinary public note";

/** A server over a DB seeded with a no-model row, a public row, and a public
 *  wrapper quoting the no-model token. Seeded BEFORE construction (the server
 *  loads the map at start), so the rows exist whatever the axis. */
function seededServer(confidentiality: boolean): {
  server: ArbiterServer; dir: string; secret: string; plain: string; wrapper: string;
} {
  const dir = mkdtempSync(join(tmpdir(), "mandu-hp-ops-"));
  const dbPath = join(dir, "symbols.db");
  const map = loadSymbolMap(dbPath);
  const secret = allocateSymbol(map, { tool: "Read", value: SECRET, origin: "/h/.aws/credentials", confidentiality: "no-model" }, dbPath);
  const plain = allocateSymbol(map, { tool: "Read", value: PLAIN, origin: "/h/notes.md" }, dbPath);
  const wrapper = allocateSymbol(map, { tool: "Read", value: `see ${secret} here` }, dbPath);
  const server = new ArbiterServer({
    socketPath: join(dir, "arbiter.sock"),
    humanSocketPath: join(dir, "human", "h.sock"),
    dbPath,
    eventDir: join(dir, "events"),
    log: () => {},
    confidentiality,
    integrity: false,
  });
  return { server, dir, secret, plain, wrapper };
}

type Resp = { ok: boolean; result?: unknown; error?: string };
const call = (s: ArbiterServer, req: Record<string, unknown>, channel: IpcChannel): Resp =>
  s.dispatch({ id: "t", ...req } as ArbiterRequest, { channel }) as Resp;

// ── the pure decision ───────────────────────────────────────────────────────

test("channelRefusal: every human-plane op is refused on data, accepted on human and admin", () => {
  assert.deepEqual([...HUMAN_PLANE_OPS].sort(), [
    "beginLaunch", "cacheSeals", "clearSessionPathLabels", "desymbolize", "endLaunch", "events", "forwardedClear", "forwardedPlaceholders", "humanPlaneStatus", "noteReserveBlock", "placeholderKnown", "promptExceptions", "promptFilterPacks", "promptHolds", "recordForwardedClear", "recordForwardedPlaceholders", "registerAuthGrant", "registerMcpServers", "registerWireRelease", "reserveBlock", "resolve", "sealCacheEntries",
    "sessionRelay", "sessions", "setSessionRelay", "subscribe", "symbolShape", "verifyEvents", "whySymbol",
  ]);
  for (const op of HUMAN_PLANE_OPS) {
    assert.equal(isHumanPlaneRequest({ op }), true, op);
    assert.equal(channelRefusal({ op }, "data"), humanPlaneOnlyError(op), `${op} on data`);
    assert.equal(channelRefusal({ op }, "human"), null, `${op} on human`);
    assert.equal(channelRefusal({ op }, "admin"), null, `${op} on admin`);
  }
  // A DEEP resolve is the quarantined U-LLM's level-gated read: data plane.
  assert.equal(isHumanPlaneRequest({ op: "resolve", deep: true }), false);
  assert.equal(channelRefusal({ op: "resolve", deep: true }, "data"), null);
  // Only a literal `true` makes it deep — anything else is the shallow lookup.
  for (const deep of [false, "true", 1, null, undefined]) {
    assert.equal(channelRefusal({ op: "resolve", deep }, "data"), humanPlaneOnlyError("resolve"), `deep=${String(deep)}`);
  }
});

test("channelRefusal: filterPrompt is a data-plane proxy op, its dry run is human-plane only (plan 15 §8.1)", () => {
  for (const dryRun of [undefined, false]) {
    assert.equal(isHumanPlaneRequest({ op: "filterPrompt", dryRun }), false, `dryRun=${String(dryRun)}`);
    assert.equal(channelRefusal({ op: "filterPrompt", dryRun }, "data"), null);
  }
  // Any other value is a dry run: refused on data rather than run live.
  for (const dryRun of [true, "true", 1, null]) {
    assert.equal(isHumanPlaneRequest({ op: "filterPrompt", dryRun }), true, `dryRun=${String(dryRun)}`);
    assert.equal(channelRefusal({ op: "filterPrompt", dryRun }, "data"), humanPlaneOnlyError("filterPrompt"));
    assert.equal(channelRefusal({ op: "filterPrompt", dryRun }, "human"), null);
    assert.equal(channelRefusal({ op: "filterPrompt", dryRun }, "admin"), null);
  }
  assert.doesNotMatch(humanPlaneOnlyError("filterPrompt"), /returns originals/);
  assert.ok(!HUMAN_PLANE_OPS.has("filterPrompt"), "the live op stays on the data plane");
});

test("humanPlaneOnlyError: says 'returns originals' only for the ops that do", () => {
  for (const op of ["desymbolize", "resolve", "events", "subscribe", "sessions", "verifyEvents"]) {
    assert.match(humanPlaneOnlyError(op), new RegExp(`^human-plane: '${op}' returns originals and is accepted only on the human socket`));
  }
  for (const op of ["symbolShape", "setSessionRelay", "sessionRelay", "noteReserveBlock", "reserveBlock", "cacheSeals", "sealCacheEntries", "beginLaunch", "endLaunch", "humanPlaneStatus", "registerMcpServers", "registerWireRelease", "registerAuthGrant", "recordForwardedClear", "forwardedClear", "recordForwardedPlaceholders", "forwardedPlaceholders"]) {
    const e = humanPlaneOnlyError(op);
    assert.match(e, new RegExp(`^human-plane: '${op}' .* is accepted only on the human socket`));
    assert.doesNotMatch(e, /returns originals/, op);
  }
});

test("channelRefusal: admin-only ops are refused on data AND human; admin accepts them", () => {
  for (const op of ADMIN_ONLY_OPS) {
    assert.equal(channelRefusal({ op }, "data"), adminOnlyError(op), `${op} on data`);
    assert.equal(channelRefusal({ op }, "human"), adminOnlyError(op), `${op} on human (human ⊉ admin)`);
    assert.equal(channelRefusal({ op }, "admin"), null, `${op} on admin`);
  }
  // No op is in both sets (the nesting is strict).
  for (const op of HUMAN_PLANE_OPS) assert.ok(!ADMIN_ONLY_OPS.has(op), op);
});

test("channelRefusal: data-plane ops are accepted on every channel", () => {
  for (const op of ["symbolize", "classify", "emit", "hello", "ping", "desymbolizationDecision", "declassifySymbol", "registerSecret"]) {
    for (const ch of ["data", "human", "admin"] as const) {
      assert.equal(channelRefusal({ op }, ch), null, `${op} on ${ch}`);
    }
  }
});

// ── the matrix through dispatch ─────────────────────────────────────────────

test("dispatch on data: the original-returning ops are refused with the human-plane error", async () => {
  const r = seededServer(true);
  try {
    call(r.server, { op: "emit", event: { sessionId: "s-hp", id: "e1" } }, "data");
    const refusals: Array<Record<string, unknown>> = [
      { op: "desymbolize", text: `x ${r.secret}` },
      { op: "resolve", symbol: r.secret },
      { op: "resolve", symbol: r.plain, deep: false },
      { op: "events", sessionId: "s-hp" },
      { op: "sessions" },
      { op: "verifyEvents", sessionId: "s-hp" },
      { op: "subscribe", sessionId: "s-hp" },
      { op: "symbolShape", token: r.secret, width: 80 },
      { op: "setSessionRelay", sessionKey: "s-hp", mode: "pty", reserve: true, cols: 80, rows: 24, wrap: true },
      { op: "sessionRelay", sessionKey: "s-hp" },
    ];
    for (const req of refusals) {
      const resp = call(r.server, req, "data");
      assert.equal(resp.ok, false, JSON.stringify(req));
      assert.equal(resp.error, humanPlaneOnlyError(req.op as string));
      assert.ok(!JSON.stringify(resp).includes(SECRET), "no original in the refusal");
    }
  } finally {
    await r.server.close();
    rmSync(r.dir, { recursive: true, force: true });
  }
});

test("dispatch on data: deep resolve, symbolize, classify, emit and hello are served", async () => {
  const r = seededServer(true);
  try {
    const deep = call(r.server, { op: "resolve", symbol: r.plain, deep: true }, "data");
    assert.equal(deep.ok, true);
    assert.equal((deep.result as { value: string }).value, PLAIN);
    const refusedDeep = call(r.server, { op: "resolve", symbol: r.secret, deep: true }, "data");
    assert.equal((refusedDeep.result as { value: null }).value, null, "no-model refused by the level gate");
    assert.equal(call(r.server, { op: "symbolize", tool: "Read", value: "fresh text" }, "data").ok, true);
    assert.equal(call(r.server, { op: "classify", request: { tool: "Read", value: "x", boundary: "model_context" } }, "data").ok, true);
    assert.equal(call(r.server, { op: "emit", event: { sessionId: "s-data", id: "e1" } }, "data").ok, true);
    const hello = call(r.server, { op: "hello" }, "data");
    assert.equal(hello.ok, true);
  } finally {
    await r.server.close();
    rmSync(r.dir, { recursive: true, force: true });
  }
});

test("dispatch on human: originals come back; every admin-only op is refused", async () => {
  const r = seededServer(true);
  try {
    call(r.server, { op: "emit", event: { sessionId: "s-h", id: "e1" } }, "human");
    const d = call(r.server, { op: "desymbolize", text: `x ${r.secret}` }, "human");
    assert.equal((d.result as { text: string }).text, `x ${SECRET}`, "the HumanView rewrite is label-unrestricted");
    const sh = call(r.server, { op: "resolve", symbol: r.secret }, "human");
    assert.equal((sh.result as { value: string }).value, SECRET);
    assert.equal(call(r.server, { op: "events", sessionId: "s-h" }, "human").ok, true);
    assert.equal(call(r.server, { op: "sessions" }, "human").ok, true);
    assert.equal(call(r.server, { op: "verifyEvents", sessionId: "s-h" }, "human").ok, true);
    // subscribe passes the channel gate; dispatch then steers it to a dedicated connection.
    assert.match(call(r.server, { op: "subscribe", sessionId: "s-h" }, "human").error ?? "", /dedicated connection/);
    // Reply row reservation (reply-row-reservation.md §11.5): the shape and
    // the relay state the proxy and the reply filter exchange.
    assert.deepEqual(call(r.server, { op: "symbolShape", token: r.secret, width: 20 }, "human").result, { lines: 1, rows: 2, last: 8 }, "28 columns at 20: 20 + 8");
    const relay = { op: "setSessionRelay", sessionKey: "s-h", mode: "pty", reserve: true, cols: 80, rows: 24, wrap: true };
    assert.equal(call(r.server, relay, "human").ok, true);
    assert.equal((call(r.server, { op: "sessionRelay", sessionKey: "s-h" }, "human").result as { wrap: boolean }).wrap, true);
    // Data-plane ops still work on the human socket (human ⊇ data).
    assert.equal(call(r.server, { op: "symbolize", tool: "Read", value: "y" }, "human").ok, true);
    // …but no admin-only op (human ⊉ admin).
    for (const op of ADMIN_ONLY_OPS) {
      const resp = call(r.server, { op, path: "/h/x", confidentiality: "public" }, "human");
      assert.equal(resp.ok, false, op);
      assert.equal(resp.error, adminOnlyError(op));
    }
  } finally {
    await r.server.close();
    rmSync(r.dir, { recursive: true, force: true });
  }
});

test("dispatch on admin: human-plane and admin-only ops pass the channel gate", async () => {
  const r = seededServer(true);
  try {
    const d = call(r.server, { op: "desymbolize", text: r.secret }, "admin");
    assert.equal((d.result as { text: string }).text, SECRET);
    const relay = { op: "setSessionRelay", sessionKey: "s-a", mode: "pty", reserve: true, cols: 80, wrap: true };
    assert.equal(call(r.server, relay, "admin").ok, true);
    assert.equal((call(r.server, { op: "sessionRelay", sessionKey: "s-a" }, "admin").result as { cols: number }).cols, 80);
    // Admin-only ops reach their handler (whatever it answers, it is not the channel refusal).
    // (Some handlers THROW on these empty requests — the socket layer turns
    // that into an error reply; either way it is not the channel refusal.)
    for (const op of ADMIN_ONLY_OPS) {
      let error: string | undefined;
      try { error = call(r.server, { op }, "admin").error; } catch (e) { error = (e as Error).message; }
      assert.notEqual(error, adminOnlyError(op), op);
    }
    // The default channel of a direct dispatch is admin (in-process = trusted).
    const direct = r.server.dispatch({ id: 1, op: "resolve", symbol: r.secret } as ArbiterRequest) as Resp;
    assert.equal((direct.result as { value: string }).value, SECRET);
  } finally {
    await r.server.close();
    rmSync(r.dir, { recursive: true, force: true });
  }
});

// ── deep resolve regardless of the axis ─────────────────────────────────────

test("deep resolve on data with the confidentiality axis OFF still refuses a no-model row; nested stays a token", async () => {
  const r = seededServer(false);
  try {
    const top = call(r.server, { op: "resolve", symbol: r.secret, deep: true }, "data");
    assert.equal(top.ok, true);
    assert.deepEqual(top.result, { value: null }, "refused, in the axis-off wire shape");
    const nested = call(r.server, { op: "resolve", symbol: r.wrapper, deep: true }, "data");
    assert.deepEqual(nested.result, { value: `see ${r.secret} here` }, "the nested no-model token stays opaque");
    const plain = call(r.server, { op: "resolve", symbol: r.plain, deep: true }, "data");
    assert.deepEqual(plain.result, { value: PLAIN }, "an unlabelled row resolves exactly as before");
    // An endpoint name the caller supplies opens nothing: no-model admits no model.
    const named = call(r.server, { op: "resolve", symbol: r.secret, deep: true, endpoint: "ollama" }, "data");
    assert.deepEqual(named.result, { value: null });
  } finally {
    await r.server.close();
    rmSync(r.dir, { recursive: true, force: true });
  }
});

// ── over real sockets ───────────────────────────────────────────────────────

test("a subscribe over the real DATA socket gets one refusal frame, then EOF; over human it streams", async () => {
  const r = seededServer(true);
  await r.server.listen();
  const dataSock = join(r.dir, "arbiter.sock");
  const humanSock = join(r.dir, "human", "h.sock");
  const human = new ArbiterClient(humanSock);
  try {
    await human.emit({ sessionId: "s-sub", id: "e1", original: SECRET } as never);

    // Raw wire: the refusal frame, then the arbiter ends the connection.
    const raw = await new Promise<{ text: string; ended: boolean }>((resolve, reject) => {
      const s = connect(dataSock);
      let text = "";
      s.setEncoding("utf8");
      s.on("data", (c: string) => { text += c; });
      s.on("end", () => resolve({ text, ended: true }));
      s.on("error", reject);
      s.on("connect", () => s.write(JSON.stringify({ id: "sub", op: "subscribe", sessionId: "s-sub", sinceSeq: 0 }) + "\n"));
      setTimeout(() => resolve({ text, ended: false }), 3000).unref();
    });
    assert.equal(raw.ended, true, "the connection is ended after the refusal");
    const frames = raw.text.trim().split("\n").map((l) => JSON.parse(l) as Resp & { id: string });
    assert.equal(frames.length, 1, "exactly one frame");
    assert.equal(frames[0]!.ok, false);
    assert.equal(frames[0]!.error, humanPlaneOnlyError("subscribe"));
    assert.ok(!raw.text.includes(SECRET), "no event (and no original) crosses the data socket");

    // The typed client sees it too: a rejection, or onError after the resolve.
    const data = new ArbiterClient(dataSock);
    const seen: unknown[] = [];
    const refused = await new Promise<string>((resolve) => {
      data.subscribe("s-sub", 0, (e) => seen.push(e), (err) => resolve(err.message))
        .catch((err: Error) => resolve(err.message));
    });
    assert.match(refused, /human-plane/);
    assert.deepEqual(seen, [], "no event delivered over data");
    data.close();

    // The human plane streams the backlog.
    const got: string[] = [];
    const handle = await human.subscribe("s-sub", 0, (e) => got.push(String(e.id)));
    const t0 = Date.now();
    while (got.length < 1 && Date.now() - t0 < 3000) await new Promise((res) => setTimeout(res, 20));
    handle.close();
    assert.deepEqual(got, ["e1"]);
  } finally {
    human.close();
    await r.server.close();
    rmSync(r.dir, { recursive: true, force: true });
  }
});

// ── the runtime-dir helpers ─────────────────────────────────────────────────

test("ensurePrivateDir: creates 0700; accepts ours at 0700; refuses wider modes and a symlink (fail closed)", () => {
  const root = mkdtempSync(join(tmpdir(), "mandu-hp-dir-"));
  try {
    const fresh = join(root, "a", "human");
    ensurePrivateDir(fresh);
    assert.equal(statSync(fresh).mode & 0o777, 0o700);
    ensurePrivateDir(fresh); // idempotent on a good dir

    const wide = join(root, "wide");
    mkdirSync(wide);
    chmodSync(wide, 0o755);
    assert.throws(() => ensurePrivateDir(wide), /mode 755, not 700/);
    assert.equal(statSync(wide).mode & 0o777, 0o755, "never silently tightened");

    const groupOnly = join(root, "g");
    mkdirSync(groupOnly);
    chmodSync(groupOnly, 0o710);
    assert.throws(() => ensurePrivateDir(groupOnly), /not 700/);

    const target = join(root, "target");
    mkdirSync(target, { mode: 0o700 });
    const link = join(root, "link");
    symlinkSync(target, link);
    assert.throws(() => ensurePrivateDir(link), /not a real directory/);

    const file = join(root, "file");
    writeFileSync(file, "");
    assert.throws(() => ensurePrivateDir(file), /not a real directory/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("humanSockPath lives under <base>/human, outside every instance dir; the sweep removes a dead instance's socket", () => {
  const base = mkdtempSync(join(tmpdir(), "mandu-hp-sweep-"));
  try {
    assert.equal(humanSockDir(base), join(base, "human"));
    const id = "20260930-0000-deadbee-p2147483646";
    assert.equal(humanSockPath(base, id), join(base, "human", `${id}.sock`));
    const paths = createInstanceDir(base, id);
    assert.ok(!humanSockPath(base, id).startsWith(paths.dir + "/"), "never inside the instance dir");
    writeManifest(paths, {
      instanceId: id, role: "arbiter", pid: 2147483646, startedAt: new Date().toISOString(),
      gitRev: "deadbee", gitDirty: false, sockPath: paths.sockPath, humanSockPath: humanSockPath(base, id),
      eventDir: join(base, "ev"), symbolDb: join(base, "db"),
    });
    ensurePrivateDir(humanSockDir(base));
    writeFileSync(humanSockPath(base, id), ""); // a stale socket file left by a crash
    const keep = humanSockPath(base, "someone-else");
    writeFileSync(keep, "");
    assert.deepEqual(sweepDeadInstances(base), [id]);
    assert.ok(!existsSync(humanSockPath(base, id)), "the dead instance's human socket is gone");
    assert.ok(existsSync(keep), "another instance's socket is untouched");
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("resolveArbiterHumanSock: the env var verbatim, else the promoted instance's socket, else null — never the data socket", () => {
  const base = mkdtempSync(join(tmpdir(), "mandu-hp-resolve-"));
  try {
    const env = { MANDU_RUNTIME_DIR: base, HOME: base } as NodeJS.ProcessEnv;
    assert.equal(resolveArbiterHumanSock({ ...env, [HUMAN_SOCK_ENV]: "/x/human.sock" }), "/x/human.sock");
    assert.equal(resolveArbiterHumanSock(env), null, "nothing promoted → null");
    // A data socket at the legacy fixed path and under `current` never answers for the human plane.
    writeFileSync(join(base, "arbiter.sock"), "");
    assert.equal(resolveArbiterHumanSock({ ...env, MANDU_ARBITER_SOCK: join(base, "arbiter.sock") }), null);
    const id = "20260930-0001-abc1234-p1";
    const paths = createInstanceDir(base, id);
    writeFileSync(paths.sockPath, "");
    symlinkSync(join("instances", id), join(base, "current"));
    assert.equal(resolveArbiterHumanSock(env), null, "promoted, but no human socket → null");
    ensurePrivateDir(humanSockDir(base));
    writeFileSync(humanSockPath(base, id), "");
    assert.equal(resolveArbiterHumanSock(env), humanSockPath(base, id));
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});
