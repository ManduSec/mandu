/**
 * attachment-session — the attachment form of `beginLaunch`
 * (docs/design/agents/openclaw-plugin.md §3.3; policy/cache-seals.ts
 * ATTACHMENTS; ipc/server.ts `beginAttachment`).
 *
 * Mandu attached to an agent it does not run (the OpenClaw plugin, beside a
 * resident service) registers a session with no pid. Its agent's programs
 * reach Mandu's home and the human socket, so an attachment is unconfined
 * and unwalled by construction:
 *
 *   - the store: a lease (renewed, lapsed, ended), one per session, a row
 *     deleted by hand does not end it, a restart keeps it at most one lease,
 *     every end rotates the epoch, seals are void while it is live, the human
 *     plane is exposed while it is live;
 *   - the op: human plane only (refused on the data socket), the session id
 *     shape (`openclaw:<name>`), the kind, the coverage (it must resolve to
 *     `gated` with the kind's own gap: confinement-posture.ts
 *     `resolvePosture`), never guarded;
 *   - the posture record: the arbiter writes the session's `launch_posture`
 *     itself, believed only when the registration was attested; no emit of
 *     a `launch_posture` for an attached session is taken from a channel that
 *     is not believed;
 *   - the route check (openclaw-plugin.md §3.6): `updateAttachment` records
 *     the coverage the service found (model context or the plugin lost, or
 *     back) as a new posture record, decided by the same rule (the kind's
 *     coverage or less); believed on the admin channel, a claim on the
 *     exposed human socket, refused on the data socket and for a token that
 *     is not live; a registration may carry a lost route too;
 *   - the periods `mandu scan` marks by (plan 17 §3 item 6): kept after the
 *     row ends (ended, replaced, lapsed at the last renewal, live now),
 *     across a restart, read read-only from another arbiter's store, and
 *     written by the human-plane ops only.
 *
 * Axes: secrets (the attachment serves the confidentiality axis).
 * Mandu-new (no reference origin).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "../../db/sqlite.js";
import { ATTACHMENT_LEASE_MS, ATTACHMENT_WHY, CacheSealStore, attachmentPeriodsIn, type CacheSealStoreOptions } from "../../policy/cache-seals.js";
import { ATTACHMENT_COVERAGE, attachmentSessionId } from "../../policy/confinement-posture.js";
import { ArbiterServer, humanPlaneOnlyError, type IpcChannel } from "../../ipc/server.js";
import type { ArbiterRequest } from "../../ipc/protocol.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets");

const COVERAGE = ATTACHMENT_COVERAGE["openclaw-plugin"];
const SID = "openclaw:main";

// ── the store ───────────────────────────────────────────────────────────────

function storeRig() {
  const dir = mkdtempSync(join(tmpdir(), "mdu-attach-"));
  const now = { t: 5_000_000 };
  let n = 0;
  let k = 0;
  const rotations: string[] = [];
  const open = (o: Partial<CacheSealStoreOptions> = {}) => new CacheSealStore({
    dbPath: join(dir, "mandu.db"), confidentiality: true, now: () => now.t, newEpoch: () => `epoch-${++n}`,
    newToken: () => `tok-${++k}`, pidExists: () => false, procStartTime: () => null,
    onRotate: (e) => rotations.push(e.reason), ...o,
  });
  return { dir, now, rotations, open, done: () => rmSync(dir, { recursive: true, force: true }) };
}

test("store: an attachment is an unwalled unconfined period on a lease; renewed it stays, lapsed it ends with a rotation", () => {
  const r = storeRig();
  try {
    const s = r.open();
    s.epoch();
    const a = s.beginAttachment({ sessionId: SID, kind: "openclaw-plugin" });
    assert.equal(a.leaseMs, ATTACHMENT_LEASE_MS);
    assert.equal(a.expiresAt, r.now.t + ATTACHMENT_LEASE_MS);
    assert.deepEqual(a.others, [], "nothing was live before it");
    const st = s.status();
    assert.equal(st.honoured, false, "no seal is honoured while an attachment is live");
    assert.deepEqual(st.live, [{ pid: 0, mode: "secrets", posture: "gated", walled: false, session: SID, begunAt: r.now.t, why: ATTACHMENT_WHY, attachment: "openclaw-plugin" }]);
    assert.deepEqual(s.humanPlaneExposure(), [{ pid: 0, mode: "secrets", posture: "gated", walled: false, session: SID, begunAt: r.now.t, attachment: "openclaw-plugin" }]);
    assert.deepEqual([...s.attachedSessions()], [SID]);

    // renewed inside the lease: one more lease from now
    r.now.t += ATTACHMENT_LEASE_MS - 1;
    const renewed = s.renewAttachment(a.token);
    assert.deepEqual(renewed, { renewed: true, expiresAt: r.now.t + ATTACHMENT_LEASE_MS });
    r.now.t += ATTACHMENT_LEASE_MS - 1;
    assert.equal(s.status().honoured, false, "still live: the renewal moved the deadline");
    const before = r.rotations.length;

    // no renewal: the lease runs out, the period ends, the epoch rotates
    r.now.t += 2;
    assert.equal(s.status().honoured, true);
    assert.deepEqual(r.rotations.slice(before), ["1 attachment ended (lease ran out)"]);
    assert.deepEqual(s.humanPlaneExposure(), []);
    assert.deepEqual(s.renewAttachment(a.token), { renewed: false, expiresAt: null }, "a lapsed token renews nothing: register again");
    s.markShutdown();
  } finally {
    r.done();
  }
});

test("store: endAttachment rotates; an unknown token changes nothing; the shapes are checked", () => {
  const r = storeRig();
  try {
    const s = r.open();
    for (const sessionId of ["", "has space", "x".repeat(200), 7, null, "-leading-dash"]) {
      assert.throws(() => s.beginAttachment({ sessionId, kind: "openclaw-plugin" }), /sessionId must be a session id/, String(sessionId));
    }
    for (const kind of ["", "Has-Caps", 3, undefined]) {
      assert.throws(() => s.beginAttachment({ sessionId: SID, kind }), /kind must be an attachment kind/, String(kind));
    }
    assert.throws(() => s.endAttachment(""), /token must be a non-empty string/);
    assert.throws(() => s.renewAttachment(""), /token must be a non-empty string/);
    const a = s.beginAttachment({ sessionId: SID, kind: "openclaw-plugin" });
    const before = r.rotations.length;
    const e = s.endAttachment(a.token);
    assert.equal(e.ended, true);
    assert.equal(e.rotated, true);
    assert.deepEqual(r.rotations.slice(before), ["an attachment ended"]);
    assert.equal(s.status().honoured, true);
    assert.equal(s.endAttachment(a.token).ended, false, "ended once");
    assert.equal(s.endAttachment("never-issued").rotated, false);
    s.markShutdown();
  } finally {
    r.done();
  }
});

test("store: one attachment per session (a second registration replaces the first, no rotation); a row deleted by hand does not end it", () => {
  const r = storeRig();
  try {
    const s = r.open();
    s.epoch();
    const first = s.beginAttachment({ sessionId: SID, kind: "openclaw-plugin" });
    const other = s.beginAttachment({ sessionId: "openclaw:ops", kind: "openclaw-plugin" });
    assert.deepEqual(other.others.map((o) => o.session), [SID], "the live attachment is named to the next");
    const rotations = r.rotations.length;
    const second = s.beginAttachment({ sessionId: SID, kind: "openclaw-plugin" });
    assert.equal(r.rotations.length, rotations, "a replacement goes on with the period");
    assert.equal(s.renewAttachment(first.token).renewed, false, "the replaced token stops working");
    assert.equal(s.renewAttachment(second.token).renewed, true);
    assert.deepEqual(s.humanPlaneExposure().map((l) => l.session).sort(), ["openclaw:main", "openclaw:ops"]);

    // a program of the Gateway (nothing hides mandu.db from it) deletes the rows
    const db = new Database(join(r.dir, "mandu.db"));
    db.prepare("DELETE FROM attachments").run();
    db.close();
    assert.equal(s.humanPlaneExposure().length, 2, "the in-memory copy keeps both live");
    assert.equal(s.status().honoured, false);
    s.markShutdown();
  } finally {
    r.done();
  }
});

test("store: a restart keeps a live attachment at most one lease (a row's own deadline is never believed further), and its shutdown was not clean", () => {
  const r = storeRig();
  try {
    const s = r.open();
    s.epoch();
    s.beginAttachment({ sessionId: SID, kind: "openclaw-plugin" });
    s.markShutdown();
    // a hand-written row claiming a deadline a year out
    const db = new Database(join(r.dir, "mandu.db"));
    db.prepare("INSERT INTO attachments (token, session, kind, begun_at, expires_at) VALUES (?, ?, ?, ?, ?)")
      .run("forged", "openclaw:forged", "openclaw-plugin", r.now.t, r.now.t + 365 * 24 * 3600_000);
    db.close();

    r.now.t += 1_000;
    const before = r.rotations.length;
    const t = r.open();
    t.epoch();
    assert.match(r.rotations[before] ?? "", /last shutdown was not clean/, "an attachment live at shutdown makes it unclean");
    assert.deepEqual(t.humanPlaneExposure().map((l) => l.session).sort(), ["openclaw:forged", "openclaw:main"], "both rows count after the restart");
    r.now.t += ATTACHMENT_LEASE_MS; // past the first one's own deadline and one lease from the restart
    assert.equal(t.status().honoured, true, "neither outlives one lease from the restart");
    assert.deepEqual(t.humanPlaneExposure(), []);
    t.markShutdown();
  } finally {
    r.done();
  }
});

test("store: each attachment's period is kept for the scan: ended at endAttachment or a replacement, at the last renewal for a lapsed lease, now while live; kept across a restart", () => {
  const r = storeRig();
  try {
    const s = r.open();
    s.epoch();
    const t0 = r.now.t;
    const ended = s.beginAttachment({ sessionId: SID, kind: "openclaw-plugin" });
    r.now.t += 20_000;
    s.renewAttachment(ended.token);
    r.now.t += 5_000;
    s.endAttachment(ended.token);
    const tEnd = r.now.t;

    r.now.t += 100_000;
    const t1 = r.now.t;
    const lapsing = s.beginAttachment({ sessionId: SID, kind: "openclaw-plugin" });
    r.now.t += 20_000;
    const lastRenew = r.now.t;
    s.renewAttachment(lapsing.token);
    r.now.t += ATTACHMENT_LEASE_MS + 1; // no renewal: it lapses
    assert.equal(s.renewAttachment(lapsing.token).renewed, false);

    const t2 = r.now.t;
    const replaced = s.beginAttachment({ sessionId: "openclaw:ops", kind: "openclaw-plugin" });
    r.now.t += 10_000;
    const t3 = r.now.t;
    s.beginAttachment({ sessionId: "openclaw:ops", kind: "openclaw-plugin" });
    assert.equal(s.renewAttachment(replaced.token).renewed, false);
    r.now.t += 1_000;

    const want = [
      { session: SID, kind: "openclaw-plugin", from: t0, to: tEnd, live: false, lapsed: false },
      { session: SID, kind: "openclaw-plugin", from: t1, to: lastRenew, live: false, lapsed: true },
      { session: "openclaw:ops", kind: "openclaw-plugin", from: t2, to: t3, live: false, lapsed: false },
      { session: "openclaw:ops", kind: "openclaw-plugin", from: t3, to: r.now.t, live: true, lapsed: false },
    ];
    assert.deepEqual(s.attachmentPeriods(), want);
    s.markShutdown();

    // A restart keeps the history; the live one, never renewed again, lapses
    // and then ends at its last renewal (here, its start).
    const t = r.open();
    t.epoch();
    assert.deepEqual(t.attachmentPeriods().slice(0, 3), want.slice(0, 3));
    r.now.t += ATTACHMENT_LEASE_MS + 1;
    assert.deepEqual(t.attachmentPeriods()[3], { ...want[3], to: t3, live: false, lapsed: true });
    t.markShutdown();
  } finally {
    r.done();
  }
});

test("store: a period an arbiter left open (it stopped with no row to adopt) ends at its last renewal; a hand-written period row of a bad shape is not read", () => {
  const r = storeRig();
  try {
    const s = r.open();
    s.epoch();
    const t0 = r.now.t;
    const a = s.beginAttachment({ sessionId: SID, kind: "openclaw-plugin" });
    r.now.t += 15_000;
    s.renewAttachment(a.token);
    s.markShutdown();
    const db = new Database(join(r.dir, "mandu.db"));
    db.prepare("DELETE FROM attachments").run(); // the live row gone, its period still open
    db.prepare("INSERT INTO attachment_periods (token, session, kind, begun_at, renewed_at) VALUES (?, ?, ?, ?, ?)").run("bad", "has space", "openclaw-plugin", t0, t0);
    db.close();
    r.now.t += 1_000;
    const t = r.open();
    assert.deepEqual(t.attachmentPeriods(), [{ session: SID, kind: "openclaw-plugin", from: t0, to: t0 + 15_000, live: false, lapsed: true }]);
    t.markShutdown();
  } finally {
    r.done();
  }
});

test("attachmentPeriodsIn: another arbiter's store, read-only (the scan's throwaway arbiter reading the resident one's): live by its row's deadline, else ended or lapsed; no store or an older one has none", () => {
  const r = storeRig();
  try {
    const s = r.open();
    s.epoch();
    const t0 = r.now.t;
    const a = s.beginAttachment({ sessionId: SID, kind: "openclaw-plugin" });
    r.now.t += 10_000;
    s.endAttachment(a.token);
    const tEnd = r.now.t;
    r.now.t += 1_000;
    const t1 = r.now.t;
    s.beginAttachment({ sessionId: SID, kind: "openclaw-plugin" });
    const db = join(r.dir, "mandu.db");
    // The resident arbiter still runs: its live row's deadline is ahead.
    assert.deepEqual(attachmentPeriodsIn(db, r.now.t + 5_000), [
      { session: SID, kind: "openclaw-plugin", from: t0, to: tEnd, live: false, lapsed: false },
      { session: SID, kind: "openclaw-plugin", from: t1, to: r.now.t + 5_000, live: true, lapsed: false },
    ]);
    // Past that deadline with no renewal: it ends at its last renewal.
    assert.deepEqual(attachmentPeriodsIn(db, r.now.t + ATTACHMENT_LEASE_MS + 1)[1], { session: SID, kind: "openclaw-plugin", from: t1, to: t1, live: false, lapsed: true });
    s.markShutdown();
    assert.deepEqual(attachmentPeriodsIn(join(r.dir, "missing.db")), []);
    const old = new Database(join(r.dir, "old.db"));
    old.exec("CREATE TABLE attachments (token TEXT PRIMARY KEY)");
    old.close();
    assert.deepEqual(attachmentPeriodsIn(join(r.dir, "old.db")), [], "a store from before the periods were kept");
  } finally {
    r.done();
  }
});

// ── the op, over the server's channels ──────────────────────────────────────

type Resp = { ok: boolean; error?: string; result?: Record<string, unknown> };

function serverRig(o: { attachmentLeaseMs?: number } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "mdu-attach-srv-"));
  const server = new ArbiterServer({
    socketPath: join(dir, "a.sock"), humanSocketPath: join(dir, "human", "h.sock"), dbPath: join(dir, "mandu.db"),
    eventDir: join(dir, "events"), log: () => {}, confidentiality: true, integrity: false, ...o,
  });
  const call = (req: Record<string, unknown>, channel: IpcChannel): Resp =>
    server.dispatch({ id: "t", ...req } as ArbiterRequest, { channel }) as Resp;
  const events = (sessionId: string) => (call({ op: "events", sessionId }, "admin").result!["events"] as Array<Record<string, unknown>>);
  const begin = (channel: IpcChannel, extra: Record<string, unknown> = {}) =>
    call({ op: "beginAttachment", sessionId: SID, kind: "openclaw-plugin", coverage: COVERAGE, ...extra }, channel);
  const emit = (channel: IpcChannel, sessionId: string, kind: string) => call({
    op: "emit",
    event: {
      id: `ev_${Math.random().toString(36).slice(2)}`, sessionId, turn: 0, ts: new Date().toISOString(), callId: null, kind,
      view: "HumanView", boundary: "shell", emitter: "launcher", invariant: { violatedInvariant: false },
      secrets: { posture: "confined" }, input: null, output: null,
    },
  }, channel);
  return {
    server, call, events, begin, emit,
    done: async () => { await server.close().catch(() => {}); rmSync(dir, { recursive: true, force: true }); },
  };
}

test("beginAttachment: refused on the data socket; on the human socket it records a gated posture the arbiter writes itself", async () => {
  const r = serverRig();
  try {
    const data = r.begin("data");
    assert.equal(data.ok, false);
    assert.equal(data.error, humanPlaneOnlyError("beginAttachment"));
    for (const op of ["renewAttachment", "endAttachment"]) {
      assert.equal(r.call({ op, token: "x" }, "data").error, humanPlaneOnlyError(op), op);
    }
    assert.deepEqual(r.events(SID), [], "nothing recorded from the data socket");

    const ok = r.begin("human");
    assert.equal(ok.ok, true, ok.error);
    assert.equal(ok.result!["posture"], "gated");
    assert.equal(ok.result!["gap"], "openclaw-plugin");
    assert.equal(ok.result!["believed"], true, "the human plane was walled before it");
    assert.equal(typeof ok.result!["token"], "string");
    const ev = r.events(SID);
    assert.equal(ev.length, 1);
    const p = ev[0]!;
    assert.equal(p["kind"], "launch_posture");
    assert.equal(p["emitter"], "arbiter");
    assert.equal(p["claimed"], undefined, "believed");
    assert.equal(p["target"], "openclaw");
    assert.deepEqual(p["secrets"], { posture: "gated", gap: "openclaw-plugin" });
    assert.equal(p["humanPlaneWalled"], false);
    assert.deepEqual(p["protection"], { mode: "secrets", integrity: false, confidentiality: true, reported: true });
    assert.deepEqual((p["attachment"] as Record<string, unknown>)["coverage"], COVERAGE);
    assert.match(String((p["dropped"] as string[])[0]), /^mandu: secrets are GATED, not confined, in this OpenClaw Gateway\./);
    // never guarded: the guard-only tools stay masked for this session
    assert.equal((r.server as unknown as { sessionGuarded(s: string): boolean }).sessionGuarded(SID), false);
  } finally {
    await r.done();
  }
});

test("the scan's attachment periods come from the human-plane ops only: a refused data-socket registration or an emitted launch_posture records none", async () => {
  const r = serverRig();
  try {
    const periods = () => (r.server as unknown as { cacheSeals: CacheSealStore }).cacheSeals.attachmentPeriods();
    assert.equal(r.begin("data").ok, false);
    assert.equal(r.emit("data", "openclaw:other", "launch_posture").ok, true, "a claim, stored");
    assert.deepEqual(periods(), [], "no period from the data socket");
    const ok = r.begin("human");
    assert.equal(ok.ok, true, ok.error);
    assert.equal(r.call({ op: "renewAttachment", token: "forged" }, "human").result!["renewed"], false);
    assert.deepEqual(periods().map((p) => [p.session, p.live]), [[SID, true]]);
    assert.equal(r.call({ op: "endAttachment", token: ok.result!["token"] }, "human").ok, true);
    assert.deepEqual(periods().map((p) => [p.session, p.live, p.lapsed]), [[SID, false, false]]);
  } finally {
    await r.done();
  }
});

test("beginAttachment: the session id, the kind and the coverage are checked; a coverage that claims more than gated is refused", async () => {
  const r = serverRig();
  try {
    const bad = (extra: Record<string, unknown>, re: RegExp) => {
      const res = r.begin("human", extra);
      assert.equal(res.ok, false, JSON.stringify(extra));
      assert.match(res.error ?? "", re, JSON.stringify(extra));
    };
    bad({ sessionId: "1791164083-1418381" }, /session id is 'openclaw:<name>'/); // a launch's scope id
    bad({ sessionId: "openclaw:" }, /session id is 'openclaw:<name>'/);
    bad({ sessionId: 42 }, /session id is 'openclaw:<name>'/);
    bad({ sessionId: "openclaw:has space" }, /sessionId must be a session id/);
    bad({ sessionId: `openclaw:${"a".repeat(200)}` }, /sessionId must be a session id/);
    bad({ kind: "claude" }, /kind must be an attachment kind/);
    bad({ kind: undefined }, /kind must be an attachment kind/);
    bad({ coverage: undefined }, /coverage must be a coverage/);
    bad({ coverage: { ...COVERAGE, extra: 1 } }, /coverage must be a coverage/);
    bad({ coverage: { ...COVERAGE, egress: "maybe" } }, /coverage must be a coverage/);
    // a covered files row beside a readable own state is no coverage at all
    bad({ coverage: { ...COVERAGE, files: { by: "guard" } } }, /coverage must be a coverage/);
    // a coverage that WOULD confine: an attachment never is
    bad({ coverage: { ...COVERAGE, files: { by: "guard" }, ownState: "walled" } }, /resolves to confined/);
    bad({ coverage: { ...COVERAGE, files: { by: "read-deny" }, ownState: "walled" } }, /resolves to read-blocked/);
    // gated, but with a host's gap instead of its own
    bad({ coverage: { ...COVERAGE, files: { by: "none", why: "apparmor-userns" } } }, /resolves to gated\/apparmor-userns/);
    assert.deepEqual(r.events(SID), []);
    // the session id the service builds from an OpenClaw agent id
    assert.equal(attachmentSessionId("openclaw-plugin", "my agent/1"), "openclaw:my-agent-1");
    const built = r.begin("human", { sessionId: attachmentSessionId("openclaw-plugin", "my agent/1") });
    assert.equal(built.ok, true, built.error);
  } finally {
    await r.done();
  }
});

test("updateAttachment (§3.6): the route check's coverage, recorded as a new posture by the same rule; believed on the admin channel only", async () => {
  const r = serverRig();
  try {
    const token = r.begin("human").result!["token"] as string;
    const LOST = { ...COVERAGE, modelContext: "none" };
    const route = { state: "lost", problems: [{ code: "route-elsewhere", detail: "Anthropic calls go to https://evil.example, not Mandu's service proxy\u0007" }], config: "/home/u/.openclaw/openclaw.json" };
    const update = (channel: IpcChannel, extra: Record<string, unknown> = {}) => r.call({ op: "updateAttachment", token, coverage: LOST, route, ...extra }, channel);

    // The data socket: refused (the agent world could record its route as restored).
    assert.equal(update("data").error, humanPlaneOnlyError("updateAttachment"));
    // The admin channel (the service's own dashboard): believed.
    const ok = update("admin");
    assert.equal(ok.ok, true, ok.error);
    assert.deepEqual(ok.result, { posture: "gated", gap: "model-route-lost", believed: true });
    const ev = r.events(SID);
    assert.equal(ev.length, 2);
    const p = ev[1]!;
    assert.equal(p["kind"], "launch_posture");
    assert.equal(p["emitter"], "arbiter");
    assert.equal(p["claimed"], undefined, "believed");
    assert.deepEqual(p["secrets"], { posture: "gated", gap: "model-route-lost" });
    assert.deepEqual((p["attachment"] as Record<string, unknown>)["coverage"], LOST);
    const rec = p["attachmentRoute"] as { state: string; problems: Array<{ detail: string }>; config: string };
    assert.equal(rec.state, "lost");
    assert.doesNotMatch(rec.problems[0]!.detail, /\u0007/, "control characters dropped");
    assert.equal(rec.config, "/home/u/.openclaw/openclaw.json");
    assert.match(String((p["input"] as Record<string, unknown>)["symbolized"]), /NOT all through Mandu's proxy/);
    assert.match(String((p["dropped"] as string[])[0]), /in this OpenClaw Gateway/);

    // The exposed human socket (the Gateway's programs reach it): a claim.
    const claim = update("human", { coverage: COVERAGE, route: { state: "routed", problems: [] } });
    assert.equal(claim.ok, true, claim.error);
    assert.equal(claim.result!["believed"], false);
    assert.equal(r.events(SID).at(-1)!["claimed"], true);

    // Back, on the admin channel: the kind's own gap again.
    assert.deepEqual(update("admin", { coverage: COVERAGE, route: { state: "routed", problems: [] } }).result, { posture: "gated", gap: "openclaw-plugin", believed: true });
    // The plugin lost alone: exec and replies none, the gap stays the kind's.
    assert.equal(update("admin", { coverage: { ...COVERAGE, exec: "none", replies: "none" } }).result!["gap"], "openclaw-plugin");

    // Never more than the kind covers; a bad route; a token not live.
    const bad = (extra: Record<string, unknown>, re: RegExp) => {
      const res = update("admin", extra);
      assert.equal(res.ok, false, JSON.stringify(extra));
      assert.match(res.error ?? "", re, JSON.stringify(extra));
    };
    bad({ coverage: { ...COVERAGE, exec: "sandbox" } }, /its kind's coverage or less \(its exec row/);
    bad({ coverage: { ...COVERAGE, egress: "gate" } }, /egress row/);
    bad({ coverage: { ...COVERAGE, files: { by: "guard" }, ownState: "walled" } }, /resolves to confined/);
    bad({ coverage: { ...COVERAGE, modelContext: "elsewhere" } }, /coverage must be a coverage/);
    bad({ route: { state: "lost", problems: [] } }, /route must be/);
    bad({ route: { state: "maybe", problems: [] } }, /route must be/);
    bad({ route: { state: "lost", problems: [{ code: "Bad Code", detail: "x" }] } }, /route must be/);
    bad({ route: { state: "lost", problems: [{ code: "x", detail: "y".repeat(401) }] } }, /route must be/);
    bad({ route: { ...route, config: "relative.json" } }, /route must be/);
    bad({ token: "forged" }, /not a live attachment/);
    const before = r.events(SID).length;
    assert.equal(r.call({ op: "endAttachment", token }, "human").result!["ended"], true);
    assert.match(update("admin").error ?? "", /not a live attachment/, "an ended attachment takes no update");
    assert.equal(r.events(SID).length, before, "nothing recorded by a refusal");
  } finally {
    await r.done();
  }
});

test("beginAttachment (§3.6): a service that starts with the route lost registers it lost, with the route on the record", async () => {
  const r = serverRig();
  try {
    const res = r.begin("human", {
      coverage: { ...COVERAGE, modelContext: "none", exec: "none", replies: "none" },
      route: { state: "lost", problems: [{ code: "unreadable", detail: "could not read /home/u/.openclaw/openclaw.json: bad" }], config: "/home/u/.openclaw/openclaw.json" },
    });
    assert.equal(res.ok, true, res.error);
    assert.equal(res.result!["gap"], "model-route-lost");
    const p = r.events(SID)[0]!;
    assert.deepEqual(p["secrets"], { posture: "gated", gap: "model-route-lost" });
    assert.equal((p["attachmentRoute"] as { state: string }).state, "lost");
    assert.equal(r.begin("human", { sessionId: "openclaw:ops", coverage: { ...COVERAGE, exec: "sandbox" } }).ok, false, "never more than the kind covers");
  } finally {
    await r.done();
  }
});

test("while an attachment is live the human socket is not believed (as for an unwalled launch); after it ends, it is again", async () => {
  const r = serverRig();
  try {
    const walled = r.call({ op: "humanPlaneStatus" }, "human").result!;
    assert.equal(walled["exposed"], false);
    const token = r.begin("human").result!["token"] as string;

    const st = r.call({ op: "humanPlaneStatus" }, "human").result!;
    assert.equal(st["exposed"], true);
    assert.deepEqual((st["launches"] as Array<Record<string, unknown>>).map((l) => ({ pid: l["pid"], session: l["session"], attachment: l["attachment"] })),
      [{ pid: 0, session: SID, attachment: "openclaw-plugin" }]);
    // an event on the human socket is a claim now
    assert.equal(r.emit("human", "s-other", "relay_mode").ok, true);
    assert.equal(r.events("s-other").at(-1)!["claimed"], true);
    // the seals are void
    assert.equal(r.call({ op: "cacheSeals", kind: "object-twin", keys: [] }, "human").result!["honoured"], false);
    // a second registration while exposed is recorded, as a claim
    const second = r.begin("human", { sessionId: "openclaw:ops" });
    assert.equal(second.ok, true);
    assert.equal(second.result!["believed"], false);
    assert.equal(r.events("openclaw:ops")[0]!["claimed"], true);

    assert.equal(r.call({ op: "endAttachment", token }, "human").result!["ended"], true);
    assert.equal(r.call({ op: "endAttachment", token: second.result!["token"] }, "human").result!["ended"], true);
    assert.equal(r.call({ op: "humanPlaneStatus" }, "human").result!["exposed"], false);
    assert.equal(r.emit("human", "s-other", "relay_mode").ok, true);
    assert.equal(r.events("s-other").at(-1)!["claimed"], undefined, "believed again");
  } finally {
    await r.done();
  }
});

test("no emit of a launch_posture for an attached session is taken from the data socket or the exposed human socket; other kinds are claims", async () => {
  const r = serverRig();
  try {
    // before any attachment, a forged posture on the data socket is a claim
    assert.equal(r.emit("data", SID, "launch_posture").ok, true);
    assert.equal(r.events(SID)[0]!["claimed"], true);
    r.begin("human");
    for (const ch of ["data", "human"] as const) {
      const res = r.emit(ch, SID, "launch_posture");
      assert.equal(res.ok, false, ch);
      assert.match(res.error ?? "", /is an attachment session; its posture is recorded by the arbiter/);
    }
    assert.equal(r.emit("data", SID, "tool_use").ok, true, "the plugin's own events still land (as claims)");
    const posture = r.events(SID).filter((e) => e["kind"] === "launch_posture");
    assert.deepEqual(posture.map((e) => [e["emitter"], e["claimed"] ?? false]), [["launcher", true], ["arbiter", false]]);
    // the admin channel (the arbiter's own, the dashboard's) stays believed
    assert.equal(r.emit("admin", SID, "launch_posture").ok, true);
  } finally {
    await r.done();
  }
});

test("a lease that runs out ends the exposure on its own (the exposure watch); renew keeps it", async () => {
  const r = serverRig({ attachmentLeaseMs: 400 });
  try {
    const token = r.begin("human").result!["token"] as string;
    assert.equal(r.call({ op: "humanPlaneStatus" }, "human").result!["exposed"], true);
    await new Promise((res) => setTimeout(res, 250));
    assert.equal(r.call({ op: "renewAttachment", token }, "human").result!["renewed"], true);
    await new Promise((res) => setTimeout(res, 250));
    assert.equal(r.call({ op: "humanPlaneStatus" }, "human").result!["exposed"], true, "renewed: still live past the first deadline");
    await new Promise((res) => setTimeout(res, 700));
    assert.equal(r.call({ op: "humanPlaneStatus" }, "human").result!["exposed"], false, "lapsed: the human plane is walled again");
    assert.equal(r.call({ op: "renewAttachment", token }, "human").result!["renewed"], false);
  } finally {
    await r.done();
  }
});
