/**
 * plugin-routes — the facts behind the Plugins page (server/plugin-routes.ts
 * `gatherPluginFacts`, dashboard.md §4.25aj), over temp files laid out as
 * `mandu serve`'s pool lays them out (attachment-contract.ts) and a mock
 * protection service:
 *
 *   - no declared file, no pool record: the service is not running and
 *     nothing is attached;
 *   - a pool record naming a live pid: running; a dead pid: not;
 *   - a declared session whose trusted port file names a proxy that answers
 *     as the session's: answering; its pool record's secret registration;
 *     the protection service's attachment with when it began; a session
 *     with a record gets its page link;
 *   - a port file others can write, or a proxy that answers as another
 *     session: not answering (the contract's trust rules);
 *   - an attachment the protection service still holds without a
 *     declaration is listed, not declared; a protection service that does
 *     not answer leaves `live` unknown;
 *   - this process's own pool (under `mandu serve`) is the service, and its
 *     state is read directly;
 *   - the answer of `apiPlugins` names no port and no path.
 * Axes: none (display only). Mandu-new test.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { apiPlugins, gatherPluginFacts, type PluginDeps } from "../../../src/server/plugin-routes.js";
import type { EventSource } from "../../../src/event-source.js";
import type { HumanPlaneStatus } from "../../../src/event-source/contract.js";
import { tmpDir } from "../tmp-dir.js";

const SESSION = "openclaw:main";
const BEGUN = Date.parse("2026-10-25T09:00:00.000Z");

function source(status: HumanPlaneStatus | "fail" | null, ids: Array<string | Record<string, unknown>> = []): EventSource {
  return {
    listSessions: async () => ids.map((id) => (typeof id === "string" ? { id } : id)),
    readEvents: async () => [],
    ...(status === null ? {} : { humanPlaneStatus: async () => { if (status === "fail") throw new Error("down"); return status; } }),
  } as unknown as EventSource;
}

const LIVE: HumanPlaneStatus = { exposed: true, since: BEGUN, launches: [{ pid: 0, mode: "secrets", posture: "gated", session: SESSION, begunAt: BEGUN, attachment: "openclaw-plugin" }] };

/** A runtime dir and a declared file as the pool and the installer leave them. */
function layout(o: { declared?: string[]; marker?: number | null; port?: number | null; portMode?: number; secrets?: boolean } = {}) {
  const root = tmpDir("mdu-plugin-routes-");
  const runtime = join(root, "run");
  const declaredFile = join(root, "state", "serve-attachments.json");
  mkdirSync(join(root, "state"), { recursive: true });
  const agents = o.declared ?? ["main"];
  writeFileSync(declaredFile, JSON.stringify({ version: 1, attachments: agents.map((a, i) => ({ kind: "openclaw-plugin", agent: a, session: `openclaw:${a}`, port: 41000 + i })) }));
  mkdirSync(join(runtime, "attachments", SESSION), { recursive: true, mode: 0o700 });
  if (o.marker !== null) writeFileSync(join(runtime, "attachments", "pool.json"), JSON.stringify({ pid: o.marker ?? process.pid, startedAt: "2026-10-25T08:59:00.000Z" }));
  if (o.port !== null) {
    const pf = join(runtime, "attachments", SESSION, "anthropic-proxy.port");
    writeFileSync(pf, `${o.port ?? 41000}\n`, { mode: 0o600 });
    if (o.portMode !== undefined) chmodSync(pf, o.portMode);
  }
  if (o.secrets !== false) {
    writeFileSync(join(runtime, "attachments", SESSION, "pool.json"), JSON.stringify({ pid: process.pid, proxyPid: 1234, session: SESSION, startedAt: "2026-10-25T09:00:00.000Z", secrets: { found: 3, registered: 2, at: "2026-10-25T09:00:01.000Z" } }));
  }
  return { runtime, declaredFile };
}

const asSession = (session: string) => async (port: number) => (port === 41000 ? { mandu: true, service: "anthropic-proxy", sessionKey: session, arbiterSock: "/run/x/arbiter.sock" } : null);

function deps(l: { runtime: string; declaredFile: string }, over: Partial<PluginDeps> = {}): PluginDeps {
  return { source: source(LIVE, [SESSION]), runtimeBase: l.runtime, declaredFile: l.declaredFile, uid: process.getuid?.(), probe: asSession(SESSION), pidAlive: (p) => p === process.pid, ...over };
}

test("no declared file and no pool record: the service is not running, nothing is attached", async () => {
  const root = tmpDir("mdu-plugin-routes-none-");
  const f = await gatherPluginFacts({ source: source({ exposed: false, since: null, launches: [] }), runtimeBase: join(root, "run"), declaredFile: join(root, "none.json") });
  assert.equal(f.serviceRunning, false);
  assert.deepEqual(f.sessions, []);
  assert.deepEqual([...f.live!], []);
});

test("a live pool record and a declared session whose proxy answers: running, answering, its secrets, the attachment with its start, the page link", async () => {
  const l = layout();
  const f = await gatherPluginFacts(deps(l));
  assert.equal(f.serviceRunning, true);
  assert.deepEqual(f.sessions, [{
    session: SESSION, kind: "openclaw-plugin", agent: "main", declared: true, answering: true, poolState: null,
    secrets: { found: 3, registered: 2, at: "2026-10-25T09:00:01.000Z" }, route: null, recorded: null,
  }]);
  assert.deepEqual([...f.live!], [[SESSION, BEGUN]]);
  assert.deepEqual([...f.known], [SESSION]);
});

test("a pool record naming a dead pid: not running, and no proxy is asked", async () => {
  const l = layout({ marker: 999_999_999 });
  let asked = 0;
  const f = await gatherPluginFacts(deps(l, { probe: async () => { asked++; return null; } }));
  assert.equal(f.serviceRunning, false);
  assert.equal(f.sessions[0]!.answering, false);
  assert.equal(asked, 0);
});

test("the contract's trust rules: a port file others can write, or a proxy that answers as another session, is not answering", async () => {
  const writable = await gatherPluginFacts(deps(layout({ portMode: 0o666 })));
  assert.equal(writable.sessions[0]!.answering, false, "a port file others can write is not trusted");
  const other = await gatherPluginFacts(deps(layout(), { probe: asSession("openclaw:other") }));
  assert.equal(other.sessions[0]!.answering, false, "a proxy of another session is not this one's");
  const none = await gatherPluginFacts(deps(layout({ port: null })));
  assert.equal(none.sessions[0]!.answering, false, "no port file: not answering");
});

test("an attachment held without a declaration is listed as not declared; a protection service that does not answer leaves it unknown", async () => {
  const held = await gatherPluginFacts(deps(layout({ declared: [] })));
  assert.deepEqual(held.sessions.map((s) => [s.session, s.agent, s.declared]), [[SESSION, "main", false]]);
  const down = await gatherPluginFacts(deps(layout(), { source: source("fail", [SESSION]) }));
  assert.equal(down.live, null);
  const old = await gatherPluginFacts(deps(layout(), { source: source(null, [SESSION]) }));
  assert.equal(old.live, null, "a source without the op: unknown, never 'not registered'");
});

test("this process's own pool is the service, its state read directly (no pool record needed)", async () => {
  const l = layout({ marker: null, secrets: false });
  const f = await gatherPluginFacts(deps(l, {
    pool: () => [{ session: SESSION, declaredPort: 41000, state: "starting", registered: false, port: null, proxyPid: null, restarts: 0, lastError: null, secrets: { found: 1, registered: 1, at: "2026-10-25T09:00:02.000Z" }, route: null }],
  }));
  assert.equal(f.serviceRunning, true);
  assert.equal(f.sessions[0]!.poolState, "starting");
  assert.deepEqual(f.sessions[0]!.secrets, { found: 1, registered: 1, at: "2026-10-25T09:00:02.000Z" });
});

test("the route check's word comes from the session list's health (the arbiter's newest believed record): lost while live, ok once restored, ignored once the attachment ended", async () => {
  const lostHealth = {
    secrets: { posture: "gated", gap: "model-route-lost", sentence: "x" },
    attachmentRoute: { problems: [{ code: "plugin-disabled", detail: "the Mandu plugin is disabled (its entry)" }], config: "/home/u/.openclaw/openclaw.json", since: BEGUN },
  };
  const lost = await gatherPluginFacts(deps(layout(), { source: source(LIVE, [{ id: SESSION, health: lostHealth }]) }));
  assert.deepEqual(lost.sessions[0]!.route, { state: "lost", problems: ["the Mandu plugin is disabled (its entry)"], since: BEGUN });
  assert.deepEqual(lost.sessions[0]!.recorded, { posture: "gated", gap: "model-route-lost" });
  const back = await gatherPluginFacts(deps(layout(), { source: source(LIVE, [{ id: SESSION, health: { secrets: { posture: "gated", gap: "openclaw-plugin", sentence: "x" } } }]) }));
  assert.deepEqual(back.sessions[0]!.route, { state: "ok" });
  assert.equal(back.sessions[0]!.recorded, null);
  const ended = await gatherPluginFacts(deps(layout(), { source: source({ exposed: false, since: null, launches: [] }, [{ id: SESSION, health: lostHealth }]) }));
  assert.deepEqual(ended.sessions[0]!.route, { state: "ok" }, "an ended attachment's last record says nothing about now");
});

test("apiPlugins answers the page, with no port and no path in it", async () => {
  const l = layout();
  let status = 0;
  let body = "";
  const res = { writeHead: (s: number) => { status = s; }, end: (b: string) => { body = b; } } as unknown as Parameters<typeof apiPlugins>[1];
  await apiPlugins(deps(l), res);
  assert.equal(status, 200);
  const vm = JSON.parse(body).plugins;
  assert.equal(vm.hosts[0].cards[0].state, "attached");
  assert.ok(!body.includes("41000"), "no port");
  assert.ok(!body.includes(l.runtime) && !body.includes("serve-attachments"), "no path");
});
