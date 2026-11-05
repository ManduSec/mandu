/**
 * limit-reset-time — dashboard.md §4.21 *On the product page* and §4.25u
 * *Every moment reads absolute and relative*, end to end: the REAL
 * DashboardServer over a FileEventSource holding a session the AI plan's
 * usage limit stopped (a `tllm_call` whose `upstreamLimit` carries the
 * provider's `resetsAt`, as anthropic-proxy records it, then a
 * `session_exit`). Its Home row (GET /api/home), its History row (GET
 * /api/home/history) and its session page (GET /api/home/agent) carry the
 * reset moment as a `time` part with that ISO time in `noticeParts`, which
 * the page draws in the reader's clock; the plain `notice` keeps it in UTC.
 * A limit without a reset time says no moment. Signed out, the same (the
 * moment is the provider's, no value the AI did not see).
 *
 * The page's drawing of the part: test/unit/ui/home-js-limit-reset.test.ts.
 * Axes: secrets (the mode the product runs by default; display only, no
 * arbiter runs).
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { DashboardServer } from "../../src/server.js";
import { FileEventSource } from "../../src/event-source.js";
import { ADMIN_OPTS, CSRF_ADMIN } from "../unit/admin-session.js";

const dir = mkdtempSync(join(tmpdir(), "mandu-limit-reset-"));
const RESETS = "2026-10-28T21:00:00.000Z";
let server: DashboardServer;
let base: string;

function ev(session: string, kind: string, ts: string, extra: Record<string, unknown>): string {
  return JSON.stringify({
    id: `ev_${session}_${kind}`, sessionId: session, turn: 0, ts, seq: 0, callId: null, parentId: null, kind,
    view: kind === "tllm_call" ? "AgentView" : "HumanView", boundary: kind === "tllm_call" ? "model_context" : "shell",
    emitter: kind === "tllm_call" ? "anthropic-proxy" : "launcher", invariant: { violatedInvariant: false },
    input: { symbolized: "hello", original: null, differs: false, symbols: [] },
    output: { symbolized: "no model response", original: null, differs: false, symbols: [] },
    ...extra,
  });
}

/** A session the limit stopped, an hour ago (inside Home's window). */
function limited(session: string, resetsAt?: string): string {
  const at = (s: number) => new Date(Date.now() - 3_600_000 + s * 1000).toISOString();
  const limit = { status: 429, unifiedStatus: "rejected", claim: "seven_day", retryAfterS: 45151, hard: true, ...(resetsAt ? { resetsAt } : {}) };
  return [
    ev(session, "launch_posture", at(0), { target: "claude", argv0: "claude", live: ["fs"], dropped: [], notes: [], mode: "secrets" }),
    ev(session, "tllm_call", at(2), { upstreamLimit: limit }),
    ev(session, "session_exit", at(3), { code: 0, durationMs: 3000, output: null }),
  ].join("\n") + "\n";
}

before(async () => {
  writeFileSync(join(dir, "sess-limit.ndjson"), limited("sess-limit", RESETS));
  writeFileSync(join(dir, "sess-nowhen.ndjson"), limited("sess-nowhen"));
  server = new DashboardServer({ ...ADMIN_OPTS, source: new FileEventSource(dir), log: () => {}, extensions: [] });
  base = `http://127.0.0.1:${await server.listen(0)}`;
});

after(async () => {
  await server.close();
  rmSync(dir, { recursive: true, force: true });
});

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function get(path: string, admin: boolean): Promise<any> {
  const r = await fetch(`${base}${path}`, admin ? { headers: CSRF_ADMIN } : {});
  assert.equal(r.status, 200, path);
  return r.json();
}

type Part = { kind: string; text: string };
/** A notice's parts and line: one time part with the reset ISO, preceded by
 *  "It resets "; no UTC in the drawn words; the plain line in UTC. */
function assertMoment(where: string, notice: string, parts: Part[]): void {
  assert.ok(Array.isArray(parts), `${where}: parts`);
  const times = parts.filter((p) => p.kind === "time");
  assert.deepEqual(times, [{ kind: "time", text: RESETS }], `${where}: ${JSON.stringify(parts)}`);
  const i = parts.findIndex((p) => p.kind === "time");
  assert.ok(parts[i - 1].text.endsWith("It resets "), where);
  assert.ok(parts[i + 1].text.startsWith("."), where);
  for (const p of parts.filter((q) => q.kind !== "time")) assert.doesNotMatch(p.text, /UTC|2026-10-28/, where);
  assert.match(notice, /It resets 2026-10-28 at 21:00 UTC\./, `${where}: the plain line keeps UTC`);
}

for (const admin of [true, false]) {
  const who = admin ? "signed in" : "signed out";

  test(`${who}: the session page's warning carries the reset moment as a time part`, async () => {
    const vm = await get("/api/home/agent?session=sess-limit", admin);
    assert.equal(vm.found, true);
    assertMoment("agent page", vm.notice, vm.noticeParts);
    const none = await get("/api/home/agent?session=sess-nowhen", admin);
    assert.match(none.notice, /This limit is your AI provider's, not Mandu's\.$/);
    assert.equal((none.noticeParts as Part[]).some((p) => p.kind === "time" || p.text.includes("It resets")), false);
  });

  test(`${who}: the Home row and the History row carry the same parts`, async () => {
    const home = await get("/api/home", admin);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const row = (home.agents as any[]).find((a) => a.id === "sess-limit");
    assert.ok(row, JSON.stringify((home.agents as Array<{ id: string }>).map((a) => a.id)));
    assertMoment("Home row", row.notice, row.noticeParts);
    const history = await get("/api/home/history", admin);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const rows = history.rows as any[];
    const hrow = rows.find((a) => a.id === "sess-limit");
    assert.ok(hrow, JSON.stringify(rows.map((a) => a.id)));
    assertMoment("History row", hrow.notice, hrow.noticeParts);
  });
}
