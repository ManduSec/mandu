/**
 * home-last-stepped-in.test — `buildHome` (GET /api/home) names the newest
 * session before the window where Mandu stepped in, only while the window
 * counts nothing (dashboard.md §4.25 *An empty window says when Mandu last
 * stepped in*).
 *
 * Pins:
 * - absent when the window counted something (its counts are the hero's);
 * - absent when no session before the window was stepped in on;
 * - absent when the window's only session ran with protection off (the
 *   window counts it: §4.25 *A session that ran with protection off says so*);
 * - the newest such session when one was: its id, agent, folder and last
 *   time, and its History row's numbers (`counts`), and nothing else;
 * - the counts carry the questions it raised that still wait, and whether
 *   a protection did not start in it (`lessProtection`, its row's mark);
 * - never a session inside the window, even one History's switch keeps
 *   (a question it raised still waits): the older one is named instead;
 * - the answer is kept while the listing and the minute stay the same, so
 *   the poll does not look through again;
 * - a look-through that fails names none, and the payload is as before.
 *
 * Axes: the stub snapshot serves the `secrets` posture (stated); display
 * only, no arbiter runs.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { copyFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { buildHome, HomeFacts, type HomeDeps } from "../../../src/server/home-routes.js";
import { FileEventSource } from "../../../src/event-source.js";
import type { SessionRef } from "../../../src/event-source/contract.js";
import type { LabelTimes } from "../../../src/server/label-times.js";
import type { HomeSessionFacts } from "../../../src/view-model/home.js";
import type { PolicySnapshot, VerdictEntry } from "../../../src/policy-model.js";

const FIXTURES_DIR = join(fileURLToPath(new URL(".", import.meta.url)), "..", "..", "..", "fixtures");
const HOUR = 3_600_000;
// sess-7af3 ended at 10:00:08 (2 untrusted items masked: Mandu stepped in).
const STEPPED_AT = "2026-06-14T10:00:08.000Z";
const STEPPED_MS = Date.parse(STEPPED_AT);
const MANDU = mkdtempSync(join(tmpdir(), "mandu-home-last-mandu-"));
const dirs: string[] = [MANDU];
after(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });

/** A session with one prompt and one reply, at `ts`: Mandu did nothing. */
function plain(dir: string, sid: string, ts: string): void {
  writeFileSync(join(dir, `${sid}.ndjson`), JSON.stringify({
    id: `01J000000000000000${sid.slice(-6).toUpperCase().padStart(6, "0")}00`, sessionId: sid, turn: 0, ts, seq: 0, callId: null, parentId: null,
    kind: "tllm_call", view: "AgentView", boundary: "model_context", emitter: "anthropic-proxy",
    input: { symbolized: "▸ user\nRename the parser helper.", original: null, differs: false, symbols: [] },
    output: { symbolized: "Done.", original: null, differs: false, symbols: [] },
    invariant: { violatedInvariant: false }, model: { id: "claude-opus-4-8", inputTokens: 10, outputTokens: 2 },
  }) + "\n");
}

/** A record dir: sess-7af3 when `stepped`, and the plain sessions named. */
function records(stepped: boolean, plains: [string, string][]): string {
  const dir = mkdtempSync(join(tmpdir(), "mandu-home-last-"));
  dirs.push(dir);
  if (stepped) copyFileSync(join(FIXTURES_DIR, "sess-7af3.ndjson"), join(dir, "sess-7af3.ndjson"));
  for (const [sid, ts] of plains) plain(dir, sid, ts);
  return dir;
}

/** A file source behind which an arbiter serves the `secrets` posture and
 *  one pending ask per session in `waiting`. */
class Source extends FileEventSource {
  constructor(dir: string, private readonly waiting: string[] = [], private readonly nowMs = 0) { super(dir); }
  override async policySnapshot(): Promise<PolicySnapshot | null> {
    const verdicts = this.waiting.map((sid, i) => ({
      id: `egr-${i}`, symbol: `$MDU:nomodel_Read[${i}abc].STRIPE_KEY`, destination: "api.stripe.com", status: "pending",
      reason: "secret symbol (no-model) at unbound destination", count: 1, firstSeen: this.nowMs - 120_000, lastSeen: this.nowMs - 60_000,
      resolvedAt: null, sessions: [sid],
    } as VerdictEntry));
    return {
      specId: "claude-code", origins: [], tools: {}, fallbackTrust: "UNTRUSTED", mcpPrefix: "mcp__",
      posture: { integrity: false, confidentiality: true }, // the `secrets` axes, stated
      usage: { rules: [], sensitivePaths: [] },
      verdicts,
    } as unknown as PolicySnapshot;
  }
}

/** Home's per-session facts, counting what it is asked for; `fail`: every
 *  ask throws (a record that cannot be read). */
class Facts extends HomeFacts {
  asked: string[] = [];
  fail = false;
  override async of(s: SessionRef, times?: LabelTimes): Promise<HomeSessionFacts> {
    this.asked.push(s.id);
    if (this.fail) throw new Error("the record cannot be read");
    return super.of(s, times);
  }
}

function deps(source: Source, nowMs: number, facts = new HomeFacts(source, "/home/u")): HomeDeps {
  return { source, facts, approvals: undefined, testRuns: [], watchRuns: [], env: { MANDU_HOME: MANDU }, home: "/home/u", now: () => nowMs };
}

test("the window counted something: no lastSteppedIn", async () => {
  // sess-7af3 is in the window: its 2 masked items are the hero's count.
  const now = STEPPED_MS + 2 * HOUR;
  const vm = await buildHome(deps(new Source(records(true, [["sess-older", new Date(STEPPED_MS - 40 * HOUR).toISOString()]])), now));
  assert.equal(vm.window.untrusted, 2, "the window counts the masked items");
  assert.equal("lastSteppedIn" in vm, false);
});

test("nothing before the window was stepped in on: no lastSteppedIn", async () => {
  const now = STEPPED_MS + 48 * HOUR;
  const dir = records(false, [["sess-new", new Date(now - 2 * HOUR).toISOString()], ["sess-old", new Date(now - 30 * HOUR).toISOString()]]);
  const vm = await buildHome(deps(new Source(dir), now));
  assert.equal(vm.window.sessions, 1);
  assert.equal(vm.window.counted, 1);
  assert.equal("lastSteppedIn" in vm, false);
});

/** Home's facts, with the sessions named recorded as run with protection off. */
class OffFacts extends HomeFacts {
  constructor(source: Source, private readonly offIds: string[]) { super(source, "/home/u"); }
  override async of(s: SessionRef, times?: LabelTimes): Promise<HomeSessionFacts> {
    const f = await super.of(s, times);
    return this.offIds.includes(s.id) ? { ...f, off: true } : f;
  }
}

test("the window's only session ran with protection off: it is counted, so no lastSteppedIn", async () => {
  const now = STEPPED_MS + 72 * HOUR;
  // sess-7af3, before the window, would be named, were the window empty.
  const dir = records(true, [["sess-today", new Date(now - 2 * HOUR).toISOString()]]);
  const source = new Source(dir);
  const vm = await buildHome(deps(source, now, new OffFacts(source, ["sess-today"])));
  assert.equal(vm.window.sessions, 1);
  assert.deepEqual([vm.window.off, vm.window.only.off], [1, "sess-today"]);
  assert.equal("lastSteppedIn" in vm, false, "Mandu only watched in it: not a quiet day");
  // The same window, protected: the line names sess-7af3, as before.
  const on = await buildHome(deps(source, now, new OffFacts(source, [])));
  assert.equal(on.window.off, 0);
  assert.equal(on.lastSteppedIn?.id, "sess-7af3");
});

test("the newest session before the window where Mandu stepped in, metadata only", async () => {
  const now = STEPPED_MS + 72 * HOUR;
  // A plain session in the window, a plain one before it that is newer than
  // the stepped-in one, and a plain one older still.
  const dir = records(true, [
    ["sess-today", new Date(now - 2 * HOUR).toISOString()],
    ["sess-plainer", new Date(STEPPED_MS + HOUR).toISOString()],
    ["sess-oldest", new Date(STEPPED_MS - 5 * HOUR).toISOString()],
  ]);
  const vm = await buildHome(deps(new Source(dir), now));
  assert.equal(vm.window.sessions, 1, "only sess-today is in the window");
  // Its History row's numbers ride along as `counts`, so the line says what
  // Mandu did there: 2 untrusted items masked, protection held.
  assert.deepEqual(vm.lastSteppedIn, {
    id: "sess-7af3", agent: "Claude Code", cwd: null, at: STEPPED_AT,
    counts: { secrets: { masked: 0, early: 0 }, untrusted: 2, blocked: 0, sent: 0, waiting: 0, holds: true, protectionOff: false },
  });
  assert.doesNotMatch(JSON.stringify(vm.lastSteppedIn), /\$MDU:|ignore all prior instructions|acme\.example/, "no item, no value");
});

test("the counts carry the questions the named session raised that still wait", async () => {
  const now = STEPPED_MS + 72 * HOUR;
  const dir = records(true, [["sess-today", new Date(now - 2 * HOUR).toISOString()]]);
  const vm = await buildHome(deps(new Source(dir, ["sess-7af3"], now), now));
  assert.equal(vm.lastSteppedIn?.id, "sess-7af3");
  assert.deepEqual(vm.lastSteppedIn?.counts, { secrets: { masked: 0, early: 0 }, untrusted: 2, blocked: 0, sent: 0, waiting: 1, holds: true, protectionOff: false });
});

test("the counts say a protection did not start in the named session, as its History row does", async () => {
  const now = STEPPED_MS + 72 * HOUR;
  const dir = records(true, [["sess-today", new Date(now - 2 * HOUR).toISOString()]]);
  // Its launch went on without the network proxy (the launcher's own line).
  const file = join(dir, "sess-7af3.ndjson");
  const line = "mandu: service 'net-proxy' is on by default but failed to start: 127.0.0.1:8790 is occupied — proceeding WITHOUT it (opt out explicitly with --no-net-proxy to silence this)";
  writeFileSync(file, JSON.stringify({
    id: "01J0000000000000000000L000", sessionId: "sess-7af3", turn: 0, ts: "2026-06-14T09:59:59.000Z", seq: 0, callId: null, parentId: null,
    kind: "launch_posture", view: "HumanView", boundary: "shell", emitter: "launcher", target: "claude", live: ["fs"], dropped: [line],
    input: null, output: null, invariant: { violatedInvariant: false },
  }) + "\n" + readFileSync(file, "utf8"));
  const vm = await buildHome(deps(new Source(dir), now));
  assert.equal(vm.lastSteppedIn?.id, "sess-7af3");
  assert.deepEqual(vm.lastSteppedIn?.counts, { secrets: { masked: 0, early: 0 }, untrusted: 2, blocked: 0, sent: 0, waiting: 0, holds: true, protectionOff: false, lessProtection: true });
  assert.doesNotMatch(JSON.stringify(vm.lastSteppedIn), /net-proxy|8790|WITHOUT/, "the count's mark, never the launch line");
});

test("never a session inside the window, even one a waiting question keeps on History's switch", async () => {
  const now = STEPPED_MS + 72 * HOUR;
  const dir = records(true, [["sess-today", new Date(now - 2 * HOUR).toISOString()]]);
  // sess-today raised a question that still waits: History's switch keeps it.
  const vm = await buildHome(deps(new Source(dir, ["sess-today"], now), now));
  assert.equal(vm.verdict, "waiting");
  assert.equal(vm.agents.find((a) => a.id === "sess-today")?.waiting, 1, "the row waits");
  assert.equal(vm.lastSteppedIn?.id, "sess-7af3", "the one before the window, never the one in it");
});

test("the answer is kept while the listing and the minute stay; a failed look-through names none", async () => {
  const now = STEPPED_MS + 72 * HOUR;
  const dir = records(true, [["sess-plainer", new Date(STEPPED_MS + HOUR).toISOString()]]);
  const source = new Source(dir);
  const facts = new Facts(source, "/home/u");
  const first = await buildHome(deps(source, now, facts));
  assert.equal(first.lastSteppedIn?.id, "sess-7af3");
  assert.ok(facts.asked.includes("sess-7af3"), "looked through");
  facts.asked = [];
  facts.fail = true;
  // Within the same minute, over the same listing: the kept answer, nothing asked.
  const again = await buildHome(deps(source, now + 10_000, facts));
  assert.equal(again.lastSteppedIn?.id, "sess-7af3");
  assert.deepEqual(facts.asked, [], "no session counted again");
  // The next minute it looks again; every record fails to read, so none is
  // named (an unreadable session keeps its listing's verdict: not stepped in).
  const later = await buildHome(deps(source, now + 60_000, facts));
  assert.equal("lastSteppedIn" in later, false);
  assert.equal(later.verdict, "secrets-only", "Home still answers");
});
