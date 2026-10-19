/**
 * label-times.test — the server's reads of when each file a session read was
 * labelled (server/label-times.ts), and Home's facts over them
 * (home-routes.ts `HomeFacts`; dashboard.md §4.25b, *Labelled after the
 * session*). Contracts:
 *   - one request reads each thing once: a path is asked once, the change
 *     log once, the Rules page labels only when a page label decides a file;
 *   - an arbiter without an op, one that fails, or one with protection off
 *     gives no time (so the page makes no claim), never a throw;
 *   - Home's facts of a session whose listing has not moved count a label
 *     made after it ended (the cache is keyed on the label times too), and
 *     a waiting card about that file learns the AI read it (`readFirstFiles`).
 *
 * Axes: none (pure reads over a scripted arbiter).
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { LabelTimes, labelTimesArbiter, type LabelTimesArbiter } from "../../../src/server/label-times.js";
import { HomeFacts } from "../../../src/server/home-routes.js";
import type { PolicyChangeRow } from "../../../src/view-model/policy-proposals.js";
import type { PathLevelsEntryWire } from "../../../src/view-model/file-browser.js";
import type { ManduEvent } from "../../../src/event-model.js";
import type { EventSource } from "../../../src/event-source.js";
import type { SessionRef } from "../../../src/event-source/contract.js";

const FILE = "/home/dev/w/deploy/staging.conf";
const T0 = Date.parse("2026-10-12T10:40:00.000Z");
const iso = (ms: number) => new Date(ms).toISOString();

function change(at: number, path = FILE): PolicyChangeRow {
  return {
    id: "pc-1", via: "proposal", requestedBy: "human", sessionKey: null, edits: [{ op: "lock-path", path, level: "no-model" }], delta: [],
    proposalId: null, createdAt: at, undoneAt: null, undoneBy: null, undoable: true, rules: [{ rowIds: [`lock:${path}`], added: true, removed: false, current: true }],
  };
}

/** A scripted arbiter: `labels` decide files now; counts every read. */
function scripted(o: { policy?: string[]; page?: string[]; at?: number; axis?: boolean; fail?: boolean } = {}) {
  const calls = { pathLevels: [] as string[][], policyChanges: 0, confidentialityState: 0 };
  const at = o.at ?? T0 + 600_000;
  const arb: LabelTimesArbiter = {
    pathLevels: async (paths) => {
      calls.pathLevels.push(paths);
      if (o.fail) throw new Error("arbiter down");
      const levels: PathLevelsEntryWire[] = paths.map((p) => {
        const store = o.policy?.includes(p) ? "policy" : o.page?.includes(p) ? "page" : null;
        return store ? { path: p, level: "no-model", bindings: [], rule: `label:${p}`, store } : { path: p, level: "public", bindings: [], rule: null, store: null };
      });
      return { axis: o.axis ?? true, levels };
    },
    policyChanges: async () => { calls.policyChanges++; return { changes: (o.policy ?? []).map((p) => change(at, p)) }; },
    confidentialityState: async () => { calls.confidentialityState++; return { labels: (o.page ?? []).map((p) => ({ path: p, source: "dashboard", updatedAt: at })) }; },
  };
  return { arb, calls };
}

test("one request reads each thing once, and the page labels only when one decides a file", async () => {
  const { arb, calls } = scripted({ policy: [FILE] });
  const times = new LabelTimes(arb, "/home/dev");
  assert.deepEqual(await times.of([FILE, "/home/dev/w/README.md"]), [{ path: FILE, level: "no-model", at: iso(T0 + 600_000) }]);
  assert.deepEqual(await times.of([FILE]), [{ path: FILE, level: "no-model", at: iso(T0 + 600_000) }]);
  assert.deepEqual(calls, { pathLevels: [[FILE, "/home/dev/w/README.md"]], policyChanges: 1, confidentialityState: 0 });

  const page = scripted({ page: [FILE] });
  assert.deepEqual(await new LabelTimes(page.arb, "/home/dev").of([FILE]), [{ path: FILE, level: "no-model", at: iso(T0 + 600_000) }]);
  assert.deepEqual([page.calls.policyChanges, page.calls.confidentialityState], [0, 1]);
});

test("no answer, no op, or protection off: no time, never a throw", async () => {
  assert.deepEqual(await new LabelTimes(scripted({ policy: [FILE], fail: true }).arb, "").of([FILE]), []);
  assert.deepEqual(await new LabelTimes(scripted({ policy: [FILE], axis: false }).arb, "").of([FILE]), []);
  assert.deepEqual(await new LabelTimes(undefined, "").of([FILE]), []);
  const { arb } = scripted({ policy: [FILE] });
  assert.deepEqual(await new LabelTimes({ pathLevels: arb.pathLevels! }, "").of([FILE]), [], "no change log: no time");
  const broken: LabelTimesArbiter = { ...arb, policyChanges: async () => { throw new Error("no"); } };
  assert.deepEqual(await new LabelTimes(broken, "").of([FILE]), []);
});

test("labelTimesArbiter forwards each read to the surface that has it", async () => {
  const seen: string[] = [];
  const composed = labelTimesArbiter(
    { pathLevels: async (paths, home) => { seen.push(`levels ${paths.join()} ${home}`); return { axis: true, levels: [] }; }, confidentialityState: async () => { seen.push("state"); return { labels: [] }; } },
    { policyChanges: async (limit) => { seen.push(`changes ${limit}`); return { changes: [] }; } },
  )!;
  await composed.pathLevels!(["/a"], "/h");
  await composed.confidentialityState!();
  await composed.policyChanges!(7);
  assert.deepEqual(seen, ["levels /a /h", "state", "changes 7"]);
  assert.equal(labelTimesArbiter(undefined, undefined), undefined);
});

/** A session that reads FILE as it was and ends. */
function events(): ManduEvent[] {
  const out: ManduEvent[] = [];
  let seq = 0;
  const dr = (s: string) => ({ symbolized: s, original: null, differs: false, symbols: [] });
  const ev = (kind: string, f: Record<string, unknown> = {}): void => {
    out.push({ id: `s-${seq}`, sessionId: "s", turn: 0, ts: iso(T0 + seq * 1000), seq, callId: null, parentId: null, kind, view: "AgentView", boundary: "model_context", emitter: "anthropic-proxy", input: null, output: null, invariant: { violatedInvariant: false }, ...f } as unknown as ManduEvent);
    seq++;
  };
  ev("launch_posture", { view: "HumanView", boundary: "shell", emitter: "launcher", protection: { mode: "secrets", integrity: false, reported: true } });
  ev("tllm_call", { input: dr("▸ user\nWhat is in it?"), output: dr(`→ Read(${JSON.stringify({ file_path: FILE })})`) });
  ev("tool_use", { callId: "c1", input: dr(`Read(${JSON.stringify({ file_path: FILE })})`) });
  ev("tool_result", { callId: "c1", output: dr('token = "ghp_x"'), policy: { trust: "TRUSTED", reason: "integrity axis OFF" } });
  ev("tllm_call", { turn: 1, input: dr("▸ tool_result\ntoken"), output: dr("One token.") });
  return out;
}

test("Home's facts of a session that has not moved count a label made after it ended", async () => {
  const ev = events();
  let reads = 0;
  const source = { readEvents: async () => { reads++; return ev; } } as unknown as EventSource;
  const listed = { id: "s", eventCount: ev.length, firstTs: ev[0]!.ts, lastTs: ev.at(-1)!.ts } as SessionRef;
  let arb: LabelTimesArbiter | undefined = scripted().arb; // nothing labelled yet
  const facts = new HomeFacts(source, "/home/dev", () => arb);

  const before = await facts.of(listed, facts.labelTimes());
  assert.deepEqual(before.secrets, { masked: 0, early: 0 });
  assert.equal(before.readFirstFiles?.has(FILE), false);
  assert.deepEqual(facts.pathsOf(["s"]), [FILE], "the file it read as it was, for the next request to ask at once");
  // The same label times: the cached facts, not re-read.
  await facts.of(listed, facts.labelTimes());
  assert.equal(reads, 1);

  arb = scripted({ policy: [FILE] }).arb; // the file is marked a secret after the session ended
  const after = await facts.of(listed, facts.labelTimes());
  assert.equal(reads, 2, "the label moved: counted again");
  assert.deepEqual(after.secrets, { masked: 0, early: 1 }, "counted as read before it was marked");
  assert.equal(after.readFirstFiles?.get(FILE), iso(T0 + 2000), "a waiting card about the file learns the AI read it");
  // Without a request's label reads (the policy panel's lookup): as cached.
  assert.equal(await facts.of(listed), after);
});
