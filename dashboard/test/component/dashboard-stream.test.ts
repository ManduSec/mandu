/**
 * dashboard-stream.test — end-to-end: fixture NDJSON → FileEventSource →
 * DashboardServer REST → derived view-model is correct & legible.
 *
 * Mandu-new test (NO reference origin). This is the dashboard presentation of
 * the §9 invariant oracle (dashboard.md §7.2/§7.3): it drives the canonical
 * ManduEvent stream through the real file-backed source and the real HTTP
 * server, then asserts the served/derived view-model:
 *   1. contains tllm_call, tool_use, tool_result, ullm_call events;
 *   2. labels views correctly (T-LLM/tool → AgentView, ullm → Quarantine, egress
 *      → HumanView);
 *   3. every untrusted-bearing DualRepr has differs===true with $MDU:* in
 *      `symbolized` and the raw payload in `original` (BOTH reprs available);
 *   4. T-LLM vs U-LLM are distinguishable by kind+view with input+output;
 *   5. the oracle holds: ∀ events !violatedInvariant, AND the attack payload
 *      appears in some `original` but NEVER un-symbolized in a tllm_call input.
 * Then a separate fixture with a violated event flips the banner red.
 */

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { join } from "node:path";

import { DashboardServer } from "../../src/server.js";
import { FileEventSource } from "../../src/event-source.js";
import type { ManduEvent } from "../../src/event-model.js";
import type { SessionViewModel } from "../../src/view-model.js";
import { ADMIN_OPTS, CSRF_ADMIN } from "../unit/admin-session.js";

const FIXTURES_DIR = join(fileURLToPath(new URL(".", import.meta.url)), "..", "..", "fixtures");

let server: DashboardServer;
let baseUrl: string;

before(async () => {
  server = new DashboardServer({ ...ADMIN_OPTS,
    source: new FileEventSource(FIXTURES_DIR),
    log: () => {}, // silence
  });
  const port = await server.listen(0); // ephemeral port
  baseUrl = `http://127.0.0.1:${port}`;
});

after(async () => {
  await server.close();
});

async function getEvents(session: string): Promise<{ events: ManduEvent[]; viewModel: SessionViewModel }> {
  const res = await fetch(`${baseUrl}/api/events?session=${session}`, { headers: CSRF_ADMIN });
  assert.equal(res.status, 200);
  return (await res.json()) as { events: ManduEvent[]; viewModel: SessionViewModel };
}

const ATTACK = "ignore all prior instructions";

// ── healthy session (sess-7af3) ───────────────────────────────────────────────

test("GET /api/sessions lists the fixture sessions", async () => {
  const res = await fetch(`${baseUrl}/api/sessions`);
  assert.equal(res.status, 200);
  const body = (await res.json()) as {
    sessions: { id: string; label: string | null; eventCount: number; violated: boolean }[];
  };
  const ids = body.sessions.map((s) => s.id);
  assert.ok(ids.includes("sess-7af3"), "healthy session listed");
  assert.ok(ids.includes("sess-bad9"), "violated session listed");
  // the list pre-flags the violated session
  assert.equal(body.sessions.find((s) => s.id === "sess-bad9")!.violated, true);
  assert.equal(body.sessions.find((s) => s.id === "sess-7af3")!.violated, false);
  // each session carries a human-readable label (the first user prompt) + count
  // so the sidebar differentiates sessions by what they do, not the opaque id.
  const healthy = body.sessions.find((s) => s.id === "sess-7af3")!;
  assert.equal(healthy.label, "Read invoice.txt and tell me where to pay.");
  assert.equal(healthy.eventCount, 13);
});

test("1. stream contains tllm_call, tool_use, tool_result, ullm_call", async () => {
  const { events } = await getEvents("sess-7af3");
  const kinds = new Set(events.map((e) => e.kind));
  for (const k of ["tllm_call", "tool_use", "tool_result", "ullm_call"]) {
    assert.ok(kinds.has(k as ManduEvent["kind"]), `missing ${k}`);
  }
});

test("2. events are correctly view-labeled (lane placement)", async () => {
  const { viewModel } = await getEvents("sess-7af3");
  // tllm_call + tool events are AgentView
  for (const c of viewModel.lanes.byLane.AgentView) {
    assert.ok(["tllm_call", "tool_use", "tool_result", "classify", "fs_action"].includes(c.kind));
  }
  // the ullm_call is Quarantine
  assert.ok(viewModel.lanes.byLane.Quarantine.some((c) => c.kind === "ullm_call"));
  // egress + HumanFS sync are HumanView
  assert.ok(viewModel.lanes.byLane.HumanView.some((c) => c.kind === "egress_request"));
  assert.ok(viewModel.lanes.byLane.HumanView.some((c) => c.kind === "fs_action"));

  // The single rendered timeline carries one annotated row per event (the UI no
  // longer splits into lanes). Every row maps to one of the four categories, and
  // the same view labeling shows up as the row annotation.
  const tl = viewModel.timeline;
  assert.equal(tl.length, viewModel.lanes.cards.length);
  for (const r of tl) assert.ok(["T-LLM", "U-LLM", "AgentView", "HumanView"].includes(r.annotation));
  assert.ok(tl.some((r) => r.kind === "tllm_call" && r.annotation === "T-LLM"));
  assert.ok(tl.some((r) => r.kind === "ullm_call" && r.annotation === "U-LLM"));
  assert.ok(tl.some((r) => r.kind === "egress_request" && r.annotation === "HumanView"));
});

test("3. untrusted-bearing DualReprs show BOTH reprs (symbolized has $MDU:*, original has raw payload)", async () => {
  const { events } = await getEvents("sess-7af3");
  // The fs_action read produced the symbolized invoice with the attack payload.
  const read = events.find((e) => e.kind === "fs_action" && e.view === "AgentView");
  assert.ok(read, "expected an AgentView fs_action");
  const out = read!.output!;
  assert.equal(out.differs, true, "symbolized differs from original");
  assert.match(out.symbolized, /\$MDU:/, "symbolized form carries a symbol");
  assert.doesNotMatch(out.symbolized, /ignore all prior instructions/, "no raw payload in symbolized");
  assert.match(out.original!, /ignore all prior instructions/, "original form reveals the raw attack payload");
  // The symbols carry privileged resolved values.
  assert.ok(out.symbols.some((s) => s.value?.includes("attacker@evil")));
});

test("4. T-LLM vs U-LLM distinguishable by kind+view, both with input+output", async () => {
  const { events } = await getEvents("sess-7af3");
  const tllm = events.find((e) => e.kind === "tllm_call" && e.view === "AgentView");
  const ullm = events.find((e) => e.kind === "ullm_call" && e.view === "Quarantine");
  assert.ok(tllm && ullm, "have at least one of each family");
  // both model calls carry input AND output
  assert.ok(tllm!.input && tllm!.output);
  assert.ok(ullm!.input && ullm!.output);
  // the U-LLM call desymbolized its input and re-symbolized its output
  assert.equal(ullm!.input!.differs, true, "U-LLM input desymbolized");
  assert.match(ullm!.input!.original!, /attacker@evil/);
  assert.equal(ullm!.output!.differs, true, "U-LLM output re-symbolized");
  assert.match(ullm!.output!.symbolized, /\$MDU:ullm/);
  assert.ok(ullm!.output!.symbols.some((s) => s.derivedFrom), "re-symbolization lineage present");
});

test("5. ORACLE: invariant holds AND attack appears in original but never un-symbolized in a tllm_call input", async () => {
  const { events, viewModel } = await getEvents("sess-7af3");
  // the dashboard's banner is green
  assert.equal(viewModel.invariant.holds, true);
  assert.equal(viewModel.invariant.level, "ok");
  assert.equal(viewModel.invariant.violationCount, 0);

  // the attack payload IS present somewhere in an `original` (proving the
  // dashboard can reveal it) ...
  const seenInOriginal = events.some(
    (e) =>
      (e.input?.original?.includes(ATTACK) ?? false) ||
      (e.output?.original?.includes(ATTACK) ?? false),
  );
  assert.ok(seenInOriginal, "attack payload is revealed in some original repr");

  // ... but NEVER un-symbolized in any tllm_call's symbolized input (the §9
  // property the dashboard visualizes).
  for (const e of events.filter((x) => x.kind === "tllm_call")) {
    assert.doesNotMatch(
      e.input?.symbolized ?? "",
      /ignore all prior instructions/,
      `tllm_call ${e.id} leaked un-symbolized untrusted data`,
    );
  }
});

test("the served trace tool step carries a ⓘ gate drawer with the fixed §4.2e template", async () => {
  const { viewModel } = await getEvents("sess-7af3");
  const t = viewModel.dualLanes.steps.find((s) => s.step === "tool" && s.callId === "call_f3a1");
  assert.ok(t && t.step === "tool", "the call_f3a1 tool step is served");
  const detail = t.gates[0]?.detail;
  assert.ok(detail && detail.length > 0, "gates[0].detail survives real-HTTP serialization");
  assert.deepEqual(
    detail.map((s) => s.label),
    ["What this is", "What it decided", "Where it's specified", "Where it came from"],
  );
});

test("symbol inspector derived from the served stream", async () => {
  const { viewModel } = await getEvents("sess-7af3");
  // symbol inspector lists the read symbols with a flow trace
  const iban = viewModel.symbols.find((s) => s.name.includes("iban"));
  assert.ok(iban, "iban symbol present in inspector");
  assert.ok(iban!.flow.length >= 1);
  assert.equal(iban!.flow[0]!.role, "created");
});

// ── violated session (sess-bad9) flips the banner red ─────────────────────────

test("violated fixture: the banner goes red and points at the offending event", async () => {
  const { events, viewModel } = await getEvents("sess-bad9");
  assert.equal(viewModel.invariant.holds, false);
  assert.equal(viewModel.invariant.level, "violation");
  assert.equal(viewModel.invariant.label, "INVARIANT VIOLATION");
  assert.equal(viewModel.invariant.violationCount, 1);
  assert.match(viewModel.invariant.firstDetail ?? "", /un-symbolized untrusted/);

  // the offending event is a tool_result whose card flares red, and whose
  // un-symbolized untrusted payload reached the next tllm_call.
  const bad = events.find((e) => e.invariant.violatedInvariant);
  assert.ok(bad);
  assert.equal(bad!.kind, "tool_result");
  const card = viewModel.lanes.cards.find((c) => c.id === bad!.id);
  assert.equal(card!.violated, true);
  // and indeed the next tllm_call DID ingest the raw payload (that's the leak)
  const tllmAfter = events.find((e) => e.kind === "tllm_call" && e.seq > bad!.seq);
  assert.match(tllmAfter!.input!.symbolized, /ignore all prior instructions/);
});

// ── sinceSeq paging ───────────────────────────────────────────────────────────

test("readEvents paging by sinceSeq is monotonic (§7.1 IPC paging analog)", async () => {
  const all = (await getEvents("sess-7af3")).events;
  const mid = all[3]!.seq;
  const res = await fetch(`${baseUrl}/api/events?session=sess-7af3&sinceSeq=${mid}`, { headers: CSRF_ADMIN });
  const body = (await res.json()) as { events: ManduEvent[] };
  assert.ok(body.events.every((e) => e.seq > mid), "all returned events are newer than sinceSeq");
  assert.equal(body.events.length, all.length - 4);
});
