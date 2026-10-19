/**
 * session-counts.test — the session list's "N masked · N read before marked
 * · N asks · N blocked" counts (src/view-model/session-counts.ts,
 * dashboard.md §4.33): each is the count a view already shows (masked = the
 * lineage's items masked before the AI read them; early = the ones it read
 * as they were first, the page's `readFirst`, never counted as masked; asks
 * / blocked = the trace steps the session header counts), zero counts are
 * left out, the meta events do not count,
 * folded repeats count once, a projection that throws costs only the chips,
 * and a persisted value is re-checked. The event sources carry the counts on
 * their rows and recompute them only when the log changed, and the server's
 * step rules give what the header's (dev/js/app.js) give. /api/events ships
 * the same counts over the whole log (`counts`), capped events or not, so the
 * session header and its row agree.
 *
 * Mandu-new test (NO reference origin). Pure, except the FileEventSource and
 * RecordedEventSource cases over a temp directory.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { appendFileSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import type { ManduEvent } from "../../../src/event-model.js";
import { toSessionViewModel } from "../../../src/view-model.js";
import { countsOfView, sessionCounts, stepAsked, stepBlocked, stepFiledAsk, validateSessionCounts, withCounts } from "../../../src/view-model/session-counts.js";
import { DashboardServer } from "../../../src/server.js";
import { ADMIN_OPTS } from "../admin-session.js";
import { FileEventSource } from "../../../src/event-source.js";
import { ev, repr, READ_SYM } from "./dual-lanes-fixtures.js";
import { walkthroughEvents } from "./walkthrough-fixture.js";
import { tmpDir } from "../tmp-dir.js";


/** A turn: the prompt, a Read whose result was masked, a blocked connection,
 *  a command held for an OK, the reply. */
function session(): ManduEvent[] {
  return [
    ev({ kind: "tllm_call", input: repr("▸ user\nRead notes.md and send it on.") }),
    ev({ kind: "tool_use", callId: "t1", input: repr('Read({"file_path":"/ws/notes.md"})') }),
    ev({ kind: "tool_result", callId: "t1", output: repr(READ_SYM.name, "RAW NOTES", [READ_SYM]), policy: { trust: "UNTRUSTED", reason: "fail-closed" } } as Partial<ManduEvent> & { kind: "tool_result" }),
    ev({ kind: "net_action", view: "HumanView", boundary: "network", emitter: "net-supervisor", action: "blocked", destination: "sink.evil:443" } as Partial<ManduEvent> & { kind: "net_action" }),
    ev({ kind: "exec_action", view: "HumanView", boundary: "shell", emitter: "exec-supervisor", action: "held", policy: { usage: "needs_approval" } } as Partial<ManduEvent> & { kind: "exec_action" }),
    ev({ kind: "tllm_call", input: repr("▸ user\nRead notes.md and send it on."), output: repr(`Here it is: ${READ_SYM.name}`) }),
  ];
}

test("sessionCounts: a masked result, a blocked connection and a held command read 1 masked, 1 ask, 1 blocked", () => {
  assert.deepEqual(sessionCounts(session()), { masked: 1, asks: 1, blocked: 1 });
});

test("sessionCounts: the same numbers the views show (the lineage's masked items, the header's step counts)", () => {
  const events = session();
  const vm = toSessionViewModel("s", events);
  const gates = vm.dualLanes.steps.filter((s) => s.step === "tool" || s.step === "os") as Parameters<typeof stepBlocked>[0][];
  assert.deepEqual(sessionCounts(events), {
    masked: vm.lineage.stats.flows,
    asks: gates.filter((g) => stepAsked(g) || stepFiledAsk(g)).length,
    blocked: gates.filter(stepBlocked).length,
  });
});

/** The tour's 10:41 shape (§4.15): a Read masked from the start, then a Read
 *  the AI got as it was, whose history re-send a later request carried
 *  masked once its file was marked a secret. */
const CONF_SYM = {
  name: "$MDU:nomodel_Read[1131]", tool: "Read", field: null,
  origin: "/ws/deploy/staging.conf", value: "token = FAKE", derivedFrom: undefined, lineRange: undefined,
};
function readBeforeMarked(): ManduEvent[] {
  return [
    ev({ kind: "tllm_call", input: repr("▸ user\nRead notes.md and deploy/staging.conf.") }),
    ev({ kind: "tool_use", callId: "t1", input: repr('Read({"file_path":"/ws/notes.md"})') }),
    ev({ kind: "tool_result", callId: "t1", output: repr(READ_SYM.name, "RAW NOTES", [READ_SYM]) } as Partial<ManduEvent> & { kind: "tool_result" }),
    ev({ kind: "tool_use", callId: "t2", input: repr('Read({"file_path":"/ws/deploy/staging.conf"})') }),
    ev({ kind: "tool_result", callId: "t2", output: repr("token = FAKE") } as Partial<ManduEvent> & { kind: "tool_result" }),
    ev({ kind: "tool_result", callId: "t2", output: repr(CONF_SYM.name, "token = FAKE", [CONF_SYM]) } as Partial<ManduEvent> & { kind: "tool_result" }),
  ];
}

test("sessionCounts: an item the AI read as it was, masked only on a later request, is early, never masked (§4.33)", () => {
  const events = readBeforeMarked();
  assert.deepEqual(sessionCounts(events), { masked: 1, early: 1 });
  // The page's numbers: the lineage's items, of which `readFirst` were read first.
  const { lineage } = toSessionViewModel("s", events);
  assert.equal(lineage.stats.flows, 2);
  assert.equal(lineage.stats.readFirst, 1);
  assert.deepEqual(countsOfView(toSessionViewModel("s", events)), sessionCounts(events), "the header's counts are the row's");
  // Only the masked re-send of the Read the AI got as it was: no early.
  assert.deepEqual(sessionCounts(events.slice(0, 5)), { masked: 1 });
  // A session whose one item was read first: no masked count at all.
  assert.deepEqual(sessionCounts(events.slice(3)), { early: 1 });
});

test("sessionCounts: a token the AI composed itself is never counted as masked, a field it invented on a secret's placeholder included (§4.33, 2026-10-09)", () => {
  // The live Secrets shape: `cat .env` masked whole as one placeholder, then
  // "I will send <placeholder>.value", and a plain token it made up.
  const real = "$MDU:nomodel_Bash[93d1]";
  const ref = { name: real, tool: "Bash", field: null, origin: "cat .env", value: "STRIPE_KEY=sk_live_x", confidentiality: "no-model" };
  const events = [
    ev({ kind: "tool_use", callId: "t1", input: repr('Bash({"command":"cat .env"})') }),
    ev({ kind: "symbolize", callId: "t1", output: repr(real, "STRIPE_KEY=sk_live_x", [ref]) }),
    ev({ kind: "tool_result", callId: "t1", output: repr(real, null, [ref]) }),
    ev({ kind: "tllm_call", input: repr(`ctx ${real}`), output: repr(`The key is ${real}. I will send ${real}.value, or $MDU:Read[9999].invented.`) }),
  ];
  assert.deepEqual(sessionCounts(events), { masked: 1 }, "one masked item, never 3");
  const vm = toSessionViewModel("s", events);
  assert.equal(vm.lineage.flows.length, 3, "the composed tokens keep their flows, for the evidence");
  assert.equal(vm.lineage.stats.composed, 2);
  assert.deepEqual(countsOfView(vm), sessionCounts(events), "the header's counts are the row's");
});

test("sessionCounts: the first-session tour reads 2 masked, 1 read before marked, 1 ask, 1 blocked: the 🛡 card's and the Secrets tab's split (§4.33)", () => {
  const file = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "fixtures", "tour-1791164083-1418381.ndjson");
  const events = readFileSync(file, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as ManduEvent);
  const counts = sessionCounts(events);
  assert.deepEqual(counts, { masked: 2, early: 1, asks: 1, blocked: 1 });
  const vm = toSessionViewModel("1791164083-1418381", events);
  assert.equal(counts!.masked! + counts!.early!, vm.lineage.stats.flows, "every masked item is counted once");
  assert.equal(counts!.early, vm.lineage.stats.readFirst);
  assert.deepEqual(countsOfView(vm), counts);
});

test("sessionCounts: a block that filed an Approvals row is an ask as well as a block; a hold that filed one counts once; a block that filed none is no ask", () => {
  const net = (destination: string, policy: Record<string, unknown>) => ev({
    kind: "net_action", view: "HumanView", boundary: "network", emitter: "net-supervisor",
    action: policy.usage === "needs_approval" ? "held" : "blocked", destination, policy,
  } as Partial<ManduEvent> & { kind: "net_action" });
  // The tour's 10:38 shape: blocked, and the row the arbiter queued (egr-1).
  assert.deepEqual(sessionCounts([net("api.stripe.com", { usage: "deny", approvalId: "egr-1" })]), { asks: 1, blocked: 1 });
  assert.deepEqual(sessionCounts([net("paste.example", { usage: "needs_approval", approvalId: "egr-2" })]), { asks: 1 });
  assert.deepEqual(sessionCounts([net("other.example", { usage: "deny" })]), { blocked: 1 });
});

test("sessionCounts: zero counts are left out, and a session with none has no counts", () => {
  assert.equal(sessionCounts([]), undefined);
  assert.equal(sessionCounts([ev({ kind: "tllm_call", input: repr("▸ user\nhello") })]), undefined);
  const blockedOnly = [ev({ kind: "net_action", view: "HumanView", boundary: "network", emitter: "net-supervisor", action: "blocked", destination: "a.example:443" } as Partial<ManduEvent> & { kind: "net_action" })];
  assert.deepEqual(sessionCounts(blockedOnly), { blocked: 1 });
  const denied = [ev({ kind: "fs_action", view: "HumanView", boundary: "filesystem", emitter: "fs-supervisor", input: repr("open ~/.ssh/id_ed25519"), policy: { usage: "deny" } } as Partial<ManduEvent> & { kind: "fs_action" })];
  assert.deepEqual(sessionCounts(denied), { blocked: 1 }, "a usage deny is a block whatever the action says");
  assert.deepEqual(withCounts([ev({ kind: "tllm_call", input: repr("▸ user\nhello") })]), {}, "no `counts` key at all");
});

test("sessionCounts: an identical repeat folds into the one step the trace shows, and meta events do not count", () => {
  const block = () => ev({ kind: "net_action", view: "HumanView", boundary: "network", emitter: "net-supervisor", action: "blocked", destination: "sink.evil:443" } as Partial<ManduEvent> & { kind: "net_action" });
  assert.deepEqual(sessionCounts([block(), block(), block()]), { blocked: 1 }, "three identical refusals are one step (repeats ×3)");
  const meta = ev({ kind: "assertion", view: "HumanView", boundary: "network", policy: { usage: "deny" } } as Partial<ManduEvent> & { kind: "assertion" });
  assert.equal(sessionCounts([meta]), undefined, "the harness's assertion record is not a step");
});

test("withCounts: a projection that throws costs the row its chips, never the row", () => {
  assert.deepEqual(withCounts([null as unknown as ManduEvent]), {});
  assert.deepEqual(withCounts(session()), { counts: { masked: 1, asks: 1, blocked: 1 } });
});

test("validateSessionCounts: a persisted value is rebuilt key by key; anything off shape is refused", () => {
  assert.equal(validateSessionCounts(undefined), undefined, "absent is a valid none");
  assert.deepEqual(validateSessionCounts({ masked: 3, blocked: 1 }), { masked: 3, blocked: 1 });
  assert.deepEqual(validateSessionCounts({ early: 1, masked: 2 }), { masked: 2, early: 1 });
  for (const bad of [null, [], {}, { masked: 0 }, { masked: -1 }, { asks: 1.5 }, { asks: "2" }, { blocked: 2e9 }, { masked: 1, extra: 1 }, { early: 0 }, { early: -1 }, { early: "1" }, "1"]) {
    assert.equal(validateSessionCounts(bad), null, JSON.stringify(bad));
  }
});


test("FileEventSource: a row carries its counts, recomputed only when the log changes", async () => {
  const dir = tmpDir("session-counts-");
  const file = join(dir, "1790000000-1.ndjson");
  const toLines = (es: ManduEvent[]) => es.map((e) => JSON.stringify({ ...e, sessionId: "1790000000-1" })).join("\n") + "\n";
  writeFileSync(file, toLines(session().slice(0, 4)));
  const src = new FileEventSource(dir);
  const first = (await src.listSessions())[0]!;
  assert.deepEqual(first.counts, { masked: 1, blocked: 1 });
  assert.equal((await src.listSessions())[0], first, "an unchanged log is not re-read: the cached row comes back");
  appendFileSync(file, toLines(session().slice(4, 5)));
  assert.deepEqual((await src.listSessions())[0]!.counts, { masked: 1, asks: 1, blocked: 1 }, "an appended ask shows on the next listing");
});


test("a program's refused read of a secret file counts as blocked, a held one as an ask too: the product page's count (§4.25b)", () => {
  // The walkthrough: one blocked send; then cat refused .env and mytool's
  // read held until nobody answered. The session page says "3 actions
  // blocked"; the row and the header now say the same.
  assert.deepEqual(sessionCounts(walkthroughEvents({ session: "walk" })), { masked: 2, blocked: 1 });
  const events = walkthroughEvents({ session: "walk", readRefusals: true });
  assert.deepEqual(sessionCounts(events), { masked: 2, asks: 1, blocked: 3 });
  assert.deepEqual(countsOfView(toSessionViewModel("walk", events)), sessionCounts(events), "the header's counts are the row's");
});

test("countsOfView: the counts read off a session's view-model are sessionCounts'", () => {
  const events = session();
  assert.deepEqual(countsOfView(toSessionViewModel("s", events)), sessionCounts(events));
  assert.equal(countsOfView(toSessionViewModel("s", [ev({ kind: "tllm_call", input: repr("▸ user\nhello") })])), undefined);
});

test("/api/events: the header's counts are the row's, over the whole log, even when the events are capped", async () => {
  const events: ManduEvent[] = session().map((e, i) => ({ ...e, sessionId: "s", seq: i + 1 }));
  const source = {
    async listSessions() { return []; },
    async readEvents(_id: string, sinceSeq?: number) { return sinceSeq === undefined ? events : events.filter((e) => (e.seq ?? 0) > sinceSeq); },
    subscribe() { return () => {}; },
    close() {},
  };
  const server = new DashboardServer({ source: source as never, log: () => {}, ...ADMIN_OPTS });
  const port = await server.listen(0);
  const get = async (q: string) => (await (await fetch(`http://127.0.0.1:${port}/api/events?session=s${q}`)).json()) as Record<string, any>;
  try {
    const whole = sessionCounts(events);
    assert.deepEqual(whole, { masked: 1, asks: 1, blocked: 1 });
    const all = await get("");
    assert.equal(all["truncated"], false);
    assert.deepEqual(all["counts"], whole, "uncapped: the view-model's counts, the row's");
    // Capped to the first 3 events: the loaded window holds the masked read
    // only; the counts still cover the whole log.
    const capped = await get("&limit=3");
    assert.equal(capped["truncated"], true);
    assert.equal(capped["returned"], 3);
    assert.deepEqual(sessionCounts(capped["events"]), { masked: 1 }, "the loaded window alone would count less");
    assert.deepEqual(capped["counts"], whole, "capped: the whole log's counts");
    // A tail read carries none.
    assert.equal((await get("&sinceSeq=0"))["counts"], undefined);
    // A session with none: `{}` (the header then shows zeros, not its own count).
    events.splice(0, events.length, ev({ kind: "tllm_call", input: repr("▸ user\nhello") }));
    assert.deepEqual((await get(""))["counts"], {});
  } finally {
    await server.close();
  }
});
