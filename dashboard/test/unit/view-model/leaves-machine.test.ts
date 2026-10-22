/**
 * leaves-machine.test — the moments data leaves this machine (dashboard.md
 * §4.2f, §4.25b). Contracts:
 *   - a net send's `resolved` (forwarded) / `withheld` (blocked) symbols ride
 *     the OS step as `carried`, in both wire shapes, and a fold never merges
 *     two sends that carried different items;
 *   - such a send is an inline `action` row, never Background; a send that
 *     carried nothing still folds;
 *   - the product story tells it: "Sent a request to X with your secret Y
 *     filled in" (outcome "sent"), "Mandu blocked a request to X that carried
 *     your secret Y", named by the variable or key, never the token; the
 *     turn's summary names the same secrets;
 *   - a send to a company's own API host, while its keys go there without
 *     asking, adds after the unchanged note that a key it issued "may" go
 *     there without asking you, linking Rules › Built-in protections; never
 *     for another host, a block, a wait, or the switch off or not read.
 *
 * Axes: none (pure projections over recorded events).
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { toDualLanes } from "../../../src/view-model/dual-lanes.js";
import type { DualOsStep } from "../../../src/view-model/dual-lanes.js";
import { buildAgentPage, osSentence, turnSummary } from "../../../src/view-model/agent-page.js";
import { toSessionViewModel } from "../../../src/view-model.js";
import type { ManduEvent } from "../../../src/event-model.js";
import { walkthroughEvents, SESSION, GH } from "./walkthrough-fixture.js";

const words = (parts: { kind: string; text: string }[]) => parts.map((p) => (p.kind === "masked" ? `[${p.text}]` : p.text)).join("");
const osSteps = (events: ManduEvent[]) => toDualLanes(events).steps.filter((s): s is DualOsStep => s.step === "os");

test("a send's resolved / withheld symbols ride the OS step as `carried`, both wire shapes", () => {
  const steps = osSteps(walkthroughEvents());
  const gh = steps.find((s) => s.target === "api.github.com")!;
  assert.deepEqual(gh.carried, [GH]);
  assert.deepEqual(steps.find((s) => s.target === "collector.evil.example")!.carried, [GH]);
  assert.equal(steps.find((s) => s.target === "api.anthropic.com")!.carried, undefined, "a send that carried nothing has no field");
  // The refuse body's shape: {symbol}[].
  const obj = walkthroughEvents().map((e) => (e.kind === "net_action" && (e as unknown as { action: string }).action === "blocked" ? { ...e, withheld: [{ symbol: GH, requiresApproval: true }] } : e));
  assert.deepEqual(osSteps(obj as ManduEvent[]).find((s) => s.target === "collector.evil.example")!.carried, [GH]);
});

test("two consecutive sends that carried different items stay two steps", () => {
  const base = walkthroughEvents().find((e) => e.kind === "net_action" && (e as unknown as { destination: string }).destination === "paste.example")!;
  const a = { ...base, id: "n1", seq: 100 } as ManduEvent;
  const b = { ...base, id: "n2", seq: 101, resolved: [GH] } as unknown as ManduEvent;
  const c = { ...base, id: "n3", seq: 102, resolved: [GH] } as unknown as ManduEvent;
  const steps = osSteps([a, b, c]);
  assert.equal(steps.length, 2, "PASTE_KEY then GITHUB_TOKEN twice: two steps");
  assert.equal(steps[1]!.repeats, 2);
});

test("a send that carried items is an inline action row; one that carried nothing stays Background", () => {
  const vm = toSessionViewModel(SESSION, walkthroughEvents());
  const turn = vm.paired.turns.find((t) => t.inputId)!;
  const actionIds = turn.rows.filter((r) => r.row === "action").map((r) => r.stepId);
  const byId = new Map(vm.dualLanes.steps.map((s) => [s.id, s]));
  const targets = actionIds.map((id) => (byId.get(id) as DualOsStep).target);
  assert.deepEqual(targets, ["api.github.com", "paste.example", "collector.evil.example"]);
  const conn = vm.paired.turns.flatMap((t) => t.background).filter((b) => b.category === "connections");
  assert.deepEqual(conn.flatMap((b) => b.labels), ["api.anthropic.com"], "the model API call carried nothing: still background");
});

test("the product story: sent with your secret filled in, a blocked send that carried it; no token", () => {
  const page = buildAgentPage({ session: null, id: SESSION, vm: toSessionViewModel(SESSION, walkthroughEvents()), cwd: null, waiting: [] });
  const steps = page.story.flatMap((t) => t.steps).filter((s) => s.kind === "action" && s.icon === "web");
  const said = steps.map((s) => (s.kind === "action" ? `${s.outcome}: ${words(s.sentence)} | ${s.note}` : ""));
  assert.deepEqual(said, [
    "sent: Sent a request to api.github.com with your secret GITHUB_TOKEN filled in | The real value left this machine, to a destination allowed to receive it.",
    "sent: Sent a request to paste.example with your secret PASTE_KEY filled in | The real value left this machine, to a destination allowed to receive it.",
    "blocked: Mandu blocked a request to collector.evil.example that carried your secret GITHUB_TOKEN | The request never left this machine.",
  ]);
  // The turn's summary names them too, with the steps' labels (as code), never a token.
  assert.equal(page.story[0]!.summary, "Mandu blocked 1 request that carried your secret GITHUB_TOKEN and hid your secret PASTE_KEY from the AI. " +
    "2 requests left this machine with your secrets GITHUB_TOKEN and PASTE_KEY filled in, each to a destination allowed to receive it.");
  assert.deepEqual(page.story[0]!.summaryParts!.filter((p) => p.kind === "code").map((p) => p.text), ["GITHUB_TOKEN", "PASTE_KEY", "GITHUB_TOKEN", "PASTE_KEY"]);
  assert.equal(page.story[0]!.tone, "blocked", "a block still sets the tone; a send does not soften it");
  assert.doesNotMatch(JSON.stringify(page.story), /\$MDU:/);
});

test("osSentence: a waiting send, an unnamed secret, a masked item, and the plain cases unchanged", () => {
  const os = (over: Partial<DualOsStep>) => ({ kind: "net_action" as const, title: "net_action · forwarded h.example", action: "forwarded", usage: null, target: "h.example", violated: false, ...over });
  const secret = () => ({ secret: true, name: null });
  assert.equal(words(osSentence(os({ carried: ["$MDU:nomodel_Read[aaaa]"] }), secret).sentence), "Sent a request to h.example with a secret of yours filled in");
  const w = osSentence(os({ action: "queued", title: "net_action · queued h.example", usage: "needs_approval", carried: ["$MDU:x[aaaa]", "$MDU:y[bbbb]"] }));
  assert.equal(w.outcome, "waiting");
  assert.equal(words(w.sentence), "Wants to send 2 masked items to h.example");
  assert.equal(words(osSentence(os({ carried: ["$MDU:nomodel_Env[aaaa].A", "$MDU:nomodel_Env[bbbb].B"] }), (n) => ({ secret: true, name: n.split(".").pop()! })).sentence),
    "Sent a request to h.example with your secrets A and B filled in");
  // No carried items: as before.
  assert.equal(words(osSentence(os({})).sentence), "Connected to h.example");
  assert.equal(osSentence(os({ action: "blocked" })).note, "The request never left this machine.");
  // A turn of only sends reads as such, in a plain tone.
  const s = turnSummary([{ kind: "action", id: "a", ts: "", icon: "web", sentence: [], outcome: "sent", note: null, split: null }]);
  assert.equal(s.summary, "1 request left this machine with a real value filled in, to a destination allowed to receive it.");
  assert.equal(s.tone, "sent");
});

test("a send to a company's own API says why it did not ask, after the unchanged note, while the company's keys go without asking", () => {
  const vm = toSessionViewModel(SESSION, walkthroughEvents());
  const sent = (issuerBindings?: { read: true; raw: unknown } | { read: false }) => buildAgentPage({ session: null, id: SESSION, vm, cwd: null, waiting: [], ...(issuerBindings ? { issuerBindings } : {}) })
    .story.flatMap((t) => t.steps).filter((s): s is Extract<typeof s, { kind: "action" }> => s.kind === "action" && s.icon === "web");
  const NOTE = "The real value left this machine, to a destination allowed to receive it.";
  const on = sent({ read: true, raw: undefined });
  const gh = on.find((s) => words(s.sentence).startsWith("Sent a request to api.github.com"))!;
  assert.equal(gh.outcome, "sent");
  assert.equal(gh.note, `${NOTE} api.github.com is GitHub's own API: a key GitHub issued may go there without asking you. Built-in protections in Rules lists these, and says how to have them ask.`);
  assert.ok(gh.note!.startsWith(NOTE), "the note before it is unchanged");
  assert.equal(words(gh.noteParts!), gh.note, "the parts are the note's words");
  assert.deepEqual(gh.noteParts!.filter((p) => p.kind === "code").map((p) => p.text), ["api.github.com"]);
  assert.deepEqual(gh.noteParts!.filter((p) => p.rules), [{ kind: "text", text: "Built-in protections", rules: "built-in" }], "one link, to Rules' card");
  assert.doesNotMatch(gh.note!, /because|the reason|allowed it/i, "it never claims to be why this send went");
  // paste.example is no company's API; the blocked send says nothing of it.
  const paste = on.find((s) => words(s.sentence).startsWith("Sent a request to paste.example"))!;
  assert.equal(paste.note, NOTE);
  assert.equal(paste.noteParts, undefined);
  assert.equal(on.find((s) => s.outcome === "blocked")!.noteParts, undefined);
  // The switch off, GitHub off, not read, or not given: the note alone.
  for (const reading of [{ read: true, raw: false } as const, { read: true, raw: { issuers_off: ["github"] } } as const, { read: false } as const, undefined]) {
    const s = sent(reading).find((x) => words(x.sentence).startsWith("Sent a request to api.github.com"))!;
    assert.equal(s.note, NOTE, JSON.stringify(reading));
    assert.equal(s.noteParts, undefined);
  }
  // The turn's summary is the same with or without it.
  const summary = (r?: { read: true; raw: unknown }) => buildAgentPage({ session: null, id: SESSION, vm, cwd: null, waiting: [], ...(r ? { issuerBindings: r } : {}) }).story[0]!.summary;
  assert.equal(summary({ read: true, raw: undefined }), summary());
});

test("osSentence: a blocked or waiting send to a company's own API has no such sentence", () => {
  const on = { read: true, raw: undefined } as const;
  const os = (over: Partial<DualOsStep>) => ({ kind: "net_action" as const, title: "net_action · forwarded api.github.com", action: "forwarded", usage: null, target: "api.github.com", violated: false, carried: ["$MDU:x[aaaa]"], ...over });
  assert.ok(osSentence(os({}), undefined, true, on).noteParts, "sent: the sentence");
  const blocked = osSentence(os({ action: "blocked" }), undefined, true, on);
  assert.equal(blocked.note, "The request never left this machine.");
  assert.equal(blocked.noteParts, undefined);
  const waiting = osSentence(os({ action: "queued", usage: "needs_approval" }), undefined, true, on);
  assert.equal(waiting.note, "Waiting for your OK.");
  assert.equal(waiting.noteParts, undefined);
  // A connection that carried nothing is not a send of a key.
  assert.equal(osSentence(os({ carried: undefined }), undefined, true, on).note, null);
});
