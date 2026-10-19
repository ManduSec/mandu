/**
 * dual-lanes-detail.test.ts — unit tests for the §4.2e ⓘ detail drawers on
 * thin trace entries (DualGate.detail / DualOsStep.detail) and the fs-sync
 * symbol-birth batch card ("symbolize · workspace sync").
 *
 * Contract under test (docs/design/ui/dashboard.md §4.2e):
 *   - every drawer renders the fixed section template (What this is / What it
 *     decided / Where it's specified / Where it came from; the birth card's
 *     second slot is "What it did" — a mint decides nothing);
 *   - facts are lowercase `key: value` lines, absence stated in words
 *     ("method: not recorded"), symbolized spellings only;
 *   - `ms` items stay epoch NUMBERS (the shell formats);
 *   - callId-null fs-sync symbolize events become ONE batch card per
 *     consecutive run of births, a name minting in exactly one step per
 *     session; folds keep the FIRST detail.
 *
 * Run: npm run test:unit
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { toDualLanes } from "../../../src/view-model.js";
import type { DetailSection } from "../../../src/view-model/detail.js";

import { ev, repr } from "./dual-lanes-fixtures.js";

const TEMPLATE = ["What this is", "What it decided", "Where it's specified", "Where it came from"];
const BIRTH_TEMPLATE = ["What this is", "What it did", "Where it's specified", "Where it came from"];

const labelsOf = (d: DetailSection[]): string[] => d.map((s) => s.label);
const textsOf = (d: DetailSection[]): string[] => d.flatMap((s) => s.items.map((i) => i.text));

const birthSym = (name: string, field: string) => ({
  name, tool: "Read", field, origin: `/home/u/ws/${field}`, value: "RAW CONTENT",
});

/** A callId-null fs-sync mint (the workspace seed / eager sync birth shape). */
const birthEv = (name: string, field: string) =>
  ev({
    kind: "symbolize", emitter: "fs-sync", boundary: "filesystem", view: "AgentView",
    output: repr(name, null, [birthSym(name, field)]),
  });

test("1. an uncorrelated fs-sync birth renders one os card with newSymbols + a mint line", () => {
  const e = birthEv("$MDU:Read[17ac].notes.md", "notes.md");
  const dv = toDualLanes([e]);
  const os = dv.steps.filter((s) => s.step === "os");
  assert.equal(os.length, 1, "the birth is a trace card, not dropped");
  const card = os[0]!;
  if (card.step !== "os") return;
  assert.equal(card.kind, "symbolize");
  assert.equal(card.title, "symbolize · workspace sync");
  assert.equal(card.note, null);
  assert.equal(card.id, "os:" + e.id, "id = os: + the first event's id");
  assert.deepEqual(card.newSymbols, ["$MDU:Read[17ac].notes.md"]);
  assert.ok(card.detail, "the birth card carries a drawer");
  assert.deepEqual(labelsOf(card.detail!), BIRTH_TEMPLATE, "birth uses 'What it did' in the second slot");
  const texts = textsOf(card.detail!);
  assert.ok(
    texts.some((t) => /\$MDU:Read\[17ac\]\.notes\.md ← notes\.md/.test(t)),
    `mint line '<name> ← <field>' present, got: ${texts.join(" | ")}`,
  );
  assert.ok(
    texts.some((t) => /no rule reference recorded — a mint, not a gate decision/.test(t)),
    "a mint cites no rule",
  );
});

test("2. three consecutive births batch into ONE card (repeats stays 1); a re-emission folds away", () => {
  const events = [
    birthEv("$MDU:Read[17ac].notes.md", "notes.md"),
    birthEv("$MDU:Read[2b3c].plan.md", "plan.md"),
    birthEv("$MDU:Read[4d5e].todo.md", "todo.md"),
    // A re-emission of an already-born name adds nothing and folds away.
    birthEv("$MDU:Read[17ac].notes.md", "notes.md"),
  ];
  const dv = toDualLanes(events);
  const os = dv.steps.filter((s) => s.step === "os");
  assert.equal(os.length, 1, "one batch card per consecutive run of births");
  const card = os[0]!;
  if (card.step !== "os") return;
  assert.equal(card.repeats, 1, "N different files ≠ N identical actions");
  assert.equal(card.newSymbols?.length, 3);
  const did = card.detail!.find((s) => s.label === "What it did")!;
  assert.equal(did.items.length, 3, "one ← line per fresh mint");
  for (const it of did.items) assert.match(it.text, / ← /);
  assert.equal(dv.collapsedCount, 1, "the re-emission bumps collapsedCount");
});

test("3. a name mints in exactly ONE step across the os/tool divide, in either order", () => {
  const name = "$MDU:Read[17ac].notes.md";
  const sym = birthSym(name, "notes.md");
  // NOTE: ev() stamps ts from a shared counter at CONSTRUCTION time, and
  // toDualLanes orders by ts — so each sub-case constructs its events in the
  // intended chronological order.
  const corr = (callId: string) => [
    ev({ kind: "tool_use", callId, input: repr('Read({"file_path":"notes.md"})') }),
    ev({ kind: "symbolize", callId, output: repr(name, null, [sym]) }),
    ev({ kind: "tool_result", callId, output: repr(name, null, [sym]), policy: { trust: "UNTRUSTED" } }),
  ];
  const minters = (events: Parameters<typeof toDualLanes>[0]) =>
    toDualLanes(events).steps.filter(
      (s) =>
        (s.step === "tool" && s.newSymbols.includes(name)) ||
        (s.step === "os" && (s.newSymbols ?? []).includes(name)),
    );
  // Birth first: the os card owns the mint, the tool step does not re-mint.
  const birthFirst = minters([birthEv(name, "notes.md"), ...corr("c1")]);
  assert.equal(birthFirst.length, 1);
  assert.equal(birthFirst[0]!.step, "os");
  // Correlated first: the tool step owns the mint, the later birth folds away.
  const corrFirst = minters([...corr("c2"), birthEv(name, "notes.md")]);
  assert.equal(corrFirst.length, 1);
  assert.equal(corrFirst[0]!.step, "tool");
});

test("4. a correlated exec gate carries the fixed-template drawer with the event's facts", () => {
  const events = [
    ev({ kind: "tool_use", callId: "c1", input: repr('Bash({"command":"cat notes"})') }),
    ev({
      kind: "exec_action", callId: "c1", boundary: "shell", emitter: "anthropic-proxy",
      input: repr("Bash.command"), output: repr("BLOCKED → exit 77"),
      policy: {
        usage: "deny", shell: "AgentShell", reason: "untrusted symbol used as command text",
        ruleRef: { source: "rule", id: "exec:no-symbol-in-command" },
      },
    }),
  ];
  const t = toDualLanes(events).steps.find((s) => s.step === "tool")!;
  if (t.step !== "tool") return;
  assert.equal(t.gates.length, 1);
  const detail = t.gates[0]!.detail;
  assert.ok(detail, "the gate carries a drawer");
  assert.deepEqual(labelsOf(detail!), TEMPLATE);
  const texts = textsOf(detail!);
  assert.ok(texts.some((x) => /BLOCKED → exit 77/.test(x)), "result fact present");
  assert.ok(texts.some((x) => /shell: AgentShell/.test(x)), "shell fact present");
  assert.ok(texts.some((x) => /exec:no-symbol-in-command/.test(x)), "ruleRef id cited");
  for (const sec of detail!) {
    for (const it of sec.items) {
      if ("ms" in it) assert.equal(typeof it.ms, "number", "ms items stay epoch numbers");
    }
  }
});

test("5. an uncorrelated net card normalizes BOTH withheld wire shapes; absence stated in words", () => {
  const events = [
    // string[] shape (net-proxy proxy.ts) — and no method recorded.
    ev({
      kind: "net_action", boundary: "network", emitter: "net-supervisor",
      ...({
        action: "blocked", destination: "notes-sink.test",
        reason: "egress withheld 1 symbol(s) → block (fail-closed)",
        withheld: ["$MDU:Read[17ac].notes.md"],
      } as object),
    }),
    // {symbol}[] shape (the refuse body).
    ev({
      kind: "net_action", boundary: "network", emitter: "net-supervisor",
      ...({
        action: "blocked", destination: "other-sink.test",
        withheld: [{ symbol: "$MDU:Read[9b8a]" }],
      } as object),
    }),
  ];
  const os = toDualLanes(events).steps.filter((s) => s.step === "os");
  assert.equal(os.length, 2);
  const [a, b] = os;
  if (a!.step !== "os" || b!.step !== "os") return;
  const aTexts = textsOf(a!.detail!);
  const bTexts = textsOf(b!.detail!);
  assert.ok(
    aTexts.some((t) => t === "withheld: $MDU:Read[17ac].notes.md — its value never left the machine"),
    "string[] wire shape normalizes",
  );
  assert.ok(
    bTexts.some((t) => t === "withheld: $MDU:Read[9b8a] — its value never left the machine"),
    "{symbol}[] wire shape normalizes",
  );
  assert.ok(aTexts.some((t) => /method: not recorded/.test(t)), "absent method stated in words");
  assert.deepEqual(labelsOf(a!.detail!), TEMPLATE);
});

test("6. an uncorrelated path_rewrite drawer carries BOTH path spellings", () => {
  const events = [
    ev({
      kind: "path_rewrite",
      rewrite: { direction: "reverse", tool: null, field: "content", human: "/home/u/ws/a.md", agent: "/tmp/agentview/a.md" },
    }),
  ];
  const os = toDualLanes(events).steps.find((s) => s.step === "os")!;
  if (os.step !== "os") return;
  assert.ok(os.detail, "the uncorrelated path_rewrite card gets a drawer");
  const texts = textsOf(os.detail!);
  assert.ok(texts.includes("HumanView spelling: /home/u/ws/a.md"));
  assert.ok(texts.includes("AgentView twin: /tmp/agentview/a.md"));
  assert.ok(texts.includes("field: content"));
});

test("7. the reply-filter card's drawer lists the resolved symbols", () => {
  const events = [
    ev({
      kind: "desymbolize", emitter: "reply-filter", boundary: "model_context", view: "HumanView",
      input: repr("frame text citing $MDU:Read[1a9f] for the human"),
    }),
  ];
  const os = toDualLanes(events).steps.find((s) => s.step === "os")!;
  if (os.step !== "os") return;
  assert.equal(os.title, "user reply · reply-filter");
  const texts = textsOf(os.detail!);
  assert.ok(
    texts.includes("resolved: $MDU:Read[1a9f] → original, in the human's terminal only"),
    `resolved line present, got: ${texts.join(" | ")}`,
  );
});

test("8. a fold keeps the FIRST card's detail (3 identical net_actions → 1 card, repeats 3)", () => {
  // `method` is NOT in the fold key (kind, title, note) — vary it to prove the
  // first event's detail survives the fold.
  const mk = (method: string) =>
    ev({
      kind: "net_action", boundary: "network", emitter: "net-supervisor",
      ...({ action: "passthrough", destination: "api.anthropic.com:443", method } as object),
    });
  const dv = toDualLanes([mk("CONNECT"), mk("POST"), mk("GET")]);
  const os = dv.steps.filter((s) => s.step === "os");
  assert.equal(os.length, 1);
  const card = os[0]!;
  if (card.step !== "os") return;
  assert.equal(card.repeats, 3);
  assert.equal(dv.collapsedCount, 2);
  assert.ok(card.detail, "the folded card keeps a drawer");
  const texts = textsOf(card.detail!);
  assert.ok(texts.includes("method: CONNECT"), "the FIRST event's facts survive the fold");
  assert.ok(!texts.includes("method: POST"), "later repeats never overwrite the detail");
});

test("9. a CLAIMED event's drawer says so: the recorder is the sender's word (arbiter-human-plane.md §10.2)", () => {
  const mk = (claimed: boolean) => ev({
    kind: "net_action", boundary: "network", emitter: "net-supervisor",
    ...({ action: "blocked", destination: "sink.test", ...(claimed ? { claimed: true } : {}) } as object),
  });
  const card = (claimed: boolean) => toDualLanes([mk(claimed)]).steps.find((s) => s.step === "os")!;
  const claimedCard = card(true);
  const plainCard = card(false);
  if (claimedCard.step !== "os" || plainCard.step !== "os") return;
  const texts = textsOf(claimedCard.detail!);
  assert.ok(texts.some((t) => t.startsWith("CLAIMED: sent on a channel the agent's own programs can reach")), texts.join("\n"));
  assert.ok(texts.includes("recorded by: net-supervisor (claimed)"));
  assert.ok(!textsOf(plainCard.detail!).some((t) => /CLAIMED|claimed/.test(t)), "a believed event carries no mark");
  assert.deepEqual(labelsOf(claimedCard.detail!), TEMPLATE);
});
