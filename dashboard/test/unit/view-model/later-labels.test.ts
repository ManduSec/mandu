/**
 * later-labels.test — a file the AI read as it was, labelled a secret after
 * that read, which the session's own record never learned (dashboard.md
 * §4.25b, *Labelled after the session*). Contracts:
 *   - only a Read (any agent's) whose result reached the AI with nothing
 *     masked counts, by its file placed absolute (the recorded origin, or
 *     its argument under the session's folder or `~`);
 *   - a read counts only strictly before its file's label time; a level
 *     the AI may read (`any-model`, `public`) is no such label;
 *   - a label's time is the recorded change that wrote its rule as it
 *     stands (`lock:<path>` in the change log), or a Rules page label's own
 *     time; no record, a removed row or a later unrecorded edit: no time;
 *   - the session page's Read step says the AI got it as it was and when it
 *     was marked (outcome `raw`), the turn's summary names the file;
 *   - *Your secrets* gets an entry for the file with no placeholder (no
 *     `ref`), no send lines, the read and the label times, never "never
 *     the real value"; it counts as read before it was marked;
 *   - a file a later read already masked (an entry with a token) learns
 *     the earlier read instead: "before it was marked", never "never";
 *   - no labels given: the page is as before.
 *
 * Axes: none (a pure projection; the mode is read from the recorded events).
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { buildAgentPage, type AgentPageVM } from "../../../src/view-model/agent-page.js";
import { hidesFromAi, labelSince, labelTimes, laterLabels, plainReads, readPath, readStepPath, type LabelTime } from "../../../src/view-model/later-labels.js";
import type { ManduEvent } from "../../../src/event-model.js";
import { toSessionViewModel } from "../../../src/view-model.js";
import type { PolicyChangeRow } from "../../../src/view-model/policy-proposals.js";
import type { PathLevelsEntryWire } from "../../../src/view-model/file-browser.js";

const SESSION = "later-1";
const FILE = "/home/dev/mandu-try/deploy/staging.conf";
const T0 = Date.parse("2026-10-12T10:40:00.000Z");
const iso = (ms: number) => new Date(ms).toISOString();
const words = (parts: { kind: string; text: string }[]) => parts.map((p) => (p.kind === "time" ? `<${p.text}>` : p.text)).join("");
const TOKEN = "$MDU:nomodel_Read[a1b2].token";

/** A session that reads `path` with Claude Code's Read and replies; its
 *  result reaches the AI as it was, or `masked` with a placeholder. */
function sessionEvents(opts: { path?: string; masked?: boolean; mode?: "secrets" | "off"; secondMaskedRead?: boolean } = {}): ManduEvent[] {
  const out: ManduEvent[] = [];
  let seq = 0;
  const dr = (symbolized: string, original: string | null = null, symbols: unknown[] = []) => ({ symbolized, original, differs: original !== null && original !== symbolized, symbols });
  const ev = (kind: string, f: Record<string, unknown> = {}): void => {
    out.push({
      id: `${SESSION}-${String(seq).padStart(3, "0")}`, sessionId: SESSION, turn: 0, ts: iso(T0 + seq * 1000), seq,
      callId: null, parentId: null, kind, view: "AgentView", boundary: "model_context", emitter: "anthropic-proxy",
      input: null, output: null, invariant: { violatedInvariant: false }, ...f,
    } as unknown as ManduEvent);
    seq++;
  };
  const path = opts.path ?? FILE;
  const user = "▸ user\nWhat is in deploy/staging.conf?";
  ev("launch_posture", { view: "HumanView", boundary: "shell", emitter: "launcher", protection: { mode: opts.mode ?? "secrets", integrity: false, reported: true } });
  ev("tllm_call", { input: dr(user), output: dr(`→ Read(${JSON.stringify({ file_path: path })})`) });
  ev("tool_use", { callId: "c1", input: dr(`Read(${JSON.stringify({ file_path: path })})`) });
  const raw = 'token = "ghp_later"';
  ev("tool_result", {
    callId: "c1",
    output: opts.masked
      ? dr(`token = "${TOKEN}"`, raw, [{ name: TOKEN, tool: "Read", field: "token", origin: FILE, value: null, confidentiality: "no-model" }])
      : dr(raw),
    policy: { trust: "TRUSTED", reason: "integrity axis OFF", ...(opts.masked ? { confidentiality: "no-model" } : {}) },
  });
  ev("tllm_call", { turn: 1, input: dr(`${user}\n\n▸ tool_result\n${opts.masked ? TOKEN : raw}`), output: dr("It holds one token.") });
  if (opts.secondMaskedRead) {
    ev("tllm_call", { turn: 2, input: dr("▸ user\nAgain?"), output: dr(`→ Read(${JSON.stringify({ file_path: path })})`) });
    ev("tool_use", { turn: 2, callId: "c2", input: dr(`Read(${JSON.stringify({ file_path: path })})`) });
    ev("tool_result", {
      turn: 2, callId: "c2",
      output: dr(`token = "${TOKEN}"`, raw, [{ name: TOKEN, tool: "Read", field: "token", origin: FILE, value: null, confidentiality: "no-model" }]),
      policy: { trust: "TRUSTED", reason: "integrity axis OFF", confidentiality: "no-model" },
    });
    ev("tllm_call", { turn: 3, input: dr(`▸ tool_result\n${TOKEN}`), output: dr("Now it is hidden.") });
  }
  return out;
}

function page(events: ManduEvent[], labels?: LabelTime[], cwd: string | null = "/home/dev/mandu-try"): AgentPageVM {
  const vm = toSessionViewModel(SESSION, events);
  return buildAgentPage({ session: null, id: SESSION, vm, cwd, waiting: [], events, believedVm: vm, home: "/home/dev", ...(labels ? { labels } : {}) });
}

const LABEL_AT = iso(T0 + 10 * 60_000);
const LABEL: LabelTime = { path: FILE, level: "no-model", at: LABEL_AT };

const readStep = (p: AgentPageVM) => p.story.flatMap((t) => t.steps).find((s) => s.kind === "action" && s.icon === "file");

test("readPath places a Read's file: absolute as named, ~ under home, else under the session's folder", () => {
  assert.equal(readPath("/a/./b//c", null, "/home/dev"), "/a/b/c");
  assert.equal(readPath("~/x/y", null, "/home/dev"), "/home/dev/x/y");
  assert.equal(readPath("deploy/../deploy/staging.conf", "/home/dev/mandu-try", "/home/dev"), FILE);
  assert.equal(readPath("deploy/staging.conf", null, "/home/dev"), null, "no folder recorded: cannot place it");
  assert.equal(readPath(TOKEN, "/w", ""), null, "a placeholder is no path");
});

test("readStepPath: a read step's file, its absolute recorded origin first, else the path its arguments name, placed by readPath", () => {
  const step = (origin: string | null, args: Record<string, unknown> | null) => ({ origin, input: args ? JSON.stringify(args) : null });
  assert.equal(readStepPath(step(null, { file_path: "deploy/staging.conf" }), "/home/dev/mandu-try", "/home/dev"), FILE);
  assert.equal(readStepPath(step("/srv/a.env", { file_path: "b.env" }), null, ""), "/srv/a.env", "an absolute origin is the file");
  assert.equal(readStepPath(step("a command", { path: "/srv/b.env" }), null, ""), "/srv/b.env", "an origin that is no path is not");
  assert.equal(readStepPath(step(null, { file_path: "deploy/staging.conf" }), null, "/home/dev"), null, "no folder recorded");
  assert.equal(readStepPath(step(null, { file_path: TOKEN }), "/w", ""), null, "a placeholder is no path");
  assert.equal(readStepPath(step(null, null), "/w", ""), null, "no arguments");
  assert.equal(readStepPath({ origin: null, input: "not json" }, "/w", ""), null, "arguments that do not parse");
});

test("plainReads: a Read whose result reached the AI as it was, never one it got masked", () => {
  const vm = toSessionViewModel(SESSION, sessionEvents());
  assert.deepEqual(plainReads(vm, null, "/home/dev").map((r) => r.path), [FILE]);
  const rel = toSessionViewModel(SESSION, sessionEvents({ path: "deploy/staging.conf" }));
  assert.deepEqual(plainReads(rel, "/home/dev/mandu-try", "/home/dev").map((r) => r.path), [FILE]);
  assert.deepEqual(plainReads(toSessionViewModel(SESSION, sessionEvents({ masked: true })), null, "/home/dev"), []);
});

test("laterLabels: reads strictly before the label's time, at a level that hides it from the AI", () => {
  const reads = [{ stepId: "s1", ts: iso(T0), path: FILE }, { stepId: "s2", ts: iso(T0 + 20 * 60_000), path: FILE }];
  const [l] = laterLabels(reads, [LABEL]);
  assert.deepEqual(l!.reads.map((r) => r.stepId), ["s1"], "a read after the label is not one");
  assert.deepEqual(laterLabels(reads, [{ ...LABEL, at: iso(T0) }]), [], "a label at the read's own moment does not come after it");
  assert.deepEqual(laterLabels(reads, [{ ...LABEL, level: "any-model" }]), []);
  assert.deepEqual(laterLabels(reads, [{ ...LABEL, level: "public" }]), []);
  assert.deepEqual(laterLabels(reads, [{ ...LABEL, at: "not a time" }]), []);
  assert.equal(hidesFromAi("local-model"), true);
  assert.equal(hidesFromAi("some-new-level"), true, "an unknown level reads as a secret (fail-closed)");
});

test("labelSince: a policy rule's time from the change log, a page label's own, else none", () => {
  const entry: PathLevelsEntryWire = { path: FILE, level: "no-model", bindings: [], rule: `label:${FILE}`, store: "policy" };
  const change = (id: string, at: number, item: { added: boolean; removed: boolean; current: boolean }): PolicyChangeRow => ({
    id, via: "proposal", requestedBy: "human", sessionKey: null, edits: [], delta: [], proposalId: null, createdAt: at, undoneAt: null, undoneBy: null, undoable: true,
    rules: [{ rowIds: [`lock:${FILE}`], ...item }],
  });
  const at = T0 + 600_000;
  assert.equal(labelSince(entry, [change("pc-1", at, { added: true, removed: false, current: true })], null), at);
  assert.equal(labelSince(entry, [change("pc-1", at, { added: true, removed: false, current: false })], null), null, "a later unrecorded edit changed it");
  assert.equal(labelSince(entry, [], null), null, "no record");
  assert.equal(labelSince(entry, null, null), null, "no change log");
  assert.equal(labelSince(entry, [change("pc-2", at + 1, { added: false, removed: true, current: false }), change("pc-1", at, { added: true, removed: false, current: false })], null), null, "its newest change removed it");
  const page: PathLevelsEntryWire = { ...entry, store: "page" };
  assert.equal(labelSince(page, null, [{ path: FILE, source: "dashboard", updatedAt: at }]), at);
  assert.equal(labelSince(page, null, [{ path: "/other", source: "dashboard", updatedAt: at }]), null);
  assert.equal(labelSince({ ...entry, rule: "shape:*.env", store: null }, [], []), null, "a built-in rule has no time");
  assert.equal(labelSince({ ...entry, level: "any-model" }, [change("pc-1", at, { added: true, removed: false, current: true })], null), null);
  assert.deepEqual(labelTimes([entry], [change("pc-1", at, { added: true, removed: false, current: true })], null), [{ path: FILE, level: "no-model", at: iso(at) }]);
});

test("the session page: the Read says the AI got it as it was and when it was marked; Your secrets tells the file with no placeholder", () => {
  const before = page(sessionEvents());
  const plain = readStep(before)!;
  assert.equal(plain.kind === "action" ? plain.outcome : null, "plain", "no labels: as the session's own record");
  assert.equal(before.secrets.secrets.length, 0);

  const p = page(sessionEvents(), [LABEL]);
  const step = readStep(p)!;
  assert.ok(step.kind === "action");
  assert.equal(step.outcome, "raw");
  assert.equal(step.note, "The AI got this as it was: nothing marked it a secret when it read it.");
  assert.equal(words(step.later!), `Marked a secret at <${LABEL_AT}>, after this read: the AI saw its real value.`);
  assert.equal(p.story[0]!.summary, "The AI read your secret staging.conf as it was: it was marked secret only later.");

  const [card] = p.secrets.secrets;
  assert.equal(words(card!.what), "The file ~/mandu-try/deploy/staging.conf");
  assert.equal(card!.level, "No AI");
  assert.equal(card!.saw, "early");
  assert.equal(card!.since, LABEL_AT, "the tag says since when it is marked");
  assert.equal(card!.ref, undefined, "no placeholder: nothing to show");
  assert.deepEqual(card!.lines.map((l) => `${l.tone}: ${words(l.parts)}`), [
    `warn: The AI read its real value at <${iso(T0 + 2000)}>, before it was marked a secret at <${LABEL_AT}>, so nothing in this session masked it.`,
    "warn: If it holds a key or a password, change it: the AI saw it as it was.",
  ]);
  // The read's time opens its step.
  assert.equal(card!.lines[0]!.parts.find((x) => x.kind === "time")!.step, step.id);
  assert.deepEqual(p.secrets.counts, { masked: 0, early: 1 });
  assert.doesNotMatch(JSON.stringify(p), /never the real value|\$MDU:/);
  // Plain product words: no inspector term in what the page says of it.
  const said = [step.note, words(step.later!), p.story[0]!.summary, words(card!.what), ...card!.lines.map((l) => words(l.parts))].join("\n");
  assert.doesNotMatch(said, /\b(symboliz|desymboliz|egress|invariant|T-LLM|U-LLM|quarantin|AgentView|HumanView|lineage|chokepoint|arbiter|symbol|token)\b/i);
});

test("a Rules page label of your own model only: the card adds what its level lets", () => {
  const p = page(sessionEvents(), [{ ...LABEL, level: "local-model" }]);
  assert.match(words(p.secrets.secrets[0]!.lines.at(-1)!.parts), /only your own model/);
  assert.equal(p.secrets.secrets[0]!.level, "Your own AI only");
});

test("a relative Read is placed in the session's folder; with no folder it makes no claim", () => {
  const ev = sessionEvents({ path: "deploy/staging.conf" });
  assert.equal(page(ev, [LABEL]).secrets.counts.early, 1);
  assert.equal(page(ev, [LABEL], null).secrets.counts.early, 0);
});

test("a label made before the read, or a read the AI got masked, is no such claim", () => {
  assert.equal(page(sessionEvents(), [{ ...LABEL, at: iso(T0 - 60_000) }]).secrets.secrets.length, 0);
  const masked = page(sessionEvents({ masked: true }), [{ ...LABEL, at: iso(T0 - 60_000) }]);
  assert.equal(masked.secrets.secrets[0]!.saw, "masked", "masked from its first read: the card as before");
});

test("Off: the card says protection was off, and counts in neither tile", () => {
  const p = page(sessionEvents({ mode: "off" }), [LABEL]);
  assert.equal(p.secrets.secrets[0]!.saw, "off");
  assert.match(words(p.secrets.secrets[0]!.lines[0]!.parts), /^Protection was off, so Mandu did not mask it\. The AI read it at /);
  assert.deepEqual(p.secrets.counts, { masked: 0, early: 0 });
});

test("a file a later read masked learns of the earlier read: never \"never the real value\"", () => {
  const ev = sessionEvents({ secondMaskedRead: true });
  // Without the label time: the masked re-read alone says "never".
  assert.match(JSON.stringify(page(ev).secrets.secrets[0]!.lines), /never the real value/);
  const p = page(ev, [{ ...LABEL, at: iso(T0 + 5500) }]);
  assert.equal(p.secrets.secrets.length, 1, "one file, one entry");
  const card = p.secrets.secrets[0]!;
  assert.equal(card.saw, "early");
  assert.ok(card.ref, "its placeholder can still be shown");
  assert.match(words(card.lines[0]!.parts), /^The AI read its real value at <[^>]+>, before it was marked a secret\. From <[^>]+> on it got a placeholder in its place/);
  assert.doesNotMatch(JSON.stringify(card.lines), /never the real value/);
  assert.deepEqual(p.secrets.counts, { masked: 0, early: 1 });
});
