/**
 * after-the-fact-note.test.ts — confidentiality.md §7.1, "Masked after the
 * fact" (2026-10-05). Every request re-sends the history and the rewrite
 * re-classifies it, so a file the user labels AFTER the model read it comes
 * back masked in the next request. The mask is right; without a word about
 * it the model read its own earlier answer beside a placeholder, concluded it
 * had made the content up and apologised to the user (live tour). A result
 * this proxy forwarded in clear before and masks now carries one more
 * `[mandu:secret]` line, static text: no byte of the result.
 *
 * Run: npm run test:unit
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { AFTER_THE_FACT_MARKER, AFTER_THE_FACT_SYSTEM_NOTE, ClearResultLedger, afterTheFactLine, arbiterClearResultStore } from "../../src/after-the-fact.js";
import { ownForwardedText, rewriteRequest, RewriteRefusal } from "../../src/rewrite-request.js";
import type { MessagesRequest, Message } from "../../src/messages-types.js";
import type { CallTaintWire, ClassifyRequest, ClassifyResult } from "../../src/arbiter-client.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";

const PATH = "/home/u/mandu-try/deploy/staging.conf";
const TOKEN = "ghp_FakeTourToken0123456789abcdefABCDEF";
const FILE_READ = `     1\t[staging]\n     2\thost = "staging.internal.example"\n     3\ttoken = "${TOKEN}"\n`;
const DEDUP = "Wasted call — file unchanged since your last Read. Refer to that earlier tool_result instead.";
const SYM_RE = /^\$MDU:[A-Za-z_][A-Za-z0-9_]*\[[0-9a-f]{4,8}\]/;

const LINE_READ = "[mandu:secret] masked after the fact: when you first read this result, earlier in this conversation, it showed you its real content; it was marked secret after that (a lock or a label, possibly one made later in this conversation), so each time the conversation is sent to you Mandu now puts a symbol in its place, and this transcript no longer shows what you saw. What you wrote about it then came from that real content: it was not invented, so do not apologise for it or say you made it up. Do not repeat or restate what it contained; refer to it by the symbol. Mandu's note in the system prompt explains this. If you Read this file again while it is unchanged, Claude Code answers with its own \"file unchanged since your last Read\" notice, not the file: that notice points back to this result, which now shows only the symbol.";
const LINE_PLAIN = "[mandu:secret] masked after the fact: when you first read this result, earlier in this conversation, it showed you its real content; it was marked secret after that (a lock or a label, possibly one made later in this conversation), so each time the conversation is sent to you Mandu now puts a symbol in its place, and this transcript no longer shows what you saw. What you wrote about it then came from that real content: it was not invented, so do not apologise for it or say you made it up. Do not repeat or restate what it contained; refer to it by the symbol. Mandu's note in the system prompt explains this.";
const LINE_TAINT = "[mandu:secret] masked after the fact: when you first read this result, earlier in this conversation, it showed you its real content; Mandu masks it now for the reason above, so each time the conversation is sent to you Mandu now puts a symbol in its place, and this transcript no longer shows what you saw. What you wrote about it then came from that real content: it was not invented, so do not apologise for it or say you made it up. Do not repeat or restate what it contained; refer to it by the symbol. Mandu's note in the system prompt explains this.";

/** The arbiter: `staging.conf` is public until the test labels it; Claude
 *  Code's dedup notice is public whatever the label (the arbiter's
 *  isReadDedupNotice, confidentiality.md §7.1). */
function labelArbiter(state: { labelled: boolean }, extra: Partial<ConstructorParameters<typeof MockArbiter>[0]> = {}): MockArbiter {
  return new MockArbiter({
    classifyFn: (r: ClassifyRequest): ClassifyResult => {
      if (r.tool === "Read" && r.value === DEDUP) return { trust: "TRUSTED", category: null, reason: "mock: read dedup notice", confidentiality: "public" };
      const names = r.origin === PATH || (typeof r.params?.["command"] === "string" && (r.params["command"] as string).includes("staging.conf"));
      return state.labelled && names
        ? { trust: "TRUSTED", category: null, reason: "mock: user label", confidentiality: "no-model", ...(r.params?.["command"] ? { namedPaths: ["deploy/staging.conf"] } : {}) }
        : { trust: "TRUSTED", category: null, reason: "mock", confidentiality: "public" };
    },
    ...extra,
  });
}

const u = (content: Message["content"]): Message => ({ role: "user", content } as Message);
const a = (content: Message["content"]): Message => ({ role: "assistant", content } as Message);
const readUse = (id: string) => a([{ type: "tool_use", id, name: "Read", input: { file_path: PATH } }] as Message["content"]);
const result = (id: string, content: string) => u([{ type: "tool_result", tool_use_id: id, content }] as Message["content"]);

/** The tour's history, turn by turn. */
const turn1: Message[] = [u("What is in deploy/staging.conf?"), readUse("toolu_read1"), result("toolu_read1", FILE_READ)];
const turn2: Message[] = [
  ...turn1,
  a([{ type: "text", text: "It holds the staging host and a GitHub token. Want me to lock it?" }] as Message["content"]),
  u("Use Mandu's policy tools to mark deploy/staging.conf as a secret hidden from you. Then read it again and tell me what you see."),
  a([{ type: "tool_use", id: "toolu_pol", name: "mcp__mandu-policy__mandu_policy_propose", input: { edits: [{ op: "lock-path", path: "deploy/staging.conf", level: "no-model" }] } }] as Message["content"]),
  result("toolu_pol", '{"applied":true,"change":"pc-000001"}'),
  readUse("toolu_read2"),
  result("toolu_read2", DEDUP),
];
const req = (messages: Message[]): MessagesRequest => ({ model: "claude-test", messages } as MessagesRequest);
const resultText = (out: Awaited<ReturnType<typeof rewriteRequest>>, id: string): string => {
  for (const m of out.request.messages) {
    if (!Array.isArray(m.content)) continue;
    for (const b of m.content as Array<{ type: string; tool_use_id?: string; content?: unknown }>) {
      if (b.type === "tool_result" && b.tool_use_id === id) return typeof b.content === "string" ? b.content : (b.content as Array<{ text: string }>).map((x) => x.text).join("");
    }
  }
  throw new Error(`no result ${id}`);
};

test("ClearResultLedger: remembers ids, ignores empty ones, forgets the oldest past its bound", () => {
  const l = new ClearResultLedger(2);
  l.remember(["a", "", "b"]);
  assert.ok(l.wasClear("a") && l.wasClear("b") && !l.wasClear(""));
  l.remember(["c"]);
  assert.ok(!l.wasClear("a") && l.wasClear("b") && l.wasClear("c"));
});

test("afterTheFactLine: the three forms, pinned (byte-identical in the openai-proxy)", () => {
  assert.equal(`[mandu:secret] ${afterTheFactLine({ taintCause: false, harnessRead: true })}`, LINE_READ);
  assert.equal(`[mandu:secret] ${afterTheFactLine({ taintCause: false, harnessRead: false })}`, LINE_PLAIN);
  assert.equal(`[mandu:secret] ${afterTheFactLine({ taintCause: true, harnessRead: false })}`, LINE_TAINT);
});

test("the tour: a Read forwarded in clear, the file labelled, the next request masks the earlier result AND says it was masked after the fact; no byte of the file in the note", async () => {
  const state = { labelled: false };
  const arbiter = labelArbiter(state);
  const clearResults = new ClearResultLedger();

  // turn 1: nothing labels the file, the Read goes raw
  const first = await rewriteRequest(req(turn1), { arbiter, clearResults });
  assert.equal(resultText(first, "toolu_read1"), FILE_READ);
  assert.ok(clearResults.wasClear("toolu_read1"));

  // the policy tool labels it; turn 2 re-sends the history
  state.labelled = true;
  const second = await rewriteRequest(req(turn2), { arbiter, clearResults });
  const r1 = resultText(second, "toolu_read1");
  const [symbol, note, ...rest] = r1.split("\n\n");
  assert.match(symbol!, SYM_RE, r1);
  assert.equal(note, LINE_READ);
  assert.deepEqual(rest, []);
  // THE ORACLE: nothing of the file in what the model reads for that result
  for (const piece of [TOKEN, "ghp_", "staging.internal", "[staging]"]) assert.ok(!r1.includes(piece), `file byte(s) in the result: ${piece}`);
  assert.equal(ownForwardedText(second.rewrites.find((r) => r.toolUseId === "toolu_read1")!), symbol, "the own-block oracle strips the whole note");

  // the second Read (Claude Code's dedup notice) holds no file byte: the
  // arbiter calls it public, so the model reads the notice itself, never a
  // symbol standing for it, and no after-the-fact line
  const r2 = resultText(second, "toolu_read2");
  assert.equal(r2, DEDUP, r2);
  assert.ok(!r2.includes("$MDU:") && !r2.includes("[mandu:secret]"), r2);

  // turn 3: the same bytes again (the history is stable)
  const third = await rewriteRequest(req([...turn2, a([{ type: "text", text: "ok" }] as Message["content"]), u("thanks")]), { arbiter, clearResults });
  assert.equal(resultText(third, "toolu_read1"), r1);
});

test("a Read with a trailing harness reminder (the split path) gets the note after its symbol", async () => {
  const state = { labelled: false };
  const reminder = "\n\n<system-reminder>\n<total_tokens>991234 tokens left</total_tokens>\n</system-reminder>";
  const arbiter = labelArbiter(state, {
    classifyFn: (r: ClassifyRequest): ClassifyResult => {
      if (/^\s*<system-reminder>\s*<total_tokens>\d+ tokens left<\/total_tokens>\s*<\/system-reminder>\s*$/.test(r.value)) return { trust: "TRUSTED", category: null, reason: "budget", confidentiality: "public" };
      return state.labelled && r.origin === PATH
        ? { trust: "TRUSTED", category: null, reason: "mock: label", confidentiality: "no-model" }
        : { trust: "TRUSTED", category: null, reason: "mock", confidentiality: "public" };
    },
  });
  const clearResults = new ClearResultLedger();
  const msgs = [u("what is in it?"), readUse("toolu_r"), result("toolu_r", FILE_READ + reminder)];
  await rewriteRequest(req(msgs), { arbiter, clearResults });
  assert.ok(clearResults.wasClear("toolu_r"));
  state.labelled = true;
  const t = resultText(await rewriteRequest(req(msgs), { arbiter, clearResults }), "toolu_r");
  assert.ok(t.endsWith(`\n\n${LINE_READ}`), t);
  assert.ok(!t.includes(TOKEN), t);
});

test("Bash after the fact: the path-derived line gives way to the after-the-fact one; a taint-masked result keeps its masked: line and joins it", async () => {
  const wire = (w: Partial<CallTaintWire>): CallTaintWire => ({ level: null, files: [], apps: [], rule: "secret", mask: [], root: "bash-1", denied: [], evidence: "tree", ...w });
  const msgs = [u("show it"), a([{ type: "tool_use", id: "toolu_b", name: "Bash", input: { command: "cat deploy/staging.conf" } }] as Message["content"]), result("toolu_b", `token = "${TOKEN}"\n`)];

  const state = { labelled: false };
  const clearResults = new ClearResultLedger();
  const pathOnly = labelArbiter(state, { callTaintFn: () => wire({}) } as Partial<ConstructorParameters<typeof MockArbiter>[0]>);
  assert.equal(resultText(await rewriteRequest(req(msgs), { arbiter: pathOnly, clearResults }), "toolu_b"), `token = "${TOKEN}"\n`);
  state.labelled = true;
  const t = resultText(await rewriteRequest(req(msgs), { arbiter: pathOnly, clearResults }), "toolu_b");
  const [sym, note, ...rest] = t.split("\n\n");
  assert.match(sym!, SYM_RE);
  assert.equal(note, LINE_PLAIN, "no path-derived line, no Read sentence");
  assert.deepEqual(rest, []);

  const tainted = labelArbiter(state, { callTaintFn: () => wire({ level: "no-model", files: ["/w/deploy/staging.conf"], apps: ["cat"] }) } as Partial<ConstructorParameters<typeof MockArbiter>[0]>);
  const t2 = resultText(await rewriteRequest(req(msgs), { arbiter: tainted, clearResults }), "toolu_b");
  const lines = t2.split("\n\n")[1]!.split("\n");
  assert.match(lines[0]!, /^\[mandu:secret\] masked: cat read \/w\/deploy\/staging\.conf;/);
  assert.equal(lines[1], LINE_TAINT);
  assert.equal(lines.length, 2);
  assert.ok(!t2.includes(TOKEN));
});

test("only after the fact: a result masked from its first request, a result still clear, and a proxy with no ledger get no line", async () => {
  const state = { labelled: true };
  const clearResults = new ClearResultLedger();
  const arbiter = labelArbiter(state);
  const fresh = resultText(await rewriteRequest(req(turn1), { arbiter, clearResults }), "toolu_read1");
  assert.match(fresh, new RegExp(`${SYM_RE.source}$`));
  assert.ok(!clearResults.wasClear("toolu_read1"), "a masked result is never remembered as clear");
  assert.ok(!resultText(await rewriteRequest(req(turn1), { arbiter, clearResults }), "toolu_read1").includes("after the fact"));

  const open = { labelled: false };
  const ledger = new ClearResultLedger();
  await rewriteRequest(req(turn1), { arbiter: labelArbiter(open), clearResults: ledger });
  assert.equal(resultText(await rewriteRequest(req(turn1), { arbiter: labelArbiter(open), clearResults: ledger }), "toolu_read1"), FILE_READ);

  // no ledger: byte-identical to before (a bare symbol)
  const none = resultText(await rewriteRequest(req(turn1), { arbiter }), "toolu_read1");
  assert.match(none, new RegExp(`${SYM_RE.source}$`));
});

test("a refused rewrite remembers nothing: its clear results never reached the model", async () => {
  const clearResults = new ClearResultLedger();
  const arbiter = new MockArbiter({
    classifyFn: (r: ClassifyRequest): ClassifyResult => {
      if (r.callId === "toolu_bad") throw new Error("arbiter down");
      return { trust: "TRUSTED", category: null, reason: "mock", confidentiality: "public" };
    },
  });
  const msgs = [...turn1, readUse("toolu_bad"), result("toolu_bad", "x")];
  await assert.rejects(rewriteRequest(req(msgs), { arbiter, clearResults }), RewriteRefusal);
  assert.ok(!clearResults.wasClear("toolu_read1"));
});

test("Mandu's system note rides with the line: absent before, once per request while a result is masked after the fact, byte-stable, not in a count", async () => {
  const state = { labelled: false };
  const arbiter = labelArbiter(state);
  const clearResults = new ClearResultLedger();
  const systemText = (out: Awaited<ReturnType<typeof rewriteRequest>>): string =>
    Array.isArray(out.request.system) ? out.request.system.map((b) => (b as { text?: string }).text ?? "").join("\n---\n") : String(out.request.system ?? "");
  const count = (hay: string, needle: string): number => hay.split(needle).length - 1;

  const first = await rewriteRequest({ ...req(turn1), system: [{ type: "text", text: "You are Claude Code." }] } as MessagesRequest, { arbiter, clearResults });
  assert.equal(count(systemText(first), AFTER_THE_FACT_MARKER), 0, "nothing masked after the fact yet");

  state.labelled = true;
  const second = await rewriteRequest({ ...req(turn2), system: [{ type: "text", text: "You are Claude Code." }] } as MessagesRequest, { arbiter, clearResults });
  const sys = second.request.system as Array<{ text: string }>;
  assert.equal(sys.at(-1)!.text, AFTER_THE_FACT_SYSTEM_NOTE, "the last system block, after the handling prompt");
  assert.equal(count(systemText(second), AFTER_THE_FACT_MARKER), 1);
  for (const piece of [TOKEN, "ghp_", "staging", "toolu_"]) assert.ok(!AFTER_THE_FACT_SYSTEM_NOTE.includes(piece), piece);

  // a client that already echoes it (or a second pass) never gets it twice
  const again = await rewriteRequest(second.request, { arbiter, clearResults });
  assert.equal(count(systemText(again), AFTER_THE_FACT_MARKER), 1);

  const counted = await rewriteRequest(req(turn2), { arbiter, clearResults, skipPromptInjection: true });
  assert.equal(count(systemText(counted), AFTER_THE_FACT_MARKER), 0, "a token count carries no Mandu system text");
});

// ── Across a resume (confidentiality.md §7.1, *Across a resume*) ─────────────

/** A store over one in-memory "mandu.db", with its calls; `fail` is live. */
function memStore(db = new Set<string>(), fail: { known?: boolean; record?: boolean } = {}) {
  const calls = { known: [] as string[][], record: [] as string[][] };
  return {
    db, calls, fail,
    store: {
      known: async (ids: string[]) => { calls.known.push([...ids]); if (fail.known) throw new Error("arbiter down"); return ids.filter((id) => db.has(id)); },
      record: async (ids: string[]) => { calls.record.push([...ids]); if (fail.record) throw new Error("arbiter down"); for (const id of ids) db.add(id); },
    },
  };
}

test("ClearResultLedger with a store: records only new ids, asks only about ids it does not know (once each), and a failed record is retried with the next one", async () => {
  const m = memStore(new Set(["toolu_old"]));
  const l = new ClearResultLedger(100, { store: m.store });
  await l.prime(["toolu_old", "toolu_new", "", "toolu_old"]);
  assert.deepEqual(m.calls.known, [["toolu_old", "toolu_new"]], "one ask, valid unique ids only");
  assert.ok(l.wasClear("toolu_old") && !l.wasClear("toolu_new"));
  await l.prime(["toolu_old", "toolu_new"]);
  assert.equal(m.calls.known.length, 1, "known and asked ids are not asked again");

  await l.remember(["toolu_new", "toolu_old"]);
  assert.deepEqual(m.calls.record, [["toolu_new"]], "an id already known is not re-recorded");
  await l.remember(["toolu_new"]);
  assert.equal(m.calls.record.length, 1, "nothing new: no record");

  const f = memStore(new Set(), { record: true });
  const logs: string[] = [];
  const l2 = new ClearResultLedger(100, { store: f.store, log: (s) => logs.push(s) });
  await l2.remember(["toolu_a"]);
  assert.ok(l2.wasClear("toolu_a"), "memory first: a failed record loses only the copy");
  assert.match(logs[0]!, /could not record 1 clear result id/);
  f.fail.record = false;
  await l2.remember(["toolu_b"]);
  assert.deepEqual(f.calls.record.at(-1), ["toolu_a", "toolu_b"], "the unsaved id rides the next record");
  assert.ok(f.db.has("toolu_a") && f.db.has("toolu_b"));
});

test("ClearResultLedger: a failed ask never throws and leaves the ids unknown (no note, the mask stays); they are asked again next time", async () => {
  const m = memStore(new Set(["toolu_x"]), { known: true });
  const logs: string[] = [];
  const l = new ClearResultLedger(100, { store: m.store, log: (s) => logs.push(s) });
  await l.prime(["toolu_x"]);
  assert.ok(!l.wasClear("toolu_x"));
  assert.match(logs[0]!, /no note for them this time \(the mask stays\)/);
  await l.prime(["toolu_x"]);
  assert.equal(m.calls.known.length, 2, "a failed ask is not cached as a miss");
});

test("the tour across a resume: launch 1 forwards the Read in clear and records it; launch 2 (a fresh ledger over the same arbiter) gets the resumed history, labelled since, and sends the note and Mandu's system note; no byte of the file", async () => {
  const state = { labelled: false };
  const db = new Set<string>();
  // launch 1: the proxy's production shape, the ledger over the arbiter's ops
  const arbiter1 = labelArbiter(state, { forwardedClearIds: db });
  const ledger1 = new ClearResultLedger(undefined, { store: arbiterClearResultStore(arbiter1) });
  assert.equal(resultText(await rewriteRequest(req(turn1), { arbiter: arbiter1, clearResults: ledger1 }), "toolu_read1"), FILE_READ);
  assert.deepEqual([...db], ["toolu_read1"], "the clear result's id (only the id) reached the arbiter");
  assert.deepEqual(arbiter1.recordForwardedClearCalls, [["toolu_read1"]]);

  // the file is labelled; the user quits and runs `claude --resume` under a new launch
  state.labelled = true;
  const arbiter2 = labelArbiter(state, { forwardedClearIds: db });
  const ledger2 = new ClearResultLedger(undefined, { store: arbiterClearResultStore(arbiter2) });
  const out = await rewriteRequest({ ...req(turn2), system: [{ type: "text", text: "You are Claude Code." }] } as MessagesRequest, { arbiter: arbiter2, clearResults: ledger2 });
  const r1 = resultText(out, "toolu_read1");
  const [symbol, note, ...rest] = r1.split("\n\n");
  assert.match(symbol!, SYM_RE, r1);
  assert.equal(note, LINE_READ);
  assert.deepEqual(rest, []);
  assert.equal((out.request.system as Array<{ text: string }>).at(-1)!.text, AFTER_THE_FACT_SYSTEM_NOTE);
  assert.deepEqual(arbiter2.forwardedClearCalls, [["toolu_read1", "toolu_pol", "toolu_read2"]], "one ask for the resumed history's ids");
  for (const piece of [TOKEN, "ghp_", "staging.internal", "[staging]"]) {
    assert.ok(!r1.includes(piece), `file byte(s) in the result: ${piece}`);
    assert.ok(!JSON.stringify(out.request.system).includes(piece), `file byte(s) in the system prompt: ${piece}`);
  }
  // the next request of launch 2 asks nothing again
  await rewriteRequest(req(turn2), { arbiter: arbiter2, clearResults: ledger2 });
  assert.equal(arbiter2.forwardedClearCalls.length, 1);
});

test("across a resume, fail-safe: an arbiter that cannot answer, or lacks the ops, leaves the resumed result masked with no note (the mask never depends on the ask)", async () => {
  const state = { labelled: true };
  for (const arbiter of [labelArbiter(state, { forwardedClearIds: new Set(["toolu_read1"]), failForwardedClear: true }), labelArbiter(state)]) {
    const ledger = new ClearResultLedger(undefined, { store: arbiterClearResultStore(arbiter), log: () => {} });
    const r1 = resultText(await rewriteRequest(req(turn2), { arbiter, clearResults: ledger }), "toolu_read1");
    assert.match(r1, new RegExp(`${SYM_RE.source}$`), r1);
    assert.ok(!r1.includes("after the fact") && !r1.includes(TOKEN), r1);
  }
  assert.equal(arbiterClearResultStore(labelArbiter(state)), undefined, "no ops: memory only");
});
