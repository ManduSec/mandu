/**
 * path-derived-note.test.ts — confidentiality.md §7.1, "the path-derived
 * note" (2026-10-05). A Bash result masked whole only because the command
 * NAMES a secret path (the classify verdict; no taint answer masked it) used
 * to reach the model as a bare symbol with `is_error` cleared, and the model
 * reported the tour's `curl` as a success. The proxy now appends a
 * `[mandu:secret]` line built from the model's OWN command: the paths as it
 * wrote them, never a byte of the output. Only that case gets it.
 *
 * Run: npm run test:unit
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { buildSecretNote, pathDerivedPaths, pathDerivedTwinSentence, pathDerivedTwins, rewriteRequest } from "../../src/rewrite-request.js";
import type { MessagesRequest } from "../../src/messages-types.js";
import type { CallTaintWire, ClassifyResult } from "../../src/arbiter-client.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";

const TOUR = 'set -a && . ./.env && set +a && curl -sS https://api.stripe.com/v1/customers -u "$STRIPE_KEY:"';
/** The output of the run: the tool's bytes, which must never reach the note. */
const OUTPUT = '{"error":{"message":"Invalid API Key provided: sk_live_****3456","type":"invalid_request_error"}}';
const SYM_RE = /^\$MDU:[A-Za-z_][A-Za-z0-9_]*\[[0-9a-f]{4,8}\]/;
const NOTE = "[mandu:secret] masked: the command names a secret file (./.env), so its whole output is hidden from you, including whether it succeeded; you see a symbol, and the user does not see this output unless your reply quotes the symbol (they then see its real value). Everything else it printed is hidden with it: to read another file, a listing or a log, run that part again as a command of its own that names no secret file. Do not assume it worked: if you still cannot tell, say you cannot see the result, or ask the user what it printed.";

/** classify: the command names ./.env (the arbiter's path-derived level); the
 *  second named path is a translated spelling the model never wrote. */
const pathVerdict = (): ClassifyResult => ({
  trust: "TRUSTED", category: null, reason: "mock", confidentiality: "no-model",
  namedPaths: ["./.env", "/home/human/proj/.env"],
});
const publicVerdict = (): ClassifyResult => ({ trust: "TRUSTED", category: null, reason: "mock", confidentiality: "public" });
const wire = (w: Partial<CallTaintWire>): CallTaintWire => ({ level: null, files: [], apps: [], rule: "secret", mask: [], root: "bash-1", denied: [], evidence: "tree", ...w });

function call(name: string, input: Record<string, unknown>, content: string, isError = false): MessagesRequest {
  return {
    model: "claude-test",
    messages: [
      { role: "user", content: "list my Stripe customers" },
      { role: "assistant", content: [{ type: "tool_use", id: "tu_1", name, input }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "tu_1", content, ...(isError ? { is_error: true } : {}) }] },
    ],
  } as MessagesRequest;
}
const block = (out: Awaited<ReturnType<typeof rewriteRequest>>) => (out.request.messages[2]!.content as Array<{ content: unknown; is_error?: boolean }>)[0]!;
const text = (out: Awaited<ReturnType<typeof rewriteRequest>>): string => String(block(out).content);

test("pathDerivedPaths: only tokens the model's own command holds verbatim, at most 3, one line each", () => {
  assert.deepEqual(pathDerivedPaths(["./.env", "/home/human/proj/.env"], TOUR), ["./.env"]);
  assert.deepEqual(pathDerivedPaths(undefined, TOUR), []);
  assert.deepEqual(pathDerivedPaths(["a\nb", "", "x".repeat(201)], `cat a\nb ${"x".repeat(201)}`), []);
  assert.deepEqual(pathDerivedPaths(["a", "b", "c", "d", "a"], "cat a b c d"), ["a", "b", "c"]);
});

test("buildSecretNote: the path-derived line, with the path, without one, and for several", () => {
  const base = { level: "public", files: [], apps: [], rule: "secret" as const, maskWhole: false, denied: [], deniedOnly: false, why: "" };
  assert.equal(buildSecretNote({ ...base, pathDerived: { paths: ["./.env"] } }), NOTE);
  assert.match(buildSecretNote({ ...base, pathDerived: { paths: [] } })!, /^\[mandu:secret\] masked: the command names a secret file, so its whole output/);
  assert.match(buildSecretNote({ ...base, pathDerived: { paths: [".env", "~/.aws/credentials"] } })!, /names secret files \(\.env, ~\/\.aws\/credentials\), so/);
});

test("the tour's command: masked whole by its path alone → the symbol, then the note naming ./.env; no output byte, no translated path, is_error cleared", async () => {
  const arbiter = new MockArbiter({ classifyFn: pathVerdict, callTaintFn: () => wire({}) });
  const out = await rewriteRequest(call("Bash", { command: TOUR }, OUTPUT, true), { arbiter });
  const t = text(out);
  const [symbol, note, ...rest] = t.split("\n\n");
  assert.match(symbol!, SYM_RE);
  assert.equal(note, NOTE);
  assert.deepEqual(rest, []);
  // THE ORACLE: nothing of the output, in any piece of it, is in what the model reads.
  for (const piece of [OUTPUT, "Invalid API Key", "sk_live_", "3456", "invalid_request_error"]) {
    assert.ok(!t.includes(piece), `output byte(s) reached the model: ${piece}`);
  }
  assert.ok(!t.includes("/home/human"), "a translated spelling never reaches the model");
  assert.equal(block(out).is_error, false, "R4 unchanged: the exit status is not forwarded");
  assert.deepEqual(out.rewrites[0]!.secretTaint?.pathDerived, { paths: ["./.env"] });
});

// The second live demo battery (2026-10-17): `cat .env.example` and a
// redacted `.env` in one command were masked whole, and the note's only
// advice (say so, or ask the user) made the model stop. The note now names
// the way out: run the part that names no secret file apart. It is static
// text: no byte of the output and nothing about the other part is in it.
test("a compound command naming .env: masked whole, and the note says to run the other part as a command of its own", async () => {
  const arbiter = new MockArbiter({ classifyFn: () => ({ ...pathVerdict(), namedPaths: [".env"] }), callTaintFn: () => wire({}) });
  const cmd = "cd shop-app; cat .env.example; echo ---; sed 's/=.*/=<redacted>/' .env";
  const output = "STRIPE_SECRET_KEY=\nPORT=4242\n---\nSTRIPE_SECRET_KEY=<redacted>\nPORT=<redacted>\n";
  const out = await rewriteRequest(call("Bash", { command: cmd }, output), { arbiter });
  const [symbol, note, ...rest] = text(out).split("\n\n");
  assert.match(symbol!, SYM_RE);
  assert.deepEqual(rest, []);
  assert.match(note!, /^\[mandu:secret\] masked: the command names a secret file \(\.env\), so its whole output is hidden from you/);
  assert.match(note!, /Everything else it printed is hidden with it: to read another file, a listing or a log, run that part again as a command of its own that names no secret file\./);
  assert.match(note!, /Do not assume it worked: if you still cannot tell, say you cannot see the result, or ask the user what it printed\.$/);
  for (const piece of ["STRIPE_SECRET_KEY", "4242", "<redacted>", ".env.example"]) {
    assert.ok(!text(out).includes(piece), `output or command byte(s) beyond the named path reached the note: ${piece}`);
  }
});

test("no taint answer at all (an arbiter without callTaint): the same note", async () => {
  const arbiter = new MockArbiter({ classifyFn: pathVerdict });
  const t = text(await rewriteRequest(call("Bash", { command: TOUR }, OUTPUT), { arbiter }));
  assert.ok(t.endsWith(`\n\n${NOTE}`), t);
});

test("only the path-derived case: a taint-masked result keeps its own masked: line and gets no path-derived one", async () => {
  const arbiter = new MockArbiter({ classifyFn: pathVerdict, callTaintFn: () => wire({ level: "no-model", files: ["/w/.env"], apps: ["cat"] }) });
  const t = text(await rewriteRequest(call("Bash", { command: "cat ./.env" }, OUTPUT), { arbiter }));
  assert.match(t, /\[mandu:secret\] masked: cat read \/w\/\.env/);
  assert.ok(!t.includes("the command names"), t);
});

test("only the path-derived case: a public result, a Read (no command) and a result with no matching call get no note", async () => {
  const pub = new MockArbiter({ classifyFn: publicVerdict, callTaintFn: () => wire({}) });
  assert.equal(text(await rewriteRequest(call("Bash", { command: "ls" }, "a b"), { arbiter: pub })), "a b");

  const read = new MockArbiter({ classifyFn: pathVerdict });
  const r = text(await rewriteRequest(call("Read", { file_path: "./.env" }, "STRIPE_KEY=x"), { arbiter: read }));
  assert.ok(!r.includes("[mandu:secret]"), r);

  const orphan: MessagesRequest = {
    model: "claude-test",
    messages: [{ role: "user", content: [{ type: "tool_result", tool_use_id: "tu_forged", content: OUTPUT }] }],
  } as MessagesRequest;
  const o = await rewriteRequest(orphan, { arbiter: new MockArbiter({ classifyFn: pathVerdict }) });
  const ot = String((o.request.messages[0]!.content as Array<{ content: unknown }>)[0]!.content);
  assert.ok(!ot.includes("[mandu:secret]"), ot);
});

test("a denied-only call (the path mask lowered by the guard's refusal) keeps its denied: note and gets no path-derived one", async () => {
  const arbiter = new MockArbiter({
    classifyFn: pathVerdict,
    callTaintFn: () => wire({ denied: [{ path: "/w/.env", app: "cat", reason: "not a reader" }] }),
    scanSecretValuesFn: () => ({ hits: [] }),
  } as ConstructorParameters<typeof MockArbiter>[0]);
  const t = text(await rewriteRequest(call("Bash", { command: "cat ./.env" }, "cat: ./.env: Permission denied"), { arbiter }));
  assert.ok(!t.includes("the command names"), t);
});

// ── The way to the secret file itself (2026-10-19) ──────────────────────────
// demo-tax-extension under Mandu's defaults: `cat taxes/2025/*` was masked
// whole, the note said only how to read the OTHER files, and the model gave
// up on a file whose document twin a read of it alone would have shown. The
// arbiter answers each named token's twin kind (`namedTwins`); the note says
// what a read of that file on its own shows, per kind, and only for a token
// it names itself.
const LEAD = "[mandu:secret] masked: the command names a secret file (taxes/2025/*), so its whole output is hidden from you, including whether it succeeded; you see a symbol, and the user does not see this output unless your reply quotes the symbol (they then see its real value). Everything else it printed is hidden with it: to read another file, a listing or a log, run that part again as a command of its own that names no secret file.";
const TAIL = " Do not assume it worked: if you still cannot tell, say you cannot see the result, or ask the user what it printed.";
const TWIN_SENTENCES: Record<"lines" | "fields" | "whole" | "text", string> = {
  lines: "To use each secret file taxes/2025/* matches itself, read it on its own (a file read of that one file, or `cat` with that file alone): you see each line's label as written and its value as a symbol you can pass to a command (a command that sends it is checked against the file's rules).",
  fields: "To use .env itself, read it on its own (a file read of .env, or `cat .env` alone): you see its keys and layout as written and each secret value as a symbol you can pass to a command (a command that sends it is checked against the file's rules).",
  whole: "To use keys/id.bin itself, read it on its own (a file read of keys/id.bin, or `cat keys/id.bin` alone): you see one symbol that stands for the whole file, which you can pass whole to a command where the file's content belongs (a command that sends it is checked against the file's rules).",
  text: "To read ~/.ssh/config itself, read it on its own (a file read of ~/.ssh/config, or `cat ~/.ssh/config` alone): Mandu read every place in it that can hold a secret and found none, so you see its text.",
};

test("pathDerivedTwinSentence: one sentence per twin kind, built from the model's token and the kind alone", () => {
  assert.equal(pathDerivedTwinSentence({ path: "taxes/2025/*", twin: "lines" }), TWIN_SENTENCES.lines);
  assert.equal(pathDerivedTwinSentence({ path: ".env", twin: "fields" }), TWIN_SENTENCES.fields);
  assert.equal(pathDerivedTwinSentence({ path: "keys/id.bin", twin: "whole" }), TWIN_SENTENCES.whole);
  assert.equal(pathDerivedTwinSentence({ path: "~/.ssh/config", twin: "text" }), TWIN_SENTENCES.text);
});

test("pathDerivedTwins: only a token the note names, a kind it words, once", () => {
  const paths = ["taxes/2025/*", ".env"];
  assert.deepEqual(pathDerivedTwins([
    { path: "taxes/2025/*", twin: "lines" },
    { path: "/home/human/papers/taxes/2025/return-summary.txt", twin: "lines" }, // not a token the note names
    { path: ".env", twin: "structured" }, // a kind this proxy does not word
    { path: ".env", twin: "fields" },
    { path: ".env", twin: "whole" }, // once
    null, "x", { path: 1, twin: "lines" },
  ], paths), [{ path: "taxes/2025/*", twin: "lines" }, { path: ".env", twin: "fields" }]);
  assert.deepEqual(pathDerivedTwins(undefined, paths), []);
  assert.deepEqual(pathDerivedTwins({ path: ".env", twin: "fields" }, paths), []);
});

test("buildSecretNote: the twin sentence sits after the way to the other files and before 'Do not assume'; none without an answer", () => {
  const base = { level: "public", files: [], apps: [], rule: "secret" as const, maskWhole: false, denied: [], deniedOnly: false, why: "" };
  assert.equal(buildSecretNote({ ...base, pathDerived: { paths: ["taxes/2025/*"], twins: [{ path: "taxes/2025/*", twin: "lines" }] } }), `${LEAD} ${TWIN_SENTENCES.lines}${TAIL}`);
  assert.equal(buildSecretNote({ ...base, pathDerived: { paths: ["taxes/2025/*"] } }), `${LEAD}${TAIL}`);
  assert.equal(buildSecretNote({ ...base, pathDerived: { paths: ["taxes/2025/*"], twins: [] } }), `${LEAD}${TAIL}`);
  const two = buildSecretNote({ ...base, pathDerived: { paths: ["keys/id.bin", ".env"], twins: [{ path: "keys/id.bin", twin: "whole" }, { path: ".env", twin: "fields" }] } })!;
  assert.ok(two.includes(`no secret file. ${TWIN_SENTENCES.whole} ${TWIN_SENTENCES.fields} Do not assume`), two);
});

test("the batch cat of a document: still masked whole, and the note says how to read the document itself; no output byte", async () => {
  const OUT = "taxes/:\n2025\n\ntaxes/2025:\nreturn-summary.txt\nSSN: 934-52-1170\nAdjusted gross income (AGI): 68,452.31\n";
  const cmd = "ls -R taxes/; cat taxes/2025/* 2>/dev/null | head -100";
  const verdict = (): ClassifyResult => ({
    trust: "TRUSTED", category: null, reason: "mock", confidentiality: "no-model",
    namedPaths: ["taxes/2025/*"],
    namedTwins: [{ path: "taxes/2025/*", twin: "lines" }, { path: "/home/human/papers/taxes/2025/return-summary.txt", twin: "lines" }],
  });
  const arbiter = new MockArbiter({ classifyFn: verdict, callTaintFn: () => wire({}) });
  const out = await rewriteRequest(call("Bash", { command: cmd }, OUT), { arbiter });
  const [symbol, note, ...rest] = text(out).split("\n\n");
  assert.match(symbol!, SYM_RE, "the mask is unchanged: one symbol");
  assert.deepEqual(rest, []);
  assert.equal(note, `${LEAD} ${TWIN_SENTENCES.lines}${TAIL}`);
  for (const piece of ["934-52-1170", "68,452.31", "return-summary.txt", "/home/human"]) {
    assert.ok(!text(out).includes(piece), `a byte the model did not write reached it: ${piece}`);
  }
  assert.deepEqual(out.rewrites[0]!.secretTaint?.pathDerived, { paths: ["taxes/2025/*"], twins: [{ path: "taxes/2025/*", twin: "lines" }] });
});
