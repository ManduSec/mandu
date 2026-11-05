/**
 * locked-object-note.test.ts — the openai-proxy twin of the anthropic
 * proxy's test (confidentiality.md §7.1, "git's report on a history
 * rewrite"; ported 2026-10-27). A public Codex output in which git reports
 * it could not read objects Mandu locked (the verdict's `lockedObjects`), or
 * could not remove a protected file's read-only copy (`protectedCopies`),
 * gets the same `[mandu:locked]` note as the Claude proxy's, on both Codex
 * wires: an `exec_command` output (a string) and a code-mode script cell (an
 * `input_text` part each, the note one more). A masked output never gets it.
 * The note's words are pinned in locked-object-note-text.test.ts.
 *
 * Live 2026-10-27 (demo-git-history-scrub on Codex): git's EACCES on the
 * locked `.env` version reached the model with nothing beside it; it took
 * the repository for broken and replaced its history with one new commit.
 *
 * Run: npm run test:unit
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { ownForwardedText, rewriteRequest } from "../../src/rewrite-request.js";
import { LOCKED_NOTE_MARKER, lockedObjectNote, protectedCopyNote } from "../../src/locked-object-note.js";
import type { ResponsesRequest } from "../../src/responses-types.js";
import type { ClassifyResult } from "../../src/arbiter-client.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";

const LOCKED = "7c72b0c959f112730dc47da675a590979839a25e";
const REPORT = `error: unable to open loose object ${LOCKED}: Permission denied\nfatal: could not read blob ${LOCKED}\n`;
const HEADER = "Chunk ID: 4f1c2a\nWall time: 0.0123 seconds\nProcess exited with code 1\nOriginal token count: 30\nOutput:\n";
const CELL_HEAD = "Script completed\nWall time 0.8 seconds\nOutput:\n";
const CMD = "git -C storefront log -p --all";

function exec(output: string): ResponsesRequest {
  return {
    model: "gpt-test",
    input: [
      { type: "message", role: "user", content: [{ type: "input_text", text: "scrub the key from storefront's history" }] },
      { type: "function_call", call_id: "call_1", name: "exec_command", arguments: JSON.stringify({ cmd: CMD }) },
      { type: "function_call_output", call_id: "call_1", output },
    ],
  } as unknown as ResponsesRequest;
}
function cell(body: string): ResponsesRequest {
  return {
    model: "gpt-test",
    input: [
      { type: "message", role: "user", content: [{ type: "input_text", text: "scrub the key from storefront's history" }] },
      { type: "custom_tool_call", call_id: "c_1", name: "exec", input: `const r = await tools.exec_command({cmd:${JSON.stringify(CMD)}}); text(r.output);` },
      { type: "custom_tool_call_output", call_id: "c_1", output: [{ type: "input_text", text: CELL_HEAD }, { type: "input_text", text: body }] },
    ],
  } as unknown as ResponsesRequest;
}
const outputOf = (r: Awaited<ReturnType<typeof rewriteRequest>>): unknown =>
  (r.request.input as Array<{ type: string; output?: unknown }>).find((x) => x.type.endsWith("_output"))!.output;
const flat = (o: unknown): string => (typeof o === "string" ? o : (o as Array<{ text: string }>).map((p) => p.text).join(""));
const arbiter = (v: Partial<ClassifyResult>): MockArbiter =>
  new MockArbiter({ classifyFn: () => ({ trust: "TRUSTED", category: null, reason: "mock", confidentiality: "public", ...v }) });

test("an exec_command output naming a locked object: the output as git printed it, then the note", async () => {
  const res = await rewriteRequest(exec(`${HEADER}${REPORT}`), { arbiter: arbiter({ lockedObjects: [LOCKED] }) });
  const t = flat(outputOf(res));
  assert.equal(t, `${HEADER}${REPORT}\n\n${lockedObjectNote([LOCKED])}`);
  const audit = res.rewrites[0]!;
  assert.equal(audit.lockedNote, lockedObjectNote([LOCKED]));
  assert.equal(ownForwardedText(audit), `${HEADER}${REPORT}`, "the note is the proxy's own, out of the oracle's scope");
});

test("a script cell's output: its parts kept, the note one more part", async () => {
  const res = await rewriteRequest(cell(REPORT), { arbiter: arbiter({ lockedObjects: [LOCKED] }) });
  const out = outputOf(res) as Array<{ type: string; text: string }>;
  assert.deepEqual(out, [
    { type: "input_text", text: CELL_HEAD },
    { type: "input_text", text: REPORT },
    { type: "input_text", text: `\n\n${lockedObjectNote([LOCKED])}` },
  ]);
  assert.equal(ownForwardedText(res.rewrites[0]!), `${CELL_HEAD}${REPORT}`);
});

test("a file git could not remove, alone and beside a locked object: the same lines as the Claude proxy's", async () => {
  const unlink = "Ref 'refs/heads/main' was rewritten\nwarning: unable to unlink '.env': Permission denied\n";
  const one = await rewriteRequest(exec(`${HEADER}${unlink}`), { arbiter: arbiter({ protectedCopies: [".env"] }) });
  assert.equal(flat(outputOf(one)), `${HEADER}${unlink}\n\n${protectedCopyNote([".env"])}`);
  const both = await rewriteRequest(exec(`${HEADER}${REPORT}${unlink}`), { arbiter: arbiter({ lockedObjects: [LOCKED], protectedCopies: [".env"] }) });
  assert.ok(flat(outputOf(both)).endsWith(`\n\n${lockedObjectNote([LOCKED])}\n${protectedCopyNote([".env"])}`), flat(outputOf(both)));
  assert.equal(ownForwardedText(both.rewrites[0]!), `${HEADER}${REPORT}${unlink}`);
});

test("no ids, invalid ids, or a masked output: no note", async () => {
  const plain = await rewriteRequest(exec(`${HEADER}${REPORT}`), { arbiter: arbiter({}) });
  assert.equal(flat(outputOf(plain)), `${HEADER}${REPORT}`);
  const junk = await rewriteRequest(exec(`${HEADER}${REPORT}`), { arbiter: arbiter({ lockedObjects: ["sk_live_x"], protectedCopies: ["a'b"] }) });
  assert.equal(flat(outputOf(junk)), `${HEADER}${REPORT}`, "nothing that is not an id or a plain path is named");
  for (const req of [exec(`${HEADER}${REPORT}`), cell(REPORT)]) {
    const masked = await rewriteRequest(req, { arbiter: arbiter({ confidentiality: "no-model", lockedObjects: [LOCKED], protectedCopies: [".env"] }) });
    const t = flat(outputOf(masked));
    assert.ok(!t.includes(LOCKED_NOTE_MARKER), t);
    assert.ok(!t.includes(LOCKED), "a masked output says nothing of what it held");
    assert.match(t, /\$MDU:/);
  }
});
