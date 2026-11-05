/**
 * locked-object-note.test.ts — confidentiality.md §7.1, "git's report on a
 * history rewrite" (2026-10-26). A public result in which git reports it
 * could not read objects Mandu locked (the arbiter names them in the verdict's
 * `lockedObjects`) gets one static `[mandu:locked]` line: what those objects
 * are, and which history operations still work. The note holds the ids and
 * nothing of the result; a masked result never gets it. The note's words are
 * pinned in locked-object-note-text.test.ts (shared with the openai-proxy);
 * this suite pins the Messages wire.
 *
 * Run: npm run test:unit
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { LOCKED_NOTE_MARKER, lockedObjectNote, ownForwardedText, protectedCopyNote, rewriteRequest } from "../../src/rewrite-request.js";
import * as shared from "../../src/locked-object-note.js";
import type { MessagesRequest } from "../../src/messages-types.js";
import type { ClassifyResult } from "../../src/arbiter-client.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";

const LOCKED = "7c72b0c959f112730dc47da675a590979839a25e";
const OUTPUT = `error: unable to open loose object ${LOCKED}: Permission denied\nfatal: unable to read ${LOCKED}`;

function call(content: string, tool = "Bash"): MessagesRequest {
  return {
    model: "claude-test",
    messages: [
      { role: "user", content: "scrub the key from storefront's history" },
      { role: "assistant", content: [{ type: "tool_use", id: "tu_1", name: tool, input: { command: "git log -p --all" } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "tu_1", content }] },
    ],
  } as MessagesRequest;
}
const text = (out: Awaited<ReturnType<typeof rewriteRequest>>): string =>
  String((out.request.messages[2]!.content as Array<{ content: unknown }>)[0]!.content);

test("rewrite-request re-exports the shared module's note (one text for both proxies)", () => {
  assert.equal(LOCKED_NOTE_MARKER, shared.LOCKED_NOTE_MARKER);
  assert.equal(lockedObjectNote, shared.lockedObjectNote);
  assert.equal(protectedCopyNote, shared.protectedCopyNote);
});

test("a public result naming a locked object: the output as git printed it, then the note", async () => {
  const verdict: ClassifyResult = { trust: "TRUSTED", category: null, reason: "mock", confidentiality: "public", lockedObjects: [LOCKED] };
  const out = await rewriteRequest(call(OUTPUT), { arbiter: new MockArbiter({ classifyFn: () => verdict }) });
  const t = text(out);
  assert.ok(t.startsWith(OUTPUT), t);
  assert.ok(t.endsWith(lockedObjectNote([LOCKED])!), t);
  const audit = out.rewrites[0]!;
  assert.equal(audit.lockedNote, lockedObjectNote([LOCKED]));
  assert.equal(ownForwardedText(audit), OUTPUT, "the note is the proxy's own, out of the oracle's scope");
});

// The other agents on this proxy (2026-10-27 parity check): OpenCode's
// `bash` and Goose's `shell` results take the same seam as Claude Code's Bash.
test("OpenCode's bash and Goose's shell: the same note on a public result", async () => {
  for (const tool of ["bash", "shell"]) {
    const verdict: ClassifyResult = { trust: "TRUSTED", category: null, reason: "mock", confidentiality: "public", lockedObjects: [LOCKED], protectedCopies: [".env"] };
    const t = text(await rewriteRequest(call(OUTPUT, tool), { arbiter: new MockArbiter({ classifyFn: () => verdict }) }));
    assert.equal(t, `${OUTPUT}\n\n${lockedObjectNote([LOCKED])}\n${protectedCopyNote([".env"])}`, tool);
  }
});

test("no ids, or a masked result: no note", async () => {
  const plain = await rewriteRequest(call(OUTPUT), { arbiter: new MockArbiter({ classifyFn: () => ({ trust: "TRUSTED", category: null, reason: "mock", confidentiality: "public" }) }) });
  assert.equal(text(plain), OUTPUT);
  const masked = await rewriteRequest(call(OUTPUT), {
    arbiter: new MockArbiter({ classifyFn: () => ({ trust: "TRUSTED", category: null, reason: "mock", confidentiality: "no-model", lockedObjects: [LOCKED] }) }),
  });
  assert.ok(!text(masked).includes(LOCKED_NOTE_MARKER), text(masked));
  assert.ok(!text(masked).includes(LOCKED), "a masked result says nothing of what it held");
});

test("a public result naming a file git could not remove: the output as printed, then the note; with a locked object too, both lines", async () => {
  const out = "Ref 'refs/heads/main' was rewritten\nwarning: unable to unlink '.env': Permission denied";
  const verdict: ClassifyResult = { trust: "TRUSTED", category: null, reason: "mock", confidentiality: "public", protectedCopies: [".env"] };
  const res = await rewriteRequest(call(out), { arbiter: new MockArbiter({ classifyFn: () => verdict }) });
  assert.equal(text(res), `${out}\n\n${protectedCopyNote([".env"])}`);
  const both = await rewriteRequest(call(`${OUTPUT}\n${out}`), { arbiter: new MockArbiter({ classifyFn: () => ({ ...verdict, lockedObjects: [LOCKED] }) }) });
  assert.ok(text(both).endsWith(`${lockedObjectNote([LOCKED])}\n${protectedCopyNote([".env"])}`), text(both));
  assert.equal(ownForwardedText(both.rewrites[0]!), `${OUTPUT}\n${out}`, "the notes are the proxy's own");
  const masked = await rewriteRequest(call(out), { arbiter: new MockArbiter({ classifyFn: () => ({ ...verdict, confidentiality: "no-model" }) }) });
  assert.ok(!text(masked).includes(LOCKED_NOTE_MARKER), "a masked result gets no note");
});
