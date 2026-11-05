/**
 * protected-read-note.test.ts — confidentiality.md §7, "A protected file read
 * whole" (2026-10-26). A `read` of a `no-model` file that the proxy masks
 * whole, with no other note on it, ends with one static `[mandu:secret]`
 * line that says what the symbol is: the file the model named, that no model
 * may read it, that the user can open it, and that a program the model runs
 * still reads the real file. Live on the OpenClaw plugin's Route 1
 * (demo-notion-token): the bare symbol came with no word, and the model
 * waited for the user to check a token it could not see.
 *
 * Run: npm run test:unit
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { ownForwardedText, protectedReadNote, rewriteRequest } from "../../src/rewrite-request.js";
import { CLAUDE_CODE_GATE_SURFACE, UNION_GATE_SURFACE } from "../../src/gate-surface.js";
import type { MessagesRequest } from "../../src/messages-types.js";
import type { ClassifyResult } from "../../src/arbiter-client.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";


const TOKEN = "secret_ProtectedReadNote4Kp8Wq2Zx6Ln3Rt7";
const FILE = `NOTION_TOKEN='${TOKEN}'\n`;

function call(name: string, input: Record<string, unknown>): MessagesRequest {
  return {
    model: "claude-test",
    messages: [
      { role: "user", content: "show me notes-app/.env, then run the script" },
      { role: "assistant", content: [{ type: "tool_use", id: "tu_1", name, input }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "tu_1", content: FILE }] },
    ],
  } as MessagesRequest;
}
const text = (out: Awaited<ReturnType<typeof rewriteRequest>>): string =>
  String((out.request.messages[2]!.content as Array<{ content: unknown }>)[0]!.content);
const verdict = (confidentiality: ClassifyResult["confidentiality"]): ClassifyResult =>
  ({ trust: "TRUSTED", category: null, reason: "path rule", confidentiality });

test("protectedReadNote: static text and the path, nothing of the file", () => {
  const note = protectedReadNote("notes-app/.env");
  assert.ok(note.startsWith(`[mandu:secret] masked: notes-app/.env is a protected file that no AI model may read`), note);
  assert.match(note, /A program you run that reads the file itself \(a script, the app\) still gets its real content/);
});

test("OpenClaw's read of a no-model file: the symbol, then the note; the token in no byte", async () => {
  const out = await rewriteRequest(call("read", { path: "notes-app/.env" }), {
    arbiter: new MockArbiter({ classifyFn: () => verdict("no-model") }),
    surface: UNION_GATE_SURFACE,
  });
  const t = text(out);
  assert.match(t, /^\$MDU:/);
  assert.ok(t.endsWith(protectedReadNote("notes-app/.env")), t);
  assert.ok(!JSON.stringify(out.request).includes(TOKEN), "CONFIDENTIALITY VIOLATION: the token reached the model");
  const audit = out.rewrites[0]!;
  assert.equal(audit.secretNote, protectedReadNote("notes-app/.env"));
  assert.ok(!ownForwardedText(audit).includes("[mandu:secret]"), "the note is the proxy's own, out of the oracle's scope");
});

test("Claude Code's Read (always behind the file twin), other levels and other tools: no such note", async () => {
  const cc = await rewriteRequest(call("Read", { file_path: "/w/notes-app/.env" }), {
    arbiter: new MockArbiter({ classifyFn: () => verdict("no-model") }),
    surface: CLAUDE_CODE_GATE_SURFACE,
  });
  assert.match(text(cc), /^\$MDU:[A-Za-z_]+\[[0-9a-f]+\]$/, "Claude Code's bare symbol is unchanged");

  const anyModel = await rewriteRequest(call("read", { path: "memo/brief.md" }), {
    arbiter: new MockArbiter({ classifyFn: () => verdict("any-model") }),
    surface: UNION_GATE_SURFACE,
  });
  assert.ok(!text(anyModel).includes("protected file"), "an any-model file may be declassified: no such note");

  const grep = await rewriteRequest(call("grep", { path: "notes-app", pattern: "TOKEN" }), {
    arbiter: new MockArbiter({ classifyFn: () => verdict("no-model") }),
    surface: UNION_GATE_SURFACE,
  });
  assert.ok(!text(grep).includes("protected file"), "a search result is not the file read whole");
});
