/**
 * path-denial-notice.test.ts — the notice for a call whose every path Mandu
 * denied, and the request side that replaces such a result with it
 * (confidentiality plan 10 §11.8, "Path denials").
 *
 * Run: npm run test:unit
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  everyPathDenied,
  isPathSentinel,
  pathDenialNotice,
  plainDenialWords,
  ResultNotices,
  RESULT_NOTICES_MAX,
} from "../../src/path-denial-notice.js";
import { rewriteRequest } from "../../src/rewrite-request.js";
import type { MessagesRequest } from "../../src/messages-types.js";
import type { ClassifyResult } from "../../src/arbiter-client.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";

const FIELDS = { fields: ["file_path", "paths"], mode: "read" as const };
const DENIED = "/mandu/denied/policy/home/u/.ssh/id_rsa";
const UNLABELED = "/dev/null/mandu-unlabeled/config/.env";
/** A test-only stand-in for bytes a tool might add (not a real credential). */
const PROGRAM_BYTES = "FIXTURE-PROGRAM-OUTPUT-7f3a";
const SYM_RE = /^\$MDU:[A-Za-z_][A-Za-z0-9_]*\[[0-9a-f]{4,8}\]/;

test("isPathSentinel: both sentinel roots, nothing else", () => {
  assert.equal(isPathSentinel(DENIED), true);
  assert.equal(isPathSentinel(UNLABELED), true);
  assert.equal(isPathSentinel("/mandu/deniedX/a"), false);
  assert.equal(isPathSentinel("/home/u/.ssh/id_rsa"), false);
});

test("everyPathDenied: every path value a sentinel, at least one; a real path left, or none, is false", () => {
  assert.equal(everyPathDenied({ file_path: DENIED }, FIELDS), true);
  assert.equal(everyPathDenied({ paths: [DENIED, UNLABELED] }, FIELDS), true);
  assert.equal(everyPathDenied({ paths: [DENIED, "/home/u/notes.md"] }, FIELDS), false, "a real path left: the tool may have read it");
  assert.equal(everyPathDenied({ file_path: DENIED, paths: ["/home/u/a"] }, FIELDS), false);
  assert.equal(everyPathDenied({ content: "x" }, FIELDS), false, "no path value");
  assert.equal(everyPathDenied({ file_path: DENIED }, undefined), false, "a tool with no path fields");
  assert.equal(everyPathDenied(null, FIELDS), false);
});

test("plainDenialWords and the notice: the path, the plain reason, then the arbiter's", () => {
  assert.match(plainDenialWords("REFUSED: the session is HIGH and this path has no stable identity"), /name the file by its absolute path/);
  assert.match(plainDenialWords("held for the user → pending"), /Approvals page/);
  assert.match(plainDenialWords("arbiter unreachable (x) — fail closed"), /not answering/);
  const n = pathDenialNotice("Read", [{ field: "file_path", path: "/home/u/.ssh/id_rsa", reason: "sensitive path" }, { field: "paths[1]", path: "/a", reason: "r2" }]);
  assert.deepEqual(n.split("\n"), [
    "mandu-fs-gate: denied, nothing was read or written: Mandu rules do not allow this tool to use this path (the dashboard lists them: mandu dashboard). path: /home/u/.ssh/id_rsa (Read.file_path). detail: sensitive path",
    "mandu-fs-gate: denied, nothing was read or written: Mandu rules do not allow this tool to use this path (the dashboard lists them: mandu dashboard). path: /a (Read.paths[1]). detail: r2",
  ]);
});

test("ResultNotices: by id, empty ignored, bounded", () => {
  const s = new ResultNotices();
  s.remember(undefined, "x");
  s.remember("a", undefined);
  assert.equal(s.noticeFor("a"), undefined);
  s.remember("a", "n");
  assert.equal(s.noticeFor("a"), "n");
  for (let i = 0; i < RESULT_NOTICES_MAX; i++) s.remember(`k${i}`, "n");
  assert.equal(s.noticeFor("a"), undefined);
});

const secretEverything = (): ClassifyResult => ({ trust: "TRUSTED", category: null, reason: "mock", confidentiality: "no-model" });
const NOTICE = pathDenialNotice("Write", [{ field: "file_path", path: "config/.env", reason: "REFUSED: the session is HIGH and this path has no stable identity (not absolute) — it cannot be labeled, so it must not be written" }]);

function request(content: unknown): MessagesRequest {
  return {
    model: "claude-test",
    messages: [
      { role: "user", content: "write it" },
      { role: "assistant", content: [{ type: "tool_use", id: "tu_w", name: "Write", input: { file_path: UNLABELED, content: "x" } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "tu_w", content, is_error: true }] },
    ],
  } as MessagesRequest;
}
const notices = (id = "tu_w") => { const s = new ResultNotices(); s.remember(id, NOTICE); return s; };
const forwarded = (out: Awaited<ReturnType<typeof rewriteRequest>>): string => {
  const c = (out.request.messages[2]!.content as Array<{ content: unknown }>)[0]!.content;
  return typeof c === "string" ? c : (c as Array<{ text: string }>).map((b) => b.text).join("");
};

test("rewriteRequest: a recorded call's result is replaced by the notice, whatever the tool said, text or array", async () => {
  const arbiter = new MockArbiter({ classifyFn: secretEverything, scanSecretValuesFn: () => ({ hits: [] }) });
  for (const content of [`<tool_use_error>ENOTDIR ${PROGRAM_BYTES}</tool_use_error>`, [{ type: "text", text: PROGRAM_BYTES }], ""]) {
    const out = await rewriteRequest(request(content), { arbiter, resultNotices: notices() });
    assert.equal(forwarded(out), NOTICE);
    assert.ok(!JSON.stringify(out.request).includes(PROGRAM_BYTES), "no byte of the tool's output is forwarded");
    assert.equal(out.rewrites[0]!.symbolized, false);
    assert.match(out.rewrites[0]!.reason ?? "", /mandu notice/);
  }
  assert.equal(arbiter.symbolizeCalls.length, 0);
});

test("rewriteRequest: no record, a backstop hit, a failing or missing backstop → classified as before", async () => {
  const content = `<tool_use_error>ENOTDIR ${PROGRAM_BYTES}</tool_use_error>`;
  const clean = new MockArbiter({ classifyFn: secretEverything, scanSecretValuesFn: () => ({ hits: [] }) });
  assert.match(forwarded(await rewriteRequest(request(content), { arbiter: clean, resultNotices: notices("tu_other") })), SYM_RE);
  assert.match(forwarded(await rewriteRequest(request(content), { arbiter: clean })), SYM_RE);
  const hit = new MockArbiter({ classifyFn: secretEverything, scanSecretValuesFn: () => ({ hits: [{ symbol: "$MDU:nomodel_Read[ab12]", level: "no-model" }] }) });
  assert.match(forwarded(await rewriteRequest(request(content), { arbiter: hit, resultNotices: notices() })), SYM_RE);
  const failing = new MockArbiter({ classifyFn: secretEverything, scanSecretValuesFn: () => { throw new Error("down"); } });
  assert.match(forwarded(await rewriteRequest(request(content), { arbiter: failing, resultNotices: notices() })), SYM_RE);
  const missing = new MockArbiter({ classifyFn: secretEverything });
  assert.match(forwarded(await rewriteRequest(request(content), { arbiter: missing, resultNotices: notices() })), SYM_RE);
});
