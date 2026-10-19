/**
 * oracle-scope.test.ts — the §9 oracle's two scopes (2026-09-26): a result's
 * raw span is looked for at ANY length in its own forwarded block, and only
 * when distinctive (DISTINCTIVE_RAW_CHARS) anywhere else in the request.
 * The live i19 drill flagged six calls on a `wc -l` result of "9" matching
 * the "9" in a trusted Write confirmation's `ws-i19-opus` path.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { DISTINCTIVE_RAW_CHARS, survivingResult, survivingUntrusted } from "../../src/events.js";
import { ownForwardedText, type RewriteAudit } from "../../src/rewrite-request.js";

const SYM = "$MDU:Bash[a355]";

test("survivingUntrusted: a blank value is never a survivor", () => {
  assert.equal(survivingUntrusted("a b\n c", [" ", "\n", ""]), null);
});

test("survivingResult: a short span elsewhere in the request is coincidence", () => {
  const haystack = `File created successfully at: /ws/ws-i19-opus/todo.txt\n${SYM}`;
  assert.equal(survivingResult(SYM, haystack, ["9"]), null);
});

test("survivingResult: a short span in its OWN block survives at any length", () => {
  assert.equal(survivingResult(`9 ${SYM}`, "", ["9"]), "9");
});

test("survivingResult: a distinctive span elsewhere in the request still survives", () => {
  const canary = "mandu-canary-7f3e91";
  assert.ok(canary.length >= DISTINCTIVE_RAW_CHARS);
  assert.equal(survivingResult(SYM, `copied /ws/${canary}/x`, [canary]), canary);
  // One character short of distinctive: elsewhere it no longer counts.
  const short = canary.slice(0, DISTINCTIVE_RAW_CHARS - 1);
  assert.equal(survivingResult(SYM, `copied /ws/${short}/x`, [short]), null);
});

test("ownForwardedText: removes the trusted piece a split result keeps verbatim", () => {
  const header = "Exit code: 0\nWall time: 0.9 seconds\nOutput:\n";
  const r = { callId: "c", tool: "shell", trust: "TRUSTED", symbolized: true, symbol: SYM, value: `${header}9\n`,
    symbolizedSpan: "9", keptVerbatim: header, forwardedText: `${header}${SYM}\n` } as RewriteAudit;
  assert.equal(ownForwardedText(r), `${SYM}\n`);
  assert.equal(survivingResult(ownForwardedText(r), "", ["9"]), null, "the header's 0.9 is not the output '9'");
  // Without the removal the header's digit would read as survival.
  assert.equal(survivingResult(r.forwardedText!, "", ["9"]), "9");
});

test("ownForwardedText: removes the proxy-authored secret note", () => {
  const note = "[mandu:secret] denied: cat is not a reader of /home/u/.aws/credentials9 (rule)";
  const r = { callId: "c", tool: "shell", trust: "TRUSTED", symbolized: true, symbol: SYM, value: "9",
    secretNote: note, forwardedText: `${SYM}\n\n${note}` } as RewriteAudit;
  assert.equal(ownForwardedText(r), SYM);
});
