/**
 * fake-anthropic.test — the scripted fake's request helpers
 * (tests/lib/fake-anthropic.ts), pure, no server.
 *
 * Pins the one normalization the differential harness relies on: the echo
 * of a tool_result never carries the proxy's `[mandu:twin]` note
 * (symbol-twin-shell-blindness.md) — trusted guidance addressed to the model,
 * which the fake would otherwise parrot into the reply and put rows on the
 * wrapped screen that vanilla never has (first seen 2026-09-19: the
 * bash-permission-prompt and long-session scenarios red on both widths).
 *
 * And extractEchoedContent, the echo the differential scenarios send back
 * after a Read (differential-interactive.md §20): normal gutters, edge
 * shapes, malformed requests.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { extractEchoedContent, extractToolResultText, type ParsedRequest } from "../lib/fake-anthropic.js";

function req(content: unknown): ParsedRequest {
  const body = JSON.stringify({
    messages: [
      { role: "assistant", content: [{ type: "tool_use", id: "t1", name: "Bash", input: {} }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "t1", content }] },
    ],
  });
  return { url: "/v1/messages", body, hasToolResult: true };
}

const NOTE =
  "[mandu:twin] notes.md is an untrusted file: in this workspace its content is the opaque symbol " +
  "$MDU:Read[9b0a] (1 token). Shell content search and line addressing over it see nothing — this " +
  "empty result is expected. To use its content: Read the file, then inspect_symbol the token for " +
  "what you need; to copy it verbatim, write the token itself.";

test("extractToolResultText: the last tool_result's text, string or blocks", () => {
  assert.equal(extractToolResultText(req("RC_PROBE_1")), "RC_PROBE_1");
  assert.equal(extractToolResultText(req([{ type: "text", text: "a" }, { type: "text", text: "b" }])), "a\nb");
  assert.equal(extractToolResultText({ url: "", body: "{}", hasToolResult: false }), null);
});

test("extractToolResultText strips the proxy's [mandu:twin] note from the echo", () => {
  assert.equal(extractToolResultText(req(`$MDU:Read[9b0a]\n\n${NOTE}`)), "$MDU:Read[9b0a]");
  // With the trusted budget reminder between body and note (claude ≥ 2.1.25x
  // appends it to every tool_result): the note goes, the rest stays.
  const withReminder = `RC_PROBE_1\n\n<system-reminder>\n<total_tokens>1 left</total_tokens>\n</system-reminder>\n\n${NOTE}`;
  assert.equal(
    extractToolResultText(req(withReminder)),
    "RC_PROBE_1\n\n<system-reminder>\n<total_tokens>1 left</total_tokens>\n</system-reminder>",
  );
  // No note → byte-identical.
  assert.equal(extractToolResultText(req("plain\noutput\n")), "plain\noutput\n");
});

// ── extractEchoedContent (differential-interactive.md §20) ─────────────────
// What the scripted model echoes after a Read: the file's content without
// Claude Code's harness framing (trailing <system-reminder> blocks, the
// `<n><sep>` gutter), so vanilla's reply shows exactly what the wrapped side's
// resolved symbol shows. Anything that is not a strict from-1 gutter is kept
// byte for byte.

const SR = (inner: string): string => `<system-reminder>\n${inner}\n</system-reminder>`;
/** Claude Code's Read rendering: a right-aligned number, a separator, the line. */
const gutter = (lines: string[], sep = "→", width = 6): string =>
  lines.map((l, i) => `${String(i + 1).padStart(width)}${sep}${l}`).join("\n");

test("extractEchoedContent: a bare symbol (the wrapped side) is the identity", () => {
  assert.equal(extractEchoedContent(req("$MDU:Read[9b0a]")), "$MDU:Read[9b0a]");
  assert.equal(extractEchoedContent(req([{ type: "text", text: "$MDU:Read[9b0a]" }])), "$MDU:Read[9b0a]");
});

test("extractEchoedContent: the Read gutter is stripped, every separator form", () => {
  assert.equal(extractEchoedContent(req(gutter(["# Title", "body line"]))), "# Title\nbody line");
  assert.equal(extractEchoedContent(req(gutter(["a", "b"], "\t", 0))), "a\nb");
  assert.equal(extractEchoedContent(req(gutter(["a", "b"], ":", 0))), "a\nb");
  // The separator splits once: an arrow, tab or colon in the content stays.
  assert.equal(extractEchoedContent(req(gutter(["a→b", "c\td", "e:f"]))), "a→b\nc\td\ne:f");
  // Empty and whitespace-only lines keep their bytes.
  assert.equal(extractEchoedContent(req(gutter(["", "  x  ", ""]))), "\n  x  \n");
  // Past 9 the number widens and the padding shrinks: still one gutter.
  const twelve = Array.from({ length: 12 }, (_, i) => `line ${i + 1}`);
  assert.equal(extractEchoedContent(req(gutter(twelve))), twelve.join("\n"));
  // The block-array content form unrenders the same way.
  assert.equal(extractEchoedContent(req([{ type: "text", text: gutter(["a", "b"]) }])), "a\nb");
});

test("extractEchoedContent: a final bare number is the empty line after a final newline", () => {
  assert.equal(extractEchoedContent(req(`${gutter(["a", "b"])}\n     3`)), "a\nb\n");
  assert.equal(extractEchoedContent(req(`${gutter(["a"])}\n2`)), "a\n");
  // With a reminder right after it (the separator trimmed).
  assert.equal(extractEchoedContent(req(`${gutter(["a"])}\n     2\n\n${SR("r")}`)), "a\n");
});

test("extractEchoedContent: trailing <system-reminder> blocks are dropped, one or many", () => {
  assert.equal(extractEchoedContent(req(`${gutter(["a", "b"])}\n\n${SR("budget")}\n`)), "a\nb");
  assert.equal(extractEchoedContent(req(`${gutter(["a"])}\n\n${SR("one")}\n\n${SR("two")}`)), "a");
  // On a non-Read body the reminder still goes and the rest stays verbatim.
  assert.equal(extractEchoedContent(req(`plain output\n${SR("x")}`)), "plain output");
  // Only a reminder: nothing left to echo.
  assert.equal(extractEchoedContent(req(SR("only"))), "");
});

test("extractEchoedContent: the twin note and a reminder both go", () => {
  assert.equal(extractEchoedContent(req(`${gutter(["a"])}\n\n${SR("r")}\n\n${NOTE}`)), "a");
  assert.equal(extractEchoedContent(req(`$MDU:Read[9b0a]\n\n${NOTE}`)), "$MDU:Read[9b0a]");
});

test("extractEchoedContent: a reminder-shaped span INSIDE the content is content (fixed 2026-09-29)", () => {
  // The old lazy pattern matched from the first reminder-shaped span to the
  // tail's closing tag and ate row 2 ("b") with it.
  const inner = "a <system-reminder>quoted</system-reminder>";
  assert.equal(extractEchoedContent(req(`${gutter([inner, "b"])}\n${SR("tail")}`)), `${inner}\nb`);
  // A reminder-shaped span with content after it and no tail reminder: kept.
  const mid = `x\n${SR("mid")}\ny`;
  assert.equal(extractEchoedContent(req(mid)), mid);
});

test("extractEchoedContent: CRLF and U+2028 rows unrender like the proxy's (fixed 2026-09-29)", () => {
  // `.` stopped at \r: a CRLF file's gutter was kept whole, while the proxy's
  // unrenderReadResult stores the file bytes behind the wrapped symbol.
  assert.equal(extractEchoedContent(req(gutter(["a\r", "b\r", "c"]))), "a\r\nb\r\nc");
  assert.equal(extractEchoedContent(req(gutter(["x y", "z "]))), "x y\nz ");
});

test("extractEchoedContent: anything short of a strict from-1 gutter is kept verbatim", () => {
  const keep = (body: string): void => assert.equal(extractEchoedContent(req(body)), body, JSON.stringify(body));
  keep("     5→offset read\n     6→starts past 1");   // not from 1 (an offset Read stays framed)
  keep("     1→a\n     3→skips 2");                  // not consecutive
  keep("     1→a\nno gutter here");                  // a row without one
  keep("     1→a\n     2\n     3→bare number mid");  // a bare number that is not the last row
  keep("     1→a\n     3");                          // a bare number with the wrong value
  keep("1");                                         // a lone "1" is Bash output, not an empty file
  keep("42");
  keep("     1→a\n     2→b\n");                      // a trailing newline: the proxy does not unrender it either
  keep("1 a\n2 b");                                  // a space is not a separator
  keep("→a");                                        // a separator with no number
  keep("");
});

test("extractEchoedContent: a from-1 `grep -n`-shaped Bash output reads as a gutter (pinned)", () => {
  // The fake does not know which tool produced the result, so output shaped
  // exactly like `1:…\n2:…` is unrendered too. No scenario echoes such output;
  // if one does, the vanilla echo loses numbers the wrapped echo keeps.
  assert.equal(extractEchoedContent(req("1:first\n2:second")), "first\nsecond");
});

test("extractEchoedContent / extractToolResultText: malformed requests", () => {
  const raw = (body: string): ParsedRequest => ({ url: "/v1/messages", body, hasToolResult: true });
  for (const body of ["not json", "", "null", "42", '"str"', "{}", '{"messages":null}', '{"messages":{}}', '{"messages":"x"}', '{"messages":[]}']) {
    assert.equal(extractEchoedContent(raw(body)), null, body);
    assert.equal(extractToolResultText(raw(body)), null, body);
  }
  // Messages without a tool_result: null (the scenarios print TOOL_RESULT_MISSING).
  assert.equal(extractEchoedContent(raw(JSON.stringify({ messages: [{ role: "user", content: "hi" }] }))), null);
  assert.equal(extractEchoedContent(raw(JSON.stringify({ messages: [{ role: "user", content: [{ type: "text", text: "hi" }] }] }))), null);
  // Null messages and null or scalar blocks are skipped, not fatal.
  const holes = JSON.stringify({ messages: [null, { content: [null, 7, { type: "tool_result", content: "$MDU:Read[1]" }] }] });
  assert.equal(extractEchoedContent(raw(holes)), "$MDU:Read[1]");
});

test("extractToolResultText: the LAST tool_result decides even when it carries no text (fixed 2026-09-29)", () => {
  const two = (lastContent: unknown): ParsedRequest => ({
    url: "/v1/messages",
    hasToolResult: true,
    body: JSON.stringify({
      messages: [
        { role: "user", content: [{ type: "tool_result", tool_use_id: "t1", content: "EARLIER" }] },
        { role: "user", content: [{ type: "tool_result", tool_use_id: "t2", content: lastContent }] },
      ],
    }),
  });
  // Before the fix each of these returned "EARLIER", the previous turn's result.
  assert.equal(extractToolResultText(two([{ type: "image", source: { type: "base64", data: "AA==" } }])), "");
  assert.equal(extractToolResultText(two([])), "");
  assert.equal(extractToolResultText(two(undefined)), "");
  assert.equal(extractToolResultText(two(12)), "");
  // Malformed text blocks are skipped; the well-formed ones still count.
  assert.equal(extractToolResultText(two([{ type: "text", text: 5 }, { type: "text", text: "ok" }, null])), "ok");
  assert.equal(extractEchoedContent(two([{ type: "image" }])), "");
  assert.equal(extractToolResultText(two("LATER")), "LATER");
});
