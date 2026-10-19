/**
 * declassify-words.test — the agent's request for a secret's real value
 * (`declassify_symbol`) in the product page's words (dashboard.md §4.25b,
 * "A request for a secret's real value"). Contracts:
 *   - only the spellings Mandu's own mount produces count (Claude Code,
 *     OpenCode, Codex, Goose, OpenClaw's bare plugin tool); another
 *     server's tool of the same name does not;
 *   - the answer comes only from the relay's fixed openings: released, the
 *     person asked, refused; anything else (masked, missing, another shape,
 *     the notice not at the start) says nothing;
 *   - no answer repeats the value or the refusal's reason, and none holds an
 *     inspector term or a token.
 * The real texts, from the real relay over a real arbiter, are pinned in
 * tests/stack/declassify-words.test.ts.
 *
 * Axes: none (pure presentation over recorded text).
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { MANDU_DECLASSIFY_TOOL_SPELLINGS, declassifyAnswer, isManduDeclassify } from "../../../src/view-model/declassify-words.js";

const FORBIDDEN = /\b(symboliz|desymboliz|declassif|egress|invariant|T-LLM|U-LLM|quarantin|AgentView|HumanView|watermark|arbiter|placeholder|HIGH)\b|\$MDU:/i;

// The relay's texts (interceptors/inspect-mcp/src/declassify-symbol.ts).
const NOTICE = "[DECLASSIFIED — this session is now HIGH (any-model). Requests to the hosts this content is bound to still go through; any other network request or shell command that could carry it out is stopped while Mandu asks the user on its Approvals page. Keep making the calls the user asks for and let Mandu decide each one: never refuse one yourself or ask the user to approve it first; if Mandu stops one, tell the user and make it again after they answer. Do not repeat this content into any tool call you would not want released.]";
const VALUE = "Deal memo: margin 31 percent. VALUE_CANARY";
const REFUSED = "declassify_symbol: REFUSED: no-model data is readable by NO model. If the model must read it, relabel the file any-model — that is a deliberate change to the standing release surface, not an approval. This is by design — do not retry.";
const ASKED = "declassify_symbol: session has ingested untrusted data — queued for the user's approval The user has been asked to approve this; stop and tell them you are waiting.";

test("only Mandu's own spellings count: Claude Code, OpenCode, Codex, Goose, OpenClaw's plugin; never another server's tool", () => {
  assert.deepEqual([...MANDU_DECLASSIFY_TOOL_SPELLINGS].sort(), [
    "declassify_symbol",
    "mandu-inspect__declassify_symbol",
    "mandu-inspect_declassify_symbol",
    "mcp__mandu-inspect__declassify_symbol",
    "mcp__mandu_inspect__declassify_symbol",
  ]);
  for (const s of MANDU_DECLASSIFY_TOOL_SPELLINGS) assert.equal(isManduDeclassify(s), true, s);
  for (const s of ["mcp__evil__declassify_symbol", "mcp__mandu-inspect__inspect_symbol", "Declassify_symbol", "declassify_symbol ", "mcp__mandu-policy__declassify_symbol", ""]) {
    assert.equal(isManduDeclassify(s), false, s);
  }
});

test("the relay's answers in the page's words: released, the person asked, refused", () => {
  const released = declassifyAnswer(`${NOTICE}\n\n${VALUE}`);
  assert.equal(released, "Mandu gave the AI the real value. From then on, a request or command of this session that could carry it to a place it may not go waits for your OK in Approvals.");
  assert.equal(declassifyAnswer(NOTICE), released, "a released empty value");
  assert.equal(declassifyAnswer(`[DECLASSIFIED — this session is now HIGH (secret). x]\n\n${VALUE}`), released, "a watermark the relay did not name");
  assert.equal(declassifyAnswer(ASKED), "Mandu asked for your OK in Approvals first, so the AI did not get the real value.");
  assert.equal(declassifyAnswer(REFUSED), "Mandu did not give the AI the real value.");
  assert.equal(declassifyAnswer("declassify_symbol: 'symbol' is required"), "Mandu did not give the AI the real value.");
  assert.equal(declassifyAnswer("declassify_symbol: arbiter error: connect ECONNREFUSED"), "Mandu did not give the AI the real value.", "an arbiter that cannot answer releases nothing");
  assert.equal(declassifyAnswer("declassify_symbol: The user has been asked to approve this; stop and tell them you are waiting. Then more."), "Mandu did not give the AI the real value.", "the person was asked only when the relay's line ends the text");
  for (const a of [released, declassifyAnswer(ASKED), declassifyAnswer(REFUSED)]) {
    assert.doesNotMatch(String(a), FORBIDDEN);
    assert.doesNotMatch(String(a), /VALUE_CANARY|relabel|untrusted|by design/, "never the value nor the refusal's reason");
  }
});

test("anything that is not one of the relay's answers says nothing", () => {
  for (const r of [
    null,
    "",
    "$MDU:anymodel_mcp__mandu-inspect__declassify_symbol[7c7c]", // masked
    VALUE, // a value with no notice
    ` ${NOTICE}\n\n${VALUE}`, // not at the start
    `${VALUE}\n${NOTICE}`,
    "[DECLASSIFIED — two\nlines]\n\nx", // the notice is one line
    "[DECLASSIFIED — no close", // no bracket closes it
    "[DECLASSIFIED — x] and more on its line", // the notice is a line of its own
    "Error: declassify_symbol: REFUSED", // another wrapper
    "inspect_symbol: refused",
    `${REFUSED.replace("declassify_symbol: ", "")}`,
  ]) assert.equal(declassifyAnswer(r), null, JSON.stringify(r));
});
