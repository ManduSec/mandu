/**
 * Unit tests for prompt-filter-core.ts, the protocol-neutral half of the
 * prompt filter (confidentiality-plan-15-prompt-filter.md §3, §7), over a
 * hand-built segmentation and an inline arbiter, so the one suite runs
 * unchanged in both model proxies. ONE SUITE, TWO COPIES: copied VERBATIM to
 * interceptors/openai-proxy/test/unit/ with the module; the source is the
 * anthropic-proxy copy (`node scripts/copies/module-copies.mjs generate`).
 * Each proxy's prompt-filter tests cover its segmenter and the whole path.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import type { FilterPromptResult } from "../../src/arbiter-client.js";
import { filterSegments, PromptBlocked, PromptFilterRefusal, type Segmentation, type SlotPieces } from "../../src/prompt-filter-core.js";

const SECRET = "hunter2-correct-horse";
const SYMBOL = "$MDU:secret_env[1a2b]";

/** One user text as a whole segment of `origin`; `box.text` is what the
 *  request holds after the filter. */
function oneText(text: string, origin: "human" | "side-call", sideCall: boolean): { seg: Segmentation; box: { text: string } } {
  const box = { text };
  const slot: SlotPieces = {
    slot: { get: () => box.text, set: (t) => { box.text = t; } },
    text,
    pieces: [{ start: 0, end: text.length, origin, id: "m0.p0" }],
    sideCall,
  };
  return { seg: { slots: [slot], segments: [{ id: "m0.p0", origin, text }] }, box };
}

/** An arbiter that masks SECRET wherever it is, and answers `action` for a
 *  segment holding it. */
function masking(action: "rewrite" | "block" = "rewrite") {
  const calls: unknown[] = [];
  return {
    calls,
    async filterPrompt(req: { segments: Array<{ id: string; origin: string; text: string }> }): Promise<FilterPromptResult> {
      calls.push(req);
      return {
        enforcing: true,
        dryRun: false,
        digest: { policy: "p", packs: "k", values: "v" },
        segments: req.segments.map((s) => {
          const at = s.text.indexOf(SECRET);
          if (at < 0) return { id: s.id, origin: s.origin as "human", action: "pass" as const, findings: [], skipped: 0, cached: false };
          return {
            id: s.id, origin: s.origin as "human", action, text: s.text.replace(SECRET, SYMBOL),
            ...(action === "block" ? { reason: "blocked by test" } : {}),
            findings: [{ start: at, end: at + SECRET.length, category: "secret", filterId: "registered-values", action: action === "block" ? "block" as const : "mask" as const, symbol: SYMBOL }],
            skipped: 0, cached: false,
          };
        }),
      };
    },
  };
}

test("a masked side call gets the caller's note after a blank line; without one, nothing is appended", async () => {
  const withNote = oneText(`summarize ${SECRET}`, "side-call", true);
  const report = await filterSegments(withNote.seg, masking(), { agent: "generic", sideCallNote: "[note]" });
  assert.equal(withNote.box.text, `summarize ${SYMBOL}\n\n[note]`);
  assert.deepEqual(report?.replaced, [SYMBOL]);

  const without = oneText(`summarize ${SECRET}`, "side-call", true);
  await filterSegments(without.seg, masking(), { agent: "generic" });
  assert.equal(without.box.text, `summarize ${SYMBOL}`);
});

test("the note is for side calls only, and only when the text changed", async () => {
  const human = oneText(`deploy with ${SECRET}`, "human", false);
  await filterSegments(human.seg, masking(), { agent: "generic", sideCallNote: "[note]" });
  assert.equal(human.box.text, `deploy with ${SYMBOL}`);

  const clean = oneText("a title for this chat", "side-call", true);
  const report = await filterSegments(clean.seg, masking(), { agent: "generic", sideCallNote: "[note]" });
  assert.equal(clean.box.text, "a title for this chat");
  assert.deepEqual(report?.segments.map((s) => s.action), ["pass"]);
});

test("fail-closed: an arbiter error, an unanswered segment or a first-seen block refuses, and the text is left as it was", async () => {
  const down = oneText(`x ${SECRET}`, "human", false);
  await assert.rejects(
    filterSegments(down.seg, { async filterPrompt() { throw new Error("arbiter down"); } }, { agent: "generic" }),
    PromptFilterRefusal,
  );
  assert.equal(down.box.text, `x ${SECRET}`);

  const silent = oneText(`x ${SECRET}`, "human", false);
  const empty = async (): Promise<FilterPromptResult> => ({ enforcing: true, dryRun: false, digest: { policy: "", packs: "", values: "" }, segments: [] });
  await assert.rejects(filterSegments(silent.seg, { filterPrompt: empty }, { agent: "generic" }), PromptFilterRefusal);
  assert.equal(silent.box.text, `x ${SECRET}`);

  const blocked = oneText(`x ${SECRET}`, "human", false);
  await assert.rejects(filterSegments(blocked.seg, masking("block"), { agent: "generic", sessionKey: "s" }), PromptBlocked);
});

test("nothing to ask: no op (an in-test arbiter) or no segment answers null and calls nothing", async () => {
  const t = oneText(`x ${SECRET}`, "human", false);
  assert.equal(await filterSegments(t.seg, {}, { agent: "generic" }), null);
  const arbiter = masking();
  assert.equal(await filterSegments({ slots: [], segments: [] }, arbiter, { agent: "generic" }), null);
  assert.equal(arbiter.calls.length, 0);
  assert.equal(t.box.text, `x ${SECRET}`);
});
