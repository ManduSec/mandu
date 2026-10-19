/**
 * prompt-filter-own-write.test — the engine's exemption for a HIGH session's
 * own write (confidentiality-plan-15-prompt-filter.md §13.10). Mandu-new.
 *
 * Proves, on the engine with a scripted `ownWrites`:
 *   - a registered value the session's exempt set covers passes in that
 *     session's `human` segment as typed, reported as a `log` finding;
 *   - the same value in `harness` and `side-call` text is still masked;
 *   - another session (no exempt set) gets the mask, and never the exempt
 *     answer from the cache, whichever session asked first;
 *   - when the set changes (the signature), the session's turn is rescanned;
 *   - an uncovered registered value in the same human segment is still
 *     masked, and the residual scan does not take the whole segment for the
 *     exempt value left in it;
 *   - with the axis OFF nothing changes (every finding `log`).
 *
 * Axes: secrets (stated), with the engine's `enforcing` switch driven
 * explicitly for the `off` case.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { PromptFilterEngine, type PromptSegmentIn, type SessionOwnWrites } from "../../prompt-filter/engine.js";
import { RegisteredValueFilter } from "../../prompt-filter/registered-value-filter.js";
import { RegisteredValueIndex } from "../../prompt-filter/registered-values.js";
import { allocateSymbol, type SymbolMap } from "../../symbol-table/symbol-table.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

const SENTENCE = "The deal closes in the third quarter.";
const KEY = "sk-live-Zq81Hc0vNw3PpL6tYb";
const ASK = `Write a file named summary.md containing the sentence: ${SENTENCE}`;

function setup(opts: { enforcing?: boolean } = {}) {
  const map: SymbolMap = { symbols: new Map() };
  // summary.md as the derived label registers it: the file's text, a line.
  const own = allocateSymbol(map, { tool: "Read", value: `${SENTENCE}\n`, confidentiality: "any-model" });
  const key = allocateSymbol(map, { tool: "env", value: KEY, confidentiality: "no-model" });
  const index = new RegisteredValueIndex();
  const exempt = new Map<string, SessionOwnWrites>();
  const asked: string[] = [];
  const engine = new PromptFilterEngine({
    filters: [new RegisteredValueFilter({
      index: () => { index.sync(map); return index; },
      rowLevel: (s) => {
        const e = map.symbols.get(s);
        return e && e.obsoleted_at === null && e.confidentiality !== "public" ? e.confidentiality : null;
      },
    })],
    enforcing: () => opts.enforcing ?? true,
    mint: (value, level) => allocateSymbol(map, { tool: "prompt_filter", value, confidentiality: level }),
    values: () => { index.sync(map); return { version: index.contentVersion, digest: index.digest }; },
    ownWrites: (session) => { asked.push(session); return exempt.get(session) ?? null; },
  });
  const grant = (session: string, signature = "v1"): void => {
    // As the server's: the file's own row, or the prompt filter's mask of a
    // piece of it (minted when the text was masked before).
    exempt.set(session, {
      signature,
      covers: (s) => {
        const e = map.symbols.get(s);
        return s === own || (e?.tool === "prompt_filter" && `${SENTENCE}\n`.includes(e.value));
      },
    });
  };
  return { map, own, key, engine, grant, exempt, asked };
}

const seg = (id: string, origin: PromptSegmentIn["origin"], text: string): PromptSegmentIn => ({ id, origin, text });

test("the writer session's human text keeps its own sentence; harness and side-call text are masked", async () => {
  const { engine, grant } = setup();
  grant("A");
  const out = await engine.run([
    seg("h", "human", ASK),
    seg("r", "harness", `<system-reminder>${SENTENCE}</system-reminder>`),
    seg("s", "side-call", `Title for: ${SENTENCE}`),
  ], { session: "A" });
  const [h, r, s] = out.segments;
  assert.equal(h!.action, "pass");
  assert.equal(h!.text, undefined, "a pass carries no rewritten text: the human's own goes");
  assert.deepEqual(h!.findings.map((f) => [f.category, f.action]), [["secret.registered", "log"]], "reported, not enacted");
  assert.equal(r!.action, "rewrite");
  assert.ok(!r!.text!.includes("third quarter"), "harness text keeps the floor");
  assert.equal(s!.action, "rewrite");
  assert.ok(!s!.text!.includes("third quarter"), "side-call text keeps the floor");
});

test("another session gets the mask, and the cache never crosses sessions", async () => {
  const { engine, grant } = setup();
  grant("A");
  const a1 = (await engine.run([seg("h", "human", ASK)], { session: "A" })).segments[0]!;
  assert.equal(a1.action, "pass");
  const b = (await engine.run([seg("h", "human", ASK)], { session: "B" })).segments[0]!;
  assert.equal(b.action, "rewrite", "B is not the writer");
  assert.equal(b.cached, false, "B's answer is its own scan, not A's cached one");
  assert.ok(!b.text!.includes("third quarter"));
  const none = (await engine.run([seg("h", "human", ASK)])).segments[0]!;
  assert.equal(none.action, "rewrite", "no session, no exemption");
  // And the other order: B's masked answer is not served to A.
  const { engine: e2, grant: g2 } = setup();
  const b2 = (await e2.run([seg("h", "human", ASK)], { session: "B" })).segments[0]!;
  assert.equal(b2.action, "rewrite");
  g2("A");
  const a2 = (await e2.run([seg("h", "human", ASK)], { session: "A" })).segments[0]!;
  assert.equal(a2.action, "pass");
  assert.equal(a2.cached, false);
  // A's resend is a cache hit of A's own answer.
  const a3 = (await e2.run([seg("h", "human", ASK)], { session: "A" })).segments[0]!;
  assert.deepEqual([a3.action, a3.cached], ["pass", true]);
});

test("a change of the exempt set rescans the session's turn", async () => {
  const { engine, grant, exempt } = setup();
  grant("A");
  assert.equal((await engine.run([seg("h", "human", ASK)], { session: "A" })).segments[0]!.action, "pass");
  // Another session became the file's last writer: the set is gone.
  exempt.delete("A");
  const after = (await engine.run([seg("h", "human", ASK)], { session: "A" })).segments[0]!;
  assert.deepEqual([after.action, after.cached], ["rewrite", false]);
  // A new signature (the set changed again) is a new key.
  grant("A", "v2");
  const again = (await engine.run([seg("h", "human", ASK)], { session: "A" })).segments[0]!;
  assert.deepEqual([again.action, again.cached], ["pass", false]);
});

test("an uncovered registered value beside the exempt one is masked; the residual scan spares the exempt sentence", async () => {
  const { engine, grant, key } = setup();
  grant("A");
  const text = `${ASK} Also use ${KEY}.`;
  const h = (await engine.run([seg("h", "human", text)], { session: "A" })).segments[0]!;
  assert.equal(h.action, "rewrite");
  assert.equal(h.text, `${ASK} Also use ${key}.`, "only the key becomes a symbol");
  assert.deepEqual(h.findings.map((f) => f.action).sort(), ["log", "mask"]);
});

test("with the axis OFF the exempt set is not even asked for; every finding is log", async () => {
  const { engine, grant, asked } = setup({ enforcing: false });
  grant("A");
  const h = (await engine.run([seg("h", "human", ASK)], { session: "A" })).segments[0]!;
  assert.equal(h.action, "pass");
  assert.deepEqual(asked, []);
});
