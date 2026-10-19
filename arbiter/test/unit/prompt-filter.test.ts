/**
 * prompt-filter.test — the `filterPrompt` engine and the registered-value
 * filter (confidentiality-plan-15-prompt-filter.md §3.2, §3.3, §4.1, phase 1).
 * Mandu-new.
 *
 * Proves: the prompt floor (a short or low-entropy registered value such as
 * `postgres` passes in a `human` segment and is counted, never named, while
 * the same value is masked in `harness` and `side-call` segments); a
 * registered value becomes its OWN symbol; a line of a multi-line secret and
 * overlapping values are minted once at the strictest level; the cache keeps
 * every symbol stable across resends and rescans when the registered set
 * changes; a dry run mints nothing and caches nothing; with the
 * confidentiality axis OFF every finding is `log` and nothing is rewritten; a
 * failed mint throws (the op errors, the proxy refuses).
 *
 * Axes: secrets (stated), with the engine's `enforcing` switch driven
 * explicitly for the `off`-mode case.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { PromptFilterEngine, parseSegments, WOULD_MINT, type PromptSegmentIn } from "../../prompt-filter/engine.js";
import { RegisteredValueFilter, belowPromptFloor, PROMPT_FLOOR_MIN_LEN } from "../../prompt-filter/registered-value-filter.js";
import { RegisteredValueIndex } from "../../prompt-filter/registered-values.js";
import { allocateSymbol, type SymbolMap } from "../../symbol-table/symbol-table.js";
import type { ConfidentialityLevel } from "../../symbol-table/confidentiality.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

const KEY = "sk-live-Zq81Hc0vNw3PpL6tYb";
const WEAK = "postgres";
const DOC = "line one of the contract\nAcme agrees to pay 4,200,000 USD on 2026-09-30.\nend";

function setup(opts: { enforcing?: boolean } = {}) {
  const map: SymbolMap = { symbols: new Map() };
  const key = allocateSymbol(map, { tool: "env", value: KEY, confidentiality: "no-model" });
  const weak = allocateSymbol(map, { tool: "env", value: WEAK, confidentiality: "no-model" });
  const doc = allocateSymbol(map, { tool: "Read", value: DOC, confidentiality: "local-model" });
  const index = new RegisteredValueIndex();
  const minted: Array<{ value: string; level: ConfidentialityLevel; origin: string }> = [];
  let failMint = false;
  const engine = new PromptFilterEngine({
    filters: [new RegisteredValueFilter({
      index: () => { index.sync(map); return index; },
      rowLevel: (s) => {
        const e = map.symbols.get(s);
        return e && e.obsoleted_at === null && e.confidentiality !== "public" ? e.confidentiality : null;
      },
    })],
    enforcing: () => opts.enforcing ?? true,
    mint: (value, level, origin) => {
      if (failMint) throw new Error("mint failed");
      minted.push({ value, level, origin });
      return allocateSymbol(map, { tool: "prompt_filter", value, confidentiality: level });
    },
    values: () => { index.sync(map); return { version: index.contentVersion, digest: index.digest }; },
  });
  return { map, key, weak, doc, engine, minted, failMint: () => { failMint = true; } };
}

const seg = (id: string, origin: PromptSegmentIn["origin"], text: string): PromptSegmentIn => ({ id, origin, text });

test("the prompt floor: postgres passes in the human's text (counted), is masked in harness and side-call text", async () => {
  assert.ok(belowPromptFloor(WEAK) && !belowPromptFloor(KEY));
  assert.equal(PROMPT_FLOOR_MIN_LEN, 12);
  assert.ok(belowPromptFloor("aaaaaaaaaaaaaaaa"), "long but low entropy is below the floor");
  const { engine, weak } = setup();
  const out = (await engine.run([
    seg("h", "human", `connect with ${WEAK} please`),
    seg("r", "harness", `<system-reminder>DB_PASSWORD=${WEAK}</system-reminder>`),
    seg("s", "side-call", `Web page content: --- ${WEAK} ---`),
  ]));
  const [h, r, s] = out.segments;
  assert.equal(h!.action, "pass");
  assert.equal(h!.skipped, 1);
  assert.deepEqual(h!.findings, []);
  assert.ok(!JSON.stringify(h).includes(weak), "a skipped value is never named");
  assert.equal(r!.action, "rewrite");
  assert.equal(r!.text, `<system-reminder>DB_PASSWORD=${weak}</system-reminder>`);
  assert.equal(r!.skipped, 0);
  assert.equal(s!.text, `Web page content: --- ${weak} ---`);
  assert.equal(s!.findings[0]!.action, "mask");
  assert.equal(s!.findings[0]!.category, "secret.registered");
  assert.equal(s!.findings[0]!.filterId, "registered-value");
});

test("a registered key in the human's text becomes its own symbol; offsets are the original's", async () => {
  const { engine, key, minted } = setup();
  const text = `use ${KEY} and ${KEY}`;
  const [h] = (await engine.run([seg("h", "human", text)])).segments;
  assert.equal(h!.action, "rewrite");
  assert.equal(h!.text, `use ${key} and ${key}`);
  assert.deepEqual(h!.findings.map((f) => [f.start, f.end, f.symbol, f.how]), [
    [4, 4 + KEY.length, key, "value"],
    [9 + KEY.length, 9 + 2 * KEY.length, key, "value"],
  ]);
  assert.equal(text.slice(h!.findings[0]!.start, h!.findings[0]!.end), KEY);
  assert.equal(minted.length, 0, "nothing new is stored for a registered value");
});

test("a line of a multi-line secret is minted at the row's level; overlapping values merge into one strict mint", async () => {
  const { engine, minted, map } = setup();
  const line = "Acme agrees to pay 4,200,000 USD on 2026-09-30.";
  const [h] = (await engine.run([seg("h", "human", `> ${line}`)])).segments;
  assert.equal(h!.action, "rewrite");
  assert.equal(minted.length, 1);
  assert.deepEqual(minted[0], { value: line, level: "local-model", origin: "human" });
  assert.equal(h!.findings[0]!.how, "line");
  // Two registered values that overlap: one span, the stricter level.
  const a = allocateSymbol(map, { tool: "env", value: "OVERLAP-AAAA-1234", confidentiality: "any-model" });
  void a;
  allocateSymbol(map, { tool: "env", value: "1234-BBBB-OVERLAP", confidentiality: "no-model" });
  const [o] = (await engine.run([seg("o", "harness", "x OVERLAP-AAAA-1234-BBBB-OVERLAP y")])).segments;
  assert.equal(o!.findings.length, 1);
  assert.equal(o!.findings[0]!.how, "merged");
  assert.deepEqual(minted.at(-1), { value: "OVERLAP-AAAA-1234-BBBB-OVERLAP", level: "no-model", origin: "harness" });
});

test("the cache: symbols are stable across resends; a newly registered value rescans an earlier turn", async () => {
  const { engine, map, minted } = setup();
  const line = "Acme agrees to pay 4,200,000 USD on 2026-09-30.";
  const turn1 = [seg("1", "human", `see ${line} and ${KEY}`)];
  const first = (await engine.run(turn1)).segments[0]!;
  // The mint added a secret row, so the next request rescans once: the
  // minted row now matches the line exactly and is reused.
  const second = (await engine.run(turn1)).segments[0]!;
  assert.equal(second.text, first.text);
  const again = (await engine.run([...turn1, seg("2", "human", "next turn")])).segments;
  assert.equal(again[0]!.cached, true);
  assert.equal(again[0]!.text, first.text, "the resend reads the same symbols");
  assert.equal(minted.length, 1, "the line was minted once");
  assert.equal(again[1]!.cached, false);
  // A value registered after turn 2 was sent: the next request masks it.
  const late = allocateSymbol(map, { tool: "env", value: "LATE-REGISTERED-9x8y7z", confidentiality: "no-model" });
  const t3 = (await engine.run([seg("3", "human", "it was LATE-REGISTERED-9x8y7z"), ...turn1])).segments;
  assert.equal(t3[0]!.text, `it was ${late}`);
  assert.equal(t3[1]!.cached, false, "the registered set changed: rescanned");
  assert.equal(t3[1]!.text, first.text, "…and the rescan mints nothing new (the reuse key)");
});

test("a dry run mints nothing, caches nothing, and shows the existing symbol of a registered value", async () => {
  const { engine, minted, key } = setup();
  const line = "Acme agrees to pay 4,200,000 USD on 2026-09-30.";
  const out = (await engine.run([seg("t", "human", `${KEY} / ${line}`)], { dryRun: true }));
  assert.equal(out.dryRun, true);
  assert.equal(out.segments[0]!.text, `${key} / ${WOULD_MINT}`);
  assert.equal(minted.length, 0);
  assert.equal(engine.cacheSize, 0);
});

test("confidentiality axis OFF (mode off): every finding is log, nothing is rewritten", async () => {
  const { engine, minted } = setup({ enforcing: false });
  const out = (await engine.run([seg("h", "harness", `token ${KEY}`)]));
  assert.equal(out.enforcing, false);
  assert.equal(out.segments[0]!.action, "pass");
  assert.equal(out.segments[0]!.text, undefined);
  assert.deepEqual(out.segments[0]!.findings.map((f) => f.action), ["log"]);
  assert.equal(minted.length, 0);
});

test("a failed mint throws (fail-closed), and malformed segments are refused", async () => {
  const { engine, failMint } = setup();
  failMint();
  await assert.rejects(() => (engine.run([seg("h", "human", "Acme agrees to pay 4,200,000 USD on 2026-09-30.")])), /mint failed/);
  assert.match(String(parseSegments("x")), /array/);
  assert.match(String(parseSegments([{ id: "a", origin: "tool", text: "" }])), /origin/);
  assert.match(String(parseSegments([{ id: "a", origin: "human", text: "" }, { id: "a", origin: "human", text: "" }])), /repeats/);
  assert.deepEqual(parseSegments([{ id: "a", origin: "side-call", text: "t" }]), [{ id: "a", origin: "side-call", text: "t" }]);
});
