/**
 * prompt-filter-actions.test — the engine under a `prompt_filters:` policy
 * (confidentiality-plan-15-prompt-filter.md §4, §4.4, §6, §7, phase 2).
 * Mandu-new.
 *
 * Proves, over the real filters (registered-value, key-shapes, a pack):
 *   - `redact` replaces the span with `[redacted: <category>]` and stores
 *     nothing; `log` reports and changes nothing; `mask` of a non-registered
 *     finding mints one symbol at the finding's level (default no-model);
 *   - `block` answers the segment block with a reason that names the
 *     category and never the value, AND a safe text with the blocked span as
 *     `[blocked: <category>]` and every other action applied;
 *   - overlapping findings take the strictest action;
 *   - an exception lets a matching finding through, on the human's text only;
 *   - harness and side-call text get the registered-value floor only, whatever
 *     the policy says (key-shapes on, registered-value off for the human);
 *   - §4.4: a pack switched on but missing, or a filter that throws, blocks
 *     with NO text under `on_error: block` (the default for an enforcing
 *     filter), and is skipped under `on_error: pass`;
 *   - with the confidentiality axis off every finding is `log`;
 *   - a policy change changes the cache key (rescanned, never a stale answer).
 *
 * Axes: secrets (stated), with the engine's `enforcing` switch driven
 * explicitly for the `off`-mode case.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { PromptFilterEngine, type PromptPolicyInput, type PromptSegmentIn } from "../../prompt-filter/engine.js";
import { RegisteredValueFilter } from "../../prompt-filter/registered-value-filter.js";
import { RegisteredValueIndex } from "../../prompt-filter/registered-values.js";
import { KeyShapesFilter } from "../../prompt-filter/key-shapes-filter.js";
import { PackFilter, parsePackText } from "../../prompt-filter/packs.js";
import { effectivePromptConfig, type PromptFiltersConfig } from "../../prompt-filter/policy.js";
import type { PromptFilter } from "../../prompt-filter/filter.js";
import { allocateSymbol, type SymbolMap } from "../../symbol-table/symbol-table.js";
import type { ConfidentialityLevel } from "../../symbol-table/confidentiality.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

const KEY = "Pw-Zq81Hc0vNw3PpL6tYbQ"; // registered, not key-shaped
const GH = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";
const CARD = "4111 1111 1111 1111";

const PACK = parsePackText(`pack: acme-dlp
version: 1
patterns:
  - id: card
    category: pii.payment-card
    regex: '\\b(?:\\d[ -]?){13,19}\\b'
    check: luhn
  - id: email
    category: pii.email
    regex: '[a-z0-9.]+@[a-z0-9.-]+\\.[a-z]{2,}'
keywords:
  - category: acme.codename
    words: [falcon]
    level: local-model
`);
if (!("doc" in PACK)) throw new Error(JSON.stringify(PACK));
const packFilter = new PackFilter({ doc: PACK.doc, source: "user", file: "/x/acme.yaml", signedBy: null, digest: "d1" });

function setup(cfg: PromptFiltersConfig | null, opts: { enforcing?: boolean; packs?: Map<string, PromptFilter>; unavailable?: Map<string, string> } = {}) {
  const map: SymbolMap = { symbols: new Map() };
  const key = allocateSymbol(map, { tool: "env", value: KEY, confidentiality: "no-model" });
  const index = new RegisteredValueIndex();
  const minted: Array<{ value: string; level: ConfidentialityLevel; origin: string }> = [];
  let policy: PromptPolicyInput = {
    config: effectivePromptConfig(cfg),
    packs: opts.packs ?? new Map([["acme-dlp", packFilter]]),
    ...(opts.unavailable ? { unavailable: opts.unavailable } : {}),
    packsDigest: "p1",
  };
  const engine = new PromptFilterEngine({
    filters: [new RegisteredValueFilter({
      index: () => { index.sync(map); return index; },
      rowLevel: (s) => {
        const e = map.symbols.get(s);
        return e && e.obsoleted_at === null && e.confidentiality !== "public" ? e.confidentiality : null;
      },
    }), new KeyShapesFilter()],
    policy: () => policy,
    enforcing: () => opts.enforcing ?? true,
    mint: (value, level, origin) => {
      minted.push({ value, level, origin });
      return allocateSymbol(map, { tool: "prompt_filter", value, confidentiality: level });
    },
    values: () => { index.sync(map); return { version: index.contentVersion, digest: index.digest }; },
  });
  return { engine, key, minted, setPolicy: (c: PromptFiltersConfig) => { policy = { ...policy, config: effectivePromptConfig(c) }; } };
}

const seg = (id: string, origin: PromptSegmentIn["origin"], text: string): PromptSegmentIn => ({ id, origin, text });

test("redact, log and mask of non-registered findings; the registered value keeps its own symbol", async () => {
  const { engine, key, minted } = setup({
    filters: { "key-shapes": "on", "acme-dlp": "on" },
    actions: { "pii.email": "log", "acme.codename": "mask" },
  });
  const text = `push ${GH} as ${KEY} for falcon, mail bob@acme.example`;
  const [h] = (await engine.run([seg("h", "human", text)])).segments;
  assert.equal(h!.action, "rewrite");
  assert.deepEqual(minted.map((m) => [m.value, m.level, m.origin]), [["falcon", "local-model", "human"]], "only the opted-in mask stores a value");
  const falcon = h!.findings.find((f) => f.category === "acme.codename")!.symbol!;
  assert.match(falcon, /^\$MDU:/);
  assert.equal(h!.text, `push [redacted: secret.shape.github-token] as ${key} for ${falcon}, mail bob@acme.example`);
  assert.ok(!h!.text!.includes(GH) && !h!.text!.includes(KEY));
  assert.deepEqual(h!.findings.map((f) => [f.category, f.filterId, f.action]), [
    ["secret.shape.github-token", "key-shapes", "redact"],
    ["secret.registered", "registered-value", "mask"],
    ["acme.codename", "acme-dlp", "mask"],
    ["pii.email", "acme-dlp", "log"],
  ]);
  assert.ok(!JSON.stringify(h!.findings).includes(GH), "a finding carries offsets and a category, never the value");
});

test("block: a reason without the value, and a safe text with every span applied", async () => {
  const { engine, key } = setup({ filters: { "acme-dlp": "on" }, actions: { "pii.payment-card": "block" } });
  const text = `card ${CARD}, and key ${KEY} for falcon`;
  const [h] = (await engine.run([seg("h", "human", text)])).segments;
  assert.equal(h!.action, "block");
  assert.match(h!.reason!, /Mandu blocked this prompt: it contains pii\.payment-card \(acme-dlp\)/);
  assert.ok(!h!.reason!.includes(CARD));
  assert.equal(h!.text, `card [blocked: pii.payment-card], and key ${key} for [redacted: acme.codename]`);
  // Not a check-valid card: nothing to block.
  const [n] = (await engine.run([seg("n", "human", "card 4111 1111 1111 1112")])).segments;
  assert.equal(n!.action, "pass");
});

test("overlapping findings take the strictest action; an exception lets a match through on the human's text only", async () => {
  const { engine } = setup({
    filters: { "acme-dlp": "on" },
    actions: { "pii.email": "redact", "acme.codename": "block" },
    exceptions: [{ category: "pii.email", match: "*@example.com" }],
  });
  const [o] = (await engine.run([seg("o", "human", "write to falcon@acme.example")])).segments;
  assert.equal(o!.action, "block", "the codename inside the address blocks the whole span");
  assert.equal(o!.text, "write to [blocked: acme.codename]");
  const [e] = (await engine.run([seg("e", "human", "write to bob@example.com or eve@evil.example")])).segments;
  assert.equal(e!.text, "write to bob@example.com or [redacted: pii.email]");
});

test("harness and side-call text: the registered-value floor whatever its switch, the policy's filters too, and block acts as redact", async () => {
  const { engine, key } = setup({ filters: { "registered-value": "off", "key-shapes": "on", "acme-dlp": "on" }, actions: { pii: "block" }, exceptions: [{ category: "pii.email", match: "*@example.com" }] });
  const out = (await engine.run([
    seg("h", "human", `mine ${KEY} ${GH}`),
    seg("r", "harness", `<system-reminder>${KEY} ${GH} ${CARD}, bob@example.com</system-reminder>`),
    seg("s", "side-call", `Write a title for: pay ${CARD}, with ${KEY}`),
  ])).segments;
  assert.equal(out[0]!.text, `mine ${KEY} [redacted: secret.shape.github-token]`, "registered-value off for the human: the key goes as typed");
  assert.equal(out[1]!.action, "rewrite", "text the human did not send is never refused");
  assert.equal(out[1]!.text, `<system-reminder>${key} [redacted: secret.shape.github-token] [redacted: pii.payment-card], bob@example.com</system-reminder>`,
    "the floor masks the key; key-shapes redacts; the card's block acts as redact; the exception holds");
  assert.equal(out[2]!.action, "rewrite");
  assert.equal(out[2]!.text, `Write a title for: pay [redacted: pii.payment-card], with ${key}`, "a title side call quoting the prompt never carries the card");
});

test("§4.4: a missing pack or a throwing filter blocks with no text under on_error block, and is skipped under pass", async () => {
  const thrower: PromptFilter = { id: "flaky", cost: "inline", categories: ["x.y"], scan: () => { throw new Error("boom"); } };
  const a = setup({ filters: { "acme-dlp": "on", ghost: "on" } }, { unavailable: new Map([["ghost", "refused: bad regex (/x/ghost.yaml)"]]) });
  const [h] = (await a.engine.run([seg("h", "human", "hello")])).segments;
  assert.equal(h!.action, "block");
  assert.equal(h!.text, undefined, "nothing of the segment may go");
  assert.match(h!.reason!, /ghost \(refused: bad regex/);
  const b = setup({ filters: { flaky: "on" } }, { packs: new Map([["flaky", thrower]]) });
  assert.equal((await b.engine.run([seg("h", "human", "hello")])).segments[0]!.action, "block");
  assert.match((await b.engine.run([seg("h2", "human", "hi")])).segments[0]!.reason!, /flaky \(boom\)/);
  const c = setup({ filters: { flaky: { on: true, on_error: "pass" }, ghost: { on: true, on_error: "pass" } } }, { packs: new Map([["flaky", thrower]]) });
  assert.equal((await c.engine.run([seg("h", "human", "hello")])).segments[0]!.action, "pass");
  // A filter whose every category is log defaults to on_error: pass.
  const d = setup({ filters: { flaky: "on" }, actions: { x: "log" } }, { packs: new Map([["flaky", thrower]]) });
  assert.equal((await d.engine.run([seg("h", "human", "hello")])).segments[0]!.action, "pass");
  assert.equal(d.engine.filterViews().find((f) => f.id === "flaky")!.onError, "pass");
  // The policy's filters run on harness text too, so their failure blocks it (fail-closed).
  assert.equal((await a.engine.run([seg("r", "harness", "hello")])).segments[0]!.action, "block");
  assert.equal((await c.engine.run([seg("r", "harness", "hello")])).segments[0]!.action, "pass");
});

test("the confidentiality axis OFF: every finding is log; the cache key follows the policy", async () => {
  const off = setup({ filters: { "key-shapes": "on" }, actions: { "secret.shape": "block" } }, { enforcing: false });
  const [h] = (await off.engine.run([seg("h", "human", `x ${GH}`)])).segments;
  assert.equal(h!.action, "pass");
  assert.deepEqual(h!.findings.map((f) => f.action), ["log"]);
  const on = setup({ filters: { "key-shapes": "on" } });
  const t = [seg("h", "human", `x ${GH}`)];
  assert.equal((await on.engine.run(t)).segments[0]!.text, "x [redacted: secret.shape.github-token]");
  assert.equal((await on.engine.run(t)).segments[0]!.cached, true);
  const d1 = on.engine.digest().policy;
  on.setPolicy({ filters: { "key-shapes": "on" }, actions: { "secret.shape": "log" } });
  assert.notEqual(on.engine.digest().policy, d1);
  const again = (await on.engine.run(t)).segments[0]!;
  assert.equal(again.cached, false, "a policy change rescans");
  assert.equal(again.action, "pass");
  assert.deepEqual(again.findings.map((f) => f.action), ["log"]);
});

test("the panel's views: who set each filter, the pack's categories, availability", async () => {
  const { engine } = setup({ filters: { "acme-dlp": "on", ghost: "on" } }, { unavailable: new Map([["ghost", "unsigned, and signed_only is on (/x/g.yaml)"]]) });
  const v = engine.filterViews();
  assert.deepEqual(v.map((f) => [f.id, f.kind, f.on, f.setBy, f.available]), [
    ["registered-value", "built-in", true, "default", true],
    ["key-shapes", "built-in", false, "default", true],
    ["acme-dlp", "pack", true, "you", true],
    ["ghost", "pack", true, "you", false],
  ]);
  assert.deepEqual(v.find((f) => f.id === "acme-dlp")!.categories.map((c) => c.category).sort(), ["acme.codename", "pii.email", "pii.payment-card"]);
  assert.match(v.find((f) => f.id === "ghost")!.problem!, /unsigned/);
  assert.equal(engine.actionViews().fallback, "redact");
});

test("phase 3: a plugin scans a request's uncached segments in ONE batch, never reads a registered value, and its finding acts", async () => {
  const seen: string[][] = [];
  const plugin: PromptFilter = {
    id: "cls", cost: "model", categories: ["acme.codename"],
    scan: () => { throw new Error("the engine batches a plugin"); },
    scanMany: async (segs) => {
      seen.push(segs.map((s) => s.text));
      return new Map(segs.map((s) => {
        const i = s.text.indexOf("osprey");
        return [s.id, { findings: i < 0 ? [] : [{ start: i, end: i + 6, category: "acme.codename" }], skipped: 0 }];
      }));
    },
  };
  const a = setup({ filters: { cls: "on" } }, { packs: new Map([["cls", plugin]]) });
  const out = (await a.engine.run([
    seg("h", "human", `key ${KEY} and osprey`),
    seg("r", "harness", "<r>osprey</r>"),
    seg("d", "human", `key ${KEY} and osprey`),
  ])).segments;
  assert.equal(seen.length, 1, "one plugin run for the request");
  assert.equal(seen[0]!.length, 2, "duplicate texts are sent once");
  assert.equal(seen[0]![0], `key ${"█".repeat(KEY.length)} and osprey`, "the registered value is shielded, offsets kept");
  assert.ok(!seen.flat().some((t) => t.includes(KEY)), "CONFIDENTIALITY: a plugin never reads a registered value");
  assert.equal(out[0]!.text, `key ${a.key} and [redacted: acme.codename]`);
  assert.equal(out[1]!.text, "<r>[redacted: acme.codename]</r>");
  assert.equal(out[2]!.text, out[0]!.text);
  // Cached: no second run.
  await a.engine.run([seg("h", "human", `key ${KEY} and osprey`)]);
  assert.equal(seen.length, 1);
});

test("phase 3 seam: an asynchronous filter (a plugin's promise) is awaited; a rejection fails per on_error", async () => {
  const slow: PromptFilter = {
    id: "slow", cost: "model", categories: ["acme.codename"],
    scan: async (text) => {
      await new Promise((r) => setTimeout(r, 5));
      const i = text.indexOf("osprey");
      return { findings: i < 0 ? [] : [{ start: i, end: i + 6, category: "acme.codename" }], skipped: 0 };
    },
  };
  const a = setup({ filters: { slow: "on" } }, { packs: new Map([["slow", slow]]) });
  const [h] = (await a.engine.run([seg("h", "human", "the osprey launch")])).segments;
  assert.equal(h!.action, "rewrite");
  assert.equal(h!.text, "the [redacted: acme.codename] launch");
  const rejecting: PromptFilter = { id: "slow", cost: "model", categories: ["acme.codename"], scan: async () => { throw new Error("deadline 5000 ms passed"); } };
  const b = setup({ filters: { slow: "on" } }, { packs: new Map([["slow", rejecting]]) });
  const [x] = (await b.engine.run([seg("h", "human", "the osprey launch")])).segments;
  assert.equal(x!.action, "block");
  assert.equal(x!.text, undefined);
  assert.match(x!.reason!, /slow \(deadline 5000 ms passed\)/);
  // A failure is not cached: the next request asks the filter again.
  let fail = true;
  const flaky: PromptFilter = { id: "slow", cost: "model", categories: ["acme.codename"], scan: async () => { if (fail) throw new Error("cold start"); return { findings: [], skipped: 0 }; } };
  const f = setup({ filters: { slow: "on" } }, { packs: new Map([["slow", flaky]]) });
  assert.equal((await f.engine.run([seg("h", "human", "hi")])).segments[0]!.action, "block");
  fail = false;
  const second = (await f.engine.run([seg("h", "human", "hi")])).segments[0]!;
  assert.equal(second.action, "pass");
  assert.equal(second.cached, false);
  const c = setup({ filters: { slow: { on: true, on_error: "pass" } } }, { packs: new Map([["slow", rejecting]]) });
  assert.equal((await c.engine.run([seg("h", "human", "the osprey launch")])).segments[0]!.action, "pass");
});
