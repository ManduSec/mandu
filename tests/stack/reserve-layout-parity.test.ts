/**
 * reserve-layout-parity.test.ts — ONE row layout in four packages, and ONE
 * reserve grammar in both model proxies (docs/design/ui/reply-row-reservation.md
 * §11.2, §11.7).
 *
 * The arbiter counts a value's rows (`symbolShape` with a width), the Claude
 * proxy wraps the model's own prefix to learn a mid-line head's free width,
 * and the reply filter paints the rows. If any two disagreed, the TUI would
 * reserve a different number of rows than the filter paints, or a row would
 * be wider than its reservation. The packages ship standalone, so
 * reserve-layout.ts is copied verbatim into each, and the Codex proxy
 * (openai-proxy) carries verbatim copies of the Claude proxy's grammar
 * (reserve-block.ts) and eligibility (reserve-context.ts). This file:
 *   - holds every copy byte-identical (the drift check);
 *   - runs one seeded corpus through all four layouts and requires the same
 *     rows;
 *   - runs one text corpus through both proxies' expand/collapse/strip.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { stateAxes } from "../lib/axes.js";
import * as filter from "../../interceptors/reply-filter/src/reserve-layout.js";
import * as arbiter from "../../arbiter/ipc/reserve-layout.js";
import * as proxy from "../../interceptors/anthropic-proxy/src/reserve-layout.js";
import * as codex from "../../interceptors/openai-proxy/src/reserve-layout.js";
import * as claudeBlock from "../../interceptors/anthropic-proxy/src/reserve-block.js";
import * as codexBlock from "../../interceptors/openai-proxy/src/reserve-block.js";

stateAxes("secrets"); // the layout reads no axis; it shapes a secret's rows on the human's screen

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const read = (p: string): string => readFileSync(join(ROOT, p), "utf8");

const CANONICAL = "interceptors/reply-filter/src/reserve-layout.ts";
const COPIES = [
  "arbiter/ipc/reserve-layout.ts",
  "interceptors/anthropic-proxy/src/reserve-layout.ts",
  "interceptors/openai-proxy/src/reserve-layout.ts",
];
/** The Claude proxy's files the Codex proxy copies verbatim (§11.7). */
const PROXY_COPIES = [
  "src/reserve-block.ts",
  "src/reserve-context.ts",
  "test/unit/reserve-block.test.ts",
  "test/unit/reserve-context.test.ts",
];

test("the four copies of reserve-layout.ts are byte-identical", () => {
  const master = read(CANONICAL);
  for (const c of COPIES) {
    assert.equal(read(c), master, `${c} drifted from ${CANONICAL}; copy the reply-filter file out again`);
  }
  assert.equal(read("interceptors/openai-proxy/test/unit/reserve-layout.test.ts"),
    read("interceptors/reply-filter/test/unit/reserve-layout.test.ts"), "the Codex proxy's layout suite is the filter's");
});

test("the Codex proxy's reserve grammar and eligibility are the Claude proxy's, byte for byte", () => {
  for (const f of PROXY_COPIES) {
    assert.equal(read(`interceptors/openai-proxy/${f}`), read(`interceptors/anthropic-proxy/${f}`),
      `interceptors/openai-proxy/${f} drifted from interceptors/anthropic-proxy/${f}; copy it out again`);
  }
});

test("both proxies expand, collapse and strip one text corpus identically", () => {
  let seed = 0xc0de5;
  const rnd = (n: number): number => ((seed = (seed * 1103515245 + 12345) >>> 0) % n);
  const T = ["$MDU:nomodel_Read[3407]", "\\$MDU:nomodel\\_Bash[0badc0d]", "$MDU:secret_x[beef].field"];
  const bits = ["word ", "\n", "- ", "```\n", "**", "pre ", " tail.", "`", "| "];
  for (let k = 0; k < 1000; k++) {
    let text = "";
    const len = 1 + rnd(12);
    for (let i = 0; i < len; i++) text += rnd(3) === 0 ? T[rnd(T.length)]! : bits[rnd(bits.length)]!;
    const shapes = new Map(T.map((t) => [t.replace(/\\/g, ""), 2 + rnd(6)] as const));
    const a = claudeBlock.expandText(text, shapes, 40);
    assert.equal(codexBlock.expandText(text, shapes, 40), a);
    assert.equal(codexBlock.collapseText(a), claudeBlock.collapseText(a));
    assert.deepEqual(codexBlock.stripResiduals(a), claudeBlock.stripResiduals(a));
  }
});

test("one seeded corpus lays out identically in all four packages", () => {
  let seed = 20260930;
  const rnd = (n: number): number => ((seed = (seed * 1103515245 + 12345) >>> 0) % n);
  const alphabet = ["a", "b", "c", " ", " ", " ", "한", "\t", "é", "Z", "\n", "\x1b[1m", "_", "-"];
  for (let t = 0; t < 2000; t++) {
    let v = "";
    const len = rnd(300);
    for (let i = 0; i < len; i++) v += alphabet[rnd(alphabet.length)]!;
    const W = 20 + rnd(200);
    const half = Math.ceil(W / 2);
    const F = rnd(4) === 0 ? 0 : half + rnd(W - half + 1);
    // §11.2: the content area's column, which moves the TAB stops.
    const I = rnd(3) === 0 ? 0 : rnd(12);
    const rule = rnd(4) === 0 ? "terminal" : "ink";
    const want = filter.layoutRows(v, W, F, rule, I);
    const at = `${JSON.stringify(v)} W=${W} F=${F} indent=${I} ${rule}`;
    assert.deepEqual(arbiter.layoutRows(v, W, F, rule, I), want, `arbiter differs on ${at}`);
    assert.deepEqual(proxy.layoutRows(v, W, F, rule, I), want, `proxy differs on ${at}`);
    assert.deepEqual(codex.layoutRows(v, W, F, rule, I), want, `codex proxy differs on ${at}`);
    const shown = 1 + rnd(want.length);
    assert.equal(arbiter.linesNotShown(want, shown), filter.linesNotShown(want, shown));
  }
});
