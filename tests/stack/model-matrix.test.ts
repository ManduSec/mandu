/**
 * model-matrix.test — the claude-e2e MODEL MATRIX's pure half (live-shared.ts:
 * CLAUDE_MODELS / extraModelsFromEnv / runsFor).
 *
 * Mandu (tests/). Runs in CI, unattended, with no `claude` and no budget:
 * the matrix decides WHICH live runs exist and what each is KEYED by, and both
 * of those fail silently rather than loudly —
 *   - a typo'd MANDU_E2E_MODELS that ran nothing would look exactly like a
 *     green matrix (hence: unknown slug throws);
 *   - a run key that collided, or that lost its `@model`, would quietly make two
 *     runs share one pool entry / one dashboard case, and the model coverage
 *     would evaporate while every test still went green.
 * So the expansion is asserted here, deterministically, rather than being
 * discovered on a live run that costs real budget.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  BASE_MODEL, CLAUDE_MODELS, extraModelsFromEnv, runsFor, type MatrixScenario,
} from "../lib/live-shared.js";

const SCENARIOS: MatrixScenario[] = [
  { name: "reasoning", modelAxis: true },
  { name: "bash-ipi" }, // not on the axis: base model only
  { name: "interactive-reply-filter-live", modelAxis: true },
];

// ── The model registry ────────────────────────────────────────────────────────

test("CLAUDE_MODELS: haiku is the base, ids are exact, slugs are id-safe + unique", () => {
  assert.equal(BASE_MODEL.slug, "haiku", "the full battery runs on the cheapest model");
  assert.equal(BASE_MODEL, CLAUDE_MODELS[0], "base is first, so runsFor's order is the registry's");
  const slugs = CLAUDE_MODELS.map((m) => m.slug);
  assert.deepEqual(slugs, [...new Set(slugs)], "slugs are the @suffix — they must be unique");
  for (const m of CLAUDE_MODELS) {
    // The slug is spliced into a run key, a session id AND a filesystem path.
    assert.match(m.slug, /^[a-z0-9-]+$/, `slug "${m.slug}" must be id- and path-safe`);
    // A date-suffixed variant is a DIFFERENT model to the API; the aliases are complete.
    assert.doesNotMatch(m.id, /-\d{8}$/, `model id "${m.id}" must not carry a date suffix`);
    assert.ok(m.timeoutScale >= 1, "a scale below the base model's would tighten its deadlines");
  }
});

// The bigger models run adaptive thinking: a turn opens with a long silent pause,
// so a base-model deadline would cut it off and the oracle would go vacuous or
// red for a TIMING reason — a red that looks like a defense finding but isn't.
test("CLAUDE_MODELS: the thinking models get more wall-clock than the base", () => {
  for (const m of CLAUDE_MODELS) {
    if (m.slug === BASE_MODEL.slug) continue;
    assert.ok(
      m.timeoutScale > BASE_MODEL.timeoutScale,
      `${m.slug} runs adaptive thinking — it needs a bigger budget than ${BASE_MODEL.slug}`,
    );
  }
});

// ── extraModelsFromEnv ────────────────────────────────────────────────────────

test("extraModelsFromEnv: unset/empty ⇒ no extras (the suite is byte-identical to pre-matrix)", () => {
  assert.deepEqual(extraModelsFromEnv(undefined), []);
  assert.deepEqual(extraModelsFromEnv(""), []);
  assert.deepEqual(extraModelsFromEnv("  ,  ,"), []);
});

test("extraModelsFromEnv: named models resolve, in registry order, deduped", () => {
  assert.deepEqual(extraModelsFromEnv("sonnet").map((m) => m.id), ["claude-sonnet-5"]);
  // Registry order, NOT the order the user typed — so a run key / session id
  // sorts predictably in the sidebar regardless of how the env var was written.
  assert.deepEqual(extraModelsFromEnv("opus,sonnet").map((m) => m.slug), ["sonnet", "opus"]);
  assert.deepEqual(extraModelsFromEnv("sonnet,sonnet").map((m) => m.slug), ["sonnet"]);
  assert.deepEqual(extraModelsFromEnv(" SONNET , opus ").map((m) => m.slug), ["sonnet", "opus"]);
});

// The base model always runs, so naming it is a no-op — never a SECOND base run
// (which would collide on the run key and silently drop one of the two).
test("extraModelsFromEnv: naming the base model is a no-op, not a duplicate run", () => {
  assert.deepEqual(extraModelsFromEnv("haiku"), []);
  assert.deepEqual(extraModelsFromEnv("haiku,sonnet").map((m) => m.slug), ["sonnet"]);
});

// FAIL LOUD. A typo'd slug that was skipped would run the matrix on nothing and
// still go green — indistinguishable from full coverage.
test("extraModelsFromEnv: an unknown model throws rather than silently running nothing", () => {
  assert.throws(() => extraModelsFromEnv("sonnett"), /unknown model "sonnett"/);
  // Fable is in the matrix since 2026-09-05, INTERACTIVE-ONLY (see runsFor below).
  assert.equal(extraModelsFromEnv("fable")[0]?.interactiveOnly, true);
  assert.throws(() => extraModelsFromEnv("sonnet,bogus"), /unknown model "bogus"/, "one bad slug reds the whole run");
});

// ── runsFor ───────────────────────────────────────────────────────────────────

test("runsFor: no extras ⇒ exactly one base-model run per scenario, un-suffixed", () => {
  const runs = runsFor(SCENARIOS, []);
  assert.deepEqual(runs.map((r) => r.name), ["reasoning", "bash-ipi", "interactive-reply-filter-live"]);
  for (const r of runs) {
    assert.equal(r.model.slug, BASE_MODEL.slug);
    // The bare key is what keeps every historical session id, TAP title and
    // badge intact — the matrix is additive, not a migration.
    assert.equal(r.name, r.scenario.name);
  }
});

test("runsFor: only modelAxis scenarios fan out; the rest stay base-only", () => {
  const runs = runsFor(SCENARIOS, extraModelsFromEnv("sonnet,opus"));
  assert.deepEqual(runs.map((r) => r.name), [
    "reasoning", "reasoning@sonnet", "reasoning@opus",
    "bash-ipi", // NOT on the axis — one run, no suffix
    "interactive-reply-filter-live", "interactive-reply-filter-live@sonnet", "interactive-reply-filter-live@opus",
  ]);
  const bashIpi = runs.filter((r) => r.scenario.name === "bash-ipi");
  assert.equal(bashIpi.length, 1, "a non-axis scenario must not pay a bigger model's price");
});

test("runsFor: each run carries the model it names, and the base run comes first", () => {
  const runs = runsFor([{ name: "reasoning", modelAxis: true }], extraModelsFromEnv("sonnet,opus"));
  assert.deepEqual(
    runs.map((r) => [r.name, r.model.id]),
    [
      ["reasoning", "claude-haiku-4-5"],
      ["reasoning@sonnet", "claude-sonnet-5"],
      ["reasoning@opus", "claude-opus-4-8"],
    ],
  );
});

// Run keys are the join key on the pool map, the TAP title and the session id.
// A collision would make two runs share one pool entry — the second overwrites
// the first, one test awaits the other's verdict, and a real failure could be
// reported as a pass.
test("runsFor: run keys are unique across the whole matrix", () => {
  const runs = runsFor(SCENARIOS, extraModelsFromEnv("sonnet,opus"));
  const keys = runs.map((r) => r.name);
  assert.equal(new Set(keys).size, keys.length, `duplicate run key in ${keys.join(", ")}`);
});

test("runsFor: an interactiveOnly model (fable) fans out to interactive scenarios and nothing else", () => {
  const fable = extraModelsFromEnv("fable")[0]!;
  const sonnet = extraModelsFromEnv("sonnet")[0]!;
  const runs = runsFor(
    [
      { name: "headless-axis", modelAxis: true },
      { name: "interactive-axis", modelAxis: true, driver: "interactive" },
      { name: "plain" },
    ],
    [sonnet, fable],
  ).map((r) => r.name);
  assert.deepEqual(runs, [
    "headless-axis", "headless-axis@sonnet",
    "interactive-axis", "interactive-axis@sonnet", "interactive-axis@fable",
    "plain",
  ]);
});
