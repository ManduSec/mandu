/**
 * integrity-flag.test.ts — the integrity-axis switch (policy/integrity-flag.ts).
 *
 * Mandu-new test (no reference origin). Four claims, the first three
 * mirroring the confidentiality kill-switch suite (confidentiality.test.ts):
 *   1. Flag resolution: default ON (opt-OUT — the inverse of confidentiality);
 *      only an explicit "0"/"false"/"off" disables.
 *   2. classify() collapse: with integrity OFF every field is TRUSTED — while
 *      the CONFIDENTIALITY derivation is untouched (a TRUSTED-but-secret datum
 *      still carries its level, so it still symbolizes). With integrity ON the
 *      fail-closed UNTRUSTED default is byte-identical to today.
 *   3. Handling prompt: integrity absent/ON ⇒ byte-identical prompt; OFF drops
 *      exactly the trust-machinery sections (Data Trust Policy, exec contract)
 *      and keeps the symbol contract + confidentiality section; both axes OFF
 *      ⇒ empty prompt.
 *   4. The freeze gate (docs/design/architecture/protection-modes.md §10): only an explicit
 *      "1"/"true"/"on"/"yes" in MANDU_EXPERIMENTAL_INTEGRITY opts in; a typo
 *      or an empty value keeps an integrity-ON start refused; integrity OFF is
 *      never refused, whatever the opt-in says.
 *
 * Run: npm run test:unit
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  assertIntegrityAllowed,
  integrityOptedIn,
  INTEGRITY_OPT_IN_ENV,
  resolveIntegrityEnabled,
} from "../../policy/integrity-flag.js";
import { createEngineBackedPolicy } from "../../policy/policy-interface.js";
import { buildSymbolSystemPrompt } from "../../symbol-table/handling-prompt.js";
import { getActiveFormat } from "../../symbol-table/symbol-format.js";
import { stateAxes } from "../axes.js";

stateAxes("injection"); // this suite states its axes (protection-modes.md §4)

// ── 1. flag resolution ───────────────────────────────────────────────────────

test("integrity switch resolves from env; nothing stated ⇒ OFF (the default mode is `secrets`, protection-modes.md)", () => {
  assert.equal(resolveIntegrityEnabled({}), false);
  assert.equal(resolveIntegrityEnabled({ MANDU_INTEGRITY: "" }), false);
  // …and a mode that includes the axis turns it on without the axis variable.
  assert.equal(resolveIntegrityEnabled({ MANDU_MODE: "full" }), true);
  assert.equal(resolveIntegrityEnabled({ MANDU_MODE: "injection" }), true);
  assert.equal(resolveIntegrityEnabled({ MANDU_INTEGRITY: "1" }), true);
  assert.equal(resolveIntegrityEnabled({ MANDU_INTEGRITY: "true" }), true);
  assert.equal(resolveIntegrityEnabled({ MANDU_INTEGRITY: "on" }), true);
  // Junk fails toward protection (ON): only an explicit negative disables.
  assert.equal(resolveIntegrityEnabled({ MANDU_INTEGRITY: "maybe" }), true);
  assert.equal(resolveIntegrityEnabled({ MANDU_INTEGRITY: "0" }), false);
  assert.equal(resolveIntegrityEnabled({ MANDU_INTEGRITY: "false" }), false);
  assert.equal(resolveIntegrityEnabled({ MANDU_INTEGRITY: "off" }), false);
  assert.equal(resolveIntegrityEnabled({ MANDU_INTEGRITY: "OFF" }), false);
});

// ── 2. classify collapse ─────────────────────────────────────────────────────

test("int OFF: a normally-UNTRUSTED WebFetch body classifies TRUSTED", () => {
  const p = createEngineBackedPolicy({ integrity: false });
  const params = { url: "https://attacker.example/post" };
  const r = p.classify({
    tool: "WebFetch", field: "content", value: "evil",
    boundary: "model_context", params,
  });
  assert.equal(r.trust, "TRUSTED");
  assert.match(r.reason, /integrity axis OFF/);
});

test("int OFF: the fail-closed unknown-tool default collapses too", () => {
  const p = createEngineBackedPolicy({ integrity: false });
  const r = p.classify({
    tool: "SomeUnknownTool", value: "whatever", boundary: "model_context",
  });
  assert.equal(r.trust, "TRUSTED");
});

test("int OFF × conf ON: level derivation is untouched — a .env read is TRUSTED but no-model", () => {
  const p = createEngineBackedPolicy({ integrity: false, confidentiality: true });
  const r = p.classify({
    tool: "Read", field: "content", value: "API_KEY=sk-live-x",
    boundary: "model_context",
    origin: "/ws/.env",
    params: { file_path: "/ws/.env" },
  });
  assert.equal(r.trust, "TRUSTED", "trust collapsed by the integrity switch");
  assert.equal(r.confidentiality, "no-model", "catalog still classifies the level");
});

test("int OFF × conf OFF: no confidentiality field at all (fold-2 inertness preserved)", () => {
  const p = createEngineBackedPolicy({ integrity: false, confidentiality: false });
  const r = p.classify({
    tool: "Read", field: "content", value: "API_KEY=sk-live-x",
    boundary: "model_context",
    origin: "/ws/.env",
    params: { file_path: "/ws/.env" },
  });
  assert.equal(r.trust, "TRUSTED");
  assert.equal("confidentiality" in r, false);
});

test("int ON (default): fail-closed UNTRUSTED unchanged", () => {
  const p = createEngineBackedPolicy({ integrity: true });
  const r = p.classify({
    tool: "SomeUnknownTool", value: "whatever", boundary: "model_context",
  });
  assert.equal(r.trust, "UNTRUSTED");
});

// ── 3. handling prompt ───────────────────────────────────────────────────────

test("prompt: integrity absent/true is byte-identical (no churn for today's system)", () => {
  const fmt = getActiveFormat();
  assert.equal(
    buildSymbolSystemPrompt(fmt, {}),
    buildSymbolSystemPrompt(fmt, { integrity: true }),
  );
  assert.equal(
    buildSymbolSystemPrompt(fmt, { confidentiality: true }),
    buildSymbolSystemPrompt(fmt, { confidentiality: true, integrity: true }),
  );
});

test("prompt: int OFF × conf ON keeps the symbol contract + secret section, drops the trust machinery", () => {
  const fmt = getActiveFormat();
  const p = buildSymbolSystemPrompt(fmt, { integrity: false, confidentiality: true });
  // Kept: the axis-neutral symbol contract and the confidentiality section.
  assert.match(p, /## Mandu Symbols/);
  assert.match(p, /### Rules/);
  assert.match(p, /confidentiality marker/);
  // Dropped: inbound-trust policy tools and the exec trust contract.
  assert.doesNotMatch(p, /Data Trust Policy/);
  assert.doesNotMatch(p, /RESTRICTED=1/);
});

test("prompt: both axes OFF ⇒ empty (nothing ever symbolizes)", () => {
  const fmt = getActiveFormat();
  assert.equal(
    buildSymbolSystemPrompt(fmt, { integrity: false, confidentiality: false }),
    "",
  );
  assert.equal(buildSymbolSystemPrompt(fmt, { integrity: false }), "");
});

// ── 4. the freeze gate ───────────────────────────────────────────────────────

test("freeze: the opt-in variable is MANDU_EXPERIMENTAL_INTEGRITY", () => {
  assert.equal(INTEGRITY_OPT_IN_ENV, "MANDU_EXPERIMENTAL_INTEGRITY");
});

test("freeze: only an explicit 1/true/on/yes opts in (case and whitespace tolerant)", () => {
  for (const v of ["1", "true", "on", "yes", "TRUE", " Yes ", "ON"]) {
    assert.equal(integrityOptedIn({ MANDU_EXPERIMENTAL_INTEGRITY: v }), true, `"${v}" opts in`);
  }
  for (const v of ["", " ", "0", "false", "off", "no", "2", "ture", "yes please", "enable", "y"]) {
    assert.equal(integrityOptedIn({ MANDU_EXPERIMENTAL_INTEGRITY: v }), false, `"${v}" does not opt in`);
  }
  // Absent never defaults on.
  assert.equal(integrityOptedIn({}), false);
  // A near-miss variable NAME is not the opt-in either.
  assert.equal(integrityOptedIn({ MANDU_EXPERIMENTAL_INTEGRITIY: "1" } as NodeJS.ProcessEnv), false);
  assert.equal(integrityOptedIn({ MANDU_INTEGRITY: "1" }), false, "the axis variable is not the opt-in");
});

test("freeze: integrity ON without the opt-in throws, naming the opt-in variable and the freeze doc", () => {
  assert.throws(
    () => assertIntegrityAllowed(true, {}),
    (e: Error) => /MANDU_EXPERIMENTAL_INTEGRITY=1/.test(e.message) && /protection-modes\.md/.test(e.message),
  );
  // A typo in the opt-in value is a refusal, not a silent yes.
  assert.throws(() => assertIntegrityAllowed(true, { MANDU_EXPERIMENTAL_INTEGRITY: "ture" }), /MANDU_EXPERIMENTAL_INTEGRITY/);
  assert.throws(() => assertIntegrityAllowed(true, { MANDU_EXPERIMENTAL_INTEGRITY: "0" }), /MANDU_EXPERIMENTAL_INTEGRITY/);
  assert.throws(() => assertIntegrityAllowed(true, { MANDU_EXPERIMENTAL_INTEGRITY: "" }), /MANDU_EXPERIMENTAL_INTEGRITY/);
});

test("freeze: integrity ON with the opt-in is allowed", () => {
  for (const v of ["1", "true", "on", "yes"]) {
    assert.doesNotThrow(() => assertIntegrityAllowed(true, { MANDU_EXPERIMENTAL_INTEGRITY: v }));
  }
});

test("freeze: integrity OFF never throws, whatever the opt-in says", () => {
  for (const v of [undefined, "", "0", "1", "ture", "yes"]) {
    const env: NodeJS.ProcessEnv = v === undefined ? {} : { MANDU_EXPERIMENTAL_INTEGRITY: v };
    assert.doesNotThrow(() => assertIntegrityAllowed(false, env));
  }
});

test("freeze: the gate composes with resolution — every integrity-ON spelling is refused without the opt-in", () => {
  const on: NodeJS.ProcessEnv[] = [
    { MANDU_INTEGRITY: "1" },
    { MANDU_INTEGRITY: "maybe" }, // junk fails toward protection (ON), so it is gated too
    { MANDU_MODE: "injection" },
    { MANDU_MODE: "full" },
  ];
  for (const env of on) {
    assert.throws(() => assertIntegrityAllowed(resolveIntegrityEnabled(env), env), /MANDU_EXPERIMENTAL_INTEGRITY/, JSON.stringify(env));
    const opted = { ...env, MANDU_EXPERIMENTAL_INTEGRITY: "1" };
    assert.doesNotThrow(() => assertIntegrityAllowed(resolveIntegrityEnabled(opted), opted));
  }
  const off: NodeJS.ProcessEnv[] = [{}, { MANDU_MODE: "secrets" }, { MANDU_MODE: "off" }, { MANDU_INTEGRITY: "0" }];
  for (const env of off) {
    assert.doesNotThrow(() => assertIntegrityAllowed(resolveIntegrityEnabled(env), env), JSON.stringify(env));
  }
});
