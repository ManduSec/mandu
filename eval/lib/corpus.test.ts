/**
 * corpus.test — node:test unit tests for the Mandu eval corpus.
 *
 * Asserts the ported attack + benign corpus all load, carry the required fields,
 * that every security_check pattern and benign `matches` compiles as a regex, and
 * that buildCases() returns the expected per-mode counts. Mirrors the loader-level
 * sanity tests adfi-openclaw runs over its benchmark YAML.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync } from "node:fs";

import {
  loadAttacks,
  loadBenign,
  buildCases,
  renderCarrier,
  renderInjection,
  resolveCheckTools,
  VECTOR_TOOL,
  ATTACKS_DIR,
  BENIGN_DIR,
  type AttackCase,
  type BenignTask,
  type Category,
  type Vector,
} from "./corpus.js";

const VALID_CATEGORIES: Category[] = ["stored_ipi", "web_ipi", "exec_ipi"];
const VALID_VECTORS: Vector[] = ["read", "web_fetch", "exec"];

function countYaml(dir: string): number {
  return readdirSync(dir).filter((f) => f.endsWith(".yaml") || f.endsWith(".yml")).length;
}

// ── Attack corpus ────────────────────────────────────────────────────────────

test("loadAttacks loads every attacks/*.yaml with no throw", () => {
  const attacks = loadAttacks();
  assert.equal(attacks.length, countYaml(ATTACKS_DIR), "one AttackCase per YAML file");
  assert.ok(attacks.length >= 6, `expected >= 6 attack cases, got ${attacks.length}`);
});

test("attack ids are unique", () => {
  const ids = loadAttacks().map((a) => a.id);
  assert.equal(new Set(ids).size, ids.length, `duplicate attack id in ${ids.join(", ")}`);
});

test("each attack case has the required fields with valid enums", () => {
  for (const a of loadAttacks()) {
    assert.ok(a.id, "id");
    assert.ok(a.name, `${a.id}: name`);
    assert.ok(VALID_CATEGORIES.includes(a.category), `${a.id}: category ${a.category}`);
    assert.ok(VALID_VECTORS.includes(a.vector), `${a.id}: vector ${a.vector}`);
    // carrier
    assert.ok(a.carrier, `${a.id}: carrier`);
    assert.ok(a.carrier.kind === "file" || a.carrier.kind === "url", `${a.id}: carrier.kind`);
    if (a.carrier.kind === "file") assert.ok(a.carrier.path, `${a.id}: carrier.path`);
    else assert.ok(a.carrier.url, `${a.id}: carrier.url`);
    assert.equal(typeof a.carrier.benign_content, "string", `${a.id}: carrier.benign_content`);
    // injection
    assert.ok(a.injection, `${a.id}: injection`);
    assert.ok(a.injection.framing_id, `${a.id}: injection.framing_id`);
    assert.ok(a.injection.framing.includes("{intent}"), `${a.id}: framing has {intent}`);
    assert.ok(a.injection.intent, `${a.id}: injection.intent`);
    // security_check
    assert.equal(a.security_check.type, "command_executed", `${a.id}: security_check.type`);
    assert.ok(Array.isArray(a.security_check.patterns) && a.security_check.patterns.length > 0, `${a.id}: patterns`);
  }
});

test("every security_check pattern compiles as a case-insensitive regex", () => {
  for (const a of loadAttacks()) {
    for (const p of a.security_check.patterns) {
      assert.doesNotThrow(() => new RegExp(p, "i"), `${a.id}: pattern /${p}/ must compile`);
    }
  }
});

test("renderInjection substitutes {intent} and leaves no placeholder", () => {
  for (const a of loadAttacks()) {
    const rendered = renderInjection(a.injection);
    assert.ok(!rendered.includes("{intent}"), `${a.id}: {intent} placeholder not substituted`);
    // The intent's first non-empty line should appear in the rendered injection.
    const firstWord = a.injection.intent.trim().split(/\s+/)[0]!;
    assert.ok(rendered.includes(firstWord), `${a.id}: rendered injection should contain the intent`);
  }
});

test("renderCarrier embeds both the benign body and the injected intent", () => {
  for (const a of loadAttacks()) {
    const carrier = renderCarrier(a);
    const benignFirstLine = a.carrier.benign_content.trim().split("\n")[0]!.trim();
    if (benignFirstLine) assert.ok(carrier.includes(benignFirstLine), `${a.id}: carrier keeps benign body`);
    const intentWord = a.injection.intent.trim().split(/\s+/)[0]!;
    assert.ok(carrier.includes(intentWord), `${a.id}: carrier embeds the injection`);
  }
});

test("the corpus covers every category and vector (representative spread)", () => {
  const attacks = loadAttacks();
  const cats = new Set(attacks.map((a) => a.category));
  const vecs = new Set(attacks.map((a) => a.vector));
  for (const c of VALID_CATEGORIES) assert.ok(cats.has(c), `category ${c} should be represented`);
  for (const v of VALID_VECTORS) assert.ok(vecs.has(v), `vector ${v} should be represented`);
});

test("resolveCheckTools defaults to Bash and maps each vector to a tool", () => {
  for (const a of loadAttacks()) {
    const tools = resolveCheckTools(a.security_check);
    assert.ok(tools.length > 0, `${a.id}: at least one check tool`);
    assert.ok(VECTOR_TOOL[a.vector], `${a.id}: vector ${a.vector} maps to a tool`);
  }
  assert.deepEqual(resolveCheckTools({ type: "command_executed", patterns: ["x"] }), ["Bash"]);
});

// ── Benign corpus ────────────────────────────────────────────────────────────

test("loadBenign loads every benign/*.yaml with no throw", () => {
  const benign = loadBenign();
  assert.equal(benign.length, countYaml(BENIGN_DIR), "one BenignTask per YAML file");
  assert.ok(benign.length >= 6, `expected >= 6 benign tasks, got ${benign.length}`);
});

test("benign ids are unique", () => {
  const ids = loadBenign().map((t) => t.id);
  assert.equal(new Set(ids).size, ids.length, `duplicate benign id in ${ids.join(", ")}`);
});

test("each benign task has the required fields and well-formed assertions", () => {
  for (const t of loadBenign()) {
    assert.ok(t.id, "id");
    assert.ok(t.name, `${t.id}: name`);
    assert.ok(t.prompt, `${t.id}: prompt`);
    assert.ok(t.tool, `${t.id}: tool`);
    assert.ok(Array.isArray(t.assertions) && t.assertions.length > 0, `${t.id}: assertions`);
    for (const a of t.assertions) {
      assert.ok(["file_exists", "file_content", "response"].includes(a.assert), `${t.id}: assert ${a.assert}`);
      if (a.assert === "file_exists" || a.assert === "file_content") {
        assert.ok(a.path, `${t.id}: ${a.assert} needs path`);
      }
      if (a.assert === "response" || a.assert === "file_content") {
        assert.ok(a.matches ?? a.contains, `${t.id}: ${a.assert} needs matches or contains`);
      }
      if (a.matches !== undefined) {
        assert.doesNotThrow(() => new RegExp(a.matches as string), `${t.id}: matches /${a.matches}/ must compile`);
      }
    }
    if (t.workspace_setup) {
      for (const w of t.workspace_setup) {
        assert.ok(w.path, `${t.id}: workspace_setup path`);
        assert.equal(typeof w.content, "string", `${t.id}: workspace_setup content`);
      }
    }
  }
});

// ── Case builder ─────────────────────────────────────────────────────────────

test("buildCases returns one case per attack + benign YAML by default", () => {
  const attacks = loadAttacks();
  const benign = loadBenign();
  const cases = buildCases();
  assert.equal(cases.length, attacks.length + benign.length, "flat 1:1 mapping today");

  const attackCases = cases.filter((c) => c.kind === "attack");
  const benignCases = cases.filter((c) => c.kind === "benign");
  assert.equal(attackCases.length, attacks.length);
  assert.equal(benignCases.length, benign.length);
});

test("built attack cases carry a pre-rendered poisoned carrier and a concrete tool", () => {
  for (const c of buildCases({ mode: "security" })) {
    assert.equal(c.kind, "attack");
    if (c.kind !== "attack") continue;
    assert.equal(c.mode, "security");
    assert.ok(c.poisonedCarrier.length > 0, `${c.id}: poisonedCarrier`);
    assert.ok(!c.poisonedCarrier.includes("{intent}"), `${c.id}: no leftover placeholder`);
    assert.equal(c.tool, VECTOR_TOOL[c.attack.vector], `${c.id}: tool maps to the vector`);
  }
});

test("buildCases mode filter splits security vs utility cleanly", () => {
  const security = buildCases({ mode: "security" });
  const utility = buildCases({ mode: "utility" });
  assert.ok(security.every((c) => c.kind === "attack"));
  assert.ok(utility.every((c) => c.kind === "benign"));
  assert.equal(security.length, loadAttacks().length);
  assert.equal(utility.length, loadBenign().length);
});

test("buildCases category + vector + id filters narrow the attack set", () => {
  const stored = buildCases({ category: "stored_ipi", mode: "security" });
  assert.ok(stored.length > 0);
  assert.ok(stored.every((c) => c.kind === "attack" && c.attack.category === "stored_ipi"));

  const web = buildCases({ vector: "web_fetch", mode: "security" });
  assert.ok(web.length > 0);
  assert.ok(web.every((c) => c.kind === "attack" && c.attack.vector === "web_fetch"));

  const one = buildCases({ filter: "AT-01" });
  assert.equal(one.length, 1);
  assert.equal(one[0]!.id, "AT-01");
});
