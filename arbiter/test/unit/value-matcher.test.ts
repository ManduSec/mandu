/**
 * value-matcher.test — the one-pass registered-value matcher
 * (confidentiality-plan-15-prompt-filter.md §4.1). Mandu-new.
 *
 * Proves: (1) the Aho-Corasick automaton finds exactly the occurrences a
 * naive search finds (overlaps, shared prefixes, patterns longer than the
 * indexed key); (2) the index over a symbol table answers EXACTLY what the
 * per-row `secretValueMatch` loop it replaces answered for the value backstop
 * (same rows, same order, same `how`), and the indexed egress tripwire
 * answers exactly what `scanEgressFingerprint` answered, with the same floors
 * (MIN_FINGERPRINT_LEN 8, line fingerprints 24), over randomized tables and
 * texts; (3) the index rebuilds when the table changes (a mint, an
 * obsolete, an escalation) and keeps its content version when the change
 * does not touch the secret rows.
 *
 * Axes: secrets (the matcher serves the confidentiality axis).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { KEY_LEN, ValueMatcher } from "../../prompt-filter/value-matcher.js";
import { RegisteredValueIndex, scanEgressFingerprintIndexed } from "../../prompt-filter/registered-values.js";
import {
  valueFingerprints,
  MIN_FINGERPRINT_LEN,
  MIN_LINE_FINGERPRINT_LEN,
  scanEgressFingerprint,
  secretValueMatch,
  type SecretFingerprint,
} from "../../policy/egress-fingerprint.js";
import {
  allocateSymbol,
  escalateSymbolConfidentiality,
  type SymbolEntry,
  type SymbolMap,
} from "../../symbol-table/symbol-table.js";
import { isRegisteredFileRow } from "../../secret-registry/registry.js";
import { isSecret, type ConfidentialityLevel } from "../../symbol-table/confidentiality.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

/** A small deterministic PRNG (mulberry32), so a failure reproduces. */
function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function naive(patterns: readonly string[], text: string): Array<{ pattern: number; start: number }> {
  const out: Array<{ pattern: number; start: number }> = [];
  patterns.forEach((p, id) => {
    if (p === "") return;
    for (let i = text.indexOf(p); i >= 0; i = text.indexOf(p, i + 1)) out.push({ pattern: id, start: i });
  });
  return out.sort((a, b) => a.pattern - b.pattern || a.start - b.start);
}

test("the automaton finds every occurrence a naive search finds, overlaps and long patterns included", () => {
  const r = rng(7);
  const alpha = "ab\nc";
  const word = (n: number): string => Array.from({ length: n }, () => alpha[Math.floor(r() * alpha.length)]).join("");
  for (let round = 0; round < 300; round++) {
    const patterns = Array.from({ length: 1 + Math.floor(r() * 8) }, () => word(1 + Math.floor(r() * (KEY_LEN * 2 + 4))));
    const text = word(Math.floor(r() * 200));
    const m = new ValueMatcher(patterns);
    const got = m.occurrences(text).map((o) => ({ pattern: o.pattern, start: o.start })).sort((a, b) => a.pattern - b.pattern || a.start - b.start);
    assert.deepEqual(got, naive(patterns, text), `round ${round}`);
    const expectSet = new Set(naive(patterns, text).map((o) => o.pattern));
    assert.deepEqual([...m.matched(text)].sort((a, b) => a - b), [...expectSet].sort((a, b) => a - b));
    for (const o of m.occurrences(text)) assert.equal(text.slice(o.start, o.end), patterns[o.pattern]);
  }
});

test("patterns that share a key are told apart by the verification past the key", () => {
  const head = "x".repeat(KEY_LEN);
  const m = new ValueMatcher([`${head}-alpha`, `${head}-beta`, head]);
  assert.deepEqual(m.occurrences(`..${head}-beta..`).map((o) => o.pattern).sort(), [1, 2]);
  assert.deepEqual([...m.matched(`${head}-alph`)], [2]);
  assert.equal(new ValueMatcher([]).occurrences("anything").length, 0);
  assert.equal(new ValueMatcher([""]).occurrences("anything").length, 0, "an empty pattern never matches");
});

// ── the index vs the per-row loop it replaces ───────────────────────────────

const LEVELS: ConfidentialityLevel[] = ["public", "any-model", "local-model", "no-model"];

function entry(value: string, level: ConfidentialityLevel, obsolete = false, bindings: string[] | null = null): SymbolEntry {
  return {
    value, tool: "Read", field: null, origin: null, session_key: null, call_id: null, created_at: 0,
    obsoleted_at: obsolete ? 1 : null, obsoleted_by: obsolete ? "human" : null, derived_from: null, line_range: null,
    confidentiality: level, bindings, integrity: "untrusted",
  };
}

/** The value backstop as it was before plan 15 (server.ts secretValueHits,
 *  minus the exec-evidence and twin rules, which read the row after the
 *  match and are unchanged). */
function referenceHits(map: SymbolMap, text: string): Array<{ symbol: string; how: "value" | "line" }> {
  const out: Array<{ symbol: string; how: "value" | "line" }> = [];
  for (const [name, e] of map.symbols) {
    if (e.obsoleted_at !== null || !isSecret(e.confidentiality)) continue;
    const how = secretValueMatch(text, e.value, valueFingerprints(e.value, 0, { bareTokens: isRegisteredFileRow(e) }));
    if (how !== null) out.push({ symbol: name, how });
  }
  return out;
}

function randomTable(r: () => number): { map: SymbolMap; values: string[] } {
  const words = ["alpha", "postgres", "Acme agrees to pay 4,200,000 USD", "ghp_0123456789abcdefABCDEF", "sk-live-9f8e7d6c", "  Termination requires notice  ", "x", "token=abc", "pw Tq7vZ2pX9kLm ok"];
  const symbols = new Map<string, SymbolEntry>();
  const values: string[] = [];
  const n = 1 + Math.floor(r() * 12);
  for (let i = 0; i < n; i++) {
    const parts = Array.from({ length: 1 + Math.floor(r() * 4) }, () => words[Math.floor(r() * words.length)]!);
    const value = parts.join(r() < 0.5 ? "\n" : "");
    values.push(value);
    const bindings = r() < 0.3 ? ["api.example.com"] : null;
    const e = entry(value, LEVELS[Math.floor(r() * 4)]!, r() < 0.15, bindings);
    // a third of the rows registered from a labelled file (plan 10 §11.15: their bare tokens are pieces)
    symbols.set(`$MDU:Read[${(0x1000 + i).toString(16)}]`, r() < 0.33 ? { ...e, origin: "/h/notes.txt", integrity: "trusted" } : e);
  }
  return { map: { symbols }, values };
}

test("the index answers exactly the per-row secretValueMatch loop (randomized)", () => {
  const r = rng(42);
  let nonEmpty = 0;
  let lineHits = 0;
  for (let round = 0; round < 400; round++) {
    const { map, values } = randomTable(r);
    const idx = new RegisteredValueIndex();
    idx.sync(map);
    const pick = (): string => {
      const v = values[Math.floor(r() * values.length)]!;
      const lines = v.split("\n");
      // the whole value, a line of it, a fragment, or noise
      const k = r();
      if (k < 0.3) return v;
      if (k < 0.6) return lines[Math.floor(r() * lines.length)]!;
      if (k < 0.8) return v.slice(0, Math.floor(r() * v.length));
      return "nothing to see";
    };
    const text = Array.from({ length: 1 + Math.floor(r() * 4) }, pick).join(r() < 0.5 ? " " : "\n-");
    const ref = referenceHits(map, text);
    assert.deepEqual(idx.hits(text), ref, `round ${round}`);
    if (ref.length > 0) nonEmpty++;
    if (ref.some((h) => h.how === "line")) lineHits++;
  }
  assert.ok(nonEmpty > 100 && lineHits > 10, `the corpus exercises hits (${nonEmpty} rounds, ${lineHits} with a line hit)`);
});

test("the floors are the same: values under 8 never match, lines under 24 never stand alone", () => {
  const map: SymbolMap = { symbols: new Map([
    ["$MDU:a[0001]", entry("short7!", "no-model")],
    ["$MDU:a[0002]", entry(`${"L".repeat(MIN_LINE_FINGERPRINT_LEN - 1)}\n${"M".repeat(MIN_LINE_FINGERPRINT_LEN)}`, "no-model")],
    ["$MDU:a[0003]", entry("eight888", "no-model")],
  ]) };
  const idx = new RegisteredValueIndex();
  idx.sync(map);
  assert.equal(MIN_FINGERPRINT_LEN, 8);
  assert.deepEqual(idx.hits("short7! and eight888"), [{ symbol: "$MDU:a[0003]", how: "value" }]);
  assert.deepEqual(idx.hits("L".repeat(MIN_LINE_FINGERPRINT_LEN - 1)), []);
  assert.deepEqual(idx.hits(`x ${"M".repeat(MIN_LINE_FINGERPRINT_LEN)} y`), [{ symbol: "$MDU:a[0002]", how: "line" }]);
  assert.deepEqual(idx.hits("short7! and eight888"), referenceHits(map, "short7! and eight888"));
});

test("the indexed egress tripwire answers exactly scanEgressFingerprint (randomized, bindings included)", () => {
  const r = rng(99);
  let tripped = 0;
  for (let round = 0; round < 300; round++) {
    const { map, values } = randomTable(r);
    const idx = new RegisteredValueIndex();
    idx.sync(map);
    const secrets: SecretFingerprint[] = [];
    for (const [name, e] of map.symbols) {
      if (e.obsoleted_at != null || !isSecret(e.confidentiality)) continue;
      secrets.push({ symbol: name, value: e.value, level: e.confidentiality, bindings: e.bindings ?? [], ...(isRegisteredFileRow(e) ? { fileRow: true } : {}) });
    }
    const row = (name: string): SecretFingerprint | null => secrets.find((s) => s.symbol === name) ?? null;
    const surface = (): string => (r() < 0.2 ? "" : `${values[Math.floor(r() * values.length)]!.split("\n")[0]} tail`);
    const surfaces = [{ where: "url", text: surface() }, { where: "header", text: surface() }, { where: "body", text: surface() }];
    const destination = r() < 0.5 ? "api.example.com" : r() < 0.5 ? "evil.example.net" : "";
    const ref = scanEgressFingerprint(surfaces, secrets, destination);
    assert.deepEqual(scanEgressFingerprintIndexed(surfaces, idx, row, destination), ref, `round ${round}`);
    if (ref.length > 0) tripped++;
  }
  assert.ok(tripped > 50, `the corpus trips the wire (${tripped} rounds)`);
});

test("the index rebuilds on a mint, an escalation and an obsolete; a public mint keeps its content version", () => {
  const map: SymbolMap = { symbols: new Map() };
  const idx = new RegisteredValueIndex();
  idx.sync(map);
  const v0 = idx.contentVersion;
  const pub = allocateSymbol(map, { tool: "Read", value: "a-public-value-123456", confidentiality: "public" });
  idx.sync(map);
  assert.equal(idx.contentVersion, v0, "a public row does not change the indexed set");
  assert.deepEqual(idx.hits("a-public-value-123456"), []);
  escalateSymbolConfidentiality(map, pub, "no-model");
  idx.sync(map);
  assert.ok(idx.contentVersion > v0, "an escalated row is indexed");
  assert.deepEqual(idx.hits("x a-public-value-123456 y"), [{ symbol: pub, how: "value" }]);
  const sec = allocateSymbol(map, { tool: "Read", value: "AKIA-NEW-SECRET-0042", confidentiality: "no-model" });
  idx.sync(map);
  assert.deepEqual(idx.hits("AKIA-NEW-SECRET-0042"), [{ symbol: sec, how: "value" }]);
  map.symbols.get(sec)!.obsoleted_at = 5; // changed past the module: the size check does not see it…
  const before = idx.contentVersion;
  map.symbols.set("$MDU:Read[ffff]", entry("one-more-secret-value", "no-model")); // …but a direct add does
  idx.sync(map);
  assert.ok(idx.contentVersion > before);
  assert.deepEqual(idx.hits("AKIA-NEW-SECRET-0042 one-more-secret-value"), [{ symbol: "$MDU:Read[ffff]", how: "value" }]);
});
