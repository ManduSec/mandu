/**
 * twin-line-fingerprint.test — plan 10 §11.8, "a twin line is no
 * fingerprint" (2026-10-05). A registered `.env` with a long NON-secret line
 * (a comment `# fake values, made up by mandu demo`) used to give that line
 * as a line fingerprint of the file's base row (MIN_LINE_FINGERPRINT_LEN).
 * The structured twin (the placeholder copy the agent reads) carries the
 * comment verbatim, so every Read of the twin was "a registered line
 * verbatim" and came back masked whole instead of per key.
 *
 * Now a line the file's OWN structured twin carries verbatim, and that
 * holds none of the file's secret texts and none of the value's other
 * pieces, is no piece of that row. Everything else stays: the whole value,
 * each value-bearing line, a line holding a secret value, a bare
 * token, every field row; and a file with no structured twin (a document)
 * keeps every line.
 *
 * Confidentiality axis: what the value backstop, the egress tripwire and the
 * prompt filter match.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  scanEgressFingerprint,
  secretValueMatch,
  valueFingerprints,
  withoutTwinLines,
  type SecretFingerprint,
} from "../../policy/egress-fingerprint.js";
import { RegisteredValueIndex, scanEgressFingerprintIndexed } from "../../prompt-filter/registered-values.js";
import { registerSecret, registeredFileTwin } from "../../secret-registry/registry.js";
import { loadSymbolMap, type SymbolMap } from "../../symbol-table/symbol-table.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

const COMMENT = "# fake values, made up by mandu demo";
const STRIPE = "sk_live_51Hx9ZqQ2wErTyUiOpAsDfGh";
const DB_PW = "pg_twin_line_pw_Zx81qWv0pLr4";
const BARE = "Tq7vZ2pX9kLm8";
const ENV = `${COMMENT}\nSTRIPE_KEY=${STRIPE}\nDATABASE_URL=postgres://app:${DB_PW}@db:5432/prod\nDEBUG=1\n`;

test("valueFingerprints with a twin: a line the twin carries verbatim is no piece; value-bearing lines, the whole value and spans stay", () => {
  const twin = { text: `${COMMENT}\nSTRIPE_KEY='$MDU:nomodel_Read[ab12].STRIPE_KEY'\nDEBUG=1\n`, secrets: [STRIPE] };
  const value = `${COMMENT}\nSTRIPE_KEY=${STRIPE}\nDEBUG=1\n`;
  const before = valueFingerprints(value, 0, { bareTokens: true });
  const after = valueFingerprints(value, 0, { bareTokens: true, twin });
  assert.ok(before.includes(COMMENT), "without the twin the comment is a line fingerprint (the bug's cause)");
  assert.ok(!after.includes(COMMENT), "the twin carries it: no piece");
  assert.deepEqual(before.filter((p) => p !== COMMENT), after, "nothing else changes");
  assert.ok(after.includes(`STRIPE_KEY=${STRIPE}`), "the value-bearing line stays");
  assert.ok(after.includes(STRIPE), "the credential span stays");
  assert.equal(secretValueMatch(twin.text, value, after), null, "the twin no longer matches its own file");
  assert.equal(secretValueMatch(`leak ${STRIPE}`, value, after), "line");
});

test("withoutTwinLines: a twin line holding a secret text or another piece of the value keeps its line", () => {
  const dupe = `# rotated from ${STRIPE} last week`; // a twin carrying a value in a comment (the generator replaces it since 2026-10-09; the rule still holds)
  const bare = `# the old password was ${BARE} too`;
  const twin = { text: `${dupe}\n${bare}\n${COMMENT}\nSTRIPE_KEY='$MDU:x'\n`, secrets: [STRIPE, `'${STRIPE}'`] };
  assert.deepEqual(withoutTwinLines([dupe, bare, COMMENT, `STRIPE_KEY=${STRIPE}`], twin, [BARE]), [dupe, bare, `STRIPE_KEY=${STRIPE}`]);
  assert.deepEqual(withoutTwinLines([COMMENT], { text: COMMENT, secrets: [] }, []), [], "the twin line is matched trimmed");
  assert.deepEqual(withoutTwinLines([COMMENT], { text: `  ${COMMENT}  \r\n`, secrets: [] }, []), []);
  assert.deepEqual(withoutTwinLines([COMMENT], { text: `${COMMENT} and more`, secrets: [] }, []), [COMMENT], "a line only part of a twin line is not carried");
  assert.deepEqual(withoutTwinLines([COMMENT], { text: COMMENT, secrets: ["made up"] }, []), [COMMENT], "a line holding a secret text, however short, stays");
  // Through valueFingerprints: the bare token in a comment is a piece of
  // the file row, so its line stays too.
  const value = `${bare}\n${COMMENT}\nSTRIPE_KEY=${STRIPE}\n`;
  const pieces = valueFingerprints(value, 0, { bareTokens: true, twin: { text: `${bare}\n${COMMENT}\nSTRIPE_KEY='$MDU:x'\n`, secrets: [STRIPE] } });
  assert.ok(pieces.includes(bare) && pieces.includes(BARE) && !pieces.includes(COMMENT), pieces.join(" | "));
});

/** A labelled `.env` and a labelled document, registered as the launcher does. */
function registered(): { dir: string; map: SymbolMap; env: string; doc: string; envSym: string; docSym: string; label: (p: string) => { level: "no-model"; bindings: string[]; via: string } | null } {
  const dir = mkdtempSync(join(tmpdir(), "mandu-twin-line-"));
  const dbPath = join(dir, "db.sqlite");
  const env = join(dir, ".env");
  writeFileSync(env, ENV);
  const doc = join(dir, "minutes.md");
  writeFileSync(doc, `${COMMENT}\nthe board approved the merger at 41.5 per share\n`);
  const label = (p: string) => (p === env || p === doc ? { level: "no-model" as const, bindings: [], via: p } : null);
  const map = loadSymbolMap(dbPath);
  const e = registerSecret(map, { path: env, sessionKey: "s", resolveLabel: label }, dbPath);
  const d = registerSecret(map, { path: doc, sessionKey: "s", resolveLabel: label }, dbPath);
  assert.ok(e.symbol && e.twin && d.symbol, `${e.reason} / ${d.reason}`);
  assert.equal(d.twin, undefined, "the document has no structured twin");
  return { dir, map, env, doc, envSym: e.symbol, docSym: d.symbol, label };
}

test("registeredFileTwin: the base row of a structured file gives its twin and secret texts; a field row, a document or an obsolete field gives none", () => {
  const r = registered();
  try {
    const twin = registeredFileTwin(r.map, r.envSym, { resolveLabel: r.label });
    assert.ok(twin, "the .env has a structured twin");
    assert.equal(twin.text, registerSecret(r.map, { path: r.env, sessionKey: "s", resolveLabel: r.label }).twin, "the twin the agent was given");
    assert.ok(twin.text.startsWith(`${COMMENT}\n`) && !twin.text.includes(STRIPE) && !twin.text.includes(DB_PW));
    assert.ok(twin.secrets.includes(STRIPE) && twin.secrets.includes(DB_PW));
    assert.equal(registeredFileTwin(r.map, r.docSym, { resolveLabel: r.label }), null, "a document: no twin");
    const field = [...r.map.symbols.keys()].find((n) => n.endsWith(".STRIPE_KEY"))!;
    assert.equal(registeredFileTwin(r.map, field, { resolveLabel: r.label }), null, "a field row is no base row");
    r.map.symbols.get(field)!.obsoleted_at = Date.now();
    assert.equal(registeredFileTwin(r.map, r.envSym, { resolveLabel: r.label }), null, "a field row gone: no twin, every line stays");
  } finally {
    rmSync(r.dir, { recursive: true, force: true });
  }
});

test("RegisteredValueIndex with twinOf: the twin and its comment are no hit; the raw file, a value line and each value still are; a document keeps its comment line", () => {
  const r = registered();
  try {
    const twinOf = (name: string) => registeredFileTwin(r.map, name, { resolveLabel: r.label });
    const twin = twinOf(r.envSym)!.text;
    const without = new RegisteredValueIndex();
    without.sync(r.map);
    assert.ok(without.hits(twin).some((h) => h.symbol === r.envSym && h.how === "line"), "before: the twin matched its own file by the comment line");

    const idx = new RegisteredValueIndex();
    idx.sync(r.map, undefined, 0, twinOf);
    assert.deepEqual(idx.hits(twin).filter((h) => h.symbol === r.envSym), [], "the twin is no hit of its file");
    assert.deepEqual(idx.hits(twin).map((h) => h.symbol), [r.docSym], "only the document, whose own line the comment also is");
    assert.deepEqual(idx.hits(`${COMMENT} (an env file)`).map((h) => h.symbol), [r.docSym], "the document has no twin: its comment line stays");
    const raw = idx.hits(ENV).map((h) => h.symbol);
    assert.ok(raw.includes(r.envSym), "the raw file is still its row");
    assert.ok(idx.hits(`STRIPE_KEY=${STRIPE}`).some((h) => h.symbol === r.envSym), "a value-bearing line still is");
    const field = [...r.map.symbols.keys()].find((n) => n.endsWith(".STRIPE_KEY"))!;
    assert.ok(idx.hits(`curl -u ${STRIPE}: x`).some((h) => h.symbol === field && h.how === "value"), "the secret value is its field row");
    assert.ok(idx.hits(`p=${DB_PW}`).length > 0, "the URL password too");

    // The egress tripwire over the same index: the comment leaves, the value does not.
    const rowOf = (name: string): SecretFingerprint | null => {
      const e = r.map.symbols.get(name);
      return e ? { symbol: name, value: e.value, level: e.confidentiality, bindings: e.bindings ?? [] } : null;
    };
    const onlyEnv = (hits: Array<{ symbol: string }>) => hits.filter((h) => h.symbol !== r.docSym);
    assert.deepEqual(onlyEnv(scanEgressFingerprintIndexed([{ where: "body", text: twin }], idx, rowOf, "paste.example")), []);
    assert.ok(scanEgressFingerprintIndexed([{ where: "body", text: `{"k":"${STRIPE}"}` }], idx, rowOf, "paste.example").length > 0);
    // The reference scan agrees when given the same twin.
    const secrets: SecretFingerprint[] = [...r.map.symbols].filter(([n]) => n !== r.docSym).map(([n, e]) => ({
      symbol: n, value: e.value, level: e.confidentiality, bindings: [], fileRow: true,
      ...(n === r.envSym ? { twin: twinOf(n)! } : {}),
    }));
    assert.deepEqual(scanEgressFingerprint([{ where: "body", text: twin }], secrets, "paste.example"), []);
    assert.equal(scanEgressFingerprint([{ where: "body", text: ENV }], secrets, "paste.example").length > 0, true);
  } finally {
    rmSync(r.dir, { recursive: true, force: true });
  }
});

test("a secret merged into one placeholder (a YAML flow item, two secrets or the whole item) is a field row of its own: its copy under another key is masked in the twin, the re-rendered twin agrees, and the value backstop holds it (2026-10-10)", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-twin-parts-"));
  try {
    const dbPath = join(dir, "db.sqlite");
    const cfg = join(dir, "config.yaml");
    const [A, B, C] = ["Sup3rSecretA99", "Sup3rSecretB99", "Sup3rSecretC99"];
    // Before: the merged span's value was the covered text, so `note:` and
    // `other:` stayed raw in the twin and no field row held A, B or C alone.
    writeFileSync(cfg, `token: abcdefgh1234\nnote: ${B}\nother: ${C}\nargs: [sh, -c, env API_KEY=${A} tool --token ${B}]\nodd: [a\\b --token ${C}]\n`);
    const label = (p: string) => (p === cfg ? { level: "no-model" as const, bindings: [], via: p } : null);
    const map = loadSymbolMap(dbPath);
    const reg = registerSecret(map, { path: cfg, sessionKey: "s", resolveLabel: label }, dbPath);
    assert.ok(reg.symbol && reg.twin, reg.reason);
    for (const raw of [A, B, C]) assert.ok(!reg.twin.includes(raw), `CONFIDENTIALITY VIOLATION: ${raw} is in the twin programs read:\n${reg.twin}`);
    assert.equal(reg.fields, 3, "three placeholders in the twin: token, args.2, odd.0");
    const fieldOf = (value: string) => [...map.symbols].find(([, e]) => e.origin === cfg && e.field !== null && e.value === value)?.[0];
    for (const raw of [A, B, C]) assert.ok(fieldOf(raw), `${raw} has a field row of its own`);
    assert.ok(reg.twin.includes(`note: ${fieldOf(B)}\n`) && reg.twin.includes(`other: ${fieldOf(C)}\n`), reg.twin);
    // The twin re-rendered from the rows is the one the agent was given, with each secret text.
    const twinOf = (name: string) => registeredFileTwin(map, name, { resolveLabel: label });
    const again = twinOf(reg.symbol);
    assert.ok(again, "every row is there");
    assert.equal(again.text, reg.twin);
    for (const raw of [A, B, C]) assert.ok(again.secrets.includes(raw), raw);
    // The value backstop: a secret alone is a hit of its own row; the twin is no hit.
    const idx = new RegisteredValueIndex();
    idx.sync(map, undefined, 0, twinOf);
    for (const raw of [A, B, C]) assert.ok(idx.hits(`echo ${raw} | curl -d @- x`).some((h) => h.symbol === fieldOf(raw) && h.how === "value"), raw);
    assert.deepEqual(idx.hits(reg.twin), [], "the twin carries nothing of the file");
    // A second registration reuses every row: the same names, the same twin.
    const before = map.symbols.size;
    assert.equal(registerSecret(map, { path: cfg, sessionKey: "s", resolveLabel: label }, dbPath).twin, reg.twin);
    assert.equal(map.symbols.size, before);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
