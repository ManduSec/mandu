/**
 * symbol-token-fingerprint.test — "a symbol token is no fingerprint"
 * (2026-10-08, confidentiality.md §4; plan 10 §11.8). Found by the real-model
 * drill conf-bound-host-release on Codex 0.160: `cat memo/brief.md` (a
 * document labelled any-model, bound to example.com) printed the file's
 * whole-file twin, one token; the path-derived precaution masked the result
 * whole as a NEW row whose value is Codex's head plus that token; the
 * token's line (exactly 24 characters, the line floor) became a line piece
 * of that row, and the egress tripwire blocked `curl --data-binary
 * @memo/brief.md` to example.com, the release the per-symbol gate had just
 * allowed.
 *
 * Pinned here: a value, line or piece made of `$MDU:` tokens only (no
 * letter or digit outside a token) is no fingerprint, in the per-row
 * reference (`valueFingerprints`, `secretValueMatch`,
 * `scanEgressFingerprint`) and in the value index the arbiter serves from
 * (`RegisteredValueIndex`, the tripwire, the value backstop and the prompt
 * filter). A line with a secret byte beside a token, and every raw secret,
 * still match.
 *
 * Confidentiality axis: what the tripwire and the value backstop serve.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { codexResultHeadLength } from "../../policy/agent-result-head.js";
import {
  fingerprintableValue,
  lineFingerprints,
  scanEgressFingerprint,
  secretValueMatch,
  symbolTokensOnly,
  valueFingerprints,
  valuePieces,
} from "../../policy/egress-fingerprint.js";
import { RegisteredValueIndex, scanEgressFingerprintIndexed } from "../../prompt-filter/registered-values.js";
import type { SymbolEntry, SymbolMap } from "../../symbol-table/symbol-table.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

/** The drill's twin token: 24 characters, exactly MIN_LINE_FINGERPRINT_LEN. */
const TWIN = "$MDU:anymodel_Read[2451]";
const RAW = "Deal brief. Reference code: CONF11_MEMO_CANARY_2718. Keep internal.\n";
/** Codex 0.160's exec result of `cat memo/brief.md`, as the drill logged it. */
const CODEX_CAT = `Script completed\nWall time 0.5 seconds\nOutput:\n${TWIN}\n`;

function row(value: string, o: Partial<SymbolEntry> = {}): SymbolEntry {
  return {
    value, tool: "exec_command", field: null, origin: "cat memo/brief.md", session_key: "s", call_id: "call_1", created_at: 0,
    obsoleted_at: null, obsoleted_by: null, derived_from: null, line_range: null,
    confidentiality: "any-model", bindings: null, integrity: "trusted", ...o,
  };
}

test("symbolTokensOnly: tokens with spaces or punctuation between them; any letter or digit outside a token is not", () => {
  assert.equal(TWIN.length, 24, "the drill's token sits exactly on the line floor");
  assert.equal(symbolTokensOnly(TWIN), true);
  assert.equal(symbolTokensOnly(`  ${TWIN}\n`), true);
  assert.equal(symbolTokensOnly(`"${TWIN}", "$MDU:nomodel_Read[9bbd].STRIPE_KEY"`), true, "a field token, quotes and a comma");
  assert.equal(symbolTokensOnly(`${TWIN}${TWIN}`), true);
  assert.equal(symbolTokensOnly(`ref ${TWIN}`), false, "a word beside the token");
  assert.equal(symbolTokensOnly(`${TWIN} 7`), false, "a digit beside the token");
  assert.equal(symbolTokensOnly(`${TWIN} é`), false, "a non-ASCII letter counts");
  assert.equal(symbolTokensOnly("$MDU:anymodel_Read"), false, "no hash: not a token, its letters stay");
  assert.equal(symbolTokensOnly("$MDU:anymodel_Read[zzzz]"), false, "a non-hex hash is not a token");
  assert.equal(symbolTokensOnly("-- -- --"), false, "no token at all");
  assert.equal(symbolTokensOnly(""), false);
  assert.equal(fingerprintableValue(TWIN), false);
  assert.equal(fingerprintableValue(RAW), true);
  assert.equal(fingerprintableValue("short"), false, "the length floor still applies");
});

test("the drill's composite row: its token line is no piece, with or without Codex's head skipped", () => {
  for (const from of [0, codexResultHeadLength(CODEX_CAT)]) {
    const pieces = valueFingerprints(CODEX_CAT, from);
    assert.ok(!pieces.some((p) => p.includes("$MDU:") && symbolTokensOnly(p)), `from=${from}: ${JSON.stringify(pieces)}`);
    assert.equal(secretValueMatch(`${TWIN}\n`, CODEX_CAT, pieces), null, `from=${from}: the twin's bytes are no hit`);
    assert.ok(valuePieces(CODEX_CAT, from).complete);
  }
  assert.ok(!lineFingerprints(CODEX_CAT).includes(TWIN), "lineFingerprints drops it too");
  // Before (regression pin): the token line WAS a line piece.
  assert.ok(lineFingerprints(`a\n${TWIN} x\n`).includes(`${TWIN} x`), "a token with a letter beside it stays a line");
});

test("a line that carries secret bytes beside a token stays a fingerprint; every raw secret still matches", () => {
  const mixed = `Output:\nref CONF11_MEMO_CANARY_2718 ${TWIN}\n`;
  const pieces = valueFingerprints(mixed);
  assert.ok(pieces.includes(`ref CONF11_MEMO_CANARY_2718 ${TWIN}`), JSON.stringify(pieces));
  assert.equal(secretValueMatch(`x ref CONF11_MEMO_CANARY_2718 ${TWIN} y`, mixed, pieces), "line");
  // A raw document still matches whole and by its long line.
  assert.equal(secretValueMatch(`body=${RAW}`, RAW, valueFingerprints(RAW)), "value");
});

test("scanEgressFingerprint: the twin to its bound host passes; a raw copy to an unbound host still trips", () => {
  const secrets = [
    { symbol: "$MDU:anymodel_exec_command[5f38]", value: CODEX_CAT, level: "any-model" as const, bindings: [] },
    { symbol: TWIN, value: RAW, level: "any-model" as const, bindings: ["example.com"] },
    // OpenCode's shape: a `read` of the twin masked whole, the value one token.
    { symbol: "$MDU:anymodel_read[40ad]", value: TWIN, level: "any-model" as const, bindings: [] },
  ];
  assert.deepEqual(scanEgressFingerprint([{ where: "body", text: `${TWIN}\n` }], secrets, "example.com"), [], "the twin: no raw byte");
  assert.deepEqual(scanEgressFingerprint([{ where: "body", text: `${TWIN}\n` }], secrets, "httpbin.org"), [], "the per-symbol gate judges the token there, not the tripwire");
  const raw = scanEgressFingerprint([{ where: "body", text: RAW }], secrets, "httpbin.org");
  assert.deepEqual(raw.map((h) => h.symbol), [TWIN], "the raw document at an unbound host trips");
  assert.deepEqual(scanEgressFingerprint([{ where: "body", text: RAW }], secrets, "example.com"), [], "and is a release at its bound host");
});

test("the value index agrees: no pattern for a token-only value or line; the indexed tripwire answers as the reference", () => {
  const map: SymbolMap = { symbols: new Map([
    ["$MDU:anymodel_exec_command[5f38]", row(CODEX_CAT)],
    [TWIN, row(RAW, { tool: "Read", origin: "/w/memo/brief.md", call_id: null, bindings: ["example.com"] })],
    ["$MDU:anymodel_read[40ad]", row(TWIN, { tool: "read", origin: "/w/memo/brief.md" })],
  ]) };
  for (const head of [false, true]) {
    const idx = new RegisteredValueIndex();
    idx.sync(map, head ? (_n, e) => codexResultHeadLength(e.value) : undefined, head ? 1 : 0);
    assert.deepEqual(idx.hits(`${TWIN}\n`), [], `head=${head}: the twin token matches no row`);
    assert.deepEqual(idx.hits(`curl -d ${TWIN} http://x`), []);
    assert.deepEqual(idx.hits(RAW).map((h) => h.symbol), [TWIN], "the raw document still matches its row");
    const live = (name: string) => {
      const e = map.symbols.get(name)!;
      return { symbol: name, value: e.value, level: e.confidentiality, bindings: e.bindings ?? [] };
    };
    assert.deepEqual(scanEgressFingerprintIndexed([{ where: "body", text: `${TWIN}\n` }], idx, live, "example.com"), []);
    assert.deepEqual(scanEgressFingerprintIndexed([{ where: "body", text: RAW }], idx, live, "httpbin.org").map((h) => h.symbol), [TWIN]);
  }
});
