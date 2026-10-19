/**
 * large-file-pieces.test — plan 10 §11.18: the pieces of a LARGE or BINARY
 * registered value, computed window by window under a bound
 * (`valuePieces`, `PieceLimits`), and the value index's record of a row
 * whose pieces were cut at the bound (`incompleteRows`, the fail-closed
 * signal the arbiter's `callTaint` reads).
 *
 * Before: a binary file's printable strings were glued to its NUL bytes, so
 * none of its tokens or lines was a piece (`strings blob | grep` carried
 * them); a large file's pieces were computed in one pass over the whole value
 * with no bound (a dense 16 MiB file: 726,420 pieces, one GiB of heap, a
 * ten-second automaton rebuilt on every new secret row).
 *
 * Confidentiality axis: what the value backstop serves.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";

import {
  DEFAULT_PIECE_LIMITS,
  PIECE_WINDOW_CHARS,
  secretValueMatch,
  valueFingerprints,
  valuePieces,
} from "../../policy/egress-fingerprint.js";
import { RegisteredValueIndex } from "../../prompt-filter/registered-values.js";
import type { SymbolEntry, SymbolMap } from "../../symbol-table/symbol-table.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

const SHORT = "Tq7vZ2pX9kLm"; // 12 characters, a bare credential token
const LINE = "the vault unseal phrase is orchid-lantern-copper-41";

function fileRow(value: string): SymbolEntry {
  return {
    value, tool: "Read", field: null, origin: "/h/big.dat", session_key: null, call_id: null, created_at: 0,
    obsoleted_at: null, obsoleted_by: null, derived_from: null, line_range: null,
    confidentiality: "no-model", bindings: null, integrity: "trusted",
  };
}

/** `n` characters of filler text lines (no credential-shaped token). */
function filler(n: number): string {
  const line = "lorem ipsum dolor sit amet consectetur\n";
  return line.repeat(Math.ceil(n / line.length)).slice(0, n).replace(/[^\n]*$/, "");
}

test("a binary value: its printable strings are pieces (a bare token, a long line); the NUL bytes around them are not part of them", () => {
  const blob = `\u0000\u0001\u0002SQLite format 3\u0000\u0000\u0007password ${SHORT}\u0000\u0013${LINE}\u0000\u0000ÿ\u0000`;
  const pieces = valueFingerprints(blob, 0, { bareTokens: true });
  assert.ok(pieces.includes(SHORT), `the token is a piece: ${JSON.stringify(pieces)}`);
  assert.ok(pieces.includes(LINE), "a printable run of 24+ characters is a line piece");
  assert.ok(pieces.every((p) => !p.includes("\u0000")), "no piece carries a NUL");
  // what `strings blob` prints, one run a line, is caught
  assert.equal(secretValueMatch(`SQLite format 3\npassword ${SHORT}\n`, blob, pieces), "line");
  // an output row (no bareTokens): only the line and credential-shaped spans
  assert.ok(!valueFingerprints(blob).includes(SHORT));
  assert.equal(valuePieces(blob, 0, { bareTokens: true }).complete, true);
});

test("a value over one window: the same pieces as the one-pass extraction (a token in the last window, a PEM key across a window boundary)", () => {
  const pem = `-----BEGIN OPENSSH PRIVATE KEY-----\n${"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n".repeat(6)}-----END OPENSSH PRIVATE KEY-----\n`;
  // the key starts 100 characters before the first window boundary
  const head = filler(PIECE_WINDOW_CHARS - 100);
  const value = `${head}\n${pem}${filler(PIECE_WINDOW_CHARS)}\npassword ${SHORT}\n${LINE}\n`;
  assert.ok(value.length > 2 * PIECE_WINDOW_CHARS);
  const windowed = valuePieces(value, 0, { bareTokens: true });
  assert.equal(windowed.complete, true);
  assert.ok(windowed.pieces.includes(SHORT), "a token in the last window");
  assert.ok(windowed.pieces.includes(LINE));
  assert.ok(windowed.pieces.some((p) => p.startsWith("-----BEGIN OPENSSH PRIVATE KEY-----") && p.endsWith("-----END OPENSSH PRIVATE KEY-----")), "the PEM span across the boundary, whole");
  // the reference: the one-pass extraction of the same value (no bound)
  const reference = valuePieces(value, 0, { bareTokens: true, limits: { scanChars: Infinity, pieces: Infinity, window: Infinity } });
  assert.deepEqual(new Set(windowed.pieces), new Set(reference.pieces));
});

test("the bounds: past `pieces` or `scanChars` the extraction stops and says it is incomplete; under them it is complete", () => {
  const tokens = Array.from({ length: 50 }, () => `k${randomBytes(9).toString("base64url")}9`);
  const value = tokens.map((t) => `token ${t}`).join("\n") + "\n";
  const capped = valuePieces(value, 0, { bareTokens: true, limits: { ...DEFAULT_PIECE_LIMITS, pieces: 10 } });
  assert.equal(capped.complete, false);
  assert.ok(capped.pieces.length <= 10);
  assert.equal(valuePieces(value, 0, { bareTokens: true }).complete, true);
  // a token past the scan bound is no piece, and the value is incomplete
  const long = `${filler(3 * 1024 * 1024)}\npassword ${SHORT}\n`;
  const scanned = valuePieces(long, 0, { bareTokens: true, limits: { ...DEFAULT_PIECE_LIMITS, scanChars: 1024 * 1024 } });
  assert.equal(scanned.complete, false);
  assert.ok(!scanned.pieces.includes(SHORT));
  const whole = valuePieces(long, 0, { bareTokens: true });
  assert.equal(whole.complete, true);
  assert.ok(whole.pieces.includes(SHORT), "the default bound covers a 3 MiB file");
});

test("RegisteredValueIndex: a large file row's token and line are hits; a row cut at the bound is in incompleteRows; a new small row does not rebuild the large row's automaton", () => {
  // 2 MiB of distinct log lines: ~50,000 line pieces, under the default bound
  const log = Array.from({ length: 50_000 }, (_, i) => `2026-10-07 request ${String(i).padStart(6, "0")} served`).join("\n");
  const big = `${log}\npassword ${SHORT}\n${LINE}\n`;
  const map: SymbolMap = { symbols: new Map([["$MDU:nomodel_Read[0001]", fileRow(big)]]) };
  const idx = new RegisteredValueIndex();
  idx.sync(map);
  assert.equal(idx.automatonBuilds, 2, "the large row's own automaton and the (empty) small rows'");
  assert.deepEqual(idx.hits("x 2026-10-07 request 031337 served y"), [{ symbol: "$MDU:nomodel_Read[0001]", how: "line" }], "a line deep in the file");
  assert.deepEqual(idx.hits(`login with ${SHORT}`), [{ symbol: "$MDU:nomodel_Read[0001]", how: "line" }]);
  assert.deepEqual(idx.hits(`> ${LINE}`), [{ symbol: "$MDU:nomodel_Read[0001]", how: "line" }]);
  assert.deepEqual([...idx.incompleteRows()], []);
  const builds = idx.automatonBuilds;
  // a new secret row: only the small rows' automaton is rebuilt
  map.symbols.set("$MDU:a[0002]", { ...fileRow("Zx81qWv0pLr4Nb\n"), tool: "exec_command", call_id: "c", integrity: "untrusted", origin: null });
  idx.sync(map);
  assert.equal(idx.automatonBuilds, builds + 1, "one automaton built (the small rows'), not the large row's");
  assert.deepEqual(idx.hits(`x Zx81qWv0pLr4Nb ${SHORT}`).map((h) => h.symbol).sort(), ["$MDU:a[0002]", "$MDU:nomodel_Read[0001]"]);
  const occ = idx.occurrences(`a ${SHORT} b Zx81qWv0pLr4Nb`);
  assert.deepEqual(occ.map((o) => [o.symbol, o.text]), [["$MDU:nomodel_Read[0001]", SHORT], ["$MDU:a[0002]", "Zx81qWv0pLr4Nb"]], "occurrences of every group, in text order");

  // the same row under a small bound: cut, and named
  const small = new RegisteredValueIndex({ pieceLimits: { ...DEFAULT_PIECE_LIMITS, scanChars: 1024 * 1024 } });
  small.sync(map);
  assert.deepEqual([...small.incompleteRows()], ["$MDU:nomodel_Read[0001]"]);
});
