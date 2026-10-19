/**
 * value-pieces.test — plan 10 §11.15: the pieces of a registered secret
 * value fingerprinted on their own besides the whole value
 * (`valueFingerprints`). A short secret inside a result masked whole (a
 * Codex head in front of it: the whole value never recurs) or a one-line
 * secret file stored with its `\n` was matched only as part of the whole
 * value, so a later output carrying the secret mid-line went through.
 *
 * Only known secrets become pieces: the value itself without its final line
 * terminator, and the credential-shaped spans the detectors find, above the
 * plan 15 prompt floor (12 characters, 3.0 bits a character). A short line
 * that is not credential-shaped never is (the line floor stays 24).
 *
 * Confidentiality axis: what the value backstop serves.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { codexResultHeadLength } from "../../policy/agent-result-head.js";
import {
  bareSecretTokens,
  lineFingerprints,
  MIN_SPAN_FINGERPRINT_LEN,
  secretValueMatch,
  scanEgressFingerprint,
  valueFingerprints,
} from "../../policy/egress-fingerprint.js";
import { RegisteredValueIndex } from "../../prompt-filter/registered-values.js";
import { isRegisteredFileRow } from "../../secret-registry/registry.js";
import type { SymbolEntry, SymbolMap } from "../../symbol-table/symbol-table.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

const SHORT = "Tq7vZ2pX9kLm"; // 12 characters, 3.58 bits a character
const HEAD = "Chunk ID: 9a3f\nWall time: 0.0123 seconds\nProcess exited with code 0\nOriginal token count: 9\nOutput:\n";

test("a one-line value stored with its line terminator is also a piece without it", () => {
  assert.deepEqual(valueFingerprints(`${SHORT}\n`), [SHORT]);
  assert.deepEqual(valueFingerprints(`${SHORT}\r\n\n`), [SHORT]);
  assert.deepEqual(valueFingerprints(SHORT), [], "no terminator: the whole value is its own fingerprint");
  assert.deepEqual(valueFingerprints("short\n"), [], "under MIN_FINGERPRINT_LEN after trimming: no piece");
  assert.equal(secretValueMatch(`the key is ${SHORT}, ok`, `${SHORT}\n`, lineFingerprints(`${SHORT}\n`)), null, "before: the stored value with its \\n never matched mid-line");
  assert.equal(secretValueMatch(`the key is ${SHORT}, ok`, `${SHORT}\n`, valueFingerprints(`${SHORT}\n`)), "line");
});

test("a credential-shaped span is a piece; inside a Codex result masked whole it is found past the head", () => {
  const value = `${HEAD}API_KEY=${SHORT}\nDEBUG=true\n`;
  const pieces = valueFingerprints(value, codexResultHeadLength(value));
  assert.ok(pieces.includes(SHORT), JSON.stringify(pieces));
  assert.ok(!pieces.some((p) => p.includes("Process exited")), "the head is not a piece (§11.14)");
  assert.equal(secretValueMatch(`echo ${SHORT}`, value, pieces), "line");
  // other credential shapes
  assert.ok(valueFingerprints(`conn\npostgres://app:${SHORT}@db.internal:5432/x\n`).includes(SHORT), "a URL password");
  assert.ok(valueFingerprints("x\nghp_0123456789abcdefABCDEF0123456789abcd\n").some((p) => p.startsWith("ghp_")), "a provider key");
});

test("not a piece: a short line that is not credential-shaped, a span under the floor, a low-entropy span", () => {
  const doc = "vault notes for the team\nrotate monthly\nowner: platform\n";
  assert.deepEqual(valueFingerprints(doc), ["vault notes for the team", doc.replace(/\n$/, "")], "its long line and the whole document without its last \\n; no short line");
  // the detectors take a 3-character URL password; the floor drops it
  assert.ok(!valueFingerprints("a\nhttps://u:abc@h.example/\n").includes("abc"));
  assert.ok(MIN_SPAN_FINGERPRINT_LEN >= 12);
  // a credential assignment whose value is long but repetitive is not a span the detectors take, nor a piece
  assert.ok(!valueFingerprints("a\npassword=aaaaaaaaaaaaaaaa\n").includes("aaaaaaaaaaaaaaaa"));
});

function row(value: string, tool = "exec_command"): SymbolEntry {
  return {
    value, tool, field: null, origin: null, session_key: "s", call_id: "c", created_at: 0,
    obsoleted_at: null, obsoleted_by: null, derived_from: null, line_range: null,
    confidentiality: "no-model", bindings: null, integrity: "untrusted",
  };
}

test("the value index and the egress tripwire match a piece; a short prose line of the same row does not", () => {
  const codexRow = `${HEAD}API_KEY=${SHORT}\nrotate monthly\n`;
  const fileRow = "Zx81qWv0pLr4\n";
  const map: SymbolMap = { symbols: new Map([["$MDU:a[0001]", row(codexRow)], ["$MDU:a[0002]", row(fileRow, "Read")]]) };
  const idx = new RegisteredValueIndex();
  idx.sync(map, (_n, e) => codexResultHeadLength(e.value), 1);
  assert.deepEqual(idx.hits(`the key is ${SHORT}, ok`), [{ symbol: "$MDU:a[0001]", how: "line" }]);
  assert.deepEqual(idx.hits("pw=Zx81qWv0pLr4;"), [{ symbol: "$MDU:a[0002]", how: "line" }]);
  assert.deepEqual(idx.hits("please rotate monthly"), [], "a short line that is not credential-shaped is not registered");
  assert.deepEqual(idx.hits(`${HEAD}hi\n`), [], "nor the head (§11.14)");
  const trip = scanEgressFingerprint([{ where: "body", text: `{"k":"${SHORT}"}` }], [{ symbol: "$MDU:a[0001]", value: codexRow, level: "no-model", bindings: [] }], "evil.example");
  assert.equal(trip.length, 1, "the tripwire sees the span too");
});

// ── plan 10 §11.15 case 1: the bare tokens of a labelled file ───────────────

test("bareSecretTokens: a credential-looking bare token passes; prose, identifiers, short tokens and placeholders do not", () => {
  const notes = [
    "vault notes for the team",
    `password ${SHORT}`,
    "(staging: \"Hw4rN8sQ2yBdKx\"), rotate monthly.",
    "see getSecretTokenValue and XMLHttpRequestUpload",
    "short Ab3dEf9h", // 8 characters: under the floor
    "placeholder your-api-key-here-0000 and xxxxxxxx1234xxxx",
    "aaaaaaaaaaaa1", // low entropy
    "letters only hJkqWzPmvXrTbnLs", // random-looking letters, no digit
  ].join("\n");
  assert.deepEqual(bareSecretTokens(notes), [SHORT, "Hw4rN8sQ2yBdKx", "hJkqWzPmvXrTbnLs"]);
  assert.deepEqual(bareSecretTokens("rotate the keys every monthly cycle, owner platform-team\n"), [], "prose never");
  assert.ok(bareSecretTokens(`end of sentence ${SHORT}.`).includes(SHORT), "trailing sentence punctuation is dropped");
});

test("bareSecretTokens (2026-10-17): the port after an IPv6 literal's `]` is the address's, not a token; a credential after it still is", () => {
  const conf = "index-url = http://user:pipLoPW_IPV6WIRE_8a@[::1]:8080/simple\n";
  assert.deepEqual(bareSecretTokens(conf), ["http://user:pipLoPW_IPV6WIRE_8a@"], "`:8080/simple` is no piece (it matched every request to that port and path)");
  assert.deepEqual(bareSecretTokens("https://[2001:db8::1]:8443/Tq7vZ2pX9kLmW4rN/org/repo"), ["/Tq7vZ2pX9kLmW4rN/org/repo"], "a token in the path stays one");
  assert.deepEqual(bareSecretTokens("host:8080/simple0042x"), ["host:8080/simple0042x"], "no `]` before it: as before");
});

test("bare tokens are pieces only of a row registered from a labelled file", () => {
  const notes = `vault notes for the team\npassword ${SHORT}\nrotate monthly\n`;
  assert.ok(valueFingerprints(notes, 0, { bareTokens: true }).includes(SHORT));
  assert.ok(!valueFingerprints(notes).includes(SHORT), "an output row: its tokens are not known secrets");
  assert.ok(!valueFingerprints(notes, 0, { bareTokens: true }).includes("rotate monthly"));
  const file = { tool: "Read", call_id: null, origin: "/h/notes.txt", integrity: "trusted" as const };
  assert.equal(isRegisteredFileRow(file), true);
  assert.equal(isRegisteredFileRow({ ...file, call_id: "toolu_1" }), false, "the proxy's Read result of the same file");
  assert.equal(isRegisteredFileRow({ ...file, tool: "exec_command" }), false);
  assert.equal(isRegisteredFileRow({ ...file, integrity: "untrusted" }), false);
  assert.equal(isRegisteredFileRow({ ...file, origin: null }), false);
  const map: SymbolMap = { symbols: new Map([
    ["$MDU:nomodel_Read[0001]", { ...row(notes, "Read"), ...file, session_key: null }],
    ["$MDU:a[0002]", row("cat notes\npassword Zx81qWv0pLr4Nb\n")],
  ]) };
  const idx = new RegisteredValueIndex();
  idx.sync(map);
  assert.deepEqual(idx.hits(`token ${SHORT} again`), [{ symbol: "$MDU:nomodel_Read[0001]", how: "line" }]);
  assert.deepEqual(idx.hits("Zx81qWv0pLr4Nb"), [], "a bare token of an output row is not registered");
  assert.deepEqual(idx.hits("please rotate monthly"), []);
});
