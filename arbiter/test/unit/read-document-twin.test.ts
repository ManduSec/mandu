/**
 * read-document-twin.test.ts — the read leg of "A document's own twin"
 * (plan 10 §11.8, 2026-10-12): a built-in read (Claude Code's `Read`,
 * OpenClaw's and OpenCode's `read`) whose rendering is EXACTLY a labelled
 * document's whole-file twin, the path's own newest base token, classifies
 * public; anything else keeps the document's label.
 *
 * Pure: the twin lookup is a map. Mandu-new test.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { allocateSymbol, loadSymbolMap } from "../../symbol-table/symbol-table.js";
import { registerSecret, wholeFileTwinFor } from "../../secret-registry/registry.js";
import { createEngineBackedPolicy } from "../../policy/policy-interface.js";
import { bindSessionSpec } from "../../policy/tool-inbound.js";
import { claudeReadWholeFileToken, wholeFileTwinTextToken } from "../../policy/claude-code-inbound.js";
import { resolvePathLabel, type PathLabel } from "../../policy/path-labels.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the rule is a confidentiality verdict

const DOC = "/ws/memo/brief.md";
const CRLF = "/ws/memo/win.txt";
const NOEOL = "/ws/memo/noeol.txt";
const TD = "$MDU:anymodel_Read[2451]";
const TCR = "$MDU:nomodel_Read[c0de]";
const TNE = "$MDU:nomodel_Read[0e01]";
const OTHER = "$MDU:anymodel_Read[77ab]"; // another document's (or an older registration's) token
const TWINS = new Map<string, { token: string; terminator: string }>([
  [DOC, { token: TD, terminator: "\n" }],
  [CRLF, { token: TCR, terminator: "\r\n" }],
  [NOEOL, { token: TNE, terminator: "" }],
]);

bindSessionSpec("rdt-cc", "claude-code");
bindSessionSpec("rdt-oc", "openclaw-agent");
bindSessionSpec("rdt-od", "opencode");

const LABELS = new Map<string, PathLabel>([
  [DOC, { path: DOC, confidentiality: "any-model", bindings: [], recursive: false, source: "user", updatedAt: 1 }],
  [CRLF, { path: CRLF, confidentiality: "no-model", bindings: [], recursive: false, source: "user", updatedAt: 1 }],
  [NOEOL, { path: NOEOL, confidentiality: "no-model", bindings: [], recursive: false, source: "user", updatedAt: 1 }],
]);
const policy = (wired = true) => createEngineBackedPolicy({
  policyFileOverride: {},
  labelLookup: (p: string) => resolvePathLabel(p, LABELS, "/home/u"),
  confidentiality: true,
  integrity: false,
  symbolAllocated: (t: string) => t === TD || t === TCR || t === TNE || t === OTHER,
  ...(wired ? { wholeFileTwin: (path: string) => TWINS.get(path) ?? null } : {}),
});
const ccRead = (p: ReturnType<typeof policy>, value: string, file_path = DOC) =>
  p.classify({ tool: "Read", value, boundary: "model_context", origin: file_path, params: { file_path }, sessionKey: "rdt-cc" });
const ocRead = (p: ReturnType<typeof policy>, value: string, path = DOC) =>
  p.classify({ tool: "read", value, boundary: "model_context", origin: path, params: { path }, sessionKey: "rdt-oc" });
const odRead = (p: ReturnType<typeof policy>, value: string, filePath = DOC) =>
  p.classify({ tool: "read", value, boundary: "model_context", origin: filePath, params: { filePath }, sessionKey: "rdt-od" });
const od1 = (token: string, path = DOC) => [`<path>${path}</path>`, "<type>file</type>", "<content>", `1: ${token}`, "", "(End of file - total 1 lines)", "</content>"].join("\n");

test("claudeReadWholeFileToken: line 1 and one token, then at most the harness's empty row for a file that ends in a terminator", () => {
  assert.equal(claudeReadWholeFileToken(`     1\t${TD}`, "\n"), TD);
  assert.equal(claudeReadWholeFileToken(`     1\t${TD}\n`, "\n"), TD);
  assert.equal(claudeReadWholeFileToken(`     1\t${TD}\n     2\t`, "\n"), TD);
  assert.equal(claudeReadWholeFileToken(`     1\t${TD}\n     2`, "\n"), TD, "the separator trimmed off the empty row");
  assert.equal(claudeReadWholeFileToken(`1:${TD}`, "\n"), TD, "the tab-aware form");
  assert.equal(claudeReadWholeFileToken(`     1→${TD}`, "\n"), TD, "older builds' arrow");
  assert.equal(claudeReadWholeFileToken(`     1\t${TCR}\r\n     2\t`, "\r\n"), TCR, "a CRLF file's \\r");
  assert.equal(claudeReadWholeFileToken(`     1\t${TNE}`, ""), TNE);
  // misses
  assert.equal(claudeReadWholeFileToken(`     1\t${TNE}\n     2\t`, ""), null, "an empty row for a file with no final terminator");
  assert.equal(claudeReadWholeFileToken(`     1\t${TD}\r`, "\n"), null, "a \\r after a LF file's token");
  assert.equal(claudeReadWholeFileToken(`     2\t${TD}`, "\n"), null, "line 2: an offset read");
  assert.equal(claudeReadWholeFileToken(`     1\t${TD}\n     2\tx`, "\n"), null, "a second line with text");
  assert.equal(claudeReadWholeFileToken(`     1\t${TD}\n     2\t\n     3\t`, "\n"), null, "three rows");
  assert.equal(claudeReadWholeFileToken(`     1\t${TD} ${TD}`, "\n"), null, "two tokens");
  assert.equal(claudeReadWholeFileToken(`     1\t ${TD}`, "\n"), null, "a byte before the token");
  assert.equal(claudeReadWholeFileToken(`${TD}`, "\n"), null, "no gutter");
  assert.equal(claudeReadWholeFileToken(`     1\t$MDU:anymodel_Read[245`, "\n"), null, "a cut token");
});

test("wholeFileTwinTextToken: the read's text is one token, trailing whitespace aside", () => {
  assert.equal(wholeFileTwinTextToken(`${TD}\n`), TD);
  assert.equal(wholeFileTwinTextToken(TD), TD);
  assert.equal(wholeFileTwinTextToken(` ${TD}`), null);
  assert.equal(wholeFileTwinTextToken(`${TD}\nx`), null);
  assert.equal(wholeFileTwinTextToken(`${TD}${TD}`), null);
  assert.equal(wholeFileTwinTextToken(null), null);
});

test("Claude Code Read: the document's own token classifies public; the raw text, another token, an offset or any other byte keeps the label", () => {
  const p = policy();
  for (const v of [`     1\t${TD}\n`, `     1\t${TD}\n     2\t`]) {
    const r = ccRead(p, v);
    assert.equal(r.confidentiality, "public", JSON.stringify(v));
    assert.match(r.reason, /whole-file read-twin/);
  }
  assert.equal(ccRead(p, `     1\t${TCR}\r\n     2\t`, CRLF).confidentiality, "public");
  assert.equal(ccRead(p, `     1\t${TNE}`, NOEOL).confidentiality, "public");
  for (const v of [
    "     1\tDeal brief. Reference code: CANARY.\n", // the raw document
    `     1\t${OTHER}\n`, // another document's / an older registration's token
    `     1\t${TNE}\n`, // the right shape, the wrong path's token
    `     2\t${TD}\n`, // an offset read
    `     1\t${TD}\n     2\tmore\n`, // a second line
    `     1\t${TD}.body\n`, // a field tail
  ]) {
    assert.equal(ccRead(p, v).confidentiality, "any-model", JSON.stringify(v));
  }
  // the lookup not wired: the rule never fires
  assert.equal(ccRead(policy(false), `     1\t${TD}\n`).confidentiality, "any-model");
});

test("OpenClaw and OpenCode read: the document's own token as the read's text classifies public; anything else keeps the label", () => {
  const p = policy();
  assert.equal(ocRead(p, `${TD}\n`).confidentiality, "public");
  assert.match(ocRead(p, `${TD}\n`).reason, /whole-file read-twin/);
  assert.equal(odRead(p, od1(TD)).confidentiality, "public");
  assert.equal(odRead(p, [`Read file ${DOC}, lines 1-1`, `1: ${TD}`].join("\n")).confidentiality, "public", "OpenCode 2's frame");
  assert.equal(ocRead(p, `${TD}\nmore\n`).confidentiality, "any-model");
  assert.equal(ocRead(p, `${OTHER}\n`).confidentiality, "any-model");
  assert.equal(odRead(p, od1(`${TD} x`)).confidentiality, "any-model");
  assert.equal(odRead(p, od1(TD, "/ws/other.md")).confidentiality, "any-model", "a frame naming another path");
  // the right token under the WRONG agent's tool name: Claude Code's `read` (lower case) is no read here
  assert.equal(p.classify({ tool: "read", value: `${TD}\n`, boundary: "model_context", origin: DOC, params: { path: DOC }, sessionKey: "rdt-cc" }).confidentiality, "any-model");
});

test("wholeFileTwinFor: the path's NEWEST registered base row, only when its twin is the whole-file twin; a proxy's Read row and a structured file never answer", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-rdt-reg-"));
  try {
    const db = join(dir, "symbols.db");
    const doc = join(dir, "brief.md");
    const env = join(dir, ".env");
    const labels = new Map<string, PathLabel>([[doc, { path: doc, confidentiality: "any-model", bindings: [], recursive: false, source: "user", updatedAt: 1 }]]);
    const resolveLabel = (p: string) => resolvePathLabel(p, labels, "/home/u");
    const map = loadSymbolMap(db);
    writeFileSync(doc, "draft\n");
    const old = registerSecret(map, { path: doc, resolveLabel }, db).symbol!;
    writeFileSync(doc, "final text\r\n");
    const cur = registerSecret(map, { path: doc, resolveLabel }, db).symbol!;
    assert.notEqual(old, cur);
    assert.deepEqual(wholeFileTwinFor(map, doc, { resolveLabel }), { token: cur, terminator: "\r\n" }, "the newest registration, its own terminator");
    // a proxy's own Read row on the same path (it has a call id) is no candidate
    allocateSymbol(map, { tool: "Read", value: `${cur}\r\n`, origin: doc, callId: "toolu_x", confidentiality: "any-model", integrity: "trusted" });
    assert.equal(wholeFileTwinFor(map, doc, { resolveLabel })?.token, cur);
    // a structured file (a catalog `.env` with a secret value): no whole-file twin
    writeFileSync(env, "STRIPE_KEY=sk_live_abcdefabcdef0123456789\n");
    assert.ok(registerSecret(map, { path: env }, db).twin, "a structured twin");
    assert.equal(wholeFileTwinFor(map, env), null);
    assert.equal(wholeFileTwinFor(map, join(dir, "nothing.md")), null);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
