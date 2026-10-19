/**
 * own-text-twin — plan 10 §11.13, "A config with no secret reaches the model
 * as its text" (2026-10-17), the pure halves:
 *   - which registered config twins as its OWN TEXT (`isOwnTextTwin`): an
 *     exhaustive shape whose extraction (and the credential belt) found no
 *     secret value, on the catalog's word under an attested HOME, and no
 *     human label; anything else (a span, a belt hit, a label, a HOME no
 *     one named, an unknown keyword) is not, and stays one handle;
 *   - which rows the value backstop then does not count (`isOwnTextRow`):
 *     the base row and a proxy's Read row of that text, never a field row;
 *   - the read and shell content tests (`isOwnTextTwinText`,
 *     `ownTextTwinExecOutputPath`, `claudeReadRenderingText`);
 *   - the launch HOME helpers of `decideSecretOpen` (`stricterMatch`,
 *     `attestedHomeOf`).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { allocateSymbol, loadSymbolMap } from "../../symbol-table/symbol-table.js";
import { isOwnTextRow, isOwnTextTwin, ownTextTwinFor, registerSecret, twinFormOf, twinMatchOf, wholeFileTwinFor, wholeFileTwinOfBase } from "../../secret-registry/registry.js";
import { claudeReadRenderingText, isOwnTextTwinText, ownTextTwinExecOutputPath } from "../../policy/claude-code-inbound.js";
import { pathConfidentiality } from "../../policy/secret-catalog.js";
import { attestedHomeOf, stricterMatch } from "../../ipc/server.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the confidentiality axis is what the twins serve

const PLAIN = "Host build\n  HostName 10.1.2.3\n  User deployer\n  IdentityFile ~/.ssh/id_work\n  Port 2222\n";
const GH = "ghp_" + "Zq7vX2pL9kWm4Rt8Yb3Nc6Hd1Jf5Gs0Ae2Uo";

function home(): { dir: string; home: string; db: string; put: (rel: string, text: string) => string; done: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "mandu-owntext-"));
  const h = join(dir, "home");
  mkdirSync(h, { recursive: true });
  return {
    dir, home: h, db: join(dir, "symbols.db"),
    put: (rel, text) => { const p = join(h, rel); mkdirSync(join(p, ".."), { recursive: true }); writeFileSync(p, text); return p; },
    done: () => rmSync(dir, { recursive: true, force: true }),
  };
}

test("isOwnTextTwin: an exhaustive config with no secret value, on the catalog's word under a named HOME", () => {
  const f = home();
  try {
    const p = f.put(".ssh/config", PLAIN);
    assert.equal(isOwnTextTwin(p, PLAIN, { homes: [f.home] }), true, "~/.ssh/config of a named HOME, nothing secret");
    // The arbiter's own HOME is not this one: with no HOME named, the
    // catalog does not cover the path, and nothing vouches (fail closed).
    assert.equal(isOwnTextTwin(p, PLAIN, {}), false, "a HOME no one named vouches for nothing");
    // A secret value anywhere: a structured twin, never its own text.
    assert.equal(isOwnTextTwin(p, `${PLAIN}  SetEnv TOKEN=abcdef123456\n`, { homes: [f.home] }), false, "a SetEnv value is a field");
    // An unknown keyword is masked (a field): not own text.
    assert.equal(isOwnTextTwin(p, `${PLAIN}  FrobnicateKey yes\n`, { homes: [f.home] }), false, "an unknown keyword is masked");
    // A comment is masked: not own text.
    assert.equal(isOwnTextTwin(p, `# old pw: x\n${PLAIN}`, { homes: [f.home] }), false, "a comment is masked");
    // !1621's credential belt: a known credential format the keyword rules
    // left raw (a token as the user) makes the twin structured.
    assert.equal(isOwnTextTwin(p, `Host gh\n  User ${GH}\n`, { homes: [f.home] }), false, "a credential-shaped user is masked by the belt");
    // A human label says the file itself is the secret: never own text.
    const label = (q: string) => (q === p ? { level: "no-model" as const, bindings: [], via: p, origin: "human" as const } : null);
    assert.equal(isOwnTextTwin(p, PLAIN, { homes: [f.home], resolveLabel: label as never }), false, "a human label keeps the whole-file twin");
    // Not an exhaustive shape: a `.env` with no secret is not vouched for.
    const env = f.put(".env", "PORT=3000\n");
    assert.equal(isOwnTextTwin(env, "PORT=3000\n", { homes: [f.home] }), false, "only the exhaustive shapes");
    // A pip.conf with no credential, a credential store with none.
    const pip = f.put(".config/pip/pip.conf", "[global]\ntimeout = 60\n");
    assert.equal(isOwnTextTwin(pip, "[global]\ntimeout = 60\n", { homes: [f.home] }), true);
    assert.equal(isOwnTextTwin(p, "", { homes: [f.home] }), false, "an empty file is nothing to show");
  } finally {
    f.done();
  }
});

test("ownTextTwinFor and isOwnTextRow: the newest registration's text; the base row and a proxy's piece are no fingerprint, a field row is", () => {
  const f = home();
  try {
    const map = loadSymbolMap(f.db);
    const p = f.put(".ssh/config", PLAIN);
    const reg = registerSecret(map, { path: p, home: f.home }, f.db);
    assert.ok(reg.symbol, reg.reason);
    assert.equal(reg.twin, PLAIN, "the twin is the file's own text");
    const homes = [f.home];
    const own = ownTextTwinFor(map, p, { homes });
    assert.deepEqual(own, { token: reg.symbol, text: PLAIN });
    assert.equal(ownTextTwinFor(map, p, {}), null, "no HOME named: not vouched for");
    assert.equal(isOwnTextRow(map, reg.symbol!, { homes }), true, "the base row");
    // A proxy's Read row of the same text (it masked a Read whole before).
    const proxyRow = allocateSymbol(map, { tool: "Read", value: PLAIN.split("\n").slice(1, 3).join("\n"), origin: p, callId: "toolu_x", confidentiality: "no-model", integrity: "trusted" }, f.db);
    assert.equal(isOwnTextRow(map, proxyRow, { homes }), true, "a piece of the own text, on that path");
    const other = allocateSymbol(map, { tool: "Read", value: "Host elsewhere\n", origin: p, callId: "toolu_y", confidentiality: "no-model", integrity: "trusted" }, f.db);
    assert.equal(isOwnTextRow(map, other, { homes }), false, "not a piece of the twin: still a fingerprint");
    const field = allocateSymbol(map, { tool: "Read", field: "old.SetEnv", value: "10.1.2.3", origin: p, confidentiality: "no-model", integrity: "trusted" }, f.db);
    assert.equal(isOwnTextRow(map, field, { homes }), false, "a field row is a secret value, even one now in a public place");

    // The file gains a secret: the newest registration is structured, the
    // old base row still vouches for its own (old) text only.
    writeFileSync(p, `${PLAIN}  SetEnv TOKEN=abcdef123456\n`);
    const reg2 = registerSecret(map, { path: p, home: f.home }, f.db);
    assert.ok(reg2.fields && reg2.fields > 0, reg2.reason);
    assert.equal(ownTextTwinFor(map, p, { homes }), null, "the newest twin is structured");
    assert.equal(isOwnTextRow(map, reg2.symbol!, { homes }), false, "a structured registration's base row is a fingerprint");
    assert.equal(isOwnTextRow(map, proxyRow, { homes }), false, "a proxy piece is judged against the twin served now");
  } finally {
    f.done();
  }
});

test("twinMatchOf / wholeFileTwinOfBase / twinFormOf under two HOMEs: a config under launch B's HOME is the own-text twin when B is named, a whole-file one only when no named HOME's catalog covers it (mandu why, 2026-10-17)", () => {
  const a = home();
  const b = home();
  try {
    const map = loadSymbolMap(b.db);
    const p = b.put(".ssh/config", PLAIN);
    // The launcher registers it under launch B's HOME: its twin is its text.
    const reg = registerSecret(map, { path: p, home: b.home }, b.db);
    assert.ok(reg.symbol, reg.reason);
    assert.equal(reg.twin, PLAIN);
    // Under the arbiter's HOME alone (the old reading) the catalog names no
    // such path: the whole-file twin, a wrong answer for this file.
    assert.equal(twinMatchOf(p, {}).rule, null);
    assert.equal(twinFormOf(p, PLAIN, twinMatchOf(p, {})).form, "whole-file");
    assert.ok(wholeFileTwinOfBase(map, reg.symbol!, {}), "the arbiter's HOME alone: called a whole-file twin");
    // Launch A's HOME is elsewhere: still no catalog word for B's file.
    assert.ok(wholeFileTwinOfBase(map, reg.symbol!, { homes: [a.home] }), "another launch's HOME vouches for nothing here");
    // Launch B's HOME named (with A's): the catalog's word, the own-text
    // twin the guard serves (isOwnTextTwin), so no whole-file twin.
    const homes = [a.home, b.home];
    assert.equal(twinMatchOf(p, { homes }).rule?.startsWith("prefix:"), true, twinMatchOf(p, { homes }).rule ?? "null");
    assert.deepEqual(twinFormOf(p, PLAIN, twinMatchOf(p, { homes })), { form: "own-text", shape: "ssh-config", fields: 0 });
    assert.equal(isOwnTextTwin(p, PLAIN, { homes }), true);
    assert.equal(wholeFileTwinOfBase(map, reg.symbol!, { homes }), null, "own text, not one placeholder");
    assert.equal(wholeFileTwinFor(map, p, { homes }), null);
    assert.equal(wholeFileTwinFor(map, p, {})?.token, reg.symbol, "the old reading (no HOME named)");
    // A human label (under any HOME) says the file itself is the secret:
    // the whole-file twin under every HOME, and never own text.
    const label = ((q: string) => (q === p ? { level: "no-model" as const, bindings: [], via: p, origin: "human" as const } : null)) as never;
    assert.equal(twinMatchOf(p, { homes, resolveLabel: label }).rule, `label:${p}`);
    assert.equal(isOwnTextTwin(p, PLAIN, { homes, resolveLabel: label }), false);
    assert.ok(wholeFileTwinOfBase(map, reg.symbol!, { homes, resolveLabel: label }), "a label: the whole-file twin");
    // A secret in the file: a structured twin under B's HOME, not whole-file.
    const withKey = `${PLAIN}  SetEnv TOKEN=abcdef123456\n`;
    assert.equal(twinFormOf(p, withKey, twinMatchOf(p, { homes })).form, "structured");
  } finally {
    a.done();
    b.done();
  }
});

test("isOwnTextTwinText: a non-empty, token-free piece of the own text, nothing else", () => {
  assert.equal(isOwnTextTwinText(PLAIN, PLAIN), true);
  assert.equal(isOwnTextTwinText("  HostName 10.1.2.3\n  User deployer\n\n", PLAIN), true, "a piece; trailing whitespace is framing");
  assert.equal(isOwnTextTwinText(`${PLAIN}  SetEnv T=x\n`, PLAIN), false, "a byte the twin does not hold");
  assert.equal(isOwnTextTwinText("Host $MDU:nomodel_Read[1a2b]", PLAIN), false, "a token is some other file's");
  assert.equal(isOwnTextTwinText("   \n", PLAIN), false, "nothing");
  assert.equal(isOwnTextTwinText(PLAIN, null), false, "no twin");
  assert.equal(isOwnTextTwinText(PLAIN, ""), false);
});

test("claudeReadRenderingText strips Claude Code's Read gutters, and refuses what is not a rendering", () => {
  const render = (t: string) => t.replace(/\n$/, "").split("\n").map((l, i) => `${String(i + 1).padStart(6)}\t${l}`).join("\n");
  assert.equal(claudeReadRenderingText(render(PLAIN)), PLAIN.replace(/\n$/, ""));
  assert.equal(claudeReadRenderingText("Host build\n  HostName x"), null, "no gutter");
  assert.equal(claudeReadRenderingText(""), null);
  assert.equal(isOwnTextTwinText(claudeReadRenderingText(render(PLAIN))!, PLAIN), true);
});

test("ownTextTwinExecOutputPath: the output is a piece of the own text of ONE file the command names", () => {
  const twins: Record<string, string> = { "/h/.ssh/config": PLAIN, "/h/.pip/pip.conf": "[global]\ntimeout = 60\n", "/h/b/config": PLAIN };
  const twinFor = (p: string) => twins[p] ?? null;
  assert.equal(ownTextTwinExecOutputPath(PLAIN, () => [["/h/.ssh/config"]], twinFor), "/h/.ssh/config", "`cat` of it");
  assert.equal(ownTextTwinExecOutputPath(PLAIN.replace(/\n$/, ""), () => [["/h/.ssh/config"]], twinFor), "/h/.ssh/config", "a runtime that trims the last newline");
  assert.equal(ownTextTwinExecOutputPath("  User deployer\n", () => [["/h/.ssh/config"]], twinFor), "/h/.ssh/config", "`grep User`");
  assert.equal(ownTextTwinExecOutputPath(`${PLAIN}\n\n`, () => [["/h/.ssh/config"]], twinFor), null, "one final newline is framing, no more");
  assert.equal(ownTextTwinExecOutputPath("     1\tHost build\n", () => [["/h/.ssh/config"]], twinFor), null, "a gutter (`cat -n`)");
  assert.equal(ownTextTwinExecOutputPath(`${PLAIN}[global]\ntimeout = 60\n`, () => [["/h/.ssh/config", "/h/.pip/pip.conf"]], twinFor), null, "two files");
  assert.equal(ownTextTwinExecOutputPath(PLAIN, () => [], twinFor), null, "the command names no registered config");
  assert.equal(ownTextTwinExecOutputPath(PLAIN, () => [["/h/.ssh/config", "/h/b/config"]], twinFor), null, "ambiguous in one tier");
  assert.equal(ownTextTwinExecOutputPath(PLAIN, () => [["/h/.env"]], twinFor), null, "no own-text twin");
  assert.equal(ownTextTwinExecOutputPath("", () => [["/h/.ssh/config"]], twinFor), null);
  assert.equal(ownTextTwinExecOutputPath("x".repeat(16 * 1024 + 1), () => [["/h/.ssh/config"]], twinFor), null, "over the bound");
});

test("decideSecretOpen's HOME: the stricter of the arbiter's and the launch's match; a launch HOME only adds places", () => {
  const launch = "/tmp/mandu-launch-home-unit";
  const path = `${launch}/.pgpass`;
  const own = pathConfidentiality(path, "/nonexistent-arbiter-home");
  const theirs = pathConfidentiality(path, launch);
  assert.equal(own.rule, null, "not a catalog place of the arbiter's HOME");
  assert.equal(theirs.rule, "prefix:~/.pgpass");
  assert.equal(stricterMatch(own, theirs), theirs, "the launch HOME adds the place");
  assert.equal(stricterMatch(theirs, own), theirs, "and never takes the arbiter's away");
  assert.equal(stricterMatch(own, null), own, "no launch HOME recorded: the arbiter's own");
  assert.equal(attestedHomeOf("/tmp/x/"), "/tmp/x");
  for (const bad of ["", "/", "relative/home", "/tmp/../etc", "/tmp/a\nb", 7, null]) assert.equal(attestedHomeOf(bad), null, String(bad));
});
