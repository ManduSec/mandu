/**
 * label-derivation.test — the USER label overrides the catalog (Plan 6, §6).
 *
 * The catalog is a zero-config DEFAULT; a human label is authoritative for its
 * path, in EITHER direction. These tests pin both directions and the fall-through
 * (no label ⇒ the catalog decides, unchanged) — which is what keeps every
 * pre-Plan-6 caller byte-identical.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  callWorkdir,
  changesDirectory,
  confidentialityForOrigin,
  confidentialityForClassify,
  labelForClassify,
  labelForUnmappedInput,
  pathConfidentiality,
  type LabelLookup,
} from "../../policy/secret-catalog.js";
import { resolvePathLabel, type PathLabel } from "../../policy/path-labels.js";
import { CODEX_WORKDIR_TOOLS as CODEX } from "../../policy/tool-gate-surface.js";

const HOME = "/home/u";

function lookupOver(...rows: Array<Partial<PathLabel> & { path: string }>): LabelLookup {
  const m = new Map<string, PathLabel>();
  for (const r of rows) {
    m.set(r.path, {
      path: r.path,
      confidentiality: r.confidentiality ?? "no-model",
      bindings: r.bindings ?? [],
      recursive: r.recursive ?? true,
      source: "user",
      updatedAt: 1,
    });
  }
  return (p) => resolvePathLabel(p, m, HOME);
}

// ── the fall-through: absent a lookup, NOTHING changes ───────────────────────

test("with no lookup, derivation is exactly the catalog (no pre-Plan-6 caller moves)", () => {
  assert.equal(confidentialityForOrigin("/home/u/.aws/credentials", HOME).level, "no-model");
  assert.equal(confidentialityForOrigin("/home/u/notes.md", HOME).level, "public");
  assert.equal(pathConfidentiality("/home/u/.ssh/id_rsa", HOME).level, "no-model");
});

test("with a lookup that labels nothing, derivation is STILL exactly the catalog", () => {
  const none = lookupOver();
  assert.equal(confidentialityForOrigin("/home/u/.aws/credentials", HOME, none).level, "no-model");
  assert.equal(confidentialityForOrigin("/home/u/notes.md", HOME, none).level, "public");
});

// ── the two directions of the override ───────────────────────────────────────

test("UP: a user label mints any-model on a path the catalog calls public", () => {
  // THE point of Plan 6. Before it, no input to the system could produce this
  // level at all — the catalog yields only public/strict, by design.
  const lk = lookupOver({ path: "/home/u/contracts", confidentiality: "any-model" });
  const m = confidentialityForOrigin("/home/u/contracts/q3.pdf", HOME, lk);
  assert.equal(m.level, "any-model");
  assert.match(m.rule ?? "", /^label:/);
});

test("DOWN: a user `public` label beats the catalog's no-model (the declassification)", () => {
  const lk = lookupOver({ path: "/home/u/proj/test/fixtures/.env", confidentiality: "public" });
  assert.equal(
    confidentialityForOrigin("/home/u/proj/test/fixtures/.env", HOME, lk).level,
    "public",
  );
  // ...and an UNLABELED .env elsewhere is still strict. The override is per-path,
  // not a global weakening of the shape rule.
  assert.equal(confidentialityForOrigin("/home/u/proj/.env", HOME, lk).level, "no-model");
});

test("the DOWN override must beat the TEXT SCAN too, not just the direct match", () => {
  // Regression guard: if the direct label lookup did not short-circuit, the
  // token `.env` inside the origin would be re-caught by the basename shape and
  // the declassification would silently not take.
  const lk = lookupOver({ path: "/home/u/proj/.env", confidentiality: "public" });
  assert.equal(confidentialityForOrigin("/home/u/proj/.env", HOME, lk).level, "public");
});

test("DOWN in COMMAND POSITION: a declassified .env ending a Bash command stays public (CONF-public-label-override, found live)", () => {
  // basename(`grep KEY /…/fixtures/.env`) is `.env`, so the WHOLE command
  // direct-matched the catalog shape and skipped the label-aware token scan —
  // the declassification was silently defeated whenever the labeled path sat
  // in command position. A catalog verdict on multi-token text now yields to
  // the token scan, which resolves the absolute-path token against the store.
  const lk = lookupOver(
    { path: "/home/u/proj/test/fixtures/.env", confidentiality: "public", recursive: false },
  );
  assert.equal(
    confidentialityForClassify(
      { origin: "Bash", params: { command: 'grep "API_KEY" /home/u/proj/test/fixtures/.env' } },
      HOME, lk,
    ),
    "public",
  );
  // The demotion is to the SCAN, not a weakening of the catalog: the same
  // command over an UNLABELED .env is still strict…
  assert.equal(
    confidentialityForClassify(
      { origin: "Bash", params: { command: 'grep "API_KEY" /home/u/other/.env' } },
      HOME, lk,
    ),
    "no-model",
  );
  // …and a SINGLE-token origin (a real path) still direct-matches the catalog.
  assert.equal(confidentialityForOrigin("/home/u/other/.env", HOME, lk).level, "no-model");
});

// ── inheritance reaches the derivation ───────────────────────────────────────

test("a directory label reaches a file under it, through classify's typed path field", () => {
  const lk = lookupOver({ path: "/home/u/contracts", confidentiality: "any-model" });
  assert.equal(
    confidentialityForClassify(
      { origin: "Read", params: { file_path: "/home/u/contracts/deep/q3.pdf" } },
      HOME, lk,
    ),
    "any-model",
  );
});

test("max() across sources still wins: a model-ok param + a strict param ⇒ strict", () => {
  const lk = lookupOver({ path: "/home/u/contracts", confidentiality: "any-model" });
  assert.equal(
    confidentialityForClassify(
      { origin: "Bash", params: { command: "cat /home/u/contracts/q3.pdf /home/u/.aws/credentials" } },
      HOME, lk,
    ),
    "no-model",
    "the strictest datum in the command sets the level",
  );
});

test("a labeled path is found in BASH COMMAND TEXT, not only in typed fields", () => {
  // The catalog's text scanner knows nothing about ~/contracts — only the label
  // makes this token secret.
  const lk = lookupOver({ path: "/home/u/contracts", confidentiality: "any-model" });
  assert.equal(
    confidentialityForClassify({ origin: "Bash", params: { command: "wc -l /home/u/contracts/q3.pdf" } }, HOME, lk),
    "any-model",
  );
});

// ── bindings ─────────────────────────────────────────────────────────────────

test("bindings ride the label all the way through classify", () => {
  const lk = lookupOver({
    path: "/home/u/contracts",
    confidentiality: "any-model",
    bindings: ["docs.corp.example"],
  });
  const out = labelForClassify(
    { origin: "Read", params: { file_path: "/home/u/contracts/q3.pdf" } },
    HOME, lk,
  );
  assert.equal(out.level, "any-model");
  assert.deepEqual(out.bindings, ["docs.corp.example"], "a binding is a standing release rule — it must reach the symbol row");
});

// ── a relative token: read where the call says it runs (2026-10-04) ─────────

test("KNOWN LIMIT: a relative token with no known directory cannot be overridden, and fails SAFE (Claude Code's Bash)", () => {
  // The label store is keyed by absolute paths; the catalog also matches
  // relative shapes. Claude Code's Bash names no directory (its shell keeps
  // the one a previous call left it in), so the override misses and the
  // catalog's `.env` shape fires: over-restriction, never a leak. Pinned
  // because the failure DIRECTION is the property.
  const lk = lookupOver({ path: "/home/u/proj/test/fixtures/.env", confidentiality: "public" });
  assert.equal(
    confidentialityForClassify({ tool: "Bash", origin: "cat test/fixtures/.env", params: { command: "cat test/fixtures/.env" } }, HOME, lk),
    "no-model",
    "over-restriction, not a leak",
  );
  // the same path spelled absolute takes the human label, as a Read does
  assert.equal(
    confidentialityForClassify({ tool: "Bash", origin: "cat /home/u/proj/test/fixtures/.env", params: { command: "cat /home/u/proj/test/fixtures/.env" } }, HOME, lk),
    "public",
  );
});

const PUBLIC_FIXTURE = { path: "/home/u/proj/test/fixtures/.env", confidentiality: "public" as const };
const codexCall = (cmd: string, workdir: string | null = "/home/u/proj") =>
  ({ tool: "exec_command", origin: cmd, params: { cmd, ...(workdir !== null ? { workdir } : {}) }, workdirTools: CODEX });

test("Codex's exec_command names its directory: a relative token there takes the human's public label, as a Read of the path does", () => {
  const lk = lookupOver(PUBLIC_FIXTURE);
  assert.equal(labelForClassify(codexCall("rg '^API_KEY=' test/fixtures/.env"), HOME, lk).level, "public");
  assert.equal(labelForClassify(codexCall("cat ./test/fixtures/.env"), HOME, lk).level, "public");
  assert.equal(labelForClassify(codexCall("cat fixtures/.env", "/home/u/proj/test"), HOME, lk).level, "public");
  // the unmapped-tool scan (Codex's exec_command is not in the Claude Code spec) reads it the same way
  const wide = labelForUnmappedInput([codexCall("rg '^API_KEY=' test/fixtures/.env").params], HOME, lk, "/home/u/proj");
  assert.equal(wide.level, "public");
  assert.match(wide.rule ?? "", /^label:/, "the human label decided it");
});

test("a call that also names a secret file stays masked: every other token keeps its own verdict", () => {
  const lk = lookupOver(PUBLIC_FIXTURE);
  assert.equal(labelForClassify(codexCall("cat test/fixtures/.env .env"), HOME, lk).level, "no-model");
  assert.equal(labelForClassify(codexCall("cat test/fixtures/.env ~/.aws/credentials"), HOME, lk).level, "no-model");
  assert.equal(labelForUnmappedInput([codexCall("cat test/fixtures/.env .env").params], HOME, lk, "/home/u/proj").level, "no-model");
  // the same name under another directory is not the labelled file
  assert.equal(labelForClassify(codexCall("cat other/.env"), HOME, lk).level, "no-model");
});

test("no override where the base is not known to be where the token is read: a directory change, no workdir, a relative workdir, another tool's workdir", () => {
  const lk = lookupOver(PUBLIC_FIXTURE);
  for (const cmd of [
    "cd test && cat fixtures/.env",
    "cd /elsewhere; cat test/fixtures/.env",
    "pushd /x >/dev/null; cat test/fixtures/.env",
    "bash -c 'cd /x && cat test/fixtures/.env'",
    "git -C /x show HEAD:test/fixtures/.env",
    "make -C/x print test/fixtures/.env",
    "env --chdir=/x cat test/fixtures/.env",
    "find /x -name x -execdir cat test/fixtures/.env ;",
  ]) {
    assert.equal(labelForClassify(codexCall(cmd), HOME, lk).level, "no-model", cmd);
  }
  assert.equal(labelForClassify(codexCall("cat test/fixtures/.env", null), HOME, lk).level, "no-model", "no workdir");
  assert.equal(labelForClassify(codexCall("cat test/fixtures/.env", "proj"), HOME, lk).level, "no-model", "a relative workdir");
  assert.equal(
    labelForClassify({ tool: "acme_runner", origin: "cat test/fixtures/.env", params: { cmd: "cat test/fixtures/.env", workdir: "/home/u/proj" } }, HOME, lk).level,
    "no-model",
    "a workdir param of a tool not known to run there is a claim nothing checks",
  );
  // a glob or an expansion is not one path
  assert.equal(labelForClassify(codexCall("cat test/*/.env"), HOME, lk).level, "no-model");
  assert.equal(labelForClassify(codexCall("cat $D/test/fixtures/.env"), HOME, lk).level, "no-model");
});

test("the human label decides in either direction: a relative token under a no-model label is masked where the catalog knew nothing", () => {
  const lk = lookupOver({ path: "/home/u/proj/vault", confidentiality: "no-model", recursive: true });
  assert.equal(labelForClassify(codexCall("cat vault/key.txt"), HOME, lk).level, "no-model");
  assert.equal(labelForClassify(codexCall("cat vault/key.txt", null), HOME, lk).level, "public", "without the directory the label is not found (the twin layer covers it)");
  // no label at the resolved path: the stricter of the two readings
  const none = lookupOver();
  assert.equal(labelForClassify(codexCall("cat notes.md"), HOME, none).level, "public");
  assert.equal(labelForClassify(codexCall("cat .env"), HOME, none).level, "no-model");
  assert.equal(labelForClassify(codexCall("cat .ssh/id_rsa", "/home/u"), HOME, none).level, "no-model");
});

test("changesDirectory and callWorkdir", () => {
  for (const t of ["cd x", "a && cd x", "(cd x; ls)", "pushd x", "popd", "git -C x log", "tar -Cx -xf a", "ls --directory=x", "npm --prefix x run", "find . -execdir ls ;", "sh -c \"cd x\""]) {
    assert.equal(changesDirectory(t), true, t);
  }
  for (const t of ["cat .env", "rg cdx file", "echo abcd", "ls -c", "grep -c x f", "cat ./cd/file"]) {
    assert.equal(changesDirectory(t), false, t);
  }
  assert.equal(callWorkdir("exec_command", { workdir: "/w" }, undefined, undefined, CODEX), "/w");
  assert.equal(callWorkdir("shell", { command: ["bash", "-lc", "x"], workdir: "/w" }, undefined, undefined, CODEX), "/w");
  assert.equal(callWorkdir("shell", { command: "x", workdir: "/w" }, undefined, undefined, CODEX), undefined, "a string-command shell is not Codex's");
  assert.equal(callWorkdir("exec_command", { workdir: "/w" }), undefined, "no agent named: no workdir believed");
  assert.equal(callWorkdir("exec_command", { workdir: "w" }, undefined, undefined, CODEX), undefined);
  assert.equal(callWorkdir("Bash", { workdir: "/w" }, undefined, undefined, CODEX), undefined);
  assert.equal(callWorkdir(undefined, { workdir: "/w" }, undefined, undefined, CODEX), undefined);
  // the session's directory stands in only where the call names no workdir
  assert.equal(callWorkdir("exec_command", { cmd: "x" }, "/s", undefined, CODEX), "/s");
  assert.equal(callWorkdir("exec_command", { workdir: "/w" }, "/s", undefined, CODEX), "/w");
  assert.equal(callWorkdir("exec_command", { workdir: "w" }, "/s", undefined, CODEX), undefined, "a relative workdir is no base, never the default");
  assert.equal(callWorkdir("exec_command", { workdir: 7 }, "/s", undefined, CODEX), undefined);
  assert.equal(callWorkdir("exec_command", { cmd: "x" }, "s", undefined, CODEX), undefined);
  assert.equal(callWorkdir("Bash", { command: "x" }, "/s", undefined, CODEX), undefined, "Claude Code's Bash keeps the previous call's directory: no default");
});

test("a Codex call that names no workdir runs in the session's directory: with it known (workdirDefault), the human label decides the relative token; without it, masked", () => {
  const lk = lookupOver(PUBLIC_FIXTURE);
  const call = (cmd: string, workdirDefault?: string) =>
    ({ tool: "exec_command", origin: cmd, params: { cmd }, workdirTools: CODEX, ...(workdirDefault !== undefined ? { workdirDefault } : {}) });
  assert.equal(labelForClassify(call("rg '^API_KEY=' test/fixtures/.env", "/home/u/proj"), HOME, lk).level, "public");
  assert.equal(labelForClassify(call("rg '^API_KEY=' test/fixtures/.env"), HOME, lk).level, "no-model");
  assert.equal(labelForClassify(call("cat test/fixtures/.env .env", "/home/u/proj"), HOME, lk).level, "no-model");
  assert.equal(labelForClassify(call("cd test && cat fixtures/.env", "/home/u/proj"), HOME, lk).level, "no-model");
});
