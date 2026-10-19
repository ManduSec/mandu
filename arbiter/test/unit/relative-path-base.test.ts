/**
 * relative-path-base.test — a human `public` label decides a RELATIVE read on
 * the agents whose tools name no absolute path (2026-10-09, live drill
 * conf-public-label-wins at 1250328fa5: the fixture the human labelled
 * public came back to the model as `$MDU:nomodel_shell[…]` on Goose and
 * `$MDU:nomodel_read[…]` on OpenClaw, while Claude Code, Codex and OpenCode
 * passed). Two causes, two fixes (confidentiality.md §6):
 *
 *   - Goose's tool is named `shell` like Codex's, so `callWorkdir` took the
 *     Codex branch (a `workdir` param, else the openai-proxy's session
 *     default) and never read the directory the kernel had recorded for the
 *     call's shell. Now a `shell` / `exec_command` call that names no
 *     workdir and has no session default falls back to that start directory.
 *   - OpenClaw's `read {path: "test/fixtures/.env"}` resolves against its
 *     workspace (the launch directory, which the launcher pins and names the
 *     proxy: MANDU_AGENT_CWD); the label store is keyed by absolute path, so
 *     only the catalog's `.env` shape met the relative path. Now a typed path
 *     field is read in that directory (`pathBase`), for a tool the session's
 *     own gate surface lists with `relativeBase: "launch"`.
 *
 * Pinned too, the invariant's side: a secret beside the public value stays
 * masked (another token, another field, the origin), a value that may name
 * another file keeps the catalog's verdict, a `no-model` label on the
 * resolved path RAISES a read the catalog knew nothing about, and a base the
 * session's surface does not vouch for is ignored.
 *
 * Run: npx tsx --test test/unit/relative-path-base.test.ts
 */
import { test, afterEach } from "node:test";
import assert from "node:assert/strict";

import { callWorkdir, labelForClassify, type LabelLookup, type TypedPathBase } from "../../policy/secret-catalog.js";
import { relativePathBase } from "../../policy/policy-interface.js";
import { resolvePathLabel, type PathLabel } from "../../policy/path-labels.js";
import { bindSessionSpec, clearSessionSpecs } from "../../policy/tool-inbound.js";
import { CODEX_WORKDIR_TOOLS, GOOSE_GATE_SURFACE } from "../../policy/tool-gate-surface.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the confidentiality derivation is the code under test

const HOME = "/home/u";
const WS = "/home/u/proj";

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

const PUBLIC_FIXTURE = { path: `${WS}/test/fixtures/.env`, confidentiality: "public" as const, recursive: false };
const VAULT = { path: `${WS}/vault`, confidentiality: "no-model" as const, recursive: true };

afterEach(() => clearSessionSpecs());

// ── Goose: `shell{command}` and the kernel's start directory ──────────────────

/** Goose's shell call as the arbiter's classify handler hands it to the
 *  policy: `callStartDir` from its own record (a bound call), or none. */
const gooseShell = (command: string, callStartDir?: string, extra: Record<string, unknown> = {}) =>
  ({ tool: "shell", origin: command, params: { command, ...extra }, ...(callStartDir !== undefined ? { callStartDir } : {}) });

test("callWorkdir: a shell call naming no workdir and no session default falls back to the kernel's start directory; Codex's workdir and session default still come first", () => {
  const GOOSE = GOOSE_GATE_SURFACE.workdir!;
  const argv = ["bash", "-lc", "x"];
  assert.equal(callWorkdir("shell", { command: "x" }, undefined, WS, GOOSE), WS, "Goose's shell: the directory its bash started in");
  assert.equal(callWorkdir("exec_command", { cmd: "x" }, undefined, WS, CODEX_WORKDIR_TOOLS), WS);
  assert.equal(callWorkdir("shell", { command: "x" }, undefined, undefined, GOOSE), undefined, "no start directory: none");
  assert.equal(callWorkdir("shell", { command: argv }, "/s", WS, CODEX_WORKDIR_TOOLS), "/s", "Codex's session default first");
  assert.equal(callWorkdir("shell", { command: argv, workdir: "/w" }, undefined, WS, CODEX_WORKDIR_TOOLS), "/w", "Codex's named workdir first");
  assert.equal(callWorkdir("shell", { command: argv, workdir: "rel" }, undefined, WS, CODEX_WORKDIR_TOOLS), undefined, "a named but relative workdir is no base, never the fallback");
  assert.equal(callWorkdir("shell", { command: "x" }, undefined, "proj", GOOSE), undefined);
  assert.equal(callWorkdir("shell", { command: "x" }, undefined, "/w/../etc", GOOSE), undefined);
  // Goose's shell has no workdir: a named one is the model's claim (2026-10-11)
  assert.equal(callWorkdir("shell", { command: "x", workdir: "/w" }, undefined, WS, GOOSE), WS, "a forged workdir loses to the kernel's directory");
  assert.equal(callWorkdir("shell", { command: "x", workdir: "/w" }, undefined, undefined, GOOSE), undefined, "and with none, no base at all");
});

test("Goose: `cat test/fixtures/.env` in a bound call takes the human's public label; unbound, the catalog's shape (fail-closed)", () => {
  const lk = lookupOver(PUBLIC_FIXTURE);
  assert.equal(labelForClassify(gooseShell("cat test/fixtures/.env", WS), HOME, lk).level, "public");
  assert.equal(labelForClassify(gooseShell("cat test/fixtures/.env"), HOME, lk).level, "no-model");
});

test("Goose: a secret beside the public fixture in the same command keeps the whole output masked, and is the path the note names", () => {
  const lk = lookupOver(PUBLIC_FIXTURE, VAULT);
  const both = labelForClassify(gooseShell("cat test/fixtures/.env .env", WS), HOME, lk);
  assert.equal(both.level, "no-model");
  assert.deepEqual(both.paths, [".env"], "the note names the secret, not the public fixture");
  assert.equal(labelForClassify(gooseShell("cat README.md contracts/deal.md .env", WS), HOME, lk).level, "no-model", "conf-three-levels' one-command read");
  assert.equal(labelForClassify(gooseShell("cat test/fixtures/.env vault/k.txt", WS), HOME, lk).level, "no-model", "a no-model label the catalog knows nothing about");
  assert.equal(labelForClassify(gooseShell("cd test && cat fixtures/.env", WS), HOME, lk).level, "no-model", "a directory change keeps the mask");
});

// ── OpenClaw: `read{path}` and the launch directory ───────────────────────────

const READ_FIELDS: TypedPathBase["fields"] = ["path", "file_path"];
/** OpenClaw's `read` as the anthropic-proxy classifies it: the origin is the
 *  path field (rewrite-request.ts originFor), and the policy wrapper adds the
 *  base when the session's surface vouches for it. */
const ocRead = (path: string, dir?: string, fields: TypedPathBase["fields"] = READ_FIELDS) =>
  ({ tool: "read", origin: path, params: { path }, ...(dir !== undefined ? { pathBase: { dir, fields } } : {}) });

test("OpenClaw: a relative read of the public fixture in the launch directory takes the human's label; without the base, the catalog's shape", () => {
  const lk = lookupOver(PUBLIC_FIXTURE);
  assert.equal(labelForClassify(ocRead("test/fixtures/.env", WS), HOME, lk).level, "public");
  assert.equal(labelForClassify(ocRead("./test/fixtures/.env", WS), HOME, lk).level, "public");
  assert.equal(labelForClassify(ocRead("fixtures/.env", `${WS}/test`), HOME, lk).level, "public");
  assert.equal(labelForClassify(ocRead("test/fixtures/.env"), HOME, lk).level, "no-model", "no base: unchanged");
  // an absolute path needs no base and is unchanged
  assert.equal(labelForClassify(ocRead(`${WS}/test/fixtures/.env`, WS), HOME, lk).level, "public");
  assert.equal(labelForClassify(ocRead(`${WS}/.env`, WS), HOME, lk).level, "no-model");
  assert.equal(labelForClassify(ocRead("~/proj/test/fixtures/.env", WS), HOME, lk).level, "public", "a home path names the labelled file itself, base or not");
});

test("OpenClaw: the label decides in either direction; with no label the stricter reading stands", () => {
  const lk = lookupOver(PUBLIC_FIXTURE, VAULT);
  // the catalog knows nothing about vault/k.txt: before, public; now the human's no-model label
  assert.equal(labelForClassify(ocRead("vault/k.txt"), HOME, lk).level, "public", "the pre-fix reading (no base)");
  assert.equal(labelForClassify(ocRead("vault/k.txt", WS), HOME, lk).level, "no-model");
  assert.equal(labelForClassify(ocRead(".env", WS), HOME, lk).level, "no-model", "no label: the catalog's shape");
  assert.equal(labelForClassify(ocRead("other/.env", WS), HOME, lk).level, "no-model", "the same name elsewhere is not the labelled file");
  assert.equal(labelForClassify(ocRead("test/fixtures/../../.env", WS), HOME, lk).level, "no-model", "`..` read lexically: names the workspace's own .env");
  assert.equal(labelForClassify(ocRead("README.md", WS), HOME, lk).level, "public");
});

test("OpenClaw: a value that may name another file than base/<value> keeps the catalog's verdict", () => {
  const lk = lookupOver(PUBLIC_FIXTURE);
  for (const v of [
    "@test/fixtures/.env", // OpenClaw strips a leading @
    "test/fixtures/ .env", // Unicode spaces are normalized
    "test/fixturés/.env", // NFD / quote variants are tried when missing
    "test/*/.env",
    "$D/test/fixtures/.env",
  ]) {
    assert.equal(labelForClassify(ocRead(v, WS), HOME, lk).level, "no-model", JSON.stringify(v));
  }
});

test("OpenClaw: a base the classify cannot use is ignored (relative, `..`), and only the surface's path fields are read there", () => {
  const lk = lookupOver(PUBLIC_FIXTURE);
  assert.equal(labelForClassify(ocRead("test/fixtures/.env", "proj"), HOME, lk).level, "no-model");
  assert.equal(labelForClassify(ocRead("test/fixtures/.env", "/home/u/x/../proj"), HOME, lk).level, "no-model");
  assert.equal(labelForClassify(ocRead("test/fixtures/.env", WS, ["file_path"]), HOME, lk).level, "no-model", "`path` is not one of this tool's fields");
  // the command text is never read in the typed base, even when listed
  const cmd = { tool: "exec", origin: "cat test/fixtures/.env", params: { command: "cat test/fixtures/.env" }, pathBase: { dir: WS, fields: ["command", "path"] } };
  assert.equal(labelForClassify(cmd, HOME, lk).level, "no-model");
});

test("OpenClaw: a secret in another source of the same call keeps it masked (the MAX holds)", () => {
  const lk = lookupOver(PUBLIC_FIXTURE);
  // a path field naming the public fixture, a second field naming a secret
  const two = { tool: "read", origin: "test/fixtures/.env", params: { path: "test/fixtures/.env", file_path: ".env" }, pathBase: { dir: WS, fields: READ_FIELDS } };
  const r = labelForClassify(two, HOME, lk);
  assert.equal(r.level, "no-model");
  assert.deepEqual(r.paths, [".env"], "the note names only the secret path");
  // an origin that is not the typed value (a different hint) is read as before
  const hint = { tool: "read", origin: "cat .env", params: { path: "test/fixtures/.env" }, pathBase: { dir: WS, fields: READ_FIELDS } };
  assert.equal(labelForClassify(hint, HOME, lk).level, "no-model");
});

// ── relativePathBase: the session's own surface vouches for the base ─────────

test("relativePathBase: only a session whose gate surface resolves relative paths against the launch directory, only for its path tools", () => {
  bindSessionSpec("s-openclaw", "openclaw-agent");
  bindSessionSpec("s-goose", "goose");
  bindSessionSpec("s-claude", "claude-code");
  assert.deepEqual(relativePathBase({ tool: "read", relativeBase: WS, sessionKey: "s-openclaw" }), { dir: WS, fields: ["path", "file_path"] });
  assert.deepEqual(relativePathBase({ tool: "tree", relativeBase: WS, sessionKey: "s-goose" }), { dir: WS, fields: ["path"] });
  assert.deepEqual(relativePathBase({ tool: "exec", relativeBase: WS, sessionKey: "s-openclaw" }), { dir: WS, fields: ["workdir"] }, "exec's gated field is its workdir, which classify does not read; its command never takes the base");
  assert.equal(relativePathBase({ tool: "web_fetch", relativeBase: WS, sessionKey: "s-openclaw" }), undefined);
  assert.equal(relativePathBase({ tool: "Read", relativeBase: WS, sessionKey: "s-claude" }), undefined, "Claude Code's relative paths follow the shell's cd");
  assert.equal(relativePathBase({ tool: "read", relativeBase: WS, sessionKey: "s-unbound" }), undefined, "an unbound session: the boot spec (Claude Code's)");
  assert.equal(relativePathBase({ tool: "read", sessionKey: "s-openclaw" }), undefined, "no base sent: none");
});
