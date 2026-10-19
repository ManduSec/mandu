/**
 * unmapped-input-label.test — the path-derived label of a tool the session's
 * spec does not map reads EVERY string of its input (plan 10 §11.11).
 *
 * Before: only the origin and four named params (`file_path`, `path`,
 * `notebook_path`, `command`) were read, so an unmapped tool naming its path
 * `target`, or a shell under another name (OpenClaw's `terminal` while it is
 * unmapped), returned a labeled file's text to the model raw in `secrets`
 * mode.
 */

import { test, afterEach } from "node:test";
import assert from "node:assert/strict";

import { stateAxes } from "../axes.js";
import {
  labelForUnmappedInput,
  UNMAPPED_INPUT_SCAN_LIMITS,
  type LabelLookup,
} from "../../policy/secret-catalog.js";
import { resolvePathLabel, type PathLabel } from "../../policy/path-labels.js";
import { createEngineBackedPolicy } from "../../policy/policy-interface.js";
import { bindSessionSpec, clearSessionSpecs, inboundSpecNamesInput } from "../../policy/tool-inbound.js";

stateAxes("secrets"); // the confidentiality axis is the one under test

const HOME = "/home/u";
const REAL_HOME = process.env.HOME ?? "/root";

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

afterEach(() => clearSessionSpecs());

// ── the scanner ───────────────────────────────────────────────────────────────

test("a labeled path under any key, at any depth, is found", () => {
  const lk = lookupOver({ path: "/home/u/contracts", confidentiality: "any-model", bindings: ["api.example.com"] });
  const r = labelForUnmappedInput([{ target: "/home/u/contracts/q3.pdf" }], HOME, lk);
  assert.equal(r.level, "any-model");
  assert.deepEqual(r.bindings, ["api.example.com"]);
  const deep = labelForUnmappedInput([{ job: { steps: [{ files: ["README.md", "/home/u/contracts/q3.pdf"] }] } }], HOME, lk);
  assert.equal(deep.level, "any-model");
});

test("shell text under another name is scanned token by token", () => {
  const lk = lookupOver({ path: "/home/u/contracts" });
  assert.equal(labelForUnmappedInput([{ keys: "cat /home/u/contracts/q3.pdf | head\n" }], HOME, lk).level, "no-model");
  // the catalog's shapes too, no label needed
  assert.equal(labelForUnmappedInput([{ input: "grep KEY .env" }], HOME).level, "no-model");
});

test("an object key naming a path counts", () => {
  assert.equal(labelForUnmappedInput([{ files: { "/home/u/.ssh/id_rsa": true } }], HOME).level, "no-model");
});

test("a file:// URL is read as its path; an https URL stays exempt", () => {
  const lk = lookupOver({ path: "/home/u/contracts" });
  assert.equal(labelForUnmappedInput([{ uri: "file:///home/u/contracts/q%203.pdf" }], HOME, lk).level, "no-model");
  assert.equal(labelForUnmappedInput([{ uri: "file://localhost/home/u/.ssh/id_rsa" }], HOME).level, "no-model");
  assert.equal(labelForUnmappedInput([{ url: "https://example.com/.env" }], HOME).level, "public");
});

test("raise-only: a public declassification on one string never lowers another", () => {
  const lk = lookupOver({ path: "/home/u/proj/.env", confidentiality: "public", recursive: false });
  assert.equal(labelForUnmappedInput([{ a: "/home/u/proj/.env" }], HOME, lk).level, "public");
  assert.equal(labelForUnmappedInput([{ a: "/home/u/proj/.env", b: "/home/u/.aws/credentials" }], HOME, lk).level, "no-model");
  assert.equal(labelForUnmappedInput([{ b: "/home/u/.aws/credentials", a: "/home/u/proj/.env" }], HOME, lk).level, "no-model");
});

test("nothing path-like: public, no rule", () => {
  const r = labelForUnmappedInput([{ query: "what is the weather", n: 3, flags: [true, null] }], HOME);
  assert.deepEqual(r, { level: "public", bindings: [], rule: null });
});

test("past the scan bounds the verdict is no-model (fail-closed)", () => {
  const big = "x".repeat(UNMAPPED_INPUT_SCAN_LIMITS.chars + 1);
  assert.equal(labelForUnmappedInput([{ blob: big }], HOME).level, "no-model");
  let deep: unknown = "leaf";
  for (let i = 0; i < UNMAPPED_INPUT_SCAN_LIMITS.depth + 2; i++) deep = { d: deep };
  assert.equal(labelForUnmappedInput([deep], HOME).rule, "unmapped-input:too-large");
  const many = Array.from({ length: UNMAPPED_INPUT_SCAN_LIMITS.strings + 1 }, (_, i) => `s${i}`);
  assert.equal(labelForUnmappedInput([{ many }], HOME).level, "no-model");
});

// ── which tools count as unmapped ─────────────────────────────────────────────

test("inboundSpecNamesInput: exact entries and Mandu's own tools name their input; the rest do not", () => {
  bindSessionSpec("s-oc", "openclaw-agent");
  assert.equal(inboundSpecNamesInput("read", "s-oc"), true);
  assert.equal(inboundSpecNamesInput("exec", "s-oc"), true);
  assert.equal(inboundSpecNamesInput("acme_blob_reader", "s-oc"), false);
  assert.equal(inboundSpecNamesInput("tool_call", "s-oc"), false);
  assert.equal(inboundSpecNamesInput("inspect_symbol", "s-oc"), true);
  bindSessionSpec("s-cc", "claude-code");
  assert.equal(inboundSpecNamesInput("Read", "s-cc"), true);
  assert.equal(inboundSpecNamesInput("mcp__files__fetch", "s-cc"), false, "the generic MCP fallback does not name an input");
});

// ── the engine-backed classify wrapper ───────────────────────────────────────

test("classify: an unmapped tool naming a secret path under `target` is secret; the same shape on a mapped tool is unchanged", () => {
  bindSessionSpec("s-oc", "openclaw-agent");
  const policy = createEngineBackedPolicy({ confidentiality: true, integrity: false });
  const unmapped = policy.classify({
    tool: "acme_blob_reader", value: "AKIA…", boundary: "model_context", sessionKey: "s-oc",
    params: { session: "t1", keys: `cat ${REAL_HOME}/.aws/credentials\n` },
  });
  assert.equal(unmapped.confidentiality, "no-model");
  assert.match(unmapped.reason, /unmapped tool/);

  const target = policy.classify({
    tool: "acme_blob_reader", value: "x", boundary: "model_context", sessionKey: "s-oc",
    params: { target: `${REAL_HOME}/.ssh/id_ed25519` },
  });
  assert.equal(target.confidentiality, "no-model");

  // `read` is mapped: its path is `path`, and an unrelated key mentioning a
  // secret path is NOT read (byte-identical to before this rule).
  const mapped = policy.classify({
    tool: "read", value: "hello", boundary: "model_context", sessionKey: "s-oc",
    params: { path: "/tmp/notes.md", note: `${REAL_HOME}/.aws/credentials` },
  });
  assert.equal(mapped.confidentiality, "public");
});

test("classify: the HumanView spelling of an unmapped tool's input is read too (a label keyed in HumanView)", () => {
  bindSessionSpec("s-oc", "openclaw-agent");
  const lk = lookupOver({ path: "/home/u/contracts", confidentiality: "any-model" });
  const policy = createEngineBackedPolicy({ confidentiality: true, integrity: false, labelLookup: lk });
  const r = policy.classify({
    tool: "acme_blob_reader", value: "x", boundary: "model_context", sessionKey: "s-oc",
    params: { target: "/av/ws/contracts/q3.pdf" },
    paramsHuman: { target: "/home/u/contracts/q3.pdf" },
  });
  assert.equal(r.confidentiality, "any-model");
});

test("classify: confidentiality axis OFF adds no level to an unmapped tool", () => {
  bindSessionSpec("s-oc", "openclaw-agent");
  const policy = createEngineBackedPolicy({ confidentiality: false, integrity: true });
  const r = policy.classify({
    tool: "acme_blob_reader", value: "x", boundary: "model_context", sessionKey: "s-oc",
    params: { target: `${REAL_HOME}/.ssh/id_ed25519` },
  });
  assert.equal(r.confidentiality, undefined);
});

test("classify: Codex's exec_command (unmapped in the default spec) reads a relative token in its workdir, so the human's public label decides it; another secret token still masks (2026-10-04)", () => {
  const lk = lookupOver({ path: "/home/u/proj/test/fixtures/.env", confidentiality: "public", recursive: false });
  const policy = createEngineBackedPolicy({ confidentiality: true, integrity: false, labelLookup: lk });
  const call = (cmd: string) => policy.classify({
    tool: "exec_command", value: "API_KEY=x", boundary: "model_context", origin: cmd,
    params: { cmd, workdir: "/av/ws" }, paramsHuman: { cmd, workdir: "/home/u/proj" },
  });
  assert.equal(call("rg '^API_KEY=' test/fixtures/.env").confidentiality, "public", "the HumanView workdir finds the label");
  assert.equal(call("cat test/fixtures/.env .env").confidentiality, "no-model", "the root .env keeps the catalog's verdict");
  assert.equal(call("cd test && cat fixtures/.env").confidentiality, "no-model", "a directory change: no override");
  // the agent's spelling alone (no HumanView map) has no label at /av/ws: fail-closed
  const agentOnly = policy.classify({
    tool: "exec_command", value: "API_KEY=x", boundary: "model_context", origin: "cat test/fixtures/.env",
    params: { cmd: "cat test/fixtures/.env", workdir: "/av/ws" },
  });
  assert.equal(agentOnly.confidentiality, "no-model");
});
