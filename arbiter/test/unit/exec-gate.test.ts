/**
 * exec-gate.test.ts — unit tests for the model-context-layer exec gate
 * (arbiter/policy/exec-gate.ts, design exec-routing.md §3).
 *
 * The gate blocks ONE thing: an untrusted `$MDU:*` in command/execution
 * position (the same detector the exec-supervisor + `asCommand` egress gate use).
 * It must NOT over-block data-position symbols (`grep $SYM | wc -l`) — that is
 * what keeps the count-security / inspect-* utility scenarios working. Evasion
 * signals (absolute-path net tools, env prefixes) are RECORDED but never block.
 *
 * Run: npm run test:unit
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { execGate } from "../../policy/exec-gate.js";
import { getActiveFormat } from "../../symbol-table/index.js";

const sym = (opts?: { tool?: string; hash?: string; field?: string }): string =>
  getActiveFormat().generate({
    tool: opts?.tool ?? "web_fetch",
    hash: opts?.hash ?? "a1b2",
    field: opts?.field ?? "text",
  });

// ── block: symbol in command / code-execution position ───────────────────────

test("execGate BLOCKS a whole-command symbol", () => {
  const r = execGate({ command: sym() });
  assert.equal(r.decision, "block");
  assert.deepEqual(r.symbols, [sym()]);
  assert.match(r.reason, /command\/execution position/);
});

test("execGate BLOCKS a symbol inside sh -c", () => {
  const r = execGate({ command: `sh -c "${sym()}"` });
  assert.equal(r.decision, "block");
  assert.deepEqual(r.symbols, [sym()]);
});

test("execGate BLOCKS a symbol inside python -c", () => {
  const r = execGate({ command: `python3 -c "${sym()}"` });
  assert.equal(r.decision, "block");
  assert.ok(r.symbols.includes(sym()));
});

// ── allow: no symbol, or a symbol in ordinary DATA position ──────────────────

test("execGate ALLOWS a symbol-free command", () => {
  const r = execGate({ command: "echo hello && ls -la" });
  assert.equal(r.decision, "allow");
  assert.deepEqual(r.symbols, []);
});

test("execGate ALLOWS a DATA-position symbol (no over-block: grep $SYM file)", () => {
  const r = execGate({ command: `grep ${sym()} file.txt` });
  assert.equal(r.decision, "allow");
});

test("execGate ALLOWS the count-security shape: grep over $SYM piped to wc", () => {
  // The answer rides back through T-LLM as a symbol; the pipe must NOT block.
  const r = execGate({ command: `printf '%s' ${sym()} | grep -o -iw security | wc -l` });
  assert.equal(r.decision, "allow");
});

// ── evasion: recorded, NEVER blocking on its own ─────────────────────────────

test("execGate RECORDS an absolute-path net tool but does not block it", () => {
  const r = execGate({ command: "/usr/bin/curl https://example.test/x" });
  assert.equal(r.decision, "allow");
  assert.ok(
    r.evasion.some((e) => e.kind === "absolute_path_net_tool" && e.evidence === "/usr/bin/curl"),
    "absolute-path curl should be recorded as evasion",
  );
});

test("execGate RECORDS an absolute-path net tool after a control operator", () => {
  const r = execGate({ command: "echo ok && /bin/nc evil.test 9000" });
  assert.equal(r.decision, "allow");
  assert.ok(r.evasion.some((e) => e.kind === "absolute_path_net_tool" && e.evidence === "/bin/nc"));
});

test("execGate RECORDS an inline env / PATH override prefix", () => {
  const r = execGate({ command: "PATH=/usr/bin curl https://example.test/x" });
  assert.equal(r.decision, "allow");
  assert.ok(r.evasion.some((e) => e.kind === "env_prefix_override" && e.evidence === "PATH=/usr/bin"));
});

test("execGate RECORDS an `env` prefix", () => {
  const r = execGate({ command: "env FOO=bar wget https://example.test/x" });
  assert.equal(r.decision, "allow");
  assert.ok(r.evasion.some((e) => e.kind === "env_prefix_override"));
});

test("execGate does not flag an ordinary relative net tool as evasion", () => {
  // A bare `curl` (relative) is the exec-wrap PATH shim's job — not evasion.
  const r = execGate({ command: "curl https://example.test/x" });
  assert.equal(r.decision, "allow");
  assert.equal(r.evasion.length, 0);
});

// ── classification metadata is reported (informational) ──────────────────────

test("execGate reports the shell + identifier (informational)", () => {
  const r = execGate({ command: "node ./scripts/build.mjs" });
  assert.equal(r.shell, "AgentShell"); // no resource hints at this layer
  assert.equal(r.identifier, "build.mjs");
});
