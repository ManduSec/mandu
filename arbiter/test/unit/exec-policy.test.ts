/**
 * exec-policy.test.ts — unit tests for the lifted exec / data-usage policy.
 *
 * Mandu-new test. Covers the lifted exec policy family (exec-identifier,
 * exec-argv-mode, untrusted-command-execution, shell-symbol-resolution,
 * script-file-command-expansion) and the exec-classify orchestration
 * (AgentShell vs HumanShell selection + argv desymbolization gated by the
 * data-usage check), plus the standalone decideDesymbolization egress gate.
 *
 * Ports the security-critical adfi behaviors:
 *   - canonical command identity / interpreter stripping
 *   - command rewriting (`python fix.py` → `python -c <file content>`)
 *   - symbol-as-command detection (whole-command symbol, sh -c, python -c)
 *   - safe argv lowering: a resolved value never escapes its argv slot
 *
 * Run: npm run test:unit
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  normalizeExecCommand,
  isSymbolicExec,
  basename,
} from "../../policy/exec-identifier.js";
import {
  classifyExec,
  resolveExecArgv,
} from "../../policy/exec-classify.js";
import { detectUntrustedCommandExecutionPatterns } from "../../policy/untrusted-command-execution.js";
import { resolveShellCommandSymbols } from "../../policy/shell-symbol-resolution.js";
import { expandScriptFileCommandForDetection } from "../../policy/script-file-command-expansion.js";
import { decideDesymbolization } from "../../policy/policy-interface.js";
import {
  type SymbolMap,
  allocateSymbol,
  getActiveFormat,
} from "../../symbol-table/index.js";

function emptyMap(): SymbolMap {
  return { symbols: new Map() };
}

// ── exec-identifier ──────────────────────────────────────────────────────────

test("normalizeExecCommand strips interpreters + flags to a canonical id", () => {
  assert.deepEqual(
    normalizeExecCommand("node ./scripts/reddit-readonly.mjs posts rust"),
    { id: "reddit-readonly.mjs", args: ["posts", "rust"] },
  );
  assert.deepEqual(
    normalizeExecCommand("python3 -u my-skill.py fetch 2401"),
    { id: "my-skill.py", args: ["fetch", "2401"] },
  );
  // Inline-code flag → unidentifiable.
  assert.equal(normalizeExecCommand("python -c 'print(1)'"), null);
  assert.equal(basename("/usr/local/bin/my-bin"), "my-bin");
});

test("isSymbolicExec recognizes RESTRICTED=1 (AgentShell pin)", () => {
  assert.equal(isSymbolicExec({ env: { RESTRICTED: "1" } }), true);
  assert.equal(isSymbolicExec({ env: { RESTRICTED: "0" } }), false);
  assert.equal(isSymbolicExec(undefined), false);
});

// ── classifyExec: AgentShell default, HumanShell on resource need ────────────

test("classifyExec defaults to AgentShell", () => {
  const d = classifyExec({ argv: ["ls", "-la"] });
  assert.equal(d.shell, "AgentShell");
  assert.match(d.reason, /AgentShell/);
});

test("classifyExec selects HumanShell when network/original FS is needed", () => {
  const net = classifyExec({ argv: ["curl", "https://api.example/x"], needsNetwork: true });
  assert.equal(net.shell, "HumanShell");
  assert.match(net.reason, /network/);

  const fs = classifyExec({ argv: ["cat", "report.pdf"], needsOriginalFs: true });
  assert.equal(fs.shell, "HumanShell");
});

test("classifyExec: RESTRICTED=1 pins AgentShell even if resources requested", () => {
  const d = classifyExec({
    argv: ["node", "reddit-readonly.mjs", "posts"],
    needsNetwork: true,
    params: { env: { RESTRICTED: "1" } },
  });
  assert.equal(d.shell, "AgentShell");
  assert.equal(d.identifier, "reddit-readonly.mjs");
});

// ── symbol-as-command detection (data-usage policy core) ─────────────────────

test("detectUntrustedCommandExecutionPatterns flags whole-command + sh -c + python -c", () => {
  const fmt = getActiveFormat();
  const sym = fmt.generate({ tool: "web_fetch", hash: "a1b2", field: "text" });

  // Whole command IS a symbol.
  const whole = detectUntrustedCommandExecutionPatterns(sym, { action: "block" });
  assert.ok(whole.some(m => m.patternId === "command_is_symbol"));

  // sh -c "<symbol>"
  const shc = detectUntrustedCommandExecutionPatterns(`sh -c "${sym}"`, { action: "block" });
  assert.ok(shc.some(m => m.patternId === "shell_c_contains_symbol"));

  // python -c "<symbol>"
  const py = detectUntrustedCommandExecutionPatterns(`python -c "${sym}"`, { action: "block" });
  assert.ok(py.some(m => m.patternId === "interpreter_inline_code_contains_symbol"));

  // An ordinary data argument is NOT flagged as code.
  const data = detectUntrustedCommandExecutionPatterns(`grep ${sym} file.txt`, { action: "block" });
  assert.equal(data.length, 0);
});

// ── shell-symbol-resolution: a resolved value cannot escape its slot ─────────

test("resolveShellCommandSymbols single-quotes an unquoted resolved value", () => {
  const map = emptyMap();
  const sym = allocateSymbol(map, { tool: "web_fetch", field: "text", value: "x; rm -rf /" });
  const r = resolveShellCommandSymbols(`echo ${sym}`, map.symbols);
  assert.equal(r.changed, true);
  // The dangerous value is single-quoted, so the metacharacters are inert.
  assert.equal(r.command, `echo 'x; rm -rf /'`);
});

test("resolveShellCommandSymbols leaves unknown symbols untouched", () => {
  const map = emptyMap();
  const ghost = "$MDU:exec[ffff]";
  const r = resolveShellCommandSymbols(`echo ${ghost}`, map.symbols);
  assert.equal(r.changed, false);
  assert.equal(r.command, `echo ${ghost}`);
});

test("resolveShellCommandSymbols resolves a model-MUTATED token like the real name", () => {
  // The candidate walk (symbol-format): an invented field suffix on a real
  // token resolves — the shell no longer runs a guaranteed-garbage literal
  // ($MDU:Read[6819].content for the real $MDU:Read[6819], seen live).
  const map = emptyMap();
  const sym = allocateSymbol(map, { tool: "Read", value: "notes body" });
  const r = resolveShellCommandSymbols(`echo ${sym}.content`, map.symbols);
  assert.equal(r.changed, true);
  assert.equal(r.command, `echo 'notes body'`);
  // A mutation with an UNKNOWN base stays untouched (no invented matches).
  const ghost = resolveShellCommandSymbols(`echo $MDU:Read[ffff].content`, map.symbols);
  assert.equal(ghost.changed, false);
});

// ── command rewriting: `python fix.py` → `python -c <file content>` ──────────

test("expandScriptFileCommandForDetection rewrites a script-file invocation to inline code", () => {
  const wd = mkdtempSync(join(tmpdir(), "mandu-exec-"));
  try {
    const scriptPath = join(wd, "fix.py");
    writeFileSync(scriptPath, "print('hello')\n");
    const exp = expandScriptFileCommandForDetection({
      command: "python fix.py",
      workdir: wd,
      // Trusted-path resolver: identity (the script lives in a trusted dir).
      trustedPathFor: (abs) => abs,
    });
    assert.ok(exp, "expansion expected");
    assert.equal(exp!.ruleId, "python_script_file");
    assert.equal(exp!.inlineRunner, "python");
    assert.equal(exp!.inlineFlag, "-c");
    // The normalized command is `python -c '<file content>'`.
    assert.match(exp!.normalizedCommand, /^python -c '/);
    assert.match(exp!.normalizedCommand, /print\('"'"'hello'"'"'\)/);
  } finally {
    rmSync(wd, { recursive: true, force: true });
  }
});

test("expandScriptFileCommandForDetection refuses an untrusted script (no expansion)", () => {
  const wd = mkdtempSync(join(tmpdir(), "mandu-exec-"));
  try {
    writeFileSync(join(wd, "evil.py"), "import os\n");
    const exp = expandScriptFileCommandForDetection({
      command: "python evil.py",
      workdir: wd,
      // The script is NOT in a trusted location → null → no expansion.
      trustedPathFor: () => null,
    });
    assert.equal(exp, null);
  } finally {
    rmSync(wd, { recursive: true, force: true });
  }
});

// ── resolveExecArgv: desymbolize argv only after the data-usage check ────────

test("resolveExecArgv (AgentShell) preserves symbols, no approvals", () => {
  const map = emptyMap();
  const sym = allocateSymbol(map, { tool: "web_fetch", field: "text", value: "secret" });
  const r = resolveExecArgv({ argv: ["grep", sym, "f.txt"], shell: "AgentShell" }, map);
  assert.deepEqual(r.argv, ["grep", sym, "f.txt"]);
  assert.equal(r.approvals.length, 0);
});

test("resolveExecArgv (HumanShell) resolves a data-position symbol in-slot", () => {
  const map = emptyMap();
  const sym = allocateSymbol(map, { tool: "web_fetch", field: "q", value: "rust lang" });
  const r = resolveExecArgv({ argv: ["grep", sym, "notes.txt"], shell: "HumanShell" }, map);
  assert.equal(r.approvals.length, 0, "data-position symbol needs no approval");
  // The symbol slot is replaced with the raw value as a single argv token.
  assert.deepEqual(r.argv, ["grep", "rust lang", "notes.txt"]);
});

test("resolveExecArgv (HumanShell) withholds a symbol-as-command (requires approval)", () => {
  const map = emptyMap();
  const sym = allocateSymbol(map, { tool: "web_fetch", field: "text", value: "rm -rf /" });
  // The WHOLE command is a symbol → command-position flow → must be approved.
  const r = resolveExecArgv({ argv: [sym], shell: "HumanShell" }, map);
  assert.ok(r.approvals.length > 0, "symbol-as-command must require approval");
  assert.equal(r.approvals[0].kind, "symbol_as_command");
  // The argv is LEFT SYMBOLIC — the raw value never enters command position.
  assert.deepEqual(r.argv, [sym]);
});

test("resolveExecArgv (HumanShell) flags a symbol inside python -c", () => {
  const map = emptyMap();
  const sym = allocateSymbol(map, { tool: "web_fetch", field: "text", value: "os.system('x')" });
  const r = resolveExecArgv({ argv: ["python", "-c", sym], shell: "HumanShell" }, map);
  assert.ok(r.approvals.length > 0);
  assert.equal(r.approvals[0].kind, "symbol_as_command");
});

// ── decideDesymbolization: the standalone egress gate ────────────────────────

const denyDest = () => false;
const allowDest = () => true;

test("decideDesymbolization: empty symbol fails closed", () => {
  const d = decideDesymbolization({ symbol: "", boundary: "network" }, () => undefined, denyDest);
  assert.equal(d.allow, false);
});

test("decideDesymbolization: unknown symbol is a no-op (allow)", () => {
  const d = decideDesymbolization(
    { symbol: "$MDU:x[0001]", boundary: "network", destination: "https://evil.example" },
    () => undefined,
    denyDest,
  );
  assert.equal(d.allow, true);
});

test("decideDesymbolization: known untrusted symbol as command requires approval", () => {
  const entry = { value: "v", origin: null, obsoleted_at: null };
  const d = decideDesymbolization(
    { symbol: "$MDU:x[0001]", boundary: "shell", asCommand: true },
    () => entry,
    allowDest,
  );
  assert.equal(d.allow, false);
  assert.equal(d.requiresApproval, true);
  assert.match(d.reason, /command\/code/);
});

test("decideDesymbolization: untrusted symbol to untrusted destination requires approval", () => {
  const entry = { value: "v", origin: null, obsoleted_at: null };
  const d = decideDesymbolization(
    { symbol: "$MDU:x[0001]", boundary: "network", destination: "https://evil.example" },
    () => entry,
    denyDest,
  );
  assert.equal(d.allow, false);
  assert.equal(d.requiresApproval, true);
});

test("decideDesymbolization: untrusted symbol to TRUSTED destination allows", () => {
  const entry = { value: "v", origin: null, obsoleted_at: null };
  const d = decideDesymbolization(
    { symbol: "$MDU:x[0001]", boundary: "network", destination: "https://internal.example" },
    () => entry,
    allowDest,
  );
  assert.equal(d.allow, true);
});

test("decideDesymbolization: network egress without a destination fails closed", () => {
  const entry = { value: "v", origin: null, obsoleted_at: null };
  const d = decideDesymbolization(
    { symbol: "$MDU:x[0001]", boundary: "network" },
    () => entry,
    allowDest,
  );
  assert.equal(d.allow, false);
});

test("decideDesymbolization: user-facing model output allows (HumanView)", () => {
  const entry = { value: "v", origin: null, obsoleted_at: null };
  const d = decideDesymbolization(
    { symbol: "$MDU:x[0001]", boundary: "model_context" },
    () => entry,
    denyDest,
  );
  assert.equal(d.allow, true);
});

test("decideDesymbolization: obsolete symbol fails closed", () => {
  const entry = { value: "v", origin: null, obsoleted_at: 12345 };
  const d = decideDesymbolization(
    { symbol: "$MDU:x[0001]", boundary: "model_context" },
    () => entry,
    denyDest,
  );
  assert.equal(d.allow, false);
});
