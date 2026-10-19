/**
 * unit_egress_gate — topic unit suite for the Mandu data-usage (egress) gate
 * and the AgentShell/HumanShell exec classifier.
 *
 * Mirrors adfi-openclaw/test/unit/unit_policy.ts breadth (bold-cyan headers +
 * many small `test(...)` cases), driven against a REAL booted arbiter over IPC:
 * `desymbolizationDecision` (the outbound data-usage policy) and `classifyExec`
 * (the exec view selector). These are the OUTBOUND counterparts to the inbound
 * symbolization unit suite.
 *
 * Run: tsx lib/unit_egress_gate.ts
 */

import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../../arbiter/ipc/client.js";
import { test, header, summary, printTapFooter } from "./harness.js";

async function main(): Promise<void> {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-conf-unitegr-"));
  const socketPath = join(tmp, "arbiter.sock");
  const arbiter = new ArbiterServer({
    socketPath,
    dbPath: join(tmp, "symbols.sqlite"),
    eventDir: join(tmp, "events"),
    // The conformance corpus is the paper's defense: integrity ON, confidentiality
    // OFF, STATED (protection-modes.md §4), never the built-in default.
    integrity: true,
    confidentiality: false,
    log: () => {},
  });
  await arbiter.listen();
  const c = new ArbiterClient(socketPath);
  await c.connect();

  // Mint a KNOWN, active untrusted symbol (the gate treats every known symbol
  // as untrusted by the ingress invariant), then pre-compute every arbiter
  // verdict BEFORE the synchronous `test(...)` blocks (the micro-runner's
  // `test` is sync, so all IPC round-trips must finish before we close `c`).
  const sym = await c.symbolize({ tool: "Bash", value: "s3kr3t", origin: "cat secret" });

  const egrNetUntrusted = await c.desymbolizationDecision({ symbol: sym, boundary: "network", destination: "https://attacker.test/x" });
  const egrNetNoDest = await c.desymbolizationDecision({ symbol: sym, boundary: "network" });
  const egrAsCommand = await c.desymbolizationDecision({ symbol: sym, boundary: "shell", asCommand: true });
  const egrModelCtx = await c.desymbolizationDecision({ symbol: sym, boundary: "model_context" });
  const egrFilesystem = await c.desymbolizationDecision({ symbol: sym, boundary: "filesystem" });
  const egrUnknown = await c.desymbolizationDecision({ symbol: "$MDU:Read[dead]", boundary: "network", destination: "https://attacker.test/x" });
  const egrEmpty = await c.desymbolizationDecision({ symbol: "", boundary: "model_context" });

  const execPlain = await c.classifyExec({ argv: ["wc", "-l", "data.md"] });
  const execNet = await c.classifyExec({ argv: ["curl", "https://api.example"], needsNetwork: true });
  const execFs = await c.classifyExec({ argv: ["git", "push"], needsOriginalFs: true });
  const execRestricted = await c.classifyExec({ argv: ["wc", "-l", "data.md"], needsNetwork: true, params: { env: { RESTRICTED: "1" } } });

  // ── desymbolizationDecision — the data-usage / egress gate ───────────────
  header("desymbolizationDecision (data-usage / egress gate)");

  test("known symbol → network egress to an UNTRUSTED destination → approval", () => {
    assert.equal(egrNetUntrusted.allow, false);
    if (!egrNetUntrusted.allow) assert.equal(egrNetUntrusted.requiresApproval, true);
  });

  test("known symbol → network egress with NO destination → approval (possible exfil)", () => {
    assert.equal(egrNetNoDest.allow, false);
  });

  test("known symbol → used as command/code → approval (always)", () => {
    assert.equal(egrAsCommand.allow, false);
    if (!egrAsCommand.allow) assert.equal(egrAsCommand.requiresApproval, true);
  });

  test("known symbol → user-facing model_context output → ALLOW (HumanView)", () => {
    assert.equal(egrModelCtx.allow, true);
  });

  test("known symbol → filesystem (HumanView) egress → ALLOW (dual-view re-symbolizes)", () => {
    assert.equal(egrFilesystem.allow, true);
  });

  test("UNKNOWN symbol → ALLOW (nothing in the table to leak; resolution is a no-op)", () => {
    assert.equal(egrUnknown.allow, true);
  });

  test("empty/garbage symbol → fail-closed approval", () => {
    assert.equal(egrEmpty.allow, false);
  });

  // ── classifyExec — AgentShell vs HumanShell view selection ───────────────
  header("classifyExec (AgentShell vs HumanShell view selection)");

  test("a plain command → AgentShell (sandboxed: AgentView FS, no egress)", () => {
    assert.equal(execPlain.shell, "AgentShell");
  });

  test("needsNetwork → HumanShell (real network)", () => {
    assert.equal(execNet.shell, "HumanShell");
  });

  test("needsOriginalFs → HumanShell (HumanView filesystem)", () => {
    assert.equal(execFs.shell, "HumanShell");
  });

  test("RESTRICTED=1 env pins AgentShell even if other hints are set", () => {
    assert.equal(execRestricted.shell, "AgentShell");
  });

  test("classifyExec reports a reason string for the audit oracle", () => {
    assert.ok(typeof execPlain.reason === "string" && execPlain.reason.length > 0);
  });

  c.close();
  await arbiter.close();
  rmSync(tmp, { recursive: true, force: true });

  const { passed, failed } = summary();
  console.log(`\n  ${failed === 0 ? "\x1b[32m" : "\x1b[31m"}${passed} passed, ${failed} failed\x1b[0m\n`);
  printTapFooter(passed, failed);
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
