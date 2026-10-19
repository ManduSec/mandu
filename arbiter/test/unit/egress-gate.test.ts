/**
 * egress-gate.test.ts — the data-usage policy over a real Unix socket.
 *
 * Mandu-new test. Stands up a real ArbiterServer wired to the engine-backed
 * policy (with a symbolLookup over the live SymbolMap) and exercises the three
 * new IPC ops end to end over an actual socket:
 *   - desymbolizationDecision : the egress gate (trusted symbol → allow;
 *                               untrusted-as-command → approval; untrusted →
 *                               untrusted destination → approval; empty/unknown
 *                               → the fail-closed/no-op rules).
 *   - classifyExec            : AgentShell default; HumanShell on resource need.
 *   - resolveExecArgv         : argv desymbolization gated by the data-usage
 *                               check (data-position resolves; command-position
 *                               withheld with an approval item).
 *
 * Run: npm run test:unit
 */

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import type { SymbolMap } from "../../symbol-table/index.js";
import { stateAxes } from "../axes.js";

stateAxes("injection"); // this suite states its axes (protection-modes.md §4)

let workdir: string;
let server: ArbiterServer;
let client: ArbiterClient;
let socketPath: string;

before(async () => {
  workdir = mkdtempSync(join(tmpdir(), "mandu-egress-"));
  socketPath = join(workdir, "arbiter.sock");
  // Engine-backed policy with a URL allowlist (internal.example TRUSTED) and the
  // default symbolLookup wired by the server over its live SymbolMap.
  server = new ArbiterServer({
    socketPath,
    dbPath: join(workdir, "symbols.db"),
    eventDir: join(workdir, "events"),
    log: () => {},
  });
  await server.listen();
  client = new ArbiterClient(socketPath);
  await client.connect();
});

after(async () => {
  client.close();
  await server.close();
  rmSync(workdir, { recursive: true, force: true });
});

// Helper: allocate a real symbol through the arbiter so the server's SymbolMap
// (and thus the egress gate's symbolLookup) knows about it.
async function symbolize(value: string, field = "text"): Promise<string> {
  return client.symbolize({ tool: "WebFetch", field, value });
}

// ── desymbolizationDecision over the socket ──────────────────────────────────

test("egress: a known untrusted symbol used as command → requiresApproval", async () => {
  const sym = await symbolize("rm -rf /");
  const d = await client.desymbolizationDecision({ symbol: sym, boundary: "shell", asCommand: true });
  assert.equal(d.allow, false);
  assert.equal((d as { requiresApproval: boolean }).requiresApproval, true);
  assert.match(d.reason, /command\/code/);
});

test("egress: a known untrusted symbol → unknown network destination → requiresApproval", async () => {
  const sym = await symbolize("user@example.com");
  const d = await client.desymbolizationDecision({ symbol: sym, boundary: "network" });
  assert.equal(d.allow, false);
  assert.equal((d as { requiresApproval: boolean }).requiresApproval, true);
});

test("egress: a known untrusted symbol → untrusted destination → requiresApproval", async () => {
  const sym = await symbolize("secret-token");
  const d = await client.desymbolizationDecision({
    symbol: sym, boundary: "network", destination: "https://evil.example/collect",
  });
  assert.equal(d.allow, false);
});

test("egress: an unknown symbol is a no-op (allow) — nothing to leak", async () => {
  const d = await client.desymbolizationDecision({
    symbol: "$MDU:WebFetch[ffff].text", boundary: "network", destination: "https://evil.example",
  });
  assert.equal(d.allow, true);
});

test("egress: a model-MUTATED token of a known symbol is gated like the real name", async () => {
  // The gate's lookup walks the same candidates as resolution
  // (findSymbolByName): an invented field suffix on a real token must not
  // demote a gated symbol to the unknown-symbol no-op while a resolution
  // surface would still resolve it — decision and resolution stay in lockstep.
  const sym = await symbolize("exfil-me");
  const d = await client.desymbolizationDecision({
    symbol: `${sym}.content`, boundary: "network", destination: "https://evil.example",
  });
  assert.equal(d.allow, false, "an invented suffix must not turn a gated symbol into a no-op");
  assert.equal((d as { requiresApproval: boolean }).requiresApproval, true);
});

test("egress: an empty symbol fails closed", async () => {
  const d = await client.desymbolizationDecision({ symbol: "", boundary: "network" });
  assert.equal(d.allow, false);
});

test("egress: a known untrusted symbol to a user-facing reply → allow (HumanView)", async () => {
  const sym = await symbolize("Acme Corp");
  const d = await client.desymbolizationDecision({ symbol: sym, boundary: "model_context" });
  assert.equal(d.allow, true);
});

test("egress: a bare shell boundary WITHOUT asCommand fails closed (requiresApproval)", async () => {
  // The shell branch (policy-interface.ts §3) is fail-closed: a value flowing
  // into a live shell whose argv position we cannot see here must go through
  // resolveExecArgv, so a bare shell-boundary desym with no asCommand flag is
  // denied with approval required. The existing tests only hit shell via
  // asCommand:true — this covers the asCommand-absent path.
  const sym = await symbolize("Acme Corp");
  const d = await client.desymbolizationDecision({ symbol: sym, boundary: "shell" });
  assert.equal(d.allow, false);
  assert.equal((d as { requiresApproval: boolean }).requiresApproval, true);
  assert.match(d.reason, /resolveExecArgv|fail-closed/);
});

test("egress: an OBSOLETED symbol at a normally-safe boundary fails closed (requiresApproval)", async () => {
  // Drives the obsolete-symbol branch (policy-interface.ts §obsolete, ~401-407)
  // end to end over a real socket, using the REAL symbol-table APIs to allocate
  // and obsolete the symbol, with the gate's symbolLookup wired over the SAME
  // live SymbolMap (exactly as ArbiterServer wires it). Even at model_context —
  // a boundary that ALLOWS an active untrusted symbol — an obsoleted symbol must
  // require human approval, because the resolved value may no longer be intended.
  const wd = mkdtempSync(join(tmpdir(), "mandu-egress-obsolete-"));
  const sock = join(wd, "arbiter.sock");
  const dbPath = join(wd, "symbols.db");

  const { createEngineBackedPolicy } = await import("../../policy/policy-interface.js");
  const { allocateSymbol, obsoleteSymbol, isSymbolActive } =
    await import("../../symbol-table/index.js");

  // A live in-memory SymbolMap the gate's symbolLookup closes over (mirrors the
  // server's `symbolLookup: (sym) => this.symbolMap.symbols.get(sym)`).
  const map: SymbolMap = { symbols: new Map() };
  const srv = new ArbiterServer({
    socketPath: sock,
    dbPath,
    eventDir: join(dbPath, "..", "events"),
    policy: createEngineBackedPolicy({
      symbolLookup: (s) => map.symbols.get(s),
    }),
    log: () => {},
  });
  await srv.listen();
  const cli = new ArbiterClient(sock);
  try {
    await cli.connect();

    // Allocate a real symbol into the map (persisted to the same DB).
    const sym = allocateSymbol(map, { tool: "Read", value: "stale untrusted content" }, dbPath);

    // Sanity: while ACTIVE, a model_context (HumanView) egress is allowed.
    assert.equal(isSymbolActive(map, sym), true);
    const active = await cli.desymbolizationDecision({ symbol: sym, boundary: "model_context" });
    assert.equal(active.allow, true);

    // Obsolete it via the REAL API (e.g. superseded by a human edit).
    obsoleteSymbol(map, sym, "human", dbPath);
    assert.equal(isSymbolActive(map, sym), false);

    // Now the SAME egress at the SAME normally-safe boundary must fail closed.
    const obsolete = await cli.desymbolizationDecision({ symbol: sym, boundary: "model_context" });
    assert.equal(obsolete.allow, false);
    assert.equal((obsolete as { requiresApproval: boolean }).requiresApproval, true);
    assert.match(obsolete.reason, /obsolete/);
  } finally {
    cli.close();
    await srv.close();
    rmSync(wd, { recursive: true, force: true });
  }
});

test("egress: trusted-destination network egress allows (URL allowlist)", async () => {
  // Bring up a second arbiter with internal.example allowlisted, sharing nothing
  // with the default one so the URL category is genuinely populated.
  const wd = mkdtempSync(join(tmpdir(), "mandu-egress-url-"));
  const sock = join(wd, "arbiter.sock");
  const { createEngineBackedPolicy } = await import("../../policy/policy-interface.js");
  // We need the gate to see the symbol AND the URL allowlist. Build the policy
  // with both an explicit symbolLookup and the allowlist.
  const known = new Map<string, { value: string; origin: string | null; obsoleted_at: number | null }>();
  known.set("$MDU:WebFetch[0001].text", { value: "v", origin: null, obsoleted_at: null });
  const srv = new ArbiterServer({
    socketPath: sock,
    dbPath: join(wd, "symbols.db"),
    eventDir: join(wd, "events"),
    policy: createEngineBackedPolicy({
      policyFileOverride: { inbound: { url: { default: "UNTRUSTED", trustedList: ["internal.example"] } } },
      symbolLookup: (s) => known.get(s),
    }),
    log: () => {},
  });
  await srv.listen();
  const cli = new ArbiterClient(sock);
  try {
    await cli.connect();
    const trusted = await cli.desymbolizationDecision({
      symbol: "$MDU:WebFetch[0001].text",
      boundary: "network",
      destination: "https://internal.example/api",
    });
    assert.equal(trusted.allow, true);

    const untrusted = await cli.desymbolizationDecision({
      symbol: "$MDU:WebFetch[0001].text",
      boundary: "network",
      destination: "https://attacker.example/x",
    });
    assert.equal(untrusted.allow, false);
  } finally {
    cli.close();
    await srv.close();
    rmSync(wd, { recursive: true, force: true });
  }
});

// ── classifyExec over the socket ─────────────────────────────────────────────

test("classifyExec: default AgentShell over IPC", async () => {
  const r = await client.classifyExec({ argv: ["ls", "-la"] });
  assert.equal(r.shell, "AgentShell");
});

test("classifyExec: HumanShell when network is needed over IPC", async () => {
  const r = await client.classifyExec({
    argv: ["node", "reddit-readonly.mjs", "posts"],
    needsNetwork: true,
  });
  assert.equal(r.shell, "HumanShell");
  assert.equal(r.identifier, "reddit-readonly.mjs");
});

// ── resolveExecArgv over the socket ──────────────────────────────────────────

test("resolveExecArgv: data-position symbol resolves over IPC (no approval)", async () => {
  const sym = await symbolize("rust lang", "q");
  const r = await client.resolveExecArgv({ argv: ["grep", sym, "notes.txt"], shell: "HumanShell" });
  assert.equal(r.approvals.length, 0);
  assert.deepEqual(r.argv, ["grep", "rust lang", "notes.txt"]);
});

test("resolveExecArgv: symbol-as-command is withheld with an approval item", async () => {
  const sym = await symbolize("rm -rf /");
  const r = await client.resolveExecArgv({ argv: [sym], shell: "HumanShell" });
  assert.ok(r.approvals.length > 0);
  assert.equal(r.approvals[0].kind, "symbol_as_command");
  // Argv stays symbolic — the raw value never reaches command position.
  assert.deepEqual(r.argv, [sym]);
});

test("resolveExecArgv: AgentShell preserves symbols over IPC", async () => {
  const sym = await symbolize("secret");
  const r = await client.resolveExecArgv({ argv: ["cat", sym], shell: "AgentShell" });
  assert.deepEqual(r.argv, ["cat", sym]);
  assert.equal(r.approvals.length, 0);
});
