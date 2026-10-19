/**
 * e2e — plan 11 phase 3 through the REAL arbiter: rung 3 (`declassify_symbol`)
 * opens a `local-model` datum into the main conversation only for a session
 * the launcher bound to a `models:` entry the law in force declares
 * `local: true`
 * (docs/design/confidentiality/model-endpoints.md §1.7.1).
 *
 * The invariant half: an unbound session, a default-vendor session and a
 * session bound to a declared outside model get no bytes back; a claim made
 * after the launcher's binding, after traffic, or after an arbiter restart is
 * refused; and a hot policy edit that drops `local: true` closes the door for
 * the running session.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";
import { pollDiskApproving } from "../held-disk.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

const CONTRACT = "Acme agrees to pay $4,200,000 on 2026-09-30. TLLM_LOCAL_CANARY";

const lawYaml = (ollamaLocal: boolean): string => [
  "version: 1",
  "models:",
  `  - { name: ollama, url: "http://127.0.0.1:11434", local: ${ollamaLocal} }`,
  '  - { name: gateway, url: "https://llm.corp.example", local: false }',
  "paths:",
  "  - { path: /h/notes/contract.md, level: local-model }",
  "",
].join("\n");

interface Stack {
  dir: string;
  file: string;
  server: ArbiterServer;
  c: ArbiterClient;
}

async function boot(dir: string, file: string): Promise<Stack> {
  const server = new ArbiterServer({
    socketPath: join(dir, "a.sock"), dbPath: join(dir, "symbols.sqlite"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, policyPath: file, policyPollMs: 0,
  });
  await server.listen();
  const c = new ArbiterClient(join(dir, "a.sock"));
  await c.connect();
  return { dir, file, server, c };
}

async function down(s: Stack): Promise<void> {
  s.c.close();
  await s.server.close();
}

async function withStack(fn: (s: Stack) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-upstream-e2e-"));
  const file = join(dir, "policy.yaml");
  writeFileSync(file, lawYaml(true));
  const s = await boot(dir, file);
  try {
    await fn(s);
  } finally {
    await down(s).catch(() => {});
    rmSync(dir, { recursive: true, force: true });
  }
}

/** A TRUSTED local-model datum, so the integrity refusal cannot be what
 *  answers: only the level and the session's main model decide. */
async function mint(c: ArbiterClient, sessionKey: string): Promise<string> {
  const r = await c.symbolizeFull({
    tool: "Read", value: CONTRACT, field: "content", origin: "/h/notes/contract.md", integrity: "trusted", sessionKey,
  });
  assert.match(r.symbol, /^\$MDU:localmodel_Read\[/);
  return r.symbol;
}

async function declassify(c: ArbiterClient, sessionKey: string) {
  return c.declassifySymbol({ symbol: await mint(c, sessionKey), sessionKey });
}

function assertRefused(r: { allowed: boolean; requiresApproval: boolean; value: string | null; reason: string }, why: string): void {
  assert.equal(r.allowed, false, why);
  assert.equal(r.requiresApproval, false, `${why}: no approval opens it`);
  assert.equal(r.value, null, `${why}: the bytes never come back`);
  assert.match(r.reason, /local-model data is readable only by the user's own model/);
}

test("only a session bound to a declared local model gets the bytes into its context", async () => {
  await withStack(async ({ c }) => {
    assertRefused(await declassify(c, "s-unbound"), "unbound session");

    assert.deepEqual(
      await c.setSessionUpstream({ sessionKey: "s-vendor", endpoint: null, requestedBy: "launcher" }),
      { sessionKey: "s-vendor", endpoint: null, location: "external", bound: true },
    );
    assertRefused(await declassify(c, "s-vendor"), "default vendor");

    assert.equal((await c.setSessionUpstream({ sessionKey: "s-gw", endpoint: "gateway" })).location, "external");
    assertRefused(await declassify(c, "s-gw"), "declared outside model");

    assert.equal((await c.setSessionUpstream({ sessionKey: "s-typo", endpoint: "olama" })).location, "external");
    assertRefused(await declassify(c, "s-typo"), "a name the law does not declare");

    assert.deepEqual(
      await c.setSessionUpstream({ sessionKey: "s-local", endpoint: "ollama", requestedBy: "launcher" }),
      { sessionKey: "s-local", endpoint: "ollama", location: "local", bound: true },
    );
    const ok = await declassify(c, "s-local");
    assert.equal(ok.allowed, true, ok.reason);
    assert.equal(ok.value, CONTRACT);
    assert.equal(ok.watermark, "local-model", "the session floats to the datum's own level");
    assert.equal((await c.sessionState("s-local")).confidentiality, "local-model");
  });
});

test("claims after the launcher's binding or after traffic are refused, and nothing changes", async () => {
  await withStack(async ({ c }) => {
    await c.setSessionUpstream({ sessionKey: "s1", endpoint: null, requestedBy: "launcher" });
    await assert.rejects(
      c.setSessionUpstream({ sessionKey: "s1", endpoint: "ollama", requestedBy: "agent" }),
      /bind-once/,
    );
    assert.deepEqual(await c.sessionUpstream("s1"), { sessionKey: "s1", endpoint: null, location: "external", bound: true });
    assertRefused(await declassify(c, "s1"), "the forged claim did not take");

    // A session that already classified traffic is not the launcher's to bind.
    await c.classify({ tool: "Read", field: "content", value: "x", sessionKey: "s2" } as never);
    await assert.rejects(c.setSessionUpstream({ sessionKey: "s2", endpoint: "ollama" }), /already carried traffic/);
    assert.equal((await c.sessionUpstream("s2")).bound, false);
    assertRefused(await declassify(c, "s2"), "late claim");
  });
});

test("the binding survives an arbiter restart; so does bind-once", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-upstream-e2e-"));
  const file = join(dir, "policy.yaml");
  writeFileSync(file, lawYaml(true));
  try {
    const a = await boot(dir, file);
    await a.c.setSessionUpstream({ sessionKey: "r-local", endpoint: "ollama", requestedBy: "launcher" });
    await a.c.setSessionUpstream({ sessionKey: "r-vendor", endpoint: null, requestedBy: "launcher" });
    await down(a);

    const b = await boot(dir, file);
    try {
      assert.equal((await b.c.sessionUpstream("r-local")).location, "local");
      await assert.rejects(b.c.setSessionUpstream({ sessionKey: "r-vendor", endpoint: "ollama" }), /bind-once/);
      assertRefused(await declassify(b.c, "r-vendor"), "after the restart");
      assert.equal((await declassify(b.c, "r-local")).allowed, true);
    } finally {
      await down(b);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a hot policy edit that drops local: true closes rung 3 for the running session", async () => {
  await withStack(async ({ c, server, file }) => {
    await c.setSessionUpstream({ sessionKey: "h", endpoint: "ollama", requestedBy: "launcher" });
    assert.equal((await c.sessionUpstream("h")).location, "local");
    writeFileSync(file, lawYaml(false));
    const t = new Date(Date.now() + 5_000);
    utimesSync(file, t, t);
    pollDiskApproving(server); // a `models:` change is held until approved (§4.6)
    assert.deepEqual(await c.sessionUpstream("h"), { sessionKey: "h", endpoint: "ollama", location: "external", bound: true });
    assertRefused(await declassify(c, "h"), "after the edit");
  });
});

test("the handling prompt tells a local session that declassify works for localmodel_, and everyone else that it is refused", async () => {
  await withStack(async ({ c }) => {
    await c.setSessionUpstream({ sessionKey: "p-local", endpoint: "ollama" });
    await c.setSessionUpstream({ sessionKey: "p-vendor", endpoint: null });
    const local = await c.handlingPrompt(undefined, undefined, "p-local");
    const vendor = await c.handlingPrompt(undefined, undefined, "p-vendor");
    const none = await c.handlingPrompt();
    assert.match(local, /`declassify_symbol` works for this level here/);
    assert.match(vendor, /`declassify_symbol` is refused\*\* for this level/);
    assert.equal(none, vendor, "no session key reads as an outside model");
  });
});
