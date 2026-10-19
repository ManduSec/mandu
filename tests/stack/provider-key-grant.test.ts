/**
 * provider-key-grant — the model services' keys a program in the session
 * sends itself (agent-sign-in.md §3.12: TYPESAFE_API_KEY for jev-ultrafast's
 * decision model, OPENROUTER_API_KEY for its text helper) over the
 * PRODUCTION wiring: the launcher's `registerProviderKeyGrants` on a real
 * ArbiterServer's human socket, then its `applyEnvSecrets` through the
 * launcher's socket adapter, exactly as run.ts calls them.
 *
 * Each key reaches the session's environment only as a placeholder, which
 * the egress decision releases at that key's own host and nowhere else (not
 * even at the other provider's host); without the grant (the human plane
 * gone) the key is still masked, and released nowhere without approval.
 *
 * Made-up keys. Axes explicit: secrets (confidentiality ON, integrity OFF).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { applyEnvSecrets, ndjsonCall, socketSecretArbiter } from "../../launcher/src/secret-setup.js";
import { registerProviderKeyGrants } from "../../launcher/src/agent-key-grant.js";
import { emptyMutation } from "../../launcher/src/backend/types.js";
import type { LaunchPlan } from "../../launcher/src/types.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets");

const TYPESAFE = "tsk_live_ProviderGrantStack9Qz2Lm7Xv4";
const OPENROUTER = "sk-or-v1-ProviderGrantStack3Wt8Kp1Hd6";

async function arbiter() {
  const dir = mkdtempSync(join(tmpdir(), "mdu-provkey-"));
  const sock = join(dir, "a.sock");
  const humanSock = join(dir, "h", "h.sock");
  const server = new ArbiterServer({
    socketPath: sock, adminSocketPath: join(dir, "admin.sock"), humanSocketPath: humanSock,
    dbPath: join(dir, "symbols.sqlite"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyPollMs: 0, policyDocument: { version: 1 },
  });
  await server.listen();
  const client = new ArbiterClient(sock);
  await client.connect();
  return {
    sock, humanSock, client,
    close: async () => { client.close(); await server.close(); rmSync(dir, { recursive: true, force: true }); },
  };
}

const plan = (humanSock: string | null) => ({ target: "shell", confidentiality: true, noContextProxy: true, arbiterHumanSock: humanSock, scopeId: "s-provkey" }) as unknown as LaunchPlan;

test("each provider key is a placeholder released at its own host only", async () => {
  const a = await arbiter();
  try {
    const env = { PATH: process.env["PATH"], TYPESAFE_API_KEY: TYPESAFE, OPENROUTER_API_KEY: OPENROUTER };
    const logs: string[] = [];
    const granted = await registerProviderKeyGrants(plan(a.humanSock), env, {}, {
      call: (sock, op, args) => ndjsonCall<unknown>(sock, op, args, 5_000), log: (m) => logs.push(m), pid: process.pid,
    });
    assert.deepEqual(granted, [{ name: "TYPESAFE_API_KEY", hosts: ["api.typesafe.ai"] }, { name: "OPENROUTER_API_KEY", hosts: ["openrouter.ai"] }], logs.join(" | "));
    const mut = emptyMutation();
    const res = await applyEnvSecrets(plan(a.humanSock), env, mut, { arbiter: socketSecretArbiter(a.sock), log: (m) => logs.push(m) });
    assert.deepEqual(res.masked, ["OPENROUTER_API_KEY", "TYPESAFE_API_KEY"], logs.join(" | "));
    const ts = mut.env["TYPESAFE_API_KEY"]!;
    const or = mut.env["OPENROUTER_API_KEY"]!;
    assert.match(ts, /^\$MDU:/);
    assert.match(or, /^\$MDU:/);
    assert.ok(!JSON.stringify(mut.env).includes(TYPESAFE) && !JSON.stringify(mut.env).includes(OPENROUTER), "no raw key in the session's environment");

    // As the egress proxy asks on a TLS-inspected request: the scheme, and
    // where in the request the placeholder sits (jev sends `Authorization:
    // Bearer <key>` to both).
    const at = async (symbol: string, destination: string, scheme = "https", positions = ["authorization"]) =>
      await a.client.desymbolizationDecision({ symbol, boundary: "network", destination, scheme, positions } as Parameters<ArbiterClient["desymbolizationDecision"]>[0]);
    assert.equal((await at(ts, "api.typesafe.ai")).allow, true, "TypeSafe's key at TypeSafe");
    assert.equal((await at(or, "openrouter.ai")).allow, true, "OpenRouter's key at OpenRouter");
    for (const [sym, host] of [[ts, "openrouter.ai"], [or, "api.typesafe.ai"], [ts, "evil.example"], [or, "pastebin.com"]] as const) {
      assert.equal((await at(sym, host)).allow, false, `${sym.slice(0, 24)}… not at ${host}`);
    }
    // Its own host, but not in the auth header, or over plain HTTP: refused.
    const inBody = await at(ts, "api.typesafe.ai", "https", ["body"]);
    assert.equal(inBody.allow, false);
    assert.match(String(inBody.reason), /Authorization header/);
    assert.equal((await at(ts, "api.typesafe.ai", "http")).allow, false, "never over plain HTTP");
  } finally {
    await a.close();
  }
});

test("without the human plane the key is not bound, and still masked: released nowhere without approval", async () => {
  const a = await arbiter();
  try {
    const env = { PATH: process.env["PATH"], TYPESAFE_API_KEY: TYPESAFE };
    const logs: string[] = [];
    assert.deepEqual(await registerProviderKeyGrants(plan(null), env, {}, {
      call: (sock, op, args) => ndjsonCall<unknown>(sock, op, args, 5_000), log: (m) => logs.push(m),
    }), []);
    assert.match(logs.join("\n"), /TYPESAFE_API_KEY not bound/);
    const mut = emptyMutation();
    await applyEnvSecrets(plan(null), env, mut, { arbiter: socketSecretArbiter(a.sock), log: (m) => logs.push(m) });
    const ts = mut.env["TYPESAFE_API_KEY"]!;
    assert.match(ts, /^\$MDU:/);
    const d = await a.client.desymbolizationDecision({ symbol: ts, boundary: "network", destination: "api.typesafe.ai" });
    assert.equal(d.allow, false);
    assert.equal("requiresApproval" in d && d.requiresApproval, true);
  } finally {
    await a.close();
  }
});
