/**
 * env-wire-grant-recorded — a pip index variable's wire grant (plan 10
 * §11.13.1: `PIP_INDEX_URL`'s password bound to the index host its own URL
 * names) survives an arbiter restart when the launcher registered it on the
 * human plane (confidentiality.md §2.1, "The wire grant is recorded",
 * 2026-10-17), over the REAL components: an ArbiterServer reading a policy
 * FILE, restarted on the same mandu.db, and the net-proxy's production
 * adapter (`new ArbiterClientAdapter(new ArbiterClient(data), new
 * ArbiterClient(human))`) asking the egress gate as the proxy does for an
 * HTTPS request carrying the placeholder in its Authorization header.
 *
 * Before: the arbiter held the host in memory only, so a restart under a
 * live session dropped it (pip's index password held at its own index until
 * the next launch). Now:
 *
 *   1. a human-plane registration is RECORDED (`wire_grants`): the grant
 *      survives the restart, while an `env.sources` binding removed from the
 *      law meanwhile does not (it is the user's, and follows the law);
 *   2. a data-plane registration (the socket the agent's world can reach)
 *      stays in memory only, as every one did before: the agent never earns a
 *      grant that outlives the arbiter.
 *
 * Axes explicit: secrets (confidentiality ON, integrity OFF).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { pollDiskApproving } from "../../arbiter/test/held-disk.js";
import { ArbiterClientAdapter as NetProxyAdapter, type RealArbiterClient as NetProxyRealClient } from "../../interceptors/net-proxy/src/arbiter-client.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const INDEX = "pypi.corp.example";
const MIRROR = "mirror.example";

interface Stack {
  server: ArbiterServer;
  data: ArbiterClient;
  human: ArbiterClient;
  net: NetProxyAdapter;
  close: () => Promise<void>;
}

function harness() {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-env-wire-"));
  const policy = join(tmp, "policy.yaml");
  const dbPath = join(tmp, "symbols.sqlite");
  let bump = 0;
  let starts = 0;
  /** env.sources: name → bindings (none: no env section). */
  const writeLaw = (env: Record<string, string[]>): void => {
    const lines = ["version: 1"];
    const entries = Object.entries(env);
    if (entries.length > 0) {
      lines.push("env:", "  sources:");
      for (const [n, b] of entries) lines.push(`    - name: ${n}`, `      source: "cmd:printf x"`, `      bindings: [${b.join(", ")}]`);
    }
    writeFileSync(policy, lines.join("\n") + "\n");
    const t = new Date(Date.now() + 5_000 + ++bump * 1_000);
    utimesSync(policy, t, t);
  };
  const start = async (): Promise<Stack> => {
    const n = ++starts;
    const sock = join(tmp, `a${n}.sock`);
    const humanSock = join(tmp, `h${n}`, "h.sock");
    const server = new ArbiterServer({
      socketPath: sock, adminSocketPath: join(tmp, `admin${n}.sock`), humanSocketPath: humanSock,
      dbPath, eventDir: join(tmp, "events"), log: () => {},
      confidentiality: true, integrity: false, policyPath: policy, policyPollMs: 0,
    });
    await server.listen();
    const data = new ArbiterClient(sock); await data.connect();
    const human = new ArbiterClient(humanSock); await human.connect();
    const netData = new ArbiterClient(sock); await netData.connect();
    const netHuman = new ArbiterClient(humanSock); await netHuman.connect();
    const net = new NetProxyAdapter(netData as unknown as NetProxyRealClient, netHuman as never);
    return {
      server, data, human, net,
      close: async () => {
        data.close(); human.close(); netData.close(); netHuman.close();
        await server.close();
      },
    };
  };
  /** The egress gate's rule for the placeholder in an HTTPS request's Authorization header. */
  const ruleAt = async (s: Stack, symbol: string, host: string): Promise<string> => {
    const d = await s.net.desymbolizationDecision({ symbol, boundary: "network", destination: host, scheme: "https", positions: ["authorization"] });
    return d.ruleRef?.id ?? (d.allow ? "allow" : "deny");
  };
  const register = async (client: ArbiterClient, name: string, value: string): Promise<string> => {
    const r = await client.registerEnvSecrets({ vars: [{ name, value }], sessionKey: "E" });
    const sym = r.vars[0]?.symbol;
    assert.equal(typeof sym, "string", JSON.stringify(r));
    return sym!;
  };
  return { writeLaw, start, ruleAt, register, cleanup: () => rmSync(tmp, { recursive: true, force: true }) };
}

test("a human-plane registration's index grant survives an arbiter restart; an env.sources host removed meanwhile does not", async () => {
  const h = harness();
  h.writeLaw({ PIP_INDEX_URL: [MIRROR] });
  let s = await h.start();
  try {
    const sym = await h.register(s.human, "PIP_INDEX_URL", `https://me:s3cr%21t_ENVWIRE_4471@${INDEX}/simple`);
    assert.equal(await h.ruleAt(s, sym, INDEX), "egress:secret-bound-trusted", "the grant: the value's own index");
    assert.equal(await h.ruleAt(s, sym, MIRROR), "egress:secret-bound-trusted", "the user's env.sources binding");

    // The arbiter goes down under the live session; the user drops the
    // env.sources entry meanwhile. No launch registers the variable again.
    await s.close();
    h.writeLaw({});
    s = await h.start();
    pollDiskApproving(s.server);
    assert.equal(await h.ruleAt(s, sym, INDEX), "egress:secret-bound-trusted", "after the restart: the recorded grant still releases at its index");
    assert.equal(await h.ruleAt(s, sym, MIRROR), "egress:secret-unbound", "the removed source's host does not come back");
    assert.equal(await h.ruleAt(s, sym, "evil.example"), "egress:secret-unbound");
    // Still automatic: only the Authorization header gets it.
    const body = await s.net.desymbolizationDecision({ symbol: sym, boundary: "network", destination: INDEX, scheme: "https", positions: ["body"] });
    assert.equal(body.ruleRef?.id, "egress:secret-wire-position");
  } finally {
    await s.close();
    h.cleanup();
  }
});

test("a data-plane registration's index grant lives in the arbiter's memory only: gone after a restart (the agent's world earns no lasting grant)", async () => {
  const h = harness();
  h.writeLaw({});
  let s = await h.start();
  try {
    const sym = await h.register(s.data, "PIP_EXTRA_INDEX_URL", `https://me:dataplane_ENVWIRE_9902@${INDEX}/simple`);
    assert.equal(await h.ruleAt(s, sym, INDEX), "egress:secret-bound-trusted", "in the running arbiter, as before");

    await s.close();
    s = await h.start();
    pollDiskApproving(s.server);
    assert.equal(await h.ruleAt(s, sym, INDEX), "egress:secret-unbound", "not recorded: bound nowhere after a restart (fail-closed)");
  } finally {
    await s.close();
    h.cleanup();
  }
});
