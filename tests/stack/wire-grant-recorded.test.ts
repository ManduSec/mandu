/**
 * wire-grant-recorded — a field's wire grant is a RECORD the registration
 * makes, never inferred from the row's bindings (confidentiality.md §2.1,
 * "The wire grant is recorded", 2026-10-17), over the REAL components: an
 * ArbiterServer reading a policy FILE (the hand-edit poll), restarted on the
 * same mandu.db, and the net-proxy's production adapter (`new
 * ArbiterClientAdapter(new ArbiterClient(data), new ArbiterClient(human))`)
 * asking the egress gate as the proxy does for an HTTPS request carrying the
 * placeholder in its Authorization header.
 *
 * The inference was "a `.npmrc` / `pip.conf` field holds the host its own
 * text names and its base row does not". It failed both ways:
 *
 *   1. SECURITY: a workspace `.npmrc` (no grant: the agent can write it)
 *      whose token a `values:` entry binds to its own registry. The field
 *      holds the host, its base row (the whole file's bindings) does not, so
 *      after the human removed the entry the sync kept the host as a "grant",
 *      in the running arbiter, after a restart and after the next launch's
 *      registration: a binding the human removed kept releasing the token;
 *   2. UTILITY: the launch HOME's `.npmrc` labelled with its registry too.
 *      Both rows held the host, so removing the label's binding took the
 *      grant with it until the next launch registered the file.
 *
 * Axes explicit: secrets (confidentiality ON, integrity OFF).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { pollDiskApproving } from "../../arbiter/test/held-disk.js";
import { ArbiterClientAdapter as NetProxyAdapter, type RealArbiterClient as NetProxyRealClient } from "../../interceptors/net-proxy/src/arbiter-client.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const REGISTRY = "registry.npmjs.org";

interface Stack {
  server: ArbiterServer;
  human: ArbiterClient;
  net: NetProxyAdapter;
  close: () => Promise<void>;
}

function harness() {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-wire-grant-"));
  const home = join(tmp, "home"); mkdirSync(home, { recursive: true });
  const ws = join(tmp, "ws"); mkdirSync(ws, { recursive: true });
  const policy = join(tmp, "policy.yaml");
  const dbPath = join(tmp, "symbols.sqlite");
  let bump = 0;
  let starts = 0;
  /** One `paths:` entry: `path`, its `bindings`, and optionally a `values:` entry for every field. */
  const writeLaw = (path: string, bindings: string[], valueHosts?: string[]): void => {
    const lines = ["version: 1", "paths:", `  - path: ${path}`, "    level: no-model", `    bindings: [${bindings.join(", ")}]`];
    if (valueHosts) lines.push("    values:", `      "*": { bindings: [${valueHosts.join(", ")}] }`);
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
    const human = new ArbiterClient(humanSock); await human.connect();
    const netData = new ArbiterClient(sock); await netData.connect();
    const netHuman = new ArbiterClient(humanSock); await netHuman.connect();
    const net = new NetProxyAdapter(netData as unknown as NetProxyRealClient, netHuman as never);
    return {
      server, human, net,
      close: async () => {
        human.close(); netData.close(); netHuman.close();
        await server.close();
      },
    };
  };
  /** The egress gate's rule for the token in an HTTPS request's Authorization header. */
  const ruleAt = async (s: Stack, symbol: string, host: string): Promise<string> => {
    const d = await s.net.desymbolizationDecision({ symbol, boundary: "network", destination: host, scheme: "https", positions: ["authorization"] });
    return d.ruleRef?.id ?? (d.allow ? "allow" : "deny");
  };
  /** Register `path` (with `home` for the launch HOME) and return its token's field symbol. */
  const registerToken = async (s: Stack, path: string, withHome: boolean): Promise<string> => {
    const r = await s.human.registerSecret({ path, sessionKey: "W", ...(withHome ? { home } : {}) });
    assert.equal(typeof r.symbol, "string", r.reason);
    const tokens = (r.twin ?? "").match(/\$MDU:[a-zA-Z_][a-zA-Z0-9_]*\[[0-9a-f]+\]\.[^\s]+/g) ?? [];
    assert.equal(tokens.length, 1, `one field placeholder in the twin: ${r.twin}`);
    return tokens[0]!;
  };
  return { tmp, home, ws, writeLaw, start, ruleAt, registerToken, cleanup: () => rmSync(tmp, { recursive: true, force: true }) };
}

const npmrc = (token: string): string => `registry=https://${REGISTRY}/\n//${REGISTRY}/:_authToken=${token}\n`;

test("security fix: a workspace .npmrc token's registry bound by values:, then removed, stops releasing at once, after a restart and after the next registration", async () => {
  const h = harness();
  const file = join(h.ws, ".npmrc");
  writeFileSync(file, npmrc("npm_WIREGRANT_VALUES_7311"));
  h.writeLaw(file, [], [REGISTRY]);
  let s = await h.start();
  try {
    const field = await h.registerToken(s, file, false);
    assert.equal(await h.ruleAt(s, field, REGISTRY), "egress:secret-bound-trusted", "the user's value binding releases");

    // The human removes the value binding (a hand edit, approved).
    h.writeLaw(file, []);
    assert.equal(pollDiskApproving(s.server), true, "the edit was seen");
    assert.equal(await h.ruleAt(s, field, REGISTRY), "egress:secret-unbound", "the removed binding no longer releases");

    // A restart on the same mandu.db, then the next launch's registration.
    await s.close();
    s = await h.start();
    pollDiskApproving(s.server);
    assert.equal(await h.ruleAt(s, field, REGISTRY), "egress:secret-unbound", "after a restart: still held");
    assert.equal(await h.registerToken(s, file, false), field, "the same row, reused");
    assert.equal(await h.ruleAt(s, field, REGISTRY), "egress:secret-unbound", "after the next registration: still held");
  } finally {
    await s.close();
    h.cleanup();
  }
});

test("the launch HOME's .npmrc keeps its wire grant when the label's binding on the same registry is removed, at once and after a restart with no registration", async () => {
  const h = harness();
  const file = join(h.home, ".npmrc");
  writeFileSync(file, npmrc("npm_WIREGRANT_HOME_5527"));
  h.writeLaw(file, [REGISTRY]);
  let s = await h.start();
  try {
    const field = await h.registerToken(s, file, true);
    assert.equal(await h.ruleAt(s, field, REGISTRY), "egress:secret-bound-trusted");

    h.writeLaw(file, []);
    assert.equal(pollDiskApproving(s.server), true, "the edit was seen");
    assert.equal(await h.ruleAt(s, field, REGISTRY), "egress:secret-bound-trusted", "the grant is the field's own: still released");
    assert.equal(await h.ruleAt(s, field, "evil.example"), "egress:secret-unbound", "and nowhere else");

    await s.close();
    s = await h.start();
    pollDiskApproving(s.server);
    assert.equal(await h.ruleAt(s, field, REGISTRY), "egress:secret-bound-trusted", "after a restart, before any registration");
    // The grant is automatic again: only the Authorization header gets it.
    const body = await s.net.desymbolizationDecision({ symbol: field, boundary: "network", destination: REGISTRY, scheme: "https", positions: ["body"] });
    assert.equal(body.allow, false);
    assert.equal(body.ruleRef?.id, "egress:secret-wire-position");
  } finally {
    await s.close();
    h.cleanup();
  }
});
