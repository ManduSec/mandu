/**
 * home-grant-human-plane — the launch HOME's `.npmrc` earns its wire grant
 * (plan 10 §11.13.1: the token bound to the registry its own key names) only
 * from a registration on the HUMAN plane (confidentiality.md §2.1, "The wire
 * grant is recorded", 2026-10-17), over the REAL components: an ArbiterServer
 * restarted on the same mandu.db, the launcher's production registration
 * call (`socketSecretArbiter(data, { humanSock })`, secret-setup.ts), and the
 * net-proxy's production adapter (`new ArbiterClientAdapter(new
 * ArbiterClient(data), new ArbiterClient(human))`) asking the egress gate as
 * the proxy does for an HTTPS request carrying the placeholder in its
 * Authorization header.
 *
 * Before: `registerSecret` granted on any socket, and the `home` was the
 * caller's word. A process of the agent's world, which reaches the data
 * socket, could plant a `.npmrc` in a directory of its choosing, name that
 * directory as `home`, and earn a recorded, standing release of the file's
 * token at the registry the file names. Now the data socket registers the
 * file with no grant (the `home` still decides the catalog's `~` places, so
 * nothing that worked is refused), and the launcher registers over the human
 * socket.
 *
 * Axes explicit: secrets (confidentiality ON, integrity OFF).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { ArbiterClientAdapter as NetProxyAdapter, type RealArbiterClient as NetProxyRealClient } from "../../interceptors/net-proxy/src/arbiter-client.js";
import { socketSecretArbiter } from "../../launcher/src/secret-setup.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const REGISTRY = "registry.npmjs.org";
const PLANTED = "registry.planted.example";

const npmrc = (host: string, token: string): string => `registry=https://${host}/\n//${host}/:_authToken=${token}\n`;

interface Stack {
  data: ArbiterClient;
  sock: string;
  humanSock: string;
  net: NetProxyAdapter;
  close: () => Promise<void>;
}

function harness() {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-home-grant-"));
  const home = join(tmp, "home"); mkdirSync(home, { recursive: true });
  const ws = join(tmp, "ws"); mkdirSync(ws, { recursive: true });
  const dbPath = join(tmp, "symbols.sqlite");
  const policy = join(tmp, "policy.yaml");
  writeFileSync(policy, "version: 1\n");
  let starts = 0;
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
    const netData = new ArbiterClient(sock); await netData.connect();
    const netHuman = new ArbiterClient(humanSock); await netHuman.connect();
    const net = new NetProxyAdapter(netData as unknown as NetProxyRealClient, netHuman as never);
    return {
      data, sock, humanSock, net,
      close: async () => {
        data.close(); netData.close(); netHuman.close();
        await server.close();
      },
    };
  };
  const ruleAt = async (s: Stack, symbol: string, host: string): Promise<string> => {
    const d = await s.net.desymbolizationDecision({ symbol, boundary: "network", destination: host, scheme: "https", positions: ["authorization"] });
    return d.ruleRef?.id ?? (d.allow ? "allow" : "deny");
  };
  /** The one field placeholder of a registration's twin. */
  const fieldOf = (r: { symbol: string | null; reason: string; twin?: string }): string => {
    assert.equal(typeof r.symbol, "string", r.reason);
    const tokens = (r.twin ?? "").match(/\$MDU:[a-zA-Z_][a-zA-Z0-9_]*\[[0-9a-f]+\]\.[^\s]+/g) ?? [];
    assert.equal(tokens.length, 1, `one field placeholder in the twin: ${r.twin}`);
    return tokens[0]!;
  };
  return { tmp, home, ws, start, ruleAt, fieldOf, cleanup: () => rmSync(tmp, { recursive: true, force: true }) };
}

test("a data-socket registerSecret naming a home of its choosing earns no grant for the .npmrc it planted there; the launcher's human-plane registration does, across a restart", async () => {
  const h = harness();
  const planted = join(h.ws, ".npmrc");
  writeFileSync(planted, npmrc(PLANTED, "npm_PLANTED_HOMEGRANT_3381"));
  const real = join(h.home, ".npmrc");
  writeFileSync(real, npmrc(REGISTRY, "npm_REAL_HOMEGRANT_7720"));
  let s = await h.start();
  try {
    // The agent's world: the data socket, `home` = the directory it planted in.
    const plantedField = h.fieldOf(await s.data.registerSecret({ path: planted, home: h.ws }));
    assert.equal(await h.ruleAt(s, plantedField, PLANTED), "egress:secret-unbound", "no grant: the planted token is held at its registry");

    // Naming the real launch HOME over the data socket earns nothing either.
    const realField = h.fieldOf(await s.data.registerSecret({ path: real, home: h.home }));
    assert.equal(await h.ruleAt(s, realField, REGISTRY), "egress:secret-unbound", "the data socket gives no grant, whatever home it names");

    // The launcher's own registration (production wiring): over the human socket.
    const launcher = socketSecretArbiter(s.sock, { humanSock: s.humanSock });
    const reg = await launcher.registerSecret(real, h.home);
    assert.equal(h.fieldOf(reg), realField, "the same row, reused");
    assert.equal(await h.ruleAt(s, realField, REGISTRY), "egress:secret-bound-trusted", "the HOME grant: released at its registry");
    assert.equal(await h.ruleAt(s, realField, "evil.example"), "egress:secret-unbound");

    // A later data-socket registration of the same file does not take it away.
    await s.data.registerSecret({ path: real, home: h.home });
    assert.equal(await h.ruleAt(s, realField, REGISTRY), "egress:secret-bound-trusted");

    // Across a restart, with no registration.
    await s.close();
    s = await h.start();
    assert.equal(await h.ruleAt(s, realField, REGISTRY), "egress:secret-bound-trusted", "the human-plane grant is recorded");
    assert.equal(await h.ruleAt(s, plantedField, PLANTED), "egress:secret-unbound", "the planted token still has none");
  } finally {
    await s.close();
    h.cleanup();
  }
});
