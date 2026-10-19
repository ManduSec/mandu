/**
 * egress-hold-launcher-default e2e — the launcher's default hold reaches the
 * real net-proxy: an interactive session holds a request waiting on a card,
 * a headless one refuses it at once (docs/design/confidentiality/egress-hold.md
 * "The default", 2026-10-17). Mandu-new.
 *
 * The REAL components, no agent: a real ArbiterServer in `secrets` with
 * data, human and admin sockets; the launcher's own decision
 * (`launcherEgressHold`, as run.ts calls it, once for a terminal running
 * `claude` and once for `claude -p` and for a pipe) put on the plan; and, per
 * session, the REAL net-proxy process the way a launch starts it
 * (services/net-proxy.ts `startNetProxy`, real deps). The tracker host is a
 * name a mock-sites host route sends to a recording loopback sink; the
 * human's answer comes through the dashboard's production approvals adapter.
 *
 * Asserted:
 *   I1  interactive (`claude` on a terminal): the POST carrying a secret's
 *       placeholder to a host it is not bound to is HELD (no answer to the
 *       client, nothing on the wire) and files one card;
 *   I2  the human answers Send without it while it waits: the SAME request
 *       reaches the sink with the marker, without the value or the
 *       placeholder;
 *   H1  headless (`claude -p` on a terminal, `claude` on a pipe): the same
 *       POST is refused at once (403, well under a second of hold), nothing
 *       on the wire, the card left waiting for the next try;
 *   E1  an explicit MANDU_EGRESS_HOLD_MS=0 in an interactive session: refused
 *       at once too.
 *   No outcome carries the raw value.
 *
 * Axes explicit: secrets (confidentiality ON, integrity OFF).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { SEND_WITHOUT_MARKER } from "../../interceptors/net-proxy/src/egress.js";
import { startNetProxy } from "../../launcher/src/services/net-proxy.js";
import { realDeps } from "../../launcher/src/services/primitives.js";
import { Layout } from "../../launcher/src/services/layout.js";
import { launcherEgressHold, type EgressHoldChoice } from "../../launcher/src/egress-hold.js";
import type { LaunchPlan } from "../../launcher/src/types.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON: the cards exist only on this axis

const REPO = resolve(fileURLToPath(new URL("../..", import.meta.url)));
const VALUE = "pg-pass-Lq83-launcher-default-hold";
const HOST = "tracker.example.com";

function post(proxyPort: number, url: string, body: string): Promise<{ status: number; body: string }> {
  const u = new URL(url);
  return new Promise((done, reject) => {
    const r = httpRequest(
      { host: "127.0.0.1", port: proxyPort, method: "POST", path: url, headers: { host: u.host, "content-type": "application/json", "content-length": Buffer.byteLength(body) } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => done({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }));
      },
    );
    r.on("error", reject);
    r.end(body);
  });
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

test("a launcher-started interactive session holds a request for its card's answer; a headless one, and an explicit 0, refuse it at once", { timeout: 180_000 }, async () => {
  const tmp = realpathSync(mkdtempSync(join(tmpdir(), "mdu-hold-default-")));
  const received: string[] = [];
  const sink: Server = createServer((req, res) => {
    let b = "";
    req.on("data", (c) => (b += c));
    req.on("end", () => { received.push(b); res.writeHead(201, { "content-type": "application/json" }); res.end("{\"number\":7}"); });
  });
  await new Promise<void>((r) => sink.listen(0, "127.0.0.1", r));
  const routes = join(tmp, "routes.yaml");
  writeFileSync(routes, `hosts:\n  - host: "${HOST}"\n    to: "127.0.0.1:${(sink.address() as AddressInfo).port}"\n`);

  const sock = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanSock = join(tmp, "human", "h.sock");
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const server = new ArbiterServer({
    socketPath: sock, adminSocketPath: adminSock, humanSocketPath: humanSock,
    dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    adminPolicyDir: null, packDir: null,
    confidentiality: true, integrity: false, policyPollMs: 0,
  });
  await server.listen();
  const agent = new ArbiterClient(sock);
  await agent.connect();
  const dash = await makeApprovalsArbiter(sock, () => ({ socketPath: adminSock }));
  assert.ok(dash, "the dashboard's adapter connects");

  const planFor = (scopeId: string, argv: string[], egressHold: EgressHoldChoice): LaunchPlan => ({
    target: "claude", argv, scopeId, tenant: "test", arbiterSock: sock,
    arbiterSockMode: "pinned" as const, arbiterRuntimeBase: tmp, eventDir: join(tmp, "events"), cwd: tmp, humanCwd: tmp,
    noContextProxy: true, fsSync: false, basePath: "/usr/bin",
    proxy: { host: "127.0.0.1", port: 0 }, openaiProxy: { host: "127.0.0.1", port: 0 }, openaiProviderName: "mandu", noProxyExtra: [],
    requested: { netProxy: true, netProxyMitm: false, execWrap: false }, execWrapCmds: [],
    ullm: { mode: "cli" as const, baseUrl: "https://api.anthropic.com", binary: "claude" },
    noScope: true, writeMcp: true, bestEffort: false, replyFilter: false,
    confidentiality: true, effectiveAxes: { confidentiality: true, integrity: false },
    arbiterHumanSock: humanSock, mockSitesPath: routes, egressHold,
  } as unknown as LaunchPlan);

  const saved = { port: process.env["MANDU_NET_PROXY_PORT"], hold: process.env["MANDU_EGRESS_HOLD_MS"] };
  delete process.env["MANDU_NET_PROXY_PORT"]; // port 0: each session its own proxy, as by default
  delete process.env["MANDU_EGRESS_HOLD_MS"];
  const stops: Array<() => void> = [];
  let n = 0;
  /** One session: its own net-proxy, the decision the launcher made for it,
   *  and a placeholder of the session's secret in an issue body. */
  const session = async (argv: string[], decision: EgressHoldChoice) => {
    const scopeId = `hold-default-${++n}`;
    const runDir = join(tmp, scopeId);
    mkdirSync(runDir);
    const r = await startNetProxy(planFor(scopeId, argv, decision), Layout.dev(REPO), runDir, realDeps);
    stops.push(r.stop);
    const value = `${VALUE}-${n}`;
    const symbol = await agent.symbolize({ tool: "Read", field: "content", value, confidentiality: "secret", sessionKey: scopeId });
    const issue = JSON.stringify({ title: "inventory-api does not start", body: `could not connect: postgres://inventory:${symbol}@db.inventory.test:5432/inventory` });
    return { port: r.netProxy.port, value, symbol, issue, url: `http://${HOST}/api/issues` };
  };
  const cardFor = async (symbol: string) => {
    for (let i = 0; i < 150; i++) {
      const card = (await dash!.arbiter.egressApprovals("pending")).find((a) => a.symbol === symbol);
      if (card) return card;
      await sleep(20);
    }
    throw new Error(`no card for ${symbol}`);
  };
  /** Refused at once: 403, quickly, nothing new on the wire, the card waiting. */
  const refusedAtOnce = async (s: Awaited<ReturnType<typeof session>>, label: string) => {
    const before = received.length;
    const t0 = Date.now();
    const r = await post(s.port, s.url, s.issue);
    const took = Date.now() - t0;
    assert.equal(r.status, 403, `${label}: ${r.body}`);
    assert.ok(took < 3_000, `${label}: refused at once, not held (${took} ms)`);
    assert.ok(!r.body.includes(s.value), `${label}: the refusal never names the value`);
    assert.equal(received.length, before, `${label}: nothing on the wire`);
    assert.equal((await cardFor(s.symbol)).status, "pending", `${label}: the card waits for the next try`);
  };

  try {
    // I1/I2: `mandu claude` on a terminal.
    const interactive = launcherEgressHold({ env: {}, argv: ["claude"], stdoutIsTTY: true });
    assert.equal(interactive.ms, "60000", "the launcher's interactive default");
    const i = await session(["claude"], interactive);
    let settled = false;
    const sending = post(i.port, i.url, i.issue).finally(() => { settled = true; });
    const card = await cardFor(i.symbol);
    assert.equal(card.stripOffered, true, "the card takes Send without it");
    await sleep(1_000);
    assert.equal(settled, false, "interactive: the client is still waiting");
    assert.equal(received.length, 0, "nothing on the wire while held");
    await dash!.arbiter.resolveEgressApproval(card.id, false, "once", { strip: true });
    const sent = await sending;
    assert.equal(sent.status, 201, sent.body);
    assert.equal(received.length, 1, "the held request itself went out, once");
    assert.ok(!received[0]!.includes(i.value) && !received[0]!.includes("$MDU:"), "neither the value nor the placeholder on the wire");
    assert.ok(received[0]!.includes(SEND_WITHOUT_MARKER), "the marker where the secret was");

    // H1: `mandu claude -p` on a terminal, and `mandu claude` on a pipe.
    const print = launcherEgressHold({ env: {}, argv: ["claude", "-p", "open the issue"], stdoutIsTTY: true });
    assert.equal(print.ms, "0");
    await refusedAtOnce(await session(["claude", "-p", "open the issue"], print), "claude -p");
    const piped = launcherEgressHold({ env: {}, argv: ["claude"], stdoutIsTTY: false });
    assert.equal(piped.ms, "0");
    await refusedAtOnce(await session(["claude"], piped), "a pipe");

    // E1: the user's 0 over the interactive default.
    const zero = launcherEgressHold({ env: { MANDU_EGRESS_HOLD_MS: "0" }, argv: ["claude"], stdoutIsTTY: true });
    assert.equal(zero.source, "explicit");
    await refusedAtOnce(await session(["claude"], zero), "MANDU_EGRESS_HOLD_MS=0");
  } finally {
    for (const stop of stops) stop();
    agent.close();
    dash!.close();
    await server.close();
    sink.close();
    for (const [k, v] of [["MANDU_NET_PROXY_PORT", saved.port], ["MANDU_EGRESS_HOLD_MS", saved.hold]] as const) {
      if (v === undefined) delete process.env[k]; else process.env[k] = v;
    }
    rmSync(tmp, { recursive: true, force: true });
  }
});
