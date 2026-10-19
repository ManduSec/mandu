/**
 * approval-loop.test — the WHOLE dashboard-side approval loop over the real
 * HTTP server + the real arbiter socket-op contract (§4.18: the Simple
 * register's "Waiting for you" inbox posts to these exact routes).
 *
 * Mandu-new test (NO reference origin). Follows arbiter-source-fixtures.ts's
 * harness conventions: a self-contained MOCK arbiter server on a temp Unix
 * socket speaking NDJSON ({id,op,…} → {id,ok,result|error}, one JSON object
 * per "\n"-terminated line — arbiter/ipc/protocol.ts framing), a real
 * DashboardServer on an ephemeral port, driven with `fetch`. The mock speaks
 * EXACTLY the ops the panel + approval routes use, with ONE in-memory
 * approvals table behind all of them so state actually flips:
 *
 *   - `policySnapshot`        req {op:"policySnapshot"} → the extended snapshot
 *                             (posture/usage/verdicts/egressPosture/lawSource —
 *                             verdicts served LIVE from the table), consumed by
 *                             GET /api/policy/panel via ArbiterEventSource.
 *   - `egressApprovals`       req {op:"egressApprovals", status?} →
 *                             {approvals:[…]} (the panel's version-skew
 *                             back-fill + GET /api/egress/approvals).
 *   - `resolveEgressApproval` req {op:"resolveEgressApproval", approvalId,
 *                             approve} → {approval} after the verdict, or
 *                             ok:false "unknown egress-approval id: …". NOTE
 *                             the entry id rides as `approvalId`, never `id`
 *                             (the reserved wire correlation field).
 *   - `hello` + `sessions`    only so GET /api/home composes (test 1b, the
 *                             product page's Details link): hello names this
 *                             same socket as the human plane; no sessions.
 *
 * The POST routes reach the socket through a minimal in-test ApprovalsArbiter
 * adapter speaking those wire ops — the same contract server-main's runtime
 * import of arbiter/ipc/client.ts speaks (this package never imports the
 * arbiter package; CONTRIBUTING.md arbiter-client pattern).
 *
 * What it pins (and the unit tier deliberately does NOT already cover —
 * egress-approvals-routes.test.ts covers the routes over an in-process fake,
 * policy-routes.test.ts the panel's skew fallback over a fake source; NOTHING
 * covered the loop over the real socket ops end-to-end):
 *   1. a pending row surfaces in the served panel VM through the REAL
 *      toPolicyPanelViewModel projection (where/outcome/actions — the §4.18
 *      inbox's row shape);
 *   2. POST approve without X-Mandu-Control → 403 and the resolve op NEVER
 *      reaches the arbiter socket;
 *   3. with the header → 200, the arbiter receives {approvalId, approve:true},
 *      and a FRESH panel GET serves the row approved/allow with the one-click
 *      reversal ("Block instead");
 *   4. the reversal POST …/deny flips it to denied/deny with the
 *      approve-flavored reversal;
 *   5. an unknown id → the route's documented 404 (the arbiter's rejection
 *      surfaced as not-found, error text intact).
 *
 * This pins the DASHBOARD side of the contract; the real-arbiter
 * cross-component version is tests/stack/approval-loop.test.ts
 * (un-deferred 2026-08-06 when the inbox grew its second verb, allow-once —
 * policy-surface.md §9.8.7).
 */

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, connect, type Server } from "node:net";
import { rmSync } from "node:fs";
import { join } from "node:path";
import { JSDOM } from "jsdom";

import {
  DashboardServer,
  type ApprovalsArbiter,
  type ApprovalStatus,
  type EgressApproval,
} from "../../src/server.js";
import { ADMIN_OPTS, ADMIN_COOKIE } from "../unit/admin-session.js";
import { ArbiterEventSource } from "../../src/event-source.js";
import type { PolicySnapshot } from "../../src/policy-model.js";
import type { PolicyPanelVM, QueueRowVM } from "../../src/view-model/policy-panel.js";
import { tmpDir } from "../unit/tmp-dir.js";
import { waitWhile } from "../unit/page-wait.js";
import { pageFetch } from "../unit/page-fetch.js";

// ── The seeded pending entry (what the arbiter's recordPending would queue) ───

const SEED: EgressApproval = {
  id: "egr-1",
  symbol: "$MDU:WebFetch[ab12].body",
  destination: "evil.example.com",
  status: "pending",
  reason: "untrusted symbol egress to an unlisted destination",
  count: 2,
  firstSeen: 1_750_000_000_000,
  lastSeen: 1_750_000_100_000,
  sessions: ["sess-e2e-loop"],
};

// ── Mock arbiter: one NDJSON socket server, one in-memory approvals table ─────

interface MockArbiter {
  socketPath: string;
  /** Every resolveEgressApproval payload the socket served, in order — the
   *  "did the op reach the arbiter at all" oracle (CSRF assertion). `scope`
   *  is recorded only when the wire carried it (so the pre-scope verbs pin
   *  their exact two-field payload). */
  resolveOps: Array<{ approvalId: string; approve: boolean; scope?: string }>;
  close(): Promise<void>;
}

/** The static (non-verdict) half of the snapshot the mock serves — shaped like
 * the real arbiter's `policySnapshot` op result (arbiter/ipc/server.ts): base
 * trust spec + the server-composed standing-state extension. */
function snapshotBase(): Omit<PolicySnapshot, "verdicts"> {
  return {
    specId: "claude-code",
    origins: [{ id: "URL", mode: "allowlist", listSize: 0, defaultTrust: "UNTRUSTED" }],
    tools: {
      WebFetch: {
        tool: "WebFetch",
        inbound: {
          kind: "literal",
          summary: "whole result: UNTRUSTED",
          fields: [{ field: "(result)", trust: "UNTRUSTED", category: null, detail: "UNTRUSTED (literal)" }],
        },
        outbound: { toolResolve: false, destination: "AgentView", summary: "no resolve", fields: [] },
      },
    },
    fallbackTrust: "UNTRUSTED",
    mcpPrefix: "mcp__",
    posture: { integrity: true, confidentiality: false },
    usage: {
      rules: [
        {
          id: "net:untrusted-egress",
          source: "rule",
          boundary: "network",
          outcome: "deny+approval",
          summary: "an untrusted symbol sent to an unlisted destination requires approval",
          gate: "net",
        },
      ],
      sensitivePaths: [],
      gates: [
        {
          id: "net",
          title: "Network egress gate",
          definedIn: "arbiter/policy/usage.ts",
          doc: "docs/design/architecture/mandu.md §4",
          evaluation: "evaluated once per egress attempt, standing verdicts first",
        },
      ],
    },
    egressPosture: "normal",
    lawSource: { kind: "builtin" },
  };
}

function startMockArbiter(seed: EgressApproval[]): Promise<MockArbiter> {
  const dir = tmpDir("mandu-approval-loop-");
  const socketPath = join(dir, "arbiter.sock");
  const table = new Map<string, EgressApproval>(seed.map((e) => [e.id, { ...e }]));
  const resolveOps: MockArbiter["resolveOps"] = [];

  const server: Server = createServer((sock) => {
    sock.setEncoding("utf8");
    let buf = "";
    const writeFrame = (obj: unknown): void => {
      sock.write(JSON.stringify(obj) + "\n");
    };
    sock.on("data", (chunk: string) => {
      buf += chunk;
      let nl: number;
      while ((nl = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        if (line.trim() === "") continue;
        let req: {
          id?: unknown;
          op?: string;
          status?: ApprovalStatus;
          approvalId?: string;
          approve?: boolean;
          scope?: string;
        };
        try {
          req = JSON.parse(line) as typeof req;
        } catch {
          continue;
        }
        if (req.op === "policySnapshot") {
          // Verdicts come LIVE from the table (the real arbiter composes
          // `verdicts: this.egressApprovals.list()` the same way), so a fresh
          // panel GET sees every flip the resolve op applied.
          const verdicts = [...table.values()]
            .map((e) => ({ ...e }))
            .sort((a, b) => b.lastSeen - a.lastSeen);
          writeFrame({ id: req.id, ok: true, result: { ...snapshotBase(), verdicts } });
        } else if (req.op === "egressApprovals") {
          const approvals = [...table.values()]
            .filter((e) => !req.status || e.status === req.status)
            .map((e) => ({ ...e }))
            .sort((a, b) => b.lastSeen - a.lastSeen);
          writeFrame({ id: req.id, ok: true, result: { approvals } });
        } else if (req.op === "resolveEgressApproval") {
          resolveOps.push({
            approvalId: String(req.approvalId),
            approve: req.approve === true,
            ...(typeof req.scope === "string" ? { scope: req.scope } : {}),
          });
          const entry = table.get(String(req.approvalId));
          if (!entry) {
            writeFrame({ id: req.id, ok: false, error: `unknown egress-approval id: ${String(req.approvalId)}` });
          } else {
            // Mirrors the real handler (arbiter/ipc/server.ts): absent or
            // unrecognized scope lands standing; resolve re-arms consumption.
            entry.status = req.approve ? "approved" : "denied";
            entry.scope = req.scope === "once" ? "once" : "always";
            entry.consumedAt = null;
            entry.resolvedAt = Date.now();
            entry.lastSeen = Date.now();
            writeFrame({ id: req.id, ok: true, result: { approval: { ...entry } } });
          }
        } else if (req.op === "hello") {
          // /api/home (the product page's Home, test 1b) lists sessions over
          // the human plane, found through hello: this same socket serves it.
          writeFrame({ id: req.id, ok: true, result: { pid: process.pid, humanSock: socketPath } });
        } else if (req.op === "sessions") {
          // The loop itself needs no sessions.
          writeFrame({ id: req.id, ok: true, result: { sessions: [] } });
        } else {
          writeFrame({ id: req.id, ok: false, error: `unknown op: ${String(req.op)}` });
        }
      }
    });
    sock.on("error", () => {
      /* a client teardown mid-write is expected; ignore */
    });
  });

  return new Promise((resolve) => {
    server.listen(socketPath, () => {
      resolve({
        socketPath,
        resolveOps,
        async close() {
          await new Promise<void>((res) => server.close(() => res()));
          rmSync(dir, { recursive: true, force: true });
        },
      });
    });
  });
}

// ── The in-test ApprovalsArbiter adapter (the wire ops server-main's runtime
//    arbiter/ipc/client.ts import speaks; this package never imports it) ──────

/** One-shot NDJSON request/response over a fresh connection — the same framing
 * ArbiterEventSource.requestOnce uses ({id,…req} in, first matching {id,ok,…}
 * out, reject on ok:false). */
function requestOnce<T>(socketPath: string, req: Record<string, unknown>): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const id = 1;
    const sock = connect(socketPath);
    sock.setEncoding("utf8");
    let buf = "";
    let settled = false;
    const finish = (fn: () => void): void => {
      if (settled) return;
      settled = true;
      sock.removeAllListeners();
      sock.end();
      sock.destroy();
      fn();
    };
    sock.once("connect", () => {
      sock.write(JSON.stringify({ id, ...req }) + "\n");
    });
    sock.on("data", (chunk: string) => {
      buf += chunk;
      let nl: number;
      while ((nl = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        if (line.trim() === "") continue;
        let resp: { id?: unknown; ok?: boolean; result?: unknown; error?: unknown };
        try {
          resp = JSON.parse(line) as typeof resp;
        } catch {
          continue;
        }
        if (resp.id !== id) continue;
        if (resp.ok === false) {
          finish(() => reject(new Error(String(resp.error ?? "arbiter error"))));
          return;
        }
        finish(() => resolve(resp.result as T));
        return;
      }
    });
    sock.on("error", (err: Error) => finish(() => reject(err)));
    sock.on("close", () => finish(() => reject(new Error("arbiter connection closed before reply"))));
  });
}

/** ApprovalsArbiter over the socket: the entry id rides as `approvalId` (never
 * `id` — the reserved correlation field), results unwrap {approvals}/{approval}
 * exactly like the real client. */
function socketApprovalsArbiter(socketPath: string): ApprovalsArbiter {
  return {
    async egressApprovals(status?: ApprovalStatus): Promise<EgressApproval[]> {
      const r = await requestOnce<{ approvals: EgressApproval[] }>(
        socketPath,
        status === undefined ? { op: "egressApprovals" } : { op: "egressApprovals", status },
      );
      return r.approvals;
    },
    async resolveEgressApproval(
      approvalId: string,
      approve: boolean,
      scope?: "once" | "always",
    ): Promise<EgressApproval> {
      const r = await requestOnce<{ approval: EgressApproval }>(socketPath, {
        op: "resolveEgressApproval",
        approvalId,
        approve,
        ...(scope !== undefined ? { scope } : {}),
      });
      return r.approval;
    },
  };
}

// ── Shared fixtures ───────────────────────────────────────────────────────────

let arbiter: MockArbiter;
let server: DashboardServer;
let baseUrl: string;

const CSRF = { "X-Mandu-Control": "1", Cookie: ADMIN_COOKIE };

async function fetchPanel(): Promise<PolicyPanelVM> {
  const res = await pageFetch(`${baseUrl}/api/policy/panel`);
  assert.equal(res.status, 200);
  return ((await res.json()) as { panel: PolicyPanelVM }).panel;
}

before(async () => {
  arbiter = await startMockArbiter([SEED]);
  server = new DashboardServer({
    source: new ArbiterEventSource({ socketPath: arbiter.socketPath }),
    approvalsArbiter: socketApprovalsArbiter(arbiter.socketPath),
    log: () => {},
    ...ADMIN_OPTS,
  });
  const port = await server.listen(0);
  baseUrl = `http://127.0.0.1:${port}`;
});

after(async () => {
  await server.close(); // closes the ArbiterEventSource too (server owns its source)
  await arbiter.close();
});

// ── 1. the pending row surfaces in the served panel VM ────────────────────────

test("GET /api/policy/panel serves the seeded pending row through the real projection", async () => {
  const panel = await fetchPanel();
  assert.equal(panel.available, true);
  assert.equal(panel.extended, true, "the mock ships the standing-state extension");
  assert.equal(panel.verdictsKnown, true);

  assert.equal(panel.queue.length, 1, "exactly the one seeded row");
  const row: QueueRowVM = panel.queue[0]!;
  assert.equal(row.id, SEED.id);
  assert.equal(row.subject, SEED.symbol);
  assert.equal(row.target, SEED.destination);
  assert.equal(row.status, "pending");
  // The §4.18 inbox's row shape: the `where` sentence key, the outcome chip,
  // and the three verdict actions in the product's words and order, Allow
  // once / Always allow / Block (§4.34; the scope discriminant marks the
  // single-use verb, §8.7).
  assert.equal(row.where, "network", "a $… subject projects to the network chokepoint label");
  assert.equal(row.outcome, "pending");
  assert.deepEqual(row.actions, [
    { approve: true, scope: "once", label: "Allow once" },
    { approve: true, label: "Always allow" },
    { approve: false, label: "Block" },
  ]);
  assert.equal(row.resolvedAt, null, "pending rows carry no resolution time");
  assert.equal(row.ruleRefId, null, "a pending row has decided nothing");
  assert.deepEqual(row.sessions, SEED.sessions);
});

// ── 1b. the product page: a Home card's Details opens that question, marked ──
//
// The served index.html + home.js run in jsdom against this server, so the
// id the Details link carries is the one the REAL /api/home projection gave
// (dashboard.md §4.25 "Details"). Read-only: it answers nothing, so the
// seeded row is still pending for the tests below.

test("Home → Details opens the seeded question in Approvals, marked, through the real /api/home", async () => {
  const html = await (await pageFetch(`${baseUrl}/`)).text();
  const js = await (await pageFetch(`${baseUrl}/js/home.js`)).text();
  const dom = new JSDOM(html.replace(/<script type="module"[^>]*><\/script>/, ""), {
    url: `${baseUrl}/`, runScripts: "outside-only", pretendToBeVisual: true,
  });
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const w = dom.window as any;
  w.fetch = (url: string, init?: RequestInit) => pageFetch(new URL(url, baseUrl).href, init);
  w.setInterval = () => 0;
  w.scrollTo = () => {};
  w.eval(js);
  const doc = w.document as Document;
  try {
    await waitWhile(() => !doc.querySelector("#home-waiting .ask-details"));
    const link = doc.querySelector("#home-waiting .ask-details") as HTMLAnchorElement | null;
    assert.ok(link, "the Home card carries a Details link");
    assert.equal(link.getAttribute("href"), `/approvals/${encodeURIComponent(SEED.id)}`);
    // The link is a real page of the server, not only a client route.
    assert.equal((await pageFetch(new URL(link.getAttribute("href")!, baseUrl).href)).status, 200);
    link.click();
    assert.equal((doc.getElementById("page-approvals") as HTMLElement).hidden, false);
    assert.equal(w.location.pathname, `/approvals/${encodeURIComponent(SEED.id)}`);
    const marked = [...doc.querySelectorAll("#page-approvals .focus")].map((x) => (x as HTMLElement).dataset.id);
    assert.deepEqual(marked, [SEED.id], "Approvals marks exactly the seeded question");
    assert.equal((doc.getElementById("approvals-focus-note") as HTMLElement).hidden, true, "it is still waiting: no note");
  } finally {
    w.close();
  }
  assert.equal(arbiter.resolveOps.length, 0, "opening details answered nothing");
});

// ── 2. CSRF: the resolve op must never reach the arbiter socket ───────────────

test("POST approve without X-Mandu-Control → 403 and NO resolve op hits the arbiter", async () => {
  const res = await pageFetch(`${baseUrl}/api/egress/approvals/${SEED.id}/approve`, { method: "POST" });
  assert.equal(res.status, 403);
  assert.match(((await res.json()) as { error: string }).error, /X-Mandu-Control/);

  assert.equal(arbiter.resolveOps.length, 0, "the arbiter socket saw no resolveEgressApproval op");
  const panel = await fetchPanel();
  assert.equal(panel.queue[0]!.status, "pending", "the arbiter-held state is untouched");
});

// ── 3. approve through the arbiter op → the re-served panel shows standing law ─

test("POST approve with the header resolves via the arbiter op; the fresh panel shows approved/allow + reversal", async () => {
  const res = await pageFetch(`${baseUrl}/api/egress/approvals/${SEED.id}/approve`, {
    method: "POST",
    headers: CSRF,
  });
  assert.equal(res.status, 200);
  const { approval } = (await res.json()) as { approval: EgressApproval };
  assert.equal(approval.id, SEED.id);
  assert.equal(approval.status, "approved");

  // The wire fact: exactly one resolve op, id as `approvalId`, approve:true.
  assert.deepEqual(arbiter.resolveOps, [{ approvalId: SEED.id, approve: true }]);

  // A FRESH panel GET (a new policySnapshot op) now serves it as standing law
  // with the one-click reversal — the deny-flavored action.
  const panel = await fetchPanel();
  const row = panel.queue.find((r) => r.id === SEED.id)!;
  assert.equal(row.status, "approved");
  assert.equal(row.outcome, "allow");
  assert.deepEqual(row.actions, [{ approve: false, label: "Block instead" }]);
  assert.equal(typeof row.resolvedAt, "number", "the resolution time is recorded");
  assert.equal(row.ruleRefId, `verdict:${SEED.id}`, "a resolved row carries its trace join key");
});

// ── 4. the reversal: deny flips it back to a standing block ───────────────────

test("POST deny with the header reverses the verdict; the row flips to denied/deny with the approve-flavored reversal", async () => {
  const res = await pageFetch(`${baseUrl}/api/egress/approvals/${SEED.id}/deny`, {
    method: "POST",
    headers: CSRF,
  });
  assert.equal(res.status, 200);
  assert.equal(((await res.json()) as { approval: EgressApproval }).approval.status, "denied");
  assert.deepEqual(arbiter.resolveOps[1], { approvalId: SEED.id, approve: false });

  const panel = await fetchPanel();
  const row = panel.queue.find((r) => r.id === SEED.id)!;
  assert.equal(row.status, "denied");
  assert.equal(row.outcome, "deny");
  assert.deepEqual(row.actions, [{ approve: true, label: "Allow instead" }]);
});

// ── 4b. the third verb: approve-once carries scope on the wire (§8.7) ─────────

test("POST approve-once threads scope=once through the wire; the fresh panel row is once-scoped", async () => {
  const res = await pageFetch(`${baseUrl}/api/egress/approvals/${SEED.id}/approve-once`, {
    method: "POST",
    headers: CSRF,
  });
  assert.equal(res.status, 200);
  const { approval } = (await res.json()) as { approval: EgressApproval };
  assert.equal(approval.status, "approved");
  assert.equal(approval.scope, "once");

  // The wire fact: the resolve op carried the scope field, id as approvalId.
  assert.deepEqual(arbiter.resolveOps[2], { approvalId: SEED.id, approve: true, scope: "once" });

  const panel = await fetchPanel();
  const row = panel.queue.find((r) => r.id === SEED.id)!;
  assert.equal(row.status, "approved");
  assert.equal(row.scope, "once");
  assert.equal(row.consumedAt, null, "resolving arms, not spends");
});

// ── 5. unknown id → the route's documented 404 (arbiter rejection surfaced) ───

test("POST for an unknown id → 404, the arbiter's rejection surfaced as not-found", async () => {
  const res = await pageFetch(`${baseUrl}/api/egress/approvals/egr-nope/approve`, {
    method: "POST",
    headers: CSRF,
  });
  assert.equal(res.status, 404);
  const body = (await res.json()) as { error: string; approvalId: string };
  assert.match(body.error, /unknown egress-approval id: egr-nope/);
  assert.equal(body.approvalId, "egr-nope");
});
