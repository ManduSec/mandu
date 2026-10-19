/**
 * rule-actions.test — the Rules page's row buttons (dashboard.md §4.25c).
 *
 * Pins:
 *   - planRuleAction turns a row id + action into the edit, read against the
 *     RAW document in force; a row with no edit op, a trusted source reached
 *     through a named list, and a rule that is gone are refused with words
 *     the page can show, never answered "done" for a no-op;
 *   - the projection's buttons (ruleRowActions) match what can be planned;
 *   - POST /api/policy/rules/change: a tightening applies at once; a
 *     loosening first answers `confirm` with the loosenings, and applies only
 *     when they come back as `expected` (the shared human-apply sequence,
 *     approved as human:rules-page); CSRF + admin session required;
 *     Allow / Block on a rule of your own names the rule at the version the
 *     read found (`basedOn`, policy-surface.md §8.4.6 "An item-level
 *     version"), and the arbiter's stale refusal is a 409 `stale`;
 *   - POST /api/egress/approvals/<id>/forget: forwarded, 409 while pending,
 *     404 unknown, 501 on an arbiter without the op;
 *   - History says the person changed a rule on the Rules page.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { DashboardServer, type PolicyDocArbiter } from "../../src/server.js";
import { planRuleAction } from "../../src/rule-actions.js";
import { ruleRowActions } from "../../src/view-model/policy-panel.js";
import { toChangeRow } from "../../src/view-model/policy-proposals.js";
import { relaxKey, type PreviewResult } from "../../src/policy-assistant.js";
import type { ApprovalsArbiter, EgressApproval } from "../../src/server/approval-routes.js";
import { ADMIN_OPTS, ADMIN_COOKIE } from "./admin-session.js";
import type { EventSource, SessionRef } from "../../src/event-source.js";
import type { ManduEvent } from "../../src/event-model.js";

const DOC = {
  version: 1,
  lists: { svc: ["api.svc.example"] },
  paths: [{ path: "~/work/.env", level: "no-model" }, { path: "**/ws-*/memo/**", level: "any-model" }],
  inbound: { url: { default: "UNTRUSTED", trustedList: ["pypi.org", "@svc"] } },
  user_rules: [
    { id: "r-0001", kind: "release", from: { host: "github.com" }, to: { host: "api.example.com" }, mode: "allow", expires: "2027-01-01T00:00:00.000Z" },
    { id: "r-0002", kind: "release", to: { host: "pastebin.com" }, mode: "block" },
  ],
  destinations: [{ host: "Registry.Example", connect: "allow" }, { host: "@svc", port: 8443, connect: "allow" }],
  rules: { "net.untrusted-destination": { mode: "block" } },
};

test("planRuleAction: one edit per row kind, read from the raw document", () => {
  const ok = (id: string, action: "remove" | "allow" | "block" = "remove") => {
    const p = planRuleAction(DOC, id, action);
    assert.ok(p.ok, `${id}: ${JSON.stringify(p)}`);
    return p.edits;
  };
  assert.deepEqual(ok("lock:/home/u/work/.env"), [{ op: "unlock-path", path: "/home/u/work/.env" }]);
  assert.deepEqual(ok("lock:**/ws-*/memo/**"), [{ op: "unlock-path", path: "**/ws-*/memo/**" }]);
  assert.deepEqual(ok("trusted-origin:url:pypi.org"), [{ op: "distrust-origin", kind: "url", pattern: "pypi.org" }]);
  assert.deepEqual(ok("r-0001"), [{ op: "retire-rule", id: "r-0001" }]);
  assert.deepEqual(ok("r-0001", "block"), [{ op: "release", id: "r-0001", to: { host: "api.example.com" }, mode: "block", from: { host: "github.com" }, expires: "2027-01-01T00:00:00.000Z" }], "a flip keeps the rule's id, ends and expiry");
  assert.deepEqual(ok("r-0002", "allow"), [{ op: "release", id: "r-0002", to: { host: "pastebin.com" }, mode: "allow" }]);
  assert.deepEqual(ok("connect:tcp:registry.example:443"), [{ op: "remove-connect", host: "Registry.Example" }], "the compiled id (lower case, default port) finds the raw entry");
  assert.deepEqual(ok("disposition:net.untrusted-destination"), [{ op: "set-disposition", rule: "net.untrusted-destination", mode: "ask" }]);
});

test("planRuleAction: refusals say why, and never plan a no-op", () => {
  const no = (id: string, action: "remove" | "allow" | "block" = "remove") => {
    const p = planRuleAction(DOC, id, action);
    assert.equal(p.ok, false, id);
    return p as { status: number; error: string };
  };
  assert.match(no("app:psql").error, /rules file/);
  assert.match(no("trusted-origin:url:api.svc.example").error, /named list/, "a list member cannot be removed by a pattern edit");
  assert.match(no("connect:tcp:api.svc.example:8443").error, /named list/);
  assert.match(no("r-9999").error, /no longer in your rules/);
  assert.match(no("disposition:other.rule").error, /no longer in your rules/);
  assert.match(no("r-0001", "allow").error, /already says allow/);
  assert.equal(no("lock:/x", "allow").status, 400, "a lock has no flip");
  assert.equal(no("", "remove").status, 400);
  assert.equal(no("r-0001", "explode" as "remove").status, 400);
  assert.equal(planRuleAction(null, "r-0001", "remove").ok, false, "no document ⇒ no rule");
});

test("ruleRowActions: Remove everywhere an edit exists; a flip only on allow/block send rules", () => {
  assert.deepEqual(ruleRowActions({ id: "lock:/x", kind: "lock" }), { remove: true, flip: null });
  assert.deepEqual(ruleRowActions({ id: "app:psql", kind: "lock" }), { remove: false, flip: null });
  assert.deepEqual(ruleRowActions({ id: "r-1", kind: "release-allow" }), { remove: true, flip: "block" });
  assert.deepEqual(ruleRowActions({ id: "r-2", kind: "release-block" }), { remove: true, flip: "allow" });
  assert.deepEqual(ruleRowActions({ id: "r-3", kind: "release-audit" }), { remove: true, flip: null });
  assert.deepEqual(ruleRowActions({ id: "trusted-origin:url:a", kind: "trusted-origin" }), { remove: true, flip: null });
  assert.deepEqual(ruleRowActions({ id: "connect:tcp:a:443", kind: "connect-allow" }), { remove: true, flip: null });
  assert.deepEqual(ruleRowActions({ id: "disposition:x", kind: "disposition" }), { remove: true, flip: null });
});

test("History: a change made on the Rules page reads as the person's", () => {
  const base = { id: "pc-000009", via: "proposal" as const, sessionKey: null, edits: [{ op: "retire-rule", id: "r-0001" }], delta: [], proposalId: "pp-000009", createdAt: 1, undoneAt: null, undoneBy: null, undoable: true };
  assert.equal(toChangeRow({ ...base, requestedBy: "human:rules-page" }).sentence, "You changed a rule on the Rules page");
  // Describe a rule approves as `human:dashboard`: yours, not the agent's (§4.25i).
  assert.equal(toChangeRow({ ...base, requestedBy: "human:dashboard" }).sentence, "You changed your rules with Describe a rule");
  assert.equal(toChangeRow({ ...base, requestedBy: "dashboard" }).sentence, "You approved a change your agent asked for");
});

// ── the routes ───────────────────────────────────────────────────────────────

const fakeSource: EventSource = {
  async listSessions(): Promise<SessionRef[]> { return []; },
  async readEvents(): Promise<ManduEvent[]> { return []; },
  subscribe(): () => void { return () => {}; },
  close(): void {},
};
const STATUS = { path: "/p", found: true, valid: true, problems: [], loadedAt: 1, refusedAt: null };
const CSRF_ADMIN = { "X-Mandu-Control": "1", Cookie: ADMIN_COOKIE, "Content-Type": "application/json" };
const LOOSE = { facet: "paths", direction: "relax" as const, subject: "/home/u/work/.env", detail: "d" };

function fakeDoc(preview: PreviewResult, propose: "applied" | "filed" = "filed") {
  const calls: string[] = [];
  const arbiter: PolicyDocArbiter = {
    async policyDocument() { calls.push("document"); return { status: STATUS, inForce: DOC, onDisk: { text: null, parsed: null, problems: [] } }; },
    async applyPolicyDocument() { return { path: "/p", status: STATUS }; },
    async mintUserRule() { return { id: "r", path: "/p", status: STATUS }; },
    async exportDbLabels() { return { added: 0, path: "/p", status: STATUS }; },
    async policyPreview(edits) { calls.push(`preview:${JSON.stringify(edits)}`); return preview; },
    async policyPropose(r) {
      calls.push(`propose:${r.requestedBy}`);
      return propose === "applied" ? { applied: true, changeId: "pc-000001" } : { applied: false, proposalId: "pp-000001", relaxes: preview.ok ? preview.relaxations : [] };
    },
    async resolvePolicyProposal(id, verdict, by) {
      calls.push(`resolve:${id}:${verdict}:${by}`);
      const p = { id, edits: [], reason: null, requestedBy: "rules-page", sessionKey: null, relaxes: [], tightens: [], status: verdict, createdAt: 1, resolvedAt: 2, resolvedBy: by ?? null, changeId: "pc-000002", supersededBy: null };
      return { proposal: p, ...(verdict === "approved" ? { changeId: "pc-000002" } : {}) };
    },
  };
  return { arbiter, calls };
}

async function start(opts: { policyDocArbiter?: PolicyDocArbiter; approvalsArbiter?: ApprovalsArbiter }) {
  const server = new DashboardServer({ source: fakeSource, ...opts, log: () => {}, ...ADMIN_OPTS });
  const port = await server.listen(0);
  return { base: `http://127.0.0.1:${port}`, close: () => server.close() };
}
const post = async (base: string, path: string, body?: unknown, headers: Record<string, string> = CSRF_ADMIN) => {
  const r = await fetch(base + path, { method: "POST", headers, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
  return { status: r.status, body: (await r.json()) as Record<string, unknown> };
};

test("rules/change: a tightening applies at once as the person's change", async () => {
  const { arbiter, calls } = fakeDoc({ ok: true, relaxations: [], tightenings: [], perEdit: [] }, "applied");
  const srv = await start({ policyDocArbiter: arbiter });
  try {
    const r = await post(srv.base, "/api/policy/rules/change", { id: "r-0001", action: "remove" });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.deepEqual(r.body, { applied: true, changeId: "pc-000001" });
    assert.deepEqual(calls, ["document", `preview:${JSON.stringify([{ op: "retire-rule", id: "r-0001" }])}`, `preview:${JSON.stringify([{ op: "retire-rule", id: "r-0001" }])}`, "propose:rules-page"]);
  } finally {
    await srv.close();
  }
});

test("rules/change: a loosening asks first, applies only with what was shown, approved as human:rules-page", async () => {
  const { arbiter, calls } = fakeDoc({ ok: true, relaxations: [LOOSE], tightenings: [], perEdit: [] });
  const srv = await start({ policyDocArbiter: arbiter });
  try {
    const first = await post(srv.base, "/api/policy/rules/change", { id: "lock:/home/u/work/.env", action: "remove" });
    assert.equal(first.status, 200);
    assert.deepEqual(first.body, { applied: false, confirm: true, expected: [relaxKey(LOOSE)] });
    assert.ok(!calls.some((c) => c.startsWith("propose")), "nothing is proposed before the person confirms");

    const wrong = await post(srv.base, "/api/policy/rules/change", { id: "lock:/home/u/work/.env", action: "remove", expected: [] });
    assert.equal(wrong.status, 409, "a loosening not in expected is refused");
    assert.match(String(wrong.body.error), /Nothing was changed/);

    calls.length = 0;
    const second = await post(srv.base, "/api/policy/rules/change", { id: "lock:/home/u/work/.env", action: "remove", expected: first.body.expected });
    assert.equal(second.status, 200, JSON.stringify(second.body));
    assert.deepEqual(second.body, { applied: true, changeId: "pc-000002" });
    assert.ok(calls.includes("propose:rules-page"));
    assert.ok(calls.includes("resolve:pp-000001:approved:human:rules-page"));
  } finally {
    await srv.close();
  }
});

test("rules/change: refusals — an unplannable row, a gone rule, bad input, and the CSRF + admin gate", async () => {
  const { arbiter, calls } = fakeDoc({ ok: false, problems: ["edits[0] (unlock-path): no lock on /home/u/gone"] });
  const srv = await start({ policyDocArbiter: arbiter });
  try {
    const app = await post(srv.base, "/api/policy/rules/change", { id: "app:psql", action: "remove" });
    assert.equal(app.status, 409);
    assert.match(String(app.body.error), /rules file/);
    const gone = await post(srv.base, "/api/policy/rules/change", { id: "lock:/home/u/gone", action: "remove" });
    assert.equal(gone.status, 409);
    assert.match(String(gone.body.error), /no longer in your rules/);
    assert.equal((await post(srv.base, "/api/policy/rules/change", { id: "r-0001", action: "remove", expected: "x" })).status, 400);
    assert.equal((await post(srv.base, "/api/policy/rules/change", { id: "r-0001", action: "remove" }, { "Content-Type": "application/json" })).status, 403, "no CSRF header, no session");
    assert.ok(!calls.some((c) => c.startsWith("propose")));
  } finally {
    await srv.close();
  }
});

test("approvals/<id>/forget: forwarded; pending 409, unknown 404, no op 501, CSRF required", async () => {
  const seen: string[] = [];
  const entry: EgressApproval = { id: "egr-3", symbol: "$MDU:x", destination: "paste.example", status: "approved", reason: "r", count: 1, firstSeen: 1, lastSeen: 2 };
  const approvals: ApprovalsArbiter = {
    async egressApprovals() { return []; },
    async resolveEgressApproval() { return entry; },
    async forgetEgressApproval(id) {
      seen.push(id);
      if (id === "egr-3") return entry;
      if (id === "egr-4") throw new Error("egress-approval egr-4 is still waiting for an answer");
      throw new Error(`unknown egress-approval id: ${id}`);
    },
  };
  const srv = await start({ approvalsArbiter: approvals });
  try {
    const ok = await post(srv.base, "/api/egress/approvals/egr-3/forget");
    assert.equal(ok.status, 200);
    assert.equal((ok.body.approval as EgressApproval).id, "egr-3");
    assert.equal((await post(srv.base, "/api/egress/approvals/egr-4/forget")).status, 409);
    assert.equal((await post(srv.base, "/api/egress/approvals/egr-5/forget")).status, 404);
    assert.equal((await post(srv.base, "/api/egress/approvals/egr-3/forget", undefined, {})).status, 403);
    assert.deepEqual(seen, ["egr-3", "egr-4", "egr-5"]);
  } finally {
    await srv.close();
  }
  const old = await start({ approvalsArbiter: { async egressApprovals() { return []; }, async resolveEgressApproval() { return entry; } } });
  try {
    assert.equal((await post(old.base, "/api/egress/approvals/egr-3/forget")).status, 501);
  } finally {
    await old.close();
  }
});

// ── GET /api/policy/rules/origins (dashboard.md §4.25i) ──────────────────────

test("rules/origins: who put each row there; complete only when every change names its rows; 501 on an arbiter without the record", async () => {
  const { arbiter } = fakeDoc({ ok: true, relaxations: [], tightenings: [], perEdit: [] });
  const changes = [
    { id: "pc-000002", via: "proposal" as const, requestedBy: "dashboard", proposedBy: "agent:sess-9", sessionKey: "sess-9", edits: [], delta: [], proposalId: "pp-000001",
      createdAt: 20, undoneAt: null, undoneBy: null, undoable: true, rules: [{ rowIds: ["r-0001"], added: true, removed: false, current: true }] },
  ];
  const srv = await start({ policyDocArbiter: { ...arbiter, async policyChanges(limit) { assert.equal(limit, 500); return { changes }; } } });
  try {
    const r = await fetch(`${srv.base}/api/policy/rules/origins`);
    assert.equal(r.status, 200);
    const body = (await r.json()) as { origins: Record<string, { sentence: string; session: string | null }>; complete: boolean; unrecorded: { recorded: boolean } };
    assert.equal(body.origins["r-0001"]!.sentence, "Your agent asked for this and you approved it");
    assert.equal(body.origins["r-0001"]!.session, "sess-9");
    assert.equal(body.complete, true);
    assert.equal(body.unrecorded.recorded, false);
  } finally {
    await srv.close();
  }
  // An arbiter predating the `rules` field: nothing may be called "no record".
  const old = await start({ policyDocArbiter: { ...arbiter, async policyChanges() { return { changes: changes.map(({ rules: _r, proposedBy: _p, ...c }) => c) }; } } });
  try {
    const body = (await (await fetch(`${old.base}/api/policy/rules/origins`)).json()) as { origins: object; complete: boolean };
    assert.deepEqual(body.origins, {});
    assert.equal(body.complete, false);
  } finally {
    await old.close();
  }
  const none = await start({ policyDocArbiter: arbiter });
  try {
    assert.equal((await fetch(`${none.base}/api/policy/rules/origins`)).status, 501);
  } finally {
    await none.close();
  }
});

test("rules/change: Allow / Block rewrites the rule whole, so it names the rule's version; a stale refusal is a 409", async () => {
  const V = "d".repeat(32);
  const seen: unknown[] = [];
  const make = (stale: boolean): PolicyDocArbiter => ({
    ...fakeDoc({ ok: true, relaxations: [], tightenings: [], perEdit: [] }, "applied").arbiter,
    async policyDocument() { return { status: STATUS, inForce: DOC, onDisk: { text: null, parsed: null, problems: [] }, itemVersions: { user_rules: { "r-0001": V } } }; },
    async policyPropose(r) {
      seen.push(r.basedOn);
      return stale ? { applied: false, refused: "stale", changed: ["user_rules r-0001"], problems: ["changed"] } : { applied: true, changeId: "pc-000001" };
    },
  });
  for (const stale of [false, true]) {
    const srv = await start({ policyDocArbiter: make(stale) });
    try {
      const r = await post(srv.base, "/api/policy/rules/change", { id: "r-0001", action: "block" });
      if (!stale) assert.equal(r.status, 200, JSON.stringify(r.body));
      else {
        assert.equal(r.status, 409);
        assert.equal(r.body.stale, true);
        assert.match(String(r.body.error), /changed somewhere else just now, so nothing was changed/);
      }
    } finally {
      await srv.close();
    }
  }
  assert.deepEqual(seen, [[{ section: "user_rules", key: "r-0001", version: V }], [{ section: "user_rules", key: "r-0001", version: V }]]);
  // A retire carries nothing over, so it names nothing.
  seen.length = 0;
  const srv = await start({ policyDocArbiter: make(false) });
  try {
    assert.equal((await post(srv.base, "/api/policy/rules/change", { id: "r-0001", action: "remove" })).status, 200);
    assert.deepEqual(seen, [undefined]);
  } finally {
    await srv.close();
  }
});
