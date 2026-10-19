/**
 * policy-proposal-routes.test — the rule-change request routes
 * (policy-surface.md §8.4.2, §8.6) over a real DashboardServer with a fake
 * arbiter surface.
 *
 * Pins: the GETs project cards / history rows (the grammar, never the reason
 * as a row); every POST needs the CSRF header AND the admin session (403
 * without either, nothing reaches the arbiter); ids and bodies are validated
 * before the arbiter is called (400); the arbiter's refusals map to 409 with
 * its text, the admin boundary to 503; a re-filed proposal comes back as a
 * card; an arbiter without the ops → 501; no arbiter → 404. Plan 15 §13.7
 * item 4: a prompt exception's pattern is in the GETs only with the CSRF
 * header AND the admin session; any other read gets the row with the
 * pattern hidden and `patternsHidden: true`. Dashboard.md §4.34: a file
 * under the dashboard's home folder reads `~/…` in both GETs' rows.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { homedir } from "node:os";

import { DashboardServer, type PolicyDocArbiter } from "../../../src/server.js";
import { adminUnavailableError } from "../../../src/server/http-util.js";
import { hidePromptPatterns, toChangeRow, toProposalCard, PATTERN_HIDDEN_LET, type PolicyChangeRow, type PolicyProposalRow } from "../../../src/view-model/policy-proposals.js";
import { ADMIN_OPTS, ADMIN_COOKIE } from "../admin-session.js";
import type { EventSource, SessionRef } from "../../../src/event-source.js";
import type { ManduEvent } from "../../../src/event-model.js";

const fakeSource: EventSource = {
  async listSessions(): Promise<SessionRef[]> { return []; },
  async readEvents(): Promise<ManduEvent[]> { return []; },
  subscribe(): () => void { return () => {}; },
  close(): void {},
};
const STATUS = { path: "/p", found: true, valid: true, problems: [], loadedAt: 1, refusedAt: null };
const CSRF_ADMIN = { "X-Mandu-Control": "1", Cookie: ADMIN_COOKIE, "Content-Type": "application/json" };

const PROPOSAL: PolicyProposalRow = {
  id: "pp-000001",
  edits: [{ op: "trust-origin", kind: "url", pattern: "https://pypi.org/" }],
  reason: "<b>please</b>",
  requestedBy: "agent:s1", sessionKey: "s1",
  relaxes: [{ facet: "origins", direction: "relax", subject: "URL:https://pypi.org/", detail: "d" }],
  tightens: [], status: "pending", createdAt: 1, resolvedAt: null, resolvedBy: null, changeId: null, supersededBy: null,
};

type Mode = "ok" | "refiled" | "conflict" | "adopted" | "held" | "stale";

function fake(mode: Mode = "ok", withOps = true) {
  const calls: string[] = [];
  const failIf = (): void => {
    if (mode === "conflict") throw new Error("cannot undo pc-000001: changed again since (paths /x.pem); nothing was changed");
    if (mode === "adopted") throw adminUnavailableError("this dashboard did not start the arbiter (adopted instance)");
    if (mode === "held") throw new Error("policy file /p/policy.yaml holds a change made on disk that waits for a human in Approvals, and this change cannot be made to it as well; nothing was written. Decide that change first, then try again.");
  };
  const arbiter: PolicyDocArbiter = {
    async policyDocument() { return { status: STATUS, inForce: null, onDisk: { text: null, parsed: null, problems: [] } }; },
    async applyPolicyDocument() { return { path: "/p", status: STATUS }; },
    async mintUserRule() { return { id: "r", path: "/p", status: STATUS }; },
    async exportDbLabels() { return { added: 0, path: "/p", status: STATUS }; },
    ...(withOps
      ? {
          async policyProposals(status?: string) { calls.push(`list:${status ?? "all"}`); return { proposals: [PROPOSAL] }; },
          async policyChanges(limit?: number) {
            calls.push(`changes:${limit}`);
            return { changes: [{ id: "pc-000001", via: "agent-tighten" as const, requestedBy: "agent:s1", sessionKey: "s1", edits: [{ op: "lock-path", path: "/x.pem", level: "no-model" }], delta: [], proposalId: null, createdAt: 1, undoneAt: null, undoneBy: null, undoable: true }] };
          },
          async resolvePolicyProposal(id: string, verdict: "approved" | "denied", by?: string) {
            calls.push(`resolve:${id}:${verdict}:${by}`);
            if (mode === "conflict") throw new Error("policy proposal pp-000001 is already approved");
            failIf();
            if (mode === "refiled") return { proposal: { ...PROPOSAL, status: "superseded" as const }, refiled: { ...PROPOSAL, id: "pp-000002" } };
            if (mode === "stale") return { proposal: { ...PROPOSAL, status: "superseded" as const, resolvedBy: "mandu:stale" }, stale: ["models gw"] };
            return { proposal: { ...PROPOSAL, status: verdict }, ...(verdict === "approved" ? { changeId: "pc-000009" } : {}) };
          },
          async undoPolicyChange(id: string, by?: string) { calls.push(`undo:${id}:${by}`); failIf(); return { changeId: "pc-000002", undone: id }; },
        }
      : {}),
  };
  return { arbiter, calls };
}

async function start(arbiter?: PolicyDocArbiter, fileBrowserHome?: string) {
  const server = new DashboardServer({ source: fakeSource, policyDocArbiter: arbiter, log: () => {}, ...ADMIN_OPTS, ...(fileBrowserHome !== undefined ? { fileBrowserHome } : {}) });
  const port = await server.listen(0);
  return { base: `http://127.0.0.1:${port}`, close: () => server.close() };
}

test("GET proposals projects cards (grammar rows, reason apart); GET changes projects history rows", async () => {
  const f = fake();
  const h = await start(f.arbiter);
  try {
    const r = await fetch(`${h.base}/api/policy/proposals?status=pending`);
    assert.equal(r.status, 200);
    const { proposals } = (await r.json()) as { proposals: Array<{ id: string; rows: Array<Array<{ text: string }>>; reason: string; wouldLet: unknown[] }> };
    assert.equal(proposals[0]!.id, "pp-000001");
    assert.match(proposals[0]!.rows[0]!.map((p) => p.text).join(""), /^Trust content from https:\/\/pypi\.org\//);
    assert.equal(proposals[0]!.reason, "<b>please</b>", "the reason travels as data, apart from the rows");
    assert.equal((await fetch(`${h.base}/api/policy/proposals?status=bogus`)).status, 400);
    const c = await fetch(`${h.base}/api/policy/changes?limit=5`);
    const { changes } = (await c.json()) as { changes: Array<{ sentence: string; undoable: boolean }> };
    assert.equal(changes[0]!.sentence, "Your agent tightened your rules");
    assert.equal(changes[0]!.undoable, true);
    assert.equal((await fetch(`${h.base}/api/policy/changes?limit=0`)).status, 400);
    assert.deepEqual(f.calls, ["list:pending", "changes:5"]);
  } finally {
    await h.close();
  }
});

test("POSTs need CSRF + the admin session; ids and bodies are checked before the arbiter", async () => {
  const f = fake();
  const h = await start(f.arbiter);
  try {
    const body = JSON.stringify({ verdict: "approved" });
    assert.equal((await fetch(`${h.base}/api/policy/proposals/pp-000001`, { method: "POST", headers: { Cookie: ADMIN_COOKIE, "Content-Type": "application/json" }, body })).status, 403, "no CSRF header");
    assert.equal((await fetch(`${h.base}/api/policy/proposals/pp-000001`, { method: "POST", headers: { "X-Mandu-Control": "1", "Content-Type": "application/json" }, body })).status, 403, "no admin session");
    assert.equal((await fetch(`${h.base}/api/policy/changes/pc-000001/undo`, { method: "POST", headers: { "X-Mandu-Control": "1" } })).status, 403);
    assert.deepEqual(f.calls, [], "nothing reached the arbiter");
    assert.equal((await fetch(`${h.base}/api/policy/proposals/egr-1`, { method: "POST", headers: CSRF_ADMIN, body })).status, 400);
    assert.equal((await fetch(`${h.base}/api/policy/proposals/pp-000001`, { method: "POST", headers: CSRF_ADMIN, body: JSON.stringify({ verdict: "yes" }) })).status, 400);
    assert.equal((await fetch(`${h.base}/api/policy/changes/pp-000001/undo`, { method: "POST", headers: CSRF_ADMIN, body: "{}" })).status, 400);
    assert.deepEqual(f.calls, []);

    const ok = await fetch(`${h.base}/api/policy/proposals/pp-000001`, { method: "POST", headers: CSRF_ADMIN, body });
    assert.equal(ok.status, 200);
    const res = (await ok.json()) as { proposal: { status: string }; changeId: string };
    assert.equal(res.proposal.status, "approved");
    assert.equal(res.changeId, "pc-000009");
    const undo = await fetch(`${h.base}/api/policy/changes/pc-000001/undo`, { method: "POST", headers: CSRF_ADMIN, body: "{}" });
    assert.deepEqual(await undo.json(), { changeId: "pc-000002", undone: "pc-000001" });
    assert.deepEqual(f.calls, ["resolve:pp-000001:approved:dashboard", "undo:pc-000001:dashboard"]);
  } finally {
    await h.close();
  }
});

test("a re-filed proposal comes back as a card; refusals → 409 with the arbiter's text; adopted → 503", async () => {
  const body = JSON.stringify({ verdict: "approved" });
  let h = await start(fake("refiled").arbiter);
  try {
    const r = (await (await fetch(`${h.base}/api/policy/proposals/pp-000001`, { method: "POST", headers: CSRF_ADMIN, body })).json()) as { proposal: { status: string }; refiled: { id: string; rows: unknown[] } };
    assert.equal(r.proposal.status, "superseded");
    assert.equal(r.refiled.id, "pp-000002");
    assert.equal(r.refiled.rows.length, 1);
  } finally {
    await h.close();
  }
  h = await start(fake("conflict").arbiter);
  try {
    const a = await fetch(`${h.base}/api/policy/proposals/pp-000001`, { method: "POST", headers: CSRF_ADMIN, body });
    assert.equal(a.status, 409);
    assert.match(((await a.json()) as { error: string }).error, /already approved/);
    const u = await fetch(`${h.base}/api/policy/changes/pc-000001/undo`, { method: "POST", headers: CSRF_ADMIN, body: "{}" });
    assert.equal(u.status, 409);
    assert.match(((await u.json()) as { error: string }).error, /changed again since/);
  } finally {
    await h.close();
  }
  // A change that cannot be made to a held hand edit too (tour item 17):
  // a refusal to show on the row, not a server error.
  h = await start(fake("held").arbiter);
  try {
    const u = await fetch(`${h.base}/api/policy/changes/pc-000001/undo`, { method: "POST", headers: CSRF_ADMIN, body: "{}" });
    assert.equal(u.status, 409);
    assert.match(((await u.json()) as { error: string }).error, /waits for a human in Approvals/);
  } finally {
    await h.close();
  }
  h = await start(fake("adopted").arbiter);
  try {
    assert.equal((await fetch(`${h.base}/api/policy/proposals/pp-000001`, { method: "POST", headers: CSRF_ADMIN, body })).status, 503);
  } finally {
    await h.close();
  }
});

test("an arbiter without the ops → 501 on every route; no arbiter → 404", async () => {
  let h = await start(fake("ok", false).arbiter);
  try {
    assert.equal((await fetch(`${h.base}/api/policy/proposals`)).status, 501);
    assert.equal((await fetch(`${h.base}/api/policy/changes`)).status, 501);
    assert.equal((await fetch(`${h.base}/api/policy/proposals/pp-000001`, { method: "POST", headers: CSRF_ADMIN, body: JSON.stringify({ verdict: "denied" }) })).status, 501);
    assert.equal((await fetch(`${h.base}/api/policy/changes/pc-000001/undo`, { method: "POST", headers: CSRF_ADMIN, body: "{}" })).status, 501);
  } finally {
    await h.close();
  }
  h = await start(undefined);
  try {
    assert.equal((await fetch(`${h.base}/api/policy/proposals`)).status, 404);
  } finally {
    await h.close();
  }
});

const WORDS = "*@my-own-private-words.example";
const EXC = { op: "add-prompt-exception", category: "pii.email", match: WORDS };

test("pure: hidePromptPatterns takes out an exception's pattern only, and the rows say it is hidden (plan 15 §13.7 item 4)", () => {
  const lock = { op: "lock-path", path: "/x.pem", level: "no-model" };
  const out = hidePromptPatterns([lock, EXC, { op: "remove-prompt-exception", category: "pii.email", match: WORDS }]);
  assert.equal(out.hidden, true);
  assert.deepEqual(out.edits, [lock, { op: "add-prompt-exception", category: "pii.email" }, { op: "remove-prompt-exception", category: "pii.email" }]);
  assert.equal(EXC.match, WORDS, "the input is not changed");
  assert.equal(hidePromptPatterns([lock]).hidden, false);
  const p: PolicyProposalRow = { ...PROPOSAL, edits: [EXC], relaxes: [{ facet: "prompt-filters", direction: "relax", subject: "prompt exception pii.email", detail: `findings of pii.email matching ${WORDS} are let through` }] };
  const hiddenCard = JSON.stringify(toProposalCard(p, { patterns: false }));
  assert.ok(!hiddenCard.includes("private-words"), hiddenCard);
  assert.ok(hiddenCard.includes(PATTERN_HIDDEN_LET));
  assert.ok(JSON.stringify(toProposalCard(p)).includes(WORDS), "shown by default (an admin's read, a POST's answer)");
  const ch: PolicyChangeRow = { id: "pc-000003", via: "tighten", requestedBy: "human:settings", sessionKey: null, edits: [EXC], delta: [], proposalId: null, createdAt: 1, undoneAt: null, undoneBy: null, undoable: true } as PolicyChangeRow;
  assert.ok(!JSON.stringify(toChangeRow(ch, { patterns: false })).includes("private-words"));
  assert.ok(JSON.stringify(toChangeRow(ch)).includes(WORDS));
});

test("GET proposals and changes: an exception's pattern only with the CSRF header AND the admin session; otherwise hidden and said so (plan 15 §13.7 item 4)", async () => {
  const f = fake();
  const withExc: PolicyDocArbiter = {
    ...f.arbiter,
    async policyProposals() { return { proposals: [{ ...PROPOSAL, edits: [EXC] }] }; },
    async policyChanges() { return { changes: [{ id: "pc-000001", via: "proposal" as const, requestedBy: "human:settings", sessionKey: null, edits: [EXC], delta: [], proposalId: null, createdAt: 1, undoneAt: null, undoneBy: null, undoable: true }] }; },
  };
  const h = await start(withExc);
  try {
    for (const path of ["policy/proposals?status=pending", "policy/changes"]) {
      for (const [what, headers] of [["no headers", {}], ["the CSRF header, no admin session", { "X-Mandu-Control": "1" }], ["the cookie, no CSRF header", { Cookie: ADMIN_COOKIE }]] as const) {
        const r = await fetch(`${h.base}/api/${path}`, { headers });
        assert.equal(r.status, 200, `${path}, ${what}: still listed`);
        const text = await r.text();
        assert.ok(!text.includes("private-words"), `${path}, ${what}: no pattern`);
        assert.equal(JSON.parse(text).patternsHidden, true, `${path}, ${what}: says it hid one`);
      }
      const admin = await fetch(`${h.base}/api/${path}`, { headers: CSRF_ADMIN });
      const text = await admin.text();
      assert.ok(text.includes(WORDS), `${path}: shown to the admin`);
      assert.equal(JSON.parse(text).patternsHidden, undefined);
    }
    // Nothing to hide: no flag either way.
    const plain = await start(fake().arbiter);
    try {
      assert.equal(((await (await fetch(`${plain.base}/api/policy/changes`)).json()) as { patternsHidden?: boolean }).patternsHidden, undefined);
    } finally {
      await plain.close();
    }
  } finally {
    await h.close();
  }
});

test("§4.34 GET proposals and changes name a file under the dashboard's home as ~/…, another account's as recorded; the home is the server's", async () => {
  const at = (home: string): PolicyDocArbiter => ({
    ...fake().arbiter,
    async policyProposals() {
      return { proposals: [{ ...PROPOSAL, edits: [{ op: "lock-path", path: `${home}/proj/.env`, level: "public" }, { op: "unlock-path", path: "/home/someone-else/.env" }],
        relaxes: [{ facet: "paths", direction: "relax", subject: `${home}/proj/.env`, detail: "d" }] }] };
    },
    async policyChanges() {
      return { changes: [
        { id: "pc-000002", via: "agent-tighten" as const, requestedBy: "agent:s1", sessionKey: "s1", edits: [{ op: "lock-path", path: `${home}/proj/a.pem`, level: "no-model" }], delta: [], proposalId: null, createdAt: 2, undoneAt: null, undoneBy: null, undoable: true },
        { id: "pc-000003", via: "undo" as const, requestedBy: "dashboard", sessionKey: null, edits: [], delta: [{ facet: "paths", direction: "relax", subject: `${home}/proj/a.pem`, detail: "d" }], proposalId: null, createdAt: 3, undoneAt: null, undoneBy: null, undoable: false },
      ] };
    },
  });
  type Rows = Array<Array<{ text: string }>>;
  const said = (rows: Rows) => rows.map((r) => r.map((p) => p.text).join(""));
  // The test seam, and a server without one: os.homedir(), as the served
  // page's home-dir (unless this host's home is the root, which is never `~`).
  const own = homedir();
  const homes: Array<[string, string | undefined]> = [["/home/u", "/home/u"], ...(own && own !== "/" ? [[own, undefined] as [string, undefined]] : [])];
  for (const [home, seam] of homes) {
    const h = await start(at(home), seam);
    try {
      const { proposals } = (await (await fetch(`${h.base}/api/policy/proposals?status=pending`)).json()) as { proposals: Array<{ rows: Rows; wouldLet: Rows }> };
      assert.deepEqual(said(proposals[0]!.rows), ["Mark ~/proj/.env not secret", "Remove the rule for /home/someone-else/.env"], home);
      assert.deepEqual(said(proposals[0]!.wouldLet), ["~/proj/.env would be protected less"], home);
      const { changes } = (await (await fetch(`${h.base}/api/policy/changes`)).json()) as { changes: Array<{ rows: Rows }> };
      assert.deepEqual(changes.map((c) => said(c.rows)), [["Make ~/proj/a.pem a secret no AI may read"], ["Loosened: ~/proj/a.pem"]], home);
    } finally {
      await h.close();
    }
  }
  // Another account's home is never `~`.
  const other = await start(at("/home/u"), "/home/v");
  try {
    const { proposals } = (await (await fetch(`${other.base}/api/policy/proposals?status=pending`)).json()) as { proposals: Array<{ rows: Rows }> };
    assert.deepEqual(said(proposals[0]!.rows), ["Mark /home/u/proj/.env not secret", "Remove the rule for /home/someone-else/.env"]);
  } finally {
    await other.close();
  }
});

test("§8.4.6: approving a request built from settings that changed since is a 409 stale, said plainly; nothing reads as approved", async () => {
  const h = await start(fake("stale").arbiter);
  try {
    const r = await fetch(`${h.base}/api/policy/proposals/pp-000001`, { method: "POST", headers: CSRF_ADMIN, body: JSON.stringify({ verdict: "approved" }) });
    assert.equal(r.status, 409);
    const b = (await r.json()) as { error: string; stale: boolean; proposal: { status: string }; changeId?: string };
    assert.equal(b.stale, true);
    assert.match(b.error, /^This change was asked for from settings that have changed since, so nothing was changed/);
    assert.equal(b.proposal.status, "superseded");
    assert.equal(b.changeId, undefined);
  } finally {
    await h.close();
  }
});
