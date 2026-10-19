/**
 * always-source-route.test — `POST /api/egress/approvals/<id>/always-source`
 * (confidentiality plan 13 §5.4, §9 R2; dashboard.md §4.34 "A send names
 * every file"): one *Always* of a program's send applies the arbiter's edit
 * for that one file as the person's own loosening (preview → propose →
 * approve, the Rules page's path), and refuses fail-closed: no op (501), no
 * file named (400), the arbiter's refusal (422 / 409), a preview that would
 * loosen anything but that file's rule (409, nothing proposed). After it,
 * the queue says whether the question is gone or which files are left.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { Readable } from "node:stream";
import type { IncomingMessage, ServerResponse } from "node:http";

import { ALWAYS_STALE, alwaysSource, type ApprovalsArbiter, type EgressApproval } from "../../../src/server/approval-routes.js";
import type { PolicyAssistantArbiter } from "../../../src/server/policy-assistant-routes.js";

const ENV = "/home/u/ws/app/.env";
const CSV = "/home/u/data/customers.csv";

function req(body: unknown): IncomingMessage {
  return Readable.from([Buffer.from(body === undefined ? "" : JSON.stringify(body))]) as unknown as IncomingMessage;
}
function res(): ServerResponse & { status: number; body: Record<string, unknown> } {
  const r = { status: 0, body: {} as Record<string, unknown> } as ServerResponse & { status: number; body: Record<string, unknown> };
  (r as unknown as { writeHead: (s: number) => void }).writeHead = (s: number) => { r.status = s; };
  (r as unknown as { end: (b: string) => void }).end = (b: string) => { r.body = JSON.parse(b) as Record<string, unknown>; };
  return r;
}

const pending = (left: string[]): EgressApproval => ({
  id: "egr-7", symbol: "holder-send:{}", destination: "hooks.slack.com", status: "pending", reason: "", count: 1, firstSeen: 1, lastSeen: 1,
  holderSources: [ENV, CSV].map((p) => ({ path: p, level: "no-model", bindings: [], blocks: left.includes(p), always: left.includes(p) })),
});

function fakes(opts: { relaxes?: Array<{ facet: string; subject: string }>; refuse?: string; after?: EgressApproval[] } = {}) {
  const log: string[] = [];
  const edits = [{ op: "lock-path", path: ENV, level: "no-model", bindings: ["hooks.slack.com"] }];
  const approvals: ApprovalsArbiter = {
    egressApprovals: async () => opts.after ?? [],
    resolveEgressApproval: async () => { throw new Error("never a verdict on the row"); },
    holderSourceBinding: async (id, path) => {
      log.push(`bind ${id} ${path}`);
      if (opts.refuse) throw new Error(opts.refuse);
      return { edits, rule: path, relaxes: [{ facet: "paths", subject: path }] };
    },
  };
  const policy: PolicyAssistantArbiter = {
    policyPreview: async (e: unknown) => { log.push(`preview ${JSON.stringify(e)}`); return { ok: true, relaxations: opts.relaxes ?? [{ facet: "paths", subject: ENV }], tightenings: [], perEdit: [{ loosens: true }] }; },
    policyPropose: async () => { log.push("propose"); return { applied: false, proposalId: "pp-1", relaxes: opts.relaxes ?? [{ facet: "paths", subject: ENV }], why: "relaxes" }; },
    resolvePolicyProposal: async (id: string, verdict: string, by: string) => { log.push(`resolve ${id} ${verdict} ${by}`); return { proposal: { id } as never, changeId: "chg-1" }; },
  } as unknown as PolicyAssistantArbiter;
  return { approvals, policy, log, edits };
}

test("one file's Always: previewed, proposed and approved as the person's loosening; the files left are named", async () => {
  const f = fakes({ after: [pending([CSV])] });
  const r = res();
  await alwaysSource(f.approvals, f.policy, "egr-7", req({ path: ENV }), r);
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.deepEqual(r.body, { applied: true, changeId: "chg-1", rule: ENV, released: false, left: [CSV] });
  assert.deepEqual(f.log, [`bind egr-7 ${ENV}`, `preview ${JSON.stringify(f.edits)}`, "propose", "resolve pp-1 approved human:dashboard"]);
});

test("the last file's Always: the question is gone, so the next send goes", async () => {
  const f = fakes({ after: [] });
  const r = res();
  await alwaysSource(f.approvals, f.policy, "egr-7", req({ path: ENV }), r);
  assert.equal(r.body.released, true);
  assert.deepEqual(r.body.left, []);
});

test("fail-closed: a preview that would loosen any other rule is refused and nothing is proposed", async () => {
  const f = fakes({ relaxes: [{ facet: "paths", subject: ENV }, { facet: "paths", subject: "/home/u/ws/app" }] });
  const r = res();
  await alwaysSource(f.approvals, f.policy, "egr-7", req({ path: ENV }), r);
  assert.equal(r.status, 409);
  assert.ok(!f.log.includes("propose"), f.log.join(" | "));
});

test("refusals: no op (501), no file (400), the arbiter's reason (422; already bound or retired: 409)", async () => {
  const none = res();
  await alwaysSource({ egressApprovals: async () => [], resolveEgressApproval: async () => { throw new Error("x"); } }, fakes().policy, "egr-7", req({ path: ENV }), none);
  assert.equal(none.status, 501);
  const noPath = res();
  await alwaysSource(fakes().approvals, fakes().policy, "egr-7", req({}), noPath);
  assert.equal(noPath.status, 400);
  const folder = res();
  const ff = fakes({ refuse: `${ENV} takes no Always from here (folder-rule): change it under Rules` });
  await alwaysSource(ff.approvals, ff.policy, "egr-7", req({ path: ENV }), folder);
  assert.equal(folder.status, 422);
  assert.match(String(folder.body.error), /folder-rule/);
  assert.ok(!ff.log.includes("propose"));
  const bound = res();
  await alwaysSource(fakes({ refuse: `${ENV} may already go to hooks.slack.com` }).approvals, fakes().policy, "egr-7", req({ path: ENV }), bound);
  assert.equal(bound.status, 409);
});

// ── the plan names the rules it read (policy-surface.md §8.4.6) ──────────

test("the arbiter's plan names the rules it read: they go with the proposal, and a rule changed in between is refused 409 stale, nothing approved", async () => {
  const V = "a".repeat(32);
  const basedOn = [{ section: "paths", key: ENV, version: V }];
  const sent: unknown[] = [];
  for (const stale of [false, true]) {
    const f = fakes({ after: [] });
    f.approvals.holderSourceBinding = async (_id, path) => ({ edits: f.edits, rule: path, relaxes: [{ facet: "paths", subject: path }], basedOn });
    (f.policy as unknown as { policyPropose: (r: unknown) => Promise<unknown> }).policyPropose = async (r: unknown) => {
      sent.push(r);
      f.log.push("propose");
      return stale
        ? { applied: false, refused: "stale", changed: [`paths ${ENV}`], problems: ["changed since it was read"] }
        : { applied: false, proposalId: "pp-1", relaxes: [{ facet: "paths", subject: ENV }], why: "relaxes" };
    };
    const r = res();
    await alwaysSource(f.approvals, f.policy, "egr-7", req({ path: ENV }), r);
    assert.deepEqual((sent.at(-1) as { basedOn?: unknown }).basedOn, basedOn, "the versions the plan was made from");
    if (!stale) {
      assert.equal(r.status, 200, JSON.stringify(r.body));
      continue;
    }
    assert.equal(r.status, 409);
    assert.equal(r.body.stale, true);
    assert.deepEqual(r.body.changed, [`paths ${ENV}`]);
    assert.equal(r.body.error, ALWAYS_STALE);
    assert.ok(!f.log.some((l) => l.startsWith("resolve")), "nothing approved");
  }
});

test("an older arbiter's plan names no rule: the proposal carries none", async () => {
  const sent: unknown[] = [];
  const f = fakes({ after: [] });
  (f.policy as unknown as { policyPropose: (r: unknown) => Promise<unknown> }).policyPropose = async (r: unknown) => {
    sent.push(r);
    return { applied: false, proposalId: "pp-1", relaxes: [{ facet: "paths", subject: ENV }], why: "relaxes" };
  };
  const r = res();
  await alwaysSource(f.approvals, f.policy, "egr-7", req({ path: ENV }), r);
  assert.equal(r.status, 200);
  assert.equal("basedOn" in (sent[0] as object), false);
});
