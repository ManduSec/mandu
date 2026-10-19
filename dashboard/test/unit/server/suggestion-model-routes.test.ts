/**
 * suggestion-model-routes.test — the model picker's routes (dashboard.md
 * §4.25t, confidentiality-plan-14 §14.5, §14.11) over a real DashboardServer
 * with a mock arbiter surface (the arbiter-client pattern: the production
 * adapter over a real ArbiterServer is in
 * tests/stack/policy-model-contents.test.ts).
 *
 * Pins: both POSTs need the CSRF header and the admin session (the global
 * gate); without MANDU_EXPERIMENTAL_POLICY_MODEL=1 on the server they are
 * refused (403) and nothing reaches the arbiter, and the GET's picker says
 * "not offered yet" without reading the models; offered, the GET's picker
 * reads the declared models and enables Contents only with one of your own;
 * the preview is validated first (the tier, the endpoint's grammar, a
 * boolean includeHome), asks for the typed folder or the recorded sessions'
 * folders, and answers the page's view (the files and sizes for Contents,
 * never their text); a refusal comes back in the page's words; the send
 * validates the digest, answers the run (still reading, then its line) with
 * the fresh listing, and a forgotten preview is 410; an arbiter without the
 * ops → 501.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { DashboardServer, type PolicyDocArbiter } from "../../../src/server.js";
import type { SuggestionWire } from "../../../src/view-model/suggestions.js";
import type { ModelPreviewWire, ModelRunWire } from "../../../src/view-model/suggestion-model.js";
import type { EventSource, SessionRef } from "../../../src/event-source.js";
import type { ManduEvent } from "../../../src/event-model.js";
import { ADMIN_OPTS, ADMIN_COOKIE } from "../admin-session.js";

const HOME = "/home/u";
const CSRF_ADMIN = { "X-Mandu-Control": "1", Cookie: ADMIN_COOKIE, "Content-Type": "application/json" };
const STATUS = { path: "/p", found: true, valid: true, problems: [], loadedAt: 1, refusedAt: null };
const DIGEST = "b".repeat(64);
const TEXT_CANARY = "DOC-TEXT-CANARY-77";

function sourceWith(cwds: string[]): EventSource {
  const now = new Date().toISOString();
  const sessions: SessionRef[] = cwds.map((_, i) => ({ id: `s-live-${i}`, label: null, eventCount: 1, firstTs: now, lastTs: now, violated: false }));
  return {
    async listSessions() { return sessions; },
    async readEvents(id: string): Promise<ManduEvent[]> {
      const cwd = cwds[Number(id.slice("s-live-".length))]!;
      return [{
        id: "e1", seq: 0, ts: now, sessionId: id, turn: 0, kind: "tllm_call", view: "AgentView", boundary: "model_context",
        emitter: "anthropic-proxy", callId: null, parentId: null, input: null, output: null, invariant: { violatedInvariant: false },
        fullInput: { blocks: [{ role: "system", source: "agent", text: `<env>\nWorking directory: ${cwd}\n</env>` }] },
      } as unknown as ManduEvent];
    },
    subscribe() { return () => {}; },
    close() {},
  };
}

const PREVIEW: ModelPreviewWire = {
  axis: true, tier: "contents", digest: DIGEST,
  destination: { kind: "declared", name: "ollama", location: "local", placement: "host", vendor: "127.0.0.1" },
  roots: [{ index: 1, root: `${HOME}/proj`, files: 4 }], items: 1, bytes: 900, requests: 1, names: [],
  files: [{ root: 1, name: "docs/contract.md", bytes: 900, truncated: false }],
  left: { covered: 0, labelled: 0, tooLong: 0, personal: 0, overCap: 0, detector: 0, registered: 0, flagged: 0, unread: 0 },
  promptVersion: "contents-1", confine: { live: true }, expiresAt: 1, walk: { examined: 4, covered: 0, capped: [] },
};
const RUN: ModelRunWire = {
  axis: true, running: false, digest: DIGEST, destination: PREVIEW.destination, sent: { requests: 1, items: 1, bytes: 900 },
  counts: { rules: 1, kept: 1, dropped: 0, merged: 0, tooBroad: 0, covered: 0, filed: 1, alreadyPending: 0, dismissed: 0, overCap: 0, failedRequests: 0, public: 0 },
  filed: ["pp-000009"], error: null, ms: 10,
};

function mock(o: { withOps?: boolean; own?: boolean; refuse?: string; running?: number } = {}) {
  const calls: string[] = [];
  let running = o.running ?? 0;
  const arbiter: PolicyDocArbiter = {
    async policyDocument() { return { status: STATUS, inForce: null, onDisk: { text: null, parsed: null, problems: [] } }; },
    async applyPolicyDocument() { return { path: "/p", status: STATUS }; },
    async mintUserRule() { return { id: "r", path: "/p", status: STATUS }; },
    async exportDbLabels() { return { added: 0, path: "/p", status: STATUS }; },
    async policySuggestions(status?: string) { calls.push(`list:${status}`); return { suggestions: [] as SuggestionWire[] }; },
    async resolvePolicyProposal() { return { proposal: {} as never }; },
    ...(o.withOps === false
      ? {}
      : {
          async modelEndpoints() { calls.push("models"); return o.own === false ? [{ name: "cloud", local: false }] : [{ name: "ollama", local: true, model: "qwen2.5:7b" }]; },
          async modelSuggestPreview(roots: string[], opts: { tier: string; endpoint?: string; home?: string; includeHome?: boolean }) {
            calls.push(`preview:${opts.tier}:${roots.join(",")}:${opts.home}${opts.endpoint ? `:${opts.endpoint}` : ""}${opts.includeHome ? ":home" : ""}`);
            if (o.refuse) throw new Error(o.refuse);
            return PREVIEW;
          },
          async modelSuggest(digest: string, opts?: { waitMs?: number }) {
            calls.push(`send:${digest.slice(0, 4)}:${opts?.waitMs !== undefined}`);
            if (digest === "f".repeat(64)) throw new Error("modelSuggest: this preview is no longer held (it is kept 15 minutes, and not across a restart): look again");
            if (running > 0) { running--; return { ...RUN, running: true, filed: [] }; }
            return RUN;
          },
        }),
  } as PolicyDocArbiter;
  return { arbiter, calls };
}

async function start(arbiter: PolicyDocArbiter, opts: { offered?: boolean; cwds?: string[] } = {}) {
  const server = new DashboardServer({
    source: sourceWith(opts.cwds ?? ["/home/u/proj"]), policyDocArbiter: arbiter, fileBrowserHome: HOME, log: () => {},
    ...(opts.offered !== undefined ? { policyModelOffered: opts.offered } : {}), ...ADMIN_OPTS,
  });
  const port = await server.listen(0);
  const base = `http://127.0.0.1:${port}`;
  const get = async () => {
    const r = await fetch(`${base}/api/suggestions`, { headers: CSRF_ADMIN });
    return { status: r.status, body: (await r.json()) as any };
  };
  const post = async (path: string, body: unknown, headers: Record<string, string> = CSRF_ADMIN) => {
    const r = await fetch(`${base}/api/suggestions/${path}`, { method: "POST", headers, body: JSON.stringify(body) });
    return { status: r.status, body: (await r.json()) as any };
  };
  return { get, post, close: () => server.close() };
}

test("not offered: both POSTs refused and the picker says so, nothing reaches the arbiter's model ops", async () => {
  const m = mock();
  const s = await start(m.arbiter, { offered: false });
  try {
    assert.equal((await s.post("model/preview", { tier: "contents" })).status, 403);
    assert.equal((await s.post("model/send", { digest: DIGEST })).status, 403);
    const g = await s.get();
    assert.equal(g.body.model.offered, false);
    assert.deepEqual(g.body.model.options.map((o: { enabled: boolean }) => o.enabled), [true, false, false]);
    assert.deepEqual(m.calls, ["list:pending"], "the models are not even read");
  } finally { await s.close(); }
});

test("both POSTs need the CSRF header and the admin session", async () => {
  const m = mock();
  const s = await start(m.arbiter, { offered: true });
  try {
    for (const [path, body] of [["model/preview", { tier: "names" }], ["model/send", { digest: DIGEST }]] as const) {
      assert.equal((await s.post(path, body, { "Content-Type": "application/json" })).status, 403);
      assert.equal((await s.post(path, body, { "X-Mandu-Control": "1", "Content-Type": "application/json" })).status, 403);
    }
    assert.deepEqual(m.calls, []);
  } finally { await s.close(); }
});

test("offered: the picker reads your models; Contents needs one of your own", async () => {
  const own = mock();
  const s1 = await start(own.arbiter, { offered: true });
  try {
    const g = await s1.get();
    assert.equal(g.body.model.offered, true);
    assert.deepEqual(g.body.model.ownModels, ["ollama"]);
    assert.equal(g.body.model.options[2].enabled, true);
  } finally { await s1.close(); }
  const none = mock({ own: false });
  const s2 = await start(none.arbiter, { offered: true });
  try {
    const g = await s2.get();
    assert.equal(g.body.model.options[2].enabled, false);
    assert.match(g.body.model.options[2].why, /No model of your own is set up/);
  } finally { await s2.close(); }
});

test("preview: validated first; the recorded folders or a typed one; the page's view of the files, never their text", async () => {
  const m = mock();
  const s = await start(m.arbiter, { offered: true });
  try {
    assert.equal((await s.post("model/preview", { tier: "everything" })).status, 400);
    assert.equal((await s.post("model/preview", { tier: "contents", endpoint: "bad name!" })).status, 400);
    assert.equal((await s.post("model/preview", { tier: "contents", includeHome: "yes" })).status, 400);
    assert.equal((await s.post("model/preview", { tier: "contents", root: "relative/dir" })).status, 400);
    assert.deepEqual(m.calls, []);
    const r = await s.post("model/preview", { tier: "contents", endpoint: "ollama" });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(r.body.preview.headline, "This sends the text of 1 file (900 bytes) to your own model ollama (this computer).");
    assert.deepEqual(r.body.preview.list, [{ text: "root 1/docs/contract.md", size: "900 bytes" }]);
    assert.equal(r.body.preview.digest, DIGEST);
    assert.ok(!JSON.stringify(r.body).includes(TEXT_CANARY));
    await s.post("model/preview", { tier: "names", root: "~/other", includeHome: true });
    assert.deepEqual(m.calls, [`preview:contents:/home/u/proj:${HOME}:ollama`, `preview:names:/home/u/other:${HOME}:home`]);
  } finally { await s.close(); }
});

test("a refusal comes back in the page's words", async () => {
  const m = mock({ refuse: "modelSuggestPreview: the model tier is not available in this install (the arbiter was started without a classifier)" });
  const s = await start(m.arbiter, { offered: true });
  try {
    const r = await s.post("model/preview", { tier: "names" });
    assert.equal(r.status, 422);
    assert.equal(r.body.error, "Asking a model is not available in this install of Mandu");
  } finally { await s.close(); }
});

test("send: the digest validated; still reading, then the run's line with the fresh listing; a forgotten preview is 410", async () => {
  const m = mock({ running: 1 });
  const s = await start(m.arbiter, { offered: true });
  try {
    assert.equal((await s.post("model/send", { digest: "nope" })).status, 400);
    const r1 = await s.post("model/send", { digest: DIGEST, tier: "contents" });
    assert.equal(r1.status, 200);
    assert.equal(r1.body.run.running, true);
    const r2 = await s.post("model/send", { digest: DIGEST, tier: "contents" });
    assert.equal(r2.body.run.running, false);
    assert.equal(r2.body.run.line, "ollama read 1 file: 1 looks sensitive and waits here for you, 0 do not.");
    assert.deepEqual(r2.body.suggestions, []);
    const gone = await s.post("model/send", { digest: "f".repeat(64) });
    assert.equal(gone.status, 410);
    assert.equal(gone.body.error, "This preview has expired. Look again before you send");
    assert.deepEqual(m.calls.filter((c) => c.startsWith("send")), ["send:bbbb:true", "send:bbbb:true", "send:ffff:true"]);
  } finally { await s.close(); }
});

test("an arbiter without the model ops: 501", async () => {
  const m = mock({ withOps: false });
  const s = await start(m.arbiter, { offered: true });
  try {
    assert.equal((await s.post("model/preview", { tier: "names" })).status, 501);
    assert.equal((await s.post("model/send", { digest: DIGEST })).status, 501);
    const g = await s.get();
    assert.equal(g.body.model.options[2].enabled, false);
  } finally { await s.close(); }
});
