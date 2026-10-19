/**
 * model-routes.test — Settings › Models (dashboard.md §4.25l) over a real
 * DashboardServer with a fake arbiter surface.
 *
 * Pins:
 *   - planModelChange: the form becomes add-model / update-model /
 *     remove-model (a rename is remove + add), empty optional fields are left
 *     out, `local` only as a literal true; missing fields are 400s before the
 *     arbiter is called;
 *   - POST /api/policy/models/change: the first send only previews and asks
 *     (rows, wouldLet, warnings, expected); the second, with what was shown,
 *     proposes on the admin surface and approves as human:settings, and the
 *     answer carries the restart note; a validator refusal is a 422 with the
 *     file position stripped; an unknown name is a 409; CSRF + the admin
 *     session are required (403, nothing reaches the arbiter);
 *   - POST /api/policy/models/test: probes the entry of the law IN FORCE by
 *     name (an unknown name is a 404, never a probe of a request's address);
 *     the token named by token_env is passed to the listing and appears
 *     nowhere in the answer;
 *   - an update names the entry as the page read it (policy-surface.md
 *     §8.4.6 "An item-level version"): no version is a 400, a version the
 *     read finds moved is a 409 `stale` before any preview, the propose
 *     carries `basedOn` (the form's entry at the page's version, a moved
 *     helper mark's entry at this read's), and the arbiter's stale refusal
 *     (at propose or at approve) is a 409 `stale` in the product's words;
 *     an arbiter that answers no versions gets no carried-over write (501).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { DashboardServer, type PolicyDocArbiter } from "../../../src/server.js";
import { formProblems, perimeterOfFile, planModelChange, probeEntryOf, RESTART_NOTE, SETTINGS_APPROVER, staleWords, tlsOfFileEntry } from "../../../src/server/model-routes.js";
import type { ProbeDeps } from "../../../src/model-probe.js";
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
const IN_FORCE = {
  version: 1,
  models: [
    { name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", model: "llama3.2", local: true, token_env: "OLLAMA_TOKEN" },
    { name: "gateway", url: "https://llm.example.com" },
  ],
};

const V_OLLAMA = "a".repeat(32);
const V_GATEWAY = "b".repeat(32);
const VERSIONS = { models: { ollama: V_OLLAMA, gateway: V_GATEWAY } };

function fake(opts: { previewProblems?: string[]; inForce?: unknown; versions?: Record<string, Record<string, string>> | null; proposeStale?: string[]; resolveStale?: string[] } = {}) {
  const calls: Array<{ op: string; args: unknown }> = [];
  const versions = opts.versions === null ? undefined : opts.versions ?? VERSIONS;
  const arbiter: PolicyDocArbiter = {
    async policyDocument() { return { status: STATUS, inForce: opts.inForce ?? IN_FORCE, onDisk: { text: null, parsed: null, problems: [] }, ...(versions ? { itemVersions: versions } : {}) }; },
    async applyPolicyDocument() { return { path: "/p", status: STATUS }; },
    async mintUserRule() { return { id: "r", path: "/p", status: STATUS }; },
    async exportDbLabels() { return { added: 0, path: "/p", status: STATUS }; },
    async policyPreview(edits: unknown) {
      calls.push({ op: "preview", args: edits });
      if (opts.previewProblems) return { ok: false as const, problems: opts.previewProblems };
      const names = (edits as Array<{ name: string }>).map((e) => e.name);
      return { ok: true as const, relaxations: names.map((n) => ({ facet: "models", direction: "relax", subject: n, detail: "d" })), tightenings: [], perEdit: names.map(() => ({ loosens: true })) };
    },
    async policyPropose(req: { edits: unknown; reason?: string; requestedBy?: string }) {
      calls.push({ op: "propose", args: req });
      if (opts.proposeStale) return { applied: false as const, refused: "stale", changed: opts.proposeStale, problems: ["changed since it was read"] };
      const names = (req.edits as Array<{ name: string }>).map((e) => e.name);
      return { applied: false as const, proposalId: "pp-000003", relaxes: names.map((n) => ({ facet: "models", subject: n })) };
    },
    async resolvePolicyProposal(id: string, verdict: "approved" | "denied", by?: string) {
      calls.push({ op: "resolve", args: [id, verdict, by] });
      if (opts.resolveStale && verdict === "approved") return { proposal: {} as never, stale: opts.resolveStale };
      return { proposal: {} as never, changeId: "pc-000011" };
    },
  };
  return { arbiter, calls };
}

async function start(arbiter: PolicyDocArbiter, probe?: ProbeDeps) {
  const server = new DashboardServer({ source: fakeSource, policyDocArbiter: arbiter, log: () => {}, ...ADMIN_OPTS, ...(probe ? { modelProbeDeps: probe } : {}) });
  const port = await server.listen(0);
  const post = async (path: string, body: unknown, headers: Record<string, string> = CSRF_ADMIN) => {
    const r = await fetch(`http://127.0.0.1:${port}${path}`, { method: "POST", headers, body: JSON.stringify(body) });
    return { status: r.status, body: (await r.json()) as Record<string, unknown> };
  };
  return { post, close: () => server.close() };
}

test("planModelChange: the form becomes the edit grammar; a rename is remove + add; missing fields are refused", () => {
  const form = { name: " lab ", url: " http://10.0.0.5:8000 ", wire: "openai-chat", model: "", local: true, tokenEnv: "" };
  assert.deepEqual(planModelChange({ action: "add", model: form }), { ok: true, edits: [{ op: "add-model", name: "lab", url: "http://10.0.0.5:8000", wire: "openai-chat", local: true }], reads: [] });
  assert.deepEqual(planModelChange({ action: "update", name: "lab", model: { ...form, local: "true", tokenEnv: "LAB" } }),
    { ok: true, edits: [{ op: "update-model", name: "lab", url: "http://10.0.0.5:8000", wire: "openai-chat", token_env: "LAB" }], reads: ["lab"] }, "local only as a literal true");
  assert.deepEqual(planModelChange({ action: "update", name: "lab", model: { ...form, name: "lab2" } }),
    { ok: true, edits: [{ op: "remove-model", name: "lab" }, { op: "add-model", name: "lab2", url: "http://10.0.0.5:8000", wire: "openai-chat", local: true }], reads: ["lab"] });
  assert.deepEqual(planModelChange({ action: "remove", name: "lab" }), { ok: true, edits: [{ op: "remove-model", name: "lab" }], reads: [] });
  assert.deepEqual(planModelChange({ action: "restore", name: "corp" }), { ok: true, edits: [{ op: "restore-model", name: "corp" }], reads: [] }, "plan 12 D5");
  for (const bad of [{}, { action: "rename" }, { action: "remove" }, { action: "restore" }, { action: "add" }, { action: "add", model: { url: "http://x" } }, { action: "add", model: { name: "x" } }, { action: "update", model: form }]) {
    const p = planModelChange(bad);
    assert.equal(p.ok, false, JSON.stringify(bad));
    if (!p.ok) assert.equal(p.status, 400);
  }
  // A helper choice MOVES the mark: the entry that had it is rewritten
  // without it, before the change, so the file never holds two.
  const inForce = [
    { name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", model: "llama3.2", local: true, helper: true, token_env: "OLLAMA_TOKEN" },
    { name: "lab", url: "http://10.0.0.5:8000", local: true },
  ];
  assert.deepEqual(planModelChange({ action: "update", name: "lab", model: { ...form, helper: true } }, inForce), { ok: true, edits: [
    { op: "update-model", name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", model: "llama3.2", local: true, token_env: "OLLAMA_TOKEN" },
    { op: "update-model", name: "lab", url: "http://10.0.0.5:8000", wire: "openai-chat", local: true, helper: true },
  ], reads: ["lab", "ollama"] }, "the moved mark's entry is read too");
  assert.deepEqual(planModelChange({ action: "update", name: "ollama", model: { ...inForce[0], tokenEnv: "OLLAMA_TOKEN", name: "ollama" } }, inForce),
    { ok: true, edits: [{ op: "update-model", name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", model: "llama3.2", local: true, token_env: "OLLAMA_TOKEN", helper: true }], reads: ["ollama"] },
    "keeping the mark on the same entry moves nothing");
  assert.equal(planModelChange({ action: "add", model: { ...form, helper: false } }, inForce).ok && (planModelChange({ action: "add", model: { ...form, helper: false } }, inForce) as { edits: unknown[] }).edits.length, 1, "no helper choice: no move");
  assert.deepEqual(formProblems(["models[2].url: must be an http(s) URL", "edits[0] (add-model): a model named \"x\" is already declared"]), ["url: must be an http(s) URL", "a model named \"x\" is already declared"]);
});

test("change: the first send asks (rows, what it would let, the warning); the second applies as the person, with the restart note", async () => {
  const f = fake();
  const h = await start(f.arbiter);
  try {
    const body = { action: "add", model: { name: "lab", url: "http://203.0.113.9:8000", local: true } };
    const ask = await h.post("/api/policy/models/change", body);
    assert.equal(ask.status, 200);
    assert.equal(ask.body.applied, false);
    assert.equal(ask.body.confirm, true);
    assert.deepEqual(ask.body.expected, ["models\u0000lab"]);
    const text = (rows: unknown) => (rows as Array<Array<{ text: string }>>).map((r) => r.map((p) => p.text).join(""));
    assert.deepEqual(text(ask.body.rows), ["Add the model lab at http://203.0.113.9:8000, as your own model"]);
    assert.match(text(ask.body.wouldLet)[0]!, /^The models Mandu knows would change for lab/);
    assert.match(text(ask.body.warnings)[0]!, /^lab would count as your own model, but http:\/\/203\.0\.113\.9:8000 is not on this machine or a private network address/);
    assert.deepEqual(f.calls.map((c) => c.op), ["preview"], "asking writes nothing");

    const done = await h.post("/api/policy/models/change", { ...body, expected: ask.body.expected });
    assert.equal(done.status, 200, JSON.stringify(done.body));
    assert.deepEqual(done.body, { applied: true, changeId: "pc-000011", note: RESTART_NOTE });
    const propose = f.calls.find((c) => c.op === "propose")!.args as { edits: unknown; requestedBy: string };
    assert.deepEqual(propose.edits, [{ op: "add-model", name: "lab", url: "http://203.0.113.9:8000", local: true }]);
    assert.equal(propose.requestedBy, "settings");
    assert.deepEqual(f.calls.find((c) => c.op === "resolve")!.args, ["pp-000003", "approved", SETTINGS_APPROVER]);

    const stale = await h.post("/api/policy/models/change", { ...body, expected: ["models\u0000other"] });
    assert.equal(stale.status, 409, "a loosening that was not shown is refused");
  } finally {
    await h.close();
  }
});

test("change: a validator refusal is a 422 with the file position stripped; an unknown name is a 409", async () => {
  const bad = await start(fake({ previewProblems: ["models[0].url: must be an http(s) URL with no credentials in it (got \"ftp://x\")"] }).arbiter);
  try {
    const r = await bad.post("/api/policy/models/change", { action: "add", model: { name: "x", url: "ftp://x" } });
    assert.equal(r.status, 422);
    assert.deepEqual(r.body, { error: "This model entry is not valid.", problems: ["url: must be an http(s) URL with no credentials in it (got \"ftp://x\")"] });
  } finally {
    await bad.close();
  }
  const gone = await start(fake({ previewProblems: ["edits[0] (remove-model): no model named \"nope\""] }).arbiter);
  try {
    const r = await gone.post("/api/policy/models/change", { action: "remove", name: "nope" });
    assert.equal(r.status, 409);
    assert.match(String(r.body.error), /no longer in your list/);
  } finally {
    await gone.close();
  }
});

test("change and test need the CSRF header and the admin session; nothing reaches the arbiter without them", async () => {
  const f = fake();
  const h = await start(f.arbiter);
  try {
    for (const path of ["/api/policy/models/change", "/api/policy/models/test"]) {
      const noCsrf = await h.post(path, { action: "remove", name: "ollama" }, { Cookie: ADMIN_COOKIE, "Content-Type": "application/json" });
      assert.equal(noCsrf.status, 403, `${path} without CSRF`);
      const noAdmin = await h.post(path, { action: "remove", name: "ollama" }, { "X-Mandu-Control": "1", "Content-Type": "application/json" });
      assert.equal(noAdmin.status, 403, `${path} without the admin session`);
    }
    assert.deepEqual(f.calls, []);
  } finally {
    await h.close();
  }
});

test("test: probes the entry of the law in force by name, with its token for the listing only; an unknown name is a 404", async () => {
  const seen: Array<{ host?: string; port?: number; url?: string; token?: string }> = [];
  const probe: ProbeDeps = {
    async probeTcp(host, port) { seen.push({ host, port }); return true; },
    async listModels(url, token) { seen.push({ url, token }); return ["llama3.2:latest", "gpt-oss:120b-cloud"]; },
    env: { OLLAMA_TOKEN: "sk-local-VALUE-123" },
  };
  const h = await start(fake().arbiter, probe);
  try {
    const r = await h.post("/api/policy/models/test", { name: "ollama" });
    assert.equal(r.status, 200);
    const result = r.body.result as { ok: boolean; reachable: boolean; modelListed: boolean; cloudListed: string[]; lines: Array<{ tone: string; text: string }> };
    assert.equal(result.reachable, true);
    assert.equal(result.modelListed, true);
    assert.deepEqual(result.cloudListed, ["gpt-oss:120b-cloud"]);
    assert.equal(result.ok, true);
    assert.deepEqual(seen, [{ host: "127.0.0.1", port: 11434 }, { url: "http://127.0.0.1:11434", token: "sk-local-VALUE-123" }]);
    assert.doesNotMatch(JSON.stringify(r.body), /sk-local-VALUE-123/, "the token never reaches the browser");
    const missing = await h.post("/api/policy/models/test", { name: "http://evil.example" });
    assert.equal(missing.status, 404, "only a declared entry is probed, never an address from the request");
    assert.equal(seen.length, 2);
  } finally {
    await h.close();
  }
});

test("plan 12 D3: an update from the form keeps the entry's tls in force (the form does not edit it); a helper move keeps other entries' tls too", () => {
  const PIN = Buffer.alloc(32, 9).toString("base64");
  const tls = { ca_file: "~/.config/mandu/corp-ca.pem", pin_sha256: [PIN] };
  const inForce = [{ name: "corp", url: "https://llm.corp.example/v1", local: true, tls }, { name: "lab", url: "https://10.0.3.7:8443", local: true, helper: true, tls }];
  const form = { name: "corp", url: "https://llm.corp.example/v1", wire: "openai-chat", model: "q", local: true, tokenEnv: "" };
  const plan = planModelChange({ action: "update", name: "corp", model: form }, inForce);
  assert.ok(plan.ok);
  if (plan.ok) assert.deepEqual((plan.edits.at(-1) as { tls?: unknown }).tls, tls);
  const moved = planModelChange({ action: "update", name: "corp", model: { ...form, helper: true } }, inForce);
  assert.ok(moved.ok);
  if (moved.ok) assert.deepEqual((moved.edits.find((e) => (e as { name?: string }).name === "lab") as { tls?: unknown }).tls, tls, "the helper move rewrites lab without dropping its tls");
});

test("plan 12 D3: tlsOfFileEntry turns the file's spelling into the probe's config (~ expanded, bad pins and half pairs dropped)", () => {
  const PIN = Buffer.alloc(32, 9).toString("base64");
  assert.deepEqual(tlsOfFileEntry({ ca_file: "~/ca.pem", pin_sha256: [PIN, "x"], client_cert: "/c.pem", client_key: "~/k.pem" }, "/home/u"),
    { caFile: "/home/u/ca.pem", pinSha256: [PIN], clientCert: "/c.pem", clientKey: "/home/u/k.pem" });
  assert.deepEqual(tlsOfFileEntry({ client_cert: "/c.pem" }, "/home/u"), undefined);
  assert.equal(tlsOfFileEntry("yes"), undefined);
  assert.equal(tlsOfFileEntry({ ca_file: "relative.pem" }, "/home/u"), undefined);
});

test("plan 12 D4: probeEntryOf carries the document's perimeter to a local entry on another machine only, and marks a name under its domains", () => {
  const per = { networks: ["10.0.0.0/8"], domains: ["Corp.Example"] };
  assert.deepEqual(probeEntryOf({ name: "corp", url: "https://llm.corp.example/v1", local: true }, per), {
    name: "corp", url: "https://llm.corp.example/v1", wire: "anthropic", local: true, perimeter: ["10.0.0.0/8"], orgDomain: true,
  });
  assert.equal(probeEntryOf({ name: "home", url: "http://127.0.0.1:11434", local: true }, per)?.perimeter, undefined, "this computer is not held to it");
  assert.equal(probeEntryOf({ name: "gw", url: "https://gw.corp.example", local: false }, per)?.perimeter, undefined, "an outside model is not held to it");
  assert.equal(probeEntryOf({ name: "gw", url: "https://gw.corp.example", local: false }, per)?.orgDomain, true);
  assert.equal(probeEntryOf({ name: "corp", url: "https://llm.corp.example", local: true })?.perimeter, undefined, "no section");
  assert.deepEqual(perimeterOfFile({ networks: ["10.0.0.0/99"] }), { networks: null, domains: [] }, "an unusable list checks nothing here (the arbiter refused the file)");
  assert.deepEqual(perimeterOfFile("x"), { networks: null, domains: [] });
});

test("plan 12 D5: Test connection finds an administrator's entry by name, with the administrator's perimeter; the user's entry of that name wins; a removed one is gone", async () => {
  const seen: string[] = [];
  const probe: ProbeDeps = {
    async probeTcp(host, port) { seen.push(`${host}:${port}`); return true; },
    async listModels() { return []; },
    async lookupHost() { return ["10.1.2.3"]; },
    env: {},
  };
  const withAdmin = (inForce: unknown): PolicyDocArbiter => ({
    ...fake().arbiter,
    async policyDocument() {
      return {
        status: STATUS, inForce, onDisk: { text: null, parsed: null, problems: [] },
        admin: { files: ["/etc/mandu/policy.d/10-corp.yaml"], locked: true, perimeter: { networks: ["10.0.0.0/8"] }, perimeterFile: "/etc/mandu/policy.d/10-corp.yaml",
          models: [{ name: "corp", url: "https://llm.corp.example:8443/v1", local: true, file: "/etc/mandu/policy.d/10-corp.yaml" }] },
      };
    },
  });
  const h = await start(withAdmin(IN_FORCE), probe);
  try {
    const r = await h.post("/api/policy/models/test", { name: "corp" });
    assert.equal(r.status, 200);
    const result = r.body.result as { perimeter?: { ok: boolean; networks: string[] } };
    assert.deepEqual(result.perimeter, { networks: ["10.0.0.0/8"], ok: true }, "the administrator's perimeter applies");
    assert.deepEqual(seen, ["llm.corp.example:8443"]);
  } finally { await h.close(); }
  const gone = await start(withAdmin({ models: [{ name: "corp", disabled: true }] }), probe);
  try {
    assert.equal((await gone.post("/api/policy/models/test", { name: "corp" })).status, 404, "removed by the user");
  } finally { await gone.close(); }
});

test("§8.4.6: an update names the entry as the page read it; a moved entry is refused 409 stale, nothing proposed", async () => {
  const form = { name: "ollama", url: "http://127.0.0.1:11435", wire: "openai-chat", model: "llama3.2", local: true, tokenEnv: "OLLAMA_TOKEN" };
  const f = fake();
  const h = await start(f.arbiter);
  try {
    const none = await h.post("/api/policy/models/change", { action: "update", name: "ollama", model: form });
    assert.equal(none.status, 400, "no version: refused");
    assert.match(String(none.body.error), /Reload the page/);
    const junk = await h.post("/api/policy/models/change", { action: "update", name: "ollama", model: form, version: "not-a-version" });
    assert.equal(junk.status, 400);
    assert.equal(f.calls.length, 0, "nothing reached the arbiter's write path");

    const moved = await h.post("/api/policy/models/change", { action: "update", name: "ollama", model: form, version: "c".repeat(32) });
    assert.equal(moved.status, 409);
    assert.equal(moved.body.stale, true);
    assert.deepEqual(moved.body.changed, ["models ollama"]);
    assert.equal(moved.body.error, staleWords("ollama"));
    assert.equal(f.calls.length, 0, "refused before the preview: the person is not asked to confirm a change built on an old read");

    const body = { action: "update", name: "ollama", model: form, version: V_OLLAMA };
    const ask = await h.post("/api/policy/models/change", body);
    assert.equal(ask.status, 200);
    assert.equal(ask.body.confirm, true);
    const done = await h.post("/api/policy/models/change", { ...body, expected: ask.body.expected });
    assert.equal(done.status, 200, JSON.stringify(done.body));
    const propose = f.calls.find((c) => c.op === "propose")!.args as { basedOn?: unknown };
    assert.deepEqual(propose.basedOn, [{ section: "models", key: "ollama", version: V_OLLAMA }]);
  } finally {
    await h.close();
  }
});

test("§8.4.6: the arbiter's stale refusal, at propose or at approve, is a 409 stale in the product's words", async () => {
  const form = { name: "ollama", url: "http://127.0.0.1:11435", wire: "openai-chat", local: true };
  const body = { action: "update", name: "ollama", model: form, version: V_OLLAMA, expected: ["models\u0000ollama"] };
  for (const opts of [{ proposeStale: ["models ollama"] }, { resolveStale: ["models ollama"] }]) {
    const f = fake(opts);
    const h = await start(f.arbiter);
    try {
      const r = await h.post("/api/policy/models/change", body);
      assert.equal(r.status, 409, JSON.stringify(opts));
      assert.equal(r.body.stale, true);
      assert.deepEqual(r.body.changed, ["models ollama"]);
      assert.equal(r.body.error, staleWords("ollama"));
      assert.equal(r.body.applied, undefined);
    } finally {
      await h.close();
    }
  }
  // Only another entry moved (a helper mark's): the general words.
  const f = fake({ proposeStale: ["models gateway"] });
  const h = await start(f.arbiter);
  try {
    const r = await h.post("/api/policy/models/change", body);
    assert.equal(r.status, 409);
    assert.match(String(r.body.error), /Your models changed while you were deciding/);
  } finally {
    await h.close();
  }
});

test("§8.4.6: a helper move names the entry it rewrites at this read's version; an arbiter without versions gets no carried-over write", async () => {
  const inForce = { models: [
    { name: "ollama", url: "http://127.0.0.1:11434", local: true, helper: true },
    { name: "lab", url: "http://127.0.0.1:8000", local: true },
  ] };
  const f = fake({ inForce, versions: { models: { ollama: V_OLLAMA, lab: V_GATEWAY } } });
  const h = await start(f.arbiter);
  try {
    const r = await h.post("/api/policy/models/change", { action: "update", name: "lab", model: { name: "lab", url: "http://127.0.0.1:8000", local: true, helper: true }, version: V_GATEWAY, expected: ["models\u0000ollama", "models\u0000lab"] });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    const propose = f.calls.find((c) => c.op === "propose")!.args as { basedOn?: unknown };
    assert.deepEqual(propose.basedOn, [{ section: "models", key: "lab", version: V_GATEWAY }, { section: "models", key: "ollama", version: V_OLLAMA }]);
    const add = await h.post("/api/policy/models/change", { action: "add", model: { name: "new", url: "http://127.0.0.1:9000", local: true, helper: true }, expected: ["models\u0000ollama", "models\u0000new"] });
    assert.equal(add.status, 200, JSON.stringify(add.body));
    const proposeAdd = f.calls.filter((c) => c.op === "propose").at(-1)!.args as { basedOn?: unknown };
    assert.deepEqual(proposeAdd.basedOn, [{ section: "models", key: "ollama", version: V_OLLAMA }], "an add that moves the mark names the entry it rewrites");
  } finally {
    await h.close();
  }
  // A file that names no model (an administrator's entry only): no `models`
  // section, and the page's version of the entry (that of none) is sent.
  const none = fake({ inForce: { version: 1 }, versions: {} });
  const n = await start(none.arbiter);
  try {
    const r = await n.post("/api/policy/models/change", { action: "update", name: "corp", model: { name: "corp", url: "https://llm.corp.example/v1" }, version: V_OLLAMA, expected: ["models\u0000corp"] });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.deepEqual((none.calls.find((c) => c.op === "propose")!.args as { basedOn?: unknown }).basedOn, [{ section: "models", key: "corp", version: V_OLLAMA }]);
  } finally {
    await n.close();
  }
  const old = fake({ versions: null });
  const o = await start(old.arbiter);
  try {
    const r = await o.post("/api/policy/models/change", { action: "update", name: "ollama", model: { name: "ollama", url: "http://127.0.0.1:11434", local: true }, version: V_OLLAMA });
    assert.equal(r.status, 501);
    assert.deepEqual(old.calls, [], "nothing proposed to an arbiter that could not refuse it as stale");
    const rm = await o.post("/api/policy/models/change", { action: "remove", name: "ollama" });
    assert.equal(rm.status, 200, "a remove carries nothing over");
  } finally {
    await o.close();
  }
});
