/**
 * policy-assistant.test — "Describe what you want" (policy-surface.md §8
 * §5.2): the pure assistant module and its two routes over a real
 * DashboardServer with a fake arbiter and a fake model.
 *
 * Pins:
 *   - the prompt carries the edit schema and the current rules; the person's
 *     sentence is fenced in the user message; the current rules include the
 *     declared models as the arbiter lists them (no key value);
 *   - the answer is parsed strictly (one JSON object, a ```json fence allowed;
 *     anything else is a 422, never a guess); the note is capped;
 *   - rows come from the page's grammar, marked per edit from the arbiter's
 *     preview; `expected` is the preview's loosenings;
 *   - a file under the page's home reads `~/…` in the rows and the lines
 *     (dashboard.md §4.34), however the assistant wrote it; `edits` and
 *     `expected` stay as the arbiter has them; the route takes the server's
 *     home (`fileBrowserHome`, else the account's);
 *   - no channel ⇒ 503 `unconfigured` BEFORE the arbiter or any model is used;
 *   - Apply: refused (409) when the re-preview loosens more than was shown,
 *     applied directly for a tightening, and approved by the same click for
 *     a loosening; the arbiter's skew-guard re-file is denied and answered
 *     409; both POSTs need CSRF + the admin session;
 *   - models are read-only here (policy-surface.md §8.4.3a): the prompt
 *     says so, an answer carrying add-model / update-model / remove-model is
 *     a 422 before any preview, and Apply refuses one (422) before any
 *     preview or propose.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { homedir } from "node:os";

import { DashboardServer, type PolicyDocArbiter } from "../../src/server.js";
import {
  AssistantAnswerError,
  AssistantUnconfiguredError,
  MODELS_ELSEWHERE,
  assistantSystemPrompt,
  modelEditProblems,
  assistantUserMessage,
  parseAssistantAnswer,
  relaxKey,
  suggestRules,
  tryLine,
  tryProbe,
  type AssistantModel,
  type PreviewResult,
} from "../../src/policy-assistant.js";
import { ADMIN_OPTS, ADMIN_COOKIE } from "./admin-session.js";
import type { EventSource, SessionRef } from "../../src/event-source.js";
import type { ManduEvent } from "../../src/event-model.js";

const fakeSource: EventSource = {
  async listSessions(): Promise<SessionRef[]> { return []; },
  async readEvents(): Promise<ManduEvent[]> { return []; },
  subscribe(): () => void { return () => {}; },
  close(): void {},
};
const STATUS = { path: "/p", found: true, valid: true, problems: [], loadedAt: 1, refusedAt: null };
const CSRF_ADMIN = { "X-Mandu-Control": "1", Cookie: ADMIN_COOKIE, "Content-Type": "application/json" };

const EDITS = [
  { op: "lock-path", path: "~/work/.env", level: "no-model" },
  { op: "trust-origin", kind: "url", pattern: "https://pypi.org/" },
  { op: "release", to: { host: "pastebin.com" }, mode: "block" },
];
const PYPI = { facet: "origins", direction: "relax" as const, subject: "URL:https://pypi.org/", detail: "d" };
const PREVIEW: PreviewResult = { ok: true, relaxations: [PYPI], tightenings: [], perEdit: [{ loosens: false }, { loosens: true }, { loosens: false }] };

function model(text: string, seen: Array<{ system: string; user: string }> = []): () => Promise<AssistantModel> {
  return async () => ({ async complete(call) { seen.push(call); return { text, model: "claude-haiku-mock" }; } });
}

function fakeArbiter(opts: { preview?: PreviewResult; previewOnApply?: PreviewResult; propose?: "applied" | "filed" | "filed-wider" | "refiled" } = {}) {
  const calls: string[] = [];
  let previews = 0;
  const arbiter: PolicyDocArbiter = {
    async policyDocument() { return { status: STATUS, inForce: null, onDisk: { text: null, parsed: null, problems: [] } }; },
    async applyPolicyDocument() { return { path: "/p", status: STATUS }; },
    async mintUserRule() { return { id: "r", path: "/p", status: STATUS }; },
    async exportDbLabels() { return { added: 0, path: "/p", status: STATUS }; },
    async policyExplain(args) { calls.push(`explain:${args.audience}`); return { locks: [], pendingAskCount: 0 }; },
    async policySchema() { calls.push("schema"); return { edits: { type: "array", title: "SCHEMA-MARKER" } }; },
    async policyPreview() {
      calls.push("preview");
      previews++;
      return previews > 1 && opts.previewOnApply ? opts.previewOnApply : (opts.preview ?? PREVIEW);
    },
    async policyPropose(r) {
      calls.push(`propose:${r.requestedBy}`);
      if (opts.propose === "applied") return { applied: true, changeId: "pc-000001" };
      const relaxes = opts.propose === "filed-wider" ? [PYPI, { facet: "user-rules", subject: "r-0001" }] : [PYPI];
      return { applied: false, proposalId: "pp-000001", relaxes };
    },
    async resolvePolicyProposal(id, verdict, by) {
      calls.push(`resolve:${id}:${verdict}:${by}`);
      const p = { id, edits: EDITS, reason: null, requestedBy: "assistant", sessionKey: null, relaxes: [PYPI], tightens: [], status: "approved" as const, createdAt: 1, resolvedAt: 2, resolvedBy: by ?? null, changeId: "pc-000002", supersededBy: null };
      if (opts.propose === "refiled" && id === "pp-000001" && verdict === "approved") {
        return { proposal: { ...p, status: "superseded" as const }, refiled: { ...p, id: "pp-000002", status: "pending" as const } };
      }
      return { proposal: { ...p, status: verdict }, ...(verdict === "approved" ? { changeId: "pc-000002" } : {}) };
    },
  };
  return { arbiter, calls };
}

async function start(arbiter: PolicyDocArbiter, assistantModel: () => Promise<AssistantModel>, extra: { fileBrowserHome?: string } = {}) {
  const server = new DashboardServer({ source: fakeSource, policyDocArbiter: arbiter, assistantModel, log: () => {}, ...ADMIN_OPTS, ...extra });
  const port = await server.listen(0);
  return { base: `http://127.0.0.1:${port}`, close: () => server.close() };
}

const post = (base: string, path: string, body: unknown, headers: Record<string, string> = CSRF_ADMIN) =>
  fetch(base + path, { method: "POST", headers, body: JSON.stringify(body) });

// ── the pure module ──────────────────────────────────────────────────────────

test("the prompt carries the schema and the current rules; the sentence is fenced", () => {
  assert.match(assistantSystemPrompt({ title: "SCHEMA-MARKER" }), /SCHEMA-MARKER/);
  assert.match(assistantSystemPrompt({}), /Never invent a host, site or path/);
  assert.match(assistantSystemPrompt({}), /lock-blob .* only with an id the person gave/, "plan 14 §8.2: the blob lock is offered, never guessed");
  const u = assistantUserMessage("keep .env secret", { locks: [{ path: "/x" }] });
  assert.match(u, /"path":"\/x"/);
  assert.match(u, /<<<\nkeep \.env secret\n>>>/);
});

test("suggestRules: the current rules the model reads list the declared models, the key's variable name only", async () => {
  const models = [
    { name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", model: "llama3.2", local: true },
    { name: "gateway", url: "https://llm.example.com/v1", wire: "anthropic", local: false, tokenEnv: "GATEWAY_TOKEN" },
  ];
  const seen: Array<{ system: string; user: string }> = [];
  const arbiter = {
    async policyExplain() { return { locks: [], models }; },
    async policySchema() { return { edits: { type: "array" } }; },
    async policyPreview(): Promise<PreviewResult> { throw new Error("no edits, no preview"); },
  };
  const r = await suggestRules({ arbiter, model: model(JSON.stringify({ edits: [], note: "" }), seen) }, "which models are set up?");
  assert.deepEqual(r.edits, []);
  const current = JSON.parse(/Current rules \(JSON\):\n(.*)\n/.exec(seen[0]!.user)![1]!) as { models: unknown };
  assert.deepEqual(current.models, models, "the models are part of the context, as listed");
  assert.match(seen[0]!.user, /"tokenEnv":"GATEWAY_TOKEN"/);
});

test("parse: one JSON object (fence allowed); anything else is refused, never guessed", () => {
  assert.deepEqual(parseAssistantAnswer(JSON.stringify({ edits: EDITS, note: "ok" })), { edits: EDITS, note: "ok" });
  assert.deepEqual(parseAssistantAnswer("```json\n" + JSON.stringify({ edits: [] }) + "\n```"), { edits: [], note: null });
  assert.equal(parseAssistantAnswer(JSON.stringify({ edits: [], note: "x".repeat(5000) })).note?.length, 1000);
  for (const bad of ["Sure! Here are your rules: lock .env", "[1,2]", JSON.stringify({ note: "no edits" }), `${JSON.stringify({ edits: [] })} and more`]) {
    assert.throws(() => parseAssistantAnswer(bad), AssistantAnswerError, bad);
  }
});

test("suggestRules: rows from the grammar, marked per edit; expected = the preview's loosenings", async () => {
  const { arbiter, calls } = fakeArbiter();
  const seen: Array<{ system: string; user: string }> = [];
  const s = await suggestRules({ arbiter: arbiter as never, model: model(JSON.stringify({ edits: EDITS, note: "I left out ~/.ssh: already locked." }), seen) }, "keep .env secret, trust pypi, never paste");
  assert.deepEqual(s.rows.map((r) => r.loosens), [false, true, false]);
  assert.equal(s.rows[0]!.parts.map((p) => p.text).join(""), "Make ~/work/.env a secret no AI may read");
  assert.deepEqual(s.expected, [relaxKey(PYPI)]);
  assert.equal(s.loosens.length, 1);
  assert.equal(s.note, "I left out ~/.ssh: already locked.");
  assert.deepEqual(calls, ["explain:assistant", "schema", "preview"]);
  assert.match(seen[0]!.system, /SCHEMA-MARKER/);
});

test("suggestRules: each wide row carries what it opens, and the suggestion the foot's sentences (dashboard.md §4.25 *A wide change says what is open*)", async () => {
  const edits = [
    { op: "lock-path", path: "~/work/.env", level: "no-model" },
    { op: "allow-connect", host: "*" },
    { op: "release", from: { host: "docs.python.org" }, to: { host: "*" }, mode: "allow" },
  ];
  const preview: PreviewResult = { ok: true, relaxations: [], tightenings: [], perEdit: [{ loosens: false }, { loosens: true }, { loosens: true }] };
  const s = await suggestRules({ arbiter: fakeArbiter({ preview }).arbiter as never, model: model(JSON.stringify({ edits })) }, "let it reach anything");
  const said = (list: Array<Array<{ text: string }>>) => list.map((parts) => parts.map((p) => p.text).join(""));
  assert.deepEqual(s.rows.map((r) => r.overBroad), [false, true, true]);
  assert.deepEqual(s.rows.map((r) => said(r.overBroadWhy)), [
    [],
    ["This lets your agent's programs connect to any address."],
    ["This lets masked data from docs.python.org be sent anywhere."],
  ]);
  assert.deepEqual(said(s.overBroadWhy), ["This lets your agent's programs connect to any address.", "This lets masked data from docs.python.org be sent anywhere."]);
  assert.deepEqual(s.edits, edits, "the words change, nothing Apply sends does");
});

test("suggestRules: no channel ⇒ unconfigured before the arbiter is read; an invalid suggestion ⇒ problems", async () => {
  const { arbiter, calls } = fakeArbiter();
  await assert.rejects(
    suggestRules({ arbiter: arbiter as never, model: async () => { throw new AssistantUnconfiguredError("no ANTHROPIC_API_KEY and no claude/codex CLI on PATH"); } }, "lock .env"),
    AssistantUnconfiguredError,
  );
  assert.deepEqual(calls, [], "nothing is read without a channel");
  const bad = fakeArbiter({ preview: { ok: false, problems: ["edits[0] (lock-path): path: must be a non-empty string"] } });
  await assert.rejects(suggestRules({ arbiter: bad.arbiter as never, model: model(JSON.stringify({ edits: [{ op: "lock-path", path: "", level: "no-model" }] })) }, "lock"), /not a valid rule change/);
});

// ── the page's home folder (dashboard.md §4.34) ─────────────────────────────

const HOME = "/home/alice";
const HOME_EDITS = [
  { op: "lock-path", path: "/home/alice/proj/.env", level: "no-model" },
  { op: "unlock-path", path: "~/proj/notes.md" },
  { op: "unlock-path", path: "/srv/shared/other.env" },
  { op: "lock-path", path: "/home/alice2/x.env", level: "any-model" },
  { op: "release", to: { host: "pastebin.com" }, mode: "block" },
];
/** The arbiter's preview names a path normalized (path-labels.ts
 *  `normalizeLabelPath` expands `~/`). */
const homePreview = (home: string): Extract<PreviewResult, { ok: true }> => ({
  ok: true,
  relaxations: [
    { facet: "paths", direction: "relax", subject: `${home}/proj/notes.md`, detail: "d" },
    { facet: "paths", direction: "relax", subject: "/srv/shared/other.env", detail: "d" },
    { facet: "paths", direction: "relax", subject: "/home/alice2/x.env", detail: "d" },
  ],
  tightenings: [{ facet: "paths", direction: "tighten", subject: `${home}/proj/.env`, detail: "d" }],
  perEdit: [{ loosens: false }, { loosens: true }, { loosens: true }, { loosens: true }, { loosens: false }],
});
const said = (parts: ReadonlyArray<{ text: string }>): string => parts.map((p) => p.text).join("");

test("suggestRules with the page's home: a file under it reads ~/…, however the assistant wrote it; edits and expected stay as the arbiter has them", async () => {
  const answer = JSON.stringify({ edits: HOME_EDITS });
  const preview = homePreview(HOME);
  const shown = await suggestRules({ arbiter: fakeArbiter({ preview }).arbiter as never, model: model(answer), home: HOME }, "lock .env, free notes.md and other.env");
  assert.deepEqual(shown.rows.map((r) => said(r.parts)), [
    "Make ~/proj/.env a secret no AI may read",
    "Remove the rule for ~/proj/notes.md",
    "Remove the rule for /srv/shared/other.env",
    "Make /home/alice2/x.env a secret any AI may read when it asks",
    "Always block sending masked data from anywhere to pastebin.com",
  ], "outside the home, another account's home and a host: as written");
  assert.deepEqual(shown.loosens.map((l) => said(l.line)), [
    "~/proj/notes.md would be protected less",
    "/srv/shared/other.env would be protected less",
    "/home/alice2/x.env would be protected less",
  ], "the path the arbiter expanded reads as its row does");
  const recorded = await suggestRules({ arbiter: fakeArbiter({ preview }).arbiter as never, model: model(answer) }, "lock .env, free notes.md and other.env");
  assert.deepEqual(recorded.rows.slice(0, 2).map((r) => said(r.parts)), ["Make /home/alice/proj/.env a secret no AI may read", "Remove the rule for ~/proj/notes.md"], "no home: every path as recorded");
  assert.equal(said(recorded.loosens[0]!.line), "/home/alice/proj/notes.md would be protected less");
  // Apply is bound to these: the words change, nothing it sends does.
  assert.deepEqual(shown.edits, HOME_EDITS);
  assert.deepEqual(shown.expected, preview.relaxations.map(relaxKey));
  assert.deepEqual(shown.expected, recorded.expected);
  assert.deepEqual(shown.rows.map((r) => [r.loosens, r.overBroad, r.tryable]), recorded.rows.map((r) => [r.loosens, r.overBroad, r.tryable]));
});

test("the suggest route names a file under the server's home ~/… (fileBrowserHome, else the account's home)", async () => {
  for (const [home, extra] of [[HOME, { fileBrowserHome: HOME }], [homedir(), {}]] as const) {
    const preview = homePreview(home);
    const srv = await start(fakeArbiter({ preview }).arbiter, model(JSON.stringify({ edits: [{ op: "lock-path", path: `${home}/proj/.env`, level: "no-model" }, ...HOME_EDITS.slice(1)] })), extra);
    try {
      const r = await post(srv.base, "/api/policy/assistant", { sentence: "lock .env" });
      assert.equal(r.status, 200, home);
      const body = (await r.json()) as { rows: Array<{ parts: Array<{ text: string }> }>; loosens: Array<{ line: Array<{ text: string }> }>; expected: string[] };
      assert.equal(said(body.rows[0]!.parts), "Make ~/proj/.env a secret no AI may read", home);
      assert.equal(said(body.loosens[0]!.line), "~/proj/notes.md would be protected less", home);
      assert.deepEqual(body.expected, preview.relaxations.map(relaxKey), "Apply's binding: the arbiter's own subjects");
    } finally {
      await srv.close();
    }
  }
});

// ── the routes ───────────────────────────────────────────────────────────────

test("routes: both POSTs need CSRF + the admin session; suggest answers 200 / 422 / 503 unconfigured", async () => {
  const { arbiter } = fakeArbiter();
  const srv = await start(arbiter, model(JSON.stringify({ edits: EDITS })));
  try {
    assert.equal((await post(srv.base, "/api/policy/assistant", { sentence: "x" }, { "Content-Type": "application/json" })).status, 403);
    assert.equal((await post(srv.base, "/api/policy/assistant/apply", { edits: EDITS, expected: [] }, { "Content-Type": "application/json" })).status, 403);
    assert.equal((await post(srv.base, "/api/policy/assistant", { sentence: "" })).status, 400);
    const ok = await post(srv.base, "/api/policy/assistant", { sentence: "keep .env secret" });
    assert.equal(ok.status, 200);
    const body = (await ok.json()) as { rows: unknown[]; expected: string[]; edits: unknown[] };
    assert.equal(body.rows.length, 3);
    assert.deepEqual(body.edits, EDITS);
  } finally {
    await srv.close();
  }
  const prose = await start(fakeArbiter().arbiter, model("Sure, I locked it."));
  try {
    const r = await post(prose.base, "/api/policy/assistant", { sentence: "lock .env" });
    assert.equal(r.status, 422);
  } finally {
    await prose.close();
  }
  const none = await start(fakeArbiter().arbiter, async () => { throw new AssistantUnconfiguredError("no channel"); });
  try {
    const r = await post(none.base, "/api/policy/assistant", { sentence: "lock .env" });
    assert.equal(r.status, 503);
    assert.equal(((await r.json()) as { unconfigured?: boolean }).unconfigured, true);
  } finally {
    await none.close();
  }
});

test("apply: a tightening applies; a loosening is approved by the same click; more than shown ⇒ 409, nothing applied", async () => {
  const cases: Array<[Parameters<typeof fakeArbiter>[0], number, string[]]> = [
    [{ propose: "applied" }, 200, ["preview", "propose:assistant"]],
    [{ propose: "filed" }, 200, ["preview", "propose:assistant", "resolve:pp-000001:approved:human:dashboard"]],
    [{ previewOnApply: { ok: true, relaxations: [PYPI, { facet: "user-rules", direction: "relax", subject: "r-0001", detail: "d" }], tightenings: [], perEdit: [] } }, 409, ["preview"]],
    [{ propose: "filed-wider" }, 409, ["preview", "propose:assistant", "resolve:pp-000001:denied:human:dashboard"]],
    [{ propose: "refiled" }, 409, ["preview", "propose:assistant", "resolve:pp-000001:approved:human:dashboard", "resolve:pp-000002:denied:human:dashboard"]],
  ];
  for (const [opts, status, want] of cases) {
    const { arbiter, calls } = fakeArbiter(opts);
    const srv = await start(arbiter, model("{}"));
    try {
      // The first preview (the suggestion) happened on another request: count from here.
      await arbiter.policyPreview!(EDITS);
      calls.length = 0;
      const r = await post(srv.base, "/api/policy/assistant/apply", { edits: EDITS, expected: [relaxKey(PYPI)] });
      assert.equal(r.status, status, JSON.stringify(opts));
      assert.deepEqual(calls, want, JSON.stringify(opts));
    } finally {
      await srv.close();
    }
  }
});

// ── models are read-only here (§4.3a) ───────────────────────────────────────

const MODEL_EDITS = [
  { op: "add-model", name: "lab", url: "http://203.0.113.9:8000", local: true },
  { op: "update-model", name: "ollama", url: "http://127.0.0.1:11434" },
  { op: "remove-model", name: "gateway" },
];

test("models: the prompt says they cannot be changed here; modelEditProblems names index and op only", () => {
  assert.match(assistantSystemPrompt({}), /models in the current rules are shown for reference only; they cannot be changed here/);
  assert.match(assistantSystemPrompt({}), /Settings › Models/);
  assert.deepEqual(modelEditProblems([EDITS[0], ...MODEL_EDITS]), [
    "edits[1] (add-model): models are changed in Settings › Models, not from the Describe box",
    "edits[2] (update-model): models are changed in Settings › Models, not from the Describe box",
    "edits[3] (remove-model): models are changed in Settings › Models, not from the Describe box",
  ]);
  assert.deepEqual(modelEditProblems(EDITS), []);
  assert.deepEqual(modelEditProblems([null, "add-model", { op: 5 }]), []);
});

test("models: an answer carrying a model op is refused before any preview; the route answers 422", async () => {
  for (const m of MODEL_EDITS) {
    const { arbiter, calls } = fakeArbiter();
    await assert.rejects(
      suggestRules({ arbiter: arbiter as never, model: model(JSON.stringify({ edits: [EDITS[0], m] })) }, "use my lab model"),
      (err: unknown) => err instanceof AssistantAnswerError && err.message === MODELS_ELSEWHERE && err.problems.length === 1 && err.problems[0]!.includes(`(${m.op})`),
    );
    assert.deepEqual(calls, ["explain:assistant", "schema"], "no preview of a model change");
  }
  const { arbiter, calls } = fakeArbiter();
  const srv = await start(arbiter, model(JSON.stringify({ edits: [MODEL_EDITS[0]] })));
  try {
    const r = await post(srv.base, "/api/policy/assistant", { sentence: "use my lab model" });
    assert.equal(r.status, 422);
    const body = (await r.json()) as { error: string; problems: string[] };
    assert.equal(body.error, MODELS_ELSEWHERE);
    assert.equal(calls.includes("preview"), false);
  } finally {
    await srv.close();
  }
});

test("models: Apply with a model op is refused (422) before any preview or propose", async () => {
  for (const m of MODEL_EDITS) {
    const { arbiter, calls } = fakeArbiter({ propose: "applied" });
    const srv = await start(arbiter, model("{}"));
    try {
      const r = await post(srv.base, "/api/policy/assistant/apply", { edits: [EDITS[0], m], expected: [] });
      assert.equal(r.status, 422, m.op);
      const body = (await r.json()) as { error: string; problems: string[] };
      assert.equal(body.error, MODELS_ELSEWHERE);
      assert.match(body.problems[0]!, new RegExp(`^edits\\[1\\] \\(${m.op}\\)`));
      assert.deepEqual(calls, [], "the arbiter is not asked anything");
    } finally {
      await srv.close();
    }
  }
});

// ── "Try it" ─────────────────────────────────────────────────────────────────

test("tryProbe: a website row probes the site (scheme and wildcard handled); a release probes the flow; other rows have none", () => {
  assert.deepEqual(tryProbe({ op: "trust-origin", kind: "url", pattern: "https://pypi.org/" }), { source: { tool: "WebFetch", origin: "https://pypi.org/" } });
  assert.deepEqual(tryProbe({ op: "distrust-origin", kind: "url", pattern: "*.corp.net" }), { source: { tool: "WebFetch", origin: "https://www.corp.net/" } });
  assert.deepEqual(tryProbe({ op: "trust-origin", kind: "url", pattern: "github.com/myorg" }), { source: { tool: "WebFetch", origin: "https://github.com/myorg" } });
  assert.deepEqual(tryProbe({ op: "release", from: { host: "docs.python.org" }, to: { host: "api.example.com" }, mode: "allow" }), {
    source: { tool: "WebFetch", origin: "https://docs.python.org/" }, destination: "https://api.example.com/", boundary: "network",
  });
  assert.equal(tryProbe({ op: "release", to: { host: "*" }, mode: "allow" }), null, "no single destination to probe");
  assert.equal(tryProbe({ op: "release", to: { host: "@svc" }, mode: "allow" }), null);
  assert.equal(tryProbe({ op: "lock-path", path: "/x", level: "no-model" }), null);
  assert.equal(tryProbe({ op: "trust-origin", kind: "dir", pattern: "/x" }), null);
});

test("tryLine: the probe's answer in plain words", () => {
  const trust = { op: "trust-origin", kind: "url", pattern: "pypi.org" };
  const text = (parts: Array<{ text: string }>) => parts.map((p) => p.text).join("");
  assert.equal(text(tryLine(trust, { inbound: { trust: "TRUSTED" } })), "Content from pypi.org reaches the AI unmasked");
  assert.equal(text(tryLine(trust, { inbound: { trust: "UNTRUSTED" } })), "Content from pypi.org is masked for the AI");
  const rel = { op: "release", to: { host: "paste.example" }, mode: "block" };
  assert.equal(text(tryLine(rel, { egress: { decision: { allow: false, requiresApproval: true } } })), "Data from a-page-you-visit.example to paste.example waits for you to allow it");
  assert.equal(text(tryLine(rel, { egress: { decision: { allow: false } } })), "Data from a-page-you-visit.example to paste.example is blocked");
  assert.equal(text(tryLine(rel, { egress: { decision: { allow: true } } })), "Data from a-page-you-visit.example to paste.example is sent without asking");
});

test("the try route: probes the law now and WITH the whole suggestion; a row with nothing to try is a 400; CSRF + admin", async () => {
  const seen: unknown[] = [];
  const { arbiter } = fakeArbiter();
  arbiter.testFlow = async (req: unknown) => {
    seen.push(req);
    return { inbound: { trust: (req as { withEdits?: unknown }).withEdits ? "TRUSTED" : "UNTRUSTED" } };
  };
  const srv = await start(arbiter, model("{}"));
  try {
    assert.equal((await post(srv.base, "/api/policy/assistant/try", { edits: EDITS, index: 1 }, { "Content-Type": "application/json" })).status, 403);
    const r = await post(srv.base, "/api/policy/assistant/try", { edits: EDITS, index: 1 });
    assert.equal(r.status, 200);
    const body = (await r.json()) as { now: Array<{ text: string }>; after: Array<{ text: string }> };
    assert.match(body.now.map((p) => p.text).join(""), /is masked/);
    assert.match(body.after.map((p) => p.text).join(""), /reaches the AI unmasked/);
    assert.deepEqual(seen, [
      { source: { tool: "WebFetch", origin: "https://pypi.org/" } },
      { source: { tool: "WebFetch", origin: "https://pypi.org/" }, withEdits: EDITS },
    ]);
    assert.equal((await post(srv.base, "/api/policy/assistant/try", { edits: EDITS, index: 0 })).status, 400, "a lock row has nothing to try");
    assert.equal((await post(srv.base, "/api/policy/assistant/try", { edits: EDITS, index: 9 })).status, 400);
  } finally {
    await srv.close();
  }
});
