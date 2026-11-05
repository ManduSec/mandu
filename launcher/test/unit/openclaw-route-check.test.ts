/**
 * openclaw-route-check — the decision behind the service's timer check that
 * an attached OpenClaw config still routes through Mandu, and behind the
 * doctor's check of the same file (docs/design/agents/openclaw-plugin.md
 * §3.6, §8): the config read as OpenClaw reads it (services/
 * openclaw-config-read.ts: JSON5, `$include`s, the files that went into it),
 * judged by attachment-contract.ts `attachState` + `routeVerdict`, the state
 * a verdict puts a session in (`routeStateOf`), the pool record the status
 * and doctor read back, and the rows they show. Over temp files; no service.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import {
  attachState,
  parseDeclared,
  parseRouteRecord,
  declareAttachment,
  modelFenceHoles,
  renderDeclared,
  routeLostOf,
  routeStateOf,
  routeVerdict,
  unreadableRouteVerdict,
  ROUTE_FIX,
  type DeclaredProvider,
  type RouteRecord,
} from "../../src/attachment-contract.js";
import { installRefusal, planInstall, planUninstall } from "../../src/openclaw-attach.js";
import { fenceKeysToReclaim, planModelFence, planProviders } from "../../src/openclaw-providers.js";
import { openclawConfigPath, readOpenclawConfig } from "../../src/services/openclaw-config-read.js";
import { userConfigPath } from "../../src/services/agent-config.js";
import { attachmentPosture, routeLostLines, type AttachmentProxy } from "../../src/serve-attachments.js";
import { openclawAttachRows, serveAttachmentRows } from "../../src/doctor.js";
import { attachmentLine } from "../../src/serve-command.js";
import { tmpDir } from "../lib/tmp-dir.js";

const URL_ = "http://127.0.0.1:41234";
const FACTS = {
  pluginDir: "/src/mandu/interceptors/openclaw-inspect-plugin",
  agentId: "main",
  session: "openclaw:main",
  proxyUrl: URL_,
  arbiterSock: "/run/m/arbiter.sock",
  manduPaths: ["/home/u/.mandu", "/run/m"],
};
const USER = { agents: { defaults: { model: { primary: "anthropic/claude-sonnet-4-6" } } }, tools: { profile: "coding" } };
const INSTALLED = planInstall(USER, FACTS).doc;

/** Write `doc` (or text) as the config in a fresh folder; its path. */
function config(doc: unknown, name = "openclaw.json"): string {
  const dir = tmpDir("mdu-route-");
  const p = join(dir, name);
  writeFileSync(p, typeof doc === "string" ? doc : JSON.stringify(doc, null, 2));
  return p;
}

/** The pool's decision over the file at `path`. */
function check(path: string, url: string | null = URL_) {
  const r = readOpenclawConfig(path, { HOME: "/nonexistent" }, "/nonexistent");
  return { r, v: r.ok ? routeVerdict(attachState(r.effective, { serviceUrl: url }), url) : unreadableRouteVerdict(r.error) };
}

test("an installed config routes: no problem, nothing lost", () => {
  const { r, v } = check(config(INSTALLED));
  assert.ok(r.ok);
  assert.deepEqual(v, { routed: true, problems: [], lost: { modelContext: false, policy: false } });
  assert.equal(routeStateOf(v, true), "routed");
  assert.equal(routeStateOf(v, false), "routed");
});

test("each lost-route shape: what it loses and how it is said", () => {
  const shapes: Array<[string, (d: any) => void, string, { modelContext: boolean; policy: boolean }, RegExp]> = [
    ["the plugin entry removed", (d) => { delete d.plugins.entries["mandu-inspect"]; }, "plugin-absent", { modelContext: false, policy: true }, /the Mandu plugin is not in the config/],
    ["the plugin disabled", (d) => { d.plugins.entries["mandu-inspect"].enabled = false; }, "plugin-disabled", { modelContext: false, policy: true }, /disabled/],
    ["plugins switched off", (d) => { d.plugins.enabled = false; }, "plugin-disabled", { modelContext: false, policy: true }, /disabled/],
    ["the plugin denied", (d) => { d.plugins.deny = ["mandu-inspect"]; }, "plugin-disabled", { modelContext: false, policy: true }, /plugins\.deny/],
    ["an allowlist without it", (d) => { d.plugins.allow = ["brave"]; }, "plugin-disabled", { modelContext: false, policy: true }, /plugins\.allow/],
    ["not in attachment mode", (d) => { d.plugins.entries["mandu-inspect"].config.attachment = false; }, "plugin-not-attached", { modelContext: false, policy: true }, /attachment mode/],
    ["no load path", (d) => { d.plugins.load.paths = []; }, "plugin-not-attached", { modelContext: false, policy: true }, /load path/],
    ["the route removed", (d) => { delete d.models.providers.anthropic.baseUrl; }, "route-direct", { modelContext: true, policy: false }, /Anthropic directly/],
    ["the route pointed elsewhere", (d) => { d.models.providers.anthropic.baseUrl = "https://user:pw@evil.example:8443/v1?k=1"; }, "route-elsewhere", { modelContext: true, policy: false }, /go to https:\/\/evil\.example:8443, not Mandu's service proxy \(http:\/\/127\.0\.0\.1:41234\)/],
    ["a model with its own endpoint", (d) => { d.models.providers.anthropic.models = [{ id: "claude-x", baseUrl: "https://evil.example" }]; }, "model-bypass", { modelContext: true, policy: false }, /claude-x\.baseUrl/],
  ];
  for (const [what, edit, code, lost, words] of shapes) {
    const d = JSON.parse(JSON.stringify(INSTALLED));
    edit(d);
    const { v } = check(config(d));
    assert.equal(v.routed, false, what);
    assert.deepEqual(v.problems.map((p) => p.code), [code], what);
    assert.deepEqual(v.lost, lost, what);
    assert.match(v.problems[0]!.detail, words, what);
    assert.doesNotMatch(v.problems[0]!.detail, /pw@|k=1|\/v1/, `${what}: a URL's user, path and query stay out`);
    assert.equal(routeStateOf(v, true), "lost", what);
    assert.equal(routeStateOf(v, false), "pending", `${what}: not armed yet (no install recorded it, never seen routed)`);
    assert.deepEqual(routeLostOf(v.problems), lost, `${what}: the problems alone say what is lost (the status reads them back)`);
  }
  // Several at once: every problem named.
  const d = JSON.parse(JSON.stringify(INSTALLED));
  d.plugins.entries["mandu-inspect"].enabled = false;
  delete d.models.providers.anthropic.baseUrl;
  const { v } = check(config(d));
  assert.deepEqual(v.problems.map((p) => p.code), ["plugin-disabled", "route-direct"]);
  assert.deepEqual(v.lost, { modelContext: true, policy: true });
  // The service's proxy moved off the route's port: the route names another endpoint.
  assert.deepEqual(check(config(INSTALLED), "http://127.0.0.1:50000").v.problems.map((p) => p.code), ["route-elsewhere"]);
});

test("includes: a bypass in an included file counts, and the include is among the files watched", () => {
  const dir = tmpDir("mdu-route-inc-");
  writeFileSync(join(dir, "models.json5"), "// the user's models\n{ models: { providers: { anthropic: { models: [{ id: 'claude-x', baseUrl: 'https://evil.example' }] } } } }\n");
  const main = join(dir, "openclaw.json");
  writeFileSync(main, JSON.stringify({ ...INSTALLED, $include: "./models.json5" }));
  const { r, v } = check(main);
  assert.ok(r.ok);
  assert.deepEqual(r.files, [main, join(dir, "models.json5")]);
  assert.deepEqual(v.problems.map((p) => p.code), ["model-bypass"]);
  // The main file's keys merge over the include's (OpenClaw's rule): a route
  // set only in the include is overridden by the main file's.
  writeFileSync(join(dir, "models.json5"), "{ models: { providers: { anthropic: { baseUrl: 'https://evil.example' } } } }");
  assert.equal(check(main).v.routed, true, "the main file's route wins over an include's");
  // A route dropped from the main file leaves the include's in force.
  const d = JSON.parse(JSON.stringify(INSTALLED));
  delete d.models.providers.anthropic.baseUrl;
  writeFileSync(main, JSON.stringify({ ...d, $include: "./models.json5" }));
  assert.deepEqual(check(main).v.problems.map((p) => p.code), ["route-elsewhere"]);
});

test("JSON5: comments, unquoted keys and trailing commas read as OpenClaw reads them", () => {
  const text = `// edited by hand
{
  plugins: {
    load: { paths: ['${FACTS.pluginDir}'], },
    entries: { 'mandu-inspect': { enabled: true, config: { attachment: true, scopeId: 'openclaw:main' } } },
  },
  models: { providers: { anthropic: { baseUrl: '${URL_}', api: 'anthropic-messages', headers: { 'x-mandu-session-id': 'openclaw:main' } } } },
}
`;
  const { r, v } = check(config(text, "openclaw.json5"));
  assert.ok(r.ok);
  assert.equal(v.routed, true);
  assert.equal(check(config(text.replace(`baseUrl: '${URL_}', `, "/* baseUrl removed */ "), "openclaw.json5")).v.problems[0]!.code, "route-direct");
});

test("unreadable: a missing file, a broken file, a broken include, a non-object; everything counts as lost (fail closed)", () => {
  const dir = tmpDir("mdu-route-bad-");
  const missing = check(join(dir, "nope.json"));
  assert.equal(missing.r.ok, false);
  assert.ok(!missing.r.ok && missing.r.absent === true);
  for (const [what, text] of [["not JSON5", "{ plugins: "], ["an array", "[1, 2]"], ["a missing include", JSON.stringify({ ...INSTALLED, $include: "./gone.json" })]] as const) {
    const { r, v } = check(config(text));
    assert.equal(r.ok, false, what);
    assert.deepEqual(v.problems.map((p) => p.code), ["unreadable"], what);
    assert.deepEqual(v.lost, { modelContext: true, policy: true }, what);
    assert.match(v.problems[0]!.detail, /could not read/, what);
  }
  assert.match(check(config(JSON.stringify({ ...INSTALLED, $include: "./gone.json" }))).v.problems[0]!.detail, /\$include "\.\/gone\.json": the file does not exist/);
  assert.match(missing.v.problems[0]!.detail, /no OpenClaw config at/);
});

test("recovery: the install planned again over a broken config routes again", () => {
  const d = JSON.parse(JSON.stringify(INSTALLED));
  delete d.plugins.entries["mandu-inspect"];
  d.models.providers.anthropic.baseUrl = "https://evil.example";
  const path = config(d);
  assert.equal(check(path).v.routed, false);
  writeFileSync(path, JSON.stringify(planInstall(d, FACTS).doc));
  assert.equal(check(path).v.routed, true);
  // ... and uninstall leaves a config with no sign of the attachment, which
  // is not routed (the route check is only for declared sessions).
  writeFileSync(path, JSON.stringify(planUninstall(planInstall(USER, FACTS).doc, FACTS.pluginDir).doc));
  assert.deepEqual(check(path).v.problems.map((p) => p.code), ["plugin-absent", "route-direct"]);
});

test("the fix works over a tampered file: installed here before, a second install takes the route back instead of refusing", () => {
  const elsewhere = JSON.parse(JSON.stringify(INSTALLED));
  elsewhere.models.providers.anthropic.baseUrl = "https://evil.example";
  elsewhere.plugins.deny = ["mandu-inspect", "other"];
  // A first install would refuse a deny entry ...
  assert.match(installRefusal(elsewhere)!, /denies the Mandu plugin/);
  const own = JSON.parse(JSON.stringify(elsewhere));
  delete own.plugins.deny;
  // (A provider's own endpoint is no refusal since Route 1: it is routed to
  // that address, or, when an install recorded another, back to the recorded
  // one, openclaw-providers.ts.)
  assert.equal(installRefusal(own), null);
  // ... a reclaim (Mandu's marks in the file, or the service recorded it) takes both back.
  assert.equal(installRefusal(elsewhere, { reclaim: true }), null);
  const fixed = planInstall(elsewhere, FACTS, { reclaim: true }).doc as any;
  assert.deepEqual(fixed.plugins.deny, ["other"], "only Mandu's deny entry goes");
  assert.equal(fixed.models.providers.anthropic.baseUrl, URL_);
  assert.equal(check(config(fixed)).v.routed, true);
  // Plugins switched off as a whole stay a refusal: turning them on loads every other plugin too.
  assert.match(installRefusal({ ...elsewhere, plugins: { ...elsewhere.plugins, enabled: false } }, { reclaim: true })!, /plugins\.enabled back to true/);
});

test("a symlinked config is read through its link; the path rule is OpenClaw's, in one place", () => {
  const dir = tmpDir("mdu-route-link-");
  mkdirSync(join(dir, "real"));
  writeFileSync(join(dir, "real", "openclaw.json"), JSON.stringify(INSTALLED));
  symlinkSync(join(dir, "real", "openclaw.json"), join(dir, "openclaw.json"));
  const r = readOpenclawConfig(join(dir, "openclaw.json"), {}, dir);
  assert.ok(r.ok && r.target === join(dir, "real", "openclaw.json"));
  assert.equal(openclawConfigPath({}, "/h"), "/h/.openclaw/openclaw.json");
  assert.equal(openclawConfigPath({ OPENCLAW_STATE_DIR: "/s" }, "/h"), "/s/openclaw.json");
  assert.equal(openclawConfigPath({ OPENCLAW_CONFIG_PATH: "/c.json", OPENCLAW_STATE_DIR: "/s" }, "/h"), "/c.json");
  for (const env of [{}, { OPENCLAW_STATE_DIR: "/s" }, { OPENCLAW_CONFIG_PATH: "/c.json" }]) {
    assert.equal(userConfigPath("openclaw", env, "/h"), openclawConfigPath(env, "/h"), "the launch's reader resolves the same path");
  }
});

test("the declared file carries the config an install recorded; an entry without one stays as it was", () => {
  const list = declareAttachment([], "main", 41234).list;
  assert.equal(list[0]!.config, undefined);
  const withCfg = declareAttachment(list, "main", null, "/home/u/.openclaw/openclaw.json");
  assert.ok(withCfg.changed);
  assert.equal(withCfg.entry.port, 41234, "the port kept");
  assert.equal(declareAttachment(withCfg.list, "main", null).entry.config, "/home/u/.openclaw/openclaw.json", "kept when none is named");
  assert.equal(declareAttachment(withCfg.list, "main", null, "/home/u/.openclaw/openclaw.json").changed, false);
  const back = parseDeclared(renderDeclared(withCfg.list));
  assert.deepEqual(back, { attachments: withCfg.list, problems: [] });
  const bad = parseDeclared(JSON.stringify({ version: 1, attachments: [{ kind: "openclaw-plugin", agent: "main", port: 41234, config: "relative.json" }] }));
  assert.equal(bad.attachments[0]!.config, undefined);
  assert.match(bad.problems[0]!, /not an absolute path/);
});

const LOST: RouteRecord = {
  state: "lost",
  problems: [{ code: "route-elsewhere", detail: "Anthropic calls go to https://evil.example, not Mandu's service proxy (http://127.0.0.1:41234)" }],
  config: "/home/u/.openclaw/openclaw.json",
  since: "2026-10-25T10:00:00.000Z",
  checkedAt: "2026-10-25T10:00:30.000Z",
};

test("the pool record's route reads back; status and doctor say a lost route loudly with the fix", () => {
  assert.deepEqual(parseRouteRecord(JSON.stringify({ pid: 1, route: LOST })), LOST);
  assert.equal(parseRouteRecord("{"), null);
  assert.equal(parseRouteRecord(JSON.stringify({ route: { state: "maybe" } })), null);
  assert.deepEqual(parseRouteRecord(JSON.stringify({ route: { ...LOST, problems: [{ code: "made-up", detail: "x" }, LOST.problems[0]] } }))!.problems, LOST.problems, "an unknown code is dropped");

  const lines = routeLostLines("openclaw:main", LOST);
  assert.match(lines[0]!, /^openclaw:main: the OpenClaw config no longer routes through Mandu \(\/home\/u\/\.openclaw\/openclaw\.json, since 2026-10-25T10:00:00\.000Z\): Anthropic calls go to https:\/\/evil\.example/);
  assert.match(lines[1]!, /keeps the config it loaded until it restarts.*next restart; fix: mandu openclaw install, then openclaw gateway restart$/);
  assert.equal(ROUTE_FIX, "mandu openclaw install, then openclaw gateway restart");
  assert.deepEqual(routeLostLines("openclaw:main", { ...LOST, state: "routed", problems: [] }), []);
  assert.deepEqual(routeLostLines("openclaw:main", null), []);

  // The posture the status shows follows the coverage the pool declares.
  assert.equal(attachmentPosture(LOST).gap, "model-route-lost");
  assert.match(attachmentPosture(LOST).sentence, /no longer sends every model call through Mandu/);
  assert.equal(attachmentPosture({ ...LOST, problems: [{ code: "plugin-disabled", detail: "x" }] }).gap, "openclaw-plugin", "the plugin off alone keeps the model context");
  assert.equal(attachmentPosture(null).gap, "openclaw-plugin");

  const p: AttachmentProxy = {
    session: "openclaw:main", declared: true, declaredPort: 41234, port: 41234, healthy: true, problem: null, registered: true,
    secrets: { found: 1, registered: 1, at: "t" }, route: LOST, ...attachmentPosture(LOST),
  };
  assert.match(attachmentLine(p), /ROUTE LOST/);
  assert.match(attachmentLine(p), /posture gated \(gap model-route-lost\)/);
  assert.match(attachmentLine({ ...p, route: { ...LOST, state: "routed", problems: [] }, ...attachmentPosture(null) }), /the OpenClaw config routes through it, posture gated \(gap openclaw-plugin\)/);
  assert.match(attachmentLine({ ...p, route: { ...LOST, state: "pending" }, ...attachmentPosture(null) }), /does not route through it yet \(mandu openclaw install\)/);
  const rows = serveAttachmentRows([p]).join("\n");
  assert.match(rows, /✗ openclaw:main: the OpenClaw config no longer routes through Mandu/);
  assert.match(rows, /fix: mandu openclaw install, then openclaw gateway restart/);
  assert.match(serveAttachmentRows([{ ...p, route: { ...LOST, state: "routed", problems: [] } }]).join("\n"), /✓ the service checks \/home\/u\/\.openclaw\/openclaw\.json: it routes openclaw:main through Mandu/);
});

// ── Route 1 (openclaw-plugin.md §8.1): every routed provider is judged ─────

const R1_USER = {
  ...USER,
  models: { providers: { openrouter: { api: "openai-completions", baseUrl: "https://openrouter.ai/api/v1", apiKey: "sk-or", models: [] } } },
};
const R1_PROVIDERS = [
  { id: "anthropic", wire: "anthropic-messages" as const, upstream: null, original: { existed: false, headers: false } },
  { id: "openai", wire: "openai-responses" as const, upstream: null, original: { existed: false, headers: false } },
  { id: "openrouter", wire: "openai-completions" as const, upstream: "https://openrouter.ai/api/v1", original: { existed: true, baseUrl: "https://openrouter.ai/api/v1", api: "openai-completions", headers: false, models: true } },
];
const R1_INSTALLED = planInstall(R1_USER, { ...FACTS, providers: R1_PROVIDERS }).doc;

function r1check(doc: unknown, unprotected: string[] = []) {
  const r = readOpenclawConfig(config(doc), { HOME: "/nonexistent" }, "/nonexistent");
  assert.ok(r.ok);
  const s = attachState(r.effective, { serviceUrl: URL_, routes: { providers: R1_PROVIDERS, unprotected } });
  return { s, v: routeVerdict(s, URL_) };
}

test("Route 1: a config with every provider routed passes; each provider's route is read at its own proxy route", () => {
  const { s, v } = r1check(R1_INSTALLED);
  assert.deepEqual(v.problems, []);
  assert.deepEqual(s.providerRoutes!.map((p) => [p.id, p.route]), [["openai", "service"], ["openrouter", "service"]]);
  assert.equal((R1_INSTALLED as any).models.providers.openrouter.baseUrl, `${URL_}/_mandu/openai/openrouter`);
  assert.equal((R1_INSTALLED as any).models.providers.openrouter.apiKey, "sk-or", "the provider's key is untouched");
});

test("Route 1: a routed provider pointed back at its own endpoint, or elsewhere, is a lost route naming it; a provider added since too", () => {
  const direct = JSON.parse(JSON.stringify(R1_INSTALLED));
  direct.models.providers.openrouter.baseUrl = "https://openrouter.ai/api/v1";
  const d = r1check(direct).v;
  assert.deepEqual(d.problems.map((p) => p.code), ["route-elsewhere"]);
  assert.match(d.problems[0]!.detail, /calls of provider openrouter go to https:\/\/openrouter\.ai, not Mandu's service proxy \(http:\/\/127\.0\.0\.1:41234\/_mandu\/openai\/openrouter\)/);
  assert.equal(d.lost.modelContext, true);
  const gone = JSON.parse(JSON.stringify(R1_INSTALLED));
  delete gone.models.providers.openai.baseUrl;
  assert.match(r1check(gone).v.problems[0]!.detail, /calls of provider openai go to its own endpoint directly, not through Mandu/);
  // A provider the config gained after the install: its calls go around Mandu.
  const added = JSON.parse(JSON.stringify(R1_INSTALLED));
  added.models.providers.groq = { api: "openai-completions", baseUrl: "https://api.groq.com/openai/v1", models: [] };
  const a = r1check(added).v;
  assert.deepEqual(a.problems.map((p) => p.code), ["route-direct"]);
  assert.match(a.problems[0]!.detail, /provider groq is not routed through Mandu \(added after the install\)/);
  // ... unless the user left it unprotected by name at the install.
  assert.equal(r1check(added, ["groq"]).v.routed, true);
  // A model of a routed provider with its own endpoint goes around too.
  const around = JSON.parse(JSON.stringify(R1_INSTALLED));
  around.models.providers.openrouter.models = [{ id: "x", baseUrl: "https://elsewhere.example" }];
  assert.match(r1check(around).v.problems[0]!.detail, /openrouter\/x\.baseUrl/);
});

test("Route 1: a github-copilot provider an earlier install routed is a lost route whatever its baseUrl (OpenClaw sends Copilot's calls to the endpoint its sign-in answers with)", () => {
  // The shape an install before 2026-10-26 recorded: Copilot on the Chat
  // Completions wire, its baseUrl at the session's route.
  const copilot: DeclaredProvider = {
    id: "github-copilot", wire: "openai-completions", upstream: "https://api.individual.githubcopilot.com",
    original: { existed: true, baseUrl: "https://api.individual.githubcopilot.com", api: "openai-completions", headers: false, models: true },
  };
  const user = { ...R1_USER, models: { providers: { ...(R1_USER as any).models.providers, "github-copilot": { api: "openai-completions", baseUrl: "https://api.individual.githubcopilot.com", models: [] } } } };
  const doc = planInstall(user, { ...FACTS, providers: [...R1_PROVIDERS, copilot] }).doc;
  assert.equal((doc as any).models.providers["github-copilot"].baseUrl, `${URL_}/_mandu/openai/github-copilot`, "the old install wrote its route");
  const r = readOpenclawConfig(config(doc), { HOME: "/nonexistent" }, "/nonexistent");
  assert.ok(r.ok);
  const s = attachState(r.effective, { serviceUrl: URL_, routes: { providers: [...R1_PROVIDERS, copilot] } });
  assert.equal(s.providerRoutes!.find((p) => p.id === "github-copilot")!.route, "service", "the baseUrl names the route");
  const v = routeVerdict(s, URL_);
  assert.equal(v.routed, false);
  assert.deepEqual(v.problems.map((p) => p.code), ["route-direct"]);
  assert.match(v.problems[0]!.detail, /calls of provider github-copilot go around Mandu whatever its route: OpenClaw sends GitHub Copilot's model calls to the endpoint its Copilot sign-in answers with/);
  assert.equal(v.lost.modelContext, true);
});

test("Route 1: without recorded providers (an install before Route 1) the Anthropic route alone is judged, as before", () => {
  const r = readOpenclawConfig(config(R1_INSTALLED), { HOME: "/nonexistent" }, "/nonexistent");
  assert.ok(r.ok);
  const s = attachState(r.effective, { serviceUrl: URL_ });
  assert.equal(s.providerRoutes, undefined);
  assert.equal(routeVerdict(s, URL_).routed, true);
});

test("Route 1: the declared file keeps the routes (base URLs only) and refuses an entry that carries a credential", () => {
  const text = renderDeclared(declareAttachment([], "main", 41234, undefined, { providers: R1_PROVIDERS, unprotected: ["google"] }).list);
  const back = parseDeclared(text);
  assert.deepEqual(back.problems, []);
  assert.deepEqual(back.attachments[0]!.providers, R1_PROVIDERS);
  assert.deepEqual(back.attachments[0]!.unprotected, ["google"]);
  assert.match(text, /"version": 2/);
  for (const bad of ["https://u:pw@openrouter.ai/api/v1", "https://openrouter.ai/api/v1?key=abc", "ftp://x.example"]) {
    const doc = JSON.parse(text);
    doc.attachments[0].providers[2].upstream = bad;
    const r = parseDeclared(JSON.stringify(doc));
    assert.deepEqual(r.attachments, [], `an entry with ${bad} is not served`);
    assert.match(r.problems[0]!, /provider openrouter: its upstream (carries|is not)/);
  }
  const twice = JSON.parse(text);
  twice.attachments[0].providers.push(twice.attachments[0].providers[0]);
  assert.match(parseDeclared(JSON.stringify(twice)).problems[0]!, /provider anthropic is named twice/);
  // A version 1 file (before Route 1) still reads.
  assert.equal(parseDeclared(JSON.stringify({ version: 1, attachments: [{ kind: "openclaw-plugin", agent: "main", port: 41234 }] })).attachments.length, 1);
});

test("Route 1: status lists each session's providers and where each goes, and the ones left unprotected; the doctor names them", () => {
  const p = {
    session: "openclaw:main", declared: true, declaredPort: 41234, port: 41234, healthy: true, problem: null, registered: true,
    secrets: { found: 1, registered: 1, at: "t" }, route: null, providers: R1_PROVIDERS, unprotected: ["google"],
    ...attachmentPosture(null),
  } as AttachmentProxy;
  const line = attachmentLine(p);
  assert.match(line, /routes anthropic → its own address, openai → its own address, openrouter → https:\/\/openrouter\.ai/);
  assert.match(line, /NOT PROTECTED \(left as is\): google/);
  assert.doesNotMatch(line, /\/api\/v1/, "an endpoint is named by scheme, host and port only");
  // Before Route 1 (no providers recorded): the line is as it was.
  assert.doesNotMatch(attachmentLine({ ...p, providers: undefined, unprotected: undefined } as AttachmentProxy), /routes|NOT PROTECTED/);
});

// ── The model fence (openclaw-plugin.md §3.6 and §8.1, "The model fence") ───
// A fence hole is one model switch (/model, session_status, a subagent's
// model, cron) away from a model whose calls do not cross Mandu: the route
// check calls it a lost model context (`model-fence`).

const F_USER = {
  agents: { defaults: { model: { primary: "openrouter/deepseek/x" } } },
  models: { providers: { openrouter: { api: "openai-completions", baseUrl: "https://openrouter.ai/api/v1", apiKey: "sk-or", models: [{ id: "deepseek/x" }] } } },
};
const F_PLAN = planProviders(F_USER, F_USER);
const F_FENCE = planModelFence(F_USER, F_PLAN);
const F_INSTALLED = planInstall(F_USER, { ...FACTS, providers: F_PLAN.routed, fence: F_FENCE }).doc;
const F_ROUTES = { providers: F_PLAN.routed, unprotected: [] as string[], allowlist: F_FENCE.record };

function fcheck(doc: unknown, routes: { providers?: typeof F_PLAN.routed; unprotected?: string[]; allowlist?: string[] } = F_ROUTES) {
  const r = readOpenclawConfig(config(doc), { HOME: "/nonexistent" }, "/nonexistent");
  assert.ok(r.ok);
  const s = attachState(r.effective, { serviceUrl: URL_, routes });
  return { s, v: routeVerdict(s, URL_) };
}
const clone = (): any => JSON.parse(JSON.stringify(F_INSTALLED));

test("fence: the installed fence holds (routed, no hole); the keys install recorded are the reference", () => {
  assert.deepEqual([...F_FENCE.record].sort(), ["anthropic/*", "openai/*", "openrouter/deepseek/x"]);
  const { s, v } = fcheck(F_INSTALLED);
  assert.deepEqual(s.fenceHoles, []);
  assert.deepEqual(v.problems, []);
  assert.equal(modelFenceHoles(F_INSTALLED, F_ROUTES).length, 0);
});

test("fence: each hole shape is a lost model context (model-fence), said without a path or a port", () => {
  const shapes: Array<[string, (d: any) => void, string, RegExp]> = [
    ["the allowlist Mandu wrote deleted", (d) => { delete d.agents.defaults.models; }, "fence-gone",
      /the model allowlist \(agents\.defaults\.models\) Mandu wrote at the install is gone, so a model switch .* can reach any model, around Mandu/],
    ["the allowlist emptied", (d) => { d.agents.defaults.models = {}; }, "fence-gone", /Mandu wrote at the install is gone/],
    ["an openrouter wildcard added", (d) => { d.agents.defaults.models["openrouter/*"] = {}; }, "openrouter-wildcard",
      /names openrouter\/\*, which OpenClaw before 2026\.3\.22 reads as the model "\*": OpenClaw before 2026\.3\.22 sends an openrouter model .* straight to openrouter\.ai, whatever the route/],
    ["an unlisted openrouter key added", (d) => { d.agents.defaults.models["openrouter/qwen/qwen3"] = {}; }, "openrouter-unlisted",
      /openrouter model qwen\/qwen3 is named by the config or its model allowlist but not listed in models\.providers\.openrouter\.models/],
    ["a configured openrouter model not listed", (d) => { d.agents.defaults.model.fallbacks = ["openrouter/qwen/qwen3"]; }, "openrouter-unlisted", /qwen\/qwen3/],
    ["a listed model unlisted under its key", (d) => { d.models.providers.openrouter.models = [{ id: "deepseek/x-v2" }]; }, "openrouter-unlisted", /deepseek\/x\b/],
    ["a key of a provider Mandu does not route", (d) => { d.agents.defaults.models["mistral/*"] = {}; }, "fence-unrouted",
      /names mistral\/\*, so a model switch can reach provider mistral, which Mandu does not route \(added after the install\)/],
    ["a key of every provider", (d) => { d.agents.defaults.models["*/*"] = {}; }, "fence-unrouted", /provider \*/],
  ];
  for (const [name, edit, kind, words] of shapes) {
    const d = clone();
    edit(d);
    const { s, v } = fcheck(d);
    assert.deepEqual(s.fenceHoles!.map((h) => h.kind), [kind], name);
    assert.deepEqual(v.problems.map((p) => p.code), ["model-fence"], name);
    assert.match(v.problems[0]!.detail, words, name);
    assert.doesNotMatch(v.problems[0]!.detail, /127\.0\.0\.1|41234|\/home\/|\/run\//, `${name}: no path or port`);
    assert.ok(v.problems[0]!.detail.length <= 400, `${name}: fits the arbiter's 400 characters`);
    assert.deepEqual(v.lost, { modelContext: true, policy: false }, name);
    assert.deepEqual(routeLostOf(v.problems), { modelContext: true, policy: false }, name);
    assert.equal(routeStateOf(v, true), "lost", name);
  }
  // Many keys are named three at a time.
  const many = clone();
  for (const p of ["a", "b", "c", "d", "e"]) many.agents.defaults.models[`${p}/*`] = {};
  assert.match(fcheck(many).v.problems[0]!.detail, /names a\/\*, b\/\*, c\/\* and 2 more, so a model switch can reach providers a, b, c and 2 more/);
});

test("fence: what is NOT a hole: a recorded key removed while others stay, a model of a routed provider, a key of a provider left unprotected, an install before the fence", () => {
  const narrower = clone();
  delete narrower.agents.defaults.models["openai/*"];
  assert.equal(fcheck(narrower).v.routed, true, "a narrower fence refuses more switches and opens none");
  const routedKey = clone();
  routedKey.agents.defaults.models["openai/gpt-5.5"] = {};
  assert.equal(fcheck(routedKey).v.routed, true, "a model of a routed provider crosses Mandu");
  const leftKey = clone();
  leftKey.agents.defaults.models["mistral/*"] = {};
  assert.equal(fcheck(leftKey, { ...F_ROUTES, unprotected: ["mistral"] }).v.routed, true, "a provider the user left on purpose is the user's choice");
  // openrouter left unprotected: its shapes are the user's choice too.
  const orLeft = clone();
  orLeft.agents.defaults.models["openrouter/*"] = {};
  const noOr = F_PLAN.routed.filter((p) => p.id !== "openrouter");
  assert.deepEqual(fcheck(orLeft, { providers: noOr, unprotected: ["openrouter"], allowlist: F_FENCE.record }).s.fenceHoles, []);
  // An install before the fence recorded none: a config without an
  // allowlist is not judged a fence removed (a second install writes one).
  const bare = clone();
  delete bare.agents.defaults.models;
  const { allowlist: _a, ...preFence } = F_ROUTES;
  assert.deepEqual(fcheck(bare, preFence).s.fenceHoles, []);
  // Before Route 1 (no providers recorded) nothing of the fence is judged.
  assert.equal(fcheck(bare, {}).s.fenceHoles, undefined);
  assert.equal(fcheck(bare, {}).v.routed, true);
});

test("fence: the user's own allowlist (recorded empty) removed is a hole too, said as the user's", () => {
  const own = clone();
  own.agents.defaults.models = { "anthropic/claude-sonnet-4-6": { alias: "sonnet" }, "openrouter/deepseek/x": {} };
  const routes = { ...F_ROUTES, allowlist: [] as string[] };
  assert.equal(fcheck(own, routes).v.routed, true);
  delete own.agents.defaults.models;
  const v = fcheck(own, routes).v;
  assert.deepEqual(v.problems.map((p) => p.code), ["model-fence"]);
  assert.match(v.problems[0]!.detail, /the model allowlist \(agents\.defaults\.models\) your config kept at the install is gone/);
});

test("fence: a configured model of a provider Mandu does not route (a catalog provider) is a provider added after the install", () => {
  const d = clone();
  d.agents.defaults.model.fallbacks = ["mistral/mistral-large"];
  const { s, v } = fcheck(d);
  assert.deepEqual(s.unrouted, ["mistral"]);
  assert.deepEqual(v.problems.map((p) => p.code), ["route-direct"]);
  assert.match(v.problems[0]!.detail, /provider mistral is not routed through Mandu \(added after the install\)/);
  assert.equal(fcheck(d, { ...F_ROUTES, unprotected: ["mistral"] }).v.routed, true);
});

test("fence: the doctor names each hole with the fix", () => {
  const d = clone();
  d.agents.defaults.models["openrouter/*"] = {};
  const { s, v } = fcheck(d);
  const rows = openclawAttachRows({ configPath: "/home/u/.openclaw/openclaw.json", session: "openclaw:main", state: s, verdict: v }).join("\n");
  assert.match(rows, /✗ the model allowlist \(agents\.defaults\.models\) names openrouter\/\*/);
  assert.match(rows, /fix: mandu openclaw install, then openclaw gateway restart \(the install puts the fence back/);
});

test("fence: a second install takes the fence back: the allowlist written again, the keys added since removed, a key of a provider left kept", () => {
  // The allowlist deleted: planned again, written again, recorded again.
  const gone = clone();
  delete gone.agents.defaults.models;
  const p1 = planProviders(gone, gone, F_PLAN.routed, F_FENCE.record);
  assert.deepEqual(fenceKeysToReclaim(gone, p1, [], F_FENCE.record), []);
  const f1 = planModelFence(gone, p1, F_FENCE.record);
  assert.deepEqual([...f1.write].sort(), [...F_FENCE.record].sort());
  const back1 = planInstall(gone, { ...FACTS, providers: p1.routed, fence: f1 }).doc;
  assert.equal(fcheck(back1).v.routed, true);

  // Holes added (a wildcard, an unlisted openrouter key, an unroutable
  // provider's key) beside a removed Mandu key: install would refuse each;
  // over a fenced config it removes them and restores the fence.
  const widened = clone();
  delete widened.agents.defaults.models["openai/*"];
  Object.assign(widened.agents.defaults.models, { "openrouter/*": {}, "openrouter/qwen/qwen3": {}, "mistral/*": {}, "anthropic/claude-opus-4-6": {} });
  assert.equal(fcheck(widened).v.lost.modelContext, true);
  const before = planProviders(widened, widened, F_PLAN.routed, F_FENCE.record);
  assert.ok(before.cannot.some((c) => c.id === "openrouter") && before.cannot.some((c) => c.id === "mistral"), "without the reclaim, install refuses");
  const drop = fenceKeysToReclaim(widened, before, [], F_FENCE.record);
  assert.deepEqual([...drop].sort(), ["mistral/*", "openrouter/*", "openrouter/qwen/qwen3"]);
  const p2 = planProviders(widened, widened, F_PLAN.routed, [...F_FENCE.record, ...drop]);
  assert.deepEqual(p2.cannot, []);
  const f2 = planModelFence(widened, p2, F_FENCE.record, drop);
  assert.deepEqual(f2.write, ["openai/*"]);
  assert.deepEqual([...f2.remove].sort(), ["mistral/*", "openrouter/*", "openrouter/qwen/qwen3"]);
  assert.ok(!f2.record.some((k) => drop.includes(k)), "a removed key is not Mandu's to record");
  const back2 = planInstall(widened, { ...FACTS, providers: p2.routed, fence: f2 }).doc as any;
  assert.ok("anthropic/claude-opus-4-6" in back2.agents.defaults.models, "a key of a routed provider the user added stays");
  assert.equal(fcheck(back2, { ...F_ROUTES, allowlist: f2.record }).v.routed, true);

  // Named in --leave-unprotected (now, or at the earlier install): the
  // user's choice; the key stays.
  assert.deepEqual([...fenceKeysToReclaim(widened, before, ["mistral"], F_FENCE.record)].sort(), ["openrouter/*", "openrouter/qwen/qwen3"]);
  // A key the install recorded is planModelFence's, never reclaimed here.
  assert.deepEqual(fenceKeysToReclaim(F_INSTALLED, F_PLAN, [], F_FENCE.record), []);
});

test("Azure OpenAI's endpoint variables (model-wires.md §9.1): set for the Gateway is route-direct; not read or not readable is route-unverified; both lose the model context; nothing set routes", () => {
  const azure: DeclaredProvider = { id: "azure", wire: "azure-openai-responses", upstream: "https://r.openai.azure.com/openai/v1", original: { existed: true, headers: false } };
  const anthropic: DeclaredProvider = { id: "anthropic", wire: "anthropic-messages", upstream: null, original: { existed: false, headers: false } };
  const user = { ...USER, models: { providers: { azure: { api: "azure-openai-responses", baseUrl: "https://r.openai.azure.com", models: [] } } } };
  const doc = planInstall(user, { ...FACTS, providers: [anthropic, azure] }).doc as Record<string, unknown>;
  const routes = { providers: [anthropic, azure], unprotected: ["openai"] };
  const v = (gatewayEnv?: { verified: boolean; why?: string; set: string[] }, d: Record<string, unknown> = doc) =>
    routeVerdict(attachState(d, { serviceUrl: URL_, routes, ...(gatewayEnv ? { gatewayEnv } : {}) }), URL_);
  assert.deepEqual(v({ verified: true, set: [] }), { routed: true, problems: [], lost: { modelContext: false, policy: false } });
  const set = v({ verified: true, set: ["AZURE_OPENAI_BASE_URL (/home/u/.config/systemd/user/openclaw-gateway.service, Environment=)"] });
  assert.deepEqual(set.problems.map((p) => p.code), ["route-direct"]);
  assert.match(set.problems[0]!.detail, /Azure OpenAI provider azure go to AZURE_OPENAI_BASE_URL \(.*openclaw-gateway\.service, Environment=\) instead of the route/);
  assert.deepEqual(set.lost, { modelContext: true, policy: false });
  // Even when the running Gateway could not be read, what is known to be set is said.
  assert.deepEqual(v({ verified: false, why: "x", set: ["AZURE_OPENAI_RESOURCE_NAME (/home/u/.openclaw/.env)"] }).problems.map((p) => p.code), ["route-direct"]);
  const unv = v({ verified: false, why: "Mandu cannot read a running OpenClaw Gateway's environment on this system (no /proc)", set: [] });
  assert.deepEqual(unv.problems.map((p) => p.code), ["route-unverified"]);
  assert.match(unv.problems[0]!.detail, /not verified: Mandu cannot read .*no \/proc/);
  assert.deepEqual(unv.lost, { modelContext: true, policy: false });
  assert.equal(routeStateOf(unv, true), "lost");
  assert.deepEqual(v(undefined).problems.map((p) => p.code), ["route-unverified"], "a caller that read nothing does not claim routed");
  // The config's own env block counts whatever the reader found.
  const envd = { ...doc, env: { vars: { AZURE_OPENAI_BASE_URL: "https://x.openai.azure.com" } } };
  assert.match(v({ verified: true, set: [] }, envd).problems[0]!.detail, /env\.vars\.AZURE_OPENAI_BASE_URL in the OpenClaw config/);
  // No Azure provider routed: the environment is not judged.
  assert.deepEqual(check(config(INSTALLED)).v.problems, []);
  // The pool record reads the new code back.
  const rec = parseRouteRecord(JSON.stringify({ route: { state: "lost", problems: unv.problems, config: "/c", since: "t", checkedAt: "t" } }));
  assert.deepEqual(rec?.problems.map((p) => p.code), ["route-unverified"]);
});
