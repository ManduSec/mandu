/**
 * openclaw-openrouter-fence.test — OpenClaw's openrouter bypass and the
 * fences against it (supported-agents.md §2.1, "The openrouter bypass";
 * openclaw-plugin.md §8.1, "The model fence").
 *
 * OpenClaw 2026.3.12 and 2026.3.13 send an openrouter model that neither
 * their catalog nor `models.providers.openrouter.models` knows straight to
 * https://openrouter.ai/api/v1, whatever the provider's baseUrl (measured on
 * 2026.3.12: the turn went to openrouter.ai; 2026.3.22 and later, measured on
 * 2026.9.9, honour the baseUrl). Per version shape:
 *   - the wrapper's run config (services/agent-config.ts): on a release that
 *     bypasses (or one the launch could not read) every openrouter model the
 *     run can reach is listed under the routed provider and the allowlist
 *     names exactly those; a release that honours the baseUrl is untouched;
 *     the launch's last check refuses a file that still leaves one;
 *   - the plugin's install (openclaw-providers.ts, openclaw-attach.ts): a
 *     configured or allowlisted openrouter model must be listed, a wildcard
 *     is refused, an allowlist key's provider is judged, and the model fence
 *     (`agents.defaults.models`) is written when the user keeps none,
 *     recorded, and removed by uninstall key for key.
 * Pure; no agent runs. Axes: none (routing and config decisions only; the
 * end-to-end oracle is tests/stack/openclaw-openrouter-bypass.test.ts).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  OPENCLAW_OPENROUTER_BASEURL_SINCE, openclawCliModel, openclawOpenrouterId, openclawOpenrouterKey,
  openclawOpenrouterReach, openclawOpenrouterUnlisted,
} from "../../src/agent-model-route.js";
import {
  fenceOpenclawModelAllowlist, fenceOpenclawOpenrouter, openclawOpenrouterBypasses, openclawOpenrouterLeaks, writeAgentConfig,
} from "../../src/services/agent-config.js";
import { Layout } from "../../src/services/layout.js";
import { planModelFence, planProviders } from "../../src/openclaw-providers.js";
import { planInstall, planUninstall } from "../../src/openclaw-attach.js";
import { declareAttachment, parseDeclared, renderDeclared } from "../../src/attachment-contract.js";
import type { LaunchPlan, Ullm } from "../../src/types.js";

type Json = Record<string, any>;

const ROUTE = { id: "openrouter", api: "openai-completions" as const, upstream: "https://openrouter.ai/api/v1" };
const ULLM: Ullm = { mode: "cli", baseUrl: "https://api.anthropic.com", binary: "claude" };

/** The run config the wrapper writes before the openrouter fence. */
function runDoc(models: Json[], primary: string, allow: Json = {}): Json {
  return fenceOpenclawModelAllowlist({
    models: { mode: "merge", providers: { openrouter: { baseUrl: "http://127.0.0.1:9/_mandu/openai/openrouter", api: "openai-completions", models } } },
    agents: { defaults: { model: { primary }, models: allow } },
  }, ["openrouter"]);
}

test("the bypass releases: 2026.3.12 and 2026.3.13 (and an unread version); 2026.3.22 on honours the baseUrl", () => {
  assert.equal(OPENCLAW_OPENROUTER_BASEURL_SINCE, "2026.3.22");
  for (const v of ["2026.3.12", "2026.3.13", "2026.3.1", null, undefined, "", "not-a-version"]) assert.equal(openclawOpenrouterBypasses(v), true, String(v));
  for (const v of ["2026.3.22", "2026.4.24", "2026.6.35", "2026.7.1-2", "2026.9.6", "2026.9.9", "2026.10.7"]) assert.equal(openclawOpenrouterBypasses(v), false, v);
  // a prerelease of the boundary release does not say
  assert.equal(openclawOpenrouterBypasses("2026.3.22-beta.1"), true);
});

test("OpenClaw's openrouter ids and keys: a bare id gains openrouter/, a vendor id is its own; the key is OpenClaw's modelKey", () => {
  assert.equal(openclawOpenrouterId("auto"), "openrouter/auto");
  assert.equal(openclawOpenrouterId("anthropic/claude-sonnet-4.5"), "anthropic/claude-sonnet-4.5");
  assert.equal(openclawOpenrouterId(" openrouter/auto "), "openrouter/auto");
  assert.equal(openclawOpenrouterKey("openrouter/auto"), "openrouter/auto");
  assert.equal(openclawOpenrouterKey("anthropic/claude-sonnet-4.5"), "openrouter/anthropic/claude-sonnet-4.5");
});

test("reach: configured references (aliases resolved), the allowlist's openrouter keys, the argv's --model; wildcards apart", () => {
  const doc = {
    models: { providers: { openrouter: { models: [{ id: "deepseek/x" }, { id: "openrouter/auto" }, { name: "no id" }] } } },
    agents: {
      defaults: {
        model: { primary: "openrouter/deepseek/x", fallbacks: ["fast"] },
        models: { "openrouter/qwen/qwen3": { alias: "fast" }, "openrouter/*": {}, "anthropic/*": {}, "OpenRouter/auto": {} },
        subagents: { model: "openrouter/mistral/m" },
      },
    },
  };
  const reach = openclawOpenrouterReach(doc, [{ ref: "openrouter/cli/model", where: "--model" }]);
  assert.deepEqual(reach.ids.map((x) => x.id).sort(), ["cli/model", "deepseek/x", "mistral/m", "openrouter/auto", "qwen/qwen3", "qwen/qwen3"].sort());
  assert.deepEqual(reach.wildcards, ["openrouter/*"]);
  assert.deepEqual([...reach.listed].sort(), ["deepseek/x", "openrouter/auto"]);
  const un = openclawOpenrouterUnlisted(doc, [{ ref: "openrouter/cli/model", where: "--model" }]);
  assert.deepEqual(un.missing.map((m) => m.id).sort(), ["cli/model", "mistral/m", "qwen/qwen3"], "each once");
  assert.equal(un.missing.find((m) => m.id === "qwen/qwen3")!.where, "agents.defaults.model.fallbacks[0]", "the first place it is named");
  assert.deepEqual(openclawCliModel(["openclaw", "agent", "--local", "--model", "openrouter/a/b", "-m", "hi"]), { ref: "openrouter/a/b", where: "--model" });
  assert.equal(openclawCliModel(["openclaw", "agent", "-m", "hi"]), null, "-m is the message");
  assert.equal(openclawCliModel(["openclaw", "tui", "--model", "openrouter/a/b"]), null, "only `agent` takes --model");
});

test("wrapper fence on 2026.3.12: every reachable openrouter model is listed for the run; the allowlist names exactly those (no wildcard)", () => {
  const before = runDoc([{ id: "deepseek/x", contextWindow: 64000 }], "openrouter/unknown/model", { "openrouter/qwen/qwen3": { alias: "q" } });
  assert.ok("openrouter/*" in before.agents.defaults.models, "the allowlist fence writes the wildcard for a routed provider");
  const { doc: d0, notes } = fenceOpenclawOpenrouter(before, "2026.3.12", [{ ref: "openrouter/cli/m", where: "--model" }]);
  const doc = d0 as Json;
  const list = doc["models"].providers.openrouter.models;
  assert.deepEqual(list, [
    { id: "deepseek/x", contextWindow: 64000 },
    { id: "unknown/model", name: "unknown/model" },
    { id: "cli/m", name: "cli/m" },
    { id: "qwen/qwen3", name: "qwen/qwen3" },
  ]);
  assert.deepEqual(doc["agents"].defaults.models, {
    "anthropic/*": {},
    "openrouter/deepseek/x": {}, "openrouter/unknown/model": {}, "openrouter/qwen/qwen3": { alias: "q" }, "openrouter/cli/m": {},
  });
  assert.equal(notes.length, 1);
  assert.match(notes[0]!, /OpenClaw 2026\.3\.12.*openrouter\.ai around Mandu/);
  assert.deepEqual(openclawOpenrouterLeaks(doc, "2026.3.12", [{ ref: "openrouter/cli/m", where: "--model" }]), [], "nothing the run can reach goes around");
  // the input is not mutated
  assert.ok("openrouter/*" in before.agents.defaults.models);
});

test("wrapper fence: 2026.3.13 and an unread version get it; 2026.3.22, 2026.9.9 and 2026.10.7 are left as they are", () => {
  const before = runDoc([], "openrouter/unknown/model");
  for (const v of ["2026.3.13", null]) {
    const out = fenceOpenclawOpenrouter(before, v).doc as Json;
    assert.deepEqual(out["models"].providers.openrouter.models, [{ id: "unknown/model", name: "unknown/model" }], String(v));
    assert.equal("openrouter/*" in out["agents"].defaults.models, false, String(v));
  }
  for (const v of ["2026.3.22", "2026.9.9", "2026.10.7"]) {
    const r = fenceOpenclawOpenrouter(before, v);
    assert.equal(r.doc, before, v);
    assert.deepEqual(r.notes, []);
    assert.deepEqual(openclawOpenrouterLeaks(before, v), [], `${v} honours the baseUrl`);
  }
  // no routed openrouter: nothing to fence
  const noOr = { models: { providers: { anthropic: { baseUrl: "http://127.0.0.1:9" } } }, agents: { defaults: { model: "anthropic/x" } } };
  assert.equal(fenceOpenclawOpenrouter(noOr, "2026.3.12").doc, noOr);
});

test("the launch's last check: on a bypass release an unlisted model or an openrouter wildcard is a leak, named with where", () => {
  const leaky = runDoc([], "openrouter/unknown/model");
  const leaks = openclawOpenrouterLeaks(leaky, "2026.3.12");
  assert.ok(leaks.includes("unknown/model (agents.defaults.model.primary)"), JSON.stringify(leaks));
  assert.ok(leaks.includes("openrouter/* (agents.defaults.models)"), JSON.stringify(leaks));
  assert.deepEqual(openclawOpenrouterLeaks(leaky, "2026.9.9"), []);
});

function wrapperPlan(version: string | null, argv: string[] = ["openclaw", "gateway"]): LaunchPlan {
  return {
    target: "openclaw", argv, cwd: "/w", scopeId: "sid-or", tenant: "live", proxy: { host: "127.0.0.1", port: 9 }, writeMcp: false,
    arbiterSock: "/s", ullm: ULLM, openaiRoutes: [ROUTE], agentVersion: version,
  } as unknown as LaunchPlan;
}

test("writeAgentConfig: on OpenClaw 2026.3.12 the run file lists the configured unlisted openrouter model and fences the allowlist; on 2026.9.9 it does not", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-or-fence-"));
  try {
    const userCfg = join(dir, "user.json");
    writeFileSync(userCfg, JSON.stringify({
      models: { providers: { openrouter: { baseUrl: "https://openrouter.ai/api/v1", api: "openai-completions", apiKey: "sk-or-v1-x", models: [] } } },
      agents: { defaults: { model: { primary: "openrouter/mandu/unknown" } } },
    }));
    const warned: string[] = [];
    const old = JSON.parse(readFileSync(writeAgentConfig(wrapperPlan("2026.3.12"), Layout.dev("/repo"), dir, (m) => warned.push(m), { OPENCLAW_CONFIG_PATH: userCfg }).path, "utf8"));
    assert.equal(old.models.providers.openrouter.baseUrl, "http://127.0.0.1:9/_mandu/openai/openrouter");
    assert.deepEqual(old.models.providers.openrouter.models, [{ id: "mandu/unknown", name: "mandu/unknown" }]);
    assert.deepEqual(Object.keys(old.agents.defaults.models).sort(), ["anthropic/*", "openrouter/mandu/unknown"]);
    assert.ok(warned.some((w) => /OpenClaw 2026\.3\.12.*openrouter\.ai around Mandu/.test(w)), warned.join("\n"));

    const now = JSON.parse(readFileSync(writeAgentConfig(wrapperPlan("2026.9.9"), Layout.dev("/repo"), dir, () => {}, { OPENCLAW_CONFIG_PATH: userCfg }).path, "utf8"));
    assert.deepEqual(now.models.providers.openrouter.models, []);
    assert.ok("openrouter/*" in now.agents.defaults.models);

    // the argv's --model is reached too
    const cli = JSON.parse(readFileSync(writeAgentConfig(wrapperPlan("2026.3.12", ["openclaw", "agent", "--local", "--model", "openrouter/cli/x", "-m", "hi"]), Layout.dev("/repo"), dir, () => {}, { OPENCLAW_CONFIG_PATH: userCfg }).path, "utf8"));
    assert.ok(cli.models.providers.openrouter.models.some((m: Json) => m.id === "cli/x"));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// ── The plugin's install (Route 1, openclaw-plugin.md §8.1) ──────────────────

const OR_PROVIDER = { api: "openai-completions", baseUrl: "https://openrouter.ai/api/v1", apiKey: "sk-or", models: [{ id: "deepseek/x" }] };

test("install's openrouter rule reads the allowlist too: an unlisted openrouter key, or a wildcard, is refused, naming it", () => {
  const cfg = (allow: Json): Json => ({ models: { providers: { openrouter: OR_PROVIDER } }, agents: { defaults: { model: "openrouter/deepseek/x", models: allow } } });
  assert.ok(planProviders(cfg({ "openrouter/deepseek/x": {} }), {}).routed.some((p) => p.id === "openrouter"), "a listed key is fine");
  const unlisted = planProviders(cfg({ "openrouter/qwen/qwen3": {} }), {}).cannot.find((c) => c.id === "openrouter")!;
  assert.match(unlisted.why, /before 2026\.3\.22/);
  assert.match(unlisted.why, /list "qwen\/qwen3" in models\.providers\.openrouter\.models/);
  const wild = planProviders(cfg({ "openrouter/*": {} }), {}).cannot.find((c) => c.id === "openrouter")!;
  assert.match(wild.why, /replace "openrouter\/\*" in agents\.defaults\.models/);
  // keys an earlier install wrote are Mandu's, not the user's
  assert.ok(planProviders(cfg({ "openrouter/*": {} }), {}, [], ["openrouter/*"]).routed.some((p) => p.id === "openrouter"));
});

test("install judges an allowlist key's provider like a configured model's: one Mandu cannot route is refused unless left", () => {
  const cfg = { agents: { defaults: { model: "anthropic/claude-sonnet-4-6", models: { "mistral/mistral-large": {}, "anthropic/*": {} } } } };
  const plan = planProviders(cfg, cfg);
  const mistral = plan.cannot.find((c) => c.id === "mistral")!;
  assert.ok(mistral, JSON.stringify(plan.cannot));
  assert.deepEqual(mistral.refs, ['agents.defaults.models["mistral/mistral-large"]']);
});

test("the model fence: written when the user keeps no allowlist (routed providers' wildcards, openrouter's listed models exactly, the configured models); a user's own allowlist is left", () => {
  const cfg: Json = {
    models: { providers: { openrouter: OR_PROVIDER } },
    agents: { defaults: { model: { primary: "openrouter/deepseek/x", fallbacks: ["anthropic/claude-haiku-4-5"] } } },
  };
  const plan = planProviders(cfg, cfg);
  assert.deepEqual(plan.cannot, []);
  const fence = planModelFence(cfg, plan);
  assert.deepEqual(fence.write.sort(), ["anthropic/*", "anthropic/claude-haiku-4-5", "openai/*", "openrouter/deepseek/x"]);
  assert.equal(fence.write.includes("openrouter/*"), false, "never an openrouter wildcard");
  assert.deepEqual(fence.remove, []);
  assert.deepEqual(fence.record.sort(), fence.write.sort());
  // a provider left unprotected keeps its models reachable (the user's choice)
  const left = planModelFence(cfg, { routed: plan.routed, cannot: [{ id: "google", why: "x", refs: [] }] });
  assert.ok(left.write.includes("google/*"));
  // the user's own allowlist: nothing written, nothing recorded
  const own = { ...cfg, agents: { defaults: { ...cfg["agents"].defaults, models: { "openrouter/deepseek/x": { alias: "ds" } } } } };
  assert.deepEqual(planModelFence(own, planProviders(own, own)), { write: [], remove: [], record: [] });
});

test("the model fence over its own output: nothing more to write; a provider gone since loses its key", () => {
  const cfg: Json = { models: { providers: { openrouter: OR_PROVIDER } }, agents: { defaults: { model: "openrouter/deepseek/x" } } };
  const plan = planProviders(cfg, cfg);
  const fence = planModelFence(cfg, plan);
  const installed = planInstall(cfg, { pluginDir: "/p/openclaw-inspect-plugin", agentId: "main", session: "openclaw:main", proxyUrl: "http://127.0.0.1:4000", arbiterSock: "/s", manduPaths: [], providers: plan.routed, fence }).doc;
  const again = planModelFence(installed, planProviders(installed, installed, plan.routed, fence.record), fence.record);
  assert.deepEqual(again.write, []);
  assert.deepEqual(again.remove, []);
  assert.deepEqual(again.record.sort(), fence.record.sort());
  // openrouter no longer routed (the user dropped it): its exact key goes
  const without = planModelFence(installed, { routed: plan.routed.filter((p) => p.id !== "openrouter"), cannot: [] }, fence.record);
  assert.ok(without.remove.includes("openrouter/deepseek/x"), JSON.stringify(without));
});

test("install then uninstall with the model fence: the allowlist is written, and uninstall puts the file back key for key", () => {
  for (const user of [
    { models: { providers: { openrouter: OR_PROVIDER } }, agents: { defaults: { model: "openrouter/deepseek/x" } } },
    { models: { providers: { openrouter: OR_PROVIDER } }, agents: { defaults: { model: "openrouter/deepseek/x", workspace: "/w" }, list: [{ id: "main" }] } },
    { agents: { defaults: { model: "anthropic/claude-haiku-4-5", models: {} } } },
  ] as Json[]) {
    const plan = planProviders(user, user);
    const fence = planModelFence(user, plan);
    const facts = { pluginDir: "/p/openclaw-inspect-plugin", agentId: "main", session: "openclaw:main", proxyUrl: "http://127.0.0.1:4000", arbiterSock: "/s", manduPaths: [], providers: plan.routed, fence };
    const doc = planInstall(user, facts).doc as Json;
    assert.deepEqual(Object.keys(doc["agents"].defaults.models).sort(), fence.record.sort(), JSON.stringify(user));
    // idempotent
    assert.deepEqual(planInstall(doc, { ...facts, fence: planModelFence(doc, planProviders(doc, doc, plan.routed, fence.record), fence.record) }).doc, doc);
    const back = planUninstall(doc, facts.pluginDir, plan.routed, fence.record).doc;
    const want = JSON.parse(JSON.stringify(user));
    if (want.agents.defaults.models !== undefined && Object.keys(want.agents.defaults.models).length === 0) delete want.agents.defaults.models; // an empty allowlist is no allowlist
    assert.deepEqual(back, want, JSON.stringify(user));
  }
});

test("uninstall removes only the fence's keys: a key the user added to the allowlist since stays", () => {
  const user: Json = { agents: { defaults: { model: "anthropic/claude-haiku-4-5" } } };
  const plan = planProviders(user, user);
  const fence = planModelFence(user, plan);
  const doc = planInstall(user, { pluginDir: "/p/openclaw-inspect-plugin", agentId: "main", session: "openclaw:main", proxyUrl: "http://127.0.0.1:4000", arbiterSock: "/s", manduPaths: [], providers: plan.routed, fence }).doc as Json;
  doc["agents"].defaults.models["anthropic/claude-opus-4-6"] = { alias: "opus" };
  const back = planUninstall(doc, "/p/openclaw-inspect-plugin", plan.routed, fence.record).doc as Json;
  assert.deepEqual(back["agents"].defaults.models, { "anthropic/claude-opus-4-6": { alias: "opus" } });
});

test("the declared file records the fence's keys (model references only) and reads them back; a malformed list makes the entry unusable", () => {
  const routes = { providers: [], unprotected: [], allowlist: ["anthropic/*", "openrouter/deepseek/x"] };
  const { list } = declareAttachment([], "main", null, undefined, routes);
  const text = renderDeclared(list);
  assert.deepEqual(parseDeclared(text).attachments[0]!.allowlist, ["anthropic/*", "openrouter/deepseek/x"]);
  // the same routes again change nothing; a new fence replaces the old
  assert.equal(declareAttachment(list, "main", null, undefined, routes).changed, false);
  const next = declareAttachment(list, "main", null, undefined, { ...routes, allowlist: ["anthropic/*"] });
  assert.deepEqual(next.entry.allowlist, ["anthropic/*"]);
  // An empty fence is recorded as such (the user's own allowlist is the
  // fence, which the route check then holds the config to); no fence given
  // keeps what was recorded.
  const own = declareAttachment(list, "main", null, undefined, { ...routes, allowlist: [] });
  assert.deepEqual(own.entry.allowlist, []);
  assert.deepEqual(parseDeclared(renderDeclared(own.list)).attachments[0]!.allowlist, []);
  assert.equal(declareAttachment(own.list, "main", null, undefined, { ...routes, allowlist: [] }).changed, false);
  const { allowlist: _none, ...noFence } = routes;
  assert.equal(declareAttachment([], "main", null, undefined, noFence).entry.allowlist, undefined, "an install before the fence records none");
  for (const bad of [["no-slash"], [3], "anthropic/*", ["a/b c"], ["a/b\n"]]) {
    const r = parseDeclared(JSON.stringify({ version: 2, attachments: [{ kind: "openclaw-plugin", agent: "main", session: "openclaw:main", port: null, allowlist: bad }] }));
    assert.equal(r.attachments.length, 0, JSON.stringify(bad));
    assert.match(r.problems.join(" "), /allowlist is not a list of model references/);
  }
});

// ── With a Google (Gemini wire) provider beside it (2026-10-25) ──────────────

test("wrapper fence with a routed google provider beside openrouter: google's allowlist entry and route are untouched; openrouter is still listed exactly", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-or-fence-google-"));
  try {
    const userCfg = join(dir, "user.json");
    writeFileSync(userCfg, JSON.stringify({
      models: { providers: { openrouter: { baseUrl: "https://openrouter.ai/api/v1", api: "openai-completions", apiKey: "sk-or-v1-x", models: [] } } },
      agents: { defaults: { model: { primary: "openrouter/mandu/unknown", fallbacks: ["google/gemini-2.5-pro"] } } },
    }));
    const plan = {
      ...wrapperPlan("2026.3.12"),
      openaiRoutes: [ROUTE, { id: "google", api: "google-generative-ai", upstream: "https://generativelanguage.googleapis.com/v1beta" }],
    } as unknown as LaunchPlan;
    const out = JSON.parse(readFileSync(writeAgentConfig(plan, Layout.dev("/repo"), dir, () => {}, { OPENCLAW_CONFIG_PATH: userCfg }).path, "utf8"));
    assert.deepEqual(Object.keys(out.agents.defaults.models).sort(), ["anthropic/*", "google/*", "openrouter/mandu/unknown"]);
    assert.deepEqual(out.models.providers.openrouter.models, [{ id: "mandu/unknown", name: "mandu/unknown" }]);
    assert.ok(!(out.models.providers.google.models ?? []).some((m: Json) => /openrouter/.test(String(m.id))), "google's models are its own");
    assert.match(out.models.providers.google.baseUrl, /^http:\/\/127\.0\.0\.1:9\//, "google still goes to the proxy");
    assert.deepEqual(openclawOpenrouterLeaks(out, "2026.3.12"), []);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("the plugin's model fence with a google provider: left unprotected or routed, `google/*` and its configured model are in the written allowlist; openrouter stays exact", () => {
  const cfg: Json = {
    models: { providers: { openrouter: OR_PROVIDER } },
    agents: { defaults: { model: { primary: "openrouter/deepseek/x", fallbacks: ["google/gemini-2.5-pro"] } } },
  };
  const plan = planProviders(cfg, cfg);
  const google = plan.cannot.find((c) => c.id === "google");
  const left = planModelFence(cfg, { routed: plan.routed, cannot: google ? [google] : [] });
  const routed = planModelFence(cfg, { routed: [...plan.routed.filter((p) => p.id !== "google"), { id: "google", wire: "openai-completions", upstream: null, original: { existed: false, headers: false } }], cannot: [] });
  for (const f of [left, routed]) {
    assert.ok(f.write.includes("google/*"), JSON.stringify(f));
    assert.ok(f.write.includes("google/gemini-2.5-pro"), JSON.stringify(f));
    assert.ok(f.write.includes("openrouter/deepseek/x") && !f.write.includes("openrouter/*"), JSON.stringify(f));
  }
});
