/**
 * openclaw-attach tests — the pure half of `mandu openclaw install|uninstall`
 * (src/openclaw-attach.ts, docs/design/agents/openclaw-plugin.md §8): the
 * service URL contract, the config plans, the state the doctor reads.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  anthropicProxyPortFile,
  attachedSession,
  attachmentSession,
  attachState,
  identityProblem,
  installRefusal,
  isLoopbackUrl,
  looksAttached,
  normalizeAgentId,
  parsePortFile,
  planInstall,
  planUninstall,
  portFileProblem,
  serviceProxyUrl,
  type AttachFacts,
} from "../../src/openclaw-attach.js";

const FACTS: AttachFacts = {
  pluginDir: "/src/mandu/interceptors/openclaw-inspect-plugin",
  agentId: "main",
  session: "openclaw:main",
  proxyUrl: "http://127.0.0.1:41234",
  arbiterSock: "/run/user/1000/mandu/instances/x/arbiter.sock",
  manduPaths: ["/home/u/.mandu", "/run/user/1000/mandu"],
};

const USER = {
  agents: { defaults: { model: { primary: "anthropic/claude-sonnet-4-6" } } },
  channels: { telegram: { botToken: "tg-123" } },
  plugins: { entries: { brave: { enabled: true } }, load: { paths: ["/opt/other-plugin"] } },
  tools: { profile: "coding", alsoAllow: ["browser"] },
  models: { providers: { anthropic: { models: [{ id: "claude-x", maxTokens: 8000, baseUrl: "https://elsewhere.example" }] } } },
  $include: "./extra.json5",
};

test("the session rule and the port-file path", () => {
  assert.equal(attachmentSession("Work"), "openclaw:work");
  assert.equal(attachmentSession(""), "openclaw:main");
  assert.equal(normalizeAgentId("My Agent!"), "my-agent");
  assert.equal(anthropicProxyPortFile("/run/user/1000/mandu/", "openclaw:main"), "/run/user/1000/mandu/attachments/openclaw:main/anthropic-proxy.port");
  assert.equal(serviceProxyUrl(41234), "http://127.0.0.1:41234");
});

test("parsePortFile: digits and one newline, 1..65535", () => {
  assert.equal(parsePortFile("41234\n"), 41234);
  assert.equal(parsePortFile("1"), 1);
  for (const bad of ["", "0", "65536", " 41234", "41234\n\n", "41234 ", "4x", "-1", "http://127.0.0.1:1"]) {
    assert.equal(parsePortFile(bad), null, JSON.stringify(bad));
  }
});

test("portFileProblem: a regular file of this user that no one else can write", () => {
  assert.equal(portFileProblem({ isFile: true, uid: 1000, mode: 0o100600 }, 1000), null);
  assert.equal(portFileProblem({ isFile: true, uid: 1000, mode: 0o100644 }, 1000), null);
  assert.match(portFileProblem({ isFile: false, uid: 1000, mode: 0o40700 }, 1000)!, /not a regular file/);
  assert.match(portFileProblem({ isFile: true, uid: 0, mode: 0o100600 }, 1000)!, /not yours/);
  assert.match(portFileProblem({ isFile: true, uid: 1000, mode: 0o100666 }, 1000)!, /written by others/);
  assert.match(portFileProblem({ isFile: true, uid: 1000, mode: 0o100620 }, 1000)!, /written by others/);
});

test("identityProblem: only this session's Mandu model proxy is adopted", () => {
  const ok = { mandu: true, service: "anthropic-proxy", sessionKey: "openclaw:main", arbiterSock: "/run/a.sock" };
  assert.equal(identityProblem(ok, "openclaw:main"), null);
  assert.match(identityProblem(null, "openclaw:main")!, /nothing answered/);
  assert.match(identityProblem({ ...ok, mandu: false }, "openclaw:main")!, /non-Mandu/);
  assert.match(identityProblem({ ...ok, service: "net-proxy" }, "openclaw:main")!, /not its model proxy/);
  assert.match(identityProblem({ ...ok, sessionKey: "openclaw:work" }, "openclaw:main")!, /not openclaw:main/);
  assert.match(identityProblem({ ...ok, arbiterSock: undefined }, "openclaw:main")!, /no arbiter socket/);
});

test("planInstall: writes the plugin, the tools and the route; keeps everything else; drops a model's own endpoint", () => {
  const { doc, dropped } = planInstall(USER, FACTS);
  const d = doc as any;
  assert.deepEqual(d.plugins.load.paths, ["/opt/other-plugin", FACTS.pluginDir]);
  assert.deepEqual(d.plugins.entries["mandu-inspect"], {
    enabled: true,
    config: { arbiterSock: FACTS.arbiterSock, scopeId: "openclaw:main", attachment: true, agentId: "main", manduPaths: FACTS.manduPaths },
  });
  assert.deepEqual(d.plugins.entries.brave, { enabled: true }, "another plugin kept");
  assert.equal((d.plugins.entries["mandu-inspect"] as Record<string, unknown>).hooks, undefined, "no conversation access granted");
  assert.deepEqual(d.tools, { profile: "coding", alsoAllow: ["browser", "inspect_symbol", "declassify_symbol"] });
  assert.deepEqual(d.models.providers.anthropic, {
    models: [{ id: "claude-x", maxTokens: 8000 }],
    baseUrl: FACTS.proxyUrl,
    api: "anthropic-messages",
    headers: { "x-mandu-session-id": "openclaw:main", "x-mandu-tenant": "live" },
  });
  assert.deepEqual(dropped, ["claude-x.baseUrl"]);
  assert.equal(d.$include, "./extra.json5", "the include directive is kept");
  assert.deepEqual(d.channels, USER.channels);
  assert.deepEqual(d.agents, USER.agents);
  assert.equal((USER as any).plugins.load.paths.length, 1, "the input is not mutated");
});

test("planInstall is idempotent, and adds to an existing allowlist once", () => {
  const once = planInstall({ ...USER, plugins: { ...USER.plugins, allow: ["brave"] } }, FACTS).doc;
  const twice = planInstall(once, FACTS).doc;
  assert.deepEqual(twice, once);
  assert.deepEqual((once as any).plugins.allow, ["brave", "mandu-inspect"]);
  // A fresh config gets the whole route, with an empty model list (2026.3.12
  // rejects a provider without one).
  const fresh = planInstall({}, FACTS).doc as any;
  assert.deepEqual(fresh.models.providers.anthropic.models, []);
});

test("planUninstall removes what install added and nothing else", () => {
  const base = { ...USER, models: { providers: { anthropic: { models: [{ id: "claude-x", maxTokens: 8000 }] } } } };
  const installed = planInstall(base, FACTS).doc;
  const { doc, changed } = planUninstall(installed, FACTS.pluginDir);
  assert.equal(changed, true);
  const d = doc as any;
  assert.equal(d.plugins.entries["mandu-inspect"], undefined);
  assert.deepEqual(d.plugins.entries.brave, { enabled: true });
  assert.deepEqual(d.plugins.load.paths, ["/opt/other-plugin"]);
  assert.deepEqual(d.tools, { profile: "coding", alsoAllow: ["browser"] });
  assert.equal(d.models.providers.anthropic.baseUrl, undefined);
  assert.equal(d.models.providers.anthropic.headers, undefined);
  assert.deepEqual(d.models.providers.anthropic.models, [{ id: "claude-x", maxTokens: 8000 }]);
  assert.equal(d.models.providers.anthropic.api, "anthropic-messages", "api stays (the provider's own)");
  assert.equal(planUninstall(doc, FACTS.pluginDir).changed, false, "a second uninstall changes nothing");
  // A user's own non-Mandu headers and https baseUrl are not ours: kept.
  const own = { models: { providers: { anthropic: { baseUrl: "https://api.anthropic.com", headers: { "x-team": "a" } } } } };
  assert.equal(planUninstall(own).changed, false);
  // A stale load path of Mandu's plugin from another checkout is Mandu's too.
  const stale = { plugins: { load: { paths: ["/old/checkout/interceptors/openclaw-inspect-plugin/"] } } };
  assert.deepEqual(planUninstall(stale).doc, {});
});

test("planUninstall after an install on a config with no Anthropic provider gives the config back exactly", () => {
  // What OpenClaw 2026.9.9's non-interactive onboarding writes (no `models`
  // key; the fresh-openclaw-plugin VM leg): install creates the provider, and
  // uninstall used to leave `models.providers.anthropic = {api, models: []}`.
  const onboarded = {
    agents: { defaults: { model: { primary: "anthropic/claude-opus-5-5" }, workspace: "/home/u/.openclaw/workspace" } },
    gateway: { mode: "local", bind: "loopback", port: 18789 },
    tools: { profile: "full" },
    plugins: { entries: { anthropic: { enabled: true } } },
  };
  const installed = planInstall(onboarded, FACTS).doc as any;
  assert.equal(installed.models.providers.anthropic.baseUrl, FACTS.proxyUrl);
  assert.deepEqual(planUninstall(installed, FACTS.pluginDir).doc, onboarded);
  // A provider that holds anything else of the user's keeps what is left.
  const other = { models: { mode: "merge", providers: { anthropic: { models: [] }, openai: { apiKey: "x" } } } };
  const back = planUninstall(planInstall(other, FACTS).doc, FACTS.pluginDir).doc as any;
  assert.deepEqual(back.models, { mode: "merge", providers: { openai: { apiKey: "x" } } },
    "an empty anthropic provider install touched goes; the others and the models block stay");
  const own = { models: { providers: { anthropic: { models: [], timeoutMs: 5000 } } } };
  assert.deepEqual((planUninstall(planInstall(own, FACTS).doc, FACTS.pluginDir).doc as any).models.providers.anthropic,
    { models: [], timeoutMs: 5000, api: "anthropic-messages" }, "a provider with a key of the user's stays, api with it");
});

test("installRefusal: plugins off, the plugin denied; a provider's own endpoint is routed, not refused (Route 1)", () => {
  assert.equal(installRefusal({}), null);
  assert.match(installRefusal({ plugins: { enabled: false } })!, /plugins off/);
  assert.match(installRefusal({ plugins: { deny: ["mandu-inspect"] } })!, /denies the Mandu plugin/);
  // Before Route 1 these were refused; the proxy now forwards each one to
  // that address (openclaw-providers.ts decides what it can route).
  assert.equal(installRefusal({ models: { providers: { anthropic: { baseUrl: "https://gw.corp.example/anthropic" } } } }), null);
  assert.equal(installRefusal({ models: { providers: { anthropic: { baseUrl: "http://127.0.0.1:4000" } } } }), null);
  assert.equal(installRefusal({ models: { providers: { anthropic: { baseUrl: "http://127.0.0.1:1", headers: { "x-mandu-session-id": "openclaw:main" } } } } }), null);
});

test("attachState: the doctor's reading of a config", () => {
  const installed = planInstall(USER, FACTS).doc;
  const s = attachState(installed, { pluginDir: FACTS.pluginDir, serviceUrl: FACTS.proxyUrl });
  assert.equal(s.plugin, "enabled");
  assert.equal(s.attachment, true);
  assert.equal(s.loadPath, true);
  assert.equal(s.route, "service");
  assert.equal(s.routeSession, "openclaw:main");
  assert.deepEqual(s.modelsAround, []);
  assert.equal(looksAttached(s), true);
  assert.equal(attachedSession(installed), "openclaw:main");

  assert.equal(attachState(installed, { serviceUrl: "http://127.0.0.1:9" }).route, "other", "the service moved: stale route");
  assert.equal(attachState(installed, { serviceUrl: null }).route, "other");
  const disabled = planInstall(USER, FACTS).doc as any;
  disabled.plugins.entries["mandu-inspect"].enabled = false;
  assert.equal(attachState(disabled, { serviceUrl: null }).plugin, "disabled");
  const allowOther = planInstall(USER, FACTS).doc as any;
  allowOther.plugins.allow = ["brave"];
  assert.equal(attachState(allowOther, { serviceUrl: null }).plugin, "disabled", "an allowlist without it keeps it off");
  const around = planInstall(USER, FACTS).doc as any;
  around.models.providers.anthropic.models.push({ id: "m2", baseUrl: "https://x" });
  assert.deepEqual(attachState(around, { serviceUrl: FACTS.proxyUrl }).modelsAround, ["m2.baseUrl"]);

  const plain = attachState(USER, { serviceUrl: null });
  assert.equal(plain.plugin, "absent");
  assert.equal(plain.route, "none");
  assert.equal(looksAttached(plain), false, "a config with no sign of Mandu gets no doctor row");
  assert.equal(attachedSession(USER), null);
});

test("isLoopbackUrl", () => {
  for (const u of ["http://127.0.0.1:1", "http://localhost:8080/x", "http://[::1]:9"]) assert.equal(isLoopbackUrl(u), true, u);
  for (const u of ["https://127.0.0.1:1", "http://10.0.0.1:1", "not a url", 5]) assert.equal(isLoopbackUrl(u), false, String(u));
});
