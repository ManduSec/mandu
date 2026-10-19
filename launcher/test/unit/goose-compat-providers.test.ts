/**
 * goose-compat-providers — Goose's built-in Chat Completions providers with
 * an env host (litellm, openrouter, ollama, xai, tetrate) routed through the
 * model proxy (src/goose-route.ts GOOSE_COMPAT_PROVIDERS, gooseCompatEndpoint;
 * supported-agents.md §5.6.4): each endpoint resolved as goose 1.53.0
 * resolves it, the host keys pinned at the proxy's route of the provider's
 * own id whether or not the launch routes it, the routes handed to the
 * proxy (ollama's marked `textCalls`), and the refusals for an endpoint the
 * proxy cannot reach.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  GOOSE_COMPAT_PROVIDERS,
  GOOSE_DEFAULT_ROUTING,
  GOOSE_PROVIDER_FENCE,
  gooseCompatEndpoint,
  gooseCompatSpec,
  gooseCompatUrl,
  gooseCustomProviderFence,
  gooseForcedEnv,
  gooseOpenAiRoutes,
  gooseProviderVerdict,
  gooseResumePin,
  gooseRoutePlan,
  type GooseConfig,
} from "../../src/goose-route.js";

const PROXY = "http://127.0.0.1:9000";
const NO_CFG: GooseConfig = { path: "/home/u/.config/goose/config.yaml", values: null, customProviders: [] };
const cfg = (values: Record<string, string> | null, customProviders: GooseConfig["customProviders"] = []): GooseConfig => ({ ...NO_CFG, values, customProviders });

/** How Goose's ApiClient joins a request path to its host (api_client.rs
 *  build_url): a slash is added to a host path without one, then the
 *  relative path is joined. */
function gooseUrl(base: string, path: string): URL {
  const u = new URL(base);
  if (u.pathname !== "/" && !u.pathname.endsWith("/")) u.pathname = `${u.pathname}/`;
  return new URL(path, u);
}

const ep = (p: string, env: Record<string, string> = {}, c: GooseConfig = NO_CFG) => gooseCompatEndpoint(gooseCompatSpec(p)!, env, c);

test("goose 1.53.0's defaults: each provider's own host, as the proxy reaches it (a loopback name as 127.0.0.1)", () => {
  assert.deepEqual(GOOSE_COMPAT_PROVIDERS.map((c) => c.provider), ["litellm", "openrouter", "ollama", "xai", "tetrate"]);
  assert.deepEqual(ep("litellm"), { provider: "litellm", upstream: "http://127.0.0.1:4000", basePath: "v1/chat/completions" });
  assert.deepEqual(ep("openrouter"), { provider: "openrouter", upstream: "https://openrouter.ai" });
  assert.deepEqual(ep("ollama"), { provider: "ollama", upstream: "http://127.0.0.1:11434" });
  assert.deepEqual(ep("xai"), { provider: "xai", upstream: "https://api.x.ai/v1" });
  assert.deepEqual(ep("tetrate"), { provider: "tetrate", upstream: "https://api.router.tetrate.ai" });
});

test("the user's own host, env first then config, normalized as Goose does (ollama: http:// added, a bare loopback name gets 11434)", () => {
  assert.equal((ep("ollama", { OLLAMA_HOST: "127.0.0.1" }) as { upstream: string }).upstream, "http://127.0.0.1:11434");
  assert.equal((ep("ollama", { OLLAMA_HOST: "localhost:8080" }) as { upstream: string }).upstream, "http://127.0.0.1:8080");
  assert.equal((ep("ollama", { OLLAMA_HOST: "https://ollama.corp.example" }) as { upstream: string }).upstream, "https://ollama.corp.example");
  assert.equal((ep("ollama", {}, cfg({ OLLAMA_HOST: "http://127.0.0.1:7000/ol" })) as { upstream: string }).upstream, "http://127.0.0.1:7000/ol");
  assert.equal((ep("openrouter", { OPENROUTER_HOST: "https://or.gw.example/" }) as { upstream: string }).upstream, "https://or.gw.example");
  assert.equal((ep("xai", { XAI_HOST: "https://x.gw.example/v1" }, cfg({ XAI_HOST: "https://ignored.example" })) as { upstream: string }).upstream, "https://x.gw.example/v1", "env outranks the config");
  assert.equal((ep("tetrate", {}, cfg({ TETRATE_HOST: "https://t.gw.example" })) as { upstream: string }).upstream, "https://t.gw.example");
});

test("litellm's base path: the default stays (the proxy reads one /v1); a prefix moves into the upstream; another wire is refused", () => {
  assert.deepEqual(ep("litellm", { LITELLM_HOST: "https://llm.corp" }), { provider: "litellm", upstream: "https://llm.corp", basePath: "v1/chat/completions" });
  assert.deepEqual(ep("litellm", { LITELLM_HOST: "https://llm.corp/gw", LITELLM_BASE_PATH: "litellm/v1/chat/completions" }),
    { provider: "litellm", upstream: "https://llm.corp/gw/litellm/v1", basePath: "chat/completions" });
  assert.deepEqual(ep("litellm", { LITELLM_HOST: "https://llm.corp/gw" }, cfg({ LITELLM_BASE_PATH: "/api/chat/completions" })),
    { provider: "litellm", upstream: "https://llm.corp/api", basePath: "chat/completions" }, "an absolute path replaces the host's path");
  assert.match((ep("litellm", { LITELLM_BASE_PATH: "v1/completions" }) as { why: string }).why, /LITELLM_BASE_PATH \(`v1\/completions`\) does not end in `chat\/completions`/);
});

test("an endpoint the proxy cannot reach is refused, naming the setting", () => {
  for (const [p, env, re] of [
    ["ollama", { OLLAMA_HOST: "http://192.168.1.20:11434" }, /OLLAMA_HOST \(`http:\/\/192\.168\.1\.20:11434`\) is not an endpoint/],
    ["ollama", { OLLAMA_HOST: "gpu-box" }, /OLLAMA_HOST \(`gpu-box`\) is not an endpoint/], // plain http to another machine
    ["litellm", { LITELLM_HOST: "localhost:4000" }, /LITELLM_HOST/], // no scheme: Goose cannot use it either
    ["openrouter", { OPENROUTER_HOST: "https://user:pw@or.example" }, /OPENROUTER_HOST/],
    ["xai", { XAI_HOST: "https://api.x.ai/v1?team=1" }, /XAI_HOST/],
    ["tetrate", { TETRATE_HOST: "http://router.corp:8080" }, /TETRATE_HOST/],
  ] as Array<[string, Record<string, string>, RegExp]>) {
    const v = ep(p, env);
    assert.ok("why" in v, `${p} ${JSON.stringify(env)}`);
    assert.match(v.why, re);
  }
});

test("verdict and plan: each provider is routed from argv, env or config, for the session or its subagents", () => {
  assert.deepEqual(gooseProviderVerdict(" OLLAMA ", {}, NO_CFG), { routed: "ollama", openai: null, compat: { provider: "ollama", upstream: "http://127.0.0.1:11434" } });
  for (const c of GOOSE_COMPAT_PROVIDERS) {
    const viaArgv = gooseRoutePlan(["goose", "run", "--provider", c.provider, "-t", "x"], {}, NO_CFG);
    assert.equal(viaArgv.refusal, null, c.provider);
    assert.equal(viaArgv.routing.provider, c.provider);
    assert.equal(viaArgv.routing.subagentProvider, c.provider, "the subagent follows the session");
    assert.equal(viaArgv.routing.compat?.length, 1);
    assert.equal(viaArgv.routing.compat![0]!.provider, c.provider);
    assert.equal(gooseRoutePlan(["goose", "session"], {}, cfg({ active_provider: c.provider })).routing.provider, c.provider);
  }
  // main on one, subagents on another: both routed
  const two = gooseRoutePlan(["goose", "session"], { GOOSE_PROVIDER: "openrouter", GOOSE_SUBAGENT_PROVIDER: "ollama" }, NO_CFG);
  assert.equal(two.refusal, null);
  assert.deepEqual(two.routing.compat!.map((c) => c.provider), ["openrouter", "ollama"]);
  assert.deepEqual(gooseOpenAiRoutes(two.routing), [
    { id: "openrouter", api: "openai-completions", upstream: "https://openrouter.ai" },
    { id: "ollama", api: "openai-completions", upstream: "http://127.0.0.1:11434", textCalls: true },
  ]);
  // a provider the launch does not use gets no route (a switch to it is refused at the proxy)
  assert.deepEqual(gooseOpenAiRoutes(gooseRoutePlan(["goose", "session"], { GOOSE_PROVIDER: "xai" }, NO_CFG).routing).map((r) => r.id), ["xai"]);
  assert.deepEqual(gooseRoutePlan(["goose", "session"], {}, NO_CFG).routing, GOOSE_DEFAULT_ROUTING, "anthropic when none is named: no compat routes");
  // refused: an endpoint the proxy cannot reach
  const bad = gooseRoutePlan(["goose", "session"], { GOOSE_PROVIDER: "ollama", OLLAMA_HOST: "http://10.0.0.9:11434" }, NO_CFG);
  assert.match(bad.refusal ?? "", /GOOSE_PROVIDER names the provider `ollama`, but the environment's OLLAMA_HOST/);
  assert.deepEqual(bad.routing, GOOSE_DEFAULT_ROUTING);
  // a resumed session gets the routed provider pinned
  assert.deepEqual(gooseResumePin(["goose", "session", "-r"], "ollama"), ["goose", "session", "--provider", "ollama", "-r"]);
});

test("forced env: every provider's host key at its own proxy route, routed or not; LITELLM_BASE_PATH pinned; none is in the fence", () => {
  for (const routing of [GOOSE_DEFAULT_ROUTING, gooseRoutePlan(["goose", "session"], { GOOSE_PROVIDER: "litellm", LITELLM_BASE_PATH: "gw/chat/completions" }, NO_CFG).routing]) {
    const e = gooseForcedEnv(PROXY, PROXY, routing);
    for (const c of GOOSE_COMPAT_PROVIDERS) {
      assert.equal(e[c.hostKey], `${PROXY}/_mandu/openai/${c.provider}`, c.hostKey);
      assert.equal(e[c.hostKey], gooseCompatUrl(`${PROXY}/`, c.provider));
      assert.ok(!GOOSE_PROVIDER_FENCE.some((f) => f.key === c.hostKey), `${c.hostKey} is not fenced`);
      // every path Goose joins to it stays under the provider's route
      const u = gooseUrl(e[c.hostKey]!, c.path);
      assert.equal(u.origin, PROXY);
      assert.ok(u.pathname.startsWith(`/_mandu/openai/${c.provider}/`), u.pathname);
    }
  }
  assert.equal(gooseForcedEnv(PROXY)["LITELLM_BASE_PATH"], "v1/chat/completions");
  const lite = gooseRoutePlan(["goose", "session"], { GOOSE_PROVIDER: "litellm", LITELLM_HOST: "https://llm.corp", LITELLM_BASE_PATH: "gw/chat/completions" }, NO_CFG).routing;
  assert.equal(gooseForcedEnv(PROXY, PROXY, lite)["LITELLM_BASE_PATH"], "chat/completions");
  assert.equal(gooseOpenAiRoutes(lite)[0]!.upstream, "https://llm.corp/gw");
  // the paths Goose sends reach `<upstream><path>` on the proxy's routes
  assert.equal(gooseUrl(gooseForcedEnv(PROXY)["OPENROUTER_HOST"]!, "api/v1/chat/completions").pathname, "/_mandu/openai/openrouter/api/v1/chat/completions");
  assert.equal(gooseUrl(gooseForcedEnv(PROXY)["XAI_HOST"]!, "chat/completions").pathname, "/_mandu/openai/xai/chat/completions");
});

test("declarative providers: one named like a routed Chat Completions provider is refused only when the launch uses that provider; an ollama-engine one on a routed key other than OLLAMA_HOST is refused", () => {
  const named = cfg(null, [{ file: "ollama.json", name: "ollama", baseUrl: "https://llm.vendor.example/v1", engine: "ollama" }]);
  assert.equal(gooseRoutePlan(["goose", "session"], {}, named).refusal, null, "not used: the fence covers its literal host");
  assert.match(gooseRoutePlan(["goose", "session"], { GOOSE_PROVIDER: "ollama" }, named).refusal ?? "", /custom_providers\/ollama\.json is named `ollama`/);
  // a `${VAR}` that is a routed host key is not fenced (already at the proxy)
  const onRouted = gooseCustomProviderFence(cfg(null, [{ file: "lite.json", name: "lite2", baseUrl: "${LITELLM_HOST}/v1", engine: "openai" }]));
  assert.deepEqual([onRouted.fencedVars, onRouted.problems], [[], []]);
  // Goose's ollama engine runs tool calls written as text: only the ollama route checks that
  for (const engine of ["ollama", "ollama_compatible"]) {
    const r = gooseCustomProviderFence(cfg(null, [{ file: "q.json", name: "qwen", baseUrl: "${OPENAI_HOST}", engine }]));
    assert.match(r.problems.join(""), /ollama-engine provider on \$\{OPENAI_HOST\}/, engine);
  }
  assert.deepEqual(gooseCustomProviderFence(cfg(null, [{ file: "q.json", name: "qwen", baseUrl: "${OLLAMA_HOST}", engine: "ollama" }])).problems, []);
});
