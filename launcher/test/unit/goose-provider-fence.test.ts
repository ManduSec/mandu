/**
 * goose-provider-fence — what keeps a provider Mandu does not route from
 * receiving a Goose session's conversation (src/goose-route.ts
 * GOOSE_PROVIDER_FENCE, gooseCustomProviderFence, GOOSE_PROVIDER_HOSTS;
 * src/upload-deny.ts goose `proxyOnly`; supported-agents.md §5.6.3).
 *
 * goose 1.53.0 builds a provider when an interactive `/model --provider
 * <name>` switches to it (and a nested `goose run --provider <name>` starts),
 * reading its endpoint keys env first at that moment: so every such key is in
 * the launch env, pointed where nothing is sent, and the hosts no key moves
 * are denied at the net-proxy.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  GOOSE_DEFAULT_ROUTING,
  GOOSE_PROVIDER_FENCE,
  GOOSE_PROVIDER_HOSTS,
  GOOSE_REFUSED_COMMAND,
  GOOSE_REFUSED_HOST,
  GOOSE_UNDENIABLE_HOSTS,
  gooseCustomProviderFence,
  gooseFenceEnv,
  gooseForcedEnv,
  gooseRefusalUrl,
  gooseRoutePlan,
  readGooseConfig,
  type GooseConfig,
} from "../../src/goose-route.js";
import { netProxyDenyHosts, uploadDenyGuardSpecs, uploadDenyHosts, uploadDenyProxyOnlyHosts } from "../../src/upload-deny.js";

const PROXY = "http://127.0.0.1:8788";
const NO_CFG: GooseConfig = { path: "/home/u/.config/goose/config.yaml", values: null, customProviders: [] };
const cfg = (values: Record<string, string> | null, customProviders: GooseConfig["customProviders"] = []): GooseConfig => ({ ...NO_CFG, values, customProviders });

/** goose-providers api_client.rs build_url: the base gets a trailing `/`,
 *  then the request path is joined (relative paths keep the base's path). */
function gooseUrl(base: string, path: string): URL {
  const u = new URL(base);
  if (u.pathname !== "/" && !u.pathname.endsWith("/")) u.pathname = `${u.pathname}/`;
  return new URL(path, u);
}

test("every endpoint key of the unrouted providers is in the forced env, each pointed where nothing is sent", () => {
  const e = gooseForcedEnv(PROXY);
  assert.ok(GOOSE_PROVIDER_FENCE.length >= 30, "goose 1.53.0's keys, pinned");
  for (const f of GOOSE_PROVIDER_FENCE) {
    const v = e[f.key];
    assert.ok(v, `${f.key} is set`);
    switch (f.form) {
      case "url": {
        assert.equal(v, gooseRefusalUrl(PROXY, f.provider), f.key);
        // whatever relative path Goose's provider appends stays under the
        // refusal route, on the proxy
        for (const p of ["v1/chat/completions", "chat/completions", "api/chat", "v1/messages", "serving-endpoints/x/invocations", "model/x/converse-stream"]) {
          const u = gooseUrl(v!, p);
          assert.equal(u.origin, PROXY, `${f.key} + ${p}`);
          assert.match(u.pathname, /^\/_mandu\/openai\/goose-unrouted-[A-Za-z0-9._-]+\//, `${f.key} + ${p}`);
        }
        break;
      }
      case "hostname":
        assert.equal(v, GOOSE_REFUSED_HOST);
        assert.ok(new URL(`https://${v}/login/device/code`).hostname.endsWith(".invalid"));
        break;
      case "location":
        // gcpvertexai.rs build_host_url: https://<location>-aiplatform.googleapis.com
        assert.ok(new URL(`https://${v}-aiplatform.googleapis.com/v1/projects/p`).hostname.endsWith(".invalid"), v);
        break;
      case "command":
        assert.equal(v, GOOSE_REFUSED_COMMAND);
        assert.ok(v!.startsWith("/dev/null/"), "under a file, so it can never exist");
        break;
    }
  }
  // the declarative `${VAR}` providers and the CLI-spawning ones are covered
  for (const k of ["GOOGLE_HOST", "LMSTUDIO_HOST", "MOONSHOT_BASE_URL", "ZAI_BASE_URL", "TANZU_AI_ENDPOINT", "CODEX_COMMAND", "CURSOR_AGENT_COMMAND", "GCP_LOCATION", "GITHUB_COPILOT_HOST", "AWS_ENDPOINT_URL_BEDROCK_RUNTIME"]) {
    assert.ok(GOOSE_PROVIDER_FENCE.some((f) => f.key === k), k);
  }
});

test("the routed providers' keys are Mandu's own, never fenced; the refusal ids are never a routed id", () => {
  for (const k of ["ANTHROPIC_HOST", "OPENAI_HOST", "OPENAI_BASE_PATH", "OPENAI_BASE_URL", "GOOSE_PROVIDER",
    "OLLAMA_HOST", "LITELLM_HOST", "LITELLM_BASE_PATH", "OPENROUTER_HOST", "XAI_HOST", "TETRATE_HOST"]) {
    assert.ok(!GOOSE_PROVIDER_FENCE.some((f) => f.key === k), k);
  }
  const e = gooseForcedEnv(PROXY);
  assert.equal(e["ANTHROPIC_HOST"], PROXY);
  assert.equal(e["OPENAI_HOST"], `${PROXY}/_mandu/openai/openai`);
  assert.equal(gooseRefusalUrl(`${PROXY}/`, "custom_corp llm"), `${PROXY}/_mandu/openai/goose-unrouted-custom_corp_llm`);
  assert.ok(!gooseRefusalUrl(PROXY, "openai").endsWith("/_mandu/openai/openai"));
});

test("the user's own declarative providers: a `${VAR}` host is fenced, a literal host is denied, what cannot be fenced is refused", () => {
  const c = cfg(null, [
    { file: "corp.json", name: "corp_llm", baseUrl: "${CORP_LLM_HOST}/v1/chat/completions" },
    { file: "corp.json", name: "corp-id", baseUrl: "${CORP_LLM_HOST}/v1/chat/completions" },
    { file: "local.json", name: "local_llama", baseUrl: "http://localhost:8080/v1" },
    { file: "cloud.json", name: "cloud_llm", baseUrl: "https://llm.vendor.example/v1/chat/completions" },
    { file: "via-proxy.json", name: "via_proxy", baseUrl: "${ANTHROPIC_HOST}" },
    { file: "nobase.json", name: "nobase" },
  ]);
  const r = gooseCustomProviderFence(c);
  assert.deepEqual(r.fencedVars, [{ key: "CORP_LLM_HOST", provider: "custom_corp_llm", form: "url" }]);
  assert.deepEqual(r.hosts, ["localhost:8080", "llm.vendor.example"]);
  assert.deepEqual(r.problems, []);
  const plan = gooseRoutePlan(["goose", "session"], {}, c);
  assert.equal(plan.refusal, null);
  assert.deepEqual(plan.routing.fencedVars, r.fencedVars);
  assert.equal(gooseForcedEnv(PROXY, PROXY, plan.routing)["CORP_LLM_HOST"], `${PROXY}/_mandu/openai/goose-unrouted-custom_corp_llm`);
  assert.equal(gooseFenceEnv(PROXY, r.fencedVars)["CORP_LLM_HOST"], `${PROXY}/_mandu/openai/goose-unrouted-custom_corp_llm`);
  // a wrapper (--target goose) is never refused, and gets the fence too
  assert.deepEqual(gooseRoutePlan(["./wrapper.sh"], {}, c).routing.fencedVars, r.fencedVars);

  for (const [p, why] of [
    [{ file: "anth.json", name: "claude_direct", baseUrl: "https://api.anthropic.com" }, /dials api\.anthropic\.com directly/],
    [{ file: "oai.json", name: "gpt_direct", baseUrl: "https://API.openai.com/v1" }, /dials api\.openai\.com directly/],
    [{ file: "mid.json", name: "regional", baseUrl: "https://${REGION}.llm.example/v1" }, /whose host Mandu cannot read/],
    [{ file: "path.json", name: "pathy", baseUrl: "${PATH}/v1" }, /takes its endpoint from \$\{PATH\}/],
    [{ file: "goosevar.json", name: "goosevar", baseUrl: "${GOOSE_PROVIDER}/v1" }, /cannot point away/],
  ] as const) {
    const refusal = gooseRoutePlan(["goose", "session"], {}, cfg(null, [p])).refusal;
    assert.ok(refusal, p.file);
    assert.match(refusal!, why);
    assert.match(refusal!, new RegExp(`custom_providers/${p.file.replace(".", "\\.")}`));
  }
});

test("the main provider in Goose's order: env GOOSE_PROVIDER, then the config's active_provider, then its GOOSE_PROVIDER", () => {
  // what `goose configure` writes on 1.53.0: refused when it names an unrouted provider
  const r = gooseRoutePlan(["goose", "session"], {}, cfg({ active_provider: "groq", GOOSE_PROVIDER: "anthropic" }));
  assert.match(r.refusal ?? "", /active_provider in .*config\.yaml names the provider `groq`/);
  // and routed when it names openai
  const o = gooseRoutePlan(["goose", "session"], {}, cfg({ active_provider: "openai" }));
  assert.equal(o.refusal, null);
  assert.equal(o.routing.provider, "openai");
  // the env outranks it
  assert.equal(gooseRoutePlan(["goose", "session"], { GOOSE_PROVIDER: "anthropic" }, cfg({ active_provider: "groq" })).refusal, null);
  // the legacy key still counts when active_provider is absent
  assert.match(gooseRoutePlan(["goose", "session"], {}, cfg({ GOOSE_PROVIDER: "groq" })).refusal ?? "", /GOOSE_PROVIDER in .* names the provider `groq`/);
  assert.deepEqual(gooseRoutePlan(["goose", "session"], {}, cfg({ active_provider: "anthropic" })).routing, GOOSE_DEFAULT_ROUTING);
});

test("readGooseConfig keeps each declarative provider's base URL as written", () => {
  const root = mkdtempSync(join(tmpdir(), "mandu-goose-fence-"));
  try {
    mkdirSync(join(root, "config", "custom_providers"), { recursive: true });
    writeFileSync(join(root, "config", "custom_providers", "corp.json"), JSON.stringify({ name: "corp_llm", engine: "openai", base_url: "${CORP_LLM_HOST}/v1" }));
    const c = readGooseConfig({ GOOSE_PATH_ROOT: root });
    assert.deepEqual(c.customProviders, [{ file: "corp.json", name: "corp_llm", baseUrl: "${CORP_LLM_HOST}/v1", engine: "openai" }]);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("network: the unrouted providers' model hosts are denied at the net-proxy only; a user's declarative host at both layers; Mandu's own hosts never", () => {
  const proxyOnly = uploadDenyProxyOnlyHosts("goose");
  for (const h of ["api.groq.com", "api.mistral.ai", "api.deepseek.com", "chatgpt.com", "cloudcode-pa.googleapis.com", "api.kimi.com",
    "nano-gpt.com", "openrouter.ai", "generativelanguage.googleapis.com", "ollama.com", "api.githubcopilot.com", ".githubcopilot.com",
    "bedrock-runtime.us-east-1.amazonaws.com", "bedrock-mantle.eu-central-1.api.aws", "api.moonshot.cn", "api.z.ai"]) {
    assert.ok(proxyOnly.includes(h), h);
  }
  for (const h of [...GOOSE_UNDENIABLE_HOSTS, "localhost", "127.0.0.1"]) {
    assert.ok(!proxyOnly.some((e) => e === h || e.startsWith(`${h}:`)), `${h} is never denied`);
    assert.ok(!GOOSE_PROVIDER_HOSTS.includes(h), h);
  }
  assert.equal(proxyOnly.length, new Set(proxyOnly).size, "no duplicates");
  // the connect guard keeps its short list: none of the provider hosts
  const both = uploadDenyHosts("goose", {}, cfg(null, [
    { file: "local.json", name: "local_llama", baseUrl: "http://localhost:8080/v1" },
    { file: "cloud.json", name: "cloud_llm", baseUrl: "https://llm.vendor.example/v1" },
  ]));
  assert.ok(both.includes("localhost:8080") && both.includes("llm.vendor.example"), both.join(","));
  assert.ok(!both.includes("api.groq.com"), "not at the guard");
  assert.ok(uploadDenyGuardSpecs(both).includes("tcp:localhost:8080"));
  // the net-proxy gets the union
  const np = netProxyDenyHosts({ uploadDenyHosts: both, netProxyOnlyDenyHosts: proxyOnly });
  assert.ok(np.includes("us.i.posthog.com") && np.includes("api.groq.com") && np.includes("llm.vendor.example"));
  assert.deepEqual(uploadDenyProxyOnlyHosts("claude"), [], "only the goose row has one");
});
