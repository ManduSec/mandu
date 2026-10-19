/**
 * goose-route — what `mandu goose` sets and checks (src/goose-route.ts):
 * the env routing (anthropic and openai), every upload switch forced off,
 * the provider check over argv, env and config (goose 1.53.0's precedence),
 * the openai endpoint resolved as Goose resolves it, and the upload hosts
 * denied at the network layer (upload-deny.ts goose row; supported-agents.md
 * §5.6, §5.3.4 rule 1).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  GOOSE_DEFAULT_ROUTING,
  GOOSE_ROUTED_PROVIDER,
  gooseConfigDir,
  gooseConfigScalars,
  gooseForcedEnv,
  gooseHostOverride,
  gooseOpenAiNeedsProxy,
  gooseOpenAiEndpoint,
  gooseOpenAiRoutes,
  gooseProviderRefusal,
  gooseProviderVerdict,
  gooseResumePin,
  gooseResumes,
  gooseRoutePlan,
  readGooseConfig,
  type GooseConfig,
} from "../../src/goose-route.js";
import { uploadDenyGuardSpecs, uploadDenyHosts } from "../../src/upload-deny.js";

const NO_CFG: GooseConfig = { path: "/home/u/.config/goose/config.yaml", values: null, customProviders: [] };
const cfg = (values: Record<string, string>, customProviders: GooseConfig["customProviders"] = []): GooseConfig => ({ ...NO_CFG, values, customProviders });

test("forced env: the anthropic provider at the proxy, the subagent provider pinned, every upload switch off", () => {
  const e = gooseForcedEnv("http://127.0.0.1:8788");
  assert.equal(e["GOOSE_PROVIDER"], GOOSE_ROUTED_PROVIDER);
  assert.equal(e["GOOSE_SUBAGENT_PROVIDER"], "anthropic");
  assert.equal(e["ANTHROPIC_HOST"], "http://127.0.0.1:8788");
  assert.equal(e["GOOSE_TELEMETRY_OFF"], "1");
  assert.equal(e["GOOSE_TELEMETRY_ENABLED"], "false");
  // Goose falls back to the INIT_PROJECT form only when the first is UNSET: all four set empty
  for (const k of ["LANGFUSE_PUBLIC_KEY", "LANGFUSE_SECRET_KEY", "LANGFUSE_INIT_PROJECT_PUBLIC_KEY", "LANGFUSE_INIT_PROJECT_SECRET_KEY"]) assert.equal(e[k], "", k);
  assert.equal(e["OTEL_SDK_DISABLED"], "true");
  assert.equal(e["SECURITY_PROMPT_CLASSIFIER_ENABLED"], "false");
  assert.equal(e["SECURITY_COMMAND_CLASSIFIER_ENABLED"], "false");
  assert.equal(e["SECURITY_COMMAND_CLASSIFIER_ENABLED_OVERRIDE"], "false");
  assert.equal(e["GOOSE_TOOLSHIM"], "false");
  assert.equal(e["GOOSE_STATE_MACHINE"], "false", "no turn starts on an ACP session/load, on the saved provider");
  assert.equal(e["ANTHROPIC_BASE_URL"], undefined, "Goose ignores it; not set");
  // openai points at the proxy's route even when unused: a mid-session
  // `/model --provider openai` reaches the proxy, which refuses it
  assert.equal(e["OPENAI_HOST"], "http://127.0.0.1:8788/_mandu/openai/openai");
  assert.equal(e["OPENAI_BASE_PATH"], "v1/chat/completions");
});

test("forced env: an openai session pins both providers to openai, OPENAI_HOST at the proxy's route, the base path as resolved", () => {
  const e = gooseForcedEnv("http://gw.example:8080", "http://127.0.0.1:9000/", {
    provider: "openai", subagentProvider: "openai",
    openai: { upstream: "https://llm.corp/openai/v1", basePath: "chat/completions", wire: "chat" },
  });
  assert.equal(e["GOOSE_PROVIDER"], "openai");
  assert.equal(e["GOOSE_SUBAGENT_PROVIDER"], "openai");
  assert.equal(e["OPENAI_HOST"], "http://127.0.0.1:9000/_mandu/openai/openai", "the proxy, never the user's own endpoint");
  assert.equal(e["OPENAI_BASE_PATH"], "chat/completions");
  assert.equal(e["ANTHROPIC_HOST"], "http://gw.example:8080");
  assert.equal(e["GOOSE_TELEMETRY_OFF"], "1", "the upload switches are the same for every provider");
  assert.equal(e["OTEL_SDK_DISABLED"], "true");
});

test("gooseHostOverride: unset or the official endpoint is no override", () => {
  assert.equal(gooseHostOverride(undefined), undefined);
  assert.equal(gooseHostOverride(" "), undefined);
  assert.equal(gooseHostOverride("https://api.anthropic.com"), undefined);
  assert.equal(gooseHostOverride("https://API.anthropic.com/"), undefined);
  assert.equal(gooseHostOverride("http://gw.local:8080"), "http://gw.local:8080");
});

test("gooseConfigDir: an absolute GOOSE_PATH_ROOT's config, else XDG, else ~/.config", () => {
  assert.equal(gooseConfigDir({ GOOSE_PATH_ROOT: "/tmp/g", HOME: "/h" }), "/tmp/g/config");
  assert.equal(gooseConfigDir({ GOOSE_PATH_ROOT: "rel", HOME: "/h" }), "/h/.config/goose");
  assert.equal(gooseConfigDir({ XDG_CONFIG_HOME: "/x", HOME: "/h" }), "/x/goose");
  assert.equal(gooseConfigDir({ HOME: "/h" }), "/h/.config/goose");
});

test("gooseConfigScalars: top-level KEY: value lines, quotes and comments stripped, nested blocks skipped", () => {
  const s = gooseConfigScalars([
    "GOOSE_PROVIDER: openai",
    "GOOSE_MODEL: \"gpt-4o\"  # main",
    "extensions:",
    "  developer:",
    "    enabled: true",
    "GOOSE_SUBAGENT_PROVIDER: 'anthropic'",
    "otel_exporter_otlp_endpoint: http://otel.corp:4318",
  ].join("\n"));
  assert.deepEqual(s, {
    GOOSE_PROVIDER: "openai", GOOSE_MODEL: "gpt-4o", GOOSE_SUBAGENT_PROVIDER: "anthropic",
    otel_exporter_otlp_endpoint: "http://otel.corp:4318",
  });
});

test("provider check: anthropic everywhere (or unset) launches", () => {
  assert.equal(gooseProviderRefusal(["goose", "session"], {}, NO_CFG), null);
  assert.equal(gooseProviderRefusal(["goose", "run", "--provider", "anthropic", "-t", "x"], { GOOSE_PROVIDER: "anthropic" }, cfg({ GOOSE_PROVIDER: "Anthropic" })), null);
  assert.equal(gooseProviderRefusal(["./wrapper.sh"], { GOOSE_PROVIDER: "openai" }, NO_CFG), null, "a wrapper is vouched for by --target");
});

test("provider check: another provider in argv, env or config — for the session or its subagents — is refused, naming where", () => {
  const cases: Array<[string[], Record<string, string>, GooseConfig, RegExp]> = [
    [["goose", "run", "--provider", "groq", "-t", "x"], {}, NO_CFG, /--provider names the provider `groq`/],
    [["goose", "session", "--provider=lmstudio"], {}, NO_CFG, /--provider names the provider `lmstudio`/],
    // review hands its --provider to every `goose run` child (its own value flags: `-s <dir>`)
    [["goose", "review", "-s", "sub", "--provider", "google"], {}, NO_CFG, /--provider names the provider `google`/],
    [["goose", "review"], { GOOSE_PROVIDER: "mistral" }, NO_CFG, /GOOSE_PROVIDER names the provider `mistral`/],
    [["goose", "session"], { GOOSE_PROVIDER: "databricks" }, NO_CFG, /environment's GOOSE_PROVIDER names the provider `databricks`/],
    [["goose", "session"], {}, cfg({ GOOSE_PROVIDER: "deepseek" }), /GOOSE_PROVIDER in .*config\.yaml names the provider `deepseek`/],
    [["goose", "session"], {}, cfg({ GOOSE_SUBAGENT_PROVIDER: "custom_corp" }), /GOOSE_SUBAGENT_PROVIDER in .* names the provider `custom_corp`/],
    [["goose", "session"], { GOOSE_SUBAGENT_PROVIDER: "google" }, NO_CFG, /GOOSE_SUBAGENT_PROVIDER names the provider `google`/],
    [["goose", "session"], {}, cfg({}, [{ file: "anthropic.json", name: "anthropic" }]), /declarative provider custom_providers\/anthropic\.json/],
    [["goose", "session"], {}, cfg({}, [{ file: "openai.json", name: "openai" }]), /declarative provider custom_providers\/openai\.json is named `openai`/],
    // openai with an endpoint the proxy cannot reach
    [["goose", "session"], { GOOSE_PROVIDER: "openai", OPENAI_HOST: "http://llm.corp:8000" }, NO_CFG, /GOOSE_PROVIDER names the provider `openai`, but the environment's OPENAI_HOST \(`http:\/\/llm\.corp:8000`\) is not an endpoint/],
    [["goose", "session"], { GOOSE_PROVIDER: "openai", OPENAI_BASE_URL: "https://gw.corp/v1?api-version=2024" }, NO_CFG, /carries query parameters/],
    [["goose", "session"], { GOOSE_PROVIDER: "openai" }, cfg({ OPENAI_BASE_PATH: "engines/llama.cpp/v1/completions" }), /OPENAI_BASE_PATH in .* ends in neither `chat\/completions` nor `responses`/],
  ];
  for (const [argv, env, c, why] of cases) {
    const r = gooseProviderRefusal(argv, env, c);
    assert.ok(r, `${argv.join(" ")} ${JSON.stringify(env)} ${JSON.stringify(c.values)}`);
    assert.match(r!, /^mandu: refusing to launch goose: /);
    assert.match(r!, why);
    assert.match(r!, /routes Goose's built-in anthropic, openai, litellm, openrouter, ollama, xai and tetrate providers/, "the refusal names what is supported");
    assert.deepEqual(gooseRoutePlan(argv, env, c).routing, GOOSE_DEFAULT_ROUTING);
  }
  // the env outranks the config, as in Goose
  assert.equal(gooseProviderRefusal(["goose", "session"], { GOOSE_PROVIDER: "anthropic" }, cfg({ GOOSE_PROVIDER: "groq" })), null);
});

test("routing plan: openai from argv, env or config is routed; the subagent follows the session unless named; anthropic when none", () => {
  const api = { upstream: "https://api.openai.com", basePath: "v1/chat/completions", wire: "per-model" } as const;
  assert.deepEqual(gooseRoutePlan(["goose", "session"], {}, NO_CFG), { refusal: null, routing: GOOSE_DEFAULT_ROUTING });
  assert.deepEqual(gooseRoutePlan(["goose", "run", "--provider", "openai", "-t", "x"], {}, NO_CFG).routing,
    { provider: "openai", subagentProvider: "openai", openai: api });
  assert.deepEqual(gooseRoutePlan(["goose", "session"], { GOOSE_PROVIDER: "OpenAI" }, NO_CFG).routing,
    { provider: "openai", subagentProvider: "openai", openai: api });
  assert.deepEqual(gooseRoutePlan(["goose", "session"], {}, cfg({ GOOSE_PROVIDER: "openai", GOOSE_SUBAGENT_PROVIDER: "anthropic" })).routing,
    { provider: "openai", subagentProvider: "anthropic", openai: api });
  assert.deepEqual(gooseRoutePlan(["goose", "session"], {}, cfg({ GOOSE_SUBAGENT_PROVIDER: "openai" })).routing,
    { provider: "anthropic", subagentProvider: "openai", openai: api }, "a subagent-only openai still gets its route");
  // --provider outranks the env, as in Goose; both are checked
  assert.deepEqual(gooseRoutePlan(["goose", "session", "--provider", "anthropic"], { GOOSE_PROVIDER: "openai" }, NO_CFG).routing,
    { provider: "anthropic", subagentProvider: "anthropic", openai: null });
  assert.match(gooseRoutePlan(["goose", "session", "--provider", "openai"], { GOOSE_PROVIDER: "groq" }, NO_CFG).refusal ?? "", /GOOSE_PROVIDER names the provider `groq`/);
  // a wrapper is never refused and keeps a routable choice
  assert.deepEqual(gooseRoutePlan(["./wrapper.sh"], { GOOSE_PROVIDER: "openai" }, NO_CFG), { refusal: null, routing: { provider: "openai", subagentProvider: "openai", openai: api } });
  assert.deepEqual(gooseRoutePlan(["./wrapper.sh"], { GOOSE_PROVIDER: "groq" }, NO_CFG), { refusal: null, routing: GOOSE_DEFAULT_ROUTING });
  // the route the context proxy serves
  assert.deepEqual(gooseOpenAiRoutes(GOOSE_DEFAULT_ROUTING), []);
  assert.deepEqual(gooseOpenAiRoutes({ provider: "openai", subagentProvider: "openai", openai: api }),
    [{ id: "openai", api: "openai-completions", upstream: "https://api.openai.com" }]);
  assert.deepEqual(gooseOpenAiRoutes({ provider: "openai", subagentProvider: "openai", openai: { upstream: "https://x.test", basePath: "responses", wire: "responses" } }),
    [{ id: "openai", api: "openai-responses", upstream: "https://x.test" }]);
});

test("openai endpoint: resolved in goose 1.53.0's order, and Goose's wire choice kept (per model on the default path)", () => {
  const ep = (env: Record<string, string>, c: GooseConfig = NO_CFG) => gooseOpenAiEndpoint(env, c);
  // default: the host is the upstream, the default path stays (Goose picks per model; the proxy takes one /v1)
  assert.deepEqual(ep({}), { upstream: "https://api.openai.com", basePath: "v1/chat/completions", wire: "per-model" });
  // env OPENAI_HOST wins over OPENAI_BASE_URL and the config
  assert.deepEqual(ep({ OPENAI_HOST: "https://gw.corp/openai/", OPENAI_BASE_URL: "https://other.corp/v1" }, cfg({ OPENAI_HOST: "https://cfg.corp" })),
    { upstream: "https://gw.corp/openai", basePath: "v1/chat/completions", wire: "per-model" });
  // OPENAI_BASE_URL: a trailing /v1 moves into the default path; without it, the versionless chat path (chat only)
  assert.deepEqual(ep({ OPENAI_BASE_URL: "https://gw.corp/openai/v1" }), { upstream: "https://gw.corp/openai", basePath: "v1/chat/completions", wire: "per-model" });
  assert.deepEqual(ep({}, cfg({ OPENAI_BASE_URL: "https://gw.corp/api" })), { upstream: "https://gw.corp/api", basePath: "chat/completions", wire: "chat" });
  assert.match((ep({ OPENAI_BASE_URL: "localhost:1234/v1" }) as { why: string }).why ?? "", /literal loopback address/, "plain http to a NAME is refused, as for OpenClaw and OpenCode");
  assert.deepEqual(ep({ OPENAI_BASE_URL: "127.0.0.1:1234/v1" }), { upstream: "http://127.0.0.1:1234", basePath: "v1/chat/completions", wire: "per-model" }, "no scheme: http for loopback, as Goose adds it");
  // the config's OPENAI_HOST, with its OPENAI_BASE_PATH
  assert.deepEqual(ep({}, cfg({ OPENAI_HOST: "http://127.0.0.1:12434", OPENAI_BASE_PATH: "engines/llama.cpp/v1/chat/completions" })),
    { upstream: "http://127.0.0.1:12434/engines/llama.cpp/v1", basePath: "chat/completions", wire: "chat" }, "a custom chat path: its prefix moves into the upstream, the wire stays Chat");
  assert.deepEqual(ep({ OPENAI_BASE_PATH: "/v1/responses" }, cfg({ OPENAI_HOST: "https://gw.corp/x" })),
    { upstream: "https://gw.corp/v1", basePath: "responses", wire: "responses" }, "an absolute path replaces the host's own path");
  assert.deepEqual(ep({ OPENAI_BASE_PATH: "responses" }), { upstream: "https://api.openai.com", basePath: "responses", wire: "responses" });
  // refused: plain http off this machine, credentials, a query, a path that is neither wire, not a URL
  for (const [env, c, why] of [
    [{ OPENAI_HOST: "http://llm.corp" }, NO_CFG, /not an endpoint Mandu's model proxy forwards to/],
    [{ OPENAI_HOST: "https://u:p@llm.corp" }, NO_CFG, /no credentials/],
    [{ OPENAI_BASE_URL: "https://gw.corp/v1?key=1" }, NO_CFG, /query parameters/],
    [{}, cfg({ OPENAI_BASE_PATH: "v1/embeddings" }), /ends in neither/],
    [{ OPENAI_BASE_URL: "https://[bad" }, NO_CFG, /is not a URL/],
  ] as Array<[Record<string, string>, GooseConfig, RegExp]>) {
    const r = ep(env, c);
    assert.ok("why" in r, JSON.stringify(env));
    assert.match((r as { why: string }).why, why);
  }
});

test("provider verdict: the per-name rule other readers (a recipe's settings) reuse", () => {
  assert.deepEqual(gooseProviderVerdict(" Anthropic ", {}, NO_CFG), { routed: "anthropic", openai: null });
  assert.deepEqual(gooseProviderVerdict("openai", {}, NO_CFG), { routed: "openai", openai: { upstream: "https://api.openai.com", basePath: "v1/chat/completions", wire: "per-model" } });
  for (const p of ["google", "gcp_vertex_ai", "aws_bedrock", "groq", "lmstudio", "xai_oauth", "custom_corp", "databricks", "ollama_cloud"]) {
    const v = gooseProviderVerdict(p, {}, NO_CFG);
    assert.ok("why" in v, p);
  }
  assert.match((gooseProviderVerdict("openai", { OPENAI_HOST: "http://10.0.0.5:8000" }, NO_CFG) as { why: string }).why, /not an endpoint/);
});

test("openai beside a user's undeclared ANTHROPIC_HOST: the refusal names the host and the three ways out", () => {
  const m = gooseOpenAiNeedsProxy("https://gw.corp.example");
  assert.match(m, /^mandu: refusing to launch goose: /);
  assert.match(m, /\(https:\/\/gw\.corp\.example\)/);
  assert.match(m, /Unset ANTHROPIC_HOST/);
  assert.match(m, /policy\.yaml `models:`/);
});

test("resume shapes: `-r` / `--resume` on session and run (alone or in a cluster) is read; a flag's value, review and other commands are not", () => {
  for (const argv of [
    ["goose", "session", "--resume"],
    ["goose", "session", "-r", "--name", "x"],
    ["goose", "s", "-r", "--session-id", "20261005_1"],
    ["goose", "session", "--resume", "--fork"],
    ["goose", "run", "-r", "-n", "x", "-t", "go"],
    ["goose", "run", "-rs", "-t", "go"],
    ["goose", "run", "--text", "hi", "--resume"],
  ]) assert.equal(gooseResumes(argv), true, argv.join(" "));
  for (const argv of [
    ["goose", "session"],
    ["goose", "session", "--name", "-r"], // -r is the name here
    ["goose", "run", "-t", "-r"],
    ["goose", "run", "--no-session", "-t", "x"],
    ["goose", "run", "-t", "x", "--", "-r"],
    ["goose", "review", "-r"],
    ["./wrapper.sh", "run", "-r"],
  ]) assert.equal(gooseResumes(argv), false, argv.join(" "));
});

test("resume pin: `--provider <routed>` right after the subcommand, which outranks the provider saved with the session; a user's own --provider is kept; nothing else changes", () => {
  assert.deepEqual(gooseResumePin(["goose", "session", "--resume"], "anthropic"), ["goose", "session", "--provider", "anthropic", "--resume"]);
  assert.deepEqual(gooseResumePin(["goose", "run", "-r", "-n", "x", "-t", "go"], "openai"), ["goose", "run", "--provider", "openai", "-r", "-n", "x", "-t", "go"]);
  assert.deepEqual(gooseResumePin(["goose", "run", "-r", "--provider", "anthropic", "-t", "go"], "anthropic"), ["goose", "run", "-r", "--provider", "anthropic", "-t", "go"], "the user's own (checked) --provider stays the only one");
  for (const argv of [["goose", "session"], ["goose", "run", "--no-session", "-t", "x"], ["goose", "review"], ["./wrapper.sh", "session", "-r"]]) {
    assert.deepEqual(gooseResumePin(argv, "anthropic"), argv, argv.join(" "));
  }
});

test("readGooseConfig: the config's scalars and the declarative providers' names; a missing file reads as none", () => {
  const root = mkdtempSync(join(tmpdir(), "mandu-goose-cfg-"));
  try {
    assert.deepEqual(readGooseConfig({ GOOSE_PATH_ROOT: root }), { path: join(root, "config", "config.yaml"), values: null, customProviders: [] });
    mkdirSync(join(root, "config", "custom_providers"), { recursive: true });
    writeFileSync(join(root, "config", "config.yaml"), "GOOSE_PROVIDER: anthropic\n");
    writeFileSync(join(root, "config", "custom_providers", "corp.json"), JSON.stringify({ name: "corp_llm", engine: "openai", base_url: "https://llm.corp" }));
    writeFileSync(join(root, "config", "custom_providers", "bad.json"), "{not json");
    const c = readGooseConfig({ GOOSE_PATH_ROOT: root });
    assert.deepEqual(c.values, { GOOSE_PROVIDER: "anthropic" });
    assert.deepEqual(c.customProviders, [{ file: "corp.json", name: "corp_llm", baseUrl: "https://llm.corp", engine: "openai" }]);
    assert.equal(gooseProviderRefusal(["goose", "session"], {}, c), null, "a declarative provider under its own name is only refused when selected");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("upload deny (rule 1): PostHog and the Nostr relays always; the user's Langfuse / OTLP / classifier endpoints from env and config", () => {
  const hosts = uploadDenyHosts("goose", {
    LANGFUSE_URL: "https://cloud.langfuse.com", OTEL_EXPORTER_OTLP_ENDPOINT: "http://otel.corp:4318",
    SECURITY_PROMPT_CLASSIFIER_ENDPOINT: "https://clf.corp/v1",
  }, cfg({ otel_exporter_otlp_endpoint: "https://otlp.other.example" }));
  for (const h of ["us.i.posthog.com", "relay.damus.io", "relay.primal.net", "nos.lol", "relay.nostr.band",
    "cloud.langfuse.com", "otel.corp:4318", "clf.corp", "otlp.other.example"]) {
    assert.ok(hosts.includes(h), `${h} in ${hosts.join(",")}`);
  }
  assert.ok(uploadDenyGuardSpecs(hosts).includes("tcp:us.i.posthog.com:*"));
  assert.deepEqual(uploadDenyHosts("opencode", { LANGFUSE_URL: "https://cloud.langfuse.com" }), [], "only the goose row reads these keys");
});
