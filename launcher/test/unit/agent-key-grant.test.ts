/**
 * agent-key-grant — which `mandu goose` launches bind Goose's key to the
 * provider they route, and to which host (agent-sign-in.md §3): only the
 * provider's own API host over https or this machine's loopback, every
 * routed provider or none, and the human-plane registration that decides
 * whether the file is twinned (a failure keeps Goose's own key file).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { claudeKeyGrantPlan, codexAuthFile, codexKeyGrantPlan, codexSavedKey, codexTwinPlaceholder, gooseEnvKeyGrantPlans, gooseKeyGrantPlan, grantableHost, registerAgentKeyGrant, registerClaudeKeyGrant, registerCodexEnvKeyGrants, registerCodexKeyGrant, registerGooseEnvKeyGrants, withoutLauncherOnlyEnv, codexEnvKeyGrantPlans, type CodexKeyGrantLaunch, type EnvKeyGrantLaunch, type KeyGrantLaunch } from "../../src/agent-key-grant.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the grant exists only with the confidentiality axis on

const ENV = { HOME: "/home/u" };
const SECRETS = "/home/u/.config/goose/secrets.yaml";
const base: KeyGrantLaunch = { target: "goose", confidentiality: true, noContextProxy: false };
const OPENAI = (upstream: string) => ({ upstream, basePath: "v1/chat/completions", wire: "per-model" as const });

test("grantableHost: the provider's own host over https, or loopback as written; nothing else", () => {
  assert.deepEqual(grantableHost("anthropic", "https://api.anthropic.com"), { host: "api.anthropic.com", https: true });
  assert.deepEqual(grantableHost("openai", "https://api.openai.com/v1"), { host: "api.openai.com", https: true });
  assert.deepEqual(grantableHost("anthropic", "https://127.0.0.1:8443"), { host: "127.0.0.1", https: true });
  assert.deepEqual(grantableHost("openai", "http://localhost:11434/v1"), { host: "localhost", https: false });
  assert.deepEqual(grantableHost("openai", "http://[::1]:8000"), { host: "::1", https: false });
  for (const [p, u] of [
    ["anthropic", "http://api.anthropic.com"], ["anthropic", "https://api.openai.com"], ["openai", "https://api.anthropic.com"],
    ["openai", "https://llm.corp.example/v1"], ["anthropic", "https://gateway.example"], ["openai", "http://0.0.0.0:8000"], ["openai", "not a url"],
  ] as const) {
    assert.ok("why" in grantableHost(p, u), `${p} ${u}`);
  }
});

test("gooseKeyGrantPlan: the routed providers' fields, each to its upstream's host", () => {
  assert.deepEqual(gooseKeyGrantPlan(base, ENV, {}), { grant: { path: SECRETS, grants: [{ field: "ANTHROPIC_API_KEY", host: "api.anthropic.com", https: true }] } });
  assert.deepEqual(gooseKeyGrantPlan(base, ENV, { MANDU_UPSTREAM: "https://127.0.0.1:9999" }), { grant: { path: SECRETS, grants: [{ field: "ANTHROPIC_API_KEY", host: "127.0.0.1", https: true }] } });
  const both = gooseKeyGrantPlan({ ...base, gooseRouting: { provider: "openai", subagentProvider: "anthropic", openai: OPENAI("https://api.openai.com") } }, ENV, {});
  assert.deepEqual(both, { grant: { path: SECRETS, grants: [
    { field: "OPENAI_API_KEY", host: "api.openai.com", https: true },
    { field: "ANTHROPIC_API_KEY", host: "api.anthropic.com", https: true },
  ] } });
  // XDG_CONFIG_HOME / GOOSE_PATH_ROOT are Goose's (agent-login.ts gooseSecretsFile).
  const xdg = gooseKeyGrantPlan(base, { HOME: "/home/u", XDG_CONFIG_HOME: "/cfg" }, {});
  assert.ok("grant" in xdg && xdg.grant.path === "/cfg/goose/secrets.yaml", JSON.stringify(xdg));
  // A declared main model on loopback is the proxy's upstream.
  const local = gooseKeyGrantPlan({ ...base, tllmEndpoint: { name: "m", url: "http://127.0.0.1:8080", local: true, upstream: "http://127.0.0.1:8080" } }, ENV, { MANDU_UPSTREAM: "https://api.anthropic.com" });
  assert.deepEqual(local, { grant: { path: SECRETS, grants: [{ field: "ANTHROPIC_API_KEY", host: "127.0.0.1", https: false }] } });
});

test("gooseKeyGrantPlan: no grant at all when any routed provider is not grantable, or the launch cannot use one", () => {
  const none = (p: KeyGrantLaunch, env: Record<string, string> = ENV, penv: Record<string, string> = {}): string => {
    const r = gooseKeyGrantPlan(p, env, penv);
    assert.ok("none" in r, JSON.stringify(r));
    return (r as { none: string }).none;
  };
  assert.match(none({ ...base, target: "claude" }), /not a Goose launch/);
  assert.match(none({ ...base, confidentiality: false }), /axis is off/);
  assert.match(none({ ...base, effectiveAxes: { confidentiality: false, integrity: false } }), /axis is off/);
  assert.match(none(base, { ...ENV, MANDU_AUTH_SUBSTITUTION: "0" }), /MANDU_AUTH_SUBSTITUTION=0/);
  assert.match(none(base, ENV, { MANDU_AUTH_SUBSTITUTION: "0" }), /MANDU_AUTH_SUBSTITUTION=0/);
  // Goose's Chat Completions providers (§3.10): a remote LiteLLM or another
  // host for a vendor provider is no grant, and nothing else is granted
  // either (all or nothing); a launch routing only Ollama has no key.
  assert.match(none({ ...base, gooseRouting: { provider: "litellm", subagentProvider: "anthropic", openai: null, compat: [{ provider: "litellm", upstream: "https://litellm.corp.example" }] } }), /litellm upstream litellm\.corp\.example is not this machine/);
  assert.match(none({ ...base, gooseRouting: { provider: "openrouter", subagentProvider: "openrouter", openai: null, compat: [{ provider: "openrouter", upstream: "https://evil.example" }] } }), /neither openrouter\.ai/);
  assert.match(none({ ...base, gooseRouting: { provider: "ollama", subagentProvider: "ollama", openai: null, compat: [{ provider: "ollama", upstream: "http://127.0.0.1:11434" }] } }), /no routed provider takes a key/);
  assert.match(none({ ...base, gooseRouting: { provider: "xai", subagentProvider: "xai", openai: null } }), /xai route has no upstream/);
  assert.match(none({ ...base, noContextProxy: true }), /no model proxy/);
  assert.match(none({ ...base, anthropicBaseUrl: "https://gw.example" }), /around the model proxy/);
  // macOS read-blocks a confined file: no file grant there (§3.10).
  const mac = gooseKeyGrantPlan(base, ENV, {}, "darwin");
  assert.ok("none" in mac && /read-blocked/.test(mac.none), JSON.stringify(mac));
  assert.ok("grant" in gooseKeyGrantPlan(base, ENV, {}, "linux"));
  // openai at a remote custom host: the binding would let the net-proxy put
  // the key into a request body to that host, so nothing is granted, and the
  // anthropic subagent's key is not granted either (all or nothing).
  assert.match(none({ ...base, gooseRouting: { provider: "openai", subagentProvider: "anthropic", openai: OPENAI("https://llm.corp.example/v1") } }), /llm\.corp\.example/);
  assert.match(none({ ...base, gooseRouting: { provider: "openai", subagentProvider: "openai", openai: null } }), /no upstream/);
  assert.match(none(base, ENV, { MANDU_UPSTREAM: "https://gateway.example" }), /gateway\.example/);
});

test("registerAgentKeyGrant: on the human socket; anything short of a recorded grant keeps the own-key-file posture", async () => {
  const lines: string[] = [];
  const calls: Array<{ sock: string; op: string; args: Record<string, unknown> }> = [];
  const deps = (answer: (args: Record<string, unknown>) => unknown, exists = true) => ({
    call: async (sock: string, op: string, args: Record<string, unknown>) => { calls.push({ sock, op, args }); return answer(args); },
    log: (m: string) => lines.push(m),
    fileExists: () => exists,
  });
  const plan = { ...base, arbiterHumanSock: "/run/h.sock" };
  const ok = await registerAgentKeyGrant(plan, ENV, {}, deps(() => ({ granted: 1 })));
  assert.deepEqual(ok, { granted: true, path: SECRETS, hosts: ["api.anthropic.com"] });
  assert.deepEqual(calls[0], { sock: "/run/h.sock", op: "registerAuthGrant", args: { path: SECRETS, grants: [{ field: "ANTHROPIC_API_KEY", host: "api.anthropic.com", https: true }] } });
  assert.equal(lines.length, 0);

  assert.equal((await registerAgentKeyGrant(plan, ENV, {}, deps(() => ({ granted: 1 }), false))).granted, false, "no file: nothing to twin");
  assert.equal((await registerAgentKeyGrant({ ...base }, ENV, {}, deps(() => ({ granted: 1 })))).granted, false, "no human plane");
  assert.match(lines.pop()!, /^WARNING: .*human-plane socket.*reads .*secrets\.yaml raw/);
  assert.equal((await registerAgentKeyGrant(plan, ENV, {}, deps(() => ({ granted: 0 })))).granted, false, "not recorded");
  assert.match(lines.pop()!, /did not record/);
  assert.equal((await registerAgentKeyGrant(plan, ENV, {}, deps(() => { throw new Error("human-plane: refused"); }))).granted, false, "refused");
  assert.match(lines.pop()!, /could not record .*refused/);
  // The launcher's pid rides along when given: the arbiter keeps the grant
  // across its own restart while this launcher lives (§3.2 item 4).
  await registerAgentKeyGrant(plan, ENV, {}, { ...deps(() => ({ granted: 1 })), pid: 4242 });
  assert.equal(calls.at(-1)!.args["pid"], 4242);
  const n = calls.length;
  assert.equal((await registerAgentKeyGrant({ ...plan, target: "codex" }, ENV, {}, deps(() => ({ granted: 1 })))).granted, false);
  assert.equal(calls.length, n, "a launch with nothing to grant asks nothing");
});

// ── Claude Code's ANTHROPIC_API_KEY (§3.8) ──────────────────────────────────

const CLAUDE: EnvKeyGrantLaunch = { target: "claude", confidentiality: true, noContextProxy: false };
const KEYENV = { HOME: "/home/u", ANTHROPIC_API_KEY: "sk-ant-api03-MANDUFAKEclaudeENVkey" };

test("claudeKeyGrantPlan: ANTHROPIC_API_KEY to the anthropic upstream's host; nothing for another target, no key, the opt-outs or an ungrantable upstream", () => {
  const grant = (host: string, https = true) => ({ grant: { env: "ANTHROPIC_API_KEY", grants: [{ field: "ANTHROPIC_API_KEY", host, https }] } });
  assert.deepEqual(claudeKeyGrantPlan(CLAUDE, KEYENV, {}), grant("api.anthropic.com"));
  assert.deepEqual(claudeKeyGrantPlan(CLAUDE, KEYENV, { MANDU_UPSTREAM: "https://127.0.0.1:9443" }), grant("127.0.0.1"));
  assert.deepEqual(claudeKeyGrantPlan({ ...CLAUDE, tllmEndpoint: { name: "box", url: "http://127.0.0.1:8080", local: true, upstream: "http://127.0.0.1:8080" } }, KEYENV, {}), grant("127.0.0.1", false));
  const none = (p: EnvKeyGrantLaunch, env: Record<string, string | undefined> = KEYENV, pe: Record<string, string | undefined> = {}) => {
    const r = claudeKeyGrantPlan(p, env, pe);
    assert.ok("none" in r, JSON.stringify(r));
    return (r as { none: string }).none;
  };
  assert.match(none({ ...CLAUDE, target: "codex" }), /not a Claude Code launch/);
  assert.match(none(CLAUDE, { HOME: "/home/u" }), /no ANTHROPIC_API_KEY/, "a subscription sign-in: nothing to put back, nothing touched");
  assert.match(none(CLAUDE, { ...KEYENV, ANTHROPIC_API_KEY: "" }), /no ANTHROPIC_API_KEY/);
  assert.match(none({ ...CLAUDE, confidentiality: false }), /axis is off/);
  assert.match(none(CLAUDE, { ...KEYENV, MANDU_AUTH_SUBSTITUTION: "0" }), /MANDU_AUTH_SUBSTITUTION=0/);
  assert.match(none(CLAUDE, KEYENV, { MANDU_AUTH_SUBSTITUTION: "0" }), /MANDU_AUTH_SUBSTITUTION=0/);
  assert.match(none({ ...CLAUDE, envSecrets: false }), /--no-env-secrets/);
  assert.match(none({ ...CLAUDE, noContextProxy: true }), /no model proxy/);
  assert.match(none({ ...CLAUDE, anthropicBaseUrl: "https://gw.example" }), /around the model proxy/);
  assert.match(none(CLAUDE, KEYENV, { MANDU_UPSTREAM: "https://gateway.example" }), /gateway\.example/);
});

test("registerClaudeKeyGrant: the env form on the human socket with the launcher's pid; anything short of a recorded grant leaves the variable raw", async () => {
  const lines: string[] = [];
  const calls: Array<{ sock: string; op: string; args: Record<string, unknown> }> = [];
  const deps = (answer: () => unknown) => ({
    call: async (sock: string, op: string, args: Record<string, unknown>) => { calls.push({ sock, op, args }); return answer(); },
    log: (m: string) => lines.push(m),
    pid: 777,
  });
  const plan = { ...CLAUDE, arbiterHumanSock: "/run/h.sock" };
  assert.deepEqual(await registerClaudeKeyGrant(plan, KEYENV, {}, deps(() => ({ granted: 1 }))), { granted: true, name: "ANTHROPIC_API_KEY", hosts: ["api.anthropic.com"] });
  assert.deepEqual(calls[0], { sock: "/run/h.sock", op: "registerAuthGrant", args: { env: "ANTHROPIC_API_KEY", grants: [{ field: "ANTHROPIC_API_KEY", host: "api.anthropic.com", https: true }], pid: 777 } });
  assert.equal(lines.length, 0);
  for (const [answer, re] of [[() => ({ granted: 0 }), /did not record/], [() => { throw new Error("human-plane: refused"); }, /could not record .*refused/]] as const) {
    assert.equal((await registerClaudeKeyGrant(plan, KEYENV, {}, deps(answer))).granted, false);
    assert.match(lines.pop()!, re);
  }
  assert.equal((await registerClaudeKeyGrant(CLAUDE, KEYENV, {}, deps(() => ({ granted: 1 })))).granted, false, "no human plane");
  assert.match(lines.pop()!, /no human-plane socket.*ANTHROPIC_API_KEY stays/);
  const n = calls.length;
  assert.equal((await registerClaudeKeyGrant(plan, { HOME: "/home/u" }, {}, deps(() => ({ granted: 1 })))).granted, false);
  assert.equal(calls.length, n, "no key: nothing asked");
});

// ── Codex's saved key (§3.9) ─────────────────────────────────────────────────

const CODEX: CodexKeyGrantLaunch = {
  target: "codex", confidentiality: true, noContextProxy: false, argv: ["/usr/bin/codex", "exec", "hi"],
  codexAuth: "sign-in", writeMcp: false, ullm: { mode: "api", baseUrl: "https://api.anthropic.com" },
};
const SAVED = JSON.stringify({ OPENAI_API_KEY: "sk-proj-MANDUFAKEcodexUNIT", tokens: null, last_refresh: null });
const AUTH = "/home/u/.codex/auth.json";

test("codexAuthFile / codexSavedKey / codexTwinPlaceholder: the file, the API-key mode only, the twin's placeholder", () => {
  assert.equal(codexAuthFile({ HOME: "/home/u" }), AUTH);
  assert.equal(codexAuthFile({ HOME: "/home/u", CODEX_HOME: "/srv/cx/" }), "/srv/cx/auth.json");
  assert.equal(codexAuthFile({ HOME: "/home/u", CODEX_HOME: "relative" }), AUTH, "a relative CODEX_HOME is not a place");
  assert.deepEqual(codexSavedKey(SAVED), { key: "sk-proj-MANDUFAKEcodexUNIT" });
  for (const [text, re] of [
    [null, /no auth\.json/], ["{", /not JSON/], ["[]", /not an object/],
    [JSON.stringify({ OPENAI_API_KEY: null, tokens: { access_token: "x" } }), /ChatGPT sign-in/],
    [JSON.stringify({ OPENAI_API_KEY: "sk-x", tokens: { access_token: "x" } }), /ChatGPT sign-in/],
    [JSON.stringify({ tokens: null }), /no saved key/], [JSON.stringify({ OPENAI_API_KEY: "sk x\n" }), /header-safe/],
  ] as const) {
    const r = codexSavedKey(text);
    assert.ok("why" in r && re.test(r.why), `${text}: ${JSON.stringify(r)}`);
  }
  assert.equal(codexTwinPlaceholder('{\n  "OPENAI_API_KEY": "$MDU:nomodel_Read[e0c7].OPENAI_API_KEY",\n  "tokens": null\n}'), "$MDU:nomodel_Read[e0c7].OPENAI_API_KEY");
  assert.equal(codexTwinPlaceholder('{"OPENAI_API_KEY": "sk-raw"}'), null, "not a placeholder");
  assert.equal(codexTwinPlaceholder("$MDU:nomodel_Read[e0c7]"), null, "a whole-file twin");
  assert.equal(codexTwinPlaceholder(undefined), null);
});

test("codexKeyGrantPlan: the saved key to the API origin's host; nothing for a key variable, a ChatGPT sign-in, another platform, the opt-out, an ungrantable upstream, or a U-LLM codex exec with no forwarder", () => {
  const read = (t: string | null) => () => t;
  const ok = codexKeyGrantPlan(CODEX, { HOME: "/home/u" }, {}, "linux", read(SAVED));
  assert.deepEqual(ok, { grant: { path: AUTH, grants: [{ field: "OPENAI_API_KEY", host: "api.openai.com", https: true }] }, key: "sk-proj-MANDUFAKEcodexUNIT" });
  assert.deepEqual((codexKeyGrantPlan(CODEX, { HOME: "/home/u" }, { MANDU_UPSTREAM: "http://127.0.0.1:9000" }, "linux", read(SAVED)) as { grant: { grants: unknown } }).grant.grants, [{ field: "OPENAI_API_KEY", host: "127.0.0.1", https: false }]);
  const none = (p: CodexKeyGrantLaunch, opts: { env?: Record<string, string>; pe?: Record<string, string>; platform?: string; text?: string | null } = {}) => {
    const r = codexKeyGrantPlan(p, opts.env ?? { HOME: "/home/u" }, opts.pe ?? {}, opts.platform ?? "linux", read(opts.text === undefined ? SAVED : opts.text));
    assert.ok("none" in r, JSON.stringify(r));
    return (r as { none: string }).none;
  };
  assert.match(none({ ...CODEX, target: "claude" }), /not a Codex launch/);
  assert.match(none({ ...CODEX, argv: ["node", "x.js"] }), /not a Codex launch/);
  assert.match(none(CODEX, { platform: "darwin" }), /read-blocked/);
  assert.match(none({ ...CODEX, confidentiality: false }), /axis is off/);
  assert.match(none(CODEX, { env: { HOME: "/home/u", MANDU_AUTH_SUBSTITUTION: "0" } }), /MANDU_AUTH_SUBSTITUTION=0/);
  assert.match(none({ ...CODEX, noContextProxy: true }), /no model proxy/);
  assert.match(none({ ...CODEX, codexAuth: "key" }), /key variable/);
  assert.match(none({ ...CODEX, openaiBaseUrl: "https://gw.example/v1" }), /around the model proxy/);
  assert.match(none(CODEX, { pe: { MANDU_UPSTREAM: "https://gateway.example" } }), /gateway\.example/);
  assert.match(none(CODEX, { text: JSON.stringify({ tokens: { access_token: "x" } }) }), /ChatGPT sign-in/);
  // The AI helper on Codex reads the same file: only with the forwarder that puts the key back for it.
  const helper = { ...CODEX, writeMcp: true, ullm: { mode: "cli" as const, baseUrl: "https://api.anthropic.com", binary: "codex" } };
  assert.match(none(helper), /no forwarder/);
  assert.ok("grant" in codexKeyGrantPlan({ ...helper, ullm: { ...helper.ullm, forwarderUrl: "http://127.0.0.1:5" } }, { HOME: "/home/u" }, {}, "linux", read(SAVED)));
});

test("registerCodexKeyGrant: the file form on the human socket with the pid; the key is returned for the forwarder and never logged", async () => {
  const lines: string[] = [];
  const calls: Array<{ op: string; args: Record<string, unknown> }> = [];
  const deps = (answer: () => unknown) => ({
    call: async (_s: string, op: string, args: Record<string, unknown>) => { calls.push({ op, args }); return answer(); },
    log: (m: string) => lines.push(m), pid: 9, platform: "linux", readFile: () => SAVED,
  });
  const plan = { ...CODEX, arbiterHumanSock: "/run/h.sock" };
  assert.deepEqual(await registerCodexKeyGrant(plan, { HOME: "/home/u" }, {}, deps(() => ({ granted: 1 }))), { granted: true, path: AUTH, hosts: ["api.openai.com"], key: "sk-proj-MANDUFAKEcodexUNIT" });
  assert.deepEqual(calls[0], { op: "registerAuthGrant", args: { path: AUTH, grants: [{ field: "OPENAI_API_KEY", host: "api.openai.com", https: true }], pid: 9 } });
  assert.equal((await registerCodexKeyGrant(plan, { HOME: "/home/u" }, {}, deps(() => { throw new Error("refused"); }))).granted, false);
  assert.equal((await registerCodexKeyGrant(CODEX, { HOME: "/home/u" }, {}, deps(() => ({ granted: 1 })))).granted, false, "no human plane");
  assert.ok(!lines.join("\n").includes("MANDUFAKEcodexUNIT"), "never the key in a line");
});

// ── Goose's Chat Completions providers (§3.10) ───────────────────────────────

test("gooseKeyGrantPlan (§3.10): each compat provider's key field to its own API host or loopback; Ollama asks for nothing", () => {
  const routing = (provider: string, sub: string, compat: Array<{ provider: string; upstream: string }>) =>
    ({ ...base, gooseRouting: { provider, subagentProvider: sub, openai: null, compat } } as KeyGrantLaunch);
  const grants = (p: KeyGrantLaunch) => {
    const r = gooseKeyGrantPlan(p, ENV, {});
    assert.ok("grant" in r, JSON.stringify(r));
    return (r as { grant: { grants: unknown } }).grant.grants;
  };
  assert.deepEqual(grants(routing("openrouter", "openrouter", [{ provider: "openrouter", upstream: "https://openrouter.ai" }])), [{ field: "OPENROUTER_API_KEY", host: "openrouter.ai", https: true }]);
  assert.deepEqual(grants(routing("xai", "xai", [{ provider: "xai", upstream: "https://api.x.ai/v1" }])), [{ field: "XAI_API_KEY", host: "api.x.ai", https: true }]);
  assert.deepEqual(grants(routing("tetrate", "tetrate", [{ provider: "tetrate", upstream: "https://api.router.tetrate.ai" }])), [{ field: "TETRATE_API_KEY", host: "api.router.tetrate.ai", https: true }]);
  assert.deepEqual(grants(routing("litellm", "litellm", [{ provider: "litellm", upstream: "http://localhost:4000" }])), [{ field: "LITELLM_API_KEY", host: "localhost", https: false }]);
  // A session on ollama with an anthropic subagent: the anthropic key only.
  assert.deepEqual(grants(routing("ollama", "anthropic", [{ provider: "ollama", upstream: "http://127.0.0.1:11434" }])), [{ field: "ANTHROPIC_API_KEY", host: "api.anthropic.com", https: true }]);
  // Two providers: both fields, each to its own host.
  assert.deepEqual(grants(routing("openrouter", "anthropic", [{ provider: "openrouter", upstream: "https://openrouter.ai" }])), [
    { field: "OPENROUTER_API_KEY", host: "openrouter.ai", https: true },
    { field: "ANTHROPIC_API_KEY", host: "api.anthropic.com", https: true },
  ]);
  for (const [p, u] of [["openrouter", "http://openrouter.ai"], ["xai", "https://api.openai.com"], ["tetrate", "https://tetrate.example"], ["litellm", "http://10.0.0.5:4000"]] as const) {
    assert.ok("why" in grantableHost(p, u), `${p} ${u}`);
  }
});

test("gooseEnvKeyGrantPlans / registerGooseEnvKeyGrants: one env grant per routed provider's key variable that is set, per variable", async () => {
  const p = { ...base, gooseRouting: { provider: "openrouter", subagentProvider: "anthropic", openai: null, compat: [{ provider: "openrouter", upstream: "https://openrouter.ai" }] } } as KeyGrantLaunch;
  const env = { ...ENV, OPENROUTER_API_KEY: "sk-or-MANDUFAKE", ANTHROPIC_API_KEY: "sk-ant-MANDUFAKE" };
  assert.deepEqual(gooseEnvKeyGrantPlans(p, env, {}), [
    { env: "OPENROUTER_API_KEY", grants: [{ field: "OPENROUTER_API_KEY", host: "openrouter.ai", https: true }] },
    { env: "ANTHROPIC_API_KEY", grants: [{ field: "ANTHROPIC_API_KEY", host: "api.anthropic.com", https: true }] },
  ]);
  assert.deepEqual(gooseEnvKeyGrantPlans(p, { ...ENV, OPENROUTER_API_KEY: "sk-or-x" }, {}).map((g) => g.env), ["OPENROUTER_API_KEY"], "only the variables that are set");
  // Per variable: an ungrantable provider leaves its own variable raw, the other is still granted.
  const remote = { ...base, gooseRouting: { provider: "openrouter", subagentProvider: "anthropic", openai: null, compat: [{ provider: "openrouter", upstream: "https://evil.example" }] } } as KeyGrantLaunch;
  assert.deepEqual(gooseEnvKeyGrantPlans(remote, env, {}).map((g) => g.env), ["ANTHROPIC_API_KEY"]);
  for (const off of [{ ...p, target: "claude" as const }, { ...p, confidentiality: false }, { ...p, noContextProxy: true }, { ...p, envSecrets: false }]) {
    assert.deepEqual(gooseEnvKeyGrantPlans(off as KeyGrantLaunch, env, {}), []);
  }
  assert.deepEqual(gooseEnvKeyGrantPlans(p, { ...env, MANDU_AUTH_SUBSTITUTION: "0" }, {}), []);

  const calls: Array<Record<string, unknown>> = [];
  const lines: string[] = [];
  const deps = (answer: (a: Record<string, unknown>) => unknown) => ({
    call: async (_s: string, _op: string, args: Record<string, unknown>) => { calls.push(args); return answer(args); },
    log: (m: string) => lines.push(m), pid: 5,
  });
  const plan = { ...p, arbiterHumanSock: "/run/h.sock" };
  assert.deepEqual(await registerGooseEnvKeyGrants(plan, env, {}, deps(() => ({ granted: 1 }))), [
    { name: "OPENROUTER_API_KEY", hosts: ["openrouter.ai"] }, { name: "ANTHROPIC_API_KEY", hosts: ["api.anthropic.com"] },
  ]);
  assert.deepEqual(calls[0], { env: "OPENROUTER_API_KEY", grants: [{ field: "OPENROUTER_API_KEY", host: "openrouter.ai", https: true }], pid: 5 });
  // One refused: that variable stays raw, said once; the other is granted.
  const some = await registerGooseEnvKeyGrants(plan, env, {}, deps((a) => { if (a["env"] === "OPENROUTER_API_KEY") throw new Error("refused"); return { granted: 1 }; }));
  assert.deepEqual(some.map((g) => g.name), ["ANTHROPIC_API_KEY"]);
  assert.match(lines.pop()!, /OPENROUTER_API_KEY stays in Goose's environment/);
  assert.deepEqual(await registerGooseEnvKeyGrants(p, env, {}, deps(() => ({ granted: 1 }))), [], "no human plane");
  assert.ok(!lines.join("\n").includes("MANDUFAKE"), "never a value in a line");
});

// ── Codex's key variables and Mandu's own helper key (§3.11) ─────────────────

test("codexEnvKeyGrantPlans: each set key variable to the API origin's host, for a Codex launch on a key; nothing otherwise", () => {
  const p = { ...CODEX, codexAuth: "key" as const, envSecrets: true };
  const env = { HOME: "/home/u", OPENAI_API_KEY: "sk-proj-MANDUFAKE", CODEX_API_KEY: "sk-proj-MANDUFAKE2" };
  assert.deepEqual(codexEnvKeyGrantPlans(p, env, {}), [
    { env: "OPENAI_API_KEY", grants: [{ field: "OPENAI_API_KEY", host: "api.openai.com", https: true }] },
    { env: "CODEX_API_KEY", grants: [{ field: "CODEX_API_KEY", host: "api.openai.com", https: true }] },
  ]);
  assert.deepEqual(codexEnvKeyGrantPlans(p, { HOME: "/home/u", CODEX_API_KEY: "sk-x" }, { MANDU_UPSTREAM: "http://127.0.0.1:9" }), [
    { env: "CODEX_API_KEY", grants: [{ field: "CODEX_API_KEY", host: "127.0.0.1", https: false }] },
  ]);
  for (const off of [
    { ...p, codexAuth: "sign-in" as const }, { ...p, target: "claude" as const }, { ...p, argv: ["bash"] },
    { ...p, confidentiality: false }, { ...p, noContextProxy: true }, { ...p, envSecrets: false }, { ...p, openaiBaseUrl: "https://gw.example/v1" },
  ]) {
    assert.deepEqual(codexEnvKeyGrantPlans(off, env, {}), [], JSON.stringify(off));
  }
  assert.deepEqual(codexEnvKeyGrantPlans(p, { ...env, MANDU_AUTH_SUBSTITUTION: "0" }, {}), []);
  assert.deepEqual(codexEnvKeyGrantPlans(p, env, { MANDU_UPSTREAM: "https://gateway.example" }), [], "an ungrantable upstream: the variables stay raw");
});

test("registerCodexEnvKeyGrants: one env grant per variable on the human socket; a refusal leaves that variable raw", async () => {
  const p = { ...CODEX, codexAuth: "key" as const, arbiterHumanSock: "/run/h.sock" };
  const calls: Array<Record<string, unknown>> = [];
  const lines: string[] = [];
  const env = { HOME: "/home/u", OPENAI_API_KEY: "sk-proj-MANDUFAKE" };
  const got = await registerCodexEnvKeyGrants(p, env, {}, {
    call: async (_s, _op, args) => { calls.push(args); return { granted: 1 }; }, log: (m) => lines.push(m), pid: 3,
  });
  assert.deepEqual(got, [{ name: "OPENAI_API_KEY", hosts: ["api.openai.com"] }]);
  assert.deepEqual(calls[0], { env: "OPENAI_API_KEY", grants: [{ field: "OPENAI_API_KEY", host: "api.openai.com", https: true }], pid: 3 });
  const refused = await registerCodexEnvKeyGrants(p, env, {}, { call: async () => { throw new Error("no"); }, log: (m) => lines.push(m) });
  assert.deepEqual(refused, []);
  assert.match(lines.pop()!, /OPENAI_API_KEY stays in Codex's environment/);
});

test("withoutLauncherOnlyEnv: MANDU_ULLM_API_KEY never reaches the agent's environment; everything else is kept", () => {
  assert.deepEqual(withoutLauncherOnlyEnv({ PATH: "/bin", MANDU_ULLM_API_KEY: "sk-ant-MANDUFAKE", MANDU_ULLM_MODEL: "m" }), { PATH: "/bin", MANDU_ULLM_MODEL: "m" });
  const same = { PATH: "/bin" };
  assert.equal(withoutLauncherOnlyEnv(same), same, "untouched when absent");
});
