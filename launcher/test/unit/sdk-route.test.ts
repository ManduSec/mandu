/**
 * sdk-route.test — the SDK route (docs/design/agents/agent-sdks.md): which
 * launches get it, the route the launcher composes, and the preload's pure
 * routeSpawn, plus the parity of the preload's Codex argv logic with
 * codex-argv.ts. No process is spawned (the hooks: the
 * sdk-route-preload component test).
 *
 * PROJECT INVARIANT: an agent CLI a host program starts reaches its model
 * through the launch's proxy, or it does not start.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import {
  CODEX_CONNECTORS_OFF, CODEX_UPLOADS_OFF, CODEX_UPLOADS_OFF_OVERRIDES, codexLaunchRefusal, codexOverridesReach, codexSpliceOverrides, codexUploadConflict,
} from "../../src/codex-argv.js";
import { codexProviderToml, codexShellNote } from "../../src/env-compose.js";
import { isAttentionNote } from "../../src/launch-banner.js";
import {
  composeSdkRoute, pythonSkipsSiteHook, requireOption, SDK_ROUTE_ENV, sdkHostNote, sdkHostRefusal, sdkRouteApplies, sdkRouteEnv,
  claudeShimRoute, claudeShimScript, sdkRouteFiles, sdkRouteWriteProtect, sdkShimScript, withHead, writeSdkRouteDir, type ClaudeShimRoute, type SdkRoute,
} from "../../src/sdk-route.js";
import { hostRuntimeOf, type LaunchPlan } from "../../src/types.js";
import { CLAUDE_ROUTE_ENV_KEYS, claudeEnvRefusal, claudeRouteArgs, claudeRouteEnv, claudeRouteOverlay } from "../../src/claude-route.js";

// Axes: none. Routing is axis-independent and nothing here starts a service.

interface Preload {
  ROUTE_ENV: string;
  parseRoute(raw: string | undefined): SdkRoute | null;
  effectiveRoute(route: SdkRoute, own: Record<string, string | undefined>): SdkRoute;
  routeEnv(route: SdkRoute, env: Record<string, string | undefined>): Record<string, string>;
  routeSpawn(route: SdkRoute | null, file: string, args: string[], env: Record<string, string | undefined>): { args: string[]; env: Record<string, string> };
  ROUTE_DIR: string;
  ROUTE_FILE: string;
  spliceCodex(argv: string[], overrides: string[]): string[];
  codexRefusal(argv: string[]): string | null;
  UPLOADS_OFF: string[][];
  UPLOADS_OFF_OVERRIDES: string[];
  CONNECTORS_OFF: string[];
  uploadConflict(kv: string): boolean;
}
const preload = createRequire(import.meta.url)("../../src/sdk-route-preload.cjs") as Preload;

const PRELOAD = "/opt/mandu/dist/sdk-route-preload.cjs";

function plan(over: Partial<LaunchPlan> = {}): LaunchPlan {
  return {
    target: "claude",
    argv: ["node", "app.js"],
    scopeId: "sid", tenant: "live",
    arbiterSock: "/run/mandu/arbiter.sock", arbiterSockMode: "pinned" as const, arbiterRuntimeBase: "/tmp/mandu",
    eventDir: "/run/mandu/sid/events",
    cwd: "/work", humanCwd: "/work",
    noContextProxy: true, fsSync: false,
    basePath: "/usr/bin:/bin",
    proxy: { host: "127.0.0.1", port: 8788 },
    openaiProxy: { host: "127.0.0.1", port: 8789 },
    openaiProviderName: "mandu",
    noProxyExtra: [],
    requested: { netProxy: false, netProxyMitm: false, execWrap: false },
    execWrapCmds: [],
    ullm: { mode: "cli", baseUrl: "https://api.anthropic.com", binary: "claude" },
    noScope: false, writeMcp: true, replyFilter: true, bestEffort: false,
    ...over,
  };
}

/** A claude launch's composed delta, as run.ts holds it in mut.env. */
const CLAUDE_ENV = {
  MANDU_SCOPE_ID: "sid", MANDU_ARBITER_SOCK: "/run/mandu/arbiter.sock", MANDU_TENANT: "live",
  ANTHROPIC_BASE_URL: "http://127.0.0.1:8788",
  ANTHROPIC_CUSTOM_HEADERS: "x-mandu-session-id: sid;x-mandu-tenant: live",
  HTTPS_PROXY: "http://127.0.0.1:8790", NO_PROXY: "127.0.0.1,localhost",
  NODE_EXTRA_CA_CERTS: "/run/mandu/sid/ca.pem",
  PATH: "/run/mandu/sid/box:/run/mandu/sid/shims:/usr/bin:/bin",
  NODE_OPTIONS: "--disable-warning=UNDICI-EHPA",
  STRIPE_KEY: "$MDU:nomodel_env[1a2b].STRIPE_KEY",
  MANDU_ARBITER_HUMAN_SOCK: "/run/mandu/human.sock",
};
const SHIMS = { execBoxShimDir: "/run/mandu/sid/box", shimDir: "/run/mandu/sid/shims" };

function claudeRoute(): SdkRoute {
  return composeSdkRoute(plan(SHIMS), CLAUDE_ENV, ["STRIPE_KEY"], PRELOAD)!;
}
function codexRoute(over: Partial<LaunchPlan> = {}): SdkRoute {
  const { ANTHROPIC_BASE_URL: _a, ANTHROPIC_CUSTOM_HEADERS: _h, ...env } = CLAUDE_ENV;
  return composeSdkRoute(plan({ target: "codex", ...SHIMS, ...over }), env, ["STRIPE_KEY"], PRELOAD)!;
}

// ── which launches get the route ────────────────────────────────────────────

test("hostRuntimeOf: Node runtimes load the preload, Python ones the Python hook, Bun and Deno neither; agents and shells are not runtimes", () => {
  for (const b of ["node", "/usr/bin/node", "nodejs", "npx", "tsx", "ts-node"]) assert.equal(hostRuntimeOf(b), "node", b);
  for (const b of ["python3", "/usr/bin/python3.12", "python", "uv", "uvx", "pipx"]) assert.equal(hostRuntimeOf(b), "python", b);
  for (const b of ["bun", "bunx", "deno"]) assert.equal(hostRuntimeOf(b), "other", b);
  for (const b of ["claude", "codex", "bash", "./app.sh", "openclaw", undefined]) assert.equal(hostRuntimeOf(b), null, String(b));
});

test("sdkRouteApplies: a runtime under claude/codex/shell, a wrapper under claude/codex; never the agent itself, a shell, or openclaw/opencode", () => {
  const at = (target: LaunchPlan["target"], ...argv: string[]) => sdkRouteApplies({ target, argv });
  assert.equal(at("claude", "node", "app.js"), "runtime");
  assert.equal(at("codex", "/usr/bin/node", "app.js"), "runtime");
  assert.equal(at("shell", "python3", "app.py"), "runtime");
  assert.equal(at("claude", "./run-app.sh"), "wrapper");
  assert.equal(at("codex", "/usr/bin/env", "node", "app.js"), "wrapper");
  assert.equal(at("claude", "claude", "-p", "hi"), null, "the agent CLI keeps its own routing");
  assert.equal(at("codex", "/usr/local/bin/codex", "exec"), null);
  assert.equal(at("claude", "bash", "-c", "x"), null, "a shell is the oracles' stand-in, not a host");
  assert.equal(at("shell", "bash"), null);
  assert.equal(at("shell", "./tool"), null, "a plain command under the shell target is not a host");
  assert.equal(at("openclaw", "node", "openclaw.mjs"), null, "config-routed agents are routed by their config file");
  assert.equal(at("opencode", "node", "x.js"), null);
});

test("codexOverridesReach: a language runtime takes no Codex argv splice (`node -c` is node's --check); its note is the SDK route's", () => {
  assert.equal(codexOverridesReach("node"), false);
  assert.equal(codexOverridesReach("/usr/bin/python3"), false);
  assert.equal(codexOverridesReach("./my-codex-wrapper"), true, "a wrapper still receives them");
  assert.equal(codexShellNote({ target: "codex", argv: ["node", "app.js"] }), null, "not the shell note");
  assert.ok(codexShellNote({ target: "codex", argv: ["bash"] }) !== null, "a shell keeps its note");
});

// ── the route ───────────────────────────────────────────────────────────────

test("composeSdkRoute (claude): the routing variables, never PATH / NODE_OPTIONS / a masked secret / the human-plane socket", () => {
  const r = claudeRoute();
  assert.equal(r.v, 1);
  assert.equal(r.target, "claude");
  assert.equal(r.anthropic, true);
  assert.equal(r.codex, null);
  assert.equal(r.env["ANTHROPIC_BASE_URL"], "http://127.0.0.1:8788");
  assert.equal(r.env["HTTPS_PROXY"], "http://127.0.0.1:8790");
  assert.equal(r.env["MANDU_ARBITER_SOCK"], "/run/mandu/arbiter.sock");
  for (const k of ["PATH", "NODE_OPTIONS", "STRIPE_KEY", "MANDU_ARBITER_HUMAN_SOCK", SDK_ROUTE_ENV]) assert.ok(!(k in r.env), k);
  assert.ok(!JSON.stringify(r).includes("human.sock"), "the human-plane socket is not even named in the route");
  assert.deepEqual(r.pathPrefix, ["/run/mandu/sid/box", "/run/mandu/sid/shims"]);
  assert.equal(r.path, CLAUDE_ENV.PATH);
  assert.equal(r.require, PRELOAD);
});

test("composeSdkRoute (codex): the provider TOML for each way the child authenticates, from codexProviderToml", () => {
  const r = codexRoute();
  assert.equal(r.anthropic, false);
  assert.equal(r.codex!.provider, "mandu");
  const p = plan({ target: "codex" });
  assert.equal(r.codex!.toml.OPENAI_API_KEY, codexProviderToml({ ...p, codexAuth: "key", openaiEnvKey: "OPENAI_API_KEY" }));
  assert.match(r.codex!.toml.CODEX_API_KEY, /env_key="CODEX_API_KEY"/);
  assert.match(r.codex!.toml["sign-in"], /requires_openai_auth=true/);
  assert.match(r.codex!.toml.OPENAI_API_KEY, /base_url="http:\/\/127\.0\.0\.1:8789\/v1"/);
  // A user base URL (MANDU_OPENAI_BASE_URL) wants its own key: never a sign-in.
  const own = codexRoute({ openaiBaseUrl: "http://10.0.0.5:8000/v1" });
  assert.doesNotMatch(own.codex!.toml["sign-in"], /requires_openai_auth/);
});

test("composeSdkRoute: null for a launch the route does not serve", () => {
  assert.equal(composeSdkRoute(plan({ argv: ["claude"] }), CLAUDE_ENV, [], PRELOAD), null);
  assert.equal(composeSdkRoute(plan({ target: "shell", argv: ["bash"] }), CLAUDE_ENV, [], PRELOAD), null);
  assert.equal(composeSdkRoute(plan({ target: "opencode", argv: ["node", "x.js"] }), CLAUDE_ENV, [], PRELOAD), null);
});

test("composeSdkRoute: the launch's permission-mode answer rides a claude or shell route (claude-permission-mode.ts), never a codex one, and survives the preload's parse", () => {
  const mode = { cwd: "/work", configDir: "/home/u/.claude", scopes: ["user" as const] };
  const r = composeSdkRoute(plan(), CLAUDE_ENV, [], PRELOAD, mode)!;
  assert.deepEqual(r.claudeMode, mode);
  assert.deepEqual(preload.parseRoute(JSON.stringify(r))!.claudeMode, mode);
  assert.deepEqual(composeSdkRoute(plan({ target: "shell", argv: ["node", "x.js"] }), CLAUDE_ENV, [], PRELOAD, mode)!.claudeMode, mode);
  assert.equal(composeSdkRoute(plan({ target: "codex", ...SHIMS }), CLAUDE_ENV, [], PRELOAD, mode)!.claudeMode, undefined);
  assert.equal("claudeMode" in composeSdkRoute(plan(), CLAUDE_ENV, [], PRELOAD)!, false);
});

test("sdkRouteEnv: NODE_OPTIONS with the preload added once, the launch's own options kept, never the route itself; a spaced path is quoted", () => {
  const r = claudeRoute();
  const e = sdkRouteEnv(r, "--disable-warning=UNDICI-EHPA");
  assert.ok(!(SDK_ROUTE_ENV in e), "the route rides the launch's file, not the environment (agent-sdks.md §3.6)");
  assert.equal(e["NODE_OPTIONS"], `--disable-warning=UNDICI-EHPA --require=${PRELOAD}`);
  assert.equal(sdkRouteEnv(r, e["NODE_OPTIONS"])["NODE_OPTIONS"], e["NODE_OPTIONS"], "not added twice");
  assert.equal(requireOption("/home/a b/x.cjs"), '--require="/home/a b/x.cjs"');
});

test("sdkHostNote: ACTIVE for a Node or Python host or a wrapper; WARNING (attention) for a Bun or Deno host, which loads neither hook", () => {
  const node = sdkHostNote({ target: "codex", argv: ["node", "app.js"] })!;
  assert.match(node, /SDK route ACTIVE .* a Node program/);
  assert.match(sdkHostNote({ target: "claude", argv: ["./run.sh"] })!, /SDK route ACTIVE/);
  const py = sdkHostNote({ target: "codex", argv: ["python3", "app.py"] })!;
  assert.match(py, /SDK route ACTIVE .* a Python program/);
  assert.ok(!isAttentionNote(py));
  const bun = sdkHostNote({ target: "claude", argv: ["bun", "app.ts"] })!;
  assert.match(bun, /WARNING: .* any `codex`, is NOT routed/);
  assert.ok(isAttentionNote(bun), "printed in full on the compact display");
  assert.equal(sdkHostNote({ target: "claude", argv: ["claude"] }), null);
});

test("sdkHostRefusal: under --target codex, a host neither hook reaches refuses the launch (Bun, Deno, Python -I/-E/-S); claude and shell launches only warn", () => {
  const at = (target: LaunchPlan["target"], ...argv: string[]) => sdkHostRefusal({ target, argv });
  assert.match(at("codex", "bun", "app.ts")!, /refusing to launch: 'bun' loads neither/);
  assert.match(at("codex", "/usr/bin/deno", "run", "app.ts")!, /'deno' loads neither/);
  assert.match(at("codex", "python3", "-I", "app.py")!, /'python3 -I' skips Python's sitecustomize/);
  assert.match(at("codex", "python3", "-BE", "app.py")!, /-E/);
  assert.match(at("codex", "python3.12", "-W", "ignore", "-S", "app.py")!, /-S/);
  assert.equal(at("codex", "python3", "-c", "import x", "-I"), null, "after -c, the rest is the program's");
  assert.equal(at("codex", "python3", "-W", "I", "app.py"), null, "-W's value is not a flag");
  assert.equal(at("codex", "python3", "-WI", "app.py"), null, "nor attached");
  assert.equal(at("codex", "python3", "app.py", "-I"), null, "after the script, the program's own");
  assert.equal(at("codex", "node", "app.js"), null);
  assert.equal(at("codex", "uv", "run", "app.py"), null);
  assert.equal(at("claude", "bun", "app.ts"), null, "claude: the environment routes the SDK's default start; the note warns");
  assert.equal(at("shell", "bun", "x.ts"), null);
  assert.equal(at("codex", "./run.sh"), null, "a wrapper is not a runtime");
  assert.equal(pythonSkipsSiteHook(["python3", "--check-hash-based-pycs", "always", "-I", "x.py"]), "-I");
});

// ── the preload's routeSpawn ────────────────────────────────────────────────

test("routeSpawn: a child given its OWN environment (the SDKs' `env` option) gets the routing back, a host base URL overridden", () => {
  const r = claudeRoute();
  const out = preload.routeSpawn(r, "/x/node_modules/@anthropic-ai/claude-agent-sdk-linux-x64/claude", ["--output-format", "stream-json"], {
    ANTHROPIC_API_KEY: "sk-ant-x", ANTHROPIC_BASE_URL: "https://api.anthropic.com", PATH: "/usr/bin",
    [SDK_ROUTE_ENV]: JSON.stringify({ ...r, launchRouting: { ...r.launchRouting, ANTHROPIC_BASE_URL: "http://127.0.0.1:9" } }),
  });
  assert.deepEqual(out.args.slice(2), ["--output-format", "stream-json"], "claude's own arguments stay");
  assert.equal(out.args[0], "--settings", "the routing rides the last --settings (claude-route.ts)");
  assert.equal((JSON.parse(out.args[1]!) as { env: Record<string, string> }).env["ANTHROPIC_BASE_URL"], "http://127.0.0.1:8788");
  assert.equal(out.env["ANTHROPIC_BASE_URL"], "http://127.0.0.1:8788", "the launch's proxy wins over the host's value");
  assert.equal(out.env["ANTHROPIC_CUSTOM_HEADERS"], CLAUDE_ENV.ANTHROPIC_CUSTOM_HEADERS);
  assert.equal(out.env["HTTPS_PROXY"], "http://127.0.0.1:8790");
  assert.equal(out.env["ANTHROPIC_API_KEY"], "sk-ant-x", "the host's own variables stay");
  assert.equal(out.env["PATH"], "/run/mandu/sid/box:/run/mandu/sid/shims:/usr/bin", "the shims back at the head");
  assert.equal(out.env["NODE_OPTIONS"], `--require=${PRELOAD}`, "the preload rides into Node grandchildren");
  assert.ok(!(SDK_ROUTE_ENV in out.env), "a route in the child's environment (stale or forged) goes no further");
  // No PATH at all: the agent PATH.
  assert.equal(preload.routeSpawn(r, "/bin/true", [], {}).env["PATH"], CLAUDE_ENV.PATH);
});

test("routeSpawn (codex): the SDK's `codex exec --experimental-json` gets the provider splice and Codex's own uploads off at every level, keyed by the child's own key", () => {
  const r = codexRoute();
  const sdkArgs = ["exec", "--experimental-json", "--config", 'openai_base_url="https://api.openai.com/v1"', "--model", "gpt-5", "--skip-git-repo-check"];
  const out = preload.routeSpawn(r, "/x/node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/bin/codex", sdkArgs, { OPENAI_API_KEY: "sk-x" });
  const ov = ["-c", "model_provider=mandu", "-c", `model_providers.mandu=${r.codex!.toml.OPENAI_API_KEY}`, ...CODEX_UPLOADS_OFF_OVERRIDES];
  assert.deepEqual(out.args, [...ov, "exec", ...ov, ...sdkArgs.slice(1)]);
  // The SDK's apiKey option arrives as CODEX_API_KEY; no key at all signs in.
  const viaCodexKey = preload.routeSpawn(r, "codex", ["exec", "hi"], { CODEX_API_KEY: "sk-y" });
  assert.ok(viaCodexKey.args.includes(`model_providers.mandu=${r.codex!.toml.CODEX_API_KEY}`));
  const signIn = preload.routeSpawn(r, "codex", ["exec", "hi"], {});
  assert.ok(signIn.args.includes(`model_providers.mandu=${r.codex!.toml["sign-in"]}`));
  // resumeThread: `exec … resume <id>` — the innermost level holds ours too.
  const resume = preload.routeSpawn(r, "codex", ["exec", "--experimental-json", "resume", "t-1"], { OPENAI_API_KEY: "k" });
  assert.deepEqual(resume.args, [...ov, "exec", ...ov, "--experimental-json", "resume", ...ov, "t-1"]);
});

test("routeSpawn (codex): already routed (the npm launcher passing argv on) is left alone; refused shapes throw", () => {
  const r = codexRoute();
  const routed = ["-c", "model_provider=mandu", "-c", "model_providers.mandu={…}", "exec", "hi"];
  assert.deepEqual(preload.routeSpawn(r, "codex", routed, {}).args, routed);
  assert.throws(() => preload.routeSpawn(r, "codex", ["exec", "--config", 'model_provider="openai"', "hi"], {}), /refusing to start codex: -c model_provider/);
  assert.throws(() => preload.routeSpawn(r, "codex", ["exec", "-c", "model_providers.x.base_url=\"https://e\"", "hi"], {}), /model_providers/);
  assert.throws(() => preload.routeSpawn(r, "codex", ["app-server", "--listen", "ws://0.0.0.0:1"], {}), /app-server/);
  assert.throws(() => preload.routeSpawn(r, "codex", ["--remote", "ws://x", "exec"], {}), /--remote/);
  assert.throws(() => preload.routeSpawn(r, "codex", ["exec", "--oss", "hi"], {}), /--oss/);
  assert.throws(() => preload.routeSpawn(r, "codex", ["cloud", "exec", "hi"], {}), /Codex Cloud/);
  assert.throws(() => preload.routeSpawn(r, "codex", ["exec", "--config", "features.apps=true", "hi"], {}), /own uploads/);
  assert.throws(() => preload.routeSpawn(r, "codex", ["--enable", "connectors", "exec", "hi"], {}), /own uploads/);
});

test("routeSpawn: an agent CLI this launch does not route refuses to start (codex under claude, claude under codex)", () => {
  assert.throws(() => preload.routeSpawn(claudeRoute(), "/usr/bin/codex", ["exec", "hi"], {}), /does not route Codex/);
  assert.throws(() => preload.routeSpawn(codexRoute(), "/x/claude", ["-p", "hi"], {}), /does not route Claude Code/);
  const shell = composeSdkRoute(plan({ target: "shell", argv: ["node", "x.js"] }), CLAUDE_ENV, [], PRELOAD)!;
  assert.throws(() => preload.routeSpawn(shell, "codex", ["exec", "hi"], {}), /does not route Codex \(target shell\)/);
  assert.doesNotThrow(() => preload.routeSpawn(shell, "claude", ["-p", "hi"], {}), "the shell target routes claude by its env");
});

test("effectiveRoute: only what this process itself carries is forced (a variable a wrapper removed stays removed)", () => {
  const r = claudeRoute();
  const eff = preload.effectiveRoute(r, { ANTHROPIC_BASE_URL: "http://127.0.0.1:8788", HTTPS_PROXY: "http://127.0.0.1:8790" });
  assert.deepEqual(Object.keys(eff.env).sort(), ["ANTHROPIC_BASE_URL", "HTTPS_PROXY"]);
  assert.equal(preload.parseRoute(JSON.stringify(r))!.target, "claude");
  assert.equal(preload.parseRoute("{not json"), null);
  assert.equal(preload.parseRoute(JSON.stringify({ v: 2, env: {} })), null);
  assert.equal(preload.parseRoute(undefined), null);
});

// ── parity with codex-argv.ts ───────────────────────────────────────────────

const CORPUS: string[][] = [
  ["codex"],
  ["codex", "exec", "hi"],
  ["codex", "exec", "--experimental-json", "--config", "x=1", "--model", "m", "resume", "t-1"],
  ["codex", "-c", "model_reasoning_effort=low", "exec", "-c", "a=b", "--skip-git-repo-check", "hi"],
  ["codex", "e", "fork", "id"],
  ["codex", "review", "--", "exec"],
  ["codex", "-m", "exec", "prompt"],
  ["codex", "exec", "--image", "a.png", "resume", "--last"],
  ["codex", "resume", "abc"],
  ["codex", "mcp", "list"],
  ["codex", "app-server", "--listen", "stdio://"],
  ["codex", "debug", "app-server", "send-message-v2", "x"],
  ["codex", "--remote=ws://x"],
  ["codex", "exec", "-cmodel_provider=openai", "x"],
  ["codex", "exec", "-c=model_provider=openai", "x"],
  ["codex", "exec", "-c=model_providers={x={base_url=\"https://e\"}}", "x"],
  ["codex", "exec", "-c=model_providers.x.base_url=\"https://e\"", "x"],
  ["codex", "exec", "--config=model_providers.y.base_url=\"u\"", "x"],
  ["codex", "--local-provider", "ollama", "exec", "x"],
  ["codex", "exec", "--", "-c", "model_provider=openai"],
  ["codex", "cloud"],
  ["codex", "cloud-tasks", "list"],
  ["codex", "exec", "cloud"],
  ["codex", "exec", "-c", "features.apps=true", "x"],
  ["codex", "-c", "features.apps=false", "exec", "x"],
  ["codex", "--enable", "apps"],
  ["codex", "--enable=connectors", "exec", "x"],
  ["codex", "--disable", "apps"],
  ["codex", "exec", "-cotel={}", "x"],
  ["codex", "exec", "--config=otel.exporter.otlp-http.endpoint=\"u\"", "x"],
  ["codex", "exec", "-c", "otel.log_user_prompt=true", "x"],
  ["codex", "exec", "-c", "analytics.enabled=true", "-c", "model_provider=openai", "x"],
];

test("parity: the preload's Codex splice equals codexSpliceOverrides (without --no-daemon) over the corpus", () => {
  const ov = ["-c", "model_provider=mandu", "-c", "model_providers.mandu={x}"];
  for (const argv of CORPUS) assert.deepEqual(preload.spliceCodex(argv, ov), codexSpliceOverrides(argv, ov), argv.join(" "));
});

test("parity: the preload's uploads-off switches equal codex-argv.ts CODEX_UPLOADS_OFF, and its conflict check agrees with codexUploadConflict", () => {
  assert.deepEqual(preload.UPLOADS_OFF, CODEX_UPLOADS_OFF.map(([k, v]) => [k, v]));
  assert.deepEqual(preload.UPLOADS_OFF_OVERRIDES, [...CODEX_UPLOADS_OFF_OVERRIDES]);
  assert.deepEqual(preload.CONNECTORS_OFF, [...CODEX_CONNECTORS_OFF]);
  // The route carries the launch's connectors decision to the child.
  assert.equal(codexRoute().codex!.connectorsOff, false);
  const conn = codexRoute({ codexConnectorsOff: true });
  assert.equal(conn.codex!.connectorsOff, true);
  const out = preload.routeSpawn(conn, "codex", ["exec", "hi"], { OPENAI_API_KEY: "k" }).args;
  assert.equal(out.filter((t) => t === "features.connectors=false").length, 2, JSON.stringify(out));
  assert.ok(!preload.routeSpawn(codexRoute(), "codex", ["exec", "hi"], { OPENAI_API_KEY: "k" }).args.includes("features.connectors=false"));
  for (const kv of [
    "features.apps=true", "features.apps=false", "otel={}", "otel.exporter=none", 'otel.exporter="none"', "otel.exporter.x=1",
    "analytics.enabled = true", "feedback.enabled=false", "features.multi_agent=true", "check_for_update_on_startup=1", "model=o3", "",
  ]) assert.equal(preload.uploadConflict(kv), codexUploadConflict(kv), kv);
});

test("parity: the preload refuses exactly the Codex command lines codexLaunchRefusal refuses", () => {
  for (const argv of CORPUS) {
    assert.equal(preload.codexRefusal(argv) !== null, codexLaunchRefusal(argv) !== null, argv.join(" "));
  }
});

// ── Claude Code's settings (claude-route.ts) ────────────────────────────────

interface PreloadClaude {
  claudeRouteEnv(env: Record<string, string | undefined>): Record<string, string>;
  claudeEnvRefusal(env: Record<string, string | undefined>): string | null;
  claudeRouteArgs(args: string[], overlay: { env: Record<string, string> }): { args: string[] } | { refusal: string };
}
const preloadClaude = preload as unknown as PreloadClaude;

test("routeSpawn (claude): the SDK's own inline --settings gets the routing merged in; a settings FILE, a cloud switch and a socket refuse", () => {
  const r = claudeRoute();
  const own = JSON.stringify({ env: { ANTHROPIC_BASE_URL: "https://elsewhere.example", KEEP: "1" }, model: "m" });
  const out = preload.routeSpawn(r, "/x/claude", ["--output-format", "stream-json", `--settings=${own}`, "--verbose"], {});
  assert.equal(out.args.filter((a) => a.startsWith("--settings")).length, 1, "never a second --settings (Claude Code reads only the last)");
  const doc = JSON.parse(out.args[2]!.slice("--settings=".length)) as { env: Record<string, string>; model: string };
  assert.equal(doc.env["ANTHROPIC_BASE_URL"], "http://127.0.0.1:8788", "the launch's proxy wins over the SDK's settings");
  assert.equal(doc.env["KEEP"], "1");
  assert.equal(doc.model, "m");
  assert.equal(doc.env["CLAUDE_CODE_USE_BEDROCK"], "0");
  assert.throws(() => preload.routeSpawn(r, "/x/claude", ["--settings", "/tmp/s.json"], {}), /not inline JSON/);
  assert.throws(() => preload.routeSpawn(r, "/x/claude", [], { CLAUDE_CODE_USE_BEDROCK: "1" }), /CLAUDE_CODE_USE_BEDROCK/);
  assert.throws(() => preload.routeSpawn(r, "/x/claude", [], { ANTHROPIC_UNIX_SOCKET: "/s" }), /ANTHROPIC_UNIX_SOCKET/);
  // Applied twice (the npm `claude` passing its argv on to the native one): the same result.
  const twice = preload.routeSpawn(r, "/x/claude", out.args, {});
  assert.deepEqual(twice.args, out.args);
});

const CLAUDE_CORPUS: string[][] = [
  [],
  ["-p", "hi"],
  ["--settings", '{"tui":"default"}', "-p", "x"],
  ['--settings={"a":[1]}'],
  ["--settings", '{"a":1}', "--settings", '{"env":{"HTTPS_PROXY":"http://e"}}'],
  ["--settings", "/tmp/s.json"],
  ["--settings=./s.json"],
  ["--settings", "{broken"],
  ["--", "--settings", "/x"],
  ["--output-format", "stream-json", "--setting-sources=user,project", "--input-format", "stream-json"],
];

test("parity: the preload's Claude overlay and its placement equal claude-route.ts over the corpus", () => {
  const envs: Array<Record<string, string | undefined>> = [
    CLAUDE_ENV, {}, { ...CLAUDE_ENV, CLAUDE_CODE_USE_GATEWAY: "true", ALL_PROXY: "socks5://x" },
    { CLAUDE_CODE_USE_VERTEX: "1" }, { ANTHROPIC_UNIX_SOCKET: "/s" }, { CLAUDE_CODE_USE_FOUNDRY: "0", ANTHROPIC_UNIX_SOCKET: " " },
  ];
  for (const env of envs) {
    assert.deepEqual(preloadClaude.claudeRouteEnv(env), claudeRouteEnv(env), JSON.stringify(env));
    assert.equal(preloadClaude.claudeEnvRefusal(env) !== null, claudeEnvRefusal(env) !== null, JSON.stringify(env));
  }
  const overlay = claudeRouteOverlay(CLAUDE_ENV);
  for (const args of CLAUDE_CORPUS) {
    const ts = claudeRouteArgs(["claude", ...args], [], overlay);
    const cjs = preloadClaude.claudeRouteArgs(args, overlay);
    if ("refusal" in ts) {
      assert.ok("refusal" in cjs, args.join(" "));
      continue;
    }
    assert.ok("args" in cjs, args.join(" "));
    assert.deepEqual(["claude", ...cjs.args], [...ts.argv.slice(0, 1), ...ts.prefix, ...ts.argv.slice(1)], args.join(" "));
  }
});

// ── the gaps closed after !698 (agent-sdks.md §4) ───────────────────────────

interface PreloadAgents {
  agentOf(file: string, args: string[], cwd: string): { kind: string; prefix?: string[]; args?: string[]; agent?: string } | null;
  scriptIndex(runtime: string, args: string[]): number;
}
const agents = preload as unknown as PreloadAgents;

const DELIVERY = { pythonPath: "/opt/mandu/dist/sdk-route-python", node: "/usr/bin/node", shimDir: "/run/mandu/sid/sdk-shims" };
function deliveredRoute(): SdkRoute {
  return composeSdkRoute(plan(SHIMS), CLAUDE_ENV, ["STRIPE_KEY"], PRELOAD, undefined, DELIVERY)!;
}

test("composeSdkRoute + sdkRouteEnv: the SDK shims lead PATH, the Python hook leads PYTHONPATH, the Node binary rides the route", () => {
  const r = deliveredRoute();
  assert.deepEqual(r.pathPrefix, ["/run/mandu/sid/sdk-shims", "/run/mandu/sid/box", "/run/mandu/sid/shims"]);
  assert.equal(r.pythonPath, DELIVERY.pythonPath);
  assert.equal(r.node, "/usr/bin/node");
  assert.ok(!("PYTHONPATH" in r.env), "PYTHONPATH is merged, never forced");
  const e = sdkRouteEnv(r, { pythonPath: "/home/u/lib:/opt/mandu/dist/sdk-route-python", path: "/usr/bin:/run/mandu/sid/sdk-shims:/bin" });
  assert.equal(e["PYTHONPATH"], "/opt/mandu/dist/sdk-route-python:/home/u/lib");
  assert.equal(e["PATH"], "/run/mandu/sid/sdk-shims:/usr/bin:/bin");
  assert.equal(e["NODE_OPTIONS"], `--require=${PRELOAD}`);
  // The older string form still works (NODE_OPTIONS only).
  assert.deepEqual(Object.keys(sdkRouteEnv(claudeRoute(), "--x")).sort(), ["NODE_OPTIONS"]);
});

test("routeEnv: the Python hook stays first on every child's PYTHONPATH, once", () => {
  const r = deliveredRoute();
  assert.equal(preload.routeEnv(r, {})["PYTHONPATH"], DELIVERY.pythonPath);
  assert.equal(preload.routeEnv(r, { PYTHONPATH: `/a:${DELIVERY.pythonPath}:/b` })["PYTHONPATH"], `${DELIVERY.pythonPath}:/a:/b`);
  assert.ok(preload.routeEnv(r, {})["PATH"]!.startsWith("/run/mandu/sid/sdk-shims:"));
});

test("sdkShimScript: hands the name and its arguments to the preload's --exec, every path quoted", () => {
  const s = sdkShimScript("codex", "/opt/node dir/bin/node", "/opt/it's/sdk-route-preload.cjs", "/run/m/sdk-shims");
  assert.match(s, /^#!\/bin\/sh\n/);
  assert.ok(s.includes(`exec '/opt/node dir/bin/node' --no-warnings '/opt/it'\\''s/sdk-route-preload.cjs' --exec '/run/m/sdk-shims' codex "$@"`), s);
});

test("claudeShimScript: hands claude's arguments to the preload's --claude with the launch's route baked in, every path quoted", () => {
  const mode = { cwd: "/w/it's", configDir: "/h/.claude", scopes: ["user" as const] };
  const route = claudeShimRoute(CLAUDE_ENV, mode);
  const s = claudeShimScript("/opt/node dir/bin/node", "/opt/p/sdk-route-preload.cjs", "/run/m/sdk-shims", route);
  assert.match(s, /^#!\/bin\/sh\n/);
  const json = JSON.stringify(route).replace(/'/g, `'\\''`);
  assert.ok(s.includes(`exec '/opt/node dir/bin/node' --no-warnings '/opt/p/sdk-route-preload.cjs' --claude '/run/m/sdk-shims' '${json}' "$@"`), s);
  assert.equal(withHead("/s", "/a:/s:/b"), "/s:/a:/b");
  assert.equal(withHead("/s", undefined), "/s");
});

// ── the `claude` shim of `mandu claude` / `mandu -- bash` (agent-sdks.md §3.5)

interface PreloadClaudeShim {
  CLAUDE_SHIM_KEYS: string[];
  parseClaudeShimRoute(raw: string): ClaudeShimRoute | null;
  claudeShimSpawn(shim: ClaudeShimRoute, file: string, args: string[], env: Record<string, string | undefined>, cwd: string):
    { args: string[]; env: Record<string, string | undefined> };
}
const shimPreload = preload as unknown as PreloadClaudeShim;
/** No mode decision (scopes the launch found none in: the rule applies). */
const NO_MODE = { cwd: "/w", configDir: "/h/.claude", scopes: [] as Array<"user"> };
const SHIM_ROUTE = claudeShimRoute(CLAUDE_ENV, NO_MODE);
const settingsOf = (args: string[]): { env: Record<string, string> } => {
  const i = args.indexOf("--settings");
  return JSON.parse(i >= 0 ? args[i + 1]! : args.find((a) => a.startsWith("--settings="))!.slice("--settings=".length)) as { env: Record<string, string> };
};

test("claudeShimRoute: the overlay `mandu claude` gets (claudeRouteEnv of the agent's environment), with every key the preload requires", () => {
  assert.deepEqual(SHIM_ROUTE.env, claudeRouteEnv(CLAUDE_ENV));
  assert.deepEqual(Object.keys(SHIM_ROUTE.env).sort(), [...shimPreload.CLAUDE_SHIM_KEYS].sort());
  assert.deepEqual(shimPreload.parseClaudeShimRoute(JSON.stringify(SHIM_ROUTE)), SHIM_ROUTE);
  // Not a route: the shim refuses rather than start an unrouted claude.
  assert.equal(shimPreload.parseClaudeShimRoute("{"), null);
  assert.equal(shimPreload.parseClaudeShimRoute(JSON.stringify({ claudeMode: NO_MODE })), null);
  assert.equal(shimPreload.parseClaudeShimRoute(JSON.stringify({ ...SHIM_ROUTE, env: { ...SHIM_ROUTE.env, ANTHROPIC_BASE_URL: " " } })), null);
  const { NO_PROXY: _n, ...partial } = SHIM_ROUTE.env;
  assert.equal(shimPreload.parseClaudeShimRoute(JSON.stringify({ ...SHIM_ROUTE, env: partial })), null);
});

test("claudeShimSpawn: a settings file's or the caller's re-pointed routing gives way to the launch's, in the environment and in the last --settings", () => {
  // The agent's own `ANTHROPIC_BASE_URL=… HTTPS_PROXY= NO_PROXY= claude -p`,
  // plus a proxy variable the launch does not set.
  const env = { ...CLAUDE_ENV, CLAUDE_CONFIG_DIR: NO_MODE.configDir, ANTHROPIC_BASE_URL: "https://api.anthropic.com", HTTPS_PROXY: "", NO_PROXY: "", HTTP_PROXY: "http://evil:8080" };
  const out = shimPreload.claudeShimSpawn(SHIM_ROUTE, "/x/claude", ["-p", "hi"], env, "/w");
  assert.equal(out.env["ANTHROPIC_BASE_URL"], "http://127.0.0.1:8788");
  assert.equal(out.env["HTTPS_PROXY"], "http://127.0.0.1:8790");
  assert.equal(out.env["NO_PROXY"], "127.0.0.1,localhost");
  assert.ok(!("HTTP_PROXY" in out.env), "a routing variable the launch does not set is removed");
  assert.equal(out.env["STRIPE_KEY"], CLAUDE_ENV.STRIPE_KEY, "the rest of the environment is the caller's");
  assert.deepEqual(out.args.slice(0, 2), ["--permission-mode", "default"]);
  assert.deepEqual(out.args.slice(-2), ["-p", "hi"], "the caller's arguments follow, unchanged");
  const doc = settingsOf(out.args);
  assert.deepEqual(doc.env, claudeRouteEnv(CLAUDE_ENV), "the launch's values, never the caller's");
  assert.equal(doc.env["HTTP_PROXY"], "", "an empty proxy variable is no proxy");
  // Its own inline --settings: merged into, the launch's routing winning; never a second one.
  const own = JSON.stringify({ env: { ANTHROPIC_BASE_URL: "https://gateway.example", KEEP: "1" }, model: "m" });
  const merged = shimPreload.claudeShimSpawn(SHIM_ROUTE, "/x/claude", ["--settings", own, "-p", "hi"], CLAUDE_ENV, "/w");
  assert.equal(merged.args.filter((a) => a === "--settings" || a.startsWith("--settings=")).length, 1);
  assert.equal(settingsOf(merged.args).env["ANTHROPIC_BASE_URL"], "http://127.0.0.1:8788");
  assert.equal(settingsOf(merged.args).env["KEEP"], "1");
  // Applied twice (a nested shim, the npm `claude` handing on to the native one): the same.
  assert.deepEqual(shimPreload.claudeShimSpawn(SHIM_ROUTE, "/x/claude", out.args, out.env, "/w").args, out.args);
});

test("claudeShimSpawn: a --settings FILE, a cloud provider switch and ANTHROPIC_UNIX_SOCKET refuse; the refusal names the way out", () => {
  assert.throws(() => shimPreload.claudeShimSpawn(SHIM_ROUTE, "/x/claude", ["--settings", "/tmp/s.json", "-p", "hi"], CLAUDE_ENV, "/w"),
    /refusing to start \/x\/claude: its --settings \/tmp\/s\.json is not inline JSON.*Pass those settings inline/);
  assert.throws(() => shimPreload.claudeShimSpawn(SHIM_ROUTE, "/x/claude", ["--settings=./s.json"], CLAUDE_ENV, "/w"), /not inline JSON/);
  assert.throws(() => shimPreload.claudeShimSpawn(SHIM_ROUTE, "/x/claude", [], { ...CLAUDE_ENV, CLAUDE_CODE_USE_BEDROCK: "1" }, "/w"), /CLAUDE_CODE_USE_BEDROCK/);
  assert.throws(() => shimPreload.claudeShimSpawn(SHIM_ROUTE, "/x/claude", [], { ...CLAUDE_ENV, ANTHROPIC_UNIX_SOCKET: "/s" }, "/w"), /ANTHROPIC_UNIX_SOCKET/);
});

test("parity: a claude the shim routes gets the --settings `mandu claude` gets from claude-route.ts, over the corpus", () => {
  const overlay = claudeRouteOverlay(CLAUDE_ENV);
  for (const args of CLAUDE_CORPUS) {
    const ts = claudeRouteArgs(["claude", ...args], [], overlay);
    let shim: { args: string[] } | null = null;
    try { shim = shimPreload.claudeShimSpawn({ ...SHIM_ROUTE, claudeMode: undefined as unknown as typeof NO_MODE }, "/x/claude", args, CLAUDE_ENV, "/w"); } catch { /* refused */ }
    if ("refusal" in ts) {
      assert.equal(shim, null, args.join(" "));
      continue;
    }
    assert.ok(shim !== null, args.join(" "));
    assert.deepEqual(["claude", ...shim.args], [...ts.argv.slice(0, 1), ...ts.prefix, ...ts.argv.slice(1)], args.join(" "));
  }
});

// ── the launch's routing values (SdkRoute.launchRouting; agent-sdks.md §3, §4)

interface PreloadLaunchRouting {
  PROXY_ROUTE_ENV_KEYS: string[];
  launchRoutingOf(v: unknown): Record<string, string> | null;
}
const launchPreload = preload as unknown as PreloadLaunchRouting;

/** A launch with no egress proxy (`--no-net-proxy`): no proxy variable, no
 *  NO_PROXY in its delta. */
const NO_NET_PROXY_ENV = (({ HTTPS_PROXY: _p, NO_PROXY: _n, ...rest }) => rest)(CLAUDE_ENV);

test("composeSdkRoute: launchRouting is claudeRouteEnv of the agent's whole environment (inherited under the delta), on every route", () => {
  const inherited = { HTTP_PROXY: "http://corp:3128", ANTHROPIC_BASE_URL: "https://api.anthropic.com", HOME: "/h" };
  const r = composeSdkRoute(plan(SHIMS), CLAUDE_ENV, ["STRIPE_KEY"], PRELOAD, undefined, {}, inherited)!;
  assert.deepEqual(r.launchRouting, claudeRouteEnv({ ...inherited, ...CLAUDE_ENV }));
  assert.equal(r.launchRouting["ANTHROPIC_BASE_URL"], "http://127.0.0.1:8788", "the delta wins");
  assert.equal(r.launchRouting["HTTP_PROXY"], "http://corp:3128", "an inherited routing variable is the launch's too");
  assert.equal(r.launchRouting["ALL_PROXY"], "", "none set: empty");
  assert.deepEqual(Object.keys(r.launchRouting).sort(), [...shimPreload.CLAUDE_SHIM_KEYS].sort());
  assert.deepEqual(launchPreload.launchRoutingOf(r.launchRouting), r.launchRouting);
  assert.deepEqual(codexRoute().launchRouting, claudeRouteEnv((({ ANTHROPIC_BASE_URL: _a, ANTHROPIC_CUSTOM_HEADERS: _h, ...e }) => e)(CLAUDE_ENV)));
  // effectiveRoute narrows the forced variables, never the launch's values.
  assert.deepEqual(preload.effectiveRoute(r, {}).launchRouting, r.launchRouting);
});

test("routeSpawn (claude): a child env with an added HTTPS_PROXY, a changed ANTHROPIC_BASE_URL or a NO_PROXY addition gets the LAUNCH's values, in its env and its overlay", () => {
  for (const delta of [CLAUDE_ENV, NO_NET_PROXY_ENV]) {
    const r = composeSdkRoute(plan(SHIMS), delta, ["STRIPE_KEY"], PRELOAD)!;
    const launch = claudeRouteEnv(delta);
    // The host (the model can steer its code) hands the SDK's child its own routing.
    const hostEnv = {
      PATH: "/usr/bin", ANTHROPIC_API_KEY: "sk-ant-x",
      ANTHROPIC_BASE_URL: "http://127.0.0.1:9999", HTTPS_PROXY: "http://127.0.0.1:9999", https_proxy: "http://127.0.0.1:9999",
      HTTP_PROXY: "http://127.0.0.1:9999", ALL_PROXY: "socks5://127.0.0.1:9999", NO_PROXY: "*", no_proxy: "127.0.0.1,api.anthropic.com",
      CLAUDE_CODE_API_BASE_URL: "http://127.0.0.1:9999", CLAUDE_CODE_USE_GATEWAY: "1",
    };
    const sdkSettings = JSON.stringify({ env: { HTTPS_PROXY: "http://127.0.0.1:9999", NO_PROXY: "*" } });
    for (const args of [["-p", "hi"], ["--settings", sdkSettings, "-p", "hi"]]) {
      const out = preload.routeSpawn(r, "/x/claude", args, hostEnv);
      const what = `${delta === CLAUDE_ENV ? "proxied" : "no egress proxy"} ${args.join(" ")}`;
      assert.deepEqual(settingsOf(out.args).env, launch, `${what}: the overlay is the launch's values, nothing of the host's (nor of the SDK's own settings)`);
      for (const [k, v] of Object.entries(launch)) {
        if ((CLAUDE_ROUTE_ENV_KEYS as readonly string[]).includes(k)) assert.equal(out.env[k], v === "" ? undefined : v, `${what}: env ${k}`);
      }
      assert.equal(out.env["ANTHROPIC_API_KEY"], "sk-ant-x", "the host's own variables stay");
    }
  }
  // A launch without a proxy: the host's proxy is gone from the child, and "" pins none over every settings file.
  const bare = preload.routeSpawn(composeSdkRoute(plan(SHIMS), NO_NET_PROXY_ENV, [], PRELOAD)!, "/x/claude", ["-p", "hi"], { HTTPS_PROXY: "http://capture:1" });
  assert.equal(bare.env["HTTPS_PROXY"], undefined);
  assert.equal(settingsOf(bare.args).env["HTTPS_PROXY"], "");
});

test("routeSpawn (codex): the proxy variables a host adds or changes for a codex child are put back to the launch's; the rest of its env is its own", () => {
  const { ANTHROPIC_BASE_URL: _a, ANTHROPIC_CUSTOM_HEADERS: _h, ...codexDelta } = NO_NET_PROXY_ENV;
  for (const delta of [(({ ANTHROPIC_BASE_URL: _x, ANTHROPIC_CUSTOM_HEADERS: _y, ...e }) => e)(CLAUDE_ENV), codexDelta]) {
    const r = composeSdkRoute(plan({ target: "codex", ...SHIMS }), delta, [], PRELOAD)!;
    const out = preload.routeSpawn(r, "codex", ["exec", "hi"], {
      OPENAI_API_KEY: "sk-x", HTTP_PROXY: "http://capture:1", HTTPS_PROXY: "http://capture:1", ALL_PROXY: "socks5://capture:1",
      all_proxy: "socks5://capture:1", NO_PROXY: "*", ANTHROPIC_BASE_URL: "http://elsewhere",
    });
    for (const k of launchPreload.PROXY_ROUTE_ENV_KEYS) {
      const v = r.launchRouting[k]!;
      assert.equal(out.env[k], v === "" ? undefined : v, k);
    }
    assert.equal(out.env["OPENAI_API_KEY"], "sk-x");
    assert.equal(out.env["ANTHROPIC_BASE_URL"], "http://elsewhere", "not a variable Codex routes by");
    assert.ok(out.args.includes("model_provider=mandu"), "the splice as before");
  }
  assert.deepEqual([...launchPreload.PROXY_ROUTE_ENV_KEYS].sort(),
    ["ALL_PROXY", "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "all_proxy", "http_proxy", "https_proxy", "no_proxy"]);
});

test("routeSpawn: a route that carries no launch values (hand-built, version-skewed) refuses an agent child; a plain child still runs", () => {
  for (const r of [claudeRoute(), codexRoute()]) {
    const { launchRouting: _l, ...without } = r;
    const agent = r.anthropic ? "/x/claude" : "codex";
    const args = r.anthropic ? ["-p", "hi"] : ["exec", "hi"];
    assert.throws(() => preload.routeSpawn(without as SdkRoute, agent, args, {}), /carries no launch routing values/);
    const partial = { ...r, launchRouting: (({ NO_PROXY: _n, ...e }) => e)(r.launchRouting) };
    assert.throws(() => preload.routeSpawn(partial, agent, args, {}), /carries no launch routing values/);
    assert.doesNotThrow(() => preload.routeSpawn(without as SdkRoute, "/bin/true", [], {}));
  }
});

test("scriptIndex: the script a runtime runs, past its own options and their values; none for inline code or stdin", () => {
  assert.equal(agents.scriptIndex("node", ["cli.js", "-p"]), 0);
  assert.equal(agents.scriptIndex("node", ["--no-warnings", "-r", "x.cjs", "--max-old-space-size=4096", "cli.js"]), 4);
  assert.equal(agents.scriptIndex("node", ["--import", "tsx", "--", "cli.ts"]), 3);
  assert.equal(agents.scriptIndex("node", ["-e", "code"]), -1);
  assert.equal(agents.scriptIndex("node", ["--print=1"]), -1);
  assert.equal(agents.scriptIndex("node", ["-"]), -1);
  assert.equal(agents.scriptIndex("bun", ["run", "--preload", "p.ts", "cli.js"]), 3);
  assert.equal(agents.scriptIndex("deno", ["run", "-A", "--config", "deno.json", "cli.js"]), 4);
});

test("agentOf: an agent by name, by the script a runtime runs, or by the SDKs' command line; one started through another program is `wrapped`", () => {
  const SDK = ["--output-format", "stream-json", "--verbose", "--input-format", "stream-json"];
  const at = (file: string, ...args: string[]) => agents.agentOf(file, args, "/nonexistent");
  assert.equal(at("/x/claude", "-p")!.kind, "claude");
  assert.equal(at("codex.exe", "exec")!.kind, "codex");
  // `node cli.js` (the SDK's `executable` + a `.js` pathToClaudeCodeExecutable)
  const js = at("node", "--no-warnings", "/x/node_modules/@anthropic-ai/claude-code/cli.js", "-p", "hi")!;
  assert.deepEqual(js, { kind: "claude", prefix: ["--no-warnings", "/x/node_modules/@anthropic-ai/claude-code/cli.js"], args: ["-p", "hi"] });
  assert.equal(at("bun", "/x/node_modules/@anthropic-ai/claude-agent-sdk/cli.js")!.kind, "claude");
  assert.equal(at("node", "/x/node_modules/.bin/claude")!.kind, "claude");
  assert.equal(at("node", "/x/node_modules/@openai/codex/bin/codex.js", "exec")!.kind, "codex");
  // A renamed binary, or a JS file under another name, speaking the SDKs' command line
  assert.equal(at("/opt/my-agent", ...SDK)!.kind, "claude");
  assert.equal(at("node", "/opt/agent/main.mjs", ...SDK)!.kind, "claude");
  assert.equal(at("/opt/cx", "exec", "--experimental-json", "--model", "m")!.kind, "codex");
  assert.equal(at("/opt/cx", "-c", "x=1", "app-server", "--listen", "stdio://")!.kind, "codex");
  // Through another program: refused (the CLI runs where Mandu cannot route it)
  assert.deepEqual(at("docker", "exec", "-i", "ctr", "claude", ...SDK), { kind: "wrapped", agent: "claude" });
  assert.deepEqual(at("ssh", "host", "codex", "exec", "--experimental-json"), { kind: "wrapped", agent: "codex" });
  assert.deepEqual(at("bun", "x", "claude", ...SDK), { kind: "wrapped", agent: "claude" });
  // Not agents: no SDK command line, or a Node/Python child that routes itself
  assert.equal(at("git", "log", "--grep", "claude"), null);
  assert.equal(at("docker", "run", "img", "claude", "-p", "hi"), null, "a plain command line is the user's own choice");
  assert.equal(at("node", "app.js"), null);
  assert.equal(at("node", "wrapper.js", "claude", ...SDK)!.kind, "claude", "a Node script speaking the protocol is routed as claude");
  assert.equal(at("node", "-e", "require('x')", "claude", ...SDK), null, "inline code loads the preload itself");
  assert.equal(at("python3", "-m", "x", "claude", ...SDK), null, "a Python child loads the Python hook itself");
  assert.equal(at("sh", "-c", "codex exec --experimental-json"), null, "a shell string: the PATH shims meet it");
});

test("routeSpawn: `node cli.js` gets the Claude routing after the script; a renamed CLI by its SDK command line; a wrapped one refuses", () => {
  const r = claudeRoute();
  const out = preload.routeSpawn(r, "/usr/bin/node", ["--no-warnings", "/x/node_modules/@anthropic-ai/claude-code/cli.js", "--output-format", "stream-json"], {});
  assert.deepEqual(out.args.slice(0, 3), ["--no-warnings", "/x/node_modules/@anthropic-ai/claude-code/cli.js", "--settings"]);
  assert.equal((JSON.parse(out.args[3]!) as { env: Record<string, string> }).env["ANTHROPIC_BASE_URL"], "http://127.0.0.1:8788");
  const renamed = preload.routeSpawn(r, "/opt/my-agent", ["--output-format", "stream-json", "--input-format", "stream-json"], {});
  assert.equal(renamed.args[0], "--settings", "the renamed Claude Code gets the overlay too");
  assert.throws(() => preload.routeSpawn(r, "docker", ["exec", "c", "claude", "--output-format", "stream-json", "--input-format", "stream-json"], {}), /through another program/);
  assert.throws(() => preload.routeSpawn(codexRoute(), "/usr/bin/node", ["/x/node_modules/@anthropic-ai/claude-code/cli.js", "-p"], {}), /does not route Claude Code/);
  const cx = preload.routeSpawn(codexRoute(), "/opt/cx", ["exec", "--experimental-json", "hi"], { OPENAI_API_KEY: "k" });
  assert.deepEqual(cx.args.slice(0, 2), ["-c", "model_provider=mandu"], "a renamed Codex gets the provider splice");
  // A child that is no agent: arguments untouched.
  const plain = ["status", "--short"];
  assert.equal(preload.routeSpawn(r, "git", plain, {}).args, plain);
});

test("routeSpawn: the Python Codex SDK's stdio `app-server` refuses with its own reason; a listening one keeps the server refusal", () => {
  const r = codexRoute();
  assert.throws(() => preload.routeSpawn(r, "/x/codex", ["app-server", "--listen", "stdio://"], {}), /Python Codex SDK\) takes its threads' provider/);
  assert.throws(() => preload.routeSpawn(r, "/x/codex", ["--config", "x=1", "app-server"], {}), /Python Codex SDK/);
  assert.throws(() => preload.routeSpawn(r, "/x/codex", ["app-server", "--listen", "ws://0.0.0.0:1"], {}), /serves clients outside the launch/);
});

// ── where the route lives (agent-sdks.md §3.6, 2026-10-18) ────────────────

test("the route's folder: the copies the route names, the route file, the names the hooks look for; both folders write-protected", () => {
  const f = sdkRouteFiles("/run/mandu/sid/sdk-route");
  assert.deepEqual(f, {
    dir: "/run/mandu/sid/sdk-route", route: "/run/mandu/sid/sdk-route/route.json",
    preload: "/run/mandu/sid/sdk-route/sdk-route-preload.cjs", rule: "/run/mandu/sid/sdk-route/claude-permission-rule.cjs",
    pythonDir: "/run/mandu/sid/sdk-route/python",
  });
  assert.equal(preload.ROUTE_DIR, "sdk-route", "the preload knows the folder by the same name");
  assert.equal(preload.ROUTE_FILE, "route.json");
  assert.deepEqual(sdkRouteWriteProtect("/run/mandu/sid"), [
    { path: "/run/mandu/sid/sdk-route", answer: "deny", label: "Mandu's own files" },
    { path: "/run/mandu/sid/sdk-shims", answer: "deny", label: "Mandu's own files" },
  ]);
  // A composed route names the copies in that folder.
  const r = composeSdkRoute(plan(SHIMS), CLAUDE_ENV, [], f.preload, undefined, { ...DELIVERY, pythonPath: f.pythonDir })!;
  assert.equal(r.require, f.preload);
  assert.equal(r.pythonPath, f.pythonDir);
});

test("writeSdkRouteDir refuses a route whose hooks are not the folder's own copies (they would read no route)", () => {
  const r = claudeRoute();
  assert.throws(() => writeSdkRouteDir("/nonexistent/sdk-route", r, { preload: "/x", rule: "/y", python: "/z" }), /names hooks outside its folder/);
});

test("routeSpawn with no route (a launch's copy whose route file is missing): an agent child refuses, any other child starts unchanged", () => {
  assert.throws(() => preload.routeSpawn(null, "/x/claude", ["-p", "hi"], {}), /route file .* is missing or unreadable/);
  assert.throws(() => preload.routeSpawn(null, "/x/codex", ["exec", "--experimental-json"], {}), /missing or unreadable/);
  const env = { PATH: "/usr/bin", X: "1" };
  const out = preload.routeSpawn(null, "/usr/bin/git", ["status"], env);
  assert.deepEqual(out, { args: ["status"], env });
});
