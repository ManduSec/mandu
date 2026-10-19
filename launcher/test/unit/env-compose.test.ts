/**
 * env-compose.test — composeLaunch(plan) is pure; assert the EXACT env delta
 * and argv splice for each concern. No process is spawned.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { CODEX_UPLOADS_NOTE_HEAD, codexProviderToml, codexShellNote, codexUploadsNote, composeLaunch, nodeTakesDisableWarning, shellTargetNote, withNodeOption } from "../../src/env-compose.js";
import { CODEX_UPLOADS_OFF_OVERRIDES } from "../../src/codex-argv.js";
import { isAttentionNote } from "../../src/launch-banner.js";
import { codexMcpProxyEnvOverrides } from "../../src/wire-release.js";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { LaunchPlan } from "../../src/types.js";

function plan(over: Partial<LaunchPlan> = {}): LaunchPlan {
  return {
    target: "claude",
    argv: ["claude"],
    scopeId: "sid", tenant: "live",
    arbiterSock: "/run/mandu/arbiter.sock", arbiterSockMode: "pinned" as const, arbiterRuntimeBase: "/tmp/mandu",
    eventDir: "/run/mandu/sid/events",
    cwd: "/work",
    humanCwd: "/work",
    noContextProxy: true,
    fsSync: false,
    basePath: "/usr/bin:/bin",
    proxy: { host: "127.0.0.1", port: 8788 },
    openaiProxy: { host: "127.0.0.1", port: 8789 },
    openaiProviderName: "mandu",
    noProxyExtra: [],
    requested: { netProxy: false, netProxyMitm: false, execWrap: false },
    execWrapCmds: [],
    ullm: { mode: "cli", baseUrl: "https://api.anthropic.com", binary: "claude" },
    noScope: false,
    writeMcp: true, replyFilter: true,
    bestEffort: false,
    ...over,
  };
}

test("always sets the MANDU_* contract", () => {
  const { env } = composeLaunch(plan());
  assert.equal(env["MANDU_SCOPE_ID"], "sid");
  assert.equal(env["MANDU_ARBITER_SOCK"], "/run/mandu/arbiter.sock");
});

test("the agent's env names no Mandu store path: MANDU_EVENT_DIR and the other retired overrides are never exported (on-disk-layout.md §5)", () => {
  const { env } = composeLaunch(plan());
  for (const k of ["MANDU_EVENT_DIR", "MANDU_SYMBOL_DB", "MANDU_VIEW_STATE", "MANDU_CONFIG", "MANDU_SECRETS",
    "MANDU_CI_RUNS_DIR", "MANDU_MATRIX_RESULTS_DIR", "MANDU_DOCKER_HOME", "MANDU_CI_CACHE"]) {
    assert.equal(env[k], undefined, `${k} must not reach the agent`);
  }
  assert.ok(!Object.values(env).some((v) => v === "/run/mandu/sid/events"), "the scope's events dir is not exported under any name");
});

test("claude: derived base URL + session header; no argv splice by default (the renderer is the release's)", () => {
  const { env, argvPrefix } = composeLaunch(plan());
  assert.equal(env["ANTHROPIC_BASE_URL"], "http://127.0.0.1:8788");
  assert.equal(env["ANTHROPIC_CUSTOM_HEADERS"], "x-mandu-session-id: sid;x-mandu-tenant: live");
  // The reply-filter resolves the fullscreen renderer too (screen-reconcile,
  // differential-interactive.md §19), so no renderer pin rides by default.
  assert.deepEqual(argvPrefix, []);
});

test("claude: MANDU_CLAUDE_TUI_PIN=1 (plan.claudeTuiPin true) pins the inline renderer, nothing else", () => {
  const unpinned = composeLaunch(plan());
  const { env, argvPrefix } = composeLaunch(plan({ claudeTuiPin: true }));
  assert.deepEqual(argvPrefix, ["--settings", '{"tui":"default"}']);
  assert.deepEqual(env, unpinned.env);
  // Never for a non-claude argv[0] under --target claude.
  assert.deepEqual(composeLaunch(plan({ claudeTuiPin: true, argv: ["bash", "-c", "true"] })).argvPrefix, []);
});

test("claude: explicit ANTHROPIC_BASE_URL wins", () => {
  const { env } = composeLaunch(plan({ anthropicBaseUrl: "http://p:9" }));
  assert.equal(env["ANTHROPIC_BASE_URL"], "http://p:9");
});

test("claude: a batch id rides the session header as the packed pair the proxy unpacks", () => {
  const { env } = composeLaunch(plan({ batchId: "batch-7" }));
  assert.equal(env["ANTHROPIC_CUSTOM_HEADERS"], "x-mandu-session-id: sid;x-mandu-batch-id: batch-7;x-mandu-tenant: live");
});

test("codex: a batch id adds no header (codex has no custom-headers channel)", () => {
  const { env } = composeLaunch(plan({ target: "codex", argv: ["codex", "exec"], batchId: "batch-7" }));
  assert.equal(env["ANTHROPIC_CUSTOM_HEADERS"], undefined);
});

test("codex: NO base-URL env; the two routing -c overrides first, then Codex's own uploads off", () => {
  const { env, argvPrefix } = composeLaunch(plan({ target: "codex", argv: ["codex", "exec"] }));
  assert.equal(env["ANTHROPIC_BASE_URL"], undefined);
  assert.deepEqual(argvPrefix, [
    "-c", "model_provider=mandu",
    "-c", 'model_providers.mandu={name="mandu",base_url="http://127.0.0.1:8789/v1",wire_api="responses",env_key="OPENAI_API_KEY"}',
    ...CODEX_UPLOADS_OFF_OVERRIDES,
  ]);
});

test("codex: `features.connectors=false` joins the switches only when the user's config names that legacy key", () => {
  const prefix = (over: Parameters<typeof plan>[0]): string[] => composeLaunch(plan({ target: "codex", argv: ["codex"], ...over })).argvPrefix;
  assert.ok(!prefix({}).includes("features.connectors=false"), "not by default: Codex would print a deprecation notice");
  const on = prefix({ codexConnectorsOff: true });
  const at = on.indexOf("features.connectors=false");
  assert.ok(at > on.indexOf("features.apps=false"), JSON.stringify(on));
});

test("codex: the uploads-off switches reach a wrapper too (its only route), never a shell or a host runtime", () => {
  const has = (argv: string[]): boolean => composeLaunch(plan({ target: "codex", argv })).argvPrefix.join(" ").includes(CODEX_UPLOADS_OFF_OVERRIDES.join(" "));
  assert.equal(has(["codex"]), true);
  assert.equal(has(["/home/u/bin/my-codex.sh", "exec"]), true);
  assert.equal(has(["/bin/sh", "-c", "codex"]), false);
  assert.equal(has(["node", "app.js"]), false, "the SDK preload carries them for a host program");
});

test("codexUploadsNote: one plain line for a ChatGPT-signed-in codex (apps need the sign-in); none for a key, a wrapper or another agent", () => {
  const n = codexUploadsNote({ target: "codex", argv: ["codex"], codexAuth: "sign-in" });
  assert.ok(n !== null && n.startsWith(CODEX_UPLOADS_NOTE_HEAD), String(n));
  assert.match(n!, /upload the local file/);
  assert.ok(!isAttentionNote(n!), "advice, not a degrade");
  assert.equal(codexUploadsNote({ target: "codex", argv: ["codex"], codexAuth: "key" }), null);
  assert.equal(codexUploadsNote({ target: "codex", argv: ["./wrap.sh"], codexAuth: "sign-in" }), null);
  assert.equal(codexUploadsNote({ target: "claude", argv: ["claude"], codexAuth: "sign-in" }), null);
});

test("codex provider shape (agent-sign-in.md §2.4 item 1): env_key with a key; the sign-in shape without one; env_key for the user's own server", () => {
  const SIGN_IN = 'model_providers.mandu={name="mandu",base_url="http://127.0.0.1:8789/v1",wire_api="responses",requires_openai_auth=true,supports_websockets=false}';
  const provider = (over: Parameters<typeof plan>[0]): string => composeLaunch(plan({ target: "codex", argv: ["codex", "exec"], ...over })).argvPrefix[3]!;
  // A key variable: env_key, whichever variable the user set.
  assert.equal(provider({ codexAuth: "key" }), 'model_providers.mandu={name="mandu",base_url="http://127.0.0.1:8789/v1",wire_api="responses",env_key="OPENAI_API_KEY"}');
  assert.match(provider({ codexAuth: "key", openaiEnvKey: "CODEX_API_KEY" }), /env_key="CODEX_API_KEY"\}$/);
  // No key variable: Codex's own sign-in, relayed; no env_key at all.
  assert.equal(provider({ codexAuth: "sign-in" }), SIGN_IN);
  assert.doesNotMatch(provider({ codexAuth: "sign-in" }), /env_key/);
  // The user's own base URL, or a declared main model: that server wants its
  // own key and never gets a ChatGPT sign-in, so env_key stays.
  assert.equal(
    provider({ codexAuth: "sign-in", openaiBaseUrl: "http://127.0.0.1:11434/v1" }),
    'model_providers.mandu={name="mandu",base_url="http://127.0.0.1:11434/v1",wire_api="responses",env_key="OPENAI_API_KEY"}',
  );
  const declared = provider({ codexAuth: "sign-in", tllmEndpoint: { name: "mine", url: "http://127.0.0.1:11434/v1", local: true, upstream: "http://127.0.0.1:11434/v1" } });
  assert.match(declared, /env_key="OPENAI_API_KEY"\}$/);
  assert.doesNotMatch(declared, /requires_openai_auth/);
  // Absent (an older plan): the key shape, as before.
  assert.match(provider({}), /env_key="OPENAI_API_KEY"\}$/);
  assert.equal(codexProviderToml(plan({ target: "codex", argv: ["codex"], codexAuth: "sign-in" })), SIGN_IN.slice("model_providers.mandu=".length));
});

test("codex: the Mandu MCP servers ride -c mcp_servers overrides, with the pre-allowed tools approved; none without mcpServers", () => {
  const servers = {
    "mandu-inspect": { command: "node", args: ["/opt/mandu/dist/inspect-mcp.mjs"], env: { MANDU_ARBITER_SOCK: "/run/a.sock", MANDU_SCOPE_ID: "sid" } },
    "mandu-policy": { command: "node", args: ["/opt/mandu/dist/policy-mcp.mjs"], env: { MANDU_ARBITER_SOCK: "/run/a.sock", MANDU_SCOPE_ID: "sid" } },
  };
  const { argvPrefix } = composeLaunch(plan({ target: "codex", argv: ["codex", "exec"], mcpServers: servers }));
  assert.deepEqual(argvPrefix.slice(0, 4), [
    "-c", "model_provider=mandu",
    "-c", 'model_providers.mandu={name="mandu",base_url="http://127.0.0.1:8789/v1",wire_api="responses",env_key="OPENAI_API_KEY"}',
  ]);
  assert.deepEqual(argvPrefix.slice(4, argvPrefix.length - CODEX_UPLOADS_OFF_OVERRIDES.length), [
    "-c", 'mcp_servers.mandu-inspect.command="node"',
    "-c", 'mcp_servers.mandu-inspect.args=["/opt/mandu/dist/inspect-mcp.mjs"]',
    "-c", 'mcp_servers.mandu-inspect.env={MANDU_ARBITER_SOCK="/run/a.sock",MANDU_SCOPE_ID="sid"}',
    "-c", 'mcp_servers.mandu-inspect.tools.inspect_symbol.approval_mode="approve"',
    "-c", 'mcp_servers.mandu-policy.command="node"',
    "-c", 'mcp_servers.mandu-policy.args=["/opt/mandu/dist/policy-mcp.mjs"]',
    "-c", 'mcp_servers.mandu-policy.env={MANDU_ARBITER_SOCK="/run/a.sock",MANDU_SCOPE_ID="sid"}',
    "-c", 'mcp_servers.mandu-policy.tools.mandu_policy_read.approval_mode="approve"',
    "-c", 'mcp_servers.mandu-policy.tools.mandu_policy_test.approval_mode="approve"',
    "-c", 'mcp_servers.mandu-policy.tools.mandu_policy_propose.approval_mode="approve"',
  ]);
  assert.ok(!argvPrefix.join(" ").includes("declassify"), "declassify_symbol keeps codex's own approval");
  // --no-mcp: the manager leaves mcpServers unset → no MCP override at all.
  assert.equal(composeLaunch(plan({ target: "codex", argv: ["codex", "exec"] })).argvPrefix.length, 4 + CODEX_UPLOADS_OFF_OVERRIDES.length);
  // --no-policy-mcp: the doc carries only the inspect server.
  const noPolicy = composeLaunch(plan({ target: "codex", argv: ["codex", "exec"], mcpServers: { "mandu-inspect": servers["mandu-inspect"] } })).argvPrefix.join(" ");
  assert.ok(noPolicy.includes("mcp_servers.mandu-inspect.command") && !noPolicy.includes("mandu-policy"));
  // A value with a quote or backslash stays one valid TOML string.
  const esc = composeLaunch(plan({ target: "codex", argv: ["codex"], mcpServers: { x: { command: "a\"b\\c", args: [], env: {} } } })).argvPrefix;
  assert.ok(esc.includes('mcp_servers.x.command="a\\"b\\\\c"'));
});

test("codex: --no-daemon (embedded mode by name) only for a read Codex version that takes it, never for a shell", () => {
  const prefix = (over: Parameters<typeof plan>[0]): string[] => composeLaunch(plan({ target: "codex", argv: ["codex"], ...over })).argvPrefix;
  const on = prefix({ agentVersion: "0.159.1" });
  assert.equal(on.filter((t) => t === "--no-daemon").length, 1, JSON.stringify(on));
  assert.equal(on.at(-1), "--no-daemon", "after the -c overrides, so their positions stay put");
  assert.ok(on.includes("model_provider=mandu"), "the routing is unchanged");
  for (const v of ["0.154.0", "0.159.0", null, undefined]) {
    assert.ok(!prefix({ agentVersion: v }).includes("--no-daemon"), `version ${v}: Codex that old would refuse the flag`);
  }
  assert.deepEqual(composeLaunch(plan({ target: "codex", argv: ["/bin/sh", "-c", "x"], agentVersion: "0.159.1" })).argvPrefix, []);
  assert.ok(!composeLaunch(plan({ target: "claude", argv: ["claude"], agentVersion: "0.159.1" })).argvPrefix.includes("--no-daemon"));
});

test("codex target: a wrapper still gets the -c routing (its only route); a POSIX shell gets none of it, MCP included", () => {
  const servers = { "mandu-inspect": { command: "node", args: ["/x.mjs"], env: {} } };
  // A wrapper vouched for by --target codex: the provider overrides are what
  // keeps the codex it runs routed, so they stay.
  const wrap = composeLaunch(plan({ target: "codex", argv: ["/home/u/bin/my-codex.sh", "exec"], mcpServers: servers })).argvPrefix;
  assert.ok(wrap.includes("model_provider=mandu"), JSON.stringify(wrap));
  assert.ok(wrap.join(" ").includes("mcp_servers.mandu-inspect.command"));
  for (const sh of ["/bin/sh", "bash", "/usr/bin/zsh", "dash"]) {
    const { argvPrefix, env } = composeLaunch(plan({ target: "codex", argv: [sh, "-c", "echo hi"], mcpServers: servers }));
    assert.deepEqual(argvPrefix, [], `${sh}: no Codex option reaches a shell`);
    assert.equal(env["ANTHROPIC_BASE_URL"], undefined, `${sh}: still the codex target's env, not claude's`);
  }
});

test("codexShellNote: a shell under --target codex says codex started from it is NOT routed; every other launch gets none", () => {
  const note = codexShellNote({ target: "codex", argv: ["/bin/sh", "-c", "x"] });
  assert.ok(note);
  assert.match(note!, /^mandu: 'sh' is a shell, not codex/);
  assert.match(note!, /WARNING: a codex started from it is NOT routed through Mandu/);
  assert.ok(isAttentionNote(note!), "shown in full even in the compact TTY display");
  assert.equal(codexShellNote({ target: "codex", argv: ["codex", "exec"] }), null);
  assert.equal(codexShellNote({ target: "codex", argv: ["./my-codex.sh"] }), null, "a wrapper gets the routing, so no note");
  assert.equal(codexShellNote({ target: "shell", argv: ["bash"] }), null, "the shell target has its own note");
  assert.equal(codexShellNote({ target: "claude", argv: ["bash"] }), null);
});

test("net-proxy: HTTP(S)_PROXY + NO_PROXY with model hosts", () => {
  const { env } = composeLaunch(plan({ netProxy: { host: "127.0.0.1", port: 8790 }, noProxyExtra: ["ex.com"] }));
  assert.equal(env["HTTP_PROXY"], "http://127.0.0.1:8790");
  assert.equal(env["https_proxy"], "http://127.0.0.1:8790");
  assert.equal(env["NO_PROXY"], "127.0.0.1,localhost,::1,api.anthropic.com,api.openai.com,ex.com");
  // Node < 24 ignores the proxy variables without this (confidentiality-plan-13-reader-set-labels.md §10)
  assert.equal(env["NODE_USE_ENV_PROXY"], "1");
  assert.equal(composeLaunch(plan()).env["NODE_USE_ENV_PROXY"], undefined, "no proxy, no flag");
});

test("mitm cert → NODE_EXTRA_CA_CERTS + CURL_CA_BUNDLE", () => {
  const { env } = composeLaunch(plan({ mitmCaCert: "/ca/mandu-egress-ca.pem" }));
  assert.equal(env["NODE_EXTRA_CA_CERTS"], "/ca/mandu-egress-ca.pem");
  assert.equal(env["CURL_CA_BUNDLE"], "/ca/mandu-egress-ca.pem");
});

test("exec shim dir → PATH prepended to the plan's basePath (pure, exact)", () => {
  const { env } = composeLaunch(plan({ shimDir: "/run/mandu/sid/exec-shims" }));
  // Exact equality is possible now that the composer no longer reads process.env.
  assert.equal(env["PATH"], "/run/mandu/sid/exec-shims:/usr/bin:/bin");
  assert.equal(env["MANDU_EXECWRAP_SHIM_DIR"], "/run/mandu/sid/exec-shims");
});

test("exec-box shim dir → PATH prepended + MANDU_EXEC_BOX_SHIM_DIR", () => {
  const { env } = composeLaunch(plan({ execBoxShimDir: "/run/sid/exec-box-shims" }));
  assert.equal(env["PATH"], "/run/sid/exec-box-shims:/usr/bin:/bin");
  assert.equal(env["MANDU_EXEC_BOX_SHIM_DIR"], "/run/sid/exec-box-shims");
  assert.equal(env["MANDU_EXECWRAP_SHIM_DIR"], undefined);
});

test("exec-box + exec-wrap compose: box dir FIRST, then wrap dir, then basePath", () => {
  const { env } = composeLaunch(plan({
    execBoxShimDir: "/run/sid/exec-box-shims",
    shimDir: "/run/sid/exec-shims",
  }));
  assert.equal(env["PATH"], "/run/sid/exec-box-shims:/run/sid/exec-shims:/usr/bin:/bin");
  assert.equal(env["MANDU_EXEC_BOX_SHIM_DIR"], "/run/sid/exec-box-shims");
  assert.equal(env["MANDU_EXECWRAP_SHIM_DIR"], "/run/sid/exec-shims");
});

test("Mandu's own bubblewrap dir goes on PATH after the shim dirs, before basePath (bwrap-grant.ts)", () => {
  const { env } = composeLaunch(plan({ execBoxShimDir: "/run/sid/exec-box-shims", bwrapDir: "/usr/lib/mandu/bin" }));
  assert.equal(env["PATH"], "/run/sid/exec-box-shims:/usr/lib/mandu/bin:/usr/bin:/bin");
  assert.equal(composeLaunch(plan({ bwrapDir: "/usr/lib/mandu/bin" })).env["PATH"], "/usr/lib/mandu/bin:/usr/bin:/bin");
  // absent (no `mandu setup`, or its grant not loaded): PATH untouched
  assert.equal(composeLaunch(plan()).env["PATH"], undefined);
});

test("mcp config path exported when set, and spliced into claude's argv as --mcp-config", () => {
  const out = composeLaunch(plan({ mcpConfig: "/run/sid/mcp.json" }));
  assert.equal(out.env["MANDU_MCP_CONFIG"], "/run/sid/mcp.json");
  // THE 2026-09-05 dialog: a project-scope <cwd>/.mcp.json is an untrusted
  // server to Claude Code's default permission posture (approval dialog on
  // every launch, default answer drops inspect_symbol); an explicit
  // --mcp-config loads without it.
  assert.deepEqual(out.argvPrefix, ["--mcp-config", "/run/sid/mcp.json", "--allowedTools", "mcp__mandu-inspect__inspect_symbol,mcp__mandu-policy__mandu_policy_read,mcp__mandu-policy__mandu_policy_test,mcp__mandu-policy__mandu_policy_propose"]);
  // By path too; never for a non-claude argv[0] under --target claude (the
  // live oracles wrap bash stand-ins, and bash rejects the flag); never for
  // codex (it takes the same servers as -c overrides; see the codex MCP test).
  assert.deepEqual(composeLaunch(plan({ mcpConfig: "/run/sid/mcp.json", argv: ["/usr/local/bin/claude", "-p", "hi"] })).argvPrefix, ["--mcp-config", "/run/sid/mcp.json", "--allowedTools", "mcp__mandu-inspect__inspect_symbol,mcp__mandu-policy__mandu_policy_read,mcp__mandu-policy__mandu_policy_test,mcp__mandu-policy__mandu_policy_propose"]);
  // The quarantine tool is pre-allowed (no per-call prompt at the default
  // posture); declassify_symbol never is — releasing a secret stays human.
  assert.ok(!out.argvPrefix.join(" ").includes("declassify"));
  // All three policy tools are pre-allowed (the arbiter's monotonic split is
  // the gate: a tightening is undoable, a loosening waits in the Inbox), and
  // --no-policy-mcp drops them from the list with the server.
  assert.ok(out.argvPrefix.join(" ").includes("mcp__mandu-policy__mandu_policy_propose"));
  assert.deepEqual(
    composeLaunch(plan({ mcpConfig: "/run/sid/mcp.json", writePolicyMcp: false })).argvPrefix,
    ["--mcp-config", "/run/sid/mcp.json", "--allowedTools", "mcp__mandu-inspect__inspect_symbol"],
  );
  assert.deepEqual(composeLaunch(plan({ mcpConfig: "/run/sid/mcp.json", argv: ["bash", "-c", "true"] })).argvPrefix, []);
  assert.ok(!composeLaunch(plan({ target: "codex", argv: ["codex"], mcpConfig: "/run/sid/mcp.json" })).argvPrefix.includes("--mcp-config"));
  // No mcp config, no pin → nothing spliced (the pin is opt-in, §19).
  assert.deepEqual(composeLaunch(plan({})).argvPrefix, [], "no mcp config → nothing spliced");
});

// ── The plain-command target (shell, agent-e2e-harness.md §9.1) ─────────────

test("shell: claude's ENV routing (base URL + packed session header), and never an argv splice", () => {
  const shell = composeLaunch(plan({ target: "shell", argv: ["bash", "-c", "echo hi"], mcpConfig: "/run/sid/mcp.json", claudeTuiPin: true }));
  assert.equal(shell.env["ANTHROPIC_BASE_URL"], "http://127.0.0.1:8788", "a claude / Anthropic SDK started inside reaches the proxy");
  assert.equal(shell.env["ANTHROPIC_CUSTOM_HEADERS"], "x-mandu-session-id: sid;x-mandu-tenant: live");
  assert.equal(shell.env["MANDU_MCP_CONFIG"], "/run/sid/mcp.json");
  assert.deepEqual(shell.argvPrefix, [], "bash rejects claude's flags; nothing is spliced");
  // No codex -c overrides and no config-file env either.
  assert.equal(shell.env["OPENCLAW_CONFIG_PATH"], undefined);
  assert.equal(shell.env["OPENCODE_CONFIG"], undefined);
  // The same env delta the live oracles' `--target claude -- bash` stand-in gets.
  const claudeStandIn = composeLaunch(plan({ target: "claude", argv: ["bash", "-c", "echo hi"], mcpConfig: "/run/sid/mcp.json" }));
  assert.deepEqual(shell.env, claudeStandIn.env);
});

test("shellTargetNote: a shell launch names what its routing does NOT reach, with the compact-display marker; agents get none", () => {
  const note = shellTargetNote({ target: "shell", argv: ["/bin/bash", "-c", "x"] });
  assert.ok(note);
  assert.match(note!, /^mandu: 'bash' runs as a plain command \(target shell\)/);
  assert.match(note!, /ANTHROPIC_BASE_URL/);
  assert.match(note!, /WARNING: codex, openclaw, opencode and goose started from it are NOT routed/);
  assert.ok(isAttentionNote(note!), "shown in full even in the compact TTY display");
  for (const target of ["claude", "codex", "openclaw", "opencode", "goose"] as const) {
    assert.equal(shellTargetNote({ target, argv: [target] }), null, target);
  }
});

// ── Goose: its own env keys (goose-route.ts; supported-agents.md §5.6) ──────────

const MCP_SERVERS = {
  "mandu-inspect": { command: "/opt/node", args: ["/opt/inspect-mcp.mjs"], env: { MANDU_ARBITER_SOCK: "/run/a.sock", ANTHROPIC_BASE_URL: "https://api.anthropic.com" } },
  "mandu-policy": { command: "/opt/node", args: ["/opt/policy-mcp.mjs"], env: { MANDU_ARBITER_SOCK: "/run/a.sock" } },
};

test("goose: ANTHROPIC_HOST at the proxy + the anthropic provider pinned (session and subagents); every upload off; no claude routing env", () => {
  const { env, argvPrefix } = composeLaunch(plan({ target: "goose", argv: ["goose", "session"] }));
  assert.equal(env["ANTHROPIC_HOST"], "http://127.0.0.1:8788");
  assert.equal(env["GOOSE_PROVIDER"], "anthropic");
  assert.equal(env["GOOSE_SUBAGENT_PROVIDER"], "anthropic");
  assert.equal(env["GOOSE_TELEMETRY_OFF"], "1");
  assert.equal(env["OTEL_SDK_DISABLED"], "true");
  assert.equal(env["LANGFUSE_PUBLIC_KEY"], "");
  assert.equal(env["SECURITY_PROMPT_CLASSIFIER_ENABLED"], "false");
  assert.equal(env["ANTHROPIC_BASE_URL"], undefined, "Goose ignores it");
  assert.equal(env["ANTHROPIC_CUSTOM_HEADERS"], undefined, "the per-launch proxy keys the session");
  assert.deepEqual(argvPrefix, [], "no MCP servers on the plan: nothing to mount");
  // a user's own ANTHROPIC_HOST (parse.ts) keeps claude's base-URL override semantics
  assert.equal(composeLaunch(plan({ target: "goose", argv: ["goose"], anthropicBaseUrl: "https://gw.corp" })).env["ANTHROPIC_HOST"], "https://gw.corp");
});

test("goose: Mandu's MCP servers mount as --with-extension '<name>:…' on the real binary only", () => {
  const { argvPrefix } = composeLaunch(plan({ target: "goose", argv: ["/usr/local/bin/goose", "run"], mcpServers: MCP_SERVERS }));
  assert.deepEqual(argvPrefix.filter((_, i) => i % 2 === 0), ["--with-extension", "--with-extension"]);
  assert.match(argvPrefix[1]!, /^mandu-inspect:MANDU_ARBITER_SOCK=\/run\/a\.sock ANTHROPIC_BASE_URL=https:\/\/api\.anthropic\.com \/opt\/node \/opt\/inspect-mcp\.mjs$/);
  assert.match(argvPrefix[3]!, /^mandu-policy:/);
  assert.deepEqual(composeLaunch(plan({ target: "goose", argv: ["./my-goose.sh"], mcpServers: MCP_SERVERS })).argvPrefix, [], "a wrapper gets no splice");
});

// ── Config-routed targets (openclaw / opencode) ──────────────────────────────

test("openclaw/opencode: the config-path env var IS the delivery — no base-URL env, no argv splice", () => {
  for (const [target, envVar] of [
    ["openclaw", "OPENCLAW_CONFIG_PATH"],
    ["opencode", "OPENCODE_CONFIG"],
  ] as const) {
    const { env, argvPrefix } = composeLaunch(
      plan({ target, argv: [target], agentConfig: { envVar, path: `/run/sid/${target}.json` } }),
    );
    assert.equal(env[envVar], `/run/sid/${target}.json`);
    // Both agents IGNORE ANTHROPIC_BASE_URL — and for openclaw the
    // plugin-mounted U-LLM child inherits the agent env, so a proxy-pointing
    // base URL there would poison the quarantine channel.
    assert.equal(env["ANTHROPIC_BASE_URL"], undefined);
    assert.equal(env["ANTHROPIC_CUSTOM_HEADERS"], undefined);
    assert.deepEqual(argvPrefix, []);
  }
});

test("openclaw/opencode: composing WITHOUT an agent config refuses (fail-closed last line)", () => {
  // Spawning a config-routed agent with no config file would launch it fully
  // functional against the real endpoint with nothing symbolized.
  assert.throws(
    () => composeLaunch(plan({ target: "openclaw", argv: ["openclaw"] })),
    /no agent config on the plan/,
  );
});

test("claude: the tenant stamp rides the packed session header (policy-surface.md §2.7) and the env", () => {
  const live = composeLaunch(plan({}));
  assert.equal(live.env["MANDU_TENANT"], "live");
  const { env } = composeLaunch(plan({ tenant: "test", batchId: "b-1" }));
  assert.equal(env["MANDU_TENANT"], "test");
  assert.equal(env["ANTHROPIC_CUSTOM_HEADERS"], "x-mandu-session-id: sid;x-mandu-batch-id: b-1;x-mandu-tenant: test");
});

test("mitm cert + combined bundle → the REPLACING CA variables get the bundle, Node keeps the additive session CA", () => {
  const { env } = composeLaunch(plan({ mitmCaCert: "/ca/mandu-egress-ca.pem", mitmCaBundle: "/ca/mandu-ca-bundle.pem" }));
  assert.equal(env["NODE_EXTRA_CA_CERTS"], "/ca/mandu-egress-ca.pem");
  for (const k of ["CURL_CA_BUNDLE", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "GIT_SSL_CAINFO", "CARGO_HTTP_CAINFO", "AWS_CA_BUNDLE", "CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE"]) assert.equal(env[k], "/ca/mandu-ca-bundle.pem", k);
  // no bundle (no system store found): the replacing variables other than curl's stay UNSET
  const { env: bare } = composeLaunch(plan({ mitmCaCert: "/ca/mandu-egress-ca.pem" }));
  assert.equal(bare["SSL_CERT_FILE"], undefined);
  assert.equal(bare["REQUESTS_CA_BUNDLE"], undefined);
  assert.equal(bare["CARGO_HTTP_CAINFO"], undefined);
  assert.equal(bare["AWS_CA_BUNDLE"], undefined);
  assert.equal(bare["CURL_CA_BUNDLE"], "/ca/mandu-egress-ca.pem");
});


test("withNodeOption appends once and keeps the user's NODE_OPTIONS", () => {
  assert.equal(withNodeOption(undefined, "--disable-warning=UNDICI-EHPA"), "--disable-warning=UNDICI-EHPA");
  assert.equal(withNodeOption("--max-old-space-size=4096", "--disable-warning=UNDICI-EHPA"), "--max-old-space-size=4096 --disable-warning=UNDICI-EHPA");
  assert.equal(withNodeOption("--disable-warning=UNDICI-EHPA", "--disable-warning=UNDICI-EHPA"), "--disable-warning=UNDICI-EHPA");
});

test("nodeTakesDisableWarning: 20.11+, 21.3+, any later major; unknown is no", () => {
  for (const v of ["v20.11.0", "v21.3.0", "v22.13.0", "v24.1.0"]) assert.equal(nodeTakesDisableWarning(v), true, v);
  for (const v of ["v20.10.9", "v21.2.0", "v18.19.0", null, "garbage"]) assert.equal(nodeTakesDisableWarning(v), false, String(v));
});

test("plan 12 F6: the user's own CA files survive TLS inspection; the merged file wins per variable, others keep the session's", () => {
  const userTrust = { NODE_EXTRA_CA_CERTS: "/ca/mandu-user-ca-1.pem", SSL_CERT_FILE: "/ca/mandu-user-ca-2.pem", GIT_SSL_CAINFO: "/ca/mandu-user-ca-2.pem" };
  const { env } = composeLaunch(plan({ mitmCaCert: "/ca/mandu-egress-ca.pem", mitmCaBundle: "/ca/mandu-ca-bundle.pem", mitmUserTrust: userTrust }));
  assert.equal(env["NODE_EXTRA_CA_CERTS"], "/ca/mandu-user-ca-1.pem");
  assert.equal(env["SSL_CERT_FILE"], "/ca/mandu-user-ca-2.pem");
  assert.equal(env["GIT_SSL_CAINFO"], "/ca/mandu-user-ca-2.pem");
  assert.equal(env["REQUESTS_CA_BUNDLE"], "/ca/mandu-ca-bundle.pem", "a variable the user never set keeps the session bundle");
  assert.equal(env["CURL_CA_BUNDLE"], "/ca/mandu-ca-bundle.pem");
  // No system bundle found: a variable only the user set is still handed their merged file.
  const { env: bare } = composeLaunch(plan({ mitmCaCert: "/ca/mandu-egress-ca.pem", mitmUserTrust: { SSL_CERT_FILE: "/ca/mandu-user-ca-1.pem" } }));
  assert.equal(bare["SSL_CERT_FILE"], "/ca/mandu-user-ca-1.pem");
  assert.equal(bare["NODE_EXTRA_CA_CERTS"], "/ca/mandu-egress-ca.pem");
  // Without inspection nothing is set, whatever the plan carries.
  const { env: off } = composeLaunch(plan({ mitmUserTrust: userTrust }));
  assert.equal(off["NODE_EXTRA_CA_CERTS"], undefined);
});

test("codex: default composition names no sandbox policy; only the platform adapters own their announced overrides", () => {
  // Linux's command-network policy and macOS's non-nesting sandbox policy
  // are decided after the platform's confinement setup. Default composition
  // must not silently introduce another sandbox override.
  const servers = { "mandu-inspect": { command: "node", args: ["/opt/i.mjs"], env: { MANDU_ARBITER_SOCK: "/run/a.sock" } } };
  const SANDBOXY = /sandbox|network_access|danger|full-auto|bypass/i;
  for (const over of [{}, { codexAuth: "sign-in" as const }, { mcpServers: servers, agentVersion: "codex-cli 0.160.0" }]) {
    const { argvPrefix, env } = composeLaunch(plan({ target: "codex", argv: ["codex"], ...over }));
    for (const a of argvPrefix) assert.doesNotMatch(a, SANDBOXY, `argv splice ${a}`);
    for (const [k, v] of Object.entries(env)) assert.ok(!/^CODEX_SANDBOX/.test(k) && !/sandbox_workspace_write|network_access/.test(v), k);
  }
  for (const a of codexMcpProxyEnvOverrides([{ name: "mandu-inspect", command: "node", args: [], source: "t" }])) assert.doesNotMatch(a, SANDBOXY);
  // The Linux network adapter and macOS sandbox adapter are the only
  // policy owners; their platform and user/admin gates have behavioral tests.
  const src = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "src");
  const walk = (d: string): string[] => readdirSync(d).flatMap((n) => (statSync(join(d, n)).isDirectory() ? walk(join(d, n)) : n.endsWith(".ts") ? [join(d, n)] : []));
  const files = walk(src);
  assert.ok(files.length > 50, "the sweep reads the launcher's sources");
  const networkOwner = join(src, "codex-shell-network.ts");
  const sandboxOwner = join(src, "codex-sandbox.ts");
  assert.ok(files.includes(networkOwner) && files.includes(sandboxOwner), "both platform policy owners exist");
  for (const f of files) {
    const text = readFileSync(f, "utf8");
    if (f !== networkOwner) assert.doesNotMatch(text, /sandbox_workspace_write|network_access/, f);
    if (f !== networkOwner && f !== sandboxOwner) assert.doesNotMatch(text, /sandbox_mode/, f);
  }
});
