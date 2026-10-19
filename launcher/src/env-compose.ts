/**
 * env-compose — the PURE cooperative-core env/argv delta for a LaunchPlan.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy):
 *   Adapted from launcher/mandu-run.sh: claude base URL + headers (L530-583),
 *   codex -c provider splice (L589-599), net-proxy env (L782-812), MITM CA env
 *   (L829-836), exec-shim PATH (L1027-1038), MANDU_* contract (L555-557).
 *   No I/O, no platform branch — this IS the coop-env backend's substance and
 *   is exhaustively unit-testable.
 */
import { inspectCallBoundMs } from "./ullm-timeout.js";
import { hostRuntimeOf, type ComposedLaunch, type LaunchPlan } from "./types.js";
import { MANDU_POLICY_SERVER, POLICY_PREALLOWED_TOOLS } from "./services/mcp.js";
import { sessionNoProxy } from "./services/net-proxy.js";
import { browserCdpAgentEnv } from "./browser-cdp.js";
import { CODEX_CONNECTORS_OFF, CODEX_NO_DAEMON, CODEX_UPLOADS_OFF_OVERRIDES, codexOverridesReach, codexTakesNoDaemon, isCodexBinary } from "./codex-argv.js";
import { gooseExtensionArg, isGooseBinary } from "./goose-argv.js";
import { gooseForcedEnv } from "./goose-route.js";

/** A TOML basic string (JSON's escapes are a subset TOML accepts). */
const tomlStr = (s: string): string => JSON.stringify(s);

/**
 * Codex (0.154) takes MCP servers as `-c mcp_servers.<name>.<key>=<TOML>`
 * overrides; there is no --mcp-config. Each Mandu server gets command /
 * args / env, and the tools the launcher pre-allows for Claude Code are
 * pre-approved the same way (`approval_mode = "approve"`), since a headless
 * `codex exec` answers every unapproved MCP call "requires approval, but
 * approval policy is never" (read off a live run, 2026-09-25):
 * inspect_symbol only on mandu-inspect (declassify_symbol keeps codex's own
 * approval: it releases a secret), all three policy tools on mandu-policy.
 * `toolTimeoutSec` sets a server's `tool_timeout_sec` (Codex's per-call
 * limit, 60 s by default): mandu-inspect's, when the entry carries a U-LLM
 * timeout, covers the longest inspect_symbol call (ullm-timeout.ts,
 * model-endpoints.md §1.9).
 */
export function codexMcpOverrides(
  servers: NonNullable<LaunchPlan["mcpServers"]>,
  opts: { toolTimeoutSec?: Readonly<Record<string, number>> } = {},
): string[] {
  const out: string[] = [];
  for (const [name, s] of Object.entries(servers)) {
    const env = Object.entries(s.env).map(([k, v]) => `${k}=${tomlStr(v)}`).join(",");
    out.push(
      "-c", `mcp_servers.${name}.command=${tomlStr(s.command)}`,
      "-c", `mcp_servers.${name}.args=[${s.args.map(tomlStr).join(",")}]`,
      "-c", `mcp_servers.${name}.env={${env}}`,
    );
    const timeout = opts.toolTimeoutSec?.[name];
    if (timeout !== undefined && Number.isInteger(timeout) && timeout > 0) out.push("-c", `mcp_servers.${name}.tool_timeout_sec=${timeout}`);
    if (name === "mandu-inspect") out.push("-c", `mcp_servers.${name}.tools.inspect_symbol.approval_mode="approve"`);
    if (name === MANDU_POLICY_SERVER) {
      for (const t of POLICY_PREALLOWED_TOOLS) out.push("-c", `mcp_servers.${name}.tools.${t}.approval_mode="approve"`);
    }
  }
  return out;
}

/** The `codexMcpOverrides` options of a launch: mandu-inspect's
 *  `tool_timeout_sec` (whole seconds, rounded up) when the inspect entry
 *  carries a U-LLM timeout, else none (Codex's own 60 s). Pure. */
export function codexMcpTimeouts(ullmEndpointTimeoutMs: number | undefined): { toolTimeoutSec?: Record<string, number> } {
  return ullmEndpointTimeoutMs === undefined ? {} : { toolTimeoutSec: { "mandu-inspect": Math.ceil(inspectCallBoundMs(ullmEndpointTimeoutMs) / 1000) } };
}

/** The settings layer the launcher pins on every claude session: the STANDARD
 *  (inline) TUI renderer. `tui: "fullscreen"` renders on the alternate screen
 *  with cell-diff repaints that re-emit a symbol token in PIECES (`$MDU:Read[d49`
 *  → cursor jump → `]`, measured 2026-09-05 with the developer's own settings),
 *  which the reply-filter's stream-level resolution cannot reassemble. Since
 *  2026-09-19 the reply-filter reads tokens back off the alternate screen
 *  (screen-reconcile.ts, differential-interactive.md §19), so the pin is OFF
 *  by default and `MANDU_CLAUDE_TUI_PIN=1` is the opt-in for a user who
 *  hits a residual. A user's own later `--settings` wins (commander keeps
 *  the last) and is their call. */
export const CLAUDE_TUI_PIN = JSON.stringify({ tui: "default" });

/**
 * The routed Codex provider's TOML (agent-sign-in.md §2.4 item 1). Three
 * shapes, by who authenticates:
 *   - a key variable (`plan.codexAuth` absent or `key`): `env_key`, read from
 *     OPENAI_API_KEY or CODEX_API_KEY, as before;
 *   - no key variable (`sign-in`): `requires_openai_auth=true` and no
 *     `env_key`, so Codex sends its own `codex login` (a ChatGPT bearer plus
 *     `chatgpt-account-id`, or a saved key) to the proxy, which relays it
 *     (openai-proxy chooseUpstream). `supports_websockets=false` keeps the
 *     transport on the HTTP SSE the proxy parses;
 *   - a user base URL (MANDU_OPENAI_BASE_URL, the proxy skipped) or a
 *     declared main model: `env_key` whatever `codexAuth` says. That server
 *     wants its own key, and a ChatGPT sign-in must never reach it.
 * Pure.
 */
export function codexProviderToml(plan: Pick<LaunchPlan, "openaiBaseUrl" | "openaiProxy" | "openaiProviderName" | "openaiEnvKey" | "codexAuth" | "tllmEndpoint">): string {
  const base = plan.openaiBaseUrl ?? `http://${plan.openaiProxy.host}:${plan.openaiProxy.port}/v1`;
  const head = `name="${plan.openaiProviderName}",base_url="${base}",wire_api="responses"`;
  if (plan.codexAuth === "sign-in" && !plan.openaiBaseUrl && !plan.tllmEndpoint) {
    return `{${head},requires_openai_auth=true,supports_websockets=false}`;
  }
  return `{${head},env_key="${plan.openaiEnvKey ?? "OPENAI_API_KEY"}"}`;
}

/** argv[0] is the Claude Code CLI (bare or by path). */
export function isClaudeBinary(argv0: string | undefined): boolean {
  const base = (argv0 ?? "").split("/").pop() ?? "";
  return base === "claude";
}

export function composeLaunch(plan: LaunchPlan): ComposedLaunch {
  const env: Record<string, string> = {
    MANDU_SCOPE_ID: plan.scopeId,
    MANDU_ARBITER_SOCK: plan.arbiterSock,
    // Tenant stamp (policy-surface.md §2.7): every emitter under the
    // agent (shims, reply-filter, the MCP child, …) inherits it.
    MANDU_TENANT: plan.tenant,
  };
  const argvPrefix: string[] = [];

  // `shell` (a plain command, types.ts Target) takes the SAME env routing as
  // claude: a claude or an Anthropic-SDK program started inside it reaches the
  // model through the anthropic-proxy. The argv splices below are claude-
  // binary-gated, so a shell never receives them. What this routing does not
  // reach is named at launch (shellTargetNote).
  if (plan.target === "claude" || plan.target === "shell") {
    env["ANTHROPIC_BASE_URL"] =
      plan.anthropicBaseUrl ?? `http://${plan.proxy.host}:${plan.proxy.port}`;
    // Claude Code delivers only ONE custom header (claude-code #1859), so the
    // optional batch id rides the session-id value as a ";x-mandu-batch-id:
    // <bid>" pair — the anthropic-proxy unpacks both (proxy.ts sessionIdFor /
    // batchIdFor), exactly the packing the e2e harnesses already use.
    env["ANTHROPIC_CUSTOM_HEADERS"] =
      `x-mandu-session-id: ${plan.scopeId}` +
      (plan.batchId ? `;x-mandu-batch-id: ${plan.batchId}` : "") +
      `;x-mandu-tenant: ${plan.tenant}`;
    // The inspect-mcp (U-LLM) server rides an EXPLICIT --mcp-config, spliced
    // right after argv[0] like codex's -c overrides. A project-scope
    // <cwd>/.mcp.json is an untrusted server to Claude Code's default
    // permission posture: it raised an approval dialog on every launch whose
    // default answer removed inspect_symbol from the session (services/mcp.ts
    // header, 2026-09-05). --mcp-config is honored by the TUI and by -p alike
    // and adds to (does not replace) the user's own MCP configuration.
    // Spliced only when argv[0] really is claude: the live oracles wrap a
    // bash/sh stand-in under `--target claude`, and bash rejects the flag.
    if (plan.claudeTuiPin === true && isClaudeBinary(plan.argv[0])) argvPrefix.push("--settings", CLAUDE_TUI_PIN);
    if (plan.mcpConfig && isClaudeBinary(plan.argv[0])) {
      argvPrefix.push("--mcp-config", plan.mcpConfig);
      // Pre-allow the quarantine tool: at the default permission posture every
      // MCP call raises "Do you want to proceed?", and inspect_symbol is the
      // agent's ONLY way to work with untrusted data — prompting on each use
      // is friction with no safety behind it (the result is re-symbolized;
      // nothing is revealed). declassify_symbol is deliberately NOT allowed:
      // it releases a secret and must stay a human decision. A user's own
      // later --allowedTools wins (commander keeps the last), which only
      // brings the prompt back.
      // The policy server's three tools join it (policy-surface.md §8
      // §5.1, §9): reading and testing change nothing, and a proposal either
      // tightens (applied, undoable from History) or waits for the user in
      // the Inbox; a Claude Code prompt on top would gate the same act twice.
      const allowed = ["mcp__mandu-inspect__inspect_symbol"];
      if (plan.writePolicyMcp !== false) {
        for (const t of POLICY_PREALLOWED_TOOLS) allowed.push(`mcp__${MANDU_POLICY_SERVER}__${t}`);
      }
      argvPrefix.push("--allowedTools", allowed.join(","));
    }
  } else if (plan.target === "goose") {
    // Goose routes by its OWN env keys (goose-route.ts): an env var named as
    // an uppercase config key outranks config.yaml, so GOOSE_PROVIDER (the
    // routed provider run.ts resolved) + ANTHROPIC_HOST at the proxy, and
    // OPENAI_HOST at the proxy's openai route, is the whole delivery (Goose
    // ignores ANTHROPIC_BASE_URL). The same env turns off every upload Goose
    // can make past the proxy (telemetry, Langfuse, OTLP, the classifiers)
    // and pins a delegate's provider (supported-agents.md §5.6). Goose sends
    // no Mandu session header: the per-launch proxy keys the session.
    // A user's own ANTHROPIC_HOST is the base-URL override (parse.ts), with
    // claude's ANTHROPIC_BASE_URL semantics.
    const proxyUrl = `http://${plan.proxy.host}:${plan.proxy.port}`;
    Object.assign(env, gooseForcedEnv(plan.anthropicBaseUrl ?? proxyUrl, proxyUrl, plan.gooseRouting));
    // The Mandu MCP servers (inspect + policy), as `--with-extension
    // '<name>:ENV=… cmd …'` flags; spliced after `session` / `run`
    // (spawn.ts buildFinalArgv), only into the real goose binary. The
    // explicit name makes the tools `mandu-inspect__inspect_symbol`, the
    // spelling the arbiter knows. The stdio child inherits Goose's whole env
    // and these entries override it (its ANTHROPIC_BASE_URL is the real
    // endpoint or the U-LLM forwarder, never the proxy). An entry Goose's
    // parser could not read back is left out (utility-class: the U-LLM is
    // missing, nothing is unprotected).
    if (plan.mcpServers && isGooseBinary(plan.argv[0])) {
      for (const [name, server] of Object.entries(plan.mcpServers)) {
        const arg = gooseExtensionArg(name, server);
        if (arg !== null) argvPrefix.push("--with-extension", arg);
      }
    }
  } else if (plan.target === "codex") {
    // Codex selects its base URL by config, not env — splice two -c overrides
    // after argv[0] AND after every subcommand (spawn.ts buildFinalArgv via
    // codex-argv.ts: the innermost -c list replaces the outer ones, so a
    // user's `exec -c …` would otherwise drop ours). This is the one place the
    // "pure env delta" abstraction also touches argv (spec §9.3).
    // Composed for codex and for a wrapper vouched for by --target (its only
    // route), never for a POSIX shell: a shell is not codex and took the
    // first -c as its script (codex-argv.ts codexOverridesReach; the launch
    // says so, codexShellNote).
    if (codexOverridesReach(plan.argv[0])) {
      const n = plan.openaiProviderName;
      argvPrefix.push("-c", `model_provider=${n}`, "-c", `model_providers.${n}=${codexProviderToml(plan)}`);
      // The Mandu MCP servers (inspect + policy), as -c overrides. Absent
      // under --no-mcp; the policy entry is absent under --no-policy-mcp.
      // mandu-inspect's own call limit follows the U-LLM timeout its entry
      // carries (ullm-timeout.ts), so a slow local model is not cut at 60 s.
      if (plan.mcpServers) argvPrefix.push(...codexMcpOverrides(plan.mcpServers, codexMcpTimeouts(plan.ullmEndpointTimeoutMs)));
      // Codex's own uploads off (analytics, feedback, OpenTelemetry export,
      // ChatGPT apps, the update check; codex-argv.ts CODEX_UPLOADS_OFF,
      // supported-agents.md §5.3.4 rule 1). A user -c that undoes one is
      // refused at parse time (codexLaunchRefusal).
      argvPrefix.push(...CODEX_UPLOADS_OFF_OVERRIDES);
      // The legacy `connectors` key, only where the user's config names it
      // (codex-argv.ts header: forced always, it prints a deprecation notice).
      if (plan.codexConnectorsOff === true) argvPrefix.push(...CODEX_CONNECTORS_OFF);
      // Embedded mode by name: the agent runs in this process, inside the
      // scope, never in Codex's shared background server. The -c above
      // already force it; the flag clears the footer warning that says so
      // (codex-argv.ts header). Only a Codex whose version was read and
      // takes the flag; the splice places it per level.
      if (codexTakesNoDaemon(plan.agentVersion)) argvPrefix.push(CODEX_NO_DAEMON);
    }
  } else {
    // openclaw / opencode: CONFIG-FILE routed (services/agent-config.ts) —
    // both probe-verifiedly IGNORE ANTHROPIC_BASE_URL, so the env var each
    // reads its config path from is the whole delivery. FAIL-CLOSED last
    // line: composing a launch for a config-routed target with no config on
    // the plan would spawn the agent straight at the real endpoint with
    // nothing symbolized — the silent-unprotected shape this target type
    // exists to prevent — so refuse instead.
    if (!plan.agentConfig) {
      throw new Error(
        `mandu: no agent config on the plan for config-routed target '${plan.target}' — ` +
        "the manager's agent-config step must run (and succeed) before composing the launch",
      );
    }
    env[plan.agentConfig.envVar] = plan.agentConfig.path;
    if (plan.agentConfig.env) Object.assign(env, plan.agentConfig.env);
    // Deliberately NO ANTHROPIC_BASE_URL for these targets: the agent ignores
    // it, and for openclaw the plugin-mounted U-LLM child INHERITS the agent
    // env — a proxy-pointing base URL there would poison the quarantine
    // channel (its loopback guard refuses the instrumented proxy, correctly).
  }

  if (plan.netProxy) {
    const url = `http://${plan.netProxy.host}:${plan.netProxy.port}`;
    env["HTTP_PROXY"] = url; env["http_proxy"] = url;
    env["HTTPS_PROXY"] = url; env["https_proxy"] = url;
    const noProxy = sessionNoProxy(plan)!;
    env["NO_PROXY"] = noProxy; env["no_proxy"] = noProxy;
  }
  // The DevTools relay (browser-cdp.ts): the agent's browser endpoint is
  // the relay, never Chrome's own port. Loopback, so NO_PROXY above covers it.
  if (plan.cdpRelay) Object.assign(env, browserCdpAgentEnv(plan.cdpRelay.url));
  if (plan.mitmCaCert) Object.assign(env, mitmTrustEnv(plan.mitmCaCert, plan.mitmCaBundle, plan.mitmUserTrust));
  // Node ignores HTTP(S)_PROXY for fetch and https unless told to. Node's docs
  // date NODE_USE_ENV_PROXY v24.0.0 / v22.21.0 for fetch and v24.5.0 /
  // v22.21.0 for http/https; an older runtime (Mandu's floor, 22.13, among
  // them) ignores it. Without it a Node script the agent writes goes around
  // the egress proxy, and a placeholder it sends is never put back (no leak:
  // it only ever held the placeholder; docs/design/confidentiality/confidentiality-plan-13-reader-set-labels.md §10.2).
  // `mandu doctor` and the launch warn about such a node (node-floor.ts
  // nodeEnvProxyGap, the one version table).
  if (plan.netProxy) env["NODE_USE_ENV_PROXY"] = "1";
  // Prepend the shim dir(s) to the AGENT's PATH (captured in the plan), NOT the
  // launcher's ambient process.env — keeps this function pure and shims the PATH
  // that actually reaches the agent. --exec-box and --exec-wrap compose (both
  // prepend a shim dir); exec-box goes FIRST so, if a user override makes their
  // sets overlap, the boxing shim wins by PATH order. The default sets do not
  // overlap (exec-box = read-only inspection tools; exec-wrap = curl/wget/nc).
  const shimDirs: string[] = [];
  if (plan.execBoxShimDir) shimDirs.push(plan.execBoxShimDir);
  if (plan.shimDir) shimDirs.push(plan.shimDir);
  // Mandu's own bubblewrap (bwrap-grant.ts): the only binary in that dir, and
  // after the shims, which never shim bwrap.
  if (plan.bwrapDir) shimDirs.push(plan.bwrapDir);
  if (shimDirs.length) env["PATH"] = `${shimDirs.join(":")}:${plan.basePath}`;
  if (plan.shimDir) env["MANDU_EXECWRAP_SHIM_DIR"] = plan.shimDir;
  if (plan.execBoxShimDir) env["MANDU_EXEC_BOX_SHIM_DIR"] = plan.execBoxShimDir;
  if (plan.mcpConfig) env["MANDU_MCP_CONFIG"] = plan.mcpConfig;

  return { env, argvPrefix };
}

/**
 * The truth-in-labeling line a `shell`-target launch prints
 * (agent-e2e-harness.md §9.1): a plain command is not an agent, so say what
 * applies to it and, above all, which agents started inside it are NOT routed
 * to the model-context proxy. Carries `WARNING` so the compact TTY display
 * (launch-banner.ts ATTENTION) prints it in full. null for every agent target.
 */
export function shellTargetNote(plan: Pick<LaunchPlan, "target" | "argv">): string | null {
  if (plan.target !== "shell") return null;
  const cmd = (plan.argv[0] ?? "").split("/").pop() || "the command";
  return (
    `mandu: '${cmd}' runs as a plain command (target shell): every protection this launch brings up applies ` +
    "to it and everything it starts, and model calls go through Mandu only for programs that read " +
    "ANTHROPIC_BASE_URL (claude, Anthropic SDKs). WARNING: codex, openclaw, opencode and goose started from it are " +
    "NOT routed; start an agent as `mandu <agent>` (or pass --target) to protect it."
  );
}

/**
 * The launch note for `--target codex` over a POSIX shell (codex-argv.ts
 * codexOverridesReach): the shell gets no Codex routing overrides, so say
 * that a codex started from it is not routed. `WARNING` for the compact TTY
 * display, as shellTargetNote. null for every other launch.
 */
export function codexShellNote(plan: Pick<LaunchPlan, "target" | "argv">): string | null {
  // A host runtime gets no overrides either, but its note is the SDK
  // route's (sdk-route.ts sdkHostNote).
  if (plan.target !== "codex" || codexOverridesReach(plan.argv[0]) || hostRuntimeOf(plan.argv[0]) !== null) return null;
  const cmd = (plan.argv[0] ?? "").split("/").pop() || "the command";
  return (
    `mandu: '${cmd}' is a shell, not codex: it does not get Codex's routing options (-c model_provider=…), ` +
    "which Codex needs on its own command line. WARNING: a codex started from it is NOT routed through Mandu; " +
    "start it as `mandu codex …` to protect it."
  );
}

/** The start of codexUploadsNote, matched by launch-banner.ts compactNotice. */
export const CODEX_UPLOADS_NOTE_HEAD = "mandu: ChatGPT apps and connectors are off in Codex under Mandu";

/**
 * The launch note for a Codex on a ChatGPT sign-in (the only kind that has
 * ChatGPT apps): CODEX_UPLOADS_OFF turns apps and connectors off, which the
 * user would otherwise find missing without a reason. One plain line (the
 * compact display shows a short form). null for every other launch.
 */
export function codexUploadsNote(plan: Pick<LaunchPlan, "target" | "argv" | "codexAuth">): string | null {
  if (plan.target !== "codex" || !isCodexBinary(plan.argv[0]) || plan.codexAuth !== "sign-in") return null;
  return (
    `${CODEX_UPLOADS_NOTE_HEAD}: an app's file parameter makes Codex upload the local file to ChatGPT, around ` +
    "Mandu's model proxy. Codex's analytics, feedback reports and OpenTelemetry export are off too."
  );
}

/**
 * The trust variables that point a session's TLS clients at the egress
 * proxy's certificate authority (docs/design/confidentiality/confidentiality-plan-13-reader-set-labels.md §10, where each
 * line is measured or sourced). Node's variable is ADDITIVE: the session CA
 * alone. The others REPLACE the client's store, so they get the combined
 * bundle (system CAs + session CA); without one (no system bundle found) only
 * curl keeps the session-CA-only setting, and the direct (NO_PROXY) hosts
 * stay reachable for everything else through the system store.
 *
 * `userTrust` (confidentiality-plan-12 F6): a variable the user had set to
 * their own CA file gets that file merged with the session CA instead
 * (net-proxy.ts `writeUserTrustFiles`), so a corporate CA survives
 * inspection; it wins over the session-only value, and a variable only the
 * user set (e.g. SSL_CERT_FILE with no system bundle found) is still set.
 */
export function mitmTrustEnv(
  caCert: string,
  bundle: string | undefined,
  userTrust: Record<string, string> = {},
): Record<string, string> {
  const env: Record<string, string> = {
    NODE_EXTRA_CA_CERTS: caCert,          // Node, npm, Bun
    CURL_CA_BUNDLE: bundle ?? caCert,     // curl
  };
  if (bundle) {
    env["SSL_CERT_FILE"] = bundle;        // OpenSSL clients, Go, Ruby, Python urllib, an OpenSSL wget (a GnuTLS wget ignores it)
    env["REQUESTS_CA_BUNDLE"] = bundle;   // Python requests, pip, twine, az
    env["GIT_SSL_CAINFO"] = bundle;       // git over https
    env["CARGO_HTTP_CAINFO"] = bundle;    // cargo (rustup's reads SSL_CERT_FILE too; one linked to a GnuTLS or CA-pinned system libcurl does not)
    env["AWS_CA_BUNDLE"] = bundle;        // aws CLI / botocore (vendor-documented)
    env["CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE"] = bundle; // gcloud (vendor-documented)
  }
  return { ...env, ...userTrust };
}

/** `existing` NODE_OPTIONS with `option` appended once (a user's own options
 *  are kept, in order). */
export function withNodeOption(existing: string | undefined, option: string): string {
  const parts = (existing ?? "").split(/\s+/).filter(Boolean);
  if (!parts.includes(option)) parts.push(option);
  return parts.join(" ");
}

/** Does a Node of this `--version` accept `--disable-warning` in NODE_OPTIONS
 *  (20.11+ on the 20 line, 21.3+ after)? Unknown (null) ⇒ no. */
export function nodeTakesDisableWarning(version: string | null): boolean {
  const m = /^v?(\d+)\.(\d+)/.exec(version ?? "");
  if (!m) return false;
  const major = Number(m[1]);
  const minor = Number(m[2]);
  return major > 21 || (major === 21 && minor >= 3) || (major === 20 && minor >= 11);
}
