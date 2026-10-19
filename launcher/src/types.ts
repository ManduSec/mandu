/**
 * types — the core data shapes of the mandu wrapper.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy):
 *   NEW Mandu code. The LaunchPlan fields are the typed form of the env/flag
 *   contract in launcher/mandu-run.sh (header ENV CONTRACT, parse loop
 *   L428-451). Pattern mirrored from interceptors/exec-wrap/src (one file per
 *   responsibility, pure logic split from the process entry).
 */
import type { ModelEndpoint } from "./model-endpoints.js";
import type { OpenAiRoute } from "./agent-model-route.js";
import type { GooseRouting } from "./goose-route.js";
import type { EgressHoldChoice } from "./egress-hold.js";
import { AGENTS, type Agent } from "./generated/agents.js";

/** Which agent is being wrapped. Auto-detected from argv[0] basename when it
 *  names a known agent; anything else REFUSES the launch and asks for an
 *  explicit --target (parse.ts). Guessing here was a real hole: `mandu --
 *  openclaw …` used to infer "claude" and compose an ANTHROPIC_BASE_URL delta
 *  both openclaw and opencode are probe-verified to IGNORE (they take their
 *  base URL from config files, agent-e2e-harness.md §2.1/§2.2) — every rung
 *  came up, nothing failed, and the agent talked straight to the real endpoint
 *  with nothing symbolized. A silent unprotected session is the one shape the
 *  launcher must never produce.
 *
 *  `shell` (agent-e2e-harness.md §9.1, 2026-09-26) is NOT an agent: a plain
 *  command (`mandu -- bash …`, or any program under an explicit `--target
 *  shell`). It gets every OS-level rung and the claude-style ENV routing
 *  (ANTHROPIC_BASE_URL → the anthropic-proxy), no agent-specific argv splice
 *  or config file, and a launch note that names what that routing does NOT
 *  reach (codex / openclaw / opencode started inside it). Inferred only from
 *  a POSIX shell's basename (SHELL_BASENAMES below): an unknown program may
 *  be an agent wrapper, so it still refuses.
 *
 *  The agents are the agent registry's (generated/agents.ts, a copy of
 *  scripts/agents/agent-registry.mjs; supported-agents.md §5.7); `shell` is
 *  the launcher's own and stays here. */
export type Target = Agent | "shell";

/** Every target, in the registry's order then `shell`: what `--target`
 *  accepts (parse.ts) and `mandu doctor --secrets --target` too. */
export const TARGETS: readonly Target[] = Object.freeze([...AGENTS, "shell"]);

export function isTarget(s: unknown): s is Target {
  return (TARGETS as readonly unknown[]).includes(s);
}

/** POSIX shells: the only non-agent argv[0] basenames inferred as the `shell`
 *  target (Target above). Interpreters (node, python, …) are deliberately
 *  absent: `node openclaw.mjs` IS an agent, and a wrong guess is the hole the
 *  refusal closes. Any other plain command takes an explicit `--target shell`.
 *  Also the argv[0]s that never receive Codex's routing overrides under
 *  `--target codex` (codex-argv.ts codexOverridesReach). */
export const SHELL_BASENAMES: ReadonlySet<string> = new Set(["sh", "bash", "dash", "zsh", "ksh", "mksh", "ash", "fish"]);

/** Node runtimes and runners: they read NODE_OPTIONS, so the SDK route's
 *  preload loads in the program they run (sdk-route.ts). */
const NODE_HOST_BASENAMES: ReadonlySet<string> = new Set(["node", "nodejs", "npx", "tsx", "ts-node"]);
/** Python runtimes and runners: they read PYTHONPATH, so the SDK route's
 *  Python hook (sdk-route-python/sitecustomize.py) loads in the program they
 *  run. */
const PYTHON_HOST_BASENAMES: ReadonlySet<string> = new Set(["python", "python3", "uv", "uvx", "pipx"]);
/** Other language runtimes a host program runs under; none loads a hook. */
const OTHER_HOST_BASENAMES: ReadonlySet<string> = new Set(["bun", "bunx", "deno"]);

/**
 * Whether argv[0] is a language runtime running a HOST program (a product
 * built on an agent SDK, docs/design/agents/agent-sdks.md), and which kind:
 * "node" (the SDK route's preload loads in it), "python" (its Python hook
 * does), "other" (neither), or null. Never inferred as a target (an
 * interpreter may run an agent: `node openclaw.mjs`); it only decides, under
 * an explicit `--target`, that argv[0] takes no agent argv splice (`node -c
 * …` is node's own --check; codex-argv.ts codexOverridesReach) and that the
 * SDK route applies. Pure.
 */
export function hostRuntimeOf(argv0: string | undefined): "node" | "python" | "other" | null {
  const b = (argv0 ?? "").split("/").pop() ?? "";
  if (NODE_HOST_BASENAMES.has(b)) return "node";
  if (PYTHON_HOST_BASENAMES.has(b) || /^python3\.\d+$/.test(b)) return "python";
  if (OTHER_HOST_BASENAMES.has(b)) return "other";
  return null;
}

/** The model-API wire a target speaks — which context proxy fronts it. claude,
 *  openclaw and opencode all speak genuine Anthropic Messages (probe-verified
 *  2026-08-05, 5af13df) and share the anthropic-proxy; codex is the openai-proxy;
 *  a plain `shell` command gets the anthropic-proxy's env routing.
 *  How the routing is DELIVERED still differs per target (env for claude and
 *  shell, -c argv splice for codex, a config file for openclaw/opencode, and
 *  Goose's own env keys for goose: goose-route.ts). goose speaks Anthropic
 *  Messages through its built-in anthropic provider (captured on 1.53.0). */
export function wireOf(target: Target): "anthropic" | "openai" {
  return target === "codex" ? "openai" : "anthropic";
}

/** Resolved U-LLM (quarantined inspect-mcp) config — see services/mcp.ts. */
export interface Ullm {
  mode: "api" | "cli";
  /** The REAL Anthropic endpoint the U-LLM uses (NOT the proxy). */
  baseUrl: string;
  /** Quarantined key (api mode only). */
  apiKey?: string;
  /** Binary hint (cli mode only): "claude" | "codex". */
  binary?: string;
  /** The launcher's CODEX_HOME (cli mode with the codex binary only): the
   *  quarantined `codex exec` signs in from the same place as the agent's
   *  Codex. Codex hands a stdio MCP server a fixed env, without CODEX_HOME,
   *  so the inspect server entry names it (services/mcp.ts). */
  codexHome?: string;
  /** The Codex quarantine's upstream pair the U-LLM forwarder relays to
   *  (services/ullm-forwarder.ts; cli mode with the codex binary only).
   *  Absent: the real pair. MANDU_ULLM_OPENAI_UPSTREAM /
   *  MANDU_ULLM_CHATGPT_UPSTREAM point it at a stand-in (a replay's
   *  quarantine model, the live runner's recording relay). */
  codexUpstreams?: { api: string; chatgpt: string };
  /** Optional model id; emitted only when set. */
  model?: string;
  /**
   * The launcher's loopback U-LLM forwarder (services/ullm-forwarder.ts), set
   * once it is live. When present the U-LLM is pointed HERE instead of dialing
   * :443 directly — the relay runs outside the landlock-net wrap and forwards
   * VERBATIM to `baseUrl`, so the strong port posture keeps a working U-LLM
   * while pinning the reachable destination. Emitted into .mcp.json as BOTH
   * ANTHROPIC_BASE_URL and the MANDU_ULLM_FORWARDER pin that inspect-mcp's
   * loopback guard trusts (it refuses every OTHER loopback URL, fail-closed).
   */
  forwarderUrl?: string;
}

/** Fully-resolved launch intent — the pure output of parse.ts. */
export interface LaunchPlan {
  target: Target;
  /** The agent command + args, verbatim from after the `--` separator. */
  argv: string[];
  scopeId: string;
  /** True when parse minted `scopeId` (`<epochSec>-<pid>`: no --id, no
   *  MANDU_SCOPE_ID). Only such a scope dir is removed at a clean exit
   *  (scope-dir-cleanup.ts). */
  scopeIdGenerated?: boolean;
  /**
   * Observability batch id (MANDU_BATCH_ID): groups this launch's session with
   * its siblings in the dashboard sidebar (one e2e suite process / one CI job =
   * one batch). For claude it is packed into the session-id custom header as a
   * ";x-mandu-batch-id: <id>" pair, which the anthropic-proxy already unpacks
   * (proxy.ts batchIdFor). Purely observability; absent for normal launches.
   */
  batchId?: string;
  /**
   * What this session IS within its batch (MANDU_BATCH_MEMBER,
   * `scenario:<key>` or `posture:<key>`): the watch runner sets it per pane,
   * one scenario variant per session or one posture group under
   * --shared-session, and it rides the `launch_posture` event so the
   * dashboard badges the row by it instead of guessing from the session id
   * (a posture group `S1` and scenario `S1` read the same there). Purely
   * observability; absent for normal launches (parse.ts batchMemberOf).
   */
  batchMember?: BatchMember;
  /**
   * TENANT (policy-surface.md §2.7): "live" — a human's real agent
   * run (the default) — or "test" — an e2e suite, a harness, a dev rig
   * (`--tenant test` / MANDU_TENANT=test). Rides to every child as
   * MANDU_TENANT and to the model proxy as the `x-mandu-tenant` header, so
   * every event the session emits is stamped and the dashboard never has to
   * guess from a session-id prefix; the launcher refuses to start against an
   * arbiter that declares the OTHER tenant.
   */
  tenant: "live" | "test";
  /**
   * Claude TUI renderer pin (env-compose.ts CLAUDE_TUI_PIN): with
   * `MANDU_CLAUDE_TUI_PIN=1` the launcher prepends `--settings
   * {"tui":"default"}` to a claude launch, forcing the inline renderer. OFF
   * by default since 2026-09-19: the reply-filter's screen-cell reconciler
   * resolves the alt-screen "fullscreen" renderer too (differential-
   * interactive.md §19), so claude runs whatever renderer the release / the
   * user's `tui` setting picks. The pin stays as the escape hatch for a
   * user who hits a §19 residual (2026-09-05 → 2026-09-19 it was ON by
   * default, §17).
   */
  claudeTuiPin?: boolean; // absent = off
  arbiterSock: string;
  /** How arbiterSock was resolved (arbiter-sock.ts): "autostart" makes run.ts
   *  start the arbiter in INSTANCE mode (bind under instances/<id>/ + promote
   *  `current`) instead of pinning the path (runtime-instances.md §5). */
  arbiterSockMode: "pinned" | "current" | "legacy" | "autostart";
  /** The runtime base (`…/mandu`) holding instances/ + `current`. */
  arbiterRuntimeBase: string;
  /** The arbiter's HUMAN-PLANE socket as its `hello` reported it
   *  (human-plane.ts, arbiter-human-plane.md): set by run.ts once the
   *  arbiter is up; null when it serves none. Handed to the human-facing
   *  children only (reply filter, fs-sync, net-proxy, and the Claude and
   *  Codex context proxies for reply row reservation), never to the agent. */
  arbiterHumanSock?: string | null;
  /** The directories the agent world is walled off from (human-plane.ts
   *  `humanPlaneDirs`): the guard's unixDeny, the twin wrap's tmpfs, the
   *  Seatbelt deny, and no Unix allow-list entry may touch them. */
  humanPlaneDirs?: string[];
  /** The launch's scope-local events dir (`<scopeRunDir>/events`): a
   *  per-launch (pinned) arbiter is started with `--event-dir` at it, and its
   *  parent is the scope run dir the launch's logs and status files use. */
  eventDir: string;
  /** Working dir the agent runs in (Part 2: the AgentView worktree). */
  cwd: string;
  /**
   * Original launch CWD (the HumanView). `cwd` above is REWRITTEN to the
   * AgentView worktree by the fs-view service; this keeps the human side.
   */
  humanCwd: string;
  /**
   * The PATH the agent will run with, captured at parse time. The env composer
   * prepends the exec-shim dir to THIS (not the launcher's ambient process.env)
   * so the composer stays pure and shims the PATH that actually reaches the agent.
   */
  basePath: string;
  /** claude anthropic-proxy endpoint. */
  proxy: { host: string; port: number };
  /** codex openai-proxy endpoint. */
  openaiProxy: { host: string; port: number };
  openaiProviderName: string;
  /** The env var the routed Codex provider reads its key from (env_key):
   *  OPENAI_API_KEY, or CODEX_API_KEY when only that one is set. Absent =
   *  OPENAI_API_KEY. */
  openaiEnvKey?: "OPENAI_API_KEY" | "CODEX_API_KEY";
  /** How the routed Codex provider authenticates (agent-sign-in.md §2.4
   *  item 1): `key` = `env_key` (a key variable is set); `sign-in` = no key
   *  variable, so Codex uses its own `codex login` (`requires_openai_auth`, no
   *  `env_key`) and the proxy relays it. A user base URL or a declared main
   *  model keeps `env_key` whatever this says (env-compose.ts). Absent = key. */
  codexAuth?: "key" | "sign-in";
  /** Resolved base URLs (explicit override wins; else derived from proxy). */
  anthropicBaseUrl?: string;
  openaiBaseUrl?: string;
  /** Set once the egress gate is wired (Part 2 populates from a running proxy). */
  netProxy?: { host: string; port: number };
  /** The egress proxy carries the model-host deny (model-host-deny.ts; set by
   *  the manager from the proxy it started): the model hosts leave NO_PROXY,
   *  the connect guard denies them, the U-LLM rides its forwarder. Absent or
   *  false: none of that (no egress proxy, or the confidentiality axis off). */
  modelHostDeny?: boolean;
  /** The live loopback U-LLM forwarder endpoint (services/ullm-forwarder.ts),
   *  set by the manager when it starts; applyLandlockNet adds its port to the
   *  allowed set. Absent when the forwarder is off (landlock-net opted out /
   *  non-Anthropic U-LLM) or failed to start (utility-class degrade). */
  ullmForwarder?: { host: string; port: number };
  /** The Chrome debugging endpoint the DevTools relay dials (`--browser-cdp`,
   *  browser-cdp.ts parseBrowserCdp: `http://<loopback>:<port>`). Absent: no
   *  relay. */
  browserCdp?: string;
  /** `--browser` (browser-launch.ts): the manager starts a Chrome for the
   *  agent (services/browser.ts) and sets `browserCdp` to its endpoint. */
  browser?: boolean;
  /** The live DevTools relay (services/cdp-relay.ts), set by the manager:
   *  the agent is given its URL (browser-cdp.ts) and the connect guards
   *  admit its port. */
  cdpRelay?: { host: string; port: number; url: string };
  /** The model endpoints policy.yaml `models:` declares (the arbiter's
   *  `modelEndpoints` op, read by run.ts; confidentiality-plan-11 D2/D5).
   *  applyLandlockNet / applyNetGuard admit the `local: true` ones.
   *  Absent / [] = none declared, or the arbiter could not say. */
  modelEndpoints?: ModelEndpoint[];
  /** The per-call endpoint timeout the inspect-mcp entry carries as
   *  MANDU_ULLM_ENDPOINT_TIMEOUT_MS (ullm-timeout.ts
   *  `entryUllmEndpointTimeoutMs`: the user's value, else the local default
   *  when a `local: true` model is declared). Absent = none written. */
  ullmEndpointTimeoutMs?: number;
  /** The declared local endpoints' token values by variable name, from the
   *  launcher's own environment (model-endpoints.ts `localModelTokens`): the
   *  inspect-mcp server entry carries them, never the agent's environment. */
  modelTokens?: Record<string, string>;
  /** Plan 12 D3: the declared local endpoints' client keys, entry name → PEM
   *  (model-endpoints.ts localModelClientKeys), for inspect-mcp's env. */
  modelClientKeys?: Record<string, string>;
  /** The session's main model when a user-set ANTHROPIC_BASE_URL equals a
   *  declared `wire: anthropic` entry of policy.yaml `models:` (plan 11 §5,
   *  phase 3; run.ts). Set together with clearing `anthropicBaseUrl`, so the
   *  manager STARTS the model proxy instead of skipping it and the agent is
   *  pointed at the proxy; context-proxy.ts hands `upstream` to the proxy as
   *  MANDU_UPSTREAM (model-endpoints.ts `tllmUpstream`: literal loopback for a
   *  `localhost` name, never plain http off this machine). `local` is the
   *  entry's declaration as the launcher read it; the arbiter's registry, by
   *  name, stays the authority for rung 3. Absent = the agent's default
   *  vendor, or an undeclared base URL (the proxy is skipped, with a warning). */
  tllmEndpoint?: { name: string; url: string; local: boolean; upstream: string; tls?: import("./endpoint-tls.js").EndpointTlsConfig; perimeter?: readonly string[] };
  /** Extra hosts appended to NO_PROXY (MANDU_MODEL_HOSTS, comma-split). */
  noProxyExtra: string[];
  /** Session-CA cert path once MITM trust is wired (Part 2). */
  mitmCaCert?: string;
  /** System CAs + the session CA in one PEM, for clients whose CA variable
   *  REPLACES the system store (curl, OpenSSL, requests, git); absent when no
   *  system bundle was found (then only the additive Node variable is set). */
  mitmCaBundle?: string;
  /** The user's own CA files (a trust variable they had set, e.g. a corporate
   *  CA in NODE_EXTRA_CA_CERTS or SSL_CERT_FILE) each merged with the session
   *  CA, by variable; these win over the session-only files so the user's CA
   *  survives TLS inspection (confidentiality-plan-12 F6). */
  mitmUserTrust?: Record<string, string>;
  /** exec-wrap PATH-shim dir once created (Part 2). */
  shimDir?: string;
  /**
   * exec-box PATH-shim dir once created (docs/design/integrity/exec-routing.md §7). One
   * shim per curated read-only command routes through `mandu-exec-box`, which
   * BOXES it in the net-off / RO-root AgentShell. Prepended to the agent PATH
   * (env-compose) ahead of the exec-wrap shim dir. Absent when --exec-box is off
   * or the box bin / bwrap is unavailable (graceful degrade).
   */
  execBoxShimDir?: string;
  /**
   * Mandu's own bubblewrap dir (bwrap-grant.ts MANDU_BWRAP_DIR), set when
   * `mandu setup` installed it and its grant is loaded. Put on the agent PATH
   * after the shim dirs, so Codex's sandbox and the exec box run the copy
   * where no secret wrap is around them (inside the wrap either bwrap works).
   */
  bwrapDir?: string;
  /** Written .mcp.json path, or undefined when --no-mcp. */
  mcpConfig?: string;
  /** The same servers as `mcpConfig`, as entries: Codex takes MCP servers as
   *  `-c mcp_servers.<name>.*` overrides (env-compose.ts), not a file. */
  mcpServers?: Record<string, { command: string; args: string[]; env: Record<string, string> }>;
  /** The inspect-mcp network confine (inspect-net-confine.ts; confidentiality-
   *  plan-11 §8 item 5): the `mandu-landlock-apply --net-only …` argv every
   *  writer of the inspect server entry prefixes to its command (services/
   *  mcp.ts inspectMcpConfigDoc). Set by the manager before the MCP config is
   *  written; absent = off or degraded (today's command). */
  inspectMcpWrap?: string[];
  /**
   * The per-run agent config file for the config-routed targets (openclaw /
   * opencode), written by the manager's agent-config step (services/
   * agent-config.ts): the user's own config deep-merged under our routing
   * override, emitted into the scope run dir. The env composer delivers it via
   * `envVar` (OPENCLAW_CONFIG_PATH / OPENCODE_CONFIG). For these targets this
   * file IS the model-context chokepoint wiring — compose refuses to launch
   * without it (fail-closed; see composeLaunch). `env`: extra variables the
   * routing also needs (OpenCode: OPENCODE_CONFIG_CONTENT, which outranks a
   * project config; agent-config.ts opencodeRoutingContent).
   */
  agentConfig?: { envVar: string; path: string; env?: Record<string, string> };
  /**
   * The agent's version as the launch probed it (agent-versions.ts
   * launchVersionCheck), null when it could not be read or was not probed (a
   * wrapper under --target). Set by run.ts; the OpenClaw config writer picks
   * which memory-search keys it may write by it (agent-config.ts
   * openclawMemoryShape), since OpenClaw rejects a config with a key its
   * release does not know.
   */
  agentVersion?: string | null;
  /**
   * The OpenAI-family providers of an OpenClaw / OpenCode / Goose launch
   * routed through the model proxy (agent-model-route.ts agentModelPlan,
   * goose-route.ts gooseOpenAiRoutes; empty or absent when every model is
   * Anthropic). Set by run.ts after the model check; the context proxy gets
   * each provider's real base URL (MANDU_OPENAI_UPSTREAMS) and the agent
   * config (Goose: its env, env-compose.ts) points the provider at
   * `<proxy>/_mandu/openai/<id>` (agent-config.ts).
   */
  openaiRoutes?: readonly OpenAiRoute[];
  /**
   * Goose: the providers the launch pins (GOOSE_PROVIDER,
   * GOOSE_SUBAGENT_PROVIDER) and the openai endpoint when one is used
   * (goose-route.ts gooseRoutePlan). Set by run.ts after the provider check;
   * absent = anthropic only.
   */
  gooseRouting?: GooseRouting;
  /**
   * fs CWD→AgentView wiring: true = explicit --fs-sync (a non-git workspace
   * then FAILS the launch), false = opted out (--no-fs-sync / MANDU_FS_SYNC=0),
   * undefined = auto — on for git workspaces, raw CWD otherwise.
   */
  fsSync?: boolean;
  /**
   * WHY fsSync is false, when it is (release checklist a4): `"mode"` = the
   * protection mode runs with the integrity axis OFF, which needs no AgentView
   * twin at all — a designed posture, reported as an informational note only;
   * absent = the user opted out (--no-fs-sync / MANDU_FS_SYNC=0 / config
   * `fs-sync = false`) while integrity is on — the DEGRADED fs rung warning.
   */
  fsSyncOffReason?: "mode";
  /**
   * Eager sync (fs-sync.md §2.8 Phase 2): default ON;
   * --no-fs-sync-eager / MANDU_FS_SYNC_EAGER=0 opt out. When the fs-view
   * service is active, ALSO run the resident `fs-sync-cli watch` so AgentView
   * writes sync to the HumanView at the tool-call boundary (per tool_result),
   * not just post-exit. UTILITY-CLASS / fail-safe: a dead watcher degrades to
   * the post-exit sweep, which stays unconditional either way. No effect when
   * fs-sync itself is off/skipped.
   */
  fsSyncEager?: boolean;
  /** MANDU_NO_CONTEXT_PROXY=1 — skip the context-proxy autostart (tests/dev). */
  noContextProxy: boolean;
  /**
   * HumanView↔AgentView root pairs for the context proxy's fs prefix map
   * (fs-sync.md §1.3, P2). Populated by the fs-view service — which is
   * why fs-view starts BEFORE the context proxy — and exported to the proxy as
   * MANDU_VIEW_MAP. Absent (non-git workspace / fs-sync off) → no rewriting.
   */
  viewMap?: Array<{ human: string; agent: string }>;
  /**
   * Chokepoint service requests. netProxy / execWrap are TRI-STATE, mirroring
   * fsSync (the non-root principle: every attachable hardening defaults ON):
   * `true` = explicit (--net-proxy / env=1; unavailability FAILS the launch
   * closed), `false` = opted out (--no-net-proxy / env=0), `undefined` = auto —
   * on by default, DEGRADING to a warning when the service cannot start (the
   * default posture must never brick a launch on a host missing a dependency).
   * netProxyMitm is tri-state too since plan 10 §11.5 (2026-09-24): `undefined`
   * = auto — ON whenever the confidentiality axis is on (a secret's value is
   * put back only inside a request the proxy can read, so TLS inspection is
   * what makes the structured twin useful for HTTPS), degrading to the blind
   * tunnel with a notice when no session CA can be minted; `true` = explicit
   * (unavailability fails the launch closed); `false` = opted out.
   * (fs-preload and --unshare/--unshare-net were retired
   * 2026-07-14: requesting one is a parse-time error, see parse.ts.)
   */
  requested: {
    netProxy?: boolean;
    netProxyMitm?: boolean;
    execWrap?: boolean;
  };
  execWrapCmds: string[];
  /**
   * Whole-agent TCP port-allow wrap (docs/design/integrity/exec-routing.md §7): prepend
   * `mandu-landlock-apply --net-only` around the agent tree so ONLY the
   * computed set (proxy ports + U-LLM forwarder; non-strict also 443 + 22) may
   * CONNECT — every other TCP is denied in-kernel even when a raw-socket exfil
   * bypasses HTTP_PROXY. TRI-STATE, ON by default (non-root principle): `true`
   * = explicit flag, `undefined` = default-on, `false` = --no-landlock-net /
   * MANDU_LANDLOCK_NET=0. Always degrades to no wrap when the applier bin is
   * missing or the kernel lacks Landlock net (never fails the launch).
   */
  landlockNet?: boolean;
  /** Explicit allowed-TCP-port override (--landlock-net=port,port /
   *  MANDU_LANDLOCK_NET_PORTS). When set it REPLACES the computed set; the
   *  auto 443/22 are suppressed and applyLandlockNet warns if the target's
   *  model-proxy port is absent (model calls would break). */
  landlockNetPorts?: number[];
  /** --landlock-net-strict / MANDU_LANDLOCK_NET_STRICT: DENY the workflow
   *  ports 443 + 22 (implies --landlock-net). Closes the TLS/ssh exfil holes;
   *  the U-LLM survives via the loopback forwarder, but any OTHER direct
   *  :443/:22 client in the agent tree (git-ssh, proxy-unaware fetchers)
   *  breaks — applyLandlockNet banners the trade-off. */
  landlockNetStrict?: boolean;
  /** --landlock-net-bind=port,port / MANDU_LANDLOCK_NET_BIND: TCP ports the
   *  agent tree may BIND (listen on) under the wrap — an agent whose TUI is a
   *  local server (OpenCode `--port`, a gateway) needs one; a handled Landlock
   *  net domain denies every other bind(2). A bind port is also connectable
   *  (added to the CONNECT set: the agent's own client half dials it). */
  landlockNetBind?: number[];
  /** supported-agents.md §2.3.1: the agent's executable (real path) when it
   *  is OpenCode 2, whose CLI talks to a private server it spawns. The guard
   *  then performs that server's ephemeral loopback bind and admits the
   *  client's connect to it, and only the client's (net-guard-setup.ts
   *  NET_GUARD_OWN_SERVER_ENV). Unset for every other launch. */
  ownServerExe?: string;
  /** The guard is a CONDITION of this launch, not additive hardening: its
   *  wrap runs without `--skip-unsupported`, so a guard that cannot start
   *  fails the launch (exit 71) instead of running the agent unguarded.
   *  Set for OpenCode 2 with the confidentiality axis on
   *  (opencode2-confidentiality.ts). */
  netGuardRequired?: boolean;
  /**
   * Box a curated set of PATH-shadowed commands (docs/design/integrity/exec-routing.md §7):
   * each shim routes its command through `mandu-exec-box` (net-off AgentShell;
   * RW = the AgentView at both its own path and the workspace path when fs-view
   * is active, RO-root otherwise), unlike --exec-wrap which only GATES
   * symbol-as-command. TRI-STATE, ON by default (non-root principle): `true` =
   * explicit --exec-box[=cmds], `undefined` = default-on, `false` =
   * --no-exec-box / MANDU_EXEC_BOX=0. Always degrades (bin/bwrap/userns
   * missing only warns). The default set is READ-ONLY data-inspection tools.
   */
  execBox?: boolean;
  /** The rung-2 CLEAN-BOX posture for boxed commands (exec-routing.md §8.5):
   *  each boxed AgentShell exec is FIRST attempted in the clean box (reads only
   *  under system roots, AgentView write-only, stdout captured + hash-reported)
   *  so a benign output rides UN-symbolized; a failed attempt reruns in the
   *  ordinary box (output UNTRUSTED, as before). Tri-state riding exec-box:
   *  `true` = --exec-clean-box, `undefined` = ON exactly when the session's
   *  guard hosts the attempt (exec-routing.md §8.5.3: only its verdict is
   *  honored; the in-tree attempt un-masks nothing, so without the guard the
   *  default is OFF), `false` = --no-exec-clean-box / MANDU_EXEC_CLEAN_BOX=0. Baked into the shims as
   *  a HARD export — the posture is the launcher's decision, not ambient env. */
  execCleanBox?: boolean;
  /** exec-routing.md §8.5.3: the arbiter offered this session a clean
   *  reporter (the launcher's first `setSessionUpstream` asked for one). */
  cleanReporterOffered?: boolean;
  /** Set by applyExecBox when the guard hosts the clean box: what
   *  applyNetGuard hands the guard (clean-host.ts). */
  cleanHost?: import("./clean-host.js").CleanHostPlan;
  /** exec-box shadowed command set (--exec-box=cmds / MANDU_EXEC_BOX_CMDS);
   *  defaults to the read-only inspection tools. Always populated by parse. */
  execBoxCmds?: string[];
  /**
   * Whole-agent IP/DOMAIN-aware connect-guard (docs/design/integrity/exec-routing.md §7.5):
   * prepend `mandu-net-guard` OUTSIDE the landlock-net port wrap so it traps
   * `connect(2)` across the whole agent tree and decides by DESTINATION (IP /
   * CIDR / resolved host × port) — closing the port-only gap where landlock's
   * `:443` allow admits ANY host. TRI-STATE, ON by default (non-root principle):
   * `true` = explicit --net-guard, `undefined` = default-on, `false` =
   * --no-net-guard / MANDU_NET_GUARD=0. Always degrades to no guard when the
   * bin is missing / seccomp is unavailable (never fails the launch). The default
   * (non-strict, uncurated) allow-set keeps arbitrary HTTPS working; strict OR an
   * explicit --net-allow list makes it IP/domain-precise.
   */
  netGuard?: boolean;
  /** Explicit connect-guard allow-list (--net-allow=spec,... /
   *  MANDU_NET_ALLOW), each spec `[proto:]host:port` (host = IP / CIDR /
   *  [IPv6] / dns-name / *). When set, the permissive `tcp:*:443`/`:22` fallback
   *  is DROPPED (curated ⇒ narrow); the loopback service + DNS + API-host rules
   *  are always kept so the agent stays functional. */
  netGuardAllow?: string[];
  /** The hosts this agent would upload a transcript, trace or telemetry to
   *  (upload-deny.ts `uploadDenyHosts`; supported-agents.md §5.3.4 rule 1),
   *  set by run.ts before the services start. Denied at both network layers:
   *  the connect guard (`--deny`) and the net-proxy
   *  (`MANDU_NET_PROXY_DENY_HOSTS`). Entries are `host` / `host:port` /
   *  `.suffix`. Absent or empty = none. */
  uploadDenyHosts?: string[];
  /** Hosts denied at the net-proxy ONLY (upload-deny.ts
   *  `uploadDenyProxyOnlyHosts`: Goose's unrouted providers' model hosts,
   *  supported-agents.md §5.6.3), joined to uploadDenyHosts in
   *  `MANDU_NET_PROXY_DENY_HOSTS`, never given to the connect guard. */
  netProxyOnlyDenyHosts?: string[];
  /** How long the net-proxy holds a request waiting on an unanswered card
   *  (egress-hold.ts `launcherEgressHold`: the user's MANDU_EGRESS_HOLD_MS,
   *  else 60 s for an interactive session on a terminal, else 0). Set by
   *  run.ts; absent (a plan built elsewhere) = the user's value or 0. */
  egressHold?: EgressHoldChoice;
  /** Codex: one of the user's config layers names the legacy `connectors`
   *  feature key, so the launch also forces `features.connectors=false`
   *  (codex-argv.ts CODEX_CONNECTORS_OFF). Set by run.ts. */
  codexConnectorsOff?: boolean;
  /** Auto-include the workspace's git-remote hosts in the connect-guard allow-set
   *  when it is NARROWED (strict / curated), so `git push`/`fetch` survive without
   *  a manual --net-allow. Default-on (`undefined`); `false` =
   *  --no-net-guard-git / MANDU_NET_GUARD_GIT=0. No effect in the permissive
   *  non-strict default (the `*` fallback already covers remotes). */
  netGuardGitRemotes?: boolean;
  /** Codex's own command sandbox network (codex-shell-network.ts,
   *  supported-agents.md §6.5): `undefined` = default (on for a codex launch
   *  where the connect guard runs and the user's Codex config does not set it,
   *  announced), `false` = --no-codex-shell-network / MANDU_CODEX_SHELL_NETWORK=0
   *  (Codex's own default), `true` = --codex-shell-network (same as default). */
  codexShellNetwork?: boolean;
  ullm: Ullm;
  mockSitesPath?: string;
  noScope: boolean;
  writeMcp: boolean;
  /** Mount the mandu-policy MCP server (policy-surface.md §8.5.1) beside
   *  mandu-inspect. Absent = on; `false` = --no-policy-mcp /
   *  MANDU_POLICY_MCP=0. --no-mcp drops both servers. */
  writePolicyMcp?: boolean;
  bestEffort: boolean;
  /** --require-confinement / MANDU_REQUIRE_CONFINEMENT / config
   *  `require-confinement` (rootless-confinement-ubuntu-2404.md §3.1): REFUSE
   *  the launch when secrets cannot be confined, instead of the default degrade
   *  to the `gated` posture. Wins over --best-effort. Absent = off. */
  requireConfinement?: boolean;
  /** Mask secret-shaped environment variables in the agent's environment
   *  (plan 10 §11.4). Default on; `--no-env-secrets` / `MANDU_ENV_SECRETS=0`. */
  envSecrets?: boolean;
  /** Plan 10 §8 phase 6: `--no-secret-bind` / `MANDU_SECRET_BIND=0` /
   *  config `secret-bind = false` skips the bwrap bind mount over the secret
   *  files and lets the whole-agent guard alone serve the twins by descriptor
   *  (the posture a host without a user namespace already gets). The soak
   *  switch before the bind is retired; ignored with a WARNING when no guard
   *  is around the launch (the bind then stays). Absent = bind where possible. */
  secretBind?: boolean;
  /** Plan 10 §11.1: when a non-reader opens a secret, hold and ask the human
   *  (`known` = programs in the consumer table only, the default; `always`;
   *  `never`). Until the Inbox hold ships, `ask` verdicts are denials. */
  secretsAsk?: "known" | "always" | "never";
  /** Launch display policy (packaging.md §5): print every rung banner line
   *  even at a TTY. --verbose / MANDU_VERBOSE=1; default off (compact at a
   *  TTY, full when stderr is not a terminal). Absent = off. */
  verbose?: boolean;
  /** User-reply egress filter (packaging.md §5): wrap the agent so its stdout is
   *  desymbolized for the human. Default ON; --no-reply-filter / MANDU_REPLY_FILTER=0
   *  opts out. Utility-only — degrades to passthrough on any failure. */
  replyFilter: boolean;
  /** `goose acp` only: the relay's JSON-aware display pass
   *  (goose-acp-display.ts) desymbolizes Goose's editor-bound messages over
   *  the human plane. The reply filter's switch, read before parse turns the
   *  byte-stream filter off for that shape. Absent on other shapes. */
  acpDisplay?: boolean;
  /** The requested protection mode's NAME (protection-modes.md), present only
   *  when the launch requested BOTH axes (a `--mode`, or both axis flags): every
   *  pair has a name. Informational; the two fields below are what is enforced. */
  mode?: import("./mode.js").Mode;
  /** The pair this launch actually runs under, filled by run.ts after the axis
   *  preflight: what the attached arbiter reports, else the request, else the
   *  built-in default mode (mode.ts effectiveAxes). Launcher-side consumers
   *  (secret-setup, the fs-sync implication, the banner) read THIS, not the
   *  request. */
  effectiveAxes?: import("./mode.js").Axes;
  /** Confidentiality axis (docs/design/confidentiality/confidentiality.md §11 kill switch):
   *  the ONE switch for the second lattice, consumed by the arbiter this
   *  launch starts. undefined ⇒ leave the arbiter's own default (OFF) and any
   *  env the user exported alone; true/false ⇒ --confidentiality /
   *  --no-confidentiality forces MANDU_CONFIDENTIALITY for the stack. */
  confidentiality?: boolean;
  /** Integrity axis (arbiter policy/integrity-flag.ts): the classic IPI
   *  defense's trust classification, default ON. undefined ⇒ leave the
   *  arbiter's default and any exported env alone; true/false ⇒ --integrity /
   *  --no-integrity forces MANDU_INTEGRITY for the stack. --no-integrity
   *  also forces fsSync=false (parse.ts post-parse implication). */
  integrity?: boolean;
}

/** The env + argv changes a single concern contributes. */
export interface ComposedLaunch {
  env: Record<string, string>;
  /** argv tokens spliced immediately after argv[0] (codex -c overrides). */
  argvPrefix: string[];
}

/** The accumulated launch changes across all backends. */
export interface LaunchMutation {
  env: Record<string, string>;
  argvPrefix: string[];
  /** argv that wraps the whole exec, outermost-first; filled by the live wrap
   *  rungs (net-guard → landlock-net → secret-twins/bwrap → reply-filter). */
  launchPrefix: string[];
}

/** What a session is within its batch (LaunchPlan.batchMember). */
export interface BatchMember {
  kind: "scenario" | "posture";
  key: string;
}
