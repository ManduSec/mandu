/**
 * agent-provision.ts — PURE per-agent provisioning for the live e2e suites.
 *
 * Mandu (tests/). Design: docs/design/testing/agent-e2e-harness.md §3.
 *
 * THE ONE THING THIS MODULE OWNS: everything that differs between agents when
 * you point one at the Mandu model-context proxy — which binary, which argv,
 * which env, which config files to materialize, and how to read the reply back
 * out of stdout. Everything else in the live harness (the oracle library, the
 * scenario pool, the group-reaping spawn, the event plumbing) is already
 * agent-agnostic and is NOT touched here.
 *
 * WHY PURE: mirrors the repo's kernel-gated Rust discipline — the DECISION
 * logic (what config, what env, what argv) carries no I/O and is unit-tested
 * with no agent installed, on any machine, in the free CI tier; the ENACTMENT
 * (mkdir, writeFile, spawn) belongs to the caller. `provision()` returns the
 * files to write rather than writing them, for exactly this reason.
 *
 * WHAT IS DELIBERATELY NOT HERE: the scenario list, the oracle selection, and
 * runScenario. Those differ because the agents' TOOL SURFACES differ, and
 * folding them together would need an `if (agent)` at every axis — the failure
 * mode docs/testing/e2e-catalog.md warned about. See the design doc §3.
 *
 * PROVISIONING FACTS ARE PROBE-VERIFIED (2026-08-05), not inferred: each agent
 * was driven against a scripted local /v1/messages endpoint and observed to
 * complete a turn, exit 0, and deliver a resolved x-mandu-session-id header.
 * Re-verify on a version bump — design doc §2.4 has the recipe.
 */

import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import type { AnthropicWireAgent } from "../../scripts/agents/agent-registry.mjs";

/** The agents this harness can drive live: the agents on the Anthropic wire
 *  (the agent registry's named filter, scripts/agents/agent-registry.mjs; it
 *  points each at the scripted /v1/messages endpoint). `claude` is described
 *  here for parity/documentation and for the unit tests; claude-e2e.test.ts
 *  predates this module and still owns its own (identical) provisioning inline. */
export type LiveAgentId = AnthropicWireAgent;

/** The arbiter inbound trust-spec id this agent's tool names are classified
 *  under (arbiter/policy/tool-inbound.ts InboundSpecId). Kept as a plain string
 *  union rather than an import so this module stays dependency-free and
 *  unit-testable in isolation; the suites assert the two agree. */
export type InboundSpecName = "claude-code" | "openclaw-agent" | "opencode" | "goose";

export interface ProvisionInput {
  /** Throwaway HOME/state root for this run — every agent-written dot-dir goes
   *  under here so a run cannot touch the developer's real agent state. */
  agentHome: string;
  /** The agent's working directory (the scenario workspace). */
  workspace: string;
  /** The Mandu model-context proxy for THIS run, e.g. http://127.0.0.1:41234 */
  proxyUrl: string;
  /** `<class>-<scenario>-<ts>` — travels as x-mandu-session-id and is what the
   *  dashboard discovers, badges, and joins the run result onto. */
  sessionId: string;
  batchId: string;
  /** Provider-side model id (what lands in the request body's `model`). */
  model: string;
  prompt: string;
  timeoutMs: number;
  /** Register an MCP stdio server (the U-LLM inspect_symbol channel). Silently
   *  dropped — and reported in `unsupported` — where the agent has no MCP.
   *  `env` is the server process's environment: inspect-mcp needs the arbiter
   *  socket and the U-LLM channel config, and MUST NOT inherit this run's
   *  instrumented ANTHROPIC_BASE_URL (the quarantine talks to the real
   *  endpoint — it refuses a loopback base URL). */
  mcp?: { name: string; command: string[]; timeoutMs?: number; env?: Record<string, string> };
  /** PATH for the child. Callers prepend shim dirs (exec-box) here. */
  path?: string;
  /**
   * Extra environment merged into the agent child's env, LAST (so a posture
   * knob wins over a default). The runner uses it for the net-proxy routing
   * vars (HTTP_PROXY/NO_PROXY and their lowercase twins) — those belong to the
   * scenario's posture, not to any agent's provisioning facts, which is why
   * they arrive here rather than being baked into a provisioner.
   */
  extraEnv?: Record<string, string>;
}

export interface ProvisionedFile {
  /** Absolute path. Always under `agentHome` or `workspace`. */
  path: string;
  content: string;
}

export interface Provisioned {
  binary: string;
  argv: string[];
  env: Record<string, string>;
  /** Config files the CALLER must write before spawning (see WHY PURE). */
  files: ProvisionedFile[];
  /** Capabilities requested but not available on this agent, e.g. ["mcp"] for
   *  OpenClaw. Suites assert on this rather than silently losing coverage. */
  unsupported: string[];
}

export interface AgentProvisioner {
  id: LiveAgentId;
  /** Dashboard session-id class + badge key (registry.ts TEST_SESSION_CLASSES). */
  sessionClass: string;
  /** The arbiter inbound spec this agent's tool names live under. */
  inboundSpec: InboundSpecName;
  /** Tool name for "run a shell command" on this agent — scenarios and
   *  execution-evidence oracles key off it. */
  execTool: string;
  /** Tool name for "read a file" on this agent. */
  readTool: string;
  /**
   * HOW this agent mounts the U-LLM `inspect_symbol` channel — a real
   * provisioning fact with a consequence the caller must act on:
   *
   *   "mcp"    a separate stdio server process (Claude Code, OpenCode). Its
   *            environment is `ProvisionInput.mcp.env`, independent of the
   *            agent's — so the quarantine's `claude -p` gets its own PATH/HOME.
   *   "plugin" registered IN-PROCESS (OpenClaw, which has no MCP client —
   *            design doc §8). There is no separate server env: the quarantined
   *            child inherits the AGENT's environment, so the agent's own
   *            PATH/HOME must be able to reach a logged-in `claude`.
   *   "none"   no channel on this agent.
   *
   * Stated here rather than inferred, because inferring it wrongly is silent:
   * the tool mounts, the model calls it, and the U-LLM call fails with no
   * `ullm_call` event ever emitted.
   */
  inspectMount: "mcp" | "plugin" | "none";
  /** How many model calls a single turn makes BEFORE the agentic one (title
   *  generation and friends). The event poll must not settle on these. */
  sideCallsPerTurn: number;
  /** Does the agent send the session id itself (an `x-mandu-session-id`
   *  header its config carries)? Absent = yes. `false` (Goose): the agent
   *  sends no custom header, so the runner keys the run by the PROXY's own
   *  session key, as the launcher's per-launch proxy is keyed. */
  sessionHeader?: boolean;
  /** Why the binary is missing and how to get it, when the agent's id does
   *  not say (OpenCode 2 shares the id `opencode`); binarySkipReason. */
  notFound?: string;
  /** Resolve the executable; undefined when the agent is not installed. */
  resolveBinary(): ResolvedBinary | undefined;
  provision(input: ProvisionInput): Provisioned;
  /** Pull the human-facing reply text out of the agent's stdout. Pure. */
  extractReply(stdout: string): ExtractedReply;
}

/**
 * The result of pulling a reply out of an agent's stdout.
 *
 * `extracted` EXISTS BECAUSE OF A REAL BUG (2026-08-05): the first OpenClaw
 * implementation silently fell back to returning the whole raw stdout when it
 * failed to locate the reply in the JSON envelope. The utility oracle then
 * matched its regex against the raw envelope — which happens to CONTAIN the
 * reply text — so a completely broken extractor produced a green suite. A
 * fallback that cannot be distinguished from success is a silent degradation,
 * so the fallback stays (never crash the harness on a surprise envelope) but it
 * is now REPORTED, and the runner asserts on it.
 */
export interface ExtractedReply {
  /** The reply text, or the raw stdout when extraction failed. */
  text: string;
  /** Did the parser actually locate the reply? False = `text` is raw stdout. */
  extracted: boolean;
}

export interface ResolvedBinary {
  binary: string;
  /** Fixed args that must precede the agent's own argv (e.g. the .mjs path when
   *  running OpenClaw from a source checkout via `node`). */
  prefixArgs: string[];
  /** Where it came from — surfaced in skip reasons so a SKIP is diagnosable. */
  source: "env" | "path" | "source-checkout";
}

/** A dummy Anthropic key for the fake-upstream tier.
 *
 *  MUST be `sk-ant-` shaped. OpenClaw's pi-ai layer branches on
 *  isOAuthToken(apiKey): on that branch it swaps x-api-key for authToken, adds
 *  Claude Code identity headers, AND injects a "You are Claude Code…" system
 *  block — silently changing the very model context these suites assert on. */
export const DUMMY_ANTHROPIC_KEY = "sk-ant-mandu-e2e-dummy";

/**
 * The real tier's upstream credential (MANDU_TEST_UPSTREAM=real, the
 * `integration.openclaw-headless` and `opencode-headless` entries): an Anthropic API KEY, from
 * MANDU_E2E_ANTHROPIC_API_KEY or ANTHROPIC_API_KEY, or null.
 *
 * Only a key (`sk-ant-api…`, or the Console's newer `sk-ant-usr…`). The agents keep DUMMY_ANTHROPIC_KEY in their
 * configs on both tiers (so the model context they send is the one the fake
 * tier grades) and the harness swaps the key in on the hop to the real API
 * (withUpstreamApiKey). A subscription OAuth token (the nightly's reduced
 * credential, `sk-ant-oat…`) cannot serve here: the API takes it only from a
 * client that presents as Claude Code, and OpenClaw's own OAuth branch then
 * injects a "You are Claude Code…" system block, changing the very context
 * these suites assert on (see DUMMY_ANTHROPIC_KEY).
 */
export function realTierApiKey(env: Record<string, string | undefined> = process.env): string | null {
  for (const k of ["MANDU_E2E_ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY"]) {
    const v = env[k]?.trim();
    if (v && /^sk-ant-(?:api|usr)\d*-[A-Za-z0-9_-]+$/.test(v)) return v;
  }
  return null;
}

/** Why the real tier cannot run here (a clean SKIP), or false. */
export function realTierSkipReason(
  tier: "fake" | "real",
  env: Record<string, string | undefined> = process.env,
): string | false {
  if (tier !== "real" || realTierApiKey(env)) return false;
  return "the real upstream tier needs an Anthropic API key (MANDU_E2E_ANTHROPIC_API_KEY or ANTHROPIC_API_KEY, sk-ant-api… or sk-ant-usr…): " +
    "the agents' dummy key is refused by the real API, and a subscription token (the nightly's reduced credential) " +
    "would make OpenClaw inject a Claude Code system block into the context these suites grade";
}

/** The fetcher that carries a request to the real API with `key` in place of
 *  whatever key the agent sent (x-api-key; any Authorization dropped). */
export function withUpstreamApiKey<A extends { headers: Record<string, string | string[] | undefined> }, R>(
  inner: (args: A) => Promise<R>,
  key: string,
): (args: A) => Promise<R> {
  return (args) => {
    const headers: Record<string, string | string[] | undefined> = {};
    for (const [k, v] of Object.entries(args.headers)) {
      const lk = k.toLowerCase();
      if (lk === "x-api-key" || lk === "authorization") continue;
      headers[k] = v;
    }
    headers["x-api-key"] = key;
    return inner({ ...args, headers });
  };
}

/** Is `cmd --version` runnable? The availability probe every suite gates on. */
function probeVersion(binary: string, prefixArgs: string[] = []): boolean {
  try {
    return (
      spawnSync(binary, [...prefixArgs, "--version"], {
        encoding: "utf8",
        timeout: 20_000,
      }).status === 0
    );
  } catch {
    return false;
  }
}

/**
 * Is the `claude` CLI USABLE for the quarantined U-LLM call — runnable AND
 * credentialed? `--version` alone is NOT enough: the CI container bakes the
 * CLI with no login, so a version-only probe made the inspect scenarios RUN
 * there and fail on the dead quarantine instead of skipping (caught by the
 * first in-container agent-mock-openclaw-opencode run, 2026-08-06). Usable
 * means the subscription OAuth store is present
 * ($HOME/.claude/.credentials.json — the ONLY file the child CLI
 * authenticates via; a container gets it mounted or seeded). An API key in the
 * environment does NOT count: the cli-mode U-LLM child deletes
 * ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN before it spawns claude
 * (inspect-mcp ullm-client.ts buildChildEnv), so a key-only host (the nightly's
 * API lane, continuous-integration.md §9.8) would run the scenario and fail on a
 * login-less CLI instead of skipping. A present-but-expired credential
 * still probes usable — this distinguishes "no credentials at all" (CI) from
 * "a developer box with a login", not token freshness.
 * Deps are injectable so the decision logic unit-tests with no CLI installed.
 */
export function ullmCliUsable(
  opts: {
    /** Ignored: no environment variable makes the cli U-LLM usable (above). */
    env?: Record<string, string | undefined>;
    home?: string;
    probe?: (binary: string) => boolean;
  } = {},
): boolean {
  const home = opts.home ?? homedir();
  const probe = opts.probe ?? ((b: string) => probeVersion(b));
  if (!probe("claude")) return false;
  return existsSync(join(home, ".claude", ".credentials.json"));
}

// ─── OpenCode ────────────────────────────────────────────────────────────────
//
// npm `opencode-ai`. One-shot mode is `opencode run`, which is non-interactive
// BY DEFAULT (no flag needed to suppress the TUI) and exits when the session
// goes idle. Wire is genuine Anthropic Messages when the provider names the
// @ai-sdk/anthropic package — so the existing anthropic-proxy is reused
// unchanged. Design doc §2.2.

/** Custom provider id in opencode.json. Deliberately NOT `anthropic`: naming it
 *  `mandu` keeps the built-in provider's model catalog and credential
 *  discovery entirely out of the run, so nothing can silently fall back to the
 *  real api.anthropic.com if our config is wrong — it fails loudly instead. */
export const OPENCODE_PROVIDER_ID = "mandu";

export function buildOpencodeConfig(input: ProvisionInput): string {
  const mcp = input.mcp
    ? {
        [input.mcp.name]: {
          type: "local" as const,
          command: input.mcp.command,
          enabled: true,
          // The default is 5000ms, which a cold inspect_symbol start can blow
          // through — and a dropped MCP server turns into a confusing
          // "tool not found" rather than a timeout.
          timeout: input.mcp.timeoutMs ?? 30_000,
          // OpenCode's spelling of the server env is `environment`.
          ...(input.mcp.env ? { environment: input.mcp.env } : {}),
        },
      }
    : undefined;

  return (
    JSON.stringify(
      {
        $schema: "https://opencode.ai/config.json",
        provider: {
          [OPENCODE_PROVIDER_ID]: {
            npm: "@ai-sdk/anthropic",
            name: "Mandu proxy",
            options: {
              baseURL: `${input.proxyUrl}/v1`,
              apiKey: DUMMY_ANTHROPIC_KEY,
              headers: {
                "x-mandu-session-id": input.sessionId,
                "x-mandu-batch-id": input.batchId,
              },
            },
            models: { [input.model]: { name: `Mandu ${input.model}` } },
          },
        },
        model: `${OPENCODE_PROVIDER_ID}/${input.model}`,
        // Belt and braces with OPENCODE_PERMISSION below: config is the durable
        // form, the env var is merged OVER file config so it always wins.
        permission: { "*": "allow" },
        ...(mcp ? { mcp } : {}),
      },
      null,
      2,
    ) + "\n"
  );
}

export const opencodeProvisioner: AgentProvisioner = {
  id: "opencode",
  sessionClass: "opencode-e2e",
  inboundSpec: "opencode",
  execTool: "bash",
  readTool: "read",
  // A real MCP client: the inspect server runs as its own stdio process.
  inspectMount: "mcp",
  // A title-generation call lands BEFORE the agentic one (probe-verified: 2
  // requests for a trivial single-turn prompt).
  sideCallsPerTurn: 1,

  resolveBinary() {
    const fromEnv = process.env["MANDU_OPENCODE_BIN"];
    if (fromEnv && existsSync(fromEnv)) {
      return { binary: fromEnv, prefixArgs: [], source: "env" };
    }
    if (probeVersion("opencode")) {
      return { binary: "opencode", prefixArgs: [], source: "path" };
    }
    return undefined;
  },

  provision(input) {
    const configPath = join(input.agentHome, "opencode.json");
    const env: Record<string, string> = {
      PATH: input.path ?? process.env["PATH"] ?? "",
      HOME: input.agentHome,
      // Every XDG root is redirected so nothing lands in the developer's real
      // ~/.config or ~/.local/share (auth.json in particular).
      XDG_CONFIG_HOME: join(input.agentHome, "xdg-config"),
      XDG_DATA_HOME: join(input.agentHome, "xdg-data"),
      XDG_CACHE_HOME: join(input.agentHome, "xdg-cache"),
      XDG_STATE_HOME: join(input.agentHome, "xdg-state"),
      OPENCODE_TEST_HOME: input.agentHome,
      OPENCODE_CONFIG: configPath,
      // REQUIRED for hermeticity: without it every run fetches the models.dev
      // catalog over the network, which both slows the suite and makes it fail
      // differently when offline.
      OPENCODE_DISABLE_MODELS_FETCH: "1",
      OPENCODE_DISABLE_AUTOUPDATE: "1",
      // The analogue of claude's --permission-mode bypassPermissions. Merged
      // over file config, so it wins outright.
      OPENCODE_PERMISSION: JSON.stringify({ "*": "allow" }),
      // Scenario posture (net-proxy routing) wins over the defaults above.
      ...(input.extraEnv ?? {}),
    };

    return {
      binary: "opencode",
      argv: [
        "run",
        "--format",
        "json",
        "--model",
        `${OPENCODE_PROVIDER_ID}/${input.model}`,
        // Auto-approve anything not explicitly denied. Redundant with
        // OPENCODE_PERMISSION and kept because the two knobs have drifted
        // independently across releases.
        "--auto",
        input.prompt,
      ],
      env,
      files: [{ path: configPath, content: buildOpencodeConfig(input) }],
      unsupported: [],
    };
  },

  /** `--format json` emits NDJSON, one event per line. The reply is the
   *  concatenation of `type:"text"` parts, in order. Tolerates non-JSON lines
   *  (a stray warning must not lose the whole reply) and both the nested
   *  `part.text` shape and a flat `text` fallback. */
  extractReply(stdout) {
    const out: string[] = [];
    for (const line of stdout.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed.startsWith("{")) continue;
      let ev: unknown;
      try {
        ev = JSON.parse(trimmed);
      } catch {
        continue;
      }
      if (typeof ev !== "object" || ev === null) continue;
      const rec = ev as Record<string, unknown>;
      if (rec["type"] !== "text") continue;
      const part = rec["part"];
      const text =
        typeof part === "object" && part !== null
          ? (part as Record<string, unknown>)["text"]
          : rec["text"];
      if (typeof text === "string") out.push(text);
    }
    // No `type:"text"` part at all → extraction failed; hand back the raw
    // stream so the oracle still has bytes, but say so.
    return out.length > 0
      ? { text: out.join(""), extracted: true }
      : { text: stdout, extracted: false };
  },
};

// ─── OpenCode 2 ──────────────────────────────────────────────────────────────
//
// npm `@opencode/cli` (2.0.23, the CI guest's pin), the `opencode` agent's
// second generation (supported-agents.md §2.3). What differs from 1.x for a
// one-shot `opencode run`:
//   - `--standalone`: a private in-process server. Without it `run` attaches
//     to (or starts) the user's shared background service, which outlives
//     the run; the launcher forces the flag for the same reason
//     (opencode-argv.ts);
//   - the tools: `shell{command, workdir, timeout, background}` (not
//     `bash`), `read{path}` (not `filePath`); the inbound spec is the same
//     `opencode` one (arbiter/policy/opencode-inbound.ts covers both);
//   - the config: 2.x reads the V1 shape above (normalized), but a V1 `mcp`
//     server defaults to CODE MODE, its tools reachable only inside
//     `execute`; so the inspect server is written in the V2 spelling,
//     `mcp.servers.<name>` with `codemode: false` (the launcher's
//     opencodeV2McpServer), and `execute` is denied as the launcher denies
//     it (OPENCODE_DENY_EXECUTE);
//   - its home: OPENCODE_TEST_HOME (set above for both) is where 2.x looks
//     for `~/.claude` and `~/.agents` (drill-target-opencode.ts
//     opencode2LaunchEnv); it has no OPENCODE_PERMISSION (`--auto` approves).

/** OpenCode 2's binary: MANDU_OPENCODE_V2_BIN, else `opencode2` on PATH (the
 *  CI guest's), and it must report major version 2 (`opencode v2.0.23`). The
 *  same rule as differential-profiles.ts resolveOpencode2Binary. */
export function resolveOpencode2(
  env: Record<string, string | undefined> = process.env,
  versionOf: (binary: string) => string | null = (b) => {
    try {
      const r = spawnSync(b, ["--version"], { encoding: "utf8", timeout: 20_000 });
      return r.status === 0 ? r.stdout : null;
    } catch {
      return null;
    }
  },
): ResolvedBinary | undefined {
  const fromEnv = env["MANDU_OPENCODE_V2_BIN"];
  const [binary, source]: [string | undefined, ResolvedBinary["source"]] = fromEnv
    ? [existsSync(fromEnv) ? fromEnv : undefined, "env"]
    : ["opencode2", "path"];
  if (!binary) return undefined;
  const v = versionOf(binary);
  return v !== null && /^(?:opencode )?v?2\.\d+\.\d+/.test(v.trim()) ? { binary, prefixArgs: [], source } : undefined;
}

/** The OpenCode 2 config: buildOpencodeConfig's routing and permission, the
 *  inspect server in the V2 spelling with code mode off, `execute` denied. */
export function buildOpencode2Config(input: ProvisionInput): string {
  const doc = JSON.parse(buildOpencodeConfig({ ...input, mcp: undefined })) as Record<string, unknown>;
  const timeoutMs = input.mcp?.timeoutMs ?? 30_000;
  const servers = input.mcp
    ? {
        [input.mcp.name]: {
          type: "local",
          command: input.mcp.command,
          ...(input.mcp.env ? { environment: input.mcp.env } : {}),
          codemode: false,
          timeout: { startup: timeoutMs, catalog: timeoutMs, execution: timeoutMs },
        },
      }
    : undefined;
  return JSON.stringify({
    ...doc,
    permissions: [{ action: "execute", resource: "*", effect: "deny" }],
    ...(servers ? { mcp: { servers } } : {}),
  }, null, 2) + "\n";
}

export const opencode2Provisioner: AgentProvisioner = {
  ...opencodeProvisioner,
  execTool: "shell",
  notFound: "no OpenCode 2 binary: set MANDU_OPENCODE_V2_BIN (npm i --prefix <dir> @opencode/cli; <dir>/bin/opencode2) or put `opencode2` on PATH",
  resolveBinary: () => resolveOpencode2(),
  provision(input) {
    const one = opencodeProvisioner.provision(input);
    const configPath = join(input.agentHome, "opencode.json");
    const { OPENCODE_PERMISSION: _gone, ...env } = one.env;
    return {
      ...one,
      binary: "opencode2",
      // `run --standalone`, then 1.x's flags (--format json, --model, --auto, the prompt)
      argv: [one.argv[0]!, "--standalone", ...one.argv.slice(1)],
      env,
      files: [{ path: configPath, content: buildOpencode2Config(input) }],
    };
  },
};

// ─── Goose ───────────────────────────────────────────────────────────────────
//
// aaif-goose/goose (formerly block/goose): ONE Rust binary, the CI guest's pin
// is 1.53.0 (scripts/ci/pins.env). Routed by ENV alone: an env var named as
// the exact uppercase config key outranks config.yaml, so GOOSE_PROVIDER=
// anthropic + ANTHROPIC_HOST=<proxy> is the whole delivery (supported-agents.md
// §5.6). One-shot mode is `goose run --no-session -t <prompt>`; with
// `--output-format json` it prints ONE JSON document of the run's messages
// after a short banner. Probe-verified 2026-10-05 against a scripted
// /v1/messages: exit 0, `POST /v1/messages` only (no GET /v1/models).
//
// SESSION IDENTITY: Goose's built-in Anthropic provider sends no custom
// header (only its own `agent-session-id: <yyyymmdd>_<N>`), so the run's
// session is the PROXY's: the runner starts the proxy with `sessionKey` set
// (as the launcher's per-launch proxy is keyed, MANDU_SESSION_KEY), the way
// Codex is keyed (agent-e2e-harness.md §2.3). `sessionHeader: false` below
// tells the runner.

/** The env every Goose run gets that switches off each channel by which Goose
 *  could carry the conversation (or its metadata) off the machine past the
 *  model proxy (supported-agents.md §5.3.4 rule 1, §5.6): PostHog usage
 *  telemetry, Langfuse traces (both keys set EMPTY: Goose reads the first of
 *  each pair and treats an empty value as unset, so the INIT_PROJECT
 *  fallbacks are never consulted), every OTLP signal, and the prompt and
 *  command classifiers (an endpoint that would receive the text). The
 *  launcher sets the same values for `mandu goose`; they are applied LAST
 *  here, over the caller's env, as the launcher applies them over the
 *  user's. */
export const GOOSE_UPLOADS_OFF_ENV: Readonly<Record<string, string>> = Object.freeze({
  GOOSE_TELEMETRY_OFF: "1",
  LANGFUSE_PUBLIC_KEY: "",
  LANGFUSE_SECRET_KEY: "",
  OTEL_SDK_DISABLED: "true",
  SECURITY_PROMPT_CLASSIFIER_ENABLED: "false",
  SECURITY_COMMAND_CLASSIFIER_ENABLED: "false",
});

/** `--with-extension` for an MCP stdio server: `<name>:K=v … <command> <args>`.
 *  Goose keeps the explicit name verbatim (its tools surface as
 *  `<name>__<tool>`) and splits the rest on whitespace, so no token may carry
 *  a space (a ':' or '=' inside an env value is kept: probed on 1.53.0). */
export function gooseExtensionSpec(mcp: NonNullable<ProvisionInput["mcp"]>): string {
  const tokens = [...Object.entries(mcp.env ?? {}).map(([k, v]) => `${k}=${v}`), ...mcp.command];
  for (const t of tokens) {
    if (/\s/.test(t) || t === "") throw new Error(`goose --with-extension cannot carry the token ${JSON.stringify(t)} (whitespace or empty)`);
  }
  return `${mcp.name}:${tokens.join(" ")}`;
}

export const gooseProvisioner: AgentProvisioner = {
  id: "goose",
  sessionClass: "goose-e2e",
  inboundSpec: "goose",
  execTool: "shell",
  // Goose has NO file-read tool: it reads a file with `shell` (`cat`).
  readTool: "shell",
  // A real MCP client: the inspect server runs as its own stdio process
  // (inheriting Goose's env, overlaid with the extension's own variables).
  inspectMount: "mcp",
  // A title-generation call (no tools) runs beside the agentic one.
  sideCallsPerTurn: 1,
  sessionHeader: false,

  resolveBinary() {
    const fromEnv = process.env["MANDU_GOOSE_BIN"];
    if (fromEnv && existsSync(fromEnv)) {
      return { binary: fromEnv, prefixArgs: [], source: "env" };
    }
    if (probeVersion("goose")) {
      return { binary: "goose", prefixArgs: [], source: "path" };
    }
    return undefined;
  },

  provision(input) {
    const env: Record<string, string> = {
      PATH: input.path ?? process.env["PATH"] ?? "",
      HOME: input.agentHome,
      // GOOSE_PATH_ROOT relocates config, data and state together.
      GOOSE_PATH_ROOT: join(input.agentHome, "goose"),
      XDG_CONFIG_HOME: join(input.agentHome, "xdg-config"),
      XDG_DATA_HOME: join(input.agentHome, "xdg-data"),
      XDG_CACHE_HOME: join(input.agentHome, "xdg-cache"),
      XDG_STATE_HOME: join(input.agentHome, "xdg-state"),
      // Secrets from env or secrets.yaml, never the developer's keyring.
      GOOSE_DISABLE_KEYRING: "1",
      GOOSE_PROVIDER: "anthropic",
      GOOSE_MODEL: input.model,
      ANTHROPIC_HOST: input.proxyUrl,
      ANTHROPIC_API_KEY: DUMMY_ANTHROPIC_KEY,
      // A subagent's provider is pinned to the routed one: env outranks a
      // model-written `delegate{provider}` (summon.rs resolve_provider).
      GOOSE_SUBAGENT_PROVIDER: "anthropic",
      // The default, stated: an approval mode would prompt in a one-shot run.
      GOOSE_MODE: "auto",
      // Scenario posture (net-proxy routing), then the upload switches, which
      // nothing overrides.
      ...(input.extraEnv ?? {}),
      ...GOOSE_UPLOADS_OFF_ENV,
    };
    const argv = ["run", "--no-session", "--output-format", "json"];
    if (input.mcp) argv.push("--with-extension", gooseExtensionSpec(input.mcp));
    argv.push("-t", input.prompt);
    return { binary: "goose", argv, env, files: [], unsupported: [] };
  },

  /** `--output-format json` prints a banner, then ONE JSON document
   *  `{messages: [...], metadata: {...}}` (captured on 1.53.0). The reply is
   *  the text of the LAST assistant message that carries any. */
  extractReply(stdout) {
    const doc = parseGooseJson(stdout);
    const msgs = doc && Array.isArray(doc["messages"]) ? doc["messages"] as unknown[] : null;
    if (!msgs) return { text: stdout, extracted: false };
    for (let i = msgs.length - 1; i >= 0; i--) {
      const m = msgs[i];
      if (typeof m !== "object" || m === null) continue;
      const rec = m as Record<string, unknown>;
      if (rec["role"] !== "assistant" || !Array.isArray(rec["content"])) continue;
      const text = (rec["content"] as unknown[])
        .map((c) => (typeof c === "object" && c !== null && (c as Record<string, unknown>)["type"] === "text" ? (c as Record<string, unknown>)["text"] : undefined))
        .filter((t): t is string => typeof t === "string")
        .join("");
      if (text !== "") return { text, extracted: true };
    }
    return { text: stdout, extracted: false };
  },
};

/** The JSON document of `goose run --output-format json`: from the first line
 *  that is exactly `{` (the banner before it is not JSON) to the end. Null when
 *  there is none or it does not parse. Pure; exported for unit tests. */
export function parseGooseJson(stdout: string): Record<string, unknown> | null {
  const lines = stdout.split("\n");
  const start = lines.findIndex((l) => l.trimEnd() === "{");
  if (start < 0) return null;
  try {
    const doc = JSON.parse(lines.slice(start).join("\n")) as unknown;
    return typeof doc === "object" && doc !== null && !Array.isArray(doc) ? doc as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

// ─── OpenClaw ────────────────────────────────────────────────────────────────
//
// npm `openclaw`, or an in-repo source checkout run via `node openclaw.mjs`.
// One-shot mode is `openclaw agent --local`. `--local` is MANDATORY: without it
// the CLI tries the gateway daemon first and only falls back to embedded, which
// is exactly the nondeterminism a harness must not have. Design doc §2.1.

/**
 * The Mandu OpenClaw plugin that mounts the U-LLM `inspect_symbol` tool
 * (interceptors/openclaw-inspect-plugin; design doc §8). OpenClaw has NO MCP
 * client, so the channel ships as a plugin-registered tool instead — same
 * security core, different mount.
 */
export const OPENCLAW_INSPECT_PLUGIN_ID = "mandu-inspect";

/** Absolute path to the plugin package, resolved from this module. */
export function openclawInspectPluginDir(): string {
  // .../tests/lib/ → repo root → interceptors/…
  const here = dirname(fileURLToPath(import.meta.url));
  return join(here, "..", "..", "interceptors", "openclaw-inspect-plugin");
}

export function buildOpenclawConfig(input: ProvisionInput): string {
  // The U-LLM channel arrives through the SAME `mcp` request field the other
  // agents use — OpenClaw just mounts it differently (a plugin, not an MCP
  // server), so the caller's request shape stays agent-agnostic.
  const plugins = input.mcp
    ? {
        plugins: {
          load: { paths: [openclawInspectPluginDir()] },
          entries: {
            [OPENCLAW_INSPECT_PLUGIN_ID]: {
              enabled: true,
              config: {
                arbiterSock: input.mcp.env?.["MANDU_ARBITER_SOCK"] ?? "",
                scopeId: input.mcp.env?.["MANDU_SCOPE_ID"] ?? input.sessionId,
                ullmMode: input.mcp.env?.["MANDU_ULLM_MODE"] ?? "cli",
                ullmBinary: input.mcp.env?.["MANDU_ULLM_BINARY"] ?? "claude",
                // The quarantine's endpoint is read from a DEDICATED key, never
                // the host ANTHROPIC_BASE_URL: inside the gateway that variable
                // is this run's instrumented proxy, and the U-LLM must never
                // re-enter the T-LLM context path.
                ...(input.mcp.env?.["ANTHROPIC_BASE_URL"]
                  ? { ullmBaseUrl: input.mcp.env["ANTHROPIC_BASE_URL"] }
                  : {}),
              },
            },
          },
        },
      }
    : {};
  return (
    JSON.stringify(
      {
        ...plugins,
        agents: {
          defaults: {
            model: { primary: `anthropic/${input.model}` },
            workspace: input.workspace,
          },
        },
        models: {
          // merge (not replace) so the built-in Anthropic model catalog stays
          // and we only override where the requests GO.
          mode: "merge",
          providers: {
            anthropic: {
              baseUrl: input.proxyUrl,
              apiKey: DUMMY_ANTHROPIC_KEY,
              api: "anthropic-messages",
              // ${VAR} config substitution — NOT env-var-NAME indirection. A
              // bare "MANDU_SESSION_ID" arrives on the wire as that literal
              // string (probe-verified the hard way). Values are interpolated
              // here directly since the config is minted per run anyway.
              headers: {
                "x-mandu-session-id": input.sessionId,
                "x-mandu-batch-id": input.batchId,
              },
              models: [],
            },
          },
        },
        tools: {
          profile: "coding",
          // `tools.profile` is an ALLOWLIST applied to the FINAL tool list —
          // core tools and plugin tools alike — and the "coding" profile does
          // not enumerate our plugin's tool, so registering it non-optional is
          // NOT enough: it loads, and is then filtered out before the model
          // ever sees it (probe-verified 2026-08-06 — the plugin logged
          // "inspect_symbol registered" and the request's tools[] did not
          // contain it). `alsoAllow` is OpenClaw's own documented additive
          // escape hatch for exactly this ("Use tools.alsoAllow for additive
          // plugin tool enablement", tool-policy-pipeline.ts), and unlike
          // widening `allow` it does not replace the profile.
          ...(input.mcp ? { alsoAllow: ["inspect_symbol", "declassify_symbol"] } : {}),
          // Defaults are host:"sandbox" + security:"deny", under which the shell
          // tool never runs on the host and every exec scenario silently
          // degrades to "the model declined". Both must be set.
          exec: { host: "gateway", security: "full" },
        },
      },
      null,
      2,
    ) + "\n"
  );
}

export const openclawProvisioner: AgentProvisioner = {
  id: "openclaw",
  sessionClass: "openclaw-e2e",
  // NOT "openclaw" — that id is the LIFTED reference ruleset, which trusts
  // `read` wholesale (safe only under the reference plugin's FS view-sync).
  // See arbiter/policy/openclaw-inbound.ts's header.
  inboundSpec: "openclaw-agent",
  execTool: "exec",
  readTool: "read",
  // NO MCP client at all — the channel mounts as an in-process PLUGIN tool
  // (interceptors/openclaw-inspect-plugin, design doc §8).
  inspectMount: "plugin",
  // Probe-verified: exactly ONE model call per turn — no title-generation side
  // call, unlike Claude Code and OpenCode.
  sideCallsPerTurn: 0,

  resolveBinary() {
    const fromEnv = process.env["MANDU_OPENCLAW_BIN"];
    if (fromEnv && existsSync(fromEnv)) {
      return { binary: fromEnv, prefixArgs: [], source: "env" };
    }
    if (probeVersion("openclaw")) {
      return { binary: "openclaw", prefixArgs: [], source: "path" };
    }
    // Source-checkout fallback — what makes the dev box work with zero install
    // (the checkout is built and carries its own node_modules).
    const src = process.env["MANDU_OPENCLAW_SRC"];
    if (src) {
      const entry = join(src, "openclaw.mjs");
      if (existsSync(entry) && probeVersion("node", [entry])) {
        return { binary: "node", prefixArgs: [entry], source: "source-checkout" };
      }
    }
    return undefined;
  },

  provision(input) {
    const configPath = join(input.agentHome, "openclaw.json");
    const env: Record<string, string> = {
      PATH: input.path ?? process.env["PATH"] ?? "",
      HOME: input.agentHome,
      OPENCLAW_HOME: input.agentHome,
      OPENCLAW_STATE_DIR: join(input.agentHome, "state"),
      OPENCLAW_CONFIG_PATH: configPath,
      // Present so the provider's credential probe is satisfied; the request is
      // authenticated by the config's apiKey either way.
      ANTHROPIC_API_KEY: DUMMY_ANTHROPIC_KEY,
      // Scenario posture (net-proxy routing) wins over the defaults above.
      ...(input.extraEnv ?? {}),
    };

    return {
      binary: "openclaw",
      argv: [
        "agent",
        // MANDATORY — see the module comment above.
        "--local",
        "--agent",
        "main",
        "--session-id",
        input.sessionId,
        "-m",
        input.prompt,
        "--json",
        "--timeout",
        String(Math.max(1, Math.round(input.timeoutMs / 1000))),
      ],
      env,
      files: [{ path: configPath, content: buildOpenclawConfig(input) }],
      // MCP as a PROTOCOL is still unsupported here (ACP explicitly rejects
      // mcpServers), but the CAPABILITY the caller asked for — the U-LLM
      // inspect_symbol channel — IS mounted, as an in-process plugin tool
      // (interceptors/openclaw-inspect-plugin; design doc §8). `inspectMount`
      // is what records the difference. Reporting "mcp" here would make the
      // runner refuse a scenario this agent can now actually run.
      unsupported: [],
    };
  },

  /** `--json` emits ONE JSON document. The reply text lives under a handful of
   *  shapes across versions, so probe them in order and fall back to raw stdout
   *  (an unparseable document must degrade to "the oracle sees the bytes",
   *  never to an empty reply that reads as a model failure). */
  extractReply(stdout) {
    const start = stdout.indexOf("{");
    if (start < 0) return { text: stdout, extracted: false };
    let doc: unknown;
    try {
      doc = JSON.parse(stdout.slice(start));
    } catch {
      return { text: stdout, extracted: false };
    }
    const text = pluckOpenclawText(doc);
    return text !== undefined ? { text, extracted: true } : { text: stdout, extracted: false };
  },
};

/** Keys whose STRING value is the reply itself, probed in order at each level. */
const OPENCLAW_TEXT_KEYS = ["text", "reply", "response", "output"] as const;

/** Keys worth descending into, in PRECEDENCE order.
 *
 *  `payloads` is FIRST and is the shape actually observed on openclaw 2026.3.12
 *  (`{payloads:[{text,mediaUrl}], meta:{…}}` — captured, not guessed). The rest
 *  are defensive alternates for other/older envelopes.
 *
 *  `meta` is DELIBERATELY ABSENT: it carries the run's telemetry (usage,
 *  systemPromptReport, timings) and descending into it would happily return
 *  some unrelated string as "the reply". An allow-list, not a blind walk. */
const OPENCLAW_DESCEND_KEYS = [
  "payloads",
  "message",
  "result",
  "content",
  "messages",
  "assistant",
] as const;

/** Depth-limited search for OpenClaw's reply text across known envelope shapes.
 *  Pure; exported for unit tests, which pin it against a CAPTURED document. */
export function pluckOpenclawText(doc: unknown, depth = 0): string | undefined {
  if (depth > 6 || doc === null || typeof doc !== "object") return undefined;

  if (Array.isArray(doc)) {
    const parts = doc
      .map((d) => (typeof d === "object" && d !== null ? pluckOpenclawText(d, depth + 1) : undefined))
      .filter((s): s is string => typeof s === "string" && s.length > 0);
    return parts.length > 0 ? parts.join("") : undefined;
  }

  const rec = doc as Record<string, unknown>;
  for (const key of OPENCLAW_TEXT_KEYS) {
    const v = rec[key];
    if (typeof v === "string" && v.length > 0) return v;
  }
  for (const key of OPENCLAW_DESCEND_KEYS) {
    if (!(key in rec)) continue;
    const nested = pluckOpenclawText(rec[key], depth + 1);
    if (nested !== undefined) return nested;
  }
  return undefined;
}

// ─── Registry ────────────────────────────────────────────────────────────────

export const PROVISIONERS: Record<Exclude<LiveAgentId, "claude">, AgentProvisioner> = {
  openclaw: openclawProvisioner,
  opencode: opencodeProvisioner,
  goose: gooseProvisioner,
};

/** The skip reason for an unavailable agent, or false when it can run. Mirrors
 *  claude-e2e's SKIP_REASON shape: a precise, actionable string beats a bare
 *  boolean when a suite silently reports 0 tests. */
export function binarySkipReason(p: AgentProvisioner): string | false {
  if (p.resolveBinary()) return false;
  if (p.notFound) return p.notFound;
  if (p.id === "goose") return "`goose` not found — install the release binary (the CI guest pins it, scripts/ci/pins.env), or set MANDU_GOOSE_BIN";
  return p.id === "openclaw"
    ?"`openclaw` not found — install it, or set MANDU_OPENCLAW_BIN / MANDU_OPENCLAW_SRC (a built openclaw source checkout)"
    : "`opencode` not found — `npm i -g opencode-ai`, or set MANDU_OPENCODE_BIN";
}
