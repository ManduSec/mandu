/**
 * parse — argv + env → LaunchPlan.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy):
 *   Adapted from launcher/mandu-run.sh (parse loop L428-451, env defaults
 *   L405-424, target auto-detect L463-476, scope-id default L479-481). Parity
 *   traps preserved: =-only value flags (--exec-wrap=/--mock-sites=),
 *   space-only value flags (--id/--target), MITM⇒net-proxy.
 *   DELIBERATE DIVERGENCE (2026-08-06): the bash default-to-claude on an
 *   unknown argv[0] is gone — inference now recognizes the four known agents
 *   and REFUSES the rest (see types.ts Target for the silent-unprotected hole
 *   the guess opened). A POSIX shell is the one non-agent basename inferred,
 *   as the plain-command `shell` target (2026-09-26).
 */
import { basename } from "node:path";
import { resolveArbiterSock } from "./arbiter-sock.js";
import {
  integrityFrozenMessage, integrityOptedIn, modeOf, parseMode, resolveRequestedAxes, type AxisLevel,
} from "./mode.js";
import { openclawDefaultArgv, openclawLaunchRefusal } from "./openclaw-argv.js";
import { gooseAcpLaunch, gooseDefaultArgv, gooseLaunchRefusal } from "./goose-argv.js";
import { gooseHostOverride } from "./goose-route.js";
import { codexLaunchRefusal } from "./codex-argv.js";
import { sdkHostRefusal } from "./sdk-route.js";
import { scopeIdProblem } from "./runtime-registry.js";
import { resolveLaunchCwd } from "./launch-cwd.js";
import { BROWSER_CDP_ENV, parseBrowserCdp } from "./browser-cdp.js";
import { BROWSER_BOTH_MESSAGE, browserFromEnv } from "./browser-launch.js";
import type { BatchMember, LaunchPlan, Target } from "./types.js";
import { SHELL_BASENAMES, TARGETS, isTarget } from "./types.js";
import { isAgent } from "./generated/agents.js";

type Env = Record<string, string | undefined>;

// Bash parity: `${VAR:-0}` treats a set-but-EMPTY var as "0" (falsy), so an
// explicit `MANDU_NET_PROXY=` must NOT enable the gate. Empty ⇒ unset.
const truthy = (v: string | undefined): boolean => v !== undefined && v !== "" && v !== "0";
const num = (v: string | undefined, d: number): number => (v ? Number(v) : d);

/** The CLI the U-LLM helper (inspect-mcp, OpenClaw's plugin) runs in the
 *  agent's world for `target`: `codex exec` under codex, `claude -p` under
 *  every other target; null in API mode (MANDU_ULLM_API_KEY or
 *  ANTHROPIC_API_KEY set: the helper calls the API itself). The secret walk
 *  leaves that CLI's login raw (secret-discovery.md §1.10); `mandu doctor
 *  --secrets --target` asks the same. Pure. */
export function ullmCliBinary(target: Target, env: Env): "claude" | "codex" | null {
  if (env["MANDU_ULLM_API_KEY"] || env["ANTHROPIC_API_KEY"]) return null;
  return target === "codex" ? "codex" : "claude";
}

/** The historical well-known context-proxy ports. NOT the default any more
 *  (the default is 0, kernel-assigned); kept only as the rendezvous for an
 *  out-of-band proxy (MANDU_NO_CONTEXT_PROXY=1), which has no port file. */
export const WELL_KNOWN_PROXY_PORT = 8788;
export const WELL_KNOWN_OPENAI_PROXY_PORT = 8789;

/** The default --exec-box shadowed set: READ-ONLY data-inspection commands that
 *  need neither network nor writes outside /tmp, so boxing them net-off + RO-root
 *  never breaks them (docs/design/integrity/exec-routing.md §7). */
const DEFAULT_EXEC_BOX_CMDS =
  "cat,grep,egrep,fgrep,sed,awk,cut,sort,uniq,head,tail,wc,tr,jq,find,xargs,comm,join,paste";

/** Parse a comma-separated TCP port list ("8788,443") into numbers. Throws on a
 *  non-numeric / out-of-range token (a loud parse error beats a silent deny-all).
 *  An empty string yields [] (a valid deny-all override for --landlock-net). */
function parsePorts(v: string | undefined, flag = "--landlock-net"): number[] | undefined {
  if (v === undefined) return undefined;
  const out: number[] = [];
  for (const tok of v.split(",").map((s) => s.trim()).filter(Boolean)) {
    const n = Number(tok);
    if (!Number.isInteger(n) || n < 1 || n > 65535) {
      throw new Error(`mandu: ${flag} port must be 1..65535, got '${tok}'`);
    }
    out.push(n);
  }
  return out;
}

/** Parse a `--net-allow` / MANDU_NET_ALLOW comma-separated spec list into the
 *  trimmed, non-empty specs (each `[proto:]host:port`). Returns undefined when
 *  unset so the connect-guard uses its default (permissive) allow-set; an EMPTY
 *  value (`--net-allow=`) yields `[]` = curated-but-empty (loopback + DNS + API
 *  host only). Spec syntax is validated by the guard bin (net-supervisor). */
function parseAllowList(v: string | undefined): string[] | undefined {
  if (v === undefined) return undefined;
  return v.split(",").map((s) => s.trim()).filter(Boolean);
}

// SHELL_BASENAMES lives in types.ts (codex-argv.ts reads it too); re-exported.
export { SHELL_BASENAMES };

/** Launcher flags that consume the FOLLOWING token as their value (space form).
 *  Everything else is boolean or `--flag=value`. Shared by the opt loop and
 *  commandStart so the two agree on where the agent argv begins. */
const SPACE_VALUE_FLAGS = new Set(["--id", "--target", "--tenant", "--mode"]);

/**
 * Index in `args` where the agent argv begins in the BARE form (`mandu claude
 * …`, no `--`): the first token that is not a launcher flag and not a flag's
 * space-form value. Returns args.length when every token is a flag. The `--`
 * form is handled separately (everything after `--` is the agent argv verbatim).
 */
export function commandStart(args: string[]): number {
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (a === "--") return i + 1;
    if (a.startsWith("-")) {
      if (SPACE_VALUE_FLAGS.has(a)) i++; // skip its value
      continue;
    }
    return i; // first bare token → the agent command
  }
  return args.length;
}

const BATCH_MEMBER_RE = /^(scenario|posture):([A-Za-z0-9][A-Za-z0-9@#._-]{0,79})$/;

/** MANDU_BATCH_MEMBER (`scenario:<key>` / `posture:<key>`, the watch
 *  runner's) as the plan's `batchMember`; anything else is undefined.
 *  Observability only: a bad value costs the badge, never the launch. */
export function batchMemberOf(raw: string | undefined): BatchMember | undefined {
  const m = raw ? BATCH_MEMBER_RE.exec(raw) : null;
  return m ? { kind: m[1] as BatchMember["kind"], key: m[2]! } : undefined;
}

/**
 * `launchDir` is the directory the launch is for; by default the real cwd,
 * spelled as `$PWD` only when PWD names that same directory (launch-cwd.ts).
 * An in-process caller (the launcher's own tests) may pass it.
 */
export function parse(args: string[], env: Env, launchDir?: string): LaunchPlan {
  // Two accepted forms (packaging.md §1):
  //   - explicit:  mandu [flags] -- <command…>   (everything after `--` verbatim)
  //   - bare:      mandu [flags] <command…>       (first non-flag token starts it)
  // `--` stays supported for disambiguation (e.g. launching a program whose name
  // collides with a launcher flag or a management subcommand).
  const sep = args.indexOf("--");
  const cut = sep >= 0 ? sep : commandStart(args);
  const opts = args.slice(0, cut);
  let argv: string[] = sep >= 0 ? args.slice(sep + 1) : args.slice(cut);
  if (argv.length === 0) {
    throw new Error("mandu: no command given (e.g. `mandu claude` or `mandu -- <command>`)");
  }

  // net-proxy / exec-wrap are tri-state, DEFAULT-ON (the non-root principle:
  // an available unprivileged hardening left off is a gap, not a choice).
  // Mirrors fsSync: unset/empty env ⇒ undefined (auto — on, degrade on
  // failure); env=1 / flag ⇒ true (explicit — fail closed); env=0 /
  // --no-<flag> ⇒ false (opt out).
  const tri = (v: string | undefined): boolean | undefined =>
    v === undefined || v === "" ? undefined : truthy(v);
  const req = {
    netProxy: tri(env["MANDU_NET_PROXY"]),
    netProxyMitm: tri(env["MANDU_NET_PROXY_MITM"]),
    execWrap: tri(env["MANDU_EXEC_WRAP"]),
  };
  // fs-preload was RETIRED 2026-07-14, in every posture (with or without
  // --no-kernel): LD_PRELOAD interposition is cooperative-only — strippable from
  // the child env, blind to static binaries — so it never was a boundary, and the
  // FS chokepoint it stood in for is covered by fs-sync plus the default-on
  // kernel-tier rungs (exec-box AgentView boxing, Landlock). A request must still
  // fail closed, not be silently ignored (spec §5):
  const fsPreloadRetired = (src: string): never => {
    throw new Error(
      `mandu: ${src}: fs-preload was retired — the FS chokepoint is fs-sync + the kernel-tier rungs (exec-box, Landlock)`,
    );
  };
  if (truthy(env["MANDU_FS_PRELOAD"])) fsPreloadRetired("MANDU_FS_PRELOAD");
  // --unshare / --unshare-net were RETIRED 2026-07-14 with fs-preload, for the
  // same shape of reason: they were enabler modes, not boundaries. The bare
  // user+mount userns attached nothing by itself (the bwrap rungs — exec-box,
  // secret-twins — create their namespaces per use), and the empty-netns +
  // slirp4netns relay is superseded by the default-on landlock-net + net-guard
  // egress rungs. A dedicated netns rung, if ever wanted, is a new co-designed
  // feature, not this flag. Same fail-closed contract: a request errors loudly.
  const unshareRetired = (src: string): never => {
    throw new Error(
      `mandu: ${src}: unshare was retired — namespaces ship via the bwrap rungs (exec-box, secret-twins), egress via landlock-net + net-guard`,
    );
  };
  if (truthy(env["MANDU_UNSHARE"])) unshareRetired("MANDU_UNSHARE");
  if (truthy(env["MANDU_UNSHARE_NET"])) unshareRetired("MANDU_UNSHARE_NET");
  let target: Target | "" = "";
  let scopeId = env["MANDU_SCOPE_ID"] ?? "";
  // Tenant (policy-surface.md §2.7): env default, flag overrides;
  // validated below — an unknown value is a usage error, never a silent "live".
  let tenantRaw = env["MANDU_TENANT"] ?? "";
  let writeMcp = true;
  // Default ON: only an explicit 0/false/off drops the policy MCP server.
  let writePolicyMcp = !["0", "false", "off", "no"].includes((env["MANDU_POLICY_MCP"] ?? "").toLowerCase());
  let noScope = false;
  let bestEffort = false;
  let requireConfinement = truthy(env["MANDU_REQUIRE_CONFINEMENT"]);
  // Default ON: only an explicit 0/false/off turns the env-var mask off.
  let envSecrets = !["0", "false", "off", "no"].includes((env["MANDU_ENV_SECRETS"] ?? "").toLowerCase());
  // Default ON (bind where possible): only an explicit 0/false/off drops the bind.
  let secretBind: boolean | undefined = ["0", "false", "off", "no"].includes((env["MANDU_SECRET_BIND"] ?? "").toLowerCase()) ? false : undefined;
  const askRaw = (env["MANDU_SECRETS_ASK"] ?? "").toLowerCase();
  let secretsAsk: "known" | "always" | "never" | undefined =
    askRaw === "always" || askRaw === "never" || askRaw === "known" ? askRaw : undefined;
  let verbose = truthy(env["MANDU_VERBOSE"]);
  let execWrapCmds = (env["MANDU_EXEC_WRAP_CMDS"] ?? "curl,wget,nc").split(",");
  let mockSitesPath = env["MANDU_NET_PROXY_MOCK_SITES"] || undefined;
  // The DevTools relay (browser-cdp.ts): Chrome's debugging endpoint.
  let browserCdp = env[BROWSER_CDP_ENV] ? parseBrowserCdp(env[BROWSER_CDP_ENV]) : undefined;
  // A Chrome Mandu starts itself (browser-launch.ts), the relay in front.
  let browser = browserFromEnv(env);
  // fs-sync tri-state: unset/empty env ⇒ undefined (auto: on for git repos).
  let fsSync: boolean | undefined =
    env["MANDU_FS_SYNC"] === undefined || env["MANDU_FS_SYNC"] === ""
      ? undefined
      : truthy(env["MANDU_FS_SYNC"]);
  // Eager tool-call-boundary sync (fs-sync.md §2.8 Phase 2): default ON;
  // MANDU_FS_SYNC_EAGER=0 / --no-fs-sync-eager opt out. Unset/empty env ⇒ on.
  let fsSyncEager =
    env["MANDU_FS_SYNC_EAGER"] === undefined || env["MANDU_FS_SYNC_EAGER"] === ""
      ? true
      : truthy(env["MANDU_FS_SYNC_EAGER"]);
  // User-reply egress filter (packaging.md §5): default ON. Bash parity
  // (mandu-run.sh `${MANDU_REPLY_FILTER:-1}` == "1"): unset/empty ⇒ on; only
  // the exact string "1" keeps it on, anything else opts out.
  let replyFilter =
    env["MANDU_REPLY_FILTER"] === undefined || env["MANDU_REPLY_FILTER"] === ""
      ? true
      : env["MANDU_REPLY_FILTER"] === "1";
  // `goose acp`'s JSON-aware display pass (set below for that shape only).
  let acpDisplay: boolean | undefined;
  // Protection mode + the two axes (protection-modes.md §3.2, mode.ts). Two
  // LEVELS are tracked here: what the env says (config.toml is already folded
  // into it by applyConfigDefaults, below the user's own exports) and what the
  // flags say. Inside a level an explicit axis beats that level's mode for
  // that axis only; the flag level beats the env level per axis. Tri-state
  // throughout: an axis nobody names stays undefined = "leave it to the
  // arbiter" (a running arbiter's posture stands; a cold start runs the
  // built-in default mode).
  const triAxis = (v: string | undefined): boolean | undefined =>
    v === undefined || v === "" ? undefined : truthy(v);
  const envLevel: AxisLevel = {
    mode: parseMode(env["MANDU_MODE"], "MANDU_MODE (or `mode` in config.toml)"),
    confidentiality: triAxis(env["MANDU_CONFIDENTIALITY"]),
    integrity: triAxis(env["MANDU_INTEGRITY"]),
  };
  const flagLevel: AxisLevel = {};
  // Whole-agent TCP port-allow wrap (exec-routing.md §7): tri-state, ON by
  // default (kernel-tier non-root hardening; the wrap itself degrades on a
  // pre-6.7 kernel / missing bin). landlockNetStrict implies it.
  let landlockNet = tri(env["MANDU_LANDLOCK_NET"]);
  let landlockNetStrict = truthy(env["MANDU_LANDLOCK_NET_STRICT"]);
  let landlockNetPorts = parsePorts(env["MANDU_LANDLOCK_NET_PORTS"]);
  // Ports the agent may LISTEN on under the wrap (exec-routing.md §7.1 bind
  // allowance) — a local TUI server / gateway; undefined = none.
  let landlockNetBind = parsePorts(env["MANDU_LANDLOCK_NET_BIND"], "--landlock-net-bind");
  // Box a curated read-only command set (exec-routing.md §7): tri-state, ON by
  // default, mirroring --exec-wrap's cmds handling; degrades without bwrap/userns.
  let execBox = tri(env["MANDU_EXEC_BOX"]);
  let execBoxCmds = (env["MANDU_EXEC_BOX_CMDS"] ?? DEFAULT_EXEC_BOX_CMDS).split(",");
  // The clean-box posture for boxed commands (exec-routing.md §8.5): tri-state,
  // ON by default since 2026-09-04 (rides exec-box; moot when exec-box is off).
  let execCleanBox = tri(env["MANDU_EXEC_CLEAN_BOX"]);
  // Whole-agent IP/domain-aware connect-guard (exec-routing.md §7.5): tri-state,
  // ON by default (non-root principle), the IP-aware companion to landlock-net.
  // Degrades to no guard when the bin/seccomp is missing. --net-allow curates.
  let netGuard = tri(env["MANDU_NET_GUARD"]);
  let netGuardAllow = parseAllowList(env["MANDU_NET_ALLOW"]);
  // Auto-include the workspace git-remote hosts when the guard is narrowed
  // (strict/curated). Tri-state, default-on; MANDU_NET_GUARD_GIT=0 opts out.
  let netGuardGitRemotes = tri(env["MANDU_NET_GUARD_GIT"]);
  // Codex's own command sandbox network (codex-shell-network.ts,
  // supported-agents.md §6.5): tri-state, default-on where Mandu's guard runs;
  // MANDU_CODEX_SHELL_NETWORK=0 / --no-codex-shell-network keeps Codex's default.
  let codexShellNetwork = tri(env["MANDU_CODEX_SHELL_NETWORK"]);

  // Umbrella kernel-tier opt-out (--no-kernel / --portable / MANDU_NO_KERNEL):
  // drop every rung that needs a kernel LSM / namespace in ONE switch, keeping the
  // full userspace cooperative defense (context proxy + fs-sync + net-proxy +
  // exec-wrap + reply-filter — the §9 IPI invariant is unaffected). The launcher
  // already AUTO-degrades these where the kernel lacks them; this is the explicit,
  // discoverable knob to force the portable posture even where they'd work (or to
  // say so up front instead of relying on silent degrade). As an ENV default it is
  // overridable by an explicit per-rung flag in the loop below (env < flag); as a
  // FLAG it is authoritative at its position (sequential-wins, like every rung).
  const dropKernelRungs = (): void => {
    execBox = false;
    execCleanBox = false;
    landlockNet = false;
    landlockNetStrict = false;
    netGuard = false;
  };
  if (truthy(env["MANDU_NO_KERNEL"])) dropKernelRungs();

  const valueOf = (tok: string): string => tok.slice(tok.indexOf("=") + 1);

  for (let i = 0; i < opts.length; i++) {
    const a = opts[i]!;
    if (a === "--id") { scopeId = opts[++i] ?? ""; continue; }
    if (a === "--tenant") { tenantRaw = opts[++i] ?? ""; continue; }
    if (a.startsWith("--tenant=")) { tenantRaw = valueOf(a); continue; }
    if (a === "--no-scope") { noScope = true; continue; }
    if (a === "--no-mcp") { writeMcp = false; continue; }
    if (a === "--no-policy-mcp") { writePolicyMcp = false; continue; }
    if (a === "--best-effort") { bestEffort = true; continue; }
    if (a === "--require-confinement") { requireConfinement = true; continue; }
    if (a === "--no-require-confinement") { requireConfinement = false; continue; }
    if (a === "--env-secrets") { envSecrets = true; continue; }
    if (a === "--no-env-secrets") { envSecrets = false; continue; }
    if (a === "--secret-bind") { secretBind = undefined; continue; }
    if (a === "--no-secret-bind") { secretBind = false; continue; }
    if (a.startsWith("--secrets-ask=")) {
      const v = valueOf(a);
      if (v !== "known" && v !== "always" && v !== "never") throw new Error(`mandu: --secrets-ask must be known, always or never (got ${JSON.stringify(v)})`);
      secretsAsk = v; continue;
    }
    if (a === "--verbose") { verbose = true; continue; }
    if (a === "--target") {
      const t = opts[++i];
      if (!isTarget(t)) {
        throw new Error(`mandu: invalid --target '${t}' (want ${TARGETS.join("|")})`);
      }
      target = t; continue;
    }
    if (a === "--unshare" || a === "--unshare-net") unshareRetired(a);
    if (a === "--fs-preload" || a.startsWith("--fs-preload=")) fsPreloadRetired(a);
    if (a === "--net-proxy") { req.netProxy = true; continue; }
    if (a === "--no-net-proxy") { req.netProxy = false; continue; }
    if (a === "--net-proxy-mitm") { req.netProxy = true; req.netProxyMitm = true; continue; }
    if (a === "--no-net-proxy-mitm") { req.netProxyMitm = false; continue; }
    if (a.startsWith("--mock-sites=")) { req.netProxy = true; mockSitesPath = valueOf(a); continue; }
    if (a === "--browser-cdp") { browserCdp = parseBrowserCdp(opts[++i] ?? ""); continue; }
    if (a.startsWith("--browser-cdp=")) { browserCdp = parseBrowserCdp(valueOf(a)); continue; }
    if (a === "--browser") { browser = true; continue; }
    if (a === "--exec-wrap") { req.execWrap = true; continue; }
    if (a === "--no-exec-wrap") { req.execWrap = false; continue; }
    if (a.startsWith("--exec-wrap=")) {
      req.execWrap = true;
      execWrapCmds = valueOf(a).split(",");
      continue;
    }
    if (a === "--fs-sync") { fsSync = true; continue; }
    if (a === "--no-fs-sync") { fsSync = false; continue; }
    if (a === "--fs-sync-eager") { fsSyncEager = true; continue; }
    if (a === "--no-fs-sync-eager") { fsSyncEager = false; continue; }
    if (a === "--reply-filter") { replyFilter = true; continue; }
    if (a === "--no-reply-filter") { replyFilter = false; continue; }
    if (a === "--mode") { flagLevel.mode = parseMode(opts[++i] ?? "", "--mode") ?? missingMode(); continue; }
    if (a.startsWith("--mode=")) { flagLevel.mode = parseMode(valueOf(a), "--mode") ?? missingMode(); continue; }
    if (a === "--confidentiality") { flagLevel.confidentiality = true; continue; }
    if (a === "--no-confidentiality") { flagLevel.confidentiality = false; continue; }
    if (a === "--integrity") { flagLevel.integrity = true; continue; }
    if (a === "--no-integrity") { flagLevel.integrity = false; continue; }
    if (a === "--landlock-net") { landlockNet = true; continue; }
    if (a === "--no-landlock-net") { landlockNet = false; continue; }
    if (a.startsWith("--landlock-net=")) { landlockNet = true; landlockNetPorts = parsePorts(valueOf(a)); continue; }
    if (a === "--landlock-net-strict") { landlockNet = true; landlockNetStrict = true; continue; }
    if (a.startsWith("--landlock-net-bind=")) { landlockNet = true; landlockNetBind = parsePorts(valueOf(a), "--landlock-net-bind"); continue; }
    if (a === "--exec-box") { execBox = true; continue; }
    if (a === "--no-exec-box") { execBox = false; continue; }
    if (a.startsWith("--exec-box=")) { execBox = true; execBoxCmds = valueOf(a).split(","); continue; }
    if (a === "--exec-clean-box") { execCleanBox = true; continue; }
    if (a === "--no-exec-clean-box") { execCleanBox = false; continue; }
    if (a === "--net-guard") { netGuard = true; continue; }
    if (a === "--no-net-guard") { netGuard = false; continue; }
    if (a.startsWith("--net-allow=")) { netGuard = true; netGuardAllow = parseAllowList(valueOf(a)); continue; }
    if (a === "--net-guard-git") { netGuardGitRemotes = true; continue; }
    if (a === "--no-net-guard-git") { netGuardGitRemotes = false; continue; }
    if (a === "--codex-shell-network") { codexShellNetwork = true; continue; }
    if (a === "--no-codex-shell-network") { codexShellNetwork = false; continue; }
    if (a === "--no-kernel" || a === "--portable") { dropKernelRungs(); continue; }
    throw new Error(`mandu: unknown option '${a}' (did you forget '--' before the command?)`);
  }
  // Post-parse implication (parity: mandu-run.sh L458-461).
  if (req.netProxyMitm) req.netProxy = true;
  const { integrity, confidentiality } = resolveRequestedAxes([flagLevel, envLevel]);
  // The integrity axis is frozen (docs/design/architecture/protection-modes.md §10): a launch
  // that ASKS for it without the opt-in is refused, never quietly downgraded.
  if (integrity === true && !integrityOptedIn(env)) {
    const source = flagLevel.integrity !== undefined || flagLevel.mode !== undefined
      ? "this launch's flags" : "MANDU_MODE / MANDU_INTEGRITY or config.toml";
    throw new Error(integrityFrozenMessage(source));
  }
  // Integrity OFF forces fs-sync OFF: the AgentView twin exists to route
  // UNTRUSTED file content around the model, which is exactly the machinery
  // the integrity axis switches. Kernel-hardening rungs stay (threat-neutral).
  // (run.ts repeats this against the EFFECTIVE axes once the arbiter answers:
  // an unflagged launch that joins or cold-starts an integrity-OFF arbiter
  // must not run the twin either.)
  if (integrity === false) fsSync = false;
  // …and say so: the mode, not the user, turned it off (manager.ts reports an
  // informational note instead of the --no-fs-sync DEGRADED warning).
  const fsSyncOffReason: "mode" | undefined = integrity === false ? "mode" : undefined;

  if (target === "") {
    // Infer ONLY from a basename that names a known agent; REFUSE anything
    // else instead of guessing "claude". The guess was a silent-unprotected
    // hole (types.ts Target): a target whose routing delivery does not match
    // the real agent launches every rung and defends nothing — openclaw and
    // opencode ignore ANTHROPIC_BASE_URL entirely (config-file routed), so a
    // "claude" guess for them produced a protected-looking session with no
    // tool_result ever symbolized. Loud refusal beats that in every case; a
    // wrapper script whose name hides the agent passes --target explicitly.
    // A POSIX shell is the one non-agent shape inferred (agent-e2e-harness.md
    // §9.1): `mandu -- bash` is what the help promises, a shell is plainly
    // not an agent binary, and the `shell` target's launch note names every
    // agent its env routing does not reach, so nothing about it is silent.
    const base = basename(argv[0]!);
    if (isAgent(base)) {
      target = base;
    } else if (base === "opencode2") {
      // OpenCode 2's own command: inferred as opencode, so it launches as
      // OpenCode 2, or is refused with the reason (agent-versions.ts
      // opencodeLaunchRefusal), never with "cannot infer".
      target = "opencode";
    } else if (SHELL_BASENAMES.has(base)) {
      target = "shell";
    } else {
      throw new Error(
        `mandu: cannot infer the target agent from '${argv[0]}' — pass --target claude|codex|openclaw|opencode|goose, ` +
        `or --target shell to run it as a plain command (env routing only, no agent-specific wiring). ` +
        `The target decides the wire (anthropic-proxy vs openai-proxy) and how routing reaches the agent ` +
        `(env for claude and goose, -c overrides for codex, a generated config file for openclaw/opencode); ` +
        `a wrong guess launches the whole stack while the agent talks to the real endpoint unprotected.`,
      );
    }
  }
  if (target === "openclaw") {
    // Bare `mandu openclaw` means the coding agent: `openclaw chat`
    // (openclaw-argv.ts openclawDefaultArgv).
    argv = [...openclawDefaultArgv(argv)];
    // Only the confined OpenClaw shapes launch (an allowlist): a Gateway
    // client, the Gateway service, Crestodian, … run the agent loop outside
    // this confinement or outside Mandu's routing (openclaw-argv.ts).
    const refusal = openclawLaunchRefusal(argv, env);
    if (refusal) throw new Error(refusal);
  }
  if (target === "goose") {
    // Bare `mandu goose` means the agent: `goose session` (goose-argv.ts
    // gooseDefaultArgv), not the `configure` setup bare Goose falls back to.
    argv = [...gooseDefaultArgv(argv)];
    // Only the shapes whose agent loop runs here launch (an allowlist):
    // `serve`, `gateway`, `--container`, sub-recipes, code mode and the
    // management subcommands are refused (goose-argv.ts); a recipe is read
    // at launch (run.ts, goose-recipe.ts).
    const refusal = gooseLaunchRefusal(argv);
    if (refusal) throw new Error(refusal);
    // `goose acp` speaks JSON-RPC to an editor on stdout: the launcher relays
    // that stream itself (goose-acp-relay.ts), and the reply filter, whose
    // line rewriting would break the framing, stays off. The relay's own
    // JSON-aware pass (goose-acp-display.ts) shows the editor originals in
    // its place, unless the reply filter was turned off.
    if (gooseAcpLaunch(argv)) {
      acpDisplay = replyFilter;
      replyFilter = false;
    }
  }
  if (target === "codex") {
    // A user -c that re-points the model provider (or --oss) would send the
    // model traffic around the openai-proxy (codex-argv.ts): refuse.
    const refusal = codexLaunchRefusal(argv);
    if (refusal) throw new Error(refusal);
    // A host program the SDK route cannot reach (a Bun or Deno host, a
    // Python started with -I/-E/-S): its codex would run unrouted
    // (agent-sdks.md §3, sdk-route.ts sdkHostRefusal).
    const hostRefusal = sdkHostRefusal({ target, argv });
    if (hostRefusal) throw new Error(hostRefusal);
  }
  const scopeIdGenerated = scopeId === "";
  if (scopeIdGenerated) {
    scopeId = `${Math.floor(dateNow() / 1000)}-${process.pid}`;
  } else {
    // The scope's dir is `<runtime base>/<id>`: one folder name, and never one
    // of Mandu's own entries there (runtime-registry.ts). `--id instances`
    // would put this launch's files in the arbiter's instance registry, and
    // the macOS profile could not deny the agent that registry.
    const why = scopeIdProblem(scopeId);
    if (why !== null) {
      throw new Error(
        `mandu: --id / MANDU_SCOPE_ID ${JSON.stringify(scopeId)} cannot name a session: ${why}. ` +
          "Pick another name, or leave it unset for a fresh one (runtime-instances.md §2).",
      );
    }
  }
  if (tenantRaw !== "" && tenantRaw !== "live" && tenantRaw !== "test") {
    throw new Error(
      `--tenant / MANDU_TENANT must be "live" or "test" (got ${JSON.stringify(tenantRaw)}). ` +
        `"test" marks e2e suites, harnesses and dev rigs so their sessions never mix with a human's live runs.`,
    );
  }
  const tenant: "live" | "test" = tenantRaw === "test" ? "test" : "live";
  // Claude renderer pin (types.ts claudeTuiPin): OFF by default since
  // 2026-09-19 — the reply-filter resolves the fullscreen renderer
  // (differential-interactive.md §19); MANDU_CLAUDE_TUI_PIN=1 re-pins inline.
  const claudeTuiPin = env["MANDU_CLAUDE_TUI_PIN"] === "1";

  // Rendezvous resolution (runtime-instances.md §3): env-pinned → promoted
  // `current` → legacy fixed path → the `current` spelling the instance-mode
  // autostart is about to create. The mode rides in the plan so run.ts knows
  // whether to start the arbiter pinned or in instance mode (+promote).
  const {
    sock: arbiterSock,
    mode: arbiterSockMode,
    base: arbiterRuntimeBase,
  } = resolveArbiterSock(env);
  // The scope run dir sits in the runtime base, the path table's
  // `runtime-dir` (on-disk-layout.md §5), so MANDU_RUNTIME_DIR moves it with
  // the instances and `mandu reap` finds it there. A TMPDIR too long for an
  // instance socket (macOS) makes that base the private /tmp/mandu-<uid>
  // (runtime-base.ts, runtime-instances.md §3b).
  // The per-launch (pinned) arbiter writes its events here, told by the
  // `--event-dir` flag (on-disk-layout.md §5); a resident arbiter keeps the
  // home's own `events/`.
  const scopeRunDir = `${arbiterRuntimeBase}/${scopeId}`;
  const eventDir = `${scopeRunDir}/events`;

  // Context-proxy ports (runtime-instances.md §8, release checklist a1): the
  // built-in default is 0 = kernel-assigned, published back via the port file,
  // so a second user or a resident stack on the same host can never collide
  // with this launch (the fixed 8788/8789 made the second launch REFUSE on a
  // foreign proxy). A pinned MANDU_PROXY_PORT / config `proxy-port` still
  // wins. The one exception is an OUT-OF-BAND proxy (MANDU_NO_CONTEXT_PROXY=1):
  // it has no port file to rendezvous through, so an unpinned launch keeps the
  // historical well-known ports 8788/8789 as that rendezvous.
  const noContextProxy = truthy(env["MANDU_NO_CONTEXT_PROXY"]);
  const proxyPortDefault = noContextProxy ? WELL_KNOWN_PROXY_PORT : 0;
  const openaiProxyPortDefault = noContextProxy ? WELL_KNOWN_OPENAI_PROXY_PORT : 0;
  // An EXPLICIT port 0 with an out-of-band proxy has no rendezvous at all —
  // the composed base URL would point at :0. Refuse up front (fail-closed)
  // instead of launching an agent whose model calls can never connect.
  if (
    noContextProxy &&
    (num(env["MANDU_PROXY_PORT"], proxyPortDefault) === 0 ||
      num(env["MANDU_OPENAI_PROXY_PORT"], openaiProxyPortDefault) === 0)
  ) {
    throw new Error(
      "mandu: MANDU_PROXY_PORT=0 (ephemeral) requires the launcher-started context proxy — " +
      "it cannot rendezvous with an out-of-band proxy. Unset MANDU_NO_CONTEXT_PROXY or pin a port.",
    );
  }

  const dir = launchDir ?? resolveLaunchCwd(env["PWD"]);
  if (browser && browserCdp !== undefined) throw new Error(BROWSER_BOTH_MESSAGE);

  const ullmKey = env["MANDU_ULLM_API_KEY"] || env["ANTHROPIC_API_KEY"] || "";
  const ullmMode: "api" | "cli" = ullmKey ? "api" : "cli";
  const ullm = {
    mode: ullmMode,
    baseUrl: env["MANDU_ULLM_BASE_URL"] || "https://api.anthropic.com",
    ...(ullmMode === "api" ? { apiKey: ullmKey } : { binary: ullmCliBinary(target, env)! }),
    ...(ullmMode === "cli" && target === "codex" && env["CODEX_HOME"] ? { codexHome: env["CODEX_HOME"] } : {}),
    ...(ullmMode === "cli" && target === "codex" && (env["MANDU_ULLM_OPENAI_UPSTREAM"] || env["MANDU_ULLM_CHATGPT_UPSTREAM"])
      ? { codexUpstreams: {
          api: env["MANDU_ULLM_OPENAI_UPSTREAM"] || "https://api.openai.com",
          chatgpt: env["MANDU_ULLM_CHATGPT_UPSTREAM"] || "https://chatgpt.com/backend-api/codex",
        } }
      : {}),
    ...(env["MANDU_ULLM_MODEL"] ? { model: env["MANDU_ULLM_MODEL"] } : {}),
  };

  return {
    target,
    argv,
    scopeId,
    scopeIdGenerated,
    // Observability batch grouping: the e2e suites / CI export MANDU_BATCH_ID
    // so every session one process launches renders as ONE dashboard batch.
    ...(env["MANDU_BATCH_ID"] ? { batchId: env["MANDU_BATCH_ID"] } : {}),
    // …and what this session is within it (the watch runner's scenario or
    // posture group); a malformed value is dropped, never an error
    ...(batchMemberOf(env["MANDU_BATCH_MEMBER"]) ? { batchMember: batchMemberOf(env["MANDU_BATCH_MEMBER"])! } : {}),
    tenant,
    claudeTuiPin,
    arbiterSock,
    arbiterSockMode,
    arbiterRuntimeBase,
    eventDir,
    // The REAL working directory, never a PWD that names another one (a
    // script's chdir without exporting PWD; packaging.md §1).
    cwd: dir,
    humanCwd: dir,
    basePath: env["PATH"] ?? "",
    proxy: { host: env["MANDU_PROXY_HOST"] || "127.0.0.1", port: num(env["MANDU_PROXY_PORT"], proxyPortDefault) },
    openaiProxy: {
      host: env["MANDU_OPENAI_PROXY_HOST"] || "127.0.0.1",
      port: num(env["MANDU_OPENAI_PROXY_PORT"], openaiProxyPortDefault),
    },
    openaiProviderName: env["MANDU_OPENAI_PROVIDER_NAME"] || "mandu",
    // The env var the routed provider reads its key from. Codex itself takes
    // CODEX_API_KEY (and, since 0.154, ignores a bare OPENAI_API_KEY without
    // `codex login`); a custom provider reads only its env_key. Name the one
    // the user set, so a CODEX_API_KEY-only user is not refused by Codex with
    // "Missing environment variable: OPENAI_API_KEY".
    openaiEnvKey: !env["OPENAI_API_KEY"] && env["CODEX_API_KEY"] ? "CODEX_API_KEY" : "OPENAI_API_KEY",
    // Neither key variable: Codex authenticates with its own `codex login`
    // (a ChatGPT sign-in or a saved key), relayed by the openai-proxy
    // (agent-sign-in.md §2.4). The same "set" test as the doctor's
    // (agent-login.ts): a blank value is no key.
    codexAuth: (env["OPENAI_API_KEY"] ?? "").trim() !== "" || (env["CODEX_API_KEY"] ?? "").trim() !== "" ? "key" : "sign-in",
    // The agent's own base-URL knob: ANTHROPIC_HOST for Goose (it ignores
    // ANTHROPIC_BASE_URL; goose-route.ts), whose value naming the official
    // endpoint is Goose's default, not an override.
    anthropicBaseUrl: (target === "goose" ? gooseHostOverride(env["ANTHROPIC_HOST"]) : env["ANTHROPIC_BASE_URL"]) || undefined,
    openaiBaseUrl: env["MANDU_OPENAI_BASE_URL"] || undefined,
    noProxyExtra: (env["MANDU_MODEL_HOSTS"] || "").split(",").filter(Boolean),
    requested: req,
    execWrapCmds: execWrapCmds.map((c) => c.trim()).filter(Boolean),
    landlockNet,
    landlockNetPorts,
    landlockNetStrict,
    ...(landlockNetBind !== undefined ? { landlockNetBind } : {}),
    execBox,
    execBoxCmds: execBoxCmds.map((c) => c.trim()).filter(Boolean),
    execCleanBox,
    netGuard,
    ...(netGuardAllow !== undefined ? { netGuardAllow } : {}),
    ...(netGuardGitRemotes !== undefined ? { netGuardGitRemotes } : {}),
    ...(codexShellNetwork !== undefined ? { codexShellNetwork } : {}),
    ullm,
    mockSitesPath,
    ...(browserCdp !== undefined ? { browserCdp } : {}),
    ...(browser ? { browser: true } : {}),
    noScope,
    writeMcp,
    ...(writePolicyMcp ? {} : { writePolicyMcp: false }),
    bestEffort,
    ...(requireConfinement ? { requireConfinement: true } : {}),
    ...(envSecrets ? {} : { envSecrets: false }),
    ...(secretsAsk ? { secretsAsk } : {}),
    ...(secretBind === false ? { secretBind } : {}),
    verbose,
    replyFilter,
    ...(acpDisplay !== undefined ? { acpDisplay } : {}),
    ...(integrity !== undefined && confidentiality !== undefined
      ? { mode: modeOf({ integrity, confidentiality }) }
      : {}),
    confidentiality,
    integrity,
    fsSync,
    ...(fsSyncOffReason ? { fsSyncOffReason } : {}),
    fsSyncEager,
    noContextProxy,
  };
}

function missingMode(): never {
  throw new Error("mandu: --mode needs a value (secrets|injection|full|off)");
}

// Isolated for testability / to satisfy the workflow no-Date rule in scripts;
// in the CLI this is just Date.now().
function dateNow(): number {
  return Date.now();
}
