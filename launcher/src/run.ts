#!/usr/bin/env tsx
/**
 * run — the `mandu` CLI entry: parse → ensure arbiter → run backends → spawn.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy):
 *   NEW Mandu code. The TS entry point replacing launcher/mandu-run.sh's
 *   main flow (spec §4 launch data flow). Part 1 wires coop-env only; Part 2
 *   registers the kernel-layer backends + service autostart.
 */
import { homedir } from "node:os";
import { manduPath } from "./generated/mandu-paths.js";
import { join, resolve } from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, realpathSync, rmSync } from "node:fs";
import { parse, commandStart } from "./parse.js";
import { dashboardUrl, liveDashboards, liveLaunchersOn, RESERVED_SUBCOMMANDS, residentPidsOn, runSubcommand, stopStackAndWait } from "./subcommands.js";
import { stackSupervisor, withStackFacts } from "./stack-supervisor.js";
import { applyReplyFilter, handOffReplyFilter, prestartReplyFilter, ReplyFilterSlot, wantsPrestart, type ReplyFilterHandoff, type ReplyFilterWiring } from "./reply-filter.js";
import { applyConfigDefaults } from "./config.js";
import { getPlatform } from "./platform/index.js";
import { coopEnv } from "./backend/coop-env.js";
import { isClaudeBinary, nodeTakesDisableWarning, withNodeOption } from "./env-compose.js";
import { nodeEnvProxyGap, nodeEnvProxyNotice } from "./node-floor.js";
import {
  CLAUDE_PERMISSION_RULE_ASSET, claudeShimRoute, composeSdkRoute, SDK_ROUTE_ASSET, SDK_ROUTE_DIR, SDK_ROUTE_PYTHON_ASSET, SDK_SHIM_DIR, sdkHostNote,
  sdkRouteApplies, sdkRouteEnv, sdkRouteFiles, sdkRouteWriteProtect, withHead, writeClaudeShim, writeSdkRouteDir, writeSdkShims, type ClaudeShimRoute,
} from "./sdk-route.js";
import { realExecutable } from "./claude-permission-rule.cjs";
import * as nodeFs from "node:fs";
import * as nodePath from "node:path";
import { claudeEnvRefusal, claudeRouteArgs, claudeRouteEnv, claudeRouteOverlay, claudeRouteRefusal, readClaudeRouteLayers, type ClaudeRouteLayer } from "./claude-route.js";
import { CLAUDE_DEFAULT_PERMISSION_ARGS, claudeModeScopes, claudePermissionModeDecision } from "./claude-permission-mode.js";
import {
  checkClaudeSandbox, claudeConfigDir, claudeManagedSettings, claudeRunsSession, claudeSettingsFiles, claudeSettingsLocations, claudeStatusProbeAllowed,
  mergeClaudeSettingsArg, planDarwinClaudeSandbox, readClaudeSandbox, readClaudeSettingsFile, readClaudeSettingsSources, realClaudeSandboxStatus,
} from "./claude-sandbox.js";
import { runBackends } from "./backend/registry.js";
import { emptyMutation } from "./backend/types.js";
import { arbiterRevOf, arbiterTreesMatch, ensureArbiter, guardRuntimePath, pollArbiterSocket, promotedSockPath, startArbiter, startArbiterInstance } from "./arbiter.js";
import { checkArbiterRelease, enforceRelease, ownArbiterBuild, type BuildIdentity, type ReleaseCheckDeps } from "./arbiter-version.js";
import { acquireRestartLock, markReleaseCheckPending, pendingReleaseChecks } from "./release-gate.js";
import { assertArbiterTenant } from "./tenant-preflight.js";
import { assertArbiterAxes } from "./axis-preflight.js";
import { realPolicySuggestDeps, startLaunchSuggest } from "./policy-suggest.js";
import { applySecretTwins, socketSecretArbiter, type SecretSetupResult, applyEnvSecrets, type EnvSecretsResult, resolveAgentExe, prefetchDiscovery, launchDiscoverOptions, withPrefetchedDiscovery, type DiscoveryPrefetch, launchHomeCarveOuts, ndjsonCall } from "./secret-setup.js";
import { applyLandlockNet } from "./landlock-net-setup.js";
import { applyNetGuard, netGuardStatusFile } from "./net-guard-setup.js";
import { uploadDenyHosts, uploadDenyProxyOnlyHosts } from "./upload-deny.js";
import { launcherEgressHold } from "./egress-hold.js";
import { gooseOpenAiNeedsProxy, gooseOpenAiRoutes, gooseResumePin, gooseRoutePlan, readGooseConfig } from "./goose-route.js";
import { gooseRecipePlan } from "./goose-recipe.js";
import { gooseAcpLaunch } from "./goose-argv.js";
import { startAcpRelay, type AcpRelay } from "./goose-acp-relay.js";
import { humanPlaneDesymbolizer } from "./goose-acp-display.js";
import type { Readable, Writable } from "node:stream";
import { applyWriteProtect, registryHolding, runtimeRegistryProtect, writeProtectList } from "./write-protect.js";
import { applyUnixPolicy, unixPolicy } from "./unix-policy.js";
import { applyHumanPlaneDeny, humanPlaneDirs, humanPlaneWalled, readArbiterHumanSock, touchesHumanPlane, withoutHumanSock } from "./human-plane.js";
import { applySeatbelt } from "./seatbelt-setup.js";
import { sandboxExecAvailable } from "./seatbelt-profile.js";
import { NO_GUARD_SETTINGS, readGuardSettings } from "./guard-policy-file.js";
import { applyTrustLookups, expandTrust, remoteMountNotes, visibleRemoteMounts } from "./remote-mounts.js";
import { afterGuardedLaunch } from "./guard-death.js";
import { gitLockNoticeFile, gitLockNoticeLines, readGitLockRefusals, registerRefusedRepositories } from "./git-lock-backstop.js";
import { movedNoticeFile, movedNoticeLines, readMovedNotice } from "./moved-files-notice.js";
import {
  checkPendingPlaceholderRecords, checkPlaceholderRecord, newPlaceholderRecord, placeholderCheckDir, recheckEarlierRecords,
  removePlaceholderRecord, unsaidBlocks, writePlaceholderRecord, PENDING_LAUNCH_BUDGET_MS, WATCH_GIT_TIMEOUT_MS, type CheckBlock, type PlaceholderRecord,
} from "./placeholder-commits.js";
import { endTwinIndexSession, restorePendingFromStores, twinIndexReadStores, untrackedNotice } from "./twin-index-stat.js";
import { gatherWslFacts, wslLaunchNotes } from "./wsl.js";
import { readConnectAllowances } from "./net-guard-law.js";
import { autoBackgroundNote, CLAUDE_MCP_AUTO_BACKGROUND_ENV, claudeMcpAutoBackgroundMs } from "./claude-mcp-background.js";
import { entryUllmEndpointTimeoutMs } from "./ullm-timeout.js";
import { assertLocalEndpoints, bindSessionUpstream, localModelClientKeys, localModelTokens, plainHttpWarnings, readModelEndpoints, reservedAddresses, selectTllmEndpoint, tllmUpstream, undeclaredBaseUrlWarning, type SessionUpstreamBind } from "./model-endpoints.js";
import { wireOf } from "./types.js";
import { applyExecBox } from "./exec-box-setup.js";
import { cleanReporterWanted } from "./clean-host.js";
import { buildFinalArgv, runAgent } from "./spawn.js";
import { createTeardownGuard, holdTeardownGuardsUntilExit } from "./teardown-signals.js";
import { removeOwnScopeDir, scopeDirCleanupDecision } from "./scope-dir-cleanup.js";
import { createScopeDir } from "./scope-dir.js";
import { accountRendezvous, defaultRuntimeBaseOf } from "./runtime-base.js";
import { startServices, type ServiceHandle } from "./services/manager.js";
import { startTwinPrefetch } from "./twin-prefetch.js";
import { openGitSession } from "./git-session.js";
import { discardedWriteNotice, discardedWrites as twinWritesDiscarded, forgetLabelledTwinRecords, forgetTwinWatch, labelledDiscardedWrites, mergeDiscardedWrites, scopeTwinDir } from "./twin-writes.js";
import { isConfigRouted, opencodeConfigDirOf, opencodeV2Input, opencodeWriteProtect, readAgentUserConfig, readOpencodeAuthTypes } from "./services/agent-config.js";
import { agentModelPlan } from "./agent-model-route.js";
import { emitLauncherEvent, launchPostureEvent, sessionExitEvent } from "./services/observe.js";
import { humanPlaneWatch, watchesHumanPlane, WATCH_CALL_TIMEOUT_MS, type HumanPlaneWatch } from "./human-plane-watch.js";
import { keepCopiesInUse, type CopiesInUse } from "./git-object-twins.js";
import { beginLaunchRecord, concurrentLaunchNotice, endLaunchRecord, purgeEnforcementCaches, unrecordedExposureRefusal, type CacheEpochDeps, type LaunchClaim, type LaunchRecord } from "./cache-epoch.js";
import { configuredMcpServers, mapLaunchMcpServers, type McpConfigWatch } from "./mcp-server-config.js";
import { codexMcpProxyEnvOverrides, endLaunchWireRelease, registerLaunchWireRelease } from "./wire-release.js";
import { codexTwinPlaceholder, registerAgentKeyGrant, registerClaudeKeyGrant, registerCodexEnvKeyGrants, registerCodexKeyGrant, registerGooseEnvKeyGrants, registerProviderKeyGrants, withoutLauncherOnlyEnv } from "./agent-key-grant.js";
import { unguardedNote } from "./browser-cdp.js";
import { inheritApiKeyApproval } from "./services/claude-trust.js";
import { codexOverridesReach } from "./codex-argv.js";
import { CODEX_SHELL_NETWORK_OVERRIDE, codexArgvSandbox, codexShellNetworkDecision, readCodexNetworkLayers } from "./codex-shell-network.js";
import { Layout } from "./services/layout.js";
import { launchUsernsOk } from "./userns.js";
import { disableProbeCache, enableProbeCache, forgetAfterFailure } from "./probe-cache.js";
import { bannerLine, dashboardLine, launchDisplayMode, modeLine } from "./launch-banner.js";
import { LaunchConsole, LaunchConsoleSlot } from "./launch-console.js";
import { LAUNCH_LOG_ENV, openLaunchLog } from "./launch-log.js";
import { formatTimings, LaunchTimer, timingsLogLine } from "./launch-timings.js";
import { bannerDashboard, requestSignInLink, terminalDashboardLines, wantsSignInLink, type SignInOutcome } from "./dashboard-sign-in.js";
import { runtimeBase } from "./arbiter-sock.js";
import { arbiterAxisEnv, effectiveAxes, modeOf } from "./mode.js";
import { usageText } from "./usage.js";
import { agentOwnCredentialFiles, codexKeyRefusal, gooseKeyringNote, launchLoginKeying, launchLoginNote, realLoginProbeDeps } from "./agent-login.js";
import {
  launchPreviewNotice, launchVersionCheck, opencode2Enabled, opencodeGeneration, opencodeLaunchRefusal, probeAgentVersionWhy,
} from "./agent-versions.js";
import { launchUpdateCheck, launcherVersion, updateChannel } from "./update-check.js";
import { opencode1LaunchArgv, opencode2LaunchArgv } from "./opencode-argv.js";
import { opencode2ConfidentialityMissing, opencode2ConfidentialityRefusal, opencode2ConfidentialityUnenforced, probeGuardNotify } from "./opencode2-confidentiality.js";
import {
  findOpencodeProjectCode, opencodeProjectCodeAllowed, opencodeProjectCodeOptOutWarning, opencodeProjectCodeRefusal, opencodeStartDirs,
} from "./opencode-project-code.js";
import { findOpencodeGlobalCode, opencodeCodeDecision, opencodeGlobalCodeAllowed } from "./opencode-global-code.js";
import { buildHintFor, resolveNativeBin } from "./services/native-bins.js";
import { codexAllConfigLayers, codexSandboxLaunch, launchCodexSandboxNote, realCodexSandboxDeps, realReadPlistJson } from "./codex-sandbox.js";
import { codexArgvCd, codexConfigNamesConnectors } from "./codex-argv.js";
import { agentBwrapDir, bwrapLaunchNotes, commandAvailable, manduBwrapInForceHere } from "./bwrap-grant.js";
import type { ScopePlan } from "./platform/index.js";
import { publishFile } from "./safe-file.js";
import { sessionKeptLine } from "./session-kept-line.js";

/**
 * How to sign in to the newest live dashboard, for this terminal's dashboard
 * line (dashboard-sign-in.ts; dashboard.md §6.z): with the Mandu dashboard
 * account, or to set one when there is none yet. Not asked when stderr is
 * not a terminal (an older dashboard may still answer with a one-time link,
 * a credential, and a log is readable by the agent's uid).
 */
function askDashboardSignIn(env: Record<string, string | undefined>): Promise<SignInOutcome> {
  if (!wantsSignInLink(process.stderr.isTTY, env)) return Promise.resolve({ kind: "not-asked" });
  const dash = liveDashboards(env)[0];
  if (!dash) return Promise.resolve({ kind: "not-asked" });
  return requestSignInLink(dash, runtimeBase(env)).catch(
    (e: unknown): SignInOutcome => ({ kind: "unavailable", why: (e as Error).message }),
  );
}

/** In-process options of main(). The CLI passes none. */
export interface MainOptions {
  /** The directory the launch is for, instead of the real cwd (the
   *  launcher's in-process tests, whose own cwd is the package; launch-cwd.ts). */
  cwd?: string;
}

export async function main(argv: string[], env = process.env, opts: MainOptions = {}): Promise<number> {
  // The early-started reply filter (reply-filter.ts, packaging.md §5.3): a
  // launch that ends before handing it the agent (a refusal, a throw) ends it
  // here, so no filter outlives its launch.
  // The per-boot kernel probe cache (probe-cache.ts, packaging.md §5.4) is on
  // only for a launch (launch() turns it on after parse). A launch that read a
  // kept answer and then failed drops the file, so a wrong "available" costs
  // one failed launch and the next one probes afresh.
  const replyFilterSlot = new ReplyFilterSlot();
  // The launch's console (launch-console.ts): from the parse on, a launch
  // routes console.error through its display policy and its log; however
  // it ends, console.error is put back here, and a launch that throws says
  // what it held (the warnings, the notice count) before its error.
  const launchConsole = new LaunchConsoleSlot();
  // How long each step of the launch takes (launch-timings.ts,
  // runtime-instances.md §14.11): always kept, printed only under --verbose.
  // `mandu` (bin/mandu.mjs, the entry below) names its process before main(),
  // so its total counts from the process start; an in-process call's from here.
  const timer = new LaunchTimer({ cli: process.title === "mandu" });
  let returned = false;
  try {
    const code = await launch(argv, env, replyFilterSlot, opts, launchConsole, timer);
    returned = true;
    if (code !== 0) forgetAfterFailure();
    return code;
  } catch (e) {
    launchConsole.abort(e);
    if (forgetAfterFailure()) {
      console.error("mandu: this launch used kernel probe answers kept from an earlier launch; they are dropped, so the next launch probes afresh");
    }
    throw e;
  } finally {
    finishLaunchTimings(timer, launchConsole, returned);
    launchConsole.end();
    disableProbeCache();
    await replyFilterSlot.abort();
  }
}

/** The launch is over: its timings go to its log (`mandu log --timings`)
 *  and, under --verbose, to stderr after everything else it said (not for a
 *  launch that stopped with an error, whose error is its last line). Only a
 *  launch (its console attached after the parse), never `--help` or a
 *  subcommand. Best-effort: never throws. */
function finishLaunchTimings(timer: LaunchTimer, slot: LaunchConsoleSlot, returned: boolean): void {
  try {
    const lc = slot.current;
    if (lc === null || !timer.started) return;
    timer.end();
    const t = timer.snapshot();
    lc.log?.write(timingsLogLine(t));
    if (returned && lc.display === "full") for (const l of formatTimings(t)) lc.print(l);
  } catch { /* best-effort */ }
}

async function launch(argv: string[], env: NodeJS.ProcessEnv, replyFilterSlot: ReplyFilterSlot, opts: MainOptions, launchConsole: LaunchConsoleSlot, timer: LaunchTimer): Promise<number> {
  timer.step("plan");
  // Apply ~/.mandu/config.toml as low-priority defaults (packaging.md
  // §7): config values seed env only where unset, so the effective precedence
  // is flags > env > config > defaults. Mutates env (process.env in the real
  // CLI) so services and the agent inherit the defaults too. No-op without a file.
  // (The pre-config snapshot lets `mandu mode` tell a variable the user
  // exported from one the config file seeded.)
  const userEnv = { ...env };
  applyConfigDefaults(env);

  // --help / -h / help, and a bare `mandu` (release review P0: it used to
  // answer "no command given"). Only BEFORE the agent command: `mandu claude
  // --help` is the agent's own help.
  const firstCmd = argv.includes("--") ? argv.indexOf("--") : commandStart(argv);
  const launcherArgs = argv.slice(0, firstCmd);
  if (launcherArgs.includes("--help") || launcherArgs.includes("-h") || argv[firstCmd] === "help") {
    process.stdout.write(usageText());
    return 0;
  }
  if (launcherArgs.includes("--version") || launcherArgs.includes("-V")) {
    process.stdout.write(`mandu ${launcherVersion()}\n`);
    return 0;
  }
  if (argv.length === 0) {
    process.stderr.write(usageText());
    return 2;
  }

  // Resolve HOW services are run (packaging.md §5): from the esbuild bundles
  // when the launcher itself runs from a dist/ (an installed package, or a
  // checkout's fresh build, §5.1), through tsx from source otherwise.
  // MANDU_LAYOUT / MANDU_DEV_REPO force it.
  const layout = Layout.detect(import.meta.url, env);

  // Management subcommands (packaging.md §5) — bare form only, where the first
  // non-flag token is a reserved verb (status/stop/dashboard). `mandu --
  // status` still LAUNCHES a program named "status" (the `--` disambiguates).
  if (!argv.includes("--")) {
    const idx = commandStart(argv);
    const sub = argv[idx];
    if (sub !== undefined && RESERVED_SUBCOMMANDS.has(sub)) {
      return runSubcommand(sub, argv.slice(idx + 1), env, layout, userEnv);
    }
  }

  const plan = parse(argv, env, opts.cwd);
  // The launch directory, physically spelled (what process.cwd() answers in
  // the CLI; plan.humanCwd may be the user's symlinked spelling of it). Every
  // scan, settings read and twin of this launch is for it: one directory,
  // never a separate process.cwd() beside the plan's (launch-cwd.ts).
  const launchDir = physicalPath(plan.humanCwd);
  // Launch display policy (launch-banner.ts, packaging.md §5): by default the
  // user sees ONE banner line (the mode, what it masks, the dashboard, how
  // many notices the log holds), a short `mandu: WARNING: …` line per layer
  // that is not in its designed posture, a wait about to start, and an error
  // that stops the launch; --verbose / MANDU_VERBOSE=1 prints every line in
  // full. Every line is KEPT either way: the launch's own log (`mandu log`,
  // launch-log.ts), launch.log and the posture event. From here to the
  // banner, console.error goes through that policy (launch-console.ts);
  // main() puts it back however the launch ends.
  const display = launchDisplayMode({ verbose: plan.verbose, env });
  const launchLog = openLaunchLog({
    // The Mandu home it lives under: the launch env's MANDU_HOME, else this
    // process's (the same env in the CLI; an in-process test's private home,
    // test/lib/private-home.ts), else HOME's.
    env: !env["MANDU_HOME"] && process.env["MANDU_HOME"] ? { ...env, MANDU_HOME: process.env["MANDU_HOME"] } : env,
    sessionId: plan.scopeId,
    header: `mandu ${launcherVersion()}: launch of ${plan.argv[0] ?? "?"} (target ${plan.target}) in ${launchDir}, session ${plan.scopeId}, ${new Date().toISOString()}`,
  });
  const lc = launchConsole.attach(new LaunchConsole(display, launchLog));
  lc.hook();
  // The print every display line ends in: console.error as it was before the hook.
  const origConsoleError = lc.print;
  // Kernel probes (userns, Mandu's bubblewrap, Landlock TCP, nesting, the git
  // sandbox, Codex's sandbox): a pass is kept for the boot and still enacted
  // (probe-cache.ts; packaging.md §5.4). MANDU_PROBE_CACHE=0 reads nothing.
  enableProbeCache(env, { log: (m) => { if (plan.verbose) console.error(m); } });
  // OpenCode: the probed major decides the routing (agent-versions.ts
  // opencodeLaunchRefusal, supported-agents.md §2.3). OpenCode 1 and 2
  // launch; an unreadable version, another major, and OpenCode 2 under
  // MANDU_OPENCODE2=0 are refused before anything starts. Its version probe
  // is the launch's version check below, run early for OpenCode only (every
  // other agent is probed after its own refusals, so a refused launch never
  // runs it). OpenCode 2 (`opencode2` probed too) runs its model calls in a
  // server process, by default the user's background service, which Mandu's
  // routing does not reach: its argv is rewritten here, where the version is
  // known: every allowed shape gets `--standalone` (a private server inside
  // the wrap) and the shapes that join or drive a server outside the launch
  // are refused (opencode-argv.ts). OpenCode 1 keeps its argv, except that
  // its server and management subcommands are refused the same way
  // (opencode1LaunchArgv).
  const opencode2 = opencode2Enabled(env);
  // The probe's failure reason goes into the refusal: a timeout under load
  // and a broken install read differently.
  let probeWhy: string | null = null;
  const opencodeProbe = (bin: string): string | null => {
    const r = probeAgentVersionWhy(bin);
    probeWhy = r.why;
    return r.version;
  };
  const opencodeVersionCheck = plan.target === "opencode" ? launchVersionCheck(plan.target, plan.argv, opencodeProbe, { opencode2 }) : undefined;
  const opencodeRefusal = opencodeLaunchRefusal(plan.target, plan.argv, opencodeVersionCheck?.check ?? null, { opencode2, probeWhy });
  if (opencodeRefusal !== null) throw new Error(opencodeRefusal);
  const opencodeGen = opencodeGeneration(plan.target, plan.argv, opencodeVersionCheck?.check ?? null);
  const opencode2Launch = opencodeGen === 2;
  if (opencode2Launch) {
    const shaped = opencode2LaunchArgv(plan.argv);
    if (shaped.refusal !== null) throw new Error(shaped.refusal);
    plan.argv = shaped.argv;
    // Its private server (`--standalone`) under the kernel layer: the guard
    // admits the server's ephemeral loopback bind and the client's connect
    // to it, and nothing else (net-guard-setup.ts, supported-agents.md
    // §2.3.1). Empty when the executable cannot be resolved: nothing then.
    const exe = resolveAgentExe(plan);
    if (exe !== "") plan.ownServerExe = exe;
  } else if (opencodeGen === 1) {
    const shaped = opencode1LaunchArgv(plan.argv);
    if (shaped.refusal !== null) throw new Error(shaped.refusal);
  }
  // A config-routed agent whose model Mandu does not route would send its
  // turns around the model proxy (agent-model-route.ts): refuse before
  // anything starts. An OpenAI-family provider it routes is recorded for the
  // context proxy and the agent config. Read with process.env, as the
  // agent-config step does.
  if (isConfigRouted(plan.target)) {
    // OpenCode 2 reads every config layer (global, project up to /, inline)
    // in its own spelling: the check reads them all (opencodeV2Input).
    const modelPlan = agentModelPlan(
      plan.target, plan.argv, readAgentUserConfig(plan.target, process.env),
      plan.target === "opencode" ? readOpencodeAuthTypes(process.env) : {},
      plan.target === "opencode" ? opencodeV2Input(plan.argv, opencodeVersionCheck?.check.version ?? null, process.env, plan.cwd) : undefined,
    );
    if (modelPlan.refusal !== null) throw new Error(modelPlan.refusal);
    plan.openaiRoutes = modelPlan.routes;
  }
  // Goose: its built-in anthropic, openai and Chat Completions providers (litellm, openrouter, ollama, xai, tetrate) are routed
  // (goose-route.ts). Any other provider named by --provider, the env or the
  // config, for the session or its subagents, or an openai endpoint the
  // proxy cannot reach, would send turns around the model proxy: refuse.
  // The openai endpoint goes to the context proxy as a routed provider.
  if (plan.target === "goose") {
    const goose = gooseRoutePlan(plan.argv, env, readGooseConfig(env));
    if (goose.refusal !== null) throw new Error(goose.refusal);
    plan.gooseRouting = goose.routing;
    plan.openaiRoutes = gooseOpenAiRoutes(goose.routing);
    // A user's own ANTHROPIC_HOST (an undeclared endpoint skips the proxy,
    // parse.ts) does not apply to a session that does not use anthropic: the
    // proxy must run for the openai route, so the override is dropped.
    if (goose.routing.provider !== "anthropic" && goose.routing.subagentProvider !== "anthropic") plan.anthropicBaseUrl = undefined;
    // `run --recipe`: a recipe's settings outrank the env routing. Read it
    // now (another provider, sub-recipes, code mode are refused), hand goose
    // the file read here, and pin `--provider` to the routed provider, which
    // outranks the recipe (goose-recipe.ts).
    const recipe = gooseRecipePlan(plan.argv, env, plan.cwd, undefined, goose.routing.provider);
    if (recipe.refusal !== null) throw new Error(recipe.refusal);
    plan.argv = recipe.argv;
    // A resumed session (`-r` / `--resume`): the provider saved with it
    // outranks the env routing, so it could be one Mandu does not route.
    // Pin `--provider` to the routed one, which outranks it (goose-route.ts
    // gooseResumePin).
    plan.argv = gooseResumePin(plan.argv, goose.routing.provider);
  }
  // Claude Code: its settings sources apply `env` over its environment, so
  // a settings file could re-point its model traffic around the model proxy
  // (claude-route.ts). What the launch's own --settings cannot outrank is
  // refused before anything starts: a cloud provider switch or a Unix socket
  // in the launch environment, and the run's own --settings FILE (Claude Code
  // would read it instead of Mandu's). Managed sources are judged below,
  // against the environment the agent really gets.
  // `claude --version`, `claude mcp …` and the other subcommands that run no
  // session reach no model, so they are not judged.
  const claudeSession = plan.target === "claude" && (!isClaudeBinary(plan.argv[0]) || claudeRunsSession(plan.argv));
  if (claudeSession) {
    const envRefusal = claudeEnvRefusal(env);
    if (envRefusal !== null) throw new Error(envRefusal);
    if (isClaudeBinary(plan.argv[0])) {
      const early = claudeRouteArgs(plan.argv, [], claudeRouteOverlay(env));
      if ("refusal" in early) throw new Error(early.refusal);
    }
  }
  const platform = getPlatform();
  // A Codex model session with nothing to authenticate with: no key variable
  // and no `codex login` (or, with the user's own base URL, no key variable:
  // a sign-in never goes to that server). Codex could not run it, so refuse
  // before anything starts with the real fix (agent-login.ts
  // codexKeyRefusal, agent-sign-in.md §2.3, §2.6).
  const keyRefusal = codexKeyRefusal(plan.target, plan.argv, realLoginProbeDeps(env), { ownServer: !!plan.openaiBaseUrl });
  if (keyRefusal !== null) throw new Error(keyRefusal);
  // No detectable agent login → one plain line before anything starts
  // (agent-login.ts): a warning only, since detection can be wrong.
  const loginNote = launchLoginNote(plan.target, plan.argv, realLoginProbeDeps(env));
  if (loginNote !== null) console.error(loginNote);
  // The agent's version against the tested range (agent-versions.ts,
  // supported-agents.md): one WARNING line outside it, never a refusal (the
  // OpenCode refusal above is the one exception). Shown below, once the
  // display policy is known.
  const versionCheck = opencodeVersionCheck !== undefined ? opencodeVersionCheck : launchVersionCheck(plan.target, plan.argv);
  plan.agentVersion = versionCheck?.check.version ?? null;
  // Codex's OWN command sandbox (codex-sandbox.ts): on a stock Ubuntu without
  // bubblewrap every command Codex runs fails, with or without Mandu. One
  // WARNING line with the fix; never a refusal. macOS decides after the
  // Seatbelt profile is applied (below): only a launch that really applied
  // one turns Codex's sandbox off.
  if (platform.id !== "darwin") {
    const codexBoxNote = launchCodexSandboxNote(plan.target, plan.argv, realCodexSandboxDeps(env));
    if (codexBoxNote !== null) console.error(codexBoxNote);
  }
  // Mandu's own bubblewrap (bwrap-grant.ts): every launch checks the copy
  // against the system bwrap and names both versions when an update left it
  // behind, and flags a pre-2026-09-27 grant. WARNING lines; never a refusal.
  if (process.platform === "linux") for (const note of bwrapLaunchNotes()) console.error(note);
  // Every note is KEPT (lc.notes: the posture event and launch.log; the
  // launch's log as it is said) and shown through the display policy.
  const launchNotes = lc.notes;
  const keepNote = (m: string): void => lc.keep(m);
  const showNote = (line: string, print?: () => void, always: boolean | "wait" = false): void => lc.show(line, print, always);
  // An aborted launch's held short lines and notice count, before its error.
  const flushNotices = (): void => lc.flushShort(true);
  if (versionCheck?.note) { const n = versionCheck.note; showNote(n); }
  // A preview agent (Goose, OpenCode 1 and 2; agent-versions.ts
  // SupportStatus, supported-agents.md §2.0): one notice line, never a
  // refusal. MANDU_PREVIEW_NOTICE=0 hides it.
  const previewNote = launchPreviewNotice(plan.target, plan.argv, opencodeGen, env);
  if (previewNote !== null) showNote(previewNote, undefined, true);
  // A newer Mandu release (update-check.ts, packaging.md §11.5): the answer
  // the previous check left in the cache, as one notice line; a cache older
  // than a day is refreshed in the background, never waited on. Off in CI,
  // from a source checkout, off a terminal, and under MANDU_UPDATE_CHECK=0.
  const updateCheck = launchUpdateCheck({
    env, version: launcherVersion(), installed: layout.mode === "installed", interactive: process.stderr.isTTY === true, channel: updateChannel(layout),
  });
  if (updateCheck.notice !== null) { const n = updateCheck.notice; showNote(n, undefined, true); }

  // The scope plan's probes, asked once: the early reply filter needs the
  // plan's `detached` now, the launch its prefix at the end.
  const scopeProbes = memoScopeProbes();
  // Launch speed (packaging.md §5.3): the reply filter's node process starts
  // NOW, loads while the arbiter, the services and the confinement come up,
  // and is handed the agent at the end. It sees nothing before that.
  if (wantsPrestart(plan, layout, env)) {
    const pre = prestartReplyFilter(layout, {
      detached: platform.planScope({ scopeId: plan.scopeId, env: {}, noScope: plan.noScope, ...scopeProbes }).detached,
      cwd: launchDir,
      env,
    });
    replyFilterSlot.set(pre);
    if (pre !== null) {
      const n = `mandu: reply filter started early (pid ${pre.child.pid ?? "?"}); it waits for the agent`;
      showNote(n);
    }
  }

  // The axis switches are arbiter-owned (confidentiality.md §11): the
  // flags simply hand them to the daemon this launch starts. Absent ⇒
  // pass nothing, so an env var the user exported still wins.
  const axisEnv = arbiterAxisEnv({
    ...(plan.integrity !== undefined ? { integrity: plan.integrity } : {}),
    ...(plan.confidentiality !== undefined ? { confidentiality: plan.confidentiality } : {}),
  });
  // The session's own folder, made by this launch before anything writes into
  // it (scope-dir.ts, runtime-instances.md §10.2): 0700, and a minted one that
  // already exists (someone prepared it, links and all) refuses the launch
  // instead of being adopted by a `mkdir -p`. The fallback base's private-dir
  // rule runs first, as for every creator. Made by the per-launch arbiter's
  // start (which writes its log and events there) or right after the arbiter
  // is up, so a launch the arbiter step refuses (a runtime dir too long for
  // its socket) still creates nothing.
  const makeScopeDir = (): void => {
    guardRuntimePath(resolve(plan.eventDir, ".."), env);
    createScopeDir({ scopeRunDir: resolve(plan.eventDir, ".."), scopeIdGenerated: plan.scopeIdGenerated === true });
  };

  // Pinned/legacy resolutions start the arbiter AT the resolved path (the
  // caller owns it); an "autostart" resolution starts it in INSTANCE mode —
  // bind under instances/<id>/, promote `current` — so a bare launch can
  // never plant a second resident arbiter beside a promoted stack
  // (runtime-instances.md §5). A function: the release check below may stop
  // an older resident stack and start this release's in its place.
  const startOrAttachArbiter = () => {
    const arbiterLogPath = plan.arbiterSockMode === "autostart"
      ? `${plan.arbiterRuntimeBase}/logs/arbiter-autostart.log`
      : `${plan.eventDir}/../arbiter.log`;
    return ensureArbiter({
      sock: plan.arbiterSock,
      // The env this launch was handed, not process.env: the runtime-dir
      // checks (the fallback base's private-dir rule) judge the base this
      // launch resolved from it.
      env,
      noAutostart: env["MANDU_NO_ARBITER_AUTOSTART"] === "1",
      start: plan.arbiterSockMode === "autostart"
        ? startArbiterInstance(layout, plan.arbiterRuntimeBase, arbiterLogPath, axisEnv, {
            // The base was resolved from main()'s env, so its checks read that
            // env; the stack itself is still spawned with process.env.
            runtimeEnv: env,
            // "starting the Mandu stack" is an all-is-well note: verbose only.
            // The fallback line (the dashboard did not come up) keeps printing.
            info: (m) => { keepNote(m); if (display === "full") process.stderr.write(m + "\n"); },
          })
        // The pinned socket's start judges its log, event dir and socket
        // with main()'s env too (2026-10-10; it read process.env).
        : ((start) => async () => { makeScopeDir(); return start(); })(startArbiter(layout, plan.arbiterSock, plan.eventDir, arbiterLogPath, axisEnv, { runtimeEnv: env })),
      waitForSocket: (s, giveUp) => pollArbiterSocket(s, giveUp),
      logPath: arbiterLogPath,
      // The session's scope dir sits under the DEFAULT runtime base, which on
      // macOS is the private /tmp/mandu-<uid> fallback: created 0700 (or
      // verified) here, like the arbiter's own base (runtime-instances.md §3b).
      runtimeDirs: [resolve(plan.eventDir, "..")],
      ...(plan.arbiterSockMode === "autostart"
        ? { startHint: "(cd arbiter && MANDU_PROMOTE=1 npm run serve)" }
        : {}),
    });
  };
  timer.step("arbiter");
  let arbiterStart = await startOrAttachArbiter();

  // The release check (arbiter-version.ts, runtime-instances.md §4.1): an
  // arbiter of another Mandu release (one left running across an upgrade),
  // or of another build of this one (two commits of one version), is never
  // used. An older resident stack, or one of another build, that no other
  // session uses is restarted as this build; otherwise the launch refuses,
  // before any session-keyed op, service or event.
  {
    const ours = launcherVersion();
    const base = plan.arbiterRuntimeBase;
    let ownBuild: BuildIdentity | null | undefined;
    const releaseDeps: ReleaseCheckDeps = {
      hello: (s: string) => ndjsonCall<unknown>(s, "hello", {}, 5_000),
      // A launch whose own release check is still running has used nothing
      // but `hello`: not a session (release-gate.ts), so two launches racing
      // on one older stack do not refuse each other.
      peers: (b: string) => {
        const pending = pendingReleaseChecks(b);
        return liveLaunchersOn(b).filter((p) => !pending.has(p));
      },
      build: {
        own: () => (ownBuild === undefined ? (ownBuild = ownArbiterBuild(layout, { revOf: arbiterRevOf })) : ownBuild),
        sameArbiterTree: (a, b) => arbiterTreesMatch(layout.repoRoot, a, b),
      },
      // A systemd service that would restart that stack (stack-supervisor.ts).
      // Which process is old and who runs it decide what its refusal says.
      supervisor: (b: string, arbiterPid: number | null) => {
        const s = stackSupervisor([...(arbiterPid !== null ? [arbiterPid] : []), ...residentPidsOn(b)]);
        return s === null ? null : withStackFacts(s, arbiterPid, layout.mode === "installed" ? layout.pkgRoot : layout.repoRoot);
      },
    };
    const checkNow = (started: boolean) => checkArbiterRelease(
      { ours, sock: plan.arbiterSock, mode: plan.arbiterSockMode, started, base }, releaseDeps,
    );
    try {
      await enforceRelease({
        check: checkNow,
        started: !arbiterStart.attached,
        pinned: () => plan.arbiterSockMode === "pinned",
        // A pinned socket is never restarted: no marker, nothing written there.
        markPending: () => (plan.arbiterSockMode === "pinned" ? () => {} : markReleaseCheckPending(base)),
        acquireLock: () => acquireRestartLock(base),
        note: (note) => showNote(note, undefined, "wait"),
        stop: () => stopStackAndWait(base),
        // This build's stack, in instance mode, at the `current` spelling (a
        // legacy fixed-path stack is replaced by an instance one).
        startThisBuild: async () => {
          plan.arbiterSockMode = "autostart";
          plan.arbiterSock = promotedSockPath(base);
          arbiterStart = await startOrAttachArbiter();
          return { verdict: (await checkNow(true)).verdict, sock: plan.arbiterSock };
        },
        ours,
        base,
      });
    } catch (e) {
      flushNotices();
      throw e;
    }
  }
  // Made now, before any service or event, unless the per-launch arbiter's
  // start made it above (then this only checks it is still a real directory
  // of this uid).
  makeScopeDir();

  // Tenant preflight (policy-surface.md §2.7): a live launch never
  // lands in a test-tenant arbiter and a test launch never in the live one.
  // Fails BEFORE any service or event exists; an untenanted arbiter passes.
  await assertArbiterTenant(plan.arbiterSock, plan.tenant, {
    warn: (m) => process.stderr.write(m + "\n"),
  });

  // Axis preflight (axis-preflight.ts): an axis this launch set EXPLICITLY
  // must be what the attached arbiter actually runs — the flags only reach a
  // daemon this launch STARTS, and a resident arbiter ignores them silently.
  const reportedAxes = await assertArbiterAxes(
    plan.arbiterSock,
    { integrity: plan.integrity, confidentiality: plan.confidentiality },
    { warn: (m) => process.stderr.write(m + "\n"), readAlways: true },
  );
  // The pair this session REALLY runs under (mode.ts): the arbiter's report,
  // else the request, else the built-in default mode. Launcher-side
  // consequences follow the effective pair, not the flags: integrity OFF ⇒ no
  // AgentView twin (parse.ts states the same rule for an explicit request);
  // confidentiality ON ⇒ secret confinement (secret-setup.ts).
  plan.effectiveAxes = effectiveAxes(
    { ...(plan.integrity !== undefined ? { integrity: plan.integrity } : {}),
      ...(plan.confidentiality !== undefined ? { confidentiality: plan.confidentiality } : {}) },
    reportedAxes,
  );
  if (!plan.effectiveAxes.integrity) {
    plan.fsSync = false;
    plan.fsSyncOffReason = "mode"; // designed posture, not an opt-out (manager.ts)
  }
  // OpenCode 2 (with its argv rule) keeps its model calls routed, but a program
  // the agent runs could reach its private server's API (and put any file's
  // text into the conversation as the user's own message) or rewrite its
  // configuration mid-session. With confidentiality ON it runs only while
  // the guards that close both are in force: the kernel-layer connect guard
  // with the private-server allowance (seccomp user notification), the
  // write-protect guard, and the config lockdown
  // (opencode2-confidentiality.ts, supported-agents.md §2.3.1). Refused
  // here, before any service or event exists, when one is off or cannot
  // run; checked again on the composed launch below.
  if (opencode2Launch && plan.effectiveAxes.confidentiality) {
    const guardBin = plan.netGuard === false || platform.id !== "linux" ? null : resolveNativeBin("mandu-net-guard", { env });
    const missing = opencode2ConfidentialityMissing({
      platform: platform.id,
      netGuardOff: plan.netGuard === false,
      guardBin: guardBin !== null,
      guardBuildHint: buildHintFor("mandu-net-guard"),
      seccompNotify: guardBin === null ? null : probeGuardNotify(guardBin),
      ownServerExe: !!plan.ownServerExe,
      writeProtectOff: env["MANDU_WRITE_PROTECT"] === "0",
    });
    if (missing.length > 0) throw new Error(opencode2ConfidentialityRefusal(modeOf(plan.effectiveAxes), missing));
    plan.netGuardRequired = true;
  }
  // A project's OpenCode plugins and custom tools run inside OpenCode and
  // write the model request itself, past every check (system prompt, a
  // tool's output, the endpoint): with confidentiality ON they do not run
  // (opencode-project-code.ts, supported-agents.md §2.3 item 11). OpenCode 2
  // gets a configuration without them (agent-config.ts); OpenCode 1 reads its
  // project directories itself, so what its OPENCODE_PURE switch (below) does
  // not cover, a custom tool, refuses the launch here, before anything
  // starts. A wrapper whose generation is unknown gets the OpenCode 1 rule.
  // MANDU_OPENCODE_PROJECT_PLUGINS=1 runs them, with a warning.
  //
  // The user's OWN plugins and custom tools (the global config directory,
  // ~/.opencode, npm plugins a global document names) are left out the same
  // way (opencode-global-code.ts, §2.3 item 12): OpenCode 2 through the
  // configuration the launcher builds, OpenCode 1 through its own
  // OPENCODE_PURE switch, which also leaves a project's plugins out, so on
  // 1.x only custom tools (which the switch does not skip) refuse.
  // MANDU_OPENCODE_GLOBAL_PLUGINS=1 runs the user's, with a warning.
  if (plan.target === "opencode" && plan.effectiveAxes.confidentiality) {
    const starts = opencodeStartDirs(plan.argv, plan.cwd);
    const generation = opencode2Launch ? 2 : 1;
    const found = findOpencodeProjectCode(generation === 2 ? [plan.cwd] : starts, generation, env);
    const projectAllowed = opencodeProjectCodeAllowed(env);
    if (projectAllowed && found.length > 0) console.error(`mandu: ${opencodeProjectCodeOptOutWarning(found)}`);
    const decision = opencodeCodeDecision({
      generation, mode: modeOf(plan.effectiveAxes), project: found, global: findOpencodeGlobalCode(generation, env),
      projectAllowed, globalAllowed: opencodeGlobalCodeAllowed(env), projectRefusal: opencodeProjectCodeRefusal,
    });
    for (const w of decision.warnings) console.error(`mandu: ${w}`);
    if (decision.refusal !== null) throw new Error(decision.refusal);
  }

  // The law's reachability allowances (policy-surface.md §2.3):
  // policy.yaml `destinations: connect: allow` → extra connect-guard specs,
  // appended WITHOUT dropping the fallback. Fail-soft toward tighter ([] when
  // the arbiter cannot answer). Skipped when the guard is opted out.
  // policy.yaml `models:` (confidentiality-plan-11 D2/D5), read in parallel so
  // a slow arbiter costs one deadline, not two. Used below, once the services
  // are up, for the local-endpoint refusal and the network confine.
  // The session's main model (plan 11 §5, phase 3) is recorded with the
  // arbiter before any service starts (see below). When no user-set base URL
  // can name a declared entry, the answer is already known (null, the agent's
  // default vendor), so that bind rides the same round as the reads and a
  // plain launch pays no extra deadline.
  // The agent's own base-URL knob: ANTHROPIC_BASE_URL for an Anthropic-wire
  // target, MANDU_OPENAI_BASE_URL (the model_provider base_url) for Codex.
  const agentWire = wireOf(plan.target);
  const userBaseUrl = agentWire === "anthropic" ? plan.anthropicBaseUrl : plan.openaiBaseUrl;
  const baseUrlKnob = agentWire === "anthropic" ? "ANTHROPIC_BASE_URL" : "MANDU_OPENAI_BASE_URL";
  const baseUrlCandidate = !!userBaseUrl && !plan.noContextProxy;
  // exec-routing.md §8.5.3: the same first bind asks for the clean box's
  // reporter, which the session's guard claims before the agent starts.
  const wantCleanReporter = cleanReporterWanted(plan, platform.id);
  // The arbiter's human plane (human-plane.ts, arbiter-human-plane.md): the
  // socket the human-facing children (reply filter, fs-sync, net-proxy) use
  // for originals, read from `hello` in the same round. None reported ⇒ they
  // get none (and degrade by their own rules); never the data socket.
  const [lawAllow, modelRead, earlyBind, humanSock] = await Promise.all([
    plan.netGuard === false ? Promise.resolve<string[]>([]) : readConnectAllowances(plan.arbiterSock),
    readModelEndpoints(plan.arbiterSock),
    baseUrlCandidate ? Promise.resolve(null) : bindSessionUpstream(plan.arbiterSock, plan.scopeId, null, undefined, wantCleanReporter),
    readArbiterHumanSock(plan.arbiterSock),
  ]);
  plan.arbiterHumanSock = humanSock;
  plan.humanPlaneDirs = humanPlaneDirs(humanSock, plan.arbiterRuntimeBase);
  // Fail closed: an arbiter socket spelled inside the human plane would put
  // the originals-returning channel in the agent's own MANDU_ARBITER_SOCK.
  if (touchesHumanPlane(plan.arbiterSock, plan.humanPlaneDirs)) {
    throw new Error(
      `mandu: the arbiter socket ${plan.arbiterSock} lies in Mandu's human-plane directory (${plan.humanPlaneDirs.join(", ")}), ` +
        "which the agent may never reach — refusing to launch. Point MANDU_ARBITER_SOCK at the data socket.",
    );
  }
  // On the plan BEFORE startServices: the manager's inspect-mcp confine
  // (inspect-net-confine.ts, plan 11 §8 item 5) reads the local endpoints'
  // ports when it writes the MCP config. A `local: true` entry at a reserved
  // address is still refused below, before the agent starts.
  plan.modelEndpoints = modelRead.endpoints;
  plan.modelTokens = localModelTokens(modelRead.endpoints, env);
  // How long inspect_symbol may wait for a declared model (ullm-timeout.ts,
  // model-endpoints.md §1.9): into the inspect-mcp entry every agent gets,
  // and the agents' own MCP call timeouts follow from it.
  const ullmTimeout = entryUllmEndpointTimeoutMs(env, modelRead.endpoints);
  if (ullmTimeout !== undefined) plan.ullmEndpointTimeoutMs = ullmTimeout;
  // The agent's own upload hosts (upload-deny.ts; supported-agents.md §5.3.4
  // rule 1), BEFORE startServices: the net-proxy is started with them and the
  // connect guard (applyNetGuard) denies them before any allow rule.
  // Each agent's own config, read for the hosts it names: Goose's config.yaml,
  // Codex's config.toml layers (its `[otel]` endpoints, realtime base URLs).
  const readText = (p: string): string | null => { try { return readFileSync(p, "utf8"); } catch { return null; } };
  const codexLayers = plan.target === "codex" ? codexAllConfigLayers(env, plan.cwd || launchDir, plan.argv, readText) : [];
  const agentUploadConfig = plan.target === "goose" ? readGooseConfig(env)
    : plan.target === "codex" ? { layers: codexLayers }
    : undefined;
  // Codex's legacy `connectors` key in the user's config would turn ChatGPT
  // apps back on after Mandu's `features.apps=false` (codex-argv.ts header).
  if (codexLayers.some((l) => codexConfigNamesConnectors(l.text))) plan.codexConnectorsOff = true;
  plan.uploadDenyHosts = uploadDenyHosts(plan.target, env, agentUploadConfig);
  // Hosts the net-proxy alone denies (upload-deny.ts `proxyOnly` says why):
  // Goose's unrouted providers' model hosts, Codex's ab.chatgpt.com.
  plan.netProxyOnlyDenyHosts = uploadDenyProxyOnlyHosts(plan.target);
  // The held request's length (egress-hold.ts, egress-hold.md "The
  // default"): the user's MANDU_EGRESS_HOLD_MS, else 60 s when a person is
  // likely watching (stdout a terminal, not a one-shot run, not CI), else 0.
  // Decided once here, from the reply filter's notion of an interactive run;
  // the net-proxy gets it in its env (services/net-proxy.ts).
  // The net-proxy's LIVE line says so when it holds (manager.ts).
  plan.egressHold = launcherEgressHold({ env, argv: plan.argv, stdoutIsTTY: process.stdout.isTTY === true });

  plan.modelClientKeys = localModelClientKeys(modelRead.endpoints);
  // The main model as a declared endpoint (confidentiality-plan-11-cleared-
  // model-endpoints.md §5, phase 3). A user-set ANTHROPIC_BASE_URL used to skip
  // the model proxy outright, so a Claude Code pointed at its own model ran
  // with no symbolization at all. When the URL is a declared `wire: anthropic`
  // entry of policy.yaml `models:`, the proxy STAYS, with that entry as its
  // upstream (clearing plan.anthropicBaseUrl makes the manager start it and
  // env-compose point the agent at it). An undeclared URL keeps the old skip,
  // loudly. Codex gets the same through MANDU_OPENAI_BASE_URL and a declared
  // `wire: openai-chat` entry (plan 11 §7.2). MANDU_NO_CONTEXT_PROXY (an
  // out-of-band proxy) keeps today's
  // behavior: this launch owns no proxy whose upstream it could set.
  // Notes are collected here and printed once the notes hook below is in
  // place (they belong in the launch_posture event).
  const tllmNotes: string[] = [];
  if (baseUrlCandidate) {
    const userUrl = userBaseUrl!;
    const matched = modelRead.status === "ok" ? selectTllmEndpoint(userUrl, modelRead.endpoints, agentWire) : null;
    if (matched !== null) {
      // Throws TllmUpstreamError (plain http to another machine): the launch
      // refuses here, before any service or the agent exists (fail-closed).
      const upstream = tllmUpstream(matched.url, baseUrlKnob);
      plan.tllmEndpoint = { name: matched.name, url: matched.url, local: matched.local, upstream, ...(matched.tls ? { tls: matched.tls } : {}), ...(matched.perimeter ? { perimeter: matched.perimeter } : {}) };
      // Clearing the user's URL makes the manager start the proxy and
      // env-compose point the agent at it (Codex: the -c model_provider
      // splice names the proxy's /v1 instead of the user's URL).
      if (agentWire === "anthropic") plan.anthropicBaseUrl = undefined;
      else plan.openaiBaseUrl = undefined;
      tllmNotes.push(
        `mandu: your main model is "${matched.name}" (${matched.url}), declared in policy.yaml models: as ` +
          `${matched.local ? "your own model (local)" : "an outside model"}; Mandu's model proxy stays in front of it`,
      );
    } else {
      tllmNotes.push(undeclaredBaseUrlWarning(userUrl, modelRead.status === "ok", agentWire));
    }
  }
  // Goose on openai (or a Chat Completions provider) beside a user's own
  // undeclared ANTHROPIC_HOST (for its anthropic session or subagents):
  // that override skips the model proxy, and the provider's route lives
  // there. Without this its turns would fail closed at a proxy that is not
  // running; say why instead.
  const gooseRoutes = plan.target === "goose" ? gooseOpenAiRoutes(plan.gooseRouting) : [];
  if (gooseRoutes.length > 0 && plan.anthropicBaseUrl && !plan.noContextProxy) {
    throw new Error(gooseOpenAiNeedsProxy(plan.anthropicBaseUrl, gooseRoutes[0]!.id));
  }
  // Record the session's main model with the arbiter: the matched entry's
  // name, else null (the default vendor, an outside model). EVERY launch
  // binds, BEFORE startServices: the proxy asks the arbiter for the handling
  // prompt per request and rung 3 reads this binding, and the binding is
  // bind-once, so the launcher's must be the first (a process inside the agent
  // must never get to claim a local main model for its own session). The key
  // is exactly plan.scopeId, the proxy's MANDU_SESSION_KEY and inspect-mcp's.
  // A failed bind never refuses the launch: the arbiter then keeps treating
  // the main model as an outside one, the strict reading (fail-closed).
  const bind: SessionUpstreamBind = earlyBind
    ?? await bindSessionUpstream(plan.arbiterSock, plan.scopeId, plan.tllmEndpoint?.name ?? null, undefined, wantCleanReporter);
  plan.cleanReporterOffered = bind.status === "ok" && bind.cleanReporter === true;
  if (plan.tllmEndpoint) {
    const name = plan.tllmEndpoint.name;
    if (bind.status !== "ok") {
      const why = bind.status === "unsupported"
        ? "the protection service is older than this launcher"
        : bind.status === "refused" ? bind.error ?? "refused" : "it did not answer";
      tllmNotes.push(
        `WARNING: mandu: could not record "${name}" as this session's main model with the protection service (${why}); ` +
          "files labeled local-model cannot be shown to your main model this session (it is treated as an outside model)",
      );
    } else if ((bind.location === "local") !== plan.tllmEndpoint.local) {
      tllmNotes.push(
        `mandu: the protection service reads your main model "${name}" as ${bind.location === "local" ? "your own model (local)" : "an outside model"} ` +
          "in the policy in force now; that reading decides whether files labeled local-model may enter the conversation",
      );
    }
  } else if (bind.status === "refused") {
    tllmNotes.push(
      `WARNING: mandu: the protection service refused to record this session's main model (${bind.error ?? "refused"}); ` +
        "files labeled local-model cannot be shown to your main model this session",
    );
  }

  // Service-manager phase (spec §2.1): start opted-in cooperative services,
  // which mutate `plan` (netProxy / mitmCaCert / shimDir / mcpConfig) that the
  // env composer then reads. scopeRunDir mirrors mandu-run.sh:485.
  const scopeRunDir = resolve(plan.eventDir, "..");
  // Session-health record (services/observe.ts): every rung banner printed
  // from here to the spawn is ALSO kept, so the launch's real posture lands
  // in the session's event stream as ONE `launch_posture` event — the
  // dashboard's per-session health chip reads it; the differential harness's
  // posture oracle reads the same phrases off stderr (under MANDU_VERBOSE=1,
  // which every stderr-reading harness sets).
  const launchedAt = Date.now();
  // console.error has gone through the display policy since the parse
  // (lc.hook above): every note is KEPT (the posture event, launch.log, the
  // launch's log). The WARNINGs about ANOTHER launch beside this one (an
  // unconfined one, a human plane exposed, §10.1.1) are held until the
  // banner is out, then the last thing on screen when the agent takes the
  // terminal (lc.sayWhole, launch-banner.ts holdUntilBanner, packaging.md §5
  // "Last before the agent").
  for (const note of tllmNotes) console.error(note);
  // The secret discovery walk (seconds on a real home) starts as soon as the
  // AgentView is seeded (it reads this workspace's AgentView copy) and runs
  // while the proxies and the network confine come up; applySecretTwins picks
  // its answer up (withPrefetchedDiscovery). Same roots, home, state base and
  // login keying (the agents whose logins stay raw, secret-discovery.md
  // §1.10) as the secret setup asks with below.
  let discovery: DiscoveryPrefetch | undefined;
  // The git-object twins' reads (confidentiality.md §7.2a "The prefetch"):
  // the history states and pack hashes the last launch from this workspace
  // needed, started now while the services come up; applySecretTwins uses
  // each only where it is what it would compute itself, and closes nothing
  // (this function does, on every path: no git call outlives the launch).
  //
  // Every git call of that prep (the prefetch, the history step, the
  // placeholder watch) runs in ONE git sandbox (git-session.ts,
  // confidentiality.md §7.2a "Cost on a relaunch"), started now so its
  // start-up overlaps the services', and closed with the prefetch.
  const twinsAhead = platform.id === "linux" && (plan.effectiveAxes?.confidentiality ?? plan.confidentiality) === true;
  const gitSession = twinsAhead ? openGitSession() : null;
  gitSession?.warm();
  const twinPrefetch = twinsAhead ? startTwinPrefetch(process.env, homedir(), [launchDir], gitSession ?? undefined) : null;
  const closeTwinReads = (): void => {
    twinPrefetch?.close();
    gitSession?.close();
  };
  // The quarantined CLI by its path, past the session's `claude` shim
  // (written below, first on the agent's PATH): by name the shim would route
  // inspect_symbol's `claude -p` to the model proxy, where the inspect
  // server's network confine refuses it (Ullm.binaryPath). Before the
  // services: the manager writes the inspect server entry.
  if (plan.ullm.mode === "cli") {
    const real = realExecutable(plan.ullm.binary ?? "claude", env["PATH"] ?? plan.basePath, join(scopeRunDir, SDK_SHIM_DIR), nodeFs, nodePath);
    if (real !== null) plan.ullm.binaryPath = nodePath.resolve(real);
  }
  let services: ServiceHandle;
  timer.step("services");
  try {
    services = await startServices(plan, layout, scopeRunDir, undefined, undefined, {
      onFsViewReady: () => {
        if ((plan.effectiveAxes?.confidentiality ?? plan.confidentiality) !== true) return;
        discovery = prefetchDiscovery(socketSecretArbiter(plan.arbiterSock), [homedir(), launchDir], homedir(), launchDiscoverOptions(process.env, homedir(), launchLoginKeying(plan)));
      },
    });
  } catch (e) {
    closeTwinReads();
    throw e;
  }
  timer.step("confine");

  // Plan 14 §5.5, §13.6: the advisory scans of this workspace (its
  // repository's history and its files on disk; no `sources`, so both run
  // within the one budget), started now so it overlaps the rest of the launch, awaited just before
  // the banner with a short budget (policy-suggest.ts startLaunchSuggest:
  // never rejects, never refuses, never waits past its budget). Once a scan
  // of this workspace has finished, the arbiter answers at once from it and
  // scans again on its own, so only a workspace's first launch waits; the
  // launcher keeps nothing of that scan. Only the debug note of a failure is
  // kept, and it prints only under --verbose, never after the banner.
  const suggestNotice: Promise<string | null> | null = (plan.effectiveAxes?.confidentiality ?? plan.confidentiality) === true
    ? startLaunchSuggest({ sock: plan.arbiterSock, cwd: launchDir, home: homedir(), env }, {
        suggest: realPolicySuggestDeps().suggest,
        debug: (m) => { keepNote(m); if (display === "full") process.stderr.write(m + "\n"); },
      })
    : null;

  let finalArgv: string[];
  let finalEnv: Record<string, string | undefined>;
  let scope: ScopePlan;
  // The reply filter's wiring, and the early-started filter's hand-off (the
  // serial form's command after `--` and its environment), set together.
  let replyFilterWiring: ReplyFilterWiring | null = null;
  let filterHandoff: ReplyFilterHandoff | null = null;
  let secretResult: SecretSetupResult | undefined;
  let envResult: EnvSecretsResult | undefined;
  // The protected files in a git work tree, watched for a commit of their
  // placeholder (placeholder-commits.ts): this launch's record (and where it
  // is kept for a launch after a crash, in the Mandu home), and the records
  // of earlier crashed sessions this launch checked at its start (checked
  // again after the agent exits; the files of those whose check at launch
  // did not complete stay on disk until then).
  let placeholderRecord: PlaceholderRecord | null = null;
  let placeholderFile: string | null = null;
  let earlierPlaceholder: PlaceholderRecord[] = [];
  let earlierKept: string[] = [];
  const placeholderHome = manduPath("mandu-home", process.env, homedir());
  const placeholderChecks = placeholderCheckDir(manduPath("object-walks", process.env, homedir()));
  let netGuarded = false;
  // Plan 14 §11.2: whether the agent's tree may not write Mandu's home, and
  // this launch's record with the arbiter (whose end voids the caches'
  // seals when the launch was unconfined).
  let writeProtected = false;
  // Plan 13 D9 leftovers: the guard carries the always-deny entry for the
  // human-plane directories (one of the two walls `humanPlaneWalled` reads).
  let humanDenied = false;
  let launchRecord: LaunchRecord | null = null;
  // §10.1.1: the human-plane watch of a walled launch (human-plane-watch.ts).
  let humanWatch: HumanPlaneWatch | null = null;
  // Plan 10 §11.17: the watch that follows the agent's MCP config.
  let mcpWatch: McpConfigWatch | null = null;
  // Plan 14 §11.1 R3 (a): the sanitized copies this launch serves, kept
  // marked used while it runs so the arbiter never prunes one mid-session.
  let copiesInUse: CopiesInUse | null = null;
  // Plan 10 §11.13.1: whether this launch told the arbiter its proxy inspects
  // TLS (withdrawn at the end).
  let wireRelease: Awaited<ReturnType<typeof registerLaunchWireRelease>> | null = null;
  // The dashboard's one-time sign-in link (dashboard-sign-in.ts,
  // policy-surface.md §2.6 "Signing in"): asked before this launch is on the
  // arbiter's record and before its agent exists, printed on the dashboard
  // line to the terminal only.
  let signInAsk: Promise<SignInOutcome> | null = null;
  const cacheEpochDeps: CacheEpochDeps = {
    call: (sock, op, args) => ndjsonCall<unknown>(sock, op, args, 5_000),
    log: (m) => console.error(m),
    purge: () => purgeEnforcementCaches(process.env, homedir()),
  };
  try {
    const mut = emptyMutation();
    // Tell the wrappers that print their own all-is-well notice from their own
    // process (the reply-filter's PTY-relay line) which display policy the
    // launch chose; flows through childEnv AND the systemd --setenv path.
    if (display === "compact") mut.env["MANDU_LAUNCH_DISPLAY"] = "compact";
    // And where their non-fatal messages go instead of the agent's terminal:
    // the launch's log (launch-log.ts; the network guard's diag.rs, the reply
    // filter's info). The agent cannot write it (the Mandu home is
    // write-protected), and the helpers that append run outside its walls.
    if (launchLog !== null) mut.env[LAUNCH_LOG_ENV] = launchLog.path;
    // exec-box (docs/design/integrity/exec-routing.md §7): box a curated read-only command
    // set through mandu-exec-box. Runs BEFORE coop-env so its shim dir
    // (plan.execBoxShimDir) is on the plan when composeLaunch prepends it to the
    // agent PATH — and AFTER startServices so plan.viewMap (fs-view) is set and
    // the shims bake the writable-AgentView bind. On by default + graceful
    // degrade (a missing bin / bwrap only warns; --no-exec-box opts out).
    // Mandu's own bubblewrap (bwrap-grant.ts), where `mandu setup` put it:
    // first bwrap on the agent's PATH, for Codex's sandbox and the exec box.
    // Else an administrator's `bwrap_path` (bwrap-path.ts): its directory
    // goes there instead, so what the agent's tools run is what Mandu runs.
    // The box itself takes the first one on PATH outside the workspace
    // (exec-supervisor `resolve_bwrap`), so this directory is what it runs.
    if (process.platform === "linux") {
      const dir = agentBwrapDir(manduBwrapInForceHere());
      if (dir !== undefined) plan.bwrapDir = dir;
    }
    applyExecBox(plan, scopeRunDir, {
      commandExists: (c) => commandExists(c),
      usernsOk: () => usernsOk(),
      log: (m) => console.error(m),
      hostEnv: env,
      // Linux only (bubblewrap); macOS says so in one informational line.
      platform: platform.id,
    });

    // coop-env (required). The registry still probes + fails closed for any
    // future backend; the last deferred stub retired with --unshare (2026-07-14
    // — requesting a retired rung is refused at parse time instead, spec §5).
    runBackends([coopEnv], plan, mut);
    if (plan.target === "claude" && isClaudeBinary(plan.argv[0]) && plan.claudeTuiPin === true) {
      // Non-default posture (the pin is OFF by default since 2026-09-19): say so.
      console.error(
        "mandu: claude TUI PINNED to the inline renderer (MANDU_CLAUDE_TUI_PIN=1) — the reply-filter " +
          "resolves the fullscreen renderer too since 2026-09-19 (differential-interactive.md §19); " +
          "unset the variable to run whatever renderer the release / your `tui` setting picks",
      );
    }

    // Declared model endpoints (confidentiality-plan-11 D2): a `local: true`
    // entry at the model proxy's or the U-LLM forwarder's address would hand
    // local-model bytes to an outside model, so the launch REFUSES. Checked
    // here because a port-0 proxy / forwarder has its real port only after
    // startServices. Then the local endpoints join the network confine (D5).
    await assertLocalEndpoints(modelRead, reservedAddresses(plan));
    if (modelRead.status === "unavailable") {
      console.error(
        "mandu: could not read policy.yaml models: from the protection service; your own model endpoints get no " +
        "network allowance this session (inspect_symbol cannot reach them)",
      );
    } else if (modelRead.dropped.length > 0) {
      console.error(`WARNING: mandu: policy.yaml models: ignored unreadable entr${modelRead.dropped.length === 1 ? "y" : "ies"} ${modelRead.dropped.join(", ")}`);
    }
    for (const w of plainHttpWarnings(modelRead.endpoints)) console.error(w);
    plan.modelEndpoints = modelRead.endpoints;
    plan.modelTokens = localModelTokens(modelRead.endpoints, env);

    plan.modelClientKeys = localModelClientKeys(modelRead.endpoints);
    // Claude Code's MCP auto-background window (claude-mcp-background.ts,
    // model-endpoints.md §1.9): with the user's own model declared, an
    // inspect_symbol call can outlast the 120 s default, and its answer
    // would then miss the turn. A value the user set stands.
    const autoBackgroundMs = claudeMcpAutoBackgroundMs({ target: plan.target, endpoints: modelRead.endpoints, env });
    if (autoBackgroundMs !== null) {
      mut.env[CLAUDE_MCP_AUTO_BACKGROUND_ENV] = String(autoBackgroundMs);
      console.error(autoBackgroundNote(autoBackgroundMs));
    }
    // landlock-net (docs/design/integrity/exec-routing.md §7): the whole-agent TCP
    // port-allow wrap. Prepended to mut.launchPrefix BEFORE applySecretTwins so
    // it ends up OUTERMOST (wrapping the secret-twins bwrap and every child) yet
    // still inside the reply-filter. On by default + graceful degrade (missing
    // bin / pre-6.7 kernel warns + no wrap; --no-landlock-net opts out).
    // macOS: the same port set, enforced by the whole-agent Seatbelt profile
    // applied below (seatbelt-setup.ts); no applier, no wrap here.
    // /usr/bin/sandbox-exec by path, the binary the wrap runs, through the
    // same check the secret setup gets (never a PATH lookup of the bare name:
    // seatbelt-profile.ts SANDBOX_EXEC).
    const seatbeltOk = platform.id === "darwin" && sandboxExecAvailable(commandExists);
    const netConfine = applyLandlockNet(plan, mut, { log: (m) => console.error(m), platform: platform.id, seatbeltAvailable: seatbeltOk });

    // net-guard (docs/design/integrity/exec-routing.md §7.5): the IP/DOMAIN-aware connect(2)
    // guard — the teeth that close the port-only gap landlock-net leaves (a :443
    // allow admits ANY host). Prepended AFTER applyLandlockNet so it lands ahead
    // of the landlock port wrap = OUTERMOST net wrap, which is LOAD-BEARING: the
    // guard supervisor must sit OUTSIDE the Landlock port restriction so its
    // supervisor-side connect to an allowed destination is not itself port-denied
    // (that is what keeps an allowed :443 reachable even under --landlock-net-strict).
    // On by default + graceful degrade (missing bin / seccomp warns + no guard;
    // --no-net-guard opts out; --net-allow curates the set).
    const netGuard = applyNetGuard(plan, mut, { log: (m) => console.error(m), lawAllow, platform: platform.id });
    netGuarded = netGuard !== null;
    // The DevTools relay is the agent's only way to Chrome only while a
    // connect guard keeps Chrome's own port out of reach (browser-cdp.ts).
    if (plan.cdpRelay && plan.browserCdp && netConfine === null && netGuard === null) console.error(unguardedNote(plan.browserCdp));
    // WSL (wsl.ts): Windows interop, a project on a Windows drive, an old
    // kernel. Notes only: the closures live in the box, the guard and the
    // secret-twin wrap.
    if (platform.id === "linux") {
      const wsl = gatherWslFacts({
        readFile: (p) => { try { return readFileSync(p, "utf8"); } catch { return null; } },
        fileExists: existsSync,
        cwd: plan.cwd,
      });
      for (const n of wslLaunchNotes(wsl, { guard: netGuard !== null })) console.error(n);
    }

    // Secret confinement (confidentiality.md §7.2/§7.3): keep RAW secret bytes
    // out of the agent's world — symbolized twins bind-mounted over the
    // credential files (Linux) or a Seatbelt read-deny (macOS). Applied BEFORE
    // the reply filter so the sandbox ends up INSIDE it (the filter stays
    // outside, desymbolizing for the human). FAIL-CLOSED: refuses the launch if
    // confinement was asked for and cannot be established (unless --best-effort).
    // (2026-09-21: a HOST gap now degrades to the named `gated` posture with a
    // loud notice; --require-confinement restores the refusal. An arbiter
    // failure still refuses. rootless-confinement-ubuntu-2404.md §3.1.)
    // A reused --id's scope dir may hold the last launch's git-lock notice.
    try { rmSync(gitLockNoticeFile(scopeRunDir), { force: true }); } catch { /* best-effort */ }
    try { rmSync(movedNoticeFile(scopeRunDir), { force: true }); } catch { /* best-effort */ }
    // Agent-sign-in.md §3: Goose's key file is twinned and the model proxy
    // puts the key back in the auth header, when this launch can bind the key
    // to the provider it routes (human plane, before the twins). Otherwise
    // the file stays Goose's own key file, read raw (agentOwnFiles below).
    timer.step("key-grants");
    const keyGrant = await registerAgentKeyGrant(plan, env, process.env, {
      call: (sock, op, args) => ndjsonCall<unknown>(sock, op, args, 5_000),
      log: (m) => console.error(m),
      fileExists: existsSync,
      pid: process.pid,
      platform: platform.id,
    });
    if (keyGrant.granted) {
      console.error(`mandu: ${keyGrant.path} is a placeholder in Goose's world; the model proxy puts its key back in the auth header to ${keyGrant.hosts!.join(", ")} only`);
    }
    // Agent-sign-in.md §3.8: Claude Code's ANTHROPIC_API_KEY, the same way
    // through the environment: granted here (human plane), then masked by
    // the env-secrets step below (`agentKeys`). Otherwise it stays raw in
    // Claude Code's environment, as before.
    const envKeyGrant = await registerClaudeKeyGrant(plan, env, process.env, {
      call: (sock, op, args) => ndjsonCall<unknown>(sock, op, args, 5_000),
      log: (m) => console.error(m),
      pid: process.pid,
    });
    // §3.10: Goose's routed providers' key variables, one env grant each.
    const gooseEnvGrants = await registerGooseEnvKeyGrants(plan, env, process.env, {
      call: (sock, op, args) => ndjsonCall<unknown>(sock, op, args, 5_000),
      log: (m) => console.error(m),
      pid: process.pid,
    });
    // §3.11: Codex's key variables (OPENAI_API_KEY / CODEX_API_KEY).
    const codexEnvGrants = await registerCodexEnvKeyGrants(plan, env, process.env, {
      call: (sock, op, args) => ndjsonCall<unknown>(sock, op, args, 5_000),
      log: (m) => console.error(m),
      pid: process.pid,
    });
    // §3.12: model services' keys a program in the session sends itself
    // (TYPESAFE_API_KEY, OPENROUTER_API_KEY), each bound to its own host;
    // masked by name below like any key, not an agent's own (no agentKeys).
    const providerGrants = await registerProviderKeyGrants(plan, env, process.env, {
      call: (sock, op, args) => ndjsonCall<unknown>(sock, op, args, 5_000),
      log: (m) => console.error(m),
      pid: process.pid,
    });
    const envGranted = [
      ...(envKeyGrant.granted ? [{ name: envKeyGrant.name!, hosts: envKeyGrant.hosts! }] : []),
      ...gooseEnvGrants,
      ...codexEnvGrants,
    ];
    // Agent-sign-in.md §3.9: Codex's saved key (`auth.json` in API-key
    // mode): granted here, then twinned by the secret setup below although
    // the walk leaves the launched agent's login out; the openai-proxy puts
    // the key back, and the U-LLM forwarder for the quarantined codex exec.
    const codexGrant = await registerCodexKeyGrant(plan, env, process.env, {
      call: (sock, op, args) => ndjsonCall<unknown>(sock, op, args, 5_000),
      log: (m) => console.error(m),
      pid: process.pid,
      platform: platform.id,
      readFile: (p) => { try { return readFileSync(p, "utf8"); } catch { return null; } },
    });
    // An earlier session that died with a twin's stat in an index
    // (twin-index-stat.ts): put back BEFORE this launch writes its own, so
    // this launch's launch stat is never a dead session's twin stat.
    timer.step("secrets");
    if (platform.id === "linux") {
      for (const root of restorePendingFromStores(twinIndexReadStores(process.env, homedir()), { log: (m) => console.error(m) })) {
        console.error(`mandu: ${root}: put back the index stat of a protected file an earlier session left (git there no longer shows it modified)`);
      }
    }
    try {
      secretResult = await applySecretTwins(plan, scopeRunDir, mut, {
        // The human socket carries the git-history caches' seals (plan 14 §11.2).
        arbiter: withPrefetchedDiscovery(socketSecretArbiter(plan.arbiterSock, { humanSock: plan.arbiterHumanSock ?? null }), discovery),
        commandExists: (c) => commandExists(c),
        usernsOk: () => usernsOk(),
        platform: platform.id,
        log: (m) => console.error(m),
        workspaceRoots: [launchDir],
        // Phase 6 (plan 10 §11.7): with the guard around the launch, the twins
        // are served by descriptor and a host without a user namespace is
        // still confined.
        guardServesTwins: netGuard !== null,
        ...(twinPrefetch !== null ? { twinPrefetch } : {}),
        ...(gitSession !== null ? { gitSession } : {}),
        // The agent's own key file (Goose's secrets.yaml): registered, left
        // readable to it (agent-login.ts agentOwnCredentialFiles), unless the
        // grant above lets it be twinned.
        agentOwnFiles: keyGrant.granted ? [] : agentOwnCredentialFiles(plan.target, env),
        ...(codexGrant.granted ? { grantedLoginFiles: [codexGrant.path!] } : {}),
        // Its parts' times (launch-timings.ts): the walk's wait, the history step, …
        timer,
      });
    } finally {
      closeTwinReads();
    }
    copiesInUse = keepCopiesInUse(secretResult.objectCopyDirs ?? []);
    // Twinned: confined, or the mount layer alone (gated for want of a guard,
    // the twin still bound); a host gap binds nothing and the file stays raw.
    const twinsBound = secretResult.posture === "confined" ||
      (secretResult.posture === "gated" && (secretResult.gap === "no-guard" || secretResult.gap === "guard-off"));
    if (codexGrant.granted && twinsBound) {
      const twin = secretResult.confined.find((c) => c.path === codexGrant.path)?.twin;
      const placeholder = codexTwinPlaceholder(twin);
      if (placeholder !== null) {
        services.setUllmKey?.({ standIn: placeholder, key: codexGrant.key! });
        console.error(`mandu: ${codexGrant.path} is a placeholder in Codex's world; the model proxy puts its key back in the auth header to ${codexGrant.hosts!.join(", ")} only`);
      }
    }
    // An earlier session that ended before it could check its repositories
    // for a placeholder commit (a crash, a kill; placeholder-commits.ts):
    // checked now, its WARNING printed whole before the agent starts, and
    // checked again after it exits. After the secret setup, whose store-link
    // check has refused a store in the home swapped for a link outside it
    // (the check itself also reads and cleans only a real folder inside the
    // home). Only an lstat when there is none. Each git call short, and no
    // further record or repository once the budget is spent (a record not
    // started waits for the next launch; one cut short, or whose git failed,
    // stays on disk until it is checked again after the agent exits): the
    // launch waits for this.
    timer.step("placeholder-check");
    if (platform.id === "linux") {
      const pending = await checkPendingPlaceholderRecords(placeholderChecks, placeholderHome, {
        timeoutMs: WATCH_GIT_TIMEOUT_MS, budgetMs: PENDING_LAUNCH_BUDGET_MS,
      });
      earlierPlaceholder = pending.records;
      earlierKept = pending.kept;
      for (const l of pending.blocks.flatMap((b) => b.lines)) lc.foldNow(l);
    }
    // The protected files in a git work tree: recorded in the Mandu home
    // (where the agent can neither read nor write) before the agent starts,
    // checked after it exits; the record is the next launch's to check if
    // this one never gets there.
    if (secretResult.placeholderWatch !== undefined) {
      placeholderRecord = newPlaceholderRecord(plan.scopeId, secretResult.placeholderWatch);
      placeholderFile = writePlaceholderRecord(placeholderChecks, placeholderHome, placeholderRecord);
    }
    // The environment half of the same registry (plan 10 §11.4): secret-shaped
    // variables reach the agent as symbols. After the twins (same axis rule),
    // before the reply filter (which shows the human the real values).
    timer.step("env-secrets");
    envResult = await applyEnvSecrets(plan, env, mut, {
      arbiter: socketSecretArbiter(plan.arbiterSock),
      log: (m) => console.error(m),
      ...(envGranted.length > 0 ? { agentKeys: envGranted.map((g) => g.name) } : {}),
    });
    for (const g of envGranted) {
      if (!envResult.masked.includes(g.name)) continue;
      console.error(`mandu: ${g.name} is a placeholder in ${plan.target === "goose" ? "Goose" : plan.target === "codex" ? "Codex" : "Claude Code"}'s environment; the model proxy puts the key back in the auth header to ${g.hosts.join(", ")} only`);
    }
    for (const g of providerGrants) {
      if (!envResult.masked.includes(g.name)) continue;
      console.error(`mandu: ${g.name} is a placeholder in the session's environment; the egress proxy puts the key back in requests to ${g.hosts.join(", ")} only`);
    }
    if (envKeyGrant.granted && envResult.masked.includes(envKeyGrant.name!)) {
      // Claude Code's "use this API key?" answer, carried over to the
      // placeholder (claude-trust.ts inheritApiKeyApproval): without it the
      // interactive start asks again, defaulting to No.
      const placeholder = mut.env[envKeyGrant.name!];
      const realKey = env[envKeyGrant.name!];
      if (placeholder !== undefined && realKey !== undefined) {
        const a = inheritApiKeyApproval({ configDir: env["CLAUDE_CONFIG_DIR"] || env["HOME"] || homedir(), realKey, placeholder });
        if (a.action === "error") console.error(`mandu: could not carry your API-key answer over to the placeholder (${a.reason}); Claude Code may ask about the key again`);
      }
    }
    // sandbox-security-review-2026-09-28 findings 2 and 6: the paths the
    // agent's tree may not change (Mandu's own files: refused; files that run
    // later outside Mandu: held for the human in the Inbox). Enforced by the
    // guard, so only with one; in every mode but `off` (the open trap it
    // needs costs about 25 µs an open). MANDU_WRITE_PROTECT=0 opts out.
    // policy.yaml write_protect: / unix_sockets: add to (and opt out of) both
    // lists below (guard-settings.ts).
    timer.step("compose");
    const guardSettings = netGuard !== null && platform.id === "linux" ? await readGuardSettings(plan.arbiterSock, (m) => console.error(m)) : NO_GUARD_SETTINGS;
    if (netGuard !== null && platform.id === "linux" && modeOf(plan.effectiveAxes!) !== "off" && env["MANDU_WRITE_PROTECT"] !== "0") {
      // The home is one refused entry; the frozen integrity modes carve their
      // AgentView (and `full` its repo.git) out of it (on-disk-layout.md §4).
      const carveOuts = launchHomeCarveOuts(plan, env["HOME"] ?? homedir(), env);
      writeProtected = true;
      // OpenCode 2: the launcher's config directory too (agent-config.ts
      // opencodeLockdownEnv; supported-agents.md §2.3 item 8).
      // The SDK route's folder (the route the hooks and shims apply) and the
      // PATH shims' folder (agent-sdks.md §3.6): never written by the agent.
      const ownDirs = [...(plan.target === "opencode" ? [opencodeWriteProtect(scopeRunDir)] : []), ...sdkRouteWriteProtect(scopeRunDir)];
      // Mandu's runtime registries (instances/, current, the dashboards, the
      // VM guests, the logs, the human plane) under this launch's base and the
      // account's default base and rendezvous, as the macOS profile has them
      // (runtime-instances.md §2, "planted paths"). One that holds what the
      // agent must keep writable refuses the launch rather than drop the rule.
      const registryBases = [plan.arbiterRuntimeBase, ...accountRegistryBases(env)];
      const wpWorkspace = plan.humanCwd || launchDir;
      const spellings = (p: string): string[] => { try { return [p, realpathSync(p)]; } catch { return [p]; } };
      const held = registryHolding(runtimeRegistryProtect(registryBases), [wpWorkspace, scopeRunDir].flatMap(spellings));
      if (held !== null) {
        throw new Error(
          `mandu: refusing to launch: ${held.holds} lies in ${held.entry}, one of Mandu's runtime registries, which the agent may never write ` +
            "(runtime-instances.md §2). Launch from another folder, or point MANDU_RUNTIME_DIR somewhere else.",
        );
      }
      applyWriteProtect([...writeProtectList(env, wpWorkspace, undefined, plan.arbiterSock, guardSettings.writeProtect, (m) => console.error(m), carveOuts, "linux", undefined, registryBases), ...ownDirs], mut.env, {
        log: (m) => console.error(m),
        scopeRunDir,
        agentExe: resolveAgentExe(plan),
        session: plan.scopeId,
        askTimeoutMs: Number(process.env["MANDU_SECRETS_ASK_TIMEOUT"] ?? "") || 60_000,
      });
    }
    // sandbox-security-review-2026-09-28 finding 1: with the confidentiality
    // axis on, the agent's tree reaches only listed Unix sockets and the ones
    // it opens itself (host services that run code on request, which would
    // read the real files, are refused). MANDU_UNIX_POLICY=0 opts out.
    if (netGuard !== null && platform.id === "linux" && plan.effectiveAxes!.confidentiality && env["MANDU_UNIX_POLICY"] !== "0") {
      applyUnixPolicy(unixPolicy(env, {
        arbiterSock: plan.arbiterSock, scopeRunDir, extra: guardSettings.unixAllow, humanDirs: plan.humanPlaneDirs,
        onRefused: (p, label) => console.error(`WARNING: mandu: unix socket allow entry ${p} (${label}) dropped — it reaches Mandu's human plane, which the agent may never connect to`),
      }), mut.env, {
        log: (m) => console.error(m),
        scopeRunDir,
        agentExe: resolveAgentExe(plan),
        session: plan.scopeId,
      });
      // The session bus is out of the agent's reach now, and with it the
      // system keyring: a Goose whose key is only there cannot log in
      // (agent-login.ts gooseKeyringNote, supported-agents.md §5.6.1).
      const keyringNote = gooseKeyringNote(plan.target, plan.argv, realLoginProbeDeps(env));
      if (keyringNote !== null) console.error(keyringNote);
    }
    // Plan 13 §4.9 (2026-10-07, "refuse raw if visible"): while a network or
    // FUSE mount is visible, the guard serves readers the placeholder (it
    // would see every name a holder looks up). policy.yaml
    // remote_mounts.trust_lookups reaches the guard here, and the launch
    // names the mounts so the user knows why (remote-mounts.ts).
    if (netGuard !== null && platform.id === "linux" && plan.effectiveAxes!.confidentiality && mut.env["MANDU_NET_GUARD_SECRETS"]) {
      applyTrustLookups(guardSettings.trustLookups, mut.env, {
        scopeRunDir, agentExe: resolveAgentExe(plan), session: plan.scopeId, home: env["HOME"] ?? homedir(),
      });
      let mountinfo = "";
      try { mountinfo = readFileSync("/proc/self/mountinfo", "utf8"); } catch { /* none to name */ }
      for (const n of remoteMountNotes(visibleRemoteMounts(mountinfo), expandTrust(guardSettings.trustLookups, env["HOME"] ?? homedir()))) console.error(n);
    }
    // The human plane's guard wall (arbiter-human-plane.md §5): an ALWAYS-DENY
    // Unix-connect entry for the human-plane directories, whatever the
    // allow-list above did (MANDU_UNIX_POLICY=0 included) and on either axis.
    // Only `off` (observe only) goes without: nothing hides Mandu's stores
    // from the agent there, so this wall would close nothing.
    if (netGuard !== null && platform.id === "linux" && modeOf(plan.effectiveAxes!) !== "off") {
      humanDenied = (plan.humanPlaneDirs ?? []).length > 0;
      applyHumanPlaneDeny(plan.humanPlaneDirs ?? [], mut.env, {
        log: (m) => console.error(m),
        scopeRunDir,
        agentExe: resolveAgentExe(plan),
        session: plan.scopeId,
      });
    }
    // macOS (confidentiality.md §7.3): the guard and landlock-net have no
    // counterpart, so ONE Seatbelt profile around the whole agent carries
    // their rules: the credential files (from the secret setup), Mandu's own
    // state (`secrets` mode), the write-protect list (every mode but `off`;
    // `ask` entries refused), the network port set (above), the Unix-socket
    // list and the host-service programs (confidentiality axis on), the
    // arbiter's human plane (every mode but `off`, as the guard's `unixDeny`
    // on Linux) and Mandu's runtime registries (every mode but `off`; no
    // Linux counterpart yet). Each switch is the Linux one (MANDU_WRITE_PROTECT=0,
    // MANDU_UNIX_POLICY=0, --no-landlock-net). Applied here, INSIDE the reply
    // filter below, which keeps the human channel.
    let seatbeltApplied = false;
    let seatbeltHumanDenied = false;
    // Plan 14 §11.2, §11.3: the launch record's macOS claim that the one
    // profile denies everything under it every direct read and write of the
    // Mandu home (seatbelt-setup.ts `profileSealsHome`, which also says what
    // it does not cover: code a system service runs outside the profile).
    let seatbeltHomeSealed = false;
    if (platform.id === "darwin") {
      const axes = plan.effectiveAxes!;
      const wpOn = modeOf(axes) !== "off" && env["MANDU_WRITE_PROTECT"] !== "0";
      const unixOn = axes.confidentiality && env["MANDU_UNIX_POLICY"] !== "0";
      const darwinSettings = seatbeltOk && (wpOn || unixOn) ? await readGuardSettings(plan.arbiterSock, (m) => console.error(m)) : NO_GUARD_SETTINGS;
      const workspace = plan.humanCwd || launchDir;
      // The frozen integrity modes carve their AgentView (and `full` its
      // repo.git) out of the refused home, as on Linux (on-disk-layout.md §4).
      const carveOuts = wpOn ? launchHomeCarveOuts(plan, env["HOME"] ?? homedir(), env) : [];
      const sb = applySeatbelt({
        plan,
        env,
        scopeRunDir,
        secrets: secretResult.seatbelt,
        sealState: axes.confidentiality && !axes.integrity,
        // With the SDK route's and the PATH shims' folders (agent-sdks.md §3.6).
        writeProtect: wpOn ? [...writeProtectList(env, workspace, undefined, plan.arbiterSock, darwinSettings.writeProtect, (m) => console.error(m), carveOuts, "darwin"), ...sdkRouteWriteProtect(scopeRunDir)] : null,
        net: netConfine?.seatbelt ?? null,
        unix: unixOn
          ? unixPolicy(env, {
              platform: "darwin", arbiterSock: plan.arbiterSock, scopeRunDir, runtimeBase: plan.arbiterRuntimeBase, cwd: workspace,
              extra: darwinSettings.unixAllow, humanDirs: plan.humanPlaneDirs,
              onRefused: (p, label) => console.error(`WARNING: mandu: unix socket allow entry ${p} (${label}) dropped — it reaches Mandu's human plane, which the agent may never connect to`),
            })
          : null,
        humanDirs: modeOf(axes) !== "off" ? plan.humanPlaneDirs ?? [] : [],
        // Mandu's runtime registries (instances/, current, the dashboards,
        // the logs): never written by the agent, in every mode the human
        // plane is walled (runtime-instances.md §2). Under this launch's base
        // and, when it has one of its own (MANDU_RUNTIME_DIR), under the
        // account's default base and rendezvous too, where the user's
        // resident stack lives.
        runtimeRegistry: modeOf(axes) !== "off",
        registryBases: accountRegistryBases(env),
        available: seatbeltOk,
      }, mut, { log: (m) => console.error(m) });
      seatbeltApplied = sb !== null;
      // The launch record (beginLaunchRecord below) claims only what the
      // applied profile enforces: the home write-protected when the profile
      // carrying write-protect is on, and sealed when every part of the seal
      // is in it (plan 14 §11.2).
      writeProtected = seatbeltApplied && wpOn;
      seatbeltHomeSealed = sb?.homeSealed === true;
      seatbeltHumanDenied = sb?.humanPlaneWalled === true;
    }
    // macOS: an agent's OWN per-command sandbox cannot start inside the
    // profile just applied (no nesting), so Mandu turns it off for the
    // session, unless the run asks for it, an administrator requires it, or
    // it protects something Mandu does not (codex-sandbox.ts,
    // claude-sandbox.ts). Gated on the profile REALLY applied, in every mode:
    // without one, the agent's own sandbox works and stays on. One line each,
    // through the hooked console (launch.log, the posture event).
    const darwinAgentBox = platform.id === "darwin" && seatbeltApplied;
    if (darwinAgentBox && plan.target === "codex") {
      // Codex's project config layers are read where Codex runs (plan.cwd),
      // and under the run's own -C / --cd.
      const codexCwd = plan.cwd || launchDir;
      const cd = codexArgvCd(plan.argv);
      const cx = codexSandboxLaunch(plan.target, plan.argv, realCodexSandboxDeps(env, codexCwd, cd !== null ? [resolve(codexCwd, cd)] : []), { outerSeatbelt: true, credsBlocked: secretResult.posture === "read-blocked" });
      if (cx.note !== null) console.error(cx.note);
      // Appended, never prepended: the routing overrides stay first, and
      // codex-argv.ts splices the whole list at every command level.
      mut.argvPrefix.push(...cx.inject);
    }
    if (darwinAgentBox && plan.target === "claude" && isClaudeBinary(plan.argv[0]) && claudeRunsSession(plan.argv)) {
      const home = env["HOME"] ?? homedir();
      const readFile = (p: string): string | null => { try { return readFileSync(p, "utf8"); } catch { return null; } };
      // Every source Claude Code reads (claude-sandbox.ts): a rule Mandu
      // never saw must not be dropped by turning the sandbox off.
      const files = claudeSettingsFiles(home, launchDir, "darwin", claudeSettingsLocations(env, home, launchDir, "darwin"));
      const view = readClaudeSandbox(readClaudeSettingsSources(files, { readFile, readPlistJson: realReadPlistJson, exists: existsSync }), home, launchDir);
      const bin = plan.argv[0]!;
      // The status probe only on a Claude Code known to have it (an older one
      // could take "sandbox status" for a prompt); else the files decide.
      const probeOk = claudeStatusProbeAllowed(plan.agentVersion);
      const cp = planDarwinClaudeSandbox({
        argv: plan.argv,
        argvPrefix: mut.argvPrefix,
        view,
        confined: secretResult.confined.map((c) => c.path),
        maskedEnv: envResult.masked,
        probe: probeOk ? (args) => realClaudeSandboxStatus(bin, args, env, launchDir) : () => null,
        readFile: readClaudeSettingsFile,
        home,
        credsBlocked: secretResult.posture === "read-blocked",
        managedPath: claudeManagedSettings("darwin"),
        // Where secret discovery looks (secret-setup: HOME and the workspace).
        scanRoots: [home, launchDir],
      });
      for (const n of cp.notes) console.error(n);
      if (cp.argv) plan.argv.splice(0, plan.argv.length, ...cp.argv);
      if (cp.argvPrefix) mut.argvPrefix.splice(0, mut.argvPrefix.length, ...cp.argvPrefix);
    } else if (plan.target === "claude" && secretResult.posture !== "off") {
      // Plan 10 §12.3: coexistence with Claude Code's OWN sandbox and mask. A
      // file both sides mask is a double placeholder (warned, the setting to
      // remove named); with its sandbox on, the arbiter socket rides through
      // sandbox.network.allowUnixSockets so the shims inside it keep their
      // channel. Nothing here changes what Mandu enforces.
      const cx = checkClaudeSandbox({
        home: env["HOME"] ?? homedir(),
        locations: claudeSettingsLocations(env, env["HOME"] ?? homedir(), launchDir, platform.id === "darwin" ? "darwin" : "linux"),
        readPlistJson: realReadPlistJson,
        cwd: launchDir,
        confined: secretResult.confined.map((c) => c.path),
        maskedEnv: envResult.masked,
        arbiterSock: plan.arbiterSock,
        humanDirs: plan.humanPlaneDirs ?? [],
        // macOS: Claude Code's own sandbox cannot nest inside Mandu's Seatbelt
        // profile, so the WARNING is for a launch that really applied one.
        ...(platform.id === "darwin" ? { outerSeatbelt: seatbeltApplied } : {}),
      });
      for (const n of cx.notes) console.error(n);
      if (cx.settingsOverlay !== null && isClaudeBinary(plan.argv[0])) mergeClaudeSettingsArg(mut.argvPrefix, cx.settingsOverlay);
    }
    // supported-agents.md §6.5: Codex's own command sandbox refuses every
    // connect while its network is off, Mandu's checks included, so a curl
    // with a bound key can never run. Open it where Mandu's guard decides
    // instead, unless the user's Codex config or command line chose; always
    // said at launch (codex-shell-network.ts).
    if (plan.target === "codex" && codexOverridesReach(plan.argv[0])) {
      const cxNet = codexShellNetworkDecision({
        wanted: plan.codexShellNetwork,
        argv: plan.argv,
        layers: readCodexNetworkLayers({
          home: env["HOME"] ?? homedir(),
          ...(env["CODEX_HOME"] ? { codexHome: env["CODEX_HOME"] } : {}),
          cwds: [...new Set([plan.cwd, plan.humanCwd].filter((d): d is string => !!d))],
          profile: codexArgvSandbox(plan.argv).profile,
        }),
        guarded: netGuard !== null,
        confidentiality: plan.effectiveAxes!.confidentiality,
        linux: platform.id === "linux",
      });
      if (cxNet.open) mut.argvPrefix.push(...CODEX_SHELL_NETWORK_OVERRIDE);
      if (cxNet.note !== null) console.error(cxNet.note);
    }

    // User-reply egress filter (packaging.md §5): default-on wrapper that
    // desymbolizes the agent's stdout for the human, prepended as the launch
    // prefix (utility-only — degrades to no wrapper if its runtime is missing).
    // Started early (packaging.md §5.3): nothing is prepended, and the
    // filter's own variables travel in its hand-off instead of mut.env.
    replyFilterWiring = applyReplyFilter(plan, layout, mut, undefined, undefined, { handOff: replyFilterSlot.started });

    // Shrink the wrapped agent's non-essential phone-home surface (exec-routing.md
    // §7.4): Claude Code's `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC` turns off
    // telemetry / error-reporting / surveys in one switch (data-usage.md). A
    // defense whose whole job is egress control should not emit session metadata
    // by default, and under --landlock-net-strict this also removes traffic that
    // would otherwise be denied. Default-if-unset via mut.env so it flows through
    // BOTH the direct childEnv and the systemd --setenv path; an explicit user
    // value (ambient env) is left untouched (they can opt back in with =0).
    // The `shell` target gets it too: it carries claude's env routing, so a
    // `claude` started from that shell is the same client (agent-e2e-harness.md §9.1).
    if ((plan.target === "claude" || plan.target === "shell") && env["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] === undefined) {
      mut.env["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] = "1";
    }
    // Every settings source Claude Code reads for a launch here (the global
    // config, the user, project, local and managed files), read once: the
    // routing check below and the permission mode (claude-permission-mode.ts)
    // both judge them.
    let claudeLayersRead: ClaudeRouteLayer[] | null = null;
    const claudeLayers = (): ClaudeRouteLayer[] => {
      if (claudeLayersRead !== null) return claudeLayersRead;
      const home = env["HOME"] ?? homedir();
      const plat = platform.id === "darwin" ? "darwin" : "linux";
      return (claudeLayersRead = readClaudeRouteLayers({
        env, home, cwd: launchDir, platform: plat,
        locations: claudeSettingsLocations(env, home, launchDir, plat),
        readPlistJson: realReadPlistJson,
      }));
    };

    // NODE_USE_ENV_PROXY (env-compose.ts) makes every Node process print an
    // "EnvHttpProxyAgent is experimental" warning on stderr: into the user's
    // terminal, and into every Node tool result the model reads. Silence that
    // one code, keeping the user's own NODE_OPTIONS.
    // A Node before 20.11 / 21.3 refuses to START with that flag in
    // NODE_OPTIONS, so it is added only when the agent's own `node` takes it.
    if (mut.env["NODE_USE_ENV_PROXY"] === "1") {
      const pathNode = probeNodeVersion(mut.env["PATH"] ?? env["PATH"]);
      if (nodeTakesDisableWarning(pathNode)) {
        mut.env["NODE_OPTIONS"] = withNodeOption(env["NODE_OPTIONS"], "--disable-warning=UNDICI-EHPA");
      }
      // The same `node` older than 22.21 (or 24.5) ignores NODE_USE_ENV_PROXY:
      // its programs' requests go around the proxy, so with TLS inspection on
      // their placeholders are never filled in and their logins fail with no
      // explanation (plan 13 §10.2). One notice line, from the probe above
      // (no second run); `mandu doctor` has the fix.
      const nodeNote = plan.mitmCaCert ? nodeEnvProxyNotice(nodeEnvProxyGap(pathNode)) : null;
      if (nodeNote !== null) showNote(nodeNote, undefined, true);
    }

    // The SDK route (agent-sdks.md, sdk-route.ts): a host program run under a
    // language runtime (`--target claude|codex -- node app.js`) starts the
    // agent CLI itself, through an SDK whose `env` option replaces the
    // child's environment and, for Codex, whose command line Mandu never
    // sees. The preload keeps the routing on every child the host's Node
    // starts. Composed LAST, from the whole delta, so the route carries the
    // values the launch really runs with. FAIL-CLOSED: a route that cannot be
    // delivered refuses the launch (a Codex host would otherwise run unrouted).
    // A `claude` the host starts gets Claude Code's default permission mode
    // as a `mandu claude` does (claude-permission-rule.cjs): the preload
    // decides per child, from which settings scopes here set a mode.
    const claudeModeHere = () => ({ cwd: launchDir, configDir: claudeConfigDir(env, env["HOME"] ?? homedir()), scopes: claudeModeScopes(claudeLayers()) });
    const claudeModeTarget = plan.target === "claude" || plan.target === "shell";
    const sdkClaudeMode = claudeModeTarget && sdkRouteApplies(plan) !== null ? claudeModeHere() : undefined;
    // The same route rides into Python (the hook on PYTHONPATH asks this
    // preload to decide each agent child, with this launcher's own Node) and
    // into the PATH shims, which route or refuse an agent CLI found by name
    // (a shell command string, a Bun or Deno host's bare `codex`).
    const sdkPreload = layout.asset(SDK_ROUTE_ASSET);
    const permissionRule = layout.asset(CLAUDE_PERMISSION_RULE_ASSET);
    const sdkPython = layout.asset(SDK_ROUTE_PYTHON_ASSET);
    const sdkShimDir = join(scopeRunDir, SDK_SHIM_DIR);
    // The route lives in a file the agent cannot write (agent-sdks.md §3.6):
    // the launch's copies of the preload and the Python hook read it from
    // beside themselves, and the shims name the preload copy by full path.
    const sdkFiles = sdkRouteFiles(join(scopeRunDir, SDK_ROUTE_DIR));
    let claudeShim: ClaudeShimRoute | null = null;
    // The route carries the launch's own value of every routing variable
    // (SdkRoute.launchRouting, from the environment the agent is launched
    // with), checked against the agent's environment below.
    const sdkRoute = composeSdkRoute(plan, mut.env, envResult?.masked ?? [], sdkFiles.preload, sdkClaudeMode, {
      pythonPath: sdkFiles.pythonDir, node: process.execPath, shimDir: sdkShimDir,
    }, withoutLauncherOnlyEnv(withoutHumanSock(env)));
    if (sdkRoute !== null) {
      for (const [what, file] of [["preload", sdkPreload], ["permission-mode rule", permissionRule], ["Python hook", sdkPython]] as const) {
        if (!existsSync(file)) {
          throw new Error(`mandu: the SDK route's ${what} is missing (${file}); reinstall Mandu. Refusing to launch a host program whose agent CLI would run unrouted.`);
        }
      }
      writeSdkRouteDir(sdkFiles.dir, sdkRoute, { preload: sdkPreload, rule: permissionRule, python: sdkPython });
      writeSdkShims(sdkShimDir, process.execPath, sdkRoute.require);
      Object.assign(mut.env, sdkRouteEnv(sdkRoute, {
        nodeOptions: mut.env["NODE_OPTIONS"] ?? env["NODE_OPTIONS"],
        pythonPath: mut.env["PYTHONPATH"] ?? env["PYTHONPATH"],
        path: mut.env["PATH"] ?? env["PATH"] ?? plan.basePath,
      }));
    } else if (claudeModeTarget) {
      // Every other claude or shell launch (`mandu claude`, `mandu -- bash`):
      // a `claude` started by name anywhere in the session (from that shell,
      // a script, the agent's own Bash tool) meets the `claude` PATH shim,
      // which routes it as this launch routes `mandu claude` below
      // (agent-sdks.md §3.5): its settings files (the user's, the project's,
      // one the agent writes) apply `env` over its environment, and an
      // `env.ANTHROPIC_BASE_URL` there would send its model traffic, the
      // files it reads, around the model proxy. Mandu never sees that
      // command line otherwise. The same shim applies the permission-mode
      // rule (supported-agents.md §2). Only when a real `claude` is on PATH,
      // so a shell user without Claude Code keeps an honest `command -v
      // claude`. FAIL-CLOSED: a missing preload refuses the launch.
      const agentPath = mut.env["PATH"] ?? env["PATH"] ?? plan.basePath;
      const realClaude = realExecutable("claude", agentPath, sdkShimDir, nodeFs, nodePath);
      if (realClaude !== null) {
        for (const [what, file] of [["preload", sdkPreload], ["permission-mode rule", permissionRule]] as const) {
          if (!existsSync(file)) {
            throw new Error(`mandu: the claude shim's ${what} is missing (${file}); reinstall Mandu. Refusing to launch a session whose own \`claude\` could run unrouted.`);
          }
        }
        claudeShim = claudeShimRoute({ ...withoutLauncherOnlyEnv(withoutHumanSock(env)), ...mut.env }, claudeModeHere());
        writeClaudeShim(sdkShimDir, process.execPath, sdkPreload, claudeShim);
        mut.env["PATH"] = withHead(sdkShimDir, agentPath);
        // `mandu claude` itself starts the real one by path: the launch
        // applies the rule to its own command line below, and the agent
        // needs no extra Node in front of it.
        if (plan.target === "claude" && plan.argv[0] === "claude") plan.argv[0] = realClaude;
      }
    }
    const hostNote = sdkHostNote(plan);
    if (hostNote !== null) console.error(hostNote);

    // The agent never inherits the human-plane socket (human-plane.ts): an
    // ambient MANDU_ARBITER_HUMAN_SOCK is dropped here; the reply filter got
    // its own through mut.env (applyReplyFilter) or its hand-off, and removes
    // it from its child's environment.
    // Its PWD is the directory it is spawned in (plan.cwd: the launch
    // directory, or its AgentView), never the launcher's inherited one,
    // which may name another folder (launch-cwd.ts) or the HumanView.
    // The human socket and Mandu's own helper key (MANDU_ULLM_API_KEY,
    // agent-sign-in.md §3.11) never reach the agent's process tree.
    const agentEnv = { ...withoutLauncherOnlyEnv(withoutHumanSock(env)), PWD: plan.cwd };
    const childEnv: Record<string, string | undefined> = { ...agentEnv, ...mut.env };
    // The `claude` shim's route and the SDK route's launch values were
    // composed above, from the delta as it was then: a routing variable
    // composed since would leave a nested or SDK-started agent routed by a
    // stale value. FAIL-CLOSED.
    if (claudeShim !== null && JSON.stringify(claudeShim.env) !== JSON.stringify(claudeRouteEnv(childEnv))) {
      throw new Error("mandu: internal: the claude shim's routing differs from the agent's environment; refusing to launch.");
    }
    if (sdkRoute !== null && JSON.stringify(sdkRoute.launchRouting) !== JSON.stringify(claudeRouteEnv(childEnv))) {
      throw new Error("mandu: internal: the SDK route's routing differs from the agent's environment; refusing to launch.");
    }
    // OpenCode 2 with confidentiality ON (opencode2-confidentiality.ts): the
    // composed launch must carry every guard the early check admitted it
    // on. A step that degraded on the way stops the launch here, before the
    // agent exists.
    if (opencode2Launch && plan.effectiveAxes!.confidentiality) {
      let guardPolicy: Parameters<typeof opencode2ConfidentialityUnenforced>[0]["guardPolicy"] = null;
      try { guardPolicy = JSON.parse(readFileSync(mut.env["MANDU_NET_GUARD_SECRETS"] ?? "", "utf8")) as typeof guardPolicy; } catch { /* absent: unenforced */ }
      const unenforced = opencode2ConfidentialityUnenforced({
        guardWrap: netGuard?.wrapArgv ?? null,
        env: childEnv,
        ownServerExe: plan.ownServerExe,
        guardPolicy,
        configDir: opencodeConfigDirOf(scopeRunDir),
      });
      if (unenforced.length > 0) throw new Error(opencode2ConfidentialityRefusal(modeOf(plan.effectiveAxes!), unenforced));
    }
    scope = platform.planScope({
      scopeId: plan.scopeId,
      env: mut.env, // marshalled into the systemd scope via --setenv
      noScope: plan.noScope,
      ...scopeProbes,
    });
    // When systemd carries env via --setenv, don't also double-set it on the child.
    finalEnv = scope.prefix.length ? { ...agentEnv } : childEnv;
    // Plan 10 §11.13.1: Codex drops HTTPS_PROXY / NO_PROXY /
    // NODE_USE_ENV_PROXY for a stdio MCP server (measured on 0.159.1); forward
    // them by each configured server's own `env_vars`, so an npx-launched
    // server reaches its registry through the session proxy (wire-release.ts).
    if (plan.target === "codex" && plan.netProxy && codexOverridesReach(plan.argv[0])) {
      mut.argvPrefix.push(...codexMcpProxyEnvOverrides(configuredMcpServers({
        target: "codex",
        home: env["HOME"] ?? homedir(),
        ...(env["CODEX_HOME"] ? { codexHome: env["CODEX_HOME"] } : {}),
        humanCwd: plan.humanCwd,
        agentCwd: plan.cwd,
      })));
    }
    // Claude Code's routing in the last --settings it reads (claude-route.ts):
    // every routing variable with the value the agent really gets, so a
    // user, project, local or global settings file, including one the agent
    // writes mid-session, cannot re-point the model traffic. A managed source
    // that sets one to another value outranks it: refused. A lower one is
    // named. An SDK host's `claude` children get the same from the preload.
    if (claudeSession) {
      const layers = claudeLayers();
      const claudeArgv = isClaudeBinary(plan.argv[0]) ? plan.argv : [plan.argv[0] ?? "claude"];
      const verdict = claudeRouteRefusal(claudeArgv, childEnv, layers);
      if ("refusal" in verdict) throw new Error(verdict.refusal);
      for (const n of verdict.notes) console.error(n);
      if (isClaudeBinary(plan.argv[0])) {
        // Claude Code's default permission mode unless the user chose one
        // (claude-permission-mode.ts): without the feature flags the launch
        // turns off above, Claude Code would start in `auto`. Decided on the
        // user's own command line and settings, before Mandu's --settings.
        if (claudePermissionModeDecision(plan.argv, layers, readClaudeSettingsFile).inject) {
          mut.argvPrefix.push(...CLAUDE_DEFAULT_PERMISSION_ARGS);
        }
        const routed = claudeRouteArgs(plan.argv, mut.argvPrefix, claudeRouteOverlay(childEnv));
        if ("refusal" in routed) throw new Error(routed.refusal);
        plan.argv.splice(0, plan.argv.length, ...routed.argv);
        mut.argvPrefix.splice(0, mut.argvPrefix.length, ...routed.prefix);
      }
    }
    finalArgv = buildFinalArgv(plan.argv, mut.argvPrefix, scope, mut.launchPrefix);
    // The early-started filter's hand-off (packaging.md §5.3): what the
    // serial form would have run it with. It runs the scope prefix itself,
    // in front of the command; its environment is the serial form's (the
    // composed env plus the human-plane socket, in both scope forms).
    if (replyFilterSlot.started && replyFilterWiring !== null) {
      filterHandoff = {
        cmd: buildFinalArgv(plan.argv, mut.argvPrefix, { prefix: [], detached: scope.detached }, mut.launchPrefix),
        outer: scope.prefix,
        env: { ...childEnv, ...replyFilterWiring.filterEnv },
        cwd: plan.cwd,
        outputFormat: replyFilterWiring.outputFormat,
      };
    }
    // Plan 10 §11.13.1: this session's proxy inspects TLS, so npm may read
    // the `.npmrc` twin (the arbiter decides per file). Best-effort.
    timer.step("record");
    wireRelease = await registerLaunchWireRelease(plan, env, {
      call: (sock, op, args) => ndjsonCall<unknown>(sock, op, args, 5_000),
      log: (m) => console.error(m),
      pid: process.pid,
    });
    // Plan 10 §11.13: the agent's configured STDIO MCP servers, told to the
    // arbiter on the HUMAN plane before the agent starts, so it can map each
    // server's tool namespace to the process the agent spawns for it
    // (mcp-server-config.ts). Confidentiality axis only; best-effort: a
    // failure or no human socket leaves them unmapped (their results take
    // the session rule) with one WARNING, and never refuses the launch.
    // §11.17: the config is followed through the session (a re-read on
    // every change, registered add-only); the arbiter's stamp check keeps a
    // changed config's servers from `clean` until the re-read lands. The
    // watch says nothing once the agent owns the terminal.
    mcpWatch = (await mapLaunchMcpServers(plan, env, {
      home: env["HOME"] ?? homedir(),
      call: (sock, op, args) => ndjsonCall<unknown>(sock, op, args, 5_000),
      log: (m) => console.error(m),
      watchLog: () => {},
    })).watch;
    mcpWatch?.start();
    // Plan 14 §11.2: the launch, on the arbiter's record before its agent
    // starts. The arbiter classifies it (fail closed); an unconfined launch
    // holds every git-history cache seal void until it ends.
    // Plan 13 D9 leftovers: the record also says whether the agent's world
    // is walled off from the human-plane socket (the guard's deny entry, or
    // the wrap's tmpfs over it); while an unwalled launch is live the
    // arbiter believes no guard or proxy record there.
    // How to sign in to the dashboard, asked now so the answer is ready for
    // the dashboard line (an older dashboard that still mints links refuses
    // one while a launch with no wall is on the record: asked before
    // `beginLaunch`, as before).
    signInAsk = askDashboardSignIn(env);
    const claim: LaunchClaim = {
      pid: process.pid,
      mode: modeOf(plan.effectiveAxes!),
      posture: secretResult?.posture ?? "off",
      writeProtect: writeProtected,
      // macOS only, and only when true: the Linux claim is unchanged.
      ...(seatbeltHomeSealed ? { homeSealed: true } : {}),
      humanPlaneWalled: humanPlaneWalled({
        dirs: plan.humanPlaneDirs ?? [],
        guardDeny: humanDenied,
        launchPrefix: mut.launchPrefix,
        platform: platform.id,
        seatbeltHumanDenied,
      }),
      // Display only: the arbiter names this launch by it while it holds
      // the human plane exposed (arbiter-human-plane.md §10.1.1).
      sessionId: plan.scopeId,
      // The HOME the secret setup found and registered this launch's files
      // under (`homedir()`, as applySecretTwins): the arbiter judges the
      // session's opens against its catalog places (plan 10 §11.13).
      home: homedir(),
      // Display only: a launch that finds the git-history caches void while
      // this one runs unconfined names it by it (plan 14 §11.2.1).
      workspace: launchDir,
    };
    // An unwalled launch waits for its link first, or its own record could
    // reach the arbiter before the dashboard asks and cost it the link. A
    // walled one records nothing that stops minting, so the two overlap.
    if (claim.humanPlaneWalled !== true) await signInAsk.catch(() => null);
    launchRecord = await beginLaunchRecord(plan.arbiterHumanSock, claim, cacheEpochDeps);
    const unrecorded = unrecordedExposureRefusal(plan.arbiterHumanSock, claim, launchRecord, { bestEffort: plan.bestEffort });
    if (unrecorded !== null) {
      if (unrecorded.refuse) {
        // Nothing was recorded, so there is no launch to end.
        launchRecord = null;
        throw new Error(unrecorded.message);
      }
      console.error(unrecorded.message);
    }
    // A multi-line WARNING block is kept whole; before the agent starts it
    // is held for the end of the banner. The default display shows its
    // marked first line as one posture line (lc.sayWhole).
    const sayWhole = (m: string): void => lc.sayWhole(m);
    const beside = concurrentLaunchNotice(claim.posture, launchRecord.others, { requireConfinement: plan.requireConfinement === true });
    for (const l of beside.lines) sayWhole(l);
    if (beside.refuse) {
      await endLaunchRecord(plan.arbiterHumanSock, launchRecord, cacheEpochDeps);
      launchRecord = null;
      throw new Error("mandu: another Mandu launch runs without confinement (--require-confinement)");
    }
    // §10.1.1: while an unwalled launch runs, this walled launch's guard is
    // not believed (fail closed, unchanged). Say so, by name and with the
    // fix: once now (before the agent owns the terminal), then whenever it
    // changes, and a recap after the agent exits. Display only.
    if (watchesHumanPlane(claim, plan.arbiterHumanSock)) {
      humanWatch = humanPlaneWatch(plan.arbiterHumanSock!, {
        call: (sock, op, args) => ndjsonCall<unknown>(sock, op, args, WATCH_CALL_TIMEOUT_MS),
        print: sayWhole,
      });
      await humanWatch.checkNow();
      humanWatch.start();
    }
  } catch (e) {
    humanWatch?.stop();
    mcpWatch?.stop();
    closeTwinReads();
    // No agent ran: nothing for this launch's placeholder check to find,
    // and the index stat the secret setup wrote goes back now.
    removePlaceholderRecord(placeholderFile, placeholderHome);
    endTwinIndex(secretResult);
    // Fail-closed abort AFTER services started (deferred backend, scope
    // planning, argv build): tear down what we started (default-on context
    // proxy / fs-view) instead of orphaning it. runAgent covers the rest via
    // its postExit finally.
    lc.unhook();
    flushNotices();
    lc.releaseLastWords();
    // Same teardown-signal policy as after the agent (teardown-signals.ts).
    const abortTeardown = createTeardownGuard({ note: (m) => origConsoleError(m) });
    abortTeardown.arm();
    try { await services.stop(); } finally { abortTeardown.disarm(); }
    throw e;
  }
  // From here console.error prints as it is, and is copied to the launch's
  // log (the lines said after the agent exits too); main() puts it back.
  lc.tee();
  timer.step("banner");
  // The mode the session really runs under (protection-modes.md §3.2), kept
  // as the mode line (the logs, the posture event) and printed: alone under
  // --verbose, as the start of the one banner line by default.
  const theMode = modeOf(plan.effectiveAxes);
  const secretFacts = secretResult && secretResult.posture !== "off"
    ? {
        confined: secretResult.confined.length,
        posture: secretResult.posture,
        ...(secretResult.structured !== undefined ? { structured: secretResult.structured } : {}),
        ...(envResult ? { envMasked: envResult.masked.length } : {}),
        ...(secretResult.readersPinned !== undefined ? { readersPinned: secretResult.readersPinned } : {}),
      }
    : undefined;
  const theModeLine = modeLine(theMode, secretFacts);
  keepNote(theModeLine);
  if (display === "full") origConsoleError(theModeLine);
  // Where approvals happen (release checklist d4): the newest live dashboard
  // of this user, found through the runtime registry it writes.
  const dash = liveDashboards(env)[0];
  const dashUrl = dash ? dashboardUrl(dash) : null;
  const theDashLine = dashboardLine(dashUrl);
  // KEPT without the link (the logs, the posture event); the terminal gets
  // the line with it, or the plain line and why there is none.
  keepNote(theDashLine);
  const signIn = dash && signInAsk !== null ? await signInAsk.catch(() => null) : null;
  const bannerDash = bannerDashboard(dashUrl, signIn);
  if (display === "full") {
    for (const l of terminalDashboardLines(theDashLine, signIn)) origConsoleError(l);
    for (const n of bannerDash.notes) keepNote(n);
  } else {
    for (const n of bannerDash.notes) showNote(n, undefined, true);
  }
  // Keys in this project the law does not cover (plan 14 §5.5, §13.6: in
  // its repository's history or its files): one notice, only when some wait
  // for the person.
  const theSuggestLine = suggestNotice !== null ? await suggestNotice : null;
  if (theSuggestLine !== null) showNote(theSuggestLine, undefined, true);
  // The default display's ONE banner line, with the count of the notices
  // the log holds; then the short lines (a posture line per warning).
  if (display === "compact") {
    origConsoleError(bannerLine({ mode: theMode, secrets: secretFacts, dashboard: bannerDash.part, notices: lc.noticeCount, hint: lc.hint }));
  }
  lc.flushShort();
  // Then the WARNINGs about another launch beside this one: the last
  // thing on screen when the agent takes the terminal. From here the watch's
  // live lines print as they come (a full-screen agent may paint over them:
  // the recap after it exits says them again).
  lc.releaseLastWords();
  // The full banner, in the session's scope dir for as long as it lives (a
  // clean end removes it, scope-dir-cleanup.ts; the posture event below keeps
  // the same lines) and under --verbose. Best-effort: a failed write costs nothing.
  // Then the steps so far and their times (launch-timings.ts), here, in the
  // launch's own log and on the posture event; the whole launch's go to the
  // launch's log at its end (finishLaunchTimings).
  timer.step("posture");
  const launchTimings = timer.snapshot();
  const launchTimingsLine = timingsLogLine(launchTimings);
  lc.log?.write(launchTimingsLine);
  try {
    mkdirSync(scopeRunDir, { recursive: true });
    publishFile(`${scopeRunDir}/launch.log`, launchNotes.map((n) => n + "\n").join("") + launchTimingsLine + "\n");
  } catch { /* best-effort */ }

  // The launch's posture, on the record (best-effort, never on the launch path).
  await emitLauncherEvent(plan.arbiterSock, launchPostureEvent({
    scopeId: plan.scopeId,
    ...(plan.tenant ? { tenant: plan.tenant } : {}),
    ...(plan.batchId ? { batchId: plan.batchId } : {}),
    ...(plan.batchMember ? { batchMember: plan.batchMember } : {}),
    target: plan.target,
    argv0: plan.argv[0] ?? "",
    notes: launchNotes,
    ...(versionCheck ? { agentVersion: versionCheck.check } : {}),
    ...(secretResult && secretResult.posture !== "off"
      ? { secrets: { posture: secretResult.posture, ...(secretResult.gap ? { gap: secretResult.gap } : {}) } }
      : {}),
    protection: {
      mode: modeOf(plan.effectiveAxes),
      ...plan.effectiveAxes,
      reported: reportedAxes.integrity !== undefined && reportedAxes.confidentiality !== undefined,
    },
    timings: launchTimings,
  }), plan.arbiterHumanSock);

  // The early-started reply filter takes the agent now (packaging.md §5.3):
  // runAgent adopts it as the chain's first process, exactly where the serial
  // form spawned it. Gone ⇒ a fresh one; that failing too ⇒ the chain runs
  // without a filter (utility-only; the WARNING says so).
  timer.step("agent-start");
  const pre = replyFilterSlot.take();
  const adopted = filterHandoff === null ? null : await handOffReplyFilter(
    pre, filterHandoff, scope.detached,
    () => prestartReplyFilter(layout, { detached: scope.detached, cwd: launchDir, env }),
  );
  if (filterHandoff === null) await pre?.abort();

  // Teardown signals (teardown-signals.ts, portable-wrapper.md §2.1): from
  // the agent's exit to this function's return a ^C is ignored, so the
  // service stop, the fs-view sweep and the session-exit event run to the
  // end; SIGTERM / SIGHUP / SIGQUIT keep their default action.
  const teardown = createTeardownGuard({ note: (m) => origConsoleError(m) });
  // What the session untracked of the twinned files git tracked (the index
  // restore at the agent's exit, postExit below), for the exit notice.
  let twinUntracked: Array<{ root: string; rel: string }> = [];
  try {
    // `mandu goose acp`: the editor's JSON-RPC stream goes through the ACP
    // relay (goose-acp-relay.ts): Goose is offered neither the editor's file
    // system nor its terminal, a provider other than the routed one and the
    // desktop's `_goose/*` methods are refused, Mandu's MCP servers are
    // mounted per session. Goose's messages to the editor go through the
    // JSON-aware display pass (goose-acp-display.ts) over the human plane:
    // the editor sees originals, the model's side stays symbolic.
    const acpRelay = plan.target === "goose" && gooseAcpLaunch(plan.argv);
    const acpDesymbolize = acpRelay && plan.acpDisplay !== false && plan.arbiterHumanSock
      ? humanPlaneDesymbolizer(plan.arbiterHumanSock)
      : null;
    const acpRelayRun: { relay: AcpRelay | null } = { relay: null };
    if (acpRelay) {
      const shown = acpDesymbolize !== null
        ? "the editor sees originals where Goose's replies carry symbols"
        : plan.acpDisplay === false
          ? "the reply filter is off, so the editor sees Goose's symbols"
          : "the arbiter names no human-plane socket, so the editor sees Goose's symbols";
      console.error(`mandu: goose acp: the editor's stream goes through Mandu's ACP relay (Goose runs every tool itself, inside this session; ${shown})`);
    }
    timer.step("agent");
    const code = await runAgent({
      argv: finalArgv,
      ...(adopted !== null ? { adopted } : {}),
      ...(acpRelay
        ? {
            stdioRelay: (chain: { stdin: Writable; stdout: Readable }) => {
              acpRelayRun.relay = startAcpRelay({
                editorIn: process.stdin, editorOut: process.stdout, gooseIn: chain.stdin, gooseOut: chain.stdout,
                note: (m) => origConsoleError(m),
                desymbolize: acpDesymbolize,
                opts: {
                  ...(plan.gooseRouting ? { routed: [plan.gooseRouting.provider, plan.gooseRouting.subagentProvider] } : {}),
                  ...(plan.mcpServers ? { mcpServers: plan.mcpServers } : {}),
                },
              });
            },
          }
        : {}),
      env: finalEnv,
      cwd: plan.cwd,
      detached: scope.detached,
      teardown,
      // What the agent left running ends with the session, before the services
      // it was pointed at stop (portable-wrapper-cross-platform.md §3.5): darwin
      // samples the tree from the spawn on and ends the survivors; Linux's
      // kernel scope holds the tree instead, and its killTree does nothing.
      // The age floor is the chain's spawn: a reply filter started with the
      // services is older than this call (reply-filter.ts handOffReplyFilter).
      tree: { track: (pid, sinceMs) => platform.trackTree(pid, { sinceMs }), end: (t) => platform.killTree(t) },
      postExit: async () => {
        // The index stat the secret setup wrote goes back FIRST, the moment
        // the agent is gone (twin-index-stat.ts): the rest of the teardown
        // can take seconds, and a SIGTERM or SIGHUP there (a closed
        // terminal, a harness that kills the pane once the agent exits)
        // keeps its default action and ends the launcher before any later
        // step runs. The exit notice of what the session untracked is said
        // below, with the other notices.
        timer.step("teardown.index");
        twinUntracked = endTwinIndex(secretResult);
        // The ACP relay's last editor-bound lines are written before the
        // services stop (their resolution may still be in flight; bounded).
        timer.step("teardown.services");
        if (acpRelayRun.relay !== null) {
          await Promise.race([acpRelayRun.relay.drained(), new Promise((r) => setTimeout(r, 5_000).unref())]);
        }
        await services.stop();
      },
      // rootless-confinement §12.2: a guard that died before its agent ends
      // the session (its processes fail every trapped syscall) and says so.
      onChainExit: (pid) => {
        if (!netGuarded) return;
        const where = scope.detached
          ? (pid ? { sessionLeader: pid } : null)
          : { scopeUnit: `mandu-${plan.scopeId}.scope` };
        const note = afterGuardedLaunch(netGuardStatusFile(plan), where);
        if (note) console.error(note);
      },
    });
    // Plan 14 §11.1 R4: the repositories whose object files the guard
    // refused (a locked key, no sanitized copy), once each, with the fix;
    // an agent's own git store (OpenCode's snapshots) apart, with nothing to
    // do. Printed after the agent is gone, so a full-screen agent's display
    // is not torn; the dashboard has the event as it happened.
    timer.step("teardown.notices");
    if (netGuarded) {
      const refused = readGitLockRefusals(gitLockNoticeFile(scopeRunDir));
      for (const line of gitLockNoticeLines(refused, env)) console.error(line);
      // R1: each is registered so the arbiter resolves its locks from now on.
      await registerRefusedRepositories(refused, (op, args) => ndjsonCall(plan.arbiterSock, op, args, 5_000));
      // guard-file-identity.md §2: a protected file moved with its folder
      // whose label could not follow (the arbiter down, the rename not
      // undone): the next session would not know its new path.
      for (const line of movedNoticeLines(readMovedNotice(movedNoticeFile(scopeRunDir)))) console.error(line);
    }
    // A protected file's placeholder that git in the session staged or
    // committed (placeholder-commits.ts; confidentiality.md §7.2a): checked
    // outside the agent's world now that it is gone, said with the repair,
    // then the record is cleared. An earlier session's record checked at
    // this launch's start is checked again (the agent may have committed on
    // top, a full-screen agent may have painted over what was said) and
    // said, unless this check just said the very same for that repository:
    // a block whose repair differs is never dropped. Then an earlier record
    // whose check at launch did not complete, kept on disk until now, is
    // removed.
    // The index entries the launch set to its twins' stat were put back
    // when the agent exited (postExit above; here only if that never ran),
    // each to the real file's stat (twin-index-stat.ts) where the entry
    // still holds the twin's. The crash record goes once every entry is
    // back (else the next launch retries). A protected file the session
    // untracked and .gitignore does not name is said: a later `git add -A`
    // would commit the real file.
    timer.step("teardown.placeholder");
    for (const line of await untrackedNotice([...twinUntracked, ...endTwinIndex(secretResult)])) console.error(line);
    const saidNow: CheckBlock[] = [];
    if (placeholderRecord !== null) {
      for (const b of await checkPlaceholderRecord(placeholderRecord)) {
        saidNow.push(b);
        for (const line of b.lines) console.error(line);
      }
      removePlaceholderRecord(placeholderFile, placeholderHome);
    }
    for (const b of unsaidBlocks(saidNow, await recheckEarlierRecords(earlierPlaceholder))) for (const line of b.lines) console.error(line);
    for (const f of earlierKept) removePlaceholderRecord(f, placeholderHome);
    // §10.1.1: the guard's lost attestation, again after the agent is gone
    // (a full-screen agent may have painted over the live lines).
    if (humanWatch !== null) {
      humanWatch.stop();
      for (const line of humanWatch.recap()) console.error(line);
    }
    // A clean end removes the launch's own scope dir (scope-dir-cleanup.ts,
    // runtime-instances.md §10.1); anything else leaves it for `mandu reap`.
    // Decided here (pure), so the notice below can say which; the removal
    // itself comes last. Still under the teardown guard: a ^C here does not
    // cut it short.
    timer.step("teardown.exit");
    const cleanup = scopeDirCleanupDecision({
      scopeRunDir, runtimeBase: plan.arbiterRuntimeBase, scopeId: plan.scopeId,
      scopeIdGenerated: plan.scopeIdGenerated === true, pid: process.pid, code,
      startedPinnedArbiter: !arbiterStart.attached && plan.arbiterSockMode !== "autostart",
      arbiterSock: plan.arbiterSock, keep: (env["MANDU_KEEP_SCOPE_DIR"] ?? "0") !== "0" && env["MANDU_KEEP_SCOPE_DIR"] !== "",
    });
    // Plan 10 §4.1: a write to a registered secret file landed in its
    // placeholder copy (the bind is writable; the guard hands a write the
    // twin), which goes with the scope dir. Name each changed file, by path
    // only, before that: on every display setting, after the agent is gone,
    // saying whether the real file changed too (checked, never assumed).
    // Then the snapshot file goes, so `mandu reap` does not say it again; a
    // launcher that dies before this line leaves it, and reap says it.
    // 2026-10-17: and so did a program's write to a labelled file the
    // launch did not register, in the twin the guard made of it
    // (`derived-twins/`, its records; confidentiality.md §6).
    const twinWatch = secretResult?.twinWatch;
    const twinDir = scopeTwinDir(scopeRunDir);
    const discarded = mergeDiscardedWrites(twinWatch !== undefined ? twinWritesDiscarded(twinWatch) : [], labelledDiscardedWrites(twinDir));
    for (const line of discardedWriteNotice(discarded, { kept: !cleanup.remove })) origConsoleError(line);
    if (twinWatch !== undefined) forgetTwinWatch(twinWatch);
    forgetLabelledTwinRecords(twinDir);
    await emitLauncherEvent(plan.arbiterSock, sessionExitEvent({
      scopeId: plan.scopeId,
      ...(plan.tenant ? { tenant: plan.tenant } : {}),
      ...(plan.batchId ? { batchId: plan.batchId } : {}),
      code,
      durationMs: Date.now() - launchedAt,
      ...(discarded.length > 0 ? { discardedWrites: discarded.map((d) => d.path) } : {}),
      // The agent's run and the teardown so far (the launch's own steps are
      // on the posture event; all of them in the launch's log at its end).
      timings: timer.snapshot({ from: "agent" }),
    }), plan.arbiterHumanSock);
    if (cleanup.remove) {
      const r = removeOwnScopeDir(scopeRunDir);
      if (r.error && display === "full") origConsoleError(`mandu: left the scope dir ${scopeRunDir} for \`mandu reap\` (${r.error})`);
    }
    // The session's last line (session-kept-line.ts; packaging.md §5,
    // dashboard.md §4.25ah): what Mandu kept from the AI, in the dashboard's
    // own counts and words, asked once the session's exit is on the record.
    // On stderr, after the agent and its reply filter have exited, so it
    // never mixes into a TUI or into an agent's machine-readable stdout.
    // Best-effort: no dashboard, no answer in time, nothing printed.
    if (plan.sessionSummary !== false) {
      timer.step("teardown.summary");
      const line = await sessionKeptLine({ session: plan.scopeId, dashboards: liveDashboards(env), runtimeBase: runtimeBase(env) });
      if (line !== null) console.error(line);
    }
    return code;
  } finally {
    timer.step("teardown.records");
    humanWatch?.stop();
    mcpWatch?.stop();
    copiesInUse?.stop();
    // Plan 10 §11.13.1: the session's word that its proxy inspects TLS ends with it.
    await endLaunchWireRelease(plan, wireRelease, { call: (sock, op, args) => ndjsonCall<unknown>(sock, op, args, 2_000), pid: process.pid });
    // Plan 14 §11.2: the end of an unconfined launch starts a new epoch.
    if (launchRecord !== null) await endLaunchRecord(plan.arbiterHumanSock, launchRecord, { ...cacheEpochDeps, log: (m) => origConsoleError(m) });
    timer.end();
    teardown.disarm();
  }
}


/** The account's own runtime bases (runtime-base.ts): the default one (rules
 *  2-4, what a launch without MANDU_RUNTIME_DIR uses) and the rendezvous. The
 *  macOS profile write-denies their registries as well as the launch's own
 *  (seatbelt-setup.ts `registryBases`); a repeat of the launch's base is
 *  dropped there. Best-effort: an unknown uid leaves the rendezvous out. */
/** The session's end (or an aborted launch): the index stat the secret
 *  setup wrote goes back, its crash record with it once complete
 *  (twin-index-stat.ts). Once. Returns the twinned paths the session
 *  untracked, for the exit notice. */
function endTwinIndex(r: SecretSetupResult | undefined): Array<{ root: string; rel: string }> {
  if (r === undefined) return [];
  const end = endTwinIndexSession(r.twinIndex, r.twinIndexRecorder, { log: (m) => console.error(m) });
  delete r.twinIndex;
  delete r.twinIndexRecorder;
  return end.untracked;
}

function accountRegistryBases(env: Record<string, string | undefined>): string[] {
  const out = [defaultRuntimeBaseOf(env).base];
  const uid = process.getuid?.();
  if (uid !== undefined) {
    try { out.push(accountRendezvous(uid)); } catch { /* no rendezvous to add */ }
  }
  return out;
}

/** `p` resolved through its symlinks; `p` itself when that fails. */
function physicalPath(p: string): string {
  try { return realpathSync(p); } catch { return p; }
}

/** `bwrap` is the distribution's outside the current directory (bwrap-path.ts). */
function commandExists(cmd: string): boolean {
  return commandAvailable(cmd);
}
/** Can this host create an unprivileged user + mount namespace? (The secret
 *  twin needs one; without it we refuse rather than silently leave the §10.1
 *  raw-bytes gap open.) bwrap decides when present (src/userns.ts): Ubuntu's
 *  AppArmor restriction grants `userns` per binary. A pass is kept for the
 *  boot (probe-cache.ts) and still enacted, so a wrong one fails closed. */
function usernsOk(): boolean {
  return launchUsernsOk();
}
function systemdUserOk(): boolean {
  return spawnSync("systemctl", ["--user", "show", "--property=Version"], { stdio: "ignore" }).status === 0;
}
/** The scope plan's two probes, each run at most once per launch (the
 *  early reply filter and the final scope plan ask the same questions). */
function memoScopeProbes(): { commandExists: (c: string) => boolean; systemdUserOk: () => boolean } {
  const seen = new Map<string, boolean>();
  let systemd: boolean | undefined;
  return {
    commandExists: (c) => { if (!seen.has(c)) seen.set(c, commandExists(c)); return seen.get(c)!; },
    systemdUserOk: () => (systemd ??= systemdUserOk()),
  };
}

// Entry when run directly (bin). Kept import-safe for tests (which call main()).
// Realpath-aware (src/entrypoint.ts): a symlinked spelling of this file — darwin's
// /tmp → /private/tmp, a checkout behind a symlink — is still the entry. The
// import sits beside the one guard it serves (ES imports hoist).
import { isEntrypoint } from "./entrypoint.js";
import { exitAfterFlush } from "./exit-flush.js";
if (isEntrypoint(import.meta.url, process.argv[1])) {
  // Canonical ps/pgrep title (runtime-instances.md §7): the per-session parent
  // of the agent tree. Set only on the real CLI entry, not when tests import main().
  process.title = "mandu";
  // The process exits as soon as main() settles, so a teardown guard stays
  // armed through that exit instead of giving SIGINT its default action for
  // the last stretch (teardown-signals.ts; portable-wrapper.md §2.1).
  holdTeardownGuardsUntilExit();
  main(process.argv.slice(2)).then(
    // Exit once stdout and stderr have drained (a macOS pipe is written
    // asynchronously; exit-flush.ts).
    (code) => exitAfterFlush(code),
    (err) => { console.error(err instanceof Error ? err.message : String(err)); exitAfterFlush(2); },
  );
}

/** `node --version` of the first `node` on PATH, or null (none, or it hung). */
function probeNodeVersion(pathVar: string | undefined): string | null {
  try {
    return execFileSync("node", ["--version"], { env: { PATH: pathVar ?? "" }, timeout: 3000, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
  } catch {
    return null;
  }
}
