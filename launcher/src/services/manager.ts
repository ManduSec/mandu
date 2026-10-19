/**
 * services/manager — the service-manager phase (spec §2.1): start the opted-in
 * cooperative services, mutate the plan with what they produced, and return an
 * aggregated teardown.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy):
 *   NEW Mandu code. Sequences the net-proxy / exec-shim / mcp services that
 *   launcher/mandu-run.sh starts inline. Fail-closed (spec §5): a REQUESTED
 *   service that fails to start aborts the launch, unless --best-effort (then a
 *   loud warning + coop-env-only) — the deliberate tightening vs the bash
 *   FALLBACK paths that silently degraded.
 */
import { posix } from "node:path";
import { startNetProxy as realStartNetProxy, egressHoldOf } from "./net-proxy.js";
import { egressHoldClause } from "../egress-hold.js";
import { probeExecShimCached as realProbeExecShimCached, writeExecShims as realWriteExecShims, type ExecShimProbeContext } from "./exec-shims.js";
import { mcpConfigDoc, writeMcpConfig as realWriteMcpConfig } from "./mcp.js";
import { planInspectNetConfine as realPlanInspectNetConfine } from "../inspect-net-confine.js";
import { startContextProxy as realStartContextProxy } from "./context-proxy.js";
import { startFsView as realStartFsView } from "./fs-view.js";
import { startCdpRelay as realStartCdpRelay, type CdpRelayResult } from "./cdp-relay.js";
import { startBrowser as realStartBrowser, type BrowserResult } from "./browser.js";
import { chromePortRefusal, upstreamPort } from "../browser-cdp.js";
import { CODEX_ULLM_API_UPSTREAM, CODEX_ULLM_CHATGPT_UPSTREAM, startUllmForwarder as realStartUllmForwarder, ullmKeyStandIn, type UllmForwarderResult } from "./ullm-forwarder.js";
import { writeAgentConfig as realWriteAgentConfig, isConfigRouted } from "./agent-config.js";
import { inheritWorkspaceTrust as realInheritWorkspaceTrust, type TrustInheritInput, type TrustInheritResult } from "./claude-trust.js";
import { inheritCodexTrust as realInheritCodexTrust, type CodexTrustInput, type CodexTrustResult } from "./codex-trust.js";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { realDeps } from "./primitives.js";
import { wireOf, type LaunchPlan } from "../types.js";
import type { Layout } from "./layout.js";

/**
 * Mirror the proxy ViewMap's pair filter: a HumanView↔AgentView pair is usable
 * only when the two roots are distinct, neither is the filesystem root, and
 * neither NESTS under the other. A workspace rooted at $HOME whose AgentView
 * state lives under $HOME produces a NESTED pair — the proxy's ViewMap would
 * filter it and its server would exit "no usable root pair", timing the whole
 * launch out with a confusing "context proxy did not come up". The manager
 * checks this up front and degrades instead of shipping a doomed pair.
 */
export function viewPairUsable(human: string, agent: string): boolean {
  const norm = (p: string): string => {
    if (typeof p !== "string" || p === "") return "";
    let n = posix.normalize(p);
    if (n.length > 1 && n.endsWith("/")) n = n.slice(0, -1);
    return n;
  };
  const h = norm(human);
  const a = norm(agent);
  if (h === "" || a === "" || h === a) return false;
  if (posix.dirname(h) === h || posix.dirname(a) === a) return false; // filesystem root
  const nests = (x: string, y: string): boolean => x === y || x.startsWith(y + "/");
  return !nests(a, h) && !nests(h, a);
}

export interface ServiceHandle {
  stop(): Promise<void>;
  /** The U-LLM forwarder's key put-back, set after the twins (agent-sign-in.md
   *  §3.9: Codex's saved key). Absent when no forwarder runs. */
  setUllmKey?: (k: { standIn: string; key: string }) => void;
}

/** Injectable service fns (defaults are the real ones). */
export interface ManagerDeps {
  startNetProxy: (plan: LaunchPlan, layout: Layout, scopeRunDir: string) => Promise<{ netProxy: { host: string; port: number }; mitmCaCert?: string; mitmCaBundle?: string; mitmUserTrust?: Record<string, string>; mitmDegraded?: string; modelHostDeny?: boolean; stop: () => void }>;
  writeExecShims: (cmds: string[], layout: Layout, arbiterSock: string, scopeRunDir: string) => string;
  writeMcpConfig: (plan: LaunchPlan, layout: Layout, scopeRunDir: string) => string;
  /** Claude only: carry the human's workspace-trust decision over to the
   *  AgentView twin (services/claude-trust.ts). */
  inheritWorkspaceTrust: (input: TrustInheritInput) => TrustInheritResult;
  /** Codex only: the same carry-over into `$CODEX_HOME/config.toml`
   *  (services/codex-trust.ts). */
  inheritCodexTrust: (input: CodexTrustInput) => CodexTrustResult;
  startContextProxy: (plan: LaunchPlan, layout: Layout, scopeRunDir: string) => Promise<{ host: string; port: number; stop: () => void }>;
  startFsView: (plan: LaunchPlan, layout: Layout) => Promise<{ agentCwd: string; gitRoot: string; agentView: string; eager?: boolean; stop: () => void | Promise<void>; ready?: Promise<void> } | null>;
  startUllmForwarder: (opts: ({ upstream: string; apiKey?: { standIn: string; key: string } } | { codex: { api: string; chatgpt: string }; apiKey?: { standIn: string; key: string } }) & { host?: string; port?: number }) => Promise<UllmForwarderResult>;
  writeAgentConfig: (
    plan: LaunchPlan, layout: Layout, scopeRunDir: string, warn: (msg: string) => void,
  ) => { envVar: string; path: string };
  /** The inspect-mcp network confine (inspect-net-confine.ts). Optional: a
   *  deps object without it (the unit tests' fakes) leaves the server
   *  command unwrapped, exactly as before. */
  planInspectNetConfine?: (plan: LaunchPlan, log: (msg: string) => void) => { wrapArgv: string[] } | null;
  /** Load-probe one written exec-wrap shim (exec-shims.ts
   *  probeExecShimCached: a pass kept earlier this boot for the same inputs
   *  answers without the node start); rejects when it cannot load. Optional:
   *  a deps object without it (the unit tests' fakes) reports the shims LIVE
   *  unprobed. */
  probeExecShim?: (shimDir: string, cmd: string, ctx: ExecShimProbeContext) => Promise<void>;
  /** The DevTools relay (services/cdp-relay.ts). Optional: a deps object
   *  without it refuses a `--browser-cdp` launch. */
  startCdpRelay?: (plan: LaunchPlan, layout: Layout, scopeRunDir: string) => Promise<CdpRelayResult>;
  /** The Chrome of a `--browser` launch (services/browser.ts). Optional: a
   *  deps object without it refuses a `--browser` launch. */
  startBrowser?: (plan: LaunchPlan, scopeRunDir: string) => Promise<BrowserResult>;
}

const defaultDeps: ManagerDeps = {
  startNetProxy: (plan, layout, scopeRunDir) => realStartNetProxy(plan, layout, scopeRunDir, realDeps),
  writeExecShims: realWriteExecShims,
  probeExecShim: realProbeExecShimCached,
  writeMcpConfig: realWriteMcpConfig,
  inheritWorkspaceTrust: realInheritWorkspaceTrust,
  inheritCodexTrust: realInheritCodexTrust,
  startContextProxy: (plan, layout, scopeRunDir) => realStartContextProxy(plan, layout, scopeRunDir, realDeps),
  startFsView: (plan, layout) => realStartFsView(plan, layout, realDeps),
  startUllmForwarder: realStartUllmForwarder,
  writeAgentConfig: realWriteAgentConfig,
  planInspectNetConfine: (plan, log) => realPlanInspectNetConfine(plan, { log, platform: process.platform }),
  startCdpRelay: (plan, layout, scopeRunDir) => realStartCdpRelay(plan, layout, scopeRunDir, realDeps),
  startBrowser: (plan, scopeRunDir) => realStartBrowser(plan, scopeRunDir, realDeps),
};

export async function startServices(
  plan: LaunchPlan,
  layout: Layout,
  scopeRunDir: string,
  deps: ManagerDeps = defaultDeps,
  warn: (msg: string) => void = (m) => console.error(`mandu: ${m}`),
  hooks: StartHooks = {},
): Promise<ServiceHandle> {
  const stops: Array<() => void | Promise<void>> = [];
  // What startServices waits for last: soft readiness signals (the eager
  // watcher's) that overlap the services started after them.
  const pending: Array<Promise<void>> = [];

  // A requested service that throws is fail-closed unless --best-effort — EXCEPT
  // an error flagged `failClosedFatal`, which --best-effort must NOT override. A
  // dead proxy port is a safe soft-fail (calls just fail), but a port held by a
  // foreign/wrong-session server is NOT: proceeding would route this session's
  // traffic through a stranger. Those throw ContextProxyConflictError, whose
  // flag forces an abort here regardless of --best-effort.
  //
  // `soft` marks a DEFAULT-ON (tri-state undefined) request: the non-root
  // principle turns the service on, but a host where it cannot start must not
  // brick the launch — degrade with a loud warning instead. Degrading is safe
  // even for a failClosedFatal error: unlike --best-effort (which proceeds
  // with env still POINTING at the conflicted port), a soft degrade leaves the
  // service out of the plan entirely, so nothing routes through the stranger.
  //
  // `refuse` (release checklist a1) marks a DEFAULT-ON service whose failure
  // must REFUSE the launch anyway — the egress gate: a launch that silently
  // continued without it (one warning line, easy to miss) ran every session
  // with no cooperative egress decision at all. It names the plain-words role
  // of the service and the deliberate opt-out; --best-effort still applies to
  // a non-fatal failure (an explicit user choice, like --no-<id>).
  const onFailure = async (
    id: string,
    e: unknown,
    soft: boolean,
    refuse?: { role: string; optOut: string },
  ): Promise<void> => {
    {
      const detail = e instanceof Error ? e.message : String(e);
      if (soft) {
        warn(`service '${id}' is on by default but failed to start: ${detail} — proceeding WITHOUT it (opt out explicitly with --no-${id} to silence this)`);
        return;
      }
      const fatal = !!(e as { failClosedFatal?: boolean })?.failClosedFatal;
      const msg = refuse
        ? `${refuse.role} (${id}) could not start: ${detail}`
        : `service '${id}' was requested but failed to start: ${detail}`;
      if (plan.bestEffort && !fatal) { warn(`${msg} — proceeding WITHOUT it (--best-effort)`); return; }
      // Tear down anything already started before aborting.
      for (const s of stops) { try { await s(); } catch { /* best-effort teardown */ } }
      const suffix = refuse
        ? ` — refusing to launch without it. Fix the cause above, or launch without ${refuse.role} on purpose with ${refuse.optOut}` +
          (fatal ? "." : " (or --best-effort).")
        : fatal
          ? " (a hard fail-closed condition — --best-effort cannot override it)"
          : " (pass --best-effort to launch anyway)";
      throw new Error(`mandu: ${msg}${suffix}`);
    }
  };
  const guarded = async (
    id: string,
    requested: boolean,
    run: () => Promise<void> | void,
    soft = false,
    refuse?: { role: string; optOut: string },
  ) => {
    if (!requested) return;
    try { await run(); }
    catch (e) { await onFailure(id, e, soft, refuse); }
  };
  // Independent services started at once. Every start SETTLES before any
  // failure is handled, so a refusal's teardown also stops a sibling that
  // came up after the failing one (none is left running unregistered); the
  // failures are then handled in list order, exactly as `guarded` would.
  const guardedTogether = async (
    items: ReadonlyArray<{ id: string; requested: boolean; run: () => Promise<void> | void; soft?: boolean; refuse?: { role: string; optOut: string } }>,
  ) => {
    const settled = await Promise.allSettled(items.map((it) => (it.requested ? Promise.resolve().then(it.run) : Promise.resolve())));
    for (let i = 0; i < items.length; i++) {
      const r = settled[i]!;
      if (r.status === "rejected") await onFailure(items[i]!.id, r.reason, items[i]!.soft ?? false, items[i]!.refuse);
    }
  };

  // Filesystem chokepoint (Part 3): default-on for git workspaces (fsSync
  // undefined = auto → the service returns null for non-git and we keep the
  // raw CWD); fsSync === false is an explicit opt-out. Runs FIRST: the context
  // proxy consumes the HumanView↔AgentView pair it produces (plan.viewMap →
  // MANDU_VIEW_MAP, the P2 prefix map — fs-sync.md §1.3).
  //
  // Truth-in-labeling (fs-sync.md §1.5, P5): the launcher REPORTS the
  // active fs rung — the cooperative-rung line when the stack is live, an
  // explicit DEGRADED line otherwise (the auto-mode non-git skip warns inside
  // fs-view with the same detail).
  await guarded("fs-sync", plan.fsSync !== false, async () => {
    const r = await deps.startFsView(plan, layout);
    if (!r) return; // auto-mode skip: not a git workspace (fs-view warned)
    if (!viewPairUsable(r.gitRoot, r.agentView)) {
      // Nested/degenerate pair (a workspace rooted at $HOME with its AgentView
      // state under it): shipping this pair would make the context proxy exit
      // "no usable root pair" and abort the launch. Degrade to raw CWD — tear
      // the worktree down and run without the prefix map (the context backstop
      // still symbolizes). Actionable: run the agent in a project folder, or
      // move the Mandu home (MANDU_HOME) out of the workspace.
      try { await r.stop(); } catch { /* best-effort teardown */ }
      warn(
        `fs rung DEGRADED: workspace ${r.gitRoot} and its AgentView ${r.agentView} nest — no usable ` +
        `HumanView↔AgentView pair, so the prefix map + sensitive-path gate are OFF (raw CWD; the context ` +
        `backstop still applies). For full protection, launch from a project folder rather than a folder ` +
        `that holds your Mandu home, or set MANDU_HOME to a directory outside the workspace.`,
      );
      return;
    }
    plan.cwd = r.agentCwd;
    plan.viewMap = [{ human: r.gitRoot, agent: r.agentView }];
    stops.push(r.stop);
    if (r.ready) pending.push(r.ready);
    // Claude keys its "Accessing workspace … Quick safety check" on the CWD —
    // now the AgentView twin, a path the human never chose, with "No, exit"
    // as the default answer (the first `mandu claude` in an already-trusted
    // project exited on Enter, 2026-09-05). The twin is a worktree OF the
    // folder the human trusted, so the decision transfers; never the other
    // way (claude-trust.ts). Utility-only: a failure just leaves the dialog.
    if (plan.target === "claude") {
      const t = deps.inheritWorkspaceTrust({
        configDir: process.env["CLAUDE_CONFIG_DIR"] || homedir(),
        humanCwd: plan.humanCwd,
        agentCwd: r.agentCwd,
      });
      if (t.action === "inherited") {
        warn(`workspace trust inherited by the AgentView twin (${plan.humanCwd} is trusted in ${t.file}, so ${r.agentCwd} is now too)`);
      } else if (t.action === "error") {
        warn(`could not inherit workspace trust for the AgentView twin (${t.reason}) — claude may ask its "Accessing workspace" question once`);
      }
    }
    // Codex keys "Do you trust the contents of this directory?" on the
    // repository root it resolves — for the twin that is the worktree's
    // PARENT (the view state dir; measured 2026-09-05) — in
    // $CODEX_HOME/config.toml. Same carry-over, both candidate keys.
    if (plan.target === "codex") {
      const t = deps.inheritCodexTrust({
        codexHome: process.env["CODEX_HOME"] || join(homedir(), ".codex"),
        humanRoot: r.gitRoot,
        agentPaths: [dirname(r.agentView), r.agentView],
      });
      if (t.action === "inherited") {
        warn(`directory trust inherited by the AgentView twin (${r.gitRoot} is trusted in ${t.file}, so ${t.added.join(" + ")} now too)`);
      } else if (t.action === "error") {
        warn(`could not inherit directory trust for the AgentView twin (${t.reason}) — codex may ask its "Do you trust" question once`);
      }
    }
    // Truth-in-labeling: report EXACTLY which protections are active. The P3
    // sensitive-path gate is a Claude-only chokepoint (the anthropic-proxy gates
    // typed path FIELDS); Codex has no typed path fields, so the openai-proxy
    // ships no gate — its shell-string paths ride the exec chokepoint instead.
    const gateClause = plan.target === "claude"
      ? " + sensitive-path gate"
      : plan.target === "codex"
        ? " (no sensitive-path gate for Codex — its paths ride the exec chokepoint)"
        : ` (no sensitive-path gate for ${plan.target} — the P3 table keys Claude Code's tool ` +
          "schemas; its paths ride the exec/fs chokepoints)";
    // Eager sync (fs-sync.md §2 Phase 1): only claimed when the watcher
    // actually spawned (fs-view warned about any failure/degradation).
    const eagerClause = r.eager ? " + eager sync (tool-call cadence)" : "";
    warn(
      `fs rung ACTIVE: cooperative — CWD→AgentView worktree + HumanView↔AgentView ` +
      `prefix map${gateClause}${eagerClause} (workspace ${r.gitRoot})`,
    );
  });
  // The AgentView is seeded (or there is none): what the caller wanted to
  // start once it exists (run.ts: the secret discovery walk, which reads it).
  hooks.onFsViewReady?.();
  if (plan.fsSync === false && plan.fsSyncOffReason === "mode") {
    // Release checklist a4: integrity OFF (the default `secrets` mode, and
    // `off`) turns fs-sync off ON PURPOSE — the AgentView twin routes
    // untrusted file content around the model, the integrity axis's own
    // machinery. A designed posture, so an informational note (--verbose /
    // launch.log / the posture event's notes), never the DEGRADED warning the
    // user "opted out" of: no attention word, no dropped-rung phrase.
    warn(
      `fs rung off by mode: integrity is off in this protection mode, so the agent works ` +
      `in your folder directly (no AgentView copy is needed)`,
    );
  } else if (plan.fsSync === false) {
    warn(
      `fs rung DEGRADED: fs-sync opted out (--no-fs-sync) — raw CWD, no prefix map, ` +
      `no sensitive-path gate; the context chokepoint backstop still applies`,
    );
  }

  // Context chokepoint (Phase 0): DEFAULT-ON. Two distinct skips:
  //  - explicit base-URL override → the user brings their own endpoint
  //    (only an UNDECLARED one reaches here: run.ts turns a base URL that is
  //    a policy.yaml `models:` entry into plan.tllmEndpoint and clears the
  //    override, so the proxy runs in front of it; plan 11 §5, phase 3);
  //  - MANDU_NO_CONTEXT_PROXY → the proxy is expected to be started
  //    out-of-band; the composed base URL still points at the proxy port and
  //    fails closed if nothing is listening there.
  const ctxRequested =
    !plan.noContextProxy &&
    (wireOf(plan.target) === "anthropic" ? !plan.anthropicBaseUrl : !plan.openaiBaseUrl);
  // The two proxies read nothing the other produces: started together.

  // Tri-state services (types.ts `requested`): explicit true = fail-closed,
  // undefined = default-on/soft (degrade + warn), false = skipped. EXCEPT the
  // egress gate (release checklist a1, 2026-09-26): default-on AND
  // fail-closed — a failed net-proxy refuses the launch; --no-net-proxy is
  // the deliberate way to run without it.
  await guardedTogether([
    {
      id: "context-proxy", requested: ctxRequested,
      run: async () => {
        const r = await deps.startContextProxy(plan, layout, scopeRunDir);
        // Adopt the port the proxy actually bound: with MANDU_PROXY_PORT=0 the
        // kernel picked it (published via the port file), and the env composer
        // reads plan.proxy to build the base URL — a no-op for pinned ports.
        if (wireOf(plan.target) === "anthropic") plan.proxy = { host: r.host, port: r.port };
        else plan.openaiProxy = { host: r.host, port: r.port };
        stops.push(r.stop);
      },
    },
    {
      id: "net-proxy", requested: plan.requested.netProxy !== false,
      refuse: { role: "the egress gate", optOut: "--no-net-proxy" },
      run: async () => {
        const r = await deps.startNetProxy(plan, layout, scopeRunDir);
        plan.netProxy = r.netProxy;
        plan.mitmCaCert = r.mitmCaCert;
        plan.mitmCaBundle = r.mitmCaBundle;
        plan.mitmUserTrust = r.mitmUserTrust;
        // The model-host deny (model-host-deny.ts): NO_PROXY, the connect
        // guard and the U-LLM forwarder follow the proxy that carries it.
        plan.modelHostDeny = r.modelHostDeny === true;
        stops.push(r.stop);
        if (r.mitmDegraded) warn(r.mitmDegraded);
        // Truth-in-labeling (matches the fs-sync / exec-box / landlock-net LIVE
        // banners): announce the wired rung so a human — and the live e2e oracles —
        // can read the posture from stderr. The MITM clause distinguishes the
        // HTTPS-body gate from the blind-tunnel default.
        warn(
          `net-proxy LIVE — cooperative egress gate on http://${r.netProxy.host}:${r.netProxy.port}` +
          (r.mitmCaCert ? " (MITM: HTTPS request bodies gated via a session CA)" : "") +
          " (a symbol bound for an untrusted destination → 403 needs-approval)" +
          egressHoldClause(egressHoldOf(plan)),
        );
      },
    },
    {
      // Started with the proxies: it reads nothing they produce, and its load
      // probe (one node start) then overlaps their startup.
      id: "exec-wrap", requested: plan.requested.execWrap !== false, soft: plan.requested.execWrap === undefined,
      run: async () => {
        const shimDir = deps.writeExecShims(plan.execWrapCmds, layout, plan.arbiterSock, scopeRunDir);
        // Truth-in-labeling: LIVE only for a shim that loads (portable-wrapper.md
        // §5). A checkout whose exec-wrap dependencies are missing wrote shims
        // that crashed on every call; the probe turns that into a failed start
        // (degrade with a warning by default, refuse when asked for
        // explicitly), and the agent's PATH is not shadowed by shims that
        // cannot run.
        // The probe's pass is kept for the boot (probe-cache.ts), keyed by
        // everything its answer depends on; a failure is never kept.
        if (deps.probeExecShim) {
          await deps.probeExecShim(shimDir, plan.execWrapCmds.map((c) => c.trim()).find(Boolean) ?? "", { layout, arbiterSock: plan.arbiterSock });
        }
        plan.shimDir = shimDir;
        warn(
          `exec-wrap LIVE — PATH-shadowing [${plan.execWrapCmds.join(", ")}] through the arbiter ` +
          "(a symbol used as a command/arg → blocked, exit 77)",
        );
      },
    },
  ]);

  // U-LLM loopback forwarder (exec-routing.md §7.1): when the landlock-net wrap
  // is on (default), run the relay in THIS process (outside the wrap) and point
  // the U-LLM at it — the strong port posture then keeps a working U-LLM with
  // the destination pinned. An Anthropic-bound U-LLM gets the verbatim relay to
  // its base URL; a Codex one (`codex exec`, agent-sign-in.md §2.11) the relay
  // of a model call to the fixed OpenAI pair (the API origin, or the ChatGPT
  // backend on a sign-in). Runs BEFORE writeMcpConfig, which emits the
  // forwarder URL + trust pin into .mcp.json.
  // UTILITY-CLASS: a forwarder that cannot start only warns; the U-LLM then
  // keeps its direct :443 dial (and the non-strict port set keeps 443 open).
  // Under the model-host deny (model-host-deny.ts) it starts in every posture:
  // a direct dial of the vendor from the agent's tree is refused there.
  const ullmCodex = plan.ullm.mode === "cli" && plan.ullm.binary === "codex";
  let setUllmKey: ((k: { standIn: string; key: string }) => void) | undefined;
  if (plan.landlockNet !== false || plan.modelHostDeny === true) {
    try {
      const fwdHost = process.env["MANDU_ULLM_FORWARDER_HOST"] || "127.0.0.1";
      const fwdPort = Number(process.env["MANDU_ULLM_FORWARDER_PORT"] || 0);
      const codex = plan.ullm.codexUpstreams ?? { api: CODEX_ULLM_API_UPSTREAM, chatgpt: CODEX_ULLM_CHATGPT_UPSTREAM };
      // Agent-sign-in.md §3.8: an API-mode U-LLM is handed a stand-in for
      // its key, which the relay replaces on its model call, so the key is
      // not written into the inspect server's entry in the agent's world.
      // Only once the relay is live: without it the U-LLM dials directly
      // and needs the key itself.
      const realKey = !ullmCodex && plan.ullm.mode === "api" && plan.ullm.apiKey ? plan.ullm.apiKey : undefined;
      const apiKey = realKey !== undefined ? { standIn: ullmKeyStandIn(), key: realKey } : undefined;
      const r = ullmCodex
        ? await deps.startUllmForwarder({ codex, host: fwdHost, port: fwdPort })
        : await deps.startUllmForwarder({ upstream: plan.ullm.baseUrl, host: fwdHost, port: fwdPort, ...(apiKey ? { apiKey } : {}) });
      plan.ullmForwarder = { host: r.host, port: r.port };
      plan.ullm.forwarderUrl = r.url;
      if (apiKey) plan.ullm.apiKey = apiKey.standIn;
      if (r.setApiKey) setUllmKey = r.setApiKey;
      stops.push(r.stop);
      const dest = ullmCodex ? `${codex.api} or ${codex.chatgpt} (a model call only)` : plan.ullm.baseUrl;
      warn(`ullm-forwarder LIVE on ${r.url} — the U-LLM reaches ${dest} via the launcher (outside the TCP confine), not a direct :443 dial`);
    } catch (e) {
      warn(
        `ullm-forwarder failed to start: ${e instanceof Error ? e.message : String(e)} — ` +
        (plan.modelHostDeny === true
          ? "the U-LLM has no route (the model hosts are denied to the agent's programs), so inspect_symbol fails closed"
          : "the U-LLM keeps its direct :443 dial (landlock-net must keep 443 open for it)"),
      );
    }
  }

  // The DevTools relay (`--browser-cdp`, devtools-relay.md §6): after the
  // services whose ports Chrome's must not share. Requested by the flag, so
  // a relay that cannot start refuses the launch unless --best-effort; then
  // the agent is given no endpoint, and Chrome's own port stays outside the
  // connect guards.
  // `--browser` (devtools-relay.md §6.4): Mandu starts the Chrome, after the
  // egress proxy (its traffic goes through it, trusting the session CA by
  // its pin), and the relay below is put in front of it. Requested by the
  // flag: a Chrome that cannot start refuses the launch unless
  // --best-effort, which launches with no browser.
  await guarded("browser", plan.browser === true, async () => {
    if (!deps.startBrowser) throw new Error("this launcher cannot start a browser");
    const r = await deps.startBrowser(plan, scopeRunDir);
    plan.browserCdp = r.endpoint;
    stops.push(r.stop);
    warn(`browser LIVE — Chrome (${r.binary}${r.headless ? ", headless" : ""}) on its own profile (${r.profile})` +
      (plan.netProxy ? `, its traffic through the egress proxy on ${plan.netProxy.host}:${plan.netProxy.port}` : ""));
    if (r.note !== null) warn(r.note);
  });

  await guarded("cdp-relay", plan.browserCdp !== undefined, async () => {
    const own = [plan.proxy.port, plan.openaiProxy.port, plan.netProxy?.port, plan.ullmForwarder?.port].filter((p): p is number => typeof p === "number" && p > 0);
    const refusal = chromePortRefusal(upstreamPort(plan.browserCdp!), own);
    if (refusal !== null) throw Object.assign(new Error(refusal), { failClosedFatal: true });
    if (!deps.startCdpRelay) throw new Error("this launcher cannot start the DevTools relay");
    const r = await deps.startCdpRelay(plan, layout, scopeRunDir);
    plan.cdpRelay = { host: r.host, port: r.port, url: r.url };
    stops.push(r.stop);
    warn(`cdp-relay LIVE on ${r.url} — the agent reaches Chrome (${plan.browserCdp}) through it: what Chrome sends is masked, a placeholder it types is released only on a page its secret is bound to`);
  });

  // The inspect-mcp network confine (confidentiality-plan-11 §8 item 5):
  // decided once, after the forwarder (its port is the U-LLM's door) and
  // before any writer of the inspect server entry (the MCP config below, the
  // Codex splice built from it, the OpenCode config). OpenClaw mounts the
  // channel inside its gateway, so there is no command to wrap. Utility-class:
  // a missing bin or an old kernel keeps today's command with one note.
  if (plan.writeMcp && plan.target !== "openclaw" && deps.planInspectNetConfine) {
    const r = deps.planInspectNetConfine(plan, (m) => warn(m.replace(/^mandu: /, "")));
    if (r) plan.inspectMcpWrap = r.wrapArgv;
  }

  // The inspect-mcp config is default-on (disabled by --no-mcp); a write
  // failure is not a security gate, so it is best-effort regardless. Written
  // into the SCOPE RUN DIR and spliced into claude's argv as --mcp-config
  // (env-compose.ts) — never a project-scope <cwd>/.mcp.json, which Claude
  // Code's default permission posture greets with an approval dialog whose
  // default answer drops the server (services/mcp.ts header). NOT for the
  // config-routed targets: openclaw mounts the inspect channel as an
  // in-process plugin and opencode registers the same server in its own
  // config's `mcp` section — both ride the agent-config file below.
  if (plan.writeMcp && !isConfigRouted(plan.target)) {
    try {
      plan.mcpConfig = deps.writeMcpConfig(plan, layout, scopeRunDir);
      // Codex reads no MCP file from us: env-compose splices these entries as
      // `-c mcp_servers.<name>.*` overrides (codex has no --mcp-config).
      plan.mcpServers = mcpConfigDoc(plan, layout).mcpServers;
    }
    catch (e) { warn(`could not write the inspect-mcp config: ${e instanceof Error ? e.message : String(e)}`); }
  }

  // Config-file routing for openclaw/opencode (services/agent-config.ts):
  // these agents IGNORE ANTHROPIC_BASE_URL (probe-verified — config-file
  // routed, agent-e2e-harness.md §2.1/§2.2), so the emitted file IS the
  // model-context chokepoint wiring. Runs LAST among the plan mutations it
  // reads: after the context proxy (plan.proxy is the ADOPTED port, port-0
  // safe) and after the U-LLM forwarder (plan.ullm.forwarderUrl rides into
  // the plugin/mcp entry). A write failure is failClosedFatal — unlike a dead
  // proxy port (calls fail loudly), a missing config file leaves the agent
  // FULLY FUNCTIONAL against the real endpoint with nothing symbolized, the
  // silent-unprotected shape --best-effort must not be able to bless.
  if (isConfigRouted(plan.target)) {
    await guarded("agent-config", true, () => {
      try {
        const r = deps.writeAgentConfig(plan, layout, scopeRunDir, warn);
        plan.agentConfig = r;
        warn(
          `agent-config LIVE — ${plan.target} routed to the model-context proxy via ${r.path} ` +
          `(${r.envVar}; your own config is merged under the routing override)`,
        );
      } catch (e) {
        (e as { failClosedFatal?: boolean }).failClosedFatal = true;
        throw e;
      }
    });
  }

  await Promise.all(pending);
  return {
    stop: async () => { for (const s of stops.reverse()) { try { await s(); } catch { /* ignore */ } } },
    ...(setUllmKey !== undefined ? { setUllmKey } : {}),
  };
}

/** Callbacks startServices makes at points the caller may start work of its
 *  own in parallel with the rest of the startup. */
export interface StartHooks {
  /** After the filesystem step (the AgentView seeded, or no fs-sync). */
  onFsViewReady?: () => void;
}
