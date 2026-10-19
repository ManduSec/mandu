/**
 * services/context-proxy — start-or-reuse the model-API context proxy
 * (Phase 0 of the golden path: architecture-map.md §9 §①).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy):
 *   NEW Mandu code; the start-or-reuse/fail-closed shape mirrors
 *   services/net-proxy.ts. DEVIATION from launcher/mandu-run.sh (which never
 *   autostarts the model proxies, L27-29): the context chokepoint is Tier-0
 *   "always-on", so the manager runs this by DEFAULT — skipped only on an
 *   explicit base-URL override or MANDU_NO_CONTEXT_PROXY=1. A base URL that is
 *   a declared `models:` entry is not an override: run.ts turns it into
 *   plan.tllmEndpoint and the proxy runs with it as MANDU_UPSTREAM (plan 11 §5,
 *   phase 3), plus MANDU_UPSTREAM_LOCAL=1 when the entry is `local: true`
 *   (the proxy then refuses cloud-backed model names; plan 11 §8 item 3).
 *
 * Fail-closed: if the proxy cannot come up the launch aborts; under
 * --best-effort it proceeds with ANTHROPIC_BASE_URL still pointing at the DEAD
 * proxy port — model calls fail rather than bypass symbolization. NEVER fall
 * back to the real endpoint (the repo's one invariant).
 *
 * Start-or-reuse identity check: a proxy already listening on the port is
 * adopted ONLY when it publishes an identity that matches THIS launch — same
 * service, same arbiter socket, same view-map roots (`GET /_mandu/identity`).
 * A leftover proxy from ANOTHER session (different arbiter → wrong symbol table;
 * different view map → wrong worktree routing) or a foreign server on the port
 * is a conflict: we FAIL CLOSED rather than route this session's model traffic
 * — and its symbolization/path decisions — through the wrong daemon. The fix is
 * to stop the other proxy or pick a free port (MANDU_PROXY_PORT). This check
 * is enforced on BOTH paths: the reuse branch AND after we start our own child
 * (a concurrent launch can win the port race, leaving a foreign proxy up).
 *
 * A port CONFLICT is a HARD fail (ContextProxyConflictError.failClosedFatal):
 * --best-effort may proceed past a DEAD port (calls fail closed) but NOT past a
 * LIVE foreign server (that would route traffic through a stranger — a leak,
 * not a fail-closed).
 */
import { readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { wireOf, type LaunchPlan } from "../types.js";
import { openclawRunsLocally } from "../openclaw-argv.js";
import { proxySecretPosture } from "../proxy-secret-posture.js";
import type { Layout } from "./layout.js";
import { describeOccupant, readinessBudget, type ServiceDeps, type ProxyIdentity } from "./primitives.js";
import { humanSockEnv } from "../human-plane.js";

export interface ContextProxyResult {
  host: string;
  port: number;
  stop: () => void;
}

/**
 * A hard fail-closed condition that --best-effort MUST NOT override: the proxy
 * port is held by a foreign / wrong-session server. Proceeding would route this
 * session's model traffic (credentials + raw untrusted tool_results) through a
 * stranger's daemon — the opposite of failing closed. `failClosedFatal` tells
 * the manager's guarded() to abort even under --best-effort (a DEAD port is the
 * only condition --best-effort may proceed past, since then calls just fail).
 */
export class ContextProxyConflictError extends Error {
  readonly failClosedFatal = true;
  constructor(message: string) {
    super(message);
    this.name = "ContextProxyConflictError";
  }
}

/** The view-map pairs this launch would configure the proxy with (canonical
 *  JSON, for an exact string compare against a listening proxy's identity). */
function wantViewMapJson(plan: LaunchPlan): string {
  return JSON.stringify(plan.viewMap ?? []);
}

/**
 * Is a listening proxy's published identity safe for THIS launch to adopt?
 * Keyed on the security-relevant routing: the service (claude vs codex proxy),
 * the arbiter socket (wrong one = wrong symbol table), and the view-map roots
 * (wrong ones = wrong worktree / gate). The sessionKey is NOT part of the key —
 * two launches sharing an arbiter + workspace legitimately reuse one proxy.
 */
export function proxyIdentityMatches(id: ProxyIdentity | null, plan: LaunchPlan, pkg: string): boolean {
  if (!id || id.mandu !== true) return false;
  if (id.service !== pkg) return false;
  if (id.arbiterSock !== plan.arbiterSock) return false;
  // The start directory relative paths are placed against: another launch's
  // would put every relative path in the wrong place (fs-gate.ts
  // resolveRelative). Only the anthropic-proxy takes it.
  // A proxy that names NO base places nothing (a `..` escape is denied, the
  // rest left to the backstops), which is safe for any launch; one naming a
  // different base is not.
  if (pkg === "anthropic-proxy" && id.agentCwd !== undefined && id.agentCwd !== agentStartDir(plan)) return false;
  return JSON.stringify(id.viewMap ?? []) === wantViewMapJson(plan);
}

/**
 * The HumanView directory the agent resolves relative paths against, when the
 * launcher KNOWS it: the directory the agent starts in (plan.humanCwd, the
 * HumanView spelling of its cwd), unless the agent's argv moves it. The
 * anthropic-proxy uses it only for an agent whose gate surface says relative
 * paths join the launch directory (arbiter tool-gate-surface.ts
 * `relativeBase`; OpenCode), so an undefined here is the safe answer
 * (the proxy then treats the base as unknown and denies `..` escapes).
 * opencode (1.18.32 `--help`): `--dir` (any form) moves it, and so does the
 * TUI's `[project]` positional, which may follow flags. The launcher cannot
 * tell a positional from a flag's value without opencode's option table, so
 * it names the base only for `opencode` with flags alone, or for
 * `opencode run …` (whose positionals are the message). Any other argv
 * (a subcommand, a server, an attach, a word it cannot place) names none.
 * openclaw: its file tools resolve against its WORKSPACE, which
 * agent-config.ts fenceOpenclawWorkspace pins to this directory exactly for
 * the shapes whose loop runs here (openclaw-argv.ts openclawRunsLocally, the
 * same predicate on the same argv); any other shape keeps the user's
 * workspace and names none, and so does `--agent` (a non-default agent
 * without a workspace of its own works in `<dir>/<id>`).
 * Pure.
 */
export function agentStartDir(plan: Pick<LaunchPlan, "target" | "argv" | "humanCwd">): string | undefined {
  if (typeof plan.humanCwd !== "string" || !plan.humanCwd.startsWith("/")) return undefined;
  if (!Array.isArray(plan.argv)) return plan.target === "opencode" ? undefined : plan.humanCwd;
  if (plan.target === "opencode") {
    const args = plan.argv.slice(1);
    if (args.some((a) => a === "--dir" || a.startsWith("--dir="))) return undefined;
    if (args[0] !== "run" && args.some((a) => !a.startsWith("-"))) return undefined;
  }
  if (plan.target === "openclaw") {
    if (!openclawRunsLocally(plan.argv)) return undefined;
    if (plan.argv.some((a) => a === "--agent" || a.startsWith("--agent="))) return undefined;
  }
  return plan.humanCwd;
}

/** The arbiter inbound spec a target's session binds to at proxy boot
 *  (arbiter/policy/tool-inbound.ts INBOUND_SPECS ids), or undefined for the
 *  targets the boot spec already covers. */
export function inboundSpecFor(target: LaunchPlan["target"]): string | undefined {
  if (target === "opencode") return "opencode";
  // `openclaw-agent`, NOT the lifted `openclaw` reference spec: that one
  // trusts `read` wholesale, safe only under the reference plugin's view-sync.
  if (target === "openclaw") return "openclaw-agent";
  // Goose: its own spec and gate table (arbiter goose-inbound.ts,
  // tool-gate-surface.ts GOOSE_GATE_SURFACE; supported-agents.md §5.6).
  if (target === "goose") return "goose";
  return undefined;
}

export async function startContextProxy(
  plan: LaunchPlan,
  layout: Layout,
  scopeRunDir: string,
  deps: ServiceDeps,
): Promise<ContextProxyResult> {
  const pkg = wireOf(plan.target) === "anthropic" ? "anthropic-proxy" : "openai-proxy";
  const { host, port } = wireOf(plan.target) === "anthropic" ? plan.proxy : plan.openaiProxy;

  let stop = () => {};
  // Start-or-reuse: if something is already listening, adopt it ONLY when its
  // published identity matches THIS launch; otherwise fail closed (a foreign or
  // wrong-session proxy must never carry this session's model traffic).
  // Port 0 (ephemeral) skips this branch entirely: there is no well-known
  // rendezvous to reuse OR to conflict on — the kernel hands this launch its
  // own port, which is the point (no stale daemon can ever squat it).
  if (port !== 0 && await deps.probePort(host, port)) {
    // A declared main model (plan 11 §5, phase 3; plan.tllmEndpoint) needs a
    // proxy whose upstream is THAT entry. A listening proxy does not publish
    // its upstream, so adopting one could send this session's conversation to
    // whatever model it was started for: never adopt, whatever its identity.
    if (plan.tllmEndpoint) {
      throw new ContextProxyConflictError(
        `mandu: ${host}:${port} already has a model proxy listening, and this launch needs its own in front of ` +
        `your main model "${plan.tllmEndpoint.name}" (${plan.tllmEndpoint.url}); a running proxy's upstream is unknown, ` +
        `so it is not reused. Stop it, or unset MANDU_PROXY_PORT (the default port 0 always starts a fresh proxy).`,
      );
    }
    // Routed OpenAI-family providers (agent-model-route.ts): the proxy must
    // hold THIS launch's upstream table, which a listening proxy does not
    // publish. Never adopt, like a declared main model.
    if ((plan.openaiRoutes?.length ?? 0) > 0) {
      throw new ContextProxyConflictError(
        `mandu: ${host}:${port} already has a model proxy listening, and this launch routes ` +
        `${plan.openaiRoutes!.map((r) => r.id).join(", ")} through its own; a running proxy's routes are unknown, ` +
        `so it is not reused. Stop it, or unset MANDU_PROXY_PORT (the default port 0 always starts a fresh proxy).`,
      );
    }
    const id = await deps.probeIdentity(host, port);
    if (proxyIdentityMatches(id, plan, pkg)) {
      // Safe reuse: same service, arbiter and view map. We did not start it, so
      // we must NOT tear it down (parity with net-proxy's reuse).
      return { host, port, stop };
    }
    throw new ContextProxyConflictError(
      `mandu: ${host}:${port} is occupied by ${describeOccupant(id)} — refusing to route this ` +
      `session's model traffic through it (its arbiter/view-map differ, so symbolization and path ` +
      `decisions would be wrong). Stop it, or set MANDU_PROXY_PORT to a free port.`,
    );
  }
  {
    // Ephemeral port (0): the kernel picks; the proxy publishes the bound port
    // into the port file (server-main's atomic tmp+rename), and we adopt it.
    // Clear any stale file first — adopting a previous run's port would probe
    // (and possibly identity-match) a daemon this launch does not own.
    const portFile = port === 0 ? join(scopeRunDir, `${pkg}.port`) : undefined;
    if (portFile) rmSync(portFile, { force: true });
    const env: Record<string, string | undefined> = {
      // MANDU_UPSTREAM / MANDU_HANDLING_MODE deliberately ride through
      // from the launcher's env (the e2e points the stack at a mock upstream),
      // as do reply row reservation's kill switch MANDU_REPLY_RESERVE and its
      // row cap MANDU_REPLY_RESERVE_MAX (reply-row-reservation.md §3.2).
      ...process.env,
      MANDU_ARBITER_SOCK: plan.arbiterSock,
      // The human plane (arbiter-human-plane.md), for reply row
      // reservation's `symbolShape` and `sessionRelay` only
      // (reply-row-reservation.md §3.3, §11.5), in both context proxies: the
      // Claude proxy and, since §11.7, the Codex proxy. Each asks nothing
      // else there (its adapter forwards only those two ops to the human
      // client). Set explicitly (undefined when absent), so an inherited
      // value never leaks through.
      ...humanSockEnv(plan.arbiterHumanSock),
      MANDU_PROXY_HOST: host,
      MANDU_PROXY_PORT: String(port),
      // Explicitly UNSET when unused (like MANDU_VIEW_MAP below) so a stale
      // ambient value can't make the proxy write a rogue port file.
      MANDU_PORT_FILE: portFile,
      MANDU_SESSION_KEY: plan.scopeId,
      // The declared main model (plan 11 §5, phase 3): the proxy's upstream
      // is that entry (model-endpoints.ts tllmUpstream). Otherwise the ambient
      // value rides through (the spread above), which the e2e suites use to
      // point the stack at a mock upstream.
      ...(plan.tllmEndpoint ? { MANDU_UPSTREAM: plan.tllmEndpoint.upstream } : {}),
      // …and whether that entry is `local: true` (plan 11 §8 item 3): the
      // proxy then refuses a request whose `model` is cloud-backed (Ollama's
      // `:cloud` tags run on the vendor's servers behind the same loopback
      // API) and sends nothing. Plan-derived for a declared main model: set
      // or explicitly UNSET, so an ambient value cannot relax or fake it.
      // Without one, the ambient value rides through like MANDU_UPSTREAM
      // (a test pointing the stack at a stand-in upstream).
      ...(plan.tllmEndpoint ? { MANDU_UPSTREAM_LOCAL: plan.tllmEndpoint.local ? "1" : undefined } : {}),
      // …and its connection checks (plan 12 D3, D4): the entry's compiled
      // `tls` as JSON, plus its `perimeter` (CIDRs) when the arbiter attached
      // one; the proxy reads the files itself (it runs outside the agent's
      // world) and refuses to start on a setting it cannot use. Always
      // plan-derived: set, or explicitly UNSET so an ambient value never applies.
      MANDU_UPSTREAM_TLS: plan.tllmEndpoint?.tls || plan.tllmEndpoint?.perimeter
        ? JSON.stringify({ ...(plan.tllmEndpoint.tls ?? {}), ...(plan.tllmEndpoint.perimeter ? { perimeter: plan.tllmEndpoint.perimeter } : {}) })
        : undefined,
      // Codex's declared main model (plan 11 §7.2): MANDU_UPSTREAM is the
      // model_provider base_url Codex would have used (…/v1 by the OpenAI
      // convention), so the openai-proxy maps its own /v1 onto that base
      // instead of prefixing it. Plan-derived: set or explicitly UNSET.
      ...(plan.tllmEndpoint && pkg === "openai-proxy" ? { MANDU_UPSTREAM_IS_BASE_URL: "1" } : { MANDU_UPSTREAM_IS_BASE_URL: undefined }),
      // Session-keyed trust spec (agent-e2e-harness.md §7.1): the proxy binds
      // MANDU_SESSION_KEY to this spec at boot, before any classify. A
      // config-routed agent's tool names (opencode `bash`/`read`/…, openclaw
      // `exec`/…) are foreign to the arbiter's boot spec (claude-code), where
      // every one of them classified UNTRUSTED by omission and the exec /
      // outbound rules keyed on the agent's own tool names never applied
      // (live 2026-09-27: `tool_surface` listed 12 UNKNOWN tools under
      // `mandu opencode`). Bound here to the agent's own reviewed spec, the
      // one its live e2e suite proves the invariant under. Other targets keep
      // whatever the environment set (the eval harnesses use this knob).
      MANDU_INBOUND_SPEC: inboundSpecFor(plan.target) ?? process.env["MANDU_INBOUND_SPEC"],
      MANDU_TENANT: plan.tenant,
      // The routed OpenAI-family providers' real base URLs (agent-model-route.ts;
      // the proxy serves them under /_mandu/openai/<id>). Plan-derived and
      // explicitly UNSET otherwise, so an ambient value cannot add a route.
      MANDU_OPENAI_UPSTREAMS: pkg === "anthropic-proxy" && (plan.openaiRoutes?.length ?? 0) > 0
        ? JSON.stringify(Object.fromEntries(plan.openaiRoutes!.map((r) => [r.id, r.upstream])))
        : undefined,
      // The routes whose agent runs a tool call written in the model's text
      // (Goose's ollama provider): the proxy ends a response carrying one.
      MANDU_OPENAI_TEXT_CALLS: pkg === "anthropic-proxy" && (plan.openaiRoutes ?? []).some((r) => r.textCalls)
        ? JSON.stringify(plan.openaiRoutes!.filter((r) => r.textCalls).map((r) => r.id))
        : undefined,
      // fs prefix map (P2): the HumanView↔AgentView pair fs-view produced (the
      // manager runs fs-view first for exactly this). Plan-derived like the
      // keys above — explicitly UNSET when absent so a stale ambient value
      // can't apply another session's map. openai-proxy parity is P4.
      MANDU_VIEW_MAP:
        plan.viewMap && plan.viewMap.length > 0 ? JSON.stringify(plan.viewMap) : undefined,
      // The directory the agent resolves relative paths against, when the
      // launcher knows it (agentStartDir): the anthropic-proxy's sensitive-
      // path gate and derived label place a relative path there for an agent
      // whose gate surface says so (OpenCode). Plan-derived and explicitly
      // UNSET otherwise, so an ambient value cannot name a wrong base.
      MANDU_AGENT_CWD: pkg === "anthropic-proxy" ? agentStartDir(plan) : undefined,
      // The model proxy's net gate (net-gate.ts, the per-symbol leg): a symbol
      // the policy ALLOWS inside a WebFetch URL can only be released by the
      // net-proxy's TLS inspection. Plan-derived and explicitly UNSET otherwise,
      // so an ambient value cannot claim an inspection this launch did not ask
      // for. The REQUEST is what is known here (this service starts before the
      // net-proxy); if the inspecting proxy then fails to start, the call goes
      // out with the literal token — the harmless pre-gate behavior.
      MANDU_NET_TLS_INSPECTED:
        (plan.requested?.netProxyMitm ?? ((plan.effectiveAxes?.confidentiality ?? plan.confidentiality) === true))
          && plan.requested?.netProxy !== false ? "1" : undefined,
      // The launch's secret posture for the handling prompt (handling-prompt.md
      // §2): `read-blocked` on macOS tells the model that credential-file reads
      // fail by design. Predicted here because this proxy starts before the
      // secret setup (proxy-secret-posture.ts); explicitly UNSET otherwise so an
      // ambient value cannot claim a posture this launch does not have.
      MANDU_SECRET_POSTURE: proxySecretPosture({
        platform: deps.platform ?? process.platform,
        confidentiality: (plan.effectiveAxes?.confidentiality ?? plan.confidentiality) === true,
        ...(deps.commandExists ? { commandExists: deps.commandExists } : {}),
      }),
    };
    const log = join(scopeRunDir, `${pkg}.log`);
    const spec = layout.daemon(pkg, join("interceptors", pkg));
    const handle = deps.startDetachedCmd(spec.cmd, spec.args, { cwd: spec.cwd, env: { ...env, ...spec.env } }, log);
    stop = handle.stop;
    // Readiness deadline: load-aware (serviceReadyDeadlineMs; runtime-instances.md §14
    // §6), one budget for the port file and the listen. Expiry fails the
    // launch closed as before; a child that already exited ends it early.
    const budget = readinessBudget(handle);
    let boundPort = port;
    if (portFile) {
      const fileUp = await deps.waitForFile(portFile, budget.opts(100));
      if (!fileUp) { stop(); throw new Error(`mandu: ${pkg} (context proxy) did not come up (no port file at ${portFile}: ${budget.note()}; its log: ${log})`); }
      boundPort = Number(readFileSync(portFile, "utf8").trim());
      // Fail-closed on a garbled value: composing a base URL from NaN/0 would
      // launch an agent whose model calls dial nonsense.
      if (!Number.isInteger(boundPort) || boundPort <= 0 || boundPort > 65535) {
        stop();
        throw new Error(`mandu: ${pkg} published an unusable port ('${readFileSync(portFile, "utf8").trim()}' in ${portFile}) — refusing to compose a base URL from it`);
      }
    }
    const up = await deps.waitFor(() => deps.probePort(host, boundPort), budget.opts(100));
    if (!up) { stop(); throw new Error(`mandu: ${pkg} (context proxy) did not come up on ${host}:${boundPort} (${budget.note()}; its log: ${log})`); }
    // The port being UP is not enough: a concurrent launch (different arbiter /
    // view map) can win the bind race while OUR child dies with EADDRINUSE,
    // leaving a FOREIGN proxy listening. Re-probe the identity and confirm the
    // proxy that came up is actually ours before routing traffic through it —
    // the same guarantee the reuse branch enforces. Fail closed on a mismatch.
    // (An ephemeral port can't be raced the same way, but the check stays: it
    // also catches OUR child publishing a port something else answers on.)
    const startedOk = await deps.waitFor(
      async () => proxyIdentityMatches(await deps.probeIdentity(host, boundPort), plan, pkg),
      { tries: 20, delayMs: 100 },
    );
    if (!startedOk) {
      stop();
      const id = await deps.probeIdentity(host, boundPort);
      throw new ContextProxyConflictError(
        `mandu: after starting ${pkg}, ${host}:${boundPort} is answered by ${describeOccupant(id)} — a foreign ` +
        `or wrong-session proxy (likely a concurrent launch that won the port). Refusing to route this ` +
        `session's model traffic through it. Set MANDU_PROXY_PORT to a free port.`,
      );
    }
    return { host, port: boundPort, stop };
  }
}
