/**
 * services/net-proxy — start-or-reuse the cooperative egress proxy.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy):
 *   Adapted from launcher/mandu-run.sh net-proxy block (L666-846): reuse if
 *   the port already listens; else start `interceptors/net-proxy` with the
 *   autostart env vars (incl. MANDU_SESSION_KEY=<scopeId>); wait for the port;
 *   under MITM wait for the async-minted CA cert. Fail-closed (spec §5): a
 *   requested proxy that can't come up THROWS; the manager applies --best-effort.
 *
 * Start-or-reuse identity check (parity with services/context-proxy.ts): a
 * proxy already listening on the port is adopted ONLY when it publishes
 * (`GET /_mandu/identity`) the same service ("net-proxy") and arbiter socket
 * as THIS launch. A net-proxy from ANOTHER session or the shared stack
 * (different arbiter → its egress gate consults the wrong policy/symbol table,
 * and approvals/events land in the wrong session) or a foreign server on the
 * port is a conflict: we FAIL CLOSED rather than point this session's
 * HTTP(S)_PROXY egress at the wrong daemon. Enforced on BOTH paths: the reuse
 * branch AND after we start our own child (a concurrent launch can win the
 * port race, leaving a foreign proxy up). MANDU_NET_PROXY_PORT=0 (config
 * `net-proxy-port = 0`) sidesteps the conflict class entirely: the kernel
 * assigns a port, published via the port file — no well-known rendezvous to
 * squat. Since 2026-09-26 port 0 is the DEFAULT (release checklist a1); only a
 * pinned port ever takes the reuse / conflict branch.
 *
 * The held request (egress-hold.ts, egress-hold.md "The default"): the
 * proxy this launch starts gets the launch's MANDU_EGRESS_HOLD_MS. A proxy
 * adopted on a pinned port keeps the hold it was started with; the hold is
 * not part of the reuse key, since it only changes how long a refusal takes,
 * never what is sent.
 */
import { readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import type { LaunchPlan } from "../types.js";
import type { Layout } from "./layout.js";
import { describeOccupant, readinessBudget, type ServiceDeps, type ProxyIdentity } from "./primitives.js";
import { humanSockEnv } from "../human-plane.js";
import { NET_PROXY_DENY_HOSTS_ENV, netProxyDenyHosts } from "../upload-deny.js";
import { publishFile } from "../safe-file.js";
import { sessionLogins, sessionLoginsKey, type SessionLogins } from "../agent-login.js";
import { homedir } from "node:os";
import { EGRESS_HOLD_ENV, launcherEgressHold, type EgressHoldChoice } from "../egress-hold.js";
import { MODEL_HOST_DENY_HOSTS, NET_PROXY_MODEL_HOST_DENY_ENV, modelHostDenyFor } from "../model-host-deny.js";
import { PROVIDER_KEY_HOSTS } from "../agent-key-grant.js";

/** The net-proxy's model-services list (net-proxy server-main). */
export const NET_PROXY_MODEL_SERVICES_ENV = "MANDU_NET_PROXY_MODEL_SERVICES";

/** The net-proxy's handling-note switch (net-proxy model-note.ts). */
export const NET_PROXY_MODEL_NOTE_ENV = "MANDU_NET_PROXY_MODEL_NOTE";

/** `browser` for a launch that runs a DevTools relay (`--browser-cdp`,
 *  `--browser`): the browser agent's own Chat Completions calls to a model
 *  service then get Mandu's handling note (devtools-relay.md §6.5). Else
 *  empty: no other program's model call is changed. */
export function modelNoteOf(plan: Pick<LaunchPlan, "browserCdp" | "browser">): string {
  return plan.browserCdp || plan.browser ? "browser" : "";
}

/** The launch's hold (plan.egressHold, run.ts), or, for a plan built
 *  without one, the unattended answer: the user's MANDU_EGRESS_HOLD_MS,
 *  else 0. */
export function egressHoldOf(plan: Pick<LaunchPlan, "egressHold" | "argv">): EgressHoldChoice {
  return plan.egressHold ?? launcherEgressHold({ env: process.env, argv: plan.argv, stdoutIsTTY: false });
}

/** The net-proxy's variable for the session's logins (interceptors/net-proxy
 *  session-logins.ts SESSION_LOGINS_ENV; the packages build independently). */
export const NET_PROXY_SESSION_LOGINS_ENV = "MANDU_NET_PROXY_SESSION_LOGINS";

/** The session's NO_PROXY list (env-compose.ts sets it beside HTTP(S)_PROXY):
 *  the loopback names (the session's own proxies and forwarder), the two
 *  model vendors' API hosts unless the model-host deny is on
 *  (model-host-deny.ts: then a model host is reached only through the egress
 *  proxy, which judges each path, and a MANDU_MODEL_HOSTS entry naming one
 *  is left out too), and MANDU_MODEL_HOSTS. null when the session has no
 *  net-proxy (nothing is proxied, so no list is set). Pure. */
export function sessionNoProxy(plan: Pick<LaunchPlan, "netProxy" | "noProxyExtra"> & Partial<Pick<LaunchPlan, "modelHostDeny">>): string | null {
  if (!plan.netProxy) return null;
  const deny = plan.modelHostDeny === true;
  const vendors = deny ? [] : ["api.anthropic.com", "api.openai.com"];
  const extra = (plan.noProxyExtra ?? []).filter((h) => !deny || !MODEL_HOST_DENY_HOSTS.includes(h.trim().toLowerCase().replace(/\.$/, "")));
  return ["127.0.0.1", "localhost", "::1", ...vendors, ...extra].join(",");
}

export interface NetProxyResult {
  netProxy: { host: string; port: number };
  mitmCaCert?: string;
  /** System CAs + the session CA (see LaunchPlan.mitmCaBundle). */
  mitmCaBundle?: string;
  /** The user's own CA files merged with the session CA, by variable (see
   *  LaunchPlan.mitmUserTrust). */
  mitmUserTrust?: Record<string, string>;
  /** Auto MITM asked for but no session CA appeared: the notice to print. */
  mitmDegraded?: string;
  /** The proxy carries the model-host deny (model-host-deny.ts); the manager
   *  puts it on the plan (`LaunchPlan.modelHostDeny`). */
  modelHostDeny: boolean;
  stop: () => void;
}

/** Where a host keeps its trusted CA bundle, first hit wins. */
const SYSTEM_CA_BUNDLES = [
  "/etc/ssl/certs/ca-certificates.crt", // Debian/Ubuntu
  "/etc/pki/tls/certs/ca-bundle.crt",   // RHEL/Fedora
  "/etc/ssl/ca-bundle.pem",             // SUSE
  "/etc/ssl/cert.pem",                  // Alpine, macOS (LibreSSL)
];

/** System CAs + the session CA in one file, or undefined when the host has
 *  no bundle we know (then only the ADDITIVE Node variable is exported: a
 *  REPLACING variable pointing at the session CA alone would make every
 *  direct TLS connection, the model host included, fail verification). */
export function writeCaBundle(caDir: string, sessionCaPem: string): string | undefined {
  for (const sys of SYSTEM_CA_BUNDLES) {
    let system: string;
    try { system = readFileSync(sys, "utf8"); } catch { continue; }
    const out = join(caDir, "mandu-ca-bundle.pem");
    const session = readFileSync(sessionCaPem, "utf8");
    publishFile(out, `${system.replace(/\s*$/, "")}\n${session.replace(/\s*$/, "")}\n`, { mode: 0o644 });
    return out;
  }
  return undefined;
}

/** The trust variables the session sets under TLS inspection (env-compose.ts
 *  `mitmTrustEnv`). Each client reads ONE file from its variable. */
export const TRUST_VARS = [
  "NODE_EXTRA_CA_CERTS", "CURL_CA_BUNDLE", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE",
  "GIT_SSL_CAINFO", "CARGO_HTTP_CAINFO", "AWS_CA_BUNDLE", "CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE",
] as const;

/**
 * Keep the user's own CA files under TLS inspection (confidentiality-plan-12
 * F6). Setting a trust variable to the session's file would REPLACE whatever
 * file the user had pointed it at, so a corporate CA they gave curl, git,
 * pip or Node (the model helper included) is lost in the agent's world and
 * TLS to their internal hosts fails. For each trust variable the user set to
 * a readable PEM file, this writes that file plus the session CA to one file
 * in `caDir` and returns it by variable; the caller hands it out instead of
 * the session-only file. The user's file keeps its meaning (a file that
 * replaced the store still replaces it, now with the session CA added); a
 * value that is not a readable file holding a certificate is left alone
 * (the session's file is used, as before). One merged file per distinct
 * source path. Never throws.
 */
export function writeUserTrustFiles(
  caDir: string,
  sessionCaPem: string,
  env: Record<string, string | undefined>,
  io: { read: (p: string) => string; write: (p: string, data: string) => void } = {
    read: (p) => readFileSync(p, "utf8"),
    write: (p, data) => publishFile(p, data, { mode: 0o644 }),
  },
): Record<string, string> {
  const out: Record<string, string> = {};
  let session: string;
  try { session = io.read(sessionCaPem); } catch { return out; }
  const bySource = new Map<string, string>();
  for (const v of TRUST_VARS) {
    const src = (env[v] ?? "").trim();
    if (src === "") continue;
    let merged = bySource.get(src);
    if (merged === undefined) {
      let pem: string;
      try { pem = io.read(src); } catch { continue; }
      if (!pem.includes("-----BEGIN CERTIFICATE-----")) continue;
      merged = join(caDir, `mandu-user-ca-${bySource.size + 1}.pem`);
      try { io.write(merged, `${pem.replace(/\s*$/, "")}\n${session.replace(/\s*$/, "")}\n`); } catch { continue; }
      bySource.set(src, merged);
    }
    out[v] = merged;
  }
  return out;
}

/**
 * A hard fail-closed condition that --best-effort MUST NOT override (parity
 * with ContextProxyConflictError): the egress-proxy port is held by a foreign /
 * wrong-session server. Proceeding would point HTTP(S)_PROXY — every
 * cooperative egress decision — at a daemon consulting the WRONG arbiter.
 * (Under the manager's default-on soft mode this instead degrades loudly:
 * net-proxy is left out of the plan entirely, so nothing routes through the
 * stranger.)
 */
export class NetProxyConflictError extends Error {
  readonly failClosedFatal = true;
  constructor(message: string) {
    super(message);
    this.name = "NetProxyConflictError";
  }
}

/**
 * Is a listening net-proxy's published identity safe for THIS launch to adopt?
 * Keyed on the security-relevant routing: the service and the arbiter socket
 * (wrong one = wrong egress policy + symbol table). The sessionKey is NOT part
 * of the key — two launches sharing an arbiter legitimately reuse one proxy
 * (parity with context-proxy's proxyIdentityMatches) — but the logins the
 * proxy exempts from the tripwire are (`logins`, `sessionLogins`): a proxy
 * started for a launch of another agent would exempt that agent's login
 * here and refuse this one's own.
 */
export function netProxyIdentityMatches(id: ProxyIdentity | null, plan: LaunchPlan, logins?: SessionLogins): boolean {
  if (!id || id.mandu !== true) return false;
  if (id.service !== "net-proxy") return false;
  if (id.arbiterSock !== plan.arbiterSock) return false;
  // The logins exempt from the tripwire (secret-discovery.md §1.10): the
  // same ones only (a proxy that predates the field publishes none).
  if (logins !== undefined && sessionLoginsKey(id.sessionLogins) !== sessionLoginsKey(logins)) return false;
  // The model-host deny (model-host-deny.ts): a proxy started without it
  // would pass a model host this launch takes out of NO_PROXY.
  const hasDeny = Array.isArray(id.modelHostDeny) && id.modelHostDeny.length > 0;
  if (hasDeny !== modelHostDenyFor(netProxyConfidentiality(plan))) return false;
  // The agent's upload hosts (upload-deny.ts): a proxy started for another
  // launch denies another set, so this launch's uploads could pass it. Equal
  // sets only (a proxy that predates the list publishes none = empty).
  return denyKey(id.denyHosts ?? []) === denyKey(netProxyDenyHosts(plan));
}

/** The confidentiality axis of the launch, as the egress proxy is set up for
 *  it (TLS inspection, the model-host deny). */
function netProxyConfidentiality(plan: Pick<LaunchPlan, "effectiveAxes" | "confidentiality">): boolean {
  return (plan.effectiveAxes?.confidentiality ?? plan.confidentiality) === true;
}

function denyKey(hosts: readonly string[]): string {
  return JSON.stringify([...new Set(hosts.map((h) => h.trim().toLowerCase()).filter(Boolean))].sort());
}

export async function startNetProxy(
  plan: LaunchPlan,
  layout: Layout,
  scopeRunDir: string,
  deps: ServiceDeps,
): Promise<NetProxyResult> {
  const host = process.env["MANDU_NET_PROXY_HOST"] || "127.0.0.1";
  // Default 0 = kernel-assigned (release checklist a1, runtime-instances.md
  // §8): the old fixed 8790 belonged to whichever stack started first, so a
  // second user's (or the resident stack's) egress proxy made this launch
  // lose its egress gate. A pinned MANDU_NET_PROXY_PORT / config
  // `net-proxy-port` still wins (and keeps the identity-checked reuse below).
  const port = Number(process.env["MANDU_NET_PROXY_PORT"] || 0);
  // Plan 10 §11.5: TLS inspection is ON whenever the confidentiality axis is
  // on (a masked value is put back only inside a request the proxy can read);
  // an explicit flag/env/config value wins either way.
  const explicitMitm = plan.requested.netProxyMitm;
  const confidentialityOn = netProxyConfidentiality(plan);
  const mitm = explicitMitm ?? confidentialityOn;
  // The model-host deny (model-host-deny.ts): with the confidentiality axis.
  const modelHostDeny = modelHostDenyFor(confidentialityOn);
  const caDir = process.env["MANDU_NET_PROXY_MITM_CA_DIR"] || join(scopeRunDir, "egress-mitm-ca");
  const caCert = join(caDir, "mandu-egress-ca.pem");

  // The AI agents' logins this session leaves raw: the net-proxy sends them
  // with each tripwire scan, so another session's registration of them does
  // not refuse this session's agent its own login (secret-discovery.md §1.10).
  // HOME: the launch's (`deps.home` is a test seam).
  const logins = sessionLogins(plan, process.env, deps.home ?? homedir());
  let stop = () => {};
  let boundPort = port;
  // Start-or-reuse: if something is already listening, adopt it ONLY when its
  // published identity matches THIS launch; otherwise fail closed (a foreign or
  // wrong-session net-proxy must never carry this session's egress). Port 0
  // (ephemeral) skips this branch entirely: there is no well-known rendezvous
  // to reuse OR to conflict on.
  if (port !== 0 && (await deps.probePort(host, port))) {
    const id = await deps.probeIdentity(host, port);
    if (!netProxyIdentityMatches(id, plan, logins)) {
      throw new NetProxyConflictError(
        `mandu: ${host}:${port} is occupied by ${describeOccupant(id)} — refusing to point this ` +
        `session's HTTP(S)_PROXY egress at it (its arbiter differs, so egress gating, approvals and ` +
        `events would be wrong; or it was started for another launch's agent, upload hosts or logins). ` +
        `Stop it, or set MANDU_NET_PROXY_PORT to a free port (0 = ephemeral).`,
      );
    }
    // Safe reuse: same service + arbiter. We did not start it → never tear it down.
  } else {
    // Ephemeral port (0): the kernel picks; the proxy publishes the bound port
    // into the port file (server-main's atomic tmp+rename), and we adopt it.
    // Clear any stale file first — adopting a previous run's port would probe
    // (and possibly identity-match) a daemon this launch does not own.
    const portFile = port === 0 ? join(scopeRunDir, "net-proxy.port") : undefined;
    if (portFile) rmSync(portFile, { force: true });
    const env: Record<string, string | undefined> = {
      ...process.env,
      MANDU_ARBITER_SOCK: plan.arbiterSock,
      // The egress resolve after desymbolizationDecision runs on the arbiter's
      // HUMAN plane (arbiter-human-plane.md); unset when none was reported.
      ...humanSockEnv(plan.arbiterHumanSock),
      MANDU_NET_PROXY_HOST: host,
      MANDU_NET_PROXY_PORT: String(port),
      // Explicitly UNSET when unused so a stale ambient value can't make the
      // proxy write a rogue port file (context-proxy parity).
      MANDU_PORT_FILE: portFile,
      MANDU_SESSION_KEY: plan.scopeId,
      MANDU_TENANT: plan.tenant,
      MANDU_NET_PROXY_MITM: mitm ? "1" : "",
      MANDU_NET_PROXY_MITM_CA_DIR: caDir,
      MANDU_NET_PROXY_MITM_INSECURE_UPSTREAM: process.env["MANDU_NET_PROXY_MITM_INSECURE_UPSTREAM"] || "",
      MANDU_NET_PROXY_MOCK_SITES: plan.mockSitesPath || "",
      // The agent's upload hosts (upload-deny.ts), refused with 403 before
      // any dial; explicitly empty otherwise so an ambient value cannot leak in.
      [NET_PROXY_DENY_HOSTS_ENV]: netProxyDenyHosts(plan).join(","),
      // The logins this session leaves raw (session-logins.ts), always set,
      // so an ambient value cannot widen the exemption.
      [NET_PROXY_SESSION_LOGINS_ENV]: JSON.stringify(logins),
      // The model-host deny (model-host-deny.ts), always set so an ambient
      // value cannot turn it on or off.
      [NET_PROXY_MODEL_HOST_DENY_ENV]: modelHostDeny ? "1" : "",
      // Model services a program calls itself (agent-sign-in.md §3.12): a
      // placeholder to one leaves as it is. Always set, from the launcher's
      // own list, so an ambient value cannot widen it.
      [NET_PROXY_MODEL_SERVICES_ENV]: Object.values(PROVIDER_KEY_HOSTS).join(","),
      // A browser agent's model calls get Mandu's handling note
      // (devtools-relay.md §6.5): always set, so an ambient value cannot
      // turn it on for a launch with no relay.
      [NET_PROXY_MODEL_NOTE_ENV]: modelNoteOf(plan),
      // The held request (egress-hold.ts): the launch's decision, always
      // set, so the proxy never holds by an ambient value the launcher did
      // not choose. A plan without one (built outside run.ts) is decided
      // as unattended: the user's value, else 0.
      [EGRESS_HOLD_ENV]: egressHoldOf(plan).ms,
    };
    const log = join(scopeRunDir, "net-proxy.log");
    const spec = layout.daemon("net-proxy", join("interceptors", "net-proxy"));
    const handle = deps.startDetachedCmd(spec.cmd, spec.args, { cwd: spec.cwd, env: { ...env, ...spec.env } }, log);
    stop = handle.stop;
    // The context proxy's load-aware readiness deadline (runtime-instances.md §14.6).
    const budget = readinessBudget(handle);
    if (portFile) {
      const fileUp = await deps.waitForFile(portFile, budget.opts(100));
      if (!fileUp) { stop(); throw new Error(`mandu: net-proxy did not come up (no port file at ${portFile}: ${budget.note()}; its log: ${log})`); }
      boundPort = Number(readFileSync(portFile, "utf8").trim());
      // Fail-closed on a garbled value: composing HTTP(S)_PROXY from NaN/0
      // would launch an agent whose egress dials nonsense.
      if (!Number.isInteger(boundPort) || boundPort <= 0 || boundPort > 65535) {
        stop();
        throw new Error(`mandu: net-proxy published an unusable port ('${readFileSync(portFile, "utf8").trim()}' in ${portFile}) — refusing to compose HTTP(S)_PROXY from it`);
      }
    }
    const up = await deps.waitFor(() => deps.probePort(host, boundPort), budget.opts(100));
    if (!up) { stop(); throw new Error(`mandu: net-proxy did not come up on ${host}:${boundPort} (${budget.note()}; its log: ${log})`); }
    // The port being UP is not enough: a concurrent launch (different arbiter)
    // can win the bind race while OUR child dies with EADDRINUSE, leaving a
    // FOREIGN proxy listening. Re-probe the identity and confirm the proxy that
    // came up is actually ours before pointing egress at it — the same
    // guarantee the reuse branch enforces. Fail closed on a mismatch.
    const startedOk = await deps.waitFor(
      async () => netProxyIdentityMatches(await deps.probeIdentity(host, boundPort), plan, logins),
      { tries: 20, delayMs: 100 },
    );
    if (!startedOk) {
      stop();
      const id = await deps.probeIdentity(host, boundPort);
      throw new NetProxyConflictError(
        `mandu: after starting net-proxy, ${host}:${boundPort} is answered by ${describeOccupant(id)} — a foreign ` +
        `or wrong-session proxy (likely a concurrent launch that won the port). Refusing to point this ` +
        `session's HTTP(S)_PROXY egress at it. Set MANDU_NET_PROXY_PORT to a free port (0 = ephemeral).`,
      );
    }
  }

  let mitmCaCert: string | undefined;
  let mitmCaBundle: string | undefined;
  let mitmUserTrust: Record<string, string> | undefined;
  let mitmDegraded: string | undefined;
  if (mitm) {
    const ready = await deps.waitForFile(caCert, { tries: 100, delayMs: 50 });
    if (!ready && explicitMitm === true) { stop(); throw new Error(`mandu: net-proxy MITM CA cert never appeared at ${caCert}`); }
    if (!ready) {
      // Auto: the proxy itself degraded to the blind tunnel (no openssl, or
      // the CA mint failed). Say so once; the gate still holds (a symbol in a
      // tunnel is withheld), only the RELEASE at a bound host is lost.
      mitmDegraded =
        "net-proxy: TLS inspection unavailable (no session CA was minted; is openssl on PATH?) — " +
        "HTTPS bodies ride a blind tunnel, so a masked value cannot be put back for a bound host. " +
        "Install openssl, or --no-net-proxy-mitm to silence this." +
        (modelHostDeny ? ` ${MODEL_HOSTS_UNREAD_NOTE}` : "");
    } else {
      mitmCaCert = caCert;
      try { mitmCaBundle = writeCaBundle(caDir, caCert); } catch { mitmCaBundle = undefined; }
      const userTrust = writeUserTrustFiles(caDir, caCert, process.env);
      if (Object.keys(userTrust).length > 0) mitmUserTrust = userTrust;
    }
  }
  // TLS inspection turned off by the user under the deny: the model hosts
  // are refused whole (no path can be read), so say what that costs.
  if (!mitm && modelHostDeny) mitmDegraded = `net-proxy: TLS inspection is off (--no-net-proxy-mitm). ${MODEL_HOSTS_UNREAD_NOTE}`;
  return { netProxy: { host, port: boundPort }, mitmCaCert, mitmCaBundle, mitmUserTrust, mitmDegraded, modelHostDeny, stop };
}

/** What the model-host deny does where the egress proxy cannot read HTTPS
 *  (model-host-deny.ts; agent-sdks.md §4, "The model-host deny"). */
export const MODEL_HOSTS_UNREAD_NOTE =
  "The model hosts (api.anthropic.com, platform.claude.com, api.openai.com, chatgpt.com) are refused whole to the " +
  "agent's programs, since no path can be read: the agent's own calls there (account, usage, sign-in refresh) fail " +
  "too, while its model calls still go through Mandu's model proxy.";
