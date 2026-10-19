/**
 * net-guard — PURE plan for the whole-agent, IP/DOMAIN-aware connect-guard wrap
 * (docs/design/integrity/exec-routing.md §7.5).
 *
 * This is the IP-aware companion to landlock-net (`landlock-net.ts`), which is
 * PORT-only: a Landlock TCP allow of 443 admits `:443` to EVERY host, so the
 * non-strict default leaves an any-host-on-443 exfil channel open and strict mode
 * has to deny 443 wholesale (breaking direct TLS + the OAuth refresh). The
 * connect-guard (`mandu-net-guard`, net-supervisor kernel bin) traps `connect(2)`
 * and decides by DESTINATION — IP / CIDR / resolved-hostname × port — so :443 can
 * be admitted to api.anthropic.com and a curated set while every other :443 is
 * denied in-kernel. Because the guard SUPERVISOR sits OUTSIDE the inner Landlock
 * port wrap, it reaches an allowed destination even under `--landlock-net-strict`.
 *
 * The allow-set policy (mirrors landlock-net's port policy, expressed as
 * destination rules):
 *   • ALWAYS: the loopback service ports the agent must keep reaching — the
 *     target's model proxy, and the net-proxy / U-LLM forwarder when live —
 *     pinned to loopback (127.0.0.0/8 + ::1);
 *   • ALWAYS: DNS (`udp`/`tcp` :53, any host) — name resolution must work;
 *   • the model API host on :443 (resolved) — covers a direct model dial
 *     and the OAuth-refresh residual that landlock-strict could not admit —
 *     EXCEPT under the model-host deny (model-host-deny.ts, whenever the
 *     confidentiality axis is on and the egress proxy runs): there every
 *     model host is a `--deny` rule instead (net-guard-setup.ts) and the
 *     tree reaches it only through the egress proxy;
 *   • an explicit `--net-allow` list is appended verbatim (curated, narrow);
 *   • the law's `destinations:` connect allowances (policy.yaml, read from the
 *     arbiter at launch — net-guard-law.ts) are appended as EXTRA allows that
 *     never narrow: the fallback below is kept (policy-surface.md §2.3);
 *   • the declared `local: true` model endpoints (policy.yaml `models:`, read
 *     from the arbiter at launch, model-endpoints.ts) likewise, pinned to
 *     their declared host (confidentiality-plan-11 D5);
 *   • the permissive fallback `tcp:*:443` + `tcp:*:22` is added ONLY in the
 *     non-strict, non-curated default so ordinary workflows (arbitrary HTTPS,
 *     git-ssh) survive the default-on wrap. Strict OR an explicit allow-list
 *     DROPS the fallback → the guard becomes IP/domain-precise.
 *
 * Plan/render only (mirrors landlock-net.ts): resolving the bin path, spawning,
 * and the degrade banner are the caller's job (net-guard-setup.ts / run.ts), so
 * this is unit-testable with no filesystem and no child process.
 *
 * Mandu-new (no reference origin).
 */

/** Loopback matchers the service-port rules pin to (v4 range + v6 localhost). */
const LOOPBACK_HOSTS = ["127.0.0.0/8", "[::1]"] as const;

/** The DNS rules — resolution must survive the wrap. UDP is the common path;
 *  TCP:53 covers large/truncated answers. (An honest residual: DNS itself is an
 *  exfil channel — see exec-routing.md §7.5; curate `--net-allow` to pin resolvers.) */
const DNS_RULES = ["udp:*:53", "tcp:*:53"] as const;

/** The non-strict permissive fallback: keep arbitrary HTTPS + git-ssh working. */
const WORKFLOW_FALLBACK = ["tcp:*:443", "tcp:*:22"] as const;

export interface NetGuardSpecInput {
  /** The target's model-context proxy endpoint (anthropic-proxy 8788 for claude,
   *  openai-proxy 8789 for codex). Pinned to loopback service rules. */
  targetProxyPort: number;
  /** The net-proxy port, or null when net-proxy is not live in this plan. */
  netProxyPort: number | null;
  /** The U-LLM loopback forwarder port, or null when it is not running. */
  ullmForwarderPort: number | null;
  /** The DevTools relay's loopback port (services/cdp-relay.ts), or
   *  null/absent. Never Chrome's own port: the agent reaches the browser
   *  only through the relay. */
  cdpRelayPort?: number | null;
  /** The model API host to admit on :443 (api.anthropic.com / api.openai.com);
   *  null under the model-host deny (model-host-deny.ts), where the tree's
   *  model-host traffic rides the egress proxy and the host is denied. */
  apiHost: string | null;
  /** An explicit user allow-list (--net-allow=spec,spec); undefined = none. When
   *  present the permissive `*` fallback is dropped (curated ⇒ narrow). */
  explicitAllow?: string[];
  /** Auto-derived specs for the workspace's git remotes (host:443 for https,
   *  host:22/host:<port> for ssh). Included ONLY when the set is narrowed (strict
   *  or curated) — where the `*` fallback would otherwise cover them — so a
   *  `git push`/`fetch` survives a tightened guard without a manual --net-allow.
   *  Redundant (and so omitted) in the permissive non-strict default. */
  gitRemoteSpecs?: string[];
  /** Strict network mode (--landlock-net-strict): drop the `*` fallback so :443
   *  is admitted ONLY to the api host + curated set. */
  strict: boolean;
  /** EXTRA allow specs from the law in force (policy.yaml `destinations:`
   *  with connect: allow — policy-surface.md §2.3, stage 4b). Appended
   *  in EVERY posture and NEVER narrowing: unlike `explicitAllow`, these keep
   *  the permissive fallback, so a rule the operator adds for one host cannot
   *  silently break every other workflow. undefined/[] = none. */
  extraAllow?: string[];
  /** Specs for the declared model entry the helper dials (policy.yaml
   *  `models:`, confidentiality-plan-11 D5; model-endpoints.ts
   *  `helperEndpointGuardSpecs`). Like `extraAllow` they are law: appended in
   *  every posture and never narrowing. undefined/[] = none. */
  modelEndpointSpecs?: string[];
}

/** The variable naming the guard's session-proxy exception
 *  (`net_supervisor::send_guard::PROXY_PORTS_ENV`). */
export const NET_GUARD_PROXY_PORTS_ENV = "MANDU_NET_GUARD_PROXY_PORTS";

/**
 * The loopback ports a process holding a secret reaches without a binding
 * (exec-routing.md §7.5, 2026-10-01): the net-proxy's, when it is live, and
 * nothing else. Before, the guard excepted every port of 127.0.0.1, so a host
 * resolver forwarding on 127.0.0.1:53 (dnsmasq, unbound) carried a secret off
 * the machine. The net-proxy is the one service there that judges the
 * process again (it attributes the connection and applies the process's
 * bindings, net-proxy egress.ts), on every leg since plan 13 D6 (2026-10-02):
 * plain HTTP, each TLS-inspected request, and a blind CONNECT. The model proxy and the U-LLM forwarder do
 * not judge a process's taint (they forward to a model), so a process holding
 * a secret is refused there like anywhere unbound; the agent itself never
 * holds a secret (it reads the twin), so its own model traffic is untouched.
 */
export function sessionProxyPorts(input: Pick<NetGuardSpecInput, "netProxyPort">): number[] {
  return input.netProxyPort !== null && input.netProxyPort > 0 ? [input.netProxyPort] : [];
}

/**
 * Compute the connect-guard's `--allow` spec set.
 *
 * Order matters only for readability (the guard's decision is first-match, but the
 * rules are non-overlapping except the intentional `*` fallback which is last).
 * The caller passes each returned spec as its own `--allow <spec>`.
 */
export function computeNetGuardSpecs(input: NetGuardSpecInput): string[] {
  const specs: string[] = [];

  // 1. Loopback service ports (the agent MUST keep reaching these).
  // Port 0 = a context proxy the launcher never adopted (base-URL override;
  // the default is kernel-assigned since 2026-09-26): no rule to add.
  const svcPorts = input.targetProxyPort > 0 ? [input.targetProxyPort] : [];
  if (input.netProxyPort !== null) svcPorts.push(input.netProxyPort);
  if (input.ullmForwarderPort !== null) svcPorts.push(input.ullmForwarderPort);
  if (input.cdpRelayPort != null) svcPorts.push(input.cdpRelayPort);
  for (const port of dedupeNums(svcPorts)) {
    for (const host of LOOPBACK_HOSTS) specs.push(`tcp:${host}:${port}`);
  }

  // 2. DNS.
  specs.push(...DNS_RULES);

  // 3. The model API host on :443 (resolved by the guard at runtime), unless
  //    the model-host deny is on (then it is a deny rule instead).
  if (input.apiHost !== null) specs.push(`tcp:${input.apiHost}:443`);

  // 4. Curated allow-list (verbatim) — or the permissive fallback when neither
  //    strict nor curated.
  const narrowed = input.strict || input.explicitAllow !== undefined;
  if (input.explicitAllow !== undefined) {
    specs.push(...input.explicitAllow.map((s) => s.trim()).filter(Boolean));
  } else if (!input.strict) {
    specs.push(...WORKFLOW_FALLBACK);
  }

  // 4b. The law's reachability allowances — additive, fallback-preserving, in
  //     every posture (the point of the rule is to survive strict/curated).
  if (input.extraAllow) {
    specs.push(...input.extraAllow.map((s) => s.trim()).filter(Boolean));
  }

  // 4c. The operator's own model endpoints (local: true only), pinned to the
  //     declared host; survive strict/curated for the same reason as 4b.
  if (input.modelEndpointSpecs) {
    specs.push(...input.modelEndpointSpecs.map((s) => s.trim()).filter(Boolean));
  }

  // 5. Git-remote hosts — only when narrowed (the `*` fallback covers them
  //    otherwise). Keeps `git push`/`fetch` working under strict/curated.
  if (narrowed && input.gitRemoteSpecs) {
    specs.push(...input.gitRemoteSpecs.map((s) => s.trim()).filter(Boolean));
  }

  return dedupeStrs(specs);
}

/**
 * Convert one git remote URL to a connect-guard `--allow` spec, or null when it
 * names no network host (a local path / `file://`). Handles the URL forms
 * (`https://`, `http://`, `ssh://`, `git://`) and the scp-like ssh shorthand
 * (`[user@]host:path`). Credentials (`user@`) are stripped; an explicit `:port`
 * wins, else the scheme's default (https 443, http 80, ssh 22, git 9418).
 */
export function gitRemoteToSpec(url: string): string | null {
  const u = url.trim();
  if (!u) return null;

  // Scheme URL: scheme://[user@]host[:port]/path
  const m = /^([a-z][a-z0-9+.-]*):\/\/([^/]+)(?:\/|$)/i.exec(u);
  if (m) {
    const scheme = m[1]!.toLowerCase();
    if (scheme === "file") return null;
    const defPort: Record<string, number> = { https: 443, http: 80, ssh: 22, git: 9418, ftp: 21, ftps: 990 };
    const port = defPort[scheme];
    if (port === undefined) return null; // unknown scheme → no rule
    const { host, port: explicit } = splitAuthority(m[2]!);
    if (!host) return null;
    return `tcp:${host}:${explicit ?? port}`;
  }

  // scp-like ssh shorthand: [user@]host:path — a ':' that precedes any '/'. The
  // host is either a bracketed IPv6 literal or a run with no ':' or '/'. Rejects a
  // bare local path (no ':' before '/').
  const scp = /^(?:[^@]+@)?(\[[^\]]+\]|[^:/]+):(?!\/)/.exec(u);
  if (scp) {
    const host = bracketHostIfV6(scp[1]!);
    return host ? `tcp:${host}:22` : null;
  }
  return null; // local path or unrecognized → no network host
}

/** Convert a set of git remote URLs to deduped connect-guard specs. */
export function gitRemoteSpecs(urls: string[]): string[] {
  return dedupeStrs(urls.map(gitRemoteToSpec).filter((s): s is string => s !== null));
}

/** Split an authority `[user@]host[:port]` (host may be a bracketed IPv6) into
 *  `{ host, port }`, stripping any userinfo. host is kept bracketed for IPv6 so
 *  it re-parses as a guard spec. */
function splitAuthority(authority: string): { host: string; port?: number } {
  let a = authority;
  const at = a.lastIndexOf("@");
  if (at >= 0) a = a.slice(at + 1);
  // Bracketed IPv6: [::1] or [::1]:port
  if (a.startsWith("[")) {
    const close = a.indexOf("]");
    if (close < 0) return { host: "" };
    const host = a.slice(0, close + 1); // keep brackets
    const rest = a.slice(close + 1);
    const port = rest.startsWith(":") ? Number(rest.slice(1)) : undefined;
    return { host, port: Number.isInteger(port) ? port : undefined };
  }
  const colon = a.lastIndexOf(":");
  if (colon >= 0) {
    const port = Number(a.slice(colon + 1));
    return { host: a.slice(0, colon), port: Number.isInteger(port) ? port : undefined };
  }
  return { host: a };
}

/** Bracket a bare IPv6 literal so it re-parses as a guard host; leave names/v4. */
function bracketHostIfV6(host: string): string {
  if (host.includes(":") && !host.startsWith("[")) return `[${host}]`;
  return host;
}

/** True iff the computed set still admits arbitrary hosts on :443 (the permissive
 *  fallback is present) — the caller banners the open trade-off in that case. */
export function specsAdmitAnyHttps(specs: string[]): boolean {
  return specs.includes("tcp:*:443");
}

/**
 * Render the `mandu-net-guard --allow <spec>... --skip-unsupported --` wrap
 * argv. Each spec is its own `--allow` pair; `--skip-unsupported` (degrade to a
 * plain exec where seccomp NEW_LISTENER is unavailable) and the trailing `--` are
 * ALWAYS present. An empty spec set is a whole-agent connect DENY-all (valid, but
 * the caller always seeds at least the model-proxy loopback rule).
 *
 * `deny`: one `--deny <spec>` pair each, after the allows. The guard refuses a
 * deny-listed destination before any allow rule is consulted (an agent's
 * upload hosts, upload-deny.ts), so a deny beats the `tcp:*:443` fallback.
 *
 * `required`: the launch depends on the guard (OpenCode 2 with the
 * confidentiality axis on, opencode2-confidentiality.ts), so the degrade is
 * dropped: a guard that cannot install its listener exits 71 and the agent
 * never runs.
 */
export function planNetGuard(opts: { binPath: string; specs: string[]; deny?: string[]; extra?: string[]; required?: boolean }): { wrapArgv: string[] } {
  const specTokens = opts.specs.flatMap((s) => ["--allow", s]);
  const denyTokens = (opts.deny ?? []).flatMap((s) => ["--deny", s]);
  return { wrapArgv: [opts.binPath, ...specTokens, ...denyTokens, ...(opts.extra ?? []), ...(opts.required ? [] : ["--skip-unsupported"]), "--"] };
}

function dedupeNums(xs: number[]): number[] {
  return [...new Set(xs)].sort((a, b) => a - b);
}

function dedupeStrs(xs: string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const x of xs) {
    if (!seen.has(x)) {
      seen.add(x);
      out.push(x);
    }
  }
  return out;
}
