/**
 * landlock-net — PURE plan for the whole-agent TCP port-allow wrap
 * (docs/design/integrity/exec-routing.md §7).
 *
 * The wrap is the committed `mandu-landlock-apply --net-only` binary
 * (interceptors/exec-supervisor/src/bin/mandu-landlock-apply.rs), prepended to
 * the agent's launch prefix so the ENTIRE agent process tree — the agent, every
 * shell it spawns, every nested bwrap sandbox, and the stdio U-LLM child — may
 * CONNECT only to the named TCP ports; all other TCP is denied in-kernel (ABI
 * ≥ 4 / kernel ≥ 6.7). A prompt-injected raw-socket exfil that bypasses
 * HTTP_PROXY therefore still fails at the LSM layer. `--skip-unsupported`
 * degrades to a plain exec on a pre-6.7 kernel (the netns / proxy stay the
 * boundary there) so the wrap never breaks a live agent.
 *
 * This module is plan/render only (mirrors secret-twins.ts): resolving the
 * applier path, deciding the port set from the live plan, and spawning are the
 * caller's job (landlock-net-setup.ts / run.ts), so the policy is unit-testable
 * with no filesystem and no child process.
 *
 * Mandu-new (no reference origin).
 */

/** Inputs for the port set: the loopback ports the agent must keep reaching,
 *  plus the workflow-port / explicit-override policy (exec-routing.md §7). */
export interface LandlockNetPortInput {
  /** The model-context proxy port for THIS target — anthropic-proxy (8788) for
   *  claude, openai-proxy (8789) for codex. The agent's T-LLM calls route
   *  through it; a wrap that severed it would be pointless. */
  targetProxyPort: number;
  /** The net-proxy port, or null when net-proxy is not enabled in this plan. */
  netProxyPort: number | null;
  /** The loopback U-LLM forwarder port, or null when it is not running. With
   *  it, the U-LLM no longer needs a direct :443 dial — the reason strict mode
   *  is viable at all. */
  ullmForwarderPort: number | null;
  /** The DevTools relay's loopback port (services/cdp-relay.ts), or
   *  null/absent when there is none. Chrome's own port is never in the set:
   *  the agent reaches the browser only through the relay. */
  cdpRelayPort?: number | null;
  /** The port of the declared model entry the helper dials (policy.yaml
   *  `models:`, confidentiality-plan-11 D5; model-endpoints.ts
   *  `helperEndpointPorts`, which says why only that one). `inspect-mcp`
   *  runs inside this wrap and dials it directly. undefined/[] = none. */
  modelEndpointPorts?: number[];
  /** An explicit user override (--landlock-net=port,port); undefined = none.
   *  When present it REPLACES the computed set (suppresses the auto 443/22). */
  explicitPorts?: number[];
  /** Strict mode (--landlock-net-strict): never auto-add the workflow ports. */
  strict: boolean;
}

/** The non-strict "workflow ports": direct TLS (443 — CC-internal calls,
 *  proxy-unaware fetchers, a codex U-LLM) and ssh (22 — git push over ssh
 *  remotes). Each is an unmediated egress channel a prompt-injected exfil can
 *  ride, which is exactly why strict mode denies both; the default keeps them
 *  so a live agent's ordinary workflows survive the default-on wrap. */
export const WORKFLOW_PORTS = [443, 22] as const;

/**
 * Compute the allowed-TCP-port set for the wrap.
 *
 * - An explicit override (`explicitPorts`) is used verbatim — the user curates
 *   the whole set (the caller warns if it omits the target's proxy port).
 * - Otherwise: always the target's model-proxy port; the net-proxy and U-LLM
 *   forwarder ports IFF live; the declared local model endpoints' ports; and
 *   the workflow ports (443 + 22) UNLESS strict.
 *
 * planLandlockNet dedupes + sorts, so order/duplicates here do not matter.
 */
export function computeLandlockNetPorts(input: LandlockNetPortInput): number[] {
  if (input.explicitPorts !== undefined) return input.explicitPorts;
  // A target proxy port of 0 is one the launcher never adopted (the context
  // proxy is skipped for an explicit base-URL override, and the built-in
  // default is 0 = kernel-assigned since 2026-09-26): there is nothing to allow.
  const ports = input.targetProxyPort > 0 ? [input.targetProxyPort] : [];
  if (input.netProxyPort !== null) ports.push(input.netProxyPort);
  if (input.ullmForwarderPort !== null) ports.push(input.ullmForwarderPort);
  if (input.cdpRelayPort != null) ports.push(input.cdpRelayPort);
  // Declared local model endpoints: law, so kept under strict too (strict
  // denies the unmediated workflow ports, not the operator's own model).
  if (input.modelEndpointPorts) ports.push(...input.modelEndpointPorts);
  if (!input.strict) ports.push(...WORKFLOW_PORTS);
  return ports;
}

/**
 * Render the `mandu-landlock-apply --net-only …` wrap argv. Each allowed port
 * is its own `--allow-tcp-port <port>` pair and each BIND port its own
 * `--allow-tcp-bind-port <port>` pair (the applier grants BIND|CONNECT on
 * those, so a bind port never needs repeating in `ports`); both lists are
 * deduped + sorted so the argv (and the tests) are deterministic.
 * `--skip-unsupported` and the trailing `--` are ALWAYS present (degrade on a
 * pre-6.7 kernel; the agent argv follows the separator), except under
 * `failClosed`: a caller whose probe just said the kernel confines TCP (the
 * inspect-mcp wrap, inspect-net-confine.ts) drops it, so a wrong probe answer
 * stops the wrapped command (exit 71) instead of running it unconfined. An
 * empty port set is valid — a whole-agent TCP deny-all.
 */
export function planLandlockNet(opts: { applierPath: string; ports: number[]; bindPorts?: number[]; failClosed?: boolean }): { wrapArgv: string[] } {
  const bind = [...new Set(opts.bindPorts ?? [])].sort((a, b) => a - b);
  const uniqueSorted = [...new Set(opts.ports)].filter((p) => !bind.includes(p)).sort((a, b) => a - b);
  const portTokens = uniqueSorted.flatMap((p) => ["--allow-tcp-port", String(p)]);
  const bindTokens = bind.flatMap((p) => ["--allow-tcp-bind-port", String(p)]);
  return { wrapArgv: [opts.applierPath, "--net-only", ...portTokens, ...bindTokens, ...(opts.failClosed ? [] : ["--skip-unsupported"]), "--"] };
}
