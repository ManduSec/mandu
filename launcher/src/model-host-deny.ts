/**
 * model-host-deny — the launch side of the model-host deny (agent-sdks.md
 * §4, "The model-host deny"; exec-routing.md §7.5).
 *
 * Every model call of a launch goes through Mandu's model proxy, which runs
 * outside the agent's tree and dials the vendor itself. A program in the tree
 * that dials a model vendor's host itself (a `claude` or `codex` started by
 * its full path, an agent SDK child past the route) bypasses it. So whenever
 * the confidentiality axis is on and the egress proxy runs, the launch:
 *   - takes the model hosts out of the tree's NO_PROXY, so a client that
 *     honours the proxy variables reaches them only through the egress proxy,
 *     whose TLS-inspected leg lets a model host take only its listed account
 *     and sign-in paths (net-proxy model-host-paths.ts; the whole host when TLS
 *     inspection is off);
 *   - drops the connect guard's allowance for the target's API host on :443
 *     and denies every model host in-kernel (`--deny`, checked before any
 *     allow, so it beats the `tcp:*:443` fallback): a client that ignores the
 *     proxy variables, or a caller that unsets them, is refused at connect;
 *   - starts the U-LLM forwarder in every posture (the quarantined U-LLM
 *     dials its vendor through the launcher, outside the tree).
 *
 * The host list is a TWIN of net-proxy model-host-paths.ts `MODEL_HOST_RULES`
 * hosts (the packages build independently; `tests/stack/model-host-deny.test.ts`
 * holds them equal).
 *
 * THE SHARED ADDRESSES. The guard denies by resolved address: api.anthropic.com,
 * platform.claude.com and claude.ai answer on one address, and chatgpt.com and
 * api.openai.com on Cloudflare's. A direct dial (around the egress proxy) to
 * another site on one of those addresses is refused too. Through the egress
 * proxy, which the guard sees only as its loopback port, nothing else changes:
 * that is where claude.ai, the OAuth refresh and the account calls go.
 *
 * Pure. Mandu-new (no reference origin).
 */

/** The model vendors' hosts the deny covers (net-proxy MODEL_HOST_RULES). */
export const MODEL_HOST_DENY_HOSTS: readonly string[] = ["api.anthropic.com", "platform.claude.com", "api.openai.com", "chatgpt.com"];

/** The net-proxy's switch (net-proxy model-host-paths.ts MODEL_HOST_DENY_ENV). */
export const NET_PROXY_MODEL_HOST_DENY_ENV = "MANDU_NET_PROXY_MODEL_HOST_DENY";

/** Is the deny on for a launch: the confidentiality axis is on. The egress
 *  proxy then carries it (services/net-proxy.ts), and the plan's
 *  `modelHostDeny` records that it does (the manager sets it from the proxy
 *  it started, so a launch with no egress proxy never takes the hosts out of
 *  NO_PROXY or denies them at the guard). Pure. */
export function modelHostDenyFor(confidentialityOn: boolean): boolean {
  return confidentialityOn;
}

/** The connect guard's deny rules for the model hosts, every port. Pure. */
export function modelHostGuardDenySpecs(): string[] {
  return MODEL_HOST_DENY_HOSTS.map((h) => `tcp:${h}:*`);
}
