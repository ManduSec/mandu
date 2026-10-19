/**
 * browser-cdp — the launch side of the DevTools relay
 * (docs/design/agents/devtools-relay.md §6).
 *
 * `--browser-cdp <url>` (or MANDU_BROWSER_CDP) names the debugging endpoint
 * of a Chrome the user runs (`--remote-debugging-port=9222` with a dedicated
 * `--user-data-dir`). The launcher starts the relay on it, outside the
 * agent's tree (services/cdp-relay.ts), and gives the agent the relay's URL
 * in the variables browser agents read:
 *
 *   BU_CDP_URL             Browser Harness (jev-ultrafast's browser layer)
 *                          resolves it through /json/version;
 *   MANDU_BROWSER_CDP_URL  the same URL, for a script or an agent's own
 *                          setting (browser-use `cdp_url`, Playwright
 *                          `connect_over_cdp`, the DevTools MCPs'
 *                          `--browserUrl` / `--cdp-endpoint`).
 *
 * The connect guards admit the relay's port (landlock-net-setup.ts,
 * net-guard-setup.ts) and not Chrome's own, so the agent reaches Chrome only
 * through the relay. Chrome's port must be one the guards do not admit
 * anyway (`chromePortRefusal`); where no guard runs, the launch says the
 * agent can reach Chrome around the relay (`unguardedNote`).
 *
 * Pure. Mandu-new (no reference origin).
 */

/** The launcher's own variable for the endpoint (parse.ts). */
export const BROWSER_CDP_ENV = "MANDU_BROWSER_CDP";

/** The variables the agent is given the relay's URL in. */
export const BROWSER_CDP_AGENT_VARS = ["BU_CDP_URL", "MANDU_BROWSER_CDP_URL"] as const;

const LOOPBACK = new Set(["127.0.0.1", "localhost", "[::1]"]);

/**
 * The upstream the relay dials, normalized to `http://host:port`, or throws
 * with a message the launch prints. Only Chrome's HTTP endpoint on this
 * machine: the relay reads `/json/version` there, and a Chrome elsewhere
 * would be reachable by the agent on the network, around the relay.
 * A `ws://…/devtools/browser/<id>` URL is turned into its HTTP endpoint (the
 * relay finds the browser target itself).
 */
export function parseBrowserCdp(raw: string): string {
  const v = raw.trim();
  let u: URL;
  try {
    u = new URL(v);
  } catch {
    throw new Error(`mandu: --browser-cdp wants Chrome's debugging endpoint, such as http://127.0.0.1:9222 (got ${JSON.stringify(raw)})`);
  }
  if (u.protocol !== "http:" && u.protocol !== "ws:") {
    throw new Error(`mandu: --browser-cdp wants an http:// (or ws://) endpoint on this machine (got ${u.protocol}//…)`);
  }
  if (!LOOPBACK.has(u.hostname)) {
    throw new Error(`mandu: --browser-cdp must name this machine (127.0.0.1, localhost or [::1]), not ${u.hostname}: a Chrome elsewhere is reachable by the agent around the relay`);
  }
  if (u.port === "") throw new Error("mandu: --browser-cdp needs the port Chrome was started with (--remote-debugging-port), such as http://127.0.0.1:9222");
  if (u.username !== "" || u.password !== "") throw new Error("mandu: --browser-cdp takes no user name or password");
  return `http://${u.hostname}:${u.port}`;
}

/** The port of a parsed upstream. */
export function upstreamPort(upstream: string): number {
  return Number(new URL(upstream).port);
}

/** The ports the connect guards admit to every host whatever the launch
 *  (landlock-net WORKFLOW_PORTS, net-guard's fallback and DNS). */
const ALWAYS_ADMITTED = [22, 53, 443];

/**
 * Why the launch refuses this Chrome port, or null: a port the guards admit
 * to every host (443, 22, 53) or one of Mandu's own services would let the
 * agent reach Chrome around the relay. Pure.
 */
export function chromePortRefusal(port: number, servicePorts: readonly number[]): string | null {
  if (ALWAYS_ADMITTED.includes(port) || servicePorts.includes(port)) {
    return `mandu: Chrome's debugging port ${port} is one the agent may reach directly, around the relay; start Chrome with another --remote-debugging-port (9222 is the usual one)`;
  }
  return null;
}

/** The agent's variables for a live relay. */
export function browserCdpAgentEnv(relayUrl: string): Record<string, string> {
  return Object.fromEntries(BROWSER_CDP_AGENT_VARS.map((k) => [k, relayUrl]));
}

/** The launch line when neither connect guard runs: the relay masks what it
 *  carries, but nothing stops the agent dialing Chrome's own port. */
export function unguardedNote(upstream: string): string {
  return `WARNING: mandu: no connect guard runs this session, so the agent can reach Chrome's own port (${upstream}) around the DevTools relay; ` +
    "what it reads there is not masked. Enable landlock-net or the net guard (mandu doctor says why they are off).";
}
