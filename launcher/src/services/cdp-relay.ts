/**
 * services/cdp-relay — start the DevTools relay for a `--browser-cdp` launch
 * (docs/design/agents/devtools-relay.md §6; browser-cdp.ts).
 *
 * The relay (interceptors/cdp-relay) runs as its own process, started here,
 * outside the agent's tree: the agent's guards never wrap it, so it can dial
 * Chrome's port, which the agent cannot. It binds a kernel-assigned loopback
 * port and publishes it in a port file; the launch adopts it, and the agent
 * gets `http://127.0.0.1:<port>` (browser-cdp.ts `browserCdpAgentEnv`).
 *
 * It talks to the session's arbiter on both planes: the data socket for the
 * prompt filter (what Chrome sends the agent) and the human socket for the
 * release decision (a placeholder the agent types). Without a human socket
 * it still starts and refuses every placeholder typed (fail-closed).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code; the start and
 * readiness steps mirror services/net-proxy.ts.
 */
import { readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import type { LaunchPlan } from "../types.js";
import type { Layout } from "./layout.js";
import { readinessBudget, type ServiceDeps } from "./primitives.js";
import { humanSockEnv } from "../human-plane.js";

export interface CdpRelayResult {
  host: string;
  port: number;
  url: string;
  stop: () => void;
}

/** Start the relay on `plan.browserCdp`, or throw (the manager decides
 *  whether that refuses the launch). */
export async function startCdpRelay(
  plan: Pick<LaunchPlan, "browserCdp" | "arbiterSock" | "arbiterHumanSock" | "scopeId">,
  layout: Layout,
  scopeRunDir: string,
  deps: ServiceDeps,
): Promise<CdpRelayResult> {
  const upstream = plan.browserCdp;
  if (!upstream) throw new Error("mandu: no --browser-cdp endpoint on the plan");
  const host = "127.0.0.1";
  const portFile = join(scopeRunDir, "cdp-relay.port");
  rmSync(portFile, { force: true });
  const env: Record<string, string | undefined> = {
    ...process.env,
    MANDU_ARBITER_SOCK: plan.arbiterSock,
    ...humanSockEnv(plan.arbiterHumanSock),
    MANDU_SESSION_KEY: plan.scopeId,
    // Set by the arguments below; cleared so an ambient value cannot point
    // the relay at another Chrome.
    MANDU_CDP_UPSTREAM: undefined,
  };
  const log = join(scopeRunDir, "cdp-relay.log");
  const spec = layout.daemon("cdp-relay", join("interceptors", "cdp-relay"));
  const args = [...spec.args, "--upstream", upstream, "--session", plan.scopeId, "--port", "0", "--port-file", portFile];
  const handle = deps.startDetachedCmd(spec.cmd, args, { cwd: spec.cwd, env: { ...env, ...spec.env } }, log);
  const budget = readinessBudget(handle);
  const fileUp = await deps.waitForFile(portFile, budget.opts(100));
  if (!fileUp) {
    handle.stop();
    throw new Error(`mandu: the DevTools relay did not come up (no port file at ${portFile}: ${budget.note()}; its log: ${log})`);
  }
  const raw = readFileSync(portFile, "utf8").trim();
  const port = Number(raw);
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    handle.stop();
    throw new Error(`mandu: the DevTools relay published an unusable port ('${raw}' in ${portFile})`);
  }
  const up = await deps.waitFor(() => deps.probePort(host, port), budget.opts(100));
  if (!up) {
    handle.stop();
    throw new Error(`mandu: the DevTools relay did not answer on ${host}:${port} (${budget.note()}; its log: ${log})`);
  }
  return { host, port, url: `http://${host}:${port}`, stop: handle.stop };
}
