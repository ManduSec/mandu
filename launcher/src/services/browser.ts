/**
 * services/browser — start the Chrome of a `--browser` launch
 * (docs/design/agents/devtools-relay.md §6.4; browser-launch.ts).
 *
 * Chrome runs as its own process group, started here, outside the agent's
 * tree like the relay: the agent's guards never wrap it, and the agent
 * reaches it only through the relay the manager puts in front of it. Its
 * traffic goes through the session's egress proxy, trusting the session CA
 * by its pin; its profile is Mandu's. Ready once its DevToolsActivePort
 * names a port that answers; the endpoint becomes the plan's `browserCdp`.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code; the start and
 * readiness steps mirror services/cdp-relay.ts.
 */
import { accessSync, constants, existsSync, lstatSync, mkdirSync, readFileSync, readlinkSync, rmSync } from "node:fs";
import { homedir, hostname } from "node:os";
import { delimiter, join } from "node:path";
import type { LaunchPlan } from "../types.js";
import { manduPath } from "../generated/mandu-paths.js";
import {
  BROWSER_NO_SANDBOX_ENV, browserEgressNote, chromeArgs, findChrome, headlessFor, parseDevToolsActivePort,
  profileFiles, profileHeldMessage, profileHolder, spkiPin,
} from "../browser-launch.js";
import { readinessBudget, type ServiceDeps } from "./primitives.js";

export interface BrowserResult {
  /** Chrome's debugging endpoint, `http://127.0.0.1:<port>`. */
  endpoint: string;
  binary: string;
  profile: string;
  headless: boolean;
  /** Said at launch when Chrome's traffic is not all gated (browser-launch.ts). */
  note: string | null;
  stop: () => void;
}

/** The environment's knobs, for tests. */
export interface BrowserOptions {
  env?: Readonly<Record<string, string | undefined>>;
  home?: string;
  platform?: NodeJS.Platform;
  /** The profile; default the Mandu home's `state/browser`. */
  profile?: string;
}

function onPath(name: string, env: Readonly<Record<string, string | undefined>>): string | null {
  for (const dir of (env["PATH"] ?? "").split(delimiter)) {
    if (dir === "") continue;
    const p = join(dir, name);
    try { accessSync(p, constants.X_OK); return p; } catch { /* next */ }
  }
  return null;
}

function alive(pid: number): boolean {
  try { process.kill(pid, 0); return true; } catch (e) { return (e as NodeJS.ErrnoException).code === "EPERM"; }
}

/** Start Chrome for the plan, or throw (the manager decides whether that
 *  refuses the launch). */
export async function startBrowser(
  plan: Pick<LaunchPlan, "netProxy" | "mitmCaCert">,
  scopeRunDir: string,
  deps: ServiceDeps,
  o: BrowserOptions = {},
): Promise<BrowserResult> {
  const env = o.env ?? process.env;
  const platform = o.platform ?? process.platform;
  const binary = findChrome(env, platform, (n) => onPath(n, env), existsSync);
  if (binary === null) {
    throw new Error("mandu: --browser found no Chrome (google-chrome, chromium); install one, or name it with MANDU_BROWSER_BIN");
  }
  const profile = o.profile ?? manduPath("browser-profile", env, o.home ?? homedir());
  mkdirSync(profile, { recursive: true, mode: 0o700 });
  const st = lstatSync(profile);
  if (!st.isDirectory() || (typeof process.getuid === "function" && st.uid !== process.getuid())) {
    throw new Error(`mandu: the browser profile ${profile} is not a directory of this user's; refusing to start Chrome on it`);
  }
  const files = profileFiles(profile);
  let lockTarget: string | null = null;
  try { lockTarget = readlinkSync(files.lock); } catch { /* no lock */ }
  const holder = profileHolder(lockTarget, hostname(), alive);
  if (holder !== null) throw new Error(profileHeldMessage(profile, holder));
  // The last run's port file would name a port no Chrome holds now.
  rmSync(files.activePort, { force: true });

  let caPin: string | undefined;
  if (plan.mitmCaCert) caPin = spkiPin(readFileSync(plan.mitmCaCert, "utf8"));
  const headless = headlessFor(env, platform);
  const args = chromeArgs({
    profile,
    ...(plan.netProxy ? { proxy: plan.netProxy } : {}),
    ...(caPin ? { caPin } : {}),
    headless,
    noSandbox: env[BROWSER_NO_SANDBOX_ENV] === "1",
  });
  const log = join(scopeRunDir, "browser.log");
  const handle = deps.startDetachedCmd(binary, args, { cwd: profile, env: { ...env } }, log);
  const budget = readinessBudget(handle);
  let port: number | null = null;
  const written = await deps.waitFor(() => {
    try { port = parseDevToolsActivePort(readFileSync(files.activePort, "utf8")); } catch { port = null; }
    return port !== null;
  }, budget.opts(100));
  if (!written || port === null) {
    handle.stop();
    throw new Error(`mandu: Chrome (${binary}) did not open its debugging port (${budget.note()}; its log: ${log})`);
  }
  const host = "127.0.0.1";
  const p: number = port;
  const up = await deps.waitFor(() => deps.probePort(host, p), budget.opts(100));
  if (!up) {
    handle.stop();
    throw new Error(`mandu: Chrome's debugging port ${host}:${p} did not answer (${budget.note()}; its log: ${log})`);
  }
  return {
    endpoint: `http://${host}:${p}`,
    binary,
    profile,
    headless,
    note: browserEgressNote(plan.netProxy !== undefined, caPin !== undefined),
    stop: handle.stop,
  };
}
