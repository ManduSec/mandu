/**
 * browser-launch — a Chrome that Mandu starts for the agent
 * (docs/design/agents/devtools-relay.md §6.4).
 *
 * `mandu --browser` (or MANDU_BROWSER=1) starts Chrome itself, instead of the
 * person starting one and naming it with `--browser-cdp`. The relay is then
 * put in front of it as for `--browser-cdp` (browser-cdp.ts). What starting
 * it adds:
 *
 *   - Chrome's own traffic goes through the session's egress proxy
 *     (`--proxy-server`): a script the agent runs in a page, or a form it
 *     submits, that sends a registered secret's real value to a host the
 *     secret is not bound to is refused there (the verbatim tripwire), where
 *     the person's own Chrome would send it. WebRTC is kept to proxied
 *     connections (`--force-webrtc-ip-handling-policy`), so no UDP leaves
 *     around the proxy. Loopback is not proxied (Chrome's default bypass;
 *     the proxy refuses this machine anyway).
 *   - Chrome trusts the session CA by its key pin
 *     (`--ignore-certificate-errors-spki-list`, honoured only with its own
 *     `--user-data-dir`), so the proxy can read HTTPS bodies without the CA
 *     being installed anywhere. The proxy sends the CA with each leaf, which
 *     the pin needs (net-proxy mitm.ts).
 *   - Its profile is Mandu's (`state/browser` in the Mandu home, which the
 *     agent can neither read nor write): the logins the person makes there
 *     stay for the next session, and the agent never reads the cookie store
 *     from the disk. One session's Chrome at a time: a profile a live
 *     Chrome holds refuses the launch (`profileHolder`).
 *   - Its debugging port is kernel-assigned and published in the profile's
 *     `DevToolsActivePort`; the connect guards admit only the relay's.
 *
 * Pure: the environment, the platform and the filesystem answers come from
 * the caller (services/browser.ts). Mandu-new (no reference origin).
 */
import { createHash, X509Certificate } from "node:crypto";
import { posix } from "node:path";

/** The launcher's own variables (parse.ts, services/browser.ts). */
export const BROWSER_ENV = "MANDU_BROWSER";
export const BROWSER_BIN_ENV = "MANDU_BROWSER_BIN";
export const BROWSER_HEADLESS_ENV = "MANDU_BROWSER_HEADLESS";
/** For a Chrome whose sandbox cannot start (a test host's Playwright
 *  headless shell under a userns restriction); never the default. */
export const BROWSER_NO_SANDBOX_ENV = "MANDU_BROWSER_NO_SANDBOX";

/** The file Chrome writes its debugging port into, in its profile. */
export const DEVTOOLS_ACTIVE_PORT = "DevToolsActivePort";
/** The link Chrome holds its profile with: `<host>-<pid>`. */
export const SINGLETON_LOCK = "SingletonLock";

const truthy = (v: string | undefined): boolean => v !== undefined && v !== "" && v !== "0";

/** The Chromes looked for, in order, when MANDU_BROWSER_BIN names none:
 *  names on PATH, then the platform's install locations. */
export function chromeCandidates(platform: NodeJS.Platform): { onPath: string[]; paths: string[] } {
  if (platform === "darwin") {
    return {
      onPath: ["google-chrome", "chromium"],
      paths: [
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
      ],
    };
  }
  return {
    onPath: ["google-chrome-stable", "google-chrome", "chromium", "chromium-browser"],
    paths: ["/opt/google/chrome/chrome", "/snap/bin/chromium"],
  };
}

/**
 * The Chrome to start, or null. MANDU_BROWSER_BIN wins (it must exist);
 * then the candidates. `which` resolves a name on PATH, `exists` a path.
 */
export function findChrome(
  env: Readonly<Record<string, string | undefined>>,
  platform: NodeJS.Platform,
  which: (name: string) => string | null,
  exists: (path: string) => boolean,
): string | null {
  const named = env[BROWSER_BIN_ENV];
  if (named !== undefined && named !== "") return exists(named) ? named : null;
  const c = chromeCandidates(platform);
  for (const n of c.onPath) {
    const p = which(n);
    if (p !== null) return p;
  }
  return c.paths.find(exists) ?? null;
}

/** Headless when asked, or on Linux with no display to open a window on. */
export function headlessFor(env: Readonly<Record<string, string | undefined>>, platform: NodeJS.Platform): boolean {
  if (truthy(env[BROWSER_HEADLESS_ENV])) return true;
  if (platform !== "linux") return false;
  return !env["DISPLAY"] && !env["WAYLAND_DISPLAY"];
}

/** The pin Chrome takes for a CA: base64 of the SHA-256 of its public key
 *  (SubjectPublicKeyInfo, DER). */
export function spkiPin(caPem: string): string {
  const der = new X509Certificate(caPem).publicKey.export({ type: "spki", format: "der" });
  return createHash("sha256").update(der).digest("base64");
}

export interface ChromeArgsInput {
  profile: string;
  /** The egress proxy; absent when none runs (the launch says so). */
  proxy?: { host: string; port: number };
  /** The session CA's pin; absent when the proxy reads no HTTPS. */
  caPin?: string;
  headless: boolean;
  noSandbox?: boolean;
}

/** Chrome's command line, without the binary. */
export function chromeArgs(i: ChromeArgsInput): string[] {
  return [
    // A kernel-assigned port, published in the profile's DevToolsActivePort.
    "--remote-debugging-port=0",
    `--user-data-dir=${i.profile}`,
    "--no-first-run",
    "--no-default-browser-check",
    ...(i.proxy ? [
      `--proxy-server=http://${i.proxy.host}:${i.proxy.port}`,
      // WebRTC only over the proxy: no UDP around it.
      "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
    ] : []),
    ...(i.caPin ? [`--ignore-certificate-errors-spki-list=${i.caPin}`] : []),
    ...(i.headless ? ["--headless"] : []),
    ...(i.noSandbox ? ["--no-sandbox"] : []),
    "about:blank",
  ];
}

/** The debugging port in a DevToolsActivePort file (its first line), or
 *  null while Chrome has not written a usable one. */
export function parseDevToolsActivePort(text: string): number | null {
  const first = text.split("\n")[0]?.trim() ?? "";
  if (!/^\d{1,5}$/.test(first)) return null;
  const port = Number(first);
  return port > 0 && port <= 65535 ? port : null;
}

/**
 * The pid of a live Chrome holding the profile, or null. Chrome's lock is a
 * link whose target is `<host>-<pid>`; a lock from another host, an
 * unreadable one, or one whose pid is gone holds nothing (Chrome takes such
 * a lock over itself).
 */
export function profileHolder(
  lockTarget: string | null,
  hostname: string,
  alive: (pid: number) => boolean,
): number | null {
  if (lockTarget === null) return null;
  const m = /^(.*)-(\d+)$/.exec(lockTarget);
  if (!m || m[1] !== hostname) return null;
  const pid = Number(m[2]);
  return pid > 0 && alive(pid) ? pid : null;
}

/** The refusal for a held profile. */
export function profileHeldMessage(profile: string, pid: number): string {
  return `mandu: the Mandu browser profile (${profile}) is in use by Chrome (pid ${pid}), from another session or left open; ` +
    "close that Chrome, or run this session's agent on your own Chrome with --browser-cdp";
}

/** What the launch says about Chrome's traffic when it cannot all go
 *  through the egress gate, or null. */
export function browserEgressNote(proxy: boolean, caPin: boolean): string | null {
  if (!proxy) {
    return "WARNING: mandu: no egress proxy runs this session, so the browser Mandu started sends straight to the network; " +
      "a page script the agent runs can send a secret it shows anywhere";
  }
  if (!caPin) {
    return "mandu: the egress proxy reads no HTTPS this session (no session CA), so the browser's HTTPS requests are " +
      "gated by destination only, not checked for a secret's value";
  }
  return null;
}

/** `--browser` and `--browser-cdp` name the same thing two ways. */
export const BROWSER_BOTH_MESSAGE =
  "mandu: --browser starts a Chrome for the agent and --browser-cdp names one you started; use one of them";

/** Is MANDU_BROWSER set? (parse.ts) */
export function browserFromEnv(env: Readonly<Record<string, string | undefined>>): boolean {
  return truthy(env[BROWSER_ENV]);
}

/** The profile's lock and port file. */
export function profileFiles(profile: string): { lock: string; activePort: string } {
  return { lock: posix.join(profile, SINGLETON_LOCK), activePort: posix.join(profile, DEVTOOLS_ACTIVE_PORT) };
}
