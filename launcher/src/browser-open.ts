/**
 * browser-open — open a URL in the person's default browser, for `mandu scan
 * --open` (confidentiality-plan-17-past-sessions-scan.md §3 item 12).
 *
 * The decision ({@link browserCommand}) is pure: which program, with which
 * arguments, or none at all. The order:
 *
 *   1. `BROWSER` (the common convention, xdg-utils and Python's webbrowser):
 *      the first of its `:`-separated commands, split on spaces, `%s`
 *      replaced by the URL (`%%` a literal `%`), or the URL appended when no
 *      argument holds `%s`. The person chose it, so it is honoured with no
 *      display too (a text browser over SSH).
 *   2. macOS: `open <url>`, unless the session is over SSH: `open` would show
 *      the page on the Mac's own screen, not to the person at the far end.
 *   3. WSL (`WSL_DISTRO_NAME`, or the kernel's own signals, wsl.ts
 *      `hostIsWsl`): `wslview <url>` when it is on the PATH, else Windows'
 *      `cmd.exe /c start "" <url>` (the empty title first, so `start` never
 *      takes the URL for a window title; cmd's metacharacters escaped with
 *      `^`, and a URL holding a space, a quote, `%` or `!` is not handed to
 *      cmd at all).
 *   4. Linux and the other Unixes: `xdg-open <url>` when there is a display
 *      (`DISPLAY` or `WAYLAND_DISPLAY`, an X forwarded over SSH included).
 *   5. Otherwise none: no browser here (an SSH session, a headless box). The
 *      caller prints the URL instead, and over SSH (`SSH_CONNECTION`) how to
 *      forward the port.
 *
 * Every program gets the URL as its own argument, never through a shell, so
 * nothing in it is interpreted except by cmd.exe (escaped above). The caller
 * hands it the plain URL and never a credential (scan-command.ts): an
 * argument sits in `ps` for every user to read.
 *
 * Spawning ({@link openUrl}) is detached with its output ignored: it never
 * waits for the browser, only for the start itself (or its failure).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 */
import { spawn } from "node:child_process";
import { accessSync, constants, existsSync, readFileSync } from "node:fs";
import { delimiter, join } from "node:path";
import { hostIsWsl } from "./wsl.js";

type Env = Record<string, string | undefined>;

/** What to run for the URL, or that there is no browser to run. */
export type BrowserPlan =
  | { kind: "spawn"; cmd: string; args: string[] }
  | { kind: "none"; ssh: boolean };

/** What {@link browserCommand} cannot read from the environment alone. */
export interface BrowserFacts {
  /** Is this WSL? Absent: only `WSL_DISTRO_NAME` says so. */
  wsl?: boolean;
  /** Is `cmd` an executable on the PATH? Absent: nothing is. */
  onPath?: (cmd: string) => boolean;
}

/** Is this session over SSH? */
export function overSsh(env: Env): boolean {
  return (env["SSH_CONNECTION"] ?? "") !== "" || (env["SSH_CLIENT"] ?? "") !== "";
}

/** `BROWSER`'s first command for `url`, as argv; null when it names none. */
function fromBrowserEnv(value: string, url: string): { cmd: string; args: string[] } | null {
  const first = value.split(":").map((s) => s.trim()).find((s) => s !== "");
  if (first === undefined) return null;
  const words = first.split(/\s+/).filter((w) => w !== "");
  const cmd = words.shift();
  if (cmd === undefined) return null;
  let substituted = false;
  const args = words.map((w) => w.replace(/%(%|s)/g, (_m, c: string) => {
    if (c === "%") return "%";
    substituted = true;
    return url;
  }));
  if (!substituted) args.push(url);
  return { cmd, args };
}

/** `start`'s arguments for `url` under `cmd.exe /c`: the empty title, then
 *  the URL with cmd's metacharacters escaped. Null for a URL cmd could
 *  still read as more than a URL (a space, a quote, `%`, `!`). Pure. */
export function cmdStartArgs(url: string): string[] | null {
  if (/[\s"%!]/.test(url)) return null;
  return ["/c", "start", "", url.replace(/[\^&|<>()]/g, (c) => `^${c}`)];
}

/**
 * Which program opens `url` in this person's browser, or none (the order
 * in the header). Pure: the platform, the environment and the facts come
 * from the caller.
 */
export function browserCommand(platform: string, env: Env, url: string, facts: BrowserFacts = {}): BrowserPlan {
  const ssh = overSsh(env);
  const browser = (env["BROWSER"] ?? "").trim();
  if (browser !== "") {
    const plan = fromBrowserEnv(browser, url);
    if (plan !== null) return { kind: "spawn", ...plan };
  }
  if (platform === "darwin") return ssh ? { kind: "none", ssh } : { kind: "spawn", cmd: "open", args: [url] };
  const cmdStart = (): BrowserPlan => {
    const args = cmdStartArgs(url);
    return args === null ? { kind: "none", ssh } : { kind: "spawn", cmd: "cmd.exe", args };
  };
  if (platform === "win32") return cmdStart();
  const wsl = facts.wsl ?? ((env["WSL_DISTRO_NAME"] ?? "") !== "");
  if (wsl) {
    if (facts.onPath?.("wslview") === true) return { kind: "spawn", cmd: "wslview", args: [url] };
    return cmdStart();
  }
  if ((env["DISPLAY"] ?? "") !== "" || (env["WAYLAND_DISPLAY"] ?? "") !== "") {
    return { kind: "spawn", cmd: "xdg-open", args: [url] };
  }
  return { kind: "none", ssh };
}

/** Is `cmd` an executable file in one of PATH's directories? */
export function onPath(cmd: string, env: Env): boolean {
  for (const dir of (env["PATH"] ?? "").split(delimiter)) {
    if (dir === "") continue;
    try { accessSync(join(dir, cmd), constants.X_OK); return true; } catch { /* not here */ }
  }
  return false;
}

/** The facts of this machine (WSL by its kernel's signals, the PATH). */
export function realBrowserFacts(env: Env): BrowserFacts {
  const read = (p: string): string | null => { try { return readFileSync(p, "utf8"); } catch { return null; } };
  return {
    wsl: (env["WSL_DISTRO_NAME"] ?? "") !== "" || hostIsWsl({ readFile: read, fileExists: existsSync, env }),
    onPath: (cmd) => onPath(cmd, env),
  };
}

/** What became of an attempt to open the URL. */
export type OpenOutcome =
  | { kind: "opened"; cmd: string }
  | { kind: "no-browser"; ssh: boolean }
  | { kind: "failed"; cmd: string; why: string };

/**
 * Open `url` in the default browser: {@link browserCommand}, then the
 * program started detached, its output ignored. Waits only for the start
 * (or its failure, such as a program not installed), never for the
 * browser.
 */
export function openUrl(url: string, env: Env, platform: string = process.platform, facts: BrowserFacts = realBrowserFacts(env)): Promise<OpenOutcome> {
  const plan = browserCommand(platform, env, url, facts);
  if (plan.kind === "none") return Promise.resolve({ kind: "no-browser", ssh: plan.ssh });
  return new Promise((resolve) => {
    let child: ReturnType<typeof spawn>;
    try {
      child = spawn(plan.cmd, plan.args, { detached: true, stdio: "ignore", env: env as NodeJS.ProcessEnv });
    } catch (e) {
      resolve({ kind: "failed", cmd: plan.cmd, why: (e as Error).message });
      return;
    }
    child.once("spawn", () => { child.unref(); resolve({ kind: "opened", cmd: plan.cmd }); });
    child.once("error", (e) => { resolve({ kind: "failed", cmd: plan.cmd, why: e.message }); });
  });
}
