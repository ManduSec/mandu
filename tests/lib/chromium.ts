/**
 * chromium — find a headless Chromium for the DevTools relay's stack tests
 * (docs/design/agents/devtools-relay.md §7), or null so the test self-skips:
 * MANDU_TEST_CHROMIUM names the binary, else Playwright's headless shell in
 * ~/.cache/ms-playwright. Started with --no-sandbox: the pages are the
 * tests' own.
 */
import { spawn, type ChildProcess } from "node:child_process";
import { existsSync, readdirSync, rmSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export function chromiumBinary(): string | null {
  const env = process.env["MANDU_TEST_CHROMIUM"];
  if (env && existsSync(env)) return env;
  const root = join(homedir(), ".cache", "ms-playwright");
  if (!existsSync(root)) return null;
  for (const d of readdirSync(root).filter((n) => n.startsWith("chromium_headless_shell-")).sort().reverse()) {
    const bin = join(root, d, "chrome-headless-shell-linux64", "chrome-headless-shell");
    if (existsSync(bin)) return bin;
  }
  return null;
}

/** A page expression that is true once the test's own page is loaded: an
 *  http(s) document with a body, complete. `document.readyState` alone is
 *  "complete" on the blank document before the navigation commits, and a
 *  read of the body in between throws. */
export const READY = "location.protocol.startsWith('http') && !!document.body && document.readyState === 'complete'";

/** Kill it and wait for the exit, then remove its profile: Chromium keeps
 *  writing into the profile until it is gone, so a removal before the exit
 *  leaves files behind. */
export async function stopChromium(proc: ChildProcess | null, profile: string): Promise<void> {
  if (proc !== null && proc.exitCode === null && proc.signalCode === null) {
    const exited = new Promise<void>((r) => proc.once("exit", () => r()));
    // Its whole process group (startChromium spawns it as a group leader):
    // the renderer, GPU and crash-handler helpers write into the profile too.
    try { if (proc.pid !== undefined) process.kill(-proc.pid, "SIGKILL"); } catch { proc.kill("SIGKILL"); }
    await Promise.race([exited, new Promise((r) => setTimeout(r, 5_000))]);
  }
  rmSync(profile, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
}

/** Start it on a kernel-assigned debugging port; resolves with the process
 *  and the port once Chromium prints its DevTools line. */
export async function startChromium(bin: string, profile: string, url: string): Promise<{ proc: ChildProcess; port: number }> {
  const proc = spawn(bin, ["--headless", "--no-sandbox", "--remote-debugging-port=0", `--user-data-dir=${profile}`, url], { stdio: ["ignore", "ignore", "pipe"], detached: true });
  const port = await new Promise<number>((resolve, reject) => {
    let err = "";
    const t = setTimeout(() => reject(new Error(`Chromium did not start: ${err.slice(-400)}`)), 20_000);
    proc.stderr!.on("data", (d) => {
      err += d;
      const m = /DevTools listening on ws:\/\/127\.0\.0\.1:(\d+)/.exec(err);
      if (m) { clearTimeout(t); resolve(Number(m[1])); }
    });
  });
  return { proc, port };
}
