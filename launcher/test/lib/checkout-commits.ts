/** Expected provenance read directly from a checkout's public snapshot trailer.
 * The public HEAD is not the internal source commit named by that trailer. */
import { spawnSync } from "node:child_process";

export function checkoutCommits(repo: string): { source: string | null; public: string | null } {
  const git = (...args: string[]): string => {
    const r = spawnSync("git", ["-C", repo, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
    return r.status === 0 ? r.stdout.trim() : "";
  };
  const head = git("rev-parse", "HEAD") || null;
  const source = git("log", "--first-parent", "-n", "200", "--format=%(trailers:key=Mandu-Snapshot,valueonly)")
    .split(/\s+/).find((s) => /^[0-9a-f]{40}$/.test(s)) ?? null;
  return { source: source ?? head, public: source === null ? null : head };
}
