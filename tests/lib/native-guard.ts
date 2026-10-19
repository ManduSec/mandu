/**
 * Which `mandu-net-guard` a kernel test runs: the newest build that is NOT
 * stale. A stale build tests an older guard: it fakes a security failure
 * (2026-09-29: a release bin built before the xattr trap "let" a setxattr
 * on policy.yaml through, while the kernel tier was relinking the debug bin
 * mid-run) or, worse, passes on code that no longer exists.
 */
import { chmodSync, copyFileSync, existsSync, realpathSync, statSync } from "node:fs";
import { join } from "node:path";
import { nativeBinStaleness } from "../../launcher/src/services/native-bins.js";

export interface GuardPick {
  /** The bin to run, or undefined when none is built. */
  path: string | undefined;
  /** Why no fresh bin exists (every build is older than its sources), for a
   *  test to fail on; null when `path` is fresh or nothing is built. */
  stale: string | null;
}

/** Newest first among the fresh `release`/`debug` builds under `target`;
 *  when every build is stale, the newest one with the reason. */
export function pickGuard(
  target: string,
  staleness: (bin: string) => { newestSource: string } | null = nativeBinStaleness,
): GuardPick {
  const built = ["release", "debug"]
    .map((p) => join(target, p, "mandu-net-guard"))
    .filter(existsSync)
    .sort((a, b) => statSync(b).mtimeMs - statSync(a).mtimeMs);
  if (built.length === 0) return { path: undefined, stale: null };
  const fresh = built.find((b) => staleness(b) === null);
  if (fresh) return { path: fresh, stale: null };
  const s = staleness(built[0]!)!;
  return {
    path: built[0],
    stale: `every mandu-net-guard build is older than its sources (${built.join(", ")}; ${s.newestSource} changed since): run scripts/build-native.sh`,
  };
}

/**
 * Plan 13 D7: a copy of this node binary in `dir`, for a test's "agent" to
 * run under the guard as the launch's `agentExe`. The guard knows the agent
 * by its executable (the call-root recorder binds a tool call to an exec by
 * the agent's own child), and other node processes of the test (an MCP
 * server) must not share it: the guard also refuses the agent's own raw
 * opens by that executable. Returns the copy's real path.
 */
export function agentNodeCopy(dir: string): string {
  const dst = join(dir, "agent-node");
  copyFileSync(realpathSync(process.execPath), dst);
  chmodSync(dst, 0o755);
  return realpathSync(dst);
}
