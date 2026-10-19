/**
 * own-paths — the launcher's helpers over the path table
 * (src/generated/mandu-paths.ts, from scripts/paths/mandu-paths.mjs;
 * on-disk-layout.md §5). Every launcher site that names one of Mandu's own
 * locations asks the table, through `manduPath` or these helpers; none spells
 * the path by hand.
 *
 * Pure: env and home come from the call site; nothing reads process.env or
 * the filesystem.
 *
 * Mandu-new (no reference origin).
 */
import { userInfo } from "node:os";
import { posix } from "node:path";
import { MANDU_PATHS, manduPath, type ManduPathEnv, type ManduPathName } from "./generated/mandu-paths.js";

/** An entry at its default location: its own per-path override ignored.
 *  Only the locations outside the Mandu home keep an override
 *  (`install-prefix`: MANDU_PREFIX; `runtime-dir`; `bin-dir`). */
export function defaultPath(name: ManduPathName, env: ManduPathEnv, home: string): string {
  const own = MANDU_PATHS[name].env;
  return manduPath(name, own === null ? env : { ...env, [own]: undefined }, home);
}

/** An entry at its default location and, when its per-path override is set,
 *  at the override too (default first). A deny list covers both: exporting
 *  an override never un-hides the default location. */
export function pathAndDefault(name: ManduPathName, env: ManduPathEnv, home: string): string[] {
  const fallback = defaultPath(name, env, home);
  const current = manduPath(name, env, home);
  return current === fallback ? [fallback] : [fallback, current];
}

/** The axes a launch runs at, as far as the home's carve-outs care. */
export interface CarveOutAxes {
  confidentiality: boolean;
  integrity: boolean;
}

/**
 * The directories under the Mandu home the agent may read and write
 * (on-disk-layout.md §4, the carve-outs from the one deny rule), for a
 * launch's axes and the AgentView worktrees it runs in:
 *
 *   `state/workspaces/<id>/agentview`  integrity on (`injection`, `full`)
 *   `state/workspaces/<id>/repo.git`   integrity and confidentiality on (`full`)
 *
 * `home` is the Mandu home, `agentViews` the candidates (the launch's cwd,
 * its view map's AgentView sides), both already resolved to real paths by
 * the caller. A candidate counts only when it is EXACTLY
 * `<home>/state/workspaces/<one name>/agentview`: anything else (the home
 * itself, `state/`, a path outside the home, a `..` spelling) carves
 * nothing, so a stray or hostile value can never open more of the home.
 * Sorted, without duplicates. Pure.
 */
export function homeCarveOuts(axes: CarveOutAxes, home: string, agentViews: readonly (string | undefined)[]): string[] {
  if (!axes.integrity) return [];
  const workspaces = manduPath("workspaces", { MANDU_HOME: home }, "/");
  const out = new Set<string>();
  for (const candidate of agentViews) {
    if (typeof candidate !== "string" || !candidate.startsWith("/")) continue;
    const p = candidate.length > 1 ? candidate.replace(/\/+$/, "") : candidate;
    if (posix.normalize(p) !== p) continue;
    if (posix.basename(p) !== "agentview") continue;
    const ws = posix.dirname(p);
    if (posix.dirname(ws) !== workspaces) continue;
    const id = posix.basename(ws);
    if (id === "" || id === "." || id === "..") continue;
    out.add(p);
    if (axes.confidentiality) out.add(posix.join(ws, "repo.git"));
  }
  return [...out].sort();
}

/** The agent's working directories that sit inside the Mandu home but in no
 *  carve-out (resolved paths; `homeCarveOuts`). A launch from inside the
 *  home would put the agent where it may neither read nor write, so the
 *  launch refuses (fail-closed; on-disk-layout.md §4). Pure. */
export function cwdsInsideHome(home: string, carveOuts: readonly string[], cwds: readonly (string | undefined)[]): string[] {
  const under = (p: string, dir: string): boolean => p === dir || p.startsWith(dir.endsWith("/") ? dir : `${dir}/`);
  const out = new Set<string>();
  for (const c of cwds) {
    if (typeof c !== "string" || c === "") continue;
    if (under(c, home) && !carveOuts.some((x) => under(c, x))) out.add(c);
  }
  return [...out];
}

/** The invoking account's home from the passwd database, not `$HOME`; null
 *  when it cannot be read. A launch with a scratch HOME (an eval leg, a test)
 *  still keeps the account's own `~/.mandu` from the agent (on-disk-layout.md
 *  §4). */
export function accountHome(): string | null {
  try { return userInfo().homedir || null; } catch { return null; }
}
