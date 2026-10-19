/**
 * runtime-sweep — the last-resort stop for every daemon a test started under
 * its own runtime base (`MANDU_RUNTIME_DIR=<base>`), whatever state it is in.
 *
 * Why not the registries alone: a daemon is in `<base>/dashboards/` or
 * `<base>/instances/*` only once it has come up. One still starting when the
 * test's `finally` runs (the dev layout's `npm run serve` → sh → tsx → node
 * chain takes seconds on a loaded host) is in neither, comes up AFTER the
 * temp dir is wiped, and, being ownerless and lifeline-free by design,
 * serves forever: a 3-hour `mandu-arbiter` orphan of
 * instance-autostart.test.ts was found that way (2026-09-29). Every such
 * process carries the base in its environment from the moment it is spawned,
 * so a /proc scan finds it at any stage. The launcher spawns each daemon
 * detached (its own process group), so the whole group is signalled: the npm
 * wrapper, tsx and the daemon together.
 *
 * Linux only (/proc); elsewhere it finds nothing and the registry-based
 * cleanup the caller also runs is all there is. Never signals this process's
 * own group.
 */
import { readdirSync, readFileSync } from "node:fs";

/** The process group of `pid` (field 5 of /proc/<pid>/stat), or null. */
function pgidOf(pid: number | "self"): number | null {
  try {
    const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
    // comm (field 2) may hold spaces and parens: parse after its LAST ')'.
    const rest = stat.slice(stat.lastIndexOf(")") + 2).split(" ");
    const pgid = Number(rest[2]);
    return Number.isInteger(pgid) && pgid > 0 ? pgid : null;
  } catch {
    return null;
  }
}

/** Process groups of this user's processes whose env has MANDU_RUNTIME_DIR=`base`. */
export function runtimeProcessGroups(base: string): number[] {
  let entries: string[];
  try { entries = readdirSync("/proc"); } catch { return []; }
  const want = `MANDU_RUNTIME_DIR=${base}`;
  const own = pgidOf("self");
  const groups = new Set<number>();
  for (const name of entries) {
    if (!/^\d+$/.test(name)) continue;
    const pid = Number(name);
    if (pid === process.pid) continue;
    let env: string;
    try { env = readFileSync(`/proc/${pid}/environ`, "latin1"); } catch { continue; } // gone, or not ours
    if (!env.split("\0").includes(want)) continue;
    const pgid = pgidOf(pid);
    if (pgid !== null && pgid !== own && pgid !== 1) groups.add(pgid);
  }
  return [...groups];
}

function groupAlive(pgid: number): boolean {
  try { process.kill(-pgid, 0); return true; } catch { return false; }
}

/** SIGTERM every process group found under `base`, then SIGKILL what is left
 *  after `graceMs`; rescans (up to three passes) so a child spawned while the
 *  first groups were going down is caught too. Returns the groups signalled. */
export async function sweepRuntimeProcesses(base: string, graceMs = 5_000): Promise<number[]> {
  const all: number[] = [];
  for (let pass = 0; pass < 3; pass++) {
    const groups = runtimeProcessGroups(base);
    if (groups.length === 0) break;
    all.push(...groups);
    for (const g of groups) { try { process.kill(-g, "SIGTERM"); } catch { /* already gone */ } }
    const deadline = Date.now() + graceMs;
    while (groups.some(groupAlive) && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 100));
    }
    for (const g of groups.filter(groupAlive)) { try { process.kill(-g, "SIGKILL"); } catch { /* already gone */ } }
  }
  return all;
}
