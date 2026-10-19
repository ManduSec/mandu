/**
 * registry — the dashboard's runtime-registry entry (runtime-instances.md §10).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code; the id scheme
 * (`<utc>-<rev>-p<pid>`), the MANDU_OWNER_PID owner semantics, and the
 * boot-time dead-pid sweep MIRROR arbiter/ipc/instance.ts (instanceId /
 * resolveOwnerPid / sweepDeadInstances), duplicated narrowly so this package
 * stays standalone. The GC consumer is launcher/src/reap.ts.
 *
 * Why dashboards register (2026-07-19 incident): FIVE dashboard servers were
 * found running side by side — one current, four stale on forgotten ports —
 * because "restart everything" starts new dashboards without any record of the
 * old ones. Arbiters solved exactly this with universal registration; the
 * dashboard was the remaining invisible daemon. An entry here makes every
 * dashboard enumerable (`mandu status`: id encodes start time + git rev,
 * manifest carries the port) and collectable (`mandu reap`: dead entries
 * removed, live orphans SIGTERMed after a /proc title check).
 *
 * Layout: `<runtimeBase>/dashboards/<id>.json` — FLAT manifest files, not
 * per-instance dirs: a dashboard owns no socket/promotion machinery, so there
 * is nothing else to put in a dir (and nothing here may ever be confused with
 * the arbiter's `instances/` promotion registry).
 */

import { lstatSync, mkdirSync, readdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";

/** Subdir of the runtime base holding one `<id>.json` per live dashboard. */
export const DASHBOARDS_DIR = "dashboards";

/** Everything `mandu status`/`reap` and a sibling dashboard need to know. */
export interface DashboardManifest {
  pid: number;
  /** The BOUND port (kernel-assigned under DASHBOARD_PORT=0). */
  port: number;
  host: string;
  /** ISO start time of this server process. */
  startedAt: string;
  /** Short git rev at boot ("nogit" when unavailable). */
  gitRev: string;
  /** Whose death makes this daemon garbage (reap's orphan rule); null = no
   *  owner — stopped only explicitly. Same semantics as the arbiter manifest. */
  ownerPid: number | null;
  repoRoot: string;
  /** The URL prefix it serves under (DASHBOARD_BASE_PATH; "" = none), so a
   *  reader builds a URL that works (`mandu dashboard`, the launch line).
   *  Absent in entries written before 2026-09-26. */
  basePath?: string;
  /** Its sign-in socket (sign-in.ts): `<runtime>/human/dashboard-<pid>.sock`,
   *  where the launcher asks for a one-time sign-in link. The path is not a
   *  secret; the human-plane walls are the boundary. Absent before
   *  2026-10-05, or when the socket could not be served. */
  signInSock?: string;
}

/** The owner pid for this daemon: $MANDU_OWNER_PID (a spawner's explicit
 *  claim), "0"/"none" for ownerless, else the parent pid — the arbiter's exact
 *  rule (arbiter/ipc/instance.ts resolveOwnerPid). The self-restart successor
 *  inherits an EXPLICIT owner through its env; a defaulted one re-resolves to
 *  the successor's own parent, which is also what the arbiter does. */
export function resolveOwnerPid(
  env: NodeJS.ProcessEnv = process.env,
  ppid: number = process.ppid,
): number | null {
  const raw = env.MANDU_OWNER_PID;
  if (raw === undefined || raw === "") return ppid;
  if (raw === "0" || raw === "none") return null;
  const n = Number(raw);
  return Number.isInteger(n) && n > 0 ? n : ppid;
}

/** `<utc yyyymmdd-hhmm>-<gitrev>-p<pid>` — sortable by start time, code rev
 *  readable at a glance, pid says what to signal (the arbiter's id scheme). */
export function dashboardId(now: Date, gitRev: string, pid: number): string {
  const p = (n: number, w = 2): string => String(n).padStart(w, "0");
  const t =
    `${now.getUTCFullYear()}${p(now.getUTCMonth() + 1)}${p(now.getUTCDate())}` +
    `-${p(now.getUTCHours())}${p(now.getUTCMinutes())}`;
  const rev = gitRev.replace(/[^a-zA-Z0-9._-]/g, "").slice(0, 16) || "nogit";
  return `${t}-${rev}-p${pid}`;
}

/** Is `p` a real directory (lstat: a symlink is NOT one)? */
function isRealDir(p: string): boolean {
  try {
    const st = lstatSync(p);
    return st.isDirectory() && !st.isSymbolicLink();
  } catch {
    return false;
  }
}

/** Write this dashboard's registry entry (atomic tmp+rename — the `.json`
 *  suffix appears only on complete files, so readers never parse a torn one).
 *  Returns the id + path for the exit-time unregister. Throws on I/O failure —
 *  the caller treats registration as best-effort and keeps serving.
 *
 *  Never through something planted (runtime-instances.md §2, "planted
 *  paths", 2026-09-30): whoever can write the runtime base could make
 *  `dashboards/` a link, or put a link at the predictable temp name, and this
 *  process runs outside the agent's confinement. So the registry must be a
 *  real directory (else this throws), and the temp file is unlinked (unlink
 *  never follows a link) and then created exclusively (`wx`: O_CREAT|O_EXCL,
 *  which refuses any entry at the name, a link included). */
export function registerDashboard(
  base: string,
  manifest: DashboardManifest,
  now: Date = new Date(),
): { id: string; path: string } {
  const dir = join(base, DASHBOARDS_DIR);
  mkdirSync(dir, { recursive: true });
  if (!isRealDir(dir)) {
    throw new Error(`the dashboard registry ${dir} is not a real directory (a link or a file); not registering (remove it)`);
  }
  const id = dashboardId(now, manifest.gitRev, manifest.pid);
  const path = join(dir, `${id}.json`);
  const tmp = `${path}.tmp`;
  try { unlinkSync(tmp); } catch { /* none left over */ }
  try {
    writeFileSync(tmp, JSON.stringify(manifest, null, 2) + "\n", { flag: "wx" });
    renameSync(tmp, path);
  } catch (e) {
    try { unlinkSync(tmp); } catch { /* never created, or already renamed */ }
    throw e;
  }
  return { id, path };
}

/** Remove this dashboard's own entry (graceful exit / self-restart). Best-effort:
 *  a SIGKILLed dashboard leaves its entry for the boot sweep / reap instead. */
export function unregisterDashboard(path: string): void {
  try {
    unlinkSync(path);
  } catch {
    /* already gone / never registered */
  }
}

/** Boot-time GC (mirror of the arbiter's sweepDeadInstances): remove entries
 *  whose pid is DEAD. Never signals anything — live entries, whatever their
 *  owner state, are reap's business, not a sibling's. Returns removed ids.
 *
 *  Never through a linked `dashboards/` (2026-09-30): swapped for a link to
 *  someone's folder, every `*.json` there that names no live pid (a
 *  `package.json`, a `tsconfig.json`) would read as a dead entry and be
 *  deleted, at every dashboard start, by a process outside the agent's
 *  confinement. A registry that is not a real directory is not swept. */
export function sweepDeadDashboards(
  base: string,
  pidAlive: (pid: number) => boolean = defaultPidAlive,
): string[] {
  const dir = join(base, DASHBOARDS_DIR);
  if (!isRealDir(dir)) return []; // no registry yet, or not one to trust
  let names: string[] = [];
  try {
    names = readdirSync(dir);
  } catch {
    return []; // no registry yet
  }
  const removed: string[] = [];
  for (const name of names) {
    if (!name.endsWith(".json")) continue; // .tmp mid-write files are not entries
    const path = join(dir, name);
    let pid: number | null = null;
    try {
      const m = JSON.parse(readFileSync(path, "utf8")) as Partial<DashboardManifest>;
      if (typeof m.pid === "number") pid = m.pid;
    } catch {
      /* corrupt → dead */
    }
    if (pid !== null && pidAlive(pid)) continue;
    try {
      unlinkSync(path);
      removed.push(name.replace(/\.json$/, ""));
    } catch {
      /* raced another sweeper — fine */
    }
  }
  return removed;
}

function defaultPidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === "EPERM";
  }
}
