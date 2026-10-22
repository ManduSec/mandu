/**
 * mandu-running — is Mandu running on this computer at all? Asked only when
 * the arbiter did not answer, so Home can tell two states apart
 * (dashboard.md §4.25, the verdict ladder; *Protection is off when nothing
 * runs*, 2026-10-22):
 *
 *   - NOT RUNNING: no arbiter socket at the rendezvous, no arbiter instance
 *     starting, and no `mandu <agent>` launch alive. Nothing of Mandu's runs,
 *     so no agent is protected: Home says protection is off, and how to start
 *     it. The person who only ran `mandu scan` (plan 17 §3 item 12), or one
 *     who stopped Mandu, is here.
 *   - ANYTHING ELSE: an arbiter socket that does not answer, an instance
 *     still starting, or a launch alive without its arbiter. A fault, or a
 *     moment: Home says "Not connected." as before.
 *
 * Neither ever says "protected": what cannot be checked is never claimed
 * (fail-closed display). A pid reused by another process keeps a stale
 * launch dir "alive", which reads as Not connected, the cautious side.
 * Off the security path: display only.
 *
 * The runtime registry it reads (runtime-instances.md §10): the instances
 * `<base>/instances/<id>/manifest.json` and the launches' scope run dirs
 * `<base>/<epochSec>-<pid>` (launcher/src/subcommands.ts `registeredPids`
 * reads the same).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 */
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { systemLogKind } from "./event-source/registry.js";

/** Mandu is not running. `everRan`: an agent session is on record in the
 *  event store, so Mandu ran here before (Home's first-run card is for
 *  someone who never did). */
export interface ManduNotRunning {
  everRan: boolean;
}

export interface RunningProbeAt {
  /** The socket the dashboard dials (server-main's ARBITER_SOCK). */
  arbiterSock: string;
  /** The runtime base (server-main's RUNTIME_BASE). */
  runtimeBase: string;
  /** The event store (event-dir.ts defaultEventDir). */
  eventDir: string;
}

export interface RunningProbeDeps {
  exists: (path: string) => boolean;
  /** Names in a directory; [] when it is absent or unreadable. */
  list: (dir: string) => string[];
  /** A JSON file's parsed body, or null. */
  readJson: (path: string) => unknown;
  pidAlive: (pid: number) => boolean;
}

export const realRunningProbeDeps: RunningProbeDeps = {
  exists: (p) => existsSync(p),
  list: (d) => { try { return readdirSync(d); } catch { return []; } },
  readJson: (p) => { try { return JSON.parse(readFileSync(p, "utf8")) as unknown; } catch { return null; } },
  pidAlive: (pid) => {
    try {
      process.kill(pid, 0);
      return true;
    } catch (e) {
      return (e as NodeJS.ErrnoException).code === "EPERM";
    }
  },
};

/** A launch's scope run dir: `<epochSec>-<pid>`. */
const LAUNCH_DIR = /^\d+-(\d+)$/;

/** Not running (see the header), or null: something of Mandu's is there. */
export function manduNotRunning(at: RunningProbeAt, deps: RunningProbeDeps = realRunningProbeDeps): ManduNotRunning | null {
  if (deps.exists(at.arbiterSock)) return null;
  for (const id of deps.list(join(at.runtimeBase, "instances"))) {
    const m = deps.readJson(join(at.runtimeBase, "instances", id, "manifest.json")) as { pid?: unknown } | null;
    if (m !== null && typeof m === "object" && typeof m.pid === "number" && deps.pidAlive(m.pid)) return null;
  }
  for (const name of deps.list(at.runtimeBase)) {
    const m = LAUNCH_DIR.exec(name);
    if (m && deps.pidAlive(Number(m[1]))) return null;
  }
  const everRan = deps.list(at.eventDir).some((n) => n.endsWith(".ndjson") && systemLogKind(n.slice(0, -".ndjson".length)) === undefined);
  return { everRan };
}
