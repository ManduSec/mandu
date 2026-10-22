/**
 * stack-supervisor — is a Mandu stack kept alive by a systemd service
 * (runtime-instances.md §4.1a)?
 *
 * The release check stops a resident stack of another release or build and
 * starts this one's (arbiter-version.ts). A stack that a systemd service runs
 * as its main process, with `Restart=` set, comes back from that stop: the
 * unit starts the OLD code again, and the launch either refuses with a
 * misleading "the installation is mixed" or the two installs replace each
 * other's services. Found 2026-10-19: a source checkout's dashboard ran as a
 * user service (`Restart=always`), and an npm install's `mandu` met its
 * arbiter. The fix is the user's to make (disable that unit), so the launch
 * and `mandu version` name the unit and the command.
 *
 * Linux only: the unit comes from `/proc/<pid>/cgroup` (cgroup v2's one line,
 * or v1's `name=systemd` hierarchy), and whether the unit restarts that
 * process from `systemctl show` (MainPID, Restart). A daemon is supervised
 * when it is the unit's main process or that process's direct child (an
 * ExecStart through tsx or a script: when the daemon dies, the wrapper exits
 * and the unit restarts it). A process merely deeper INSIDE a service's
 * cgroup (a launch from a CI runner's job) is not: the unit restarts only its
 * main process. Everything is best effort and null when it cannot be told.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 */
import { spawnSync } from "node:child_process";
import { readdirSync, readFileSync, readlinkSync, realpathSync } from "node:fs";
import { resolve } from "node:path";
import { runtimeBase } from "./arbiter-sock.js";

/** A systemd service that runs a Mandu daemon as its main process. */
export interface StackSupervisor {
  /** The unit, e.g. `mandu-dashboard.service`. */
  unit: string;
  /** A user unit (`systemctl --user`) or a system one. */
  user: boolean;
  /** The unit's main process (one of the stack's daemons). */
  mainPid: number;
  /** Its `Restart=` setting (`always`, `on-failure`, …). */
  restart: string;
  /** Its WorkingDirectory, or null when unset: where its code most likely is. */
  workingDirectory: string | null;
  /** Its unit file, or null. */
  fragmentPath: string | null;
  /** The stack's arbiter is NOT this service's process (its cgroup is not
   *  the unit's): another launch or dashboard started it and the service's
   *  dashboard adopted it. null/absent = not told (no arbiter pid, no /proc). */
  arbiterOutside?: boolean | null;
  /** The service runs this mandu's own code (its folder is inside this
   *  mandu's package or checkout). null/absent = cannot tell. */
  runsOurCode?: boolean | null;
}

/** The effects `withStackFacts` needs (test seams). */
export interface StackFactDeps {
  cgroupOf: (pid: number) => string | null;
  /** The folder a process runs in (/proc/<pid>/cwd), or null. */
  cwdOf: (pid: number) => string | null;
  /** A path with its links resolved, or the path itself when that fails. */
  realpath: (p: string) => string;
}

export const realStackFactDeps: StackFactDeps = {
  cgroupOf: realSupervisorDepsCgroup,
  cwdOf: (pid) => {
    if (process.platform !== "linux") return null;
    try { return readlinkSync(`/proc/${pid}/cwd`).replace(/ \(deleted\)$/, ""); } catch { return null; }
  },
  realpath: (p) => { try { return realpathSync(p); } catch { return p; } },
};

function realSupervisorDepsCgroup(pid: number): string | null {
  if (process.platform !== "linux") return null;
  try { return readFileSync(`/proc/${pid}/cgroup`, "utf8"); } catch { return null; }
}

/**
 * `s` with the two facts that decide what a refusal tells the user
 * (runtime-instances.md §4.1a, §4.1b): whether the stack's arbiter
 * (`arbiterPid`) runs outside the service (the service's dashboard adopted
 * an arbiter someone else started), and whether the service runs the code of
 * this mandu (`ourRoot`: its package root, or its checkout). Never throws.
 */
export function withStackFacts(
  s: StackSupervisor,
  arbiterPid: number | null,
  ourRoot: string,
  deps: StackFactDeps = realStackFactDeps,
): StackSupervisor {
  let arbiterOutside: boolean | null = null;
  if (arbiterPid !== null) {
    const cg = deps.cgroupOf(arbiterPid);
    if (cg !== null) arbiterOutside = serviceUnitOfCgroup(cg)?.unit !== s.unit;
  }
  const dir = s.workingDirectory ?? deps.cwdOf(s.mainPid);
  let runsOurCode: boolean | null = null;
  if (dir !== null) {
    const d = deps.realpath(dir).replace(/\/+$/, "");
    const root = deps.realpath(ourRoot).replace(/\/+$/, "");
    runsOurCode = d === root || d.startsWith(`${root}/`);
  }
  return { ...s, arbiterOutside, runsOurCode };
}

/** The service unit a `/proc/<pid>/cgroup` text places the process in, or
 *  null (a scope, a slice, no systemd). Pure. */
export function serviceUnitOfCgroup(text: string): { unit: string; user: boolean } | null {
  const lines = text.split("\n").map((l) => l.trim()).filter(Boolean);
  // cgroup v2 ("0::/path"), else v1's systemd hierarchy.
  const line = lines.find((l) => l.startsWith("0::")) ?? lines.find((l) => /^\d+:name=systemd:/.test(l));
  if (!line) return null;
  const path = line.slice(line.indexOf(":", line.indexOf(":") + 1) + 1);
  const parts = path.split("/").filter(Boolean);
  const last = parts[parts.length - 1];
  if (!last || !last.endsWith(".service")) return null;
  // The per-user manager itself (user@1000.service) is not a unit anyone set up.
  if (/^user@\d+\.service$/.test(last)) return null;
  return { unit: last, user: parts.some((p) => /^user@\d+\.service$/.test(p)) };
}

/** `systemctl show` output (Key=Value lines) as a map. Pure. */
export function parseSystemctlShow(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of text.split("\n")) {
    const i = line.indexOf("=");
    if (i > 0) out[line.slice(0, i)] = line.slice(i + 1);
  }
  return out;
}

/** The parent pid in a `/proc/<pid>/stat` text, or null. The command name
 *  may hold spaces and parentheses, so the fields are read after its last `)`. Pure. */
export function ppidOfStat(text: string): number | null {
  const fields = text.slice(text.lastIndexOf(")") + 2).split(" ");
  const ppid = Number(fields[1]);
  return Number.isInteger(ppid) && ppid > 0 ? ppid : null;
}

/** The effects stackSupervisor needs, injectable for tests. */
export interface SupervisorDeps {
  /** `/proc/<pid>/cgroup`, or null. */
  cgroupOf: (pid: number) => string | null;
  /** The parent pid, or null. */
  ppidOf: (pid: number) => number | null;
  /** `systemctl [--user] show -p MainPID -p Restart -p WorkingDirectory -p FragmentPath <unit>`, or null. */
  show: (unit: string, user: boolean) => string | null;
}

export const realSupervisorDeps: SupervisorDeps = {
  cgroupOf: (pid) => {
    if (process.platform !== "linux") return null;
    try { return readFileSync(`/proc/${pid}/cgroup`, "utf8"); } catch { return null; }
  },
  ppidOf: (pid) => {
    if (process.platform !== "linux") return null;
    try { return ppidOfStat(readFileSync(`/proc/${pid}/stat`, "utf8")); } catch { return null; }
  },
  show: (unit, user) => {
    const r = spawnSync("systemctl", [...(user ? ["--user"] : []), "show",
      "-p", "MainPID", "-p", "Restart", "-p", "WorkingDirectory", "-p", "FragmentPath", "--", unit], {
      encoding: "utf8", timeout: 3_000, stdio: ["ignore", "pipe", "ignore"],
    });
    return r.status === 0 && typeof r.stdout === "string" ? r.stdout : null;
  },
};

/**
 * The systemd service that restarts one of `pids` (a stack's resident
 * daemons) when it is stopped, or null. The first such unit wins.
 */
export function stackSupervisor(pids: readonly number[], deps: SupervisorDeps = realSupervisorDeps): StackSupervisor | null {
  const seen = new Set<string>();
  for (const pid of pids) {
    const cg = deps.cgroupOf(pid);
    const u = cg === null ? null : serviceUnitOfCgroup(cg);
    if (u === null || seen.has(u.unit)) continue;
    seen.add(u.unit);
    const shown = deps.show(u.unit, u.user);
    if (shown === null) continue;
    const p = parseSystemctlShow(shown);
    const mainPid = Number(p["MainPID"]);
    const restart = (p["Restart"] ?? "").trim();
    // Only the main process is restarted, and only when Restart= is set. A
    // daemon is the main process, or its direct child (an ExecStart through
    // a wrapper: tsx, npm, a shell script); one further down (a launch from a
    // CI runner's job) is not the unit's to restart.
    if (!Number.isInteger(mainPid) || mainPid <= 0) continue;
    if (!pids.some((p) => p === mainPid || (deps.cgroupOf(p) === cg && deps.ppidOf(p) === mainPid))) continue;
    if (restart === "" || restart === "no") continue;
    return {
      unit: u.unit,
      user: u.user,
      mainPid,
      restart,
      // systemd prefixes a WorkingDirectory= it may skip ("-") or that a
      // transient unit defaulted to the home ("!"): the folder is what follows.
      workingDirectory: p["WorkingDirectory"]?.trim().replace(/^[-!+~]+/, "") || null,
      fragmentPath: p["FragmentPath"]?.trim() || null,
    };
  }
  return null;
}

/** The command that stops the unit for good. */
export function disableCommand(s: Pick<StackSupervisor, "unit" | "user">): string {
  return `systemctl${s.user ? " --user" : ""} disable --now ${s.unit}`;
}

/** The other way out, for a service kept on purpose (the lab's dashboard
 *  service, a deliberate second install): this mandu on a stack of its own
 *  beside the one at `base`. A runtime folder of its own is not enough: the
 *  symbol database has one writer (its owner lock refuses a second arbiter),
 *  so the second stack has a Mandu folder of its own too (verified
 *  2026-10-19 on the lab host: the runtime folder alone was refused at the
 *  lock, both together launched). */
export function ownStackCommand(base: string): string {
  return `MANDU_HOME=~/.mandu-own MANDU_RUNTIME_DIR=${base.replace(/\/+$/, "")}-own mandu …`;
}

/** What that second Mandu folder means, said beside the command. */
export const OWN_STACK_NOTE =
  "a Mandu folder of its own, so its own rules and history: copy your policy.yaml and config.toml from ~/.mandu into it to keep your rules";

/** The effects stackService needs, injectable for tests. */
export interface StackServiceDeps extends SupervisorDeps {
  /** This user's pids (Linux: /proc), or [] where that cannot be read. */
  listPids: () => number[];
  /** The environment `pid` was started with, or null (gone, another user's). */
  environOf: (pid: number) => Record<string, string> | null;
  /** The stack (runtime base) an environment selects (arbiter-sock.ts runtimeBase). */
  stackOfEnv: (env: Record<string, string>) => string | null;
}

function normBase(p: string): string {
  return resolve(p).replace(/\/+$/, "") || "/";
}

export const realStackServiceDeps: StackServiceDeps = {
  ...realSupervisorDeps,
  listPids: () => {
    if (process.platform !== "linux") return [];
    try { return readdirSync("/proc").filter((n) => /^\d+$/.test(n)).map(Number); } catch { return []; }
  },
  environOf: (pid) => {
    let raw: string;
    try { raw = readFileSync(`/proc/${pid}/environ`, "utf8"); } catch { return null; }
    const env: Record<string, string> = {};
    for (const kv of raw.split("\0")) {
      const i = kv.indexOf("=");
      if (i > 0) env[kv.slice(0, i)] = kv.slice(i + 1);
    }
    return env;
  },
  stackOfEnv: (env) => {
    if (!env["MANDU_RUNTIME_DIR"] && !env["XDG_RUNTIME_DIR"] && !env["HOME"]) return null;
    try { return runtimeBase(env); } catch { return null; }
  },
};

/**
 * The systemd service that runs the stack at `base` right now, or null
 * (runtime-instances.md §4.1c): a process of this user in a service's cgroup
 * whose environment selects that stack (any process of it, so the unit's
 * main process counts while it is still loading, before its dashboard has a
 * title or an arbiter), and whose unit restarts it (stackSupervisor's rule).
 * Found while the service restarts, too: systemd starts the new main process
 * as soon as the old one is gone. Linux only; null elsewhere.
 */
export function stackService(base: string, deps: StackServiceDeps = realStackServiceDeps): StackSupervisor | null {
  const want = normBase(base);
  const pids: number[] = [];
  for (const pid of deps.listPids()) {
    if (pid === process.pid) continue;
    const cg = deps.cgroupOf(pid);
    if (cg === null || serviceUnitOfCgroup(cg) === null) continue;
    const env = deps.environOf(pid);
    const stack = env === null ? null : deps.stackOfEnv(env);
    if (stack !== null && normBase(stack) === want) pids.push(pid);
  }
  return pids.length === 0 ? null : stackSupervisor(pids, deps);
}

/** "the systemd user service mandu-dashboard.service (Restart=always, in /home/u/mandu)". */
export function describeSupervisor(s: StackSupervisor): string {
  const where = s.workingDirectory ? `, in ${s.workingDirectory}` : "";
  return `the systemd ${s.user ? "user " : ""}service ${s.unit} (Restart=${s.restart}${where})`;
}
