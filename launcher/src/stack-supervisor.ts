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
import { readFileSync } from "node:fs";

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
      workingDirectory: p["WorkingDirectory"]?.trim() || null,
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

/** "the systemd user service mandu-dashboard.service (Restart=always, in /home/u/mandu)". */
export function describeSupervisor(s: StackSupervisor): string {
  const where = s.workingDirectory ? `, in ${s.workingDirectory}` : "";
  return `the systemd ${s.user ? "user " : ""}service ${s.unit} (Restart=${s.restart}${where})`;
}
