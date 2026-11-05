/**
 * fake-systemd — a stand-in for `systemctl --user` that RUNS the unit file it
 * is given, for the component test of `mandu serve`
 * (test/component/serve-command.test.ts). The test never touches the host's
 * real user manager: the maintainer's live stack runs there.
 *
 * What it does with the one unit it knows (`mandu.service` at `unitPath`):
 *   daemon-reload  reads the file;
 *   enable/disable records it;
 *   start          parses the loaded file (serve-unit.ts parseUnitFile) and
 *                  spawns its ExecStart in its WorkingDirectory with ONLY a
 *                  user manager's environment (HOME, XDG_RUNTIME_DIR, USER)
 *                  plus the unit's Environment= lines, specifiers expanded:
 *                  so the unit, not the test's env, has to carry everything
 *                  the stack needs;
 *   stop           SIGTERMs the main process (KillMode=mixed), waits, then
 *                  SIGKILLs what is left of its process group;
 *   show           answers LoadState/ActiveState/SubState/UnitFileState/
 *                  MainPID from that process (and `-p Version` for the probe).
 * Restart= is not simulated. The started process also gets
 * MANDU_TEST_OWNER_PID (runtime-instances.md §8a), so it dies with the test.
 */
import { spawn, type ChildProcess } from "node:child_process";
import { openSync, readdirSync, readFileSync } from "node:fs";
import { expandSpecifiers, parseUnitFile, SERVE_UNIT } from "../../src/serve-unit.js";
import type { SystemctlResult } from "../../src/serve-command.js";

/** The process state letter in /proc/<pid>/stat ('Z' a zombie), or null when gone. */
function procState(pid: number): string | null {
  try {
    const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
    return stat.slice(stat.lastIndexOf(")") + 2).split(" ")[0] ?? null;
  } catch {
    return null;
  }
}

function alive(pid: number): boolean {
  const s = procState(pid);
  return s !== null && s !== "Z" && s !== "X";
}

function ppidOf(pid: number): number | null {
  try {
    const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
    const n = Number(stat.slice(stat.lastIndexOf(")") + 2).split(" ")[1]);
    return Number.isInteger(n) && n > 0 ? n : null;
  } catch {
    return null;
  }
}

/** Block the thread for `ms` (systemctl's stop is synchronous too). */
function sleepSync(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

export class FakeSystemd {
  private loaded: string | null = null;
  private child: ChildProcess | null = null;
  enabled = false;
  /** Every call, as `systemctl --user` would have been given it. */
  readonly calls: string[] = [];

  constructor(
    private readonly unitPath: string,
    /** The user manager's own environment (HOME, XDG_RUNTIME_DIR, USER). */
    private readonly managerEnv: Record<string, string>,
    private readonly logPath: string,
  ) {}

  /** The unit's main process while it runs. */
  get mainPid(): number | null {
    const pid = this.child?.pid;
    return pid !== undefined && alive(pid) ? pid : null;
  }

  /** Is `pid` the unit's main process or one of its descendants (its cgroup)? */
  inUnit(pid: number): boolean {
    const main = this.mainPid;
    if (main === null) return false;
    for (let p: number | null = pid, hops = 0; p !== null && p > 1 && hops < 64; p = ppidOf(p), hops++) {
      if (p === main) return true;
    }
    return false;
  }

  readonly run = (args: string[]): SystemctlResult => {
    this.calls.push(args.join(" "));
    const ok = (stdout = ""): SystemctlResult => ({ code: 0, stdout, stderr: "" });
    const [verb, ...rest] = args;
    if (verb === "show" && rest.includes("Version")) return ok("255\n");
    const named = rest.filter((a) => !a.startsWith("-"));
    if (verb !== "daemon-reload" && verb !== "show" && !named.includes(SERVE_UNIT)) {
      return { code: 5, stdout: "", stderr: `Unit ${named.join(" ")} not known to the fake` };
    }
    switch (verb) {
      case "daemon-reload":
        try { this.loaded = readFileSync(this.unitPath, "utf8"); } catch { this.loaded = null; }
        return ok();
      case "enable": this.enabled = true; return ok();
      case "disable":
        this.enabled = false;
        if (rest.includes("--now")) this.stopUnit();
        return ok();
      case "start": return this.startUnit();
      case "stop": this.stopUnit(); return ok();
      case "show": {
        const pid = this.mainPid;
        return ok(
          `LoadState=${this.loaded === null ? "not-found" : "loaded"}\nActiveState=${pid !== null ? "active" : "inactive"}\n` +
          `SubState=${pid !== null ? "running" : "dead"}\nUnitFileState=${this.enabled ? "enabled" : "disabled"}\n` +
          `MainPID=${pid ?? 0}\nActiveEnterTimestamp=${pid !== null ? "now" : "n/a"}\nNRestarts=0\n`,
        );
      }
      default:
        return { code: 1, stdout: "", stderr: `the fake does not do '${verb}'` };
    }
  };

  private startUnit(): SystemctlResult {
    if (this.mainPid !== null) return { code: 0, stdout: "", stderr: "" };
    if (this.loaded === null) return { code: 5, stdout: "", stderr: `Unit ${SERVE_UNIT} not found.` };
    const u = parseUnitFile(this.loaded);
    const env: Record<string, string> = { ...this.managerEnv, MANDU_TEST_OWNER_PID: String(process.pid) };
    for (const [k, v] of Object.entries(u.environment)) env[k] = expandSpecifiers(v, this.managerEnv);
    const log = openSync(this.logPath, "a");
    const child = spawn(u.execStart[0]!, u.execStart.slice(1), {
      cwd: u.workingDirectory ?? this.managerEnv["HOME"],
      env,
      detached: true,
      stdio: ["ignore", log, log],
    });
    child.unref();
    this.child = child;
    return { code: 0, stdout: "", stderr: "" };
  }

  private stopUnit(): void {
    const pid = this.child?.pid;
    if (pid === undefined) return;
    // The unit's "cgroup": the main process and its descendants, collected
    // before the stop (once the main process is gone they are reparented).
    const members = this.descendants(pid);
    try { process.kill(pid, "SIGTERM"); } catch { /* gone */ }
    for (let i = 0; i < 300 && alive(pid); i++) sleepSync(100);
    for (let i = 0; i < 100 && members.some(alive); i++) sleepSync(100);
    for (const m of [pid, ...members]) { try { if (alive(m)) process.kill(m, "SIGKILL"); } catch { /* gone */ } }
    this.child = null;
  }

  private descendants(root: number): number[] {
    let names: string[] = [];
    try { names = readdirSync("/proc").filter((n) => /^\d+$/.test(n)); } catch { return []; }
    const out: number[] = [];
    for (const n of names) {
      const p = Number(n);
      if (p === root) continue;
      for (let q: number | null = ppidOf(p), hops = 0; q !== null && q > 1 && hops < 64; q = ppidOf(q), hops++) {
        if (q === root) { out.push(p); break; }
      }
    }
    return out;
  }

  /** Stop whatever the fake started (the test's finally). */
  stopAll(): void {
    this.stopUnit();
  }
}
