/**
 * opencode2-confidentiality — when OpenCode 2 may run with the
 * confidentiality axis ON (mode `secrets`, the default, and the frozen
 * modes): every 2.x launch, supported by default since 2026-10-05
 * (supported-agents.md §2.3.1, "Confidentiality ON: allowed under three
 * conditions").
 *
 * WHY CONDITIONS (2026-10-05). OpenCode 2's private server (`--standalone`,
 * opencode-argv.ts) is a loopback HTTP server, and the agent's own `shell`
 * tool runs as its child: a command can read the server's password from
 * `/proc/$PPID/environ` and call its API, which puts any program's output
 * into the conversation as the user's own message, past every check of a
 * tool result. The API can also reload the configuration, and 2.x reloads a
 * config file written mid-session, so a model endpoint the agent writes
 * would take the next request around the proxy. Each hole is closed by one
 * mechanism, and the launch is allowed only while all of them are in force:
 *
 *   1. THE KERNEL-LAYER CONNECT GUARD with the private-server allowance
 *      (mandu-net-guard; net-supervisor own_server.rs): only the client
 *      reaches its server's port, so no command of the agent can call the
 *      server's API. The guard is seccomp user notification, Linux only; a
 *      host without it, or a launch that turned it off (`--no-net-guard`,
 *      `--no-kernel`, MANDU_NO_KERNEL), or a guard bin that is not built, or
 *      an executable the launcher cannot name for the allowance, is refused.
 *      Its wrap then runs WITHOUT `--skip-unsupported` (net-guard.ts
 *      planNetGuard `required`), so a guard that cannot start on the day
 *      fails the launch (exit 71) instead of running the agent unguarded.
 *   2. THE WHOLE-AGENT WRITE-PROTECT GUARD (write-protect.ts), which keeps
 *      the agent's tree out of the launcher-owned OpenCode config directory
 *      (agent-config.ts opencodeWriteProtect): the residual of the config
 *      lockdown. MANDU_WRITE_PROTECT=0 is refused.
 *   3. THE CONFIG LOCKDOWN ENV (agent-config.ts opencodeLockdownEnv): no
 *      file watcher, no project layer, the global layer at the launcher's
 *      directory, in the environment the agent really starts with.
 *
 * Two checks, both fail-closed with one plain line naming what is missing
 * and the fix:
 *   - `opencode2ConfidentialityMissing` before anything starts (run.ts, right
 *     after the effective axes are known), from the launch's flags, the
 *     platform, the guard bin and a probe of seccomp user notification
 *     (`probeGuardNotify`: the guard bin itself run around `true` without
 *     `--skip-unsupported`);
 *   - `opencode2ConfidentialityUnenforced` once the launch is composed and
 *     before the agent starts: the guard wrap is on the launch, the
 *     allowance names the executable, the write-protect list carries the
 *     config directory as `deny`, and the lockdown env is what the agent
 *     gets. A step that silently degraded is caught here.
 *
 * These conditions are what makes OpenCode 2 a default-supported agent:
 * where one is missing, the launch is refused with the way out (`--mode
 * off`, or OpenCode 1), never run unguarded.
 *
 * Pure but for the probe; unit-tested in test/unit/opencode2-confidentiality.test.ts,
 * through main() in test/component/opencode-v2-standalone.test.ts.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code.
 */
import { spawnSync } from "node:child_process";
import { opencodeInstall } from "./agent-versions.js";

/** What the launcher knows before anything starts. */
export interface Opencode2ConfidentialityFacts {
  /** The host platform (`linux`, `darwin`, …). */
  platform: string;
  /** The launch turned the connect guard off (plan.netGuard === false:
   *  `--no-net-guard`, `--no-kernel`, `--portable`, MANDU_NO_KERNEL). */
  netGuardOff: boolean;
  /** The guard bin resolved (services/native-bins.ts). */
  guardBin: boolean;
  /** How to build it, when it did not (buildHintFor). */
  guardBuildHint?: string;
  /** The guard could install its seccomp listener here (probeGuardNotify);
   *  null when not probed (an earlier condition already fails). */
  seccompNotify: boolean | null;
  /** The launcher named the agent's executable for the private-server
   *  allowance (plan.ownServerExe). */
  ownServerExe: boolean;
  /** MANDU_WRITE_PROTECT=0. */
  writeProtectOff: boolean;
}

/** One missing protection: what, and what to do. */
export interface Opencode2Missing {
  what: string;
  fix: string;
}

/** The protections a confidentiality-ON OpenCode 2 launch lacks, from the
 *  facts known before anything starts ([] = allowed). Linux first: off Linux
 *  there is no guard at all, and the other lines would only repeat it. */
export function opencode2ConfidentialityMissing(f: Opencode2ConfidentialityFacts): Opencode2Missing[] {
  if (f.platform !== "linux") {
    return [{
      what: "the connect guard that keeps the agent's commands away from OpenCode 2's own server is Linux only",
      fix: "on this system run OpenCode 2 with `--mode off`, or use OpenCode 1",
    }];
  }
  const out: Opencode2Missing[] = [];
  if (f.netGuardOff) {
    out.push({
      what: "the kernel-layer connect guard is turned off for this launch (--no-net-guard, --no-kernel, --portable or MANDU_NO_KERNEL)",
      fix: "launch without that switch",
    });
  } else if (!f.guardBin) {
    out.push({
      what: "the connect guard (mandu-net-guard) is not built",
      fix: f.guardBuildHint ?? "build it with scripts/build-native.sh",
    });
  } else if (f.seccompNotify === false) {
    out.push({
      what: "this kernel gives the connect guard no seccomp user notification (it cannot start here)",
      fix: "run on a Linux kernel with seccomp user notification (not WSL1, not inside a sandbox that already holds the listener)",
    });
  }
  if (!f.ownServerExe) {
    out.push({
      what: "the launcher could not find the OpenCode 2 executable to give its private server the guard's allowance",
      fix: "launch it by a path or a name on PATH",
    });
  }
  if (f.writeProtectOff) {
    out.push({
      what: "MANDU_WRITE_PROTECT=0 turns off the write-protect guard, which keeps the agent from rewriting OpenCode 2's configuration mid-session",
      fix: "unset MANDU_WRITE_PROTECT",
    });
  }
  return out;
}

/** What the composed launch carries (run.ts, before the agent starts). */
export interface Opencode2Enactment {
  /** The guard wrap is on the launch prefix (applyNetGuard returned one),
   *  without `--skip-unsupported`. */
  guardWrap: string[] | null;
  /** The agent's environment as composed (the env the agent starts with). */
  env: Record<string, string | undefined>;
  /** The executable the allowance must name. */
  ownServerExe: string | undefined;
  /** The guard policy document the agent's guard reads
   *  (MANDU_NET_GUARD_SECRETS), parsed; null when absent or unreadable. */
  guardPolicy: { writeProtect?: Array<{ path?: unknown; answer?: unknown }> } | null;
  /** The launcher's OpenCode config directory (agent-config.ts opencodeConfigDirOf). */
  configDir: string;
}

/** The lockdown keys (agent-config.ts opencodeLockdownEnv) the agent must start with. */
const LOCKDOWN_FLAGS = ["OPENCODE_DISABLE_PROJECT_CONFIG", "OPENCODE_DISABLE_FILEWATCHER"] as const;

/** The protections the composed launch does not carry ([] = enforced).
 *  Each names the step that should have put it there. */
export function opencode2ConfidentialityUnenforced(e: Opencode2Enactment): Opencode2Missing[] {
  const out: Opencode2Missing[] = [];
  const restart = "start the session again; if this repeats, report it (the launch was stopped before the agent ran)";
  if (e.guardWrap === null) {
    out.push({ what: "the connect guard did not wrap the launch", fix: restart });
  } else if (e.guardWrap.includes("--skip-unsupported")) {
    out.push({ what: "the connect guard would run the agent unguarded where it cannot start (--skip-unsupported)", fix: restart });
  }
  if (!e.ownServerExe || e.env["MANDU_NET_GUARD_OWN_SERVER"] !== e.ownServerExe) {
    out.push({ what: "the guard's private-server allowance does not name the OpenCode 2 executable", fix: restart });
  }
  if (e.env["MANDU_NET_GUARD_PROTECT"] !== "1"
    || !(e.guardPolicy?.writeProtect ?? []).some((w) => w.path === e.configDir && w.answer === "deny")) {
    out.push({ what: "the write-protect guard does not cover OpenCode 2's configuration directory", fix: restart });
  }
  if (e.env["OPENCODE_CONFIG_DIR"] !== e.configDir || LOCKDOWN_FLAGS.some((k) => e.env[k] !== "1")
    || !(e.env["OPENCODE_CONFIG"] ?? "").startsWith(e.configDir + "/")) {
    out.push({ what: "the agent's environment does not carry OpenCode 2's config lockdown (no file watcher, no project layer, the launcher's config directory)", fix: restart });
  }
  return out;
}

/** The refusal: one paragraph, the mode, every missing protection with its
 *  fix, and the ways out. */
export function opencode2ConfidentialityRefusal(mode: string, missing: readonly Opencode2Missing[]): string {
  const items = missing.map((m) => `${m.what} (fix: ${m.fix})`).join("; ");
  return (
    `mandu: refusing OpenCode 2 in mode ${mode}: Mandu keeps secrets from the model under OpenCode 2 only with ` +
    `its guards in force, and this launch lacks ${missing.length === 1 ? "one" : "some"}: ${items}. ` +
    "Without them a program the agent runs could reach OpenCode 2's own server and put a file's text into the " +
    "conversation as if you had typed it. " +
    `Otherwise run OpenCode 2 with \`--mode off\` (observing only), or use OpenCode 1 (${opencodeInstall(1)}).`
  );
}

/** Can the guard install its seccomp listener here? Runs the guard bin
 *  around `true` WITHOUT `--skip-unsupported`: exit 0 when it supervised,
 *  71 (fail-closed setup) when the kernel gives no user notification
 *  (mandu-net-guard.rs). Any other outcome counts as no. */
export function probeGuardNotify(guardBin: string, run: typeof spawnSync = spawnSync): boolean {
  const r = run(guardBin, ["--", "true"], { stdio: "ignore", timeout: 10_000, env: { PATH: process.env["PATH"] ?? "/usr/bin:/bin" } });
  return r.status === 0;
}
