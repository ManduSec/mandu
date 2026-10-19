/**
 * doctor-live — `mandu doctor --live`: does Mandu WORK on this machine,
 * with this user's config, right now? (dashboard.md §4.21 / packaging.md §7b)
 *
 * `mandu doctor` checks that the parts exist. This runs them the way a
 * launch does — the real launcher, the user's own config.toml and HOME, every
 * rung default-on — around commands that cannot cost a model call, and reads
 * the answer off the same banners the session-health record uses:
 *
 *   L1 launch        `mandu --target claude -- <true>`: exit 0, and NO
 *                    default-on rung dropped / degraded (the 2026-09-05
 *                    bricked launch, the resident-stack port collisions and
 *                    the codex nested-bwrap failure all fail HERE). `<true>`
 *                    is the platform's (`liveTrueCommand`): /usr/bin/true on
 *                    macOS, which has no /bin/true; /bin/true elsewhere, which
 *                    a split-/usr Linux (Alpine, an unmerged Debian) has and
 *                    /usr/bin/true may not be.
 *   L2 relay (pipe)  a symbol the arbiter minted for this check, echoed by a
 *                    child under the launcher on a PIPE, reaches stdout
 *                    RESOLVED — the reply-filter's pipe path end to end.
 *   L3 relay (pty)   the same under the host's script(1) (util-linux on
 *                    Linux, found on PATH; BSD /usr/bin/script by path on
 *                    macOS; the argv per flavor mirrors reply-filter's
 *                    pty-relay.ts): the PTY relay path a TUI actually rides,
 *                    and its "PTY RELAY" note.
 *   L4 agent binary  `mandu -- claude --version` (and codex when present):
 *                    the agent's own binary starts INSIDE the full wrap —
 *                    secret twins, landlock-net, net-guard, exec shims on
 *                    Linux; the Seatbelt read-block profile on macOS.
 *   L5 model turn    (--model) `mandu -- claude -p 'reply OK'`: one real,
 *                    cheap model call through the proxy — auth, routing and
 *                    the handling prompt all live. Opt-in: it spends budget.
 *
 * macOS (2026-09-29): the Linux-only rungs (the command box, landlock-net,
 * the connect guard, the inspect_symbol network confine) are not part of the
 * macOS posture, so L1 does not grade them there. The key is the PLATFORM,
 * not only the wording: a darwin launch may print the older "not built …
 * proceeding WITHOUT it" line for them, or the informational "Linux only"
 * one; either way the line is counted as Linux only, never as dropped (a
 * line about the macOS mechanism itself, Seatbelt, stays a drop).
 *
 * Every check is a spawned process with injectable `run`, so the report
 * logic is unit-tested against canned outputs; the e2e runs it for real.
 * Exit 1 if any check fails — this IS the user-side gate.
 *
 * Mandu-new (no reference origin).
 */
import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { resolveArbiterSock } from "./arbiter-sock.js";
import { ndjsonCall } from "./secret-setup.js";
import { postureFindings } from "./services/observe.js";
import type { Layout } from "./services/layout.js";

export type Env = Record<string, string | undefined>;

export interface RunResult { code: number; stdout: string; stderr: string }

/** Injectable process/IPC seams so the report is testable without a host. */
export interface DoctorLiveDeps {
  /** Run the launcher with `args` (after `mandu`), capturing both streams. */
  launcher: (args: string[], env: Env, opts?: { pty?: boolean }) => Promise<RunResult>;
  /** Mint a symbol for `value` via the arbiter at `sock` (null when unreachable). */
  symbolize: (sock: string, value: string) => Promise<string | null>;
  commandExists: (cmd: string) => boolean;
  /** The host platform (the L1 grading and the L3 script(1) flavor key on
   *  it). Optional: absent = this process's own. */
  platform?: NodeJS.Platform;
}

/** The `script(1)` dialect a platform ships. MIRRORS interceptors/reply-filter/
 *  src/pty-relay.ts `ptyFlavor` (the launcher never imports another package's
 *  source; a parity unit test holds the two together). */
export type LivePtyFlavor = "util-linux" | "bsd";

export function livePtyFlavor(platform: NodeJS.Platform = process.platform): LivePtyFlavor | null {
  if (platform === "linux") return "util-linux";
  if (platform === "darwin") return "bsd";
  return null;
}

/** The script(1) binary per flavor. MIRRORS pty-relay.ts `ptyScriptPath`:
 *  macOS's BSD script by absolute path (a PATH entry the agent can write
 *  cannot stand in for it); util-linux looked up on PATH, as always. */
export function livePtyScript(flavor: LivePtyFlavor): string {
  return flavor === "bsd" ? "/usr/bin/script" : "script";
}

/** L1's command: a no-op that exists at that path on the platform. macOS has
 *  no /bin/true; a split-/usr Linux may have no /usr/bin/true. */
export function liveTrueCommand(platform: NodeJS.Platform = process.platform): string {
  return platform === "darwin" ? "/usr/bin/true" : "/bin/true";
}

/** POSIX single-quote one word (util-linux `script -c` runs `sh -c`). */
function shQuote(word: string): string {
  return "'" + word.replace(/'/g, "'\\''") + "'";
}

/** The PTY relay argv for `cmd`. MIRRORS pty-relay.ts `buildPtyArgv`:
 *  util-linux `script -qefc 'exec env SHELL=<user's> <cmd>' /dev/null` (one
 *  POSIX-quoted shell string, run by the relay shell `LIVE_PTY_RELAY_SHELL`,
 *  the user's SHELL handed back to the command), BSD `/usr/bin/script -q
 *  /dev/null <cmd…>` (execs the argv directly; BSD script rejects `-f`/`-c`
 *  with "illegal option -- f"). */
export function livePtyArgv(cmd: readonly string[], flavor: LivePtyFlavor, userShell: string | null = process.env["SHELL"] ?? null): string[] {
  if (flavor === "bsd") return [livePtyScript(flavor), "-q", "/dev/null", ...cmd];
  const restore = userShell ? `env SHELL=${shQuote(userShell)}` : "env -u SHELL";
  return [livePtyScript(flavor), "-qefc", `exec ${restore} ` + cmd.map(shQuote).join(" "), "/dev/null"];
}

/** The shell util-linux script runs its `-c` string with. MIRRORS pty-relay.ts
 *  `PTY_RELAY_SHELL`: POSIX sh reads no startup file for `-c`, where a
 *  user's shell may (and one that `exec`s another shell swallows the
 *  command). */
export const LIVE_PTY_RELAY_SHELL = "/bin/sh";

/** The stdin the relay is spawned with. BSD script reads the terminal
 *  attributes of its stdin and dies on a pipe (measured on macOS 26.5.1:
 *  "script: tcgetattr/ioctl: Operation not supported on socket", exit 1, the
 *  child never runs), so it gets /dev/null; util-linux keeps spawnSync's
 *  empty pipe, as before. */
export function livePtyStdin(flavor: LivePtyFlavor): "ignore" | "pipe" {
  return flavor === "bsd" ? "ignore" : "pipe";
}

/** The default-on rungs that exist only on Linux (bubblewrap, Landlock,
 *  seccomp), matched on their launch lines in the older wording ("… is not
 *  built … proceeding WITHOUT it") and the newer ("… Linux only …") alike. */
export const LINUX_ONLY_RUNG_RES: readonly RegExp[] = [
  /\bexec-box\b|mandu-exec-box/,
  /\blandlock-net\b|whole-agent TCP confine|mandu-landlock-apply/,
  /\bnet-guard\b|connect-guard|mandu-net-guard/,
  /inspect_symbol network confine/,
];

/** What makes a rung's degrade a LINUX-ONLY absence and not a failure of a
 *  macOS rung: a Linux native bin, bubblewrap, a user namespace, the Landlock
 *  kernel feature, or the words "Linux only". */
const LINUX_CAUSE_RE = /mandu-(?:exec-box|landlock-apply|net-guard)\b|\bbwrap\b|bubblewrap|\bLandlock\b|user namespaces|\bLinux only\b/;
/** …and never a line about the macOS mechanism itself (a Seatbelt rung that
 *  failed is a real drop, whatever rung name it shares). */
const MAC_MECHANISM_RE = /Seatbelt|sandbox-exec/;

/** A launch line about a Linux-only rung's absence (either wording). */
export function isLinuxOnlyRungLine(line: string): boolean {
  return LINUX_ONLY_RUNG_RES.some((re) => re.test(line)) && LINUX_CAUSE_RE.test(line) && !MAC_MECHANISM_RE.test(line);
}

/** L1's grading of a launch's banner lines on `platform`. On Linux it is
 *  exactly `postureFindings`. Off Linux a "dropped" line about a Linux-only
 *  rung's absence is not a degradation (the rung is not part of that
 *  platform's posture): it moves to `linuxOnly`, and so, for the count, does
 *  a newer-wording "Linux only" line that never read as dropped. Pure. */
export function gradeLaunch(lines: readonly string[], platform: NodeJS.Platform): { live: string[]; dropped: string[]; linuxOnly: string[] } {
  const { live, dropped } = postureFindings(lines);
  if (platform === "linux") return { live, dropped, linuxOnly: [] };
  const linuxOnly: string[] = [];
  const kept: string[] = [];
  for (const d of dropped) (isLinuxOnlyRungLine(d) ? linuxOnly : kept).push(d);
  for (const raw of lines) {
    const l = raw.trim();
    const rung = LINUX_ONLY_RUNG_RES.some((re) => re.test(l));
    if (rung && /\bLinux only\b/.test(l) && !linuxOnly.includes(l) && !kept.includes(l)) linuxOnly.push(l);
  }
  return { live, dropped: kept, linuxOnly };
}

export interface LiveCheck {
  id: "launch" | "relay-pipe" | "relay-pty" | "agent-claude" | "agent-codex" | "model";
  ok: boolean | null; // null = skipped
  summary: string;
  detail?: string[];
}

export interface DoctorLiveReport {
  checks: LiveCheck[];
  ok: boolean;
}

function launcherArgv(_layout: Layout): string[] {
  // Re-exec THIS launcher exactly as it is running: node + its loader flags
  // (tsx in a dev checkout, none for the installed bundle) + the entry script.
  // Whatever `mandu` resolved to for the user is what the live checks run.
  return [process.execPath, ...process.execArgv, process.argv[1] ?? "mandu"];
}

export function realDoctorLiveDeps(layout: Layout, platform: NodeJS.Platform = process.platform): DoctorLiveDeps {
  const base = launcherArgv(layout);
  const flavor = livePtyFlavor(platform);
  return {
    platform,
    launcher: async (args, env, opts) => {
      // gatherLive asks for a PTY only where a flavor exists.
      const pty = opts?.pty === true && flavor !== null;
      const argv = pty ? livePtyArgv([...base, ...args], flavor, env["SHELL"] ?? null) : [...base, ...args];
      // util-linux script runs its -c string through $SHELL (pty-relay.ts
      // ptyRelayEnv); BSD script execs the argv itself.
      const spawnEnv = pty && flavor === "util-linux" ? { ...env, SHELL: LIVE_PTY_RELAY_SHELL } : env;
      const r = spawnSync(argv[0]!, argv.slice(1), {
        env: spawnEnv as NodeJS.ProcessEnv, encoding: "utf8", timeout: 120_000, maxBuffer: 16 * 1024 * 1024,
        ...(pty ? { stdio: [livePtyStdin(flavor), "pipe", "pipe"] } : {}),
      });
      return { code: r.status ?? 127, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
    },
    symbolize: async (sock, value) => {
      try {
        const r = await ndjsonCall<{ symbol?: string } | string>(sock, "symbolize", { tool: "doctor", value }, 5000);
        return typeof r === "string" ? r : (r?.symbol ?? null);
      } catch {
        return null;
      }
    },
    commandExists: (cmd) => spawnSync("bash", ["-c", `command -v ${cmd}`], { stdio: "ignore" }).status === 0,
  };
}

const PROBE_PREFIX = "MANDU_DOCTOR_LIVE_";

/** Run the live checks. Pure over deps; the env is the user's (config.toml,
 *  HOME, MANDU_* all honored — that is the point). */
export async function gatherLive(userEnv: Env, deps: DoctorLiveDeps, opts: { model?: boolean } = {}): Promise<DoctorLiveReport> {
  const checks: LiveCheck[] = [];
  // Every check reads the rung banners (and the relay's PTY RELAY note) off
  // the launch's stderr; a launch prints only the mode line by default
  // (launch-banner.ts, release checklist a6), so ask for the full banner.
  const env: Env = { ...userEnv, MANDU_VERBOSE: "1" };
  const common = ["--no-scope", "--target", "claude"];
  const platform = deps.platform ?? process.platform;

  // L1 — the launch itself, at the full default posture. Off Linux the
  // Linux-only rungs are not graded (gradeLaunch): they are not part of that
  // platform's posture, whatever their line says.
  {
    const r = await deps.launcher([...common, "--", liveTrueCommand(platform)], env);
    const { live, dropped, linuxOnly } = gradeLaunch(r.stderr.split("\n"), platform);
    const ok = r.code === 0 && dropped.length === 0;
    const notGraded = linuxOnly.length > 0
      ? `; ${linuxOnly.length} line(s) about Linux-only rungs not graded on ${platformName(platform)}`
      : "";
    const posture = platform === "linux" ? "the full posture" : `the full ${platformName(platform)} posture`;
    checks.push({
      id: "launch",
      ok,
      summary: r.code !== 0
        ? `launch FAILED (exit ${r.code})`
        : dropped.length
          ? `launched, but ${dropped.length} default-on rung(s) dropped/degraded${notGraded}`
          : `launched at ${posture} (${live.length} rung(s) live${notGraded})`,
      detail: r.code !== 0 ? r.stderr.trim().split("\n").slice(-6) : dropped,
    });
    if (r.code !== 0) {
      return { checks, ok: false }; // nothing below can run
    }
  }

  // L2/L3 — the reply-filter resolves a real symbol, pipe and pty.
  const sock = resolveArbiterSock(env).sock;
  const probe = `${PROBE_PREFIX}${randomUUID().slice(0, 8)}`;
  const token = await deps.symbolize(sock, probe);
  if (!token) {
    checks.push({ id: "relay-pipe", ok: false, summary: `could not mint a probe symbol (arbiter at ${sock} unreachable)` });
    checks.push({ id: "relay-pty", ok: null, summary: "skipped (no probe symbol)" });
  } else {
    const flavor = livePtyFlavor(platform);
    for (const pty of [false, true]) {
      const id = pty ? "relay-pty" : "relay-pipe";
      if (pty && flavor === null) {
        checks.push({ id, ok: null, summary: `skipped: no PTY relay on ${platformName(platform)} (the reply-filter uses passthrough here)` });
        continue;
      }
      if (pty && !deps.commandExists(livePtyScript(flavor!))) {
        const which = flavor === "bsd" ? "/usr/bin/script is not there" : "util-linux script(1) not on PATH";
        checks.push({ id, ok: null, summary: `skipped: ${which} (the PTY relay degrades to passthrough here)` });
        continue;
      }
      const r = await deps.launcher([...common, "--", "/bin/echo", token], env, { pty });
      const out = r.stdout + (pty ? "" : "");
      const resolved = out.includes(probe);
      const leaked = out.includes(token);
      const note = pty ? (/PTY RELAY/.test(r.stderr + r.stdout) ? "PTY RELAY" : "no PTY RELAY note") : "pipe";
      checks.push({
        id,
        ok: r.code === 0 && resolved && !leaked,
        summary: r.code !== 0
          ? `child exited ${r.code}`
          : resolved && !leaked
            ? `symbol resolved on the ${pty ? "PTY relay" : "pipe"} (${note})`
            : leaked
              ? `symbol reached the terminal RAW (${note}) — the reply-filter did not resolve it`
              : `neither the value nor the symbol appeared (${note})`,
        detail: r.code !== 0 ? r.stderr.trim().split("\n").slice(-4) : undefined,
      });
    }
  }

  // L4 — the agent binaries start inside the full wrap.
  for (const agent of ["claude", "codex"] as const) {
    const id = agent === "claude" ? "agent-claude" : "agent-codex";
    if (!deps.commandExists(agent)) {
      checks.push({ id, ok: agent === "claude" ? false : null, summary: `${agent} not on PATH${agent === "codex" ? " (skipped)" : ""}` });
      continue;
    }
    const r = await deps.launcher(["--no-scope", "--target", agent, "--", agent, "--version"], env);
    const ver = (r.stdout + r.stderr).match(/\d+\.\d+\.\d+/)?.[0] ?? null;
    checks.push({
      id,
      ok: r.code === 0 && ver !== null,
      summary: r.code === 0 && ver ? `${agent} ${ver} starts inside the wrap` : `${agent} --version failed inside the wrap (exit ${r.code})`,
      detail: r.code !== 0 ? (r.stderr + r.stdout).trim().split("\n").slice(-6) : undefined,
    });
  }

  // L5 — one real model turn (opt-in).
  if (opts.model) {
    const r = await deps.launcher([...common, "--", "claude", "-p", "Reply with exactly the word OK and nothing else.", "--model", "haiku", "--output-format", "text"], env);
    const ok = r.code === 0 && /\bOK\b/.test(r.stdout);
    checks.push({ id: "model", ok, summary: ok ? "a real model turn came back through the proxy" : `model turn failed (exit ${r.code}): ${(r.stdout + r.stderr).trim().split("\n").slice(-2).join(" / ")}` });
  } else {
    checks.push({ id: "model", ok: null, summary: "skipped (pass --model to spend one cheap real turn)" });
  }

  return { checks, ok: checks.every((c) => c.ok !== false) };
}

/** A platform's name in the report. */
function platformName(p: NodeJS.Platform): string {
  return p === "darwin" ? "macOS" : p === "linux" ? "Linux" : p;
}

const OK = "✓";
const NO = "✗";
const DOT = "·";

/** Render the live report. Pure. */
export function renderLive(rep: DoctorLiveReport): string {
  const L: string[] = ["Mandu doctor --live", ""];
  const label: Record<LiveCheck["id"], string> = {
    launch: "launch at the default posture",
    "relay-pipe": "reply-filter (pipe)",
    "relay-pty": "reply-filter (PTY relay)",
    "agent-claude": "claude inside the wrap",
    "agent-codex": "codex inside the wrap",
    model: "one real model turn",
  };
  for (const c of rep.checks) {
    const mark = c.ok === null ? DOT : c.ok ? OK : NO;
    L.push(`  ${mark} ${label[c.id]}: ${c.summary}`);
    for (const d of c.detail ?? []) L.push(`      ${d}`);
  }
  L.push("");
  L.push(rep.ok
    ? "Verdict: Mandu works on this machine with your configuration."
    : "Verdict: something a real session would hit is broken — fix the ✗ lines above before trusting a launch.");
  return L.join("\n") + "\n";
}

export async function runDoctorLive(env: Env, layout: Layout, rest: string[], deps: DoctorLiveDeps = realDoctorLiveDeps(layout)): Promise<number> {
  const rep = await gatherLive(env, deps, { model: rest.includes("--model") });
  process.stdout.write(renderLive(rep));
  return rep.ok ? 0 : 1;
}

/** Is a `doctor` invocation asking for the live checks? */
export function wantsLive(rest: string[]): boolean {
  return rest.includes("--live");
}

