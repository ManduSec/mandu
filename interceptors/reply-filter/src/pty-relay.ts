/**
 * pty-relay — the PTY relay backend helpers for the user-reply egress wrapper.
 *
 * Interactive full-screen TUIs need a real terminal on stdout, so pipe-mode
 * filtering breaks them. The relay runs the child under the platform's
 * `script(1)` instead: script allocates a pseudo-terminal for the child
 * (raw-mode stdin forwarding, SIGWINCH → pty resize, exit-code propagation) and
 * relays the whole session to ITS stdout — which the wrapper pipes through the
 * desymbolizing filter to the human's real terminal. Reused, not rewritten
 * (CONTRIBUTING.md): `script(1)` IS the proven PTY relay on POSIX; this module only
 * builds its argv and probes for it. The parenthetical is util-linux script;
 * BSD script does the pty and raw mode but not the rest, which the macOS
 * companion adds (bsd-relay.ts, docs/design/agents/pty-relay.md).
 *
 * Two flavors of `script(1)`, one per shipped platform (packaging.md §6):
 *   - Linux  → util-linux `script -qefc 'exec <cmd>' /dev/null`. The command is
 *     one shell string run through script's `$SHELL -c`, so it is
 *     POSIX-quoted, and `exec` so the agent replaces that shell.
 *   - macOS  → BSD `/usr/bin/script -q /dev/null <cmd> [args…]`. BSD script
 *     execs the command DIRECTLY (no `sh -c`), so the argv is passed through
 *     verbatim — no quoting layer, and no shell-metacharacter exposure.
 *     The binary is named by absolute path, as the companion's /bin/ps and
 *     /bin/stty are: the relay runs OUTSIDE the Seatbelt profile with the
 *     agent's PATH, whose user directories (`~/.local/bin`) the profile
 *     does not write-protect, so a `script` an agent planted there in one
 *     session would otherwise run outside the profile in the next
 *     (review 2026-09-29, docs-tests-11; pty-relay.md §3.2). Linux keeps
 *     util-linux `script` found on PATH, unchanged.
 * A false candidate token merely fails the arbiter lookup and passes through
 * byte-identical, so neither flavor can corrupt the stream.
 *
 * Kept separate from run.ts because run.ts executes main() at module load —
 * tests import THIS module, never run.ts.
 */

import { spawnSync } from "node:child_process";
import { fstatSync } from "node:fs";

/** The `script(1)` dialect for a platform. `util-linux` (Linux) takes the
 *  command as a single `-c` shell string; `bsd` (macOS) execs the trailing
 *  argv directly. `null` = no PTY relay backend on this platform → the caller
 *  degrades to passthrough (run.ts). */
export type PtyFlavor = "util-linux" | "bsd";

/** Map a platform to its `script(1)` flavor. Linux ships util-linux; macOS
 *  ships the BSD variant. Everything else (win32, freebsd, …) has no vetted
 *  relay here and returns null. Platform is a param so the mapping is unit-
 *  tested off the host platform. */
export function ptyFlavor(platform: NodeJS.Platform = process.platform): PtyFlavor | null {
  if (platform === "linux") return "util-linux";
  if (platform === "darwin") return "bsd";
  return null;
}

/** macOS's BSD script(1), by absolute path (module header). */
export const BSD_SCRIPT = "/usr/bin/script";

/** The script(1) binary a flavor runs: BSD by absolute path, util-linux
 *  looked up on PATH (as it always was). */
export function ptyScriptPath(flavor: PtyFlavor): string {
  return flavor === "bsd" ? BSD_SCRIPT : "script";
}

/** POSIX single-quote a word for `script -c` (which runs the command through
 *  `sh -c`): wrap in single quotes, escaping embedded ones as '\''. Only the
 *  util-linux flavor needs this — BSD script execs the argv directly. */
export function shellQuote(word: string): string {
  return "'" + word.replace(/'/g, "'\\''") + "'";
}

/**
 * Build the relay argv for a flavor:
 *   - util-linux: `script -qefc 'exec <cmd>' /dev/null` — -q quiet, -e propagate
 *     the child's exit code (128+n on signal death), -f flush per write, -c the
 *     command (POSIX-quoted, run via `$SHELL -c`); the typescript file →
 *     /dev/null. The `exec` makes the agent REPLACE that shell: bash and zsh
 *     exec a single command anyway, but dash forks and waits, and the waiting
 *     shell sits in the agent's foreground group on the inner pty, so a ^C
 *     once the agent's terminal is cooked again killed it and `script -e`
 *     reported 130 (differential-interactive.md §21).
 *   - bsd:        `/usr/bin/script -q /dev/null <cmd> [args…]` — -q quiet, the typescript
 *     file → /dev/null, then the command and its args passed straight to execvp
 *     (no shell, no quoting). BSD script passes a normal exit code through but
 *     reports a signal death as the bare signal number, and relays neither a
 *     resize nor a signal to the child: the macOS companion (bsd-relay.ts)
 *     covers those (docs/design/agents/pty-relay.md §3).
 * `flavor` defaults to the detected platform's flavor; tests pass it explicitly.
 */
export function buildPtyArgv(
  cmd: string[],
  flavor: PtyFlavor | null = ptyFlavor(),
  userShell: string | null = process.env["SHELL"] ?? null,
): string[] {
  if (flavor === "bsd") {
    return [BSD_SCRIPT, "-q", "/dev/null", ...cmd];
  }
  // util-linux (default; also the defensive fallback — callers only reach here
  // after ptyRelayAvailable() confirmed a backend, so flavor is never null).
  // script runs `-c` through `$SHELL -c`, and the caller spawns it with
  // SHELL=/bin/sh (ptyRelayEnv); `env` hands the agent the user's own SHELL
  // back (Claude Code picks its Bash tool's shell from it).
  const restore = userShell ? `env SHELL=${shellQuote(userShell)}` : "env -u SHELL";
  return ["script", "-qefc", `exec ${restore} ` + cmd.map(shellQuote).join(" "), "/dev/null"];
}

/** The shell util-linux `script` runs its `-c` string with. Not the user's
 *  `$SHELL`: a user's shell can read startup files even for `-c`, and one of
 *  them can swallow the command. Ubuntu's bash reads `~/.bashrc` for `bash -c`
 *  when it thinks sshd started it (SSH_CLIENT set, SHLVL below 2, as under a
 *  tmux server started from an ssh login), and a `.bashrc` that `exec zsh`s on
 *  a terminal then left the agent's pane at a zsh prompt: the agent never ran
 *  (2026-09-30). POSIX sh reads no startup file for `-c`. */
export const PTY_RELAY_SHELL = "/bin/sh";

/** The environment for the util-linux relay's `script` process: the caller's,
 *  with SHELL=/bin/sh (PTY_RELAY_SHELL). buildPtyArgv restores the user's
 *  SHELL for the agent itself. */
export function ptyRelayEnv(env: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  return { ...env, SHELL: PTY_RELAY_SHELL };
}

/** The probe argv per flavor (pure, so the shape is asserted without a Mac):
 *   - util-linux: `script --version` (its output names "util-linux").
 *   - bsd:        `/usr/bin/script -q /dev/null /usr/bin/true` — BSD script
 *     has no `--version`; the cheapest reliable probe is to run the real argv
 *     shape on `true`, which exits immediately. `true` by path too: BSD
 *     script execvp's it with the agent's PATH, outside the profile. Absence
 *     surfaces as an ENOENT spawn error. */
export function ptyProbeArgv(flavor: PtyFlavor): string[] {
  return flavor === "util-linux" ? ["--version"] : ["-q", "/dev/null", "/usr/bin/true"];
}

/** The fstat facts about the wrapper's stdin that decide whether BSD script
 *  can start on it. */
export interface StdinFacts {
  socket: boolean;
  fifo: boolean;
  dev: number;
  nlink: number;
}

/** fstat the wrapper's stdin; null when it cannot be read. */
export function stdinFacts(fd = 0): StdinFacts | null {
  try {
    const s = fstatSync(fd);
    return { socket: s.isSocket(), fifo: s.isFIFO(), dev: s.dev, nlink: s.nlink };
  } catch {
    return null;
  }
}

/**
 * Why the flavor's script(1) cannot start on this stdin, or null when it can.
 * BSD script calls tcgetattr on its stdin and tolerates only ENOTTY. On macOS a
 * socket (node's "pipe" stdio is a socketpair) and a named FIFO (fifofs is
 * built on sockets) fail with EOPNOTSUPP instead, and script exits 1 before
 * the child runs ("script: tcgetattr/ioctl: Operation not supported on
 * socket"). An anonymous pipe (fstat: a FIFO on no device, with no links),
 * /dev/null, a regular file and a TTY all work (measured on macOS 26.5.1,
 * pty-relay.md §3.1). util-linux script is not affected.
 */
export function ptyStdinProblem(flavor: PtyFlavor | null, s: StdinFacts | null): string | null {
  if (flavor !== "bsd" || s === null) return null;
  if (s.socket) return "stdin is a socket, which BSD script(1) cannot start on";
  if (s.fifo && (s.dev !== 0 || s.nlink > 0)) return "stdin is a named FIFO, which BSD script(1) cannot start on";
  return null;
}

/**
 * The PTY relay backend probe. Resolves the platform's `script(1)` flavor and
 * confirms the binary is present and the expected dialect:
 *   - Linux: `script --version` must name util-linux (a stray BSD script on a
 *     Linux box would lack the -e/-c semantics).
 *   - macOS: `/usr/bin/script -q /dev/null /usr/bin/true` must run (exit
 *     status is not asserted: we only need to know the binary exists and
 *     accepts the BSD argv shape). Never a `script` found on PATH.
 * Unsupported platforms (win32, freebsd, …) report not-ok with the reason.
 * `platform` is a param for unit tests; the host-keyed unit test proves the
 * ok-path on whichever platform runs it (macOS 26.5.1 measured, pty-relay.md).
 */
export function ptyRelayAvailable(platform: NodeJS.Platform = process.platform): { ok: boolean; why: string } {
  const flavor = ptyFlavor(platform);
  if (flavor === null) {
    return {
      ok: false,
      why: `platform '${platform}' has no vetted PTY relay backend (Linux util-linux / macOS BSD script only)`,
    };
  }
  try {
    const r = spawnSync(ptyScriptPath(flavor), ptyProbeArgv(flavor), {
      stdio: ["ignore", "pipe", "ignore"],
      timeout: 5000,
    });
    if (r.error) {
      const where = flavor === "bsd" ? `no ${BSD_SCRIPT}` : "no `script` on PATH";
      return { ok: false, why: `${where} (${(r.error as Error).message})` };
    }
    if (flavor === "util-linux") {
      if (r.status === 0 && String(r.stdout).includes("util-linux")) return { ok: true, why: "" };
      return { ok: false, why: "no util-linux `script` on PATH" };
    }
    // bsd: the binary ran the relay argv shape — that is all we need. `true`
    // exits 0; a missing binary already returned above via r.error.
    return { ok: true, why: "" };
  } catch (err) {
    return { ok: false, why: `script(1) probe failed: ${(err as Error).message}` };
  }
}
