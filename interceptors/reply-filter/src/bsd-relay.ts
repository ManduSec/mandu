/**
 * bsd-relay — the macOS companion of the PTY relay: what BSD `script(1)` does
 * not do for the relayed child, done from outside (docs/design/agents/pty-relay.md §3).
 *
 * Mandu user-reply egress chokepoint (interceptors/reply-filter). Mandu-new
 * (no reference origin). UTILITY-ONLY like the rest of the relay: every step
 * here is best-effort and a failure leaves the pre-companion behavior (a TUI
 * that keeps its old size, a signal that goes to script); nothing gates.
 *
 * What BSD script does NOT do (measured on macOS 26.5.1, arm64; pty-relay.md
 * §3.1 has the probes):
 *   - RESIZE: it sizes its pty once, from ITS stdin, when it starts, and never
 *     again: it installs no SIGWINCH handler (the default action is ignore).
 *     util-linux script re-copies the winsize on SIGWINCH; BSD script does
 *     not, so a terminal resize never reached the TUI while the reply-filter's
 *     screen model resized to the real terminal.
 *   - SIGNALS: it has no handler for SIGINT/SIGTERM/SIGHUP either. A signal
 *     sent to script kills script ITSELF: the child only sees the SIGHUP of
 *     the pty master closing, whatever it prints while shutting down (a
 *     TUI's closing lines) is lost with the master, and script never restores
 *     the terminal mode (under the reply-filter, node's exit-time stdio reset
 *     puts it back; a bare `script` leaves the terminal raw).
 *   - EXIT STATUS: script exits with the child's exit code, or with the BARE
 *     signal number when the child died by a signal (WTERMSIG, not 128+n), so
 *     `exit 9` and a SIGKILL death both read 9.
 *
 * What the companion does:
 *   1. LOCATE the relayed child. script forks exactly one child, which calls
 *      login_tty() on the pty slave (a new session with the slave as its
 *      controlling terminal) and execs the command. One process-table
 *      snapshot (`ps -A -o pid=,ppid=,tty=`) names script's child and its
 *      tty. The tty counts only once it differs from script's own: between
 *      fork and login_tty the child still shows script's terminal.
 *   2. RESIZE on request: `stty -f /dev/ttysNNN rows R cols C`, a TIOCSWINSZ
 *      on the slave (a same-user device). When the size changed, the kernel
 *      itself raises SIGWINCH in the slave's foreground process group, the
 *      same signal a terminal emulator's resize raises, so the TUI repaints.
 *      Requests coalesce: one stty in flight, the latest size wins.
 *   3. FORWARD SIGINT/SIGTERM/SIGHUP to the child instead of to script, as
 *      pipe mode forwards them to the agent: the child decides, its last
 *      output still flows, and script exits in order (terminal restored)
 *      with the child's status.
 *   4. MAP the exit status: a code equal to the number of a signal the
 *      companion delivered reads as 128+n (util-linux `script -e`'s
 *      convention). A death by a signal the relay did not deliver (a crash, a
 *      `kill -9` from elsewhere) stays the bare number: it cannot be told
 *      apart from a normal exit with that code, and mapping every small code
 *      would turn a real `exit 1` into 129.
 *
 * Kept apart from run.ts (which runs main() at module load) so tests import
 * this module; the process-facing steps are injected (BsdRelayDeps) and the
 * pure pieces are exported.
 */

import { execFile } from "node:child_process";
import { constants } from "node:os";

/** script's child as one snapshot saw it. `tty` is the slave's device path,
 *  null until login_tty() has run (or when the name is not a pty slave's). */
export interface RelayedChild {
  pid: number;
  tty: string | null;
}

/** A pty slave as macOS `ps -o tty` prints it (`ttys003`); `pts/N` is the
 *  other BSDs' spelling. Anything else (`??`, `console`, a path with `..`) is
 *  never turned into a device path. */
const SLAVE_TTY_RE = /^(?:ttys[0-9]+|pts\/[0-9]+)$/;

/**
 * Find script's child in a `ps -A -o pid=,ppid=,tty=` snapshot. Returns null
 * when script has no child yet (or no longer). The child's tty is reported
 * only when it is a pty slave name that differs from script's own tty: until
 * login_tty() the forked child still carries script's controlling terminal,
 * which is the human's, never the one to resize.
 */
export function parseRelayedChild(psOut: string, scriptPid: number): RelayedChild | null {
  let scriptTty: string | null = null;
  let child: { pid: number; tty: string } | null = null;
  for (const line of psOut.split("\n")) {
    const f = line.trim().split(/\s+/);
    if (f.length < 3) continue;
    const pid = Number(f[0]);
    const ppid = Number(f[1]);
    if (!Number.isSafeInteger(pid) || !Number.isSafeInteger(ppid) || pid <= 0) continue;
    if (pid === scriptPid) scriptTty = f[2]!;
    else if (ppid === scriptPid && child === null) child = { pid, tty: f[2]! };
  }
  if (child === null) return null;
  const usable = SLAVE_TTY_RE.test(child.tty) && child.tty !== scriptTty;
  return { pid: child.pid, tty: usable ? `/dev/${child.tty}` : null };
}

/** The winsize a terminal can carry (struct winsize: unsigned short). */
function winsizeField(n: number): number | null {
  return Number.isInteger(n) && n > 0 && n <= 0xffff ? n : null;
}

/** BSD `stty` argv that sets a tty's size (`-f` names the device; GNU stty
 *  spells it `-F`, but this companion only runs over BSD script). Null when
 *  either dimension is not a valid winsize field. */
export function sttyResizeArgv(dev: string, rows: number, cols: number): string[] | null {
  const r = winsizeField(rows);
  const c = winsizeField(cols);
  if (r === null || c === null) return null;
  return ["-f", dev, "rows", String(r), "cols", String(c)];
}

/** The reply-filter's exit code for a code BSD script exited with: 128+n when
 *  n is the number of a signal the relay delivered to the child (the child
 *  died by it, and script reported the bare number), else the code as is. */
export function relayExitCode(code: number | null, delivered: ReadonlySet<number>): number | null {
  if (code !== null && code > 0 && delivered.has(code)) return 128 + code;
  return code;
}

/** The process-facing steps, injected so unit tests run without a pty. */
export interface BsdRelayDeps {
  /** One process-table snapshot: the stdout of `ps -A -o pid=,ppid=,tty=`. */
  psSnapshot(): Promise<string>;
  /** Set a tty's size; resolves false on any failure (never rejects). */
  setWinsize(dev: string, rows: number, cols: number): Promise<boolean>;
  kill(pid: number, sig: NodeJS.Signals): void;
  sleep(ms: number): Promise<void>;
}

/** How long to keep looking for the child after script starts: script forks
 *  at once, and login_tty() plus exec take a few milliseconds. The waits
 *  before each snapshot, about 2.5 s in all. */
export const LOCATE_WAITS_MS: readonly number[] = [0, 10, 20, 40, 80, 160, 320, 640, 1280];

export class BsdRelayCompanion {
  private child: RelayedChild | null = null;
  private locating: Promise<RelayedChild | null> | null = null;
  private wanted: { cols: number; rows: number } | null = null;
  private pumping = false;
  private disposed = false;
  private readonly delivered = new Set<number>();

  constructor(
    private readonly scriptPid: number,
    private readonly deps: BsdRelayDeps,
    private readonly waits: readonly number[] = LOCATE_WAITS_MS,
  ) {}

  /** Begin locating the child now: the signal path needs its pid at once. */
  start(): void {
    void this.locate();
  }

  /** The child's pid once a snapshot has seen it (tests, diagnostics). */
  get childPid(): number | null {
    return this.child?.pid ?? null;
  }

  /** Resize the relayed child's pty (coalesced; the latest request wins). */
  resize(cols: number, rows: number): void {
    if (this.disposed) return;
    this.wanted = { cols, rows };
    if (!this.pumping) void this.pump();
  }

  /**
   * Deliver `sig` to the relayed child. True when it was sent; false when the
   * child is not known yet or already gone, so the caller signals script
   * instead (the pre-companion behavior).
   */
  signal(sig: NodeJS.Signals): boolean {
    const pid = this.child?.pid;
    if (this.disposed || pid === undefined) return false;
    try {
      this.deps.kill(pid, sig);
    } catch {
      return false;
    }
    const n = constants.signals[sig as keyof typeof constants.signals];
    if (typeof n === "number") this.delivered.add(n);
    return true;
  }

  /** The exit code to report for script's exit code (relayExitCode). */
  exitCode(code: number | null): number | null {
    return relayExitCode(code, this.delivered);
  }

  /** Stop: no snapshot, resize or signal after script is gone (its pty name
   *  and the child's pid are free to be reused from then on). */
  dispose(): void {
    this.disposed = true;
    this.wanted = null;
  }

  /** Poll snapshots on the `waits` schedule until the child's tty is known.
   *  Concurrent callers share one poll; a finished poll that found nothing is
   *  not cached, so a later request polls again. */
  private locate(): Promise<RelayedChild | null> {
    if (this.child?.tty) return Promise.resolve(this.child);
    if (this.locating) return this.locating;
    const poll = async (): Promise<RelayedChild | null> => {
      for (const wait of this.waits) {
        if (wait > 0) await this.deps.sleep(wait);
        if (this.disposed) return null;
        let snapshot: string;
        try {
          snapshot = await this.deps.psSnapshot();
        } catch {
          continue;
        }
        const found = parseRelayedChild(snapshot, this.scriptPid);
        // Keep a pid seen before login_tty (signals need only the pid); a
        // later snapshot without the child means script is on its way out.
        if (found) this.child = found;
        if (found?.tty) return found;
      }
      return null;
    };
    // .finally runs as a microtask, after the assignment below.
    const p: Promise<RelayedChild | null> = poll().finally(() => {
      if (this.locating === p) this.locating = null;
    });
    this.locating = p;
    return p;
  }

  private async pump(): Promise<void> {
    this.pumping = true;
    try {
      while (this.wanted !== null && !this.disposed) {
        const child = await this.locate();
        const want = this.wanted;
        this.wanted = null;
        if (want === null || this.disposed || !child?.tty) continue;
        await this.deps.setWinsize(child.tty, want.rows, want.cols);
      }
    } finally {
      this.pumping = false;
    }
  }
}

/** The real steps: /bin/ps and /bin/stty (macOS base system, named by path so
 *  a PATH entry cannot stand in for them), process.kill, an unref'd timer. */
export function realBsdRelayDeps(): BsdRelayDeps {
  return {
    psSnapshot: () =>
      new Promise((resolve, reject) => {
        execFile("/bin/ps", ["-A", "-o", "pid=,ppid=,tty="], { timeout: 3000, maxBuffer: 8 << 20 }, (err, out) =>
          err ? reject(err) : resolve(String(out)),
        );
      }),
    setWinsize: (dev, rows, cols) =>
      new Promise((resolve) => {
        const argv = sttyResizeArgv(dev, rows, cols);
        if (argv === null) return resolve(false);
        execFile("/bin/stty", argv, { timeout: 3000 }, (err) => resolve(!err));
      }),
    kill: (pid, sig) => {
      process.kill(pid, sig);
    },
    sleep: (ms) =>
      new Promise((resolve) => {
        setTimeout(resolve, ms).unref();
      }),
  };
}
