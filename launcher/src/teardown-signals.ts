/**
 * teardown-signals — what a signal does to the launcher once the agent has
 * exited and the launcher is tearing down (portable-wrapper.md §2.1
 * "Teardown signals"; differential-interactive.md §21).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin:
 * the plugin realization ran inside its host and had no teardown of its own).
 *
 * The problem. While the agent runs under the reply filter's PTY relay the
 * terminal is raw, so a ^C is a byte for the agent. When the agent quits, the
 * relay's `script(1)` restores cooked mode, and the next ^C is a SIGINT for the
 * terminal's foreground process group: the launcher, which is then stopping
 * the session's services and (under the integrity axis) running the fs-view
 * sweep that brings the agent's AgentView writes into the HumanView. With no
 * handler installed, that SIGINT killed the launcher part-way (exit 130).
 *
 * The policy, per signal, for the teardown window (from the agent's exit to
 * the launcher's return):
 *   - SIGINT: IGNORED, every time. The first ^C prints one line saying why
 *     and how to end it now. There is no "press ^C N times" escape: reflexive
 *     ^C bursts (claude's own ^C-^C quit, OpenCode's) spill into the teardown
 *     and must never count toward cutting the write-back short, and every
 *     teardown step is bounded by its own timeout anyway.
 *   - SIGTERM, SIGHUP, SIGQUIT: the default disposition (no handler), so a
 *     supervisor's SIGTERM, a closed terminal, or a ^\ ends the launcher at
 *     once. The services go with it through their lifelines
 *     (runtime-instances.md §8), and the sweep runs in its own session
 *     (fs-view.ts), so it finishes on its own instead of stopping half-done.
 *
 * The window ends at the process's exit, not at the guard's disarm. The CLI
 * entry (run.ts) exits as soon as its command settles, and removing the last
 * SIGINT listener restores the default action at once, so a guard disarmed
 * before that exit left a last stretch unguarded: main()'s return and
 * process.exit()'s own shutdown (the 'exit' handlers, stopping the module
 * loader's worker, restoring a terminal's modes), tens of milliseconds on a
 * terminal. A ^C landing there killed the launcher 130 after its teardown was
 * done: the `--no-reply-filter` 2-in-10 of differential-interactive.md §21,
 * 5 in 10 under a 30 ms ^C burst (§21.1). The CLI entry therefore calls
 * `holdTeardownGuardsUntilExit()`, after which `disarm()` leaves the handler
 * in place; code that imports main() (the tests) keeps the old disarm.
 *
 * Pure decision logic (`teardownSignalAction`, `teardownSigintNote`) plus a
 * small guard over an injectable signal emitter (`createTeardownGuard`).
 */

/** The signals the teardown policy names. */
export type TeardownSignal = "SIGINT" | "SIGTERM" | "SIGHUP" | "SIGQUIT";

/** `ignore`: a handler swallows it. `default`: no handler, the kernel's
 *  default action (terminate) applies at once, even inside a sync step. */
export type TeardownAction = "ignore" | "default";

/** The teardown policy, per signal. Pure. */
export function teardownSignalAction(sig: TeardownSignal): TeardownAction {
  return sig === "SIGINT" ? "ignore" : "default";
}

/** The line the Nth ignored ^C prints (1-based), or null for every press
 *  after the first: one explanation is enough, repeats would only scroll. */
export function teardownSigintNote(press: number, pid: number): string | null {
  if (press !== 1) return null;
  return (
    "mandu: finishing up after the agent (stopping the session's services); " +
    `^C is ignored until that is done. To end it now: kill ${pid}`
  );
}

/** The slice of `process` the guard needs; tests pass a fake emitter. */
export interface SignalHost {
  on(sig: "SIGINT", fn: () => void): unknown;
  off(sig: "SIGINT", fn: () => void): unknown;
  readonly pid: number;
}

/** Set once by a CLI entry that exits the process as soon as its command
 *  settles (run.ts). Module state on purpose: every guard of that process,
 *  the launch's, the aborted launch's and `mandu demo`'s, follows it. */
let holdUntilExitDefault = false;

/** From now on a guard's `disarm()` leaves its SIGINT handler installed: the
 *  process is about to exit, and the handler must outlive the exit's own
 *  shutdown. Only for an entry that exits right after its command. */
export function holdTeardownGuardsUntilExit(): void {
  holdUntilExitDefault = true;
}

export interface TeardownGuard {
  /** Install the SIGINT handler (idempotent). Call it BEFORE the agent-run
   *  forwarding handlers come off, so SIGINT never has its default action. */
  arm(): void;
  /** Remove it (idempotent), unless the guard holds until the process exits
   *  (`holdUntilExit`): then the handler stays and `armed` stays true. */
  disarm(): void;
  /** The ^C presses swallowed so far. */
  readonly presses: number;
  readonly armed: boolean;
}

export function createTeardownGuard(opts: {
  note: (line: string) => void;
  host?: SignalHost;
  /** Keep the handler past `disarm()` (default: `holdTeardownGuardsUntilExit`
   *  was called). */
  holdUntilExit?: boolean;
}): TeardownGuard {
  const host: SignalHost = opts.host ?? process;
  const hold = opts.holdUntilExit ?? holdUntilExitDefault;
  let presses = 0;
  let armed = false;
  // Only SIGINT gets a handler: teardownSignalAction says the others keep
  // their default action, and installing a handler for them would defer
  // their effect past any synchronous step of the teardown.
  const onSigint = (): void => {
    presses++;
    const line = teardownSigintNote(presses, host.pid);
    if (line !== null) {
      try { opts.note(line); } catch { /* a closed terminal must not end the teardown */ }
    }
  };
  return {
    arm() {
      if (armed) return;
      armed = true;
      host.on("SIGINT", onSigint);
    },
    disarm() {
      if (!armed || hold) return;
      armed = false;
      host.off("SIGINT", onSigint);
    },
    get presses() { return presses; },
    get armed() { return armed; },
  };
}
