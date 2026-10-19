/**
 * lifeline — kernel-bound service lifetime (docs/design/architecture/runtime-instances.md §8).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code, duplicated verbatim in
 * each service package (arbiter/ipc, interceptors/{anthropic,openai,net}-proxy/src,
 * fs-sync/src) — the repo's narrow-module convention (no cross-package src
 * imports). Keep the copies in sync.
 *
 * The spawner (launcher services/primitives.startDetachedCmd, or a test
 * harness) passes MANDU_LIFELINE=stdin and holds the ONLY write end of this
 * process's stdin pipe, never writing to it. When the spawner dies — gracefully
 * or by SIGKILL — the kernel closes that end and stdin EOFs here: the owner is
 * gone, so shut down instead of orphaning. This retires the stale-daemon class
 * (2026-07-14) where a detached service's only teardown was an in-memory stop()
 * closure inside a parent that died ungracefully.
 *
 * OPT-IN: absent env (a human's `npm run serve`; the shared arbiter stack,
 * which must OUTLIVE any single launcher) arms nothing. A TTY stdin refuses to
 * arm as a second fence — a leaked env var must not turn the user's Ctrl-D
 * into a daemon kill or put their terminal into flowing mode.
 */

/** The narrow slice of process.stdin the lifeline needs (test-injectable). */
export interface LifelineStream {
  isTTY?: boolean | undefined;
  once(event: "end" | "error", listener: () => void): unknown;
  resume(): unknown;
  unref?(): unknown;
}

/**
 * Arm the lifeline when the spawner asked for it. Returns true when armed.
 * `onSevered` fires AT MOST ONCE, on stdin EOF or a torn pipe — treat it
 * exactly like SIGTERM (run the graceful shutdown path).
 */
export function armLifeline(
  onSevered: () => void,
  env: Record<string, string | undefined> = process.env,
  stdin: LifelineStream = process.stdin,
): boolean {
  if (env["MANDU_LIFELINE"] !== "stdin") return false;
  if (stdin.isTTY) return false;
  let severed = false;
  const sever = (): void => {
    if (severed) return;
    severed = true;
    onSevered();
  };
  stdin.once("end", sever);
  stdin.once("error", sever); // EIO/EPIPE from a dying owner is also "gone"
  stdin.resume(); // start flowing so 'end' can fire
  stdin.unref?.(); // the lifeline must not keep a closing event loop alive
  return true;
}
