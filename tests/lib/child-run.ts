/**
 * child-run — spawn a real agent CLI (claude / codex / the launcher) and wait
 * for its EXIT without ever letting its descendants hang the test runner.
 *
 * Mandu (tests/). NEW code, no reference origin.
 *
 * WHY: every live suite used to `spawn(...)` and await the child's "close"
 * event. "close" fires only after BOTH the process exits AND its stdio pipes
 * reach EOF — and the pipe write-ends are INHERITED by the child's
 * descendants (Claude Code's MCP servers, model-run `cmd &` backgrounds, the
 * codex sandbox). A descendant that outlives the child holds the write-ends
 * open, so:
 *   - a clean `claude` exit burned the whole child-timeout and was then
 *     misreported as "timed out" even though the run succeeded;
 *   - the runner's pipe fds (unix socketpairs under libuv) stayed active
 *     FOREVER, so the node:test runner process never exited — the hung-runner
 *     zombie class (observed live 2026-07-11: the last runner held ~7 leaked
 *     unix sockets for 7.5h after all tests finished; the TAP epilogue never
 *     printed). The interactive driver fixed the same class for its PTY tree
 *     (interactive-driver.ts killTree); this helper is the headless dual.
 *
 * HOW: the child is spawned DETACHED (its own process group). We resolve on
 * "exit" — at that point every byte the child itself wrote is already in the
 * pipe buffers and flowing to our data handlers — giving "close" a short
 * grace to fire naturally (the clean path), then SIGKILL the whole process
 * group and destroy our pipe read-ends so no orphan can hold the event loop.
 * On timeout the group is killed the same way and the promise REJECTS (the
 * same contract the inline spawns had).
 */

import { spawn } from "node:child_process";

export interface ChildRunOpts {
  cwd: string;
  env: Record<string, string | undefined>;
  /** Hard deadline: the process GROUP is SIGKILLed and the promise rejects. */
  timeoutMs: number;
  /** Name used in errors/diagnostics, e.g. "claude" / "codex". */
  label: string;
  /** How long after "exit" to wait for "close" (stdio EOF) before force-
   *  reaping the group and settling anyway. Default 2000ms — the child's own
   *  output has already been buffered/delivered by exit time; only a
   *  descendant still holding the write-ends keeps "close" from firing. */
  closeGraceMs?: number;
}

export interface ChildRunResult {
  /** The child's exit code; -1 when it died on a signal. */
  code: number;
  stdout: string;
  stderr: string;
}

/**
 * Run `cmd argv` to process EXIT (stdin ignored, stdout/stderr captured).
 * Resolves with {code, stdout, stderr}; rejects on spawn error or timeout.
 * ALWAYS reaps the child's whole process group before settling, so no
 * descendant survives to hold pipes (the runner's event loop) or the box.
 */
export function runChildToExit(
  cmd: string,
  argv: string[],
  opts: ChildRunOpts,
): Promise<ChildRunResult> {
  const child = spawn(cmd, argv, {
    cwd: opts.cwd,
    env: opts.env,
    stdio: ["ignore", "pipe", "pipe"],
    // Own process group: the whole tree is killable in one signal, and killing
    // it can never touch the runner or its siblings.
    detached: true,
  });
  let stdout = "";
  let stderr = "";
  child.stdout!.on("data", (c) => (stdout += c));
  child.stderr!.on("data", (c) => (stderr += c));

  /** SIGKILL the child's group + release our pipe read-ends: descendants can
   *  neither survive the run nor hold the runner's event loop. */
  const reapTree = (): void => {
    try {
      process.kill(-child.pid!, "SIGKILL");
    } catch {
      /* group already empty */
    }
    child.stdout?.destroy();
    child.stderr?.destroy();
  };

  return new Promise<ChildRunResult>((resolve, reject) => {
    let closeGrace: NodeJS.Timeout | undefined;
    const deadline = setTimeout(() => {
      reapTree();
      const tail = (s: string): string => (s.length > 400 ? `…${s.slice(-400)}` : s);
      reject(
        new Error(
          `${opts.label} timed out after ${Math.round(opts.timeoutMs / 1000)}s` +
            (stdout || stderr
              ? `; stdout: ${JSON.stringify(tail(stdout))}; stderr: ${JSON.stringify(tail(stderr))}`
              : ""),
        ),
      );
    }, opts.timeoutMs);
    const settle = (code: number): void => {
      clearTimeout(deadline);
      if (closeGrace) clearTimeout(closeGrace);
      reapTree();
      resolve({ code, stdout, stderr });
    };
    child.once("error", (e) => {
      clearTimeout(deadline);
      if (closeGrace) clearTimeout(closeGrace);
      reapTree();
      reject(e);
    });
    // The clean path: exit + stdio EOF (no descendant held the pipes).
    child.once("close", (c) => settle(c ?? -1));
    // "exit" without "close" means a descendant still holds the stdio
    // write-ends; give "close" the grace, then force-settle.
    child.once("exit", (c) => {
      closeGrace = setTimeout(() => settle(c ?? -1), opts.closeGraceMs ?? 2000);
    });
  });
}
