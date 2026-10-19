/**
 * exit-flush — exit the CLI only after what it printed has left the process.
 *
 * `process.exit()` drops whatever stdout and stderr still hold. On Linux a
 * pipe is written synchronously, so nothing is held; on macOS a pipe is
 * written asynchronously, and `mandu paths --json | jq` read the first 8 KiB
 * and then a cut-off document (the macOS wrapper suite, 2026-10-09). So the
 * entry waits for each stream's queued writes to finish (a zero-length write
 * whose callback runs after them), then exits. A reader that never reads would
 * hold the exit forever, so the wait is bounded: past `graceMs` the process
 * exits as it did before (development.md, "Developing and testing on macOS").
 */

export interface FlushableStream {
  write(chunk: string, cb: (err?: Error | null) => void): boolean;
  readonly destroyed?: boolean;
}

export interface ExitAfterFlushDeps {
  streams?: FlushableStream[];
  exit?: (code: number) => void;
  /** The longest wait for a reader before exiting anyway (default 5 s). */
  graceMs?: number;
}

export function exitAfterFlush(code: number, deps: ExitAfterFlushDeps = {}): void {
  const exit = deps.exit ?? ((c: number) => process.exit(c));
  const streams = (deps.streams ?? [process.stdout, process.stderr]).filter((s) => !s.destroyed);
  let pending = streams.length;
  let exited = false;
  const finish = (): void => {
    if (exited) return;
    exited = true;
    clearTimeout(timer);
    exit(code);
  };
  const timer = setTimeout(finish, deps.graceMs ?? 5_000);
  if (pending === 0) { finish(); return; }
  for (const s of streams) {
    let counted = false;
    const one = (): void => { if (counted) return; counted = true; if (--pending === 0) finish(); };
    try { s.write("", one); } catch { one(); }
  }
}
