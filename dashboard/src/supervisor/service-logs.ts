/**
 * service-logs — the supervisor's per-service log capture (moved out of
 * supervisor.ts, agent-legibility split; no logic change): stdout/stderr
 * line-splitting into the in-memory ring (the live tail the control panel's
 * SSE stream replays), fan-out to live subscribers, the durable per-module
 * `<logDir>/<id>.log` file, and the stderr tail quoted in crash diagnostics.
 * dashboard.md §4.8 "Per-module logging".
 *
 * Mandu-new (NO reference origin). Internal to src/supervisor/; every helper
 * operates on one ServiceRuntime record.
 */

import { type ChildProcess } from "node:child_process";
import { createWriteStream } from "node:fs";
import { resolve } from "node:path";
import { openSafeLog } from "./safe-log.js";

import type { LogLine, ServiceId } from "./supervisor-defs.js";
import type { ServiceRuntime } from "./service-runtime.js";

const MAX_LINE_LEN = 8192;

// ── durable per-module log file ──────────────────────────────────────────────

/**
 * Open (or re-open) the durable `<logDir>/<id>.log` for a service. BEST-EFFORT:
 * any failure (mkdir, open, write) is swallowed — a log-file problem must NEVER
 * throw or break the supervisor. The file is FRESH per dashboard process (first
 * launch this process TRUNCATES with "w"); a later in-process restart APPENDS
 * ("a") so the prior run's output is preserved. `truncatedLogs` is the
 * supervisor's per-process record of which services have been truncated once.
 *
 * Never through something planted (runtime-instances.md §2, "planted paths",
 * 2026-09-30): the default `<logDir>` is `<runtime base>/logs`, which whoever
 * can write the base could fill with links, and this process runs outside
 * the agent's confinement. A plain open with "w" followed a link there and
 * truncated the file it named (a shell startup file, say); "a" appended
 * service output to it. So the file is opened through `safe-log.ts`
 * `openSafeLog` (2026-10-17: every component on its way, not the last one
 * only, so a `logs/` that is a link to a folder gets nothing; a missing
 * directory made one at a time, never `mkdir -p` through a link):
 * O_NOFOLLOW (a link fails the open), O_NONBLOCK (a FIFO without a reader
 * fails it instead of hanging), then a regular file with one link (a FIFO,
 * a device or a hard link to someone's file is refused), truncated only
 * after those checks. A refused file means no durable log, as any other
 * failure here does.
 */
export function openLogFile(
  svc: ServiceRuntime,
  id: ServiceId,
  logDir: string,
  logFilePath: string,
  truncatedLogs: Set<ServiceId>,
): void {
  try {
    const truncate = !truncatedLogs.has(id);
    truncatedLogs.add(id);
    const fd = openSafeLog(resolve(logFilePath), { truncate });
    const stream = createWriteStream(logFilePath, { fd });
    // An async write error (disk full, etc.) must not crash the process.
    stream.on("error", () => {
      /* best-effort logging — never throw */
    });
    stream.write(`==== ${id} started ${new Date().toISOString()} ====\n`);
    svc.logStream = stream;
  } catch {
    svc.logStream = null;
  }
}

/** End the durable stream when the child exits (stop or crash). Its queued
 *  lines still reach the file; `logClosing` resolves when they have. */
export function endLogFile(svc: ServiceRuntime): void {
  const stream = svc.logStream;
  svc.logStream = null;
  if (stream === null) return;
  const closing: Promise<void> = new Promise((resolve) => {
    stream.once("close", () => resolve());
    stream.once("error", () => resolve());
  });
  svc.logClosing = closing;
  void closing.then(() => {
    if (svc.logClosing === closing) svc.logClosing = null;
  });
  stream.end();
}

/**
 * Resolves once every line pushed so far is in the durable file. A line
 * reaches the ring (the live view) synchronously and the file through the
 * stream's asynchronous writes, so a read of the file right after the ring
 * showed a line could miss it: the "full log" then lacked the line the
 * fold had just shown (CI pipeline 11021, a loaded guest). The stream
 * writes in order, so an empty write's callback runs after every line
 * before it; an ended stream is waited for until it closes. Bounded by
 * `timeoutMs` (a disk that does not answer must not hold the reader), and
 * never rejects: the log file is best-effort.
 */
export function logFileWritten(svc: ServiceRuntime, timeoutMs: number): Promise<void> {
  const stream = svc.logStream;
  const written: Promise<void> | null = stream?.writable
    ? new Promise((resolve) => { stream.write("", () => resolve()); })
    : svc.logClosing;
  if (written === null) return Promise.resolve();
  return new Promise((resolve) => {
    const timer = setTimeout(resolve, timeoutMs);
    timer.unref?.();
    void written.then(() => { clearTimeout(timer); resolve(); });
  });
}

// ── log ring buffer ─────────────────────────────────────────────────────────

export function wireLogs(svc: ServiceRuntime, child: ChildProcess, logRingMax: number): void {
  const onChunk = (stream: "stdout" | "stderr") => (buf: Buffer) => {
    ingest(svc, stream, buf.toString("utf8"), logRingMax);
  };
  child.stdout?.on("data", onChunk("stdout"));
  child.stderr?.on("data", onChunk("stderr"));
}

function ingest(svc: ServiceRuntime, stream: "stdout" | "stderr", chunk: string, logRingMax: number): void {
  const combined = svc.carry[stream] + chunk;
  const parts = combined.split("\n");
  // Last element is an incomplete fragment (no trailing newline yet).
  svc.carry[stream] = parts.pop() ?? "";
  for (const raw of parts) {
    // Trim a trailing CR (CRLF terminators).
    const line = raw.endsWith("\r") ? raw.slice(0, -1) : raw;
    pushLine(svc, stream, line, logRingMax);
  }
}

function pushLine(svc: ServiceRuntime, stream: "stdout" | "stderr", lineRaw: string, logRingMax: number): void {
  const line = lineRaw.length > MAX_LINE_LEN ? lineRaw.slice(0, MAX_LINE_LEN) : lineRaw;
  const entry: LogLine = { ts: Date.now(), stream, line };
  svc.ring.push(entry);
  if (svc.ring.length > logRingMax) {
    svc.ring.splice(0, svc.ring.length - logRingMax);
  }
  // Also append to the durable per-module log file (best-effort; the writable
  // guard skips a closed/never-opened stream so this never throws).
  if (svc.logStream?.writable) {
    svc.logStream.write(`${new Date(entry.ts).toISOString()} [${stream}] ${line}\n`);
  }
  for (const cb of svc.subscribers) {
    try {
      cb(entry);
    } catch {
      /* a misbehaving subscriber must not break logging */
    }
  }
}

/** Last few stderr lines for crash diagnostics. */
export function tailStderr(svc: ServiceRuntime, n = 5): string {
  const lines = svc.ring
    .filter((l) => l.stream === "stderr")
    .slice(-n)
    .map((l) => l.line);
  return lines.join("\n");
}
