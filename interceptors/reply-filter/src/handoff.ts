/**
 * handoff — the early-start form of the reply filter (packaging.md §5.3).
 *
 * The launcher starts this process alongside the session's services, before
 * it knows the agent's final command, so the node start and the module load
 * (about 0.26 s from the bundle, about 1 s from source) leave the launch's
 * critical path. Started as `reply-filter --mandu-handoff-fd=3`, the process
 * loads its modules and then waits on fd 3 (a socket pair the launcher holds)
 * for ONE line of JSON, the hand-off:
 *
 *   {"v":1,"cmd":[…],"outer":[…],"env":{…},"cwd":"…","outputFormat":"text"}
 *
 *   cmd           the command the filter wraps, exactly what followed `--`
 *                 in the serial form (the security wrappers, then the agent);
 *                 the mode decision (print-mode.ts) reads it as before.
 *   outer         the launch scope's prefix (`systemd-run --user --scope …
 *                 --`, or nothing): the filter runs it in front of whatever
 *                 it spawns, so the agent's tree still lands in the scope.
 *   env, cwd      the environment and directory the serial form would have
 *                 started the filter with (the human-plane socket included;
 *                 the filter drops it from its child's env, as before).
 *   outputFormat  the launcher's `--mandu-output-format=` value.
 *
 * The filter answers `ok\n` once the message is valid and applied, closes
 * fd 3 (the agent never inherits the channel), and runs exactly as the
 * serial form would have. Before the hand-off it touches nothing: it reads
 * no terminal, writes nothing, connects to no arbiter.
 *
 * An end of file before a complete line means the launch stopped before its
 * agent started: the filter exits 0, silently. A malformed message gets no
 * `ok` (the launcher then starts a filter the serial way, or runs without
 * one: the filter is a utility surface, and a symbol shown raw leaks nothing).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (the plugin
 * realization had no process to start).
 */

import { Socket } from "node:net";

import type { ReplyOutputFormat } from "./output-format.js";

/** The flag that selects the early-start form. Only fd 3 is supported. */
export const HANDOFF_FLAG = "--mandu-handoff-fd=3";
export const HANDOFF_FD = 3;
/** The acknowledgement line. */
export const HANDOFF_ACK = "ok\n";
/** A hand-off larger than this is refused (an environment is a few KiB). */
export const HANDOFF_MAX_BYTES = 4 * 1024 * 1024;

export interface Handoff {
  cmd: string[];
  outer: string[];
  env: Record<string, string>;
  cwd: string;
  outputFormat: ReplyOutputFormat;
}

const FORMATS: ReadonlySet<string> = new Set(["text", "json", "stream-json", "passthrough"]);

const isStringArray = (v: unknown): v is string[] => Array.isArray(v) && v.every((s) => typeof s === "string");

/** Parse and validate one hand-off line. Throws a plain Error naming what is
 *  wrong. Pure. */
export function parseHandoff(line: string): Handoff {
  let m: unknown;
  try {
    m = JSON.parse(line);
  } catch {
    throw new Error("the hand-off is not JSON");
  }
  if (typeof m !== "object" || m === null) throw new Error("the hand-off is not an object");
  const o = m as Record<string, unknown>;
  if (o["v"] !== 1) throw new Error(`unknown hand-off version ${JSON.stringify(o["v"])}`);
  if (!isStringArray(o["cmd"]) || o["cmd"].length === 0) throw new Error("the hand-off has no command");
  if (!isStringArray(o["outer"])) throw new Error("the hand-off's scope prefix is not a list of strings");
  const env = o["env"];
  if (typeof env !== "object" || env === null || Array.isArray(env) ||
    !Object.values(env as Record<string, unknown>).every((v) => typeof v === "string")) {
    throw new Error("the hand-off's environment is not a map of strings");
  }
  if (typeof o["cwd"] !== "string" || o["cwd"] === "") throw new Error("the hand-off has no directory");
  const fmt = o["outputFormat"];
  if (typeof fmt !== "string" || !FORMATS.has(fmt)) throw new Error(`unknown output format ${JSON.stringify(fmt)}`);
  return {
    cmd: o["cmd"],
    outer: o["outer"],
    env: { ...(env as Record<string, string>) },
    cwd: o["cwd"],
    outputFormat: fmt as ReplyOutputFormat,
  };
}

/** The argv the serial form would have been started with (consumed by
 *  output-format.ts parseReplyInvocation). Pure. */
export function handoffArgv(h: Handoff): string[] {
  return [`--mandu-output-format=${h.outputFormat}`, "--", ...h.cmd];
}

/** Make this process look as the serial form would have been started:
 *  exactly the hand-off's environment, in its directory. `proc` is
 *  injectable for tests. */
export function applyHandoff(h: Handoff, proc: { env: NodeJS.ProcessEnv; chdir(dir: string): void } = process): void {
  proc.chdir(h.cwd);
  for (const k of Object.keys(proc.env)) delete proc.env[k];
  Object.assign(proc.env, h.env);
}

/** The outcome of waiting on the channel: the hand-off, or why there is none. */
export type HandoffWait =
  | { kind: "handoff"; handoff: Handoff }
  | { kind: "aborted" } // end of file before a complete line: the launch stopped
  | { kind: "invalid"; why: string };

/**
 * Wait on `channel` for one hand-off line. On a valid one, run `apply` (which
 * may throw: the hand-off is then invalid), answer HANDOFF_ACK and close the
 * channel before resolving (so no child inherits it); on anything else, close
 * it without an answer. Never rejects.
 */
export function receiveHandoff(channel: Socket, apply: (h: Handoff) => void = () => {}): Promise<HandoffWait> {
  return new Promise((resolve) => {
    let buf = "";
    let done = false;
    const finish = (w: HandoffWait): void => {
      if (done) return;
      done = true;
      channel.removeAllListeners("data");
      if (w.kind !== "handoff") {
        channel.destroy();
        resolve(w);
        return;
      }
      // The answer, then close: destroy() closes the descriptor at once.
      channel.end(HANDOFF_ACK, () => {
        channel.destroy();
        resolve(w);
      });
    };
    channel.setEncoding("utf8");
    channel.on("data", (chunk: string) => {
      buf += chunk;
      if (buf.length > HANDOFF_MAX_BYTES) {
        finish({ kind: "invalid", why: "the hand-off is too large" });
        return;
      }
      const nl = buf.indexOf("\n");
      if (nl < 0) return;
      try {
        const handoff = parseHandoff(buf.slice(0, nl));
        apply(handoff);
        finish({ kind: "handoff", handoff });
      } catch (err) {
        finish({ kind: "invalid", why: (err as Error).message });
      }
    });
    channel.on("end", () => finish({ kind: "aborted" }));
    channel.on("close", () => finish({ kind: "aborted" }));
    channel.on("error", () => finish({ kind: "aborted" }));
  });
}

/** The channel on fd 3. */
export function handoffChannel(fd: number = HANDOFF_FD): Socket {
  return new Socket({ fd, readable: true, writable: true });
}
