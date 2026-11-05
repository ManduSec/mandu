/**
 * box-client — the plugin's side of the box socket (box/host.mjs;
 * docs/design/agents/openclaw-plugin.md §10). Mandu-new (no reference origin).
 *
 * One connection per call, as the host serves them: `prepare` a command for
 * the exec relay (a one-time ticket), run a `shell` script and collect its
 * output (the sandbox handle's runShellCommand), and the file operations of
 * the fs bridge. Every failure is an Error: a call that cannot reach the box
 * never falls back to running anything on the host (fail closed).
 */
import { connect } from "node:net";

import { FrameDecoder, T, chunkFrames, encodeFrame, frameJson } from "../../box/frames.mjs";

/** A failure the box reported (its errno-style code when it gave one). */
export class BoxError extends Error {
  readonly code?: string;
  constructor(message: string, code?: string) {
    super(message);
    this.name = "BoxError";
    if (code !== undefined) this.code = code;
  }
}

export interface ShellResult {
  stdout: Buffer;
  stderr: Buffer;
  code: number;
}

/** One request/answer exchange: the request, optional stdin, and what came back. */
interface Exchange {
  answer: Record<string, unknown> | null;
  data: Buffer;
  stdout: Buffer;
  stderr: Buffer;
  exit: { code: number | null; signal: string | null } | null;
}

export interface BoxClientOptions {
  /** Per-call ceiling (ms). Default 120 s; a script or file call that takes
   *  longer is ended (the host kills what it started). */
  timeoutMs?: number;
}

export class BoxClient {
  constructor(readonly socketPath: string, private readonly opts: BoxClientOptions = {}) {}

  private exchange(request: Record<string, unknown>, stdin?: Buffer, signal?: AbortSignal): Promise<Exchange> {
    return new Promise((resolve, reject) => {
      const out: Exchange = { answer: null, data: Buffer.alloc(0), stdout: Buffer.alloc(0), stderr: Buffer.alloc(0), exit: null };
      const data: Buffer[] = [];
      const so: Buffer[] = [];
      const se: Buffer[] = [];
      let settled = false;
      const sock = connect(this.socketPath);
      const decoder = new FrameDecoder();
      const finish = (err: Error | null): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        signal?.removeEventListener("abort", onAbort);
        sock.destroy();
        if (err) { reject(err); return; }
        out.data = Buffer.concat(data);
        out.stdout = Buffer.concat(so);
        out.stderr = Buffer.concat(se);
        resolve(out);
      };
      const onAbort = (): void => finish(new BoxError("the call was aborted", "ABORT_ERR"));
      if (signal?.aborted) { onAbort(); return; }
      signal?.addEventListener("abort", onAbort, { once: true });
      const timer = setTimeout(() => finish(new BoxError("the box did not answer in time", "ETIMEDOUT")), this.opts.timeoutMs ?? 120_000);
      timer.unref?.();
      sock.on("connect", () => {
        sock.write(encodeFrame(T.REQUEST, request));
        if (stdin !== undefined) {
          for (const f of chunkFrames(T.STDIN, stdin)) sock.write(f);
          sock.write(encodeFrame(T.STDIN_END));
        }
      });
      sock.on("data", (chunk: Buffer) => {
        let frames;
        try { frames = decoder.push(chunk); } catch (e) { finish(new BoxError(`the box sent an unreadable frame (${(e as Error).message})`)); return; }
        for (const f of frames) {
          if (f.type === T.ANSWER) { out.answer = (frameJson(f.payload) as Record<string, unknown>) ?? {}; }
          else if (f.type === T.DATA) data.push(Buffer.from(f.payload));
          else if (f.type === T.STDOUT) so.push(Buffer.from(f.payload));
          else if (f.type === T.STDERR) se.push(Buffer.from(f.payload));
          else if (f.type === T.EXIT) {
            const j = (frameJson(f.payload) ?? {}) as { code?: number | null; signal?: string | null };
            out.exit = { code: typeof j.code === "number" ? j.code : null, signal: typeof j.signal === "string" ? j.signal : null };
          } else if (f.type === T.FAIL) {
            const j = (frameJson(f.payload) ?? {}) as { error?: string; code?: string };
            finish(new BoxError(j.error ?? "the box refused the call", j.code));
            return;
          }
        }
      });
      sock.on("error", (e: NodeJS.ErrnoException) => finish(new BoxError(`Mandu's confined-commands box is not reachable (${e.message})`, e.code)));
      sock.on("close", () => {
        if (out.answer === null && out.exit === null) finish(new BoxError("the box closed the connection without an answer"));
        else finish(null);
      });
    });
  }

  /** Is the host answering? */
  async ping(): Promise<boolean> {
    try {
      const r = await this.exchange({ op: "ping" });
      return r.answer?.["pong"] === true;
    } catch {
      return false;
    }
  }

  /** Prepare a command for the exec relay; the ticket it answers with is good once, for a minute. */
  async prepare(spec: { command: string; cwd?: string; env: Record<string, string>; pty: boolean }): Promise<string> {
    const r = await this.exchange({ op: "prepare", ...spec });
    const ticket = r.answer?.["ticket"];
    if (typeof ticket !== "string" || !/^[0-9a-f]{32}$/.test(ticket)) throw new BoxError("the box gave no ticket for the command");
    return ticket;
  }

  /** Run `script` (`sh -c script mandu-box args…`) in the box and collect it. */
  async shell(p: { script: string; args?: string[]; stdin?: Buffer | string; cwd?: string; signal?: AbortSignal }): Promise<ShellResult> {
    const stdin = p.stdin === undefined ? Buffer.alloc(0) : Buffer.isBuffer(p.stdin) ? p.stdin : Buffer.from(p.stdin, "utf8");
    const r = await this.exchange({ op: "shell", script: p.script, args: p.args ?? [], ...(p.cwd ? { cwd: p.cwd } : {}) }, stdin, p.signal);
    if (r.exit === null) throw new BoxError("the script ended without an exit status");
    const code = r.exit.code ?? 128 + 15;
    return { stdout: r.stdout, stderr: r.stderr, code };
  }

  /** One file operation in the box (host.mjs `fs`). Answers its JSON and any data it sent. */
  async fs(req: Record<string, unknown> & { fsOp: string; root: string }, opts: { data?: Buffer; signal?: AbortSignal } = {}): Promise<{ answer: Record<string, unknown>; data: Buffer }> {
    const r = await this.exchange({ op: "fs", ...req }, opts.data, opts.signal);
    if (r.answer === null) throw new BoxError(`the box gave no answer to ${req.fsOp}`);
    return { answer: r.answer, data: r.data };
  }
}
