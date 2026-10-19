/**
 * exit-flush.test — the CLI exits only after what it printed has left
 * (src/exit-flush.ts). On macOS a pipe is written asynchronously, and
 * `mandu paths --json` piped to a reader was cut at 8 KiB by process.exit()
 * (the macOS wrapper suite, 2026-10-09). The child-process case is the one
 * that failed there; on Linux a pipe is synchronous, so it passes either way.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { stateAxes } from "../axes.js";
import { exitAfterFlush, type FlushableStream } from "../../src/exit-flush.js";

stateAxes("off");

const LAUNCHER_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

function fakeStream(): FlushableStream & { flush: () => void; writes: number } {
  const cbs: Array<() => void> = [];
  const s = {
    writes: 0,
    write(_chunk: string, cb: () => void) { s.writes++; cbs.push(cb); return false; },
    flush() { for (const cb of cbs.splice(0)) cb(); },
  };
  return s;
}

test("exitAfterFlush: exits only once every stream's queued writes are done, exactly once, with the code", async () => {
  const out = fakeStream(), err = fakeStream();
  const codes: number[] = [];
  exitAfterFlush(3, { streams: [out, err], exit: (c) => codes.push(c), graceMs: 10_000 });
  assert.deepEqual(codes, [], "not before the streams drain");
  out.flush();
  assert.deepEqual(codes, [], "one stream still holds bytes");
  err.flush();
  assert.deepEqual(codes, [3]);
  out.flush();
  assert.deepEqual(codes, [3], "exactly once");
});

test("exitAfterFlush: a reader that never reads holds the exit only for the grace; a destroyed or throwing stream does not hold it", async () => {
  const stuck = fakeStream();
  const codes: number[] = [];
  exitAfterFlush(1, { streams: [stuck], exit: (c) => codes.push(c), graceMs: 50 });
  await new Promise((r) => setTimeout(r, 150));
  assert.deepEqual(codes, [1], "exited past the grace");

  const gone: FlushableStream = { destroyed: true, write: () => { throw new Error("never called"); } };
  const throws: FlushableStream = { write: () => { throw new Error("EPIPE"); } };
  const codes2: number[] = [];
  exitAfterFlush(0, { streams: [gone, throws], exit: (c) => codes2.push(c), graceMs: 10_000 });
  assert.deepEqual(codes2, [0], "nothing to wait for");
});

test("a child that prints 1 MiB to a slow pipe and exits through exitAfterFlush: every byte arrives", { timeout: 60_000 }, async () => {
  const script = [
    `import { exitAfterFlush } from ${JSON.stringify(join(LAUNCHER_ROOT, "src", "exit-flush.ts"))};`,
    `process.stdout.write(JSON.stringify({ pad: "x".repeat(1 << 20) }) + "\\n");`,
    "exitAfterFlush(0);",
  ].join("\n");
  const c = spawn(process.execPath, ["--import", "tsx", "--input-type=module", "-e", script], { cwd: LAUNCHER_ROOT, stdio: ["ignore", "pipe", "inherit"] });
  const chunks: Buffer[] = [];
  // A slow reader: the pipe fills before the child reaches its exit.
  c.stdout.pause();
  setTimeout(() => c.stdout.resume(), 300);
  c.stdout.on("data", (d: Buffer) => chunks.push(d));
  const code = await new Promise<number | null>((r) => c.on("close", r));
  assert.equal(code, 0);
  const text = Buffer.concat(chunks).toString("utf8");
  assert.equal(text.length, (1 << 20) + 11, "the whole document, not a cut-off one");
  assert.equal((JSON.parse(text) as { pad: string }).pad.length, 1 << 20);
});
