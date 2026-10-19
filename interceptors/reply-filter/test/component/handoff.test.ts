/**
 * handoff.test (component) — the REAL wrapper (src/run.ts under tsx) in its
 * early-start form (src/handoff.ts, packaging.md §5.3), spawned the way the
 * launcher spawns it: `run.ts --mandu-handoff-fd=3` with a socket pair on
 * fd 3, against a real Unix-socket mock arbiter on the HUMAN plane.
 *
 *   (a) before the hand-off it touches nothing (no arbiter connection, no
 *       output); handed a command, it answers, runs the scope prefix in
 *       front of the command, and the human sees the RAW value; the agent's
 *       env has no human socket and the agent holds no fd 3; the exit code
 *       propagates.
 *   (b) an end of file before any hand-off (the launch stopped): it exits 0,
 *       silently, and runs nothing.
 *   (c) a malformed hand-off: no answer, exit 2, nothing runs.
 *   (d) PTY RELAY through the hand-off (host script backend): the agent sees a
 *       TTY inside the scope prefix and the reply still resolves.
 * Mandu-new (no reference origin).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server, type Socket } from "node:net";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { HANDOFF_ACK, HANDOFF_FLAG } from "../../src/handoff.js";
import { ptyRelayAvailable } from "../../src/pty-relay.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

const PKG_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const RUN_TS = join(PKG_ROOT, "src", "run.ts");
const TSX_ESM = join(PKG_ROOT, "node_modules", "tsx", "dist", "esm", "index.mjs");

const SYM = "$MDU:Read[c0de]";
const RAW = "the original value";

function mockArbiter(path: string): { server: Server; connections: () => number } {
  let n = 0;
  const server = createServer((c: Socket) => {
    n++;
    let buf = "";
    c.setEncoding("utf8");
    c.on("data", (chunk: string) => {
      buf += chunk;
      let nl: number;
      while ((nl = buf.indexOf("\n")) >= 0) {
        const req = JSON.parse(buf.slice(0, nl)) as { id: number; op: string; text?: string };
        buf = buf.slice(nl + 1);
        const result = req.op === "desymbolize" ? { text: (req.text ?? "").split(SYM).join(RAW) } : { seq: 1 };
        c.write(JSON.stringify({ id: req.id, ok: true, result }) + "\n");
      }
    });
  });
  server.listen(path);
  return { server, connections: () => n };
}

interface Started {
  child: ReturnType<typeof spawn>;
  channel: Socket;
  out: () => string;
  err: () => string;
  answer: () => string;
  closed: Promise<number | null>;
}

/** Spawn the real filter in its early form, stdout/stderr captured. */
function startEarly(env: Record<string, string | undefined>): Started {
  const child = spawn(process.execPath, ["--import", TSX_ESM, RUN_TS, HANDOFF_FLAG], {
    env: { ...process.env, MANDU_ARBITER_HUMAN_SOCK: undefined, MANDU_ARBITER_SOCK: undefined, MANDU_SCOPE_ID: undefined, ...env },
    stdio: ["ignore", "pipe", "pipe", "pipe"],
  });
  let out = "";
  let err = "";
  let answer = "";
  child.stdout!.setEncoding("utf8").on("data", (c: string) => (out += c));
  child.stderr!.setEncoding("utf8").on("data", (c: string) => (err += c));
  const channel = child.stdio[3] as Socket;
  channel.on("error", () => {});
  channel.setEncoding("utf8").on("data", (c: string) => (answer += c));
  const closed = once(child, "close").then(([code]) => code as number | null);
  return { child, channel, out: () => out, err: () => err, answer: () => answer, closed };
}

/** A stand-in scope prefix: records that it ran, then execs the rest. */
function outerWrapper(dir: string): string {
  const p = join(dir, "outer.sh");
  writeFileSync(p, `#!/bin/bash\necho outer >> "${join(dir, "outer.trace")}"\n[ "$1" = "--" ] && shift\nexec "$@"\n`, { mode: 0o700 });
  return p;
}

/** The agent: prints the symbol; records its env and whether fd 3 is open. */
const AGENT = [
  "bash", "-c",
  'echo "human-sock=${MANDU_ARBITER_HUMAN_SOCK:-unset}" > "$EVIDENCE"; ' +
  'if [ -e /proc/$$/fd/3 ]; then echo fd3=open >> "$EVIDENCE"; else echo fd3=closed >> "$EVIDENCE"; fi; ' +
  'if [ -t 1 ]; then echo TTY-YES; else echo TTY-NO; fi; echo "Reply: $SYMBOL"; exit 7',
];

function setup(): { dir: string; sock: string; arb: ReturnType<typeof mockArbiter>; done: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "mandu-rf-handoff-"));
  const sock = join(dir, "human.sock");
  const arb = mockArbiter(sock);
  return { dir, sock, arb, done: () => { arb.server.close(); rmSync(dir, { recursive: true, force: true }); } };
}

function handoffEnv(dir: string, sock: string, extra: Record<string, string> = {}): Record<string, string> {
  const env: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) if (v !== undefined && !k.startsWith("MANDU_")) env[k] = v;
  return { ...env, MANDU_ARBITER_HUMAN_SOCK: sock, SYMBOL: SYM, EVIDENCE: join(dir, "evidence"), ...extra };
}

test("(a) waits untouched, then runs the scope prefix + command handed to it; the reply resolves; nothing leaks to the agent", async () => {
  const { dir, sock, arb, done } = setup();
  try {
    const f = startEarly({});
    // Loaded and waiting (a generous wait on a loaded host): nothing seen yet.
    await new Promise((r) => setTimeout(r, 1500));
    assert.equal(f.child.exitCode, null, `still waiting: ${f.err()}`);
    assert.equal(arb.connections(), 0, "no arbiter connection before the hand-off");
    assert.equal(f.out(), "", "no output before the hand-off");
    const outer = outerWrapper(dir);
    f.channel.write(JSON.stringify({ v: 1, cmd: AGENT, outer: [outer, "--"], env: handoffEnv(dir, sock), cwd: dir, outputFormat: "text" }) + "\n");
    const code = await f.closed;
    assert.equal(f.answer(), HANDOFF_ACK, "it answered the hand-off");
    assert.equal(code, 7, `the agent's exit code propagates; stderr: ${f.err()}`);
    assert.match(f.out(), new RegExp(`Reply: ${RAW}`), `resolved; got ${JSON.stringify(f.out())}`);
    assert.ok(!f.out().includes("$MDU:"), "no token reached the human");
    assert.match(f.out(), /TTY-NO/, "a pipe here: pipe mode, as the serial form decides");
    assert.ok(arb.connections() >= 1, "resolved over the human socket after the hand-off");
    assert.equal(readFileSync(join(dir, "outer.trace"), "utf8"), "outer\n", "the scope prefix ran, once, in front of the command");
    const evidence = readFileSync(join(dir, "evidence"), "utf8");
    assert.match(evidence, /human-sock=unset/, "the agent never inherits the human socket");
    assert.match(evidence, /fd3=closed/, "the agent never inherits the hand-off channel");
  } finally { done(); }
});

test("(b) an end of file before any hand-off: exit 0, silent, nothing runs", async () => {
  const { dir, done } = setup();
  try {
    const f = startEarly({});
    await new Promise((r) => setTimeout(r, 300));
    f.channel.end();
    assert.equal(await f.closed, 0);
    assert.equal(f.out(), "");
    assert.equal(f.err(), "");
    assert.equal(existsSync(join(dir, "evidence")), false);
  } finally { done(); }
});

test("(c) a malformed hand-off: no answer, exit 2, nothing runs", async () => {
  const { dir, sock, done } = setup();
  try {
    const f = startEarly({});
    f.channel.write(JSON.stringify({ v: 1, cmd: AGENT, outer: [], env: handoffEnv(dir, sock), cwd: dir, outputFormat: "yaml" }) + "\n");
    assert.equal(await f.closed, 2);
    assert.equal(f.answer(), "");
    assert.match(f.err(), /refused the launcher's hand-off: unknown output format/);
    assert.equal(existsSync(join(dir, "evidence")), false);
  } finally { done(); }
});

const SCRIPT = ptyRelayAvailable();

test("(d) PTY relay through the hand-off: the agent has a TTY inside the scope prefix; the reply resolves", { skip: SCRIPT.ok ? false : SCRIPT.why }, async () => {
  const { dir, sock, done } = setup();
  try {
    const f = startEarly({});
    const outer = outerWrapper(dir);
    f.channel.write(JSON.stringify({
      v: 1, cmd: AGENT, outer: [outer, "--"], env: handoffEnv(dir, sock, { MANDU_REPLY_FILTER_PTY: "1" }), cwd: dir, outputFormat: "text",
    }) + "\n");
    const code = await f.closed;
    assert.equal(code, 7, `exit code through the host script backend; stderr: ${f.err()}`);
    // The relay paints a value with autowrap off around it (\x1b[?7l … \x1b[?7h).
    const shownText = f.out().replace(/\x1b\[[?0-9;]*[A-Za-z]/g, "");
    assert.match(shownText, /TTY-YES/);
    assert.match(shownText, new RegExp(`Reply: ${RAW}`));
    assert.ok(!f.out().includes("$MDU:"));
    assert.equal(readFileSync(join(dir, "outer.trace"), "utf8"), "outer\n");
    assert.match(readFileSync(join(dir, "evidence"), "utf8"), /human-sock=unset\nfd3=closed/);
  } finally { done(); }
});
