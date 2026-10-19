/**
 * run.test — E2E tests for the user-reply egress CLI (src/run.ts), spawned as a
 * real process against a real Unix-domain-socket mock arbiter.
 *
 * The unit tests (test/unit/filter.test.ts) drive the pure stream core with an
 * in-memory resolver. These e2e tests close the gap to the process boundary:
 * they launch the ACTUAL wrapper entrypoint (src/run.ts under tsx, the same way
 * `npm run filter` / the launcher runs it) wrapping a real child process, and
 * assert on the observable contract — stdout content, exit-code propagation,
 * and the DEGRADE-TO-PASSTHROUGH posture.
 *
 * Mirrors the exec-wrap e2e idiom (test/component/wrap.test.ts): a real NDJSON server
 * over a real socket + assertions on observable side effects.
 *
 * Scenarios:
 *   (a) arbiter up, agent prints a symbol      → stdout carries the RAW value;
 *                                                a `desymbolize` event was emitted.
 *   (b) arbiter up, exit code                  → the child's non-zero exit code
 *                                                propagates through the wrapper.
 *   (c) MANDU_ARBITER_HUMAN_SOCK → dead     → PASSTHROUGH: the symbol stays
 *                                                OPAQUE in stdout, exit code still
 *                                                propagates (utility-only degrade).
 *   (d) MANDU_ARBITER_HUMAN_SOCK unset       → PASSTHROUGH, same contract.
 *   (k) ONLY the data socket set (it would    → PASSTHROUGH: never a fallback to
 *       even answer desymbolize)                  the data socket
 *                                                (docs/design/architecture/arbiter-human-plane.md).
 *   (l) the wrapped child's env never carries MANDU_ARBITER_HUMAN_SOCK, in the
 *       filtered and the passthrough spawn alike.
 *   (u) the child dies by a signal           → the wrapper dies by it too (the
 *                                                parent sees 128+n), its own
 *                                                forwarder no longer swallowing it.
 *   (v) macOS, PTY forced, a socket stdin    → BSD script cannot start on it:
 *                                                PASSTHROUGH, the child still runs.
 *   (i) PTY RELAY, ALTERNATE SCREEN: a fake fullscreen TUI paints a token in
 *       PIECES around a cursor jump (the cell-diff shape the stream filter
 *       cannot glue — differential-interactive.md §17); the screen reconciler
 *       (src/screen-reconcile.ts) reads it back off the screen and repaints
 *       the value in place while the child is alive; rendering the wrapper's
 *       whole output through a headless terminal shows the value, no token.
 *   (j) PTY RELAY, ALTERNATE SCREEN, TAB IN THE VALUE: the same split shape
 *       with a value carrying a TAB; the human's screen shows the tab expanded
 *       to the terminal's next 8-column tab stop (what a vanilla terminal
 *       shows for the raw value at that column), and no raw TAB byte from the
 *       value ever reaches the wire (differential-interactive.md §19).
 *   (k)/(l) PTY RELAY, RESERVE BLOCKS (docs/design/ui/reply-row-reservation.md
 *       §3.7): a fake inline (main screen) and a fake fullscreen TUI paint
 *       the phase-0 reserve block, then a cell-diff re-layout frame whose
 *       marker rows go out as fragments; on the rendered screen row i reads
 *       line i of the value, and the relay reported `pty` + `reserve: true`.
 *   (m)/(n) the relay report under the kill switch (reserve off) and in pipe
 *       mode (reserve off; a block that arrives anyway prints the full value).
 *   (o)/(p) PTY RELAY, V2 BLOCKS (reply-row-reservation.md §11): a one-line
 *       value wider than the 80-column terminal fills its reserved rows
 *       (78 + 42, no clip; the relay reported `wrap: true`), and a block
 *       inside a sentence (prefix before the head, suffix after the last
 *       row) survives its cell-diff re-layout.
 *   (r) PTY RELAY, ALTERNATE SCREEN, the echo-fidelity-long capture
 *       (differential-interactive.md §19.1): a re-layout whose cell diff
 *       writes `$MDU/`, jumps a cell and writes the rest of the marker; no
 *       `$MDU` byte ever reaches the wrapper's stdout, and every row reads its
 *       line ((i) and (l) assert the same of their streams). (r2) a token
 *       the arbiter does not know, on a TUI that then goes quiet: masked on
 *       the wire, restored by the idle drain's reconcile, never left blank.
 *   (t) PTY RELAY, MAIN SCREEN, the CI capture of Claude Code 2.1.273's
 *       inline renderer (differential-interactive.md §30): a tool's live
 *       output paints a token over `Running…` by cell diff (`$MDU:` CHA
 *       `omodel_Read[5ccd]`); no `$MDU` byte reaches the wrapper's stdout and
 *       the row reads the value.
 *   (u) PTY RELAY, both screens, the first-session tour's shape (Claude
 *       Code 2.1.289): a value NARROWER than its token, quoted
 *       `STRIPE_KEY='<token>'` with a CHA-addressed word after it, reads
 *       `STRIPE_KEY='<value>'` with no padding inside the line (screen-
 *       reconcile.ts CLOSE UP), and the desymbolize event's original carries
 *       no pad either.
 *   (w) PTY RELAY, MAIN SCREEN, Goose 1.53's reply reads (differential-
 *       interactive.md §32): a reserve head its Markdown streamer restyled
 *       at the `_`, over two reads; the block reads the value's lines, no
 *       `/1:N:W:F` and no `$MDU` on the human's terminal stream.
 *   (q) the PASSTHROUGH relay report goes over the HUMAN socket only (the op
 *       is human-plane; the data socket gets the health event at most).
 *   (e)–(h) PTY RELAY (MANDU_REPLY_FILTER_PTY=1; util-linux script on Linux,
 *       BSD script on macOS; skipped where the host has neither): the child
 *       sees a REAL TTY on stdout while the relayed session is still
 *       desymbolized; exit codes propagate through script; a
 *       prompt with NO trailing newline resolves via the idle flush WHILE the
 *       child is still alive (the TUI screen never freezes); and a token the
 *       "TUI" hard-wraps mid-token (newline + continuation indent) is
 *       aggressively reassembled and resolved.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server, type Socket } from "node:net";
import { spawn } from "node:child_process";
import * as xtermHeadlessNs from "@xterm/headless";
import { once } from "node:events";
import { mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import {
  BT,
  BV,
  shown,
  INLINE_FIRST_PAINT,
  INLINE_RELAYOUT,
  FULLSCREEN_FIRST_PAINT,
  KT,
  KV,
  KEY_FIRST_PAINT,
  MT,
  MV,
  MID_FIRST_PAINT,
  MID_RELAYOUT,
  MID_SCREEN,
  LONG_FIRST_PAINT,
  LONG_LINES,
  LONG_SCROLL_RELAYOUT,
  LONG_TOKEN,
  LONG_VALUE,
} from "../unit/reserve-fixtures.js";
import { SPLIT_AFTER, SPLIT_FRAME, SPLIT_ROW, SPLIT_SETUP, SPLIT_TOKEN, SPLIT_VALUE } from "../unit/inline-split-fixtures.js";
import { GOOSE_HEAD_TOKEN, GOOSE_REPLY_READS, GOOSE_REPLY_SCREEN, GOOSE_ROWS_VALUE } from "../unit/goose-fixtures.js";
import { formatBlock } from "../../src/reserve-block.js";
import { stateAxes } from "../axes.js";
import { ptyRelayAvailable } from "../../src/pty-relay.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

const HERE = dirname(fileURLToPath(import.meta.url));
/** interceptors/reply-filter (this package root). */
const PKG_ROOT = join(HERE, "..", "..");
/** The wrapper entrypoint we spawn. */
const RUN_TS = join(PKG_ROOT, "src", "run.ts");
/** This package's local tsx binary (see exec-wrap e2e for why not `npx tsx`). */
const TSX_BIN = join(PKG_ROOT, "node_modules", ".bin", "tsx");

const SYM = "$MDU:Read[9b0a]";
const RAW = "# Project notes — TODO: ship the proxy.";
/** A second symbol whose value carries a TAB (case (j)). */
/** The first-session tour's shape (u): a value NARROWER than its token. */
const CLOSE_SYM = "$MDU:nomodel_Read[5c6e].STRIPE_KEY";
const CLOSE_RAW = "sk_live_fake_123456";
const TAB_SYM = "$MDU:Read[7ab1]";
const TAB_RAW = "key\tvalue";
/** A value far WIDER than the rest of its row (x): a real Stripe secret key
 *  is 107 columns; this stand-in is 111. */
const WIDE_SYM = "$MDU:nomodel_Read[aad5].STRIPE_SECRET_KEY";
const WIDE_RAW = `wide-value-${"0123456789".repeat(10)}`;

/**
 * A real Unix-domain-socket NDJSON mock arbiter (mirrors arbiter/ipc wire
 * format: `{id, op, ...}` per line → `{id, ok, result}` per line). Answers the
 * two ops the reply filter uses: `desymbolize` (replace the known symbol) and
 * `emit` (record the event, return a seq).
 */
function startMockArbiter(sockPath: string): { server: Server; emitted: unknown[]; relays: Array<Record<string, unknown>> } {
  const emitted: unknown[] = [];
  const relays: Array<Record<string, unknown>> = [];
  const server = createServer((c: Socket) => {
    let buf = "";
    c.setEncoding("utf8");
    c.on("data", (chunk: string) => {
      buf += chunk;
      let nl: number;
      while ((nl = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        if (line.trim() === "") continue;
        const req = JSON.parse(line) as { id: number | string; op: string; text?: string; event?: unknown };
        let result: unknown;
        if (req.op === "desymbolize") {
          result = {
            text: (req.text ?? "").split(SYM).join(RAW).split(TAB_SYM).join(TAB_RAW).split(BT).join(BV)
              .split(KT).join(KV).split(MT).join(MV).split(LONG_TOKEN).join(LONG_VALUE).split(SPLIT_TOKEN).join(SPLIT_VALUE)
              .split(CLOSE_SYM).join(CLOSE_RAW).split(GOOSE_HEAD_TOKEN).join(GOOSE_ROWS_VALUE)
              .split(WIDE_SYM).join(WIDE_RAW),
          };
        } else if (req.op === "emit") {
          emitted.push(req.event);
          result = { seq: emitted.length };
        } else if (req.op === "setSessionRelay") {
          // The relay report (reply-row-reservation.md §3.6): recorded as sent.
          const { id: _id, op: _op, ...args } = req as Record<string, unknown>;
          relays.push(args);
          result = {};
        } else {
          result = {};
        }
        c.write(JSON.stringify({ id: req.id, ok: true, result }) + "\n");
      }
    });
  });
  server.listen(sockPath);
  return { server, emitted, relays };
}

interface RunResult {
  code: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
}

/** Spawn the wrapper CLI around a child command; collect stdout/stderr/code.
 *  `stdin` "pipe" gives the wrapper node's socketpair stdin (default: none). */
async function runFilter(
  cmd: string[],
  env: Record<string, string | undefined>,
  stdin: "ignore" | "pipe" = "ignore",
): Promise<RunResult> {
  const child = spawn(TSX_BIN, [RUN_TS, "--", ...cmd], {
    env: { ...process.env, MANDU_ARBITER_SOCK: undefined, MANDU_ARBITER_HUMAN_SOCK: undefined, MANDU_SCOPE_ID: undefined, ...env },
    stdio: [stdin, "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  child.stdout!.setEncoding("utf8");
  child.stderr!.setEncoding("utf8");
  child.stdout!.on("data", (c: string) => (stdout += c));
  child.stderr!.on("data", (c: string) => (stderr += c));
  const [code, signal] = (await once(child, "close")) as [number | null, NodeJS.Signals | null];
  return { code, signal, stdout, stderr };
}

test("(a) symbol in the agent's reply → the human sees the RAW value + a desymbolize event", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-replyfilter-"));
  const sock = join(dir, "arbiter.sock");
  const { server, emitted } = startMockArbiter(sock);
  try {
    const r = await runFilter(
      ["node", "-e", `console.log("Summary: ${SYM.replace(/\$/g, "\\$")}")`],
      { MANDU_ARBITER_HUMAN_SOCK: sock, MANDU_SCOPE_ID: "reply-e2e" },
    );
    assert.equal(r.code, 0);
    assert.equal(r.stdout, `Summary: ${RAW}\n`);
    assert.ok(!r.stdout.includes("$MDU:"), "no opaque token reaches the human");
    // The observability event landed (best-effort, but the mock is up).
    // Two events: the session-health `relay_mode` record first (which mode
    // THIS terminal got — pipe here), then the desymbolize the resolve made.
    assert.equal(emitted.length, 2);
    const mode = emitted[0] as { kind: string; mode: string; emitter: string };
    assert.equal(mode.kind, "relay_mode");
    assert.equal(mode.mode, "pipe");
    assert.equal(mode.emitter, "reply-filter");
    const ev = emitted[1] as { kind: string; sessionId: string; emitter: string; view: string; input: { symbolized: string }; output: { symbolized: string; original: string } };
    assert.equal(ev.kind, "desymbolize");
    assert.equal(ev.sessionId, "reply-e2e");
    assert.equal(ev.emitter, "reply-filter");
    assert.equal(ev.view, "HumanView");
    // Its AgentView form is the placeholder the reply named, never the reply
    // (the signed-out projection keeps every `symbolized`, dashboard.md §6);
    // what the human saw is its original.
    assert.equal(ev.input.symbolized, SYM);
    assert.equal(ev.output.symbolized, SYM);
    assert.equal(ev.output.original, `Summary: ${RAW}\n`);
  } finally {
    server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("(b) the child's non-zero exit code propagates through the wrapper", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-replyfilter-"));
  const sock = join(dir, "arbiter.sock");
  const { server } = startMockArbiter(sock);
  try {
    const r = await runFilter(
      ["node", "-e", `console.log("partial ${SYM.replace(/\$/g, "\\$")}"); process.exit(3)`],
      { MANDU_ARBITER_HUMAN_SOCK: sock },
    );
    assert.equal(r.code, 3);
    // Output was still filtered before the exit propagated.
    assert.equal(r.stdout, `partial ${RAW}\n`);
  } finally {
    server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("(c) DEAD socket → PASSTHROUGH: symbol stays opaque, exit code still propagates", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-replyfilter-"));
  const deadSock = join(dir, "nothing-listens-here.sock");
  try {
    const r = await runFilter(
      ["node", "-e", `console.log("Summary: ${SYM.replace(/\$/g, "\\$")}"); process.exit(5)`],
      { MANDU_ARBITER_HUMAN_SOCK: deadSock },
    );
    assert.equal(r.code, 5);
    assert.ok(r.stdout.includes(SYM), "the token passes through OPAQUE (fail toward symbolic)");
    assert.ok(!r.stdout.includes(RAW), "no resolution can have happened");
    assert.match(r.stderr, /PASSTHROUGH/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("(d) no MANDU_ARBITER_HUMAN_SOCK → PASSTHROUGH with the same contract", async () => {
  const r = await runFilter(["node", "-e", `console.log("plain ${SYM.replace(/\$/g, "\\$")}")`], {});
  assert.equal(r.code, 0);
  assert.ok(r.stdout.includes(SYM));
  assert.match(r.stderr, /PASSTHROUGH/);
});

test("(k) ONLY the data socket set → PASSTHROUGH: the filter never falls back to it", async () => {
  // The mock would answer desymbolize on this path; the point is that the
  // filter never asks it — the data socket is not the human plane.
  const dir = mkdtempSync(join(tmpdir(), "mandu-replyfilter-"));
  const sock = join(dir, "arbiter.sock");
  const { server, emitted } = startMockArbiter(sock);
  try {
    const r = await runFilter(
      ["node", "-e", `console.log("Summary: ${SYM.replace(/\$/g, "\\$")}")`],
      { MANDU_ARBITER_SOCK: sock, MANDU_SCOPE_ID: "reply-e2e-data-only" },
    );
    assert.equal(r.code, 0);
    assert.ok(r.stdout.includes(SYM), "the token stays OPAQUE");
    assert.ok(!r.stdout.includes(RAW), "no desymbolize was asked of the data socket");
    assert.match(r.stderr, /MANDU_ARBITER_HUMAN_SOCK not set — PASSTHROUGH/);
    assert.ok(
      !emitted.some((e) => (e as { kind?: string }).kind === "desymbolize"),
      "no desymbolize event: nothing was resolved",
    );
  } finally {
    server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("(l) the wrapped child never sees MANDU_ARBITER_HUMAN_SOCK (filtered and passthrough)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-replyfilter-"));
  const sock = join(dir, "arbiter.sock");
  const { server } = startMockArbiter(sock);
  const probe = ["node", "-e", `console.log("child-sees=" + (process.env.MANDU_ARBITER_HUMAN_SOCK ?? "<unset>"))`];
  try {
    const filtered = await runFilter(probe, { MANDU_ARBITER_HUMAN_SOCK: sock });
    assert.equal(filtered.code, 0);
    assert.equal(filtered.stdout, "child-sees=<unset>\n", filtered.stderr);
    const dead = await runFilter(probe, { MANDU_ARBITER_HUMAN_SOCK: join(dir, "dead.sock") });
    assert.match(dead.stderr, /PASSTHROUGH/);
    assert.equal(dead.stdout, "child-sees=<unset>\n", "the passthrough spawn drops it too");
  } finally {
    server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("(u) a child's signal death re-raises through the wrapper (128+n), not a clean exit", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-replyfilter-"));
  const sock = join(dir, "arbiter.sock");
  const { server } = startMockArbiter(sock);
  try {
    // Filtered pipe mode: the wrapper's own SIGTERM forwarder used to catch
    // the re-raised signal, and the drained wrapper exited 0.
    const r = await runFilter(["sh", "-c", 'echo "partial ${TEST_SYM}"; kill -TERM $$'], {
      MANDU_ARBITER_HUMAN_SOCK: sock,
      TEST_SYM: SYM,
    });
    assert.ok(r.signal === "SIGTERM" || r.code === 143, `died by SIGTERM (or 143); got code=${r.code} signal=${r.signal}`);
    assert.equal(r.stdout, `partial ${RAW}\n`, "the output before the death was still filtered");
  } finally {
    server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── PTY relay (util-linux script on Linux, BSD script on macOS) ───────────────

/** The relay backend gate: skip (don't fail) where the host has no backend —
 *  the same probe the wrapper runs (src/pty-relay.ts ptyRelayAvailable). */
const SCRIPT_AVAILABLE = ptyRelayAvailable().ok;
const NO_BACKEND = "no PTY relay backend (util-linux or BSD script)";

test(
  "(v) PTY relay on macOS: a socket stdin (BSD script cannot start on one) degrades to PASSTHROUGH, the child still runs",
  { skip: (process.platform !== "darwin" || !SCRIPT_AVAILABLE) && "macOS BSD script only" },
  async () => {
    const dir = mkdtempSync(join(tmpdir(), "mandu-replyfilter-"));
    const sock = join(dir, "arbiter.sock");
    const { server } = startMockArbiter(sock);
    try {
      // node's "pipe" stdin is a socketpair: BSD script would exit 1 with
      // "tcgetattr/ioctl: Operation not supported on socket" before the child ran.
      const r = await runFilter(
        ["bash", "-c", 'echo "Summary: ${TEST_SYM}"; exit 4'],
        { MANDU_ARBITER_HUMAN_SOCK: sock, MANDU_REPLY_FILTER_PTY: "1", TEST_SYM: SYM },
        "pipe",
      );
      assert.equal(r.code, 4, `the child ran and its exit code propagated; stderr: ${r.stderr}`);
      assert.match(r.stderr, /stdin is a socket.*PASSTHROUGH/);
      assert.doesNotMatch(r.stderr, /tcgetattr/, "script was never started on the socket");
      assert.ok(r.stdout.includes(SYM), "passthrough: the symbol stays opaque (nothing leaks)");
    } finally {
      server.close();
      rmSync(dir, { recursive: true, force: true });
    }
  },
);

test(
  "(e) PTY relay: the child sees a REAL TTY on stdout AND the reply still resolves",
  { skip: !SCRIPT_AVAILABLE && NO_BACKEND },
  async () => {
    const dir = mkdtempSync(join(tmpdir(), "mandu-replyfilter-"));
    const sock = join(dir, "arbiter.sock");
    const { server, emitted } = startMockArbiter(sock);
    try {
      // The symbol travels via the env (quoting discipline: only the CHILD's
      // bash expands it — the literal token lands on the pty, like a reply).
      const r = await runFilter(
        ["bash", "-c", 'if [ -t 1 ]; then echo "TTY-YES"; else echo "TTY-NO"; fi; echo "Summary: ${TEST_SYM}"'],
        { MANDU_ARBITER_HUMAN_SOCK: sock, MANDU_SCOPE_ID: "reply-pty-e2e", MANDU_REPLY_FILTER_PTY: "1", TEST_SYM: SYM },
      );
      assert.equal(r.code, 0);
      assert.ok(r.stdout.includes("TTY-YES"), `the child must see a TTY; got: ${r.stdout}`);
      assert.ok(r.stdout.includes(RAW), "the human sees the RAW value through the relay");
      assert.ok(!r.stdout.includes("$MDU:"), "no opaque token reaches the human");
      assert.match(r.stderr, /PTY RELAY/);
      assert.ok(emitted.length >= 1, "a desymbolize event was emitted");
    } finally {
      server.close();
      rmSync(dir, { recursive: true, force: true });
    }
  },
);

test(
  "(e2) PTY relay under the compact launch display: the notice is folded, the reply still resolves",
  { skip: !SCRIPT_AVAILABLE && NO_BACKEND },
  async () => {
    const dir = mkdtempSync(join(tmpdir(), "mandu-replyfilter-"));
    const sock = join(dir, "arbiter.sock");
    const { server } = startMockArbiter(sock);
    try {
      const r = await runFilter(
        ["bash", "-c", 'echo "Summary: ${TEST_SYM}"'],
        { MANDU_ARBITER_HUMAN_SOCK: sock, MANDU_SCOPE_ID: "reply-pty-compact", MANDU_REPLY_FILTER_PTY: "1", MANDU_LAUNCH_DISPLAY: "compact", TEST_SYM: SYM },
      );
      assert.equal(r.code, 0);
      assert.ok(r.stdout.includes(RAW) && !r.stdout.includes("$MDU:"), "the relay still desymbolizes");
      assert.doesNotMatch(r.stderr, /PTY RELAY/, `the all-is-well notice is folded by the launcher's summary: ${r.stderr}`);
      assert.doesNotMatch(r.stderr, /mandu-reply-filter:/, "no wrapper chatter at all on a healthy launch");
    } finally {
      server.close();
      rmSync(dir, { recursive: true, force: true });
    }
  },
);

test(
  "(e3) the launch's log (MANDU_LAUNCH_LOG, packaging.md §5): under the compact display the notice goes there, never to the terminal; a log that is a link is never written",
  { skip: !SCRIPT_AVAILABLE && NO_BACKEND },
  async () => {
    const dir = mkdtempSync(join(tmpdir(), "mandu-replyfilter-"));
    const sock = join(dir, "arbiter.sock");
    const log = join(dir, "launch.log");
    writeFileSync(log, "header\n", { mode: 0o600 });
    const { server } = startMockArbiter(sock);
    try {
      const r = await runFilter(
        ["bash", "-c", 'echo "Summary: ${TEST_SYM}"'],
        { MANDU_ARBITER_HUMAN_SOCK: sock, MANDU_SCOPE_ID: "reply-pty-log", MANDU_REPLY_FILTER_PTY: "1", MANDU_LAUNCH_DISPLAY: "compact", MANDU_LAUNCH_LOG: log, TEST_SYM: SYM },
      );
      assert.equal(r.code, 0);
      assert.ok(r.stdout.includes(RAW), "the relay still desymbolizes");
      assert.doesNotMatch(r.stderr, /mandu-reply-filter:/, `nothing on the terminal: ${r.stderr}`);
      const kept = readFileSync(log, "utf8");
      assert.match(kept, /^header\nmandu-reply-filter: .*PTY RELAY/m, kept);
      assert.ok(!kept.includes(RAW) && !kept.includes(SYM), "the log holds the filter's own message, never the agent's output");
      // A link at the log's name: not followed, nothing written through it.
      const target = join(dir, "target");
      writeFileSync(target, "");
      const link = join(dir, "link.log");
      symlinkSync(target, link);
      const l = await runFilter(
        ["bash", "-c", "true"],
        { MANDU_ARBITER_HUMAN_SOCK: sock, MANDU_SCOPE_ID: "reply-pty-link", MANDU_REPLY_FILTER_PTY: "1", MANDU_LAUNCH_DISPLAY: "compact", MANDU_LAUNCH_LOG: link },
      );
      assert.equal(l.code, 0);
      assert.equal(readFileSync(target, "utf8"), "", "nothing written through the link");
    } finally {
      server.close();
      rmSync(dir, { recursive: true, force: true });
    }
  },
);

test(
  "(f) PTY relay: the child's non-zero exit code propagates through script",
  { skip: !SCRIPT_AVAILABLE && NO_BACKEND },
  async () => {
    const dir = mkdtempSync(join(tmpdir(), "mandu-replyfilter-"));
    const sock = join(dir, "arbiter.sock");
    const { server } = startMockArbiter(sock);
    try {
      const r = await runFilter(["bash", "-c", "exit 9"], {
        MANDU_ARBITER_HUMAN_SOCK: sock,
        MANDU_REPLY_FILTER_PTY: "1",
      });
      assert.equal(r.code, 9);
    } finally {
      server.close();
      rmSync(dir, { recursive: true, force: true });
    }
  },
);

test(
  "(g) PTY relay: a newline-LESS prompt resolves via the idle flush while the child is alive",
  { skip: !SCRIPT_AVAILABLE && NO_BACKEND },
  async () => {
    const dir = mkdtempSync(join(tmpdir(), "mandu-replyfilter-"));
    const sock = join(dir, "arbiter.sock");
    const { server } = startMockArbiter(sock);
    try {
      // The child paints a prompt containing the token, NO trailing newline,
      // then stays alive. Without the idle flush the text would stay held
      // until exit — the assertion is that the RESOLVED prompt reaches stdout
      // while the child still runs.
      const child = spawn(
        TSX_BIN,
        [RUN_TS, "--", "bash", "-c", 'printf "reply: ${TEST_SYM} > "; sleep 5'],
        {
          env: {
            ...process.env,
            MANDU_ARBITER_HUMAN_SOCK: sock,
            MANDU_REPLY_FILTER_PTY: "1",
            TEST_SYM: SYM,
          },
          stdio: ["ignore", "pipe", "pipe"],
        },
      );
      let stdout = "";
      let closed = false;
      child.stdout.setEncoding("utf8");
      child.on("close", () => {
        closed = true;
      });
      const resolvedWhileAlive = await new Promise<boolean>((resolve) => {
        const deadline = setTimeout(() => resolve(false), 4000);
        child.stdout.on("data", (c: string) => {
          stdout += c;
          // PTY (eager) mode renders the value FRAME-SAFELY: longer-than-token
          // values are wrap-off-bracketed (src/filter.ts header), so match the
          // value itself, not the old contiguous splice.
          if (stdout.includes(RAW) && !closed) {
            clearTimeout(deadline);
            resolve(true);
          }
        });
      });
      child.kill("SIGKILL");
      await once(child, "close");
      assert.ok(
        resolvedWhileAlive,
        `the resolved prompt must appear before the child exits; got: ${JSON.stringify(stdout)}`,
      );
      assert.ok(!stdout.includes("$MDU:"), "no opaque token reached the human");
    } finally {
      server.close();
      rmSync(dir, { recursive: true, force: true });
    }
  },
);

test(
  "(h) PTY relay: a token hard-wrapped across rows (TUI-style) reassembles and resolves",
  { skip: !SCRIPT_AVAILABLE && NO_BACKEND },
  async () => {
    const dir = mkdtempSync(join(tmpdir(), "mandu-replyfilter-"));
    const sock = join(dir, "arbiter.sock");
    const { server } = startMockArbiter(sock);
    try {
      // The "TUI" wraps the token mid-hash: first half, newline + continuation
      // indent, second half — exactly the stream a width-constrained repaint
      // produces. The halves travel via env to keep the token literal.
      const r = await runFilter(
        ["bash", "-c", 'printf "reply: %s\\n  %s end\\n" "${SYM_HEAD}" "${SYM_TAIL}"'],
        {
          MANDU_ARBITER_HUMAN_SOCK: sock,
          MANDU_REPLY_FILTER_PTY: "1",
          // Mid-hash cut: everything but the closing `]` on the first row.
          SYM_HEAD: SYM.slice(0, SYM.length - 1),
          SYM_TAIL: SYM.slice(SYM.length - 1),
        },
      );
      assert.equal(r.code, 0);
      assert.ok(r.stdout.includes(RAW), `the wrapped token must resolve; got: ${JSON.stringify(r.stdout)}`);
      assert.ok(!r.stdout.includes("$MDU:"), "no opaque token half reached the human");
    } finally {
      server.close();
      rmSync(dir, { recursive: true, force: true });
    }
  },
);

// ── (i) the alternate-screen (fullscreen) renderer ────────────────────────────

/** Render PTY bytes through a headless terminal and return the viewport rows
 *  (right-trimmed) — what a human's terminal would show. */
async function renderRows(bytes: string, cols = 80, rows = 24): Promise<string[]> {
  const { Terminal } = ((xtermHeadlessNs as { default?: unknown }).default ??
    xtermHeadlessNs) as typeof import("@xterm/headless");
  const term = new Terminal({ cols, rows, allowProposedApi: true, scrollback: 0 });
  await new Promise<void>((r) => term.write(bytes, r));
  const buf = term.buffer.active;
  const out: string[] = [];
  for (let y = 0; y < rows; y++) out.push((buf.getLine(y)?.translateToString(true) ?? "").trimEnd());
  term.dispose();
  return out;
}

/** The fake fullscreen TUI's two frames for a cell-diff SPLIT of `sym`
 *  painted at row 3, column 3 (bash printf source). Frame 1 paints a spinner
 *  row whose cell under the hash's LAST glyph already holds that glyph;
 *  frame 2 paints the token up to that cell, CHAs over it, then writes `]`
 *  plus `after`, erases the rest of the row, and parks the cursor in the
 *  input box. Derived from the token so the columns track its spelling. */
function splitFrameScript(sym: string, after = ""): string {
  const skip = sym.indexOf("]") - 1; // offset of the hash's last glyph
  assert.ok(skip > 0 && sym.startsWith("$"), "fixture: a canonical token");
  const col = 3;
  return (
    `printf "\\033[?1049h\\033[3;${col}H${"Reading the".padEnd(skip)}${sym[skip]}..."; sleep 0.4; ` +
    `printf "\\033[3;${col}H\\$${sym.slice(1, skip)}\\033[${col + skip + 1}G]${after}\\033[K\\033[6;3H"; sleep 6`
  );
}

test(
  "(i) PTY relay, alternate screen: a cell-diff SPLIT token is read back off the screen and repainted",
  { skip: !SCRIPT_AVAILABLE && NO_BACKEND },
  async () => {
    const dir = mkdtempSync(join(tmpdir(), "mandu-replyfilter-"));
    const sock = join(dir, "arbiter.sock");
    const { server, emitted } = startMockArbiter(sock);
    try {
      // A fake fullscreen TUI: enter the alt screen; frame 1 paints a spinner
      // row whose column under the hash's last glyph already holds the `a`
      // the token's hash needs; frame 2 diff-paints the reply row — the token
      // minus that one cell (`$MDU:Read[9b0` → CHA over the `a` → `]`) — parks
      // the cursor in the input box and stays alive. No byte sequence on the
      // wire ever contains the whole token; only the screen does.
      const script = splitFrameScript(SYM);
      const child = spawn(TSX_BIN, [RUN_TS, "--", "bash", "-c", script], {
        env: { ...process.env, MANDU_ARBITER_HUMAN_SOCK: sock, MANDU_REPLY_FILTER_PTY: "1", MANDU_SCOPE_ID: "reply-e2e-fs" },
        stdio: ["ignore", "pipe", "pipe"],
      });
      let stdout = "";
      let closed = false;
      child.stdout.setEncoding("utf8");
      child.on("close", () => { closed = true; });
      const resolvedWhileAlive = await new Promise<boolean>((resolve) => {
        const deadline = setTimeout(() => resolve(false), 5000);
        child.stdout.on("data", (c: string) => {
          stdout += c;
          if (stdout.includes(RAW) && !closed) { clearTimeout(deadline); resolve(true); }
        });
      });
      // Let the repaint's trailing bytes land, then stop the child.
      await new Promise((r) => setTimeout(r, 200));
      child.kill("SIGKILL");
      await once(child, "close");
      assert.ok(resolvedWhileAlive, `the value must reach the screen while the TUI is alive; got: ${JSON.stringify(stdout)}`);
      const rows = await renderRows(stdout);
      assert.equal(rows[2], `  ${RAW}`, `row 3 shows the value in place; screen was:\n${rows.join("\n")}`);
      assert.ok(!rows.join("\n").includes("$MDU:"), "no opaque token on the human's screen");
      assert.ok(!stdout.includes("$MDU"), `no token byte on the wire, not even the split prefix: ${JSON.stringify(stdout)}`);
      // The repaint reported itself (desymbolize event, after relay_mode).
      const kinds = (emitted as Array<{ kind: string }>).map((e) => e.kind);
      assert.ok(kinds.includes("desymbolize"), `a desymbolize event for the repaint; got ${kinds.join(",")}`);
    } finally {
      server.close();
      rmSync(dir, { recursive: true, force: true });
    }
  },
);

test(
  "(j) PTY relay, alternate screen: a TAB in the value lands on the terminal's tab stop, never as a raw TAB",
  { skip: !SCRIPT_AVAILABLE && NO_BACKEND },
  async () => {
    const dir = mkdtempSync(join(tmpdir(), "mandu-replyfilter-"));
    const sock = join(dir, "arbiter.sock");
    const { server, emitted } = startMockArbiter(sock);
    try {
      // The (i) shape with TAB_SYM: row 3, column 3 (0-based 2). Frame 1 leaves
      // the `1` the hash needs under its cell; frame 2 paints `$MDU:Read[7ab`,
      // jumps over the `1`, paints `]`. A trailing marker after the token
      // proves the row's tail survives the repaint.
      const script = splitFrameScript(TAB_SYM, " END");
      const child = spawn(TSX_BIN, [RUN_TS, "--", "bash", "-c", script], {
        env: { ...process.env, MANDU_ARBITER_HUMAN_SOCK: sock, MANDU_REPLY_FILTER_PTY: "1", MANDU_SCOPE_ID: "reply-e2e-fs-tab" },
        stdio: ["ignore", "pipe", "pipe"],
      });
      let stdout = "";
      let closed = false;
      child.stdout.setEncoding("utf8");
      child.on("close", () => { closed = true; });
      const resolvedWhileAlive = await new Promise<boolean>((resolve) => {
        const deadline = setTimeout(() => resolve(false), 5000);
        child.stdout.on("data", (c: string) => {
          stdout += c;
          if (stdout.includes("value") && !closed) { clearTimeout(deadline); resolve(true); }
        });
      });
      await new Promise((r) => setTimeout(r, 200));
      child.kill("SIGKILL");
      await once(child, "close");
      assert.ok(resolvedWhileAlive, `the value must reach the screen while the TUI is alive; got: ${JSON.stringify(stdout)}`);
      assert.ok(!stdout.includes("\t"), "the value's TAB never reaches the wire raw (the fake TUI emits none itself)");
      const rows = await renderRows(stdout);
      // key@2..4, tab@5 → stop 8 (3 spaces), value@8..12 (11 columns); the
      // value is narrower than the token, so the TUI's own " END" closes up
      // behind it (screen-reconcile.ts CLOSE UP: no padding inside the line).
      const want = "  key" + " ".repeat(3) + "value" + " END";
      assert.equal(rows[2], want, `row 3 shows the tab-stop form; screen was:\n${rows.join("\n")}`);
      // Parity with a vanilla terminal printing the raw value at that column.
      const vanilla = await renderRows(`\x1b[3;3H${TAB_RAW}`);
      assert.equal(rows[2]!.slice(0, vanilla[2]!.length), vanilla[2]);
      assert.ok(!rows.join("\n").includes("$MDU:"), "no opaque token on the human's screen");
      const kinds = (emitted as Array<{ kind: string }>).map((e) => e.kind);
      assert.ok(kinds.includes("desymbolize"), `a desymbolize event for the repaint; got ${kinds.join(",")}`);
    } finally {
      server.close();
      rmSync(dir, { recursive: true, force: true });
    }
  },
);

// ── (k)–(n) reserve blocks (docs/design/ui/reply-row-reservation.md §3.6, §3.7) ──
// A fake TUI under real script(1) paints the phase 0 reserve block (first
// paint, then a cell-diff RE-LAYOUT frame whose marker rows go out as
// fragments only). Rendering the wrapper's whole output on a headless
// terminal must show line i of the value on row i, and the wrapper must have
// reported its relay to the arbiter (`setSessionRelay`, reserve only for the
// PTY relay).

/** Run the wrapper around a fake TUI that prints `frames` (env-carried bytes,
 *  printed verbatim with `printf %s`) 0.4s apart, then stays alive; stop it
 *  once `settled` appears in stdout (plus a grace period for the repaint). */
async function runFakeTui(
  frames: string[],
  settled: string,
  env: Record<string, string>,
): Promise<{ stdout: string; aliveWhenSettled: boolean }> {
  const script = frames.map((_, i) => `printf '%s' "$FRAME_${i}"; sleep 0.4`).join("; ") + "; sleep 6";
  const frameEnv: Record<string, string> = {};
  frames.forEach((f, i) => { frameEnv[`FRAME_${i}`] = f; });
  const child = spawn(TSX_BIN, [RUN_TS, "--", "bash", "-c", script], {
    env: { ...process.env, MANDU_REPLY_FILTER_PTY: "1", ...frameEnv, ...env },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  let closed = false;
  child.stdout.setEncoding("utf8");
  child.on("close", () => { closed = true; });
  const aliveWhenSettled = await new Promise<boolean>((resolve) => {
    const deadline = setTimeout(() => resolve(false), 8000);
    child.stdout.on("data", (c: string) => {
      stdout += c;
      if (stdout.includes(settled) && !closed) { clearTimeout(deadline); resolve(true); }
    });
  });
  await new Promise((r) => setTimeout(r, 400));
  child.kill("SIGKILL");
  await once(child, "close");
  return { stdout, aliveWhenSettled };
}

const RESERVE_ROWS = [1, 2, 3, 4, 5].map((i) => "  " + shown(i));

test(
  "(k) PTY relay, MAIN screen (inline renderer): a reserve block and its cell-diff re-layout → row i reads line i",
  { skip: !SCRIPT_AVAILABLE && NO_BACKEND },
  async () => {
    const dir = mkdtempSync(join(tmpdir(), "mandu-replyfilter-"));
    const sock = join(dir, "arbiter.sock");
    const { server, emitted, relays } = startMockArbiter(sock);
    try {
      const { stdout, aliveWhenSettled } = await runFakeTui([INLINE_FIRST_PAINT, INLINE_RELAYOUT], "PROBE para", {
        MANDU_ARBITER_HUMAN_SOCK: sock,
        MANDU_SCOPE_ID: "reply-e2e-reserve",
      });
      assert.ok(aliveWhenSettled, `the re-layout must reach the screen while the TUI is alive; got: ${JSON.stringify(stdout)}`);
      const rows = await renderRows(stdout);
      assert.equal(rows[2], "  PROBE para", `screen was:\n${rows.join("\n")}`);
      assert.deepEqual(rows.slice(3, 8), RESERVE_ROWS, `screen was:\n${rows.join("\n")}`);
      assert.ok(!rows.join("\n").includes("$MDU") && !rows.join("\n").includes("464e"), "no marker or fragment on the human's screen");
      assert.ok(!stdout.includes("\t"), "the value's TAB never reaches the wire raw");
      // The relay report: PTY, reserve on, keyed by the session.
      assert.deepEqual(relays[0], { sessionKey: "reply-e2e-reserve", mode: "pty", reserve: true, wrap: true }, JSON.stringify(relays));
      // One desymbolize record for the block's value — whole, not per row.
      const values = (emitted as Array<{ kind: string; output?: { original?: string } }>)
        .filter((e) => e.kind === "desymbolize" && e.output?.original === BV);
      assert.equal(values.length, 1, `one record for the value; events: ${JSON.stringify(emitted.map((e) => (e as { kind: string }).kind))}`);
    } finally {
      server.close();
      rmSync(dir, { recursive: true, force: true });
    }
  },
);

test(
  "(l) PTY relay, ALTERNATE screen: a reserve block and its cell-diff re-layout → row i reads line i",
  { skip: !SCRIPT_AVAILABLE && NO_BACKEND },
  async () => {
    const dir = mkdtempSync(join(tmpdir(), "mandu-replyfilter-"));
    const sock = join(dir, "arbiter.sock");
    const { server } = startMockArbiter(sock);
    try {
      const cup = (r: number, c: number) => `\x1b[${r};${c}H`;
      const relayout =
        `${cup(3, 1)}  PROBE para\x1b[K${cup(4, 7)}:nomodel_Bash[464e]/1:5${cup(5, 13)}2${cup(6, 13)}3${cup(7, 13)}4` +
        `${cup(8, 1)}  $MDU/464e/5${cup(20, 3)}`;
      const { stdout, aliveWhenSettled } = await runFakeTui([FULLSCREEN_FIRST_PAINT, relayout], "PROBE para", {
        MANDU_ARBITER_HUMAN_SOCK: sock,
        MANDU_SCOPE_ID: "reply-e2e-reserve-fs",
      });
      assert.ok(aliveWhenSettled, `got: ${JSON.stringify(stdout)}`);
      const rows = await renderRows(stdout);
      assert.equal(rows[2], "  PROBE para", `screen was:\n${rows.join("\n")}`);
      assert.deepEqual(rows.slice(3, 8), RESERVE_ROWS, `screen was:\n${rows.join("\n")}`);
      assert.ok(!rows.join("\n").includes("$MDU") && !rows.join("\n").includes("464e"));
      assert.ok(!stdout.includes("$MDU"), `no marker byte on the wire: ${JSON.stringify(stdout)}`);
    } finally {
      server.close();
      rmSync(dir, { recursive: true, force: true });
    }
  },
);

test(
  "(r) PTY relay, ALTERNATE screen: the echo-fidelity-long capture (`$MDU/` CHA `101/3`) never puts `$MDU` on the wire",
  { skip: !SCRIPT_AVAILABLE && "util-linux script not available" },
  async () => {
    const dir = mkdtempSync(join(tmpdir(), "mandu-replyfilter-"));
    const sock = join(dir, "arbiter.sock");
    const { server } = startMockArbiter(sock);
    try {
      // CI pipeline 7896's frames (reserve-fixtures.ts). The wrapper's models
      // are 80x24 here (stdout is a pipe), so the 33-row block clamps at the
      // bottom row; rows 1..23 are what the capture's rows 1..23 show.
      const { stdout, aliveWhenSettled } = await runFakeTui(
        [`\x1b[?1049h\x1b[2J${LONG_FIRST_PAINT}`, LONG_SCROLL_RELAYOUT],
        "136 tokens)",
        { MANDU_ARBITER_HUMAN_SOCK: sock, MANDU_SCOPE_ID: "reply-e2e-long-fs" },
      );
      assert.ok(aliveWhenSettled, `got: ${JSON.stringify(stdout)}`);
      assert.equal(stdout.match(/\$MDU[:\w[\].]*/)?.[0] ?? null, null, "no `$MDU` byte on the human's terminal stream (F2)");
      const rows = await renderRows(stdout);
      const want = LONG_LINES.slice(1, 24).map((l) => `  ${l}`.trimEnd());
      assert.deepEqual(rows.slice(0, 23), want, `screen was:\n${rows.join("\n")}`);
    } finally {
      server.close();
      rmSync(dir, { recursive: true, force: true });
    }
  },
);

test(
  "(t) PTY relay, MAIN screen: claude 2.1.273's inline cell-diff split (`$MDU:` CHA `omodel_Read[5ccd]`) never puts `$MDU` on the wire",
  { skip: !SCRIPT_AVAILABLE && "util-linux script not available" },
  async () => {
    const dir = mkdtempSync(join(tmpdir(), "mandu-replyfilter-"));
    const sock = join(dir, "arbiter.sock");
    const { server, emitted } = startMockArbiter(sock);
    try {
      const { stdout, aliveWhenSettled } = await runFakeTui([SPLIT_SETUP, SPLIT_FRAME], SPLIT_VALUE, {
        MANDU_ARBITER_HUMAN_SOCK: sock,
        MANDU_SCOPE_ID: "reply-e2e-inline-split",
      });
      assert.ok(aliveWhenSettled, `the value must reach the screen while the TUI is alive; got: ${JSON.stringify(stdout)}`);
      assert.equal(stdout.match(/\$MDU[:\w[\].]*/)?.[0] ?? null, null, "no `$MDU` byte on the human's terminal stream (F2)");
      const rows = await renderRows(stdout);
      assert.equal(rows[SPLIT_ROW], SPLIT_AFTER, `screen was:\n${rows.join("\n")}`);
      const kinds = (emitted as Array<{ kind: string }>).map((e) => e.kind);
      assert.ok(kinds.includes("desymbolize"), `a desymbolize event for the repaint; got ${kinds.join(",")}`);
    } finally {
      server.close();
      rmSync(dir, { recursive: true, force: true });
    }
  },
);

test(
  "(r2) PTY relay, ALTERNATE screen: a token the arbiter does not know, then a quiet TUI — restored by the idle drain, never left blank",
  { skip: !SCRIPT_AVAILABLE && "util-linux script not available" },
  async () => {
    const dir = mkdtempSync(join(tmpdir(), "mandu-replyfilter-"));
    const sock = join(dir, "arbiter.sock");
    const { server } = startMockArbiter(sock);
    try {
      const unknown = "$MDU:Read[dead]";
      const { stdout, aliveWhenSettled } = await runFakeTui(
        [`\x1b[?1049h\x1b[3;3Hsee ${unknown} here\x1b[6;1H`],
        "here",
        { MANDU_ARBITER_HUMAN_SOCK: sock, MANDU_SCOPE_ID: "reply-e2e-unknown-fs" },
      );
      assert.ok(aliveWhenSettled, `got: ${JSON.stringify(stdout)}`);
      const rows = await renderRows(stdout);
      assert.equal(rows[2], `  see ${unknown} here`, `the opaque token is restored; screen was:\n${rows.join("\n")}`);
    } finally {
      server.close();
      rmSync(dir, { recursive: true, force: true });
    }
  },
);

test(
  "(m) PTY relay with MANDU_REPLY_RESERVE=0: the relay reports reserve OFF (the proxy never expands)",
  { skip: !SCRIPT_AVAILABLE && NO_BACKEND },
  async () => {
    const dir = mkdtempSync(join(tmpdir(), "mandu-replyfilter-"));
    const sock = join(dir, "arbiter.sock");
    const { server, relays } = startMockArbiter(sock);
    try {
      const r = await runFilter(["bash", "-c", "echo hi"], {
        MANDU_ARBITER_HUMAN_SOCK: sock,
        MANDU_SCOPE_ID: "reply-e2e-reserve-off",
        MANDU_REPLY_FILTER_PTY: "1",
        MANDU_REPLY_RESERVE: "0",
      });
      assert.equal(r.code, 0);
      assert.deepEqual(relays, [{ sessionKey: "reply-e2e-reserve-off", mode: "pty", reserve: false }]);
    } finally {
      server.close();
      rmSync(dir, { recursive: true, force: true });
    }
  },
);

test("(n) PIPE mode: the relay reports pipe (no reserve); a block that arrives anyway prints the FULL value", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-replyfilter-"));
  const sock = join(dir, "arbiter.sock");
  const { server, relays } = startMockArbiter(sock);
  try {
    const r = await runFilter(["bash", "-c", 'printf "%s\\n" "$BLOCK"'], {
      MANDU_ARBITER_HUMAN_SOCK: sock,
      MANDU_SCOPE_ID: "reply-e2e-reserve-pipe",
      BLOCK: formatBlock(BT, 5),
    });
    assert.equal(r.code, 0);
    assert.equal(r.stdout, BV, "the block collapses to the value, line breaks and TAB intact");
    assert.deepEqual(relays, [{ sessionKey: "reply-e2e-reserve-pipe", mode: "pipe", reserve: false }]);
  } finally {
    server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── (o)–(q) v2 blocks and the relay report's plane (reply-row-reservation.md §11) ──

test(
  "(o) PTY relay, v2: a one-line value WIDER than the 80-column terminal fills its reserved rows (78 + 42)",
  { skip: !SCRIPT_AVAILABLE && NO_BACKEND },
  async () => {
    const dir = mkdtempSync(join(tmpdir(), "mandu-replyfilter-"));
    const sock = join(dir, "arbiter.sock");
    const { server, relays } = startMockArbiter(sock);
    try {
      const { stdout, aliveWhenSettled } = await runFakeTui([KEY_FIRST_PAINT], "key done", {
        MANDU_ARBITER_HUMAN_SOCK: sock,
        MANDU_SCOPE_ID: "reply-e2e-v2-key",
      });
      assert.ok(aliveWhenSettled, `got: ${JSON.stringify(stdout)}`);
      const rows = await renderRows(stdout);
      assert.deepEqual(rows.slice(1, 5), ["  Your key:", `  ${KV.slice(0, 78)}`, `  ${KV.slice(78)}`, "  key done"], `screen was:\n${rows.join("\n")}`);
      assert.ok(!rows.join("\n").includes("$MDU"), "no marker on the human's screen");
      // The relay said it paints v2 heads (`wrap: true` rides with reserve).
      assert.equal(relays[0]?.["wrap"], true, JSON.stringify(relays));
    } finally {
      server.close();
      rmSync(dir, { recursive: true, force: true });
    }
  },
);

test(
  "(p) PTY relay, v2: a block INSIDE a sentence, then its cell-diff re-layout → prefix, rows and suffix intact",
  { skip: !SCRIPT_AVAILABLE && NO_BACKEND },
  async () => {
    const dir = mkdtempSync(join(tmpdir(), "mandu-replyfilter-"));
    const sock = join(dir, "arbiter.sock");
    const { server, emitted } = startMockArbiter(sock);
    try {
      const { stdout, aliveWhenSettled } = await runFakeTui([MID_FIRST_PAINT, MID_RELAYOUT + "  mid done"], "mid done", {
        MANDU_ARBITER_HUMAN_SOCK: sock,
        MANDU_SCOPE_ID: "reply-e2e-v2-mid",
      });
      assert.ok(aliveWhenSettled, `got: ${JSON.stringify(stdout)}`);
      const rows = await renderRows(stdout);
      assert.deepEqual(rows.slice(1, 5), [...MID_SCREEN, "  mid done"], `screen was:\n${rows.join("\n")}`);
      assert.ok(!rows.join("\n").includes("$MDU") && !rows.join("\n").includes("5e2a"), "no marker or fragment left");
      // One desymbolize record for the value, whole.
      const values = (emitted as Array<{ kind: string; output?: { original?: string } }>)
        .filter((e) => e.kind === "desymbolize" && e.output?.original === MV);
      assert.equal(values.length, 1);
    } finally {
      server.close();
      rmSync(dir, { recursive: true, force: true });
    }
  },
);

test("(q) PASSTHROUGH: the relay report goes over the HUMAN socket, never the data socket", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-replyfilter-"));
  const humanSock = join(dir, "human.sock");
  const dataSock = join(dir, "data.sock");
  const human = startMockArbiter(humanSock);
  const data = startMockArbiter(dataSock);
  /** A launcher-forced PASSTHROUGH (an unsupported structured format). */
  const passthrough = async (env: Record<string, string>): Promise<number | null> => {
    const child = spawn(TSX_BIN, [RUN_TS, "--mandu-output-format=bogus", "--", "bash", "-c", "sleep 1"], {
      env: { ...process.env, MANDU_ARBITER_SOCK: undefined, MANDU_ARBITER_HUMAN_SOCK: undefined, ...env },
      stdio: ["ignore", "pipe", "pipe"],
    });
    const [code] = (await once(child, "close")) as [number | null];
    return code;
  };
  try {
    assert.equal(await passthrough({ MANDU_ARBITER_HUMAN_SOCK: humanSock, MANDU_ARBITER_SOCK: dataSock, MANDU_SCOPE_ID: "reply-e2e-pt" }), 0);
    assert.deepEqual(human.relays, [{ sessionKey: "reply-e2e-pt", mode: "passthrough", reserve: false }]);
    assert.deepEqual(data.relays, [], "the data socket never gets the (human-plane) relay report");
    assert.equal((human.emitted[0] as { kind?: string }).kind, "relay_mode");
    // Only the data socket: the health event still goes there, the relay
    // report is skipped (the data socket would refuse it).
    assert.equal(await passthrough({ MANDU_ARBITER_SOCK: dataSock, MANDU_SCOPE_ID: "reply-e2e-pt-data" }), 0);
    assert.deepEqual(data.relays, []);
    assert.equal((data.emitted[0] as { kind?: string }).kind, "relay_mode");
  } finally {
    human.server.close();
    data.server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── Signals (docs/testing/differential-interactive.md §21) ────────────────────
// A ^C after the agent lets go of the terminal is a SIGINT for the wrapper's
// group; the launcher also forwards one. The wrapper must survive it and pass
// it on, and a child that DIES of a signal must still end the wrapper with the
// same signal (128+n), in every mode.

interface SignalRun { code: number | null; signal: NodeJS.Signals | null; stdout: string; stderr: string }

/** Run the wrapper as ONE node process (`node --import tsx`), not through the
 *  tsx CLI: that CLI is a parent process of its own that relays signals and
 *  reports a child's signal death as exit 0, which would hide what these
 *  tests pin. */
function spawnFilterLive(cmd: string[], env: Record<string, string | undefined>) {
  const child = spawn(process.execPath, ["--import", "tsx", RUN_TS, "--", ...cmd], {
    cwd: PKG_ROOT,
    env: { ...process.env, MANDU_ARBITER_SOCK: undefined, MANDU_ARBITER_HUMAN_SOCK: undefined, MANDU_SCOPE_ID: undefined, ...env },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (c: string) => (stdout += c));
  child.stderr.on("data", (c: string) => (stderr += c));
  const done = once(child, "close").then(([code, signal]) => ({ code, signal, stdout, stderr }) as SignalRun);
  const waitFor = async (text: string): Promise<void> => {
    const t0 = Date.now();
    while (!stdout.includes(text)) {
      if (Date.now() - t0 > 15_000) throw new Error(`timed out waiting for ${JSON.stringify(text)}; stdout=${stdout} stderr=${stderr}`);
      await new Promise((r) => setTimeout(r, 20));
    }
  };
  return { child, done, waitFor };
}

/** A child that ignores SIGINT, says `ready`, and exits 0 a moment later. */
const SIGINT_IGNORING_CHILD = ["node", "-e", "process.on('SIGINT',()=>{}); console.log('ready'); setTimeout(()=>process.exit(0),1500)"];
/** A child that dies of its own SIGTERM. */
const SELF_SIGTERM_CHILD = ["node", "-e", "setTimeout(()=>process.kill(process.pid,'SIGTERM'),50)"];

test("(s1) PASSTHROUGH: a SIGINT to the wrapper is forwarded, not fatal; the child's exit code stands", async () => {
  const run = spawnFilterLive(SIGINT_IGNORING_CHILD, {});
  await run.waitFor("ready");
  run.child.kill("SIGINT");
  const r = await run.done;
  assert.match(r.stderr, /PASSTHROUGH/);
  assert.equal(r.signal, null, `the wrapper must survive the SIGINT (got signal ${r.signal})`);
  assert.equal(r.code, 0, "the child ignored the ^C and exited 0");
});

test("(s2) PASSTHROUGH: a child that dies of a signal ends the wrapper with the same signal", async () => {
  const r = await spawnFilterLive(SELF_SIGTERM_CHILD, {}).done;
  assert.equal(r.signal, "SIGTERM");
});

test("(s3) filtered: a child that dies of a signal ends the wrapper with the same signal", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-replyfilter-"));
  const sock = join(dir, "arbiter.sock");
  const { server } = startMockArbiter(sock);
  try {
    const r = await spawnFilterLive(SELF_SIGTERM_CHILD, { MANDU_ARBITER_HUMAN_SOCK: sock }).done;
    assert.doesNotMatch(r.stderr, /PASSTHROUGH/);
    assert.equal(r.signal, "SIGTERM", `the forwarding handler must not swallow the re-raise (got code ${r.code})`);
  } finally {
    server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test(
  "(s4) PTY relay under a forking sh (dash): the agent replaces the shell, so no shell is left to die of a ^C",
  // util-linux only: BSD script runs no shell at all (it execs the argv), and
  // the probe reads /proc.
  { skip: (process.platform !== "linux" || !SCRIPT_AVAILABLE) && "util-linux script only" },
  async () => {
    const dir = mkdtempSync(join(tmpdir(), "mandu-replyfilter-"));
    const sock = join(dir, "arbiter.sock");
    const { server } = startMockArbiter(sock);
    try {
      const r = await spawnFilterLive(
        ["node", "-e", "console.log('parent=' + require('fs').readFileSync('/proc/' + process.ppid + '/comm', 'utf8').trim())"],
        { MANDU_ARBITER_HUMAN_SOCK: sock, MANDU_REPLY_FILTER_PTY: "1", SHELL: "/bin/sh" },
      ).done;
      assert.equal(r.code, 0);
      assert.match(r.stdout, /parent=script/, `the relayed command must be script's direct child: ${r.stdout}`);
    } finally {
      server.close();
      rmSync(dir, { recursive: true, force: true });
    }
  },
);

// ── (u) the first-session tour: a value narrower than its token ─────────────
for (const screen of ["alternate", "main"] as const) {
  test(
    `(u) PTY relay, ${screen.toUpperCase()} screen: a narrower value closes up — \`STRIPE_KEY='<value>' next\`, no padding inside the line`,
    { skip: !SCRIPT_AVAILABLE && "util-linux script not available" },
    async () => {
      const dir = mkdtempSync(join(tmpdir(), "mandu-replyfilter-"));
      const sock = join(dir, "arbiter.sock");
      const { server, emitted } = startMockArbiter(sock);
      try {
        // The tour's reply row, then (next frame) the renderer's cell diff
        // appending a word at the column IT believes follows the quote.
        const lead = "  STRIPE_KEY='";
        const after = lead.length + CLOSE_SYM.length + 1; // 0-based column after `'`
        const frames = screen === "alternate"
          ? [
            `\x1b[?1049h\x1b[3;1H${lead}${CLOSE_SYM}'\x1b[4;3HDEBUG=1\x1b[6;3H`,
            `\x1b[3;${after + 2}Hnext\x1b[6;3H`,
          ]
          : [
            `\r\n${lead}${CLOSE_SYM}'\r\n  DEBUG=1\r\n\r\n> `,
            `\x1b[3A\x1b[${after + 2}Gnext\r\x1b[3B\x1b[3G`,
          ];
        const { stdout, aliveWhenSettled } = await runFakeTui(frames, "next", {
          MANDU_ARBITER_HUMAN_SOCK: sock,
          MANDU_SCOPE_ID: `reply-e2e-closeup-${screen}`,
        });
        assert.ok(aliveWhenSettled, `the reply must reach the screen while the TUI is alive; got: ${JSON.stringify(stdout)}`);
        const rows = await renderRows(stdout);
        const row = screen === "alternate" ? 2 : 1;
        assert.equal(rows[row], `${lead}${CLOSE_RAW}' next`, `screen was:\n${rows.join("\n")}`);
        assert.equal(rows[row + 1], "  DEBUG=1");
        assert.doesNotMatch(stdout, /\$MDU/, "no symbol byte on the human's terminal stream");
        // The event's original is what the human reads: no pad either.
        const originals = (emitted as Array<{ kind: string; output?: { original?: string | null } }>)
          .filter((e) => e.kind === "desymbolize")
          .map((e) => e.output?.original ?? "");
        assert.ok(originals.some((o) => o.includes(`${CLOSE_RAW}'`)), `a desymbolize event with the value; got ${JSON.stringify(originals)}`);
        assert.ok(!originals.some((o) => new RegExp(`${CLOSE_RAW} +'`).test(o)), "no event carries the padded form");
      } finally {
        server.close();
        rmSync(dir, { recursive: true, force: true });
      }
    },
  );
}

// ── (x) a value far wider than the rest of its row (2026-10-17) ─────────────
// The demo's 107-column Stripe key in a Claude Code fullscreen reply: the
// words after the token, moved right by the column translation, went out
// with auto-wrap on and wrapped onto rows the TUI never counted, so a later
// row read `connected0totStripe`. The wrapper runs on a REAL 72-column
// terminal here (an outer util-linux script sized with stty): the stream
// filter only knows the width from a TTY, as in a live session.
test(
  "(x) PTY relay on a 72-column terminal, ALTERNATE screen: a value far wider than its row clips; the rows below stay intact",
  { skip: (process.platform !== "linux" || !SCRIPT_AVAILABLE) && "util-linux script only" },
  async () => {
    const dir = mkdtempSync(join(tmpdir(), "mandu-replyfilter-"));
    const sock = join(dir, "arbiter.sock");
    const { server, emitted } = startMockArbiter(sock);
    try {
      const cha = (n: number) => `\x1b[${n}G`;
      const frame =
        `\x1b[?1049h\x1b[2;1H●${cha(3)}Found${cha(9)}the${cha(13)}key${cha(17)}(${WIDE_SYM})${cha(61)}and${cha(65)}got` +
        `\r\x1b[2C\x1b[1BHTTP${cha(8)}200.` +
        `\r\x1b[2C\x1b[2Bpayments:${cha(13)}connected${cha(23)}to${cha(26)}Stripe${cha(33)}(test${cha(39)}mode)` +
        "\x1b[8;3H";
      const body = 'stty cols 72 rows 24; exec "$RF_TSX" "$RF_RUN" -- bash -c \'printf "%s" "$FRAME"; sleep 1\'';
      const child = spawn("script", ["-qec", body, "/dev/null"], {
        env: {
          ...process.env, RF_TSX: TSX_BIN, RF_RUN: RUN_TS, FRAME: frame,
          MANDU_ARBITER_SOCK: undefined, MANDU_ARBITER_HUMAN_SOCK: sock, MANDU_REPLY_FILTER_PTY: "1",
          MANDU_SCOPE_ID: "reply-e2e-wide-value",
        },
        stdio: ["ignore", "pipe", "pipe"],
      });
      let stdout = "";
      child.stdout.setEncoding("utf8");
      child.stdout.on("data", (c: string) => { stdout += c; });
      const timer = setTimeout(() => child.kill("SIGKILL"), 20_000);
      await once(child, "close");
      clearTimeout(timer);
      const rows = await renderRows(stdout, 72, 24);
      assert.deepEqual(rows.slice(1, 6), [
        `● Found the key (${WIDE_RAW}`.slice(0, 72),
        "  HTTP 200.",
        "",
        "  payments: connected to Stripe (test mode)",
        "",
      ], `screen was:\n${rows.join("\n")}`);
      assert.doesNotMatch(stdout, /\$MDU/, "no symbol byte on the human's terminal stream");
      // Only the part of the value the row shows goes to the terminal.
      assert.ok(!stdout.includes(WIDE_RAW), "the clipped tail of the value is not sent");
      const kinds = (emitted as Array<{ kind: string }>).map((e) => e.kind);
      assert.ok(kinds.includes("desymbolize"), `a desymbolize event for the value; got ${kinds.join(",")}`);
    } finally {
      server.close();
      rmSync(dir, { recursive: true, force: true });
    }
  },
);

// ── (w) Goose 1.53: a reserve head restyled mid-token (§32) ─────────────────
test(
  "(w) PTY relay, MAIN screen: Goose's reply — a reserve head restyled at its `_` over two reads paints as a block, no `/1:N:W:F`, no `$MDU`",
  { skip: !SCRIPT_AVAILABLE && "util-linux script not available" },
  async () => {
    const dir = mkdtempSync(join(tmpdir(), "mandu-replyfilter-"));
    const sock = join(dir, "arbiter.sock");
    const { server, emitted } = startMockArbiter(sock);
    try {
      const { stdout, aliveWhenSettled } = await runFakeTui([...GOOSE_REPLY_READS], "DIFF_S1_DONE", {
        MANDU_ARBITER_HUMAN_SOCK: sock,
        MANDU_SCOPE_ID: "reply-e2e-goose-head",
      });
      assert.ok(aliveWhenSettled, `the reply must reach the screen while the TUI is alive; got: ${JSON.stringify(stdout)}`);
      assert.doesNotMatch(stdout, /\$MDU|\/1:5/, "no token, marker or head suffix on the human's terminal stream");
      const rows = await renderRows(stdout);
      const at = rows.indexOf(GOOSE_REPLY_SCREEN[0]!);
      assert.ok(at >= 0, `screen was:\n${rows.join("\n")}`);
      assert.deepEqual(rows.slice(at, at + GOOSE_REPLY_SCREEN.length), GOOSE_REPLY_SCREEN, `screen was:\n${rows.join("\n")}`);
      const kinds = (emitted as Array<{ kind: string }>).map((e) => e.kind);
      assert.ok(kinds.includes("desymbolize"), `a desymbolize event for the block; got ${kinds.join(",")}`);
    } finally {
      server.close();
      rmSync(dir, { recursive: true, force: true });
    }
  },
);
