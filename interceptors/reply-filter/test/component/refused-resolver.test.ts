/**
 * refused-resolver.test — the S8 miss through the real wrapper (src/run.ts),
 * spawned as a process against a Unix-socket mock arbiter
 * (docs/design/ui/reply-row-reservation.md §18).
 *
 * The miss (2026-09-30, live drill S8): Claude Code's reply row read
 * `  $MDU:nomodel_Bash[66b7]` on the human's terminal. The run's own arbiter
 * (a worktree, with the human plane) refused nine `desymbolize` calls on its
 * DATA socket: the `mandu` the run launched came from a main checkout that
 * predated the human plane, and its reply filter still asked the data
 * socket. The filter passed every token through, and nothing said so.
 *
 *   (x1) pipe: the arbiter REFUSES every lookup with its real refusal text →
 *        the token passes through byte-exact (no original anywhere), the
 *        child's exit code stands, a `relay_mode` record carries
 *        `resolveFailure`, and the wrapper says it when the agent exits.
 *   (x2) PTY, the S8 reply as an inline renderer paints it, the arbiter
 *        refusing → the row reads the token (never blank, never a part), the
 *        record and the exit note as in (x1).
 *   (x3) PTY, the same reply, the arbiter answering → the row reads the
 *        value, no `$MDU` byte on the wire, no degraded record, no note.
 *   (x4) PTY, refused once then answered → a degraded record, then a plain
 *        `relay_mode` (recovered), and the second reply resolves.
 *   (x5) PTY, MAIN screen: the cell-diff split (`$MDU:` CHA `omodel_Bash…`,
 *        the !601 shape with this token) → no `$MDU` on the wire, the row
 *        reads the value.
 *   (x6) PTY, ALTERNATE screen: the token painted in two pieces around a
 *        cursor jump → the screen model repaints the value.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server, type Socket } from "node:net";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import * as xtermHeadlessNs from "@xterm/headless";

import { SPLIT_FRAME, SPLIT_ROW, SPLIT_SETUP } from "../unit/inline-split-fixtures.js";
import { ptyRelayAvailable } from "../../src/pty-relay.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

const HERE = dirname(fileURLToPath(import.meta.url));
const PKG_ROOT = join(HERE, "..", "..");
const RUN_TS = join(PKG_ROOT, "src", "run.ts");
const TSX_BIN = join(PKG_ROOT, "node_modules", ".bin", "tsx");
const SCRIPT_AVAILABLE = ptyRelayAvailable().ok;
const NO_BACKEND = "no PTY relay backend (util-linux or BSD script)";

/** The S8 token (one whole-result no-model symbol for the tainted Bash call). */
const TOKEN = "$MDU:nomodel_Bash[66b7]";
/** Short enough to sit on an 80-column row (a wider one is clipped, by design). */
const VALUE = "mdu-digest sha256=3f1c9a7e .env";
/** The same split as the !601 capture, this token: `Read[5ccd]` and
 *  `Bash[5ccd]` are the same width, so every cursor move still lands. */
const SPLIT_TOKEN_BASH = "$MDU:nomodel_Bash[5ccd]";
const SPLIT_FRAME_BASH = SPLIT_FRAME.replace("omodel_Read[5ccd]", "omodel_Bash[5ccd]");
const SPLIT_VALUE_BASH = "RC_PROBE_BASH_5527";
/** The arbiter's refusal on the data socket, verbatim (server.ts humanPlaneOnlyError). */
const REFUSAL = "human-plane: 'desymbolize' returns originals and is accepted only on the human socket (or the admin channel), never on the data socket";

/** The S8 reply as Claude Code 2.1.285's inline renderer paints it (the
 *  run's pane text, 2026-09-30): a bullet line, the token on its own
 *  indented row, the turn's status line. */
const S8_REPLY =
  "\r\n\x1b[38;5;231m●\x1b[39m It printed the following (Mandu masked it from me):\r\n" +
  `  ${TOKEN}\r\n\r\n`;
const S8_DONE = "\x1b[38;5;174m✻\x1b[39m Sautéed for 7s · done 9:15 AM\r\n";

interface Mock {
  server: Server;
  emitted: Array<Record<string, unknown>>;
  desymbolizeCalls: number;
}

/** A mock arbiter: `refuse` lookups are refused the way the data socket
 *  refuses them; after those, it answers. */
function startMock(sockPath: string, refuse: number): Mock {
  const m: Mock = { server: undefined as unknown as Server, emitted: [], desymbolizeCalls: 0 };
  m.server = createServer((c: Socket) => {
    let buf = "";
    c.setEncoding("utf8");
    c.on("error", () => { /* the wrapper may drop its connection at exit */ });
    c.on("data", (chunk: string) => {
      buf += chunk;
      let nl: number;
      while ((nl = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        if (line.trim() === "") continue;
        const req = JSON.parse(line) as { id: number; op: string; text?: string; event?: Record<string, unknown> };
        if (req.op === "desymbolize") {
          m.desymbolizeCalls += 1;
          if (m.desymbolizeCalls <= refuse) {
            c.write(JSON.stringify({ id: req.id, ok: false, error: REFUSAL }) + "\n");
            continue;
          }
          const text = (req.text ?? "").split(TOKEN).join(VALUE).split(SPLIT_TOKEN_BASH).join(SPLIT_VALUE_BASH);
          c.write(JSON.stringify({ id: req.id, ok: true, result: { text } }) + "\n");
          continue;
        }
        if (req.op === "emit" && req.event) m.emitted.push(req.event);
        c.write(JSON.stringify({ id: req.id, ok: true, result: req.op === "emit" ? { seq: m.emitted.length } : {} }) + "\n");
      }
    });
  });
  m.server.listen(sockPath);
  return m;
}

interface Run { code: number | null; stdout: string; stderr: string }

/** Run the wrapper around a child that prints `frames` (env-carried, `printf
 *  %s`) `gap` seconds apart and exits `exit`. */
async function runFrames(frames: string[], env: Record<string, string>, exit = 0, gap = 0.4): Promise<Run> {
  const script = frames.map((_, i) => `printf '%s' "$FRAME_${i}"; sleep ${gap}`).join("; ") + `; exit ${exit}`;
  const frameEnv: Record<string, string> = {};
  frames.forEach((f, i) => { frameEnv[`FRAME_${i}`] = f; });
  const child = spawn(TSX_BIN, [RUN_TS, "--", "bash", "-c", script], {
    env: { ...process.env, MANDU_ARBITER_SOCK: undefined, MANDU_LAUNCH_DISPLAY: undefined, ...frameEnv, ...env },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (c: string) => (stdout += c));
  child.stderr.on("data", (c: string) => (stderr += c));
  // Generous: a loaded CI host runs tsx and script slowly; the bound only
  // keeps a wedged wrapper from hanging the suite.
  const timer = setTimeout(() => child.kill("SIGKILL"), 90000);
  const [code] = (await once(child, "close")) as [number | null];
  clearTimeout(timer);
  return { code, stdout, stderr };
}

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

const relayModes = (m: Mock): Array<Record<string, unknown>> => m.emitted.filter((e) => e["kind"] === "relay_mode");

/** The record and the note every refused run must leave. */
function assertRefusalRecorded(m: Mock, r: Run, session: string): void {
  const modes = relayModes(m);
  const degraded = modes.filter((e) => typeof e["resolveFailure"] === "string");
  assert.equal(degraded.length, 1, `one degraded record: ${JSON.stringify(modes)}`);
  assert.equal(degraded[0]!["sessionId"], session);
  assert.match(String(degraded[0]!["resolveFailure"]), /^human-plane: 'desymbolize'/);
  const said = (degraded[0]!["input"] as { symbolized: string }).symbolized;
  assert.match(said, /DEGRADED: the arbiter did not resolve a placeholder/);
  assert.ok(!said.includes(VALUE), "the record names no original");
  assert.ok(!m.emitted.some((e) => e["kind"] === "desymbolize"), "nothing was resolved, so no desymbolize event");
  assert.match(r.stderr, /mandu-reply-filter: \d+ placeholder lookups? failed \(first: human-plane: 'desymbolize'.*nothing leaked/);
}

test("(x1) pipe: the arbiter refuses every lookup → the token passes byte-exact, recorded, and said at exit", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-rf-refused-"));
  const sock = join(dir, "arbiter.sock");
  const m = startMock(sock, Infinity);
  try {
    const r = await runFrames([`It printed: ${TOKEN}\n`], { MANDU_ARBITER_HUMAN_SOCK: sock, MANDU_SCOPE_ID: "rf-x1", MANDU_REPLY_FILTER_PTY: "0" }, 3, 0);
    assert.equal(r.code, 3, `the child's exit code stands; stderr: ${r.stderr}`);
    assert.equal(r.stdout, `It printed: ${TOKEN}\n`, "the reply passes through unchanged");
    assert.ok(m.desymbolizeCalls >= 1);
    assertRefusalRecorded(m, r, "rf-x1");
    assert.equal(relayModes(m)[0]!["mode"], "pipe", "the mode record comes first and keeps the mode");
  } finally {
    m.server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test(
  "(x2) PTY: the S8 reply with every lookup refused → the row reads the whole token; recorded; said at exit",
  { skip: !SCRIPT_AVAILABLE && NO_BACKEND },
  async () => {
    const dir = mkdtempSync(join(tmpdir(), "mandu-rf-refused-"));
    const sock = join(dir, "arbiter.sock");
    const m = startMock(sock, Infinity);
    try {
      const r = await runFrames([S8_REPLY, S8_DONE], { MANDU_ARBITER_HUMAN_SOCK: sock, MANDU_SCOPE_ID: "rf-x2", MANDU_REPLY_FILTER_PTY: "1" });
      assert.equal(r.code, 0, r.stderr);
      const rows = await renderRows(r.stdout);
      assert.ok(rows.includes(`  ${TOKEN}`), `the token stays whole on its row:\n${rows.join("\n")}`);
      assertRefusalRecorded(m, r, "rf-x2");
      assert.equal(relayModes(m)[0]!["mode"], "pty");
    } finally {
      m.server.close();
      rmSync(dir, { recursive: true, force: true });
    }
  },
);

test(
  "(x3) PTY: the S8 reply with the arbiter answering → the row reads the value; no `$MDU` on the wire; no note",
  { skip: !SCRIPT_AVAILABLE && NO_BACKEND },
  async () => {
    const dir = mkdtempSync(join(tmpdir(), "mandu-rf-refused-"));
    const sock = join(dir, "arbiter.sock");
    const m = startMock(sock, 0);
    try {
      const r = await runFrames([S8_REPLY, S8_DONE], { MANDU_ARBITER_HUMAN_SOCK: sock, MANDU_SCOPE_ID: "rf-x3", MANDU_REPLY_FILTER_PTY: "1" });
      assert.equal(r.code, 0, r.stderr);
      const rows = await renderRows(r.stdout);
      assert.ok(rows.includes(`  ${VALUE}`), `the value on the token's row:\n${rows.join("\n")}`);
      assert.doesNotMatch(r.stdout, /\$MDU/, "no token byte on the human's terminal stream");
      assert.ok(!relayModes(m).some((e) => "resolveFailure" in e), "no degraded record");
      assert.ok(m.emitted.some((e) => e["kind"] === "desymbolize"), "the resolution is on the record");
      assert.doesNotMatch(r.stderr, /placeholder lookup/);
    } finally {
      m.server.close();
      rmSync(dir, { recursive: true, force: true });
    }
  },
);

test(
  "(x4) PTY: refused once, then answered → a degraded record, then a recovered one; the later reply resolves",
  { skip: !SCRIPT_AVAILABLE && NO_BACKEND },
  async () => {
    const dir = mkdtempSync(join(tmpdir(), "mandu-rf-refused-"));
    const sock = join(dir, "arbiter.sock");
    const m = startMock(sock, 1);
    try {
      const r = await runFrames([`first ${TOKEN}\r\n`, `second ${TOKEN}\r\n`], { MANDU_ARBITER_HUMAN_SOCK: sock, MANDU_SCOPE_ID: "rf-x4", MANDU_REPLY_FILTER_PTY: "1" });
      assert.equal(r.code, 0, r.stderr);
      const rows = await renderRows(r.stdout);
      assert.ok(rows.includes(`second ${VALUE}`), `the later reply resolves:\n${rows.join("\n")}`);
      const modes = relayModes(m);
      const changes = modes.slice(1).map((e) => ("resolveFailure" in e ? "down" : "up"));
      assert.deepEqual(changes, ["down", "up"], JSON.stringify(modes));
      assert.match(r.stderr, /1 placeholder lookup failed/);
    } finally {
      m.server.close();
      rmSync(dir, { recursive: true, force: true });
    }
  },
);

test(
  "(x5) PTY, MAIN screen: the cell-diff split `$MDU:` CHA `omodel_Bash[5ccd]` never puts `$MDU` on the wire; the row reads the value",
  { skip: !SCRIPT_AVAILABLE && "util-linux script not available" },
  async () => {
    const dir = mkdtempSync(join(tmpdir(), "mandu-rf-refused-"));
    const sock = join(dir, "arbiter.sock");
    const m = startMock(sock, 0);
    try {
      // The TUI stays up while the reconciler paints (a quiet tail).
      const r = await runFrames([SPLIT_SETUP, SPLIT_FRAME_BASH, ""], { MANDU_ARBITER_HUMAN_SOCK: sock, MANDU_SCOPE_ID: "rf-x5", MANDU_REPLY_FILTER_PTY: "1" }, 0, 1.2);
      assert.equal(r.code, 0, r.stderr);
      assert.doesNotMatch(r.stdout, /\$MDU/, "no `$MDU` byte reaches the human's terminal stream");
      const rows = await renderRows(r.stdout);
      assert.ok(rows[SPLIT_ROW]!.includes(SPLIT_VALUE_BASH), `row ${SPLIT_ROW} reads the value:\n${rows.join("\n")}`);
    } finally {
      m.server.close();
      rmSync(dir, { recursive: true, force: true });
    }
  },
);

test(
  "(x6) PTY, ALTERNATE screen: the token painted in two pieces around a cursor jump → the value repainted",
  { skip: !SCRIPT_AVAILABLE && NO_BACKEND },
  async () => {
    const dir = mkdtempSync(join(tmpdir(), "mandu-rf-refused-"));
    const sock = join(dir, "arbiter.sock");
    const m = startMock(sock, 0);
    try {
      const frames = [
        "\x1b[?1049h\x1b[H\x1b[2J\x1b[3;3H$MDU:nomodel_\x1b[10;1Hstatus\x1b[3;16H",
        "Bash[66b7]\x1b[10;1Hstatus done\x1b[11;1H",
        "",
      ];
      const r = await runFrames(frames, { MANDU_ARBITER_HUMAN_SOCK: sock, MANDU_SCOPE_ID: "rf-x6", MANDU_REPLY_FILTER_PTY: "1" }, 0, 1.2);
      assert.equal(r.code, 0, r.stderr);
      const rows = await renderRows(r.stdout);
      assert.equal(rows[2], `  ${VALUE}`, `screen was:\n${rows.join("\n")}`);
      assert.ok(!rows.join("\n").includes("$MDU"), "no token text on the screen");
    } finally {
      m.server.close();
      rmSync(dir, { recursive: true, force: true });
    }
  },
);
