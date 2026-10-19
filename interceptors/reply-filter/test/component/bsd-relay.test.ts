/**
 * bsd-relay.test — E2E for the macOS PTY relay (src/pty-relay.ts BSD flavor +
 * the src/bsd-relay.ts companion), through a REAL terminal.
 *
 * The wrapper (src/run.ts under tsx, as the launcher runs it from source) runs
 * inside an OUTER pseudo-terminal that stands in for the human's terminal: a
 * BSD `script -q /dev/null bash -c …` the test holds, so the wrapper's stdin
 * and stdout are a real TTY and it takes the PTY relay on its own (no
 * MANDU_REPLY_FILTER_PTY=1). Its child runs behind the INNER BSD script, on a
 * pty of its own. The test resizes the outer terminal with `stty -f` — a
 * TIOCSWINSZ, the same thing a terminal emulator does on a window resize — and
 * signals the wrapper the way the launcher does.
 *
 *   (k) RESIZE: the outer terminal grows 24x80 → 40x120; the child behind the
 *       inner script sees 40x120 (`stty size` in its SIGWINCH trap), and a
 *       reply printed after the resize still resolves. Before the companion,
 *       BSD script never re-sized its pty: the child stayed 24x80.
 *   (l) SIGTERM to the wrapper reaches the CHILD as SIGTERM (not the SIGHUP
 *       of a killed script, whose master is gone before the child can say
 *       so), the child's last output arrives, the wrapper exits 143 though
 *       BSD script reported the bare 15, and the terminal ends in the mode it
 *       started in.
 *
 * darwin only: the companion exists for BSD script. On Linux, util-linux
 * script re-sizes on SIGWINCH and relays SIGTERM itself; its resize is
 * covered by the differential harness's resize-reflow scenario
 * (docs/testing/differential-interactive.md §18).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server, type Socket } from "node:net";
import { execFileSync, spawn, type ChildProcess } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { ptyRelayAvailable } from "../../src/pty-relay.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const PKG_ROOT = join(HERE, "..", "..");
const RUN_TS = join(PKG_ROOT, "src", "run.ts");
const TSX_BIN = join(PKG_ROOT, "node_modules", ".bin", "tsx");

const SYM = "$MDU:Read[9b0a]";
const RAW = "# Project notes — TODO: ship the proxy.";

const SKIP = process.platform !== "darwin"
  ? "macOS only (the BSD script companion)"
  : !ptyRelayAvailable().ok && "no BSD script(1)";

/** The NDJSON mock arbiter (the run.test.ts shape): resolves SYM, records emits. */
function startMockArbiter(sockPath: string): Server {
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
        const req = JSON.parse(line) as { id: number | string; op: string; text?: string };
        const result = req.op === "desymbolize" ? { text: (req.text ?? "").split(SYM).join(RAW) } : { seq: 1 };
        c.write(JSON.stringify({ id: req.id, ok: true, result }) + "\n");
      }
    });
  });
  server.listen(sockPath);
  return server;
}

/**
 * The outer terminal: BSD script running bash, which prints its tty, sizes it
 * 24x80, records the terminal mode, runs the wrapper around `child` (a bash
 * body), then prints the wrapper's exit code and the terminal mode again.
 *
 * The outer script's stdin is /dev/null. BSD script tolerates only ENOTTY
 * from tcgetattr on its stdin: node's "pipe" stdio is a socketpair and a
 * macOS FIFO is a socket too, and with either it exits at once
 * ("tcgetattr/ioctl: Operation not supported on socket"). At EOF the outer
 * script queues one VEOF on the outer terminal, which the inner script's
 * TCSAFLUSH discards when it takes that terminal raw.
 */
class OuterTerminal {
  readonly proc: ChildProcess;
  private buf = "";
  private waiters: Array<() => void> = [];

  constructor(child: string, env: Record<string, string>) {
    const body =
      'echo "OUTER=$(tty)"; stty rows 24 cols 80; echo "MODE0=$(stty -a | grep lflags)"; ' +
      '"$RF_TSX" "$RF_RUN" -- bash -c "$RF_CHILD"; echo "RC=$?"; echo "MODE1=$(stty -a | grep lflags)"';
    this.proc = spawn("script", ["-q", "/dev/null", "bash", "-c", body], {
      env: {
        ...process.env,
        MANDU_ARBITER_SOCK: undefined,
        MANDU_ARBITER_HUMAN_SOCK: undefined,
        MANDU_SCOPE_ID: undefined,
        MANDU_REPLY_FILTER_PTY: undefined,
        MANDU_REPLY_FILTER_FORCE: undefined,
        MANDU_LAUNCH_DISPLAY: undefined,
        ...env,
        RF_TSX: TSX_BIN,
        RF_RUN: RUN_TS,
        RF_CHILD: child,
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    const take = (c: string): void => {
      this.buf += c;
      for (const w of this.waiters.splice(0)) w();
    };
    this.proc.stdout!.setEncoding("utf8");
    this.proc.stderr!.setEncoding("utf8");
    this.proc.stdout!.on("data", take);
    this.proc.stderr!.on("data", take);
  }

  /** Everything the terminal showed so far, CRs dropped. */
  get text(): string {
    return this.buf.replace(/\r/g, "");
  }

  async waitFor(re: RegExp, ms = 15_000): Promise<RegExpExecArray> {
    const deadline = Date.now() + ms;
    for (;;) {
      const m = re.exec(this.text);
      if (m) return m;
      const left = deadline - Date.now();
      if (left <= 0) throw new Error(`timed out waiting for ${re}; the terminal showed:\n${this.text}`);
      await new Promise<void>((resolve) => {
        const t = setTimeout(resolve, left);
        this.waiters.push(() => { clearTimeout(t); resolve(); });
      });
    }
  }

  /** End the session: wait briefly for the outer script to finish on its
   *  own, else kill it (its pty closing hangs up everything inside). */
  async close(): Promise<void> {
    if (this.proc.exitCode === null && this.proc.signalCode === null) {
      const done = new Promise((r) => this.proc.once("close", r));
      const t = setTimeout(() => this.proc.kill("SIGKILL"), 3000);
      await done;
      clearTimeout(t);
    }
  }
}

test("(k) BSD relay: a terminal resize reaches the child behind the inner script; the reply still resolves", { skip: SKIP }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-bsdrelay-"));
  const sock = join(dir, "arbiter.sock");
  const server = startMockArbiter(sock);
  // The "TUI": report the size at start and on every SIGWINCH; after the first
  // resize print a reply carrying the token and exit 7.
  const child =
    'n=0; trap \'echo "WINCH $(stty size)"; n=$((n+1))\' WINCH; echo "START $(stty size)"; ' +
    'while [ "$n" -lt 1 ]; do sleep 0.05; done; echo "Summary: ${TEST_SYM}"; exit 7';
  const term = new OuterTerminal(child, { MANDU_ARBITER_HUMAN_SOCK: sock, MANDU_SCOPE_ID: "bsd-relay-k", TEST_SYM: SYM });
  try {
    const outer = (await term.waitFor(/OUTER=(\/dev\/ttys\d+)/))[1]!;
    await term.waitFor(/START 24 80\n/);
    // The window grows: TIOCSWINSZ on the outer terminal → SIGWINCH to its
    // foreground group (the wrapper and the inner script; BSD script ignores it).
    execFileSync("stty", ["-f", outer, "rows", "40", "cols", "120"]);
    await term.waitFor(/WINCH 40 120\n/);
    await term.waitFor(/RC=\d+/);
    const out = term.text;
    assert.match(out, /RC=7\n/, "the child's exit code propagates through both scripts");
    assert.match(out, /PTY RELAY \(BSD script\)/, "the wrapper took the PTY relay on its own (real TTY)");
    assert.ok(out.includes(RAW), `the reply after the resize resolves; the terminal showed:\n${out}`);
    assert.ok(!out.includes("$MDU:"), "no opaque token reaches the human");
    assert.equal((out.match(/WINCH /g) ?? []).length, 1, "one resize, one SIGWINCH (the start-up sync changed nothing)");
  } finally {
    await term.close();
    server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("(l) BSD relay: SIGTERM reaches the child itself, the terminal mode is restored, the wrapper exits 143", { skip: SKIP }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-bsdrelay-"));
  const sock = join(dir, "arbiter.sock");
  const server = startMockArbiter(sock);
  // The child names the wrapper (its parent is the inner script, whose parent
  // is the wrapper), then dies by whatever it is sent, saying which.
  const child =
    'echo "WRAPPER=$(ps -o ppid= -p $PPID | tr -d " ")"; ' +
    "trap 'echo GOT-TERM; trap - TERM; kill -TERM $$' TERM; " +
    "trap 'echo GOT-HUP; trap - HUP; kill -HUP $$' HUP; " +
    "echo READY; while :; do sleep 0.05; done";
  const term = new OuterTerminal(child, { MANDU_ARBITER_HUMAN_SOCK: sock });
  try {
    const wrapper = Number((await term.waitFor(/WRAPPER=(\d+)\n/))[1]);
    await term.waitFor(/READY\n/);
    // Give the companion its first snapshots (it locates the child within
    // milliseconds of script's start; a signal before that goes to script).
    await new Promise((r) => setTimeout(r, 300));
    process.kill(wrapper, "SIGTERM");
    await term.waitFor(/MODE1=.*\n/);
    const out = term.text;
    assert.match(out, /GOT-TERM/, `the child got the SIGTERM; the terminal showed:\n${out}`);
    assert.doesNotMatch(out, /GOT-HUP/, "not the SIGHUP of a killed script");
    assert.match(out, /RC=143\n/, "a death by the SIGTERM the relay delivered reads 128+15");
    const mode0 = /MODE0=(.*)\n/.exec(out)![1];
    const mode1 = /MODE1=(.*)\n/.exec(out)![1];
    assert.equal(mode1, mode0, "script restored the terminal mode it found (not left raw)");
    assert.match(mode1!, /lflags: icanon /, "cooked again");
  } finally {
    await term.close();
    server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
