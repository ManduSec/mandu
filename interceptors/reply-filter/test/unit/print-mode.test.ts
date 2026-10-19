/**
 * print-mode.test — unit tests for the pure TTY-safety decision
 * (src/print-mode.ts) that lets the launcher enable the reply filter BY
 * DEFAULT without breaking interactive TUI runs.
 *
 * The contract under test (three-way mode):
 *   - stdout NOT a TTY → "pipe", regardless of argv (a pipe is exactly where
 *     the filter works — this is the posture the e2e suite exercises).
 *   - stdout IS a TTY → "pipe" for KNOWN print-mode invocations
 *     (`claude -p/--print …`, `codex exec …`); everything else → "pty" (the
 *     PTY relay keeps the TUI on a real terminal while output is filtered).
 *   - MANDU_REPLY_FILTER_PTY=0 at the call site → interactive TTY runs fall
 *     back to "passthrough" (the pre-relay behavior; symbols stay opaque).
 *   - MANDU_REPLY_FILTER_PTY=1 → "pty" even when stdout is a pipe.
 *   - force (MANDU_REPLY_FILTER_FORCE=1 at the call site) → always "pipe".
 *
 * Tests import THIS pure module, never src/run.ts — run.ts executes main()
 * at module load.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { decideMode } from "../../src/print-mode.js";

test("non-TTY → pipe regardless of argv (piped/captured runs)", () => {
  // Even an interactive-looking `claude` pipe-filters when stdout is a pipe.
  assert.equal(decideMode(["claude"], false).mode, "pipe");
  assert.equal(decideMode(["claude", "-p", "summarize"], false).mode, "pipe");
  assert.equal(decideMode(["codex"], false).mode, "pipe");
  assert.equal(decideMode(["some-unknown-tool", "--flag"], false).mode, "pipe");
  assert.equal(decideMode(["bash", "-c", "echo hi"], false).mode, "pipe");
});

test("TTY + claude PRINT mode (-p / --print) → pipe", () => {
  assert.equal(decideMode(["claude", "-p", "summarize ./notes.md"], true).mode, "pipe");
  assert.equal(decideMode(["claude", "--print", "summarize"], true).mode, "pipe");
  // basename handling: an absolute argv[0] still counts as `claude`.
  assert.equal(decideMode(["/usr/local/bin/claude", "-p", "x"], true).mode, "pipe");
});

test("TTY + interactive claude (no -p/--print) → PTY relay (TUI keeps a real terminal)", () => {
  const d = decideMode(["claude"], true);
  assert.equal(d.mode, "pty");
  assert.match(d.reason, /PTY relay/);
  // Other flags don't count as print mode.
  assert.equal(decideMode(["claude", "--resume", "abc"], true).mode, "pty");
});

test("TTY + codex exec → pipe; TTY + codex (no exec) → PTY relay", () => {
  assert.equal(decideMode(["codex", "exec", "summarize ./notes.md"], true).mode, "pipe");
  // `exec` found as the FIRST subcommand even behind leading flags.
  assert.equal(decideMode(["/opt/bin/codex", "--json", "exec", "x"], true).mode, "pipe");
  assert.equal(decideMode(["codex"], true).mode, "pty");
  assert.equal(decideMode(["codex", "resume"], true).mode, "pty");
});

test("TTY + openclaw agent one-shot → pipe; openclaw tui / bare → PTY relay", () => {
  assert.equal(
    decideMode(["openclaw", "agent", "--local", "--agent", "main", "-m", "hi", "--json"], true).mode,
    "pipe",
  );
  assert.equal(decideMode(["/usr/local/bin/openclaw", "agent", "-m", "x"], true).mode, "pipe");
  // The TUI (a gateway-client full-screen app) and anything else stay relayed.
  assert.equal(decideMode(["openclaw", "tui"], true).mode, "pty");
  assert.equal(decideMode(["openclaw"], true).mode, "pty");
  // Source-checkout form: basename is `node` — not recognized, PTY relay
  // (documented limitation, same as any interpreter-launched agent).
  assert.equal(decideMode(["node", "openclaw.mjs", "agent", "-m", "x"], true).mode, "pty");
  // Non-TTY unchanged.
  assert.equal(decideMode(["openclaw", "agent", "-m", "x"], false).mode, "pipe");
});

test("TTY + opencode run one-shot → pipe; opencode TUI (default cmd) → PTY relay", () => {
  assert.equal(decideMode(["opencode", "run", "--format", "json", "hi"], true).mode, "pipe");
  assert.equal(decideMode(["/opt/bin/opencode", "run", "x"], true).mode, "pipe");
  // The flagless default command IS the TUI — must keep the relay.
  assert.equal(decideMode(["opencode"], true).mode, "pty");
  assert.equal(decideMode(["opencode", "/some/project"], true).mode, "pty");
  assert.equal(decideMode(["opencode", "serve"], true).mode, "pty");
  // Non-TTY unchanged.
  assert.equal(decideMode(["opencode", "run", "x"], false).mode, "pipe");
});

test("TTY + unknown command → PTY relay (interactive default)", () => {
  assert.equal(decideMode(["vim", "notes.md"], true).mode, "pty");
  assert.equal(decideMode(["bash"], true).mode, "pty");
  // `-p` on a NON-claude command does not trigger print mode.
  assert.equal(decideMode(["mytool", "-p"], true).mode, "pty");
  // Degenerate empty argv: still relayed on a TTY.
  assert.equal(decideMode([], true).mode, "pty");
});

test("MANDU_REPLY_FILTER_PTY=0 → interactive TTY runs fall back to passthrough", () => {
  const d = decideMode(["claude"], true, { ptyOverride: "0" });
  assert.equal(d.mode, "passthrough");
  assert.match(d.reason, /MANDU_REPLY_FILTER_PTY=0/);
  // Pipe cases are unaffected by the opt-out.
  assert.equal(decideMode(["claude"], false, { ptyOverride: "0" }).mode, "pipe");
  assert.equal(decideMode(["claude", "-p", "x"], true, { ptyOverride: "0" }).mode, "pipe");
});

test("MANDU_REPLY_FILTER_PTY=1 → PTY relay even when stdout is a pipe (test hook)", () => {
  const d = decideMode(["claude"], false, { ptyOverride: "1" });
  assert.equal(d.mode, "pty");
  assert.match(d.reason, /MANDU_REPLY_FILTER_PTY=1/);
  assert.equal(decideMode(["vim"], true, { ptyOverride: "1" }).mode, "pty");
});

test("force override → pipe even for an interactive command on a TTY", () => {
  assert.equal(decideMode(["claude"], true, { force: true }).mode, "pipe");
  assert.equal(decideMode(["vim"], true, { force: true }).mode, "pipe");
  assert.match(decideMode(["claude"], true, { force: true }).reason, /FORCE/);
  // force beats the pty override (documented precedence).
  assert.equal(decideMode(["claude"], true, { force: true, ptyOverride: "1" }).mode, "pipe");
});

test("decisions carry a human-readable reason", () => {
  for (const d of [
    decideMode(["claude"], false),
    decideMode(["claude", "-p", "x"], true),
    decideMode(["claude"], true),
    decideMode(["claude"], true, { ptyOverride: "0" }),
    decideMode(["codex", "exec", "x"], true),
  ]) {
    assert.equal(typeof d.reason, "string");
    assert.ok(d.reason.length > 0);
  }
});
