/**
 * agent-version e2e — the launch-time agent-version check through the real CLI
 * entry (main → parse → launchVersionCheck → spawn), against a Unix-socket mock
 * arbiter (release checklist e4; agent-versions.ts; supported-agents.md).
 *
 * A stand-in `claude` answers `--version` with a version OUTSIDE the tested
 * range: the launch keeps ONE warning line naming the tested range (counted
 * on the default banner, in full in the launch's log and under --verbose), STILL
 * starts the agent (a warning, never a refusal), and puts the check on the
 * `launch_posture` event the dashboard reads. An in-range stand-in prints no
 * version line at all.
 */
import { test } from "node:test";
import "../lib/private-home.js"; // daemons' npm cache, the Mandu home and agent trust files go to temp, not the real HOME (test-organization.md §8.4)
import { PRIVATE_MANDU_HOME } from "../lib/private-home.js";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:net";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { once } from "node:events";
import { launchLogs } from "../lib/launch-log-read.js";
import { main } from "../lib/launch-in-dir.js"; // the launch is for the env's PWD (launch-cwd.ts)
import { TESTED_AGENT_VERSIONS } from "../../src/agent-versions.js";
import { answerUnavailable } from "../lib/unanswered-arbiter.js";

/** A mock arbiter that records every NDJSON line it receives. */
async function withRecordingArbiter(fn: (sock: string, dir: string, received: () => string) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-e2e-ver-"));
  const sock = join(dir, "arbiter.sock");
  let buf = "";
  const srv: Server = createServer(answerUnavailable((l) => { buf += `${l}\n`; }));
  srv.listen(sock);
  await once(srv, "listening");
  try { await fn(sock, dir, () => buf); } finally {
    srv.close(); rmSync(dir, { recursive: true, force: true });
  }
}

/** A stand-in `claude`: prints `version` for --version, else touches `ran`. */
function fakeClaude(dir: string, version: string): { bin: string; ran: string } {
  const binDir = join(dir, `bin-${version.replace(/\W/g, "_")}`);
  mkdirSync(binDir);
  const bin = join(binDir, "claude");
  const ran = join(binDir, "ran");
  writeFileSync(bin, `#!/bin/sh\nif [ "$1" = --version ]; then echo '${version} (Claude Code)'; exit 0; fi\ntouch '${ran}'\n`);
  chmodSync(bin, 0o755);
  return { bin, ran };
}

/** One launch: its exit code, the terminal's lines, and its own log's (launch-log.ts). */
async function launch(argv: string[], env: Record<string, string | undefined>): Promise<{ code: number; lines: string[]; log: string[] }> {
  const lines: string[] = [];
  const orig = console.error;
  const before = launchLogs(env);
  console.error = (...a: unknown[]) => { lines.push(a.map(String).join(" ")); };
  try {
    const code = await main(argv, env);
    return { code, lines, log: before.newLines() };
  } finally {
    console.error = orig;
  }
}

test("an out-of-range claude: ONE warning line with the tested range, the agent still launches, the check is on the posture event", async () => {
  await withRecordingArbiter(async (sock, dir, received) => {
    const { bin, ran } = fakeClaude(dir, "9.0.0");
    const env = {
      HOME: dir, PWD: dir, MANDU_ARBITER_SOCK: sock, PATH: process.env["PATH"], ANTHROPIC_API_KEY: "sk-e2e-unused",
      MANDU_NO_CONTEXT_PROXY: "1", MANDU_HOME: PRIVATE_MANDU_HOME, MANDU_MODE: "off", XDG_RUNTIME_DIR: dir,
    };
    const r = await launch(["--no-scope", "--no-reply-filter", "--", bin], env);
    assert.equal(r.code, 0, "a warning, never a refusal");
    assert.ok(existsSync(ran), "the agent ran");
    const { min, max } = TESTED_AGENT_VERSIONS.claude;
    // The default display (packaging.md §5, 2026-10-18): the banner counts
    // the notice; the launch's log holds the one warning line, in full.
    assert.ok(!r.lines.some((l) => /than (Mandu has )?tested|version \(/.test(l)), JSON.stringify(r.lines));
    assert.match(r.lines.find((l) => / mode · /.test(l)) ?? "", / · \d+ notices?: `mandu log`$/, JSON.stringify(r.lines));
    const logged = r.log.filter((l) => /than (Mandu has )?tested|version \(/.test(l));
    assert.equal(logged.length, 1, JSON.stringify(r.log));
    assert.ok(logged[0]!.startsWith(`mandu: WARNING — Claude Code 9.0.0 is newer than tested (Mandu was tested with Claude Code ${min} to ${max})`), logged[0]);
    const posture = received().split("\n").find((l) => l.includes("\"launch_posture\""));
    assert.ok(posture, "the launch_posture event reached the arbiter");
    assert.match(posture!, /"agentVersion":\{"agent":"claude","name":"Claude Code","min":"[^"]+","max":"[^"]+","version":"9\.0\.0","verdict":"newer"\}/);
    // The full warning is kept on the record, and printed under --verbose.
    assert.ok(posture!.includes(`Claude Code 9.0.0 is newer than tested (Mandu was tested with Claude Code ${min} to ${max})`), posture);
    const v = await launch(["--verbose", "--no-scope", "--no-reply-filter", "--", bin], env);
    assert.equal(v.code, 0);
    const full = v.lines.filter((l) => /than (Mandu has )?tested/.test(l));
    assert.equal(full.length, 1, JSON.stringify(v.lines));
    assert.ok(full[0]!.startsWith(`mandu: WARNING — Claude Code 9.0.0 is newer than tested (Mandu was tested with Claude Code ${min} to ${max})`), full[0]);
  });
});

test("an in-range claude prints no version line", async () => {
  await withRecordingArbiter(async (sock, dir) => {
    const { bin, ran } = fakeClaude(dir, TESTED_AGENT_VERSIONS.claude.max);
    const env = {
      HOME: dir, PWD: dir, MANDU_ARBITER_SOCK: sock, PATH: process.env["PATH"], ANTHROPIC_API_KEY: "sk-e2e-unused",
      MANDU_NO_CONTEXT_PROXY: "1", MANDU_HOME: PRIVATE_MANDU_HOME, MANDU_MODE: "off", XDG_RUNTIME_DIR: dir,
    };
    const r = await launch(["--no-scope", "--no-reply-filter", "--", bin], env);
    assert.equal(r.code, 0);
    assert.ok(existsSync(ran));
    assert.ok(!r.lines.some((l) => /than (Mandu has )?tested|could not read the Claude Code version/.test(l)), JSON.stringify(r.lines));
  });
});
