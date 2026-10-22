/**
 * launch-timings e2e — every launch times its named steps
 * (runtime-instances.md §14.11), through the real CLI entry (main → parse →
 * services → spawn → teardown) against a Unix-socket mock arbiter:
 *
 *   - the `launch_posture` event carries the steps before the agent, in
 *     launch order, from the documented set;
 *   - the `session_exit` event carries the agent's run and the teardown;
 *   - the launch's own log ends with the whole launch's record (what
 *     `mandu log --timings` reads back);
 *   - a normal launch prints none of it; a `--verbose` one prints the
 *     breakdown on stderr after everything else it said.
 *
 * Mode `off` (stated): the timings are the same machinery in every mode; the
 * mock arbiter cannot serve a secret setup.
 */
import { test } from "node:test";
import "../lib/private-home.js"; // the Mandu home and the agents' trust files go to temp (test-organization.md §8.4)
import { PRIVATE_MANDU_HOME } from "../lib/private-home.js";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:net";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { once } from "node:events";
import { launchLogs } from "../lib/launch-log-read.js";
import { main } from "../lib/launch-in-dir.js";
import { answerUnavailable } from "../lib/unanswered-arbiter.js";
import { asLaunchTimings, LAUNCH_STEPS, timingsFromLog, type LaunchTimings } from "../../src/launch-timings.js";
import { runLog } from "../../src/launch-log.js";

const KNOWN = new Set<string>(LAUNCH_STEPS.map(([n]) => n));
const ORDER: string[] = LAUNCH_STEPS.map(([n]) => n);

async function withRecordingArbiter(fn: (sock: string, dir: string, events: () => Array<Record<string, unknown>>) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-e2e-timings-"));
  const sock = join(dir, "arbiter.sock");
  const lines: string[] = [];
  const srv: Server = createServer(answerUnavailable((l) => { lines.push(l); }));
  srv.listen(sock);
  await once(srv, "listening");
  const events = (): Array<Record<string, unknown>> => lines.flatMap((l) => {
    try {
      const m = JSON.parse(l) as { op?: string; event?: Record<string, unknown> };
      return m.op === "emit" && m.event ? [m.event] : [];
    } catch { return []; }
  });
  try { await fn(sock, dir, events); } finally {
    srv.close(); rmSync(dir, { recursive: true, force: true });
  }
}

function fakeClaude(dir: string): { bin: string; ran: string } {
  const binDir = join(dir, "bin");
  mkdirSync(binDir, { recursive: true });
  const bin = join(binDir, "claude");
  const ran = join(binDir, "ran");
  writeFileSync(bin, `#!/bin/sh\nif [ "$1" = --version ]; then echo '2.1.0 (Claude Code)'; exit 0; fi\ntouch '${ran}'\n`);
  chmodSync(bin, 0o755);
  return { bin, ran };
}

async function launch(argv: string[], env: Record<string, string | undefined>): Promise<{ code: number; lines: string[]; logPath: string }> {
  const lines: string[] = [];
  const orig = console.error;
  const before = launchLogs(env);
  console.error = (...a: unknown[]) => { lines.push(a.map(String).join(" ")); };
  try {
    const code = await main(argv, env);
    return { code, lines, logPath: before.newPath() };
  } finally {
    console.error = orig;
  }
}

/** The steps' names in the order they appear, each documented and in the documented order. */
function assertOrdered(t: LaunchTimings, what: string): string[] {
  const names = t.steps.map((s) => s.step);
  for (const n of names) assert.ok(KNOWN.has(n), `${what}: ${n} is a documented step`);
  const idx = names.map((n) => ORDER.indexOf(n));
  assert.deepEqual(idx, [...idx].sort((a, b) => a - b), `${what}: in launch order (${names.join(", ")})`);
  for (const s of t.steps) assert.ok(Number.isInteger(s.ms) && s.ms >= 0, `${what}: ${s.step} has a time`);
  return names;
}

test("a launch's steps: before the agent on launch_posture, the agent and the teardown on session_exit, the whole in its log; nothing printed by default", async () => {
  await withRecordingArbiter(async (sock, dir, events) => {
    const { bin, ran } = fakeClaude(dir);
    const env = {
      HOME: dir, PWD: dir, MANDU_ARBITER_SOCK: sock, PATH: process.env["PATH"], ANTHROPIC_API_KEY: "sk-e2e-unused",
      MANDU_NO_CONTEXT_PROXY: "1", MANDU_HOME: PRIVATE_MANDU_HOME, MANDU_MODE: "off", XDG_RUNTIME_DIR: dir,
    };
    const r = await launch(["--no-scope", "--no-reply-filter", "--", bin], env);
    assert.equal(r.code, 0);
    assert.ok(existsSync(ran), "the agent ran");

    const posture = events().find((e) => e["kind"] === "launch_posture");
    assert.ok(posture, "a launch_posture event reached the arbiter");
    const before = asLaunchTimings(posture!["timings"]);
    assert.ok(before, `the posture event carries a timings record: ${JSON.stringify(posture!["timings"])}`);
    const names = assertOrdered(before!, "launch_posture");
    for (const n of ["plan", "arbiter", "services", "confine", "key-grants", "secrets", "env-secrets", "compose", "record", "banner"]) {
      assert.ok(names.includes(n), `launch_posture has ${n}: ${names.join(", ")}`);
    }
    assert.ok(!names.some((n) => n === "agent" || n.startsWith("teardown.")), "nothing after the agent's start on the posture event");
    assert.ok(!names.includes("node"), "an in-process launch has no process start to count from");
    const sum = before!.steps.filter((s) => !s.step.includes(".")).reduce((a, s) => a + s.ms, 0);
    // Each top-level step carries its cost (CPU time, git calls, sandboxes);
    // a part does not. Mode off: no secret setup, so its step asks no git.
    for (const s of before!.steps) {
      if (s.step.includes(".")) assert.equal(s.git, undefined, `${s.step}: a part carries no cost`);
      else assert.ok([s.cpuMs, s.git, s.sandboxes].every((x) => Number.isInteger(x) && x! >= 0), `${s.step}: its cost: ${JSON.stringify(s)}`);
    }
    assert.equal(before!.steps.find((s) => s.step === "secrets")?.git, 0, "mode off: the secret step asks no git");
    assert.ok(sum <= before!.totalMs + before!.steps.length, `the steps fit in the total (${sum} <= ${before!.totalMs})`);

    const exit = events().find((e) => e["kind"] === "session_exit");
    assert.ok(exit, "a session_exit event reached the arbiter");
    const after = asLaunchTimings(exit!["timings"]);
    assert.ok(after);
    const tail = assertOrdered(after!, "session_exit");
    assert.equal(tail[0], "agent", "the agent's run first");
    for (const n of ["teardown.index", "teardown.services", "teardown.notices", "teardown.placeholder"]) assert.ok(tail.includes(n), `session_exit has ${n}: ${tail.join(", ")}`);
    assert.ok(after!.totalMs >= before!.totalMs);

    // The launch's log: the record before the agent, and the whole launch's last.
    const text = readFileSync(r.logPath, "utf8");
    const whole = timingsFromLog(text);
    assert.ok(whole);
    const all = assertOrdered(whole!, "the launch's log");
    assert.ok(all.includes("plan") && all.includes("agent") && all.includes("teardown.records"), all.join(", "));
    assert.equal(text.split("\n").filter((l) => l.startsWith("mandu: launch timings ")).length, 2);

    // A normal launch prints none of it.
    assert.ok(!r.lines.some((l) => /launch timings/.test(l)), JSON.stringify(r.lines));

    // `mandu log --timings` reads it back.
    const out: string[] = [];
    assert.equal(runLog(["--timings"], { ...env }, { out: (s) => { out.push(s); }, err: () => {} }), 0);
    assert.match(out.join(""), /^step \(ms\)/);
    assert.match(out.join(""), /\nteardown\.services +\d+/);
  });
});

test("--verbose: the breakdown is printed on stderr after everything else the launch said", async () => {
  await withRecordingArbiter(async (sock, dir) => {
    const { bin } = fakeClaude(dir);
    const env = {
      HOME: dir, PWD: dir, MANDU_ARBITER_SOCK: sock, PATH: process.env["PATH"], ANTHROPIC_API_KEY: "sk-e2e-unused",
      MANDU_NO_CONTEXT_PROXY: "1", MANDU_HOME: PRIVATE_MANDU_HOME, MANDU_MODE: "off", XDG_RUNTIME_DIR: dir,
    };
    const r = await launch(["--verbose", "--no-scope", "--no-reply-filter", "--", bin], env);
    assert.equal(r.code, 0);
    const at = r.lines.findIndex((l) => /^mandu: launch timings: \d+ ms in all \(cpu \d+ ms, \d+ git, \d+ sandbox(es)?\)$/.test(l));
    assert.ok(at >= 0, JSON.stringify(r.lines.slice(-30)));
    const rest = r.lines.slice(at + 1);
    assert.ok(rest.length > 5 && rest.every((l) => /^ {2,4}[a-z.-]+ +\d+ ms( {3}cpu \d+ ms, \d+ git, \d+ sandbox(es)?)?$/.test(l)), `only the breakdown after it: ${JSON.stringify(rest)}`);
    assert.ok(rest.some((l) => /^ {2}agent +\d+ ms {3}cpu \d+ ms, 0 git, 0 sandboxes$/.test(l)), "a top-level step with its cost (the agent's: no git of the launcher's)");
  });
});
