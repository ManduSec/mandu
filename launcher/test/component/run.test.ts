/**
 * run.test — E2E: launch a fake agent under mandu main() against a real
 * Unix-socket mock arbiter, and assert the composed context. Plus the
 * fail-closed oracle: arbiter unreachable → main() refuses (throws).
 *
 * PROJECT INVARIANT (fail-closed): no reachable arbiter → the agent is NOT
 * launched (spec §5). This test is that invariant's oracle for the launcher.
 */
import { test } from "node:test";
import "../lib/private-home.js"; // daemons' npm cache, the Mandu home and agent trust files go to temp, not the real HOME (test-organization.md §8.4)
import { PRIVATE_MANDU_HOME } from "../lib/private-home.js";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:net";
import { mkdtempSync, rmSync, chmodSync, existsSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { once } from "node:events";
import { main as mainIn } from "../lib/launch-in-dir.js"; // the launch is for the env's PWD (launch-cwd.ts)
import { hermetic } from "../lib/test-runtime.js";
import { isAttentionNote, NOTICE_PREFIX, POSTURE_PREFIX } from "../../src/launch-banner.js";
import { launchLogs } from "../lib/launch-log-read.js";
import { answerUnavailable } from "../lib/unanswered-arbiter.js";
import { standInService } from "../lib/stand-in-service.js";

/** main with this file's own runtime dir when the env names none: a launch
 *  resolves (and checks) the runtime base, and an env without one would make
 *  that the host's shared /tmp/mandu (test-runtime.ts). */
const main = hermetic(mainIn, 1);

const HERE = dirname(fileURLToPath(import.meta.url));
const FAKE = join(HERE, "..", "fixtures", "fake-agent.sh");
/** The Linux rungs' wiring (stand-in exec-box / landlock-net / net-guard
 *  bins): on macOS the launcher never looks for them, and the Seatbelt
 *  profile that replaces them is proven by test/darwin/seatbelt-live.test.ts. */
const LINUX_RUNGS = process.platform === "linux" ? false : "Linux rungs (macOS: test/darwin/seatbelt-live.test.ts)";

async function withMockArbiter(fn: (sock: string) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-e2e-"));
  const sock = join(dir, "arbiter.sock");
  const srv: Server = createServer(answerUnavailable());
  srv.listen(sock);
  await once(srv, "listening");
  try { await fn(sock); } finally {
    srv.close(); rmSync(dir, { recursive: true, force: true });
  }
}

test("launches the fake agent with the composed claude context (--no-scope)", async () => {
  chmodSync(FAKE, 0o755);
  await withMockArbiter(async (sock) => {
    // Capture the fake agent's stdout by pointing it through a temp file:
    // main() inherits stdio, so run it with output redirected via a subshell arg.
    const outFile = join(dirname(sock), "out.json");
    const code = await main(
      ["--target", "claude", "--no-scope", "--", "bash", "-c", `${FAKE} > ${outFile} 2>&1`],
      // A temp MANDU_HOME with no config.toml keeps every e2e main() hermetic: the
      // developer's real ~/.mandu/config.toml must never leak in.
      // XDG_RUNTIME_DIR: the scope run dir lands in the test's own dir, not
      // the shared /tmp/mandu/<scope> (test-organization.md §8.4).
      { HOME: process.env["HOME"], PWD: dirname(sock), MANDU_ARBITER_SOCK: sock, PATH: process.env["PATH"], MANDU_NO_CONTEXT_PROXY: "1", MANDU_HOME: PRIVATE_MANDU_HOME, MANDU_MODE: "off", XDG_RUNTIME_DIR: dirname(sock) },
    );
    assert.equal(code, 0);
    const { readFileSync } = await import("node:fs");
    const got = JSON.parse(readFileSync(outFile, "utf8"));
    assert.match(got.base_url, /^http:\/\/127\.0\.0\.1:8788$/);
    assert.equal(got.headers, "x-mandu-session-id: " + got.scope + ";x-mandu-tenant: live");
    assert.equal(got.arbiter, sock);
    assert.equal(got.cwd, dirname(sock));
    // Non-essential CC traffic is disabled by default (egress-surface reduction).
    assert.equal(got.nonessential, "1");
  });
});

// The per-path overrides of stores inside the Mandu home are retired
// (on-disk-layout.md §5): the launcher neither reads nor exports them, so the
// agent never learns where the event log or the symbol DB lives.
const RETIRED_PATH_VARS = [
  "MANDU_CONFIG", "MANDU_SECRETS", "MANDU_SYMBOL_DB", "MANDU_VIEW_STATE", "MANDU_EVENT_DIR",
  "MANDU_CI_RUNS_DIR", "MANDU_MATRIX_RESULTS_DIR", "MANDU_DOCKER_HOME", "MANDU_CI_CACHE",
];

test("the launched agent's environment carries none of the retired per-path variables", async () => {
  await withMockArbiter(async (sock) => {
    const outFile = join(dirname(sock), "agent-env.json");
    const dump = `require("node:fs").writeFileSync(${JSON.stringify(outFile)}, JSON.stringify(process.env))`;
    const code = await main(
      ["--target", "claude", "--no-scope", "--", process.execPath, "-e", dump],
      { HOME: process.env["HOME"], PWD: dirname(sock), MANDU_ARBITER_SOCK: sock, PATH: process.env["PATH"], MANDU_NO_CONTEXT_PROXY: "1", MANDU_HOME: PRIVATE_MANDU_HOME, MANDU_MODE: "off", XDG_RUNTIME_DIR: dirname(sock) },
    );
    assert.equal(code, 0);
    const { readFileSync } = await import("node:fs");
    const agentEnv = JSON.parse(readFileSync(outFile, "utf8")) as Record<string, string>;
    // The launch really composed the agent's env (the arbiter rendezvous is there)...
    assert.equal(agentEnv["MANDU_ARBITER_SOCK"], sock);
    // ...and none of the retired names rode along.
    for (const k of RETIRED_PATH_VARS) assert.equal(agentEnv[k], undefined, `${k} reached the agent: ${agentEnv[k]}`);
  });
});

test("the launch names its log to Mandu's helpers in the chain (MANDU_LAUNCH_LOG, with MANDU_LAUNCH_DISPLAY=compact by default), where their messages go instead of the agent's terminal (packaging.md §5)", async () => {
  await withMockArbiter(async (sock) => {
    const outFile = join(dirname(sock), "agent-env.json");
    const dump = `require("node:fs").writeFileSync(${JSON.stringify(outFile)}, JSON.stringify(process.env))`;
    const env = { HOME: process.env["HOME"], PWD: dirname(sock), MANDU_ARBITER_SOCK: sock, PATH: process.env["PATH"], MANDU_NO_CONTEXT_PROXY: "1", MANDU_HOME: PRIVATE_MANDU_HOME, MANDU_MODE: "off", XDG_RUNTIME_DIR: dirname(sock) };
    const { readFileSync } = await import("node:fs");
    const r = await mainCapturingStderr(["--target", "claude", "--no-scope", "--", process.execPath, "-e", dump], env);
    assert.equal(r.code, 0);
    const agentEnv = JSON.parse(readFileSync(outFile, "utf8")) as Record<string, string>;
    assert.equal(agentEnv["MANDU_LAUNCH_LOG"], r.logPath, "the chain is told the launch's own log");
    assert.equal(agentEnv["MANDU_LAUNCH_DISPLAY"], "compact");
    const v = await mainCapturingStderr(["--verbose", "--target", "claude", "--no-scope", "--", process.execPath, "-e", dump], env);
    assert.equal(v.code, 0);
    const verboseEnv = JSON.parse(readFileSync(outFile, "utf8")) as Record<string, string>;
    assert.equal(verboseEnv["MANDU_LAUNCH_LOG"], v.logPath, "under --verbose too (the helpers print and log)");
    assert.equal(verboseEnv["MANDU_LAUNCH_DISPLAY"], undefined);
  });
});

/** Run main() with console.error captured; returns the captured lines and
 *  the lines of the launch's own log (launch-log.ts; packaging.md §5). */
async function mainCapturingStderr(argv: string[], env: Record<string, string | undefined>): Promise<{ code: number; lines: string[]; log: string[]; logPath: string | null }> {
  const lines: string[] = [];
  const orig = console.error;
  const before = launchLogs(env);
  console.error = (...a: unknown[]) => { lines.push(a.map(String).join(" ")); };
  try {
    const code = await main(argv, env);
    const log = before.newLinesIfAny();
    return { code, lines, log, logPath: log.length > 0 ? before.newPath() : null };
  } finally {
    console.error = orig;
  }
}

test("launch display policy (packaging.md §5, 2026-10-18): by default ONE banner line plus one short line per warning, TTY or not; the launch's log, launch.log and MANDU_VERBOSE=1 carry every line", async () => {
  chmodSync(FAKE, 0o755);
  await withMockArbiter(async (sock) => {
    const runtime = dirname(sock);
    const base = {
      HOME: process.env["HOME"], PWD: runtime, MANDU_ARBITER_SOCK: sock, PATH: process.env["PATH"],
      MANDU_NO_CONTEXT_PROXY: "1", MANDU_HOME: PRIVATE_MANDU_HOME, MANDU_MODE: "off", XDG_RUNTIME_DIR: runtime,
    };
    const argv = ["--target", "claude", "--no-scope", "--id", "disp1", "--", "bash", "-c", `${FAKE} > /dev/null 2>&1`];

    // Default: the ONE banner line (the mode, the dashboard: none is
    // registered in this hermetic runtime), then one short posture line per
    // warning (this hermetic launch degrades kernel rungs and has a mock
    // arbiter), nothing else.
    const quiet = await mainCapturingStderr(argv, base);
    assert.equal(quiet.code, 0);
    const banner = quiet.lines.filter((l) => / mode · /.test(l));
    assert.equal(banner.length, 1, JSON.stringify(quiet.lines));
    assert.match(banner[0]!, /^mandu: off mode · observing only, nothing is enforced · no dashboard \(start one: `mandu dashboard`\)( · \d+ notices?: `mandu log`)?$/);
    assert.equal(quiet.lines[0], banner[0], "the banner comes first");
    for (const l of quiet.lines.slice(1)) {
      assert.ok(l.startsWith(POSTURE_PREFIX) && l.endsWith("(more: `mandu log`)"), `only short posture lines follow the banner, got: ${l}`);
      assert.ok(isAttentionNote(l), l);
      assert.ok(l.length <= 200, `short: ${l}`);
    }
    assert.ok(!quiet.lines.some((l) => l.startsWith("mandu: mode ") || /^mandu: (no )?dashboard/.test(l) || l.startsWith(NOTICE_PREFIX)), "no mode line, dashboard line or notice line by default: " + JSON.stringify(quiet.lines));
    assert.ok(!quiet.lines.some((l) => /\b(LIVE|ACTIVE)\b/.test(l)), "no healthy rung line leaks into the default display");

    // The launch's own log holds everything, in full: the header, every
    // rung line, every warning, the mode and dashboard lines; owner-only.
    const { readFileSync, existsSync, statSync } = await import("node:fs");
    assert.ok(quiet.logPath !== null, "the launch wrote its log");
    assert.match(quiet.logPath!, /\/state\/launch-logs\/\d{8}T\d{9}Z-disp1\.log$/);
    assert.equal(statSync(quiet.logPath!).mode & 0o777, 0o600);
    assert.match(quiet.log[0]!, /^mandu \S+: launch of bash \(target claude\) in .*, session disp1, /);
    assert.ok(quiet.log.some((l) => /\bLIVE\b/.test(l)), "the log carries the healthy rung lines");
    assert.ok(quiet.log.includes("mandu: mode off (observing only, nothing is enforced)"));
    assert.ok(quiet.log.includes("mandu: no dashboard is running; start one with `mandu dashboard` to answer approval requests"));
    const warnings = quiet.lines.length - 1;
    assert.ok(quiet.log.filter((l) => isAttentionNote(l)).length >= warnings, "each short line's warning is in the log in full");
    // launch.log in the scope dir still holds the full note list.
    const logPath = join(runtime, "mandu", "disp1", "launch.log");
    assert.ok(existsSync(logPath), `launch.log exists at ${logPath}`);
    const scopeLog = readFileSync(logPath, "utf8").split("\n").filter(Boolean);
    assert.ok(scopeLog.some((l) => /\bLIVE\b/.test(l)), "launch.log carries the healthy rung lines");
    assert.ok(scopeLog.length > quiet.lines.length, "launch.log holds MORE than the terminal showed");

    // MANDU_VERBOSE=1 (and --verbose) → every note prints, the mode line and
    // the dashboard line as before, and the log is still written.
    const verbose = await mainCapturingStderr(argv, { ...base, MANDU_VERBOSE: "1" });
    assert.equal(verbose.code, 0);
    assert.ok(verbose.lines.some((l) => /\bLIVE\b/.test(l)), "verbose prints the rung lines");
    assert.deepEqual(verbose.lines.filter((l) => l.startsWith("mandu: mode ")), ["mandu: mode off (observing only, nothing is enforced)"]);
    assert.ok(!verbose.lines.some((l) => / mode · /.test(l)), "no banner line under --verbose");
    assert.ok(verbose.lines.length > quiet.lines.length);
    assert.ok(verbose.log.some((l) => /\bLIVE\b/.test(l)), "verbose still writes the log");
    const flag = await mainCapturingStderr(["--verbose", ...argv], base);
    assert.deepEqual(
      flag.lines.filter((l) => !/\d{4,}/.test(l)),
      verbose.lines.filter((l) => !/\d{4,}/.test(l)),
      "--verbose == MANDU_VERBOSE=1 (modulo per-run ids/ports)",
    );
  });
});

test("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: default 1, but an explicit user value is preserved", async () => {
  chmodSync(FAKE, 0o755);
  await withMockArbiter(async (sock) => {
    const outFile = join(dirname(sock), "out.json");
    const { readFileSync } = await import("node:fs");
    // User explicitly opts back IN to non-essential traffic (=0) — we must not override.
    await main(
      ["--target", "claude", "--no-scope", "--", "bash", "-c", `${FAKE} > ${outFile} 2>&1`],
      {
        HOME: process.env["HOME"], PWD: dirname(sock), MANDU_ARBITER_SOCK: sock,
        PATH: process.env["PATH"], MANDU_NO_CONTEXT_PROXY: "1", MANDU_HOME: PRIVATE_MANDU_HOME, MANDU_MODE: "off",
        XDG_RUNTIME_DIR: dirname(sock), CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "0",
      },
    );
    assert.equal(JSON.parse(readFileSync(outFile, "utf8")).nonessential, "0", "explicit user value wins");
  });
});

test("fail-closed: arbiter unreachable + no autostart → main refuses", async () => {
  await assert.rejects(
    main(["--target", "claude", "--no-scope", "--", "bash", "-c", "echo SHOULD_NOT_RUN"], {
      HOME: process.env["HOME"], PWD: tmpdir(),
      MANDU_ARBITER_SOCK: join(tmpdir(), "definitely-absent.sock"),
      MANDU_NO_ARBITER_AUTOSTART: "1", PATH: process.env["PATH"], MANDU_HOME: PRIVATE_MANDU_HOME, MANDU_MODE: "off",
    }),
    /refusing to launch ungated/,
  );
});

test("the autostart's runtime-dir checks read the env main() was handed, not process.env", async () => {
  // A base the current/ socket fits under but an instance socket does not:
  // startArbiterInstance refuses it, and names XDG_RUNTIME_DIR as the source
  // only when the env it judges has XDG_RUNTIME_DIR and no MANDU_RUNTIME_DIR.
  // This process's own env names a MANDU_RUNTIME_DIR, so a check that read
  // process.env (as it did before 2026-10-09) would drop that advice.
  const dir = realpathSync(mkdtempSync(join(existsSync("/tmp") ? "/tmp" : tmpdir(), "mrt-")));
  const xdg = join(dir, "x".repeat(Math.max(1, 74 - dir.length - 1)));
  const base = join(xdg, "mandu");
  assert.ok(Buffer.byteLength(base) + "/current/arbiter.sock".length < 104, "the promoted socket fits");
  const saved = process.env["MANDU_RUNTIME_DIR"];
  process.env["MANDU_RUNTIME_DIR"] = join(dir, "process-env-base");
  try {
    await assert.rejects(
      main(["--target", "claude", "--no-scope", "--", "bash", "-c", "echo SHOULD_NOT_RUN"], {
        HOME: process.env["HOME"], PWD: dir, PATH: process.env["PATH"],
        MANDU_NO_CONTEXT_PROXY: "1", MANDU_HOME: PRIVATE_MANDU_HOME, MANDU_MODE: "off", XDG_RUNTIME_DIR: xdg,
      }),
      (err: Error) => {
        assert.match(err.message, /refusing to launch: .*MANDU_RUNTIME_DIR/);
        assert.match(err.message, /The dir comes from XDG_RUNTIME_DIR; MANDU_RUNTIME_DIR overrides it\./);
        return true;
      },
    );
    assert.ok(!existsSync(join(dir, "process-env-base")), "nothing was made under process.env's base");
  } finally {
    if (saved === undefined) delete process.env["MANDU_RUNTIME_DIR"]; else process.env["MANDU_RUNTIME_DIR"] = saved;
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── `mandu -- <shell>` (agent-e2e-harness.md §9.1) ─────────────────────────

test("`mandu -- bash …` launches with NO --target: the plain-command shell target, claude's env routing, and the note naming what it does not route", async () => {
  chmodSync(FAKE, 0o755);
  await withMockArbiter(async (sock) => {
    const outFile = join(dirname(sock), "out.json");
    const run = await mainCapturingStderr(
      ["--no-scope", "--", "bash", "-c", `${FAKE} > ${outFile} 2>&1`],
      // XDG_RUNTIME_DIR: the scope run dir lands in the test's own dir, not
      // the shared /tmp/mandu/<scope> (test-organization.md §8.4).
      { HOME: process.env["HOME"], PWD: dirname(sock), MANDU_ARBITER_SOCK: sock, PATH: process.env["PATH"], MANDU_NO_CONTEXT_PROXY: "1", MANDU_HOME: PRIVATE_MANDU_HOME, MANDU_MODE: "off", XDG_RUNTIME_DIR: dirname(sock) },
    );
    assert.equal(run.code, 0, JSON.stringify(run.lines));
    const { readFileSync } = await import("node:fs");
    const got = JSON.parse(readFileSync(outFile, "utf8"));
    // A model client inside the shell reaches the model-context proxy, stamped with this session.
    assert.match(got.base_url, /^http:\/\/127\.0\.0\.1:8788$/);
    assert.equal(got.headers, "x-mandu-session-id: " + got.scope + ";x-mandu-tenant: live");
    assert.equal(got.arbiter, sock);
    assert.equal(got.argv, "", "no claude flag was spliced into bash's argv");
    // Truth in labeling: the launch says it is a plain command and what is NOT
    // routed: the warning as one short line on the terminal, the note in full
    // in the launch's log (packaging.md §5).
    assert.ok(run.lines.some((l) => l.startsWith(`${POSTURE_PREFIX}codex, openclaw, opencode and goose started from it are NOT routed`)), "shell warning printed: " + JSON.stringify(run.lines));
    const note = run.log.find((l) => l.includes("runs as a plain command (target shell)"));
    assert.ok(note, "shell note kept: " + JSON.stringify(run.log));
    assert.match(note!, /WARNING: codex, openclaw, opencode and goose started from it are NOT routed/);
    // A claude started from the shell is the same client: telemetry off by default.
    assert.equal(got.nonessential, "1");
  });
});

test("an unknown non-shell program still REFUSES before anything starts, naming --target shell", async () => {
  await assert.rejects(
    main(["--no-scope", "--", "python3", "-c", "print('SHOULD_NOT_RUN')"], {
      HOME: process.env["HOME"], PWD: tmpdir(), PATH: process.env["PATH"], MANDU_HOME: PRIVATE_MANDU_HOME, MANDU_MODE: "off",
      MANDU_ARBITER_SOCK: join(tmpdir(), "definitely-absent.sock"), MANDU_NO_ARBITER_AUTOSTART: "1",
    }),
    /cannot infer the target agent from 'python3'.*--target shell/,
  );
});

test("fail-closed holds for the shell target: arbiter unreachable + no autostart → main refuses", async () => {
  await assert.rejects(
    main(["--no-scope", "--", "bash", "-c", "echo SHOULD_NOT_RUN"], {
      HOME: process.env["HOME"], PWD: tmpdir(),
      MANDU_ARBITER_SOCK: join(tmpdir(), "definitely-absent.sock"),
      MANDU_NO_ARBITER_AUTOSTART: "1", PATH: process.env["PATH"], MANDU_HOME: PRIVATE_MANDU_HOME, MANDU_MODE: "off",
    }),
    /refusing to launch ungated/,
  );
});

// ── The agent's login (agent-login.ts) ───────────────────────────────────────

test("launch with no detectable claude login prints ONE plain warning line (none on macOS: the Keychain) and still launches; a login variable silences it", async () => {
  chmodSync(FAKE, 0o755);
  await withMockArbiter(async (sock) => {
    const dir = dirname(sock);
    const { mkdirSync, symlinkSync, existsSync, writeFileSync } = await import("node:fs");
    // A stand-in named `claude` (the probe runs only for the real binary name).
    const bin = join(dir, "bin");
    mkdirSync(bin);
    symlinkSync(FAKE, join(bin, "claude"));
    const home = join(dir, "empty-home");
    mkdirSync(home);
    const base = {
      HOME: home, PWD: dir, MANDU_ARBITER_SOCK: sock, PATH: process.env["PATH"],
      MANDU_NO_CONTEXT_PROXY: "1", MANDU_HOME: PRIVATE_MANDU_HOME, MANDU_MODE: "off", XDG_RUNTIME_DIR: dir,
    };
    const argv = ["--no-scope", "--no-reply-filter", "--", join(bin, "claude")];

    const missing = await mainCapturingStderr(argv, base);
    assert.equal(missing.code, 0, "a warning, never a refusal");
    const notes = missing.lines.filter((l) => /login/.test(l));
    const kept = missing.log.filter((l) => /login found/.test(l));
    if (process.platform === "darwin") {
      // macOS keeps the Claude Code login in the Keychain, which a file check
      // cannot see: "cannot tell" is not a warning (packaging.md §7).
      assert.equal(notes.length, 0, JSON.stringify(missing.lines));
    } else {
      // One short line on the terminal, the full line in the launch's log.
      assert.equal(notes.length, 1, JSON.stringify(missing.lines));
      assert.match(notes[0]!, /^mandu: WARNING: no Claude Code login found on this machine; to log in, run `claude` once/);
      assert.equal(kept.length, 1, JSON.stringify(missing.log));
      assert.match(kept[0]!, /^mandu: WARNING — no Claude Code login found on this machine; to log in, run `claude` once/);
    }

    const withKey = await mainCapturingStderr(argv, { ...base, ANTHROPIC_API_KEY: "sk-ant-E2E-NOT-PRINTED" });
    assert.equal(withKey.code, 0);
    assert.ok(!withKey.lines.some((l) => /login found/.test(l)), JSON.stringify(withKey.lines));
    assert.ok(![...withKey.lines, ...withKey.log].some((l) => l.includes("sk-ant-E2E-NOT-PRINTED")), "a credential value is never printed, nor logged");

    // A subscription login file (existence only; its contents are never read).
    mkdirSync(join(home, ".claude"));
    writeFileSync(join(home, ".claude", ".credentials.json"), "{\"claudeAiOauth\":\"E2E-FILE-SECRET\"}");
    assert.ok(existsSync(join(home, ".claude", ".credentials.json")));
    const withFile = await mainCapturingStderr(argv, base);
    assert.ok(![...withFile.lines, ...withFile.log].some((l) => /login found/.test(l) || l.includes("E2E-FILE-SECRET")), JSON.stringify(withFile.lines));
  });
});

test("a native bin older than its source prints a STALE warning at launch — one short line in the default display, in full in the launch's log — and lands in launch.log", { skip: LINUX_RUNGS }, async () => {
  // 2026-09-17: a fixed sandbox.rs + a never-rebuilt target/debug bin looked
  // healthy at launch and failed every boxed command for a whole session.
  // The launcher now reads cargo's <bin>.d beside the resolved bin and warns
  // when any listed source is newer. Overrides resolve first, so a fake bin +
  // a hand-written .d exercise the real resolver → real probe → real display.
  chmodSync(FAKE, 0o755);
  await withMockArbiter(async (sock) => {
    const runtime = dirname(sock);
    const { writeFileSync, utimesSync, readFileSync } = await import("node:fs");
    const src = join(runtime, "sandbox.rs");
    writeFileSync(src, "// newer than the bin\n");
    const mkStale = (name: string): string => {
      const bin = join(runtime, name);
      writeFileSync(bin, "#!/bin/sh\nexit 0\n"); chmodSync(bin, 0o755);
      writeFileSync(`${bin}.d`, `${bin}: ${src}\n`);
      const old = new Date(Date.now() - 3600_000);
      utimesSync(bin, old, old);
      return bin;
    };
    const boxBin = mkStale("mandu-exec-box");
    const guardBin = mkStale("mandu-net-guard");
    const env = {
      HOME: process.env["HOME"], PWD: runtime, MANDU_ARBITER_SOCK: sock, PATH: process.env["PATH"],
      MANDU_NO_CONTEXT_PROXY: "1", MANDU_HOME: PRIVATE_MANDU_HOME, MANDU_MODE: "off", XDG_RUNTIME_DIR: runtime,
    };
    // The bin resolver reads the PROCESS env for its per-bin overrides (the
    // CLI's env is process.env), so the override is set there for this test.
    const saved = { box: process.env["MANDU_EXEC_BOX_BIN"], guard: process.env["MANDU_NET_GUARD_BIN"] };
    process.env["MANDU_EXEC_BOX_BIN"] = boxBin;
    process.env["MANDU_NET_GUARD_BIN"] = guardBin;
    const restore = () => {
      if (saved.box === undefined) delete process.env["MANDU_EXEC_BOX_BIN"]; else process.env["MANDU_EXEC_BOX_BIN"] = saved.box;
      if (saved.guard === undefined) delete process.env["MANDU_NET_GUARD_BIN"]; else process.env["MANDU_NET_GUARD_BIN"] = saved.guard;
    };
    // net-guard / landlock-net are opted OUT: the guard wrap would exec the
    // stub as the agent's outermost wrapper. The exec-box path is the oracle
    // (the stale probe fires at resolve time, before any capability probe).
    const argv = ["--target", "claude", "--no-scope", "--id", "stale1", "--no-net-guard", "--no-landlock-net", "--", "bash", "-c", `${FAKE} > /dev/null 2>&1`];
    const tty = await mainCapturingStderr(argv, env).finally(restore);
    assert.equal(tty.code, 0);
    // The default display: one short line names the stale bin; the launch's
    // log holds the full note (the bin, the newer source, the rebuild).
    assert.ok(tty.lines.some((l) => l.startsWith(`${POSTURE_PREFIX}mandu-exec-box at …/mandu-exec-box is STALE`)), "the stale warning reaches the terminal: " + JSON.stringify(tty.lines));
    const stale = tty.log.filter((l) => /WARNING/.test(l) && /is STALE/.test(l));
    assert.ok(stale.some((l) => l.includes(`mandu-exec-box at ${boxBin}`) && l.includes(src)), "exec-box stale note names the bin and the newer source: " + JSON.stringify(tty.log));
    assert.ok(stale.every((l) => /cargo build -p \S+ --features kernel --bins/.test(l)), "every stale note carries the rebuild command");
    assert.ok(!tty.lines.some((l) => /\bLIVE\b/.test(l)), "the default display stayed compact while the warning was shown");
    const logPath = join(runtime, "mandu", "stale1", "launch.log");
    assert.ok(readFileSync(logPath, "utf8").includes(`mandu-exec-box at ${boxBin} is STALE`), "launch.log carries the stale note");

    // Fresh bin (touched AFTER the source) → no note.
    const now = new Date();
    utimesSync(boxBin, now, now);
    process.env["MANDU_EXEC_BOX_BIN"] = boxBin;
    const fresh = await mainCapturingStderr(argv, env).finally(restore);
    assert.equal(fresh.code, 0);
    assert.ok(!fresh.lines.some((l) => /mandu-exec-box .* is STALE/.test(l)), "a rebuilt bin is silent: " + JSON.stringify(fresh.lines));
  });
});

test("a guarded launch tells the guard to serve the command box's socket allow-list (exec-routing §4.2)", { skip: LINUX_RUNGS }, async () => {
  // The kernel allows ONE seccomp listener per filter chain and the guard holds
  // it, so a box under the guard cannot have its own: the launch must tell the
  // guard to serve boxes (and the box that it does). A stand-in guard records
  // the variable it was launched with, then runs the agent it wraps.
  chmodSync(FAKE, 0o755);
  await withMockArbiter(async (sock) => {
    const runtime = dirname(sock);
    const { writeFileSync, readFileSync } = await import("node:fs");
    const seen = join(runtime, "guard-env.txt");
    const guardBin = join(runtime, "mandu-net-guard");
    writeFileSync(
      guardBin,
      `#!/bin/sh\nprintf '%s|%s\\n' "\${MANDU_NET_GUARD_BOX_SOCKETS:-unset}" "\${MANDU_NET_GUARD_PROXY_PORTS-unset}" >> "${seen}"\n` +
        'while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do shift; done\n[ "$#" -gt 0 ] && shift\n[ "$#" -gt 0 ] && exec "$@"\nexit 0\n',
    );
    chmodSync(guardBin, 0o755);
    const env = {
      HOME: process.env["HOME"], PWD: runtime, MANDU_ARBITER_SOCK: sock, PATH: process.env["PATH"],
      MANDU_NO_CONTEXT_PROXY: "1", MANDU_HOME: PRIVATE_MANDU_HOME, MANDU_MODE: "off", XDG_RUNTIME_DIR: runtime,
    };
    const saved = process.env["MANDU_NET_GUARD_BIN"];
    process.env["MANDU_NET_GUARD_BIN"] = guardBin;
    const restore = () => {
      if (saved === undefined) delete process.env["MANDU_NET_GUARD_BIN"]; else process.env["MANDU_NET_GUARD_BIN"] = saved;
    };
    const argv = ["--target", "claude", "--no-scope", "--id", "boxsock1", "--no-landlock-net", "--", "bash", "-c", `${FAKE} > /dev/null 2>&1`];
    const r = await mainCapturingStderr(argv, env).finally(restore);
    assert.equal(r.code, 0, JSON.stringify(r.lines));
    const lines = readFileSync(seen, "utf8").trim().split("\n");
    assert.ok(lines.length > 0 && lines.every((l) => l.split("|")[0] === "1"), `the guard ran with MANDU_NET_GUARD_BOX_SOCKETS=1: ${JSON.stringify(lines)}`);
    // exec-routing.md §7.5 (2026-10-01): the guard is told the session-proxy
    // ports a process holding a secret may reach (here no net-proxy: none),
    // never left to guess, and never the model proxy's.
    for (const l of lines) {
      const ports = l.split("|")[1];
      assert.notEqual(ports, "unset", `the guard was not told the session-proxy ports: ${JSON.stringify(lines)}`);
      assert.ok(!/(^|,)878[89](,|$)/.test(ports ?? ""), `a model proxy port is no exception: ${ports}`);
    }
  });
});

test("a launch names the dashboard where approvals happen (release checklist d4): the newest live registered one, with its own base path", async () => {
  chmodSync(FAKE, 0o755);
  await withMockArbiter(async (sock) => {
    const runtime = dirname(sock);
    const { mkdirSync, writeFileSync } = await import("node:fs");
    const reg = join(runtime, "mandu", "dashboards");
    mkdirSync(reg, { recursive: true });
    // This test process stands in for a live dashboard (its pid is alive).
    writeFileSync(join(reg, `20260926-0000-test-p${process.pid}.json`), JSON.stringify({ pid: process.pid, port: 40555, host: "0.0.0.0", basePath: "" }));
    writeFileSync(join(reg, "20260101-0000-old-p1999999.json"), JSON.stringify({ pid: 1999999, port: 40444, host: "127.0.0.1", basePath: "" }));
    const env = {
      HOME: process.env["HOME"], PWD: runtime, MANDU_ARBITER_SOCK: sock, PATH: process.env["PATH"],
      MANDU_NO_CONTEXT_PROXY: "1", MANDU_HOME: PRIVATE_MANDU_HOME, MANDU_MODE: "off", XDG_RUNTIME_DIR: runtime,
    };
    const argv = ["--target", "claude", "--no-scope", "--id", "dash1", "--", "bash", "-c", `${FAKE} > /dev/null 2>&1`];
    const r = await mainCapturingStderr(argv, env);
    assert.equal(r.code, 0);
    // The default banner names it (packaging.md §5); the log keeps the line.
    const banner = r.lines.filter((l) => / mode · /.test(l));
    assert.equal(banner.length, 1, JSON.stringify(r.lines));
    assert.match(banner[0]!, / · dashboard http:\/\/127\.0\.0\.1:40555\/( · |$)/, "the live one, on loopback; the dead entry is skipped");
    assert.ok(r.log.includes("mandu: dashboard http://127.0.0.1:40555/ (approve requests, see what was protected)"), JSON.stringify(r.log));
    // --verbose: the dashboard line itself.
    const v = await mainCapturingStderr(["--verbose", ...argv], env);
    assert.equal(v.code, 0);
    assert.deepEqual(
      v.lines.filter((l) => /^mandu: (no )?dashboard/.test(l)),
      ["mandu: dashboard http://127.0.0.1:40555/ (approve requests, see what was protected)"],
      "the live one, on loopback; the dead entry is skipped",
    );
  });
});

// ── policy.yaml models: (confidentiality-plan-11 D2/D5) ──────────────────────
// A mock arbiter that ANSWERS: `modelEndpoints` returns the declared list (the
// wire shape of arbiter/ipc/protocol.ts ModelEndpointWire), the secret walk
// finds nothing, every other op is unknown (the preflights pass on that).
// It also records every request in arrival order and answers
// `setSessionUpstream` (plan 11 §5, phase 3) the way the arbiter does: the
// bound entry's location from the declared list, `external` for null.
// `stubProxyHello` is the stand-in proxy's first session call (see
// fakeProxyRepo), answered so the stub can go on to listen.
type ArbiterReq = { id: unknown; op: string; sessionKey?: string; endpoint?: string | null; requestedBy?: string };
async function withModelsArbiter(endpoints: unknown[], fn: (sock: string, reqs: ArbiterReq[]) => Promise<void>, opts: { bindError?: string } = {}): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-e2e-models-"));
  const sock = join(dir, "arbiter.sock");
  const reqs: ArbiterReq[] = [];
  const srv: Server = createServer((s) => {
    let buf = "";
    s.setEncoding("utf8");
    s.on("data", (chunk: string) => {
      buf += chunk;
      let nl: number;
      while ((nl = buf.indexOf("\n")) >= 0) {
        const req = JSON.parse(buf.slice(0, nl)) as ArbiterReq;
        buf = buf.slice(nl + 1);
        reqs.push(req);
        const declared = (endpoints as Array<{ name?: string; local?: boolean }>).find((e) => e.name === req.endpoint);
        const result =
          req.op === "modelEndpoints" ? { endpoints } :
          req.op === "setSessionUpstream" && opts.bindError !== undefined ? null :
          req.op === "setSessionUpstream" ? { sessionKey: req.sessionKey, endpoint: req.endpoint ?? null, location: declared?.local === true ? "local" : "external", bound: true } :
          req.op === "stubProxyHello" ? { hello: true } :
          req.op === "discoverSecrets" ? { files: [], skipped: [], counts: {}, limits: { maxDepth: 6, maxFiles: 500 }, truncated: false } :
          req.op === "registerEnvSecrets" ? { vars: [] } :
          null;
        const error = req.op === "setSessionUpstream" && opts.bindError !== undefined ? opts.bindError : `unknown op: ${req.op}`;
        s.write(JSON.stringify(result === null ? { id: req.id, ok: false, error } : { id: req.id, ok: true, result }) + "\n");
      }
    });
  });
  srv.listen(sock);
  await once(srv, "listening");
  try { await fn(sock, reqs); } finally {
    srv.close(); rmSync(dir, { recursive: true, force: true });
  }
}

/** A stand-in native wrap bin: records its argv (one line), then runs the
 *  command after `--`, as the real wraps do. */
async function recordingWrap(dir: string, name: string): Promise<{ bin: string; argvs: () => string[][] }> {
  const { writeFileSync, readFileSync, existsSync } = await import("node:fs");
  const bin = join(dir, name);
  const log = join(dir, `${name}.argv`);
  writeFileSync(
    bin,
    `#!/bin/sh\nprintf '%s\\037' "$@" >> "${log}"\nprintf '\\n' >> "${log}"\n` +
      'while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do shift; done\n[ "$#" -gt 0 ] && shift\n[ "$#" -gt 0 ] && exec "$@"\nexit 0\n',
  );
  chmodSync(bin, 0o755);
  return {
    bin,
    argvs: () => (existsSync(log) ? readFileSync(log, "utf8").split("\n").filter(Boolean).map((l) => l.split("\x1f").filter((t) => t !== "")) : []),
  };
}

function withProcessEnv<T>(vars: Record<string, string>, fn: () => Promise<T>): Promise<T> {
  const saved = Object.fromEntries(Object.keys(vars).map((k) => [k, process.env[k]]));
  Object.assign(process.env, vars);
  return fn().finally(() => {
    for (const [k, v] of Object.entries(saved)) if (v === undefined) delete process.env[k]; else process.env[k] = v;
  });
}

test("plan 11 D5: a declared local model endpoint's port reaches the TCP confine and the connect guard; an external one opens nothing", { skip: LINUX_RUNGS }, async () => {
  chmodSync(FAKE, 0o755);
  const endpoints = [
    { name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", model: "llama3.2", local: true },
    { name: "cloud", url: "https://llm.example.com:8443", wire: "anthropic", local: false },
  ];
  await withModelsArbiter(endpoints, async (sock) => {
    const runtime = dirname(sock);
    const applier = await recordingWrap(runtime, "mandu-landlock-apply");
    const guard = await recordingWrap(runtime, "mandu-net-guard");
    const outFile = join(runtime, "out.json");
    const env = {
      HOME: process.env["HOME"], PWD: runtime, MANDU_ARBITER_SOCK: sock, PATH: process.env["PATH"],
      MANDU_NO_CONTEXT_PROXY: "1", MANDU_HOME: PRIVATE_MANDU_HOME, MANDU_MODE: "secrets", XDG_RUNTIME_DIR: runtime,
    };
    const argv = ["--target", "claude", "--no-scope", "--id", "models1", "--no-exec-box", "--landlock-net-strict", "--", "bash", "-c", `${FAKE} > ${outFile} 2>&1`];
    const r = await withProcessEnv({ MANDU_LANDLOCK_APPLY: applier.bin, MANDU_NET_GUARD_BIN: guard.bin }, () => mainCapturingStderr(argv, env));
    assert.equal(r.code, 0, JSON.stringify(r.lines));
    const { existsSync } = await import("node:fs");
    assert.ok(existsSync(outFile), "the agent ran");

    const ll = applier.argvs().find((a) => a[0] === "--net-only");
    assert.ok(ll, `the TCP confine ran: ${JSON.stringify(applier.argvs())}`);
    const ports = ll.filter((_, i) => ll[i - 1] === "--allow-tcp-port").map(Number);
    assert.ok(ports.includes(11434), `the local endpoint's port is allowed: ${JSON.stringify(ports)}`);
    assert.ok(ports.includes(8788), "the model proxy's port stays allowed");
    assert.ok(!ports.includes(8443) && !ports.includes(443), `strict: no external endpoint port, no workflow port: ${JSON.stringify(ports)}`);

    const g = guard.argvs()[0];
    assert.ok(g, "the connect guard ran");
    const specs = g.filter((_, i) => g[i - 1] === "--allow");
    assert.ok(specs.includes("tcp:127.0.0.0/8:11434") && specs.includes("tcp:[::1]:11434"), JSON.stringify(specs));
    assert.ok(!specs.some((s) => s.includes("llm.example.com")), `an external declared endpoint is not admitted: ${JSON.stringify(specs)}`);

    // inspect-mcp's refusal list: the session's model proxy origin rides its env.
    const { readFileSync } = await import("node:fs");
    const mcp = JSON.parse(readFileSync(join(runtime, "mandu", "models1", "mcp.json"), "utf8"));
    assert.ok(String(mcp.mcpServers["mandu-inspect"].env.MANDU_MODEL_PROXY_URL).split(",").includes("http://127.0.0.1:8788"), JSON.stringify(mcp.mcpServers["mandu-inspect"].env));
  });
});

test("plan 11 D2: a `local: true` entry at the model proxy's address REFUSES the launch before the agent starts, naming the entry", async () => {
  chmodSync(FAKE, 0o755);
  // MANDU_NO_CONTEXT_PROXY=1 pins the model proxy at 127.0.0.1:8788; the entry
  // spells the same listener another way.
  await withModelsArbiter([{ name: "sneaky", url: "http://localhost:8788", wire: "anthropic", local: true }], async (sock) => {
    const runtime = dirname(sock);
    const outFile = join(runtime, "out.json");
    const env = {
      HOME: process.env["HOME"], PWD: runtime, MANDU_ARBITER_SOCK: sock, PATH: process.env["PATH"],
      MANDU_NO_CONTEXT_PROXY: "1", MANDU_HOME: PRIVATE_MANDU_HOME, MANDU_MODE: "secrets", XDG_RUNTIME_DIR: runtime,
    };
    await assert.rejects(
      mainCapturingStderr(["--target", "claude", "--no-scope", "--id", "models2", "--no-exec-box", "--no-net-guard", "--no-landlock-net", "--", "bash", "-c", `${FAKE} > ${outFile} 2>&1`], env),
      (e: Error) => {
        assert.equal(e.name, "ModelEndpointConflictError");
        assert.match(e.message, /refusing to launch/);
        assert.match(e.message, /models: sneaky \(http:\/\/localhost:8788\) is the model proxy \(anthropic-proxy\) at 127\.0\.0\.1:8788/);
        return true;
      },
    );
    const { existsSync } = await import("node:fs");
    assert.ok(!existsSync(outFile), "fail-closed: the agent never started");
  });
});

test("plan 12 D2: a `local: true` entry on another machine over plain http REFUSES the launch (an arbiter older than the load rule); with allow_plain_http it launches, loudly", async () => {
  chmodSync(FAKE, 0o755);
  const lab = { name: "lab", url: "http://192.168.1.20:8000", wire: "openai-chat", model: "qwen", local: true };
  const envFor = (sock: string, runtime: string) => ({
    HOME: process.env["HOME"], PWD: runtime, MANDU_ARBITER_SOCK: sock, PATH: process.env["PATH"],
    MANDU_NO_CONTEXT_PROXY: "1", MANDU_HOME: PRIVATE_MANDU_HOME, MANDU_MODE: "secrets", XDG_RUNTIME_DIR: runtime,
  });
  const argvFor = (id: string, outFile: string) =>
    ["--target", "claude", "--no-scope", "--id", id, "--no-exec-box", "--no-net-guard", "--no-landlock-net", "--", "bash", "-c", `${FAKE} > ${outFile} 2>&1`];
  const { existsSync } = await import("node:fs");
  await withModelsArbiter([lab], async (sock) => {
    const runtime = dirname(sock);
    const outFile = join(runtime, "out.json");
    await assert.rejects(mainCapturingStderr(argvFor("plain1", outFile), envFor(sock, runtime)), (e: Error) => {
      assert.equal(e.name, "PlainHttpLocalModelError");
      assert.match(e.message, /^mandu: refusing to launch: policy\.yaml declares a model on another machine as `local: true` over plain http:\n  - models: lab \(http:\/\/192\.168\.1\.20:8000\)\n/);
      assert.match(e.message, /add allow_plain_http: true to the entry to accept that/);
      return true;
    });
    assert.ok(!existsSync(outFile), "fail-closed: the agent never started");
  });
  await withModelsArbiter([{ ...lab, allowPlainHttp: true }], async (sock) => {
    const runtime = dirname(sock);
    const outFile = join(runtime, "out.json");
    const r = await mainCapturingStderr(argvFor("plain2", outFile), envFor(sock, runtime));
    assert.equal(r.code, 0, JSON.stringify(r.lines));
    assert.ok(existsSync(outFile), "the agent ran");
    // One short line on the terminal (packaging.md §5), the warning in full in the launch's log.
    assert.ok(r.lines.some((l) => l.startsWith(POSTURE_PREFIX) && /plain http/.test(l)), `the opt-out is announced even in the default display: ${JSON.stringify(r.lines)}`);
    const warn = r.log.find((l) => /models: lab .* is plain http on another machine/.test(l));
    assert.ok(warn && isAttentionNote(warn), JSON.stringify(r.log));
    assert.match(warn!, /cross the network unencrypted \(allow_plain_http: true in policy\.yaml\)/);
  });
});

// ── The main model as a declared endpoint (plan 11 §5, phase 3) ─────────────
// These launches start the model proxy for real through the launcher's own
// service path (start-or-reuse, port 0 + port file, identity check), with
// MANDU_DEV_REPO pointing at a throwaway repo whose
// interceptors/anthropic-proxy is a stand-in: its entry is a stub
// that records the env the launcher gave it (MANDU_UPSTREAM above all),
// makes ONE session-keyed arbiter call before it listens (standing in for the
// real proxy's first per-request arbiter traffic), then publishes its port and
// its /_mandu/identity. The real proxy is not used: its boot talks to a real
// arbiter, and what is under test is the launcher's wiring of it.

type ProxyRecord = { upstream: string | null; sessionKey: string; upstreamLocal: string | null; upstreamIsBaseUrl?: string | null; upstreamTls?: string | null };

async function fakeProxyRepo(dir: string, service: "anthropic-proxy" | "openai-proxy" = "anthropic-proxy"): Promise<{ repo: string; record: () => ProxyRecord | null }> {
  const { existsSync, readFileSync } = await import("node:fs");
  const repo = join(dir, "repo");
  const rec = join(dir, "proxy-record.json");
  standInService(repo, service, join("interceptors", service), `
import { createServer } from "node:http";
import { connect } from "node:net";
import { writeFileSync, renameSync } from "node:fs";
const e = process.env;
writeFileSync(${JSON.stringify(rec)}, JSON.stringify({ upstream: e.MANDU_UPSTREAM ?? null, sessionKey: e.MANDU_SESSION_KEY, upstreamLocal: e.MANDU_UPSTREAM_LOCAL ?? null, upstreamIsBaseUrl: e.MANDU_UPSTREAM_IS_BASE_URL ?? null, upstreamTls: e.MANDU_UPSTREAM_TLS ?? null }));
process.stdin.on("end", () => process.exit(0)); // the launcher's lifeline
process.stdin.resume();
await new Promise((done) => {
  const s = connect(e.MANDU_ARBITER_SOCK);
  s.on("connect", () => s.write(JSON.stringify({ id: "stub", op: "stubProxyHello", sessionKey: e.MANDU_SESSION_KEY }) + "\\n"));
  s.on("data", () => { s.destroy(); done(); });
  s.on("error", done);
});
const srv = createServer((req, res) => {
  if (req.url !== "/_mandu/identity") { res.writeHead(404); res.end(); return; }
  res.writeHead(200, { "content-type": "application/json" });
  res.end(JSON.stringify({ mandu: true, service: ${JSON.stringify(service)}, sessionKey: e.MANDU_SESSION_KEY, arbiterSock: e.MANDU_ARBITER_SOCK, viewMap: e.MANDU_VIEW_MAP ? JSON.parse(e.MANDU_VIEW_MAP) : [] }));
});
srv.listen(Number(e.MANDU_PROXY_PORT), e.MANDU_PROXY_HOST, () => {
  if (e.MANDU_PORT_FILE) { writeFileSync(e.MANDU_PORT_FILE + ".tmp", String(srv.address().port)); renameSync(e.MANDU_PORT_FILE + ".tmp", e.MANDU_PORT_FILE); }
});
`);
  return { repo, record: () => (existsSync(rec) ? JSON.parse(readFileSync(rec, "utf8")) : null) };
}

/** The phase 3 launch: the real service path for the model proxy (no
 *  MANDU_NO_CONTEXT_PROXY), the kernel wraps and the other services off so
 *  nothing but the proxy is spawned. */
function phase3Launch(sock: string, repo: string, id: string, outFile: string, extraEnv: Record<string, string> = {}) {
  const runtime = dirname(sock);
  return mainCapturingStderr(
    ["--target", "claude", "--no-scope", "--id", id, "--no-exec-box", "--no-net-guard", "--no-landlock-net", "--no-net-proxy", "--no-reply-filter",
      "--", "bash", "-c", `${FAKE} > ${outFile} 2>&1`],
    {
      HOME: process.env["HOME"], PWD: runtime, MANDU_ARBITER_SOCK: sock, PATH: process.env["PATH"],
      MANDU_HOME: PRIVATE_MANDU_HOME, MANDU_MODE: "secrets", XDG_RUNTIME_DIR: runtime, MANDU_DEV_REPO: repo, ...extraEnv,
    },
  );
}

/** The ops that may precede the bind: the launch's own preflight reads,
 *  none of them keyed on the session. */
const PREFLIGHT_OPS = new Set(["hello", "policySnapshot", "netConnectAllow", "modelEndpoints"]);

function assertBoundFirst(reqs: ArbiterReq[], scope: string, endpoint: string | null): void {
  const binds = reqs.filter((r) => r.op === "setSessionUpstream");
  assert.equal(binds.length, 1, `exactly one bind: ${JSON.stringify(reqs.map((r) => r.op))}`);
  assert.deepEqual({ sessionKey: binds[0]!.sessionKey, endpoint: binds[0]!.endpoint, requestedBy: binds[0]!.requestedBy }, { sessionKey: scope, endpoint, requestedBy: "launcher" });
  const at = reqs.indexOf(binds[0]!);
  const before = reqs.slice(0, at).map((r) => r.op);
  assert.ok(before.every((op) => PREFLIGHT_OPS.has(op)), `only the preflight reads precede the bind: ${JSON.stringify(before)}`);
  assert.ok(reqs.slice(0, at).every((r) => r.sessionKey === undefined), "no session-keyed traffic before the bind");
}

test("plan 11 phase 3: ANTHROPIC_BASE_URL equal to a declared anthropic entry keeps the model proxy in front of it (MANDU_UPSTREAM = the entry, loopback literal) and binds the session's main model first", async () => {
  chmodSync(FAKE, 0o755);
  const endpoints = [
    { name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", model: "llama3.2", local: true },
    { name: "gpu", url: "http://localhost:18080/", wire: "anthropic", local: true },
  ];
  await withModelsArbiter(endpoints, async (sock, reqs) => {
    const runtime = dirname(sock);
    const { repo, record } = await fakeProxyRepo(runtime);
    const outFile = join(runtime, "out.json");
    const r = await phase3Launch(sock, repo, "p3match", outFile, { ANTHROPIC_BASE_URL: "http://LOCALHOST:18080" });
    assert.equal(r.code, 0, JSON.stringify(r.lines));
    const { readFileSync } = await import("node:fs");
    const got = JSON.parse(readFileSync(outFile, "utf8"));

    // The proxy ran, with the declared entry as its upstream (localhost → 127.0.0.1).
    const rec = record();
    assert.ok(rec, "the model proxy was started");
    assert.equal(rec.upstream, "http://127.0.0.1:18080");
    assert.equal(rec.sessionKey, got.scope);
    // …and is told that upstream is a declared LOCAL model, so it refuses a
    // cloud-backed model name there (plan 11 §8 item 3).
    assert.equal(rec.upstreamLocal, "1");
    // The agent talks to the proxy, not to the user's URL.
    assert.match(got.base_url, /^http:\/\/127\.0\.0\.1:\d+$/);
    assert.notEqual(got.base_url, "http://LOCALHOST:18080");
    const stubHello = reqs.findIndex((q) => q.op === "stubProxyHello");
    assert.ok(stubHello >= 0, "the stand-in proxy reached the arbiter");

    // The main model is bound (name + scope id) before any session traffic.
    assertBoundFirst(reqs, got.scope, "gpu");
    assert.ok(reqs.findIndex((q) => q.op === "setSessionUpstream") < stubHello, "bound before the proxy's first call");

    const log = readFileSync(join(runtime, "mandu", "p3match", "launch.log"), "utf8");
    assert.ok(log.includes(`mandu: your main model is "gpu" (http://localhost:18080/), declared in policy.yaml models: as your own model (local); Mandu's model proxy stays in front of it`), log);
    assert.ok(!r.lines.some((l) => /model proxy is skipped/.test(l)), "no skip warning");
  });
});

test("plan 11 phase 3: an undeclared ANTHROPIC_BASE_URL keeps today's skip, says so as a WARNING with the fix, and binds the default vendor (null)", async () => {
  chmodSync(FAKE, 0o755);
  await withModelsArbiter([{ name: "gpu", url: "http://localhost:18080", wire: "anthropic", local: true }], async (sock, reqs) => {
    const runtime = dirname(sock);
    const { repo, record } = await fakeProxyRepo(runtime);
    const outFile = join(runtime, "out.json");
    const r = await phase3Launch(sock, repo, "p3miss", outFile, { ANTHROPIC_BASE_URL: "http://127.0.0.1:18081" });
    assert.equal(r.code, 0, JSON.stringify(r.lines));
    const { readFileSync } = await import("node:fs");
    const got = JSON.parse(readFileSync(outFile, "utf8"));
    assert.equal(got.base_url, "http://127.0.0.1:18081", "the user's endpoint, as before");
    assert.equal(record(), null, "no model proxy started");
    // One short line on the terminal (packaging.md §5), the warning in full in the launch's log.
    assert.ok(r.lines.some((l) => l.startsWith(`${POSTURE_PREFIX}Mandu's model proxy is skipped`)), `the skip is announced even in the default display: ${JSON.stringify(r.lines)}`);
    const warn = r.log.find((l) => /model proxy is skipped/.test(l));
    assert.ok(warn, JSON.stringify(r.log));
    assert.ok(isAttentionNote(warn!));
    assert.match(warn!, /^WARNING: mandu: Mandu's model proxy is skipped because ANTHROPIC_BASE_URL \(http:\/\/127\.0\.0\.1:18081\) is not declared in policy\.yaml models:, so the model reads file contents and tool results unprotected\. Declare it under models: with wire: anthropic/);
    assertBoundFirst(reqs, got.scope, null);
  });
});

test("plan 11 phase 3: a declared main model on plain http off this machine REFUSES the launch; nothing is spawned", async () => {
  chmodSync(FAKE, 0o755);
  await withModelsArbiter([{ name: "lan", url: "http://192.168.1.20:8080", wire: "anthropic", local: true }], async (sock, reqs) => {
    const runtime = dirname(sock);
    const { repo, record } = await fakeProxyRepo(runtime);
    const outFile = join(runtime, "out.json");
    await assert.rejects(
      phase3Launch(sock, repo, "p3lan", outFile, { ANTHROPIC_BASE_URL: "http://192.168.1.20:8080/" }),
      (e: Error) => {
        assert.equal(e.name, "TllmUpstreamError");
        assert.match(e.message, /^mandu: refusing to launch: your main model http:\/\/192\.168\.1\.20:8080 /);
        assert.match(e.message, /plain http only to this machine .*Put the model behind https, or run it on this machine/);
        return true;
      },
    );
    const { existsSync } = await import("node:fs");
    assert.ok(!existsSync(outFile), "fail-closed: the agent never started");
    assert.equal(record(), null, "fail-closed: no model proxy started");
    assert.ok(!reqs.some((q) => q.op === "setSessionUpstream"), "refused before any binding");
  });
});

test("plan 12 D2: allow_plain_http is the helper's only: a main model declared with it on plain http off this machine still REFUSES the launch", async () => {
  chmodSync(FAKE, 0o755);
  await withModelsArbiter([{ name: "lan", url: "http://192.168.1.20:8080", wire: "anthropic", local: true, allowPlainHttp: true }], async (sock, reqs) => {
    const runtime = dirname(sock);
    const { repo, record } = await fakeProxyRepo(runtime);
    const outFile = join(runtime, "out.json");
    await assert.rejects(
      phase3Launch(sock, repo, "p3lanplain", outFile, { ANTHROPIC_BASE_URL: "http://192.168.1.20:8080/" }),
      (e: Error) => e.name === "TllmUpstreamError",
    );
    assert.equal(record(), null, "fail-closed: no model proxy started");
    assert.ok(!reqs.some((q) => q.op === "setSessionUpstream"), "refused before any binding");
  });
});

test("plan 12 D3: a declared main model's tls rides MANDU_UPSTREAM_TLS to the proxy; a launch without one unsets an ambient value", async () => {
  chmodSync(FAKE, 0o755);
  const tls = { caFile: "/etc/ssl/corp/root.pem", pinSha256: [Buffer.alloc(32, 3).toString("base64")] };
  await withModelsArbiter([{ name: "corp", url: "https://llm.corp.example/anthropic", wire: "anthropic", local: true, tls }], async (sock) => {
    const runtime = dirname(sock);
    const { repo, record } = await fakeProxyRepo(runtime);
    const saved = process.env["MANDU_UPSTREAM_TLS"];
    process.env["MANDU_UPSTREAM_TLS"] = JSON.stringify({ caFile: "/ambient.pem" });
    try {
      const r = await phase3Launch(sock, repo, "p3tls", join(runtime, "out.json"), { ANTHROPIC_BASE_URL: "https://llm.corp.example/anthropic" });
      assert.equal(r.code, 0, JSON.stringify(r.lines));
      assert.deepEqual(JSON.parse(record()?.upstreamTls ?? "null"), tls, "the entry's compiled tls, as JSON");
    } finally {
      if (saved === undefined) delete process.env["MANDU_UPSTREAM_TLS"]; else process.env["MANDU_UPSTREAM_TLS"] = saved;
    }
  });
  await withModelsArbiter([{ name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", model: "m", local: true }], async (sock) => {
    const runtime = dirname(sock);
    const { repo, record } = await fakeProxyRepo(runtime);
    const saved = process.env["MANDU_UPSTREAM_TLS"];
    process.env["MANDU_UPSTREAM_TLS"] = JSON.stringify({ caFile: "/ambient.pem" });
    try {
      const r = await phase3Launch(sock, repo, "p3notls", join(runtime, "out.json"));
      assert.equal(r.code, 0, JSON.stringify(r.lines));
      assert.equal(record()?.upstreamTls ?? null, null, "plan-derived: never an ambient value");
    } finally {
      if (saved === undefined) delete process.env["MANDU_UPSTREAM_TLS"]; else process.env["MANDU_UPSTREAM_TLS"] = saved;
    }
  });
});

test("plan 11 §8 item 3: a declared OUTSIDE main model gets no MANDU_UPSTREAM_LOCAL, even with one in the ambient env", async () => {
  chmodSync(FAKE, 0o755);
  await withModelsArbiter([{ name: "gw", url: "https://127.0.0.1:18443", wire: "anthropic", local: false }], async (sock) => {
    const runtime = dirname(sock);
    const { repo, record } = await fakeProxyRepo(runtime);
    const outFile = join(runtime, "out.json");
    const saved = process.env["MANDU_UPSTREAM_LOCAL"];
    process.env["MANDU_UPSTREAM_LOCAL"] = "1";
    const r = await phase3Launch(sock, repo, "p3outside", outFile, { ANTHROPIC_BASE_URL: "https://127.0.0.1:18443" }).finally(() => {
      if (saved === undefined) delete process.env["MANDU_UPSTREAM_LOCAL"]; else process.env["MANDU_UPSTREAM_LOCAL"] = saved;
    });
    assert.equal(r.code, 0, JSON.stringify(r.lines));
    const rec = record();
    assert.equal(rec?.upstream, "https://127.0.0.1:18443");
    assert.equal(rec?.upstreamLocal, null, "plan-derived: an outside entry is explicitly not local");
  });
});

test("plan 11 §8 item 3: a local: true entry naming a cloud model REFUSES the launch (an arbiter older than the load rule); the agent never starts", async () => {
  chmodSync(FAKE, 0o755);
  await withModelsArbiter([{ name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", model: "gpt-oss:120b-cloud", local: true }], async (sock) => {
    const runtime = dirname(sock);
    const { repo } = await fakeProxyRepo(runtime);
    const outFile = join(runtime, "out.json");
    await assert.rejects(phase3Launch(sock, repo, "p3cloud", outFile), (e: Error) => {
      assert.equal(e.name, "CloudLocalModelError");
      assert.match(e.message, /^mandu: refusing to launch: policy\.yaml declares a cloud model as `local: true`:\n  - models: ollama \(model gpt-oss:120b-cloud, http:\/\/127\.0\.0\.1:11434\)\n/);
      assert.match(e.message, /runs on the vendor's servers, so files labeled local-model would leave your trust boundary \(the models you or your organization run\)/);
      return true;
    });
    const { existsSync } = await import("node:fs");
    assert.ok(!existsSync(outFile), "fail-closed: the agent never started");
  });
});

test("plan 11 phase 3: a default launch (no base URL) binds the default vendor (null) before any session traffic, and the proxy keeps the ambient upstream", async () => {
  chmodSync(FAKE, 0o755);
  await withModelsArbiter([{ name: "gpu", url: "http://localhost:18080", wire: "anthropic", local: true }], async (sock, reqs) => {
    const runtime = dirname(sock);
    const { repo, record } = await fakeProxyRepo(runtime);
    const outFile = join(runtime, "out.json");
    const saved = process.env["MANDU_UPSTREAM"];
    const savedLocal = process.env["MANDU_UPSTREAM_LOCAL"];
    delete process.env["MANDU_UPSTREAM"];
    delete process.env["MANDU_UPSTREAM_LOCAL"];
    const r = await phase3Launch(sock, repo, "p3default", outFile).finally(() => {
      if (saved !== undefined) process.env["MANDU_UPSTREAM"] = saved;
      if (savedLocal !== undefined) process.env["MANDU_UPSTREAM_LOCAL"] = savedLocal;
    });
    assert.equal(r.code, 0, JSON.stringify(r.lines));
    const { readFileSync } = await import("node:fs");
    const got = JSON.parse(readFileSync(outFile, "utf8"));
    assert.match(got.base_url, /^http:\/\/127\.0\.0\.1:\d+$/);
    assert.deepEqual(record(), { upstream: null, sessionKey: got.scope, upstreamLocal: null, upstreamIsBaseUrl: null, upstreamTls: null }, "no upstream invented for the default vendor");
    assertBoundFirst(reqs, got.scope, null);
    assert.ok(reqs.findIndex((q) => q.op === "setSessionUpstream") < reqs.findIndex((q) => q.op === "stubProxyHello"));
    assert.ok(!r.lines.some((l) => /main model/.test(l)), `a default launch says nothing about it: ${JSON.stringify(r.lines)}`);
  });
});

test("plan 11 phase 3: a declared main model the arbiter will not record (an older arbiter, or a refusal) still launches behind the proxy, with a WARNING that local-model files stay closed to it", async () => {
  chmodSync(FAKE, 0o755);
  const endpoints = [{ name: "gpu", url: "http://127.0.0.1:18080", wire: "anthropic", local: true }];
  for (const [bindError, why] of [
    ["unknown op: setSessionUpstream", "the protection service is older than this launcher"],
    ["setSessionUpstream: session has already carried traffic; the main model is recorded only before the session starts", "setSessionUpstream: session has already carried traffic"],
  ] as const) {
    await withModelsArbiter(endpoints, async (sock) => {
      const runtime = dirname(sock);
      const { repo, record } = await fakeProxyRepo(runtime);
      const outFile = join(runtime, "out.json");
      const r = await phase3Launch(sock, repo, "p3old", outFile, { ANTHROPIC_BASE_URL: "http://127.0.0.1:18080/" });
      assert.equal(r.code, 0, JSON.stringify(r.lines));
      assert.equal(record()?.upstream, "http://127.0.0.1:18080", "the proxy still fronts the declared model");
      assert.ok(r.lines.some((l) => l.startsWith(POSTURE_PREFIX)), `one short line on the terminal: ${JSON.stringify(r.lines)}`);
      const warn = r.log.find((l) => /could not record "gpu"/.test(l));
      assert.ok(warn && isAttentionNote(warn), JSON.stringify(r.log));
      assert.ok(warn!.includes(why), warn);
      assert.match(warn!, /files labeled local-model cannot be shown to your main model this session \(it is treated as an outside model\)$/);
    }, { bindError });
  }
});

// ── Codex: the main model as a declared endpoint (plan 11 §7.2) ─────────────
// The same launcher wiring for Codex: MANDU_OPENAI_BASE_URL (the
// model_provider base_url Codex would have used) equal to a declared
// `wire: openai-chat` entry keeps the openai-proxy in front of it. A stand-in
// binary NAMED `codex` records the argv the launcher composed (the -c
// model_provider splice names the proxy, not the user's URL).

async function standInCodex(dir: string): Promise<{ codex: string; argv: () => string[] | null }> {
  const { writeFileSync, existsSync, readFileSync } = await import("node:fs");
  const argvFile = join(dir, "codex-argv.json");
  const codex = join(dir, "codex");
  // The launcher's own `codex --version` probe is not the agent starting.
  writeFileSync(codex, `#!/usr/bin/env node\nconst a = process.argv.slice(2);\nif (a[0] === "--version") { console.log("codex-cli 0.154.0"); process.exit(0); }\nrequire("fs").writeFileSync(${JSON.stringify(argvFile)}, JSON.stringify(a));\n`, { mode: 0o755 });
  return { codex, argv: () => (existsSync(argvFile) ? JSON.parse(readFileSync(argvFile, "utf8")) : null) };
}

function codexLaunch(sock: string, repo: string, id: string, codex: string, extraEnv: Record<string, string> = {}) {
  const runtime = dirname(sock);
  return mainCapturingStderr(
    ["--target", "codex", "--no-scope", "--id", id, "--no-exec-box", "--no-net-guard", "--no-landlock-net", "--no-net-proxy", "--no-reply-filter", "--no-mcp",
      "--", codex, "exec", "--skip-git-repo-check", "hi"],
    {
      HOME: process.env["HOME"], PWD: runtime, MANDU_ARBITER_SOCK: sock, PATH: process.env["PATH"],
      MANDU_HOME: PRIVATE_MANDU_HOME, MANDU_MODE: "secrets", XDG_RUNTIME_DIR: runtime, MANDU_DEV_REPO: repo,
      OPENAI_API_KEY: "sk-test-only", ...extraEnv,
    },
  );
}

/** The base_url of the model_provider the launcher spliced in. */
function splicedBaseUrl(argv: string[]): string | null {
  for (const a of argv) {
    const m = /base_url="([^"]+)"/.exec(a);
    if (m) return m[1]!;
  }
  return null;
}

test("plan 11 §7.2: Codex with MANDU_OPENAI_BASE_URL equal to a declared openai-chat entry keeps the openai-proxy in front of it and binds the main model first", async () => {
  const endpoints = [
    { name: "gpu", url: "http://127.0.0.1:18080", wire: "anthropic", local: true },
    { name: "ollama", url: "http://localhost:11434/v1", wire: "openai-chat", model: "gpt-oss:20b", local: true },
  ];
  await withModelsArbiter(endpoints, async (sock, reqs) => {
    const runtime = dirname(sock);
    const { repo, record } = await fakeProxyRepo(runtime, "openai-proxy");
    const { codex, argv } = await standInCodex(runtime);
    const r = await codexLaunch(sock, repo, "cx-match", codex, { MANDU_OPENAI_BASE_URL: "http://LOCALHOST:11434/v1/" });
    assert.equal(r.code, 0, JSON.stringify(r.lines));

    const rec = record();
    assert.ok(rec, "the openai-proxy was started");
    assert.equal(rec.upstream, "http://127.0.0.1:11434/v1", "the entry, localhost made literal, path kept");
    assert.equal(rec.upstreamLocal, "1");
    assert.equal(rec.upstreamIsBaseUrl, "1", "the proxy maps its own /v1 onto the entry's base");

    const a = argv();
    assert.ok(a, "codex ran");
    const base = splicedBaseUrl(a);
    assert.match(base ?? "", /^http:\/\/127\.0\.0\.1:\d+\/v1$/, `Codex talks to the proxy: ${JSON.stringify(a)}`);
    assert.ok(!a.some((x) => x.includes("11434")), "the user's URL is not in Codex's argv");

    const binds = reqs.filter((q) => q.op === "setSessionUpstream");
    assert.equal(binds.length, 1);
    assert.equal(binds[0]!.endpoint, "ollama");
    assert.ok(reqs.indexOf(binds[0]!) < reqs.findIndex((q) => q.op === "stubProxyHello"), "bound before the proxy's first call");
    assert.ok(!r.lines.some((l) => /model proxy is skipped/.test(l)), "no skip warning");
  });
});

test("plan 11 §7.2: Codex with MANDU_OPENAI_BASE_URL equal to an ANTHROPIC-wire entry does not match; the skip is a WARNING naming the Codex knob and wire", async () => {
  await withModelsArbiter([{ name: "gpu", url: "http://127.0.0.1:18080/v1", wire: "anthropic", local: true }], async (sock, reqs) => {
    const runtime = dirname(sock);
    const { repo, record } = await fakeProxyRepo(runtime, "openai-proxy");
    const { codex, argv } = await standInCodex(runtime);
    const r = await codexLaunch(sock, repo, "cx-miss", codex, { MANDU_OPENAI_BASE_URL: "http://127.0.0.1:18080/v1" });
    assert.equal(r.code, 0, JSON.stringify(r.lines));
    assert.equal(record(), null, "no model proxy started");
    assert.equal(splicedBaseUrl(argv() ?? []), "http://127.0.0.1:18080/v1", "the user's endpoint, as before");
    assert.ok(r.lines.some((l) => l.startsWith(`${POSTURE_PREFIX}Mandu's model proxy is skipped`)), `one short line on the terminal: ${JSON.stringify(r.lines)}`);
    const warn = r.log.find((l) => /model proxy is skipped/.test(l));
    assert.ok(warn && isAttentionNote(warn), JSON.stringify(r.log));
    assert.match(warn!, /^WARNING: mandu: Mandu's model proxy is skipped because MANDU_OPENAI_BASE_URL \(http:\/\/127\.0\.0\.1:18080\/v1\) is not declared in policy\.yaml models:.*with wire: openai-chat/);
    const binds = reqs.filter((q) => q.op === "setSessionUpstream");
    assert.deepEqual(binds.map((b) => b.endpoint), [null], "an outside model");
  });
});

test("plan 11 §7.2: a Codex main model declared on plain http off this machine REFUSES the launch, naming the Codex knob; nothing is spawned", async () => {
  await withModelsArbiter([{ name: "lan", url: "http://192.168.1.20:8000/v1", wire: "openai-chat", local: true }], async (sock, reqs) => {
    const runtime = dirname(sock);
    const { repo, record } = await fakeProxyRepo(runtime, "openai-proxy");
    const { codex, argv } = await standInCodex(runtime);
    await assert.rejects(codexLaunch(sock, repo, "cx-lan", codex, { MANDU_OPENAI_BASE_URL: "http://192.168.1.20:8000/v1" }), (e: Error) => {
      assert.equal(e.name, "TllmUpstreamError");
      assert.match(e.message, /^mandu: refusing to launch: your main model http:\/\/192\.168\.1\.20:8000\/v1 \(MANDU_OPENAI_BASE_URL, declared in policy\.yaml models:\)/);
      return true;
    });
    assert.equal(argv(), null, "fail-closed: codex never started");
    assert.equal(record(), null, "fail-closed: no model proxy started");
    assert.ok(!reqs.some((q) => q.op === "setSessionUpstream"), "refused before any binding");
  });
});

test("plan 11 §7.2: a default Codex launch keeps the ambient upstream, sets no base-URL mapping, and binds the default vendor (null)", async () => {
  await withModelsArbiter([{ name: "ollama", url: "http://127.0.0.1:11434/v1", wire: "openai-chat", local: true }], async (sock, reqs) => {
    const runtime = dirname(sock);
    const { repo, record } = await fakeProxyRepo(runtime, "openai-proxy");
    const { codex } = await standInCodex(runtime);
    const saved = { u: process.env["MANDU_UPSTREAM"], b: process.env["MANDU_UPSTREAM_IS_BASE_URL"] };
    delete process.env["MANDU_UPSTREAM"];
    process.env["MANDU_UPSTREAM_IS_BASE_URL"] = "1"; // an ambient value must not leak into the proxy
    const r = await codexLaunch(sock, repo, "cx-default", codex).finally(() => {
      if (saved.u !== undefined) process.env["MANDU_UPSTREAM"] = saved.u;
      if (saved.b === undefined) delete process.env["MANDU_UPSTREAM_IS_BASE_URL"]; else process.env["MANDU_UPSTREAM_IS_BASE_URL"] = saved.b;
    });
    assert.equal(r.code, 0, JSON.stringify(r.lines));
    const rec = record();
    assert.equal(rec?.upstream, null);
    assert.equal(rec?.upstreamIsBaseUrl, null, "plan-derived: explicitly unset without a declared main model");
    assert.deepEqual(reqs.filter((q) => q.op === "setSessionUpstream").map((b) => b.endpoint), [null]);
  });
});
