/**
 * stop-scope.test — E2E: the real `mandu stop` (src/run.ts in its own
 * process) against live processes of two stacks, told apart by their own
 * environment the way a real arbiter, dashboard or launcher is
 * (runtime-instances.md §10.3). A benchmark stack's bare stop once stopped the
 * shared stack and two live sessions (2026-10-04); here the isolated caller is
 * refused, `--stack` stops only its own stack, and the operator's bare stop
 * keeps its every-stack meaning. The operator is who the OS says, not the
 * caller's env: a test harness's `XDG_RUNTIME_DIR=<own dir> mandu stop`
 * stopped the systemd dashboard and two live drill runs' arbiters
 * (2026-10-09), and is refused here too.
 *
 * Safety: the CLI runs with a `ps` on PATH that lists only this test's
 * processes, so even a regressed guard can never signal the developer's or
 * CI's real stack. Everything else is real: /proc/<pid>/environ, SIGTERM.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runCli } from "../lib/run-cli.js";
import { darwinUserTempDir } from "../../src/runtime-base.js";
import { operatorStack } from "../../src/subcommands.js";

const dir = mkdtempSync(join(tmpdir(), "mdu-stop-scope-"));
const bench = join(dir, "bench", "run");   // an isolated MANDU_RUNTIME_DIR
const isoXdg = join(dir, "iso-xdg");       // an isolated XDG_RUNTIME_DIR
mkdirSync(bench, { recursive: true });
mkdirSync(isoXdg);

/** logind's runtime dir of this account, when the host has one (Linux). */
const uid = process.getuid?.() ?? null;
const loginDir = process.platform === "linux" && uid !== null && (() => {
  try { return statSync(`/run/user/${uid}`).isDirectory(); } catch { return false; }
})() ? `/run/user/${uid}` : null;

/** The env that selects the OPERATOR's stack (subcommands.ts operatorStack):
 *  the login session's XDG_RUNTIME_DIR on Linux, the per-user TMPDIR on
 *  macOS, a private stand-in XDG dir on a host with no logind dir (there the
 *  env's default is the operator's, as before). Only a filtered `ps` is ever
 *  consulted, so naming the real stack signals nothing outside this test. */
const fakeXdg = join(dir, "xdg");
const OPERATOR_SEL: Record<string, string> =
  process.platform === "darwin" ? { TMPDIR: darwinUserTempDir() }
  : { XDG_RUNTIME_DIR: loginDir ?? fakeXdg };
if (OPERATOR_SEL["XDG_RUNTIME_DIR"] === fakeXdg) mkdirSync(join(fakeXdg, "mandu"), { recursive: true });
const shared = operatorStack(OPERATOR_SEL);
const home = join(dir, "home");
mkdirSync(home);

const children: ChildProcess[] = [];
const allowFile = join(dir, "allow");
const bin = join(dir, "bin");
mkdirSync(bin);
const realPs = spawnSync("sh", ["-c", "command -v ps"], { encoding: "utf8" }).stdout.trim();
writeFileSync(join(bin, "ps"), [
  "#!/usr/bin/env bash",
  `"${realPs}" "$@" | awk -v allow="$(cat '${allowFile}')" 'BEGIN { n = split(allow, a, " "); for (i = 1; i <= n; i++) ok[a[i]] = 1 } ($1 in ok)'`,
  "",
].join("\n"));
chmodSync(join(bin, "ps"), 0o755);

after(() => {
  for (const c of children) { try { c.kill("SIGKILL"); } catch { /* gone */ } }
  rmSync(dir, { recursive: true, force: true });
});

/** A live process titled like a Mandu one, of the stack its env selects. */
async function proc(title: string, env: Record<string, string>): Promise<ChildProcess> {
  const c = spawn(process.execPath, ["-e", "process.title = process.argv[1]; setInterval(() => {}, 1e9); console.log('up')", title], {
    env: { PATH: process.env["PATH"] ?? "", HOME: home, ...env },
    stdio: ["ignore", "pipe", "ignore"],
  });
  children.push(c);
  await new Promise<void>((res) => c.stdout!.once("data", () => res()));
  writeFileSync(allowFile, children.map((x) => x.pid).join(" "));
  return c;
}

const alive = (c: ChildProcess): boolean => c.exitCode === null && c.signalCode === null;
async function gone(c: ChildProcess): Promise<boolean> {
  for (let i = 0; i < 50 && alive(c); i++) await new Promise((r) => setTimeout(r, 100));
  return !alive(c);
}

/** Whether another process's environment can be read here (Linux /proc). */
const ENVIRON = existsSync("/proc/self/environ");

const OPERATOR = { ...OPERATOR_SEL, HOME: home, PATH: `${bin}:${process.env["PATH"] ?? ""}` };
const ISOLATED = { ...OPERATOR, MANDU_RUNTIME_DIR: bench };

test("stop scope: the isolated caller is refused, --stack stops only its stack, the operator's bare stop sweeps all", async () => {
  const sharedDash = await proc("mandu-dashboard", OPERATOR_SEL);
  const sharedArb = await proc("mandu-arbiter", OPERATOR_SEL);
  const benchArb = await proc("mandu-arbiter", { ...OPERATOR_SEL, MANDU_RUNTIME_DIR: bench });
  const benchLauncher = await proc("mandu", { ...OPERATOR_SEL, MANDU_RUNTIME_DIR: bench });

  // 1. The call that took the shared stack down, refused: nothing signalled.
  // A stand-in's stack is read from /proc/<pid>/environ; macOS has no /proc
  // and shows no other process's environment, and a stand-in registers
  // nowhere, so there every one is "stack unknown": refused all the same.
  const refused = await runCli(["stop", "--all"], ISOLATED);
  assert.equal(refused.code, 2, refused.stderr);
  assert.match(refused.stderr, /refused/);
  assert.match(refused.stderr, new RegExp(`${sharedDash.pid}\\s+mandu-dashboard\\s+\\(${ENVIRON ? shared : "stack unknown"}\\)`));
  assert.match(refused.stderr, new RegExp(`mandu stop --all --stack ${bench}`));
  await new Promise((r) => setTimeout(r, 300));
  for (const c of [sharedDash, sharedArb, benchArb, benchLauncher]) assert.ok(alive(c), `pid ${c.pid} survived the refusal`);

  // 2. --stack: the benchmark's own processes only.
  const scoped = await runCli(["stop", "--all", "--stack", bench], ISOLATED);
  assert.equal(scoped.code, 0, scoped.stderr);
  if (ENVIRON) {
    assert.match(scoped.stdout, /stopped 2 process\(es\) of the stack at .*\(2 of other stacks left running\)/);
    assert.ok(await gone(benchArb), "the bench arbiter stopped");
    assert.ok(await gone(benchLauncher), "the bench launcher stopped");
  } else {
    // Not attributable to the stack (macOS, unregistered stand-ins): never signalled.
    assert.match(scoped.stdout, /no mandu processes of the stack at .* to stop \(4 of other stacks left running\)/);
    for (const c of [benchArb, benchLauncher]) { assert.ok(alive(c), `pid ${c.pid} of no known stack is left alone`); c.kill("SIGKILL"); assert.ok(await gone(c)); }
  }
  assert.ok(alive(sharedDash) && alive(sharedArb), "the shared stack still runs");

  // 3. The operator's bare stop keeps its meaning: every stack's daemons.
  const benchArb2 = await proc("mandu-arbiter", { ...OPERATOR_SEL, MANDU_RUNTIME_DIR: bench });
  const swept = await runCli(["stop"], OPERATOR);
  assert.equal(swept.code, 0, swept.stderr);
  assert.match(swept.stdout, /stopped 3 process\(es\)/);
  for (const c of [sharedDash, sharedArb, benchArb2]) assert.ok(await gone(c), `pid ${c.pid} stopped by the sweep`);
});

test("stop scope: --every-stack from an isolated caller is the sweep, said explicitly", async () => {
  const sharedArb = await proc("mandu-arbiter", OPERATOR_SEL);
  const benchArb = await proc("mandu-arbiter", { ...OPERATOR_SEL, MANDU_RUNTIME_DIR: bench });
  const r = await runCli(["stop", "--every-stack"], ISOLATED);
  assert.equal(r.code, 0, r.stderr);
  assert.ok(await gone(sharedArb) && await gone(benchArb));
});

test("stop scope: an isolated XDG_RUNTIME_DIR is another stack, however the caller got there (2026-10-09)", {
  skip: process.platform === "linux" && loginDir === null ? "no logind runtime dir: the env's default stays the operator's (runtime-instances.md §10.3)" : false,
}, async () => {
  const sharedDash = await proc("mandu-dashboard", OPERATOR_SEL);
  const sharedArb = await proc("mandu-arbiter", OPERATOR_SEL);
  const isoArb = await proc("mandu-arbiter", { XDG_RUNTIME_DIR: isoXdg });
  const ISO_XDG = { XDG_RUNTIME_DIR: isoXdg, HOME: home, PATH: OPERATOR.PATH };

  // The call that stopped the systemd dashboard and the drill runs' arbiters:
  // MANDU_RUNTIME_DIR unset, so before the fix the caller counted as the operator.
  const refused = await runCli(["stop"], ISO_XDG);
  assert.equal(refused.code, 2, `${refused.stdout}${refused.stderr}`);
  assert.match(refused.stderr, /refused/);
  assert.ok(refused.stderr.includes(`not this account's own at ${shared}`), refused.stderr);
  assert.match(refused.stderr, new RegExp(`${sharedDash.pid}\\s+mandu-dashboard`));
  assert.ok(refused.stderr.includes(`mandu stop --stack ${isoXdg}/mandu`), refused.stderr);
  await new Promise((r) => setTimeout(r, 300));
  for (const c of [sharedDash, sharedArb, isoArb]) assert.ok(alive(c), `pid ${c.pid} survived the refusal`);

  // Its own stack, named: only its own arbiter.
  const scoped = await runCli(["stop", "--stack", `${isoXdg}/mandu`], ISO_XDG);
  assert.equal(scoped.code, 0, scoped.stderr);
  if (ENVIRON) assert.ok(await gone(isoArb), "the isolated arbiter stopped");
  else { assert.ok(alive(isoArb), "of no known stack: left alone"); isoArb.kill("SIGKILL"); assert.ok(await gone(isoArb)); }
  assert.ok(alive(sharedDash) && alive(sharedArb), "the operator's stack still runs");
  sharedDash.kill("SIGKILL"); sharedArb.kill("SIGKILL");
  assert.ok(await gone(sharedDash) && await gone(sharedArb));
});
