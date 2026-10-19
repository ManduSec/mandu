/**
 * reap-real-probe e2e — `mandu reap` through the real CLI entry (run.ts →
 * runSubcommand → runReap with realReapDeps) against REAL processes wearing
 * the canonical daemon titles (runtime-instances.md §7, §10).
 *
 * What it pins, on every host the launcher suite runs on (Linux reads
 * /proc/<pid>/cmdline, darwin asks `ps -o args=`; both read the start time
 * from `ps -o lstart=` in UTC): a live, owned dashboard keeps its registry
 * entry; a live dashboard and a live arbiter whose owner died are named for
 * SIGTERM by --dry-run and actually stopped by a real run. Before the ps rung
 * darwin read no command line at all: reap deleted the live dashboard's entry
 * as "recycled" and never stopped an orphan. A record whose pid is now another
 * arbiter (title right, start time after the record's startedAt) or a process
 * that only mentions the arbiter in its argv loses its record and is never
 * signalled.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runCli } from "../lib/run-cli.js";
import { processStartMs } from "../../src/reap.js";

/** A live child that names itself like a Mandu daemon (no title: it keeps
 *  its argv, with `argv` appended). */
async function daemonStandIn(title: string | null, argv: string[] = []): Promise<ChildProcess> {
  const setTitle = title === null ? "" : `process.title = ${JSON.stringify(title)}; `;
  const child = spawn(process.execPath, ["-e", `${setTitle}console.log("up"); setInterval(() => {}, 1e9);`, ...argv], {
    stdio: ["ignore", "pipe", "ignore"],
  });
  await new Promise<void>((resolve, reject) => {
    child.stdout!.once("data", () => resolve());
    child.once("exit", () => reject(new Error(`${title} stand-in exited early`)));
  });
  return child;
}

/** A pid that has just exited (an owner that died). */
async function deadPid(): Promise<number> {
  const child = spawn(process.execPath, ["-e", "0"], { stdio: "ignore" });
  await new Promise((resolve) => child.once("exit", resolve));
  return child.pid!;
}

function exited(child: ChildProcess, ms: number): Promise<boolean> {
  if (child.exitCode !== null || child.signalCode !== null) return Promise.resolve(true);
  return new Promise((resolve) => {
    const t = setTimeout(() => resolve(false), ms);
    child.once("exit", () => { clearTimeout(t); resolve(true); });
  });
}

test("mandu reap reads live daemons' command lines on this host: an owned dashboard is kept, orphans are named and stopped", async () => {
  const root = mkdtempSync(join(tmpdir(), "mdu-reap-probe-"));
  const base = join(root, "mandu");
  const home = join(root, "home");
  mkdirSync(home, { recursive: true });
  const owned = await daemonStandIn("mandu-dashboard");
  const orphanDash = await daemonStandIn("mandu-dashboard");
  const orphanArb = await daemonStandIn("mandu-arbiter");
  // The record's startedAt is written once the arbiter listens: after its process started.
  const orphanArbStartedAt = new Date().toISOString();
  // Recycled pids: another session's live arbiter (its process started after
  // the record's arbiter did), and an untitled process whose argv only
  // mentions the arbiter's source (the old /arbiter|server-main/ matched it).
  const otherArb = await daemonStandIn("mandu-arbiter");
  const editor = await daemonStandIn(null, ["arbiter/ipc/server-main.ts"]);
  const all = [owned, orphanDash, orphanArb, otherArb, editor];
  try {
    const gone = await deadPid();
    mkdirSync(join(base, "dashboards"), { recursive: true });
    writeFileSync(join(base, "dashboards", "owned.json"), JSON.stringify({ pid: owned.pid, ownerPid: process.pid, port: 4500 }));
    writeFileSync(join(base, "dashboards", "orphan.json"), JSON.stringify({ pid: orphanDash.pid, ownerPid: gone, port: 4501 }));
    const record = (id: string, manifest: object): string => {
      const dir = join(base, "instances", id);
      mkdirSync(dir, { recursive: true });
      writeFileSync(join(dir, "manifest.json"), JSON.stringify(manifest));
      return dir;
    };
    const orphanDir = record("20260929-0000-e2e-orphan", { pid: orphanArb.pid, ownerPid: gone, mode: "instance", startedAt: orphanArbStartedAt });
    const hourAgo = new Date(Date.now() - 3_600_000).toISOString();
    const otherDir = record("20260929-0001-e2e-other", { pid: otherArb.pid, ownerPid: gone, mode: "instance", startedAt: hourAgo });
    const editorDir = record("20260929-0002-e2e-editor", { pid: editor.pid, ownerPid: gone, mode: "instance", startedAt: hourAgo });
    const env = { HOME: home, MANDU_RUNTIME_DIR: base, MANDU_CONFIG: "/dev/null" };

    const dry = await runCli(["reap", "--dry-run"], env);
    assert.equal(dry.code, 0, dry.stderr);
    assert.match(dry.stdout, new RegExp(`would kill-orphan-dashboard: orphan: owner ${gone} is dead; SIGTERM dashboard pid ${orphanDash.pid}`));
    assert.match(dry.stdout, new RegExp(`would kill-orphan-arbiter: 20260929-0000-e2e-orphan: owner ${gone} is dead; SIGTERM arbiter pid ${orphanArb.pid}`));
    assert.match(dry.stdout, new RegExp(`would rm-dead-instance: 20260929-0001-e2e-other: pid ${otherArb.pid} is a different arbiter \\(started .*; the record says ${hourAgo}\\) \\(recycled\\) — record removed, nothing signalled`),
      `the start time is read on this host and disproves the record:\n${dry.stdout}`);
    assert.match(dry.stdout, new RegExp(`would rm-dead-instance: 20260929-0002-e2e-editor: pid ${editor.pid} is not an arbiter any more \\(recycled\\)`));
    assert.doesNotMatch(dry.stdout, /kill-orphan-arbiter: 20260929-000[12]/);
    assert.doesNotMatch(dry.stdout, /owned:/, `a live, owned dashboard is not garbage (nor "recycled"):\n${dry.stdout}`);

    const run = await runCli(["reap"], env);
    assert.equal(run.code, 0, run.stdout + run.stderr);
    assert.ok(await exited(orphanDash, 5000), "the orphaned dashboard got its SIGTERM");
    assert.ok(await exited(orphanArb, 5000), "the orphaned arbiter got its SIGTERM");
    assert.ok(existsSync(orphanDir), "a signalled arbiter's dir is left to its own shutdown");
    assert.equal(owned.exitCode, null, "the owned dashboard is untouched");
    assert.ok(existsSync(join(base, "dashboards", "owned.json")), "…and keeps its entry");
    assert.equal(await exited(otherArb, 300), false, "another session's arbiter on a recycled pid is never signalled");
    assert.equal(await exited(editor, 0), false, "nor is a process that only mentions the arbiter");
    assert.ok(!existsSync(otherDir) && !existsSync(editorDir), "their stale records are removed");
  } finally {
    for (const c of all) c.kill("SIGKILL");
    rmSync(root, { recursive: true, force: true });
  }
});

test("processStartMs reads this process's start time on this host, in UTC whatever the zone", () => {
  const started = processStartMs(process.pid);
  assert.notEqual(started, null, "ps -o lstart= answers for a live pid");
  const expected = Date.now() - process.uptime() * 1000;
  // lstart is whole seconds (rounded down), the fork precedes node's clock.
  assert.ok(Math.abs(started! - expected) < 5000, `lstart ${new Date(started!).toISOString()} vs process start ${new Date(expected).toISOString()}`);
  assert.equal(processStartMs(2 ** 30), null, "no such pid");
});
