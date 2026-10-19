/**
 * reap.test — `mandu reap` planning + execution (runtime-instances.md §10).
 *
 * The decision matrix under test is the conservatism contract: reap collects
 * ONLY what it can prove is garbage (dead pid, dead owner + a process proven
 * to be the record's arbiter, dangling link, dead-pid scope dir, dead legacy
 * socket) and skips everything ambiguous — the promoted instance, live
 * owners, unreadable command lines. A recycled pid is never signalled; its
 * stale record is removed.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  ARBITER_START_AFTER_MS, ARBITER_START_BEFORE_MS, arbiterIdentity, listDashboards, listInstances, parseLstartUtc,
  planReap, processCmdline, processStartMs, runReap, type CmdlineSource, type ReapDeps, type StartTimeSource,
} from "../../src/reap.js";
import { watchTwins } from "../../src/twin-writes.js";

function withBase(fn: (base: string) => Promise<void> | void): Promise<void> | void {
  const root = mkdtempSync(join(tmpdir(), "mandu-reap-"));
  const base = join(root, "mandu");
  mkdirSync(base, { recursive: true });
  const out = fn(base);
  if (out instanceof Promise) return out.finally(() => rmSync(root, { recursive: true, force: true }));
  rmSync(root, { recursive: true, force: true });
}

/** Deps whose world is a pid table + cmdlines; sockets always dead; kills recorded. */
function fakeDeps(world: Record<number, string>, killed: Array<[number, string]> = []): ReapDeps {
  return {
    pidAlive: (pid) => pid in world,
    cmdlineOf: (pid) => world[pid] ?? null,
    kill: (pid, sig) => { killed.push([pid, sig]); },
    socketLive: async () => false,
    now: () => Date.now(),
  };
}

function seedInstance(base: string, id: string, manifest: object | null): string {
  const dir = join(base, "instances", id);
  mkdirSync(dir, { recursive: true });
  if (manifest) writeFileSync(join(dir, "manifest.json"), JSON.stringify(manifest));
  return dir;
}

test("dead-pid instance → rm; live promoted instance → keep", async () => {
  await withBase(async (base) => {
    seedInstance(base, "20260714-0001-abc-p100", { pid: 100, mode: "instance" }); // dead
    seedInstance(base, "20260714-0002-abc-p200", { pid: 200, mode: "instance", ownerPid: 999 }); // live, promoted, owner dead
    symlinkSync(join("instances", "20260714-0002-abc-p200"), join(base, "current"));
    // make current resolve (existsSync target)
    writeFileSync(join(base, "instances", "20260714-0002-abc-p200", "arbiter.sock"), "");

    const actions = await planReap(base, fakeDeps({ 200: "mandu-arbiter" }));
    assert.deepEqual(actions.map((a) => a.kind), ["rm-dead-instance"]);
    assert.match(actions[0]!.detail, /pid 100 is dead/);
  });
});

test("live arbiter with DEAD owner → SIGTERM, but only when its canonical title confirms an arbiter; a recycled pid loses its record, unsignalled", async () => {
  await withBase(async (base) => {
    // Owner 900 dead; pid 300 IS an arbiter → kill. pid 400 was recycled by
    // vim → must NOT be signalled; the stale record goes.
    const keep = seedInstance(base, "a-p300", { pid: 300, mode: "pinned", ownerPid: 900 });
    const stale = seedInstance(base, "b-p400", { pid: 400, mode: "pinned", ownerPid: 901 });
    const killed: Array<[number, string]> = [];
    const deps = fakeDeps({ 300: "mandu-arbiter", 400: "vim notes.txt" }, killed);

    const actions = await planReap(base, deps);
    const kinds = Object.fromEntries(actions.map((a) => [a.detail.split(":")[0], a.kind]));
    assert.deepEqual(kinds, { "a-p300": "kill-orphan-arbiter", "b-p400": "rm-dead-instance" });
    assert.match(actions.find((a) => a.pid === 400)!.detail, /pid 400 is not an arbiter any more \(recycled\) — record removed, nothing signalled/);

    const code = await runReap([], { MANDU_RUNTIME_DIR: base }, deps);
    assert.equal(code, 0);
    assert.deepEqual(killed, [[300, "SIGTERM"]]);
    assert.ok(existsSync(keep), "the live orphan keeps its dir (its own shutdown tidies it)");
    assert.ok(!existsSync(stale), "the recycled pid's record is removed");
  });
});

// ── the orphan-arbiter rule proves identity, not kind (a pid that came back
//    as an editor, a test runner, or ANOTHER session's arbiter is not ours) ──

/** fakeDeps plus a start-time table (epoch ms). */
function depsWithStarts(world: Record<number, string>, starts: Record<number, number | null>, killed: Array<[number, string]> = []): ReapDeps {
  return { ...fakeDeps(world, killed), startMsOf: (pid) => starts[pid] ?? null };
}

const STARTED = "2026-09-29T04:00:10.500Z";
const STARTED_MS = Date.parse(STARTED);

test("orphan arbiter: a recycled pid whose command line merely mentions the arbiter is never signalled (the loose /arbiter|server-main/ was)", async () => {
  for (const cmd of [
    "nvim arbiter/ipc/server.ts",
    "node --test arbiter/ipc/server-main.test.ts",
    "grep mandu-arbiter /tmp/log",
    "npx tsx ipc/server-main.ts /tmp/x.sock", // an untitled process, whatever it runs
    "mandu-arbiterx",
  ]) {
    await withBase(async (base) => {
      const dir = seedInstance(base, "a-p400", { pid: 400, ownerPid: 901, startedAt: STARTED });
      const killed: Array<[number, string]> = [];
      const deps = depsWithStarts({ 400: cmd }, { 400: STARTED_MS - 1000 }, killed);
      const actions = await planReap(base, deps);
      assert.deepEqual(actions.map((a) => [a.kind, a.pid]), [["rm-dead-instance", 400]], cmd);
      assert.equal(await runReap([], { MANDU_RUNTIME_DIR: base }, deps), 0);
      assert.deepEqual(killed, [], `${cmd}: nothing signalled`);
      assert.ok(!existsSync(dir), `${cmd}: the stale record is removed`);
    });
  }
});

test("orphan arbiter: ANOTHER session's live arbiter on a recycled pid (title matches, start time does not) keeps running; the stale record goes", async () => {
  await withBase(async (base) => {
    const dir = seedInstance(base, "old-p400", { pid: 400, ownerPid: 901, startedAt: STARTED });
    const killed: Array<[number, string]> = [];
    // The record's arbiter died; hours later pid 400 is another session's arbiter.
    const deps = depsWithStarts({ 400: "mandu-arbiter" }, { 400: STARTED_MS + 3 * 3_600_000 }, killed);
    const actions = await planReap(base, deps);
    assert.deepEqual(actions.map((a) => a.kind), ["rm-dead-instance"]);
    assert.match(actions[0]!.detail, /pid 400 is a different arbiter \(started 2026-09-29T07:00:10\.500Z; the record says 2026-09-29T04:00:10\.500Z\) \(recycled\) — record removed, nothing signalled/);
    assert.equal(await runReap([], { MANDU_RUNTIME_DIR: base }, deps), 0);
    assert.deepEqual(killed, []);
    assert.ok(!existsSync(dir));
  });
});

test("orphan arbiter: the record's own arbiter (title + a start just before startedAt) is SIGTERMed and keeps its dir", async () => {
  await withBase(async (base) => {
    const dir = seedInstance(base, "a-p300", { pid: 300, ownerPid: 900, startedAt: STARTED });
    const killed: Array<[number, string]> = [];
    // lstart is whole seconds, rounded down: 04:00:08 for a process that
    // forked at 04:00:08.9 and listened at 04:00:10.5.
    const deps = depsWithStarts({ 300: "mandu-arbiter" }, { 300: STARTED_MS - 2500 }, killed);
    assert.deepEqual((await planReap(base, deps)).map((a) => [a.kind, a.pid]), [["kill-orphan-arbiter", 300]]);
    assert.equal(await runReap([], { MANDU_RUNTIME_DIR: base }, deps), 0);
    assert.deepEqual(killed, [[300, "SIGTERM"]]);
    assert.ok(existsSync(dir));
  });
});

test("arbiterIdentity: the start-time window, and every unknown keeps the title-only check (never wider)", () => {
  const m = { pid: 300, startedAt: STARTED };
  const at = (ms: number | null, cmd: string | null = "mandu-arbiter") =>
    arbiterIdentity(m, { cmdlineOf: () => cmd, startMsOf: () => ms });
  assert.deepEqual(at(STARTED_MS - 1000), { kind: "arbiter", checked: "title+start" });
  assert.deepEqual(at(STARTED_MS + ARBITER_START_AFTER_MS), { kind: "arbiter", checked: "title+start" }, "clock slack after");
  assert.equal(at(STARTED_MS + ARBITER_START_AFTER_MS + 1000).kind, "recycled");
  assert.deepEqual(at(STARTED_MS - ARBITER_START_BEFORE_MS), { kind: "arbiter", checked: "title+start" }, "a slow start");
  assert.equal(at(STARTED_MS - ARBITER_START_BEFORE_MS - 1000).kind, "recycled", "a process older than the record's arbiter could be");
  // Unknowns: no start time, no startMsOf at all, a record without (or with a
  // garbled) startedAt → the title decides alone.
  assert.deepEqual(at(null), { kind: "arbiter", checked: "title" });
  assert.deepEqual(arbiterIdentity(m, { cmdlineOf: () => "mandu-arbiter" }), { kind: "arbiter", checked: "title" });
  let asked = 0;
  const probe = { cmdlineOf: () => "mandu-arbiter", startMsOf: () => { asked++; return STARTED_MS + 9e9; } };
  assert.deepEqual(arbiterIdentity({ pid: 300 }, probe), { kind: "arbiter", checked: "title" });
  assert.deepEqual(arbiterIdentity({ pid: 300, startedAt: "yesterday-ish" }, probe), { kind: "arbiter", checked: "title" });
  assert.equal(asked, 0, "no record time, no ps call");
  // …but an unknown start never rescues a wrong title, and an unreadable
  // command line is left alone (neither signalled nor removed).
  assert.equal(at(null, "vim notes.txt").kind, "recycled");
  assert.deepEqual(at(STARTED_MS, null), { kind: "unknown" });
});

test("orphan arbiter: an unreadable command line is ambiguous — no signal, and the record stays", async () => {
  await withBase(async (base) => {
    const dir = seedInstance(base, "a-p300", { pid: 300, ownerPid: 900, startedAt: STARTED });
    const deps: ReapDeps = { ...depsWithStarts({ 300: "" }, { 300: STARTED_MS }), cmdlineOf: () => null };
    assert.deepEqual(await planReap(base, deps), []);
    assert.ok(existsSync(dir));
  });
});

test("processStartMs: `ps -o lstart= -p <pid>` pinned to the C locale and UTC; anything unreadable is null", () => {
  const calls: Array<{ args: string[]; env: Readonly<Record<string, string>> }> = [];
  const src = (out: string | Error): StartTimeSource => ({
    ps: (args, env) => { calls.push({ args, env }); if (out instanceof Error) throw out; return out; },
  });
  assert.equal(processStartMs(300, src("Tue Sep 29 04:17:03 2026    \n")), Date.UTC(2026, 8, 29, 4, 17, 3));
  assert.deepEqual(calls[0], { args: ["-o", "lstart=", "-p", "300"], env: { LC_ALL: "C", TZ: "UTC0", PATH: "/usr/bin:/bin" } },
    "TZ pinned: the answer does not move with the system time zone");
  assert.equal(processStartMs(300, src(new Error("exit 1"))), null, "no such pid, or no procps");
  assert.equal(processStartMs(300, src("ps: lstart: keyword not found\n")), null, "a ps without lstart (busybox)");
  calls.length = 0;
  for (const bad of [0, -1, 2.5]) assert.equal(processStartMs(bad, src("Tue Sep 29 04:17:03 2026")), null);
  assert.deepEqual(calls, [], "a non-pid never reaches ps");
});

test("parseLstartUtc: the C-locale lstart shape (day space-padded) as UTC; anything else is null", () => {
  assert.equal(parseLstartUtc("Tue Sep 29 04:17:03 2026"), Date.UTC(2026, 8, 29, 4, 17, 3));
  assert.equal(parseLstartUtc("  Wed Sep  2 09:05:01 2026  "), Date.UTC(2026, 8, 2, 9, 5, 1));
  assert.equal(parseLstartUtc("Thu Jan  1 00:00:00 1970"), 0);
  for (const bad of ["", "Tue Sep 29 04:17:03", "Tue Foo 29 04:17:03 2026", "화 9 29 04:17:03 2026", "2026-09-29T04:17:03Z"]) {
    assert.equal(parseLstartUtc(bad), null, bad);
  }
});

test("live owner → keep (a session's arbiter is not garbage while the session lives)", async () => {
  await withBase(async (base) => {
    seedInstance(base, "a-p300", { pid: 300, mode: "pinned", ownerPid: 900 });
    const actions = await planReap(base, fakeDeps({ 300: "mandu-arbiter", 900: "bash" }));
    assert.equal(actions.length, 0);
  });
});

test("dangling current symlink → rm; healthy current → keep", async () => {
  await withBase(async (base) => {
    symlinkSync(join("instances", "gone-p1"), join(base, "current"));
    const actions = await planReap(base, fakeDeps({}));
    assert.deepEqual(actions.map((a) => a.kind), ["rm-dangling-current"]);
  });
});

test("scope-run dirs: dead launcher pid → rm; live → keep; non-scope names untouched", async () => {
  await withBase(async (base) => {
    mkdirSync(join(base, "1783953649-115809")); // dead pid
    mkdirSync(join(base, "1783953650-500"));    // live pid
    mkdirSync(join(base, "logs"));               // not a scope dir
    const actions = await planReap(base, fakeDeps({ 500: "node launcher" }));
    assert.deepEqual(actions.map((a) => a.kind), ["rm-stale-scope-dir"]);
    assert.match(actions[0]!.path, /1783953649-115809$/);
  });
});

test("dead legacy socket file → rm (it would win resolution and break launches)", async () => {
  await withBase(async (base) => {
    writeFileSync(join(base, "arbiter.sock"), "");
    const actions = await planReap(base, fakeDeps({}));
    assert.deepEqual(actions.map((a) => a.kind), ["rm-dead-legacy-sock"]);
  });
});

test("--dry-run: prints the plan, executes nothing", async () => {
  await withBase(async (base) => {
    const dir = seedInstance(base, "a-p100", { pid: 100 });
    const killed: Array<[number, string]> = [];
    const code = await runReap(["--dry-run"], { MANDU_RUNTIME_DIR: base }, fakeDeps({}, killed));
    assert.equal(code, 0);
    assert.ok(existsSync(dir), "dry-run must not remove the dead instance dir");
    assert.equal(killed.length, 0);
  });
});

test("runReap executes: dead instance dir + stale scope dir removed", async () => {
  await withBase(async (base) => {
    const inst = seedInstance(base, "a-p100", { pid: 100 });
    mkdirSync(join(base, "17000-100"));
    const code = await runReap([], { MANDU_RUNTIME_DIR: base }, fakeDeps({}));
    assert.equal(code, 0);
    assert.ok(!existsSync(inst));
    assert.ok(!existsSync(join(base, "17000-100")));
  });
});

/** runReap's stdout, captured. */
async function reapOutput(args: string[], base: string, deps: ReapDeps): Promise<{ code: number; out: string }> {
  const w = process.stdout.write.bind(process.stdout);
  let out = "";
  process.stdout.write = ((c: string | Uint8Array) => { out += String(c); return true; }) as typeof process.stdout.write;
  try {
    const code = await runReap(args, { MANDU_RUNTIME_DIR: base }, deps);
    return { code, out };
  } finally {
    process.stdout.write = w;
  }
}

test("a stale scope dir whose launcher died before saying so: reap names each protected file the session changed, by path, before removing it (plan 10 §4.1)", async () => {
  await withBase(async (base) => {
    const scope = "1790000000-4343";
    const twins = join(base, scope, "secret-twins");
    mkdirSync(twins, { recursive: true });
    const files = [
      { twinPath: join(twins, "000-.env"), targetPath: "/w/.env", content: "API_KEY='$MDU:nomodel_Read[aa]'\n" },
      { twinPath: join(twins, "001-credentials"), targetPath: "/h/.aws/credentials", content: "$MDU:nomodel_Read[bb]\n" },
    ];
    for (const f of files) writeFileSync(f.twinPath, f.content, { mode: 0o600 });
    watchTwins(files, twins);
    writeFileSync(files[0]!.twinPath, "NEW_TOKEN=ghp_FRESHreapUNITtoken0123\n");
    // A second stale scope whose launcher ended normally (it said so, and
    // removed its snapshot file): nothing to say.
    const quiet = "1790000001-4444";
    mkdirSync(join(base, quiet, "secret-twins"), { recursive: true });
    writeFileSync(join(base, quiet, "secret-twins", "000-.env"), "changed\n");

    const dry = await reapOutput(["--dry-run"], base, fakeDeps({}));
    assert.equal(dry.code, 0);
    const notice = `  the session ${scope} ended before Mandu could say so: its agent changed /w/.env; ` +
      "the change went to the file's placeholder copy, which goes with the scope dir, never to the real file. Apply it yourself if you want it.";
    assert.ok(dry.out.split("\n").includes(notice), dry.out);
    assert.ok(existsSync(twins), "dry-run removes nothing");

    const run = await reapOutput([], base, fakeDeps({}));
    assert.equal(run.code, 0);
    const lines = run.out.split("\n");
    const at = lines.indexOf(notice);
    assert.ok(at >= 0, run.out);
    assert.match(lines[at + 1]!, new RegExp(`^  rm-stale-scope-dir: scope ${scope}: `), "said before the removal");
    assert.equal(lines.filter((l) => l.includes("ended before Mandu could say so")).length, 1, `only the changed file, only the dead launcher's session:\n${run.out}`);
    assert.ok(!run.out.includes("ghp_FRESH") && !run.out.includes("$MDU:"), "never what was written");
    assert.ok(!existsSync(join(base, scope)) && !existsSync(join(base, quiet)));
  });
});

test("listInstances: tags mode/promotion/dead owners for status", async () => {
  await withBase(async (base) => {
    seedInstance(base, "a-p100", { pid: 100, mode: "pinned", ownerPid: 900 });
    seedInstance(base, "b-p200", { pid: 200, mode: "instance", ownerPid: null });
    symlinkSync(join("instances", "b-p200"), join(base, "current"));
    const lines = listInstances(
      { MANDU_RUNTIME_DIR: base },
      fakeDeps({ 100: "node arbiter", 200: "node arbiter" }),
    );
    assert.equal(lines.length, 2);
    assert.match(lines[0]!, /a-p100.*\[pinned\].*owner 900 \(exited; `mandu reap` stops it\)/);
    assert.match(lines[1]!, /b-p200.*\[instance, PROMOTED\].*no owner \(resident\)/);
  });
});

// ── dashboards register too (dashboard/src/registry.ts entries) ───────────────

function seedDash(base: string, id: string, manifest: object | string): string {
  const dir = join(base, "dashboards");
  mkdirSync(dir, { recursive: true });
  const path = join(dir, `${id}.json`);
  writeFileSync(path, typeof manifest === "string" ? manifest : JSON.stringify(manifest));
  return path;
}

test("dashboard entries: dead pid → rm entry; corrupt → rm; live owned → keep", async () => {
  await withBase(async (base) => {
    seedDash(base, "a-p100", { pid: 100, ownerPid: null, port: 4500 }); // dead pid
    seedDash(base, "b-bad", "{not json");                               // corrupt
    seedDash(base, "c-p200", { pid: 200, ownerPid: 900, port: 4501 }); // live, owner live
    const actions = await planReap(
      base,
      fakeDeps({ 200: "mandu-dashboard", 900: "bash" }),
    );
    assert.deepEqual(actions.map((a) => a.kind).sort(), ["rm-dead-dashboard-entry", "rm-dead-dashboard-entry"]);
    assert.ok(actions.some((a) => /pid 100 is dead/.test(a.detail)));
    assert.ok(actions.some((a) => /unreadable entry/.test(a.detail)));
  });
});

test("live orphan dashboard → SIGTERM; a RECYCLED pid loses its entry and is NEVER signalled", async () => {
  await withBase(async (base) => {
    // Owner 900 is dead. pid 300 still IS a dashboard (canonical title) → kill.
    seedDash(base, "orphan-p300", { pid: 300, ownerPid: 900, port: 4500 });
    // pid 400 was recycled — by an EDITOR ON dashboard.md, the adversarial case
    // a loose /dashboard/ regex would kill. Entry only, no signal.
    seedDash(base, "recycled-p400", { pid: 400, ownerPid: 900 });
    const killed: Array<[number, string]> = [];
    const actions = await planReap(
      base,
      fakeDeps({ 300: "mandu-dashboard", 400: "vim docs/design/ui/dashboard.md" }, killed),
    );
    const kinds = Object.fromEntries(actions.map((a) => [a.detail.split(":")[0], a.kind]));
    assert.equal(kinds["orphan-p300"], "kill-orphan-dashboard");
    assert.equal(kinds["recycled-p400"], "rm-dead-dashboard-entry");
    assert.match(actions.find((a) => a.kind === "kill-orphan-dashboard")!.detail, /port 4500/);

    // Execute: the orphan gets SIGTERM (its own exit hook removes the entry —
    // reap must NOT rm a live pid's entry); the recycled entry is unlinked.
    const code = await runReap([], { MANDU_RUNTIME_DIR: base },
      fakeDeps({ 300: "mandu-dashboard", 400: "vim docs/design/ui/dashboard.md" }, killed));
    assert.equal(code, 0);
    assert.deepEqual(killed, [[300, "SIGTERM"]]);
    assert.ok(existsSync(join(base, "dashboards", "orphan-p300.json")), "live orphan keeps its entry until it exits");
    assert.ok(!existsSync(join(base, "dashboards", "recycled-p400.json")), "recycled entry removed");
  });
});

test("listDashboards: port + owner liveness for status; .tmp files ignored", async () => {
  await withBase(async (base) => {
    seedDash(base, "a-p100", { pid: 100, ownerPid: 900, port: 4500, host: "127.0.0.1" });
    seedDash(base, "b-p200", { pid: 200, ownerPid: null, port: 41809, host: "0.0.0.0" });
    writeFileSync(join(base, "dashboards", "c.json.tmp"), "half");
    const lines = listDashboards(
      { MANDU_RUNTIME_DIR: base },
      fakeDeps({ 200: "mandu-dashboard" }),
    );
    assert.equal(lines.length, 2);
    // A dead pid only loses its record, so the owner note does not promise a stop.
    assert.match(lines[0]!, /a-p100.*\[not running; `mandu reap` removes the record, http:\/\/127\.0\.0\.1:4500\].*owner 900 \(exited\)$/);
    assert.match(lines[1]!, /b-p200.*\[http:\/\/0\.0\.0\.0:41809\].*no owner \(resident\)/);
  });
});

test("listInstances: a PROMOTED arbiter whose owner exited is never promised to reap (it keeps it)", async () => {
  await withBase(async (base) => {
    seedInstance(base, "p-p100", { pid: 100, mode: "instance", ownerPid: 900 });
    symlinkSync(join("instances", "p-p100"), join(base, "current"));
    const [line] = listInstances({ MANDU_RUNTIME_DIR: base }, fakeDeps({ 100: "node arbiter" }));
    assert.match(line!, /PROMOTED\].*owner 900 \(exited\)$/);
    const actions = await planReap(base, fakeDeps({ 100: "node arbiter" }));
    assert.equal(actions.length, 0, "and reap indeed plans nothing for it");
  });
});

// ── processCmdline: /proc on Linux, ps where there is no /proc (darwin) ──

function sourceOf(platform: NodeJS.Platform, proc: () => string, ps: () => string): CmdlineSource & { asked: string[] } {
  const asked: string[] = [];
  return {
    asked,
    platform,
    readProcCmdline: () => { asked.push("proc"); return proc(); },
    psArgs: () => { asked.push("ps"); return ps(); },
  };
}

test("processCmdline: Linux keeps /proc (NULs as spaces, no ps fallback); darwin asks ps and trims the title padding", () => {
  const linux = sourceOf("linux", () => "mandu-dashboard\0\0\0", () => "WRONG");
  assert.equal(processCmdline(300, linux), "mandu-dashboard");
  assert.deepEqual(linux.asked, ["proc"]);
  const linuxGone = sourceOf("linux", () => { throw new Error("ENOENT"); }, () => "WRONG");
  assert.equal(processCmdline(300, linuxGone), null);
  assert.deepEqual(linuxGone.asked, ["proc"], "an unreadable /proc entry stays null on Linux");

  const darwin = sourceOf("darwin", () => "WRONG", () => "mandu-dashboard      \n");
  assert.equal(processCmdline(300, darwin), "mandu-dashboard");
  assert.deepEqual(darwin.asked, ["ps"]);
  assert.equal(processCmdline(300, sourceOf("darwin", () => "", () => { throw new Error("exit 1"); })), null, "no such pid");
  assert.equal(processCmdline(300, sourceOf("darwin", () => "", () => "\n")), null, "an empty answer");
  const none = sourceOf("darwin", () => "", () => "x");
  for (const bad of [0, -1, 2.5]) assert.equal(processCmdline(bad, none), null);
  assert.deepEqual(none.asked, [], "a non-pid never reaches ps");
});

test("planReap over the darwin probe shape: an orphan arbiter answering its padded title through ps is confirmed; a recycled pid there is not", async () => {
  await withBase(async (base) => {
    seedInstance(base, "orphan-p300", { pid: 300, ownerPid: 900, startedAt: STARTED });
    seedInstance(base, "recycled-p301", { pid: 301, ownerPid: 900, startedAt: STARTED });
    // What `ps -ww -o args=` prints for a node process whose title is set: the
    // title, then a space for each emptied argument (measured, macOS 26.5.1).
    const args: Record<number, string> = { 300: "mandu-arbiter     \n", 301: "nvim arbiter/ipc/server.ts\n" };
    const psOnly: CmdlineSource = {
      platform: "darwin",
      readProcCmdline: () => { throw new Error("no /proc on darwin"); },
      psArgs: (pid) => { if (!(pid in args)) throw new Error("ps exited 1"); return args[pid]!; },
    };
    const deps: ReapDeps = {
      ...depsWithStarts({ 300: "", 301: "" }, { 300: STARTED_MS - 1000, 301: STARTED_MS - 1000 }),
      cmdlineOf: (pid) => processCmdline(pid, psOnly),
    };
    const actions = await planReap(base, deps);
    assert.deepEqual(actions.map((a) => [a.kind, a.pid]).sort(), [["kill-orphan-arbiter", 300], ["rm-dead-instance", 301]]);
  });
});

test("planReap over the darwin probe shape: a live dashboard answering its title through ps keeps its entry; only its dead owner makes it a target", async () => {
  await withBase(async (base) => {
    seedDash(base, "owned-p300", { pid: 300, ownerPid: 900, port: 4500 });
    seedDash(base, "orphan-p301", { pid: 301, ownerPid: 901, port: 4501 });
    const titles: Record<number, string> = { 300: "mandu-dashboard   \n", 301: "mandu-dashboard   \n" };
    const psOnly: CmdlineSource = {
      platform: "darwin",
      readProcCmdline: () => { throw new Error("no /proc on darwin"); },
      psArgs: (pid) => { if (!(pid in titles)) throw new Error("ps exited 1"); return titles[pid]!; },
    };
    const deps: ReapDeps = { ...fakeDeps({ 300: "", 301: "", 900: "bash" }), cmdlineOf: (pid) => processCmdline(pid, psOnly) };
    const actions = await planReap(base, deps);
    assert.deepEqual(actions.map((a) => [a.kind, a.pid]), [["kill-orphan-dashboard", 301]],
      "the live owned dashboard is NOT treated as recycled (the /proc-only probe deleted its entry on darwin)");
  });
});
