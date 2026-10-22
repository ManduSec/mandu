/**
 * launch-log — the per-launch log file and `mandu log` (packaging.md §5
 * "Launch display policy", 2026-10-18): where it lives (`mandu paths`),
 * owner-only, nothing followed through a link, the newest 20 kept, and the
 * verb that reads it (the latest, a session, --list, --path), printed with
 * no control character a helper's message could carry.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync, mkdirSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  LAUNCH_LOG_KEEP, launchLogDir, launchLogName, listLaunchLogs, openLaunchLog, parseLaunchLogName,
  printable, prunableLaunchLogs, runLog,
} from "../../src/launch-log.js";
import { timingsLogLine } from "../../src/launch-timings.js";
import { manduPath } from "../../src/generated/mandu-paths.js";
import { PATH_DESCRIPTIONS } from "../../src/paths-command.js";

function tmpHome(): { home: string; env: Record<string, string>; done: () => void } {
  const home = mkdtempSync(join(tmpdir(), "mandu-launch-log-"));
  return { home, env: { HOME: home }, done: () => rmSync(home, { recursive: true, force: true }) };
}

function io(): { out: string[]; err: string[]; sink: { out: (s: string) => void; err: (s: string) => void } } {
  const out: string[] = [];
  const err: string[] = [];
  return { out, err, sink: { out: (s) => { out.push(s); }, err: (s) => { err.push(s); } } };
}

test("the log folder is the path table's launch-logs, under Mandu's state folder, and `mandu paths` says what it holds", () => {
  const env = { HOME: "/h" };
  assert.equal(launchLogDir(env, "/h"), "/h/.mandu/state/launch-logs");
  assert.equal(launchLogDir(env, "/h"), manduPath("launch-logs", env, "/h"));
  assert.equal(launchLogDir({ HOME: "/h", MANDU_HOME: "/m" }, "/h"), "/m/state/launch-logs");
  assert.match(PATH_DESCRIPTIONS["launch-logs"], /mandu log/);
});

test("a log's name: its UTC start, then the session id (sorts by time; an odd id is made safe)", () => {
  const at = new Date("2026-10-18T01:02:03.456Z");
  assert.equal(launchLogName(at, "1792285255-1238844"), "20261018T010203456Z-1792285255-1238844.log");
  assert.equal(launchLogName(at, "a/b c"), "20261018T010203456Z-a_b_c.log");
  assert.equal(launchLogName(at, ""), "20261018T010203456Z-launch.log");
  const e = parseLaunchLogName("/d", "20261018T010203456Z-my-id.log")!;
  assert.equal(e.sessionId, "my-id");
  assert.equal(e.startedAt.toISOString(), "2026-10-18T01:02:03.456Z");
  assert.equal(e.path, "/d/20261018T010203456Z-my-id.log");
  assert.equal(parseLaunchLogName("/d", "notes.txt"), null);
  assert.equal(parseLaunchLogName("/d", "20261018T010203456Z-x.log.bak"), null);
  assert.equal(parseLaunchLogName("/d", "20261018T010203Z-x.log"), null, "the time to the millisecond");
});

test("retention: the newest LAUNCH_LOG_KEEP are kept; anything that is not a launch log is never removed", () => {
  const names = Array.from({ length: 25 }, (_, i) => launchLogName(new Date(Date.UTC(2026, 9, 1, 0, 0, i)), `s${i}`));
  const gone = prunableLaunchLogs([...names, "README", "x.log"], LAUNCH_LOG_KEEP);
  assert.equal(LAUNCH_LOG_KEEP, 20);
  assert.deepEqual(gone.sort(), names.slice(0, 5).sort(), "the five oldest");
  assert.deepEqual(prunableLaunchLogs(names.slice(0, 3), 20), []);
});

test("openLaunchLog: the folder 0700 and the file 0600, the header first, lines appended in order; old logs pruned to the newest 20", () => {
  const t = tmpHome();
  try {
    // A fresh home: every folder the log makes is 0700.
    const first = openLaunchLog({ env: t.env, home: t.home, sessionId: "s0", now: new Date("2026-10-17T00:00:00Z") })!;
    first.close();
    for (const d of [join(t.home, ".mandu"), join(t.home, ".mandu", "state"), join(t.home, ".mandu", "state", "launch-logs")]) {
      assert.equal(statSync(d).mode & 0o777, 0o700, `${d} is 0700`);
    }
    const dir = launchLogDir(t.env, t.home);
    for (let i = 0; i < 22; i++) writeFileSync(join(dir, launchLogName(new Date(Date.UTC(2026, 0, 1, 0, 0, i)), `old${i}`)), "x\n");
    writeFileSync(join(dir, "keep-me.txt"), "not a log\n");
    const log = openLaunchLog({ env: t.env, home: t.home, sessionId: "s1", now: new Date("2026-10-18T00:00:00Z"), header: "mandu x: launch of claude" })!;
    assert.ok(log, "opened");
    log.write("mandu: exec-wrap LIVE");
    log.write("WARNING: mandu: a\n  block\n");
    log.close();
    log.write("after close: dropped");
    assert.equal(readFileSync(log.path, "utf8"), "mandu x: launch of claude\nmandu: exec-wrap LIVE\nWARNING: mandu: a\n  block\n");
    assert.equal(statSync(log.path).mode & 0o777, 0o600);
    const left = readdirSync(dir);
    assert.ok(left.includes("keep-me.txt"));
    assert.equal(left.filter((n) => n.endsWith(".log")).length, LAUNCH_LOG_KEEP, "the new log and the 19 newest old ones");
    assert.ok(left.includes(launchLogName(new Date("2026-10-18T00:00:00Z"), "s1")));
    assert.ok(!left.includes(launchLogName(new Date(Date.UTC(2026, 0, 1, 0, 0, 0)), "old0")), "the oldest went");
  } finally { t.done(); }
});

test("openLaunchLog never writes through a link: a link at the name is stepped over (a new name, the target untouched), a link on the folder's way refuses (null, never a throw); two launches of one session id get two logs", () => {
  const t = tmpHome();
  try {
    const dir = launchLogDir(t.env, t.home);
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const victim = join(t.home, "victim");
    writeFileSync(victim, "keep\n");
    const now = new Date("2026-10-18T00:00:00Z");
    symlinkSync(victim, join(dir, launchLogName(now, "s1")));
    const log = openLaunchLog({ env: t.env, home: t.home, sessionId: "s1", now })!;
    log.write("x");
    log.close();
    assert.notEqual(log.path, join(dir, launchLogName(now, "s1")));
    assert.equal(readFileSync(victim, "utf8"), "keep\n", "nothing written through the link");
    const again = openLaunchLog({ env: t.env, home: t.home, sessionId: "s1", now })!;
    again.close();
    assert.notEqual(again.path, log.path, "one session id, two launches: two logs");
    // A folder on the way swapped for a link: refused.
    const other = mkdtempSync(join(tmpdir(), "mandu-launch-log-other-"));
    try {
      const home2 = mkdtempSync(join(tmpdir(), "mandu-launch-log-h2-"));
      mkdirSync(join(home2, ".mandu"), { mode: 0o700 });
      symlinkSync(other, join(home2, ".mandu", "state"));
      assert.equal(openLaunchLog({ env: { HOME: home2 }, home: home2, sessionId: "s2" }), null);
      assert.deepEqual(readdirSync(other), [], "nothing made through the link");
      rmSync(home2, { recursive: true, force: true });
    } finally { rmSync(other, { recursive: true, force: true }); }
    // A Mandu home that cannot be made (a file in the way): null.
    assert.equal(openLaunchLog({ env: { HOME: t.home, MANDU_HOME: victim }, home: t.home, sessionId: "s3" }), null);
  } finally { t.done(); }
});

test("printable: a control character a helper's message may carry never reaches the terminal as one; newlines and tabs stay", () => {
  assert.equal(printable("a\tb\nc\u001b[31mred\u0007\u0000\r"), "a\tb\nc?[31mred???");
  assert.equal(printable("plain · text …"), "plain · text …");
});

test("mandu log: the latest launch's log; a session by id or prefix; --path; --list newest first; no log, an unknown session and a bad option say so", () => {
  const t = tmpHome();
  try {
    let r = io();
    assert.equal(runLog([], t.env, r.sink), 1);
    assert.match(r.err.join(""), /no launch log yet \(launch logs are kept in .*\/\.mandu\/state\/launch-logs\)/);

    const a = openLaunchLog({ env: t.env, home: t.home, sessionId: "alpha-1", now: new Date("2026-10-18T00:00:00Z"), header: "launch A" })!;
    a.write("line A \u001b[2J");
    a.close();
    const b = openLaunchLog({ env: t.env, home: t.home, sessionId: "beta-2", now: new Date("2026-10-18T00:05:00Z"), header: "launch B" })!;
    b.write("line B");
    b.close();

    r = io();
    assert.equal(runLog([], t.env, r.sink), 0);
    assert.equal(r.out.join(""), "launch B\nline B\n", "the latest");
    r = io();
    assert.equal(runLog(["alpha-1"], t.env, r.sink), 0);
    assert.equal(r.out.join(""), "launch A\nline A ?[2J\n", "by id, printed without the escape");
    r = io();
    assert.equal(runLog(["alp"], t.env, r.sink), 0, "by prefix");
    r = io();
    assert.equal(runLog(["--path"], t.env, r.sink), 0);
    assert.equal(r.out.join(""), `${b.path}\n`);
    r = io();
    assert.equal(runLog(["--list"], t.env, r.sink), 0);
    const rows = r.out.join("").trim().split("\n");
    assert.equal(rows.length, 2);
    assert.match(rows[0]!, /^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d {2}beta-2 {2}\/.*beta-2\.log$/);
    assert.match(rows[1]!, /alpha-1/);
    assert.deepEqual(listLaunchLogs(t.env, t.home).map((e) => e.sessionId), ["beta-2", "alpha-1"]);

    r = io();
    assert.equal(runLog(["nope"], t.env, r.sink), 1);
    assert.match(r.err.join(""), /no kept launch log for session nope/);
    r = io();
    assert.equal(runLog(["--follow"], t.env, r.sink), 2);
    assert.match(r.err.join(""), /unknown option --follow\nusage: mandu log/);
    r = io();
    assert.equal(runLog(["a", "b"], t.env, r.sink), 2);
  } finally { t.done(); }
});

test("mandu log --timings: the last launches' step times side by side with their median; a session's alone; logs without timings passed over", () => {
  const t = tmpHome();
  try {
    let r = io();
    const plain = openLaunchLog({ env: t.env, home: t.home, sessionId: "old-0", now: new Date("2026-10-18T00:00:00Z"), header: "an older launch" })!;
    plain.close();
    assert.equal(runLog(["--timings"], t.env, r.sink), 1, "no log has timings yet");
    assert.match(r.err.join(""), /no kept launch log has its timings yet/);
    const timed = (id: string, at: string, total: number, history: number): void => {
      const l = openLaunchLog({ env: t.env, home: t.home, sessionId: id, now: new Date(at), header: `launch ${id}` })!;
      // The one written before the agent, then the whole launch's at its end: the last wins.
      l.write(timingsLogLine({ v: 1, totalMs: 1, steps: [{ step: "plan", ms: 1 }] }));
      l.write(timingsLogLine({ v: 1, totalMs: total, steps: [{ step: "plan", ms: 5 }, { step: "secrets", ms: history + 10 }, { step: "secrets.history", ms: history }] }));
      l.close();
    };
    timed("alpha-1", "2026-10-18T00:01:00Z", 1500, 200);
    timed("beta-2", "2026-10-18T00:02:00Z", 2100, 600);
    timed("gamma-3", "2026-10-18T00:03:00Z", 1700, 300);
    r = io();
    assert.equal(runLog(["--timings"], t.env, r.sink), 0);
    const rows = r.out.join("").trimEnd().split("\n");
    assert.match(rows[0]!, /^step \(ms\) +median( +\d\d-\d\d \d\d:\d\d){3}$/, "a median, then three launches newest first");
    assert.match(rows[1]!, /^total +1700 +1700 +2100 +1500$/);
    assert.match(rows.find((l) => l.trimStart().startsWith("history"))!, /^ {2}history +300 +300 +600 +200$/);
    r = io();
    assert.equal(runLog(["beta", "--timings"], t.env, r.sink), 0, "a session by prefix: that launch alone");
    const one = r.out.join("").split("\n");
    assert.ok(!one[0]!.includes("median"));
    assert.match(one[1]!, /^total +2100$/);
    r = io();
    assert.equal(runLog(["old-0", "--timings"], t.env, r.sink), 1);
    assert.match(r.err.join(""), /no kept launch log for session old-0 has its timings/);
  } finally { t.done(); }
});
