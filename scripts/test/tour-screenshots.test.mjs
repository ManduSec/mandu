/**
 * tour-screenshots.test — the pure parts of scripts/tour-screenshots.mjs, the
 * tool that regenerates the first-session tour's dashboard pictures
 * (docs/development.md §5): which browser it drives (or none: SKIP), the
 * recorded tour as it seeds it (moved to now, the temp home folder, the
 * tour's wording), the second session it builds (no real value, one session),
 * the clip of a page region, and the check that refuses a picture showing a
 * fake secret's value, and the browser's teardown (stopProc ends its whole
 * process group, over a stand-in browser). The run itself needs a browser
 * and is not a suite.
 *
 * Run:  node --test scripts/test/tour-screenshots.test.mjs
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  FAKE_VALUES, RECORDED_HOME, STAGING_SESSION, TOUR_SESSION, WIDTH,
  clipFor, groupAlive, leakedValues, movedTour, parseArgs, probeBrowser, removeProfile, stagingSession,
  startBrowser, stopProc,
} from "../tour-screenshots.mjs";

const FIXTURE = fileURLToPath(new URL(`../../dashboard/test/fixtures/tour-${TOUR_SESSION}.ndjson`, import.meta.url));
const tourLines = () => readFileSync(FIXTURE, "utf8").split("\n");

/** A fake filesystem for the probe: the paths that exist, the dirs' names. */
const io = (paths) => ({
  exists: (p) => paths.includes(p),
  list: (d) => [...new Set(paths.filter((p) => p.startsWith(`${d}/`)).map((p) => p.slice(d.length + 1).split("/")[0]))],
});

test("probeBrowser: the flag, then the env, then the newest Playwright shell, then PATH, else none", () => {
  const home = "/h";
  const cache = "/h/.cache/ms-playwright";
  const old = `${cache}/chromium_headless_shell-1100/chrome-headless-shell-linux64/chrome-headless-shell`;
  const neu = `${cache}/chromium_headless_shell-1243/chrome-headless-shell-linux64/chrome-headless-shell`;
  const all = io([old, neu, "/usr/bin/chromium", "/opt/c"]);
  assert.equal(probeBrowser({ flag: "/opt/c", env: { MANDU_TOUR_BROWSER: "/x" }, home, io: all }), "/opt/c");
  assert.equal(probeBrowser({ flag: "/missing", env: {}, home, io: all }), null, "a named browser that is not there is none, not a guess");
  assert.equal(probeBrowser({ env: { MANDU_TOUR_BROWSER: "/opt/c" }, home, io: all }), "/opt/c");
  assert.equal(probeBrowser({ env: { PATH: "/usr/bin" }, home, io: all }), neu, "the newest Playwright shell first");
  assert.equal(probeBrowser({ env: { PATH: "/usr/bin" }, home, io: io(["/usr/bin/chromium"]) }), "/usr/bin/chromium");
  const full = `${cache}/chromium-1200/chrome-linux64/chrome`;
  assert.equal(probeBrowser({ env: {}, home, io: io([full]) }), full);
  assert.equal(probeBrowser({ env: { PATH: "/usr/bin:/bin" }, home, io: io([]) }), null);
});

test("movedTour: ends at the given moment, in the temp home, with the tour's questions and the tour's file", () => {
  const endMs = Date.parse("2030-01-02T03:04:05.000Z");
  const events = movedTour(tourLines(), { endMs, home: "/tmp/x/home" });
  const raw = tourLines().filter(Boolean).map((l) => JSON.parse(l));
  assert.equal(events.length, raw.length);
  assert.equal(Date.parse(events[events.length - 1].ts), endMs);
  // The gaps between events are the recorded ones.
  assert.equal(Date.parse(events[1].ts) - Date.parse(events[0].ts), Date.parse(raw[1].ts) - Date.parse(raw[0].ts));
  const text = JSON.stringify(events);
  assert.ok(!text.includes(`${RECORDED_HOME}/mandu-try`), "no recorded home folder left");
  assert.ok(text.includes("/tmp/x/home/mandu-try/deploy/staging.tfvars"));
  // The recording's file (a `.conf`, which the content tier finds since
  // 2026-10-19) renamed and written as the tour's (RECORDED_RENAMES).
  assert.ok(!text.includes("staging.conf"), "no recorded file name left");
  assert.ok(text.includes(JSON.stringify('host = "staging.example.com"').slice(1, -1)), "the host line as the tour writes it");
  assert.ok(!text.includes("host = staging.example.com"), "no recorded host line left");
  assert.ok(text.includes("What is in .env? Show me its lines."));
  assert.ok(text.includes("What is in deploy/staging.tfvars? Show me its lines."));
  assert.ok(!text.includes("Show me its lines. Show me its lines."), "each question reworded once");
  assert.ok(events.every((e) => e.sessionId === TOUR_SESSION));
});

test("stagingSession: one running session that read the file with its token masked, no value in any event", () => {
  const tour = movedTour(tourLines(), { endMs: Date.now(), home: "/tmp/x/home" });
  const events = stagingSession({
    startMs: Date.parse("2030-01-02T03:00:00.000Z"), home: "/tmp/x/home",
    launch: tour.find((e) => e.kind === "launch_posture"), client: tour.find((e) => e.kind === "client_info"),
  });
  assert.ok(events.every((e) => e.sessionId === STAGING_SESSION));
  assert.deepEqual(events.map((e) => e.seq), events.map((_, i) => i + 1));
  assert.equal(new Set(events.map((e) => e.id)).size, events.length);
  assert.ok(events.every((e, i) => i === 0 || Date.parse(e.ts) > Date.parse(events[i - 1].ts)));
  assert.equal(events[0].kind, "launch_posture");
  assert.equal(events[0].agentVersion?.name, "Claude Code", "the recorded launch's agent");
  assert.ok(!events.some((e) => e.kind === "session_exit"), "still running");
  const result = events.find((e) => e.kind === "tool_result");
  assert.equal(result.output.symbols[0].origin, "/tmp/x/home/mandu-try/deploy/staging.tfvars");
  assert.match(result.output.symbolized, /token = "\$MDU:nomodel_Read\[[0-9a-f]+\]\.token"/);
  assert.deepEqual(leakedValues(JSON.stringify(events).replaceAll(/\$MDU:/g, "")), []);
});

test("clipFor: the full width, padded, whole pixels, never above the page", () => {
  assert.deepEqual(clipFor({ top: 100.4, bottom: 300.2 }), { x: 0, y: 84, width: WIDTH, height: 233, scale: 1 });
  assert.deepEqual(clipFor({ top: 5, bottom: 50 }, { pad: { top: 16, bottom: 0 } }), { x: 0, y: 0, width: WIDTH, height: 50, scale: 1 });
  assert.throws(() => clipFor({ top: 10, bottom: 10 }), /no region/);
  assert.throws(() => clipFor(null), /no region/);
});

test("leakedValues: names each fake value and a token, nothing for clean text", () => {
  assert.deepEqual(leakedValues("STRIPE_KEY comes from ~/mandu-try/.env."), []);
  assert.deepEqual(leakedValues(`a ${FAKE_VALUES[0]} b $MDU:nomodel_Read[1].X`), [FAKE_VALUES[0], "$MDU token"]);
});

test("parseArgs: the defaults, --only checked against the four pictures", () => {
  const d = parseArgs([]);
  assert.equal(d.out, join(fileURLToPath(new URL("../..", import.meta.url)), "docs", "assets", "tour"));
  assert.deepEqual(d.only, ["home", "session", "masked-later", "approval"]);
  assert.deepEqual(parseArgs(["--only", "home, approval", "--browser", "/b"]), { ...d, only: ["home", "approval"], browser: "/b" });
  assert.throws(() => parseArgs(["--only", "sent"]), /unknown picture/);
  assert.throws(() => parseArgs(["--out"]), /needs a value/);
  assert.throws(() => parseArgs(["--bogus"]), /unknown argument/);
});

/** A stand-in browser: says the DevTools line, starts a helper that ignores
 *  SIGTERM and keeps writing into the profile (as Chromium's helpers write
 *  after the main process is told to stop), then waits as the main process. */
const FAKE_BROWSER = `#!/bin/sh
dir=""
for a in "$@"; do case "$a" in --user-data-dir=*) dir="\${a#--user-data-dir=}";; esac; done
mkdir -p "$dir/Default"
( trap '' TERM; i=0; while :; do i=$((i + 1)); echo x > "$dir/Default/f$((i % 20))"; sleep 0.02; done ) &
echo "DevTools listening on ws://127.0.0.1:9/devtools/browser/stand-in" >&2
exec sleep 60
`;

test("stopProc ends the browser's whole process group before it returns, so its profile comes off at once and stays off", { skip: process.platform === "win32" ? "process groups" : false, timeout: 30_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-tour-group-"));
  try {
    const bin = join(dir, "browser");
    writeFileSync(bin, FAKE_BROWSER, { mode: 0o755 });
    const profile = join(dir, "profile");
    const { proc, wsUrl } = await startBrowser(bin, profile, process.env);
    assert.equal(wsUrl, "ws://127.0.0.1:9/devtools/browser/stand-in");
    for (const end = Date.now() + 5_000; !existsSync(join(profile, "Default", "f1")) && Date.now() < end;) await new Promise((r) => setTimeout(r, 20));
    assert.ok(existsSync(join(profile, "Default", "f1")), "the helper writes into the profile");
    assert.ok(groupAlive(proc.pid), "the browser leads a process group of its own");
    await stopProc(proc, { graceMs: 300 });
    assert.notEqual(proc.exitCode ?? proc.signalCode, null, "the browser exited");
    assert.equal(groupAlive(proc.pid), false, "no process of its group is left (the helper ignored SIGTERM: SIGKILL ended it)");
    rmSync(profile, { recursive: true }); // no retries: nothing writes into it any more
    await new Promise((r) => setTimeout(r, 150));
    assert.equal(existsSync(profile), false, "nothing writes it back");
    await stopProc(proc); // a second stop of a stopped browser returns at once
  } finally {
    removeProfile(dir);
  }
});
