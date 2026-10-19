/**
 * launch-console — where each line a launch says goes (packaging.md §5
 * "Launch display policy", 2026-10-18): every line kept (the notes and the
 * launch's log); by default an all-is-well line only there, a notice counted,
 * a warning one short line under the banner, a WARNING block folded to its
 * posture line; under --verbose everything printed as before. console.error
 * goes through that policy while hooked, is copied to the log once teed, and
 * is put back however the launch ends; an aborted launch says what it held.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { LaunchConsole, LaunchConsoleSlot } from "../../src/launch-console.js";
import { POSTURE_PREFIX, postureLine } from "../../src/launch-banner.js";
import type { LaunchLog } from "../../src/launch-log.js";

function memLog(): LaunchLog & { lines: string[]; closed: boolean } {
  const m = {
    path: "/mem/launch.log",
    lines: [] as string[],
    closed: false,
    write(l: string) { m.lines.push(l); },
    close() { m.closed = true; },
  };
  return m;
}

const HEALTHY = "mandu: exec-wrap LIVE — PATH-shadowing [curl, wget, nc] through the arbiter";
const WARN = "mandu: exec-box is on by default, but `bwrap` (bubblewrap) is not installed, so the box cannot run — proceeding WITHOUT it";
const NOTICE = "mandu: 40 possible keys in this project are not protected: run `mandu policy suggest` or open Keys Mandu found in the dashboard";
const WAIT = "mandu: ! an earlier Mandu session without protection has ended, so Mandu is re-checking the git history of 2 repositories (slower this once)";

test("default display: the all-is-well line and the notice stay off the terminal (kept, counted), the warning waits as one short line, the wait prints now", () => {
  const printed: string[] = [];
  const log = memLog();
  const lc = new LaunchConsole("compact", log, (...a) => { printed.push(a.join(" ")); });
  lc.show(HEALTHY);
  lc.show(NOTICE);
  lc.show(NOTICE); // said twice: counted once
  lc.show(WARN);
  lc.show(WARN); // and shown once
  lc.show(WAIT);
  assert.deepEqual(printed, [WAIT], "only the wait, at once");
  assert.equal(lc.noticeCount, 1);
  assert.deepEqual(lc.notes, [HEALTHY, NOTICE, NOTICE, WARN, WARN, WAIT], "every line kept, in order");
  assert.deepEqual(log.lines, lc.notes, "and in the launch's log as it is said");
  lc.flushShort();
  assert.deepEqual(printed, [WAIT, postureLine(WARN)], "under the banner: the posture line, no count line (the banner names the count)");
  assert.equal(lc.noticeCount, 0, "flushed");
});

test("--verbose: every line printed as it is said, nothing held; still kept and logged", () => {
  const printed: string[] = [];
  const log = memLog();
  const lc = new LaunchConsole("full", log, (...a) => { printed.push(a.join(" ")); });
  for (const l of [HEALTHY, NOTICE, WARN]) lc.show(l);
  assert.deepEqual(printed, [HEALTHY, NOTICE, WARN]);
  assert.equal(lc.noticeCount, 0);
  assert.deepEqual(log.lines, [HEALTHY, NOTICE, WARN]);
});

test("without a log the short lines point at --verbose", () => {
  const printed: string[] = [];
  const lc = new LaunchConsole("compact", null, (...a) => { printed.push(a.join(" ")); });
  assert.equal(lc.hint, "`--verbose`");
  lc.show(WARN);
  lc.show(NOTICE);
  lc.flushShort(true);
  assert.deepEqual(printed, [postureLine(WARN, "`--verbose`"), "mandu: 1 notice: `--verbose`"]);
});

test("console.error while hooked goes through the policy; teed it prints as it is and is copied to the log; unhooked it is the original again", () => {
  const printed: string[] = [];
  const orig = console.error;
  const print = (...a: unknown[]): void => { printed.push(a.map(String).join(" ")); };
  console.error = print;
  const log = memLog();
  try {
    const lc = new LaunchConsole("compact", log);
    assert.equal(lc.print, print, "prints go to console.error as it was");
    lc.hook();
    console.error(HEALTHY);
    console.error(new Error(WARN));
    assert.equal(printed.length, 0, "nothing on the terminal yet");
    assert.deepEqual(lc.notes, [HEALTHY, WARN], "an Error is kept by its message");
    lc.tee();
    console.error("mandu: after the agent exited");
    assert.deepEqual(printed, ["mandu: after the agent exited"]);
    assert.equal(log.lines.at(-1), "mandu: after the agent exited");
    lc.end();
    assert.equal(console.error, print, "put back");
    assert.ok(log.closed);
    assert.deepEqual(printed, ["mandu: after the agent exited", postureLine(WARN)], "end says what was still held");
  } finally {
    console.error = orig;
  }
});

test("a WARNING block about another launch: held until the banner, then (default) its marked first line as one posture line, the rest kept; --verbose prints it whole", () => {
  const block = [
    "WARNING: mandu: 1 other Mandu launch runs without confinement beside this one: pid 4242 (secrets, gated).",
    "  Until it ends, its programs can rewrite this launch's placeholder files.",
  ];
  const printed: string[] = [];
  const lc = new LaunchConsole("compact", memLog(), (...a) => { printed.push(a.join(" ")); });
  for (const l of block) lc.sayWhole(l);
  assert.equal(printed.length, 0, "held");
  lc.releaseLastWords();
  assert.deepEqual(printed, [postureLine(block[0]!)]);
  assert.ok(printed[0]!.startsWith(POSTURE_PREFIX));
  assert.deepEqual(lc.notes, block, "kept whole");
  const full: string[] = [];
  const v = new LaunchConsole("full", null, (...a) => { full.push(a.join(" ")); });
  for (const l of block) v.sayWhole(l);
  v.releaseLastWords();
  assert.deepEqual(full, block);
  // foldNow: the same fold, printed at once.
  const now: string[] = [];
  const f = new LaunchConsole("compact", null, (...a) => { now.push(a.join(" ")); });
  for (const l of block) f.foldNow(l);
  assert.deepEqual(now, [postureLine(block[0]!, "`--verbose`")]);
});

test("an aborted launch: console.error put back, the held short lines and the notice count said before the error, the error in the log; once", () => {
  const printed: string[] = [];
  const orig = console.error;
  const print = (...a: unknown[]): void => { printed.push(a.map(String).join(" ")); };
  console.error = print;
  const log = memLog();
  try {
    const slot = new LaunchConsoleSlot();
    const lc = slot.attach(new LaunchConsole("compact", log));
    lc.hook();
    console.error(WARN);
    console.error(NOTICE);
    slot.abort(new Error("mandu: refused: no arbiter"));
    slot.abort(new Error("again"));
    slot.end();
    slot.end();
    assert.equal(console.error, print);
    assert.deepEqual(printed, [postureLine(WARN), "mandu: 1 notice: `mandu log`"]);
    assert.ok(log.lines.includes("mandu: the launch stopped: mandu: refused: no arbiter"));
    assert.ok(log.closed);
  } finally {
    console.error = orig;
  }
  // A slot never attached (a subcommand, a parse error) does nothing.
  assert.doesNotThrow(() => { new LaunchConsoleSlot().abort(new Error("x")); new LaunchConsoleSlot().end(); });
});
