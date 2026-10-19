/**
 * moved-files-notice.test.ts — the end-of-session notice of a protected file
 * moved with its folder whose label could not follow
 * (docs/design/confidentiality/guard-file-identity.md §2, 2026-10-16). The
 * guard's half (it writes `<old>\t<new>` once the rename stood unlabelled) is
 * net-supervisor secret_open.rs `a_moved_file_left_unlabelled_is_written_to_the_notice`.
 *
 * Mandu-new test (no reference origin).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { cleanNoticeField, MOVED_NOTICE_MAX, movedNoticeField, movedNoticeFile, movedNoticeLines, parseMovedNotice, readMovedNotice } from "../../src/moved-files-notice.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets");

test("the notice file lives in the scope directory and is handed to the guard", () => {
  assert.equal(movedNoticeFile("/run/scope/abc"), "/run/scope/abc/moved-unlabelled");
  assert.deepEqual(movedNoticeField("/run/scope/abc"), { movedNotice: "/run/scope/abc/moved-unlabelled" });
});

test("bidi formatting characters never reorder a printed path; other text is kept", () => {
  assert.equal(cleanNoticeField("/h/‮vne.⁦x⁩‏/y"), "/h/ vne. x  /y");
  assert.equal(cleanNoticeField("/h/日本語/ünï"), "/h/日本語/ünï");
  assert.deepEqual(parseMovedNotice("/a/‮b\t/c/‎d\n"), [{ from: "/a/ b", to: "/c/ d" }]);
});

test("past the cap the lines say how many more there were", () => {
  const many = Array.from({ length: MOVED_NOTICE_MAX + 5 }, (_, i) => ({ from: `/a/${i}`, to: `/b/${i}` }));
  const lines = movedNoticeLines(many);
  assert.equal(lines.filter((l) => l.startsWith("  /b/")).length, MOVED_NOTICE_MAX);
  assert.ok(lines.includes("  … and 5 more"), lines.join("\n"));
  assert.ok(!movedNoticeLines(many.slice(0, MOVED_NOTICE_MAX)).some((l) => /more$/.test(l)), "no count when all are shown");
});

test("lines: absolute paths only, each new path once, control characters out, every entry kept", () => {
  const text = [
    "/h/.aws/credentials\t/h/.aws2/credentials",
    "/h/.aws/credentials\t/h/.aws2/credentials",
    "relative\t/x",
    "/a\trelative",
    "no tab here",
    "/w/a\u001b[31m\t/w/b\u0007",
    "",
  ].join("\n");
  assert.deepEqual(parseMovedNotice(text), [
    { from: "/h/.aws/credentials", to: "/h/.aws2/credentials" },
    { from: "/w/a [31m", to: "/w/b" },
  ]);
  const many = Array.from({ length: MOVED_NOTICE_MAX + 5 }, (_, i) => `/a/${i}\t/b/${i}`).join("\n");
  assert.equal(parseMovedNotice(many).length, MOVED_NOTICE_MAX + 5);
});

test("what the person reads: the new path, the old one, and how to give it a rule again; nothing when none", () => {
  assert.deepEqual(movedNoticeLines([]), []);
  const one = movedNoticeLines([{ from: "/h/.aws/credentials", to: "/h/.aws2/credentials" }]);
  assert.match(one[0]!, /^mandu: ! a protected file was moved with its folder and Mandu could not record where/);
  assert.equal(one[1], "  /h/.aws2/credentials  (was /h/.aws/credentials)");
  assert.match(one[2]!, /Rules page.*`paths:` in your policy.yaml.*`mandu why <path>`/);
  const two = movedNoticeLines([{ from: "/a", to: "/b" }, { from: "/c", to: "/d" }]);
  assert.match(two[0]!, /^mandu: ! 2 protected files were moved with their folders/);
});

test("an absent or unreadable file says nothing", () => {
  assert.deepEqual(readMovedNotice("/x", () => null), []);
  assert.deepEqual(readMovedNotice("/x", () => "/a\t/b\n"), [{ from: "/a", to: "/b" }]);
});
