/**
 * path-row-files.test — confidentiality-plan-15-prompt-filter.md §13.12,
 * "What a path row registers", the pure parts:
 *
 *   - `labelForClassify`'s `files`: every secret reading of a call's origin
 *     and input placed on an absolute file, or none at all (a relative token
 *     read nowhere, a command that changes directory, a glob, a source
 *     secret with no secret token): the arbiter narrows a path row only when
 *     it knows every file that made it secret; a leading `cd` to one
 *     literal folder places the rest in it (`leadingCdDir`, 2026-10-19:
 *     an absolute folder, or a relative one read where the command starts,
 *     Claude Code's `Bash` and Codex's `exec_command` alike), and offers the
 *     same readings placed where the command started for a `cd` that
 *     failed (`ifCdFailed`, `leadingCdStart`, `isDirectoryNow`: "A cd that
 *     fails", 2026-10-19);
 *   - the path rows' store keeps an EMPTY line list (the usual case: no
 *     registered secret in the output), which the raised rows' store still
 *     refuses.
 *
 * The real-server conditions: arbiter/test/component/path-row-narrowing.test.ts.
 * Axes explicit: secrets (confidentiality ON, integrity OFF).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { isDirectoryNow } from "../../ipc/server.js";
import { labelForClassify, labelForUnmappedInput, leadingCdDir, leadingCdStart, placedFilesInText, type LabelLookup } from "../../policy/secret-catalog.js";
import { CODEX_WORKDIR_TOOLS } from "../../policy/tool-gate-surface.js";
import { resolvePathLabel, type PathLabel } from "../../policy/path-labels.js";
import { RaisedRowStore } from "../../symbol-table/raised-rows.js";
import type { SymbolEntry, SymbolMap } from "../../symbol-table/symbol-table.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets");

const HOME = "/home/u";
const bash = (command: string, callStartDir?: string) =>
  ({ tool: "Bash", origin: command, params: { command }, ...(callStartDir !== undefined ? { callStartDir } : {}) });

function lookupOver(...rows: Array<Partial<PathLabel> & { path: string }>): LabelLookup {
  const m = new Map<string, PathLabel>();
  for (const r of rows) {
    m.set(r.path, { path: r.path, confidentiality: r.confidentiality ?? "no-model", bindings: [], recursive: r.recursive ?? true, source: "user", updatedAt: 1 });
  }
  return (p) => resolvePathLabel(p, m, HOME);
}
const none: LabelLookup = () => null;

test("files: the c6 batch's one secret reading, placed where the shell ran; the plain files are not secret", () => {
  const l = labelForClassify(bash("cat notes-app/.env notes-app/add-page.sh meetings/2026-10-16-team-sync.md", "/w/ws"), HOME, none);
  assert.equal(l.level, "no-model");
  assert.deepEqual(l.files, ["/w/ws/notes-app/.env"]);
  // the quoted separator Codex printed names the same file
  const codex = labelForClassify(bash("printf '%s\\n' '--- notes-app/.env ---' && sed -n '1,160p' notes-app/.env", "/w/ws"), HOME, none);
  assert.deepEqual(codex.files, ["/w/ws/notes-app/.env"]);
});

test("files: an absolute path needs no directory; a user label's file and a catalog file are both placed; placed lists every plain path token", () => {
  const lk = lookupOver({ path: "/w/ws/secrets/plan.md", recursive: false });
  const l = labelForClassify(bash("cat /w/ws/secrets/plan.md /w/ws/.aws/credentials notes.md /w/ws/notes.md"), HOME, lk);
  assert.equal(l.level, "no-model");
  assert.deepEqual(l.files, ["/w/ws/.aws/credentials", "/w/ws/secrets/plan.md"]);
  assert.deepEqual(l.placed, ["/w/ws/.aws/credentials", "/w/ws/notes.md", "/w/ws/secrets/plan.md"], "a relative token with no directory is placed nowhere");
  // every word is a candidate (the arbiter reads only an existing regular
  // file no label calls secret); a token with quoting or an escape inside
  // it, a glob or a .. segment places nothing
  const rel = labelForClassify(bash("cat .env notes.md a\\b.md x\"y\".md *.md ../up.md", "/w/ws"), HOME, none);
  assert.deepEqual(rel.placed, ["/w/ws/.env", "/w/ws/cat", "/w/ws/notes.md"]);
});

test("files: absent when any secret reading cannot be placed (fail-closed)", () => {
  const cases: Array<[string, ReturnType<typeof bash>]> = [
    ["a relative token, no directory known", bash("cat .env notes.md")],
    ["a command that changes directory", bash("cat .env; cd app && cat x.md", "/w/ws")],
    ["a leading relative cd, no directory known", bash("cd app && cat .env")],
    ["a sourced file (it may change directory)", bash(". ./setup.sh; cat .env", "/w/ws")],
    ["one placed, one not", bash("cat /w/ws/.env other/.env")],
    ["a .. segment in an absolute path", bash("cat /w/ws/../ws/.env")],
    ["a .. segment in a relative path (the kernel reads it through symlinks)", bash("cat lnk/../.env", "/w/ws")],
    ["a ~ path (the shell's HOME may not be the arbiter's)", bash("cat ~/.aws/credentials")],
    ["an escaped cd", bash("\\cd app && cat .env", "/w/ws")],
    ["a cd split by quotes", bash("c\"\"d app && cat .env", "/w/ws")],
    ["a chdir in code the command runs", bash("python3 -c 'import os; os.chdir(\"app\"); print(open(\".env\").read())' .env", "/w/ws")],
  ];
  for (const [why, req] of cases) {
    const l = labelForClassify(req, HOME, none);
    assert.equal(l.level, "no-model", `${why}: still secret`);
    assert.equal(l.files, undefined, `${why}: no files`);
  }
  // a public verdict has no files either
  assert.equal(labelForClassify(bash("cat notes.md", "/w/ws"), HOME, none).files, undefined);
});

test("a leading cd: the c1 batch (Claude Code, defaults) is placed in the folder its absolute cd names", () => {
  const c1 = "cd /w/ws/weather-app && ls; echo ---; cat config/settings.json 2>/dev/null; echo ---; cat logs/app.log 2>/dev/null; echo ---ENV---; cat .env 2>/dev/null";
  for (const start of ["/w/ws", undefined]) {
    const l = labelForClassify(bash(c1, start), HOME, none);
    assert.equal(l.level, "no-model", "still secret: the mask is unchanged");
    assert.deepEqual(l.files, ["/w/ws/weather-app/.env"], `placed where the rest runs (start ${start})`);
    for (const f of ["/w/ws/weather-app/config/settings.json", "/w/ws/weather-app/logs/app.log"]) assert.ok(l.placed?.includes(f), `${f} placed`);
  }
  // `;` or a line break after the cd, and a quoted folder
  assert.deepEqual(labelForClassify(bash("cd /w/ws/app; cat .env notes.md", "/w/ws"), HOME, none).files, ["/w/ws/app/.env"]);
  assert.deepEqual(labelForClassify(bash("cd /w/ws/app\ncat .env", "/w/ws"), HOME, none).files, ["/w/ws/app/.env"]);
  assert.deepEqual(labelForClassify(bash("cd '/w/my ws/app' && cat .env", "/w/ws"), HOME, none).files, ["/w/my ws/app/.env"]);
  assert.equal(leadingCdDir("cd /w/ws/app/ && cat .env"), "/w/ws/app");
});

test("a leading cd: anything but one absolute literal folder first, and a rest that stays there, places nothing (fail-closed)", () => {
  const cases: Array<[string, string]> = [
    ["the previous folder", "cd - && cat .env"],
    ["an empty folder", "cd '' && cat .env"],
    ["zsh's directory stack", "cd +1 && cat .env"],
    ["zsh's =cmd", "cd =app && cat .env"],
    ["a relative .. segment", "cd ../app && cat .env"],
    ["a relative .. segment inside", "cd app/../other && cat .env"],
    ["a cd that is not the first command", "echo hi; cd /w/ws/app && cat .env"],
    ["the rest changes directory again", "cd /w/ws/app && cd sub && cat .env"],
    ["a subshell's cd in the rest", "cd /w/ws/app && (cd /w/other; cat .env)"],
    ["the rest runs a sourced file", "cd /w/ws/app && . ./setup.sh; cat .env"],
    ["an expansion in the folder", "cd $HOME/app && cat .env"],
    ["a quoted expansion", "cd \"$APP\" && cat .env"],
    ["a ~ folder", "cd ~/app && cat .env"],
    ["a .. segment", "cd /w/ws/../ws/app && cat .env"],
    ["a glob", "cd /w/ws/ap* && cat .env"],
    ["an option", "cd -P /w/ws/app && cat .env"],
    ["an escaped cd", "\\cd /w/ws/app && cat .env"],
    ["`||`: the rest runs where the cd failed", "cd /w/ws/app || cat .env"],
    ["`&`: the cd runs in the background", "cd /w/ws/app & cat .env"],
    ["a pipe", "cd /w/ws/app | cat .env"],
    ["a redirection before the separator", "cd /w/ws/app >/dev/null && cat .env"],
  ];
  for (const [why, command] of cases) {
    const l = labelForClassify(bash(command, "/w/ws"), HOME, none);
    assert.equal(l.level, "no-model", `${why}: still secret`);
    assert.equal(l.files, undefined, `${why}: no files`);
  }
  assert.equal(leadingCdDir("cat .env"), undefined);
  assert.equal(leadingCdDir("cd /w/ws/app"), undefined, "a cd alone has no rest");
});

test("a leading relative cd (2026-10-19): placed in the folder it names below the directory the command starts in, and only there", () => {
  // the c1 command as the model wrote it when its shell was already in the workspace
  const c1 = "cd weather-app && ls; echo ---; cat config/settings.json 2>/dev/null; echo ---; cat logs/app.log 2>/dev/null; echo ---ENV---; cat .env 2>/dev/null";
  const l = labelForClassify(bash(c1, "/w/ws"), HOME, none);
  assert.equal(l.level, "no-model", "still secret: the mask is unchanged");
  assert.deepEqual(l.files, ["/w/ws/weather-app/.env"]);
  for (const f of ["/w/ws/weather-app/config/settings.json", "/w/ws/weather-app/logs/app.log"]) assert.ok(l.placed?.includes(f), `${f} placed`);
  // no start directory (no kernel record): placed nowhere
  assert.equal(labelForClassify(bash(c1), HOME, none).files, undefined);
  // `./`, a deeper folder, a quoted one, `;` and a line break
  assert.deepEqual(labelForClassify(bash("cd ./app && cat .env", "/w/ws"), HOME, none).files, ["/w/ws/app/.env"]);
  assert.deepEqual(labelForClassify(bash("cd app/sub; cat .env notes.md", "/w/ws"), HOME, none).files, ["/w/ws/app/sub/.env"]);
  assert.deepEqual(labelForClassify(bash("cd 'my app'\ncat .env", "/w/ws"), HOME, none).files, ["/w/ws/my app/.env"]);
  assert.equal(leadingCdDir("cd app && cat .env", "/w/ws"), "/w/ws/app");
  assert.equal(leadingCdDir("cd . && cat .env", "/w/ws"), "/w/ws");
  // a start directory that is not one
  assert.equal(leadingCdDir("cd app && cat .env"), undefined);
  assert.equal(leadingCdDir("cd app && cat .env", "w/ws"), undefined, "relative start");
  assert.equal(leadingCdDir("cd app && cat .env", "/w/lnk/../ws"), undefined, "a .. segment in the start");
  // the plain files: placed in the folder too, none without a start
  // (every word is a candidate: the arbiter reads only an existing plain file)
  assert.deepEqual(placedFilesInText("cd app && cat notes.md /w/x.md", "/w/ws"), ["/w/ws/app/app", "/w/ws/app/cat", "/w/ws/app/cd", "/w/ws/app/notes.md", "/w/x.md"]);
  assert.deepEqual(placedFilesInText("cd app && cat notes.md /w/x.md"), ["/w/x.md"]);
  // the rest changes directory again: nothing
  assert.equal(labelForClassify(bash("cd app && cd sub && cat .env", "/w/ws"), HOME, none).files, undefined);
});

test("a leading cd that fails (2026-10-19): the same readings also placed where the command started, offered beside the folder's", () => {
  // battery m1r2: Claude Code's shell was already in weather-app (an earlier
  // call's `cd weather-app;`), so this `cd weather-app` failed and `;` ran
  // the rest from weather-app itself
  const c1 = "cd weather-app; ls -la; echo ---; cat config/settings.json 2>/dev/null; echo ---; cat logs/app.log 2>/dev/null | head -50; echo ---ENV---; cat .env 2>/dev/null";
  const l = labelForClassify(bash(c1, "/w/ws/weather-app"), HOME, none);
  assert.equal(l.level, "no-model", "still secret: the mask is unchanged");
  assert.deepEqual(l.files, ["/w/ws/weather-app/weather-app/.env"], "the folder's placement is unchanged");
  assert.ok(l.ifCdFailed, "the start directory's placement is offered");
  assert.equal(l.ifCdFailed.dir, "/w/ws/weather-app/weather-app", "the folder whose absence selects it");
  assert.deepEqual(l.ifCdFailed.files, ["/w/ws/weather-app/.env"]);
  for (const f of ["/w/ws/weather-app/config/settings.json", "/w/ws/weather-app/logs/app.log"]) assert.ok(l.ifCdFailed.placed.includes(f), `${f} placed where the command started`);
  assert.ok(!l.ifCdFailed.placed.some((f) => f.startsWith("/w/ws/weather-app/weather-app/")), "nothing of the folder's placement in it");
  // an absolute folder: the start directory's placement too; an absolute token is itself both ways
  const abs = labelForClassify(bash("cd /w/ws/app; cat .env /w/x.md", "/w/other"), HOME, none);
  assert.deepEqual(abs.files, ["/w/ws/app/.env"]);
  assert.deepEqual(abs.ifCdFailed?.files, ["/w/other/.env"]);
  assert.ok(abs.ifCdFailed?.placed.includes("/w/x.md"));
  // `&&` too: the commands past the first `;` run whatever the cd did
  assert.deepEqual(labelForClassify(bash("cd app && ls; cat .env", "/w/ws"), HOME, none).ifCdFailed?.files, ["/w/ws/.env"]);
  // not offered: no start directory (an absolute folder is still placed), no leading cd, nothing placed
  const noStart = labelForClassify(bash("cd /w/ws/app; cat .env"), HOME, none);
  assert.deepEqual(noStart.files, ["/w/ws/app/.env"]);
  assert.equal(noStart.ifCdFailed, undefined, "no start directory: nowhere to place a failed cd's rest");
  assert.equal(labelForClassify(bash("cat .env notes.md", "/w/ws"), HOME, none).ifCdFailed, undefined, "no leading cd");
  assert.equal(labelForClassify(bash("cd app && cd sub && cat .env", "/w/ws"), HOME, none).ifCdFailed, undefined, "a second cd: nothing placed");
  assert.equal(labelForClassify(bash("cd app; cat .env", "/w/lnk/../ws"), HOME, none).ifCdFailed, undefined, "a .. segment in the start");
  // the pure parts
  assert.equal(leadingCdStart("/w/ws/"), "/w/ws");
  assert.equal(leadingCdStart(undefined), undefined);
  assert.equal(leadingCdStart("w/ws"), undefined, "relative start");
  assert.equal(leadingCdStart("/w/lnk/../ws"), undefined, "a .. segment in the start");
  assert.deepEqual(placedFilesInText("cd app; cat notes.md /w/x.md", "/w/ws", { ifCdFailed: true }), ["/w/ws/app", "/w/ws/cat", "/w/ws/cd", "/w/ws/notes.md", "/w/x.md"]);
  assert.deepEqual(placedFilesInText("cat notes.md", "/w/ws", { ifCdFailed: true }), placedFilesInText("cat notes.md", "/w/ws"), "no leading cd: placed as without it");
  assert.deepEqual(placedFilesInText("cd app; cat notes.md /w/x.md", undefined, { ifCdFailed: true }), ["/w/x.md"], "no start: the absolute tokens only");
});

test("isDirectoryNow: false only for nothing there or a non-directory (a failed cd), true for a directory and a link to one", () => {
  const d = mkdtempSync(join(tmpdir(), "mandu-cd-now-"));
  try {
    mkdirSync(join(d, "app"));
    writeFileSync(join(d, "file"), "x");
    symlinkSync(join(d, "app"), join(d, "link"));
    assert.equal(isDirectoryNow(join(d, "app")), true);
    assert.equal(isDirectoryNow(join(d, "link")), true, "cd follows a link");
    assert.equal(isDirectoryNow(join(d, "missing")), false, "ENOENT");
    assert.equal(isDirectoryNow(join(d, "file")), false, "a file: cd fails");
    assert.equal(isDirectoryNow(join(d, "file", "sub")), false, "ENOTDIR");
  } finally { rmSync(d, { recursive: true, force: true }); }
});

test("a leading cd in Codex's exec_command (2026-10-19): placed in its folder, read from the workdir the call names", () => {
  const codex = (cmd: string, extra: Record<string, unknown> = {}) => ({ cmd, workdir: "/w/ws", yield_time_ms: 10000, ...extra });
  for (const [cmd, file] of [
    ["cd /w/ws/notes-app && sed -n '1,160p' .env && cat /w/ws/meetings/sync.md", "/w/ws/notes-app/.env"],
    ["cd notes-app && sed -n '1,160p' .env && cat add-page.sh", "/w/ws/notes-app/.env"],
  ] as const) {
    // every string of the unmapped input (the wide reading)
    const wide = labelForUnmappedInput([codex(cmd)], HOME, none, "/w/ws");
    assert.equal(wide.level, "no-model", `${cmd}: still secret`);
    assert.deepEqual(wide.files, [file], `${cmd}: the wide reading places it`);
    // the named reading (its origin is the cmd)
    const named = labelForClassify({ tool: "exec_command", origin: cmd, params: codex(cmd), workdirTools: CODEX_WORKDIR_TOOLS }, HOME, none);
    assert.deepEqual(named.files, [file], `${cmd}: the named reading places it`);
  }
  assert.ok(labelForClassify({ tool: "exec_command", origin: "cd notes-app && cat .env add-page.sh", params: codex("cd notes-app && cat .env add-page.sh"), workdirTools: CODEX_WORKDIR_TOOLS }, HOME, none).placed?.includes("/w/ws/notes-app/add-page.sh"));
  // fail-closed: another string moves it, a relative workdir, no directory
  const cases: Array<[string, unknown, string | undefined]> = [
    ["a cd in another string", codex("cd notes-app && cat .env", { note: "cd /w/other" }), "/w/ws"],
    ["a relative workdir (read like a cd target)", { cmd: "cd notes-app && cat .env", workdir: "sub" }, undefined],
    ["a directory key that is no string", codex("cd notes-app && cat .env", { cwd: ["/w"] }), "/w/ws"],
    ["no directory the call runs in", { cmd: "cd notes-app && cat .env" }, undefined],
    ["the rest changes directory", codex("cd notes-app && cd .. && cat .env"), "/w/ws"],
  ];
  for (const [why, input, base] of cases) {
    const wide = labelForUnmappedInput([input], HOME, none, base);
    assert.equal(wide.level, "no-model", `${why}: still secret`);
    assert.equal(wide.files, undefined, `${why}: no files`);
  }
  // a label in the folder the cd leads to still raises the token, which
  // is then placed nowhere (its reading is the label's, not its own)
  const lk = lookupOver({ path: "/w/ws/notes-app/plan.md", recursive: false });
  const labelled = labelForUnmappedInput([codex("cd notes-app && cat plan.md .env")], HOME, lk, "/w/ws");
  assert.equal(labelled.level, "no-model");
  assert.equal(labelled.files, undefined);
});

test("a leading cd places, never lifts: a label after it stays raise-only", () => {
  // a human `public` label on the .env the cd leads to does not lower the
  // catalog's reading of the token (only an exact base lifts a label)
  const pub = lookupOver({ path: "/w/ws/app/.env", recursive: false, confidentiality: "public" });
  assert.equal(labelForClassify(bash("cd /w/ws/app && cat .env", "/w/ws"), HOME, pub).level, "no-model");
  assert.equal(labelForClassify(bash("cd app && cat .env", "/w/ws"), HOME, pub).level, "no-model", "nor after a relative cd");
  // a label at the start directory (where a failed cd leaves the shell)
  // still raises the token, which is then placed nowhere
  const atStart = lookupOver({ path: "/w/ws/notes.md", recursive: false });
  const failed = labelForClassify(bash("cd app && cat .env notes.md", "/w/ws"), HOME, atStart);
  assert.equal(failed.level, "no-model");
  assert.equal(failed.files, undefined, "a secret reading the cd's folder does not hold is not placed");
  // a label that raises a plain name there still raises it; its reading is
  // the label's, not the token's own, so it is placed nowhere
  const lk = lookupOver({ path: "/w/ws/app/plan.md", recursive: false });
  const l = labelForClassify(bash("cd /w/ws/app && cat plan.md", "/w/ws"), HOME, lk);
  assert.equal(l.level, "no-model");
  assert.equal(l.files, undefined);
});

test("second review: a quoting-hidden directory change stops placing a relative token, never the level its base gives", () => {
  const lk = lookupOver({ path: "/w/ws/secrets/plan.md", recursive: false });
  for (const command of ["cat secrets/plan.md; grep -n 'chdir(' tool.py", "cat secrets/plan.md; grep -rn 'os.chdir(' ."]) {
    const l = labelForClassify(bash(command, "/w/ws"), HOME, lk);
    assert.equal(l.level, "no-model", `${command}: the human's label on the file still decides`);
    assert.equal(l.files, undefined, `${command}: but the reading is not placed`);
  }
  assert.deepEqual(labelForClassify(bash("cat secrets/plan.md", "/w/ws"), HOME, lk).files, ["/w/ws/secrets/plan.md"], "control");
});

test("files: a typed path field is placed as the agent reads it", () => {
  const read = labelForClassify({ tool: "Read", origin: "/w/ws/.env", params: { file_path: "/w/ws/.env" } }, HOME, none);
  assert.deepEqual(read.files, ["/w/ws/.env"]);
  const based = labelForClassify(
    { tool: "read", origin: "test/.env", params: { path: "test/.env" }, pathBase: { dir: "/w/ws", fields: ["path"] } },
    HOME, none,
  );
  assert.deepEqual(based.files, ["/w/ws/test/.env"]);
});

test("files: a tool the spec does not map has every string read, and each secret reading placed (Codex's exec_command)", () => {
  const input = { cmd: "sed -n '1,160p' notes-app/.env && cat meetings/sync.md", workdir: "/w/ws", yield_time_ms: 10000 };
  const wide = labelForUnmappedInput([input], HOME, none, "/w/ws");
  assert.equal(wide.level, "no-model");
  assert.deepEqual(wide.files, ["/w/ws/notes-app/.env"]);
  // a string the command does not show (another key) naming an unplaced secret: none
  assert.equal(labelForUnmappedInput([{ ...input, note: "see .env" }], HOME, none).files, undefined, "no directory: the relative readings are placed nowhere");
  assert.equal(labelForUnmappedInput([{ ...input, extra: "cat other/.env" }], HOME, none, undefined).files, undefined);
  // a file:// URL is a path
  assert.deepEqual(labelForUnmappedInput([{ src: "file:///w/ws/.env" }], HOME, none).files, ["/w/ws/.env"]);
  // past the scan's bounds: no-model, no files
  assert.equal(labelForUnmappedInput([{ big: "x".repeat(2 * 1024 * 1024) }], HOME, none).files, undefined);
});

function row(value: string): SymbolEntry {
  return {
    value, tool: "Bash", field: null, origin: "cat .env", session_key: "s", call_id: "c", created_at: 0,
    obsoleted_at: null, obsoleted_by: null, derived_from: null, line_range: null,
    confidentiality: "no-model", bindings: null, integrity: "trusted",
  };
}

test("the path rows' store keeps an empty line list, bound to the row's value; the raised rows' store still refuses one", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-path-store-"));
  try {
    const dbPath = join(dir, "db.sqlite");
    const path = new RaisedRowStore({ dbPath, kind: "path" });
    path.record("$MDU:p[0001]", "batch output\n", new Set());
    path.record("$MDU:p[0002]", "old value\n", new Set());
    path.close();
    const raised = new RaisedRowStore({ dbPath });
    raised.record("$MDU:r[0001]", "batch output\n", new Set());
    raised.close();
    const map: SymbolMap = { symbols: new Map([["$MDU:p[0001]", row("batch output\n")], ["$MDU:p[0002]", row("another value\n")], ["$MDU:r[0001]", row("batch output\n")]]) };
    const p2 = new RaisedRowStore({ dbPath, kind: "path" });
    assert.deepEqual([...p2.load(map)].map(([n, k]) => [n, [...k]]), [["$MDU:p[0001]", []]], "an empty list loads; a changed value does not");
    p2.close();
    const r2 = new RaisedRowStore({ dbPath });
    assert.deepEqual([...r2.load(map)], [], "a raised row with no kept line is not loaded");
    r2.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
