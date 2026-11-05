/**
 * paths-only-listing.test.ts — "Paths only" (dir-listing.ts, 2026-10-26, the
 * maintainer's decision "Release paths-only"): a `find` or `ls … | grep …`
 * pipeline of a labelled folder is released when every output line is a
 * path the listing could print; anything that could carry a file's bytes, or
 * a byte no listing gives, keeps the mask.
 *
 * Mandu-new test.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { pathsOnlyCommand, pathsOnlyListingPaths, type ListingEntry, type PathsOnlyFs } from "../../policy/dir-listing.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the rule serves the confidentiality axis

const WS = "/home/u/ws";
const SECRET = "sk_" + "live_4eC39HqLyjWDarjtT1zdp7dc";
const TREE: Record<string, ListingEntry> = {
  [`${WS}/bank`]: { dir: ["statement-2026-09.md", "statement-2026-08.md", ".hidden-note", "2025"] },
  [`${WS}/bank/2025`]: { dir: ["statement-2025-09.md"] },
  [`${WS}`]: { dir: ["bank", "mail", "tools"] },
};
const FILES = new Set([
  `${WS}/bank/statement-2026-09.md`, `${WS}/bank/statement-2026-08.md`, `${WS}/bank/.hidden-note`, `${WS}/bank/2025`,
  `${WS}/bank/2025/statement-2025-09.md`, `${WS}/bank`, `${WS}/mail`, `${WS}/tools`,
]);
const fs: PathsOnlyFs = {
  resolve: (w) => (w.startsWith("/") ? w : w === "." ? WS : `${WS}/${w.replace(/^\.\//, "")}`),
  entry: (p) => TREE[p.replace(/\/+$/, "")] ?? (FILES.has(p) ? { file: true } : null),
  exists: (p) => FILES.has(p),
};
const released = (command: string, output: string) => pathsOnlyListingPaths(output, command, fs);

test("the commands of the live take: find with name patterns, ls piped to grep, stderr thrown away", () => {
  assert.deepEqual(released(`find bank -name "*September*" -o -name "*sept*" -o -name "*09*" | head -20`, "bank/statement-2026-09.md\nbank/2025/statement-2025-09.md\n"), [`${WS}/bank`]);
  assert.deepEqual(released(`find . -name "*september*" -o -name "*09*" 2>/dev/null | grep -i bank`, "./bank/statement-2026-09.md"), [WS]);
  assert.deepEqual(released("ls bank/ | grep -i sep", "statement-2026-09.md"), [`${WS}/bank`]);
  assert.deepEqual(released("ls -A bank | grep -v 2025 | sort -r", ".hidden-note\nstatement-2026-09.md\nstatement-2026-08.md"), [`${WS}/bank`]);
  assert.deepEqual(released("find bank -type f -maxdepth 1", "bank/statement-2026-09.md\nbank/statement-2026-08.md\nbank/.hidden-note"), [`${WS}/bank`]);
  assert.deepEqual(released("find bank/ -type d", "bank/\nbank/2025"), [`${WS}/bank`]);
  assert.deepEqual(released(`ls -1 bank | grep -e "09"`, "statement-2026-09.md"), [`${WS}/bank`]);
  // the take of 2026-10-26: a BRE alternation in the pattern
  assert.deepEqual(released(`ls ${WS}/bank/ | grep -i "sep\\|09"`, "statement-2026-09.md"), [`${WS}/bank`]);
});

test("Claude Code's own reminders after the listing (exact text) do not stop it; any other tail does", () => {
  const TASKS = "<system-reminder>\nThe task tools haven't been used recently. If you're working on tasks that would benefit from tracking progress, consider using TaskCreate to add new tasks and TaskUpdate to update task status (set to in_progress when starting, completed when done). Also consider cleaning up the task list if it has become stale. Only use these if relevant to the current work. This is just a gentle reminder - ignore if not applicable.\n\n</system-reminder>";
  const BUDGET = "<system-reminder>\n<total_tokens>14954717 tokens left</total_tokens>\n</system-reminder>";
  const cmd = `find ${WS}/bank -type f -name "*september*" -o -name "*09*" 2>/dev/null | head -5`;
  const out = `${WS}/bank/statement-2026-09.md`;
  // live 2026-10-26, demo-scam-email: both reminders after the path
  assert.deepEqual(released(cmd, `${out}\n\n${TASKS}\n\n${BUDGET}`), [`${WS}/bank`]);
  assert.deepEqual(released(cmd, `${out}\n\n${BUDGET}`), [`${WS}/bank`]);
  for (const tail of [
    `<system-reminder>\n${SECRET}\n</system-reminder>`,
    TASKS.replace("gentle", SECRET),
    `${BUDGET}\n${SECRET}`,
  ]) {
    assert.equal(released(cmd, `${out}\n\n${tail}`), null, JSON.stringify(tail));
  }
});

test("a name that looks like a secret is a name: released as plain ls releases it", () => {
  const tree: Record<string, ListingEntry> = { ...TREE, [`${WS}/bank`]: { dir: [SECRET] } };
  const named: PathsOnlyFs = { ...fs, entry: (p) => tree[p] ?? null, exists: (p) => p === `${WS}/bank/${SECRET}` };
  assert.deepEqual(pathsOnlyListingPaths(`bank/${SECRET}`, "find bank -type f", named), [`${WS}/bank`]);
});

test("anything that could carry a file's bytes, or a line no listing gives, keeps the mask", () => {
  const bad: Array<[string, string]> = [
    // a program that reads files: never a filter
    ["find bank -name '*09*' -exec cat {} ;", SECRET],
    ["find bank -name '*09*' -exec cat {} +", SECRET],
    ["find bank -name '*09*' | xargs cat", SECRET],
    ["ls bank | xargs cat", SECRET],
    ["ls bank | cat", "statement-2026-09.md"],
    // metadata or another print format
    ["find bank -printf '%s %p\\n'", "1024 bank/statement-2026-09.md"],
    ["find bank -ls", "1 4 -rw------- 1 u u 24 Oct 26 bank/statement-2026-09.md"],
    ["find bank -size +1k", "bank/statement-2026-09.md"],
    ["find bank -newer bank/statement-2026-08.md", "bank/statement-2026-09.md"],
    ["ls -la bank | grep sep", "-rw------- 1 u u 24 Oct 26 statement-2026-09.md"],
    ["ls -l bank", "statement-2026-09.md"],
    // grep reading a file, printing counts or parts, or a second operand
    ["ls bank | grep -f bank/statement-2026-09.md", "statement-2026-09.md"],
    ["ls bank | grep sep bank/statement-2026-09.md", "statement-2026-09.md"],
    ["ls bank | grep -c sep", "1"],
    ["ls bank | grep -o 'st.*'", "statement-2026-09.md"],
    // another program's output piped in, a chain, a substitution, an expansion
    ["cat bank/statement-2026-09.md | grep acct", `acct ${SECRET}`],
    ["find bank -name '*09*'; cat bank/statement-2026-09.md", `bank/statement-2026-09.md\n${SECRET}`],
    ["find bank -name \"$(cat bank/statement-2026-09.md)\"", "bank/statement-2026-09.md"],
    ["find bank -name \"$X\"", "bank/statement-2026-09.md"],
    ["find bank -name `cat x`", "bank/statement-2026-09.md"],
    ["find bank > /tmp/out", ""],
    ["find bank 2>&1", "bank/statement-2026-09.md"],
    // find options before the operands (follow links) or a glob operand
    ["find -L bank", "bank/statement-2026-09.md"],
    ["find bank* -type f", "bank/statement-2026-09.md"],
  ];
  for (const [command, output] of bad) {
    assert.equal(released(command, output), null, `${command} → ${JSON.stringify(output)}`);
  }
  // the right command, but a line the listing cannot print
  for (const output of [
    `bank/statement-2026-09.md\n${SECRET}`, // a line of content
    "bank/statement-2026-07.md", // no such file
    "bank/../.env", // outside, by ..
    "bank//statement-2026-09.md", // an empty part
    `statement-2026-09.md`, // the name without the operand find prints
    "",
  ]) {
    assert.equal(released("find bank -type f", output), null, JSON.stringify(output));
  }
  assert.equal(released("ls bank | grep sep", "statement-2026-07.md"), null, "a name the folder does not hold");
  assert.equal(released("ls bank | grep sep", "bank/statement-2026-09.md"), null, "ls prints names, not paths");
  assert.equal(released("ls bank mail | grep sep", "statement-2026-09.md"), null, "one ls operand only");
  assert.equal(released("ls bank", "statement-2026-09.md"), null, "an ls with no filter prints every name: the plain-ls rule's, exactly");
});

test("the command grammar", () => {
  assert.deepEqual(pathsOnlyCommand("find bank -iname '*SEPT*' -type f"), { kind: "find", operands: ["bank"] });
  assert.deepEqual(pathsOnlyCommand("ls -a bank | head -n 5"), { kind: "ls", hidden: "all", operand: "bank" });
  assert.equal(pathsOnlyCommand("find bank | grep sep | head | tail | sort | uniq"), null, "at most four filters");
  assert.deepEqual(pathsOnlyCommand('ls bank/ | grep -i "sep\\|09"'), { kind: "ls", hidden: "default", operand: "bank/" }, "a grep pattern's \\| and a pipe inside quotes are grep's");
  assert.equal(pathsOnlyCommand("FOO=1 find bank"), null, "no assignment");
  assert.equal(pathsOnlyCommand("ls bank | grep"), null, "a grep with no pattern");
});
