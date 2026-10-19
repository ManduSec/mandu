/**
 * dir-listing-compound.test.ts — the pure parts of "a folder's names beside
 * another command" (docs/design/confidentiality/folder-listing-compound.md):
 * the compound's parse (L1-L3), the rebuild without the listing (L4), the
 * split of the output (L5) and the `ls` exec match (L8).
 *
 * Run: npm run test:unit
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { compoundListingPaths, compoundLsCommand, compoundWithoutLs, isLsArgv, lsArgvMatches, plainLsCommand, type ListingFs } from "../../policy/dir-listing.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets");

test("L1-L3: one plain ls at an end beside allow-listed programs", () => {
  const c = compoundLsCommand("tools/mail list; ls mail/inbox bank");
  assert.ok(c);
  assert.deepEqual(c.segments, ["tools/mail list", "ls mail/inbox bank"]);
  assert.equal(c.lsIndex, 1);
  assert.deepEqual(c.ls.operands, ["mail/inbox", "bank"]);
  assert.equal(compoundLsCommand("ls -A bank && git status")?.lsIndex, 0);
  assert.equal(compoundLsCommand("./run.sh 'a b'; ls bank")?.lsIndex, 1);
  for (const cmd of [
    "ls bank",                                    // one segment: the single listing's
    "tools/mail list || ls bank", "tools/mail list | ls bank", "tools/mail list & ls bank", "tools/mail list &&& ls bank",
    "tools/mail list;; ls bank", "; ls bank", "ls bank;", "tools/mail list; ls bank; tools/mail list",
    "ls a; ls b", "/bin/ls bank; tools/x", "command ls bank; tools/x", "VAR=1 tools/x; ls bank", "'hash' -p /tmp/ls ls; ls bank",
    "cd bank; ls", "cd bank && ls .", "hash -p /tmp/x/ls ls; ls bank", "autoload /x/ls; ls bank", "echo hi; ls bank",
    "tools/mail list; ls -l bank", "tools/mail list; ls bank > x", "tools/mail list; ls $D", "tools/mail list; ls ba*",
    "tools/mail list; ls ~/bank", "tools/mail list; ls bank^x", "tools/mail list; ls bank%1", "tools/mail list\nls bank",
    "tools/mail 'list; ls' bank", "tools/mail list; ls 'bank",
    "date; ls bank\v", "date; ls bank\u00a0", "date; ls bank\u2028",
  ]) assert.equal(compoundLsCommand(cmd), null, cmd);
  // a quoted separator does not split
  assert.equal(compoundLsCommand("tools/mail ';' ls bank"), null);
});

test("L4: rebuilt by the command's own split; never a substring replace", () => {
  assert.equal(compoundWithoutLs("tools/mail list; ls mail/inbox bank", 1, 2), "tools/mail list");
  assert.equal(compoundWithoutLs("grep -rn ls x.md; ls x.md", 1, 2), "grep -rn ls x.md");
  assert.equal(compoundWithoutLs("git log && tools/x; ls bank", 2, 3), "git log; tools/x");
  assert.equal(compoundWithoutLs("tools/mail list; ls bank", 0, 2), null, "the ls at another index");
  assert.equal(compoundWithoutLs("tools/mail 'list; ls bank'", 1, 2), null, "a spelling that splits otherwise");
});

const fs: ListingFs = {
  resolve: (w) => `/ws/${w}`,
  entry: (p) => p === "/ws/bank" ? { dir: ["statement-2026-08.md", "statement-2026-09.md"] } : p === "/ws/mail/inbox" ? { dir: ["1.md", "2.md"] } : null,
};

test("L5: the listing as the first or last lines, at its one line count", () => {
  const listing = "bank:\nstatement-2026-08.md\nstatement-2026-09.md\n\nmail/inbox:\n1.md\n2.md";
  assert.deepEqual(compoundListingPaths(`mail: 2 new\n${listing}\n`, "ls mail/inbox bank", false, fs), ["/ws/bank", "/ws/mail/inbox"]);
  assert.deepEqual(compoundListingPaths(`statement-2026-08.md\nstatement-2026-09.md\nOn branch main\n`, "ls bank", true, fs), ["/ws/bank"]);
  for (const out of [
    `${listing}\n`,                                   // no other line
    `mail: 2 new\n${listing}\nextra\n`,               // a line after the listing
    `mail: 2 new\n${listing.replace("2.md", "")}`,    // a name short
    `mail: 2 newbank:\nstatement-2026-08.md\nstatement-2026-09.md\n\nmail/inbox:\n1.md\n2.md`, // merged into the first line
    `see $MDU:nomodel_x[abcd]\n${listing}`,           // a token
  ]) assert.equal(compoundListingPaths(out, "ls mail/inbox bank", false, fs), null, out);
  // Codex's head is looked through only when the caller says so
  const head = "Chunk ID: 5e1f\nWall time: 0.0123 seconds\nProcess exited with code 0\nOriginal token count: 12\nOutput:\n";
  assert.deepEqual(compoundListingPaths(`${head}mail: 2 new\n${listing}\n`, "ls mail/inbox bank", false, fs, { codexHead: true }), ["/ws/bank", "/ws/mail/inbox"]);
});

test("L8: the guard's argv of ls, with the listing's operands; names-only options allowed", () => {
  const ls = plainLsCommand("ls mail/inbox bank")!;
  assert.equal(lsArgvMatches(["ls", "mail/inbox", "bank"], ls), true);
  assert.equal(lsArgvMatches(["/usr/bin/ls", "--color=auto", "mail/inbox", "bank"], ls), true);
  assert.equal(lsArgvMatches(["ls", "-l", "mail/inbox", "bank"], ls), false);
  assert.equal(lsArgvMatches(["ls", "bank", "mail/inbox"], ls), false);
  assert.equal(lsArgvMatches(["cat", "mail/inbox", "bank"], ls), false);
  assert.equal(lsArgvMatches(["ls", "mail/inbox", "bank\v"], plainLsCommand("ls mail/inbox bank")!), false, "a non-printable byte");
  assert.equal(isLsArgv(["/bin/ls"]), true);
  assert.equal(isLsArgv(["lsof"]), false);
});
