/**
 * dir-listing.test.ts — "A folder's names" (plan 10 §11.8, 2026-10-17;
 * policy/dir-listing.ts): the content half of the release of a names-only
 * `ls` of a labelled folder. A plain `ls` (no `-l`, no chain, pipe,
 * redirection or expansion) whose output is EXACTLY the names the named
 * folders hold, in byte or GNU locale order, names its folders; anything
 * else (metadata options, a content-printing command beside it, an extra or
 * missing line, a byte no name gives) does not, and the path-derived mask
 * stands.
 *
 * Found live (demo-c2, mode `secrets`): `ls mail/inbox bank/` was masked
 * whole because `bank/` is labelled `no-model`.
 *
 * Mandu-new test. Pure: the filesystem is a map.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DIR_LISTING_MAX_ENTRIES, hostListingFs, plainLsCommand, plainLsListingPaths, type ListingEntry, type ListingFs } from "../../policy/dir-listing.js";
import { KEY_LISTING_OUTPUT_MAX } from "../../policy/claude-code-inbound.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the rule serves the confidentiality axis

const WS = "/home/u/ws";
const TREE: Record<string, ListingEntry> = {
  [`${WS}/bank`]: { dir: ["statement-2026-09.md", "statement-2026-08.md", ".hidden-note"] },
  [`${WS}/mail/inbox`]: { dir: ["3-park-tax.md", "1-dentist.md", "2-book-club.md"] },
  [`${WS}/empty`]: { dir: [] },
  [`${WS}/mixed`]: { dir: ["README.md", "bank", ".env", "Zeta", "_x", "a-b", "ab", "zeta"] },
  [`${WS}/notes.txt`]: { file: true },
  [`${WS}/bank/statement-2026-09.md`]: { file: true },
};

/** A filesystem over TREE, the shell started in WS. */
function fsOver(tree: Record<string, ListingEntry> = TREE, start: string | null = WS): ListingFs {
  return {
    resolve: (w) => (w.startsWith("/") ? w : w.startsWith("~/") ? `/home/u${w.slice(1)}` : w.startsWith("~") ? null : start === null ? null : `${start}/${w}`),
    entry: (p) => tree[p] ?? null,
  };
}

/** What `ls mail/inbox bank/` prints in a pipe (uutils, or GNU in C). */
const DEMO = "bank/:\nstatement-2026-08.md\nstatement-2026-09.md\n\nmail/inbox:\n1-dentist.md\n2-book-club.md\n3-park-tax.md";

test("plainLsCommand: a plain ls with names-only options parses; metadata options, chains, pipes, redirections, expansions and globs do not", () => {
  assert.deepEqual(plainLsCommand("ls mail/inbox bank/"), { hidden: "default", operands: ["mail/inbox", "bank/"] });
  assert.deepEqual(plainLsCommand("ls -1 bank"), { hidden: "default", operands: ["bank"] });
  assert.deepEqual(plainLsCommand("ls -a bank"), { hidden: "all", operands: ["bank"] });
  assert.deepEqual(plainLsCommand("ls -A1 bank"), { hidden: "almost", operands: ["bank"] });
  assert.deepEqual(plainLsCommand("ls -a -A bank"), { hidden: "almost", operands: ["bank"] }, "the last of -a/-A wins, as in GNU ls");
  assert.deepEqual(plainLsCommand("ls --all --color=never bank"), { hidden: "all", operands: ["bank"] });
  assert.deepEqual(plainLsCommand("ls bank -a"), { hidden: "all", operands: ["bank"] }, "options after an operand, as GNU ls takes them");
  assert.deepEqual(plainLsCommand("ls -- -odd"), { hidden: "default", operands: ["-odd"] });
  assert.deepEqual(plainLsCommand(`ls "my dir" 'bank'`), { hidden: "default", operands: ["my dir", "bank"] });
  assert.deepEqual(plainLsCommand("  ls  bank  "), { hidden: "default", operands: ["bank"] });
  for (const cmd of [
    "ls", "ls -a", // no operand: the command names no folder
    "ls -l bank", "ls -la bank", "ls -al bank", "ls -s bank", "ls -i bank", "ls -F bank", "ls -p bank", "ls -R bank", "ls -d bank",
    "ls -t bank", "ls -S bank", "ls -r bank", "ls --full-time bank", "ls --size bank", "ls --color=always bank", "ls -lh bank",
    "ls bank && cat bank/statement-2026-09.md", "ls bank; cat bank/x", "ls bank | head", "ls bank || true", "ls bank & cat x",
    "cat bank/x; ls bank", "(ls bank)", "ls bank > out", "ls bank 2>&1", "ls < x", "ls $HOME", "ls `pwd`", "ls $(pwd)",
    "ls bank/*", "ls bank/?", "ls bank/[a]", "ls {bank,mail}", "ls bank # note", "ls ba\\nk", "ls bank\ncat x",
    "LC_ALL=C ls bank", "/bin/ls bank", "command ls bank", "ls\tbank", "ls 'unterminated", "ls ''", "lsof bank", "dir bank",
  ]) {
    assert.equal(plainLsCommand(cmd), null, cmd);
  }
});

test("the demo: `ls mail/inbox bank/` printing exactly the two folders' names names both folders", () => {
  assert.deepEqual(plainLsListingPaths(DEMO, "ls mail/inbox bank/", fsOver()), [`${WS}/bank`, `${WS}/mail/inbox`]);
  // Codex keeps the final newline; one is framing
  assert.deepEqual(plainLsListingPaths(`${DEMO}\n`, "ls mail/inbox bank/", fsOver()), [`${WS}/bank`, `${WS}/mail/inbox`]);
  // one folder: no header
  assert.deepEqual(plainLsListingPaths("statement-2026-08.md\nstatement-2026-09.md", "ls bank", fsOver()), [`${WS}/bank`]);
  assert.deepEqual(plainLsListingPaths("statement-2026-08.md\nstatement-2026-09.md", "ls -1 bank/", fsOver()), [`${WS}/bank`]);
  // absolute and ~ operands
  assert.deepEqual(plainLsListingPaths("statement-2026-08.md\nstatement-2026-09.md", `ls ${WS}/bank`, fsOver()), [`${WS}/bank`]);
  assert.deepEqual(plainLsListingPaths("statement-2026-08.md\nstatement-2026-09.md", "ls ~/ws/bank", fsOver()), [`${WS}/bank`]);
});

test("-a and -A: hidden names, and . and .. with -a", () => {
  assert.deepEqual(plainLsListingPaths(".\n..\n.hidden-note\nstatement-2026-08.md\nstatement-2026-09.md", "ls -a bank", fsOver()), [`${WS}/bank`]);
  assert.deepEqual(plainLsListingPaths(".hidden-note\nstatement-2026-08.md\nstatement-2026-09.md", "ls -A bank", fsOver()), [`${WS}/bank`]);
  // without -a the hidden name is no entry of the listing
  assert.equal(plainLsListingPaths(".hidden-note\nstatement-2026-08.md\nstatement-2026-09.md", "ls bank", fsOver()), null);
  // with -a it must be there
  assert.equal(plainLsListingPaths("statement-2026-08.md\nstatement-2026-09.md", "ls -A bank", fsOver()), null);
});

test("file operands first, then the folders, a blank line between groups; an empty folder keeps its header", () => {
  const out = "notes.txt\n\nbank/:\nstatement-2026-08.md\nstatement-2026-09.md\n\nempty:\n\nmail/inbox:\n1-dentist.md\n2-book-club.md\n3-park-tax.md";
  assert.deepEqual(plainLsListingPaths(out, "ls notes.txt mail/inbox empty bank/", fsOver()), [`${WS}/bank`, `${WS}/empty`, `${WS}/mail/inbox`, `${WS}/notes.txt`]);
  // a single file operand: the operand as written
  assert.deepEqual(plainLsListingPaths("bank/statement-2026-09.md", "ls bank/statement-2026-09.md", fsOver()), [`${WS}/bank/statement-2026-09.md`]);
  // a file operand with a trailing slash is an error in ls
  assert.equal(plainLsListingPaths("notes.txt/", "ls notes.txt/", fsOver()), null);
  // a single empty folder prints nothing: nothing to release
  assert.equal(plainLsListingPaths("", "ls empty", fsOver()), null);
});

test("two orders: byte order (uutils, a C locale) and GNU ls under en_US.UTF-8; one order for the whole output", () => {
  const bytes = ".env\nREADME.md\nZeta\n_x\na-b\nab\nbank\nzeta";
  const gnu = "a-b\nab\nbank\n.env\nREADME.md\n_x\nzeta\nZeta"; // measured with GNU coreutils ls, LC_ALL=en_US.UTF-8
  assert.deepEqual(plainLsListingPaths(bytes, "ls -A mixed", fsOver()), [`${WS}/mixed`]);
  assert.deepEqual(plainLsListingPaths(gnu, "ls -A mixed", fsOver()), [`${WS}/mixed`]);
  // any other order (here: reversed, or the readdir order) is not a listing
  assert.equal(plainLsListingPaths(bytes.split("\n").reverse().join("\n"), "ls -A mixed", fsOver()), null);
  assert.equal(plainLsListingPaths("README.md\nbank\n.env\nZeta\n_x\na-b\nab\nzeta", "ls -A mixed", fsOver()), null);
  // two groups in different orders: no
  const mixedOrders = `mail/inbox:\n1-dentist.md\n2-book-club.md\n3-park-tax.md\n\nmixed:\n${gnu}`;
  assert.deepEqual(plainLsListingPaths(mixedOrders, "ls -A mixed mail/inbox", fsOver()), [`${WS}/mail/inbox`, `${WS}/mixed`]);
  const bad = `mail/inbox:\n1-dentist.md\n2-book-club.md\n3-park-tax.md\n\nmixed:\n${bytes}`;
  assert.deepEqual(plainLsListingPaths(bad, "ls -A mixed mail/inbox", fsOver()), [`${WS}/mail/inbox`, `${WS}/mixed`], "the inbox's names are in both orders, so byte order holds for both groups");
  const reversedGroups = `mixed:\n${gnu}\n\nmail/inbox:\n1-dentist.md\n2-book-club.md\n3-park-tax.md`;
  assert.equal(plainLsListingPaths(reversedGroups, "ls -A mixed mail/inbox", fsOver()), null, "the folders come in the order's order");
});

test("a content-printing command, a byte no name gives, a missing or duplicated name: no answer (the mask stands)", () => {
  const ACCT = "Account DEMO-ACCT-000123, balance 4,210.00";
  const misses: Array<[string, string, string]> = [
    ["a chain with cat", "ls bank && cat bank/statement-2026-09.md", `statement-2026-08.md\nstatement-2026-09.md\n${ACCT}`],
    ["a chain with cat, the listing alone", "ls bank && cat bank/statement-2026-09.md", "statement-2026-08.md\nstatement-2026-09.md"],
    ["a pipe", "ls bank | cat", "statement-2026-08.md\nstatement-2026-09.md"],
    ["ls -l", "ls -l bank", "total 8\n-rw-r--r-- 1 u u 120 Oct 17 09:00 statement-2026-08.md\n-rw-r--r-- 1 u u 131 Oct 17 09:00 statement-2026-09.md"],
    ["ls -l, names only printed", "ls -l bank", "statement-2026-08.md\nstatement-2026-09.md"],
    ["a content line appended", "ls bank", `statement-2026-08.md\nstatement-2026-09.md\n${ACCT}`],
    ["a content line in place of a name", "ls bank", `statement-2026-08.md\n${ACCT}`],
    ["a name missing", "ls bank", "statement-2026-09.md"],
    ["a name twice", "ls bank", "statement-2026-08.md\nstatement-2026-09.md\nstatement-2026-09.md"],
    ["a trailing space", "ls bank", "statement-2026-08.md \nstatement-2026-09.md"],
    ["a trailing tab", "ls bank", "statement-2026-08.md\nstatement-2026-09.md\t"],
    ["two final newlines", "ls bank", "statement-2026-08.md\nstatement-2026-09.md\n\n"],
    ["a CR", "ls bank", "statement-2026-08.md\r\nstatement-2026-09.md"],
    ["a header on a single folder", "ls bank", "bank:\nstatement-2026-08.md\nstatement-2026-09.md"],
    ["no header on two", "ls mail/inbox bank/", "statement-2026-08.md\nstatement-2026-09.md\n\n1-dentist.md\n2-book-club.md\n3-park-tax.md"],
    ["a header spelled otherwise", "ls mail/inbox bank/", DEMO.replace("bank/:", "bank:")],
    ["no blank line between groups", "ls mail/inbox bank/", DEMO.replace("\n\n", "\n")],
    ["a token", "ls bank", "statement-2026-08.md\n$MDU:nomodel_abc[1a2b]"],
    ["an error line", "ls bank missing", "ls: cannot access 'missing': No such file or directory\nstatement-2026-08.md\nstatement-2026-09.md"],
    ["a folder the command does not name", "ls mail/inbox", "statement-2026-08.md\nstatement-2026-09.md"],
    ["the same folder twice", "ls bank bank/", "bank:\nstatement-2026-08.md\nstatement-2026-09.md\n\nbank/:\nstatement-2026-08.md\nstatement-2026-09.md"],
    ["a column layout (a terminal)", "ls mail/inbox", "1-dentist.md  2-book-club.md  3-park-tax.md"],
  ];
  for (const [why, cmd, out] of misses) assert.equal(plainLsListingPaths(out, cmd, fsOver()), null, why);
  // over the size bound
  const many: Record<string, ListingEntry> = { [`${WS}/big`]: { dir: Array.from({ length: 1500 }, (_, i) => `file-${String(i).padStart(5, "0")}.txt`) } };
  const big = (many[`${WS}/big`] as { dir: string[] }).dir.join("\n");
  assert.ok(big.length > KEY_LISTING_OUTPUT_MAX);
  assert.equal(plainLsListingPaths(big, "ls big", fsOver(many)), null);
});

test("relative operands need the start directory; ~user, a missing operand and a name with a control character answer nothing", () => {
  const out = "statement-2026-08.md\nstatement-2026-09.md";
  assert.equal(plainLsListingPaths(out, "ls bank", fsOver(TREE, null)), null, "no start directory from the guard");
  assert.deepEqual(plainLsListingPaths(out, `ls ${WS}/bank`, fsOver(TREE, null)), [`${WS}/bank`], "an absolute operand needs none");
  assert.equal(plainLsListingPaths(out, "ls ~bob/bank", fsOver()), null);
  assert.equal(plainLsListingPaths(out, "ls nowhere", fsOver()), null);
  const odd: Record<string, ListingEntry> = { [`${WS}/odd`]: { dir: ["a", "b\nc"] } };
  assert.equal(plainLsListingPaths("a\nb\nc", "ls odd", fsOver(odd)), null, "a newline in a name splits it over two lines");
  const esc: Record<string, ListingEntry> = { [`${WS}/esc`]: { dir: ["a", "b\u001b[31m"] } };
  assert.equal(plainLsListingPaths("a\nb\u001b[31m", "ls esc", fsOver(esc)), null);
  // a folder over the entry bound is never matched, even with -A hiding none
  const huge: Record<string, ListingEntry> = { [`${WS}/huge`]: { dir: Array.from({ length: DIR_LISTING_MAX_ENTRIES + 1 }, (_, i) => `.h${i}`) } };
  assert.equal(plainLsListingPaths("x", "ls huge", fsOver(huge)), null);
});

test("hostListingFs: reads the folder as the host has it; a symlinked folder is followed; a non-UTF-8 name, a missing path or no start directory is nothing", () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-dir-listing-"));
  try {
    mkdirSync(join(tmp, "bank"));
    writeFileSync(join(tmp, "bank", "statement-2026-09.md"), "Account DEMO-ACCT-000123\n");
    writeFileSync(join(tmp, "bank", ".hidden"), "x");
    symlinkSync(join(tmp, "bank"), join(tmp, "link"));
    const fs = hostListingFs(tmp, "/nonexistent-home");
    assert.equal(fs.resolve("bank"), join(tmp, "bank"));
    assert.equal(fs.resolve("~/bank"), "/nonexistent-home/bank");
    assert.equal(fs.resolve("~bob/bank"), null);
    const e = fs.entry(join(tmp, "bank"));
    assert.ok(e !== null && "dir" in e);
    assert.deepEqual([...(e as { dir: string[] }).dir].sort(), [".hidden", "statement-2026-09.md"]);
    assert.deepEqual(fs.entry(join(tmp, "bank", "statement-2026-09.md")), { file: true });
    assert.equal(fs.entry(join(tmp, "missing")), null);
    assert.deepEqual(plainLsListingPaths("statement-2026-09.md", "ls link", fs), [join(tmp, "link")]);
    assert.deepEqual(plainLsListingPaths("statement-2026-09.md", "ls bank/", fs), [join(tmp, "bank")]);
    assert.equal(hostListingFs(null, "/h").resolve("bank"), null);
    // a name that is not UTF-8: the folder is never matched
    mkdirSync(join(tmp, "latin1"));
    writeFileSync(Buffer.from(`${join(tmp, "latin1")}/caf\xe9`, "latin1"), "");
    assert.equal(fs.entry(join(tmp, "latin1")), null);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("Codex's head: looked through only when the proxy says the output is Codex's", () => {
  const head = "Chunk ID: 5e1f\nWall time: 0.0123 seconds\nProcess exited with code 0\nOriginal token count: 12\nOutput:\n";
  const out = "statement-2026-08.md\nstatement-2026-09.md\n";
  assert.deepEqual(plainLsListingPaths(`${head}${out}`, "ls bank", fsOver(), { codexHead: true }), [`${WS}/bank`]);
  assert.equal(plainLsListingPaths(`${head}${out}`, "ls bank", fsOver()), null, "on another agent the head is the program's");
  assert.equal(plainLsListingPaths(`${head}${head}${out}`, "ls bank", fsOver(), { codexHead: true }), null, "a second head is body");
});
