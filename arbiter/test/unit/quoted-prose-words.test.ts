/**
 * quoted-prose-words.test.ts — a word inside a quoted run of words is prose,
 * not the labelled folder of the same name (secret-catalog.ts
 * quotedProseWords, 2026-10-26). Live on Haiku 4.5 (demo-scam-email):
 * `tools/mail send jo@parktax.test "…" "Hi Jo, I have my September bank
 * statement ready."` was masked whole as "the command names a secret file"
 * because `bank/` is labelled. Both directions: the prose word is left out;
 * every real reference to the folder still reads secret (fail-closed).
 *
 * Mandu-new test.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { labelForClassify, quotedProseWords, type LabelLookup } from "../../policy/secret-catalog.js";
import type { LabelDecision } from "../../policy/path-labels.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets");

const BANK = "/proj/bank";
const lookup: LabelLookup = Object.assign(
  (p: string): LabelDecision | null => (p === BANK || p.startsWith(`${BANK}/`) ? { level: "no-model", bindings: [], via: BANK } : null),
  { roots: () => [{ path: BANK, level: "no-model" as const }] },
);
const level = (command: string): string =>
  labelForClassify({ tool: "Bash", origin: command, params: { command }, callStartDir: "/proj" }, "/home/u", lookup).level;

test("the live take's mail: `bank` in the message is prose, the send is not masked", () => {
  const live = `tools/mail send jo@parktax.test "Re: Q3 bookkeeping: your September statement" "Hi Jo, I have my September bank statement ready. I'll get it uploaded to both https://parktax.test/clients/alex-demo/upload and the Ledgerly share."`;
  assert.deepEqual([...quotedProseWords(live)].includes("bank"), true);
  assert.equal(level(live), "public");
  for (const c of [
    `git commit -m "fix the bank statement parser"`,
    `echo 'Remember: the bank closes at five'`,
    `tools/mail send a@b.test "Subject" "Your bank, your rules."`,
  ]) {
    assert.equal(level(c), "public", c);
  }
});

test("every real reference to the folder still reads secret (fail-closed)", () => {
  for (const c of [
    "ls bank", // an unquoted bare argument
    "ls bank/",
    "cat ./bank/statement.md",
    "ls bank/*.pdf",
    'ls "$PWD/bank"',
    "cat $PWD/bank/statement.md",
    'cat "bank/statement 2026.md"', // a quoted path with a space
    'cat "bank"', // a single quoted word is an argument
    "cat 'bank'",
    'git commit -m "move bank/statement.pdf out of the repo"', // a path inside the message
    "cat ../proj/bank/statement.md", // through ..
    'grep -r "card number" bank', // the prose is the pattern, the folder an operand
    'tools/mail send x "about bank" bank', // the word also stands outside the quotes
    "cat <<EOF\nsee bank\nEOF", // a heredoc's body is not a quoted run
    'cat "bank',  // unterminated: read as written
    'tar czf out.tgz "bank" docs',
    // a quoted run some program runs as code is no prose
    'bash -c "ls bank"',
    "sh -c 'cat bank/x'",
    'echo "ls bank" | sh',
    'ssh host "ls bank"',
    'sudo sh -c "ls bank"',
    'eval "ls bank"',
    'find . -name x -exec sh -c "ls bank" ;',
    'xargs -I{} /bin/bash -c "ls bank"',
    'timeout 5 zsh -c "ls bank"',
    "git -c alias.x='!ls bank' x",
    'env FOO=1 bash -c "ls bank"',
    'python3 -c "import os; print(os.listdir(\'bank\'))"',
    'awk "BEGIN { system(\\"ls bank\\") }"',
  ]) {
    assert.equal(level(c), "no-model", c);
  }
});

test("a substring of a longer token never named the folder (unchanged)", () => {
  for (const c of ["cat banking.txt", "ls databank/", "cat bank.bak"]) {
    assert.equal(level(c), "public", c);
  }
});

test("quotedProseWords: only plain words, only inside quotes holding a space", () => {
  assert.deepEqual([...quotedProseWords(`echo "a bank b" "x.y z/w" '$HOME q'`)].sort(), ["a", "b", "bank", "q"]);
  assert.deepEqual([...quotedProseWords(`echo "bank"`)], [], "one quoted word is an argument");
  assert.deepEqual([...quotedProseWords(`echo "a bank" bank`)].includes("bank"), false, "also outside the quotes");
  assert.deepEqual([...quotedProseWords(`echo "a b\\" bank c"`)].sort(), ["a", "bank", "c"], "an escaped quote stays inside (and its word is no plain word)");
});
