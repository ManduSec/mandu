/**
 * exec-signature quoting — the call-root recorder's signature (plan 13 D7)
 * must read a shell `-c` payload exactly as the shell does, and must never
 * make two different commands look alike.
 *
 * The bug (plan 13 D8 leftover (5), 2026-10-03): `unwrapTokens` stripped one
 * more layer of quotes off a `-c` payload that the shell (or the tokenizer)
 * had already unquoted. A Codex/OpenCode/OpenClaw shell `bash -lc '<cmd>'`
 * whose command starts and ends with the same quote character
 * (`"$H" "$F" | tr -d " \n"`) was then re-read with its quotes paired the
 * wrong way round, its signature no longer equalled the call's, and the call
 * was unbound and masked whole. The other half: the signature joined tokens
 * with spaces, so `echo "a b"` and `echo a b`, or a payload with an extra
 * quote layer and the command inside it, had one signature.
 *
 * Unit twin of `tests/stack/quoted-payload-binding.test.ts`.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { execSignature, execSignatureForArgv, rootSignaturesOfArgv } from "../../policy/exec-signature.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the call binding serves the confidentiality axis

/** Claude Code's shell for one Bash call (its `eval '<command>'` quoting). */
const ccShell = (command: string): string[] =>
  ["/bin/zsh", "-c", `source /h/.claude/shell-snapshots/snapshot-zsh-1.sh 2>/dev/null || true && eval '${command.replace(/'/g, `'"'"'`)}' && pwd -P >| /tmp/claude-q-cwd`];
/** Codex/OpenCode/OpenClaw's shell for one call. */
const lcShell = (command: string): string[] => ["/bin/bash", "-lc", command];

/** Commands that start and end with the same quote character. */
const QUOTED = [
  `"/tmp/h/mdu-holder" "$PGPASSFILE" | od -An -tx1 | tr -d " \\n"`,
  `"printf" '%s\\n' "q-ok"`,
  `'a\\b' "c"`,
  `"$X" | grep "y"`,
  `'it'"'"'s' 'x'`,
  `"a\\"b" c "d"`,
];

test("a quoted payload: the shell's signature equals the call's, for every agent's shell shape", () => {
  for (const cmd of QUOTED) {
    const want = execSignature(cmd);
    assert.notEqual(want, "", cmd);
    assert.ok(rootSignaturesOfArgv(lcShell(cmd)).includes(want), `bash -lc ${cmd}: ${JSON.stringify(rootSignaturesOfArgv(lcShell(cmd)))} lacks ${want}`);
    assert.equal(execSignatureForArgv(lcShell(cmd)), want, cmd);
    assert.ok(rootSignaturesOfArgv(ccShell(cmd)).includes(want), `Claude Code eval ${cmd}`);
    // the model wrote the wrapper itself: the same core either way
    const single = `bash -c '${cmd.replace(/'/g, `'"'"'`)}'`;
    assert.equal(execSignature(single), want, single);
    assert.ok(rootSignaturesOfArgv(lcShell(single)).includes(want), `bash -lc ${single}`);
    // Codex's `shell{command: [argv]}`, joined by the proxy's quoteArg
    const joined = ["bash", "-lc", cmd].map((a) => (/^[A-Za-z0-9_@%+=:,./-]+$/.test(a) ? a : `'${a.replace(/'/g, `'"'"'`)}'`)).join(" ");
    assert.equal(execSignature(joined), want, joined);
  }
});

test("the signature keeps argument boundaries: missing or extra quotes are a different command", () => {
  const pairs: Array<[string, string]> = [
    [`echo "a b"`, `echo a b`],                               // missing quotes
    [`grep "x y" f`, `grep x y f`],
    [`mytool ./x.tx? | wc -c`, `"mytool ./x.tx? | wc -c"`],   // an extra quote layer (one word: no such program)
    [`mytool ./x.tx? | wc -c`, `'mytool ./x.tx? | wc -c'`],
    [`cat "$F" | wc -c`, `"cat "$F" | wc -c"`],
    [`tr -d " \\n"`, `tr -d "  \\n"`],                         // whitespace inside a quoted word
    [`echo ''`, `echo`],                                       // an empty argument
    [`echo '' x`, `echo x`],
  ];
  for (const [a, b] of pairs) {
    assert.notEqual(execSignature(a), execSignature(b), `${a}  vs  ${b}`);
    // and as the shells the agent spawns
    assert.ok(!rootSignaturesOfArgv(lcShell(b)).includes(execSignature(a)), `bash -lc ${b} must not bind a call of ${a}`);
    assert.ok(!rootSignaturesOfArgv(ccShell(b)).includes(execSignature(a)), `Claude Code ${b} must not bind a call of ${a}`);
    assert.ok(!rootSignaturesOfArgv(lcShell(a)).includes(execSignature(b)), `bash -lc ${a} must not bind a call of ${b}`);
  }
});

test("a payload equal to another call's command after one more unquoting does not bind that call", () => {
  // The old reading: strip one quote layer off the (already unquoted) payload.
  // A shell whose payload is "<C>" (with the quotes) ran a different command
  // than C; it must not bind C's call.
  for (const c of [`mytool ./x.tx?`, `cat .env | grep FOO`, `head -c 64 ./x.txt`]) {
    for (const q of [`"${c}"`, `'${c}'`]) {
      assert.ok(!rootSignaturesOfArgv(lcShell(q)).includes(execSignature(c)), `bash -lc ${q} bound ${c}`);
      assert.notEqual(execSignatureForArgv(lcShell(q)), execSignature(c), q);
    }
  }
});

test("near-miss payloads never share a signature", () => {
  const cmds = [
    `cat x.txt`, `cat x.txt `, `cat  x.txt`, // the same command (unquoted whitespace)
    `cat x.txt2`, `cat ./x.txt`, `cat x.txt y`, `cat 'x.txt y'`,
    `"cat" x.txt`, // the same command as cat x.txt (a quoted word is the word)
    `cat x.tx?`, `cat x.txt; true`, `cat x.txt ;true`, `cat x.txt\\;true`,
  ];
  const same = new Set([`cat x.txt`, `cat x.txt `, `cat  x.txt`, `"cat" x.txt`]);
  const sigs = new Map<string, string>();
  for (const c of cmds) {
    const s = execSignature(c);
    if (same.has(c)) { assert.equal(s, execSignature("cat x.txt"), c); continue; }
    const prior = sigs.get(s);
    assert.equal(prior, undefined, `${c} and ${prior} share the signature ${s}`);
    assert.notEqual(s, execSignature("cat x.txt"), c);
    sigs.set(s, c);
  }
});

test("the signature is printable and stable for plain commands (no quoting where none is needed)", () => {
  assert.equal(execSignature("grep -n foo   file.txt"), "grep -n foo file.txt");
  assert.equal(execSignature(`bash -lc "curl https://x.test/a"`), "curl https://x.test/a");
  assert.equal(execSignatureForArgv(["/usr/bin/cat", "x.txt"]), "/usr/bin/cat x.txt");
  assert.equal(execSignature(`echo "a b"`), `echo 'a b'`);
  assert.equal(execSignature(`echo "it's"`), `echo 'it'"'"'s'`);
  // the signature read as a command has the same signature (a fixed point)
  for (const cmd of [...QUOTED, `echo "a b"`, `echo ''`]) {
    const s = execSignature(cmd);
    assert.equal(execSignature(s), s, cmd);
  }
});
