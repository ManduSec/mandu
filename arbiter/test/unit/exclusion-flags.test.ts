/**
 * exclusion-flags.test.ts — a search that excludes a labelled path
 * (docs/design/confidentiality/exclusion-flags.md): the pure blanking of a
 * grep's `--exclude-dir=NAME` (X2) and `--exclude=` (X7) words and an rg's
 * negated globs (X6), inside an exactly segmented command (X4, X5), never
 * after `--` nor as a file argument (X3); the classify's path rules reading
 * demo-c2's and demo-notion-token's commands with it (`labelForClassify`);
 * the three call sites read alike (the classify, the unmapped-input scan
 * behind `pathLevelWith`), and a seeded fuzz: the reading of a blanked line
 * equals the reading of the line with the words deleted.
 *
 * Run: npm run test:unit
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { searchExclusionSpans, withoutSearchExclusions } from "../../policy/exclusion-flags.js";
import { labelForClassify, type LabelLookup } from "../../policy/secret-catalog.js";
import { snapshotLookup, withLabelRoots, type LabelSnapshot } from "../../policy/label-lookup.js";
import { createEngineBackedPolicy } from "../../policy/policy-interface.js";
import type { LabelDecision } from "../../policy/path-labels.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets");

const DEMO = "grep -rIl -i park . --exclude-dir=bank";
const blanked = (c: string): boolean => withoutSearchExclusions(c) !== c;

test("blanked: each whole --exclude-dir=NAME word of a grep, same length", () => {
  assert.equal(withoutSearchExclusions(DEMO), `grep -rIl -i park . ${" ".repeat("--exclude-dir=bank".length)}`);
  assert.equal(withoutSearchExclusions(DEMO).length, DEMO.length);
  for (const c of [
    "grep -r park . --exclude-dir=bank --exclude-dir=.git",
    "egrep -rl 'a b' . --exclude-dir=bank/",
    "fgrep -r x --exclude-dir=bank.old .",
    "grep -e --exclude-dir=bank -r .", // as -e's pattern it is text, never a path
    // X4 (2026-10-27): a segment of an exactly split compound
    "grep -r park . --exclude-dir=bank | head",
    "cd ws && grep -r park . --exclude-dir=bank",
  ]) {
    const spans = searchExclusionSpans(c);
    assert.ok(spans && spans.length > 0, c);
    assert.ok(!/--exclude-dir=/.test(withoutSearchExclusions(c)), c);
  }
});

// demo-notion-token (Codex, 2026-10-27): its first command and its retry
const CODEX_1 = `pwd && rg --files -g 'AGENTS.md' -g 'notes-app/**' -g 'meetings/**' -g '!notes-app/.env' | sort && echo '--- notes-app listing ---' && ls -la notes-app && echo '--- meeting file ---' && sed -n '1,240p' meetings/2026-10-16-team-sync.md && echo '--- scripts/config references ---' && rg -n "notion|env|dotenv|token|meeting" notes-app --glob '!*.env'`;
const CODEX_2 = CODEX_1.replace("-g '!notes-app/.env'", "-g '!notes-app/.env' -g '!**/*.env'");

test("blanked (X6): Codex's two exact commands, each negated pair whole, nothing else", () => {
  const b1 = withoutSearchExclusions(CODEX_1);
  assert.equal(b1.length, CODEX_1.length);
  assert.equal(b1, CODEX_1.replace("-g '!notes-app/.env'", " ".repeat("-g '!notes-app/.env'".length)).replace("--glob '!*.env'", " ".repeat("--glob '!*.env'".length)));
  const b2 = withoutSearchExclusions(CODEX_2);
  assert.ok(!b2.includes("!"), b2);
  for (const kept of ["-g 'AGENTS.md'", "-g 'notes-app/**'", "-g 'meetings/**'", "sed -n '1,240p' meetings/2026-10-16-team-sync.md", `"notion|env|dotenv|token|meeting"`]) {
    assert.ok(b2.includes(kept), `a positive glob and every other word stay: ${kept}`);
  }
});

test("blanked (X6, X7): every accepted shape", () => {
  const cases: Array<[string, string[]]> = [
    ["rg -n foo -g '!x'", ["-g", "'!x'"]],
    ["rg -n foo notes-app --glob '!*.env'", ["--glob", "'!*.env'"]],
    ["rg -n foo --iglob '!**/*.env' .", ["--iglob", "'!**/*.env'"]],
    ["rg -n foo --glob='!x' .", ["--glob='!x'"]],
    ["rg -n foo --iglob='!*.ENV' .", ["--iglob='!*.ENV'"]],
    ["rg -n foo -g '!a' --glob '!b' --glob='!c' .", ["-g", "'!a'", "--glob", "'!b'", "--glob='!c'"]],
    ["rg -uuu --hidden -L foo -g '!notes-app/.env' .", ["-g", "'!notes-app/.env'"]],
    [`rg -n "a|b" . -g '!x' | sort`, ["-g", "'!x'"]],
    ["rg -n foo . -g '!x'|sort", ["-g", "'!x'"]],
    ["rg foo -g '!x' . ; ls", ["-g", "'!x'"]],
    ["ls || rg foo -g '!x' .", ["-g", "'!x'"]],
    ["rg -g -g '!x' foo", ["-g", "'!x'"]], // the first -g takes `-g`; `!x` is then a path, never x
    ["grep -rn KEY . --exclude=.env", ["--exclude=.env"]],
    ["grep -rn KEY . --exclude='*.env'", ["--exclude='*.env'"]],
    ["grep -rn KEY . --exclude='notes-app/.env' --exclude-dir=bank", ["--exclude='notes-app/.env'", "--exclude-dir=bank"]],
  ];
  for (const [c, words] of cases) {
    const spans = searchExclusionSpans(c);
    assert.deepEqual(spans?.map((s) => c.slice(s.start, s.end)), words, c);
    assert.equal(withoutSearchExclusions(c).length, c.length, c);
  }
});

test("unchanged: every refusal of X1-X7", () => {
  for (const c of [
    // X2, X7: the word
    "grep -r park . --exclude-dir bank",           // the two-word form
    "grep -r park . --exclude .env",
    "grep -r park . --exclude-dir=./bank",         // a path
    "grep -r park . --exclude-dir=/ws/bank",
    "grep -r park . --exclude-dir=..",
    "grep -r park . --exclude=..",
    "grep -r park . --exclude=notes-app/.env",     // a path, unquoted
    "grep -r park . --exclude-dir='bank'",         // a quote in the word
    "grep -r park . '--exclude-dir=bank'",
    "grep -r park . '--exclude=.env'",
    "grep -r park . --exclude=\"*.env\"",          // double-quoted: refused
    "grep -r park . --exclude-dir=bank*",          // a glob
    "grep -r park . --exclude-dir={bank,.git}",
    "grep -r park . --exclude-dir=^bank",
    "grep -r park . --exclude-dir=%bank",
    "grep -r 'park --exclude-dir=bank' .",         // inside a quoted pattern
    "grep -r KEY . --include=.env",                // never --include
    "grep -r KEY . --exclude-from=.env",           // never --exclude-from: it opens the file
    "grep -r KEY . --exclude-from='.env'",
    // X6: the rg pair
    "rg foo -g!x .", "rg foo -g'!x' .", "rg foo -g='!x' .", "rg foo -g \"!x\" .", "rg foo -g !x .", "rg foo -g '\\!x' .",
    "rg foo --glob \"!x\" .", "rg foo '--glob' '!x' .", "rg foo --glob '!x''y' .", "rg foo --glob '!x'y .", "rg foo --glob='!x'y .",
    "rg foo -g 'notes-app/.env' .", "rg foo -g '*.env' .", "rg foo -g '*' .",          // positive globs
    "rg foo --pre-glob '!x' .", "rg foo --ignore-file '!x' .", "rg foo --type-add '!x' .",
    "rg foo -f '!x' .", "rg foo --file '!x' .",
    "rg foo -f -g '!x' .", "rg foo -nf -g '!x' .", "rg foo --file -g '!x' .", "rg foo --ignore-file -g '!x' .", // X3
    "rg foo -- -g '!x' .", "rg foo '--' -g '!x' .", "rg foo \"--\" --glob='!x' .",                             // X3: after --
    "grep -v zzz -- --exclude=.env", "grep -f --exclude=.env -r .", "grep --file --exclude='*.env' -r .",
    // X5: the segment's first word
    "xargs rg foo -g '!x'", "sh -c \"rg foo -g '!x'\"", "bash -lc 'rg foo -g '\\''!x'\\'''", "bash -lc \"rg foo -g '!x' .\"",
    "/usr/bin/rg foo -g '!x' .", "env rg foo -g '!x' .", "command rg foo -g '!x' .", "'rg' foo -g '!x' .", "X=1 rg foo -g '!x' .",
    "/usr/bin/grep -r park . --exclude-dir=bank", "'grep' -r park . --exclude-dir=bank",
    // X4: anywhere in the command
    "rg foo -g '!x' . $(pwd)", "rg foo -g '!x' . `pwd`", "rg foo -g '!x' . 2>&1", "rg foo -g '!x' . |& cat",
    "rg foo -g '!x' . &", "rg foo -g '!x' . & ls", "rg foo -g '!x' . > out.txt", "rg foo -g '!x' . < in.txt",
    "cat <<EOF\nx\nEOF\nrg foo -g '!x' .", "rg foo -g '!x' .\nls", "rg foo\t-g '!x' .", "rg foo -g '!x' .\0",
    "rg foo -g '!x' . 'unterminated", "rg \"foo -g '!x' .", "rg \"$HOME\" -g '!x' .", "rg \"a\\b\" -g '!x' .", "rg \"a!b\" -g '!x' .",
    "rg foo -g '!x' ~/x", "rg foo -g '!x' * ", "rg foo -g '!x' ./[ab]", "rg foo -g '!x' {a,b}", "rg foo -g '!x' . # c",
    "(rg foo -g '!x' .)", "rg foo -g '!x' \\.", "rg foo -g '!x' =rg", "rg foo -g '!x' . ;; ls", "; rg foo -g '!x' .",
    "rg foo -g '!x' . &&", "rg foo -g '!x' . |", "rg foo -g '!x' . && && ls", "rg foo -g '!x' . é",
    "grep -r park . --exclude-dir=bank 2>/dev/null", "bash -lc 'grep -r park . --exclude-dir=bank'",
    "grep -r 'park . --exclude-dir=bank",          // unterminated
    // implementation review rounds 1 and 2: a file literally named so
    "grep -v zzz -- --exclude-dir=server.key",
    "grep -f --exclude-dir=bank -r .",
    "grep -rf --exclude-dir=bank .",
    "grep --file --exclude-dir=bank -r .",
    "grep --exclude-from --exclude-dir=bank -r .",
    'grep -v zzz "--" --exclude-dir=server.key',
    "grep -v zzz '--' --exclude-dir=server.key",
    "grep --from --exclude-dir=server.key x",
    "grep --include-from --exclude-dir=x -r .",
    "grep --exclude-f --exclude-dir=x -r .",
  ]) assert.equal(withoutSearchExclusions(c), c, JSON.stringify(c));
});

test("a word repeated in another segment is a different span and is still read", () => {
  const c = "rg foo -g '!notes-app/.env' . && cat '!notes-app/.env'";
  const b = withoutSearchExclusions(c);
  assert.ok(b.endsWith("cat '!notes-app/.env'"), b);
  assert.ok(!b.startsWith("rg foo -g"), b);
});

// ── the classify ─────────────────────────────────────────────────────────────

const BANK = "/proj/bank";
const ENV = "/proj/.env";
const lookup: LabelLookup = Object.assign(
  (p: string): LabelDecision | null => p === BANK || p.startsWith(`${BANK}/`) ? { level: "no-model", bindings: [], via: BANK }
    : p === ENV ? { level: "public", bindings: [], via: ENV } : null,
  { roots: () => [{ path: BANK, level: "no-model" as const }] },
);
const classify = (command: string, extra: Record<string, unknown> = {}) =>
  labelForClassify({ tool: "Bash", origin: command, params: { command, ...extra }, callStartDir: "/proj" }, "/home/u", lookup);

test("the classify: demo-c2's command is public; an operand or statement naming the folder stays secret", () => {
  assert.equal(classify("grep -rIl -i park .").level, "public", "the search with no exclusion: public today");
  assert.equal(classify(DEMO).level, "public", "the exclusion is not read as a path");
  assert.equal(classify("grep -rIl -i park . --exclude-dir bank").level, "no-model", "the two-word form: as before");
  assert.equal(classify("grep -r park bank --exclude-dir=x").level, "no-model", "an operand naming the folder");
  assert.equal(classify("grep -r park . --exclude-dir=bank bank/statement.md").level, "no-model", "a statement named beside it");
  // X7 (2026-10-27): `--exclude=bank` is read as `grep -r park .`, which is
  // public; what grep reads by recursion was never the text scan's to catch
  assert.equal(classify("grep -r park . --exclude=bank").level, "public", "--exclude=: the search without the word");
  assert.equal(classify("grep -r park . --include=bank").level, "no-model", "--include=: as before");
  assert.equal(classify("grep -r park . --exclude-from=bank").level, "no-model", "--exclude-from=: as before");
});

test("the classify: whole-text heuristics lose the blanked word (grep never changes directory)", () => {
  // `.env` labelled public: read with the exact base once no word reads as a change of directory
  assert.equal(classify("grep KEY .env --exclude-dir=chdir").level, "public");
  assert.equal(classify("grep KEY .env --exclude-dir=cd").level, "public");
});

test("the classify: a typed path field holding the command's text is never blanked", () => {
  // a file labelled no-model whose NAME is the command's text, read through a
  // typed relative path field equal to the command (implementation review round 1)
  for (const odd of ["grep x --exclude-dir=q", "rg x -g '!q'"]) {
    const oddLookup: LabelLookup = Object.assign(
      (p: string): LabelDecision | null => p === `/proj/${odd}` ? { level: "no-model", bindings: [], via: p } : null,
      { roots: () => [{ path: `/proj/${odd}`, level: "no-model" as const }] },
    );
    const m = labelForClassify({ tool: "custom", params: { path: odd, command: odd }, pathBase: { dir: "/proj", fields: ["path"] } }, "/home/u", oddLookup);
    assert.equal(m.level, "no-model", odd);
  }
});

test("the classify: a catalog file literally named --exclude-dir=NAME keeps its reading after --", () => {
  assert.equal(classify("grep -v zzz -- --exclude-dir=server.key").level, "no-model");
  assert.equal(classify("grep -v zzz -- --exclude=server.key").level, "no-model");
  assert.equal(classify("rg zzz -- -g '!server.key'").level, "no-model", "after -- the word is a file operand");
});

// demo-notion-token's labels: the drill's PATTERN label and a literal one
const WS = "/w/ws-58c7c7326a";
const snap = (path: string, glob: boolean): LabelSnapshot => ({
  human: new Map([[path, { path, confidentiality: "no-model" as const, bindings: ["api.notion.com"], recursive: false, source: "policy-file" as const, updatedAt: 1, ...(glob ? { glob: true as const } : {}) }]]),
  derived: new Map(), clientKeys: [],
});
const over = (s: LabelSnapshot): LabelLookup => withLabelRoots(snapshotLookup(s), () => s);
const PATTERN = over(snap("**/ws-*/notes-app/.env", true));
const LITERAL = over(snap(`${WS}/notes-app/.env`, false));
const codex = (cmd: string, lk: LabelLookup) =>
  labelForClassify({ tool: "exec_command", origin: cmd, params: { cmd, workdir: WS }, callStartDir: WS }, "/home/u", lk);

test("the classify: demo-notion-token's commands read public under the drill's pattern label", () => {
  for (const c of [CODEX_1, CODEX_2]) {
    const l = codex(c, PATTERN);
    assert.equal(l.level, "public", `${c}: ${JSON.stringify(l.paths)}`);
  }
  assert.equal(codex("rg -n foo notes-app --glob '!*.env'", PATTERN).level, "public");
  assert.equal(codex("rg -n foo notes-app", PATTERN).level, "public", "the same search without the glob: public today");
  assert.equal(codex("grep -rn foo notes-app --exclude=.env", PATTERN).level, "public");
  assert.equal(codex("grep -rn foo notes-app --exclude='*.env'", PATTERN).level, "public");
});

test("the classify: known, kept — under a LITERAL label the positive glob over the folder still raises (the separate follow-up)", () => {
  const l = codex(CODEX_1, LITERAL);
  assert.equal(l.level, "no-model");
  assert.deepEqual(l.paths, ["notes-app/**"], "only the positive glob; the negations are no longer read");
});

test("the classify (fail closed): an exclusion that does not hold stays as it was read", () => {
  for (const lk of [PATTERN, LITERAL]) {
    for (const c of [
      "rg foo notes-app/.env -g '!notes-app/.env'",          // a positional naming the file
      "rg -n foo -g '!notes-app/.env' . ; cat notes-app/.env", // another segment reads it
      "rg -n foo -g '!x' -g 'notes-app/.env' .",               // a positive glob naming it
      "rg -n foo -g '!x' -g '.env' .",
      "rg -n foo -g '!notes-app/.env' . 2>&1 notes-app/.env",
      "xargs rg -n foo -g '!notes-app/.env' notes-app/.env",
      "bash -lc \"rg -n foo -g '!notes-app/.env' . notes-app/.env\"",
      "grep -rn foo notes-app --include=.env",
      "grep -rn foo notes-app --exclude-from=notes-app/.env",
      "rg foo -f notes-app/.env -g '!x' .",
      "rg -n foo -g \"!notes-app/.env\" .",                     // double quotes: refused, read as before
    ]) assert.equal(codex(c, lk).level, "no-model", c);
  }
});

// ── the three call sites alike ───────────────────────────────────────────────

/** The line with each span deleted (an independent spelling of "the
 *  command without the word"). */
const deleted = (c: string): string => {
  const spans = searchExclusionSpans(c) ?? [];
  let out = "";
  let at = 0;
  for (const s of spans) { out += c.slice(at, s.start); at = s.end; }
  return out + c.slice(at);
};

const policyFor = (lk: LabelLookup) => createEngineBackedPolicy({ confidentiality: true, integrity: false, labelLookup: lk });
const pathLevel = (policy: ReturnType<typeof policyFor>, lk: LabelLookup, cmd: string, tool = "exec_command") =>
  policy.pathLevelWith!({ tool, value: "x", boundary: "model_context", origin: cmd, params: tool === "exec_command" ? { cmd, workdir: WS } : { command: cmd }, callStartDir: WS } as never, lk);

test("parity: the classify (Bash, exec_command) and the unmapped-input scan read a blanked command as the command without the words", () => {
  for (const [lk, name] of [[PATTERN, "pattern"], [LITERAL, "literal"]] as const) {
    const policy = policyFor(lk);
    for (const c of [CODEX_1, CODEX_2, "rg -n foo notes-app --glob '!*.env'", "rg -n foo --glob='!notes-app/.env' .", "grep -rn foo . --exclude=.env",
      "grep -rn foo . --exclude='*.env' --exclude-dir=notes-app", "rg foo -g '!notes-app/.env' notes-app/.env", "rg foo -- -g '!notes-app/.env'"]) {
      const d = deleted(c);
      const want = codex(d, lk).level;
      assert.equal(codex(c, lk).level, want, `${name}, classify exec_command: ${c}`);
      assert.equal(labelForClassify({ tool: "Bash", origin: c, params: { command: c }, callStartDir: WS }, "/home/u", lk).level,
        labelForClassify({ tool: "Bash", origin: d, params: { command: d }, callStartDir: WS }, "/home/u", lk).level, `${name}, classify Bash: ${c}`);
      // exec_command is unmapped in the default spec: pathLevelWith reads
      // its every string too (policy-interface.ts), with the same blanking
      assert.equal(pathLevel(policy, lk, c), pathLevel(policy, lk, d), `${name}, unmapped scan: ${c}`);
      assert.equal(pathLevel(policy, lk, c), want, `${name}, unmapped scan = classify: ${c}`);
    }
  }
});

// ── the fuzz ─────────────────────────────────────────────────────────────────

/** A seeded PRNG (mulberry32). */
function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

interface Piece { text: string; excl?: true; last: string }
const P = (text: string, last = text.split(" ").pop()!): Piece => ({ text, last });
const X = (text: string): Piece => ({ text, excl: true, last: text.split(" ").pop()! });

const RG_OPTS = ["-n", "--files", "--hidden", "-uuu", "-i", "-l", "--no-ignore", "-L", "-f", "--ignore-file", "--"].map((o) => P(o));
const RG_PATTERNS = ["foo", `"notion|env|token"`, "'KEY='"].map((o) => P(o));
const PATHS = ["notes-app", ".", "meetings", "notes-app/.env", "src"].map((o) => P(o));
const RG_EXCL = ["-g '!notes-app/.env'", "--glob '!*.env'", "--iglob '!**/*.env'", "--glob='!notes-app/.env'", "--iglob='!*.env'"].map(X);
const RG_KEEP = ["-g 'notes-app/.env'", "-g '*.env'", "-g '*'", "-g 'meetings/**'", "-g'!*.env'", "-g='!*.env'", "-g '\\!*.env'"].map((o) => P(o));
const GREP_OPTS = ["-r", "-n", "-i", "-l", "--color", "-f", "--"].map((o) => P(o));
const GREP_EXCL = ["--exclude=.env", "--exclude='*.env'", "--exclude-dir=notes-app", "--exclude='notes-app/.env'"].map(X);
const GREP_KEEP = ["--include=.env", "--exclude-from=.env", "--exclude .env", "--exclude=notes-app/.env"].map((o) => P(o));
const OTHER = ["cat notes-app/.env", "ls -la notes-app", "sort", "echo '--- x ---'", "sed -n '1,9p' meetings/m.md", "pwd", "cat '!notes-app/.env'"];
const SEPS = [" && ", " || ", " ; ", " | ", "&&", "|"];
const POISON = [" 2>&1", " > out.txt", " $(pwd)", " `pwd`", " &", "\nls", " ~/x"];

/** One command, and its expected line with every provable exclusion
 *  deleted (computed from the pieces, independently of the code). */
function generate(r: () => number): { command: string; expected: string } {
  const pick = <T>(xs: readonly T[]): T => xs[Math.floor(r() * xs.length)]!;
  const segs: Array<{ text: string; expected: string }> = [];
  const nSeg = 1 + Math.floor(r() * 3);
  for (let s = 0; s < nSeg; s++) {
    const kind = r();
    if (kind < 0.25) { const o = pick(OTHER); segs.push({ text: o, expected: o }); continue; }
    const isRg = kind < 0.7;
    const pieces: Piece[] = [isRg ? P("rg") : P(pick(["grep", "egrep", "fgrep"]))];
    const n = 2 + Math.floor(r() * 6);
    for (let k = 0; k < n; k++) {
      const x = r();
      const pool = isRg
        ? (x < 0.15 ? RG_OPTS : x < 0.3 ? RG_PATTERNS : x < 0.45 ? PATHS : x < 0.8 ? RG_EXCL : RG_KEEP)
        : (x < 0.2 ? GREP_OPTS : x < 0.35 ? RG_PATTERNS : x < 0.5 ? PATHS : x < 0.8 ? GREP_EXCL : GREP_KEEP);
      pieces.push(pick(pool));
    }
    // which exclusions hold: not after `--`, not as a file argument
    let dashDash = false;
    const kept: string[] = [];
    for (let k = 0; k < pieces.length; k++) {
      const p = pieces[k]!;
      const prev = k > 0 ? pieces[k - 1]!.last : "";
      const fileArg = isRg ? /^-[^-]*f$/.test(prev) || prev === "--file" || prev === "--ignore-file" : /^-[^-]*f$/.test(prev) || /^--[^=]+$/.test(prev);
      if (p.text === "--") dashDash = true;
      if (p.excl && !dashDash && !fileArg) continue;
      kept.push(p.text);
    }
    segs.push({ text: pieces.map((p) => p.text).join(" "), expected: kept.join(" ") });
  }
  const seps = segs.slice(1).map(() => pick(SEPS));
  const join = (xs: string[]): string => xs.reduce((acc, x, k) => k === 0 ? x : acc + seps[k - 1] + x, "");
  const command = join(segs.map((s) => s.text));
  if (r() < 0.12) {
    const poisoned = command + pick(POISON);
    return { command: poisoned, expected: poisoned };
  }
  return { command, expected: join(segs.map((s) => s.expected)) };
}

const norm = (s: string): string => s.replace(/ *(&&|\|\||;|\|) */g, "$1").replace(/ +/g, " ").trim();

test("fuzz: exactly the provable exclusions are blanked, and every call site reads the blanked line as the line without them", () => {
  const policies = new Map([[PATTERN, policyFor(PATTERN)], [LITERAL, policyFor(LITERAL)]]);
  let blankedLines = 0;
  for (const seed of [1027, 4242]) {
    const r = rng(seed);
    for (let i = 0; i < 600; i++) {
      const { command, expected } = generate(r);
      const b = withoutSearchExclusions(command);
      assert.equal(b.length, command.length, command);
      assert.equal(norm(b), norm(expected), `the spans: ${JSON.stringify(command)}`);
      if (b !== command) blankedLines++;
      for (const [lk, policy] of policies) {
        const want = codex(expected, lk);
        const got = codex(command, lk);
        assert.equal(got.level, want.level, `classify: ${JSON.stringify(command)}`);
        assert.deepEqual(got.files, want.files, `classify files: ${JSON.stringify(command)}`);
        assert.equal(pathLevel(policy, lk, command), pathLevel(policy, lk, expected), `unmapped scan: ${JSON.stringify(command)}`);
      }
    }
  }
  assert.ok(blankedLines > 300, `the fuzz reaches the rule: ${blankedLines}`);
});
