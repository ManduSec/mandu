/**
 * dir-change-label-raise (unit) — a directory change in a shell command, or
 * a directory the scan does not know, never LOWERS the level a labelled
 * relative path reads at (2026-10-17, confidentiality.md §6, "A directory
 * change only raises"; secret-catalog.ts `findSecretPathsInText`).
 *
 * The bug: `changesDirectory` made the scan drop the call's start directory
 * entirely, so in `cd . && cat secrets/plan.md` the token `secrets/plan.md`
 * was read only as written. The label store is keyed by absolute path, so a
 * relative token matches no label, and a file the human labelled `no-model`
 * (not a catalog shape, not a registered secret) classified PUBLIC.
 *
 * Pure: the label lookup is the arbiter's own composition
 * (label-lookup.ts `composedLabel` + `withLabelRoots`) over a fixed
 * snapshot, so `labelRoots` is exercised too.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  changesDirectory,
  directoryMayChange,
  findSecretPathsInText,
  labelForClassify,
  labelForUnmappedInput,
  unresolvedDirChange,
  type LabelLookup,
} from "../../policy/secret-catalog.js";
import { composedLabel, labelRoots, withLabelRoots, type LabelSnapshot } from "../../policy/label-lookup.js";
import { resolvePathLabel, type PathLabel } from "../../policy/path-labels.js";
import type { DerivedLabel } from "../../policy/derived-labels.js";
import { CODEX_WORKDIR_TOOLS as CODEX } from "../../policy/tool-gate-surface.js";
import type { ConfidentialityLevel } from "../../symbol-table/confidentiality.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the confidentiality derivation under test

const HOME = "/home/u";
const WS = "/home/u/proj";

type Row = { path: string; level?: ConfidentialityLevel; recursive?: boolean; glob?: true };

function snapshotOf(rows: Row[], derived: Array<{ path: string; level: ConfidentialityLevel }> = []): LabelSnapshot {
  const human = new Map<string, PathLabel>();
  for (const r of rows) {
    human.set(r.glob ? `glob:${r.path}` : r.path, {
      path: r.path, confidentiality: r.level ?? "no-model", bindings: [], recursive: r.recursive ?? true,
      source: "policy-file", updatedAt: 1, ...(r.glob ? { glob: true as const } : {}),
    });
  }
  const d = new Map<string, DerivedLabel>();
  for (const r of derived) d.set(r.path, { path: r.path, confidentiality: r.level, bindings: [], sessionKey: "s-high", tool: "Write", sources: null, createdAt: 1, updatedAt: 1 });
  return { human, derived: d, clientKeys: [] };
}

/** The arbiter's lookup over `rows`, with its roots. */
function lookup(rows: Row[], derived: Array<{ path: string; level: ConfidentialityLevel }> = []): LabelLookup {
  const s = snapshotOf(rows, derived);
  return withLabelRoots((p) => composedLabel(p, s), () => s);
}

const SECRETS: Row = { path: `${WS}/secrets` };
// A name no catalog shape matches (`*secret*` would mask `cd secrets` with no label at all).
const VAULT: Row = { path: `${WS}/vault` };
const bash = (command: string, callStartDir?: string) => ({ tool: "Bash", origin: command, params: { command }, ...(callStartDir !== undefined ? { callStartDir } : {}) });
const codex = (cmd: string, workdir: string = WS) => ({ tool: "exec_command", origin: cmd, params: { cmd, workdir }, workdirTools: CODEX });
const level = (req: Parameters<typeof labelForClassify>[0], lk: LabelLookup): string => labelForClassify(req, HOME, lk).level;

test("THE BUG: `cd .` before a labelled relative path no longer reads it public (Claude Code Bash and Codex exec_command)", () => {
  const lk = lookup([SECRETS]);
  assert.equal(level(bash("cat secrets/plan.md", WS), lk), "no-model", "the baseline: read at the start directory");
  for (const cmd of ["cd . && cat secrets/plan.md", "cd .; cat secrets/plan.md", "cd ./ && cat secrets/plan.md", "cd -- . && cat secrets/plan.md", "(cd . && cat secrets/plan.md)", "pushd . && cat secrets/plan.md", 'cd "$PWD" && cat secrets/plan.md', "cd ${PWD} && cat secrets/plan.md"]) {
    assert.equal(level(bash(cmd, WS), lk), "no-model", `Bash: ${cmd}`);
    assert.equal(level(codex(cmd), lk), "no-model", `exec_command: ${cmd}`);
  }
  // the path-derived note still names the token
  assert.deepEqual(labelForClassify(bash("cd . && cat secrets/plan.md", WS), HOME, lk).paths, ["secrets/plan.md"]);
});

test("a resolvable change of directory: the token is read at the start directory and under every label it could name", () => {
  const lk = lookup([VAULT]);
  const cases: Array<[string, string | undefined]> = [
    ["cd vault && cat plan.md", WS],
    ["cd sub && cat ../vault/plan.md", WS],
    ["cd sub/deeper && cat ../../vault/plan.md", WS],
    ["cd sub; cd deeper; cat ../../vault/plan.md", WS],
    [`cd ${WS}/vault && cat plan.md`, "/tmp"],
    ["cd .. && cat proj/vault/plan.md", WS],
    ["cd ../.. && cat vault/plan.md", `${WS}/sub/deeper`],
    ["cd && cat proj/vault/plan.md", WS],
    ["cd ~/proj && cat vault/plan.md", "/tmp"],
    ["cd $HOME/proj/vault && cat plan.md", "/tmp"],
    ["\\cd sub && cat ../vault/plan.md", WS],
    ["builtin cd sub && cat ../vault/plan.md", WS],
    ["command cd sub && cat ../vault/plan.md", WS],
    // the start directory unknown (no guard): the token names the label's tail
    ["cat vault/plan.md", undefined],
    ["cd . && cat vault/plan.md", undefined],
    ["cd sub && cat ../vault/plan.md", undefined],
  ];
  for (const [cmd, start] of cases) assert.equal(level(bash(cmd, start), lk), "no-model", `${cmd} (start ${start ?? "unknown"})`);
});

test("the flag forms and an interpreter's chdir", () => {
  const lk = lookup([VAULT]);
  for (const cmd of [
    "git -C sub show HEAD:../vault/plan.md",
    "make -C vault -f plan.md",
    "tar -C vault -cf - plan.md",
    "tar -Cvault -cf - plan.md",
    "env -C sub cat ../vault/plan.md",
    "env --chdir=vault cat plan.md",
    "ls --directory=vault plan.md",
    "pnpm --dir=sub exec cat ../vault/plan.md",
    "uv run --directory sub cat ../vault/plan.md",
    `python3 -c "import os; os.chdir('sub'); print(open('../vault/plan.md').read())"`,
    `node -e "process.chdir('vault'); console.log(require('fs').readFileSync('plan.md','utf8'))"`,
    `ruby -e "Dir.chdir('sub'); puts File.read('../vault/plan.md')"`,
  ]) {
    assert.equal(level(bash(cmd, WS), lk), "no-model", cmd);
  }
});

test("a target the scan cannot read: the precaution masks a command that passes a relative argument while a label stands", () => {
  const lk = lookup([VAULT]);
  for (const cmd of [
    'cd "$TARGET" && cat plan.md',
    "cd - && cat plan.md",
    "cd $(dirname vault/x) && cat plan.md",
    "cd `echo vault` && cat plan.md",
    "cd vau* && cat plan.md",
    "cd {vault,x} && cat plan.md",
    "cd ~other && cat plan.md",
    "popd && cat plan.md",
    "pushd +1 && cat plan.md",
    "git -C \"$D\" show HEAD:plan.md",
    "find . -name plan.md -execdir cat {} ;",
    'eval "cd $D" && cat plan.md',
    `python3 -c "import os; os.chdir(os.environ['D']); print(open('plan.md').read())"`,
  ]) {
    const r = labelForClassify(bash(cmd, WS), HOME, lk);
    assert.equal(r.level, "no-model", cmd);
  }
  // the rule says why, and the note names no path for it
  const hits = findSecretPathsInText('cd "$T" && cat plan.md', HOME, lk, WS);
  assert.ok(hits.some((h) => h.rule === "dir-change:unresolved"));
  assert.deepEqual(labelForClassify(bash('cd "$T" && cat plan.md', WS), HOME, lk).paths, []);
});

test("the precaution is narrow: no label above public, no relative argument, or a readable target leaves the command in clear", () => {
  assert.equal(level(bash('cd "$TARGET" && cat plan.md', WS), lookup([])), "public", "no label stands");
  assert.equal(level(bash('cd "$TARGET" && cat plan.md', WS), lookup([{ path: `${WS}/docs`, level: "public" }])), "public", "only a public label");
  const lk = lookup([VAULT]);
  assert.equal(level(bash('cd "$TARGET" && ls', WS), lk), "public", "no argument");
  assert.equal(level(bash('cd "$(git rev-parse --show-toplevel)" && make', WS), lk), "public", "no argument");
  assert.equal(level(bash("source .venv/bin/activate && python -m pytest tests", WS), lk), "public", "source is indirection the command does not show (§10.1), not counted");
  // a lookup without roots (not the arbiter's) takes no precaution
  const plain: LabelLookup = (p) => composedLabel(p, snapshotOf([VAULT]));
  assert.equal(level(bash('cd "$TARGET" && cat plan.md', WS), plain), "public");
  // but still reads the start directory, raise-only
  assert.equal(level(bash("cd . && cat vault/plan.md", WS), plain), "no-model");
});

test("no benign command is newly masked by a directory change", () => {
  const lk = lookup([VAULT, { path: `${WS}/notes/plan.md`, recursive: false }]);
  for (const cmd of [
    "cd . && cat README.md",
    "cd sub && ls",
    "cd sub && cat ../README.md",
    "git -C sub log --oneline",
    "make -C sub test",
    "cd /tmp && cat report.txt",
    "cd build && cat config.json",
    "npm --prefix web run build",
    "git log --dirstat",
  ]) {
    assert.equal(level(bash(cmd, WS), lk), "public", cmd);
  }
});

test("raise-only: a public label at the start directory never lifts a token in a command that changes directory", () => {
  const lk = lookup([{ path: `${WS}/test/fixtures/.env`, level: "public", recursive: false }, VAULT]);
  assert.equal(level(bash("cat test/fixtures/.env", WS), lk), "public", "the lift where the base is exact");
  assert.equal(level(bash("cd . && cat test/fixtures/.env", WS), lk), "no-model", "the catalog's .env stands after a cd");
  assert.equal(level(bash("cd test && cat fixtures/.env", WS), lk), "no-model");
});

test("the tail reading: an exact file label, a pattern with a literal prefix, an any-depth pattern, a derived label", () => {
  const exact = lookup([{ path: `${WS}/notes/plan.md`, recursive: false }]);
  assert.equal(level(bash("cd notes && cat plan.md", WS), exact), "no-model", "the file's own name");
  assert.equal(level(bash("cd x && cat ../notes/plan.md", WS), exact), "no-model");
  assert.equal(level(bash("cd x && cat ../notes/other.md", WS), exact), "public", "a sibling of a labelled file");

  const prefixed = lookup([{ path: `${WS}/vault/*.md`, glob: true }]);
  assert.equal(level(bash("cd sub && cat ../vault/plan.md", WS), prefixed), "no-model");
  assert.equal(level(bash("cd sub && cat ../vault/plan.txt", WS), prefixed), "public", "not the pattern's shape");

  const anywhere = lookup([{ path: "**/*.private.md", glob: true }]);
  assert.equal(level(bash("cd sub && cat plan.private.md", WS), anywhere), "no-model");
  assert.equal(level(bash("cat plan.private.md"), anywhere), "no-model", "no start directory: the pattern matches anywhere");
  assert.equal(level(bash("cd sub && cat plan.md", WS), anywhere), "public");

  const derived = lookup([], [{ path: `${WS}/out/report.md`, level: "no-model" }]);
  assert.equal(level(bash("cd x && cat ../out/report.md", WS), derived), "no-model", "a file a high session wrote");
});

test("labelRoots: the labels above public, a pattern by its literal prefix", () => {
  const roots = labelRoots(snapshotOf([
    VAULT,
    { path: `${WS}/docs`, level: "public" },
    { path: `${WS}/vault/*.md`, glob: true },
    { path: "**/*.pem", glob: true, level: "local-model" },
    { path: `${WS}/data/**/*.csv`, glob: true },
  ], [{ path: `${WS}/out/r.md`, level: "no-model" }, { path: `${WS}/out/p.md`, level: "public" }]), HOME);
  assert.deepEqual(roots.map(({ matches: _m, ...r }) => r), [
    { path: `${WS}/vault`, level: "no-model" },
    { path: `${WS}/vault`, level: "no-model", anyDepth: false },
    { path: "/", level: "local-model", anyDepth: true },
    { path: `${WS}/data`, level: "no-model", anyDepth: true },
    { path: `${WS}/out/r.md`, level: "no-model" },
  ]);
  // a pattern carries its own matcher, a literal path none
  assert.equal(roots[0]!.matches, undefined);
  assert.equal(roots[1]!.matches?.(`${WS}/vault/plan.md`), true);
  assert.equal(roots[1]!.matches?.(`${WS}/vault/plan.txt`), false);
});

test("a label that matched a whole multi-token string no longer short-circuits the scan (a `public` pattern over `/bin/cat <labelled>`)", () => {
  const lk = lookup([{ path: "**/*.md", glob: true, level: "public" }, VAULT]);
  assert.equal(level(bash(`/bin/cat ${WS}/vault/plan.md`, WS), lk), "no-model");
  assert.equal(level(bash(`/bin/cat ${WS}/README.md`, WS), lk), "public");
  // an exact label on a path with a space still decides it
  const spaced = lookup([{ path: `${WS}/My Notes/a.env`, level: "public", recursive: false }]);
  assert.equal(labelForClassify({ tool: "Read", origin: `${WS}/My Notes/a.env`, params: { file_path: `${WS}/My Notes/a.env` } }, HOME, spaced).level, "public");
});

test("an unmapped tool's input that names a directory: no token is placed exactly", () => {
  const lk = lookup([VAULT]);
  assert.equal(labelForUnmappedInput([{ cwd: "sub", path: "../vault/plan.md" }], HOME, lk, WS).level, "no-model", "a relative directory");
  assert.equal(labelForUnmappedInput([{ working_dir: `${WS}/sub`, file: "../vault/plan.md" }], HOME, lk, WS).level, "no-model", "an absolute directory is read at");
  assert.equal(labelForUnmappedInput([{ command: "cd sub", file: "../vault/plan.md" }], HOME, lk, WS).level, "no-model", "a cd in another field");
  assert.equal(labelForUnmappedInput([{ cwd: `${WS}/sub`, file: "../README.md" }], HOME, lk, WS).level, "public");
});

test("changesDirectory: the new spellings, and what is still not one", () => {
  for (const t of ["\\cd x", "os.chdir('x')", "process.chdir (x)", "Dir.chdir('x')", "pnpm --dir x i", "pnpm --dir=x i", "just --working-directory x", "x --workdir=y", "x --wd y", "x --root y"]) {
    assert.equal(changesDirectory(t), true, t);
  }
  for (const t of ["git log --dirstat", "cat ./x", "x --rooted"]) assert.equal(changesDirectory(t), false, t);
});

test("unresolvedDirChange: which targets the scan cannot read", () => {
  for (const t of ['cd "$X"', "cd -", "cd $(pwd)/x", "cd `pwd`", "cd a*", "cd {a,b}", "cd ~bob", "popd", "pushd +2", "pushd -0", "git -C $D log", "make --directory=$D", "find . -execdir ls ;", "find . -okdir ls ;", 'eval "$X"', "os.chdir(d)", "os.chdir(f'{d}')"]) {
    assert.equal(unresolvedDirChange(t), true, t);
  }
  for (const t of ["cd", "cd .", "cd -- x", "cd -P ../x", 'cd "$PWD"', "cd ${HOME}/x", "cd ~", "cd ~/x", "pushd x", "git -C x log", "tar -Cx -xf a", "make --directory=x", "os.chdir('x')", 'process.chdir("x")', "source x", ". x", "eval 'cd x'"]) {
    assert.equal(unresolvedDirChange(t), false, t);
  }
});

test("a lookup that labels nothing changes nothing (the catalog decides, as before)", () => {
  const none = lookup([]);
  assert.equal(level(bash("cd . && cat notes.md", WS), none), "public");
  assert.equal(level(bash("cd . && cat .env", WS), none), "no-model");
  // and the stock resolver without a snapshot still works as a lookup
  const bare: LabelLookup = (p) => resolvePathLabel(p, new Map(), HOME);
  assert.equal(level(bash("cd x && cat ../y.md", WS), bare), "public");
});

// ── the adversarial review of this change (2026-10-17) ───────────────────────

test("review 1: a pattern label whose literal prefix is the directory a cd enters", () => {
  const notes = lookup([{ path: `${WS}/notes/*.md`, glob: true }]);
  for (const cmd of ["cd notes && cat plan.md", "git -C notes show HEAD:plan.md", "tar -C notes -cf - plan.md"]) {
    assert.equal(level(bash(cmd, WS), notes), "no-model", cmd);
    assert.equal(level(bash(cmd), notes), "no-model", `${cmd} (no start directory)`);
  }
  assert.equal(labelForUnmappedInput([{ cwd: "notes", path: "plan.md" }], HOME, notes, WS).level, "no-model");
  assert.equal(level(bash("cd notes && cat plan.txt", WS), notes), "public", "not the pattern's shape");
  assert.equal(level(bash("cd .. && cat vault/plan.md", `${WS}/sub`), lookup([{ path: `${WS}/*/plan.md`, glob: true }])), "no-model");
  assert.equal(level(bash("cd x; cat plan.md", `${WS}/a`), lookup([{ path: `${WS}/*/x/*.md`, glob: true }])), "no-model");
});

test("review 2 and 3: a substitution, a glob or an input redirection after an unreadable cd counts as an argument", () => {
  const lk = lookup([VAULT]);
  for (const cmd of [
    'cd "$D" && echo "$(cat plan.md)"',
    'cd "$D" && echo "$(<plan.md)"',
    "cd - ; echo `cat plan.md`",
    'popd && cat "$(ls | head -1)"',
    'cd "$D" && tail -n +1 $(ls)',
    'cd "$D" && cat *.md',
    "cd vau* && cat *",
    'cd "$D" && cat<plan.md',
    "cd vau*;head<plan.md",
    "cd vau*\ncat<plan.md",
  ]) {
    assert.equal(level(bash(cmd, WS), lk), "no-model", JSON.stringify(cmd));
  }
  // an output redirection's file and a descriptor are not read
  assert.equal(level(bash('cd "$D" && make >build.log 2>&1', WS), lk), "public");
});

test("review 4: quoting and escapes inside a token are read as the shell reads them", () => {
  const lk = lookup([VAULT]);
  for (const cmd of ['cat va""ult/plan.md', "cat vau\\lt/plan.md", `cat ${WS}/va""ult/plan.md`, "cd va''ult && cat plan.md", 'cd "va"ult && cat plan.md', "cd va\\\nult && cat plan.md"]) {
    assert.equal(level(bash(cmd, WS), lk), "no-model", JSON.stringify(cmd));
  }
  const exact = lookup([{ path: `${WS}/vault/plan.md`, recursive: false }]);
  for (const cmd of ['cat vault/"plan.md"', "cat 'vault'/plan.md", "cat vault\\/plan.md", "cat vault/pl\\an.md", `cat ${WS}/vault/pl''an.md`]) {
    assert.equal(level(bash(cmd, WS), exact), "no-model", JSON.stringify(cmd));
  }
  // a dequoted spelling is never placed on a file (plan 15 §13.12)
  assert.equal(labelForClassify(bash('cat vault/"plan.md"', WS), HOME, exact).files, undefined);
});

test("review 5: the directory changes the scan used to miss", () => {
  const lk = lookup([VAULT]);
  const sub = `${WS}/sub`;
  for (const cmd of [
    `ruby -e 'Dir.chdir ".."; puts File.read("vault/plan.md")'`,
    `python3 -c 'import os; os.fchdir(os.open("..",0)); print(open("vault/plan.md").read())'`,
    `python3 -c 'import subprocess; subprocess.run(["cat","vault/plan.md"], cwd="..")'`,
    `node -e 'require("child_process").execSync("cat vault/plan.md",{cwd:"..",stdio:"inherit"})'`,
    "env -iC .. cat vault/plan.md",
    "c$''d ..; cat vault/plan.md",
    "C=cd; $C ..; cat vault/plan.md",
    "sudo -D .. cat vault/plan.md",
  ]) {
    assert.equal(level(bash(cmd, sub), lk), "no-model", cmd);
    assert.equal(directoryMayChange(cmd), true, cmd);
  }
});

test("review 6: a relative workdir Codex honours is read like a cd target", () => {
  const lk = lookup([VAULT]);
  for (const workdir of ["vault", "./vault"]) {
    const req = { tool: "exec_command", origin: "cat plan.md", params: { cmd: "cat plan.md", workdir }, workdirDefault: WS, workdirTools: CODEX };
    assert.equal(level(req, lk), "no-model", workdir);
  }
  const unknown = { tool: "exec_command", origin: "cat plan.md", params: { cmd: "cat plan.md", workdir: "$D" }, workdirDefault: WS, workdirTools: CODEX };
  assert.equal(level(unknown, lk), "no-model", "an unreadable workdir: the precaution");
  const benign = { tool: "exec_command", origin: "cat README.md", params: { cmd: "cat README.md", workdir: "sub" }, workdirDefault: WS, workdirTools: CODEX };
  assert.equal(level(benign, lk), "public");
});

test("a pattern that only says `everything below` is a directory: no word of a web search is read inside it", () => {
  const lk = lookup([{ path: `${WS}/vault/**`, glob: true }]);
  assert.equal(labelForClassify({ tool: "websearch", origin: "acme payments 2026", params: { query: "acme payments 2026" } }, HOME, lk).level, "public");
  assert.equal(labelForUnmappedInput([{ query: "acme payments 2026" }], HOME, lk).level, "public");
  assert.equal(level(bash("cd sub && cat ../vault/plan.md", WS), lk), "no-model", "its directory is still read");
  const roots = labelRoots(snapshotOf([{ path: `${WS}/vault/**`, glob: true }, { path: `${WS}/vault2/**/*`, glob: true }]), HOME);
  assert.deepEqual(roots.map((r) => r.anyDepth), [false, false]);
});

test("review 7: an unmapped tool's own directory places no relative file", () => {
  const lk = lookup([{ path: "/home/u/other" }, { path: WS }]);
  const r = labelForUnmappedInput([{ cwd: "/home/u/other", path: "vault/plan.md" }], HOME, lk, WS);
  assert.equal(r.level, "no-model");
  assert.equal(r.files, undefined, "the tool read /home/u/other/vault/plan.md, not a file under the start directory");
});

// ── the second adversarial review (2026-10-17) ───────────────────────────────

test("review 2.1: a single relative token with a directory target is not read as placed (no lowering)", () => {
  const pub = lookup([{ path: `${WS}/.env`, level: "public", recursive: false }]);
  assert.equal(labelForUnmappedInput([{ cwd: "services/api", path: ".env" }], HOME, pub, WS).level, "no-model");
  const codexRel = { tool: "exec_command", origin: ".env", params: { cmd: ".env", workdir: "sub" }, workdirDefault: WS, workdirTools: CODEX };
  assert.equal(level(codexRel, pub), "no-model");
  const hr = lookup([{ path: WS, level: "public" }, { path: `${WS}/hr/salaries.csv`, recursive: false }]);
  assert.equal(labelForUnmappedInput([{ cwd: "hr", path: "salaries.csv" }], HOME, hr, WS).level, "no-model");
});

test("review 2.2-2.4: a quoted or escaped space, a glob below a named labelled directory, the current directory spelled otherwise", () => {
  const spaced = lookup([{ path: `${WS}/my vault` }]);
  for (const cmd of ['cd "my vault" && cat plan.md', "cd my\\ vault && cat plan.md", 'cat "my vault/plan.md"']) {
    assert.equal(level(bash(cmd, WS), spaced), "no-model", cmd);
  }
  const lk = lookup([VAULT]);
  for (const cmd of ["cat vault/*", "cat vault/plan.m?", "cd . && cat vault/{plan.md,}", "cd . && cat $(pwd)/vault/plan.md", "cat `pwd`/vault/plan.md", "cat ~+/vault/plan.md", "cd /tmp && cat ~-/vault/plan.md", "cd /tmp && cat $OLDPWD/vault/plan.md"]) {
    assert.equal(level(bash(cmd, WS), lk), "no-model", cmd);
  }
  const notes = lookup([{ path: `${WS}/notes/*.md`, glob: true }]);
  assert.equal(level(bash("cat notes/*.md", WS), notes), "no-model");
  assert.equal(level(bash("cd notes && cat *.md", WS), notes), "no-model");
  assert.equal(level(bash("cat 'notes/my plan.md'", WS), notes), "no-model");
  assert.equal(level(bash("cat src/*.ts", WS), lk), "public", "a glob below an unlabelled directory");
});

test("review 2.5-2.6: a long chain of cd, an any-depth pattern with no start directory", () => {
  const hr = lookup([{ path: `${WS}/*/hr/*.md`, glob: true }]);
  assert.equal(level(bash("cd .. && cd .. && cd .. && cd .. && cat x/hr/p.md", `${WS}/a/b/c/d`), hr), "no-model");
  assert.equal(level(bash("cd ..; cd ..; cd ..; cd x/hr; cat p.md", `${WS}/a/b/c`), hr), "no-model");
  for (const pattern of ["**/hr/*.md", `${WS}/**/hr/*.md`]) {
    const any = lookup([{ path: pattern, glob: true }]);
    assert.equal(level(bash("cd hr && cat x.md"), any), "no-model", pattern);
    assert.equal(level(bash("cd sub/hr && cat x.md"), any), "no-model", pattern);
  }
});

test("review 2.7-2.10: the precaution's arguments, ANSI-C quoting, a bare directory with no start directory, a quoted variable command, zsh's cd old new", () => {
  const lk = lookup([VAULT]);
  for (const cmd of ['cd "$X" && grep -rv 12345', "cd \"$X\" && grep -r ''", "cd \"$X\" && rg ''"]) assert.equal(level(bash(cmd, WS), lk), "no-model", cmd);
  const salaries = lookup([{ path: `${WS}/hr/salaries.csv`, recursive: false }]);
  assert.equal(level(bash("$'\\x63d' hr && cat salaries.csv", WS), salaries), "no-model");
  assert.equal(level(bash("cd hr && cat $'\\x73alaries.csv'"), salaries), "no-model");
  for (const cmd of ["grep -r '' vault", "tar cz vault"]) assert.equal(level(bash(cmd), lk), "no-model", `${cmd} (no start directory)`);
  assert.equal(level(bash('C=${X:-cd}; "$C" hr; cat salaries.csv', WS), salaries), "no-model");
  assert.equal(level(bash("cd a notes && cat plan.md", `${WS}/a`), lookup([{ path: `${WS}/notes/*.md`, glob: true }])), "no-model");
});

test("review 2 (utility): a mention of chdir or cd in text, a pushd/popd pair, a variable command stay in clear", () => {
  const lk = lookup([VAULT]);
  for (const cmd of ["grep -rn chdir src", "rg 'os.chdir' .", "grep -rn 'cwd=' src", "git log -S chdir", "git commit -m 'fix cd - handling'", "echo 'run: cd - to go back'", "pushd web && npm run build && popd", "$PYTHON -m pytest tests"]) {
    assert.equal(level(bash(cmd, WS), lk), "public", cmd);
  }
});

test("review 2 (cost): past the token budget the strictest label stands for the text", () => {
  const lk = lookup([VAULT]);
  const words = Array.from({ length: 2100 }, (_, i) => `w${i}/x.md`).join(" ");
  const r = findSecretPathsInText(`cd sub && cat <<EOF\n${words}\nEOF`, HOME, lk, WS);
  assert.ok(r.some((h) => h.rule === "scan:too-many-tokens" && h.level === "no-model"));
  assert.equal(level(bash(`cd sub && cat <<EOF\n${words}\nEOF`, WS), lookup([])), "public", "no label: nothing to stand");
  assert.equal(level(bash(`cd sub && cat ${Array.from({ length: 50 }, (_, i) => `w${i}/x.md`).join(" ")}`, WS), lk), "public", "within the budget");
});

test("review 2 (cost): a long command after a cd, with thousands of labels sharing a name, stays bounded", () => {
  const derived = Array.from({ length: 3000 }, (_, i) => ({ path: `${WS}/out/d${i}/index.md`, level: "no-model" as const }));
  const lk = lookup([VAULT], derived);
  // thousands of distinct path tokens, one of them a name 3000 labelled files share
  const words = [...Array.from({ length: 3000 }, (_, i) => `w${i}/out/d${i}/x.md`), "index.md"].join(" ");
  // The bound is on this process's CPU time, not the wall clock: ~1.6 s
  // alone, and a quadratic walk is minutes; a loaded CI host stretched the
  // wall clock past 10 s (11.5 s, 2026-10-18) with the same work.
  const c0 = process.cpuUsage();
  assert.equal(level(bash(`cd sub && cat <<EOF\n${words}\nEOF`, WS), lk), "no-model");
  const c = process.cpuUsage(c0);
  const cpuMs = Math.round((c.user + c.system) / 1000);
  assert.ok(cpuMs < 10_000, `took ${cpuMs} ms of CPU`);
});
