# A search that excludes a labelled folder

Decision note, 2026-10-18. Status: built. Amends the
path-derived precaution (`labelForClassify`, `confidentiality.md` §7.1).

## 1. The problem

The path rules read every word of a shell command as a possible path. In
the scam-email demo (demo-c2) the model searched the workspace while keeping
out of the labelled `bank/` folder:

    grep -rIl -i park . --exclude-dir=bank

With the call's start directory known, the scan reads the piece `bank` of the
word `--exclude-dir=bank` where the call started, so the command read as
naming a secret path and its whole output (the matching file names) was one
symbol. The same search without the flag (`grep -rIl -i park .`) names no
secret path and is not masked: what a recursive search reads by recursion
was never the text scan's to catch (confidentiality.md §6 lists `grep -r
password .`); the twins, the process taint and the value backstop stand
behind it.

## 2. The rule

When a shell command is ONE plain `grep` (or `egrep`, `fgrep`) call, each of
its words that is exactly `--exclude-dir=NAME`, with NAME one plain path
segment, is not read by the classify's path rules. Every other word is read
as before. In every other case nothing changes.

`withoutGrepExclusions` (`arbiter/policy/exclusion-flags.ts`), applied by
`labelForClassify` to the shell command alone, of a shell tool (`Bash`,
`bash`, `shell`, `exec_command`, `local_shell`, `exec`; the `cmd` or
`command` param, and the origin hint when it is that same text), in both of its passes (the level, and the paths and
files it names): the command with each such word blanked by spaces of its
length (the whole word, so nothing of it is left as a token), or the command
unchanged, unless every rule holds:

- **X1. One plain command.** At most 4 KiB; the first word exactly `grep`,
  `egrep` or `fgrep` (no path, no `command`, no assignment before it, no
  quote in it); nowhere in the command (quoted or not): `;`, `&`, `|`, `<`,
  `>`, `(`, `)`, `$`, a backquote, `\`, `*`, `?`, `[`, `]`, `{`, `}`, `#`,
  `!`, `^`, `~`, `%`, a line break, a tab or a NUL. Words split on spaces;
  `'…'` and `"…"` group; an unterminated quote is refused.
- **X2. The word.** Written exactly `--exclude-dir=NAME` with no quote
  anywhere in it, NAME one plain path segment (`[A-Za-z0-9._+-]+`, an
  optional trailing `/`, not `.` or `..`). Not `--exclude=` (a file glob,
  which keeps no folder out), not a path (`./bank`, `/abs/bank`: GNU grep
  and ugrep match NAME against a directory's own name, so those keep
  nothing out either; design review round 2). One word only: the two-word
  form (`--exclude-dir bank`) is never blanked, since its meaning depends on
  what grep and the environment do with the words before it
  (`POSIXLY_CORRECT`, `GREP_OPTIONS` up to GNU grep 3.5, an option another
  grep parses differently: ugrep's optional-argument `--group-separator`),
  and in some of them `bank` is a file operand (design review round 1).
- **X3. Not where it names a file.** A word after `--` (quoted or not), or
  right after `-f` (or a short cluster ending in it) or ANY long option
  written without `=` (`--file`, `--exclude-from`, ugrep's `--from`, a GNU
  abbreviation such as `--exclude-f`), may name the file literally called
  `--exclude-dir=NAME`; it is kept, so the catalog still reads that name
  (`grep -v x -- --exclude-dir=server.key` stays as before; implementation
  review rounds 1 and 2).

The scan of every string of a tool the session's spec does not map
(`labelForUnmappedInput`, which reads Codex's `exec_command` input) gets
the same blanking in its `command` and `cmd` fields only, and only for a
shell tool (`Bash`, `bash`, `shell`, `exec_command`, `local_shell`,
`exec`). `cmd` is read before `command`, as the openai-proxy names the
origin. Never a typed path
field, any other string, nor a joined argv (Codex's `shell{command: [...]}`,
whose elements may hold blanks): blanking a string the scan reads as one
path could skip an exact label on it (design review round 2).

## 3. Why the invariant holds

A word `--exclude-dir=NAME` is never a path any grep opens, however the
command is parsed: as an option it is a name grep matches against folders;
as the argument of `-e` it is pattern text; as an operand, after `--`, as
the argument of `-f`, under `POSIXLY_CORRECT` or with `GREP_OPTIONS` in
front, it names the file literally called `--exclude-dir=bank`, never `bank`
(checked with strace on GNU grep 3.12, on ugrep 7.8.4 called as Claude
Code's shell snapshot calls it, and on busybox 1.37, which refuses the
option). So the scan loses no reading of a path the command opens BY NAME, except
the catalog's reading of that literal name where grep takes it as a file:
under `POSIXLY_CORRECT` a trailing `--exclude-dir=server.key` is a file
operand, and the catalog no longer sees `server.key` in it. Such a file
needs that exact odd name, a label on a token starting with `-` was never
read (`isResolvableRelativeToken`), and the twins, the process taint and the
value backstop stand behind it.
What grep reads by recursion is what the same search without the word
reads, which the path rules never caught (`grep -rIl -i park .` is public
today): the release is exactly as safe as an already-unmasked recursive
search, and no safer. No grep option is parsed, so no option table can be
wrong.

The scan's heuristics that look at the whole text (a change of directory:
`chdir`, `cd`, `-C`, `--directory` anywhere) no longer see the blanked
word, so `grep KEY .env --exclude-dir=chdir` is read with the exact base,
where a human `public` label can apply. That is the right reading: grep
never changes directory.

## 4. What this widens

Nothing a recursive search with no exclusion does not already show. The
flag does not always keep grep out: Claude Code's grep (ugrep with
`--ignore-files`) re-includes a folder a `.gitignore` in the tree names
with `!bank/`, whatever `--exclude-dir` says; then grep reads the labelled
files, served their twins, exactly as `grep -r … .` would. Kept as before
(masked when the folder is labelled): the two-word form, `--exclude=bank`,
`--exclude-dir=./bank` or any path, `--exclude-dir=bank*` or any glob or
special character, `--exclude-dir={bank,.git}`, `--exclude-from=FILE` and
`--include` (read as before); `rg -g '!bank'`, `git grep … ':!bank'`,
`find . -path ./bank -prune …`; a second command, a pipe, a trailing
`2>/dev/null`, `bash -lc '…'`; a command not first or behind a path or `cd
… &&`; an operand or any other word naming the folder.

## 5. Tests

- Arbiter `test/unit/exclusion-flags.test.ts`: blanked, the whole word, one
  or several; unchanged for every refusal of X1 and X2 (the two-word form,
  `--exclude=`, a path, a quote, a glob, `^`, `%`, a quoted word holding the
  flag, an unterminated quote, `rg`, `cd x && grep`, a pipe).
- Arbiter `test/unit/named-paths.test.ts` (or a component test): demo-c2's
  command with `bank/` labelled is public; with an operand naming the folder
  or a statement, secret; `grep KEY .env --exclude-dir=chdir` (and `=cd`)
  with `.env` labelled public reads public; a typed path field holding the
  flag's text is never blanked.
- `tests/stack/`: the demo's command reaches Claude Code and Codex in clear;
  the two-word form and a grep naming a statement beside the flag stay one
  symbol; THE ORACLE.

## 6. Review rounds

- **Design round 1** (the first draft: GNU grep's getopt table, the one- and
  two-word forms). It found: **a leak, medium, environment-dependent**: the
  two-word form's `bank` is a file operand under `GREP_OPTIONS=-e` (GNU
  grep up to 3.5) or a non-permuting parse; Claude Code's `grep` is ugrep,
  not GNU grep, so a GNU option table is not what runs; §3's "taking an
  exclusion away only reads more" was false (`--include` rules) and not
  needed; blanking changes whole-text heuristics (`chdir`). Fixed: the
  one-word form only, no option parsing, the argument restated, the
  heuristic documented.
- **Design round 2** (this rule, with strace on three greps). No leak in
  the rule. It found: blanking a typed path field or a joined argv could
  skip an exact label on that string (leak-low, from the hook's place):
  fixed, the shell command only, in both passes; `--exclude=` and a path
  NAME keep nothing out: dropped; the heuristics note widened to `cd`/`-C`;
  the `.gitignore` re-include, documented in §4.
- **Implementation round 1** (the code, side by side with the code before
  it: every new reading equals the old reading of the command without the
  word). No leak. It found: after `--` or as `-f`'s argument the word is a
  file literally so named, whose catalog reading the blanking dropped
  (`grep -v zzz -- --exclude-dir=server.key`; weakness, low): fixed by X3;
  the unmapped scan blanked any tool's `command` field: now shell tools
  only; `cmd` and `command` were read in the other order than the proxy's:
  aligned; the tests did not reach the typed-field guard nor Codex's
  fail-closed cases: added. Out of this change: a relative operand that
  starts with `-` (`cat -- -memo.md`) is never read where the call
  started (`isResolvableRelativeToken`), before and after this change; a
  path-rule hole of its own, left to its own fix.
- **Implementation round 2** (a fuzz of 23,497 grep command lines in five
  call shapes, against the code before the change with the word deleted: no
  difference). It found: **a leak, medium, with the clean-tree release**
  (clean-tree-release.md, merged first): that release's counterfactual
  never answers a string the request carries, but the blanked command is a
  new string, which its blank-holding rule then answered as one empty
  place, calling `grep --exclude-dir=x memo/plan.md` public. Fixed there:
  the blanked spellings join its never-answered strings, and the
  blank-holding rule answers only one shell word of the command. Tests:
  its component test. Also: a quoted `--`, ugrep's `--from FILE` and GNU
  abbreviations of `--exclude-from`: fixed by X3; the blanking in
  `labelForClassify` gated on the shell tools as the note says.
- **Implementation round 3** (round 2's probes and fuzz re-run on the
  rebased tree: 3 seeds of 20,000 commands, 0 differences; the clean-tree
  counterfactual fuzzed on 12,000 requests naming labelled files beside
  exclusion words, 0 lowerings, 486 with both fixes reverted). No leak;
  each of round 2's two fixes alone closes the combined finding, and the
  clean-tree release's demo commands keep their release. Low notes: the
  never-answered list names this rewrite by hand, so the one-word rule is
  the structural guard (each guard now has a unit test of its own); `grep -e
  --exclude-dir=bank -r .` reads public, its search of `bank/` resting on the
  tree's evidence like any recursive search (§3). The reviews stop here.
