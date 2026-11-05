# A search that excludes a labelled path

Decision note, 2026-10-18; amended 2026-10-27 (rg negated globs and grep
`--exclude=`, X4-X7: approved by the maintainer on 2026-10-27, "build as
drafted"). Status: built. Amends the path-derived precaution
(`labelForClassify`, `confidentiality.md` §7.1).

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

**The rg form** (2026-10-27). In the live Codex take of demo-notion-token
(posture `confined`), Codex's first call was

    pwd && rg --files -g 'AGENTS.md' -g 'notes-app/**' -g 'meetings/**' -g '!notes-app/.env' | sort
      && echo '--- notes-app listing ---' && ls -la notes-app && echo '--- meeting file ---'
      && sed -n '1,240p' meetings/2026-10-16-team-sync.md && echo '--- scripts/config references ---'
      && rg -n "notion|env|dotenv|token|meeting" notes-app --glob '!*.env'

(one line). The words `!notes-app/.env` and `!*.env` match the catalog's
name rule `shape:*.env`, so the result came back as one symbol ("names
secret files (!notes-app/.env, !*.env)"), and so did Codex's retry with
`-g '!**/*.env'` added. Both outputs held the meeting notes; no process had
read a secret raw. The path row of each output fingerprinted every line (a
glob places nothing, plan 15 §13.12 condition 1), and the §4 tripwire then
blocked the notes' upload to `api.notion.com` twice. The rule of 2026-10-18
did not apply: it took one plain `grep` only.

## 2. The rule

`withoutSearchExclusions` (`arbiter/policy/exclusion-flags.ts`) returns the
command with each exclusion word below blanked by spaces of its length (the
whole word, so nothing of it is left as a token), or the command unchanged.
Anything not provably an exclusion is left as written, and is read exactly
as before.

- **X4. Exact segmentation.** At most 4 KiB, printable ASCII only (a line
  break, a tab, a NUL or any other character refuses the whole command).
  The command is split outside quotes on `&&`, `||`, `;` and `|`; words
  split on spaces, `'…'` and `"…"` group. The whole command is refused when
  any of these appears outside quotes: `$`, a backquote, `\`, `(`, `)`,
  `{`, `}`, `<`, `>`, `#`, `~`, `^`, `%`, `!`, `*`, `?`, `[`, `]`, a lone
  `&`, `|&`, or a word starting with `=` (zsh's `=cmd` expansion); inside
  `"…"`: `$`, a backquote, `\` or `!`; an unterminated quote; an empty
  segment. So no expansion and no redirection is anywhere in it, and a
  blanked word lives only in its own program's argv. A word repeated in
  another segment (`cat '!notes-app/.env'`) is a different span and is
  still read.
- **X5 (and X1's first word). The segment.** Its first word is exactly
  `rg`, or `grep`, `egrep` or `fgrep`: unquoted, no path, no `command`,
  `env`, `xargs`, `sh -c` in front, no assignment before it. Other
  segments are left as they are.
- **X2. grep `--exclude-dir=NAME`** (2026-10-18). Written exactly so with
  no quote in it, NAME one plain path segment (`[A-Za-z0-9._+-]+`, an
  optional trailing `/`, not `.` or `..`). Not a path (`./bank`,
  `/abs/bank`: GNU grep and ugrep match NAME against a directory's own name,
  so those keep nothing out; design review round 2). One word only: the
  two-word form (`--exclude-dir bank`) is never blanked, since its meaning
  depends on what grep and the environment do with the words before it
  (`POSIXLY_CORRECT`, `GREP_OPTIONS` up to GNU grep 3.5, an option another
  grep parses differently: ugrep's optional-argument `--group-separator`),
  and in some of them `bank` is a file operand (design review round 1).
- **X7. grep `--exclude=`** (2026-10-27). `--exclude=NAME` (NAME as in X2,
  no `/`) or `--exclude='GLOB'` (one single-quoted string). The first
  round dropped this form because it "keeps no folder out", a relevance
  argument, not a safety one: for a file label it does keep the file out,
  and no grep opens the word. Never `--exclude-from=FILE` (it opens FILE by
  name), never `--include`, never the two-word `--exclude NAME`.
- **X6. rg's negated globs** (2026-10-27). The option word `-g`, `--glob`
  or `--iglob` (unquoted), followed by a word that is one single-quoted
  string beginning with `!`: both words. Or the one word `--glob='!…'` /
  `--iglob='!…'`. The glob text inside the quotes is free (`*` and `**`
  are literal to the shell and only a filter to rg). Never blanked: `-g!x`,
  `-g'!x'`, `-g='!x'` (the glob `=!x`), `"!x"` (history expansion in an
  interactive bash; X4 refuses it), an unquoted `!x`, `'\!x'` (a positive
  glob), `'!x'y`, any positive glob, `--pre-glob`, `--ignore-file`,
  `-f`/`--file`, `--type-add`.
- **X3. Not where it names a file.** In both programs a word after `--`
  (quoted or not) is an operand: nothing after it is blanked. In a grep, a
  word right after `-f` (or a short cluster ending in it) or ANY long option
  written without `=` (`--file`, `--exclude-from`, ugrep's `--from`, a GNU
  abbreviation such as `--exclude-f`) may name the file literally called
  `--exclude-dir=NAME`; it is kept, so the catalog still reads that name
  (`grep -v x -- --exclude-dir=server.key` stays as before; implementation
  review rounds 1 and 2). In an rg (which takes no abbreviations), a pair
  or word right after `-f` (or a cluster ending in it), `--file` or
  `--ignore-file` is kept the same way.

**The three call sites** apply the one function alike, to a shell tool's
command only (`Bash`, `bash`, `shell`, `exec_command`, `local_shell`,
`exec`: `SEARCH_EXCLUSION_SHELL_TOOLS`):

- `labelForClassify`, to the shell command (`cmd` first, then `command`,
  as the openai-proxy names the origin; and the origin when it is that same
  text), in both of its passes (the level, and the paths and files it
  names). Never a typed path field.
- The scan of every string of a tool the session's spec does not map
  (`labelForUnmappedInput`, which reads Codex's `exec_command` input): the
  `command` and `cmd` fields only, of a shell tool only. Never a typed path
  field, any other string, nor a joined argv (Codex's `shell{command:
  [...]}`, whose elements may hold blanks): blanking a string the scan reads
  as one path could skip an exact label on it (design review round 2).
- The clean-tree counterfactual (`clean-tree-release.md`), which never
  answers a string the request carries: each such string as this function
  rewrites it joins that never-answered list (any string, any tool). The
  2026-10-18 implementation round 2 leak came from a missing entry there.

A unit parity test reads the same commands through the first two sites
(and a seeded fuzz through both), and the clean-tree component test the
third.

## 3. Why the invariant holds

**The rg facts that matter** (ripgrep 15.1.0, checked). A negated glob
never guarantees exclusion: a later positive glob overrides it (`-g
'!app/.env' -g 'app/**'` reads `.env`), and an explicit path bypasses it
(`rg TOKEN -g '!app/.env' app/.env` reads the file). A positive glob
overrides rg's hidden-file and ignore logic, so it reads MORE than the same
search without it (`rg TOKEN .` skips `.env`; `rg TOKEN -g 'app/.env' .`
reads it); an agent-written `.rgignore` that whitelists `!app/.env` makes a
plain `rg TOKEN .` read it too (a `-g '!x'` still beats that `.rgignore`).
On a parse shift (`rg -e -g '!app/.env' .`) the word becomes the path
`./!app/.env` ("No such file"), never `app/.env`.

So the argument must not depend on the program actually excluding the file.
It is only this: **the blanked word is never opened as the labelled path by
name, however the command is parsed.** A grep `--exclude-dir=NAME` or
`--exclude=…` word is, as an option, a name grep matches against files or
folders; as the argument of `-e`, pattern text; as an operand (after `--`,
as `-f`'s argument, under `POSIXLY_CORRECT` or with `GREP_OPTIONS` in
front), the file literally called `--exclude-dir=bank`, never `bank`
(checked with strace on GNU grep 3.12, on ugrep 7.8.4 called as Claude
Code's shell snapshot calls it, and on busybox 1.37, which refuses the
option). An rg negated glob is a filter, pattern text, or a path starting
with `!`, never the labelled path. The option words `-g`, `--glob`,
`--iglob` are, at worst, files of those names, whose label a token starting
with `-` never had (`isResolvableRelativeToken`). With no expansion and no
redirection anywhere (X4), the words reach no other program: rg prints its
globs only under `--debug`, to stderr, and `2>&1` and `|&` are refused.

So the scan loses no reading of a path the command opens BY NAME, except the
catalog's reading of a literal odd name where the program takes the word as
a file: under `POSIXLY_CORRECT` a trailing `--exclude-dir=server.key` is a
file operand, and on a parse shift `!notes-app/.env` is the file
`./!notes-app/.env`. Such a file needs that exact odd name, the launch walk
twins one ending in `.env` all the same, and the twins, the process taint
and the value backstop stand behind it.

What the program reads by recursion is what the same search without the
words reads, which the path rules never caught (`grep -rIl -i park .`, `rg
foo notes-app` are public): the release is exactly as safe as an
already-unmasked recursive search, and no safer. Glob precedence, `-uuu` and
`--no-ignore`, `--hidden`, `-L`, `--iglob`'s case folding and an
agent-written `.rgignore` change only what is read by recursion, which was
already the twins' job, not the text scan's. A positive glob does not
qualify: it widens the read past rg's defaults and selects the file by
name, so it stays read (the clean-tree note keeps `--include=.env` masked
for the same reason). No option is parsed beyond X3's file-argument guard,
so no option table can be wrong.

The scan's heuristics that look at the whole text (a change of directory:
`chdir`, `cd`, `-C`, `--directory` anywhere) no longer see the blanked
word, so `grep KEY .env --exclude-dir=chdir` is read with the exact base,
where a human `public` label can apply. That is the right reading: grep
never changes directory.

**The second line of defense.** Under the `confined` posture (guard plus
bind, `confidentiality.md` §10.1) every open of a registered file by any
process in the agent's world, rg included, is served its twin, and the
recorder shows whether any process read a secret raw. If an exclusion does
not hold (a later positive glob, an explicit path, a `.rgignore`), the
model sees the twin's placeholders, never the value; the inbound value
backstop turns a registered value in the output into its own symbol.

## 4. What this widens

Nothing a recursive search with no exclusion does not already show:

1. **The `gated` posture.** Without the guard, a raw read by recursion of
   an unregistered secret (a `.env` past the walk's caps, a label the
   guard never confined) is not caught. That is `confidentiality.md`
   §10.1's "What does NOT hold" item 3, identical to `rg KEY -g '*' .` or
   `rg foo notes-app`, which are public.
2. **A literal `!`-led name** read on a parse shift (§3).
3. **The `.gitignore` re-include.** Claude Code's grep (ugrep with
   `--ignore-files`) re-includes a folder a `.gitignore` in the tree names
   with `!bank/`, whatever `--exclude-dir` says; then grep reads the
   labelled files, served their twins, exactly as `grep -r … .` would.

Nothing new reaches the network: the egress gate and the tripwire on the
secret's own registered row are untouched.

**The fingerprint tripwire.** An output the carve-out releases is public,
so its call mints no path row and none of its lines become fingerprints
(confidentiality.md §4): the model read the text in clear, and
fingerprinting it would only make the user's own notes un-sendable again.
Every registered value (the token's own row), every value-only symbol the
backstop mints in that output and every credential shape keep their own
rows. `egress-fingerprint.ts` is unchanged.

Kept as before (masked when they name a labelled path): the two-word grep
form, `--exclude-dir=./bank` or any path, an unquoted glob or special
character anywhere, `--exclude-dir={bank,.git}`, `--exclude-from=FILE`,
`--include`; an rg positive glob (`-g 'notes-app/.env'`, `-g '*.env'`;
`-g 'notes-app/**'` under a LITERAL label, §6), `--pre-glob`,
`--ignore-file`, `-f`; anything after `--`; `git grep … ':!bank'`, `find .
-path ./bank -prune …`; a trailing `2>/dev/null` or `2>&1`, `|&`, a lone
`&`, `$( )`, a backquote, a here-doc, a line break, `bash -lc '…'`, `xargs
rg`, `/usr/bin/rg`, `env rg`; an operand or any other word naming the path,
in the same segment or another.

## 5. Tests

- Arbiter `test/unit/exclusion-flags.test.ts`: blanked, the whole word, one
  or several (Codex's two exact commands; `-g '!x'`, `--glob '!*.env'`,
  `--iglob '!**/*.env'`, `--glob='!x'`, several pairs, a compound with `|
  sort` and a double-quoted `"a|b"` pattern, grep `--exclude=.env` and
  `--exclude='*.env'`); unchanged for every refusal of X2-X7 (each X6
  refusal, positive globs, after `--`, `-f`, `--ignore-file`,
  `--pre-glob`, `--exclude-from`, `--include`, `xargs rg`, `sh -c`, `bash
  -lc`, `/usr/bin/rg`, `env rg`, `$( )`, a backquote, `2>&1`, `|&`, a lone
  `&`, a here-doc, a line break, an unterminated quote, a quoted `--`, the
  grep file-argument guards); the classify: demo-c2's command public, an
  operand or statement naming the folder secret, `grep KEY .env
  --exclude-dir=chdir` with `.env` labelled public reads public, a typed
  path field holding the text never blanked; demo-notion-token's commands
  public under the drill's pattern label, and no-model under a literal
  label (the positive glob `notes-app/**`, pinned as known, §6); `rg foo
  notes-app/.env -g '!notes-app/.env'`, `…; cat notes-app/.env` and a
  positive glob naming the file no-model; a parity test: the classify
  (`Bash`, `exec_command`) and the unmapped-input scan (`pathLevelWith`)
  read a blanked command as the command with the words deleted; a seeded
  fuzz (1,200 rg, grep and compound lines over two label shapes): exactly
  the provable exclusions are blanked, and both sites read the blanked line
  as the line with them deleted (the unmapped site's blanking removed fails
  it, checked by mutation).
- Arbiter `test/component/clean-tree-release.test.ts`: blanked rg and grep
  `--exclude=` spellings beside a document are never answered as an empty
  place (with both of the counterfactual's guards removed, each of them is
  offered: checked by mutation).
- `tests/stack/exclusion-flags.test.ts`: the demo's command, and its rg
  spelling, reach Claude Code and Codex in clear; the two-word form, a
  statement beside the flag or the glob, `--include=`, `--exclude-from=`,
  an rg positive glob over the folder, `xargs rg` and `bash -lc 'rg …'`
  stay one symbol; demo-notion-token's Codex leg: its exact first command
  and its retry reach Codex as printed under the pattern label (as a
  function call and as the take's own code-mode cell), a command
  naming the file beside the glob, a double-quoted glob and a later `cat`
  stay one symbol; THE ORACLE in both.
- `tests/stack/path-row-bound-upload.test.ts`: the rg shape, Codex's exact
  first command under the drill's pattern label through the production
  openai-proxy and net-proxy: the model sees the notes, their upload to
  `api.notion.com` is forwarded with the real token, the raw token to an
  unbound host trips; THE ORACLE: an exclusion that does not hold (`-g
  '!notes-app/.env' -g '*'`) shows the model only the twin's placeholder,
  the raw token in the output is no model's to read, and the forms the
  rule does not prove stay one symbol.

## 6. Open

Under a LITERAL label on `notes-app/.env`, Codex's first command still
reads no-model: its positive glob `-g 'notes-app/**'` is a glob under a
folder that holds a label (`globRaise`), which the drill's pattern label
(root `/`) cannot show. And a call that stays masked so still fingerprints
every line, because a glob places nothing in plan 15 §13.12 (condition 1).
The follow-up, not part of this change: let §13.12 place a glob whose label
hits are all registered credential files (the clean-tree R4 set C).

## 7. Review rounds

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
- **The rg amendment** (2026-10-27; design draft from the demo-notion-token
  take, recommendation "build narrower": the negated globs and `--exclude=`
  only, no exclusion semantics; approved by the maintainer on 2026-10-27,
  "build as drafted"). Decisions in the build: X4's segmentation replaces
  the one-plain-command rule for grep as well as rg (so `cd ws && grep …
  --exclude-dir=bank` and `… | head` now blank, as the draft's grep
  `--exclude='*.env'` needs a quoted glob); the X3 file-argument guard is
  kept for rg (`-f`, `--file`, `--ignore-file`) beside `--`; a word starting
  with `=` and an empty segment refuse the command; one shell-tool list
  (`SEARCH_EXCLUSION_SHELL_TOOLS`) for the two scan sites. With a positive
  glob after a negated one, an explicit path naming the file, `-uuu` and
  `--iglob` covered by tests; the stack's oracle shows only the
  placeholder reaching the model when the exclusion does not hold. Open:
  §6.
