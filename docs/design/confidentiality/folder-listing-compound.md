# A folder's names beside another command

Decision note, 2026-10-18. Status: built. Amends
plan 10 §11.8 "A folder's names" (`arbiter/policy/dir-listing.ts`, !1629)
and builds on [clean-tree-release.md](./clean-tree-release.md), whose offer
it reuses.

## 1. The problem

A plain `ls` of a labelled folder (`ls mail/inbox bank/`) is released as a
names-only listing since !1629. Any compound command stays masked whole,
because the command names the labelled folder. In the scam-email demo
(demo-c2) the model ran `tools/mail list; ls mail/inbox bank` in one call;
the whole output (the inbox summary included) came back as one symbol, and
the model then read the messages one by one.

## 2. The rule

Computed in the arbiter's classify op, beside the clean-tree release
(`compoundListingOffer` beside `pathReleaseOffer` in `arbiter/ipc/server.ts`;
the pure `compoundLsCommand`, `compoundWithoutLs`, `compoundListingPaths`
and `lsArgvMatches` in `arbiter/policy/dir-listing.ts`; the guard's exec
records of the tree from `callTreeExecArgvs`), from the classify request
itself (rounds 1 and 2 of
the design review: `callTaint` sees only the command's signature, never the
request's `workdir`, view-map spellings or typed paths, so a counterfactual
there could not read what the classify reads). The offer is the clean-tree
release's `pathRelease` (`spans` empty) with `listing: { paths, part }`; the
proxies take it by the same rules Q1-Q3 and add the `listing:` line.

No offer unless every rule holds:

- **L0. The evidence.** The clean-tree release's R1 (a shell command tool,
  a path-derived verdict), R2 (no placeholder), R3 (a tree the recorder
  bound, `exact` or `shared`, with a root, no raw read, no refused open or
  connection), R5 (at most 16 KiB here, the listing's bound), R6 (no `$MDU`
  text in any case), and R7 with no value backstop hit at all (no value-only
  spans: a registered value in the output refuses).
- **L1. The command.** At most 4 KiB. Split on `;` and `&&` only, outside
  quotes, into 2 to 8 segments. Anywhere in it (quoted or not): no `|`, a
  lone `&`, `||`, `<`, `>`, `(`, `)`, `$`, a backquote, `\`, `*`, `?`, `[`,
  `]`, `{`, `}`, `#`, `!`, `^`, `~`, `%`, and nothing outside printable
  ASCII (a line break, a tab, a NUL, a vertical tab, a non-ASCII space the
  shell does not split on). No empty segment.
- **L2. One listing part, at an end.** Exactly one segment is a plain `ls`
  (`plainLsCommand`, unchanged), the first or the last. No other segment's
  first word is `ls`.
- **L3. The other parts.** Each other segment's first word holds no `=` and
  no quote and is on an allow-list: a path to a program (it holds a `/`
  and is not a directory, which interactive bash's `autocd` would enter; a
  path with nothing there fails in the shell and prints only its error), or
  one of `git`, `cat`, `head`, `tail`, `wc`, `grep`, `sort`, `uniq`,
  `file`, `stat`, `date`, `python3`, `node` (a builtin in neither bash nor
  zsh). So no part changes the shell's state by a builtin (`cd`, `alias`,
  `hash -p`, zsh's `autoload`, `setopt`).
- **L4. The other parts name no secret (the counterfactual).** Every source
  string of the request that holds the command (the origin, `params.command`
  or Codex's `params.cmd`, and their view-map spellings) is split by its OWN
  text into the same segments with the plain `ls` at the same index (else
  refused), and rebuilt from its other segments joined by `; ` (never a
  substring replace, never another source's offsets). The request with those
  rebuilt strings, every other param, the `workdir` and the start directory
  unchanged, read by the path rules with the engine's own lookup
  (`pathLevelWith`), is public. So only the listing's operands made the
  call secret, and lowering the whole verdict lowers only them.
- **L6. The spellings.** Every command source is a string (an argv array
  refuses); L1-L3 hold on each, with the same segments; the listing's
  operands are those of the delivered (agent) spelling, which is what `ls`
  received. On Codex the classify has no guard start directory: the
  guard's (`callStartDir(treeCallId)`) must equal the base the verdict was
  read in (`callWorkdirOf`), and a `shell` param other than sh, bash or zsh,
  or `tty: true`, refuses.
- **L7. The command that ran.** The proxy recorded a command for the call,
  and the delivered command's signature is one it recorded.
- **L8. The `ls` that ran.** The guard's exec records of the call's tree
  (by the guard's own lineage, never a claim over the data socket) hold
  exactly one exec whose program's name is `ls` and whose words, read
  by `plainLsCommand`, give the listing segment's operands (names-only
  options, such as an alias's `--color=auto`, allowed). A function or alias
  that stands in for `ls` without running it, or an `ls` another part runs,
  refuses.
- **L9. Across turns.** The agent re-sends the history, and the folders may
  change between turns (a mail tool renaming a file). The offer, once made,
  is remembered by (call, sha256 of the result); a later classify of the
  same result re-runs every rule but L5's comparison with the folders.
- **L5. The output.** With the single listing's framing (`keyListingLines`:
  on Codex after Codex's own head, at most one final newline, no token, not
  empty): its first lines (listing part first) or last lines (listing part
  last) are exactly what `plainLsListingPaths` accepts for that segment, the
  operands read where the call started (the guard's start directory, else
  the call's absolute `workdir`). The count of those lines is fixed by what
  the folders hold, so the split is at one line, not searched for.

The proxies: as the clean-tree release (Q1-Q3; `listing` with spans, or
without a release, refuses), then the line naming the operands as the model
wrote them (filtered as the path-derived note filters, never the arbiter's
resolved paths):

> `[mandu:secret] listing: the last lines of this output are the names in
> <paths> as ls printed them, no file's content, size or date. The lines
> before them are the other commands' output, which may describe any
> folder. The files there may still be secret: reading one shows you a
> symbol where its secret content is.`

("first lines" / "lines after them" when the listing part is first).

## 3. Why the invariant holds

The model reads two kinds of line.

- The listing lines: names the folders hold now, exactly as the single
  listing proves (plan 10 §11.8), checked against the folders at classify
  time. A name holding a token refuses.
- The other lines: printed by commands that, read by the path rules with
  the listing taken out (L4), name no secret path, in a call whose recorded
  tree read no secret raw (L0), with no token, no registered value, and
  nothing the residue scan, the shapes or the bare-token check find. Run as
  a call of its own, the same command would be public by the path rules and
  released on the value backstop alone.

Neither kind rests on which process printed which line: the guard does. A
labelled file a part reads is served its twin, whose tokens refuse the
release; a raw read taints the tree.

## 4. What this widens

1. Attribution. Which lines a part printed is not observed; the split is by
   count. A shadowed `ls` (an alias or function in the shell snapshot, a
   writable directory early on `PATH`, or one a part before it planted there
   in the same call, since nothing is hashed yet) can print other bytes
   ahead of its listing, and they count as the other part's. Through a
   working guard they hold no secret (above). Only through a gap in the
   guard could they hold a labelled file's content, and a command that names
   no folder can print it then. The release is as strong as running the
   parts as two calls, which the path-derived note advises, and no stronger.
2. The echoed command is bound to the recorded one by its signature, which
   does not tell `a '&&' b` from `a && b`; an agent that echoes another text
   than it ran could make the parse differ from what ran. The tree's
   evidence still holds (the guard's records), so only the split of the
   output could be wrong, which the guard covers as in item 1.

What stays masked whole: `||`, a pipe, a background job, a subshell, a
redirection, any expansion or glob; `ls` in the middle, two `ls` parts;
`cd bank && ls`; `ls -l`; another part that names a labelled path, starts
with a builtin, an assignment or a program off the allow-list; an output
whose first or last lines are not exactly the listing; a token or a
registered value anywhere; a raw read in the tree; a call no recorded tree
answers for; a `bash -lc '…'` wrapper (one segment).

## 5. Tests

As built:

- Arbiter `test/unit/dir-listing-compound.test.ts`: the parse (L1-L3, every
  refusal, a quoted separator), the rebuild (L4: `grep -rn ls x.md; ls
  x.md` is not stripped twice; a spelling that splits otherwise refuses),
  the split (L5: first, last, no other line, a line after, a name short, a
  merged first line, a token, Codex's head), the `ls` exec match (L8).
- Arbiter `test/component/compound-listing.test.ts`: the classify op offers
  the compound (listing last and first, operands as written) and refuses a
  raw read, an unbound call, nothing recorded, a recorded command that
  differs, an `ls` the guard did not see, two `ls`, an `ls` with other
  options, a part naming a statement, `git -C bank`, a typed path naming a
  statement, a builtin, a Codex `workdir` other than the guard's start
  directory, `tty`, a registered value, a bare token, the listing not where
  its part is, a line after it.
- Both proxies' `test/unit/clean-tree-release.test.ts`: the `listing:` line
  naming only operands the model's command holds; a listing with spans, no
  operands, another part, a line break, null: masked whole.
- `tests/stack/compound-listing.test.ts`, over the real arbiter and both
  proxies' production adapters with a real `ls`: demo-c2's command reaches
  Claude Code and Codex with the line; the second turn after a rename still
  does (L9); a part naming a statement, the listing in the middle, `cd bank
  && ls`, an `ls` the guard did not see, a raw read and a Codex `workdir` in
  `bank/` stay one symbol; THE ORACLE.

## 6. Review rounds

- **Design round 1** (the first draft, computed in `callTaint`). No leak
  through a working guard. It found: the proxy's lowering dropped EVERY
  reason for the secret verdict, not only the listing's (a Codex `workdir`
  inside the folder); a builtin deny-list is the wrong shape under zsh and
  after quote removal (`'hash' -p`, `autoload`); attribution of lines to a
  part is never observed. Fixed: the counterfactual over the whole request
  (L4), an allow-list (L3), §4 item 1.
- **Design round 2.** It found: `callTaint` never sees the classify
  request (its `workdir`, view-map spellings, typed paths), so the
  counterfactual could not be computed there: moved into the classify op;
  the segment must be removed by each source's own split, never a
  substring replace; a part before `ls` can plant an `ls` on `PATH` in the
  same call (§4 item 1); `callTaint`'s listing ran on the echoed command
  when none was recorded; the note's "nothing else" was false: reworded.
- **Design round 3** (the classify-op draft against the merged clean-tree
  release). Sound to implement once: the release survives a folder change
  between turns (L9), the spellings and Codex's base are pinned (L6), the
  delivered command is checked against the recorded one (L7: added to the
  clean-tree release too, which had no such check on its path), the `ls`
  exec is checked (L8), and the note names operands as written.
- **Implementation round 1** (probes against a real arbiter). No leak:
  every spelling of a part naming a statement refused, a human spelling
  naming one refused, a Codex relative `workdir` refused; what the guard
  must hold (a `git log -p` of the history, a symlink to the folder) is what
  the same part run alone already rests on. It found: L8 walked claimed
  lineage, which the agent can add: now the guard's own only; vertical tabs
  and non-ASCII spaces parsed as blanks by a trim but not by the shell (an
  `ls` of a folder named `bank\v`, names-only): now refused, and an argv
  with a non-printable byte matches no `ls`. Out of this change: Codex's
  `shell_command` tool is not among the clean-tree release's shell tools,
  so neither release reaches a Codex that uses it (before this change too).
- **Implementation round 2.** No leak; round 1's fixes hold. It found: the
  shared evidence's new recorded-command check refused Codex's argv
  `shell` / `local_shell`, whose clean-tree release worked before (utility,
  fail-closed): an argv is now checked by its own elements
  (`execSignatureForArgv`), with a component test; a listing was logged
  with the clean-tree reason: it has its own. Checked: every agent's proxy
  records the delivered command the check reads (Claude Code `Bash`,
  OpenCode `bash`, Goose `shell`, OpenClaw `exec` by `command`, Codex
  `exec_command` by `cmd`); a poll (`write_stdin`, `wait`) can ride neither
  the offer nor the memo; the note's operands never name more than the
  command already on the wire. The memo is keyed by the call, not the
  session: a second session reusing a call id gets only bytes already
  released for it. The reviews stop here.
