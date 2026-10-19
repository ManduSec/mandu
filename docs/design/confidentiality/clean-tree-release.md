# The path-derived mask's clean-tree release

Decision note, 2026-10-18. Status: built. Amends the path-derived
precaution of [`confidentiality.md`](./confidentiality.md) §7.1 ("the
path-derived note") and plan 10 §11.8
([`confidentiality-plan-10-flow-taint.md`](./confidentiality-plan-10-flow-taint.md)),
and reuses the value-only release of
[`backstop-value-only.md`](./backstop-value-only.md).

## 1. The problem

A shell command whose text names a secret file gets the file's level from
the path rules (`labelForClassify`, the "path-derived" level), and the model
proxy masks its whole result as one symbol. The precaution was written for
`cat .env`: the command's output may be the file. It also hides the output of
every command that names the file without printing it.

The git history demo (demo-c4) is the case. Asked to scrub a key from a
repository's history, the model ran, among others:

- `git rm -q --cached .env && printf '.env\n' >> .gitignore && git add
  .gitignore && git commit -q -m 'Stop tracking .env' && git status --short
  --ignored`;
- `git filter-branch --force --index-filter 'git rm -q --cached
  --ignore-unmatch .env' --prune-empty -- --all`;
- `git log --all --oneline -- .env`.

None of them prints the file: git reads its index and its objects, and the
`.env`'s committed versions are hidden from the agent's git by the object
twins (confidentiality.md §7.2a). Each output was still one symbol. On Claude
Code the model lost about three turns and could not see why its first
`filter-branch` did nothing ("Cannot rewrite branches: You have unstaged
changes", in the masked output). On Codex, OpenCode, OpenClaw and Goose the
demo failed outright.

The existing releases of a path-derived mask all prove the output is
something the model may see: a refused open's failure text (the denied-only
release), the file's structured twin, its key listing, a folder's names.
Git's output is none of these.

## 2. The rule

A command result masked only by the path-derived level, from a call whose
recorded process tree read no secret, is released when every secret path it
names is a registered credential file and the output carries none of those
files' secret bytes in any form Mandu can look for. Each registered value in
the output becomes its own symbol (the value-only release); every other byte
stays. In every other case the result is masked whole, as before.

The arbiter makes an offer (`pathRelease` beside the classify verdict, whose
level stays secret). The proxy takes it only on its own evidence. An older
proxy, or another classify consumer, ignores the field and masks the result
whole.

**The arbiter's rules** (`pathReleaseOffer` in `arbiter/ipc/server.ts`, the
pure parts in `arbiter/policy/clean-tree-release.ts`). No offer
unless every rule holds:

- **R1. The verdict.** The confidentiality axis is on, the classify verdict
  is secret by the path rules alone (no value-backstop raise: a public path
  verdict takes the value-only release instead), and the tool is a shell
  command tool (`Bash`, `bash`, `shell`, `exec_command`, `local_shell`,
  `exec`): never `Read`, an MCP tool or a background poll.
- **R2. The command.** The call's input and origin hold no `MDU:` in any
  case: a command that carries a placeholder may be run with the value it
  stands for, and print it (the rule the path row's narrowing already uses,
  plan 15 §13.12).
- **R3. The tree.** The proxy names the call (`callId`; the openai-proxy,
  whose classify names no call, sends `treeCallId`), and asked its process
  taint first (the ask on the human socket binds the call; the openai-proxy
  asks before its classify since this change, as the Claude proxy has since
  2026-10-04). Since folder-listing-compound.md (design review round 3),
  the command the request carries must also be one the proxy recorded for
  the call (its signature among the recorded ones): nothing else tied the
  history's echo of the command to the tree's. Its process tree was
  bound by the recorder (`exact` or `shared`, never a claim or a guess), has
  a root, and no process in it (or in an orphan root it may have started)
  opened a secret raw. No open in it was refused, and no connection from it
  was refused. (A refused open has the denied-only release; it is not
  combined with this one.)
- **R4. The named files** (the counterfactual test). Let C be the
  registered credential files whose bytes the content checks below can
  recognize. A file is in C when all of these hold:
  - the secret registry holds an active base row for it, and its label (or
    the catalog) still calls it secret;
  - it has a structured twin with at least one masked value
    (`structuredTwinWithSecretsFor`): a credential file such as a `.env`,
    never a document, whose whole content is its secret;
  - its bytes on disk now are the registered row's value
    (`fileRegisteredAsIs`, one bounded read: its own real path, a regular
    file, not over the scan bound, never under `/proc`, `/sys`, `/dev`,
    `/run` or Mandu's own state), and its pieces are complete
    (`fileUnpieced` false; plan 10 §11.18).

  The arbiter then reads the call's paths again, by the classify's own
  path rules (`pathLevelWith`), through a counterfactual label lookup
  (`counterfactualLookup`). It answers as the real one does except, for a
  path no label covers:
  - a file in C reads as an explicit `public` label (which overrides the
    catalog, as a human label does), and the text scan's list of label
    roots loses exactly C's literal roots (a folder or pattern label over
    one stays);
  - a relative token as the scan passes it (`.env`, read by the catalog's
    name rule wherever it lies) reads `public` when it resolves to a file in
    C in at least ONE directory the command's words are read in, and in
    every other one to a file in C, an empty place (nothing on disk, `lstat`
    ENOENT only, and no registry row) or a path a label calls public;
  - an absolute path that is such an other resolution of such a token, and
    lies empty, reads `public` too (after `cd storefront` the scan also
    reads `.env` where the call started, `/ws/.env`, where no file is);
  - a token holding a blank (a quoted message or script, which the scan
    also reads word by word) that lies empty in every directory, and is no
    `REV:path`, reads `public`, and so does its absolute reading.

  Those directories are the start directory (the guard's, else a `workdir`
  the session's agent honours for that tool, as the classify reads it:
  `callWorkdirOf`) and each plain `cd` / `pushd` of every command text the
  request carries, in order (`commandDirsReached`, the key listing's walk).
  When any of them is not known, or the command may change directory in a
  way the walk does not follow (`wordDirectories`: a computed target, a
  `cd` it did not count such as one inside a quoted script or an `eval` or
  `\cd`, a `popd`, `-C`, `--work-tree`, `chdir`, `source`, `$C ..`, a line
  break, a lone `&`, a brace group), relative tokens keep their own reading.

  An empty place alone never reads public (review round 3, finding 1): git
  prints from its object store what no longer lies on disk (`git show
  HEAD:config/.env.production`, `git log -p -- old/.env`), and the
  path-derived mask was the only thing holding a secret file that lives
  only in history. A token reads public only for its link to a registered
  credential file, whose every committed version the object twins hide.

  The counterfactual reads the command with its message words blanked
  (`messageSpans`): every argument of `printf` and `echo` up to a
  redirection, and the message of `git commit -m`, which no program opens
  (none at all when the command holds `$` or a backquote). So `printf
  '.env\n' >> .gitignore` and `git commit -m 'Stop tracking .env'` are not
  read as paths.

  It never answers a string the request itself carries (its origin, any
  string of its input, either spelling, each as the path rules may rewrite
  it before they read it, `--exclude-dir=NAME` blanked by
  [exclusion-flags.md](./exclusion-flags.md), and for a tool the spec does
  not map each object key of its input), and its blank-holding rule answers
  only a word of the command (`commandWords`): the scan asks the lookup about a whole
  command as one path, where an exact label on that string short-circuits
  the token scan (`confidentialityForOrigin`), so an answer for one would
  call the command public unread (review round 1, finding 1). A `file:`
  anywhere in the request refuses the release (that scan decodes such a URL
  into another string). Nor a string holding a line break or a NUL, nor a
  `~` token. The release needs that second reading to be public. So every
  secret reading of the command is a reading of a file in C, by the
  classify's own scan: a document, a labelled folder, a key, a file changed
  since it was registered, a file the registry does not hold, a secret file
  that lives only in git history, an unregistered `.env` in a directory the
  command moves to or a search reaches by name (`--include=.env`), and a
  glob over a labelled directory each keep the mask.
- **R5. The size.** The result is at most 256 KiB (`VALUE_ONLY_MAX_CHARS`).
- **R6. No token.** The result holds no `$MDU` text in any case. A twin
  printed beside other output (`cat .env; git status`) keeps the mask, as do
  forged or relayed tokens.
- **R7. The content.** With the value backstop's hits counted as for any
  result:
  - with no hit, the text as it is is checked;
  - with hits, the value-only plan (backstop-value-only.md A2-A6) must
    succeed, and its text is checked with each replaced span cut out (a NUL
    in its place).

  The checks, all of which must find nothing:
  - **(a)** the value backstop's own scan on the planned text (A6a);
  - **(b)** the residue scan (A6b): every registered single-line value of
    8 or more characters, in every encoding and view that note lists, and
    the fragments of the credential-like ones and of the replaced values;
  - **(c)** the credential shapes (`locateSecretShapes`: a vendor key, a
    private key block, a URL's password, a credential assignment), so a
    key no registry row holds (an old `.env` version no object twin hid)
    is not released either;
  - **(d)** the files' own values: no masked value of a file in C (its
    twin's secret texts, the commented-out key the credential belt masks
    included), and no value any registry row of that file has held
    (obsoleted rows of an earlier registration included: a rotated key an
    old commit may print), of 6 or more characters, verbatim. This reaches
    the short and low-entropy values the residue scan leaves out (a
    7-character `DB_PASSWORD`);
  - **(e)** a bare token that reads as a credential
    (`bareCredentialToken`): a run of 16 or more letters, digits and
    `_-+/=` holding an upper-case letter, a lower-case letter and a digit,
    at 3.5 bits a character or more, that is neither hex alone (git's ids)
    nor a UUID. The shapes need a vendor prefix or a `name=` beside the
    value; an old value no row holds, printed alone, has neither (review
    round 1, finding 2).
- **R8. Errors.** Any error while planning or scanning means no offer.

**The proxies' rules** (`acceptPathReleaseOffer`, beside
`acceptValueOnlyOffer`, byte-identical in
`interceptors/anthropic-proxy/src/rewrite-request.ts` and
`interceptors/openai-proxy/src/rewrite-request.ts`). The offer is taken only
when all of these hold:

- **Q1.** The verdict is secret, the arbiter's own (`raisedBy` absent), and
  this proxy raised it no further.
- **Q2.** The call's evidence is clean exactly as the value-only release asks
  (`valueOnlyEvidenceClean`, backstop-value-only.md P2): no taint answer
  masks it, no file read in its tree (a listed reader's release included),
  no refused open, no twin matched, no refused connection, no blocked
  command, nothing received from a secret holder during the call (the Claude
  proxy), no harness mask; the result is text only and the integrity axis
  does not distrust it; for Codex it is no unparsed user shell record; it was
  not forwarded in clear in an earlier request.
- **Q3.** The offer is rebuilt from the proxy's own copy of the result. With
  no spans its text must equal the result exactly. With spans, the
  value-only rebuild (P3): sorted, disjoint, in bounds, each a whole `$MDU`
  token, the rebuilt text equal to the offered one, no replaced value left.

A release with no span lowers the verdict to public: the result is forwarded
as received, with no note (it is not masked). A release with spans is
forwarded as the value-only release is: each value a `symbolize` event, the
values the §9 oracle's must-not-survive spans, no note.

## 3. Why the invariant holds

The path-derived mask is a second line. The first is the guard: in a call
whose tree it recorded, every program that opened the named file was served
its twin (keys, and a symbol for each masked value), and nothing in the tree
read a secret raw (R3). Through the first line alone the output can hold only
twin text, and R6 refuses any token, so what is left is what the programs
printed that is no part of the file: git's messages, file names, commit ids.

The mask guarded the case where the first line failed: a read the guard did
not see. Against an adversary it never was a defence, since a command that
does not name the file (`cat .e*`, a script) is not masked for its name. It
caught an accident: a command that names a file and, through a gap in the
guard, prints its bytes. For a file in C the release catches the same
accident by its content. Every masked value of the file is a registered row:
each copy of one that is long and random enough becomes its symbol, and the
residue scan refuses its encoded and partial copies. Every long line of the
file is a piece of its row, so a raw copy of the file is refused (a piece
outside a replaced value, A4). A short value is looked for verbatim (R7d), a
key no row holds by its shape (R7c). And R4 keeps the release to files whose
twin already shows the model everything but those values: a document, whose
content is all secret, keeps the mask.

So, compared with before, the model sees no secret byte through a working
guard, and through a gap in the guard it sees what a command that does not
name the file already showed it, with the file's own values looked for in
more forms than for that command.

## 4. What this widens

Each item reaches the model only where the first line failed (a read the
guard did not record), and each is already reachable today by a command that
does not name the file:

1. A secret of a file in C that Mandu does not hold as a value and that has
   no credential shape: a value the extractor did not find, outside a long
   line (a line under 24 characters), shorter than 6 characters, hex alone
   or under 16 characters (so no bare token either), or encoded in a form
   the residue scan does not know (backstop-value-only.md §4 item 3), or
   with fewer than 6 characters of it surviving. Such a byte also reaches
   the model from an OLD version of a file in C held in a store the twins
   do not cover: where the object twins missed a committed version
   (confidentiality.md §7.2a: `--best-effort`, a commit made after the
   launch planned them), since `git log -p .env` names a file in C, and in
   every other store (`tar -xOf backup.tar storefront/.env`, an archive, a
   database dump), which no twin covers at all. The same output from a
   command that does not name the file is released today on the value
   backstop alone, so the release is tighter there, not looser (round 4).
2. Whatever can be derived from the output beside the values: a blob id of
   an old version of the file (`git log --raw` prints them anyway), a
   length, a checksum.
3. A secret file that lives only in git history and whose name holds a
   blank, named in quotes outside a `REV:path`, where only a label (no
   catalog name rule) makes it secret: R4's reading of a blank-holding
   message. Its name must also lie empty on disk in every directory of the
   command. Round 4 could not reach it: the catalog's name rule keeps a
   `.env`-style name secret first (`git log -p -- "my creds.env"` stays
   masked).
4. A release is not recorded as forwarded in clear (as in
   backstop-value-only.md §4 item 6): otherwise the next request's
   re-classify of the history would take it for a result masked after the
   fact and turn it into a symbol (review round 3, finding 2). If a later
   request masks the same result whole, it gets no "masked after the fact"
   note.
5. Forms of a key the residue scan does not know, beyond
   backstop-value-only.md §4 item 3: percent-encoding of EVERY byte
   (`%73%6b…`; only the `encodeURIComponent` form is matched), chunks of
   under 8 characters split by letters or digits, a reordered passphrase.

What stays masked whole: any token in the output; a call no recorded tree
answers for, a raw read in it, a refused open or connection, a blocked
command; a document, a labelled folder, a glob over a labelled directory, a
file changed since its registration or over the piece bound; any shape,
fragment or encoded copy the checks find; a result over 256 KiB; a command
holding a placeholder; `Read` and every non-shell tool.

## 5. Tests

- Arbiter `test/unit/clean-tree-release.test.ts`: the pure plan, one test per
  refusal (a token in any case, too long, a shape, a file's short value, a
  value-only plan that fails) and the release with and without spans.
- Arbiter `test/component/clean-tree-release.test.ts`: the classify op over a
  real server offers the release for the demo's commands (git's output, and a
  `git log -p` line holding the key) on a bound clean tree, and makes no
  offer: with the axis off, for a tree that read a secret raw, a refused
  open, an unbound call, a document named beside the `.env`, a `.env`
  changed since its registration, a command holding `$MDU:`, a `Read`, an
  output holding a token, a credential shape, an encoded copy of the key, a
  raw copy of the file, a short value of it.
- Both proxies' `test/unit/clean-tree-release.test.ts`: the offer is
  rebuilt or refused (Q3), and taken only on clean evidence (Q1, Q2).
- `tests/stack/clean-tree-release.test.ts`, the e2e oracle over the real
  arbiter and both proxies in their production wiring: the demo's commands
  reach Claude Code and Codex in clear; a raw `.env` printed by an unseen
  read, a base64 copy of its key, a tainted tree and a document beside the
  `.env` stay one symbol; no request to the model carries the key in any
  form the test knows.
- The demo drill (`demo-git-history-scrub`), replayed in the kernel lane:
  its checks are unchanged (the key reaches neither the model nor origin).

## 6. Review rounds

Adversarial reviews (a reviewer told to get a registered value, a piece of
one, an unregistered secret in a labelled file or a document's content to
the model or the network through the release), in order:

- **Round 1** (the note, and the first code it found in the tree). It
  found:
  1. **A leak, high.** The first counterfactual called any path with nothing
     on disk public, the WHOLE command string included. The scan asks the
     lookup about the whole origin as one path, and an exact label on it
     short-circuits the token scan, so `cat vault/plan.md` (a labelled
     document), `cat ~/.ssh/id_rsa` and every other command read public:
     R4 did nothing. Fixed: the empty-place answer is for absolute
     normalized paths only, never a string the request carries, and a
     relative token is answered only by resolving it in every directory the
     command's words are read in. Tests: the component test's list
     (`cat memo/plan.md`, `/bin/cat memo/plan.md`, a document beside the
     `.env`, `git show HEAD:memo/plan.md`, an unregistered `.env` read after
     a `cd`, a `cd` inside a quoted script, `git -C`, `popd`, `~/.ssh`).
  2. **A leak, medium (through a gap only).** The release with no span
     forwards the output as received, and the shapes miss a bare
     high-entropy token and a rotated value no active row holds. Fixed:
     R7d also reads the file's obsoleted rows, and R7e looks for a bare
     token that reads as a credential. The reviewer also proposed refusing
     whenever a repository's object twins were made best-effort; the
     arbiter does not know that per repository, so it stays §4 item 1.
  3. The "second line" argument of §3 holds only as far as every raw read
     of a named file becomes a taint row of the tree and the twins and
     object twins hold: confirmed for the taint rows; the object twins'
     gaps are §4 item 1.
  4. R4 is load-bearing (a labelled document of short lines has nothing R7
     can find), so the counterfactual stays.
- **Round 2** (the code after round 1; a partial pass, cut short). It
  found no leak, confirmed the `pathLabel` refactor leaves `classify` as it
  was, and found two weaknesses:
  1. For a tool the session's spec does not map, the scan also reads each
     object key of the input, and a `file:` URL decoded into another
     string, as one whole path; neither was in the sources the
     counterfactual never answers. Fixed: every key is a source, and a
     `file:` anywhere in the request refuses the release. Test: the
     component test's `file:` URL.
  2. R4 trusts the walk and `directoryMayChange` to agree with the shell.
     Fixed: a lone `&` (a background job; `2>&1` and `&>` are
     redirections) and a `{ …; }` group refuse relative answers too. Tests:
     the unit test's list.
- **Round 3** (the code after round 2: the proxies' acceptance, the
  openai-proxy's reordering, R7, a real arbiter). It confirmed the proxies'
  Q1-Q3 (a forged offer, a non-text block, `$MDU` text, a background poll,
  an MCP result, Codex's envelope, `custom_tool_call_output`, a user shell
  record and after the fact all mask whole) and that asking the taint first
  changes nothing else in the openai-proxy. It found:
  1. **A leak, high, with no gap in the guard.** The empty-place answer
     released a secret file that lives only in git history (`git show
     HEAD:config/.env.production`, `git log -p -- old/.env`, `git show
     HEAD:keys/id_ed25519`, `cd storefront && git show other-branch:.env`):
     its path holds nothing on disk, and lines such as `JWT_SECRET=…` or a
     quoted `DB_PASSWORD="…"` pass R7. Fixed: a token reads public only for
     its link to a file in C (§2 R4), and message words are blanked instead
     of read as empty places. Tests: the component test's list, the stack
     oracle's history-only `.env`.
  2. **A utility bug, high.** The release was recorded as forwarded in
     clear, so the next request refused it as masked after the fact.
     Fixed in both proxies; a two-turn test in each.
  3. R4 read a `workdir` the tool ignores (Claude Code's Bash). Fixed: the
     classify's own `callWorkdir`. Test: the component test.
  4. Searches that reach another folder's `.env` by name (`find memo -name
     .env`, `grep -r X --include=.env .`, `x=../memo; cat $x/.env`) were
     released; closed by fix 1. Tests: the component test.
  5. Forms the residue scan does not know (§4 item 5).
  6. A Codex script cell is named by its first `exec_command` literal, and
     its other literals are covered by the session fold alone. Fixed: the
     openai-proxy offers the release to a plain call only (no cell, no
     `wait`, no call asked another way).
- **Round 4** (the code after round 3, with round 3's probes). Every round
  3 fix holds (the history-only list and the directory tricks all masked;
  two turns released on both proxies), and it found no leak in the new
  parts: no word `messageSpans` blanks is opened by any program (`git
  commit -F .env`, `-- .env` after the message and `git -c … commit` stay
  masked); archives naming a file in C release only what a command not
  naming it releases today, with the shapes and the bare-token check on
  top. It found: the residual of §4 item 1 holds for every store no twin
  covers, not only git (now said there); §4 item 3's example was not
  reachable (now said there). The regression suites pass (the value-only,
  path-derived note, key listing and folder listing tests in the arbiter,
  both proxies and the stack). The reviews stop here.
- **With exclusion-flags.md** (2026-10-18, that change's implementation
  review, round 2): the path rules now read a grep command with its
  `--exclude-dir=NAME` words blanked, a string the request does not carry,
  which the blank-holding rule answered as one empty place (`grep
  --exclude-dir=x memo/plan.md` read public; a leak, medium). Fixed: those
  spellings are never answered, and the blank-holding rule answers only one
  shell word of a command text. Tests: the component test.

## 7. Log

- 2026-10-18: built (this note). Prompted by demo-c4's blind git in the
  live demo batteries of 2026-10-17.
