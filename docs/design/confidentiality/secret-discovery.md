# Finding secrets: the launch walk, the catalog's recall, and the git-history scan

> Status: **BUILT.** Three parts of one question, *which secrets does a
> `secrets`-mode launch know about?*
>
> - §1, the launch-time walk over the user's real HOME and workspace, its
>   "not covered" ledger, and `mandu doctor --secrets`, the dry run that
>   shows the inventory before a launch (built 2026-09-24, with fixture
>   homes as its live oracle).
> - §2, the recall of the default-secret catalog the walk applies, measured
>   against an 84-file corpus of where developer tools keep their login state
>   (built 2026-09-25; the corpus is a regression gate), and since 2026-10-19
>   the catalog's content tier: a config file the walk reads a credential in
>   is labelled like a catalog file (§2.6; INI-family files and short
>   passwords, §2.9), and so is a text document it
>   recognises as a personal document, a statement, a payslip, a tax
>   return, a lab report, an identity document or household codes (§2.7),
>   in a PDF or an Office file as well (§2.8). Since 2026-10-21 the MCP
>   and editor config files too, each launch's agent keeping its own
>   readable so its MCP servers get their values (§2.10).
> - §3, the git-history scan: keys that live only in history, which no walk
>   can find, reported by `mandu doctor --secrets` and turned into suggested
>   locks by [`confidentiality-plan-14-policy-suggestions.md`](./confidentiality-plan-14-policy-suggestions.md)
>   (built 2026-09-30, with an incremental, sealed cache).
>
> The same detector, over the agents' own transcripts instead of git, is
> `mandu scan` (secrets that already reached a model; built 2026-10-21):
> [`confidentiality-plan-17-past-sessions-scan.md`](./confidentiality-plan-17-past-sessions-scan.md).
>
> Spine: [`confidentiality.md`](./confidentiality.md) (§6 the catalog, §7.2
> the twins, §7.2a the git object twins, §10.1 the documented gaps).
> Companions: [`protection-modes.md`](../architecture/protection-modes.md)
> (confidentiality is the default, which is what raises the stakes here) and
> [`rootless-confinement-ubuntu-2404.md`](./rootless-confinement-ubuntu-2404.md)
> (the posture a launch gets).

## 1. The launch-time walk on a real home

### 1.1 Why this matters

With confidentiality ON, every launch runs the secret walk against the user's
real HOME and workspace, then plans one twin per discovered file. The
confinement is fail-closed, so any surprise in that walk or plan is a
**refused launch**: the user's first experience is that Mandu does not
start, on a home directory nobody tested.

It happened once before this work: a walk followed a symlinked directory into
a kernel source tree, a `*credentials*` catalog shape matched a documentation
file, and the twin bind through the symlinked spelling failed:

```
bwrap: Can't mkdir parents for ~/tools/linux/Documentation/security/credentials.rst
```

Every launch on that machine refused (fixed in `confidentiality.md` §7.2
"Symlinks"; the shape also skips documentation pages since 2026-09-28,
`confidentiality.md` §6). No test saw it, because every suite ran either with
the axis OFF or against an empty synthetic HOME. The answer is cheap (no
model budget, seconds per case) and the failure it prevents is total.

### 1.2 What the walk and planner do

- `arbiter/policy/secret-discovery.ts`: a synchronous walk inside the
  arbiter; `lstat` decides the walk (symlinked directories are never
  descended); `SKIP_DIRS` prunes caches and toolchains; `MAX_DEPTH = 4` and
  `MAX_FILES = 256` bound it (a caller may raise the file cap,
  `DiscoveryOptions.maxFiles`, never lower it: only `mandu scan`'s own
  walk does, to 4096, as it binds nothing and must know every value; it
  also reads the catalog's stores and every agent's login by their places,
  confidentiality-plan-17-past-sessions-scan.md §3 item 5); the human labels' places are roots of their
  own with a budget of their own, `MAX_LABEL_FILES = 256` (§1.11); only
  readable regular files are returned;
  `AGENT_STORES` keeps every agent's own data unmasked in every launch, and
  `AGENT_LOGIN_FILES` keeps the logins THIS launch runs on unmasked (§1.10).
- `launcher/src/secret-setup.ts`: `discoverSecrets` (30 s deadline), then
  `registerSecret` per file (5 s each; the arbiter reads the bytes, the
  launcher only ever holds the symbol), then twin materialization. A file
  that is THIS launch's agent's own key file (`agentOwnFiles`: Goose's
  `secrets.yaml` under `mandu goose`, when the launch cannot bind its key to
  the provider it routes) is registered but not twinned, the launcher's
  form of the per-launch login rule (§1.10)
  ([`supported-agents.md`](../agents/supported-agents.md) §5.6.1). With the
  binding, the file is twinned and the model proxy puts the key back in the
  auth header ([`agent-sign-in.md`](../agents/agent-sign-in.md) §3).
- `launcher/src/secret-twins.ts`: the bind plan; `realpath` per file, one
  bind per real file, vanished files skipped loudly.

Two product gaps, separate from crashes, shaped the work:

1. **Silent truncation (gap 1).** A secret at depth 5, or the 257th match,
   would be left raw with no signal. Under a "your keys cannot leave"
   default, the user must be told what was NOT covered. Closed: §1.9 A.
   The signal must also mean something: a notice that fires on every
   launch is ignored. It counts only what could hold a user's secret (§1.9
   F): not the too-deep directories inside package caches
   (`PACKAGE_CACHE_DIRS`), not a socket or FIFO named like a secret, not a
   directory another root's walk reaches anyway. The dry run still lists
   the first two.
2. **No way to look before launching (gap 2).** Closed by
   `mandu doctor --secrets` (§1.3).

  On macOS (2026-09-29) the HOME walk also prunes HOME's `Library`,
  `.Trash`, `Pictures`, `Music` and `Movies` (`DARWIN_HOME_SKIP`), keeping
  the catalog's paths inside them and never hiding a labeled file
  (confidentiality.md §7.2, discovery cost). Measured 2026-09-29 on the
  development Mac, read-only (the walk alone: no arbiter, nothing
  registered; counts only): the real HOME is light (27 entries in
  `~/Library`, 226 to depth 4): 18 ms → 16 ms warm, the same 11 files, 16
  fewer `depth` records and 10 fewer `symlinked-directory` records, all of
  them inside `~/Library`. A synthetic used-Mac HOME in a scratch dir (300
  app containers, 100 group containers, 15k cache files, 3k app-support
  files, 3k media files: 24k entries): 1.0–1.7 s → 1 ms, the same files.
  Since 2026-09-30 plan 14's two other HOME walks apply the same prune
  through the same helper (`darwinHomeSkipDirs`, exposed as
  `discoveryPrunes(…).homeSkip`): the workspace scan's home tier and the
  known-repository walk (confidentiality-plan-14-policy-suggestions.md
  §13.1, §11.1 R1). The scan re-enters for nothing: a file a label covers
  is never opened by it wherever it lies, so the prune loses no key
  finding (it does lose plan 14's sensitivity labels and model candidates
  under `~/Library`, plan 14 §11.3).
  The repository walk re-enters by discovery's rule (`darwinPrune`): the
  registry's `label` source walks UP from a label to its work tree, so it
  reaches a labelled file's repository but never one below a labelled
  folder (`~/Library/Mobile Documents/com~apple~CloudDocs/`) or below a
  pattern's literal prefix, or any for a pattern with none (`**/*.pem`);
  for those the walk enters the folder.

### 1.3 `mandu doctor --secrets` (the dry run)

It runs discovery and the twin planner exactly as a launch would, but starts
no agent, registers nothing, and **enters no namespace**, so it works on
hosts where confinement is unavailable (`launcher/src/doctor-secrets.ts`).

- **Which arbiter.** A resident arbiter whose secrets axis is ON; else a
  THROWAWAY arbiter on a private socket, DB and event directory, from the
  layout's own daemon spec (checkout or bundle), stopped afterwards. A
  resident arbiter with the axis OFF is a WARNING (a launch attaching to it
  masks nothing), and the inventory still comes from a throwaway.
- **What it prints.** The posture a launch would get (the doctor's own probe,
  so it cannot promise what a launch will not do); per file the path as the
  user spells it, the resolved path when it differs, the level and the
  catalog rule that matched; the planner's own drops (`planSecretTwins` with
  the real `realpath`: two spellings bind once, a vanished file is skipped);
  the environment variable NAMES that would be masked (`envSecretNames`, a
  names-only arbiter op: no value crosses the socket; a note says a value
  holding a URL password or a key in a known format is masked at launch
  under any name, and that a listed `*_PWD` holding a directory stays raw,
  which a names-only list cannot show); the "not covered"
  ledger by reason, ✗ for the consequential ones and `·` for the expected
  ones; timings; the git-history section (§3, advisory, `--no-history`
  skips it); and the launch verdict, mirrored from the launch's own decision
  table (`onConfinementFailure`: a host gap refuses only under
  `require-confinement`, an arbiter that cannot answer refuses, a discovery
  error refuses).
- **Never a value.** No file contents and no original behind a symbol; the
  renderer is unit-tested on that.
- Exit 0 when a launch would succeed, 1 with the reason when it would refuse;
  `--json` for the dashboard and tests.
- `--target <agent>` asks the walk a launch of that agent asks: the logins
  it runs on stay raw, every other agent's is in the inventory (§1.10), or
  listed as left readable under `MANDU_OTHER_AGENT_LOGINS=raw`; `--no-mcp`
  with it is a launch with `--no-mcp` (no AI helper). Without it every
  agent's login is listed as left raw.

The `discoverSecrets` IPC op answers the whole structured report
(`DiscoverSecretsResultWire`: `files`, `skipped`, `counts`, `limits`,
`truncated`); older callers read `files`. Both `discoverSecrets` and
`registerSecret` carry the launch's `home` and view state base (§1.9 B, D).

### 1.4 Fixture homes

`tests/sandbox/launcher/launcher-fixture-homes.test.ts` launches the real
launcher (bwrap, no API budget) around `/bin/cat` reads, once per HOME shape,
plus the dry run under the same HOME, and asserts L1 (exit 0), L2 (every
spelling of every discovered secret reads back as a twin), L3 (what is left
raw is REPORTED and reads raw), L4 (`doctor --secrets --json` agrees: same
files, same ledger, same verdict; the dry run never says "would succeed" for
a home the launcher refuses, or the reverse). The per-push CI runs it as
three shards (`MANDU_FIXTURE_SHARD=k/n`); unset, one run takes every shape.
`launcher-real-home.test.ts` is the one-home smoke beside it.

| Shape | Expected |
| --- | --- |
| broken symlink named like a secret (`~/.aws/credentials → /nonexistent`) | skipped loudly, launch succeeds |
| symlink loop (`a → b → a`), directory and file variants | no hang, no crash |
| secret symlinked to an unreadable target (`→ /etc/shadow`) | not masked, launch succeeds |
| unreadable directory (`chmod 000`) on the walk path | skipped, launch succeeds |
| secret file with mode 0400 / 0600 / owned-by-other-but-readable | masked |
| two spellings of one real file (hard link; symlink chain of length 3) | one bind per real file, all spellings masked |
| path with spaces, newline, leading dash, non-UTF-8 bytes, very long name | bind argv survives; masked |
| secret inside the workspace AND under HOME (overlapping roots) | deduplicated |
| workspace that is itself a symlink, or lives under a symlinked parent | masked under the path the agent uses |
| secret on a different filesystem (tmpfs, bind mount) | masked or skipped loudly; never a refusal |
| FIFO, socket or device node matching a catalog shape | ignored (regular files only); listed as `special-file`, never the launch WARNING (§1.9 F) |
| package caches below the depth cap (`~/.cargo/registry/src/…`, `~/go/pkg/mod/…`) beside an ssh-agent socket and a key | listed as `package-cache` / `special-file`, no launch WARNING; the key masked (§1.9 F) |
| caches moved by `CARGO_HOME` / `GOMODCACHE` (under HOME, below the depth cap) beside a key | listed as `package-cache`, no launch WARNING; the key masked (§1.9 G) |
| a launch from HOME itself (the workspace IS HOME) with one depth-5 folder | walked once: the folder reported once by the WARNING and the dry run (§1.9 G) |
| file that vanishes between discovery and bind | skipped loudly, launch succeeds |
| file that APPEARS after discovery | documented gap (`confidentiality.md` §10.1), asserted raw so the doc stays honest |
| 300 catalog matches | `MAX_FILES` truncation is REPORTED, launch succeeds |
| secret at depth 5 | depth truncation is REPORTED |
| huge tree (50k entries) beside the secrets | walk stays under the discovery deadline |
| empty HOME; HOME unset; HOME not writable | launch succeeds with zero twins, or refuses with an actionable line |
| the agents' logins present (`~/.claude.json`, `~/.codex/auth.json`) under `--target claude` | the launched agent's never masked, agent still starts; the other agent's twinned (§1.10) |
| `.env` files at several depths in the workspace | per catalog, asserted |
| the view state base DEEP under HOME, or the default `~/.mandu` with a stale workspace beside this one | the state dir pruned (`mandu-state`) and hidden from the agent whole; nothing in it reads back |

Every case is mirrored at the unit level against the pure planner
(`planSecretTwins`) and `discoverSecretFiles`, which need no privilege and so
run on every CI tier, containers without a user namespace included.

**Mode.** The table and the real-home smoke run their private arbiter in
`secrets`, the built-in default, under a throwaway HOME (they never touch the
developer's), and each launch asserts the fs rung off by mode. In `secrets`
there is no AgentView worktree, so a view state base under HOME is pruned and
hidden whole (`ownStoresHidden` in `secret-setup.ts`), asserted with a raw
canary planted in a shadow-repository directory and a stale workspace's copy;
the agents (claude and codex targets) run in the workspace the human trusted,
no twin is created, and neither agent's config is rewritten. The integrity
forms of these rows (AgentView copies reached through the view map, the twin
inheriting the agents' workspace trust) live in the frozen lane
(`tests/integrity/`, `protection-modes.md §10` §7).

### 1.6 Non-goals

- Changing WHAT counts as a secret beyond fixes the runs motivated: the
  catalog's scope is `confidentiality.md` §6 (and §2 below).
- Post-launch secrets and unregistered files: the documented §10.1 gap of
  `confidentiality.md`; the dry run only makes it visible.
- macOS (`confidentiality.md` §7.3): the fixture builders are written so a
  Seatbelt variant can reuse them.

### 1.7 Tests

- Unit: the structured discovery result and its ledger
  (`arbiter/test/unit/secret-discovery.test.ts`), the planner cases of §1.4,
  the `doctor --secrets` renderer with no raw bytes in its output
  (`launcher/test/unit/doctor-secrets.test.ts`), the launch WARNING
  (`secret-setup.test.ts`).
- E2E: the fixture table (§1.4); `discover-secrets-view-map.test.ts` over a
  real `ArbiterServer` and `ArbiterClient` (the wire carries `stateBase`;
  absent, the default applies); `install-sh.test.ts` (§1.9 E).

### 1.9 As built

**A. The structured report and the launch WARNING.**
`discoverSecretsReport(roots, home, labels)` returns `{ files, skipped,
counts, limits, truncated }`; `discoverSecretFiles` is its files-only view.
Every place the walk declines a candidate has a `SkipReason`: `agent-auth`,
`agent-login` (§1.10), `symlinked-directory`, `dangling-symlink`, `unreadable`, `depth`, `count`,
`unreadable-dir`, `mandu-state`, `agentview-symbolized`, `mandu-install`,
`package-cache`, `special-file` (F).
`counts` is complete; `skipped` is capped at 200 records with the
consequential reasons first. Past the file cap the rest of the current
directory is still classified (one `readdir`'s worth), so a match the cap
leaves raw is named `count`; directories not yet visited are not entered,
which `truncated` reports. The launcher's `applySecretTwins` prints the
consequential skips (depth, count, unreadable, truncation) on every launch as
one WARNING block (`notCoveredNotice`) ending in `mandu doctor --secrets`;
dangling links, directory links and the agent's own auth stay quiet there.

**B. Bugs the fixture table found, fixed.**

1. A symlink loop refused every launch: `statSync(…, { throwIfNoEntry })`
   covers ENOENT only, so `a → b → a` threw ELOOP out of the walk and the
   launch refused fail-closed. A loop is now a dangling link.
2. The catalog's `~/…` rules resolved against the ARBITER's HOME. A resident
   arbiter's `homedir()` may differ from the session's (a fixture home, a
   launch with HOME overridden), so a home with three keys reported "0
   credential files masked". `discoverSecrets` and `registerSecret` now carry
   the launch's `home`.
3. Matches past the file cap were unnamed (found by the report's own unit
   test); now classified as above.

**C. A real home.** On a developer's HOME the dry run listed 161 files in
1.0 s with no consequential skips, but most of them were Mandu's own
AgentView copies under `~/.mandu`, found only because of where the depth cap
happened to fall. That led to D.

**D. Mandu's own state is pruned; AgentView copies come through the view
map** (`agentViewRoots`, `DiscoveryOptions.stateBase`; the op, the launcher's
adapter and the dry run carry the launch's view state base, the home's
`state/` from the path table, on-disk-layout.md §5). The default base put
every workspace's AgentView root exactly at `MAX_DEPTH`: nested copies were
never reached, a base one level deeper would have reached none, and the
shadow repositories filled the ledger with thousands of `depth` records (the
launch WARNING fired on every launch). The copies themselves are fs-sync's
own mask, so registering them minted secrets over tokens. The walk now:

- **prunes** the launch's state base and the conventional `~/.mandu` (one
  `mandu-state` record each, no descent). The arbiter's DB and the shadow
  repositories hold no catalog shape.
- **walks the AgentView worktrees of the workspace roots as roots of their
  own** (depth 0, same caps), found THROUGH the view map fs-sync persists:
  every `<stateBase>/workspaces/<id>/workspace.json` whose `workspacePath`
  is a root or an ancestor of one names `<id>/agentview`. Malformed or
  relative metadata, a missing or symlinked `agentview`, an unreadable base
  are ignored, never an error. A copy whose whole content is symbols is
  skipped as `agentview-symbolized`; anything else in it (a human-edited
  twin with a raw line, a file fs-sync could not symbolize, a copy over
  1 MiB) is discovered like its HumanView original. The content check reads
  the file; the report never carries it.
- Neither reason is consequential: the WARNING stays quiet, the dry run
  lists them with a `·`.

After D the same home listed 24 files, all real, none under `~/.mandu`. One
cost: the `depth` ledger reports a too-deep directory in both spellings when
the workspace has an AgentView mirror. Not in scope: the shadow repository's
objects hold the HumanView's raw bytes of tracked files, which a program the
agent runs could read with `git show`; that is a state-directory question for
the exec and FS chokepoints (the shadow repository,
[`fs-sync.md`](../integrity/fs-sync.md) §3; stated to users in
`guarantees.md` §3).

**E. Mandu's own install is pruned too (2026-09-26).** A fresh install of the
release tarball into an empty HOME printed "secrets NOT covered by the walk"
on every launch, naming `~/.local/share/mandu/pkg/bin` and `pkg/lib`: the
installer's default prefix puts the npm prefix `pkg/` exactly at `MAX_DEPTH`
(and a downloaded Node at `~/.local/share/mandu/node/` likewise). The walk now
prunes Mandu's own install trees under a quiet reason, `mandu-install`
(`manduInstallTrees`), VERIFIED on disk and matched by REALPATH, never by
name:

- the running package's root, when the arbiter runs from an installed
  `…/node_modules/@mandusec/mandu` (a repository checkout is never pruned);
- for each installer prefix candidate (the path table's `install-prefix`,
  `MANDU_PREFIX` when set, its default, and the prefix the running package
  sits in, which covers a custom `--prefix`): `<prefix>/pkg` only when it is
  a real directory holding the `@mandusec/mandu` package, then
  `<prefix>/node` only beside that verified `pkg` and only with the
  nodejs.org layout (`bin/node` + `include/node/node_version.h`).

It cannot hide a real secret: the prefix itself is still walked (a stray
`~/.local/share/mandu/.env` is found), an impostor `pkg` without the package
is walked, a same-named tree elsewhere is walked, a `pkg` symlink names
nothing, and relative candidates are ignored. Pinned by arbiter unit tests
(the prune, the look-alikes, realpath through a symlinked HOME, the
running-package derivation), a doctor test, and an e2e over the real
installed artifact (`install-sh.test.ts`: the installed `mandu doctor
--secrets --json` answers from its own throwaway arbiter, no `depth` record
under the install, `~/.aws/credentials` still found; with the prune disabled
it fails on exactly `pkg/bin, pkg/lib`).

**F. The notice counts what could hold a user's secret (2026-10-04).** On a
developer's home the compact launch line read `mandu: ! 487 places were not
searched for secrets` on every launch, and meant nothing: nearly all of it
was `~/.cargo/registry/src/<index>/<crate>/…` (each crate's subdirectories
sit at depth 5), the ssh-agent's sockets under `~/.ssh/agent/` (a catalog
match, `~/.ssh/*`, that is not a regular file, so it was an "unreadable
candidate"), and, when the launch ran from a project under HOME, the
project's own subdirectories that the HOME walk found too deep although the
workspace root's walk visits them. Three changes to the LEDGER; the walk
(what is visited, discovered, twinned) is unchanged:

- **`package-cache`** (quiet): a directory below `MAX_DEPTH` strictly inside
  one of `PACKAGE_CACHE_DIRS` (`secret-discovery.ts`, the one list):
  `~/.cargo/registry`, `~/.cargo/git`, `~/go/pkg/mod`, the pnpm stores
  (`~/.local/share/pnpm/store`, `~/.pnpm-store`), `~/.yarn/berry/cache`,
  `~/.bun/install/cache`, `~/.m2/repository`, `~/.gradle/caches`,
  `~/.gradle/wrapper/dists`, `~/.nuget/packages`, the RubyGems user trees
  (`~/.gem/ruby`, `~/.local/share/gem/ruby`), pip's user site
  (`~/.local/lib/python*/site-packages`, `*` within one segment),
  `~/.pyenv/versions`, the VS Code and Cursor extension folders, and
  `~/.local/share/opentui`, where OpenCode's terminal UI library unpacks its
  tree-sitter grammars and queries at depth 5 (added 2026-10-11: every
  OpenCode launch after its first said "2 places were not searched for
  secrets"). Each is filled by a package manager or a program with
  downloaded or installed third-party code. The credential files those tools read sit outside them and stay
  ordinary walk targets (`~/.cargo/credentials.toml`, `~/.m2/settings.xml`,
  `~/.gradle/gradle.properties`, `~/.gem/credentials`, `~/.npmrc`); the
  caches themselves are still walked to the cap. `~/.npm` and everything
  under `~/.cache` (pip, yarn v1) are already pruned by `SKIP_DIRS`, so no
  record arises there. These are the HOME-relative defaults; a cache moved
  by `CARGO_HOME`, `GOMODCACHE` and the like is G.
- **`special-file`** (quiet): a catalog match that is a socket, FIFO or
  device (judged by `lstat`, so never a link). It holds no file to mask. An
  unreadable REGULAR file is still the consequential `unreadable`.
- **No record for a directory another root reaches**: when the HOME walk
  finds `~/proj/a/b/c/d` too deep (depth 5) and `~/proj` is also a root,
  that root's walk visits it at depth 4, so it is not a miss. A directory
  too deep for every directory root still is `depth`. This is sound because
  every prune is by basename or by absolute path, the same in both walks,
  and the HOME walk reached the directory through real directories only.

`notCoveredNotice` (and so `compactNotice`) still counts only `depth`,
`count`, `unreadable` and truncation. `mandu doctor --secrets` lists the two
new reasons as `·` lines ("directories below depth 4 inside package caches
not searched (skipped package caches: …)", "sockets, pipes or devices named
like secrets"), so nothing is dropped from view. A second development
host, measured with a workspace under HOME, went from 492 counted places
(490 `depth`, 2 `unreadable` ssh-agent sockets) to 469 `depth` (21
`package-cache`, 2 `special-file`); with a smaller project as the
workspace, 467 to 440 (the overlap rule took 4 more). What remains there is
the user's own trees deeper than four levels (other repository checkouts,
shell plugin folders), which could hold a secret and stay in the notice.
Pinned by arbiter unit
tests (the classification, the overlap, sockets and FIFOs beside an
unreadable key), the wire test in `discover-secrets-view-map.test.ts`, the
launcher's renderer and notice tests, and two fixture-home rows (§1.4).

**G. Each root walked once; moved caches are caches (2026-10-09).** Two
more ways the launch notice counted places twice or wrongly (launch speed
J's agent-ready parts). Again the LEDGER and the walk's repetition change,
never what is discovered:

- **Roots deduplicated.** A launch from HOME itself sends the roots
  `[home, home]` (`run.ts` prefetches `[homedir(), launchDir]`), and each
  was walked in full: every count and record doubled, and the walk took
  twice as long. `discoverSecretsReport` now normalizes the roots (`~`, a
  trailing `/`, `..`) and walks each once. A directory root INSIDE another
  (the workspace under HOME) is no longer entered by the outer walk: its own
  root walks it from depth 0, which reaches everything the outer walk would
  and deeper, so its subtree is walked once and its records (a dangling
  link, a symlinked directory, an unreadable key) are counted once. The
  overlap rule of F stays as a backstop.
- **Moved package caches.** `CARGO_HOME=/data/cargo` puts Cargo's registry
  where `PACKAGE_CACHE_DIRS` (HOME-relative) never matches, so its crate
  folders were counted as `depth`. The arbiter is shared by every launch and
  cannot read the session's environment, so the launcher sends the launch's
  values of the variables that move a cache, and ONLY those
  (`discoverSecrets.cacheEnv`; the rest of the environment can hold keys):
  `CARGO_HOME` (its `registry`, `git`), `GOMODCACHE`, `GOPATH` (each
  entry's `pkg/mod`), `GRADLE_USER_HOME` (its `caches`, `wrapper/dists`),
  and the moved forms of the `SKIP_DIRS` caches: `RUSTUP_HOME`, `NVM_DIR`,
  `npm_config_cache` / `NPM_CONFIG_CACHE`, `XDG_CACHE_HOME`,
  `PIP_CACHE_DIR`, `YARN_CACHE_FOLDER` (`RELOCATED_PACKAGE_CACHES` in
  `secret-discovery.ts`; the launcher's copy of the name list is pinned by
  `tests/stack/package-cache-env-parity.test.ts`). The arbiter drops any
  other name on the wire. A moved cache is treated like a
  `PACKAGE_CACHE_DIRS` tree, NOT like a `SKIP_DIRS` prune, even when its
  default is pruned whole: it is still walked to the cap (a catalog match in
  it is still masked), only its folders below the cap are the quiet
  `package-cache`. Pruning a moved tree whole would make the walk's coverage
  depend on the session's environment; recording it differently changes
  only the count. A value that is not absolute, or that is HOME, a walk
  root, or an ancestor of either, is ignored (`GOMODCACHE=$HOME` must not
  quiet HOME). `mandu doctor --secrets` sends the same values, so the dry
  run agrees with the launch.

Left open, a separate decision: the deep folders in the user's own
repository checkouts under HOME (`~/project/*`, `.claude/worktrees`) still
count; they could hold a secret, and quieting them needs a rule (H makes
the notice say where they are instead). Pinned by
arbiter unit tests (the spellings of one root, a nested root's records, the
moved trees and their guards, the wire filter), the wire test in
`discover-secrets-view-map.test.ts` (`[home, home]`, `cacheEnv` through the
production client, junk on a raw line), the launcher's unit tests (the
variables sent and nothing else, the prefetch key, the dry run), the parity
test, and two fixture-home rows (§1.4).

**H. The notice says where the deep folders are (2026-10-11).** Walking
the first-session tour on a developer's home, every launch said `mandu: !
445 places were not searched for secrets`. Measured read-only on that home
(the walk alone, roots HOME and the tour folder, the record cap lifted in
a scratch copy): 447 `depth` records. 418 were the user's own repository
checkouts under `~/project` (three checkouts held 414, agent worktrees in
`.claude/worktrees/<name>` included), 21 oh-my-zsh plugins (15 under
`~/.oh-my-zsh/plugins`, 6 under a custom folder of the user's own
naming), two under `~/.local/share` (a CI runner's work tree, a
hand-installed Ollama), and one each in the RustSec advisory database
(`~/.cargo/advisory-db`), Ollama's models
(`~/.ollama/models/manifests/…`), TeX Live's per-user caches
(`~/.texlive2025/texmf-var/luatex-cache/…`), VS Code's user data
(`~/.config/Code`), glab's config (`~/.config/glab-cli`) and a project
outside `~/project`. No cap was counted wrongly: each is one directory at
depth 5 that no root reaches. Two changes, the walk itself unchanged:

- **More package caches** (`PACKAGE_CACHE_DIRS`): `~/.oh-my-zsh/plugins`
  and `~/.oh-my-zsh/custom/plugins` (plugins oh-my-zsh ships or clones;
  the user's own `custom/*.zsh` sit above the cap and are walked, and a
  custom folder elsewhere still counts), `~/.cargo/advisory-db`,
  `~/.ollama/models` and `~/.texlive*/texmf-var` (each filled by a tool
  with downloaded or generated data; Ollama's key and TeX Live's
  `texmf-config` lie outside them). On that home: 447 to 429 `depth`.
  VS Code's and glab's folders stay counted: they hold the user's tokens.
- **Grouped by folder.** What remains is the user's own trees, which could
  hold a secret, so it stays in the notice, which now says where: the
  report carries `depthAreas`, every `depth` record (not the capped
  `skipped` list) counted under its folder two levels below its walk root
  (`~/project/app`; the deepest directory root holding it, so a workspace
  record is grouped under the workspace), the most first, at most 20. The
  launch WARNING's line reads (the checkouts renamed here) `429
  directories below depth 4 not searched, in ~/project/app (216),
  ~/project/app-old (107), ~/project/lib (91) and 15 more elsewhere`, and
  the compact line
  `mandu: ! 429 places were not searched for secrets: folders more than 4
  levels deep, in … and 15 more elsewhere; see \`mandu doctor --secrets\``
  (beside other misses: `N places …, M of them folders more than 4 levels
  deep, in …`). `mandu doctor --secrets` adds a `by folder:` line naming up
  to ten. An older arbiter sends no areas, and the line keeps its first
  paths, as before.

Pinned by arbiter unit tests (the new caches and their look-alikes, the
areas over more records than the cap, the root a record is grouped under),
the launcher's notice and dry-run tests, and the fixture-home rows (§1.4),
whose deep folder now reads `in ~/a/b (1)`.

### 1.10 The agents' logins, per launch (2026-10-09)

**The gap.** One global list (`AGENT_AUTH_EXCLUDE`) kept every supported
agent's credentials out of the walk, whatever was launched. It existed so
the LAUNCHED runtime could read its own login (plan decision 3); its global
scope was never analyzed. So under `mandu claude`, `~/.codex/auth.json` (an
OpenAI key or ChatGPT tokens) was neither twinned nor registered: a program
the agent ran read it raw, the AI saw it masked only when a command named
the path (`jq . $HOME/.codex/auth.json` classified public), and neither the
value backstop nor the egress tripwire knew the value. Under `mandu codex`
the same held for Claude Code's subscription login and `~/.claude.json`
(which also holds MCP servers' tokens). `mandu why` called these files
placeholder copies, `doctor --secrets` called them "the agent's own login",
and `guarantees.md` listed `~/.codex` among what Mandu masks. A policy.yaml
label could not reach them either: the exclusion ran before the label.

**The split.** `arbiter/policy/secret-discovery.ts` has two lists.
`AGENT_STORES` (each agent's own data: `~/.claude`, `~/.codex`, OpenCode's
and Goose's data and state directories, and the OpenCode / Goose data
shapes) stays out of every launch, before labels, as before: the agent
reads and writes it raw, the catalog's path mask covers a command naming
it, and twinning another agent's transcripts would add nothing while using
up `MAX_FILES`. `AGENT_LOGIN_FILES` is keyed by agent:

| agent | login files |
|---|---|
| claude | `~/.claude/.credentials.json`, `~/.claude.json`, `~/.anthropic`; with `CLAUDE_CONFIG_DIR`, its `.credentials.json` and `.claude.json` too |
| codex | `~/.codex/auth.json`, `~/.openai`; with `CODEX_HOME`, its `auth.json` too |
| opencode | `~/.local/share/opencode/auth.json`; with `XDG_DATA_HOME`, its `opencode/auth.json` too |

Goose's `secrets.yaml` keeps its launcher keying (`agentOwnCredentialFiles`,
`supported-agents.md` §5.6.1). The login files inside a store are judged on
their own: the walk records the store (`agent-auth`) and visits each login
path inside it. One exception to "the launched agent's login stays raw"
(2026-10-11): under `mandu codex` on Linux, an `auth.json` holding a saved
key (no ChatGPT tokens) is twinned anyway when the launch grants its key to
the openai-proxy's upstream, which puts the key back in the auth header
(`grantedLoginFiles`, [`agent-sign-in.md`](../agents/agent-sign-in.md) §3.9).

**Which logins stay raw** (`keptLoginOwners(target, ullmBinary)`): the
launched agent's, and the AI helper's when it runs an agent's CLI in the
agent's world (`inspect-mcp` and OpenClaw's plugin in CLI mode: `codex exec`
under codex, `claude -p` under every other target, `launcher/src/parse.ts`
`ullmCliBinary`; none in API mode, that is with `ANTHROPIC_API_KEY` or
`MANDU_ULLM_API_KEY` set, or under `--no-mcp`). A `shell` target keeps
Claude Code's whatever the helper does: its routing is Claude Code's
(`ANTHROPIC_BASE_URL`), so a `claude` started inside it is protected and
must log in. An `openclaw` target keeps Claude Code's AND Codex's: OpenClaw
reads both itself (its `claude-cli` and `codex-cli` auth profiles read
`~/.claude/.credentials.json` and `$CODEX_HOME/auth.json`, and its Codex
app-server harness, which it defaults to for OpenAI's own endpoint, reads
`~/.codex/auth.json`; found in review of OpenClaw 2026.7.1-2). A kept login
is skipped before labels (`agent-login`, a quiet reason) and that launch
does not register it (one exception since 2026-10-21, §2.10: a kept
`.claude.json` whose MCP servers hold a credential is listed again by the
walk's MCP pass, tagged `agentConfig`, registered and left readable). Every other agent's login goes on through the walk
like any file: the user's label decides, else the catalog (`SENSITIVE_PATHS`
already labels the default places `no-model`), else, for a login a variable
moved out of the catalog's places, `no-model` under the rule
`agent-login:<agent>` (`agentLoginConfidentiality`). So it is registered
and twinned (a structured JSON twin keeps its keys), and the report tags it
`agentLogin: <agent>`. The resulting matrix:

| launch | raw (kept) | twinned and registered |
|---|---|---|
| `mandu claude` | Claude Code's | Codex's, OpenCode's |
| `mandu codex` | Codex's | Claude Code's, OpenCode's |
| `mandu openclaw` | Claude Code's, Codex's | OpenCode's |
| `mandu opencode` | OpenCode's, and Claude Code's while the helper runs `claude` | Codex's, and Claude Code's in the helper's API mode or under `--no-mcp` |
| `mandu goose` | Claude Code's while the helper runs `claude` | Codex's, OpenCode's, and Claude Code's in API mode or under `--no-mcp` |
| a plain command (`shell`) | Claude Code's | Codex's, OpenCode's |

In words, the one phrasing `mandu why`, `doctor --secrets` and the user
docs use (`launcher/src/agent-login.ts` `loginKeptWhere`): Claude Code's
login stays raw under `mandu claude`, a plain command and `mandu openclaw`,
and under `mandu goose` or `mandu opencode` while Mandu's AI helper runs
`claude` (neither `ANTHROPIC_API_KEY` nor `MANDU_ULLM_API_KEY` set, and no
`--no-mcp`); Codex's under `mandu codex` and `mandu openclaw`; OpenCode's
under `mandu opencode`.

**In the session that runs the agent** (2026-10-10). Registration is
global and durable: a launch that does not run an agent registers that
agent's login, and the values stay in the arbiter's symbol table after that
launch ends, for every session sharing the arbiter. A kept login is
therefore NOT unregistered in a later or concurrent session of its own
agent, and the value-based gate that refuses requests, the §4 egress
tripwire in the net-proxy (`egressFingerprintScan`, which scans the URL,
headers and body of every request the proxy reads; only the model vendors'
API hosts bypass it), would refuse that agent its own login: Codex's
ChatGPT bearer to `chatgpt.com` and its token refresh to `auth.openai.com`
under a `mandu codex` after a `mandu claude`, Claude Code's OAuth refresh
and the MCP servers' bearers from `~/.claude.json` under a `mandu claude`
after a `mandu codex` (found in review, reproduced through the real
arbiter and secret setup). So each session tells its own net-proxy which
logins it leaves raw: the launcher computes `sessionLogins(plan, env, HOME)`
(`agent-login.ts`: the walk's keying, every agent's under the opt-out below,
HOME and the `LOGIN_ENV` values) and hands it to the net-proxy in
`MANDU_NET_PROXY_SESSION_LOGINS`
(`interceptors/net-proxy/src/session-logins.ts`); the proxy sends it with
every tripwire scan (`sessionLogins`); the arbiter turns it into login-file paths only
(`sessionLoginPaths`: the kept owners' `agentLoginPaths`, plus their real
paths) and leaves out of THAT scan the registered-file rows
(`isRegisteredFileRow`: the file's base row and its fields) whose origin is
one of those paths (`originUnder`). Bounded by construction: a session can
exempt only agents' login files, never another path, and only from its own
scans; a scan that names no session or a malformed value exempts nothing,
and another HOME exempts only that HOME's logins, so the tripwire is as
strict as before. In the owning
session this is exactly the state before any launch registered the file
(no tripwire on those values), so no session is weaker than it was. The
proxy publishes the value in its identity, and a launch adopts a running
net-proxy (a pinned `net-proxy-port`) only when it carries the same logins
(`netProxyIdentityMatches`): a proxy started for a launch of another agent
is refused, fail-closed, as one with another deny list is.

The model-side gates stay as they are in every session: the value backstop
on tool results (`scanSecretValues`, the classify-time raise), the prompt
filter and the upload gate SYMBOLIZE (or hold) a registered value in what
the MODEL sees or a model tool sends; they never refuse the agent runtime's
own requests (its login is read from disk, its model call carries the
token in a header no gate scans, its refresh and MCP connections go through
the net-proxy). Leaving them active means a kept login's values that reach
the model through a tool's output (`claude mcp get`, a debug log) are a
placeholder there, as the invariant asks of a registered credential; making
them inert would only let those values reach the model raw. Rows minted
from a tool's result (a `Read` the model made of the file, with a call id)
are not exempt either: they predate this change and stay as strict.

**The wire.** `discoverSecrets` takes `target`, `ullmBinary` and
`loginEnv` (`CLAUDE_CONFIG_DIR`, `CODEX_HOME`, `XDG_DATA_HOME`: absolute
paths only, every other name dropped, `pickLoginEnv`; the launcher's copy of
the list, `LOGIN_ENV` in `agent-login.ts`, is pinned by
`tests/stack/login-env-parity.test.ts`). The launcher sends them from
`launchLoginKeying(plan)` (`agent-login.ts`) in both run.ts's prefetch and
the secret setup, and the prefetch key includes them. `registerSecret`
takes the same `loginEnv` for a file the walk tagged `agentLogin`, so a
moved login registers with the walk's verdict instead of being refused as
"not a secret path"; `whyPath` takes it too. `egressFingerprintScan` takes
`sessionLogins` (above). A caller that names no target (an older launcher,
`mandu doctor --secrets` without `--target`) gets every agent's login kept
raw: version skew fails toward the old behavior rather than bricking an
agent.

**Moved logins.** A login a variable moved (`CODEX_HOME=~/.config/codex`,
`CLAUDE_CONFIG_DIR=~/.claude-work`, a `CODEX_HOME` outside HOME) is kept
raw for its own agent and, under every other agent, is visited by its own
path (under no walked root, or below the depth cap, all the same) and
judged `no-model` (`agent-login:<agent>`) unless a label says otherwise: it
is twinned and registered like the default place. Only the variables the
LAUNCH's environment sets count; `mandu why` names the file a login when
the user's environment sets them.

**The opt-out.** `MANDU_OTHER_AGENT_LOGINS=raw` (config
`other-agent-logins = "raw"`): another agent's login is registered (masked
in what reaches the model) but left readable, the `agentOwnFiles` posture,
and the session's net-proxy treats every agent's login as kept
(`sessionLogins.otherLoginsRaw`), so that agent started inside the session
(a Codex MCP server under Claude Code, `codex exec` from a Claude Code
session, a `claude` under `mandu codex`) logs in and uses its token with
its own services: a nested ChatGPT-mode Codex refreshes at
`auth.openai.com` and calls `chatgpt.com`. In that session those values
are as unchecked on the network as before this change (the posture the
opt-out asks for); other sessions still trip on them. Any other value is
the default and a value that is neither `raw` nor `twin` is said. By
default the launch names the twinned logins in one line; a nested agent of
another kind reads a placeholder and fails to log in (it is not routed
through Mandu anyway: the shell target's launch note says so for codex,
openclaw and opencode).

**Reporting.** `whyPath` answers `agentFile: {kind, agent}`
(`agentFileOf`) and a moved login's `agent-login` verdict, and `mandu why`
says a store is left raw in every session (only a command that names the
path is masked for the AI, its values are not registered) and a login is
left raw only in a session that runs that agent (`loginKeptWhere`), a
credential like any other elsewhere, with the opt-out. `mandu doctor
--secrets` lists stores and kept logins as two groups, and takes `--target
<agent>` (with `--no-mcp`, as on a launch) to be the walk of that agent's
launch (the fixture table and `other-agent-logins.test.ts` compare them);
under the opt-out, another agent's login is listed as left readable, not
among the masked files. Both name the agents the same way
(`agentDisplayName`).

**Not changed.** The environment's equivalent (`OPENAI_API_KEY` stays raw
under `mandu claude`, `secret-extract.ts` `AGENT_CREDENTIAL_NAMES_RE`) is
still global: an open question for the maintainer. A Windows profile's
agent logins are not probed (WSL, `windowsProfileSecretRoots`). Goose's own
key file under `mandu goose` without a key grant (`agentOwnFiles`) is
registered and is not in the session's kept logins: its tripwire posture is
unchanged by this section.

Pinned by `arbiter/test/unit/agent-login-discovery.test.ts` (the matrix
with OpenClaw, the stores, the file cap, the labels, the moved logins under
no root and with no label, `registerSecret` with `loginEnv`, the session's
kept paths, derived paths and file roots), the arbiter's `why` component
test, the net-proxy's `session-logins` unit test and tripwire component
test (the value rides every scan and the identity), the launcher's unit
tests (`launchLoginKeying`, `sessionLogins`, the identity match, the
opt-out, the options sent, the launch note, the doctor's groups,
`--target`, `--no-mcp` and opt-out rows, `mandu why`'s lines), the stack
tests `tests/stack/other-agent-logins.test.ts` (the real arbiter: twin
content, the tripwire per session, the opt-out, a moved `CODEX_HOME`),
`tests/stack/own-login-net-proxy.test.ts` (the REAL net-proxy the launcher
starts, per session, after the other launch registered each login: the
owning session's refresh, bearer and MCP token reach their hosts, the
other session's are refused; fails without the session's logins) and
`tests/stack/why-cli.test.ts` (`mandu why` on a store, a login and a moved
login over the production call path), the sandbox test
`tests/sandbox/launcher/other-agent-logins.test.ts` (the real launcher: a
shell launch and a codex launch, each also sending Codex's token through
its session's proxy: refused in the shell launch, let through in the codex
launch) and the fixture-home row (§1.4).

### 1.11 The label roots (2026-10-17)

**The gap.** The walk reached a labelled file only from HOME and the
workspace: a folder the human labelled outside both, deeper than
`MAX_DEPTH` from them, or past `MAX_FILES` was never registered, and
neither was a file under a label set while the session ran. Its values were
unknown to the value backstop, so a program that printed them without
naming the file (`grep -r password .`, `tar cf - .`, `os.walk`, a read from
a shell already inside the folder; confidentiality.md §6, "Read by a
program the launch did not see") sent them to the model in clear.

**The decision.**

- Each human label above `public` is a root of its own
  (`labelWalkRoots`, label-lookup.ts): a literal label's path, a pattern's
  literal directory prefix; never `/` (a pattern with no literal prefix
  matches anywhere, and walking the filesystem is no bounded walk: the
  guard gates such files at the open, confidentiality.md §6). The
  arbiter adds them to every `discoverSecrets` job (`labelRoots`).
- The label pass runs LAST, from each root's own top (depth 0, `MAX_DEPTH`
  below it), under its own budget `MAX_LABEL_FILES = 256`: a HOME full of
  catalog matches cannot crowd a labelled folder out, and a big labelled
  folder cannot crowd `~/.ssh` out. A labelled folder inside HOME or the
  workspace is walked by itself only (the outer walk does not enter it,
  as for a workspace under HOME, §1.9 G). What the pass finds is judged as
  everything else is: a pattern's prefix is only where to look.
- A label root spelled through a symlink is not walked (`symlinked-directory`):
  a bind over a path with a symlinked parent bricks the launch (§1.9).
- A label added or raised mid-session (a dashboard act, a policy.yaml edit)
  makes the arbiter walk its root the same way (`syncLabelRegistrations`,
  on the discovery thread, triggered when the composed human label set
  changes) and register each file it finds as the guard's raw-read report
  does (`registerReadFile`). So the value backstop knows those values in
  every posture, the guardless ones included (`gated`, `--no-net-guard`,
  macOS). A lowered or removed label registers nothing (a known secret
  stays known). The labels in force when the arbiter starts are the
  launches' to walk.

**What stays open.** A file created under a label after the launch's walk
(and after any label act) is registered only when the guard gates its open
(confidentiality.md §6); a label root through a symlink and a pattern with
no literal prefix are found only where HOME's or the workspace's walk
reaches them.

Tests: `arbiter/test/unit/label-walk-roots.test.ts` (outside the roots,
below the depth cap, past the file cap, the label budget, a pattern, a
labelled file, a symlinked root), `arbiter/test/component/label-set-registers.test.ts`
(the op's report; a dashboard label and a policy.yaml pattern registered
mid-session; `public` and the axis OFF register nothing) and
`tests/stack/labelled-recursive-read.test.ts` (the thirteen reads through
the real proxy, masked; red with the label act's registration off).

### 1.12 The catalog at the open (2026-10-17)

**The gap.** The walk is the only thing that registers a CATALOG file: a
`.env`, a key or a credentials file created after the launch, deeper than
`MAX_DEPTH` (a monorepo's `services/api/config/env/.env`), past
`MAX_FILES`, or outside HOME and the workspace (another project under
`/srv`, a `/tmp` checkout) was known to nothing, so any program the agent
ran read it raw and a print that did not name its path (`grep -r`, `rg`,
`tar`, a script) reached the model in clear (confidentiality.md §6, "A
catalog file the launch did not register"). Raising the caps would not
close it: a file created mid-session is never walked.

**The rule the walk applies, and the gate copies.** The walk decides by
PATH alone (`pathConfidentiality`: a label, then the catalog's prefixes and
basename shapes): it never reads a file's content to decide (the one read
is the AgentView copy's symbolized check). A template is no secret by its
NAME (`.env.example`, `.env.sample`, `*.example.*`, `SHAPE_EXCEPTIONS`,
`TEMPLATE_NAME_RE`), whatever it holds. Around that rule it prunes: the
agents' own files (AGENT_STORES, the logins this launch runs on), Mandu's
own state and install trees, the SKIP_DIRS names at any depth, and below
the depth cap the package caches (recorded as `package-cache`, never
reached).

**The decision.** The guard gates the open of a regular file the launch
did not register when the walk's rule, without its budget, calls it a
secret (`gateVerdict`, through the `labelledLevel` op):

- *Where it looks.* The catalog's prefixes for the arbiter's HOME and the
  session's launch HOME are guard roots (`catalogGateRoots`; an agent's own
  store or login never is); the basename shapes go as a prefilter of
  literal name anchors (`catalogNameAnchors`, each shape's necessary
  condition). A name no anchor admits costs no round trip.
- *What it prunes.* For a catalog verdict (a label decides wherever it
  lies): an agent's own store or login under any of the homes
  (`isAgentAuthPath`: another agent's login created mid-session is not
  gated, a deliberate narrowing; the launch registers the ones that
  exist); Mandu's state but a raw AgentView copy; a directory named in
  SKIP_DIRS below the deepest home holding the file (below `/` outside
  every home; below the prefix for a prefix rule), and for a basename
  shape `site-packages` and `dist-packages` too (CATALOG_GATE_SKIP_DIRS:
  the gate has no depth cap, and a library's own `credentials.json` there is
  no credential of the user's); the package caches (PACKAGE_CACHE_DIRS).
- *Outside every home.* A name-matched file another account owns is not
  gated (`other-owner`: a system package's `botocore/data/credentials.json`, a
  root-owned fixture): the catalog speaks for the user's own files; a file
  whose owner cannot be read is gated (fail-closed).
- *Why `node_modules` and the other skipped directories stay ungated.*
  Parity with the walk, which never registers them; the trees package
  managers fill carry catalog shapes that are no credentials (test
  fixtures' `credentials.json` and `server.key`, a package's sample
  `.env`), and gating them would hand every program that loads them a
  placeholder; a human does not keep a credential in a dependency tree by
  hand, and a copy a secret holder writes there is a derived file (plan 13
  D4), gated wherever it lies.

- *The guard's side.* A gated catalog file is a `labelled` entry
  (`label_index`, `labelled_entry`, plan 13 D4): its twin from
  `registerSecret` (which arms the value backstop; a file only the launch
  HOME's catalog names is registered under that HOME), the real file for a
  reader the law names (`decideSecretOpen`), its writes, renames onto it
  and its second names gated as a labelled file's; a candidate the arbiter
  cannot classify is refused; the agent's own process is not gated; the
  guard's own twins (the launch's, `derived-twins/`) are never candidates.

**Cost.** A name no anchor admits costs no round trip: the prefilter is
about 0.26 µs per open in a release build with 90 prefix roots and every
anchor (`label_index` `candidate_cost`). A candidate costs one
`labelledLevel` round trip (about 0.2 ms through the Node client), cached
per file state and roots key.

**What changes for utility.** A program other than the agent that reads
such a file gets its placeholder, as for a registered one: a `.env` a tool
writes and another reads mid-session, a key copied into a project, a new
`~/.aws` SSO cache, a deeper `~/.kube/cache` file. A `public` label
releases one. The launch ledger still counts what the walk did not reach
(`depth`, `count`); under the guard those files are gated at the open all
the same.

**Program source is no credential file (2026-10-17).** As first built, the
`*credentials*` shape matched a source file named after what it handles
(`src/auth/providers/credentials.ts`, `pkg/auth/credentials_test.go`,
`CredentialsProvider.java`): the walk twinned one above depth 4, and the
gate, which has no depth cap, twinned one at any depth, so a compiler, a
bundler or a test runner read the placeholder. The shape now skips program
source as it skips documentation pages: a name whose extension is in
`SOURCE_EXTS` (secret-catalog.ts: `ts tsx mts cts js jsx mjs cjs vue
svelte py pyi rb php go rs java kt kts scala groovy swift m mm c h cc cpp
cxx hh hpp cs fs dart lua ex exs erl hs clj zig`) is no match.

- *What stays a match, and why.* Shell scripts (`credentials.sh`,
  `.bash`, `.zsh`, `.ps1`): a file a user sources to export AWS_* or a
  token is a store in practice. Every data or configuration format
  (`json`, `yaml`, `toml`, `ini`, `conf`, `cfg`, `env`, `properties`,
  `xml`, `txt`, `tfvars`, `plist`, `csv`), an encrypted store
  (`credentials.yml.enc`), a name with no extension, and a backup of a
  source file (`credentials.ts.bak`): each holds the credential itself.
- *One list, three readers.* The shape's own test reads the list, and its
  anchor carries it to the guard as `notSuffixes` (with the documentation
  extensions): the walk, `labelledLevel` and the guard's prefilter agree,
  and a source file costs no round trip. A guard that predates
  `notSuffixes` ignores the field, asks, and gets `public`.
- *Fail-closed where it matters.* A human label still wins
  (`pathConfidentiality` reads it first); a catalog PREFIX still covers a
  source-named file under it (`~/.aws/credentials.py`); a key pasted into
  a source file is what the workspace scan finds (secret-workspace-scan.ts
  never opens a file the catalog covers, so it never read these before);
  and a value registered elsewhere still masks at the model (the value
  backstop).
- *The other broad shapes (the audit).* `*secret*` already fires on data
  extensions only (`secrets.ts`, `secret_manager.py` were never matches);
  the private-key, service-account, `secrets*.json`, `*.env`, `*.keytab`,
  `*.tfstate` and ssh-key shapes name data files or exact names; there is
  no `*token*` or `*password*` shape (the catalog names those stores by
  prefix: `~/.vault-token`, `~/.password-store`). The one kept on
  purpose: `.env*` still matches `.env.js` and `.env.ts` (env-cmd reads a
  `.env.js` that exports the variables). `secret-catalog.test.ts` checks
  every shape against `SOURCE_EXTS`.

**What stays open.** A name-matched file inside a directory named like a
skipped one ABOVE a workspace outside every home (`/srv/build/app/.env`);
another agent's login created mid-session; any posture with no guard.

Tests: `arbiter/test/unit/catalog-gate.test.ts` (anchor soundness over a
generated corpus, walk parity over the credential corpus at and below
`MAX_DEPTH`, the prunes, the owner rule, two homes; a source file named
like a credential neither walked nor gated nor admitted, its data
siblings all three, a label still winning),
`arbiter/test/unit/secret-catalog.test.ts` (the source and data spellings
of `*credentials*`, the audit of every shape against `SOURCE_EXTS`) and
the guard's, listed in confidentiality.md §6.

## 2. The catalog's recall

### 2.1 The question

In `secrets` mode a credential file is protected only if the launch-time walk
registers it, and protected *well* only if the twin the agent reads in its
place still parses. The audit asks two things of every file:

1. **Walk recall.** Does `discoverSecretsReport` register it?
2. **Twin safety.** Does the rendered twin (structured, or whole-file when no
   shape applies or no span is found) contain none of the secret's bytes?

It also records the **shape** each file gets, because a whole-file twin
breaks the program that reads the file (the placeholder does not parse),
while a structured twin keeps keys and layout. The structured twin itself is
[`confidentiality-plan-10-flow-taint.md`](./confidentiality-plan-10-flow-taint.md)
§2.4.

### 2.2 Method

- **Corpus:** `arbiter/test/fixtures/credential-corpus.ts`, 84 entries (72
  until 2026-10-19; 81 with §2.6, 84 with §2.9):
  where developer tools write their login state (cloud CLIs, clusters and
  registries, source hosting, package registries, databases, SaaS CLIs, keys
  and keychains, project files), each with a realistic body and a canary
  value. Paths come from each tool's own documentation.
- **Unit gate:** `arbiter/test/unit/secret-catalog-recall.test.ts` lays the
  corpus out in a synthetic HOME, runs the real walk and extractor, and
  fails on any miss or any twin carrying a canary. It also holds the
  precision list (files that must *not* be registered).
- **E2E gate:** `arbiter/test/component/catalog-recall.test.ts`, the same
  over the real `ArbiterServer` + `ArbiterClient`.
- **Live gate:** a fixture-home row (§1.4) launches for real and reads
  `~/.pgpass`, `~/.npmrc`, a TOML CLI config, maven `settings.xml` and
  `~/.cache/huggingface/token` back as twins with their structure intact.
- **Real repositories:** a names-only scan (no file opened) of a developer's
  project tree, 426k files, listing credential-looking data files and
  whether the catalog registers them.

### 2.3 Result

| | Before the audit | Now |
|---|---|---|
| Walk recall on the corpus | **24 / 69** | **72 / 72** |
| Twins with no canary (of those registered) | 24 / 24 | 72 / 72 |

The misses before included three files `guarantees.md` already claimed:
`~/.pgpass`, `~/.npmrc` and `~/.pypirc` (the extractor knew their formats, no
catalog rule registered them). Also missed then: every Azure, OCI, Alibaba and
DigitalOcean file; podman, helm, vault; glab and hub; yarn, composer, maven,
gradle, NuGet; MySQL, Databricks, Snowflake; Vercel, Netlify, Cloudflare, Fly,
Supabase, Stripe, Firebase, ngrok, rclone, Hugging Face, Kaggle, Copilot,
1Password; project private keys, GCP service-account keys, `prod.env`, Rails
`master.key`, Terraform state and `secrets.auto.tfvars`.

**Real repositories (names only).** 76 credential-looking data files; the
catalog registers 23. The 53 it leaves are templates (`.env.example`),
source and docs named after the concept (`reduce-credential.mjs`), and 4
project `.npmrc` files (deliberately not a basename rule, §2.4). False
positives among the 23: a `detect-secrets` config, research JSON named after
the sysfs attribute `dhchap_secret`, and three older rules' hits. A false
positive costs utility, never security: the twin keeps non-secret keys raw,
and a file with no secret-looking key becomes a whole-file placeholder.

### 2.4 What the catalog does

**Catalog (`arbiter/policy/secret-catalog.ts`).**

- Home-anchored prefixes for every tool above (`~/.pgpass`, `~/.npmrc`,
  `~/.pypirc`, `~/.azure`, `~/.config/stripe`, …). Home-anchored on purpose:
  a project `.npmrc` usually holds `engine-strict=true` or a `${NPM_TOKEN}`
  reference, and a whole-file twin of it would break npm in every
  JavaScript repository.
- Basename shapes that hold anywhere: `*.env` and `.envrc`; `*secret*` on
  data extensions only (`json`, `yaml`, `toml`, `tfvars`, `env`, `ini`,
  `conf`, `cfg`, `properties`, `xml`, `txt`) or an extension-less name ending
  in `secret(s)`; private-key files (`*.key`, `*.p12`, `*.pfx`, `*.jks`,
  `*.keystore`, `*.ppk`, `*.kdbx`, `privkey*.pem`, `*-key.pem`); GCP
  service-account keys (`*service-account*.json`, `*-key.json`,
  `keyfile.json`); `*.tfstate`.
- Template names (`*.example.*`, `*.sample`, `*.dist`, `*.template`,
  `*.tmpl`) never match a shape.
- Since 2026-10-19 (§2.6): a CLI's login file in its own directory
  (`shape:tool-login-file`: `auth.json`, `auth.y(a)ml`, `auth.toml`,
  `oauth_creds.json`, `access-token` in a dot-directory or right under
  `~/.config`), the HTTP client's private environment
  (`shape:*.private.env.json`), and the CONTENT tier: a JSON, YAML or TOML
  config file the walk read a credential in (`content:secret-key`).

**Walk (`secret-discovery.ts`).** `~/.cache` and the other pruned
directories stay pruned, except a path the catalog names inside one
(`~/.cache/huggingface/token`), visited directly (`catalogPrefixesUnder`).

**Twin shapes (`secret-extract.ts`).** `toml` (`key = "value"`, quotes kept;
an inline table or a multi-line string falls back to whole-file) and
`xml-keys` (`<password>…</password>`, `<add key="…Password" value="…"/>`,
secret-named attributes). Routed: `*.env` and `.envrc` to dotenv (an
`.envrc` keeps direnv's built-ins raw, plan 10 §2.4.1); `.my.cnf`,
`.boto`, `.s3cfg`, `.databrickscfg`, `.sentryclirc`, `*.properties`, `*.ini`,
`*.cfg`, `*.conf` to INI; `*.toml` and `*.tfvars` to TOML; `*.xml` and
`*.config` to XML; `*.tfstate` to JSON keys; `~/.kube/config` to YAML keys.

Three EXHAUSTIVE shapes (2026-10-02, plan 10 §11.13), whose extractor reads
every place the format can hold a secret and masks any line it cannot read,
so a file with no secret twins as its own text instead of a placeholder:
`ssh-config` (`~/.ssh/config`, `~/.ssh/config.d/*`), `pip-conf` (`pip.conf`,
`pip.ini`) and `git-credentials` (`~/.git-credentials`,
`~/.config/git/credentials`). The public files directly in `~/.ssh`
(`known_hosts*`, `authorized_keys*`, `allowed_signers`, `*.pub`) are not in
the catalog.

### 2.5 What the audit does not cover

- **Content.** The catalog decides by path. A private key named `server.pem`
  is not registered (a `.pem` is as often a public certificate); a key pasted
  into `notes.txt` is not either. Label it, or see §3 and plan 14's
  workspace scan.
- **A project `.npmrc` with a literal token** is not registered (§2.4).
- **Whole-file twins still break their reader** unless that program is a
  listed reader: `~/.vault-token`, `~/.supabase/access-token`, the Hugging
  Face token, `~/.config/op/config`, `~/.config/hub`, SSH and GPG keys,
  PKCS#12 bundles. For single-token files the placeholder *is* the token,
  and the wire release puts the value back at a bound host.
- **A person-labelled JSON, YAML, TOML, INI or XML file is protected only
  for the values the extractor recognizes. A known gap in the
  invariant, not a design choice** (security gap, confirmed end to end
  and documented as interim 2026-10-16). The twin decision
  (`twinDecision`, `arbiter/secret-registry/registry.ts`) does not ask who
  labelled the file: a labelled file of a keyed shape with one span gets
  the structured twin, and every value under a key that does not look
  secret stays raw in it. The model receives those values through Read of
  the twin (the read-twin release passes twin text as carrying no secret
  byte) and through any command that does not name the path (`cat
  ./ret*`); a command naming the path is masked whole. A labelled dotenv
  masks by value, but keeps `BENIGN_VALUE_RE` values (integers, plain
  words) raw. This contradicts what a whole-file label says: a file
  labelled above `public` reaches a model only as symbols unless its level
  admits it. The fix is plan 16's document twin
  ([`confidentiality-plan-16-document-twins-writeback.md`](./confidentiality-plan-16-document-twins-writeback.md)
  §1.2, §3: every value of a labelled data file a symbol). A whole-file
  twin for every non-catalog label was prototyped and not taken: it
  breaks the labelled MCP-config flow (`tests/stack/labelled-mcp-config-twin.test.ts`,
  Claude Code could no longer parse its `.mcp.json`). Workarounds today,
  each checked in the code: a label's `extract:` replaces the shape
  extractor (`extractSecretSpans` → `extractByRegex`), so a pattern
  matching every value masks every value, and one matching nothing gives
  the whole-file twin; a file of no known shape (`.txt`, `.csv`) gets the
  whole-file twin; `whyPath`'s `twin` (`twinFormOf`) tells the two forms
  apart. A `readers:` list does not help (`flow-taint.ts`: the agent's own
  process always reads the twin), nor does another secret level (every
  secret level registers the same twin). Pinned, not as an oracle:
  `tests/stack/labelled-data-file-twin.test.ts` (KNOWN LIMIT; the fix
  must flip it). User docs: guarantees.md §3, usage.md.
- **A credential the shape rules leave raw: closed for every format the
  detector knows, and for a comment's random-looking token (2026-10-17,
  P0).** An adversarial review found a `.env` whose comment held an old
  live key (`# OLD_STRIPE_KEY=sk_live_51Old…`) twinned with the key raw:
  the dotenv rule reads no comment, and the twin is what every program is
  served. `base64 ./.e*` or `cut -c9- ./.e*` (a command in a clean tree
  that does not name the file) gave the model the key, and the value
  backstop, which matches verbatim bytes, saw none of it. The structured
  twin now has a CREDENTIAL BELT (`withCredentialBelt`,
  `secret-extract.ts`; plan 10 §2.4): every span the content detector
  finds anywhere in the file (`locateSecretShapes`: the vendor formats, a
  private key, a URL's password, a credential assignment), and in a
  comment, whole-line or trailing by the shape's own grammar (review of
  !1621), every bare token `looksLikeSecretValue` takes
  (`locateBareSecretTokens`, the value backstop's own), is a field of the
  file, masked in the twin and registered as a value of it. A comment's
  field is bound nowhere unless a label's `values:` names it. The belt
  narrows the item below too: a VENDOR key under a key that does not look
  secret is a field now. What it does not reach: a secret with no
  detector format, outside a comment, under an ordinary key (`notes:
  hunter2`), and every other value of a person-labelled data file (the
  bullet above).
- **Recall inside a structured file** relies on key names
  (`SECRET_KEY_RE`) for a keyed value: a secret under a key that does not
  look secret in a JSON, YAML, INI, TOML or XML file stays raw in the twin
  unless the content detector knows its format (the credential belt
  above, 2026-10-17).
  Dotenv masks any value that does not look benign. The corpus has no such
  case today, but a file a human labels can (an MCP or editor config), so
  user docs list it as a known gap (guarantees.md §3), with `extract:` and
  `readers:` as the way out. List items have no key: until 2026-10-09 every
  one stayed raw, and a labelled `.mcp.json` with an `env` block kept its
  `args` raw (`"--api-key", "…"`, `"--token=…"`, a database URL's
  password), reaching programs and, when short, the model. Now the items of
  a JSON array, a YAML sequence and a TOML array are judged by
  `listItemSpans` (`secret-extract.ts`): per item, a URL's password, a
  detector format, and every item of a list under a secret-looking key;
  and the list read as one command line (`scanCommand`), each item one
  word, with every item that holds blanks, quotes or a backslash also read
  as the shell words it holds (`commandWords`: quotes, escapes, `; | & < >
  ( )`, `$(`, a backquote and a newline end a command's context, so
  `--token $(cat f)` takes no value and `cat f` is read; of these, `; | &
  ( $(`, an opening backquote and a newline start a command, while the word
  after `<`, `>`, `>&`, `)` or a closing backquote is a file, a descriptor
  or the rest of a word; up to `MAX_COMMAND_DEPTH` 3, so a line, a `sh -c
  "…"` script in it and a quoted command in that). The item after `-c`
  (`sh -c`, `bash -lc`) is a script: read only as words, so `PGPASSWORD=…
  psql -h db` masks the password, not the rest as one value; a quoted word
  after `-c` inside a line is read as a script too. In the words, every
  word is judged once:

  - a flag that takes a secret takes its value after `=`, glued, or as the
    next word when that word is no flag and no shell operator stands
    between; any other flag takes nothing. A word that starts with `-` is
    a flag, never a value, unless `credentialShaped` (then it is the value
    and still read as a flag). Long flags: `secretFlagName` (the flag list
    is in the code and its test), with `/`, `:` and `@` as word breaks
    (npm's `--//registry.npmjs.org/:_authToken=…`), not a switch of
    `AUTH_SWITCH_WORDS` (`--skip-auth`), a pattern of `PATTERN_PAT_WORDS`
    (`--exclude-pat`) or an asking switch of `ASK_SWITCH_WORDS`
    (`--ask-password`, `--ask-pass`); `--password` alone takes no next
    word when psql, a PostgreSQL client or mysql is the command itself
    (`PROMPTED_PASSWORD_PROGRAMS`, `isCommand` below: they ask). Single-dash:
    Go's `-password`, `-token=`; else a cluster (`-fsSL`, `-su`), whose
    first letter that takes a secret takes the rest of the word or the next
    word: `-u` (not when a `UID_GID_USER_PROGRAMS` program is the command),
    curl's `-U`, `-H`, a program's own letter (`PASSWORD_LETTER_FLAGS`:
    `sshpass -p`, mysql's glued `-p`, `redis-cli -a`; read before a
    Go-style name when that program is the command, so `mysql -pass` is the
    password `ass`, while `--db-type mysql -password S` takes `S`), `-p`
    after `login` of
    `LOGIN_PASSWORD_PROGRAMS` (`docker login`, `podman login`, `helm
    registry login`, `az login`; not gh, whose `auth login -p` is a
    protocol), httpie's `-a`, curl's `-b`, and `-b`/`--body` after `gh
    secret`;
  - a value is judged by its flag (never one to three characters of
    punctuation, `$` or `*`, which as a needle would rewrite the twin's
    punctuation, nor a reference resolved before the program runs,
    `referenceValue`: `${…}` anywhere, which an MCP client expands, and
    `$NAME` in a shell word whose `$` is not single-quoted or escaped; an
    item no shell reads passes `$ecretPass99` to the program as it is, so
    that is a value, and a URL's password, read on the item's raw text, is
    a value unless it is `${…}`; fourth review, 2026-10-10: every `$NAME`
    stayed raw. Residual, documented in guarantees.md §3: every word
    `commandWords` yields counts as a shell word, so `$NAME` inside an item
    of several words that is not a `-c` script, inside a quoted word
    re-read at depth 2 (the literal-`$` marks are not carried through), or
    after bash's `$'…'` / `$"…"` quoting still counts as a reference; the
    narrower code fix, a shell flag per word, is left for later): whole (`valueSpan`: a URL keeps all but its password),
    `user:password` (`--user`, `--proxy-user`, `-u`, `-U`: the password,
    the user when the password is empty, nothing for a bare user, a
    numeric `uid:gid` or a reference), a credential (httpie's `-a` /
    `--auth`: `user:password` so, a value with no `:` whole), or a header
    (`-H`, `--header`, `--proxy-header`);
  - a header (`Name: value`, the value of `Authorization` past its scheme
    word, or of a `secretFlagName` header such as `X-API-Key` or
    `PRIVATE-TOKEN`), wherever it stands as a word or after a non-secret
    `NAME=` or `--flag=` (git's `-c http.extraHeader=…`); written unquoted
    over several words (`-H Authorization: Bearer X`) its value is the
    next word, past a scheme word; not httpie's `name:=value`;
  - `NAME=value` (and httpie's `NAME:=` and `NAME==`) with a secret-looking
    NAME (`isSecretKey`, `ENV_SECRET_NAME_RE`); a form body whose every
    `&` piece is a pair (`-d 'grant_type=…&client_secret=…'`) masks each
    secret pair's value (`PASSWORD=p&ss` is one value);
  - after a word `set` or `config`, a `secretFlagName`-named setting
    (`//registry.npmjs.org/:_authToken`, `user.password`) takes the next
    word.

  The program a command names (`CommandContext`) decides how some flags
  read. The `KNOWN_PROGRAMS` program named last (`program`: any word whose
  basename is one; the command word sets it, to none when it names no such
  program) turns on the rules that mask MORE: curl's `-U` and `-b`, `docker
  login -p`, httpie's `-a`, mysql's glued `-p`, `gh secret set --body`; so
  `docker run … curl -u u:pw` masks. The rules that mask LESS hold only when
  the command word named it (`isCommand`): `--password` alone after
  `PROMPTED_PASSWORD_PROGRAMS`, `-u` as a user and group after
  `UID_GID_USER_PROGRAMS` (and only until another known program is named:
  `-u x:y` past `docker run img tool` stays, a user and group), a program's
  letter before a Go-style name. The command word (`commandSlot`) is the
  list's `command` (an MCP server's; with several words, read as a command's
  first words), or the first word of a script or of a command after an
  operator that starts one, past `NAME=value` and past `WRAPPERS` (`sudo`,
  `doas`, `env`, `nice`, `nohup`, `timeout`, `exec`, `command`, `xargs`,
  `time`, `stdbuf`, `ionice`, `setsid`, and `!`, `{`, `if`, `then`, `elif`,
  `else`, `do`, `while`, `until`) with their options: each wrapper lists the
  options that take a value (`sudo -u postgres`), those that take none, and
  its positional words (timeout's duration); an option it does not list ends
  the search, so the command has no command word and nothing narrows (`sudo
  -h host`, `env -S`, `command -v`). A list with no `command` has none
  either: its first item may be an argument (Kubernetes `args` beside a
  `command` list). Nor has a quoted word read as words that is no script
  (`ssh host "…"`, a conninfo string), nor an item that holds a command line
  beside other items. Over-masking in the safe direction follows: `docker
  exec db psql --password prod` masks `prod` (docker is the command), as
  does a list `["psql", "--password", "prod"]` with no `command`. Fourth
  review (2026-10-10): any plain word whose basename was a known program set
  the program, so a path (`--datadir /var/lib/mysql`), an image (`docker run
  mcp/mysql`) or another flag's value (`--db-type mysql`, `--runtime
  docker`) made a later `--password S` a prompt or `-u admin:S` a user and
  group, and `S` stayed raw in the twin the model reads (the regex extractor
  before the third review's tokenizer had masked them). A shell operator
  ends the command's context and a script starts a new one.
  `secret-extract-command-lines.test.ts` is the table of real command lines
  (curl, wget, httpie, psql, mysql, docker login, gh, npm, git, and the
  fourth review's words that only name a program, with the commands whose
  exceptions hold) with switches before, between and after the secret flags,
  in JSON, YAML block and flow (quoted, and plain where every item reads
  back as the same string), and TOML, as one item, one item per word and an
  MCP `command` with `args`: exactly the secrets are masked, everything else
  is as written. Beside it: a property test (random lines that also hold
  words naming a program), the command-position test (each wrapper, operator
  and list shape), the `$` test, and the unrecognized pin. Its last test
  pins what stays unrecognized (guarantees.md §3 lists it): a secret with no
  flag or name before it (`cargo login`, `poetry config http-basic.<repo>
  <user> <password>`) or on stdin; a dash-led value that reads like a word;
  a JSON body; a URL's query value; a word-like token as a URL's user with
  no password; `-u x:y` later in a docker command; a flag Mandu does not
  know (curl's `-E cert:password`) or a header whose name does not say
  secret; a command line nested past two levels of quotes in a line. Until
  the
  third review (2026-10-10) a regex took the word after ANY flag as its
  value and went on after it, so a switch before a secret flag swallowed it
  (`curl -s -u admin:pw`, `tool --verbose --auth S` stayed raw while the
  docs said masked), and a header inside one item was never read. Since
  the first review (2026-10-10) the flag list holds `--auth`
  (`--basic-auth`, `--http-auth`, `--proxy-auth`) and `--pat`; the second
  review added the switch and pattern exceptions. They only add
  to a file whose keys gave a span; a file with none stays whole-file, so
  list rules never turn a whole-file twin into one that shows more (a file
  whose only recognized secret is a list item is hidden whole, and `mandu
  why` says "no secret value it can hide in place", not "recognizes no
  secret value"). The list rules cover JSON, YAML and TOML only: an INI or
  XML file has no list syntax they read. Field names `<list>.<index>`
  (`args.3`, `servers.brave.args.3`), scanner-complete as written
  (mandu.md §9). MCP and editor configs (`.mcp.json`, `~/.cursor/mcp.json`,
  `.vscode/mcp.json`, `claude_desktop_config.json`) are still not in the
  catalog: twinning them would hand every MCP server placeholders, a
  maintainer decision.
- **The YAML and TOML list readers are line-based, with known limits.**
  YAML: a value inside a flow mapping (`env: {GITHUB_TOKEN: …}`) is not
  judged (the keyed reader reads `key: value` lines only, and the list
  reader skips a mapping inside a list), so it stays raw when the file has
  another span; a block-scalar list item (`- |` and the lines under it) is
  no string item; a plain or quoted item that goes on to the next line is
  read as its first line only; a sequence nested in an item (`- - a`) names
  only the items on that line by place. The text of a block scalar
  (`script: |`) is skipped, so a `key: [` in it opens no list. A
  placeholder in a plain item of a flow sequence (`[-y, --token=x]`) is
  written single-quoted (`'--token=$MDU:…'`, the dotenv `wrap`): `[` and
  `]` in the token are flow indicators, and the twin must still parse
  (js-yaml, unit test); two placeholders in one plain item become one, and
  an item whose own text holds a quote or a backslash is one placeholder
  whole. Such a placeholder keeps each secret in it as a part
  (`SecretSpan.parts`, as an overlap union of `finishMerged` does): a copy
  of one elsewhere in the file is its own placeholder, and the registry
  holds its value (plan 10 §2.4; until the second review the copy stayed
  raw). TOML: an inline table or a multi-line string makes the whole file
  the twin, as before. In both, a flow list that never closes, or lists
  nested deeper than 64 (or a list name past 1024 characters), make the
  whole file the twin: the twin of a file Mandu cannot read in place is
  the whole-file one.
- **The extractors are linear in the file.** A file the agent writes can
  match a shape (a workspace `.env*`, or a path a label covers), and `mandu why`
  extracts it on demand from the data socket (`whyPath`), so no walk may
  rescan text: the URL-password scan goes by `@` (each `@` looks back only
  over its own run of non-blank, non-`@` characters), the command-line
  reader splits an item in one pass and judges each word a bounded number
  of times, at most `MAX_COMMAND_DEPTH` deep (its own 256 KB cases in
  `secret-extract-command-lines.test.ts`), the keyed JSON scan
  never starts at a quote after a backslash (a walk over the JSON strings
  as they are runs beside it, so on valid JSON the two find every pair the
  old regex found: a property test on generated documents), the YAML key regex has no
  blank run before its `:`, a JSON closer with no open container of its
  kind is ignored without a walk down the stack, the flow-list reader
  recurses at most 64 deep, and a field name over 2 048 characters hides
  the file whole (V8 hashes a longer string by its length alone, so the
  key dedupe map went quadratic on many long names). 2026-10-10: a 256 KB
  list item took 9.7 s, a YAML line of blanks 0.4 s per 16 KB, `[` ×
  100 000 overflowed the stack, and 10 000 `password:` lines under one
  20 000-character YAML key (156 KB) took 137 s;
  `secret-extract-lists.test.ts` pins each under a second. `whyPath`
  itself (`arbiter/ipc/why-preview.ts`) checks a file before it opens it
  (`lstat`, then `stat` of a link's target: only a regular file, so a FIFO
  or a device is never opened), reads at most `WHY_MAX_BYTES` (256 KiB)
  `O_NONBLOCK` and checks it again on the descriptor: a FIFO named `.env`
  blocked the arbiter for good, and a link to `/dev/zero` was read without
  end. Linear is still about 1 µs a byte on an adversarial file (a 7 MB
  YAML of `-u a:b` flow items took 3.5 s a call), so an answer is
  remembered by the hash of the text read, and on the data socket texts
  not remembered spend a budget of 1 MiB per 10 s (the dashboard asks on
  the human plane, which has its own); past either bound the answer has no
  `twin`.
- **Tools not in the corpus.** The corpus is the claim. A new tool's login
  file is covered only if a prefix or shape already reaches it, or, since
  2026-10-19, the content tier reads a credential in it (§2.6).

### 2.6 The saved logins: two shapes and a content tier (2026-10-19)

**The evidence.** The `secrets-defaults` battery of 2026-10-18 (Mandu with
its default catalog only, run by the drill suite) saw two secrets reach the
model. demo-c7: the power company's password, saved as `password:` in
`accounts/brightgrid.yaml`. demo-c11: the hosting platform's API token,
`{"token": "ldk_…"}` in `.launchdeck/auth.json` at the top of the
workspace. demo-staging-admin-request's `api/http-client.private.env.json`
was missed the same way (offline). The launch's policy scan (plan 14 S2)
found each and filed a `lock-path` suggestion, which protects nothing until
a human applies it.

**Why each was missed.**

- `secret-catalog.ts` `SECRET_BASENAME_SHAPES` had no shape for either
  name: `brightgrid.yaml` says nothing, and `auth.json` was covered only at
  the prefixes of the tools the audit listed (`~/.config/composer/auth.json`,
  `~/.local/share/com.vercel.cli`, …), never in a project's or a new tool's
  own dot-directory. `secretPathConfidentiality` returned `NO_MATCH`, so
  `discoverSecretsReport` did not list the file, `registerSecret` refused
  it ("not a secret path"), no value was registered, the value backstop
  knew nothing, and the egress tripwire had no fingerprint.
- The extractor (`secret-extract.ts`) would have masked both values: it
  reads `password:` and `"token"` as secret keys. It is only asked about a
  file the catalog or a label already registered.
- The content detector (`secret-detectors.ts`, `credential-assignment`)
  found both lines, but its findings feed only the launch scan's
  suggestions, by the plan 14 decision that a scan never changes the law
  on its own.

**What is widened.**

1. **Two path shapes** (`secret-catalog.ts`). `shape:tool-login-file`: the
   names a CLI gives its login file (`auth.json`, `auth.yaml`, `auth.yml`,
   `auth.toml`, `oauth_creds.json`, `access-token`, `access_token`), in a
   directory of its own: a dot-directory (`.launchdeck/`, `~/.gemini/`,
   `~/.now/`), or a directory right under `.config` (`~/.config/planetscale/`).
   Never by the name alone: `public/locales/en/auth.json` is an app's
   strings. The shape reads the parent and grandparent names, so its guard
   prefilter anchor is the name (`{exact: "auth.json", ci: true}`) and the
   arbiter's `labelledLevel` decides. `shape:*.private.env.json`: the
   JetBrains HTTP Client's private environment, which its convention keeps
   out of version control because the passwords and tokens go there.
2. **The content tier** (`found-labels.ts`). The walk READS each candidate
   it meets (`contentProbeCandidate`): a `.json`, `.yaml`, `.yml` or
   `.toml` file of at most 64 KiB, anywhere in a workspace root's walk, and
   in HOME only directly in a tool's dot-directory (`~/.railway/config.json`,
   `~/.config/turso/settings.json`); never a template, a manifest or
   lockfile (`package.json`, `Cargo.toml`, …), a file under a test,
   fixture, example or documentation directory (below the walk root), or
   an agent's or editor's own config (`.claude/`, `.vscode/`, `.mcp.json`,
   `~/.config/opencode/`, …; an MCP config among them is read by a route of
   its own since 2026-10-21, §2.10). At most 1024 files and 8 MiB a walk
   (`content.capped` counts the rest). It labels the file when the
   extractor that builds its twin finds a span that is a credential beyond
   reasonable doubt (`credentialInDataFile`): a value under a
   credential-named key (the `credential-assignment` names: `password`,
   `token`, `secret`, `api_key`, `access_key`, `private_key`,
   `passphrase`, `credential`) whose last word is no reference word
   (`token_url`, `secret_name`, `password_file`, `api_key_id`,
   `adminPasswordKey`), that `looksLikeSecretValue` takes (12+ characters,
   mixed or random, no stand-in) and is no reference (`${X}`, `{{ … }}`,
   `<%= … %>`, `ENC[…]`, an ARN, `op://`, a URL with no password, a path,
   prose); or a vendor-format key the twin's credential belt adds. A file
   so found gets a **found label**: `no-model`, bound nowhere, rule
   `content:secret-key`, kept in the symbol DB (`found_labels`) so an
   arbiter restart keeps it. The arbiter records the walk's verdicts
   (`recordFound`) before it answers, so the launcher's `registerSecret` of
   the file finds it labelled.

**How a found label composes** (label-lookup.ts `composeAt`): as the
catalog does. A human label on the file or on a folder above it decides
instead, in either direction (a `public` label releases it, and the walk
then does not read the file); with no human label it is `no-model`, which a
derived row or a client key cannot raise. A catalog path rule on the same
file keeps its own name. The text scan reads a command that names the file
(`labelRoots`), the guard gates it at the open (`guardLabelRoots`: its own
root), and the next walks list it wherever it lies (`foundPaths`, as
derived paths are). `mandu why` says "Mandu found a saved password or key
in this config file"; the dashboard's file browser "Built in: a saved
password or key Mandu found in it".

**Lifetime.** A row stays until a walk reads the file again and finds no
credential in it (`cleared`: the human took the password out, and a
whole-file twin would only break the file); then the file is public again.
A file the walk did not reach keeps its row. A file found past the walk's
file cap is labelled all the same (the guard gates it at the open).

**The stance, amended.** `secret-catalog.ts` said an unmatched path is
`public` by design, and confidentiality.md §6 calls mislabeling the
feature's biggest practical risk. Both still hold for a file the walk never
read, or read and found nothing in. What changes: a config file the walk
read a credential in is no longer unmatched. This is §6's "advisory
credential-shape heuristics" promoted, for one narrow, high-precision
class, from a suggestion to a default label. The plan 14 rule that a scan
never changes the law stands: a found label is a machine record outside
`policy.yaml` (no `paths:` entry is written), shown in its own words, and a
human label overrides it. Why it may apply by itself when the scan's
suggestions may not: its cost is bounded. The file's twin is structured by
construction (the deciding span is one of the extractor's), so the program
that parses the file still parses it, and only the values the extractor
masks become placeholders: a false positive costs a masked value, never a
broken file. Masking by shape at run time stays rejected (plan 14 §1): the
verdict is taken by the launch walk, over files at rest, never over a tool
result.

**False positives, weighed.** The unit table (`found-labels.test.ts`)
holds what must stay public: a reference (`${DB_PASSWORD}`, `<%= ENV[…]
%>`, `${{ secrets.X }}`, `ENC[…]` from sops, an ARN), a stand-in
(`changeme`), a short dev password (`postgres`, `hunter2`), an app's
strings (`"password": "Password"`), a URL or a path under a credential-ish
name (`token_uri`, `password_file`), a Helm chart's key names
(`adminPasswordKey`), a tokenizer config, an OpenAPI `securitySchemes`, a
JSON schema, and a commented-out non-vendor token. Over the drill
workspace it labels exactly the three saved logins (two of which the path
shapes also name); the recorded HTTP exchange of demo-refund-fixture
(`test/fixtures/refund.json`, which holds the sandbox password and which
that task re-records) is under a test directory, so the value backstop
keeps masking the password there as before (backstop-value-only.md). What
remains a real false positive: a credential-looking value that is no
credential under a credential name in a config file (a long throwaway dev
password in a `docker-compose.yml`, a non-secret id under `token:`). Its
cost is that value as a placeholder to the model and to the programs the
agent runs; `mandu why` names the rule, and a `public` label on the file
(or one with `bindings`) is the way out.

**What it does not cover** (open):

- A password too short or too simple for `looksLikeSecretValue`
  (`password: Tr0ub4`), or under a name that does not say credential
  (`pin:`, `pass:`), in a config file: closed the same day for a password's
  and a PIN's names by the short-value rule (§2.9); a password of letters
  alone or a public default (`password: hunter2`) stays public.
- A vendor key alone under a name that says nothing (`notify: {url_value:
  "sk-ant-…"}`): the extractor finds no keyed span and the twin would be
  one whole-file placeholder, so the tier leaves it to the suggestion.
- INI-like files (`.conf`, `.ini`, `.properties`) were not read: read
  since the same day (§2.9). `Label: value` notes in Markdown
  (demo-dog-sitter-text's `home/house-codes.md`) and plain-text exports
  (demo-tax-extension's SSN) were not read either: documents are not
  credentials. A narrow class of them, personal documents, is read since
  the same day (§2.7).
- A project in HOME that is not the launch's workspace: the HOME tier reads
  only tools' dot-directories, so `~/other-project/config.yaml` is read
  when a launch names that project.
- A project-level Composer `auth.json` beside `composer.json`: no shape (a
  bare `auth.json` is too often an app's strings), and its tokens are keyed
  by host (`"github-oauth": {"github.com": "…"}`), so the content tier does
  not take it either.
- A credential written into a config file during a session is found by the
  next launch's walk (a new `.env` is gated at the open by its name; a
  config file has none).
- The data plane may ask for a walk (`discoverSecrets`), so a caller can
  make the arbiter read a candidate and learn from the listing whether a
  file it cannot read holds a credential under a credential name: one bit,
  about a file the next launch's walk would read anyway.

**Tests.** `arbiter/test/unit/found-labels.test.ts` (the candidates, the
names and values, the positive and negative tables, the reader, the
composition, the store across a reopen, the walk's `found` and `cleared`,
and a found file outside the roots); `secret-catalog.test.ts` (the two
shapes, positive and negative); `catalog-gate.test.ts` (the anchors'
soundness, and the walk's parity with the gate for the path rules); the
corpus (`credential-corpus.ts`: Gemini CLI, Qwen Code, PlanetScale, the old
Vercel CLI, Railway, Turso, Doppler, Twilio, the JetBrains private
environment) through `secret-catalog-recall.test.ts` and the component
`catalog-recall.test.ts`; `tests/stack/content-tier-config-secret.test.ts`
(the e2e oracle over the real arbiter, the launch's secret setup and the
production proxy wiring: no byte of the three values in any model-facing
request, by a Read of the raw file, a command naming it or one that does
not; the twin keeps the rest readable; each placeholder asks at every host;
the scan no longer suggests them; a restarted arbiter keeps the label; a
walk that reads the file clean drops it; a human `public` label decides);
and the drill suite's defaults table (the rows of demo-c7, demo-c11 and the
staging request flipped to labelled, recognised and asked).

### 2.7 Personal documents: the content tier reads documents (2026-10-19)

**The evidence.** The same `secrets-defaults` battery (2026-10-18) let two
documents reach the cloud model. demo-scam-email (c2): a bank statement,
`bank/statement-2026-09.md`, whose account number (`DEMO-ACCT-000123`)
the model read, and whose upload, which the task sends to the accountant's
host and must not send to a lookalike share, rested on the agent's own
judgement with no card. demo-local-health-summary (c3): a blood-test
report, `health/lab-results.md`, the patient's name and values in the
cloud model's context. The drill suite's defaults table showed two more
documents missed the same way: demo-dog-sitter-text's
`home/house-codes.md` (an alarm code, a Wi-Fi password) and
demo-tax-extension's `taxes/2025/return-summary.txt` (an SSN, the AGI).

**Why each was missed.**

- `secret-catalog.ts` decides by path, and no path rule names a document:
  `secretPathConfidentiality` fell through to `return NO_MATCH`
  (secret-catalog.ts:458 before this change), by the stance its header
  states (secret-catalog.ts:12, "an unmatched path is `public` BY
  DESIGN").
- The content tier of §2.6 reads config files only: `DATA_EXT_RE`
  (found-labels.ts:107, `.json`, `.yaml`, `.yml`, `.toml`) gates
  `contentProbeCandidate` (found-labels.ts:157), and the walk returned
  before reading anything else (secret-discovery.ts:1278).
- Had a human labelled a document, its twin would have been one whole-file
  placeholder: `secretFileShape` (secret-extract.ts:3442) has no shape for
  `.md` or `.txt` and returns null (secret-extract.ts:3464), so the model
  could upload the statement but not tell the SSN from the AGI. The drill
  tunes this away with its own `extract: ':[ \t]*(.+)'` label, which a
  fresh install does not have.

**The product answer: an automatic label, not a launch question.** A
launch-time question ("Mandu found a statement and a lab report; keep them
from the AI?") was weighed. It asks the human to decide about files they
did not mention, before the task, on every launch that finds a new one,
and a question that is answered "yes" every time is a default with a
delay. The automatic label is what the §2.6 content tier already is (a
machine record, `no-model`, bound nowhere, overridden by any human label),
and its cost is bounded the same way: a false positive costs the model the
values of one file, never the file's use, since the twin keeps the labels
and the human allows a send on its card. So the second content tier labels
by default, with rules narrow enough that the question would almost always
have been answered "keep them".

**The rule** (`personal-documents.ts`). The walk reads each candidate
(`documentProbeCandidate`): a `.md`, `.markdown`, `.txt`, `.text`, `.csv`
or `.tsv` file of at most 64 KiB, anywhere in a workspace root's walk, and
in HOME only under `Documents`, `Desktop` or `Downloads`; never a project's
README, changelog, licence, contributing guide or agent notes
(`AGENTS.md`, `CLAUDE.md`), a requirements file, a template; never in a
test, fixture, example, sample, docs, design, ADR, eval, source, vendored,
seed, locale or build directory, nor in a dot-directory; and never inside a
software project below the walk root (`inSoftwareProject`: a directory
between the root and the file holds `package.json`, `Cargo.toml`,
`pyproject.toml`, `go.mod`, `Makefile`, …; the root itself is never asked,
since a workspace may be a repository). At most 512 documents and 8 MiB a
walk, a budget of their own (`documents.capped` counts the rest). Each
document kind needs several independent signals at once
(`personalDocumentKind`):

| Kind | All of |
|---|---|
| bank or card statement | an account identifier (a mod-97-valid IBAN, a Luhn-valid card number, a masked card `**** 1234` / `ending in 4411`, or 4+ digits under an account, sort-code, routing or card label; never a documented test card or example IBAN), two statement terms (`statement`, `closing balance`, `available balance`, `minimum payment`, …), money amounts on 3+ lines |
| payslip | a payslip term (`payslip`, `pay stub`, `gross pay`, `net pay`), three payroll terms, amounts on 3+ lines, an `Employee:` (or name, staff or payroll number) line |
| tax return | a taxpayer number (an SSN or ITIN of a valid shape, never area 000 or 666, group 00, serial 0000, nor a documented example such as `123-45-6789`; a UK NI number or UTR under its label; 9+ digits under a tax-id label), two tax-return terms (`tax return`, `adjusted gross income`, `filing status`, `total tax`, `Form 1040`, `self assessment`, …), an amount |
| lab report | a patient line (`Patient:`, `MRN`, `NHS number`, or a name and a date of birth), 3+ results with a lab unit (`mmol/L`, `g/L`, `x10^9/L`, `mU/L`, `mg/dL`, …), 2+ reference ranges (`(120-160)`, `(below 3.0)`) |
| identity document | a passport machine-readable zone; or a passport, licence or ID number line, a date of birth and an expiry, issue or nationality line; or an SSN of a valid shape (or an NI number) under its own label |
| household codes | 2+ `Label: value` lines (or two-cell table rows) naming a door, gate, garage, keypad, alarm, lockbox or safe code (4+ digits, not `1234` or `0000`) or a Wi-Fi password (8+ characters, no stand-in such as `<your password>`) |

A file so found gets a found label of kind `document` (found-labels.ts:
the same store, a `kind` column, its `field` the document's kind):
`no-model`, bound nowhere, rule `content:personal-document`. The arbiter
records it before it answers the walk (`recordFound`), so the launcher's
`registerSecret` finds it labelled. The `cleared` lifetime is §2.6's: a
walk that reads the file and recognises no document in it drops the label.

**How the model still does the task: the document twin.** The found
label carries an `extract:` of Mandu's own (`DOCUMENT_TWIN_EXTRACT`, a
real `paths[].extract` regex, so a human may use it too): on each line the
leading Markdown markers and a short `Label:` stay as written and the rest
of the line is one placeholder; a line with no label is a placeholder
whole; a blank line or a rule (`---`, `|---|---|`) stays, and a line with
no letter or digit is never a placeholder (the twin replaces every other
copy of a value in the file, and a value of `-` would eat every hyphen).
The statement's twin reads

```
# $MDU:nomodel_Read[…].extract_1

Account: $MDU:nomodel_Read[…].extract_2
Holder: $MDU:nomodel_Read[…].extract_3

$MDU:nomodel_Read[…].extract_4
…
Closing balance: $MDU:nomodel_Read[…].extract_7
```

so the model knows which line is the account, the SSN or the alarm code,
puts the right placeholder in a form field, a text or an upload, and reads
no value; the reply filter shows the human the originals. Each value is a
field row of the file's registration (bound nowhere, so the value backstop
masks it wherever else it shows, and its placeholder asks at every host);
a value shorter than the fingerprint floor (8 characters) is masked where
the file is read by name and through the twin, not when a command that
does not name the file prints it (the value backstop's floor, as for any
registered value).

**A human's *Always* keeps the twin** (label-lookup.ts
`withDocumentTwin`). The human's answer *Always* on the statement's upload
card writes an exact `paths:` rule with the accountant's host
(holder-send-ask.ts `holderBindEdit`), which outranks the found label. The
policy-edit grammar cannot write an `extract:` (on purpose: a suggestion
must not be able to narrow a twin), so the twin would have turned into one
whole-file placeholder mid-task and every placeholder the model held would
have stopped naming a line. A human label with no `extract:` of its own on
a file the content tier found to be a document therefore keeps the
document twin; the human's label decides the level and the destinations,
a `public` label has no twin, and a human `extract:` wins.

**The invariant.** The document's values reach a model only as
placeholders: through a Read (the twin), a command naming the file (the
twin's rules), and a command that does not (the value backstop, every
value of 8+ characters and every line of 24+; a person's name, below, is a
placeholder through a Read and a command that names the file, and masked
with the rest in an output that carries another of the file's values, but
no fingerprint on its own); the labels and the Markdown
structure are what the model reads. They leave only where the human
allows: bound nowhere, every placeholder asks at every host
(`egress:secret-unbound`), and after an *Always* the file goes to that host
and still asks at any other. `tests/stack/content-tier-personal-documents.test.ts`
asserts all of it through the real arbiter and the production proxy
wiring.

**False positives, weighed.** Each rule needs an identifier of a checked
shape (mod 97, Luhn, the SSN ranges, a lab unit with a reference range)
with the vocabulary and the amounts of its kind, so a document that only
talks about statements, taxes or cholesterol is not taken. Measured on
2026-10-19: the detector alone (no path filter) over 2,096 text documents
(the Mandu source tree's docs, tests and evaluation corpora, three
`node_modules` trees, `/usr/share/doc`) took two: a sensitive corpus's bank
statement summary (a true positive) and a design note quoting the tax
drill's fixture (now behind the `design` directory rule). A labelled
corpus of 100 documents (60 ordinary developer documents, 10 written to
steer a classifier, 30 sensitive business and personal ones) gave no false
positive and that one true positive: most of its sensitive documents (a
contract, a memo, a diary) are not this tier's kinds. The whole walk over
the Mandu tree, a developer's project tree and three other work trees
labelled no document. The unit tables hold what must stay
readable: a payments API's notes with documented test cards and example
IBANs, a budget, meeting notes, a glucose log with no patient, an article
on cholesterol, a router guide with stand-ins and the default `1234`, one
Wi-Fi password alone, an invoice, the documented example SSN, a developer's
payroll notes, sales data, a recipe, version lists, contacts, a CV. What
remains a real false positive: a person's own document that is not
personal in that sense (a budget note with an account number and statement
words, a sample statement kept outside any project); its cost is the
model reading its labels and not its values, and a card on its first send;
`mandu why` names the rule, and a `public` label on the file is the way
out. A cost of a true positive, too: each value of 8+ characters is a
registered value, so it is masked wherever else the AI reads it; a
person's name is the exception (below).

**A person's name is a placeholder in the twin, not a fingerprint**
(2026-10-19). Until then the holder's name on a statement (`Alex Demo`,
under `Holder:`) was a registered value like the account number, and the
value backstop masks a whole output that holds a registered value. The
battery of 2026-10-19, demo-inbox-you-decide under `secrets-defaults`:
the accountant's follow-up quoted the user (`> On
Monday, Alex Demo wrote:`), so the whole mail reached the model as one
placeholder; the model never read the lookalike share's request in it, and
the human was never warned. A user's own name is in most of their mail,
logs and pages, so this masked far more than the document.

The rule (maintainer's direction, 2026-10-19): a person's name in a
personal document stays a placeholder in that document's twin (with a lab
report's results, or a statement's balance, the name is the sensitive
part), and its field row is minted as before, so the reply filter shows
the human the original and its placeholder asks at every host. But it is
no fingerprint: the value index (`RegisteredValueIndex`, which serves the
value backstop and the egress tripwire) and the clean-tree residue scan
leave the row out (registry.ts `documentNameRows`, the arbiter's
`isDocumentNameRow`), and a line of the file whose only secret is the
name (`Account holder: Alexandra Demonstration-Smith`, 24+ characters) is
no line piece of the file's row (egress-fingerprint.ts
`ValueTwin.nameLines`). Which values are names
(personal-documents.ts `documentNameField`, marked by the twin's extractor
as `SecretSpan.name`, only under the document twin's own rule):

- under a name label (`Holder`, `Account holder`, `Name`, `Full name`,
  `Patient`, `Employee`, `Taxpayer`, `Spouse`, `Prepared for`, `Insured`,
  `Member`, `Customer`, `Cardholder name`, a physician, …,
  case-insensitive): 1 to 6 words of letters (initials, hyphens,
  apostrophes, `&` between two names);
- on a line with no label, or under a label that names no secret: 2 to 4
  capitalized words;
- never a value with a digit (an account number, a date of birth, an
  address with a house number, `Alex Demo (MRN 4412)`), never under a
  label that names a secret (a password, a code, a PIN, a security answer,
  a maiden name, a network, an address, a number or ID), never on a span
  that merged others, and never under a human's own `extract:` (there
  every value stays a fingerprint, as before).

Account numbers, IBANs, SSNs, card numbers, codes, passwords, amounts and
dates stay registered values: they are masked in any output and trip the
tripwire at any host.

*What the model can now learn, and why that is acceptable.* It reads the
user's name where the user's own mail, logs and pages carry it, which it
did before Mandu and which no task can do without. Holding a name it sees
elsewhere and the twin's `Holder: $MDU:…` line, it can GUESS that the
statement is that person's, which the file's place in the user's own
folder already says. Through the twin it cannot confirm the guess: the
twin never carries the name, a command that names the file reads the
twin, the placeholder is substituted only for the human (the reply
filter) or at a host the human allowed, and masking no longer acts as an
oracle (before this change, a mail coming back masked whole told the
model that it held a registered value). One narrow way to confirm it:
where no file guard serves the twin (an unconfined agent, a copy of the
file in git history), a command that does not name the file and prints
the name's line alone (`grep -r Patient`) shows that line as it is, so
the model learns that some file holds that person's name under that
label, never what else it holds; an output that carries the name with
any other value of the file is masked whole, as before. What it cannot
get is unchanged: the account number,
the balance, the lab results, the SSN, each a placeholder wherever it
appears and a tripwire hit at every host. The name may now leave in a
message the model writes itself (a reply signed `Alex Demo` sends with
no card); a name alone is no secret of the document, and the document's
upload (its base placeholder) and the name's own placeholder still ask at
every host. What remains a cost: a name of a capitalized-words shape that
is in fact a secret on a line with no label (a passphrase written alone on
a line of a house note) is a placeholder in the twin but no fingerprint;
under its `Wi-Fi password:` label it stays one.

**What it does not cover** (open):

- PDF and Office documents (most real statements and lab reports): read
  since 2026-10-19 by §2.8; what that reader cannot read (a scan, a
  password-protected file, a legacy `.doc` or `.xls`) stays public unless
  labelled.
- A personal document of another kind (clinical notes with no lab values,
  a prescription, an insurance letter, a contract, a diary), or one of
  these kinds with fewer signals (a statement with no account number, a
  note with one code, a payslip with no employee line): still public, or
  suggested by the policy model.
- A document in HOME outside `Documents`, `Desktop` and `Downloads` when
  the launch's workspace is elsewhere, one inside a software project, one
  in a dot-directory, or one larger than 64 KiB.
- A label is kept as written, so a person's name used as a label
  (`Kim Alvarez: +1 555-0142`) stays readable.
- The field names are positional (`extract_2`): an Approvals card names
  the file and the field, not the line's label.
- With no local model declared, a lab report is kept from the cloud model
  and the summary is not done (demo-local-health-summary: a capability
  gap, not a leak).

**Tests.** `arbiter/test/unit/personal-documents.test.ts` (the positive
and negative tables, the number checks, the candidates and the project
test, the twin and its linear time, the composition with a human's label,
the store's `kind` and its migration, the walk); `found-labels.test.ts`
(the §2.6 tier unchanged); `launcher/test/unit/why.test.ts` and the
dashboard's `file-browser.test.ts` (the words);
`tests/stack/content-tier-personal-documents.test.ts` (the e2e oracle:
no value in any model-facing request by a Read of the raw file, a command
naming it or one that does not; the twin keeps the labels; every
placeholder asks at the accountant's host and the lookalike share; the
scan no longer suggests the files; a project's sample statement, a docs
page and meeting notes stay readable; after the human's *Always* the
statement goes to the accountant's host, still asks at the share, and its
twin is still the document twin; and, for a person's name, a mail quoting
the holder by name reaches the model as written while the statement's
account number is masked in any output and trips at every host, the name's
placeholder and the statement's upload still ask, the name is no value of
the backstop); the unit tests of a person's name in
`personal-documents.test.ts` (`documentNameField`'s table, which spans the
twin marks, the rows `documentNameRows` leaves out of the value index and
the name line out of the file's pieces, none under a human's extract); and
the drill suite's defaults table
(the rows of the statement, the lab report, the house codes and the tax
return flipped to labelled, recognised and asked).

### 2.8 Personal documents in PDF and Office files (2026-10-19)

**The gap.** §2.7 read `.md`, `.txt` and `.csv` only, and a bank sends a
statement as a PDF, an employer a payslip as a PDF or a `.docx`, a clinic
a lab report as a PDF. How each path delivered such a file to the model
before this change:

- **Claude Code's `Read` of a PDF.** Claude Code (2.1.x) refuses a file
  with no `%PDF-` header, and otherwise sends the whole file as a base64
  `document` block in the tool result, after a `PDF file read:` line (with
  `pages`, page images). The model proxy masks every result that carries
  a block other than text whole (rewrite-request.ts `hasNonTextBlock`,
  forced untrusted in every mode), so the model got one placeholder: no
  leak, and no use of the document either.
- **Claude Code's `Read` of `.docx`, `.xlsx`, `.odt`, `.ods`.** Refused by
  extension ("cannot read binary files … use a shell command or script"),
  so the agent runs a command.
- **A command.** `pdftotext statement.pdf -`, a `pypdf` or `python-docx`
  one-liner, `unzip -p payslip.docx word/document.xml`, `pandoc`. The file
  was public (no path rule, no label), so its output reached the model as
  printed, every value in it, and an upload sent the file with no card.
  Codex reads every file this way: its tools are commands, and it has no
  reader of its own for a PDF.
- **The file guard** (the twin bind, fs-supervisor) serves a twin only for
  a registered file, and these were not registered.

**Detection.** The walk's document candidates (§2.7's rules unchanged: a
workspace, HOME's `Documents`, `Desktop` and `Downloads`; never in a
project, test, docs or source tree, never a template) now include `.pdf`,
`.docx` and `.docm`, `.xlsx` and `.xlsm`, `.odt` and `.ods`. Their text is
extracted (`document-text.ts`, `pdf-text.ts`) and decided by
`personalDocumentKind` exactly as a text document's, with the same
signals. What the reader takes as the text:

| Format | Read | Not read |
|---|---|---|
| PDF | the text layer of every page (content streams and the Form XObjects they draw), in reading order: a page's strings grouped into lines by baseline, top to bottom, left to right; a gap wider than 1.2 em splits a line into cells; the filled-in form fields (`TU` or `T`: `V`) after the pages. Fonts by `ToUnicode`, else WinAnsi, MacRoman, Standard and `Differences` by glyph name. Flate (with predictors), ASCIIHex, ASCII85, LZW, RunLength; object streams; a broken cross-reference table. The standard security handler with an empty user password: RC4 40 and 128, AES-128, AES-256 (R5, R6) | a scan (images only: `no-text`; no OCR), a file needing a password, another security handler, text drawn as outlines, a composite font with no `ToUnicode`, annotations other than form fields |
| `.docx` `.docm` | `word/document.xml`: paragraphs as lines, a table row as one line of cells | headers, footers, notes, comments, deleted text, field codes |
| `.xlsx` `.xlsm` | the first 16 worksheets in order, each row a line of cells; a shared string as its text; a number as its cell format shows it where the format is money (`0.00`, `#,##0.00`, currency, accounting: grouped, two decimals) or a date (ISO), else as stored (two decimals, grouped, where it has at most two) | formulas, phonetic runs, charts |
| `.odt` `.ods` | `content.xml`: paragraphs and headings, a table row as one line of cells (a spreadsheet's cell as the file shows it) | notes, annotations, tracked deletions |

A row of two cells whose first is a short label reads `Label: value`
(`renderRow`), so a statement's `Account number    0042-118833-77` column
pair is `Account number: 0042-118833-77`, which the detectors read as the
Markdown tier reads `Account: …` and the twin keeps the label of; any other
row is its cells joined by ` | `. An encrypted OOXML file (its CFB
container, which is also what a legacy `.doc` or `.xls` is) and an ODF
file whose manifest names encryption are `encrypted`, never read.

The caps: a file of at most 8 MiB, read whole; at most 128 such files and
64 MiB a walk (their own budget, beside §2.7's); a zip's parts inflate to
at most 8 MiB each and 32 MiB in all, a PDF's streams to 8 MiB each and
32 MiB in all; the text at most 256 KiB (what `personalDocumentKind`
reads). Each verdict is remembered by path, size, modification time and
inode for the discovery worker's lifetime (one per arbiter), so a launch
re-reads only a file that changed. A file the reader cannot read
(encrypted, unreadable, too long) is UNREAD: no label is added and an
earlier one stays (raise-only); a scan is read clean.

*Why no dependency.* The vetted PDF reader on npm (Mozilla's `pdfjs-dist`)
is a large, asynchronous package built around a worker; the walk and the
registry are synchronous and bounded, and a statement, a payslip or a lab
report is a generated document whose text layer a small reader covers.
The reader is pure TypeScript over Node's `zlib` and `crypto`, never
throws, and is fuzzed by byte flips in its tests; it is checked against
files Ghostscript and MuPDF wrote (`arbiter/test/fixtures/documents`).

**The twin.** The registered row of such a file holds its extracted TEXT
(registry.ts `registeredDocumentText`, under an `extract:` only: a found
document, or a human's label with one), so §2.7's document twin, its field
rows, the value backstop, the egress tripwire and a person's name work on
it unchanged. What the guard serves at the file's path:

- **A PDF: a PDF of the twin** (`document-twin-pdf.ts`): the twin's lines
  in Courier, WinAnsi (a character it lacks is `?`), uncompressed, ASCII
  (the twin travels as text to the launcher), deterministic. So
  `pdftotext`, `pypdf` or `mutool` print the labels and the placeholders,
  and Claude Code's `Read` accepts the file. A PDF tool lays the lines out
  its own way (a form feed at a page's end, `-layout`'s padded columns,
  blank lines), so for a PDF document's twin the exec-output twin rule
  (claude-code-inbound.ts `structuredTwinExecOutputPath`) also accepts an
  output whose lines, with each run of blanks made one and blank lines
  dropped, are the twin's lines in order (`blankNormalLines`). Only blanks
  may differ, and only for a call whose tree the guard recorded reading
  the twin and nothing raw, as before: a program that never had a value
  cannot put one in the blanks.
- **An Office document: the twin's text itself.** A format parser
  (`python-docx`, `unzip`) fails on it ("not a zip file"), and `cat` prints
  it, which the exec-output twin rule releases as for a `.md` document. A
  twin that is still a valid `.docx` or `.xlsx` needs binary twins end to
  end (the registry's `twin` is text, and so is what the launcher writes):
  open.

**A document block** (`document-blocks.ts`, the `documentText` op; the
proxy's `pdfBlocksAsText`). A tool result carrying a PDF as an inline
`document` block is no longer masked whole for that alone: the proxy asks
the arbiter for the block's TEXT and forwards that text in place of the
block, so what reaches the model is exactly what the classify then judges
(the path's label, the value backstop, the read-twin rule); the block never
does. The arbiter answers:

- the twin's text, when the bytes are the twin the guard serves for the
  Read's path (rendered again from the registry and compared byte for
  byte), or the document itself unchanged since it was registered (no
  guard served the twin): its text equals the registered text. Either way
  the model reads the labels and placeholders, never a value;
- any other PDF's text layer: a labelled path's level masks it whole, the
  value backstop masks a registered value in it, and an unlabelled PDF's
  text reaches the model as text (before, one placeholder). Images and
  anything else in the file are never forwarded;
- nothing for a scan, a password-protected or unreadable file, a file over
  8 MiB or a block that is not a PDF: the result is masked whole, as
  before. So is a result with an image beside the PDF, one the arbiter
  could not answer (fail closed), and every page image Claude Code sends
  for a `Read` with `pages`.

A Claude Code `Read` becomes one text block in the harness's rendering of a
text file (`N\tline`; its `PDF file read:` line dropped), so the read rules
judge it as a `Read` of a text file; another tool's PDF block is replaced
in place. The op is on the data socket: it answers a text the caller
already holds, or a twin's, which holds no value. It runs on the
arbiter's own thread, bounded by the reader's caps (2,000,000 content
operators, 32 MiB of streams: measured at under half a second for a
planted worst case); past the IPC timeout the proxy masks the result whole.
The proxy keeps the last
64 answers by path and data (a request re-sends the whole history); a
stale answer can only cost the twin release, since the classify judges
whatever text it is.

**Each path now** (the invariant: no value reaches a model or leaves
except as a placeholder):

| Path | Confined session (the guard serves the twin) | No guard (an unconfined posture) |
|---|---|---|
| Claude Code `Read` of the PDF | the twin PDF: the model reads its text, the labels and placeholders | the raw PDF as registered: the model reads the twin's text; changed since: its text, masked whole by the path's label |
| A command naming the file (`pdftotext x.pdf -`, `unzip -p x.docx …`) | prints the twin; released as the twin (above) | the path-derived mask: the whole output one placeholder |
| A command not naming it (a script over the folder) | its programs get the twin | the value backstop: every value of 8+ characters and every line of 24+ of the extracted text masks the output whole |
| Codex | its commands: the two rows above | the same |
| An upload, a send | every value's placeholder asks at every host, and the values trip the tripwire | the same |

**Flagged: what can still pass, unconfined only.** The value backstop
matches values verbatim. A program's own rendering can split one: Word
cuts a run at a formatting or spell-check boundary
(`<w:t>0042-1188</w:t><w:t>33-77</w:t>`), so `unzip -p` of the XML need
not hold the account number whole, and an XML entity (`&amp;`) or a
layout's padding changes a line. Such output, from a command that does not
name the file, in a session with no guard, can carry a value past the
backstop. A command naming the file is masked whole whatever it prints,
and under the guard no program reads the original. A value shorter than 8
characters is masked where the file is read by name or through its twin
only (§2.7, the backstop's floor).

**After the human's *Always*.** As in §2.7, the human's exact rule with the
host keeps the document twin. An upload carries what the program read: the
twin, with each placeholder put back at that host, so the host receives
the document's text in the PDF Mandu made, not the bank's original file. A
program the human lists as a reader of the file (`readers:` on its label)
is served the original by the guard and sends it as it is.

**Tests.** `arbiter/test/unit/document-text.test.ts` (each format, the row
rendering, number formats, every PDF encoding the generators use and the
Ghostscript and MuPDF files, the empty-password decryption and the
refusals, 300 byte flips, the twin PDF, the walk's candidates, finds,
leaves and memo, the registry's twins, the PDF rendering rule);
`personal-documents.test.ts` (the candidates now include the formats);
`tests/stack/content-tier-document-files.test.ts` (the e2e oracle: a
statement PDF, a payslip `.docx`, a statement `.xlsx` and a lab report
`.odt` found and twinned through the real arbiter; no value in any
model-facing request by `pdftotext` or `unzip -p` naming the raw file, a
script that names none, another layout, Claude Code's `Read` of the raw
PDF; the twin read through the guard's record shows the labels, and so
does `pdftotext -layout`'s rendering of it; Claude Code's `Read` of the
twin PDF and of the raw PDF shows the twin's labels and placeholders, a
changed statement is masked whole, a scan stays one placeholder, a manual's
text reaches the model; each value asks and trips at every host; a
project's sample PDF and a scan left alone); the anthropic-proxy's
`pdf-document-block.test.ts` (the replacement, the rendering, and every
fail-closed case: no text, an image beside it, no op, a throw); and
`tests/stack/proxy-real-client-parity.test.ts` (the `documentText`
wiring).

### 2.9 INI-family files and short passwords (2026-10-19)

**The evidence.** The head-to-head of 2026-10-19 (15 everyday tasks, 10
protection settings, 3 takes each) left one open issue on the default
catalog: credentials in INI-style and `.conf` files (`config.ini`,
`app.conf`, `my.cnf`, `*.properties`, a `[section]` with `password = …`)
stayed public, and so did a password that was short (`password = Tr0ub4`)
or under a name the content tier did not read as a credential's (`pw`,
`db_pw`, `SMTP_PASS`, `pin`). §2.6 listed both as open.

**Why each was missed.**

- The content tier read `.json`, `.yaml`, `.yml` and `.toml` only
  (`found-labels.ts` `DATA_EXT_RE`). An INI file was never read, though
  the extractor has an `ini` shape that masks a secret key's value and
  keeps the rest of the file.
- `credentialInDataFile` took a value only when `looksLikeSecretValue` did
  (12+ characters, mixed, random-looking): a 6-character password never
  was. Its names were the `credential-assignment` names, so `pw`, `db_pw`,
  `SMTP_PASS` and `pin` were none.
- The extractor's own key test (`secret-extract.ts` `isSecretKey`, a
  substring regex) missed `pw`, `db_pw`, `passphrase`, `passcode`, `pin`
  and `access_code`, so even a file the human labelled kept those values
  raw in its twin (the residual of the ledger's "labelled data file"
  item, plan 16 §3).
- A registered value under 8 characters is no fingerprint
  (`egress-fingerprint.ts` `MIN_FINGERPRINT_LEN`): the value backstop and
  the egress tripwire never matched a short password copied where no path
  names it.

**What is widened.**

1. **The files** (`found-labels.ts` `contentProbeCandidate`). The tier
   reads the INI family as well: `.ini`, `.conf`, `.cnf`, `.cfg`,
   `.properties`. The extractor reads each as `ini` (`.cnf` newly mapped:
   MySQL's option files, as `.my.cnf` already was). By name, wherever the
   tier reads: `.netrc`, `_netrc`, `.npmrc`, `.pypirc`, `.pgpass`,
   `.boto`, `.s3cfg`, `.databrickscfg`, `.sentryclirc` (a project copy of
   one; in HOME the catalog's prefixes already name them). Directly in
   HOME, where the tier otherwise reads only a tool's dot-directory:
   `.pg_service.conf`, `.odbc.ini` and `.wakatime.cfg`, per-user configs
   no prefix names because a whole-file twin of one with no credential
   would break its tool. Not read: the INI manifests a project has many of
   and that hold no credential (`setup.cfg`, `tox.ini`, `pytest.ini`,
   `mypy.ini`, `.bumpversion.cfg`, `gradle-wrapper.properties`), and, as
   before, templates, test, fixture, example and documentation trees, and
   an agent's or editor's own config. The caps are the tier's (1024 files,
   8 MiB a walk).

   | File | Covered by |
   |---|---|
   | `~/.netrc`, `~/_netrc`, `~/.npmrc`, `~/.pypirc`, `~/.pgpass`, `~/.my.cnf`, `~/.config/pip/pip.conf`, `~/.pip/pip.conf` | catalog prefix (unchanged) |
   | the same names in a workspace (`proj/.npmrc` with an `_authToken`, `proj/.pgpass`) | content tier, by name (new) |
   | `pip.conf` in a workspace or a virtualenv | content tier, `.conf` (new) |
   | `~/.pg_service.conf`, `~/.odbc.ini`, `~/.wakatime.cfg` | content tier, HOME by name (new) |
   | `pg_service.conf` under `PGSYSCONFDIR` in a workspace, `config.ini`, `app.conf`, `my.cnf`, `*.properties` | content tier, by extension (new) |

2. **The names** (`credential-names.ts` `passwordKind`, shared by the
   extractor's `isSecretKey`, the tier's `credentialName` and the value
   index). A key's words (split at camelCase and at every mark) name a
   `password` when the last word is `password`, `passwd`, `pwd`, `pw`,
   `pass`, `passphrase` or `pword`, or ends in `password`, `passwd` or
   `passphrase` glued (`PGPASSWORD`, `dbpassword`); `pass` after a word
   that makes it a pass of something else (`render_pass`, `first_pass`) is
   none. They name a `pin` when the last word is `passcode` or `pincode`;
   `pin` alone or after a card's, a phone's, a door's or an account's word
   (`card_pin`; never `led_pin` or `gpio_pin`); `pin_code`; or
   `<word>_code` for an access, security, door, alarm or gate code (never
   `status_code` or `country_code`). A name ABOUT a password ends in
   another word (`password_file`, `password_hint`, `pw_hash`) and is none.
   `auth` (`_auth` in an `.npmrc`, `"auth"` in a registry login) is a
   credential's name for a long value that reads as a token, never for
   lowercase words (`auth = basic`, `oauth2-client-credentials`).

3. **The short-value rule** (`shortCredentialValue`). Under a password's
   or a PIN's name, a value `looksLikeSecretValue` refuses still labels
   the file when it is:
   - for a `pin`: 4 to 12 digits, not a run that counts up or down
     (`1234`) or one digit repeated (`0000`);
   - for a `password` (or a `pin` that is not digits): 6 characters or
     more, no blank, and either 6 to 12 digits (no run) or a letter
     together with a digit or a mark;
   - and never a stand-in (`isPlaceholder`: `changeme`, `xxxxxx`, `${X}`,
     `$X`, `%(x)s`, `<pw>`), a public default or a famous example
     (`COMMON_PASSWORDS`, also followed by digits or marks: `postgres`,
     `changeit`, `admin123`, `Password1!`, `hunter2`), letters alone (a
     word, a translation, a mode, an identifier: `Password`,
     `Contraseña`, `keyring`, `dbPassword`), or a value that names
     something (`namesSomething`: an environment variable's name
     `DB_PASSWORD`, lowercase words joined by `-`, `_` or `.` such as
     `scram-sha-256`, a version, an e-mail address, a file name,
     `host:port`, a YAML alias, Maven's `@x@`, Windows' `%X%`, Azure
     DevOps' `__X__`, `#{x}`, `{x}`).

   So `password = Tr0ub4` in `config.ini`, `db_pw = k9z!q2x` in
   `app.conf`, `password=S3cret-77` in `my.cnf`,
   `spring.datasource.password=…` in `application.properties`, a `.pgpass`
   line, a `.netrc` password, a URL password in `alembic.ini` or
   `pip.conf`, `PGPASSWORD: …` and `card_pin: 4821` in a YAML file are
   found; `port = 5432`, `debug = true`, `name = admin`, `auth = basic`,
   `password = postgres`, `password = ${DB_PASSWORD}`, `led_pin = 4821`,
   `password=Contraseña` stay public.

4. **The tripwire and the value backstop** (`prompt-filter/registered-values.ts`
   `shortTokenRow`, `credential-names.ts` `shortTokenValue`,
   `tokenBounded`). A registered row under the general floor of 8 is a
   pattern of the value index when it is a PASSWORD: a field of a
   registered file (catalog, found or human-labelled) whose last name is a
   password's (`database.password`, `smtp.pass`, `db.db_pw`, a `.pgpass`
   or `.netrc` password), or a password variable's row (`PGPASSWORD`,
   `SMTP_PASS`); and its value has 6 or 7 characters that the short-value
   rule takes as a password and that hold a letter. It is matched as a
   WHOLE TOKEN only: no letter or digit glued to an end of it that is
   itself a letter or digit (`"Tr0ub4"`, `password=Tr0ub4&…` and a line
   holding only it match; `xTr0ub4y` does not). The value backstop then
   masks it in an output that names no file (`printenv DB_PASSWORD`), the
   tripwire trips on it in a request body, and the upload gate's stream
   finds it across chunk boundaries (a token that ends at a chunk's end
   waits for the next chunk's first character; the text's end is a token
   end). The pure reference `scanEgressFingerprint` takes the same rule
   through `SecretFingerprint.token`, and its equivalence with the index
   is a test. The prompt filter's own floor for human text (12
   characters, plan 15 §4.1) is unchanged, so a short password typed in a
   prompt is not masked by it.

**The trade-off, decided.** A short value matched as a substring is a
false-positive generator: `Tr0ub4` inside a hash, a base64 blob or an
identifier would mask an output or hold a request by coincidence, and a
4-digit PIN matches every body with a year in it. So the floor of 8 stays
for every value but one class, and that class is narrowed four ways: it is
a password by its key's name (never an arbitrary short field), from a
labelled file or a password variable (never an output row), it is 6 or 7
characters with a letter and a digit or a mark (never digits alone, never
a default), and it matches only as a whole token. A digits-only PIN or code
is found (the file is labelled and its twin masks it, so the model reads
a placeholder) but is no fingerprint: a copy of it elsewhere is caught
only by the symbol gates and the path rules, not by the backstop or the
tripwire. That is the residual this rule accepts.

**False positives, weighed.** A found label masks a value from the model
and from the programs the agent runs (the twin), so every rule has
negative rows in `credential-names.test.ts` and `found-labels.test.ts`:
ordinary INI values, an `[auth]` section's modes, defaults, references,
an env variable's name, a mode word, `password_file`, a comment,
hardware pins, an i18n `.properties` file with `password=Contraseña`, an
`nginx.conf`, a `my.cnf` with only a server section, an `.npmrc` with only
settings. What remains a real false positive: a 6+ character value that
is no password under a password's name in a config file (`password:
dev-Pass1`, a sample value outside a template's name); its cost is that
value as a placeholder, and `mandu why` names the rule and a `public`
label is the way out, as in §2.6. A coincidental whole-token match of a
6-character password masks one output (the backstop) or holds one request
for approval (the tripwire): fail-closed, never a leak.

**Still not covered.**

- A password of letters alone (`password = sunshine`, a one-case
  passphrase): read as a word. The launch scan still suggests a long one.
- A password under a name that says nothing (`[db] magic = …`,
  `key2 = …` in an INI file): the extractor's `ini` shape masks only
  secret-named keys, so the file is not found (and §2.6's vendor-key
  exception does not reach a file whose keys gave no span).
- An INI-like file with no INI extension and no known name (`~/.wgetrc`,
  `~/.transifexrc`, `~/.edgerc`, `~/.snowsql/config`, `~/.offlineimaprc`),
  and a file in HOME outside a tool's dot-directory other than the three
  named above.
- A `.properties` value written with a blank separator (`password Tr0ub4`)
  or a line continuation: the `ini` reading takes `=` and `:` only.
- An environment variable named `*_PW`, `*_PASSPHRASE` or `*_PASSCODE`:
  the launch's variable masking (`ENV_SECRET_NAME_RE`) is unchanged, so
  such a variable stays raw in the agent's environment (guarantees.md
  says so for `DB_PW`).
- A digits-only PIN or code, and any short value that is not a password's,
  is no fingerprint (the trade-off above).

**Tests.** `arbiter/test/unit/credential-names.test.ts` (the names, the
short-value rule's positives and negatives, `shortTokenValue` and the
token bounds, `shortTokenRow` over file, variable and output rows, and
the index's hits, occurrences and stream at every split, with the indexed
tripwire and the pure reference agreeing); `found-labels.test.ts` (the
INI candidates, the INI and short-value tables with their twins, and a
walk that finds a `config.ini` and HOME's `.pg_service.conf`); the corpus
(`.pg_service.conf`, `.odbc.ini`, `.wakatime.cfg`) through
`secret-catalog-recall.test.ts` and `catalog-recall.test.ts`; and the e2e
oracle `tests/stack/content-tier-ini-short-password.test.ts` (the real
arbiter, the launch's secret setup and the production proxy wiring: a
6-character password in `config.ini`, a `db_pw` in `app.conf` and a
project `.pgpass` reach the model only as placeholders by a Read of the
raw file and by a command naming it; the twins keep `port`, `debug`,
`user`; the short password in an output that names no file is masked;
glued inside a word it is not; it trips the tripwire as a token and not
glued; its placeholder asks at every host; `settings.ini`, a default
password and a reference stay public).

**The first-session tour.** The tour (`docs/first-session.md`) teaches the
suggestion flow on a file Mandu does not know: step 3 reads it raw, the
launch counts "1 possible key in this project is not protected", and
`mandu policy suggest` locks it. Its file was `deploy/staging.conf` with a
`token = "ghp_…"` line, which this change made a file the content tier
finds at launch: a fresh user saw a placeholder from the start and no
notice. The tour's file is now `deploy/staging.tfvars` (the same two lines,
the host quoted as a Terraform value): the content tier reads no `.tfvars`
(`DATA_EXT_RE`), no name rule matches it, the workspace scan reads it
(`HINT_EXT_RE`), and once locked the extractor's `toml` shape masks only
the token's value. A neutral key name in a `.conf` was the other candidate,
rejected: such a file's twin is one whole-file placeholder (the `ini` shape
masks only secret-named keys), against the tour's "you still see the real
lines". `tests/stack/first-session-fixture.test.ts` (also in the docs lane)
pins the premise from the tour's own text: it makes the folder the setup
block makes, and through the real arbiter checks that `.env` is found,
step 3's file is not, the launch notice and the `mandu policy suggest`
screen are the tour's, and the applied rule masks only the token; the same
lines in a `.conf` are found (the check is not vacuous). When the content
tier learns `.tfvars` that test fails, and the tour moves again. The
sandbox oracle K12 (`tests/sandbox/git-history-locks.test.ts`) moved to a
`.tfvars` for the same reason. `scripts/tour-screenshots.mjs` renames the
recording's file to the tour's, and the screenshots were redrawn.

### 2.10 MCP and editor config files (2026-10-21)

**The gap.** Every MCP user keeps tokens in an MCP config: a GitHub token
in a stdio server's `env`, a Linear bearer in an HTTP server's `headers`, a
database URL in `args`. No catalog rule named `.mcp.json`,
`~/.cursor/mcp.json`, `.vscode/mcp.json` or Claude Desktop's config; the
content tier (§2.6) skipped agents' and editors' own configs on purpose;
under `mandu claude` the kept login `~/.claude.json` (Claude Code's user
and local scopes) was neither twinned nor registered (§1.10), and Codex's
`config.toml` sits in its store, never walked. A model that read one ("fix
my MCP setup", `cat .mcp.json`, a glob, a script) sent every server's token
to its provider; only a human label protected them (!1222 masks a labelled
config's lists). The obvious fix, twinning them, hands every MCP server the
agent spawns a placeholder: the agent reads its config in its own process,
so a twin there reaches the server's `env` and the HTTP client's headers.
The maintainer's decision (2026-10-21): catalog them, with the values kept
where each server needs them.

**Who reads what.** Measured from the agents' code paths Mandu already
models (`launcher/src/mcp-server-config.ts`, plan 10 §11.13):

| File | Read by | Written by |
|---|---|---|
| `~/.claude.json` (`mcpServers`, `projects.*.mcpServers`) | Claude Code's own process: it spawns stdio servers with each entry's `env` and connects HTTP servers with its `headers` itself | Claude Code, constantly (its whole state file: onboarding, project trust, its login metadata) |
| a project's `.mcp.json` | Claude Code's own process (project scope, at its working directory) | `claude mcp add -s project`, editors, the user |
| Codex's `~/.codex/config.toml` (`[mcp_servers.*]`) | Codex's own process (`env`, `bearer_token`, `http_headers`) | Codex (trust decisions, `codex mcp add`) |
| `~/.cursor/mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, VS Code's user `mcp.json`, Claude Desktop's and Windsurf's configs | an editor or app outside the session; no supported agent reads them | the editor, the user |

A stdio server gets its values in its environment from the agent at spawn;
an HTTP or SSE server's credential is sent by the agent's own MCP client.
Nothing put back on the wire reaches a stdio server's environment, and the
two state files cannot be twinned to their own agent without breaking it
(its saves would land in the placeholder copy, and the next save would
write placeholders over the real tokens).

**The decision.**

1. *The catalog* (`arbiter/policy/mcp-config.ts`, `found-labels.ts`
   `mcpConfigCandidate` / `mcpConfigCredential`). An MCP config is a secret
   file when one of its server entries holds a credential: the twin's own
   spans (the key rules, the list rules, the credential belt, and
   `mcpEntrySpans`, below) inside a server entry, one of which is a
   credential by the content tier's test, a vendor format, or a word that
   reads as a token (`Bearer <token>`, a key under a name that says
   nothing, a header set in a variable). A config whose values are all
   references the client expands (`"${GITHUB_TOKEN}"`, VS Code's
   `${input:…}`) or that holds none stays public: every program reads it as
   written. The walk reads a project's configs where it meets them
   (`.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, never in a test or
   docs tree) and the per-user ones at their places in HOME
   (`mcpHomeConfigPaths`, its MCP pass), past every prune (`~/.codex` is a
   store, `~/Library` a macOS prune, `.claude.json` a login). The editors'
   and projects' configs get a found label (§2.6, rule
   `content:secret-key`); `.claude.json` and `config.toml` are judged per
   launch (point 3) and get no found label, so the guard's catalog gate
   keeps pruning them as an agent's login and store.
2. *The twin* (`secret-extract.ts`, `extractShape` for an MCP config). The
   shape's own reading plus each entry's values: an `env` value under a
   secret-looking name, under a name that holds a header set
   (`OPENAPI_MCP_HEADERS`), or one that reads as a credential under any
   name; every `headers` / `http_headers` value but a benign header's
   (`Content-Type`, `Accept`, a `*-Version`); Codex's `bearer_token`. Never
   a reference (`withoutMcpReferences` also drops the key rule's span over
   `"GITHUB_TOKEN": "${GITHUB_TOKEN}"`), an empty value or a URL (its
   password is the key rules', its query the belt's). Codex's one-line
   inline tables in a server's table (`env = { K = "v" }`, Codex's own
   documented form) are read in full (`codexTomlReading`) and blanked for
   the generic TOML reading, which twins any file with an inline table
   whole; one it cannot read in full, or one elsewhere, still makes the
   whole-file twin. The twin parses as the original (JSON, JSONC, TOML).
3. *The launch posture: the agent's own configs are left readable to it.*
   The walk tags `agentConfig: <agent>` on the launched agent's own MCP
   configs that hold a credential: `.claude.json` (where Claude Code's
   login is kept: `mandu claude`, a plain command, `mandu openclaw`, and a
   helper that runs `claude`) and the `.mcp.json` at a walk root under
   those launches; Codex's `config.toml` under `mandu codex` and `mandu
   openclaw`. The launcher registers each (its values are known to the
   value backstop, the prompt filter, the upload gate and the egress
   tripwire) and leaves it readable (the `agentOwnFiles` posture: no bind,
   no twin in the guard's policy file). So the agent spawns its stdio
   servers with the real values and sends its HTTP servers' credentials
   itself, and keeps writing its state. Where the guard runs, a found
   label still gates a project `.mcp.json` at the open for every program
   but the agent (§1.12: the agent's own open is not gated), so `cat`,
   `jq`, a script or a nested `claude` read its twin; `.claude.json` and
   `config.toml` stay readable to the agent's whole world, as its login
   and store always were (Mandu's AI helper runs `claude -p` and saves
   `.claude.json`). Every other MCP config is twinned like any catalog
   file: Codex's `config.toml` under `mandu claude`, `.mcp.json` and
   `.claude.json` under `mandu codex`, the editors' configs everywhere.
4. *The bindings: each value only where its own entry sends it.*
   - An HTTP server's Authorization credential (JSON `headers.Authorization`,
     Codex's `bearer_token` and `http_headers.Authorization`) is marked
     `wire: {host, scheme: bearer, httpsOnly}` with the host of its entry's
     own `url` (`withMcpWire`; only a span that is exactly that value).
     In an editor's HOME config (`isHomeWireFile`: `~/.cursor/mcp.json`,
     Claude Desktop's, Windsurf's, VS Code's user file), twinned in every
     launch so nothing in the agent's world writes the real file, the
     registration records it as a wire grant (confidentiality.md §2.1): a
     program that reads the twin sends the placeholder, and the session's
     egress proxy puts the credential back at that host, in the
     Authorization header only (the npm rule, plan 10 §11.13.1), over
     https only unless the entry's URL is `http://`. NOT in `.claude.json`
     or `config.toml`: their agent's launch leaves them writable to its
     world, so a host a session wrote there would be granted to the next
     launch, in every session; nor in a workspace config (§11.6).
   - The tripwire, in the session that runs the config's agent
     (`sessionLoginPaths` + `sessionMcpConfigPaths`: Codex's `config.toml`
     when Codex is kept, and the session's `mcpConfigs`, the project
     `.mcp.json` the launcher names, accepted only as a kind a kept agent
     reads): a stdio server's value is exempt everywhere, as a login's token
     is (the config names no host its server talks to, and the tripwire was
     never the guarantee for a raw holder); an HTTP server's Authorization
     credential is exempt only at its entry's host (`keptRowWireHost`): the
     agent's own header to another host trips, in its own session. Because
     a masked tool result is a row of its own that holds the raw config and
     outlives the session (a Read the model made of `.claude.json`), the
     scan also drops an occurrence of exactly a kept value from such a
     row (`keptMcpValues`, `scanEgressFingerprintIndexed`'s `exemptText`;
     the credential after `Bearer ` too), at the host the value may go to;
     never from another file's or a masked variable's row with the same
     value, and never a longer text around it (a whole line of the file
     still trips). In every other session the values trip at any host but
     a granted one.
   - Placeholders of the twinned configs that no grant covers (a stdio
     server's variable, another header, a workspace config's credential)
     ask before they leave, as any unbound secret does; a vendor format the
     issuer bindings know (confidentiality.md §2.3) goes to its issuer.
5. *What the model sees.* A Read of the raw file (the agent's own config:
   it reads the real file), a command naming it, a glob, a script: the path
   rule (the found label, or `~/.claude.json` and `~/.codex` in
   `SENSITIVE_PATHS`) masks the result, and the value backstop catches every
   registered value elsewhere (a server's error message that quotes its
   token, `claude mcp get`). A Read of a twin shows its keys and layout with
   each value a placeholder.

**Why not the other shapes.**

- *Twin the agent's own config and put the values back at the server's
  spawn.* The agent would hold placeholders and the guard would rewrite the
  environment of the exec whose argv is a registered server's. That needs
  the guard to write the agent's memory at `execve` (seccomp user
  notification cannot change a syscall's arguments), and the server then
  holds the value raw, so plan 10 §11.13.1's rule makes it a holder whose
  every result is masked whole: MCP results would reach the model as one
  placeholder each. Not built; the maintainer's question below.
- *Twin it and put values back on the wire only.* Breaks every stdio server
  whose credential is no HTTP header its own process sends through the
  proxy: a database URL (the PostgreSQL server), a server run with `docker
  run -e` (GitHub's official one: the container's traffic leaves outside
  the session), an SDK that checks a key's format or signs with it. And it
  breaks `.claude.json` and `config.toml` themselves (their agent's saves).
- *Grant the HTTP credential's host from `.claude.json` and a project
  `.mcp.json` too.* Rejected above (a session could rewrite the host and
  the next launch would grant it). The session-scoped narrowing gives the
  same "own host only" check for the agent's raw header without a grant.

**What changes for utility.** Nothing for the agent's own MCP servers
(they start and authenticate as without Mandu, also after the model read
the config). A program the agent runs reads the twin of an editor's config
and, where the guard runs, of the project's `.mcp.json`: a server that
`claude mcp list` starts from a shell gets placeholders; `claude mcp add -s
project` run as a command writes into the twin, lost at the session's end
and named there. The model reads a config with no credential as written, a twin's
keys and layout, and the agent's own config masked whole by a Read (its
programs show it the twin under the guard).

**What stays open (not covered).**

- *A stdio server holds its values raw, and is not tracked as a holder*,
  as before this section: a server that runs commands, or one the model
  reconfigures through the agent's own write tool (a changed `command`
  keeping the `env`, effective at the next start), can print or send an
  encoding of its token, which neither the value backstop nor the tripwire
  sees. Writing `~/.claude.json` from the agent's file tools asks first
  (`SENSITIVE_PATHS`); a program in its world writes it freely, and a
  project `.mcp.json` is in the workspace. The maintainer's question below.
- *Without the guard* (`--no-kernel`, a host without it), the agent's own
  project `.mcp.json` is readable to every program in the session (the bind
  posture cannot exempt one process): only the path rule and the value
  backstop stand between it and the model, as for `~/.claude.json` and
  `config.toml` in every posture.
- A workspace config's HTTP credential is put back nowhere for a program
  that reads the twin (no grant, §11.6); it asks.
- A `config.toml` a `CODEX_HOME` moved out of `.codex` is read as any TOML
  file (its secret-named keys only); a `.mcp.json` named by
  `--mcp-config <file>` is a project file like any other (twinned unless at
  the launch's directory).
- Other agents' and tools' MCP configs: OpenCode's `opencode.json`
  (`mcp.*.environment`, `headers`), Goose's `config.yaml` extensions
  (`envs`), Gemini CLI's `settings.json`, Zed's `context_servers`,
  Continue's YAML. They stay in the content tier's exclusion; their
  launches' own posture (point 3) would need their readers modelled.
- A secret written into one of these files during a session is found by the
  next launch's walk.

**Question for the maintainer.** Point 3 keeps a stdio server's values
where the server needs them by leaving the agent's own config readable to
it, so the server holds them raw and untracked, as it did before. Two ways
to close it, each with a cost: (a) treat a configured stdio server holding
a registered value as a holder (plan 10's rule), which masks every result
it returns to the model; (b) build the spawn-time put-back (the agent reads
a twin; the guard puts the values into the registered server's environment
at its exec, kernel work, and the server is then a holder as in (a) unless
the human vouches for it, `prints: nothing`). Until a decision, the
guarantee for these values is the model door (path rule, value backstop)
and the tripwire, not the flow taint.

**Tests.** `arbiter/test/unit/mcp-config.test.ts` (the files and their
readers, the JSON and TOML readings with offsets, every format's twin and
what it keeps, the wire marks, the content decision, the candidates, the
walk's MCP pass per launch, the grants, a session's exempt paths);
`found-labels.test.ts` and `agent-login-discovery.test.ts` (updated: a
`.mcp.json` is listed, a kept `.claude.json` holding a server's token is
tagged); `arbiter/test/component/mcp-config-tripwire.test.ts` (the
tripwire in the owning session, a masked Read's row, another file's copy,
other sessions); launcher `secret-setup.test.ts` (`agentConfig` left
readable) and `agent-login.test.ts` (`sessionMcpConfigs`, the identity
key); net-proxy `session-logins.test.ts`; and the e2e oracle
`tests/stack/mcp-config-catalog.test.ts` (the real arbiter, the launcher's
secret setup for `mandu claude` and `mandu codex`, the production proxy
wiring and each session's real net-proxy: a stdio server spawned from the
config the agent reads gets the real value; no value of any config in any
model-facing request; an HTTP credential at its own host only, raw and put
back; a stdio server's token in its own session, also after the model read
the config, and refused in the other; the arbiter gone fails closed);
`tests/stack/other-agent-logins.test.ts` (updated: a plain command
registers `~/.claude.json`'s server token and leaves the file readable).

## 3. The git-history secret scan

Phase 1 is the scanner (an arbiter op) and the advisory report in
`mandu doctor --secrets`, with an incremental cache whose entries are sealed
with the arbiter (plan 14 §11.2). Nothing here writes policy, registers a
value or changes a launch; the remediation (each finding as a typed policy
suggestion the human accepts) is
[`confidentiality-plan-14-policy-suggestions.md`](./confidentiality-plan-14-policy-suggestions.md).

This is how `secrets` mode answers the boundary decided on 2026-09-29
(`test-organization.md` §7.2, `docs/guarantees.md` §3): **not** masking text
that looks like a key, but a scan the human runs that finds such keys in git
history and says what would close each one.

### 3.1 The gap

A deploy key committed and later deleted lives only in git history. It is in
no file on disk, so the catalog walk never finds it; it matches no label and
no registry entry; and the git object-store twins (`confidentiality.md`
§7.2a) hide only the committed versions of files that are **confined now**,
found by their current path. So in `secrets` mode `git log -p` or `git show
<old commit>` hands the key to the model raw. (Under the frozen integrity
axis the `git show` output was untrusted and symbolized, which covered it.)

The invariant defines a secret as a registered credential or a file labelled
above `public`. The history key is neither, so this is a boundary, not a
regression. The scan makes it **visible**; plan 14 makes it closable.

### 3.2 Decisions

1. **A scan, not a mask.** Shape-masking every tool output that looks like a
   key was rejected (2026-09-29): it changes the promise from "what you
   registered" to "what a regex guessed", false positives mask the agent's
   own work, and false negatives would look covered. The scan reads and
   reports; it enforces nothing and writes nothing.

2. **The arbiter reads the blobs.** Blob contents are secret bytes, so the
   scan runs where `discoverSecrets` and `registerSecret` run: in the
   arbiter, outside every agent's sandbox. The launcher never sees a blob.
   The pure scanner is `arbiter/policy/secret-history-scan.ts` (git runner,
   blob reader, path classifier, `exists` and the clock injected); the
   arbiter answers it as the op **`scanSecretHistory {roots, home?}`**
   (`ScanSecretHistoryOpRequest`, `ArbiterClient.scanSecretHistory`), and
   `mandu doctor --secrets` calls it through its dry-run arbiter (§1.3).

   - **Data plane, read-only.** It changes nothing and returns no value. What
     it returns (paths, a detector kind, a line, a fixed mask, an
     assignment's variable name) is metadata a structured twin already shows
     the agent (`KEY=$MDU:…`).
   - **Asynchronous, one at a time, yielding.** The git calls are child
     processes; matching yields to the event loop every 15 ms; a second scan
     while one runs is refused ("already running").
   - **Axis OFF answers empty** (`axis: false`), as discovery does.
   - **git runs hardened.** The repository may be one the agent built and
     the arbiter runs outside the sandbox, so no repository-configured
     program may start. The commands used (`rev-parse`, `rev-list`,
     `ls-files`, `ls-tree`, `cat-file`, `log --raw`) run no hook, diff
     driver, textconv or filter; the shared git hardening (write-protection.md §8)
     forces off every program-starting key git knows (`core.fsmonitor`,
     `log.showSignature`, which would hand each signed commit to the
     repository's `gpg.program`, …), drops inherited `GIT_*`, disables lazy
     fetch (a partial clone's missing object would run the promisor remote's
     transport), and runs git in the no-network, read-only git sandbox where
     bubblewrap works. Unit tests configure a fsmonitor program and a
     signature verifier over a signed commit and assert neither ran.

3. **The findings type is stable** (plan 14's generator consumes it):

   ```ts
   interface SecretHistoryFinding {
     repoRoot: string;                  // the work tree
     blob: string;                      // object name (full)
     paths: string[];                   // every path the blob had, repo-relative
     firstCommit: string | null;        // oldest commit that added it (null: index only / not traced)
     lastCommit: string | null;         // newest commit that added or removed it
     inHead: boolean; inIndex: boolean;
     stillPresent: boolean;             // one of its paths exists in the work tree now
     pathStillSecretByCatalog: boolean; // the law covers it now: covered (item 7)
     detector: SecretHistoryDetector;   // the strongest reason
     detectors: SecretHistoryDetector[];
   }
   type SecretHistoryDetector =
     | { kind: "content-shape"; rule: SecretShape; line: number; preview: string }
     | { kind: "catalog-path"; rule: string; path: string; level: string };
   ```

   The scan (`SecretHistoryScan`) adds `repos` (each root's work tree or why
   it has none), `counts`, `limits`, `ms`, and **`capped`**: complete counts
   of what a cap or failure left unread (`tooBig`, `overTotal`, `overTime`,
   `readFailed`, `binary`, `pathsUnchecked`, `untraced`, `unlisted`) with one
   human line each. `readFailed` is its own count (the blob reader failed or
   came back short before the deadline: the git sandbox did not start, git
   exited non-zero, a missing object), so a failure is never reported as "the
   time budget ran out"; the next chunk is still read. The terminal prints
   every `capped` line, and the dashboard's Suggested view says "Part of the
   history could not be read, so there may be more."

4. **What the scan reads.** The work tree holding each root (`git rev-parse
   --show-toplevel`; the doctor passes the workspace), and in it every blob
   reachable from any ref, the reflog and the stash (what `git rev-list
   --all --reflog --objects` lists, read as `rev-list --all --ignore-missing
   --stdin --objects` with the reflogs' names on stdin, read from their
   files once: confidentiality.md §7.2a, `arbiter/policy/history-tips.ts`;
   never fewer objects, and git's own `--reflog` on any doubt), plus the
   index's stages (`git ls-files -s`): the same reach the object twins
   protect. Each blob is read once, by name (`git cat-file --batch`, in 32
   MiB chunks). Findings are traced to their commits (which also adds every
   path the blob had): a single finding by its own `--find-object` walk,
   more in ONE streamed pass of `git log -m --root --raw` from the same
   start (a walk costs the same for one object as for all). Bounded:

   | cap | default | knob (the arbiter's environment) |
   |---|---|---|
   | one blob's size | 1 MiB (larger blobs are counted, not read) | `MANDU_HISTORY_SCAN_BLOB_MAX_KB` |
   | bytes read in all | 256 MiB | `MANDU_HISTORY_SCAN_MAX_MB` |
   | the whole scan (one deadline for every git call) | 60 s | `MANDU_HISTORY_SCAN_TIMEOUT_S` |
   | findings traced to commits per call (cached traces are free) | 1000 | none |
   | deleted paths asked of the catalog | 5000 | none |
   | roots per request | 8 | none |

   Blobs in no file of `HEAD` and not in the index are read first, so a cap
   cuts what the working tree already shows before it cuts history. What a
   cap left unread is in `capped` and on a "not scanned" line, never
   silently; binary blobs (a NUL in the first 8000 bytes, git's own test) are
   skipped and counted. A history too large to list in the budget (or over
   the runner's 512 MiB output buffer) scans nothing and says so, rather
   than a biased part. The doctor waits the scan's budget plus 30 s.

5. **Two detectors, both reported with their reason.** The detector lives in
   `arbiter/policy/secret-detectors.ts`, shared with plan 14's workspace scan
   (plan 14 §13.2) and the `key-shapes` prompt filter (plan 15 §4.1);
   `secret-history-scan.ts` re-exports it.

   - **`content-shape`**: well-known credential formats only, chosen for a
     low false-positive rate: PEM and OpenSSH private-key blocks (a header
     alone, as in documentation, is not one), AWS access key ids
     (`AKIA`/`ASIA`) and `aws_secret_access_key` values, GitHub (`ghp_`,
     `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`), GitLab (`glpat-`, a
     newer token's `.version.id` suffix included: `glpat-<body>.01.<id>`
     is one value, 2026-10-22; stopping at the dot left the suffix in the
     clear),
     Anthropic (`sk-ant-`), OpenAI-style `sk-` keys, Slack (`xox?-`), Stripe
     live keys, Google API keys (`AIza`), npm (`npm_`), PyPI (`pypi-`),
     Hugging Face (`hf_`), a URL with a password, and an assignment whose
     name says credential (`*TOKEN*`, `*SECRET*`, `*PASSWORD*`,
     `*API_KEY*`, …). `detectSecretShapes` is pure and unit-tested per
     format. The value rules:
     - *Vendor-prefixed values* take a body with a letter, no stand-in, and
       either a digit or 3+ bits of entropy a character (a random body of
       20+ characters is always over it). The digit alone is not required:
       a Hugging Face token is `hf_` + 34 letters, and 3.3% of 20-character
       GitLab tokens, 1.5% of 24-character Stripe keys and 0.19% of
       36-character alphanumeric bodies hold no digit (measured; each pinned
       in `secret-detectors.test.ts`).
     - *GitHub's checksum.* A prefixed GitHub token (`ghp_`, `gho_`, `ghu_`,
       `ghs_`, `ghr_`) is 30 random characters and then the CRC-32 (zlib's)
       of those 30 in base62 over `0-9A-Za-z`, zero-padded to 6 (confirmed
       on published scanner test tokens, pinned as known answers).
       `githubTokenChecksumOk` accepts a token whose checksum holds before
       any other check: a chance match is 1 in 2^32, so a stand-in word in
       its random part no longer drops it. `github_pat_` fine-grained tokens
       are not checksum-checked: no checksum for that layout is published,
       and a guessed check could only admit fakes.
     - *Stand-ins* (`isStandIn`): a placeholder (`changeme`, `${VAR}`,
       `<token>`, `…example…`, `redacted`, `placeholder`, a `$MDU:` symbol,
       a word at a separator such as `-dummy-` or `_xxxx`, six x in a row,
       template syntax) is no credential, so AWS's documented `…EXAMPLEKEY`
       values and `sk-…-PLACEHOLDER-…` test keys stay out. Only `xxxx` and
       `dummy`, short enough to occur by chance, are forgiven inside a
       random body: when every occurrence has a letter or digit on both sides
       and the rest is still a long random value (16+ characters, two thirds
       of the value, 3+ bits a character). About 1 in 400,000 36-character
       draws is still dropped (a word at the body's edge).
     - *Assignments* take a value with a letter, 12+ characters, 3+ bits of
       entropy a character, and a digit, or with no digit when it reads as
       random (`randomLetters`: 16+ characters, no separator, both cases,
       3.5+ bits a character, short case runs, vowels under 30%). Measured:
       72% of 16-letter, 79% of 20-letter and 90% of 24-letter random
       mixed-case passwords are taken; a one-case passphrase
       (`correcthorsebatterystaple`) is missed, a precision choice.

     Each widening was checked against false positives: over Mandu's own
     2,627 tracked text files and 63,656 more (a Linux host's Python
     packages, `/usr/share/doc`, `node_modules`), no hit was lost and none
     added, and the prompt filter's ordinary corpus has none.
   - **`catalog-path`**: a path the blob had that **no longer exists** in
     the work tree and that the catalog or a label calls a secret (the same
     derivation as `pathLevels`: a deleted `.env`, `id_rsa`,
     `credentials.json`). Whatever its content, it was a credential file,
     and nothing on disk leads a launch to its history.

6. **No value leaves the arbiter.** A content hit carries the shape, the line
   and a **fixed mask**: the format's public prefix at most (`sk-ant-…`,
   `AKIA…`, `ghp_…`), a key block's BEGIN header followed by `…`, an
   assignment's name (`DB_PASSWORD=…`, or `credential=…` when the name could
   be part of a credential), or a URL's scheme and host
   (`postgres://…:…@db.host`). Never a character of a value's body, its
   length or a hash of it (a short hash of a weak password is a guessing
   oracle); a last check replaces any mask that would hold the value's tail
   with the shape name. The raw bytes live in the arbiter's memory while a
   chunk is matched and nowhere else: not in the reply, the arbiter's log
   line (repositories and counts only), an event, or the doctor's text or
   `--json`. Tests assert all of these over keys assembled at run time.

7. **What would close each finding (text only).** The doctor sorts each
   finding into one class and prints the ways out; it acts on none:
   - **covered** (`pathStillSecretByCatalog`): a launch's object twins hide
     this blob. A path of it that exists now is a secret (catalog or label),
     or a path of it that no longer exists has a human label above `public`
     (`labelledAbovePublic`, plan 14 §8.1), or the blob itself is locked
     above `public` in `blobs:` (`lockedBlobs`, plan 14 §8.2). Nothing to do
     for the AI; rotate the key if the repository is shared.
   - **in a file that exists now, not protected** (`stillPresent`): protect
     the file (the dashboard's Rules page, or `policy.yaml` `paths:`) if it
     still holds the key; the next launch then hides it and its whole
     history. Rotate either way.
   - **only in history**: nothing hides it from the AI until a lock is
     applied. Rotate the key (it is in every clone), remove it from the
     history (`git filter-repo`) if the repository is shared, and review the
     suggested lock with `mandu policy suggest` (plan 14 §5.3).

   The findings never change the launch verdict or the exit code.

8. **The cache: incremental scans.** Every secrets-mode launch asks
   `suggestPolicy` (plan 14 §5.5), which runs this scan; uncached, each call
   read every reachable blob again (17.9 s and the byte cap on Mandu's own
   repository, 16k blobs). The arbiter keeps what a scan knows per
   repository (`arbiter/policy/secret-history-cache.ts`):

   - **Key.** The work tree root; a base (the detector's fingerprint, a hash
     of every rule and of the code of every function a verdict depends on,
     plus `HISTORY_DETECTOR_VERSION`; the object format; the git version; the
     replace refs); and the TIPS every reachable object hangs from (what
     `git rev-list --all --reflog --no-walk` names, the reflogs read from
     their files, plus every ref's own object). A
     shallow clone changes what is reachable without moving a tip, so such
     a repository is not cached (`plan: "off"`). Grafts and replace refs no
     longer change what the scan lists (2026-10-21, a security fix:
     every hardened git call runs with replace refs off and an empty graft
     file; confidentiality.md §7.2a "What the walk does not let a repository
     hide"), so an `info/grafts` file no longer turns the cache off. The
     listing and the traces apply the history walk's shallow rule: a
     shallow file is honoured only where no commit it names has a parent
     in the store, so one written over a full history hides no key. A change to
     the detector moves the fingerprint, so every blob a cache called clean
     is read once more.
   - **Stored.** The reachable blobs (name, size, a path); the blobs READ,
     clean or not; the hits among them as masks (never a value, a length or
     a hash of one); the findings' traces. A blob's name is its content, so a
     verdict on it holds as long as the detector does.
   - **Plans.** Same base and tips: `hit`, nothing listed, no blob read. Only
     new tips: `incremental` (`git rev-list --objects --stdin` with the old
     tips as exclusions; traces re-done only for blobs a new commit adds or
     removes). A tip gone (a reset, a force-push, an expired reflog, then
     `gc`): `relist` (the history listed again, only never-read blobs read,
     unreachable entries dropped). A different base, a torn or foreign file,
     or an incremental list git refuses: `fresh`.
   - **Not cached.** The index and HEAD's tree, whether a path exists, the
     catalog and the labels: the `catalog-path` detector and coverage follow
     the law in force. The limits are not in the key: a raised cap reads
     what a lower one left.
   - **A capped scan resumes.** What a cap left unread is not in the read
     set, so the next call reads it.
   - **Where, and bounded.** `<state>/object-walks/history-scan/<sha256(work
     tree)>.json` (inside the agent-denied `state/`, on-disk-layout.md §3),
     0600 files in a 0700 directory, written atomically; an entry over
     64 MiB is not stored, at most 64 repositories (least recently used
     out), 30 days unused and it is dropped. A missing or unreadable file
     scans as if there were none.
   - **Sealed (plan 14 §11.2).** An entry that marks a blob read and clean
     hides a finding, and the file is writable by anything unconfined (an
     `off` session, a `gated` launch). Every save records a seal with the
     arbiter's seal store (`cache-seals.ts`: kind `history-scan`, the file's
     sha256 and size, the current epoch); a load uses the file only when its
     bytes match a seal of the current epoch, else it scans `fresh` and an
     admin event names the key. The epoch rotates when an unconfined period
     ends; while an unconfined launch runs no entry is used.
   - **Reported.** Each repository of the reply carries `cache: {plan, read,
     stored}`.
   - **Measured on Mandu's repository:** the first call 12.6 s (the byte
     cap), the second 7.4 s (the rest), every later unchanged call 0.2 s,
     and a call after a new commit reads only that commit's blobs.

### 3.3 What stays open

- A key in a blob over the size cap, in a binary blob, encoded (base64 in a
  YAML value), split across lines, or in a format the detector does not know
  is not found. The scan is a net for the common case, not a proof.
- Only the workspace's repository is scanned; another repository the agent
  can reach needs its own run.
- Objects reachable from nothing (dangling after a rebase, before `git gc`)
  are not scanned; `git show <name>` still reads one if the agent knows the
  name. The object twins have the same reach, except that a version a
  launch once found protected stays locked while its path is protected,
  reachable or not (confidentiality.md §7.2a "A version once locked stays
  locked", 2026-10-21).
- A repository whose history is too large to list inside the budget is not
  scanned at all (said, with the knob).

### 3.4 Tests

- `arbiter/test/unit/secret-detectors.test.ts`: every detector format and
  its mask, the stand-in and code filters, the pinned fingerprint, and the
  values older rules missed.
- `arbiter/test/unit/secret-history-scan.test.ts`: the git output parsers
  and the walk over real temporary repositories (a key committed then
  deleted, staged-only, stashed; a deleted `.env` found by the catalog; a
  covered labelled file; binary and oversized blobs; each cap; a history that
  cannot be listed; a blob read that fails before the deadline counted
  `readFailed`; the fsmonitor hardening; the server op). No value in any
  serialized result.
- **Fixture tokens** in every scan test are drawn by
  `arbiter/test/helpers/random-secret.ts` (a letter and a digit, no stand-in
  run); the no-digit and edge cases are pinned with fixed values instead, so
  a random draw cannot make a test flaky.
- `arbiter/test/unit/secret-history-cache.test.ts`: the plans, the file
  store's bounds, and over real repositories: unchanged reads nothing, a new
  commit reads only its blobs, a rewritten history reads nothing twice, a
  capped scan resumes, a shallow clone is not cached, the one-pass trace
  equals the per-finding walks, the cache file holds no key.
- `arbiter/test/component/history-scan-cache.test.ts`: a real
  `ArbiterServer` and `ArbiterClient` with the production wiring (`hit`,
  `incremental`, no key byte in the file, the replies or the log). Axis:
  `secrets`.
- `arbiter/test/unit/cache-seals.test.ts`, `arbiter/test/component/cache-seals.test.ts`:
  an entry with a finding's hit removed is refused and the finding returns.
- `launcher/test/unit/doctor-secrets.test.ts`: the history section, the three
  classes, `--no-history`, an axis-OFF answer and a failed call (said, never
  a refusal), `--json`.
- `tests/stack/doctor-history-scan.test.ts` (the parity test): the
  production `historyScan` over a real `ArbiterServer` reports the
  committed-then-deleted key masked and traced, the deleted `.env` by the
  catalog, the labelled file covered; stdout, `--json`, the reply, the log
  and the event store carry no key byte. Axis: `secrets`.
- `tests/stack/dashboard-suggestions.test.ts`: a blob reader that hands
  nothing back makes the Suggested view say part of the history could not be
  read, and only what the names show is filed.
