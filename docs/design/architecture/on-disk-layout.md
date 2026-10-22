# On-disk layout: one Mandu home

Decision note, BUILT (2026-09-29; every phase of §7). Where Mandu keeps what
it stores, who may read it, and why an older layout is not carried over.
Supersedes the per-feature choices recorded in `runtime-instances.md` §12
(events under `XDG_STATE_HOME`), `packaging.md` (config under
`XDG_CONFIG_HOME`) and `fs-sync.md §3` (the `~/.mandu` state base).

## 1. Why change

**Two stores of plaintext secrets were readable by the agent (a security
regression, found by code reading; confirmed by the phase 1 oracle, which
fails on the pre-fix code; fixed by phase 1).**
Mandu's invariant is that a secret reaches the agent only as a `$MDU:` symbol.
Two files hold the originals:

- `~/.mandu/mandu.db`: the symbol table's `symbols.value` column
  (`arbiter/symbol-table/symbol-table.ts` ~130-146), including whole protected
  files registered as secrets (`arbiter/secret-registry/registry.ts` ~115-127).
- The event log (then under the XDG state dir): `DualRepr.original`
  and `SeededFile.content` carry originals by design, "a human-facing surface"
  (`dashboard/src/event-model.ts` ~57-63, ~287).

Nothing denied the agent READ access to either. The whole-agent wrap binds the
host filesystem (`--dev-bind / /`, `launcher/src/secret-twins.ts` ~204); the
guard's read-deny list holds only `~/.mandu/workspaces`
(`launcher/src/secret-setup.ts` ~808; `interceptors/net-supervisor/src/secret_open.rs`
~1680 pins that `.mandu/mandu.db` is not in it); write-protect
(`write-protection.md`) acts on write-intent opens only; the exec box and the
fs-supervisor Landlock backend leave `/` readable. The per-launch egress CA
private key (`<scope>/egress-mitm-ca/`, `interceptors/net-proxy/src/ca.ts`) is
readable from the whole-agent wrap too (the exec box hides `/run`).
Since 2026-10-09 `ensureCa` keeps the key only in a real directory of this
uid with no group/other bits (it tightens its own dir's mode and refuses a
link or another account's dir); the standalone net-proxy's default, used
only when no launch names one, is the per-uid `$TMPDIR/mandu-egress-mitm-ca-<uid>`
(it was a fixed `$TMPDIR/mandu-egress-mitm-ca` another account could make
first).

**Other local users could read them too.** No code set a mode on `~/.mandu`
or on the state dirs, and SQLite creates `0644`; a typical developer home had
a group-writable `~/.mandu`, a world-readable `mandu.db` and hundreds of
world-readable event files.

**Five roots nobody chose together.** `~/.mandu` came with the DualView code;
`~/.config`, `~/.local/state`, `~/.local/share` and `~/.cache` were each picked
per feature. The agent's deny lists must name each root, and each new file is a
chance to land somewhere unprotected (the event log did). Users must learn five
places; `usage.md`'s uninstall list missed two.

**About 40 hand-written copies of the path rules**, one or more per package by
the standalone-package policy, with one parity test (events). Five
disagreed: `MANDU_RUNTIME_DIR` (honored by `arbiter/ipc/instance.ts`, ignored by
`launcher/src/parse.ts`, `subcommands.ts`, `platform/linux.ts`), `MANDU_CONFIG`
(ignored by `launcher/src/policy-level-spelling.ts`), `XDG_DATA_HOME` (ignored by
`scripts/install.sh`), `XDG_CACHE_HOME` (ignored by `exec-box-setup.ts`,
`scripts/ci/lib.sh`), and two hardcoded `~/.local/state` / `~/.config` uses.

**Test isolation failed three times on the number of knobs:** unit tests
wrote the live event store (`runtime-instances.md` §12), a test moved a
developer's real directories, and a scratch HOME was promoted as the account's
stack (`runtime-instances.md` §13).

## 2. Decision

**Everything Mandu stores lives under one directory, `~/.mandu` (`MANDU_HOME`),
mode `0700`, and the agent can neither read nor write anything in it.** Two
things stay outside, each for a reason the home cannot meet:

| Outside the home | Why |
|---|---|
| `/run/user/<uid>/mandu/` (runtime: sockets, instances, per-launch scope dirs, `human/`, the arbiter's human-plane sockets, and `probe-cache/`, the kernel probes a launch kept for this boot, packaging.md §5.4; on macOS, and on Linux without `XDG_RUNTIME_DIR`, the short private `0700` `/tmp/mandu-<uid>` (per-user since 2026-10-09), runtime-instances.md §3b) | must be a per-boot tmpfs, `0700` by logind, removed at logout; users never look there |
| `~/.local/share/mandu/`, `~/.local/bin/mandu` (the installed program, and `exec-box/`, the staged exec-box applier) | the agent must read and execute it (the box binary, shims, inspect-mcp run inside the agent's tree), so it cannot sit under a root the agent may not read |

**No XDG variables.** `MANDU_HOME` is the only relocation knob for stored data
(besides `MANDU_RUNTIME_DIR` and the install's `MANDU_PREFIX`/`MANDU_BIN_DIR`).
Mixing XDG with a home dir is what confuses people; the tools Mandu sits beside
made the same call (`~/.claude` / `CLAUDE_CONFIG_DIR`, `~/.codex` / `CODEX_HOME`;
Copilot CLI moved from XDG back to `~/.copilot`). Tools that keep unencrypted
secrets use one dot-directory (`~/.gnupg`, `~/.ssh`, `~/.password-store`);
OpenSSH declined XDG because spreading security configuration is risky. The XDG
tools that hold secrets mostly encrypt them (gnome-keyring, KWallet). nono keeps
config and audit under XDG but no plaintext secret store.

Alternatives considered: **XDG split by lifetime** (config / state / cache /
data / runtime). Rejected: five roots to deny, a secret store that follows
`XDG_STATE_HOME` onto whatever filesystem a user put it (synced, shared), and
moving `workspaces/` under the write-protected state root breaks the integrity
modes' AgentView (write-protect could not carve out an own-files entry
then; phase 4 added the carve-out, `except`, for the one home entry). **Keep `~/.mandu` for secrets only,
XDG for the rest.** Rejected: fixes the leak but keeps five places for users and
the deny lists, and the event log (secret-bearing) would stay outside.

## 3. The layout

```
~/.mandu/                       MANDU_HOME   0700   agent: no read, no write
├── config.toml                 launcher defaults (`mandu init`, `mandu mode`)
├── policy.yaml                 the law (the arbiter rewrites and restores it)
├── packs/  pack-keys/          signed consumer packs and trusted keys
├── prompt-filters/             the person's prompt filter packs (confidentiality-plan-15 §4.2)
├── secrets.json                developer API keys (scripts/secrets-to-env.mjs)
├── dashboard.env               a resident dashboard's EnvironmentFile (its host, allowlist, base path; a DASHBOARD_BASIC_AUTH there moves into state/dashboard-account.json; dashboard.md §6.z)
├── state/                      durable; losing it loses approvals and history
│   ├── mandu.db                0600  symbol table + every durable policy table (+ the cache seals)
│   ├── mandu-test.db           0600  the test tenant
│   ├── workspaces/<id>/        shadow repos (raw bytes) + AgentView (integrity modes)
│   ├── object-walks/           git history-walk cache (names protected blobs)
│   │   ├── history-scan/       0600  the arbiter's history-scan cache, one file per repository
│   │   ├── launch-hints/       0600  what the last launch per workspace read of git (a hint; confidentiality.md §7.2a "The prefetch")
│   │   ├── locked-memory/      0600  per object store, every (version, path) a launch found protected, only ever added to (confidentiality.md §7.2a "A version once locked stays locked")
│   │   ├── store-scan/<key>/   0600  per object store, every object id its scan has seen, every (object, path) a tree names, the path table, and a sealed state.json naming them by identity (ids and paths, never content; confidentiality.md §7.2a "Every stored object is checked once")
│   │   ├── twin-index/         0600  a running launch's record (in the HOME's own `~/.mandu` whatever MANDU_HOME says, so a scratch home removed after a killed launch does not take it along; every launch and reap reads it, and MANDU_HOME's own too) of the git index entries whose cached stat it set to a protected file's twin (index path, file path, blob id and the stat words before and after, never a value), written before each patched index lands; removed once the session's end put every entry back, a crashed launch's restored by the next launch before its own patch or by `mandu reap`, only while this folder and object-walks/ are real directories inside the home (confidentiality.md §7.2a "A twinned file git tracks looks clean")
│   │   └── placeholder-checks/ 0600  a running launch's note of the protected files in a git work tree to check for a commit of their placeholder (ids, paths and commit names, never a value); removed once checked, a crashed launch's checked by the next (kept until a check of it completes), only while this folder and object-walks/ are real directories inside the home, made one level at a time, each checked first (confidentiality.md §7.2a "A placeholder in your repository")
│   ├── paired-approvals/       one-shot approvals for paired evaluation runs
│   ├── browser/                0700  the Chrome profile `mandu --browser` starts the agent's browser with: the person's logins and cookies on the sites the agent uses; one session's Chrome at a time (devtools-relay.md §6.4)
│   ├── dashboard-account.json  0600  the Mandu dashboard account: a username and a salted scrypt hash of its password, never the password; written by `mandu dashboard --set-password` (and once from DASHBOARD_BASIC_AUTH), read per request by the dashboard, which refuses it unless it is the user's own private regular file with one link (dashboard.md §6.z). Hidden from a confined agent with the rest of the home (§4) and in the secret catalog
│   ├── launch-logs/            0600  one log per launch: every line it said, in full, and its helpers' messages (never a value, never the agent's output); the newest 20 kept; `mandu log` (packaging.md §5 "Launch display policy")
│   └── last-scan.json          0600  the last `mandu scan`'s report: kinds, masks, names, files, counts, hosts, dates, never a value; written whole by the command, read by the dashboard and `mandu doctor` (confidentiality-plan-17 §3 item 12)
├── events/                     session history, 90-day retention (holds originals)
│   └── test/                   the test tenant
├── runs/                       results the dashboard reads; made only when used
│   ├── test-runs.json  test-runs/  ci/  matrix/  eval/   the dashboard's test-run history, each Tests-tab run's results (summary.json, junit.xml, logs/), CI, OS-matrix and evaluation results
│   └── drills/live/  drills/replay/  drills/baselines/   live-drill and replay-drill run records, the plain-agent baseline cache (test-reorganization.md §4, §6.3, §6.7)
├── dev/                        developer-only credentials (docker-e2e home)
└── cache/                      regenerable; safe to delete
    ├── object-twins/           sanitized git packs (served to the agent via bind/fd)
    ├── ci/                     CI VM images
    ├── dashboard/              0600 listings.json.gz, drill-scenarios.json: the dashboard's listing summaries and drill scenario list, so a restart starts warm (dashboard.md §4.30)
    └── update-check.json       0600  the last release check's answer, for the launch's update notice (packaging.md §11.5)
```

Rules:

- **Top level is what a human edits.** Everything a user is told to open or
  change is one level down; subdirectories are Mandu's.
- **`cache/` may be deleted at any time**; `state/` and `events/` may not
  (backup = copy `~/.mandu` minus `cache/`).
- **Modes.** Every directory Mandu creates under the home is `0700`, every file
  `0600` (SQLite gives `-wal`/`-shm`/`-journal` the main file's mode; the
  single-owner lock `<db>.owner` is created `0600` too, and `mandu doctor`
  checks all four beside each DB). On every
  start the arbiter and the launcher check the home: they create it `0700`, and
  when an existing home or `state/`, `events/` is group- or world-accessible they
  tighten it and say so once (`mandu doctor` reports it). Tightening instead of
  refusing, unlike ssh: the directory is Mandu's own, and refusing would stop
  every existing install at once.
- **`state/object-walks/history-scan/`** is the arbiter's git-history scan
  cache (secret-discovery.md §3.2 item 8): one `<sha256(work tree)>.json` per
  repository, holding blob names, sizes and paths, which blobs were read, and
  the findings' masks and traces, never content or a value. It sits inside
  the path table's `object-walks` (the launcher's walk cache) rather than in
  an entry of its own: both are git-history caches under the agent-denied
  `state/`, and the arbiter bounds it itself (64 repositories, 64 MiB an
  entry, 30 days unused). Deleting it costs one full scan per repository.
- **The lock's reach lives in `mandu.db`** (confidentiality-plan-14 §11.1):
  `known_repos` (the known-repository registry: a work tree's real path and
  when each source last named it; at most 768 rows) and `lock_resolutions`
  (per repository, the blob names of its labelled versions, the tips and
  keys they were resolved at; never content). The resolution is an
  ENFORCEMENT cache (a row missing a version would drop a locked blob), so
  it is kept in the arbiter's single-writer DB, not as a file under
  `object-walks/`; deleting `mandu.db` costs one resolution per repository.
- **The enforcement caches are sealed** (confidentiality-plan-14 §11.2):
  `cache/object-twins/`, `state/object-walks/` and its `history-scan/`
  decide what the object twins strip, and something unconfined (an `off`
  session, a `gated` launch, a program outside Mandu) can write them. Every
  entry is used only when its sha256 and size match a seal the arbiter holds
  in mandu.db (`cache_seals`, `cache_seal_state`, `unconfined_launches`;
  schema v6) for the current epoch; the epoch rotates, voiding every seal,
  when an unconfined period ends. The `lock_resolutions` rows above are
  sealed the same way (kind `lock-resolution`), checked when read back at
  start. A file that does not match is rebuilt,
  never trusted, so deleting any of them stays safe (`cache/` still may be
  deleted at any time; the walks and the scan cost one full pass). An
  unprotected launch the arbiter could not record deletes
  `cache/object-twins/` and `state/object-walks/` when it ends.
- **`cache/object-twins/` has two writers** (confidentiality-plan-14 §11.1
  R3): the launcher (its workspace's packs, at launch) and the arbiter (the
  copies it prepares in the background for every known repository holding a
  locked object, sealed through its own store; on Linux only since
  2026-09-30, `preparedCopiesOff`: only a Linux launch uses a copy, and the
  launcher's own writes, from `hideGitHistory`, run on Linux only too).
  Both use the same key (the pack's name and the ids excluded), so either
  one's copy is the other's cache hit. The arbiter keeps what it prepared under
  `MANDU_GIT_PREP_TOTAL_MB` (4096 MiB of source packs by default), touches
  it every cycle, and removes a copy it made once no repository wants it;
  the launcher's 30-day prune removes the rest. No new path.
- **`runs/` and `dev/` exist only on developer hosts** (created on first use), so
  an end user's home holds only config, `state/`, `events/` and `cache/`.

## 4. What the agent may touch

One rule replaces the per-path lists: **deny read and write under `MANDU_HOME`**,
enforced by the same layers that deny the shadow repos today (the guard's
`denyPrefixes`, resolved by pinned identity; the wrap's `--tmpfs` mask; write-protect's
own-files list, which already treats any `.mandu` path segment as Mandu's own,
`arbiter/policy/guard-settings.ts` ~105). The agent needs nothing there: it
reaches the symbol table and the policy through the arbiter socket, and
agent-side components (inspect-mcp, the exec-box shims) take their settings
from the environment and from files the launcher stages in the per-launch scope
dir (which a launch that ends cleanly removes, runtime-instances.md §10.1).

Exceptions, each by a path under the home, never a second root:

| Path | Agent access | When | Why |
|---|---|---|---|
| `state/workspaces/<id>/agentview/` | read + write | `injection`, `full` (frozen) | the agent's cwd in the integrity modes (`fs-sync/src/manager.ts` ~206) |
| `state/workspaces/<id>/repo.git/` | read + write | `full` only | agent-side git behind the AgentView; the documented `full`-mode residual (`guarantees.md`) stays as is |
| `cache/object-twins/` | read, only through the bind / guard-injected fd at the repo's own pack path | confidentiality on | sanitized; never by its own path |

Outside the home: the per-launch `egress-mitm-ca/` joins the deny list (the agent
reads the certificate through the path the launcher exports, never the key).

The integrity-mode exceptions are carve-outs from the deny rule, so the frozen
modes keep working without a second root; their canaries in the default suite
prove it.

Details (built in phase 4):

- **Which home.** The home's real path; when `MANDU_HOME` moves it, the
  default `~/.mandu` is denied too (an older home's `mandu.db` stays there
  until it is deleted, §6). So is the account's own `~/.mandu` (its passwd
  home, not `$HOME`) when the launch runs with a scratch `HOME`, as an eval
  leg or a test does: the real home's stores stay out of reach (phase 5). A missing home is created `0700` before the mask,
  so the agent cannot create it.
- **Which layers.** Reads are denied where confidentiality is on (`secrets`,
  `full`), as the own stores were; writes in every mode but `off`
  (write-protect). A carve-out must be exactly
  `<home>/state/workspaces/<one name>/agentview` (or its `repo.git` in
  `full`) and exist; anything else carves nothing.
- **An agent started inside the home** (its cwd outside every carve-out) is
  refused at launch with confidentiality on: "…inside Mandu's home… Launch
  from another directory". The integrity modes' own cwd is the AgentView
  carve-out.
- **Not trapped:** `mkdir(2)` under the guard alone (unchanged): an agent
  can make empty directories in the home, never a file. Under the wrap
  everything it makes lands on the throwaway tmpfs.
- **Stores stay inside the home (confidentiality-plan-14 §11.2 residual
  (c)).** The layers name the home's real path, so a store whose path
  inside the home resolves outside it is behind none of them. The arbiter's
  daemon refuses to start, and a launch with confidentiality on is refused,
  while `state/`, `state/workspaces/`, `state/object-walks/`, `events/`,
  `events/test/` or `cache/object-twins/` resolves outside the home (a
  symlink on its path) or is not the user's own directory, or `mandu.db` /
  `mandu-test.db` (or a `-wal`, `-shm`, `-journal` beside it) is a symlink,
  has a second hard link or is not the user's own
  (`arbiter/db/store-links.ts`, mirrored in `launcher/src/store-links.ts`).
  The home itself may be a symlink (its real path is what the layers use),
  and so may the config files and `cache/ci` or `runs/` (no original is
  written there).
- **`injection` gives up `repo.git` writes**, as the table says: before
  phase 4 only the DB family was denied there. That is stricter, not a leak;
  if the AgentView's own version control needs them, the freeze rule applies
  (protection-modes.md §10.3).

## 5. One path table

- **The rules live in one table**, `scripts/paths/mandu-paths.mjs`: each entry is
  a name, a path relative to `MANDU_HOME` (or to the runtime / install base), a
  mode, and whether the agent may read it.
- **Each package gets a generated copy**, `src/generated/mandu-paths.ts` (and
  `interceptors/mandu-paths/src/lib.rs` for Rust), keeping packages standalone. A
  parity test fails when a generated copy differs from the table, replacing the
  one-rule-three-copies event-dir test with an all-rules one.
- **Resolution order:** `MANDU_HOME`, else `$HOME/.mandu`, with the
  foreign-HOME guard of `runtime-instances.md` §13 applied to `MANDU_HOME`.
- **Per-path overrides are retired** (phase 4; decided §9.1):
  `MANDU_SYMBOL_DB`, `MANDU_EVENT_DIR`, `MANDU_VIEW_STATE`, `MANDU_CONFIG`
  (with its "policy.yaml beside the config" rule and the `view-state` config
  key), `MANDU_CI_RUNS_DIR`, `MANDU_MATRIX_RESULTS_DIR`, `MANDU_CI_CACHE`,
  `MANDU_SECRETS`, `MANDU_DOCKER_HOME`. Nothing in the home has its own
  variable; `MANDU_HOME` moves all of it. Only the locations outside the home
  keep one (`MANDU_RUNTIME_DIR`, `MANDU_PREFIX`, `MANDU_BIN_DIR`), and
  `MANDU_POLICY_FILE` stays (tests point it at `/dev/null/...` to run
  policy-less).
  - **Mandu's own spawners place an arbiter's stores with flags**, never the
    environment: `--symbol-db <path>` and `--event-dir <dir>` on
    `arbiter/ipc/server-main.ts`. The launcher's per-launch arbiter gets its
    scope dir's `events/`, the dashboard's test tenant `state/mandu-test.db`
    and `events/test`; a resident arbiter takes the defaults. The agent's
    environment carries no store path. The same holds for the program the
    arbiter runs for a names-only model run: `--classifier <json argv>` and
    `--landlock-apply <path>`, passed by the dashboard supervisor and the
    launcher from their own layout (confidentiality-plan-14 §14.10). The
    launcher's temporary arbiter for `mandu why` (no Mandu running) gets
    `--seed-from <store> --seed-policy <policy file>`: its own store, in
    its own temporary home, starts as a read-only copy of what the resident
    store keeps, values left out (runtime-instances.md §9b).
  - **Tests** set `MANDU_HOME` and `MANDU_RUNTIME_DIR` to temp dirs. Every
    package's `npm test*` scripts (and `scripts/test-all.sh`) pin
    `MANDU_HOME=/dev/null/mandu-test-home`, so a test that forgets to isolate
    fails at its first write instead of reaching a real home; reads of an
    optional file there (`config.toml`, `policy.yaml`) count as absent.
- **`mandu paths`** prints every location with its mode and whether it exists,
  for users and bug reports; `mandu doctor` flags wrong modes. The dashboard's
  "Where your data lives" shows the same rows, without the developer-only
  places that are not there (`dashboard.md` §4.25q).
- **A broken link.** A location that is a dangling
  symlink is reported as **there but broken**, on both surfaces: `exists`
  true (something is at the path: Mandu cannot create its own file or folder
  there), no mode, `brokenLink` true; `mandu paths` says "broken link" with a
  note, the page shows a "broken link" badge, and `mandu doctor` names each
  one with its fix. Both surfaces are for a person asking where the data is,
  and the likely cause (a relocated folder on a disk not mounted) is exactly
  what "not there yet" would hide. Pinned on both sides:
  `launcher/test/unit/paths-command.test.ts`, `doctor-home.test.ts`, and
  `dashboard/test/unit/data-locations.test.ts`.

## 6. No migration: a clean start

The one home breaks compatibility with the older layout on purpose. The code
knows only `~/.mandu`: no automatic move, no carry-over of old event logs or
test history, no second set of old locations on the deny lists. An automatic
move at start (lock, live-stack check, move-don't-merge) was built and dropped
before release: moving a user's directories under a running stack is a risk
the compatibility did not justify for a pre-release layout.

**What an older host keeps, and must remove by hand.** The old directories
(`~/.config/mandu`, `~/.local/state/mandu`, `~/.cache/mandu`, and in
`~/.mandu` the old `mandu.db*`, `workspaces/` and `object-twins/`) stay where
they are. The old symbol DB and event log hold real values. The old DB lies
inside `~/.mandu`, which the single deny rule covers;
`~/.local/state/mandu/events` does not, so it stays readable to the agent
until it is deleted (the user docs say so under "Where Mandu keeps its
files"). The same holds for a store that moved inside the home since: older
live-drill records in `runs/watch/` are read by nothing; move them to
`runs/drills/live/` or delete them.

## 7. Plan

Built in five phases, each with unit and e2e tests; phase 1, the security fix,
shipped first.

1. **Close the read leak on the old paths.** The Mandu home (minus the
   integrity carve-outs) and the event dir joined the guard's read deny and
   the wrap's mask, the per-launch CA key too, and Mandu creates and tightens
   its modes (`0700`/`0600`). What it covers and its residuals:
   `confidentiality.md`, "Mandu's own stores of originals". E2E oracle, per
   mode (`secrets`, `off` as the negative control, the `full` canary): an
   agent under `mandu` cannot read `mandu.db`, an event file, or the CA key,
   and the symbolized path still works.
2. **The path table and generated copies** (§5), still emitting the old
   locations, with the parity test; no behavior change. The table is
   `scripts/paths/mandu-paths.mjs`; `node scripts/paths/mandu-paths.mjs
   generate` writes the copies and `check` verifies them. Copies: `arbiter`,
   `launcher`, `dashboard`, `fs-sync`, `eval` (`src/generated/mandu-paths.ts`,
   `lib/generated/` for eval), the `mandu-paths` crate (for `fs-supervisor`)
   and a bash copy, `scripts/paths/mandu-paths.sh` (`source` it, then
   `mandu_path <name> [home]`). Each entry has a name, a base or parent
   entry, a relative path, a mode, `agentReadable` and, until phase 4, its
   override variable. Resolvers take `(env, home)` and read no file; an empty
   variable counts as unset. Parity: `scripts/test/mandu-paths.test.mjs`
   fails on a stale copy; `tests/stack/mandu-paths-parity.test.ts` checks
   each TS copy against the table and the hand-written owners against it; the
   crate carries generated cases; the bash copy is checked on every fixture
   under `env -i`.
3. **Every caller asks the table, then the flip.** Every package's
   hand-written path rules were replaced by the table, one package at a
   time; where a copy disagreed (the list in §1), the table won. Then the
   table moved to a `mandu` base (`MANDU_HOME`, else `$HOME/.mandu`), the
   entries were re-pointed to §3, and `mandu paths` and `mandu doctor`'s
   mode check landed, with no migration (§6). Tests: the table and every copy
   on the new layout, each package's owners, and the kernel oracle
   `own-stores-hidden.test.ts` on the one home.
4. **Collapse the deny lists to the single home rule** (§4) and retire the
   per-path overrides (§5):
   - The launcher's `ownStoresHidden` returns the home (its real path, plus
     the default `~/.mandu` when `MANDU_HOME` moves it) for the guard's
     `denyPrefixes`, one `--tmpfs` over it for the wrap, and the carve-outs;
     write-protect's `ownFiles` is one refused entry for the home with those
     carve-outs as `except` (the guard's `denyExcept`, `net-supervisor`
     `secret_open.rs`: a carve-out spares a path only from a prefix it lies
     strictly below). The wrap masks the home before any secret-twin bind,
     so a twin over an AgentView copy of a credential lands on the carve-out
     rather than under it.
   - The per-path overrides are gone from the table and every reader; the
     arbiter takes `--symbol-db` / `--event-dir` from Mandu's spawners; every
     package's test scripts pin `MANDU_HOME=/dev/null/mandu-test-home`.
   - The staged exec-box applier lives at the install prefix
     (`exec-box-cache`, §3): the agent runs it, so it cannot sit where the
     agent may not read, and it must stay write-protected.
   - Tests: the kernel oracle `own-stores-hidden.test.ts` (no stray
     `<home>/mandu.db` read, no new file at the top of the home or in
     `state/`, the object twin still served at the pack path, and the `full`
     canary's AgentView and `repo.git` read and written through);
     `guard_integration.rs`'s whole-home test; unit tests per layer; the
     arbiter's `store-flags` e2e; the dashboard's `supervisor-home` e2e;
     `mandu-paths-parity` (a retired variable moves nothing in any copy).
5. **Docs and the decided features (§9).** `usage.md` "Where Mandu keeps its
   files" (everything in `~/.mandu`, the program, and the per-boot runtime
   dir; backup; uninstall = `rm -rf ~/.mandu` + the program) and the README's
   one-line pointer to it; each superseded design section bannered. The
   dashboard's product page gained a collapsed "Where your data lives"
   section fed by `GET /api/data-locations` (`dashboard.md` §4.25q), the rows
   and wording of `mandu paths` (a parity test reads the launcher's text).
   Eval output defaults to `runs/eval/<UTC stamp>-<suite>-<6 hex>/` (0700)
   when no `--out` is given; only results go there: everything the agent
   under test touches (its workspace, scratch HOME, per-leg Mandu home,
   sockets) runs in a short temp dir outside every Mandu home and is copied
   back at the leg's end (`eval/lib/paired/leg-work.ts`). A launch with a
   scratch `HOME` (an eval leg, a test) also denies the account's own
   `~/.mandu` (§4), and the shared stack's foreign-HOME rewrite drops a
   `MANDU_HOME` inside the foreign HOME (`runtime-instances.md` §13).

## 8. Not changed

- The runtime base and everything in it (`runtime-instances.md`), apart from
  the CA key's denial and `human/` ([`arbiter-human-plane.md`](./arbiter-human-plane.md)):
  the arbiter's human-plane sockets, `human/<instance id>.sock`, in a
  directory the arbiter creates `0700` and refuses to start in when it is not
  its own `0700` directory. The agent may not connect under it (the guard's
  always-deny unix entry, the wrap's `--tmpfs`, Seatbelt); it is never under a
  scope dir, and no unix allow-list entry may equal or contain it.
- The install prefix and the `mandu` wrapper (`packaging.md`), and the
  system-level paths (`/usr/lib/mandu/bin/bwrap`, `/etc/apparmor.d/mandu-bwrap`,
  `/etc/mandu/policy.d`).
- SQLite on a network home stays unsupported (WAL does not work over NFS);
  `MANDU_HOME` on a local disk is the answer, and `mandu doctor` should say so.

## 9. Decided questions

1. **No per-path override survives but `MANDU_POLICY_FILE`.** Tests and
   `scripts/dev-arbiter.sh` set `MANDU_HOME` (and `MANDU_RUNTIME_DIR`) to
   temp dirs. One variable keeps the agent's deny rule one rule.
2. **The dashboard's product page shows "where your data lives"**: a small
   section with each location, what it holds, and whether its mode is
   owner-only (the `mandu paths` data).
3. **Evaluation output defaults to `runs/eval/<run>`** when no `--out` is
   given; `--out` still wins (the `eval-runs` entry).
