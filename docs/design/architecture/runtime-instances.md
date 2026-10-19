# Runtime instances — per-deployment identity for the Mandu stack

Status: implemented (arbiter `ipc/instance.ts` + `server-main.ts`, dashboard
supervisor, launcher), with unified discovery and instance-mode autostart,
the symbol-DB single-writer lock, universal registration + `mandu reap`,
port-0 everywhere and the container-scoped-pid rule (§§3–13). §14 is launch
time: where a launch's seconds go (§14.7: the 2026-10-16 pass; §14.8: the guard's work per exec), and the readiness deadlines that bound how
long it waits for the services it starts.
 macOS also uses the short, owner-checked
private runtime base of §3b and an account rendezvous (macOS branch,
2026-09-29); those copies obey the same shared discovery contract.

## 1. The problem (three real incidents)

Every arbiter start — dashboard-supervised, launcher autostart, hand-check
one-offs — once targeted the SAME well-known socket path
(`${XDG_RUNTIME_DIR}/mandu/arbiter.sock`). Three properties compounded, each
of which caused a real incident:

1. **Last-binder-wins.** Unix sockets are unlink-before-bind: the newest binder
   silently steals the path while the old daemon keeps serving already-open
   connections — both "work", nothing errors. A hand-check arbiter with a
   throwaway event dir rebound the shared socket and blackholed every
   dashboard session for a day. (The arbiter refuses to clobber a LIVE
   socket — `server.ts listen()` — but a *stopped-then-started* squatter
   still won the path.)
2. **Daemons outlive code.** `tsx` loads source at process start; a socket
   carries no version marker, so a weeks-stale daemon is indistinguishable from
   a fresh one (dashboards running old code looked healthy while missing new
   features).
3. **Identity lives nowhere.** Which pid/git-rev/event-dir a listener uses was
   only recoverable via `ss -xlp` + `/proc/<pid>/environ` forensics; fixed
   default ports (4500, 8788–8790) let a second stack half-start and adopt a
   foreign, older arbiter (the mixed-generation stack).

Durable state was never the problem: the event dir and the arbiter DB live in
the Mandu home (`~/.mandu/events`, `~/.mandu/state/mandu.db`;
on-disk-layout.md §3) and are deliberately shared across restarts. `mandu.db`
carries no schema back-compat (§9a). Only the **runtime identity** (socket,
pid, code rev) needed scoping.

## 2. The scheme

```
<runtime base>/     # $MANDU_RUNTIME_DIR, else $XDG_RUNTIME_DIR/mandu, else
                    # $TMPDIR/mandu if an instance socket fits, else the
                    # private /tmp/mandu-<uid> (§3b)
  current -> instances/20260707-1139-91dca36-p402360     # atomic symlink swap
  instances/
    20260707-1139-91dca36-p402360/    # <utc yyyymmdd-hhmm>-<git-rev>-p<pid>
      arbiter.sock                    # bound HERE — never at a shared path
      manifest.json                   # pid/rev/startedAt/eventDir/symbolDb/humanSockPath
      logs/
  human/                              # 0700; the HUMAN-PLANE sockets (2026-09-30)
    20260707-1139-91dca36-p402360.sock  # one per instance, pinned or not
  logs/                               # supervisor per-service logs (base level)
  arbiter.sock                        # LEGACY fixed path (compat, read-only)
  dashboards/<id>.json                # the dashboards' registry (§10)
  dashboard.log                       # `mandu dashboard`'s log (§8)
  dashboard-<pid>.port                # its port rendezvous, while it starts one
  vm-guests/<harness>-<pid>.json      # the VM test harness guests (§10)
  test/arbiter.sock                   # the supervisor's test-tenant arbiter
  release-check/                      # the release check's gate: pending-<pid> markers, lock/ (§4.1)
  <epoch>-<pid>/                      # one scope dir per launch (§10.1)
```

Everything under this base is RUNTIME state — meaningless after a boot, and
on `/run/user/<uid>` it does not survive one. The event store and the
test-run history are NOT here: they live on disk in the Mandu home,
`${MANDU_HOME:-~/.mandu}/events/` and `runs/test-runs.json` (§12,
on-disk-layout.md §3).

- **A daemon binds only inside its own instance dir**, so binding can never
  steal another instance's socket — squatting is impossible by construction,
  not by discipline.
- **`current` is the rendezvous.** Promotion = create the symlink under a temp
  name + `rename(2)` over `current` (atomic; readers always resolve a complete
  path). The link target is RELATIVE so a moved/bind-mounted base stays valid.
- **The manifest is written atomically too** (2026-09-30): `writeManifest`
  writes `.manifest.json.<pid>.tmp` in the instance dir and `rename(2)`s it
  over `manifest.json`, so a registry reader (`mandu reap`/`status`, the
  sweeper, the dashboard, tests polling for the daemon) sees no manifest or the
  whole one. A plain write to the final path created it empty first, and a
  polling test caught that window (`Unexpected end of JSON input`,
  `store-flags.test.ts`). Readers still treat an unparsable
  manifest as unknown (`readManifest`/`readManifestLite` return null; a
  manifest-less dir is grace-protected), never as fatal. The temp file is
  created exclusively (see "planted paths" below).
- **Planted paths (2026-09-30).** Every name under the base is predictable
  (the instance id is `<utc-minute>-<rev>-p<pid>`, a minted scope id
  `<epochSec>-<pid>`, the temp names and `mandu dashboard`'s port file carry
  a pid), the arbiter, the dashboard, the launcher and `mandu reap` run
  OUTSIDE the agent's confinement, and the agent may write the base: on
  macOS its Seatbelt profile keeps the base writable for the session's own
  dir, and on Linux nothing stops a same-uid process. A link or a forged
  entry planted where one of them is about to write or delete would make it
  act for the agent: write the manifest, a log or a port number into a file
  the link names (a shell startup file), adopt a pre-made instance or scope
  dir, bind the socket wherever a linked `instances/` points, or (the worst)
  let a start-up sweep take every old entry of a linked-to directory for a
  dead one and remove it. So, on every platform:
  - `writeManifest` unlinks any leftover at `.manifest.json.<pid>.tmp` (unlink
    never follows a link) and creates it with `O_CREAT|O_EXCL` (`wx`): open(2)
    refuses any entry at the name, a symlink included, so one re-planted in
    between makes the write fail, never follow;
  - `createInstanceDir` requires `instances/` to be a real directory (lstat,
    not a link) and makes `instances/<id>` non-recursively, mode `0700`: an
    instance dir that already exists is refused and left alone, never
    adopted. The one legitimate way to meet one, an earlier process that
    had this pid in the same minute, clears itself: the next start gets a
    new id. The mode also keeps other accounts out of a socket dir in a
    shared base (`/tmp/mandu`), where the umask left it `0755`. No chmod
    follows the mkdir (the umask only narrows 0700, and a chmod by path
    would follow a link swapped in after it);
  - `sweepDeadInstances` does not sweep an `instances/` that is not a real
    directory, and the dashboard's `sweepDeadDashboards` does not sweep a
    `dashboards/` that is not one (a check, not a lock: the rename of the
    directory is a race a same-uid process can still try on Linux). Through
    a link to a project, the dashboard's sweep deleted every `*.json` there
    that names no live pid (`package.json`) at every dashboard start;
  - `registerDashboard` refuses a `dashboards/` that is not a real directory
    and writes its `<id>.json.tmp` as `writeManifest` does (unlink, then
    `wx`); the dashboard publishes its port (`MANDU_PORT_FILE`, `mandu
    dashboard`'s `<base>/dashboard-<pid>.port`) the same way
    (`dashboard/src/port-file.ts`);
  - the logs Mandu opens there are opened `O_NOFOLLOW|O_NONBLOCK` and must
    be a regular file with one link (a link, a FIFO or a hard link to
    someone's file is refused): `mandu dashboard`'s `<base>/dashboard.log`,
    the arbiter's autostart log in `<base>/logs/` and every service log in a
    scope dir (launcher `openAppendLog`), and the supervisor's per-service
    logs in `<base>/logs/` (truncated only after the check). Since
    2026-10-17 every component on the way is checked too, not the last one
    only (`safe-log.ts` `openSafeLog`, byte-identical in the launcher and
    the dashboard, `tests/stack/safe-log-parity.test.ts`): the walk starts
    at `/` and opens each directory in the descriptor of the one before
    (`/proc/self/fd/<fd>/<name>` on Linux, the openat(2) form),
    `O_DIRECTORY|O_NOFOLLOW`, the descriptor checked to be the directory the
    lstat saw; a link on the way is refused unless the system owns it (root,
    or the overflow uid a user namespace shows for an owner it does not map:
    macOS's `/tmp`), and never at or below the runtime base when the caller
    names it; each directory must be the system's or this user's and none
    every account may write unless it is sticky, and at or below the
    runtime base this user's only (a group- or other-writable one, an older
    release's `mkdir -p` under umask 002, is tightened on its descriptor); a
    missing directory is made one at a time, 0700, in its parent's
    descriptor (the `mkdir -p` by path before the open is gone, which made a
    dangling link's target folder); and the file is created in the last
    directory's descriptor. So a `<base>/logs` that is a link to a folder
    refuses the autostart (and gets the supervisor no durable log) and the
    folder gets nothing. Without `/proc` (macOS) the steps name paths, each
    lstat-checked just before; the Seatbelt profile below keeps the agent
    out of the registries there. Tests: `launcher/test/unit/safe-log.test.ts`,
    `launcher/test/component/log-dir-planted.test.ts` (the real autostart and
    service spawners), the dashboard's `supervisor-logs.test.ts`;
  - the arbiter's event store (2026-10-17, `arbiter/events/event-store.ts`,
    the third copy of `safe-log.ts`): a per-launch arbiter's event dir is
    `<scope dir>/events`, open to the agent while its session runs, and the
    session id is the scope id, so `appendFileSync(<session>.ndjson)`
    followed a link planted there and appended records the agent can steer
    (its commands, its tool output) to the file it named. The store now
    opens its directory once (`openSafeDir`, made 0700 one component at a
    time) and appends each record in that descriptor (`openSafeLogIn`:
    `O_NOFOLLOW|O_NONBLOCK`, a regular file of its own, 0600); a refused
    file fails that emit (the feed is best-effort, off the security path)
    and nothing reaches the linked file. Reads, the retention sweep and the
    resident arbiter's `~/.mandu/events` (inside the Mandu home, which the
    guard hides from the agent) still go by path. Tests:
    `arbiter/test/unit/event-store-planted.test.ts`,
    `arbiter/test/component/event-file-planted.test.ts` (a real server, the
    production client);
  - the guard's own files (2026-10-17, net-supervisor `safe_write.rs`): its
    status record for the launcher (`MANDU_NET_GUARD_STATUS`, in the scope
    dir the agent may write while it runs) is written in its directory's
    descriptor, opened once at the guard's start with the same per-component
    rules (`openat`), as a fresh temp name made `O_CREAT|O_EXCL|O_NOFOLLOW`
    0600 and `renameat` over the name: until then the `exited` record at the
    guard's exit (`std::fs::write("<status>.tmp")`) followed a link the
    agent planted there and truncated the file it named to `exited 0`
    (`guard-death-live.test.sh` step 5). The opt-in trace
    (`MANDU_NET_GUARD_TRACE`) is appended the same way
    (`O_APPEND|O_NOFOLLOW|O_NONBLOCK`, a regular file of its own), and the
    test-only open counts (`MANDU_NET_GUARD_OPEN_STATS`) replaced like the
    record;
  - `mandu reap` (2026-10-07) opens the base and each registry it walks
    (`instances/`, `dashboards/`, `vm-guests/`) as a real directory of this
    user's (lstat, then `O_DIRECTORY|O_NOFOLLOW`, the descriptor checked to
    be the directory the lstat saw) and walks it through that descriptor
    (`/proc/self/fd/<fd>/<name>` on Linux: the openat(2) form), so a
    registry that is a link is not walked at all and says so (`refused:
    instances/ not walked: … is a symbolic link`); an entry that is a link
    is skipped, a manifest or entry is read `O_NOFOLLOW|O_NONBLOCK` (a link
    or a FIFO is never read through or waited on). Execution re-checks
    every removal at that moment, not the plan: the base and each directory
    on the way are opened again the same way, the entry must be this
    user's and of the kind its registry holds (an instance or scope dir a
    directory, `current` a link, a dashboard or guest entry a regular
    file), and a tree goes bottom-up relative to descriptors, a link inside
    unlinked, never followed (`launcher/src/safe-remove.ts`). A guest's
    scratch path must lie below a temp or cache root (the temp dirs, the
    user's cache dir, Mandu's cache root, `MANDU_CI_WORK`, `MANDU_VM_CACHE`;
    `~/Documents` is refused) and is removed only when no link this user
    could have made lies on its way (a root-owned one, macOS's `/tmp`, is
    the system's) and the entry itself is this user's. Without `/proc`
    (macOS) the steps name paths, each lstat-checked just before: the
    residual race there is closed by the Seatbelt profile below, which
    keeps the agent out of the registries;
  - every file Mandu's launcher and services write by name in a scope dir
    (2026-10-07: the proxies' port files, the agent and MCP configs, the
    guard policy and secret policy, the secret twins, the exec and exec-box
    shims, the CA bundles, `launch.log`) and the temp files beside the
    agents' trust configs (`~/.claude.json`, Codex's `config.toml`) go
    through one helper, `safe-file.ts` `publishFile` (byte-identical in the
    launcher and the three proxies; `tests/stack/safe-file-parity.test.ts`):
    the directory must be a real directory of this user's (a link is
    refused, except a config directory the user linked), the content goes
    to a fresh temp name with a random part, created
    `O_CREAT|O_EXCL|O_NOFOLLOW` mode 0600 (the final mode set on the
    descriptor), and rename(2) puts it in place, replacing a link at the
    name rather than writing through it. A proxy whose port-file directory
    is refused stops (the launcher waiting for the port fails the launch);
  - a launch makes its own scope dir before anything is written into it, and
    never adopts one someone prepared (§10.2), and a scope id that is not one
    folder name or names one of the entries below (`--id instances`) is
    refused at parse (`launcher/src/runtime-registry.ts` `scopeIdProblem`).
    The match ignores letter case and Unicode normalization, on every
    platform (2026-09-30): the default macOS volume and Seatbelt's path match
    both ignore them, so `--id Instances` named the arbiter's registry.
    `applySeatbelt`'s check that a registry entry holds nothing the agent
    keeps compares the same folded spelling.
  And on macOS the agent's Seatbelt profile write-denies the registries
  themselves (`confidentiality.md` §7.3, "Mandu's runtime registries"; the
  one list is `launcher/src/runtime-registry.ts`): `instances/`,
  `dashboards/`, `vm-guests/`, `logs/`, `test/`, `release-check/` (subpath), `current`, the
  legacy `arbiter.sock` and `dashboard.log` (the entry itself), the
  promotion's temp link `.current.tmp-<pid>` and `mandu dashboard`'s
  `dashboard-<pid>.port(.tmp)` (a `prefix`: a link swapped in between the
  arbiter's symlink(2) and rename(2) would otherwise become `current`), under
  the launch's runtime base AND the account's default base and rendezvous
  (where the user's resident stack lives when the launch has a
  `MANDU_RUNTIME_DIR` of its own), with the folders above them
  unrenameable. Sockets there stay reachable (connect(2) is not a write).
  An entry that holds what the agent must keep writable (its workspace, its
  runtime or scope dir) refuses the launch rather than drop the rule. And the
  launch hands its profile to `sandbox-exec` inline (`-p`), so no file in the
  base is read back after it was written. With the profile, the agent can
  neither forge a live instance's manifest (a dead pid in it would have had
  the next sweep remove the live dir and its socket) nor plant anything in
  a registry for an unconfined process to follow.
  On Linux (2026-10-07) the same entries ride the whole-agent guard's
  write-protect list as Mandu's own files (`deny`; write-protect.ts
  `runtimeRegistryProtect`, from the one list in runtime-registry.ts), under
  the same bases (the launch's, the account's default base and
  rendezvous), wherever the list is applied (a running guard, every mode
  but `off`, `MANDU_WRITE_PROTECT` not `0`), each in the form the guard
  needs (net-supervisor secret_open.rs `WriteForm`): the directories
  (`instances/`, `dashboards/`, `vm-guests/`, `logs/`, `test/`, `release-check/`, and the
  human plane's `human/`) with everything below them; `current`, the
  legacy `arbiter.sock` and `dashboard.log` as `name` entries (the entry
  itself under its own name: resolved, `current` would have named the
  instance it points at and left the link replaceable, which is also why
  the links on the arbiter socket's way are now `name` entries);
  `.current.tmp-` and `dashboard-` as `prefix` entries; and the base itself
  as a `self` entry, so it cannot be renamed away for a forged one while
  the session's own folder in it stays writable. The guard matches a
  `name`/`prefix`/`self` entry by the spelling the kernel gives the pinned
  target and by identity (the entry's directory reached under another
  spelling, or the entry itself by its own, unfollowed identity). As on
  macOS, a registry that would hold the workspace or the scope dir refuses
  the launch. Not judged: a new DIRECTORY (`mkdir` was never on the list,
  write-protection.md §2), so the agent can make an empty dir at a
  registry name; nothing can be written into it, and its only effect is a
  refused start (an instance id or a temp name already taken). Test:
  `tests/sandbox/write-protect-registry.test.ts`. Still open, recorded as
  follow-up work (TODO.md in private/): where no list applies (no guard on
  Linux, `MANDU_WRITE_PROTECT=0`, mode `off`), the code-level checks above
  are what holds (the log checks cover every component since 2026-10-17,
  above); and on every
  platform the base stays writable, so ANOTHER session's scope dir is open
  to the agent while that session runs: Mandu's writes there no longer
  follow a link (above), but a file can still be REPLACED by another
  (rename(2) over it) between Mandu's write and its reader: a port file
  naming another port, an agent or MCP config, and on Linux the guard
  policy file the launcher reads back to merge into and the guard reads
  at its start. A named scope dir that already exists is reused as the
  caller's.
- **The instance id is the diagnosis**: start time (sortable), git rev ("is
  this the new code?"), pid ("what do I signal?") — all from `ls instances/`.
- **Promotion is opt-in** (`MANDU_PROMOTE=1`). A bare
  `cd arbiter && npm run serve` creates an instance but does NOT repoint
  `current` — the hand-start behind incident 1 now logs how to reach it and
  how to promote, and steals nothing. The dashboard
  supervisor and the launcher autostart — the deployment owners — pass
  `MANDU_PROMOTE=1`.
- **GC**: instance dirs whose manifest pid is dead are swept at the next
  arbiter startup (`sweepDeadInstances`; a manifest-less dir younger than 60s
  is grace-protected as mid-creation). Graceful shutdown removes the daemon's
  own dir; a dangling `current` simply stops resolving.

- **The human-plane socket** ([`arbiter-human-plane.md`](./arbiter-human-plane.md)) sits in `human/`,
  deliberately outside the instance dir, so the launcher can wall the agent
  world off from one directory. The arbiter creates `human/` `0700` and refuses
  to start when it is a symlink, not its own, or group/other-accessible. It is
  bound in BOTH modes (a pinned `MANDU_ARBITER_SOCK` never moves it), recorded
  in the manifest, answered by `hello` (`humanSock`), unlinked on a graceful
  shutdown, and swept with a dead instance's dir. Clients resolve it with
  `resolveArbiterHumanSock()`: `$MANDU_ARBITER_HUMAN_SOCK`, else
  `human/<current's instance id>.sock`, else none: never the data socket.
  On macOS the agent's profile walls off `human/` under every registry base
  above, not only the launch's own (2026-09-30): a launch with a
  `MANDU_RUNTIME_DIR` of its own also gets no connect, read or write in the
  resident stack's `human/` under the account's default base and
  rendezvous, and the folders above it cannot be renamed
  (arbiter-human-plane.md §6).

## 3. Client resolution order

`resolveArbiterSock()` (arbiter/ipc/instance.ts; the base itself is the §3b
rule in `runtime-base.ts`, mirrored per package; small mirrors in
dashboard/src/server-main.ts, launcher/src/arbiter-sock.ts (used by parse.ts
and the status/stop/doctor/dashboard verbs), launcher/mandu-run.sh,
claude-e2e.test.ts — each package stays standalone):

1. `$MANDU_ARBITER_SOCK` (legacy alias `MANDU_ARBITER_SOCKET`) — verbatim.
   Tests and pinned deployments; the whole existing test suite is untouched.
2. `${base}/current/arbiter.sock` — when the promoted instance's socket exists.
   Note clients keep the **`current/` spelling** (not the resolved target), so
   every re-connect follows the newest promotion automatically.
3. `${base}/arbiter.sock` — the legacy fixed path (pre-instance stacks), one
   release of compat.

**Never `mkdir -p` a path through `current`** — creating `current` as a real
directory breaks the promotion rename. The supervisor and launcher special-case
this (logs live at `${base}/logs`, not `dirname(sock)/logs`).

### 3a. A socket path the kernel would shorten is refused

`sockaddr_un.sun_path` holds 108 bytes on Linux (104 on macOS and the BSDs),
the trailing NUL included, and the size is fixed by the kernel ABI: it cannot
be raised. bind(2) and connect(2) do not fail on a longer path; they use its
first 107 bytes. An arbiter started on such a path therefore binds a name no
client looks for, and a client dials whatever sits at the shorter name (another
arbiter, if one is there).

A check only in the launcher (`launcher/src/arbiter.ts` `assertSockPathFits`)
is not enough: `scripts/dev-arbiter.sh`, an explicit path to `server-main`,
the dashboard supervisor under a deep `MANDU_RUNTIME_DIR`, and the TS client
all reach the kernel without it (a 113-byte socket bound as `…/arb/arbiter`,
and `mandu doctor` reported the arbiter unreachable with no hint why).
`arbiter/ipc/socket-path.ts` is the one check, applied where the kernel is
asked: `ArbiterServer.listen()` refuses before it claims the symbol DB (so
server-main exits 1 with the reason and removes its instance dir), the admin
socket path is refused the same way, and `ArbiterClient` refuses to dial or
subscribe. The limit is measured in bytes of the string handed to the kernel,
so a relative path counts as given. The Rust client needs no check: std's
`UnixStream::connect` already returns an error for a path that does not fit.
Workarounds that lift the limit (bind a relative path after `chdir`, bind
through `/proc/self/fd/N/`, abstract sockets) are not used: the first two
need every client to repeat the trick, and an abstract socket has no file
permissions, so any process in the network namespace could reach the arbiter.

### 3b. The runtime base fits an instance socket by construction; its /tmp fallback is private (2026-09-29)

**The incident.** macOS has no `XDG_RUNTIME_DIR`, and the per-user `TMPDIR`
it sets at login (`/var/folders/<2>/<28>/T/`, 49 bytes) left no room under
macOS's 103 usable `sun_path` bytes: the arbiter was asked to bind
`$TMPDIR/mandu/instances/<id>/arbiter.sock` (107 bytes) and refused (§3a),
the launcher's preflight had checked only the short `current/arbiter.sock`
spelling (75 bytes), so it waited 11 s for an arbiter that could never bind
and then refused "did not come up", and the dashboard it had spawned stayed
behind with no owner. `mandu claude` could not start on any Mac. The rule
itself was spelled five ways (arbiter `instance.ts`, launcher `arbiter-sock.ts`,
`parse.ts`, `subcommands.ts`, dashboard `server-main.ts`), no two alike.

**The rule** (one pure function, `resolveRuntimeBase`, with the platform, uid
and fallback root injectable; identical in every copy):

1. `$MANDU_RUNTIME_DIR` verbatim (one trailing `/` stripped);
2. else `$XDG_RUNTIME_DIR/mandu` — Linux, unchanged;
3. else `cand = ($TMPDIR || /tmp)/mandu-<uid>` (per-user since 2026-10-09,
   below; `($TMPDIR || /tmp)/mandu` before), used when
   `byteLength(cand) + INSTANCE_SOCK_SUFFIX_MAX < SUN_PATH_MAX` (104 on
   darwin and the BSDs, 108 elsewhere) — a short TMPDIR;
4. otherwise the **fallback** `/tmp/mandu-<uid>` (`process.getuid()`).

Rules 1–2 are the path table's `runtime-dir` (on-disk-layout.md §5), and
rule 3 is the table's `runtime-dir` under `TMPDIR` with `-<uid>` appended
(each copy takes it from the generated `manduPath`): only env counts, so an
env without `TMPDIR` gives `/tmp/mandu-<uid>`, never the process's
`os.tmpdir()`. The rule adds the uid, the fit check and rule 4, which the
table (a function of the environment alone) cannot express; a process with
no uid (no `getuid`) keeps the shared `($TMPDIR || /tmp)/mandu`. The shell
callers that need the base (the VM harnesses' guest registry) use the same
rule from `scripts/lib/runtime-base.sh`. The
human-plane sockets (`<base>/human/<id>.sock`, arbiter-human-plane.md) add at
most 51 bytes, under the instance socket's 63, so the same budget covers them.

`INSTANCE_SOCK_SUFFIX_MAX` = `/instances/` + the longest `instanceId()` (13-char
time + `-` + the rev sliced to 16 + `-p` + a 7-digit pid, Linux's pid_max
4194304) + `/arbiter.sock` = **63 bytes**, pinned against `instanceId()` by
`arbiter/test/unit/runtime-base.test.ts`. So `cand` must be at most 40 bytes on
macOS and 44 on Linux; the fallback is at most 21 bytes (`/tmp/mandu-4294967294`),
so a base from rule 4 always has room. Rule 2 takes `XDG_RUNTIME_DIR` as
given, with no size check: real ones (`/run/user/<uid>`) are short, and a
long one is caught by the launcher preflight below, which names
`XDG_RUNTIME_DIR` for that reason. The stock macOS TMPDIR gives
`/tmp/mandu-<uid>` (a dev-checkout instance socket of about 67 bytes). The fallback
also leaves macOS's `T/` dir, whose `dirhelper` deletes entries unused for 3
days — a resident `current` link or instance socket there could vanish.

The copies: `arbiter/ipc/runtime-base.ts` (the owner; `instance.ts runtimeBase`,
`socket-path.ts SUN_PATH_MAX`), `launcher/src/runtime-base.ts`
(`arbiter-sock.ts runtimeBase`/`resolveArbiterSock`; the kernel-probe cache
location and deletion in `probe-cache.ts`; the scope-dir root in
`parse.ts`; `mandu dashboard`'s `dashboard.log` and port file in
`subcommands.ts`; `platform/{darwin,linux}.ts runtimeDir`, until now unused and
different), `dashboard/src/runtime-base.ts` (`server-main.ts RUNTIME_BASE`). The
parity oracle `tests/stack/runtime-base-parity.test.ts` runs every
copy over one env × platform × uid × root × tmpdir matrix. The test-harness
mirrors under `tests/integration/test/{live,e2e}` (`live-shared.ts`,
`codex-e2e.test.ts`, `replay-e2e.test.ts`) import the arbiter's
`resolveRuntimeBase` instead of spelling the old form. The fourth place that
names a base, the entrypoint of the maintainers' docker e2e rig (not
published, docker-e2e.md §2), spelled the pre-rule form
`${XDG_RUNTIME_DIR:-${TMPDIR:-/tmp}}/mandu` and would have polled the wrong
base under a TMPDIR too long for rule 3. It now carries no copy of the rule:
before it starts anything it exports `MANDU_RUNTIME_DIR` (the path table's
`runtime-dir` with TMPDIR unset: the caller's, else `${XDG_RUNTIME_DIR:-/tmp}/mandu`),
so the dashboard, its
arbiters and the suite all take rule 1 and agree. A test beside the rig
evaluates that line.

**Scope dirs and `mandu dashboard` use the same base** (rules 1–4; since the
path table moved them, on-disk-layout.md §5, `MANDU_RUNTIME_DIR` moves them
with the instances): `scopeRunDir = <base>/<scopeId>` and `mandu dashboard`
writes `<base>/dashboard.log`. On a Mac they leave the long TMPDIR the same way
the arbiter does (and `mandu reap`, which scans the base for stale scope dirs,
finds them there).

**The fallback is private or nothing.** `/tmp` is shared by every account, so
a `/tmp/mandu-<uid>` another user created first could hold a `current` link
to an impostor arbiter that every client would dial. Wherever Mandu is about
to use the fallback it is created with mode 0700 when absent (then `chmod`ed,
since the umask can narrow it); otherwise `lstat` must show a real directory
(not a symlink), owned by this uid, with no group/other permission bits — else
the start is **refused** with the fix named (remove it if it is yours, or set
`MANDU_RUNTIME_DIR` to a private dir). Never chmod-repaired: a shared dir may
already hold someone's link. After the check it stays ours: `/tmp` is sticky,
so nobody else can rename or remove it. A process recognizes the fallback by
PATH (both `/tmp/…` and the canonical `/private/tmp/…`), because the arbiter
and dashboard the launcher spawns receive the base as `MANDU_RUNTIME_DIR`.

**A base directly in a shared sticky dir is ours or nothing** (2026-09-29).
The same attack works on any base whose PARENT is world-writable with the
sticky bit (`/tmp`, `/var/tmp`): `/tmp/mandu` on Linux without
`XDG_RUNTIME_DIR` (su, cron, ssh without pam_systemd, containers) and
`$TMPDIR/mandu` on macOS with `TMPDIR=/tmp`. Another account could create it
first and plant a `current` link, and before this change nothing checked it
(the gap predates macOS support; Linux always had it). Such a base gets a
RELAXED form of the fallback rule (`ownedDirProblem`): created 0700 when
absent (non-recursive, so a dir someone made first is checked, never adopted
by a `mkdir -p`); otherwise a real directory, owned by this uid, that no other
account can WRITE. Group/other read and search stay allowed, so the 0755 dir
an earlier arbiter made with a 022 umask passes. The strict rule would have
refused every such dir. The check keys on the parent's mode, not on where the
base came from, so an explicit `MANDU_RUNTIME_DIR=/tmp/<x>` is covered too
(the arbiter and dashboard the launcher spawns receive every base as an
explicit one). The fallback keeps
the strict rule. **Visible on Linux:** a `/tmp/mandu` owned by another
account, or one that group/other can write, is now refused with the fix
named (remove it, or set `MANDU_RUNTIME_DIR`). That includes the 0775 dir an
earlier version made under a 002 umask (the default for user-private-group
accounts on several distributions): a one-time `rm -rf /tmp/mandu` (after
`mandu stop`), and the next start makes it 0700. A new `/tmp/mandu` is created
0700 instead of with the umask's mode.

**Any other base is made 0700** (2026-10-17). The two rules above left every
other base unchecked: `$XDG_RUNTIME_DIR/mandu` (Linux's default) and an
explicit `MANDU_RUNTIME_DIR` whose parent is not a shared sticky dir (the
dashboard service unit sets `%t/mandu`). Whoever got there first made it with a
`mkdir -p` and the umask's mode (`startArbiterInstance`'s `mkdirSync(base,
{recursive})`, the arbiter's `createInstanceDir`), so a 002 umask (the default
for user-private-group accounts on several distributions) left
`/run/user/<uid>/mandu` at 0775, found on a dev host. The base holds the
sockets, `current` and the registry: a base that group members can write lets
one of them plant or replace a socket or a `current` link, the same impostor
attack the fallback rule closes. Under `/run/user/<uid>` (logind makes it
0700) nobody else could reach it, so the hole was latent there; under an
explicit base in an open directory it was not. The third rule
(`ensureRuntimeBaseDir`, `assertRuntimeBaseIfPresent`, `runtimeBaseVerdict`;
in every copy, held equal by the parity oracle):

- absent: created 0700 (its missing ancestors too) and `chmod`ed, since the
  umask can narrow the mode;
- a symlink, not a directory, or another uid's: refused;
- ours with group/other bits, **sealed**: tightened to 0700. Sealed
  (`sealedFromOthers`) means an ancestor owned by this uid or root grants
  group and other no search permission (`/run/user/<uid>`, a mkdtemp dir,
  macOS's per-user `T/`). Then only this uid could have set the bits (only an
  owner chmods) and no other account could have reached inside, so nothing
  can be planted there and tightening loses nothing. This is what repairs an
  existing 0775 `/run/user/<uid>/mandu` on the next start, with no step from
  the user;
- ours with group/other bits, not sealed: the relaxed rule above. A base
  others can WRITE is refused with the fix named, never chmod-repaired (a
  link or socket may already be planted, and a chmod would not remove it); a
  0755 one passes.

The verify-only readers (`assertTrustedIfPresent`) refuse what the rule
refuses and pass a sealed base with group/other bits without changing it.
`ensureArbiter`'s preflight applies the rule to a PRESENT base (tighten or
refuse, before it attaches to a socket there) but does not create an absent
one (`guardRuntimePath`'s `createOther: false`), so a launch the arbiter
step refuses (a base too long for its socket) still creates nothing; the
creators after it (`startArbiterInstance`, `startArbiter`, the scope-dir
guard, `mandu dashboard`, the arbiter and dashboard `server-main`) make it
0700. The launcher unit tests that handed `parse` a literal
`XDG_RUNTIME_DIR=/run/user/1000` now use their own private runtime dir: on a
host where uid 1000 exists, that path is another account's 0700 dir, which the
rule rightly refuses (test-organization.md §8.7).

The checks for all three rules sit before first use (`ensurePrivateIfFallback`
creates or verifies, `assertTrustedIfPresent` only verifies):

- **arbiter** `server-main.ts`: before the dead-instance sweep reads the base
  and before the instance dir is created (`[arbiter] fatal: …`, exit 1);
- **dashboard** `server-main.ts main()`: before its event source dials
  `current/arbiter.sock`, the registry writes `dashboards/`, or the supervisor
  starts an arbiter (`[dashboard] fatal: …`, exit 1);
- **launcher**: `assertRuntimeBaseTrusted` (`arbiter-sock.ts`), called by
  `resolveArbiterSock` — so by every launch's `parse` and by `status`, `stop`,
  `doctor`, `mode`, `dashboard`, even for a pinned socket, since the registry
  still lives under the base — and by `mandu reap` before it signals any pid
  a manifest names, verifies a present base (the fallback, a shared-sticky-dir
  base, any other base) before anything under it is trusted (read-only: an absent one passes); `ensureArbiter` — the first
  thing a launch does after `parse` — creates-or-verifies it for the
  socket, the log and the DEFAULT base (the
  scope-dir root, which can be the fallback even when `MANDU_RUNTIME_DIR`
  moved the arbiter elsewhere), before attaching; `run.ts` runs the same
  check, with `main()`'s env, right before it makes its scope dir (§10.2);
  `startArbiter` and `startArbiterInstance`
  before they create anything; `mandu dashboard` before it trusts a
  registry entry (a stranger's URL) and before its log.

`ensureArbiter` and `startArbiterInstance` judge the env `main()` was
handed (2026-10-09; before, both read `process.env`, which the real CLI
passes but a caller with another env, a test, does not): the fallback rule,
the default base, the instance socket's fit and its `XDG_RUNTIME_DIR` advice
and the moved-base hint are all about the base this launch resolved from
that env (`startArbiterInstance`'s `runtimeEnv`). The pinned socket's
`startArbiter` takes the same `runtimeEnv` for its log, event dir and
socket (2026-10-10; it read `process.env`, harmless only because
`ensureArbiter` and the scope-dir guard had already judged those paths with
`main()`'s env), so no launcher runtime-dir check reads `process.env`. The
autostarted stack, and the pinned arbiter, are still spawned with
`process.env`, the same env in the real CLI. A caller with a different env could once have had
`run.ts` create a fallback scope root with the umask's group bits, which the
next default launch then refused (fail closed, "remove it"); `run.ts`
passing its scope dir as `runtimeDirs` closed that, and since 2026-09-30 it
also guards the scope dir with `main()`'s env right before it makes it
(§10.2). Tests: `launcher/test/component/run.test.ts` ("the autostart's
runtime-dir checks read the env main() was handed") and
`launcher/test/unit/arbiter.test.ts` (`runtimeEnv` over the spawn env, for
`startArbiterInstance` and the pinned `startArbiter`).

**`MANDU_RUNTIME_FALLBACK_ROOT` is a test hook**, not a product setting: it
replaces the `/tmp` root of the fallback so the e2e suites exercise the real
fallback without touching the host's `/tmp/mandu-<uid>`. It grants nothing
`MANDU_RUNTIME_DIR` does not (whoever sets the env picks the base anyway), and
the account rendezvous (§13) never reads it.

**The launcher preflight checks the socket the arbiter will bind.** In
autostart (instance) mode, `startArbiterInstance` refuses at once when the
instance socket of the arbiter it is about to start would not fit, naming the
byte budget and `MANDU_RUNTIME_DIR` (and `XDG_RUNTIME_DIR` when that is where
the base came from). A base from rules 3–4 always fits, so this fires only for
an explicit dir or a long `XDG_RUNTIME_DIR`. The socket is sized with the REAL
suffix (`instanceSockSuffix`): the rev the arbiter will put in its id, read the
way `server-main.ts` reads it (`git rev-parse --short HEAD` in `REPO_DIR` =
its own dir `/../..`: the checkout root, or the dir that holds an installed
package, else `nogit`; `arbiterRevOf(arbiterRevDir(layout))`), and the widest
pid of the platform (5 digits on darwin, 7 elsewhere). The rev is read only
when the 63-byte worst case does not fit, so a short base runs no git. The
first version of this preflight used the worst case and refused 45–52-byte
Linux dirs that had always bound (an 8-char rev and a 7-digit pid make 101
bytes of 107). Now it refuses only what the arbiter cannot bind, and the
arbiter's own `socketPathProblem` (§3a) stays the authority. The advice still
names the worst-case budget (40 bytes on macOS, 44 on Linux), since a dir that
size always fits.

**A base moved off `$TMPDIR/mandu` is named once.** On Linux without
`XDG_RUNTIME_DIR` and with a TMPDIR of 39–47 bytes, the rule moves the base
from `$TMPDIR/mandu`, where every earlier version put it, to
`/tmp/mandu-<uid>`. A resident stack started before the upgrade then keeps
running unseen: `mandu status`/`reap` look under the new base, and its arbiter
still holds the symbol DB, so the autostart beside it can fail. When an
autostart finds the default base is the fallback while
`$TMPDIR/mandu/current/arbiter.sock` resolves (`movedBaseHint`,
`arbiter-sock.ts`), `startArbiterInstance` prints one line naming the old base
and how to stop it (`MANDU_RUNTIME_DIR=<old> mandu stop --all`). The old base
is not reused.

**A failed supervised autostart stops its dashboard.** The dashboard the
launcher spawns is ownerless (`MANDU_OWNER_PID=none`, §8), so when it does not
promote an arbiter within 6 s the launcher now SIGTERMs its whole process
group (SIGKILL after 10 s if still there — longer than the supervisor's own 4 s
stop grace, so it can stop an arbiter it started) before falling back to the
bare arbiter.

**A squatted `/tmp/mandu` (2026-10-09).** On a host without
`XDG_RUNTIME_DIR` every account's default base was the same `/tmp/mandu`,
so whoever made it first owned it. Found on a shared dev host where another
account's `/tmp/mandu` (mode 0700) stood: every reader and creator above
refused it with the actionable message (no product path trusted it), so a
launch there failed closed and needed `MANDU_RUNTIME_DIR` or an
`XDG_RUNTIME_DIR`: a denial of service another local account could cause,
not a leak. **Rule 3 is per-user since then:** the name an account resolves
is `($TMPDIR || /tmp)/mandu-<uid>`, its own, so on Linux without `TMPDIR`
rule 3 gives the fallback's own name and the same strict check (created
0700, else a private dir of this uid); another account's `/tmp/mandu` is
simply not looked at, and a squat of the per-user name is still refused.
The arbiter, launcher and dashboard copies change together (the parity
oracle holds them equal); the path table stays a function of the
environment alone. **An install from before:** a stack an older version
started under `/tmp/mandu` keeps running there unseen by the new
`mandu status`/`stop`/`reap`; the first autostart that finds this user's
own `/tmp/mandu/current/arbiter.sock` live prints one line naming it and
`MANDU_RUNTIME_DIR=/tmp/mandu mandu stop --all` (`movedBaseHint`, which now
fires for any rule 3–4 base that moved off the shared name, and never for a
`/tmp/mandu` that is not this user's directory). Nothing is migrated: the
base is per-boot state (sockets, scope dirs, kernel-probe cache) that the
next start makes afresh, and `/tmp` is cleared at boot. Tests:
`launcher/test/unit/runtime-base.test.ts` (two accounts, two bases; a squat
of the per-user name refused), `arbiter/test/unit/runtime-base.test.ts`,
`launcher/test/unit/arbiter-sock.test.ts` (the hint, this user's old stack
only), and the e2e `launcher/test/component/runtime-fallback.test.ts` case 6
(a squatted, world-writable `$TMPDIR/mandu` with a planted `current` to an
impostor: the real launch autostarts under its own `mandu-<uid>`, the
impostor gets no connection, nothing is created in the squat). The
audit found three helpers that read or wrote under the base without the
check, closed then: `mandu stop` attributes a process to a stack through a
base's registry only when that base is a real directory of this uid and,
directly in a shared sticky dir, one no other account can write (the rule
above; `registryTrusted`, `subcommands.ts`; the registry is consulted only
for a process whose environment it cannot read);
`mandu setup`'s probe-cache delete goes only through a `probe-cache` dir that
is this uid's private directory, never through a planted link
(`clearProbeCacheFile`); and the VM harnesses' guest registry
(`scripts/lib/guest-registry.sh`) creates its dirs under umask 077, refuses
a base directly in a shared sticky dir that is not this uid's or that
others can write, and refuses a `vm-guests` that is a link or not its own.
The launcher's tests no longer reach the shared name either
(test-organization.md §8.7).

Tests: `arbiter/test/unit/runtime-base.test.ts` (every branch, the 63-byte pin,
the real-suffix pin against `instanceId()`, the private-dir and owned-dir
verdicts incl. a simulated foreign owner, the darwin rendezvous),
`arbiter/test/component/runtime-fallback.test.ts` (the real daemon binds and
promotes under a 0700 fallback; refuses a 0755 one and a symlink; under a
sticky TMPDIR it creates `<TMPDIR>/mandu` 0700, serves a self-made 0755 one,
refuses a 0775 one),
`launcher/test/unit/{runtime-base,arbiter-sock,arbiter,parse,platform,subcommands}.test.ts`
(the mirror, the verify-before-trust refusal for both rules, the preflight
with the real suffix — a Linux 46-byte base starts, a 53-byte one refuses —
the rev reader, the moved-base hint, the private creation, the dashboard
group stop with a real process group, `accountOf` on darwin),
`launcher/test/component/runtime-fallback.test.ts` (a real launch with a
long TMPDIR autostarts under a 0700 fallback; a 0755 one refuses before any
spawn; an over-long `MANDU_RUNTIME_DIR` fails in well under 5 s; a 46-byte
`MANDU_RUNTIME_DIR` autostarts; a group-writable base in a sticky TMPDIR
refuses before any spawn),
`launcher/test/component/instance-autostart.test.ts` (now on a short base, so it
passes on macOS), `dashboard/test/unit/runtime-base.test.ts`,
`dashboard/test/component/runtime-fallback.test.ts` (the real dashboard creates and
registers in a 0700 fallback; exits 1 on a 0755 one, never listening), and the
parity oracle above (which also holds the real suffix, the rev reader, the
owned-dir rule and the docker entrypoint's pin to one answer). The third rule
(2026-10-17): `{launcher,arbiter,dashboard}/test/unit/runtime-base.test.ts`
(created 0700 under a 002 umask, ancestors too; a sealed 0775 base tightened,
the reader leaving it as is; an open 0775 one refused and never
chmod-repaired, an open 0755 one kept; a symlink and a foreign owner refused;
the sealing walk; no Linux env with a known uid resolves the shared
`/tmp/mandu`), `arbiter/test/component/runtime-fallback.test.ts` (the real
daemon under a 002 umask with `MANDU_RUNTIME_DIR` in a private dir, as the
service unit starts it: created 0700, an earlier 0775 one tightened), and
`launcher/test/component/runtime-dir-mode.test.ts` (a real launch under a
002 umask with `XDG_RUNTIME_DIR` set autostarts under `<xdg>/mandu` made
0700 and leaves the shared `/tmp/mandu` and `$TMPDIR/mandu` untouched; an
earlier 0775 one is tightened and the launch starts; an explicit open 0775
`MANDU_RUNTIME_DIR` refuses before anything is spawned).

## 4. The `hello` handshake (staleness detection)

New IPC op `hello` → `{ pid, startedAt, instanceId, gitRev, gitDirty,
version, build, sockPath, eventDir, symbolDb, protocolVersion }` (`version`,
the release, since 2026-10-09; `build`, which build of it, since 2026-10-17:
§4.1). The dashboard supervisor:

- on **adopt** (endpoint already live), fetches identity and logs WHO it
  adopted; another release or build (below), or a stale `gitRev`, marks the
  service **STALE** in
  `/api/control/status` (`identity` + `stale` + `staleReason` fields) and the
  control panel shows "STALE arbiter: \<reason\> — restart it to load the
  current code".
- on **spawn**, records the identity of the child it started.

Staleness is **scope-honest** (`supervisor-defs.ts arbiterStaleness`): a rev mismatch flags only when
`git diff --name-only <identityRev> <HEAD> -- arbiter/` is non-empty — the
arbiter is a standalone package, so a dashboard-only commit must not banner it
(restarting would load byte-identical code; an over-eager badge trains the
operator to ignore it — the same committed-drift rule as the dashboard's own
self-status). HEAD is re-read per status poll, so an arbiter commit landing
mid-run flags without a dashboard restart. One deliberate asymmetry vs the
self-check: a rev this repo **cannot resolve** (rebased away, another checkout's
unpushed commit) flags stale, **fail-loud** — the identity is a foreign daemon's
claim, and an unresolvable rev is the masquerading-daemon trap itself, not noise
(the self-check's `bootRev` is self-captured, so there an unresolvable rev means
repo breakage and fails quiet).

**Release and build first (2026-10-17).** Before the rev rule, the
supervisor compares the adopted arbiter with what it would start itself
(`supervisor-defs.ts arbiterReleaseStaleness`, its own side read by
`own-arbiter-build.ts`: its package.json's version and the SHA-256 prefix of
the arbiter bundle it spawns, `<pkg>/dist/arbiter.mjs` installed or the
checkout's `launcher/dist/arbiter.mjs`, cached by size and mtime and re-read
per status poll). STALE when the arbiter reports another `version` (or, with
`protocolVersion`, none: a release from before the check); when both sides
have a bundle and the hashes differ (another build of one release, which an
installation, with no rev to compare, could not see before); or when an
installation's dashboard adopts an arbiter that runs a checkout's source.
Otherwise the rev rule decides, so a checkout keeps its scope-honest verdict.
The adopt log names the version and bundle too.

Old daemons without the op adopt as before with `identity: null` (unknown, not
trusted-as-fresh).

### 4.1 A launch never uses an arbiter of another release (2026-10-09)

**The gap.** The resident stack (the dashboard supervisor and its arbiter)
outlives the launcher on purpose (§8). After an upgrade, the next `mandu`
found the old arbiter on `current/arbiter.sock` and attached to it without
a word. An op the new launcher or one of its children needs could be
missing or refused there (the S8 miss, reply-row-reservation.md §18, was
one such skew between two commits), and the fixes of the new release were
not in force where the decisions are made. The dashboard's STALE flag
(§4) compares git revs in a checkout; an installed release has none.

**The marker.** `hello` reports `version`, the release the arbiter's code
belongs to (`arbiter/ipc/release-version.ts`: the `package.json` one level
above the module, which is `arbiter/package.json` from source and the
package root beside `dist/` in the bundle; one version for the product,
packaging.md §11.2). The launcher's own is `launcherVersion`.

**The build (2026-10-17).** `version` orders releases; two commits of one
version share it (the S8 miss, reply-row-reservation.md §18.2). `hello`
also reports `build: { bundle, rev }` (`arbiter/ipc/build-identity.ts`),
from what the code already carries, with no network and no git at run time
for an install:

- `bundle`: when the arbiter runs from a bundle (an install's
  `dist/arbiter.mjs`, or a checkout's own build), the first 16 hex digits of
  the SHA-256 of that file, hashed when the process starts (server-main), so
  a rebuild that renames a new file over it later does not change what it
  reports. esbuild's output is a function of its inputs: a commit that did
  not touch the arbiter's code builds the same bytes. Null from source.
- `rev`: the short git rev the instance id carries (`gitRevOf`), only from
  source or from a checkout's own build (`dist/` beside `../src/run.ts`). An
  installed bundle reports none: the directory holding the package can sit
  inside an unrelated work tree (a Homebrew prefix).

The launcher computes the build the arbiter it starts would report
(`arbiter-version.ts ownArbiterBuild`: the hash of `<pkgRoot>/dist/arbiter.mjs`
when its layout runs bundles, the checkout's rev in a dev layout), read only
when the release matches and the arbiter reports a build. **Same build or
not** (`compareBuilds`; a build has no order):

| Both sides | Same build when |
|---|---|
| run a bundle | the hashes are equal (whatever the revs) |
| carry a checkout rev (one runs from source) | the revs are equal, or their `arbiter/` trees are (`arbiterTreesMatch`: one hardened `git rev-parse <rev>^{commit}:arbiter` each, hex revs only; a rev this checkout cannot resolve is not the same), the scope of the dashboard's STALE flag (§4) |
| share neither (an install's bundle against a checkout's source) | never: two places |
| either reports nothing (an arbiter from before 2026-10-17, an embedded test server, a launcher with no git and no bundle) | no evidence: the version decides alone |

**The check** (`launcher/src/arbiter-version.ts`, wired in `run.ts` right
after `ensureArbiter`, before the tenant and axis preflights and before any
session-keyed op, service or event):

| `hello` says | What the launch does |
|---|---|
| this release, the same build (or no build to compare) | proceeds |
| nothing comparable: no answer, a refusal, or a result without `protocolVersion` (no arbiter identity); or this `mandu` cannot read its own release (a bundle moved away from its `package.json`, where the arbiter it starts cannot read its own either) | proceeds; a mute arbiter is no evidence of a skew, and every op the launch then needs fails closed on its own |
| another release, or no `version` beside `protocolVersion` (a real arbiter of a release from before the check) | by the cases below |
| this release, another build | by the cases below, as "older" (there is no "newer" build); each message names both builds (`another build of Mandu X (bundle …, rev …) than this mandu (…)`) |

For another release (or build):

- **the arbiter this launch just started**: refused (a mixed install, or
  another release's launch won the start at the same moment);
- **a pinned socket** (`MANDU_ARBITER_SOCK`): refused, naming the socket and
  `unset MANDU_ARBITER_SOCK`; the caller owns that arbiter, so the launcher
  never stops it;
- **the account's resident stack** (`current` or the legacy path), **newer**
  than this `mandu` (semver precedence, update-check.ts): refused, naming
  `mandu stop --stack <runtime dir>`. Never a downgrade by accident: two
  installs of different releases would otherwise restart each other's stack;
- **the resident stack, older** (or a version that does not parse, or
  another build of this release), **while
  another `mandu` session uses it**: refused, naming the sessions' pids and
  `mandu stop --stack <runtime dir>` (which ends their protection). A
  session is a process of this user titled `mandu` (§7) whose stack is this
  one, placed the way `mandu stop` places it (§10.3: its environment, else
  the stack's registry, where every launch has its scope dir, §10.4); a
  container's is another stack's. A short-lived verb (`mandu status`)
  carries the title too and counts: the refusal is the safe side;
- **the resident stack, older (or another build), no other session**: the
  launch says so in one line (`the Mandu services running for you were
  Mandu X; restarting them as Mandu Y`; for a build, `… were another build
  of Mandu X (…) than this mandu (…); restarting them as this build`), SIGTERMs the stack's resident daemons (what `mandu stop
  --stack` signals, `stopStackAndWait`), waits up to 15 s for them to exit
  (refused, naming them, if one does not), and starts this release's stack in
  instance mode at the `current` spelling (a legacy fixed-path stack is
  replaced by an instance one). The restarted arbiter must then report this
  release and build; anything else, an unanswered `hello` included, is a
  refusal.

The table as decisions (`launcher/test/unit/arbiter-build.test.ts` walks
all 48 rows: six verdicts × started × pinned × in use):

| `hello` | started by this launch | pinned | another session | Action |
|---|---|---|---|---|
| same release and build, or nothing to compare | any | any | any | proceed |
| another build, older release | yes | any | any | refuse |
| another build, older release | no | yes | any | refuse |
| another build, older release | no | no | yes | refuse, naming `mandu stop --stack` |
| another build, older release | no | no | no | restart as this build |
| newer release | any | any | any | refuse |

**Racing launches (2026-10-17, `launcher/src/release-gate.ts`).** Two
launches started together on one older (or other-build) unused stack used
to refuse each other: each saw the other, a process titled `mandu` on the
stack, as a session. Under `<base>/release-check/` (made only inside an
existing runtime dir, never creating it; nothing for a pinned socket):

- every launch writes `pending-<pid>` when its check starts and removes it
  when the check ends, before any session op. The peer scan leaves out a
  launch with a fresh marker (it has used nothing but `hello`); a marker
  whose pid is dead or older than 10 min counts for nothing, so that launch
  is a session again, the safe side;
- a launch that would restart takes the stack's restart lock (`lock/`, an
  atomic mkdir holding its pid; a dead holder's is taken over; refused after
  90 s), reads `hello` again under it and only then stops and starts. The
  second launch, once it holds the lock, finds this build's stack and
  proceeds; when the stack it saw is gone (a legacy path the first one
  replaced) it attaches at `current` and checks that, as after a restart.

`enforceRelease` (arbiter-version.ts) is that driver, with the effects
injected; run.ts wires the real `hello`, the gate, `stopStackAndWait` and
the start.

**The gate and the agent.** A marker the agent could write is an attack: a
`pending-<pid>` naming a live session's launcher takes that session out of
the next launch's scan, so a launch of another build (or an older stack's
upgrade) would stop the stack under it. Nothing would leak (the session's
interceptors fail closed while the arbiter is down and then reach the new
one, the build the user just ran), but the session would lose protection
mid-run and talk to an arbiter it was not checked against, the very skew
this check exists for. So `release-check/` is a runtime registry entry
(`launcher/src/runtime-registry.ts`, §2 "planted paths"): the Linux guard's
write-protect list and the macOS profile deny the agent every file write
under it, and a scope id may not name it. The guard does not judge a bare
mkdir (write-protection.md §2), so the gate believes only what a launch
writes: `release-check/` must be a real directory (lstat, not a link), a
marker must be a regular file whose content is its pid, and a lock dir
with no owner file (all the agent can make) is taken over after 5 s. What
the agent can still do is delay a restart by re-making that ownerless
lock; a launch that waits too long refuses (the safe side). An unconfined agent (no guard) can write there
as it can write every registry entry; that posture is the guard's
(write-protection.md).

**Fail-closed.** Every case that does not proceed refuses before any
session op, so nothing reaches an arbiter of another release beyond the
one `hello`. The stack test proves it with an op tap.

**Not covered.** Two dirty work trees at one rev, both running from source,
look alike (the rev is all they report; a checkout's bundle is hashed, so
there an edit shows). Two checkouts of one version alternately launching on
one unused stack restart it each time (a build has no order to settle it);
when a session is on it they refuse instead. A launch still in
`ensureArbiter` when another scans for sessions has no marker yet and counts
as a session (the safe side: that scan refuses). A stack under a service
manager that restarts it (a systemd unit) is §4.1a.

**Tests.** `launcher/test/unit/arbiter-version.test.ts` (the verdicts, every
case of the table above, the session scan only when a restart is possible,
`liveLaunchersOn` and `stopStackAndWait` over a mock process table);
`launcher/test/unit/arbiter-build.test.ts` (`parseBuild` keeps hex only,
`compareBuilds`, the build verdict and when the launcher's own build is
read, the 48-row decision table, both builds in every message,
`ownArbiterBuild` per layout, and `enforceRelease` with two launches racing
on one stack over the real gate in a temp dir: one restart, the other
adopts; beside a real session both refuse; stale markers and dead lock
holders); `arbiter/test/unit/release-version.test.ts` (`hello` reports the
package's version; an identity can stand in for another release or a
pre-check one); `arbiter/test/unit/build-identity.test.ts` (the digest, the
rev only from source or a checkout's build, `hello`'s `build` and its
stand-ins); `launcher/test/component/bundle-smoke.test.ts` (the bundled
arbiter reports the package's version and its own file's hash, which is
what `ownArbiterBuild` computes for that package);
`dashboard/test/unit/supervisor/supervisor-release-stale.test.ts` (the
release and build verdict, the dashboard's own build, and `status()` going
STALE live when the bundle it would start changes);
`tests/stack/arbiter-version-skew.test.ts` (the real launcher against real
arbiters that say they are another release: a pinned one refused with only
`hello` on the wire; a resident one with a session on it refused and left
running; a resident one with none stopped and replaced, the agent run
against this release's arbiter); `tests/stack/arbiter-build-skew.test.ts`
(the same against real arbiters of this release and another build: pinned
refused naming both builds with only `hello` on the wire; resident in use
refused and left running, and a real dashboard supervisor adopting it flags
it STALE by build; resident unused replaced, the new arbiter reporting this
checkout's rev, no gate file left behind).

### 4.1a A stack a systemd service restarts is named, not fought (2026-10-19)

**The gap.** §4.1 restarts an unused resident stack of another release or
build. Found 2026-10-19 on a host that moved from a source checkout to the
npm package: the checkout's dashboard ran as a systemd user service
(`ExecStart=…/node_modules/.bin/tsx src/server-main.ts`, `Restart=always`)
on the account's default runtime folder. Stopping that stack only started
the old code again a few seconds later, so the outcome raced: either the
new launch's arbiter came up first and the old dashboard re-attached to it
(a mixed stack nobody checked), or the old dashboard started its own old
arbiter first and the launch refused with "the installation is mixed:
reinstall Mandu", which sent the user to the wrong fix.

**The rule** (`launcher/src/stack-supervisor.ts`, wired into
`checkArbiterRelease`). For a resident stack of another release or build
(not pinned, not started by this launch), the launch reads
`/proc/<pid>/cgroup` of the arbiter (its pid from `hello`) and of every
resident daemon of that stack (`residentPidsOn`, by title and stack). A
daemon in a `*.service` cgroup is **supervised** when `systemctl [--user]
show` says the unit has `Restart=` set (not `no`) and its `MainPID` is that
daemon or the daemon's direct parent (an ExecStart through tsx, npm or a
script: when the daemon dies the wrapper exits and the unit restarts).
Deeper inside a service's cgroup is not supervised: a launch from a CI
runner's job sits in the runner's cgroup, and the runner does not restart
it. Supervised, the restart becomes a refusal naming the unit, its
`Restart=` and working directory, its unit file, and two ways out: for a
leftover service, `systemctl [--user] disable --now <unit>`; for a service
kept on purpose, this mandu on a stack of its own beside it,
`MANDU_HOME=~/.mandu-own MANDU_RUNTIME_DIR=<base>-own mandu …`. Both
variables: a runtime folder of its own is not enough, because the symbol
database has one writer and its owner lock (`mandu.db.owner`) refuses a
second arbiter, so the second stack's arbiter would not start and the
launch would refuse to run ungated (tried on the lab host 2026-10-19: the
runtime folder alone was refused at the lock; both together launched). Its
own Mandu folder means its own rules and history; the message says to copy
`policy.yaml` and `config.toml` over to keep the rules.
Every other refusal of §4.1 that says "stop it" names both instead of
`mandu stop --stack`. Linux only; elsewhere, and whenever /proc or
systemctl does not answer, nothing is supervised and §4.1 stands.

**Why refuse rather than restart through systemd, or warn and go on.** The
unit is the user's configuration and runs another install's code;
replacing what it runs, or stopping it, is the user's decision. Restarting
it would bring the same old code back, and a launch that only warned would
go on into the race above (an old dashboard re-attached to new services,
or old services back first), which no later check sees. On the lab's own
host the dashboard service is kept on purpose and a worktree's launch takes
the second way out; a launch of the build the service runs matches and is
never refused.

**Seen before launching.** `mandu version` (packaging.md §11.7) reports the
running arbiter's release and build against this mandu's, the folder its
code runs from (`/proc/<pid>/cwd`: the layout starts every daemon in its
package), and the unit that keeps it alive; `mandu doctor` shows the same
problem under "Mandu service".

**Tests.** `launcher/test/unit/stack-supervisor.test.ts` (cgroup v1 and v2,
user and system units, the user manager and scopes not units; the main
process or its direct child supervised, a CI runner's job and `Restart=no`
not; every skew verdict refused when supervised and still restarted when
not; the stop command in the refusals; the probe asked only for a resident
stack and a throwing probe ignored); `launcher/test/unit/version-report.test.ts`
(the incident's shape: an npm mandu, the old shim behind it, its services
kept alive by the unit).

## 5. Who runs in which mode

| Starter | Mode | Promotes? |
| --- | --- | --- |
| dashboard supervisor (default) | instance (`MANDU_RUNTIME_DIR` + cleared sock env) | yes |
| launcher autostart (no env, no live socket) | instance (`startArbiterInstance`) | yes |
| launcher / dashboard with explicit `$MANDU_ARBITER_SOCK` | pinned path (legacy) | n/a |
| `cd arbiter && npm run serve` | instance | **no** (log tells how) |
| tests (tmp socket paths) | pinned path | n/a |

The supervised Track-A proxies receive `MANDU_ARBITER_SOCK=<base>/current/arbiter.sock`
— the spelling, so their reconnects follow promotions.

Every starter must resolve the socket the same way: a launcher that pinned
the legacy fixed path next to a promoted stack once started a SECOND resident
arbiter on the same default symbol DB, silently breaking the single-writer
invariant (now refused outright, §9). `launcher/src/arbiter-sock.ts` is the
launcher's resolution (env → `current` → legacy → the `current` spelling with
mode `"autostart"`), and `startArbiterInstance` makes the autostart row above
true.

## 6. Invariant note

This is availability/operability hardening; the security invariant is
untouched: interceptors still fail closed when the arbiter is unreachable, and
a mis-resolved/dangling socket yields *refusal*, never raw passthrough. The
pre-existing anti-squat guards (listen() refuses a live path; close() unlinks
only its own inode) remain the last line of defense for pinned paths.

## 7. Canonical process titles

Every long-running Mandu daemon sets `process.title = "mandu-<service>"` as
its first act, so `ps`/`top`/`pgrep -f mandu-`/`ss -xlp` name the service
directly instead of showing the anonymous `node …/tsx …/server-main.ts` trees
that made stale-daemon triage a `/proc/<pid>/environ` forensics job (§1
incident 3).

| Title | Entrypoint |
| --- | --- |
| `mandu-arbiter` | `arbiter/ipc/server-main.ts` |
| `mandu-dashboard` | `dashboard/src/server-main.ts` |
| `mandu-anthropic-proxy` | `interceptors/anthropic-proxy/src/server-main.ts` |
| `mandu-openai-proxy` | `interceptors/openai-proxy/src/server-main.ts` |
| `mandu-net-proxy` | `interceptors/net-proxy/src/server-main.ts` |
| `mandu-inspect-mcp` | `interceptors/inspect-mcp/src/server-main.ts` |
| `mandu-policy-classifier` | `interceptors/inspect-mcp/src/classify-main.ts` (one-shot, spawned by the arbiter per names-only model run; confidentiality-plan-14 §14.10) |

Notes:

- **The title names the LEAF process** — the one that owns the listening
  socket. The `npm`/`tsx` shim ancestors it forks through keep their generic
  names; only the leaf matters for socket forensics, and the supervisor
  already kills the whole process group.
- **Linux `comm` truncates to 15 chars** (`mandu-arbiter` fits exactly;
  `mandu-anthropic-proxy` shows as `mandu-anthrop` in bare `pgrep`/`comm`
  views). `pgrep -f`, `ps`, and `ss -xlp` see the full title — prefer
  `pgrep -f mandu-` when sweeping.
- **exec-wrap is deliberately EXCLUDED**: its argv0 must remain the shadowed
  command name (`interceptors/exec-wrap/src/wrap.ts` learns which command it
  is from its own argv0; the launcher shims use `exec -a <cmd>`). Retitling it
  would break command resolution — and its whole point is to look like the
  command it wraps.
- **In-process components have no title of their own** (they live inside their
  host): the launcher's ViewMap'd context proxy is `anthropic-proxy
  server-main` (titled above) spawned per launch; the e2e harnesses construct
  proxy objects in-process; the reply-filter PTY relay is util-linux
  `script(1)`.
- **A title does not imply "ours to signal."** The dashboard's docker e2e
  runner and the hand-run docker rig (`scripts/ci/docker-run.sh`) start full
  stacks in containers under the SAME uid
  (`docker run --user`), so their `mandu-*` pids show up in a host
  `ps -u`/`pgrep` sweep and are signalable. `mandu stop` therefore excludes
  any pid whose `/proc/<pid>/cgroup` is container-scoped
  (`subcommands.ts isContainerCgroup`) in BOTH default and `--all` mode —
  containers tear down via their own `--rm --init`, never via host verbs.
  Nor does a title say which STACK a pid serves: `stop` reads that from the
  pid's environment, and an isolated caller must name it (§10.3).
  Likewise `mandu-inspect-mcp` is titled for forensics but is a per-session
  MCP child (claude spawns it from mcp.json): it is NOT in the resident `stop`
  set — killing it would break a live session's inspect tool.

## 8. The lifeline — kernel-bound service lifetime

**The incident class.** Per-session services (the context proxy, net-proxy,
fs-sync eager watcher) are spawned `detached` + `unref()` so foreground TTY
signals reach the agent, not them — but their only teardown used to be an
in-memory `stop()` closure the launcher runs at post-exit. Any spawner death
that skips that code path (SIGKILL, OOM, a wedged-then-abandoned test runner)
orphaned the whole detached group forever (several proxy trees and test
arbiters hours old, serving sockets in deleted temp trees, were once found
live at once). With fixed rendezvous ports, and the context-proxy identity
check correctly failing CLOSED on a wrong-session occupant, one orphan
converts into "every subsequent launch aborts" — fail-closed amplifies the
blast radius.

**The mechanism.** Bind service lifetime to the spawner in the KERNEL, not in
protocol: the spawner passes `MANDU_LIFELINE=stdin` and holds the only write
end of the service's stdin pipe, never writing. The kernel closes that end when
the spawner dies — *however* it dies — and the service treats the EOF exactly
like SIGTERM (same graceful shutdown path). Pure unprivileged POSIX semantics,
in keeping with the non-root principle.

- **Spawner side:** `launcher/src/services/primitives.ts startDetachedCmd`
  (stdio `["pipe", log, log]`, env injected, write end held + unref'd;
  `stop()` also severs the pipe so even a SIGTERM-ignoring service exits).
  Bash live suites use the FIFO variant, `launcher/test/lib/lifeline.sh`
  (the suite shell holds fd 9 rw; daemons get `<fifo 9>&-`).
- **Service side:** `armLifeline(onSevered)` — a narrow module duplicated per
  package (`arbiter/ipc/lifeline.ts` and copies in the anthropic/openai/net
  proxies and fs-sync; the no-cross-package-src-imports convention). OPT-IN by
  env and TTY-guarded, so a human's `npm run serve` is unaffected.
- **stdin is the channel** (not an extra fd) because it survives the
  `npm run serve → sh → tsx` chain; extra fds do not.

**Who gets it:** every service `startDetachedCmd` spawns (one node process
since 2026-10-04: a bundle, or the source through `node --import <tsx>`;
packaging.md §5.1) —
i.e. everything launcher-owned and per-session. **Who does NOT:** the
launcher-autostarted arbiter (`launcher/src/arbiter.ts`) and the dashboard
stack — the shared attach-or-start daemons that must OUTLIVE any one launcher
(§5); their teardown remains `mandu stop` / the instance sweep. Test
harnesses that start private arbiters DO pass the lifeline (they own them).

**Ephemeral rendezvous (the collision half).** `MANDU_PROXY_PORT=0` lets the
kernel pick the context-proxy port; the proxy publishes the bound port through
`MANDU_PORT_FILE` (atomic tmp+rename), the launcher adopts it into the plan,
and the env composer emits the real base URL. No fixed port → nothing a stale
daemon could squat, and no start-or-reuse branch (there is no well-known
address to reuse — the identity re-check after start stays). Port 0 with
`MANDU_NO_CONTEXT_PROXY=1` is refused at parse (an out-of-band proxy cannot
rendezvous with a kernel-picked port).

EVERY TCP service speaks this contract, not just the two model proxies: `MANDU_NET_PROXY_PORT=0` (net-proxy) and `DASHBOARD_PORT=0`
(dashboard) publish their bound port through the same `MANDU_PORT_FILE`
atomic write — so N concurrent host stacks need no fixed ports anywhere.

**Port 0 is the launcher's DEFAULT.** Fixed defaults (8788 / 8789 / 8790 /
4500) cost too much on a shared machine: a second user's (or any second
stack's) launch REFUSED on the foreign context proxy holding 8788, and
silently lost its egress gate to the foreign net-proxy holding 8790. So:

- **Context proxies** (`MANDU_PROXY_PORT`, `MANDU_OPENAI_PROXY_PORT`,
  `launcher/src/parse.ts`): default 0. The one exception is an out-of-band
  proxy (`MANDU_NO_CONTEXT_PROXY=1`): it has no port file to rendezvous
  through, so an UNPINNED launch keeps 8788 / 8789 as the rendezvous (an
  explicit 0 there is still refused). Cost accepted: two launches on one
  arbiter no longer share one context proxy; each runs its own (one more
  small process per session).
- **Egress proxy** (`MANDU_NET_PROXY_PORT`, `services/net-proxy.ts`):
  default 0. Only a pinned port takes the identity-checked reuse/conflict
  branch. The egress gate is also FAIL-CLOSED now: a net-proxy that cannot
  start refuses the launch (`services/manager.ts`, the `refuse` option of
  `guarded`), naming `--no-net-proxy` as the deliberate opt-out;
  `--best-effort` still lets a non-conflict failure through, loudly.
- **Dashboard.** The dashboard's OWN default (`dashboard/src/server-main.ts`,
  `DASHBOARD_PORT ?? 4500`) stays: a dashboard an operator runs directly
  (`npm run serve`, a `mandu-dashboard` systemd unit) keeps its bookmark. The
  launcher's two entry points differ. (1) The stack autostart (`launcher/src/arbiter.ts`
  `startArbiterInstance`) passes `DASHBOARD_PORT=0` unless the user pinned
  one: a dashboard already on 4500 (another user's, the resident deployment)
  does not cost a first launch its supervisor. (2) `mandu dashboard`
  (`launcher/src/subcommands.ts` `runDashboard`) does not probe a fixed
  4500 and print whatever answers there. Unpinned, it REUSES a live
  dashboard from the user's own runtime registry (§10: `<runtimeBase>/
  dashboards/<id>.json`, pid alive AND port answering, newest first; the
  runtime base is per user, so this is "owned by the same user" by
  construction), else starts one on port 0 through `MANDU_PORT_FILE` and
  prints the bound port; the dashboard registers that port itself, so the
  next call reuses it. Pinned (`DASHBOARD_PORT` / config `dashboard-port`),
  a listener on the port is adopted only when it is one of the user's
  registered dashboards; anything else is refused with the conflict named,
  never handed out as "already up". An operator's resident dashboard on 4500
  is found through the registry, so the deployment and its bookmark are
  untouched.
- The dashboard SUPERVISOR's own stack (`dashboard/src/supervisor/supervisor-defs.ts`:
  8788 / 8789 / 8790 for the proxies it supervises) is an operator-run shared
  stack and keeps its pinned ports; launches do not depend on it (they start
  their own proxies on port 0 instead of adopting the stack's).

Env pins keep working everywhere (`MANDU_PROXY_PORT`,
`MANDU_OPENAI_PROXY_PORT`, `MANDU_NET_PROXY_PORT`, `DASHBOARD_PORT`, and
their `config.toml` keys). Guarded by `launcher/test/unit/parse.test.ts`
(defaults + the out-of-band exception), `net-proxy.test.ts` (the default
never probes 8790), `manager.test.ts` (refusal, `--no-net-proxy`,
`--best-effort`), `arbiter.test.ts` (autostart port), `subcommands.test.ts`
(the dashboard matrix), and end to end by `launcher/test/component/services.test.ts`
(the REAL anthropic-proxy and net-proxy come up through the port-file
handshake with foreign listeners squatting 8788 / 8790; a failed egress proxy
refuses and `--no-net-proxy` launches) and
`launcher/test/component/dashboard-subcommand.test.ts` (the real CLI against a
real registry and real listeners).

Proven by: `launcher/test/component/lifeline.test.ts` (a REAL SIGKILLed spawner; a
SIGTERM-ignoring service felled by the severed pipe),
`arbiter/test/component/lifeline.test.ts` (the real daemon's graceful lifeline
shutdown; shared-stack immunity without the env), per-package
`lifeline.test.ts` unit suites, and the port-0 e2e in
`launcher/test/component/services.test.ts`.

## 9. Symbol-DB single-writer lock

The arbiter is the single writer of the symbol table. As a convention alone
that failed: a second arbiter opening the same DB — the launcher/dashboard
split-brain (§5), a stray hand-started daemon — interleaved
writes SILENTLY, and because each arbiter full-rewrites the table from its
in-memory `SymbolMap`, overlap means lost updates, surfacing much later as
inexplicable symbol state.

`arbiter/symbol-table/db-owner.ts` makes the invariant loud: `listen()`
acquires an `<db>.owner` JSON lockfile (O_EXCL; `{pid, cmdline, startedAt}`)
and a conflicting start throws `SymbolDbOwnedError` naming the live owner —
fail-closed, at startup, instead of corruption later. Staleness is probed, so
a SIGKILLed owner never wedges the stack: a recorded pid that is dead, or
alive with a DIFFERENT command line (/proc/<pid>/cmdline on Linux,
`ps -ww -o args=` on macOS; pid recycling), is stale and stolen;
alive-and-matching — or unprobeable — refuses. `close()` releases with a
pid-guard (never deletes a successor's steal), and a listen() failure of any
kind releases immediately (never own the DB without a serving socket).

Consequences for the §2/§5 flows:

- **Side-by-side live instances need separate DBs.** An unpromoted hand-start
  next to the resident stack now refuses unless it is started on its own
  home (`MANDU_HOME`) or DB (the arbiter's `--symbol-db`) — the §2 "steals nothing" promise holds by refusal.
- **Same-DB handover is SEQUENTIAL**: stop the old arbiter (graceful release),
  then start+promote the successor. Clients fail closed during the gap and
  follow `current` to the successor — the already-documented behavior.
- Readers are unaffected (the lock is app-level writer identity, not an
  SQLite lock), and per-operation connections inside one arbiter never
  contend with it.

Proven by: `arbiter/test/unit/db-owner.test.ts` (staleness/steal/release
matrix + two real ArbiterServers on one DB) and the same-DB refusal +
sequential-successor e2e in `arbiter/test/component/instance-mode.test.ts`.

### 9a. `mandu.db` carries a schema version; a mismatch is a refusal with a remedy

**mandu.db has no schema back-compat** — every column lives in the CREATE
TABLE, there are no guarded ALTERs (one bounded exception below), no
migrations. What matters for the product is how "not supported" presents:
without a version, a file from another release failed as a raw SQLite column
error deep in the boot (or, worse, opened and mis-read), and the remedy
(delete the file) had no message pointing at it.

`arbiter/symbol-table/symbol-table.ts` now stamps `PRAGMA user_version`
(`MANDU_DB_SCHEMA_VERSION`: 1 as of 2026-09-25, 2 since the policy agent surface's tables, 3 since the
symbol token prefix became `$MDU:` on 2026-09-27) and `openSymbolDb` — the
first open of every boot (`loadSymbolMap` runs before any store is built) —
compares it **before any table is touched**:

- stamp == current → proceed;
- a stamp listed in `ADDITIVE_FROM` → re-stamp, proceed. A version is listed
  only when the step from it to the current one ADDED whole tables and changed
  nothing that exists, so no existing row is read differently (not a
  migration). v2 (2026-09-25) is v1 plus `policy_proposals` and
  `policy_changes` (policy-surface.md §8.4.5), so a v1 file was adopted
  by v2. **v3 lists nothing**: a v1/v2 file stores every symbol under the
  retired prefix (the `sym_name` key and every token inside values, bindings
  and twins), which no scanner matches any more, so it is refused. **v4
  (the `$MDU:` prefix, the same day) lists nothing either**: a v3 file's
  tokens spell the prefix v4 retired. **v5 (the level names `any-model` /
  `no-model` and their markers, the same day) lists nothing**: a v4 file's
  level columns and markers use the old spellings. **v6 (the enforcement
  caches' seal tables `cache_seals`, `cache_seal_state` and
  `unconfined_launches`, 2026-09-30, confidentiality-plan-14 §11.2) lists
  v5**: it only added whole tables. **v7 (the prompt filter's
  `prompt_hold_state`, 2026-10-03, confidentiality-plan-15 §13.6) lists v5
  and v6**: one whole table, the key its span references are keyed with.
  **v8 (the bindings sync's `session_label_sources` and `symbol_sources`,
  2026-10-05, confidentiality.md §2.1) lists v5, v6 and v7**: two whole
  tables, the symbols each session read into context and a multi-input
  join's sources (a high session of an adopted file has no recorded
  sources, so it is bound nowhere until it ends). **v9 (the model proxies'
  `forwarded_clear`, 2026-10-09, confidentiality.md §7.1, *Across a
  resume*) lists v5 to v8**: one whole table, the tool-call ids whose
  result a proxy forwarded in clear. **v10 (`result_heads`,
  2026-10-09, confidentiality-plan-10 §11.14) lists v5 to v9**: one whole
  table, the durable mark that a row is an agent's whole result led by its
  runtime's head (an adopted file's rows have no mark, so their head lines
  count, fail-closed). **v11 (the provenance table `call_polls`,
  2026-10-09, confidentiality-plan-13 D7) lists v5 to v10**: one whole
  table, the background polls the model proxy tied to the call that
  started their task (an adopted file's polls are untied, as before).
  **v12 (the policy proposals' `suggest_scans`, 2026-10-09,
  confidentiality-plan-14 §5.5) lists v5 to v11**: one whole table, when a
  `suggestPolicy` scan of every source last finished over each root (an
  adopted file has none, so its next launch waits for its scan once).
  **v13 (the model proxies' `forwarded_placeholders`, 2026-10-11,
  confidentiality.md §6, *Across a relaunch*) lists v5 to v12**: one
  whole table, where Mandu's placeholders sat in an OpenClaw result
  forwarded in clear and its digest (an adopted file has no record, so a
  relaunch masks a redacted result whole, as before).
  **v14 (`raised_rows`, 2026-10-12, confidentiality-plan-15 §4.1, *What a
  raised row registers*) lists v5 to v13**: one whole table, the mark that
  a row is secret only because the value backstop found a registered
  secret in it and which of its lines held one (an adopted file's rows
  have no mark, so every line of a raised row counts, as before).
  **v15 (`path_rows`, 2026-10-17, confidentiality-plan-15 §13.12, *What a
  path row registers*) lists v5 to v14**: one whole table, the same mark
  for a row masked whole only by the path rule, whose call's tree read no
  secret raw and whose named files are registered as they are on disk (an
  adopted file's path rows have no mark, so every line counts, as before).
  **v16 (`wire_grants`, 2026-10-17, confidentiality.md §2.1, *The wire
  grant is recorded*) lists v5 to v15**: one whole table, the field rows a
  registration gave their own wire host (an adopted file has no record, so
  a field's wire grant is dropped until the next launch registers the file
  again, fail-closed). Since the same day it also holds a pip index
  variable's grant from a human-plane registration, as new rows of the
  same shape (no bump). **v17 (`wire_release_sessions`, 2026-10-17,
  confidentiality-plan-10 §11.13.1, *The session's word*) lists v5 to
  v16**: one whole table, the sessions whose egress proxy inspects TLS,
  with their launcher's pid (an adopted file has none, so npm reads
  `.npmrc` raw until the next launch, as after any restart before,
  fail-closed);
- fresh file (no `symbols` table) → stamp, proceed;
- unstamped (0) with a `symbols` table whose columns are exactly the v1 set
  → adopted by v1 and v2 (the shape before versioning); refused since v3 for
  the same token-prefix reason;
- anything else (an unstamped older shape, a NEWER stamp from a later
  release) → `ManduDbSchemaError`, naming the file, both versions and the
  remedy: `mandu stop --all`, delete `<db>` (+ `-wal`/`-shm`), relaunch;
  policy.yaml `paths:` labels survive, DB-only labels and past approvals do
  not. The file is left untouched.

The arbiter prints it as `[arbiter] fatal: …` and exits 1; the launcher's
`ensureArbiter` quotes the log's last `[arbiter] fatal:` line in its own
refusal (with the log path), so the user reads the remedy in the terminal
that launched, not in a daemon log they do not know exists.

**The rule for every schema change**, in this file or in any store sharing
the file (`egress_approvals`, `path_labels`, `session_labels`,
`session_label_sources`, `symbol_sources`, `forwarded_clear`, `forwarded_placeholders`, `result_heads`, `raised_rows`, `path_rows`, `derived_labels`, `rule_hits`, `policy_proposals`, `policy_changes`, the
provenance tables): **bump the constant**. Add the old version to
`ADDITIVE_FROM` only when the change was a whole new table.
One exception is in the file today: `policy_proposals` gains NULLABLE columns
in place (`disk_hash`, `disk_text` for held disk changes, 2026-09-28; `kind`,
`finding_key`, `suggestion` for plan 14's suggestions, 2026-09-30), through a
guarded `ALTER TABLE … ADD COLUMN` in its store, with no bump: NULL reads as
the old meaning, so an older build reads such a row as an ordinary proposal
(policy-surface.md §8.4.5). The provenance store's `process_secret_taint`
gains NULLABLE columns the same way (`exe`, `sha256`, `via`, `script`,
`script_sha256`, `claimed`, 2026-10-02; `wall_at`, the wall clock's time of
the read for display, 2026-10-17, confidentiality-plan-13 §3 D7): NULL reads
as before. Anything that changes how an existing column
is read still bumps.
The number is the whole contract — a change that lands without the bump is
a file the next boot mis-reads instead of refusing. 0.x releases may bump it
on a minor (`packaging.md §11` §2). There is still no `mandu reset` verb: the
remedy is two commands the message spells out, and a deleting verb next to
the single-writer lock is a footgun not yet earned.

Proven by `arbiter/test/unit/db-schema-version.test.ts` (fresh stamp, v1
adoption pinned to what SCHEMA_SQL creates, older-shape refusal before any
read, newer-stamp refusal) and `launcher/test/unit/arbiter.test.ts` (the
fatal line reaches the refusal). Users: `docs/usage.md` Troubleshooting.

### 9b. A stopped arbiter's store is read, never opened for writing (2026-10-18)

`mandu why` with no Mandu running starts a temporary arbiter (its own
socket, home and store; `throwawayArbiter`). On an empty store of its own it
held none of what the stopped arbiter kept: the remembered answers, the
changes waiting in Approvals, the content in force while a hand edit of
`policy.yaml` waits, dashboard labels, the files a secret-holding session
wrote, the registered files' placeholders. So `--to` never met a remembered
answer, and a waiting edit read as if it were in force (the CLI said both).

Now its store is **seeded** from the resident one's (`--seed-from <store>
--seed-policy <policy file>`, which server-main accepts only on a pinned,
unpromoted start; `arbiter/db/store-seed.ts`), before any store is built:

- **Read only, no second writer.** The store is opened on a connection of
  its own with SQLITE_OPEN_READONLY (SQLite refuses every write and creates
  no database). Where Node's SQLite takes a URI filename it is opened by one,
  and with no `-wal` beside it (no connection open: the last one to close
  checkpoints and deletes it) `immutable=1`, so the read creates no `-wal` /
  `-shm` next to it. Node 22.13 (the floor, and CI's) takes no URI filename
  (the first CI run failed on exactly that); there the store is opened by its
  path, read-only, and SQLite creates the empty `-wal` and the `-shm` index
  any reader of a WAL database creates, owner-only like the store, and leaves
  them for the next arbiter; the store's own bytes are not written. With a
  `-wal` beside it (an arbiter running under another socket, or one that
  died unclean) the read goes through the WAL, so the newest commit is read.
  The writer lock above is untouched: it names
  writers, and readers were always allowed. The attached file is checked to
  be the one asked for, and its stamp to be one this build reads
  (`schemaVersionReadable`, §9a): another release's store is refused, not
  mis-read. A missing store is no store (nothing is created).
- **No original is copied.** Only the tables `mandu why`'s ops read beyond
  the file's law are copied (`SEED_TABLES`), into a fresh 0600 file that
  must not exist. `symbols` keeps only the registered files' rows, each
  `value` replaced by the placeholder's own name; `policy_enforced` only the
  row of the policy file the resident arbiter read, re-keyed to a copy of
  that file the temporary arbiter reads, so a declined edit it would restore
  at start is written over the copy, never over the person's file.
- **The arbiter's own code answers.** The temporary arbiter then starts as
  any arbiter starts on that store (a held edit is held again, a proposal the
  law already says is closed), so its answers are the ones the resident
  arbiter gives once started: the same ops, the same renderer.
- **Fail closed to the answer of before.** A seed that fails refuses the
  temporary start (`[arbiter] fatal: --seed-from: …`, at once); the launcher
  then starts an unseeded one, and the CLI says, as before, that remembered
  answers were not consulted and a waiting change reads as in force.

Proven by `arbiter/test/unit/store-seed.test.ts` (the tables, no original,
the source's bytes and neighbours unchanged, the WAL read, the refusals),
`arbiter/test/component/store-seed.test.ts` (a server on the copy answers
`whyPath` / `whyHost` / `testFlow` byte for byte as the server that wrote the
store) and `tests/stack/why-offline-store.test.ts` (the CLI end to end with
no arbiter running).

## 10. The registry covers EVERY arbiter; `mandu reap` collects the garbage

The incident this closes: orphan arbiters from closed dev sessions
(hand-rolled `setsid npx tsx ipc/server-main.ts <sock> &` spawns, hours old),
dozens of dead scope-run dirs, and no way to tell which of them was safe to
kill — pinned-mode arbiters wrote NO manifest, so the registry could not
answer.

**Universal registration.** `server-main` registers an instance dir in
BOTH modes: a pinned arbiter binds the caller's path but still writes
`instances/<id>/manifest.json` (registry-only dir; promotion is refused for
pinned paths). The daemon arms its graceful SIGTERM shutdown (close, then
remove the instance dir) before it creates that dir, so no SIGTERM after the
dir appears can take the default action and leave it behind. The manifest is
written right after `listen()`, so a caller that waits for the socket (as
`dev-arbiter.sh` does) reads the registry with a bounded wait for the entry.
The manifest carries two lifecycle fields:

- `mode: "instance" | "pinned"` — how the socket was chosen;
- `ownerPid: number | null` — WHOSE death makes this daemon garbage.
  Spawners declare it via `MANDU_OWNER_PID` (`"0"`/`"none"` ⇒ ownerless);
  default is the parent pid. The blessed dev spawn
  (`scripts/dev-arbiter.sh`) passes the invoking SHELL's pid — the fix for
  setsid orphan chains, where every in-chain parent survives with the daemon
  and parent-pid heuristics never fire. That spawn is the `test` tenant
  (policy-surface.md §2.7) unless `MANDU_DEV_ARBITER_TENANT=live` asks
  otherwise (2026-10-18: a filmed demo, whose sessions the product page must
  list as Live; still its own home, DB and events). Any other value is
  refused (exit 2).

In-process `ArbiterServer` uses (tests, the integration harness) deliberately
do NOT register — only the process entrypoint does. Tests that spawn real
`server-main` processes scope `MANDU_RUNTIME_DIR` into their tmp trees.

**Signalling through the tsx CLI.** The tsx CLI shim (`node_modules/.bin/tsx`)
relays a SIGTERM to its child and SIGKILLs the child unless it reports the
signal back over tsx's IPC within 30 ms, which a busy daemon misses, so the
graceful shutdown is skipped and the dir is left for the next sweep. The
rule for tests: one that asserts on what the signalled process does on its
way out (a removed instance dir or registry entry, exit code 0, a final log
line) spawns `node --import tsx <entry>` from the package dir, so the signal
lands on the daemon, and pins that the manifest/registry pid is the spawned
pid; one that signals only to tear down may keep the CLI.

**`mandu reap [--dry-run]`** (launcher/src/reap.ts) — the by-hand GC the
startup-only sweep could never be:

| collects | rule |
| --- | --- |
| `instances/<id>/` | manifest pid dead, or manifest-less + abandoned (>10 min) |
| live orphan arbiter | ownerPid dead AND not the promoted `current` target AND the process proves it is THIS record's arbiter (`arbiterIdentity`): its command line (/proc on Linux, `ps -ww -o args=` on macOS, trimmed) is the canonical title `mandu-arbiter` at argv[0], and, where `ps -o lstart=` answers (LC_ALL=C TZ=UTC0, both platforms) and the manifest has `startedAt`, the process started no earlier than startedAt − 10 min and no later than startedAt + 5 s → SIGTERM (its graceful shutdown tidies its own dir). A title or start-time mismatch means the pid was recycled: the record is removed and nothing is signalled. An unreadable command line is skipped; an unreadable start time keeps the title-only check, never a wider one. (The old `/arbiter\|server-main/` rule matched any process whose argv mentioned the arbiter; it went live on macOS once the command line came from `ps`, 2026-09-29.) |
| `current` | dangling symlink |
| `<epochSec>-<pid>/` scope dirs | launcher pid dead. First, when the dir still holds `secret-twins/twin-snapshots.json` (the launcher died before its own end), reap prints one line per registered secret file whose placeholder copy that session changed, by path only, and likewise per labelled file whose guard-made copy changed (`secret-twins/derived-twins/labelled-twins.ndjson`) (`launcher/src/twin-writes.ts` `staleScopeDiscardedWrites`, read through the open dirs; confidentiality-plan-10-flow-taint.md §4.1) |
| legacy `arbiter.sock` file | nothing listening (a dead file here would WIN the §3 resolution and break the next launch) |
| `vm-guests/<id>.json` + a leaked qemu | owner harness gone (pid + start time); a live guest is stopped only if pid, start time, boot id and a `qemu-system-*` argv[0] all still match; its scratch dir goes (see below) |

Everything ambiguous is skipped, and nothing is walked or deleted through a
link (2026-10-07, §2 "planted paths"; `launcher/src/safe-remove.ts`): a
registry that is a link is not walked, an entry that is a link or not the
kind its registry holds is skipped, each removal is re-checked when it runs,
and a guest's scratch path must lie below a temp or cache root with no link
of this user's on its way. What reap refused is printed as `refused: …`.
Tests: `launcher/test/unit/reap-planted.test.ts` (each planted link to a
canary folder, a swap between plan and execution, the helper's rules) and
`launcher/test/component/reap-planted-link.test.ts` (the real CLI). `mandu status` answers in plain words
first: whether Mandu is running, the
dashboard URL, and a count of leftovers from ended sessions taken from the
same `planReap` plan `mandu reap` would execute ("2 services from ended
sessions, 22 stale records"). `mandu status --verbose` adds the registry
(mode, promotion, owner liveness, each worded as what reap does with it:
"exited; `mandu reap` stops it", or just "exited" for the promoted arbiter
and for a record whose pid is gone) above the titled process list, so "what
is this arbiter and whose is it" is answerable without /proc forensics. The
process list is every Mandu process of this user, so on a shared dev or CI
host it includes other stacks'; that is why it is verbose-only.

**The resident stack has no owner.** The launcher's autostart
(`startArbiterInstance`) and `mandu dashboard` start the dashboard (and the
fallback bare arbiter) with `MANDU_OWNER_PID=none`. With the default owner
(the parent, i.e. the launcher or the short-lived CLI), `status` would call
the user's own dashboard "DEAD → reapable" the moment it exited, and `mandu
reap` would SIGTERM it. A
resident stack stops only by `mandu stop` or from the dashboard; owners
remain for what a session or a harness starts on purpose (pinned arbiters,
`scripts/dev-arbiter.sh`), which is exactly what reap should collect. Pinned
by `instance-autostart.test.ts` (the real autostart's entry is ownerless and
reap plans no stop once the launcher is gone) and the unit spawn tests.

**One resident arbiter per autostart.** On a loaded host the supervisor
dashboard may not have promoted within the autostart's first wait although it
is still bringing its own arbiter up; starting the bare fallback BESIDE it
then made a second resident arbiter, ownerless and lifeline-free like the
first, which stole `current` from the supervised one and kept serving after
the dashboard stopped. The autostart treats a supervisor that is still
RUNNING at its first wait as slow, not failed: it gets a further grace, and
one that never promotes is stopped, SIGTERM then SIGKILL to its whole process
group (it is spawned detached, so the npm wrapper, tsx and the dashboard go
together; the dashboard's SIGTERM path stops its supervised arbiter), before
the fallback starts, with the log saying so. A supervisor that already
exited (port busy, package missing) falls back at once.

**Autostart deadlines under load.** All of these waits follow the launcher's
load-aware readiness deadline (§14.6): the fallback's
socket wait is that deadline, the supervisor is handed it in its env for its
own arbiter start, and the launcher waits two of them for the supervisor (its
own start, then its arbiter's), never less than 20 s. A supervisor started
with `DASHBOARD_AUTOSTART=arbiter` whose arbiter start fails exits (code 1),
so the launcher's fallback starts at once; every wait also ends as soon as
the process it waits on has exited. Pinned by the `startArbiterInstance` unit
tests (slow → no fallback; stalled → stop before the fallback; exited → no
grace; the env hand-off),
`launcher/test/component/autostart-supervisor-stall.test.ts` (the real
detached spawner with stand-in daemons in a stand-in checkout; fails on a launcher
without the grace), `dashboard/test/component/autostart-arbiter-exit.test.ts`
(the real dashboard exits 1 on a missed deadline) and a load repro (the test
pinned to 2 cores beside 24 busy loops, a cold tsx cache: refused 5 of 5
times before, green 6 of 6 after). Test side,
`launcher/test/lib/runtime-sweep.ts` stops every process group whose
environment carries the test's `MANDU_RUNTIME_DIR`, registered or still
starting.

**Dashboards register too.** Without it, several dashboard servers were once
found serving side by side — one current, the rest stale on forgotten ports —
and an operator's browser tab pinned to a stale one read a truthful "code
changed since boot" banner that no restart could ever clear. Now
`dashboard/src/server-main.ts`
writes `dashboards/<id>.json` under the runtime base after `listen()`
(`dashboard/src/registry.ts` — same id scheme, same `MANDU_OWNER_PID`
owner semantics, mirrored per the standalone-package rule; FLAT files, not
instance dirs — a dashboard owns no socket/promotion machinery, and nothing
may be confusable with the arbiter's `instances/`). The manifest carries the
**bound port** (kernel-assigned under `DASHBOARD_PORT=0`), so a forgotten
dashboard is *findable*, not merely known to exist. Entries are removed on
every deliberate exit (signal handler AND the self-restart path — the
successor writes its own); a SIGKILLed entry is swept at the next dashboard
boot (`sweepDeadDashboards`, dead pids only, never signals) or by reap:

| collects | rule |
| --- | --- |
| `dashboards/<id>.json` | pid dead, or unreadable, or the pid no longer bears the canonical `mandu-dashboard` title (§7 — recycled pids lose the ENTRY only, never a signal; the title check is deliberately not a loose `/dashboard/`, which an editor open on `dashboard.md` would match) |
| live orphan dashboard | ownerPid dead AND the title check confirms → SIGTERM (its exit hook removes its own entry; a live pid's entry is never removed — that would re-create the invisible-daemon incident) |

`mandu status --verbose` lists dashboards under the instances (`registered
dashboards (n):` with id, liveness, `http://host:port`, owner liveness). An
entry also records `basePath` (the `DASHBOARD_BASE_PATH` it serves under), so
`mandu dashboard`, `status` and the launch line build a URL that works; an
entry without it is from an older dashboard served under `/mandu`.

**Test VMs register too.** The qemu guests the VM test
harnesses start (`scripts/ci/vm-run.sh`, `vm-image.sh`, the matrix qemu
executor, `kernel-vm.sh`) are registered by `scripts/lib/guest-registry.sh`
as flat `vm-guests/<harness>-<pid>.json` entries: qemu's `-pidfile` pid and
its start time, the boot id, the harness process as owner (with its start
time), the run's scratch dir and whether it was `--keep`, and `alsoRemove`
paths (a host credential copy) that go even under `--keep`. The harness
drops its entry when the guest stops, and stops a guest still up from its
EXIT trap; `mandu reap` collects what a SIGKILLed harness left:

| collects | rule |
| --- | --- |
| live orphan guest | owner gone (dead, or its pid reused: start time differs) AND the guest's pid, start time and boot id match AND argv[0] is `qemu-system-*`/`qemu-kvm` → SIGTERM, SIGKILL after 5 s (identity re-checked before each signal), then its scratch paths and entry; a guest that outlives SIGKILL keeps both and reap exits 1 |
| stopped guest's leftovers | owner gone AND the guest pid is dead, reused, or from an earlier boot → scratch paths and entry, never a signal |
| `vm-guests/<id>.json` | unreadable (written tmp + rename) → the entry alone |

A live owner, an unreadable start time (a zombie not yet collected) and a
live pid with the recorded start time but no qemu argv[0] all mean nothing
is done. Scratch paths must be absolute, normalized, two levels deep, and
neither the runtime dir, the home dir nor an ancestor of either. Full
design and tests: os-test-matrix.md §10.17.3.

**Deliberately deferred — per-service member files.** The design's full
stack-instance registry (one `members/<role>.json` per proxy/fs-sync under the
arbiter's instance dir, written by the dashboard supervisor and the launcher)
is NOT implemented yet: those services are already title-visible (§7),
lifeline-bound (§8), and never orphan — registration there is pure
observability. Un-defer when a member-level question ("which session owns
proxy pid X?") actually blocks an investigation, or when `stop` moves from
title-sweep to registry-scoped kills.

### 10.1 A clean launch removes its own scope dir

A launch stages `<runtime base>/<epochSec>-<pid>/` (the exec shims, the MCP
and agent configs, the secret twins, the guard policy, the services' port
files and logs, `launch.log`). Left behind, `mandu reap --dry-run` would never
be empty after a launch (os-test-matrix.md §10.16.2). The launcher
removes its own scope dir at the end of `main()`, after the services have
stopped and the session-exit event is sent, still under the teardown guard
(`launcher/src/scope-dir-cleanup.ts`). Nothing reads the dir after the
launch: the session's record is the arbiter's event store, and `launch.log`'s
lines are also its `launch_posture` event.

Only the launcher's own dir, and only on a clean end. All must hold:

| condition | why |
| --- | --- |
| the teardown ran to the end and the session's exit code is 0 | a failed session keeps its logs (a refusal's message may name one); a launcher killed part-way (SIGTERM, SIGHUP, a crash) never gets here. `mandu reap` collects both, their pid being dead |
| the launcher minted the scope id (`<epochSec>-<own pid>`) | a scope named with `--id` / `MANDU_SCOPE_ID` is the caller's: harnesses read it afterwards, and two launches may share the name |
| the path is `<runtime base>/<that id>`, a real directory owned by this uid | never a symlinked dir; `rm -r` unlinks links inside it and never follows them |
| no arbiter this launch started lives off it | a per-launch (pinned) arbiter writes its events and log there (`--event-dir`) and outlives the launcher; a socket inside it would be cut off |
| `MANDU_KEEP_SCOPE_DIR` is unset (or `0`) | forensics, and the live harness (`launcher-live.ts` `launcherEnv`), which reads the staged shims and proxy port afterwards |

Removal is best-effort: a failure (a read-only subdir the agent left) leaves
the dir for `mandu reap` and, under `--verbose`, says so. `mandu reap`'s
rule for scope dirs is unchanged; since 2026-10-10 it first names the
protected files whose placeholder copy a session changed when that
session's launcher died before it could (the launcher removes the twins'
snapshot file once it has said so itself, so a kept dir is not reported
twice). Tests: `launcher/test/unit/scope-dir-cleanup.test.ts`
(the decision, the removal: symlinks, siblings, ownership, failures) and
`launcher/test/component/scope-dir-cleanup.test.ts` (the real CLI: removed on a
clean exit after the agent saw it populated, a neighbour's dir untouched;
kept for exit 3, `--id`, the knob, and a pinned arbiter the launch started).

### 10.2 `dev-arbiter.sh stop` ends the whole process group

`scripts/dev-arbiter.sh` records in `$WORK/pid` the setsid'd daemon, the
leader of the arbiter's own session and process group. Since 2026-10-04 that
daemon is ONE node process (packaging.md §5.1: the checkout's fresh bundle,
else the source through arbiter's own tsx), so `kill $(cat $WORK/pid)` ends
it, gracefully. Until then it was `npm run serve` (npm → sh → tsx →
`mandu-arbiter`), where that kill ended only npm and left tsx and the daemon
serving, reparented to init, until `mandu reap` collected them after the
owner shell died. The stop below still collects the whole group, whatever it
holds.

The stop is a subcommand: `scripts/dev-arbiter.sh stop [workdir]` (the
work dir defaults to `MANDU_DEV_ARBITER_WORK`, which the start exports). It

- refuses a group that is not this work dir's arbiter: some process of the
  group must carry `MANDU_ARBITER_SOCK=$WORK/arbiter.sock` in its environment
  (a stale pid file whose number was reused is left alone, exit 1);
- SIGTERMs the daemon (`/proc/<pid>/comm` = `mandu-arbiter`, §7) first, so its
  own graceful shutdown closes the sockets and removes its instance dir (no
  tsx shim stands in front of it any more to relay, or SIGKILL, the signal:
  §10's relay note);
- then SIGTERMs the rest of the group, waits for every member to exit, and
  SIGKILLs the group after `MANDU_DEV_ARBITER_STOP_GRACE` seconds (default 10);
- removes the pid file and any socket a SIGKILLed daemon left. A missing pid
  file or a group already gone is exit 0, so a cleanup trap can call it
  unconditionally.

A start whose sockets (the data and the admin socket) never appear within
the readiness deadline (§14.6, "Tests and the dev arbiter": 30 s idle,
stretched by load, doubled on CI, or `MANDU_SERVICE_READY_TIMEOUT_MS`) stops the group the same way rather
than leaving a slow start serving, and a group that exits first ends the wait
at once ("it exited before its socket appeared"). The deadline was a fixed
10 s, which the first, cold start on a fresh GitHub runner missed. Until
setsid(1) has run in the forked child, the group is empty though the start
is alive, so "it exited" means the group is empty AND the recorded pid is
gone (or a zombie), never the group alone: a group-only check read that
window as an exit on loaded GitLab guests (pipelines 8805, 8811 and 8834 on
2026-10-04, the `drill-own-arbiter` flake: an "exit" 100 ms into a start),
and the stop then found the group "already gone" and left the start to come
up and serve. Before a failed start's stop, the script waits (10 s bound)
for the recorded pid to lead its own group or to exit, so the stop finds
what it must end. The test runs the start with a setsid(1) that runs late,
both past a 1 ms deadline (refused, the group stopped) and under the default
one (it comes up). A failed start prints the last 30 lines of its
`arbiter.log` on stderr (or says it is empty): the work dir of a CI caller is
in a guest's `/tmp` that goes with the run, so the caller's own log must
carry why. A server that exited before the start's first look once ended
the script silently (a failing `ps` under `set -e`); it is reported like any
exit. A caller that may die without its trap passes
its lifeline (§8): with `MANDU_LIFELINE_FIFO` naming a FIFO whose only write
end the caller holds on fd 9 (`launcher/test/lib/lifeline.sh`), the arbiter
reads it as stdin under `MANDU_LIFELINE=stdin` (fd 9 closed in it) and shuts
down gracefully when the caller dies; a path that is not a FIFO is refused
(exit 2). The live launcher suites pass it, because they register their
arbiter under their own `MANDU_RUNTIME_DIR`, where `mandu reap` does not look. The registration is unchanged: an arbiter nobody
stops is still owner-registered, and `mandu reap` still collects it. Callers
in the tree use the subcommand (the launcher live tests, the SIEM scenarios,
the nightly stack's teardown, which then still signals the group
itself). The drill runner (`drill-arbiter.ts`) stops its
own arbiter the same way: the daemon (`comm` = `mandu-arbiter`, and not the
child of one: a process the daemon forks carries its title until its exec,
which on 2026-10-09 put a second "daemon" in the group on loaded guests, the
discovery worker's esbuild service starting under a cold tsx cache;
`daemonsOf`) first, then
the rest of the group (`stopOwnArbiter` awaits the daemon's exit, then
SIGTERMs the group, SIGKILL after 10 s); a group SIGTERM first reached the
tsx shim, which SIGKILLed a loaded daemon before its graceful shutdown and
left its instance dir behind. The synchronous exit-handler stop signals the
daemon alone (the shims exit with it), the whole group only when no daemon
is found. Tests: `scripts/test/dev-arbiter.test.sh` (a
real arbiter stopped by the documented stop: no group member survives,
sockets, pid file and instance dir gone; the leaderless group a bare `kill`
leaves; the `MANDU_DEV_ARBITER_WORK` default; the stale-pid refusal; the
SIGKILL fallback; the lifeline: a SIGKILLed caller ends the group, its
instance dir tidied; a start past its readiness deadline, and one whose
arbiter exits, refused with the group stopped) and `drill-own-arbiter.test.ts`.

### 10.3 `mandu stop` stops the stack you name

`mandu stop` picks its targets by canonical title (§7) across the whole uid:
the resident daemons, or every Mandu process under `--all`. That is the
operator's verb (apply a mode, back up, uninstall: "stop everything"), and
its meaning stays. But it ignored the stack the caller's environment
selects. On 2026-10-04 a benchmark agent ran `MANDU_HOME=… MANDU_RUNTIME_DIR=…
mandu stop` four times to swap its throwaway stack. Each run SIGTERMed the
shared systemd dashboard and its arbiter. The last, `--all`, also ended two
live `mandu claude` sessions: their guards died first, so each launcher
ended its own scope (`guard-death.ts`). The sessions saw `ECONNREFUSED`.

A process's **stack** is its runtime base (`runtimeBase`, the runtime-dir
resolution every verb and daemon uses). `stop` reads it from the process's
own `/proc/<pid>/environ`, or, when that is unreadable, from the registries
of the stacks in question (§10: an instance manifest, a dashboard entry, a
`<epochSec>-<pid>` scope dir naming the pid). Otherwise it is unknown.

| Form | Signals |
|---|---|
| `mandu stop [--all]` from the operator's stack (below) | every stack, as before |
| `mandu stop [--all]` from another stack | its own stack's processes when those are all it would reach; else **refused** (exit 2, nothing signalled), listing the other stacks' targets and the two forms below |
| `mandu stop [--all] --stack <runtime dir>` | only that stack's processes; another stack's and an unknown one are left running (counted in the summary) |
| `mandu stop [--all] --every-stack` | every stack, said explicitly |

An unknown stack counts as another stack for the refusal, and is never a
`--stack` target: the uncertain case never signals. `MANDU_HOME` alone does
not select a stack, since the rendezvous lives in the runtime dir. Container-scoped
pids stay excluded in every form (§7).

**Who the operator is comes from the OS, not the caller's env (2026-10-09).**
The first fix compared the caller's stack with the stack its env selected
once `MANDU_RUNTIME_DIR` was dropped. That caught a benchmark's
`MANDU_RUNTIME_DIR`, but not a harness that isolates itself through
`XDG_RUNTIME_DIR` (or, on macOS, `TMPDIR`): there the dropped variable was
never set, so its own throwaway stack counted as the default and its bare
stop swept every stack. On 2026-10-09 a fresh-install harness ran
`env -i HOME=<scratch> XDG_RUNTIME_DIR=<scratch> mandu stop` after each leg.
To the second, each run SIGTERMed the systemd dashboard (restarted by its
unit) and the own arbiter of a live OpenClaw drill run on the same host. The
drill's guard then could not refresh its derived-label list
(`derivedLabelsSince`), so it refused the files OpenClaw had written in that
session (derived_index.rs, fail-closed). OpenClaw reported "Auth profile store
… openclaw-agent.sqlite is unreadable" (`SQLITE_CANTOPEN`, an EACCES). The
two failures looked like interference between concurrent OpenClaw runs.

The operator's stack is now `operatorStack`: on Linux,
`/run/user/<uid>/mandu` when logind made `/run/user/<uid>`; on macOS, the
account's rendezvous (`accountRendezvous`, from `DARWIN_USER_TEMP_DIR`, in
practice `/tmp/mandu-<uid>`). A caller whose env selects any other stack is
isolated, however it got there: `MANDU_RUNTIME_DIR`, an `XDG_RUNTIME_DIR` or
`TMPDIR` of its own, or none at all (`env -i`, cron). The refusal names the
account's stack and the two ways out. On a Linux host with no logind
directory (a container), the env's default stays the operator's, as before:
there is no OS answer to compare with.

The guard's refusal was correct and is unchanged. A file written after the
guard started may be a copy of a secret, and with the arbiter gone nothing
can say it is not. The fix is that a stranger can no longer stop the arbiter.

Pure decision logic: `parseStopArgs`, `planStop`, `operatorStack`
(`launcher/src/subcommands.ts`). Tests:
`launcher/test/unit/subcommands.test.ts` (the four forms, the unknown stack,
the registry attribution, `operatorStack` per platform, the isolated
`XDG_RUNTIME_DIR` caller refused) and
`launcher/test/component/stop-scope.test.ts` (the real CLI against live
processes of two stacks, the isolated `XDG_RUNTIME_DIR` caller among them,
with a `ps` that lists only the test's processes, so a regressed guard cannot
reach a real stack).

### 10.4 A launch makes its own scope dir, and never adopts one (2026-09-30)

The scope dir used to be made by whichever service came first, with `mkdir
-p`, which adopts whatever is there. A minted id is predictable
(`<epochSec>-<pid>`), and the runtime base stays writable to the agent (§2,
"planted paths"), so an agent could make a FUTURE launch's scope dir in
advance with links in it (`launch.log`, a service log, the profile's copy),
for that launch's unconfined launcher and services to write through into
the user's files. Now `run.ts` makes it itself before anything is written
into it (`launcher/src/scope-dir.ts`): in the per-launch (pinned) arbiter's
start, which writes its log and events there, or else right after the
arbiter is attached or started in instance mode, before any service; a
launch the arbiter step refuses (a runtime dir too long for its socket)
still creates nothing. The fallback's private-dir rule runs first
(`guardRuntimePath`, with `main()`'s env):

| the dir | what happens |
| --- | --- |
| absent | made non-recursively, mode `0700` (the base with `mkdir -p`, as before) |
| present, minted id | the launch is REFUSED and the dir left as it was: its name holds this process's pid and the current second, so no one else had a reason to make it. The one exception is a dir this same process made: the per-launch arbiter's start made it a moment before, or an in-process caller of `main()` (the e2e tests) launched twice in one second; it is checked again as a named one is |
| present, named (`--id`, `MANDU_SCOPE_ID`) | reused as the caller's, but only as a real directory (not a link) owned by this uid |

The macOS profile is no longer read from the scope dir: the launch hands its
text to `sandbox-exec` inline (`-p`), and `seatbelt/agent.sb` is a copy for
reading, made in a fresh `0700` dir with `O_CREAT|O_EXCL|O_NOFOLLOW`
(confidentiality.md §7.3). What stays open: once made, the dir is writable to
the agent of ANOTHER session while this one runs (§2). Tests:
`launcher/test/unit/scope-dir.test.ts` and
`launcher/test/component/scope-dir-planted.test.ts` (a wrapper plants
`<sec>-<own pid>` for the coming seconds, as a link and as a dir with a
link inside, then runs the real `main()`: refused, nothing written through
either; `--id instances`, `--id instances/x` and a linked named scope
refused).

## 11. One server, four quadrants — the sharing contract

A development machine can be simultaneously the dev box, a CI runner, the
resident dashboard stack, and N live agent sessions. Four execution quadrants
coexist:
**host/non-CI** (the resident stack; ad-hoc dev stacks; host-run live tests;
sessions' inspect-mcp children), **host/CI** (unit/typecheck jobs — in-process
tmp arbiters), **docker/CI** (live jobs via `scripts/ci/docker-run.sh`), and
**docker/non-CI** (the dashboard's "Run e2e" docker mode). What they may and
may not share:

CI itself runs every job that executes code from a commit in a disposable
KVM guest with no network and no shared filesystem (`scripts/ci/vm-run.sh`,
[`continuous-integration.md`](../testing/continuous-integration.md) §3), so CI shares no
row below with the host and the docker/CI quadrant is gone. Its results reach
the dashboard as files in a runs directory the dashboard reads (`dashboard.md`
§4.27), not through the event dir. The rows govern the other three quadrants
and the hand-run docker rig.


| Resource | Shared by | Guard |
| --- | --- | --- |
| arbiter socket | host stacks | instance dirs + `current` (§2); one resolution order everywhere (§3, §5) |
| TCP ports | host stacks (docker has its own netns) | port-0 + `MANDU_PORT_FILE` on EVERY service (§8); fixed defaults only for the resident stack |
| symbol DB | at most ONE live arbiter per DB file | `<db>.owner` lock — loud refusal (§9) |
| event dir | ALL quadrants (docker bind-mounts it rw) | intentional: append-only, per-session NDJSON files — this is how docker runs reach the host dashboard; ON DISK (§12), one rule in three copies + a parity test |
| `~/.claude` credentials | host + every docker run | intentional rw share: OAuth refresh-token rotation makes a COPY more dangerous than the race (a rotated copy invalidates the host's original) |
| process namespace | host + docker (same uid, host-visible pids) | host verbs NEVER signal a container-scoped pid — `/proc/<pid>/cgroup` is the marker (§7); containers tear down via their own `--rm --init` |
| runtime registry | host stacks | universal registration + `mandu reap` (§10: arbiters, dashboards, test-harness qemu guests); containers register in their OWN container-local base, invisible to the host — correctly so |

The lifecycle model in one paragraph: **every arbiter defines an instance;
every instance has a mode (`instance`/`pinned`), an owner (whose death makes
it garbage), and at most one is promoted as the resident rendezvous.** The
resident stack is stopped explicitly (`mandu stop` — container-safe,
session-safe); session-bound services die by lifeline (§8); everything else
is enumerable (`mandu status`) and collectable (`mandu reap`) by exactly
the rules in §10. Deferred pieces and their un-defer triggers live in §10
(per-service member files) and the packaging notes (registry-scoped stop).

## 12. Durable state lives on disk — the event store is not runtime state

> Where the event store lives is [on-disk-layout.md](./on-disk-layout.md) §3
> (the one home); the rule, retention and diagnosis below are current.

**Why.** The event store once defaulted to `${XDG_RUNTIME_DIR}/events`, with
`test-runs.json` next to it — on `/run/user/<uid>`, the per-boot tmpfs logind
creates at login. The §2 scheme put the SOCKETS there on purpose (they must
die with the boot); the event store had followed by analogy and inherited a
lifetime it never wanted: a reboot wiped every session trace and the
dashboard's test-run history. (Linger does not help: it keeps the dir across
logouts, not reboots.) The event store is history, not runtime state.

**The rule now** — one rule, three copies, each resolving the path table's
`events` entry (on-disk-layout.md §5). `arbiter/events/event-store.ts
getEventDir` is the owner; `dashboard/src/event-dir.ts` is the TS mirror the
dashboard needs (it is an arbiter CLIENT and does not import the arbiter
package — the arbiter-client pattern); `scripts/ci/docker-run.sh
--publish-events` is the shell mirror, the host side of the bind mount that
puts docker-rig sessions in the host dashboard.
`tests/stack/event-dir-parity.test.ts` fails the moment any copy disagrees
with the owner.

```
--event-dir <dir>   (the arbiter's flag; Mandu's own spawners only)
${MANDU_HOME:-$HOME/.mandu}/events                    default — ON DISK
```

`test-runs.json` is the path table's `test-runs`
(`~/.mandu/runs/test-runs.json`, the developer view's `test-history.ts`),
which an `--event-dir` does not move. No environment variable moves the event
dir (`MANDU_EVENT_DIR` is retired); only `MANDU_HOME` moves it, with the whole
home. The launcher's per-launch arbiter gets `--event-dir <scope run
dir>/events`, the dashboard's test tenant `--event-dir <home>/events/test`.
Nothing from an older layout is carried over (on-disk-layout.md §6). What
stays under the runtime base: sockets, the instance registry and manifests,
per-service supervisor logs — all meaningless after a boot.

The shell copy keys on the invoking uid's **passwd home**, not `$HOME`:
"publish to the host dashboard" means the dashboard of the USER running the
rig, even when a job overrides HOME. An explicit `MANDU_HOME` wins in all
three copies.

**Retention, because disk is not tmpfs.** The tmpfs default had one virtue:
it was self-cleaning. On disk the store needs a bound, so the arbiter prunes
sessions whose file has been idle longer than `$MANDU_EVENT_RETENTION_DAYS`
(default **90** — deliberately generous, the sweep exists to bound growth,
not to expire evidence anyone still wants; `0` disables; unparseable →
default). Idle = file mtime: under the append-only writer contract mtime IS
the last-activity time, so a live session can never qualify. One sweep at
`listen()` — a daemon that was down for weeks catches up at boot — then
hourly (`setInterval`, unref'd, cleared by `close()`). Removal is the
`deleteSession` path (`ArbiterServer.removeSession`: file, seq state, live
subscribe streams, coalescer state), so nothing lingers in memory and a
reused id starts at seq 1. The reserved `arbiter-admin` audit stream is never
pruned. Observability-only: symbol table, policy, approvals are untouched.
dashboard.md §3.3 (incremental summaries) is what makes a large on-disk dir
cheap to LIST; retention is what keeps it from growing without bound — the
two are independent. Test-run history is bounded separately (50 runs).

**`eventDir` is REQUIRED on `ArbiterServer`.** When
`ArbiterServerOptions.eventDir` defaulted silently, unit tests that never set
it wrote their approval fixtures into the developer's LIVE shared store (fake
`approval_resolved` rows in the resident stack's `arbiter-admin` audit
stream). server-main resolves the default and passes it explicitly; every
other constructor — in practice a test — names its own temp dir, and
forgetting it is a compile error. Every package's `npm test` also pins
`MANDU_HOME=/dev/null/mandu-test-home` (on-disk-layout.md §5), so a test that
forgets to isolate fails at its first write.

**Diagnosis.** The manifest's `eventDir` (`mandu status`) says where a
running arbiter writes; the daemon logs `event store: <dir> (retention: 90d)`
at boot, and `retention: removed N session(s) idle > 90d: …` for every sweep
that removed anything. An empty session rail right after a reboot is now a
real absence, not a wiped tmpfs.

Pinned by `arbiter/test/unit/event-dir.test.ts` (rule, the retired
`MANDU_EVENT_DIR` moving nothing, stale listing, retention knob),
`arbiter/test/unit/event-retention.test.ts` (the sweep
over a real socket: boot sweep, stream teardown, timer, off, symbols intact),
`arbiter/test/component/event-store-durability.test.ts` (the REAL daemon: the
default in the one home, the older layouts' dirs never read, boot prune,
`0`, an explicit `--event-dir`), `dashboard/test/unit/event-dir.test.ts`
(mirror + the test-run history path), the parity oracle above, and
`scripts/test/docker-run.test.sh` (the passwd-home and `MANDU_HOME`
branches).

## 13. The account's rendezvous is never promoted from a foreign HOME

**The incident.** `HOME=<scratch> mandu --target shell …`, run by a test
while no stack was up, autostarted the shared stack. The launcher passes its
own env to the stack, so the promoted arbiter kept the ACCOUNT's symbol DB,
policy file and event dir under the scratch HOME, and it sat at
`/run/user/<uid>/mandu/current` for hours: every launch in that window joined
a throwaway store under the built-in policy, and the account's dashboard
adopted it and showed the scratch dir's sessions (dashboard.md §3.3a).

**The rule.** The rendezvous at `/run/user/<uid>/mandu` belongs to the account,
so whatever gets promoted there runs under the account's passwd home.

**The rendezvous on macOS (2026-09-29).** Both guards compared the base with a
hard-coded `/run/user/<uid>/mandu`, which never exists on a Mac, so both were
inert there: a scratch-HOME launch could promote itself as the account's
`current`. The rendezvous is now the account's DEFAULT runtime base
(`runtime-base.ts accountRendezvous`): Linux keeps `/run/user/<uid>/mandu`;
macOS applies the §3b rule to `getconf DARWIN_USER_TEMP_DIR` (the per-user
`T/` dir, read from the OS and cached — never this process's possibly
overridden `TMPDIR`; `os.tmpdir()` if it cannot be read) with the real `/tmp`
fallback root, which in practice is `/tmp/mandu-<uid>`. The fallback-root test
hook is never read here. A Mac user who exported a short `TMPDIR` in the login
shell gets a different default base than the rendezvous, so the guard does not
cover that base (the same gap as a Linux session without `XDG_RUNTIME_DIR`).

- **Launcher** (`launcher/src/arbiter.ts sharedStackHomeEnv`): an autostart at
  the account's rendezvous under a foreign HOME starts the supervisor (and the
  bare-arbiter fallback) with `HOME` set to the account's home, and drops a
  `MANDU_HOME` (since on-disk-layout.md phase 5) or any
  `XDG_{CONFIG,STATE,DATA,CACHE}_HOME` that points into the foreign HOME. The
  launch's own agent keeps its HOME; only the shared stack moves. A note says
  so (`--verbose`).
- **Arbiter** (`arbiter/ipc/instance.ts foreignHomePromotion`): a `MANDU_PROMOTE`
  instance at the account's rendezvous whose HOME is not the account's home is
  NOT promoted; it serves its own instance socket and logs why. This catches
  the paths the launcher does not see (a hand-started arbiter, `HOME=… mandu
  dashboard`).
- **`MANDU_HOME` on both sides.** The launcher drops a
  `MANDU_HOME` inside the foreign HOME and keeps one set elsewhere; the
  arbiter's refusal is keyed on HOME, and a `MANDU_HOME` never lifts it, even
  one at the account's own `~/.mandu`: HOME is also the `~` of the policy's
  path labels and of the secret catalog, so an arbiter under a scratch HOME
  would guard the scratch dir's keys, not the account's, wherever its stores
  are. Its refusal names where the Mandu home resolves (inside the foreign
  HOME, or a `MANDU_HOME` elsewhere). With the account's HOME, a relocated
  `MANDU_HOME` is a deliberate move and is promoted, as the launcher keeps it.
  So the arbiter refuses exactly the envs the launcher rewrites, and promotes
  every env the rewrite produces, whose Mandu home is never inside the
  foreign HOME: `tests/stack/foreign-home-parity.test.ts`
  checks this over every combination of HOME, `MANDU_HOME`, an XDG root and
  the runtime base. What neither side can tell is a scratch `MANDU_HOME`
  under the account's own HOME (a test that sets only `MANDU_HOME`): it looks
  like a relocation, and such a run must also set `MANDU_RUNTIME_DIR`
  (on-disk-layout.md §5 "Tests").
- **Out of scope on purpose:** a fully isolated run (its own
  `MANDU_RUNTIME_DIR` or `XDG_RUNTIME_DIR`) keeps its HOME and promotes inside
  its own base, which is what the test harnesses and the demo sandbox do. An
  account the platform cannot name (no `getuid`, no passwd entry) skips both
  checks rather than guess.

Tests: `launcher/test/unit/arbiter.test.ts` (the rewrite, the XDG rule, both
spawns, the untouched real-home case, `accountOf` and the rewrite at the macOS
rendezvous), `arbiter/test/unit/instance.test.ts` (the refusal conditions,
`MANDU_HOME` included, `accountIdentity` and the refusal on macOS),
`tests/stack/foreign-home-parity.test.ts` (the two sides
agree), the parity oracle `tests/stack/runtime-base-parity.test.ts`
(the two rendezvous copies agree), and the dashboard's adopt-time displacement in
`dashboard/test/unit/supervisor/supervisor-adopt.test.ts`.

## 14. Launch time

Decision note, BUILT (2026-09-28). Where the seconds of a `mandu claude` /
`mandu codex` launch go, what was changed to cut them, and what bounds the
rest. Every change here keeps each security decision exactly as it was: it
changes when work runs, never what is decided.

### 14.1 What was measured

On a developer home (~50,000 directories to the discovery walk's depth, 13
git repositories holding a protected file, one of them a Linux kernel
checkout; a workspace with ~1,800 tracked files, ~1,700 of them symbolic
twins in `full` mode), a relaunch took 40 to 60 s. Timestamping every launch
line and tracing every process the launcher spawned (`strace -f -e execve`)
gave, in order, all of it sequential:

| Step | Cost | Why |
|---|---|---|
| git history of protected files | ~35 s | the kernel checkout's full history walked and three pack indexes read whole on every launch (`confidentiality.md` §7.2a "Cost on a relaunch") |
| fs-view init | ~3 s | the re-launch seed asked the arbiter about each twin one at a time (~4,400 round trips) |
| secret discovery | 2.5–3.8 s | the HOME walk, synchronous in the arbiter |
| context proxy, then net-proxy | ~1.9 s | one after the other, each a `npm run serve` + tsx start (since 2026-10-04 one node process each, from the checkout's prebuilt bundle: packaging.md §5.1) |
| fs-sync watcher readiness | ~1.6 s | awaited before anything after it started |
| git history, 13 repositories | ~2.5 s | one repository at a time, even with the walk cached |

The kernel checkout was in the git step only because the `*credentials*`
catalog shape matched `Documentation/security/credentials.rst`
(`confidentiality.md` §6: documentation pages no longer match).

### 14.2 The changes

1. **The git history walk is cached, and pack indexes are searched, not
   read** (`launcher/src/git-object-twins.ts`; `confidentiality.md` §7.2a).
2. **The re-launch seed checks its twins concurrently**, 32 at a time over
   the one pipelined arbiter client, and still mints one file at a time in
   tracked order (`fs-sync/src/view-sync.ts`; `fs-sync.md §3`
   "Concurrent checks").
3. **Secret discovery starts as soon as the AgentView is seeded**
   (`run.ts` `prefetchDiscovery` from the `onFsViewReady` hook of
   `startServices`; `secret-setup.ts` `withPrefetchedDiscovery` hands its
   answer to the secret setup) and runs while the proxies and the network
   confine come up. Not earlier: the walk reads this workspace's AgentView
   copy to twin any raw secret in it (`secret-discovery.ts`
   `agentViewRoots`), and a walk before the seed could miss one the seed just
   made. After the seed, the only AgentView writer before the agent starts is
   the watcher's catch-up reconcile, which writes symbols only. The prefetch
   is served only to a call with exactly its arguments; a failed prefetch
   surfaces where the secret setup awaits it, as the same fail-closed
   refusal.
4. **The context proxy and the net-proxy start together**
   (`services/manager.ts` `guardedTogether`). Neither reads what the other
   produces. Every start settles before any failure is handled, so a refusal
   also tears down a sibling that came up after the failing one, and the
   failures are handled in list order, as one at a time did.
5. **The fs-sync watcher's readiness is awaited last** (`FsViewResult.ready`,
   awaited at the end of `startServices`): it is soft (a timeout only warns)
   and its node start overlaps the proxies'.
6. **The git history step reads repositories concurrently** (8 at a time:
   the walk or its cache, the inventory, the plan) and then rebuilds packs
   and assembles twins one object store at a time in order, so the rebuild
   cap counts as before; `git version` is asked at most once (taken from the
   git sandbox's probe where there is one), work trees of one object store
   share the tips, the walks and the plan, and the tips are read without
   `rev-list --reflog` (confidentiality.md §7.2a "Cost on a relaunch").
7. **Secret discovery runs on a worker thread in the arbiter**
   (`arbiter/policy/secret-discovery-thread.ts` `DiscoveryWorker`, entry
   `secret-discovery-worker.ts`). The walk used to run synchronously in the
   arbiter's event loop, so for its ~1.5-3 s every other arbiter call waited:
   the launching session's watcher subscription, its proxies' and network
   confine's calls, and on a shared stack every other session. Now:
   - The arbiter builds the job at request time: the roots (the declared
     model client keys added, confidentiality-plan-12 D3) and a snapshot of
     the label stores (`LabelSnapshot`: the human labels, the derived labels,
     the client keys). `postMessage` clones it on the spot. The worker runs
     the same `discoverSecretsReport` over the same composition
     (`arbiter/policy/label-lookup.ts` `composedLabel`, which the arbiter's
     live lookup also uses), so the answer is the one the in-process walk
     would have given at that instant. A label act that lands during the walk
     is seen by the next discovery, just as one landing right after a
     synchronous walk was.
   - One thread serves the arbiter for its lifetime. The daemon starts it at
     listen (`warmDiscoveryWorker`; its start is ~0.4 s under tsx), and
     embedders and tests start it on the first walk. Walks run on it one at
     a time, in order, as they did in-process. It keeps the event loop
     alive only while a walk is pending.
   - The worker only reads the filesystem and returns plain data. It never
     opens the symbol DB (single writer), mints nothing and decides no gate.
   - Where the entry is found: beside the module in its own form (`.ts` in
     the source tree, which registers tsx inside the worker because tsx
     hooks only the main thread; `.js` compiled), or
     `dist/secret-discovery-worker.mjs` beside the bundled `dist/arbiter.mjs`
     (bundle-manifest.json `modules`).
   - Failure: if the thread cannot start, or dies holding walks, those walks
     run in-process (the old behavior, the same answer), with an arbiter log
     line `discoverSecrets: … walking in-process`. A walk that throws on the
     thread is that error (the in-process walk would throw the same). A
     closing arbiter stops the thread; a pending walk's client sees its
     connection close, as with any in-flight call.
   - Only the socket path runs off-thread: a direct `dispatch` (tests,
     embedders) still walks in-process. The reply is written when the walk
     finishes; the client matches replies by id, so later calls on the same
     connection are not held behind it.

   Measured (a HOME walk of 1.5-1.9 s in-process): while the walk runs, a
   concurrent `ping` answers in 1-6 ms (before: it waited for the whole walk),
   and the walk takes as long as in-process. A launch's own time did not
   change (median 4.64 s to Claude Code's first screen, warm, in `secrets`
   mode, before and after): the secret setup still waits for the walk. What
   the change buys is the arbiter staying responsive during the walk: to
   every other session on a shared stack, and to the launching session's
   watcher and proxies.

### 14.3 Result

Measured interleaved on the same machine and load, `full` mode, against an
isolated dev arbiter (`scripts/dev-arbiter.sh`), relaunch to Claude Code's
first output:

| Build | Relaunch |
|---|---|
| before changes 2–6 (change 1 and the name rule already in) | 10.0–10.4 s |
| with change 2 | 8.9–10.0 s |
| changes 2–6 | 6.2–7.2 s |

Before change 1 and the name rule, the same machine took 46 s.

### 14.4 What bounds the rest

- **The discovery walk itself** (~1.5-3 s on a developer HOME, at the I/O
  floor: `confidentiality.md` §7.2) still has to finish before the secret
  setup can plan the twins, so it stays on the launch's critical path. Since
  change 7 it no longer holds the arbiter. Making the walk itself cheaper
  (fewer directories, or a cached inventory revalidated by directory mtimes)
  is what would shorten a launch now.
- **Source-checkout layout only:** each of the launcher, fs-sync init, the
  watcher and the two proxies starts through tsx (~0.5 s of transpile and
  module load each). An installed Mandu runs prebuilt bundles.
- **The first launch of a workspace** still seeds every twin and sanitizes
  any pack holding a protected version (~30 s on the workspace above); both
  are cached for every launch after it.

### 14.5 Tests

- `fs-sync/test/component/seed-idempotency.test.ts` (200 files: the checks
  overlap within the bound, exactly the obsoleted and relabeled twins
  re-mint), `fs-sync/test/integrity/map-pool.test.ts`.
- `launcher/test/unit/manager.test.ts`: the proxies start together; a
  failure refuses only after the sibling settled and tears it down; both
  failing names the first in list order; `onFsViewReady` fires after the
  filesystem step and before the proxies; the watcher's readiness is awaited
  before `startServices` returns.
- `launcher/test/unit/secret-setup.test.ts`: the prefetch is served once and
  only for its exact arguments; a class arbiter's methods are forwarded; a
  failed prefetch refuses with no unhandled rejection.
- `tests/stack/discovery-prefetch-parity.test.ts`: the
  production wiring over a real `ArbiterServer`: a prefetched launch
  confines exactly what a plain one does, no twin holds a secret byte, a
  mismatched prefetch is not used, a failed one refuses.
- `launcher/test/kernel/git-object-twins.test.ts`: five real repositories read
  concurrently, `git version` asked once, the same twins as one at a time;
  a worktree and its main checkout get one twin per object file, and no
  protected version of either reaches git in the wrap.
- `launcher/test/unit/reflog-tips.test.ts`: the tips read from the reflog
  files equal git's `rev-list --all --reflog --no-walk` (a superset where
  git skips a log), every doubt asks git, and one object store's work trees
  share the tips, the base and the walks.
- `arbiter/test/unit/secret-discovery-thread.test.ts`: the thread answers
  exactly what the in-process walk answers (catalog, human labels both ways,
  a derived label, a client key), walk after walk and for walks sent
  together; no entry, an entry that fails to load, or one that exits: the
  in-process walk, the same answer; a throwing walk is its error and the
  thread serves on; a stopped thread rejects without walking in-process; the
  entry is found only beside the module in its own form; the label
  composition.
- `arbiter/test/component/discover-secrets-off-thread.test.ts`: over a real
  `ArbiterServer` + client, warmed at listen: the same answer as `dispatch`,
  DB labels included; a `ping` sent during the walk is answered first; the
  next walk sees a later label act; a closing arbiter fails the pending call.
- `launcher/test/component/bundle-smoke.test.ts`: the worker ships beside
  `dist/arbiter.mjs` and the bundled arbiter walks on it, not in-process.

### 14.6 Readiness deadlines under load

The other side of launch time: how long a launch WAITS for a service it
started before it refuses. Fixed probe counts (about 10 s for the proxies,
5 s for the arbiter socket, 6 s plus a 14 s grace for the stack autostart's
supervisor, 10 s for the supervisor's own arbiter start) looked wide on an
idle machine, where each start takes 0.5 to 2 s (§14.4: tsx in a source
checkout). On a saturated host they were not: the context proxy missed its
10 s on a heavily loaded CI host and the launch refused ("service
'context-proxy' was requested but failed to start";
`docs/testing/differential-interactive.md` §23.1), and
`instance-autostart.test.ts` refused under load with "arbiter did not come
up" (§10, "One resident arbiter per autostart"). Every refusal was correct
(fail-closed); the deadlines were wrong.

**The deadline** (`launcher/src/services/primitives.ts`
`serviceReadyDeadlineMs`): 30 s on an idle host, stretched by the 1-minute
load average per usable CPU when that ratio exceeds 1 (`os.loadavg()[0] /
os.availableParallelism()`; twice the CPU count, twice the time), capped at
120 s. `MANDU_SERVICE_READY_TIMEOUT_MS` (a positive integer, milliseconds)
replaces the computation, uncapped; a garbled value is ignored. The deadline
decides how long, never whether: expiry refuses the launch exactly as
before, and `--best-effort` is still the only way past a proxy that did not
come up (and never past a foreign one).

**A dead service ends the wait at once.** A longer deadline must not make a
broken start slower to report, so every wait also watches the process it
started (`DetachedHandle.exited`, `WaitOpts.giveUp`; the arbiter's
`DaemonHandle.running` through `ensureArbiter`) and stops on its exit. The
refusal names which it was: `not ready within 30 s;
MANDU_SERVICE_READY_TIMEOUT_MS (milliseconds) sets a longer deadline`, or
`it exited with code 1 before becoming ready`.

Where it applies:

- the context proxy and the net-proxy (`services/context-proxy.ts`,
  `services/net-proxy.ts`): one budget (`readinessBudget`) shared by the
  port-file wait and the listen wait. The identity re-check after the listen
  and the net-proxy's MITM CA wait keep their fixed bounds: the first answers
  in milliseconds once the port is up, and the second, when it misses,
  degrades the launch to a blind tunnel with a warning rather than refusing
  it, and a longer wait there would delay every launch on a host without
  `openssl`.
- the arbiter socket after a start (`arbiter.ts` `pollArbiterSocket`, from
  `run.ts`): the fallback arbiter's wait and a pinned `startArbiter`'s.
- the stack autostart (`arbiter.ts` `startArbiterInstance`): the supervisor
  dashboard is handed the deadline (`MANDU_SERVICE_READY_TIMEOUT_MS` in its
  env; `dashboard/src/supervisor/supervisor-defs.ts` `startTimeoutFromEnv`)
  for its own arbiter start, and the launcher gives it two deadlines in all
  (its own start, then its arbiter's; `defaultSupervisorGraceMs`, never under
  20 s). A supervisor whose arbiter start failed exits (code 1) when it runs
  as `DASHBOARD_AUTOSTART=arbiter`, so the launcher starts its fallback at
  once instead of waiting for a promotion that cannot come.

- `scripts/dev-arbiter.sh`: its socket wait (§10.2) takes the test budget
  below, and a group that exits ends the wait at once. Ready is both
  sockets: its output names the admin socket too, and the daemon binds that
  one a moment after the data socket (`server.ts` `listen()`: the human
  plane, the data socket, then the admin channel), so "up" on the data
  socket alone let a caller find no admin socket on a slow host. A refusal
  says how long it waited and which socket was missing. Its callers' own
  bounds sit above the budget (the drill runner's backstop: 300 s). Tests:
  `scripts/test/dev-arbiter.test.sh` (a 1 ms deadline refuses and stops the
  start; an arbiter refusing a policy file that does not validate is reported
  at once, not at the deadline; a stand-in daemon whose admin socket comes
  late is waited for, and one that never binds it is refused).

Not changed: the fs-sync watcher's readiness (soft, a timeout only warns),
and the waits of subcommands and `mandu demo`.

**Tests and the dev arbiter.** A suite that starts an arbiter itself waits
for its socket on one budget, not on a fixed wait of its own: the deadline
above, doubled where `CI` is set (and not `false`, `0` or `no`);
`MANDU_SERVICE_READY_TIMEOUT_MS` sets it exactly, not doubled. The suites had
waits of 10 s (`bundle-smoke`), 20 s (`agent-config-delivery`, `golden-path`,
the goose suites, `installed-spawn`) and 20 plus 10 s (the live shell
suites), sized on an idle workstation. On GitHub's runners the first start of
a job is the slow one: a cold tsx cache, and the job's other test files
compiling on the same few vCPUs at that moment. The 1-minute load average
lags behind that burst, so the load scaling alone does not cover it. In the
beta.5 snapshot's green run (`ManduSec/mandu` run 37803498998, the
`ts (launcher)` job) `agent-config-delivery`'s first test, whose before-hook
starts the arbiter, took 13.5 s of its 20 s wait, against 0.04 s for the next
test of the same file; the staging run before it lost two starts to their
waits and was rerun once. The wait still ends when the socket appears or the
started process exits (a fixed wait sat out its whole length after an
arbiter that had died at once), and a refusal names what was missing, the
time spent against the budget and the last lines of the daemon's log. The
TS suites use `launcher/test/lib/arbiter-ready.ts` (`testReadyBudgetMs`,
`waitForPaths`), the shell suites and `dev-arbiter.sh`
`scripts/lib/ready-deadline.sh` (`mdu_ready_deadline_ms`,
`mdu_wait_sockets`). The TS suites also start the arbiter from source as one
node process (`sourceArbiterArgs`: `node --import <arbiter's tsx>`), as
`dev-arbiter.sh` does, not through the tsx binary, which starts a second
node. Tests: `launcher/test/unit/arbiter-ready.test.ts` and
`scripts/test/ready-deadline.test.sh` pin the same numbers (30 s idle; load
scaling capped at 120 s; doubled on CI, so at most 240 s; the override
exact, on CI too; garbled overrides and nonsense host figures ignored) and
the wait's three endings.

A start that does not come up FAILS the suite that asked for it, with the
daemon's log's last lines, and never SKIPs it (2026-10-18,
[`test-organization.md`](../testing/test-organization.md) §8.11). Until
then the live shell suites turned "arbiter sockets never appeared" into a
SKIP and exit 0, so a hung start on a slow runner showed green, and the
kernel-lane tests `own-stores-hidden`, `secret-bind-nesting` and
`wsl-windows-secrets` kept a fixed 20 s wait of their own. Now the shell
suites end the wait with `mdu_ready_why` and `mdu_log_tail`
(`scripts/lib/ready-deadline.sh`), the suites on `dev-arbiter.sh` fail on its
exit status (it already prints why and the log's tail) instead of polling a
second time, and the three kernel-lane tests use `waitForPaths` and
`sourceArbiterArgs`. A suite SKIPs only on a prerequisite it checks before
the start. `launcher/test/arbiter-start-fail.test.sh` runs the live suites
with a 1 ms budget and requires each to fail that way.

Tests:

- `launcher/test/unit/primitives.test.ts`: the deadline (idle base, load
  scaling, cap, nonsense host figures, the override and garbled overrides),
  one budget across two waits, the timeout and exit notes, `giveUp`, and
  `exited()` of a real detached process.
- `launcher/test/unit/context-proxy.test.ts`,
  `launcher/test/unit/net-proxy.test.ts`: the waits cover the deadline, the
  override shortens it and the launch still refuses and tears down, and an
  exited proxy ends the wait at once, named in the refusal.
- `launcher/test/unit/arbiter.test.ts`: `ensureArbiter` hands the wait the
  started daemon's liveness, `pollSocket` gives up early, `pollArbiterSocket`
  waits the given deadline, the supervisor's grace, and the supervisor env
  carrying the deadline.
- `launcher/test/component/services.test.ts`: a stand-in context proxy (the real
  detached spawner, `MANDU_DEV_REPO`) that never becomes ready refuses the
  launch at the deadline, the agent never runs and the proxy is torn down;
  one that exits refuses at once, naming the exit.
- `dashboard/test/unit/supervisor/start-timeout-env.test.ts`,
  `dashboard/test/component/autostart-arbiter-exit.test.ts`: the real dashboard
  under `DASHBOARD_AUTOSTART=arbiter` uses the handed deadline and exits 1
  when its arbiter misses it.

### 14.7 The second pass (2026-10-16)

Measured on the developer host (128 cores, load average 30-90 while it
ran, mode `secrets`, a warm resident stack, distro Node 22.22.1): every
agent's `<agent> --version` raw and through `mandu`, five runs each, from a
plain directory, a one-commit repository and the Mandu checkout; and the
time to Claude Code's and Codex's first interactive screen in a PTY. Raw,
each agent answers in 0.02-0.06 s (OpenCode 0.6-0.7 s); through Mandu the
launch added 1.3-2 s from a plain directory and 2.5-3.5 s in the checkout,
for every agent alike, so the cost was the launch, not the agent. Claude
Code's first screen: 0.33 s raw, ~1.85 s through Mandu.

Timing every step of `launch()` (marks at its statements in a copy of the
bundle) and every process it starts gave, for a warm launch from a plain
directory:

| Step | Cost | Why |
|---|---|---|
| the checkout shim | ~0.4 s | `mandu-run.sh` started two node processes (the secrets file, the bundle stamp) before the launcher's own |
| the git history step | 0.28-0.75 s | ~70 git calls, each in its own bubblewrap: 21 ms against 5 ms bare, and 8 at once 70 ms against 12 ms (bubblewrap's mount setup serializes; no single namespace is the cost) |
| the exec-wrap shim probe | ~0.2 s | a bash and a node start, awaited inside `startServices` |
| the discovery walk | 0-0.7 s | longer in a large checkout (§14.4) |
| the agent under the guards | 0.2-0.35 s | net-guard, Landlock, the PTY relay |

The changes, each keeping every decision as it was:

1. **One node before the launcher** (!1586, `packaging.md` §5.1): in a
   checkout the shim execs the launcher's node at once; the secrets file
   and the bundle stamp are read in that process, with the same rules (a
   variable already set is never overridden; a stale bundle never runs).
2. **The exec-wrap shim probe is kept per boot** (!1588,
   `portable-wrapper.md` §5): what it proves is the same for every session,
   so a pass is kept under the kernel probes' cache, keyed by every input
   that could change the answer; a failure is never kept.
3. **The history step's read-only git calls share one git sandbox per
   launch** (!1590, `write-protection.md` §8.5.3, `confidentiality.md`
   §7.2a): one bubblewrap runs a request runner that starts each call. Its
   /proc is empty and it is used only where Yama keeps a call from
   attaching to a sibling (ptrace_scope >= 1); elsewhere each call keeps
   its own sandbox. The step: ~345 ms -> ~175 ms.

Result, the same benchmark after the three merged (medians of five, warm):

| `<agent> --version` through Mandu | plain dir | small repo | Mandu checkout |
|---|---|---|---|
| claude | 1.74 -> 1.17 s | 1.79 -> 1.33 s | 3.50 -> 2.31 s |
| codex | 1.64 -> 1.37 s | 1.74 -> 1.26 s | 3.48 -> 2.21 s |
| openclaw (Node 24) | 1.34 -> 1.26 s | 1.46 -> 0.85 s | 3.70 -> 1.65 s |
| opencode | 2.61 -> 1.78 s | 2.67 -> 1.85 s | 4.15 -> 2.74 s |
| goose | 1.78 -> 1.22 s | 1.88 -> 1.42 s | 2.69 -> 2.24 s |

Claude Code's first screen: ~1.85 s -> 1.55-1.65 s; Codex's: ~2.0 s ->
~1.7 s. The first launch after the stack starts is slower (3.8-10 s: the
arbiter and the dashboard start, and the per-boot caches fill). So is the
first launch after an UNPROTECTED one ends (`--no-net-guard`, mode `off`,
any `gated` posture): that end starts a new seal epoch, and the next launch
rebuilds every sanitized git pack it binds (confidentiality-plan-14 §11.2;
§11.2.1 names a launch only while it is still running). From a small
repository on the developer host that was 5-7 s against ~1.3 s, the
sanitizing of ~90 MiB of the Mandu checkout's packs (7 packs holding
protected versions), since the history step covers every repository the
secret walk finds, not only the launch's own. The launches that looked slow
"with `--no-landlock-net`" on 2026-10-16 were each the first after a
`--no-net-guard` launch (their `launch_posture` events: 6.4, 7.5 and
7.1 s, and 8.1 s for one with the rung on in the same place); the rung
itself costs nothing measurable (1.1-1.5 s either way, 2026-10-17).
That wait is still paid (the rule is unchanged) but no longer silent
(2026-10-17, plan 14 §11.2.1 "The rebuild notice"): the launch prints one
line before the work, above its mode line, without `--verbose`:
`mandu: ! an earlier Mandu session without protection has ended, so Mandu
is re-checking the git history of 2 repositories (slower this once)`.

What is left:

- **The node runtime.** Ubuntu's `/usr/bin/node` (22.22.1, a 26 KB binary
  over `libnode`) starts in 93 ms where the official Node 24 build starts
  in 31 ms, and loads the launcher bundle in 257 ms against 117 ms; a
  launch starts about five node processes. Interleaved, a whole launch from
  a plain directory took ~1.45 s on the official build against ~1.95 s on
  the distro one. Not a code change; a host one.
- **The discovery walk** (§14.4), still the variable part in a large
  checkout.
- **Hosts without Yama, or with ptrace_scope 0**, keep one git sandbox per
  call, so the history step keeps its old cost there.

### 14.8 The guard's work per exec (2026-10-18)

Decision note, BUILT. Under a secret policy the guard's filter traps every
`execve`/`execveat` of the agent's tree (plan 10 §4.2): the guard reads the
argv, the process's key, its live ancestor chain (plan 13 D7) and its
directory while the tracee is suspended, asks the arbiter first when the exec
is a call root in a session (`sessionExecRoot`, confidentiality.md §4), lets
the exec go, and then records it (`recordExecRoot`). Nothing there can refuse
an exec. Every exec attempt pays it, a failed `PATH` probe too.

**Measured** on the developer host (128 cores, Linux 7.0, load average 35-90
while it ran), with the release guard (`mandu-net-guard`) around a
`sh` loop of 2,000 `/bin/true` runs under a one-file secret policy, and
the guard's own timing of each step (a throwaway build). Per exec, from
the guard's receipt of the notification to its `CONTINUE`:

| Step | Before | Why |
|---|---|---|
| making the handler's thread and its first run | ~100 µs | `on_own_thread`: a thread per exec (~48 µs of it in the receiving worker) |
| the process's key | 76-86 µs | `own_key_of`: the thread's `status` (its `Tgid:`), its process's `stat` |
| the ancestor chain, one level | 60-64 µs | `lineage_chain_of`: the thread's `status` AGAIN (`PPid:`), then a `stat` and a `status` per ancestor |
| the argv | 12-13 µs | `process_vm_readv` |
| the directory | 11-12 µs | a `readlink` of `/proc/<pid>/cwd` |
| the answer | 4-5 µs | |
| **held in all** | **~270-285 µs** | |

The record (`recordExecRoot`, ~370 µs a round trip to a dev arbiter) is
sent after the `CONTINUE`, off the tracee's path. The same `/proc` reads in
a tight loop cost a tenth of that (`status` 10-14 µs, `stat` 5 µs,
`readlink` 1.3 µs); in the guard each runs on a cold, just-made thread.
For comparison, bare, each loop iteration (a fork, an exec, an exit) took
0.55-0.8 ms on that host.

**The two changes**, neither changing what is read, decided or recorded:

1. **The reads run on the worker that received the exec** (`dispatch`,
   `exec_seen`), as an open's do (plan 10 §4.1a): `/proc` and the tracee's
   memory only, nothing that waits on the arbiter or another process. Only
   an exec that asks the arbiter before it goes (`exec_asks`: a call root
   with a secret policy and an arbiter) is held on a thread of its own, as
   before, with the old refusal (`EAGAIN`) when none can be made. The record
   is sent from a thread made after the `CONTINUE` (`after_answer`); when
   none can be made it is sent from the worker, since the exec is already
   answered and only the report is left. Without an arbiter there is no
   record and no thread. The clean-box membership and the Landlock mirror's
   re-keying (`exec_seen`) still happen before the `CONTINUE`.
2. **The key and the chain come from one walk** (`secret_open::
   exec_lineage_of`): the thread's `status` once (its `Tgid:` and `PPid:`),
   its process's `stat` for the start time, and one `stat` per ancestor for
   both its start time and ITS parent (`stat`'s field 4 is the value
   `status` prints as `PPid:`). Five reads at one level of ancestry become
   three; each level costs one read instead of two. The answer is the one
   the three separate calls gave (a unit test compares them over the real
   `/proc`: a grandchild, a child of the guard, a worker thread, a gone
   process); the walk stops at the same places (below the guard, at init, at
   an unreadable start, after 32 levels); and an ancestor's key and its
   parent now come from the same read, so an exit between two reads can no
   longer pair them across two processes.

Not changed: what the arbiter is told and when, the call root's ask before
the exec goes (a kernel test reads the process's image while the arbiter
answers: still the old one), the fail-closed rules around it.

**Result**, interleaved runs of the same loop (µs per iteration; best and
worst of 3-4 runs; `depth`: shells that stay alive between the guard and
the loop, so the chain has that many more levels):

| | bare | before | after | held per exec, after |
|---|---|---|---|---|
| no arbiter, depth 0 | 556-1027 | 1137-1535 | 916-991 | 75-80 µs |
| no arbiter, depth 5 | 747-799 | 1793-2174 | 1037-1171 | 115-138 µs |
| dev arbiter, depth 0 | 672-743 | 1649-1733 | 1038-1084 | 91-93 µs |
| dev arbiter, depth 5 | 765-817 | 1613-1844 | 1060-1213 | 131-141 µs |

What the guard adds to an exec fell from ~0.9-1.2 ms to ~0.3-0.4 ms on that
host. A tool call starts a handful of execs (the agent's shell, the
command, the box's bwrap and applier), so this is a few milliseconds a call;
it matters for exec-heavy work (a build or a `configure`: thousands of
execs).

**What is left**, measured but not changed:

- **The loader's opens.** Every exec of a dynamically linked program opens
  `ld.so.cache` and its libraries, and each trapped open costs the guard
  70-78 µs on that host (the open performed for the tracee, plan 10 §4.1),
  so `/bin/true` pays ~150 µs there. Now the largest per-exec part.
  Measured step by step and trimmed in §14.9.
- **The record's thread.** With an arbiter, a thread per exec is still made
  after the `CONTINUE` (~50 µs of the worker's time, not the tracee's).
  One long-lived reporter would save it; the reports are serialized on the
  guard's one arbiter client anyway.
- **The box's host-socket scan** (~13 ms a boxed command,
  confidentiality-plan-10 §4.1a) stays per command: which host sockets
  exist is its security input (exec-routing.md §4).
- **A secret open's chain** (`handle_open_notif`) still takes the three
  separate reads; it is far rarer than an exec.

**Tests.** `net-supervisor/src/secret_open.rs` unit tests: the two parses,
the walk's stops (`chain_from`), and the one walk against the three
separate reads over the real `/proc`. `guard_kernel.rs`: a report owed after
the answer runs on its own thread, or on the caller when no thread can be
made, its handler count released either way. Kernel tests
`net-supervisor/tests/exec_record_integration.rs` (the real seccomp
listener, a recording arbiter): an exec two non-exec'ing subshells deep
names both, nearest first; a worker thread's exec names its process; the
tree's top process names the guard's process and no chain; each was held
on the worker (`EXECS_HELD_HERE`); a call root in a session is asked
before its exec goes (the old image while the arbiter answers), made a
holder and held on its own thread (`EXECS_HELD_ON_THREAD`); red when the
`CONTINUE` is moved before the ask. The guard writes the exec counts and
the total held time beside its open counts at exit
(`MANDU_NET_GUARD_OPEN_STATS`: `execs_held_here`, `execs_held_on_thread`,
`exec_held_us`), a diagnostic no decision reads. End to end, the guard
suites that drive exec records through a real arbiter
(`tests/sandbox/guard/call-tree.test.ts`, `high-session-command.test.ts`,
`guard-provenance.test.ts`, `agent-flow.test.ts`, `forged-reports.test.ts`)
are unchanged and pass.

### 14.9 The loader's opens (2026-10-18)

Decision note, BUILT. Every exec of a dynamically linked program opens
`/etc/ld.so.cache` and its libraries (`/bin/true`: the cache and libc).
Under a secret policy the guard performs each open for the tracee and
hands the descriptor over (plan 10 §4.1a), so these two opens were the
largest per-exec part left in §14.8.

**Measured** on the developer host (128 cores, Linux 7.0, load average
35-70 while it ran), with a throwaway build of the release guard that
times each step on the worker, a one-file secret policy, with and without
a dev arbiter, in two shapes: a tight loop of 5,000 `open`+`close` of
libc in one process (what the tracee waits, warm caches), and a loop of
1,000-2,000 `/bin/true` (the loader's own opens, each in a fresh
process). A bare `open`+`close` of libc there takes 0.7 µs.

Per open in the `/bin/true` loop, with the dev arbiter (each step's mean
over a run; ranges over 3 interleaved runs):

| Step | Before | After | What it is |
|---|---|---|---|
| receipt to the handler | 4-5 µs | 4-5 µs | the death watch's look, the dispatch |
| reading the call | 5-5.6 µs | 5-5.6 µs | the registers, the path (`process_vm_readv`) |
| performing the open | 19-24 µs | 15-18 µs | `/proc/<tid>/root`, the id check, `openat2(RESOLVE_IN_ROOT)`; before, also an `fstatfs` |
| the pseudo-filesystem test | 3.3-3.4 µs | 0.1 µs | an `fstatfs`; now the `fstat`'s device |
| the file's identity | 5.7-8 µs | 5.4-6.1 µs | `fstat`, `readlink`, the registered-file lookup |
| the label and derived gates | 3.6-5.7 µs | 3 µs | in memory: no arbiter round trip for these files |
| the in-flight object record | 5.2-7.4 µs | 2.7-3.1 µs | before, its own `fstat` and `readlink` |
| the handover | 13.6-15 µs | 13.8-14.5 µs | `ADDFD`: the tracee woken to install the descriptor, then the guard |
| **the guard's work** | **62-73 µs** | **50-56 µs** | |

In the tight loop the tracee waited 34-38 µs an open (median) before, of
which the guard's work was 33-40 µs; 23-30 µs after. Without an arbiter
the numbers are the same but for the gates (0.1-0.2 µs: no label list to
consult). The rest of each open is the kernel's: the notification's
wakeups (the trap waking a worker, `ADDFD` waking the tracee), about
10-12 µs there.

So the decision was never the cost. The registered-file lookup, the label
roots, the derived index and the git lock check take 1-3 µs warm and 3-6
µs in a fresh process, all in memory: the label list is read at most once a second (`label_index::
REFRESH_NS`), the derived index only when a file changed after its last
read, and the arbiter is asked about a file only when it lies under a
label root. What cost was the syscalls around the decision.

**The two changes**, neither changing what is opened, decided or refused:

1. **No `fstatfs` for a file on a block device.** The guard asked
   `fstatfs` twice an open (`remap_own_procfs`, `context_helper::classify`)
   to learn whether the file is on procfs, sysfs, cgroupfs or another
   pseudo filesystem; on ext4 it sums per-CPU counters, 2.4-2.8 µs on that
   host (an `fstat`: 0.2 µs). Every pseudo filesystem is a superblock with
   no block device behind it, numbered from the kernel's anonymous devices
   (major 0), and its inodes report that number; a non-zero major is a
   block device's (ext4, xfs, a loop or device-mapper volume). So a file
   whose `fstat` shows a non-zero major is answered "not a pseudo file"
   (`fs_supervisor::tracee::may_be_pseudo_fs`); every other file (tmpfs,
   overlayfs, btrfs, FUSE, the pseudo filesystems) is judged by its
   `fstatfs` as before. The rule only ever says "not pseudo", and only for
   a block device: the wrong answer would hand the guard's own open of a
   `/proc` file to the tracee instead of the opener-judged reopen, so it
   takes no other shortcut.
2. **One look at the opened descriptor.** Four `fstat`s and two or three
   `readlink`s of `/proc/self/fd/N` (one more under deny prefixes) became
   one of each (the link read when first needed), handed to each check: the
   deny prefixes, the identity, the git lock check, the label and derived
   gates, the object record, the FIFO link. Each read was a snapshot of the
   same descriptor (its file cannot change; a rename can change its name
   between any two reads), and the checks now agree on one snapshot.

**Considered and refused:**

- **Answering `CONTINUE` for files no label can reach** (read-only opens
  of root-owned files on system paths). A `CONTINUE` lets the kernel read
  the path from the tracee's memory and resolve it again after the guard
  answered: another thread, an ancestor writing the tracee's memory
  (`process_vm_writev`, which Yama's default allows an ancestor), or a mount
  in the tree's own mount namespace (a sandbox) can change what it names
  in between, the race plan 10 §4.1a closed (757 of 3,000 opens read the
  secret before it). No check before a `CONTINUE` binds the decision to
  the file the kernel then opens, whatever the first path named; and the
  decision it would skip costs 3-6 µs of 50.
- **Caching "unlabelled"** per file: the gates are in memory already, and
  a label set mid-session must reach a file read before it (the kernel
  test below reads one raw, then its twin once the label is listed).
- **`SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP`** (Linux 6.6: the worker woken on
  the tracee's CPU and back). Measured: the tracee's median unchanged, its
  90th percentile worse (47-52 µs against 38-40), and the handover held
  the worker 37-46 µs instead of 10-13 (the woken tracee runs on the
  worker's CPU first). Not used.
- **A shorter read of the path**: 4,096 bytes cost 0.93 µs, 64 bytes
  0.74 µs.
- **The tracee's root kept per process**: the loader's opens are each new
  process's first two, so it would serve one of them, and every way a root
  changes (`chroot`, `pivot_root`, `setns`, `unshare`, a thread sharing it)
  would have to reach the cache.

**Result**, interleaved runs: an open in the tight loop 34-38 µs before,
23-30 µs after (median); the guard's work per open in a fresh process
62-73 µs before, 50-56 µs after, so a dynamically linked exec pays about
20-30 µs less. The `/bin/true` loop as a whole is too noisy on that host to
show it alone (per iteration: bare 535-960 µs, before 1,050-1,500 µs,
after 980-1,490 µs). In these runs the exec trap itself held each exec
210-250 µs (§14.8 measured 75-93 µs on a quieter host); not looked into
here.

**What is left** of an open, in a fresh process: the handover and the
notification's wakeups (about 25 µs, the kernel's), the performed open
(15-18 µs: the tracee's root by `/proc/<tid>/root`, its pid check,
`openat2`), reading the call (5 µs) and the gates (3 µs). Each is either
the kernel's own work or a check.

**Tests.** `fs-supervisor/src/tracee.rs` unit tests: the major decoded as
glibc does and only major 0 may be a pseudo filesystem
(`only_an_anonymous_device_may_be_a_pseudo_filesystem`), and every pseudo
filesystem the host mounts has major 0
(`every_pseudo_filesystem_here_has_an_anonymous_device`).
`net-supervisor/src/context_helper.rs`: the shortcut classifies as the
`fstatfs` alone did over procfs, sysfs, cgroupfs, devtmpfs, tmpfs and the
build tree's file system (`the_stat_shortcut_classifies_as_the_statfs_did`).
Kernel test `net-supervisor/tests/labelled_open_integration.rs` (j), its
fixture on a block device's file system (the build tree's, `/var/tmp` or
`$HOME`; SKIP where none can be written): a file under a label set
mid-session reads raw before the label is listed and its twin after, and
so do the file by its name, a symlink and a hard link outside the label's
root, after a rename inside the root and one out of it; the registered
secret by a symlink and a hard link gets its twin; `/proc/self/status` is
still the tracee's own. The kernel suites of the guard
(`net-supervisor/tests/*`, among them the path rewritten and the symlink
swapped mid-open) and the guard e2e suites (`tests/sandbox/guard/
guard-provenance.test.ts`, `forged-reports.test.ts`, `call-tree.test.ts`,
`agent-flow.test.ts`, `high-session-command.test.ts`, `tar-secret.test.ts`,
and `launcher/test/secret-readers-live.test.sh`) are unchanged and pass.
