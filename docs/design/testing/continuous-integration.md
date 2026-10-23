# Continuous integration: one disposable VM per run

Status: BUILT. The per-push gate (§3 to §8, since 2026-09-28), the docs-only
lane (§5.5), the nightly and its two credential lanes (§9, 2026-09-29/30)
and the Linux 7.0 guest (§4.1, 2026-09-30). The public repository's GitHub
Actions run the sealed kinds (§12). How test credentials are supplied, on a
developer's machine and in the nightly: §13. The clippy gate and the
dependency audit (§14, 2026-10-09).

- What runs: the kinds of [`test-organization.md`](./test-organization.md)
  §3. This document decides where and when they run, not what they are.
- The Docker-based pipeline this replaced was retired on 2026-09-28. Its
  wrapper, `scripts/ci/docker-run.sh`, and the `Dockerfile.ci` image survive
  as a hand-run rig ([`docker-e2e.md`](./docker-e2e.md) §1); no CI job uses
  them.

## 1. Why

The retired pipeline used a model credential on every push, mixed
`allow_failure` soaks into the gate (so a red did not say whether the code or
the model had moved), and ran in containers that shared the kernel, and with
`--publish-events` the dashboard, of the machine it ran on. It also once
stopped running for two days without anyone noticing: a pipeline that never
runs is green by absence.

The current design keeps three properties:

1. **Every automatic per-push run is deterministic and needs no credential.**
   A red is always a code bug, and no push holds a credential.
2. **A test run cannot touch the host.** Not its files, its processes, its
   ports, its logins or its kernel.
3. **What CI runs, a developer runs with one command** (§8), on the same
   image, with the same result.

## 2. What runs when

| When | Kinds (`test-organization.md` §3) | Blocking | Where |
|---|---|---|---|
| every merge request, every push to `master` | `unit`, `component`, `stack`, `replay-drill`, `sandbox` | yes | one VM, no network (§3 to §6) |
| hourly, on `master`'s head when it moved since its last finished test (the master check, §7.1) | the same per-push kinds, a run no newer commit cancels | a red master pipeline | the same VM |
| a merge request whose diff is documentation only | the docs lane: the manifest's `docsLane` entries (§5.5) | yes | the same VM |
| a merge request whose code paths are all in a declared scope (the drill machinery) | the scoped lane: the per-push entries that can reach it, plus the docs lane's (§5.8) | yes | the same VM |
| release tag `v*` | the above, plus `install` (the VM matrix); the release itself is built and published from the public snapshot by the public repository's release workflow once this pipeline passed (§12, packaging.md §11.3) | yes (the release waits for it) | the VM, the matrix's own guests, and the matrix's `host` cells on the runner host itself, from the job's clean checkout under the runner's clean `HOME` (`os-test-matrix.md` §4.1) |
| nightly | `live-drill`, `env`, `eval`, in `secrets` mode only, plus every `flaky` entry | no | one VM with a network, the host's Ollama on one port and one credential kind per lane (§9); the only run that holds a credential |
| nightly, release tag `v*`, and a merge request that changes a lockfile or the audit | the dependency audit: `deps.audit-npm`, `deps.audit-cargo` (§14.2) | yes (the release waits for it, packaging.md §11.3) | one VM like the per-push one with a network and no credential (§14.2) |
| nightly, and release tag `v*` | the entries that need `kernel`, on Linux 7.0 | yes on a tag (the release waits for it, packaging.md §11.3); a red nightly run otherwise | one VM like the per-push one (no network, no credential), booted from the Ubuntu 26.04 image (§4.1) |
| a pull request on the public repository, the release check (a `v*` tag there runs `ci.yml` through `release.yml`), and a check by hand (§12) | `unit`, `component`, `stack` only (no macOS: a maintainer runs the darwin entries on a Mac by hand, §12), plus the dependency audit (§14.2) | yes | GitHub-hosted Linux runners (§12) |
| never automatic | the frozen lane (runs only when integrity is revived, `protection-modes.md §10` §5) | n/a | by hand |

Every row but the GitHub one runs through `scripts/ci/vm-run.sh` on a host
with KVM. The maintainers run it from their own runners (§7); anyone with
`/dev/kvm` runs the same command by hand (§8).

The `replay-drill` and `live-drill` entries are the agent drills, the
maintainers' evidence tooling. They are not published: their entries live in
the source repository's second manifest (`test-organization.md` §3, §5), so
in the public tree those two kinds select nothing outside the frozen lane,
and the sections below that describe the drill entries (their records, the
replay store, the live drill lane) describe the maintainers' runs. What the
drills show is in
[`drill-results.md`](../../testing/drill-results.md).

## 3. The boundary: one KVM guest per pipeline

Every run boots a fresh guest from a prepared image, runs the kinds inside it,
writes a results archive and powers off. The guest's disk is a throwaway
overlay, deleted after the run.

**Why a VM, not Docker.** A container shares the host's kernel: a test that
wedges or panics the kernel, or exhausts memory or PIDs, takes the host and
anything else running on it with it. The kernel tier needed Docker's seccomp,
AppArmor and `systempaths` relaxed (docker-run.sh's `--kernel-tests`); in a
guest it runs as on a real host with nothing relaxed. The runner account
needs only `/dev/kvm` (the `kvm` group), not the `docker` group, which is
root-equivalent on the host. The cost is a boot and an image to maintain
(§4). Measured: the guest's unit starts about 6 to 8 s after power-on, and a
`--selftest` round trip (overlay, disks, boot, the sandbox's own test,
results back through the collector) takes 15 s.

**Why one guest, not one per kind.** The kinds share one build (`npm ci`,
`tsc`, `cargo build`, the kernel-feature binaries), which is a large share of
the run. One guest builds once and runs everything; per-suite isolation
inside it comes from namespace sandboxes (§5), which cost nothing.

**What crosses the boundary.** Three virtio disks and nothing else (the
nightly adds a network, one host port and a fourth, read-only credential
disk, §9; nothing else runs with them):

| Disk | Direction | Content |
|---|---|---|
| system | read-write overlay over the image (qcow2, `backing_file`; `bootindex=0`, or SeaBIOS tries the tar disk first and hangs; `cache=unsafe`, below) | the guest's root; deleted after the run |
| input (`serial=mandu-in`) | read-only, raw | a tar: `git archive` of the commit under test under `src/`, `src/.git` (a one-commit shallow repository whose detached HEAD is that commit, so suites that read the repository's git state see the real commit; a `--worktree` run's edits show as a dirty tree), plus `job.env` (mode, kinds, selection, concurrency, run id, commit, ref, image) |
| output (`serial=mandu-out`) | write, raw, fixed size (2 GiB, sparse) | a tar the guest writes at the end: `summary.json`, `junit.xml`, one log per suite, `artifacts/release/` for `--exec` |

- **The system disk ignores the guest's flushes** (`cache=unsafe`). It is
  deleted after the run and nothing reads it, so a flush buys nothing; on a
  spinning disk each of the guest's fsyncs (dpkg, npm, SQLite, cargo) was a
  seek, and one unpacked package took 9 s against 0.17 s on an SSD. The input
  disk is read-only and the output disk keeps the default: only the one
  throwaway disk skips flushes.
- **No network device** (`-nic none`). Everything the run needs is in the
  image. A suite that tries to go online fails loudly instead of passing
  against the internet.
- **No shared filesystem.** No 9p, no virtiofs: the guest never sees any path
  of the host. The host never mounts a filesystem the guest wrote; it reads
  the output disk as a tar stream (§6).
- **A hard timeout, behind the guest's own budget.** The host kills the guest
  after `MANDU_CI_TIMEOUT` (default 45 minutes) and reports the run as
  `error`. A kill leaves nothing but the console: the output disk is written
  only when the guest ends its run. Pipelines 10978, 11050 and 11099 (October 2026)
  were killed like this with every finished suite green. Their consoles stopped
  about 650 s in, not because the console was cut off but because the runner
  prints an entry's line only when the entry ends: the entries that never
  printed were `rust.kernel`, whose own timeout (then 3600 s) was past the
  guest's whole timeout, and the serial stage queued behind it. No suite log
  came back to name the hung test. So the guest now ends its own run first:
  - vm-run.sh puts a **budget** in `job.env` (`MANDU_CI_BUDGET`, lib.sh's
    `ci_guest_budget`): the seconds of guest uptime by which the pipeline
    must be over, the timeout less a tenth of it, at most 150 s (2550 s for
    the default timeout).
  - boot.sh gives the pipeline a **deadline** a tenth of the budget (at most
    150 s) before it (`pipeline.sh --deadline`, `run-suites.mjs --deadline`):
    from then on no entry starts, and an entry still running is stopped as at
    its own timeout, with the timeout report (its processes, the test files or
    cargo test binaries still running) in its log, the result `timeout` and a
    reason that names the deadline. The run is an `error` (`deadline: …`) with
    the entries never started listed as not run, and the summary, junit and
    every log so far reach the output disk as usual.
  - A **watchdog** in boot.sh fires at the budget itself, for what the
    deadline does not cover (a build that hangs, a runner that does not stop):
    SIGTERM, then SIGKILL, to every process of `ci`, then the stage
    `watchdog: error` in the runner's summary, or an `error` summary of its own
    when there is none, and the results disk as usual.
  - The runner prints a **heartbeat** every 120 s (`run-suites.mjs
    --heartbeat`, `MANDU_CI_HEARTBEAT`): every entry still running with its
    age and timeout, so even the console of a killed guest says what was
    running. A guest that did not end by itself also gets its console's last
    40 lines in the job log.
  - `scripts/kernel-tests.sh` writes each crate's log into
    `logs/kernel-tests/` as it runs, and on SIGTERM says which crate it
    stopped, the tests libtest reported as running for over 60 seconds, and
    the log's tail. `rust.kernel`'s timeout is 1200 s (a CI run takes
    200 to 290 s). It reads every crate log as text (`grep -a`): a test that
    prints raw bytes (a git pack) made grep call the log binary and drop the
    `test result:` lines the runner sums, so the 2026-10-17 nightly's
    `rust.kernel` counted 256 of its 1016 tests and failed its `ci.minPass`
    with every test green.
- **No leaked guest.** qemu writes `-pidfile` and vm-run.sh (and vm-image.sh's
  provisioning boot) registers it for `mandu reap` with itself as owner; a
  signalled run stops its guest from its EXIT trap, and a run killed hard
  leaves a guest `mandu reap` stops, removing the run's disks
  ([`os-test-matrix.md`](./os-test-matrix.md) §10.17.3).

**Inside the guest.**
- Ubuntu 24.04 (the release the product's main target runs), kernel 6.8. The
  entries that need `kernel` also run on Ubuntu 26.04, kernel 7.0, outside
  the per-push gate (§4.1).
- A systemd unit (`mandu-ci.service`, `scripts/ci/guest/boot.sh`) runs at
  boot: it finds the disks by `/dev/disk/by-id/virtio-mandu-in` and
  `virtio-mandu-out` and mounts nothing; reads `job.env` **as data** (a fixed
  key list, one narrow character set, the `--exec` command base64-encoded; a
  line outside that grammar stops the run); unpacks `src/` over
  `/work/mandu` as `ci`; runs `scripts/ci/pipeline.sh` as the unprivileged
  user `ci`; writes `/work/out` with `tar -c -f /dev/disk/by-id/virtio-mandu-out`
  (after dropping anything but files and directories); powers off. The
  pipeline itself comes from the commit under test; only `boot.sh` is baked
  into the image. `mandu.ci=off` on the kernel command line, or
  `MANDU_CI_MODE=shell` in `job.env` (`vm-run.sh --shell`), keeps it from
  running.
- Root is used only for that setup. Every suite runs as `ci`: the default
  suites must pass unprivileged ([`CONTRIBUTING.md`](../../../CONTRIBUTING.md)),
  and the `kernel`-need entries prove the *unprivileged* attachments.
- **A cgroup delegated to `ci`.** No `user@UID.service` delegates one in
  the guest, so `boot.sh` makes the shape a desktop terminal or tmux gives a
  user (`delegate_cgroup`): `mandu-ci.service` has `Delegate=memory pids`;
  `boot.sh` moves itself to `<unit>/boot`, switches on `memory` and `pids`
  where the kernel offers them (no limit is set), and delegates
  `<unit>/ci` to `ci` as cgroup-v2.rst "Delegation" documents (the
  directory, `cgroup.procs`, `cgroup.threads`, `cgroup.subtree_control`);
  `ci` makes `ci/run`, where the pipeline (and `--shell`'s login) runs, and
  an empty `ci/spare` beside it. So the guard's cgroup rule
  (rootless-confinement-ubuntu-2404.md §12.2, "The cgroup") is exercised
  in every run: its kernel test in `net-supervisor/tests/guard_integration.rs`
  finds a user-owned own cgroup, a user-owned parent and a user-owned
  sibling. A step that fails leaves the suites in the unit's root-owned
  cgroup and says so on the console; that test then skips, which
  `rust.kernel`'s strict skips refuse. **Never `cpu`** (neither in the
  unit's `Delegate=`, which would make systemd switch it on in the root
  cgroup and `system.slice`, nor below it): a cgroup with `cpu` on is a
  cpu task group of its own, and the kernel applies autogroups (each
  session one fair share; `sched_autogroup_enabled` is 1 in the guest) only
  in the root task group. With `cpu` on (2026-10-21, image
  `mandu-ci-111e5ca9…`) every suite's processes shared one per-task pool:
  a single-threaded TUI agent got a per-task slice beside the cargo builds
  (a CPU-bound task beside 12 busy ones on 4 vCPUs took 3.2× its idle
  time, against 1.5× in the root task group), the first OpenClaw replay
  drill went from 43 s to 120-220 s and timed out at its 90 s composer
  wait, and a `nice -n 19` call starved (§11, both). `boot.sh` says on the
  console which cpu task group the suites are in (`cpu:`); `cpu.max` is
  then absent from the suites' cgroup, which the guard's test lists only
  where it exists.
- The guest sets `kernel.apparmor_restrict_unprivileged_userns=0` (and the
  26.04 guest also disables `bwrap-userns-restrict`, §4.1), so the kernel
  lane's plain `unshare --user` and bwrap work as on an unrestricted host. The
  restricted posture a stock 24.04 user has (Mandu's granted bwrap after
  `mandu setup`) is the `install` kind's subject (`fresh-install` on
  `ubuntu-2404`), not the per-push gate's.
- It also allows unprivileged ports from 80 and sends the maintainers' demo
  drills' named hosts to a live run's sink (`/etc/hosts`, a TEST-NET
  address redirected to `127.0.0.2`), so Claude Code's own protections can
  be measured beside Mandu in the guest (§9.9).
- 32 vCPUs and 64 GiB by default (`MANDU_CI_VCPUS`, `MANDU_CI_MEM`).

## 4. The image

`scripts/ci/vm-image.sh` builds it; `scripts/ci/vm-run.sh` calls it when the
image it needs is missing. The provisioning boot's disk is `cache=unsafe` as
well (§3), and the image is flushed once (`sync -d`, an `fdatasync` of that
one file) after a good boot and before it is renamed into the cache, so a
published image is on disk even if the host then crashes; a failed build's
disk is deleted unflushed. Not a bare `sync FILE`: the uutils `sync` waits
for the whole filesystem's dirty pages, which on a busy host held the build
lock for many minutes.

- **Base:** the Ubuntu 24.04 cloud image of a **dated** release
  (`UBUNTU_CLOUD_RELEASE` in `pins.env`, immutable), cached under
  `<cache>/base/`, checked against that release's `SHA256SUMS`. Ubuntu
  removes dated releases after some months; the download then fails with a
  message to bump the pin.
- **Provisioning** (one boot with network, `scripts/ci/guest/provision.sh`
  through a cloud-init `runcmd` that unpacks the provisioning input disk, the
  tree the image is built from): apt packages, from the pinned mirror
  `UBUNTU_APT_MIRROR` in place of `archive.ubuntu.com` and
  `security.ubuntu.com` (a speed choice: apt still checks every package
  against Ubuntu's signed Release files, and a sources layout the rewrite does
  not match fails the build rather than fall back) (build-essential, git,
  bubblewrap, tmux, util-linux `script`, openssl, python3, netcat-openbsd,
  curl, bzip2, uidmap, slirp4netns, pkg-config, jq, iproute2, nftables; the aarch64
  cross toolchain `gcc-aarch64-linux-gnu`, `libc6-dev-arm64-cross` and
  `qemu-user` for the arm64 native bins; meson, ninja and libcap-dev to build
  bubblewrap; socat and ripgrep, which Claude Code's own sandbox needs, §9.9,
  and which `launcher.secret-readers-live`'s socket step (4c) drives as a
  listed relay; mksh (with lksh), yash and luajit, the interpreter families
  that suite's step (6g) copies, renames and pins to prove the guard knows
  them by content, each checked to run (without one the step skips; with
  none it never ran in any lane until 2026-10-17); golang-go (the distro's
  Go: 1.22 on 24.04, 1.26 on 26.04), which the Go leg of the sibling refusal's tests
  (`clone_filter_integration`'s (c), `wrap-clone-filter`'s Go case,
  exec-routing.md §7.5 gap (d)) builds its probe with, checked to run
  (without it the leg skips, and `rust.kernel` allows one skip only);
  python3-venv and unzip for
  the third-party baselines, §9.10), node at the pinned version (the nodejs.org tarball, checked
  against its `SHASUMS256.txt`), **bubblewrap `BWRAP_VERSION` from source**
  (sha256-pinned) into `/usr/local/lib/mandu-ci/bwrap`, off the PATH (§5
  says why), **git `GIT_REFTABLE_VERSION` from source** (2026-10-21;
  kernel.org's release tarball, sha256-pinned, built without gettext,
  Tcl/Tk, Perl, Python, curl or expat against `zlib1g-dev`, checked to make
  a reftable repository) into `/usr/local/lib/mandu-ci/git`, off the PATH
  too: 24.04's git is 2.43 and a reftable repository needs 2.45, so the
  reftable tests (`launcher/test/unit/prefetch-reftable.test.ts`,
  `launcher/test/component/prefetch-reftable-worktree.test.ts`) skipped in
  CI; now they put it first on their own process's PATH
  (`launcher/test/lib/reftable-git.ts`, which `scripts/test/ci-pins.test.mjs`
  holds to the same path) and run, while every other suite and the product
  under test keep the distro's git, the pinned agent CLIs installed globally (`claude`, `codex`, `opencode` and
  `openclaw` from npm; `goose` from its release tarball, sha256-pinned, by
  provision.sh's `install_release_bin`, the pattern for the next agent shipped
  as one binary), each checked to **run** (`--version`), not
  only to be on PATH, since a CLI that installs but refuses to start would
  make its suite skip to green (`openclaw` needs a newer node than Mandu's
  floor, so it gets its own, `AGENT_NODE_VERSION`, under `/opt/agent-node`
  behind a wrapper; Mandu itself stays on `NODE_VERSION`, its documented
  minimum), the `ci` user with rust at the pinned version plus the
  `aarch64-unknown-linux-gnu` target, a system git identity, the guest unit,
  the sysctl, and a quiet boot (no getty on the serial console, no network
  wait, no apt/motd/fstrim timers, no snapd or unattended-upgrades,
  cloud-init disabled after this boot).
- **The provisioning boot cannot reach the host.** It is the one boot with a
  network, and the code it runs (provision.sh, every npm lifecycle script)
  comes from the tree under test, so a merge request that changes a lockfile
  gets it. QEMU's own user-mode network maps the guest's `10.0.2.2` to the
  host's loopback, where a live stack's arbiter, dashboard and Ollama listen.
  So qemu runs in its own user and network namespace (a bwrap that can create
  one: on Ubuntu 24.04 Mandu's granted copy) joined to `slirp4netns
  --disable-host-loopback`, with a resolver pointed at slirp4netns's DNS: the
  guest reaches the internet and nothing on the host's loopback.
  `MANDU_CI_PROVISION_NET=plain` builds without that where it is impossible;
  without either, vm-image.sh refuses.
- **Warm dependencies:** provisioning copies the tree into `/work/mandu`,
  stamps every source file with one fixed mtime and records each file's
  sha256, runs `npm ci` in every package (and writes
  `node_modules/.mandu-ci-lock`, the lockfile's sha256), `cargo fetch`,
  `cargo build --tests` at default features and with `--features kernel`,
  and `scripts/build-native.sh`, then deletes every source file and keeps
  only the dependency directories (`**/node_modules`, `interceptors/target`,
  `~/.cargo`, `~/.rustup`, `~/.npm`). A run unpacks its own commit into the
  same path, so the dependencies and the cargo fingerprints (which hold
  absolute paths) match, and a deleted source file cannot survive into a
  run. **Mtimes:** a run unpacks with the extraction time as every file's
  mtime, then gives each file whose content equals the image's recorded one
  the fixed mtime back. Cargo's fingerprints of the workspace's own crates
  compare mtimes, so it rebuilds exactly the crates whose sources changed;
  unpacking with the commit's own mtimes (`git archive` stamps the commit
  time) would have made an edit older than the image's build look fresh.
- **Pins in one file:** `scripts/ci/pins.env` (node, rust, the npm agent CLIs' versions, each
  release-binary agent's version and tarball sha256 (`GOOSE_VERSION`,
  `GOOSE_SHA256`), OpenCode 2 (`OPENCODE2_VERSION`: the guest installs it
  under `/opt/opencode2` and links only `opencode2` onto PATH, so `opencode`
  stays the 1.x pin and the real-binary OpenCode 2 tests run instead of
  skipping; the hand-run docker rig does not carry it), the base image's release, the sandbox's bubblewrap and its
  sha256). `packaging/docker/Dockerfile.ci` keeps its own `ARG` defaults for
  the hand-run docker rig; a unit test (`scripts/test/ci-pins.test.mjs`)
  asserts they equal `pins.env` (each release-binary agent installed, sha-checked
  and run by both), and that `.github/workflows/ci.yml` tests at
  the same node and rust.
- **The image key** is a hash of `pins.env`, `vm-image.sh`, everything under
  `scripts/ci/guest/`, every `package-lock.json` outside `node_modules/`, and
  `interceptors/Cargo.lock`: the first 16 hex digits of a sha256 over their
  `path, git blob id` lines, so a work tree whose key files equal a commit's
  has that commit's key (`vm-image.sh --key [--commit REV | --worktree]`
  prints it). An image is `mandu-ci-<key>.qcow2` in the path table's
  `ci-cache` (`${MANDU_HOME:-~/.mandu}/cache/ci`). A commit that changes a
  lockfile or a pin gets a new image built for it; a source-only change
  reuses the cached one. The newest three images by last use (vm-run.sh
  touches the one it boots) are kept, older ones pruned, never one a run
  holds (a shared `flock`).
- **The guest re-checks.** If a package's lockfile differs from the one its
  baked `node_modules` came from (the `.mandu-ci-lock` stamp), the pipeline
  runs `npm ci --offline` from the baked cache, and ends the run as `error`,
  reason `image stale: <package> …`, when that is not enough. It never
  reaches the network to fix it.
- **Measured** (16 vCPUs for the build): the image takes about 5 to 6
  minutes from download to poweroff (apt about half of it with the default
  archive, much less with the mirror) and is 6.7 GB on disk; a source-only
  run's build stage then takes about 1 s (npm current, cargo fresh).
- **The agent pins track the tested ranges.** `CLAUDE_CODE_VERSION` and
  `CODEX_VERSION` sit inside the ranges `launcher/src/agent-versions.ts`
  states, and the PATH `codex` is not older than the one the agent-SDK
  fixture's `@openai/codex-sdk` installs (`ci-pins.test.mjs` fails
  otherwise): every per-push replay drill runs these binaries, so a pin at
  the floor tests a version users no longer run. Bumped 2026-10-09 from
  2.1.273 and 0.144.1 to 2.1.295 and 0.162.0, the ranges' tops; on Codex
  that moves the differential lane's prompted posture from `untrusted` to
  `on-request` and drops the early-output fold
  (`differential-interactive.md` §34.1).

### 4.1 The Linux 7.0 guest (built 2026-09-30)

**Why.** The per-push guest runs Linux 6.8, so the kernel lane proves the
unprivileged attachments on 6.8 only. A 7.0-only bug was invisible to CI: the
guard's worker thread's `pidfd_open` answers `ENOENT` on 7.0 where 6.8
answered `EINVAL`, which the guard did not handle (found on a developer's 7.0
host, not by CI). Ubuntu 26.04 (kernel 7.0) is a supported install target
([`os-test-matrix.md`](./os-test-matrix.md) §10.9 item 3), and the `install`
matrix's 26.04 guest does not close this gap: it runs
`scripts/kernel-tests.sh` on a stock, AppArmor-restricted 26.04, where the
userns entries SKIP by design (os-test-matrix.md §4), and only on tags.

**What.** `vm-run.sh --guest ubuntu-2604` (and `vm-image.sh --guest
ubuntu-2604`) boots an image built from the Ubuntu 26.04 ("resolute") cloud
image instead of 24.04's; the default guest, `ubuntu-2404`, is unchanged.

- **Pins:** `UBUNTU_2604_CLOUD_BASE`, `UBUNTU_2604_CLOUD_RELEASE` (a dated,
  immutable release) and `UBUNTU_2604_CLOUD_IMAGE` in `pins.env`, beside
  24.04's `UBUNTU_CLOUD_*` (`lib.sh` `ci_pins_prefix`). Everything else is the
  same: the same `provision.sh`, node, rust, the four CLIs, the sandbox's
  bubblewrap, the apt mirror, the sysctl that lifts the AppArmor userns
  restriction (§3), so the kernel lane runs as on the 24.04 guest and a
  difference is the kernel's.
- **The second restriction.** On 26.04 the sysctl is not enough: the
  distro's `bwrap-userns-restrict` AppArmor profile is attached to
  `/usr/bin/bwrap` whatever the sysctl says, and moves what a bwrap sandbox
  runs into `unpriv_bwrap`, which may not create a user namespace. A bwrap
  inside a bwrap then fails ("No permissions to create a new namespace"),
  which is the whole-agent wrap around the exec box and the guard's
  pid-namespace tests. `provision.sh` disables that profile the documented
  way (a link in `/etc/apparmor.d/disable`; 24.04 has no such profile, so its
  image is unchanged). The restricted posture a stock 26.04 user has (the
  launcher's nesting probe, guard-only twins, Mandu's own bwrap after `mandu
  setup`) stays the `install` matrix's subject, as 24.04's does (§3).
- **Key and name:** the key hashes the guest's name as well (for a guest
  other than the default, so 24.04's keys are what they were), and the image
  is `mandu-ci-ubuntu-2604-<key>.qcow2`. The name reaches `job.env`
  (`MANDU_CI_IMAGE`) and the run's `summary.json` (`image`), so the dashboard
  and the job's artifact say which guest ran.
- **Pruning** is per guest: the newest three images of each (`lib.sh`
  `ci_image_glob`), so a 26.04 build never evicts a per-push 24.04 image, nor
  the other way round. The base image's `SHA256SUMS` is cached under the
  image's name and release, since the two releases' dates can coincide.
- **Cost:** a second image (7.5 GB on disk, one provisioning boot of 3.5 to
  5 minutes per key change), built the first time a 26.04 run needs it; the
  kernel lane itself is ~50 s from `vm-run.sh` to results on 16 vCPUs.

**Where it runs: nightly and on `v*` tags, not per merge request** (the job
`kernel-linux-7`, §7). A second job per merge request would double the
per-request cost, and add a second image build on every lockfile or pin
change, for one lane whose only difference is the kernel. A kernel-version
difference is rare: it takes a change to the code that talks to the kernel
(the guard, the supervisors, the launcher's wraps) meeting a behavior 6.8 and
7.0 do not share, so one run a night finds it within a day, and a release
cannot ship without it. If such regressions turn out to land often, the step
up is a per-request rule on the same job (a ~50 s run). The job is the
per-push boundary (no network, no credential, `--kind sandbox,replay-drill
--need kernel`: the kernel lane), **not** `allow_failure`: its reds are code
bugs on 7.0, so a red fails the scheduled pipeline, and on a tag
the release waits for it (packaging.md §11.3). By hand, before merging a change to the guard,
the supervisors or the launcher's kernel paths:

```sh
scripts/ci/vm-run.sh --guest ubuntu-2604 --kind sandbox,replay-drill --need kernel --worktree
```

Rejected: a 26.04 job per merge request (the cost above); making 26.04 the
per-push guest (6.8 is Ubuntu 24.04's, the product's main target, and would
then go unproven); the full per-push run on 26.04 nightly (the entries
without the `kernel` need do not touch the kernel; a 26.04 userland
difference is the `install` matrix's subject).

**First runs** (16 vCPUs, the same tree on both guests). With the sysctl
alone, 26.04 failed four entries, all of them the nested-bwrap denial above,
not the kernel; with the profile disabled it matched 24.04 (716 passed, 0
failed, the same one structural skip). With the `ENOENT` fix reverted, the
26.04 run failed two guard tests (`tracee_fd_copies_a_worker_threads_descriptor`,
`guard_supervises_an_allowed_connect_from_a_worker_thread`) and 24.04 none:
the job catches the bug it was built for, which the per-push guest cannot.
The guard's namespace tests that fail on a developer host without the
AppArmor grant pass by name on 7.0 in the guest, whose lifted restrictions
are what the grant gives a host.

## 5. The run inside the guest

`scripts/ci/pipeline.sh` is the one entry point, in the guest and on a
developer's host (§8):

1. **Build once:** `npm ci` where needed, `cargo build --tests` (default and
   `kernel` features), `scripts/build-native.sh`, into `logs/build.log`. A
   build failure ends the run as `fail`, with the build log as the only
   result: one entry `build` (kind `build`) whose log it is, since the
   schema gives a stage no log (§6).
2. **The parallel stage:** every per-push entry of the manifest that does not
   need `kernel` (`tests/suites.mjs`, `test-organization.md` §5), run by
   `scripts/run-suites.mjs` with a concurrency limit (`MANDU_CI_JOBS`,
   default half the vCPUs), **each entry in its own sandbox**
   (`scripts/ci/ns-run.sh`, below). An entry marked `parallel: false` runs
   alone after the others (and after the kernel lane).
3. **The kernel entries,** in the same queue as the parallel stage (§5.2,
   §5.4): kernel entries run as `ci` directly in the guest (the guest is
   their sandbox), because they create their own namespaces. The ones marked
   `parallel: true` (their own temp dirs, kernel-assigned ports, a private
   arbiter) run up to `--kernel-jobs` at a time (`pipeline.sh` default 3,
   `MANDU_CI_KERNEL_JOBS`); one marked `parallel: false` would start only
   when no other kernel entry runs or waits (since 2026-10-12 every kernel
   entry is `parallel: true`, §5.4). Nothing in the
   parallel stage can meet a kernel entry on a port, a process or a private
   path: each of those entries has its own network, PID and IPC namespaces,
   `$HOME`, `/tmp` and overlay of the tree. The one thing both lanes see is
   the tree itself (the overlay's lower layer), which the kernel entries only
   read: `rust.kernel`'s cargo finds the build stage's `--features kernel`
   output current and compiles nothing. Their pass and skip counts are
   compared against the manifest's expected counts: a kernel entry that
   skipped what it should have run fails. A kernel wedge also loses the
   parallel entries still running; each entry's timeout and the guest's hard
   timeout bound it, and every result already written survives.
4. **Results:** `summary.json`, `junit.xml`, `logs/<entry>.log` into the
   output directory.

Every entry runs to the end whatever the others did: one early failure does
not hide the rest. Each has the manifest's timeout.

**`scripts/ci/ns-run.sh`** runs one command in a sandbox (bubblewrap): new
user, PID, IPC, UTS and network namespaces (loopback only); `--ro-bind / /`;
the checkout as a private overlay (`--overlay-src /work/mandu --tmp-overlay
/work/mandu`), so an entry's writes into the tree are its own and vanish with
it; a fresh tmpfs over `$HOME` (at the same path, so `HOME` keeps its value;
the account's passwd home too when it differs), `/tmp`, `/dev/shm` and the
host's `/run/user/<uid>`, and `XDG_RUNTIME_DIR` a fresh directory; a
container daemon's socket, if any, covered by `/dev/null`; `--clearenv` with
an explicit allow-list (`PATH`, `LANG`, `TERM`, `HOME`, `USER`, `LOGNAME`,
`TMPDIR`, `XDG_RUNTIME_DIR`, the manifest's `env` as `--setenv` pairs,
`MANDU_AXES_STRICT`, `MANDU_POLICY_FILE`, `RUSTUP_HOME` and `CARGO_HOME` when
set, and the names in `MANDU_CI_PASSENV`, which the guest sets to the CLIs'
no-self-update switches and `CARGO_NET_OFFLINE`); a fixed git identity
(`GIT_CONFIG_GLOBAL`, a file in the sandbox's `/tmp`), since git refuses to
commit without one and the real `~/.gitconfig` is hidden; `--die-with-parent
--new-session`. The toolchain directories that live under `$HOME` (the
`PATH` entries there, `~/.cargo`, `~/.rustup`) come back as private
overlays. Nothing of the host is writable except each `--bind-rw DIR` (for a
replay drill's records, §6): bound read-write at its own path, mounted last
over the tmpfs and the overlays, and refused (exit 125, before anything runs)
unless it is an absolute canonical path with no symlink in it, an existing
**empty** directory this user owns (the box gets a fresh place to write,
never a view of host files), not under `/proc`, `/sys` or `/dev`, and neither
`/`, the checkout, `$HOME`, the account's home nor the runtime dir, nor an
ancestor of any of them; two may not nest. A hard link from outside into it
cannot be made (another mount, `EXDEV`), so the box cannot hand the host a
file it could only read; what it leaves there (a symlink, a fifo) is the
reader's to refuse (§6). Two entries in parallel therefore cannot collide on
a port, a socket, a `$HOME` file or a process. The hazards
`test-organization.md` §8.4 lists become harmless inside it. Its exit status
is the command's, or 125 when the sandbox cannot be set up. It returns only
once the box is gone (2026-10-18): bwrap returns as soon as the command
exits, while the box's init (pid 1 inside, its own session outside) still
kills and waits for what the command left and releases the box, which under
load took seconds and made the runner count it as a stray, nameless (`(?)`,
test-organization.md §8.5 "A box still ending"). So ns-run stays bwrap's
parent, reads the init's pid from `--info-fd` and waits for it to end (at
most `NS_RUN_END_S`, 30 s).

- **Which bubblewrap.** `--overlay-src`/`--tmp-overlay` arrived in
  bubblewrap **0.10**; Ubuntu 24.04 ships 0.9.0 (so does Mandu's granted
  copy). The image therefore builds `BWRAP_VERSION` (0.11.0) from source into
  `/usr/local/lib/mandu-ci/bwrap`, off the PATH, and the guest points
  `MANDU_CI_BWRAP` at it: the product under test keeps the distro's
  `/usr/bin/bwrap`, as a user's machine has. Without `MANDU_CI_BWRAP`,
  ns-run tries `bwrap` from the PATH, then `/usr/lib/mandu/bin/bwrap`, and
  takes the first that can create a user namespace here and lets a bwrap
  inside its sandbox create one too (§5.6), else the first that can create
  one at all; probed, not guessed. `ns-run.sh --check` prints the choice,
  its overlay support and whether a bwrap nests in it, and runs nothing.
- **Without overlay support ns-run refuses** (exit 125): it never binds the
  checkout read-write. `--tree copy` (or `MANDU_CI_TREE=copy`) is the
  explicit fallback for such a host: a per-run copy of the checkout without
  `node_modules/` and `.git/`, bound read-write, with every `node_modules/`
  bound back read-only (a suite that writes into one fails with `EROFS`),
  removed afterwards; about 2.5 s per entry on a checkout with a 230 MB
  `target/`. `--tree auto` takes overlay when it can, else the copy, and
  says so; `pipeline.sh --host` uses it.
- `scripts/test/ci-ns-run.test.sh` (kind `sandbox`, need `kernel`,
  `ci.maxSkip 0`) proves the isolation for real in both modes: an empty
  `$HOME` whose files are unreadable, only `lo`, no host process, no host
  `/tmp` file, no host loopback port, the environment cleared to the
  allow-list, a write to the checkout that never reaches the host's tree,
  two sandboxes binding the same port at once, and each refusal; `--bind-rw`
  (a write into the dir reaches the host, one beside it, into its parent or
  into the checkout does not, no hard link into it from outside, a dir under
  the hidden home comes back alone) and each of its refusals; and nesting
  (§5.6): `--check`'s answer is what a real bwrap inside the box finds, a box
  that cannot nest says so, and the auto-pick passes over a bwrap whose
  sandbox cannot nest for one whose can; and the end of the box: with a
  256 MiB process left behind, ns-run returns only once the box's init is
  gone, in both modes, where bare bwrap (the control) returns while it is
  still ending. The guest's `--selftest` runs it
  too, and its `selftest.probe` log records `ns-run.sh --check`.

**Two other modes** of `pipeline.sh`, for the plumbing and the release jobs:

- `--selftest` skips the build and the suites and writes its own summary:
  an entry `selftest.probe` (the guest's facts in its log) and, in the guest,
  `selftest.ns-run` (the test above on the guest's own bubblewrap).
- `--exec 'COMMAND'` runs after the build, instead of the suites: `bash -c
  COMMAND` as `ci` in `/work/mandu`, unsandboxed, as one entry `exec` (its
  exit status decides the result); whatever it leaves under `release/`
  (regular files and directories only) comes back under
  `artifacts/release/` of the results. No network, as for every run.

**Time.** A run costs the boot, the build and the longest entry, instead of
the sum of the entries; `summary.json` records every entry's duration, so the
numbers below come from runs, not estimates.

### 5.1 Where a push's time goes

The first all-green full run (32 vCPUs, 16 jobs, 89 entries, 6,872 tests)
took **495 s** from `vm-run.sh` to results: boot and unpack ~8 s, build 3 s,
the parallel stage ~300 s, the kernel stage ~171 s (one entry at a time,
after the parallel stage), power off and collect ~8 s. Two things bounded
it: one test file (`launcher/test/component/run.test.ts`, 293 s, whose mock
arbiter accepted every request and never answered, so each launch waited out
seven 3 s reads; six more launcher files had the same mock), and the serial
kernel stage behind the parallel one.

After the speedup (§5.2), the same tiers on the same image:

| Guest | Wall, `vm-run.sh` to results | Busy cores (qemu CPU ÷ wall) | CPU-seconds per run |
|---|---|---|---|
| 32 vCPUs, 16 jobs | **142 to 155 s** | ~21 | ~3,000 to 3,200 |
| 16 vCPUs, 8 jobs | 216 s | ~11 | ~2,300 |
| 8 vCPUs, 4 jobs | 357 s | ~6 | ~2,100 |
| two 16-vCPU guests at once | 236 to 246 s each | ~11 each | ~2,700 to 2,800 each |

The work is about 2,100 CPU-seconds; the rest is contention, which grows with
the guest (every `node --test` entry runs its files up to the vCPU count at
once, so 16 entries side by side oversubscribe the guest). The longest
entries now bound the run.

A push that changes Rust (measured by touching `mandu-arbiter`, which most
crates depend on) adds **14 s** of build; the image's warm `target/` already
covers it. A push that changes a lockfile, `pins.env` or
`scripts/ci/guest/**` first builds a new image: 5 to 6 minutes, once per such
change.

### 5.2 The speedup (built 2026-09-29)

| Step | Change | Effect |
|---|---|---|
| 1 | **The launcher's silent mock arbiter answers** (`launcher/test/lib/unanswered-arbiter.ts`): every request gets `{id, ok: false}` with no error text, which each launch-time reader treats exactly as no answer (an error text would make the bind `refused`, `unknown op` would make the model reads `unsupported`), without the 3 s wait. | `run.test.ts` 289 s → 26 s; the launcher e2e shards no longer wait |
| 2 | **The kernel lane runs beside the parallel stage** (`run-suites.mjs`, under `--sandbox` only: the sandbox is what keeps a kernel entry and a sandboxed one apart, §5 step 3). Without `--sandbox` (`test-all.sh`) the order is unchanged. | the kernel tier's time hides under the parallel stage |
| 3 | **Independent kernel entries run three at a time** (`--kernel-jobs`), longest first; `parallel: true` on every kernel entry but `net-guard-live`. | the kernel lane is bounded by its longest entry |

The denser schedule brought out tests that raced the clock under load, all
test bugs (§11). What this does **not** do: add more guests per pipeline
(the build is shared, a second guest would repeat it), cache results between
pushes (a red must always be a run of this commit), or drop suites from the
per-push run.

### 5.3 Guest size and concurrent pipelines

32 vCPUs buys the shortest single run (~150 s against ~216 s at 16), at about
40% more CPU-seconds for the same work. Two 16-vCPU guests at once each take
~245 s, so two pipelines that arrive together are both done in ~245 s,
against ~285 s back to back at 32 vCPUs. Nothing in the VM layer prevents
concurrent runs: each has its own work directory and overlay, image builds
serialize on `.build.lock`, a booted image is held by a shared `flock` that
pruning respects, and run ids are unique. How many run at once is the
runner's concurrency; the guest size is `MANDU_CI_VCPUS` in the runner's
environment. The maintainers' runners use 16-vCPU guests, so several
pipelines run side by side and a shared host keeps cores for its other
users; `vm-run.sh` keeps 32 vCPUs as its default for a run by hand.

### 5.4 One queue, longest first (built 2026-09-29)

On a 16-vCPU guest a push still spent ~213 s in its suites after §5.2.
Replaying that run's durations through the scheduler reproduced the 213 s
and showed where it went: the kernel lane's three slots idled from 118 s on,
and the parallel pool ran in manifest order, so the ~70 s `differential`
shards started last and made a ~70 s tail. The guest was at 16 of 16 cores
until the tail: the run is CPU-bound, and a better order can only close the
tail. Built:

| Change | Effect (16 vCPUs) |
|---|---|
| **One queue over `--jobs` + `--kernel-jobs` slots** (`run-suites.mjs`, under `--sandbox`): at most `--kernel-jobs` kernel entries at once, a non-`parallel` kernel entry only when no other kernel entry runs or waits; a slot the kernel entries do not need runs the others. | the kernel lane's idle slots do work |
| **Longest first** by the cost table `tests/suite-costs.json` (seconds by entry id, each entry's median over the last ten green full runs; `node scripts/suites.mjs costs <runs dir>` regenerates it, `costs <summary.json>` from one run). A CI run orders by its host's own medians over it (below). It names only the public manifest's entries; the private manifest's are timed in a table of their own beside it (`costs --private`), so the public snapshot's table names no entry the snapshot lacks (§12). The table only orders the queue; an entry it does not know costs 30 s, and a manifest `queueAs` (seconds) overrides it for that entry (test-reorganization.md §6.9). | the long entries start at 0 s, not at 140 s |
| **`launcher/test/component/services.test.ts` answers its mock arbiter** (`unanswered-arbiter.ts`'s `unavailableReply`), as `run.test.ts` did (§5.1). | 93 s → 6 s on a host |
| **The dashboard's jsdom windows close at the end of the file** (`control-js-fixtures.ts`): a test's armed Restart kept its successor poll alive 45 s after the last assertion. | that file 50 s → 3 s |
| **`launcher-fixture-homes` runs as three shards** (`MANDU_FIXTURE_SHARD=k/3`, `tests/lib/shard.ts`; the cases outside a shard are not registered, so `ci.maxSkip: 0` holds). | 114 s → three of 41 to 52 s |

Since the guest is saturated, the next seconds come from doing less work, not
from ordering it better. Three cuts of tests that repeated another's
coverage were made, none of them a security or fail-closed assertion that
nothing else makes:

- the `integration.differential.two-turn-prose` shard (long-session's first
  three turns are the same prose turns; differential-interactive.md §8);
- `arbiter/test/component/integrity-freeze-gate.test.ts`, five daemon starts
  one after another: its two checks nothing else made (a refused start
  registers nothing, in instance and pinned mode; hello reports the axis
  asked for) moved into the parallel daemon cases of
  `tests/stack/protection-modes.test.ts`;
- `launcher/test/component/subcommand-help.test.ts` spawns the real CLI three
  times instead of twelve; the per-verb `--help` dispatch is a unit test.

With all of the above: **139 s of suites, 168 s from `vm-run.sh` to
results** on 16 vCPUs (against ~250 s), 6,893 tests green. Candidates left
undecided: the 160×40 differential cells with no width-dependent behavior,
the dashboard's nine cold server starts, `typecheck.conformance` re-checking
other packages' files.

**Costs that stay fresh (2026-10-12).** By October the suites took ~630 s
(the last 30 full per-push runs) for ~4,290 s of work over 11 slots
(~390 s). Replaying those runs' durations through the scheduler
reproduced each within 2 s and found the queue order, not the work: the
table had no row for `integration.kernel` (259 s) and
`integration.opencode-project-plugins` (293 s), so they cost the default
30 s, and `rust.kernel` (168 s) was costed 11.7 s, so the three started at
~180, ~200 and ~430 s and the last ~230 s ran one or two entries.
`integration.replay-push-kernel`, the only kernel entry left `parallel:
false`, could start only after every other kernel entry and always ran
last. Changed:

| Change | Effect (16 vCPUs) |
|---|---|
| **The CI host measures the costs.** `vm-run.sh` computes each entry's median duration over its host's last ten green full runs in `ci-runs` (`ci_append_costs`: `suites.mjs costs --all --last 10`; a full run is one with at least 90% of the largest green run's entries, so the docs lane, `--only` runs, the nightly and the Linux 7.0 kernel job are left out) and brings them in the input disk as `.mandu-ci/suite-costs.json`; `pipeline.sh` passes them as `run-suites --costs`, which lays them over the checked-in tables (an entry they do not name, such as a new shard, keeps its table cost). Only a per-push run (not the nightly, `--exec`, `--shell`, `--selftest`); `MANDU_CI_NO_MEASURED_COSTS=1` turns it off. A host with no such run (a fresh runner) and the public CI (§12), which runs `run-suites.mjs` without `vm-run.sh`, order by the tables, which `costs <runs dir>` regenerates the same way. A failure to measure only logs: the order never decides whether an entry runs or how it is judged. | a new or slower entry starts in time without anyone regenerating the tables |
| **`integration.replay-push-kernel` is `parallel: true`**: like `launcher-kernel-tier` its replays run in their own temp workspace and HOME, with a private arbiter, a fresh scope id and reserved or kernel-assigned ports; `false` had no recorded reason. Green in all 16 measured runs below. | it starts in its cost order beside the other kernel entries |
| **`placeholder-commit-warning`'s killed launches release their agent** (W3, W6): the agent's `sleep 120` outlived the SIGKILLed launcher's process group and held its output pipes, so each test waited the full 120 s. The agent now waits on a release file the test writes once the launcher is dead. | `integration.kernel` 260 s → ~87 s |
| **`integration.opencode-project-plugins` runs as three shards** (`MANDU_OPENCODE_PLUGINS_SHARD=k/3`, `tests/lib/shard.ts` `shardPicker` over the registration order), an OpenCode 1 control (~78 s each) in each. | 293 s → three of ~113 to 129 s |

Measured with `vm-run.sh --worktree` on the maintainers' runner host (16
vCPUs, `--jobs 8`), one guest at a time beside the runner's own pipelines,
suites stage in seconds:

| Configuration | Runs | Suites stage |
|---|---|---|
| before: the stale tables, `--kernel-jobs 3` (GitLab, the last 30 full runs) | 30 | ~630 (578 to 684) |
| measured costs, `replay-push-kernel` parallel, `--kernel-jobs 3` | 1 | 416 |
| ... and the `placeholder-commit-warning` fix | 1 | 417 |
| ... and the `opencode-project-plugins` shards (this change) | 3 | 404, 412, 413 |
| the same, `--kernel-jobs 4` | 3 | 445 (red), 417 (red), 381 |
| the same, `--kernel-jobs 5` | 5 | 365, 360, 350, 354, 356 |

The guest is CPU-bound: each step that made more entries overlap made the
others slower (the run's summed durations grew from ~4,300 s at three
kernel jobs to ~4,600 to 5,000 s at five), so a wider kernel lane gains
less than the schedule alone predicts (a replay of the durations without
contention: ~337 s at five). The two red `--kernel-jobs 4` runs were each
one test that never failed in the 30 GitLab runs: `fresh-agents-fake-model`
read the fake model's port file while it was still empty (a race, fixed:
it waits for a port), and `agent-page-step-links` got the proxy's
fail-closed 502 when its arbiter call did not answer in time on the loaded
guest. `pipeline.sh` keeps three kernel jobs here; the wider lane is its
own decision with these numbers.

### 5.5 The docs lane (built 2026-09-29)

**Why.** About one change in five touches documentation only, yet ran all
~2,100 CPU-seconds of the tiers while other pipelines queued behind it.

**What.** In a merge-request pipeline the job first runs
`scripts/ci/lane.mjs` on the runner host (git and the manifest only; no
suite code runs outside the guest). When every path in the request's diff
(`git diff --no-renames <diff base>...<head>`) is documentation, it selects
the docs lane (`vm-run.sh --only <ids>`); when every code path is in a
declared scope, the scoped lane (§5.8); otherwise the per-push kinds. Every
push to `master` after a merge runs the per-push kinds, so a docs-only
change is still fully tested once it lands (or, when newer merges cancel
that run, by the hourly master check, §7.1).

- **Documentation** is `docs/**` and `*.md` anywhere, **except**
  `launcher/README.md` (it ships in the npm tarball, and `npm-pack.test.ts`
  compares it) and anything under a `fixtures/` directory (golden test data,
  e.g. arbiter's `handling-prompt-*.md`).
- **Fail-safe**: a git error, an unknown base, an empty diff, a rename out of
  code (`--no-renames` lists the deleted source path), a path outside the
  globs or a manifest with no docs-lane entry each selects the full run.
- **The lane** is the manifest entries with `docsLane: true`: the manifest
  check (`scripts.suites-manifest`: every `doc:` path exists, the
  `protection-modes.md §10` §5 canary list, the drill catalog) and four narrow
  `idOnly` re-runs of the files that read docs at run time:
  `arbiter.docs-sweep` (every tracked text file is free of the retired
  symbol spellings), `dashboard.context-pack` (the pack reads `docs/design`
  and `docs/testing`: present, indexed, under its size budget),
  `integration.user-docs` (README and `docs/*.md` links, anchors, required
  copy, the supported-agents table) and `launcher.docs` (every `docsUrl()`
  target exists; `licensing.md` is DECIDED). `idOnly` keeps them out of a
  kind run, where their parents run the same files.
- **Measured**: 46 s from `vm-run.sh` to results in an 8-vCPU guest (5
  entries, 46 tests), against ~210 s for the tiers.

**Keeping the lane complete.** A new test that reads docs at run time must
join one of the lane's entries, or the lane misses it until the next
`master` run. The manifest check enforces it (`node scripts/suites.mjs
check`, test-organization.md §5): it sweeps every test file a per-push entry
runs for run-time reads of the repository's docs and fails on one no
`docsLane` entry runs, unless the file carries a `docs-lane-exempt: <reason>`
comment. The sweep is a heuristic (a whole `docs/…` path literal, or a
repo-root name joined with `docs` or a `*.md` name, that the tree has). Two
more signals catch the readers it cannot see: a test that runs `git
ls-files` or `git grep` and names a repo root, and a test whose code names an
entry point that a docs-reading module declares in a `docs-reader:` comment
(the developer view's `context-pack.ts` names `buildContextPack` and
`/api/context-pack.md`). Following imports instead was rejected: every
dashboard server test reaches the context pack through `server.ts`, and
non-test code names docs in messages and comments, so the closure flagged
over a hundred files. A new module that reads docs for its caller adds the
marker, and the check makes it (2026-10-17, `unmarkedDocsReaders`): every
non-test module the same path heuristic sees reading the repository's docs
must carry a `docs-reader:` marker or a `docs-lane-exempt: <reason>` (one
that only writes docs, or names them as data), or the check fails with the
module's file and line. Before, such a module was invisible: the tests that
reach it name no docs path, and without its marker nothing named it. A link
to a doc (`docsUrl("docs/…")`) is not a read, and a mention of the
exemption's syntax (`docs-lane-exempt: <reason>`) is no exemption. `scripts.suites-manifest` asserts that every file the lane's
`idOnly` re-runs hold is one the sweep sees, so no lane member is kept by
hand.

### 5.6 A sandbox inside ns-run's sandbox

**The gap.** Mandu's git sandbox (write-protection.md §8.5) is a bubblewrap that
Mandu's own git calls run in, and in a sandboxed entry it starts inside
ns-run's bubblewrap. Ubuntu's AppArmor profile `bwrap-userns-restrict`
(loaded by default from 26.04, an extra on 24.04) runs what `/usr/bin/bwrap`
starts under `unpriv_bwrap`, which may not create a user namespace: a
bubblewrap inside a bubblewrap fails. On such a host the git sandbox's probe
finds nothing inside ns-run, the hardened git runs unsandboxed, and the
tests that need the sandbox SKIP. The CI guest disables that profile
(`scripts/ci/guest/provision.sh`), so those paths run only there. (The
kernel entries do not run in ns-run; on such a host they meet the same
restriction directly.)

**What ns-run does.**

- **It says so.** An ns-run whose bwrap cannot nest prints one line on
  stderr before the command runs (so at the top of each sandboxed entry's
  log): the git sandbox is off inside and its tests SKIP; the CI guest runs
  them (`scripts/ci/vm-run.sh`), or this host with Mandu's own bubblewrap.
  `pipeline.sh` says it once more before the suites, and `--selftest`'s
  probe log records `ns-run.sh --check`.
- **It matches the guest where it can.** Mandu's own bubblewrap
  (`/usr/lib/mandu/bin/bwrap`, installed by `mandu setup`;
  rootless-confinement-ubuntu-2404.md §12.5 option 2) runs under
  `mandu_bwrap`, whose children run bwrap back under `mandu_bwrap`: a sandbox
  nests in it. ns-run's auto-pick therefore takes the first candidate a
  sandbox nests in, so on a host where `mandu setup` has run, the git sandbox
  runs inside ns-run as in the guest. A nesting candidate without the overlay
  the tree asks for is passed over, so the choice never turns a working run
  into a refusal. (VM-verified for the launch's wrap, bwrap-grant.ts; for
  ns-run it follows from the same profile.)
- **The alternatives were rejected.** Disabling `bwrap-userns-restrict` on
  a developer's host, as the guest does, weakens every program on that host;
  a `local/unpriv_bwrap` include that allows `userns` has the same reach.
  Mandu's own copy is scoped to its path.

### 5.7 The suites doubled again, and three fixes (2026-10-18)

**What happened.** The suites stage went from ~395 s (2026-10-12 to 14, after
§5.4) to ~766 s (the 76 full runs of 2026-10-17 after 08:00 UTC), at the same
`--jobs 8 --kernel-jobs 3` on 16 vCPUs. Measured from 1,690 GitLab `test`
jobs' summaries and the host's sysstat, with the §5.4 scheduler model (it
reproduces each day's median within 1 s):

- **A serial tail.** `integration.demo-rehearsal` came `parallel: false` (no
  recorded reason) on 2026-10-16 and ran alone after the parallel stage:
  ~95 s, then ~165 s once demo-c7/c8/c9 took it from 8 sessions to 14.
- **More work.** The summed entry seconds grew from 4,019 to 6,324: 1,076 s
  of new entries (the dashboard split into three, the demo rehearsal and
  baselines, the MCP-timeout entries) and 1,228 s of the same tests running
  longer, mostly under contention (`arbiter` 112 → 256 s on about the same
  tests).
- **Host contention.** From 2026-10-16 the runner ran up to five 16-vCPU
  guests at once (its `concurrent = 5`), and local `vm-run.sh` runs (32
  vCPUs by default) came on top, on a host of 64 physical cores: at the
  same code, a run with the host 60 to 70% busy took ~150 s longer than one
  at 10 to 20%.
- The queue's order was otherwise right (ordering by each run's actual
  durations gives the same wall time); with no serial tail ~38 s were left
  over the area bound (summed seconds ÷ 11 slots), the last kernel entries
  draining three at a time while eight slots idled.

**The fixes.**

| Change | Model (76 runs) |
|---|---|
| `integration.demo-rehearsal` is `parallel: true`: each of its sessions has its own tmux server, Mandu home, workspace and ports, and in CI each entry its own namespaces, `$HOME` and `/tmp` (ns-run). Measured beside a run of its base at 16 vCPUs: 882 → 740 s. | 763 → 611 s |
| **The shared queue weights a kernel entry's cost by slots ÷ kernel jobs** (`scripts/suites.mjs` `sharedQueueOrder`, 11 ÷ 3 here), so the narrow lane's long entries start in the opening burst. Order only. | 611 → 573 s (the area bound) |
| **One CPU budget for every guest on the host** (`scripts/ci/lib.sh` `ci_take_cpu_slots`): `vm-run.sh` holds ceil(vCPUs ÷ 8) slots of the host's physical cores (64: eight slots, four 16-vCPU guests or two 32-vCPU ones) before it boots, the runner's jobs and runs by hand alike; a guest that finds no room waits (at most `MANDU_CI_SLOT_WAIT`, 1800 s, then boots anyway and says so). `MANDU_CI_HOST_VCPUS` sets the budget, `0` turns it off. A job then waits in the queue instead of slowing four others. | −50 to −150 s at busy times |

The one paired measurement of the first change also had the one red run of
`integration.replay-push.codex` in 103 on record (a replay TIMEOUT), with
two other guests and the runner's jobs on the host: the CPU budget is what
keeps the rehearsal's extra overlap from starving a replay, so the two
changes ship together.

Left (each a coverage decision, none a security or fail-closed assertion):
the 160×40 differential cells (~180 summed s), dashboard-dev's 95 stack
tests each booting their own stack (~100 s), the dashboard-dev budget tests
to the nightly (~110 s), demo-rehearsal's `baseline-none` sessions to the
demo lane (~70 s); and a wider `--jobs` or `--kernel-jobs`, to measure
(§5.4).

### 5.8 Scoped lanes (built 2026-10-18)

**Why.** After §5.7 the full run is ~8.5 min and throughput-bound: the
entries' summed seconds ÷ the 11 slots (5,396 ÷ 11 = 490 s) is the suites'
wall time, so only less work makes a run shorter. Of the last 106 merge
requests that changed code, 21 changed the drill suite's own machinery and
nothing else, and each ran the product's suites (the kernel lane, the
arbiter, the launcher) that such a change cannot reach.

**What.** A manifest may declare **scopes**, `{ id, owns(path), marks,
via, runs(entry) }` (`loadManifest` returns both manifests' `scopes`). When
every non-documentation path of a merge request's diff is owned by a scope,
`scripts/ci/lane.mjs` selects the **scoped lane**: of the per-push selection
(`selectEntries` over the five kinds), the entries that can reach a touched
scope, plus the docs lane's, as `vm-run.sh --only <ids>` (its stderr lists
the entries it skips). An entry reaches a scope when the scope's `runs` takes
it, or a file in its reach is owned by the scope, is one of its `via` files,
or holds one of its `marks`. Its **reach** is the files it runs (its claims,
test-organization.md §5) or, when it claims none (a `tsc -p`, a `cargo
test`), every file of its package, then transitively each script's relative
imports (a `.js` specifier finds its `.ts` source) and each shell script's
path-like words, comments left out. A master push runs everything, so a
change the scoped lane under-tests is fully tested once it lands (at the
latest by the hourly master check, §7.1, when newer merges cancel the
push's run).

- **Fail-safe**: a path in no scope, an entry that claims no file and runs
  at the repository root, a scope that throws, or a selection that keeps
  every entry is the full run. A relative import that resolves to nothing
  is not followed: it is a fixture's text (a source file held in a test's
  string), since a real one would not load.
- **Unlike §5.5's sweep** (where following imports flagged over a hundred
  files), a scope's marks are exact: what names the scope's own tree, not
  any doc path in a message.
- **The one scope** is the maintainers' drill machinery (the private
  manifest's): the drill suite's tree, its fixtures and its manifest. It
  runs every private entry, and the public entries whose reach names the
  drill-tree resolver (`scripts/drill-tree.mjs`), loads the manifest
  (`scripts/suites.mjs`, which loads the drill entries), or matches the
  export check's own drill rules. Those rules are why it is sound: the
  export leaves the tree out and its check, on every push, fails a public
  file that imports or names it, so a public entry reads the tree only
  through the resolver. The scope reads its marks from that denylist, so the
  two cannot drift.
- **Measured** on the real manifest (a drill-only diff): 108 of 231
  per-push entries run (3,266 summed s), 123 are skipped (2,079 s; among
  them `rust.kernel` 276 s, `integration` 256 s, `arbiter` 182 s, the three
  `opencode-project-plugins` shards 363 s): ~300 s of suites against ~490 s,
  the longest kept entry (`integration.demo-rehearsal`, ~227 s) under it.
  A scoped run is left out of the queue's cost learning, as a docs-lane run
  is (§5.4, `COSTS_FULL_SHARE`).

Rejected for now: a scope for the developer view (the launcher bundles it
and the drill machinery imports it, so nearly every entry reaches it) and
for the public dashboard or the Rust crates (the replay drills run the
whole stack). A new scope is worth it where a diff's paths are common and
few entries reach them.

## 6. Results: GitLab and the dashboard

**The results archive** (the output disk's tar) holds:

- `summary.json` (schema below);
- `junit.xml`, one `<testsuite>` per entry, so a merge request's test widget
  names the failing entry;
- `logs/<entry-id>.log`, each capped at 5 MiB (the tail kept), plus
  `logs/build.log`, the guest's `logs/pipeline.log`, `logs/drills.log`, and
  `logs/kernel-tests/{exec,net,fs}.log`: the kernel lane's full per-crate
  cargo logs, each its last 5 MiB (`scripts/kernel-tests.sh` keeps them where
  `MANDU_KERNEL_TESTS_LOG_DIR` says, which `pipeline.sh` sets);
- `artifacts/release/**` after `--exec` (the release jobs, §7);
- `drills/replay/**` and `drills/baselines/**`: the replay-drill entries'
  records and their plain-run baselines (below);
- `drills/live/<drill run>/<record file>`: the live-drill entries' run
  records, the nightly's drill runs, with each session's event log
  (`events-<session>.ndjson`, below).

Nothing else: the collector refuses any other path.

**The replay records** (test-reorganization.md §6.3, §7.3). `pipeline.sh`
runs the suites with `run-suites.mjs --replay-store $OUT/drills/replay
--replay-baselines $OUT/drills/baselines`. Every replay-drill entry then gets
`MANDU_REPLAY_STORE`, `MANDU_REPLAY_RUN_ID` (the run's id) and
`MANDU_REPLAY_BASELINES`; under `--sandbox` each entry has its own
`<dir>/<entry id>` for both, created empty and bound into its box with
ns-run's `--bind-rw`, its only writable host path, shared with no other entry
(a kernel-lane entry, unsandboxed, gets the same per-entry dirs; the
nightly's unsandboxed run shares one store, where the record's `run.json` is
created `O_EXCL` and the first shard wins). Without `--replay-store` (a local
`run-suites` or `test-all.sh`, unless given) the three are unset for every
entry, whatever the caller's environment holds: no record. After the suites,
`pipeline.sh` makes what the entries left fit the archive, since the
collector refuses a whole archive for one bad member and every other result
would go with it: anything but a regular file or a directory and any name
outside the collector's characters are removed, a hard-linked file becomes a
copy of its own, empty directories go, and past the caps below the whole of
`drills/` is dropped (the archive's other results are kept).
`logs/drills.log` says what it did and how full `drills/` came. The collector
checks all of it again: `drills/` is under the same archive rules and caps as
the rest.

**The live-drill records** (test-reorganization.md §8.1). Every drill entry
(`drill.*`, `drill-run.ts`) records its run (meta, chapters, report, the
terminal recordings, the pane captures, the seeds) into the watch store
run-suites names (`--watch-store`, test-organization.md §7.2). `pipeline.sh`
names a scratch store (`$TMP/live`, outside the results) and, after the
suites, copies from each run directory only the record files the dashboard
reads to `$OUT/drills/live/<drill run>/`: `meta.json`, `chapters.json`,
`report.json`, `matrix.json`, what the dashboard's file route serves
(`terminal-*.cast`, `run.log`, `report.md`, `*-<n>.pane.txt`,
`seed-*.json`), and two data files it does not (`wire.ndjson`, a
baseline's model-traffic log, and `compare.md`, the demo battery's
comparison, §9.9), each a regular file of at most 32 MiB. An entry that is
not a `drill.*` entry records there too when it says `watchStore: true`. A run directory also
holds what must never leave the guest: the drill workspaces, the owned
arbiter's work dir (its symbol DB), a private `CODEX_HOME`, the model
captures. None of it is copied, and anything else is left behind and named in
`logs/drills.log`.

**The event lanes** (built 2026-10-03). A drill entry runs against its own
arbiter (`drill-run.ts --own-arbiter`), which logs every session's events to
`<its work dir>/events/<session>.ndjson`: `<run dir>/arbiter/events`, or the
`<tmp>/mdu-a-XXXXXX/events` that `meta.json`'s `arbiter.eventDir` names when
that socket path would be too long (`drill-arbiter.ts ownArbiterWorkDir`).
That arbiter is discarded with the guest, so without its logs a CI live
session had its recording, chapters and verdicts and no event lanes.
`scripts/ci/live-events.mjs` (run by `collect_live` after the record files)
copies, for each copied run, the log of each session the run NAMES
(`meta.sessions`, the chapters' and report rows' `scopeId`) to
`$OUT/drills/live/<drill run>/events-<session>.ndjson`, and nothing else of
the work dir: not its symbol DB, its log, its policy copy, nor the log of a
session the run does not name. Each is a regular file read without following
a symlink, at most 32 MiB (the dashboard's per-log cap); all of them together
at most 96 MiB (`LIVE_EVENTS_MAX_BYTES`, `live-events.mjs EVENTS_MAX_BYTES`,
a test holds them equal), an explicit budget inside `drills/live`'s bytes so
the recordings keep room. Past it the largest logs are left behind first (so
the most sessions keep their lanes), each named in `logs/drills.log`, with a
`WARNING` in the pipeline log. A nightly's ~41 sessions at a few MB each fit.

`drills/live` has caps of its own, 10,000 members and 768 MiB
(`LIVE_MAX_FILES` / `LIVE_MAX_BYTES`, the collector's `LIVE_MAX_MEMBERS` /
`LIVE_MAX_BYTES`, a test holds them equal). Past either, the recordings go
first, the casts and then the pane captures, then the event logs, then the
wire logs, largest first, so every verdict stays, with a `WARNING` in the pipeline log. Only if
the record files alone are over is `drills/live` dropped whole, with the
stage `drills-live: skip`. A nightly comes to about 7 members a drill (with
its event log) and 5 a run, about 310: a margin of 3x in members. The
demo battery (§9.9: 6 demos, Mandu and 5 baselines, 3 rounds, 108 runs of
one drill each) comes to about 12 members a run, ~1,300: a margin of 1.5x
with every recording kept. The cap was 1,000 until 2026-10-17, when a
battery's trim took every cast and then every demo's turn-2 pane capture,
the one record of what the user saw that a grade reads (a pane capture is a
few KB; it goes only after the casts). It was 2,500 members and 256 MiB
until 2026-10-18, when the battery took Opus beside Sonnet: the planned
battery (9 demos, Mandu and 9 sides, 2 models, 3 takes: 540 runs) comes to
about 13 members and 1.1 MB a run (the wire log about 0.8 MB of it),
~7,000 members and ~600 MB, and its record files alone (7 a run, ~3,800)
were over the old member cap, so the guest would have dropped `drills/live`
whole and kept no record of it. The caps now hold it with a margin of 1.4x
in members and 1.3x in bytes, every recording kept.

**Why carrying the events is safe.** An event log holds originals
(`DualRepr.original`, what a symbol stood for), so it is handled as every
event log under `~/.mandu` is, even though a drill's data is synthetic (the
seeded workspaces, the canaries, the labels of `drill-policy.yaml`):

- owner-only at every step: `collect_live` makes `drills/live` 0700 / 0600 in
  the guest, the collector writes the host's run directories 0700 and their
  files 0600 (the path table's `live-drill-runs` is 0700, not
  agent-readable), and makes `--out`'s `drills/live` owner-only too;
- the results disk, events included, goes through the credential canary
  (§9.3) before anything is published: a log that held the lane's token
  withholds the whole run;
- the GitLab job artifact (`--out`) carries them, as it carries the replay
  records' event logs, readable by whoever may read the project's artifacts,
  for 30 days. They hold the drill's synthetic data and the model's answers
  to the drill prompts; a real secret never enters a drill workspace;
- the dashboard serves a CI log to its trace through a read-only source with
  no arbiter behind it (`dashboard.md` §4.22), never through the file route,
  and never desymbolizes its `$MDU:*` tokens against the host's table.

**A per-push run uses master's baselines** (test-reorganization.md §6.9).
`vm-run.sh` appends the host store's promoted baselines (the path table's
`drill-baselines`, each a `<key>/baseline.json`, newest first, up to
512 MiB) to the input tar under `src/.mandu-ci/baselines/`
(`ci_append_baselines` in `lib.sh`), for a per-push run only: not the
nightly, which reruns every plain run, nor `--exec`, `--shell` or
`--selftest`. `MANDU_CI_NO_BASELINES=1` leaves them out. In the guest,
`pipeline.sh` adds `--replay-baseline-mode use --replay-baselines-seed
<tree>/.mandu-ci/baselines`, so every replay-drill entry gets
`MANDU_REPLAY_BASELINE=use` and the read-only seed. A key the seed holds runs
the Mandu side alone. A key it lacks records its plain run into
`drills/baselines`, which the collector promotes only from a master run
(below). The seed is data in the guest's tree (ignored by git), never written
and never archived.

**A per-push run blocks on the replay verdict** (test-reorganization.md
§6.9, since 2026-10-11). The same branch of `pipeline.sh` adds
`--replay-blocking`, so every replay-drill entry also gets
`MANDU_REPLAY_BLOCKING=1`: a FAIL or TIMEOUT verdict of a replayed drill
or differential session fails its test, and so the entry, beside the
entry's own assertions. The nightly (networked) run does not pass it: its
whole-catalog entries stay `nightly` and are read as a trend.

**The caps.** `drills/` holds at most 3,000 members and 256 MiB
(`DRILLS_MAX_FILES` / `DRILLS_MAX_BYTES` in `pipeline.sh`, the collector's
`DRILLS_MAX_MEMBERS` / `DRILLS_MAX_BYTES`, a test holds them equal), counted
without `drills/live`; the whole archive 14,000 members and 1,280 MiB
(6,500 and 768 MiB until 2026-10-18, when `drills/live`'s caps grew), so
both trees full still leave 1,000 members and 256 MiB for the logs, and the
archive fits the 2 GiB results disk `vm-run.sh` gives the guest (a test
reads both). A baseline is
one file (`baseline-cache.ts` schema 2: `<key>/baseline.json` holds the
scalars, the requests, the screens, the history, the files and the PTY bytes
in base64), so a per-push run's ~65 recorded sessions and their baselines
come to about 700 members and 41 MB: a margin of about 4x in members and 6x
in bytes.

**A drop is never silent.** Over either cap, `pipeline.sh` drops `drills/`
(safe: an archive the collector would refuse loses every result), and says so
three ways: a `WARNING` line in the pipeline log, the stage `drills: skip` in
`summary.json` (the dashboard's run facts show it; the run's result is not
changed), and the collector, which reads that stage from the validated
summary and prints `collect-results: WARNING: the guest DROPPED drills/ …`
in the job log. The collector also prints every run's `drills/` count against
the caps, from the archive's own listing (the host's numbers, not the
guest's text), and warns from 80% of either cap on, before anything is lost.

**What the collector does with them** (only for a run whose archive it
accepted; an `error` run copies nothing of `drills/`, and none of this
changes the run's result or exit status):

- `runs/ci/<run>/` holds no `drills/`; `--out` (the CI job's artifact) holds
  the guest's `drills/` as it came.
- **The records** go to the host's store beside the CI runs,
  `<runs root>/drills/replay/<run>/` (the path table's `replay-drill-runs`
  row). Every record directory of the archive (one that holds `run.json`, at
  `drills/replay/<x>/` or `drills/replay/<entry>/<x>/`) is merged into that
  ONE run: `run.json` from the first whose `run.json` is a
  `mandu-replay-run` object, its `runId` forced to the CI run's id and its
  `commit` to the commit the host tested; each `sessions/<key>.json` that is
  that key's `mandu-replay-session`, its `sessionId` forced to
  `<run>/<key>`; and only that session's `events-<key>.ndjson`,
  `casts/<key>.{mandu,plain}.cast` and `panes/<key>/…`, each at most 32 MiB.
  A key two entries both wrote keeps the first; any other file stays behind,
  and the collector's report says so. Written `O_EXCL`, mode 0644 (0755
  directories), staged under a hidden name and renamed over an older copy;
  then the store's retention policy runs (below). The dashboard re-validates
  every record it reads, as strictly as a CI summary.
- **The baselines** are promoted into the host's cache,
  `<runs root>/drills/baselines/<key>/` (the `drill-baselines` row), only
  from a **passing default-branch push or scheduled run**: the collector
  reads the CI job's environment on the runner host (never the guest's) and
  requires source `gitlab`, `CI_PIPELINE_SOURCE` `push` or `schedule`,
  `CI_COMMIT_BRANCH` equal to `CI_DEFAULT_BRANCH` and to the recorded ref,
  and no merge request or tag. A merge request's baseline is never promoted:
  the plain run is the control a replay is graded against, so a baseline a
  merge request wrote would be a way to poison every later run
  (test-reorganization.md §6.3). A baseline is a directory holding only
  `baseline.json`, at most 32 MiB, a JSON object of kind
  `mandu-replay-baseline` whose `key` is the directory's name,
  `[A-Za-z0-9][A-Za-z0-9._-]{0,159}`; anything else is not promoted, and the
  cache's loader re-checks every field before it uses one. The cache keeps
  the newest 500. `baseline-cache.test.ts` writes a baseline with
  the cache's own `saveBaseline`, promotes it with the collector and loads it
  back.
- **No stale statusline is promoted** (2026-10-18). The differential
  harness's fixture config prints a status line row, `sl p<P>/d<D> m<M> | …`
  (`P` prompts submitted, `D` turns finished), and the harness waits, before
  each turn checkpoint and the resize checkpoint after it, for the row to
  read `sl p<k>/d<k>` after turn k; a wait that runs out captures the screen
  as it is. When both sides run out with the same old row, screen parity
  agrees, the run passes, and promoting its plain side would freeze a stale
  screen into the control. A passing run's Mandu side matched its plain
  side, so the collector judges the baseline's own screens
  (`staleStatusline`): a `turn` or `resize` checkpoint that shows a fixture
  row and none reading its turn's marker is stale (a screen with no fixture
  row, a dialog's or the `quit` capture, is not judged). A stale baseline is
  not promoted and the host's entry for its key is kept; the job log
  WARNS, naming the key and the checkpoint (`checkpoint 1 (turn 2, turn)
  shows sl p2/d1, not sl p2/d2`), and the per-push runs record that key's
  plain run again until a master run brings a fresh one. A human who means
  it promotes one anyway: `--allow-stale-statusline KEY[,KEY…]` (or `all`),
  or `MANDU_CI_ALLOW_STALE_STATUSLINE` with the same value in the GitLab
  job's environment (a pipeline or schedule variable; read on the runner
  host, never in the guest), and a note records it. A malformed value
  promotes nothing it refused. Tests: `ci-collect-results.test.mjs`, and
  `baseline-cache.test.ts` (the judgment equals the harness's own wait on
  what `saveBaseline` writes).
- **The live-drill records** go to the host's live store,
  `<runs root>/drills/live/<run>.<drill run>/` (the `live-drill-runs` row,
  the dashboard's watch store, which its Live drills section and the drill
  matrix's live cells read; a colon of the CI run id becomes a dash, and a
  hash stands for a CI run id too long for the store's 81-character names).
  Each run directory of the archive holding `meta.json` is checked again as
  the dashboard's reader would: `meta.json` an object with a `startedAt`, at
  most 16 MiB, else the run is not copied; `chapters.json` and `report.json`
  arrays and `matrix.json` an object, else that file is skipped; the other
  files the file route's names, each at most 32 MiB, and the event logs
  (`events-<session>.ndjson`, at most 32 MiB) of the sessions the run names
  (a log of any other session is skipped). `meta.json`'s `runId` becomes
  the host name, a status other than `done` or `aborted` becomes `aborted`,
  and its `pid` 0 (a guest's pid means nothing on the host). Every session id
  the record names (`meta.sessions`, the chapters' and report rows'
  `scopeId`) and each event log's name are **namespaced by the CI run**
  (`liveSessionName`: `<CI part>.<guest session>`, so the guest's
  `<drill run>-<key>` reads `<host run>-<key>`, the shape the dashboard joins
  a run's sessions by): every private arbiter mints its own ids, so two CI
  runs' sessions, or a CI run's and the host's, would otherwise share one (as
  the replay records' ids are, test-reorganization.md §7.3). An id too long
  once namespaced keeps the guest's and carries no events. A marker,
  `ci-run.json`, names the CI run, its commit, the guest's run name and the
  guest's session ids, and only marked runs are pruned, to the newest 200
  unpinned ones (a pinned run stays: below):
  the store also holds the host's own live runs, which the collector never
  touches. Written owner-only (0700 / 0600, above). From any run whose
  archive it accepted, like the replay records: an observation, not a
  control, so no master-only rule. The dashboard reads the logs as the
  session's event lanes (`dashboard.md` §4.22), so a CI live session in the
  inspector has its trace like a local one.

**Pinned runs: the records behind a published number** (2026-10-18). The two
prunes go by count (the ci store's below, the live store's above), and a
demo battery alone brings about 108 live runs (§9.9), so the records of a
battery whose numbers were published (comparisons.md §5) rotated out after
about two more batteries: battery 3's were gone from the host in under two
days. A company that publishes comparative numbers must be able to show
what they rest on when asked, so those records must not expire on a count.
A run directory of the ci store (`runs/ci/<run>/`) or a CI-brought one of
the live store holding an entry named `.keep` (the replay store's pin too,
below) is **pinned**: neither prune removes it, and it does not count
toward the cap of 200 (the newest 200 unpinned runs are kept beside every
pinned one). A pin is a small JSON note,
`{"kind":"mandu-keep","reason":…,"pinnedAt":…}`, and a directory the
collector replaces (the same run collected again) keeps its pin.

- **The demo battery is pinned as collected.** The collector takes the
  job's suite selection, `--only` (vm-run.sh and pipeline.sh pass the
  `--only` they ran, `MANDU_CI_ONLY`), and when it names a job of
  `PINNED_JOBS`, today `live.demo-battery` and its API-key form
  `live.demo-battery.api` (§9.9), pins that run's directory
  and every live run it brings, and says so in the job log. Batteries are
  rare and each is bounded by the guest's cap on `drills/live`
  (`LIVE_MAX_BYTES`, 768 MiB), so keeping every one costs little; the
  scripted rehearsal, `live.demo-battery.rehearsal`, is not pinned (a
  scripted model's numbers are no one's evidence).
- **Only the host pins.** The selection is the host's, never the guest's
  word; the collector copies only record files, and `.keep` is never one
  (a `.keep` in a guest's live run is skipped, one at the top of its
  archive refuses the archive), so a CI run cannot pin itself.
- **By hand**: `node scripts/ci/collect-results.mjs --pin <CI run> [--reason
  TEXT]` pins a CI run's run directory and each live run whose `ci-run.json`
  names it (a live directory's name may hold a hash of the run id instead,
  so the marker, not the name, decides); `--unpin <CI run>` releases them
  for the next prune; `--pinned` lists the pinned CI runs (the run
  directory pinned or not, how many live runs, when, why). Each takes
  `--runs-dir` / `--live-dir` as a collection does, and `--pin` / `--unpin`
  exit 1 when nothing of the run is left. A battery run on a host
  (`npm run drills:demo:battery` outside CI) writes no `ci-run.json` and is
  never pruned at all.

No archive step copies a pinned battery elsewhere: the path table has no
row for a durable evidence directory, and a pin keeps the records where the
dashboard and the comparison read them. A GitLab-run battery's `--out` copy
is its job artifact besides.

**Retention of the replay store** (`scripts/ci/replay-retention.mjs`). Every
per-push run adds about 15 MiB of replay records to the runner host's store.
The rule, applied by the collector after each run it copies in and runnable
by hand:

- **What is a run.** A store entry is a replay run only when it is a real
  directory (`lstat`: a symlink is never one), its name a run id
  (`[A-Za-z0-9][A-Za-z0-9._:-]{0,119}`, no `..`), and its `run.json` a
  regular file (opened `O_NOFOLLOW | O_NONBLOCK`) of at most 64 KiB holding a
  `mandu-replay-run` object of schema 1 whose `runId` is the directory's name
  and whose `startedAt` is a time. Anything else is **ignored**: reported,
  never deleted.
- **What is kept.** The runs in the dashboard's order (`startedAt` newest
  first, then the run id descending, as `replay-run-store.ts` lists them),
  and a run is kept when it is one of the newest **N** (`DEFAULT_KEEP_RUNS`,
  300, about 4.5 GiB; `MANDU_REPLAY_KEEP_RUNS` or `--keep` changes it, and
  anything but a whole number ≥ 1 is refused, so a typo never empties the
  store), when it is **pinned** (it holds an entry named `.keep`, which the
  host's operator touches; the collector copies only record files, so a CI
  run cannot pin itself), or when it is **recent** (its directory,
  `run.json`, `sessions/`, `casts/` or `panes/` changed within the grace,
  default 60 minutes, `--grace-minutes`: a writer may still be filling it).
- **Retention and the listing windows are separate constants.** The replay
  page's `/api/replay` lists the newest 300 (`REPLAY_LIST_LIMIT`), so every
  kept run is browsable; the recorded sessions of `/api/sessions`
  (`REPLAY_SESSIONS_RUN_LIMIT`) and the drill matrix (`REPLAY_RUN_LIMIT`)
  read the newest 50, since each of their sessions also costs an events
  summary (dashboard.md §4.28, §4.30). `scripts/test/replay-retention.test.mjs`
  reads the three windows out of the dashboard's source and asserts
  retention is at least each of them and equals the replay page's window.
- **How a run goes.** Re-checked (a real directory directly under the
  store), renamed to a hidden `.prune-<run>-<hex>` in the same directory,
  then removed with `rm -r` semantics that remove a symlink inside it, never
  its target. The rename is the one step a reader can observe: the dashboard
  skips dot names and treats a run that disappears between its `readdir` and
  its reads as absent, so a pruned run drops out of every listing and its
  detail, files and trace answer 404 or empty, never an error
  (`dashboard/test/component/replay-retention.test.ts` prunes under a live
  server's reads). A hidden `.prune-*` or `.tmp-*` directory older than the
  grace is removed too.
- **By hand.** `node scripts/ci/replay-retention.mjs --dry-run` lists
  exactly what a real run deletes, each run with its `startedAt` and its size
  on disk, and the total; without `--dry-run` it deletes that. `--dir DIR`
  (default: the path table's `replay-drill-runs`), `--keep N`,
  `--grace-minutes M`, `--json`. A store that is itself a symlink is refused.
  A failed prune is a note and never undoes the copy.

A run whose entries named their agent also writes `summary.md`, the agent
matrix as a Markdown table (test-organization.md §5); the collector accepts
it beside `summary.json` and `junit.xml` and copies it, as text.

`summary.json`, schema 1:

```json
{
  "schema": 1,
  "kind": "mandu-ci-run",
  "run": "gl-1234-5678",
  "source": "gitlab",
  "commit": "b814495e…",
  "ref": "master",
  "image": "mandu-ci-3f2a…",
  "started": "2026-09-28T10:00:00Z",
  "finished": "2026-09-28T10:07:12Z",
  "result": "pass",
  "stages": { "build": { "result": "pass", "duration_s": 131 } },
  "entries": [
    { "id": "arbiter", "kind": "component", "result": "pass",
      "pass": 431, "fail": 0, "skip": 2, "duration_s": 48.2,
      "log": "logs/arbiter.log" },
    { "id": "integration.codex-headless", "kind": "live-drill", "result": "pass",
      "pass": 3, "fail": 0, "skip": 0, "duration_s": 412.7,
      "log": "logs/integration.codex-headless.log",
      "agent": "codex", "agentVersion": "0.162.0" }
  ]
}
```

The rules, which the collector (`validateSummary` in
`scripts/ci/collect-results.mjs`) and the dashboard
(the developer view's `ci-runs.ts`) both enforce, and a test feeds the collector's
outputs through both (`scripts/test/ci-collect-results.test.mjs`):

- required: `schema` (1), `kind`, `run`, `source` (`gitlab` or `local`),
  `commit`, `ref`, `started`, `finished`, `result`, `entries`; optional:
  `image`, `reason`, `stages`. **No other field, at any level.**
- `run`, entry ids, entry kinds and stage names match `^[A-Za-z0-9._:-]{1,120}$`
  (not `.` or `..`); `run` equals its directory's name and does not start
  with `.`.
- `commit` is `^[0-9a-f]{7,64}(\+dirty)?$`: `<sha>+dirty` is a `--worktree`
  run with local changes. `ref` is text of at most 255 characters (may be
  empty), `image` at most 200; text never holds control or bidi characters.
- `started` and `finished` are ISO-8601 with `Z` or `±hh:mm`.
- `result` is `pass`, `fail` (a suite or the build failed) or `error` (the
  run itself broke); `reason` (at most 2000 characters) says why an `error`
  run broke: `image stale: …`, `unreadable results: …`, `timeout: …`.
- A stage is `{result, duration_s}` and an entry `{id, kind, result, pass,
  fail, skip, duration_s, log?, agent?, agentVersion?, ullm?}` (the entry's `kind` was `tier` until
  2026-10-01, test-organization.md §9.3); their `result` is `pass`, `fail`,
  `skip` (its prerequisite was absent and it was allowed to be), `timeout` or
  `error`; counts are integers up to 10⁹; an entry's `log`, when present, is
  exactly `logs/<id>.log` and is in the archive.
- An entry that drove a named agent (every live-drill entry,
  test-organization.md §5) also carries `agent` (`^[a-z][a-z0-9-]{0,39}$`),
  `agentVersion` when the agent's CLI reported one
  (`^[0-9][0-9A-Za-z.+-]{0,63}$`) and `ullm`, the agent that served as its
  U-LLM, when another one did; `agentVersion` and `ullm` come only with
  `agent` (2026-10-15).
- A run that did not go through the VM says so with a stage `vm: skip`
  (`pipeline.sh --host`): the schema has no free-text field for it.

**The collector** (`scripts/ci/collect-results.mjs`, run by `vm-run.sh`
after the guest powers off, and by `pipeline.sh --host`) treats the archive
as untrusted, because code from a merge request produced it. It reads the tar
itself (ustar, GNU long names, pax `path`/`size`), without tar(1):

- lists the tar first and refuses it unless every member is a regular file or
  a directory under a relative path with no `..` or empty component, in the
  layout above and in the characters `[A-Za-z0-9._@+=,:-]`, with no
  duplicate and nothing under a file, at most 14,000 members and 1,280 MiB
  unpacked (from the headers, before reading any data); a bad header checksum
  or a missing end marker refuses it too;
- extracts into a fresh directory, creating each file with `O_EXCL |
  O_NOFOLLOW`, mode 0644 (directories 0755), never the archive's owner or
  mode;
- validates `summary.json` (at most 1 MiB) against the rules above and checks
  it is this run: its `run`, `commit` and `image` equal what the host set; a
  missing or invalid one makes the run `error`, reason `unreadable results:
  …`;
- with `--error` (vm-run.sh passes it on a timeout or a qemu failure) does
  not read the archive and records the `error` run with that reason;
- in every case writes a run directory, so a broken run still appears: the
  staged copy `.tmp-<run>-…` (hidden names are ignored by the dashboard) is
  renamed to `${MANDU_HOME:-~/.mandu}/runs/ci/<run>/` (mode 0755, replacing
  an older run of the same id), with the guest's serial console as
  `console.log` (its last 5 MiB), and prunes that directory to the newest 200
  runs (a pinned run, `.keep`, neither goes nor counts: above; a run of the
  demo battery is pinned as collected); `--out DIR` copies the same files
  there;
- exits with the run's result (0 pass, 1 fail, 2 error), which is the CI
  job's status.

**The CI system** gets the same files as job artifacts (a JUnit report), so a
failing test shows in the merge request.

**The dashboard** reads the runs directory (read-only) and shows a **CI**
section in the inspector (`/dev/`): the recent runs by commit and ref, each
with its result and its kinds' pass, fail and skip counts; a run's entries;
an entry's log as plain text. It fetches nothing from the CI server and holds
no token. It re-validates every `summary.json` it reads, caps what it sends,
and renders every field as text. The CI runs' sessions never enter the live
event store: the inspector's `CI` chip and `docker-run.sh --publish-events`
belong to the retired pipeline and are unused by this one. A host's
dashboard shows only the runs that host executed, since the runs directory
is local.

## 7. GitLab wiring

The maintainers also run the same guest on their own runners: shell
executors in the `kvm` group (nothing else, no `docker` group), each serving
several 16-vCPU guests at once (§5.3). `.gitlab-ci.yml` holds the jobs, each
one `vm-run.sh` line (or `nightly.sh`, `run-matrix.sh`): `test` (every merge
request and every push to `master`; the docs lane for a documentation-only
request, §5.5; and the hourly master check, §7.1), `kernel-linux-7`
(nightly and `v*` tags, §4.1), `install`
(`scripts/matrix/run-matrix.sh --require ubuntu-2404 --require ubuntu-2604`
on `v*` tags; a SKIP of either supported install target is a FAIL; no guest
of its own: its `host` cells and every host prep run in the job's clean
checkout, so the matrix installs the packages its bundle build reads and
builds Rust with the `pins.env` toolchain itself, `os-test-matrix.md` §4.1),
`audit` (the dependency audit in a guest with a network: the schedule, `v*`
tags and a merge request that changes a lockfile, §14.2), `website-deploy` (a push to `master` that
changes the company website's published files uploads them to Cloudflare
Pages from the runner host; the other token, a Pages-only one in a masked,
protected CI variable), and the nightly lane `nightly-subscription`
(§9), which only a scheduled pipeline runs and which holds a scoped agent
credential kept on the runner host, outside the repository, never in a CI
variable. The API-key lane
has no job (removed 2026-10-09, §9.8): no vendor API key is installed on a
runner (§13.4), so the scheduled `nightly-api` job failed every night.
`scripts/test/ci-workflow.test.mjs` evaluates the rules for each kind of pipeline and pins them (no push, merge
request or tag runs a nightly lane; no credential in a CI variable). A job
names a runner role, never a host, and with no runner for its role it waits
visibly pending: a merge request cannot merge green by absence, and the
dashboard's CI section shows the age of the newest run, so a silent runner
is seen.

### 7.1 The hourly master check (built 2026-10-18)

**Why.** Every job is `interruptible` (the `default:`), so GitLab's
auto-cancel of redundant pipelines cancels a running master pipeline as soon
as a newer merge lands. That is right for throughput (only master's head is
worth testing) but, when merges come fast, nothing on master finishes: on
2026-10-17, from 22:03 to 22:56 UTC, twenty master pipelines in a row were
cancelled and none finished, so master went untested for the hour, a
change the docs or scoped lane under-tested (§5.5, §5.8) went untested
after it landed, and a reader of the pipeline list saw only an hours-old
verdict.

**What.** A second pipeline schedule on `master`, hourly, with the schedule
variable `MANDU_SCHEDULE=master-check` (the nightly's schedule sets none,
which is how the two are told apart; every nightly job's rule excludes
`master-check`). Its pipeline is named `master-check` (`workflow:name`; every
other pipeline has none) and runs the `test` job alone: the same full
per-push selection a master push runs, the same guest, the same runner role.

- **Nothing cancels it.** Its `workflow:rules` entry sets
  `auto_cancel: on_new_commit: none`, which GitLab reads from the pipeline
  being cancelled, so a newer merge cancels none of its jobs, not even one
  still pending for a runner. As a second guard, `test` is
  `interruptible: false` in it (`rules:interruptible`): in GitLab's default
  `conservative` mode a pipeline in which a non-interruptible job has started
  is no longer cancelled. A push pipeline keeps `interruptible: true` for
  `test`, so pushes still cancel each other's tests, but its workflow rule
  sets `auto_cancel: on_new_commit: interruptible` (2026-10-18): a newer merge
  cancels only interruptible jobs, so `website-deploy` (not interruptible)
  survives even while it still waits for a runner. In `conservative` mode a
  pending deploy was cancelled with its pipeline, and the merges after it,
  not touching the site, started no deploy.
- **It cancels nothing.** Auto-cancel on a new pipeline cancels only the
  older pipelines of the same ref for another commit than the new one's
  ("the new pipeline must be for a commit with new changes", GitLab's
  `interruptible` reference). The check runs on master's head, which the
  newest push pipeline already has, so that one keeps running.
- **It costs nothing when master has not moved.** After `vm-run.sh`, the
  `test` job of every master pipeline (a push or the check) runs
  `scripts/ci/master-check.mjs record`: when `vm-run.sh` exited 0 (pass) or 1
  (fail) and the run's summary agrees (the same commit, the same result), the
  commit is written to a small state file on the runner host
  (`master-tested.json` in the path table's `ci-cache` directory; the last
  50 commits). An `error` (the guest broke, a timeout) or a cancel writes
  nothing. In the check, the first line of `test` is `master-check.mjs skip`:
  when the state already holds a finished test of the commit, it renames the
  pipeline `master-check: skipped, <sha> already tested in #<pipeline>
  (<result>)` through the job token (`PUT
  /projects/:id/pipelines/:pipeline_id/metadata`, the one Pipelines API
  endpoint a job token may call) and the job ends at once. Fail-safe: no
  state, another commit, or a rename GitLab refuses runs the test.
- **Why a state file, not the API.** The job token cannot list pipelines
  (GitLab's job-token endpoint list), and a stored token would be the
  pipeline's first credential for a check that needs none. The file is
  regenerable: losing it costs one redundant run. With several runner hosts
  a host does not see the others' tests, so a check can test a commit
  another host already tested; it never skips a commit that no host tested.
- **How it is read.** A reader of master's pipelines counts a pipeline named
  `master-check` as a master verdict, passes over one renamed
  `master-check: skipped, …` (it ran no test) and an unnamed scheduled one
  (the nightly), and gives the deciding pipeline's age, so a verdict hours
  old reads as such. A red check makes its pipeline red and nothing else: no
  merge waits for it (merge requests are gated by their own pipeline).

**Setting it up.** A maintainer creates the schedule once: on `master`,
cron `30 * * * *` (half past each hour, away from the nightly's 01:00 start),
active, with the variable `MANDU_SCHEDULE=master-check`. The owner of a
schedule is the user its pipelines run as.

Tests: the rules (which jobs each pipeline kind runs, the check's
`auto_cancel` and `interruptible`, the nightly unaffected, a push still
interruptible) are pinned by the maintainers' workflow test; the skip and the
record by `scripts/test/ci-master-check.test.mjs`
(`scripts.ci-master-check`), against a stand-in GitLab on the loopback.

## 8. Running the same thing locally

One command runs exactly what CI runs:

```sh
scripts/ci/vm-run.sh                          # the per-push kinds on HEAD, in the CI image
```

| Option | Effect |
|---|---|
| `--kind <k>[,<k>]` | the kinds to run (default `unit,component,stack,replay-drill,sandbox`) |
| `--need <n>` | only the selected entries with this need (`--need kernel`: the kernel lane) |
| `--only <id>[,<id>]` | only these manifest entries (`node scripts/suites.mjs list` shows them) |
| `--commit <rev>` | test that commit (default `HEAD`) |
| `--worktree` | test the working tree instead, uncommitted changes and untracked files included (never ignored files) |
| `--guest ubuntu-2404\|ubuntu-2604` | the guest image (default `ubuntu-2404`, kernel 6.8); `ubuntu-2604` is Ubuntu 26.04 on Linux 7.0, its own image (§4.1) |
| `--jobs N`, `--vcpus N`, `--mem MiB` | concurrency (default half the vCPUs) and guest size |
| `--shell` | boot the same image with the same checkout and open a shell as `ci` in it (serial console) instead of running; the guest powers off when the shell exits |
| `--keep` | keep the overlay and the raw disks (and the console log) after the run |
| `--out DIR` | also copy the results there (CI uses it for the artifacts) |
| `--dry-run` | print the qemu command and the job file, run nothing |
| `--run-id ID`, `--source local\|gitlab`, `--ref REF` | how the run is recorded (default `local-<time>-<sha>`, `local`, `$CI_COMMIT_REF_NAME` or the branch) |
| `--selftest` | the VM plumbing only: no build, no suites (§5) |
| `--exec 'CMD'` | after the build, run `CMD` as `ci` in the checkout instead of the suites; `release/` comes back as `artifacts/release/` (§5) |
| `--network` | the nightly: user-mode network to the internet, qemu in its own namespace behind `slirp4netns --disable-host-loopback`; the suites run unsandboxed in the guest, after the nightly stack (§9.2, §9.4) |
| `--ollama` | the host's Ollama (`MANDU_CI_OLLAMA_HOST`, default `127.0.0.1:11434`) at `10.0.2.100:11434` in the guest, and nothing else of the host (§9.2) |
| `--credential claude\|codex\|claude,codex\|api` | the reduced credentials placed on this host (§9.3, §9.8), on a read-only fourth disk that is gone with the guest; the canary after the run. The subscription and tool kinds combine; `api` stands alone or with the `docker` tool kind (`api,docker`, §9.8 "Tool credentials"), never with a subscription kind. Needs `--network`; refused with `--shell` and `--exec` |
| `--lane subscription\|api-key` | the nightly lane (§9.8): of the selected entries, only those whose `credential` is this one; `api-key` takes `--credential api` (or `api,docker`), `subscription` never takes `api` |
| `--include-flaky`, `--include-internet` | every `flaky` entry of every kind; the selected kinds' `internet` entries (needs `--network`) |

`scripts/ci/nightly.sh --lane L [--canary-credential] [options]` is vm-run
with the nightly's selection and options (§9.1); `--canary-credential`
rehearses it with synthetic credentials (§9.6).

Environment: `MANDU_CI_TIMEOUT` (seconds, default 2700; the guest's budget
and deadline follow from it, §3), `MANDU_CI_VCPUS`
(32, capped to the host's CPUs), `MANDU_CI_MEM` (MiB, 65536), `MANDU_HOME`
(the images in its `cache/ci`, the results in its `runs/ci`),
`MANDU_CI_WORK` (a run's disks, default `<cache>/runs`, removed unless
`--keep`), and for the nightly `MANDU_CI_CLAUDE_CREDENTIAL` (the token file,
§9.3) and `MANDU_CI_OLLAMA_HOST`.

It needs `/dev/kvm` (the `kvm` group), `qemu-system-x86_64`, `qemu-img`,
`genisoimage` or `xorriso` (for the first image build), and network for the
first image build only. Results land in the runs directory, so a local run
appears in your dashboard's CI section, marked `source: local`.

**Reproducing a CI failure:** `scripts/ci/vm-run.sh --commit <sha> --only
<entry>`. The image is chosen by the commit's own key, so it is the image CI
used, unless it was pruned, in which case it is rebuilt from the same pins.

**Without KVM** (a laptop, a VM without nested virtualization):

```sh
scripts/ci/pipeline.sh --host --kind unit,component,stack,replay-drill
```

runs the same stages on the host, each entry in `ns-run.sh`'s sandbox, with
the host's toolchain instead of the pinned one, and hands its results to the
same collector, so they land in the same runs directory. On a host that
restricts unprivileged user namespaces (Ubuntu 24.04's default), the sandbox
goes through Mandu's granted bwrap (`/usr/lib/mandu/bin/bwrap`, installed by
`mandu setup`), the only bwrap AppArmor lets create one; `MANDU_CI_BWRAP`
overrides the choice. That bwrap is 0.9, without overlay, so the host run
uses ns-run's private copy of the checkout (`--tree auto`, §5). On a host
with Ubuntu's `bwrap-userns-restrict` (26.04's default) the system bwrap
works but a sandbox cannot nest inside it, so the git sandbox's tests SKIP
in the sandboxed entries unless Mandu's own bubblewrap is installed; the run
says so (§5.6). Host mode installs missing or stale `node_modules` in the
checkout itself (with network) and builds into its `interceptors/target`.
The kernel lane (the entries that need `kernel`) is not equivalent there:
plain `unshare --user` is refused, so its entries SKIP; the host run does
not pass `--strict-skips`, and its summary carries the stage `vm: skip` to
say it was not the VM. Use the VM for the kernel lane.

**The quick loops stay:** `npm test` in one package, `scripts/test-all.sh`.
They run on the host, unsandboxed. They are for the edit loop, not for
proof: only `vm-run.sh` is what CI runs.

**Never run the suites under `mandu`** (the agent launcher). That posture
confines an agent (an AgentView, gated egress, symbolization); tests run
inside it would measure the product's interference, and a regression in the
sandbox would also break the harness meant to catch it.

## 9. Nightly

The nightly runs from its own pipeline schedule, which sets no
`MANDU_SCHEDULE` (the hourly master check's schedule sets `master-check`,
§7.1, and no nightly job runs in it). The nightly kinds (`live-drill`, `env`, `eval`) run in `secrets` mode only
(`test-organization.md` §7; the frozen lane stays out of every automatic
run), non-blocking, plus every `flaky` entry of every kind. **It is the only
automatic run that holds a credential**. The entries split into two lanes
that each hold **one** kind (§9.8): the subscription lane a scoped agent
credential (plus an optional reduced Codex sign-in), the API lane vendor API
keys. Only the subscription lane is scheduled (`nightly-subscription`); the
API lane is hand-run only, since no vendor API key is installed on a runner
(§13.4; its scheduled job `nightly-api` was removed 2026-10-09).

### 9.1 What runs

Each lane is one command; the first is the scheduled job, the second is
run by hand only, on a host that holds the api credential file (§9.8):

```sh
scripts/ci/nightly.sh --lane subscription --commit <sha> --run-id nightly-subscription-<id> --out ci-out
scripts/ci/nightly.sh --lane api-key      --commit <sha> --run-id nightly-api-<id>          --out ci-out
```

`nightly.sh --lane L` is `vm-run.sh --kind live-drill,env,eval
--include-flaky --include-internet --network --lane L` plus the lane's
`--credential` and, for the subscription lane only, `--ollama`, with
`MANDU_CI_TIMEOUT` defaulting to 8 h for the subscription lane (the drill
entries alone run for hours) and 3 h for the API lane. `--lane` is required.
Later options win and `--only` selects exactly, within the lane, so a
rehearsal of one suite is one command (§9.6).

- **Every flaky entry.** `run-suites.mjs --flaky-kinds <k,k>` adds the flaky
  entries, and only those, of more kinds to the `--kind` selection
  (`selectEntries`); the pipeline passes every automatic kind. An `idOnly`
  flaky entry stays out. A flaky entry keeps its own red and never fails the
  run (test-organization.md §4). The frozen lane's flaky entry stays out
  (`--frozen` is never passed).
- **Internet entries.** `--include-internet` adds the nightly kinds'
  `internet` entries (`node scripts/suites.mjs list` names them); the
  per-push run never has them.
- **The launch-time budget** (`integration.launch-budget`, built
  2026-10-21, `runtime-instances.md` §14.11). Warm `mandu claude
  --version` and `mandu codex --version` launches from a small home and
  from a developer-sized one, medians against
  `tests/env/launch-budget-baseline.json`, which is recorded in this guest
  (`vm-run.sh --kind env --only integration.launch-budget --network`). It
  needs no login, so the subscription lane runs it, alone (about a
  minute). A launch more than 50% and 300 ms slower than its baseline
  turns the night red; one more than 20% and 150 ms slower prints a `WARN`
  line and stays green; every step's time is in its log either way.

### 9.2 The guest's network, and the one host port

- **`--network`** gives the guest a virtio NIC on QEMU's user-mode network,
  with qemu inside its own user and network namespace joined to
  `slirp4netns --disable-host-loopback`, exactly as the image build's
  provisioning boot (§4): the guest reaches the internet and **no port on the
  host's loopback** (a developer's live arbiter, dashboard). `boot.sh` waits
  for the lease. Without a bwrap that can make that namespace, or without
  `slirp4netns`, the run is an `error` before it boots.
- **`--ollama`** is the one exception, and only for one port: a `guestfwd`
  maps the guest's `10.0.2.100:11434` to a command qemu starts per
  connection, `port-bridge.mjs connect <socket>`. That command runs inside
  qemu's namespace too, where the host's loopback is not, so it reaches the
  host through a unix socket in a private (0700) directory, where
  `port-bridge.mjs listen` (outside the namespace) pipes each connection to
  `127.0.0.1:11434` and nothing else (`MANDU_CI_OLLAMA_HOST` may name another
  loopback port; any other address is refused; half-close safe, §9.7). In the
  guest, `pipeline.sh` relays its own `127.0.0.1:11434` to
  `10.0.2.100:11434`, so every local-model suite finds Ollama at its default
  URL. `--ollama` without `--network` gives a `restrict=on` network whose
  only reachable address is that one.
- The host's Ollama must have `llama3.2` (the suites' default model) and be
  0.14 or newer (`local-main-model` speaks `/v1/messages`).

### 9.3 The credential

- **What.** One scoped agent credential: an access token only, limited to
  inference, with no refresh token. It can never rotate the host's own login
  (a refresh would), and a leak of it can be revoked on its own. (The
  subscription lane's Codex sign-in has no such token; §9.8 "The Codex
  sign-in" says how it is held instead.)
- **Where it lives.** A file on the runner host that a human places once,
  outside the repository and outside Mandu's own state, so nothing of
  Mandu's (the path table, `mandu reap`, the dashboard) lists, reads or
  deletes it (`node scripts/ci/credential.mjs path claude` prints where;
  `MANDU_CI_CLAUDE_CREDENTIAL` overrides). **Not** in the repository, **not**
  in a CI variable: a variable would be in every job's environment on every
  runner.
- **Its shape.** `credential.mjs install claude` writes the agent's own
  credential shape with the allow-listed fields only, mode 0600, directory
  0700. `check` refuses a file that is absent, not a regular file (a
  symlink), not the account's own, readable or writable by anyone else, a
  refresh token (or any `refresh…` key), an API key, or a token that expires
  before the run's timeout plus five minutes.
- **Into the guest.** vm-run checks the file **before anything slow** (no
  image build, no boot): an unusable one ends the run in about a second as an
  `error` whose reason names the problem and the setup steps. Then
  `credential.mjs prepare` writes a tar holding the credential (the
  allow-listed fields only) 0600 in the run's work dir; vm-run opens it
  on fd 7 and **unlinks it at once**. qemu gets it as an fd set (`-add-fd
  fd=7,set=7`, `-drive file=/dev/fdset/7,…,readonly=on`, virtio serial
  `mandu-cred`), a fourth, read-only disk: no path to it exists while the
  guest runs, and it is gone with the guest however the run ends (a SIGKILL
  included), `--keep` or not. The token is never in a variable, an argument,
  job.env or a log of vm-run's. In the guest, `boot.sh` copies it into the
  CI user's agent configuration (0600, owner `ci`), refusing one with a
  refresh token, says only its size, and deletes it after the pipeline,
  before the results are written.
- **The canary.** After the guest powers off, `credential.mjs scan` looks for
  the token, or any 19 consecutive characters of it (16-character pieces at
  every fourth offset), in the console log and the whole results disk
  (all-zero stretches of the sparse disk skipped). A hit withholds both: the
  run is recorded as an `error`, "credential canary: …", with neither the
  guest's console nor its results, and nothing of the guest's is echoed to the
  job log. What is then published (the run directory, `--out`, the
  collector's report) is scanned again and removed on a hit. A test that
  prints the token therefore turns the nightly red instead of publishing it.

### 9.4 The drill stack in the guest

`pipeline.sh --network` (or `--ollama`) runs the suites **unsandboxed** in
the guest: ns-run's loopback-only namespace and empty `$HOME` would take
away the network and the credential those suites exist to use. The guest is
their boundary, as it is the kernel entries'. Every nightly entry is
`parallel: false` except the flaky differential entries, so they run one at a
time. Before them, `scripts/ci/nightly-stack.sh` (`nightly_stack_start`,
`nightly_stack_stop`) starts:

- a `secrets`-mode arbiter of the test tenant (`scripts/dev-arbiter.sh`),
  its policy the drill labels of `drill-policy.yaml`,
  exported as `MANDU_ARBITER_SOCK` and `MANDU_ADMIN_SOCK`, stopped when the
  run ends, its log kept as `logs/nightly-arbiter.log`. The `drill.*` entries
  each start their own with the same labels (`drill-run.ts --own-arbiter`,
  `test-organization.md` §7.2); this one serves the `claude-e2e` cut and
  every other suite. Its `MANDU_TENANT=test` reaches every suite too, so a
  harness with its own private arbiter must pin that arbiter's tenant and its
  launch's together (`differential-interactive.md` §24);
- `MANDU_BIN=launcher/mandu-run.sh` (no `mandu` is installed in the image)
  and `MANDU_TEST_DASHBOARD=1` (the `claude-e2e` cut and `codex-e2e` skip to
  green without it).

`scripts/test-all.sh --lane` sources the same helper, so a host lane run gets
the same stack (`test-organization.md` §5). The helper keeps the arbiter's
sockets under the 107-byte `sun_path` (in `$TMPDIR`, or `/tmp` when
`$TMPDIR` is longer than 60 bytes), stops the arbiter through
`scripts/dev-arbiter.sh stop` (graceful shutdown first, then its group;
`runtime-instances.md` §10.2), signals the whole process group itself as
well, and removes the directory. The Ollama relay, a claude config that skips
the first-run screens the drill runner does not answer, and the guest's
credential files stay in `pipeline.sh`: they are the guest's. No dashboard
server is started: the drill runner and the e2e suites read the arbiter's
socket, and a human reads the results on the host's dashboard (§9.5).

### 9.5 Results, and how a red nightly is noticed

- The run is an ordinary CI run (§6): `nightly-<lane>-<id>` in the runner
  host's runs directory, so that host's dashboard CI section lists it beside
  the push runs, and the job's `ci-out/` artifact.
- Its drill runs land in the runner host's live store,
  `runs/drills/live/nightly-<lane>-<id>.<drill run>/` (§6, "The live-drill
  records"), where the dashboard's Live drills section and the drill
  matrix's live cells read them, each session with its event lanes.
- **No live tree at all** (the matrix's live cells empty, no
  `nightly-*` run in the CI section) means no nightly has run: the pipeline
  schedule is inactive, or the subscription lane's credential is missing
  (its job then fails in seconds with the setup steps, §9.6). Check the
  project's pipeline schedules and `node scripts/ci/credential.mjs check
  claude` on the runner host. Only the subscription lane runs drills (their
  credential is `subscription`), so an API-lane run never brings one.
- A red nightly makes its job red and blocks nothing. It is seen in the
  pipeline list and the dashboard's CI section, which also shows the newest
  run's age (a schedule that stops is seen as a stale run, not as green). A
  release is cut only after the nightly has been checked (test-organization.md
  §2, "non-blocking").

### 9.6 Setting it up (the human steps)

On each runner host that runs the nightly, as the runner's account, from a
checkout:

1. **The agent credential.** Place a scoped agent credential with `node
   scripts/ci/credential.mjs install claude` on the runner host (it reads
   the token with no echo; its help names the options). `node
   scripts/ci/credential.mjs check claude --min-seconds 29100` must then say
   "usable".
1b. **The API keys** (the API lane, §9.8; NOT installed, decided 2026-10-05,
   §13.4: API keys stay on developers' machines, and the lane has no
   scheduled job; this step serves a hand run only), one per provider: `node
   scripts/ci/credential.mjs install api --provider anthropic`, then `…
   --provider openai`, pasting a key made for CI with a limit on the
   vendor's side. `node scripts/ci/credential.mjs check api` must say
   "usable". Either key may be left out: the entries that need it then skip.
1c. **The Codex sign-in** (optional, §9.8 "The Codex sign-in"): the
   sign-in of a **dedicated** account made for CI, never a personal one,
   placed with `node scripts/ci/credential.mjs install codex` (its help
   names the options). `node scripts/ci/credential.mjs check codex
   --min-seconds 29100` must say "usable". Without it the lane runs and its
   ChatGPT-sign-in suites skip. If a refresh ever fails ("the refresh was
   refused" in the job log), repeat this step. Install one sign-in on **one**
   runner host only: two hosts refreshing copies of the same sign-in spend
   each other's refresh token, so a second nightly host needs its own CI
   account.
2. `ollama pull llama3.2` if the host's Ollama lacks it.

Until step 1 (or 1b) is done, each run of that lane fails in about a second
with "credential: not usable: no credential file at …" and the setup steps.
Rotating the credential is step 1 again; revoking it is done on the
vendor's side. A rehearsal that authenticates nothing, per lane:

```sh
scripts/ci/nightly.sh --lane subscription --canary-credential --worktree --only integration.ollama-doctor,integration.network-model
scripts/ci/nightly.sh --lane api-key --canary-credential --worktree
```

`--canary-credential` hands the guest synthetic credentials of the lane's kind
(they authenticate nothing), so the whole credential path and the canary run,
and only the local-model suites can pass. The first rehearsal passed both
suites against the host's Ollama through the bridge, with the credential in
the guest and the canary finding it nowhere (console, the 2 GiB results
disk, the published run), in 54 s.

The same lanes run on a host without a VM, on its own logins and keys:
`scripts/test-all.sh --lane subscription|api-key`, with `--agents` (and,
for the maintainers' drill entries, `--drills`) to narrow it
(`test-organization.md` §5). It keeps one lane's
credentials per run as the guest does (the subscription lane drops the
API-key variables; the API lane drops the agent credential and the Codex
sign-in path, and loads the secrets file, §13, when a key is unset); unlike
the guest, the host's own agent login stays. It starts the nightly's stack
first (§9.4) and stops it when the run ends.

### 9.7 Signal, not noise: what the first real nightly shows

Settled before the first real run, so that a nightly's reds are the product's
or the model's, not the harness's:

- **The evals are by hand.** `eval.utility` (72 legs, up to 8 h, rows that
  need a human's per-fact review) and `eval.paired`
  are batches with chosen models and a review after. The manifest's `byHand`
  field (its value the reason) keeps an entry out of every kind run, reported
  as excluded with that reason, and still runs it when named (`--only`).
  `eval.paired` is in the frozen lane: its wrapped leg runs `injection`, the
  integrity defense (protection-modes.md §10.7).
- **`integration.openclaw-headless` and `integration.opencode-headless`
  need an API key.** OpenClaw and OpenCode keep
  a dummy key in their configs on both tiers, so the context they send is the
  one the fake tier grades, and the harness swaps a real Anthropic API key
  in on the hop to the real API (`withUpstreamApiKey`,
  `tests/lib/agent-provision.ts`); the recording relay records bodies,
  not headers. They need an API key, so they run in the API lane (§9.8),
  and skip with that reason without a key.
- **The eval runners accept the nightly's credential.** The runners ask the
  agent's own `auth status` (it reads the credential file only, no network
  call) and refuse a file it does not report as signed in; `install` writes
  the shape it accepts. The check proves the file's shape, not that the
  token works. `eval/lib/paired/paired-subscription.test.ts` pins the shape.
- **The Ollama bridge is half-close safe.** Its sockets were not
  `allowHalfOpen`, so a client that sent its request and then its FIN got an
  empty reply. Now each direction ends on its own, and `connect` exits only
  after the upstream's last byte is written to the guest.
  `scripts/test/ci-port-bridge.test.mjs` holds it under load (hundreds of
  connections, 64 at once, 4 MiB each way, the `connect` process run as qemu
  runs it), and every case in it fails on the old code.

**Tests:** `scripts/test/reduce-credential.test.mjs` (the host file's
checks, the install shape, the credential disk as tar(1) reads it, the
canary's reach, the CLI never printing the token);
`scripts/test/ci-vm-run.test.sh` (the dry-run qemu line of each option and
the refusals; a real run with no credential file failing in seconds as a
recorded `error`; a stand-in guest that reads the credential from fd 7,
proves the tar had no path, and on request leaks the token into its console
or a results log, where vm-run must withhold both and print no piece of it;
`port-bridge.mjs` both ways; `nightly.sh`'s command line);
`scripts/test/ci-port-bridge.test.mjs`; `scripts/test/run-suites.test.mjs`;
`scripts/test/suites-manifest.test.mjs` (`byHand`);
`scripts/test/ci-pipeline.test.sh`; `scripts/test/ci-workflow.test.mjs` (the
jobs' triggers).

### 9.8 Two lanes: the subscription and the API keys (built 2026-09-30)

**Why.** With only the scoped agent credential, every suite that authenticates
with a vendor **API key** skipped to green every night: `codex-e2e` and
`codex-mcp` (they read `OPENAI_API_KEY` only, into a fresh `CODEX_HOME`) and
`openclaw-headless` / `opencode-headless` (§9.7; one `agents-real` entry until
2026-10-15). A key cannot simply be added to the one guest: several
suites switch to a key when one is present (`policy-assistant-corpus` in auto
mode, the claude CLI in a drill's tmux pane, the launcher's U-LLM api mode),
so in a guest holding both a suite could pass on the wrong credential. **One lane's
credentials per guest** (a subscription sign-in or an API key, never both)
makes that impossible by construction.

**The api-key lane runs weekly, one agent a night (2026-10-15).** From
2026-10-09 to -15 only the subscription lane was scheduled: no vendor key was
on a runner (§13.4), so the old `nightly-api` job failed every night on the
missing credential file. The lane itself stayed (the manifest's
`credential: "api-key"`, `nightly.sh --lane api-key`, `vm-run.sh
--credential api`, `test-all.sh --lane api-key`), and since 2026-10-15 the
scheduled `nightly-api-key` job runs `nightly.sh --lane api-key --weekly`:
tonight's agent of the rotation (Monday OpenCode 1 and 2, Wednesday
OpenClaw, Friday Goose, by the UTC weekday; `MANDU_CI_WEEKDAY` overrides it),
its live-drill entries of the lane only (`--only`, from `suites.mjs list
--agents`); another night it exits 0 at once. The runner host holds the
Anthropic key in its api credential file (§13.4); without it the job fails
in seconds with the setup steps. By hand, `nightly.sh --lane api-key` still
runs the whole lane.

| Lane | Credential (a file on the runner host) | Entries |
|---|---|---|
| `subscription` | the scoped agent credential (§9.3, `credential.mjs path claude`), plus, when the host holds one, a reduced copy of a dedicated CI account's Codex sign-in (below, `credential.mjs path codex`) | the drills (Claude Code's and Codex's entries); `local-model`, `local-model-netns`; `subscription`, `subscription-real`; `claude-headless.policy`, `eval.policy-assistant-corpus`; `openclaw-headless.inspect` and `opencode-headless.inspect` (their U-LLM is the login); `codex-headless`, `codex-headless.policy`; the Ollama `env` suites, `tls-compat` and the flaky entries (scripted upstreams), which need no login and hold no credential |
| `api-key` | vendor API keys, one per provider (`credential.mjs path api`) | `openclaw-headless`, `opencode-headless`, `codex-headless.openai-key`, `codex-headless.policy.openai-key`; by name only, the demo battery on the key, `live.demo-battery.api` (§9.9) |

- **The manifest says the lane.** Every entry a nightly runs that needs a
  login (a sign-in or an API key) carries `credential: "subscription" |
  "api-key"` (`tests/suites.mjs`). One that needs no login carries none and
  runs in the subscription lane, the guest with the network and the host's
  Ollama (test-reorganization.md §8). `node scripts/suites.mjs check` fails
  an entry that needs a login and names no credential, a credential on an
  entry that needs no login, an entry with a credential no nightly runs, an
  `api-key` entry that needs no API key or needs a subscription sign-in, and
  a `subscription` entry that needs an API key. The needs name the
  credential exactly: `claude-login` (the agent's own sign-in; an API key
  does not serve), `chatgpt-login` (a reduced Codex sign-in at
  `MANDU_CI_CODEX_AUTH`), `anthropic-api-key`, `openai-api-key`.
  `run-suites.mjs --lane L` keeps the selected entries whose `credential` is
  L, or none for L = `subscription` (`selectEntries`, `inLane`; the others
  are reported excluded with the lane), `--only` included: a lane never runs
  another lane's entry. `scripts/test-all.sh --lane L` is the host form
  (§9.6).
- **The API lane's credential.** `credential.mjs install api --provider
  anthropic|openai` reads one key from stdin (no echo) into the API lane's
  file on the runner host (`MANDU_CI_API_CREDENTIAL` overrides), 0600,
  keeping the other provider's key. `check` and `prepare` refuse the file's
  other fields, an OAuth token, an admin key and a key of the wrong shape.
  The disk, its fd set, the unlink and the canary are §9.3's: the tar holds
  the allow-listed keys only; `boot.sh` copies them into the guest (0600,
  owner `ci`, refused unless it is an object of `anthropic` / `openai`
  strings) and deletes them before the results are written; the nightly stack exports it as
  `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` for the suites, logging only the
  names. The canary (`credential.mjs scan api`) looks for 19 characters of
  **every** key, each with its vendor prefix stripped.
- **What the keys may do.** Keys made for CI only, each with a limit on
  the vendor's side, so a runaway suite is capped by the vendor, not by a
  test.
- **No Ollama in the API lane.** None of its entries uses one, so its guest
  gets the network only.
- **A fix the split exposed.** `ullmCliUsable` (the probe that decides
  whether an agent scenario's quarantined read can run) counted an API key
  as a usable CLI, but the cli-mode U-LLM child deletes `ANTHROPIC_API_KEY`
  before it spawns `claude` (inspect-mcp `ullm-client.ts`). In the API lane
  that scenario now skips; the subscription lane runs it as
  `integration.openclaw-headless.inspect` and `integration.opencode-headless.inspect`.

#### The Codex sign-in (built 2026-09-30)

The subscription lane also carries a Codex sign-in, so the Codex suites
run through Mandu's ChatGPT relay
([`agent-sign-in.md §2`](../agents/agent-sign-in.md) §4), not only
on an API key in the API lane.

**The problem.** A Codex sign-in has no scoped, refresh-free token like
§9.3's: it is a short-lived access token plus a refresh token that rotates
on every use. Handing the guest the refresh token does not work: a refresh
in the guest rotates it, the rotated token dies with the guest, and the
host's copy is spent, so the next night fails (and a personal sign-in would
be logged out). The two workable shapes were (a) the guest gets the access
token only and a human re-exports it often, or (b) the **runner host** keeps
the full sign-in of a **dedicated CI account** and refreshes it itself
before each run; the guest still gets the access token only. (b) was
chosen: it needs no upkeep while it works.

**The exception it makes.** §9.3's rule is that the runner host keeps no
refresh token. (b) reverses that for this one credential, and only for a
dedicated account: its refresh token reaches only that account and nothing
of anyone's own. `install codex` refuses the invoking account's own
sign-in, a saved API key and a sign-in without a refresh token. The guest never holds
the refresh token, and the canary looks for it all the same.

- **On the host.** `credential.mjs install codex` places the CI account's
  sign-in in its file on the runner host (`MANDU_CI_CODEX_CREDENTIAL`
  overrides), 0600. `credential.mjs refresh codex` refreshes it as Codex
  itself does, writing the rotated tokens back. It runs under `flock(1)` on
  a lock beside the file, so two refreshes never present the same refresh
  token, and writes tmp + rename, so a failure leaves the file as it was.
  Only the vendor's error code is reported, never its text or a token.
- **When it refreshes.** `nightly.sh --lane subscription` runs `refresh
  codex --min-seconds <…>` before the run: only when the access token no
  longer covers the run with a margin, or the last refresh is old enough
  that Codex's own refresh could come due in a guest. No file: the lane
  runs without it and says so in one line. A refresh that fails: a WARNING
  line, and the lane keeps the sign-in while its access token still covers
  the run; once it does not, the lane runs without it (the ChatGPT-sign-in
  suites skip) and says so. `--canary-credential` hands the guest a
  synthetic sign-in and never refreshes.
- **The suites.** `integration.codex-headless` and
  `integration.codex-headless.policy` (`codex-e2e-chatgpt` and
  `codex-mcp-chatgpt` until 2026-10-15) are the API lane's
  `codex-headless.openai-key` and `codex-headless.policy.openai-key` run
  again with `MANDU_CODEX_AUTH=chatgpt` (variants of the same
  files, `credential: "subscription"`, `needs: chatgpt-login`). The switch is
  `tests/lib/codex-auth.ts`: each run writes a reduced copy of
  `MANDU_CI_CODEX_AUTH` (no refresh token) into its own fresh
  `CODEX_HOME` (never the path itself: Codex writes its own file), sets no
  `OPENAI_API_KEY`, gives Codex the launcher's sign-in provider
  (`codexProviderToml`, `requires_openai_auth`), and lets the openai-proxy
  relay each turn to the ChatGPT backend. Same scenarios, same oracles. By
  hand, pointing `MANDU_CI_CODEX_AUTH` at one's own sign-in is safe for the
  same reason: the run only ever holds a reduced copy, so it cannot rotate
  the source sign-in. Without the variable both SKIP with that reason.
- **What breaks it, and the fix.** A refresh the vendor accepted whose answer
  never reached the file (the host died between the two) spends the old
  refresh token: the next refresh is refused as reused. So does anyone else
  refreshing a copy of the same sign-in. Either way the fix is §9.6 step 1c
  again.
- **Into the guest.** `vm-run.sh --credential claude,codex` (the subscription
  kinds combine; `api` never combines with them, and `--lane api-key` refuses
  them) checks each kind's file, then `prepare` writes ONE tar holding both,
  the §9.3 disk. The codex member is the reduced copy (the allow-listed
  fields, no refresh token), refused when its access token does not cover
  the run's timeout plus five minutes. `boot.sh` places it in the guest
  (0600, owner `ci`, refused if it holds a refresh token) and deletes it
  before the results are written; `pipeline.sh` exports its path as
  `MANDU_CI_CODEX_AUTH`. In a
  guest, a 401 makes Codex try its own refresh, which fails without a
  refresh token: nothing rotates.
- **The canary.** `credential.mjs scan claude,codex` looks for every token of
  the HOST files: the agent credential, the Codex access and id tokens, and the
  refresh token the guest never had. A JWT's needles are the whole token and
  19-character pieces of its signature: its header and claims are shared by
  every token of the kind and would flag harmless output.

#### Tool credentials (built 2026-10-17)

Two of the demo lane's baselines (§9.9, §9.10) need an account of a
third-party tool, not of a model: Docker Sandboxes signs in to Docker, and
ggshield scans through GitGuardian's API. Each is its own credential kind,
`docker` and `gitguardian`, which a **subscription-lane** run carries beside
its subscription kinds (`--credential claude,docker,gitguardian`). An
**API-lane** run may carry `docker` beside `api` (`--credential api,docker`,
2026-10-19: Docker Sandboxes in the published battery, whose local
sandboxes Docker's FAQ calls free "including for commercial and
professional work"), never `gitguardian` (GitGuardian's free-plan terms bar
commercial use; ggshield is out of the published battery). `api` never
combines with a subscription kind (`parseKinds` and its `API_TOOL_KINDS`,
vm-run's own check), so the API lane's guest never holds a subscription
credential, and a tool token is never taken for a model key (each kind has
its own file, shape and check).

- **On the host.** One file per tool kind on the runner host
  (`MANDU_CI_DOCKER_CREDENTIAL`, `MANDU_CI_GITGUARDIAN_CREDENTIAL`
  override), each the bare token, no
  newline, mode 0600, owned by the runner's account (`checkFile`, as for the
  other kinds). Docker's sign-in also needs the account's username, which is
  not secret: `MANDU_CI_DOCKER_USER`, else the file `docker-user` beside the
  token. It is the Docker ID (the account handle), not the email: Docker
  Hub's own login takes either, but `sbx login` refuses the email ("docker
  token username does not match requested username", 2026-10-17), so
  `check` refuses one.
- **Placing them.** `credential.mjs install docker` (also spelled `install
  api --provider docker`) reads one token from stdin with the terminal's echo
  off (stty, not a shell `read`, so zsh and bash behave the same), refuses
  one not shaped `dckr_pat_…`, writes the file, and, when `docker-user` is
  absent, writes it from `MANDU_CI_DOCKER_USER` or asks for it on the next
  line (echoed); `install docker-user` writes the username alone, for a token
  already in place. `install gitguardian` (or `install api --provider
  gitguardian`) takes one GitGuardian token: GitGuardian documents no
  format, so the check is one word of 32 to 128 letters, digits, `_` or `-`,
  refusing a model key (`sk-…`), a GitGuardian test token (`ggtt-…`) and
  other vendors' known prefixes. Neither ever writes the API lane's file,
  and no message prints a token.
- **Into the guest.** The same disk as §9.3: Docker's `{"username",
  "token"}` and GitGuardian's `{"token"}`; `boot.sh` copies them into the
  guest (0600, owner `ci`, refused unless they hold exactly those fields),
  logs only Docker's username and the GitGuardian
  file's size, and deletes both before the results are written. The nightly
  stack exports their **paths**, `MANDU_CI_DOCKER_AUTH` and
  `MANDU_CI_GITGUARDIAN_AUTH`, never the tokens: the agent under test
  inherits the pipeline's environment, and the baselines read each file
  where they need it.
- **The canary.** `credential.mjs scan claude,docker,gitguardian` looks for
  19 characters of each token (Docker's with `dckr_pat_` stripped) in the
  console and the results, as for every kind; a hit withholds both.

**Tests:** `scripts/test/reduce-credential.test.mjs` (the api kind: install
per provider, the refusals, the disk, the canary over every key, the CLI
never printing a key; the codex kind: the kinds that combine, the host
file's refusals, the reduced copy's shape, `install codex` refusing a
personal sign-in, `refresh codex` against a rotating stand-in endpoint: the
request Codex sends, the rotated sign-in written back 0600, a refused,
unreachable or malformed refresh leaving the file byte for byte, two
concurrent CLI refreshes serialized by the lock; `prepare claude,codex` and
the canary finding 19 characters of each token; the tool kinds: their
shapes and refusals, both `install` spellings writing the bare token 0600
and never the API lane's file, the username from the variable, the file or the
next line, `install docker-user`, the disk, the canary, no token printed);
`scripts/test/ci-vm-run.test.sh` (`--credential api` and `--lane` on the
qemu line and in job.env; `nightly.sh --lane` for each lane, a missing
`--lane` refused; stand-in guests that leak the API lane's second key, the
Codex access token or the refresh token they never had, each caught and
withheld; `--credential claude,docker,gitguardian` on one disk,
`api,docker` on one disk for the API lane (no piece of a key or the token
printed), `gitguardian,api`, `api,docker,gitguardian`, `--lane api-key`
with only a tool kind and `--lane subscription` with `api,docker` refused,
and stand-in guests leaking either tool token, caught and withheld;
`nightly.sh` with no, a fresh, an unrefreshable-but-covering and an
expiring Codex sign-in); `scripts/test/suites-manifest.test.mjs` (the
check's lane rules, and the manifest's two lanes splitting the nightly's
selection with nothing lost and nothing in both);
`scripts/test/run-suites.test.mjs` (`--lane`);
`scripts/test/ci-workflow.test.mjs` (the nightly job's triggers, command and
role, no `nightly-api` job, no credential in a CI variable);
`tests/stack/agent-provision.test.ts` (`ullmCliUsable`).

### 9.9 The demo lane: Mandu beside other protections, on one machine (built 2026-10-16)

**Why in the guest.** The maintainers' demo drills are filmed under Mandu
and under baselines that run the agent with no Mandu at all: the bare agent
(`baseline-none`) and Claude Code's own protections (`baseline-cc-mask`,
`baseline-cc-deny`), each graded by a neutral recorder of the model traffic.
Two of those cannot run on a developer host that restricts unprivileged user
namespaces: Claude Code's own sandbox then fails every command, and the mask
side dials the drill's named hosts itself, so it runs only where
`/etc/hosts` sends each one to the run's sink. The CI guest has both by construction, so one controlled
machine produces every side's numbers. Filming for video stays on a
developer host (a terminal to watch); the guest is for the numbers.

**The image and the boot.**

- `provision.sh` installs `socat` and `ripgrep` beside `bubblewrap`: Claude
  Code's sandbox refuses to start without them (`failIfUnavailable`), and
  the image build fails if any of the three is not on PATH.
- The guest allows unprivileged ports from 80
  (`net.ipv4.ip_unprivileged_port_start=80`, in the image's sysctl file and
  again by `boot.sh`), so a live run's sink binds :80 and :443 as `ci`.
- `boot.sh`, after unpacking the checkout and before anything runs (the
  shell mode too), maps the demo drills' named hosts to `192.0.2.<slot>` in
  `/etc/hosts`, in one marked block, and redirects each such address's :80
  and :443 to `127.0.0.<slot>`, where a live run's sink listens (an
  nftables `nat output` rule per slot for the guest's own connections,
  table `mandu_ci_sink`, and a route through `lo`). A demo drill has a
  slot of its own (drills that name a host in common share one), from 2,
  as the generated list says (`<slot> <host>` a line), so cc-mask sides of
  two drills listen on two addresses and run at once (the battery's
  `MANDU_DEMO_JOBS`, drill-runner.md §3.9; 2026-10-17, before which every
  host was on `192.0.2.2` and every cc-mask side took its turn). Why not `127.0.0.2` itself: Claude Code's sandbox
  proxy refuses to dial an address that is loopback or one of the machine's
  own (2.1.295: `deny network-outbound api.mailer.test:443 (resolved to a
  loopback address)`, seen in the first rehearsal), so the mask side's sends
  never reached the sink. `192.0.2.2` is TEST-NET-1 (RFC 5737), which no
  real host answers: a missing redirect fails the dial, never reaches the
  internet. The pipeline's environment gets every slot's pair,
  `MANDU_DRILL_SINK_NAT=192.0.2.2>127.0.0.2,192.0.2.3>127.0.0.3,…`, from
  which the live runner listens on the drill's `127.0.0.<slot>` and probes
  its redirect (a TCP connect to `192.0.2.<slot>:443`) before a mask
  session, refusing it if the probe fails; a sandboxed entry's box (its own
  network namespace, without the rule) is not told. The list is a generated file of the
  maintainers' drill catalog (found with `scripts/drill-tree.mjs`, its
  `catalog/guest-hosts`; the catalog's generator writes it and its
  freshness check fails while a demo drill names a host the file lacks). It
  is read as `ci` and taken as data: comments, blank lines and one
  lower-case DNS name a line, at most 200; any other line and nothing is
  mapped. A checkout without the drill tree (the public one) maps nothing.
  Today: `api.stripe.com`, `api.notion.com` and seven `.test` hosts
  (`api.github.com` was one until demo-c1 moved to a `.test` support
  host, 2026-10-16). **So in the guest those hosts are the sink, not the
  internet**: nothing a nightly entry needs may reach them for real
  (`agent-latest.sh` takes goose's newest release by GitHub's download
  redirect, not its REST API, for that reason, which stays: a demo drill
  may name a real API host again; `ci-pins.test.mjs` holds it).

**The entries.** Three, all `manual` (they run only when named, never with
their kind, never per push), with `watchStore: true` so their runs are
collected as a drill entry's are (§6):

| Entry | What | Credential |
|---|---|---|
| `live.demo-battery` | every selected demo drill on every side (`mandu`, then each baseline), on each model, each take, one live run per side, then the comparison | `subscription` (the maintainer's go per run) |
| `live.demo-battery.api` | the same battery with every side on the Anthropic API key alone (`MANDU_DEMO_AUTH=api-key`, below "On an API key", 2026-10-18) | `api-key` (the maintainer's go per run) |
| `live.demo-battery.api.codex` | the same battery on Codex (`MANDU_DEMO_AGENTS=codex`, 2026-10-19), every Codex side on the OpenAI API key alone (the API lane file's `openai` key) and the sides Codex can take | `api-key` (the maintainer's go per run) |
| `live.demo-battery.rehearsal` | the same battery against a scripted stand-in model (`MANDU_DEMO_STAND_IN=scripted`: the drill's own replay script, its own seeded workspace and a Claude config with a dummy key, per side) | none: no token, no login |

Their choices are environment variables, which `vm-run.sh` carries from its
own environment into `job.env` (the job.env character set, `boot.sh`'s key
list) and `boot.sh` into the pipeline's: `MANDU_DEMO_IDS` (default every
demo drill), `MANDU_DEMO_SIDES` (default `mandu,baseline-none,
baseline-cc-mask,baseline-cc-deny`), `MANDU_DEMO_MODELS` (default
`sonnet,opus` since 2026-10-18, each model its own runs and rows; the
rehearsal `sonnet` alone, drill-runner.md §3.9), `MANDU_DEMO_REPEAT` (default 1), `MANDU_DEMO_JOBS` (default 6
sides at once, 1 to 8, `1` one after another; each with its own TMPDIR,
Mandu home and tmux session, the cc-mask sides of one drill in turn on its
sink address, drill-runner.md §3.9 "Sides at once"), `MANDU_DEMO_AGENTS`
(default `claude`; `codex`, or `claude,codex`: each agent its own runs and
rows, each side on the agents that can take it, a Codex model named
`codex:<model>` in `MANDU_DEMO_MODELS`, 2026-10-19). Both run with `--network` (the
suites then run unsandboxed in the guest, §9.4, in the namespace whose port
floor and `/etc/hosts` the boot set). The battery's own result is whether
every side ran to a grade: a baseline's leak is a measurement, not a red, and so is a side the
model's safeguards PAUSED (said apart, in no count of kept, done or both);
a side refused or LAUNCH-FAILED makes the entry fail.

**The rehearsal (no tokens):**

```sh
scripts/ci/vm-run.sh --worktree --network --only live.demo-battery.rehearsal \
  --timeout 5400 --demo-ids demo-scam-email,demo-api-401-debug
```

Each `MANDU_DEMO_*` variable has a `vm-run.sh` flag of its own
(`--demo-ids`, `--demo-sides`, `--demo-models`, `--demo-repeat`,
`--demo-jobs`, `--demo-agents`; `--timeout` for `MANDU_CI_TIMEOUT`), each winning over the
variable, so a battery's whole command starts with the script (2026-10-18:
an agent's permission rule for `scripts/ci/vm-run.sh` matches it, where a
command that sets a variable first does not).

**The real battery** (run it only with the maintainer's go for that run).
The subscription lane's credential (§9.3),
the host's Ollama for the drill whose Mandu side quarantines to a local
model (`--ollama`), and a timeout to match (four sides of six drills took
about one to two hours on Sonnet; the default runs Opus too, about twice
that; the token must outlive it, §9.3):

```sh
scripts/ci/vm-run.sh --commit <sha> --network --ollama --credential claude --lane subscription \
  --only live.demo-battery --timeout 14400 --demo-models sonnet,opus --demo-repeat 1 --out <dir>
```

**On an API key (built 2026-10-18).** The published numbers come from
`live.demo-battery.api`: the same battery in the API lane (§9.8), its guest
holding the vendor keys and nothing else. The entry sets
`MANDU_DEMO_AUTH=api-key`, under which the battery holds every side to the
one credential, so the comparison stays like for like:

- **Refused before anything starts** (exit 2, the reason in the log): a
  bearer credential in the environment (`CLAUDE_CODE_OAUTH_TOKEN`, which
  Claude Code would use instead of the key, or `ANTHROPIC_AUTH_TOKEN`); no
  `ANTHROPIC_API_KEY`, or one that is not an API key; a tmux server already
  running with another key or a bearer credential in its environment (a
  pane takes its environment from the tmux server; the guest starts none
  before the battery); and a side that needs a tool credential the API lane
  never carries: `baseline-ggshield` (ggshield scans through GitGuardian's
  API with the `gitguardian` credential; and GitGuardian's free-plan terms
  bar commercial use), which runs only in the subscription battery.
  `baseline-docker-sbx` runs on the key since 2026-10-19, in a run that
  carries the `docker` credential too (`--credential api,docker`; without
  it each of its sessions is refused, LAUNCH-FAILED): the key is stored in
  sbx as its docs direct for CI (`sbx secret set anthropic`, on stdin), the
  VM holds only the claude kit's placeholder, and the wire recorder puts the
  key on as `x-api-key` (drill-runner.md §7.10).
- **Each side's own Claude Code config**, seeded in the side's own
  TMPDIR and removed with it: a sanitized copy of the guest's (its settings
  and plugins, nono's among them) with no sign-in in it (no
  `.credentials.json`, no `oauthAccount` or `primaryApiKey`, no
  `apiKeyHelper`, `forceLoginMethod` or credential variable in the
  settings) and the key's "use this API key?" answer pre-approved, so no
  side stalls on the dialog or shows the key's tail on a recorded screen.
  The Mandu sides' launcher masks the key for the agent and puts it back at
  the model proxy (agent-sign-in.md §3.8, carrying the approval over to the
  placeholder); OpenShell's sides put it in a provider bound to the wire
  recorder (`x-api-key`); every other side's Claude Code reads it from its
  environment.
- **Checked after each side**: the side's own wire log must show the key
  (`x-api-key`) on its model calls and no bearer (`authorization`) on any
  (where the recorder itself put the credential on, Docker Sandboxes', the
  names it added, `credentialAdded`: what reached the vendor); a side that
  ran on anything else is NOT-GRADED (`CREDENTIAL MISMATCH`) and the battery
  fails, never a silent fallback.
- **What the API lane guest has**: the same image, so OpenShell (its
  MicroVM driver needs the guest's `/dev/kvm`, nested KVM, as in the
  subscription lane; its images are in the image's cache, nothing pulled),
  nono, fencepost and PrivAiTe (offline, its model cached) all run there;
  `--ollama` carries the host's Ollama in this lane too, for the drill
  whose Mandu side quarantines to a local model.
- **One risk the subscription lane has in another form**: a baseline
  agent's tools inherit `ANTHROPIC_API_KEY` (a user on an API key runs that
  way), as they could read the agent's credential file; an agent
  that prints its environment puts the key in its transcript, and the
  credential canary (§9.3) then withholds the run's results.

The run below is every demo drill on the ten sides of the 2026-10-19
battery, three takes on Sonnet and on Opus (2026-10-18, the battery's
default models): 540 live sides, twice the few hours of one model at six
sides at once (an estimate: the OpenShell sides boot a MicroVM per session,
the PrivAiTe sides load a model per session), so the guest's timeout (17 h)
is set past the entry's own (16 h; 8 h for Sonnet alone, `--demo-models
sonnet`):

```sh
scripts/ci/vm-run.sh --commit <sha> --network --ollama --credential api --lane api-key \
  --only live.demo-battery.api --timeout 61200 --demo-ids all --demo-repeat 3 --demo-models sonnet,opus \
  --demo-sides mandu,secrets-defaults,baseline-none,baseline-cc-mask,baseline-cc-deny,baseline-fencepost,baseline-privaite,baseline-openshell-docs,baseline-openshell-full,baseline-nono \
  --out <dir>
```

Docker Sandboxes (2026-10-19) is an eleventh side: `--credential api,docker`
and `baseline-docker-sbx` added to `--demo-sides`, a tenth more sides (its
first `sbx create` in a guest pulls the agent image, about three minutes):

```sh
scripts/ci/vm-run.sh --commit <sha> --network --ollama --credential api,docker --lane api-key \
  --only live.demo-battery.api --timeout 61200 --demo-ids all --demo-repeat 3 --demo-models sonnet,opus \
  --demo-sides mandu,secrets-defaults,baseline-none,baseline-cc-mask,baseline-cc-deny,baseline-fencepost,baseline-privaite,baseline-openshell-docs,baseline-openshell-full,baseline-nono,baseline-docker-sbx \
  --out <dir>
```

Its records are pinned as collected, as the subscription battery's are
(§6 "Pinned runs").

**Where the results land.** Each side is its own live run,
`demo-<stamp>-<drill>-<side>`, in the run's watch store; `collect_live`
carries its record files to `drills/live/<run>/` on the results disk and
the collector to the host's live store, `runs/drills/live/<CI run>.<run>/`
(§6), and `--out <dir>/drills/live/` for a job artifact: `report.json`,
`report.md`, `matrix.json`, `run.log`, the terminal recordings
(`terminal-*.cast`), and two data files the dashboard's file route does not
serve (`LIVE_DATA_FILE_RE`): a baseline's `wire.ndjson`, the neutral
recorder's log of the model traffic (credentials redacted at the source),
and `compare.md`, the battery's comparison (its headline, coverage and
head-to-head tables, one table over every drill, one per drill, and every
side's outcome), written into each side's run. The
comparison is also at the end of the entry's log
(`logs/live.demo-battery.log`). Over the `drills/live` caps the wire logs go
after the recordings and the event logs (§6). Everything on the results
disk, these included, is scanned by the credential canary (§9.3) before
anything is published. The collector **pins** a `live.demo-battery` run as
it collects it (the run directory and every side's live run, §6 "Pinned
runs"): a battery's numbers may be published, and its records are kept
until someone unpins them by hand, whatever ran since.

**Tests:** the catalog's own tests hold the generated host list fresh and
equal to every demo drill's named hosts, run `boot.sh`'s mapping function
on it and check that every demo drill's mask side is then routed to the
sink and never refused, and check the battery's plan (its configuration,
run ids, side outcomes and the footer the suite runner reads);
`scripts/test/ci-vm-run.test.sh` (the `MANDU_DEMO_*` keys in `job.env` and
`boot.sh`); `scripts/test/ci-pins.test.mjs` (the packages, the port floor,
no `api.github.com` in `agent-latest.sh`);
`scripts/test/ci-collect-results.test.mjs` (`wire.ndjson`, `compare.md`,
a collected battery comes out pinned and outlives the prunes);
`scripts/test/run-suites.test.mjs` (`watchStore`).

### 9.10 Third-party baselines in the image (built 2026-10-16)

The demo lane (§9.9) also measures third-party protections
(`baseline-fencepost`, `baseline-privaite`, `baseline-ggshield`,
`baseline-docker-sbx`), installed by `provision.sh` (under
`/opt/mandu-baselines`, but Docker Sandboxes' package) and run offline, but
ggshield, whose every scan is a call to GitGuardian's API, and Docker
Sandboxes, which signs in to Docker and pulls its agent image:

| Tool | Pin | What the image holds |
|---|---|---|
| fencepost (GPL-3.0-or-later), a Claude Code plugin | `FENCEPOST_VERSION` / `FENCEPOST_SHA256` (the release's `fencepost-v<v>.zip`) | `/opt/mandu-baselines/fencepost`, its plugin version checked |
| gitleaks (MIT), fencepost's secrets scanner | `GITLEAKS_VERSION` / `GITLEAKS_SHA256` (`install_release_bin`) | `/usr/local/bin/gitleaks`, its version checked |
| PrivAiTe (BSD-3-Clause), a redacting API gateway | `PRIVAITE_VERSION`; every wheel by sha256 in `scripts/ci/guest/privaite-requirements.txt` (`pip install --require-hashes --no-deps --only-binary :all:`), spaCy's `en_core_web_lg` 3.8.0 among them | a venv at `/opt/mandu-baselines/privaite`, checked to import and load the spaCy model offline |
| GitGuardian ggshield (MIT), Claude Code AI hooks that scan through GitGuardian's API (`baseline-ggshield`, added 2026-10-17) | `GGSHIELD_VERSION` / `GGSHIELD_SHA256` (the standalone `ggshield-<v>-x86_64-unknown-linux-gnu.tar.gz`) | `/opt/mandu-baselines/ggshield`, its version checked; it is the only baseline that needs the network and a key at run time: the guest's `gitguardian` credential (§9.8 "Tool credentials") |
| Docker Sandboxes (`sbx`, proprietary; local sandboxes free), Claude Code in a microVM (`baseline-docker-sbx`, added 2026-10-17) | `SBX_VERSION` / `SBX_SHA256` (`DockerSandboxes-linux-amd64-ubuntu2404.deb`) | the `docker-sbx` package (`/usr/bin/sbx`, its shim and microVM kernel, its AppArmor profile), the 24.04 guest only, its version checked; `ci` in the `kvm` group (the guest has nested KVM: `-cpu host`); at run time it signs in with the guest's `docker` credential (§9.8 "Tool credentials") and pulls its agent image |
| `openai/privacy-filter`, PrivAiTe's `onnx` model | `PRIVACY_FILTER_REVISION`; each file by sha256 in `scripts/ci/guest/privaite-model.sha256` | the Hugging Face cache at `/opt/mandu-baselines/hf` (the q4 ONNX model, its tokenizer and config, about 900 MB) |

PrivAiTe's wheels are CPython 3.12's, the 24.04 guest's `python3`: the 26.04
guest (kernel lane only) installs no PrivAiTe, and a `baseline-privaite`
session there is refused. The two packages add `python3-venv` and `unzip`
to the apt list. **Size and time:** the baselines add about 2.5 GB to the
image (the PrivAiTe venv about 1.4 GB, spaCy's model about 430 MB of it; the ONNX
model about 900 MB; fencepost and gitleaks a few MB) and a few minutes to its
build (downloads). To bump one: the new release's sha256 into `pins.env`;
for PrivAiTe, `pip download privaite==<v> --python-version 3.12
--only-binary :all:` and each wheel's sha256 into the requirements file;
for the model, the new revision and each file's sha256. The image key
covers all three files, so the next run builds the new image.

**The sandbox baselines (2026-10-17):** `baseline-openshell-docs`,
`baseline-openshell-full` and `baseline-nono` (the drill suite's sandbox baselines) run the
agent inside a sandbox:

| Tool | Pin | What the image holds |
|---|---|---|
| NVIDIA OpenShell (Apache-2.0), a sandbox with credential providers | `OPENSHELL_VERSION`; `OPENSHELL_CLI_SHA256`, `OPENSHELL_GATEWAY_SHA256`, `OPENSHELL_DRIVER_VM_SHA256` (the release's CLI, gateway and MicroVM driver tarballs) | `/opt/mandu-baselines/openshell/bin`, each binary's version checked |
| OpenShell's images | `OPENSHELL_SANDBOX_IMAGE` / `_DIGEST` (Docker's `buildpack-deps:noble-scm`: git, curl, CA certificates), `OPENSHELL_BOOTSTRAP_IMAGE` / `_DIGEST` (the root disk each MicroVM boots and unpacks the sandbox image in: Docker's `ubuntu:noble-20260930.1`, a public Ubuntu image in place of OpenShell's default NGC image `nvcr.io/nvidia/base/ubuntu:24.04`, so every image in the run is under a public license; the same Ubuntu 24.04 packages at the same versions as the NGC build it replaced, 2026-10-18) | the VM driver's image cache at `/opt/mandu-baselines/openshell/vm/images`, prepared once by `scripts/ci/guest/openshell-cache.sh` (a throwaway gateway creates and runs one sandbox from the pinned digests), so a run pulls nothing |
| nono (Apache-2.0), a Landlock sandbox | `NONO_VERSION` / `NONO_SHA256` (`install_release_bin`) | `/usr/local/bin/nono`, its version checked |
| nono's Claude Code pack `nolabs-ai/claude` | `NONO_CLAUDE_PACK_VERSION`; its profile by `NONO_CLAUDE_PACK_PROFILE_SHA256` | pulled (signed) into the CI user's `~/.config/nono`; its plugin's enable taken out of the user's `~/.claude/settings.json` so no other side runs it (the nono session enables it for itself) |

OpenShell's MicroVM driver opens `/dev/kvm`. The guest runs under KVM with
the host's CPU (`-cpu host`, §3), so with nested virtualization on the host
(`kvm_intel nested=Y`) it has its own `/dev/kvm`; the image puts the CI
user in the `kvm` group (checked 2026-10-17: `kvm_intel` loaded in the
24.04 guest, the ci user denied `/dev/kvm` before the group, a sandbox from
the pinned image created and run after). The image build needs it too: the
image cache is prepared in a MicroVM on the provisioning boot. **Size and
time:** the OpenShell binaries about 170 MB, the image cache about 700 MB
on disk (the bootstrap and the image root disks and an overlay template,
sparse ext4 files of 17 GB apparent size), nono a few MB; a minute of build.
To bump: the new release's three sums, the images' new digests.

## 10. What is dropped

- Docker as the CI boundary. `scripts/ci/docker-run.sh`,
  `scripts/ci/build-image.sh` and `Dockerfile.ci` stay for the hand-run
  docker rig ([`docker-e2e.md`](./docker-e2e.md) §1); no CI job uses them.
- `--publish-events` and the dashboard's `CI` chip, for the reason in §6.
- Every job of the retired pipeline that held a login on a push.

## 11. Open items

- `--shell`'s login shell has no job control (the serial console is not its
  controlling terminal).
- A runner host's dashboard shows only the runs that host executed (§6); a
  run on another host is read from its job artifact.
- The first live runs of the nightly's drills in `secrets` re-grade the
  drills of `S` and `S-mock` (test-organization.md §7.2).

**What the first full runs found** (all fixed when found; recorded because
each is a pattern that recurs):

- Suites that read the repository's git state needed a one-commit `.git` in
  the guest (§3).
- **A real launcher regression**: the git-remote auto-allow read the
  AgentView's shadow repository, which has no remotes (exec-routing.md
  §7.5). Every other red was a test bug:
  - fixed start polls and exit races (the arbiter's `lifeline`,
    `instance-mode`, `integrity-freeze-gate`, `event-store-durability` and
    the dashboard's server e2e files): condition waits with load-sized
    deadlines (90 s starts, 60 s SIGTERM-to-SIGKILL grace, since a
    SIGKILLed arbiter cannot tidy its registry entry); fixed short sleeps
    before log checks (`secret-readers-live`) became a 30 s poll;
  - reads racing a write (a manifest of an instance directory mid-creation,
    a pid or env file between its creation and its write): both now wait
    for the content;
  - shared state across test threads: the guard's unix allow-list test
    inherited a "stale" socket through another thread's `fork()`, and
    exec-supervisor's Landlock net test exec'd a probe script another
    thread's `fork()` could hold open for writing (unique names, run through
    `bash`);
  - a test assuming a non-empty ancestor chain (empty when cargo is the PID
    namespace's init), and TPROXY tests that found no `nft` on the `ci`
    user's PATH;
  - `ns-run.sh`'s overlay probe (`bwrap --help | grep -q`) under `pipefail`:
    `grep -q` exits at the first match, bwrap's second write died of
    SIGPIPE, and under load the probe said "no overlay". grep now reads to
    the end; `ci-ns-run.test.sh` pins it with a stand-in bwrap whose help
    runs 300 KB. The test's own probe kept `grep -q` until 2026-10-03
    (a red master run: bubblewrap 0.11 read as "overlay: 0", so the
    two refusal checks expected a refusal ns-run rightly did not give);
    it now reads to the end too. The same race in `net-guard-live`'s checks
    (pipeline 11108): `echo "$out" | grep -q` under `pipefail`, and bash's
    echo writes into a pipe a line at a time, so a match on the probe's
    first line (`127.0.0.1:<port> CONNECTED`) could kill the second write
    and read as "the allowed IP was blocked". Its checks read a here-string
    now (`has`, a whole-line literal match), which has no writer to kill.
    `landlock-net-live`'s skip probe had the same pipe (2026-10-18; at
    worst a kernel without Landlock TCP-net failed instead of skipping)
    and reads a here-string too; `dev-arbiter.sh`'s environment check
    (`tr … | grep -q`) reads to the end. A loop of `printf '%s\n' "$list"
    | grep -q` over a 2,000-line list whose first line matched failed 110
    of 200 times under `pipefail`, the here-string 0;
  - two timing ratios that load moved: the `events` 16 MB reply now bounds
    the process's CPU time instead of wall time, and the secret catalog's
    100k-path throughput ratio is replaced by a test of the per-home prefix
    memo itself (`normalizedPrefixes`);
  - the differential shards' quit loop pressed ^C again after a fixed 3 s
    window; with claude gone the pty is cooked again, so that ^C killed the
    wrapped launcher during its teardown. The harness now presses only while
    the TUI holds the pty in raw mode and gives the exit its own 60 s
    deadline (differential-interactive.md §21;
    `differential-quit.test.ts`);
  - a stub that answered after one read: `secret-readers-live`'s stub
    ssh-agent answered and closed after a single `recv`, but `ssh-add`
    writes the request's 4-byte length and its body separately. When the
    first `recv` returned the length alone (a loaded host: 2026-10-04, 3 of
    40 runs with 8 copies in parallel and every CPU busy, 3 pipelines in a
    day), the admitted `ssh-add` died of SIGPIPE on its second write, with
    no output, which the check read as a refusal. The stub now reads the
    whole length-prefixed request, as an agent does, and the test prints
    the signal that killed a program instead of an empty output;
  - a check made before a reader thread could append: net-supervisor's
    `agent_flow_integration` asserted the unbound sink held the agent's own
    `AGENT-LIVE` the moment the guarded child returned, while the sink's
    per-connection thread was still reading (pipeline 8591; the send had
    reported `sent`). Under load in the guest (4 vCPUs, 12 CPU burners) the
    immediate check failed 4 of 40 runs; it now polls for up to 5 s
    (`sink_received`), 0 of 40;
  - fixed reader deadlines shorter than a loaded holder (2026-10-21, CI
    jobs 18268 and 18285, and an earlier 240 s STUCK in the same file):
    in `agent_flow_integration` the agent role gave up on its own clock
    (the FIFO `drain` after 5 s, `read_some`'s 3 s `SO_RCVTIMEO`, `wait_for`'s
    5 s) while a holder's first secret read took over 7 s on a busy host.
    The agent then closed its end first. In the FIFO test the holder's
    blocking `O_WRONLY` open met a FIFO with no reader and waited forever,
    in the guard worker that performs it (`wait_for_partner`), as it would
    with no guard: STUCK at 240 s. In the keep-alive test the server read
    its secret with the agent's end of its connection already gone, and the
    sweep rightly refused the raw open (`e13`). The same load also made the
    fixed 800 ms wait for the guard's close report miss. Reproduced on a host
    with 4 to 5 CPU burners per core: the FIFO test failed 7 of 20 runs (2
    of them the job's exact STUCK, the agent's 5 s over before the holder
    read its secret), and the whole file 3 of 6 (both reds of the jobs
    among them). The agent now reads until
    the holder reports it is done (FIFO) or the peer closes, under the run's
    wait limit (`wait_limit`), and waits for the close report itself (the
    mock arbiter marks it, each test's mock its own file: one marker for
    the file let a guard's late report stand for the next test's); the same
    load then gave 0 of 20 and 0 of 6, and the CI guest in the kernel
    lane's namespaces (8 vCPUs, 8 CPU burners) 0 of 29. Not
    a guard bug: the guard answers each of these calls as the kernel would.
    Left open, found on the way: a guard worker that performs a FIFO open
    still blocked for its peer stays blocked after its tracee is killed
    (the call is gone), until some process opens the other end, which then
    meets a writer that comes and goes; a probe that killed the writer saw
    the worker in `wait_for_partner` after the supervisor returned. Each
    such worker counts against the guard's 64 (`spawn_worker`);
  - two tmux races in the drill runner's pane tests (pipelines 7649, 8605,
    8825, "first program never showed"): a stand-in program that wrote and
    exited at once lost its output to tmux's pty close, and a
    `new-session` right after the last session's `kill-session` can meet
    the exiting server;
  - two checks made on a timer instead of a condition (2026-10-18, each 1
    red in about 110 runs): `differential-cleanup.test.ts`'s scratch owner
    ended "by exit" exited on its own 100 ms after printing its dirs, so a
    parent slower than that (master pipeline 11658) found them already
    removed and failed "the dirs exist while the owner runs"; the owner now
    exits when the parent tells it on its stdin, after the check (an exit
    at 0 ms reproduced the red every time). `dev-arbiter.test.sh`'s stale
    pid file named `setsid sleep 600 &`'s `$!` before setsid(1) had run in
    it (pipeline 11654): the group had no member yet, so `stop` rightly
    read the file as "already gone", exited 0 and removed it. The test now
    waits for the group to exist (and its SIGKILL case for both members)
    and checks that it did; a stand-in setsid that runs 1 s late reproduced
    both reds before and passes after. The "run aborted" line logged just
    before the first red is the next test's, which aborts its run on
    purpose;
  - a reset read by the connect (2026-10-18, pipeline 11803, 1 red in
    about 30 runs): `holder-accept` read a leg as refused only when the
    client's `recv` met the reset, but python's timed connect is a
    non-blocking connect, a poll and `SO_ERROR`. The kernel completes the
    handshake before any accept, so when the guard's accept and reset
    (`SO_LINGER` 0) landed before the client's poll woke, the connect itself
    answered ECONNRESET ("connect-e104"; an RST to the SYN would be
    ECONNREFUSED). The server's accept still answered ECONNABORTED and no
    byte crossed. Both readings are a refusal now (`refusedLeg`, with a test
    of its own); data, a reset after data, a hang or any other connect error
    still fail, and the accepts' check still asks ECONNABORTED for each
    refused leg. A client held between its connect and its poll reproduces
    the reading. Two stack tests that ran the arbiter beside jsdom failed
    in the same run on its clients' 5 s timer (test-organization.md, *An
    in-process arbiter's clients take a long deadline*);
  - **a real guard bug behind a red that looked like a missing ask**
    (2026-10-18, pipelines 11765 and 11856, 2 reds in about 95 runs):
    `write-protect.test.ts` failed "the workspace copy was not asked about
    under its own path". The copy of tee that `cp` had just written never
    ran: the guard performs a write-capable open and hands the tracee its
    own open file description (ADDFD), and it closed its descriptor only
    after the answer that woke the tracee. A guard thread descheduled
    there kept the file open for writing while `cp` exited and bash exec'd
    the copy, which met ETXTBSY (exit 126, its output sent to /dev/null).
    The refusal was fail-closed (the write did not happen) but no question
    was filed, and any agent's `cp prog ws/p && ws/p` or `cc -o a && ./a`
    could fail the same way. `guard-written-exec.test.ts` reproduced it at
    96 to 182 of 2000 copy-and-run loops on a 4-vCPU guest; the guard now
    closes a write-capable descriptor before it answers
    (confidentiality-plan-10-flow-taint.md §4.1a,
    "The descriptor handed over"), 0 of 6000, and the write-protect test
    names an exit 126 as the copy never having run. The kernel test that
    pins the order failed once on master right after (pipeline 11893,
    `rust.kernel`): it held the guard side's descriptor in the test binary,
    whose other tests fork from their own threads, and a child forked in
    that moment kept a copy of it. Its guard side now runs in a process of
    its own (plan 10 §4.1a).
  - **a real exec-supervisor bug behind a lost clean verdict** (2026-10-18,
    hourly master pipeline 11899, 1 red in the 89 kernel runs its runner
    host kept): `clean_box_completes_and_reports_the_hash_bound_verdict` ran its
    command to exit 0 but reported no clean verdict (`clean: None`). The
    clean attempt's capture pipes were plain `pipe(2)`s, and a process
    another test thread spawned in the moment they existed in the parent
    (a long `mandu-exec-box` run, a box child's bwrap) kept their write
    ends for as long as it ran. Since 2026-10-17 the drain gives up 2 s
    after the box exits with its pipes still open (`DRAIN_GRACE`,
    exec-routing.md §4.4), so the attempt was voided and the command rerun
    in the ordinary box. `clean_box_verdict_survives_concurrent_spawns`
    (two threads spawning a 4 s `sleep` through six clean runs) reproduced
    it at 8 of 18 runs in the guest; the pipes are close-on-exec now
    (`capture_pipe`), 0 of 36. The same leak let a box spawned on another
    thread write into the clean attempt's captured stdout. `mandu-exec-box`
    runs one exec per process, so the product was not exposed; a threaded
    caller of `supervise_exec` was.
  - **a real runner gap behind a git sandbox kill that "did not close"**
    (2026-10-21, CI jobs 18255 to 18296, 10 reds in the 22 runs after the
    delegated cgroup of §3 landed, none in the 50 before): the arbiter's
    `child-run.test.ts` "bubblewrap … killed in its start-up" found calls
    whose output stayed open 5 s after the kill. bubblewrap's sandbox child
    (the sandbox's pid 1) calls setsid and only later, after it forked the
    command, arms `--die-with-parent`, with no check that bubblewrap still
    lives; a kill in between reached bubblewrap's group but not the
    sandbox, which ran the command to its end. An idle host showed it too:
    with `sleep 3` in the sandbox, 2 of 8192 kills (the CI guest, bubblewrap
    0.9.0: 3 of 2048) left it running its 3 s. `git --version` ends in
    milliseconds, so the test saw it only once nice 19 starved it: with the
    suites in one cpu cgroup the test's duration went from 2-4 s to 9-13 s.
    In the product, a killed git call (a deadline, a `stop()`) ran on. The
    runner now kills the descendants it reads just before the kill too
    (write-protection.md §8.5.1), 0 of 2048 in the guest; a new test runs
    `sleep 300` in the sandbox, which fails without it on an idle host (3
    of 512). The start-up tests' kill grace is 120 s: at nice 19 in a guest
    with four busy loops per vCPU, killed processes waited seconds for the
    CPU to exit, and killed bubblewraps sat up to 64 s in the kernel (state
    D, `rtnl_lock`, in the clone that makes the network namespace) with
    nothing left running; neither window's process closes within it.
  - **a CI environment change behind a replay drill timeout, not a
    commit** (2026-10-21, `integration.replay-openclaw`'s `util-reasoning`
    TIMEOUT, "launch 0: the TUI never showed its composer", in jobs 18289
    to 18323, master's own included, and on branches cut before the day's
    merges): the first drill of the suite runs in the run's busiest
    minutes, and from the first run on the delegated-cgroup image (job
    18248, image `mandu-ci-111e5ca9…`) it took 117-223 s instead of
    35-50 s; the agent's screen arrived uniformly 2-4× later (its composer
    at 76-92 s instead of 23 s, against the replay's 90 s boot wait for
    OpenClaw, 45 s scaled ×2), so it passed or timed out by a few seconds.
    The image had switched `cpu` on (`Delegate=yes`, and `boot.sh` asked for
    it), so the suites left the root cpu task group and with it the
    autogroups that had given each session its fair share (§3). The unit
    now delegates `memory pids` and `boot.sh` never switches `cpu` on; the
    guard's cgroup test still finds its user-owned cgroups. A replay that
    passes only by luck of the clock is the pattern: compare its timings
    before and after the image, not only its verdict.
  - **five reds of one day's flake sweep** (2026-10-21; counted in the kept
    runs of the CI runner host):
    - `launcher.component3`'s `test-owner-cleanup.test.ts` failed
      `ENOTEMPTY, rmdir '<tmp>/tsx-1000'` in its cleanup (jobs 18107 and
      18368, master's; 2 of about 100 runs). The test SIGKILLs a launch
      mid-way, and per-session services the launch had just spawned (the net
      proxy, the exec shim of a `curl` probe) were still loading through tsx,
      writing its cache under the launch's TMPDIR, after the sweep: they
      carry no `MANDU_RUNTIME_DIR`, which is what the sweep finds, and see
      their cut lifeline only once loaded. A snapshot in the guest showed
      both alive after the sweep and the cache growing from 802 to 824
      entries in the next 3 s. The retries added that morning
      (`rmSync`'s `maxRetries`) retry only the failed `rmdir`, never the
      walk, so an entry created after the walk fails every retry: job 18368
      slept 47 s in them and failed anyway. The cleanup now waits (60 s,
      then SIGKILL) for every process whose env names the test's TMPDIR,
      and removes the tree walking it again on each pass. The test's own
      claims (the dashboard and the arbiter gone, their registry entries
      removed) are unchanged. 0 of 36 in the guest beside 8 CPU burners.
    - `launcher.component3`'s `demo.test.ts` "sabotage: a guard whose
      reports the arbiter cannot believe" passed the sabotaged run (job
      18346; 1 of 122 runs). The sabotage was an explicit
      `MANDU_ARBITER_HUMAN_SOCK` naming the data socket: the guard's start
      refused it, but its looker (`report_channel::decide_upgrade`, first
      after 250 ms) ignores the variable, re-learns the human socket from the
      data socket's `hello` and moved there under every check, so a Codex
      read after the move was believed. The upgrade is right: what the data
      socket's `hello` names is fixed by the arbiter at its start
      (`humanSockPath` of its base and instance id), no data-plane request
      changes it, and the move still requires the walled directory, the
      private place, `channel: human` for the same instance and the same
      listening process outside the guard's tree. The sabotage is now a
      guard policy with no `unixDeny`, which can believe no human socket at
      its start or in any look (the looker is not started), and the test
      checks the guard said so (mandu-demo.md §7). 0 of 18 in the guest.
    - `integration`'s `nested-claude-route.test.ts` "mandu -- sh …" saw 0 of
      2 starts of its stand-in claude (one local full run; 1 of about 245
      runs), with no launch output: the starts were checked before the
      launch's exit. Every check of the oracle now carries the launch's exit
      and its output's tail. Not reproduced: 0 of 18 in the guest under load;
      the next red names its cause. A second hunt (2026-10-22) did not
      reproduce it either: 0 of 2,396 runs of the test in the guest, in five
      shapes (a box per run, 12 and 32 at a time beside 8 and 48 CPU burners;
      one shared box, as the entry's files share one, 24 and 40 at a time on
      32 and 16 vCPUs, the slowest runs at 32 s against the red's 13.5 s;
      10 at a time beside three whole passes of the entry's
      `stack/*.test.ts`, all green). Ruled out by reading: the per-session
      net proxy and the session's shims carry no `MANDU_RUNTIME_DIR`, but
      inherit the launch's `XDG_RUNTIME_DIR` (the rig's own directory, so
      the base they resolve is the launch's), and the `claude` shim reads no
      runtime directory at all (its route is baked into it); no pids limit
      (the guest's unit has TasksMax 77114); no arbiter deadline on the
      shim's path (its route and refusals are pure, and the guard's exec
      trap never refuses an exec). What the red does fix: the stand-in
      wrote its record only when its request ended, so a start that threw
      first (an unreadable file, a write refused) left no trace, the same
      as one that never ran. It now writes a trace when it begins (its
      arguments) and when a throw ends it (the stack), every oracle failure
      prints the trace, both nested claudes run whatever the first one's
      end, the shell prints both exits, and the refusals test checks that
      the stand-in never began.
    - the inspector's `sessions-scale.test.ts` (in `private/`) bounded the warm
      `/api/sessions` by wall time, under 2000 ms, and one local full run
      measured 2080 ms beside a cold listing of 54 s (local full runs 50-54
      s; CI 20-36 s). Alone in a guest the same listing takes 1.5 s cold
      (1.0-1.9 s of CPU) and under 0.1 s warm (60-90 ms of CPU, 16 runs
      beside 12 CPU burners): the wall times
      measured the share of the CPU the file got, which per-session fair
      sharing (§3) gives the suite's session as a whole, not the code. The
      absolute bound is now the warm request's CPU time (under 1000 ms, and
      under a quarter of the cold pass's), the wall-time ratio stays; a warm
      pass that re-read the store would cost the cold pass's CPU again. No
      code change: nothing in the timings points at the listing, and a
      process of its own (an entry for one file) would still share the CPU.
    - `vm-run.sh --worktree` sent the inspector's relative links (in `private/`)
      (`fixtures`, `test/fixtures`, `public`) dangling: GNU tar's
      `--transform` rewrites link targets too, so `../../dashboard/fixtures`
      arrived as `src/../../dashboard/fixtures`, and the suite's fixture
      reads failed ENOENT (local run 20261021-105403; a commit's run, `git
      archive`, was never affected). The transform takes the `S` flag
      (lib.sh `ci_source_tar`); `ci-vm-run.test.sh` unpacks a relative link
      and follows it.

Three more per-push reds of the same weeks were already explained: the
real-config `fidelity-permission-prompt` (`$MDU:nomodel_Read` on screen,
pipelines 8551, 8607, 8633, 8636) was a real reply-filter gap, the inline
renderer splitting a token by cell diff, fixed by !601 (no red in the 37
runs after it); `secret-readers-live`'s stub
ssh-agent is the item above; the dashboard's `scenario-cache-restart`
("the restart answered without the child") is tracked on its own.

**The lesson that generalizes:** for a suite that is allowed to self-skip,
assert the COUNT, not the colour. A green from a suite that ran nothing looks
exactly like a green from one that ran clean (docker-e2e.md §1 has the case
that taught it).

## 12. Public CI on GitHub

The public repository's workflows give a pull request the part of the
per-push run that needs no privilege, no credential and no special hardware:
the manifest's sealed kinds, `unit`, `component` and `stack`
([`test-organization.md`](./test-organization.md) §3). **GitHub does not run
the `replay-drill` or `sandbox` kinds, the nightly kinds, the install matrix
or anything on macOS** (§12.2); the first four run in the VM of §3 (the
maintainers' CI, or `vm-run.sh` by hand), macOS on a maintainer's Mac.

### When GitHub runs (decided 2026-10-09)

GitHub's minutes go only where GitHub is the only signal: the exported
tree's own test, the release, and outside contributors' pull requests.
Everything else the GitLab pipeline already ran, a superset, on the same
commit (§12.3).

| Trigger | `CI` (`ci.yml`) | `Release` (`release.yml`) | When |
|---|---|---|---|
| a snapshot push to `main` or `master` | never | never | no `push` trigger: GitLab ran a superset on the commit |
| a `v*` tag | yes, called by `release.yml` (`workflow_call`) | yes | the release check, then the pack and, after a maintainer's approval, the publish (§12.5) |
| by hand | yes (`workflow_dispatch`) | never | a check of any snapshot |
| a pull request, while the repository is private | skipped | never | every root job's `if` admits only a run that is not a pull request there |
| a pull request, once public | yes, unless it changes documentation only | never | a newer push cancels the older run (`cancel-in-progress`) |

**No macOS on GitHub (decided 2026-10-09).** A macOS runner's minutes count
ten times against a private repository's quota (one run of the darwin
entries, about 30 real minutes, was about 300 quota minutes), and the suite
needs a Mac's judgment anyway (a Seatbelt or PTY failure is read on the
machine). A maintainer runs the manifest's darwin entries on a Mac by hand
after a change to the darwin code
([`development.md`](../../development.md), "Developing and testing on macOS");
since 2026-10-21 that run is not a release gate (a release neither runs nor
waits for it; [`packaging.md §11.3`](../distribution/packaging.md)).
The `macos-wrapper.yml` workflow and its path gate were removed;
`scripts.suites-manifest` checks that no workflow job runs on a macOS runner.

**Why only a manual run while private.** A private repository on the free
plan draws its Actions minutes from a monthly quota of 2000: in October 2026
the quota was spent by the 9th (1380 Linux minutes, 60 macOS ones at ten
times the rate), at about 93 billed minutes for `CI` per push. So every job
without a `needs` carries `if: !github.event.repository.private ||
github.event_name == 'workflow_dispatch'` (alone, or AND-ed with one further
condition), and the jobs that need them skip with them; a skipped job bills
nothing. The repository is public since 2026-10-19, where standard runners
draw no quota, so the gate no longer skips anything; it stays for a fork or a
return to private. The release workflow refuses to run on a private
repository: its check is this workflow, whose jobs would all skip there, and
a check of skipped jobs would pass.

**A documentation-only pull request runs no `CI`.** The `pull_request`
trigger has a `paths` filter, `**` then `!docs/**` and `!**/*.md`, then
`launcher/README.md` and `**/fixtures/**` back in: the same cut as the GitLab
docs lane (§5.5, `scripts/ci/lane.mjs`). GitHub selects a request when any
changed path's last matching pattern is not a `!`, so a request that also
touches code runs. `paths-ignore` cannot re-include the docs lane's two
exceptions, so the filter is a `paths` list. The docs-lane suites (links,
anchors, the context pack) run on such a request when a maintainer lands it
through the VM run (§12.3). `scripts.suites-manifest` checks the filter
against `isDocsPath` over every tracked file.

**Reruns.** A red run is re-run once, failed jobs only (`gh run rerun <id>
--failed`), never as a whole run: a whole rerun bills every green job again.
A second failure is a bug, fixed on GitLab and exported again. An arbiter
start that did not come up is no longer the expected cause (§12.1, "Waits
for a started arbiter double on CI"): read the failing suite's log tail
before rerunning.

**Caches.** With no push trigger, the default branch's caches (the npm cache,
`interceptors/target`) are written by manual runs on `main` (`gh workflow run
ci.yml`); a pull request reads them. A release run caches under its tag,
which no other run reads. Once the repository is public, do not make
`CI`'s jobs required status checks: a documentation-only request never
reports them and would wait forever.

Once the repository is public, where standard runners are free, the
pull-request rows start with no edit. `scripts.suites-manifest` checks the
gate on every root job of `ci.yml`, that only `release.yml` has a tag
trigger and no workflow a branch push or schedule trigger, the `CI` docs
filter, and that no job runs on macOS; `scripts.release-workflow` checks the
release workflow (§12.5).

### 12.1 What GitHub runs

`.github/workflows/ci.yml`, on `ubuntu-24.04`, by hand and on a pull request
that is not documentation only (above):

| Job | What it runs | Manifest entries (`tests/suites.mjs`) |
|---|---|---|
| `packages` | lists every tracked `package-lock.json` | the directories `node scripts/suites.mjs packages` names |
| `ts` (matrix, one cell per package) | `npm ci` in every package, then `npm run typecheck` and `npm test` in the cell's package | `typecheck.*`, the package entries (a sharded entry such as `launcher` runs whole), `eval.lib` |
| `shell` (one job) | `npm ci` in every package, then `node scripts/suites.mjs list --kind unit,component,stack --platform linux --json --public`, reduced to the entries whose command is `bash` or `node` and that do not need cargo, all run by `node scripts/run-suites.mjs --only <ids> --jobs 2`: each entry's cwd, command, env and timeout plus the fixed test env | the sealed `launcher.*-live` (not `internet`) and `scripts.*` entries, `matrix.smoke` |
| `rust` | the listing's entries that need cargo (the complement of `shell`'s filter), through `node scripts/run-suites.mjs --only <ids>` at the workspace's `rust-version` (1.75.0) with the `aarch64-unknown-linux-gnu` target and the clippy component installed; a skipped entry fails the job | `rust` (`cargo test`, default features), `rust.check-aarch64`, `rust.clippy` (§14.1), `fs-preload.redirect` |
| `audit` | cargo-audit installed from the pinned release (`scripts/ci/pins.env`, sha256-checked), then `node scripts/run-suites.mjs --only deps.audit-npm,deps.audit-cargo --strict-skips` | `deps.audit-npm`, `deps.audit-cargo` (§14.2; kind `env`, `internet`, run by id) |

Every sealed, Linux, public entry lands in exactly one job.
`scripts/test/suites-manifest.test.mjs` checks this without a GitHub remote:
it runs the workflow's own `packages`, `shell` and `rust` list steps
against the current manifest, and parses every workflow (their `needs` and
`outputs` name what exists).

Choices worth stating:

- **Packages are found, not listed.** The workflow derives the matrix from the
  lockfiles, so a new package is covered without editing the workflow.
- **Every cell installs every package.** `tests`, `tests/conformance` and the
  launcher's e2e suites import or spawn sibling packages from source, and
  Node resolves a sibling's dependencies from that sibling's own
  `node_modules`. The guest image (`scripts/ci/vm-image.sh`) bakes all of
  them in for the same reason. With the npm cache warm this costs a few
  seconds per package.
- **Node 22.13.0, the engines floor.** The same pin as the guest image
  (`scripts/ci/pins.env`): testing the floor catches a newer-Node API before
  a user on the floor does.
- **No product environment variable in the matrix.** Each package's `npm test`
  script sets the axes-strict flag itself
  ([`protection-modes.md`](../architecture/protection-modes.md) §4), and the
  suite runner (`scripts/run-suites.mjs`) sets it for every entry the
  `shell` and `rust` jobs run.
- **One job for the shell entries, not a cell each** (2026-10-09). The
  thirty-odd cells of a matrix did about 30 s of checkout, setup and test each, and
  GitHub bills every job by the whole minute: about 35 billed minutes a run
  for a few minutes of work. `run-suites.mjs` does not stop at a failure, so
  one failure still does not hide the rest (its summary names each), and a new
  sealed shell or script entry in the manifest joins the job without a
  workflow edit. The `ts` job keeps a cell per package: its large cells are
  minutes of real test time each.
- **Waits for a started arbiter double on CI.** GitHub's runners have few
  vCPUs, and a job's first arbiter start runs with a cold tsx cache while the
  job's other test files compile their own imports. In the beta.5 snapshot's
  green run, the launcher job's first start (`agent-config-delivery`) took
  13.5 s of a fixed 20 s wait, against about 1 s later in the same job, and a
  few launcher and `scripts.dev-arbiter` starts missed their waits now and
  then (the staging run before beta.5, rerun once). The suites and
  `scripts/dev-arbiter.sh` now share one budget instead of fixed waits of
  their own: the launcher's load-aware readiness deadline, doubled where `CI`
  is set (GitHub and GitLab set it), and `MANDU_SERVICE_READY_TIMEOUT_MS` sets
  it exactly. A wait still ends when the socket appears or the started process
  exits, and a refusal says how long it waited, against what budget, and the
  log's last lines ([`runtime-instances.md`](../architecture/runtime-instances.md)
  §14.6, "Tests and the dev arbiter"). A failure past that budget is a hung
  start to look at, not a reason to rerun. The first staging run on the
  shared budget (2026-10-09) passed on its first attempt with no
  arbiter-start timeout. Since 2026-10-18 such a start FAILS its suite with
  the arbiter's log's last lines in every suite, shell and kernel lane
  alike, and never SKIPs it to green
  ([`test-organization.md`](test-organization.md) §8.11), so the log of a
  red run already says why.
- **Git sandbox probe unit tests do not require a host sandbox.** The
  version-retention and retry cases inject the candidate binary lookup as
  well as the process runner. A host without bubblewrap must still exercise
  the simulated Linux probe, just as it exercises the simulated macOS
  probe. A separate absent-candidate case asserts a final `null` sandbox
  without invoking any runner. Real confinement stays in the kernel and
  macOS live suites (§12.2); no production probe is bypassed.
- **A stack test whose subject depends on the launch's wall probes the host
  the way the launcher does** (2026-10-23). With no file guard
  (`MANDU_NO_KERNEL=1`), only the bind wrap walls a launch off from the
  human plane, and the wrap needs a bubblewrap that can make a user
  namespace, which this runner's AppArmor restriction refuses (§12.2). A
  launch with no wall has every report it makes stored as a claim
  ([`arbiter-human-plane.md`](../architecture/arbiter-human-plane.md) §10.1),
  and Home counts no claim. So `tests/stack/session-end-kept-line.test.ts`
  asks the launcher's own facts (`systemBwrapBin` and `probeUserns`) which
  host it is on: where the wrap can go up, it requires the walled record and
  the line that counts the `.env`; here it requires the host's gap, every
  event a claim, and the line that matches Home's count of none. The branch
  follows the probe, never the launch's output, so a walled host whose
  launch lost its wall still fails. GitHub's run of the snapshot before
  beta.8 (2026-10-22) failed this test before the probe was added.
- **A browser's teardown waits for its whole process group** (2026-10-23).
  Chromium's helpers (zygote, renderers, the GPU and network services, the
  crash handler) keep writing into the profile for a moment after the main
  process exits. A profile removed when only the main process was gone
  failed with `ENOTEMPTY` (`settings-notify-off`, the same run; an earlier
  release run was retried for the same thing). `scripts/tour-screenshots.mjs`
  `startBrowser` now starts the browser as the leader of its own process
  group, and `stopProc` sends the group SIGTERM, then SIGKILL, and returns
  only once no process of the group is left (a group still alive when the
  test process exits is killed then); `removeProfile` removes the directory
  with retries. Every stack test that drives a page through it gets this;
  `tests/lib/chromium.ts` `stopChromium` waits for the group the same way.
  `tests/lib/teardown.ts` `withTeardown` runs a test's teardown steps
  without letting a failing one replace the test's own error, as a throwing
  `finally` does.

**macOS, before it moved off GitHub.** A `macos-latest` workflow ran
`scripts/test-all.sh --kind unit,component,stack,sandbox`, which on darwin
selects the manifest's darwin entries, until 2026-10-09. Its first runs that
reached the suites (2026-10-09, after `bootstrap.sh` was made bash-3.2 safe)
failed 7 of 26 entries, and `launcher.component2` hung until its 1800 s
timeout. The hang was a Linux-only test (`setsid(1)` and `ps -o sid=` do not
exist on macOS, and an unbounded shell wait spun); it now probes and SKIPs,
and its shell is bounded. Two failures were product bugs on macOS. First, the
session-end teardown of the agent's process tree found nothing once the
reply filter was started early, so the agent's background jobs outlived the
session inside the Seatbelt wrap (`portable-wrapper.md` §10.3.5, "The age
floor is the chain's spawn"). Second, the CLI cut off a `--json` document
longer than 8 KiB written to a pipe. The rest were tests with Linux
assumptions: `/proc`, GNU `mktemp`, platform defaults, the shell's own
variables, and a darwin-only test that missed a routing change. The fixes
await their confirming run on a Mac (development.md lists the pitfalls).


### 12.2 What GitHub does not run, and where it runs

| Left out | Why | Where it runs |
|---|---|---|
| The `sandbox` kind and the other entries that need `kernel` (`scripts/kernel-tests.sh`, net-guard, exec-box, landlock-net, secret twins and readers, guard-death live; the `kernel` cargo feature) | They need an unprivileged user namespace with a working uid map. The `ubuntu-24.04` image sets `kernel.apparmor_restrict_unprivileged_userns=1`, so `unshare --user --map-root-user` fails. They would self-SKIP to a green that proved nothing. | the per-push VM run, which sets the sysctl to 0 (§3) |
| The `replay-drill` kind | It drives the real claude, codex, openclaw and opencode CLIs, pinned in the guest image, against a scripted model. Without those CLIs the suites self-SKIP. Porting them needs the pinned installs and a flake record on GitHub's runners first. Its entries are the maintainers' drills and are not in the public tree (§2). | the maintainers' per-push VM run |
| The `live-drill`, `env` and `eval` kinds | A local model, a real model with a login and its quota, or the internet. The two dependency-audit entries are the exception: the `audit` job runs them by id (§14.2). | by hand; the nightly (§9) |
| The `install` kind (the VM matrix) | Needs `/dev/kvm` and a VM image cache. | `v*` tags, or by hand ([`os-test-matrix.md`](./os-test-matrix.md)) |
| `internet` entries (`wire-release-live`; `tls-compat` is an `env` entry) | They reach the public internet; the manifest runs them only when selected. | by hand (`--only <id>` or `--include-internet`) |
| The darwin entries (macOS) | A macOS runner costs ten times a Linux one on a private repository, and a Seatbelt or PTY failure is read on the machine (above). | a maintainer's Mac, by hand ([`development.md`](../../development.md)) |
| The frozen integrity lane | Runs only when the integrity axis is revived ([`protection-modes.md §10`](../architecture/protection-modes.md) §5). | by hand, on revival |

### 12.3 How the two relate

The VM run of §3 is the merge gate for the canonical repository: it runs the
five per-push kinds, which cover everything GitHub runs plus the
`replay-drill` kind and the entries that need `kernel`. A contributor runs the
same thing locally with `scripts/ci/vm-run.sh` (§8), less the drill entries,
which are the maintainers' (§2). GitHub is the gate an
outside contributor sees on a pull request. A change that passes GitHub can
still fail the VM gate (an agent-CLI suite, a sandbox suite), so an outside
pull request also goes through the VM run before it lands.

The two must not drift apart. The manifest's sealed kinds are the list GitHub
should run: a TS package needs nothing (discovery picks it up); any other
sealed entry is in the `shell` job when its command is `bash` or `node`
(the rest fits `rust`); a suite that needs privilege or credentials is of
another kind and §12.2 covers it. The workflow builds that matrix from the
manifest ([`test-organization.md`](./test-organization.md) §9.2), so no list
is kept by hand.

### 12.4 Drift from the manifest (one difference by design)

With the matrix built from the manifest, no hand-kept list can drift. One
difference remains, by design: the `ts` job runs each package's `npm test`
rather than the manifest's package entries (the same files; a sharded entry
such as `launcher` runs whole), so the same files run, only grouped per
package. Eval's `npm test` takes `lib/run-live.test.ts`, the offline half
(the claude stream normalizer, no binary), which the manifest's `eval.lib`
owns as well; the live smoke is a separate file no default glob reaches
(test-reorganization.md §8). `scripts.suites-manifest` pins the split: each
file has one owner.

Contributor-facing files that ship with the workflows: the issue forms and
their `config.yml` (security reports go to GitHub private vulnerability
reporting, as `SECURITY.md` says), the pull request template (tests and the
design-doc update in the same change, stated axes, the commit format), and
`CODE_OF_CONDUCT.md` (Contributor Covenant 2.1; conduct reports go to
hello@mandusecurity.com, not the security channel).


### 12.5 The release workflow (2026-10-21)

`.github/workflows/release.yml` is where a release is built and published
([`packaging.md §11.3`](../distribution/packaging.md)): a release is cut from
the public tree so the artifact is provably the public snapshot. A
maintainer pushes an annotated `v<version>` tag on a snapshot of `main`,
after the development repository's own tag pipeline (the kernel lane, the
audit, the install matrix: everything §12.2 lists as not on GitHub) has
passed on the snapshot's source commit.

| Job | What it does | Credential |
|---|---|---|
| `check` | `ci.yml` (`workflow_call`) on the tagged snapshot | none (`contents: read`) |
| `pack` | refuses a private repository, a lightweight tag, a commit that is not a snapshot of `main`; runs `scripts/ci/release-pack.sh` (packaging.md §11.3) and `scripts/ci/release-assets.mjs`; keeps the `release` artifact | none |
| `publish` | needs `check` and `pack`, runs in the `release` environment (a maintainer's approval); checks out no code; checks `SHA256SUMS`; creates the GitHub release; `npm publish --provenance --ignore-scripts` of the same tarball | `contents: write` and an OIDC identity (`id-token: write`) that npm's trusted publishing accepts only from this workflow in this environment; no stored token |

`scripts.release-workflow` pins this shape: the trigger, the permissions per
job, the approval, no `secrets.` reference and no npm token, the publish
flags and their order, and the packages the pack installs against the
launcher's bundle manifest; it also runs `release-pack.sh`'s refusals of a
tree that is not the public one.

## 13. Test credentials: one secrets file

How Mandu's tests and tools get API keys on a developer's machine: a
**single gitignored JSON file**, and the list of which suites need which key.
It refines [`agent-sign-in.md §1`](../agents/agent-sign-in.md) (why the
subscription works for the agent but not for third-party clients) and the
launcher's env contract (`launcher/mandu-run.sh`, `launcher/src/parse.ts`).
The nightly's credentials are separate files on the runner host, outside
the repository (§9.3, §9.8).

### 13.1 In short

- **Running Claude Code under Mandu needs no API key**: the Pro/Max
  subscription is enough. The T-LLM path relays Claude Code's own credential;
  the U-LLM defaults to `claude -p` (also first-party).
- **The per-push kinds need no key at all**; neither does
  `scripts/test-all.sh`.
- **An Anthropic Console key** (`ANTHROPIC_API_KEY`) is needed only by
  third-party clients that cannot use the subscription: the API lane's
  `openclaw-headless` and `opencode-headless` (§9.7), eval's `--mode real-api`, and U-LLM api mode.
- **An `OPENAI_API_KEY`** is needed only for the Codex suites that run on a
  key (`codex-e2e`, `codex-mcp`); Codex itself also runs on its own `codex
  login`.
- Keys are set once in a gitignored `secrets.local.json`; everything reads
  from it.
- **No API key in CI (decided 2026-10-05).** A vendor API key is used only
  for runs on a developer's machine, never on the runner host, but for the
  weekly rotation of §13.4, which has the rule.

### 13.2 The file

The quickest way to set a key: `node scripts/set-api-key.mjs` (or `…
anthropic` / `… openai`) asks for it with no echo, refuses an OAuth token,
an admin key or a wrong shape, checks it with one model-list request (no
tokens), and writes it, mode 0600, into the Mandu home's `secrets.json`
(`~/.mandu/secrets.json`), which every checkout and worktree finds; the other
fields are kept. By hand:

```sh
cp secrets.example.json secrets.local.json
chmod 600 secrets.local.json          # keep it private
$EDITOR secrets.local.json
```

```json
{
  "anthropic_api_key": "sk-ant-…",     // Console key: real-API runs + U-LLM api mode
  "openai_api_key": "sk-…",            // only for the Codex track
  "ullm_api_key": "",                  // optional; defaults to anthropic_api_key
  "ullm_base_url": "",                 // optional
  "ullm_model": "",                    // optional
  "typesafe_api_key": "",              // optional: jev-ultrafast's TypeSafe model
  "openrouter_api_key": "",            // optional: an OpenRouter key (jev's text helper)
  "env": {}                            // optional passthrough of extra env vars
}
```

**Load it into a shell** (then run the launcher or a suite normally):

```sh
source scripts/mandu-env.sh
```

That maps the JSON to the env vars the stack already reads
(`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `OPENAI_BASE_URL`,
`MANDU_ULLM_API_KEY`, `MANDU_ULLM_BASE_URL`, `MANDU_ULLM_MODEL`,
`TYPESAFE_API_KEY`, `OPENROUTER_API_KEY`, the last two bound by the launch to
their own hosts, [agent-sign-in.md §3.12](../agents/agent-sign-in.md); the `MAP` in
`scripts/secrets-to-env.mjs` is the one place these names are defined).
`launcher/mandu-run.sh` loads the file itself (a checkout's bundled launch
in the launcher's own node, through `applySecretsEnv`, the same variables
and precedence; packaging.md §5.1), so you only need to source it for direct
`npx tsx` runs.

**Discovery** (first that exists wins): `<repo>/secrets.local.json`, then the
Mandu home's `secrets.json` (`${MANDU_HOME:-~/.mandu}/secrets.json`,
[`on-disk-layout.md`](../architecture/on-disk-layout.md) §3), which keeps the
file outside the repository. There is no per-file override.
`MANDU_SECRETS_FILE=0` reads no file at all (the environment alone counts;
added 2026-10-09): a launch that must ride the agent's own sign-in sets it,
so the shim loads no `ANTHROPIC_API_KEY`, which would also switch the U-LLM
to api mode. The hand-run Claude Code live drill is that launch.

**Safety properties** (by construction, see `secrets-to-env.mjs`):

- Only `secrets.example.json` (an empty template) is committed;
  `secrets.local.json` and `secrets.json` are gitignored.
- Diagnostics are **masked** (`sk-ant…9XYZ`), never the raw key.
- It **never overrides** an env var already set: an explicit `export` wins
  over the file.
- A missing file, an unreadable file or a JSON parse error is **non-fatal**:
  sourcing it never breaks the shell; it just loads nothing.
- It warns if the file is group- or other-readable.

### 13.3 Why the subscription serves the agent but not every client

The **agent** path is first-party: `anthropic-proxy` is a verbatim relay, so
Claude Code forwards its own subscription OAuth bearer through it to
`api.anthropic.com` (agent-sign-in.md §1 F1 to F3); the **U-LLM** defaults
to `claude -p`, which is also Claude Code. Both are "actually Claude Code",
the only robust way to present a subscription token.

A **third-party** client is different: eval's live backend spawns a fresh
agent with a clean env (it must not nest the session's auth), and OpenClaw
or OpenCode on the real API are not Claude Code. A subscription OAuth token
presented by anything that is not Claude Code is not a supported use
(agent-sign-in.md §1 F4/F6/F7). Those suites need a **Console API key**,
and they skip cleanly (exit 0) when it is absent, so you never have to set
one.

**Codex.** Two ways, like Claude. A key: `OPENAI_API_KEY` (in the file as
`openai_api_key`) or `CODEX_API_KEY`, which the launcher's provider reads.
Or Codex's own `codex login` (a ChatGPT plan, or a saved key), used when no
key variable is set: the openai-proxy relays a ChatGPT sign-in to the
ChatGPT backend's Codex base and anything else to the API, with the same
masking; Mandu never stores, refreshes or originates with it
([`agent-sign-in.md §2`](../agents/agent-sign-in.md)). The
nightly's Codex sign-in: §9.8.

### 13.4 Keys and CI

**Decided 2026-10-15: an Anthropic key in CI, for a weekly rotation.** From
2026-10-05 to -15 no vendor key was in CI (the lane's `nightly-api` job, red
every night for want of a key, was removed 2026-10-09). The agents that run
only on an API key (OpenClaw, OpenCode, OpenCode 2 and Goose) then had no
regular live run at all, so the
maintainers reopened the lane for them, narrowly: the scheduled
`nightly-api-key` job runs `nightly.sh --lane api-key --weekly`, one agent a
night (Monday OpenCode 1 and 2, Wednesday OpenClaw, Friday Goose; the other
nights it exits at once), that agent's live-drill entries only, on Haiku 4.5.
The key is the runner host's api credential file (`credential.mjs install
api`, §9.8), a key of its own made for CI with a limit on the vendor's
side; until it is installed the job fails in seconds with the
setup steps. The OpenAI key stays off the runner: the Codex entries on a key
(`codex-headless.openai-key`, …) run only by hand.
An API key lives only on a developer's machine (§13.2: the repository's
`secrets.local.json`, or the Mandu home's `secrets.json`, which every
worktree finds) and serves runs started by hand: the API-key live legs of the
non-Claude-Code agents (the maintainers' drill runner on OpenCode, OpenClaw
and the others, `openclaw-headless`, `opencode-headless`), live recording into replay scripts (the
maintainers' drill recorder), and
eval's `--mode real-api`. Revisit when a wider API cut (one model,
a few scenarios, a limit) is worth it.

**Decided 2026-10-05: spend API tokens as little as possible, also by
hand.** A run on an API key is the exception, not a habit:

1. **Free lanes first.** Replay (no model) and the local-model lane prove
   what they can; a key run proves only what they cannot: a new agent's
   first live leg, a change to an agent's wiring, a release.
2. **The smallest cut.** One agent, the conf trio or the named scenarios in
   question, the cheapest model (haiku); never the whole battery to see what
   happens.
3. **Record, do not repeat.** A live run is recorded into replay scripts
   (the drill recorder), so its behavior is re-checked for free afterwards; a
   flake is studied from the recording, not re-run until green.
4. **Not often.** No schedule but the weekly rotation above, no loop, no
   re-run of a green result.
5. **Ask first.** An agent session asks the maintainer before starting a run
   that spends the key, naming its scope (agents, scenarios, model), unless
   the maintainer asked for that run.

Set the key with `node scripts/set-api-key.mjs` (§13.2).

**The per-push run holds no key and no credential** (§1). The nightly holds
one credential kind per lane (the subscription lane nightly, the api-key
lane in its weekly rotation),
from files on the runner host, never from a CI variable (§9.3, §9.8). The hand-run docker rig takes keys only through
`docker-run.sh --with-secrets`, which materializes them with this same
loader (`secrets-to-env.mjs --format=env-file`, the effective value of each
key: the environment wins, the file fills the gaps) into a mode-600
`--env-file`, never `-e KEY=value`, which would expose the secret to `docker
inspect` and `ps` (docker-e2e.md §1).

## 14. Static analysis and the dependency audit (built 2026-10-09)

Two checks the OpenSSF Best Practices "passing" criteria name and the
pipeline did not have: a static-analysis gate for the Rust workspace, and an
audit of every dependency against the published advisories. Both are
manifest entries (`tests/suites.mjs`), so CI runs them the way it runs every
other suite and a developer runs them by id.

### 14.1 Clippy: `rust.clippy`

`rust.clippy` is a `unit` entry: every push, in the GitLab `test` job and
GitHub's `rust` job. It runs, in `interceptors/`,

```sh
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy --workspace --all-targets --features kernel -- -D warnings
```

The second pass covers the attachment code a default build leaves out (the
seccomp listeners, the guard, the kernel tests). Clippy is the pinned
toolchain's (1.75, `scripts/ci/pins.env` `RUST_VERSION`): a newer clippy
brings new lints, so the toolchain bump is the change that takes them on.
The CI image and the docker rig install the clippy component, and the image
build runs both passes once so a run only rechecks what changed; GitHub's
`rust` job installs it too. Where clippy is missing the entry SKIPs with the
reason; `ci: { maxSkip: 0, minPass: 2 }` makes that red in the guest, and the
GitHub job fails on any entry that did not pass.

**The lint policy** is `[workspace.lints.clippy]` in
`interceptors/Cargo.toml`, which every crate inherits (`[lints] workspace =
true`): clippy's default set, with four relaxations, each reasoned there:

| Lint | Sites | Why it is off |
|---|---|---|
| `unnecessary_cast` | about 380, the seccomp and notification decoders | libc's syscall numbers and stat fields are cast to one fixed width so one source builds for x86_64 and aarch64; on the host target the cast is often to the same type |
| `needless_borrows_for_generic_args` | about 90, nearly all tests | clippy 1.75 asks to move a field out of a struct that is used or dropped later (`ArbiterClient::new(&arbiter.socket_path)`); the suggested fix does not compile |
| `format_collect` | 7 | the hex encoders of short digests, pinned byte for byte against the TS side |
| `type_complexity` | 5 | a tuple type spelled once at its one use |

Where a fix would have touched decision logic in a security-path crate, the
site carries a reasoned `#[allow]` instead: `nonminimal_bool` on the guard's
path-change pass-through test (`guard_kernel.rs`, the term-by-term list of
what makes a call worth guarding), `vec_init_then_push` on the AgentShell
seccomp program builder (`seccomp_filter.rs`, one instruction per push with
cfg-gated steps), `len_without_is_empty` on `git_lock::Format`; and in tests,
`identity_op` (glibc's makedev spelled term by term), `enum_variant_names`
and `nonminimal_bool`. The rest was fixed without a change of behavior (13
sites): `# Safety` sections on fs-preload's four interposers; a test's `while
fd >= 0` whose condition never changes (clippy's deny-by-default
`while_immutable_condition`) made `if fd >= 0 { loop { … } }`; the net
guard's proxy-ports read as `if let` (the same fail-closed message on a bad
list); in the guard, a slice passed instead of a `to_vec()` copy of it, a
`then_some` on a plain struct, a closure passed without a borrow; a `while
let` over an iterator as `for` (`script_identity.rs`); and `== false`, `p +
0` and a manual `flatten` in tests. No check was removed or narrowed.

### 14.2 The dependency audit: `deps.audit-npm`, `deps.audit-cargo`

`scripts/dep-audit.mjs npm|cargo` reads lockfiles only (no install, no
lifecycle script):

- **npm**: `npm audit --json` in every directory holding a
  `package-lock.json` (found by walking the tree, skipping `node_modules`,
  build output and dot-directories, so a new package is covered without a
  list), development dependencies included: the build and test tools run on
  the maintainers' machines and in CI.
- **cargo**: `cargo audit --json --file interceptors/Cargo.lock`: the
  vulnerabilities, and the warnings (unmaintained, unsound, yanked crates).

**Every finding fails, of any severity, unless the allow-list names it.**
`scripts/dep-audit-allow.json` holds the exceptions: advisories with no fix
yet that do not reach Mandu's users. An entry names the advisory (`id`:
GHSA-…, RUSTSEC-…, or `yanked:<crate>@<version>`), `ecosystem`, `package`,
optionally `where` (the lockfile directories it covers), a `reason` (why it
cannot be fixed now, and why it does not matter here), `added`, and
`expires`, at most 180 days after `added`. Past its expiry an entry allows
nothing, so every exception is looked at again; an entry that matches no
finding is reported for deletion; an invalid file fails the audit before it
runs. A finding with a fix is fixed, not listed: `npm audit fix
--ignore-scripts` (within the declared ranges) or `cargo update -p <crate>`.
The list started empty.

**Where and when.** Both entries need the internet (npm's registry, the
RustSec database that cargo-audit fetches), so they are kind `env` with
`internet: true` and `manual`: no kind listing selects them, and the nightly
does not run them. Two jobs run them by id:

- GitLab `audit`: `vm-run.sh --network --only deps.audit-npm,deps.audit-cargo`,
  the per-push guest with §9.2's network (the internet, never the host's
  loopback) and no credential. It still executes the commit's code (the
  audit script), so it runs in the guest, not on the runner host. It runs in
  the nightly's schedule (a new advisory against an unchanged tree makes the
  scheduled pipeline red: not `allow_failure`, an advisory is a finding, not
  a flake), on `v*` tags (the release waits for it), and on a merge request
  that changes a lockfile or the audit itself. Not on every push: a new
  advisory is news about the tree, not about the change, and would turn every
  unrelated request red until someone fixed it.
- GitHub `audit` (§12.1): the same two entries, on the same triggers as the
  rest of that workflow.

`pipeline.sh` always passes `--strict-skips` and GitHub's job passes it too,
and both entries carry `ci: { maxSkip: 0, minPass: 1 }`: an unreachable
database or a missing cargo-audit, which the script reports as a SKIP with
its reason, is red there, never a quiet green. On a developer's machine the
same SKIP is what an offline audit says.

**cargo-audit** is the RustSec release's static build
(`cargo-audit-x86_64-unknown-linux-musl`), pinned by version and sha256 in
`scripts/ci/pins.env` (`CARGO_AUDIT_VERSION`, `CARGO_AUDIT_SHA256`, the
release's own asset digest): the image installs it (`provision.sh`
`install_release_bin`) and GitHub's job downloads the same file and checks
the same sum. Not `cargo install`: the current releases need a newer rustc
than the workspace's pinned 1.75. `CARGO_AUDIT=<path>` points the script at
another binary.

**The first run (2026-10-09).** cargo: no finding (27 crates against 1296
advisories). npm: five lockfiles had advisories, every one with a fix inside
the declared ranges, applied in the same change: js-yaml 4.2.0 to 4.3.2
(three high-severity CPU-exhaustion advisories in merge keys and `!!omap`) in
`arbiter`, `dashboard`, `eval`, `interceptors/net-proxy` and
`tests/conformance`; and the dashboard's development tools, undici 7.28.0 to
7.30.0 (fifteen advisories), seroval 1.5.6 to 1.6.9 (one critical, one
high), source-map-js 1.2.1 to 1.2.2 and solid-js 1.9.15 to 1.9.17 (the
vendored asciinema player is prebuilt, untouched).

**An advisory between two nightlies (2026-10-22).** GHSA-rxp7-6hxx-x8q5
(`ip-address` up to 10.7.3: a zone identifier matched in quadratic time;
moderate) was published at 16:19 UTC, sixteen minutes after that day's
GitLab nightly had run the audit green. The first audit to run after it was
GitHub's, on the snapshot before beta.8 that evening: `tests/fixtures/agent-sdk-host`
holds the only copy, a transitive dependency of the Claude Agent SDK's
`express-rate-limit` (`^10.2.0`). `npm audit fix --package-lock-only
--ignore-scripts` moved it to 10.7.4 and changed nothing else in the lock;
no allow-list entry. The GitLab audit runs the same two entries, so the
next nightly would have failed the same way.
