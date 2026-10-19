# OS test matrix and fresh-install testing (`scripts/matrix/`)

Status: BUILT. The matrix harness (§1 to §9) and its fresh-install suites
(§10): a disposable VM where `sudo` is real, used to prove the install,
`mandu setup`, every supported agent on a clean machine, and the release
upgrade. It is the `install` kind
([`test-organization.md`](./test-organization.md) §3), run on `v*` tags and
by hand ([`continuous-integration.md`](./continuous-integration.md) §2); the
per-push gate does **not** boot it.

> Companion to [`privilege-model.md`](../architecture/privilege-model.md) (the
> enforcement layers this matrix exercises) and `scripts/kernel-vm.sh` (the
> single-target VM harness this design generalizes). Motivating direction: the
> **portable wrapper** — all four chokepoints realized by a cooperative wrapper
> process with no OS-specific kernel support required, per-OS hardening as
> optional probed backends ([`portable-wrapper.md`](../distribution/portable-wrapper.md)).
> "Portable" is a *tested* claim only if the repo's suites actually run on more
> than one OS/kernel/config — this doc designs that harness.

## 1. Motivation — what the matrix must prove

Two claims from the portable-wrapper direction need a test home:

1. **The cooperative core runs everywhere.** The env/PATH/CWD/proxy chokepoint
   set (the wrapper layer, `privilege-model.md` §2) is pure userspace and must pass
   unchanged on every target OS — eventually including macOS.
2. **The enforcement-backend probes degrade correctly.** Hard backends
   (userns/seccomp today) must *detect* each host posture — userns on, userns
   AppArmor-restricted, userns off, ADDFD present/absent, old kernel — and
   degrade to the cooperative floor cleanly, never falling through to raw.

A developer host shows only its own posture, and `kernel-vm.sh`'s hardcoded
Ubuntu 22.04 guest adds old-kernel posture coverage. The matrix turns that
ad-hoc pair into a declared, extensible target set.

## 2. Design — target × suite, one executor contract

```
scripts/matrix/
  run.sh <target> <suite>     # one target, one suite
  run-matrix.sh [--require t] # all targets × their declared suites, summary table
  targets/<name>.conf         # declarative target definitions
  suites/<name>.sh            # what runs inside a target
  lib/qemu.sh                 # extracted from kernel-vm.sh: image cache, qcow2
                              #   overlay, cloud-init seed ISO, virtio-9p shares,
                              #   serial log, RESULT collection
  lib/host.sh                 # direct executor (throwaway workdir on this host)
```

Every executor implements the same contract:

> **preflight → provision → push repo → run suite → collect `RESULT=pass|fail`
> + full log → aggregate**

with the PASS/FAIL/SKIP summary idiom `scripts/test-all.sh` and
`scripts/kernel-tests.sh` already use. The RESULT protocol is `kernel-vm.sh`'s
(the suite writes `RESULT=…` plus its log to the collected output location) —
reused, not reinvented.

**Target conf fields:** `EXECUTOR=host|qemu` (later `ssh`), `IMAGE_URL` (+
`IMAGE_SHA256`), `CPUS`, `MEM`, `TIMEOUT`, `LABELS` (facts the target claims to
exercise, e.g. `os=linux kernel=7.0 userns=apparmor-restricted addfd=yes`), and
an optional `SYSCTLS` knob (applied via cloud-init) so posture variants — e.g.
an unrestricted-userns twin of a target — are a one-line conf, not new code.

**Executors:**

- **`host`** — runs the suite directly in a throwaway workdir. Covers the
  host's live posture for free and doubles as the harness self-test vehicle.
- **`qemu`** — `kernel-vm.sh`'s mechanics, extracted into `lib/qemu.sh` and
  parameterized by the target conf: cached read-only base image
  (`MANDU_VM_CACHE`), a cached provisioned layer on it (the packages the
  suite's deps declare, nothing of Mandu's; §10.17.1, `MANDU_VM_SNAPSHOT=0`
  skips it) + fresh qcow2 overlay per run (guests are disposable, no state
  leaks; each is registered for `mandu reap`, so one a killed run leaves is
  stopped and its `RUN_WORK` removed, §10.17.3), cloud-init seed ISO for
  provisioning, virtio-9p read-only repo share + writable out-share, headless
  KVM boot, user-mode (SLIRP) networking, serial console captured. `run.sh
  --interactive <target> [<suite>]` boots the same guest for ssh instead of
  running a suite (§10.17.2).
- **`ssh` (DEFERRED — designed seam, not implemented).** Same contract over
  rsync + ssh for real hardware, first user being a macOS target (§3).
  Non-disposable-target rules apply: throwaway remote workdir, cleanup trap,
  no global mutation beyond declared toolchains. Nothing in the driver may
  assume all executors are local.

### 2.1 Reboots

A suite that must reboot its guest (the `release-upgrade` suite: run
`do-release-upgrade`, then boot the new release; `fresh-install`: reboot a
set-up host, §10.16.1) saves its own state on the guest's disk and exits
**75**. The guest runner then arms a resume flag, enables the
`mandu-matrix-resume` systemd unit (written by cloud-init next to the runner)
and powers off with `RESULT=reboot`. The qemu executor boots the SAME overlay
again; on that boot the unit runs the runner again, which mounts the shares,
skips provisioning, the repo copy and the toolchains (already on the disk),
disarms the flag and runs the suite with `MATRIX_RESUME=1`. The suite reads
its phase back from its own state.

Two suite headers bound it, next to `# deps:`: `# boots: N` (at most N boots;
default 1, so a suite that never declared it cannot loop) and
`# min-timeout: S` (the run gets at least S seconds whatever the target's
`TIMEOUT`). Every boot shares ONE `TIMEOUT` budget. `RESULT` is removed
before each boot, so a boot that dies before its runner writes anything
fails the run instead of being read as the previous boot's `reboot`. Every
boot's serial console is appended to `serial.log`. Unit test:
`scripts/test/matrix-reboot.test.sh`: the rendered user-data and unit, the
resume detection, the exit-75 path, and the real `executor_run` against a
stub qemu playing scripted boots.

## 3. Targets

### Initial set (implemented now)

| Target | Executor | Posture (LABELS) | What it uniquely proves |
|---|---|---|---|
| `host` | host | the host's own (e.g. `os=linux kernel=6.8 userns=on addfd=yes landlock=v4`) | the host posture; the full kernel tier live (ADDFD redirect + Landlock FS/net) |
| `ubuntu-2604` | qemu | `os=linux kernel=7.0 userns=apparmor-restricted† addfd=yes` | modern hardened host: new kernel + the restricted-userns probe/degrade posture; a supported install target |
| `ubuntu-2404` | qemu | `os=linux kernel=6.8 userns=apparmor-restricted addfd=yes` | the end-user release's primary platform; home of the `fresh-install` suite (§10) |
| `ubuntu-2510` | qemu | `os=linux kernel=6.17 userns=apparmor-restricted addfd=yes` | the interim release where Ubuntu's own `bwrap-userns-restrict` is already in force (enabled from 25.04), with apparmor 5.0.0~alpha1 and bubblewrap 0.11.0; `fresh-install` and `fresh-agents` (§10.15). 25.10 reached end of life in July 2026: when its archive moves to old-releases.ubuntu.com the target needs a mirror override |
| `linux-arm64` (**not a target yet**) | — | `os=linux arch=arm64` | The release tarball ships cross-built arm64 native bins (packaging.md §11.3, packaging.md §5); they are started under qemu-user in release-pack and the Rust unit suites pass under `qemu-aarch64`, which proves they link and decide right, not that seccomp/Landlock attach on an arm64 kernel. Every target above is amd64. Closing it needs an arm64 guest (`qemu-system-aarch64` under TCG is slow but unprivileged) or arm64 hardware running `fresh-install`. Until then: built, not run on hardware. |
| `wsl2` (**supported, simulated; no executor**) | — | `os=linux kernel=wsl2` | WSL2 is a real Linux kernel (6.6 in current Windows builds: Landlock and seccomp user notification present), so the Linux rules apply unchanged. The WSL-only surface is handled (exec-routing.md §4.1): the Windows interop door is closed in the command box (tmpfs over `/run/WSL` and `/mnt/wslg`, `/dev/null` over `/init` and the `$WSL_INTEROP` socket, `socket(AF_VSOCK)` and io_uring denied), refused by the connect guard for the whole agent (the interop socket and `AF_VSOCK`), and hidden by the secret-twin wrap; `mandu doctor` and the launch name the kernel gate, the interop state, systemd and a project on a Windows drive (`launcher/src/wsl.ts`); the installer and doctor refuse to call WSL1 confinable. **Covered:** every decision is unit-tested on WSL kernel-release strings, binfmt contents and WSL mountinfo fixtures, and the enforcement is proved on a Linux host with the WSL signals PINNED (kernel tests `bubblewrap_backend_hides_the_wsl_interop_door`, `guard_refuses_the_wsl_interop_socket`, `guard_refuses_vsock_on_wsl`, `guard_supervises_unix_connects_on_wsl`, `guard_wsl_check_survives_a_symlink_swap_race`; launcher e2e `wsl-interop.test.ts`, stand-in socket and `/init`). Windows-side credential files are discovered per profile (`/mnt/<drive>/Users/<name>` as a second home, the catalog's paths probed, never walked; confidentiality.md §7.2 "WSL2"), proved by launcher e2e `wsl-windows-secrets.test.ts`. A different-case spelling of a twinned file (drvfs folds case) misses the bind but not the guard, which matches the file by inode (confidentiality-plan-10-flow-taint.md §4.1; proved with a hard link standing in for the folded name, `secret-readers-live.test.sh` step 4e). **Not yet covered:** a real WSL2 executor (WSL2 inside a QEMU Windows guest needs nested virtualization) to run `fresh-install` and check what no fixture can: the real `/init` interop client failing against the hidden socket, Hyper-V vsock refused, Landlock on drvfs (9p) paths, systemd-less distributions, the twin bind over a real drvfs file, and the guard's inode match on real drvfs inode numbers. |

The `ubuntu-2604` base image is the Ubuntu 26.04 LTS ("resolute") amd64 cloud
image (`https://cloud-images.ubuntu.com/releases/26.04/release/ubuntu-26.04-server-cloudimg-amd64.img`,
~860 MB). The base image + overlay need ~3 GB headroom; the `kernel-vm.sh`
disk preflight carries over.

† **Verified on first boot:** the guest reports `apparmor_userns=1
userns_clone=1`, so the AppArmor unprivileged-userns restriction is present
in 26.04; the LABELS are the observed posture. On a restricted target the
`kernel` suite's clean self-SKIP *is* the degrade-path assertion; an
unrestricted twin is a one-line `SYSCTLS` conf.

### Deferred targets (designed for, not built)

- **`macos`** (ssh executor) — a developer's Mac; intermittently reachable, so
  manual-trigger only, never required. On Apple Silicon, a later upgrade is
  Tart-managed disposable macOS VMs *on* the Mac behind the same ssh
  executor. Out of scope for now.
- **`ubuntu-2204`** (qemu) — would absorb `kernel-vm.sh`'s role (kernel 5.15,
  old-kernel coverage). Until it exists, `kernel-vm.sh` stays as it is (§6).
  Ubuntu 22.04 is not a supported install target (§10.9).
- **`debian-userns-off`** (qemu) — `kernel.unprivileged_userns_clone=0`, the
  hard-off probe path.
- **Windows** (qemu) — legally fine, mechanically supported by the design, but
  the image is ~12 GB+; revisit with the wrapper's Windows milestone.
- **macOS-on-QEMU is permanently out** — Apple's license permits macOS only on
  Apple hardware; the matrix will not build on an EULA-violating foundation.

## 4. Suites

| Suite | Runs | Deps declared | Notes |
|---|---|---|---|
| `smoke` | trivial `RESULT=pass` | none | validates driver plumbing end-to-end; cheap enough for the per-push gate |
| `kernel` | `scripts/kernel-tests.sh` | rust | self-SKIPs per missing facility (existing semantics) — on a restricted target the SKIP is the assertion |
| `all` | `scripts/test-all.sh` | node, rust | full TS + Rust suite; provisioning (toolchain install via cloud-init) adds minutes |
| `fresh-install` | the PACKED `@mandusec/mandu` tarball installed by an empty-HOME user, then doctor / launch / `mandu setup` with a real guest `sudo`; over two boots (§2.1): a reboot of the set-up host, then the Node 18 negative, the NodeSource (system-wide, `sudo npm install -g`) variant and the uninstall hygiene | none (installs Node as the user, via nvm) | §10; uses the host-prep hook below; the checkout is unmounted before the product runs |
| `fresh-agents` | the PACKED tarball installed as the README says, then Claude Code, Codex, OpenCode and OpenClaw from npm, each run through the installed `mandu` against a scripted loopback model (default mode: a credential file; `full`: a poisoned file) and, with `FRESH_AGENTS_LIVE=1`, live Claude Code and Codex | none (nvm, as the user) | §10.14; `FRESH_AGENTS_VERSIONS=tested` (default, the launcher's tested maxima) or `latest` |
| `release-upgrade` | on `ubuntu-2404` only and by hand (not in its `SUITES`: about 30 minutes), over three boots (§2.1): bring 24.04 up to date; install the PACKED tarball as fresh-install does, run `mandu setup` (or plant the old grants, `RELEASE_UPGRADE_FROM=legacy`) and prove it confined; run a real `do-release-upgrade` to 26.04; then check doctor, a confined launch and Ubuntu's own rules before and after `mandu setup` | none (nvm, as the user) | §10.15; `RELEASE_UPGRADE_PATH=auto` (default: the regular LTS path when Ubuntu offers it, else `-d`) \| `regular` \| `development` \| `proposed` |
| `wrapper` | launcher package `npm test` — fake-agent parity e2e + fail-closed arbiter-refuse | node | live on `host` + `ubuntu-2604` (`portable-wrapper.md` §6); installs the sibling packages the launcher's bundle and golden-path e2e reach into |

**Host-prep hook.** A suite may ship `suites/<suite>.host.sh`. The qemu
executor runs it on the host before boot with `ARTIFACT_DIR` set, and shares
that directory read-only into the guest at `/mnt/artifacts`. This is how a
suite tests a host-built artifact (the packed tarball) instead of the checkout.

Suites declare their toolchain deps; each executor's preflight checks them
(qemu: cloud-init installs; host: `command -v`; ssh later: remote probe).

**The qemu provisioning gate.** cloud-init's `packages:` module only *warns*
when the Ubuntu mirror is unreachable, then runs the guest script anyway. A
slow `archive.ubuntu.com` once left 26.04 guests without `build-essential`,
and the `kernel` suite reported "linker `cc` not found, 0 passed / 0
failed", which reads like a product break. The guest runner therefore
re-checks every declared package by a probe command (`cc` for
`build-essential`, `nft` for `nftables`, the header for `libssl-dev`, the
package name otherwise), retries `apt-get` for the missing ones four times
with backoff and `Acquire::Retries=5`, and if they are still missing ends the
run as `fail: provisioning: packages missing after retries: <list>` before any
toolchain install or suite. It is a FAIL, not a SKIP: the target itself is
available, and a SKIP would let a mirror outage hide under `--require`. One
flat package list feeds both cloud-init and the gate (`@PKGS@`). The rustup
and NodeSource downloads retry too. Unit test:
`scripts/test/matrix-provision.test.sh`.

## 5. SKIP vs `--require` — how targets are kept honest

- **Default: clean SKIP.** An unavailable target (image URL unreachable, no
  /dev/kvm, Mac offline) or missing facility SKIPs with a printed reason and
  does not fail the run — the `kernel-tests.sh` convention, safe on any host.
- **CI: `--require <target>`.** A required target that is unavailable is a
  **FAIL**, so a target cannot rot silently while the summary stays green.
  The `install` CI job requires `ubuntu-2404` and `ubuntu-2604`, the two
  supported install targets (§6, §10.9 item 3); `ubuntu-2510` runs there but
  may SKIP; manual targets are never required.

## 6. CI wiring

- **The per-push gate does not boot the matrix** — VM boots are minutes each.
  Exception: `run.sh host smoke` is the harness self-test (seconds, no VM),
  the manifest entry `matrix.smoke`, and runs on every push.
- **The `install` kind** runs `run-matrix.sh --require ubuntu-2404 --require
  ubuntu-2604` on every `v*` tag, after the per-push run, directly on a KVM
  host (the matrix boots its own guests), and `release-pack` needs it green
  (continuous-integration.md §7). There is no scheduled matrix run;
  `release-upgrade` and `scripts/kernel-vm.sh` stay by hand.
- **`kernel-vm.sh` stays as it is.** When a `ubuntu-2204` target is added,
  `kernel-vm.sh` becomes a thin shim over `run.sh ubuntu-2204 kernel` (a
  parity-then-shim migration).

## 7. Fences (what this is NOT)

- **No Vagrant / packer / libvirt / multipass.** The in-house qemu mechanics
  are proven and minimal (reuse, don't rewrite); an orchestration stack is
  pure dependency weight here.
- **No new interception or enforcement.** The matrix runs existing suites in
  more places; it changes nothing about what they test.
- **No always-on macOS or Windows commitments.** Deferred targets are seams,
  not promises with dates.

## 7b. Acceptance check: `mandu setup` on a fresh Ubuntu 24.04 (automated)

`mandu setup` installs AppArmor profiles through `sudo`, which no CI lane may
do **on the host**. A throwaway qemu guest's root is a different thing, so
this check is automated: `FRESH_INSTALL_REF=HEAD scripts/matrix/run.sh
ubuntu-2404 fresh-install` runs the steps below with a real guest `sudo`,
against the packed tarball, as an empty-HOME user (§10.4). Run it before a
release, and before merging a change that touches `launcher/src/setup.ts`,
`confinement-posture.ts`, `scripts/apparmor/`, `build-bundle.mjs` or
`bundle-manifest.json`. What it asserts (the posture names are
rootless-confinement-ubuntu-2404.md's; since the whole-agent guard ships,
a stock 24.04 is already `confined` by the guard and `mandu setup` adds the
bind layer, §10.12):

1. `mandu doctor` reports the first-day posture the target declares, with
   its cause and fix.
2. `mandu claude` (confidentiality on) launches and prints the mode banner;
   with `--require-confinement` it refuses when the posture is `gated`.
3. `mandu setup` shows Mandu's profile and its `sudo` commands; answer `y`.
   It ends with secrets `confined`. A sandbox starts inside Mandu's own
   bubblewrap, and `unshare -Ur` inside it is refused (no trampoline).
4. `mandu doctor` reports `posture: confined` with both layers; `mandu setup`
   again says `nothing to do`.
5. `mandu setup --uninstall` removes Mandu's bubblewrap and profile and never
   unloads Ubuntu's `bwrap` profile; doctor is back to the first-day posture.
6. With a hand-written `/etc/apparmor.d/unshare` lacking the `# Mandu:` first
   line, install skips it and uninstall leaves it in place.
7. The migration (step 10): with the old Mandu grants planted, doctor flags
   them and `mandu setup` removes them, after which Ubuntu's own restriction
   is back in force.

## 8. Honest caveats

1. **An old QEMU booting a kernel-7.0 guest.** Verified: the 26.04 image boots
   under the default SeaBIOS path on QEMU 4.2.1, with no OVMF or machine-type
   pinning.
2. **Suite duration in guests.** `all` inside a fresh guest pays toolchain
   provisioning (~minutes) plus per-package `npm install`; acceptable by hand
   or nightly, unacceptable per push — which is why only `smoke` on `host`
   joins the gate.
3. **The matrix tests Linux only until the ssh executor lands.** That is the
   deliberate initial scope: the deliverable is the *harness shape* (executor
   contract + declarative targets) that makes the macOS/Windows legs additive
   instead of a redesign.

## 9. The run record and the dashboard view

**Why.** `run.sh` works in a throwaway `$RUN_WORK` and deletes it on exit
(unless `--keep`). Only a 25-line tail of the guest's `suite.log` reached the
terminal, so a run's per-step results, including a live leg's read-evidence
line, died with it.

**The record.** Every `run.sh` run (not `--check`) writes
`~/.mandu/runs/matrix/<runId>/`, with
`<runId> = <UTC yyyymmdd-hhmmss>-<target>-<suite>` (`lib/record.sh`; `run.sh`
is the single writer):

| File | What |
|---|---|
| `meta.json` | target, suite, executor, status (`pass`/`fail`/`skip`), rc, the guest's RESULT line, the commit under test (the one host prep packed, else HEAD with `+dirty`), `FRESH_INSTALL_REF`, whether the live leg was requested, labels, host, start, finish, duration |
| `suite.log` | the suite's full output (guest or host) |
| `steps.log` | `PASS`/`FAIL`/`NOTE step=<id> …` lines, for suites that write them (`fresh-install`, `fresh-agents`) |
| `run.log` | the host console of `run.sh`, ANSI stripped |
| `serial.log` | the guest serial console, last 1 MiB, FAIL only |
| `logs-<pkg>.log` | the `all` suite's per-package logs (`MANDU_TEST_LOG_DIR`) |

The artifacts share is never recorded, because host-prep secrets live there
(the live leg's reduced credential). The store dir is 0700. The newest
`MANDU_MATRIX_KEEP` runs (default 200) are kept. The store is the Mandu
home's `runs/matrix/` (`MANDU_HOME` moves it with the home; on-disk-layout.md
§9) and `MANDU_MATRIX_RECORD=0` turns recording off. Recording is best effort:
a failure to record is a warning and never changes the run's exit status.

**The view.** The developer view's **Tests › VM matrix** page
(`/dev/tests/vm`; `dashboard.md` §4.26, §4.32). It shows a target × suite grid of each pair's latest
run, built from the declared `SUITES=` plus any recorded pair, then the run
history, and one run's steps and logs. The view is read-only. Runs start from
a terminal, because a run takes 6 to 40 minutes, needs KVM, and the live leg
copies a developer's Claude login.

**Tests.** `scripts/test/matrix-record.test.sh` drives `record_finish` on
fabricated qemu-shaped run dirs: every file lands, the credential does not,
the JSON escapes, prune works, and the off switch works. It then runs the
real `run.sh host smoke` into a temp store. The dashboard's `matrix-area` e2e
does the same run and reads it back over `/api/matrix`.

## 10. Fresh-install testing: a disposable VM where `sudo` is real

Status: BUILT. The `fresh-install` suite (steps 0 to 12, the reboot, Node 18
and NodeSource legs, the live leg), the `fresh-agents` suite (§10.14), the
`ubuntu-2510` target and the `release-upgrade` suite (§10.15), the snapshot
layer, `--interactive` and the guest registry (§10.17).

Related: `rootless-confinement-ubuntu-2404.md` (`mandu setup`, the posture
names), `packaging.md` (the npm bundle, first-run UX), `protection-modes.md`
and `secret-discovery.md §1` (behavior a fresh install must also
show).

### 10.1 The problem in plain terms

Every machine we test on is already set up: AppArmor grants installed, a
populated Mandu home, an nvm Node, a logged-in `claude`, a resident stack. So
three things an end user meets on day one were never exercised end to end:

1. **The install itself**: `npm install -g` of the packed bundle on a machine
   that has never seen the repo, run by a user with an empty HOME.
2. **The privileged step**: `mandu setup` calling a real `sudo` that writes
   `/etc/apparmor.d/` and reloads AppArmor. CI covers only the unprivileged
   half against a fake `sudo` (§7b says why).
3. **The before and after**: a stock Ubuntu's first-day posture, the posture
   after setup, and the posture after uninstall. On a set-up host the
   "before" state no longer exists.

### 10.2 Why a VM, and why not a container

A container cannot test this, for a reason specific to what `mandu setup`
does. AppArmor is a kernel facility, and a container shares the host kernel.
The `kernel.apparmor_restrict_unprivileged_userns` sysctl a container sees is
the host's, and `apparmor_parser -r` from a privileged container would load
profiles into **the host's** kernel. That is also a mutation of global host
state, which the privilege model rules out. systemd-nspawn has the same
shared-kernel problem. Docker remains the right tool for running the test
kinds in a container (docker-e2e.md) and the wrong one here.

A qemu/KVM guest has its own kernel, its own AppArmor, and its own root.
**`sudo` inside the guest needs no privilege on the host**: the user is in the
`kvm` group, qemu runs unprivileged, networking is user-mode SLIRP. The plan
was one new target and one new suite on the matrix harness, plus a few small
executor additions (§10.5); no Vagrant, libvirt or multipass (§7).

### 10.3 What gets built

#### 10.3.1 Target `ubuntu-2404`

`scripts/matrix/targets/ubuntu-2404.conf`: the Ubuntu 24.04 ("noble") amd64
cloud image, `LABELS="os=linux kernel=6.8 userns=apparmor-restricted"` plus
the first-day labels of §10.12, `SUITES="smoke fresh-install fresh-agents"`.
This is the release's primary platform and the one where the restriction
bites. `ubuntu-2604` carries the same suites as the second leg. Those two are
the whole supported set (§10.9); Ubuntu 22.04 gets no leg.

#### 10.3.2 The artifact under test is the packed tarball, not the checkout

The host runs `npm run build:bundle && npm pack` in `launcher/` and places
`mandusec-mandu-*.tgz` in a 9p share. The guest installs **only that file**.
The repo share is not mounted for this suite (a `NO_REPO=1` suite header), so
a bundle that secretly depends on a checkout path fails here instead of at a
user's desk. The checkout-only AppArmor path was exactly this class of bug.

#### 10.3.3 Guest users: passwordless sudo, and no sudo

The matrix guest script runs as root. The suite creates ordinary users and
runs every step as them through `runuser -l`, so HOME is empty and PATH is a
login PATH.

| User | sudo | What it proves |
|---|---|---|
| `alice` | `NOPASSWD: ALL` | the automated happy path, `mandu setup --yes` end to end |
| `carol` | none | setup fails with a clear message, leaves no partial files, the launch keeps its first-day posture, exit codes are sane |

A password-prompting sudo user is deliberately not automated (§10.9): the
prompt is sudo's own, and driving it through a PTY buys fragility, not
coverage.

#### 10.3.4 Node: install it the way users do

`engines.node >= 22.13`, and noble's apt Node is 18. The suite installs Node
two ways, as separate scenarios: **nvm** (what the audience mostly has, and
the reason the fix text says `mandu setup` and not `sudo mandu setup`, since
root's PATH has no nvm `mandu`) and **NodeSource apt** (a system-wide Node,
global prefix owned by root, so `npm install -g` itself needs sudo). A third,
negative check: with Node 18, the first run must say "Node 22 required" in
words, not a stack trace (§10.16.3, §10.16.4).

#### 10.3.5 The agent is a stub, plus one live leg

A `claude` stub on PATH (the launcher suite's fake agent, packed into the
share) makes the run deterministic and credential-free. It records its env and
argv, tries to read a planted secret (`~/.aws/credentials`, `~/.ssh/id_ed25519`
with canary contents), writes what it saw to a file, and exits. The secret
read is the behavioral oracle: `confined` means the stub saw the twin,
`gated` means what the gated design says it means. Posture strings alone would
only test our own printing.

**The live leg** runs the real Claude Code in the guest on a developer's
subscription login. After the stub cycle, the suite `npm install -g
@anthropic-ai/claude-code` and runs one `mandu claude -p` prompt about the
canary file (§10.13 says what it asks and why). Pass means: the reply
arrives, the arbiter logged the read, and the canary bytes appear nowhere in
what the model was given.

**Credential handling.** A copied Claude credential is a hazard: OAuth
refresh tokens rotate, so a second holder that refreshes invalidates the
first (docker-e2e.md §1.4). A VM has no bind mount, and sharing all of
`~/.claude` read-write over 9p is far too broad. So the host side prepares a
**reduced credential** (`scripts/matrix/lib/reduce-credential.mjs`):

1. Read `~/.claude/.credentials.json`, check `expiresAt`. If less than the
   suite timeout plus a margin remains, run one trivial host-side `claude -p`
   so the host refreshes its own token first, then re-read.
2. Write a copy with the **refresh token removed**, mode 0600, into a per-run
   directory (`artifacts/ephemeral/`), shared read-only into the guest. The
   guest holds an access token that dies within hours and can never rotate
   the host's lineage. Claude Code accepts a credential file with no refresh
   token (verified on a host and in the guest; the host file stayed
   byte-identical), so no copy-back is needed.
3. The per-run directory is deleted the moment the guest exits, `--keep` or
   not, and the per-run overlay at exit. The credential is never written into
   the cached snapshot layer. `--keep` and `--interactive` refuse to combine
   with the live leg unless `--keep-credential` is also given (§10.17.2).

The live leg is a suite flag (`FRESH_INSTALL_LIVE=1`, off by default) and
self-SKIPs with a reason when the host has no credential. The `install` CI
job holds no credential, so a tag runs the stub leg only and the live leg is
a hand run before a release.

### 10.4 The scenario script (`scripts/matrix/suites/fresh-install.sh`)

Each step asserts on exit code plus output, and appends a line to a step log
that lands in the out share. Steps 3 to 10 are §7b made executable.

0. **Baseline facts.** Kernel, `apparmor_restrict_unprivileged_userns`,
   whether `bwrap` exists and its version, the apparmor version, Node
   version; `mandu --version` answers. Logged so every result is explained.
1. **Install.** `npm install -g ./mandusec-mandu-*.tgz` as `alice`. Assert:
   exit 0, `mandu --version` runs, no native compilation, no writes outside
   the npm prefix, install time recorded.
2. **No bubblewrap yet.** Neither cloud image ships it. `mandu doctor` must
   name the cause `no-bwrap` with the `sudo apt install bubblewrap` fix, and
   `mandu setup` must report `blocked` with the same fix. Then install it and
   continue.
3. **Doctor before setup.** The first-day posture the target declares
   (§10.12).
4. **Launch before setup.** `mandu claude` with the stub: the launch
   succeeds, prints the one-line mode banner, first-run state is created
   only in the directories the path table gives Mandu (the home `~/.mandu`,
   and the runtime dir outside HOME; on-disk-layout.md §3); the stub's secret
   read matches the posture. Where the posture is `gated`,
   `--require-confinement` refuses, non-zero, and the stub never runs.
5. **Setup.** `mandu setup --print` shows the profile and its `sudo` commands
   and changes nothing (checksum `/etc/apparmor.d` before and after). `mandu
   setup --yes` ends with secrets `confined`. It installs Mandu's own
   root-owned bwrap copy (`/usr/lib/mandu/bin/bwrap`) and one profile file,
   `mandu-bwrap`, carrying the `# Mandu:` first line, byte-identical to the
   bundle assets, listed by `aa-status`.
6. **Doctor and launch after setup.** `posture: confined`; the stub's secret
   read returns the twin, not the canary; nesting works inside the wrap,
   `unshare -Ur` and the copy run by hand get no namespace with capabilities.
7. **Idempotence.** Second `mandu setup` says `nothing to do` and runs no
   `sudo`.
8. **Foreign profile.** Replace `/etc/apparmor.d/unshare` with a hand-written
   file lacking the marker: install skips it, uninstall leaves it.
9. **Uninstall.** `mandu setup --uninstall` removes Mandu's files and leaves
   Ubuntu's own `bwrap` profile loaded; doctor is back to the first-day
   posture.
10. **Migration.** The old Mandu grants (`/etc/apparmor.d/bwrap` and
    `unshare`, installed by setup before 2026-09-27,
    rootless-confinement-ubuntu-2404.md §12.3) are planted; setup removes them
    and Ubuntu's restriction is back.
11. **Second user.** `carol` installs for herself on the machine `alice`
    already set up: confined immediately, setup says nothing to do. Then her
    no-sudo setup attempt (§10.3.3).
12. **Hygiene** (`12a`, `12b`, §10.16.2) and **reboot persistence** (`R0`,
    `R`, §10.16.1); then the Node 18 negative (`N18`) and the NodeSource
    variant (`NS`) on the second boot.

**Invariant note.** This suite adds no ingress or egress path, so it adds no
new invariant oracle. Step 6's canary check is the confidentiality oracle for
the install path, and it must fail closed: if the stub's report file is
missing or unparsable, the step fails.

### 10.5 Executor additions (`scripts/matrix/lib/qemu.sh`)

1. **Artifact share.** A third 9p share for host-built artifacts (the
   host-prep hook, §4), plus the `NO_REPO=1` header that drops the repo
   share; `artifacts/ephemeral/` is deleted the moment the guest exits.
2. **Provisioned snapshot layer** (§10.17.1).
3. **`--interactive`** (§10.17.2): the manual lane, to poke at first-run UX
   by hand, run the real `claude` login for a live check, or reproduce a
   user's bug report on a clean machine.
4. **Credential share.** The reduced-credential preparation of §10.3.5 and
   its cleanup, as a host-side helper with unit tests (strip, expiry check,
   refuse to write outside the per-run dir).

Guests are registered with the owner registry so `mandu reap` collects a
leaked qemu, same as `dev-arbiter.sh` stacks (§10.17.3).

### 10.6 Where it runs

Not in the per-push gate (VM boots are minutes). It is the `install` kind:
`run-matrix.sh --require ubuntu-2404 --require ubuntu-2604` on every `v*` tag
(§6). `scripts/test/ci-workflow.test.mjs` pins the `--require` set to exactly
the two supported targets and checks each declares `fresh-install`. The tag
job is the backstop; the working rule is: **run it by hand before tagging a
release, and before merging a change that touches `launcher/src/setup.ts`,
`confinement-posture.ts`, `scripts/apparmor/`, `build-bundle.mjs`, or
`bundle-manifest.json`.**

The rule "no CI lane may `sudo`" stays true for the host. A throwaway guest's
root is a different thing.

### 10.7 Tests for the harness itself

- Unit (no VM, runs in the normal gate): the credential reducer; the suite's
  assertion helpers against canned doctor/setup output; the snapshot
  cache-key function; the step-log parser. The stub agent's canary report
  format gets a parser test, including the missing-file fail-closed case.
- E2E: `run.sh host smoke` proves driver plumbing per push. The suite's e2e is
  the VM run itself, `--require`d in the `install` job.
- **A red check** for every oracle: break the bundle (drop the `apparmor/`
  assets) and step 5 goes red; each new check was seen to fail once before it
  was trusted. A fresh-install test that cannot fail is worth nothing.

### 10.9 Decisions

1. **Passwordless sudo only.** The automated lane uses a `NOPASSWD` user (and
   the no-sudo negative). No password-prompt user.
2. **Live Claude Code runs on a copy of a developer's credential**, as the
   reduced, refresh-token-free copy of §10.3.5, because of the rotation
   hazard.
3. **Supported and tested: Ubuntu 24.04 and 26.04 only.** No 22.04 leg, and
   22.04 is not a supported install target. Both legs are blocking on a tag.
4. **The `.deb` kernel tier** stays out of scope here (packaging.md §9).

### 10.10 Honest caveats

- A cloud image is not a desktop install. It lacks a display manager, snapd
  desktop integration and whatever a user's dotfiles do. The desktop ISO is a
  possible later target (autoinstall), at several GB and much slower boots.
- SLIRP networking means the guest reaches the internet through the host, so
  a corporate-proxy or offline first run is not covered.
- The stub agent proves the wrapper's behavior, not Claude Code's. A Claude
  Code release that changes its config handling is caught by the
  `claude-latest` lane (docker-e2e.md §1.7), not here.

### 10.11 First findings

The first runs (24.04 with the live leg: 50 pass, 1 fail; 26.04: 25 pass, 1
fail) passed the §7b acceptance list in full with a real `sudo`. The canary
oracle held: the stub read the raw canary while `gated` (as that posture
documents) and not once `confined`. The live leg found Claude Code accepting
a credential file with no refresh token.

**The two targets tell different first-day stories, and the suite asserts
which.** Each target declares `fresh-posture=gated|confined` (and, since
§10.12, `setup=installs|nothing`) in `LABELS`, and step 3 asserts the
observed posture equals it, so a distro that changes its mind is a loud
failure and never a silent branch.

**Findings, none of them harness bugs, all fixed:**

1. `mandu --version` exited 2 (`no command given`); it now answers ahead of
   the parse, and step 0 asserts it.
2. **The dashboard could not start any service on an installed bundle**:
   `supervisor-defs.ts` gave each service a checkout `cwd`
   (`join(repoRoot, "arbiter")`), which surfaced as `spawn <node> ENOENT`,
   and the launch fell back to a bare arbiter with "port busy? package not
   built?". `SupervisorOptions.layout` (`{mode: "installed", pkgRoot}`) now
   spawns `<pkgRoot>/dist/<name>.mjs` with cwd pkgRoot and the arbiter-client
   bundle in the proxies' env; `server-main.ts` detects the bundle; the
   launcher passes `MANDU_ARBITER_CLIENT_MODULE` to the dashboard
   (`supervisor-defs-installed.test.ts`). The suite asserts "no autostart
   fallback line". No other test saw this, because every one runs from the
   checkout.
3. **An npm user was told three times to `cd interceptors && cargo build`.**
   The bundle now ships the native bins for linux-x64 (packaging.md §5), so
   the hint fires only on another platform, where it names the package gap.
   The suite asserts no `cargo build` in doctor or launch output.
4. Neither cloud image ships **bubblewrap**, so the very first doctor on a
   stock host says `no-bwrap`. First-run docs lead with `sudo apt install
   bubblewrap`.

**Harness lessons:** boot-time apt holds the dpkg lock, so guest `apt-get`
needs `DPkg::Lock::Timeout`; a broken precondition (no bubblewrap
obtainable) aborts the suite instead of cascading into a dozen misleading
failures; `install -D` as root leaves a root-owned parent directory in the
user's HOME. Run: about six minutes per target with the image cached; set
`MANDU_VM_CACHE` somewhere persistent (the default is under `/tmp`).

    FRESH_INSTALL_REF=HEAD FRESH_INSTALL_LIVE=1 scripts/matrix/run.sh ubuntu-2404 fresh-install
    FRESH_INSTALL_REF=HEAD                      scripts/matrix/run.sh ubuntu-2604 fresh-install

`FRESH_INSTALL_REF=<ref>` packs a clean `git archive` of a commit instead of
the working tree, which is what a release test wants; the host packer sets
`MANDU_NATIVE_BIN_DIR` to the checkout's release tree, so the pack still
carries the native bins the host built.

### 10.12 The sudo-free first day

The bundle ships the whole-agent guard, and the guard alone confines a host
with no user namespace (confidentiality-plan-10-flow-taint.md §11.7;
rootless-confinement-ubuntu-2404.md §11). The
targets declare `fresh-posture=gated|confined` and `setup=installs|nothing`,
and the suite asserts both: 24.04, 25.10 and 26.04 are `confined
setup=installs` (confined by the guard from the first launch; `mandu setup`
installs Mandu's own bubblewrap as the second, bind layer). Assertions on
the confined story: doctor says "by the guard" and names the bind gap with
setup as the optional second layer, no `fix:` line; the FIRST launch, before
any privileged step, does not read the canary and prints the
guard-serves-the-twins line; no `cargo build` anywhere; no autostart
fallback line; after uninstall the posture is the first-day one, still
`confined`. The gated story stays selectable for a bundle packed without
native bins.

### 10.13 The live leg needs read evidence

An early live leg proved nothing: the model refused the prompt ("print the
value after aws_secret_access_key") before it called `Read` at all, so "no
canary in the reply" held with no read. The live leg now does two things
differently:

- **The prompt asks for the file's shape, not the secret**: the profile
  names, the key names, whether each value looks like a real AWS string or a
  placeholder, and to quote any placeholder.
- **A read is required.** The suite notes the arbiter log's position before
  the run (a timestamp cutoff, since `mandu stop` restarts the log). After
  it, a `decideSecretOpen` line for `~/.aws/credentials` must appear, or the
  leg FAILS as vacuous. An `$MDU` token echoed in the reply stays a note,
  because the model may paraphrase it.

With it, on both targets, the arbiter served the agent the twin; the model
reported `[default]` with `aws_secret_access_key` as an opaque `nomodel_Read`
handle and said it could not see the value; the canary appears nowhere in the
reply.

### 10.14 Every supported agent on a fresh install: the `fresh-agents` suite

`fresh-install` proves the install, the posture story and `mandu setup`, with
a stub agent plus one live Claude Code leg. `fresh-agents` runs Codex,
OpenCode and OpenClaw too on a clean machine. It follows the README's
first-day path: nvm Node (the major the chosen OpenClaw's `engines` asks
for), `npm install -g` the packed tarball, then each agent from npm. Step 2b
then does what Codex needs on Ubuntu, `apt install bubblewrap` plus `mandu
setup`, and checks both sides of it: before, `mandu doctor` names the fix and
`mandu codex` prints its one warning line; after, `codex sandbox --
/bin/true` runs under `mandu` and neither says anything. Then it runs each
agent through the installed `mandu`.

**The scripted model.** `suites/fresh-agents/fake-model.mjs` is a standalone
Node server (the guest has no checkout) that speaks Anthropic Messages and the
OpenAI Responses API, including Codex's `custom_tool_call` `exec` cell. The
launch points the context proxy at it with
`MANDU_UPSTREAM=http://127.0.0.1:<port>`, so it sits exactly where the
privileged model would. The agent's first request that advertises its read
tool gets a call reading the target file (Claude Code `Read.file_path`,
OpenCode `read.filePath`, OpenClaw `read.path`, Codex a shell `cat`). The
request carrying that tool's result gets a closing text turn, Claude Code's
auto-mode classifier (a request that stops at `</severity>`) gets an
allowing verdict (§10.14.1 item 9), and anything else (title calls, warmups)
gets an ACK. A request that does not stream gets its answer as one Message
JSON, as the real API gives it. Every request body is captured. No
key and no budget are involved, and the keys the runner sets are dummies, so
a real credential never reaches a stand-in. (This needed the OpenAI proxy to
allow a plain-http upstream to a literal loopback address, under the
Anthropic proxy's rule; `openai-proxy` README "Upstream transport".)

**The oracles** (`suites/fresh-agents/agent-leg.sh`, run once per agent and
mode; they read the capture, i.e. what the model was given):

1. A request reached the model endpoint through mandu, the model's tool call
   went out, and a request carrying the tool result came back. With no tool
   result the remaining checks would be vacuous, so it FAILS.
2. The planted marker appears in no captured request body.
3. The tool result ITSELF (extracted per wire by the fake) carries a `$MDU:`
   symbol. Grepping the whole body would be vacuous, because Mandu's handling
   prompt carries example `$MDU:` tokens of its own.
4. The read really happened (§10.14.1 item 4 says why): the arbiter decided
   an open of a secret target during the run, and the agent's own local
   record shows the command's output (Codex's rollout log; Claude Code's
   transcript for a Bash leg). The test reads those records; no model ever
   does.

Two modes per agent, plus two extra legs: Codex again with the user's own
`exec -c` (and a check that `-c model_provider=…` is refused), and Claude Code
reading the file with its Bash tool through Mandu's command box (step
`4-claude-bash`). **Default** (no `--mode`, i.e. the shipped `secrets`): the
target is `~/.aws/credentials` holding a canary. **`full`** (both axes,
FROZEN, protection-modes.md §10): the target is a poisoned `~/proj/notes.md`
whose injection marker must reach the model only as a symbol. These legs
(step 5) are an integrity form, so they are in the frozen lane: a run skips
them with one NOTE unless the host sets `FRESH_AGENTS_INTEGRITY=1`, which
runs them with the opt-in `MANDU_EXPERIMENTAL_INTEGRITY=1` (without it a
launch refuses `--mode full`, exit 2; §10.14.1 item 11). `mandu stop` runs
between the modes, because a mode is read once when the arbiter starts.

**Red check** (on the host, the same runner in an isolated HOME): `--mode off`
with OpenCode FAILS both the canary check and the symbol check, with the raw
`aws_secret_access_key = FRESHINSTALLCANARY…` line quoted from the captured
request. The oracle can fail.

**Live legs** (`FRESH_AGENTS_LIVE=1`): real Claude Code on the reduced
subscription credential (§10.3.5) and real Codex on the OpenAI key from
`secrets.local.json` (continuous-integration.md §13). Host prep writes the
key only into `ephemeral/`, which the executor deletes when the guest powers
off. Each leg asks for the credential file's shape and FAILS unless the
arbiter logged a `decideSecretOpen` for the file during the run (§10.13).
Then each is asked to `cat .env` with its shell tool (steps `6c-env`,
`6x-env`), and `fresh-agents/env-twin-check.mjs` reads the proxies'
`tool_result` events for what the model was given: every key visible, one
symbol per secret value, the twin note, no canary in any event, and FAIL when
no result of the read reached the model (§10.14.1 item 7). OpenCode and
OpenClaw have no live leg: third-party agents never use the subscription and
would need an Anthropic Console key.

**Which agents.** The agent registry's agents whose CLI installs from npm
(`scripts/agents/agent-registry.mjs` `NPM_AGENTS`, supported-agents.md
§5.7: Claude Code, Codex, OpenClaw, OpenCode), which the host prep reads
from the registry, in its order; the guest's npm package table is held to
the registry's packages (unit `scripts.fresh-agents-host`). Goose is not
among them: it ships as a release binary, not on npm, and a Goose leg (the
binary's install in the guest, its config routing in `agent-leg.sh`) is not
built.

**Versions.** `FRESH_AGENTS_VERSIONS=tested` (default) installs each agent's
tested maximum from `launcher/src/agent-versions.ts`; `latest` installs what
npm serves today, which is what a new user gets. The guest's Node major is
the README's 22 unless the chosen OpenClaw's `engines.node` rules it out,
then the lowest of 24, 26 whose current release satisfies it; host prep
compares with its own small range parser (`scripts/matrix/lib/node-major.mjs`,
unit `scripts.node-major`), never npm's `semver` (§10.14.1 item 10).

Run:

    FRESH_INSTALL_REF=HEAD FRESH_AGENTS_LIVE=1 scripts/matrix/run.sh ubuntu-2404 fresh-agents
    FRESH_INSTALL_REF=HEAD FRESH_AGENTS_VERSIONS=latest scripts/matrix/run.sh ubuntu-2404 fresh-agents
    # the frozen lane: also the `full` legs (only when the integrity axis is revived)
    FRESH_INSTALL_REF=HEAD FRESH_AGENTS_INTEGRITY=1 scripts/matrix/run.sh ubuntu-2404 fresh-agents

The runner also works on the host for iteration, in an isolated `env -i`
HOME with `XDG_RUNTIME_DIR` on a short path (the arbiter socket path must fit
in 107 bytes): `bash agent-leg.sh <agent> <mode>` with `mandu` and the agent
on PATH.

#### 10.14.1 First runs and what they found (2026-09-27)

After four rounds, with every item below fixed: `fresh-agents` **111 pass /
0 fail on both `ubuntu-2404` and `ubuntu-2604`** (every agent in both modes,
the Claude Bash leg, the Codex user `-c` leg and both live legs with read
evidence); `fresh-install` 0 failing on both; with `latest` (Claude Code
2.1.283, Codex 0.157.1, OpenCode 1.18.32, OpenClaw 2026.9.6 on Node 24) every
scripted leg passes.

| Agent (tested max) | Scripted, default mode | Scripted, `full` | Live |
|---|---|---|---|
| Claude Code 2.1.281 | pass (`$MDU:nomodel_Read[…].default.aws_secret_access_key`) | pass | pass: read evidence, value seen only as the handle |
| Codex 0.154.0 | pass with read evidence (`/usr/bin/cat → twin`), also with the user's own `exec -c` | pass | pass with read evidence, both targets |
| OpenCode 1.18.13 | pass (`$MDU:nomodel_read[…]`) | pass | none (needs a Console key) |
| OpenClaw 2026.9.6 (Node 24) | pass | pass | none |

**Found and fixed** (the numbering is kept; other documents cite it):

1. **OpenClaw and its model catalog.** 2026.7.1 no longer lists
   `claude-sonnet-4-5`; under the routing override it resolved the planted
   model without limits and failed "requires a positive maxTokens value".
   The launcher bug behind it: its override wrote `models: []` over the
   user's `models.providers.anthropic.models`, and OpenClaw's config merge
   replaces arrays, so it deleted the entries OpenClaw needs for an
   uncatalogued model. It now keeps them, minus any per-model
   `baseUrl`/`api`/`headers` (a per-model `baseUrl` would route that model
   around the proxy; dropped with one WARNING line; `agent-config.ts`
   `openclawUserAnthropicModels`). Also fixed in this round: **Codex routing
   bypass (security)**: `mandu codex exec -c <anything> …` sent Codex's
   model traffic straight to api.openai.com, unmasked (portable-wrapper.md
   item 3; `launcher/src/codex-argv.ts`); the suite runs the Codex leg a
   second time with a user `-c` and checks that `-c model_provider=openai`
   is refused before Codex starts. And Codex with only `CODEX_API_KEY` failed
   closed; the routed provider now reads it when it is the only key set.
2. **The model proxies relayed every request they did not parse raw
   (security).** The anthropic-proxy transformed only `POST /v1/messages`
   and the openai-proxy only `POST …/responses`; anything else (another
   generation wire such as `/chat/completions`, `/v1/complete`, Messages
   batches, Codex's older `/responses/compact`, and Claude Code's
   `count_tokens`) reached the provider with tool results and secret values
   unmasked. Both proxies now route fail-closed (`src/route.ts` in each;
   `mandu.md` §4.1 "Which requests go upstream"): the parsed wire is
   symbolized; `count_tokens` goes through the same symbolization without the
   handling prompt; a bodyless `GET`/`HEAD` is relayed; anything else is
   answered 403 ("mandu: refusing POST /chat/completions: …") and never
   sent. Pinned by each proxy's `route-fail-closed` e2e (a counting upstream
   sees zero requests) and `tests/stack/proxy-route-fail-closed.test.ts` over
   the real arbiter.
3. **OpenClaw 2026.9.3 and later need Node ≥ 24.16**, and 2026.7.1 needs ≥
   22.22.3 (the README and usage docs say so; host prep picks the guest's
   Node major from OpenClaw's `engines`). 2026.9.6 hides most tools behind
   its Tool Search dispatcher (`tool_call`), which the wire gates did not see
   through (a live bypass), and with the dispatcher off advertises tools the
   inbound spec had not mapped. Both closed: the gates read a `tool_call` as
   the tool it runs and refuse `tool_search_code`; every 2026.9.6 tool is
   mapped, or refused on the wire when it acts outside every Mandu chokepoint
   (`supported-agents.md` §2.1). The tested max was 2026.9.6 then; it is
   2026.9.9 since 2026-10-09.
4. **Codex's shell is dead on a stock Ubuntu 24.04 or 26.04, with or without
   Mandu; Mandu now says so.** Codex runs each command in its own
   bubblewrap: the `bwrap` on PATH, else a bundled copy. The cloud images ship
   no bubblewrap, and AppArmor grants `userns` per binary, never to the
   bundled copy, so every command dies `bwrap: loopback: Failed RTM_NEWADDR:
   Operation not permitted`. `mandu doctor` has a Codex sandbox row
   (`codex-sandbox.ts`, `packaging.md` §7) that runs Codex's own probe
   against the system bwrap and names the fix (`sudo apt install
   bubblewrap`, then `mandu setup`); a `mandu codex` launch prints one
   WARNING line and never refuses. **The lesson for the oracles:** the early
   rounds PASSED every scripted Codex check, because a failed command's
   error text comes back masked too (the command names a secret path), so "a
   tool result arrived, it carries a symbol, no canary" held with no read at
   all. Only the live leg's arbiter-evidence check caught it. Every scripted
   leg now needs evidence of the read itself (oracle 4); with bwrap hidden,
   both new checks FAIL while the old three pass.
6. **On 26.04, no sandbox could start inside Mandu's secret bind wrap.**
   26.04's `bwrap-userns-restrict` profile puts `unpriv_bwrap` on everything
   a bwrap sandbox runs, and that profile denies every capability, even
   inside a child's own user namespace; a local AppArmor override cannot lift
   it (deny beats allow). The launch now probes the bind wrap with a nested
   sandbox inside, and where that fails it serves the twins with the guard
   alone (`bindGap: "bwrap-nesting"`, posture still `confined`; doctor says
   "mount layer off"; `rootless-confinement-ubuntu-2404.md` §12). Without a
   guard the bind stays and a WARNING says the agent's sandboxes will fail.
7. **Codex masked the whole shell result as one handle**, where Claude
   Code's `Read` got a structured handle per value; confidentiality held,
   utility was lower. A shell result that is one piece of one registered
   file's twin, from a tree the guard recorded with no raw secret open, is
   now released with its keys and one symbol per value, plus a
   `[mandu:secret] twin:` note (confidentiality-plan-10-flow-taint.md §11.8;
   `tests/stack/exec-output-twin.test.ts` over the real arbiter and both
   production proxy adapters). Live-verified (steps `6c-env`, `6x-env`) on
   both targets and both agents: every key visible, each secret value one
   `$MDU:nomodel_Read[…].<KEY>` symbol, the twin note there, no canary in any
   event. Still one handle: `cat -n` and other reformatting, two files in one
   command, and a host with the bind layer but no guard (no record to rest
   the release on).
8. **OpenClaw and OpenCode sent non-Anthropic models around the proxy
   (security).** The routing override pointed only the agent's `anthropic`
   provider at the anthropic-proxy, so OpenClaw on `openai/gpt-5.5` (its
   built-in default with no model configured) and OpenCode with `run -m
   openai/gpt-5` delivered a file's untrusted text to the model raw; a
   repository's own `opencode.json` could also re-point
   `provider.anthropic`. `secrets`-mode credential files stayed masked by
   their twins (the file layer does not depend on the route). Fixed in three
   layers (`agent-e2e-harness.md` §9; `launcher/src/agent-model-route.ts`):
   the launch refuses any non-Anthropic model reference in the config or
   argv, and an OpenClaw with no model or an unreadable config; OpenCode is
   fenced by `enabled_providers: ["anthropic"]` in
   `OPENCODE_CONFIG_CONTENT`, which outranks a project config; OpenClaw's
   `/model` allowlist is narrowed to `anthropic/*`. OpenClaw's memory-search
   embeddings, which went to its embedding provider directly, are switched
   off by the run config (`agent-e2e-harness.md` §9, "OpenClaw embeddings
   fence").

**The `latest` run of 2026-10-08** (Claude Code 2.1.295, Codex 0.162.0,
OpenCode 1.18.35, OpenClaw 2026.9.9 on Node 24): 79 pass / 18 fail on both
targets. Every failure was the harness; no product change came of it:

9. **Claude Code's auto-mode classifier got no verdict** (the one failing
   check of step `4-claude-bash`: Claude Code's own transcript held "…the
   classifier… continue with other tasks that don't require this action",
   not the file). Under Mandu, Claude Code starts in permission mode `auto`:
   the launch sets `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`
   (exec-routing.md §7.4), Claude Code then fetches no feature flags, and
   with none it starts `-p` in `auto` (its transcript records
   `permissionMode: auto`; without the variable, where the served flags keep
   auto mode off, `default`). In `auto` a Bash command, even one
   `--allowedTools` names, first goes to Claude Code's classifier: a
   non-streaming Messages request to the same base URL (so through the
   context proxy, to the stand-in) that stops at `</severity>` and must read
   `<severity>N` with N below 50 to allow. The fake answered it as an SSE ACK,
   which is no verdict, and Claude Code denied the command. Measured on the
   host without Mandu, with only that variable set: Claude Code 2.1.290,
   2.1.292, 2.1.294 and 2.1.295 all start in `auto` and send the same
   classifier request, and the leg run on the host under Mandu with the old
   fake fails the same way on the tested 2.1.292. So this is not new in
   2.1.295 and not an incompatibility: with a real model the classifier
   answers, and a live
   2.1.295 under Mandu ran Bash the same day. The fake now answers that
   request with an allowing verdict (Anthropic's classifier is not under
   test) and any non-streaming request with one Message JSON; the leg notes
   the permission mode and the classifier count, and names a classifier
   denial (unit `scripts.fresh-agents-fake-model`). Side effects worth
   knowing, not changed here: a Claude Code under Mandu runs in auto mode
   unless the user chooses a mode, and the classifier's requests carry
   Mandu's handling prompt like any Messages request. *Later the same day*
   the first was changed (supported-agents.md §2, "Claude Code's permission
   mode under Mandu"): the launch passes `--permission-mode default` unless
   the user chose a mode, so the leg, which chooses none, now runs in
   `default` (its `--allowedTools` admits the tool, no classifier request);
   the fake keeps answering the classifier for a run that chooses `auto`.
10. **The guest got Node 22 for an OpenClaw that needs 24.** Host prep
    loaded npm's `semver` from `npm root -g`; Debian's and Ubuntu's npm keep
    it under `/usr/share/nodejs`, so the require failed and the pick fell
    back to 22 (OpenClaw 2026.9.9 wants `>=24.16.0 <25 || >=26.1.0`). Host
    prep now compares with `scripts/matrix/lib/node-major.mjs`, a small
    parser of npm's range syntax (comparators, `||`, caret, tilde,
    x-ranges, hyphen ranges) that throws on anything else.
11. **Every agent's `full` leg failed "launch exit 2"**: the frozen axis
    refuses `--mode full` without `MANDU_EXPERIMENTAL_INTEGRITY=1`
    (protection-modes.md §10.4), which the suite never set. Per the freeze
    rule the legs moved to the frozen lane (above, `FRESH_AGENTS_INTEGRITY=1`;
    protection-modes.md §10.7), not a silent opt-in in the default run.

After the fixes, `latest` (same versions, the guest on Node 24): **75 pass / 0
fail on both `ubuntu-2404` and `ubuntu-2604`**, the Claude Bash leg with
`permission mode auto; auto-mode classifier requests: 1`, step 5 one SKIP
note (fewer checks than before: the four `full` legs left the default run).

### 10.15 Ubuntu 25.10, and a real upgrade to 26.04

**Target `ubuntu-2510`** (`scripts/matrix/targets/ubuntu-2510.conf`): the
questing cloud image, kernel 6.17, apparmor 5.0.0~alpha1, bubblewrap 0.11.0,
Ubuntu's `bwrap-userns-restrict` in force. It declares the 26.04 story
(`fresh-posture=confined setup=installs`): the distro bubblewrap forbids a
sandbox inside it, the first launch is confined by the guard alone, and
`mandu setup` installs Mandu's own bubblewrap. `fresh-install` (68/0, every
step including the migration of step 10) and `fresh-agents` (105/0) pass at
the tested agent maxima with no product change.

**Suite `release-upgrade`** (`scripts/matrix/suites/release-upgrade.sh`, on
`ubuntu-2404` only). It reboots its guest between phases (§2.1; `# boots:
4`, `# min-timeout: 10800`):

| Boot | Release | What it does |
|---|---|---|
| 1 | 24.04 | `apt full-upgrade`, bubblewrap and the upgrader (do-release-upgrade refuses pending updates or a pending reboot) |
| 2 | 24.04 | install the packed tarball as alice (nvm Node), then today's `mandu setup` (`RELEASE_UPGRADE_FROM=current`, default) or the old `bwrap` + `unshare` grants byte for byte (`legacy`); doctor `confined` and a confined launch (the stub must not read the canary); then `do-release-upgrade -f DistUpgradeViewNonInteractive` |
| 3 | 26.04.1 | before the user does anything: doctor, a confined launch, the launch's WARNING lines, Ubuntu's own rules; then `mandu setup` and the same checks again, plus nesting inside Mandu's copy, no trampoline, and the agent starting a sandbox of its own |

The upgrade path is recorded in the steps log: `RELEASE_UPGRADE_PATH=auto`
takes the regular LTS path when `do-release-upgrade -c` offers 26.04, else the
development path (`-d`), which offers the same 26.04.1. The upgrade itself
takes 21 to 23 minutes of a ~27-minute run.

**Results.** `current` 38/0: the 24.04 copy (bubblewrap 0.9.0) still loads
and nests on 26.04, so the launch keeps both layers; doctor says the copy is
older than `/usr/bin/bwrap` and names `mandu setup`, which refreshes it.
`legacy` 36/0 and one finding: the real upgrade loaded Ubuntu's `bwrap`
profile, not Mandu's (load order decides), so Ubuntu's no-nesting rule held,
but Mandu's old `unshare` grant stayed loaded, so `unshare -Ur` worked for
every program until `mandu setup`. **Fixed:** `legacyGrantWarning` names each
file's own danger ("the unshare one lets every program on this machine create
a user namespace through unshare"); unit `bwrap-grant.test.ts`, e2e
`bwrap-launch-notes.test.ts`, and the suite asserts the wording. Mandu stayed
`confined`, and the stub never read the canary, at every step of both runs.

**When to run it.** Not in `ubuntu-2404`'s `SUITES` (the tag-blocking
`install` job runs every declared suite): it takes about 30 minutes and a
gigabyte of downloads, and depends on Ubuntu's upgrade metadata. Run
`scripts/matrix/run.sh ubuntu-2404 release-upgrade` (and once with
`RELEASE_UPGRADE_FROM=legacy`) before a release and after a change to
`setup.ts`, `bwrap-grant.ts` or `scripts/apparmor/`, and again with
`RELEASE_UPGRADE_PATH=regular` once Ubuntu opens the regular LTS path.

### 10.16 Reboot, hygiene, Node 18, NodeSource

`fresh-install` runs over **two boots** (`# boots: 2`, §2.1). Boot 1 is steps
0 to 10, then step `12a` and step `R0`, which exits 75; the qemu executor
boots the same disk again and boot 2 runs `R`, `N18`, `NS` and `12b`. The
suite keeps its phase, the install timestamp and a listing of alice's HOME
from just before step 1 in `/var/lib/mandu-matrix/fresh-install/`, and counts
`FAIL` lines in `steps.log` over both boots.

#### 10.16.1 Reboot persistence (steps `R0`, `R`)

`R0` launches the stub once more, so the reboot interrupts a running stack
(the arbiter and dashboard stay up after a launch, as on a user's machine),
and records the boot id and whether alice's systemd user manager answers.
After the reboot, before anything of Mandu's runs, `R` checks:

- a new boot id (the reboot really happened), and no process of alice's;
- Mandu's AppArmor profiles (`mandu_bwrap`, `mandu_child`) are loaded,
  i.e. `apparmor.service` loaded them at boot from `/etc/apparmor.d` alone;
  `/usr/lib/mandu/bin/bwrap` is still the root:755 copy of the system bwrap;
  a sandbox still starts inside it and `unshare` inside it is still refused;
- `mandu doctor` says `confined` with both layers;
- a launch with `--require-confinement` exits 0, its background services come
  up from the bundle again (no autostart fallback line) on a runtime dir the
  reboot emptied, and the stub does not read the canary;
- alice's systemd user manager answers as it did before the reboot, and
  there is no failed `mandu*` user unit;
- `mandu reap --dry-run` as in §10.16.2.

Mandu installs no persistent system service and no persistent user unit: its
services start on demand at a launch (runtime-instances.md), and a launch
runs the agent in a transient `systemd-run --user --scope` unit where a user
manager answers. So the system-level thing that must survive a reboot is
AppArmor loading Mandu's profile, and the services must start clean from an
empty runtime dir. If Mandu ever ships a persistent unit, `R` must also check
it is enabled and active after the boot.

#### 10.16.2 Hygiene (steps `12a`, `12b`)

`12a`, after a launch: alice's remaining processes are listed (the background
services, `mandu-arbiter` and `mandu-dashboard`); every TCP/UDP port they
listen on is loopback; `mandu stop --all` exits 0 and leaves her no process
but her user manager; and nothing she owns and that is newer than the
install lies outside her HOME and her runtime dir (`/run/user/<uid>/mandu`,
from the path table), across `/`, `/tmp`, `/var/tmp`, `/dev/shm` and `/run`.
Mandu's home (`~/.mandu`) is `0700` with nothing in it group- or
world-accessible (on-disk-layout.md §3); `12b` checks that again after the
uninstall.

`12b`, at the end, follows docs/usage.md "Uninstall" as alice: `mandu stop
--all`, `mandu setup --uninstall`, `npm uninstall -g @mandusec/mandu`. Then:
no `mandu` on PATH and no package; no process left for any of the suite's
users; every path added to alice's HOME since the install (minus what the
suite planted) lies inside a directory the path table
(`scripts/paths/mandu-paths.sh`) gives Mandu, so the check follows the layout
as on-disk-layout.md moves it; the outside-HOME check of `12a` again; and
nothing named for Mandu is left under `/etc`, `/usr`, `/opt`, `/srv` or
`/var/lib` (the harness's own `/var/lib/mandu-matrix` and cloud-init's
instance record aside).

**What stays behind after the uninstall**: `~/.mandu`, the one Mandu home
(on-disk-layout.md §3: the placeholder table, the event log, the settings).
The per-session files under `/run/user/<uid>/mandu` go at the next reboot.
usage.md "Uninstall" names both; the suite prints what it found as a `NOTE`.

**A finished launch's scope dir is not accepted.** A launch that ends
cleanly removes its own scope dir (runtime-instances.md §10.1), so
`reap_check` requires `nothing to reap` after the launches, and a
`rm-stale-scope-dir` entry is a FAIL naming the dir, as is anything else reap
would collect (an orphan arbiter, a dead instance record, a dangling
`current`). On a FAIL, `mandu reap` then collects it and a second dry run must
be empty. The one launch meant to fail, the `gated` story's
`--require-confinement` refusal in step 4, keeps its dir (a refusal is not a
clean end; its logs are what the message may name), so step 4 checks that at
most that one dir is left and has `mandu reap` collect it right there (no
current target is `gated`, so that branch runs on the first one that is).

**One thing the suite accepts:** `/tmp/node-compile-cache/` belongs to npm
(its `cli.js` enables Node's compile cache under the OS temp dir); Mandu's
bundles never enable it. `npm uninstall -g` of a system install also leaves
the empty `@mandusec` scope directory; the suite notes empty directories and
fails only on a non-empty leftover.

#### 10.16.3 The Node 18 negative (step `N18`)

User `dave` installs Node 18 with nvm and then the tarball. npm only warns on
`engines` (`EBADENGINE`, and the suite asserts the warning names the floor),
so the install succeeds; the refusal is the first run's. `mandu --version` and
`mandu claude` both exit 2 with one sentence, `mandu: Node 18.20.8 is too old
— Mandu needs Node >= 22.13.0 (node:sqlite is unflagged from 22.13; try: nvm
install 22).`, no stack trace, the stub never runs, and no Mandu directory is
created. Where the distro's own `nodejs` is below the floor (24.04 ships
18.19), the suite also runs alice's installed `mandu` with `/usr/bin/node`:
the same refusal. 26.04's distro Node is 22.22, so that leg is a `NOTE`
there.

#### 10.16.4 The NodeSource variant (step `NS`)

NodeSource's `setup_22.x` and `apt install nodejs` give a system-wide Node
whose npm prefix is `/usr`. User `erin` (passwordless sudo, no nvm): a plain
`npm install -g` is refused (the prefix is root's), `sudo npm install -g` of
the tarball works with no native compilation, the package is root-owned in
`/usr/lib/node_modules/@mandusec/mandu`, and `mandu` resolves to
`/usr/bin/mandu`. Doctor says `confined` and finds alice's setup (setup is per
host): `mandu setup` says nothing to do and the installed profile is
byte-identical to the system install's asset. A confined launch from the
root-owned install exits 0, its services start, and the stub does not read
the canary. `sudo npm uninstall -g` removes it.

#### 10.16.5 Results

Both targets pass every check over both boots (24.04: 138 pass / 0 fail;
26.04: 141 / 0): confined after the reboot with both layers and the profiles
loaded at boot, Node 18 refused in words, the root-owned NodeSource install
confined, only `~/.mandu` left after the uninstall. The first run of the new
steps failed on the scope-dir leftovers, npm's compile cache and the
harness's own 9p mount and cloud-init record, so each new check was seen to
fail once.

**Harness fix: packing in parallel.** Two targets started together pack the
same working tree, and `npm pack`'s `prepack` rebuilds `launcher/dist/`; one
run got a tarball without its bundle. `fresh-install.host.sh` takes an
`flock` on the `launcher/` directory around the pack, and the two targets
pass side by side.

### 10.17 The executor's additions: snapshot layer, `--interactive`, guest registry

#### 10.17.1 The provisioned snapshot layer

`lib/qemu.sh` puts a cached middle qcow2 between the base image and the
per-run overlay: `$MANDU_VM_CACHE/provisioned-<target>-<key>.qcow2`, where
`<key>` is the first 16 hex of a sha256 over the image digest
(`IMAGE_SHA256`, else the cached file's own sha256), the package list and a
`QEMU_LAYER_VERSION`. The package list is `qemu_pkg_list <deps>`, the one list
that also feeds cloud-init's `packages:` and the guest's provisioning gate,
so the key covers exactly what the layer holds.

- **Built by one provisioning boot** of the same guest runner with
  `SUITE=__provision__`: cloud-init installs the packages, the provisioning
  gate (§4) verifies them, then the runner cleans the apt cache, empties
  `/etc/machine-id` (no identity shared by every run) and powers off with
  `RESULT=provisioned`. The boot gets **no share but its own out dir**: no
  repo, no artifacts, so no credential (§10.3.5) can reach the layer. It uses
  a different cloud-init instance-id from the runs, so a run's first boot is
  a new instance and runs its own `write_files`/`runcmd`.
- **Written as `<layer>.part`** and renamed only on `RESULT=provisioned`;
  a lock file serializes two runs of one target that want the same layer.
- **Rebuilt** when the key changes (new image, new package list, new layer
  version) or when it is older than `MANDU_VM_LAYER_MAX_AGE_DAYS` (7).
- **Never fails a run.** If the provisioning boot does not finish, the run
  warns and sits on the base image, provisioning itself as before.
- **"Fresh" still means no mandu state, not a stale apt cache:** the layer
  has no Mandu file, and every run's cloud-init still runs `apt update`.
- `MANDU_VM_SNAPSHOT=0` turns the layer off.

Unit test: `scripts/test/matrix-provision.test.sh` (the key, the rendered
provisioning branch, and the executor on a stub qemu: build then reuse,
expiry, the out-share-only provisioning boot, the fall-back, the off switch).
Measured: building a layer takes about three minutes per target; with the
layers cached, a two-boot `fresh-install` takes about 230 to 310 s against
310 to 440 s before. The suite's own nvm, npm, bubblewrap and NodeSource
downloads are part of what it tests and stay per run.

#### 10.17.2 `run.sh --interactive <target> [<suite>]`

Boots the guest a suite would get (same image and layer, the repo read-only
at `/mnt/reposrc`, and, when a suite is named, that suite's host prep, so
`--interactive ubuntu-2404 fresh-install` has the packed tarball and the stub
agent in `/mnt/artifacts`), but the runner stops before the suite
(`SUITE=__interactive__`) and the guest stays up. The executor generates an
ed25519 key per run (`$RUN_WORK/ssh/`, mode 600), authorizes it for the
image's default user `ubuntu` with password login off, forwards a free
**loopback** port to the guest's port 22, waits for the runner to report
ready, and prints the `ssh -i … -p … ubuntu@127.0.0.1` line. It stays up
until `sudo poweroff` in the guest or Ctrl-C on the host; the overlay goes
with `RUN_WORK` unless `--keep`. To reproduce a clean machine, `sudo umount
/mnt/reposrc` first, as the suite does.

**Credential rule (§10.3.5).** `--keep` or `--interactive` with a live leg
(`FRESH_INSTALL_LIVE=1` or `FRESH_AGENTS_LIVE=1`) exits 2 unless
`--keep-credential` is also given; with it, the run prints where the copy
lived. The host copy in `artifacts/ephemeral/` is still deleted when the
guest stops; a kept overlay may hold the guest's copy.

#### 10.17.3 Leaked guests: the owner registry

A killed test run used to leave its qemu running (up to the run's timeout, or
for good in the interactive lane and `vm-run.sh --shell`), with its overlay
and disks, and nothing enumerated it. Worse than the disk: a leaked guest
inherits the harness's lock fds, so a leaked provisioning boot kept the image
build lock or the layer lock, and every later build of that key or target
waited on it.

Every VM harness registers each guest it starts, like
`scripts/dev-arbiter.sh` registers its arbiter: `scripts/ci/vm-run.sh`,
`scripts/ci/vm-image.sh` (provisioning boot), the matrix executor
`scripts/matrix/lib/qemu.sh` (layer build, each suite boot, `--interactive`)
and `scripts/kernel-vm.sh`. The shared helper is
`scripts/lib/guest-registry.sh`:

- qemu runs with `-pidfile`, in the background (a foreground child would
  also keep the harness from acting on a SIGTERM until the guest ended);
  `guest_register` waits for the pidfile (at most 60 s, while the launcher
  lives; no pidfile means no registration and a warning, never a failed
  run) and writes `<runtime dir>/vm-guests/<harness>-<pid>.json` (0600,
  tmp + rename) beside the arbiter `instances/` and the `dashboards/`
  entries;
- the entry holds the guest's pid and **start time** (`/proc/<pid>/stat`
  field 22) and the boot id, so a reused pid never matches; the **owner**
  is the harness process (`$$`) with its start time, so a reused owner pid
  does not keep a leaked guest alive; the run's scratch dir (`workDir`,
  kept when the run had `--keep`); and `alsoRemove`, paths removed even
  under `--keep` (the matrix's `artifacts/ephemeral/` credential copy, the
  layer build's `.part`, the vm-run Ollama bridge's socket dir);
- `guest_release` runs after each boot and from the harness's EXIT trap: a
  guest still up (the harness was signalled) is stopped, SIGTERM then
  SIGKILL after 10 s, only if pid and start time still match, and the entry
  goes. So a SIGTERM or Ctrl-C stops the guest with its harness instead of
  leaving it to its timeout.

`mandu reap` (launcher/src/reap.ts, runtime-instances.md §10) plans every
entry by these rules:

| owner (pid + start time) | guest (pid + start time + boot id; qemu cmdline) | reap does |
| --- | --- | --- |
| alive, or not provable | anything | nothing |
| gone | same process, argv[0] is `qemu-system-*` / `qemu-kvm` | `kill-orphan-guest`: SIGTERM, SIGKILL after 5 s (identity re-checked before each signal), then remove the scratch paths and the entry |
| gone | gone, or its pid now another process, or an earlier boot's | `rm-dead-guest`: scratch paths and entry, no signal |
| gone | same start time but not qemu, or start time unreadable | nothing (ambiguous) |
| none recorded | alive | nothing (nobody's garbage) |

An unreadable entry is removed alone. A scratch path is removed only when
it is absolute, normalized, at least two levels deep and neither the runtime
dir, the home dir nor an ancestor of either; others are refused and named in
the plan. A process the registry does not name is never looked at, however
much it looks like qemu. `--dry-run` prints the plan
(`would kill-orphan-guest: vm-run vm-run-<pid>: owner <pid> is gone; stop
qemu pid <pid>; remove <work dir>`), and `mandu status` counts a live leaked
guest as "1 test VM from ended runs".

Tests: `launcher/test/unit/reap-guests.test.ts` (the decision table, the
SIGKILL escalation, a pid reused between plan and execute, the path
refusals), `launcher/test/component/reap-qemu-guests.test.ts` (a stand-in
harness sources the real helper and starts a long-running process named
`qemu-system-x86_64`; it is SIGKILLed; the real `mandu reap` leaves the guest
alone while the owner lives, lists it under `--dry-run`, then stops it and
removes its dir; `--keep`; an unregistered qemu-named process and a reused
pid are never signalled), `scripts/test/guest-registry.test.sh` (the entry,
`guest_release`), and the stub-qemu harness tests (`ci-vm-run.test.sh`,
`matrix-provision.test.sh`) assert each boot was registered while it ran and
left the registry after.
