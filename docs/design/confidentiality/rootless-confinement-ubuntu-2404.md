# Rootless install on Ubuntu 24.04: root stays optional

Status: **BUILT.** A stock Ubuntu 24.04 and every later release (25.04 to
26.04) launch `confined` with no sudo at all: the npm bundle ships the
whole-agent guard, and the guard alone serves the credential placeholders by
descriptor (plan 10 §11.7, §11; §12 for 25.04 and later). `mandu setup` is
the optional second layer (the bind mount, through Mandu's own copy of
bubblewrap), never a prerequisite. A launch without the guard is `gated`, a
named, weaker posture that degrades with a loud notice instead of refusing
(§2, §13). The bubblewrap is the distribution's, never one inside the
working directory (decided 2026-10-09, §0.7). **Start with §0**, the current answer to every question; §1 to
§13 are the reasoning behind each answer. Companions:
[`protection-modes.md`](../architecture/protection-modes.md) (whose default
depends on this) and [`secret-discovery.md`](./secret-discovery.md) §1 (the
secret walk on a real home). Background: `privilege-model.md` "Host
prerequisite: Ubuntu's AppArmor userns restriction (24.04)",
`confidentiality.md` §7.2, §10.1 and §11, `scripts/apparmor/README.md`.

## 0. Where it stands

This section collects the current answers. Where it and a later section
disagree, the later section is history and this one is the current state.

### 0.1 Two layers: the guard and the bind

Mandu keeps secret files away from the agent with two independent
mechanisms. Both serve the same **twin** (the symbolized copy of a secret
file):

- **The guard** (`mandu-net-guard`, whole-agent seccomp user-notification).
  It traps the `open` family and hands the agent the twin's descriptor
  instead of the secret's. It needs only `no_new_privs`, with no user
  namespace and no root, so Ubuntu's restriction does not apply to it. The npm
  bundle ships it (§11). It is the layer that holds the claim.
- **The bind** (the secret twin wrap, a bwrap mount namespace that mounts
  each twin over its secret). It needs a bwrap that may create a user
  namespace and, so that the agent's tools still work, one that lets a
  sandbox start inside it. It is a second implementation of the same twin, a
  defense in depth against a bug in the guard (§12.2). It is not the fallback
  if the guard dies: a dead guard fails closed on its own (`ENOSYS`).

| Guard | Bind | Posture | Why |
|---|---|---|---|
| on | on | `confined` | both layers |
| on | off | `confined` (by the guard alone) | the default on every stock Ubuntu (§11, §12) |
| off | on | `gated` (gap `no-guard` or `guard-off`) | a secret file the host replaces during a session detaches the bind, and only the guard's by-path lookup catches that (§13, finding 7) |
| off | off | `gated` | model-context masking and egress gates only; a subprocess can read the raw file |

`--require-confinement` turns `gated` into a refusal (§3.1).

Only the guard reaches what the launch did not prepare. The bind covers the
paths the launcher knew at launch; the guard sees every open, so it is also
the backstop for a locked git object in a repository the launch prepared no
sanitized copy of (another checkout, a clone, a fork): it refuses that
repository's pack, index or loose copy (confidentiality-plan-14 §11.1 R4,
confidentiality.md §7.2a "The guard's backstop"). The same rule holds with
the bind up or not; a launch without a guard (`gated`) has no backstop.

### 0.2 Ubuntu 24.04 and 26.04

The bind needs two things from the host: bwrap may create a user namespace,
and a bwrap may start inside a bwrap (Codex's shell sandbox and Mandu's exec
box are both a bwrap started inside the agent's wrap). Each release fails a
different one:

| Host | User namespace for bwrap | Nesting | Stock posture (no sudo) | After `mandu setup` |
|---|---|---|---|---|
| **24.04** | refused: `apparmor_restrict_unprivileged_userns=1` and no profile grants `/usr/bin/bwrap` (Ubuntu's own `bwrap-userns-restrict` ships disabled, in `extra-profiles`) | n/a, no bind at all | `confined` by the guard alone (bind gap `apparmor-userns`) | `confined`, both layers; sandboxes nest |
| **24.04 with Ubuntu's extra profile enabled** | allowed | refused | `confined` by the guard alone (bind gap `bwrap-nesting`) | `confined`, both layers |
| **25.04, 25.10, 26.04** | allowed: `bwrap-userns-restrict` is enabled and grants `/usr/bin/bwrap` its namespace | refused: that profile stacks `unpriv_bwrap`, which denies every capability, on everything a bwrap sandbox runs | `confined` by the guard alone (bind gap `bwrap-nesting`) | `confined`, both layers |
| **24.04 upgraded to 26.04** | as 26.04 | as 26.04 | as 26.04 | the 24.04 copy keeps working; each launch warns it is older than the system bwrap until `mandu setup` refreshes it (§12.3) |

"Nesting refused" is found by running it, not by reading the release: before
it binds, every launch that has secrets to bind runs the twin wrap around a
nested `bwrap --unshare-user --unshare-pid --unshare-net` (§12.1), and
leaves the bind off where that fails. With the guard missing as well, the
bind stays on, since keeping raw bytes out comes first, and a WARNING names
what will fail.

Setting `apparmor_restrict_unprivileged_userns=0` is not enough on 25.04 and
later: `bwrap-userns-restrict` is attached to `/usr/bin/bwrap` whatever the
sysctl says. The CI guests set the sysctl to 0 and also disable that profile
(`continuous-integration.md` §3, §4.1). That is a test-bed choice, never advice
to a user.

Verified in VMs: 24.04 (apparmor 4.0.1, bubblewrap 0.9.0, kernel 6.8), 25.10
(apparmor 5.0.0~alpha1, bubblewrap 0.11.0, kernel 6.17), 26.04 (apparmor
5.0.2, bubblewrap 0.11.1, kernel 7.0), and a real `do-release-upgrade` from
24.04 to 26.04 starting from both today's install and the grants Mandu
installed before 2026-09-27 (`os-test-matrix.md §10` §14, §15).

### 0.3 Root

- **At runtime: never.** No launch, no daemon, no dashboard action asks for
  root.
- **Once, optionally, at the user's choice: `mandu setup`.** The command
  runs as the user. It probes, explains, prints the exact profile text and
  the exact commands, asks, and then runs only these under `sudo`:

  ```
  install -d -m 0755 -o root -g root /usr/lib/mandu /usr/lib/mandu/bin
  install -m 0755 -o root -g root /usr/bin/bwrap /usr/lib/mandu/bin/bwrap
  install -m 0644 -o root -g root <bundle>/apparmor/mandu-bwrap /etc/apparmor.d/mandu-bwrap
  apparmor_parser -r /etc/apparmor.d/mandu-bwrap
  ```

  It also removes the Mandu-marked grants of before 2026-09-27 (§12.3).
  `--print` shows everything and runs nothing, `--yes` skips the prompt,
  `--uninstall` removes what Mandu installed. The fix line is `mandu setup`,
  never `sudo mandu setup`: root's PATH commonly lacks an npm-global or nvm
  `mandu` (§3.2).
- **Again only when bubblewrap is updated**, to refresh the copy (§0.4).
  Every launch says so.
- **Never:** the host-global sysctl as the suggested fix (mentioned once
  under `--print`, with why it is not preferred), editing or overriding
  Ubuntu's `bwrap-userns-restrict` or `local/unpriv_bwrap`, or a profile
  named or attached like a distro one.

This is inside the non-root principle (`privilege-model.md` §0): a one-time
host change the administrator chooses, which widens nothing for any other
program, and on which no runtime path depends. Without it the host is still
`confined`.

### 0.4 The bwrap binary: a copy of the system one

`mandu setup` copies the system `/usr/bin/bwrap` (or an administrator's
`bwrap_path`, §0.7) to `/usr/lib/mandu/bin/bwrap`. Mandu does not build,
vendor, download or patch bubblewrap, and does not ship a bwrap in the npm
bundle: it uses the distribution's (decision A, §0.7).

- **Why a copy.** AppArmor attaches a profile by executable path. A separate
  path lets Mandu's profile apply to Mandu's sandbox only, leaving
  `/usr/bin/bwrap` and Ubuntu's profile for it untouched.
- **When the launch uses it.** Only when it is in force: a regular file,
  root-owned, in root-owned directories, not writable by anyone else, and
  able to create a user namespace (so its profile is loaded)
  (`bwrap-grant.ts` `manduBwrapInForce`). An AppArmor grant on a path someone
  else could write would hand its rights to their binary. No environment
  variable can move the path. Otherwise the launch uses the distribution's
  (`bwrap-path.ts`, §0.7: an administrator's `bwrap_path`, else the first
  `bwrap` on PATH outside the current directory, run by its absolute path),
  or none.
- **Where it is used.** The twin wrap runs it, the nesting probe uses it as
  the outer bwrap, and its directory goes first on the agent's PATH (after
  the shim directories), so Codex's sandbox and Mandu's exec box run it too.
- **Staleness.** The copy does not follow bubblewrap updates. Every launch
  compares its bytes with `/usr/bin/bwrap` (or the administrator's
  `bwrap_path`, what `mandu setup` copies) and, when they differ, prints one
  WARNING naming both versions and `mandu setup` (equal version strings
  still warn: an Ubuntu security update often keeps the upstream version).
  `mandu doctor` says the same.
- **It inherits the system bwrap's bugs.** bubblewrap before 0.12.0 follows
  symlinks in mount destinations (CVE-2026-87766), and whether a given distro
  build is fixed cannot be read from its version alone (§13). The copy is
  exactly as vulnerable as the binary it was copied from. `mandu doctor` asks
  the bwrap the wrap would use and flags it with its version, and a launch
  whose bind is on warns; when that bwrap is the copy, the fix line adds
  `mandu setup` (upgrading the package does not refresh the copy). The
  exposure is limited to the bind: the guard still serves twins by path.
  Where the copy comes from while the distro's bwrap is vulnerable is
  decided: the distribution's, as Claude Code and Codex do (§0.7).
- **Outside Mandu.** A bare `codex` on 24.04 does not get the copy. Codex's
  own docs tell the user to enable Ubuntu's extra profile; 26.04 ships it.

### 0.5 The AppArmor policy

`scripts/apparmor/mandu-bwrap` (shipped in the npm bundle, installed as
`/etc/apparmor.d/mandu-bwrap`) defines two profiles, both named for Mandu and
attached to Mandu's path only:

- `mandu_bwrap`, attached to `/usr/lib/mandu/bin/bwrap`: `userns`,
  capabilities, `mount`, `umount`, `pivot_root`, file and network access. A
  bwrap it runs (the copy or `/usr/bin/bwrap`) stays `mandu_bwrap` (`ix`).
  Everything else it runs goes to `&mandu_bwrap//&mandu_child` (stacked).
- `mandu_child`: file and network access, no `userns`, `deny capability`.
  A bwrap it runs goes back to `mandu_bwrap` (`Px`), and everything else stays
  `mandu_child`.

What that gives, VM-verified (the §12.3 matrix): inside the wrap only
bubblewrap holds capabilities, so a sandbox nests (three levels deep, Codex's
sandbox included), while `unshare -Ur` is refused and the nested sandbox's
payload has no effective capabilities. Running the copy by hand gives nobody
a namespace with capabilities, so it is no trampoline around Ubuntu's
restriction. A program with its own host profile keeps it:
`<its profile>//mandu_bwrap//mandu_child`.

Why this shape and not a simpler one:
- **Stacking, not a `Cx` child profile.** bwrap always sets
  `PR_SET_NO_NEW_PRIVS`, and under it AppArmor refuses an exec transition
  whose new label drops the label in force when no_new_privs was set. So
  every transition keeps `mandu_bwrap` in the label. Ubuntu's own profile
  (`&bwrap//&unpriv_bwrap`) does the same for the same reason.
- **Not `flags=(unconfined) { userns, }` on the copy** (the Podman,
  rootlesskit and Flatpak shape, §12.5 option 3). It would give the whole
  agent tree `userns` and capabilities, and anyone could use the copy as a
  trampoline.
- **Not a profile on `/usr/bin/bwrap`.** That is what Mandu shipped until
  2026-09-27: a host-wide trampoline, whose profile NAME `bwrap` collides
  with Ubuntu's; whichever file loads last wins, which after an upgrade to
  26.04 could switch Ubuntu's restriction off for every program (§12.3).
- **Not a local override of `unpriv_bwrap`.** A `deny` beats every `allow`,
  and any edit of the distro profile loosens the whole host.
- The capability deny is quiet (`deny`, not `audit deny`): Node probes
  CAP_SYS_ADMIN at startup, which filled the audit log otherwise.

The alternatives and why each was rejected: §12.4 (what Flatpak, Codex,
Claude Code, Cursor, nono, Kiro and glycin do) and §12.5 (the six options).
A sibling-sandbox broker (option 4) stays the long-term route if AppArmor
proves too fragile, or if a non-Ubuntu host forbids nesting.

### 0.6 Where each answer is enforced and tested

| What | Code | Tests |
|---|---|---|
| posture resolution, gaps, notice text | `launcher/src/confinement-posture.ts` | `test/unit/confinement-posture.test.ts` |
| nesting probe, guard-only fallback | `launcher/src/secret-twins.ts` `nestedSandboxProbeArgv`, `secret-setup.ts` | `test/unit/secret-setup.test.ts`, `test/kernel/secret-bind-nesting.test.ts` |
| the copy: in force, stale, launch notes | `launcher/src/bwrap-grant.ts` | `test/unit/bwrap-grant.test.ts`, `test/kernel/bwrap-launch-notes.test.ts` |
| `mandu setup` planning and commands | `launcher/src/setup.ts` | `test/unit/setup.test.ts` (the sudo step itself only in VMs) |
| doctor rows | `launcher/src/doctor.ts` | `test/unit/doctor.test.ts` |
| which bwrap: the distribution's, never one inside the working directory; an administrator's `bwrap_path` (§0.7) | `launcher/src/bwrap-path.ts` (four copies), `interceptors/exec-supervisor/src/sandbox.rs` `find_bwrap_in`, `arbiter/policy/admin-layer.ts` (the key's form) | `test/unit/bwrap-path.test.ts`, `test/component/bwrap-path-launch.test.ts` (the real CLI in a workspace with planted bwraps: doctor and a strict launch), the `sandbox.rs` unit tests, `interceptors/exec-supervisor/tests/kernel_integration.rs` `exec_box_bin_runs_only_the_resolved_system_bwrap` (the command box end to end, `rust.kernel`), `arbiter/test/unit/admin-layer.test.ts`, `tests/stack/hardened-git-parity.test.ts` (the copies equal) |
| CVE-2026-87766 probe (behavior, then version) | `launcher/src/bwrap-symlink-probe.ts` | `test/unit/bwrap-symlink-probe.test.ts`, `test/component/bwrap-cve-version.test.ts` (a fake `bwrap` on PATH, old and new versions, through `mandu doctor`), `tests/sandbox/bind-only-posture.test.ts` (the host's real one) |
| a dead guard fails closed | `launcher/src/guard-death.ts` | `test/guard-death-live.test.sh`, `test/kernel/guard-death.test.ts` |
| the tree cannot freeze, throttle or move the guard through its cgroup (§12.2 "The cgroup") | `interceptors/net-supervisor/src/cgroup_guard.rs`, `cgroup_guard_kernel.rs` | its unit tests; `net-supervisor/tests/guard_integration.rs` `a_write_open_that_could_freeze_or_move_the_guard_is_refused` (opens only; runs in CI's `rust.kernel` in the cgroup the guest delegates to `ci`; self-SKIPs without a user-owned cgroup) |
| the gated posture is honest | | `launcher-gated-posture.test.ts`, `tests/sandbox/bind-only-posture.test.ts` |
| each release, fresh and upgraded | | the `fresh-install`, `fresh-agents` and `release-upgrade` VM suites on `ubuntu-2404`, `ubuntu-2510`, `ubuntu-2604` (`os-test-matrix.md §10` §14, §15) |

### 0.7 Where Mandu's bubblewrap comes from: the distribution's (decided 2026-10-09)

**Decision A (the maintainer, 2026-10-09): Mandu uses the distribution's
bubblewrap**, as Claude Code and Codex do. It bundles none and downloads
none. `mandu setup` copies the distribution's (§0.4), and without
`mandu setup` the launch runs the distribution's itself. The options of
2026-10-07, for the record:

| Option | What it is | For | Against |
|---|---|---|---|
| **A. The distro's (chosen)** | `mandu setup` copies `/usr/bin/bwrap`; no setup: the distribution's bwrap | The distro owns bubblewrap's security updates and backports; built against the distro's libraries; no compiler, no new artifact, nothing new to sign or license; Codex's lesson (PR #14963: a bwrap outside the distro's path fell outside the distro's path-scoped AppArmor profile) does not apply | Affected until the distro ships a fix (26.04 has none yet; 24.04 regressed); Mandu can only warn; the copy goes stale after every update until `mandu setup` is rerun (warned on each launch) |
| B. Vendored static build in the release tarball | CI builds bubblewrap 0.12.0+ statically per architecture and ships it in the npm bundle | The fix on every host now | Mandu owns bubblewrap's security updates for good (the failure mode: Codex still vendors 0.11.2, which has this CVE); a C toolchain and an attested build in the release pipeline; an LGPL binary in an Apache-2.0 bundle; without `mandu setup` it helps only hosts that do not restrict userns |
| C. `mandu setup` fetches it | builds or downloads a pinned 0.12.0+ where the probe says the system's is affected | Only affected hosts pay | The network at setup time; a compiler on the user's machine, or B's ownership plus a download path to secure; a third path for the OS matrix |

**What the two agents do (researched 2026-10-09).**

| | Claude Code 2.1.294 (sandbox-runtime) | Codex 0.160 to 0.162 (`codex-rs/sandboxing/src/bwrap.rs`, `linux-sandbox/src/bundled_bwrap.rs`) |
|---|---|---|
| Which bwrap | the distribution's only; bundles and downloads none; docs and errors say `apt install bubblewrap socat` | the first `bwrap` on PATH, skipping PATH entries inside the cwd, and only if its `--help` lists `--as-pid-1` and `--perms` (about 0.5.0 and later); else its own bundled static 0.11.2, built from vendored source and hash-checked at run time (`CODEX_BWRAP_SHA256`, run through `/proc/self/fd/N`) |
| Override | `sandbox.bwrapPath`, honoured only from managed (administrator) settings | none |
| Version or CVE check | none | none; the bundled 0.11.2 is itself under CVE-2026-87766 |
| No usable bwrap | warns and runs unsandboxed by default; `failIfUnavailable: true` refuses, and the Agent SDK turns that on by default | a functional userns probe (`bwrap --unshare-user --unshare-net --ro-bind / / true`); with no usable bwrap it refuses and never runs unsandboxed |
| Ubuntu 24.04+ AppArmor | in the docs only: root writes a profile for `/usr/bin/bwrap` | the bundled copy is refused there (only `/usr/bin/bwrap` is admitted) |

So A, with the follow-ups below (all built 2026-10-09).

**Follow-up 1: a missing bwrap, or one that cannot make a user namespace.**
Mandu decides this by a functional probe, like Codex's, never by presence:
`userns.ts` runs `bwrap --unshare-user --unshare-pid --ro-bind / / -- true`
through the bwrap the launch would run, and the nesting probe (§12.1) and
the git sandbox's probe run theirs. What each site does when the probe
fails was already decided, and stays:

| Site | No usable bwrap | Why this, and where it is decided |
|---|---|---|
| Secret twins (the bind, `secret-setup.ts`) | with the guard: `confined` by the guard alone, the bind off (gap named in doctor); without the guard: `gated` with the loud notice; `--require-confinement` refuses | §2 and §3.1 (degrade by default, refusal is the opt-in), §11 (the guard alone confines). A refusal here would stop every stock 24.04 launch, where the guard alone keeps every secret out. The notice and doctor now name `sudo apt install bubblewrap`, `sudo dnf install bubblewrap` and, on Ubuntu 24.04 and later, `mandu setup` for the AppArmor grant |
| Command box (`exec-box-setup.ts`, `mandu-exec-box`) | warns and runs the listed commands unboxed (an administrator's `bwrap_path` that cannot be used counts as none) | exec-routing.md §7: a utility-class layer on top of the whole-agent confinement; a box that cannot start would only fail every command. The box itself refuses (exit 126, with the message, the command not run) when it finds no bwrap outside the command's cwd, the workspace and the AgentView, never a PATH search; proven end to end through the bin (Follow-up 2) |
| Git sandbox (`hardened-git.ts`) | the hardened git runs unsandboxed; doctor shows a ✗ | write-protection.md §8: defense in depth over the hardening, probe-gated under the non-root principle |
| Prompt-filter plugins (`plugin-confine.ts`) | the namespace leg is off; the guard and Landlock legs stay | confidentiality-plan-15 §4.3, probe-gated |
| Codex's own sandbox (`codex-sandbox.ts`) | a doctor row and a launch WARNING | Codex refuses its commands itself; Mandu cannot run them in another sandbox |
| macOS | not bubblewrap: Seatbelt (`read-blocked`) | §2 |

No site runs the agent with less confinement silently: each degrade is a
named posture or a WARNING line, and none leaves a secret readable while the
guard runs. So no new refusal was added. The one new refusal is where the
bind is about to go up and its bwrap is gone since the host check (a race):
the launch refuses rather than run a bare `bwrap`.

**Follow-up 2: never a `bwrap` from the workspace.** `bwrap-path.ts`
(four byte-identical copies: launcher, arbiter, dashboard, fs-sync; held
equal by `tests/stack/hardened-git-parity.test.ts`) resolves the
distribution's bwrap as Codex does: the first `bwrap` on PATH, skipping
empty and relative entries (both mean the current directory) and every
entry, and every candidate's real path, inside the current directory; the
answer is the real path, and every caller runs that absolute path, never a
bare `bwrap` (whose PATH search would find `./bwrap`, a repository's `bin/`
put on PATH by direnv, or `node_modules/.bin` put there by an npm script).
None found is "no bwrap". It serves the twin wrap, the userns, nesting,
Codex and CVE probes, doctor, `mandu setup`'s probes, and the git sandbox.
The command box resolves its own the same way in Rust
(`exec-supervisor` `sandbox::find_bwrap_in`, excluding the command's cwd,
the workspace, the AgentView worktree and its own cwd) and refuses with 126
when there is none. The AgentView exclusion came from the end-to-end test
below (2026-10-09): with a view pair, a `bwrap` in the AgentView's `bin/` on
PATH, from a cwd outside both trees, ran as the user on the host and the
boxed command never ran. The view pair exists only with the integrity axis
on (frozen), but the agent writes the AgentView in any mode that has one.
That test, `interceptors/exec-supervisor/tests/kernel_integration.rs`
`exec_box_bin_runs_only_the_resolved_system_bwrap` (`rust.kernel`, probe-gated:
it SKIPs where no bwrap outside the test tree can start a box), drives the
production `mandu-exec-box` bin with only a shim's environment: the command
runs inside the first bwrap on PATH outside the excluded trees, exec'd by its
absolute real path (a stand-in records the path it was run by), and inside
the box (a write outside the workspace fails); bwraps planted at `.`, at a
relative entry that points outside the workspace, in the workspace's `bin/`,
behind a link from outside into it, and in the AgentView never run (each
would write a marker); with only planted ones on PATH the bin exits 126 with
the message and runs nothing, with the clean box first or not; and a
directory ahead of the system one on PATH (how the launch hands the box an
administrator's `bwrap_path`, Follow-up 4) is the one it runs.
Before this, every one of these ran a bare `bwrap` (a PATH search), and the
nesting probe also ran a bare inner `bwrap` inside the wrap: a launch in a
workspace with `.` or a workspace directory on PATH ran the workspace's
`bwrap` as the user, outside any sandbox. The prompt-filter plugins already
used `/usr/bin/bwrap` or `/bin/bwrap` by path. Tests:
`launcher/test/unit/bwrap-path.test.ts`, the Rust unit tests in
`sandbox.rs`, and `launcher/test/component/bwrap-path-launch.test.ts` (the
real CLI in a workspace that plants a bwrap that would pass every probe:
neither `mandu doctor` nor a launch runs it, and the launch probes the one
outside, which here cannot make a namespace, so `--require-confinement`
refuses).

**Follow-up 3: the version is not proof.** The `version-affected` line
(§13) no longer says "a distro build may carry the fix". It says the build
reports a version older than 0.12.0 and could not be tested, that a version
number settles nothing either way (Ubuntu shipped the fix in
`0.9.0-1ubuntu0.2` and in 26.04's `0.11.1-1ubuntu0.2`, and dropped it again
in the `ubuntu0.3` update of each, the latter three days later), and what to
check instead: the installed build's changelog naming CVE-2026-87766 (`apt
changelog bubblewrap`, `rpm -q --changelog bubblewrap`), or `mandu doctor`
where bubblewrap can make a namespace, which tests the build itself. Every
CVE fix line now ends with "then run mandu doctor, which tests the build
itself".

**Follow-up 4: an administrator's `bwrap_path`, like Claude Code's
`sandbox.bwrapPath`.** Mandu has an administrator's layer that the user
cannot write: `/etc/mandu/policy.d/*.yaml` (model-endpoints.md §2 D5,
`arbiter/policy/admin-layer.ts`). A top-level `bwrap_path: /abs/path`
there names the bubblewrap Mandu runs in place of the one on PATH:
`bwrap-path.ts` reads it by line (the last file in name order that sets it
wins), and honours it only when the file and every directory above it, and
the binary and every directory above it (by real path), are root-owned and
writable by neither group nor others. A file someone else could write is
ignored (the PATH answer stands, as with no administrator). Set but unusable
(missing, not root's alone, not one plain absolute path on its line) means
no bubblewrap at all, never the PATH one in its place: every launch prints
a WARNING with the reason, doctor a ✗, and `mandu setup` stops with the same
reason and fix instead of "bubblewrap is not installed" (one wording,
`bwrap-grant.ts` `adminBwrapRefusedReason` and `ADMIN_BWRAP_FIX`, tested
word for word against doctor's row in `test/unit/setup.test.ts`); the
launch's `bwrap` presence check fails, so the command box stays off. With it
in force: the launch, the
probes, the git sandbox and the prompt-filter plugins run it; its directory
goes first on the agent's PATH (`bwrap-grant.ts` `agentBwrapDir`), so
Codex's sandbox and the command box find it (point it at a directory that
holds bwrap alone): the box reads no administrator's file itself, it takes
the first bwrap on PATH outside the workspace, which is that one; `mandu setup` copies it
instead of `/usr/bin/bwrap`, and the stale-copy check compares the copy with
it. Mandu's own copy, where `mandu setup` installed it, still comes first:
the copy is what Ubuntu's AppArmor admits. The arbiter accepts the key and
checks its form with the same line reader, so a value the two would read
differently stops the arbiter instead of being ignored. No environment
variable or user config can name a bwrap.

**Hosts other than Ubuntu.** The profile is Ubuntu's AppArmor. Other
distributions either do not restrict unprivileged user namespaces (the bind
works with the system bwrap, and `mandu setup` says there is nothing to do)
or are untested.

## 1. The problem in plain terms

Mandu hides secret files from the agent by serving a symbolized **twin** in
place of each one (`confidentiality.md` §7.2). The first implementation was
only the bind: a bwrap mount namespace inside the agent's world. Creating a
mount namespace without root requires an **unprivileged user namespace**.

Ubuntu 23.10 and later, including 24.04, ship
`kernel.apparmor_restrict_unprivileged_userns = 1`. Under that setting an
unprivileged process may create a user namespace only if the binary it
executes carries an AppArmor profile granting `userns`. Stock `/usr/bin/bwrap`
and `/usr/bin/unshare` carry none on 24.04, so:

```
bwrap: setting up uid map: Permission denied
```

With confidentiality ON the launch refused (fail-closed), the exec box
degraded, and `scripts/kernel-tests.sh` self-SKIPped. Granting `userns` needs
root, by design: if an unprivileged user could grant it to themselves, the
restriction would mean nothing. Other products take root once at install time
(the userns-granting profiles of Chrome, VS Code, Firefox, Slack, 1Password,
Flatpak, Podman, runc and LXC each arrive in their own `.deb`); tools that
install with no root at all (npm globals, rustup, nvm, Claude Code itself)
manage it only because they never create a namespace. Mandu's answer was
first a degraded posture (§2, §3), then a twin that needs no namespace at all
(§10, §11).

## 2. The decision

**Mandu installs and runs with no root. The one-time privileged step is an
optional upgrade, never a prerequisite.** On a host where confinement cannot
be established, the launch proceeds in a clearly named, weaker posture with
a loud, specific notice, and offers the command that upgrades it.

This answers gate (2) of `confidentiality.md` §11 ("a decided answer for the
no-userns host: refuse, or degrade-with-a-loud-warning by default"): **degrade
with a loud warning is the default; refusal is the opt-in.** It is
consistent with the non-root principle (`privilege-model.md` §0,
[`CONTRIBUTING.md`](../../../CONTRIBUTING.md)): the privileged step changes host
state once at the administrator's choice, and nothing at runtime depends on
root.

### Posture names (one vocabulary for CLI, doctor, dashboard, docs)

The single source is `launcher/src/confinement-posture.ts` (the names and one
honest sentence each).

| Posture | When | What holds |
| --- | --- | --- |
| **confined** | **the whole-agent guard is around the launch** (the npm bundle ships it; REQUIRED since 2026-09-28, §13), with the bwrap bind as a second layer where bwrap + an unprivileged userns work (`HostPosture.bindGap` names why the bind is unavailable or, `bwrap-nesting`, why it is left off: §12) | Raw secret bytes are absent from the agent's world. `cat ~/.aws/credentials` yields a symbol; `cat secret \| curl …` carries a token. The full `confidentiality.md` §10 claim. With the guard alone the twin is served by descriptor at `open()`; with the bind it is also mounted. |
| **read-blocked** | no Linux backend (§10); the name is kept because macOS Seatbelt is exactly that | Secret files are unreadable to the agent tree. Reads fail instead of returning a symbol. |
| **gated** | no guard: neither layer, **or bind only** (gap `no-guard`, or `guard-off` when the user turned the guard off; §13) | Track A only (`confidentiality.md` §10.1): model-context masking of labelled reads through the agent's tools, egress gates on symbols, net-proxy / net-guard / exec-wrap as configured. A subprocess CAN read raw secret files, so `cat secret \| curl` is **not** stopped by construction. |

The `gated` posture must never be described with the `confined` claim. The
launch banner, `mandu doctor`, the dashboard protection chip and the
session-health record all carry the posture name and one honest sentence.
Under the bind-only `gated` (§13) the bind still goes up as a partial layer:
the notice, doctor and the dashboard reason say what it covers (a placeholder
over each credential file found at launch) and what it misses (a file the
host replaces while the agent runs).

## 3. What was built

### 3.1 Default degrade, explicit strictness

`secret-setup.ts` routes every confinement failure through
`onConfinementFailure`:

- **What degrades by default**: host-capability gaps only (no `bwrap`, no
  unprivileged userns, an unsupported platform, no guard). An ARBITER failure
  during discovery or registration is an incident, not a host condition: it
  still refuses unless `--best-effort` (on an already gated host it only
  warns, since no confinement is left to lose).
- **`--require-confinement`** (env `MANDU_REQUIRE_CONFINEMENT`, config
  `require-confinement = true`) refuses in every case and wins over
  `--best-effort`. The docs recommend it outright for managed deployments.
- **The notice** prints on every gated launch as an attention line (so the
  compact banner shows it too); the compact summary says `secrets GATED (not
  confined)`. No acknowledgement, state file or prompt: the dashboard chip is
  amber. A missing `bwrap` gets its own fix line (`sudo apt install
  bubblewrap`), since `mandu setup` cannot fix it; its cause line adds
  `sudo dnf install bubblewrap` and, for Ubuntu 24.04 and later, `mandu
  setup` after installing it (the AppArmor grant). "Missing" means no
  `bwrap` on PATH outside the working directory (§0.7).
- `SecretSetupResult` carries `posture` + `gap`, which `run.ts` puts on the
  `launch_posture` event as `secrets`. A `gated` launch still asks the
  arbiter to pre-register the catalog secrets (labels stay authoritative for
  Track A masking).

**Security review note.** This changed a fail-closed default to a degrade.
The model-context invariant (no un-symbolized secret in a model context it is
not cleared for, through the agent's tools) still holds in `gated`; what
weakens is the claim that no subprocess reads the raw file, and only with a
visible posture (`confidentiality.md` §10.1). `--require-confinement` is
covered by an e2e so the strict path cannot rot:
`launcher-gated-posture.test.ts` reproduces a 24.04 host
with a failing `bwrap` stub on PATH and checks G1 the default launch proceeds
gated with notice and event, G2 the raw read really succeeds (the honesty
oracle), G3 `--require-confinement` refuses (flag, flag + `--best-effort`,
env), G4 a tool-mediated Read of the labelled secret reaches the model only
as a symbol while gated.

### 3.2 `mandu setup`: the one-command upgrade

`launcher/bundle-manifest.json` ships the AppArmor files as `assets`, copied
verbatim to `dist/apparmor/` and resolved by `Layout.asset()`, so an
npm-installed user has them (a checkout-only script path is never offered).
`launcher/src/setup.ts` plans by probing, explains what it will install and
why, prints the exact profile text and commands, confirms, runs only those
commands under `sudo`, and re-probes. `--print` emits the profile and the
manual commands for administrators who deploy by configuration management;
`--uninstall` removes what Mandu installed (ownership marker: the `# Mandu:`
first line). It is idempotent and does nothing, saying so, on hosts that do
not need it. The fix command is `mandu setup`, not `sudo mandu setup`: the
command runs unprivileged and asks for sudo for the one install step, while
`sudo mandu` commonly fails because root's PATH lacks an npm-global `mandu`.
It never suggests the host-global sysctl as the fix (mentioned once in
`--print`, with why not). What it installs is Mandu's own bubblewrap copy and
profile (§0.3, §12.3). The acceptance check on a fresh 24.04 guest is
automated (`os-test-matrix.md` §7b).

### 3.3 `mandu doctor` reports it before launch

`mandu doctor` has a "Secrets" section driven by the same probes the launch
uses (`probeUserns` + `usernsGapHint`, the guard's presence, the nesting
probe, the copy's state, the CVE probe): the posture a launch would get, the
bind gap, its cause, and the fix command where one exists. It renders, for
example, "credential files are protected (posture: confined, by the guard
alone)" and "mount layer unavailable", with `mandu setup` as the optional
second layer. One capability report drives the CLI, the dashboard and the
docs.

The same section reports Yama's `ptrace_scope`
(`/proc/sys/kernel/yama/ptrace_scope`, Linux only; `ptraceScopeFacts` /
`ptraceScopeRow` in `launcher/src/doctor.ts`, read through the doctor's knob
reader). Every same-account boundary assumes it is 1 or more: the dashboard
sign-in, the human plane (arbiter-human-plane.md §8), the reply filter. At 1
a program can trace only the programs it started, at 2 only with
`CAP_SYS_PTRACE`, at 3 never: a ✓ row naming the value. At 0, or with no
Yama in the kernel (the file absent), any program of the account, the
agent's included, can trace or `pidfd_getfd` any other, so those boundaries
are weaker: a ✗ warning naming what is exposed and the fix (`sudo sysctl
kernel.yama.ptrace_scope=1`, kept by a line in `/etc/sysctl.d/`; a kernel
built with Yama). A warning only: the guard is not dumpable (§12.2) and
stands either way, and a launch is not refused for it. Added 2026-10-07 (the
first-session tour); before, nothing told the human the assumption did not
hold.

### 3.4 Dashboard

The protection chip, the health chip, the plain-terms card and the 🛡
drawer's secrets group header show the posture (`confined` / `gated`) from
session-health (`dashboard.md` §4.23). `gated` is amber with the upgrade
command as copyable text where one exists; it is never the red "Protection
failed" state, because it is a known host condition and not an incident.
The session-health reason adds the partial-layer sentence for the bind-only
`gated` (`SECRETS_PARTIAL_NOTE`, §13).

### 3.5 Packaging

A `.deb` (or an apt repository) whose postinst installs the profile would
make root-at-install invisible, the way Chrome and VS Code do it. Since the
bundle ships the prebuilt guard (`packaging.md` §5, "native"), the profile no
longer stands between a fresh install and `confined`; a `.deb` would only
make the second layer invisible. Not planned.

## 4. Tests

- Unit: the posture resolution table (bind possible × guard present ×
  `require-confinement` × `best-effort`), the notice text, `setup --print`
  equal to the in-tree profile byte for byte, the doctor rows for each
  sysctl and probe state (Yama's `ptrace_scope` at 0, 1, 2, 3 and absent:
  `test/unit/doctor.test.ts`; this host's real value through the CLI:
  `test/component/doctor-yama.test.ts`).
- E2E: the gated drill of §3.1 (G1 to G4); the nesting probe against a
  26.04-like and a 24.04-like `bwrap` stand-in
  (`launcher/test/kernel/secret-bind-nesting.test.ts`); the copy's launch
  notes (`bwrap-launch-notes.test.ts`); the bind-only posture
  (`tests/sandbox/bind-only-posture.test.ts`); the guard's death
  (`guard-death-live.test.sh`, `guard-death.test.ts`); the real-home and
  fixture-home launches (`secret-discovery.md` §1.4).
- VM: `mandu setup` cannot run as root in the per-push CI; the matrix's
  `fresh-install`, `fresh-agents` and `release-upgrade` suites run it on
  fresh and upgraded guests (`os-test-matrix.md §10` §14, §15).

## 5. Spike: a rootless `read-blocked` posture with Landlock

Landlock needs only `no_new_privs`, no user namespace, so Ubuntu's
restriction does not apply to it, and the applier binary already existed
(`mandu-landlock-apply`). The spike asked whether an allow-list ruleset that
grants read to everything except the secrets (every sibling of each secret
and of each ancestor) keeps ordinary work usable: new files, the rule count,
stacking with the existing Landlock layers, workspace secrets, and how the
agent copes with a failing read. The answer was no; the result and the
mechanism built instead are §10.

## 10. A rootless `read-blocked` posture with Landlock: not built

Before the guard served twins, the candidate for a no-namespace posture was
Landlock, an unprivileged LSM that needs only `no_new_privs`. A spike
(2026-09-21, a throwaway ruleset handling only `LANDLOCK_ACCESS_FS_READ_FILE`
with a rule for every sibling of each secret and of each ancestor, on kernel
6.8, Landlock ABI 4) answered it. **Recommendation, taken: do not build it.**

What worked: the block itself is sound (`cat`, `cp`, Python `open()` of a
secret get EACCES; a hard link into a readable directory and `mv` of the
secret are refused, `EXDEV`); the cost is negligible (a real HOME's 164
catalog files: 4880 rules, under 90 ms); it stacks with the whole-agent
`--net-only` Landlock wrap.

What breaks it is **the agent's own runtime**, and no restriction of scope
rescues it:

- **Rules bind to inodes, and there is no non-recursive directory rule.** An
  ancestor of a secret can never be granted, only its existing children.
  Anything created later directly inside an ancestor matches no rule: a new
  file or directory in `~` is unreadable (with everything beneath it), and a
  new file in `~/.config` is unreadable once any secret lives under it.
- **An atomic save is a new inode.** After write-temp-then-rename, the path
  holds an inode with no rule. Claude Code replaces `~/.claude.json` by rename
  continuously, so the agent loses read access to its own configuration
  after its first write, mid-session, and a ruleset cannot be loosened after
  `restrict_self`.
- **Restricting to dot-directory secrets does not help**: `~` is an ancestor
  of every secret under HOME. **Workspace secrets** are the worst case: with
  `ws/.env` denied, `git checkout` and atomic saves in the workspace root
  produce unreadable files.

The unprivileged mechanism worth building instead was a whole-agent
**seccomp user-notification interposer on `open`/`openat`/`openat2`** with a
**supervisor-side open and `ADDFD`**: it needs no user namespace, yields the
full `confined` semantics (a read returns the symbol), is path-based so new
files and atomic saves are unaffected, and has no check-then-use race because
the supervisor performs the open. That is the guard as built (plan 10 phases
2 and 6, §11). `HostFacts.landlockReadBlock` stays in `confinement-posture.ts`
as an always-false input.

## 11. The guard-confined first day (2026-09-24)

Plan 10 phase 6 made the whole-agent guard (`mandu-net-guard`, seccomp
user-notification, `no_new_privs` only) serve every registered secret by
descriptor: a non-reader's `open()` gets the twin's fd, a listed reader the
real file's, and `io_uring_setup` / `open_by_handle_at` are refused under a
secret policy (`io_uring_setup` in every posture). That needs no user
namespace, so the only thing that kept a stock 24.04 `gated` was that an npm
install had no guard binary to run. Two changes closed that:

- **The bundle ships the native bins.** `bundle-manifest.json` `native` lists
  `mandu-net-guard`, `mandu-exec-box`, `mandu-landlock-apply`;
  `build-bundle.mjs` copies them (stripped, ~0.8 MB each) from
  `$MANDU_NATIVE_BIN_DIR` or `interceptors/target/release` into
  `dist/native/<platform>-<arch>/`, and `services/native-bins.ts` resolves
  that directory first when running from `dist/`. A bin that is not built is
  a note in the pack log, never a failure: the package still works, and the
  matrix target's `fresh-posture=` label decides whether that is a test
  failure.
- **The posture resolver knows the guard.** `resolveHostPosture` takes
  `guard`: no bind possible + guard present ⇒ `confined` with `bindGap`
  naming why the bind is unavailable (not a gap in the guarantee). The doctor
  says the native supervisors attach WITHOUT root, and its build hints are
  layout-aware: an npm user is never told to run `cargo build`
  (`os-test-matrix.md §10` §11).

**Evidence.** The fresh-install suite's 24.04 target declares
`fresh-posture=confined setup=installs` (26.04: `confined setup=nothing`) and
asserts, on a stock guest with no sudo, that doctor says confined-by-the-guard,
the FIRST launch reads the canary as a placeholder, no GATED notice appears,
no `cargo build` is suggested, and the real Claude Code on a reduced
credential declines to print the key. `mandu setup` still installs the second
layer (and, on 24.04, the namespace the exec box wants), and uninstall returns
to the same `confined` posture.

**The bind stays where it can mount.** Plan 10 §13's guard-only soak held the
S1 to S6 battery, but the bind is a second, independent implementation of the
twin (at the VFS, where the guard emulates `open` in user space; §12.2), and
it costs nothing where userns is available. So the default is "bind where
possible, the guard always"; `--no-secret-bind` remains the soak switch.
Where the bind can mount but would stop the agent's own sandboxes, as on a
26.04 without `mandu setup`, it is left off (§12).

## 12. Ubuntu 26.04: the bind would stop nested sandboxes (2026-09-27)

**Found** by the fresh-agents VM suite (`os-test-matrix.md §10` §14.1): on
26.04 with bubblewrap installed, every shell command Codex ran under `mandu`
died `bwrap: No permissions to create a new namespace`, and so did every
command Claude Code's Bash tool ran through Mandu's exec box. Both are a bwrap
started inside the secret bind wrap. `--no-secret-bind` and `--mode off`
worked.

**Root cause** (apparmor 5.0.2, bubblewrap 0.11.1). 26.04's `apparmor`
package ships `/etc/apparmor.d/bwrap-userns-restrict`: `profile bwrap
/usr/bin/bwrap` may create a user namespace, and `allow pix /** ->
&bwrap//&unpriv_bwrap` stacks `unpriv_bwrap` on everything a bwrap sandbox
runs. `unpriv_bwrap` has `audit deny capability`, which also denies
CAP_SYS_ADMIN inside a child's OWN new user namespace, so any bwrap nested
inside a bwrap sandbox cannot set up its namespaces (the kernel log shows
`apparmor="DENIED" operation="capable" profile="unpriv_bwrap" comm="bwrap"
capname="sys_admin"`). This is Ubuntu's deliberate design: bwrap must not be
a trampoline around the userns restriction.

**What cannot fix it without weakening the host.** Anything unprivileged (the
confinement is inherited by every child of the wrap); a local override
(`/etc/apparmor.d/local/unpriv_bwrap` with `userns,` or `capability,`: an
AppArmor `deny` beats every `allow`); loading a 24.04-style `bwrap` profile
over the distro one (nesting works, but it replaces Ubuntu's restriction for
every program on the host).

**The fix: probe, then serve the twins with the guard alone.** Before it
binds, `applySecretTwins` runs the nesting probe (§12.1). If it fails and the
guard is around the launch, the bind is left off (`bindGap:
"bwrap-nesting"`). The twins and the guard's policy file are still written,
so this is the `--no-secret-bind` posture chosen by probe, and the posture
stays `confined`. The launch line saying so is shown under `--verbose` and
kept in `launch.log` and the posture event, not as an attention line: nothing
the mode line claims changed. `mandu doctor` renders "posture: confined, by
the guard alone" and "mount layer off: …", and offers `mandu setup` as the
optional second layer (§12.3). Without a guard the bind STAYS, keeping raw
bytes out ahead of a working shell, and a WARNING names what will fail.

**What guard-only gives up** is the second layer, nothing in the claim
(§12.2). It is the same posture a stock 24.04 runs from its first launch
(§11).

**Evidence.** On a diagnostic guest, nested bwrap and `codex sandbox` worked
on the bare host and failed inside a hand-built twin wrap and under `mandu`
before the fix. The scripted Claude Bash leg had passed on the masked wire
copy while Claude Code's own transcript held the bwrap error, so the agent leg
now also reads the local transcript. Tests: unit `confinement-posture`,
`secret-twins`, `secret-setup`, `doctor`; e2e
`launcher/test/kernel/secret-bind-nesting.test.ts` (real arbiter, the default
probe against 26.04-like and 24.04-like `bwrap` stand-ins, and the resulting
prefix run with a nested sandbox inside; red with the probe disabled); the
fresh-agents VM suite on both targets.

### 12.1 The probe, step by step

"Can a sandbox start inside the wrap" is decided by running one, not by
reading the OS version. Just before the agent starts, and only when there
are secret files to bind, `applySecretTwins` runs:

    bwrap --dev-bind / / <the twin wrap's own flags> -- \
        bwrap --unshare-user --unshare-pid --unshare-net --ro-bind / / -- true

The outer bwrap is the twin wrap exactly as the launch would run it
(`TWIN_WRAP_HARDENING` plus the WSL flags; secret-twins.ts
`nestedSandboxProbeArgv`). The inner bwrap is what the agent's own tools
start: Codex's per-command sandbox, Mandu's exec box. `true` does nothing.

- **Exit 0** (24.04 with the setup grant, any release with Mandu's copy):
  nesting works; the bind goes on.
- **Anything else** (26.04 with `bwrap-userns-restrict` only): the bind would
  kill every command the agent's tools run; with the guard present the bind
  is left off (`bindGap: "bwrap-nesting"`).

Cost: two bwrap spawns, tens of milliseconds, with a 10 s timeout. A
transient failure (a starved host) also lands on guard-only, which is a
supported `confined` posture, never on raw bytes.

### 12.2 What guard-only gives up (corrected 2026-09-27)

Earlier text justified keeping the bind as "the one thing that still confines
a session whose guard dies mid-run". By the kernel's semantics that is the
wrong reason: a dead guard fails closed on its own, and the agent cannot stop
its guard.

**The agent cannot stop its guard.** The guard is an ordinary process of the
same user, so a crash, the OOM killer or a `kill` from outside the session
can end it, but nothing the agent's tree does can
(`interceptors/net-supervisor/src/guard_signals.rs`, `harden_guard` in the
guard binary):

- **Catchable signals.** The guard ignores or handles every catchable signal
  whose default is to end or stop it (glibc's reserved 32 through the raw
  syscall), so only SIGKILL, SIGSTOP and 33 can hurt it. SIGTERM, SIGINT,
  SIGHUP and SIGQUIT sent by a process are forwarded to the agent, and the
  guard keeps serving until the tree exits; a `SIGIO` owner set to the guard
  kills nothing, and `fcntl(F_SETSIG)` to SIGKILL or SIGSTOP is refused.
- **Signals by number.** The filter hands `kill`, `tgkill`, `tkill`,
  `rt_sigqueueinfo`, `rt_tgsigqueueinfo` and `pidfd_open` to the guard when
  they could name it (its pid, its group, `-1`, `0`, and, since the kernel
  reads a `kill` pid as a THREAD id, any positive pid for the four harmful
  signals); `prlimit64` of another pid is checked too (an `RLIMIT_CPU` ends in
  SIGKILL). The guard refuses (`EPERM`) a call that would reach itself or one
  of its threads, `kill(-1)`, and `kill(0)` from its group; `setpgid` into
  its group is refused in the filter. A caller in a pid namespace below the
  guard's cannot name it; a namespace the guard cannot read counts as its own
  (fail-closed).
- **Signals by descriptor.** For the four harmful signals the guard PERFORMS
  `pidfd_send_signal` itself (`decide_send`, `perform_pidfd_send_signal`): it
  copies the caller's descriptor (`pidfd_getfd`), judges the copy, and sends
  through it only where the kernel would have let the caller send, on a
  thread under the caller's own Landlock layers, so a `dup2` swap between the
  check and the send cannot win. Other signals are checked and continued (a
  swap can then deliver only a signal the guard ignores).
- **Process group and scheduling.** The guard moves to a process group of
  its own. `setpriority`, `ioprio_set` and the `sched_*` calls that name
  anything but the caller go to the guard, which refuses the ones that would
  reach it (`renice -u` from inside the session gets `EPERM`).
- **Not dumpable.** `PR_SET_DUMPABLE 0`, so `ptrace`, `pidfd_getfd`,
  `process_vm_readv` and `/proc/<guard>/{mem,environ,fd}` need
  `CAP_SYS_PTRACE` whatever Yama's `ptrace_scope` is; otherwise, on a host
  with `ptrace_scope=0`, the agent could take the guard's listener and answer
  its own notifications.

Pinned by `launcher/test/guard-death-live.test.sh` case 2: each attempt
above, run by the agent, returns `EPERM` (`EACCES` for the environ read), the
guard survives and still serves the twin, and the tree's own signals and
scheduling calls still work; repeated under a secret policy and a
connect-only guard, including a stream of `pidfd_send_signal(SIGKILL)` under
`dup2` swaps. The guard's thread ids are handed to the test from outside the
tree, so the attempts never guess.

Residue:
- A performed SIGKILL, SIGSTOP, 32 or 33 by pidfd differs from the kernel's
  own send in three corners: the receiver sees the guard as the sender when
  no `siginfo` is passed; a caller signalling ITSELF with its own `siginfo`
  and a non-negative `si_code` gets `EPERM`; under a Landlock signal scope the
  send is refused even to the caller's own domain (stricter, never looser). A
  caller the guard cannot `pidfd_getfd` from gets `EPERM` for those four.
- When the guard leads the session's group (under `script(1)` or `setsid`), a
  process that leaves it cannot come back.
- The cgroup is not a signal, so it has its own rule (below, "The cgroup",
  2026-10-21). Before it, the tree could freeze or throttle the guard where
  `/sys/fs/cgroup` was writable to it. What is left: a mode with no guard
  policy (`off`), a cgroup v1 hierarchy, and the cost (podman and crun
  cannot place their own cgroups inside a session).

**The cgroup (built 2026-10-21).** The launcher runs the guard and the agent
in one `systemd-run --user --scope` under `user@UID.service/app.slice`, which
the user owns (systemd delegates it, `nsdelegate`), files included. So any
process of the uid could make a child cgroup, move the guard into it, and
freeze or kill the scope, the child or `app.slice` (`cgroup.freeze`,
`cgroup.kill`), or throttle it (`cpu.max`, `memory.max`). A frozen guard does
not fail closed: the tree's trapped calls wait. Nothing leaks; the session
hangs. A launch from a desktop terminal or tmux (a user-owned cgroup) had the
same exposure; a guard in a root-owned cgroup (an SSH `session-N.scope`, the
CI guest's service) or under a read-only `/sys/fs/cgroup` did not. No
unprivileged placement fixes it: the owner of a cgroup can always give
itself write access back. Every write to a cgroup file starts with an open,
and the guard performs every open that can write (plan 10 §4.1a), so the
guard refuses the open (`EACCES`)
(`interceptors/net-supervisor/src/cgroup_guard.rs`, the decision, pure;
`cgroup_guard_kernel.rs`, the facts, behind the `kernel` feature):

- **What is judged.** A write-capable descriptor (any access mode but
  `O_RDONLY`; never `O_PATH`) of a file on cgroup2, told by the descriptor's
  `fstatfs` (magic `0x63677270`), never by a path. It is judged on the
  descriptor about to be handed over, after the context helper's reopen
  (plan 10 §4.1a "Pseudo-filesystems"), so a `/proc/self/fd/N` reopen, a
  bind mount of `/sys/fs/cgroup` or a symlink to it is judged the same.
- **Rule 1, the guard's cgroup and every one above it.** Any of their files
  opened for writing is refused: `cgroup.freeze`, `cgroup.kill`, `cpu.max`,
  `memory.max`, `pids.max`, `cgroup.procs`, `cgroup.subtree_control`, …
- **Rule 2, a task list a move could use.** cgroup v2 lets a writer move a
  task from cgroup S to D when it may write D's `cgroup.procs` (the open) and
  the `cgroup.procs` of the common ancestor of S and D (a permission check at
  the write, not an open). With S the guard's cgroup, the common ancestor is
  the first cgroup above D that is also the guard's or above it. A
  write-capable open of `cgroup.procs` or `cgroup.threads` anywhere else is
  refused unless that ancestor's `cgroup.procs` is not writable to the
  opener (mode bits: kernfs keeps no ACLs). So under `app.slice` every task
  list of the user's tree is refused, and a guard in a root-owned SSH
  session scope leaves the user's own cgroups usable (their common ancestor
  with it, `user-UID.slice`, is root's).
- **Every other cgroup file** (a cgroup beside or below the guard's:
  `cgroup.freeze` of a child the agent made) opens as before; freezing a
  cgroup the guard is not in hangs only what is in it.
- **Fail-closed.** The guard's cgroup is `/proc/self/cgroup`'s `0::` path
  under a cgroup2 mount of its `mountinfo` (the one with the shortest root
  first), believed only when that directory's `cgroup.procs` lists the
  guard. The opened file's cgroup is placed by the path its descriptor
  names, opened in the guard's view and believed only when it holds the same
  file (same device and inode; a kernfs node has one parent), then walked up
  by `..` while the file system stays cgroup2. A guard that cannot find its
  own cgroup refuses every write-capable cgroup2 open; so does one that
  cannot place the target (a private cgroup2 mount in the tracee's own mount
  namespace, a deleted cgroup), or whose two walks share no cgroup (the
  target could be above what the guard's view shows), or that cannot read
  the common ancestor's permission.
- **The cost, accepted (the maintainer's call, 2026-10-21).** A tool in the
  session that moves processes between cgroups is refused while the guard's
  cgroup is the user's: podman and crun placing a container in a cgroup of
  their own (with the cgroupfs manager, or crun's own write to the scope
  systemd made), and anything that writes the session's own cgroup files
  (`cgroup.subtree_control` to delegate controllers below the scope, a PSI
  trigger on its `*.pressure` files). The guard says so once per session
  where its messages go (`diag`). Run such tools outside the session.
- **Not covered.** Mode `off` and any launch whose guard has no policy file
  (opens are continued, not performed: nothing is judged); a cgroup v1
  hierarchy (`cgroup`, not `cgroup2`: systemd delegates only v2 to users);
  a process of the same uid outside the agent's tree, which could also kill
  the guard; a write through a descriptor the tree did not open (none is
  handed to it). A launcher watchdog on `cgroup.events` was weighed and not
  built: the agent's tree could freeze the launcher's cgroup too, which is
  the same one.

Pinned, DEFENSIVELY (opens only, nothing is written to a cgroup file, and
no test freezes, kills or moves anything), by
`interceptors/net-supervisor/tests/guard_integration.rs`
`a_write_open_that_could_freeze_or_move_the_guard_is_refused` (a tracee
under the real guard: `O_WRONLY` and `O_RDWR` of the guard's own
`cgroup.freeze`, `cgroup.kill`, `cgroup.procs`, `cgroup.threads`,
`cgroup.subtree_control`, `cpu.max`, `memory.max`, `pids.max`, of the
freeze, kill and task-list files of every user-owned cgroup above it, and of
a sibling's `cgroup.procs` / `cgroup.threads` all answer `EACCES`, each one
the kernel would have allowed; reads of the same files pass; first, the
verdict behind each refusal, on descriptors the test opens itself and
closes unwritten); the decision by `cgroup_guard.rs`'s unit tests. The
kernel test runs in every CI run: the guest's `boot.sh` delegates a cgroup
to `ci` in the shape a desktop session has (the suites' own cgroup, a
user-owned parent above it and a user-owned sibling beside it:
continuous-integration.md §3), so all three of its cases run, and
`rust.kernel` allows no skip for it (the guest leaves `cpu` off, so CI
covers `memory.max` and `pids.max` but not `cpu.max`, whose refusal is the
same rule; a desktop run with `cpu` delegated covers it). Elsewhere it self-SKIPs where the
test's own cgroup is not user-owned (an SSH `session-N.scope`); from a
desktop terminal or tmux: `cargo test -p net-supervisor --features kernel
--test guard_integration -- --ignored cgroup freeze`.

**A dead guard fails closed, by kernel rule, and ends the session.** When a
seccomp user-notification listener goes away, every syscall the filter routes
to it fails with `ENOSYS` (seccomp_unotify(2)), and the filter stays on the
agent's processes for good: every `open` and `connect` fails, and no open
reaches the real file. The session also ends instead of lingering:

- **The agent's top process dies with the guard**: the guard's child sets
  `PR_SET_PDEATHSIG` to SIGKILL before it runs the target. An AppArmor
  profile change at an exec clears that death signal (AppArmor's
  `bprm_committing_creds`), and `bwrap --die-with-parent` alone does not
  cover it: bwrap sets its own death signal just before it execs the
  sandboxed program, and on Ubuntu 26.04 that exec is the profile change
  (`bwrap-userns-restrict` moves the program to `unpriv_bwrap`), so the
  agent outlived the guard there (found 2026-10-03 on a stock Ubuntu 26.04
  host; the CI guests set `kernel.apparmor_restrict_unprivileged_userns=0`,
  so the profile change never happens in them and they could not show it).
  What covers it is the twin wrap's own pid namespace (`--unshare-pid`):
  its first process is bwrap itself, which never execs and keeps its death
  signal, and when it dies the kernel kills everything in the namespace.
- **The launcher ends what is left and says why.** The guard writes
  `supervising <guard> <child>` to `MANDU_NET_GUARD_STATUS` (`<scope-run
  dir>/net-guard.status`) once it serves the tree and `exited <code>` when the
  tree is done, in the directory it opened at its start and never through a
  link the tree plants at either name (`safe_write.rs`, 2026-10-17;
  runtime-instances.md §2, "planted paths"). The code, which is also the guard's own exit status, is the
  child's, or 128 + the signal that killed it, as a shell reports it
  (`child_status.rs`; it was the exec-failure 126 until 2026-10-07, so an
  agent ended by a ^C looked like a launch that never ran). If the file still says `supervising` when the launch returns,
  the launcher (`launcher/src/guard-death.ts`) kills the rest of the session
  (its systemd scope, or every process of the launch's session) and prints
  `mandu: WARNING — the guard … stopped before the agent did …`.

Pinned by `guard-death-live.test.sh` (case 1, guard only: after an outside
SIGKILL the agent is gone and a reparented tool process finds opening the
secret, an ordinary file, a TCP and a Unix connect and an `execve` all fail
`ENOSYS`; case 3, guard outside and the twin wrap's bwrap inside with its
flags, `--die-with-parent` and `--unshare-pid` among them: the guard's death
takes the whole tree down, on Ubuntu 26.04 too; case 4, a normal exit
leaves `exited 0`) and
`launcher/test/kernel/guard-death.test.ts` (the real launcher: the agent gone,
its background tool killed with the session, the note printed; a control
prints none).

**What the bind really adds: a second implementation, not a second life.**
The guard re-implements `open` in user space (plan 10 §4.1), and its known
hard cases are exactly where a bug would let a real file through: `/proc/self`
and `/proc/thread-self` rewriting; `/dev/tty`, the one path left on
`CONTINUE`; FIFOs, `O_TMPFILE`, hard links, case-insensitive filesystems. It
denies outright the open paths it cannot see (`io_uring_setup`,
`open_by_handle_at`), so a syscall family a later kernel adds is another gap.
The bind works at the VFS: whatever syscall, `mmap` or static binary reaches
the path, it sees the twin. Guard-only therefore loses **defense in depth
against a guard bug**, not protection after a guard death.

**Metadata by path.** The bind also answers a `stat` of the path with the
twin's metadata. In the guard-only posture the launcher sets
`MANDU_NET_GUARD_STAT_TWINS=1` and the guard answers a following stat
(`stat`, `newfstatat`, `statx`) of a registered path with the twin's metadata
(git compares the sizes of a pack and its file, and dropped every sanitized
pack otherwise: `confidentiality.md` §7.2a "Guard-only metadata"), and since
2026-10-04 an `lstat` relative to the cwd or absolute too (`git diff
--no-index` sized the twin by the real file and printed it cut: §7.2a "The
size a reader sees"); an `lstat` relative to a directory descriptor (`find`,
`du`) runs free, so it still sees the real file's metadata, never its bytes.

### 12.3 Mandu's own bubblewrap: a profile that lets only Mandu's sandbox nest (built 2026-09-27)

Status: **built and VM-verified** on 24.04, 25.10 and 26.04 (versions in
§0.2) and across a real `do-release-upgrade` 24.04 → 26.04 (below). Code:
`launcher/src/bwrap-grant.ts`, `launcher/src/setup.ts`; profile:
`scripts/apparmor/mandu-bwrap`.

`mandu setup` (one sudo) copies the system bwrap to the **root-owned**
`/usr/lib/mandu/bin/bwrap` and loads `/etc/apparmor.d/mandu-bwrap`, whose two
Mandu-named profiles attach to that path only. A `Cx` child profile cannot
work: bwrap sets `PR_SET_NO_NEW_PRIVS` unconditionally, and under
no_new_privs AppArmor refuses ("no new privs", `EPERM`) any exec transition
whose new label does not contain the label recorded when NNP was first seen
(security/apparmor/domain.c; kernel ≥ 4.17). The distro profile stacks for
the same reason. The shipped shape:

    profile mandu_bwrap /usr/lib/mandu/bin/bwrap {
      <capability, userns, mount, umount, pivot_root, file rwlkm, network, …>
      /usr/lib/mandu/bin/bwrap ix,          # bwrap run inside stays mandu_bwrap
      /usr/bin/bwrap ix,
      pix /** -> &mandu_bwrap//&mandu_child, # everything else: stacked, capability-less
    }
    profile mandu_child {
      <file rwlkm, network, unix, ptrace, signal, …; no userns>
      /usr/lib/mandu/bin/bwrap Px -> mandu_bwrap,
      /usr/bin/bwrap Px -> mandu_bwrap,     # a nested bwrap: capabilities again
      pix /** -> &mandu_child,
      deny capability,
    }

In a stacked label each profile computes its own transition and the results
are merged. For `/usr/bin/bwrap` both halves say `mandu_bwrap`, so a nested
bwrap runs as `mandu_bwrap` (it contains the NNP label, so it is allowed) and
can set up its namespace; its payload goes back to `mandu_bwrap//mandu_child`.
The nested bwrap goes to Mandu's own profile, not the distro's `bwrap`, so the
design is the same on a 24.04 without any distro profile. The target of the
catch-all names `mandu_bwrap` itself (`-> &mandu_bwrap//&mandu_child`), as
Ubuntu's own profile does: a first version stacked only `mandu_child`, which
dropped `mandu_bwrap` from the label of a program with its OWN host profile,
and NNP then refused to exec that program at all. Such a program now runs as
`<its profile>//mandu_bwrap//mandu_child`, its host confinement kept and its
own `userns` grant of no use inside the wrap.

**The matrix** (as the unprivileged user; the wrap is the twin wrap's own
flags plus a twin bound over `~/.aws/credentials`; 24.04 and 26.04 gave the
same results):

| Check | Result |
|---|---|
| label inside the wrap | `mandu_bwrap//&mandu_child (enforce)` |
| nested `/usr/bin/bwrap --unshare-user --unshare-pid --unshare-net` | runs; the nested bwrap's label is `mandu_bwrap`; its payload has `CapEff 0` |
| three levels of bwrap | run |
| the twin, read from inside the nested sandbox | the twin, never the file |
| `codex sandbox -- /bin/true` and `cat` of the twin inside the wrap | run |
| `unshare -Ur true` inside the wrap | refused (`userns_create` DENIED for `mandu_child`) |
| file I/O, `curl`, signals, `ps`, node spawning children | unaffected |
| a program with its own host `userns` profile | runs; its `unshare` is refused |
| outside any wrap, `PATH=/usr/lib/mandu/bin:$PATH codex sandbox` | runs (24.04 bare Codex fails) |
| **trampoline:** `/usr/lib/mandu/bin/bwrap --dev-bind / / -- unshare -Ur true` | refused |
| **trampoline:** the copy with `--unshare-user`, payload `unshare -Ur` | payload `CapEff 0`, `unshare` refused |
| **trampoline:** the copy running the system bwrap running `unshare -Ur` | refused |
| 24.04 with Ubuntu's `bwrap-userns-restrict` extra enabled alongside | same results; both profiles loaded |

**In the product.**
- `mandu setup` installs the copy and the profile on 24.04 AND 26.04 (26.04
  gets its mount layer back), refreshes a copy older than the system bwrap,
  and removes the Mandu-marked pre-2026-09-27 grants (below).
- The launch uses the copy when it is IN FORCE (§0.4); otherwise everything
  is as before.
- `mandu doctor` shows "Mandu's own bubblewrap: installed", says when the
  copy is older than `/usr/bin/bwrap`, and flags a leftover old grant with
  its fix.
- **Every launch checks the copy** (`bwrapLaunchNotes`): it compares the
  copy's bytes with `/usr/bin/bwrap` (two small reads) and, when they differ,
  prints one WARNING without `--verbose`, naming both versions and `mandu
  setup`. The same check flags a leftover old grant. The copy's path cannot be
  moved by any env var, so the e2e (`test/kernel/bwrap-launch-notes.test.ts`)
  passes paths in-process over a real copy of the host's bwrap.
- **A change for Codex OUTSIDE Mandu on 24.04:** the old grant made
  `/usr/bin/bwrap` work for every program, bare Codex included. Mandu's copy
  is used only under `mandu`, so a bare `codex` on 24.04 needs Ubuntu's own
  profile (the `apparmor-profiles` extra), as Codex's own docs say.
- The developer-only `scripts/apparmor/mandu-dev-unshare` (Mandu-named,
  installed only by `install.sh --dev-unshare`) keeps
  `scripts/kernel-tests.sh` working on a development machine.

**Why the old grant had to go.** The grant `mandu setup` installed until
2026-09-27 (`profile bwrap /usr/bin/bwrap flags=(unconfined) { userns, }`,
plus the same for `unshare`) gave every program on the host an unconfined
bwrap that can create namespaces, the trampoline 26.04's distro profile
closes. It also defined a profile NAMED `bwrap` for `/usr/bin/bwrap`, as the
distro's `bwrap-userns-restrict` does, and the kernel keeps whichever file
loaded last: on 24.04 with the distro profile, Mandu's grant silently
vanished while `mandu setup` said "nothing to do"; on 26.04 with Mandu's
files, Ubuntu's nesting restriction was silently off for the whole host; and
`mandu setup --uninstall`'s `apparmor_parser -R` unloaded the distro's
`bwrap` too, until the next reload. So `mandu setup` now never installs a
profile named or attached like a distro one; removes a Mandu-marked
`/etc/apparmor.d/bwrap` or `unshare` even where the probes pass (the leftover
makes them pass); deletes the file and reloads the other file that defines the
same profile name instead of unloading by name; and `mandu doctor` and every
launch flag the leftover, naming each file's own danger
(`legacyGrantWarning`). The fresh-install suite plants the old grants and
checks all of it.

**A real `do-release-upgrade` 24.04 → 26.04.** The matrix suite
`release-upgrade` (`os-test-matrix.md §10` §15) installs Mandu on an
up-to-date 24.04, upgrades it with the real upgrader (the development path,
`-d`, while the LTS path is not yet open) and boots 26.04.1. From today's
`mandu setup`, nothing breaks: the 24.04 copy still loads and nests, so the
launch keeps both layers, and doctor and every launch name the stale copy
until `mandu setup` refreshes it. From the pre-2026-09-27 grants, Ubuntu's
`bwrap` profile won the load order (Ubuntu's no-nesting rule in force) but
Mandu's old `unshare` grant stayed loaded, so `unshare -Ur` worked for every
program until `mandu setup` removed it. In both runs Mandu stayed `confined`
and the agent never read the canary.

### 12.4 How other tools handle it (research, 2026-09-27)

**The distro profile.** `bwrap-userns-restrict` landed in noble's apparmor
4.0.1 SRU (July 2024), broke Flatpak and was reverted within days
(LP #2072811); on 24.04 it sits disabled under
`/usr/share/apparmor/extra-profiles/`. apparmor `4.1.0~beta4-0ubuntu1`
(Feb 2025) enabled it by default from 25.04 on; 26.04 ships it. Its comments
say nesting is forbidden on purpose, and that AppArmor has no clean
per-target escape yet. Canonical recommends no nesting workaround.

| Tool | What it does | Relevance to Mandu |
|---|---|---|
| Flatpak, Steam pressure-vessel | Nested bwrap is forbidden inside Flatpak (seccomp, plus a userns limit of 0 since 1.15.6). `flatpak-spawn` asks a host-side portal to start a **sibling** sandbox, optionally tighter; pressure-vessel uses it. On the host, `/usr/bin/flatpak` has a `flags=(unconfined) { userns, }` profile and needs one level only. | The broker pattern: no nesting at all. |
| OpenAI Codex | bwrap plus seccomp; prefers `/usr/bin/bwrap` (a vendored copy fell outside the path-scoped profile, PR #14963). Docs: 25.04+ works; on 24.04 load `bwrap-userns-restrict` or set the sysctl to 0; inside an outer sandbox run `--sandbox danger-full-access`. | Supports turning its sandbox off under an outer boundary. |
| Claude Code / sandbox-runtime | bwrap plus an `apply-seccomp` helper that nests a userns. Docs suggest an unconfined `/usr/bin/bwrap` profile, which collides with the 25.04+ distro one. `enableWeakerNestedSandbox` still fails on 26.04. Fails open unless `sandbox.failIfUnavailable`. | Same nesting failure on 26.04. |
| Cursor | Landlock plus seccomp and overlay copies of ignored files; ships its own profile for its helper. | Avoids namespaces for files. |
| nono | Landlock plus seccomp user-notification with `ADDFD`, no namespaces; tells users to run `codex --sandbox danger-full-access` to avoid nesting. | The same design as Mandu's guard; also disables the agent's sandbox. |
| Kiro | Tried `change_profile` to an unconfined profile; on 26.04 it is "converted to stacking" and still `EPERM`. | Profiles must attach by exec path, not by `change_profile`. |
| Podman, rootlesskit, LXC, Chrome, VS Code, Electron | Per-binary `flags=(unconfined) { userns, }` profiles shipped by the apparmor package. Chromium lists sysctl=0, a path profile, or the setuid sandbox. | The common pattern; unconfines the whole tree under the binary. |
| glycin (GNOME image loaders) | Callers `Px` into a dedicated confined bwrap profile (`:glycin:bwrap`) with `userns` and named capabilities; its loader is stacked `bwrap//&loaders`. | The closest precedent for §12.3; its callers are not under NNP. |
| bootc CI, some Claude Code users | Edit the distro profile (`local/unpriv_bwrap` with `priority=1 capability sys_admin,`, or `pix` → `ix`). | Host-wide loosening; rejected for Mandu. |

**No unprivileged file substitution besides seccomp user-notification.**
Landlock only denies (and cannot hide a file's existence), and a
Landlock-restricted process may not `mount` or `pivot_root`, so it would stop
nested bwrap the same way. fanotify permission events need `CAP_SYS_ADMIN`.
The seccomp_unotify(2) man page confirms §12.2: after the supervisor is gone,
a trapped syscall fails with `ENOSYS`.

### 12.5 Options and the recommendation

1. **Guard only where nesting fails (built, the default).** No sudo and no
   host change. Loses the VFS second implementation (§12.2).
2. **A Mandu-owned bwrap with a stacked, capability-denying child (§12.3,
   BUILT).** Tightest: only bubblewrap holds capabilities inside the wrap, no
   trampoline, `/usr/bin/bwrap` untouched. Needs one sudo.
3. **A Mandu-owned bwrap with a `flags=(unconfined) { userns, }` profile**
   (the podman, rootlesskit and flatpak pattern). Simple, but the whole agent
   tree regains `userns` and capabilities inside its namespaces, and anyone
   can run the copy as a trampoline. Not needed.
4. **A sibling-sandbox broker (the Flatpak portal pattern).** Inside the
   wrap, a shim over `/usr/bin/bwrap` forwards the argv to a broker outside
   it, which starts the real bwrap as a sibling with the twin binds and the
   guard's filter reapplied. No AppArmor change and no nesting, so it works on
   any host. The cost is heavy plumbing: bwrap's `--args`/`--sync-fd`/seccomp
   fds, pid-namespace mismatches, and a broker that must never start a
   sibling looser than the agent. The long-term route if AppArmor proves too
   fragile or a non-Ubuntu host forbids nesting.
5. **Turn the agent's own sandbox off under Mandu** (`codex --sandbox
   danger-full-access`, Claude Code `sandbox.enabled=false`), as nono, OpenAI
   and Anthropic advise inside an outer boundary. Invasive (it rewrites the
   user's agent policy and drops protections Mandu does not replace one for
   one), and it does not fix Mandu's own exec box, which nests too.
6. **Ask the user to loosen the host** (sysctl 0, or edit
   `local/unpriv_bwrap`). Host-wide weakening; ruled out by the privilege
   model.

Option 1 is the no-sudo default and option 2 is what `mandu setup` installs
on 24.04 and 26.04; it replaced the old `/usr/bin/bwrap` + `unshare` grants,
which removes the collision hazard on both releases. What is still open is in
§0.7.

### 12.6 The probes are kept for the boot (2026-10-04)

The probes of this section (userns, the nesting probe of §12.1, Mandu's own
bubblewrap's grant of §12.3, Codex's sandbox) and the git sandbox's run once
per boot per set of inputs, not once per launch (packaging.md §5.4,
`launcher/src/probe-cache.ts`). Only a PASS is kept, so a host that cannot
nest, or whose userns is shut, is probed on every launch exactly as before,
and `mandu setup`'s result is seen at once (setup also deletes the file). A
kept pass changes nothing about what the launch enacts: the bind wrap still
runs bubblewrap, and where the kept answer was wrong bubblewrap fails, the
agent never starts, and the launch drops the file. The key covers what these
answers depend on: `boot_id`, the userns knobs, the AppArmor profile files
(`mandu-bwrap`, `bwrap-userns-restrict` and the legacy names) and Mandu's
copy, each bubblewrap's identity, and the launcher's own namespaces, seccomp
state and AppArmor label. `mandu doctor` always probes fresh;
`MANDU_PROBE_CACHE=0` makes one launch do the same.

## 13. Bind-only is `gated`; the bwrap symlink CVE (2026-09-28)

Two decisions from a sandbox security review (its findings 7 and 14).

**Finding 7: `confined` requires the guard.** Before, bwrap + userns alone
resolved to `confined`. In that bind-only posture a secret file the HOST
replaces while the agent runs (a token refresh, an editor save: write a new
file, rename it over the old one) detaches the twin bind, which sat on the
old inode, and the real new file is readable to every program the agent
runs. Only the guard's by-path lookup at `open()` catches it. So
`resolveHostPosture` (launcher/src/confinement-posture.ts) returns `gated`
for bwrap + userns without the guard, with a `HostGap`:

| Gap | When | Cause shown | Fix |
| --- | --- | --- | --- |
| `no-guard` | the guard binary does not resolve (no prebuilt for this machine; a checkout that has not run `scripts/build-native.sh`) | the file guard is not available, so a credential file replaced while the AI runs is readable | none as one command (the cause names the build step) |
| `guard-off` | the user turned it off: `--no-net-guard`, `MANDU_NET_GUARD=0`, `net-guard = false`, `--no-kernel` / `MANDU_NO_KERNEL` | the file guard is turned off (same consequence) | none (drop the opt-out) |

The bind still goes up (the partial layer is kept, never removed), and every
consumer says what it covers and what it does not:

- **Launch**: the `GATED` notice (an attention line) with the partial-layer
  line; the mode line reads `credential files GATED (N behind a placeholder,
  no file guard)`; the `launch_posture` event carries `secrets: { posture:
  "gated", gap: "no-guard" | "guard-off" }`. `--require-confinement` refuses
  before anything is registered or bound. An arbiter failure still refuses
  unless `--best-effort` (the partial layer is something to lose).
- **`mandu doctor`** (and `doctor --secrets`): `✗ … (posture: gated)`, the
  two `bindOnlyLines`, the cause, the `--require-confinement` hint. Doctor
  reads the same opt-outs the launch does (`guardOptedOut`: the launch's own
  `parse` over env + config.toml), so it names `guard-off` too.
- **Dashboard**: amber chip, no fix command; the session-health reason adds
  the partial-layer sentence (`SECRETS_PARTIAL_NOTE`). The parity test in
  `dashboard/test/unit/session-health.test.ts` iterates the launcher's
  `HOST_GAPS`, so a new gap cannot miss the dashboard.
- **`mandu setup`** does not say "secrets are `confined`" after installing
  the mount layer; it says `confined` needs the guard too and points at
  doctor.

**Finding 14: a probe, warn only.** bubblewrap < 0.12.0 follows symlinks in
mount DESTINATIONS during setup (CVE-2026-87766); the fix resolves
destinations without following them and rejects a mount onto a symlink
("Can't mount on symlink destination"). A version floor is wrong both ways:
Ubuntu 24.04 backported the fix in `0.9.0-1ubuntu0.2` and dropped it again in
`0.9.0-1ubuntu0.3` (a Flatpak regression, LP #2167621). So
`launcher/src/bwrap-symlink-probe.ts` asks the binary: in a fresh temp dir,
`real/`, `link -> real` and `src/<marker>`, one run of the bwrap the wrap
would use (`resolveWrapBwrap`: Mandu's own copy when installed) with
`--dev-bind / / --bind src link -- test -e real/<marker>` (about 20 ms). Exit
0 with no bwrap error = `vulnerable`; a bwrap error naming the symlink =
`fixed`; anything else (no userns, no bwrap, an unexpected outcome) =
`unknown`, which warns only through the version (below). Verified both ways
on 24.04: `0.9.0-1ubuntu0.3` follows the link, `0.9.0-1ubuntu0.2` refuses
and binds a non-symlink destination normally.

- `mandu doctor` prints a row under Your secrets: `✗ bubblewrap on this host
  follows symlinks while it sets up a sandbox (CVE-2026-87766) (/usr/bin/bwrap,
  version 0.11.1) … fix: a bubblewrap with the fix: upgrade the distro
  package when it ships one (Debian, Ubuntu: sudo apt update && sudo apt
  install --only-upgrade bubblewrap; Fedora: sudo dnf upgrade bubblewrap),
  or bubblewrap 0.12.0 or newer (an administrator can point Mandu at one
  with bwrap_path in /etc/mandu/policy.d); then run mandu doctor, which
  tests the build itself (a version number is not proof)`, or `✓ … refuses
  to mount onto a symlink`.
  When the bwrap asked is Mandu's own copy, the fix adds `then run mandu
  setup, which refreshes Mandu's own copy … from it`.
- A launch whose bind is in use prints one `WARNING:` line when the probe
  says `vulnerable` or `version-affected`. It never refuses and never
  changes the posture.

**The version, second (2026-10-07, before the 0.2.0 release).** Users must
be told the version they run and how to upgrade, and an `unknown` answer used
to say nothing even on a 0.11.1. So the probe now also reads `bwrap
--version` (bwrap-grant.ts `bwrapVersion`, the same probe the stale-copy note
uses), only when the behavior did NOT say `fixed`: a fixed host spawns
nothing more, and an affected one one short process, once per launch (the
probe runs where the bind goes up, never per command). Pure rules
(`withVersion`, unit-tested with no bwrap):

| Behavior | Version | Verdict | Says |
|---|---|---|---|
| refuses the symlink | any (0.9.0 with Ubuntu's backport included) | `fixed` | ✓ row; no line |
| follows it | any (a "0.12.0" that follows it included) | `vulnerable` | ✗ row and the line, naming the version |
| could not run | older than 0.12.0 | `version-affected` | ✗ row and the line: "reports a version older than 0.12.0 … Mandu could not test this build itself (bwrap's reason), so it may be affected; the version number does not settle it … check the installed build instead" (reworded 2026-10-09, §0.7 follow-up 3: distros backport and revert, so the line names the changelog and `mandu doctor` as the checks) |
| could not run | 0.12.0 or newer, or unreadable | `unknown` | nothing |

The behavior wins wherever it answered; the version never clears a finding
and only turns silence into a warning. The fixed version, 0.12.0, is what
upstream's NEWS for 0.12.0 and the fixing commit (c77dd38, "setup: Use O_PATH
fds and disallow symlink targets", advisory GHSA-pxhw-h44j-8pfx) record.

**Why a warning, not a refusal (re-checked for 0.2.0 against the threat
model).** A refusal (with an override variable) was considered and rejected:

- What the bug gives: the attacker must be a process of the same user that
  is already running when a launch builds its whole-agent wrap and that wins
  the race between the launcher's realpath check and bwrap's setup (the
  realistic one is another session's agent). The command box gains nothing.
- What it costs in the confined posture: nothing that leaks. The guard
  looks up each `open()` by path and serves the twin wherever the bind
  landed; only bind-only (`gated`, finding 7) loses the file, and that
  posture already prints `GATED` on every launch, and
  `--require-confinement` refuses it.
- What a refusal would cost: every launch on a stock Ubuntu 26.04 (0.11.1,
  no fixed package yet) and 24.04 (`0.9.0-1ubuntu0.3`) would stop, and the
  user's only ways forward would be an override or running the agent
  without Mandu, which hands every secret to the model. The invariant is
  better served by the guard plus a loud line than by no protection at all.
- So the fail-closed rule (`CONTRIBUTING.md`: labelling,
  classification and the egress gate fail closed) is not engaged: the probe
  decides no label, no egress and no posture; it reports a weakness of one
  of two layers.

Assessment: the **command box** gains nothing from the bug (its writable
mounts are a private /tmp and the AgentView, which the agent can already
write; its base is `--ro-bind / /`, so a swapped destination only confuses
the box's own view). The **whole-agent wrap** is built once at launch over a
writable `--dev-bind / /` (launcher/src/secret-twins.ts): a process of the
same user already running (a concurrent session's agent, say) can race the
launcher's realpath check and swap a secret's parent directory for a symlink,
so the twin lands elsewhere and the real file stays visible (the guard's
by-path lookup still serves the twin; exposed only bind-only, which finding
7 calls `gated`), and it can make bwrap create an empty file at a chosen
path. Tests: `launcher/test/unit/{confinement-posture,bwrap-symlink-probe,
secret-setup,doctor}.test.ts`, `tests/sandbox/bind-only-posture.test.ts`
(the real host: guard off ⇒ gated with the bind up, strict refuses, the probe
agrees with an independent look).
