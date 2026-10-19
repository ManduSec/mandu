# docker-e2e — Docker and the test suites

Status: implemented. `packaging/docker/Dockerfile.ci` is an image that holds
every test kind's toolchain, and `scripts/ci/docker-run.sh` runs any test
command in a fresh container built from it. They were the environment of the
Docker-based CI pipeline retired on 2026-09-28; CI now runs in a disposable
KVM guest ([`continuous-integration.md`](./continuous-integration.md)). No CI
job uses them; they stay as a hand-run way to run any test kind in a
container, and §1 records what they do and the lessons they taught. §2 says
what the dashboard's Docker mode is.

## 1. The Docker test wrapper (`scripts/ci/docker-run.sh`)

`docker-run.sh` runs any test command in a container built from
`packaging/docker/Dockerfile.ci` (`scripts/ci/build-image.sh` builds it). It
was the job sandbox of the CI pipeline retired on 2026-09-28, whose every job
was one `docker-run.sh` line; the KVM guest replaced it because a container
shares the host's kernel and needed relaxations for the kernel tier
(continuous-integration.md §1, §3). It stays as a hand-run tool, for example:

```sh
scripts/ci/docker-run.sh core -- npm run typecheck
scripts/ci/docker-run.sh core -- scripts/test-all.sh --scope shipping   # = --kind unit,component,stack
scripts/ci/docker-run.sh userns --kernel-tests -- scripts/test-all.sh   # + the sandbox kind
scripts/ci/docker-run.sh vm -- scripts/kernel-vm.sh
scripts/ci/docker-run.sh vm -- scripts/matrix/run-matrix.sh --require ubuntu-2404
```

Each run is one fresh `docker run --rm`: its own network and PID namespace,
its own `/tmp` and arbiter socket, **no published host port**, so concurrent
runs (and a host's own stack on `:4500`) never collide. Shared read-write
state is deliberately tiny: a named volume for the cargo *registry* (a
download-only, content-addressed cache) and one for the VM base image; the
cargo build dir is per-container, since a shared `target/` makes one build
block on the other's lock and two source trees thrash each other's
fingerprints.

### 1.1 Profiles: what Docker can and cannot host

| Profile | Grants | For |
|---|---|---|
| `core` | **nothing** beyond a plain container | typecheck, unit, component and stack kinds, cargo decision logic, the scripted-model agent suites |
| `userns` | `seccomp=unconfined` + `apparmor=unconfined` (+ `--kernel-tests` → `systempaths=unconfined`) | the kernel tier |
| `vm` | the above + `--device /dev/kvm` | `scripts/kernel-vm.sh`, the VM matrix (QEMU runs inside the same container) |

No profile uses `--privileged` or `--cap-add`; `scripts/test/docker-run.test.sh`
asserts that, so a profile cannot quietly gain privilege.

**The measurement behind `userns`.** Docker's **default** seccomp profile
blocks `clone(CLONE_NEWUSER)`, and AppArmor separately blocks the mount
namespace, so a default container fails `scripts/require-userns.sh`'s
`unshare --user --map-root-user --mount --net --pid --fork` probe. That
policy is removable per container, and removing exactly those two is enough:

| Container flags | userns gate |
|---|---|
| (default) | FAIL |
| `--security-opt seccomp=unconfined` | FAIL (AppArmor still blocks the mount ns) |
| `--security-opt seccomp=unconfined --security-opt apparmor=unconfined` | **PASS** |
| `--privileged` | PASS (but grants far more) |

Inside such a container, inside an unprivileged userns, `nft` also creates a
table and a chain at `prerouting priority -150`, net-supervisor's real TPROXY
hook. So the enforcement tier runs in Docker with **two security-opts, no
`--privileged`, and no added capability**.

`scripts/kernel-tests.sh` needs one flag more: `unshare --mount-proc`. Docker
masks parts of `/proc` (`/proc/kcore` and others) with bind mounts; those
count as **locked mounts**, so the kernel refuses to mount a fresh procfs over
`/proc` inside a nested userns+mountns. The unlock is a third security-opt,
`systempaths=unconfined`, behind `--kernel-tests` (its old name
`--kernel-tier` stays an alias), off by default: granting a `/proc`-masking
relaxation for tests a run does not need is privilege not earned. The same
flag serves the exec box (bwrap + Landlock), whose fresh `/proc` needs it
(`bwrap: Can't mount proc on /newroot/proc: Operation not permitted`
otherwise).

**What Docker cannot host.** A container shares the host kernel, so a
different kernel's behavior (old-kernel probe and degrade paths, other
distros' userns policies) needs a VM; the `vm` profile is the same container
with `/dev/kvm` added and QEMU inside it. That shared kernel is also why CI
moved to a KVM guest: a test that wedges the kernel takes the host with it.

### 1.2 The userns hard gate, and assert the count

Without `--kernel-tests`, `kernel-tests.sh` **skips and still counts green**,
and its skip message blamed "unprivileged user namespaces are unavailable",
which is false in the container (userns works, only `--mount-proc` is
blocked). `require-userns.sh` could not catch it, because it probes
*without* `--mount-proc`, a weaker condition than the tests need. The suite
reported green while running 0 of its 16 attachment tests, and the only way
to see it was to diff the container run's counts against a host run's.

**The lesson generalizes: for a suite that is allowed to self-skip, assert
the COUNT, not the colour.** A green from a suite that ran nothing is the
failure mode the fail-closed discipline exists to prevent. Two mechanisms
carry it:

- **The userns hard gate.** `test-all.sh` and `kernel-tests.sh` self-SKIP
  the userns suites where unprivileged userns is unavailable, which is right
  for portability and wrong for a gate. `MANDU_CI_REQUIRE_USERNS=1` makes
  `scripts/test-all.sh` run `scripts/require-userns.sh` as a preflight and
  **fail** (not skip) when the host cannot grant userns.
- **Exclusion by name, not self-skip.** `--scope shipping` excludes the
  kernel tier's live suites by name and prints the scope it ran, so a run
  that left them out says so instead of passing them silently. The CI
  guest's equivalent is the manifest's expected pass and skip counts
  (continuous-integration.md §5).

### 1.3 The image (`Dockerfile.ci`)

- **Dependencies are baked** into a layer keyed on the lockfiles, so no run
  installs anything and **no run writes a shared npm cache**. That retires
  at the root a corruption class the retired pipeline met: npm's cacache is
  not safe under concurrent writers, and two overlapping installs into one
  shared `~/.npm/_cacache` left an integrity-mismatched entry from which a
  later `npm ci` silently produced an incomplete `node_modules` with exit 0,
  so every suite importing the missing package failed. The interim guard was
  a CI resource group serializing every cache-writing job ("single-writer
  npm cache"); baked dependencies made it unnecessary. A source-only change
  rebuilds only the final `COPY` layer.
- **The agent CLIs are baked** (`claude`, `codex`, `opencode`, `openclaw`,
  pinned in lock-step with `scripts/ci/pins.env`, which
  `scripts/test/ci-pins.test.mjs` checks), so the scripted-model agent suites
  cannot self-skip to green for want of a CLI on PATH, which is how they once
  passed while running nothing.
- **`.git` is in the image** (`Dockerfile.ci.dockerignore` keeps it): the
  dashboard's stale-code check runs `git rev-parse HEAD`, and the launcher
  suites seed a symbolized AgentView worktree of the repository.
- **`private/` is not** (the same file drops it, 2026-10-19): neither the
  build nor a test kind needs it, so the container tests the tree the public
  export holds, and no maintainers' file reaches a layer.
- **A git committer identity is baked** (`Mandu CI <ci@mandu.invalid>`):
  fs-sync's view init commits to the AgentView worktree, and without an
  identity it correctly fails closed (`fs-view init failed (fail-closed):
  Author identity unknown`), which looks like a security failure of the
  launcher's golden path and is purely environmental.
- **python3 and bubblewrap** are installed, for the exec box's clean-box
  runs; with them the container found that the box's bwrap argv emitted
  `--disable-userns` without `--unshare-user`, which bubblewrap ≥ 0.8 rejects
  (`exec-supervisor/src/sandbox.rs bwrap_argv`, fixed).

### 1.4 Credentials: the container is the secret boundary

`docker-run.sh` forwards keys and credentials **only** under an explicit flag,
and its env passthrough is an allowlist of non-secret knobs rather than a bare
`-e NAME`, so a container not meant to have a key provably has none (a CI
system that injects variables into every job would otherwise leave an
"offline" run holding a real key). `scripts/test/docker-run.test.sh` exports
decoy keys and proves they do not reach the container.

- **`--with-claude-auth`** bind-mounts the host's real `~/.claude`
  (read-write) as the container's credential store. The `claude` CLI inside
  is first-party Claude Code, so the subscription authenticates it
  ([`agent-sign-in.md §1`](../agents/agent-sign-in.md) F1/F3); nothing
  hand-rolls an OAuth call (F4/F6/F7). It is a **mount, not a copy**, on
  purpose: OAuth refresh tokens rotate, so two copies are two token lineages
  and the loser goes red at unpredictable times for auth reasons, not
  defense reasons (a copy goes stale the moment either side refreshes). One
  shared store has one lineage and cannot go stale. The cost: the container writes transcripts into the host's
  `~/.claude/projects/` and uses the host's own login. `--with-codex-auth`
  does the same for `~/.codex`.
- **`--with-secrets`** materializes API keys from the central secrets file
  (`scripts/secrets-to-env.mjs --format=env-file`,
  continuous-integration.md §13) into a mode-600 `--env-file`, never as `-e
  KEY=value`, which would expose the secret to `docker inspect` and `ps`. Only
  third-party clients that cannot use the subscription need it.
- **`--with-npm-token`** forwards `$NPM_TOKEN`; **`--out DIR`** bind-mounts
  one host dir at `/repo/release` for a release tarball. Nothing else is
  mounted.

### 1.5 Grouped live runs and the posture guard

A container arbiter's axis posture is fixed at boot, so the retired
pipeline's live battery was grouped by the integrity × confidentiality fold
matrix (confidentiality.md §11/§12): group (i) a few essential scenarios at
the default posture, group (ii) the confidentiality-only scenarios on
conf-ON/int-OFF arbiters, group (iii) every scenario with
`MANDU_CONFIDENTIALITY=1`. The arbiter a run rides is the supervisor's
test-tenant arbiter, whose axes are pinned only by
`MANDU_TEST_CONFIDENTIALITY` / `MANDU_TEST_INTEGRITY`; the container's
entrypoint (today the maintainers' rig's, §2) maps the job's axis env onto
them and routes the suite to the test tenant. Every
grouped run carries an `MANDU_E2E_EXPECT_*` posture guard that probes the
arbiter's `hello()` and FAILS (never skips) on a mismatch, so a fold can
never silently run at the wrong posture. `docker-run.sh` forwards the posture
knobs, and `scripts/test/docker-run.test.sh` asserts the allowlist. (The
integrity axis is frozen; protection-modes.md §10.)

### 1.6 The CI badge (`--publish-events`)

`--publish-events` gives the container a Mandu home at the host home's path
whose `events/` is the host's event dir (bind-mounted, the host's test tenant
mounted where the container's test tenant writes), so the run's sessions land
in the dashboard the user looks at instead of dying with the container. The
host event dir is keyed on the invoking uid's passwd home, not `$HOME`, since
a CI runner may run jobs with a HOME of its own.

When a CI runner and a developer write the same event dir, a pipeline's batch
and a hand-run one are otherwise indistinguishable. The harness therefore
stamps `origin` on every event it emits (`"ci"` from `MANDU_E2E_ORIGIN`, or
the CI system's own `$CI` as a fallback, so a new job that forgets the
variable still gets badged; `tests/lib/live-shared.ts`), the sidebar
rolls it up to the batch, and the group row renders a **`CI`** chip. `origin`
is **orthogonal** to `runtime` (§2), not a third value of it: a CI run is
also a docker run, so it shows both badges; `runtime` answers WHERE it ran,
`origin` WHO ran it. The KVM-guest CI does not publish events
(continuous-integration.md §6), so today only a hand run with
`--publish-events` and `MANDU_E2E_ORIGIN=ci` produces the chip.

### 1.7 The claude pin tracks the host

`CLAUDE_CODE_VERSION` (in `scripts/ci/pins.env`, mirrored in
`Dockerfile.ci`) is bumped to the release developers run once the host lanes
are green on it. The pin is a measurement, never a comfort: two months of
drift once hid a boot-chrome change, the token-budget reminder inside every
untrusted symbol, an auto-allow rule change and the MCP approval dialog, none
of which reached the pinned lane. The host-drift lane `ci.claude-latest`
(`scripts/ci/claude-latest-lane.sh`, test-organization.md §6.5) installs the
current release into a temporary prefix, reports how far the pin lags it, and
runs the claude differential lane against it. `CODEX_VERSION` follows the
same rule; both were last bumped on 2026-10-09, to 2.1.295 and 0.162.0, the
tops of the tested ranges (continuous-integration.md §4).

## 2. The maintainers' e2e rig and the dashboard's Docker mode

The maintainers also keep a containerized rig for their live agent drills:
an image with the real agent CLIs that boots the stack and runs a drill
suite, watchable from the host dashboard. The drills are the maintainers'
evidence tooling and are not published (what they show is in
[`drill-results.md`](../../testing/drill-results.md); for access, for
research for example, write to hello@mandusecurity.com), so the rig is not
published either: an image whose every service runs a missing suite would
only fail.

The dashboard's test panel keeps its **🐳 Docker** checkbox, which runs the
e2e batch inside that rig. In a tree without the rig (this one) it answers
HTTP 412 with "this tree does not include the maintainers' e2e rig" before it
runs any `docker` command (the developer view's `test-docker.ts`,
`dockerRigProblem`); run the e2e batch on the host instead.

What stays visible from the rig is the **runtime badge**: a session the rig
ran carries `runtime: "docker"` on its events (`MANDU_E2E_RUNTIME`, stamped
by `tests/lib/live-shared.ts`), and the dashboard badges the session and its
batch **🐳 docker**; a host run is `"host"`. It answers WHERE a run ran;
`origin` (§1.6) answers WHO ran it.
