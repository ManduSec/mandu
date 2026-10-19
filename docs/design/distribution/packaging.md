# Mandu — Packaging, Distribution & Release (Linux + macOS)

> **Status: BUILT** (M1, M2, M4 and the M5 release mechanics, §8);
> `@mandusec/mandu` goes to npm from `0.2.0-beta.6` (2026-10-19), packed
> from the public tree only (§11.4), and the real-Mac pass is open (§6).
> §11 is the release engineering: one version, one tag, one artifact.
>
> Companion to [`licensing.md`](./licensing.md) (the license),
> [`portable-wrapper.md`](./portable-wrapper.md) (the `mandu` launcher CLI,
> the thing being packaged; its §10 is the darwin/win32 platform status),
> [`privilege-model.md`](../architecture/privilege-model.md) §2 (the
> context → wrapper → kernel layers the install is tiered to), and
> [`runtime-instances.md`](../architecture/runtime-instances.md) §7 (canonical
> process titles, which this package extends to every shipped process).
>
> Decisions (2026-07-12): **npm-first** primary channel; **pure-JS
> runtime** (the arbiter moved off `better-sqlite3` to `node:sqlite`).

## 1. The UX contract

Two lines, total, from a user who already runs Claude Code:

```sh
npm install -g @mandusec/mandu        # one-line install (Node >= 22.13.0)
mandu claude                     # run Claude Code under Mandu
```

- `mandu claude [args…]` passes every remaining arg to the agent verbatim
  (`mandu claude -p "summarize ./notes.md"`). `mandu codex`, `mandu
  openclaw`, `mandu opencode` likewise (the last two are CONFIG-routed:
  the launcher generates a per-run config file merging the user's own;
  agent-e2e-harness.md §9). The first non-flag token starts the agent argv
  (`parse.ts`); a bare `--` still disambiguates. Any OTHER program name
  REFUSES with a pointer to `--target claude|codex|openclaw|opencode|goose`: the
  launcher never guesses an agent, because a wrong guess launches every
  layer while the agent talks to the real endpoint unprotected.
- Everything auto-starts on first run: arbiter, context proxy, net-proxy,
  fs-view worktree, exec shims (exec-wrap + the exec-box boxed set), the
  whole-agent landlock-net TCP confine, reply-filter, the inspect-mcp config
  (scope run dir, `--mcp-config`), all **on by default**, each probe-gated
  and degrading with a warning where the host lacks it (exec-routing.md §7;
  portable-wrapper.md §2.1).
- **The launch directory** (2026-10-07, `launch-cwd.ts`): a launch is for
  the folder `mandu` runs in, the process's REAL working directory
  (`process.cwd()`, the kernel's view), never for `$PWD` alone. A program
  that `chdir`s without exporting PWD (Python's `subprocess.run(cwd=…)`,
  `env -i`, a non-shell parent) leaves a PWD naming another folder; the
  launcher used to take it, and then ran the agent, confined it, twinned
  and scanned for secrets in that other folder. `$PWD` is kept only as the
  human's spelling of the same folder (a shell's logical path through a
  symlink, e.g. macOS `/tmp` for `/private/tmp`, or a symlinked home): it
  is accepted when it is an absolute, normal path naming the same device
  and inode as the real cwd, and ignored silently otherwise. The plan's
  `cwd` and `humanCwd` both start as that directory; every scan and
  settings read of the launch (twin prefetch, secret discovery, the launch
  suggestions, Claude's and Codex's settings) is for its physical path, and
  the agent's `PWD` is the directory it is spawned in (`plan.cwd`: the
  launch directory, or its AgentView). A cwd that no longer exists refuses
  the launch with a plain message. `mandu why`, `mandu doctor` and `mandu
  revert` already read `process.cwd()` and never `$PWD`. Tests:
  `launcher/test/unit/launch-cwd.test.ts`,
  `launcher/test/component/launch-cwd.test.ts`,
  `tests/sandbox/launcher/launch-cwd-pwd.test.ts`. An in-process test names
  the launch's folder explicitly (`main(argv, env, { cwd })`, through
  `launcher/test/lib/launch-in-dir.ts`).
- Optional zero-thought mode: `mandu alias` prints (or installs) an
  `alias claude="mandu claude"` line so `claude` itself is always gated.
- Prerequisites: Node ≥ 22.13.0 (checked at install and at launch with a
  plain-language error), `git` (fs-view worktrees; degrades loudly to
  raw-CWD without it), and the agent binary itself (`claude`, also used by
  inspect-mcp's U-LLM path via `claude -p`,
  [agent-sign-in.md](../agents/agent-sign-in.md) §1).

## 2. What the package ships: the process inventory

The wrapper layer is TypeScript with almost no runtime deps (`js-yaml`). The
shipped package is ONE npm package containing the launcher plus one bundled
single-file entry per service. Every process carries a canonical `ps` title
(runtime-instances.md §7):

| Process (ps title) | Source entry | Lifecycle |
|---|---|---|
| `mandu-arbiter` | `arbiter/ipc/server-main.ts` | resident, shared, start-or-attach |
| `mandu-anthropic-proxy` | `interceptors/anthropic-proxy/src/server-main.ts` | resident, start-or-reuse (identity-probed) |
| `mandu-openai-proxy` | `interceptors/openai-proxy/src/server-main.ts` | resident, start-or-reuse |
| `mandu-net-proxy` | `interceptors/net-proxy/src/server-main.ts` | resident, start-or-reuse |
| `mandu-inspect-mcp` | `interceptors/inspect-mcp/src/server-main.ts` | spawned by the agent via `--mcp-config <scope run dir>/mcp.json` |
| `mandu-dashboard` | `dashboard/src/server-main.ts` | resident, via `mandu dashboard` (§5) |
| `mandu-policy-classifier` | `interceptors/inspect-mcp/src/classify-main.ts` (`dist/policy-classifier.mjs`) | one-shot, spawned by the arbiter per names-only model run from its `--classifier` argv (confidentiality-plan-14 §14.10) |
| `mandu` (launcher) | `launcher/src/run.ts` | per session, parent of the agent tree |
| `mandu-reply-filter` | `interceptors/reply-filter/src/run.ts` (+ `script(1)` PTY child) | per session |
| `mandu-fs-watch` | `fs-sync/src/fs-sync-cli.ts watch` | per session (eager mode) |
| `mandu-fs-cli` | `fs-sync/src/fs-sync-cli.ts init/sweep` | one-shot |
| `mandu-exec-shim` | `interceptors/exec-wrap/src/wrap.ts` | transient, per intercepted command |
| *(the agent)* `claude` / `codex` | — | child of the launcher, keeps its own name |

From the bundle (§5) each service is a **single** node process carrying its
title (in a dev checkout, tsx adds an anonymous wrapper parent), so `ps`,
`pgrep -f mandu-`, teardown, and `mandu status` stay simple and strict.

## 3. Distribution shape: npm-first (decided)

**Primary: npm.** The target user has Node: Claude Code is itself
`npm install -g @anthropic-ai/claude-code`. A bundled npm package is the
zero-new-prerequisites channel and matches the audience's habits.

- `npm install -g @mandusec/mandu` → global `mandu` bin. `npx @mandusec/mandu
  claude` works for try-before-install.
- **`curl | sh` and Homebrew** (BUILT 2026-09-25) wrap the same npm artifact.
  `scripts/install.sh` (POSIX sh, no sudo): uses the Node on PATH when it
  meets `NODE_FLOOR`, else downloads the pinned `NODE_PIN` from nodejs.org
  into `~/.local/share/mandu/node`, SHA-256 checked against the release's
  `SHASUMS256.txt` (a mismatch installs nothing); installs the package into
  its own npm prefix (`~/.local/share/mandu/pkg`); writes
  `~/.local/bin/mandu` as a wrapper that runs it with that Node, falling
  back to the node on PATH if that Node is later gone (an `nvm uninstall`),
  and exiting 127 with what to do when there is no Node at all.
  `--dry-run`, `--package <spec|tgz|url>`, `--prefix`, `--bin-dir`,
  `--node-version`, `MANDU_NODE_MIRROR`. Refuses root. Tests:
  `launcher/test/unit/install-sh.test.ts` (offline: stub Node on PATH, a
  `file://` Node mirror, checksum mismatch, floor refusal, POSIX parse, the
  wrapper's fallback when its Node disappears) and
  `launcher/test/component/install-sh.test.ts` (the real `npm pack` tarball
  installed and run); `node-floor.test.ts` pins its floor and pin.
  `packaging/homebrew/mandu.rb` depends on `node@22`; its `url`/`sha256`
  are placeholders until the first public release (marked TODO), and
  `scripts/set-version.sh` stamps its version.
- **Docker stays what it is**: a test environment (`packaging/docker/Dockerfile.ci`,
  docker-e2e.md), not a product artifact. A container is the wrong shape for
  wrapping the *user's local* claude with its login state and workspace.
- **Kernel-layer packaging is out** (§9): the npm package is the wrapper
  layer plus the three unprivileged native bins (§5), and says so
  (`mandu doctor`, §7).

**The publish gate.** The license is decided (`licensing.md`:
Apache-2.0 since 2026-10-09, open-core line in its §6); the root
`LICENSE`, `NOTICE` and per-package fields are in the tree and the npm bundle
ships `launcher/LICENSE` (npm always includes it) and `launcher/NOTICE`
(listed in `files`); the npm-pack e2e asserts both. Every package is
`private: true` in Mandu Security's source repository, the one the public
repository is exported from; the export drops it from `launcher/package.json`
only (the M5 unlock, §8, §11.4), so a tarball packed in the source repository,
whose bundle can carry a module the public tree leaves out, is refused by
npm, and the publishable one is packed from the public tree.

## 4. Pure-JS runtime: `better-sqlite3` → `node:sqlite` (decided)

`better-sqlite3` was the repo's ONLY native addon (arbiter: `symbol-table/`,
`provenance/provenance-store.ts`, `policy/egress-approvals.ts`). Native
addons are the most common npm first-run failure class: prebuilds cover
common platforms until they don't (a fresh Node major before prebuilds
publish, musl/Alpine, ABI mismatch after a user upgrades Node) and then
`npm install` falls back to node-gyp and demands a C toolchain, the worst
possible first contact.

The API surface used is small and fully covered by Node's built-in
`node:sqlite` (`DatabaseSync`): `prepare/run/get/all`, `exec`,
`pragma("journal_mode = WAL")` → `exec("PRAGMA …")`, `pragma("table_info…")`
→ `prepare(…).all()`, and `db.transaction(fn)` → an explicit
`BEGIN/COMMIT/ROLLBACK` helper.

Consequences: the shipped package has **zero native npm deps and zero
postinstall scripts**: one universal JavaScript artifact for linux/darwin ×
x64/arm64; install cannot fail on compilation. Cost: the Node ≥ 22.13 floor
(`node:sqlite` is unflagged from 22.13), enforced via `engines` + a
launch-time check with a clear message (§10.2).

**Status (landed):** a thin `better-sqlite3`-shaped adapter
(`arbiter/db/sqlite.ts`) over `DatabaseSync`; the three consumers changed by
one import line each. Multiple simultaneous connections to the one arbiter DB
file in one process (provenance + egress long-lived, symbol-table transient)
round-trip with correct cross-connection visibility and atomic
`INSERT OR IGNORE` (§10.3). `better-sqlite3` is gone from every package; the
repo has zero native addons. The one-time `node:sqlite`
`ExperimentalWarning` at daemon startup is suppressed at the service spawn
(`--no-warnings=ExperimentalWarning`).

## 5. The bundle: mechanics

- **esbuild** each §2 entry into a single-file `dist/<service>.mjs` inside
  `@mandusec/mandu` (deps inlined; all pure-JS after §4). No tsx, no
  per-package `node_modules`, no `npm run serve` at runtime.
- A **layout resolver** with two modes: `installed` (`dist/` inside the
  package, spawn `node dist/<svc>.mjs`) and dev (auto-detected inside the
  repo). A checkout runs its own `launcher/dist` while that build matches the
  source and tsx over `src/` otherwise (§5.1); a stale build is rebuilt on
  demand, so the dev flow still has no manual build step. The shipped flow is
  what the bundle tests run.
- Spawns are direct `node` children, not `npm run serve` chains. A worker
  thread is started from source text (`new Worker(src, { eval: true })`,
  the git-object twins' seal hashes, `launcher/src/file-hashes.ts`), never
  from a file path, so the bundle stays one file per entry; the worker's
  function takes its modules as parameters, so minifying keeps it whole.
- **Tests:** the bundle is tested as `dist/` (test is source, subject is
  `dist/`), and `npm pack` + install-into-tmp + run is a test (below).

**The pipeline.** `launcher/scripts/build-bundle.mjs` esbuilds every entry in
`launcher/bundle-manifest.json` (the single source of truth the resolver also
reads) into `launcher/dist/<name>.mjs`: ESM, `platform:node`, `node:*` (incl.
`node:sqlite`) external, everything else inlined (js-yaml is the only runtime
dep); `npm run build:bundle` in the launcher. The arbiter IPC **client** is
bundled separately (`arbiter-client.mjs`) because the interceptor, dashboard
and fs-sync entries load it through a runtime-computed `import()` (the
`[...].join("/")` trick that keeps each package's standalone typecheck from
dragging `arbiter/**.ts` into its rootDir); esbuild cannot inline a computed
specifier, and the relative path breaks once relocated to `dist/`. Each site
reads a `MANDU_ARBITER_CLIENT_MODULE` env override, set by the installed-mode
resolver to the co-located `dist/arbiter-client.mjs` and unset in dev and
tests (the relative source path). The arbiter's secret-discovery worker
thread is a module too (`dist/secret-discovery-worker.mjs`), started from
beside the bundled arbiter (`runtime-instances.md §14` §2 item 7). Verified by
`launcher/test/component/bundle-smoke.test.ts` (the §10.1 anti-drift oracle):
the bundled arbiter boots and walks on its worker, and the bundled client
round-trips symbolize → desymbolize over IPC; every bundle loads and reports
`ready` in a simulated installed-mode boot.

**Static directories.** The manifest's `assetDirs` copies the product page
whole into `dist/dashboard/public`, and the build fails if it lacks an
`index.html`. The server finds it with `resolveStaticDir`: `../public` from
source, else `./dashboard/public` beside the bundled `dashboard.mjs`.

**The developer view is optional (2026-10-15, dashboard.md §4.25ac).** The
manifest's `optionalModules` (`dashboard-dev`: the inspector's module) and
`optionalAssetDirs` (its pages, `dist/dashboard/dev`) are built and copied when
their source exists, and skipped with a note when it does not. A skipped
directory's old copy is removed. The bundled `dashboard.mjs` loads
`dist/dashboard-dev.mjs` when it is there (`extension-loader.ts`), and the
module finds its pages the way the server finds the product's.

A build from the public tree has neither, so the package it makes serves the
product page only: `/dev/` answers 404, with a page saying the developer
view is not included and is available on request (dashboard.md §4.25ac),
and the product page shows no link into it. `bundle-smoke.test.ts` pins the product page, and the developer
view exactly when its source is in the tree.

**Static files.** The manifest's `assets` are copied byte for byte to
`dist/<key>` and resolved by `Layout.asset()` (the checkout's source file in
a checkout): the AppArmor profile, the SDK route's Node preload, and (since
2026-10-07) the reference prompt classifier with its pack writer,
`dist/prompt-filters/local-classifier.mjs` and `local-classifier-pack.mjs`,
which `mandu policy classifier-pack` runs (confidentiality-plan-15 §13.5
item 15). They are plain node programs with no import beyond node's
built-ins, so they run unbundled. `bundle-smoke.test.ts` runs the built
package's `mandu policy classifier-pack` and the shipped classifier.

**The layout resolver** (`launcher/src/services/layout.ts`) is a mode-aware
object threaded through every `services/*.ts`. `Layout.detect(import.meta.url)`
picks **installed** (the launcher runs from an installed package's `dist/`:
`node dist/<svc>.mjs` + `MANDU_ARBITER_CLIENT_MODULE`) or **dev**, in the
form the launcher itself runs in (§5.1): *bundled* when it runs from the
checkout's own `launcher/dist` (the services run from that same `dist/`,
exactly as installed), *source* when it runs from `src/` via tsx (each
service is `node --import <the package's tsx ESM entry> <entry.ts>`, one node
process; the daemons no longer start as `npm run serve`, which put npm, sh and
the tsx binary's own node in front of each one, about a second per daemon on
the launch's critical path). `MANDU_LAYOUT` / `MANDU_DEV_REPO` force it
(`MANDU_DEV_REPO` always selects the source form: another tree's services are
not in this build). `SERVICE_SOURCES` mirrors the manifest's `services`
(`layout.test.ts` holds them equal). It is wired through arbiter start, context-proxy,
net-proxy, mcp-config, fs-view (one-shot + eager watch), and exec-shims.
Installed mode is proven by `layout.test.ts` (the dev/installed spec matrix +
`detect`) and `installed-spawn.test.ts` (the REAL `startContextProxy` driven
through `Layout.installed()` spawns the bundled proxy, which loads the
bundled client, reaches the bundled arbiter, and publishes a matching
identity).

**The source form never runs the tsx BINARY.** The package-local
`node_modules/.bin/tsx` re-spawns node with a CJS `--require <preflight.cjs>`,
and a CJS preload makes node parse the CWD's `package.json`. A helper that
inherits the agent's cwd (the reply filter, the exec-wrap shim, inspect-mcp)
would therefore die with `ERR_INVALID_PACKAGE_CONFIG` in any workspace whose
AgentView `package.json` is a whole-file symbol twin. `Layout` spawns
`node --import <file URL of the package's tsx/dist/esm/index.mjs> <entry.ts>`
for every service and helper it runs from source (`devTsx`), which registers
the same hooks and resolves
nothing from the cwd (`launcher/test/unit/layout.test.ts` pins the tokens and
the regression end to end). The installed layout's bundles are unaffected.
The bootstrap shim (`scripts/bootstrap.sh`) hands off to
`launcher/mandu-run.sh`, so a shim launch loads `secrets.local.json` like a
direct one.

**Native bins in the bundle.** `bundle-manifest.json` `native` lists the three
Rust supervisor bins (`mandu-net-guard`, `mandu-exec-box`,
`mandu-landlock-apply`). `build-bundle.mjs` copies each one that is built,
from `$MANDU_NATIVE_BIN_DIR` (default `interceptors/target/release`), into
`dist/native/<platform>-<arch>/<name>`, `strip`ped (a release bin is ~14 MB
with symbols, ~0.8 MB without), mode 0755; a bin that is not built is a note
in the pack log, never a failure. `services/native-bins.ts` resolves
`dist/native/<tag>/<name>` right after the env override and before the
checkout's `target/` and PATH, only when the launcher itself runs from an
installed `dist/` (a checkout's own `dist/` keeps resolving `target/`, §5.1). Consequence: an `npm install -g @mandusec/mandu` on linux-x64 runs the
whole-agent connect/open guard, the exec box and the Landlock applier with no
Rust toolchain, and, since the guard alone serves the secret twins by
descriptor (confidentiality-plan-10 §11.7), a stock Ubuntu 24.04 launches
`confined` with no sudo (rootless-confinement-ubuntu-2404.md §11). The bins
are linked only against libc and libgcc, so a bin built on 24.04 runs on
24.04 and later; other platforms and architectures get the layout-aware hint
("this package has no prebuilt … for darwin-arm64") instead of a `cargo
build` in a directory they do not have. The package is ~4 MB.

**linux-arm64 in the same tarball.** One package serves every CPU:
`dist/native/` holds a directory per shipped tag, `linux-x64` and
`linux-arm64`, and the launcher's own `process.platform-process.arch` picks
(`nativePlatformTag`). The Node side needs nothing: the bundle has no native
npm deps (§4). The tag table is `launcher/scripts/native-targets.mjs` (tag →
rust triple, ELF machine, strip tool). `build-bundle.mjs` reads
`$MANDU_NATIVE_BIN_DIRS` (`linux-x64=<dir>,linux-arm64=<dir>`) when set, else
the host tag from `$MANDU_NATIVE_BIN_DIR` / `target/release`, and **refuses**
a bin whose ELF machine is not its tag's (an x64 bin under `linux-arm64` would
fail every exec with ENOEXEC while looking shipped). A cross copy is stripped
with its own `aarch64-linux-gnu-strip` or `llvm-strip`, never the host's
`strip`. `scripts/build-native.sh --target aarch64-unknown-linux-gnu`
cross-builds into `target/<triple>/release/` (needs the rust target and
`aarch64-linux-gnu-gcc`; the CI guest image carries both,
`scripts/ci/guest/provision.sh`, §11.3). The installer's `uname -m` →
`x64`/`arm64` mapping picks the Node download and reports whether the package
has this CPU's helpers; other CPUs are refused by name. The installed hint
lists the tags the package actually carries (`shippedNativeTags`). **Built,
not run on arm64 hardware:** release-pack starts each arm64 bin under
qemu-user (it links and runs on an arm64 userland), and the Rust unit suites
pass under `qemu-aarch64`; the seccomp and Landlock attachment has never run
on an arm64 kernel. The net-guard's open family is arch-selected
(`secret_open::open_nrs`; aarch64 has no `SYS_open`), and the typecheck job
`cargo check`s the tree for aarch64 on every push.

**Management verbs and the pack test.** `mandu status` / `stop` /
`dashboard` / `reap` (`subcommands.ts`) are dispatched from `run.ts` in the
bare form only (`mandu -- status` still launches a program named "status").
`stop` targets resident daemons by default, `--all` includes launchers; both
SKIP container-scoped pids (a CI/docker-e2e stack runs under this uid with
host-visible pids, and `/proc/<pid>/cgroup` marks that its lifecycle belongs
to the container's `--rm --init`), and neither targets `mandu-inspect-mcp`,
a per-session MCP child that dies with its owning agent. `dashboard`
start-or-attaches and prints the URL; `reap [--dry-run]` garbage-collects the
instance registry (runtime-instances.md §10). The reply filter is wired into
the TS launcher (`reply-filter.ts` / `applyReplyFilter`: default-on, the
first process of the agent's chain, the security wrappers and the agent
below it; started early and handed the agent at the end, §5.3;
`--no-reply-filter` / `MANDU_REPLY_FILTER=0` opts out; utility-only,
degrading to no wrapper if its runtime is missing; off for `goose acp`,
whose stdout is a JSON-RPC stream the launcher relays itself and
desymbolizes field by field, supported-agents.md §5.6 and
reply-row-reservation.md §15.4). The **bin**
(`bin/mandu.mjs`) runs `dist/mandu.mjs`'s `main()` with plain node, so the
bundle's `Layout.detect` sees it under `dist/` → installed mode (or, in a
checkout, the dev layout's bundled form, §5.1); `engines`
`node >=22.13.0`; `prepack` builds the bundles; `files` ships `dist/` +
`bin/` only. The **`npm pack` test** (`npm-pack.test.ts`) packs, installs the
tarball into a throwaway dir, and runs the installed `mandu` with **plain
node**: the dependency install pulls no tsx, so a working run proves `npm
install -g @mandusec/mandu` needs neither a repo checkout nor tsx nor a native
build. The bundle-boot tests and the two pack tests (`npm-pack`,
`install-sh`) build into a private dir: a plain `npm pack` in `launcher/`
runs `prepack`, which wipes and rebuilds `dist/`, so two at once would pack
a half-rebuilt bundle. `test/lib/pack-private.ts` stages `package.json`, the
always-shipped files and the non-`dist` `files` entries, runs `prepack`'s
build into the stage (`--outdir`), and packs the stage with
`--ignore-scripts`; the tarball's file list matches a real `npm pack`, and
the helper refuses to run if `prepack` changes without it. Open: a fuller
wrapper-parity matrix axis run against `dist`. The build record and the build
lock (§5.1) are left out of the tarball (`!dist/.bundle-stamp.json`,
`!dist/.build.lock` in `files`; `npm-pack.test.ts` pins it).

### 5.1 A checkout runs its own build while it is fresh

Running the launcher and its services from TypeScript costs a transpile per
process on every launch: on the development host (2026-10-04, loaded) the
launcher's own tsx load was about 1.3 s, each per-session daemon (context
proxy, egress proxy) about 2 s through `npm run serve`, and the reply filter
and the exec-wrap shim's load probe about 1 s each. The bundle the npm package
ships has none of it, so a checkout runs that bundle too, under one rule: **a
stale bundle never runs.**

- **The build record.** `build-bundle.mjs` ends a clean build by writing
  `dist/.bundle-stamp.json` (`launcher/scripts/bundle-stamp.mjs`): every file
  the bundles were built from, taken from esbuild's own metafile inputs (so
  the list is exact: the launcher's source and every other package's source
  it inlines, js-yaml included), plus what shapes the build without being an
  input (each source package's `package.json` and `tsconfig.json`, each
  `node_modules` tree's `.package-lock.json`, which npm rewrites on every
  install while it backdates the files it extracts, and the build's own
  scripts and manifest), each with its mtime and size, and each output's mtime
  and size. The build removes the record when it starts and writes it only if
  no input changed while it ran (an input whose mtime is not older than the
  build's start, read from the filesystem's own clock, may have been read
  before its edit), so an interrupted, failed or raced build is never taken as
  fresh.
- **The check.** `checkStamp` (`scripts/bundle-stamp.mjs`; on the command
  line `node scripts/bundle-stamp.mjs --root=<repo> <dist>`, exit 0 when
  fresh) calls the bundle fresh only when the record names this repo and
  every recorded input and output still has its mtime and size; a missing
  record, a changed, resized or deleted input, and a missing or replaced
  output are all stale. It stats about 630 files, a few milliseconds.
- **The shim** (`launcher/mandu-run.sh`, which `scripts/bootstrap.sh`'s
  `mandu` execs): in a checkout, a fresh bundle runs through `bin/mandu.mjs`;
  a stale one is rebuilt first (`build-bundle.mjs --if-stale --no-native
  --quiet`, about 0.5 to 0.8 s) and checked again; if it still is not fresh
  (a build error, an edit during the build), the launcher runs from source
  through tsx and says so. `MANDU_FROM_SOURCE=1` forces the source path with
  no build. An installed package (no `src/`, no tsx) runs its bundle as
  before.
- **One node before the launcher: its own** (2026-10-16). The shim used to
  start two node processes before the launcher's: `source
  scripts/mandu-env.sh`, which ran `node scripts/secrets-to-env.mjs` and
  eval'd its exports (the secrets file, continuous-integration.md §13), and
  `node bundle-stamp.mjs` for the check. On the development host a node
  start costs 0.1 to 0.2 s (the distribution's node 22), so each was about
  0.2 s of every launch. In a checkout the shim now starts no node of its
  own: it execs `node bin/mandu.mjs` with `MANDU_SHIM_CHECKOUT=<repo root>`,
  and `bin/mandu.mjs` runs the checkout prelude
  (`scripts/checkout-launch.mjs`) before it imports the bundle. The prelude
  removes the variable (it never reaches the launcher or the agent), then
  1. loads the secrets file into its own `process.env` with
     `applySecretsEnv` (`scripts/secrets-to-env.mjs`): the same computation
     the CLI prints as `export` lines, so the same variables with the same
     values; a variable already set non-empty is never overridden; the
     informational lines print only for a verbose launch (`--verbose`
     before any `--`, or `MANDU_VERBOSE`), the shim's rule; a name the
     shell's `export` would refuse is skipped and a NUL byte dropped, as the
     shell did; best effort: an error is one `[mandu-secrets]` line and the
     launch goes on. The env-masking step (`applyEnvSecrets`) therefore sees
     exactly the variables it saw before;
  2. runs `checkStamp`; when stale, runs the rebuild as a child (its output
     on stderr) and checks again; when still stale, prints the shim's
     warning and replaces itself with tsx over the source
     (`process.execve`, node 22.15 and later, as the shim's `exec` did; on
     an older node, a child that holds the terminal, gets SIGTERM and SIGHUP
     relayed, and whose exit it mirrors). A stale bundle never runs.

  The source path (`MANDU_FROM_SOURCE=1`) and an installed package still
  source `mandu-env.sh` in the shim, as do the harnesses that source it
  themselves (`eval/agentdojo/run.sh`, the test runner's api-key lane);
  only the bundled checkout launch changed. Measured on the development
  host (2026-10-16, a 128-core host at a load of 74 to 94, `mandu claude
  --version` from a non-git directory against a private arbiter, medians of
  eleven interleaved runs): the whole launch went from 1.66 s to 1.36 s;
  from the exec of the shim to the launcher's bundle being opened (strace,
  which slows every process start, medians of nine) from 0.51 s to 0.20 s.
- **The services follow the launcher.** `Layout.detect` calls a `dist/`
  beside `src/run.ts` a checkout's build (`isCheckoutBuild`): dev layout,
  bundled. Every per-session service (arbiter, context and egress proxies,
  reply filter, exec-wrap shims and their load probe, fs-sync, inspect-mcp,
  policy-mcp, the policy classifier) then runs from the same `dist/`, the
  snapshot the launch just checked. The resident dashboard follows too
  (since 2026-10-04): `dashboard/src/server-main.ts` reads a `dist/` beside
  `src/run.ts` as a checkout's build, not an installed package, so it keeps
  the dev layout (the repo root two levels up, the checkout's supervisor
  definitions) and serves the checkout's own `dashboard/public` and, through
  the developer view's bundled module, the developer view's pages rather than the
  copies its build took
  (`server.ts resolveStaticDir`; the build record does not cover those
  files). A launcher run through tsx runs every service from source (`node
  --import <tsx>`), so `MANDU_FROM_SOURCE=1` is a whole-launch switch.
- **The dashboard's supervisor and `dev-arbiter.sh` apply the same rule
  per start.** The dashboard outlives builds, so its supervisor
  (`dashboard/src/supervisor/`) asks again at every spawn, a restart
  included: each checkout definition is the source form (`node --import
  <the package's tsx> <entry.ts>`, one process) and carries its bundled
  form (`checkoutBundle`: `node <repo>/launcher/dist/<name>.mjs`, cwd
  `launcher/`, the proxies pointed at `dist/arbiter-client.mjs`), and the
  bundled form runs only when the launcher's own check
  (`bundle-stamp.mjs checkStamp`, loaded from the checkout at run time; any
  error reads as stale) calls the build fresh. The log says which form ran
  and, for the source, why. `scripts/dev-arbiter.sh` does the same with the
  CLI check (`MANDU_FROM_SOURCE=1` forces the source; `$WORK/form` records
  the choice). Neither builds: a stale bundle runs the source, it is never
  run itself. The arbiter, the proxies and the test arbiter no longer start
  through `npm run serve`, so each is one node process leading its own
  process group: `kill <pid>` now ends the daemon, and the supervisor's and
  `dev-arbiter.sh stop`'s group kills are unchanged. Measured on the
  development host (medians of five, time to listening): a proxy took about
  1.35 s through `npm run serve`, 0.6 s as one tsx process and 0.2 s from
  the bundle; `dev-arbiter.sh` took about 2.8 s and now about 1.3 s either
  way (four processes became one; the arbiter's own start-up is what is
  left); the resident dashboard listens after about 0.2 s from the bundle
  against 0.75 s from source.
- **The arbiter's policy classifier follows its arbiter** (2026-10-09). The
  supervised arbiter runs inspect-mcp's `classify-main` once per model run
  from its `--classifier` argv. Until now that argv was the source through
  inspect-mcp's tsx in every checkout, even behind an arbiter started from
  the bundle. Each form now carries its own (`arbiterClassifierArgs`
  `checkoutDist`): the bundled arbiter is given `node
  <launcher/dist>/policy-classifier.mjs` from the build whose record the
  supervisor just checked, and the source arbiter keeps tsx and the source.
  A build without the classifier bundle falls back to the source form. The
  launcher's own per-launch arbiter already took it from
  `Layout.policyClassifier`, so this was the supervisor's gap only. The
  inspect-mcp stdio server an agent starts already followed the launch
  (`Layout.inspectMcp`). Measured on the development host (medians of nine
  interleaved runs on a loaded host, 128 cores at a load of about 35): the
  classifier answering one `describe` request, spawn to exit, took 326 ms
  from source and 141 ms from the bundle; the inspect-mcp server answering
  `initialize` took 335 ms and 137 ms. Each model run saves about 0.2 s of
  start, and the start no longer reads inspect-mcp's `node_modules`. Tested
  by `arbiter-classifier-args.test.ts` (the argv per form, the fallback, the
  same tail otherwise), `tests/stack/supervisor-checkout-bundle.test.ts`
  (the arbiter from a private build is given the build's classifier, and a
  names-only run through it reaches the policy's declared mock model) and
  `tests/stack/ullm-quarantine-stdio.test.ts` (the inspect_symbol quarantine
  oracle and its fail-closed starts, from source and from a private build's
  `inspect-mcp.mjs`).
- **Native bins** stay where a checkout builds them: `native-bins.ts` treats a
  checkout's `dist/` as not installed, so it never serves a `dist/native` copy
  as old as the last full build (with no `.d` for the staleness check); the
  rebuild skips copying them (`--no-native`).
- **Safe under live sessions.** A rebuild never removes `dist/`: each bundle
  is written to a temp name and renamed over the old one (a running session's
  next exec-wrap shim call sees the old file or the new one, never a missing
  or partial one), entries the manifest dropped are pruned at the end, and
  builds are serialized by `dist/.build.lock` (created exclusively, holding
  the builder's pid; a dead holder's lock is broken). `--if-stale` checks the
  record again after taking the lock, so two launches that both found the
  bundle stale build it once. As with the source path, a session that is
  already running picks up the new code at its next helper start.
- **Keeping it warm.** `scripts/bootstrap.sh` builds the bundle on setup, and
  the main checkout's update step rebuilds it after a fast-forward, so the
  first launch after either does not pay for the build.

Same code, same decisions: the bundle is the source, prebuilt. Nothing on the
security path changes, and every fail-closed rule is the source's own.
Measured on the development host from a non-git directory (`mandu claude
--version`, no native bins, the git-history step excluded since it is the
same in both; medians of four interleaved runs on a loaded host): about 4.8 s
before, 2.5 s after (1.7 s on a quieter run), with the services up at about
1.5 s instead of 3.5 s. `MANDU_FROM_SOURCE=1` (tsx, but each daemon one node
process instead of `npm run serve`) sits between, at about 4.0 s. Tested by `test/unit/bundle-stamp.test.ts` (the
record and the check), `test/component/bundle-freshness.test.ts` (the real
shim's and prelude's decision in a stand-in checkout, one node process for a
fresh launch, the execve and child fallbacks, the hand-off variable never
reaching the launcher; the real build, its record, `--if-stale` and the
lock), `test/unit/checkout-launch.test.ts` (the verbose rule, the best-effort
load, a broken record read as stale), `tests/stack/shim-secrets-env.test.ts`
(the launcher's environment equals the old shell path's, set, unset,
pre-set, pre-set-empty and refused names, no file, `MANDU_SECRETS_FILE=0`,
the same `[mandu-secrets]` lines; then the real `applyEnvSecrets` over a
real arbiter masks the same variables from either, and a token from the file
reaches the agent only as a placeholder), `scripts/test/secrets-to-env.test.mjs`
(`applySecretsEnv` against the CLI's export lines) and
`test/unit/layout.test.ts` (the bundled and source spawn
forms, `detect` over a checkout's `dist/`); the supervisor's choice by
`dashboard/test/unit/supervisor/supervisor-checkout-bundle.test.ts` (asked at
every spawn, the stale case, the real record check) and
`supervisor-defs-installed.test.ts` (the two forms), the real services from a
private build by `tests/stack/supervisor-checkout-bundle.test.ts` (fresh: the
arbiter and proxies start from it and serve; stale: the restart runs the
source; every pid reaped; the dashboard bundle knows a checkout's build), and
`dev-arbiter.sh` by `scripts/test/dev-arbiter.test.sh` (fresh, stale and
forced forms; one process; the stop).

### 5.2 A git worktree uses its main checkout's native bins when they are built from its own sources (2026-10-04)

A checkout resolves its native bins from its own `interceptors/target/`
(`native-bins.ts`). A git worktree made for a change that does not touch the
native crates has none, and building them takes minutes, so its launches ran
gated. A gated launch is unconfined, and while any unconfined launch runs the
arbiter honours no git-history cache seal for anyone (plan 14 §11.2): every
launch on the machine rebuilt its sanitized packs, several seconds each on
the Mandu repository. So a worktree with no bins of its own now uses its main
checkout's, under one rule: **a bin is used only when it was built from
exactly this worktree's native sources**, never because it exists.

- **The record.** `scripts/build-native.sh` ends a host build by running
  `scripts/native-provenance.mjs record`, which writes
  `<bin>.provenance.json` beside each bin: the bin's sha256 and size, and the
  sha256 of every file cargo's dep-info (`<bin>.d`) says it was compiled
  from, plus the workspace `Cargo.toml` and `Cargo.lock`, each crate's
  `Cargo.toml` and `build.rs`, and the cargo config and toolchain files (an
  absent one recorded as absent). It writes none (and removes an older one)
  when a dep-info source lies outside `interceptors/` or changed after the bin
  was built (cargo's own staleness rule), so a record never claims sources a
  bin was not built from. A plain `cargo build` writes no record.
- **The check** (`launcher/src/services/native-provenance.ts`). After the
  worktree's own `target/release` and `target/debug`, and before the PATH
  lookup, the launcher finds the main checkout from git's own files (`.git`:
  `gitdir:`, then `commondir`; no git process) and takes its
  `interceptors/target/{release,debug}/<bin>` only when the record is of the
  expected shape, the bin still hashes to it, and every recorded source
  hashes the same under the worktree's `interceptors/` (an absent one is
  absent there too). One byte of difference, a bin rebuilt since, no record,
  or a record naming a path outside the directory refuses it. Hashing costs
  tens of milliseconds and is done once per bin per launch. An installed
  package never takes this step.
- **Refused, said.** The worktree's launch then runs as before (gated, with
  each missing bin's degrade line), and the build hint names the refused bin,
  the reason, and the fix: "run scripts/build-native.sh in this worktree to
  launch confined".
- **The staleness warning** (§5's freshness check by mtime) is skipped for a
  bin taken this way: the record proved it is exactly what the worktree's
  sources build, whatever the main checkout's sources have done since.
- **Trust.** The record, the bins and the checkout's own `target/` belong to
  the same user, and the launcher has always run a checkout's own bins on
  sight; the record adds no new principal, it only refuses a bin of another
  source tree. A same-user writer that swaps the bin after the check could
  swap the worktree's own bins as well (plan 14 §11.2 S3's line).

Tested by `launcher/test/unit/native-provenance.test.ts` (the writer and the
check over a real main checkout and `git worktree add`: every refusal, the
precedence, the hint) and the kernel-lane
`tests/sandbox/unconfined-launch-notice.test.ts` W1 (the worktree's own
launcher bundle, launched for real: confined with matching bins; one source
byte changed, refused, gated, the hint printed, and its end voids the seals).

### 5.3 The reply filter starts with the services

The reply filter used to start serially, as the first token of the agent's
command: its node start and module load (about 0.26 s from the bundle, about
1 s from source) sat on the launch's critical path after everything else was
ready. It now starts early and is handed the agent at the end.

- **The start.** Right after the launch is parsed (before the arbiter check
  and the services), the launcher spawns `reply-filter
  --mandu-handoff-fd=3` (`prestartReplyFilter`): the real terminal on fds
  0 to 2, as the serial form had it, and a socket pair on fd 3; `detached`
  is the scope plan's (its two probes are asked once per launch, so the
  early plan and the final one agree). The process loads its modules, warms
  the import of the arbiter client (no connection) and waits on fd 3. Before
  the hand-off it reads no terminal, writes nothing and connects to nothing.
  Under `--verbose` the launch says `reply filter started early (pid N)`.
- **The hand-off.** Where the serial form spawned the chain, the launcher
  writes one JSON line (`handoffLine`; the filter reads it with
  `interceptors/reply-filter/src/handoff.ts`): `cmd`, the serial form's
  command after `--` (the security wrappers, then the agent); `outer`, the
  scope's prefix (`systemd-run --user --scope … --`, or nothing); `env` and
  `cwd`, what the serial form would have started the filter with (the
  composed environment plus the human-plane socket); `outputFormat`. The
  filter replaces its environment and directory with them, answers `ok`,
  closes fd 3, and runs exactly as `reply-filter
  --mandu-output-format=<f> -- <cmd>` does, with `outer` in front of
  whatever it spawns (the command, or `script(1)` for the PTY relay).
  `runAgent` then adopts the filter as the chain's first process
  (`AdoptedChain`): signal forwarding, the SIGWINCH group forward, the exit
  status (128+n for a signal), the teardown guard and the guard-death check
  are the serial form's.
- **What changes in the chain.** With no scope (`--no-scope`, no user
  systemd, macOS) nothing: the filter is the session leader as before. With
  a systemd scope the filter now runs `systemd-run` instead of being run by
  it, so the filter itself sits outside the session's `mandu-<id>.scope`
  while `script(1)`, the security wrappers and the agent stay inside it. The
  filter is a human-side process; it exits when its child does, so stopping
  the scope still ends the session. The human-plane socket is never in the
  scope's `--setenv` list (the scope would hand it to the agent); it travels
  only in the hand-off, and the filter drops it from its child's env as
  before. The agent's own environment is unchanged.
- **A launch that stops first.** `main` holds the filter in a
  `ReplyFilterSlot` and ends it in a `finally` whatever stopped the launch (a
  refusal, a throw): the channel is closed, the filter exits 0 on the end of
  file without a word, and after 2 s it is SIGKILLed; `main` returns only
  once it is gone. A launcher that dies outright closes the channel too.
- **Degrading.** A filter that is gone at the hand-off, does not answer
  within 10 s, or was spawned with another `detached` than the final scope
  plan's is ended and replaced by a fresh one, started and handed off at
  once (the serial cost). If that fails too, the chain runs without a
  filter after a `WARNING` line: the filter is utility-only, and a symbol
  shown raw leaks nothing. `MANDU_REPLY_FILTER_PRESTART=0` keeps the serial
  form.

Measured on the development host (2026-10-04, heavily loaded: load average
about 40 on 128 cores), `mandu claude --version` from a non-git directory, a
dev arbiter, no native bins, medians of interleaved runs: from the bundle
1.34 s serial, 1.11 s early, 1.04 s with no filter at all (9 runs each);
from source (`MANDU_FROM_SOURCE=1`) 3.42 s serial, 2.70 s early, 2.68 s
with no filter (7 runs each). Tested by `launcher/test/unit/reply-filter-prestart.test.ts`
(start, hand-off, abort, the SIGKILL after the grace, the fallbacks, the
slot, `runAgent` adopting the chain, and the hand-off line's parity with the
filter's reader), `interceptors/reply-filter/test/unit/handoff.test.ts` (the
protocol and its reader) and `test/component/handoff.test.ts` (the real
filter: untouched before the hand-off, then the scope prefix, the resolved
reply, no human socket and no fd 3 in the agent, the exit code; the end of
file; a malformed line; the PTY relay), and end to end by
`launcher/test/reply-filter-live.test.sh` (the default launch resolves
through the early filter; a launch refused after the early start leaves no
process; the exit status and the agent's env; the serial form; the systemd
scope form).

### 5.4 The kernel probes are kept for the boot (2026-10-04)

Every launch used to ask the kernel the same questions: can bubblewrap make a
user namespace (twice: the command box and the secret setup each asked),
does the Landlock applier confine TCP, can a sandbox start inside the secret
wrap, does the git sandbox run, is Mandu's own bubblewrap's grant loaded,
does Codex's own sandbox start, and (since 2026-10-09) does the command
box's bubblewrap take `--disable-userns` (`bwrap-help`, which the launcher
asks for the box once instead of each boxed command asking it,
exec-routing.md §4). That is one to three processes each. Since
2026-10-04 a launch keeps each probe that PASSED in
`<runtime dir>/probe-cache/kernel-probes.json` (`launcher/src/probe-cache.ts`)
and the next launch in the same boot asks it again only when an input
changed. Its directory uses the same socket-aware runtime-base resolver as
the stack and scope directories (runtime-instances.md §3b), including the
private `/tmp/mandu-<uid>` fallback for a long TMPDIR. Cache creation, reads
and `mandu setup` deletion therefore agree on that base; no kept probe
creates the abandoned `$TMPDIR/mandu` candidate. Since 2026-10-16 the file
also keeps one launch probe that is not a kernel question, under the same
rules: the exec-wrap shim's load probe (`exec-shim`, a node start of
0.18-0.24 s; its key and why it is not per-session are in
portable-wrapper.md §5). The rules, security first:

- **Only a pass is kept, and only the best one.** An entry says "passed with
  the strongest answer this probe gives" (the git sandbox: the first
  bubblewrap with the most hardened flag set). A failed or weaker answer is
  never written, so it is asked on every launch: a host fixed by `mandu
  setup` or by hand is seen by the next launch, and no entry, whoever wrote
  it, can make a launch weaker than a fresh probe would. A fresh failure
  drops a kept pass for the same probe, also under `MANDU_PROBE_CACHE=0`
  (which then looks in the file it otherwise does not read). The file holds no
  value at all, only "passed" per key; the git sandbox's `git --version` is
  not kept (the walk key's version is asked of git, in the sandbox).
- **A kept pass is still enacted, and each step fails closed.** The secret
  wrap and the command box run bubblewrap as after a fresh probe; if it
  cannot make its namespace the agent (or the boxed command) never runs. A
  sandboxed git call fails and the object twins refuse the launch (unless
  `--best-effort`, which says so). The inspect_symbol Landlock wrap now runs
  WITHOUT `--skip-unsupported` once its probe passed (fresh or kept): the
  applier exits 71 instead of running inspect-mcp unconfined (before this,
  a wrong probe answer would have degraded silently). A kept exec-wrap shim
  pass still puts shims on the agent's PATH that run exec-wrap on every
  call, and a shim that cannot load fails that call closed (exit 77 or a
  crash), never running the real command raw. A launch that used a
  kept pass and then failed deletes the file, so the next one probes afresh.
- **The key is every input a probe reads**: `boot_id`, the uid, the kernel
  release, the userns knobs (`apparmor_restrict_unprivileged_userns`,
  `apparmor_restrict_unprivileged_unconfined`, `unprivileged_userns_clone`,
  `unprivileged_userns_apparmor_policy`, every `user.max_*_namespaces`), the
  LSM list, the launcher's own namespaces, seccomp mode and filters,
  no_new_privs, capabilities and AppArmor label (a launch from inside a
  sandbox asks different questions), the identity of the AppArmor profile
  files and directory and of Mandu's own bubblewrap, PATH, `MANDU_GIT_SANDBOX`,
  the probe code's own file (any rebuild or upgrade), and per probe the
  identity (real path, device, inode, size, mtime, ctime, mode, owner) of
  every binary it runs plus its argv. An entry is also trusted at most six
  hours, a backstop for AppArmor policy loaded or unloaded outside
  `/etc/apparmor.d` (the kernel's policy `revision` file cannot be read
  without blocking, so it is not an input).
- **The file is the user's own.** Its directory is made 0700 (the runtime dir
  itself may be looser: the dev host's was 0775), the file is written 0600
  by rename and read through `O_NOFOLLOW`; a file or directory not owned by
  the caller or open to group or others, a symlink, a file over 64 KiB, a
  parse error or an unknown version is a miss (and nothing is written into a
  loose directory).
- **Only a launch reads it.** `mandu doctor` and `mandu setup` probe fresh;
  `mandu setup` deletes the file (any form but `--print`).
  `MANDU_PROBE_CACHE=0` reads nothing for one launch (fresh probes; a fresh
  pass is still kept); `--verbose` names each probe answered from the file.

Measured on the development host (Linux 7.0, Ubuntu's AppArmor userns
restriction, load 50-110): the probe phase of a launch, in-process, from a
median of 118 ms (master's sequence: userns twice, Landlock, nesting, git
sandbox) to 13 ms (only the nesting probe, which fails on this host and is
therefore never kept). The whole `mandu claude --version` moved by less than
the load's noise (medians 1.56 s vs 1.54 s, seven interleaved runs each).
Tested by `launcher/test/unit/probe-cache.test.ts` (keying, the file's
refusals, only passes kept, the bypass, setup and failure invalidation, the
git sandbox's best answer, the strict Landlock wrap stopping at exit 71) and
`tests/sandbox/probe-cache-launch.test.ts` (the real launch: a poisoned pass
fails closed and is dropped, a failure is re-probed, setup clears, a real pass
is kept and its bind still enacted). The exec-wrap shim probe's entry is
tested with the shims (portable-wrapper.md §5): the exec-shim step of
`startServices` went from a median of 132 ms to 2.6 ms on a kept pass.

### Launch display policy

Every layer prints its truth-in-labeling line as it comes up
(fs-sync.md §1 P5), and every one of those lines is still PRODUCED on
every launch: it lands in the session's `launch_posture` event (the
dashboard's health chip), in `<scopeRunDir>/launch.log`, and in the
launch's own log (`mandu log`, below). What a user sees by default is
short, TTY or pipe (`launchDisplayMode` does not look at the TTY). Since
2026-10-18 ("quiet launch": the maintainer's ask, for regular use as much
as for a recording) a healthy launch prints ONE line before the agent:

```
mandu: secrets mode · 33 credential files, 1 env var masked · dashboard http://127.0.0.1:4500/ · 2 notices: `mandu log`
```

The rule, line by line (`noteShow` in `launch-banner.ts`, the state in
`launch-console.ts`):

- **The banner** (`bannerLine`): the mode the session really runs under and
  what it masks (`modeFacts`, the mode line's facts in short form: no
  pinned-reader count, no `(read-blocked)` tag), the dashboard, and how many
  notices the launch kept for its log (none: no count). The dashboard part
  (`bannerDashboard` in `dashboard-sign-in.ts`) is the newest live dashboard
  in this user's runtime registry (`liveDashboards`, `dashboardUrl` in
  `subcommands.ts`: loopback for a wildcard bind, the prefix the entry
  recorded), with the one-time sign-in link in place of the URL when there
  is one (`dashboard http://…/login?ticket=… (the link signs this browser in,
  once)`; terminal only, never in a log, policy-surface.md §2.6), or `no
  dashboard (start one: \`mandu dashboard\`)`. The dashboard registers before
  it starts the arbiter, so a first launch that autostarts the stack finds
  it. When the autostarted dashboard does not come up, the fallback line
  names the reason this start left in the log (`lastStartFailure`: an
  `EADDRINUSE` becomes "port N is already in use"; else the last error
  line); `mandu dashboard` does the same on its failure paths. A GATED
  posture reads in the banner as on the mode line (`credential files GATED,
  not masked`): it is the fact that protection is not what the mode
  promises.
- **One short line per posture warning**, under the banner: a note that
  says a layer is NOT in its designed posture (`isAttentionNote`: `WARNING`,
  `DEGRADED`, `proceeding WITHOUT`, `GATED`, `failed`, `could not`, `is not
  installed`, `not built`, `is absent`, a pinned TUI, an agent's own sandbox
  turned off) prints as `mandu: WARNING: <gist> (more: \`mandu log\`)`
  (`postureLine`): the note's first line without its `WARNING:` / `mandu:` /
  helper prefixes, starting after a `WARNING` that comes later in the line
  (the shell target's truth-in-labeling line, whose warning is its second
  sentence), a long absolute path shortened to its last name, cut at a word
  near 160 characters. The prefix keeps the marker, so the short line is
  itself an attention note. A warning two producers say alike prints once.
  The WARNING blocks about ANOTHER launch beside this one (below) and the
  placeholder-commit block (placeholder-commits.ts) fold the same way, to
  their marked first line. Posture is never only counted: a degraded launch
  says so on the terminal, in one line per degradation, every launch.
- **Notices are counted, not printed**: advice the launch is safe without,
  its full text in the log. They are the producers `compactNotice` knows
  (its patterns match the producers' exact text, and
  `launch-banner.test.ts` feeds it each producer's real output, so a
  reworded producer fails a test): the agent outside its tested version
  range (`versionWarning`; it carries `WARNING`, but a known notice is
  matched first), what the secret walk left unsearched (`notCoveredNotice`,
  count only on the banner), keys in this project no rule covers
  (`launchSuggestionNotice`), the git-history caches found void because
  another Mandu launch runs without protection (`voidedCachesLine`, plan 14
  §11.2.1), the update notice (§11.5), the preview notice of a preview agent
  (`previewNotice`, `supported-agents.md` §2.0; `MANDU_PREVIEW_NOTICE=0`
  hides it), the old-Node notice (`nodeEnvProxyNotice`, §7), the Codex
  apps-off note, a dashboard sign-in link that could not be made; and a
  caller's own notice (`showNote(…, true)`). The keys notice waits for the
  workspace's scan (within 1.5 s) only on its first launch: after a finished
  scan the arbiter answers at once from it and scans again in the background
  (plan 14 §5.5).
- **Three notices still print**, each as its short `mandu: ! …` line under
  the banner (`mustHearNotice`): the ones that say Mandu changed what the
  agent itself does this launch, which the user would otherwise meet as a
  mystery, and a security update. Mandu turned Codex's own sandbox network
  ON (`codex-shell-network.ts` OPEN_NOTE: `mandu: ! Codex's commands may use
  the network (Mandu decides where they connect);
  --no-codex-shell-network keeps Codex's default`); the OpenCode plugins
  and custom tools the launch left out, by file, with the switch that runs
  them (`supported-agents.md` §2.3 items 11 and 12; first-session.md
  promises the launch names them: `mandu: ! this project's OpenCode plugins
  do not run under Mandu: <files>; MANDU_OPENCODE_PROJECT_PLUGINS=1 runs
  them unchecked`); and a newer release with SECURITY fixes (a plain update
  is only counted).
- **A wait about to start**, one line printed AT ONCE, in both display
  modes, above the banner: collected under the banner it would appear only
  after the wait it explains. The history re-check (`historyRecheckNotice`
  in `cache-seals.ts`, plan 14 §11.2.1 "The rebuild notice": `mandu: ! an
  earlier Mandu session without protection has ended, so Mandu is
  re-checking the git history of 2 repositories (slower this once)`) and
  the release check's restart of an older stack (`mandu: the Mandu services
  running for you were …; restarting them as …`, arbiter-version.ts; run.ts
  passes it as a wait). It is printed before the agent starts, so a
  full-screen agent never draws over it.
- **Last before the agent** (2026-10-17): the WARNINGs about ANOTHER launch
  beside this one, said before the agent starts, are held until the banner
  above is out, so they are the last thing on screen when the agent takes
  the terminal (`holdUntilBanner` in `launch-banner.ts`): the human-plane
  exposure block (`exposureLostLines`, arbiter-human-plane.md §10.1.1) and
  the unconfined launch beside a confined one (`concurrentLaunchNotice`).
  By default each block shows as its marked first line's posture line
  (which names the launch by pid and session); `--verbose` prints them
  whole, and the log keeps them whole. Once the agent runs, the watch's live
  lines print as they come (folded the same way); a full-screen agent may
  paint over those, which is why the recap after it exits says them again,
  in full, and the dashboard's Home page shows the same notice. No pause or
  keypress: nothing in this policy waits on the user.
- **A refusal or an error that stops the launch** prints in full: it is
  thrown, not a note, and the CLI entry prints its message after `main()`
  has put the console back. An aborted launch first prints the posture
  lines it held and a `mandu: N notices: \`mandu log\`` line (no banner was
  printed), and its log ends with `mandu: the launch stopped: <message>`.
- **After the agent exits**, the lines a launch says (the files the agent
  changed in a placeholder copy, a placeholder git recorded, the recap of
  another launch's exposure, what the teardown stopped) print as they are,
  and are copied to the log.

Under `--verbose` / `MANDU_VERBOSE=1` every line prints in full as it is
said, as before 2026-10-18: the mode line (`mandu: mode secrets (14
credential files masked, 1 env var masked)`, `modeLine`), the dashboard line
(`dashboardLine`, `terminalDashboardLines`), every notice and every layer.

**The launch's log** (`launch-log.ts`). Every line a launch says goes to a
file of its own as it is said, in both display modes: a header (the Mandu
version, the program, the target, the launch directory, the session id, the
UTC time), every note in full, the mode and dashboard lines (without the
sign-in link: the log never holds what the terminal alone may show), the
error that stopped a launch, the lines said after the agent exits, and the
non-fatal messages of Mandu's own helpers while the agent runs. It holds
nothing the terminal would not have shown under `--verbose`, and never the
agent's own output: the agent keeps the real terminal.

- *Where*: `launch-logs/` in Mandu's state folder (the path table's
  `launch-logs`, on-disk-layout.md §5; `mandu paths` lists it), one file per
  launch, `<UTC yyyymmddThhmmssmmmZ>-<session id>.log` (a name already
  taken, as by two in-process launches of one session id, steps the time by
  a millisecond). The folder 0700, each file 0600, opened through
  `safe-log.ts` (no link on the way, a link or a FIFO at the name refused).
  The agent can neither read nor write it: the whole Mandu home is outside
  its world (write-protect.ts). A launch that cannot open it (a read-only
  home) runs as before and its short lines say `(more: \`--verbose\`)`.
- *Kept*: the newest 20 (`LAUNCH_LOG_KEEP`); a launch that opens a new one
  removes the older ones. Unlike `launch.log`, it outlives the scope dir and
  a reboot.
- *Helpers*: the launch names the file to the wrapper chain in
  `MANDU_LAUNCH_LOG` (with `MANDU_LAUNCH_DISPLAY=compact` by default; both
  are display-only and the SDK route never forces them). The network guard
  sends its non-fatal messages there (`diag.rs` in net-supervisor: the
  arbiter older than the guard, a clean box not hosted, the report
  channel's fallbacks, a held command's one-time allow): to the log only
  under the default display, to stderr and the log under `--verbose`, and
  to stderr when no log is named or the append fails. Its fatal messages
  (the target not exec'd) and its pre-agent degrade (`proceeding WITHOUT the
  IP-aware guard`) stay on stderr. The reply filter's all-is-well notice
  (its PTY-relay line) goes to the log under the default display; its
  degrades go to stderr and the log. Both append through no link (the
  guard's `safe_write`, the filter's O_NOFOLLOW open of an existing file).
  The services the launcher starts already write their own logs in the
  scope dir.
- *Reading it*: `mandu log` prints the latest launch's log (control
  characters a helper's message may carry shown as `?`); `mandu log <session
  id>` (or a prefix) that launch's; `mandu log --list` the kept launches,
  newest first; `mandu log --path` the file's path (`tail -f "$(mandu log
  --path)"` follows a running session's helpers).

The `^@` before a helper's line in the first report of the problem
(2026-10-18) was not Mandu's: it came from the capture, a `script(1)` whose
own stdin was at end of file (`< /dev/null`), which writes the session's EOF
character into the pty; the reply filter's PTY relay passes it to the
agent's pty, whose echo shows it as `^@`. A real terminal (or a capture
whose stdin stays open) never sends it.

The from-source shim (`launcher/mandu-run.sh`) loads the developer secrets
file through `scripts/mandu-env.sh` before the launcher starts; it sets
`MANDU_SECRETS_QUIET=1` unless the launch is verbose (`--verbose` before any
`--`, or `MANDU_VERBOSE`), so its `[mandu-secrets]` lines (no file found,
what was loaded) print only then. Its warnings (a group-readable file, bad
JSON) always print. The Linux scope planner passes `--quiet` to
`systemd-run` so its own "Running as unit" line goes too.

Why: a healthy launch used to print about fifteen lines of internal terms
before the agent's own welcome, which the agent's inline renderer never
clears; 2026-09-26 cut that to the mode line, the dashboard line and one
line per notice, still four to six lines with every warning in full and a
helper writing over the agent's screen. The security labeling is not
weakened, only the noise: every degradation still reaches the terminal, in
one line, and its full text is one command away. Every harness that reads
layer phrases off stderr asks for them with `MANDU_VERBOSE=1`:
`withStack`'s `launcherEnv` (integration `launcher-live.ts`, shared by the
launcher-live suites and the differential driver), `interactive-driver.ts`,
the drill runner, `mandu doctor --live` (`gatherLive`), and the launcher's
bash live oracles; an in-process test that asserts a producer's full text
reads the launch's log (`launcher/test/lib/launch-log-read.ts`).

Guarded by `launcher/test/unit/launch-banner.test.ts` (the mode matrix
without a TTY input, the real banner phrases classified, `noteShow` per
kind, `postureLine`, `bannerLine`, `modeFacts`, the must-hear notices),
`launch-console.test.ts` (what goes where, the console hooked, teed and put
back, a held block folded, an aborted launch), `launch-log.test.ts` (the
place, the modes, no link followed, retention, `mandu log`),
`dashboard-sign-in.test.ts` (`bannerDashboard`), `arbiter.test.ts` (the
fallback reads only this start's part of the log), `subcommands.test.ts`,
`launcher/test/component/run.test.ts` (the default prints the banner first
and only short posture lines after it; the launch's log holds every line
and is 0600; `launch.log` too; `MANDU_VERBOSE=1` and `--verbose` print
everything, agree, and still write the log; the chain is told the log; a
registered live dashboard named with its URL, a dead one skipped), the
reply filter's component test (its notice in the log, never through a
link), and net-supervisor's `diag` unit tests.

`launch.log` lives as long as the scope dir: a launch that ends cleanly (exit
0, a minted scope id) removes its scope dir (runtime-instances.md §10.1), and
the full note list stays on record in the `launch_posture` event and the
launch's log. A session that fails, a named scope (`--id`) and
`MANDU_KEEP_SCOPE_DIR=1` keep `launch.log` on disk.

## 6. macOS (experimental, `read-blocked`)

The dated results below are the macOS branch's historical hardware record.
The merge with current master has not yet run on a Mac; rerun the listed
checks before treating this integration as verified.

The darwin platform module ran on real hardware for the first time on
2026-09-29 (macOS 26.5.1, arm64 Mac mini, Node 22.23.3, Claude Code 2.1.284;
portable-wrapper-cross-platform.md §3.3, §3.5). Packaging work:

1. **Real-Mac verification pass** ✅ **done for `mandu claude` (2026-09-29)**.
   On that Mac, with the account's real HOME and a scratch project holding
   fake secrets:
   - `mandu doctor --live`: L1 (a launch at the full macOS posture; the
     Linux-only rungs are named, not graded), L2/L3 (the reply filter on a
     pipe and on the PTY relay) and "claude inside the wrap" pass.
   - `mandu claude -p …` (a real model): the agent's Read, Write, Edit and Bash
     work inside the whole-agent Seatbelt profile (confidentiality.md §7.3); a
     credential file in the project fails to read (`Operation not
     permitted`); a masked environment variable reaches the model only as
     `$MDU:nomodel_Env[…]` (the model quoted the prefix `$MDU:n`); HTTPS through
     the TLS-inspecting net-proxy works (`curl https://example.com` → 200); a
     direct TCP connect to a port outside the set is refused (`nc … 80`); the
     agent's `curl` resolves to Mandu's exec shim despite macOS's
     `path_helper`.
   - Interactive `mandu claude` in a real pty: the TUI comes up (the trust
     dialog answered with the arrow keys through the relay), a prompt runs a
     Bash command and replies, a resize from 120 to 90 columns re-renders the
     TUI (pty-relay.md §3), `/exit` returns 0, and no agent process is left
     behind (the resident arbiter and dashboard stay, by design).
   - The runtime dir is the private `/tmp/mandu-<uid>` (0700, owner-checked;
     runtime-instances.md §3b): the per-user TMPDIR is too long for an
     instance socket.
   `mandu codex` (re-checked 2026-10-01, Codex 0.159.3, the Homebrew cask):
   Codex starts inside the wrap (`doctor --live` ✓) and its model turns go
   through Mandu's proxy. Its commands run only with Codex's own sandbox off,
   since its per-command Seatbelt cannot nest inside Mandu's
   (`sandbox_apply: Operation not permitted`); since 2026-10-02 Mandu turns
   it off for the session (confidentiality-plan-10-flow-taint.md §12.3). So
   checked: an env canary reached the model only as a `$MDU:` placeholder,
   `.env` and `~/.mandu` were refused, and Codex's session log held no raw
   copy. On 2026-09-29 a Codex 0.155.1 was SIGKILLed at start (exit 137);
   that no longer reproduces. The interactive TUI was not driven. Still open:
   OpenCode and OpenClaw were not tried; fs-view worktrees (integrity,
   frozen) were not exercised.
2. **Reply-filter PTY backend for darwin** ✅ **landed** (`pty-relay.ts`). The
   relay was util-linux `script(1)` only; on macOS it degraded to passthrough,
   so interactive users saw raw `$MDU:*` tokens — utility-class, not a
   security hole, but exactly the polish the macOS target needs. BSD `script -q
   /dev/null <cmd>` gives the same real-PTY shape and execs the argv directly
   (no `sh -c`, so no quoting layer); it sits behind the existing backend probe
   keyed on `ptyFlavor()` (`linux → util-linux`, `darwin → bsd`, else `null →`
   degrade). The pure pieces (flavor map, per-flavor argv, probe argv) are
   unit-tested off-platform; the BSD *ok-path* is host-keyed so the SAME
   reply-filter unit assertion proves it when the suite runs on the macOS
   runner. Measured on macOS 26.5.1 (§10.5, `pty-relay.md`): normal exit
   codes propagate; BSD script relays neither a resize nor a signal and
   reports a signal death as the bare number, so a companion (`bsd-relay.ts`)
   re-sizes the child's pty, forwards INT/TERM/HUP to the child and maps a
   delivered signal to 128+n.
   **The util-linux relay's shell (2026-09-30).** util-linux `script -c` runs
   its string through `$SHELL -c`, and a user's shell can swallow it: Ubuntu's
   bash reads `~/.bashrc` even for `bash -c` when it thinks sshd started it
   (`SSH_CLIENT` set, `SHLVL` below 2, as under a tmux server started from an
   ssh login), and a `.bashrc` that `exec zsh`s on a terminal left the agent's
   pane at a zsh prompt with the agent never started. The relay's `script`
   now runs with `SHELL=/bin/sh` (`PTY_RELAY_SHELL`; POSIX sh reads no startup
   file for `-c`), and the command is `exec env SHELL=<the user's> <agent…>`
   (`env -u SHELL` when there was none), so the agent keeps the user's shell
   for its own tools. BSD `script` execs the argv and needs neither.
3. **Tests: by hand on a Mac, no CI** (decided 2026-10-09). No macOS runner
   exists on the canonical remote (self-hosted GitLab, Linux shell runner),
   and GitHub's `macos-latest` job cost ten times a Linux one against a
   private repository's quota, so it was removed after its first runs
   (continuous-integration.md §12, which records what they found). A
   maintainer installs (`scripts/bootstrap.sh --no-shim`) and runs
   `scripts/test-all.sh`, which on darwin selects exactly the manifest's
   darwin entries (typecheck and the whole `npm test` of the packages marked
   for macOS, the launcher shards, and the live Seatbelt suite
   `launcher.darwin-seatbelt`; development.md, "Developing and testing on
   macOS"), before a release and after a change to the darwin code. The
   deferred ssh matrix executor remains the fuller answer. The same set ran
   green by hand on the Mac of item 1 (24 suites, 2026-09-29).

After §4 there is no per-platform build at all, so "macOS support" is purely
the runtime items above (items 1 and 2 done for `mandu claude`) plus CI proof
(item 3, mirror-gated).

### 6.1 WSL2 (the Windows answer, 2026-09-27)

Windows users run Mandu inside WSL2, which is a real Linux kernel: the Linux
package, bins and rules apply as they are. What is WSL-only
(`launcher/src/wsl.ts`):

1. **Windows interop** is closed in the command box, refused by the connect
   guard and hidden by the secret-twin wrap (exec-routing.md §4.1, with the
   one race the guard leaves where no wrap runs).
2. **A project on a Windows drive** (`/mnt/c`, drvfs over 9p): a launch
   WARNS and `mandu doctor` marks it ✗, with the fix (move the project into
   the Linux file system, for example `~/src`). Not a refusal: no view leaks
   (the AgentView lives in the Mandu home, on the Linux file system, either
   way), but file access is slow and an edit made from Windows raises no
   inotify event, so fs-sync's human-edit clock misses it and reconciles at
   the AI's next tool call instead. Landlock on 9p paths is unverified until
   a WSL2 run.
3. **`mandu doctor`'s Platform section** adds, on WSL2: the kernel against
   Landlock (5.13) and its TCP rules (6.7) (old WSL kernels are 5.10; fix:
   `wsl --update`), Windows interop on or off against whether the connect
   guard is installed, systemd (off by default in older distributions: the
   dashboard's user unit cannot start; fix: `[boot] systemd=true` in
   `/etc/wsl.conf`, then `wsl --shutdown`), and a working folder on a Windows
   drive.
4. **WSL1** (a syscall translation layer: no Landlock, seccomp user
   notification or user namespaces) is refused by `scripts/install.sh` before
   anything is downloaded, marked ✗ by `mandu doctor`, and WARNED at launch,
   each naming `wsl --set-version <distro> 2`. Detection (`wslVersion`, and
   `mandu_arbiter::wsl::wsl_version` for the Rust boxes, parity-tested): a
   kernel release containing `microsoft-standard` or `WSL2` is WSL2 (the first
   4.19 WSL2 kernels had no `-WSL2` suffix), any other `Microsoft` is WSL1.

Not yet run on Windows itself (os-test-matrix.md `wsl2` row).

## 7. First-run UX

- **`mandu doctor`** ✅ (`doctor.ts`): prints Node/git/agent versions, the
  layout mode (dev vs installed), arbiter reachability, and what Mandu
  enforces on this machine per chokepoint, naming the layer each is enforced
  at. The summary states plainly whether enforcement is cooperative
  (context + wrapper layers) or kernel-backed, so a user can never believe
  they have kernel enforcement while running wrapper-only. Pure-render +
  gatherFacts are unit-tested.
- **The agent's login** ✅ (`agent-login.ts`). `mandu doctor` prints one row
  per agent: **claude** is found by `ANTHROPIC_API_KEY` /
  `ANTHROPIC_AUTH_TOKEN` / `CLAUDE_CODE_OAUTH_TOKEN`, a provider switch
  (`CLAUDE_CODE_USE_BEDROCK` / `_VERTEX` / `_FOUNDRY`; a launch with one
  of them on is refused, since that provider's wire skips the model proxy:
  supported-agents.md §2.5), or
  `$CLAUDE_CONFIG_DIR|~/.claude/.credentials.json`; **codex** by
  `OPENAI_API_KEY` / `CODEX_API_KEY` or `$CODEX_HOME|~/.codex/auth.json` (a
  `codex login` sign-in is relayed by the model proxy,
  [agent-sign-in.md](../agents/agent-sign-in.md) §2). Missing → ✗ with the
  fix (run `claude` once on its own and log in, or `claude /login`, or set
  the key; `codex login`); codex's row is a note (·) while codex is not
  installed. On macOS Claude Code keeps its login in the Keychain, which an
  existence check cannot see: the row says "cannot tell", never "missing".
  The launch runs the same probe for a real `claude` / `codex` argv[0] (not a
  stand-in, not a `login` subcommand) and, if nothing is found, prints ONE
  plain WARNING line before anything starts. It does not refuse, since
  detection can be wrong (an `apiKeyHelper`, a login elsewhere), with one
  exception: a `mandu codex` model session with neither a key variable nor
  a sign-in, which Codex itself could not run, is refused before anything
  starts (agent-sign-in.md §2.3). Rules held: **existence checks only** (a
  variable's NAME and a file's PATH are reported, never a value; no
  credential file is opened), and Mandu never logs anyone in. **goose**
  (a row only where goose is installed) is found by `ANTHROPIC_API_KEY`,
  its `secrets.yaml`, or an item in the system keyring, which doctor asks
  for by Secret Service `SearchItems` (object paths, never a secret); a key
  only in the keyring is a ✗ because a guarded `mandu goose` keeps the
  agent off the session bus, and that launch prints one line with the two
  fixes. On macOS doctor asks the login Keychain with `security
  find-generic-password` without `-w` (attributes, never the password), and
  a key there is a ✓ (the Keychain stays reachable). A
  `GOOSE_SUBAGENT_PROVIDER` on the other provider gets its own `goose
  subagent login` row (supported-agents.md §5.6.1). OpenClaw and
  OpenCode are not probed (their provider credentials live in their own
  config, merged under the routing override, agent-e2e-harness.md §9).
  Tests: `launcher/test/unit/{agent-login,doctor}.test.ts`,
  `launcher/test/component/doctor-login.test.ts` (the real `mandu doctor`
  over an empty HOME, then a login file; no value printed) and
  `launcher/test/component/run.test.ts` (the launch line, silenced by a key).
- **The `node` a session's programs run** ✅ (2026-10-09, `node-floor.ts`
  `nodeEnvProxyGap`; confidentiality-plan-13-reader-set-labels.md §10.2).
  Mandu runs on Node 22.13, but a Node *program* in a session uses Mandu's
  network proxy only when its Node honours the launcher's
  `NODE_USE_ENV_PROXY=1`: `fetch` from 22.21 / 24.0, `http`/`https` from
  22.21 / 24.5, never 23.x. Below that its requests go around the proxy:
  nothing leaks (they carry placeholders), but no placeholder is filled in,
  so its logins fail with no explanation. `mandu doctor` finds the first
  executable `node` on the user's PATH (the PATH a launch keeps: env-compose
  only prepends Mandu's own shims, none named `node`; not the Node Mandu
  itself runs on, which `install.sh` may have downloaded for Mandu alone),
  runs `node --version` with the user's environment (3 s), and prints a row
  under the Node.js row: ✓ when it honours the variable; ✗ naming the
  version, what does not work ("Node programs in a Mandu session won't have
  your secrets filled in on their web requests", or only on `http`/`https`
  for 24.0 to 24.4) and the upgrade (22.21+ or 24.5+); · when its answer is
  not a version, or it gave none. No node on PATH, no row. A warning: doctor
  still exits 0 and Mandu still runs. The launch prints the same as ONE
  notice line (Launch display policy, below), from the `node --version` it
  already runs for `--disable-warning` (no second probe), and only when the
  session inspects TLS (without inspection no placeholder is filled in for
  any program). The version table is the one the TLS-compat matrix uses
  (`tests/lib/tls-compat-cells.ts` re-exports it), so the warning and the
  measured cells cannot disagree. Tests:
  `launcher/test/unit/node-env-proxy.test.ts` (the floor per version, the
  rows, the notice, the real PATH probe over a stand-in `node`),
  `launcher/test/unit/launch-banner.test.ts` (the notice is a known one,
  counted on the default banner), `launcher/test/component/doctor-path-node.test.ts`
  (the real `mandu doctor` with a stand-in `node` first on PATH printing a
  chosen version, and with none) and `launcher/test/net-proxy-mitm-live.test.sh`
  step 6 (a real launch with TLS inspection: the notice once for a stand-in
  22.13, none for 24.21, the agent runs either way).
- **The agent's version against the tested range** ✅ (`agent-versions.ts`;
  the full note is [`supported-agents.md`](../agents/supported-agents.md)). A
  launch runs `<agent> --version` (3 s budget, only for the target's own
  binary) and prints ONE WARNING line outside the tested range, never
  refusing; `mandu doctor` prints a row per installed agent; the check rides
  `launch_posture.agentVersion` to the dashboard. The README's "Supported
  agents" table is pinned to the code by a parity test.
- **Codex's own command sandbox** ✅ (`codex-sandbox.ts`;
  os-test-matrix.md §10.14.1 item 4). Codex runs each command in its own
  bubblewrap: the `bwrap` on PATH, else a copy it bundles. A stock Ubuntu
  24.04 / 26.04 ships no bubblewrap and restricts unprivileged user
  namespaces through AppArmor, which grants `userns` per binary and never to
  the bundled copy, so every Codex command dies (`bwrap: loopback: Failed
  RTM_NEWADDR`), with or without Mandu. The decision (pure, unit-tested):
  Linux with `codex` on PATH, then (a) a userns sysctl shut → `userns-off`,
  the sysctl named; (b) no system bwrap and
  `apparmor_restrict_unprivileged_userns=1` → `no-bwrap`, fix `sudo apt
  install bubblewrap, then mandu setup` (setup asks for sudo only where the
  grant is needed: 24.04; 26.04's package brings `bwrap-userns-restrict`);
  no bwrap without the restriction is ok (the bundled copy runs); (c) a
  system bwrap failing Codex's OWN probe (`bwrap --unshare-user
  --unshare-net --ro-bind / / /bin/true`, read out of the 0.154 binary)
  under the restriction → `bwrap-denied`, fix `mandu setup`; otherwise
  `probe-failed` with no guessed fix. `mandu doctor` prints a ✓/✗ row under
  "What Mandu needs" (only when codex is installed); a `mandu codex` launch
  (real `codex` argv[0], not `login` / `--version`) prints ONE `WARNING`
  line with the fix and never refuses. The probe runs against the host,
  outside Mandu's wrap: whether Codex's sandbox nests INSIDE the launch is
  os-test-matrix.md §10.14.1 item 6. The login how-to
  (`CODEX_LOGIN_HOWTO`) reads "run `codex login` once without mandu (a
  ChatGPT plan), or set CODEX_API_KEY (or OPENAI_API_KEY) to an OpenAI API
  key": Codex 0.154 alone honors CODEX_API_KEY but answers 401 to a bare
  OPENAI_API_KEY without `codex login`, while the launcher's routed
  provider reads either. Tests: `launcher/test/unit/codex-sandbox.test.ts`,
  `doctor.test.ts`, and `launcher/test/kernel/codex-sandbox.test.ts` (the
  real doctor and launch with a stand-in `codex` and the host's `bwrap`
  hidden from PATH).
- **Plain words in doctor, why, revert and block messages** ✅. These are
  what a first-week user reads, so they use the dashboard product page's
  vocabulary (`rule-words.ts` TERMS: the AI, placeholder, masked, needs your
  OK, the dashboard's Approvals page, dashboard.md §4.25u), with the
  internal name kept in parentheses where a bug report needs it.
  - `mandu doctor`: "What Mandu needs / Installed / Mandu service / Your
    secrets / What Mandu enforces on this machine / Summary"; each layer is
    named by what it does with its component and kernel guard in parentheses.
    `posture: <name>` stays verbatim (the VM fresh-install suite and the
    dashboard chip use the names). A unit sweep keeps tier, chokepoint,
    arbiter, rung, symbolized, AgentView and § out of the default report.
    `POSTURE_SENTENCE` and the guard-only lines (`confinement-posture.ts`)
    are shared with `doctor --secrets` and `mandu setup`.
  - `mandu doctor --secrets`: the level column reads hidden / may read it /
    not secret; the not-covered rows and the launch line are plain.
  - `mandu why`: the level is the glossary's term with the level name in
    parentheses; a decision prints its rule id and, when held, where it is
    answered (the dashboard); the arbiter's internal reason text is left to
    `--json`.
  - `mandu revert`: fs-sync's `[fs-sync-cli]` prefix is dropped and "no
    history" says why (only injection and full record writes).
  - **Block messages.** exec-wrap and the exec box print what was blocked,
    why and what to do, then the unchanged machine reason as `detail:`.
    Neither has an approval queue (the arbiter files none for an exec), so
    neither promises one: the way on is a plain rewrite or a run outside
    the agent. Both word the refusal per withheld kind (for the box,
    `exec_supervisor::refusal`, exec-routing.md §5): a `secret_symbol` says
    a secret's real value never goes into a command line and points at the
    network request (and its dashboard approval) as the secret's way out
    (since 2026-10-05 only a defense-in-depth refusal: a secret's
    placeholder stays in the argv and the command runs, confidentiality.md
    §7.1);
    only the frozen `symbol_as_command` speaks of untrusted data. The
    model-proxy exec gate's sentinel (both proxies) points at the dashboard
    only when the arbiter filed an approval (`→ pending`, the program-text
    gate). A blocked `curl` that used to read "shell_construct_unsupported
    ({)" reads "the command carries a placeholder for protected data and
    uses shell syntax Mandu cannot check safely ({)". Reason codes,
    decisions and exit 77 are unchanged.
- **`mandu init`** + `config.toml` ✅ (`config.ts`). Per-user defaults
  replacing the `MANDU_*` env spread; env vars stay as overrides (they are
  the e2e harness surface). Precedence **flags > env > config > defaults**
  is achieved cheaply: config values seed `env` only where unset (mutating
  process.env in the real CLI so services + the agent inherit them), then
  parse.ts's env→default precedence and flag overrides take over. A tiny
  built-in TOML subset (`key = value`, `#` comments, strings/bools/ints;
  sections flattened) keeps the package TOML-dependency-free; friendly keys
  (`reply-filter`, `fs-sync`, `net-proxy`, `proxy-port`, …) map to the
  MANDU_* vars, including the chokepoint-hardening keys `net-proxy`,
  `exec-wrap`, `exec-box`, `landlock-net`, and `landlock-net-strict`, which
  (bar strict) default **ON** with a probe-gated degrade, so the template
  documents opting *out*. `mandu init` writes an all-commented template (so a
  fresh config == no config == defaults); the path is the Mandu home's
  `config.toml` (`${MANDU_HOME:-~/.mandu}/config.toml`, on-disk-layout.md
  §3). Unit-tested (parse / mapping / precedence). Per-agent
  `[claude]`/`[codex]` profile sections remain a possible extension.
- **`mandu --mode <name>` + `mandu mode [name]` + `mandu --help`** ✅
  (`mode.ts`, `mode-command.ts`, `config-edit.ts`, `usage.ts`; design:
  [protection-modes.md](../architecture/protection-modes.md)). One knob
  over the two arbiter axes: `secrets`, `injection`, `full`, `off`. Flag
  `--mode`, env `MANDU_MODE`, config key `mode`; precedence flags > env >
  config, resolved PER AXIS: inside one level an explicit axis (`--no-integrity`,
  `MANDU_INTEGRITY`, `integrity = …`) beats that level's mode for that axis
  only, and the first level that says anything about an axis wins it. A `mode`
  key beside axis keys in config.toml is therefore resolved, never an error.
  `mandu mode` prints the RUNNING mode (what the attached arbiter reports)
  and the SAVED one; `mandu mode <name>` saves through a surgical editor
  that mirrors the dashboard's (it re-aligns any existing axis line, so the
  file never contradicts itself). Every launch prints the mode line (§5),
  naming the EFFECTIVE mode (the arbiter's report, else the request, else
  the built-in default). Launcher-side consequences follow the effective
  pair too: integrity OFF means no fs-sync twin, confidentiality ON means
  secret confinement, even for an unflagged launch that joins a running
  arbiter. A `--mode` that differs from the running arbiter is REFUSED
  before anything starts, naming the running mode and the way out
  (protection-modes.md §3.4). `mandu --help` (also `-h`, `help`, and a bare
  `mandu`, which exits 2) prints usage with the four modes. `mandu
  --version` (`-V`) prints the package version (§11.2).
- **`mandu setup`** ✅ (`setup.ts`,
  [`rootless-confinement-ubuntu-2404.md`](../confidentiality/rootless-confinement-ubuntu-2404.md)
  §3.2): the one OPTIONAL privileged step as a single command. On Ubuntu
  >= 23.10 the secret posture is `gated` until bwrap carries an AppArmor
  `userns` grant; `mandu setup` runs unprivileged, prints the exact profile
  text and commands, asks, then runs only those commands under `sudo` and
  re-probes. `--print` for review or configuration management, `--uninstall`
  to remove. It decides need by probing (a distro-provided profile means
  "nothing to do") and never overwrites or removes a file it did not create.
  Setup installs Mandu's own bubblewrap (a root-owned copy at
  `/usr/lib/mandu/bin/bwrap` plus a profile for that path only) and removes
  a Mandu-marked older grant on the system `bwrap`
  (rootless-confinement-ubuntu-2404.md §12.3). The profile ships in the
  package as a bundle **asset** (`bundle-manifest.json` `assets` →
  `dist/apparmor/mandu-bwrap`, resolved by `Layout.asset()`; the npm-pack
  e2e holds it byte-identical to `scripts/apparmor/`). **Not built:** a
  `.deb` (or apt repository) whose postinst installs the profile would make
  root-at-install invisible, the way Chrome and VS Code deliver theirs.
- **`mandu demo`** ✅ ([`mandu-demo.md`](./mandu-demo.md)): the default
  product (`secrets` mode) on a throwaway project with a FAKE Stripe key,
  for Claude Code and for Codex on each one's own wire, in three plain
  scenes: the agent reads `.env` (the AI gets a placeholder, you see the
  key), uses the key with curl at the host it is bound to (the real value
  goes in on the way out), and tries to send it elsewhere (stopped, an
  approval raised). The real arbiter, both model proxies, the egress proxy
  with TLS inspection and the reply filter run in a sandbox, and the
  agent's commands run under the whole-agent guard where the host has it
  (so Codex's `cat .env` shows per key); the model and
  the two web hosts are loopback stand-ins. No key, no login, offline, about
  7 s from source and 3 s from the bundle. An attack-contrast version is
  deferred (mandu-demo.md §9).

### 7b. `mandu doctor --live`: does it WORK here, now?

`mandu doctor` checks that the parts exist. `--live` runs them the way a
launch does (the real launcher, this user's config.toml and HOME, every layer
default-on) around commands that cost no model call, and grades the same
banners the session-health record (dashboard.md §4.21) is built from:

- **launch at the default posture**: `mandu --target claude -- /bin/true`
  exits 0 with NO dropped/degraded layer (a bricked launch, resident-stack
  port collisions and the codex nested-bwrap failure all fail here);
- **reply-filter, pipe and PTY relay**: a symbol the arbiter minted for this
  check, echoed by a child under the launcher, reaches stdout RESOLVED on
  both paths (and the relay reports `PTY RELAY`);
- **claude / codex inside the wrap**: `<agent> --version` starts under the
  secret twins, landlock-net, net-guard and the exec shims;
- **one real model turn**: opt-in `--model`: `claude -p` through the proxy,
  one cheap call, proves auth + routing + the handling prompt live.

Exit 1 on any ✗. This is the only check that runs on hosts the project does
not own (their bwrap, their kernel, their config); the `bwrap ≥ 0.8`
pairing defect would have failed it on every Ubuntu 24.04 install. Run it
after every install or upgrade of Mandu OR of the agent CLI.

**On macOS (2026-09-29).** The PTY relay check runs the host's script(1)
in its own dialect: BSD `/usr/bin/script -q /dev/null <argv…>` (named by path;
the argv is exec'd
directly; BSD script rejects util-linux's `-qefc … /dev/null` with "illegal
option -- f", which made this check fail on every Mac). The argv builder
mirrors reply-filter's `pty-relay.ts` (`ptyFlavor` / `buildPtyArgv`), held
together by a parity unit test; a platform with no relay skips the check by
name. BSD script also reads its stdin's terminal attributes and dies on a
pipe ("script: tcgetattr/ioctl: Operation not supported on socket", the
child never runs; measured), so the check hands it `/dev/null` there;
util-linux keeps the empty pipe it always had. The launch check keys on the PLATFORM, not only on the wording: the
command box, landlock-net, the connect guard and the inspect_symbol network
confine are Linux kernel guards, not part of the macOS posture, so their
lines (the older "not built … proceeding WITHOUT it", which names a Linux
bin, bubblewrap, a user namespace or Landlock, or the newer "Linux only")
are counted as "not graded on macOS", never as a dropped rung; any other
drop (a service that failed, `secrets are GATED`, and a line about the macOS
mechanism itself, Seatbelt or `sandbox-exec`, whatever rung it names) still
fails it.
`mandu doctor` (§7) says the same in its table: each kernel guard is "Linux
only", the file row names the Seatbelt profile that blocks reads of the
credential files, and the summary never offers a build from source. Tests:
`launcher/test/unit/doctor-live.test.ts` (both flavors, both wordings, the
parity), `launcher/test/component/doctor-live-pty.test.ts` (the argv through the
host's own script(1)).

## 8. Milestones

| # | Deliverable | Status |
|---|---|---|
| **M1** | `scripts/bootstrap.sh`: clone → one command → `mandu` on PATH (Node ≥ 22.13 preflight, installs every package's deps, per-package typecheck, writes a from-source `mandu` shim via the launcher's local tsx, doctor-style summary + PATH check) | ✅ the from-source channel; also contributor onboarding |
| **M2** | `node:sqlite` migration (§4) + the bundle & layout resolver (§5) + launcher parity (reply-filter, dashboard, bare argv, status/stop, titles) + bin→bundle + `npm pack` test | ✅; open: the fuller wrapper-parity-against-`dist` matrix axis. `mandu-run.sh` is a shim (portable-wrapper.md §7) |
| **M3** | ◐ macOS: BSD PTY relay and Seatbelt profile implemented; historical `mandu claude` and `codex exec` hardware record (§6); tested by hand on a Mac, no CI | Fresh integrated-branch hardware pass still required; Codex TUI, OpenCode and OpenClaw unverified |
| **M4** | `doctor` + `init`/config.toml + `demo` (`secrets` mode: hide, use, stop; Claude Code and Codex) | ✅; the attack-contrast demo is deferred ([mandu-demo.md](./mandu-demo.md) §9) |
| **M5** | the `@mandusec/mandu` name + publish-readiness metadata (license, keywords, `publishConfig.access=public`) + versioning and the release pipeline (§11) + the actual `npm publish` + curl-sh/brew pointing at the public artifact | ◐ published from `0.2.0-beta.6` (2026-10-19): `homepage` and `bugs` set, `private` dropped in the public tree only, packed there with the native bins and published by hand with `--tag latest` (§11.4); `repository` waits for the public GitHub repository |

## 9. Fences (what this is NOT)

- **No kernel-layer packaging**: the Rust supervisors beyond the three
  unprivileged native bins (§5) stay repo-built, `.deb` later; `doctor`
  reports the layer honestly.
- **No Windows build**: Windows users run the Linux package in WSL2 (§6.1);
  the platform seam admits `win32` (portable-wrapper.md §10), not built here.
- **No new interception mechanisms, no behavior changes** inside
  arbiter/proxies/fs-sync beyond the §4 storage adapter: packaging
  reorganizes how existing components are built, resolved, and spawned.
- **No npm publish except a tarball packed from the public tree** (§11.4):
  npm from `0.2.0-beta.6`; curl-sh and brew stay off until the GitHub
  repository is public (§11.6).

## 10. Honest caveats

1. **Bundle vs source drift** is a failure class tsx-from-src never had;
   the mitigation is structural (the bundle tests in §5 run `dist/`), not hope.
2. **Node ≥ 22.13.0 floor** excludes users pinned to older Node; the error
   message says exactly that (`nvm install 22`) rather than failing
   obscurely. The four gates (`engines`, `bin/mandu.mjs`, `bootstrap.sh`,
   `doctor`) compare major.minor.patch (a major-only check would admit
   22.0 to 22.12, where `node:sqlite` is still behind a flag), and
   `launcher/test/unit/node-floor.test.ts` pins them to one constant
   (`launcher/src/node-floor.ts`).
3. **`node:sqlite` maturity**: `DatabaseSync` is synchronous like
   better-sqlite3 (semantics match); WAL-mode behavior under the arbiter's
   single-writer assumption is re-asserted by the concurrency tests (§4),
   not assumed.
4. **The npm scope `@mandusec`**: the `mandusec` npm organization owns it
   from the first publish, `0.2.0-beta.6` (M5, §11.4).
5. **Interactive TUI fidelity through the reply-filter on macOS.** The
   darwin PTY backend (§6 item 2) was measured on 2026-09-29 on macOS 26.5.1
   (arm64) with BSD `script(1)`. The design and the probes are in
   [`pty-relay.md`](../agents/pty-relay.md). Print mode (`claude -p`) uses pipe mode,
   which spawns the agent directly, so none of this applies to it.
   - **Exit codes.** A normal exit code passes through (`exit 9` gives 9). A
     signal death reads as the bare signal number (SIGTERM gives 15, SIGKILL
     gives 9), which cannot be told apart from `exit n`. The relay reports
     128+n for a signal it delivered itself, because it now forwards
     INT/TERM/HUP to the agent. A death by a signal from elsewhere (a crash,
     `kill -9` of the agent) stays the bare number. That is a stated residual.
   - **Resize.** BSD script sizes its pty once, from its stdin, and ignores
     SIGWINCH. Until 2026-09-29 a resized terminal never reached the TUI, while
     the reply-filter's screen model resized, so the two disagreed. The
     reply-filter's macOS companion (`src/bsd-relay.ts`) now finds script's
     child in one `ps -A -o pid=,ppid=,tty=` snapshot (about 11 ms, once per
     session). On each resize it runs `stty -f /dev/ttysNNN rows R cols C`
     (about 3 ms). The kernel then raises SIGWINCH in the pty's foreground
     group, as a terminal emulator's resize does. It needs no native addon
     and no python3, which is a Command Line Tools stub on a stock Mac.
     Proven by `interceptors/reply-filter/test/component/bsd-relay.test.ts` and by a
     hand run of the launcher in a pty: `mandu --target shell`, 24x80 then
     40x120 in the child, exit 7 back.
   - **Signals.** Sent to script, SIGINT/SIGTERM/SIGHUP killed script itself.
     The agent saw only the SIGHUP of the closing master, and its shutdown
     output was lost. A bare `script` also leaves the terminal raw; under
     Mandu, node restores it at exit. The companion now signals the agent.
   - **Stdin.** BSD script starts only on a TTY, /dev/null, an anonymous pipe
     or a regular file. With a socket (node's `"pipe"` stdio) or a named FIFO
     as stdin it exits 1 before the agent runs, so the reply-filter falls back
     to passthrough there. With a non-TTY stdin its pty starts at 0x0 (the
     companion re-sizes it from stdout), and at EOF it types a `^D` into a
     child in canonical mode.
   - **Still open:** the same check by hand in Terminal.app and in iTerm2
     specifically: raw mode, the alternate-screen renderer and a clean exit.
     An interactive `mandu claude` session with a real model has run in a
     real pty on the same Mac (§6 item 1: the TUI, a Bash command, a resize,
     `/exit` returning 0); which terminal hosted it is not recorded there.
     The runs in this item (`mandu --target shell`) made no model call.

## 11. Release engineering: one version, one tag, one artifact

Status: **BUILT 2026-09-25**; npm from `0.2.0-beta.6` (2026-10-19, §11.4). A product needs three things a placeholder version
cannot give: a number a user can report, a commit that number points at, and
an artifact that is provably that commit. The fresh-install proof is
[`os-test-matrix.md §10`](../testing/os-test-matrix.md).

### 11.2 Versioning

- **One version for the whole product.** There is no root package.json or
  workspace ([CONTRIBUTING.md](../../../CONTRIBUTING.md)): standalone npm
  packages and one Cargo workspace. They release together, so they carry one
  semver, and `launcher/test/unit/version-parity.test.ts` refuses a tree
  where any manifest (package.json, package-lock.json, `[workspace.package]`
  in `interceptors/Cargo.toml`, the inspect-mcp `SERVER_VERSION` constant)
  disagrees with `launcher/package.json`.
- **`scripts/set-version.sh <semver>` is the only bump path.** It rewrites
  every manifest and prints what changed; it never commits or tags.
- **`mandu --version`** prints `mandu <version>` from the launcher's
  package.json (`update-check.ts launcherVersion`), in both the dev checkout and the
  installed bundle. Whether a newer release is out is the update notice's
  (§11.5): a launch line and a `mandu doctor` row.
- **`CHANGELOG.md`** at the repo root, one section per version, written for
  the user of `@mandusec/mandu` (what changed for them), not the designer.
- **The tag is `v<version>`**, annotated. `release-pack` refuses a tag that
  does not equal the manifests' version, so a mistagged commit cannot
  produce an artifact. Tags are never moved: a red release is fixed with a
  patch bump and a new tag.
- 0.x semantics: minor bumps may change behavior and the `mandu.db` schema
  (`runtime-instances.md` §9a); patch bumps do not.

### 11.3 The release steps

A `v*` tag builds, tests on fresh guests, packs and publishes. No automatic
step holds a credential; only the manual publish sees a token.

1. **Test**: `scripts/ci/vm-run.sh --kind unit,component,stack,replay-drill,sandbox`,
   the per-push kinds ([`test-organization.md`](../testing/test-organization.md)
   §3) in a disposable KVM guest with no network and no credential.
2. **Fresh install**: `scripts/matrix/run-matrix.sh --require ubuntu-2404
   --require ubuntu-2604` (the `install` kind): the fresh-install suite on a
   real 24.04 and a real 26.04 guest (`npm install -g <tarball>` as a fresh
   user, no sudo, `confined`, a launch that exits 0). `--require` makes a
   SKIP a FAIL.
3. **Pack**: `scripts/ci/release-pack.sh`, inside the same kind of guest
   (`vm-run.sh --exec`): tag == version; version-parity + license-manifest +
   node-floor; `scripts/build-native.sh` for linux-x64 and `--target
   aarch64-unknown-linux-gnu` for linux-arm64 (the bundle's native bins,
   which a plain `cargo build` skips; both ride in the one tarball via
   `MANDU_NATIVE_BIN_DIRS`, §5); each arm64 bin started once under
   qemu-user; the tarball must hold all three bins for both tags; the
   npm-pack self-contained-artifact oracle; `npm pack` →
   `release/mandusec-mandu-<v>.tgz` + `SHA256SUMS` + `COMMIT`.
4. **Publish** (manual): checks `SHA256SUMS`, then `npm publish
   --ignore-scripts` of that artifact, executing no code from the commit.
   npm refuses a tarball packed in the source repository, whose
   `launcher/package.json` is `private: true` (and whose bundle can carry a
   module the public tree leaves out); one packed in the public tree has no
   `private`. Until this step packs the public tree, the npm tarball is
   packed by hand from it (§11.4).

Each step runs by hand on any host with `/dev/kvm`: `scripts/ci/vm-run.sh`
for the test step, `scripts/matrix/run-matrix.sh --require ubuntu-2404
--require ubuntu-2604` for the fresh install, and `scripts/ci/vm-run.sh
--exec "bash scripts/ci/release-pack.sh v<version>"` for the pack (the
tarball comes back under the run's `artifacts/release/`). The frozen
integrity lane is not a release step: it runs only when the integrity axis is
revived ([`protection-modes.md §10`](../architecture/protection-modes.md) §5).
The public repository's GitHub CI ([`continuous-integration.md §12`](../testing/continuous-integration.md))
runs the offline subset and must be green on the tagged commit (while the
repository is private no push starts it: both workflows are started by hand on
the snapshot before the release is published).

### 11.4 Channels and the publish gate

- **Now:** npm (`npm install -g @mandusec/mandu`, below), or a checkout via
  `scripts/bootstrap.sh`. A version has one artifact: the public-tree
  tarball that went to npm. Any other channel for that version (a GitHub
  release, `install.sh --package`) carries that same file and its
  `SHA256SUMS`, never a tarball `release-pack` packed in the source
  repository.
- **Beta (from 2026-10-04):** prerelease builds `0.2.0-beta.N`, each a
  `release-pack` tarball released with its `SHA256SUMS` on the one GitHub
  repository, `ManduSec/mandu` (private until launch; decided 2026-10-04 not
  to keep a second, files-only repository). Each release carries a **release
  copy** of `install.sh`: the publisher rewrites its `PACKAGE_DEFAULT` /
  `PACKAGE_DEFAULT_SHA256` lines to the release's versioned tarball URL and
  SHA-256. While the repository is private, an invited tester downloads the
  release's files (signed in, or `gh release download -R ManduSec/mandu -p
  '*' --clobber`) and runs `sh install.sh` there: the copy finds its tarball
  beside it and installs that file. Once the repository is public, the same
  copy works as `curl -fsSL
  https://github.com/ManduSec/mandu/releases/latest/download/install.sh | sh`,
  downloading the tarball itself. Either way the hash is checked and a
  mismatch installs nothing (`--sha256`; `launcher/test/unit/install-sh.test.ts`,
  and the component e2e over the real packed tarball). By hand: `npm install
  -g ./mandusec-mandu-<v>.tgz` after `sha256sum -c SHA256SUMS`. The public
  launch is `0.2.0` (0.1.0 was an internal pilot, never published).
- **Public npm (`@mandusec/mandu`):** from `0.2.0-beta.6` (2026-10-19), as
  `latest`. The M5 unlock (§8) is a strip rule of the public export: the
  source repository's `launcher/package.json` keeps `private: true`, and
  the public tree's has none, so npm accepts only a tarball packed from the
  public tree. That tarball is packed by hand: the public tree of the
  release commit, its own `scripts/build-native.sh` for linux-x64 and
  linux-arm64 (Rust 1.75.0, with `RUSTFLAGS="--remap-path-prefix=<cargo
  home>=/cargo --remap-path-prefix=<tree>=/mandu"` so no build path ships;
  the script itself passes none),
  `MANDU_NATIVE_BIN_DIRS`, the release-pack gates and `npm pack`; checked
  (all six bins, no module the public tree lacks, `NOTICE`, no `private`,
  the export's denylist and gitleaks over the unpacked package, an install
  whose `mandu doctor` reports `posture: confined`); then `npm publish
  <tgz> --access public --tag latest --ignore-scripts` from the
  maintainer's own terminal (npm 11+ refuses a prerelease without `--tag`,
  and `latest` is what a plain `npm install -g @mandusec/mandu` resolves).
  After publishing, `dist.shasum` on the registry must equal the checked
  file's SHA-1. `repository` is set when the GitHub repository is public:
  the npm page keeps a version's metadata, and a link to a private
  repository is a 404.
- **What the npm page shows:** the package ships `launcher/README.md`, a
  user-facing page with absolute links only (listed in `package.json` `files`;
  the npm-pack e2e asserts it is in the tarball and byte-identical). User-facing
  CLI text never names a repo-relative `docs/` path, which an npm install lacks:
  it names the public URL from `launcher/src/docs-url.ts` (`DOCS_BASE_URL`,
  `github.com/mandusec/mandu/blob/main/`), and a unit test checks that every
  `docsUrl()` target exists in the tree.

### 11.4a The public repository

The public repository is a snapshot of the development repository: one
commit per release, holding only the paths an allow-list names and checked
for leaks before the commit is made.

### 11.5 The update notice (2026-10-07)

Status: **BUILT** (`launcher/src/update-check.ts`). Mandu ships security
releases (0.2.0-beta.3 fixed real leaks), and before this a user on an old
build heard of a new one only from us.

**What the user sees.** One line on stderr among a launch's notices
(launch-banner.ts passes it through unchanged, under the mode line):

```
mandu: ! Mandu 0.2.0 is out (you have 0.2.0-beta.3); to update: npm install -g @mandusec/mandu@0.2.0
mandu: ! Mandu 0.2.0-beta.4 is out with SECURITY fixes (you have 0.2.0-beta.3); update now: npm install -g @mandusec/mandu@0.2.0-beta.4
```

The npm install line pins the advertised version, so a different npm dist-tag
cannot send the user to another release. Installed packages use npm unless
`scripts/install.sh` wrote `.mandu-installer` in that package's root; the
installer's packages and opted-in source checkouts keep that release's own
`install.sh` line (§11.4), which verifies the tarball's SHA-256. The marker is
local installation state and is never packed. Both launch notices and doctor
use this channel, including cached/offline answers. Installations made by an
older curl installer have no marker and use npm advice until reinstalled.
`mandu doctor` adds `version <v>` and one row to its "Installed" section:
✓ newest, · a newer release, ✗ a newer release with security fixes, or why
it did not ask.

**Which release.** The newest non-draft release tagged `v<semver>`, by semver
precedence with prereleases (`0.2.0-beta.3` < `0.2.0-beta.4` < `0.2.0`): a
prerelease user is told of the next prerelease and of the release, a release
user of releases only. "SECURITY" when any release after the running one, up
to the newest, has `<!-- mandu: security-release -->` in its notes (an HTML
comment, invisible on the release page; the release notes checklist says to
add it). A running version that is not semver is told nothing.

**When.** At most once a day. A launch prints the answer the previous check
left in the cache, so it never waits on the network; when that answer is a
day old it asks again in the background (one request, a 5 s budget, the
socket and timer unref'd so the launcher never stays alive for it). The first
launch after an install therefore prints nothing; the next one does.
`mandu doctor` always asks afresh (a 4 s budget) and falls back to the cached
list, saying how old it is. `MANDU_UPDATE_CHECK=0` (config
`update-check = false`) turns both off; `=1` turns them on anywhere. Unset,
they run only from an installed package (not a source checkout), outside CI
(`CI` set), and at a terminal (stderr for a launch, stdout for doctor), so a
test, a script or a pipe never touches the network.

**Errors are silent.** Offline, a 404 (the repository is private during the
beta, and unauthenticated requests see nothing), a rate limit, a redirect (not
followed), a body over 2 MiB or not a release list: no line, and the attempt
is still stamped, so the next one waits a day too; the last good list is kept.

**What is sent.** One HTTPS GET of
`https://api.github.com/repos/ManduSec/mandu/releases?per_page=30` with two
headers, `Accept: application/vnd.github+json` and `User-Agent:
mandu-update-check`: no version, no session, user, machine or token, no
cookie. GitHub sees the caller's IP address and the time, as for any
download. `MANDU_UPDATE_CHECK_URL` points it elsewhere for tests (https, or
http on a loopback address only).

**Security.** The request is made by the launcher, outside the agent's
confinement, on its own fresh HTTP agent (no proxy from the environment, no
keep-alive), before the session's services start: it neither goes through
nor opens any of the session's egress paths, and nothing of the session is
in it (the component test asserts the request's bytes hold none of the
launch's key, home, socket or work folder). Of the response only the release
tags, each checked to be a semver version, and the marker's presence are
kept; no other text from it reaches the terminal.

The cache is the path table's `update-check`, `<home>/cache/update-check.json`
(on-disk-layout.md §3), `0600` in a `0700` directory, written by
`safe-file.ts`'s rename, read through `O_NOFOLLOW` and refused unless a
regular file of this user, closed to group and other writes, under 256 KiB
and well-formed. The Mandu home is closed to the agent's writes in every
mode but `off` (on-disk-layout.md §4), so the agent cannot forge it.
**Residual:** something that can write the home (an `off` session, a
program outside Mandu running as the user) can write an "up to date" answer
and silence the launch notice until the next check; a `checkedAt` in the
future counts as stale, so that lasts at most a day, and `mandu doctor`,
which always asks afresh, is not affected. The answer is advisory either
way: it changes no protection, and a forged "newer release" can only print
the fixed install line for a version tag on the real repository.

The release list still comes from GitHub for every channel. Publish the npm
package before the matching GitHub release so the advertised exact version is
available. A private or unavailable GitHub release list cannot announce a new
npm version; npm registry polling is not implemented.

### 11.6 What this does not do

- No `.deb`/brew/curl-sh channels pointing at a public artifact until the
  first public release (§3).
- No macOS native artifact: the experimental runtime uses the same pure-JS package at posture `read-blocked`
  (`os-test-matrix.md`); the bundle ships native bins for linux-x64 and
  linux-arm64 only. The arm64 bins are cross-built and started under
  qemu-user, **not run on arm64 hardware**: no matrix target boots an arm64
  guest yet (`os-test-matrix.md` §3).
- No `mandu.db` migrations: a schema change is a refusal with a remedy
  (`runtime-instances.md` §9a).

### 11.7 Build provenance and `mandu version` (2026-10-19)

Status: **BUILT** (`launcher/scripts/build-info.mjs`,
`launcher/src/version-report.ts`). Found on a host that moved from a source
checkout to the npm package: the npm `mandu` misbehaved, and nothing said
which code was running. `mandu --version` printed the release only, so two
builds of one release looked alike, and an installed package could not say
its commit at all: the tarball is packed from the exported tree (§11.4),
which has no `.git`.

**The record.** `build-bundle.mjs` writes `dist/build-info.json` beside the
bundles: `version`, `sourceCommit` (the source repository's),
`publicCommit` (the public repository's), `publicAhead`, `dirty`. Each
commit comes from `MANDU_BUILD_SOURCE_COMMIT` / `MANDU_BUILD_PUBLIC_COMMIT`
first (the release pack of the exported tree knows both and sets them),
else from git when the tree is a work tree: a HEAD whose first-parent
history reaches a snapshot commit (its `Mandu-Snapshot: <source commit>`
trailer, which the export writes) is a public clone, so the public commit is
HEAD, the source commit is the trailer's, and `publicAhead` counts the
commits on top; any other HEAD is the source repository's. With neither,
the commit is null ("not recorded"), never a guess. There is no timestamp
and no path in it, so two builds of one commit stay byte-identical, and the
reader re-checks every commit as hex. `release-pack.sh` prints the record
and fails a pack whose record names no source commit.

**The command.** `mandu version [--json]` (a reserved verb; `--version`
stays the one line `mandu <version>` that scripts and the release steps
read). It reports:

- *this mandu*: argv[1] and its realpath; how it is installed, from where
  the launcher module itself is (an npm package, a checkout's own build, a
  checkout from TypeScript), independent of any environment override; the
  release; the commits: an npm package's from `build-info.json`, a
  checkout's from git now (a recorded file would go stale after a pull that
  did not touch the bundles' inputs, §5.1);
- *every `mandu` on PATH*, in order, classified by its resolved file: the
  npm bin, a checkout's `bin/mandu.mjs` or `mandu-run.sh`, the shim
  `scripts/bootstrap.sh` writes (it names its checkout in `REPO_ROOT`), or
  something else; and which one is running;
- *the running services*: the arbiter on the socket a launch would use,
  asked `hello` (never started), compared with this mandu by the launch's
  own `versionVerdict` (runtime-instances.md §4.1); its pid, start time and
  the folder its code runs from (`/proc/<pid>/cwd`); the systemd unit that
  keeps it alive (§4.1a);
- the environment variables that change which code or services run
  (`MANDU_DEV_REPO`, `MANDU_LAYOUT`, `MANDU_FROM_SOURCE`,
  `MANDU_ARBITER_SOCK`, `MANDU_RUNTIME_DIR`, `MANDU_HOME`);
- the global npm package (npm_config_prefix, else ~/.npmrc's `prefix`, else the running node's prefix: never `npm` itself, which writes under `~/.npm`), when there is one.

Then the problems, each with its fix: the environment forces another
layout (`MANDU_DEV_REPO` left by a source install makes an npm mandu run
its services from that tree); typing `mandu` runs another one; another
`mandu` waits behind this one on PATH; the services are another release or
build (supervised by a unit: disable it; pinned: unset or restart it;
otherwise the next launch replaces them unless a session uses them); the
global npm package is not the mandu running; Node below the floor.
`mandu doctor` reuses the report: the commit under "Installed", the install
problems there, the services' under "Mandu service". The report is
read-only and every effect is injected (`VersionDeps`).

**Tests.** `launcher/test/unit/build-info.test.ts` (the source and public
cases, `publicAhead`, the override, nothing guessed, the reader's checks,
against a real git repository with a snapshot trailer, byte-identical
records); `launcher/test/unit/version-report.test.ts` (classification, every
problem rule, the incident's shape, an npm package with no record);
`launcher/test/component/version-command.test.ts` (the real CLI from this
checkout: its live commit, a bootstrap shim first on PATH, a stand-in older
arbiter asked over its socket, `--json`, `--version`, `--help`);
`launcher/test/component/npm-pack.test.ts` (the packed tarball records the
checkout's provenance: source HEAD in the internal repository, source
snapshot trailer plus public HEAD in a public checkout, or explicit release
build overrides; the installed `mandu version --json` reports the npm
install, both commits, its own bin first on PATH and no problems, and names
`MANDU_DEV_REPO` when it is set).
