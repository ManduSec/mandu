/**
 * secret-twins — keep RAW SECRET BYTES out of the agent's world, unprivileged
 * (docs/design/confidentiality/confidentiality.md §7.2/§7.3; plan 4′).
 *
 * The invariant, realized per OS:
 *
 *   Linux — THE TWIN. For each registered secret, write a file whose CONTENT IS
 *   ITS SYMBOL and `bwrap --bind` it over the real path inside the agent's mount
 *   namespace. `cat ~/.aws/credentials` yields `$MDU:nomodel_Read[3fa9]`. Reads
 *   SUCCEED (shell idioms keep working, the egress gate substitutes the real
 *   value at a bound destination) but the raw bytes are ABSENT from every world
 *   the agent — or anything it spawns, or anything an injection smuggles in —
 *   can reach.
 *
 *   macOS — THE DENY. No mount namespaces, so no substitution is possible.
 *   A Seatbelt (`sandbox-exec`) profile denies `file-read*` and `file-write*`
 *   on the same paths, and a rename of any directory above them: reads FAIL.
 *   Same security, harsher ergonomics; routing comes from the registry
 *   instead of from reading the file (seatbelt-profile.ts renders it).
 *
 * This module is PURE (plan/render only). Materializing the twin files and
 * spawning are the caller's job (run.ts), so the whole policy is unit-testable
 * with no filesystem and no child processes.
 *
 * Mandu-new (no reference origin).
 */
import { renderSeatbeltProfile, seatbeltWrapArgv } from "./seatbelt-profile.js";

/** One registered secret: the real path and the symbol standing for it. */
export interface SecretTwin {
  /** Absolute path of the real secret file (the bind/deny target). */
  path: string;
  /** The arbiter-minted symbol whose text becomes the twin's content. */
  symbol: string;
  /** The STRUCTURED twin text (plan 10 §2.4): the file's own keys with each
   *  secret value replaced by its field symbol. When present it is the twin's
   *  content; absent ⇒ the whole-file twin (the symbol alone). */
  twin?: string;
  /** Whole-file twin only: the original's final line terminator as the
   *  arbiter reported it (registry.ts `terminator`). Absent ⇒ `\n`. */
  terminator?: string;
  /** The confidentiality level the arbiter reports for the file (secret-setup.ts
   *  `secretLevel`); carried to the guard's policy file, which only prints it. */
  level?: string;
}

/** The whole-file twin's text: the symbol, then the original's final line
 *  terminator (`""`, `"\n"` or `"\r\n"`), so a file that ends without a
 *  newline reads back without one (an escalated Codex `cat` quoted the extra
 *  byte as a blank row, differential-interactive.md §16). One bit of the
 *  file's shape and never its length. Anything else from the wire (an older
 *  arbiter sends nothing) is the old `\n`. Pure. */
export function wholeFileTwinText(symbol: string, terminator?: string): string {
  const end = terminator === "" || terminator === "\n" || terminator === "\r\n" ? terminator : "\n";
  return `${symbol}${end}`;
}

/** A twin file the caller must materialize before spawning. */
export interface TwinFile {
  /** Where to write it (inside the scope run dir, mode 0600). */
  twinPath: string;
  /** Exactly what to write: the structured twin text when the arbiter
   *  produced one, else the symbol token + the original's final line
   *  terminator (`wholeFileTwinText`), nothing else. */
  content: string;
  /** The real path it will be bound over. */
  targetPath: string;
  /** The secret's level, when known (SecretTwin.level). */
  level?: string;
}

export interface SecretTwinPlan {
  /** Twin files to write before spawning (empty ⇒ nothing to do). */
  files: TwinFile[];
  /** argv that wraps the agent exec. EMPTY when there is nothing to mask —
   *  we never pay for a sandbox we do not need. */
  wrapArgv: string[];
  /** Registered secrets that got NO bind, each with the reason — logged by the
   *  caller so a dropped twin is never silent (a duplicate spelling of a file
   *  already bound, or a file that vanished between discovery and the plan). */
  skipped: Array<{ path: string; reason: string }>;
}

export interface TwinPlanOpts {
  /** Map a registered path to the REAL path the bind must land on (the
   *  caller passes `realpath`). bwrap creates the mount point INSIDE the new
   *  namespace and cannot mkdir through a symlinked parent — a registered
   *  `~/tools/linux/…` spelling of a file under `/mnt/…` failed with `Can't
   *  mkdir parents` and, being fail-closed, bricked every launch on that host
   *  (2026-09-05). Binding on the resolved path masks EVERY spelling of the
   *  file. Return null when the file no longer exists: it is then skipped —
   *  a file that is not there leaks nothing. Defaults to identity so the
   *  planner stays pure for the unit tests. */
  resolveTarget?: (path: string) => string | null;
  /** Extra bwrap flags placed after the hardening flags and before the twin
   *  binds: on WSL, the interop hiding (`wsl.ts` `wslTwinWrapFlags`). */
  extraFlags?: string[];
}

/** Basename-safe, collision-free twin filename for a target path. */
function twinName(targetPath: string, index: number): string {
  const base = targetPath.split("/").filter(Boolean).pop() ?? "secret";
  const safe = base.replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 40);
  // The index keeps two same-named files (~/.aws/credentials and
  // ~/.config/gcloud/credentials) from colliding.
  return `${String(index).padStart(3, "0")}-${safe}`;
}

/**
 * Plan the Linux twin sandbox.
 *
 * The bwrap invocation is `--dev-bind / /` (the agent keeps its normal view of
 * the machine — this is a MASK, not a jail: net, /proc and the workspace all
 * stay reachable) followed by one `--bind <twin> <real>` per secret. Order
 * matters: the binds come after the root bind so they win.
 *
 * `--die-with-parent` so a killed launcher never orphans a sandboxed agent.
 *
 * ── Hardening: what this wrap ADDS, and what it must NOT ──────────────────────
 * This wrap goes around the WHOLE agent process — a live, interactive,
 * NETWORKED, parent-supervised Claude Code — not an isolated sandbox. So it only
 * adds isolation that is invisible to such a process, and deliberately withholds
 * isolation that would break it.
 *
 * ADDED (safe, unprivileged, on by default), placed AFTER --die-with-parent and
 * BEFORE the binds:
 *   --cap-drop ALL   the agent needs no in-userns capabilities; drop them all.
 *   --unshare-ipc    the agent needs no shared SysV IPC / shm; isolate it.
 *   --unshare-uts    the agent needs no shared hostname; isolate it.
 *   --unshare-pid    with a fresh `--proc /proc`: the agent's tree sees and
 *                    signals only itself, so it cannot kill (or read the
 *                    procfs of) the arbiter, the proxies or any host process
 *                    (sandbox review finding 3). The first try (2026-09-28)
 *                    broke every `/proc/self/…` open under the guard, which
 *                    runs outside this namespace and for which procfs `self`
 *                    names nobody there; the guard now names the tracee's own
 *                    entry by the number that procfs shows (fs-supervisor
 *                    tracee.rs `own_entry_in`, `walk_to_proc_self`) and
 *                    translates §4.1's pid numbers to host pids
 *                    (net-supervisor `procfs_targets`). Side effect: what the
 *                    agent starts in the background ends with the session
 *                    (the namespace dies with its first process).
 *
 * ON WSL ALSO (`wsl.ts` `wslTwinWrapFlags`, via `opts.extraFlags`): an empty
 *   tmpfs over /run/WSL, /dev/null over /init, WSL_INTEROP unset. Windows
 *   interop starts a program outside this wrap that reads the REAL files
 *   through \\wsl.localhost; hiding its socket costs the agent only Windows
 *   conveniences (opening a browser, pasting from the Windows clipboard).
 *
 * WITHHELD ON PURPOSE — each of these would break the live agent:
 *   --unshare-net    would sever the agent from the 127.0.0.1 anthropic-proxy
 *                    it must reach for every model call.
 *   --new-session    detaches the controlling TTY, which kills Claude Code's
 *                    interactive terminal.
 *   --clearenv       would wipe ANTHROPIC_BASE_URL / proxy / arbiter env the
 *                    agent depends on to route through the defense.
 *   --disable-userns the agent may itself spawn nested bwrap sandboxes
 *                    (exec-supervisor AgentShell); blocking nested userns could
 *                    break that.
 */
export function planSecretTwins(
  secrets: readonly SecretTwin[],
  twinDir: string,
  bwrapPath = "bwrap",
  opts: TwinPlanOpts = {},
): SecretTwinPlan {
  if (secrets.length === 0) return { files: [], wrapArgv: [], skipped: [] };

  const resolve = opts.resolveTarget ?? ((p: string) => p);
  const skipped: Array<{ path: string; reason: string }> = [];
  // Deterministic order: sort by registered path so the argv (and the tests)
  // are stable regardless of registry iteration order.
  const sorted = [...secrets].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));

  // Resolve each registered path to the real bind target; one bind per REAL
  // file (two spellings — a symlink and its target — must not race for the
  // same mount point), and a vanished file gets no bind at all.
  const boundBy = new Map<string, string>(); // real target → first registered path
  const targets: Array<{ secret: SecretTwin; target: string }> = [];
  for (const s of sorted) {
    const target = resolve(s.path);
    if (target === null) {
      skipped.push({ path: s.path, reason: "file no longer exists — nothing to confine" });
      continue;
    }
    const first = boundBy.get(target);
    if (first !== undefined) {
      skipped.push({ path: s.path, reason: `same file as ${first} — bound once at ${target}` });
      continue;
    }
    boundBy.set(target, s.path);
    targets.push({ secret: s, target });
  }
  if (targets.length === 0) return { files: [], wrapArgv: [], skipped };

  const files: TwinFile[] = [];
  const binds: string[] = [];
  targets.forEach(({ secret, target }, i) => {
    const twinPath = `${twinDir.replace(/\/$/, "")}/${twinName(target, i)}`;
    files.push({
      twinPath,
      content: secret.twin ?? wholeFileTwinText(secret.symbol, secret.terminator),
      targetPath: target,
      ...(secret.level !== undefined ? { level: secret.level } : {}),
    });
    binds.push("--bind", twinPath, target);
  });

  // Root bind first (agent keeps its normal FS view), then the hardening flags
  // (see the block above for why these three and not the others), then the
  // per-secret binds LAST so they win over the root bind.
  const bare = bareTwinWrap(bwrapPath, opts.extraFlags ?? []);
  return { files, skipped, wrapArgv: [...bare.slice(0, -1), ...binds, "--"] };
}

/** The twin wrap with no bind of its own: the root bind and the hardening.
 *  A launch with no secret to bind still runs it to mask the Mandu home
 *  (secret-setup.ts `ownStoresHidden`) when no guard can hide it. Pure. */
export function bareTwinWrap(bwrapPath: string, extraFlags: readonly string[] = []): string[] {
  return [bwrapPath, "--dev-bind", "/", "/", ...TWIN_WRAP_HARDENING, ...extraFlags, "--"];
}

/**
 * The twin wrap's ops that hide the Mandu home (on-disk-layout.md §4):
 * `--tmpfs <dir>` over each masked directory (the home, the launch's event
 * dir; the outermost only), then `--bind <dir> <dir>` for each carve-out of
 * the home (the integrity modes' AgentView, `full`'s repo.git), whose source
 * bwrap takes from the host's tree, so it comes back over the tmpfs at its
 * own path. The caller places these among the wrap's leading flags, BEFORE
 * the secret-twin binds: a twin whose file lies inside a carve-out then lands
 * on the carve-out, where a later tmpfs would have buried it under the raw
 * copy bound back after it. A carve-out outside every mask is still bound
 * (onto itself, a no-op). Pure.
 */
export function homeMaskOps(maskDirs: readonly string[], carveOuts: readonly string[]): string[] {
  const out: string[] = [];
  for (const d of [...new Set(maskDirs)].sort()) out.push("--tmpfs", d);
  for (const c of [...new Set(carveOuts)].sort()) out.push("--bind", c, c);
  return out;
}

/** One extra mask for the twin wrap (secret-setup.ts): a git object-store
 *  file served its sanitized twin or made unreadable (git-object-twins.ts),
 *  bound like a secret's twin. */
export interface ExtraBind {
  twinPath: string;
  targetPath: string;
}

/**
 * Add the object-store binds and the directory masks to a planned wrap, just
 * before its trailing `--`: `--tmpfs <dir>` hides a directory the agent has no
 * business reading (the Mandu home, on-disk-layout.md §4), then one `--bind`
 * per extra bind (an object-store twin, a carve-out of the home bound back at
 * its own path, an unreadable file over a store file), parents before
 * children. Masks go first so a bind can never land inside a directory a
 * later tmpfs would cover; bwrap takes every bind SOURCE from the host's
 * tree, not the masked view, so a twin cached under the masked home still
 * binds. An empty wrap stays empty (the guard alone serves the twins then).
 * Pure.
 */
export function withObjectTwins(wrapArgv: readonly string[], binds: readonly ExtraBind[], maskDirs: readonly string[]): string[] {
  if (wrapArgv.length === 0) return [];
  const end = wrapArgv.lastIndexOf("--");
  const head = end >= 0 ? wrapArgv.slice(0, end) : [...wrapArgv];
  const extra: string[] = [];
  for (const d of [...maskDirs].sort()) extra.push("--tmpfs", d);
  const seen = new Set<string>();
  for (const b of [...binds].sort((a, z) => (a.targetPath < z.targetPath ? -1 : a.targetPath > z.targetPath ? 1 : 0))) {
    if (seen.has(b.targetPath)) continue;
    seen.add(b.targetPath);
    extra.push("--bind", b.twinPath, b.targetPath);
  }
  return [...head, ...extra, "--"];
}

/** The twin wrap's flags between the root bind and the binds (the block
 *  above says why these and not the others). Shared with the nesting probe
 *  so the probe runs the wrap the launch would run. */
export const TWIN_WRAP_HARDENING: readonly string[] = [
  "--die-with-parent",
  "--cap-drop", "ALL",
  "--unshare-ipc",
  "--unshare-uts",
  "--unshare-pid",
  "--proc", "/proc",
];

/** What a sandbox the agent's tools start looks like: a bubblewrap with its
 *  own user, pid and net namespaces (Codex's shell sandbox, Mandu's exec box). */
export const NESTED_SANDBOX_PROBE: readonly string[] = [
  "--unshare-user", "--unshare-pid", "--unshare-net", "--ro-bind", "/", "/", "--", "true",
];

/**
 * The nesting probe (os-test-matrix.md §10.14.1 item 6): the twin wrap as
 * the launch would run it, around a nested bubblewrap as the agent's tools
 * would start one. Exit 0 = a sandbox can start inside the wrap.
 *
 * WHY: on Ubuntu 26.04 the distro's `bwrap-userns-restrict` AppArmor profile
 * moves every program a /usr/bin/bwrap sandbox runs into `unpriv_bwrap`,
 * which may not create a user namespace. Inside the twin wrap, Codex's shell
 * sandbox and Mandu's own exec box then die with "No permissions to create a
 * new namespace", so every shell command the agent runs fails. Nothing the
 * launcher can do without root lifts a confinement the wrap's children
 * inherit, so the launch probes instead and serves the twins with the guard
 * alone where the probe fails (secret-setup.ts `applySecretTwins`).
 */
export function nestedSandboxProbeArgv(
  bwrapPath = "bwrap",
  extraFlags: readonly string[] = [],
  innerBwrap = bwrapPath,
): string[] {
  // The outer bwrap is the one the wrap runs (Mandu's own copy where `mandu
  // setup` installed it, bwrap-grant.ts); the inner is the one the agent's
  // tools find: the same binary, since the copy's directory goes first on
  // the agent's PATH and the distribution's is otherwise the first there.
  // Named by absolute path by every launch caller: a bare `bwrap` would be a
  // PATH search inside the wrap, which could find one planted in the
  // workspace (bwrap-path.ts).
  return [bwrapPath, "--dev-bind", "/", "/", ...TWIN_WRAP_HARDENING, ...extraFlags, "--", innerBwrap, ...NESTED_SANDBOX_PROBE];
}

/**
 * The secrets-only macOS Seatbelt profile (confidentiality.md §7.3): each
 * credential file unreadable and unwritable, and neither it nor a directory
 * above it renameable. A thin wrapper over `renderSeatbeltProfile`
 * (seatbelt-profile.ts), which renders the launch's WHOLE profile (Mandu's
 * state, write-protect, the network and Unix-socket confines, host
 * services); the launch uses that one (seatbelt-setup.ts).
 *
 * SBPL is LAST-MATCH-WINS, which is what makes this composable: a blanket
 * `(allow file-read*)` — which the AgentShell profile in
 * `exec-supervisor/src/sandbox.rs` already emits, justified by the *integrity*
 * lattice's E4 guarantee — is overridden by the denies that follow it. That
 * blanket allow is exactly the line that is safe for integrity and WRONG for
 * confidentiality (a subprocess seeing raw secret bytes IS the threat here).
 *
 * `carveOuts` (on-disk-layout.md §4): the home's carve-outs, allowed back
 * after the own-store denies. `humanDirs` (arbiter-human-plane.md §5): the
 * arbiter's human-plane socket directories. A `file-read*` rule does not
 * cover connect(2) to a Unix socket; Seatbelt checks that as
 * `network-outbound` on the socket's path, so each gets a connect deny AND a
 * read/write deny, after every allow that could reach them.
 *
 * Returns null when there is nothing to deny (never wrap for nothing).
 */
export function seatbeltSecretProfile(secrets: readonly SecretTwin[], ownStores: readonly string[] = [], carveOuts: readonly string[] = [], humanDirs: readonly string[] = []): string | null {
  if (secrets.length === 0 && ownStores.length === 0 && humanDirs.length === 0) return null;
  // Mandu's own stores of originals (secret-setup.ts `ownStoresHidden`): the
  // whole Mandu home, the event dir, the CA key, as the state component
  // (`subpath` matches the path itself and everything under it), the home's
  // carve-outs allowed back after them.
  return renderSeatbeltProfile({
    secrets: secrets.map((s) => s.path),
    stateDirs: [...ownStores],
    stateCarveOuts: [...carveOuts],
    humanDirs: [...humanDirs],
  });
}

/** The macOS wrap argv for a rendered profile file (seatbelt-profile.ts). */
export { seatbeltWrapArgv };
