/**
 * bwrap-grant — Mandu's own bubblewrap and its AppArmor grant
 * (docs/design/confidentiality/rootless-confinement-ubuntu-2404.md §12.3, §12.5 option 2).
 *
 * WHY. Ubuntu restricts unprivileged user namespaces per binary through
 * AppArmor. Until 2026-09-27 `mandu setup` granted `/usr/bin/bwrap` itself
 * (`profile bwrap /usr/bin/bwrap flags=(unconfined) { userns, }`, plus the
 * same for `/usr/bin/unshare`). That had three problems, all VM-verified:
 *   - it was a trampoline: every program on the host, run under bwrap or
 *     unshare, got a user namespace WITH capabilities, which is what the
 *     restriction exists to prevent;
 *   - its profile is NAMED `bwrap`, like Ubuntu's own `bwrap-userns-restrict`
 *     (shipped enabled from 25.04, an extra on 24.04). Whichever file loads
 *     last wins: on a 24.04 host upgraded to 26.04 Mandu's leftover silently
 *     disables Ubuntu's restriction host-wide; with the distro profile on top
 *     Mandu's is inert (fork H, §12.3 "Verified");
 *   - on 26.04 it is not needed for userns, yet the distro profile forbids a
 *     sandbox inside a bwrap sandbox, so the secret bind wrap stopped Codex's
 *     shell and Mandu's exec box (§12, the guard-only fallback).
 *
 * THE DESIGN (option 2, VM-verified on 24.04 and 26.04). `mandu setup` copies
 * the system bwrap to a ROOT-OWNED path, `/usr/lib/mandu/bin/bwrap`, and loads
 * `/etc/apparmor.d/mandu-bwrap` (scripts/apparmor/mandu-bwrap), whose two
 * Mandu-named profiles attach to that path only:
 *   - `mandu_bwrap` (the copy): userns, capabilities, mounts. It runs bwrap
 *     (the copy or the system one) as itself, and everything else stacked
 *     with `mandu_child`;
 *   - `mandu_child`: every capability denied, no userns, except that bwrap
 *     transitions back to `mandu_bwrap`.
 * So inside Mandu's wrap only bwrap holds capabilities, a sandbox nests
 * (Codex's, the exec box), `unshare -Ur` is refused, and anyone who runs the
 * copy directly gets a sandbox whose contents hold nothing: no trampoline.
 * bwrap sets NO_NEW_PRIVS, so every transition keeps `mandu_bwrap` in the
 * label (a `Cx` child would be refused "no new privs"), and a program with its
 * own host profile runs as `<its profile>//mandu_bwrap//mandu_child`: the
 * host's confinement of it is kept, not dropped.
 *
 * The launch uses the copy when it is IN FORCE (root-owned, not writable by
 * anyone else, and able to create a user namespace, i.e. its profile is
 * loaded): the secret wrap runs it, and its directory goes first on the
 * agent's PATH so Codex and the exec box find it where no wrap is around
 * them. Otherwise the launch runs the distribution's bubblewrap, by absolute
 * path (bwrap-path.ts: an administrator's `bwrap_path`, else the first on
 * PATH outside the current directory), or none.
 *
 * Pure decisions over injectable facts; the real probes are memoized per
 * process (one bwrap spawn).
 *
 * Mandu-new (no reference origin).
 */
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, statSync } from "node:fs";
import { dirname } from "node:path";
import { adminBwrap, systemBwrap, systemBwrapBin, type AdminBwrap, type SystemBwrap } from "./bwrap-path.js";
import { cachedProbe, probeCacheEnabled } from "./probe-cache.js";

export const MANDU_BWRAP_DIR = "/usr/lib/mandu/bin";
export const MANDU_BWRAP = `${MANDU_BWRAP_DIR}/bwrap`;
export const SYSTEM_BWRAP = "/usr/bin/bwrap";
export const APPARMOR_DIR = "/etc/apparmor.d";
/** The profile file Mandu installs (defines `mandu_bwrap` and `mandu_child`). */
export const MANDU_PROFILE_FILE = `${APPARMOR_DIR}/mandu-bwrap`;
/** The pre-2026-09-27 grants, by file name under /etc/apparmor.d. Mandu no
 *  longer installs them; `mandu setup` removes a Mandu-marked one. */
export const LEGACY_PROFILES = ["bwrap", "unshare"] as const;
export type LegacyProfile = (typeof LEGACY_PROFILES)[number];

/** First-line marker of a profile Mandu created: the ownership test. */
export const OWNERSHIP_MARKER = "# Mandu:";
export const isOurs = (content: string | null): boolean => content !== null && content.startsWith(OWNERSHIP_MARKER);

/** The probe that says the copy's grant is loaded: a user + pid namespace. */
export const MANDU_BWRAP_PROBE_ARGV = ["--unshare-user", "--unshare-pid", "--ro-bind", "/", "/", "--", "true"];

export interface FileStat { uid: number; mode: number; isFile: boolean }

export interface BwrapGrantDeps {
  stat: (path: string) => FileStat | null;
  readFile: (path: string) => Buffer | null;
  /** Run a command; true iff it exited 0. */
  run: (cmd: string, args: readonly string[]) => boolean;
}

export const realBwrapGrantDeps: BwrapGrantDeps = {
  stat: (p) => {
    try { const s = statSync(p); return { uid: s.uid, mode: s.mode, isFile: s.isFile() }; } catch { return null; }
  },
  readFile: (p) => { try { return readFileSync(p); } catch { return null; } },
  run: (cmd, args) => spawnSync(cmd, [...args], { stdio: "ignore", timeout: 10_000 }).status === 0,
};

/** Root-owned and writable by nobody else: an AppArmor grant attached to a
 *  path anyone else could write would hand its rights to their binary. */
function rootOnly(s: FileStat | null): boolean {
  return s !== null && s.uid === 0 && (s.mode & 0o022) === 0;
}

/** The copy is present and trustworthy as a file (no probe). */
export function manduBwrapInstalled(deps: BwrapGrantDeps): boolean {
  const f = deps.stat(MANDU_BWRAP);
  return f !== null && f.isFile && rootOnly(f) && rootOnly(deps.stat(MANDU_BWRAP_DIR)) && rootOnly(deps.stat(dirname(MANDU_BWRAP_DIR)));
}

/** The copy is in force: installed as above AND its grant is loaded. */
export function manduBwrapInForce(deps: BwrapGrantDeps): boolean {
  return manduBwrapInstalled(deps) && deps.run(MANDU_BWRAP, MANDU_BWRAP_PROBE_ARGV);
}

/** The copy differs from the system bwrap (a bubblewrap update since
 *  `mandu setup`): it still works, but misses that update. */
export function manduBwrapStale(deps: BwrapGrantDeps, source: string = SYSTEM_BWRAP): boolean {
  const mine = deps.readFile(MANDU_BWRAP);
  const sys = deps.readFile(source);
  return mine !== null && sys !== null && !mine.equals(sys);
}

/** The Mandu-marked pre-2026-09-27 grants still on this host. */
export function staleLegacyProfiles(readText: (path: string) => string | null): LegacyProfile[] {
  return LEGACY_PROFILES.filter((n) => isOurs(readText(`${APPARMOR_DIR}/${n}`)));
}

let memo: boolean | undefined;
/** Is the copy in force on this host? Outside a launch, memoized: one probe
 *  per process. In a launch (probe-cache.ts) the probe's pass is kept for the
 *  boot, keyed by the copy's identity and the profile files; the root-owned
 *  checks are made fresh every time, and a wrong kept answer fails at the
 *  wrap (the copy cannot make its namespace, so the agent never starts). */
export function manduBwrapInForceHere(): boolean {
  if (probeCacheEnabled()) {
    const d = realBwrapGrantDeps;
    return process.platform === "linux" && manduBwrapInstalled(d) &&
      cachedProbe("mandu-bwrap", () => ({ bins: [MANDU_BWRAP], argv: MANDU_BWRAP_PROBE_ARGV }), () => d.run(MANDU_BWRAP, MANDU_BWRAP_PROBE_ARGV));
  }
  if (memo === undefined) memo = process.platform === "linux" && manduBwrapInForce(realBwrapGrantDeps);
  return memo;
}

/** The bwrap the secret wrap runs: the copy when it is in force, else the
 *  distribution's (bwrap-path.ts: an administrator's `bwrap_path`, else the
 *  first on PATH outside the current directory), by absolute path; null when
 *  there is none. Never a bare `bwrap`: a PATH search would find one planted
 *  in the workspace. */
export function resolveWrapBwrap(inForce: boolean = manduBwrapInForceHere(), system: () => string | null = systemBwrapBin): string | null {
  return inForce ? MANDU_BWRAP : system();
}

/** The directory a launch puts on the agent's PATH ahead of the system's,
 *  so the agent's own sandboxes (Codex's) and Mandu's command box find the
 *  bubblewrap Mandu runs: the copy's directory when the copy is in force,
 *  else the administrator's `bwrap_path` directory, else none (the box then
 *  resolves the distribution's itself, exec-supervisor `resolve_bwrap`). An
 *  administrator's that cannot be used puts nothing there: the launch's
 *  `bwrap` presence check then fails, and the command box stays off.
 *  Pure over its inputs. */
export function agentBwrapDir(inForce: boolean, system: () => SystemBwrap = () => systemBwrap()): string | undefined {
  if (inForce) return MANDU_BWRAP_DIR;
  const sys = system();
  return sys.source === "admin" && sys.bin !== null ? dirname(sys.bin) : undefined;
}

/** `command -v`, as the launch and doctor probes ask it, except that `bwrap`
 *  means the distribution's bubblewrap outside the current directory
 *  (bwrap-path.ts): a presence check must agree with what would run, and a
 *  `bwrap` planted in the workspace is not one. */
export function commandAvailable(cmd: string): boolean {
  if (cmd === "bwrap") return systemBwrapBin() !== null;
  return spawnSync("bash", ["-c", `command -v ${cmd}`], { stdio: "ignore" }).status === 0;
}

/** The bubblewrap `mandu setup` copies, and the one the copy is compared
 *  with for staleness: an administrator's trusted `bwrap_path`
 *  (bwrap-path.ts), else SYSTEM_BWRAP. */
export function copySourceBwrap(): string {
  const a = adminBwrap();
  return a.kind === "path" ? a.path : SYSTEM_BWRAP;
}

/** One doctor/launch line for a stale legacy grant, or null. Each file names
 *  its own danger: the `bwrap` one clashes with the distro's own profile
 *  when that exists (else it opens bwrap to every program), and the
 *  `unshare` one opens unshare to every program whatever else is loaded. A
 *  real 24.04 → 26.04 `do-release-upgrade` (os-test-matrix.md §10.15)
 *  loaded Ubuntu's `bwrap` over Mandu's but kept Mandu's `unshare`, so
 *  `unshare -Ur` worked for any program until `mandu setup`: naming only the
 *  name clash would have described the one hazard that did not happen. */
export function legacyGrantWarning(stale: readonly LegacyProfile[], distroBwrapProfile: boolean): string | null {
  if (stale.length === 0) return null;
  const files = stale.map((n) => `${APPARMOR_DIR}/${n}`).join(" and ");
  const danger = (n: LegacyProfile): string => n === "bwrap" && distroBwrapProfile
    ? "shares the name of Ubuntu's own `bwrap` profile and, when it loads last, switches Ubuntu's user-namespace restriction off for every program on this machine"
    : `lets every program on this machine create a user namespace through ${n}`;
  const why = stale.length === 1
    ? `it ${danger(stale[0]!)}`
    : stale.map((n) => `the ${n} one ${danger(n)}`).join(", and ");
  return `an older Mandu grant is still installed (${files}): ${why}; fix: mandu setup (replaces it with Mandu's own bubblewrap)`;
}

/** Does /etc/apparmor.d carry Ubuntu's bwrap-userns-restrict? */
export const DISTRO_BWRAP_PROFILE_FILE = `${APPARMOR_DIR}/bwrap-userns-restrict`;

/** `bwrap --version`'s first line ("bubblewrap 0.9.0"), or null. */
export function bwrapVersion(bin: string): string | null {
  const r = spawnSync(bin, ["--version"], { encoding: "utf8", timeout: 5_000 });
  const line = r.status === 0 ? (r.stdout ?? "").split("\n")[0]!.trim() : "";
  return line === "" ? null : line;
}

export interface BwrapLaunchDeps {
  readFile: (path: string) => Buffer | null;
  readText: (path: string) => string | null;
  exists: (path: string) => boolean;
  version: (bin: string) => string | null;
  /** The administrator's `bwrap_path` (bwrap-path.ts adminBwrap). Optional:
   *  absent reads as none. */
  admin?: () => AdminBwrap;
}

export const realBwrapLaunchDeps: BwrapLaunchDeps = {
  readFile: realBwrapGrantDeps.readFile,
  readText: (p) => { try { return readFileSync(p, "utf8"); } catch { return null; } },
  exists: (p) => existsSync(p),
  version: bwrapVersion,
  admin: () => adminBwrap(),
};

/** What an administrator's `bwrap_path` that cannot be used means, in the
 *  one wording `mandu doctor`, `mandu setup` and the launch WARNING share;
 *  `why` is bwrap-path.ts `adminBwrap`'s reason (missing, not root's alone,
 *  not one plain absolute path). */
export function adminBwrapRefusedReason(why: string): string {
  return `your administrator's bubblewrap cannot be used: ${why}; Mandu runs no other bubblewrap in its place ` +
    "(the mount layer, the command box and the git sandbox stay off)";
}

/** The fix for adminBwrapRefusedReason: only the administrator can make it. */
export const ADMIN_BWRAP_FIX = "ask your administrator to correct it (the file and the binary must be root's alone)";

/** The launch line for an administrator's `bwrap_path` that cannot be used. */
export function adminBwrapRefusedNote(why: string): string {
  return `mandu: WARNING — ${adminBwrapRefusedReason(why)}; fix: ${ADMIN_BWRAP_FIX}`;
}

/**
 * The bubblewrap lines every launch prints (rootless-confinement-ubuntu-2404.md
 * §12.3, "Every launch checks the copy"): nothing when all is well.
 *
 * - The copy differs from the system bwrap: bubblewrap was updated after
 *   `mandu setup`, so the copy Mandu runs misses that update (a security fix,
 *   usually). Checked by content on every launch (two small reads); the
 *   versions are read only when the bytes differ, and both are named. An
 *   Ubuntu security update often keeps the upstream version string, so equal
 *   versions still warn.
 * - A pre-2026-09-27 Mandu grant is still installed: on 26.04 it can switch
 *   Ubuntu's restriction off for the whole host (legacyGrantWarning).
 * - An administrator's `bwrap_path` that cannot be used (bwrap-path.ts):
 *   Mandu then runs no bubblewrap outside its own copy, and says why.
 *
 * The copy is compared with what `mandu setup` copies (copySourceBwrap: an
 * administrator's `bwrap_path`, else the system bwrap).
 *
 * `paths` exists for the in-process e2e only (no env var can move the trusted
 * copy: a variable that did would let anyone point Mandu at another binary).
 */
export function bwrapLaunchNotes(
  deps: BwrapLaunchDeps = realBwrapLaunchDeps,
  paths: { copy: string; system: string; apparmorDir: string } = { copy: MANDU_BWRAP, system: copySourceBwrap(), apparmorDir: APPARMOR_DIR },
): string[] {
  const notes: string[] = [];
  const admin = deps.admin?.() ?? { kind: "none" };
  if (admin.kind === "refused") notes.push(adminBwrapRefusedNote(admin.why));
  const mine = deps.readFile(paths.copy);
  const sys = deps.readFile(paths.system);
  if (mine !== null && sys !== null && !mine.equals(sys)) {
    const vMine = deps.version(paths.copy) ?? "version unknown";
    const vSys = deps.version(paths.system) ?? "version unknown";
    const same = vMine === vSys ? "; same version string, a different build (likely a security update)" : "";
    notes.push(
      `mandu: WARNING — Mandu's own bubblewrap (${paths.copy}, ${vMine}) is not the system's (${paths.system}, ${vSys})${same}: ` +
      "bubblewrap was updated after `mandu setup`, and Mandu's copy misses that update; fix: mandu setup (refreshes the copy)",
    );
  }
  const legacy = LEGACY_PROFILES.filter((n) => isOurs(deps.readText(`${paths.apparmorDir}/${n}`)));
  const warn = legacyGrantWarning(legacy, deps.exists(`${paths.apparmorDir}/bwrap-userns-restrict`));
  if (warn !== null) notes.push(`mandu: WARNING — ${warn}`);
  return notes;
}
