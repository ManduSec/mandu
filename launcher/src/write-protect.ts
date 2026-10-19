/**
 * write-protect — the paths the agent's process tree may not change
 * (sandbox-security-review-2026-09-28 findings 2 and 6). Mandu-new.
 *
 * Two kinds, both enforced by the whole-agent guard (mandu-net-guard) on every
 * write-intent open, rename, unlink, link, symlink, truncate and creat under
 * them (net-supervisor secret_open.rs `WriteProtect`). On macOS the same list
 * is enforced by the whole-agent Seatbelt profile (seatbelt-profile.ts
 * component 3), which cannot hold a change for an answer: there every entry,
 * `ask` included, is REFUSED (write-protection.md §8):
 *
 *   deny  Mandu's own files: the whole Mandu home (MANDU_HOME, else
 *         ~/.mandu: the law, the config, the symbol DB, the events, the
 *         caches; on-disk-layout.md §4, one rule), minus the integrity
 *         modes' carve-outs (`except`), plus the install dir and an explicit
 *         MANDU_POLICY_FILE (each from the path table,
 *         src/generated/mandu-paths.ts). The agent never has a reason to
 *         change them, and a change would rewrite the law, the persisted
 *         approvals, or the binaries the next launch runs.
 *   ask   files that run LATER, outside Mandu: shell startup files, systemd
 *         user units, desktop autostart entries, user environment files, ssh
 *         settings, git settings, the workspace repository's hooks, the
 *         user's and the project's OpenCode plugin and tool directories, the
 *         user's OpenCode settings files (which can name a plugin). The change
 *         waits while the Inbox asks the human (allow once / always / deny;
 *         no answer is a denial).
 *
 * Deliberately NOT on the list (the user's decision, 2026-09-28): a
 * repository's `.git/config` (`git push -u`, `git remote add` write it) and
 * Claude Code's own `~/.claude/settings.json` (it saves its settings there).
 * Both can name a program that runs later (`core.hooksPath`, `core.fsmonitor`,
 * a hook command); docs/guarantees.md names them.
 *
 * policy.yaml `write_protect:` (the human's law, read from the arbiter at
 * launch; arbiter/policy/guard-settings.ts) adds `deny` and `ask` paths and
 * drops built-in `ask` entries (`unprotect`, exact paths). An opt-out never
 * removes an entry of Mandu's own files or the arbiter socket, whatever it
 * names (the arbiter's validator also refuses such a value).
 *
 * The labels are the arbiter's PROTECTED_WRITE_LABELS (the Inbox shows no
 * other words), pinned equal by
 * tests/stack/write-protect-labels-parity.test.ts.
 *
 * Pure except `repoHooksDirs` (reads `.git` entries) and `applyWriteProtect`.
 */
import { existsSync, lstatSync, readdirSync, readFileSync, realpathSync, statSync } from "node:fs";
import { expandHome, mergeGuardPolicy, type GuardPolicyDeps, type GuardSettings } from "./guard-policy-file.js";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { manduPath } from "./generated/mandu-paths.js";
import { accountHome, pathAndDefault } from "./own-paths.js";
import { darwinUserTempDir } from "./runtime-base.js";
import { projectOpencodeCodeDirs, userOpencodeCodeDirs } from "./opencode-project-code.js";
import { sshIncludeTargets } from "./ssh-config-includes.js";
import { opencodeSettingFiles } from "./opencode-global-code.js";
import { runtimeRegistryPaths } from "./runtime-registry.js";

export type WriteAnswer = "deny" | "ask";

export interface WriteProtectEntry {
  path: string;
  answer: WriteAnswer;
  label: string;
  /** Directories below `path` the entry does not cover (the Mandu home's
   *  carve-outs, own-paths.ts `homeCarveOuts`). The guard ignores one that
   *  is not strictly below `path` (net-supervisor secret_open.rs `carves`). */
  except?: string[];
  /** How `path` names what it covers (net-supervisor secret_open.rs
   *  `WriteForm`): absent = the path with its links followed, and everything
   *  below it; `name` = the entry itself under its own name, a link included
   *  (`current`), and below it; `prefix` = every name in that directory that
   *  starts with the last component (`.current.tmp-`); `self` = the entry
   *  itself only (the runtime base: not renamed, while what is in it stays
   *  writable). */
  form?: "name" | "prefix" | "self";
}

/** The labels an `ask` entry may carry (the arbiter's PROTECTED_WRITE_LABELS). */
export const WRITE_PROTECT_LABELS = [
  "a shell startup file",
  "a systemd user unit",
  "a desktop autostart entry",
  "a user environment file",
  "an ssh setting",
  "a git setting",
  "a git hook",
  "an OpenCode plugin or tool",
  "an OpenCode setting",
  "a file you protected in policy.yaml",
] as const;

const OWN = "Mandu's own files";
const USER = "a file you protected in policy.yaml";

/** Mandu's own files, `deny` (on-disk-layout.md §4): the whole Mandu home
 *  (MANDU_HOME, else ~/.mandu) as ONE entry, the carve-outs of this launch
 *  (`carveOuts`, own-paths.ts `homeCarveOuts`: the integrity modes'
 *  AgentView, `full`'s repo.git) left out of it; the default `~/.mandu` too
 *  when MANDU_HOME moves the home (a relocated home never un-protects the
 *  default one); the install dir (the table's `install-prefix`: MANDU_PREFIX
 *  and its default ~/.local/share/mandu, where scripts/install.sh puts it,
 *  never `$XDG_DATA_HOME`); and an explicit MANDU_POLICY_FILE. A new file
 *  anywhere in the home, a stray one at its top included, is refused before
 *  it is created (the guard judges the directory it lands in). */
export function ownFiles(env: Record<string, string | undefined>, carveOuts: readonly string[] = [], account: string | null = accountHome()): WriteProtectEntry[] {
  const home = env["HOME"];
  if (!home) return [];
  const manduHome = manduPath("mandu-home", env, home);
  const defaultHome = manduPath("mandu-home", {}, home);
  // The carve-outs are real paths (homeCarveOuts validated each is a
  // workspace's AgentView or repo.git in the real home); the guard resolves
  // the entry's path the same way and ignores one not strictly below it.
  const except = unique(carveOuts.filter((p) => p.startsWith("/")));
  const out: WriteProtectEntry[] = [{ path: manduHome, answer: "deny", label: OWN, ...(except.length > 0 ? { except } : {}) }];
  // The account's own `~/.mandu` too, when a scratch HOME hides it.
  const rest = [defaultHome, ...(account ? [manduPath("mandu-home", {}, account)] : []), ...pathAndDefault("install-prefix", env, home)];
  if (env["MANDU_POLICY_FILE"]) rest.push(env["MANDU_POLICY_FILE"]!);
  for (const path of unique(rest)) if (path !== manduHome) out.push({ path, answer: "deny", label: OWN });
  return out;
}

/** The platform a list is built for: the Linux guard's (the default) or the
 *  macOS Seatbelt profile's (seatbelt-setup.ts), which adds the macOS places
 *  where a file runs later. */
export type WriteProtectPlatform = "linux" | "darwin" | "win32";

/** Files that run later outside Mandu, `ask`. On macOS also the per-user
 *  launchd agents (`~/Library/LaunchAgents`, run at the next login or
 *  `launchctl load`), under the existing autostart label, and the xcrun
 *  shim's cache (`<DARWIN_USER_TEMP_DIR>xcrun_db`, which picks the program
 *  /usr/bin/git and every other Apple developer shim runs, for the user and
 *  for Mandu: git-hardening.md §5.2), under the git-setting label (the labels
 *  are the arbiter's, pinned by a parity test). `darwinTempDir` is
 *  `getconf DARWIN_USER_TEMP_DIR`, injectable for tests. */
export function laterRunFiles(
  env: Record<string, string | undefined>,
  platform: WriteProtectPlatform = "linux",
  darwinTempDir: () => string = darwinUserTempDir,
): WriteProtectEntry[] {
  const home = env["HOME"];
  if (!home) return [];
  const config = env["XDG_CONFIG_HOME"] || join(home, ".config");
  const h = (...p: string[]) => join(home, ...p);
  const groups: Array<[(typeof WRITE_PROTECT_LABELS)[number], string[]]> = [
    ["a shell startup file", [
      h(".bashrc"), h(".bash_profile"), h(".bash_login"), h(".bash_logout"), h(".profile"),
      h(".zshrc"), h(".zshenv"), h(".zprofile"), h(".zlogin"), h(".zlogout"),
      join(config, "fish"),
    ]],
    ["a systemd user unit", [join(config, "systemd", "user"), h(".local", "share", "systemd", "user")]],
    ["a desktop autostart entry", [join(config, "autostart"), ...(platform === "darwin" ? [h("Library", "LaunchAgents")] : [])]],
    ["a user environment file", [join(config, "environment.d"), h(".pam_environment")]],
    ["an ssh setting", [h(".ssh", "authorized_keys"), h(".ssh", "authorized_keys2"), h(".ssh", "config"), h(".ssh", "rc")]],
    ["a git setting", [h(".gitconfig"), join(config, "git", "config"), ...(platform === "darwin" ? xcrunCache(darwinTempDir) : [])]],
    // The user's own OpenCode plugin and custom tool directories: modules
    // every later OpenCode session imports into its own process, under Mandu
    // or not (opencode-project-code.ts; supported-agents.md §2.3 item 11).
    ["an OpenCode plugin or tool", userOpencodeCodeDirs(env)],
    // The user's OpenCode settings files (the global `opencode.json` and its
    // kin): a `plugin` list there names npm packages every later session
    // imports, outside Mandu, or under it with the global opt-in
    // (opencode-global-code.ts; supported-agents.md §2.3 item 12). OpenCode
    // writes some of them itself; that write waits for the human too.
    ["an OpenCode setting", opencodeSettingFiles(env)],
  ];
  const out: WriteProtectEntry[] = [];
  for (const [label, paths] of groups) for (const path of paths) out.push({ path, answer: "ask", label });
  return out;
}

/** The xcrun cache under the per-user temp dir, or none when that dir is
 *  not absolute (no macOS, getconf missing). */
function xcrunCache(darwinTempDir: () => string): string[] {
  const t = darwinTempDir();
  return t.startsWith("/") ? [join(t, "xcrun_db")] : [];
}

/** The hooks directory of the git repository `cwd` is in (its `.git`
 *  directory's `hooks`, or a linked worktree's common dir's), or none. */
export function repoHooksDirs(cwd: string, fs: { exists: (p: string) => boolean; isDir: (p: string) => boolean; read: (p: string) => string | null } = realFs): string[] {
  let dir = resolve(cwd);
  for (;;) {
    const dotGit = join(dir, ".git");
    if (fs.exists(dotGit)) {
      if (fs.isDir(dotGit)) return [join(dotGit, "hooks")];
      // A linked worktree: `.git` is a file `gitdir: <path>`; hooks live in
      // the common dir (`<gitdir>/commondir`, relative to gitdir).
      const m = /^gitdir:\s*(.+)\s*$/m.exec(fs.read(dotGit) ?? "");
      if (!m) return [];
      const gitdir = isAbsolute(m[1]!) ? m[1]! : resolve(dir, m[1]!);
      const common = (fs.read(join(gitdir, "commondir")) ?? "").trim();
      return [join(common ? resolve(gitdir, common) : gitdir, "hooks")];
    }
    const up = dirname(dir);
    if (up === dir) return [];
    dir = up;
  }
}

/** The file reads the list is built from: `repoHooksDirs`'s, and `list`
 *  for an ssh `Include` pattern's matches (`sshIncludeTargets`). */
export interface WriteProtectFs {
  exists: (p: string) => boolean;
  isDir: (p: string) => boolean;
  read: (p: string) => string | null;
  list?: (dir: string) => string[] | null;
}

const realFs: WriteProtectFs = {
  exists: (p: string) => existsSync(p),
  isDir: (p: string) => { try { return statSync(p).isDirectory(); } catch { return false; } },
  read: (p: string) => { try { return statSync(p).isFile() ? readFileSync(p, "utf8") : null; } catch { return null; } },
  list: (d: string) => { try { return readdirSync(d); } catch { return null; } },
};

/** The files ssh reads as configuration through an `Include` of
 *  `~/.ssh/config` (the launch's home's and the account's) or of
 *  `/etc/ssh/ssh_config`, `ask` under the ssh label (P0 (D), 2026-10-07;
 *  ssh-config-includes.ts, write-protection.md §2). An include too broad to
 *  hold (the home, `/tmp`) is logged as a warning and left out. */
export function sshIncludeFiles(
  env: Record<string, string | undefined>,
  fs: Pick<WriteProtectFs, "read" | "list">,
  account: string | null,
  log: (m: string) => void = () => {},
  systemConfig?: string,
  user?: string,
): WriteProtectEntry[] {
  const homes = [env["HOME"], account].filter((h): h is string => typeof h === "string" && h.startsWith("/"));
  if (homes.length === 0) return [];
  const t = sshIncludeTargets(homes, fs, systemConfig, user);
  for (const u of t.unprotectable) {
    log(`WARNING: mandu: ${u.file} includes ${u.word}, which names files Mandu cannot hold for your OK without holding a whole ` +
      "home or top-level directory: the agent may write a file ssh then reads as its configuration (write-protection.md §4)");
  }
  // ssh reads the account's ~/.ssh/config (its home from the password
  // database), not $HOME's: a launch with another HOME holds that one too.
  const accountConfig = account && account !== env["HOME"] ? [join(account, ".ssh", "config")] : [];
  return unique([...accountConfig, ...t.paths]).map((path) => ({ path, answer: "ask" as const, label: "an ssh setting" }));
}

/** The arbiter's data socket, `deny` (sandbox-security-review-2026-09-28
 *  finding 3): the path the interceptors dial, its real path, and every
 *  symlink on the way (`mandu/current`). With these refused, and a pathname
 *  `bind` judged like any new file, no program in the tree can remove the
 *  socket and stand up an impostor arbiter that answers "allow". Not the
 *  socket's directory: a test or a dev arbiter may keep it in a directory
 *  the agent writes to. */
export function arbiterSocketFiles(sock: string | undefined, fsx: { real: (p: string) => string | null; isLink: (p: string) => boolean } = realLinks): WriteProtectEntry[] {
  if (!sock || !sock.startsWith("/")) return [];
  const paths = [sock];
  const real = fsx.real(sock);
  if (real && real !== sock) paths.push(real);
  const links: string[] = [];
  for (let p = dirname(sock); p !== "/" && p !== "."; p = dirname(p)) {
    if (fsx.isLink(p)) links.push(p);
  }
  // A link on the way is protected as ITSELF (`name`): with its target
  // resolved, the entry would name the directory it points at and leave the
  // link free to be replaced (2026-10-07).
  return [
    ...unique(paths).map((path): WriteProtectEntry => ({ path, answer: "deny", label: OWN })),
    ...unique(links).filter((p) => !paths.includes(p)).map((path): WriteProtectEntry => ({ path, answer: "deny", label: OWN, form: "name" })),
  ];
}

/**
 * Mandu's runtime registries under each runtime base in `bases`, `deny`, for
 * the Linux guard (runtime-instances.md §2, "planted paths"; the macOS
 * profile denies the same list, seatbelt-setup.ts): the directories
 * (`instances/`, `dashboards/`, `vm-guests/`, `logs/`, `test/`, `release-check/`, and the
 * human plane's `human/`) with everything below them; `current`, the legacy
 * `arbiter.sock` and `dashboard.log` as the entries themselves (`name`:
 * `current` is a link); the promotion's `.current.tmp-<pid>` and `mandu
 * dashboard`'s `dashboard-<pid>.port(.tmp)` as name prefixes; and the base
 * itself (`self`: not renamed or removed, so no forged base can take its
 * place, while the session's own folder in it stays writable). One list,
 * runtime-registry.ts `RUNTIME_REGISTRY`. A relative base or `/` adds
 * nothing; the bases are deduplicated.
 */
export function runtimeRegistryProtect(bases: readonly (string | undefined)[]): WriteProtectEntry[] {
  const out: WriteProtectEntry[] = [];
  const seen = new Set<string>();
  for (const raw of bases) {
    if (!raw || !raw.startsWith("/")) continue;
    const b = raw.length > 1 ? raw.replace(/\/+$/, "") : raw;
    if (b === "/" || seen.has(b)) continue;
    seen.add(b);
    const r = runtimeRegistryPaths(b);
    out.push(
      ...[...r.dirs, join(b, HUMAN_DIR_NAME)].map((path): WriteProtectEntry => ({ path, answer: "deny", label: OWN })),
      ...r.names.map((path): WriteProtectEntry => ({ path, answer: "deny", label: OWN, form: "name" })),
      ...r.prefixes.map((path): WriteProtectEntry => ({ path, answer: "deny", label: OWN, form: "prefix" })),
      { path: b, answer: "deny", label: OWN, form: "self" },
    );
  }
  return out;
}

/** The human plane's directory name under a runtime base (human-plane.ts). */
const HUMAN_DIR_NAME = "human";

/**
 * A registry entry that holds a path the agent must keep writable (its
 * workspace, the session's scope dir), or null. A launch refuses such a
 * registry rather than drop the rule (as the macOS profile does,
 * seatbelt-setup.ts): only a workspace or a MANDU_RUNTIME_DIR inside a
 * registry gets here (parse.ts refuses a scope id that names one).
 */
export function registryHolding(entries: readonly WriteProtectEntry[], keep: readonly string[]): { entry: string; holds: string } | null {
  for (const e of entries) {
    if (e.form === "self") continue;
    const p = e.path.replace(/\/+$/, "");
    for (const k of keep) {
      if (!k.startsWith("/")) continue;
      const inside = e.form === "prefix" ? k.startsWith(p) : k === p || k.startsWith(`${p}/`);
      if (inside) return { entry: e.form === "prefix" ? `${p}*` : p, holds: k };
    }
  }
  return null;
}

const realLinks = {
  real: (p: string) => { try { return realpathSync(p); } catch { return null; } },
  isLink: (p: string) => { try { return lstatSync(p).isSymbolicLink(); } catch { return false; } },
};

/** The whole list for a launch in `cwd`. The guard takes the FIRST entry a
 *  path falls under, so the order is the precedence: Mandu's own files, then
 *  the human's `deny` paths (a deny may harden a built-in `ask`), then the
 *  `ask` entries. `settings` is policy.yaml `write_protect:`. `carveOuts`:
 *  the directories under the Mandu home this launch's agent writes
 *  (own-paths.ts `homeCarveOuts`; secret-setup.ts `launchHomeCarveOuts`
 *  resolves them for a plan); none by default, so the whole home is
 *  refused (fail-closed). `platform` "darwin" builds the macOS list, which
 *  the Seatbelt profile enforces with every entry refused (no Inbox hold
 *  there; seatbelt-setup.ts). */
export function writeProtectList(
  env: Record<string, string | undefined>,
  cwd: string,
  fs: WriteProtectFs = realFs,
  arbiterSock?: string,
  settings: GuardSettings["writeProtect"] = { deny: [], ask: [], unprotect: [] },
  log: (m: string) => void = () => {},
  carveOuts: readonly string[] = [],
  platform: WriteProtectPlatform = "linux",
  account: string | null = accountHome(),
  registryBases: readonly (string | undefined)[] = [],
): WriteProtectEntry[] {
  const home = env["HOME"];
  const norm = (p: string): string | null => {
    const x = expandHome(p, home);
    return x && x.startsWith("/") ? (x.length > 1 ? x.replace(/\/+$/, "") : x) : null;
  };
  // Mandu's runtime registries ride the Linux list (the macOS profile has a
  // component of its own for them, seatbelt-setup.ts).
  const registry = platform === "linux" ? runtimeRegistryProtect(registryBases) : [];
  const own = [...ownFiles(env, carveOuts), ...arbiterSocketFiles(arbiterSock), ...registry];
  // A value at or below an own-files entry (anything in the Mandu home).
  const ownPaths = {
    has: (p: string): boolean => own.some((e) => p === e.path || (e.form !== "self" && p.startsWith(`${e.path.replace(/\/+$/, "")}${e.form === "prefix" ? "" : "/"}`))),
  };
  const hooks = repoHooksDirs(cwd, fs).map((path) => ({ path, answer: "ask" as const, label: "a git hook" }));
  // The project's OpenCode plugin and custom tool directories (cwd up to the
  // repository root), as the repository's git hooks: they run in the user's
  // next OpenCode session outside Mandu (or under it with the opt-out).
  const ocCode = projectOpencodeCodeDirs(cwd, { isDir: fs.isDir, isFile: (p) => fs.exists(p) && !fs.isDir(p) })
    .map((path) => ({ path, answer: "ask" as const, label: "an OpenCode plugin or tool" }));
  const optOut = new Set<string>();
  for (const raw of settings.unprotect) {
    const p = norm(raw);
    if (p === null) continue;
    if (ownPaths.has(p)) {
      log(`WARNING: mandu: policy.yaml write_protect.unprotect names ${p}, one of Mandu's own files; it stays protected`);
      continue;
    }
    optOut.add(p);
  }
  // The files ssh reads as configuration through an `Include` (P0 (D)):
  // ssh reads a key raw, so a config the agent writes could make it print
  // the key; each such file waits for the human as ~/.ssh/config does. Only
  // with real file reads (`list`): a test's stub fs has none.
  const sshIncludes = fs.list ? sshIncludeFiles(env, fs, account, log) : [];
  const later = uniqueByPath([...laterRunFiles(env, platform), ...hooks, ...ocCode, ...sshIncludes]);
  for (const p of optOut) {
    if (!later.some((e) => e.path === p)) log(`mandu: policy.yaml write_protect.unprotect names ${p}, which is not on the built-in list; nothing to drop`);
  }
  const kept = later.filter((e) => !optOut.has(e.path));
  const user = (list: readonly string[], answer: WriteAnswer): WriteProtectEntry[] =>
    unique(list.map(norm).filter((p): p is string => p !== null && p !== "/")).map((path) => ({ path, answer, label: USER }));
  return [...own, ...user(settings.deny, "deny"), ...kept, ...user(settings.ask, "ask")];
}

function unique(xs: string[]): string[] {
  return [...new Set(xs)];
}

/** The first entry for each path. */
function uniqueByPath(xs: WriteProtectEntry[]): WriteProtectEntry[] {
  const seen = new Set<string>();
  return xs.filter((e) => !seen.has(e.path) && (seen.add(e.path), true));
}

export interface WriteProtectDeps extends GuardPolicyDeps {
  log: (m: string) => void;
}

/**
 * Hand the list to the guard: added to the launch's guard policy file (the
 * secret setup's, `MANDU_NET_GUARD_SECRETS`), or a policy file of its own when
 * the launch has none (a mode with the confidentiality axis off). Either way
 * the guard then traps the open family and the delete / write family
 * (`MANDU_NET_GUARD_PROTECT=1`). Only with a running guard and a mode other
 * than `off`; the caller decides both.
 */
export function applyWriteProtect(list: WriteProtectEntry[], mutEnv: Record<string, string>, deps: WriteProtectDeps): void {
  if (list.length === 0) return;
  mergeGuardPolicy(mutEnv, deps, { writeProtect: list });
  mutEnv["MANDU_NET_GUARD_PROTECT"] = "1";
  const asks = list.filter((e) => e.answer === "ask").length;
  deps.log(
    `mandu: write-protect — Mandu's own files are read-only to the agent; ${asks} file(s) that run later ` +
      "(shell startup, systemd user units, autostart, ssh and git settings, repo hooks, OpenCode plugins and settings) wait for your OK in Approvals before they change",
  );
}
