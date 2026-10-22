/**
 * hardened-git — how Mandu runs git on a repository the agent may have
 * written (docs/design/architecture/write-protection.md §8).
 *
 * The launcher, the arbiter, the dashboard and fs-sync run git OUTSIDE every
 * sandbox, on repositories an agent can write: the workspace, and any
 * repository a data-plane op names (`registerRepository`, `scanSecretHistory`,
 * `suggestPolicy`, `gitHistoryLocks` `roots`). A repository's own config
 * (`.git/config`, the files it includes) and its attributes (`.gitattributes`,
 * `.git/info/attributes`) can name programs git runs: `core.fsmonitor`, hooks,
 * the signature verifier `log.showSignature` hands a commit to, filter,
 * textconv, diff and merge drivers, the transport of a lazy fetch, editors,
 * pagers. Planted by an agent in a confined session, such a program would run
 * UNCONFINED the next time Mandu reads the repository. So every such call:
 *
 *   - forces off, on the command line (which outranks every config file and
 *     every include), each config key that starts a program by a name git
 *     knows (GIT_NO_PROGRAM_CONFIG), and turns the pager off;
 *   - runs with a scrubbed environment (hardenedGitEnv): no `GIT_*` inherited
 *     (GIT_DIR, GIT_CONFIG_PARAMETERS, GIT_EXTERNAL_DIFF, GIT_SSH_COMMAND,
 *     GIT_PAGER, GIT_EXEC_PATH …), the system config skipped, no lazy fetch,
 *     no prompt, no askpass, and a no-op editor;
 *   - uses only commands that run no DRIVER a repository names by a free name
 *     (`filter.<x>.clean`, `diff.<x>.textconv`, `merge.<x>.driver`), which no
 *     `-c` can switch off without knowing `<x>`: a caller that must hash a
 *     working copy does it with `--no-filters` or in a scratch git directory
 *     (git-object-twins.ts `worktreeBlobNames`), never by `git add`, `git
 *     status` or `git diff` against the work tree;
 *   - sees history as the objects record it, not as a repository rewrites
 *     it (security fix 2026-10-21, confidentiality.md §7.2a "What the walk
 *     does not let a repository hide"): replace refs off
 *     (GIT_NO_REPLACE_OBJECTS, core.useReplaceRefs=false) and an empty graft
 *     file (GIT_GRAFT_FILE=/dev/null, its deprecation hint off), so a graft
 *     or a `refs/replace/*` an agent wrote cannot cut commits out of a walk
 *     that decides what is protected (a replace ref is still a ref: its
 *     target is walked). The shallow file is the history walk's to judge
 *     (history-labels.ts walkShallowRule).
 *
 * Defense in depth (gitSandbox): the launcher's and the arbiter's git runners
 * (launch prep; the history scan, lock resolver and prepared copies; not the
 * single probes, gitRevOf, the dashboard or fs-sync, which are hardened
 * only) also run git in a sandbox with no network, writable only where the
 * call must write (the pack cache) and no host process within its reach:
 *
 *   - Linux, where an unprivileged bubblewrap works: a read-only view of the
 *     filesystem, no capabilities, its own user, pid, ipc and uts namespaces
 *     and a new session;
 *   - macOS: a Seatbelt profile (`/usr/bin/sandbox-exec -p`, rendered per
 *     call by gitSeatbeltProfile) that also lets no process but git itself
 *     start: no fork, and no exec of anything but the git binary resolved at
 *     probe time, so a program a repository names cannot even start. No
 *     host services (Mach lookups but the user database, Apple Events), no
 *     signal or IPC outside the sandbox, no terminal.
 *
 * Probe-gated: where neither can be made (no bwrap or no user namespaces; no
 * sandbox-exec, or inside another Seatbelt profile, which sandbox-exec cannot
 * nest in), the hardened git runs as is. MANDU_GIT_SANDBOX=0 turns it off.
 * A probe that could not be judged (a timeout, no free process) is never
 * settled as none: gitSandbox probes again later, and a process that once
 * ran git under Seatbelt never falls back to none (gitSandboxCache).
 *
 * ONE FILE, FOUR COPIES: launcher/src, arbiter/src, dashboard/src and
 * fs-sync/src each ship this file byte-identical (the packages ship
 * standalone and do not import each other). tests/stack/
 * hardened-git-parity.test.ts holds the copies equal and runs a hostile
 * repository through each; it holds bwrap-path.ts, which this file imports,
 * equal the same way. Change the launcher's copies and copy them out.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 */
import { spawnSync } from "node:child_process";
import { accessSync, constants, realpathSync, statSync } from "node:fs";
import { systemBwrapBin } from "./bwrap-path.js";

/**
 * Every hook event githooks(5) lists (git 2.54 to 2.56: the same 28). From git
 * 2.54 on, the config can name hooks with no file in any hooks directory
 * (`hook.<name>.command` run on each `hook.<name>.event`), so
 * `core.hooksPath=/dev/null` no longer covers hooks. From git 2.55 on,
 * `hook.<event>.enabled=false` turns off every hook of that event,
 * configured or not, whatever `<name>` the repository picked. git 2.54 has
 * only the per-name switch (`hook.<name>.enabled`), which no `-c` can name
 * ahead of time: write-protection.md §8.6. An older git ignores the keys.
 */
export const GIT_HOOK_EVENTS: readonly string[] = [
  "applypatch-msg", "pre-applypatch", "post-applypatch", "pre-commit", "pre-merge-commit", "prepare-commit-msg",
  "commit-msg", "post-commit", "pre-rebase", "post-checkout", "post-merge", "pre-push", "pre-receive", "update",
  "proc-receive", "post-receive", "post-update", "reference-transaction", "push-to-checkout", "pre-auto-gc",
  "post-rewrite", "sendemail-validate", "fsmonitor-watchman", "p4-changelist", "p4-prepare-changelist",
  "p4-post-changelist", "p4-pre-submit", "post-index-change",
];

/**
 * The config every call forces (`-c key=value`, the highest precedence git
 * has). Each names a program git would start, or a step that would start
 * one: the fsmonitor query of an index read; hooks (a directory that holds
 * none); the signature verifier of `git log` and of commits, tags and merges
 * (`gpg.program`, `gpg.ssh.program`, `gpg.x509.program`); credential helpers
 * (an empty value clears the list); every transport (ssh and its
 * `core.sshCommand`, remote helpers, `ext::`), so neither a fetch nor the lazy
 * fetch of a partial clone reaches a program or the network; the automatic
 * gc and maintenance a commit may spawn; submodule recursion; and every
 * hook event switched off (GIT_HOOK_EVENTS), which is what turns off the
 * config-based hooks of git 2.55 and later.
 */
export const GIT_NO_PROGRAM_CONFIG: readonly string[] = [
  "core.fsmonitor=false",
  "core.hooksPath=/dev/null",
  "log.showSignature=false",
  "commit.gpgSign=false",
  "tag.gpgSign=false",
  "merge.verifySignatures=false",
  "credential.helper=",
  "protocol.allow=never",
  "gc.auto=0",
  "maintenance.auto=false",
  "submodule.recurse=false",
  ...GIT_HOOK_EVENTS.map((e) => `hook.${e}.enabled=false`),
  // History as the objects record it (the module comment): no replace
  // refs, and no hint for the empty graft file the environment names.
  "core.useReplaceRefs=false",
  "advice.graftFileDeprecated=false",
];

/** The global options every call starts with: no pager, then the forced
 *  config. (No `--no-lazy-fetch`: git before 2.44 refuses an unknown global
 *  option, so the environment carries it, GIT_NO_LAZY_FETCH, and
 *  `protocol.allow=never` stops the fetch on an older git.) */
export const HARDENED_GIT_GLOBAL_ARGS: readonly string[] = [
  "--no-pager",
  ...GIT_NO_PROGRAM_CONFIG.flatMap((kv) => ["-c", kv]),
];

/** `args` behind the hardened global options (and `--literal-pathspecs`
 *  when asked). Pure. */
export function hardenedGitArgs(args: readonly string[], opts: { literalPathspecs?: boolean } = {}): string[] {
  return [...HARDENED_GIT_GLOBAL_ARGS, ...(opts.literalPathspecs ? ["--literal-pathspecs"] : []), ...args];
}

/** What the scrubbed environment sets. GIT_ASKPASS empty (not unset) keeps
 *  git from falling back to `core.askPass`; `:` is git's own no-op editor. */
export const HARDENED_GIT_ENV: Readonly<Record<string, string>> = {
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_NO_LAZY_FETCH: "1",
  GIT_TERMINAL_PROMPT: "0",
  GIT_ASKPASS: "",
  GIT_EDITOR: ":",
  GIT_SEQUENCE_EDITOR: ":",
  // History as the objects record it (the module comment).
  GIT_NO_REPLACE_OBJECTS: "1",
  GIT_GRAFT_FILE: "/dev/null",
  // macOS: Apple's /usr/bin/git is an xcrun shim that runs whatever git the
  // per-user cache `$(getconf DARWIN_USER_TEMP_DIR)xcrun_db` names, a file of
  // the user's that the agent can rewrite. Without the cache the shim finds
  // git through the root-owned xcode-select link (git-hardening.md §5.2;
  // verified on macOS 26.5). Ignored everywhere else.
  xcrun_nocache: "1",
};

/**
 * The environment for a hardened call: `base` without any `GIT_*` variable
 * (whatever set them, none reaches git), then HARDENED_GIT_ENV, then `extra`
 * (the caller's own GIT_DIR, GIT_OBJECT_DIRECTORY, LC_ALL …). Pure.
 */
export function hardenedGitEnv(
  base: Readonly<Record<string, string | undefined>> = process.env,
  extra: Readonly<Record<string, string>> = {},
): Record<string, string> {
  const env: Record<string, string> = {};
  for (const [k, v] of Object.entries(base)) {
    if (v !== undefined && !k.startsWith("GIT_")) env[k] = v;
  }
  return { ...env, ...HARDENED_GIT_ENV, ...extra };
}

// ── Defense in depth: the git sandbox ───────────────────────────────────────

/** Linux: a bubblewrap that can run git sandboxed here, and the flags it
 *  took. */
export interface BwrapGitSandbox {
  bwrap: string;
  flags: readonly string[];
  /** The probe's successful `git --version` output; reuse it rather than
   *  starting git again just to ask its version. */
  gitVersion?: string;
}

/** macOS: the `sandbox-exec` that applies the Seatbelt profile (always
 *  SANDBOX_EXEC) and the git it runs, by the absolute, resolved path the
 *  probe found (resolveGitBinary): the profile lets that one binary start. */
export interface SeatbeltGitSandbox {
  sandboxExec: string;
  git: string;
  /** The resolved git's successful `--version` output from inside Seatbelt. */
  gitVersion?: string;
}

/** The sandbox a git call runs in: bubblewrap on Linux, Seatbelt on macOS. */
export type GitSandbox = BwrapGitSandbox | SeatbeltGitSandbox;

/** Is `s` the macOS kind? */
export function isSeatbeltGitSandbox(s: GitSandbox): s is SeatbeltGitSandbox {
  return "sandboxExec" in s;
}

/** The sandbox's flags, most hardened first: the probe takes the first set
 *  the host's bubblewrap accepts (`--disable-userns` needs bubblewrap 0.8). A
 *  fresh /dev (a read-only bind of the host's refuses writes to /dev/null),
 *  the host's /dev/shm read-only again on it. */
export const GIT_SANDBOX_FLAG_SETS: ReadonlyArray<readonly string[]> = [
  [
    "--unshare-user", "--unshare-pid", "--unshare-net", "--unshare-ipc", "--unshare-uts",
    "--die-with-parent", "--new-session", "--cap-drop", "ALL", "--disable-userns",
    "--ro-bind", "/", "/", "--dev", "/dev", "--ro-bind-try", "/dev/shm", "/dev/shm", "--proc", "/proc",
  ],
  [
    "--unshare-user", "--unshare-pid", "--unshare-net", "--unshare-ipc", "--unshare-uts",
    "--die-with-parent", "--new-session", "--cap-drop", "ALL",
    "--ro-bind", "/", "/", "--dev", "/dev", "--ro-bind-try", "/dev/shm", "/dev/shm", "--proc", "/proc",
  ],
];

/** Mandu's own bubblewrap (`mandu setup`, launcher bwrap-grant.ts). */
export const MANDU_OWN_BWRAP = "/usr/lib/mandu/bin/bwrap";

/** The base system's `sandbox-exec`, by absolute path: never a PATH lookup,
 *  where a planted copy would run git with no profile (the launcher's
 *  seatbelt-profile.ts SANDBOX_EXEC, duplicated here because the arbiter,
 *  the dashboard and fs-sync do not import the launcher; a launcher unit
 *  test holds the two equal). */
export const SANDBOX_EXEC = "/usr/bin/sandbox-exec";

/** SBPL string literal: backslash and double quote escaped. */
function sbplQuote(p: string): string {
  return `"${p.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

/** An absolute path without empty or `.` components or a trailing slash,
 *  or null: a relative path, or one with a `..` (which the kernel resolves
 *  through links, so no spelling here would name what it names). */
function normalizeAbs(p: string): string | null {
  if (!p.startsWith("/")) return null;
  const parts: string[] = [];
  for (const c of p.split("/")) {
    if (c === "" || c === ".") continue;
    if (c === "..") return null;
    parts.push(c);
  }
  return "/" + parts.join("/");
}

const realpathOrNull = (p: string): string | null => {
  try {
    return realpathSync(p);
  } catch {
    return null;
  }
};

/** The canonical spelling of `p`: the realpath of its longest existing
 *  prefix plus the rest (a directory not made yet still gets its `/private/…`
 *  spelling). Seatbelt matches a path rule against the resolved path only: a
 *  rule spelled `/tmp/x` or `/var/folders/…` never matches (both are links on
 *  macOS). The launcher's seatbelt-profile.ts `canonicalPath`, copied (a
 *  launcher unit test holds the two equal). */
export function canonicalSpelling(p: string, realpath: (p: string) => string | null = realpathOrNull): string {
  const abs = normalizeAbs(p);
  if (abs === null) return p;
  const rest: string[] = [];
  let head = abs;
  for (;;) {
    const r = realpath(head);
    if (r !== null) return rest.length === 0 ? r : `${r === "/" ? "" : r}/${rest.join("/")}`;
    if (head === "/") return abs;
    const i = head.lastIndexOf("/");
    rest.unshift(head.slice(i + 1));
    head = i === 0 ? "/" : head.slice(0, i);
  }
}

/** The Mach service git may look up: the user database (`getpwnam`, which a
 *  `~user/` include path needs; without it git dies "could not expand
 *  include path"). */
export const GIT_SEATBELT_MACH_ALLOW = "com.apple.system.opendirectoryd.libinfo";

/**
 * The Seatbelt profile one git call runs under (macOS; write-protection.md
 * §8), each rule the counterpart of a bubblewrap flag, each verified with
 * `sandbox-exec` on macOS 26.5. Last match wins: `(allow default)`, then
 * each deny, then its own exceptions.
 *
 *   - no fork, and no exec but `git` (an absolute, resolved path: an exec
 *     rule matches the resolved path only): a program a repository names
 *     cannot start at all (bubblewrap lets it start and contains it);
 *   - no file write but `/dev/null` and each of `writable`, in its given
 *     spelling and its canonical one (`canonical`; a rule matches the
 *     canonical path only). A `writable` that is relative, holds a `..` or
 *     is `/` is dropped (fail closed: the write fails);
 *   - no terminal (`/dev/tty`, `/dev/ttys*`): bubblewrap's `--new-session`;
 *   - no network, TCP, UDP or Unix socket: `--unshare-net`;
 *   - no Mach lookup but the user database, no Apple Event: no host service
 *     can run anything for it;
 *   - no signal outside the sandbox (`--unshare-pid`); no POSIX shared
 *     memory or semaphore and no System V object another process made
 *     (`--unshare-ipc`: only a new private System V object can still be
 *     created, which reaches no one); no IOKit.
 *
 * Reads stay open, as under bubblewrap. Pure given `canonical`; the output
 * is sorted and deduped, so the unit test pins it byte for byte.
 */
export function gitSeatbeltProfile(
  git: string,
  writable: readonly string[] = [],
  canonical: (p: string) => string = canonicalSpelling,
): string {
  const binds = new Set<string>();
  for (const w of writable) {
    const p = normalizeAbs(w);
    if (p === null || p === "/") continue;
    binds.add(p);
    const c = normalizeAbs(canonical(p));
    if (c !== null && c !== "/") binds.add(c);
  }
  const writes = ["(literal \"/dev/null\")", ...[...binds].sort().map((p) => `(subpath ${sbplQuote(p)})`)];
  return [
    "(version 1)",
    "(allow default)",
    "(deny process-fork)",
    "(deny process-exec)",
    `(allow process-exec (literal ${sbplQuote(git)}))`,
    "(deny file-write*)",
    `(allow file-write* ${writes.join(" ")})`,
    "(deny file-read* file-write* (literal \"/dev/tty\") (regex #\"^/dev/ttys[0-9]+$\"))",
    "(deny network*)",
    "(deny mach-lookup)",
    `(allow mach-lookup (global-name ${sbplQuote(GIT_SEATBELT_MACH_ALLOW)}))`,
    "(deny appleevent-send)",
    "(deny signal)",
    "(allow signal (target same-sandbox))",
    "(deny ipc-posix-shm*)",
    "(deny ipc-posix-sem* ipc-sysv*)",
    "(deny iokit-open)",
  ].join("\n") + "\n";
}

/** The command that runs `git <args>`: git itself; bubblewrap running it in
 *  the sandbox with each of `writable` bound read-write; or `sandbox-exec`
 *  running the probed git under gitSeatbeltProfile, `writable` its only
 *  writable paths (`canonical` gives their resolved spelling; default the
 *  host's realpath). Pure given `canonical`. */
export function gitCommand(
  args: readonly string[],
  sandbox: GitSandbox | null,
  writable: readonly string[] = [],
  canonical: (p: string) => string = canonicalSpelling,
): { file: string; args: string[] } {
  if (sandbox === null) return { file: "git", args: [...args] };
  if (isSeatbeltGitSandbox(sandbox)) {
    return { file: sandbox.sandboxExec, args: ["-p", gitSeatbeltProfile(sandbox.git, writable, canonical), sandbox.git, ...args] };
  }
  const binds = [...new Set(writable)].flatMap((w) => ["--bind", w, w]);
  return { file: sandbox.bwrap, args: [...sandbox.flags, ...binds, "--", "git", ...args] };
}

/** How a probe run ended: true (exit 0), false (it ran and failed, or the
 *  program is not there to run), or "transient": it could not be judged (a
 *  spawn error but a missing program, EAGAIN when no process is free; a
 *  kill, the timeout's among them). A transient answer is never settled as
 *  "no sandbox" (gitSandboxCache). */
export type ProbeRun = boolean | "transient";

export interface GitSandboxProbeDeps {
  /** Runs a command: how it ended (ProbeRun). */
  runOk?: (file: string, args: readonly string[]) => ProbeRun;
  /** Runs a command and captures stdout. `runOk` takes precedence when
   *  supplied; otherwise this runner (or the default) also retains the
   *  successful probe's git version. Transient results never count as OK. */
  run?: (file: string, args: readonly string[]) => { ok: ProbeRun; stdout: string };
  /** Is `p` a root-owned file no one else can write (Mandu's own copy)? */
  rootOwned?: (p: string) => boolean;
  /** The distribution's bubblewrap by absolute path, or null (default:
   *  bwrap-path.ts systemBwrapBin over `env`'s PATH). */
  systemBwrap?: () => string | null;
  env?: Readonly<Record<string, string | undefined>>;
  /** The platform to probe for. Default: `process.platform`. */
  platform?: string;
  /** Is `p` an executable regular file (no PATH search)? */
  executable?: (p: string) => boolean;
  /** macOS: the git to run sandboxed (resolveGitBinary): a path, null
   *  (none), or "transient" (its `--exec-path` could not be judged). */
  resolveGit?: () => string | null | "transient";
}

/** A spawn error that says the program is not there to run: an answer, not
 *  a transient state. */
const NOT_RUNNABLE: ReadonlySet<string> = new Set(["ENOENT", "EACCES", "ENOEXEC", "ENOTDIR", "ELOOP", "ENAMETOOLONG"]);

/** How a spawnSync run ended (ProbeRun): a spawn error is "not there"
 *  (false) or transient; a signal (the timeout's SIGTERM among them) is
 *  transient; else exit 0 or not. Pure. */
export function probeRunVerdict(r: { status: number | null; signal: NodeJS.Signals | null; error?: Error }): ProbeRun {
  if (r.error !== undefined) return NOT_RUNNABLE.has((r.error as NodeJS.ErrnoException).code ?? "") ? false : "transient";
  if (r.signal !== null) return "transient";
  return r.status === 0;
}

const defaultRun = (file: string, args: readonly string[]): { ok: ProbeRun; stdout: string } => {
  const r = spawnSync(file, [...args], { stdio: ["ignore", "pipe", "ignore"], encoding: "utf8", timeout: 10_000, env: hardenedGitEnv() });
  return { ok: probeRunVerdict(r), stdout: typeof r.stdout === "string" ? r.stdout : "" };
};

/** Adapt the verdict-only runner without losing the transient state. */
const probeRunner = (deps: GitSandboxProbeDeps): NonNullable<GitSandboxProbeDeps["run"]> => {
  const runOk = deps.runOk;
  return runOk !== undefined ? (file, args) => ({ ok: runOk(file, args), stdout: "" }) : (deps.run ?? defaultRun);
};

/** Only a successful version response is retained; stderr or unrelated
 *  stdout does not become a cached git version. */
const probeVersion = (stdout: string): { gitVersion?: string } =>
  /^git version \S/.test(stdout) ? { gitVersion: stdout } : {};

const defaultRootOwned = (p: string): boolean => {
  try {
    const s = statSync(p);
    return s.isFile() && s.uid === 0 && (s.mode & 0o022) === 0;
  } catch {
    return false;
  }
};

/** An executable regular file at `p` (no PATH search). */
const executableFile = (p: string): boolean => {
  try {
    if (!statSync(p).isFile()) return false;
    accessSync(p, constants.X_OK);
    return true;
  } catch {
    return false;
  }
};

/** Is `p` (absolute, resolved) a system binary only root can change: the
 *  file and every directory above it root-owned, none writable by group or
 *  others (Apple's `/usr/bin/git`, APPLE_GIT_SHIM; never in a Homebrew
 *  prefix or `~/.local/bin`, which the user and so the agent can write). */
const defaultSystemOwned = (p: string): boolean => {
  if (!p.startsWith("/")) return false;
  try {
    for (let q = p; ; q = q.slice(0, q.lastIndexOf("/")) || "/") {
      const s = statSync(q);
      if (s.uid !== 0 || (s.mode & 0o022) !== 0) return false;
      if (q === "/") return true;
    }
  } catch {
    return false;
  }
};

export interface ResolveGitDeps {
  /** The PATH to search (default: this process's). */
  path?: string;
  executable?: (p: string) => boolean;
  realpath?: (p: string) => string | null;
  /** `<git> --exec-path`, under the git profile (`boxed`) or as is: its
   *  answer, null when it fails, "transient" when it could not be judged. */
  execPath?: (git: string, boxed: boolean) => string | null | "transient";
  /** Is `p` a system binary only root can change (defaultSystemOwned)?
   *  Asked of APPLE_GIT_SHIM only. */
  systemOwned?: (p: string) => boolean;
}

/** Apple's stand-in for git: it finds the developer directory's git through
 *  xcrun and runs it. The one binary whose `--exec-path` is asked as is. */
export const APPLE_GIT_SHIM = "/usr/bin/git";

const defaultExecPath = (git: string, boxed: boolean): string | null | "transient" => {
  const file = boxed ? SANDBOX_EXEC : git;
  const args = boxed ? ["-p", gitSeatbeltProfile(git), git, "--exec-path"] : ["--exec-path"];
  const r = spawnSync(file, args, { cwd: "/", encoding: "utf8", timeout: 10_000, stdio: ["ignore", "pipe", "ignore"], env: hardenedGitEnv() });
  const v = probeRunVerdict(r);
  return v === true ? r.stdout.trim() : v === "transient" ? "transient" : null;
};

/**
 * The git binary the macOS sandbox runs, by absolute resolved path, or null
 * (none), or "transient" (its `--exec-path` could not be judged): the first
 * executable `git` on PATH (absolute entries only), resolved; then, when
 * `<it> --exec-path` names a directory whose `git` resolves to an executable
 * file, that one. The Apple `/usr/bin/git` is a shim that finds the
 * developer directory's git through xcrun and runs it (a second exec, and
 * xcrun's own cache writes); its exec path's `git` is the real binary (the
 * Command Line Tools' `libexec/git-core/git` → `../../bin/git`), which reads
 * no DEVELOPER_DIR. `--exec-path` reads no repository.
 *
 * The `--exec-path` run is itself sandboxed: under the git profile
 * (gitSeatbeltProfile, nothing writable: no network, no write, no fork, no
 * exec but that binary), so a `git` planted on PATH never runs outside a
 * sandbox here. Only the Apple shim (APPLE_GIT_SHIM), which must exec
 * xcrun's pick and so cannot run under that profile, is asked again as is
 * when the sandboxed run fails, and only while it and every directory above
 * it are root's alone (systemOwned): never another binary a link on PATH
 * names, root's or not.
 */
export function resolveGitBinary(deps: ResolveGitDeps = {}): string | null | "transient" {
  const executable = deps.executable ?? executableFile;
  const realpath = deps.realpath ?? realpathOrNull;
  const execPath = deps.execPath ?? defaultExecPath;
  const systemOwned = deps.systemOwned ?? defaultSystemOwned;
  let first: string | null = null;
  for (const dir of (deps.path ?? process.env["PATH"] ?? "").split(":")) {
    if (!dir.startsWith("/")) continue;
    const cand = `${dir === "/" ? "" : dir.replace(/\/+$/, "")}/git`;
    if (!executable(cand)) continue;
    const r = realpath(cand);
    if (r !== null && executable(r)) { first = r; break; }
  }
  if (first === null) return null;
  let dir = execPath(first, true);
  if (dir === null && first === APPLE_GIT_SHIM && systemOwned(first)) dir = execPath(first, false);
  if (dir === "transient") return "transient";
  if (dir !== null && dir.startsWith("/")) {
    const real = realpath(`${dir.replace(/\/+$/, "")}/git`);
    if (real !== null && executable(real)) return real;
  }
  return first;
}

/** What one probe found: the sandbox, or none. `transient`: none only
 *  because a run could not be judged (a timeout, no free process), so the
 *  answer is not final (gitSandboxCache probes again later). */
export interface GitSandboxProbe {
  sandbox: GitSandbox | null;
  transient: boolean;
}

const NO_SANDBOX: GitSandboxProbe = { sandbox: null, transient: false };

/** Linux: Mandu's own root-owned bubblewrap, then the distribution's
 *  (bwrap-path.ts: an administrator's `bwrap_path`, else the first on PATH
 *  outside the current directory, by absolute path; never a bare `bwrap`),
 *  each with every flag set, running `git --version` inside. */
function probeBwrapGitSandbox(deps: GitSandboxProbeDeps): GitSandboxProbe {
  const run = probeRunner(deps);
  const rootOwned = deps.rootOwned ?? defaultRootOwned;
  const env = deps.env ?? process.env;
  const system = (deps.systemBwrap ?? ((): string | null => systemBwrapBin(env["PATH"] !== undefined ? { path: env["PATH"] } : {})))();
  const candidates = [...(rootOwned(MANDU_OWN_BWRAP) ? [MANDU_OWN_BWRAP] : []), ...(system !== null ? [system] : [])];
  let transient = false;
  for (const bwrap of candidates) {
    for (const flags of GIT_SANDBOX_FLAG_SETS) {
      const probe = gitCommand(["--version"], { bwrap, flags });
      const ran = run(probe.file, probe.args);
      if (ran.ok === true) return { sandbox: { bwrap, flags, ...probeVersion(ran.stdout) }, transient: false };
      if (ran.ok === "transient") transient = true;
    }
  }
  return { sandbox: null, transient };
}

/** macOS: SANDBOX_EXEC present, a git resolved, and `sandbox-exec -p
 *  <profile> <git> --version` exiting 0. It exits 71 ("sandbox_apply:
 *  Operation not permitted") inside another Seatbelt profile: sandbox-exec
 *  does not nest. */
function probeSeatbeltGitSandbox(deps: GitSandboxProbeDeps, env: Readonly<Record<string, string | undefined>>): GitSandboxProbe {
  const run = probeRunner(deps);
  const executable = deps.executable ?? executableFile;
  if (!executable(SANDBOX_EXEC)) return NO_SANDBOX;
  const path = env["PATH"] ?? process.env["PATH"];
  const git = (deps.resolveGit ?? (() => resolveGitBinary({ executable, ...(path !== undefined ? { path } : {}) })))();
  if (git === "transient") return { sandbox: null, transient: true };
  if (git === null) return NO_SANDBOX;
  const sandbox: SeatbeltGitSandbox = { sandboxExec: SANDBOX_EXEC, git };
  const probe = gitCommand(["--version"], sandbox);
  const ran = run(probe.file, probe.args);
  return ran.ok === true ? { sandbox: { ...sandbox, ...probeVersion(ran.stdout) }, transient: false } : { sandbox: null, transient: ran.ok === "transient" };
}

/**
 * Probe for the sandbox git runs in here: on Linux a bubblewrap (Mandu's own
 * copy when it is installed root-owned, else the distribution's (bwrap-path.ts), each tried
 * with every flag set, GIT_SANDBOX_FLAG_SETS); on macOS `sandbox-exec` with
 * the git resolveGitBinary finds. Each is kept only when `git --version`
 * runs inside. None when none works (no bwrap, no unprivileged user
 * namespaces, an AppArmor restriction; no sandbox-exec, inside another
 * Seatbelt profile; another platform) or MANDU_GIT_SANDBOX=0: the hardened
 * git then runs as is. `transient` when none was found only because a run
 * could not be judged.
 */
export function probeGitSandboxOutcome(deps: GitSandboxProbeDeps = {}): GitSandboxProbe {
  const env = deps.env ?? process.env;
  if (env["MANDU_GIT_SANDBOX"] === "0") return NO_SANDBOX;
  const platform = deps.platform ?? process.platform;
  if (platform === "linux") return probeBwrapGitSandbox(deps);
  if (platform === "darwin") return probeSeatbeltGitSandbox(deps, env);
  return NO_SANDBOX;
}

/** The sandbox probeGitSandboxOutcome found, or null. */
export function probeGitSandbox(deps: GitSandboxProbeDeps = {}): GitSandbox | null {
  return probeGitSandboxOutcome(deps).sandbox;
}

/** How long gitSandbox waits before it probes again while it has no final
 *  answer (a transient probe, or a Seatbelt sandbox whose git is gone and
 *  no working one yet): from `first`, doubling, up to `max`. */
export const GIT_SANDBOX_RETRY_MS = { first: 1_000, max: 300_000 } as const;

export interface GitSandboxCacheDeps {
  probe?: () => GitSandboxProbe;
  now?: () => number;
  /** Is `p` an executable regular file (the Seatbelt git still there)? */
  executable?: (p: string) => boolean;
  env?: Readonly<Record<string, string | undefined>>;
}

/**
 * The per-process answer behind gitSandbox, as a function (a factory so the
 * unit test can drive it). It probes on first use and keeps what it finds,
 * never settling on "none" by accident:
 *
 *   - a sandbox found is kept; a Seatbelt one is probed again when its git
 *     is gone (a `brew upgrade` moves Homebrew's Cellar path);
 *   - "none" is kept only when the probe's answer is final: a transient
 *     probe (a timeout, no free process) returns null for that call and
 *     probes again after a backoff (GIT_SANDBOX_RETRY_MS);
 *   - once this process has run git under Seatbelt it never falls back to
 *     none (MANDU_GIT_SANDBOX=0 aside): until a probe finds a working
 *     sandbox again it keeps returning the last one, whose missing git makes
 *     each call fail (fail closed), and probes again after the backoff. A
 *     `git` swapped for one that fails the probe while the real one is away
 *     cannot turn the sandbox off for good.
 */
export function gitSandboxCache(deps: GitSandboxCacheDeps = {}): () => GitSandbox | null {
  const probe = deps.probe ?? (() => probeGitSandboxOutcome());
  const now = deps.now ?? Date.now;
  const executable = deps.executable ?? executableFile;
  const env = deps.env ?? process.env;
  let held: GitSandbox | null | undefined;
  let lastSeatbelt: SeatbeltGitSandbox | null = null;
  let retryAt = 0;
  let wait = 0;
  return () => {
    if (held !== undefined && held !== null && isSeatbeltGitSandbox(held) && !executable(held.git)) held = undefined;
    if (held !== undefined) return held;
    if (now() < retryAt) return lastSeatbelt;
    const found = probe();
    if (found.sandbox !== null) {
      held = found.sandbox;
      if (isSeatbeltGitSandbox(found.sandbox)) lastSeatbelt = found.sandbox;
      wait = 0;
      retryAt = 0;
      return held;
    }
    if (!found.transient && (lastSeatbelt === null || env["MANDU_GIT_SANDBOX"] === "0")) {
      held = null;
      return null;
    }
    wait = wait === 0 ? GIT_SANDBOX_RETRY_MS.first : Math.min(wait * 2, GIT_SANDBOX_RETRY_MS.max);
    retryAt = now() + wait;
    return lastSeatbelt;
  };
}

const processGitSandbox = gitSandboxCache();
/** The sandbox for this process's git calls (gitSandboxCache). */
export function gitSandbox(): GitSandbox | null {
  return processGitSandbox();
}
