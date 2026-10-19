/**
 * seatbelt-profile — the ONE whole-agent Seatbelt (`sandbox-exec`) profile of a
 * macOS launch: the macOS enactment of the Linux whole-agent guard and
 * landlock-net (docs/design/confidentiality/confidentiality.md §7.3; write-protection.md §8;
 * exec-routing.md §4.3 and §7.1).
 *
 * macOS has no mount namespaces, no seccomp user notification and no Landlock,
 * so the guard's by-descriptor twins, its write-protect trap, its Unix-socket
 * supervision and the Landlock TCP rules have no direct counterpart. What an
 * unprivileged macOS process CAN do is run a program under a Seatbelt profile
 * that the kernel enforces on it and on everything it starts. This module
 * renders that profile, one component per Linux rung:
 *
 *   1. credential files   unreadable and unwritable; the file and every
 *                         directory above it cannot be renamed or removed
 *                         (a rename of the file, or of a parent, then a read
 *                         of the new name was the verified bypass of the old
 *                         read-only deny, 2026-09-29);
 *   2. Mandu's own state  the symbol DB (plaintext registered values), the
 *                         event store (originals) and the shadow repositories:
 *                         unreadable and unwritable (`secrets` mode only),
 *                         the home's carve-outs allowed back after them;
 *   3. write-protect      the write-protect list (write-protect.ts): nothing
 *                         under it may be written, created, renamed or removed,
 *                         nor any directory above it renamed. Seatbelt cannot
 *                         ask, so the list's `ask` entries are REFUSED;
 *   4. network            the landlock-net port set: TCP connect only to the
 *                         listed ports, TCP bind only to the bind ports. UDP is
 *                         left alone, as on Linux (DNS keeps working);
 *   5. Unix sockets       connect only to the listed sockets (unix-policy.ts);
 *                         known host services that run code (docker, …) are
 *                         refused even inside an allowed directory;
 *   6. host services      no exec of the programs that ask launchd or
 *                         LaunchServices to run code outside the profile
 *                         (`open`, `osascript`, `launchctl`, `crontab`, `at`,
 *                         `batch`), and no Apple Events;
 *   and the arbiter's HUMAN PLANE (the guard's always-deny `unixDeny` on
 *   Linux, arbiter-human-plane.md §5): no connect to a socket in its
 *   directories, no read or write under them, no rename above them —
 *   whatever the components allow;
 *   and Mandu's RUNTIME REGISTRIES (runtime-registry.ts; runtime-instances.md
 *   §2): the arbiter's `instances/`, the `current` link and its promotion's
 *   temporary link, the legacy socket path, the dashboards and VM-guest
 *   registries, `mandu dashboard`'s log and port files, the base-level logs
 *   and the test tenant's socket dir, under the launch's runtime base and
 *   the account's default one. Nothing there may be written, created,
 *   renamed or removed, nor a directory above them renamed: Mandu processes
 *   OUTSIDE the profile (the arbiter's sweep and manifest write, `mandu
 *   reap`, the dashboard) read, write through and delete from them, so a
 *   link or a forged entry planted there would act for the agent. The rest
 *   of the runtime dir (the session's own dir) stays writable, and every
 *   socket in it reachable.
 *
 * SBPL facts this relies on, each verified with `sandbox-exec` on macOS 26.5
 * (the probes are the darwin live test, test/darwin/seatbelt-live.test.ts):
 *   - path filters match the CANONICAL path only (`/private/tmp`, never
 *     `/tmp`), so every path rule is emitted for the given spelling AND its
 *     canonical one (the caller's `canonical`);
 *   - `subpath` matches whole components (`/a/b` never matches `/a/bc`) and
 *     the path itself, so one `subpath` rule serves a file or a directory;
 *   - `file-write*` on a file covers truncate, replace-by-rename, unlink,
 *     chmod, `renamex_np(RENAME_SWAP)` and `exchangedata`; `file-read*`
 *     covers `ln`, `cp -c` and `clonefile`; renaming a PARENT directory needs
 *     `file-write-unlink` on that directory itself (literal, so the directory
 *     stays writable);
 *   - `(remote tcp "localhost:P")` matches 127.0.0.1 and ::1 (and this host's
 *     own addresses); `(remote tcp)` and `(remote unix-socket)` are separate
 *     domains;
 *   - a bind rule that works: `(deny network-bind (local ip))` then
 *     `(allow network-bind (local udp))` then `(allow network-bind (local ip
 *     "*:P"))`. `(local tcp "*:P")` never matches a bind, so it cannot be
 *     used to re-allow one;
 *   - `connect(2)` to a Unix socket whose FILE is write-denied still works
 *     (the arbiter socket is write-protected and reachable), and so does one
 *     under a write-denied `subpath` (the instance registry), by its path
 *     or through `current`; a new socket cannot be bound there (2026-09-30);
 *   - `(prefix "P")` matches every path that starts with the string P (a
 *     name prefix, not a component): creating, replacing or removing
 *     `<base>/.current.tmp-<pid>` or `<base>/dashboard-<pid>.port.tmp` is
 *     refused, `<base>/.current.tmpX` and `<base>/dashboardX` are not;
 *   - `sandbox-exec -p <text>` applies the same profile as `-f <file>`, and
 *     both refuse one whose compiled form passes 64 KiB ("data object length
 *     … exceeds maximum (65535)"), so passing it inline adds no size limit;
 *   - a `(remote unix-socket (subpath D))` connect deny holds through a
 *     symlink to the socket or to D, and a hard link to the socket cannot be
 *     made when D is read- and write-denied; renaming a directory ABOVE D
 *     escapes it, so D's ancestors get the rename guard (2026-09-30);
 *   - ORDER MATTERS between the two `network-outbound` families: a bare
 *     `(deny network-outbound (remote unix-socket))` placed AFTER the TCP
 *     allow misfires on a TCP connect to some ports (~6%, by port number), so
 *     the Unix-socket component is rendered before the TCP one (below).
 *
 * SBPL is last-match-wins: `(allow default)` first, then each component's
 * denies, then that component's own exceptions (which re-allow only within
 * the operation the deny named).
 *
 * PURE: every host fact (the canonical spelling of a path) is an input, and
 * the output is sorted and deduped, so the unit tests pin it byte for byte.
 * The one exception is `sandboxExecAvailable`, the host check for the
 * `sandbox-exec` the wrap names by absolute path (`SANDBOX_EXEC`).
 *
 * Mandu-new (no reference origin).
 */
import { accessSync, constants, statSync } from "node:fs";

/** One TCP connect allowance: `localhost` for Mandu's own loopback services,
 *  `*` where Linux's port-only rule is kept verbatim (443, 22, a declared
 *  model endpoint, an explicit --landlock-net port). */
export interface SeatbeltNetRule {
  host: "localhost" | "*";
  port: number;
}

/** Component 4, the landlock-net analog. */
export interface SeatbeltNet {
  connect: SeatbeltNetRule[];
  /** TCP ports the tree may bind (listen on); each is also connectable. */
  bind: number[];
}

/** Component 5, the unix-policy analog. Every entry is a socket file or a
 *  directory of sockets (a `subpath` serves both). */
export interface SeatbeltUnix {
  /** Reachable: Mandu, name service, logging, the ssh and gpg agents, the
   *  display, the workspace. */
  allow: string[];
  /** Refused even when an `allow` entry holds them: host services that run
   *  code on request (docker and its kin, a host tmux server). */
  refuse: string[];
  /** The human's own additions (policy.yaml `unix_sockets.allow`,
   *  MANDU_UNIX_ALLOW): reachable, over `refuse`. */
  extra: string[];
}

/** Mandu's runtime registries (runtime-registry.ts `runtimeRegistryPaths`):
 *  `deny file-write*`, so nothing there is written, created, renamed or
 *  removed from inside the profile. Reads and connects stay allowed. */
export interface SeatbeltRuntime {
  /** Directories, as a `subpath` (the directory itself and all below it). */
  dirs: string[];
  /** Entries named ITSELF, as a `literal` in the given spelling and with
   *  only the parent resolved: `current` is a link, and following it would
   *  name the instance dir instead of the link. */
  names: string[];
  /** Name prefixes, as a `prefix` (spelled like `names`): the promotion's
   *  temporary link `.current.tmp-<pid>`. */
  prefixes: string[];
}

export interface SeatbeltProfileInput {
  /** Component 1: the registered credential files. */
  secrets?: readonly string[];
  /** Component 2: Mandu's secret-bearing state, directories and files. */
  stateDirs?: readonly string[];
  stateFiles?: readonly string[];
  /** Component 2: Mandu's own config and install dirs (write only). */
  stateWriteOnly?: readonly string[];
  /** Component 2's exceptions: the home's carve-outs (the integrity modes'
   *  AgentView, `full`'s repo.git; on-disk-layout.md §4), read and write
   *  allowed back after the state denies. Only with a state deny to carve
   *  from: an allow alone adds nothing to `(allow default)`. */
  stateCarveOuts?: readonly string[];
  /** The arbiter's human-plane socket directories (arbiter-human-plane.md
   *  §5): no connect to a socket in them, no read or write under them, and no
   *  rename of a directory above them — the one rule that serves originals
   *  must stay out of the agent's reach, whatever the other components
   *  allow. */
  humanDirs?: readonly string[];
  /** Component 3: the write-protect list's paths (both answers). A symlink
   *  here protects its target too (its canonical spelling), as the Linux
   *  guard judges the file a write resolves to. */
  writeProtect?: readonly string[];
  /** Component 3, the entries that name a file or link ITSELF, never what a
   *  link points to: the arbiter socket and the symlinks on its way
   *  (write-protect.ts `arbiterSocketFiles`). `/tmp` → `/private/tmp` is such
   *  a link on macOS; following it would seal all of /private/tmp. Literal,
   *  in the given spelling and with only the parent directory resolved. */
  writeProtectLinks?: readonly string[];
  /** Component 3's exceptions: directories strictly below a write-protected
   *  entry that stay writable (the Mandu home's carve-outs, write-protect.ts
   *  `except`), as the Linux guard skips them. */
  writeProtectExcept?: readonly string[];
  /** policy.yaml `protect:` — no delete, no rename, of it or under it. */
  noDelete?: readonly string[];
  /** Mandu's runtime registries: never written; the directories above them
   *  unrenameable. null/absent: none. */
  runtime?: SeatbeltRuntime | null;
  /** Component 4. null/absent: TCP is not confined. */
  net?: SeatbeltNet | null;
  /** Component 5. null/absent: Unix sockets are not confined. */
  unix?: SeatbeltUnix | null;
  /** Component 6. */
  hostServices?: boolean;
  /** Map a path to its canonical spelling (the realpath of its longest
   *  existing prefix; `canonicalPath`). Default: identity. */
  canonical?: (p: string) => string;
}

/** The programs that hand work to launchd or LaunchServices, which then runs
 *  it OUTSIDE this profile (sandbox review finding 1's macOS analog). A copy
 *  of an Apple platform binary elsewhere is killed at exec (code signing);
 *  `launchctl` is the exception, a residual (docs/guarantees.md §3). */
export const HOST_SERVICE_PROGRAMS: readonly string[] = [
  "/bin/launchctl",
  "/usr/bin/at",
  "/usr/bin/batch",
  "/usr/bin/crontab",
  "/usr/bin/open",
  "/usr/bin/osascript",
];

/** SBPL string literal: backslash and double quote escaped. */
export function sbplQuote(p: string): string {
  return `"${p.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

/** An absolute, normalized path (no trailing slash, no empty, `.` or `..`
 *  component), or null for anything else: a relative path would match
 *  nothing in SBPL, and a `..` would name a different file. */
export function normalizeAbs(p: string): string | null {
  if (!p.startsWith("/")) return null;
  const parts: string[] = [];
  for (const c of p.split("/")) {
    if (c === "" || c === ".") continue;
    if (c === "..") { parts.pop(); continue; }
    parts.push(c);
  }
  return "/" + parts.join("/");
}

/** The canonical spelling of `p`: the realpath of its longest existing
 *  prefix plus the rest, so a file that does not exist yet (a `~/.zshrc` to
 *  be created, a `~/Library/LaunchAgents` not made) still gets its
 *  `/private/…` spelling. Pure given `realpath` (null = does not resolve). */
export function canonicalPath(p: string, realpath: (p: string) => string | null): string {
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

/** Every directory above `p`, nearest first, `/` excluded. */
export function ancestorsOf(p: string): string[] {
  const out: string[] = [];
  let d = p;
  for (;;) {
    const i = d.lastIndexOf("/");
    if (i <= 0) break;
    d = d.slice(0, i);
    out.push(d);
  }
  return out;
}

function sorted(xs: Iterable<string>): string[] {
  return [...new Set(xs)].sort();
}

/** Every spelling the profile renders for `paths`: each one normalized as
 *  given and in its canonical spelling (`canon`), sorted and deduped. A path
 *  that is not absolute, and `/` itself, is dropped: a relative path would
 *  match nothing in SBPL. The renderer's own, exported so seatbelt-setup.ts
 *  judges what a profile seals on exactly what it renders. Pure. */
export function seatbeltSpellings(paths: readonly string[] | undefined, canon: (p: string) => string = (p) => p): string[] {
  const out = new Set<string>();
  for (const raw of paths ?? []) {
    const p = normalizeAbs(raw);
    if (p === null || p === "/") continue;
    out.add(p);
    const c = normalizeAbs(canon(p));
    if (c !== null && c !== "/") out.add(c);
  }
  return sorted(out);
}

/**
 * Render the profile, or null when no component has anything to say (never
 * wrap for nothing).
 */
export function renderSeatbeltProfile(input: SeatbeltProfileInput): string | null {
  const canon = input.canonical ?? ((p: string) => p);
  /** Both spellings of each path, normalized, sorted, deduped. */
  const spell = (paths: readonly string[] | undefined): string[] => seatbeltSpellings(paths, canon);
  /** A link's own spellings: as given, and with only its parent resolved. */
  const spellNoFollow = (paths: readonly string[] | undefined): string[] => {
    const out = new Set<string>();
    for (const raw of paths ?? []) {
      const p = normalizeAbs(raw);
      if (p === null || p === "/") continue;
      out.add(p);
      const i = p.lastIndexOf("/");
      const parent = normalizeAbs(canon(i === 0 ? "/" : p.slice(0, i)));
      if (parent !== null) out.add(`${parent === "/" ? "" : parent}/${p.slice(i + 1)}`);
    }
    return sorted(out);
  };
  const secrets = spell(input.secrets);
  const stateDirs = spell(input.stateDirs);
  const stateFiles = spell(input.stateFiles);
  const stateWrite = spell(input.stateWriteOnly);
  const carveOuts = stateDirs.length > 0 ? spell(input.stateCarveOuts) : [];
  const human = spell(input.humanDirs);
  const writeProtect = spell(input.writeProtect);
  const writeLinks = spellNoFollow(input.writeProtectLinks);
  // Only strictly below a protected entry (net-supervisor `carves`): an
  // exception elsewhere would re-allow writes no deny had taken away.
  const writeExcept = spell(input.writeProtectExcept).filter((x) => writeProtect.some((w) => x.startsWith(`${w}/`)));
  const noDelete = spell(input.noDelete);
  const runtimeDirs = spell(input.runtime?.dirs);
  const runtimeNames = spellNoFollow(input.runtime?.names);
  const runtimePrefixes = spellNoFollow(input.runtime?.prefixes);
  const net = input.net ?? null;
  const unix = input.unix ?? null;
  const hostServices = input.hostServices === true;
  if (
    secrets.length + stateDirs.length + stateFiles.length + stateWrite.length + writeProtect.length + writeLinks.length + noDelete.length +
      human.length + runtimeDirs.length + runtimeNames.length + runtimePrefixes.length === 0 &&
    net === null && unix === null && !hostServices
  ) {
    return null;
  }

  const lines: string[] = [
    "(version 1)",
    ";; Mandu — the whole-agent Seatbelt profile (confidentiality.md §7.3).",
    ";; The macOS enactment of the Linux guard and landlock-net: last match wins,",
    ";; so each component's denies follow the default allow and its own",
    ";; exceptions follow its denies.",
    "(allow default)",
  ];
  const rule = (head: string, filters: string[]): void => {
    if (filters.length === 0) return;
    lines.push(`(${head}`, ...filters.map((f, i) => `  ${f}${i === filters.length - 1 ? ")" : ""}`));
  };
  const lit = (p: string): string => `(literal ${sbplQuote(p)})`;
  const sub = (p: string): string => `(subpath ${sbplQuote(p)})`;
  const pre = (p: string): string => `(prefix ${sbplQuote(p)})`;

  // The directories above every protected path: renaming one moves the
  // protected tree to a name no rule covers. Literal, so each directory's
  // own contents stay writable.
  // The human plane's included: a renamed runtime base puts its socket at a
  // path the connect deny does not name (verified on macOS 26.5, 2026-09-30).
  // So are the runtime registries: a renamed base would let the agent build a
  // new one, planted links and all, for the next Mandu process to find.
  const guarded = [
    ...secrets, ...stateDirs, ...stateFiles, ...stateWrite, ...writeProtect, ...writeLinks, ...noDelete, ...human,
    ...runtimeDirs, ...runtimeNames, ...runtimePrefixes,
  ];
  const covered = (d: string): boolean =>
    [...stateDirs, ...stateWrite, ...writeProtect, ...noDelete, ...human, ...runtimeDirs].some((s) => d === s || d.startsWith(`${s}/`));
  const ancestors = sorted(guarded.flatMap(ancestorsOf)).filter((d) => !covered(d));

  if (secrets.length > 0) {
    lines.push(";; 1. Credential files: a read fails; no write, rename or delete.");
    rule("deny file-read* file-write*", secrets.map(lit));
  }
  if (stateDirs.length + stateFiles.length + stateWrite.length > 0) {
    lines.push(";; 2. Mandu's own state: the symbol DB, the event store, the shadow repositories.");
    rule("deny file-read* file-write*", [...stateDirs.map(sub), ...stateFiles.map(lit)]);
    rule("deny file-write*", stateWrite.map(sub));
  }
  if (carveOuts.length > 0) {
    lines.push(";;    Its carve-outs (on-disk-layout.md §4), allowed back after the denies.");
    rule("allow file-read* file-write*", carveOuts.map(sub));
  }
  if (writeProtect.length + writeLinks.length > 0) {
    lines.push(";; 3. Write-protect: Mandu's own files and the files that run later (refused, not asked).");
    rule("deny file-write*", [...writeProtect.map(sub), ...writeLinks.map(lit)]);
    rule("allow file-write*", writeExcept.map(sub));
  }
  if (noDelete.length > 0) {
    lines.push(";; policy.yaml protect: no delete or rename, of it or of anything under it.");
    rule("deny file-write-unlink", noDelete.map(sub));
  }
  // After every file allow above (the carve-outs, the write-protect
  // exceptions): last match wins, and none may reopen a registry.
  if (runtimeDirs.length + runtimeNames.length + runtimePrefixes.length > 0) {
    lines.push(";; Mandu's runtime registries (runtime-instances.md §2): never written from here; sockets stay reachable.");
    rule("deny file-write*", [...runtimeDirs.map(sub), ...runtimeNames.map(lit), ...runtimePrefixes.map(pre)]);
  }
  if (ancestors.length > 0) {
    lines.push(";; The directories above them: no rename, no delete (their contents stay writable).");
    rule("deny file-write-unlink", ancestors.map(lit));
  }
  // The Unix-socket rules come BEFORE the TCP rules, on purpose. Verified on
  // macOS 26.5 (2026-09-29, randomized ports and paths): with the TCP rules
  // first, a later bare `(deny network-outbound (remote unix-socket))`
  // spuriously matched a TCP connect to about 6% of allowed ports (EPERM on
  // the model proxy's port, depending only on the port number), whichever
  // path filter the socket rules used. With the socket rules first and the
  // TCP rules last, every TCP decision comes from the TCP rules, and no
  // decision was wrong in 550 randomized runs (none ever allowed what it
  // should deny, in either order). The darwin live test re-checks it.
  if (unix !== null) {
    lines.push(";; 5. Unix sockets (unix-policy): only the listed ones; host services that run code are refused.");
    lines.push(";;    (Before the TCP rules: after them, the bare unix-socket deny misfires on some TCP ports.)");
    lines.push("(deny network-outbound (remote unix-socket))");
    const remote = (p: string): string => `(remote unix-socket (subpath ${sbplQuote(p)}))`;
    rule("allow network-outbound", spell(unix.allow).map(remote));
    rule("deny network-outbound", spell(unix.refuse).map(remote));
    rule("allow network-outbound", spell(unix.extra).map(remote));
  }
  // The human plane after every file and socket allow above (last match
  // wins), and like the socket rules before the TCP rules.
  if (human.length > 0) {
    lines.push(";; The arbiter's human plane (arbiter-human-plane.md §5): no connect, no read or write.");
    rule("deny file-read* file-write*", human.map(sub));
    rule("deny network-outbound", human.map((p) => `(remote unix-socket (subpath ${sbplQuote(p)}))`));
  }
  if (net !== null) {
    const connect = [...new Set(net.connect.filter((r) => Number.isInteger(r.port) && r.port > 0 && r.port < 65536).map((r) => `${r.host}:${r.port}`))];
    const bind = [...new Set(net.bind.filter((p) => Number.isInteger(p) && p > 0 && p < 65536))].sort((a, b) => a - b);
    // A bind port is also connectable (the agent's own client dials its server).
    for (const p of bind) connect.push(`*:${p}`);
    const order = (a: string, b: string): number => {
      const [ha, pa] = a.split(":");
      const [hb, pb] = b.split(":");
      return Number(pa) - Number(pb) || (ha! < hb! ? -1 : ha! > hb! ? 1 : 0);
    };
    lines.push(";; 4. Network (landlock-net): TCP connect and bind only to the listed ports; UDP untouched.");
    lines.push("(deny network-outbound (remote tcp))");
    rule("allow network-outbound", [...new Set(connect)].sort(order).map((a) => `(remote tcp ${sbplQuote(a)})`));
    lines.push("(deny network-bind (local ip))");
    lines.push("(allow network-bind (local udp))");
    rule("allow network-bind", bind.map((p) => `(local ip ${sbplQuote(`*:${p}`)})`));
  }
  if (hostServices) {
    lines.push(";; 6. Host services that run code outside this profile: launchd, LaunchServices, Apple Events.");
    rule("deny process-exec", sorted(HOST_SERVICE_PROGRAMS).map(lit));
    lines.push("(deny appleevent-send)");
  }
  return lines.join("\n") + "\n";
}

/** The ONE `sandbox-exec` a launch runs and checks for: the base system's, by
 *  absolute path. Never the bare name: the wrap is exec'd through the agent's
 *  PATH (BSD script's execvp, or node's spawn with the agent env), which keeps
 *  the user's own directories (`~/.local/bin`, `/opt/homebrew/bin`) ahead of
 *  /usr/bin, and the profile does not write-protect them. A `sandbox-exec`
 *  the agent planted there in one session would otherwise run the NEXT
 *  session's agent with no profile while the launch still said read-blocked
 *  (review 2026-09-29, docs-tests-11; confidentiality.md §7.3). */
export const SANDBOX_EXEC = "/usr/bin/sandbox-exec";

/** The macOS wrap argv for a rendered profile FILE: SANDBOX_EXEC by path. A
 *  launch does not use it (`seatbeltWrapArgvInline` below); it serves a
 *  person re-running a session's copy by hand. */
export function seatbeltWrapArgv(profilePath: string): string[] {
  return [SANDBOX_EXEC, "-f", profilePath];
}

/** The macOS wrap argv that hands SANDBOX_EXEC the profile TEXT (`-p`), the
 *  one a launch uses (seatbelt-setup.ts): nothing is read back from a path
 *  after the launcher rendered it. A profile file in the runtime dir is
 *  writable to the agent of ANOTHER session (the base stays writable, and
 *  only this session's own profile protects this session's copy), which
 *  could swap it between the write and sandbox-exec's read and so start
 *  this session's agent under a profile of its own (review 2026-09-30).
 *  The text (paths and rules, no secret values) is in the argv of the
 *  processes that carry the wrap (the reply filter, script(1)), as readable
 *  to this account as the file copy is; sandbox-exec itself execs the agent
 *  in place. */
export function seatbeltWrapArgvInline(profile: string): string[] {
  return [SANDBOX_EXEC, "-p", profile];
}

/** An executable regular file at `p` (no PATH search). */
function executableFile(p: string): boolean {
  try {
    if (!statSync(p).isFile()) return false;
    accessSync(p, constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

/** Is SANDBOX_EXEC there to run? Every availability check of a launch, the
 *  proxy's posture prediction and the doctor asks THIS, so each answers for
 *  the binary the wrap runs and none for a PATH entry. `check` answers for a
 *  path: a caller's injected command check (`commandExists`; given an
 *  absolute path, `command -v` tests that file and never searches PATH) or,
 *  by default, the file's own executable bit. The one host probe here; the
 *  renderer above stays pure. */
export function sandboxExecAvailable(check: (path: string) => boolean = executableFile): boolean {
  return check(SANDBOX_EXEC);
}
