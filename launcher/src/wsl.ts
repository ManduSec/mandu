/**
 * wsl — Windows Subsystem for Linux: what `mandu doctor` and a launch say
 * about it, and the flags the whole-agent wrap adds there
 * (docs/design/testing/os-test-matrix.md `wsl2` row, exec-routing.md §4.1).
 *
 * WSL2 is a real Linux kernel, so every Linux mechanism applies unchanged.
 * Three things are WSL-only:
 *   1. Windows interop. A PE exec (`cmd.exe`, a copied `.exe`) is handed by the
 *      kernel's `WSLInterop` binfmt entry to `/init`, which asks the Windows
 *      side over the socket `$WSL_INTEROP` names (`/run/WSL/<pid>_interop`) to
 *      start the program OUTSIDE every Linux namespace, Landlock domain and
 *      seccomp filter; it can read the real files through `\\wsl.localhost` and
 *      reach any host. The boxes hide the socket (exec-supervisor, and the
 *      secret-twin wrap via `wslTwinWrapFlags`) and the connect guard refuses
 *      it plus AF_VSOCK (net-supervisor `WslGuard`). The same detection lives
 *      in Rust (`mandu_arbiter::wsl`); `wslVersion` is parity-tested on the
 *      same strings.
 *   2. Windows drives (`/mnt/c`, drvfs over 9p). Slow, and an edit made from
 *      Windows raises no inotify event, so fs-sync's human-edit clock misses
 *      it (it reconciles at the next tool result instead). A launch there
 *      WARNS with the fix (move the project into the Linux file system); it
 *      does not refuse, since no view leaks: the AgentView lives under the
 *      Linux state dir either way.
 *   3. systemd is optional per distribution: without it the dashboard's user
 *      unit never starts.
 *   4. A second HOME per Windows user: `/mnt/<drive>/Users/<name>` holds the
 *      same credential stores (`.aws`, `.ssh`, `AppData/Roaming/gcloud`, …).
 *      Secret discovery probes the catalog's paths under each profile
 *      (`windowsProfiles`, `windowsProfileSecretRoots`), so the `secrets`
 *      mode twins them as it twins `~/.aws` (confidentiality.md §7.2).
 *
 * Pure: every host read is an injected dep.
 *
 * Mandu-new (no reference origin).
 */

export const WSL_INTEROP_ENV = "WSL_INTEROP";
export const INTEROP_DIR = "/run/WSL";
export const INIT_PATH = "/init";
export const BINFMT_INTEROP = "/proc/sys/fs/binfmt_misc/WSLInterop";
export const OSRELEASE = "/proc/sys/kernel/osrelease";
export const MOUNTINFO = "/proc/self/mountinfo";
export const SYSTEMD_RUNNING = "/run/systemd/system";

/** WSL generation from `/proc/sys/kernel/osrelease`: WSL2 kernels carry
 *  `-microsoft-standard` (`-microsoft-standard-WSL2` since 5.10; the first
 *  4.19 ones had no suffix), WSL1 reports `…-Microsoft`. Pure. Mirrors
 *  `mandu_arbiter::wsl::wsl_version` and scripts/install.sh. */
export function wslVersion(osrelease: string | null): 1 | 2 | null {
  if (!osrelease) return null;
  if (/microsoft-standard|wsl2/i.test(osrelease)) return 2;
  if (/microsoft/i.test(osrelease)) return 1;
  return null;
}

/** Is the running host WSL (either generation)? Any one signal is enough,
 *  as in `mandu_arbiter::wsl::WslSignals::is_wsl`: the kernel release, a set
 *  `$WSL_INTEROP`, or the interop binfmt entry. */
export function hostIsWsl(deps: { readFile: (p: string) => string | null; fileExists: (p: string) => boolean; env: Record<string, string | undefined> }): boolean {
  return wslVersion(deps.readFile(OSRELEASE)) !== null
    || (deps.env[WSL_INTEROP_ENV] ?? "") !== ""
    || deps.fileExists(BINFMT_INTEROP);
}

/** `[major, minor]` of a kernel release string, or null. */
export function kernelVersion(osrelease: string | null): [number, number] | null {
  const m = /^(\d+)\.(\d+)/.exec((osrelease ?? "").trim());
  return m ? [Number(m[1]), Number(m[2])] : null;
}

function atLeast(v: [number, number] | null, major: number, minor: number): boolean {
  return v !== null && (v[0] > major || (v[0] === major && v[1] >= minor));
}

/** The interop binfmt entry's state: its file's first line is `enabled` or
 *  `disabled`; no file = interop not registered. */
export function interopState(binfmt: string | null): "enabled" | "disabled" | "absent" {
  if (binfmt === null) return "absent";
  return binfmt.split("\n")[0]!.trim() === "enabled" ? "enabled" : "disabled";
}

export interface MountEntry {
  mountPoint: string;
  fstype: string;
  source: string;
  superOptions: string;
}

/** mountinfo escapes space, tab, newline and backslash as `\ooo`. */
function unescapeMount(s: string): string {
  return s.replace(/\\([0-7]{3})/g, (_m, o: string) => String.fromCharCode(parseInt(o, 8)));
}

/** Parse `/proc/self/mountinfo` (proc(5)): `id parent maj:min root mountpoint
 *  opts [optional…] - fstype source superopts`. Malformed lines are skipped. */
export function parseMountinfo(text: string): MountEntry[] {
  const out: MountEntry[] = [];
  for (const line of text.split("\n")) {
    const f = line.split(" ");
    const dash = f.indexOf("-");
    if (dash < 6 || f.length < dash + 3) continue;
    out.push({
      mountPoint: unescapeMount(f[4]!),
      fstype: f[dash + 1]!,
      source: unescapeMount(f[dash + 2]!),
      superOptions: f[dash + 3] ?? "",
    });
  }
  return out;
}

/** Is this mount a Windows drive? drvfs is 9p with `aname=drvfs` (or a
 *  `C:\`-style source), `drvfs` itself on older builds, or virtiofs with a
 *  drive-letter source on the newest. */
export function isWindowsDrive(m: MountEntry): boolean {
  const driveSource = /^[A-Za-z]:(\\|$)/.test(m.source);
  if (m.fstype === "drvfs") return true;
  if (m.fstype === "9p") return /(^|[,;])aname=drvfs/.test(m.superOptions) || driveSource;
  if (m.fstype === "virtiofs") return driveSource;
  return false;
}

/** The mount `path` lives on (longest mount-point prefix; the last of equal
 *  ones wins, as the kernel stacks them), when that mount is a Windows drive. */
export function windowsDriveMount(path: string, mounts: MountEntry[]): MountEntry | null {
  let best: MountEntry | null = null;
  for (const m of mounts) {
    const mp = m.mountPoint === "/" ? "/" : m.mountPoint.replace(/\/+$/, "");
    const under = mp === "/" || path === mp || path.startsWith(mp + "/");
    if (under && (best === null || mp.length >= best.mountPoint.replace(/\/+$/, "").length)) best = m;
  }
  return best !== null && isWindowsDrive(best) ? best : null;
}

export interface WslFacts {
  version: 1 | 2;
  /** The kernel release string. */
  kernel: string;
  /** Landlock (5.13) and its TCP rules (6.7): old WSL2 kernels (5.10) lack both. */
  landlock: boolean;
  landlockNet: boolean;
  interop: "enabled" | "disabled" | "absent";
  /** Is systemd PID 1 in this distribution? */
  systemd: boolean;
  /** The Windows drive the working folder is on, or null. */
  workspaceDrive: { path: string; mountPoint: string } | null;
}

export interface WslDeps {
  /** Read a file; null when absent or unreadable. */
  readFile: (path: string) => string | null;
  fileExists: (path: string) => boolean;
  /** The working folder (the project a launch opens). */
  cwd: string;
}

/** Gather the WSL facts, or null off WSL. */
export function gatherWslFacts(deps: WslDeps): WslFacts | null {
  const kernel = (deps.readFile(OSRELEASE) ?? "").trim();
  const version = wslVersion(kernel);
  if (version === null) return null;
  const v = kernelVersion(kernel);
  const drive = windowsDriveMount(deps.cwd, parseMountinfo(deps.readFile(MOUNTINFO) ?? ""));
  return {
    version,
    kernel,
    landlock: version === 2 && atLeast(v, 5, 13),
    landlockNet: version === 2 && atLeast(v, 6, 7),
    interop: interopState(deps.readFile(BINFMT_INTEROP)),
    systemd: deps.fileExists(SYSTEMD_RUNNING),
    workspaceDrive: drive ? { path: deps.cwd, mountPoint: drive.mountPoint } : null,
  };
}

/** The bwrap flags the whole-agent secret-twin wrap adds on WSL: an empty
 *  tmpfs over the interop socket dir, `/dev/null` over the interop client,
 *  and the socket's address dropped from the env. Unlike the AgentShell box it
 *  leaves `/mnt/wslg` alone (a live agent may use its display) and adds
 *  nothing off WSL. A path that does not exist is skipped (bwrap cannot make
 *  a mount point there, and a missing socket is already unreachable).
 *  `paths` is for the e2e, which proves the wrap on stand-in paths. */
export function wslTwinWrapFlags(
  onWsl: boolean,
  exists: (p: string) => boolean,
  paths: { interopDir: string; init: string } = { interopDir: INTEROP_DIR, init: INIT_PATH },
): string[] {
  if (!onWsl) return [];
  const flags: string[] = [];
  if (exists(paths.interopDir)) flags.push("--tmpfs", paths.interopDir);
  if (exists(paths.init)) flags.push("--ro-bind", "/dev/null", paths.init);
  flags.push("--unsetenv", WSL_INTEROP_ENV);
  return flags;
}

/** What a launch says on WSL (empty elsewhere). `guard`: is the connect
 *  guard around this launch (it refuses the interop socket + AF_VSOCK)? */
export function wslLaunchNotes(f: WslFacts | null, opts: { guard: boolean }): string[] {
  if (f === null) return [];
  const notes: string[] = [];
  if (f.version === 1) {
    notes.push(
      "WARNING: mandu: this is WSL1, a syscall translation layer with no Landlock, no seccomp user notification and " +
      "no user namespaces, so nothing Mandu enforces in the kernel works here. Convert the distribution: " +
      "wsl --set-version <distro> 2",
    );
    return notes;
  }
  if (f.interop === "enabled") {
    notes.push(opts.guard
      ? "mandu: WSL2 — Windows interop is on: commands in the box cannot reach it, and the connect guard refuses the " +
        "interop socket and AF_VSOCK for the rest of the agent (a Windows program the agent starts would run outside Mandu)"
      : "WARNING: mandu: WSL2 — Windows interop is on and the connect guard is not running, so a Windows program the " +
        "agent starts outside the command box (cmd.exe, powershell.exe, any .exe) runs outside Mandu: it can read your " +
        "real files and reach any host. Turn interop off in /etc/wsl.conf ([interop] enabled=false), or build the guard " +
        "(scripts/build-native.sh).");
  }
  if (!f.landlock) {
    notes.push(`WARNING: mandu: WSL2 kernel ${f.kernel} predates Landlock (5.13), so the command box has no file-access ` +
      "layer below its mounts. Update the WSL kernel: wsl --update");
  }
  if (f.workspaceDrive) {
    notes.push(
      `WARNING: mandu: ${f.workspaceDrive.path} is on a Windows drive (${f.workspaceDrive.mountPoint}): file access is ` +
      "slow there, and an edit you make from Windows is only picked up at the AI's next tool call. Move the project " +
      "into the Linux file system (for example ~/src) for the full speed and the live edit clock.",
    );
  }
  return notes;
}

/** Entries of `<drive>/Users` that are not a person's profile (compared
 *  case-insensitively; drvfs directories created by Windows fold case). */
const NOT_A_PROFILE = new Set(["public", "default", "default user", "all users", "desktop.ini", "defaultapppool"]);

/** One directory entry, as `readdir(…, { withFileTypes: true })` reports it
 *  (a junction such as `All Users` is a symlink, not a directory). */
export interface DirEntry { name: string; dir: boolean }

/** The Windows user profiles reachable from this distribution: `<mount>/Users/<name>`
 *  for every Windows drive in `mounts` (the automount root is configurable,
 *  so drives come from the mount table, never a hard-coded `/mnt/c`). Skips
 *  the shared and template profiles and anything that is not a plain
 *  directory. `listDir` answers null for a missing or unreadable directory.
 *  Pure: the host reads are the arguments. */
export function windowsProfiles(mounts: MountEntry[], listDir: (path: string) => DirEntry[] | null): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const m of mounts) {
    if (!isWindowsDrive(m)) continue;
    const mp = m.mountPoint.replace(/\/+$/, "") || "/";
    if (seen.has(mp)) continue;
    seen.add(mp);
    const users = `${mp === "/" ? "" : mp}/Users`;
    for (const e of listDir(users) ?? []) {
      if (!e.dir || e.name.startsWith(".") || NOT_A_PROFILE.has(e.name.toLowerCase())) continue;
      out.push(`${users}/${e.name}`);
    }
  }
  return out.sort();
}

/** The paths discovery probes under ONE Windows profile, relative to it:
 *  the secret catalog's home-anchored stores (arbiter/policy/secret-catalog.ts
 *  `SECRET_PREFIXES` minus the agent-auth ones discovery never twins; the
 *  parity test in tests/stack keeps the two lists equal). A list, not a
 *  walk: a profile sits on drvfs (9p, a round trip per stat) and its
 *  `AppData` alone runs to tens of thousands of entries. The catalog's
 *  basename shapes (`*credentials*`, `.env`) are therefore NOT searched for
 *  anywhere else in a profile (a project under `C:\Users\<name>\src` keeps
 *  its `.env` raw: move the project into the Linux file system). */
export const WINDOWS_PROFILE_SECRET_PATHS: readonly string[] = [
  // Spelled as on Linux (fs-outbound SENSITIVE_PATHS, then the catalog's own).
  ".ssh", ".gnupg", ".aws", ".kube", ".docker/config.json", ".netrc", ".git-credentials",
  ".config/gh", ".config/gcloud", ".config/goose/secrets.yaml",
  ".local/share/keyrings", ".password-store",
  ".pgpass", ".my.cnf", ".boto", ".s3cfg", ".databrickscfg", ".snowflake", ".config/rclone",
  ".npmrc", ".yarnrc.yml", ".pypirc", ".config/pip", ".pip",
  ".config/composer/auth.json", ".composer/auth.json",
  ".m2/settings.xml", ".m2/settings-security.xml", ".gradle/gradle.properties",
  ".nuget/NuGet/NuGet.Config", ".terraformrc",
  ".azure", ".oci", ".aliyun", ".config/doctl", ".config/hcloud",
  ".config/openstack", ".config/containers/auth.json", ".config/helm/registry",
  ".vault-token", ".config/sops",
  ".config/glab-cli", ".config/hub",
  ".local/share/com.vercel.cli", ".config/netlify", ".config/.wrangler", ".wrangler",
  ".fly", ".supabase", ".config/stripe", ".config/configstore", ".config/ngrok",
  ".ngrok2", ".circleci/cli.yml", ".sentryclirc", ".kaggle", ".huggingface",
  ".cache/huggingface/token", ".cache/huggingface/stored_tokens",
  ".config/github-copilot", ".config/op", ".op",
  // Where Windows builds of the same tools keep them.
  "_netrc",
  "AppData/Roaming/gcloud", "AppData/Roaming/GitHub CLI", "AppData/Roaming/rclone",
  "AppData/Roaming/pip", "AppData/Roaming/Composer/auth.json", "AppData/Roaming/NuGet/NuGet.Config",
  "AppData/Roaming/terraform.rc", "AppData/Roaming/doctl", "AppData/Roaming/postgresql/pgpass.conf",
  "AppData/Roaming/helm/registry", "AppData/Roaming/sops", "AppData/Roaming/com.vercel.cli",
];

/** The discovery roots for one profile (absolute), in list order. */
export function windowsProfileSecretRoots(profile: string): string[] {
  const base = profile.replace(/\/+$/, "");
  return WINDOWS_PROFILE_SECRET_PATHS.map((rel) => `${base}/${rel}`);
}
