/**
 * codex-sandbox — can Codex's OWN command sandbox run on this host
 * (os-test-matrix.md §10.14.1, open item 4; packaging.md §7)?
 *
 * WHY (found by the fresh-agents VM suite, 2026-09-27, codex-cli 0.154):
 * Codex runs every shell command in its own bubblewrap sandbox. It uses the
 * `bwrap` on PATH and, when there is none, a copy it bundles
 * (`codex-resources/bwrap`; re-read 2026-10-09 for 0.160 to 0.162: the first
 * `bwrap` on PATH outside the current directory whose `--help` lists
 * `--as-pid-1` and `--perms`, else its own static 0.11.2, hash-checked;
 * rootless-confinement-ubuntu-2404.md §0.7). A stock Ubuntu 24.04 or 26.04 cloud image ships
 * no bubblewrap, and its AppArmor restriction on unprivileged user namespaces
 * (`kernel.apparmor_restrict_unprivileged_userns=1`) grants `userns` per
 * binary, never to the bundled copy: every command dies with
 * `bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted`. That
 * happens with or without Mandu, and Codex answers the user with the error.
 * The fix is `sudo apt install bubblewrap`: on 26.04 the package brings its
 * own AppArmor grant (`bwrap-userns-restrict`); on 24.04 `mandu setup` adds
 * Mandu's own bubblewrap (bwrap-grant.ts), which a launch puts first on
 * Codex's PATH, so Codex's sandbox runs UNDER MANDU. Outside Mandu a 24.04
 * Codex still needs Ubuntu's own profile (the apparmor-profiles extra).
 *
 * The decision is pure (`assessCodexSandbox`, unit-tested); the one probe is
 * Codex's own (`CODEX_BWRAP_PROBE_ARGV`, read out of the 0.154 binary), run
 * against the system bwrap only. The bundled copy is judged from the kernel
 * knobs, since it has no AppArmor grant on any host that restricts userns.
 * `mandu doctor` prints a row, and a `mandu codex` launch prints one WARNING
 * line; neither refuses (the agent still runs, only its shell tool fails).
 *
 * macOS (re-measured 2026-10-01 on macOS 26.5.1; decided 2026-10-02). A launch
 * that protects secrets runs the whole agent inside Mandu's Seatbelt profile
 * (posture `read-blocked`). Codex starts there and its model turns go through
 * Mandu's proxy, but Codex runs each command in its OWN Seatbelt sandbox,
 * which macOS refuses inside Mandu's (`sandbox_apply: Operation not
 * permitted`): with it on, every command Codex runs fails. So when Mandu's
 * profile really wraps the launch, Mandu turns Codex's sandbox off for the
 * session (`seatbelt-mandu-off`): it adds CODEX_SANDBOX_OFF_ARGS (`-c
 * sandbox_mode="danger-full-access"`) to its own overrides, which
 * codex-argv.ts splices at EVERY command level (a root-only `-c` is dropped
 * as soon as any level has its own), and prints ONE line saying so and what
 * that gives up (Codex's limits on where its commands write and connect;
 * Mandu's profile still keeps the credential files from them). It does not
 * override, and keeps the WARNING (`seatbelt-nests`), when:
 *   - the run asks for the sandbox itself (`-s`/`--sandbox`, `-c
 *     sandbox_mode`/`default_permissions`, `--approve-for-me`,
 *     `--enable network_proxy`, a `-p` profile that sets the mode or its
 *     permissions): codexArgvSandboxChoice;
 *   - an administrator requires it (`/etc/codex/requirements.toml`, the legacy
 *     `/etc/codex/managed_config.toml`, forced MDM preferences in
 *     `com.openai.codex`, the cloud requirements cache): Codex would fall
 *     back to read-only, and `exec` would refuse to start;
 *   - the user's Codex config relies on it for something Mandu does not do
 *     (a permission profile of the user's own, where every filesystem
 *     restriction beyond the built-ins lives; the network proxy feature,
 *     which wraps commands in Seatbelt even with full access, unless the run
 *     turns it off): codexConfigKeeps, codexNetworkProxySetting, over every
 *     layer Codex may apply (codexConfigLayers: /etc/codex/config.toml,
 *     $CODEX_HOME/config.toml, the `-p` profile, every ancestor's and the
 *     run's `-C` directory's `.codex/config.toml`), any layer counting.
 * `--remote` gets its own WARNING and nothing injected: the session's
 * commands run on that app server, outside Mandu's profile, whatever else
 * the run asks for (CODEX_REMOTE_NOTE). A bare `codex app-server` gets the
 * OFF line with the caveat that a client choosing a sandbox per thread
 * overrides the default (CODEX_APP_SERVER_OFF_NOTE).
 * The run turning it off itself (`--yolo`, `-s danger-full-access`, a `-c`
 * at the level Codex reads): `seatbelt-sandbox-off`, a ✓ doctor row and no
 * launch line. A config or `-p` profile that turns it off gets the line:
 * which layer Codex applies is not Mandu's to guess. Every Mandu `-c` also keeps an interactive
 * Codex off its shared app-server daemon (any `-c` but a feature toggle
 * does, 0.159.3), so a daemon started outside Mandu never runs its
 * commands. Linux is unchanged: there Codex's bubblewrap nests in Mandu's.
 *
 * Mandu-new (no reference origin).
 */
import { spawnSync } from "node:child_process";
import { sandboxExecAvailable } from "./seatbelt-profile.js";
import { existsSync, readFileSync } from "node:fs";
import { homedir, userInfo } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { APPARMOR_USERNS_SYSCTL, MAX_USER_NAMESPACES_SYSCTL, USERNS_CLONE_SYSCTL } from "./userns.js";
import { commandAvailable, manduBwrapInForceHere, resolveWrapBwrap } from "./bwrap-grant.js";
import { codexArgvCd, codexArgvLevels, codexBareAppServer, codexSubcommand, codexTalksToModel } from "./codex-argv.js";
import { cachedProbe } from "./probe-cache.js";

/** The probe Codex itself runs before it trusts a bwrap (0.154 binary). */
export const CODEX_BWRAP_PROBE_ARGV = ["--unshare-user", "--unshare-net", "--ro-bind", "/", "/", "/bin/true"];

export interface CodexSandboxFacts {
  platform: "linux" | "darwin" | "win32";
  /** `codex` is on PATH. */
  codex: boolean;
  /** A `bwrap` is on PATH (the one Codex prefers), or Mandu's own is in force
   *  (a launch puts it first on Codex's PATH). */
  systemBwrap: boolean;
  /** Codex's probe through that bwrap exited 0; null when not run. */
  systemBwrapOk: boolean | null;
  /** The kernel knobs, trimmed; null when the file is absent. */
  apparmorRestrict: string | null;
  usernsClone: string | null;
  maxUserNamespaces: string | null;
  /** macOS: a launch wraps the agent in Mandu's Seatbelt profile
   *  (`sandbox-exec` is present, so secrets are `read-blocked`). Optional:
   *  absent = no outer profile. */
  outerSeatbelt?: boolean;
  /** Codex's own command sandbox is off by the run itself (its argv says
   *  `danger-full-access` or bypasses it). Optional: absent = on, Codex's
   *  default. */
  codexSandboxOff?: boolean;
  /** macOS: the option of this run that asks for Codex's own sandbox
   *  (codexArgvSandboxChoice), or null. Optional: absent = none. */
  explicitOn?: string | null;
  /** macOS: the administrator source that requires Codex's own sandbox
   *  (codexAdminSandboxLock), or null. Optional: absent = none. */
  adminLock?: string | null;
  /** macOS: what in the user's Codex config would be lost if Mandu turned
   *  the sandbox off (codexConfigKeeps: a filesystem deny entry), or null.
   *  Optional: absent = nothing. */
  configKeeps?: string | null;
  /** macOS: Codex's network proxy is on (config.toml, the run's profile or
   *  argv), which wraps every command in Seatbelt even with full access, so
   *  its commands fail inside Mandu's profile whatever the sandbox mode.
   *  Optional: absent = off. */
  networkProxy?: string | null;
  /** macOS: does the profile around the launch block the credential files
   *  (posture `read-blocked`)? It does not in mode `off`, where only its TCP
   *  rules apply. Optional: absent = it does. */
  credsBlocked?: boolean;
}

export type CodexSandboxState =
  | "not-applicable" // not Linux or macOS, or no codex, or nothing to warn about on macOS
  | "ok"
  | "no-bwrap" //       no system bwrap, and the bundled copy cannot run here
  | "bwrap-denied" //   a system bwrap that AppArmor gives no user namespace
  | "userns-off" //     the kernel refuses unprivileged user namespaces
  | "probe-failed" //   the probe failed for another reason
  | "seatbelt-nests" //  macOS: Codex's own sandbox stays on (asked for, required or relied on), and cannot start inside Mandu's profile
  | "seatbelt-mandu-off" // macOS: Mandu turns Codex's own sandbox off for the session
  | "seatbelt-sandbox-off"; // macOS: Codex's own sandbox is off already; Mandu's profile confines its commands

export interface CodexSandboxAssessment {
  state: CodexSandboxState;
  /** The exact fix for this host, or null. */
  fix: string | null;
  /** `seatbelt-nests`: why the sandbox stays on, in the product's words. */
  why?: string;
  /** `seatbelt-mandu-off` in a mode whose profile blocks no credential file. */
  noCreds?: boolean;
}

export const APT_BUBBLEWRAP = "sudo apt install bubblewrap";

/** macOS: the override Mandu adds to its own Codex overrides (spliced at
 *  every command level, codex-argv.ts) to turn Codex's sandbox off. */
export const CODEX_SANDBOX_OFF_ARGS: readonly string[] = ["-c", 'sandbox_mode="danger-full-access"'];
/** …and the run's own "network proxy off", carried to every level. */
export const CODEX_PROXY_OFF_ARGS: readonly string[] = ["-c", "features.network_proxy=false"];

/** macOS: the ONE launch line when Mandu turns Codex's sandbox off. Matches
 *  launch-banner.ts's attention pattern ("own sandbox is OFF for this
 *  session"), so the compact display shows it. */
export const CODEX_SANDBOX_OFF_NOTE =
  "mandu: Codex's own sandbox is OFF for this session: macOS cannot start it inside Mandu's profile. " +
  "Mandu's profile still keeps your credential files from the commands Codex runs, but Codex's own limits on " +
  "where they write and connect do not apply (pass --sandbox <mode> to keep it; its commands then fail).";
/** …in a mode whose profile blocks no credential file (mode `off`). */
export const CODEX_SANDBOX_OFF_NOTE_NO_CREDS =
  "mandu: Codex's own sandbox is OFF for this session: macOS cannot start it inside Mandu's profile. " +
  "In this mode Mandu's profile does not block your credential files either, and Codex's own limits on " +
  "where its commands write and connect do not apply (pass --sandbox <mode> to keep it; its commands then fail).";

/** macOS, a bare `codex app-server`: the injected value is only the
 *  server's default, and a client that picks a sandbox per thread overrides
 *  it (that thread's commands then fail). No `--sandbox` hint: app-server
 *  takes none. */
export const CODEX_APP_SERVER_OFF_NOTE =
  "mandu: Codex's own sandbox is OFF for this session: macOS cannot start it inside Mandu's profile, so Mandu sets this " +
  "app server's default to danger-full-access. A client that picks a sandbox for a thread overrides that default, and " +
  "that thread's commands then fail inside Mandu's profile. Mandu's profile still keeps your credential files from the " +
  "commands Codex runs, but Codex's own limits on where they write and connect do not apply.";
/** …in a mode whose profile blocks no credential file (mode `off`). */
export const CODEX_APP_SERVER_OFF_NOTE_NO_CREDS =
  "mandu: Codex's own sandbox is OFF for this session: macOS cannot start it inside Mandu's profile, so Mandu sets this " +
  "app server's default to danger-full-access. A client that picks a sandbox for a thread overrides that default, and " +
  "that thread's commands then fail inside Mandu's profile. In this mode Mandu's profile does not block your credential " +
  "files either, and Codex's own limits on where its commands write and connect do not apply.";

/** macOS, `--remote`: the session's commands run on that app server. */
export const CODEX_REMOTE_NOTE =
  "mandu: WARNING — with --remote, Codex runs this session's commands on that app server, outside Mandu's " +
  "profile: Mandu does not change that server's own sandbox, and its profile does not cover those commands.";

/** macOS, the run asks for the sandbox: what keeps it, and the fix. */
export const CODEX_DARWIN_FIX =
  "drop that option and Mandu turns Codex's own sandbox off for the session, or use `mandu claude` on macOS";
/** macOS, an administrator requires the sandbox. */
export const CODEX_DARWIN_ADMIN_FIX =
  "ask your administrator to allow danger-full-access for sessions under mandu, or use `mandu claude` on macOS";
/** macOS, the user's config relies on the sandbox. */
export const CODEX_DARWIN_CONFIG_FIX =
  "protect those files with Mandu instead (mode secrets, a label in policy.yaml) and turn that setting off for " +
  "sessions under mandu; then Mandu turns Codex's own sandbox off for the session";
/** macOS, the network proxy feature keeps a Seatbelt wrap. */
export const CODEX_DARWIN_PROXY_FIX =
  "pass --disable network_proxy (or turn features.network_proxy off in your Codex config); then Mandu turns " +
  "Codex's own sandbox off for the session";

function usernsKnobShut(f: CodexSandboxFacts): string | null {
  if (f.usernsClone === "0") return "sudo sysctl -w kernel.unprivileged_userns_clone=1 (persist it under /etc/sysctl.d/)";
  if (f.maxUserNamespaces === "0") return "sudo sysctl -w user.max_user_namespaces=<n> (persist it under /etc/sysctl.d/)";
  return null;
}

/** Can Codex's command sandbox run here, and if not, the fix. Pure. */
export function assessCodexSandbox(f: CodexSandboxFacts): CodexSandboxAssessment {
  if (f.platform === "darwin") {
    // Only a profile around the launch matters: inside one, Codex's own
    // Seatbelt sandbox cannot start (no nesting), so its commands fail
    // unless that sandbox is off.
    if (!f.codex || f.outerSeatbelt !== true) return { state: "not-applicable", fix: null };
    // An administrator's requirement wins over everything a run or a config
    // asks for (Codex itself falls back to read-only).
    if (f.adminLock) {
      return { state: "seatbelt-nests", fix: CODEX_DARWIN_ADMIN_FIX, why: `your organization's Codex settings require its own sandbox (${f.adminLock})` };
    }
    // The network proxy wraps commands in Seatbelt whatever the mode, so
    // neither the run's nor Mandu's "off" helps.
    if (f.networkProxy) {
      return { state: "seatbelt-nests", fix: CODEX_DARWIN_PROXY_FIX, why: `Codex's network proxy is on (${f.networkProxy}), which runs every command in its own sandbox` };
    }
    if (f.codexSandboxOff === true) return { state: "seatbelt-sandbox-off", fix: null };
    if (f.explicitOn) return { state: "seatbelt-nests", fix: CODEX_DARWIN_FIX, why: `this run asks for Codex's own sandbox (${f.explicitOn})` };
    if (f.configKeeps) return { state: "seatbelt-nests", fix: CODEX_DARWIN_CONFIG_FIX, why: `your Codex config relies on its own sandbox (${f.configKeeps})` };
    return { state: "seatbelt-mandu-off", fix: null, ...(f.credsBlocked === false ? { noCreds: true } : {}) };
  }
  if (f.platform !== "linux" || !f.codex) return { state: "not-applicable", fix: null };
  const knob = usernsKnobShut(f);
  if (knob !== null) return { state: "userns-off", fix: knob };
  const restricted = f.apparmorRestrict === "1";
  if (!f.systemBwrap) {
    // The bundled copy runs only where any program may create a user
    // namespace; with the AppArmor restriction on, nothing grants it one.
    return restricted
      ? { state: "no-bwrap", fix: `${APT_BUBBLEWRAP}, then mandu setup (it asks for sudo only if this host needs the grant)` }
      : { state: "ok", fix: null };
  }
  if (f.systemBwrapOk !== false) return { state: "ok", fix: null };
  return restricted
    ? { state: "bwrap-denied", fix: "mandu setup (it installs Mandu's own bubblewrap, which Codex uses under mandu; asks for sudo once)" }
    : { state: "probe-failed", fix: null };
}

/** Why, in the product's plain words (doctor row and launch line share it). */
function cause(a: CodexSandboxAssessment): string {
  const s = a.state;
  switch (s) {
    case "no-bwrap":
      return "bubblewrap is not installed, and the copy Codex bundles cannot run under this host's AppArmor rules";
    case "bwrap-denied":
      return "AppArmor does not let bubblewrap create the namespace Codex needs";
    case "userns-off":
      return "this kernel refuses unprivileged user namespaces, which Codex's sandbox needs";
    case "probe-failed":
      return "bubblewrap could not create the namespace Codex needs (a container or seccomp policy may deny it)";
    case "seatbelt-nests":
      return `${a.why ?? "Codex's own sandbox is on"}, and macOS cannot start it inside Mandu's profile ` +
        "(sandbox_apply: Operation not permitted), so every command Codex runs fails";
    default:
      return "";
  }
}

/** The `mandu doctor` row under "What Mandu needs", or null when Codex is
 *  absent (its "not installed" row already says so). */
export function codexSandboxRow(a: CodexSandboxAssessment): string | null {
  if (a.state === "not-applicable") return null;
  if (a.state === "ok") return "  ✓ Codex can run commands in its own sandbox (bubblewrap)";
  // The doctor knows the host, not the mode a launch will run in: the
  // credential-file clause is said for mode secrets, where it holds.
  if (a.state === "seatbelt-sandbox-off") {
    return "  ✓ Codex runs commands under mandu on macOS: its own sandbox is off" +
      (a.noCreds ? "" : ", and in mode secrets Mandu's profile keeps them from your credential files");
  }
  if (a.state === "seatbelt-mandu-off") {
    return "  ✓ Codex runs commands under mandu on macOS: Mandu turns its own sandbox off for each session (macOS cannot " +
      "start it inside Mandu's profile)" + (a.noCreds ? "; Codex's own limits on where they write and connect do not apply"
        : ", and in mode secrets Mandu's profile keeps those commands from your credential files");
  }
  const fix = a.fix === null ? "" : `; fix: ${a.fix}`;
  if (a.state === "seatbelt-nests") return `  ✗ Codex cannot run commands under mandu on macOS: ${cause(a)}${fix}`;
  return `  ✗ Codex cannot run any command here, with or without Mandu: ${cause(a)}${fix}`;
}

/** The ONE launch line for a failing host, or null. Carries `WARNING` so the
 *  compact display shows it (launch-banner.ts). */
export function codexSandboxLaunchNote(a: CodexSandboxAssessment): string | null {
  if (a.state === "seatbelt-mandu-off") return a.noCreds ? CODEX_SANDBOX_OFF_NOTE_NO_CREDS : CODEX_SANDBOX_OFF_NOTE;
  if (a.state === "not-applicable" || a.state === "ok" || a.state === "seatbelt-sandbox-off") return null;
  const fix = a.fix === null ? "run `mandu doctor` for details" : `fix: ${a.fix}`;
  if (a.state === "seatbelt-nests") {
    return `mandu: WARNING — Codex cannot run commands inside Mandu on macOS (${cause(a)}); ${fix}`;
  }
  return `mandu: WARNING — Codex's own sandbox cannot run commands on this machine (${cause(a)}); ${fix}`;
}

/** What a codex argv says about Codex's own sandbox (codex-cli 0.159.3,
 *  measured 2026-10-02):
 *    - `remote`: `--remote`. The session's commands run on that app server,
 *      which applies the run's sandbox options in its own process, outside
 *      Mandu's profile, so this wins over everything below;
 *    - `on`: the network proxy turned on by the run (it keeps a Seatbelt wrap
 *      whatever the mode, so it wins even over the bypass flag), any mode
 *      but `danger-full-access`, `-c default_permissions`,
 *      `--approve-for-me` / `--not-so-yolo` (workspace-write), or a `-p`
 *      profile whose `default_permissions` or `sandbox_mode` asks for one;
 *    - `off`: the bypass flag (`--yolo`), the mode `danger-full-access`, or
 *      `default_permissions` `:danger-full-access`;
 *    - `none`.
 *  Precedence as Codex applies it (0.159.3, measured with `codex debug
 *  prompt-input`): `--remote`, the run's network proxy, the bypass flag, a
 *  typed `-s` / `--sandbox` (it beats any `-c`), then at the innermost
 *  command level with a sandbox `-c`: `-c default_permissions` (in any
 *  order), `--approve-for-me`, `-c sandbox_mode`; then a `-p` profile file
 *  (`readProfile(name)`: its text, or null), where `default_permissions`
 *  outranks `sandbox_mode`. `netProxy: "off"` marks a
 *  run that turns the network proxy off (codexArgvNetworkProxy), which
 *  cancels a config or profile that turns it on. `by` names the option,
 *  for the launch line. Every command level is scanned; nothing after `--`.
 *  Pure over `readProfile`. */
export type CodexSandboxChoice = ({ kind: "none" } | { kind: "off"; by: string } | { kind: "on"; by: string } | { kind: "remote"; by: string }) & {
  /** The run turns the network proxy off (cancels a config or profile
   *  that turns it on). */
  netProxy?: "off";
};

/** One `-c` key/value: the key (dotted, unquoted) and the value (unquoted). */
function codexConfigKv(kv: string): { key: string; val: string } | null {
  const unquote = (v: string): string => v.trim().replace(/^["']|["']$/g, "");
  const m = /^\s*([A-Za-z0-9_.\-"']+)\s*=\s*(.*)$/.exec(kv);
  return m ? { key: unquote(m[1]!), val: unquote(m[2]!) } : null;
}

/** The run's own setting of Codex's network proxy feature, or null when it
 *  sets none. Codex appends `--enable` / `--disable` after the `-c`
 *  overrides, disables last, so a `--disable network_proxy` wins over any
 *  `--enable` and any `-c`, an `--enable` over any `-c`, and among the `-c`
 *  forms (`features.network_proxy=true|false`, `.enabled=…`, the inline
 *  `{ enabled = … }`) the last one wins. Pure. */
export function codexArgvNetworkProxy(argv: readonly string[]): { state: "on" | "off"; by: string } | null {
  let enable = false;
  let disable = false;
  let config: { state: "on" | "off"; by: string } | null = null;
  const fromKv = (kv: string, form: string): void => {
    const c = codexConfigKv(kv);
    if (c === null) return;
    if (c.key === "features.network_proxy" || c.key === "features.network_proxy.enabled") {
      if (/^true$/i.test(c.val)) config = { state: "on", by: `${form} ${c.key}=true` };
      else if (/^false$/i.test(c.val)) config = { state: "off", by: `${form} ${c.key}=false` };
      else if (c.key === "features.network_proxy" && /\benabled\s*=\s*true\b/.test(c.val)) config = { state: "on", by: `${form} features.network_proxy` };
      else if (c.key === "features.network_proxy" && /\benabled\s*=\s*false\b/.test(c.val)) config = { state: "off", by: `${form} features.network_proxy` };
    }
  };
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === "--") break;
    if ((a === "--enable" || a === "--disable") && i + 1 < argv.length) {
      if (argv[++i] === "network_proxy") { if (a === "--enable") enable = true; else disable = true; }
      continue;
    }
    if (a.startsWith("--enable=")) { if (a.slice("--enable=".length) === "network_proxy") enable = true; continue; }
    if (a.startsWith("--disable=")) { if (a.slice("--disable=".length) === "network_proxy") disable = true; continue; }
    if ((a === "-c" || a === "--config") && i + 1 < argv.length) { fromKv(argv[++i]!, a); continue; }
    if (a.startsWith("--config=")) { fromKv(a.slice("--config=".length), "--config"); continue; }
    if (a.startsWith("-c") && !a.startsWith("--") && a.length > 2) { fromKv(a.slice(2).replace(/^=/, ""), "-c"); continue; }
    // A value-taking option's value is never read as a flag.
    if ((a === "-s" || a === "--sandbox" || a === "-p" || a === "--profile" || a === "--remote") && i + 1 < argv.length) i++;
  }
  if (disable) return { state: "off", by: "--disable network_proxy" };
  if (enable) return { state: "on", by: "--enable network_proxy" };
  return config;
}

export function codexArgvSandboxChoice(
  argv: readonly string[],
  readProfile: (name: string) => string | null = () => null,
): CodexSandboxChoice {
  const FULL = "danger-full-access";
  const unquote = (v: string): string => v.trim().replace(/^["']|["']$/g, "");
  let bypass: string | null = null;
  let typed: { mode: string; by: string } | null = null;
  let approve: string | null = null;
  let remote = false;
  // Per command level: the last `-c default_permissions` and `-c
  // sandbox_mode` (within one level, default_permissions wins in any order).
  const perms = new Map<number, { mode: string; by: string }>();
  const modes = new Map<number, { mode: string; by: string }>();
  let profile: string | null = null;
  const levels = codexArgvLevels(argv);
  let at = 0;
  const configKv = (kv: string, form: string): void => {
    const c = codexConfigKv(kv);
    if (c === null) return;
    if (c.key === "sandbox_mode") modes.set(at, { mode: c.val, by: `${form} sandbox_mode=${c.val}` });
    else if (c.key === "default_permissions") perms.set(at, { mode: c.val === `:${FULL}` ? FULL : "permissions", by: `${form} default_permissions` });
  };
  for (let i = 1; i < argv.length; i++) {
    if ((levels[i] ?? -1) >= 0) at = levels[i]!;
    const a = argv[i]!;
    if (a === "--") break;
    if (a === "--dangerously-bypass-approvals-and-sandbox" || a === "--yolo") { bypass = a; continue; }
    if ((a === "--sandbox" || a === "-s") && i + 1 < argv.length) { const m = unquote(argv[++i]!); typed = { mode: m, by: `${a} ${m}` }; continue; }
    if (a.startsWith("--sandbox=")) { const m = unquote(a.slice("--sandbox=".length)); typed = { mode: m, by: `--sandbox ${m}` }; continue; }
    // An attached short value: `-sX`, `-s=X` (clap strips one `=`).
    if (a.startsWith("-s") && !a.startsWith("--") && a.length > 2) { const m = unquote(a.slice(2).replace(/^=/, "")); typed = { mode: m, by: `-s ${m}` }; continue; }
    if (a === "--approve-for-me" || a === "--not-so-yolo") { approve = a; continue; }
    if (a === "--remote") { remote = true; i++; continue; }
    if (a.startsWith("--remote=")) { remote = true; continue; }
    if ((a === "--enable" || a === "--disable") && i + 1 < argv.length) { i++; continue; }
    if ((a === "-c" || a === "--config") && i + 1 < argv.length) { configKv(argv[++i]!, a); continue; }
    if (a.startsWith("--config=")) { configKv(a.slice("--config=".length), "--config"); continue; }
    if (a.startsWith("-c") && !a.startsWith("--") && a.length > 2) { configKv(a.slice(2).replace(/^=/, ""), "-c"); continue; }
    if ((a === "-p" || a === "--profile") && i + 1 < argv.length) { profile = argv[++i]!; continue; }
    if (a.startsWith("-p") && !a.startsWith("--") && a.length > 2) { profile = a.slice(2).replace(/^=/, ""); continue; }
    if (a.startsWith("--profile=")) { profile = a.slice("--profile=".length); continue; }
  }
  // `--remote` first: whatever else the run asks for is applied on that
  // server, outside Mandu's profile.
  if (remote) return { kind: "remote", by: "--remote" };
  const net = codexArgvNetworkProxy(argv);
  const tag = net?.state === "off" ? { netProxy: "off" as const } : {};
  // The network proxy keeps a Seatbelt wrap whatever the mode (even with
  // the bypass flag), so a run that turns it on asks for a sandbox first.
  if (net?.state === "on") return { kind: "on", by: net.by, ...tag };
  if (bypass !== null) return { kind: "off", by: bypass, ...tag };
  if (typed !== null) return typed.mode === FULL ? { kind: "off", by: typed.by, ...tag } : { kind: "on", by: typed.by, ...tag };
  // Codex reads only the innermost command level's `-c` list (Mandu's splice
  // gives every level one). There `default_permissions` outranks
  // `--approve-for-me`, which outranks `sandbox_mode`. A sandbox `-c` at an
  // outer level is dropped by Codex: one that asks for a sandbox still
  // counts as the run asking (warn, never override), one that turns it off
  // does not.
  const inner = Math.max(0, ...levels);
  const dp = perms.get(inner) ?? null;
  const sm = modes.get(inner) ?? null;
  if (dp !== null) return dp.mode === FULL ? { kind: "off", by: dp.by, ...tag } : { kind: "on", by: dp.by, ...tag };
  if (approve !== null) return { kind: "on", by: approve, ...tag };
  if (sm !== null) return sm.mode === FULL ? { kind: "off", by: sm.by, ...tag } : { kind: "on", by: sm.by, ...tag };
  for (const m of [perms, modes]) for (const [lv, c] of m) if (lv !== inner && c.mode !== FULL) return { kind: "on", by: c.by, ...tag };
  if (profile !== null) {
    const text = readProfile(profile);
    if (text !== null) {
      // Within one file, default_permissions outranks sandbox_mode. A
      // profile that turns it off is not the run's own "off": Codex's project
      // layers sit above it, so Mandu still checks what they rely on.
      const perms = codexConfigDefaultPermissions(text);
      if (perms !== null && perms !== `:${FULL}`) return { kind: "on", by: `--profile ${profile} (default_permissions)`, ...tag };
      const mode = perms !== null ? FULL : codexConfigSandboxMode(text);
      if (mode !== null && mode !== FULL) return { kind: "on", by: `--profile ${profile} (sandbox_mode ${mode})`, ...tag };
    }
  }
  return { kind: "none", ...tag };
}

/** The `-p` / `--profile` a codex argv selects (the last one), or null. */
export function codexArgvProfile(argv: readonly string[]): string | null {
  let profile: string | null = null;
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === "--") break;
    if ((a === "-p" || a === "--profile") && i + 1 < argv.length) { profile = argv[++i]!; continue; }
    if (a.startsWith("--profile=")) { profile = a.slice("--profile=".length); continue; }
    if (a.startsWith("-p") && !a.startsWith("--") && a.length > 2) profile = a.slice(2).replace(/^=/, "");
  }
  return profile;
}

/** Does this codex argv turn Codex's own command sandbox off? Pure. */
export function codexArgvSandboxOff(argv: readonly string[]): boolean {
  return codexArgvSandboxChoice(argv).kind === "off";
}

function stripTomlComments(text: string): string {
  return text.split("\n").map((l) => l.replace(/#.*$/, "")).join("\n");
}

/** The top-level `sandbox_mode` of a Codex TOML file, or null. */
export function codexConfigSandboxMode(text: string): string | null {
  for (const raw of text.split("\n")) {
    const line = raw.replace(/#.*$/, "").trim();
    if (line.startsWith("[")) return null; // the top-level table ended
    const m = /^sandbox_mode\s*=\s*["']([^"']*)["']$/.exec(line);
    if (m) return m[1]!;
  }
  return null;
}

/** The top-level `default_permissions` of a Codex TOML file, or null. */
export function codexConfigDefaultPermissions(text: string): string | null {
  for (const raw of text.split("\n")) {
    const line = raw.replace(/#.*$/, "").trim();
    if (line.startsWith("[")) return null;
    const m = /^["']?default_permissions["']?\s*=\s*["']([^"']*)["']$/.exec(line);
    if (m) return m[1]!;
  }
  return null;
}

/** Does a Codex TOML text set the network proxy feature, and to what? True
 *  when any spelling turns it on (codexNetworkProxyOn, fail-safe), false
 *  when one turns it off and none on, null when it says nothing. Pure. */
export function codexNetworkProxySetting(text: string): boolean | null {
  if (codexNetworkProxyOn(text)) return true;
  const t = stripTomlComments(text);
  if (/\bnetwork_proxy\s*=\s*false\b/.test(t) || /\bnetwork_proxy\.enabled\s*=\s*false\b/.test(t)) return false;
  if (/\bnetwork_proxy\s*=\s*\{[^}]*\benabled\s*=\s*false\b[^}]*\}/.test(t)) return false;
  const lines = t.split("\n");
  for (let i = 0; i < lines.length; i++) {
    if (!/^\s*\[[^\]]*\bnetwork_proxy\s*\]\s*$/.test(lines[i]!)) continue;
    for (let j = i + 1; j < lines.length && !/^\s*\[/.test(lines[j]!); j++) if (/^\s*enabled\s*=\s*false\b/.test(lines[j]!)) return false;
  }
  return null;
}

/** What in an administrator's Codex requirements (requirements.toml schema:
 *  `/etc/codex/requirements.toml`, MDM `requirements_toml_base64`, the cloud
 *  cache) keeps Codex's own sandbox on, or null. Conservative: anything that
 *  restricts permissions counts. Pure. */
export function codexRequirementsLock(text: string): string | null {
  const t = stripTomlComments(text);
  const modes = /allowed_sandbox_modes\s*=\s*\[([\s\S]*?)\]/.exec(t);
  if (modes && !/["']danger-full-access["']/.test(modes[1]!)) return "allowed_sandbox_modes leaves out danger-full-access";
  if (/^\s*\[\[\s*remote_sandbox_config\s*\]\]/m.test(t)) return "remote_sandbox_config";
  if (/^\s*\[?\s*allowed_permission_profiles\b/m.test(t) || /^\s*default_permissions\s*=/m.test(t)) return "permission profiles";
  if (/\bdeny_read\s*=/.test(t)) return "deny_read";
  if (/^\s*\[\s*experimental_network\s*\]/m.test(t)) return "experimental_network";
  if (codexNetworkProxyOn(t)) return "network_proxy";
  return null;
}

/** Does a Codex TOML text turn the network proxy feature on, in any of its
 *  spellings (`network_proxy = true`, `network_proxy.enabled = true`, an
 *  inline `{ enabled = true }`, a `[features.network_proxy]` or
 *  `[profiles.<p>.features.network_proxy]` table with `enabled = true`)?
 *  Pure. */
export function codexNetworkProxyOn(text: string): boolean {
  const t = stripTomlComments(text);
  if (/\bnetwork_proxy\s*=\s*true\b/.test(t) || /\bnetwork_proxy\.enabled\s*=\s*true\b/.test(t)) return true;
  if (/\bnetwork_proxy\s*=\s*\{[^}]*\benabled\s*=\s*true\b[^}]*\}/.test(t)) return true;
  const lines = t.split("\n");
  for (let i = 0; i < lines.length; i++) {
    if (!/^\s*\[[^\]]*\bnetwork_proxy\s*\]\s*$/.test(lines[i]!)) continue;
    for (let j = i + 1; j < lines.length && !/^\s*\[/.test(lines[j]!); j++) if (/^\s*enabled\s*=\s*true\b/.test(lines[j]!)) return true;
  }
  return false;
}

/** The same for a managed config (the legacy `/etc/codex/managed_config.toml`,
 *  MDM `config_toml_base64`): it sits ABOVE the command line, so a
 *  `sandbox_mode` other than danger-full-access keeps the sandbox, and Codex
 *  reads it as requirements too. Pure. */
export function codexManagedConfigLock(text: string): string | null {
  const mode = codexConfigSandboxMode(text);
  if (mode !== null && mode !== "danger-full-access") return `sandbox_mode = "${mode}"`;
  return codexRequirementsLock(text);
}

/** What in one Codex config file (any layer) relies on Codex's sandbox for
 *  something Mandu does not do: a permission profile of the user's own,
 *  defined or selected (`default_permissions` naming one that does not
 *  start with `:`, any `[permissions…]` table or `permissions…` key). Such a
 *  profile is where every filesystem restriction beyond Codex's built-in
 *  ones lives (an allowlist of reads, a `deny` / `none` entry; the
 *  built-ins cannot be edited), and the override drops it. Conservative: a
 *  profile that only touches the network, or one defined but not selected,
 *  counts too; `deny_read` (valid only in requirements) as well. Pure. */
export function codexConfigKeeps(text: string | null): string | null {
  if (text === null) return null;
  const PROFILE = "a permission profile of your own";
  const perms = codexConfigDefaultPermissions(text);
  if (perms !== null && !perms.startsWith(":")) return PROFILE;
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (line.startsWith("#")) continue;
    if (/^\[\[?\s*["']?permissions["']?\s*[.\]]/.test(line)) return PROFILE;
    if (/^["']?permissions["']?\s*[.=]/.test(line)) return PROFILE;
    if (/^["']?deny_read["']?\s*=/.test(line)) return PROFILE;
  }
  return null;
}

/** Codex's system config, the lowest layer (0.159.3). */
export const CODEX_SYSTEM_CONFIG_PATH = "/etc/codex/config.toml";

/** Codex's config layers for a run in `cwd`, lowest precedence first
 *  (0.159.3: the system file 10, `$CODEX_HOME/config.toml` 20, the `-p`
 *  profile 21, then the project layers 25): the files that exist, with
 *  their text. Conservative where the decision is "keep": every
 *  `.codex/config.toml` from `/` down to `cwd` is read (Codex reads those
 *  from its project root, which `project_root_markers` may put above the
 *  nearest `.git`), whether or not the project is trusted (Mandu's own
 *  launch may trust it); `extraCwds` (a run's `-C`) add theirs. Pure over
 *  its readers. */
export function codexConfigLayers(
  env: Record<string, string | undefined>,
  cwd: string,
  profile: string | null,
  io: { readFile: (p: string) => string | null; exists?: (p: string) => boolean },
  extraCwds: readonly string[] = [],
): Array<{ path: string; text: string }> {
  const paths = [CODEX_SYSTEM_CONFIG_PATH, codexConfigPath(env)];
  if (profile !== null && codexProfileNameOk(profile)) paths.push(join(codexHomeDir(env), `${profile}.config.toml`));
  for (const c of [cwd, ...extraCwds]) {
    const dirs: string[] = [];
    for (let d = c; ; d = dirname(d)) {
      dirs.unshift(d);
      if (dirname(d) === d) break;
    }
    for (const d of dirs) paths.push(join(d, ".codex", "config.toml"));
  }
  const out: Array<{ path: string; text: string }> = [];
  for (const p of [...new Set(paths)]) {
    const text = io.readFile(p);
    if (text !== null) out.push({ path: p, text });
  }
  return out;
}

/** Every Codex config layer a run in `cwd` with this argv may read: the
 *  layers below the command line (codexConfigLayers, with the run's `-p`
 *  profile and `-C` directory) and the legacy managed config above it. Read
 *  for the upload hosts the launch denies (upload-deny.ts, the codex row).
 *  Pure over its reader. */
export function codexAllConfigLayers(
  env: Record<string, string | undefined>,
  cwd: string,
  argv: readonly string[],
  readFile: (p: string) => string | null,
): Array<{ path: string; text: string }> {
  const cd = codexArgvCd(argv);
  const layers = codexConfigLayers(env, cwd, codexArgvProfile(argv), { readFile }, cd !== null ? [resolve(cwd, cd)] : []);
  const managed = readFile(CODEX_MANAGED_CONFIG_PATH);
  if (managed !== null) layers.push({ path: CODEX_MANAGED_CONFIG_PATH, text: managed });
  return layers;
}

/** Over Codex's layers (lowest first): does the highest layer that sets the
 *  sandbox (`default_permissions` or `sandbox_mode`; within one layer
 *  `default_permissions` wins) turn it off? Pure. */
export function codexLayersSandboxOff(layers: ReadonlyArray<{ text: string }>): boolean {
  for (let i = layers.length - 1; i >= 0; i--) {
    const t = layers[i]!.text;
    const perms = codexConfigDefaultPermissions(t);
    if (perms !== null) return perms === ":danger-full-access";
    const mode = codexConfigSandboxMode(t);
    if (mode !== null) return mode === "danger-full-access";
  }
  return false;
}

/** Over Codex's layers: the first that relies on the sandbox (codexConfigKeeps), named, or null. Pure. */
export function codexLayersKeeps(layers: ReadonlyArray<{ path: string; text: string }>): string | null {
  for (const l of layers) {
    const k = codexConfigKeeps(l.text);
    if (k !== null) return `${k} (${l.path})`;
  }
  return null;
}

/** Over Codex's layers: the first that turns the network proxy on, else
 *  null. Conservative: a higher layer that turns it off does not count,
 *  since Codex may not apply it (an untrusted project); only the run's own
 *  "off" cancels it. Pure. */
export function codexLayersNetworkProxy(layers: ReadonlyArray<{ path: string; text: string }>): string | null {
  for (const l of layers) if (codexNetworkProxySetting(l.text) === true) return l.path;
  return null;
}

/** Where an administrator's Codex settings live on macOS, for
 *  codexAdminSandboxLock. */
export const CODEX_REQUIREMENTS_PATH = "/etc/codex/requirements.toml";
export const CODEX_MANAGED_CONFIG_PATH = "/etc/codex/managed_config.toml";
export function codexMdmPlists(user: string): string[] {
  return ["/Library/Managed Preferences/com.openai.codex.plist", `/Library/Managed Preferences/${user}/com.openai.codex.plist`];
}

/** The administrator source that keeps Codex's own sandbox on, or null:
 *  the system requirements, the legacy managed config, forced MDM
 *  preferences (a configuration profile's plist, read as JSON by
 *  `readPlistJson`; one that exists but cannot be read counts, fail-safe),
 *  and the cloud requirements cache. Pure over its readers. */
export function codexAdminSandboxLock(r: {
  readFile: (p: string) => string | null;
  readPlistJson: (p: string) => string | null;
  exists: (p: string) => boolean;
  user: string;
  codexHome: string;
}): string | null {
  const req = r.readFile(CODEX_REQUIREMENTS_PATH);
  if (req !== null) { const w = codexRequirementsLock(req); if (w) return `${CODEX_REQUIREMENTS_PATH}: ${w}`; }
  const managed = r.readFile(CODEX_MANAGED_CONFIG_PATH);
  if (managed !== null) { const w = codexManagedConfigLock(managed); if (w) return `${CODEX_MANAGED_CONFIG_PATH}: ${w}`; }
  for (const plist of codexMdmPlists(r.user)) {
    if (!r.exists(plist)) continue;
    const json = r.readPlistJson(plist);
    if (json === null) return `${plist}: unreadable managed preferences`;
    let doc: unknown;
    try { doc = JSON.parse(json); } catch { return `${plist}: unreadable managed preferences`; }
    if (typeof doc !== "object" || doc === null) continue;
    const d = doc as Record<string, unknown>;
    const decode = (k: string): string | null => (typeof d[k] === "string" ? Buffer.from(d[k] as string, "base64").toString("utf8") : null);
    const rq = decode("requirements_toml_base64");
    if (rq !== null) { const w = codexRequirementsLock(rq); if (w) return `${plist} (requirements): ${w}`; }
    const cf = decode("config_toml_base64");
    if (cf !== null) { const w = codexManagedConfigLock(cf); if (w) return `${plist} (managed config): ${w}`; }
  }
  const cache = r.readFile(join(r.codexHome, "cloud-config-bundle-cache.json"));
  if (cache !== null) {
    try {
      const found: string[] = [];
      const walk = (v: unknown, key: string): void => {
        if (typeof v === "string") { if (/requirements/i.test(key)) found.push(v); return; }
        if (Array.isArray(v)) { for (const x of v) walk(x, key); return; }
        if (typeof v === "object" && v !== null) for (const [k, x] of Object.entries(v)) walk(x, /requirements/i.test(key) ? key : k);
      };
      walk(JSON.parse(cache), "");
      for (const t of found) { const w = codexRequirementsLock(t); if (w) return `your organization's cloud requirements (cached in ${join(r.codexHome, "cloud-config-bundle-cache.json")}): ${w}`; }
    } catch { /* a cache, best effort */ }
  }
  return null;
}

/** Does Codex's config.toml turn its sandbox off by default? A line scan of
 *  the top-level table only (a `[profiles.x]` value applies only when that
 *  profile is chosen, so it does not count). A `default_permissions` other
 *  than `:danger-full-access` outranks `sandbox_mode` in the same file, so
 *  then it does not (the permission profile applies, and its deny entries
 *  must be checked). Never returns the file's text. */
export function codexConfigSandboxOff(text: string | null): boolean {
  if (text === null) return false;
  const perms = codexConfigDefaultPermissions(text);
  if (perms !== null) return perms === ":danger-full-access";
  return codexConfigSandboxMode(text) === "danger-full-access";
}

/** Codex's home: `$CODEX_HOME`, else `~/.codex`. */
export function codexHomeDir(env: Record<string, string | undefined> = process.env): string {
  return env["CODEX_HOME"] || join(env["HOME"] || homedir(), ".codex");
}

/** Where Codex keeps its config.toml: `$CODEX_HOME`, else `~/.codex`. */
export function codexConfigPath(env: Record<string, string | undefined> = process.env): string {
  return join(codexHomeDir(env), "config.toml");
}

export interface CodexSandboxProbeDeps {
  platform: () => "linux" | "darwin" | "win32";
  commandExists: (cmd: string) => boolean;
  readKnob: (path: string) => string | null;
  /** Codex's bwrap probe; true iff it exited 0. */
  bwrapProbe: () => boolean;
  /** Mandu's own bubblewrap is in force (bwrap-grant.ts). Optional: absent
   *  reads as not. */
  manduBwrapInForce?: () => boolean;
  /** macOS: Codex's config.toml turns its sandbox off (codexConfigSandboxOff
   *  over codexConfigPath). Optional: absent reads as on, Codex's default. */
  codexConfigSandboxOff?: () => boolean;
  /** macOS: the administrator source that keeps Codex's sandbox on
   *  (codexAdminSandboxLock). Optional: absent reads as none. */
  codexAdminLock?: () => string | null;
  /** macOS: what in Codex's config layers (with the profile a run selects)
   *  relies on the sandbox (codexLayersKeeps). Optional: absent reads as
   *  nothing. */
  codexConfigKeeps?: (profile?: string | null) => string | null;
  /** macOS: a profile file's text (`$CODEX_HOME/<name>.config.toml`), for a
   *  run's `-p`. Optional: absent reads as none. */
  readCodexProfile?: (name: string) => string | null;
  /** macOS: where Codex's network proxy is turned on (the highest of its
   *  config layers that sets it, with the profile a run selects), or null.
   *  Optional: absent reads as off. */
  codexNetworkProxy?: (profile: string | null) => string | null;
}

/** Codex's probe through the bwrap Codex gets under mandu: Mandu's own when
 *  it is in force (first on the agent's PATH), else the one on PATH. */
export const realCodexSandboxProbe = (): boolean => {
  const bwrap = resolveWrapBwrap();
  if (bwrap === null) return false;
  // In a launch a pass is kept for the boot (probe-cache.ts). A warning-only
  // probe: a wrong kept pass only drops the warning; Codex's own commands
  // still fail on their own.
  return cachedProbe("codex-bwrap", () => ({ bins: [bwrap], argv: CODEX_BWRAP_PROBE_ARGV }), () =>
    spawnSync(bwrap, CODEX_BWRAP_PROBE_ARGV, { stdio: "ignore", timeout: 5000 }).status === 0);
};

/** Gather the facts; the bwrap probe runs only for an installed codex with a
 *  system bwrap on Linux. On macOS: is there a Seatbelt profile around the
 *  launch, and does codex's config turn its own sandbox off? `opts` carries
 *  what a launch knows better than a probe: its argv's own sandbox flags,
 *  and whether it wraps the agent in the profile at all (a launch that
 *  protects secrets; absent = `sandbox-exec` is present, the doctor's view). */
export function gatherCodexSandbox(
  deps: CodexSandboxProbeDeps,
  codexInstalled?: boolean,
  opts: { argvSandboxOff?: boolean; argvChoice?: CodexSandboxChoice; outerSeatbelt?: boolean; profile?: string | null; credsBlocked?: boolean } = {},
): CodexSandboxFacts {
  const platform = deps.platform();
  if (platform === "darwin") {
    const codex = codexInstalled ?? deps.commandExists("codex");
    return {
      platform,
      codex,
      systemBwrap: false,
      systemBwrapOk: null,
      apparmorRestrict: null,
      usernsClone: null,
      maxUserNamespaces: null,
      // By path, never a PATH lookup: a planted `sandbox-exec` must not count (seatbelt-profile.ts).
      outerSeatbelt: codex && (opts.outerSeatbelt ?? sandboxExecAvailable(deps.commandExists)),
      // Only the run's own "off" (a typed flag or a -c at the level Codex
      // reads) is quiet. A config that turns it off gets the same override
      // and the launch line: which config layer Codex applies (an untrusted
      // project's, a profile under a project's) is not Mandu's to guess.
      codexSandboxOff: codex && opts.argvSandboxOff === true,
      explicitOn: opts.argvChoice?.kind === "on" ? opts.argvChoice.by : null,
      adminLock: codex ? deps.codexAdminLock?.() ?? null : null,
      configKeeps: codex && opts.argvChoice?.kind !== "off" ? deps.codexConfigKeeps?.(opts.profile ?? null) ?? null : null,
      // The run's own proxy setting wins over its profile and config.toml.
      networkProxy: !codex || opts.argvChoice?.netProxy === "off" ? null : deps.codexNetworkProxy?.(opts.profile ?? null) ?? null,
      ...(opts.credsBlocked !== undefined ? { credsBlocked: opts.credsBlocked } : {}),
    };
  }
  const linux = platform === "linux";
  const codex = linux && (codexInstalled ?? deps.commandExists("codex"));
  const systemBwrap = codex && (deps.commandExists("bwrap") || (deps.manduBwrapInForce?.() ?? false));
  const knob = (p: string): string | null => deps.readKnob(p)?.trim() ?? null;
  return {
    platform,
    codex,
    systemBwrap,
    systemBwrapOk: systemBwrap ? deps.bwrapProbe() : null,
    apparmorRestrict: codex ? knob(APPARMOR_USERNS_SYSCTL) : null,
    usernsClone: codex ? knob(USERNS_CLONE_SYSCTL) : null,
    maxUserNamespaces: codex ? knob(MAX_USER_NAMESPACES_SYSCTL) : null,
  };
}

/** Subcommands that never run a model command, so need no sandbox note. */
const QUIET_SUBCOMMANDS = new Set(["login", "logout", "--version", "-V", "--help", "-h", "help", "completion", "features"]);

/** What a launch does about Codex's own sandbox: its ONE line (or null) and
 *  the overrides to add to Mandu's own (spliced at every level), empty
 *  unless Mandu turns the sandbox off. Only a real `codex` argv[0] under the
 *  codex target. Linux: the line only (unchanged). macOS: only a run that
 *  talks to the model (codex-argv.ts codexTalksToModel: not `login`,
 *  `sandbox`, `--version`, …), and `outerSeatbelt` must be the profile the
 *  launch REALLY applied (run.ts seatbeltApplied): without one, Codex's own
 *  sandbox works and stays on. */
export function codexSandboxLaunch(
  target: string,
  argv: readonly string[],
  deps: CodexSandboxProbeDeps = realCodexSandboxDeps(),
  opts: { outerSeatbelt?: boolean; credsBlocked?: boolean } = {},
): { note: string | null; inject: readonly string[] } {
  const none = { note: null, inject: [] as readonly string[] };
  if (target !== "codex" || basename(argv[0] ?? "") !== "codex") return none;
  if (deps.platform() === "darwin") {
    const sub = codexSubcommand(argv);
    // A bare `codex app-server` (an IDE's backend) runs sessions too; its
    // `daemon` / `proxy` / `generate-*` subcommands do not, even after its
    // own options.
    const appServer = codexBareAppServer(argv);
    if (!codexTalksToModel(argv) && !appServer) {
      // `codex sandbox` / `exec-server` run commands in Codex's own sandbox
      // by design: they fail inside Mandu's profile, so say so.
      if ((sub === "sandbox" || sub === "exec-server") && opts.outerSeatbelt === true) {
        return {
          note: `mandu: WARNING — \`codex ${sub}\` runs commands in Codex's own sandbox, which macOS cannot start inside Mandu's ` +
            "profile (sandbox_apply: Operation not permitted), so they fail under mandu on macOS",
          inject: [],
        };
      }
      return none;
    }
    const choice = codexArgvSandboxChoice(argv, deps.readCodexProfile ?? (() => null));
    if (choice.kind === "remote") return opts.outerSeatbelt === true ? { note: CODEX_REMOTE_NOTE, inject: [] } : none;
    const a = assessCodexSandbox(gatherCodexSandbox(deps, true, {
      argvChoice: choice,
      argvSandboxOff: choice.kind === "off",
      profile: codexArgvProfile(argv),
      ...(opts.outerSeatbelt !== undefined ? { outerSeatbelt: opts.outerSeatbelt } : {}),
      ...(opts.credsBlocked !== undefined ? { credsBlocked: opts.credsBlocked } : {}),
    }));
    // Off by Mandu, or off by the run or config.toml already: the override
    // goes in either way (same value), since Codex drops a root-level `-c`
    // once a subcommand has its own, and a config's default_permissions
    // would otherwise outrank its sandbox_mode.
    const off = a.state === "seatbelt-mandu-off" || a.state === "seatbelt-sandbox-off";
    const note = appServer && a.state === "seatbelt-mandu-off"
      ? (a.noCreds ? CODEX_APP_SERVER_OFF_NOTE_NO_CREDS : CODEX_APP_SERVER_OFF_NOTE)
      : codexSandboxLaunchNote(a);
    // A run that turns the proxy off with a root `-c` would lose it once
    // Mandu's splice gives the subcommand its own `-c` list: carry it to
    // every level with the override.
    return { note, inject: off ? [...CODEX_SANDBOX_OFF_ARGS, ...(choice.netProxy === "off" ? CODEX_PROXY_OFF_ARGS : [])] : [] };
  }
  if (argv[1] !== undefined && QUIET_SUBCOMMANDS.has(argv[1])) return none;
  return {
    note: codexSandboxLaunchNote(assessCodexSandbox(gatherCodexSandbox(deps, true, {
      argvSandboxOff: codexArgvSandboxOff(argv),
      ...(opts.outerSeatbelt !== undefined ? { outerSeatbelt: opts.outerSeatbelt } : {}),
    }))),
    inject: [],
  };
}

/** The launch line alone (codexSandboxLaunch). */
export function launchCodexSandboxNote(
  target: string,
  argv: readonly string[],
  deps: CodexSandboxProbeDeps = realCodexSandboxDeps(),
  opts: { outerSeatbelt?: boolean } = {},
): string | null {
  return codexSandboxLaunch(target, argv, deps, opts).note;
}

/** Read a plist as JSON (plutil, by absolute path), or null. */
export function realReadPlistJson(p: string): string | null {
  const r = spawnSync("/usr/bin/plutil", ["-convert", "json", "-o", "-", "--", p], { encoding: "utf8", timeout: 5000 });
  return r.status === 0 && typeof r.stdout === "string" ? r.stdout : null;
}

/** The macOS readers over Codex's config layers for a run in `cwd`
 *  (codexConfigLayers), shared by a launch and the doctor. */
export function codexLayerReaders(
  env: Record<string, string | undefined>,
  cwd: string,
  readFile: (p: string) => string | null,
  exists: (p: string) => boolean,
  extraCwds: readonly string[] = [],
): Pick<CodexSandboxProbeDeps, "codexConfigSandboxOff" | "codexConfigKeeps" | "codexNetworkProxy" | "readCodexProfile"> {
  const layers = (profile: string | null): Array<{ path: string; text: string }> => codexConfigLayers(env, cwd, profile, { readFile, exists }, extraCwds);
  return {
    codexConfigSandboxOff: () => codexLayersSandboxOff(layers(null)),
    codexConfigKeeps: (profile) => codexLayersKeeps(layers(profile ?? null)),
    codexNetworkProxy: (profile) => codexLayersNetworkProxy(layers(profile)),
    readCodexProfile: (name) => readCodexProfileFile(env, name, readFile),
  };
}

export function realCodexSandboxDeps(env: Record<string, string | undefined> = process.env, cwd: string = process.cwd(), extraCwds: readonly string[] = []): CodexSandboxProbeDeps {
  const readKnob = (p: string): string | null => { try { return readFileSync(p, "utf8"); } catch { return null; } };
  return {
    platform: () => (process.platform === "darwin" ? "darwin" : process.platform === "win32" ? "win32" : "linux"),
    commandExists: commandAvailable,
    readKnob,
    bwrapProbe: realCodexSandboxProbe,
    manduBwrapInForce: manduBwrapInForceHere,
    ...codexLayerReaders(env, cwd, readKnob, existsSync, extraCwds),
    codexAdminLock: () => codexAdminSandboxLock({
      readFile: readKnob,
      readPlistJson: realReadPlistJson,
      exists: (p) => existsSync(p),
      user: env["USER"] || safeUserName(),
      codexHome: codexHomeDir(env),
    }),
  };
}

/** A profile's file (`$CODEX_HOME/<name>.config.toml`); a name with a path
 *  separator or `..` reads nothing. */
function readCodexProfileFile(env: Record<string, string | undefined>, name: string, readKnob: (p: string) => string | null): string | null {
  return codexProfileNameOk(name) ? readKnob(join(codexHomeDir(env), `${name}.config.toml`)) : null;
}

function codexProfileNameOk(name: string): boolean {
  return /^[A-Za-z0-9_][A-Za-z0-9_.-]*$/.test(name) && !name.includes("..");
}

function safeUserName(): string {
  try { return userInfo().username; } catch { return ""; }
}
