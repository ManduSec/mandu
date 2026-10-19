/**
 * setup — `mandu setup`: the ONE optional privileged step, made a single
 * command (docs/design/confidentiality/rootless-confinement-ubuntu-2404.md §3.2, §12.3).
 *
 * Ubuntu (>= 23.10) lets an unprivileged process create a user namespace only
 * when the binary it execs carries an AppArmor profile granting `userns`, and
 * 26.04 also forbids a sandbox inside a bwrap sandbox. `mandu setup` installs
 * Mandu's OWN bubblewrap: a copy of the system bwrap at the root-owned
 * `/usr/lib/mandu/bin/bwrap` plus `/etc/apparmor.d/mandu-bwrap`
 * (bwrap-grant.ts has the design). That adds the mount layer to the guard on
 * every supported Ubuntu, lets the agent's own sandboxes nest, and changes
 * nothing for any other program on the host.
 *
 * It also MIGRATES away from the grants it installed before 2026-09-27
 * (`/etc/apparmor.d/bwrap` + `unshare`, Mandu-marked): they were host-wide
 * trampolines, and the `bwrap` one shares its profile NAME with Ubuntu's own,
 * so after a 24.04 → 26.04 upgrade it silently switched Ubuntu's restriction
 * off for every program (fork H, §12.3 "Verified"). Removing one never unloads
 * by a name another file also defines: the file goes, then that other file is
 * reloaded.
 *
 * The command itself runs UNPRIVILEGED: it probes, explains, prints the exact
 * profile text and the exact commands, asks, and only then runs those commands
 * under `sudo`. Nothing else in Mandu ever asks for root.
 *
 *   mandu setup              plan, confirm, install, re-probe
 *   mandu setup --yes        no prompt (still goes through sudo)
 *   mandu setup --print      profile + manual commands, runs nothing
 *   mandu setup --uninstall  remove what Mandu installed (old grants too)
 *
 * Rules that keep it safe on a host we do not own:
 *   - need is decided by PROBING, never by file presence alone;
 *   - a file Mandu did not create (no `# Mandu:` first line) is never
 *     overwritten and never removed;
 *   - no profile Mandu installs is named, or attached, like a distro one;
 *   - the host-global sysctl is never the suggested fix (mentioned once, under
 *     --print, with the reason it is not preferred).
 *
 * PURE planning (`planSetup`, the command builders, `renderPrint`) + an
 * injectable executor, so every branch except the real sudo call is
 * unit-tested with no privilege.
 *
 * Mandu-new (no reference origin).
 */
import { spawnSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { createInterface } from "node:readline";
import { dirname } from "node:path";
import {
  ADMIN_BWRAP_FIX,
  adminBwrapRefusedReason,
  APPARMOR_DIR,
  DISTRO_BWRAP_PROFILE_FILE,
  isOurs,
  LEGACY_PROFILES,
  MANDU_BWRAP,
  MANDU_BWRAP_DIR,
  MANDU_PROFILE_FILE,
  manduBwrapInForce,
  manduBwrapInstalled,
  manduBwrapStale,
  realBwrapGrantDeps,
  resolveWrapBwrap,
  SYSTEM_BWRAP,
  type LegacyProfile,
} from "./bwrap-grant.js";
import { adminBwrap, type AdminBwrap } from "./bwrap-path.js";
import { POSTURE_SENTENCE } from "./confinement-posture.js";
import { nestedSandboxProbeArgv } from "./secret-twins.js";
import type { Layout } from "./services/layout.js";
import { APPARMOR_USERNS_SYSCTL, probeUserns, usernsGapHint } from "./userns.js";
import { clearProbeCacheFile } from "./probe-cache.js";

export { APPARMOR_DIR, isOurs, LEGACY_PROFILES, OWNERSHIP_MARKER } from "./bwrap-grant.js";
export type { LegacyProfile } from "./bwrap-grant.js";

/** The shipped profile's asset key (services/layout.ts ASSET_SOURCES). */
export const PROFILE_ASSET = "apparmor/mandu-bwrap";

export interface SetupFacts {
  platform: "linux" | "darwin" | "win32";
  /** The root-owned system bwrap the copy is made from; null when absent. */
  systemBwrap: string | null;
  /** Why the administrator's `bwrap_path` cannot be used (bwrap-path.ts
   *  `adminBwrap`), when it is set and refused; then `systemBwrap` is null
   *  because of it, not because bubblewrap is missing. */
  adminRefused?: string;
  /** The launch's userns probe passes (the copy when in force, else bwrap). */
  usernsOk: boolean;
  /** A sandbox can start inside the wrap the launch would run. */
  nestingOk: boolean;
  /** kernel.apparmor_restrict_unprivileged_userns reads 1. */
  apparmorRestricted: boolean;
  apparmorParser: boolean;
  /** Mandu's copy: absent, identical to the system bwrap, or older. */
  copy: "absent" | "current" | "stale";
  /** Current content of /etc/apparmor.d/mandu-bwrap; null when absent. */
  profileFile: string | null;
  /** Current content of the pre-2026-09-27 files; null when absent. */
  legacy: Record<LegacyProfile, string | null>;
  /** Per legacy name: the OTHER /etc/apparmor.d files that define a profile
   *  of that name (Ubuntu's bwrap-userns-restrict defines `bwrap`). */
  sameName: Record<LegacyProfile, string[]>;
  /** One cause sentence for a probe failure that is NOT the AppArmor knob. */
  usernsHint: string;
}

export type SetupPlan =
  | { kind: "nothing"; reason: string }
  | { kind: "blocked"; reason: string; fix: string | null }
  | {
      kind: "apply";
      /** install (or refresh) Mandu's bubblewrap + its profile */
      install: boolean;
      /** the Mandu-marked pre-2026-09-27 grants to remove */
      removeLegacy: LegacyProfile[];
      /** why `install` is false while there is still legacy to remove */
      note?: string;
    };

const legacyOurs = (f: SetupFacts): LegacyProfile[] => LEGACY_PROFILES.filter((n) => isOurs(f.legacy[n]));

/** Decide what `mandu setup` would do. Pure. `profileText` is the shipped
 *  profile, so a changed profile is re-installed. */
export function planSetup(f: SetupFacts, profileText: string): SetupPlan {
  if (f.platform !== "linux") {
    return { kind: "nothing", reason: "this is not Linux: the AppArmor user-namespace restriction does not exist here" };
  }
  const removeLegacy = legacyOurs(f);
  if (removeLegacy.length > 0 && !f.apparmorParser) {
    return { kind: "blocked", reason: "`apparmor_parser` is not on PATH, so an older Mandu grant cannot be unloaded", fix: "sudo apt install apparmor" };
  }

  // Does this host need Mandu's bubblewrap?
  let install = false;
  let why: string | null = null;
  let fix: string | null = null;
  // No bubblewrap to copy or run. An administrator's that cannot be used says
  // so in doctor's words (bwrap-grant.ts), never "not installed": Mandu runs
  // no other bubblewrap in its place, installed or not.
  const noBwrap = (): void => {
    if (f.adminRefused !== undefined) {
      why = adminBwrapRefusedReason(f.adminRefused);
      fix = ADMIN_BWRAP_FIX;
    } else {
      why = "bubblewrap (`bwrap`) is not installed, and Mandu's copy is made from it";
      fix = "sudo apt install bubblewrap   (then re-run `mandu setup`)";
    }
  };
  if (!f.apparmorRestricted) {
    // No per-binary restriction: any bwrap may create a namespace and nest.
    if (!f.usernsOk) {
      if (f.adminRefused !== undefined) noBwrap();
      else why = `user namespaces are unavailable for a reason AppArmor profiles cannot fix: ${f.usernsHint}`;
    }
  } else {
    const current = f.copy === "current" && isOurs(f.profileFile) && f.profileFile === profileText;
    // The system bwrap already nests (a site profile): nothing to add, unless
    // it is one of OUR old grants that is about to go.
    const systemSuffices = f.copy === "absent" && removeLegacy.length === 0 && f.usernsOk && f.nestingOk;
    if (!(current && f.nestingOk) && !systemSuffices) {
      if (f.profileFile !== null && !isOurs(f.profileFile)) {
        return {
          kind: "blocked",
          reason: `${MANDU_PROFILE_FILE} exists and was not created by Mandu`,
          fix: "review that file; Mandu will not overwrite it",
        };
      }
      if (f.systemBwrap === null) noBwrap();
      else if (!f.apparmorParser) {
        why = "`apparmor_parser` is not on PATH, so a profile cannot be loaded";
        fix = "sudo apt install apparmor";
      } else install = true;
    }
  }

  if (!install && removeLegacy.length === 0) {
    if (why !== null) return { kind: "blocked", reason: why, fix };
    return {
      kind: "nothing",
      reason: f.apparmorRestricted
        ? "Mandu's own bubblewrap is in place and a sandbox can start inside Mandu's: the mount layer can go up (secrets are `confined` where Mandu's file guard runs; `mandu doctor` says)"
        : "this host can already create an unprivileged user namespace through bwrap: the mount layer can go up (secrets are `confined` where Mandu's file guard runs; `mandu doctor` says)",
    };
  }
  return { kind: "apply", install, removeLegacy, ...(why !== null ? { note: why } : {}) };
}

/** The exact privileged commands that install (or refresh) Mandu's bwrap. */
export function installCommands(src: { bwrap: string; profile: string }): string[][] {
  return [
    ["install", "-d", "-m", "0755", "-o", "root", "-g", "root", dirname(MANDU_BWRAP_DIR), MANDU_BWRAP_DIR],
    ["install", "-m", "0755", "-o", "root", "-g", "root", src.bwrap, MANDU_BWRAP],
    ["install", "-m", "0644", "-o", "root", "-g", "root", src.profile, MANDU_PROFILE_FILE],
    ["apparmor_parser", "-r", MANDU_PROFILE_FILE],
  ];
}

/** Remove one pre-2026-09-27 grant. When another file defines a profile of
 *  the same name (Ubuntu's `bwrap`), unloading by name would unload THAT one
 *  too: delete our file, then reload theirs, which replaces ours in place. */
export function legacyRemovalCommands(name: LegacyProfile, sameName: readonly string[]): string[][] {
  const path = `${APPARMOR_DIR}/${name}`;
  return sameName.length > 0
    ? [["rm", "-f", path], ["apparmor_parser", "-r", ...sameName]]
    : [["apparmor_parser", "-R", path], ["rm", "-f", path]];
}

/** Remove Mandu's bwrap and its profile (names only Mandu uses). */
export function uninstallCommands(): string[][] {
  return [
    ["apparmor_parser", "-R", MANDU_PROFILE_FILE],
    ["rm", "-f", MANDU_PROFILE_FILE, MANDU_BWRAP],
    ["rmdir", "--ignore-fail-on-non-empty", MANDU_BWRAP_DIR, dirname(MANDU_BWRAP_DIR)],
  ];
}

const sh = (argv: string[]): string => `sudo ${argv.join(" ")}`;

/** `--print`: the profile byte for byte + the manual commands. Pure. */
export function renderPrint(profile: { path: string; text: string }, legacy: { name: LegacyProfile; sameName: string[] }[] = []): string {
  const L: string[] = [
    "# Mandu setup: Mandu's own bubblewrap for Ubuntu's restricted unprivileged user",
    "# namespaces (kernel.apparmor_restrict_unprivileged_userns=1). A copy of the system",
    `# bwrap at the root-owned ${MANDU_BWRAP}, and a profile that attaches to that copy`,
    "# only: it may create a namespace, and everything it runs holds no capabilities",
    "# except bubblewrap itself, so a sandbox can start inside Mandu's and nothing else",
    "# on the host changes.",
    "",
    `# ───── ${MANDU_PROFILE_FILE}   (shipped at ${profile.path}) ─────`,
    profile.text.replace(/\n$/, ""),
    "",
    "# ───── manual install (what `mandu setup` runs) ─────",
    ...installCommands({ bwrap: SYSTEM_BWRAP, profile: profile.path }).map(sh),
  ];
  if (legacy.length > 0) {
    L.push("", "# ───── remove the older Mandu grants on this host ─────");
    for (const l of legacy) for (const c of legacyRemovalCommands(l.name, l.sameName)) L.push(sh(c));
  }
  L.push("", "# ───── remove ─────", ...uninstallCommands().map(sh), "");
  L.push("# Broader alternative, NOT preferred: `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`");
  L.push("# lifts the restriction for EVERY binary on the host. Mandu's own bubblewrap gives the");
  L.push("# one program Mandu runs the one capability it needs, and nothing else.");
  return L.join("\n") + "\n";
}

export interface SetupDeps {
  facts: () => SetupFacts;
  /** Shipped profile: where it lives in this install + its text. */
  profile: () => { path: string; text: string };
  /** Run `sudo <argv>` attached to the terminal; the exit status. */
  sudo: (argv: string[]) => number;
  /** Ask y/N. */
  confirm: (question: string) => Promise<boolean>;
  isTTY: boolean;
  out: (s: string) => void;
  err: (s: string) => void;
  /** Drop the launch's per-boot kernel probe cache (probe-cache.ts): what
   *  setup changes is noticed by the next launch at once. Optional: absent,
   *  nothing to drop. */
  clearProbeCache?: () => void;
}

function runAll(cmds: string[][], deps: SetupDeps): boolean {
  for (const c of cmds) {
    if (deps.sudo(c) !== 0) { deps.err(`mandu setup: '${sh(c)}' failed\n`); return false; }
  }
  return true;
}

/** `mandu setup`. Exit 0 = the host is (now) fine or nothing was needed. */
export async function runSetup(rest: string[], deps: SetupDeps): Promise<number> {
  const unknown = rest.find((a) => !["--print", "--uninstall", "--yes", "-y"].includes(a));
  if (unknown !== undefined) {
    deps.err(`mandu setup: unknown option '${unknown}' (usage: mandu setup [--print | --uninstall] [--yes]; mandu setup --help)\n`);
    return 2;
  }
  const profile = deps.profile();
  const yes = rest.includes("--yes") || rest.includes("-y");
  const facts = deps.facts();
  const legacy = legacyOurs(facts).map((name) => ({ name, sameName: facts.sameName[name] }));
  const legacyCmds = legacy.flatMap((l) => legacyRemovalCommands(l.name, l.sameName));
  const legacyFiles = legacy.map((l) => `${APPARMOR_DIR}/${l.name}`).join(" and ");

  if (rest.includes("--print")) {
    deps.out(renderPrint(profile, legacy));
    return 0;
  }
  // Whatever happens below (an install, a removal, nothing), the next launch
  // probes the kernel afresh. Only passes are ever kept, and every input is
  // in their key; this is the belt to those braces.
  deps.clearProbeCache?.();

  if (rest.includes("--uninstall")) {
    for (const n of LEGACY_PROFILES) {
      if (facts.legacy[n] !== null && !isOurs(facts.legacy[n])) {
        deps.out(`mandu setup: ${APPARMOR_DIR}/${n} was not created by Mandu: left untouched\n`);
      }
    }
    if (facts.profileFile !== null && !isOurs(facts.profileFile)) {
      deps.out(`mandu setup: ${MANDU_PROFILE_FILE} was not created by Mandu: left untouched\n`);
    }
    const mine = isOurs(facts.profileFile) || facts.copy !== "absent";
    if (!mine && legacy.length === 0) {
      deps.out("mandu setup: nothing to remove (Mandu installed nothing on this host)\n");
      return 0;
    }
    const cmds = [...(mine ? uninstallCommands() : []), ...legacyCmds];
    deps.out(`mandu setup: this removes ${[mine ? `${MANDU_BWRAP} and ${MANDU_PROFILE_FILE}` : "", legacyFiles].filter(Boolean).join(", and ")}:\n`);
    for (const c of cmds) deps.out(`    ${sh(c)}\n`);
    deps.out("  Afterwards the guard alone keeps your credential files out (the mount layer is off where this host needs Mandu's bubblewrap).\n");
    if (!(await proceed(yes, deps))) return 1;
    if (!runAll(cmds, deps)) return 1;
    deps.out("mandu setup: removed\n");
    return 0;
  }

  const plan = planSetup(facts, profile.text);
  if (plan.kind === "nothing") {
    deps.out(`mandu setup: nothing to do: ${plan.reason}.\n`);
    return 0;
  }
  if (plan.kind === "blocked") {
    deps.err(`mandu setup: cannot upgrade this host: ${plan.reason}.\n`);
    if (plan.fix !== null) deps.err(`  fix: ${plan.fix}\n`);
    return 1;
  }

  const cmds = [
    ...(plan.install ? installCommands({ bwrap: facts.systemBwrap ?? SYSTEM_BWRAP, profile: profile.path }) : []),
    // After the new grant is in place, so a failure midway never leaves the
    // host with less than it had.
    ...legacyCmds,
  ];
  if (plan.install) {
    deps.out(
      "mandu setup: Ubuntu lets a program create a user namespace only if its AppArmor profile\n" +
      "  grants `userns`, and Mandu needs one (through bubblewrap) for the mount layer that keeps\n" +
      "  your credential files out of the agent's world. This installs Mandu's own copy of\n" +
      `  bubblewrap (${MANDU_BWRAP}) and a profile for that copy only: it may create the\n` +
      "  namespace, and everything it runs holds no capabilities except bubblewrap itself, so\n" +
      "  the agent's own sandboxes (Codex's, Mandu's command box) still start inside it.\n\n",
    );
    deps.out(`  ── ${MANDU_PROFILE_FILE} ──\n`);
    deps.out(profile.text.replace(/^/gm, "    ").replace(/ +$/gm, "") + "\n");
  }
  if (legacy.length > 0) {
    deps.out(
      `  Also removes the older Mandu grant${legacy.length > 1 ? "s" : ""} ${legacyFiles}: ` +
      "they let every program on this machine create a user namespace" +
      (legacy.some((l) => l.name === "bwrap" && l.sameName.length > 0)
        ? ", and the bwrap one overrides Ubuntu's own bwrap profile when it loads last"
        : "") +
      ".\n",
    );
    if (plan.note !== undefined) deps.out(`  (Mandu's own bubblewrap is not installed: ${plan.note}.)\n`);
  }
  deps.out("  Commands (the only step that needs root, once):\n");
  for (const c of cmds) deps.out(`    ${sh(c)}\n`);
  deps.out("  Review first: mandu setup --print     Undo: mandu setup --uninstall\n\n");
  if (!(await proceed(yes, deps))) return 1;
  if (!runAll(cmds, deps)) { deps.err("  Nothing after that command was run.\n"); return 1; }

  // Report what is TRUE now, not what we hoped: re-run the launch's probes.
  const after = deps.facts();
  if (!plan.install) {
    deps.out(`mandu setup: done: removed ${legacyFiles}.\n`);
    return 0;
  }
  if (after.copy === "current" && after.usernsOk && after.nestingOk) {
    // `confined` needs the file guard too (sandbox-security-review finding 7):
    // the mount layer alone is `gated`; doctor names the posture.
    deps.out(`mandu setup: done: the mount layer is on; with Mandu's file guard, secrets are \`confined\`. ${POSTURE_SENTENCE.confined} (\`mandu doctor\` shows this host's posture.)\n`);
    return 0;
  }
  deps.err("mandu setup: Mandu's bubblewrap is installed, but it still cannot create a user namespace here.\n  See `mandu doctor` for the cause.\n");
  return 1;
}

async function proceed(yes: boolean, deps: SetupDeps): Promise<boolean> {
  if (yes) return true;
  if (!deps.isTTY) {
    deps.err("mandu setup: not a terminal: re-run with --yes to proceed, or use --print for the manual commands\n");
    return false;
  }
  const ok = await deps.confirm("Proceed (sudo will ask for your password)? [y/N] ");
  if (!ok) deps.err("mandu setup: cancelled: nothing was changed\n");
  return ok;
}

const readOrNull = (p: string): string | null => { try { return readFileSync(p, "utf8"); } catch { return null; } };
const onPath = (cmd: string): boolean =>
  spawnSync("bash", ["-c", `command -v ${cmd} || test -x /usr/sbin/${cmd} || test -x /sbin/${cmd}`], { stdio: "ignore" }).status === 0;

/** The /etc/apparmor.d files, other than `except`, that define `profile <name>`. */
export function filesDefiningProfile(name: string, except: string, dir = APPARMOR_DIR): string[] {
  const re = new RegExp(`^\\s*profile\\s+${name}[\\s{]`, "m");
  let entries: string[] = [];
  try { entries = readdirSync(dir); } catch { return []; }
  const out: string[] = [];
  for (const e of entries.sort()) {
    const p = `${dir}/${e}`;
    if (p === except) continue;
    try { if (!statSync(p).isFile()) continue; } catch { continue; }
    const text = readOrNull(p);
    if (text !== null && re.test(text)) out.push(p);
  }
  return out;
}

/** The bwrap the copy is made from: an administrator's trusted `bwrap_path`
 *  (bwrap-path.ts; root's alone by construction), else the root-owned system
 *  bwrap; null when neither (a user-writable one is never copied, and an
 *  administrator's that cannot be used is not replaced by another). */
function rootOwnedSystemBwrap(admin: AdminBwrap): string | null {
  if (admin.kind === "path") return admin.path;
  if (admin.kind === "refused") return null;
  const s = realBwrapGrantDeps.stat(SYSTEM_BWRAP);
  return s !== null && s.isFile && s.uid === 0 && (s.mode & 0o022) === 0 ? SYSTEM_BWRAP : null;
}

export function realSetupFacts(): SetupFacts {
  const d = realBwrapGrantDeps;
  const installed = manduBwrapInstalled(d);
  const inForce = installed && manduBwrapInForce(d);
  // The distribution's by absolute path, never one inside the current
  // directory (bwrap-path.ts).
  const wrap = resolveWrapBwrap(inForce);
  const [cmd, ...args] = nestedSandboxProbeArgv(wrap ?? "");
  const admin = adminBwrap();
  const source = rootOwnedSystemBwrap(admin);
  return {
    platform: process.platform === "darwin" ? "darwin" : process.platform === "win32" ? "win32" : "linux",
    systemBwrap: source,
    ...(admin.kind === "refused" ? { adminRefused: admin.why } : {}),
    usernsOk: wrap !== null && (inForce || probeUserns()),
    nestingOk: wrap !== null && d.run(cmd!, args),
    apparmorRestricted: readOrNull(APPARMOR_USERNS_SYSCTL)?.trim() === "1",
    apparmorParser: onPath("apparmor_parser"),
    copy: !installed ? "absent" : manduBwrapStale(d, source ?? SYSTEM_BWRAP) ? "stale" : "current",
    profileFile: existsSync(MANDU_PROFILE_FILE) ? (readOrNull(MANDU_PROFILE_FILE) ?? "") : null,
    legacy: Object.fromEntries(
      LEGACY_PROFILES.map((n) => [n, existsSync(`${APPARMOR_DIR}/${n}`) ? (readOrNull(`${APPARMOR_DIR}/${n}`) ?? "") : null]),
    ) as Record<LegacyProfile, string | null>,
    sameName: Object.fromEntries(
      LEGACY_PROFILES.map((n) => [n, filesDefiningProfile(n, `${APPARMOR_DIR}/${n}`)]),
    ) as Record<LegacyProfile, string[]>,
    usernsHint: usernsGapHint(),
  };
}

/** Is Ubuntu's own bwrap profile on this host (doctor wording)? */
export const distroBwrapProfilePresent = (): boolean => existsSync(DISTRO_BWRAP_PROFILE_FILE);

export function realSetupDeps(layout: Layout): SetupDeps {
  return {
    facts: realSetupFacts,
    profile: () => {
      const path = layout.asset(PROFILE_ASSET);
      return { path, text: readFileSync(path, "utf8") };
    },
    sudo: (argv) => spawnSync("sudo", argv, { stdio: "inherit" }).status ?? 1,
    confirm: (q) =>
      new Promise((res) => {
        const rl = createInterface({ input: process.stdin, output: process.stdout });
        rl.question(q, (a) => { rl.close(); res(/^y(es)?$/i.test(a.trim())); });
      }),
    isTTY: !!process.stdin.isTTY,
    out: (s) => { process.stdout.write(s); },
    err: (s) => { process.stderr.write(s); },
    clearProbeCache: () => clearProbeCacheFile(process.env),
  };
}
