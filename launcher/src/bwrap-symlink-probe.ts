/**
 * bwrap-symlink-probe: does the bubblewrap Mandu runs follow a symlink in a
 * mount DESTINATION while it sets up a sandbox (CVE-2026-87766)?
 *
 * bubblewrap < 0.12.0 resolves a mount destination through symlinks; the fix
 * creates and resolves destinations without following them and REJECTS a
 * mount onto a symlink destination ("Can't mount on symlink destination").
 * A version floor is wrong both ways: Ubuntu backported the fix in 24.04's
 * 0.9.0-1ubuntu0.2 and dropped it again in 0.9.0-1ubuntu0.3 (a Flatpak
 * regression, LP #2167621), so the version string says nothing. This module
 * asks the binary instead: one bwrap run in a fresh temp dir, binding a
 * directory onto `link -> real` and checking from inside whether the bind
 * landed on `real`.
 *
 * WARN ONLY (the maintainer's decision, sandbox-security-review-2026-09-28
 * finding 14): the result never refuses a launch and never changes the
 * posture. The assessment (docs/guarantees.md): the command box gains nothing
 * (its writable mounts are a private /tmp and the AgentView, which the agent
 * can already write; its base is `--ro-bind / /`); the whole-agent wrap is
 * built once at launch over `--dev-bind / /`, and a process of the same user
 * already running can race the launcher's realpath check and swap a
 * secret's parent directory for a symlink, so the twin lands elsewhere and
 * the real file stays visible (caught by the guard's by-path lookup, exposed
 * only bind-only, which finding 7 now calls `gated`).
 *
 * The classifier is PURE and conservative: only "bwrap accepted the symlink
 * destination and the bind landed on its target" is `vulnerable`; a refusal
 * naming the symlink is `fixed`; anything else (no user namespace, no bwrap,
 * an unexpected outcome) is `unknown`.
 *
 * THE VERSION, SECOND (2026-10-07, before 0.2.0). The behavior decides; the
 * version string (`bwrap --version`, read only when the behavior did not say
 * `fixed`, so a fixed host spawns nothing more) only adds to it: a
 * `vulnerable` answer names the version, and an `unknown` answer from a
 * bubblewrap older than 0.12.0 becomes `version-affected` (warned, worded as
 * "could not be checked; a distro build may carry the fix"): a user must be
 * told when the bwrap Mandu runs is likely affected even where the sandbox
 * start could not be tried. `unknown` from 0.12.0 or newer, or with no
 * readable version, still says nothing.
 *
 * Mandu-new (no reference origin).
 */
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { bwrapVersion, MANDU_BWRAP } from "./bwrap-grant.js";

export type SymlinkProbeVerdict = "vulnerable" | "fixed" | "unknown" | "version-affected";

export interface SymlinkProbeResult {
  verdict: SymlinkProbeVerdict;
  /** The bwrap that was asked (Mandu's own copy or `bwrap`). */
  bwrap: string;
  /** Why `unknown` / `version-affected`: bwrap's own error line, or what
   *  was unexpected. */
  detail?: string;
  /** The upstream version `bwrap --version` printed ("0.11.1"); absent when
   *  it was not read (a `fixed` answer) or not readable. */
  version?: string;
}

/** The first upstream release with the fix (NEWS 0.12.0, commit c77dd38,
 *  GHSA-pxhw-h44j-8pfx). */
export const CVE_FIXED_IN = "0.12.0";

/** "bubblewrap 0.11.1" (or a bare "0.11.1") -> "0.11.1"; null otherwise. Pure. */
export function parseBwrapVersion(line: string | null | undefined): string | null {
  const m = /^(?:bubblewrap\s+)?v?(\d+)\.(\d+)(?:\.(\d+))?\b/.exec((line ?? "").trim());
  return m === null ? null : `${m[1]}.${m[2]}.${m[3] ?? "0"}`;
}

/** Is `version` older than CVE_FIXED_IN? null for an unparsable one. Pure. */
export function olderThanFix(version: string): boolean | null {
  const v = parseBwrapVersion(version);
  if (v === null) return null;
  const a = v.split(".").map(Number);
  const b = CVE_FIXED_IN.split(".").map(Number);
  for (let i = 0; i < 3; i++) if (a[i]! !== b[i]!) return a[i]! < b[i]!;
  return false;
}

/** Combine the behavior with the version line (null: not readable). The
 *  behavior wins wherever it answered; the version only names itself, or
 *  turns an `unknown` from a pre-0.12.0 bubblewrap into `version-affected`.
 *  Pure. */
export function withVersion(
  behavior: { verdict: SymlinkProbeVerdict; detail?: string },
  versionLine: string | null,
): { verdict: SymlinkProbeVerdict; detail?: string; version?: string } {
  const version = parseBwrapVersion(versionLine);
  if (version === null || behavior.verdict === "fixed") return behavior;
  if (behavior.verdict === "unknown" && olderThanFix(version) === true) return { ...behavior, verdict: "version-affected", version };
  return { ...behavior, version };
}

/** The marker the bind source carries, looked for through the link target. */
export const PROBE_MARKER = "mandu-symlink-probe";

/**
 * The probe argv (after the bwrap binary): bind `src` onto `<dir>/link`
 * (a symlink to `<dir>/real`), then, inside, test whether the marker shows up
 * under `<dir>/real`. A fixed bwrap refuses the mount; an unpatched one
 * follows the link and the test succeeds. `--dev-bind / /` is the base the
 * whole-agent wrap uses (secret-twins.ts).
 */
export function symlinkProbeArgv(dir: string): string[] {
  return ["--dev-bind", "/", "/", "--bind", join(dir, "src"), join(dir, "link"), "--", "test", "-e", join(dir, "real", PROBE_MARKER)];
}

/** Classify one probe run. Pure. `status` null = killed / did not start. */
export function classifySymlinkProbe(r: { status: number | null; stderr: string; error?: boolean }): { verdict: SymlinkProbeVerdict; detail?: string } {
  const err = r.stderr.trim();
  const bwrapLine = err.split("\n").find((l) => l.startsWith("bwrap:"));
  if (r.error === true || r.status === null) return { verdict: "unknown", detail: bwrapLine ?? "bwrap did not run" };
  // Accepted, and the marker is visible through the link's target: the bind
  // followed the symlink.
  if (r.status === 0 && bwrapLine === undefined) return { verdict: "vulnerable" };
  // The fix's refusal ("Can't mount on symlink destination <path>").
  if (bwrapLine !== undefined && /symlink/i.test(bwrapLine)) return { verdict: "fixed" };
  // bwrap could not run at all (no user namespace, AppArmor, …), or it
  // accepted the mount without following the link: nothing to warn about.
  return { verdict: "unknown", detail: bwrapLine ?? `exit ${r.status}${err ? `: ${err.split("\n")[0]}` : ""}` };
}

export interface SymlinkProbeDeps {
  /** Run bwrap; default spawnSync with a short timeout. */
  run?: (bin: string, args: string[]) => { status: number | null; stderr: string; error?: boolean };
  /** Parent for the temp dir; default os.tmpdir(). */
  tmpRoot?: string;
  /** `bwrap --version`'s first line, or null; default bwrap-grant.ts
   *  `bwrapVersion`. Asked only when the behavior did not say `fixed`. */
  version?: (bin: string) => string | null;
}

const defaultRun = (bin: string, args: string[]): { status: number | null; stderr: string; error?: boolean } => {
  const r = spawnSync(bin, args, { encoding: "utf8", timeout: 5_000, stdio: ["ignore", "ignore", "pipe"] });
  return { status: r.status, stderr: r.stderr ?? "", ...(r.error ? { error: true } : {}) };
};

/** Run the probe with `bwrap` (resolveWrapBwrap's answer). One bwrap run,
 *  about 20 ms, plus one `bwrap --version` (a few ms) only when that run did
 *  not say `fixed`; the temp dir is removed again. Never throws. */
export function probeBwrapSymlink(bwrap: string, deps: SymlinkProbeDeps = {}): SymlinkProbeResult {
  let dir: string | null = null;
  try {
    dir = mkdtempSync(join(deps.tmpRoot ?? tmpdir(), "mandu-bwrap-probe-"));
    mkdirSync(join(dir, "real"));
    mkdirSync(join(dir, "src"));
    writeFileSync(join(dir, "src", PROBE_MARKER), "");
    symlinkSync("real", join(dir, "link"));
    const c = classifySymlinkProbe((deps.run ?? defaultRun)(bwrap, symlinkProbeArgv(dir)));
    if (c.verdict === "fixed") return { bwrap, ...c };
    let line: string | null = null;
    try { line = (deps.version ?? bwrapVersion)(bwrap); } catch { /* no version: the behavior alone */ }
    return { bwrap, ...withVersion(c, line) };
  } catch (e) {
    return { bwrap, verdict: "unknown", detail: (e as Error).message };
  } finally {
    if (dir !== null) try { rmSync(dir, { recursive: true, force: true }); } catch { /* best-effort */ }
  }
}

/** The plain-words cause and fix, shared by the doctor row and the launch
 *  warning. */
export const SYMLINK_CVE_CAUSE =
  "bubblewrap on this host follows symlinks while it sets up a sandbox (CVE-2026-87766)";
export const SYMLINK_CVE_FIX =
  "a bubblewrap with the fix: upgrade the distro package when it ships one " +
  "(Debian, Ubuntu: sudo apt update && sudo apt install --only-upgrade bubblewrap; Fedora: sudo dnf upgrade bubblewrap), " +
  `or bubblewrap ${CVE_FIXED_IN} or newer (an administrator can point Mandu at one with bwrap_path in /etc/mandu/policy.d)`;
/** The closing step of every fix: the version number is not proof. */
export const SYMLINK_CVE_CHECK = "then run mandu doctor, which tests the build itself (a version number is not proof)";

/** The fix for the bwrap that was asked. Mandu's own copy (bwrap-grant.ts) is
 *  a copy of the system one that `mandu setup` made, so upgrading the package
 *  alone leaves the copy as it was. */
export function symlinkCveFix(bwrap: string): string {
  return bwrap === MANDU_BWRAP
    ? `${SYMLINK_CVE_FIX}; then run mandu setup, which refreshes Mandu's own copy (${MANDU_BWRAP}) from it; ${SYMLINK_CVE_CHECK}`
    : `${SYMLINK_CVE_FIX}; ${SYMLINK_CVE_CHECK}`;
}

/** "bwrap" or "bwrap, version 0.11.1": the binary asked, and its version. */
function asked(r: SymlinkProbeResult): string {
  return r.version !== undefined ? `${r.bwrap}, version ${r.version}` : r.bwrap;
}

/** What to check when only the version spoke: the version cannot settle it
 *  either way (rootless-confinement-ubuntu-2404.md §13). */
export const VERSION_NOT_PROOF =
  "the version number does not settle it: distributions backport the fix without changing it, and have dropped a backport " +
  "again (Ubuntu shipped the fix in 0.9.0-1ubuntu0.2 and 0.11.1-1ubuntu0.2, and removed it in the ubuntu0.3 update of each). " +
  "Check the installed build instead: its changelog must list CVE-2026-87766 " +
  "(Debian, Ubuntu: apt changelog bubblewrap; Fedora: rpm -q --changelog bubblewrap), " +
  "or let Mandu test it by running mandu doctor where bubblewrap can create a user namespace";

/** The pre-0.12.0 sentence for a build the probe could not check. */
function versionAffectedCause(r: SymlinkProbeResult): string {
  return `bubblewrap ${r.version ?? "(version unknown)"} (${r.bwrap}) reports a version older than ${CVE_FIXED_IN}, the first upstream ` +
    `release with the fix for CVE-2026-87766 (it follows symlinks while it sets up a sandbox), and Mandu could not test this build itself` +
    `${r.detail ? ` (${r.detail})` : ""}, so it may be affected; ${VERSION_NOT_PROOF}`;
}

/** The doctor row for a probe result (indented like the rows around it).
 *  null for `unknown`: a probe that could not run, on a bubblewrap not known
 *  to be older than the fix, says nothing. */
export function symlinkProbeRow(r: SymlinkProbeResult | undefined): string | null {
  if (r === undefined || r.verdict === "unknown") return null;
  if (r.verdict === "fixed") return `  ✓ bubblewrap (${r.bwrap}) refuses to mount onto a symlink (fixed for CVE-2026-87766)`;
  const consequence = "a program already running as you could redirect the mount layer while a launch sets it up; " +
    "Mandu's file guard, where it runs, still hands out the placeholders by path. A warning only: the launch goes ahead.";
  const cause = r.verdict === "version-affected" ? versionAffectedCause(r) : `${SYMLINK_CVE_CAUSE} (${asked(r)})`;
  return `  ✗ ${cause}: ${consequence} fix: ${symlinkCveFix(r.bwrap)}`;
}

/** The one launch WARNING line, or null. */
export function symlinkProbeWarning(r: SymlinkProbeResult): string | null {
  if (r.verdict !== "vulnerable" && r.verdict !== "version-affected") return null;
  const cause = r.verdict === "version-affected" ? versionAffectedCause(r) : `${SYMLINK_CVE_CAUSE} (${asked(r)})`;
  return `WARNING: mandu: ${cause}; the mount layer is still used. Fix: ${symlinkCveFix(r.bwrap)}. Details: mandu doctor`;
}
