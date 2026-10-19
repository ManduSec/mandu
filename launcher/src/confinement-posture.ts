/**
 * confinement-posture — the ONE vocabulary for how well secrets are kept from
 * the agent's world on this host (docs/design/confidentiality/rootless-confinement-ubuntu-2404.md
 * §2; confidentiality.md §10.1). The launch notice, `mandu doctor`, the
 * `launch_posture` event and the dashboard chip all read the names and the
 * honest sentences from here, so they cannot drift apart.
 *
 *   confined      raw secret bytes are ABSENT from the agent's world (Linux:
 *                 the whole-agent guard serving the twins by descriptor, with
 *                 the bwrap bind mount as a second layer where the host can
 *                 mount it; `bindGap` says when it cannot). Since
 *                 2026-09-28 (sandbox-security-review finding 7) confined
 *                 REQUIRES the guard: the bind alone misses a secret file the
 *                 host replaces while the agent runs.
 *   read-blocked  secret files are UNREADABLE to the agent tree; a read fails
 *                 instead of returning a symbol (macOS: the whole-agent Seatbelt
 *                 profile, seatbelt-profile.ts, which also keeps the files and
 *                 their folders from being renamed, seals Mandu's own state,
 *                 and carries the write-protect, network and Unix-socket
 *                 rules; the rootless Linux Landlock variant is a spike, §5).
 *                 No reader is ever handed the real file there, so a launch
 *                 names no pinned readers.
 *   gated         neither. Track A only: model-context masking + egress gates.
 *                 A subprocess CAN read raw secret files. On a host whose
 *                 bwrap can mount but with no guard around the launch (gap
 *                 `no-guard` / `guard-off`) the bind still goes up as a
 *                 partial layer; see `bindOnlyLines` for what it covers.
 *
 * PURE: every host fact is an input, so the whole decision table is unit-tested
 * with no privilege. The `gated` posture must never borrow the `confined` claim.
 *
 * Mandu-new (no reference origin).
 */

export type ConfinementPosture = "confined" | "read-blocked" | "gated";

export const POSTURES: readonly ConfinementPosture[] = ["confined", "read-blocked", "gated"];

/** One honest sentence per posture; shown wherever the posture name is. */
export const POSTURE_SENTENCE: Record<ConfinementPosture, string> = {
  "confined": "Programs the AI runs get a placeholder copy of each credential file, never the real one. A program you allow to read a file gets the real contents, and what it prints is masked before the AI sees it.",
  "read-blocked": "Programs the AI runs cannot open your credential files: a read fails instead of returning a placeholder.",
  "gated": "The AI sees placeholders and a secret is sent out only where a rule or your OK allows, but programs the AI runs can still read your credential files.",
};

/** The one-command upgrade (§3.2). Run WITHOUT sudo: it explains, then asks
 *  for sudo itself for the one install step (`sudo mandu` commonly fails
 *  anyway: root's PATH lacks an nvm / npm-global `mandu`). */
export const SETUP_COMMAND = "mandu setup";

/** Why confinement cannot be established on this host, as a stable code. */
export type HostGap =
  | "apparmor-userns"   // Ubuntu >= 23.10: bwrap carries no `userns` AppArmor grant — `mandu setup` fixes it
  | "userns-off"        // another kernel knob / container policy denies the namespace
  | "no-bwrap"          // bubblewrap is not installed
  | "bwrap-nesting"     // the bind wrap would stop every sandbox the agent's tools start (Ubuntu 26.04's bwrap profile) — `mandu setup` fixes it
  | "no-sandbox-exec"   // macOS without sandbox-exec
  | "unsupported-os"    // Windows
  // The two below leave the bind mount up as a partial layer (bind-only):
  | "no-guard"          // the whole-agent guard (mandu-net-guard) is unavailable: no binary for this host
  | "guard-off";        // the user turned the guard off (--no-net-guard, MANDU_NET_GUARD=0, net-guard = false, --no-kernel)

/** Every HostGap, for the vocabulary parity tests (the dashboard mirrors the
 *  fixes). A Record so a new code that is not listed fails to compile. */
const GAP_SET: Record<HostGap, true> = {
  "apparmor-userns": true, "userns-off": true, "no-bwrap": true, "bwrap-nesting": true,
  "no-sandbox-exec": true, "unsupported-os": true, "no-guard": true, "guard-off": true,
};
export const HOST_GAPS: readonly HostGap[] = Object.keys(GAP_SET) as HostGap[];

/** The gaps under which the bind mount still goes up (a partial layer): the
 *  host can mount, but no guard is around the launch. */
export function isBindOnlyGap(gap: HostGap | string | undefined): gap is "no-guard" | "guard-off" {
  return gap === "no-guard" || gap === "guard-off";
}

export interface HostFacts {
  platform: "linux" | "darwin" | "win32";
  /** `bwrap` on PATH (Linux). */
  bwrap: boolean;
  /** The userns probe passed (Linux; src/userns.ts `probeUserns`). */
  userns: boolean;
  /** kernel.apparmor_restrict_unprivileged_userns reads 1 (Linux). */
  apparmorRestricted: boolean;
  /** `/usr/bin/sandbox-exec` is there (macOS; checked by that path, never a
   *  PATH lookup: seatbelt-profile.ts `sandboxExecAvailable`). */
  sandboxExec: boolean;
  /** A rootless Landlock `read-blocked` backend is built AND the kernel
   *  supports it. Always false today: the backend is a spike (§5), so a
   *  Landlock-capable Linux host without userns still resolves to `gated`. */
  landlockReadBlock: boolean;
  /** The whole-agent guard (`mandu-net-guard`) is available on this Linux
   *  host: it traps `open()` and serves every registered secret by descriptor
   *  (plan 10 §11.7 / §8 phase 6), so no user namespace is needed to confine.
   *  Absent/false = the pre-phase-6 table. */
  guard?: boolean;
  /** The user turned the guard off for launches (--no-net-guard,
   *  MANDU_NET_GUARD=0, `net-guard = false`, --no-kernel): names the gap
   *  `guard-off` instead of `no-guard`. Only read when `guard` is not true. */
  guardOff?: boolean;
  /** A sandbox can start INSIDE the bind wrap (secret-twins.ts
   *  `nestedSandboxProbeArgv`). false on Ubuntu 26.04, whose bwrap profile
   *  bars a user namespace to everything a bwrap sandbox runs: the bind would
   *  break Codex's shell and Mandu's exec box. Absent = not probed (as true). */
  nesting?: boolean;
}

export interface HostPosture {
  posture: ConfinementPosture;
  /** Set iff the host cannot reach its platform's best posture. */
  gap?: HostGap;
  /** `confined` by the guard ALONE: the bind-mount layer is unavailable for
   *  this reason. Not a gap in the guarantee (raw bytes are still absent from
   *  the agent's world); `mandu setup` adds the bind as a second layer. */
  bindGap?: HostGap;
}

/** The posture a launch on this host would get. Pure. */
export function resolveHostPosture(f: HostFacts): HostPosture {
  if (f.platform === "win32") return { posture: "gated", gap: "unsupported-os" };
  if (f.platform === "darwin") {
    return f.sandboxExec ? { posture: "read-blocked" } : { posture: "gated", gap: "no-sandbox-exec" };
  }
  if (f.bwrap && f.userns) {
    // Bind-only (sandbox-security-review-2026-09-28 finding 7): without the
    // guard a secret file the HOST replaces while the agent runs (a token
    // refresh, an editor save) detaches the twin bind and the new real file
    // is readable; only the guard's by-path open catches that. So the bind
    // alone is `gated`, and the bind still goes up as a partial layer.
    if (f.guard !== true) return { posture: "gated", gap: f.guardOff === true ? "guard-off" : "no-guard" };
    // The bind can mount but would stop nested sandboxes: with the guard the
    // twins go out by descriptor and the bind stays off (§14.1 item 6).
    if (f.nesting === false) return { posture: "confined", bindGap: "bwrap-nesting" };
    return { posture: "confined" };
  }
  const gap: HostGap = !f.bwrap ? "no-bwrap" : f.apparmorRestricted ? "apparmor-userns" : "userns-off";
  // Phase 6 (plan 10 §11.7): the guard serves the twins by descriptor, so a
  // host that cannot mount the bind is still confined. The bind stays a
  // second layer where it CAN mount (belt and braces; the maintainer's
  // decision after the 2026-09-24 soak, plan 10 §8 phase 6).
  if (f.guard === true) return { posture: "confined", bindGap: gap };
  return { posture: f.landlockReadBlock ? "read-blocked" : "gated", gap };
}

/** The doctor lines under a `confined`-by-the-guard posture: what the bind
 *  layer would add and how to get it. Empty for a bind-backed posture. */
export function guardOnlyLines(p: HostPosture): string[] {
  if (p.posture !== "confined" || p.bindGap === undefined) return [];
  const { cause, fix } = gapExplanation(p.bindGap);
  const lines = [
    "protected by Mandu's file guard alone (it hands every program the placeholder copies); the extra mount layer is not in use",
    // bwrap-nesting: the mount COULD go up, and is left off on purpose.
    `mount layer ${p.bindGap === "bwrap-nesting" ? "off" : "unavailable"}: ${cause}`,
  ];
  if (fix !== null) {
    lines.push(`optional second layer: ${fix}${fix === SETUP_COMMAND ? "   (adds the mount layer; asks for sudo once)" : ""}`);
  }
  return lines;
}

/** The doctor lines under a bind-only `gated` posture (no guard): what the
 *  mount layer still covers and what it does not. Empty otherwise. */
export function bindOnlyLines(p: HostPosture): string[] {
  if (p.posture !== "gated" || !isBindOnlyGap(p.gap)) return [];
  return [
    "partial layer in use: the mount layer puts a placeholder copy over each credential file found at launch",
    "not covered without the file guard: a credential file replaced while the AI runs (a token refresh, an editor save) is readable, and no program can be allowed to read the real file",
  ];
}

/** Cause line + fix command for a gap, in plain words. */
export function gapExplanation(gap: HostGap): { cause: string; fix: string | null } {
  switch (gap) {
    case "apparmor-userns":
      return { cause: "Ubuntu restricts unprivileged user namespaces (AppArmor).", fix: SETUP_COMMAND };
    case "userns-off":
      return { cause: "This host does not allow unprivileged user namespaces.", fix: null };
    case "no-bwrap":
      // Mandu runs the distribution's bubblewrap and ships none
      // (rootless-confinement-ubuntu-2404.md §0.7, decision A).
      return {
        cause: "bubblewrap (`bwrap`) is not installed (Mandu uses your distribution's, never one inside the working directory). " +
          "Fedora: sudo dnf install bubblewrap. Ubuntu 24.04 and later: after installing it, mandu setup adds the AppArmor grant.",
        fix: "sudo apt install bubblewrap",
      };
    case "bwrap-nesting":
      return {
        cause: "this host's bubblewrap AppArmor profile lets no sandbox start inside another, and the mount layer would stop the sandboxes the agent's tools start (Codex's shell, Mandu's command box).",
        // Mandu's own bubblewrap lets a sandbox nest (bwrap-grant.ts).
        fix: SETUP_COMMAND,
      };
    case "no-sandbox-exec":
      return { cause: "`/usr/bin/sandbox-exec` is unavailable on this Mac.", fix: null };
    case "unsupported-os":
      return { cause: "Secret confinement is not implemented for Windows.", fix: null };
    case "no-guard":
      return {
        cause: "Mandu's file guard (mandu-net-guard) is not available here (no binary for this machine; a source checkout builds it with scripts/build-native.sh), so a credential file replaced while the AI runs (a token refresh, an editor save) is readable.",
        fix: null,
      };
    case "guard-off":
      return {
        cause: "Mandu's file guard is turned off (--no-net-guard, MANDU_NET_GUARD=0, net-guard = false in config.toml, or --no-kernel), so a credential file replaced while the AI runs (a token refresh, an editor save) is readable. Drop the opt-out to confine.",
        fix: null,
      };
  }
}

/**
 * The multi-line stderr notice for a launch that is not `confined`/`read-blocked`
 * by host condition. First line carries the posture name; stable text (the
 * banner's attention rule and the posture oracles match on "secrets are GATED").
 */
export function gatedNotice(gap: HostGap): string[] {
  const { cause, fix } = gapExplanation(gap);
  const lines = [
    "mandu: secrets are GATED, not confined, on this host.",
    `  ${cause}`,
    isBindOnlyGap(gap)
      ? "  A mount layer still puts a placeholder over each credential file found at launch; a file replaced while the agent runs is not covered."
      : "  Programs the agent runs can still read your credential files.",
  ];
  if (fix !== null) lines.push(`  One-time upgrade:  ${fix}${fix === SETUP_COMMAND ? "   (asks for sudo once)" : ""}`);
  lines.push("  Details:           mandu doctor");
  return lines;
}

/** What went wrong: the host cannot confine (a known condition), or the
 *  arbiter failed mid-setup (an incident). */
export type ConfinementFailure = "host" | "arbiter";

export interface StrictnessOpts {
  /** --require-confinement / MANDU_REQUIRE_CONFINEMENT / config. */
  requireConfinement: boolean;
  /** --best-effort. */
  bestEffort: boolean;
}

/**
 * Refuse the launch, or degrade to `gated`? (§3.1)
 *   - require-confinement always refuses (it wins over --best-effort: a managed
 *     deployment's config must not be undone by a flag meant for dev boxes).
 *   - a HOST gap degrades by default: root stays optional.
 *   - an ARBITER failure is an incident, not a host condition: it refuses
 *     unless --best-effort, exactly as before.
 */
export function onConfinementFailure(kind: ConfinementFailure, o: StrictnessOpts): "refuse" | "degrade" {
  if (o.requireConfinement) return "refuse";
  if (kind === "host") return "degrade";
  return o.bestEffort ? "degrade" : "refuse";
}
