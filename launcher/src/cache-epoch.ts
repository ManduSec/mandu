/**
 * cache-epoch — the launch's record with the arbiter, which decides when the
 * enforcement caches' seals are void (confidentiality-plan-14 §11.2, S2;
 * arbiter/policy/cache-seals.ts).
 *
 * The git-history caches under the Mandu home are trusted only through the
 * arbiter's seals, and the seals only for as long as no unconfined agent
 * could have written the home. So every launch tells the arbiter, before
 * its agent starts, what it is (`beginLaunch` on the human socket: the
 * launcher's pid, the mode, the secret posture, whether the home is
 * write-protected, and on macOS whether the one Seatbelt profile seals the
 * home), and says when it ends (`endLaunch`). The arbiter classifies it,
 * failing closed: an unconfined launch (`off`, `gated`, `read-blocked`
 * without the home sealed, write protection off, anything it does not
 * recognize) holds every seal void while it runs, and its end starts a new
 * epoch. A launcher that dies without `endLaunch` ends the period too: the
 * arbiter finds its pid gone.
 *
 * Fallback: an unconfined launch the arbiter could not record (no human
 * socket, a failed call) deletes the enforcement caches when it ends, so no
 * file its agent wrote there is read again. What that leaves (a confined
 * launch started while it runs) is recorded in plan 14 §11.2.
 *
 * The human plane (confidentiality plan 13 D9 leftovers, 2026-10-02): the
 * record also says whether the agent's world is walled off from the
 * human-plane socket (`humanPlaneWalled`). While an unwalled launch is live
 * the arbiter believes no guard or proxy record on that socket. So an
 * unwalled launch in a protecting mode that the arbiter could NOT record,
 * while the arbiter has a human socket, is refused unless --best-effort
 * (`unrecordedExposureRefusal`): unrecorded, its agent's programs would be
 * believed there. And a confined launch is told which unconfined launches
 * are live beside it (`beginLaunch`'s `others`): it warns, and refuses under
 * --require-confinement (`concurrentLaunchNotice`, plan 14 §11.2 residual
 * (a)).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 */
import { rmSync } from "node:fs";
import { manduPath } from "./generated/mandu-paths.js";

/** What a launch says about itself. */
export interface LaunchClaim {
  pid: number;
  /** The protection mode (mode.ts `modeOf`). */
  mode: string;
  /** The secret posture (confinement-posture.ts), or "off". */
  posture: string;
  /** The Mandu home is write-denied to the agent's tree (write-protect). */
  writeProtect: boolean;
  /** macOS only (posture `read-blocked`): the launch's one Seatbelt profile
   *  denies everything under it every direct read and write of the Mandu
   *  home (seatbelt-setup.ts `homeSealed`: every home a launch hides is
   *  read- and write-denied with no carve-out reaching an enforcement store,
   *  write-protected, the human plane walled off, the socket list and the
   *  six-program host-service deny on). The confidentiality.md §7.3
   *  residual remains, code a system service runs for the agent outside the
   *  profile, accepted for the caches (plan 14 §11.2 residual (e), §12).
   *  Set only by run.ts's darwin path, and only when true; the Linux launch
   *  never sends it. */
  homeSealed?: boolean;
  /** The agent's world cannot reach the human-plane socket
   *  (human-plane.ts `humanPlaneWalled`). */
  humanPlaneWalled?: boolean;
  /** The launch's session (its scope id), so the arbiter can name it while
   *  it holds the human plane exposed (display only, §10.1.1). */
  sessionId?: string;
  /** The launch's HOME (the one its secrets were found and registered
   *  under, and its agent's `$HOME`): the arbiter judges this session's
   *  opens against the catalog's `~` places of it as well as its own HOME
   *  (plan 10 §11.13, 2026-10-17). Recorded only on the human plane. */
  home?: string;
  /** The launch's workspace (its working directory), so a launch that finds
   *  the git-history caches void while this one runs unconfined can name it
   *  (display only, plan 14 §11.2.1). */
  workspace?: string;
}

/** Another unconfined launch live when this one began (the arbiter's answer). */
export interface OtherLaunch {
  pid: number;
  mode: string;
  posture: string;
  walled: boolean;
}

/** The launcher's own reading of the arbiter's rule (cache-seals.ts
 *  `launchConfinedForCaches`), used only to decide the fallback. Pure. */
export function launchConfinedLocally(claim: LaunchClaim): boolean {
  return (claim.mode === "secrets" || claim.mode === "full")
    && claim.writeProtect === true
    && (claim.posture === "confined" || (claim.posture === "read-blocked" && claim.homeSealed === true));
}

export interface LaunchRecord {
  /** `endLaunch`'s token, or null when the arbiter did not record the launch. */
  token: string | null;
  /** Confined for the caches' purpose (the arbiter's answer, else the
   *  launcher's own reading). */
  confined: boolean;
  /** Delete the enforcement caches at the end (an unconfined launch the
   *  arbiter did not record). */
  purgeAtEnd: boolean;
  /** The unconfined launches live before this one (empty when not recorded,
   *  or from an arbiter that does not say). */
  others: OtherLaunch[];
}

export interface CacheEpochDeps {
  /** One request on a socket (secret-setup.ts `ndjsonCall`). */
  call: (sock: string, op: string, args: Record<string, unknown>) => Promise<unknown>;
  log: (m: string) => void;
  /** Delete the enforcement caches (default: `purgeEnforcementCaches`). */
  purge: () => void;
}

/** Record the launch. Never throws: a failure falls back (see above). */
export async function beginLaunchRecord(humanSock: string | null | undefined, claim: LaunchClaim, deps: CacheEpochDeps): Promise<LaunchRecord> {
  const local = launchConfinedLocally(claim);
  const fallback = (why: string): LaunchRecord => {
    if (!local) {
      deps.log(
        `WARNING: mandu: the protection service could not record this unprotected launch (${why}); ` +
        "Mandu's git-history caches will be deleted when it ends",
      );
    }
    return { token: null, confined: local, purgeAtEnd: !local, others: [] };
  };
  if (!humanSock) return fallback("it reported no human socket");
  try {
    const r = (await deps.call(humanSock, "beginLaunch", { ...claim })) as { token?: unknown; confined?: unknown; others?: unknown } | null;
    if (r === null || typeof r !== "object" || typeof r.token !== "string" || r.token === "" || typeof r.confined !== "boolean") {
      return fallback("its answer is not {token, confined}");
    }
    return { token: r.token, confined: r.confined, purgeAtEnd: false, others: asOthers(r.others) };
  } catch (e) {
    return fallback((e as Error).message);
  }
}

function asOthers(v: unknown): OtherLaunch[] {
  if (!Array.isArray(v)) return [];
  const out: OtherLaunch[] = [];
  for (const o of v.slice(0, 64)) {
    if (o === null || typeof o !== "object") continue;
    const x = o as Record<string, unknown>;
    if (typeof x.pid !== "number") continue;
    out.push({ pid: x.pid, mode: String(x.mode ?? "unknown"), posture: String(x.posture ?? "unknown"), walled: x.walled === true });
  }
  return out;
}

/**
 * The refusal for an unwalled launch the arbiter did not record (plan 13 D9
 * leftovers), or null. Only where it matters: the arbiter has a human socket
 * (else there is no human plane to expose), the launch protects something
 * (`off` observes only: its residual is recorded in arbiter-human-plane.md
 * §8), and it is not walled. Under --best-effort a WARNING instead (`warn`).
 * Pure.
 */
export function unrecordedExposureRefusal(
  humanSock: string | null | undefined,
  claim: LaunchClaim,
  rec: LaunchRecord,
  strict: { bestEffort: boolean },
): { refuse: boolean; message: string } | null {
  if (!humanSock || rec.token !== null || claim.humanPlaneWalled === true || claim.mode === "off") return null;
  const why =
    "mandu: this launch's agent can reach Mandu's human-plane socket (no file guard and no mount layer here), " +
    "and the protection service could not record the launch, so it would keep believing the records that socket carries";
  return strict.bestEffort
    ? { refuse: false, message: `WARNING: ${why} (--best-effort).` }
    : { refuse: true, message: `${why}. Refusing to launch: fix the protection service (mandu doctor), or re-run with --best-effort, or turn secret protection off for this launch: --mode off.` };
}

/**
 * What a CONFINED launch says about the unconfined launches live beside it
 * (plan 14 §11.2 residual (a), plan 13 D9 leftovers). Each can rewrite this
 * launch's placeholder files in place; an unwalled one also reaches Mandu's
 * records and the human-plane socket, so while it runs this launch's guard
 * reports are not believed (secret opens get placeholders, protected writes
 * are refused): that part is the human-plane watch's to say
 * (human-plane-watch.ts), which also follows launches begun later. Lines to
 * print (empty when none); `refuse` under --require-confinement. Pure.
 */
export function concurrentLaunchNotice(
  posture: string,
  others: readonly OtherLaunch[],
  strict: { requireConfinement: boolean },
): { lines: string[]; refuse: boolean } {
  if (posture !== "confined" || others.length === 0) return { lines: [], refuse: false };
  const list = others.slice(0, 5).map((o) => `pid ${o.pid} (${o.mode}, ${o.posture}${o.walled ? "" : ", can reach Mandu's state"})`).join("; ");
  // An unwalled one also holds this launch's guard unbelieved: the human
  // plane watch says so, with the launch's session and the fix, and again
  // whenever that changes (human-plane-watch.ts, §10.1.1).
  const lines = [
    `WARNING: mandu: ${others.length} other Mandu launch${others.length === 1 ? " runs" : "es run"} without confinement beside this one: ${list}.`,
    "  Until it ends, its programs can rewrite this launch's placeholder files.",
  ];
  if (strict.requireConfinement) {
    lines.push("  Refusing to launch (--require-confinement): end the other launch first.");
  }
  return { lines, refuse: strict.requireConfinement };
}

/** The launch ended. Never throws. */
export async function endLaunchRecord(humanSock: string | null | undefined, rec: LaunchRecord, deps: CacheEpochDeps): Promise<void> {
  if (rec.token !== null && humanSock) {
    try {
      await deps.call(humanSock, "endLaunch", { token: rec.token });
    } catch {
      // The arbiter ends the period itself once this launcher's pid is gone.
    }
  }
  if (rec.purgeAtEnd) {
    try {
      // Said at the start (beginLaunchRecord's WARNING); quiet when done.
      deps.purge();
    } catch (e) {
      deps.log(`WARNING: mandu: could not delete Mandu's git-history caches (${(e as Error).message}); delete cache/object-twins and state/object-walks under Mandu's home before the next launch`);
    }
  }
}

/** Delete the enforcement caches: the sanitized packs and the walks (the
 *  history-scan cache lives inside the walks). Regenerable (on-disk-layout.md). */
export function purgeEnforcementCaches(env: NodeJS.ProcessEnv, home: string): void {
  for (const name of ["object-twins", "object-walks"] as const) {
    rmSync(manduPath(name, env, home), { recursive: true, force: true });
  }
}
