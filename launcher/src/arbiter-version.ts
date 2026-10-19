/**
 * arbiter-version — a launch never uses an arbiter of another Mandu release
 * (runtime-instances.md §4.1; reply-row-reservation.md §18.6).
 *
 * The resident stack (the dashboard supervisor and its arbiter) outlives the
 * launcher on purpose (§8), so after an upgrade the next `mandu` finds the
 * OLD arbiter on the `current` rendezvous. Before this check it attached
 * silently: an op the new launcher or its children need could be missing, or
 * refused (the S8 miss was one such skew, between two commits), and the
 * security fixes of the new release would not be in force where the decisions
 * are made.
 *
 * The arbiter's `hello` reports `version`, the release its code belongs to
 * (arbiter/ipc/release-version.ts). The launcher compares it with its own
 * (`launcherVersion`) once the socket is there, before any session-keyed op:
 *
 *   - same release, or nothing to compare (no answer; an answer that is not a
 *     Mandu arbiter's identity, which every real one carries with
 *     `protocolVersion`; a launcher that cannot read its own release) → proceed. A mute arbiter is no evidence of a skew,
 *     and every op the launch then needs fails closed on its own.
 *   - another release (or a real arbiter that reports none: a release from
 *     before this check) →
 *       · the arbiter this launch itself just started: refuse (a mixed install,
 *         or another release's launch won the start);
 *       · a pinned socket (MANDU_ARBITER_SOCK): refuse; the caller owns it;
 *       · the account's resident stack, NEWER than this mandu: refuse (never a
 *         downgrade by accident; two installs would restart each other);
 *       · the resident stack, older (or not comparable), while another `mandu`
 *         session uses it: refuse, naming `mandu stop --stack <dir>`;
 *       · the resident stack, older, no other session: stop it, start this
 *         release's, and check again (the restarted one must match).
 *   - this release, but ANOTHER BUILD of it (hello's `build`, arbiter/ipc/
 *     build-identity.ts: two commits of one version, the S8 miss) → handled
 *     like "older" (a build has no order, so there is no "newer"): refused
 *     when this launch started it, when pinned, or when another session uses
 *     the stack; an unused resident stack is replaced by this build. Each
 *     message names both builds. "Same build" is `compareBuilds`: two bundles
 *     by their hash; else two checkout revs, the same when their `arbiter/`
 *     trees are; else (an install's bundle against a checkout's source) not
 *     the same. Either side reporting no build is no evidence: version only.
 *   - a resident stack of another release or build that a systemd service
 *     runs with `Restart=` (stack-supervisor.ts, §4.1a) is never restarted:
 *     the service would start the old code again. The launch refuses, naming
 *     the unit and `systemctl [--user] disable --now <unit>`, and every
 *     refusal's "stop it" names that command instead of `mandu stop`.
 *
 * Pure decisions (`versionVerdict`, `compareBuilds`, `skewAction`) + two
 * drivers over injected effects: `checkArbiterRelease` (one check) and
 * `enforceRelease` (the check, the restart, and the gate that keeps two
 * racing launches from refusing each other, release-gate.ts).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { ArbiterSockMode } from "./arbiter-sock.js";
import { describeSupervisor, disableCommand, OWN_STACK_NOTE, ownStackCommand, type StackSupervisor } from "./stack-supervisor.js";
import { compareVersions, parseVersion } from "./update-check.js";

/** Which build of a release an arbiter's code is (hello `build`; mirrors
 *  arbiter/ipc/build-identity.ts). `bundle`: SHA-256 prefix of the bundle
 *  file; `rev`: short git rev of the checkout the code came from. */
export interface BuildIdentity {
  bundle: string | null;
  rev: string | null;
}

/** A hex digest or rev as the wire may carry it (a foreign claim: it later
 *  reaches a git argv, so nothing else passes). */
const HEXISH = /^[0-9a-f]{4,64}$/;

/** The `build` a hello reports, or null when it reports none (an arbiter
 *  from before 2026-10-17, an embedded test server) or nothing usable. */
export function parseBuild(hello: unknown): BuildIdentity | null {
  if (!hello || typeof hello !== "object") return null;
  const b = (hello as Record<string, unknown>)["build"];
  if (!b || typeof b !== "object") return null;
  const field = (k: string): string | null => {
    const v = (b as Record<string, unknown>)[k];
    return typeof v === "string" && HEXISH.test(v) ? v : null;
  };
  const out = { bundle: field("bundle"), rev: field("rev") };
  return out.bundle === null && out.rev === null ? null : out;
}

/** "bundle 3f2a91c0d4e5b6a7, rev abc1234", for the messages. */
export function describeBuild(b: BuildIdentity): string {
  const parts: string[] = [];
  if (b.bundle) parts.push(`bundle ${b.bundle}`);
  if (b.rev) parts.push(`rev ${b.rev}`);
  return parts.join(", ") || "an unknown build";
}

/**
 * Are two builds of one release the same code? Pure but for the injected
 * `sameArbiterTree` (the launcher's checkout: do two revs hold one
 * `arbiter/` tree; null when it cannot say).
 *   - either side reports nothing → "unknown" (no evidence; version only);
 *   - both run a bundle → the hashes decide (esbuild's output is a function
 *     of its inputs, so a commit that did not touch the arbiter's code builds
 *     the same bytes);
 *   - both carry a checkout rev → the same rev, or two revs whose `arbiter/`
 *     trees are identical (scope-honest, as the dashboard's STALE flag,
 *     runtime-instances.md §4); a rev this checkout cannot resolve is not;
 *   - otherwise (an install's bundle against a checkout's source) → not the
 *     same: they come from two different places.
 */
export function compareBuilds(
  ours: BuildIdentity | null,
  theirs: BuildIdentity | null,
  sameArbiterTree: (a: string, b: string) => boolean | null = () => null,
): "same" | "different" | "unknown" {
  if (ours === null || theirs === null) return "unknown";
  if (ours.bundle === null && ours.rev === null) return "unknown";
  if (theirs.bundle === null && theirs.rev === null) return "unknown";
  if (ours.bundle !== null && theirs.bundle !== null) return ours.bundle === theirs.bundle ? "same" : "different";
  if (ours.rev !== null && theirs.rev !== null) {
    if (ours.rev === theirs.rev) return "same";
    return sameArbiterTree(theirs.rev, ours.rev) === true ? "same" : "different";
  }
  return "different";
}

/** The build the arbiter this launcher starts would report: the hash of the
 *  bundle it spawns (`<pkgRoot>/dist/arbiter.mjs`) when it runs bundles, and
 *  the checkout's rev in a dev layout (source or a checkout's own build); an
 *  install has no rev. Null when neither is known. */
export function ownArbiterBuild(
  layout: { mode: "dev" | "installed"; bundled: boolean; pkgRoot: string; repoRoot: string },
  deps: { readFile?: (p: string) => Uint8Array; revOf: (dir: string) => string },
): BuildIdentity | null {
  let bundle: string | null = null;
  if (layout.bundled) {
    try {
      bundle = createHash("sha256").update((deps.readFile ?? readFileSync)(join(layout.pkgRoot, "dist", "arbiter.mjs"))).digest("hex").slice(0, 16);
    } catch {
      bundle = null;
    }
  }
  let rev: string | null = null;
  if (layout.mode === "dev") {
    const r = deps.revOf(layout.repoRoot);
    rev = r && r !== "nogit" ? r : null;
  }
  return bundle === null && rev === null ? null : { bundle, rev };
}

/** What the arbiter's hello says about its release, against ours. */
export type VersionVerdict =
  | { kind: "match"; theirs: string }
  /** Nothing to compare: no answer, a refusal, or not a Mandu identity. */
  | { kind: "unknown" }
  /** Another release. `theirs` null = a real arbiter that reports none (a
   *  release from before the check, hence older). `other` = not comparable. */
  | { kind: "older" | "newer" | "other"; theirs: string | null }
  /** This release, another build of it (two commits of one version). */
  | { kind: "build"; theirs: string; theirsBuild: BuildIdentity; oursBuild: BuildIdentity };

/** What versionVerdict needs to tell two builds of one release apart. */
export interface BuildDeps {
  /** The build this launcher would start (ownArbiterBuild); called only when
   *  the release matches and the arbiter reports a build. */
  own: () => BuildIdentity | null;
  /** compareBuilds' tree check. */
  sameArbiterTree?: (a: string, b: string) => boolean | null;
}

/** Compare a `hello` result with this launcher's release (and, given
 *  `build`, its build). Pure but for the injected build reads. */
export function versionVerdict(ours: string, hello: unknown, build?: BuildDeps): VersionVerdict {
  // A launcher that cannot read its own release (a bundle moved away from
  // its package.json) has nothing to compare; the arbiter it starts from the
  // same place cannot read its own either.
  if (ours === "unknown" || ours.trim() === "") return { kind: "unknown" };
  if (!hello || typeof hello !== "object") return { kind: "unknown" };
  const h = hello as Record<string, unknown>;
  const theirs = typeof h["version"] === "string" && h["version"].trim() !== "" ? h["version"].trim() : null;
  if (theirs === null) {
    // Every real arbiter's hello has carried protocolVersion since the op
    // existed (runtime-instances.md §4): one without `version` is a release
    // from before this check. An answer with neither is no arbiter identity.
    return typeof h["protocolVersion"] === "number" ? { kind: "older", theirs: null } : { kind: "unknown" };
  }
  if (theirs === ours) {
    const theirsBuild = build ? parseBuild(hello) : null;
    if (!build || theirsBuild === null) return { kind: "match", theirs };
    const oursBuild = build.own();
    return oursBuild !== null && compareBuilds(oursBuild, theirsBuild, build.sameArbiterTree) === "different"
      ? { kind: "build", theirs, theirsBuild, oursBuild }
      : { kind: "match", theirs };
  }
  const a = parseVersion(theirs);
  const b = parseVersion(ours);
  if (a && b) {
    const c = compareVersions(a, b);
    if (c < 0) return { kind: "older", theirs };
    if (c > 0) return { kind: "newer", theirs };
  }
  return { kind: "other", theirs };
}

export type SkewAction =
  | { kind: "proceed" }
  /** Stop the stack at `base` and start this release's. */
  | { kind: "restart"; note: string }
  | { kind: "refuse"; message: string };

export interface SkewInput {
  verdict: VersionVerdict;
  /** This launcher's release. */
  ours: string;
  sock: string;
  /** How the launch resolved the socket (arbiter-sock.ts). */
  mode: ArbiterSockMode;
  /** This launch started the arbiter that answered (ensureArbiter). */
  started: boolean;
  /** The stack's runtime dir (`mandu stop --stack` takes it). */
  base: string;
  /** The answering arbiter's pid, when it said. */
  arbiterPid: number | null;
  /** Other `mandu` sessions on this stack (their launcher pids). */
  peers: readonly number[];
  /** A systemd service that restarts the stack when it is stopped
   *  (stack-supervisor.ts); absent or null = none found. */
  supervisor?: StackSupervisor | null;
}

/** "Mandu 0.2.0-beta.4", or the words for an arbiter that reports none. */
export function describeRelease(theirs: string | null): string {
  return theirs === null ? "an older Mandu release (one that does not report its version)" : `Mandu ${theirs}`;
}

/** What the launch does about the arbiter's release. Pure. */
export function skewAction(i: SkewInput): SkewAction {
  const v = i.verdict;
  if (v.kind === "match" || v.kind === "unknown") return { kind: "proceed" };
  const pid = i.arbiterPid !== null ? `, pid ${i.arbiterPid}` : "";
  // A stack a systemd service restarts is stopped through that service: a
  // `mandu stop` would only bring the old code back (stack-supervisor.ts).
  // A service kept on purpose is left alone: this mandu then runs on a stack
  // of its own.
  const stop = i.supervisor
    ? `${disableCommand(i.supervisor)}; or, to keep that service, run this mandu on its own stack: ${ownStackCommand(i.base)} (${OWN_STACK_NOTE})`
    : `mandu stop --stack ${i.base}`;
  if (v.kind === "build") return buildSkewAction(i, v, pid, stop);
  const theirs = describeRelease(v.theirs);
  if (i.started) {
    return {
      kind: "refuse",
      message:
        `mandu: the arbiter this launch started (${i.sock}${pid}) reports ${theirs}, but this mandu is ${i.ours}; ` +
        `refusing to launch against another release. Another release's mandu may have started its own at the same ` +
        `moment: run mandu again. If this repeats, the installation is mixed: reinstall Mandu.`,
    };
  }
  if (i.mode === "pinned") {
    return {
      kind: "refuse",
      message:
        `mandu: the arbiter at ${i.sock} (MANDU_ARBITER_SOCK${pid}) runs ${theirs}, but this mandu is ${i.ours}; ` +
        `refusing to launch against another release. Restart that arbiter from this release, or unset ` +
        `MANDU_ARBITER_SOCK to use your own Mandu services.`,
    };
  }
  const running = `the Mandu services running for you (the arbiter at ${i.sock}${pid})`;
  if (v.kind === "newer") {
    return {
      kind: "refuse",
      message:
        `mandu: ${running} are ${theirs}, newer than this mandu (${i.ours}); refusing to launch against another ` +
        `release. Update this mandu, or stop those services to run this one: ${stop}`,
    };
  }
  if (i.peers.length > 0) {
    const n = i.peers.length;
    return {
      kind: "refuse",
      message:
        `mandu: ${running} are ${theirs}, but this mandu is ${i.ours}; refusing to launch against another release. ` +
        `They were not restarted because ${n === 1 ? "another mandu session uses them" : `${n} other mandu sessions use them`} ` +
        `(pid ${i.peers.join(", ")}). Run mandu again once ${n === 1 ? "it ends" : "they end"}, or restart the services ` +
        `now, which ends the protection of ${n === 1 ? "that session" : "those sessions"}: ${stop}`,
    };
  }
  if (i.supervisor) return supervisedRefusal(i.supervisor, i.base, `${running} are ${theirs}, but this mandu is ${i.ours}`, "another release");
  return {
    kind: "restart",
    note: `mandu: the Mandu services running for you were ${theirs}; restarting them as Mandu ${i.ours}`,
  };
}

/** The refusal for a stack this launch would restart, but a systemd service
 *  would start again as the old code. */
function supervisedRefusal(s: StackSupervisor, base: string, what: string, other: string): SkewAction {
  return {
    kind: "refuse",
    message:
      `mandu: ${what}; refusing to launch against ${other}. They are run by ${describeSupervisor(s)}, ` +
      `which starts them again when they are stopped, so this mandu cannot replace them. If that service is an ` +
      `older Mandu you no longer use, stop it for good and run mandu again: ${disableCommand(s)}` +
      (s.fragmentPath ? ` (its unit file is ${s.fragmentPath})` : "") +
      `. If you keep that service on purpose, run this mandu on its own stack instead: ${ownStackCommand(base)} (${OWN_STACK_NOTE})`,
  };
}

/** skewAction for another build of this release: the "older" rules (a build
 *  has no order, so no "newer"), each message naming both builds. */
function buildSkewAction(
  i: SkewInput,
  v: Extract<VersionVerdict, { kind: "build" }>,
  pid: string,
  stop: string,
): SkewAction {
  const what = `another build of Mandu ${v.theirs} (${describeBuild(v.theirsBuild)}) than this mandu (${describeBuild(v.oursBuild)})`;
  const refusing = "refusing to launch against another build";
  if (i.started) {
    return {
      kind: "refuse",
      message:
        `mandu: the arbiter this launch started (${i.sock}${pid}) runs ${what}; ${refusing}. Another checkout's or ` +
        `install's mandu may have started its own at the same moment: run mandu again. If this repeats, this mandu ` +
        `and the services it starts come from two places: reinstall Mandu, or rebuild the checkout.`,
    };
  }
  if (i.mode === "pinned") {
    return {
      kind: "refuse",
      message:
        `mandu: the arbiter at ${i.sock} (MANDU_ARBITER_SOCK${pid}) runs ${what}; ${refusing}. Restart that arbiter ` +
        `from this build, or unset MANDU_ARBITER_SOCK to use your own Mandu services.`,
    };
  }
  const running = `the Mandu services running for you (the arbiter at ${i.sock}${pid})`;
  if (i.peers.length > 0) {
    const n = i.peers.length;
    return {
      kind: "refuse",
      message:
        `mandu: ${running} run ${what}; ${refusing}. ` +
        `They were not restarted because ${n === 1 ? "another mandu session uses them" : `${n} other mandu sessions use them`} ` +
        `(pid ${i.peers.join(", ")}). Run mandu again once ${n === 1 ? "it ends" : "they end"}, or restart the services ` +
        `now, which ends the protection of ${n === 1 ? "that session" : "those sessions"}: ${stop}`,
    };
  }
  if (i.supervisor) return supervisedRefusal(i.supervisor, i.base, `${running} run ${what}`, "another build");
  return {
    kind: "restart",
    note: `mandu: the Mandu services running for you were ${what}; restarting them as this build`,
  };
}

/** The effects the driver needs, injectable for tests. */
export interface ReleaseCheckDeps {
  /** One `hello`; rejects or resolves undefined when there is no answer. */
  hello: (sock: string) => Promise<unknown>;
  /** Other `mandu` sessions (launcher pids) on the stack at `base`. */
  peers: (base: string) => number[];
  /** Tell two builds of one release apart (absent: version only). */
  build?: BuildDeps;
  /** The systemd service that restarts the stack at `base` (whose arbiter is
   *  `arbiterPid`), or null (stack-supervisor.ts). Absent: none is looked for. */
  supervisor?: (base: string, arbiterPid: number | null) => StackSupervisor | null;
}

/** Read the arbiter's release and decide. Never throws: an unreadable
 *  `hello` is "unknown". */
export async function checkArbiterRelease(
  i: Omit<SkewInput, "verdict" | "arbiterPid" | "peers">,
  deps: ReleaseCheckDeps,
): Promise<{ verdict: VersionVerdict; action: SkewAction }> {
  let hello: unknown;
  try {
    hello = await deps.hello(i.sock);
  } catch {
    hello = undefined;
  }
  const verdict = versionVerdict(i.ours, hello, deps.build);
  const pidRaw = hello && typeof hello === "object" ? (hello as Record<string, unknown>)["pid"] : undefined;
  const arbiterPid = typeof pidRaw === "number" && Number.isInteger(pidRaw) && pidRaw > 0 ? pidRaw : null;
  // Only a resident stack of another release that this launch may restart
  // needs the process scan.
  const needPeers = !i.started && i.mode !== "pinned" && (verdict.kind === "older" || verdict.kind === "other" || verdict.kind === "build");
  const peers = needPeers ? deps.peers(i.base) : [];
  // Who keeps that stack alive matters to every way it would be stopped:
  // this launch's restart, and the `stop` a refusal names.
  const resident = !i.started && i.mode !== "pinned" && verdict.kind !== "match" && verdict.kind !== "unknown";
  let supervisor: StackSupervisor | null = null;
  if (resident && deps.supervisor) {
    try { supervisor = deps.supervisor(i.base, arbiterPid); } catch { supervisor = null; }
  }
  return { verdict, action: skewAction({ ...i, verdict, arbiterPid, peers, supervisor }) };
}

/** After a restart the new arbiter must be this release, answering: an
 *  unknown verdict there is a refusal too (the socket left by the stopped
 *  stack, or a start that did not come up). Pure. */
export function afterRestartRefusal(verdict: VersionVerdict, ours: string, sock: string): string | null {
  if (verdict.kind === "match") return null;
  if (verdict.kind === "unknown") {
    return `mandu: the restarted Mandu arbiter at ${sock} did not report this release (${ours}); refusing to launch. ` +
      `\`mandu status\` shows what is running.`;
  }
  if (verdict.kind === "build") {
    return `mandu: the restarted Mandu arbiter at ${sock} runs another build of Mandu ${verdict.theirs} ` +
      `(${describeBuild(verdict.theirsBuild)}) than this mandu (${describeBuild(verdict.oursBuild)}); refusing to launch. ` +
      `This mandu and the services it starts come from two places: reinstall Mandu, or rebuild the checkout.`;
  }
  return `mandu: the restarted Mandu arbiter at ${sock} reports ${describeRelease(verdict.theirs)}, but this mandu is ` +
    `${ours}; refusing to launch. The installation is mixed: reinstall Mandu.`;
}

/** The launch's side of enforceRelease, injectable for tests (run.ts wires
 *  the real arbiter, the release gate and the stack's stop and start). */
export interface EnforceDeps {
  /** This launch's release check against the arbiter it now points at. */
  check: (started: boolean) => Promise<{ verdict: VersionVerdict; action: SkewAction }>;
  /** This launch started the arbiter that answered first (ensureArbiter). */
  started: boolean;
  /** Is the socket pinned (MANDU_ARBITER_SOCK)? Read when it matters. */
  pinned: () => boolean;
  /** release-gate.ts: this launch's pending marker (returns its remover)
   *  and the stack's restart lock (null when the wait ran out). */
  markPending: () => () => void;
  acquireLock: () => Promise<(() => void) | null>;
  /** Say the restart note. */
  note: (msg: string) => void;
  /** Stop the stack's resident daemons (stopStackAndWait). */
  stop: () => Promise<{ survivors: number[] }>;
  /** Start or attach to this build's stack at the `current` spelling and
   *  return its verdict and the socket it answered on. */
  startThisBuild: () => Promise<{ verdict: VersionVerdict; sock: string }>;
  ours: string;
  base: string;
}

/**
 * The release check of one launch, with its restart (runtime-instances.md
 * §4.1). Throws an Error carrying the refusal; resolves when the launch may
 * go on (`restarted`: this launch replaced the stack).
 *
 * Racing launches (release-gate.ts): every launch marks itself pending while
 * it checks (so a peer scan does not take it for a session); one that would
 * restart takes the stack's restart lock, reads `hello` again under it (the
 * last holder may have replaced the stack, and then this launch adopts it, or
 * starts this build's when the stack it saw is gone) and only then stops and
 * starts.
 */
export async function enforceRelease(d: EnforceDeps): Promise<{ restarted: boolean }> {
  const clearPending = d.markPending();
  try {
    const first = await d.check(d.started);
    if (first.action.kind === "refuse") throw new Error(first.action.message);
    if (first.action.kind === "proceed") return { restarted: false };
    const unlock = await d.acquireLock();
    if (unlock === null) {
      throw new Error(`mandu: another mandu has been restarting the Mandu services at ${d.base} for too long; refusing to ` +
        "launch. Run mandu again; `mandu status` shows what is running.");
    }
    try {
      const again = await d.check(false);
      const verify = async (): Promise<void> => {
        const after = await d.startThisBuild();
        const refusal = afterRestartRefusal(after.verdict, d.ours, after.sock);
        if (refusal !== null) throw new Error(refusal);
      };
      if (again.verdict.kind === "unknown" && !d.pinned()) {
        // The stack this launch saw is gone (the last holder stopped it):
        // attach to the one that holder started, or start this build's.
        await verify();
        return { restarted: false };
      }
      if (again.action.kind === "refuse") throw new Error(again.action.message);
      if (again.action.kind === "proceed") return { restarted: false };
      d.note(again.action.note);
      const { survivors } = await d.stop();
      if (survivors.length > 0) {
        throw new Error(
          `mandu: the Mandu services of another release or build did not stop (pid ${survivors.join(", ")}); ` +
            `refusing to launch beside them. Stop them: mandu stop --stack ${d.base}`,
        );
      }
      await verify();
      return { restarted: true };
    } finally {
      unlock();
    }
  } finally {
    clearPending();
  }
}
