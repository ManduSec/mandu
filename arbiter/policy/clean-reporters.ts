/**
 * clean-reporters — who may vouch for a clean-box run (exec-routing.md §8
 * §5.3, sandbox-security-review-2026-09-28 finding 4). Mandu-new, no
 * reference origin.
 *
 * A clean verdict un-masks a Bash result, so it may come only from a reporter
 * outside the agent's process tree: the session's whole-agent guard
 * (`mandu-net-guard`), which runs the clean attempt itself. Every op here is
 * on the data socket, which the agent's processes reach too, so the guard is
 * told apart by a token only it holds:
 *
 *   1. ALLOW. The launcher, in its first `setSessionUpstream` for the session
 *      (bind-once, before any service or the agent exists), asks for a
 *      reporter. Only that FRESH bind marks the session claimable: a re-bind,
 *      a bind after traffic, or a session the launcher never bound is never
 *      claimable, so a process inside the agent cannot open the door for its
 *      own session later.
 *   2. CLAIM. The guard claims the token over its own connection, before it
 *      lets the agent start. The first claim gets a fresh random token; the
 *      arbiter keeps only its sha256.
 *   3. A SECOND CLAIM REVOKES. The session key is not secret (it names run
 *      directories), so another session's process could race the guard to
 *      the claim. Whoever loses, the reporter is gone: a second claim drops
 *      the token and refuses, and the session reports nothing clean. At worst
 *      a race costs the upgrade; it never leaves a token with anyone but the
 *      guard, because the guard claims before its agent has a callId to
 *      forge for, and a verdict is only honored for the session it names.
 *   4. REPORT. A report carrying a token that maps to a session resolves as
 *      `authenticated-supervisor` for THAT session (the report's own
 *      sessionKey is ignored); classify honors a clean verdict only for the
 *      session that classifies.
 *
 * The token is 256 random bits, lives in the guard's memory (the guard is
 * not dumpable: no ptrace, no /proc/<guard>/mem, no pidfd_getfd), and rides
 * only the guard's Unix-socket connection. In memory only: an arbiter restart
 * forgets every reporter (fail-closed: reports then resolve UNCLEAN, and no
 * session is claimable again because its upstream binding persists).
 */

import { createHash, randomBytes } from "node:crypto";

export type ClaimResult =
  | { ok: true; token: string }
  | { ok: false; error: string };

type Slot = { state: "claimable" } | { state: "claimed"; tokenSha256: string } | { state: "revoked" };

const sha256 = (s: string): string => createHash("sha256").update(s).digest("hex");

export class CleanReporters {
  private readonly slots = new Map<string, Slot>();
  private readonly byToken = new Map<string, string>();

  /** The launcher's fresh bind asked for a reporter. Only a session with no
   *  slot yet becomes claimable (a revoked or claimed slot stays as it is). */
  allow(sessionKey: string): void {
    if (!sessionKey || this.slots.has(sessionKey)) return;
    this.slots.set(sessionKey, { state: "claimable" });
  }

  /** Is the session's reporter still claimable or claimed (not revoked)? */
  offered(sessionKey: string): boolean {
    const s = this.slots.get(sessionKey);
    return s !== undefined && s.state !== "revoked";
  }

  claim(sessionKey: string): ClaimResult {
    const slot = this.slots.get(sessionKey);
    if (slot === undefined) {
      return { ok: false, error: "claimCleanReporter: this session has no reporter (the launcher did not ask for one when it bound the session)" };
    }
    if (slot.state === "claimable") {
      const token = randomBytes(32).toString("hex");
      const tokenSha256 = sha256(token);
      this.slots.set(sessionKey, { state: "claimed", tokenSha256 });
      this.byToken.set(tokenSha256, sessionKey);
      return { ok: true, token };
    }
    if (slot.state === "claimed") this.byToken.delete(slot.tokenSha256);
    this.slots.set(sessionKey, { state: "revoked" });
    return {
      ok: false,
      error: "claimCleanReporter: the reporter was already claimed; a second claim revokes it, so this session reports nothing clean",
    };
  }

  /** The session a token was issued for, or undefined (no token, a wrong
   *  one, or one a second claim revoked). */
  sessionFor(token: unknown): string | undefined {
    if (typeof token !== "string" || !/^[0-9a-f]{64}$/.test(token)) return undefined;
    return this.byToken.get(sha256(token));
  }
}
