/**
 * session-approvals — the HUMAN half of a HIGH session's gate
 * (confidentiality.md §4, "The human half: a HIGH session's approvals",
 * 2026-10-11). Mandu-new (no reference origin).
 *
 * `decideSessionEgress` (session-egress.ts) stays PURE: it says whether a
 * HIGH session's request or command needs a human. This module is the pure
 * part of turning that "needs a human" into a row of the existing approval
 * queue (egress-approvals.ts) and a prior human answer back into a verdict:
 *
 *   - the queue KEY: `session-net:<session>` × host for a network request,
 *     `session-exec:<session>` × the exact command for a shell command. The
 *     session is in the key because what a request may carry depends on
 *     what THAT session read: an answer about one session never opens
 *     another. Retries of the same request bump one row (the store's upsert);
 *   - the COMPOSITION: an approved prior lets this one through (the arbiter
 *     spends a once at the gate), a denied prior refuses with no new card,
 *     no prior files a pending row;
 *   - a HELD command's refused connection (below): which holders ask the
 *     session's network question, and the words its row and note carry.
 *
 * The stateful half (consult, spend, record) is the arbiter server's, which
 * owns the store, exactly as for the per-symbol egress rows.
 */

import { createHash } from "node:crypto";
import { ruleRef, verdictRef } from "./rule-ref.js";
import type { SessionEgressDecision } from "./session-egress.js";

/** The subject prefix of a HIGH session's network ask. */
export const SESSION_NET_SUBJECT_PREFIX = "session-net:";
/** The subject prefix of a HIGH session's command ask. */
export const SESSION_EXEC_SUBJECT_PREFIX = "session-exec:";
/** The target of a network ask whose call names no destination (a search). */
export const UNNAMED_DESTINATION = "(no destination named)";
/** A command longer than this is keyed by its head and its SHA-256, so the
 *  row stays readable and two long commands sharing a head never share a
 *  key (an Allow once for one must never admit the other). */
export const SESSION_EXEC_TARGET_MAX = 2000;
const SESSION_EXEC_TARGET_HEAD = 160;

export type SessionApprovalBoundary = "network" | "shell";

/** The queue subject for one session's asks at one boundary. */
export function sessionApprovalSubject(boundary: SessionApprovalBoundary, sessionKey: string): string {
  return `${boundary === "network" ? SESSION_NET_SUBJECT_PREFIX : SESSION_EXEC_SUBJECT_PREFIX}${sessionKey}`;
}

/** The host a network ask is keyed on: lower-cased, a URL reduced to its
 *  host[:port], a trailing dot dropped, a default port (`:80`, `:443`)
 *  dropped ({@link approvalDestination}). Empty ⇒ {@link UNNAMED_DESTINATION}. */
export function sessionNetTarget(destination: string | undefined): string {
  let s = (destination ?? "").trim().toLowerCase();
  const m = /^[a-z][a-z0-9+.-]*:\/\/([^/?#]+)/.exec(s);
  if (m) s = m[1]!;
  s = approvalDestination(s.split(/[/?#]/)[0]!.replace(/^[^@]*@/, "").replace(/\.(?=:\d+$|$)/, ""));
  return s === "" ? UNNAMED_DESTINATION : s;
}

/**
 * The destination a human's answer about a network send is keyed on: the
 * destination as stated, less a default port (`host:443`, `host:80`,
 * `[2001:db8::1]:443` → the host). The egress proxy states every
 * destination's port since 2026-10-17 (the binding rule needs it, plan 10
 * §11.13.1), while the model proxies' pre-checks name the host of the URL,
 * and before then the proxy named `host` for both default ports: an answer
 * given at `host` keeps applying at `host:443` and `host:80`, and one at
 * `host:8443` only there. Only `host:port` and `[v6]:port` forms are reduced
 * (a bare IPv6 address is left whole). Pure.
 */
export function approvalDestination(destination: string): string {
  const m = /^(\[[^\]]+\]|[^:[\]]+):(?:80|443)$/.exec(destination);
  return m ? m[1]! : destination;
}

/** The exact command a shell ask is keyed on (header: SESSION_EXEC_TARGET_MAX). */
export function sessionExecTarget(command: string): string {
  if (command.length <= SESSION_EXEC_TARGET_MAX) return command;
  const sha = createHash("sha256").update(command, "utf8").digest("hex");
  return `${command.slice(0, SESSION_EXEC_TARGET_HEAD)}… [sha256:${sha}]`;
}

/** Which session and boundary a queue subject names, or null when it is not
 *  a session ask (or names no session: a malformed row grants nothing). */
export function parseSessionApprovalSubject(subject: string): { boundary: SessionApprovalBoundary; sessionKey: string } | null {
  if (typeof subject !== "string") return null;
  for (const [prefix, boundary] of [[SESSION_NET_SUBJECT_PREFIX, "network"], [SESSION_EXEC_SUBJECT_PREFIX, "shell"]] as const) {
    if (subject.startsWith(prefix)) {
      const sessionKey = subject.slice(prefix.length);
      return sessionKey === "" ? null : { boundary, sessionKey };
    }
  }
  return null;
}

/** Is this queue subject a HIGH session's ask? Those take no standing
 *  answer: an Always is kept as once (confidentiality.md §4). */
export function isSessionApprovalSubject(subject: string): boolean {
  return parseSessionApprovalSubject(subject) !== null;
}

/** A prior human answer as the composition reads it (already filtered by
 *  the arbiter's `consultPriorVerdict`: a spent once, or an approval read
 *  from an unattested channel, arrives as `undefined`). */
export interface SessionPriorVerdict {
  id: string;
  status: "approved" | "denied";
  scope: "once" | "always";
}

/** The session gate's answer with the queue folded in. `file` ⇒ the caller
 *  records a pending row and returns `decision` with its id. */
export type SessionApprovalStep =
  | { kind: "decided"; decision: SessionEgressDecision }
  | { kind: "file"; decision: SessionEgressDecision };

/**
 * Compose the pure session verdict with a prior human answer. Pure.
 *
 *   - allowed by the law (not high, bound host, AgentShell) ⇒ unchanged;
 *   - not an approval case (`requiresApproval: false`) ⇒ unchanged, no row;
 *   - an approved prior ⇒ allow, `verdict:<id>` provenance;
 *   - a denied prior ⇒ refuse, `human-denied`, no new row;
 *   - no prior ⇒ refuse and file a row: the reason ends `→ pending`, which
 *     the proxies' notices read as "the user was asked".
 */
export function composeSessionApproval(
  verdict: SessionEgressDecision,
  prior: SessionPriorVerdict | undefined,
): SessionApprovalStep {
  if (verdict.allow || !verdict.requiresApproval) return { kind: "decided", decision: verdict };
  if (prior?.status === "approved") {
    return {
      kind: "decided",
      decision: {
        allow: true,
        requiresApproval: false,
        reason: `human-approved (${prior.id}, ${prior.scope}): ${verdict.reason}`,
        ruleRef: verdictRef(prior.id),
      },
    };
  }
  if (prior?.status === "denied") {
    return {
      kind: "decided",
      decision: {
        allow: false,
        requiresApproval: false,
        reason: `${verdict.reason} — human-denied (${prior.id})`,
        ruleRef: verdictRef(prior.id),
      },
    };
  }
  return {
    kind: "file",
    decision: { ...verdict, reason: `${verdict.reason} → pending`, ruleRef: verdict.ruleRef ?? ruleRef("session:high-unbound") },
  };
}

// ── A held command's refused connection (2026-10-12) ────────────────────────
//
// Under the kernel guard a HIGH session's command runs HELD by what the
// session read (`sessionExecRoot`, one `via: "session"` taint row per datum):
// its connections go only to those data's bound hosts. When the net-proxy or
// the guard refuses such a connection at an unbound host, the question is
// the session's own network question (`session-net:<session>` × host), not a
// holder's send question: the command carries what the session read, which
// is exactly what that row is about. An Allow once is then spent by the next
// held connection (or the agent's own request) of that session to that host:
// the retry, which is a new command (confidentiality.md §4, "A held command's
// refused connection").

/** The reason a held command's network ask is filed with. The arbiter
 *  attaches `sessionHeld: true` at list time to a `session-net:` row whose
 *  (latest) reason starts with it, so the card says the command's request
 *  was stopped. */
export const SESSION_HELD_REASON_PREFIX = "HELD COMMAND:";

/** One taint row as the question reads it. */
export interface HeldTaintRow {
  via?: string;
  session?: string;
}

/**
 * The session a holder's refused send asks as, or null when it is not a
 * HIGH session's held command: every row the process (and its ancestors and
 * flows) holds is a `session` row of ONE session, and that session is the
 * asking proxy's or guard's own (`requestSession`, when it names one). Any
 * raw read, claim or flow from elsewhere keeps the holder's send question
 * (holder-send-ask.ts), which names every file. Pure.
 */
export function heldSessionOf(rows: readonly HeldTaintRow[], requestSession: string | undefined): string | null {
  if (rows.length === 0) return null;
  let session: string | null = null;
  for (const r of rows) {
    if (r.via !== "session" || typeof r.session !== "string" || r.session === "") return null;
    if (session === null) session = r.session;
    else if (r.session !== session) return null;
  }
  if (typeof requestSession === "string" && requestSession !== "" && requestSession !== session) return null;
  return session;
}

/** The pending row's reason for a held command's refused connection: what
 *  it holds (file paths or `symbol:<name>` rows, never a value) and the host. */
export function sessionHeldNetReason(target: string, held: readonly string[]): string {
  const what = held.length > 0 ? held.join(", ") : "what the session read";
  return `${SESSION_HELD_REASON_PREFIX} a command of this HIGH session holds what the session read (${what}); its connection to ${target} was refused: not a place all of it may go → human approval required (§4).`;
}

/** Is this a held command's network ask (by its latest reason)? */
export function isSessionHeldReason(reason: unknown): boolean {
  return typeof reason === "string" && reason.startsWith(SESSION_HELD_REASON_PREFIX);
}

/** The refusal kind the arbiter records for the asking process
 *  (`recordEgressRefusal`), so the call's result tells the model: asked
 *  (retry after the user's answer) or blocked (final). An approval records
 *  nothing (the connection goes). */
export function heldRefusalKind(status: "pending" | "approved" | "denied"): "session-asked" | "session-blocked" | null {
  return status === "pending" ? "session-asked" : status === "denied" ? "session-blocked" : null;
}
