/**
 * view-model/session-counts — the developer view's session-list chips
 * "N masked · N read before marked · N asks · N blocked" (dashboard.md
 * §4.33), as four small integers per session. Mandu-new (no reference origin). OBSERVABILITY ONLY:
 * nothing here is on the security path, and nothing read out of an event
 * leaves this module but a count.
 *
 * Each count is one the views already show, computed the same way, so a row
 * and the page it opens never disagree:
 *   - masked: the session's items masked before the AI read them,
 *     `lineage.stats.flows` less `early` (masked tokens, the developer view's
 *     unit; the product's Home rows and agent page tiles count secrets
 *     instead, agent-page.ts `pageSecrets`). A token the AI composed itself
 *     is no item (`stats.composed`), so it is never counted (2026-10-09);
 *   - early: the items the AI read as they were before they were masked
 *     (`lineage.stats.readFirst`, by the page's own rule: `withReadFirst`
 *     over the trace's `maskedLater`, as toSessionViewModel builds it), never
 *     counted as masked (2026-10-06; the 🛡 card and the Secrets tab already
 *     told the two apart);
 *   - asks / blocked: the trace's steps that asked for an approval (held
 *     for it, or blocked with an Approvals row filed) / that Mandu blocked,
 *     by the rule the session header's summary and the step rail use
 *     (dev/js/app.js stepAsked + stepFiledAsk / stepBlocked, which this
 *     mirrors). A blocked step that filed a row counts in both. A program's
 *     refused read of a secret file is a blocked step (a held one asked
 *     too), as the product's session page counts it (secret-note.ts).
 *
 * The event sources call it once per session where they already derive the
 * row from the session's events, and cache the row by the log's identity
 * (file-source, arbiter-source; recorded-source in its persisted summary),
 * so a list request does not re-read an unchanged log. Zero counts are left
 * out, and a session with none has no `counts` at all (§4.30 payload budget).
 *
 * The session header reads the SAME counts: /api/events ships them over the
 * whole log (`counts`), even when it caps the events it models at the first
 * DEFAULT_EVENT_LIMIT, so a long session's header and its row agree.
 */
import type { ManduEvent } from "../event-model.js";
import { correlateUllmCalls } from "./correlate.js";
import { toDualLanes } from "./dual-lanes.js";
import type { DualStep } from "./dual-lanes-types.js";
import { toSessionLineage, withReadFirst } from "./lineage.js";

/** The row's counts; a zero count is absent. */
export interface SessionCounts {
  /** items masked before the AI read them */
  masked?: number;
  /** items the AI read as they were, masked only later */
  early?: number;
  asks?: number;
  blocked?: number;
}

/** The events every trace projection reads (toSessionViewModel): the META
 *  events (the harness's assertion verdict, the seed and final disk records)
 *  out, orphan U-LLM calls attached to their inspect tool call. */
export function traceEvents(events: ManduEvent[]): ManduEvent[] {
  return correlateUllmCalls(
    events.filter((e) => e.kind !== "assertion" && e.kind !== "workspace_seed" && e.kind !== "workspace_final"),
  );
}

type GateStep = Extract<DualStep, { step: "tool" | "os" }>;

/** A step Mandu blocked (dev/js/app.js stepBlocked): a deny verdict, a
 *  blocking OS action, or a program's refused read of a secret file, which
 *  only the result's note records (`readRefused`, dashboard.md §4.25b). */
export function stepBlocked(s: GateStep): boolean {
  return s.usage === "deny" || /block|den/i.test((s.step === "os" ? s.action : null) ?? "") || (s.step === "tool" && !!s.readRefused);
}

/** A step held for the person's approval (dev/js/app.js stepAsked). */
export function stepAsked(s: GateStep): boolean {
  return s.usage === "needs_approval";
}

/** A step whose check filed an Approvals row for the person (`askId`, the
 *  event's `policy.approvalId`), whether Mandu then blocked or held it, or
 *  a program's read of a secret file held for the person until nobody
 *  answered (`readRefused.held`: its row stays open; dev/js/app.js
 *  stepFiledAsk). */
export function stepFiledAsk(s: GateStep): boolean {
  return s.step === "tool" ? (s.gates ?? []).some((g) => !!g.askId) || !!s.readRefused?.held : !!s.askId;
}

/** The counts of a session's trace (pure): undefined when all are zero. */
export function sessionCounts(events: ManduEvent[]): SessionCounts | undefined {
  if (events.length === 0) return undefined;
  const trace = traceEvents(events);
  const dualLanes = toDualLanes(trace);
  const later = dualLanes.steps.flatMap((s) => (s.step === "tool" && s.maskedLater ? [s.maskedLater] : []));
  return countsOfView({ lineage: withReadFirst(toSessionLineage(trace), later), dualLanes });
}

/** The same counts read off projections already built over a session's
 *  trace (a SessionViewModel's `lineage` and `dualLanes`, which
 *  toSessionViewModel builds from the same `traceEvents`): /api/events uses
 *  it when it modeled the whole log, so the header's counts cost nothing
 *  more (dashboard.md §4.33). Pure. */
export function countsOfView(vm: {
  lineage: { stats: { flows: number; readFirst?: number } };
  dualLanes: { steps: readonly DualStep[] };
}): SessionCounts | undefined {
  const { flows } = vm.lineage.stats;
  const early = Math.max(0, Math.min(vm.lineage.stats.readFirst ?? 0, flows));
  const masked = flows - early;
  let asks = 0;
  let blocked = 0;
  for (const s of vm.dualLanes.steps) {
    if (s.step !== "tool" && s.step !== "os") continue;
    if (stepBlocked(s)) blocked++;
    if (stepAsked(s) || stepFiledAsk(s)) asks++;
  }
  const out: SessionCounts = {
    ...(masked ? { masked } : {}),
    ...(early ? { early } : {}),
    ...(asks ? { asks } : {}),
    ...(blocked ? { blocked } : {}),
  };
  return Object.keys(out).length ? out : undefined;
}

/** The row's `counts` field, spread into a SessionRef. Fail-soft: a trace
 *  projection that throws costs the row its chips, never the row. */
export function withCounts(events: ManduEvent[]): { counts?: SessionCounts } {
  try {
    const counts = sessionCounts(events);
    return counts ? { counts } : {};
  } catch {
    return {};
  }
}

const COUNT_KEYS = ["masked", "early", "asks", "blocked"] as const;
/** A count larger than any real session's (a persisted entry over it is off shape). */
const COUNT_MAX = 1_000_000_000;

/** A persisted `counts` value, re-checked key by key (built fresh): the
 *  listing cache file is not trusted (listing-cache-file.ts). `undefined` is
 *  a valid "none"; null = off shape. */
export function validateSessionCounts(v: unknown): SessionCounts | undefined | null {
  if (v === undefined) return undefined;
  if (!v || typeof v !== "object" || Array.isArray(v)) return null;
  const o = v as Record<string, unknown>;
  const keys = Object.keys(o);
  if (keys.length === 0 || keys.some((k) => !(COUNT_KEYS as readonly string[]).includes(k))) return null;
  const out: SessionCounts = {};
  for (const k of COUNT_KEYS) {
    const n = o[k];
    if (n === undefined) continue;
    if (typeof n !== "number" || !Number.isSafeInteger(n) || n < 1 || n > COUNT_MAX) return null;
    out[k] = n;
  }
  return out;
}
