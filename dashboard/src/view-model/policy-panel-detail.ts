/**
 * view-model/policy-panel-detail — the Policy panel's shared vocabulary
 * (whereLabel / verdictFamily / the outcome-chip folds) and its ⓘ detail
 * builders (the fixed §8 template: rule + verdict drawers, posture chips, the
 * law-source line).
 *
 * Extracted verbatim from policy-panel.ts (2026-09-11 overnight cleanup,
 * behavior-preserving). Pure; policy-panel.ts re-exports whereLabel and
 * verdictFamily so existing importers are unchanged. The VM types come back
 * from policy-panel.ts as type-only imports (erased at runtime — no cycle).
 */

import type {
  LawSourceRow,
  PolicySnapshot,
  UsageGateRow,
  UsageRuleRow,
  VerdictEntry,
} from "../policy-model.js";
import type { DetailItem, DetailSection } from "./detail.js";
import type {
  LockdownState, OutcomeKind, PolicyPanelVM, PostureState, QueueRowVM, VerdictFamily,
} from "./policy-panel.js";

// ── Shared vocabulary ─────────────────────────────────────────────────────────

/** The ONE chokepoint display vocabulary (§8): queue families and rule
 * boundaries land on the same labels (shell/exec are one chokepoint). */
export function whereLabel(x: string): string {
  switch (x) {
    case "filesystem": return "file";
    case "network": return "network";
    case "shell":
    case "exec": return "exec";
    case "model_context": return "model context";
    // Plan 15 §7: a prompt the human typed, held before the model reads it.
    case "prompt": return "prompt";
    case "any": return "any";
    default: return "?";
  }
}

export function verdictFamily(subject: string): VerdictFamily {
  if (subject.startsWith("fs:")) return "filesystem";
  // Plan 10 §11.1: `open:<app>` × path — a program asking to read a secret
  // file RAW (the held open). A filesystem act, judged at the open.
  if (subject.startsWith("open:") || subject.startsWith("trust:")) return "filesystem";
  // sandbox-security-review-2026-09-28 finding 6: `write:<exe>#<sha256>` ×
  // path (`write:<app>` before 2026-10-02, write-protection.md §2.1), a
  // held change to a file that runs later. Judged at the change.
  if (subject.startsWith("write:")) return "filesystem";
  if (subject.startsWith("exec-escalate:")) return "exec";
  // Plan 15 §7 (phase 3): `prompt:<category>#<ref>` × `model:<session>[#turn:<ref>]`,
  // a found part of the human's own message, held before the model reads it.
  if (subject.startsWith("prompt:")) return "prompt";
  // exec-routing.md §8.7a: `exec-program:<originHost>` × path — the
  // provenance gate's net-fetched program text. Same chokepoint, same label.
  if (subject.startsWith("exec-program:")) return "exec";
  // confidentiality.md §4 (2026-10-11): a HIGH session's request to a host
  // (`session-net:<session>` × host) or its command (`session-exec:<session>`
  // × the command), asked of the human.
  if (subject.startsWith("session-net:")) return "network";
  // Confidentiality plan 13 §5.4 (2026-10-11): a program holding secret
  // files wants to send to a host not all of them may go to.
  if (subject.startsWith("holder-send:")) return "network";
  if (subject.startsWith("session-exec:")) return "exec";
  if (subject.startsWith("$")) return "network";
  return "unknown";
}

export function ruleOutcome(outcome: UsageRuleRow["outcome"]): OutcomeKind {
  return outcome === "deny+approval" ? "needs-approval" : outcome;
}

export function verdictOutcome(status: QueueRowVM["status"]): OutcomeKind {
  return status === "approved" ? "allow" : status === "denied" ? "deny" : "pending";
}

function postureOf(v: boolean | undefined): PostureState {
  return v === undefined ? "unknown" : v ? "on" : "off";
}

// ── ⓘ detail builders (the fixed §8 template) ────────────────────────────────

const VERDICTS_FIRST =
  "Your standing decisions (section ①) are checked before this rule and override it.";

export function ruleDetail(
  r: UsageRuleRow,
  gate: UsageGateRow | undefined,
  sensitivePaths: string[],
): DetailSection[] {
  const what: DetailItem[] = [
    r.source === "fail-closed"
      ? { text: "A fail-closed default: it fires when no rule matched or the input was out of contract — never a silent fall-through to allow." }
      : { text: "A built-in policy rule, compiled into the arbiter." },
    { text: VERDICTS_FIRST },
  ];
  const does: DetailItem[] = [
    r.outcome === "allow"
      ? { text: "When it matches, the request is allowed." }
      : r.outcome === "deny"
        ? { text: "When it matches, the request is denied outright — no approval can override it." }
        : { text: "When it matches, the request is denied and queued for one-time human approval; the answer becomes a standing decision in section ①." },
    { text: r.summary },
  ];
  const specified: DetailItem[] = [{ text: `rule id: ${r.id}` }];
  if (gate) {
    specified.push({ text: `${gate.title} — ${gate.definedIn}` });
    specified.push({ text: `design: ${gate.doc}` });
  }
  const applies: DetailItem[] = [{ text: `chokepoint: ${whereLabel(r.boundary)}` }];
  if (gate) applies.push({ text: gate.evaluation });
  const out: DetailSection[] = [
    { label: "What this is", items: what },
    { label: "What it does", items: does },
    { label: "Where it's specified", items: specified },
    { label: "When it applies", items: applies },
  ];
  // The sensitive-path rule's configuration is DETAIL of this rule, not a
  // dangling panel section (§8).
  if (r.id === "fs:sensitive-path" && sensitivePaths.length) {
    out.push({
      label: "Configured sensitive prefixes",
      items: sensitivePaths.map((p) => ({ text: p })),
    });
  }
  return out;
}

export function verdictDetail(v: VerdictEntry, status: QueueRowVM["status"]): DetailSection[] {
  const pending = status === "pending";
  // Verdict scope (policy-surface.md §9.8.7). Absent on a pre-scope arbiter,
  // whose verdicts were all standing — so absent reads as "always".
  const once = !pending && v.scope === "once";
  const spent = once && typeof v.consumedAt === "number";
  const what: DetailItem[] = pending
    ? [
        { text: "A question waiting for a human: a gate denied this request and queued it for one-time approval." },
        { text: "Until answered, matching requests stay denied (fail-closed)." },
      ]
    : once
      ? [
          { text: "A single-use human decision (docs term: once-scoped verdict), stored in the arbiter." },
          { text: "It answers ONE matching request, then the question is asked again — it is checked BEFORE every built-in rule in section ② until spent." },
        ]
      : [
          { text: "A standing human decision (docs term: standing verdict), stored in the arbiter." },
          { text: "It never expires, and it is checked BEFORE every built-in rule in section ②." },
        ];
  const decides: DetailItem[] = [
    { text: `subject: ${v.symbol}` },
    { text: `target: ${v.destination}` },
    spent
      ? { text: "Nothing anymore — it was used once and is spent; the next matching request asks again." }
      : status === "approved"
        ? once
          ? { text: "The NEXT request matching this subject × target is allowed; after that one use, asking resumes." }
          : { text: "Every future request matching this subject × target is allowed without asking again." }
        : status === "denied"
          ? once
            ? { text: "The NEXT request matching this subject × target is denied; after that one use, asking resumes." }
            : { text: "Every future request matching this subject × target is denied without asking again." }
          : { text: "No standing effect yet — it decides nothing until a human answers." },
  ];
  const from: DetailItem[] = [
    { text: `queued because: ${v.reason}` },
    { text: `asked ${v.count}× — first`, ms: v.firstSeen },
    { text: "last", ms: v.lastSeen },
    v.sessions?.length
      ? { text: `requesting ${v.sessions.length === 1 ? "session" : "sessions"}: ${[...v.sessions].reverse().join(", ")}` }
      : { text: "no session recorded (this row predates session attribution)" },
  ];
  const resolution: DetailItem[] = pending
    ? [{ text: "Awaiting a human decision: Allow once, Always allow or Block on the row." }]
    : [
        { text: `${status} by a human${once ? " (once)" : ""}`, ms: v.resolvedAt ?? null },
        ...(spent ? [{ text: "spent by its one use", ms: v.consumedAt ?? null }] : []),
        { text: "Reversible any time with the row's one-click action." },
      ];
  return [
    { label: "What this is", items: what },
    { label: "What it decides", items: decides },
    { label: "Where it came from", items: from },
    { label: "Resolution", items: resolution },
  ];
}

export function postureChips(
  snapshot: PolicySnapshot,
): PolicyPanelVM["posture"] {
  const integrity = postureOf(snapshot.posture?.integrity);
  const confidentiality = postureOf(snapshot.posture?.confidentiality);
  const egress: LockdownState = snapshot.egressPosture ?? "unknown";
  const explain = (state: string, on: string, off: string, unknown: string): DetailSection[] => [
    {
      label: "What this means",
      items: [{ text: state === "unknown" ? unknown : state === "on" || state === "lockdown" ? on : off }],
    },
  ];
  return {
    integrity: {
      state: integrity,
      detail: explain(
        integrity,
        "The IPI defense is active: inbound tool results are classified, and untrusted spans reach the model only as opaque $MDU:* symbols.",
        "Trust classification is OFF: every inbound value classifies TRUSTED, no untrusted symbols are minted, and the untrusted-egress and exec gates are inert.",
        "This arbiter predates posture reporting — restart the Mandu stack onto newer code to see it.",
      ),
    },
    confidentiality: {
      state: confidentiality,
      detail: explain(
        confidentiality,
        "The secret lattice is active: secrets symbolize even when trusted, and the watermark / secret-egress gates fire.",
        "OFF is byte-identical to the integrity-only system: no secret levels, wire markers, or secret-egress enforcement.",
        "This arbiter predates posture reporting — restart the Mandu stack onto newer code to see it.",
      ),
    },
    egress: {
      state: egress,
      detail: explain(
        egress,
        "SIEM-triggered lockdown (tighten-only): EVERY network egress requires human approval until a human explicitly relaxes it. Per-egress approvals still work — that is the sanctioned relief valve.",
        "No lockdown: network egress follows the standing decisions and built-in rules below.",
        "This arbiter predates lockdown reporting — restart the Mandu stack onto newer code to see it.",
      ),
    },
  };
}

export function lawSourceVM(
  src: LawSourceRow | undefined,
  specId: string,
): PolicyPanelVM["lawSource"] {
  if (!src) return null; // old arbiter — omit, never invent provenance
  if (src.kind === "custom") {
    return {
      text: "law source: custom policy engine (injected) — source unknown to the arbiter",
      detail: [
        {
          label: "What this means",
          items: [
            { text: "The arbiter was handed a pre-built policy engine (tests / embedders) instead of loading one, so it can vouch for nothing about where its rules came from." },
          ],
        },
      ],
    };
  }
  const builtin = `built-in ${specId} spec`;
  if (src.kind === "builtin") {
    const missing = src.configuredPath !== undefined;
    return {
      text: missing
        ? `law source: ${builtin} — configured policy file NOT loaded: ${src.resolvedPath ?? src.configuredPath}`
        : `law source: ${builtin} — no policy file`,
      detail: [
        {
          label: "What this means",
          items: [
            { text: "No YAML policy file is layered on: the built-in per-tool inbound spec and the intrinsic origin defaults (URL allowlist-empty → untrusted; CHANNEL/DIR blocklist-empty → trusted) are the whole trust law." },
            ...(missing
              ? [{ text: "A policy file was configured but was missing or unparseable at arbiter start — the built-ins are what is actually in force." }]
              : []),
          ],
        },
      ],
    };
  }
  const s = src.sections;
  const parts: string[] = [];
  if (s) {
    if (s.url) parts.push("URL origin list");
    if (s.channel) parts.push("CHANNEL origin list");
    if (s.dir) parts.push("DIR origin list");
    if (s.toolOverrides) parts.push(`${s.toolOverrides} tool override${s.toolOverrides === 1 ? "" : "s"}`);
    if (s.commandEntries) parts.push(`${s.commandEntries} per-command entr${s.commandEntries === 1 ? "y" : "ies"}`);
  }
  return {
    text: `law source: ${builtin} + policy file ${src.resolvedPath ?? src.configuredPath ?? "(unknown path)"}`,
    detail: [
      {
        label: "What this means",
        items: [
          { text: "A YAML policy file layers origin lists and per-tool/command overrides on top of the built-in spec. It was loaded once at arbiter start." },
          { text: parts.length ? `it sets: ${parts.join(", ")}` : "it sets nothing the built-ins don't already say" },
        ],
      },
    ],
  };
}
