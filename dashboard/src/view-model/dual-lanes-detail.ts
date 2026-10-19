/**
 * view-model/dual-lanes-detail — the ⓘ detail builders for the §4.2c lane
 * steps (dashboard.md §4.2e).
 *
 * Extracted verbatim from dual-lanes.ts (2026-09-11 overnight cleanup,
 * behavior-preserving). Pure: each builder turns one ManduEvent into the
 * DetailSection[] the shared drawer renders, reusing the Policy panel §8
 * vocabulary; only toDualLanes consumes them.
 */

import type { ManduEvent, EventKind, PathRewriteDetail, SymbolRef } from "../event-model.js";
import type { DetailItem, DetailSection } from "./detail.js";
import { whereLabel } from "./policy-panel.js";

// ── ⓘ detail builders (dashboard.md §4.2e) ────────────────────────────────────
// The thin timeline entries (net_action / exec_action / fs_action / uncorrelated
// path_rewrite / guard cards / the fs-sync birth card) carry their event's facts
// into a structured drawer, reusing the Policy panel §8 vocabulary
// (DetailSection[] + the fixed section template). Register rules: plain full
// sentences for the "What this is" slot; lowercase `key: value` lines for facts;
// absence stated in words, never omitted ("method: not recorded"); values capped
// at 160 chars; SYMBOLIZED spellings only (never DualRepr.original).

/** The 160-char value cap (fs_action results can carry symbolized file content). */
const capVal = (s: string): string => (s.length > 160 ? `${s.slice(0, 159)}…` : s);

/** A `key: value` fact line — absence stated in words, never omitted. */
const fact = (key: string, v: string | null | undefined): DetailItem =>
  ({ text: v ? `${key}: ${capVal(v)}` : `${key}: not recorded` });

/** Loose (off-schema) string field read — same pattern pushOs uses for `note`. */
const looseStr = (e: ManduEvent, k: string): string | null => {
  const v = (e as unknown as Record<string, unknown>)[k];
  return typeof v === "string" ? v : null;
};

/** The net_action `withheld` list, normalized across BOTH wire shapes:
 *  `string[]` (net-proxy proxy.ts) and `{symbol}[]` (the refuse body). */
const looseWithheld = (e: ManduEvent): string[] => {
  const v = (e as unknown as Record<string, unknown>)["withheld"];
  if (!Array.isArray(v)) return [];
  const out: string[] = [];
  for (const w of v) {
    if (typeof w === "string") out.push(w);
    else if (w && typeof w === "object" && typeof (w as { symbol?: unknown }).symbol === "string") {
      out.push((w as { symbol: string }).symbol);
    }
  }
  return out;
};

/** "Where it came from" — event provenance (`ms` stays an epoch number; the
 *  shell formats). */
const provenanceItems = (e: ManduEvent): DetailItem[] => [
  // A claim (arbiter-human-plane.md §10.2): the arbiter got it where the
  // agent's own programs reach, so the emitter below is the sender's word.
  ...(e.claimed === true
    ? [{ text: "CLAIMED: sent on a channel the agent's own programs can reach; every field below, the recorder included, is the sender's word" }]
    : []),
  { text: `recorded by: ${e.emitter}${e.claimed === true ? " (claimed)" : ""}` },
  { text: `chokepoint: ${whereLabel(e.boundary)}` },
  { text: `event seq ${e.seq}, recorded`, ms: Date.parse(e.ts) },
];

/** "Where it's specified" — decision provenance from the event's ruleRef;
 *  absence stated in words. */
const specifiedItems = (e: ManduEvent): DetailItem[] => {
  const ref = e.policy?.ruleRef;
  if (!ref) return [{ text: "no rule reference recorded on this event" }];
  const by =
    ref.source === "rule" ? "policy rule"
    : ref.source === "verdict" ? "a standing human verdict"
    : "the fail-closed default";
  return [{ text: `decided by ${by}: ${ref.id}` }];
};

/** The one shared skeleton — the fixed section template can't drift. */
function baseDetail(e: ManduEvent, what: DetailItem[], decided: DetailItem[]): DetailSection[] {
  return [
    { label: "What this is", items: what },
    { label: "What it decided", items: decided },
    { label: "Where it's specified", items: specifiedItems(e) },
    { label: "Where it came from", items: provenanceItems(e) },
  ];
}

function netSentence(action: string | null, usage: string | null): string {
  switch (action) {
    case "blocked":
    case "block":
      return "A network egress the chokepoint refused: the request never left the machine.";
    case "forwarded":
    case "forward":
      return "A network egress the chokepoint forwarded to its destination.";
    case "passthrough":
      return "Network traffic the chokepoint passed through unchanged.";
    case "tunneled":
      return "An encrypted tunnel the chokepoint relayed without reading its contents.";
    case "forward_error":
      return "A network egress that failed in transit: the forward attempt errored.";
    case "loop_detected":
      return "A request the chokepoint refused because it looped back into the proxy.";
  }
  if (usage === "deny") return "A network action the policy denied.";
  if (usage === "allow") return "A network action the policy allowed.";
  if (usage === "needs_approval") return "A network action held for a human decision.";
  return "A network action recorded at the network chokepoint.";
}

export function netDetail(e: ManduEvent): DetailSection[] {
  const action = looseStr(e, "action");
  const decided: DetailItem[] = [
    fact("action", action),
    fact("method", looseStr(e, "method")),
    fact("destination", looseStr(e, "destination")),
    fact("note", looseStr(e, "note")),
  ];
  const result = e.output?.symbolized;
  if (result) decided.push({ text: `result: ${capVal(result)}` });
  decided.push(fact("Why", e.policy?.reason ?? looseStr(e, "reason")));
  for (const sym of looseWithheld(e)) {
    decided.push({ text: `withheld: ${sym} — its value never left the machine` });
  }
  return baseDetail(e, [{ text: netSentence(action, e.policy?.usage ?? null) }], decided);
}

export function execDetail(e: ManduEvent): DetailSection[] {
  const usage = e.policy?.usage ?? null;
  const what =
    usage === "deny"
      ? "An exec the chokepoint denied: the command was rewritten to a failing sentinel — the original command never ran."
      : usage === "allow"
        ? "An exec the chokepoint allowed to run."
        : usage === "needs_approval"
          ? "An exec held for a human decision."
          : "An exec decision recorded at the exec chokepoint.";
  const decided: DetailItem[] = [
    fact("gated input", e.input?.symbolized),
    fact("result", e.output?.symbolized),
    fact("shell", e.policy?.shell),
    fact("Why", e.policy?.reason ?? looseStr(e, "reason")),
    fact("decision", usage),
  ];
  return baseDetail(e, [{ text: what }], decided);
}

export function fsDetail(e: ManduEvent): DetailSection[] {
  const usage = e.policy?.usage ?? null;
  const what =
    usage === "deny"
      ? "A filesystem action the chokepoint denied."
      : usage === "allow"
        ? "A filesystem action the chokepoint allowed."
        : usage === "needs_approval"
          ? "A filesystem action held for a human decision."
          : "A filesystem action recorded at the filesystem chokepoint.";
  const trust = e.policy?.trust;
  const classified = trust
    ? e.policy?.category ? `${trust} (${e.policy.category})` : trust
    : null;
  const decided: DetailItem[] = [
    fact("operation", e.input?.symbolized),
    fact("result", e.output?.symbolized),
    fact("classified", classified),
    fact("Why", e.policy?.reason),
    fact("decision", usage),
  ];
  return baseDetail(e, [{ text: what }], decided);
}

/** Uncorrelated path_rewrite only — the CORRELATED path keeps dvPathBand
 *  (already shows every field spatially) and gets no ⓘ (documented decision). */
export function pathRewriteDrawer(e: ManduEvent, d: PathRewriteDetail): DetailSection[] {
  const what =
    d.direction === "forward"
      ? "A path spelling translated on the model wire: the HumanView spelling the model used was rewritten to its AgentView twin for the agent to execute on."
      : "A path spelling translated on the model wire: the AgentView spelling the agent produced was rewritten back to its HumanView twin for the model to see.";
  const decided: DetailItem[] = [
    fact("field", d.field),
    { text: `HumanView spelling: ${capVal(d.human)}` },
    { text: `AgentView twin: ${capVal(d.agent)}` },
    fact("Why", e.policy?.reason),
  ];
  return baseDetail(e, [{ text: what }], decided);
}

/** The user-reply desymbolize card (reply-filter). */
export function replyFilterDetail(e: ManduEvent, syms: string[]): DetailSection[] {
  const what =
    "The user-reply surface: the reply filter resolved symbol tokens in the terminal stream the human sees — the agent's context keeps the symbols.";
  const decided: DetailItem[] = syms.length
    ? syms.map((s) => ({ text: `resolved: ${s} → original, in the human's terminal only` }))
    : [{ text: "no symbol tokens resolved in this frame" }];
  return baseDetail(e, [{ text: what }], decided);
}

/** Generic uncorrelated guard card (desymbolize / egress_request / egress_decision). */
const GENERIC_SENTENCES: Partial<Record<EventKind, string>> = {
  desymbolize: "A symbol resolved back to its original at an egress surface.",
  egress_request: "A question for the data-usage policy: may this symbol's value leave through this destination?",
  egress_decision: "The recorded verdict on an egress request.",
};
export function genericDetail(e: ManduEvent): DetailSection[] {
  const what = GENERIC_SENTENCES[e.kind] ?? `A ${e.kind} event recorded by ${e.emitter}.`;
  const decided: DetailItem[] = [
    fact("input", e.input?.symbolized),
    fact("output", e.output?.symbolized),
    fact("Why", e.policy?.reason),
    fact("decision", e.policy?.usage),
  ];
  return baseDetail(e, [{ text: what }], decided);
}

/** One `<name> ← <field ?? origin>` mint line for the birth card's
 *  "What it did" section (a mint decides nothing). */
export const birthItem = (r: SymbolRef): DetailItem =>
  ({ text: `${r.name} ← ${r.field ?? r.origin ?? "(source not recorded)"}` });

/** The fs-sync batch birth card's drawer. The second slot is "What it did":
 *  a mint decides nothing. Provenance = the batch's FIRST event. */
export function birthDetail(e: ManduEvent, refs: SymbolRef[]): DetailSection[] {
  return [
    {
      label: "What this is",
      items: [
        { text: "A symbol minted at the filesystem chokepoint: fs-sync replaced this file's untrusted content with a symbol on disk, so the agent reads the symbol — the raw bytes never enter the model's context." },
      ],
    },
    { label: "What it did", items: refs.map(birthItem) },
    {
      label: "Where it's specified",
      items: [{ text: "no rule reference recorded — a mint, not a gate decision" }],
    },
    { label: "Where it came from", items: provenanceItems(e) },
  ];
}

/** The batch birth card's fixed title (one card per consecutive run of births). */
export const BIRTH_TITLE = "symbolize · workspace sync";
