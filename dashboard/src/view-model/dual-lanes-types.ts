/**
 * view-model/dual-lanes-types — the §4.2c DualView lane model's types (moved
 * out of dual-lanes.ts, which re-exports every one it exported before; the
 * public API is unchanged). Types only: the builder is toDualLanes in
 * dual-lanes.ts.
 */

import type { EventKind } from "../event-model.js";
import type { DetailSection } from "./detail.js";
import type { ModelEndpointRef } from "./model-endpoints.js";
import type { StoryPart } from "./agent-page-types.js";
import type { ReadRefusals } from "./secret-note.js";
import type { PatchFile } from "./patch-files.js";

/** One symbol↔raw mapping rendered in a translation band. */
export interface DualBandSym {
  name: string;
  /** privileged resolved original; null when not recorded. */
  value: string | null;
}

/** One P2 ViewMap application (HumanView↔AgentView path spelling), deduped. */
export interface DualPathRewrite {
  direction: "forward" | "reverse";
  tool: string | null;
  field: string | null;
  human: string;
  agent: string;
  /** How many turns re-applied the identical rewrite (history re-sends). */
  repeats: number;
}

/** One gate line on a tool card: text + the ruleRef that decided it (null on
 * pre-provenance events). */
export interface DualGate {
  text: string;
  ruleRef: { source: "rule" | "verdict" | "fail-closed"; id: string } | null;
  /** ⓘ-drawer payload (the fixed template shared with the Policy panel §8) —
   * the gate event's own facts, absent on pre-detail view-models (old bundles
   * degrade button-less). Dedup keeps the FIRST gate's detail. */
  detail?: DetailSection[];
  /** Which guard recorded the check (a command, a request, a file access);
   * the trace names the check by it (dashboard.md §4.2f). Absent on older
   * view-models. */
  kind?: "exec_action" | "net_action" | "fs_action";
  /** What the guard decided, the event's own `policy.usage`; null when the
   * event recorded none. The trace says the decision in words and colours the
   * line by it, never by its kind (an allowed command is not a denial).
   * Absent on older view-models. */
  usage?: "allow" | "deny" | "needs_approval" | null;
  /** On a check that blocked or held the call: why, from its `ruleRef`, in
   * the session page's words (block-why.ts; dashboard.md §4.2f, *A check
   * says why*). Absent when it let the call through, its rule is not one the
   * words cover, or none was recorded. */
  why?: StoryPart[];
  /** On a check that blocked or held the call: the Approvals row Mandu filed
   * for it, the event's `policy.approvalId` (`egr-<n>`; dashboard.md §4.2f,
   * *A check says it asked*). Absent when it filed none, or let the call
   * through. */
  askId?: string;
  /** On a net check: the destination it recorded, the host the call asked
   * for before the proxy rewrote it (the net-proxy's `destination`, else the
   * model proxy's `WebFetch → <host>`); null when it named none. The session
   * page names the host a blocked fetch asked for by it (dashboard.md
   * §4.25b, *A call Mandu rewrote reads as what it stopped*). Absent on
   * other kinds and older view-models. */
  target?: string | null;
}

export interface DualStepBase {
  /** Render/jump id — unique across the trace (prefixed synthetic ids). */
  id: string;
  ts: string;
  turn: number;
  violated: boolean;
}

/** A user prompt — a left-lane blue entry endpoint. The session's FIRST one is
 *  hoisted to the top of the trace; each later prompt renders in flow order. */
export interface DualInputStep extends DualStepBase {
  step: "input";
  text: string;
}

/** T-LLM prose output. The last one is the delivered reply (delivery zone). */
export interface DualResponseStep extends DualStepBase {
  step: "response";
  text: string;
  final: boolean;
  /** Symbols referenced in the text (resolved for the delivery band). */
  symbols: DualBandSym[];
}

/** One tool call, with everything that happened to it folded on. */
export interface DualToolStep extends DualStepBase {
  step: "tool";
  callId: string;
  tool: string;
  trust: "TRUSTED" | "UNTRUSTED" | null;
  /** True → renders as a wall-crossing group (call → HumanView exec → result). */
  crossing: boolean;
  /** True → the tool operated on the AgentView TWIN, not the raw HumanView file:
   *  the fs dual-view chokepoint already symbolized the content ON DISK, so the
   *  agent read a symbol and got a symbol — no untrusted data crosses the wall at
   *  THIS step (it crossed earlier, on disk). Such a read is a pure AgentView
   *  action, NOT a "HumanView (Original) executes" crossing; rendering it as one
   *  put a HumanView label on an agentview-dir path (the visual contradiction this
   *  flag fixes). Detected from the call's OWN result being already-symbolized
   *  (`resultHuman` carries a $MDU: token — the twin's on-disk content) or a
   *  ViewMap path rewrite having translated the path to its twin. Excludes
   *  Quarantine (the U-LLM card owns that lane). */
  readsTwin: boolean;
  /** inspect_symbol / ullm — the right-lane card is the U-LLM (Quarantine) card. */
  quarantine: boolean;
  /** The args T-LLM issued (symbolized spelling). */
  input: string | null;
  /** A patch tool's files, read off its patch's headers as the AI wrote
   *  them (patch-files.ts; dashboard.md §4.25b "A patch names its files").
   *  Absent for any other tool, or a patch that names none. */
  patchFiles?: PatchFile[];
  /** What T-LLM received back (symbol token / trusted passthrough). */
  resultAgent: string | null;
  /** The original raw result (HumanView side). */
  resultHuman: string | null;
  /** Signed out (view-model/redact.ts), where `resultHuman` is left out:
   *  the placeholders it held as written, names only. */
  resultHumanTokens?: string[];
  origin: string | null;
  /** Inbound classification reason (data-trust policy). */
  reason: string | null;
  /** Plan 10 §11.8: the `[mandu:secret]` note the model read with this
   *  result (masked because X read Y / released by rule / denied). */
  secretNote: string | null;
  /** The note's only news is that Mandu refused programs' reads of secret
   *  files (secret-note.ts `readRefusals`: no gate event records them): a
   *  blocked step, and a held read also asked (dashboard.md §4.25b). Counts
   *  only. Absent otherwise. */
  readRefused?: ReadRefusals;
  /** The result reached the AI UNMASKED first (`resultAgent` carries no
   *  token) and a LATER request re-sent it masked: the file was labelled a
   *  secret after the AI read it, and the proxy now masks that history
   *  result (dashboard.md §4.25b, "masked after the fact"). `deliveredTs`:
   *  when the AI got it as it was; `ts`: the first request that carried it
   *  masked; `symbols`: the tokens it was masked to. The step's record stays
   *  what the AI received at its own turn. Absent: nothing changed later. */
  maskedLater?: { ts: string; deliveredTs: string; symbols: string[] };
  /** Outbound egress decision, when one was recorded. */
  usage: "allow" | "deny" | "needs_approval" | null;
  /** Symbols resolved on the way OUT (args → execution): the down band. */
  downSyms: DualBandSym[];
  /** Symbols minted from the result (raw → symbol): the up band. */
  upSyms: DualBandSym[];
  /** WHO performed the raw→symbol rewrite feeding upSyms (the emitter of the
   *  symbolize/tool_result event, e.g. "anthropic-proxy") — the translation bands
   *  name the underlying technique from this. null = not recorded. */
  symbolizedBy: string | null;
  /** WHO resolved symbols on the way out (desymbolize/egress emitter). */
  desymbolizedBy: string | null;
  /** WHO ran the quarantined processing (ullm_call emitter, e.g. "inspect-mcp"). */
  quarantinedBy: string | null;
  /** Plan 11 D6: WHICH model read the datum for an inspect step (the
   *  ullm_call event's `endpoint`): the user's own model or an outside one.
   *  Absent when the event predates the field (renders as before). */
  readBy?: ModelEndpointRef;
  /** §4.14 assignment markers: symbol names FIRST minted at this step — i.e.
   *  not seen earlier in the session by canonical order. Re-emissions (history
   *  re-sends) and re-minted names for an already-banded value are folds, not
   *  births, so a name appears in exactly ONE step's newSymbols per session. */
  newSymbols: string[];
  /** P2 path rewrites recorded for this call (both directions, deduped). */
  pathRewrites: DualPathRewrite[];
  /** Gate decisions folded onto this call (P3 fs denials, the proxies'
   * exec/net gates, which also record each allow): the readable one-liner,
   * the decision provenance chip (policy-surface.md §9.5 — the trace⇄policy
   * join), and the decision itself. */
  gates: DualGate[];
  /** tool_result re-emissions folded into this step (≥1; >1 = history re-sends). */
  repeats: number;
}

/** An uncorrelated OS/quarantine action — a right-lane (HumanView) card. */
export interface DualOsStep extends DualStepBase {
  step: "os";
  kind: EventKind;
  title: string;
  note: string | null;
  quarantine: boolean;
  /** Consecutive identical actions folded into this one (≥1). */
  repeats: number;
  /** Decision provenance for an uncorrelated gate card (policy-surface.md §9.5). */
  ruleRef: { source: "rule" | "verdict" | "fail-closed"; id: string } | null;
  /** The OS interceptor's own `action` field (net: tunneled / forwarded /
   *  passthrough / blocked …), the recorded usage decision, and the net
   *  destination — the paired-rows model (§4.2f) sorts a card into the turn's
   *  background fold or keeps it inline as a decision from these. null when
   *  the event did not record one. */
  action: string | null;
  usage: "allow" | "deny" | "needs_approval" | null;
  target: string | null;
  /** ⓘ-drawer payload (the fixed template shared with the Policy panel §8) —
   * absent on pre-detail view-models. A fold keeps the FIRST card's detail. */
  detail?: DetailSection[];
  /** Plan 11 D6: on an uncorrelated U-LLM card, the endpoint that served it. */
  readBy?: ModelEndpointRef;
  /** net_action only: the symbols the send carried, as the net-proxy
   *  recorded them (net-proxy mitm.ts / proxy.ts): `resolved` on a forwarded
   *  request (their real value was filled in on the way out), `withheld` on
   *  a blocked one. Absent when it recorded none. Such a send is a moment
   *  data leaves (or was kept on) this machine, so paired-rows keeps it
   *  inline (§4.2f). */
  carried?: string[];
  /** §4.14 assignment markers on an OS card: symbol names FIRST minted here —
   * today only the fs-sync batch birth card ("symbolize · workspace sync")
   * populates it. Absent elsewhere; shares the session-wide one-birth-per-name
   * invariant with DualToolStep.newSymbols. */
  newSymbols?: string[];
  /** On an OS step that blocked or held something: why, from its `ruleRef`,
   *  in the session page's words (block-why.ts; §4.2f, *A check says why*),
   *  a send's recorded host named. Absent otherwise, as on `DualGate`. */
  why?: StoryPart[];
  /** On an OS step that blocked or held something: the Approvals row Mandu
   *  filed for it, as on `DualGate`. */
  askId?: string;
  /** net_action only: a FILE decision of the kernel guard (dual-lanes.ts
   *  `fileGuardOf`). Its binary hosts the file guard as well as the connect
   *  guard, and records both as `net_action` (net-supervisor events.rs), so
   *  without this the session page called a refused git read "a connection
   *  to the network". A refused LOCAL socket rides here too (`local-socket`):
   *  a `unix:` destination is a door on this machine, not the network. */
  fileGuard?: FileGuard;
}

/** A file decision the kernel guard recorded as a `net_action`
 *  (net-supervisor events.rs): git kept out of a history holding a locked
 *  secret (`git-lock`), a delete or rename of a `protect:` path, a change
 *  held for the human (`write-protect`), and a reader served the placeholder
 *  copy because a network or FUSE mount could see the read (`raw-withheld`),
 *  and a connect to a Unix socket outside the allow-list (`local-socket`: a
 *  program outside the session listens there, such as the tmux server the
 *  agent itself runs in).
 *  `path`: the repository for `git-lock`; for `local-socket` the socket (its
 *  path, or `@name` for an abstract one; "" when the guard named none); else
 *  the file. `program`: `local-socket` only, the base name of the program
 *  that tried to connect, when the guard named it. */
export interface FileGuard {
  what: "git-lock" | "protected-path" | "write-protect" | "raw-withheld" | "local-socket";
  path: string;
  program?: string;
}

export type DualStep =DualInputStep | DualResponseStep | DualToolStep | DualOsStep;

/**
 * How the lane builder read one `tllm_call` — the self-check seam (render-lint):
 *   - "conversation": the call's prompt list extends the conversation seen so
 *     far (the stateless Messages API replays history, so a genuine agent turn
 *     always extends or equals it).
 *   - "side": a recognized harness side call (isSideCall's string shapes, or —
 *     structurally, when the proxy recorded `callShape` — a request that
 *     carried NO tools: the agent conversation loop always sends the agent's
 *     tool battery).
 *   - "unknown": neither — the shape the NEXT Claude Code release invents, or a
 *     history rewrite (prompt edit+resubmit, /compact). An unknown call with
 *     prose output is exactly what steals the delivered reply, so render-lint
 *     surfaces it as a warning instead of leaving the render silently wrong.
 */
export interface ModelCallClass {
  /** The tllm_call event id. */
  id: string;
  ts: string;
  turn: number;
  cls: "conversation" | "side" | "unknown";
  /** True iff the call produced prose that renders a response card (the only
   *  calls that can take the delivery zone). */
  prose: boolean;
}

export interface DualLanesModel {
  steps: DualStep[];
  /** Total duplicate events folded away (the de-verbosity counter). */
  collapsedCount: number;
  /** Per-tllm_call classification, in canonical order (render-lint's canary). */
  calls: ModelCallClass[];
}
