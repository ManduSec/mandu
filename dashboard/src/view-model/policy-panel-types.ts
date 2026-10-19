/**
 * view-model/policy-panel-types — the Policy panel view-model's types (moved
 * out of policy-panel.ts, which re-exports every one of them; the public API is
 * unchanged). Types only: the projection logic stays in policy-panel.ts.
 */

import type { ModelEndpointRow } from "./model-endpoints.js";
import type { PlainRule } from "./rule-words.js";
import type { HolderSourceWire, UsageRuleRow } from "../policy-model.js";
import type { DetailSection } from "./detail.js";
import type { HumanPlaneVM } from "./human-plane.js";
import type { AskWords } from "./ask-words.js";

export type PostureState = "on" | "off" | "unknown";

export type LockdownState = "normal" | "lockdown" | "unknown";

/** Which gate family a verdict row governs, parsed from its queue KEY shape
 * (the store keys all three families into one table — server.ts wraps):
 * `fs:<tool>:<mode>` × path, `exec-escalate:<resource>` × signature, and a
 * `$…` symbol × destination for network egress. */
export type VerdictFamily = "network" | "filesystem" | "exec" | "prompt" | "unknown";

/** The ONE outcome-chip vocabulary (§8) — same three semantic kinds as the
 * per-call ⚖ modal's .policy-usage chips, plus "pending" (styled like
 * needs-approval; a question, not yet law). */
export type OutcomeKind = "allow" | "deny" | "needs-approval" | "pending";

/** ONE row shape for the whole queue — pending, approved and denied rows
 * render in a single filterable table (the merged panel), so their columns
 * cannot drift apart by construction. */
export interface QueueRowVM {
  id: string;
  family: VerdictFamily;
  /** Plain-register chokepoint label (§8 one vocabulary): file / network /
   * exec / model context / any / ?. */
  where: string;
  /** The key's subject half (symbol name / fs:<tool>:<mode> / exec-escalate:<resource> / exec-program:<host>). */
  subject: string;
  /** The key's target half (destination host / path / command signature). */
  target: string;
  status: "pending" | "approved" | "denied";
  /** Status projected onto the shared outcome-chip vocabulary. */
  outcome: OutcomeKind;
  /** The gate reason recorded when the entry was queued (why it needed a
   * human at all) — table-hidden since §8 (lives in the ⓘ drawer). */
  reason: string;
  count: number;
  firstSeen: number;
  lastSeen: number;
  /** When the human resolved it (epoch ms); null while pending and for rows
   * resolved before the audit column existed — rendered as "unknown", not
   * guessed from lastSeen (policy-surface.md §9.6). */
  resolvedAt: number | null;
  /** Distinct session keys that created/bumped this entry (most-recent-last,
   * arbiter-capped) — rendered as links to the responsible sessions. Empty
   * for rows recorded before attribution existed: an honest "—". */
  sessions: string[];
  /** Verdict scope (policy-surface.md §9.8.7): "always" standing, "once"
   * single-use. "always" for pre-scope arbiters too — their verdicts were all
   * standing by construction, so the default is the honest reading. */
  scope: "once" | "always";
  /** Epoch millis a once-scoped verdict was spent by its one use, or null. */
  consumedAt: number | null;
  /** Verdict actions via the same resolveEgressApproval op, labelled in the
   * product's words and order (dashboard.md §4.34): Allow once
   * (approve-once), Always allow (approve), Block (deny) for a pending row;
   * the one-click reversal (Block instead / Allow instead) for a resolved
   * one. `scope: "once"` marks the single-use verb: the shells key the verb
   * off it and `approve`, never off the label. `strip` marks "Send without
   * it" (send-without: a one-shot denial whose use sends the request with a
   * marker where the secret was), offered only on a card the arbiter marks
   * `stripOffered` (§4.34 "Send without it"). */
  actions: { approve: boolean; label: string; scope?: "once"; strip?: true; prompt?: "send" | "mask" | "cancel"; promptScope?: "once" | "session" }[];
  /** An answered "Send without it" (a once denial with the flag). */
  strip?: true;
  /** A waiting card that takes "Send without it" (the arbiter's read-time
   * mark, narrowed here to a card about a secret's placeholder). The
   * product's card adds the answer (home.ts `sendWithoutActions`). */
  stripOffered?: true;
  /** A held message under a LOCKED administrator's `ask` row (plan 15 §12,
   * 2026-10-04): answered for this message only, so `actions` offers no
   * session answer and `words.onlyThisMessage` says why. Absent otherwise. */
  onceOnly?: boolean;
  /** An answer that applies to nothing any more (the arbiter's read-time
   * mark, §4.34 "Answers that no longer apply"): `actions` offers no
   * reversal, since changing it would change nothing; `staleNote` says
   * why in the product's words (rule-words.ts `noLongerAppliesWords`).
   * Absent otherwise. */
  noLongerApplies?: "name-only" | "printer" | "interpreter" | "unvetted";
  staleNote?: string;
  /** The event-side join key (EventPolicy.ruleRef.id, `verdict:<id>`) for a
   * RESOLVED row — phase 3 highlights trace decisions it produced. Null while
   * pending (a pending row has decided nothing). */
  ruleRefId: string | null;
  /* No `detail`: the row's ⓘ drawer (the fixed §8 template) is fetched when
   * it opens, from GET /api/policy/verdict?id=<id> (`verdictDetailOf`). On
   * every row it was about 900 of the row's 1,500 bytes, repeating the row's
   * own fields in sentences (dashboard.md §4.30 "The policy panel's rows"). */
  /** The symbol's origin host (from the arbiter, read-time), or null. */
  originHost: string | null;
  /** Where a secret the row asks about came from, when that is a file path
   *  or an environment variable (`env:NAME`): the arbiter's read-time
   *  `source.origin`, which `describeAsk` names the secret by (dashboard.md
   *  §4.34 "A send names its secret"). Absent for any other origin (a web
   *  address or a command adds no bytes) and when the arbiter did not say. */
  origin?: string;
  /** When the AI first read the row's item as it was, before it was masked,
   *  in a session on the row (ISO time; a pending `$MDU:` row, or a
   *  program's request to read a secret file, `open:`/`trust:`, by that
   *  file): the dashboard's own reading of those sessions' records (lineage
   *  `readFirstByBase`, `readFirstByFile`), so `words` never says the AI
   *  never read it, nor that it has not seen the file (dashboard.md §4.34
   *  "Read before it was marked"). A time, never a value. Absent: none
   *  known. */
  readFirst?: string;
  /** A HIGH session's ask (`session-net:` / `session-exec:`,
   *  confidentiality.md §4, 2026-10-11): what that session read, as the
   *  arbiter attached it (symbols and their origins, never a value), and how
   *  many more; `describeAsk` names them on the card. Absent otherwise. */
  sessionReads?: Array<{ symbol: string; origin: string | null }>;
  sessionReadsMore?: number;
  /** A HIGH session's command ask: whether an allowed run is held by the
   *  guard (only `sessionBindings` reachable, its files labeled) or not
   *  (confidentiality.md §4, "Without the guard"). Absent otherwise. */
  sessionConfined?: boolean;
  sessionBindings?: string[];
  /** A HIGH session's network ask whose latest request was a HELD
   *  command's connection (confidentiality.md §4, "A held command's refused
   *  connection", 2026-10-12): the card says the command's request was
   *  stopped and Allow once lets the next try through. */
  sessionHeld?: boolean;
  /** A FILE's card (egress-hold.md "One card per file", 2026-10-19): the
   *  answer covers this many protected values of the file (two or more);
   *  `describeAsk` says "the secrets in <file>". Absent otherwise. */
  fileValues?: number;
  /** A holder's send question (`holder-send:`, confidentiality plan 13
   *  §5.4, 2026-10-11): every file the program holds as the arbiter
   *  attached it to the pending row (paths and hosts, never a value);
   *  `describeAsk` names the ones in the way, and the product card offers
   *  one *Always* per file (`holderSourceWords`). Absent otherwise. */
  holderSources?: HolderSourceWire[];
  /** The rule this ask could MINT (policy-surface.md §2.5):
   * "anything from <origin> to <target>", offered on a pending NETWORK row.
   * `from` is null when the origin is not a URL (the rule then reads "from any
   * source"). Null when no rule-shaped answer exists (not a network egress). */
  mintable: { from: string; to: string } | null;
  /** The row in the product Rules page's words (§4.25e): for a network
   * answer, the destination and exactly WHICH data it covers. */
  plain: PlainRule;
  /** The question in the product's words (view-model/ask-words.ts, the
   * describeAsk the product home uses; dashboard.md §4.34): a pending row
   * carries the Approvals card's sentence and three cells (each as text
   * and as parts), an answered row its sentence only. "The agent" names who
   * asked: the panel does not know which agent ran the session. */
  words: Pick<AskWords, "family" | "sentence"> & Partial<Pick<AskWords, "why" | "aiNow" | "ifAllowed" | "whyParts" | "aiNowParts" | "ifAllowedParts" | "onlyThisMessage">>;
}

/** One built-in-rule row, projected onto the shared grammar. */
export interface RuleRowVM {
  id: string;
  source: UsageRuleRow["source"];
  boundary: UsageRuleRow["boundary"];
  where: string;
  outcome: OutcomeKind;
  summary: string;
  detail: DetailSection[];
  /** Decisions this rule made (rule_hits; null on arbiters that do not report). */
  hits: number | null;
  lastHit: number | null;
  /** An operator disposition on this rule (policy.yaml rules:), if any. */
  disposition: "ask" | "block" | null;
}

/** Rules grouped by their owning GATE, in catalog order (= evaluation order
 * within the gate). `evaluation` is null when the arbiter shipped no gate
 * catalog — the shell then omits the precedence caption (never invents it). */
export interface GateGroupVM {
  id: string;
  title: string;
  evaluation: string | null;
  rules: RuleRowVM[];
}

/** A posture chip: current state + its ⓘ explanation. */
export interface PostureChipVM {
  state: PostureState | LockdownState;
  detail: DetailSection[];
}

export interface PolicyPanelVM {
  /** False ⇒ no snapshot at all (arbiter down / fixtures mode): the shell
   * renders one quiet status line and nothing else. */
  available: boolean;
  /** False ⇒ a live snapshot WITHOUT the standing-state extension (an old
   * arbiter): posture renders unknown and the Rules section says why it is
   * empty. */
  extended: boolean;
  /** True ⇒ `queue` is the real queue (either from the extended snapshot or
   * the route's approvals-op fallback, which works on ANY arbiter). False ⇒
   * we could not learn the queue at all — the panel must say so, never render
   * an empty list as "no decisions" (the unknown-is-not-off rule applied to
   * rows). Decoupled from `extended` so version skew degrades per-section. */
  verdictsKnown: boolean;
  posture: {
    integrity: PostureChipVM;
    confidentiality: PostureChipVM;
    /** SIEM lockdown (siem-integration.md §4.3): "lockdown" flips every
     * network egress to needs-approval — the panel MUST show it. Absent from
     * the snapshot ⇒ "unknown", never "normal". */
    egress: PostureChipVM;
  };
  /** The human plane's exposure (arbiter-human-plane.md §10.1.1): set by
   * the route (loadPolicyPanel) from the arbiter's `humanPlaneStatus`; absent
   * from the pure snapshot projection. Absent or `unknown` is never walled. */
  humanPlane?: HumanPlaneVM;
  /** The §8 "law source" header line + its ⓘ detail; null when the arbiter
   * predates the field (the shell omits the line — no invented provenance). */
  lawSource: { text: string; detail: DetailSection[] } | null;
  /** The WHOLE queue — pending + approved + denied in one list, newest
   * activity first. The shell filters by status checkbox; the projection does
   * not pre-split, so every filter combination renders the same columns.
   * Every row that decides something is here: every pending ask, every
   * standing answer and every unspent single-use one. Only the HISTORY is
   * windowed: the newest `SPENT_HISTORY_LIMIT` spent single-use answers
   * (they decide nothing any more), the rest counted in `queueOmitted`. */
  queue: QueueRowVM[];
  /** The queue's rows by status over EVERY verdict the arbiter reported,
   * the omitted history included: what a count on the page reads. */
  queueCounts: { pending: number; approved: number; denied: number };
  /** Spent single-use answers older than the history window, not in `queue`. */
  queueOmitted: number;
  /** Built-in rules grouped by gate (§8), catalog order within each. */
  gateGroups: GateGroupVM[];
  /** Kept for cross-checks; the §8 shell renders these inside the
   * fs:sensitive-path rule's ⓘ drawer, not as a dangling section. */
  sensitivePaths: string[];
  /** §8.8: the TRUST side — "what gets symbolized on the way in". Projected
   * from the snapshot's base fields (specId/origins/tools/fallbackTrust),
   * which every arbiter ships (they predate the standing-state extension);
   * null only when there is no snapshot at all. */
  inbound: InboundVM | null;
  /** The operator's law from policy.yaml (policy-surface.md §4,
   * stage 5b), one row grammar for every kind. `null` on arbiters predating
   * the document snapshot — the section renders as unavailable, never as
   * "no rules". */
  yourRules: YourRuleRowVM[] | null;
  /** Every way the compiled law is MORE permissive than the built-ins —
   * always visible (§2.4). Null when the arbiter does not report them. */
  relaxations: RelaxationRowVM[] | null;
  /** Named lists (`lists:` in policy.yaml) a rule may reference as `@name` —
   *  the Lists editor's data. null on an arbiter predating the document. */
  lists: Record<string, string[]> | null;
  /** The policy file's status: `valid:false` ⇒ the file on disk is refused and
   * the last-known-good law is in force — the header shows a banner. */
  policyFile: PolicyFileVM | null;
  /** Plan 11 D2/D6: the declared model endpoints (policy.yaml `models:`),
   * read-only, never a token value. `[]` when the document declares none (or
   * an arbiter predating plan 11 sends a document without the field); null
   * when there is no document at all. The Rules page offers "Your own model
   * only" exactly when a row has `local: true` (`hasLocalModel`). */
  models: ModelEndpointRow[] | null;
  /** Plan 12 D5: the administrator's layer (its files, the lock, the user's
   *  entries it keeps out of force, a refused re-read, the administrator's
   *  entries the user removed), or null. */
  modelsAdmin: { files: string[]; locked: boolean; conflicts: string[]; refused: string[]; removed: Array<{ name: string; file: string }> } | null;
  /** Plan 12 D4: the perimeter in force and who set it, or null. */
  perimeter: { networks: string[] | null; domains: string[]; by: "administrator" | "you" | "narrowed" } | null;
}

/** The kinds a "Your rules" row can be (§4 — one row grammar, many kinds). */
export type YourRuleKind =
  | "lock" // paths: — a secret-file label
  | "trusted-origin" // an allow-listed URL/CHANNEL/DIR origin (its data enters the AI unmasked)
  | "untrusted-origin" // a block-listed origin (its data is masked)
  | "release-allow" | "release-block" | "release-audit" | "release-off" // user_rules
  | "connect-allow" // destinations: — the agent's processes may reach a host:port (stage 4b)
  | "disposition"; // rules: — a built-in ask set to Block

export interface YourRuleRowVM {
  id: string;
  kind: YourRuleKind;
  /** The plain icon for the row (🔒 🌐 📤 ⛔ 🧪 ⏸ ⚙). */
  icon: string;
  /** What the rule is about: a path, a host, a rule id. UNTRUSTED (textContent). */
  subject: string;
  /** The plain-words effect (§4.16 vocabulary). */
  effect: string;
  source: "policy.yaml";
  /** How far it reaches (release rules): "from <origin> to <dest>"; else null. */
  reach: string | null;
  /** True when this row lets MORE through than the built-in law. */
  relaxes: boolean;
  /** Decisions this rule made (null = not tracked by this arbiter). */
  hits: number | null;
  auditHits: number | null;
  lastHit: number | null;
  /** ISO expiry or null; `expired` when that moment has passed. */
  expires: string | null;
  expired: boolean;
  detail: DetailSection[];
  /** The row in the product page's terms (rule-words.ts, dashboard.md §4.25d). */
  plain: PlainRule;
  /** A file rule's reach, for the product page's folder tree (§4.25f):
   *  "subtree" (a folder and everything inside), "exact" (this path only),
   *  "pattern" (every matching file). Absent on every other kind. */
  covers?: "subtree" | "exact" | "pattern";
  /** A "subtree" rule whose path is a file on disk (server/path-kinds.ts):
   *  nothing is inside it, so the page words and draws it as that one file
   *  (§4.25f *A rule on a file reads as a file*). `covers` still says what
   *  the rule reaches, for the edits made on the page. Absent otherwise. */
  pathIsFile?: true;
  /** A file rule's level and the hosts its contents may go to, for the
   *  explorer's label buttons (§4.25n). Absent on every other kind. */
  level?: string;
  bindings?: string[];
  /** A file rule's version as read (the snapshot's `pathVersions`;
   *  policy-surface.md §8.4.6 "An item-level version"): a label chosen on
   *  it in the explorer sends it back, refused once the rule changed.
   *  Absent on every other kind, and from an older service. */
  version?: string;
  /** Plan 13 §5.2: the rule's per-value hosts (`values:`), in document
   *  order. Absent when it has none. The product page shows them read only
   *  in the second menu ("Per value"); they change in policy.yaml. */
  values?: Array<{ key: string; bindings: string[] }>;
  /** A caution under the row: a "your own model only" lock while no model of
   *  your own is declared (dashboard.md §4.25l). Absent otherwise. */
  warning?: string;
  /** The buttons the product Rules page offers (dashboard.md §4.25c). The
   *  server plans the edit from the row id (rule-actions.ts); this only says
   *  which buttons exist. */
  actions: RuleRowActions;
}

export interface RuleRowActions {
  /** Remove is offered. False only for a kind with no edit op (per-program
   *  output rules), which the page says are set in the rules file. */
  remove: boolean;
  /** The one-click flip of a two-state rule, or null. */
  flip: "allow" | "block" | null;
}

export interface RelaxationRowVM {
  kind: string;
  subject: string;
  detail: string;
}

export interface PolicyFileVM {
  path: string | null;
  found: boolean;
  valid: boolean;
  problems: string[];
  loadedAt: number | null;
  refusedAt: number | null;
}

/** One tool row of the §8.8 inbound-trust section. */
export interface InboundToolRowVM {
  tool: string;
  /** The spec's one-line inbound summary; a tool with NO inbound spec says so
   * with its fail-closed consequence. */
  summary: string;
  /** Per-field counts for the at-a-glance cell. Conditional (origin-keyed)
   * fields count as untrusted — they are UNTRUSTED unless proven otherwise. */
  trustedFields: number;
  untrustedFields: number;
  detail: DetailSection[];
}

/** §8.8: the panel-level inbound-trust section — the same spec objects
 * `classify()` reads (policy-snapshot.ts: "cannot diverge from enforcement"),
 * until now rendered only in the per-call ⚖ modal. */
export interface InboundVM {
  specId: string;
  /** The fail-closed line: what happens to tools the spec does not describe. */
  fallbackLine: string;
  /** One pre-rendered line per origin category (id, mode, size, default). */
  originLines: string[];
  /** One row per described tool, spec order. */
  tools: InboundToolRowVM[];
}
