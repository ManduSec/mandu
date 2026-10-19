/**
 * view-model/block-why — why Mandu blocked or held one step, in the
 * product's words (dashboard.md §4.25b, *A block says why*). Mandu-new (no
 * reference origin).
 *
 * The page said "Mandu stopped it." and "The request never left this
 * machine." and never why, though every gate event records the rule that
 * decided it (`policy.ruleRef`, the arbiter's catalog
 * `arbiter/policy/rule-ref.ts` `RULES`, plus the model proxy's own
 * fail-closed ids). This module words a curated set of those ids.
 *
 * HONEST CLAIMS ONLY. A sentence says only what the branch that emits its id
 * decides: `decideDesymbolization`, `wireSchemeRefusal` and
 * `wirePositionRefusal` (policy-interface.ts), `decideSessionEgress` (session-egress.ts),
 * `execGate` (exec-gate.ts), the escalation wrap (ipc/server.ts),
 * `decideFsPath` (fs-outbound.ts) and the model proxy's net gate
 * (net-gate.ts). An id this module does not know, an allowing rule, an id
 * of the frozen integrity axis (an untrusted item: `egress:symbol-as-command`,
 * `egress:untrusted-destination`) and an id whose words would need more than
 * the event holds (`egress:secret-bound-approval`, whose reason depends on
 * how the secret's flow was shaped) give no line: the step reads as before.
 * `tests/stack/block-why.test.ts` pins every `egress:`, `exec:`, `fs:` and
 * `session:` id here to a deny outcome in the catalog.
 *
 * NEVER A VALUE OR A TOKEN. A line reads the rule id, the destination host
 * the event recorded and how many items the step carried, nothing else; the
 * secret itself is the step's own sentence's ("…that carried your secret
 * `STRIPE_KEY`").
 *
 * THE INSPECTOR TOO (dashboard.md §4.2f, *A check says why*). dual-lanes
 * stamps the same words on a blocked or held check (`DualGate.why`, an OS
 * step's `why`), so the inspector's trace says beside its ⚖ rule chip what
 * the session page says. The decision is the one the inspector's line draws
 * (`checkOutcome`), so a why never sits under a check that let the call
 * through.
 *
 * Vocabulary: the product's (rule-words.ts `TERMS`, the §4.18 sweep): never
 * symbol, egress, binding, AgentView or `$MDU:`. Pure, no I/O.
 */

import type { StoryPart } from "./agent-page-types.js";

/** The decision provenance a gate event records (dual-lanes `DualGate`). */
export interface WhyRuleRef {
  source: string;
  id: string;
}

export interface WhyContext {
  /** What the page says of the step: only a block or a wait has a why. */
  outcome: "blocked" | "waiting";
  /** The destination host the event recorded, for a send; else absent. */
  host?: string | null;
  /** How many masked items the send carried, when the event recorded them. */
  carried?: number;
}

const t = (text: string): StoryPart => ({ kind: "text", text });
const c = (text: string): StoryPart => ({ kind: "code", text });

/** "this secret", "one of these secrets", "the secret it carried". */
function theSecret(carried: number | undefined): string {
  if (carried === undefined || carried < 1) return "the secret it carried";
  return carried === 1 ? "this secret" : "one of these secrets";
}

/** "`api.stripe.com`" as code, or "there" when no host was recorded. */
function toHost(host: string | null | undefined): StoryPart[] {
  return host ? [t(" to "), c(host)] : [t(" there")];
}

const OR_YOUR_OK = " Mandu sends a secret only where a rule lets it go, or with your OK.";
const COULD_NOT_CHECK = "Mandu could not check every place this request was going, so it sent nothing.";
const WHICH_FILE = "Mandu could not tell which file it was, so it would not guess.";

/** The words for each rule id, by the branch that emits it. */
const WHY: Record<string, (ctx: WhyContext) => StoryPart[]> = {
  // ── The egress gate (decideDesymbolization, confidentiality §3.2) ──
  "egress:secret-unbound": (x) => [t(`No rule lets ${theSecret(x.carried)} go`), ...toHost(x.host), t("." + OR_YOUR_OK)],
  "egress:secret-unknown-destination": () => [t("Mandu could not tell where this request was going." + OR_YOUR_OK)],
  "egress:secret-https-only": () => [t("Mandu fills this secret in only in requests it knows are HTTPS, and this one was not.")],
  // Also when the caller stated no position at all (the model proxy's
  // pre-check, the Rust net-supervisor): the words claim only that Mandu
  // could not confirm the header was the one place (2026-10-10).
  "egress:secret-wire-position": () => [t("Mandu fills this login secret in only in a request's Authorization header, and could not confirm that is the only place this request carried it.")],
  "egress:secret-model-context": () => [t("Mandu never gives a secret's real value to the AI.")],
  "egress:obsolete-symbol": () => [t("The placeholder stands for a value that has changed since, so Mandu would not guess which one to send.")],
  "egress:invalid-symbol": () => [t("Mandu could not read a placeholder in it, so it would not guess.")],
  "egress:user-rule-block": () => [t("One of your rules blocks sending this data there.")],
  "egress:disposition-block": () => [t("Your rules block this kind of send instead of asking you.")],
  // The net-proxy's check for a placeholder a shell emptied (confidentiality
  // §7): nothing was in the request to send or to approve.
  "egress:shell-expanded-placeholder": () => [t("The program's shell had emptied the secret's placeholder (it was not in single quotes), so the request carried neither your secret nor its placeholder. Mandu stopped it so it would not fail unseen, and told the AI how to quote it. There is nothing to approve.")],
  // ── The session gate (decideSessionEgress, confidentiality §4) ──
  "session:high-unbound": (x) => [
    t("This session read a secret, and "), ...(x.host ? [c(x.host)] : [t("this place")]),
    t(" is not a place it may go. The AI could pass a secret on in its own words, which no placeholder marks."),
  ],
  // A HIGH session's command (confidentiality.md §4, 2026-10-11): no gate can
  // tell whether it sends anything, so it waits for your OK.
  "session:high-shell": () => [
    t("This session read a secret, and Mandu cannot tell whether this command sends anything over the network. The AI could pass a secret on in its own words, which no placeholder marks."),
  ],
  // ── The exec gate (execGate) and the escalation wrap ──
  "exec:symbol-in-command": () => [t("The command would run a placeholder as code, and Mandu never runs one.")],
  "exec:tainted-program-text": () => [t("It runs code downloaded from the internet, which can do anything the site that served it wants.")],
  "exec:escalation-approval": () => [t("The command needed the network or your real files. The AI's commands get those only with your OK.")],
  // ── The file gate (decideFsPath) ──
  "fs:sensitive-path": () => [t("Files like this hold keys and passwords, so Mandu asks before the AI can use one.")],
  "fs:default-deny": () => [t("The file is outside the folders this agent works in, so Mandu asks first.")],
  "fs:invalid-path": () => [t(WHICH_FILE)],
  "fs:relative-path": () => [t(WHICH_FILE)],
  // ── The upload gate (decideFileUpload: a tool that sends a file off this
  //    computer without the AI reading it, Claude Code's DesignSync) ──
  "fs:upload-secret-file": () => [t("The AI's tool would have sent a secret file off this computer." + OR_YOUR_OK)],
  "fs:upload-secret-value": () => [t("The file holds one of your secrets, and the AI's tool would have sent it off this computer." + OR_YOUR_OK)],
  "fs:upload-unreadable": () => [t("Mandu could not read the file to check it, so it sent nothing.")],
  "fs:upload-invalid-path": () => [t(WHICH_FILE)],
  "fs:upload-unattested": () => [t("Mandu could not check the upload on its own channel, so it sent nothing.")],
  "fs:upload-process-file": () => [t("The file belongs to a running program or to the system, and Mandu cannot check it the way the tool would read it." + OR_YOUR_OK)],
  "proxy:upload-after-write": () => [t("Another step the AI asked for at the same time runs first and could change the file, so Mandu sent nothing. The AI can send it again on its own.")],
  // ── The model proxy's own fail-closed legs (net-gate.ts, each client) ──
  "proxy:arbiter-unreachable": () => [t("Mandu's service did not answer, so Mandu blocked it to be safe.")],
  "proxy:symbol-in-tls-tunnel": () => [t("Mandu could not fill in the real value inside this tool's encrypted request, so it sent nothing.")],
  "proxy:net-gate-unreadable": () => [t(COULD_NOT_CHECK)],
  "proxy:net-gate-destination-bound": () => [t(COULD_NOT_CHECK)],
  "proxy:net-gate-symbol-bound": () => [t("The request carried more placeholders than Mandu checks at once, so it sent nothing.")],
};

/** Block words in a check's recorded text ("net_action · blocked …",
 *  "BLOCKED → exit 77"): the product page's `BLOCK_RE`. */
const BLOCK_RE = /\b(block(ed)?|den(y|ied)|refused|rejected)\b/i;

/**
 * What a check decided, as the inspector draws its line (app.js
 * `gateDecision`; `stepAsked` before `stepBlocked` on a send): the recorded
 * `usage`, else the block words in its recorded text (a tool card's check
 * text, an OS step's `action`). null: allowed, or not known; no why.
 */
export function checkOutcome(usage: string | null | undefined, recorded: string | null | undefined): WhyContext["outcome"] | null {
  if (usage === "needs_approval") return "waiting";
  if (usage === "deny") return "blocked";
  if (usage === "allow") return null;
  return BLOCK_RE.test(recorded ?? "") ? "blocked" : null;
}

/** The rule ids this module words (the stack test pins them to the catalog). */
export const WHY_RULE_IDS: readonly string[] = Object.keys(WHY);

/**
 * Why a blocked or held step was stopped, from the rule its event recorded;
 * null when there is no rule, the rule is not one this module words, or (a
 * standing answer of the person's) the step was not blocked.
 */
export function blockWhy(ref: WhyRuleRef | null | undefined, ctx: WhyContext): StoryPart[] | null {
  if (!ref || typeof ref.id !== "string") return null;
  // A standing answer (an approval-queue verdict) that blocks: the person's.
  if (ref.source === "verdict") return ctx.outcome === "blocked" ? [t("An answer you gave earlier blocks this.")] : null;
  const words = Object.prototype.hasOwnProperty.call(WHY, ref.id) ? WHY[ref.id] : undefined;
  return words ? words(ctx) : null;
}
