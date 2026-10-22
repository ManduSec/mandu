/**
 * view-model/mandu-tool-words — the agent's calls to Mandu's OWN rule tools
 * (the mandu-policy server's read, test and propose; policy-surface.md
 * §8.5.1) in the product page's words (dashboard.md §4.25b, "Mandu's own
 * tools").
 *
 * The session page used to tell such a call as "Used `mandu-policy
 * mandu_policy_propose`", although the record holds both what was asked (the
 * typed edits) and what Mandu answered (the server's fixed-shape envelope).
 * Pure; no I/O.
 *
 *   - NAME: only the spellings Mandu's own mount produces count, the list
 *     the arbiter's trust gate keeps (arbiter/policy/policy-tool.ts
 *     `POLICY_TOOL_SPELLINGS`; tests/stack/policy-tool-words.test.ts pins the
 *     two equal). Another server's tool of the same name stays "Used …".
 *   - WHAT WAS ASKED: each edit in the Approvals card's grammar
 *     (policy-proposals.ts `editWords`), with prompt-exception patterns hidden
 *     and a file under the dashboard's home read `~/…`, as there. The agent's
 *     `reason` is untrusted text and is never used.
 *   - WHAT MANDU ANSWERED: read only from a well-formed envelope whose `tool`
 *     names the same tool (interceptors/policy-mcp/src/tools.ts). A masked,
 *     missing or other result has no answer, so the page claims nothing.
 *
 * The parts come back unmasked: the caller (agent-page.ts) masks every
 * `$MDU:` token and cuts long values, as it does for every sentence.
 */
import { editWords, hidePromptPatterns, type Part } from "./policy-proposals.js";
import { tildePath } from "./rule-words.js";

export type ManduPolicyTool = "read" | "test" | "propose";

const SERVER = "mandu-policy";
const BASENAMES: Record<ManduPolicyTool, string> = {
  read: "mandu_policy_read",
  test: "mandu_policy_test",
  propose: "mandu_policy_propose",
};

/** Every spelling of Mandu's own policy tools, as the arbiter's gate keeps
 *  them: Claude Code, OpenCode (one underscore), Codex (the server's "-"
 *  read as "_") and Goose. No bare name: nothing else may claim one. */
export const MANDU_POLICY_TOOL_SPELLINGS: readonly string[] = Object.values(BASENAMES).flatMap((b) => [
  `mcp__${SERVER}__${b}`,
  `${SERVER}_${b}`,
  `mcp__${SERVER.replace(/-/g, "_")}__${b}`,
  `${SERVER}__${b}`,
]);

/** Which of Mandu's policy tools `tool` is, or null for any other name. */
export function manduPolicyTool(tool: string): ManduPolicyTool | null {
  if (!MANDU_POLICY_TOOL_SPELLINGS.includes(tool)) return null;
  for (const kind of Object.keys(BASENAMES) as ManduPolicyTool[]) if (tool.endsWith(BASENAMES[kind])) return kind;
  return null;
}

const t = (text: string): Part => ({ kind: "text", text });
const c = (text: string): Part => ({ kind: "code", text });

function str(v: unknown): string | null {
  return typeof v === "string" && v.trim() ? v.trim() : null;
}

/** A sentence from `editWords` read after "to" or in a list: "Make …" → "make …". */
function lowerFirst(parts: Part[]): Part[] {
  const [first, ...rest] = parts;
  if (!first || first.kind !== "text") return parts;
  return [t(first.text.charAt(0).toLowerCase() + first.text.slice(1)), ...rest];
}

/** A row's list of names (`editWords` draws a rule's hosts and a list's
 *  entries one code each, ", " between) as one code again, so the session
 *  page cuts a long list at `POLICY_VALUE_CAP` as one value (agent-page.ts),
 *  as before (dashboard.md §4.25u, *A rule change names each host*). */
function oneCodePerList(parts: Part[]): Part[] {
  const out: Part[] = [];
  for (const p of parts) {
    const n = out.length;
    const sep = out[n - 1], prev = out[n - 2];
    if (p.kind === "code" && sep?.kind === "text" && sep.text === ", " && prev?.kind === "code") out.splice(n - 2, 2, c(`${prev.text}, ${p.text}`));
    else out.push(p);
  }
  return out;
}

/** At most this many edits are spelled out; the rest are counted. */
export const POLICY_ROWS_CAP = 3;

/** `editWords`' row for an op its grammar does not know. */
const UNKNOWN_ROW = "a change this page cannot describe (";

function proposeSentence(args: Record<string, unknown>, home: string): Part[] {
  const edits = Array.isArray(args["edits"]) ? hidePromptPatterns(args["edits"]).edits : [];
  if (!edits.length) return [t("Asked Mandu to change your rules")];
  const rows = edits.slice(0, POLICY_ROWS_CAP).map((e) => oneCodePerList(lowerFirst(editWords(e, home))));
  if (edits.length === 1) {
    const row = rows[0]!;
    const head = row[0]?.text ?? "";
    if (head === UNKNOWN_ROW) return [t("Asked Mandu for a rule change this page cannot describe ("), ...row.slice(1)];
    // A row that does not start with a verb cannot follow "Asked Mandu to".
    return /^in your prompts\b/.test(head) ? [t("Asked Mandu for a rule change: "), ...row] : [t("Asked Mandu to "), ...row];
  }
  const out: Part[] = [t(`Asked Mandu for ${edits.length} rule changes: `)];
  rows.forEach((row, i) => {
    if (i > 0) out.push(t("; "));
    out.push(...row);
  });
  if (edits.length > POLICY_ROWS_CAP) out.push(t(`; and ${edits.length - POLICY_ROWS_CAP} more`));
  return out;
}

function testSentence(args: Record<string, unknown>, home: string): Part[] {
  const src = args["source"] && typeof args["source"] === "object" && !Array.isArray(args["source"]) ? (args["source"] as Record<string, unknown>) : {};
  const origin = str(src["origin"]);
  const from = origin && tildePath(origin, home);
  const to = str(args["destination"]);
  if (from && to) return [t("Asked Mandu whether data from "), c(from), t(" could be sent to "), c(to)];
  if (to) return [t("Asked Mandu whether data could be sent to "), c(to)];
  if (from) return [t("Asked Mandu how it would treat data from "), c(from)];
  return [t("Asked Mandu how its rules would treat some data")];
}

/** The step's sentence: what the agent asked Mandu, in the page's words; a
 *  file under `home`, the dashboard's home folder, as `~/…`. */
export function policyToolSentence(kind: ManduPolicyTool, args: Record<string, unknown>, home = ""): Part[] {
  if (kind === "read") return [t("Read your Mandu rules")];
  if (kind === "test") return testSentence(args, home);
  return proposeSentence(args, home);
}

/** The result as the policy server's envelope for `kind`, or null. */
function envelopeOf(kind: ManduPolicyTool, result: string | null): Record<string, unknown> | null {
  if (!result) return null;
  let v: unknown;
  try {
    v = JSON.parse(result);
  } catch {
    return null;
  }
  if (!v || typeof v !== "object" || Array.isArray(v)) return null;
  const env = v as Record<string, unknown>;
  return env["tool"] === BASENAMES[kind] ? env : null;
}

/** One part of the step's note: words, and on "Approvals" the id of the
 *  rule change it names (`ask`, as a stop's link names its row): the page
 *  draws it as a link to `/approvals/<id>`, which marks that change
 *  (dashboard.md §4.25b *Mandu's own tools*). An id, never a value. */
export interface PolicyAnswerPart {
  kind: "text";
  text: string;
  ask?: string;
}

/** The shapes of the policy server's ids (policy-proposal-routes.ts
 *  PROPOSAL_ID, CHANGE_ID): any other leaves the words without a link. */
const CHANGE_ID = /^pc-\d+$/;
const PROPOSAL_ID = /^pp-\d+$/;

/** "… in Approvals." with "Approvals" linking `id`, or, with no id of the
 *  right shape, today's words (`plain`). */
function inApprovals(head: string, id: string, shape: RegExp, plain: string): PolicyAnswerPart[] {
  if (!shape.test(id)) return [{ kind: "text", text: plain }];
  return [{ kind: "text", text: head }, { kind: "text", text: "Approvals", ask: id }, { kind: "text", text: "." }];
}

/** "Mandu answered …" for the step's note, from the recorded envelope only:
 *  null when the result is not one (masked, missing, an error, another
 *  shape), so the page says nothing it cannot back. A propose call's note
 *  links the change it made, or the request waiting for you, in Approvals. */
export function policyToolAnswerParts(kind: ManduPolicyTool, result: string | null): PolicyAnswerPart[] | null {
  const env = envelopeOf(kind, result);
  if (!env) return null;
  const words = (text: string): PolicyAnswerPart[] => [{ kind: "text", text }];
  if (kind === "propose") {
    const applied = env["applied"];
    if (applied === true) {
      const changeId = env["changeId"];
      if (typeof changeId !== "string") return words("Nothing changed: your rules already said this.");
      // Only a tightening is applied at once; the envelope lists what it tightened.
      const tightens = Array.isArray(env["tightens"]) && env["tightens"].length > 0;
      const head = tightens ? "Mandu applied it at once, because it only adds protection." : "Mandu applied it at once.";
      return inApprovals(head + " You can undo it in ", changeId, CHANGE_ID, head + " You can undo it under Rule changes in Approvals.");
    }
    if (applied !== false) return null;
    const proposalId = env["proposalId"];
    if (typeof proposalId !== "string") return words("Mandu did not apply it, so nothing changed.");
    const loosens = Array.isArray(env["relaxes"]) && env["relaxes"].length > 0;
    const head = loosens ? "Not applied: it would loosen protection, so Mandu asked for your OK in " : "Not applied: Mandu asked for your OK in ";
    return inApprovals(head, proposalId, PROPOSAL_ID, head + "Approvals.");
  }
  if (kind === "test") {
    const egress = env["egress"];
    const answer = egress === "allow" ? " Mandu answered that it may go there."
      : egress === "ask" ? " Mandu answered that it would ask you first."
      : egress === "block" ? " Mandu answered that it would be blocked."
      : "";
    return words("Only a question: nothing was sent or changed." + answer);
  }
  return null;
}

/** policyToolAnswerParts' words, joined: the step's `note`. */
export function policyToolAnswer(kind: ManduPolicyTool, result: string | null): string | null {
  const parts = policyToolAnswerParts(kind, result);
  return parts ? parts.map((p) => p.text).join("") : null;
}
