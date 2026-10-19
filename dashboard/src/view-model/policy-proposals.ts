/**
 * view-model/policy-proposals — the product page's "Your agent wants to change
 * a rule" card and the rule-change History (policy-surface.md §8.6,
 * dashboard.md §4.25).
 *
 * The card is decidable WITHOUT trusting the agent: every row is rendered here
 * from the typed edit by a fixed grammar (one plain sentence per op), and the
 * "This would let" lines come from the arbiter's delta by facet, in our own
 * words (the arbiter's `detail` strings are inspector prose). The agent's
 * `reason` is carried SEPARATELY and never enters a row: it is untrusted text
 * (in the default `secrets` mode the agent reads pages in the clear, so a page
 * can write it) and the page shows it last, as the agent's words.
 *
 * A model change (add-model / update-model / remove-model, plan 11 §7.3)
 * shows its address in full, and a `local: true` entry whose host is not on
 * this machine or a local network adds a warning and the typed confirmation:
 * such an entry is the one way a steered agent could ask for a file marked
 * "your own model only" to be sent off the machine.
 *
 * A file a rule names reads `~/…` under `home`, the dashboard's home folder,
 * as the Rules row of the same file does; any other path as recorded
 * (rule-words.ts `tildePath`, dashboard.md §4.34 "`~` is the dashboard's
 * home"). No `home`: every path as recorded.
 */
import { needsHostHint } from "../model-probe.js";
import { endpointPlacement } from "./model-endpoints.js";
import { tildePath } from "./rule-words.js";

/** A sentence part: plain text, or a value shown as code (paths, hosts). */
export type Part = { kind: "text"; text: string } | { kind: "code"; text: string };

/** The arbiter's proposal wire shape (arbiter/ipc/protocol.ts PolicyProposalWire), structurally. */
export interface PolicyProposalRow {
  id: string;
  edits: unknown[];
  reason: string | null;
  requestedBy: string;
  sessionKey: string | null;
  relaxes: Array<{ facet: string; direction: string; subject: string; detail: string }>;
  tightens: Array<{ facet: string; direction: string; subject: string; detail: string }>;
  status: "pending" | "approved" | "denied" | "superseded";
  createdAt: number;
  resolvedAt: number | null;
  resolvedBy: string | null;
  changeId: string | null;
  supersededBy: string | null;
  /** A held disk change (policy-surface.md §8.4.6): policy.yaml was
   *  changed on disk and would loosen the rules; absent from an older arbiter. */
  diskHash?: string | null;
}

/** The arbiter's change wire shape (PolicyChangeWire), structurally. */
export interface PolicyChangeRow {
  id: string;
  /** The last five are writes outside the policy surface (§4.25j). */
  via: "agent-tighten" | "tighten" | "proposal" | "undo" | "disk" | "apply" | "mint-rule" | "export-labels" | "pin-reader" | "move-labels";
  requestedBy: string;
  sessionKey: string | null;
  edits: unknown[];
  delta: Array<{ facet: string; direction: string; subject: string; detail: string }>;
  proposalId: string | null;
  createdAt: number;
  undoneAt: number | null;
  undoneBy: string | null;
  undoable: boolean;
  /** Who first asked, when the change answers a proposal (`via` "proposal":
   *  `requestedBy` is then the approver) or applies a suggestion of Mandu's
   *  scan (`mandu:scan`). Absent from an arbiter predating it (dashboard.md
   *  §4.25i). */
  proposedBy?: string | null;
  /** The Rules page rows the change wrote; absent from an older arbiter. */
  rules?: Array<{ rowIds: string[]; added: boolean; removed: boolean; current: boolean }>;
}

export interface ProposalCardVM {
  id: string;
  status: PolicyProposalRow["status"];
  /** Who asked, in plain words ("Your agent"). */
  requester: string;
  /** The session of the agent that asked: its page links the request, and
   *  the card links its page (dashboard.md §4.25 *A rule change and the
   *  agent that asked*). Null for anyone else, and for a request with no
   *  session recorded. */
  session: string | null;
  /** Your agent asked (`requestedBy` is `agent:…`, which the arbiter sets
   *  for every request over the data socket, and only for those). False
   *  for your own request left waiting, the setup assistant and a held
   *  change to policy.yaml: the page never credits those to your agent
   *  (dashboard.md §4.25 *A rule change you asked for is never credited
   *  to your agent*). */
  byAgent: boolean;
  /** The card's first sentence: who wants what (a held disk change says
   *  that nothing changes until you approve). */
  headline: string;
  /** A change made to policy.yaml on disk, held because it loosens the rules
   *  (§4.6): it has no rows, only what it would let. */
  onDisk: boolean;
  /** One sentence per edit, from the grammar. Never contains the reason. */
  rows: Part[][];
  /** What approving gives up, in plain words (empty when the change only
   *  waits because of the per-session tightening cap). */
  wouldLet: Part[][];
  /** The change only tightens but the agent hit its per-session cap. */
  capped: boolean;
  /** Needs the typed word ALLOW before Allow enables. */
  overBroad: boolean;
  /** Warnings about what the change names (a model of "your own" at an
   *  address off this machine); empty for most changes. */
  warnings: Part[][];
  /** The words of whoever asked (the agent's when `byAgent`: UNTRUSTED);
   *  render as text, last. */
  reason: string | null;
  createdAt: number;
}

export interface ChangeRowVM {
  id: string;
  /** Who did it, in plain words. */
  sentence: string;
  /** The session of the agent that made the change, or asked for it: the
   *  row links its page, as the Rules origin line does (dashboard.md §4.25
   *  *A rule change and the agent that asked*). Null for anyone else, and
   *  for a change with no session recorded. */
  session: string | null;
  rows: Part[][];
  createdAt: number;
  undone: boolean;
  undoable: boolean;
}

const t = (text: string): Part => ({ kind: "text", text });
const c = (text: string): Part => ({ kind: "code", text: String(text) });

/** Names in a row (a rule's hosts, a list's entries): one code each, ", "
 *  between, so the page keeps each short one whole and a line breaks
 *  between names (dashboard.md §4.25u, *A rule change names each host*).
 *  The text is the names joined with ", ", as one code said it. */
function codeList(names: readonly string[]): Part[] {
  return names.flatMap((n, i) => (i ? [t(", "), c(n)] : [c(n)]));
}

function str(v: unknown): string {
  return typeof v === "string" ? v : v === undefined || v === null ? "" : String(v);
}

/** "egress:untrusted-destination" → "untrusted destination" (a built-in rule, in words). */
export function plainRuleName(id: string): string {
  return str(id).replace(/^[a-z-]+:/, "").replace(/-/g, " ");
}

function hostPort(host: unknown, port: unknown): string {
  return str(host) + (port !== undefined && port !== null ? ":" + str(port) : "");
}

/** Where a connection rule lets the agent's programs connect, in the words of
 *  every line that names it (dashboard.md §4.25u, *A rule change names its
 *  port*): a host of `*` is "any address", a port of `*` is "any port", and a
 *  port is never dropped. A named host keeps its code, with its port
 *  (`db.internal:5432`). No port: the edit's own words (the arbiter's
 *  default port shows in the *This would let* line). */
export function connectTarget(host: unknown, port: unknown): Part[] {
  const anyHost = str(host) === "*";
  const hasPort = port !== undefined && port !== null && str(port) !== "";
  if (hasPort && str(port) === "*") return [anyHost ? t("any address") : c(str(host)), t(" on any port")];
  if (anyHost) return hasPort ? [t("any address on port "), c(str(port))] : [t("any address")];
  return [c(hostPort(host, port))];
}

/** A connection allowance in force (a `destinations:` entry as compiled:
 *  its host, port and protocol) as {@link connectTarget} words it, and
 *  " over UDP" for a UDP one: the Rules row of the rule an Approvals card
 *  asked for reads as the card did (dashboard.md §4.25u, *Rules names a
 *  connection in words*). New parts on every call. */
export function connectWords(host: unknown, port: unknown, proto: unknown): Part[] {
  return [...connectTarget(host, port), ...(str(proto) === "udp" ? [t(" over UDP")] : [])];
}

/** The arbiter's connection subject (`proto:host:port`, compiled-policy.ts
 *  `connectAllowSpecs`) as {@link connectWords} words it. An unparsable
 *  subject is shown as recorded, without its protocol. */
function connectSpecWords(spec: string): Part[] {
  const m = /^(tcp|udp):(.+):([^:]+)$/.exec(spec);
  if (!m) return [c(spec.replace(/^(tcp|udp):/, ""))];
  return connectWords(m[2], m[3], m[1]);
}

/** A level as the Rules page names it (the glossary's words). */
export function labelLevelWords(level: unknown): string {
  return level === "no-model" ? "No AI"
    : level === "local-model" ? "Your own AI only"
    : level === "any-model" ? "Any AI, when it asks"
    : level === "public" ? "Not secret"
    : "an unknown level";
}

/** An exception's row when its pattern is hidden (plan 15 §13.7 item 4). */
export const PATTERN_HIDDEN_LET = " in your prompts through when it matches a pattern you set (sign in as the admin to see it)";

/** The line a listing carries when it hid a pattern (plan 15 §13.7 item 4). */
export const PATTERNS_HIDDEN_NOTE = "Some of these changes let words you chose through the prompt filter. Sign in as the admin to see them.";

/**
 * The edits with each prompt exception's pattern taken out (plan 15 §13.7
 * item 4). An exception's pattern may hold the person's own words, and a
 * GET is open to any same-host process: History and the rule-change cards
 * are read without the admin session too (the product page lists them for
 * anyone with the dashboard), so a read without it gets the edit with no
 * `match` and the row says the pattern is hidden. Pure; the input is not
 * changed. `hidden` says whether any pattern was taken out.
 */
export function hidePromptPatterns(edits: readonly unknown[]): { edits: unknown[]; hidden: boolean } {
  let hidden = false;
  const out = edits.map((raw) => {
    const e = raw && typeof raw === "object" ? (raw as Record<string, unknown>) : null;
    if (!e || (e.op !== "add-prompt-exception" && e.op !== "remove-prompt-exception") || !("match" in e)) return raw;
    hidden = true;
    const { match: _match, ...rest } = e;
    return rest;
  });
  return { edits: out, hidden };
}

/** One edit → one plain sentence. Deterministic; unknown ops say so. Every
 *  path as recorded. */
export function editRow(edit: unknown): Part[] {
  return editWords(edit, "");
}

/** {@link editRow} on a page whose home folder is `home`: a file under it
 *  reads `~/…`. */
export function editWords(edit: unknown, home: string): Part[] {
  const e = (edit && typeof edit === "object" ? edit : {}) as Record<string, unknown>;
  const path = (): Part => c(tildePath(str(e.path), home));
  switch (e.op) {
    case "lock-path": {
      const only = e.recursive === false ? t(" (this item only, not what is inside it)") : null;
      const bindings = Array.isArray(e.bindings) && e.bindings.length ? e.bindings.map(str) : [];
      let parts: Part[];
      // The Rules page's terms (rule-words.ts, dashboard.md §4.25d).
      if (e.level === "no-model") parts = [t("Make "), path(), t(" a secret no AI may read")];
      else if (e.level === "any-model") parts = [t("Make "), path(), t(" a secret any AI may read when it asks")];
      else if (e.level === "local-model") parts = [t("Make "), path(), t(" a secret only your own AI may read")];
      else if (e.level === "public") parts = [t("Mark "), path(), t(" not secret")];
      else parts = [t("Set "), path(), t(" to an unknown level")];
      if (bindings.length) parts.push(t(", may be sent to "), ...codeList(bindings));
      if (only) parts.push(only);
      return parts;
    }
    case "unlock-path":
      return [t("Remove the rule for "), path()];
    case "lock-blob": {
      // Plan 14 §8.2: one old version of a file, named by its content hash.
      const what = [t("the old file version "), c(str(e.blob))];
      const parts: Part[] = e.level === "public"
        ? [t("Mark "), ...what, t(" not secret")]
        : [t("Hide "), ...what, t(" from the AI in every project's history")];
      if (typeof e.note === "string" && e.note) parts.push(t(" ("), c(e.note), t(")"));
      return parts;
    }
    case "unlock-blob":
      return [t("Stop hiding the old file version "), c(str(e.blob))];
    case "trust-origin":
    case "distrust-origin": {
      const where = e.kind === "dir" ? "files under " : e.kind === "channel" ? "messages from " : "";
      return e.op === "trust-origin"
        ? [t("Trust " + (where || "content from ")), c(str(e.pattern)), t(", so it reaches the AI unmasked")]
        : [t("Always mask " + (where || "content from ")), c(str(e.pattern))];
    }
    case "release": {
      const from = e.from && typeof e.from === "object" ? str((e.from as Record<string, unknown>).host) : "";
      const to = e.to && typeof e.to === "object" ? str((e.to as Record<string, unknown>).host) : "";
      const verb = e.mode === "allow" ? "Always allow sending masked data from " : e.mode === "block" ? "Always block sending masked data from " : "Only count masked data sent from ";
      const parts: Part[] = [];
      if (typeof e.id === "string" && e.id) parts.push(t("Change rule "), c(e.id), t(": "));
      parts.push(t(parts.length ? verb.charAt(0).toLowerCase() + verb.slice(1) : verb));
      parts.push(from ? c(from) : t("anywhere"), t(" to "), to === "*" ? t("anywhere") : c(to));
      if (typeof e.expires === "string" && e.expires) parts.push(t(" until "), c(e.expires));
      if (e.mode === "audit") parts.push(t(", which still needs your OK"));
      return parts;
    }
    case "retire-rule":
      return [t("Remove rule "), c(str(e.id))];
    case "set-disposition":
      return e.mode === "block"
        ? [t("Always block, without asking, what the built-in rule "), c(plainRuleName(str(e.rule))), t(" stops")]
        : [t("Ask you again before the built-in rule "), c(plainRuleName(str(e.rule))), t(" stops something")];
    case "allow-connect":
      return [t("Let your agent's programs connect to "), ...connectTarget(e.host, e.port)];
    case "remove-connect":
      return [t("Stop letting your agent's programs connect to "), ...connectTarget(e.host, e.port)];
    case "trust-command":
      return e.trustHelp === true
        ? [t("Show the AI the help text of "), c(str(e.id)), t(" unmasked")]
        : [t("Mask the help text of "), c(str(e.id)), t(" again")];
    case "tool-inbound":
      return e.trust === "TRUSTED"
        ? [t("Show the AI results from the tool "), c(str(e.tool)), t(" unmasked")]
        : [t("Mask results from the tool "), c(str(e.tool))];
    case "list": {
      const add = Array.isArray(e.add) ? e.add.map(str) : [];
      const remove = Array.isArray(e.remove) ? e.remove.map(str) : [];
      const parts: Part[] = [];
      if (add.length) parts.push(t("Add "), ...codeList(add), t(" to the list "), c(str(e.name)));
      if (remove.length) parts.push(t(add.length ? ", and remove " : "Remove "), ...codeList(remove), t(" from it"));
      if (!parts.length) parts.push(t("Create the list "), c(str(e.name)));
      return parts;
    }
    case "add-model":
    case "update-model": {
      const parts: Part[] = e.op === "add-model"
        ? [t("Add the model "), c(str(e.name)), t(" at "), c(str(e.url))]
        : [t("Change the model "), c(str(e.name)), t(" to "), c(str(e.url))];
      parts.push(t(e.local === true ? ", as your own model" : ", as an outside model"));
      if (typeof e.model === "string" && e.model) parts.push(t(", using "), c(e.model));
      if (typeof e.token_env === "string" && e.token_env) parts.push(t(", key from "), c(e.token_env));
      return parts;
    }
    case "remove-model":
      return [t("Remove the model "), c(str(e.name))];
    case "restore-model":
      return [t("Bring back your administrator's model "), c(str(e.name))];
    // Plan 14 §14.1: the sensitivity labels mapped to levels (they change
    // what Mandu's scan suggests, not what is protected now).
    case "map-sensitivity-label": {
      const parts: Part[] = [t("Suggest "), c(labelLevelWords(e.level)), t(" for documents with the sensitivity label "), c(str(e.name) || str(e.id))];
      if (str(e.name)) parts.push(t(" ("), c(str(e.id)), t(")"));
      if (e.level === "public") parts.splice(0, 3, t("Suggest nothing for documents with the sensitivity label "));
      return parts;
    }
    case "unmap-sensitivity-label":
      return [t("Stop suggesting a label for documents with the sensitivity label "), c(str(e.id))];
    // Confidentiality plan 15 §6: the checks on what the person types.
    case "set-prompt-filter": {
      const parts: Part[] = [t(e.on === true ? "Turn on the prompt check " : "Turn off the prompt check "), c(str(e.filter))];
      if (e.on_error === "block") parts.push(t(", and refuse the prompt when it cannot run"));
      else if (e.on_error === "pass") parts.push(t(", and send the prompt unchecked when it cannot run"));
      if (typeof e.endpoint === "string") parts.push(t(", reading your prompts with your model "), c(e.endpoint));
      else if (e.endpoint === null) parts.push(t(", with no model named (it cannot run)"));
      return parts;
    }
    case "set-prompt-action":
      return [t("In your prompts, "), c(str(e.category)), t(promptActionWords(e.action))];
    case "remove-prompt-action":
      return [t("Remove your own rule for "), c(str(e.category)), t(" in your prompts")];
    // Plan 15 §13.7 item 4: with no `match` (hidePromptPatterns: a read
    // without the admin session), the pattern is not shown.
    case "add-prompt-exception":
      return [t("Let "), c(str(e.category)), ...(typeof e.match === "string" ? [t(" in your prompts through when it matches "), c(e.match)] : [t(PATTERN_HIDDEN_LET)])];
    case "remove-prompt-exception":
      return [t("Stop letting "), c(str(e.category)), ...(typeof e.match === "string" ? [t(" in your prompts through when it matches "), c(e.match)] : [t(PATTERN_HIDDEN_LET)])];
    default:
      return [t("A change this page cannot describe ("), c(str(e.op) || "no kind"), t(")")];
  }
}

/** The model edits that declare a model "your own" at an address that is not
 *  on this machine or a local network (the doctor's host hint, plan 11 D6). */
function farOwnModels(edits: readonly unknown[]): Array<{ name: string; url: string }> {
  const out: Array<{ name: string; url: string }> = [];
  for (const raw of edits) {
    const e = (raw && typeof raw === "object" ? raw : {}) as Record<string, unknown>;
    if ((e.op === "add-model" || e.op === "update-model") && e.local === true && needsHostHint(str(e.url))) {
      out.push({ name: str(e.name), url: str(e.url) });
    }
  }
  return out;
}

/** The model edits that send "your own model only" files over plain http
 *  to another machine by the entry's `allow_plain_http` (plan 12 D2). */
function plainHttpOwnModels(edits: readonly unknown[]): Array<{ name: string; url: string }> {
  const out: Array<{ name: string; url: string }> = [];
  for (const raw of edits) {
    const e = (raw && typeof raw === "object" ? raw : {}) as Record<string, unknown>;
    if ((e.op === "add-model" || e.op === "update-model") && e.local === true && e.allow_plain_http === true &&
        /^http:\/\//i.test(str(e.url)) && endpointPlacement(str(e.url)) === "network") {
      out.push({ name: str(e.name), url: str(e.url) });
    }
  }
  return out;
}

/** Warnings a change deserves before anyone allows it. */
export function changeWarnings(edits: readonly unknown[]): Part[][] {
  return [
    ...farOwnModels(edits).map((m) => [
      c(m.name), t(" would count as your own model, but "), c(m.url),
      t(" is not on this machine or a private network address. Files marked \u201cYour own AI only\u201d could then be sent there. Allow it only if you or your organization control that server."),
    ]),
    ...plainHttpOwnModels(edits).map((m) => [
      c(m.name), t(" is at a plain http address on another computer ("), c(m.url),
      t("). Files marked \u201cYour own AI only\u201d would cross the network unencrypted."),
    ]),
  ];
}

/** What a prompt category's action does, as the end of a sentence. */
function promptActionWords(action: unknown): string {
  switch (action) {
    case "block": return " stops the prompt from being sent";
    case "mask": return " is replaced by a placeholder the AI can still use";
    case "redact": return " is removed before the AI reads it";
    case "log": return " is only recorded";
    case "pass": return " is sent as typed";
    default: return ` gets ${str(action)}`;
  }
}

/** A delta row the human would give up, in plain words, by facet. */
export function relaxLine(r: { facet: string; subject: string }): Part[] {
  return relaxWords(r, "");
}

/** {@link relaxLine} on a page whose home folder is `home`: a file under
 *  it reads `~/…`. */
export function relaxWords(r: { facet: string; subject: string }, home: string): Part[] {
  const s = str(r.subject);
  switch (r.facet) {
    case "paths":
      return [c(tildePath(s, home)), t(" would be protected less")];
    case "blob-lock":
      return [t("The old file version "), c(s), t(" could be read by the AI again")];
    case "origins": {
      const m = /^(URL|DIR|CHANNEL):(.*)$/.exec(s);
      const kind = m?.[1];
      const v = m ? m[2]! : s;
      if (v === "default") return [t("Content from unlisted places would be treated differently")];
      const lead = kind === "DIR" ? "Files under " : kind === "CHANNEL" ? "Messages from " : "Content from ";
      return [t(lead), c(v), t(" would reach the AI unmasked")];
    }
    case "command-output":
      return [t("Output of "), c(s), t(" would reach the AI unmasked")];
    case "tools": {
      if (s.endsWith(":resolve")) return [t("The tool "), c(s.slice(0, -":resolve".length)), t(" would send the real data out")];
      if (s.includes(".")) return [c(s), t(" would send the real data out")];
      return [t("Results from the tool "), c(s), t(" would reach the AI unmasked")];
    }
    case "dispositions":
      return [t("The built-in rule "), c(plainRuleName(s)), t(" would ask you instead of blocking")];
    case "user-rules":
      return [t("Rule "), c(s), t(" would let more data leave without asking")];
    case "destinations":
      return [t("Your agent's programs could connect to "), ...connectSpecWords(s)];
    case "apps":
      return [c(s), t("'s output would stay readable after it read a secret")];
    case "env":
      return [t("The environment variable "), c(s), t(" would be shown to the AI in the clear")];
    case "models":
      return [t("The models Mandu knows would change for "), c(s), t(". They decide which model counts as your own, and which main model Mandu keeps checking")];
    case "perimeter":
      return s === "networks"
        ? [t("Your own models on other computers would no longer be held to your organization's networks")]
        : [t("A model at an address in "), c(s), t(" could count as on your organization's network")];
    // Plan 14 §14.1: the subject is the label's GUID (and its tenant's).
    case "sensitivity-labels":
      return [t("Mandu would suggest less for documents with the sensitivity label "), c(s)];
    // Plan 15 §6: the subject names a check, a category or an exception.
    case "prompt-filters":
      // Plan 15 phase 3: a classifier's model moves (or goes): what you type
      // is read by another of your own models, or the check cannot run.
      if (s.startsWith("prompt filter model ")) return [t("Another model of your own would read what you type for the check "), c(s.slice("prompt filter model ".length))];
      return [t("Less of what you type would be checked before the AI reads it: "), c(s)];
    default:
      return [t("A change Mandu cannot check for you: "), c(s)];
  }
}

/** Rows that deserve a typed confirmation: a rule with no limit on one side. */
export function isOverBroad(edits: readonly unknown[]): boolean {
  return edits.some((raw) => {
    const e = (raw && typeof raw === "object" ? raw : {}) as Record<string, unknown>;
    if (e.op === "release" && e.mode === "allow") {
      const from = e.from && typeof e.from === "object" ? str((e.from as Record<string, unknown>).host) : "";
      const to = e.to && typeof e.to === "object" ? str((e.to as Record<string, unknown>).host) : "";
      return from === "" || from === "*" || to === "*";
    }
    if (e.op === "trust-origin") return str(e.pattern).includes("*");
    if (e.op === "allow-connect") return str(e.host) === "*" || str(e.host).startsWith("*");
    return false;
  }) || farOwnModels(edits).length > 0;
}

export function requesterOf(requestedBy: string): string {
  // "file": a held change to policy.yaml; who wrote the file is unknown, so
  // it is never called "you" (§4.25j).
  return requestedBy.startsWith("agent:") ? "Your agent" : requestedBy === "assistant" ? "The setup assistant" : requestedBy === "file" ? "policy.yaml" : "You";
}

/** The first sentence of a held disk change's card (§4.6). */
export function diskHeadline(loosens: number): string {
  return `policy.yaml was changed on disk and would loosen ${loosens} ${loosens === 1 ? "rule" : "rules"}. Nothing changes until you approve`;
}

/** `patterns: false`: a read without the admin session (hidePromptPatterns).
 *  `home`: the dashboard's home folder, so a file under it reads `~/…`. */
export interface PatternView { patterns?: boolean; home?: string }

export function toProposalCard(p: PolicyProposalRow, view: PatternView = {}): ProposalCardVM {
  const all = Array.isArray(p.edits) ? p.edits : [];
  const edits = view.patterns === false ? hidePromptPatterns(all).edits : all;
  const requester = requesterOf(str(p.requestedBy));
  const onDisk = typeof p.diskHash === "string" && p.diskHash !== "";
  const agent = str(p.requestedBy).startsWith("agent:") && !onDisk;
  return {
    id: p.id,
    status: p.status,
    requester,
    session: agent && typeof p.sessionKey === "string" && p.sessionKey !== "" ? p.sessionKey : null,
    byAgent: agent,
    headline: onDisk ? diskHeadline((p.relaxes ?? []).length) : `${requester} ${requester === "You" ? "want" : "wants"} to change a rule`,
    onDisk,
    rows: edits.map((e) => editWords(e, view.home ?? "")),
    wouldLet: (p.relaxes ?? []).map((r) => relaxWords(r, view.home ?? "")),
    capped: (p.relaxes ?? []).length === 0,
    overBroad: isOverBroad(edits),
    warnings: changeWarnings(edits),
    reason: typeof p.reason === "string" && p.reason !== "" ? p.reason : null,
    createdAt: p.createdAt,
  };
}

/** The proposer of a suggestion Mandu's own scan filed (arbiter
 *  policy-proposals.ts SCAN_REQUESTER). */
const SCAN_PROPOSER = "mandu:scan";

/**
 * Who made a recorded change (dashboard.md §4.25i), from what the arbiter
 * recorded: the agent on its own (a tightening), the agent with your approval,
 * a suggestion of Mandu's scan applied from the terminal or by the agent,
 * you on the Rules page, you with Describe a rule, you some other way, or an
 * Undo; and, since §4.25j, writes outside the policy surface: a hand edit of
 * the file (who wrote it is unknown: never called "you"), the developer
 * view, or Mandu pinning a program you allowed. For a proposal, the one who
 * ASKED is `proposedBy`; an arbiter
 * predating that field is read by the approver's name instead (the Rules page
 * approves as `human:rules-page`, Describe as `human:dashboard`, Approvals'
 * approval of an agent's request as `dashboard`).
 */
export type ChangeWho = "agent" | "agent-approved" | "scan-applied" | "rules-page" | "settings" | "describe" | "you" | "undo" | "file" | "file-approved" | "developer" | "mandu" | "moved";
export function changeWho(ch: Pick<PolicyChangeRow, "via" | "requestedBy" | "proposedBy">): ChangeWho {
  if (ch.via === "undo") return "undo";
  // A rule Mandu's scan suggested, applied on the agent's channel (`mandu
  // policy suggest` in a terminal, or a program of the agent): nobody there
  // is attested a person, so it is never "you" (`agent-tighten`; an arbiter
  // before 2026-10-17 recorded it `tighten` by "data-plane").
  if (ch.proposedBy === SCAN_PROPOSER && (ch.via === "agent-tighten" || (ch.via === "tighten" && ch.requestedBy === "data-plane"))) return "scan-applied";
  // A held change to policy.yaml that you approved in Approvals (§4.6).
  if (ch.via === "proposal" && ch.proposedBy === "file") return "file-approved";
  if (ch.via === "disk") return "file";
  if (ch.via === "apply" || ch.via === "mint-rule" || ch.via === "export-labels") return "developer";
  if (ch.via === "pin-reader") return "mandu";
  if (ch.via === "move-labels") return "moved";
  if (ch.via === "agent-tighten") return "agent";
  const asker = ch.via === "proposal" ? ch.proposedBy : ch.requestedBy;
  if (ch.via === "proposal" && (asker === undefined || asker === null)) {
    return ch.requestedBy === "human:rules-page" ? "rules-page" : ch.requestedBy === "human:settings" ? "settings" : ch.requestedBy === "human:dashboard" ? "describe" : "agent-approved";
  }
  if (asker?.startsWith("agent:")) return "agent-approved";
  if (asker === "rules-page") return "rules-page";
  if (asker === "settings") return "settings";
  if (asker === "assistant") return "describe";
  return "you";
}

export function toChangeRow(ch: PolicyChangeRow, view: PatternView = {}): ChangeRowVM {
  const who = changeWho(ch);
  const sentence =
    who === "agent" ? "Your agent tightened your rules"
    : who === "scan-applied" ? "A rule Mandu suggested was applied from the terminal or by your agent"
    : who === "agent-approved" ? "You approved a change your agent asked for"
    : who === "rules-page" ? "You changed a rule on the Rules page"
    : who === "settings" ? "You changed your models in Settings"
    : who === "describe" ? "You changed your rules with Describe a rule"
    : who === "you" ? (ch.via === "tighten" ? "You tightened your rules" : "You changed your rules")
    : who === "file" ? "policy.yaml was edited directly, not through Mandu"
    : who === "file-approved" ? "You approved a change made to policy.yaml directly"
    : who === "developer" ? "You changed your rules in the developer view"
    : who === "mandu" ? "Mandu noted a program you allowed to read a file"
    : who === "moved" ? "You moved rules made on the Rules page into policy.yaml, unchanged"
    : "You undid an earlier change";
  const rows = ch.via === "undo" || !Array.isArray(ch.edits) || ch.edits.length === 0
    ? (ch.delta ?? []).map((d) => [t(d.direction === "relax" ? "Loosened: " : "Tightened: "), c(d.facet === "paths" ? tildePath(str(d.subject), view.home ?? "") : str(d.subject))])
    : (view.patterns === false ? hidePromptPatterns(ch.edits).edits : ch.edits).map((e) => editWords(e, view.home ?? ""));
  const agent = who === "agent" || who === "agent-approved";
  const session = agent && typeof ch.sessionKey === "string" && ch.sessionKey !== "" ? ch.sessionKey : null;
  return { id: ch.id, sentence, session, rows, createdAt: ch.createdAt, undone: ch.undoneAt !== null, undoable: ch.undoable === true };
}

// ── Where each rule came from (dashboard.md §4.25i) ──────────────────────────

/** One line under a Rules row: who put the rule there, and when. */
export interface RuleOriginVM {
  /** False: no recorded change wrote the rule as it stands (it predates the
   *  record, or was written while Mandu was not running). */
  recorded: boolean;
  sentence: string;
  /** When the change was made (epoch ms); null when not recorded. */
  at: number | null;
  /** The agent's session, for "See what the agent was doing"; null unless
   *  an agent asked for the change. */
  session: string | null;
  /** A later edit, not recorded here, changed the rule since. */
  changedSince: boolean;
}

export const UNRECORDED_ORIGIN: RuleOriginVM = {
  recorded: false,
  sentence: "No record of who added this. It was already in policy.yaml before Mandu kept a record, or was written while Mandu was not running",
  at: null, session: null, changedSince: false,
};

function originSentence(who: ChangeWho, added: boolean): string {
  switch (who) {
    case "agent": return added ? "Your agent added this. It only makes your rules stricter, so it did not need your OK" : "Your agent changed this. It only made your rules stricter, so it did not need your OK";
    case "scan-applied": return added ? "Mandu suggested this, and it was applied from the terminal or by your agent. It only makes your rules stricter, so it did not need your OK" : "Mandu suggested this change, and it was applied from the terminal or by your agent. It only made your rules stricter, so it did not need your OK";
    case "agent-approved": return added ? "Your agent asked for this and you approved it" : "Your agent asked to change this and you approved it";
    case "rules-page": return added ? "You added this on the Rules page" : "You changed this on the Rules page";
    case "settings": return added ? "You added this in Settings" : "You changed this in Settings";
    case "describe": return added ? "You added this with Describe a rule" : "You changed this with Describe a rule";
    case "you": return added ? "You added this" : "You changed this";
    case "undo": return "This came back when you undid a change";
    case "file": return added ? "Added to policy.yaml directly, not through Mandu" : "Changed in policy.yaml directly, not through Mandu";
    case "file-approved": return added ? "Added to policy.yaml directly, and you approved it" : "Changed in policy.yaml directly, and you approved it";
    case "developer": return added ? "You added this in the developer view" : "You changed this in the developer view";
    case "mandu": return "Mandu updated this when you let a program read the file";
    case "moved": return "You made this on the Rules page, and it was later moved into policy.yaml unchanged";
  }
}

/**
 * For every row id a recorded change names, the NEWEST change that touched
 * it: who made it, when, and whether it still stands as that change left it.
 * A row whose newest change REMOVED it exists again only through an edit
 * nobody recorded, so it reads as not recorded. A row no change names is not
 * in the map (the caller says "no record" only when the list is complete).
 * Changes arrive newest first (the arbiter's order); an arbiter predating
 * `rules` gives nothing to join on, so the map is empty.
 */
export function ruleOrigins(changes: readonly PolicyChangeRow[]): Record<string, RuleOriginVM> {
  const out: Record<string, RuleOriginVM> = {};
  const newestFirst = [...changes].sort((a, b) => b.createdAt - a.createdAt || b.id.localeCompare(a.id));
  for (const ch of newestFirst) {
    const who = changeWho(ch);
    for (const item of ch.rules ?? []) {
      for (const id of item.rowIds) {
        if (id in out) continue;
        out[id] = item.removed
          ? UNRECORDED_ORIGIN
          : {
              recorded: true,
              sentence: originSentence(who, item.added),
              at: ch.createdAt,
              session: who === "agent" || who === "agent-approved" ? ch.sessionKey : null,
              changedSince: !item.current,
            };
      }
    }
  }
  return out;
}
