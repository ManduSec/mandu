/**
 * prompt-settings — the PRODUCT page's Settings › Prompt filters
 * (confidentiality-plan-15-prompt-filter.md §6, §7, §11 phase 4, §13.7;
 * dashboard.md §4.25y). Mandu-new (no reference origin).
 *
 * Built over the developer panel's own projection (server/prompt-filter-routes.ts
 * `promptFiltersProjection`, the arbiter's `promptFilters` op field by field):
 * the same rows, told in the product's words. A person changes here only
 *
 *   - the action for each kind of finding (`set-prompt-action`, or
 *     `remove-prompt-action` to go back to the default), and
 *   - the exceptions list (`add-prompt-exception`, `remove-prompt-exception`).
 *
 * The switches, the packs, the plugins and the test bench stay in the
 * developer view. Pure; the routes do the arbiter.
 *
 * WHAT IS SHOWN: kinds of finding (categories), actions, who set each, the
 * administrator's file for a lock, and the exceptions' patterns (which the
 * person or the administrator wrote). Never a found value: the projection
 * carries none.
 */

/** The actions a kind may get, weakest first (arbiter/prompt-filter/filter.ts
 *  ACTION_RANK: `log` < `redact` < `mask` < `ask` < `block`). */
export const PROMPT_ACTION_ORDER = ["pass", "log", "redact", "mask", "ask", "block"] as const;
export type PromptActionName = (typeof PROMPT_ACTION_ORDER)[number];

/** The product's word for each action (the maintainer, 2026-10-03: hide =
 *  mask, ask me = ask, block, just note it = log; redact where the plan has
 *  it). `pass` is shown only on a row that already has it. */
export const ACTION_WORDS: Readonly<Record<PromptActionName, string>> = {
  pass: "Send as written",
  log: "Just note it",
  redact: "Remove it",
  mask: "Hide it",
  ask: "Ask me",
  block: "Block the message",
};

/** What each action does, said once under the list. */
export const ACTION_MEANINGS: ReadonlyArray<{ action: PromptActionName; words: string; meaning: string }> = [
  { action: "mask", words: ACTION_WORDS.mask, meaning: "The AI gets a short code in its place. It can still pass the code to a program you allow, which gets the real value." },
  { action: "redact", words: ACTION_WORDS.redact, meaning: "The AI reads a note that something was removed. Nothing of it is kept." },
  { action: "ask", words: ACTION_WORDS.ask, meaning: "The message waits in Approvals until you answer. With no answer in time, it goes with that part hidden." },
  { action: "block", words: ACTION_WORDS.block, meaning: "The message is not sent. The agent tells you why." },
  { action: "log", words: ACTION_WORDS.log, meaning: "The AI reads it as you wrote it. Mandu only notes that it was there." },
];

/** The choices a row offers (not `pass`, unless the row has it now). */
const OFFERED: readonly PromptActionName[] = ["mask", "redact", "ask", "block", "log"];

const SHAPE_WORDS: Readonly<Record<string, string>> = {
  "private-key": "a private key",
  "aws-access-key-id": "an AWS access key",
  "aws-secret-key": "an AWS secret key",
  "github-token": "a GitHub token",
  "gitlab-token": "a GitLab token",
  "anthropic-key": "an Anthropic API key",
  "openai-key": "an OpenAI API key",
  "slack-token": "a Slack token",
  "stripe-key": "a Stripe key",
  "google-api-key": "a Google API key",
  "npm-token": "an npm token",
  "pypi-token": "a PyPI token",
  "huggingface-token": "a Hugging Face token",
  "url-password": "a password in an address",
  "credential-assignment": "a password or key written as a setting",
};

const PII_WORDS: Readonly<Record<string, string>> = {
  email: "an email address",
  "payment-card": "a card number",
  phone: "a phone number",
  person: "a person's name",
  address: "a postal address",
  iban: "a bank account number",
  ssn: "a social security number",
};

/**
 * A kind of finding in plain words, as a noun phrase ("an email address"),
 * or null when Mandu has no words for it (an organization's own category,
 * which the page then shows as written). Pure.
 */
export function categoryWords(category: string): string | null {
  const c = String(category ?? "");
  if (c === "secret.registered" || c.startsWith("secret.registered.")) return "a secret Mandu already knows";
  if (c === "secret.shape") return "something shaped like a key or password";
  if (c.startsWith("secret.shape.")) return SHAPE_WORDS[c.slice("secret.shape.".length)] ?? "something shaped like a key or password";
  if (c === "pii") return "personal information";
  if (c.startsWith("pii.")) return PII_WORDS[c.slice("pii.".length)] ?? "personal information";
  return null;
}

/** A kind's name as a heading: its words with a capital, or the category. */
export function kindName(category: string): string {
  const w = categoryWords(category);
  return w ? w.charAt(0).toUpperCase() + w.slice(1) : category;
}

/** The panel's projection (GET /api/prompt-filters/filters), structurally:
 *  only the fields this section reads. */
export interface PromptFiltersProjection {
  filters?: Array<{ id: string; on: boolean; available?: boolean; categories?: Array<{ category: string; action: string }> }>;
  actions?: Array<{ category: string; action: string; setBy: string; locked: boolean; file?: string }>;
  fallback?: string;
  exceptions?: Array<{ category: string; match: string; setBy: string; file?: string; inForce: boolean }>;
  enforcing?: boolean;
  editable?: boolean;
}

export interface PromptKindVM {
  category: string;
  /** "An email address", or the category as written. */
  name: string;
  /** True when `name` is the category itself (the page shows it as code). */
  named: boolean;
  /** The action in force for it (the longest covering row, never below a
   *  locked administrator's row, else the fallback). */
  action: string;
  actionWords: string;
  /** Who decides it, in a few words ("Set by you", "Mandu's default", "Set
   *  by your administrator (10-org.yaml)", "From your rule for …"). */
  who: string;
  /** A row of the person's own for exactly this kind (Reset removes it). */
  own: boolean;
  /** The administrator locked it: only as strict or stricter is offered,
   *  and `lockedBy` names the file. */
  locked: boolean;
  lockedBy: string | null;
  /** The choices offered; empty when the page cannot write or a lock leaves
   *  nothing to choose. */
  choices: Array<{ action: string; words: string }>;
  /** Reset to the default (remove the person's own row). */
  canReset: boolean;
}

export interface PromptExceptionVM {
  category: string;
  name: string;
  named: boolean;
  match: string;
  who: string;
  /** The person's own: Remove is offered. */
  removable: boolean;
  /** False when a locked administrator's rule keeps it out of force. */
  inForce: boolean;
}

export interface PromptSettingsVM {
  available: boolean;
  editable: boolean;
  /** One line above the list (or why nothing can be changed here). */
  note: string;
  /** False with protection off: Mandu only notes what it finds. */
  enforcing: boolean;
  kinds: PromptKindVM[];
  exceptions: PromptExceptionVM[];
  /** The kinds an exception may name (the add form's choice). */
  exceptionKinds: Array<{ category: string; name: string }>;
  /** Why no exception can be added here, said in place of how to write one
   *  (`exceptionNotOffered`). Null when the form is offered, or when the
   *  page cannot write (the note above says so). */
  exceptionNotOffered: string | null;
  meanings: typeof ACTION_MEANINGS;
}

const isAction = (a: unknown): a is PromptActionName => typeof a === "string" && (PROMPT_ACTION_ORDER as readonly string[]).includes(a);
const rank = (a: string): number => (isAction(a) ? PROMPT_ACTION_ORDER.indexOf(a) : PROMPT_ACTION_ORDER.indexOf("redact"));
const covers = (prefix: string, category: string): boolean => category === prefix || category.startsWith(`${prefix}.`);
const base = (file: string): string => file.split("/").filter(Boolean).pop() ?? file;
const str = (v: unknown, d = ""): string => (typeof v === "string" ? v : d);

/** The action `category` gets under `rows` (the arbiter's `resolveAction`,
 *  mirrored for display: the arbiter decides). Pure. */
export function effectiveAction(rows: NonNullable<PromptFiltersProjection["actions"]>, category: string, fallback: string): { action: string; row: (typeof rows)[number] | null; floor: (typeof rows)[number] | null } {
  let best: (typeof rows)[number] | null = null;
  let floor: (typeof rows)[number] | null = null;
  for (const r of rows) {
    if (!covers(r.category, category)) continue;
    if (best === null || r.category.length > best.category.length) best = r;
    if (r.locked && r.setBy !== "default" && (floor === null || rank(r.action) > rank(floor.action))) floor = r;
  }
  const own = best?.action ?? fallback;
  const action = floor && rank(floor.action) > rank(own) ? floor.action : own;
  return { action, row: best, floor };
}

/** The administrator's lock on `category` under `rows` (the arbiter's
 *  `lockedAction` and `lockedAsk`, arbiter/prompt-filter/policy.ts, mirrored
 *  for display): `action` is the strictest locked row that covers it, and a
 *  let-through is refused unless that is `ask`; `ask` says a locked `ask`
 *  row covers it, and a let-through for the session is refused. Null when no
 *  locked row covers it. The arbiter decides every let-through; this keeps a
 *  page from offering one it refuses. Pure. */
export function lockOf(rows: NonNullable<PromptFiltersProjection["actions"]>, category: string): { action: string; ask: boolean } | null {
  const { floor } = effectiveAction(rows, category, "redact");
  if (floor === null) return null;
  const ask = rows.some((r) => r.locked && r.setBy !== "default" && r.action === "ask" && covers(r.category, category));
  return { action: floor.action, ask };
}

export const READ_ONLY_SETTINGS = "These choices cannot be changed from this page right now. Restart the Mandu service on the current version.";
export const SETTINGS_NOTE = "Mandu checks what you type before the AI reads it. Changes are saved to prompt_filters: in policy.yaml and apply to your next message.";
export const OFF_NOTE = "Protection is off, so Mandu only notes what it finds. These choices apply when it is on.";

/** Why the add form is not offered (dashboard.md §4.25y *An exception that
 *  cannot be added says why*). A default install finds only the secrets it
 *  knows, so these words, not how to write a pattern, are what it shows. */
export const NOT_OFFERED_REGISTERED = "Exceptions are not offered for a secret Mandu already knows: the choice above decides what happens to it.";
export const NOT_OFFERED_REGISTERED_LOCKED = "Exceptions are not offered for a secret Mandu already knows, and your administrator locked the other kinds.";
export const NOT_OFFERED_LOCKED = "Your administrator locked every kind above, so none can have an exception.";
export const NOT_OFFERED_NO_KIND = "There is no kind to add an exception for.";

/** A registered secret has its own ways out (the choice of its kind, the
 *  note under your message), so the add form never names it. */
const isRegisteredKind = (category: string): boolean => category.startsWith("secret.registered");

/** Why no kind can take an exception here, or null when one can (the form
 *  is offered) or nothing can be changed at all. Pure. */
export function exceptionNotOffered(editable: boolean, kinds: readonly Pick<PromptKindVM, "category" | "locked">[]): string | null {
  if (!editable) return null;
  if (kinds.some((k) => !isRegisteredKind(k.category) && !k.locked)) return null;
  const registered = kinds.some((k) => isRegisteredKind(k.category));
  const locked = kinds.some((k) => !isRegisteredKind(k.category));
  if (registered && locked) return NOT_OFFERED_REGISTERED_LOCKED;
  if (registered) return NOT_OFFERED_REGISTERED;
  if (locked) return NOT_OFFERED_LOCKED;
  return NOT_OFFERED_NO_KIND;
}

/** The section's view model from the panel's projection. Pure. */
export function promptSettingsVM(p: PromptFiltersProjection | null | undefined): PromptSettingsVM {
  if (!p || !Array.isArray(p.actions)) {
    return { available: false, editable: false, note: READ_ONLY_SETTINGS, enforcing: false, kinds: [], exceptions: [], exceptionKinds: [], exceptionNotOffered: null, meanings: ACTION_MEANINGS };
  }
  const rows = p.actions.map((r) => ({ category: str(r.category), action: str(r.action), setBy: str(r.setBy, "default"), locked: r.locked === true, ...(typeof r.file === "string" ? { file: r.file } : {}) }));
  const fallback = isAction(p.fallback) ? p.fallback : "redact";
  const editable = p.editable === true;
  // Every kind a rule names, and every kind a check that is on can find.
  const cats = new Set<string>(rows.map((r) => r.category));
  for (const f of p.filters ?? []) {
    if (f.on !== true || f.available === false) continue;
    for (const c of f.categories ?? []) if (typeof c?.category === "string" && c.category) cats.add(c.category);
  }
  const kinds: PromptKindVM[] = [...cats].sort(kindOrder).map((category) => {
    const { action, row, floor } = effectiveAction(rows, category, fallback);
    const ownRow = rows.find((r) => r.category === category) ?? null;
    // A locked administrator's row that covers the kind is a floor (plan 15
    // §6): the person may only choose as strict or stricter, and the page
    // names the file that set it.
    const lockedBy = floor ? (floor.file ? base(floor.file) : "your administrator's settings") : null;
    let who: string;
    if (floor && ownRow?.setBy === "you") who = `Set by you. Your administrator locked it at ${ACTION_WORDS[isAction(floor.action) ? floor.action : "redact"]} or stricter (${lockedBy}).`;
    else if (floor) who = `Locked by your administrator (${lockedBy}).`;
    else if (ownRow?.setBy === "you") who = "Set by you";
    else if (ownRow?.setBy === "administrator") who = `Set by your administrator (${ownRow.file ? base(ownRow.file) : "their settings"})`;
    else if (ownRow) who = "Mandu's default";
    else if (row) who = `From the rule for ${row.category}`;
    else who = "Mandu's default";
    const offered = [...OFFERED, ...(action === "pass" ? (["pass"] as const) : [])]
      .filter((a) => !floor || rank(a) >= rank(floor.action));
    return {
      category,
      name: kindName(category),
      named: categoryWords(category) === null,
      action,
      actionWords: isAction(action) ? ACTION_WORDS[action] : action,
      who,
      own: ownRow?.setBy === "you",
      locked: floor !== null,
      lockedBy,
      // A lock at the strictest action leaves nothing to choose.
      choices: editable && offered.length > 1 ? offered.map((a) => ({ action: a, words: ACTION_WORDS[a] })) : [],
      canReset: editable && ownRow?.setBy === "you",
    };
  });
  const exceptions: PromptExceptionVM[] = (p.exceptions ?? []).map((e) => {
    const category = str(e.category);
    const admin = e.setBy === "administrator";
    return {
      category,
      name: kindName(category),
      named: categoryWords(category) === null,
      match: str(e.match),
      who: admin ? `Set by your administrator (${e.file ? base(e.file) : "their settings"})` : "Added by you",
      removable: editable && !admin,
      inForce: e.inForce !== false,
    };
  });
  return {
    available: true,
    editable,
    note: editable ? SETTINGS_NOTE : READ_ONLY_SETTINGS,
    enforcing: p.enforcing === true,
    kinds,
    exceptions,
    // Not a registered secret (it has its own release paths), not a kind
    // the administrator locked (the validator refuses the exception).
    exceptionKinds: kinds.filter((k) => !isRegisteredKind(k.category) && !k.locked).map((k) => ({ category: k.category, name: k.name })),
    exceptionNotOffered: exceptionNotOffered(editable, kinds),
    meanings: ACTION_MEANINGS,
  };
}

/** Mandu's own kinds first (secrets, then personal information), then the
 *  organization's, each alphabetical. */
function kindOrder(a: string, b: string): number {
  const g = (c: string): number => (c.startsWith("secret.") ? 0 : c === "pii" || c.startsWith("pii.") ? 1 : 2);
  return g(a) - g(b) || a.localeCompare(b);
}

/** The ops this section may send (the panel's change route takes one more,
 *  `set-prompt-filter`, which stays in the developer view). */
export const SETTINGS_PROMPT_OPS: readonly string[] = ["set-prompt-action", "remove-prompt-action", "add-prompt-exception", "remove-prompt-exception"];
