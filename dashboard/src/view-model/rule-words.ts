/**
 * rule-words — the product Rules page's vocabulary (dashboard.md §4.25d).
 * Mandu-new (no reference origin).
 *
 * One term per idea, each explained once in the page's "What the words mean"
 * list (public/index.html `#rules-glossary`, pinned to TERMS by a test). Every
 * rule row's plain words are built here from these terms, so a row never
 * says a thing the glossary does not explain. The inspector at /dev/ keeps
 * its own wording (policy-panel.ts `effect` / `detail`).
 */

import type { HomeTextPart } from "./ask-words.js";
import { toolFamily } from "./tool-family.js";

export const TERMS = {
  masked: "Masked",
  hidden: "No AI",
  ownModel: "Your own AI only",
  readable: "Any AI, when it asks",
  notSecret: "Not secret",
  trusted: "Trusted source",
  allowed: "Always allowed",
  blocked: "Always blocked",
  ask: "Needs your OK",
  toHosts: "Listed hosts without asking",
  perValue: "Per value",
  answer: "Your answer",
} as const;

/** What each term means, in the order the glossary lists them. A secret
 *  level never promises an OK that a rule skips: a row on the same page
 *  reads "…, may be sent to <host>" (`levelWords`), and an Always-allow
 *  sends with no question, so each says "only where a rule or your OK
 *  allows", Home's words (dashboard.md §4.25d). */
export const GLOSSARY: ReadonlyArray<{ term: string; meaning: string }> = [
  { term: TERMS.masked, meaning: "Before the AI saw it, Mandu replaced the real text with a short code that stands for it. You still see the real text." },
  { term: TERMS.hidden, meaning: "Every AI sees it masked, Mandu's helper included, and your OK does not change that. Only the programs allowed to open it get the real file: ssh, and programs you name, never a database shell. It is sent only where a rule or your OK allows." },
  { term: TERMS.ownModel, meaning: "Only your own AI may read it, when it asks: one you or your organization run, on this computer or your organization's network, listed in Settings › Models. Any other AI sees it masked, and your OK does not change that. It is sent only where a rule or your OK allows." },
  { term: TERMS.readable, meaning: "The AI first sees it masked. When it needs the contents, Mandu's helper reads them for it, or the AI reads them itself. Each read is logged, and your AI provider gets what is read. It is sent only where a rule or your OK allows." },
  { term: TERMS.notSecret, meaning: "Treated like any other file, even if it looks like a secret (a test .env, for example)." },
  { term: TERMS.trusted, meaning: "What comes from it reaches the AI unmasked." },
  { term: TERMS.allowed, meaning: "Happens without asking you." },
  { term: TERMS.blocked, meaning: "Stopped without asking you." },
  { term: TERMS.ask, meaning: "The default: Mandu pauses and asks you first. One exception: a key whose shape names the company that issued it, such as a Stripe or GitHub key, goes to that company's own API without asking (issuer_bindings in policy.yaml turns this off)." },
  { term: TERMS.toHosts, meaning: "For a secret: the hosts listed on its rule get the real value without asking you, over HTTPS too. Any other send still needs a rule or your OK. A program that read two secrets may send only where both may go." },
  { term: TERMS.perValue, meaning: "Shown, greyed, in the second menu of a file that holds several secrets, such as a .env, when each value has its own listed hosts. Those are set in policy.yaml. A program that opened the whole file may send it only where every value may go." },
  { term: TERMS.answer, meaning: "Your choice when Mandu asked and you picked always. For sending, it covers only the data you were asked about, going to that one place. Other data sent there still needs your OK." },
];

/** A rule row in plain words: what it is about, how far it reaches, what it does. */
export interface PlainRule {
  subject: string;
  /** `subject` as parts, when it is words around names: a connection rule
   *  ("any address on port `2222`", policy-proposals.ts `connectWords`), a
   *  send rule to anywhere, a held message's answer ("`acme.codename` in
   *  your message to the AI", `promptAnswerWords`). Their text joined is
   *  `subject`. Absent on every other kind. */
  subjectParts?: HomeTextPart[];
  reach: string | null;
  /** `reach` as parts, when it names something: a send's file, address or
   *  command, a program's files, a send rule's sources, each a code
   *  (§4.25u, *Rules names what a send covers*). Their text joined is
   *  `reach`. Absent when the reach names nothing. */
  reachParts?: HomeTextPart[];
  effect: string;
  /** A send rule that allows or blocks until a moment still to come: that
   *  moment (ISO, the rule's `expires`), which the page draws after
   *  `effect` in the reader's own clock ("Always allowed until Dec 1,
   *  09:00", dashboard.md §4.25u *A rule with an end date says when*).
   *  Absent with no end, and once it has passed ("Expired, no longer used"). */
  until?: string;
  /** A file rule: which programs may open the real file (`opensWords`). */
  opens?: string;
  /** A file rule with `values:` (plan 13 §5.2): where each value may be
   *  sent, as one sentence (`perValueWords`). */
  send?: string;
  /** `send` as parts, each key and host a code (`perValueParts`). */
  sendParts?: HomeTextPart[];
}

/** How one `readers:` entry fares, as the arbiter judges it (plan 13 D8):
 *  `checked` a program Mandu vetted (ssh, ssh-add), `word` one the entry
 *  vouches for (`prints: nothing`), `masked` a listed program that is
 *  neither (it gets the masked copy), `never` one that admits nothing (a
 *  shell, an interpreter, a program that prints files). */
export type OpenerHow = "checked" | "word" | "masked" | "never";

function joinAnd(xs: readonly string[]): string {
  return xs.length <= 1 ? (xs[0] ?? "") : `${xs.slice(0, -1).join(", ")} and ${xs[xs.length - 1]}`;
}

/** The third relation of a label (plan 13 §4.2, Openers), read back as the
 *  Rules row's "Opens it" line (plan 13 §5.3). `list` null: the rule has no
 *  `readers:`, so programs get the masked copy. */
export function opensWords(list: ReadonlyArray<{ name: string; how: OpenerHow }> | null, others?: string): string {
  if (list === null) return "Programs get a masked copy.";
  const real = list.filter((o) => o.how === "checked" || o.how === "word")
    .map((o) => `${o.name} (${o.how === "checked" ? "checked by Mandu" : "your word"})`);
  const masked = list.filter((o) => o.how === "masked").map((o) => o.name);
  const never = list.filter((o) => o.how === "never").map((o) => o.name);
  const out = [real.length ? `${joinAnd(real)} may open the real file.` : "No program opens the real file."];
  if (masked.length) out.push(`${joinAnd(masked)} ${masked.length === 1 ? "gets" : "get"} a masked copy.`);
  if (never.length) out.push(`${joinAnd(never)} never ${never.length === 1 ? "gets" : "get"} the real file: ${never.length === 1 ? "it prints or runs what it reads" : "they print or run what they read"}.`);
  out.push(others === "twin" ? "Other programs get a masked copy." : "Other programs are refused.");
  return out.join(" ");
}

/** The file level as a term, with the places it may still be sent to. The
 *  text of `levelParts`. */
export function levelWords(level: string, bindings: readonly string[] = []): string {
  return levelParts(level, bindings).map((p) => p.text).join("");
}

/** `levelWords` as parts: each host a code of its own (`hostParts`), so the
 *  Rules page keeps a short host whole in a change waiting to be saved and
 *  in Save's confirmation, as it does in *May be sent to* (dashboard.md
 *  §4.25u, *A waiting change names each host*). Every call builds new parts. */
export function levelParts(level: string, bindings: readonly string[] = []): HomeTextPart[] {
  if (level === "public") return [{ kind: "text", text: TERMS.notSecret }];
  // An unknown level reads as hidden (the fail-closed direction).
  const base = level === "any-model" ? TERMS.readable : level === "local-model" ? TERMS.ownModel : TERMS.hidden;
  const to = bindings.filter(Boolean);
  return to.length ? [{ kind: "text", text: `${base}; may be sent to ` }, ...hostParts(to)] : [{ kind: "text", text: base }];
}

/** One sentence from text and parts, in order: neighbouring text joined,
 *  empty text dropped, each part copied. */
export function sentenceParts(...items: Array<string | readonly HomeTextPart[]>): HomeTextPart[] {
  const out: HomeTextPart[] = [];
  for (const item of items) {
    for (const p of typeof item === "string" ? [{ kind: "text" as const, text: item }] : item) {
      if (p.text === "") continue;
      const last = out[out.length - 1];
      if (p.kind === "text" && last?.kind === "text") last.text += p.text;
      else out.push({ ...p });
    }
  }
  return out;
}

/** The destinations half of a label whose values are bound one by one
 *  (plan 13 §5.2, `values:`), in plan 13 §5.3's form: "STRIPE_KEY may be
 *  sent only to api.stripe.com; AWS_* only to *.amazonaws.com; a program
 *  holding the whole file may send it nowhere without asking." A value with
 *  no entry goes where the file's own hosts allow (said only when it has
 *  some); the whole file, where every value may go (`whole`). The text of
 *  `perValueParts`. */
export function perValueWords(
  values: ReadonlyArray<{ key: string; bindings: readonly string[] }>,
  fileBindings: readonly string[],
  whole: readonly string[],
): string {
  return perValueParts(values, fileBindings, whole).map((p) => p.text).join("");
}

/** `perValueWords` as parts: each value's key and each host a code of its
 *  own, a host list's ", " text between them, so the Rules page keeps each
 *  short name whole as Approvals does (dashboard.md §4.25u, *Rules names
 *  each host*). Every call builds new parts. */
export function perValueParts(
  values: ReadonlyArray<{ key: string; bindings: readonly string[] }>,
  fileBindings: readonly string[],
  whole: readonly string[],
): HomeTextPart[] {
  const out: HomeTextPart[] = [];
  const text = (s: string): void => {
    const last = out[out.length - 1];
    if (last?.kind === "text") last.text += s;
    else out.push({ kind: "text", text: s });
  };
  const where = (b: readonly string[], first: boolean): void => {
    if (first) text("may be sent ");
    if (!b.length) { text("nowhere without asking"); return; }
    text("only to ");
    for (const p of hostParts(b)) {
      if (p.kind === "text") text(p.text);
      else out.push(p);
    }
  };
  let clause = 0;
  const next = (): void => { if (clause++) text("; "); };
  values.forEach((v, i) => {
    next();
    out.push({ kind: "code", text: v.key });
    text(" ");
    where(v.bindings, i === 0);
  });
  if (fileBindings.length) { next(); text("any other value "); where(fileBindings, false); }
  next();
  text("a program holding the whole file may send it ");
  where(whole, false);
  text(".");
  return out;
}

/** Hosts as parts: each a code of its own, ", " between them as text (the
 *  text `hosts.join(", ")`). */
export function hostParts(hosts: readonly string[]): HomeTextPart[] {
  const out: HomeTextPart[] = [];
  hosts.forEach((h, i) => {
    if (i) out.push({ kind: "text", text: ", " });
    out.push({ kind: "code", text: h });
  });
  return out;
}

export function pathReach(opts: { recursive: boolean; glob: boolean }): string {
  return opts.glob ? "every matching file" : opts.recursive ? "and everything inside" : "this file only";
}

export function sourceReach(cat: "url" | "dir" | "channel"): string {
  return cat === "dir" ? "a folder" : cat === "channel" ? "a chat channel" : "a website";
}

export function sendWords(mode: string, expired: boolean): string {
  if (expired) return "Expired, no longer used";
  return mode === "allow" ? TERMS.allowed
    : mode === "block" ? TERMS.blocked
    : mode === "audit" ? "Only counted, still needs your OK"
    : "Turned off";
}

export function programWords(output: string): string {
  return output === "clear" ? "Its output reaches the AI unmasked"
    : output === "mask" ? "Only parts of its output are masked"
    : "Its output is masked after it reads a secret file";
}

/** A built-in rule id (`net.untrusted-destination`) as words. */
export function builtinName(id: string): string {
  return id.replace(/^[a-z]+[.:]/, "").replace(/[-_.]+/g, " ");
}

/** A send rule's reach: it covers ANY masked data (from one source, or from
 *  anywhere), unlike an answer, which covers one piece (`answerWords`). */
export function sendRuleReach(from: string | null): string {
  return from ? `sending any masked data from ${from}` : "sending any masked data";
}

/** `sendRuleReach` of a rule's sources as parts: each source a code (the
 *  text `sendRuleReach(from.join(", "))`). No source: no parts. */
export function sendRuleReachParts(from: readonly string[] | null): HomeTextPart[] | undefined {
  return from && from.length ? [{ kind: "text", text: "sending any masked data from " }, ...hostParts(from)] : undefined;
}

/** Where a gated symbol's value came from (the arbiter's read-time `source`,
 *  the symbol table's tool + origin), as words: the file, the web address, or
 *  the command whose output it is. Provenance only, never the value. */
export function dataWords(source: { tool: string; origin: string | null } | null | undefined, home = ""): string {
  return dataParts(source, home).map((p) => p.text).join("");
}

/** `dataWords` as parts: the file, the address or the command a code. */
export function dataParts(source: { tool: string; origin: string | null } | null | undefined, home = ""): HomeTextPart[] {
  if (!source) return [{ kind: "text", text: "the data you were asked about" }];
  const origin = source.origin?.trim() ?? "";
  if (origin.startsWith("/") || origin.startsWith("~")) return [{ kind: "text", text: "the file " }, { kind: "code", text: compactPath(origin, home) }];
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(origin)) {
    try {
      const u = new URL(origin);
      return [{ kind: "text", text: "what was fetched from " }, { kind: "code", text: clip(u.host + (u.pathname === "/" ? "" : u.pathname), 48) }];
    } catch {
      // fall through to the generic wording
    }
  }
  // Any agent's shell (tool-family.ts): its origin is the command. The
  // quotes stay around its code, so the text reads the same without parts.
  if (origin && toolFamily(source.tool) === "exec") return [{ kind: "text", text: "the output of \u201c" }, { kind: "code", text: clip(origin.replace(/\s+/g, " "), 40) }, { kind: "text", text: "\u201d" }];
  return [{ kind: "text", text: `what the ${source.tool} tool returned` }];
}

/** A reach from parts: the text, and the parts only when one is a name. */
function reachOf(parts: readonly HomeTextPart[]): { reach: string; reachParts?: HomeTextPart[] } {
  const merged: HomeTextPart[] = [];
  for (const p of parts) {
    const last = merged[merged.length - 1];
    if (p.kind === "text" && last?.kind === "text") merged[merged.length - 1] = { kind: "text", text: last.text + p.text };
    else merged.push({ ...p });
  }
  const reach = merged.map((p) => p.text).join("");
  return merged.some((p) => p.kind === "code") ? { reach, reachParts: merged } : { reach };
}

/** A past answer (an "always" verdict) as a row: the thing it is about and
 *  exactly how far it reaches. `family` is the queue key's gate family. */
export function answerWords(
  family: string,
  target: string,
  source: { tool: string; origin: string | null } | null | undefined,
  status: "pending" | "approved" | "denied",
  home = "",
): PlainRule {
  const effect = status === "approved" ? TERMS.allowed : status === "denied" ? TERMS.blocked : TERMS.ask;
  if (family === "network") return { subject: target, ...reachOf([{ kind: "text", text: "sending only " }, ...dataParts(source, home)]), effect };
  if (family === "exec") return { subject: target, reach: "running this command", effect };
  return { subject: target, reach: "opening this file", effect };
}

/** Why an answer about a program applies to nothing any more (the
 *  arbiter's read-time `noLongerApplies`, dashboard.md §4.34 "Answers that
 *  no longer apply"), in the product's words. Each place that lists the
 *  answer says it: Approvals › Answered earlier, the Rules page's answers,
 *  the inspector's table. */
export function noLongerAppliesWords(kind: "name-only" | "printer" | "interpreter" | "unvetted"): string {
  switch (kind) {
    case "name-only":
      return "This answer no longer applies: it names the program by its name only, as Mandu asked before October 2, 2026. Mandu now asks about the program's file, so it asks again.";
    case "printer":
      return "This answer no longer applies: the program prints what it reads, so it never gets the real file, and Mandu does not ask about it again.";
    case "interpreter":
      return "This answer no longer applies: it names the interpreter, not the script it runs. Mandu asks about each script on its own.";
    case "unvetted":
      return "This answer no longer applies: the question did not say the program may print what it reads. Mandu asks again, saying so.";
  }
}

/** A past answer about a HIGH session's request or command
 *  (`session-net:<session>` × host, `session-exec:<session>` × command,
 *  confidentiality.md §4, 2026-10-11): it covers that one session only. */
export function sessionAnswerWords(subject: string, target: string, status: "pending" | "approved" | "denied"): PlainRule {
  const effect = status === "approved" ? TERMS.allowed : status === "denied" ? TERMS.blocked : TERMS.ask;
  return subject.startsWith("session-exec:")
    ? { subject: target, reach: "running this command in one session that read a secret", effect }
    : { subject: target, reach: "requests to it from one session that read a secret", effect };
}

/** Confidentiality plan 13 §5.4: a past answer about a program's send of
 *  the files it holds (`holder-send:` × host): the answer covers that set
 *  of files in that session (Allow this session) or one send (Allow once). */
export function holderAnswerWords(files: readonly string[], target: string, status: "pending" | "approved" | "denied", home = ""): PlainRule {
  const effect = status === "approved" ? TERMS.allowed : status === "denied" ? TERMS.blocked : TERMS.ask;
  const more: HomeTextPart[] = files.length > 3 ? [{ kind: "text", text: ` and ${files.length - 3} more` }] : [];
  return { subject: target, ...reachOf([{ kind: "text", text: "a program in one session sending data from " }, ...hostParts(files.slice(0, 3).map((f) => tildePath(f, home))), ...more]), effect };
}

/** Plan 15 §7: a past answer about a found part of the human's own message
 *  (`prompt:<category>#<ref>` × `model:<session>[#turn:<ref>]`). The text
 *  itself is never in the row; the category names it, as code, as the
 *  Approvals card that asked does (§4.25u *Rules names a held message's
 *  answer*). Its effect says what went to the AI, in Approvals' words
 *  ("Sent as written", "Sent masked"): a masked message was not stopped,
 *  which *Always blocked* ("Stopped without asking you") said (§4.25u
 *  *A held message's answer says what was sent*). */
export function promptAnswerWords(subject: string, target: string, status: "pending" | "approved" | "denied"): PlainRule {
  const named = /^prompt:([^#]+)#/.exec(subject)?.[1];
  const category = named ?? "a found part";
  const effect = status === "approved" ? "Sent as written" : status === "denied" ? "Sent masked" : TERMS.ask;
  const message = target.includes("#turn:");
  return {
    subject: `${category} in your message to the AI`,
    ...(named !== undefined ? { subjectParts: [{ kind: "code" as const, text: named }, { kind: "text" as const, text: " in your message to the AI" }] } : {}),
    reach: status === "denied"
      ? (message ? "masked in that one message" : "masked for that session")
      : (message ? "as you wrote it, in that one message" : "as you wrote it, for that session"),
    effect,
  };
}

/** `/home/u/x` → `~/x` under `home`, the dashboard's own home folder;
 *  anything else unchanged, another account's home folder included, so `~`
 *  never names the wrong folder (dashboard.md §4.34 "`~` is the dashboard's
 *  home"). No `home`: unchanged. */
export function tildePath(p: string, home: string): string {
  if (!home || home === "/") return p;
  if (p === home) return "~";
  return p.startsWith(home + "/") ? "~" + p.slice(home.length) : p;
}

/** A long path cut to its last three parts, `~` for the dashboard's home. */
function compactPath(p: string, home: string): string {
  const short = tildePath(p, home);
  if (short.length <= 48) return short;
  const parts = short.split("/").filter(Boolean);
  return parts.length > 3 ? `\u2026/${parts.slice(-3).join("/")}` : short;
}

function clip(s: string, n: number): string {
  return s.length > n ? `${s.slice(0, n - 1)}\u2026` : s;
}
