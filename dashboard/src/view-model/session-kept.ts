/**
 * view-model/session-kept — what Mandu kept from the AI in ONE session, for
 * the line the launcher prints when a `mandu <agent>` session ends
 * (dashboard.md §4.25ah). Mandu-new (no reference origin).
 *
 * The numbers are Home's: the session's secrets as its page's tiles count
 * them (secret-story.ts `SecretsStory.counts`, each secret by its Your
 * secrets card's first line), and the blocked steps and the sends with a
 * real value filled in as its story counts them (agent-page.ts
 * `storyCounts`). Home (home-routes.ts `HomeFacts`) derives both for the
 * same session in the same call that derives this, so the line, the
 * session's Home row and its page always say the same numbers.
 *
 * The words are Home's too ("2 secrets masked before the AI saw them",
 * "1 send with a real value filled in", "1 action blocked", "1 secret the
 * AI read before it was marked a secret"), led by "In this session:" as
 * Home's are by "In the last 24 hours:", and swept for inspector terms by
 * the unit test like every product projection.
 *
 * NEVER A VALUE. A secret is named by what its card says it stands for
 * (`secretWhat`: a variable's name, a key and its file, a file), a send by
 * its host: names, paths and hosts only, a path under the home folder as
 * `~/…`. Each name is plain text with every control character replaced, so
 * a file name cannot drive the person's terminal.
 *
 * TRUTHFUL. A session whose leak check fired claims nothing about what the
 * AI saw (the card's rule). Under `off` (observe only) nothing is masked:
 * the line says so, and names the secrets the record holds that Mandu did
 * not mask, when it holds any (the proxies do not mask in `off`, so most
 * `off` sessions hold none, and then nothing is claimed about what Secrets
 * mode would have masked). A session with nothing to say still gets one
 * short line, so a missing line always means the line was off or could not
 * be read, never "nothing happened".
 *
 * Pure.
 */

import type { SecretsStory, StorySecret } from "./secret-story.js";
import type { StoryPart, StoryTurn } from "./agent-page-types.js";
import type { ProtectionMode } from "./paired-rows.js";

/** Names (or hosts) a fact lists before "and N more". */
export const KEPT_NAMES_SHOWN = 3;
/** The longest a name is printed; a longer one is cut with "…". */
export const KEPT_NAME_MAX = 80;
/** Where the person reads the rest. */
export const KEPT_DETAILS = "details: `mandu dashboard`";

/** One fact's count and the first names of what it counts. */
export interface KeptFact {
  count: number;
  names: string[];
}

/** What Mandu kept from the AI in one session: the counts Home counts the
 *  session by, and the names behind them. */
export interface SessionKept {
  mode: ProtectionMode | null;
  /** The leak check fired: no claim about what the AI saw. */
  flagged: boolean;
  /** Secrets masked before the AI saw them (the page's tile). */
  masked: KeptFact;
  /** Secrets the AI read before they were marked secrets. */
  early: KeptFact;
  /** Under `off`: the secrets the record holds that Mandu did not mask. */
  unmasked: KeptFact;
  /** Steps Mandu blocked (a command, a file, a send). */
  blocked: number;
  /** Sends that left with a real value filled in; `names`: their hosts. */
  sent: KeptFact;
}

/** `s` as one plain line: control characters (C0, DEL, C1), the line and
 *  paragraph separators and the format characters (a bidi override would
 *  reorder what the terminal shows) become `?`, runs of white space one space, and a
 *  long name is cut. */
export function plainName(s: string, max = KEPT_NAME_MAX): string {
  const flat = s.replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029\p{Cf}]/gu, "?").replace(/\s+/g, " ").trim();
  return flat.length > max ? flat.slice(0, max - 1) + "…" : flat;
}

/** A card's "what" as a name in a list: its parts' text joined, a leading
 *  "The"/"A"/"An"/"Output" lower-cased ("the file ~/.aws/credentials",
 *  "PASTE_KEY in ./.env"). */
export function keptName(what: readonly StoryPart[]): string {
  const text = plainName(what.map((p) => p.text).join(""));
  const first = what[0];
  return first && first.kind === "text" && /^[A-Z][a-z]/.test(text) ? text.charAt(0).toLowerCase() + text.slice(1) : text;
}

function namesOf(secrets: readonly StorySecret[], saw: StorySecret["saw"]): string[] {
  const out: string[] = [];
  for (const s of secrets) {
    if (s.saw !== saw) continue;
    const n = keptName(s.what);
    if (n && !out.includes(n)) out.push(n);
  }
  return out;
}

/** The hosts the story's sends went to, in order, each once: a `sent`
 *  step's first code part (agent-page.ts `osWords`: "Sent a request to
 *  `host` with … filled in"). */
export function sentHosts(turns: readonly StoryTurn[]): string[] {
  const out: string[] = [];
  for (const turn of turns) {
    for (const s of turn.steps) {
      if (s.kind !== "action" || s.outcome !== "sent") continue;
      const host = s.sentence.find((p) => p.kind === "code")?.text;
      if (host) {
        const h = plainName(host);
        if (!out.includes(h)) out.push(h);
      }
    }
  }
  return out;
}

/** The session's facts, from the SAME story and counts Home counts it by
 *  (home-routes.ts `HomeFacts.of`): `story`, its Your secrets (whose
 *  `counts` are the tiles'); `turns`, the story `storyCounts` read; and
 *  those counts. */
export function sessionKept(story: SecretsStory, turns: readonly StoryTurn[], counts: { blocked: number; sent: number }): SessionKept {
  const unmaskedNames = story.mode === "off" ? namesOf(story.secrets, "off") : [];
  const unmaskedCount = story.mode === "off" ? story.secrets.filter((s) => s.saw === "off").length + story.more : 0;
  return {
    mode: story.mode,
    flagged: story.flagged,
    masked: { count: story.counts.masked, names: namesOf(story.secrets, "masked") },
    early: { count: story.counts.early, names: namesOf(story.secrets, "early") },
    unmasked: { count: Math.max(unmaskedCount, unmaskedNames.length), names: unmaskedNames },
    blocked: counts.blocked,
    sent: { count: counts.sent, names: sentHosts(turns) },
  };
}

function plural(n: number, one: string, many: string): string {
  return `${n} ${n === 1 ? one : many}`;
}

/** "(a, b and c)", "(a, b, c and 2 more)": at most KEPT_NAMES_SHOWN names;
 *  `count` is how many there are in all (names past the card cap are
 *  counted, not named). Nothing when no name is known. */
export function nameList(names: readonly string[], count: number): string {
  const shown = names.slice(0, KEPT_NAMES_SHOWN);
  if (!shown.length) return "";
  const more = Math.max(0, count - shown.length);
  let s = "";
  shown.forEach((n, i) => {
    if (i > 0) s += i === shown.length - 1 && !more ? " and " : ", ";
    s += n;
  });
  if (more) s += ` and ${more} more`;
  return ` (${s})`;
}

/** The line the launcher prints when the session ends (dashboard.md
 *  §4.25ah), in Home's words. One line, always (see the header). */
export function keptLine(k: SessionKept): string {
  if (k.flagged) {
    return `mandu: Mandu's leak check flagged this session, so Mandu cannot say what the AI saw · ${KEPT_DETAILS}`;
  }
  if (k.mode === "off") {
    const n = k.unmasked.count;
    const what = n > 0
      ? `so Mandu did not mask ${plural(n, "secret", "secrets")}${nameList(k.unmasked.names, n)}`
      : "so Mandu masked nothing";
    return `mandu: protection was off this session (observe only), ${what} · \`mandu mode secrets\` turns it on · ${KEPT_DETAILS}`;
  }
  // Home's order (home.js renderHero): masked, read before marked, blocked, sent.
  const facts: string[] = [];
  if (k.masked.count > 0) {
    facts.push(`${plural(k.masked.count, "secret masked before the AI saw it", "secrets masked before the AI saw them")}${nameList(k.masked.names, k.masked.count)}`);
  }
  if (k.early.count > 0) {
    facts.push(`${plural(k.early.count, "secret the AI read before it was marked a secret", "secrets the AI read before they were marked secrets")}${nameList(k.early.names, k.early.count)}`);
  }
  if (k.blocked > 0) facts.push(plural(k.blocked, "action blocked", "actions blocked"));
  if (k.sent.count > 0) {
    facts.push(`${plural(k.sent.count, "send with a real value filled in", "sends with a real value filled in")}${nameList(k.sent.names, k.sent.names.length)}`);
  }
  if (!facts.length) return "mandu: no secret came up in this session, so Mandu had nothing to mask";
  return `mandu: in this session: ${facts.join(" · ")} · ${KEPT_DETAILS}`;
}
