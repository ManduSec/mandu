/**
 * view-model/declassify-words — the agent's request to read a secret's real
 * value into its own conversation (`declassify_symbol`, the in-context read
 * of the mandu-inspect server; confidentiality.md §4) in the product page's
 * words (dashboard.md §4.25b, "A request for a secret's real value").
 *
 * The session page used to tell such a call as "Used `mandu-inspect
 * declassify_symbol`", although the record holds both what was asked (the
 * call's `symbol`) and what Mandu answered (the relay's fixed text,
 * interceptors/inspect-mcp/src/declassify-symbol.ts). Pure; no I/O.
 *
 *   - NAME: only the spellings Mandu's own mount produces count, the list
 *     the arbiter's trust rule keeps (arbiter/policy/inspect-tool.ts
 *     `isManduDeclassifyTool`; tests/stack/declassify-words.test.ts pins
 *     the two equal). Another server's tool of the same name stays "Used …".
 *   - WHAT MANDU ANSWERED: read only from the relay's fixed openings: the
 *     one-line notice before a released value, or a refusal, with the line
 *     the relay adds when the person was asked. A masked, missing or other
 *     result has no answer, so the page claims nothing. Neither the value
 *     after the notice nor a refusal's reason is ever read into the words.
 */

const SERVER = "mandu-inspect";
const BASENAME = "declassify_symbol";

/** Every spelling of Mandu's declassify tool, as the arbiter keeps them:
 *  Claude Code, OpenCode (one underscore), Codex (the server's "-" read as
 *  "_"), Goose, and OpenClaw's plugin tool (bare, it has no namespace). */
export const MANDU_DECLASSIFY_TOOL_SPELLINGS: readonly string[] = [
  `mcp__${SERVER}__${BASENAME}`,
  `${SERVER}_${BASENAME}`,
  `mcp__${SERVER.replace(/-/g, "_")}__${BASENAME}`,
  `${SERVER}__${BASENAME}`,
  BASENAME,
];

/** Is `tool` Mandu's own declassify tool? */
export function isManduDeclassify(tool: string): boolean {
  return MANDU_DECLASSIFY_TOOL_SPELLINGS.includes(tool);
}

/** The relay's notice before a released value: one line in brackets (the
 *  shape the arbiter checks, declassifyResultTrusted), then the value. */
const RELEASED_RE = /^\[DECLASSIFIED[^\n\]]*\](?:\n|$)/;
/** Every refusal of the relay opens with the tool's name. */
const REFUSED_RE = /^declassify_symbol: /;
/** The line the relay adds when the arbiter queued the read for the person. */
const ASKED_RE = / The user has been asked to approve this; stop and tell them you are waiting\.$/;

/** The note under the step, from the recorded result only: null when it is
 *  not one of the relay's answers (masked, missing, another shape), so the
 *  page says nothing it cannot back. */
export function declassifyAnswer(result: string | null): string | null {
  if (!result) return null;
  if (RELEASED_RE.test(result)) {
    // The notice the AI read says the same (declassifiedNotice).
    return "Mandu gave the AI the real value. From then on, a request or command of this session that could carry it to a place it may not go waits for your OK in Approvals.";
  }
  if (!REFUSED_RE.test(result)) return null;
  return ASKED_RE.test(result)
    ? "Mandu asked for your OK in Approvals first, so the AI did not get the real value."
    : "Mandu did not give the AI the real value.";
}
