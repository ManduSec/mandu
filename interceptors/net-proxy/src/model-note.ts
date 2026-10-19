/**
 * model-note — Mandu's handling note in a browser agent's own model calls
 * (docs/design/agents/devtools-relay.md §6.5; handling-prompt.md §11).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 *
 * WHY. Claude Code and Codex reach their model through Mandu's model proxy,
 * which puts the handling note (what a `$MDU:` placeholder is, and that it
 * may be used as the value) into every request. A browser agent such as
 * browser-use is a program that calls a model service itself (OpenRouter,
 * agent-sign-in.md §3.12): no model proxy fronts it, so its model met a
 * placeholder in a page with no word on what it is. Live (2026-10-19), Gemini
 * 2.5 Flash then refused to fill the key ("the key is redacted"), and the
 * drills had to hand browser-use the note themselves.
 *
 * THE RULE. When the launch runs a DevTools relay (`--browser-cdp`,
 * `--browser`), the launcher starts this proxy with
 * `MANDU_NET_PROXY_MODEL_NOTE=browser` (always set, so an ambient value
 * cannot turn it on). Then a Chat Completions request (`POST
 * …/chat/completions`, a JSON body with a `messages` array) to a model
 * service, on the TLS-inspected leg, gets the note as one more `system`
 * message at the front, after the egress gate and the tripwire passed it.
 * The note is the arbiter's own (`handlingPrompt`, with the capabilities of
 * a browser agent: no inspect, exec or policy tools, the *Web pages*
 * section).
 *
 * WHY IT IS SAFE. The note is Mandu's fixed text and holds no secret; what
 * the gate decided about the request is unchanged (the note is added after
 * it). A request it cannot read (another wire, a compressed or non-JSON
 * body, no `messages`) leaves as written, and so does every request when
 * the arbiter cannot give the note: utility only, the placeholders stay
 * opaque either way. Every other launch, host and path is untouched.
 *
 * THE RELAY'S REFUSALS (relay-notice.ts, devtools-relay.md §3.4). The same
 * call also gets the session's pending relay refusals, taken from the
 * arbiter, as one message at the END of `messages` (`editModelCall`). The
 * note stays byte for byte as it was (the prompt cache); a body the step
 * cannot read is left as written and its refusals stay pending.
 */
import { appendRelayNotice, relayNoticeText, toldNotices, type RelayNotice } from "./relay-notice.js";

/** The proxy's switch (launcher services/net-proxy.ts sets it). */
export const MODEL_NOTE_ENV = "MANDU_NET_PROXY_MODEL_NOTE";

/** Which note a launch's model-service calls get. One kind today. */
export type ModelNoteKind = "browser";

/** The switch's value, or null (off) for anything but a known kind. */
export function modelNoteFromEnv(value: string | undefined): ModelNoteKind | null {
  return value === "browser" ? "browser" : null;
}

/** What a browser agent's model has: no inspect_symbol, no shell, no policy
 *  tools, no view map; it reads and acts on pages (handling-prompt.ts
 *  HandlingPromptCapabilities). */
export const BROWSER_NOTE_CAPABILITIES = {
  inspect: false,
  policyTools: false,
  exec: false,
  fsView: false,
  browser: true,
} as const;

/** A Chat Completions call: POST to a path ending in `/chat/completions`
 *  (OpenRouter's `/api/v1/chat/completions`, any OpenAI-compatible base). */
export function isChatCompletionsCall(method: string, target: string): boolean {
  if (method.toUpperCase() !== "POST") return false;
  const path = target.split("?")[0]!.replace(/\/+$/, "");
  return path === "/chat/completions" || path.endsWith("/chat/completions");
}

export type NoteResult =
  | { kind: "added"; bodyText: string }
  | { kind: "skipped"; reason: string };

/** A Chat Completions body the step can read: a JSON object with a
 *  `messages` array, not compressed. */
export interface ChatBody {
  body: Record<string, unknown> & { messages: unknown[] };
}

/** The body, parsed, or why the step leaves it as written. Pure. */
export function readChatBody(bodyText: string, headers: NodeJS.Dict<string | string[]>): ChatBody | string {
  const enc = headerValue(headers, "content-encoding");
  if (enc && enc.toLowerCase() !== "identity") return `a ${enc} body`;
  let body: unknown;
  try {
    body = JSON.parse(bodyText);
  } catch {
    return "not a JSON body";
  }
  if (typeof body !== "object" || body === null || Array.isArray(body)) return "not a JSON object";
  const messages = (body as { messages?: unknown }).messages;
  if (!Array.isArray(messages)) return "no messages array";
  return { body: body as ChatBody["body"] };
}

/** The body with the note as the first `system` message, or why not. */
export function addModelNote(
  bodyText: string,
  headers: NodeJS.Dict<string | string[]>,
  note: string,
): NoteResult {
  if (note === "") return { kind: "skipped", reason: "no note (both protection axes off)" };
  const read = readChatBody(bodyText, headers);
  if (typeof read === "string") return { kind: "skipped", reason: read };
  const why = withNote(read, note);
  return why === null ? { kind: "added", bodyText: JSON.stringify(read.body) } : { kind: "skipped", reason: why };
}

/** Put the note first in `chat` (in place), or say why not. */
function withNote(chat: ChatBody, note: string): string | null {
  if (note === "") return "no note (both protection axes off)";
  // A retried or replayed request may carry the note already.
  if (chat.body.messages.some((m) => isSystem(m) && (m as { content?: unknown }).content === note)) return "already there";
  chat.body.messages = [{ role: "system", content: note }, ...chat.body.messages];
  return null;
}

/** What the step did to one model-service call (mitm.ts reads it). */
export interface ModelCallEdit {
  /** The body to send; absent: the request leaves as written. */
  bodyText?: string;
  /** The forwarded event's `modelNote`: `added`, or `not added: <why>`. */
  note: string;
  /** How many relay refusals were appended (0: none). */
  relayNotices: number;
}

/** Where the step gets the note and the refusals (proxy.ts: the arbiter).
 *  Either may throw: the call goes on without it. */
export interface ModelCallSources {
  note?: () => Promise<string>;
  relayNotices?: () => Promise<readonly RelayNotice[]>;
}

/** The note first and the pending relay refusals last, or the request as
 *  written with why. The refusals are taken only from a body the step can
 *  read, so an unread call leaves them pending. Never throws. */
export async function editModelCall(
  bodyText: string,
  headers: NodeJS.Dict<string | string[]>,
  from: ModelCallSources,
): Promise<ModelCallEdit> {
  const chat = readChatBody(bodyText, headers);
  if (typeof chat === "string") return { note: `not added: ${chat}`, relayNotices: 0 };
  let noteWhy: string | null;
  if (!from.note) noteWhy = "the protection service gives no note";
  else {
    try {
      noteWhy = withNote(chat, await from.note());
    } catch (err) {
      noteWhy = `the protection service did not give the note (${(err as Error).message})`;
    }
  }
  let told = 0;
  if (from.relayNotices) {
    let notices: readonly RelayNotice[] = [];
    try { notices = await from.relayNotices(); } catch { /* none: a hint lost, nothing else */ }
    const text = Array.isArray(notices) ? relayNoticeText(notices) : null;
    if (text !== null) {
      chat.body.messages = appendRelayNotice(chat.body.messages, text);
      told = toldNotices(notices).length;
    }
  }
  const note = noteWhy === null ? "added" : `not added: ${noteWhy}`;
  return noteWhy === null || told > 0 ? { bodyText: JSON.stringify(chat.body), note, relayNotices: told } : { note, relayNotices: 0 };
}

function isSystem(m: unknown): boolean {
  return typeof m === "object" && m !== null && (m as { role?: unknown }).role === "system";
}

function headerValue(headers: NodeJS.Dict<string | string[]>, name: string): string | undefined {
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() !== name) continue;
    return Array.isArray(v) ? v.join(",") : v;
  }
  return undefined;
}
