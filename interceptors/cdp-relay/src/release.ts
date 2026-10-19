/**
 * release — a placeholder the agent types, put back into the page only
 * when the page's origin may have it (docs/design/agents/devtools-relay.md
 * §3.2). Mandu-new (no reference origin).
 *
 * The agent's `Input.insertText` (or a typing `Input.dispatchKeyEvent`)
 * whose text holds a `$MDU:*` placeholder is NOT forwarded. Instead:
 *   1. the relay asks Chrome, on the same target, for its main frame
 *      (`Page.getFrameTree`: the browser's own account of the frame's
 *      origin, not the page's);
 *   2. for each placeholder, the arbiter's egress decision with the
 *      network boundary and the page's host as the destination (typing a
 *      value into a page gives it to that origin); then the value, on the
 *      human plane;
 *   3. the value is inserted by a function the relay runs in an ISOLATED
 *      world of that frame (`Page.createIsolatedWorld`: the page's scripts
 *      cannot patch its prototypes), which checks the origin again and the
 *      focus, and inserts, in one turn of the page's event loop: no page
 *      script runs between the check and the insert. The value travels as
 *      a call argument, never in the function's source (a script's source
 *      is what `Debugger.getScriptSource` hands back).
 * Anything else (no frame, an opaque origin, a denial, an unanswered ask,
 * the arbiter unreachable, the page moved, the focus in a frame) refuses
 * the command; the agent gets an error and nothing is typed.
 *
 * A placeholder the arbiter does not know (`resolve` answers null: a hash
 * the model made up, a character it dropped) refuses the command too, with
 * a message that tells the model to type the placeholder exactly as the
 * page shows it and names the nearest placeholders the pages showed
 * (shown.ts; names only). Nothing raw could leak either way (an unknown
 * name has no value); refusing is for the task: typed as written, the page
 * got the literal and the model never learned it was wrong (§3.2, *A
 * placeholder that names nothing*).
 *
 * A LOOKALIKE (symbols.ts `findLookalikes`: the placeholder's shape with a
 * code no placeholder has, such as a UUID the model made up) is refused the
 * same way, without asking the arbiter (it can name nothing): the agent is
 * told as for an unknown placeholder, and the notice says `malformed`
 * without quoting it, since its code is free text (§3.2, *A placeholder
 * lookalike*).
 *
 * A placeholder TYPED A KEY AT A TIME is checked on the key that closes
 * its code (`checkTyped`, typing.ts `check`): a base the arbiter does not
 * know is refused there as unknown, so the agent's typing fails while it
 * types (§3.3).
 *
 * Every refusal also carries a `notice`: the same refusal as structured
 * names (a kind, a cause, the page's host, the placeholders), which the
 * relay reports to the arbiter so the agent's MODEL is told on its next
 * call even when the agent drops the error (§3.4).
 */
import type { Arbiter, RelayNotice } from "./arbiter-client.js";
import { RELEASE_METHODS } from "./policy.js";
import { findLookalikes, findSymbols, substituteSymbols } from "./symbols.js";

/** The isolated world's name (visible to the agent as a new context). */
export const RELEASE_WORLD = "mandu-relay";

/** Runs in the isolated world: check, then insert, in one turn. */
export const INSERT_FUNCTION = `function (origin, text) {
  if (location.origin !== origin) return "origin";
  let el = document.activeElement;
  while (el && el.shadowRoot && el.shadowRoot.activeElement) el = el.shadowRoot.activeElement;
  if (!el || el === document.body || el === document.documentElement) return "none";
  const tag = el.tagName;
  if (tag === "IFRAME" || tag === "FRAME" || tag === "OBJECT" || tag === "EMBED") return "focus";
  return document.execCommand("insertText", false, text) ? "ok" : "failed";
}`;

/** One command sent to Chrome on the agent's own target (the relay's id). */
export interface PageTarget {
  send(method: string, params: Record<string, unknown>): Promise<Record<string, unknown>>;
}

export interface ReleaseDeps {
  arbiter: Arbiter;
  target: PageTarget;
  session?: string;
  /** The placeholders the agent was shown nearest to an unknown one
   *  (shown.ts `nearest`), named in its refusal. */
  hints?: (symbol: string) => string[];
}

/** The most placeholders one notice names (the arbiter's
 *  RELAY_NOTICE_MAX_SYMBOLS). */
export const NOTICE_MAX_SYMBOLS = 8;

/** The trace's reason for a placeholder the arbiter does not know. */
export const UNKNOWN_PLACEHOLDER = "unknown placeholder";

/** `message` is the agent's (its model reads it); `reason` the trace's
 *  (events.ts); `unknown` the placeholders that name nothing; `notice` the
 *  refusal for the model's next call (§3.4). */
export type ReleaseOutcome =
  | { kind: "done"; origin: string }
  | { kind: "refuse"; message: string; reason: string; unknown?: string[]; notice: RelayNotice };

/** What the agent is told for placeholders the arbiter does not know. Pure. */
export function unknownMessage(unknown: readonly string[], hints: readonly string[]): string {
  const which = unknown.length === 1 ? `no such placeholder ${unknown[0]}` : `no such placeholders ${unknown.join(", ")}`;
  const shown = hints.length === 0 ? "" : ` (the pages showed ${hints.join(", ")})`;
  return `Mandu: nothing was typed: ${which}: type the placeholder exactly as the page shows it, every character${shown}`;
}

/** The text a command would type when it carries a placeholder or a
 *  lookalike of one (symbols.ts), else null
 *  (the command is forwarded as it is). Pure. */
export function releaseText(method: string, params: unknown): string | null {
  if (!RELEASE_METHODS.has(method) || typeof params !== "object" || params === null) return null;
  const p = params as Record<string, unknown>;
  if (method === "Input.dispatchKeyEvent" && p["type"] !== "keyDown" && p["type"] !== "char") return null;
  const text = p["text"];
  return typeof text === "string" && (findSymbols(text).length > 0 || findLookalikes(text).length > 0) ? text : null;
}

/** The main frame's id and origin from a `Page.getFrameTree` answer, or why
 *  not. Only http(s) origins can be named to the egress decision. Pure. */
export function frameOrigin(answer: Record<string, unknown>): { frameId: string; origin: string; host: string; scheme: "http" | "https" } | string {
  const tree = answer["frameTree"] as Record<string, unknown> | undefined;
  const frame = tree?.["frame"] as Record<string, unknown> | undefined;
  const frameId = frame?.["id"];
  if (typeof frameId !== "string" || frameId === "") return "Chrome named no main frame";
  const raw = typeof frame?.["securityOrigin"] === "string" && frame["securityOrigin"] !== "" ? frame["securityOrigin"] : frame?.["url"];
  let u: URL;
  try {
    u = new URL(String(raw));
  } catch {
    return "the page has no origin a secret can be released to";
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") return `a ${u.protocol} page has no origin a secret can be released to`;
  return { frameId, origin: u.origin, host: u.hostname, scheme: u.protocol === "https:" ? "https" : "http" };
}

/** What the agent is told for the insert function's answer. */
export function insertRefusal(answer: unknown): string | null {
  return insertCause(answer)?.message ?? null;
}

/** The insert function's answer as a refusal's words and cause, or null
 *  for `ok`. Pure. */
export function insertCause(answer: unknown): { message: string; cause: NonNullable<RelayNotice["cause"]> } | null {
  switch (answer) {
    case "ok": return null;
    case "origin": return { message: "the page moved to another site before the value was typed", cause: "page-moved" };
    case "focus": return { message: "the focus is in a frame of another page", cause: "frame" };
    case "none": return { message: "no editable field has the focus", cause: "no-field" };
    default: return { message: "the page did not take the text", cause: "page-refused" };
  }
}

/** The hints for an unknown placeholder or a lookalike (none when the
 *  hints fail). */
function hintsFor(token: string, deps: ReleaseDeps): string[] {
  try { return deps.hints?.(token) ?? []; } catch { return []; }
}

/** A site that may not have the secret (`not-allowed`, and `needs-approval`
 *  unless the person asked for it there): the task goes on without it, as a
 *  held request's *Send without it* does (devtools-relay.md §3.4). The
 *  model's own notice says the same at more length (net-proxy
 *  relay-notice.ts). */
export const LEAVE_IT_OUT = "leave it out (name it in plain words if the text needs it, never its placeholder) and go on";

/** Lookalikes refused: nothing typed, the arbiter not asked (they name
 *  nothing), the page asked for only to name its host to the model. Never
 *  throws. Also the refusal of a key run decided on its way (typing.ts
 *  `decide`, pair.ts). */
export async function refuseLookalikes(lookalikes: string[], deps: ReleaseDeps): Promise<ReleaseOutcome> {
  const page = await pageHost(deps);
  const hints = hintsFor(lookalikes[0]!, deps);
  return {
    kind: "refuse", message: unknownMessage(lookalikes, hints), reason: UNKNOWN_PLACEHOLDER, unknown: lookalikes,
    // Its code is free text: the notice says what it was, never quotes it.
    notice: { kind: "malformed", symbols: [], ...(page !== undefined ? { page } : {}), ...(hints.length > 0 ? { shown: hints } : {}) },
  };
}

/** The page's host, best-effort (only to name it to the model). */
async function pageHost(deps: ReleaseDeps): Promise<string | undefined> {
  try {
    const p = frameOrigin(await deps.target.send("Page.getFrameTree", {}));
    return typeof p === "string" ? undefined : p.host;
  } catch {
    return undefined;
  }
}

/** A key run's placeholder, checked on the key that closes its code
 *  (typing.ts `check`, devtools-relay.md §3.3): null when the arbiter knows
 *  its base (the run goes on, and is released or refused at its end as
 *  before); else the refusal: a base no row has is refused exactly as a
 *  placeholder that names nothing (`unknown`, the nearest shown named), and
 *  an arbiter that cannot answer refuses too (fail-closed: without the human
 *  plane no release could happen at the run's end either). Asks nothing of
 *  the gate and reads no value. Never throws. */
export async function checkTyped(base: string, deps: ReleaseDeps): Promise<ReleaseOutcome | null> {
  let known: boolean;
  try {
    known = await deps.arbiter.placeholderKnown(base);
  } catch (err) {
    const page = await pageHost(deps);
    const message = `Mandu: the placeholder was not typed: it could not be looked up (${(err as Error).message})`;
    return { kind: "refuse", message, reason: message, notice: { kind: "failed", cause: "unavailable", symbols: [base], ...(page !== undefined ? { page } : {}) } };
  }
  if (known) return null;
  const page = await pageHost(deps);
  const hints = hintsFor(base, deps);
  return {
    kind: "refuse", message: unknownMessage([base], hints), reason: UNKNOWN_PLACEHOLDER, unknown: [base],
    notice: { kind: "unknown", symbols: [base], ...(page !== undefined ? { page } : {}), ...(hints.length > 0 ? { shown: hints } : {}) },
  };
}

/** Steps 1 to 3 (a lookalike refused first). Never throws. */
export async function release(text: string, deps: ReleaseDeps): Promise<ReleaseOutcome> {
  const lookalikes = findLookalikes(text);
  if (lookalikes.length > 0) return refuseLookalikes(lookalikes, deps);
  const all = findSymbols(text);
  let host: string | undefined;
  const refuse = (why: string, notice: Omit<RelayNotice, "page" | "symbols"> & { symbols?: string[] }): ReleaseOutcome => {
    const message = `Mandu: the placeholder was not typed: ${why}`;
    return { kind: "refuse", message, reason: message, notice: { ...notice, symbols: (notice.symbols ?? all).slice(0, NOTICE_MAX_SYMBOLS), ...(host !== undefined ? { page: host } : {}) } };
  };
  let page: ReturnType<typeof frameOrigin>;
  try {
    page = frameOrigin(await deps.target.send("Page.getFrameTree", {}));
  } catch (err) {
    return refuse(`Chrome did not name the page (${(err as Error).message})`, { kind: "failed", cause: "unavailable" });
  }
  if (typeof page === "string") return refuse(page, { kind: "failed", cause: "no-page" });
  host = page.host;

  const values = new Map<string, string>();
  const unknown: string[] = [];
  for (const symbol of all) {
    let decision;
    try {
      decision = await deps.arbiter.desymbolizationDecision({
        symbol, boundary: "network", destination: page.host, asCommand: false,
        scheme: page.scheme, positions: ["body"],
        ...(deps.session !== undefined && deps.session !== "" ? { sessionKey: deps.session } : {}),
      });
    } catch (err) {
      return refuse(`the release gate could not be asked (${(err as Error).message})`, { kind: "failed", cause: "unavailable", symbols: [symbol] });
    }
    if (decision.strip === true) return refuse(`you chose to go on without ${symbol}`, { kind: "declined", symbols: [symbol] });
    if (!decision.allow) {
      return decision.requiresApproval
        ? refuse(`${page.host} may not have ${symbol} without the person's approval in Mandu; ${LEAVE_IT_OUT}; ask the person only if they asked for it to go there, then type it again`, { kind: "needs-approval", symbols: [symbol] })
        : refuse(`${symbol} may not go to ${page.host} (${decision.reason}); ${LEAVE_IT_OUT}`, { kind: "not-allowed", symbols: [symbol] });
    }
    let value: string | null;
    try {
      value = await deps.arbiter.resolve(symbol);
    } catch (err) {
      return refuse(`the value could not be read (${(err as Error).message})`, { kind: "failed", cause: "unavailable", symbols: [symbol] });
    }
    // Unknown to the table (the gate allows it: no value to leak), so the
    // command is refused, to tell the model; see the header.
    if (value === null) unknown.push(symbol);
    else values.set(symbol, value);
  }
  if (unknown.length > 0) {
    const hints = hintsFor(unknown[0]!, deps);
    return {
      kind: "refuse", message: unknownMessage(unknown, hints), reason: UNKNOWN_PLACEHOLDER, unknown,
      notice: { kind: "unknown", page: page.host, symbols: unknown.slice(0, NOTICE_MAX_SYMBOLS), ...(hints.length > 0 ? { shown: hints } : {}) },
    };
  }

  try {
    const world = await deps.target.send("Page.createIsolatedWorld", { frameId: page.frameId, worldName: RELEASE_WORLD, grantUniveralAccess: false });
    const contextId = world["executionContextId"];
    if (typeof contextId !== "number") return refuse("Chrome made no isolated world", { kind: "failed", cause: "unavailable" });
    const r = await deps.target.send("Runtime.callFunctionOn", {
      functionDeclaration: INSERT_FUNCTION,
      executionContextId: contextId,
      arguments: [{ value: page.origin }, { value: substituteSymbols(text, values) }],
      returnByValue: true,
      awaitPromise: false,
    });
    if (r["exceptionDetails"] !== undefined) return refuse("the page refused the text", { kind: "failed", cause: "page-refused" });
    const why = insertCause((r["result"] as Record<string, unknown> | undefined)?.["value"]);
    return why === null ? { kind: "done", origin: page.origin } : refuse(why.message, { kind: "failed", cause: why.cause });
  } catch (err) {
    return refuse(`Chrome did not insert it (${(err as Error).message})`, { kind: "failed", cause: "unavailable" });
  }
}
