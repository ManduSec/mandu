/**
 * policy — which DevTools commands the relay forwards, refuses or releases
 * into (docs/design/agents/devtools-relay.md §4). Pure. Mandu-new (no
 * reference origin).
 *
 * Three tables:
 *   - ALLOWED_DOMAINS: a command outside them is refused. The protocol has
 *     about fifty domains; these are the ones browser agents drive
 *     (Playwright, Puppeteer, browser-use, the browser MCPs). A domain is
 *     added when an agent needs it and its results are text the filter can
 *     read.
 *   - REFUSED_METHODS: inside an allowed domain, commands whose answer the
 *     relay cannot mask: pixels (screenshots, screencasts, PDFs, traces,
 *     layer replays), the cookie jar, and one that hands the page the
 *     protocol itself.
 *   - RELEASE_METHODS: the input commands a placeholder is put back into
 *     (release.ts). In any other command a placeholder is forwarded as
 *     written: the page gets the literal, which leaks nothing.
 */

export const ALLOWED_DOMAINS: ReadonlySet<string> = new Set([
  "Accessibility", "Browser", "CSS", "Console", "DOM", "DOMDebugger", "DOMSnapshot", "DOMStorage",
  "Debugger", "Emulation", "Fetch", "IO", "IndexedDB", "Input", "Inspector", "Log", "Network",
  "Overlay", "Page", "Performance", "Runtime", "Schema", "Security", "ServiceWorker", "Storage",
  "Target",
]);

/** Commands refused whatever their domain; the value says why (shown to the agent). */
export const REFUSED_METHODS: ReadonlyMap<string, string> = new Map([
  ["Page.captureScreenshot", "pixels"],
  ["Page.startScreencast", "pixels"],
  ["Page.screencastFrameAck", "pixels"],
  ["Page.printToPDF", "pixels"],
  ["Page.captureSnapshot", "pixels"],
  ["Tracing.start", "pixels"],
  ["HeadlessExperimental.beginFrame", "pixels"],
  ["LayerTree.replaySnapshot", "pixels"],
  ["Network.getCookies", "cookies"],
  ["Network.getAllCookies", "cookies"],
  ["Storage.getCookies", "cookies"],
  ["Target.exposeDevToolsProtocol", "protocol"],
  // The nested (non-flat) session mode carries whole commands and answers as
  // strings, past every table here: a nested screenshot would come back as
  // text. Agents use flat sessions (`sessionId` on each message).
  ["Target.sendMessageToTarget", "protocol"],
]);

/** What the agent is told for a refused command, by reason. */
export function refusalMessage(method: string, why: string): string {
  switch (why) {
    case "pixels":
      return `Mandu: ${method} is not relayed: the relay masks text, not pixels (use the page's text or accessibility tree)`;
    case "cookies":
      return `Mandu: ${method} is not relayed: cookies are the browser's credentials`;
    case "protocol":
      return `Mandu: ${method} is not relayed: it would carry DevTools messages past the relay (use flat sessions)`;
    case "domain":
      return `Mandu: ${method} is not relayed: the ${method.split(".")[0]} domain is outside the relay's list`;
    default:
      return `Mandu: ${method} is not relayed`;
  }
}

/** The reason a command is refused, or null when it may go. */
export function refusedBecause(method: string): string | null {
  const why = REFUSED_METHODS.get(method);
  if (why !== undefined) return why;
  const domain = method.split(".")[0] ?? "";
  return ALLOWED_DOMAINS.has(domain) ? null : "domain";
}

/** The input commands a placeholder is released into, and the parameter
 *  that carries the text. `Input.dispatchKeyEvent` only for a key that
 *  types (`keyDown` / `char` with `text`). */
export const RELEASE_METHODS: ReadonlyMap<string, "text"> = new Map([
  ["Input.insertText", "text"],
  ["Input.dispatchKeyEvent", "text"],
]);

/** Header names whose values are the browser's credentials: masked in every
 *  message whatever the filter says (not symbols: a session cookie is not a
 *  registered secret, and the agent never needs it). */
export const CREDENTIAL_HEADERS: ReadonlySet<string> = new Set([
  "cookie", "set-cookie", "authorization", "proxy-authorization",
]);

/** The text a credential header's value is replaced with. */
export const WITHHELD_HEADER = "[withheld by Mandu]";
