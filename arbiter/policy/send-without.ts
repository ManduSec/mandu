/**
 * send-without — which Approvals cards take "Send without it"
 * (confidentiality.md §4, "Send without it", 2026-10-17). Mandu-new (no
 * reference origin). PURE: the arbiter server passes in what it knows of
 * the row's symbol; nothing here reads a store.
 *
 * "Send without it" is the fourth answer to a card about a secret in a
 * network request: the NEXT request carrying that secret's symbol to that
 * host goes, with a neutral marker where the symbol was (the net-proxy's
 * egress.ts `SEND_WITHOUT_MARKER`). It is safe exactly where the withheld
 * content IS the symbol: the request holds a `$MDU:` token, never the raw
 * value, so taking the token out leaves nothing of the secret behind.
 *
 * It is NEVER right on a content-agnostic card: a program holding a secret
 * connecting somewhere (`holder-send:`, `<secret-taint:…>`), a HIGH
 * session's request or command (`session-net:` / `session-exec:`), an
 * unattributed connection, the frozen integrity taint gate (`<taint:…>`),
 * a file open or change (`open:` / `write:` / `trust:`), a program run, a
 * held message (`prompt:`), or a masked value asked into the model's
 * context (`model_context:in-context-read`). On those the request may hold
 * the raw bytes in any encoding, with no symbol to take out, so "sending it
 * without the secret" would send the secret. The arbiter refuses the answer
 * there (fail-closed), whatever the page offered.
 */

/** A whole `$MDU:` symbol, anchored (the symbol grammar of
 *  symbol-table.ts `SYMBOL_PATTERN`: a base symbol and an optional dotted
 *  field path). Nothing before or after it. */
const WHOLE_SYMBOL_RE = /^\$MDU:[a-zA-Z_][a-zA-Z0-9_]*\[[0-9a-f]{4,8}\](?:\.[a-zA-Z_][a-zA-Z0-9_[\].]*)*$/;

/** A network destination as the egress gates name one: a host name (or a
 *  bracketed IPv6 literal, or an IPv4 address), with an optional port.
 *  Never a path, a URL, a `model:` / `model_context:` act or a command. */
const NETWORK_DESTINATION_RE = /^(?:\[[0-9a-fA-F:.]+\]|[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?(?:\.[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?)*\.?)(?::\d{1,5})?$/;

/** Is `subject` a whole `$MDU:` symbol (the subject of a per-symbol egress
 *  card)? */
export function isSymbolSubject(subject: string): boolean {
  return WHOLE_SYMBOL_RE.test(subject);
}

/** Is `destination` a network host[:port] (the target of a per-symbol
 *  NETWORK egress card)? */
export function isNetworkDestination(destination: string): boolean {
  return destination.length > 0 && destination.length <= 260 && NETWORK_DESTINATION_RE.test(destination);
}

/** What the server knows of a row's subject when it asks. */
export interface SendWithoutFacts {
  /** The confidentiality axis is on (mode `secrets` / `full`). */
  confidentiality: boolean;
  /** The row's symbol is a secret the symbol table holds (above `public`);
   *  false for a public or unknown symbol. */
  secretSymbol: boolean;
}

/**
 * Why `row` takes no "Send without it", or null when it does. It does only
 * when: the confidentiality axis is on, the row is still about a network
 * request (its subject a whole `$MDU:` symbol, its target a host), and the
 * symbol is a secret the table holds (an `egress:secret-*` card). The
 * reason is for the refusal and the log; product copy words it itself.
 */
export function sendWithoutRefusal(
  row: { symbol: string; destination: string },
  facts: SendWithoutFacts,
): string | null {
  if (!facts.confidentiality) return "secrets protection is off, so no request is held for a secret";
  if (!isSymbolSubject(row.symbol)) {
    return "this question is not about a secret's placeholder in a request: the request may hold the data itself, so it cannot be sent without it";
  }
  if (!isNetworkDestination(row.destination)) return "this question is not about a request to a network host";
  if (!facts.secretSymbol) return "the placeholder in this question is not a secret Mandu holds";
  return null;
}
