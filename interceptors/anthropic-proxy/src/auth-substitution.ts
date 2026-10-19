/**
 * auth-substitution — the agent's own key, put back in the auth header of
 * the request the proxy forwards to its provider (agent-sign-in.md §3).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference
 * origin). The release itself is the egress gate's bound-destination release
 * (confidentiality.md §3.2), asked exactly as the net-proxy asks it before it
 * puts a value back on the wire (net-proxy egress.ts `gateRequest`):
 * `desymbolizationDecision` and, on allow, the shallow `resolve`, both on the
 * arbiter's human plane.
 *
 * The agent's key file (Goose's `secrets.yaml`) is twinned, so the agent
 * sends the key's placeholder. The launch bound that placeholder to the host
 * it routes the provider to (registerAuthGrant). Here, for each request
 * forwarded upstream:
 *
 *   - exactly TWO header shapes are read: `x-api-key: <symbol>` and
 *     `authorization: Bearer <symbol>`, the whole value one placeholder;
 *   - the destination is the upstream's host, the scheme the upstream's;
 *   - allowed and resolved ⇒ the value replaces the placeholder in that
 *     header; anything else (a denial, an unbound host, no human plane, an
 *     arbiter error, a null resolve, a value with a control character) ⇒ the
 *     placeholder stays, and the provider answers 401 (FAIL CLOSED: nothing
 *     raw is sent, and nothing is made up);
 *   - the body, the URL and every other header are never touched: the
 *     model's context keeps the symbol.
 *
 * The value never reaches a log or an event: the caller logs the header name
 * and the host only.
 */

/** The placeholder grammar (arbiter symbol-table SYMBOL_PATTERN, as net-gate.ts
 *  mirrors it), anchored: the whole header value is one symbol. */
const WHOLE_SYMBOL_RE = /^\$MDU:[a-zA-Z_][a-zA-Z0-9_]*\[[0-9a-f]{4,8}\](?:\.[a-zA-Z_][a-zA-Z0-9_[\].]*)*$/;
const BEARER_RE = /^(Bearer) (\S+)$/i;

/** A header value a key may be put back into: printable ASCII only (no CR,
 *  LF, NUL or other control character, so no header injection). */
const HEADER_SAFE_RE = /^[\x21-\x7e]+$/;

/** The one placeholder an auth header carries as its whole credential, and
 *  how to write the value back in its place; null for any other header or
 *  shape. Pure. */
export function authHeaderSymbol(name: string, value: string): { symbol: string; render: (v: string) => string } | null {
  const n = name.toLowerCase();
  if (n === "x-api-key") {
    return WHOLE_SYMBOL_RE.test(value) ? { symbol: value, render: (v) => v } : null;
  }
  if (n === "authorization") {
    const m = BEARER_RE.exec(value);
    if (!m || !WHOLE_SYMBOL_RE.test(m[2]!)) return null;
    const scheme = m[1]!;
    return { symbol: m[2]!, render: (v) => `${scheme} ${v}` };
  }
  return null;
}

/** The arbiter side of the release: the gate and the resolve, on the human
 *  plane (arbiter-client.ts `ArbiterClientAdapter.authCredential`). Resolves
 *  to the value when the gate allows the symbol at `destination` and the
 *  resolve answers, else null with why. May throw (treated as null). */
export interface AuthCredentialSource {
  authCredential(req: {
    symbol: string;
    destination: string;
    scheme: "http" | "https";
    sessionKey?: string;
  }): Promise<{ value: string | null; reason: string }>;
}

/** What the substitution did, per header (never a value). */
export interface AuthSubstitution {
  header: string;
  symbol: string;
  restored: boolean;
  reason: string;
}

/** The upstream a request goes to: its host (with a port when it has one)
 *  and scheme, from the upstream origin or base URL. Null when unparsable
 *  (then nothing is put back). Pure. */
export function upstreamDestination(upstream: string): { host: string; scheme: "http" | "https" } | null {
  let u: URL;
  try {
    u = new URL(upstream);
  } catch {
    return null;
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") return null;
  if (u.host === "") return null;
  return { host: u.host, scheme: u.protocol === "https:" ? "https" : "http" };
}

/**
 * Put the agent's key back into `headers` (mutated in place), for a request
 * to `dest`. Every header that is not one of the two shapes, and every
 * failure, is left as it is. Returns one record per auth header that held a
 * placeholder.
 */
export async function substituteAuthHeaders(
  headers: Record<string, string | string[] | undefined>,
  dest: { host: string; scheme: "http" | "https" } | null,
  source: AuthCredentialSource | undefined,
  sessionKey?: string,
): Promise<AuthSubstitution[]> {
  const out: AuthSubstitution[] = [];
  for (const [name, value] of Object.entries(headers)) {
    if (typeof value !== "string") continue;
    const hit = authHeaderSymbol(name, value);
    if (hit === null) continue;
    const keep = (reason: string): void => { out.push({ header: name.toLowerCase(), symbol: hit.symbol, restored: false, reason }); };
    if (dest === null) { keep("no upstream host to bind to"); continue; }
    if (!source) { keep("no arbiter op to ask (the human plane is needed)"); continue; }
    let answer: { value: string | null; reason: string };
    try {
      answer = await source.authCredential({ symbol: hit.symbol, destination: dest.host, scheme: dest.scheme, ...(sessionKey ? { sessionKey } : {}) });
    } catch (err) {
      keep(`the arbiter failed: ${(err as Error).message}`);
      continue;
    }
    if (answer.value === null) { keep(answer.reason); continue; }
    if (!HEADER_SAFE_RE.test(answer.value)) { keep("the value is not a header-safe token"); continue; }
    headers[name] = hit.render(answer.value);
    out.push({ header: name.toLowerCase(), symbol: hit.symbol, restored: true, reason: answer.reason });
  }
  return out;
}
