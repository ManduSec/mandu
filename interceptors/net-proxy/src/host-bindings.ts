/**
 * host-bindings — the net-proxy's copy of the ONE binding rule: does a
 * destination fall under a secret's `bindings`, and does one binding admit
 * every destination another does (confidentiality.md §2.2).
 *
 * Copied from the arbiter (`arbiter/policy/host-bindings.ts`, which carries
 * the table and the history): the proxy refuses a holder's send by this rule
 * (egress.ts `hostIsBound`) and the arbiter files the question by its own, so
 * the two must agree to the character. This package does not import the
 * arbiter (the arbiter-client pattern), so the text below the marker is kept
 * identical to the arbiter's; `tests/stack/host-binding-parity.test.ts`
 * fails when they drift, and runs one case table through both.
 *
 * Pure.
 */

// ── the rule: identical in both copies below this line (host-binding-parity.test.ts) ──

import { isIP } from "node:net";

/** A binding as this module reads it: a name (bare or `*.`), an address, or
 *  nothing it can match a host against (null). */
type ParsedBinding =
  | { kind: "name"; host: string; wild: boolean; port: string | null }
  | { kind: "addr"; host: string; port: string | null };

/** `unix:` and `mount:` bindings name local sinks, compared by equality in
 *  their own legs; they never match a network host. */
export function isPathBinding(b: string): boolean {
  return b.startsWith("unix:") || b.startsWith("mount:");
}

/** Split `host`, `host:port`, `[v6]` or `[v6]:port`. A bare IPv6 address
 *  (more than one colon, no brackets) is the host whole. Null when the port
 *  is neither digits nor `*`. */
function splitHostPort(s: string): { host: string; port: string | null } | null {
  if (s.startsWith("[")) {
    const end = s.indexOf("]");
    if (end < 0) return null;
    const host = s.slice(1, end);
    const rest = s.slice(end + 1);
    if (rest === "") return { host, port: null };
    if (!rest.startsWith(":")) return null;
    const port = rest.slice(1);
    if (port === "*") return { host, port: null };
    return /^\d+$/.test(port) ? { host, port } : null;
  }
  const colons = s.split(":").length - 1;
  if (colons === 0) return { host: s, port: null };
  if (colons > 1) return isIP(s) === 6 ? { host: s, port: null } : null;
  const at = s.indexOf(":");
  const host = s.slice(0, at);
  const port = s.slice(at + 1);
  if (port === "*") return { host, port: null };
  return /^\d+$/.test(port) ? { host, port } : null;
}

function cleanName(h: string): string {
  const l = h.trim().toLowerCase();
  return l.endsWith(".") ? l.slice(0, -1) : l;
}

/** An IP literal as compared: IPv4 as written, IPv6 in its canonical text
 *  (lower case, the longest zero run compressed: `2001:db8:0::1` →
 *  `2001:db8::1`). Null for an IPv6 literal with a zone id, or a string that
 *  is no IP literal. */
function canonicalAddress(h: string): string | null {
  if (h.includes("%")) return null;
  const kind = isIP(h);
  if (kind === 4) return h;
  if (kind !== 6) return null;
  try {
    return new URL(`http://[${h}]/`).hostname.slice(1, -1);
  } catch {
    return null;
  }
}

/** Strip a URL down to its authority (`https://a.b:8443/x` → `a.b:8443`),
 *  dropping any userinfo. Anything else is returned trimmed. */
function authorityOf(raw: string): string {
  let s = raw.trim();
  const m = /^[a-z][a-z0-9+.-]*:\/\/([^/?#]*)/i.exec(s);
  if (m) s = m[1]!;
  const at = s.lastIndexOf("@");
  if (at >= 0) s = s.slice(at + 1);
  return s;
}

function parseBinding(raw: string): ParsedBinding | null {
  const b = raw.trim();
  if (b === "" || b === "*" || isPathBinding(b) || (b.includes("/") && !/^[a-z][a-z0-9+.-]*:\/\//i.test(b))) return null;
  const hp = splitHostPort(authorityOf(b));
  if (hp === null) return null;
  const host = cleanName(hp.host);
  if (host === "" || host.includes("%")) return null;
  if (isIP(host) !== 0) {
    const addr = canonicalAddress(host);
    return addr === null ? null : { kind: "addr", host: addr, port: hp.port };
  }
  const wild = host.startsWith("*.");
  const name = wild ? host.slice(2) : host;
  if (name === "" || name.includes("*")) return null;
  return { kind: "name", host: name, wild, port: hp.port };
}

function parseDestination(raw: string): { host: string; port: string | null } | null {
  const hp = splitHostPort(authorityOf(raw).split(/[/?#]/)[0]!);
  if (hp === null) return null;
  const host = cleanName(hp.host);
  if (host === "" || host.includes("*") || host.includes("/") || host.includes("%")) return null;
  if (isIP(host) !== 0) {
    const addr = canonicalAddress(host);
    return addr === null ? null : { host: addr, port: hp.port };
  }
  return { host, port: hp.port };
}

/** Is `host` the name `name` or under it, by whole labels? */
function atOrUnder(host: string, name: string): boolean {
  return host === name || host.endsWith(`.${name}`);
}

/** Does ONE binding admit `destination` (table in the header)? */
export function bindingAdmits(destination: string, binding: string): boolean {
  const d = parseDestination(destination);
  const b = parseBinding(binding);
  if (d === null || b === null) return false;
  if (b.port !== null && d.port !== null && b.port !== d.port) return false;
  if (b.kind === "addr") return d.host === b.host;
  if (isIP(d.host) !== 0) return false;
  return b.wild ? d.host.endsWith(`.${b.host}`) : atOrUnder(d.host, b.host);
}

/** Does `destination` fall under one of `bindings`? Empty or missing
 *  bindings admit nothing. */
export function destinationMatchesBindings(destination: string, bindings: readonly string[] | null | undefined): boolean {
  if (!bindings || bindings.length === 0) return false;
  return bindings.some((b) => bindingAdmits(destination, b));
}

/**
 * Does binding `outer` admit every destination binding `inner` admits?
 * CONSERVATIVE: false unless sure. Equal bindings cover each other (case
 * folded but for `unix:`/`mount:`, compared exactly); a port-less binding
 * covers any port of what it covers, one with a port only that port; a bare
 * name covers itself, every name under it and every `*.` at or under it; a
 * `*.x` covers names and `*.`s strictly under `x`, never `x`; an address
 * covers only itself; a CIDR covers only itself. Pure.
 */
export function bindingCovers(outer: string, inner: string): boolean {
  const o = outer.trim();
  const i = inner.trim();
  if (isPathBinding(o) || isPathBinding(i)) return o === i;
  if (o.toLowerCase() === i.toLowerCase()) return true;
  const a = parseBinding(o);
  const b = parseBinding(i);
  if (a === null || b === null) return false;
  if (a.port !== null && a.port !== b.port) return false;
  if (a.kind === "addr" || b.kind === "addr") return a.kind === b.kind && a.host === b.host;
  if (!a.wild) return atOrUnder(b.host, a.host);
  return b.wild ? atOrUnder(b.host, a.host) : b.host.endsWith(`.${a.host}`);
}
