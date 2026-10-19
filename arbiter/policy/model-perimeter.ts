/**
 * model-perimeter — policy.yaml `perimeter:`, the organization's own networks
 * (docs/design/confidentiality/model-endpoints.md §2 D4).
 *
 *   perimeter:
 *     networks: [ 10.0.0.0/8, "fd00:1234::/32" ]   # enforced
 *     domains:  [ corp.example ]                   # words only
 *
 * When `networks` is present, a `local: true` endpoint on another machine
 * (placement `network`, model-placement.ts) must resolve, at every connection,
 * only to addresses inside it. The arbiter does not dial anything: it compiles
 * the list onto each such endpoint (`ModelEndpoint.perimeter`), and every
 * client that dials one (the helper, the model proxies, doctor, the dashboard's
 * Test connection) checks the addresses in the shared `endpoint-tls.ts`
 * module; the launcher refuses a launch on an address outside it. Here, at
 * load: the section's syntax, and an entry whose url is a literal address
 * outside the list (no lookup can ever change that answer).
 *
 * `domains` is not enforcement (a name suffix proves nothing about where it
 * resolves): a matching `network` endpoint is marked `orgDomain`, so doctor
 * and the dashboard can say "on your organization's network".
 *
 * Pure. PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code.
 */
import { BlockList, isIP } from "node:net";

import { endpointPlacement } from "./model-placement.js";

/** The compiled section. `networks` null = no enforcement. */
export interface Perimeter {
  readonly networks: readonly string[] | null;
  readonly domains: readonly string[];
}

export interface Cidr {
  readonly address: string;
  readonly prefix: number;
  readonly family: "ipv4" | "ipv6";
}

/** `a.b.c.d/n`, `x::/n`, or a bare address (one host). null when malformed. */
export function parseCidr(s: unknown): Cidr | null {
  if (typeof s !== "string") return null;
  const m = /^([^/\s]+)(?:\/(\d{1,3}))?$/.exec(s.trim());
  if (!m) return null;
  const address = m[1]!.replace(/^\[|\]$/g, "");
  const v = isIP(address);
  if (v === 0) return null;
  const family = v === 4 ? "ipv4" : "ipv6";
  const max = v === 4 ? 32 : 128;
  const prefix = m[2] === undefined ? max : Number(m[2]);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > max) return null;
  return { address, prefix, family };
}

/** An IPv4-mapped IPv6 address (`::ffff:10.0.0.1`) as its IPv4 form. */
export function unmapAddress(address: string): string {
  const a = address.toLowerCase().replace(/^\[|\]$/g, "");
  const dotted = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(a);
  if (dotted) return dotted[1]!;
  const hex = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(a);
  if (hex) {
    const hi = parseInt(hex[1]!, 16);
    const lo = parseInt(hex[2]!, 16);
    return `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
  }
  return a;
}

function blockListOf(networks: readonly string[]): BlockList {
  const bl = new BlockList();
  for (const n of networks) {
    const c = parseCidr(n);
    if (c) bl.addSubnet(c.address, c.prefix, c.family);
  }
  return bl;
}

/** Is this address inside one of the networks? A malformed address is not. */
export function inPerimeter(address: string, networks: readonly string[]): boolean {
  const a = unmapAddress(address);
  const v = isIP(a);
  if (v === 0) return false;
  return blockListOf(networks).check(a, v === 4 ? "ipv4" : "ipv6");
}

/** Is `inner` wholly inside `outer`? (A narrower or equal network.) */
export function cidrWithin(inner: string, outer: string): boolean {
  const i = parseCidr(inner);
  const o = parseCidr(outer);
  if (!i || !o || i.family !== o.family || i.prefix < o.prefix) return false;
  return inPerimeter(i.address, [outer]);
}

/** Is every network of `inner` inside one of `outer`'s? */
export function networksWithin(inner: readonly string[], outer: readonly string[]): boolean {
  return inner.every((n) => outer.some((o) => cidrWithin(n, o)));
}

const DOMAIN_RE = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/;

function normalizeDomain(d: string): string {
  return d.trim().toLowerCase().replace(/^\*?\./, "").replace(/\.$/, "");
}

/** Does the host equal one of the domains or sit under one? */
export function domainMatches(host: string, domains: readonly string[]): boolean {
  const h = host.toLowerCase().replace(/\.$/, "");
  return domains.some((d) => h === d || h.endsWith(`.${d}`));
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

/** Validate the section (problems appended to `out`). */
export function checkPerimeter(v: unknown, at: string, out: string[]): void {
  if (!isPlainObject(v)) {
    out.push(`${at}: must be a mapping with 'networks' (a list of CIDRs) and/or 'domains' (a list of names)`);
    return;
  }
  for (const k of Object.keys(v)) {
    if (k !== "networks" && k !== "domains") out.push(`${at}.${k}: unknown key (allowed: networks, domains)`);
  }
  if (!("networks" in v) && !("domains" in v)) out.push(`${at}: needs 'networks' and/or 'domains' (an empty perimeter says nothing)`);
  if ("networks" in v) {
    if (!Array.isArray(v.networks) || v.networks.length === 0) {
      out.push(`${at}.networks: must be a non-empty list of networks such as 10.0.0.0/8 or fd00::/8 (remove it to check no addresses)`);
    } else {
      (v.networks as unknown[]).forEach((n, i) => {
        if (parseCidr(n) === null) out.push(`${at}.networks[${i}]: not a network: ${JSON.stringify(n)} (write an address with its prefix length, such as 10.0.0.0/8)`);
      });
    }
  }
  if ("domains" in v) {
    if (!Array.isArray(v.domains)) out.push(`${at}.domains: must be a list of names such as corp.example`);
    else {
      (v.domains as unknown[]).forEach((d, i) => {
        if (typeof d !== "string" || !DOMAIN_RE.test(normalizeDomain(d))) out.push(`${at}.domains[${i}]: not a domain name: ${JSON.stringify(d)}`);
      });
    }
  }
}

/** The compiled section, or null when absent or malformed (validation runs first). */
export function compilePerimeter(v: unknown): Perimeter | null {
  if (!isPlainObject(v)) return null;
  const networks = Array.isArray(v.networks) && v.networks.length > 0 && v.networks.every((n) => parseCidr(n) !== null)
    ? Object.freeze((v.networks as string[]).map((n) => n.trim()))
    : null;
  const domains = Array.isArray(v.domains)
    ? Object.freeze((v.domains as unknown[]).filter((d): d is string => typeof d === "string").map(normalizeDomain).filter((d) => DOMAIN_RE.test(d)))
    : Object.freeze([] as string[]);
  if (networks === null && domains.length === 0) return null;
  return Object.freeze({ networks, domains });
}

/** The url's host, brackets stripped, or null. */
export function urlHost(url: string): string | null {
  try { return new URL(url).hostname.replace(/^\[|\]$/g, "") || null; } catch { return null; }
}

/** Does the perimeter's address check apply to this entry? A `local: true`
 *  entry on another machine, with `networks` present. */
export function perimeterApplies(entry: { url?: unknown; local?: unknown }, p: Perimeter | null): p is Perimeter & { networks: readonly string[] } {
  return p !== null && p.networks !== null && entry.local === true && typeof entry.url === "string" && endpointPlacement(entry.url) === "network";
}

/** The load-time check: a `local: true` entry whose url is a literal address
 *  outside the perimeter can never pass the connection check. */
export function checkLiteralsInPerimeter(models: unknown, p: Perimeter | null, at: string, out: string[]): void {
  if (!Array.isArray(models) || p === null || p.networks === null) return;
  (models as unknown[]).forEach((e, i) => {
    if (!isPlainObject(e) || !perimeterApplies(e, p)) return;
    const host = urlHost(String(e.url));
    if (host === null || isIP(unmapAddress(host)) === 0) return;
    if (!inPerimeter(host, p.networks!)) {
      const label = typeof e.name === "string" ? e.name : `models[${i}]`;
      out.push(`${at}[${i}].url: '${label}' is at ${host}, outside perimeter.networks (${p.networks!.join(", ")}); fix the address or list its network`);
    }
  });
}
