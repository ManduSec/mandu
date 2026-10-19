/**
 * issuer-bindings — the default catalog's ISSUER BINDINGS (confidentiality.md
 * §2.3, 2026-10-19): a credential whose own format names the service that
 * issued it (a Stripe secret key, a GitHub token, …) is put back, with no
 * Approvals card, in a request to that issuer's documented API host, as if
 * a binding of the user's bound it there. Nowhere else.
 *
 * The narrow release, every condition required (`issuerRelease`):
 *
 *   - the VALUE matches exactly one issuer's format, whole (anchored: a
 *     prefix alone is not enough, and a value two formats match is no
 *     issuer's);
 *   - the destination is one of that issuer's hosts EXACTLY: no suffix, no
 *     subdomain, no wildcard (`api.stripe.com.evil.io`, `api-stripe.com`,
 *     `x.api.stripe.com` and `stripe.com` are not `api.stripe.com`), on
 *     port 443 or no stated port, never an address;
 *   - the request is HTTPS, and every place the placeholder sits is the
 *     request's own `Authorization` header (plan 10 §11.13.1's position
 *     rule, the one the wire grants follow): a key in a body, a URL or
 *     another header still asks;
 *   - the switch is on (policy.yaml `issuer_bindings`, default on), the
 *     issuer is not listed under `issuers_off` and the value's name not
 *     under `values_off`.
 *
 * Which rows may use it, and the order against the human's answers, are the
 * gate's (server.ts `issuerReleaseOf`): only a registered file's own field
 * row or a masked environment variable's row, trusted, not from a derived
 * label nor a comment line nor an AI agent's own login file, after every
 * standing answer and the lockdown.
 *
 * THE TABLE IS DELIBERATELY SMALL. An issuer is in it only when its key
 * format names it (a fixed prefix), its documented API takes the key in
 * the `Authorization` header, and its API lives at a fixed set of hosts the
 * issuer's own documentation names (`docs` on each row). Left out, and why
 * (confidentiality.md §2.3): Anthropic (the key goes in `x-api-key`; the
 * agent's own sign-in is never masked), AWS (SigV4 signs with the secret on
 * this machine, so no placeholder can be put back), Twilio (its auth token
 * has no format of its own), GitLab (a `glpat-` token may be a self-managed
 * instance's: the format names no host), Google API keys (many hosts, the
 * key in the URL), Notion's legacy `secret_` tokens (the prefix names no
 * issuer).
 *
 * Pure. Mandu-new (no reference origin).
 */
import { isValueKey, valueKeyMatches } from "./value-bindings.js";

export interface Issuer {
  /** The id `issuers_off` names. */
  id: string;
  /** For people: "Stripe". */
  name: string;
  /** The key formats, each anchored over the whole value. */
  formats: readonly RegExp[];
  /** The formats in words, for `mandu why` and the docs. */
  shapes: readonly string[];
  /** The exact API hosts (lower case, no port). */
  hosts: readonly string[];
  /** Where each host is documented by the issuer itself. */
  docs: readonly string[];
}

/** The table (confidentiality.md §2.3 prints it with its sources). */
export const ISSUERS: readonly Issuer[] = [
  {
    id: "stripe", name: "Stripe",
    formats: [/^(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{20,247}$/],
    shapes: ["sk_live_…", "sk_test_…", "rk_live_…", "rk_test_…"],
    hosts: ["api.stripe.com", "files.stripe.com"],
    docs: ["https://docs.stripe.com/api", "https://docs.stripe.com/api/files/create"],
  },
  {
    id: "github", name: "GitHub",
    formats: [/^gh[pous]_[0-9A-Za-z]{36,251}$/, /^github_pat_[0-9A-Za-z_]{50,244}$/],
    shapes: ["ghp_…", "gho_…", "ghu_…", "ghs_…", "github_pat_…"],
    hosts: ["api.github.com", "uploads.github.com"],
    docs: ["https://docs.github.com/en/rest/authentication/authenticating-to-the-rest-api", "https://docs.github.com/en/rest/releases/assets#upload-a-release-asset"],
  },
  {
    id: "notion", name: "Notion",
    formats: [/^ntn_[0-9A-Za-z]{40,64}$/],
    shapes: ["ntn_…"],
    hosts: ["api.notion.com"],
    docs: ["https://developers.notion.com/reference/authentication"],
  },
  {
    id: "openai", name: "OpenAI",
    formats: [/^sk-(?:proj|svcacct|admin)-[0-9A-Za-z_-]{20,250}$/],
    shapes: ["sk-proj-…", "sk-svcacct-…", "sk-admin-…"],
    hosts: ["api.openai.com"],
    docs: ["https://platform.openai.com/docs/api-reference/authentication"],
  },
  {
    id: "slack", name: "Slack",
    formats: [/^xox[bp]-[0-9A-Za-z-]{20,250}$/],
    shapes: ["xoxb-…", "xoxp-…"],
    hosts: ["slack.com"],
    docs: ["https://docs.slack.dev/apis/web-api/"],
  },
  {
    id: "npm", name: "npm",
    formats: [/^npm_[0-9A-Za-z]{36}$/],
    shapes: ["npm_…"],
    hosts: ["registry.npmjs.org"],
    docs: ["https://docs.npmjs.com/cli/using-npm/registry"],
  },
  {
    id: "pypi", name: "PyPI",
    formats: [/^pypi-AgEIcHlwaS5vcmc[0-9A-Za-z_-]{50,2000}$/],
    shapes: ["pypi-AgEIcHlwaS5vcmc…"],
    hosts: ["upload.pypi.org"],
    docs: ["https://docs.pypi.org/api/upload/", "https://pypi.org/help/#apitoken"],
  },
  {
    id: "huggingface", name: "Hugging Face",
    formats: [/^hf_[0-9A-Za-z]{34}$/],
    shapes: ["hf_…"],
    hosts: ["huggingface.co", "router.huggingface.co"],
    docs: ["https://huggingface.co/docs/hub/security-tokens", "https://huggingface.co/docs/inference-providers/index"],
  },
  {
    id: "sendgrid", name: "SendGrid",
    formats: [/^SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}$/],
    shapes: ["SG.….…"],
    hosts: ["api.sendgrid.com"],
    docs: ["https://www.twilio.com/docs/sendgrid/api-reference/how-to-use-the-sendgrid-v3-api/authentication"],
  },
];

/** The issuer whose format `value` matches, whole; null for none, and for a
 *  value two issuers' formats match (no doubt is resolved toward a send). */
export function issuerOfValue(value: unknown): Issuer | null {
  if (typeof value !== "string" || value.length > 4096) return null;
  const hits = ISSUERS.filter((i) => i.formats.some((f) => f.test(value)));
  return hits.length === 1 ? hits[0]! : null;
}

/** The host of `destination` when it is a plain DNS name on port 443 or on
 *  no stated port (`host`, `host:443`, `https://host[:443]/…`), lower case,
 *  a trailing dot dropped; null for anything else (an address, userinfo, a
 *  wildcard, another port, another scheme). Pure. */
export function issuerDestinationHost(destination: unknown): string | null {
  if (typeof destination !== "string") return null;
  let s = destination.trim();
  const m = /^([a-z][a-z0-9+.-]*):\/\/([^/?#]*)(?:[/?#].*)?$/is.exec(s);
  if (m) {
    if (m[1]!.toLowerCase() !== "https") return null;
    s = m[2]!;
  }
  if (s.includes("@") || s.includes("[") || s.includes("*") || s.includes("/")) return null;
  const parts = s.split(":");
  if (parts.length > 2) return null;
  if (parts.length === 2 && parts[1] !== "443") return null;
  let host = parts[0]!.toLowerCase();
  if (host.endsWith(".")) host = host.slice(0, -1);
  if (!/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(host)) return null;
  return host;
}

/** Is `destination` one of `issuer`'s hosts, exactly? */
export function isIssuerHost(issuer: Issuer, destination: unknown): boolean {
  const host = issuerDestinationHost(destination);
  return host !== null && issuer.hosts.includes(host);
}

/** The issuer that owns `destination` as one of its hosts, or null. */
export function issuerOfHost(destination: unknown): Issuer | null {
  const host = issuerDestinationHost(destination);
  return host === null ? null : ISSUERS.find((i) => i.hosts.includes(host)) ?? null;
}

// ── policy.yaml `issuer_bindings` ────────────────────────────────────────────

/** The compiled switch. */
export interface IssuerBindingSettings {
  /** False: no value is released by its format (every send asks). */
  enabled: boolean;
  /** Issuer ids whose keys still ask. */
  issuersOff: readonly string[];
  /** Value names (a `.env` key, an environment variable; `*` globs, as
   *  `values:` keys) whose keys still ask. */
  valuesOff: readonly string[];
}

/** The default: on for every issuer (a fresh install). */
export const DEFAULT_ISSUER_BINDINGS: IssuerBindingSettings = { enabled: true, issuersOff: [], valuesOff: [] };

const SETTINGS_KEYS = ["issuers_off", "values_off"] as const;

/** Validate `issuer_bindings:`; problems are pushed to `out`. Pure. */
export function checkIssuerBindings(v: unknown, at: string, out: string[]): void {
  if (typeof v === "boolean") return;
  if (v === null || typeof v !== "object" || Array.isArray(v)) {
    out.push(`${at}: must be true, false, or a mapping with issuers_off: and values_off:`);
    return;
  }
  for (const k of Object.keys(v)) {
    if (!(SETTINGS_KEYS as readonly string[]).includes(k)) out.push(`${at}: unknown key '${k}' (allowed: ${SETTINGS_KEYS.join(", ")})`);
  }
  const o = v as Record<string, unknown>;
  if ("issuers_off" in o) {
    if (!Array.isArray(o.issuers_off)) out.push(`${at}.issuers_off: must be a list of issuer ids (${ISSUERS.map((i) => i.id).join(", ")})`);
    else o.issuers_off.forEach((e, i) => {
      if (typeof e !== "string" || !ISSUERS.some((x) => x.id === e)) out.push(`${at}.issuers_off[${i}]: ${JSON.stringify(e)} is not an issuer id (${ISSUERS.map((x) => x.id).join(", ")})`);
    });
  }
  if ("values_off" in o) {
    if (!Array.isArray(o.values_off)) out.push(`${at}.values_off: must be a list of value names (a .env key or an environment variable; * matches any run)`);
    else o.values_off.forEach((e, i) => {
      if (!isValueKey(e)) out.push(`${at}.values_off[${i}]: must be a value name with no spaces`);
    });
  }
}

/** Compile `issuer_bindings:`. Absent: the default (on). Anything malformed
 *  (the validator refuses it at boot and on every write) compiles to OFF:
 *  a switch Mandu cannot read never sends a key without asking. */
export function compileIssuerBindings(raw: unknown): IssuerBindingSettings {
  if (raw === undefined || raw === null) return DEFAULT_ISSUER_BINDINGS;
  if (typeof raw === "boolean") return raw ? DEFAULT_ISSUER_BINDINGS : { enabled: false, issuersOff: [], valuesOff: [] };
  const problems: string[] = [];
  checkIssuerBindings(raw, "issuer_bindings", problems);
  if (problems.length > 0) return { enabled: false, issuersOff: [], valuesOff: [] };
  const o = raw as { issuers_off?: string[]; values_off?: string[] };
  return { enabled: true, issuersOff: [...new Set(o.issuers_off ?? [])], valuesOff: [...new Set(o.values_off ?? [])] };
}

// ── the release ──────────────────────────────────────────────────────────────

export interface IssuerReleaseInput {
  /** The real value of the row the placeholder stands for. */
  value: string;
  /** The names the value goes by (its field, its variable). */
  names: readonly string[];
  destination: unknown;
  /** The request's scheme as the egress proxy stated it. */
  scheme?: unknown;
  /** Every place in the request the placeholder sits. */
  positions?: unknown;
  /** A probe (`mandu why --to`, Test a flow): no request to read, so it
   *  answers for a send in the Authorization header over HTTPS. */
  probe?: boolean;
}

/** Why an issuer release did not apply, for tests and `mandu why`. */
export type IssuerMiss = "off" | "no-issuer" | "issuer-off" | "value-off" | "host" | "scheme" | "position";

/** The issuer that releases this send, or why none does. Pure. */
export function issuerRelease(input: IssuerReleaseInput, settings: IssuerBindingSettings): { issuer: Issuer } | { miss: IssuerMiss } {
  if (!settings.enabled) return { miss: "off" };
  const issuer = issuerOfValue(input.value);
  if (issuer === null) return { miss: "no-issuer" };
  if (settings.issuersOff.includes(issuer.id)) return { miss: "issuer-off" };
  if (input.names.some((n) => settings.valuesOff.some((p) => valueKeyMatches(p, n)))) return { miss: "value-off" };
  if (!isIssuerHost(issuer, input.destination)) return { miss: "host" };
  if (input.probe !== true) {
    if (input.scheme !== "https") return { miss: "scheme" };
    const positions: unknown[] = Array.isArray(input.positions) ? input.positions : [];
    if (positions.length === 0 || !positions.every((p) => p === "authorization")) return { miss: "position" };
  }
  return { issuer };
}
