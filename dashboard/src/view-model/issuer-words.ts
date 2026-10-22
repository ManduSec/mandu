/**
 * issuer-words — the Rules page's words for the built-in issuer bindings
 * (dashboard.md §4.25z, confidentiality.md §2.3): a key whose format names
 * the company that issued it goes, with no Approvals card, to that company's
 * own API host. On by default; policy.yaml `issuer_bindings` turns it off,
 * for every company, for some (`issuers_off`) or for some values
 * (`values_off`). Mandu-new (no reference origin).
 *
 * ISSUER_TABLE is a DISPLAY COPY of the arbiter's `ISSUERS`
 * (arbiter/policy/issuer-bindings.ts: id, name, hosts; never the formats):
 * the dashboard does not import the arbiter (the arbiter-client
 * convention), so tests/stack/issuer-table-parity keeps the copy equal, and
 * keeps `issuerState` equal to the arbiter's `compileIssuerBindings` over
 * the same inputs. Display only: nothing here decides a send.
 *
 * Pure.
 */

import type { HomeTextPart } from "./ask-words.js";

/** One company whose keys go to its own API without asking. */
export interface IssuerRow {
  /** The id `issuers_off` names. */
  id: string;
  name: string;
  /** The exact API hosts. */
  hosts: readonly string[];
}

/** The arbiter's table, as people read it (same order). */
export const ISSUER_TABLE: readonly IssuerRow[] = [
  { id: "stripe", name: "Stripe", hosts: ["api.stripe.com", "files.stripe.com"] },
  { id: "github", name: "GitHub", hosts: ["api.github.com", "uploads.github.com"] },
  { id: "notion", name: "Notion", hosts: ["api.notion.com"] },
  { id: "openai", name: "OpenAI", hosts: ["api.openai.com"] },
  { id: "slack", name: "Slack", hosts: ["slack.com"] },
  { id: "npm", name: "npm", hosts: ["registry.npmjs.org"] },
  { id: "pypi", name: "PyPI", hosts: ["upload.pypi.org"] },
  { id: "huggingface", name: "Hugging Face", hosts: ["huggingface.co", "router.huggingface.co"] },
  { id: "sendgrid", name: "SendGrid", hosts: ["api.sendgrid.com"] },
];

/** The switch as the arbiter compiles it (`IssuerBindingSettings`). */
export interface IssuerSettings {
  enabled: boolean;
  issuersOff: readonly string[];
  valuesOff: readonly string[];
}

const ON: IssuerSettings = { enabled: true, issuersOff: [], valuesOff: [] };
const OFF: IssuerSettings = { enabled: false, issuersOff: [], valuesOff: [] };
const KEYS = ["issuers_off", "values_off"];
/** `isValueKey` (arbiter/policy/value-bindings.ts): a name, no spaces. */
const isValueName = (k: unknown): k is string => typeof k === "string" && k !== "" && k.length <= 256 && !/[\s\u0000-\u001f\u007f]/.test(k);

/**
 * policy.yaml's `issuer_bindings` as the arbiter reads it
 * (`compileIssuerBindings`): absent is on; `true` on, `false` off; a mapping
 * is on except its `issuers_off` and `values_off`; anything malformed is
 * OFF, as the arbiter compiles it (a switch it cannot read never sends).
 */
export function issuerState(raw: unknown): IssuerSettings {
  if (raw === undefined || raw === null) return ON;
  if (typeof raw === "boolean") return raw ? ON : OFF;
  if (typeof raw !== "object" || Array.isArray(raw)) return OFF;
  const o = raw as Record<string, unknown>;
  if (Object.keys(o).some((k) => !KEYS.includes(k))) return OFF;
  const issuers = "issuers_off" in o ? o.issuers_off : [];
  const values = "values_off" in o ? o.values_off : [];
  if (!Array.isArray(issuers) || !issuers.every((e) => typeof e === "string" && ISSUER_TABLE.some((i) => i.id === e))) return OFF;
  if (!Array.isArray(values) || !values.every(isValueName)) return OFF;
  return { enabled: true, issuersOff: [...new Set(issuers as string[])], valuesOff: [...new Set(values as string[])] };
}

/** What the home route read: policy.yaml's `issuer_bindings` as in force
 *  (`raw`, absent when the file has none), or nothing (`read: false`: no
 *  reader, or a read that failed). */
export type IssuerReading = { read: true; raw: unknown } | { read: false };

/** The Rules page item. */
export interface HomeIssuerItem {
  /** `partly`: on, with some companies or values asking. */
  state: "on" | "partly" | "off" | "unknown";
  /** The item's sentence: `parts` joined. */
  text: string;
  parts: HomeTextPart[];
  /** Each company and its hosts, for the "Which companies" fold; `off`
   *  when its keys still ask. Empty when the item is off or unknown. */
  companies: Array<{ name: string; hosts: string[]; off: boolean }>;
  /** How to change it, as policy.yaml text; null when the state is unknown. */
  change: { text: string; parts: HomeTextPart[] } | null;
}

/** A sentence written with its code spans between backticks. */
function marked(s: string): { text: string; parts: HomeTextPart[] } {
  const parts = s.split("`")
    .map((text, i): HomeTextPart => ({ kind: i % 2 ? "code" : "text", text }))
    .filter((p) => p.text !== "");
  return { text: parts.map((p) => p.text).join(""), parts };
}

const SENT = "A key whose format names the company that issued it goes to that company's own API without asking.";

/** The item for what the route read. Never "on" for a state it could not read. */
export function issuerItem(reading: IssuerReading | undefined): HomeIssuerItem {
  if (!reading || !reading.read) {
    return {
      state: "unknown",
      ...marked("Mandu could not read whether a key whose format names the company that issued it goes to that company's own API without asking."),
      companies: [],
      change: null,
    };
  }
  const s = issuerState(reading.raw);
  if (!s.enabled) {
    const why = reading.raw === false
      ? "(`issuer_bindings` is off in `policy.yaml`)"
      : "(the `issuer_bindings` setting in `policy.yaml` is not valid, so it is off)";
    return {
      state: "off",
      ...marked(`Every key asks before it goes to its company's API ${why}.`),
      companies: [],
      change: marked("To turn it back on, remove `issuer_bindings` from `policy.yaml`."),
    };
  }
  const offNames = ISSUER_TABLE.filter((i) => s.issuersOff.includes(i.id)).map((i) => i.name);
  const offValues = s.valuesOff.map((v) => `\`${v}\``).join(", ");
  const offFor = offNames.length && offValues ? `${offNames.join(", ")}; and for ${offValues}` : offNames.length ? offNames.join(", ") : offValues;
  return {
    state: offFor ? "partly" : "on",
    ...marked(offFor ? `${SENT} Off for: ${offFor}.` : SENT),
    companies: ISSUER_TABLE.map((i) => ({ name: i.name, hosts: [...i.hosts], off: s.issuersOff.includes(i.id) })),
    change: marked("To have every key ask, write `issuer_bindings: false` in `policy.yaml`; for one company only, `issuer_bindings: { issuers_off: [stripe] }`."),
  };
}

/**
 * The company whose own API `host` is, exactly as the table names it (case,
 * a `:443` and a trailing dot aside), while its keys go there without
 * asking; null for every other host (a subdomain, a lookalike), a company
 * `issuers_off` names, the switch off or malformed, and a switch not read.
 * The session page's sent step says with it why nobody asked (dashboard.md
 * §4.25b, *A send to its company's own API says why it did not ask*).
 * Display only: it knows the host, never which rule let a send through.
 */
export function issuerOfHost(host: string, reading: IssuerReading | undefined): IssuerRow | null {
  if (!reading || !reading.read) return null;
  const s = issuerState(reading.raw);
  if (!s.enabled) return null;
  const h = host.toLowerCase().replace(/:443$/, "").replace(/\.$/, "");
  const row = ISSUER_TABLE.find((i) => i.hosts.includes(h));
  return row && !s.issuersOff.includes(row.id) ? row : null;
}
