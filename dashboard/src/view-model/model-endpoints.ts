/**
 * view-model/model-endpoints — the declared model endpoints (confidentiality
 * plan 11 D2 / D6) as the dashboard shows them, and "which model read this"
 * for an inspect step.
 *
 * Mandu-new (no reference origin). Two read-only projections:
 *
 *   1. `toModelEndpointRows(document.models)`: the policy.yaml `models:` list
 *      from the arbiter's policy snapshot, for the product page's Settings and
 *      for the Rules page's level picker (the "Your own AI only" choice is
 *      offered only when at least one entry says `local: true`). Fields are
 *      copied EXPLICITLY, never spread: a future arbiter that started sending
 *      a token value could not have it reach the page by accident. Only the
 *      NAME of the token's environment variable is ever shown.
 *
 *   2. `endpointOf(event)` + `readByWords(ref)`: the top-level `endpoint` an inspect
 *      (`ullm_call`) event records, as words: "read by your own model
 *      (ollama)" or "read by the helper". An event without the field (an
 *      older inspect-mcp) yields null and the caller renders as before.
 *
 * Location is a DECLARATION (plan 11 D2): an endpoint is local only when the
 * snapshot or the event says so. Nothing here infers it from an address.
 * PLACEMENT is derived from the address (plan 12 D1): `host` when the url's
 * host is a loopback spelling (this computer), else `network` (another
 * machine, "your organization's network" in the words). It never makes an
 * entry local; it says where a local one is and how it must be reached.
 */

export type ModelWire = "anthropic" | "openai-chat";

/** One `models:` entry as the arbiter's policy snapshot carries it
 *  (`document.models`, plan 11 D2). Every field but `name`/`url` optional on
 *  the wire so a half-formed row still renders. */
export interface ModelEndpointWire {
  name: string;
  url: string;
  wire?: ModelWire | string;
  model?: string;
  local?: boolean;
  tokenEnv?: string;
  /** policy.yaml `helper: true` (present only when true). */
  helper?: boolean;
  /** policy.yaml `allow_plain_http: true` (plan 12 D2, present only when true). */
  allowPlainHttp?: boolean;
  /** policy.yaml `tls:` compiled (plan 12 D3): paths and pins. */
  tls?: { caFile?: string; pinSha256?: readonly string[]; clientCert?: string; clientKey?: string };
}

/** One declared model, ready to render (no token value, by construction). */
export interface ModelEndpointRow {
  name: string;
  url: string;
  wire: string;
  /** The API style in words ("Anthropic Messages", "OpenAI chat"). */
  wireWords: string;
  model: string | null;
  local: boolean;
  /** "Your own model" | "Outside model" (confidentiality.md §2). */
  where: string;
  /** The env var that holds the token, by NAME only; null when none. */
  tokenEnv: string | null;
  /** policy.yaml `helper: true` as written on this entry. */
  helperMarked: boolean;
  /** The entry the quarantined helper reads "your own model only" files
   *  with: the local entry marked `helper: true`, else the first local entry
   *  (inspect-mcp's `helperEndpoint`, the same rule). */
  helper: boolean;
  /** Plan 12 D1: `host` (this computer) | `network` (another machine) |
   *  null (an address that does not parse). */
  placement: "host" | "network" | null;
  /** The placement in words: "On this computer" | "On your network
   *  (llm.corp.example)"; null for an outside model or an unusable url. */
  placementWords: string | null;
  /** policy.yaml `allow_plain_http: true` as written on this entry. */
  allowPlainHttp: boolean;
  /** A local entry reached over plain http on another machine (only by the
   *  opt-out: the file refuses it otherwise). Shown as "Not encrypted". */
  notEncrypted: boolean;
  /** Plan 12 D3: the configured TLS checks in words ("checked with your
   *  CA, a pinned key"), null when the entry names none. Never a path. */
  tlsWords: string | null;
  /** Plan 12 D4: "only at addresses in 10.0.0.0/8" when the law holds this
   *  entry to `perimeter.networks`; null otherwise. */
  perimeterWords: string | null;
  /** Plan 12 D5: set in the administrator's file (no Edit on the page). */
  admin: boolean;
  /** Plan 12 D5: set by the administrator and locked. */
  locked: boolean;
  /** The entry's version as read (the snapshot's `modelVersions`; an
   *  opaque keyed hash, policy-surface.md §8.4.6 "An item-level version"):
   *  the form's update sends it back, so a change made to the same entry
   *  meanwhile refuses the save instead of being overwritten. null when
   *  the arbiter sends none (an older one). */
  version: string | null;
}

export const OWN_MODEL = "Your own model";
export const OUTSIDE_MODEL = "Outside model";

/** Where a model url sits (plan 12 D1): `host` when its host is a loopback
 *  spelling (`localhost`, `*.localhost`, 127.0.0.0/8, `::1`, the unspecified
 *  addresses), else `network`; null when it is not an http(s) url with a
 *  host. MIRROR of arbiter/policy/model-placement.ts `endpointPlacement`
 *  (the dashboard never imports the arbiter); pinned with the other copies
 *  by tests/stack/model-placement-parity.test.ts. Pure. */
export function endpointPlacement(url: string): "host" | "network" | null {
  let u: URL;
  try { u = new URL(url.trim()); } catch { return null; }
  if ((u.protocol !== "http:" && u.protocol !== "https:") || u.hostname === "") return null;
  let h = u.hostname.toLowerCase();
  if (h.startsWith("[") && h.endsWith("]")) h = h.slice(1, -1);
  if (h.endsWith(".")) h = h.slice(0, -1);
  const mapped = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(h);
  if (mapped) {
    const hi = parseInt(mapped[1]!, 16);
    const lo = parseInt(mapped[2]!, 16);
    h = `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
  }
  if (h === "localhost" || h.endsWith(".localhost")) return "host";
  if (h === "::1" || h === "::" || h === "0:0:0:0:0:0:0:1") return "host";
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  if (m) {
    const o = m.slice(1).map(Number);
    if (o.every((n) => n <= 255) && (o[0] === 127 || o.every((n) => n === 0))) return "host";
  }
  return "network";
}

/** "On this computer" | "On your network (host)" | "On your organization's
 *  network (host)" (the host is under `perimeter.domains`, plan 12 D4). Pure. */
export function placementWords(url: string, orgDomain = false): string | null {
  const p = endpointPlacement(url);
  if (p === null) return null;
  if (p === "host") return "On this computer";
  return `On your ${orgDomain ? "organization's " : ""}network (${new URL(url.trim()).hostname.replace(/^\[|\]$/g, "")})`;
}

/** "checked with your CA, a pinned key and a client certificate", or null. */
export function tlsWordsOf(raw: unknown): string | null {
  if (!raw || typeof raw !== "object") return null;
  const t = raw as Record<string, unknown>;
  const parts = [
    ...(typeof t["caFile"] === "string" ? ["your CA"] : []),
    ...(Array.isArray(t["pinSha256"]) && t["pinSha256"].length > 0 ? ["a pinned key"] : []),
    ...(typeof t["clientCert"] === "string" ? ["a client certificate"] : []),
  ];
  if (parts.length === 0) return null;
  const list = parts.length === 1 ? parts[0] : `${parts.slice(0, -1).join(", ")} and ${parts[parts.length - 1]}`;
  return `TLS checked with ${list}`;
}

function wireWordsOf(wire: string): string {
  return wire === "openai-chat" ? "OpenAI chat" : wire === "anthropic" ? "Anthropic Messages" : wire;
}

/** Project `document.models`. Absent, not an array, or empty ⇒ []. A row
 *  without a string name is dropped (nothing to call it by). `local` is true
 *  only for a literal `true` (fail closed: a typo is an outside model). */
export function toModelEndpointRows(raw: unknown, versions?: unknown): ModelEndpointRow[] {
  if (!Array.isArray(raw)) return [];
  const vs = versions && typeof versions === "object" && !Array.isArray(versions) ? (versions as Record<string, unknown>) : {};
  const rows: ModelEndpointRow[] = [];
  for (const m of raw as unknown[]) {
    if (!m || typeof m !== "object") continue;
    const r = m as Record<string, unknown>;
    if (typeof r["name"] !== "string" || r["name"] === "") continue;
    const wire = typeof r["wire"] === "string" && r["wire"] !== "" ? (r["wire"] as string) : "anthropic";
    const local = r["local"] === true;
    const tokenEnv = typeof r["tokenEnv"] === "string" && r["tokenEnv"] !== "" ? (r["tokenEnv"] as string) : null;
    const url = typeof r["url"] === "string" ? (r["url"] as string) : "";
    const placement = endpointPlacement(url);
    const allowPlainHttp = r["allowPlainHttp"] === true;
    let http = false;
    try { http = new URL(url.trim()).protocol === "http:"; } catch { http = false; }
    rows.push({
      name: r["name"] as string,
      url,
      wire,
      wireWords: wireWordsOf(wire),
      model: typeof r["model"] === "string" && r["model"] !== "" ? (r["model"] as string) : null,
      local,
      where: local ? OWN_MODEL : OUTSIDE_MODEL,
      tokenEnv,
      helperMarked: local && r["helper"] === true,
      helper: false,
      placement,
      placementWords: local ? placementWords(url, r["orgDomain"] === true) : null,
      allowPlainHttp,
      notEncrypted: local && placement === "network" && http,
      tlsWords: tlsWordsOf(r["tls"]),
      perimeterWords: Array.isArray(r["perimeter"]) && r["perimeter"].length > 0
        ? `only at addresses in ${(r["perimeter"] as unknown[]).filter((n): n is string => typeof n === "string").join(", ")}`
        : null,
      admin: typeof r["adminFile"] === "string",
      locked: typeof r["adminFile"] === "string" && r["locked"] === true,
      version: typeof vs[r["name"] as string] === "string" && /^[0-9a-f]{32}$/.test(vs[r["name"] as string] as string) ? (vs[r["name"] as string] as string) : null,
    });
  }
  const helper = rows.find((r) => r.helperMarked) ?? rows.find((r) => r.local);
  if (helper) helper.helper = true;
  return rows;
}

/** Under a "your own model only" rule while no `local: true` model is
 *  declared: such a label behaves as "hidden from every model" (plan 11 D2),
 *  which loses nothing, but the person should know nothing reads the file.
 *  home.js carries the same words for the labels made on the page. */
export const NO_OWN_MODEL_WARNING = "No AI of your own is listed, so no AI reads this file. Add one in Settings › Models.";

/** Does the snapshot declare at least one model the user runs themselves?
 *  The Rules page offers "Your own AI only" exactly when this holds. */
export function hasLocalModel(rows: readonly ModelEndpointRow[] | null | undefined): boolean {
  return !!rows && rows.some((r) => r.local);
}

// ── which model read a datum (the inspect event's `endpoint`) ───────────────

export interface ModelEndpointRef {
  name: string;
  location: "local" | "external";
  /** Plan 12 D6: where the declared model is, when the event says. */
  placement?: "host" | "network";
  /** Plan 12 D2: the call crossed a network unencrypted (the opt-out). */
  plainHttp?: true;
}

function refOf(v: unknown): ModelEndpointRef | null {
  if (!v || typeof v !== "object") return null;
  const r = v as Record<string, unknown>;
  if (typeof r["name"] !== "string" || r["name"] === "") return null;
  // Only a literal "local" is local; anything else reads as outside.
  const location = r["location"] === "local" ? "local" : "external";
  const placement = r["placement"] === "host" || r["placement"] === "network" ? r["placement"] : undefined;
  return {
    name: r["name"] as string,
    location,
    ...(placement ? { placement } : {}),
    ...(location === "local" && placement === "network" && r["plainHttp"] === true ? { plainHttp: true as const } : {}),
  };
}

/** The endpoint an event recorded (the ullm_call's top-level `endpoint`,
 *  plan 11's contract with inspect-mcp), or null when none is recorded. */
export function endpointOf(e: unknown): ModelEndpointRef | null {
  if (!e || typeof e !== "object") return null;
  return refOf((e as Record<string, unknown>)["endpoint"]);
}

/** "read by your own model (ollama)" | "read by the helper", with the
 *  placement when the event records it (plan 12 D6): "read by your own model
 *  (corp-vllm), on your network" / "…, on this computer", and ", not
 *  encrypted" for an opted-in plain-http call. inspect-mcp
 *  routes only to a declared `local: true` entry or to the default helper
 *  (plan 11 D5), so a named outside endpoint is not a case it produces; an
 *  event that says so anyway (a future router, or an entry that stopped
 *  being local) reads "read by an outside model (<name>)", never as local. */
export function readByWords(ref: ModelEndpointRef | null | undefined): string | null {
  if (!ref) return null;
  if (ref.location === "local") {
    const where = ref.placement === "network" ? ", on your network" : ref.placement === "host" ? ", on this computer" : "";
    return `read by your own model (${ref.name})${where}${ref.plainHttp ? ", not encrypted" : ""}`;
  }
  return ref.name === "default" ? "read by the helper" : `read by an outside model (${ref.name})`;
}
