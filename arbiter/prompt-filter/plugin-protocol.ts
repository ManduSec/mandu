/**
 * plugin-protocol — the wire between the arbiter and an out-of-process
 * prompt filter plugin (confidentiality-plan-15-prompt-filter.md §4.3, phase
 * 3). Mandu-new (no reference origin). Pure: no I/O.
 *
 * ONE JSON REQUEST ON STDIN, one JSON answer on stdout, stderr discarded:
 *
 *   request  {"protocol": "mandu-prompt-filter/1", "filter": "<pack id>",
 *             "segments": [{"id", "origin", "text"}],
 *             "categories": ["pii.person", …],          // the pack's declared list
 *             "deadlineMs": 5000,
 *             "endpoint": {"name", "url", "wire", "model"?, "tokenEnv"?}}   // only when the
 *                                                           // plugin needs a model
 *   answer   {"findings": [{"segment": "<id>", "start": 4, "end": 9,
 *                           "category": "pii.person", "confidence"?: 0.93}]}
 *
 * THE ANSWER IS CHECKED AGAINST A CLOSED SHAPE (§4.3, §12 2026-10-03): only
 * the key `findings` at the top, only `segment`, `start`, `end`, `category`
 * and an optional `confidence` in a finding; a segment id from the request;
 * whole-number offsets in UTF-16 code units inside that segment's text with
 * `start < end`; a category from the pack's declared list, exactly. Anything
 * else refuses the WHOLE answer: a filter error, which the policy's
 * `on_error` decides (§4.4). A plugin can only ADD findings: it never removes
 * another filter's, and nothing it says sets a level: a `mask` mints at the
 * level the pack declares for the category (default `no-model`).
 */
import type { ConfidentialityLevel } from "../symbol-table/confidentiality.js";
import type { Finding, SegmentOrigin } from "./filter.js";
import type { PluginCategory } from "./packs.js";

export const PLUGIN_PROTOCOL = "mandu-prompt-filter/1";
/** The most stdout a plugin may write (larger is a filter error). */
export const MAX_PLUGIN_ANSWER_BYTES = 1024 * 1024;
/** The most findings one answer may carry. */
export const MAX_PLUGIN_FINDINGS = 10_000;

export interface PluginSegment {
  id: string;
  origin: SegmentOrigin;
  text: string;
}

/** The endpoint a model-backed plugin is told about (the cleared entry). */
export interface PluginEndpoint {
  name: string;
  url: string;
  wire: string;
  model?: string;
  /** The NAME of the environment variable holding the entry's token (the
   *  plugin's environment carries that one variable, §12). */
  tokenEnv?: string;
}

export interface PluginRequest {
  protocol: typeof PLUGIN_PROTOCOL;
  filter: string;
  segments: PluginSegment[];
  categories: string[];
  deadlineMs: number;
  endpoint?: PluginEndpoint;
}

export function buildPluginRequest(o: { filter: string; segments: readonly PluginSegment[]; categories: readonly PluginCategory[]; deadlineMs: number; endpoint?: PluginEndpoint }): PluginRequest {
  return {
    protocol: PLUGIN_PROTOCOL,
    filter: o.filter,
    segments: o.segments.map((s) => ({ id: s.id, origin: s.origin, text: s.text })),
    categories: o.categories.map((c) => c.category),
    deadlineMs: o.deadlineMs,
    ...(o.endpoint ? { endpoint: { name: o.endpoint.name, url: o.endpoint.url, wire: o.endpoint.wire, ...(o.endpoint.model ? { model: o.endpoint.model } : {}), ...(o.endpoint.tokenEnv ? { tokenEnv: o.endpoint.tokenEnv } : {}) } } : {}),
  };
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

const FINDING_KEYS = new Set(["segment", "start", "end", "category", "confidence"]);

/**
 * Check a plugin's stdout against the closed shape and turn it into findings
 * per segment id, each with the level the pack declares for its category.
 * `{ok: false, why}` refuses the whole answer. Pure.
 */
export function parsePluginAnswer(
  stdout: string,
  req: Pick<PluginRequest, "segments">,
  categories: readonly PluginCategory[],
): { ok: true; findings: Map<string, Finding[]> } | { ok: false; why: string } {
  if (stdout.length > MAX_PLUGIN_ANSWER_BYTES) return { ok: false, why: `its answer is larger than ${MAX_PLUGIN_ANSWER_BYTES} bytes` };
  let raw: unknown;
  try {
    raw = JSON.parse(stdout);
  } catch {
    return { ok: false, why: "its answer is not JSON" };
  }
  if (!isPlainObject(raw)) return { ok: false, why: "its answer is not a JSON object" };
  const extra = Object.keys(raw).filter((k) => k !== "findings");
  if (extra.length > 0) return { ok: false, why: `its answer has a key the protocol does not know (${extra[0]})` };
  if (!Array.isArray(raw.findings)) return { ok: false, why: "its answer has no findings list" };
  if (raw.findings.length > MAX_PLUGIN_FINDINGS) return { ok: false, why: `its answer has more than ${MAX_PLUGIN_FINDINGS} findings` };
  const texts = new Map(req.segments.map((s) => [s.id, s.text]));
  const levels = new Map<string, ConfidentialityLevel | undefined>(categories.map((c) => [c.category, c.level]));
  const out = new Map<string, Finding[]>(req.segments.map((s) => [s.id, []]));
  for (let i = 0; i < raw.findings.length; i++) {
    const f = raw.findings[i] as unknown;
    const at = `finding ${i}`;
    if (!isPlainObject(f)) return { ok: false, why: `${at} is not an object` };
    const bad = Object.keys(f).find((k) => !FINDING_KEYS.has(k));
    if (bad !== undefined) return { ok: false, why: `${at} has a key the protocol does not know (${bad})` };
    if (typeof f.segment !== "string" || !texts.has(f.segment)) return { ok: false, why: `${at} names no segment of the request` };
    const text = texts.get(f.segment)!;
    const { start, end } = f;
    if (!Number.isInteger(start) || !Number.isInteger(end)) return { ok: false, why: `${at} has an offset that is not a whole number` };
    if (!((start as number) >= 0 && (start as number) < (end as number) && (end as number) <= text.length)) {
      return { ok: false, why: `${at} has a span outside its segment` };
    }
    if (typeof f.category !== "string" || !levels.has(f.category)) return { ok: false, why: `${at} has a category the pack does not declare` };
    if (f.confidence !== undefined && !(typeof f.confidence === "number" && f.confidence >= 0 && f.confidence <= 1)) {
      return { ok: false, why: `${at} has a confidence outside 0..1` };
    }
    const level = levels.get(f.category);
    out.get(f.segment)!.push({
      start: start as number, end: end as number, category: f.category, rule: "plugin",
      ...(level ? { level } : {}),
    });
  }
  return { ok: true, findings: out };
}
