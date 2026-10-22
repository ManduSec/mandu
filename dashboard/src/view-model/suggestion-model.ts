/**
 * suggestion-model — the Suggested view's model picker, its preview and a
 * model run's outcome (confidentiality-plan-14-policy-suggestions.md §14.5,
 * §14.11; dashboard.md §4.25t). Pure; the routes (server/suggestion-routes.ts)
 * ask the arbiter. Mandu-new (no reference origin).
 *
 * The picker: Off (the default), Names only (any model you chose, with the
 * list of names first), Contents (only your own model, declared local: true;
 * disabled with the reason when none is). Both are "not offered yet" unless
 * the dashboard server runs with MANDU_EXPERIMENTAL_POLICY_MODEL=1 (§14.6).
 *
 * The preview is what the protection service built and KEEPS under a digest:
 * for Names only, every line exactly as it would be sent; for Contents, the
 * files and the bytes of each, never a byte of their text. Send sends
 * exactly that (the digest), once. Everything here is the service's own
 * words or counts; nothing a model wrote reaches this page (the service keeps
 * only two enums and an id per answer).
 */
import { tildePath } from "./file-browser.js";
import { MODELS_LINK, type ModelsPlacePart } from "./model-endpoints.js";

// ── the wire (arbiter/ipc/protocol.ts), declared here so the dashboard
//    typechecks standalone ──────────────────────────────────────────────────

export interface ModelDestinationWire {
  kind: "declared" | "default";
  name: string;
  location: "local" | "external";
  placement: "host" | "network";
  vendor: string;
}

export interface ModelPreviewWire {
  axis: boolean;
  tier: "names" | "contents";
  digest: string;
  destination: ModelDestinationWire;
  roots: Array<{ index: number; root: string; files: number }>;
  items: number;
  bytes: number;
  requests: number;
  names: string[];
  files?: Array<{ root: number; name: string; bytes: number; truncated: boolean }>;
  left: {
    covered: number; labelled: number; tooLong: number; personal: number; overCap: number; detector: number; registered: number;
    flagged?: number; unread?: number;
  };
  promptVersion: string;
  confine: { live: boolean; note?: string };
  expiresAt: number;
  walk: { examined: number; covered: number; capped: string[] };
}

export interface ModelRunWire {
  axis: boolean;
  running: boolean;
  digest: string;
  destination: ModelDestinationWire | null;
  sent: { requests: number; items: number; bytes: number };
  counts: {
    rules: number; kept: number; dropped: number; merged: number; tooBroad: number; covered: number;
    filed: number; alreadyPending: number; dismissed: number; overCap: number; failedRequests: number;
    public?: number;
  };
  filed: string[];
  error: string | null;
  ms: number;
}

/** A declared model as `modelEndpoints` answers it (the fields read here). */
export interface ModelEndpointFact {
  name: string;
  local: boolean;
  model?: string;
}

// ── the picker ───────────────────────────────────────────────────────────────

export type ModelTier = "off" | "names" | "contents";

export interface ModelOptionVM {
  value: ModelTier;
  label: string;
  enabled: boolean;
  /** Why it cannot be picked, or null. */
  why: string | null;
  /** `why` as parts where it names a place the page links (Settings ›
   *  Models); absent otherwise. */
  whyParts?: ModelsPlacePart[];
}

export interface ModelPickerVM {
  /** MANDU_EXPERIMENTAL_POLICY_MODEL=1 on the dashboard server. */
  offered: boolean;
  options: ModelOptionVM[];
  /** The models of your own that Contents may use (their names). */
  ownModels: string[];
  /** One line under the picker. */
  hint: string;
}

export const NOT_OFFERED = "Not offered yet: asking a model is still being tested.";
/** The line under the picker when it is not offered: one sentence (until
 *  2026-10-16 it was "Asking a model to suggest rules: not offered yet:
 *  asking a model is still being tested."). */
export const NOT_OFFERED_LINE = "Asking a model to suggest rules is not offered yet: it is still being tested.";
export const NO_OWN_MODEL = "No model of your own is set up. Add one in Settings › Models, and mark it as your own.";
/** `NO_OWN_MODEL` as parts, "Settings › Models" the link: joined, the same
 *  words (dashboard.md §4.25t). */
export const NO_OWN_MODEL_PARTS: readonly ModelsPlacePart[] = [
  { kind: "text", text: "No model of your own is set up. Add one in " },
  MODELS_LINK,
  { kind: "text", text: ", and mark it as your own." },
];
export const MODELS_UNKNOWN = "Your models could not be read from the protection service.";

/** The picker (§14.5). Pure. `endpoints` null: the list could not be read. */
export function modelPickerVM(offered: boolean, endpoints: readonly ModelEndpointFact[] | null): ModelPickerVM {
  const own = (endpoints ?? []).filter((e) => e.local).map((e) => e.name);
  const contentsWhy = !offered ? NOT_OFFERED : endpoints === null ? MODELS_UNKNOWN : own.length === 0 ? NO_OWN_MODEL : null;
  return {
    offered,
    options: [
      { value: "off", label: "Off", enabled: true, why: null },
      { value: "names", label: "Names only", enabled: offered, why: offered ? null : NOT_OFFERED },
      { value: "contents", label: "Contents (your own model)", enabled: contentsWhy === null, why: contentsWhy, ...(contentsWhy === NO_OWN_MODEL ? { whyParts: [...NO_OWN_MODEL_PARTS] } : {}) },
    ],
    ownModels: own,
    hint: offered
      ? "Off: only Mandu's own scan. Names only: a model reads the names of your files, never what is in them. Contents: your own model reads the start of your documents, on your side. You see everything first."
      : NOT_OFFERED_LINE,
  };
}

// ── the preview ──────────────────────────────────────────────────────────────

export interface ModelPreviewVM {
  tier: "names" | "contents";
  /** Empty: nothing to send (then `empty` says why). */
  digest: string;
  /** "This sends …" in one sentence. */
  headline: string;
  /** Where it goes, in words. */
  where: string;
  /** The names (as sent) or the files (with their size). */
  caption: string;
  list: Array<{ text: string; size: string | null }>;
  /** Which folder each "root N" is (shown here, never sent). */
  roots: string[];
  notes: string[];
  empty: string | null;
  expiresAt: number;
}

const num = (n: number): string => n.toLocaleString("en-US");
const plural = (k: number, one: string, many: string): string => `${num(k)} ${k === 1 ? one : many}`;
const clean = (s: string): string => s.replace(/[\u0000-\u001f\u007f-\u009f]/g, " ");

/** A byte count in the page's words ("380 KB", "900 bytes"). Pure. */
export function kbWords(bytes: number): string {
  return bytes < 1024 ? `${num(bytes)} bytes` : `${num(Math.round(bytes / 1024))} KB`;
}

/** Where a model runs, in words. Pure. */
export function destinationWhere(d: ModelDestinationWire): string {
  if (d.location === "local") return d.placement === "host" ? "your own model, on this computer" : "your own model, on your organization's network";
  return d.placement === "host" ? "an outside model, reached through this computer" : "an outside model, outside this computer";
}

/** The preview as the dialog shows it (§14.5). Pure. */
export function modelPreviewVM(p: ModelPreviewWire, home: string): ModelPreviewVM {
  const name = clean(p.destination.name);
  const where = destinationWhere(p.destination);
  const roots = p.roots.map((r) => `root ${r.index} is ${tildePath(r.root, home)} (the folder's name is not sent)`);
  const l = p.left;
  const notes: string[] = [];
  const confine = p.confine.live
    ? "Mandu lets the request reach only that model's address."
    : "This computer cannot limit the request to that model's address, so it relies on the address you set.";
  if (p.tier === "contents") {
    const out = [
      l.covered + l.labelled > 0 ? plural(l.covered + l.labelled, "document your rules or a sensitivity label protects", "documents your rules or a sensitivity label protects") : "",
      (l.flagged ?? 0) + l.detector + l.registered > 0 ? plural((l.flagged ?? 0) + l.detector + l.registered, "document that holds something like a key", "documents that hold something like a key") : "",
      (l.unread ?? 0) > 0 ? plural(l.unread ?? 0, "document too large or not text", "documents too large or not text") : "",
      l.overCap > 0 ? plural(l.overCap, "document past the first 200", "documents past the first 200") : "",
    ].filter(Boolean);
    notes.push("Only documents (.md, .txt, .rst, .org, .tex, .csv, .tsv, .rtf, .html, and the text of Word, Excel and PowerPoint files) your rules leave unprotected are read, at most the first 16 KB of each.");
    if (out.length) notes.push(`Not sent: ${out.join(", ")}.`);
    notes.push(confine);
    const files = p.files ?? [];
    return {
      tier: "contents",
      digest: p.digest,
      headline: `This sends the text of ${plural(p.items, "file", "files")} (${kbWords(p.bytes)}) to your own model ${name} (${p.destination.placement === "host" ? "this computer" : "your organization's network"}).`,
      where: `${name}: ${where}`,
      caption: "The files it reads (their text is not shown here)",
      list: files.map((f) => ({ text: `root ${f.root}/${clean(f.name)}`, size: kbWords(f.bytes) + (f.truncated ? " (the first 16 KB)" : "") })),
      roots,
      notes,
      empty: p.digest === "" ? "No document to send: every document the scan found is protected, holds something like a key, or was left out." : null,
      expiresAt: p.expiresAt,
    };
  }
  const out = [
    l.covered + l.labelled > 0 ? plural(l.covered + l.labelled, "name your rules protect", "names your rules protect") : "",
    l.detector + l.registered > 0 ? plural(l.detector + l.registered, "name that looks like a key", "names that look like a key") : "",
    l.personal > 0 ? plural(l.personal, "name holding your home folder or user name", "names holding your home folder or user name") : "",
    l.tooLong > 0 ? plural(l.tooLong, "name over 300 characters", "names over 300 characters") : "",
    l.overCap > 0 ? plural(l.overCap, "name past the first 5,000", "names past the first 5,000") : "",
  ].filter(Boolean);
  if (out.length) notes.push(`Not sent: ${out.join(", ")}.`);
  notes.push(confine);
  return {
    tier: "names",
    digest: p.digest,
    headline: `This sends ${plural(p.items, "file or folder name", "file and folder names")} from ${plural(p.roots.length, "folder", "folders")} to ${name} (${clean(p.destination.vendor)}, ${where}). No file's content is sent.`,
    where: `${name}: ${where}`,
    caption: "The names it sends, exactly as sent",
    list: p.names.map((n) => ({ text: clean(n), size: null })),
    roots,
    notes,
    empty: p.digest === "" ? "No file or folder name to send: everything the scan listed is protected or was left out." : null,
    expiresAt: p.expiresAt,
  };
}

// ── a run ────────────────────────────────────────────────────────────────────

export interface ModelRunVM {
  running: boolean;
  line: string;
  error: string | null;
  filed: number;
}

/** A run's outcome in one line (§14.5). Pure. */
export function modelRunVM(r: ModelRunWire, tier: "names" | "contents"): ModelRunVM {
  const name = r.destination ? clean(r.destination.name) : "your model";
  if (r.running) return { running: true, line: `${name} is reading… This can take a few minutes.`, error: null, filed: 0 };
  const k = r.counts;
  const error = r.error === null ? null : modelErrorWords(r.error);
  if (r.error !== null && k.rules === 0) return { running: false, line: `The model did not finish: ${error}. Nothing was added.`, error, filed: 0 };
  const extra = [
    k.alreadyPending > 0 ? `${num(k.alreadyPending)} already waiting here` : "",
    k.covered > 0 ? `${num(k.covered)} your rules already cover` : "",
    k.dismissed > 0 ? `${num(k.dismissed)} you marked as not a secret before` : "",
    k.overCap > 0 ? `${num(k.overCap)} wait until you review these` : "",
    k.failedRequests > 0 ? `${plural(k.failedRequests, "request", "requests")} failed` : "",
  ].filter(Boolean);
  const tail = extra.length ? ` (${extra.join(", ")})` : "";
  const line = tier === "contents"
    ? `${name} read ${plural(r.sent.items, "file", "files")}: ${plural(k.filed, "looks sensitive and waits", "look sensitive and wait")} here for you, ${num(k.public ?? 0)} ${(k.public ?? 0) === 1 ? "does" : "do"} not${tail}.`
    : `${name} suggested ${plural(k.rules, "rule", "rules")}: ${plural(k.filed, "waits", "wait")} here for you${k.tooBroad > 0 ? `, ${num(k.tooBroad)} too broad to suggest` : ""}${tail}.`;
  return { running: false, line, error, filed: k.filed };
}

/** The service's refusal in the page's words: without the op's name, and
 *  without the service's internal names. Pure. */
export function modelErrorWords(msg: string): string {
  let m = clean(msg).replace(/^(modelSuggestPreview|modelSuggest): /, "").trim();
  if (/not available in this install/.test(m)) return "Asking a model is not available in this install of Mandu";
  if (/no longer held|look again/.test(m)) return "This preview has expired. Look again before you send";
  m = m.replace(/\barbiter\b/gi, "protection service").replace(/\bclassifier\b/gi, "model helper");
  return m.length > 300 ? `${m.slice(0, 297)}…` : m;
}
