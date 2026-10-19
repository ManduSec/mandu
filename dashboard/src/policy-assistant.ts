/**
 * policy-assistant — "Describe what you want" (policy-surface.md §8.5.2).
 *
 * The person types a sentence on the product page's Rules page; this module
 * turns it into typed policy edits through a QUARANTINED model call and hands
 * the page rows it can show without trusting the model:
 *
 *   1. context: the arbiter's `policyExplain` (the assistant audience: bounded
 *      tokens only, no reasons, no event text, §4.4) and the edit JSON Schema
 *      from `policySchema`;
 *   2. one isolated, tool-less call on the U-LLM channel (inspect-mcp's
 *      `selectUllmConfig` + `buildUllmClient`: `api` or `cli`, and NEVER the
 *      anthropic-proxy, which is T-LLM's chokepoint: the selector refuses a
 *      loopback base URL). No channel ⇒ {@link AssistantUnconfiguredError}; the
 *      page says so and links to Settings. There is no heuristic fallback that
 *      guesses edits from the words;
 *   3. the model's answer is parsed strictly (one JSON object with `edits` and
 *      an optional `note`), then validated and classified by the arbiter's
 *      `policyPreview` (nothing written). Rows come from the page's own
 *      grammar (`editWords` / `relaxWords`: a file under the page's home
 *      reads `~/…`, dashboard.md §4.34), never from the model's prose; the
 *      `note` is shown last, as the assistant's words.
 *
 * Applying is a separate, human act over the admin channel (the routes
 * module), bound to the loosenings the preview showed (`expected`).
 *
 * Model endpoints (policy.yaml `models:`) are READ-ONLY here (decision
 * 2026-09-28, policy-surface.md §8.4.3a): the arbiter's schema omits the
 * add-model / update-model / remove-model / restore-model ops, the prompt
 * says models are changed in Settings › Models, and an answer or an Apply
 * carrying one is refused ({@link modelEditProblems}); the arbiter refuses it again.
 */
import { editWords, isOverBroad, relaxWords, type Part } from "./view-model/policy-proposals.js";

/** The narrow arbiter surface the assistant needs (reads, data socket). */
export interface AssistantArbiter {
  policyExplain(args: { audience?: "agent" | "assistant" }): Promise<unknown>;
  policySchema(): Promise<{ edits: unknown }>;
  policyPreview(edits: unknown): Promise<PreviewResult>;
}

export interface DeltaChangeRow {
  facet: string;
  direction: "relax" | "tighten";
  subject: string;
  detail: string;
}

export type PreviewResult =
  | { ok: true; relaxations: DeltaChangeRow[]; tightenings: DeltaChangeRow[]; perEdit: Array<{ loosens: boolean }> }
  | { ok: false; problems: string[] };

/** One isolated model call (inspect-mcp's UllmClient, structurally). */
export interface AssistantModel {
  complete(call: { system: string; user: string }): Promise<{ text: string; model: string }>;
}

/** No quarantined model channel is configured (fail closed, no fallback). */
export class AssistantUnconfiguredError extends Error {
  readonly unconfigured = true;
}

/** The model answered, but not with a valid rule change. */
export class AssistantAnswerError extends Error {
  constructor(message: string, readonly problems: string[]) {
    super(message);
  }
}

export const SENTENCE_MAX = 2000;
export const NOTE_MAX = 1000;

export interface Suggestion {
  model: string;
  note: string | null;
  /** `tryable`: the row names a website or a release, so "Try it" can probe it. */
  rows: Array<{ parts: Part[]; loosens: boolean; overBroad: boolean; tryable: boolean }>;
  loosens: Array<{ line: Part[] }>;
  edits: unknown[];
  /** The loosenings the person is shown, as `facet\0subject` keys: Apply is
   *  refused if the law has moved and applying would loosen anything else. */
  expected: string[];
}

/** The edit ops over policy.yaml `models:` (arbiter/policy/policy-edit.ts
 *  MODEL_EDIT_OPS): never suggested or applied from the Describe box. */
export const MODEL_EDIT_OPS: ReadonlySet<string> = new Set(["add-model", "update-model", "remove-model", "restore-model"]);
export const MODELS_ELSEWHERE = "Models are not changed here. Add, change or remove a model in Settings › Models.";

/** One problem per model-endpoint edit (index and op only, never a value). */
export function modelEditProblems(edits: readonly unknown[]): string[] {
  const out: string[] = [];
  edits.forEach((e, i) => {
    const op = e && typeof e === "object" && !Array.isArray(e) ? (e as Record<string, unknown>).op : undefined;
    if (typeof op === "string" && MODEL_EDIT_OPS.has(op)) out.push(`edits[${i}] (${op}): models are changed in Settings › Models, not from the Describe box`);
  });
  return out;
}

export function relaxKey(r: { facet: string; subject: string }): string {
  return `${r.facet}\u0000${r.subject}`;
}

export function assistantSystemPrompt(schema: unknown): string {
  return [
    "You translate a person's description of how Mandu should protect their work into Mandu policy edits.",
    "Mandu can: lock files (lock-path; no-model = no AI may read it; any-model = any AI may read it when it asks, and it is sent only to its bindings; local-model = only a model the person runs themselves may read it, never an outside model; public = not secret),",
    "trust or distrust where content comes from (trust-origin / distrust-origin; trusted content reaches the AI unmasked),",
    "allow or block sending data to a host (release; mode block to stop it, allow to let it through without asking),",
    "and let the agent's programs connect to a host (allow-connect).",
    "",
    "Answer with ONE JSON object and nothing else: {\"edits\": [...], \"note\": \"...\"}.",
    "`edits` must match this JSON Schema:",
    JSON.stringify(schema),
    "",
    "Rules:",
    "- Only what the person asked for. Never invent a host, site or path they did not mention.",
    "- Paths are absolute or start with ~/. A directory lock covers what is inside it.",
    "- lock-blob hides one old version of a file by its id (sha1:... or sha256:...). Use it only with an id the person gave; never invent one.",
    "- A trusted website is a hostname (pypi.org), *.suffix or hostname/path, never with https://.",
    "- A secret defaults to no-model unless the person says the AI may read it. Use local-model only when the person says their own (local) model may read it.",
    "- To stop data going to a site, use release with mode block and that site as the destination; one edit per site.",
    "- Do not repeat what the current rules already say.",
    "- The models in the current rules are shown for reference only; they cannot be changed here. If the person asks to add, change or remove a model, leave it out and say in `note` that models are changed in Settings › Models.",
    "- If something is unclear or cannot be expressed, leave it out and say so in `note` in one or two plain sentences. `note` may be empty.",
  ].join("\n");
}

export function assistantUserMessage(sentence: string, currentRules: unknown): string {
  return `Current rules (JSON):\n${JSON.stringify(currentRules)}\n\nThe person wrote:\n<<<\n${sentence}\n>>>`;
}

/** Strictly parse the model's answer: one JSON object (a ```json fence is
 *  tolerated) with an `edits` array and an optional string `note`. */
export function parseAssistantAnswer(text: string): { edits: unknown[]; note: string | null } {
  let body = text.trim();
  const fence = /^```(?:json)?\s*\n([\s\S]*?)\n```$/.exec(body);
  if (fence) body = fence[1]!.trim();
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    throw new AssistantAnswerError("the assistant did not answer with a rule change", ["its answer was not one JSON object"]);
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new AssistantAnswerError("the assistant did not answer with a rule change", ["its answer was not one JSON object"]);
  }
  const o = parsed as Record<string, unknown>;
  if (!Array.isArray(o.edits)) throw new AssistantAnswerError("the assistant did not answer with a rule change", ["its answer has no list of edits"]);
  const note = typeof o.note === "string" && o.note.trim() !== "" ? o.note.trim().slice(0, NOTE_MAX) : null;
  return { edits: o.edits, note };
}

/** `deps.home`: the page's home folder; the rows and lines name a file
 *  under it `~/…`. `edits` and `expected` stay as the arbiter has them:
 *  Apply is bound to those. */
export async function suggestRules(
  deps: { arbiter: AssistantArbiter; model: () => Promise<AssistantModel>; home?: string },
  sentence: string,
): Promise<Suggestion> {
  const s = sentence.trim();
  if (s === "" || s.length > SENTENCE_MAX) throw new AssistantAnswerError("describe what you want in 1 to 2000 characters", []);
  const model = await deps.model(); // throws AssistantUnconfiguredError first: nothing else is read without a channel
  const [rules, schema] = await Promise.all([deps.arbiter.policyExplain({ audience: "assistant" }), deps.arbiter.policySchema()]);
  const answer = await model.complete({ system: assistantSystemPrompt(schema.edits), user: assistantUserMessage(s, rules) });
  const { edits, note } = parseAssistantAnswer(answer.text);
  const modelEdits = modelEditProblems(edits);
  if (modelEdits.length > 0) throw new AssistantAnswerError(MODELS_ELSEWHERE, modelEdits);
  if (edits.length === 0) {
    return { model: answer.model, note: note ?? "Nothing to change.", rows: [], loosens: [], edits: [], expected: [] };
  }
  const preview = await deps.arbiter.policyPreview(edits);
  if (!preview.ok) throw new AssistantAnswerError("the assistant's suggestion is not a valid rule change", preview.problems);
  const home = deps.home ?? "";
  return {
    model: answer.model,
    note,
    rows: edits.map((e, i) => ({ parts: editWords(e, home), loosens: preview.perEdit[i]?.loosens ?? true, overBroad: isOverBroad([e]), tryable: tryProbe(e) !== null })),
    loosens: preview.relaxations.map((r) => ({ line: relaxWords(r, home) })),
    edits,
    expected: preview.relaxations.map(relaxKey),
  };
}

// ── "Try it" (§5.2): one probe per row, before and after ─────────────────────

/** The Test-a-flow input that exercises one edit, or null when the row is
 *  not about a website or a release (locks are judged by their level). */
export function tryProbe(edit: unknown): { source: { tool: string; origin: string }; destination?: string; boundary?: "network" } | null {
  const e = (edit && typeof edit === "object" ? edit : {}) as Record<string, unknown>;
  const asUrl = (hostish: string): string => {
    const bare = hostish.trim().replace(/^[a-z][a-z0-9+.-]*:\/\//i, "").replace(/^\*\./, "www.");
    return `https://${bare}${bare.includes("/") ? "" : "/"}`;
  };
  const host = (side: unknown): string | null => {
    const h = side && typeof side === "object" ? (side as Record<string, unknown>).host : undefined;
    return typeof h === "string" && h.trim() !== "" && h !== "*" && !h.startsWith("@") ? h : null;
  };
  if ((e.op === "trust-origin" || e.op === "distrust-origin") && e.kind === "url" && typeof e.pattern === "string" && e.pattern.trim() !== "") {
    return { source: { tool: "WebFetch", origin: asUrl(e.pattern) } };
  }
  if (e.op === "release" && (e.mode === "allow" || e.mode === "block")) {
    const to = host(e.to);
    if (!to) return null;
    const from = host(e.from);
    return { source: { tool: "WebFetch", origin: from ? asUrl(from) : "https://a-page-you-visit.example/" }, destination: asUrl(to), boundary: "network" };
  }
  return null;
}

type FlowAnswer = { inbound?: { trust?: string }; egress?: { decision?: { allow?: boolean; requiresApproval?: boolean } } | null };

/** One probe's answer in the page's words. */
export function tryLine(edit: unknown, answer: unknown): Part[] {
  const e = (edit && typeof edit === "object" ? edit : {}) as Record<string, unknown>;
  const a = (answer && typeof answer === "object" ? answer : {}) as FlowAnswer;
  const code = (text: string): Part => ({ kind: "code", text });
  const text = (t: string): Part => ({ kind: "text", text: t });
  const probe = tryProbe(edit);
  if (!probe) return [text("Nothing to try for this row")];
  const site = probe.source.origin.replace(/^https:\/\//, "").replace(/\/$/, "");
  if (e.op === "release") {
    const d = a.egress?.decision;
    const to = probe.destination!.replace(/^https:\/\//, "").replace(/\/$/, "");
    const verdict = d?.allow ? " is sent without asking" : d?.requiresApproval ? " waits for you to allow it" : " is blocked";
    return [text("Data from "), code(site), text(" to "), code(to), text(verdict)];
  }
  return a.inbound?.trust === "TRUSTED"
    ? [text("Content from "), code(site), text(" reaches the AI unmasked")]
    : [text("Content from "), code(site), text(" is masked for the AI")];
}

/**
 * The production model factory: inspect-mcp's selector + client, imported at
 * runtime by a specifier built from parts (the arbiter-adapter pattern) so the
 * sibling package stays out of this package's tsc program. A bundled build
 * sets MANDU_ULLM_MODULE to the co-located dist/ullm-client.mjs.
 */
export function productionAssistantModel(env: NodeJS.ProcessEnv = process.env): () => Promise<AssistantModel> {
  return async () => {
    const specifier = env["MANDU_ULLM_MODULE"] ?? ["..", "..", "interceptors", "inspect-mcp", "src", "ullm-config.js"].join("/");
    let mod: {
      selectUllmConfig(env: Record<string, string | undefined>, cliAvailable: (b: "claude" | "codex") => boolean): unknown;
      buildUllmClient(config: unknown): AssistantModel;
      isOnPath(b: "claude" | "codex"): boolean;
    };
    try {
      mod = await import(specifier);
    } catch (err) {
      throw new AssistantUnconfiguredError(`the quarantined model channel is not installed (${(err as Error).message})`);
    }
    let config: unknown;
    try {
      config = mod.selectUllmConfig(env, mod.isOnPath);
    } catch (err) {
      throw new AssistantUnconfiguredError((err as Error).message);
    }
    return mod.buildUllmClient(config);
  };
}
