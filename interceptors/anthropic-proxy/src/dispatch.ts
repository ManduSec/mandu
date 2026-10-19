/**
 * dispatch — see through a tool that RUNS ANOTHER TOOL (supported-agents.md
 * §2.1; the table is GateSurface.dispatch, owned by the arbiter's
 * tool-gate-surface.ts).
 *
 * OpenClaw's Tool Search dispatcher (on by default from 2026.9.x, opt-in on
 * 2026.6.35 and 2026.7.1) advertises `tool_call{id, args}` in place of most
 * tools: `exec`, `web_fetch`, `memory_search`, `cron` and the rest are reached
 * as `tool_call{id: "exec", args: {command: …}}`. Every model-context gate
 * keys on the tool name (exec, net, sensitive path, derived label, and the
 * exec-output legs on the result), so before this module a call through the
 * dispatcher passed all of them unseen.
 *
 * `unwrapDispatch` turns a dispatcher call into the INNER tool's name and
 * input, which the gates then read exactly as if the model had called the
 * inner tool directly, plus a `rewrap` that puts a gated inner input back
 * into the dispatcher's envelope. It accepts only the shapes whose meaning is
 * the same in every OpenClaw version that has the dispatcher, read from the
 * published source (2026.7.1 `readCallArgs`: `input = args ?? input ?? {}`;
 * 2026.9.6 `readToolSearchCallArgs`: the same, plus flattened target keys,
 * `args.<key>` dotted keys and a catalog-dependent choice among several
 * selector keys). Anything else is REFUSED, never guessed:
 *
 *   - exactly one selector key (`id`, `toolId` or `name`), a non-empty string;
 *   - at most one of `args` / `input`;
 *   - no `args.<key>` dotted keys;
 *   - a nested input that is a non-empty object takes no other keys beside
 *     it (both versions ignore them; refusing keeps one reading);
 *   - a nested input that is not an object (a string, an array) is refused.
 *
 * Flattened keys (`tool_call{id: "exec", command: "ls"}`) are the inner input.
 * 2026.7.1 ignores them (it runs the tool with `{}`), so gating them there is
 * over-gating, never under-gating.
 *
 * The inner tool's NAME is the selector's last `:` segment: a catalog id is
 * `<source>:<plugin>:<name>` (`openclaw:core:exec`), a bare name is itself.
 * An MCP tool that shares a core tool's name is then gated as that tool:
 * over-gating again. A dispatcher named inside a dispatcher is refused.
 *
 * A tool the surface REFUSES outright (GateSurface.refuse: `terminal`,
 * `automations`, `plugins`, …) is refused through the dispatcher too, the
 * same `{id: "mandu-refused: <why>"}` way; a direct call gets
 * `refusedToolInput`.
 *
 * A tool refused in one FORM (GateSurface.refuseArgs: `exec{host: "node"}`,
 * `browser{target: "node"}`) is judged by `refusedArg` on the inner input,
 * and through the dispatcher is refused the dispatcher's way too
 * (`dispatcherRefusalInput`); a direct call gets `refusedArgInput`.
 *
 * A `refuse` dispatcher (`tool_search_code`, JavaScript that calls tools) is
 * refused on every call: no gate can read which tool the code runs with which
 * input, the case the openai-proxy handles by refusing an unparseable Codex
 * JS cell.
 *
 * REFUSAL ON THE WIRE (the exec gate's pattern: the agent runs a harmless
 * replacement and the session continues):
 *   - `tool_call` → `{id: "mandu-refused: <why>"}`. OpenClaw resolves no such
 *     tool and answers "Unknown tool id: mandu-refused: <why>", so nothing
 *     runs and the model reads why.
 *   - a `refuse` dispatcher → `{code: "throw new Error(\"mandu: <why>\")"}`.
 *     The code runs in OpenClaw's isolated Node child and throws at once.
 *
 * Pure and total: never throws.
 */

import type { GateSurface } from "./gate-surface.js";

export type Dispatched =
  /** Not a dispatcher on this surface: gate `name` / `input` as they are. */
  | { kind: "none" }
  /** A dispatcher call parsed to exactly one inner tool. */
  | {
      kind: "call";
      dispatcher: string;
      name: string;
      input: Record<string, unknown>;
      /** The dispatcher input with the inner input replaced (after a gate
       *  rewrote a field of it). */
      rewrap: (inner: Record<string, unknown>) => Record<string, unknown>;
    }
  /** Refused: send `input` in place of the model's call. */
  | { kind: "refuse"; dispatcher: string; reason: string; input: Record<string, unknown> };

const SELECTOR_KEYS = ["id", "toolId", "name"] as const;
const NEST_KEYS = ["args", "input"] as const;

/** The prefix of a refused `tool_call` id (the model reads it back). */
export const REFUSED_ID_PREFIX = "mandu-refused: ";

const HOW = 'call it as tool_call{"id": "<tool name>", "args": {<its input>}}';

const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  v !== null && typeof v === "object" && !Array.isArray(v);

function refusal(dispatcher: string, kind: "openclaw-tool-call" | "refuse", reason: string): Dispatched {
  const input = kind === "openclaw-tool-call"
    ? { id: `${REFUSED_ID_PREFIX}${reason}` }
    : { code: `throw new Error(${JSON.stringify(`mandu: ${reason}`)});` };
  return { kind: "refuse", dispatcher, reason, input };
}

/** The input a REFUSED tool (GateSurface.refuse) receives in place of the
 *  model's: an `action` no refused tool's schema accepts. OpenClaw validates
 *  every call against the tool's schema before it runs
 *  (`validateToolArguments`, 2026.7.1 and 2026.9.6), and every refused tool
 *  takes a required `action` enum, so the call fails with the reason in the
 *  error and nothing runs. */
export function refusedToolInput(reason: string): Record<string, unknown> {
  return { action: `${REFUSED_ID_PREFIX}${reason}` };
}

/** A direct call to a refused tool: its reason, else null. Pure. */
export function refusedTool(name: string, surface: Partial<Pick<GateSurface, "refuse">>): string | null {
  const refuse = surface.refuse ?? {};
  return Object.prototype.hasOwnProperty.call(refuse, name) ? refuse[name]! : null;
}

/** The input a dispatcher call is refused with (`tool_call` resolves no tool
 *  named "mandu-refused: <why>", so nothing runs). For a gate that refuses
 *  the INNER tool after unwrapDispatch parsed it (a refused form, a blocked
 *  stdin write). */
export function dispatcherRefusalInput(reason: string): Record<string, unknown> {
  return { id: `${REFUSED_ID_PREFIX}${reason}` };
}

/** A call in a refused FORM (GateSurface.refuseArgs): the first rule whose
 *  field is present with a value outside its `allow` list (a string compared
 *  trimmed and lowercased, OpenClaw's own normalization of an exec host; a
 *  boolean compared as "true" / "false", so OpenCode 2's `background: false`
 *  passes a rule that allows "false"; any other type is outside every list),
 *  else null. `undefined` and `null` are absent (OpenClaw reads both as "not
 *  given"). Pure. */
export function refusedArg(
  name: string,
  input: unknown,
  surface: Partial<Pick<GateSurface, "refuseArgs">>,
): { field: string; reason: string } | null {
  const rules = surface.refuseArgs && Object.prototype.hasOwnProperty.call(surface.refuseArgs, name) ? surface.refuseArgs[name]! : [];
  if (rules.length === 0 || !isPlainObject(input)) return null;
  for (const r of rules) {
    if (!Object.prototype.hasOwnProperty.call(input, r.field)) continue;
    const v = input[r.field];
    if (v === undefined || v === null) continue;
    const text = typeof v === "string" ? v : typeof v === "boolean" ? String(v) : null;
    if (text !== null && r.allow.includes(text.trim().toLowerCase())) continue;
    return { field: r.field, reason: r.reason };
  }
  return null;
}

/** A direct call in a refused form: the field becomes "mandu-refused:
 *  <why>", a value outside the tool's enum (the call fails validation, and
 *  OpenClaw's own check of an exec host throws on it too), and a shell tool's
 *  command becomes `commandSentinel` so nothing could run even past both. */
export function refusedArgInput(
  input: Record<string, unknown>,
  field: string,
  reason: string,
  command?: { field: string; sentinel: string },
): Record<string, unknown> {
  const out: Record<string, unknown> = { ...input, [field]: `${REFUSED_ID_PREFIX}${reason}` };
  if (command && typeof input[command.field] === "string") out[command.field] = command.sentinel;
  return out;
}

export function unwrapDispatch(name: string, input: unknown, surface: Pick<GateSurface, "dispatch"> & Partial<Pick<GateSurface, "refuse">>): Dispatched {
  const dispatch = surface.dispatch ?? {};
  if (!Object.prototype.hasOwnProperty.call(dispatch, name)) return { kind: "none" };
  const kind = dispatch[name]!;
  if (kind === "refuse") {
    return refusal(name, kind, `${name} runs code that calls tools, which Mandu cannot check; call each tool directly instead`);
  }
  if (!isPlainObject(input)) return refusal(name, kind, `the call's input is not an object; ${HOW}`);
  const keys = Object.keys(input);
  const selectors = keys.filter((k) => (SELECTOR_KEYS as readonly string[]).includes(k));
  if (selectors.length !== 1) {
    return refusal(name, kind, `name the tool with exactly one of id, toolId or name; ${HOW}`);
  }
  const selKey = selectors[0]!;
  const raw = input[selKey];
  if (typeof raw !== "string" || raw.trim() === "") return refusal(name, kind, `the tool id is not a non-empty string; ${HOW}`);
  if (keys.some((k) => k.startsWith("args."))) return refusal(name, kind, `dotted args.<key> input keys are not accepted; ${HOW}`);
  const nests = keys.filter((k) => (NEST_KEYS as readonly string[]).includes(k));
  if (nests.length > 1) return refusal(name, kind, `pass the input under args only; ${HOW}`);
  const others = keys.filter((k) => k !== selKey && !(NEST_KEYS as readonly string[]).includes(k));

  const id = raw.trim();
  const innerName = id.includes(":") ? id.slice(id.lastIndexOf(":") + 1) : id;
  if (innerName === "") return refusal(name, kind, `the tool id names no tool; ${HOW}`);
  if (Object.prototype.hasOwnProperty.call(dispatch, innerName)) {
    return refusal(name, kind, `${innerName} cannot be called through ${name}; call the tool directly`);
  }
  const refused = refusedTool(innerName, surface);
  if (refused !== null) return refusal(name, kind, refused);

  const nestKey = nests[0];
  const nested = nestKey !== undefined ? input[nestKey] : undefined;
  if (nestKey !== undefined && isPlainObject(nested) && Object.keys(nested).length > 0) {
    if (others.length > 0) return refusal(name, kind, `put every input key under args; ${HOW}`);
    return {
      kind: "call",
      dispatcher: name,
      name: innerName,
      input: nested,
      rewrap: (inner) => ({ ...input, [nestKey]: inner }),
    };
  }
  if (nested !== undefined && nested !== null && !isPlainObject(nested)) {
    return refusal(name, kind, `args must be an object; ${HOW}`);
  }
  // Flattened (or no) input: the keys beside the selector (and beside an
  // empty / null args) are the inner tool's input.
  const flat: Record<string, unknown> = {};
  for (const k of others) flat[k] = input[k];
  return {
    kind: "call",
    dispatcher: name,
    name: innerName,
    input: flat,
    rewrap: (inner) => {
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(input)) if (!others.includes(k)) out[k] = v;
      return { ...out, ...inner };
    },
  };
}
