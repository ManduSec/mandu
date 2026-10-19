/**
 * goose-acp-relay — `mandu goose acp`: Goose as an ACP agent server on stdio,
 * with the launcher between the editor and Goose (supported-agents.md §5.6
 * "ACP").
 *
 * WHY A RELAY (goose 1.53.0 crates/goose/src/acp, probed 2026-10-06): the
 * editor speaking ACP is the human's side, and the protocol hands it powers
 * the env routing does not cover.
 *   - TOOLS OUTSIDE THE WRAP. When the editor's `initialize` offers
 *     `clientCapabilities.fs` / `terminal`, Goose runs `shell` through the
 *     editor's `terminal/create` and its file tools through `fs/*` (acp/fs.rs;
 *     captured: `shell · cat notes.txt` became a `terminal/create` request),
 *     i.e. in the editor's process, outside the wrap and the twins, and it
 *     adds a `read` tool the gate surface does not know. The relay offers
 *     Goose NEITHER capability, so every tool runs in Goose, inside the wrap,
 *     on the 17-tool surface `GOOSE_GATE_SURFACE` was captured from; a
 *     `fs/*` or `terminal/*` request from Goose anyway is answered with an
 *     error here and never reaches the editor.
 *   - THE PROVIDER. `session/set_config_option {configId: "provider"}`
 *     rebuilds the session's provider (the editor shows it as a picker);
 *     `session/new`'s `_meta.provider` picks one, and a recipe named in its
 *     `_meta` outranks that; `session/load` / `session/fork` restore the
 *     saved session's provider. The relay refuses a provider other than the
 *     ones this launch routes through the proxy (goose-route.ts: the
 *     session's and the subagents'; or `goose`, the default, which is the
 *     env-pinned session provider), refuses recipes and `enabledExtensions`
 *     in `_meta`, tracks each session's provider from Goose's own answers
 *     (`configOptions`, the `config_option_update` notifications) and
 *     refuses `session/prompt` on a session whose provider it has not seen
 *     to be a routed one.
 *   - THE REST OF THE SURFACE. Goose answers the desktop's `_goose/*`
 *     methods over the same stream (provider and custom-provider setup with
 *     their own endpoints, config writes, extensions, schedules, dictation,
 *     local models, recipes). Only the standard ACP methods an editor needs
 *     pass (ALLOWED_METHODS); everything else is answered with an error.
 * THE STREAM. The editor's view (the human view here) is Goose's stdout:
 * the relay reads it (to track providers and catch `fs/*` / `terminal/*`)
 * and forwards each line in order through the editor-bound writer
 * (goose-acp-display.ts), which desymbolizes the human-display strings of a
 * known shape (the reply text, tool calls, plan entries, titles) over the
 * arbiter's human plane and leaves every other byte as Goose wrote it. The
 * byte-stream reply filter is off for this shape (its line rewriting would
 * break the JSON-RPC framing; parse.ts); `--no-reply-filter` /
 * `MANDU_REPLY_FILTER=0` turn this pass off too. Nothing the relay sends
 * toward Goose is desymbolized. The launcher's own notices go to stderr.
 *
 * The U-LLM: Mandu's MCP servers (inspect, policy) are added to every
 * `session/new` / `load` / `fork`'s `mcpServers`, Goose's ACP spelling of
 * `--with-extension`, so the tools appear as `mandu-inspect__inspect_symbol`.
 *
 * Decisions are pure (acpFromEditor / acpFromGoose); startAcpRelay wires
 * them to the streams. Unit-tested in test/unit/goose-acp-relay.test.ts.
 */
import type { Readable, Writable } from "node:stream";
import { AcpEditorWriter, type Desymbolize } from "./goose-acp-display.js";
import { GOOSE_ROUTED_PROVIDER } from "./goose-route.js";

/** Goose's id for "the default provider", resolved from GOOSE_PROVIDER
 *  (acp/server.rs DEFAULT_PROVIDER_ID), which the launch pins. */
export const GOOSE_DEFAULT_PROVIDER_ID = "goose";

/** Editor → Goose requests that pass (ACP v1 as Goose 1.53.0 dispatches it,
 *  acp/server/dispatch.rs). */
export const ALLOWED_METHODS: ReadonlySet<string> = new Set([
  "initialize", "authenticate",
  "session/new", "session/load", "session/fork", "session/list", "session/close", "session/delete",
  "session/prompt", "session/set_mode", "session/set_config_option",
]);

/** Editor → Goose notifications that pass. */
export const ALLOWED_NOTIFICATIONS: ReadonlySet<string> = new Set(["session/cancel", "$/cancel_request"]);

/** JSON-RPC's "method not found", and the code Mandu answers a refusal with. */
export const METHOD_NOT_FOUND = -32601;
export const REFUSED_CODE = -32001;

type Json = Record<string, unknown>;

/** One stdio MCP server to mount (plan.mcpServers' shape). */
export interface AcpMcpServer { command: string; args: readonly string[]; env: Readonly<Record<string, string>> }

export interface AcpRelayState {
  /** Session id → its provider as Goose last reported it (null: unknown). */
  sessions: Map<string, string | null>;
  /** Editor request id (JSON) → what it asked, for reading Goose's answer. */
  pending: Map<string, { method: string; sessionId?: string }>;
}

export function newAcpRelayState(): AcpRelayState {
  return { sessions: new Map(), pending: new Map() };
}

export interface AcpRelayOpts {
  /** The providers this launch routes through the proxy (goose-route.ts
   *  GooseRouting: the session's and the subagents'); `anthropic` when
   *  absent. */
  routed?: readonly string[];
  /** Mandu's MCP servers by name (plan.mcpServers). */
  mcpServers?: Readonly<Record<string, AcpMcpServer>>;
}

/** What to do with one message. `toGoose` / `toEditor` are lines to write
 *  (without the newline); `note` goes to the launcher's stderr. */
export interface AcpStep {
  toGoose?: string;
  toEditor?: string;
  note?: string;
  /** For a Goose response to an editor request the relay tracks: that
   *  request's method (the display pass reads session/list's titles). */
  answers?: string;
}

const isObj = (v: unknown): v is Json => typeof v === "object" && v !== null && !Array.isArray(v);
const idKey = (id: unknown): string => JSON.stringify(id);
const isAllowedProvider = (p: string, routed: readonly string[]): boolean => {
  const v = p.trim().toLowerCase();
  return routed.includes(v) || v === GOOSE_DEFAULT_PROVIDER_ID;
};
const spell = (routed: readonly string[]): string =>
  `Goose's ${routed.join(" and ")} provider${routed.length > 1 ? "s" : ""}`;

function errorReply(id: unknown, code: number, message: string): string {
  return JSON.stringify({ jsonrpc: "2.0", id, error: { code, message } });
}

/** The provider Goose reports in a `configOptions` list, or undefined when
 *  the list has no provider entry (null: the list is absent). */
export function providerOf(configOptions: unknown): string | null {
  if (!Array.isArray(configOptions)) return null;
  for (const o of configOptions) {
    if (isObj(o) && o["id"] === "provider" && typeof o["currentValue"] === "string") return o["currentValue"];
  }
  return null;
}

/** A config option's value as Goose reads it (`as_value_id`): a string, or
 *  an object carrying one. */
function valueId(v: unknown): string | null {
  if (typeof v === "string") return v;
  if (isObj(v)) for (const k of ["value", "valueId", "id"]) if (typeof v[k] === "string") return v[k] as string;
  return null;
}

/** ACP's stdio McpServer form of Mandu's servers. */
export function acpMcpServers(servers: Readonly<Record<string, AcpMcpServer>> | undefined): Json[] {
  if (!servers) return [];
  return Object.entries(servers).map(([name, s]) => ({
    name, command: s.command, args: [...s.args], env: Object.entries(s.env).map(([n, value]) => ({ name: n, value })),
  }));
}

/** Decide one editor → Goose line. Pure except that it updates `state`. */
export function acpFromEditor(line: string, state: AcpRelayState, opts: AcpRelayOpts = {}): AcpStep {
  const routed = [...new Set(opts.routed ?? [GOOSE_ROUTED_PROVIDER])];
  if (line.trim() === "") return {};
  let msg: unknown;
  try { msg = JSON.parse(line); } catch { return { note: "mandu: goose acp: dropped a line from the editor that is not JSON" }; }
  if (!isObj(msg)) return { note: "mandu: goose acp: dropped a JSON-RPC batch or non-object from the editor (ACP sends single messages)" };
  const method = typeof msg["method"] === "string" ? (msg["method"] as string) : undefined;
  const hasId = "id" in msg && msg["id"] !== null && msg["id"] !== undefined;
  // A response to one of Goose's requests (a permission answer, …).
  if (method === undefined) return hasId ? { toGoose: line } : { note: "mandu: goose acp: dropped a message with neither method nor id" };
  if (!hasId) {
    return ALLOWED_NOTIFICATIONS.has(method)
      ? { toGoose: line }
      : { note: `mandu: goose acp: dropped the editor's \`${method}\` notification (not one Mandu passes)` };
  }
  const id = msg["id"];
  const refuse = (why: string): AcpStep => ({
    toEditor: errorReply(id, REFUSED_CODE, `mandu: ${why}`),
    note: `mandu: goose acp: refused \`${method}\`: ${why}`,
  });
  if (!ALLOWED_METHODS.has(method)) {
    return {
      toEditor: errorReply(id, METHOD_NOT_FOUND, `mandu: \`${method}\` is not passed to Goose under Mandu (only the standard ACP session methods are)`),
      note: `mandu: goose acp: refused \`${method}\` (not a standard ACP session method)`,
    };
  }
  const params = isObj(msg["params"]) ? (msg["params"] as Json) : {};
  const sessionId = typeof params["sessionId"] === "string" ? (params["sessionId"] as string) : undefined;
  let out: Json = msg;
  switch (method) {
    case "initialize": {
      // Offer Goose neither the editor's file system nor its terminal: every
      // tool then runs in Goose, inside the wrap.
      const caps = isObj(params["clientCapabilities"]) ? { ...(params["clientCapabilities"] as Json) } : {};
      caps["fs"] = { readTextFile: false, writeTextFile: false };
      caps["terminal"] = false;
      out = { ...msg, params: { ...params, clientCapabilities: caps } };
      break;
    }
    case "session/new":
    case "session/load":
    case "session/fork": {
      const meta = isObj(params["_meta"]) ? (params["_meta"] as Json) : {};
      const p = meta["provider"];
      if (p !== undefined && p !== null && !(typeof p === "string" && isAllowedProvider(p, routed))) {
        return refuse(`the session's provider \`${String(p)}\` is not one Mandu routes (this launch sends only ${spell(routed)} through its model proxy)`);
      }
      const recipeKey = Object.keys(meta).find((k) => /recipe/i.test(k) && k !== "recipeParameterScopeId");
      if (recipeKey !== undefined) return refuse(`a recipe in \`_meta.${recipeKey}\` can name its own provider above Mandu's routing; run it with \`mandu goose run --recipe <file>\``);
      if (meta["enabledExtensions"] !== undefined && meta["enabledExtensions"] !== null) {
        return refuse("`_meta.enabledExtensions` replaces the session's extensions (code mode among them) outside Mandu's checks");
      }
      const mounts = acpMcpServers(opts.mcpServers);
      if (mounts.length > 0) {
        const own = Array.isArray(params["mcpServers"]) ? (params["mcpServers"] as unknown[]) : [];
        const names = new Set(mounts.map((m) => m["name"]));
        out = { ...msg, params: { ...params, mcpServers: [...own.filter((s) => !(isObj(s) && names.has(s["name"]))), ...mounts] } };
      }
      state.pending.set(idKey(id), { method, ...(sessionId !== undefined ? { sessionId } : {}) });
      break;
    }
    case "session/prompt": {
      const prov = sessionId === undefined ? undefined : state.sessions.get(sessionId);
      if (prov === undefined || prov === null) {
        return refuse("Mandu has not seen this session's provider (start or load the session through `mandu goose acp`)");
      }
      if (!isAllowedProvider(prov, routed)) {
        return refuse(`this session's provider is \`${prov}\`; this launch routes only ${spell(routed)} through Mandu's model proxy`);
      }
      break;
    }
    case "session/set_config_option": {
      if (params["configId"] === "provider") {
        const v = valueId(params["value"]);
        if (v === null || !isAllowedProvider(v, routed)) {
          return refuse(`switching the provider to \`${v ?? JSON.stringify(params["value"])}\`: this launch routes only ${spell(routed)} through Mandu's model proxy`);
        }
      }
      state.pending.set(idKey(id), { method, ...(sessionId !== undefined ? { sessionId } : {}) });
      break;
    }
    case "session/list":
      // Tracked for the display pass only (its answer's titles).
      state.pending.set(idKey(id), { method });
      break;
    default:
      break;
  }
  return { toGoose: out === msg ? line : JSON.stringify(out) };
}

/** Decide one Goose → editor line. The line is forwarded (to the display
 *  pass, goose-acp-display.ts) unless it is a `fs/*` / `terminal/*` request
 *  (answered here). Pure except that it updates `state`. */
export function acpFromGoose(line: string, state: AcpRelayState): AcpStep {
  let msg: unknown;
  try { msg = JSON.parse(line); } catch { return { toEditor: line }; }
  if (!isObj(msg)) return { toEditor: line };
  const method = typeof msg["method"] === "string" ? (msg["method"] as string) : undefined;
  const hasId = "id" in msg && msg["id"] !== null && msg["id"] !== undefined;
  if (method !== undefined && hasId && (method.startsWith("fs/") || method.startsWith("terminal/"))) {
    return {
      toGoose: errorReply(msg["id"], METHOD_NOT_FOUND, "mandu: the editor's file system and terminal are not offered under Mandu; run the tool in Goose"),
      note: `mandu: goose acp: answered Goose's \`${method}\` itself (the editor's file system and terminal are not offered)`,
    };
  }
  let answers: string | undefined;
  if (method === undefined && hasId) {
    const asked = state.pending.get(idKey(msg["id"]));
    if (asked !== undefined) {
      state.pending.delete(idKey(msg["id"]));
      answers = asked.method;
      const result = isObj(msg["result"]) ? (msg["result"] as Json) : null;
      if (result !== null) {
        const sid = typeof result["sessionId"] === "string" ? (result["sessionId"] as string) : asked.sessionId;
        if (sid !== undefined) {
          const prov = providerOf(result["configOptions"]);
          // A session/load or fork that reports no provider stays unknown
          // (its prompts are refused); a config change that reports none
          // keeps what was known only if it was not a provider change.
          if (prov !== null) state.sessions.set(sid, prov);
          else if (asked.method !== "session/set_config_option") state.sessions.set(sid, null);
        }
      }
    }
  } else if (method === "session/update" && isObj(msg["params"])) {
    const p = msg["params"] as Json;
    const u = isObj(p["update"]) ? (p["update"] as Json) : null;
    if (u !== null && u["sessionUpdate"] === "config_option_update" && typeof p["sessionId"] === "string") {
      const prov = providerOf(u["configOptions"]);
      if (prov !== null) state.sessions.set(p["sessionId"], prov);
    }
  }
  return answers !== undefined ? { toEditor: line, answers } : { toEditor: line };
}

/** Split a byte stream into lines (ACP's stdio framing: one JSON-RPC
 *  message per line), calling `onLine` for each and `onEnd` at the end. */
function lines(src: Readable, onLine: (l: string) => void, onEnd: () => void): void {
  let buf = "";
  src.setEncoding("utf8");
  src.on("data", (chunk: string) => {
    buf += chunk;
    let nl: number;
    while ((nl = buf.indexOf("\n")) >= 0) {
      const l = buf.slice(0, nl).replace(/\r$/, "");
      buf = buf.slice(nl + 1);
      onLine(l);
    }
  });
  src.on("end", () => { if (buf !== "") onLine(buf); buf = ""; onEnd(); });
  src.on("error", () => onEnd());
}

/** A running relay: its state, and `drained()`, which settles once Goose's
 *  output has ended and every line queued for the editor is written. */
export interface AcpRelay {
  state: AcpRelayState;
  drained(): Promise<void>;
}

/** Wire the relay: editor (the launcher's stdin / stdout) ⇄ Goose (the
 *  chain's stdin / stdout). The editor's end of input closes Goose's; Goose's
 *  end of output closes nothing (the launcher exits with the chain, after
 *  `drained()`). `desymbolize` (the human plane's, goose-acp-display.ts)
 *  resolves the display strings of the editor-bound lines; null or absent
 *  forwards them as Goose wrote them. Everything written toward the editor,
 *  the relay's own answers included, goes through one ordered queue. */
export function startAcpRelay(io: {
  editorIn: Readable;
  editorOut: Writable;
  gooseIn: Writable;
  gooseOut: Readable;
  note?: (m: string) => void;
  opts?: AcpRelayOpts;
  desymbolize?: Desymbolize | null;
}): AcpRelay {
  const state = newAcpRelayState();
  const note = io.note ?? ((m: string) => console.error(m));
  let gooseOpen = true;
  io.gooseIn.on("error", () => { gooseOpen = false; });
  io.editorOut.on("error", () => { /* the editor went away; the chain ends on its stdin */ });
  const toGoose = (l: string): void => { if (gooseOpen) io.gooseIn.write(`${l}\n`); };
  const editor = new AcpEditorWriter((l) => { io.editorOut.write(`${l}\n`); }, io.desymbolize ?? null, note);
  // Only lines that come from Goose are display candidates; the relay's
  // own refusals carry nothing to resolve.
  const apply = (s: AcpStep, fromGoose: boolean): void => {
    if (s.note) note(s.note);
    if (s.toGoose !== undefined) toGoose(s.toGoose);
    if (s.toEditor !== undefined) editor.push(s.toEditor, s.answers, fromGoose);
  };
  let gooseEnded!: () => void;
  const ended = new Promise<void>((r) => { gooseEnded = r; });
  lines(io.editorIn, (l) => apply(acpFromEditor(l, state, io.opts), false), () => { gooseOpen = false; io.gooseIn.end(); });
  lines(io.gooseOut, (l) => apply(acpFromGoose(l, state), true), () => gooseEnded());
  return { state, drained: async () => { await ended; await editor.drained(); } };
}
