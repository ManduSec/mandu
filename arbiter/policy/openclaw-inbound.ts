/**
 * openclaw-inbound — the inbound data-trust ruleset Mandu uses when DEFENDING
 * a live OpenClaw CLI at the model-context proxy (spec id `openclaw-agent`).
 *
 * ─── WHY THIS EXISTS ALONGSIDE THE `openclaw` SPEC ───────────────────────────
 *
 * tool-inbound.ts's TOOL_INBOUND_SPEC (spec id `openclaw`) is the ruleset LIFTED
 * VERBATIM from the reference DUALVIEW plugin. It is kept faithful on purpose —
 * two arbiter unit tests pin it as the reference — and it must NOT be edited to
 * suit a live deployment.
 *
 * It is also NOT SAFE to reuse as-is for a live OpenClaw CLI, and the reason is
 * the whole point of this file. The lifted spec grants `read: TRUSTED`
 * wholesale. That was correct IN THE REFERENCE, because the reference ran the
 * plugin's FS view-sync: every untrusted file on disk already carried a symbol
 * token in the agent's view, so a trusted `read` returned an already-symbolized
 * body. Mandu defending OpenClaw at the PROXY has no such guarantee — the
 * model-context proxy is the only enforcement live unprivileged today
 * (CONTRIBUTING.md), fs-sync is not in the default posture, and so a wholesale-trusted
 * `read` would forward a poisoned file's bytes RAW to the privileged model.
 * That is precisely the stored-IPI chain, and it would be a security regression.
 *
 * So this file re-maps OpenClaw's tools onto Mandu's proxy-only posture,
 * inheriting each decision from the corresponding claude-code-inbound.ts entry
 * rather than re-litigating it — the same relationship claude-code-inbound.ts
 * has to the lifted spec. Divergences from the lifted spec are marked
 * `DIVERGES:` with the reason.
 *
 * ─── TOOL SURFACE — ESTABLISHED FROM THE WIRE (2026-08-05) ───────────────────
 *
 * Names and param keys were read out of a real `openclaw agent --local` request
 * body captured against a local /v1/messages endpoint
 * (docs/design/testing/agent-e2e-harness.md §2.4), under `tools.profile: "coding"`:
 *   read, edit, write, exec, process, cron, sessions_list, sessions_history,
 *   sessions_send, sessions_yield, sessions_spawn, subagents, session_status,
 *   web_search, web_fetch, image, memory_search, memory_get
 * The `full` profile adds browser, canvas, message, gateway, nodes, agents_list,
 * tts, apply_patch; the unambiguous ones are mapped so enabling that profile
 * does not silently degrade.
 *
 * 2026-09-27: the `coding` profile of 2026.6.35 and 2026.7.1 also advertises
 * create_goal, get_goal, update_goal, update_plan and skill_workshop, and
 * 2026.9.6 adds ls, view_image and the Tool Search dispatcher (tool_search,
 * tool_describe, tool_call; tool_search_code in its code mode), and with
 * `tools.toolSearch: false` shows 17 more (agents_wait, ask_user, the
 * conversations_* trio, sessions, sessions_search, intent, dashboard, theme,
 * progress_card, and the refused terminal, automations, gateway, plugins,
 * secrets, portal). Each is mapped (or refused on the wire) below from the
 * tool's source in the published package, not from its name.
 * 2026-10-09: 2026.9.9 adds `presence` (with `tools.toolSearch: false`), and
 * every release from 2026.5.18 has Code Mode (`tools.codeMode`), whose
 * surface is `exec{code}` and `wait{runId}`: both refused on the wire
 * (tool-gate-surface.ts), and Code Mode is off in the launcher's run config.
 * The captured surfaces are arbiter/test/fixtures/openclaw-tool-surface-2026-09-27.json;
 * unit tests hold every tool of each captured build to a rule here, a
 * refusal, or a dispatcher.
 *
 * NOTE `read` accepts BOTH `path` (primary) and `file_path` (alias). The lifted
 * spec keys only `file_path`, so against the current CLI its DIR key never
 * resolves. Both are keyed here — keying the wrong param name is a silent
 * fail-closed, so this is load-bearing.
 *
 * SECURITY INVARIANT (carried over, unchanged): TRUSTED is granted ONLY on an
 * explicit rule match; anything unlisted fails closed to UNTRUSTED.
 */

import type { SchemaNode, ToolSpec } from "./schema-types.js";

export const OPENCLAW_AGENT_INBOUND_SPEC: Record<string, ToolSpec> = {
  // ── Local filesystem reads ──────────────────────────────────────────────
  // DIVERGES from the lifted spec (`read: TRUSTED`): no `wholeResult` rule, so
  // the live whole-result path stays FAIL-CLOSED UNTRUSTED — see the header.
  // The per-field schema below serves field-addressed callers and the policy
  // snapshot; both param spellings are keyed.
  read: {
    paramsKeys: {
      path: { category: "DIR", role: "key" },
      file_path: { category: "DIR", role: "key" },
    },
    schema: {
      content: { category: "DIR", role: "data", keyField: "params.path" },
      text: { category: "DIR", role: "data", keyField: "params.path" },
      path: { category: "DIR", role: "key" },
      file_path: { category: "DIR", role: "key" },
      offset: "TRUSTED",
      limit: "TRUSTED",
    } satisfies SchemaNode,
  },

  // ── Local filesystem writes / edits — agent-authored metadata ───────────
  // The result echoes what the AGENT produced → TRUSTED metadata.
  // (agrees with the lifted spec; mirrors Claude Code Write/Edit)
  write: { schema: "TRUSTED" },
  edit: { schema: "TRUSTED" },
  apply_patch: { schema: "TRUSTED" },

  // ── Shell ───────────────────────────────────────────────────────────────
  // `exec` stdout/stderr is attacker-reachable → plaintext UNTRUSTED.
  // (agrees with the lifted spec; the analogue of Claude Code `Bash`)
  exec: { schema: "UNTRUSTED" },

  // `process` polls/interacts with a BACKGROUND shell session — the same bytes
  // `exec` would have returned inline, so the same threat model → UNTRUSTED.
  // (mirrors Claude Code BashOutput)
  process: { schema: "UNTRUSTED" },

  // ── External network ────────────────────────────────────────────────────
  // Body is EXTERNAL content → UNTRUSTED, keyed off the requested URL so an
  // operator-trusted origin can still resolve TRUSTED. Field names follow the
  // lifted spec's web_fetch shape (which was written against this exact tool).
  web_fetch: {
    paramsKeys: { url: { category: "URL", role: "key" } },
    schema: {
      url: { category: "URL", role: "key" },
      finalUrl: { category: "URL", role: "key" },
      status: "TRUSTED",
      contentType: "TRUSTED",
      extractMode: "TRUSTED",
      truncated: "TRUSTED",
      length: "TRUSTED",
      title: { category: "URL", role: "data", keyField: "params.url" },
      text: { category: "URL", role: "data", keyField: "params.url" },
    } satisfies SchemaNode,
  },

  // Per-item URL trust: the resolver walks __items and resolves keyField
  // against each item. No whole-result rule — a flattened result mixes
  // per-URL items, so whole-result stays fail-closed.
  web_search: {
    schema: {
      query: "TRUSTED",
      provider: "TRUSTED",
      count: "TRUSTED",
      results: {
        __items: {
          url: { category: "URL", role: "key" },
          published: "TRUSTED",
          siteName: "TRUSTED",
          title: { category: "URL", role: "data", keyField: "url" },
          description: { category: "URL", role: "data", keyField: "url" },
        },
      },
    } satisfies SchemaNode,
  },

  // `browser` drives a real browser and returns page content — the same
  // external-origin class as web_fetch but without a single stable key field on
  // the result → literal UNTRUSTED. (`full` profile only.)
  browser: { schema: "UNTRUSTED" },

  // ── Memory ──────────────────────────────────────────────────────────────
  // DIVERGES from the lifted spec (`memory_search`/`memory_get`: TRUSTED).
  // Memory is STORED CONTENT that earlier turns ingested — the canonical
  // stored-IPI carrier, and the exact persistence channel the defense exists to
  // close (persistence across sessions). The lifted
  // spec could trust it because view-sync symbolized untrusted content at rest;
  // proxy-only has no such backstop → UNTRUSTED.
  memory_search: { schema: "UNTRUSTED" },
  memory_get: { schema: "UNTRUSTED" },

  // ── Sessions / subagents ────────────────────────────────────────────────
  // A subagent's or sibling session's content can be attacker-influenced (that
  // session may itself have read untrusted data) → UNTRUSTED.
  // (mirrors Claude Code Task/TaskOutput)
  sessions_history: { schema: "UNTRUSTED" },
  sessions_send: { schema: "UNTRUSTED" },
  sessions_spawn: { schema: "UNTRUSTED" },
  sessions_yield: { schema: "UNTRUSTED" },
  subagents: { schema: "UNTRUSTED" },
  // DIVERGES (lifted spec has no entry): session LABELS are derived from
  // message content, which on a gateway deployment is untrusted channel input.
  sessions_list: { schema: "UNTRUSTED" },

  // `session_status` returns the harness's own lifecycle/model metadata for a
  // session the agent already owns — no channel for foreign content.
  // (agrees with the lifted spec)
  session_status: { schema: "TRUSTED" },

  // ── Messaging ───────────────────────────────────────────────────────────
  // DIVERGES (lifted spec has no inbound entry): `message` reaches OpenClaw's
  // multi-channel ingress (Telegram/WhatsApp/Slack/Discord/email…). Inbound
  // channel content is the single most exposed untrusted surface this agent
  // has — the reference plugin gave it its own hook
  // (transform_webhook_content). → UNTRUSTED. (`full` profile only.)
  message: { schema: "UNTRUSTED" },

  // ── Agent-authored scheduling / UI metadata ─────────────────────────────
  // Results echo the schedule/canvas/node state the AGENT itself authored.
  // (agrees with the lifted spec)
  cron: { schema: "TRUSTED" },
  canvas: { schema: "TRUSTED" },
  nodes: { schema: "TRUSTED" },
  tts: { schema: "TRUSTED" },

  // `image` returns generated/fetched image metadata whose provenance is
  // external or model-generated → UNTRUSTED.
  image: { schema: "UNTRUSTED" },

  // ── Thread goals and the work plan (2026.6.35+) ─────────────────────────
  // create_goal / update_goal / get_goal return the session's goal record
  // (src/agents/tools/goal-tools.ts over config/sessions/goals.ts): an
  // `objective` the agent wrote through create_goal or the user set with
  // `/goal start|edit` (the same trust as the user's own turn), the agent's
  // `lastStatusNote`, a status enum, timestamps and token counters. The store
  // is scoped to the CURRENT session key, so no sibling session or subagent
  // writes into it. → TRUSTED (TaskCreate/TaskUpdate's class).
  create_goal: { schema: "TRUSTED" },
  update_goal: { schema: "TRUSTED" },
  get_goal: { schema: "TRUSTED" },
  // update_plan validates the agent's own step list and echoes it back
  // (`{status:"updated", explanation?, plan}`) and reads nothing.
  // (mirrors Claude Code TodoWrite)
  update_plan: { schema: "TRUSTED" },

  // skill_workshop's `list` / `inspect` return skill PROPOSALS stored in the
  // workspace (PROPOSAL.md + support files), which autocapture or a planted
  // file can author, and `update` works on a live skill's body. Workspace-file
  // procedure text is Skill's class in claude-code-inbound.ts → UNTRUSTED.
  skill_workshop: { schema: "UNTRUSTED" },

  // ── 2026.9.x additions (outside the tested range; mapped ahead) ─────────
  // `ls` lists directory entry NAMES (JSON-quoted, `/` for directories) from
  // the agent's own path param: Claude Code LS's class → TRUSTED.
  ls: { schema: "TRUSTED" },
  // `view_image` replaces `image`: a local path or a URL loaded into the
  // model's context, or described by a configured image model → UNTRUSTED.
  view_image: { schema: "UNTRUSTED" },

  // ── The rest of 2026.9.6's coding surface (read from its source) ────────
  // `progress_card` replaces the session's progress card and answers only
  // `{revision, steps: {completed, total}}` (src/agents/tools/
  // progress-card-tool.ts): counts over the agent's own card → TRUSTED.
  progress_card: { schema: "TRUSTED" },
  // `agents_wait` returns the finished subagents' results: Task/TaskOutput's
  // class (sessions_spawn above) → UNTRUSTED.
  agents_wait: { schema: "UNTRUSTED" },
  // `ask_user` returns the answer to a question it may deliver over a message
  // channel (question-channel-runtime): whoever answers in that channel, not
  // necessarily the operator at this terminal. Claude Code's AskUserQuestion
  // is TRUSTED because only the terminal user can answer it; here the
  // channel is `message`'s class → UNTRUSTED.
  ask_user: { schema: "UNTRUSTED" },
  // External channel conversations (src/agents/tools/conversation-tools.ts):
  // `conversations_list` lists conversation refs with channel metadata,
  // `conversations_turn` returns the PEER's reply, `conversations_send` a
  // delivery receipt. Channel content is `message`'s class → UNTRUSTED. The
  // two senders are also net tools (tool-gate-surface.ts).
  conversations_list: { schema: "UNTRUSTED" },
  conversations_send: { schema: "UNTRUSTED" },
  conversations_turn: { schema: "UNTRUSTED" },
  // `sessions` (list/patch/archive across the agent's sessions) and
  // `sessions_search` (full-text over transcripts) return other sessions'
  // titles, labels and transcript text: sessions_list/sessions_history's
  // class → UNTRUSTED.
  sessions: { schema: "UNTRUSTED" },
  sessions_search: { schema: "UNTRUSTED" },
  // `intent` lists standing intents whose descriptions earlier sessions (on
  // any channel) wrote, re-injected when a keyword fires: memory's class →
  // UNTRUSTED.
  intent: { schema: "UNTRUSTED" },
  // `dashboard` returns Control UI tabs with plugin widget props; `theme`
  // returns built-in, PLUGIN and personal theme definitions with their
  // descriptions → UNTRUSTED (plugin-authored text).
  dashboard: { schema: "UNTRUSTED" },
  theme: { schema: "UNTRUSTED" },
  // The dispatcher's catalog readers: `tool_search` / `tool_describe` return
  // catalog entries whose descriptions come from plugins and client tools →
  // UNTRUSTED (mapped so the session-health surface names no unknown tool;
  // the trust is what omission gave them).
  tool_search: { schema: "UNTRUSTED" },
  tool_describe: { schema: "UNTRUSTED" },
  // 2026.9.9 (`tools.toolSearch: false`; behind the dispatcher by default):
  // `presence` asks the gateway who and which devices are connected
  // (`presence.query`, src/agents/tools/presence-tool.ts; read-only). Its
  // answer carries display names, device names and activity that the people
  // and devices connected to the gateway report, plus their IP addresses and
  // approximate locations → UNTRUSTED (remote-authored text).
  presence: { schema: "UNTRUSTED" },

  // ── Provider tools outside the coding capture (2026.9.6 source) ─────────
  // Net tools in tool-gate-surface.ts. `x_search` returns X posts (external
  // authors); `code_execution` returns the output of code xAI ran on the
  // task text; `show_widget` returns the host's presentation receipt, which
  // echoes widget state a Control UI viewer can change. None opens a local
  // path, so none needs the unmapped-input scan → UNTRUSTED.
  x_search: { schema: "UNTRUSTED" },
  code_execution: { schema: "UNTRUSTED" },
  show_widget: { schema: "UNTRUSTED" },

  // REFUSED ON THE WIRE, left unmapped (their results are the schema error
  // the refusal produces, UNTRUSTED by omission): `terminal`, `automations`
  // (and its `cron` alias's calls), `gateway`, `plugins`, `secrets`,
  // `portal`, `nodes`. Each acts outside every Mandu chokepoint (a shell in
  // the gateway, runs that fire later in the gateway, executable plugins, a
  // credential bound to hosts the agent names, a public route to a local
  // port, commands on paired devices), so the proxy replaces the call
  // (tool-gate-surface.ts `refuse`; supported-agents.md §2.1).
  //
  // Also refused (2026-09-28, the same reasons): `sessions_send` and
  // `sessions_spawn` (the work runs in whichever gateway serves the call,
  // outside Mandu under `mandu openclaw chat`; their entries above stay for
  // the reference spec's sake), and the `full`-profile `computer`,
  // `mobile_ui`, `canvas`, `openclaw` (the setup delegate) and
  // `github_publish`. `exec{host: "node"}` and `browser{target: "node"}` are
  // refused in that form only (tool-gate-surface.ts `refuseArgs`).
  //
  // Code Mode (2026-10-09): `wait` is refused outright and `exec` in its
  // Code Mode form (`exec{code}`, `exec{language}`) is refused by form: the
  // JavaScript calls tools inside OpenClaw, where no gate reads them. `wait`
  // stays unmapped; `exec` keeps its rule above (the shell's output).
  //
  // DELIBERATELY UNMAPPED (fail-closed UNTRUSTED by omission): `agents_list`,
  // and anything a future OpenClaw release adds. A new tool must
  // be mapped with a provenance justification before its results pass raw.
  // `pdf`, `image_generate`, `music_generate` and `video_generate` stay
  // unmapped ON PURPOSE although the gate table covers them: each reads
  // local files named in array fields (`pdfs`, `images`, `videos`), and
  // only an unmapped tool gets the input scan that raises its result's level
  // for every labeled path it names (confidentiality-plan-10 §11.11). The
  // sensitive-path gate reads those arrays too since 2026-09-29
  // (tool-gate-surface.ts), but only paths it can place and only with the
  // view map, so the scan stays.
  //
  // THE TOOL SEARCH DISPATCHER (2026.9.x, ON by default: `tools.toolSearch`
  // unset means enabled, mode "tools"): `tool_call` and `tool_search_code`
  // stay unmapped ON PURPOSE (the session-health surface counts them as
  // handled by the gate surface, not unknown). `tool_call`
  // runs ANY catalog tool by id (`{id, args}`), including exec, web_fetch and
  // memory_search, so its result carries whatever that tool returns;
  // `tool_search` / `tool_describe` return catalog entries whose descriptions
  // come from plugins and client tools; `tool_search_code` runs JavaScript that
  // calls tools. None has one provenance, so all four stay UNTRUSTED. The
  // wire-side gates see THROUGH the dispatcher (tool-gate-surface.ts
  // `dispatch`, the proxy's dispatch.ts): a `tool_call` is gated as its inner
  // tool, and its result's path-derived level and exec-output legs read the
  // inner tool too; only the TRUST verdict stays the dispatcher's own, because
  // the id may resolve to a plugin or MCP tool that shares a core name.
  // `tool_search_code` is refused on the wire. docs/design/agents/supported-agents.md
  // §2.1.
  //
  // NB OpenClaw has NO MCP client, so there is no MCP tool family to match
  // here. Mandu's quarantine channel ships as plugin tools instead
  // (interceptors/openclaw-inspect-plugin): bare `inspect_symbol` and
  // `declassify_symbol`, both mapped spec-independently in tool-inbound.ts
  // getToolInboundSpec (inspect-tool.ts owns the names), not in this table
  // (docs/design/testing/agent-e2e-harness.md §8, §8.5).
};

/** The size OpenClaw prints in a read notice (`formatSize`: `512B`,
 *  `50.0KB`, `1.5MB`; the capped notice drops a `.0` before `KB`). */
const OC_SIZE = String.raw`\d{1,12}(?:\.\d)?(?:B|KB|MB)`;

/**
 * The continuation notices OpenClaw's `read` appends after the file text,
 * read from the published source (2026.7.1 `sessions-*.js` and
 * `openclaw-tools-*.js`, 2026.9.6 `tools-*.mjs` read-page): digits, a size
 * and fixed words only, never a file byte. Anchored at the END of the result;
 * any other trailer (a cursor continuation, a `[Resolved filename: …]` note,
 * a blank-lines message) is not stripped and so fails the content test.
 */
const OPENCLAW_READ_NOTICE_RE = new RegExp(
  String.raw`\n\n\[(?:` +
    String.raw`\d{1,12} more lines? in file\. Use offset=\d{1,12} to continue\.` +
    String.raw`|Showing lines \d{1,12}-\d{1,12} of \d{1,12}(?: \(${OC_SIZE} limit\))?\. Use offset=\d{1,12} to continue\.` +
    String.raw`|Read output capped at ${OC_SIZE} for this call\. Use offset=\d{1,12}(?:, limit=\d{1,12})? to continue\.` +
    String.raw`)\]$`,
);

/**
 * OpenClaw's `read` rendering of a text file, reduced to the file text it
 * carries, for the structured read-twin rule (plan 10 §2.4 and §11.8;
 * policy-interface.ts runs the content test, claude-code-inbound.ts
 * isStructuredTwinText). OpenClaw prints the selected lines as they are, no
 * gutter, and may append ONE continuation notice (OPENCLAW_READ_NOTICE_RE);
 * that notice is the only thing removed. Pure; never throws.
 */
export function openclawReadRenderingText(value: string): string {
  if (typeof value !== "string") return "";
  const v = value.replace(/\s+$/, "");
  const m = OPENCLAW_READ_NOTICE_RE.exec(v);
  return m ? v.slice(0, m.index) : v;
}
