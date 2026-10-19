# Mandu Inbound/Outbound Specification

> Source of truth: `adfi-openclaw/plugin/adfi/policy/tool-inbound.ts`, `policy/tool-outbound.ts`
> User extension surface: `tools:` section in `aos-policy.yaml` (see [Per-tool YAML overrides](#per-tool-yaml-overrides))
> Last updated: 2026-04-20

## Summary

Mandu spec for each inbound/outbound data flow.

- **Inbound (tool → agent):** TRUSTED if the source cannot be influenced by an attacker. UNTRUSTED if attacker-reachable, and Mandu symbolizes/labels the data.
- **Outbound (agent → tool):** Resolve if the destination is Human File System or another human-facing/external interface. Do not resolve if the destination is Agent File System (symbolized context).

| Tool | Inbound (tool → agent) | Outbound (agent → tool) | Notes |
| --- | --- | --- | --- |
| `web_fetch` | UNTRUSTED (per-field) | ⚡ Resolve | Untrusted: `title`, `text`; Trusted: `url`, metadata |
| `web_search` | UNTRUSTED (per-field) | ⚡ Resolve | Untrusted: `results[].title`, `results[].description`; Trusted: `results[].url`, metadata |
| `exec` (default) | UNTRUSTED (full wrap) | ⚡ Resolve | |
| `exec` (`RESTRICTED=1`) | TRUSTED | 🛡️ Not resolve | Restricted: no network, symbolized FS view |
| `process` (poll/log) | UNTRUSTED (full wrap) | ⚡ Resolve | Shell stdout/stderr from live exec session — same threat model as `exec` output |
| `process` (write/send-keys/submit/paste) | TRUSTED | ⚡ Resolve | Metadata-only result (byte counts); input fields (`data`/`keys`/`hex`/`literal`/`text`) feed PTY stdin so symbols resolved |
| `process` (list/kill/clear/remove) | TRUSTED | ⚡ Resolve | Registry metadata and lifecycle confirmations |
| `process` (unknown action) | UNTRUSTED (full wrap) | ⚡ Resolve | Fail-closed default for unrecognized actions |
| `image` | UNTRUSTED (full wrap) | ⚡ Resolve | |
| `sessions_send` | configurable (per-field) | 🛡️ Not resolve | Baseline TRUSTED. Channel-trust policy can override to UNTRUSTED (only `reply` symbolized) |
| `sessions_spawn` | TRUSTED | 🛡️ Not resolve | Spawned session has symbolized view by default |
| `sessions_history` | configurable (per-field) | 🛡️ Not resolve | Baseline TRUSTED. Channel-trust policy can override (only `messages[].content[].text` symbolized) |
| `sessions_list` | TRUSTED | 🛡️ Not resolve | |
| `subagents` | TRUSTED | 🛡️ Not resolve | |
| `message` (send) | TRUSTED | ⚡ Resolve | Outbound to channel -- symbols resolved |
| `message` (read/search) | configurable (full wrap) | ⚡ Resolve | Baseline TRUSTED. Channel-trust policy can override to UNTRUSTED |
| `read` | TRUSTED | 🛡️ Not resolve | |
| `write` | TRUSTED | 🛡️ Not resolve | Symbols preserved in worktree |
| `edit` | TRUSTED | 🛡️ Not resolve | Symbols preserved in worktree |
| `inspect_symbol` | TRUSTED | 🛡️ Not resolve | U-LLM extracts structured data; output fields re-symbolized as derived symbols |
| `memory_search` | TRUSTED | 🛡️ Not resolve | |
| `memory_get` | TRUSTED | 🛡️ Not resolve | |
| `session_status` | TRUSTED | No params | Internal state |
| `canvas` | — | ⛔ Disabled | Mac-only tool; not applicable to current Mandu deployment |
| `nodes` | — | ⛔ Disabled | Paired-device tool (iOS/Android/Mac); not applicable to headless deployment. Note: `notifications_list` output should be UNTRUSTED when enabled |
| `cron` | TRUSTED | 🛡️ Not resolve | |
| `tts` | TRUSTED | ⚡ Resolve | Outbound to user — symbols resolved |
| Channel messages | N/A (user input) | N/A (user input) | Enter as user messages; Mandu applies to tools the LLM calls in response |
| Webhooks | UNTRUSTED (per-field) | No params | `transform_webhook_content` hook; see [webhook design](webhook.md) |

### Inbound Data Classification Policy

How inbound data (tool results, webhook payloads) is classified as TRUSTED or UNTRUSTED.

| Policy | Status | Description |
| --- | --- | --- |
| Tool allowlist | ✅ Done | Unified `TOOL_RESULT_TRUST` map in `policy/tool-inbound.ts` with `ToolResultSpec` type (TRUSTED, UNTRUSTED, FieldTrustSchema, configurable) |
| Field allowlist | ✅ Done | Inline in `TOOL_RESULT_TRUST` for `web_fetch`, `web_search`, `sessions_send`, `sessions_history` |
| Webhook allowlist | ✅ Done | `webhookSchemas` config or payload `security` field; per-job field trust classification |
| Web URL allowlist | ✅ Done | Trusted URL allowlist via `aos-policy.yaml`. `web_fetch`/`image` URL match -> TRUSTED. `web_search` per-result filtering. `policy/url-trust.ts` |
| Channel allowlist | 🔶 Partial | Untrusted channel list via `aos-policy.yaml`. `sessions_send`, `sessions_history` verified (e2e). `message` read/search unit tested only (no platform e2e). `policy/channel-trust.ts` |
| Sender allowlist | ❌ Not done | Applicable: user messages, `message` read/search. Trust decision based on message sender identity |
| Email allowlist | ❌ Not done | Applicable: `exec` (email CLI). Trust decision based on email sender/headers vs body content |

### Outbound Data Flow Policy

How outbound data (agent tool params sent to external systems) is governed.

| Policy | Status | Description |
| --- | --- | --- |
| Network proxy policy | ❌ Not done | Endpoint-level trust for exec outbound traffic |
| CLI allowlist policy | ❌ Not done | Per-CLI trust for known tools (gh, glab, gcloud) |

---

## Mandu Specification

### Policy single-source principle

All trust-policy input flows through a single YAML file referenced by
`cfg.policyPath`. The YAML schema is detailed below (per-category
inbound rules under `inbound.{url,channel,dir,command}`, per-tool
overrides under `tools.<name>`). There are no plugin-config shortcuts:
`openclaw.json` cannot inject policy values directly.

For test setups that need to vary paths per run (e.g. WORKSPACE is a
fresh tmpdir each E2E invocation), set `perTestConfig.policyFixture`
to point at a fixture YAML; `test/lib/defense-registry.ts` copies the
file into the host state dir, substitutes `${WORKSPACE}`, `${STATE_DIR}`
and other tokens, and rewrites the config to use `policyPath`. This
keeps the plugin layer ignorant of test-infrastructure tokens.

### Inbound Data Spec (tool/webhook → agent)

Determines trust level of each field in agent inbound data (tool results, webhook payloads). Controls whether Mandu symbolizes/labels the field.

#### Schema model

Each tool's inbound data is described by a `SchemaNode` tree (`plugin/adfi/policy/schema-types.ts`):

- **Leaf** — a `FieldMarker`, one of four kinds:
  | Kind | Shape | Meaning |
  | --- | --- | --- |
  | literal `"TRUSTED"` | `"TRUSTED"` | Always trusted at the output. |
  | literal `"UNTRUSTED"` | `"UNTRUSTED"` | Always untrusted; the field is symbolized/labeled. |
  | **KeySpec** | `{ category, role: "key" }` | This field's *value is the lookup key* for some category (URL/CHANNEL/DIR/...). Keys are raw user/agent input — always TRUSTED at the output. Example: `web_fetch.url`. |
  | **DataSpec** | `{ category, role: "data", keyField }` | This field's trust is decided at hook time by classifying `keyField` against the named category. Example: `read`'s body, with `keyField: "params.file_path"` resolved against the DIR category. |
- **Internal node** — either an *object schema* `{ field1: SchemaNode, field2: SchemaNode, ... }` or an *array schema* `{ __items: SchemaNode }` (homogeneous element shape).

Object/array schemas are the common case for structured tools (`web_fetch`, `web_search`). Top-level leaves are the degenerate case where the tool's whole output is a single labeled blob (`exec` defaults to a literal `"UNTRUSTED"`; `read` is a single `DataSpec` keyed off the file path).

**Tool results:**

| Level | Meaning | Inline Mode | Symbolize Mode |
| --- | --- | --- | --- |
| **TRUSTED** | Local system data. Attacker cannot inject. | No change | No change |
| **UNTRUSTED** | External, attacker-reachable source. | `<<<AOS_UNTRUSTED>>>` markers | `$MDU:*` symbols |

Unknown/unclassified tools → fall back to the configurable **inbound default** (see [Default semantics when no spec matches](#default-semantics-when-no-spec-matches)).

**Webhook payloads** (via `transform_webhook_content` hook):

| Source | Behavior |
| --- | --- |
| Payload `security` field | Per-field trust from the payload itself (highest priority) |
| `webhookSchemas` config | Per-field trust from plugin config (keyed by `jobName`) |
| No schema | Entire content symbolized as single variable |

### Outbound Data Spec (agent → tool)

Determines whether `$MDU:*` symbols in agent outbound data (tool params) are resolved to raw values before the tool executes.

| Spec | Behavior | When |
| --- | --- | --- |
| **Not resolve** | Symbols kept as literal `$MDU:*` symbols | Tool supports symbolized execution (local FS, exec `RESTRICTED=1`, inter-session messaging) |
| **Resolve** | Symbols replaced with raw values before execution | (1) Tool sends data to external network (web_fetch URL, etc.), (2) outbound to user (message text, tts), (3) non-string type data (IDs, numbers, booleans — symbols can't meaningfully exist) |
| **No symbols expected** | Currently: resolved by `deepResolveSymbols`. Symbols should not appear in these fields (enums, config, booleans). | Fields where symbol presence indicates an LLM error |

**Future work:** Per-field configurable behavior when symbols appear in "no symbols expected" fields: `reject` (error), `resolve` (current default), or `not_resolve`.

### Per-tool YAML overrides

Third-party plugin authors can add or override tool specs in the same
YAML file used for category-level policies (URL / CHANNEL / DIR). Built-in
defaults (`TOOL_INBOUND_SPEC`, `TOOL_INPUT_RESOLVE`, `TOOL_INPUT_FIELD_POLICY`)
stay in TypeScript; YAML entries override a matching tool or add a new one.

```yaml
# aos-policy.yaml
tools:
  web_fetch:
    inbound:                 # SchemaNode — overrides TOOL_INBOUND_SPEC.schema
      url:   TRUSTED
      title: UNTRUSTED
      text:  UNTRUSTED
    outbound:                # per-field map — updates TOOL_INPUT_FIELD_POLICY
      url: resolve           # derives TOOL_INPUT_RESOLVE.web_fetch = true
  read:
    inbound: TRUSTED         # literal whole-tool override
    outbound:
      file_path: not_resolve
  my_custom_api:             # new tool — added to all three maps
    inbound: UNTRUSTED
    outbound: resolve        # scalar form — sets tool-level resolve=true
```

`outbound` accepts three forms:

- `"resolve"` / `"not_resolve"` — tool-level boolean; sets
  `TOOL_INPUT_RESOLVE[tool]` directly (field policy untouched).
- object (`field: resolve | not_resolve | no_symbols_expected`) — merged
  into `TOOL_INPUT_FIELD_POLICY[tool]`, and `TOOL_INPUT_RESOLVE[tool]` is
  derived (true iff any field is `resolve`).

**Back-compat:** the older JSON keys `toolSchemas` and `toolInputResolve`
in `openclaw.json` are still read (with a deprecation warning at startup).
They are applied after the YAML merge, so they override YAML on collision.

### Default semantics when no spec matches

Every tool-spec lookup can miss — either because the tool name is genuinely
unknown to Mandu or because the operator hasn't yet declared its rules. The
fallback is configurable per deployment via two plugin-config keys:

| Config key | Values | Default | Direction |
| --- | --- | --- | --- |
| `inboundDefault` | `"TRUSTED"` \| `"UNTRUSTED"` | `"TRUSTED"` | Inbound (tool → agent) |
| `outboundDefault` | `"resolve"` \| `"not_resolve"` | `"resolve"` | Outbound (agent → tool) |

The defaults favor ergonomics over fail-closed safety — an unspec'd tool
receives raw values on input and passes its output through unchanged.
Hardened deployments should flip both to the fail-closed variants.

**Inbound default.** `TRUSTED` (fail-open) passes the result through
unmodified and is the right choice when most tools in the deployment are
local/internal and the spec list is believed complete. `UNTRUSTED`
(fail-closed) synthesizes a blanket `schema: "UNTRUSTED"` for the missing
tool, running the same symbolize/label pipeline as any other UNTRUSTED
result. Pick this when new tools are being added faster than their specs —
every unclassified tool becomes safe by default at the cost of forcing
the agent through `inspect_symbol` for otherwise-trusted local data.

**Outbound default.** `resolve` (fail-open) replaces `$MDU:*`
tokens with raw values before the tool runs; new tools work without
declaring a spec, at the cost of letting untrusted values flow into
them. `not_resolve` (fail-closed) keeps symbols opaque — attacker-tainted
values cannot leak into an unspec'd tool's params, but any tool that
cannot interpret `$MDU:*` literals will misbehave until a spec is
declared.

**What counts as "spec'd".** For the outbound fallback, a tool is
considered spec'd if it appears in either `TOOL_INPUT_RESOLVE` (scalar
decision) or `TOOL_INPUT_FIELD_POLICY` (per-field map). This lets tools
like `read` — which have no scalar entry but a per-field policy keeping
`file_path` unresolved — retain their explicit rule even when the
deployment sets `outboundDefault: "resolve"`. For the inbound fallback
the check is simpler: a tool is spec'd iff it appears in
`TOOL_INBOUND_SPEC` (including YAML-sourced additions from
`mergeToolOverrides`).

**P1 implication.** `inboundDefault: "TRUSTED"` is fail-open against P1:
a tool whose output is attacker-reachable but not yet spec'd will leak
raw content to T-LLM. Deployments that add tools dynamically (e.g.
ClawHub skill installs — see #182) should flip this to `UNTRUSTED` and
opt tools in via YAML once their inbound schemas are verified.

---

# External Network Tools

## `web_fetch`

Primary prompt injection vector. Fetches arbitrary external URLs.

**Inbound (tool → agent):**

| Field | Trust | Notes |
| --- | --- | --- |
| `title` | UNTRUSTED | Symbolized/labeled by Mandu |
| `text` | UNTRUSTED | Symbolized/labeled by Mandu |
| `url`, `finalUrl` | TRUSTED | Needed for tool chaining |
| `status`, `contentType` | TRUSTED | Protocol metadata |
| `warning` | TRUSTED | OpenClaw-generated truncation notice |
| `externalContent` | TRUSTED | Metadata marker |
| `fetchedAt`, `tookMs` | TRUSTED | Telemetry |

OpenClaw already wraps `title`/`text` with `<<<EXTERNAL_UNTRUSTED_CONTENT>>>`. Mandu detects `externalContent.untrusted === true` to avoid double-wrapping.

**Outbound (agent → tool):**

| Field | Resolve | Notes |
| --- | --- | --- |
| `url` | ⚡ Resolve | Sent to external network — needs raw URL |
| `extractMode` | ⚡ Resolve | Config param, resolved via `deepResolveSymbols` (whole params) |
| `maxChars` | ⚡ Resolve | Config param, resolved via `deepResolveSymbols` (whole params) |

---

## `web_search`

Search results from attacker-reachable external sites (Brave API).

**Inbound (tool → agent):**

| Field | Trust | Notes |
| --- | --- | --- |
| `results[].title` | UNTRUSTED | Symbolized/labeled by Mandu |
| `results[].description` | UNTRUSTED | Symbolized/labeled by Mandu |
| `results[].url` | TRUSTED | Keep raw |
| `published`, `siteName` | TRUSTED | URL-derived metadata |

**Outbound (agent → tool):**

| Field | Resolve | Notes |
| --- | --- | --- |
| `query` | ⚡ Resolve | Sent to external search API — needs raw query |

---

## `image`

Vision model analysis. `content[].text` is always attacker-influenced (vision model output from potentially attacker-controlled image).

**Inbound (tool → agent):**

| Field | Trust | Notes |
| --- | --- | --- |
| `content[].text` | UNTRUSTED | Vision model output (full content wrap) |
| `details.model` | TRUSTED | Model metadata |
| `details.image` | TRUSTED | Resolved source path/URL |
| `details.attempts` | TRUSTED | Retry metadata |

No per-field schema yet. **Policy (future work):** inspect `details.image` — URL → UNTRUSTED, local path → TRUSTED.

**Outbound (agent → tool):**

| Field | Resolve | Notes |
| --- | --- | --- |
| `image` | ⚡ Resolve | May be sent to external URL — needs raw path/URL |

---

# Exec

## `exec`

Shell commands. Two modes control trust and isolation. Mode determined by `env.RESTRICTED`.

### Two Exec Modes

| | Default exec | Trusted exec (`RESTRICTED=1`) |
| --- | --- | --- |
| **Symbol handling** | Symbols resolved → raw values before execution | Symbols kept as literal `$MDU:*` symbols |
| **Filesystem view** | Raw (real values on disk) | Symbolized (same view as `read`) |
| **Network** | ✅ Allowed | ❌ Blocked |
| **Output trust** | UNTRUSTED (output symbolized) | TRUSTED (readable directly) |
| **Use case** | `curl`, `npm install`, commands needing raw data | `ls`, `grep`, `git status`, local-only commands |

**T-LLM prompt guidance** (injected via `ADFI_SYMBOL_SYSTEM_PROMPT` in `before_prompt_build`):
- Prefer `RESTRICTED=1` for local-only commands (`ls`, `grep`, `git status`, `find`)
- Use default exec when command needs network or would fail with symbols
- Retry pattern: if `RESTRICTED=1` fails (e.g. `jq` on symbolized JSON), retry without it — output gets symbolized as untrusted

**Inbound (tool → agent):**

| Field | Default exec | `RESTRICTED=1` |
| --- | --- | --- |
| `content[].text` | UNTRUSTED (symbolized) | TRUSTED (readable directly) |
| `details.aggregated` | UNTRUSTED | TRUSTED |
| `details.status`, `exitCode` | TRUSTED | TRUSTED |

**Outbound (agent → tool):**

| Field | Default exec | `RESTRICTED=1` |
| --- | --- | --- |
| `command` | ⚡ Resolve (unrestricted — needs raw values for network/parsing) | 🛡️ Not resolve (symbolized execution) |
| `host` | Stays as-is (resolve policy applies) | Stays `local` (trusted exec) |
| `env` | No symbols expected | `RESTRICTED: "1"` triggers trusted mode |

Default exec resolves symbols in `command` with shell-context escaping rather than raw text substitution. Standalone unquoted symbol words become POSIX single-quoted words; standalone symbols inside double or single quotes are escaped for that quote context. Mixed/partial-token placements are audited as unsupported and keep the compatibility fallback behavior.

### Policy (future work)

**CLI Policy:** Pre-define trust for known CLIs (gh, glab, gcloud) with per-CLI field schemas. Unknown → UNTRUSTED fallback.

**Network Policy:** Route exec traffic through proxy for endpoint-level trust. Auto-distinguishes local vs network.

|  | CLI Policy | Network Policy |
| --- | --- | --- |
| Coverage | Known commands only | All HTTP/HTTPS |
| curl/wget | Miss | Catch |
| Implementation | Simple (regex) | Complex (MITM proxy) |
| Local cmd auto-trust | Manual policy | Automatic |

**Endpoint-level trust policy (proxy):**
```yaml
exec:
  networkTrust:
    providers: [google, github]
    trusted: [internal.company.com/*]
    untrusted: ["*"]
    unknownPolicy: untrusted
```

Reference: [Rewrite Your CLI for AI Agents](https://justin.poehnelt.com/posts/rewrite-your-cli-for-ai-agents/)

---

# Session / Messaging Tools

## `sessions_send`

Send message to another agent session and receive reply.

**Use cases:**
- Delegate work to specialized agent, receive structured result
- Multi-agent workflow (e.g. send code to review agent, get feedback)
- Cross-session data aggregation

**Inbound (tool → agent):**

| Field        | Trust   | Notes                                                                       |
| ------------ | ------- | --------------------------------------------------------------------------- |
| `runId`      | TRUSTED | Message delivery ID                                                         |
| `status`     | TRUSTED | Delivery status (e.g. "completed")                                          |
| `sessionKey` | TRUSTED | Target session identifier                                                   |
| `delivery`   | TRUSTED | Delivery details                                                            |
| `reply`      | configurable | Baseline TRUSTED. Channel-trust policy overrides to UNTRUSTED if session matches `untrustedChannels` |

**Outbound (agent → tool):**

| Field | Resolve | Notes |
| --- | --- | --- |
| `sessionKey` | ⚡ Resolve | String identifier -- resolve if contains symbol |
| `message` | 🛡️ Not resolve | Symbolized execution -- target session operates in symbolized context |

**Policy:** Channel-trust via `aos-policy.yaml`. If `sessionKey` matches `untrustedChannels`, `reply` is UNTRUSTED and symbolized. Per-field schema in `policy/tool-inbound.ts`.

---

## `sessions_spawn`

Spawn a new sub-agent session. `mode="run"` is one-shot, `mode="session"` is persistent/thread-bound.

**Inbound (tool → agent):**

| Field | Trust | Notes |
| --- | --- | --- |
| `runId` | TRUSTED | Spawn job ID |
| `status` | TRUSTED | Spawn status |
| `note` | TRUSTED | Confirmation message |

Reply from the spawned agent arrives asynchronously via announce — not in this tool's output.

**Outbound (agent → tool):**

| Field                   | Resolve             | Notes                                                                                    |
| ----------------------- | ------------------- | ---------------------------------------------------------------------------------------- |
| `task`                  | 🛡️ Not resolve     | Spawned session has symbolized view by default — symbols preserved |
| `label`                 | 🛡️ Not resolve     | Label/name for the session                                                               |
| `runtime`               | No symbols expected | `"subagent"` or `"acp"`                                                                  |
| `agentId`               | ⚡ Resolve           | Identifier — resolve if contains symbol                                                  |
| `resumeSessionId`       | ⚡ Resolve           | UUID — resolve if contains symbol                                                        |
| `model`, `thinking`     | No symbols expected | Config overrides                                                                         |
| `cwd`                   | 🛡️ Not resolve     | Working directory — local FS                                                             |
| `runTimeoutSeconds`     | No symbols expected | Numeric config                                                                           |
| `mode`                  | No symbols expected | `"run"` or `"session"`                                                                   |
| `sandbox`               | No symbols expected | `"inherit"` or `"require"`                                                               |
| `attachments[].name`    | 🛡️ Not resolve     | Filename                                                                                 |
| `attachments[].content` | 🛡️ Not resolve     | File content — symbols preserved for spawned session                                     |

---

## `sessions_history`

Retrieve past conversation history from a session.

**Inbound (tool → agent):**

| Field | Trust | Notes |
| --- | --- | --- |
| `sessionKey` | TRUSTED | Session identifier |
| `truncated`, `droppedMessages`, `contentTruncated`, `contentRedacted` | TRUSTED | Metadata flags |
| `bytes` | TRUSTED | Response size |
| `messages[].role` | TRUSTED | System metadata (user/assistant) |
| `messages[].timestamp` | TRUSTED | System metadata |
| `messages[].content[].type` | TRUSTED | Content block type |
| `messages[].content[].text` | configurable | Baseline TRUSTED. Channel-trust policy overrides to UNTRUSTED |

**Outbound (agent → tool):**

| Field          | Resolve             | Notes                                          |
| -------------- | ------------------- | ---------------------------------------------- |
| `sessionKey`   | ⚡ Resolve           | String identifier -- resolve if contains symbol |
| `limit`        | No symbols expected | Numeric param                                  |
| `includeTools` | No symbols expected | Boolean param                                  |

**Policy:** Channel-trust via `aos-policy.yaml`. If `sessionKey` matches `untrustedChannels`, message content text is symbolized. Per-field schema in `policy/tool-inbound.ts`.

---

## `sessions_list`

List active sessions with optional filters and last messages.

**Inbound (tool → agent):**

| Field | Trust | Notes |
| --- | --- | --- |
| Session keys, status, metadata | TRUSTED | Internal orchestration state only |

**Outbound (agent → tool):**

| Field           | Resolve             | Notes                                                                |
| --------------- | ------------------- | -------------------------------------------------------------------- |
| `kinds`         | No symbols expected | Filter: `"main"`, `"group"`, `"cron"`, `"hook"`, `"node"`, `"other"` |
| `limit`         | No symbols expected | Numeric param                                                        |
| `activeMinutes` | No symbols expected | Numeric param                                                        |
| `messageLimit`  | No symbols expected | Numeric param                                                        |

---

## `subagents`

List, steer, or kill sub-agent runs.

**Inbound (tool → agent):**

| Field | Trust | Notes |
| --- | --- | --- |
| Run metadata (status, model, runId, etc.) | TRUSTED | Internal orchestration state only |

**Outbound (agent → tool):**

| Field | Resolve | Notes |
| --- | --- | --- |
| `action` | No symbols expected | `"list"`, `"kill"`, `"steer"` |
| `target` | No symbols expected | Subagent target identifier — system-generated |
| `message` | 🛡️ Not resolve | Steering message — target session has symbolized view |
| `recentMinutes` | No symbols expected | Numeric filter |

---

## `message`

Channel interaction tool (Telegram, Slack, Discord, WhatsApp, etc.). Covers both sending and reading.

**Send actions:** `send`, `sendWithEffect`, `sendAttachment`, `reply`, `thread-reply`, `broadcast`, `delete`, `react`, `poll`, `pin`, `unpin`, `sticker`, `presence`, `channel-create`, `channel-edit`, `channel-delete`, `category-create`, `category-edit`, `category-delete`, `kick`, `ban`, `timeout`, `role-add`, `role-remove`.

**Read actions:** `read` (fetch messages with pagination), `search` (query messages), `thread-list`, `list-pins`, `download-file`.

**Metadata actions (not affected by channel-trust):** `reactions`, `member-info`, `role-info`, `channel-info`, `channel-list`, `event-list`.

**Inbound (tool → agent):**

| Field | Trust | Notes |
| --- | --- | --- |
| Delivery confirmation / action result | TRUSTED | Send/delete/react/pin actions don't return external data |
| `read` message content | configurable | Baseline TRUSTED. Channel-trust policy overrides to UNTRUSTED (full wrap) |
| `search` result content | configurable | Same as `read` |
| `thread-list` message content | configurable | Same as `read` |
| `list-pins` content | configurable | Same as `read` |
| `download-file` content | configurable | Same as `read` |
| `reactions`, `member-info`, `channel-info`, metadata | TRUSTED | Platform-generated metadata, not affected by channel-trust |

**Outbound (agent → tool):**

| Field | Resolve | Notes |
| --- | --- | --- |
| `action` | No symbols expected | Action enum (see above) |
| `message` | ⚡ Resolve | Message text — outbound to channel, user sees raw values. Resolved via `message_sending` hook |
| `channel`, `target`, `targets` | ⚡ Resolve | Channel/user identifiers — resolve if contains symbol |
| `media`, `buffer` | ⚡ Resolve | Media content — outbound, needs raw data |
| `caption` | ⚡ Resolve | Media caption — outbound, user sees raw values |
| `replyTo`, `threadId`, `messageId` | ⚡ Resolve | Message identifiers — resolve if contains symbol |
| `emoji` | No symbols expected | Reaction emoji |
| `limit`, `before`, `after` | No symbols expected | Pagination/filter params |
| `silent`, `dryRun` | No symbols expected | Boolean config |
| `accountId` | No symbols expected | Account identifier |
| `buttons`, `card`, `components` | ⚡ Resolve | Interactive elements — outbound to channel, user sees raw values |

---

# Filesystem Tools

## `read`

Read local file contents.

**Inbound (tool → agent):**

| Field | Trust | Notes |
| --- | --- | --- |
| File content | TRUSTED | Agent reads the symbolized trusted worktree view |

**Outbound (agent → tool):**

| Field | Resolve | Notes |
| --- | --- | --- |
| `file_path` | 🛡️ Not resolve | Local FS — symbolized execution |

---

## `write`

Write/create local files.

**Inbound (tool → agent):**

| Field | Trust | Notes |
| --- | --- | --- |
| Write confirmation | TRUSTED | Confirmation message only |

**Outbound (agent → tool):**

| Field | Resolve | Notes |
| --- | --- | --- |
| `file_path` | 🛡️ Not resolve | Local FS — symbolized execution |
| `content` | 🛡️ Not resolve | Symbols preserved in trusted worktree; commit handler resolves raw values for human view |

---

## `edit`

Make precise edits to local files.

**Inbound (tool → agent):**

| Field | Trust | Notes |
| --- | --- | --- |
| Edit confirmation | TRUSTED | Confirmation message only |

**Outbound (agent → tool):**

| Field | Resolve | Notes |
| --- | --- | --- |
| `file_path` | 🛡️ Not resolve | Local FS — symbolized execution |
| `old_string`, `new_string` | 🛡️ Not resolve | Symbols preserved — same as `write` |

---

# Mandu Internal Tools

## `inspect_symbol`

Dual-LLM structured extraction from symbolized data.

**Inbound (tool → agent):**

| Field | Trust | Notes |
| --- | --- | --- |
| Derived symbol names | TRUSTED | Re-symbolized output. T-LLM sees only `$MDU:*` symbols, never raw values |

**Outbound (agent → tool):**

| Field | Resolve | Notes |
| --- | --- | --- |
| `symbols` | 🛡️ Not resolve | Symbol names passed to tool; resolved internally for untrusted LLM |
| `outputSchema` | No symbols expected | JSON schema definition — T-LLM provides structure |
| `prompt` | 🛡️ Not resolve | T-LLM may include symbol names in extraction instructions. If so, should be added to `symbols` list instead |

---

# Other Local Tools

## `memory_search`

Semantic search over local `MEMORY.md` / `memory/*.md`.

**Inbound (tool → agent):**

| Field | Trust | Notes |
| --- | --- | --- |
| Search results | TRUSTED | Local memory files only |

**Outbound (agent → tool):**

| Field | Resolve | Notes |
| --- | --- | --- |
| `query` | 🛡️ Not resolve | Local search — symbolized execution |

---

## `memory_get`

Read specific lines from local memory files.

**Inbound (tool → agent):**

| Field | Trust | Notes |
| --- | --- | --- |
| File content | TRUSTED | Local memory files only |

**Outbound (agent → tool):**

| Field | Resolve | Notes |
| --- | --- | --- |
| `file` | 🛡️ Not resolve | Local FS — symbolized execution |
| `line` | No symbols expected | Numeric param |

---

## `session_status`

Show current session status. Returns formatted status card with usage, time, cost, queue info, model info.

**Inbound (tool → agent):**

| Field | Trust | Notes |
| --- | --- | --- |
| `statusText` | TRUSTED | Formatted status card — usage, cost, model, queue info. System-generated metadata only |
| `sessionKey` | TRUSTED | Resolved session key |
| `ok`, `changedModel` | TRUSTED | Boolean status |

**Outbound (agent → tool):**

| Field | Resolve | Notes |
| --- | --- | --- |
| `sessionKey` | No symbols expected | Optional — session identifier (system-generated) |
| `model` | No symbols expected | Optional — set per-session model override |

---

## `canvas` — DISABLED ⛔

Mac-only tool; not applicable to current Mandu deployment. Disabled — no input/output policy enforced.

---

## `nodes` — DISABLED ⛔

Paired-device tool (iOS/Android/Mac). Low priority for Mandu. Currently all output classified as TRUSTED.

Note: when enabled, `notifications_list` output should be UNTRUSTED (contains external app notification content).

---

## `cron`

Manage local cron jobs and wake events.

**Actions:** `status`, `list`, `add`, `update`, `remove`, `run`, `runs`, `wake`.

**Inbound (tool → agent):**

| Field | Trust | Notes |
| --- | --- | --- |
| Job metadata | TRUSTED | List, confirmation, run history |

Note: the cron *tool* manages schedules — when a cron job fires, it triggers other tools which have their own trust classification.

**Outbound (agent → tool):**

| Field | Resolve | Notes |
| --- | --- | --- |
| `action` | No symbols expected | Action enum (see above) |
| `job` (add) | 🛡️ Not resolve | Job config — symbols preserved for execution time |
| `jobId` / `id` | No symbols expected | Job identifier (system-generated) |
| `patch` (update) | 🛡️ Not resolve | Job update — symbols preserved for execution time |
| `text` (wake) | 🛡️ Not resolve | Wake event text — symbols preserved |
| `mode`, `runMode` | No symbols expected | Enum config |
| `includeDisabled` | No symbols expected | Boolean filter |
| `contextMessages` | 🛡️ Not resolve | System event payloads — symbols preserved |

---

## `tts`

Convert text to speech (local output).

**Inbound (tool → agent):**

| Field | Trust | Notes |
| --- | --- | --- |
| Playback confirmation | TRUSTED | Local audio output |

**Outbound (agent → tool):**

| Field | Resolve | Notes |
| --- | --- | --- |
| `text` | ⚡ Resolve | User hears raw values — outbound to human |

---

# Network Input Entry Points

Non-tool entry points where external data enters the agent context.

OpenClaw has `InputProvenance` (`src/sessions/input-provenance.ts`) with kinds: `external_user`, `inter_session`, `internal_system`.

## Channel Messages — User Input Path

Incoming messages from Telegram, Slack, Discord, WhatsApp enter the agent as user messages. Mandu does not intercept these directly — they follow the normal agent loop. Mandu applies to the tools the LLM calls in response (e.g., `web_fetch`, `exec`).

---

## Webhooks

HTTP webhook endpoints that trigger agent actions (GitHub, CI, monitoring, etc.). Webhook provider is trusted (authenticated by token), but the data it carries may be partially untrusted (e.g., GitHub issue body is user-written, but author/labels are GitHub-generated).

Mandu uses the `transform_webhook_content` hook to apply per-field schema-based symbolization before the LLM sees the message. OpenClaw's security scaffolding (SECURITY NOTICE, EXTERNAL_UNTRUSTED_CONTENT markers) is stripped since Mandu handles taint itself.

**Source:** `plugin/adfi/index.ts` (`transform_webhook_content` hook)
**Design doc:** [webhook.md](webhook.md)

**Schema config:** `webhookSchemas` in plugin config maps `jobName` → per-field trust schema.

**Inbound (webhook → agent):**

| Field | Trust | Notes |
| --- | --- | --- |
| Configured TRUSTED fields | TRUSTED | Preserved as-is (e.g., `number`, `author`, `labels`) |
| Configured UNTRUSTED fields | UNTRUSTED | Symbolized with `$MDU:webhook[hash].field` |
| No schema for jobName | — | Webhook ignored (pass-through) |

**Hook point:** `transform_webhook_content`

**Key implementation detail:** OpenClaw calls `register()` in `[gateway]` and `[plugins]` phases. `sessionSymbols` is module-level to ensure hooks and tools share the same symbol map.

---

## Gmail PubSub — DISABLED ⛔

Google PubSub notifications for new emails.

**Status:** Disabled in Mandu. Gmail Pub/Sub hooks MUST NOT be enabled on Mandu-protected agents.

**Reason:** OpenClaw's Gmail Pub/Sub integration depends on `gog` (deprecated; see [openclaw#50026](https://github.com/openclaw/openclaw/issues/50026)). The pipeline renders email fields into flat text via `messageTemplate` before Mandu's `transform_webhook_content` hook fires, destroying field boundaries. Mandu cannot perform per-field symbolization on the rendered output, so email content would enter the agent context untagged and unsymbolized.

**What this means in practice:**
- Email content (subject, body) is fully attacker-controlled — anyone can send an email
- Without symbolization, prompt injection via crafted emails is unmitigated
- Mandu has no way to distinguish trusted metadata (sender address) from untrusted content (body)

**Future consideration:** If OpenClaw migrates to `gws` and exposes structured email payloads to `transform_webhook_content`, per-field symbolization becomes feasible.
