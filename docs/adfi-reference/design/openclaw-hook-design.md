```
User                  LLM                       OpenClaw (gateway)                Tool
  |                    |                              |                              |
  |  "Fetch quotes     |                              |                              |
  |   .toscrape.com    |                              |                              |
  |   and show me      |                              |                              |
  |   the first quote" |                              |                              |
  +------------------->+----------------------------->+                              |
  |                    |                              |                              |
  |                    |    deliver user message      |                              |
  |                    +<-----------------------------+                              |
  |                    |                              |                              |
  |                    |  tool_call:                  |                              |
  |                    |  web_fetch                   |                              |
  |                    |  {url:"https://..."}         |                              |
  |                    +----------------------------->+                              |
  |                    |                              |                              |
  |                    |               +--------------v--------------+               |
  |                    |               | HOOK: before_tool_call      |               |
  |                    |               | read:  tool name, params    |               |
  |                    |               | write: modify params,       |               |
  |                    |               |        block execution,     |               |
  |                    |               |        inject result        |               |
  |                    |               +--------------+--------------+               |
  |                    |                              |                              |
  |                    |                              | execute (modified) params    |
  |                    |                              +----------------------------->+
  |                    |                              |                              |
  |                    |                              |        raw result            |
  |                    |                              |  {title:"Quotes to Scrape",  |
  |                    |                              |   text:"The world as...",    |
  |                    |                              |   url:"https://...",         |
  |                    |                              |   status:200}                |
  |                    |                              +<----------------------------+
  |                    |                              |                              |
  |                    |               +--------------v-----------------+            |
  |                    |               | HOOK: tool_result |            |
  |                    |               | read:  tool name, raw result   |            |
  |                    |               | write: replace result before   |            |
  |                    |               |        LLM sees it (this turn) |            |
  |                    |               +--------------+-----------------+            |
  |                    |                              |                              |
  |                    |    (modified) result         |                              |
  |                    +<-----------------------------+                              |
  |                    |                              |                              |
  |                    |               +--------------v--------------+               |
  |                    |               | HOOK: after_tool_call       |               |
  |                    |               | read:  tool name, result    |               |
  |                    |               | write: none (observe only)  |               |
  |                    |               +--------------+--------------+               |
  |                    |                              |                              |
  |                    |               +--------------v-----------------+            |
  |                    |               | HOOK: tool_result_persist      |            |
  |                    |               | read:  tool name, result msg   |            |
  |                    |               | write: replace what gets       |            |
  |                    |               |        written to transcript   |            |
  |                    |               |        (future turns)          |            |
  |                    |               +--------------+-----------------+            |
  |                    |                              |                              |
  |                    |                              v                              |
  |                    |                [session.jsonl transcript]                   |
  |                    |                              |                              |
  |                    |                              |                              |
  |                    |  reply text:                 |                              |
  |                    |  "The first quote is: ..."   |                              |
  |                    +----------------------------->+                              |
  |                    |                              |                              |
  |                    |               +--------------v--------------+               |
  |                    |               | HOOK: message_sending       |               |
  |                    |               | read:  outbound text, dest  |               |
  |                    |               | write: modify text,         |               |
  |                    |               |        cancel delivery      |               |
  |                    |               +--------------+--------------+               |
  |                    |                              |                              |
  |  (modified) reply  |                              |                              |
  |  to target channel |                              |                              |
  +<-------------------+<-----------------------------+                              |
  |                    |                              |                              |
```

## Hook Summary

| Hook                         | Read                                       | Write                                              | Execution                 | Gate                           |
|------------------------------|--------------------------------------------|----------------------------------------------------|---------------------------|--------------------------------|
| `before_tool_call`           | tool name, params                          | modify params, block execution, inject result      | sequential, async         | `allowResultModification`      |
| `tool_result`   | tool name, tool call ID, params, result    | replace result (what LLM sees this turn)           | sequential, async         | `allowResultModification`      |
| `after_tool_call`            | tool name, params, result                  | none (observe only)                                | parallel, fire-and-forget | --                             |
| `tool_result_persist`        | tool name, tool call ID, result message    | replace what gets written to transcript             | **synchronous**, hot path | --                             |
| `message_sending`            | outbound text, destination, metadata       | modify text, cancel delivery                       | sequential, async         | --                             |

### Gate: `allowResultModification`

Added in [cc182a45d](https://github.com/openclaw/openclaw/commit/cc182a45d) (`feat/result-modifying-hooks`).

`before_tool_call` and `tool_result` can return modified results,
but the write is **blocked unless `plugins.allowResultModification` is enabled**
in the gateway config. Without it, the hook can still read all fields but any
result replacement is silently dropped with a `[security]` warning in logs.

This gate exists because result modification changes what the LLM sees --
a malicious or buggy plugin could inject arbitrary content into the agent's
reasoning context.

### Commit history

- **cc182a45d** `feat/result-modifying-hooks`: Added `tool_result` hook
  and `result` injection support in `before_tool_call`. Both gated behind
  `allowResultModification`. This is what Mandu uses for same-turn taint labeling
  and symbolization.

- **e94ed84e7** `feat(plugins): add outbound message hook for Slack replies`: Added
  `message_sending` hook dispatch via `runOutboundMessageHook()` utility. Plugins
  can read outbound text and destination, and write modified text or cancel delivery.
  This is what Mandu uses for symbol resolution in user-facing replies.
