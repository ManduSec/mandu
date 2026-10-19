# @mandusec/policy-mcp

The confined agent's side of the policy agent surface
([docs/design/ui/policy-surface.md §8](../../docs/design/ui/policy-surface.md) §5.1):
an MCP stdio server, `mandu-policy`, with three tools.

| Tool | What it does |
|---|---|
| `mandu_policy_read` | The law as structured data (the arbiter's `policyExplain`, agent projection), including the declared models, read-only (the key's variable name, never its value). |
| `mandu_policy_test` | Would data from a source reach the model masked, and could it go to a destination (allow / ask / block)? Nothing recorded. |
| `mandu_policy_propose` | Typed edits (the arbiter's `PolicyEdit` grammar, schema embedded in the tool description). A tightening applies at once; anything that loosens protection is a proposal the user approves on the dashboard's Approvals page. A relative path in a `lock-path` / `unlock-path` edit is read in the project directory (`MANDU_PROJECT_DIR`) and stated back under `resolved`; one that leaves the project, and a lock on a path that does not exist (`/.env` for the project's `.env`), are refused with a problem that says what to write. The model-endpoint ops (`add-model` / `update-model` / `remove-model`) are not in the schema and the arbiter refuses them from this server: models change only in Settings › Models or policy.yaml (policy-surface.md §8.4.3a). |

Every successful result is one text item holding a token-only JSON envelope
(`src/envelope.ts`). The arbiter trusts it only under the Mandu tool names and
only in that shape (`arbiter/policy/policy-tool.ts`); errors are masked like any
other MCP result. The server is a data-socket client: it cannot approve or undo
anything.

The launcher mounts it beside `mandu-inspect` for Claude Code (in the
`--mcp-config` file; all three tools are pre-allowed (the arbiter gates propose), keeps
Claude Code's prompt), OpenCode, and Codex. Codex (0.154) has no MCP config
flag, so the launcher passes both servers as `-c mcp_servers.<name>.*`
overrides and pre-approves the same tools (`tools.<tool>.approval_mode =
"approve"`); a headless `codex exec` otherwise refuses every MCP call. Codex
defers MCP tools behind its `tool_search` tool and calls one as
`{name, namespace: "mcp__mandu_policy"}`; the openai-proxy names it
`mcp__mandu_policy__<tool>` for the arbiter, and splits Codex's
`Wall time: N seconds\nOutput:` header off the result so the envelope is
judged on its own bytes. `--no-policy-mcp` / `MANDU_POLICY_MCP=0` opt out;
`--no-mcp` drops both servers.

```sh
npm install && npm run typecheck && npm test
```
