# DualView reference design (upstream copy)

These are the design documents of the original DualView implementation
([compsec-snu/dualview](https://github.com/compsec-snu/dualview), an OpenClaw
plugin, internally called adfi-openclaw), copied here for provenance: Mandu
carries forward its symbol table, policy engine and two-view workspace, and
these files record the design it started from. They are kept as written
upstream, so they describe the plugin, not Mandu, and their relative links
point at the upstream repository's layout and may not resolve here.

The upstream vocabulary is in [`terminology.md`](terminology.md). How it maps
to the paper's terms and to Mandu's is the terminology table at the end of
[`mandu.md`](../design/architecture/mandu.md#8-terminology-cross-reference);
the plain-language terms are in
[How Mandu works](../how-it-works.md#words-you-will-meet).

| File | What it covers |
|---|---|
| [`architecture.md`](architecture.md) | The plugin's architecture and execution flow |
| [`design-doc.md`](design-doc.md) | The original design document |
| [`terminology.md`](terminology.md) | The repo vocabulary |
| [`design/openclaw-hook-design.md`](design/openclaw-hook-design.md) | The OpenClaw hook lifecycle Mandu replaces with OS-level chokepoints |
| [`design/fs-level-tracking.md`](design/fs-level-tracking.md) | The git-worktree view sync |
| [`design/human-edit-policy.md`](design/human-edit-policy.md) | How human edits re-enter the two views |
| [`design/revert.md`](design/revert.md) | Reverting the agent's changes |
| [`design/on-demand-tracking.md`](design/on-demand-tracking.md) | On-demand tracking |
| [`design/inbound-outbound-spec.md`](design/inbound-outbound-spec.md) | The data-trust and data-usage policies |
| [`design/symbol.md`](design/symbol.md) | The symbol format |
| [`design/exec-with-symbols.md`](design/exec-with-symbols.md) | AgentShell and HumanShell |
| [`design/untrusted-command-execution-patterns.md`](design/untrusted-command-execution-patterns.md) | Patterns for commands built from untrusted data |
| [`design/gws-exec-classification.md`](design/gws-exec-classification.md) | Exec classification for the Google Workspace CLI |
| [`design/webhook.md`](design/webhook.md) | Webhooks |
