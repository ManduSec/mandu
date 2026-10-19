# Design docs

The design record of Mandu, for contributors and reviewers, grouped by area.
Documentation for people who use Mandu (getting started, the user guide, the
guarantees, a plain-language overview) starts at [`../README.md`](../README.md);
building and testing Mandu is in [`../development.md`](../development.md); the
rules every change follows are in [`../../CONTRIBUTING.md`](../../CONTRIBUTING.md).

**Read first:** [`architecture/mandu.md`](architecture/mandu.md) (the two
views, the four chokepoints, the invariant), then
[`architecture/architecture-map.md`](architecture/architecture-map.md) (where
each decision is made and enforced) and
[`confidentiality/confidentiality.md`](confidentiality/confidentiality.md)
(what `secrets` mode, the default, protects).

**Conventions.** Each area has a living *spine* that states the model, the
decisions and their reasons, and is kept current when behavior changes (a
change without its doc update is incomplete). A numbered *plan*
(`confidentiality-plan-N-…`) is one large implementation step with a status
banner; *decision notes* record one choice and its alternatives. When a doc is
folded into another it becomes a numbered section there, and its opening line
says which file it was. Code cites docs as `name.md §N`; file names are unique
across the areas. Figures live under the area that uses them.

## `architecture/` — the model and its principles

| Doc | What it decides |
|---|---|
| [`mandu.md`](architecture/mandu.md) | The architecture: AgentView / HumanView (repo: Agent / Human File System), the four chokepoints, the hook → chokepoint mapping, the invariant, the terminology map (§8); §9 the canonical symbol fields. |
| [`architecture-map.md`](architecture/architecture-map.md) | Decide once in the arbiter, enforce at any chokepoint: the one-grid map of the design; §9 how each chokepoint is realized per layer and OS, with status. |
| [`implementation-plan.md`](architecture/implementation-plan.md) | The build decisions the prototype followed; §9 the end-to-end oracle every ingress and egress path is tested against. |
| [`privilege-model.md`](architecture/privilege-model.md) | How much OS privilege Mandu needs: the invariant at zero privilege, every unprivileged hardening on by default, no host root (§0); §6 the parked microVM tier. |
| [`protection-modes.md`](architecture/protection-modes.md) | The one knob over the two axes: `secrets` (default), `off`, and the frozen `injection` / `full`; §10 the integrity freeze (what is frozen, the opt-in, the canaries). |
| [`arbiter-human-plane.md`](architecture/arbiter-human-plane.md) | A third arbiter channel for the operations that return originals, walled off from the agent's world. |
| [`write-protection.md`](architecture/write-protection.md) | What the agent's process tree may not change (Mandu's files; files that run later, held for the human); §8 hardening Mandu's own git against repositories the agent can write. |
| [`runtime-instances.md`](architecture/runtime-instances.md) | Per-deployment identity of the stack, instances, tenants and autostart; §14 launch time and load-aware readiness deadlines. |
| [`on-disk-layout.md`](architecture/on-disk-layout.md) | One Mandu home (`~/.mandu`, `MANDU_HOME`), one generated path table, and what the agent may not read or write there. |

## `confidentiality/` — secrets (the shipping axis)

| Doc | What it decides |
|---|---|
| [`confidentiality.md`](confidentiality/confidentiality.md) | The spine: the label model and levels (`no-model`, `any-model`, `local-model`), the session watermark (§4), enforcement per chokepoint, secret twins, claim scoping (§10). |
| [`confidentiality-plan-10-flow-taint.md`](confidentiality/confidentiality-plan-10-flow-taint.md) | Flow-based confinement: raw secrets for the programs that need them, taint on what they emit, readers and bindings. |
| [`confidentiality-plan-13-reader-set-labels.md`](confidentiality/confidentiality-plan-13-reader-set-labels.md) | Reader-set labels: one check for every flow, where the OS approximation breaks and how each gap was closed; §10 which clients the wire release serves (TLS compatibility). |
| [`confidentiality-plan-14-policy-suggestions.md`](confidentiality/confidentiality-plan-14-policy-suggestions.md) | The policy generator: scans that propose rules for the human to approve. |
| [`confidentiality-plan-15-prompt-filter.md`](confidentiality/confidentiality-plan-15-prompt-filter.md) | The prompt filter: pluggable detectors over what the human types to the agent. |
| [`confidentiality-plan-16-document-twins-writeback.md`](confidentiality/confidentiality-plan-16-document-twins-writeback.md) | Proposal (2026-10-16): per-cell twins of labelled data files (CSV, JSON, YAML, text), writing the values the model routed into a file back to disk, and values escaped for their place on the wire. |
| [`backstop-value-only.md`](confidentiality/backstop-value-only.md) | Built (2026-10-17), decision note on plan 10 §2.2: when the value backstop finds a registered value in a result whose call read no secret, only the value becomes its symbol (verified by a residue scan for encoded and partial copies); every doubt masks the whole result. |
| [`clean-tree-release.md`](confidentiality/clean-tree-release.md) | Built (2026-10-18), decision note on the path-derived mask (spine §7.1): a shell result whose command names a registered credential file without printing it (`git rm --cached .env`), from a recorded tree that read no secret, is released as printed, each registered value its symbol, after a counterfactual reading of its paths and content checks; every doubt keeps the whole mask. |
| [`exclusion-flags.md`](confidentiality/exclusion-flags.md) | Built (2026-10-18), decision note on the path-derived mask (spine §7.1): the word `--exclude-dir=NAME` of one plain `grep` is not read as a path (no grep opens it), so a search that keeps out of a labelled folder is read as the same search without the flag. |
| [`folder-listing-compound.md`](confidentiality/folder-listing-compound.md) | Built (2026-10-18), decision note on plan 10 §11.8 "A folder's names": a plain `ls` of a labelled folder at either end of a compound (`tools/mail list; ls mail/inbox bank`) is released with the other parts' output, when those parts are allow-listed programs that name no secret path (a counterfactual with the `ls` taken out), the guard saw that `ls` run, and the output's first or last lines are exactly the names. |
| [`egress-hold.md`](confidentiality/egress-hold.md) | Built (2026-10-17), detail of the spine's §4: a request waiting on an unanswered card is held at the egress proxy (`MANDU_EGRESS_HOLD_MS`: the launcher holds 60 s in an interactive session, 0 for headless, one-shot and CI runs) and the human's answer, Send without it included, decides that request; fail-closed on the deadline, the arbiter gone and the client gone. |
| [`guard-file-identity.md`](confidentiality/guard-file-identity.md) | Built (2026-10-16), detail of the spine's §7.2a: how the guard keeps knowing a file through a history rewrite (reused inode numbers, the orphan pack index) and a folder moved above a protected file (held by its inode this session, its label following it to the next). |
| [`model-endpoints.md`](confidentiality/model-endpoints.md) | Which models may read a `local-model` file: declared endpoints (Part 1) and perimeter endpoints over the network (Part 2). |
| [`secret-discovery.md`](confidentiality/secret-discovery.md) | Finding secrets: the launch walk over a real home, the catalog's measured recall, keys in git history. |
| [`rootless-confinement-ubuntu-2404.md`](confidentiality/rootless-confinement-ubuntu-2404.md) | Confinement on a stock Ubuntu without root, and the postures (`confined`, `read-blocked`, `gated`). |
| [`comparisons.md`](confidentiality/comparisons.md) | How Mandu compares: nono, Claude Code's own credential mask (a measured head-to-head), and what Mandu took from them. |

Figures: [`flow-confidentiality.html`](confidentiality/figures/flow-confidentiality.html),
[`reader-set-labels.html`](confidentiality/figures/reader-set-labels.html),
[`policy-lattice.html`](confidentiality/figures/policy-lattice.html) (the lattice and rules for a reader new to them, end-user setup and use cases, an assessment of the reader-set model).

## `agents/` — the agents and the model path

| Doc | What it decides |
|---|---|
| [`supported-agents.md`](agents/supported-agents.md) | The tested agent versions and the policy outside them; §5 which agents Mandu can defend and the defendability test; §6 the Codex wire (script cells, tool-call arrays). |
| [`agent-sign-in.md`](agents/agent-sign-in.md) | Using the agent's own login through Mandu: Claude subscription sign-in (§1), Codex ChatGPT sign-in (§2), an agent's own key file put back in the auth header at the model proxy (§3). |
| [`agent-sdks.md`](agents/agent-sdks.md) | Programs built on the Claude Agent SDK or the Codex SDK: how each SDK starts its CLI, the SDK route that keeps the routing on every child (a Node preload), the bypasses examined. |
| [`devtools-relay.md`](agents/devtools-relay.md) | Browser agents: a relay on the DevTools connection between the agent and Chrome. Page text reaches the agent with secrets as placeholders; a placeholder it types is put back only for a page whose origin is bound to it; pixels refused. Step 1 built, not yet in `mandu`. |
| [`handling-prompt.md`](agents/handling-prompt.md) | The capability-gated system prompt that teaches the model how to handle symbols. |

## `ui/` — what the human sees

| Doc | What it decides |
|---|---|
| [`dashboard.md`](ui/dashboard.md) | The dashboard: the product page at `/` and the developer view at `/dev/` (one nav of six pages, §4.32; the Sessions page, §4.33), the server projections, session batches (§4.10.1), server security (§6). |
| [`policy-surface.md`](ui/policy-surface.md) | One law (`policy.yaml`), its editors (CLI, dashboard, the agent's policy tools, §8), and how it is shown (`mandu why`, §9). |
| [`reply-row-reservation.md`](ui/reply-row-reservation.md) | The reply filter on a live terminal: multi-line secrets under a TUI; §15 structured (`json` / `stream-json`) output, §15.4 Goose's ACP stream; §18 a resolver that refuses (the S8 miss). |
| [`symbol-lineage.md`](ui/symbol-lineage.md) | The provenance view: where a symbol came from and where it went. |
| [`siem-integration.md`](ui/siem-integration.md) | The public seam for a SIEM: the event feed, the redaction rule, the lockdown. |

## `distribution/` — getting Mandu onto a machine

| Doc | What it decides |
|---|---|
| [`packaging.md`](distribution/packaging.md) | The published package, native bins (§5), platforms; §11 versioning and release. |
| [`portable-wrapper.md`](distribution/portable-wrapper.md) | The `mandu` launcher CLI and its backends; §10 the cross-platform plan (macOS code-complete, Windows not built). |
| [`licensing.md`](distribution/licensing.md) | Apache-2.0 (2026-10-09, replacing AGPL-3.0-or-later), the open-core line (§6). |
| [`mandu-demo.md`](distribution/mandu-demo.md) | `mandu demo`: an offline, keyless demonstration. |

The terminal relay is described in [`pty-relay.md`](agents/pty-relay.md):
util-linux on Linux, BSD with a resize/signal companion on macOS.

## `testing/` — tests, CI and evaluation

| Doc | What it decides |
|---|---|
| [`test-organization.md`](testing/test-organization.md) | Test kinds, the one suite manifest (`tests/suites.mjs`), and stated axes. |
| [`continuous-integration.md`](testing/continuous-integration.md) | One disposable KVM guest per run (`scripts/ci/vm-run.sh`), the nightly, the public GitHub CI (§12), test credentials (§13). |
| [`os-test-matrix.md`](testing/os-test-matrix.md) | The multi-OS matrix and the fresh-install suites (§10). |
| [`docker-e2e.md`](testing/docker-e2e.md) | The Docker test wrapper (`Dockerfile.ci`, `docker-run.sh`); §2 the maintainers' e2e rig, not published. |
| [`agent-e2e-harness.md`](testing/agent-e2e-harness.md) | The multi-agent live harness (OpenClaw, OpenCode). |
| [`evaluation.md`](testing/evaluation.md) | The evaluation harnesses (AgentDojo, the paired benign eval, the twelve-task utility suite) and the results so far. |

The test pages for people running them are under [`../testing/`](../testing/running-tests.md).

## `integrity/` — the frozen integrity axis

**Frozen since 2026-09-28** ([`protection-modes.md`](architecture/protection-modes.md) §10).
These docs record the injection defense (untrusted data reaches the privileged
model, paper **T-LLM**, only as a symbol). They are kept and not extended; each
says which of its parts still run in `secrets` mode.

| Doc | What it decides |
|---|---|
| [`exec-routing.md`](integrity/exec-routing.md) | Classify commands at the proxy, enforce at the exec boundary: AgentShell vs HumanShell, the exec box, net-guard; §8 the trust of command output. |
| [`fs-sync.md`](integrity/fs-sync.md) | The portable filesystem core (§1), sync cadence (§2), and the shadow repository behind `mandu revert` (§3). |
| [`fs-provenance.md`](integrity/fs-provenance.md) | Filesystem taint tracking and dropping network-ingress symbolization; §10 file-symbol provenance. |
| [`symbol-quality.md`](integrity/symbol-quality.md) | Symbol quality and the quarantined U-LLM (`inspect_symbol`): multi-input inspection (§7), the transparent U-LLM design (§8). |
| [`symbol-twin-shell-blindness.md`](integrity/symbol-twin-shell-blindness.md) | A trusted per-call note when a shell command reads whole-file symbol twins. |
| [`read-result-rendering.md`](integrity/read-result-rendering.md) | What a Read symbol stands for, and the two shapes that pass raw. |

## Reference

- [`../adfi-reference/`](../adfi-reference/README.md): the original DualView
  (adfi-openclaw) design, kept for provenance; its vocabulary in
  `terminology.md`.
- [`../formal/`](../formal/README.md): working drafts of the formal statement
  of the guarantees.
- The paper: DualView, [arXiv:2607.03821](https://arxiv.org/abs/2607.03821).
