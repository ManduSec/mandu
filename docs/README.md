# Mandu documentation

Pick the path that matches what you want to do.

## Use Mandu

| Page | Read it when |
|---|---|
| [Getting started](getting-started.md) | You are new. Install, check your machine, see a secret masked, run your agent, use the dashboard. About ten minutes. |
| [Your first session](first-session.md) | Mandu is installed and you want a guided tour: four requests to your agent (Claude Code, Codex, OpenClaw or OpenCode), and what each one shows on your screen and on the dashboard. About fifteen minutes. |
| [User guide](usage.md) | You want a command, a flag, a setting, the `policy.yaml` format, or help with an error. |
| [GitHub Actions](github-action.md) | You run Claude Code or Codex in a workflow and want the job's secrets kept from the model, with a summary of what was kept and what was blocked. |
| [What Mandu guarantees](guarantees.md) | You need to know exactly what is protected in each mode, what is not, and how to check it on your machine. |
| [How Mandu works](how-it-works.md) | You want to understand what happens behind the scenes, or you are reviewing Mandu before a rollout. |
| [Supported agents](design/agents/supported-agents.md) | You want the tested agent versions and what happens outside them. |
| [Changelog](../CHANGELOG.md) | You want to know what changed between versions. |

## Evaluate Mandu

| Page | What it covers |
|---|---|
| [Threat model and guarantees](guarantees.md#4-the-threat-model-in-three-sentences) | The attacker Mandu is built against, in three sentences. |
| [Formal model (draft)](formal/README.md) | Working drafts of a formal statement of the invariant; not authoritative, the design docs and the code are. |
| [Mandu and other secret protections, measured](design/confidentiality/comparisons.md#5-mandu-and-other-protections-measured) | Mandu against Claude Code's credential mask and deny rules, NVIDIA OpenShell, nono, two third-party redactors and no protection, live on 15 everyday tasks (ten settings, 450 sessions, one agent and model): secret kept and task done in 41 of 45 sessions on a fresh install and 43 of 44 with a rule for each task, the next best 27 of 45; the head-to-head over the tasks both sides can win, and the caveats, beside it. |
| [Mandu and nono](design/confidentiality/comparisons.md) | How Mandu relates to another agent sandbox. |
| [Evaluation](design/testing/evaluation.md) | The AgentDojo benchmark setup for the injection modes (frozen and experimental, see [protection-modes.md §10](design/architecture/protection-modes.md)). |
| [Security policy](../SECURITY.md) | How to report a vulnerability. |

## Contribute to Mandu

| Page | What it covers |
|---|---|
| [Developing Mandu](development.md) | Build from source, the packages, running the stack, the tests. |
| [`CONTRIBUTING.md`](../CONTRIBUTING.md) | The license terms, what a pull request must include, and the rules every change follows. |
| [Design index](design/README.md) | Every design document by area, with its status. Start with [`design/architecture/mandu.md`](design/architecture/mandu.md). |
| [Running the tests](testing/running-tests.md) | How to run the suites: on your machine, in the CI guest, one agent. |
| [Test suites](testing/suites.md) | Every test suite by kind, generated from the suite manifest `tests/suites.mjs`. |
| [End-to-end test catalog](testing/e2e-catalog.md) | What each end-to-end test does and asserts. |
| [Drill results](testing/drill-results.md) | What the maintainers' agent drills show at the last release, property by property. The drills are not published; ask at hello@mandusecurity.com. |
| [Manual testing](testing/manual-testing.md) | A hand-run test plan for Claude Code and Codex: the policy setup, utility stories, and hostile prompts that show the secrets stay protected. |

## Research background

Mandu implements DualView ([arXiv:2607.03821](https://arxiv.org/abs/2607.03821)),
which follows Prompt Flow Integrity ([arXiv:2503.15547](https://arxiv.org/abs/2503.15547)),
a defense that isolates the agent from untrusted data and guards against
privilege escalation in LLM agents. The design of the original DualView, an OpenClaw plugin, is kept in
[`adfi-reference/`](adfi-reference/README.md) for provenance; its vocabulary is in
[`adfi-reference/terminology.md`](adfi-reference/terminology.md), and the
mapping to plain terms is at the end of [How Mandu works](how-it-works.md#words-you-will-meet).

If you use Mandu in research, please cite both papers:

```bibtex
@misc{dualview2026,
  title         = {DualView: Preventing Indirect Prompt Injection in Personal AI Agents},
  author        = {Kim, Juhee and Choi, Woohyuk and Kang, Taehyun and Kim, Youngmin and Lee, Byoungyoung},
  year          = {2026},
  eprint        = {2607.03821},
  archivePrefix = {arXiv},
  primaryClass  = {cs.CR},
  url           = {https://arxiv.org/abs/2607.03821}
}

@misc{pfi2025,
  title         = {Prompt Flow Integrity to Prevent Privilege Escalation in LLM Agents},
  author        = {Kim, Juhee and Choi, Woohyuk and Lee, Byoungyoung},
  year          = {2025},
  eprint        = {2503.15547},
  archivePrefix = {arXiv},
  primaryClass  = {cs.CR},
  url           = {https://arxiv.org/abs/2503.15547}
}
```

## How these docs are organized

- `docs/*.md`: for people who use Mandu. Written in plain language and kept
  in step with the released behavior.
- `docs/design/`: the design record, for contributors and reviewers. Each
  area has a living *spine* document, numbered *plans* for its implementation
  steps, and *decision notes*; the conventions are at the top of the
  [design index](design/README.md).
- `docs/testing/`: how the test suites work, the manual test plan, and the
  drill results.
- `docs/formal/`, `docs/adfi-reference/`: working drafts of a formal model,
  and the original DualView design kept for provenance.
