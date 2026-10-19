# Mandu security guarantees: proposed contracts

> **Working draft (2026-09), not authoritative.** A modeling proposal: no
> formal proof has been done. It was written before the protection modes and
> the integrity freeze (2026-09-21, 2026-09-28): today the default mode is
> `secrets` (confidentiality on, integrity off) and the integrity axis is
> frozen ([`protection-modes.md`](../design/architecture/protection-modes.md),
> [`protection-modes.md §10`](../design/architecture/protection-modes.md)). Where
> this draft and the design docs or the code disagree, they win.

These are the security contracts to specify and verify, not a claim that the
implementation has been formally proved. “Mechanism present” means the reviewed
code contains enforcement for covered paths; it does not certify complete
coverage, classifier correctness, or resistance to all races and bypasses.
“Target” identifies a stronger property whose realization needs further work.

All contracts assume the relevant axis is enabled, protected data is correctly
identified, and the particular channels are mediated by the active deployment.
(When this draft was written integrity was on by default and
confidentiality opt-in; see the note at the top.) The user, policy
administration, runtime interface behavior, and enforcement TCB follow the
assumptions in [formal-situation.md](formal-situation.md). An absent secret label
is not automatically a no-model label. Permitted human access, explicit
release, and authorized relabeling are part of the policy, not violations.

## Confidentiality: who may learn protected information

- **C1 — Exclude strict secrets from models.** Content labeled `no-model`
  must not enter either T-LLM or U-LLM through protected model-input paths.
  Models can handle its opaque reference. A release approval alone must not
  override the model-read prohibition; changing the label is a separate act.
  **Status:** mechanism present in model admission and quarantine/declassification
  gates; end-to-end coverage remains a verification obligation.

- **C2 — Control model access to model-readable secrets.** A
  `any-model` label permits controlled reads, not automatic plaintext
  admission. Quarantined processing returns a symbolized answer. A permitted
  T-LLM read must pass the integrity check, applicable approval check, and
  session-watermark update. Provider access to such permitted content is part
  of the authorized disclosure.
  **Status:** mechanism present.

- **C3 — Restrict external release.** Confidential data may be released only
  under an applicable destination binding or an explicit, scoped release
  authorization. A URL's integrity trust alone must not authorize receiving a
  secret. Untrusted-influenced flows can require approval even at a bound sink.
  The user's own HumanView and human-facing replies are permitted sinks under
  the current ownership model; this is not a promise to encrypt those files.
  **Status:** per-symbol and session gates present on covered release paths.

- **C4 — Confine sessions after secret exposure.** After an allowed secret
  read into T-LLM, subsequent mediated network and network-enabled shell outputs
  must pass session-level restrictions, including outputs with no symbol token.
  Summaries, paraphrases, or encodings must not evade the check merely by changing
  the bytes. The watermark must not silently fall during that context's lifetime.
  **Status:** watermark and session-egress mechanisms present. This establishes
  a policy-relative gate, not a proof that every authorized session destination
  is appropriate for every secret the session has seen; mixed-source destination
  composition needs its own proof obligation.

- **C5 — Preserve confidentiality through derivation and storage.** Tracked
  summaries, derived symbols, and files written by a secret-bearing session
  must retain the confidentiality restrictions needed by their sources.
  Ending a session and reading a derived artifact in another session must not
  make it public. Deriving an artifact must not invent new release permissions.
  **Status:** source-label inheritance and persistent derived-file labels are
  present; completeness across arbitrary copies, transformations, aliases, and
  unmediated writers is a target.

- **C6 — Require authority to weaken confidentiality.** Changing a token's
  spelling, omitting label metadata, or writing a derived value must not silently
  lower an established confidentiality restriction. Decisions must use
  authoritative policy/store records. Authorized relabeling and release must be
  explicit, scoped acts rather than incidental consequences of processing.
  **Status:** authoritative symbol labels, conservative label joins, and
  explicit user-label overrides are present; universal preservation is a target.

- **C7 — Fail closed at mandatory confidentiality gates.** If a required
  policy, label, or authorization check cannot complete, the protected operation
  must not expose the raw secret. Denial or leaving an opaque reference is safe.
  **Status:** contract of the mandatory gates; supplementary fingerprint scans
  and observability are not themselves universal fail-closed enforcement.

## Integrity: what may acquire authority over privileged behavior

- **I1 — Keep untrusted payloads out of privileged context.** Content that
  remains integrity-untrusted must reach T-LLM as an opaque symbol. Every raw
  external span admitted to T-LLM needs a valid trust-policy justification.
  **Status:** classification and proxy symbolization mechanisms present. This
  is policy-relative; attacker-controlled and policy-untrusted are not synonyms.

- **I2 — Contain quarantined processing.** U-LLM's free-text results must be
  re-symbolized before returning to T-LLM. Processing attacker-controlled data
  must not grant U-LLM the privileged agent's tool authority. Structured feedback
  may cross only through the explicitly admitted interface.
  **Status:** output symbolization is present; tool isolation is a per-backend
  verification target. The reviewed Codex CLI branch invokes `codex exec` without
  an explicit tool-disable setting, so a universal “U has no tools” guarantee is
  not established by that code.

- **I3 — Preserve protection against stored prompt injection.** Storing,
  synchronizing, transforming, and rereading untrusted content must not silently
  make it trusted. The property must extend across sessions for tracked data.
  **Status:** persistent symbols, dual views, and conservative reread admission
  are present; complete lineage preservation through every transformation and
  filesystem operation is a target. HumanView location alone does not prove
  human authorship.

- **I4 — Control use of untrusted data as executable instructions.** Resolving
  an untrusted symbol into command/code position must pass the applicable usage
  policy and required human approval; a request to process data is not automatic
  permission to execute it.
  **Status:** command-position and argv gates present on covered execution
  paths; this does not imply complete mediation of arbitrary native programs.

- **I5 — Keep trust endorsement explicit.** A tool returning content, a model
  summarizing it, or a human authorizing its release must not by itself promote
  that content to integrity-trusted. Such promotion requires an explicit
  applicable trust rule or authorized endorsement. Confidentiality permission
  must not override the integrity restriction on raw model admission.
  **Status:** separate axes and refusal of untrusted in-context declassification
  are present; trust-grant soundness and author attribution need verification.

- **I6 — Fail closed at mandatory integrity gates.** Missing or unknown trust
  classifications must not become implicit TRUSTED grants. Failure of a required
  classification or symbolization step must not fall back to sending the raw
  untrusted payload. A tool error that echoes untrusted content is still input
  requiring protection.
  **Status:** conservative classification and symbolization paths present;
  coverage is conditional on the active adapter and enforcement route.

- **I7 — Limit attacker influence to declared channels.** Beyond preventing
  raw payload admission, changing attacker-controlled content should not change
  privileged observations except through the explicitly admitted observation
  surface L or an authorized endorsement. A corresponding action-level claim
  also needs assumptions about model state, randomness, and scheduling.
  **Status:** stronger verification target, not a current theorem. Trusted
  filename results, content_kind/next_step feedback, token identity/equality,
  and exact-context-echo selection must be modeled. Some admitted channels
  contain arbitrary text; calling them metadata does not make them harmless.

## How the axes compose

A datum can be both untrusted and confidential. For an operation that crosses
both boundaries, both applicable policies must permit it. A trusted datum can
still be secret, and a public datum can still be untrusted. A human approval for
one use must not be interpreted as a universal bypass of either axis.

Correct task completion, factual summary accuracy, availability, immediate
equality of the two views, zero metadata/timing leakage, and protection against
all hostile native applications are not established by these contracts.

## Implementation anchors

- [Inbound and usage policy](../../arbiter/policy/policy-interface.ts),
  [adapter trust exceptions](../../arbiter/policy/claude-code-inbound.ts).
- [Quarantined inspection](../../interceptors/inspect-mcp/src/inspect-symbol.ts),
  [model transports](../../interceptors/inspect-mcp/src/ullm-client.ts).
- [In-context read decisions](../../arbiter/policy/declassify.ts),
  [session labels](../../arbiter/policy/session-labels.ts),
  [session egress](../../arbiter/policy/session-egress.ts).
- [Derived-file labels](../../arbiter/policy/derived-labels.ts),
  [label interpretation](../../arbiter/symbol-table/confidentiality.ts),
  [arbiter operations](../../arbiter/ipc/server.ts).
- [Confidentiality design](../design/confidentiality/confidentiality.md),
  [deployment boundaries](../design/architecture/privilege-model.md),
  [view synchronization](../design/integrity/fs-sync.md).
