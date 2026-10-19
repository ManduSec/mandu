# Mandu: proposed formal operating situation

> **Working draft (2026-09), not authoritative.** A modeling proposal: no
> formal proof has been done. It was written before the protection modes and
> the integrity freeze (2026-09-21, 2026-09-28): today the default mode is
> `secrets` (confidentiality on, integrity off) and the integrity axis is
> frozen ([`protection-modes.md`](../design/architecture/protection-modes.md),
> [`protection-modes.md §10`](../design/architecture/protection-modes.md)). Where
> this draft and the design docs or the code disagree, they win.

This document separates the concrete system to model from the properties we
would like to prove about it.

**Notation reference.** These letters name parts of the proposed mathematical
model; they are not necessarily identifiers in the source code. Use `sigma` (σ)
for one opaque symbol and `s_t` for a whole system state. Use `r_t` for runtime state to distinguish
it from the runtime participant R. A subscript t means “at step t,” not wall time.

| Participant | Meaning | Concrete example |
|---|---|---|
| H | Trusted human/user | Person requesting a report summary |
| R | Agent runtime | Claude Code dispatching a tool call |
| T | Privileged model (T-LLM) | Model choosing to fetch or save a report |
| U | Quarantined model (U-LLM) | Isolated call summarizing the report |
| X | Tools and processes | File reader, shell process, HTTP client |
| M | Mandu enforcement monitor | Arbiter and enabled interceptors |
| E | Persistent external environment | Files, websites, messages, services |
| A | Adversary | Party controlling a report's content |

| Task/data notation | Meaning | Example / reading |
|---|---|---|
| τ = (q, Auth, Goal) | Task, including authority and success criteria | Summarize and save a report |
| q | Natural-language instruction | “Save a summary in my project folder” |
| Auth | Predicate describing authorized actions | Writing the chosen output is permitted |
| Goal | Predicate describing successful traces | A satisfactory summary is saved |
| d | One logical datum, including labels and provenance | Downloaded report record |
| value(d) | Its raw contents | The report's text |
| origin / parents | Source / input data from which it was derived | URL / report summarized into an answer |
| integrity | Authority classification | trusted or untrusted |
| confidentiality / bindings | Secrecy level / permitted destination bindings | no-model / a bound service |
| σ | One opaque symbol name | `$MDU:WebFetch[8c2a]` |
| Σ (Sigma) | Symbol-to-data map | Σ(σ) = d: “this symbol refers to this datum” |
| Ref(σ) | Reference presented instead of raw contents | The token placed in a model request |

As a compact state tuple, write
`s_t = (C_t, r_t, F_A,t, F_H,t, E_t, Σ_t, Π_t, P_t, G_t, W_t, Q_t, K_t)`.
The comma-t spellings for filesystem subscripts are plain-text shorthand.

| State component | Meaning | Example |
|---|---|---|
| C | Model contexts | What T has been sent; isolated U-call inputs |
| r | Runtime/process state | Active tool calls and child processes |
| F_A | AgentView filesystem (Agent File System / agent-view) | File containing a symbol |
| F_H | HumanView filesystem (Human File System / human-view) | Corresponding readable report |
| E | External environment state | Current remote response or service state |
| Σ | Symbol store | Stored report and summary references |
| Π (Pi) | Provenance information | Summary derived from report |
| P | Active policy state | Trust rules and usage rules |
| G | Approvals | Scoped human permission for a release |
| W | Session security labels | Watermark after a permitted secret read |
| Q | Pending operations | In-flight inspection or filesystem sync |
| K | Component health | Arbiter available or proxy failed |

The A in `F_A` means AgentView, not adversary A. E names the environment as a
participant; E_t denotes its state at a particular step. Likewise P_in/P_use
below are decision functions, whereas P is the policy state they consult.

| System/rule notation | Meaning / how to read it |
|---|---|
| κ (kappa) | One fixed deployment configuration: adapter, active controls, host support |
| S_κ | The transition-system model for configuration κ |
| States / Events | Sets of possible system snapshots / events |
| Init_κ(s) | “s is an allowed starting state” |
| Next_κ(s, e, s′) | “event e may take state s to state s′” |
| s_t --e_t--> s_(t+1) | State before an event, the event, then state after it |
| trace | A sequence of these states and events: one execution |
| P_in | Classifies incoming content for model admission |
| P_use | Decides whether a particular use is permitted, denied, or needs approval |
| Obs_T(trace) | Sequence of requests actually presented to T in that execution |
| Eff(trace) | Execution's effects: writes, program execution, releases, replies |
| L | Explicitly permitted observation channels, including selected metadata |

Example: let d be an untrusted report and σ its allocated token. `Σ(σ) = d`
means the monitor stores the association. A model request can contain `Ref(σ)`
while an authorized U-call receives `value(d)`. The resulting summary is another
datum d′ with another reference σ′. A prime (′) means a new/updated value; it
does not mean “trusted.” Parentheses group a tuple or supply a function's input;
`f : X -> Y` means f maps inputs in X to outputs in Y.

**1. The verification object.** Mandu mediates an AI agent's interaction with
a persistent, partially attacker-controlled environment. A trusted user supplies
a task; a privileged model selects actions; tools execute those actions; results
and stored artifacts become inputs to later model calls. The task may span
multiple sessions. Prompt injection is an attempt to use environment data as
authority over privileged decisions.

Fix a deployment configuration `kappa`: agent adapter, enabled integrity and
confidentiality axes, actual active interceptors, host isolation capabilities,
workspace mapping, model routes, and versions. Requested launcher flags are not
evidence that a mechanism is active. Start with one Linux adapter, integrity ON,
and a declared set of mediated channels. Confidentiality is an optional extension.

The system is the composition of user H, agent runtime R, privileged model T,
quarantined model U, tools/processes X, Mandu monitor M, persistent environment
E, and adversary A. M includes the arbiter, model adapters/proxies, enabled
filesystem/exec/network controls, and the wrappers that enforce policy decisions.
The enabled kernel mechanisms and their OS substrate are dependencies of the TCB.
The approval UI and policy management path are trusted where they can grant access.

T is privileged by its role, not assumed correct or immune to injection. Model T
is an arbitrary stateful strategy over its visible history; U is an arbitrary
strategy over the request and data supplied to its isolated calls. Neither needs
to produce a correct summary for a content-confinement proof. R is assumed to
preserve message roles and use the configured routes honestly. This does not,
by itself, prove that every shell command R can execute respects those routes.

**2. Task, authority, and attacker.** Represent a task as `(q, Auth, Goal)`:
the user's instruction, an independently specified authorization predicate over
actions and destinations, and a predicate over successful execution traces.
Natural-language q does not automatically supply a formal Auth or Goal.
Policy compliance and successful task completion are separate obligations.

A may adaptively choose web/tool payloads, untrusted messages, and attacker-owned
file contents, including content stored before the current session. File names,
errors, response status, timing, and tool-discoverable descriptions must each be
explicitly included or excluded. A cannot directly rewrite trusted user messages,
policy, approvals, the symbol database, or monitor code. Native compromise, kernel
escape, malicious agent applications, and human social engineering are outside
the initial model. Any desired theorem against attacker-supplied executable code
requires a stronger execution-confinement model.

Do not define attacker ownership using the policy's TRUSTED/UNTRUSTED verdict.
Actual ownership/provenance and the implemented verdict are different concepts:
their mismatch is a possible policy defect, not a reason to remove an attack from
the model. Trust means authority to enter privileged context, not factual truth.

**3. Data and symbols.** Use logical data records
`d = (id, value, origin, parents, integrity, confidentiality, bindings)`.
These are specification/ghost records, not a claim of byte-level runtime taint
tracking. Integrity is trusted or untrusted. Confidentiality is public,
any-model, or no-model; destination bindings are additional constraints.
Untrusted public content and trusted confidential content are both meaningful.

A symbol store `Sigma : Symbol -> DataRecord` holds references and provenance.
The specification distinguishes literal text, a monitor-recognized reference,
and approved metadata even though all serialize to strings in the implementation.
Parsing, allocation, lookup, scope, nested resolution, reuse, and obsolescence
must later justify this abstraction. A token-looking string is not proof of
authority, and a short random token is not an unguessable security capability.

AgentView (repo: Agent File System / agent-view) exposes a policy-controlled
representation; HumanView (repo: Human File System / human-view) exposes usable
originals at permitted sinks. The logical protected model view must be distinguished
from the physical AgentView worktree: tools and programs can encounter raw bytes
whose subsequent model admission still depends on the proxy.

**4. State and steps.** Define a labeled transition system
`S_kappa = (States, Init_kappa, Events, Next_kappa)` with state

```text
s = (contexts, runtime/processes, F_A, F_H, externalState,
     Sigma, provenance, policy, approvals, sessionLabels,
     inFlight, componentHealth)
```

Contexts include model-visible histories and isolated U-call inputs. F_A and F_H
are versioned file maps. inFlight contains pending tool/model/IPC requests and
filesystem synchronization. Policy, health and approvals are state because they
may change during a run. Persistent files and symbols can survive session reset;
model context and session labels have distinct lifetimes.

An execution is `s0 --e0--> s1 --e1--> ...`, with `Init_kappa(s0)` and each
step in `Next_kappa`. Interleave concurrent operations and permit crashes,
timeouts, retries, dropped sync triggers, and external edits. Do not assume the
entire classify/allocate/rewrite/send path or a two-view update is atomic.

The principal event families and intended abstract contracts are:

| Event | Abstract role / contract to establish |
|---|---|
| User instruction | Append authenticated authority to T's input. |
| T proposes an action | Produce a tool request from T's visible history. |
| Tool completion / environment update | Produce bytes and provenance; neither inherently grants trust. |
| Model admission | Classify each covered span, symbolize disallowed raw content, and forward the resulting request. |
| Inspect | Resolve permitted inputs only into U; symbolize its free-text answer; return only the approved structured feedback. |
| Write / synchronize / reread | Track versions and references across both views; reapply admission checks on later reads. |
| Release / execute | Check usage permission for the actual resolved value, operation and destination before the effect. |
| Policy or approval change | Record an authorized change with its scope; distinguish release approval from integrity endorsement. |
| Failure / recovery | Preserve boundary-specific restrictions and persistent bindings, with explicitly modeled recovery behavior. |

These contracts are proof targets, not premises about the implementation.
Concrete request handlers must later refine these abstract transitions.

**5. Policies and observations.** Model the inbound trust policy as
`P_in(state, source, tool, arguments, span) -> classification` and usage policy as
`P_use(state, datum, operation, destination) -> allow | deny | approvalRequired`.
Only a scoped approval that the policy accepts can turn approvalRequired into
permission; not every denial has an approval path. In particular the current
declassification operation refuses raw untrusted-integrity data in T even with
approval (`arbiter/policy/declassify.ts`).

Define `Obs_T(trace)` to be the sequence of actual model requests T receives,
including all roles, metadata, errors and attachments within the supported
adapter's coverage. Define `Eff(trace)` separately for file mutations, execution,
network releases and human replies. T's own generated text is not new external
authority simply because it occupies an assistant message.

The current system permits data-dependent feedback. Define an explicit admission
surface `L`, including inspect content_kind and its fixed next_step mapping,
accepted harness metadata, symbol identity/equality patterns and tags, approved
namespace metadata, and exact-context-echo upgrades. This is a description of
permitted observations, not proof they are harmless. In particular filenames can
contain arbitrary text and are not a small finite leakage channel. A bounded
content-kind field also admits repeated data-dependent signals over many calls.

**6. First candidate properties.** The narrow first property is policy-relative
model admission: every external span forwarded raw has a valid admission
justification under the policy version authorizing it; a span that remains
integrity-untrusted is represented by a symbol. This is a safety property over
provenance-annotated model-request events, not substring absence (the same words
can independently occur in trusted text).

The stronger content-confinement target relates observations to independent
source ownership: attacker-controlled payloads influence T only through explicitly
specified L or an authorized endorsement. It requires classifier soundness,
complete model-input coverage, and justification of each exception in addition to
correct rewriting. An attacker-controlled filename treated as trusted illustrates
why the narrow property does not imply the stronger one.

Stored-data preservation requires unendorsed untrusted lineage to remain protected
on every later covered admission, including after write, copy, transformation,
sync, restart and reread. A HumanView location alone cannot establish human authorship.
Usage safety requires every covered raw release/execution to have a valid usage
authorization bound to its actual arguments and state. Policy/approval races,
path aliases and nested symbols belong in that proof.

Full noninterference would compare executions with different attacker payloads.
It is too strong for the existing feedback channels. A later candidate is
observational equivalence modulo explicit L: matching trusted inputs and allowed
feedback should yield matching T-observations, with symbolic names related by a
consistent renaming that preserves equality and reference structure. Stateful
model randomness and schedules must be coupled explicitly, or the theorem must
compare distributions/sets of observations. Do not infer this theorem merely
from the fact that raw free text was symbolized.

Confidentiality, when enabled, adds permitted readers, bound releases, inherited
labels, and a session watermark after a permitted in-context secret read. It
does not follow from integrity confinement. Task correctness and eventual sync
are separate; liveness needs service availability and scheduling assumptions.

**7. Current implementation constraints.**

- `arbiter/policy/claude-code-inbound.ts:187` and `:195` grant Glob/LS raw trust;
  filenames must be restricted, treated as an explicit exception, or protected
  differently before claiming arbitrary attacker-text exclusion.
- `interceptors/inspect-mcp/src/inspect-symbol.ts:433` derives content_kind from
  the data; `arbiter/policy/claude-code-inbound.ts:505` admits fixed next-step
  directives selected by that kind. This intentionally enables action influence.
- `arbiter/policy/claude-code-inbound.ts:947` upgrades exact trusted-context echoes.
  Revealing no new bytes does not establish independence of selection/order.
- `fs-sync/src/eager-sync.ts:126` schedules asynchronous, coalesced sync. Therefore
  `F_H = resolve(F_A)` is not an all-state invariant. Correspondence belongs at
  successfully synchronized, conflict-free versions; eventual convergence needs
  a quiescent environment and successful retry/sweep assumptions.
- `docs/design/integrity/fs-sync.md §2:198` states human-edit reconciliation is not on
  the production launcher path. Model it only for entry points that call it.
- `docs/design/architecture/privilege-model.md:377` identifies cooperative wrapper bypasses.
  Mediation must be scoped per channel and checked for the actual deployment;
  honest runtime behavior alone does not establish universal syscall mediation.

The proposed first verification slice is therefore a fixed Linux adapter with
integrity ON, the arbiter/model-admission/inspect protocol, persistent symbols,
and a stored-file reread. Check its admission property before expanding to
filesystem concurrency, usage gates, confidentiality, or task semantics. This
document does not assert that any of those properties already hold universally.

Formal-method references: Lamport's [Specifying Systems](https://lamport.azurewebsites.net/tla/book-02-02-27.pdf)
provides the state/behavior and safety/liveness framework; Clarkson and Schneider's
[Hyperproperties](https://www.cs.cornell.edu/fbs/publications/Hyperproperties.pdf)
explains why information-flow claims can require comparison of multiple traces.
