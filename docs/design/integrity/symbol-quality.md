# Mandu — Symbol quality and quarantined processing (U-LLM)

> **Status: Frozen with the integrity axis (2026-09-28,
> [`protection-modes.md §10`](../architecture/protection-modes.md)).** The record
> stays; nothing here is extended. Built: Fix C (§3), Fix B with its
> request-aware v2 (§4), the candidate walk and alias tier (§6), multi-input
> inspection (§7) and the U-LLM refusal fixes (§9). Deferred and unbuilt: the
> transparent U-LLM (§8), eager triage and persistent tool-call records
> (§4.7).
>
> **Still running in `secrets` mode.** The `inspect-mcp` core is shared:
> confidentiality's quarantined read of a secret symbol runs on it, so the
> multi-input contract and label inheritance (§7), the system-slot transport
> (§9) and the candidate walk every symbol lookup goes through (§6) are
> maintained. The `content_kind` triage (§4) and the "a symbol proves nothing"
> prompt section (§3) are not axis-gated in the code and still run wherever
> `inspect_symbol` is mounted, but they were designed for untrusted data and
> are not developed further.
>
> Companion to [`mandu.md`](../architecture/mandu.md) (§6 #7 points here) and
> the U-LLM path in `interceptors/inspect-mcp/`. Paper terms are paired with
> repo terms per `mandu.md` §8: *T-LLM (privileged LLM)*, *U-LLM (quarantined
> LLM)*, *AgentView (repo: Agent File System / agent-view)*.
>
> In one line: symbolization hides not just the *content* of an untrusted
> tool result but its *quality*. T-LLM cannot see that a fetch returned an
> error page, an auth wall, or the tool's own refusal, and because every
> `inspect_symbol` result is unconditionally re-symbolized it can never
> plausibility-check a derived result either. The defense thereby converts a
> *recoverable* tool misuse into a *silent wrong answer*. Fix C teaches T-LLM
> to guard the two points it still controls; Fix B adds the one readable
> quality signal the architecture can grant safely: an enum-constrained
> triage verdict in the `inspect_symbol` envelope.

## 1. The incident and the bug class

A live session (2026-07-11, task: *"Count security mentions on
homepage.example.test"*):

1. T-LLM called `WebFetch({url, prompt: "Return the raw HTML content"})`.
   WebFetch discards raw HTML by design (it converts the page to markdown and
   answers the prompt with a small model), so the tool returned a
   **success-shaped refusal**: polite prose explaining it cannot reconstruct
   HTML, `is_error: false`, no machine-readable failure signal.
2. The proxy correctly classified the result UNTRUSTED and symbolized it to
   `$MDU:WebFetch[5854]`. T-LLM saw only the bare token.
3. T-LLM forwarded the symbol to `inspect_symbol` ("count security
   mentions"). The U-LLM faithfully counted occurrences in the *refusal
   prose* and returned `0`, re-symbolized per the boundary.
4. T-LLM emitted the result symbol; the reply-filter resolved it; the user
   received a confident, wrong **0**.

**The class**: any symbolized tool result (web fetch, exec output, file
read, API response) can hold an error page, a login/access-denied page, an
empty response, or the tool's own refusal instead of the requested content,
and under symbolization T-LLM has *no channel* through which to notice.
Vanilla Claude Code self-heals here (the agent reads the refusal in the
tool_result and retries with a better prompt); Mandu severs exactly that
feedback loop. Security held throughout: this is a **utility regression of
the defense**, in the same family as the `mandu.md` §6 #1
uncooperative-agent gap (§8) but distinct, because it bites even a *fully
cooperating* agent.

The trigger is shared (WebFetch's success-shaped refusal is the harness's
design; the raw-HTML prompt is agent misuse), but the silent amplification is
Mandu's, so the fix lives here.

## 2. Design principle for any fix

A "quality signal" about untrusted content is itself derived from untrusted
content, so every candidate channel must be one of:

- **(a) trusted-code-derived**: computed by TCB code without any model
  reading the content (byte length, truncation flag, the tool envelope's
  `is_error`). Injection bandwidth ≈ 0, but weak: this incident's refusal
  had `is_error: false` and an unremarkable size.
- **(b) enum-constrained model verdict**: a quarantined model reads the
  content but only a value from a **closed vocabulary**, validated by TCB
  code, crosses to T-LLM (the low-bandwidth-channel argument from the
  dual-LLM literature). Attacker-controlled content can at most flip a
  few-bit signal, and both flip directions are benign: claiming
  "as-requested" for garbage is the pre-fix status quo; claiming "error" for
  good content costs one bounded refetch.

**Never** a free-text summary, label, or explanation of untrusted content:
that is a prose injection channel straight into T-LLM and would break the §1
invariant of `mandu.md`.

## 3. Fix C — handling-prompt guidance (IMPLEMENTED 2026-07-12)

Because inspect results are *always* re-symbolized (`inspect-symbol.ts`,
fail-closed), T-LLM can never inspect-then-read a triage answer. So
instruction-level mitigation can only shape the two points T-LLM still
controls, and the guidance is written **generically for all tools**:

1. **Request only producible content.** Prompt-answering fetch tools (e.g.
   WebFetch) can never return raw HTML / "the raw response"; asking for that
   makes the internal model's refusal become the symbolized result. Ask for
   the information itself.
2. **Quality guard inside every `inspect_symbol` instruction** whose answer
   depends on content quality: *"If the content is not \<what you expect\>,
   e.g. an error message, a login or access-denied page, an empty response,
   or a tool's own refusal, say so plainly in your result instead of
   answering."* The derived result reaches the user, so the guard turns a
   hidden failure into a **visible failure report** at delivery time. (It
   cannot make T-LLM *react*; that is Fix B.)

Where: `arbiter/symbol-table/handling-prompt.ts` `buildSymbolSystemPrompt`
(the "A symbol proves nothing about success or quality" section + Rule 8).
[`handling-prompt.md`](../agents/handling-prompt.md) owns the assembly; this
doc owns the wording. The inspect-specific half (guard point 2, Rule 8)
renders only when an `inspect_symbol` tool is in the request's battery; the
general half (point 1) is core and renders always. Pinned by
`arbiter/test/unit/ipc.test.ts` ("symbols can hide tool failures") and,
through the real arbiter → proxy → upstream path, by
`tests/stack/full-stack.test.ts`.

Limits: mitigation by instruction. Nothing enforces the guard; a weak model
may omit it; and when the agent never inspects (writes the symbol to a file,
egresses it), no guard runs at all (though there the *original* bytes
surface, which is at least not silent).

## 4. Fix B — enum triage verdict in the inspect envelope (IMPLEMENTED 2026-07-12)

Give T-LLM the one readable signal principle 2(b) allows. The design below
was refined by walking the incident replay end to end through every
component plus nine failure variants (the chained inspect, a multi-span
result, a huge value, triage-output injection, version skew, the
budget-reminder tail, a permanent auth wall, an honest zero, prompt/tool
signature drift); each variant's resolution is folded into the subsection it
changed.

Proven live by the claude-e2e scenario **E25 `inspect-verdict-retry`**: the
mock's first fetch serves a 503 maintenance notice (a serve-once fixture);
the real triage minted `error_or_refusal`; T-LLM retried the fetch exactly
once; the retried page triaged positive and the resolved reply carried the
exact id that exists only in the retried page. The live page carries no
injection: an injected comment makes the quarantined model refuse the
extraction, which would mask the recovery under test.

**The triage must not starve the IPC deadline.** The U-LLM runner is an
async `spawn` (a synchronous runner froze the event loop while the
re-symbolize request's fail-closed deadline was armed, so a healthy arbiter
reply was discarded on resume and the inspect degraded), and
`inspectSymbol` settles the triage promise BEFORE the first deadline-armed
arbiter request, so no U-LLM exec is runnable while an IPC deadline is
pending whatever the injected seam does. Pinned by a loop-liveness test of
`defaultCliExec` and an ordering test.

### 4.1 Mechanism

`inspect_symbol`'s success envelope grows one field:

```json
{ "result_symbol": "$MDU:inspect[130c].result",
  "model": "claude-haiku-4-5",
  "content_kind": "error_or_refusal" }
```

`content_kind` is a verdict about the **inspected input content** (not the
derived result), so T-LLM learns "the thing I asked to be counted was a
refusal, not the page" and can refetch before answering.

**v1, intrinsic classification.** A fixed triage instruction knows nothing
about what T-LLM asked the *source tool* for, so it can judge only the
content's intrinsic shape: `substantive`, `error_or_refusal`, `auth_wall`,
`empty`, `unknown`. Two scope notes: the verdict describes the resolved value
of the **given symbol regardless of lineage** (inspecting an inspect-result
symbol judges the derived text, not the original page), and it is
**per-symbol, not per-page** (a tool_result symbolized as several spans is
judged fragment by fragment).

**v2, request-aware (built).** The proxy passes `callId: tool_use_id` into
`symbolize()` and the arbiter records `toolUseId → {name, input}`
(`recordToolCall`, in memory). The read-only `symbolProvenance` IPC op walks
that linkage (field-path symbols fall back to the base entry), and the
triage then uses a REQUEST-aware fixed prompt: a TCB-rendered, head-truncated
(1 KiB) `ToolName({...input})` block precedes the data window, and the
positive verdict splits into **`as_requested`** vs **`wrong_content`** (the
"right-looking but wrong page" failure v1 cannot express). The vocabulary is
SEVEN tokens (gate, parser and prompt in sync).

- The new pair's flip directions stay benign (forged `as_requested` = the
  pre-verdict status quo; forged `wrong_content` = one bounded refetch).
- The REQUEST block is T-LLM-authored (the privileged principal's own tool
  call), trusted context rather than an override channel; the fixed prompt
  tells the classifier not to act on instructions inside it. The CALLER's
  inspect instruction never reaches triage.
- Degradation is total and utility-only: a missing op (older arbiter), an
  incomplete linkage (no `call_id`, no record; records do not survive an
  arbiter restart, deliberately), or a provenance error all fall back to the
  v1 prompt, and the inspect never fails on this path. Test bridges must
  FORWARD the optional op or they silently exercise only the degraded path.

**`empty` is a judgment of form, not meaning.** A request-aware classifier
once answered `empty` for the requested line `nothing to see here.` because
the sentence *says* there is nothing, and `next_step` sent T-LLM back to the
source call. Both triage prompts now carry the clause "judge emptiness by
FORM, never by what the text says" (`inspect-mcp/src/inspect-symbol.ts`,
unit-pinned). Still a closed vocabulary; the clause narrows one label.

### 4.2 Minting (inspect-mcp, lazy — at inspect time)

In `inspectSymbol()` after the main U-LLM call: one **separate** quarantined
U-LLM call with a **fixed** instruction (never caller-supplied), a
multiple-choice question over the same raw value, answered with exactly one
vocabulary token.

- **Separate call, not piggybacked** on the main call as structured output:
  a combined JSON response would make the verdict extractable only by
  parsing model output that the caller's instruction and the untrusted
  content both influence (§5).
- **Truncated triage window, TCB-applied**: first 4 KiB + last 1 KiB of the
  raw value. Error pages, auth walls and refusals announce themselves early;
  this bounds cost on huge values.
- **Strict parse**: trim → lowercase → **exact full-string equality**
  against the closed set. Never substring matching: "not substantive" must
  parse as `unknown`. Prose, multi-token, refusal, empty output → `unknown`.
- **Failure isolation**: a triage error or timeout must NOT fail the
  inspect; it degrades to `"unknown"`. The signal is utility, never on the
  security path. The raw triage output is never returned or logged
  unsymbolized; only the validated enum value enters the envelope.
- **Per-symbol cache**: an in-process map keyed by the exact symbol token
  (inspect-mcp is a per-session stdio server, so the cache is
  session-bounded).
- **Quota exposure**: the extra call raises quota pressure on the U-LLM
  transport (`claude -p` under subscription auth); the cache and the
  truncation are the mitigations. The triage call uses the same transport
  constraints as the main call (real model endpoint, never the
  anthropic-proxy).

**Not at a declared local endpoint.** When the inspect routes to the user's
own model (`local: true`,
[`model-endpoints.md §1`](../confidentiality/model-endpoints.md)
§8), no triage call runs and the verdict is `unknown`. A small local model
labelled real documents `wrong_content` / `auth_wall` right after
summarizing them correctly, and the `next_step` those verdicts carry told
the main model to abandon the answer. The contradiction retry (§4.4) needs a
positive verdict, so it does not run there either.

### 4.3 Trust gate (lands in the SAME change as the envelope)

`mcp-server.ts`'s shape contract and `arbiter/policy/claude-code-inbound.ts`
trust ONLY the exact inspect envelope; an unknown key re-triggers the
fail-closed double-wrap. The gate (`isInspectSuccessEnvelope`) is a
`JSON.parse` + key-allowlist check, not an order-sensitive regex:

- The allowed key set is `{result_symbol, model?, content_kind?}` (plus the
  fixed `next_step` directive, §7.2); `content_kind` must **full-match** an
  anchored alternation of the enum tokens (the `INSPECT_MODEL_ID_RE` pattern
  for `model` is the precedent). A forged field buys an attacker only the
  bounded enum flip of §2.
- All accepted serializations (bare token / envelope / token immediately
  followed by envelope) share `isInspectSuccessEnvelope`.
- **`content_kind` is OPTIONAL, for version-skew safety**: an old
  inspect-mcp emitting the two-key envelope stays trusted. The reverse skew
  (new inspect-mcp, stale arbiter daemon) fails closed to the
  harmless-but-noisy double-wrap.
- **Reminder-tail composition**: `splitTrailingSystemReminders` re-classifies
  the envelope BODY alone after splitting Claude Code's appended
  `<system-reminder>` blocks; the widened envelope must pass there too.
- Unchanged: the same shape under any other tool name stays UNTRUSTED, and a
  forged envelope *inside* untrusted content never reaches this gate (it is
  classified, and symbolized whole, under the fetching tool's name).

### 4.4 Handling prompt — per-verdict actions, retry bounded

`buildSymbolSystemPrompt` says `content_kind` is the system's own verdict
about the inspected content, with a per-verdict action table (an unbounded
"retry on bad verdict" diverges on a permanently auth-walled URL):

| verdict | action |
|---|---|
| `substantive` / `as_requested` | proceed; report the derived result |
| `wrong_content` | retry the source call ONCE with corrected parameters; then surface |
| `error_or_refusal` | retry the source call ONCE with corrected parameters; if still bad, surface the failure |
| `auth_wall` | do NOT retry (changed parameters won't help); surface to the user immediately |
| `empty` | retry the source call once; then surface |
| `unknown` | no signal: proceed, never retry on `unknown` (else a triage outage causes refetch storms) |

A genuinely substantive page with an honestly-zero answer is `substantive`:
the verdict is about the content, not the answer, so there is no false
refetch loop (this is why the signal must not be derived from the result).
The **contradiction retry** is the refusal backstop: when the main call's
output opens with a refusal shape (`REFUSAL_SHAPE_RE`, start-of-text only)
while the independent triage certified the input as genuine requested
content, inspect-mcp re-asks the U-LLM once with a fixed retry note (§9).

### 4.5 Observability

The triage call emits its own `ullm_call` event (view "Quarantine") with a
`DualRepr`: original = the truncated triage input + the raw one-token
output; symbolized = the validated enum; tagged `purpose: "triage"` so the
dashboard can render a verdict chip on the inspect lane.

### 4.6 Tests

- **inspect-mcp unit**: strict-parse table (each token; case/whitespace
  variants; substring traps like "not substantive" → `unknown`; prose /
  multi-token / empty → `unknown`); truncation window; triage failure →
  `unknown` with the inspect still succeeding; per-symbol cache; raw triage
  text never escapes.
- **arbiter unit** (`claude-code-policy.test.ts`): the envelope with each
  valid token → TRUSTED; the legacy two-key envelope still TRUSTED (skew);
  invalid/prose `content_kind` → UNTRUSTED (fail-closed); token+envelope
  form; envelope + trailing token-budget reminder (via the proxy's split
  path); the same shape under any other tool name → UNTRUSTED.
- **integration e2e** (`tests/integrity/content-kind.test.ts`): full stack,
  a symbolized refusal inspected with a counting instruction yields
  `content_kind: "error_or_refusal"` readable by T-LLM while the derived
  result stays symbolic; adversarial content that *contains* enum-lookalike
  text does not alter the verdict channel; both adversarial forgeries.
- **claude-e2e (driver axis)**: E25, the incident scenario end to end (live
  agent refetches after `error_or_refusal`, at most once, final answer
  correct or failure surfaced). A raw triage output that IS a bare enum
  token is the sanctioned channel, not an `ullm-raw-absent` leak.

### 4.7 Later extensions (explicitly deferred)

- **Eager mode**: triage at *symbolization time* (every untrusted
  tool_result, verdict attached next to the minted token) would also cover
  symbols that are never inspected, but puts a model call + latency on the
  security-path hot loop and interacts with the pure-symbolic re-ingestion
  rules. Do not build until the lazy signal proves useful.
- **Persistent tool-call records**: `recordToolCall` is in memory, so
  request-aware triage degrades to v1 across an arbiter restart; persist only
  if real sessions show that mattering.

## 5. Rejected alternatives

- **Free-text triage / summaries to T-LLM**: a prose injection channel;
  breaks the invariant. Rejected outright.
- **Piggybacking the verdict on the main U-LLM call as structured output**:
  one call instead of two, but the verdict would be extracted by parsing
  model output that both the caller's instruction and the untrusted content
  shape, and the malformed-JSON fallback must guess which part is "the
  result". The separate fixed-instruction call keeps the channel clean; the
  per-symbol cache recovers most of the cost (§4.2).
- **Trusted-code metadata only (§2(a) alone)**: `is_error` + byte counts do
  not detect success-shaped refusals (this incident passes both).
- **Name-only trust of the inspect envelope**: already rejected in
  `claude-code-inbound.ts` (its ERROR-path audit); Fix B keeps the strict
  shape rule and widens it by allowlisted fields only.
- **Do nothing (treat as an agent/tool bug)**: the undefended agent recovers
  from this class on its own; a defense that silently removes that recovery
  owns the regression.

## 6. Model-mutated tokens — the candidate walk (IMPLEMENTED 2026-07-16)

A sibling class to §1's silent tool failures: the model MISQUOTES a symbol
token, and every exact-name lookup goes blind. Two shapes, both seen live:

- **Invented field suffix**: a reply carried `$MDU:Read[6819].content` for
  the real bare token `$MDU:Read[6819]` (pattern-completing the
  `$MDU:<tool>[hash].field` grammar from the handling prompt).
- **Glued sentence punctuation**: `…$MDU:anymodel_inspect[0e09].result.` at
  the end of a sentence; the scanner grammar admits dots inside field
  segments, so the match swallows the period and the exact lookup misses.

**Fix: one lookup walk for every name→entry read.**
`symbolNameCandidates(token)` (`symbol-table/symbol-format.ts`, pure grammar)
yields the exact token, the token minus its trailing dot-run, then
progressively shorter field paths down to the `$MDU:tool[hash]` base,
most-specific first, every candidate a string prefix of the input. All
lookups route through it (`findSymbolByName`): `resolveSymbol`,
`getSymbolEntry`, the `resolveAllSymbols(Deep)` scanners, the egress gate's
`symbolLookup` (`ipc/server.ts`), and the exec policy's three lookup sites
(exec-classify / shell-symbol-resolution / exec-argv-mode).

**The invariant this serves: decision and resolution must agree on what is
"known".** Before the fix the egress gate used a raw `map.get` while deep
resolution had a one-level fallback, so a mutated token could be "unknown →
no-op allow" to the gate yet resolvable on another surface (no live leak
existed, but only by accident of which op each path used). Now a mutated
token is gated exactly like the name it mutates, and a genuinely unknown
token behaves as before everywhere: no-op at the gate, literal in text, null
on resolve.

Consequences, by surface:

- **Reply-filter / HumanView desymbolize**: mutations resolve; sentence
  punctuation survives (`resolveAllSymbols` re-attaches the trailing dot-run
  the resolved name did not consume; an invented suffix is dropped).
- **inspect_symbol**: a mutated token inspects the real symbol instead of
  refusing "unknown symbol" (`nearestSymbolName` is exported for future
  messaging).
- **Exec**: a mutated token in a data slot resolves (quoted, slot-safe); in
  command position it is detected and gated like the real token.
- **Secret twins**: a mutated secret token maps to its entry, so the
  confidentiality branches fire for it (deny/skip), strictly safer than the
  old unknown-token no-op.
- **Dashboard lineage miner**: trims the trailing dot-run so prose-glued
  sightings unify with the real node instead of minting a phantom.
- **Handling prompt R3**: never invent, append, or alter field suffixes.

Rejected: a proxy-side repair round-trip (intercept the reply, append a
corrective user turn, re-ask), because resolution tolerance captures most of
its value at a fraction of the complexity and zero latency; and fuzzy
matching beyond suffix-stripping (edit distance on hashes), because a wrong
hash is indistinguishable from a reference to another session's symbol and
guessing across hashes would fabricate provenance.

### 6.1 The alias tier — a stranded base resolves its one field extension (2026-07-19)

A third mutation shape, from the STREAM rather than the model's spelling: the
model streams a token's base and its `.field` tail in separate SSE deltas,
and a TUI frame interposed between them hands every scanner the BARE BASE
(`$MDU:inspect[c72f]`), a name the table never minted (inspect-mcp allocates
the field-ful `…[c72f].result`). The shortening walk cannot help (it only
strips), so the reply-filter showed the human a raw token. The filter's idle
re-hold covers only the quiet gap; no hold can bridge an interposed frame
(`docs/testing/differential-interactive.md` §12).

`uniqueFieldExtension(token, names)` (`symbol-format.ts`) runs the REVERSE
direction, bounded to be guess-free, as a final tier of `findByCandidates`
after every shortening candidate misses: the token (trailing dots trimmed)
must be grammar-complete and extend to allocated names only at a `.` field
boundary. One extension → that name. A family whose shortest member is an
ancestor every other one extends (the human-edit `.__mdu_split[n]` shape) →
the ancestor. Sibling extensions (`.stdout` vs `.stderr`) → no match: never
guess between different values. Mid-segment prefixes (`…[ab].res`) and
mid-hash fragments never alias.

The §6 lockstep invariant extends to this tier: every walk site passes its
name enumerator, so a stranded base is gated exactly like the name it
abbreviates. Pinned end to end (real arbiter + real reply-filter stream core,
both seam shapes) by `tests/stack/reply-filter-seam.test.ts`.

**Parked: a self-terminating token grammar.** The seam's root enabler is
that the grammar is open-ended at the right edge: `$MDU:tool[hash]` is both a
complete token and a prefix of `$MDU:tool[hash].field`. A hash-LAST format
(`$MDU:tool.field[hash]`) or a closing sentinel would remove that ambiguity
structurally, and the `SymbolFormat` interface is pluggable. Parked because
the trade is bad today: the alias tier already closes every observed shape,
and does better than hash-last on the interposed-frame shape (a hash-last
fragment cut before its `[hash]` can never resolve); what hash-last would
add covers only unobserved residuals (a mid-hash split leaks under every
grammar; sibling ambiguity needs two allocations sharing one hash, which the
fresh-hash-per-mint allocator does not produce); and the migration touches
every scanner copy (arbiter, reply-filter, the Rust interceptors,
dashboard), the handling prompt, golden fixtures and e2e oracles, plus a
dual-read back-compat story. Un-defer on any of: a live failure whose byte
shape is a mid-hash split; a stranded-base leak from genuine sibling
extensions; or the symbol format being reopened for another reason
(`docs/adfi-reference/design/symbol.md` lists comparing formats), in which
case the replacement grammar must be self-terminating.

## 7. Multi-input inspection

A two-file merge task exposed the single-input limit: both files were read,
but the merge instruction carried only one file's symbol, so the U-LLM never
saw the other file's records, and a format-only check missed the omission.
The evaluated reference (`dualview-inspect-symbol.ts`) already accepts a
symbols array; Mandu reuses its resolve-all-before-processing pattern and
per-input framing, keeping its own free-text instruction and fully symbolic
result envelope. No raw strings or model-derived success booleans enter
T-LLM.

`inspect_symbol` accepts exactly one of legacy `symbol` or `symbols` (1–16
unique opaque handles), plus `instruction`. The wire schema uses ordinary
object properties and the core validates exclusivity: a root `oneOf` made
one Claude Code version silently drop the inspection tool while still
registering the other tools of the same MCP server.

- Every input resolves through the arbiter's quarantined deep resolution
  before any U-LLM call. An unknown or refused input stops the whole
  operation; a partial set is never processed. The combined input is
  bounded to 1 MiB.
- Inputs are framed separately as `## Input N`, numbers only. The frame no
  longer carries the handle: its hex hash is the one thing an otherwise
  empty input hands the U-LLM to invent from (a run answered a "release
  code" built from two label hashes when no input held one). The
  instruction addresses inputs by number.
- The handling prompt teaches one multi-input transformation over all
  original sources, not a chain of attempts to reveal data. A completeness
  check compares a candidate against all originals and returns the complete
  corrected artifact, not a formatting verdict. `content_kind` classifies the
  input; it never certifies the output's correctness.

Single-input behavior and the result shape are unchanged.

### 7.1 Label inheritance and compatibility

The `symbolizeDerived` arbiter operation requires the complete
`sourceSymbols` list (implementation: `arbiter/symbol-table/source-label.ts`).
The source join follows the same bounded deep-resolution scanner as the
quarantine and includes nested symbol restrictions; joining only explicit
wrapper rows would miss restrictions on nested data actually consumed.

- Confidentiality is the maximum source level; only bindings shared by every
  confidential source are kept (exact intersection; non-identical
  overlapping URL patterns conservatively require approval). Public inputs
  impose no destination restriction. Explicit bindings cannot widen the
  inherited set. Output integrity is untrusted. Unknown parents are refused.
- It is a separate operation so an old arbiter rejects multi-input output
  instead of silently ignoring the new label fields and minting a public
  symbol. A client without the operation refuses multi-input inspection.
  The real adapter uses it for single-input inspection too, because one
  wrapper can contain several nested sources, and never falls back after an
  unknown-operation response.
- Outputs minted this way are always fresh symbols: the legacy reuse key
  lacks the complete source and binding set, so reusing a prior output could
  keep broader bindings.
- The single-parent storage column keeps the first parent for legacy
  consumers; all input edges and values are in the quarantine event. No
  symbol-DB schema change. Every raw derived output is re-symbolized before
  returning.

Tests cover mixed `public`/`any-model` inputs, `no-model`/unknown refusal,
destination intersections, both input orders, and model-boundary re-entry
through real components.

### 7.2 Output artifacts and result guidance

An optional `output_format` accepts `text` (default, byte-preserving) or
`json`. JSON mode adds a fixed quarantine instruction, removes only a single
complete Markdown JSON fence if present, and parses the candidate before
symbolization, keeping the validated bytes (no parse/stringify rounding of
numbers). Invalid output returns a fixed error with no parser text or raw
content. Validation checks syntax, not task correctness. Both tool mounts
(the MCP server and the OpenClaw plugin) pass the option to the same core;
no automatic repair call is made, so malformed output cannot become a
successful artifact.

The `next_step` envelope field carries a fixed artifact-routing directive
for `as_requested`, `substantive` and `unknown`: write the returned symbol,
supply all originals for further processing, and treat `content_kind` as
input triage rather than output verification. This extends readable TCB
metadata deliberately: the arbiter accepts only the exact fixed string paired
with its validated enum, and arbitrary or modified text is symbolized. No
U-LLM-generated prose becomes trusted. Older envelopes without the directive
stay accepted; older arbiters symbolize the new strings. Tests drive both
genuine and altered metadata through the real proxy.

### 7.3 File-backed inputs

A file path such as `src/config.mjs` in a symbol's field suffix stopped the
scanner at the slash, so an outer Read symbol resolved to an inner
placeholder instead of the source. The canonical-field encoding
([`mandu.md §9`](../architecture/mandu.md))
keeps the rendered token within the scanner grammar while the original field
and lineage stay as arbiter metadata. The cross-component regression
(`tests/stack/multi-input-inspection.test.ts`) seeds nested files through
real fs-sync, sends their AgentView contents through the real model proxy,
and supplies both Read symbols together to inspection; it requires both
complete originals in the quarantine, only opaque input/output in the
captured model requests, and the complete artifact in the HumanView (repo:
Human File System / human-view) after real view sync. A deterministic
processor stands in for the U-LLM, so this proves the plumbing and the
confinement, not real-model task quality.

## 8. Transparent U-LLM — the uncooperative-agent utility gap (DESIGN, deferred)

**Status: designed, not built, not scheduled (deferred 2026-07-12; frozen
with the axis).** Realizes path (a) of `mandu.md` §6 problem #1.

### 8.1 Scope: a utility problem, not a security one

`inspect_symbol` is a **cooperative** path: an MCP tool the agent must
*choose* to call, steered by the handling prompt. An agent that does not
call it (no MCP client, its own system prompt outranks ours, or simply not
ours to steer) still receives only symbols: **security holds; utility for
tasks that need to read the data degrades.** Nothing here fixes a
vulnerability. The honest claim is: *Mandu is secure against an arbitrary
agent, but only fully useful to a cooperating one.*

The gap is not total. Tasks over untrusted data fall into three classes:

| # | Class | Answer path | Needs U-LLM? |
|---|---|---|---|
| 1 | **Pass-through**: the answer *is* the content | T-LLM emits the symbol; `reply-filter` desymbolizes for the human | No (`untrusted-file-lookup`) |
| 2 | **Exec-derivable**: a tool over AgentView files computes it (`wc`, `grep`, `jq`, `sort`) | T-LLM runs the tool; its output symbol resolves at reply | No (`count-security`: an exact count over untrusted bytes, inspect-free) |
| 3 | **Semantic derivation**: summarize, extract, compare, translate, judge | the model must *read* the content | Yes (`inspect-summarize`, `inspect-extract`, `inspect-compare`) |

**Why deferred.** A coding agent with a shell routes around symbolization
for class 2, and `count-security` shows Claude Code doing exactly that. The
residue that genuinely fails is natural-language understanding (summarize,
judge tone, translate), a minority of a coding agent's work. For shell-less
agents (RAG assistants, support bots, browser agents) classes 1–2 are
unavailable and the gap would be real.

**Un-defer triggers**, any of: (1) the Phase 0 measurement (§8.5) shows a
real class-3 collapse under `--no-mcp`; (2) Mandu targets a shell-less agent
([`supported-agents.md §5`](../agents/supported-agents.md) §3.2); (3) the
uncooperative-agent claim is challenged, so the answer is either this work or
a narrower claim.

### 8.2 Design

The proxy, which already sees every request, does the `inspect_symbol` work
**itself**: desymbolize → quarantined call → **re-symbolize** → inject the
derived token as TCB-authored context, so the agent gets a usable derived
value without calling a tool and no untrusted byte enters T-LLM. What changes
is **who calls** the quarantine, not the invariant.

- **Placement.** A new `autoInspect` stage in the proxy's request path,
  after `rewriteRequest` (symbolization, fail-closed, unchanged) and before
  the view-map path rewrite. It runs only after every untrusted span is
  already a token, may only **ADD** content, and **fails open to safe**: any
  error, timeout or refusal forwards the already-safe request un-augmented.
  This is not a fail-closed violation: degrading sends the model *less*
  information, never more (the same argument as `reply-filter`'s
  passthrough). It stays off the symbolization hot loop (§4.7's constraint).
- **Request-side, not response-side.** Detecting a fabricated or refused
  answer after the fact would need buffering the SSE text that streams to
  the agent's TUI on every turn, and "did it fabricate?" is a harder
  judgment than "will it need to read?", which trusted inputs alone answer.
- **Injection point.** Not inside the `tool_result` (the proxy re-walks every
  `tool_result` each turn and a symbol-plus-prose result would fail the
  pure-symbolic check and be double-wrapped). Instead a TCB-authored text
  block at the tail of the user message carrying the symbolized result:
  skipped by the inbound classifier, prompt-cache prefix preserved, never in
  the agent's stored history; marked `[mandu:derived]` and guarded against
  re-injection. Its wording must name the derived token as *the* answer and
  the source token as *not* the answer (a weak model once grabbed a decoy
  token minted beside the real one).
- **The detector** decides class 3 vs classes 1–2 from **trusted inputs
  only**: the user's latest turn and T-LLM's originating tool call. It never
  sees the untrusted bytes, so it is not an injection surface. It is one
  quarantined enum call reusing the §4.2 machinery (fixed instruction,
  strict parse, failure isolation, cache) over `needs_read` /
  `symbol_suffices` / `unknown`; both non-positive verdicts mean "do
  nothing", so every failure mode is the status quo. It is cached per task
  (a hash of the latest human turn), behind a structural pre-gate (no
  untrusted symbol minted this turn → no I/O).

### 8.3 Reuse

`inspect-symbol.ts` is transport-agnostic (two injected deps, `Arbiter` and
`UllmClient`; zero MCP imports), so the proxy needs a new *caller*, not a new
engine: `inspectSymbol()`, the quarantine prompt, the triage kit, both U-LLM
transports with `assertNonProxyBaseUrl`, and the `ullm_call` event builders
import unchanged. The proxy's narrow `Arbiter` interface must grow `resolve`
(the daemon already has it). Keep `inspectSymbol`'s strict emit contract
(refuse an un-audited quarantined call); here a refusal just means no derived
block. The inbound inspect trust gate (§4.3) is **not traversed**: it exists
because the MCP result re-enters T-LLM through a spoofable `tool_result`
channel, so the transparent path is strictly less TCB. Inside the proxy the
`tool_use` id/name/input are in hand at symbolize time, so the request-aware
triage never needs the `symbolProvenance` round-trip and never degrades
across an arbiter restart.

### 8.4 The oracle

> An agent that never calls `inspect_symbol` completes a class-3 benign task
> over UNTRUSTED data CORRECTLY, while the security invariant holds.

- **The uncooperative agent, simulated**: `--no-mcp` launches the agent with
  no `inspect_symbol` registered at all (stricter than a prompt-level ban).
- **Harness-enforced negative**: no `ullm_call` event in Phase 0; in Phase 1+
  exactly one, emitted by the *proxy*, not the MCP server.
- **Unforgeable correctness**: the claude-e2e EXACT-ANSWER pattern (ground
  truth exists only in the untrusted content, never in the prompt, graded
  against the resolved reply, `tests/lib/assertions-utility.ts`
  `evalReplyAchieves`).
- **Security holds in both arms**: the `implementation-plan.md` §9 oracle
  stays green.

The deterministic `eval/` benign row cannot fail for the right reason (it
reconstructs the scored workspace from the assertions' own operands), so it
is reported as **"benign fidelity (byte-fidelity + no-over-block)"**, not
task utility (`eval/lib/metrics.ts`, `eval/README.md`); task completion is
graded by the live EXACT-ANSWER tier.

### 8.5 Risks and phasing

Risks: the detector is the only unproven piece (over-trigger pays a model
call per turn; under-trigger lets the agent fabricate); **self-recursion**
(a U-LLM inside the proxy inherits `ANTHROPIC_BASE_URL` pointing at the
proxy itself, so the in-proxy client must be built from explicit config,
never `process.env`, with `assertNonProxyBaseUrl` and the child-env scrub
reused verbatim); whether a weak T-LLM uses the injected token (prove on
haiku); quota (a detector call plus a derivation call; the §4.2 mitigations
apply from the start); the prompt-cache cost of a per-turn tail block; and
extracting "the user's task" past Claude Code's injected system-reminders
(reuse `splitTrailingSystemReminders`). Multi-symbol class-3 tasks are
covered by §7's `symbols` array.

Phasing, for whoever un-defers it: **Phase 0** measures the gap with no new
machinery (the three class-3 scenarios under `--no-mcp` with the
no-`ullm_call` assertion, while `untrusted-file-lookup` and `count-security`
still pass); **Phase 1** builds the derivation pipe with the detector stubbed
to "always derive"; **Phase 2** adds the detector and caches, gated on
classes 1–2 emitting zero `ullm_call` events, and measures trigger rate,
tokens and latency; **Phase 3** ports the stage to `openai-proxy`, which has
the same `rewriteRequest` shape.

Fences: not a replacement for `inspect_symbol` (a cooperating agent keeps
the better deal, since it controls the instruction); no new chokepoint or
kernel work; not on the security path; no claim about classes 1–2, which
must stay free.

## 9. The U-LLM refusing its own task (FIXED 2026-07-15)

The sibling of §1 where the *quarantined U-LLM itself* is the failure: a
U-LLM asked to copy a token-shaped value (`DEPLOY-TOKEN-…`) or read off an
id refused ("I can't follow instructions that ask me to output secrets…"),
so the human got refusal prose instead of the value. The defense held (the
refusal was re-symbolized like any result); this was purely utility. Three
causes, three fixes:

1. **The quarantine preamble arrived as USER text** (`claude -p` takes one
   prompt, so the fixed system prompt was concatenated ahead of the data),
   which reads as role-override injection. Fix (`ullm-client.ts`
   `buildCliArgs`): `--system-prompt <quarantine prompt>` replaces the
   agent's own system prompt, so the child boots *as* the data processor;
   the untrusted data stays on STDIN, never argv. Codex has no system slot;
   system + user stay concatenated there.
2. **The preamble never said why faithful reproduction is safe.** Fix
   (`inspect-symbol.ts` `QUARANTINE_SYSTEM_PROMPT`): name Mandu, state that
   the isolation is the security mechanism, and explain that output is
   re-symbolized and released only under the owner's egress policy. Every
   claim is true by construction.
3. **T-LLM inspected a verbatim copy.** Fix (`handling-prompt.ts` R2/R6 + a
   copy example): a verbatim copy/move/save writes the SOURCE symbol; R6
   applies only to artifacts whose content must differ from the source.

None of this is a security surface: symbolization at ingress and the egress
gates enforce the invariant whatever either model does with either prompt.
Pinned by `inspect-mcp/test/unit/cli-ullm-client.test.ts` (argv carries the
quarantine prompt, never the data), the handling-prompt golden fixtures, and
the live `untrusted-writeback` and `inspect-verdict-retry` scenarios.
