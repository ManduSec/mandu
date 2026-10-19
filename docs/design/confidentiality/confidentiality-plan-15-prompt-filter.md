# Confidentiality Plan 15 — the prompt filter: pluggable detectors over the human's prompt

> **Status: BUILT (2026-10-02 to 2026-10-03), every phase of §11.** Phase 1:
> the one-pass value matcher (which the value backstop and the egress
> tripwire also run on), the `registered-value` filter with the prompt floor,
> the `filterPrompt` op with its cache and its human-plane dry run, the
> segmenters per wire and agent, the OpenAI-family write-back of user text,
> the `prompt_filter` event, and the developer dashboard's read-only panel
> (§13.1). Phase 2: `key-shapes`, pattern packs, `prompt_filters:` with the
> administrator's layer, the actions `redact`, `block` and `log`, the proxies'
> `block` on every wire, and the panel's editing (§13.2 to §13.4). Phase 3:
> out-of-process plugins with a reference local classifier (§13.5), and `ask`
> with the Inbox hold and "let it through" (§13.6). Phase 4: the product
> page's Settings › Prompt filters and the note under the person's message
> (§13.7), `mandu why` for a prompt placeholder (§13.8), the SIEM mapping
> (§13.9). 2026-10-07: the reference classifier's chunks overlap, a plugin's
> imports are pinned (`modules:`) and its install directory is no longer
> readable to it, and releases ship the classifier with `mandu policy
> classifier-pack` (§13.5 items 2, 6, 7, 14, 15, 18). 2026-10-09: a HIGH
> session's own write no longer masks the human's text that dictated it
> (§13.10). 2026-10-11: a Write's own success notice reaches the model raw
> (§13.10, "A Write's own result"), OpenClaw's and OpenCode 1's included,
> and a masked write result no longer registers its notice line.
> 2026-10-12: a result the value backstop raised registers only the lines a
> secret was found in (§13.11). 2026-10-18: an agent that disconnects while
> its prompt is held ends the proxy's wait at once, nothing sent, the hold
> left pending for its retry; OpenClaw and OpenCode have their own `ask` e2e
> on both of their wires (§13.6 items 13, 16); OpenCode 2's nested
> `Instructions from:` message is harness text, not the human's (§13.6
> item 20).
>
> Supersedes Plan 13 §4.8 ("the user's prompt is an object") and its §7 step
> 7. The human's prompt stays **trusted** (public) by default; one filter,
> the registered-value filter, is on by default because it cannot misfire;
> every other filter (key shapes, organization patterns and keywords, a
> classifier model) is opt-in through `policy.yaml` and pattern packs.
> Confidentiality axis only (mode `secrets`); the frozen integrity axis is
> untouched (§9).

Spine: [`confidentiality.md`](./confidentiality.md). Builds on
[`model-endpoints.md §1`](model-endpoints.md)
(`models:`, `local: true`, `admits`),
[`model-endpoints.md §2`](model-endpoints.md)
(`perimeter:`, the administrator's `/etc/mandu/policy.d/` layer),
[`confidentiality-plan-14-policy-suggestions.md`](./confidentiality-plan-14-policy-suggestions.md)
(the detectors in `secret-detectors.ts`, the quarantined classifier child
of §14.10) and [`policy-surface.md §8`](../ui/policy-surface.md) §3
(anyone may tighten, only a human may relax).

## 0. At a glance

- **The default.** The human writes the prompt and knows what is in it, so
  the prompt reaches the model as typed.
- **The safeguard.** A person with little security awareness pastes a key,
  a customer's personal data, or a project's code name. The prompt filter
  catches those before the request leaves the machine. It is a set of
  **detectors** (filters) that only report findings, and a **policy** that
  maps each finding's category to an action (`mask`, `redact`, `ask`,
  `block`, `log`).
- **Pluggable.** A filter is built in, a declarative **pattern pack**
  (regexes and keyword lists, YAML), or an **out-of-process plugin** (one
  JSON request in, one JSON answer out, a confined child). Third-party code
  never runs inside the arbiter.
- **One implementation.** The proxies only cut the request into segments by
  origin and apply the answer; the arbiter runs the filters and the policy
  (`filterPrompt`).
- **On by default:** the registered-value filter, action `mask`: a value
  Mandu already holds as a secret is replaced by the symbol it has
  everywhere else.
- **A classifier model is local or inside the organization's perimeter,**
  never an outside model: it reads the raw prompt (§5).

## 1. The problem

Before this plan, user-role text reached the model raw on every wire: the
anthropic-proxy walked `tool_result` blocks only (the side-call scan ran only
on requests that advertise no tools); its OpenAI-family wires for OpenClaw
and OpenCode never wrote a change to user text back; the openai-proxy (Codex)
read only tool outputs; and nothing on the security path told the human's
text from the text the harness adds (only display heuristics did). So a
registered key pasted into a prompt reached the provider, and so did anything
else the human pasted. Plan 13 §4.8 had decided to scan the prompt for
registered values; the side-call fix (confidentiality.md, the side-call
section) had left the human's prompt alone as an open product decision. This
plan takes that decision (§2) and makes the scan one filter among several.

## 2. Decisions (2026-10-02)

1. **The prompt is trusted by default.** The human is aware of what they
   type; the default reaches the model as typed.
2. **The registered-value filter is on by default, action `mask`.** It
   matches only values Mandu already protects, so it cannot misfire on
   unrelated text, and the value already has a symbol, so nothing new is
   stored. The one carve-out from decision 1. Short or low-entropy values
   are skipped in the prompt (§4.1), so a `DB_PASSWORD=postgres` does not
   mask the word "postgres".
3. **Findings that are not registered values default to `redact`;** `mask`
   is opt-in per category, because it stores the found value in the symbol
   table (Plan 14 §7 declined to store found values).
4. **Third-party filters run only as out-of-process plugins,** never loaded
   into the arbiter.
5. **Design and implementation are public** (`docs/design/`, the arbiter,
   the proxies). Organization packs are data the organization ships.
6. **A classifier model is local or inside the perimeter** (§5).
7. **Switches in `policy.yaml`, patterns in pack files** (§6).

## 3. Architecture

```
 agent ──HTTP──▶ model-API proxy                         arbiter
                 ┌─────────────────────────┐   filterPrompt   ┌───────────────────────────┐
                 │ segmenter (per wire,    │ ───────────────▶ │ cache (segment hash)       │
                 │ per agent): human /     │                  │ filters: built-in, packs,  │
                 │ harness / side-call     │ ◀─────────────── │   plugins (child process)  │
                 │ apply: replace spans,   │   per-span        │ policy: category → action  │
                 │ hold, refuse            │   decisions       │ symbols, events, Inbox     │
                 └─────────────────────────┘                  └───────────────────────────┘
```

### 3.1 Segments and their origin

Each proxy cuts the user-role text of a request into **segments** and tags
each with an origin:

| Origin | What | Filters |
|---|---|---|
| `human` | text the human typed (the newest user turn's free text, and earlier turns on resend) | the policy's filters (§4, §6) |
| `harness` | `<system-reminder>` blocks, `<environment_context>`, `AGENTS.md` / `CLAUDE.md` text (also OpenCode 2's nested `Instructions from: <path>` message, §13.6 item 20), IDE context the harness adds | the registered-value floor, always; also the policy's filters, with `block` and `ask` acting as `redact` (§13.3 item 1) |
| `side-call` | a request the harness makes on its own (no tools advertised: title, quota probe, WebFetch summarizer) | the registered-value floor, always; also the policy's filters, with `block` and `ask` acting as `redact` |
| `tool` | `tool_result`, `function_call_output` | unchanged: the existing ingress path |

The segmenter's rules live per agent, beside each proxy's `GateSurface`
(§13.1 item 7). **Fail direction: a segment the rules cannot place is not
`human`.** The registered-value floor is exact, so applying it to text that
was in fact the human's costs nothing. The policy's filters run on every
segment, because the human's own text reaches the model inside harness and
side-call text too (a title side call quotes the prompt), but only a `human`
segment can be refused or held. This keeps the WebFetch class of leak closed
whatever the prompt policy says: a page or a tool output pasted into user
text by the harness is never trusted as the human's.

**Where "placed" is the remainder (2026-10-18).** OpenClaw's human text
carries a marker (its wall-clock envelope) and an unknown agent has no
`human` segment, so for them the rule holds as stated. Claude Code's,
OpenCode's and Goose's typed text carries none: their segmenters place as
the human's what is left of a user text once every known harness shape (tag
spans, whole-message instructions, a text beside a tool_result, OpenCode's
pre-read parts and nested instructions) is cut out. A harness shape a new
agent version adds therefore lands in `human` until a rule names it, as
OpenCode 2's nested instruction message did (§13.6 item 20). That
mis-placement is the stricter side for the model (a `block` refuses, an
`ask` holds; the registered values stay masked on every origin), but it
asks the human about text they did not type and offers to send it as
written. Making the remainder harness would leave these agents no `human`
segment at all (no `ask`, no `block`), so the remainder rule stays and each
new harness shape gets its own rule with a captured request.

The registered-value floor on harness and side-call segments is **always
on** in `secrets` mode and cannot be turned off by `prompt_filters:`; it is
ingress of data the human did not write.

### 3.2 The arbiter op

```ts
// arbiter/ipc/protocol.ts
interface FilterPromptRequest {
  op: "filterPrompt";
  session: string;
  agent: string;                 // "claude-code", "codex", ...
  segments: { id: string; origin: "human" | "harness" | "side-call"; text: string }[];
  holds?: boolean;               // the caller can wait out an `ask` hold (§13.6)
  progress?: boolean;            // the caller understands progress frames (§13.5 item 11)
  dryRun?: boolean;              // human plane only (§8.1)
}
interface FilterPromptResult {
  segments: {
    id: string;
    action: "pass" | "rewrite" | "hold" | "block";
    text?: string;               // for "rewrite": the text with spans replaced; for "block": the safe text
    hold?: { approvalId: string; timeoutMs: number };
    reason?: string;             // for "block": shown to the human by the agent
    findings: { start: number; end: number; category: string; filterId: string; action: Action; symbol?: string }[];
  }[];
}
```

The proxy applies the result; it holds no filter logic and no policy. One
implementation serves the anthropic-proxy (Messages and the OpenAI-family
wires) and the openai-proxy (Codex Responses and Chat). Fail-closed: an op
error or timeout on a segment with any enforcing filter answers `block` for
the request (a 502), unless every enabled filter that would run on it is
`on_error: pass` (§4.4).

### 3.3 The cache

Every request resends the conversation. The arbiter caches the result per
segment, keyed by the text's hash, its origin, the axis, the policy digest,
the packs digest and the registered set's content version (§13.1 item 4), so
each human turn is scanned once, a symbol minted for a span is the same on
every resend (the model's context stays stable, and prompt caching at the
provider keeps working), and a classifier is called once per new turn. A
policy or pack change changes the digest and rescans. A human segment of a
session whose own writes exempt a value (§13.10) is keyed by the session
and that exempt set as well, so its answer is never served to another
session.

## 4. Filters

```ts
// arbiter/prompt-filter/filter.ts
interface PromptFilter {
  id: string;                               // "registered-value", "key-shapes", "acme-pii"
  cost: "inline" | "model";                 // latency class
  scan(text: string, ctx: FilterContext): Finding[] | Promise<Finding[]>;
}
interface Finding {
  start: number; end: number;               // a span; the whole segment is [0, text.length)
  category: string;                         // dotted: "secret.registered", "secret.shape.github",
                                            // "pii.email", "acme.codename"
  confidence?: number;                      // classifiers only
  level?: ConfidentialityLevel;             // for mask: the symbol's level
}
```

A filter only **detects**. What happens to a finding is the policy's (§6).
That split is the extension point: a new filter adds categories, and nothing
it reports acts until a policy names the category, except the
registered-value filter's built-in default.

Overlapping findings are merged; the strictest action wins (`block` >
`ask` > `mask` > `redact` > `log` > `pass`).

### 4.1 Built-in filters

| id | What | Default | Code |
|---|---|---|---|
| `registered-value` | spans equal to a registered secret's value, a long line of a multi-line one, or one of its credential-shaped pieces | **on**, `mask` with the existing symbol | `registered-value-filter.ts`, `registered-values.ts`, `value-matcher.ts` |
| `key-shapes` | known credential formats (provider keys with checksums, private keys, URL passwords, credential assignments with entropy) | off | `key-shapes-filter.ts` over `locateSecretShapes` (`secret-detectors.ts`; the rules are [`secret-discovery.md`](./secret-discovery.md) §3.2 item 5) |

**The prompt floor for registered values.** In `human` segments a registered
value is skipped when it is shorter than 12 characters or its Shannon
entropy is under 3.0 bits per character (the `credential-assignment` gate of
`secret-detectors.ts`); the general floor `MIN_FINGERPRINT_LEN` = 8 stays for
every other path, but for a registered short password matched as a whole
token (2026-10-19, [`secret-discovery.md`](./secret-discovery.md) §2.9),
which the 12-character prompt floor still leaves out of human text. Skipped values are counted in the event (§8), never named.
The matcher is one pass over the text (§13.1 item 1), shared with the
tool-result backstop and the egress tripwire.

**What a raised row registers** (2026-10-12, §13.11). A tool result the
value backstop raised (a registered secret found in a result the path rules
call public) is masked whole and registered like any secret result, but
when the arbiter can tell its level is that raise alone, its row keeps as
pieces only the long lines a secret was found in, any line with a
credential shape, its credential-shaped spans and its whole value. Its other
long lines (a heading, a log line) are no piece, so a later unrelated result
that shares one is not masked by it.

**What a path row registers** (2026-10-17, §13.12). A shell result masked
whole only because its command names a secret path (the path-derived
precaution) gets a like narrowing when the arbiter can prove the named
files' bytes are covered elsewhere (the call's tree read no secret raw and
every named secret file is registered as it is on disk): a long line stops
being a piece only when a plain file the command names holds it. Then a
batched read
(`.env`, a script and the meeting notes in one command, also after a
leading `cd` to the app's folder, absolute or relative, 2026-10-19) no
longer makes the notes' lines fingerprints.

### 4.2 Pattern packs

A pack is a YAML file of detectors, no code:

```yaml
# /etc/mandu/prompt-filters.d/acme.yaml   (a detached acme.yaml.sig signs it)
pack: acme-dlp
version: 3
patterns:
  - id: kr-rrn
    category: pii.national-id
    regex: '\b\d{6}-[1-4]\d{6}\b'
    check: kr-rrn-checksum      # optional built-in validator: luhn, kr-rrn-checksum, iban, ...
  - id: card
    category: pii.payment-card
    regex: '\b(?:\d[ -]?){13,19}\b'
    check: luhn
keywords:
  - category: acme.codename
    match: word                 # word | substring; case-insensitive
    salt: 9f2c…                 # keywords stored as salted SHA-256, not plain text
    max_words: 3
    hashes: [5d41…, 7c21…]
```

- **Regexes** run under a linear-time engine (RE2 semantics: re2js, a
  pure-JavaScript port with no native build), so a pack cannot stall the
  arbiter with catastrophic backtracking; a pattern the engine rejects fails
  the pack's validation.
- **Validators** (`check:`) are built in and named; a pack cannot ship code.
- **Keywords** may be stored hashed: an organization's list of project names
  is itself confidential, and a hashed list can sit on every laptop without
  disclosing it. The filter hashes each word (and each n-gram up to
  `max_words`) of the segment with the pack's salt. Plain keywords are
  allowed for a person's own pack.
- **Signatures** are detached `<file>.sig` files (Ed25519 over the exact
  bytes, verified against the trusted keys in `~/.mandu/pack-keys/`, the
  consumer packs' format); the details are §13.2 item 2.

### 4.3 Out-of-process plugins

A plugin is an executable named in a pack (`plugin: { exec: …, sha256: …,
cost: model, endpoint: required }`). The arbiter runs it as a one-shot child,
the way the policy model's classifier runs (Plan 14 §14.3):

- one JSON request on stdin, one JSON answer on stdout, stderr discarded
  (protocol `mandu-prompt-filter/1`, §13.5 item 4);
- the answer is checked against a closed shape: spans inside the text,
  categories from the pack's declared list, nothing else; any deviation is a
  filter error (§4.4);
- confined: the guard limiting its network to the cleared endpoint (§5),
  Landlock and the seccomp deny filter, an environment allowlist, a scratch
  directory, a deadline (§13.5 items 7 to 10);
- the program is pinned by path and SHA-256 in the pack, as readers are
  (Plan 13 D8), and so are its script and every other file it loads
  (`modules:`); it runs from verified private copies and reads nothing of
  the directory it was installed in (§13.5 items 6, 7);
- it never reads a registered value (§13.5 item 3).

This is the path for Presidio, a vendor DLP engine, or a classifier model.
Third-party code never loads into the arbiter (decision 4).

### 4.4 Failure

Each filter declares `on_error: block | pass` in the policy (§6). The default
is `block` when any of the filter's categories maps to an enforcing action
(`mask`, `redact`, `ask`, `block`), and `pass` when all map to `log`. A
timeout is an error. The registered-value filter cannot fail independently of
the arbiter; an unreachable arbiter fails the request closed, as every proxy
path does.

## 5. A classifier model

A classifier reads the raw prompt, so its endpoint must be cleared for the
most sensitive thing the prompt may hold:

- **Allowed:** a `models:` entry with `local: true` (Plan 11 D2: never
  inferred from loopback; the proxy's own URL refused), or an endpoint the
  administrator's layer places inside `perimeter:` (Plan 12), for example an
  in-house model server or a DLP service under contract.
- **Refused:** anything else, at policy validation and again at spawn: the
  plugin's network confinement opens only the cleared endpoint's address.
  Sending the prompt to an outside model to ask whether it may go to an
  outside model defeats the filter.
- **Shape.** Tool-less, history-less, a fixed system prompt, a closed answer
  (categories and spans), as Plan 14 §14.10's classifier.
- **Which text it reads (amended 2026-10-03, §12).** Every segment, like
  every other filter: the human's prompt, and harness and side-call text
  too, because the human's text reaches the model inside them. The answer is
  cached by the segment's hash (§3.3), so a resent reminder costs one call.
  Reading the human's prompt alone would have let a classifier's finding
  through in the title request. Harness text may try to steer the classifier
  toward a miss; that is no worse than not scanning it, and the endpoint is
  cleared for the raw prompt either way.
- **Cost.** A small local model adds roughly 0.2 to 2 s per new human turn
  warm, more when it loads; the cache keeps resends free. A deadline and
  `on_error` decide what a slow model costs.

## 6. Policy: switches in `policy.yaml`, patterns in packs

```yaml
# ~/.mandu/policy.yaml
prompt_filters:
  filters:
    registered-value: on            # the default; "off" is a relaxation
    key-shapes: on
    acme-dlp: on                    # a pack, by its `pack:` id
    acme-classifier: { on: true, endpoint: ollama-local, on_error: pass }
  actions:                          # category (prefix match, longest wins) → action
    secret.registered: mask         # the default
    secret.shape: redact
    pii: redact
    pii.payment-card: block
    acme.codename: ask
  exceptions:
    - category: pii.email
      match: "*@example.com"
  signed_only: false                # true: unsigned packs are ignored
```

- **Why split.** The switches are law: they need `policyDelta`'s
  tighten/relax proof, the Inbox for a relaxation, and the administrator's
  layer. Packs are data: they can be large, are versioned, are shipped by an
  organization or a vendor, and can be signed. Packs live in
  `~/.mandu/prompt-filters/*.yaml` and `/etc/mandu/prompt-filters.d/*.yaml`.
- **Monotonic split** (`policy-delta.ts`, the `prompt-filters` facet):
  turning a filter on, a stronger action (`log` < `redact` < `mask` < `ask` <
  `block`), and a new pattern in a pack are tightenings, which the agent may
  make. Turning a filter off, a weaker action, an exception, a removed
  pattern, and any change to a classifier's `endpoint:` are relaxations,
  only the human's. A pack's content is compared by pattern id and digest,
  so editing a regex counts as remove-then-add.
- **The administrator's layer.** `admin-layer.ts` admits `prompt_filters` in
  `/etc/mandu/policy.d/`. Merge is stricter-wins per category; a filter or
  action the administrator sets with `locked: true` cannot be relaxed by the
  person, and the dashboard says who set it (§13.2 item 5).
- **Modes.** In `off` mode every filter logs only. The floor of §3.1 runs in
  `secrets` mode. The integrity axis does not read this section.

## 7. Actions

| Action | Effect on the span | Stored | The human |
|---|---|---|---|
| `pass` | unchanged | nothing | |
| `log` | unchanged | the finding (category, filter, no value) | dashboard, SIEM |
| `redact` | `[redacted: pii.email]` | nothing | sees the redaction in the transcript; the original is in their own terminal |
| `mask` | a symbol (`$MDU:…`); a registered value gets its existing symbol, another finding a new symbol at the category's level (default `no-model`) | the value, in the symbol table, for a new symbol | sees the original through the reply filter and the dashboard; the model may route the symbol into a tool call, released at its bindings like any secret |
| `ask` | the request is held; the Inbox shows the category and the span (the human's own text) with *send*, *mask*, *cancel* | the verdict, once (this message) or this session | answers in the dashboard; no answer within the deadline means `mask` (`redact` for a category without a level) |
| `block` | the request is refused with a reason the agent shows; a later resend carries the span as `[blocked: <category>]` | the finding | sees why |

- **Overriding a finding.** The human lets a span through from the Inbox or
  the dashboard, once or for the session, never in band (a phrase in the
  prompt that unlocks the filter would be the attacker's too; Plan 13 §9
  R5). A locked administrator rule cannot be overridden, and a registered
  value never goes as written (§13.6 item 9). Under a locked `ask` rule the
  human answers one message at a time, never for the session (§12,
  2026-10-04; §13.6 item 6).
- **`ask` and the agent's timeout.** The proxy holds the HTTP request; the
  hold deadline (default 30 s) stays inside every supported agent's client
  timeout. The verdict is keyed by the category and a keyed digest of the
  span (§13.6 item 4), so a resend of the same turn needs no second answer.
- **Oracle and tripwire.** The anthropic-proxy's trusted-context haystack
  (text treated as forwarded raw, which the §9 oracle and the backstop
  exclude) leaves out the spans a filter replaced, and keeps a span the human
  sent as written.

## 8. Observability

- An event kind, **`prompt_filter`** (`dashboard/src/event-model.ts`
  `PromptFilterDetail`), per segment with a finding: origin, filter,
  category, action, symbol if any, counts of skipped registered values, the
  keyed references of §13.6; and one with no findings when a segment's
  earlier finding no longer applies on a resend (§13.7 item 10). Never the
  value or the segment's text; the
  dashboard resolves a symbol on demand, on the human plane, as it does for
  the transcript. The side-call masks emit it too.
- The **SIEM exporter** (the enterprise component) forwards it; an
  organization that turns on `log` for every category first sees what would
  be caught before it enforces (§13.9; siem-integration.md §6.6).
- The **dashboard** shows "one value in your prompt was hidden from the
  model" with the category and the way to let it through (§13.7), and the
  product page keeps its plain vocabulary.

### 8.1 Configuring it in the developer dashboard (2026-10-02)

The developer inspector (`/dev/`, dashboard.md §4.31) has a **Prompt
filters** panel (its `prompt-filters.js`, served by
`/api/prompt-filters/*`). The product page's Settings › Prompt filters
(§13.7) reuses its server projections.

| Part | Shows | May change |
|---|---|---|
| **Filters** | every filter: built-in, each pack, each plugin; on or off; who set it (you, the administrator, the default); `on_error`; a plugin's pinned program, its model, its last run, latency and confinement legs | on/off, `on_error`, the classifier's model (only from the cleared list, §5) |
| **Actions** | the category → action table, with the effective value after the administrator's layer and a lock mark | an action per category; a new category row |
| **Exceptions** | the exception list | add, remove |
| **Packs** | each pack: id, source, version, signed or not, pattern and keyword counts; patterns with their regex and validator; hashed keywords as a count only | in a person's own unsigned pattern pack: add, edit, remove a pattern or a plain keyword; an administrator's, a signed or a plugin pack is read-only |
| **Test bench** | paste text, pick an origin (`human`, `harness`), see the findings, the action each gets, and the text the model would receive | nothing |
| **Held for your answer** | prompts held by `ask`, with the found text (human plane only) | send as written (this message or the session), send masked, cancel |
| **Recent findings** | the session's `prompt_filter` events: category, filter, action, symbol; resolved to the original on demand | let a finding through (once / this session) |

- **One write path.** Every change is a typed `PolicyEdit`
  (`set-prompt-filter`, `set-prompt-action`, `remove-prompt-action`,
  `add-prompt-exception`, `remove-prompt-exception`) checked by
  `policyDelta`'s prompt facet (§6), and pack edits go through the arbiter's
  `promptPackEdit` on the admin channel (§13.2 item 9). The dashboard is the
  human's channel, so a relaxation made there applies, after a confirm, and
  is audited; a change the administrator locked is refused with who locked
  it. The agent cannot reach these routes.
- **A regex is validated before it is saved:** the RE2 engine must accept
  it, and the panel shows its match counts over the test bench text and a
  fixed corpus of ordinary prose, so a pattern that matches everything is
  seen before it masks every prompt.
- **The test bench is a dry run on the human plane.** `filterPrompt` with
  `dryRun: true` mints no symbol (a `mask` shows as `$MDU:<would-mint>`, a
  registered value as its existing symbol), writes no event or cache entry,
  stores no text. On the data plane it would let the agent's processes test
  guesses against the registered values and the organization's hashed
  keywords, so it is refused there.
- **Live effect.** A saved change takes effect on the next request (the cache
  key includes the policy and pack digests, §3.3); the panel shows the digest
  the arbiter is enforcing.

## 9. What this does not do

- **Integrity.** The prompt stays TRUSTED on the frozen axis; no filter
  changes classification.
- **Unregistered secrets with the default policy.** A key Mandu does not know
  reaches the model unless `key-shapes` or a pack is on; Plan 14's scans
  remain the answer for secrets nobody registered.
- **The transcript.** Claude Code writes the raw prompt to
  `~/.claude/projects/`; a tool that reads it brings the text back as a tool
  result, where the tool-result path and its registered-value backstop apply.
  A redacted or masked non-registered finding is not in that path: the filter
  does not register it, so a tool read of the transcript returns it raw.
  Stated, not fixed: the transcript is the human's file, and labelling it is
  a policy the human may write.
- **What the agent itself echoes.** The agent's TUI shows the prompt as
  typed; that never leaves the machine.

## 10. Relation to earlier decisions

| Record | Change |
|---|---|
| Plan 13 §4.8, its §8 prompt rows, §7 step 7 | superseded: the prompt is trusted by default; the registered-value scan is this plan's default filter |
| Plan 14 §1 (masking by shape at run time rejected) | an explicit, scoped exception: on the human's own prompt only, opt-in, with the finding shown to the human at once and overridable. Plan 14 §1 still governs tool results and files |
| Plan 14 §7 (found values not registered) | kept as the default: non-registered findings `redact`; `mask` is the person's or administrator's opt-in |
| confidentiality.md, the side-call note | its open product decision is this plan's decision 1; the side-call scan runs under `filterPrompt` (§3.1) |

## 11. Build order

Each phase landed with unit tests, a stack test over the production client,
and an e2e per proxy asserting that no registered value reaches the fake model
raw. All four are built.

1. **Plumbing and the default filter.** The segmenter per wire and agent
   (Claude Code, Codex, OpenClaw, OpenCode); `filterPrompt`; the cache; the
   `registered-value` filter with offsets, the prompt floor and the one-pass
   matcher; the `mask` action; the side-call scan moved under it; the
   OpenAI-family write-back for user text and the openai-proxy's
   user-message path; the tripwire exclusion; the `prompt_filter` event. The
   developer panel, read-only (§13.1).
2. **Patterns and policy.** `key-shapes` with offsets; YAML packs with RE2,
   validators and hashed keywords; `prompt_filters:` with its validator,
   loader and `policyDelta` facet; the administrator's layer; `redact`,
   `block`, `log`; the panel's editing (§13.2 to §13.4).
3. **Plugins and the classifier; `ask`.** The plugin protocol, confinement
   and pinning; a reference classifier plugin over a `local: true` model;
   `ask` with the Inbox hold and "let it through" (§13.5, §13.6).
4. **Surfaces.** The product page (Settings › Prompt filters, the Inbox card,
   the note under the person's message), `mandu why` for a prompt finding,
   the SIEM mapping (§13.7 to §13.9).

## 12. Decisions recorded here

| Date | Decision | Section |
|---|---|---|
| 2026-10-02 | The human's prompt is trusted by default | §2 |
| 2026-10-02 | The registered-value filter is on by default, action `mask`, with a prompt floor (12 characters, entropy 3.0) | §2, §4.1 |
| 2026-10-02 | Non-registered findings default to `redact`; `mask` is opt-in | §2, §7 |
| 2026-10-02 | Text not placed as the human's always gets the registered-value floor | §3.1 |
| 2026-10-02 | Filters detect, the policy acts; third-party filters only out of process | §4 |
| 2026-10-02 | A classifier model is `local: true` or inside the perimeter | §5 |
| 2026-10-02 | Switches in `policy.yaml`, patterns in packs; the administrator's layer may lock | §6 |
| 2026-10-02 | The developer dashboard configures it through typed `PolicyEdit`s; the test bench is a human-plane dry run | §8.1 |
| 2026-10-02 | The policy's filters run on every segment, not only the human's (the human's text reaches the model in title and token-count requests too); on `harness` and `side-call` text `block` and `ask` act as `redact`, since the harness's own request is not refused for text the human did not send | §3.1, §13.3 item 1 |
| 2026-10-03 | Plugins and classifiers also run on every segment, cached by hash; §5 amended | §5 |
| 2026-10-03 | A plugin runs only under `mandu-net-guard` (its network limited by address to the cleared endpoint); without it the plugin does not run and its `on_error` applies. The Landlock filesystem and TCP-port legs, the namespaces and the seccomp deny filter are probe-gated and may degrade, with a note | §4.3, §13.5 |
| 2026-10-03 | What a plugin may read and write: read-only `/usr`, `/lib*`, `/bin`, `/sbin`, `/etc` and the plugin's own directory (amended 2026-10-07: its verified copies instead of its own directory); one fresh scratch directory per run; no home. Environment: `PATH`, `LANG`, `LC_ALL`, `HOME` = `TMPDIR` = the scratch, the endpoint's URL and the cleared `models:` entry's token variable only. Plus `no_new_privs`, a new session, PID/IPC/UTS namespaces where available, the seccomp deny filter. No pack-declared extra paths | §4.3, §13.5 |
| 2026-10-03 | A plugin is pinned by `exec` + `sha256` (and an optional `script` + `script_sha256` for an interpreter); the arbiter runs the verified bytes from a copy in its private directory and re-checks the pin at every spawn (a mismatch is a filter error). Modules the plugin imports stay unpinned (stated; closed 2026-10-07, below) | §4.3, §13.5 |
| 2026-10-03 | Setting or changing a classifier's `endpoint:` is a relaxation, checked at validation and again at spawn. A plugin may only ADD findings (offsets inside the text, categories from its pack's declared list, never a built-in prefix such as `secret.registered`); a level it reports is ignored. Plugin packs are files only: read-only to the pack editor, no plugin edit for the agent | §5, §6, §13.5 |
| 2026-10-03 | `ask` holds only a `human` segment, only for an attested caller that can wait; "once" is the message (wherever it is resent), "this session" the span in the session; the deadline runs from the first sighting; a registered value and a finding under a locked non-`ask` row never go as written | §7, §13.6 |
| 2026-10-03 | A plugin never reads a registered value: each is replaced by `█` (offsets kept) before the plugin sees the segment, since a classifier is a model and a `no-model` value reaches none | §13.5 item 3 |
| 2026-10-03 | The product page's Settings › Prompt filters changes only the action per kind and the exceptions; the switches, packs, plugins and test bench stay in the developer view | §13.7 |
| 2026-10-07 | A plugin's other files are pinned too: `modules:` lists each by path and SHA-256 (at most 256, each under the script's directory, else the program's), checked at every spawn like the program and copied with the script into one verified tree, so a relative import loads the copy. The plugin no longer reads the directory it was installed in, so a file it did not pin cannot load (a plugin that loaded one now fails, under its `on_error`, until its pack pins it). A file over 512 MiB (a model's weights) cannot be pinned; such a plugin serves its model over its endpoint | §4.3, §13.5 items 2, 6, 7 |
| 2026-10-07 | The reference classifier's chunks overlap by 1000 characters: a span of up to 1000 characters is read whole by one call; findings are one per span; about one sixth more input per cut | §13.5 item 14 |
| 2026-10-07 | Releases ship the reference classifier and its pack writer (package assets); `mandu policy classifier-pack` prints the pack from the copy the install ships | §13.5 item 15 |
| 2026-10-04 | Under a LOCKED administrator's `ask` row (any locked `ask` row that covers the category, even when another row decides the action) the human answers a hold for THIS MESSAGE only, never for the session: a session answer on any route (`resolvePromptHold`, an Always on `resolveEgressApproval`, a session `letPromptFindingThrough`) is REFUSED with the reason, never downgraded to once (the human chose the session and must see it was not given); a session verdict stored before the lock is not consulted under it; the hold says `onceOnly` so the front ends offer no session answer. Otherwise a session answer would stop the administrator's locked rule from asking for the rest of the session | §13.6 items 6, 9, 15, 18 |
| 2026-10-18 | An agent that disconnects while its prompt is held ends the proxy's wait at once: no further ask (not the last one either), nothing forwarded, no answer written. The hold is NOT retired: it stays pending in the Inbox like every unanswered ask (pending asks are not expired), and an answer given later decides the agent's retry, which carries the message again. Until then the proxy polled to the deadline and then forwarded the request (masked, or as the human answered) to a model whose answer nobody read | §13.6 item 13 |

## 13. As built

### 13.1 Phase 1 (2026-10-02)

Code: `arbiter/prompt-filter/` (`value-matcher.ts`, `registered-values.ts`,
`registered-value-filter.ts`, `engine.ts`), the `filterPrompt` and
`promptFilters` ops (`arbiter/ipc/server.ts`),
`interceptors/{anthropic,openai}-proxy/src/prompt-filter.ts`.

1. **The matcher.** An Aho-Corasick automaton over the first 16 UTF-16 code
   units of every pattern (a whole value of 8+ characters, a line of 24+),
   each key hit verified with `startsWith`: exactly the answer of one
   `includes` per pattern, with a trie that stays small when a row is a whole
   document. Rebuilt when the symbol table changes (a per-map generation
   that every mutating function bumps). The value backstop and the egress
   tripwire run on it with their semantics unchanged; randomized tests pin
   them to the per-row answers (`value-matcher.test.ts`).
2. **What "registered" means.** Every active secret row the value backstop
   counts, at any secret level. Besides its whole value and long lines, a
   row matches by its pieces (plan 10 §11.15): the value without its final
   line terminator, and its credential-shaped spans of 12+ characters at
   3.0+ bits a character. A row named as Codex's whole result has no line
   fingerprint inside the head Codex's runtime wrote (plan 10 §11.14), and
   a registered file's row none for a line its own structured twin carries
   verbatim with no secret in it (plan 10 §11.8).
3. **Mask.** A span that is exactly one registered value becomes that row's
   symbol (the strictest row when two hold the same value). A long line of a
   multi-line secret, or overlapping values, is minted once at the strictest
   level through `symbolize` (tool `prompt_filter`, or `side_call`), so the
   reuse key keeps it stable. The rewritten text is scanned again; a value
   that survives masks the segment whole.
4. **The cache key** is (text hash, origin, axis, policy digest, packs
   digest, the registered set's content version). A value registered later
   changes the version, so an earlier turn that holds it is masked on the
   next request.
5. **Dry run.** Any `dryRun` other than absent or `false` is a dry run and is
   refused on the data socket; it reads and writes no cache entry. The live
   op is a proxy op.
6. **Modes.** With the confidentiality axis OFF every finding is `log` and
   nothing is rewritten.
7. **Segment rules** (§3.1), each a positive placement, everything else
   harness: Claude Code places the text outside its tag spans
   (`<system-reminder>`, the slash-command record, `!` bash mode, IDE
   context, the prompt-submit hook; an unclosed tag runs to the end) and
   outside its whole-message instructions (compaction summary, suggestion
   mode, away recap, the local-command caveat, an interrupt marker);
   OpenClaw places only the text after its last wall-clock envelope;
   OpenCode places text outside the tag spans, outside a pre-read file
   part and the part after it, and outside OpenCode 2's nested
   `Instructions from:` message (§13.6 item 20); Codex places text outside its runtime context
   (`<environment_context>`, AGENTS.md, `<user_instructions>`,
   `<user_shell_command>`, `<turn_aborted>`, the compaction hand-off). A text
   in the same message as a tool_result is harness. The agent comes from the
   session's gate surface; an unknown one places nothing as human. The
   openai-proxy's Chat Completions route gets Codex's rules only when the
   request carries Codex's runtime context. Program output carried as user
   text never reaches the segmenter (2026-10-05): Claude Code's bash-mode
   output block (`<bash-stdout>…<bash-stderr>…`) and OpenCode 2's
   background and user-shell notices are read as their shell's tool
   result before the filter runs (anthropic-proxy `opencode-background.ts`;
   supported-agents.md §2.3 items 6 and 9, §2.4); the `<bash-input>`
   command stays a harness span here. Codex's `<user_shell_command>` record
   is read the same way by the openai-proxy (`user-shell.ts`, §2.4): its
   text part is emptied for the filter, which still reads the message's
   other parts.
8. **Side calls** mask the registered value's span, not its whole line; the
   `[mandu:secret]` note still follows the text.
9. **Events.** The proxies emit `prompt_filter`, one per segment with a
   finding or a skipped value, deduplicated per session and segment so a
   resend does not repeat it; never a value or the segment's text. (Since
   phase 4 an outcome that changes is recorded again, and one gone records
   an event with no findings: §13.7 item 10.)
10. **Failure.** An op error or a missing answer refuses the request (502).
11. **The openai-proxy has no trusted-context haystack**, so there is no span
    to exclude there.
12. **End to end per agent family** (the real agent CLIs against a scripted
    model, the `replay-drill` kind): the `LIVE prompt filter` tests of
    `claude-prompt-filter.test.ts` and `codex-prompt-filter.test.ts`, and the
    `prompt-secret` scenario of `openclaw-e2e.test.ts` and
    `opencode-e2e.test.ts` (property `model-ingress/prompt`). Also
    `openai-route.test.ts` and `tests/stack/web-fetch-secret-ingress.test.ts`
    (a registered value on a fetched page reaches the provider as its symbol
    on the OpenAI-family side calls).

### 13.2 Phase 2, the arbiter (2026-10-02)

Code: `arbiter/prompt-filter/` (`policy.ts`, `packs.ts`, `regex.ts`,
`validators.ts`, `key-shapes-filter.ts`, `pack-edit.ts`, `engine.ts`),
`locateSecretShapes`, `admin-layer.ts`, the validator, `policyDelta`'s
`prompt-filters` facet and the typed edits (`policy-edit.ts`).

1. **The regex engine** is re2js (linear time, no backreferences or
   lookaround; MIT; no native build at install). Offsets are UTF-16 code
   units. A pattern reports at most 256 matches per text; an empty match finds
   nothing.
2. **Packs.** The signature is a detached `<file>.sig` (an inline field would
   need a canonical form to sign; one is refused with that advice). A keyword
   hash is hex SHA-256 of `<salt>:<keyword>`, the keyword normalized to its
   words, lowercased NFKC, one space apart (`hashKeyword`); since a hash hides
   a phrase's length, a hashed group says `max_words` (default 3, at most 8),
   and hashed keywords match whole words only. A pattern or keyword group may
   set `level:` (what a `mask` mints at; default `no-model`). A pack that does
   not validate is refused WHOLE and named; an id an earlier file or a
   built-in took is refused; a pack does nothing until `prompt_filters`
   turns it on. The directories are re-read when their signature (names,
   sizes, mtimes, inodes, `.sig` files, keys) changes, checked at most once a
   second.
3. **`signed_only`** applies to the person's packs only (the administrator's
   directory is trusted by its location). Turning it on is a relaxation
   (patterns stop running).
4. **Validation.** `locked` is refused in the person's file; an action the
   engine does not know is read as `block`, never as less.
5. **The administrator's layer.** A file in `/etc/mandu/policy.d/` may set
   `prompt_filters:` (filters, actions, exceptions; not `signed_only`) and
   `locked: true` on a filter or an action row. Unlocked, its rows are
   defaults the person may change. Locked, the effective value is the
   stricter of the two; a person's row under a locked prefix cannot weaken
   it; an exception on a locked category is not in force; a write that adds
   such a conflict is refused with "set by your administrator (<file>)"
   (`promptLockProblems`). Two administrator's files setting one filter or
   one category refuse the layer.
6. **Resolution.** A category's action is its longest prefix row's; with no
   row, `redact` (decision 3); the one built-in row is
   `secret.registered: mask`. The default `on_error` is `block` when any
   category the filter may report resolves to an enforcing action, and `pass`
   when all resolve to `log` or `pass`; a filter switched on that is not
   available defaults to `block`.
7. **The delta facet** compares the person's `prompt_filters:` before and
   after under the same administrator's layer, with resolved actions (a new
   sub-row is judged against what its parent gave); anything it cannot place
   relaxes.
8. **The typed edits** (`set-prompt-filter`, `set-prompt-action`,
   `remove-prompt-action`, `add-prompt-exception`, `remove-prompt-exception`)
   are not offered to a model and not refused on the data plane: the
   monotonic split decides, so the agent's tightening applies and its
   relaxation waits in the Inbox.
9. **Pack edits are their own op**, `promptPackEdit`, because a pack is a
   file outside policy.yaml: `set-prompt-pattern`, `remove-prompt-pattern`,
   `add-prompt-keyword`, `remove-prompt-keyword` (plain words), applied to a
   copy, validated by the loader's own rules and classified by §6. It is
   ADMIN-ONLY (the person's channel; audited as a `config_change`, `via:
   prompt-pack`). The agent gets no pack edit, not even an added pattern
   (§6 would allow it; deferred, fail-safe). A dry run returns each pattern's
   match counts over the ordinary corpus and the panel's sample. The write
   is atomic (`0600`, rename).
10. **Who reads what.** `promptFilters` (data plane) carries the switches
    with who set them, the action rows, the exceptions, each pack's location
    and COUNTS, refused files and lock conflicts: no regex and no keyword.
    `promptFilterPacks` (HUMAN plane) carries the patterns and plain
    keywords: from the data socket the agent would learn exactly what to
    rephrase around.
11. **The actions.** `redact` writes `[redacted: <category>]`; `mask` of a
    non-registered finding mints one symbol at the finding's level (tool
    `prompt_filter`); `log` reports. `block` answers the segment `block` with
    a reason naming the categories and filters, never a value, AND the
    segment's SAFE text (each blocked span as `[blocked: <category>]`, every
    other finding applied). A filter that cannot run under `on_error: block`
    answers `block` with NO text. Overlapping findings take the strictest
    action, reported under the category that set it.
12. **Where the policy applies:** see §3.1 and §13.3 item 1 (every segment;
    exceptions apply too).
13. **`key-shapes`** runs the scans' own rules (`locateSecretShapes`, beside
    `detectSecretShapes`, so the history scan's fingerprint does not move):
    every occurrence, by offset of the VALUE (an assignment's value, a URL's
    password, a private key's whole block), category
    `secret.shape.<shape>`, level `no-model`.
    `arbiter/test/component/key-shapes-misses.test.ts` redacts each value
    the older rules missed through a real arbiter.
14. **The cache key**'s policy digest hashes the effective configuration
    (filters with `on_error`, rows with locks, exceptions in force,
    `signed_only`, the floors) and the packs digest the usable packs' file
    hashes and signers.
15. (Superseded by §13.3 item 1.)
16. **Tests.** Unit: `prompt-filter-policy.test.ts`,
    `prompt-filter-packs.test.ts`, `prompt-filter-actions.test.ts`;
    component: `prompt-filter-policy-op.test.ts` (the data, human and admin
    channels, the pack editor, the monotonic split); stack:
    `tests/stack/prompt-filter-policy.test.ts` (each agent family's wire
    through the real proxies: a token redacted, a code name masked and
    restored on the human plane, a card that never reaches the model, a pack
    that cannot be loaded refusing the prompt).

### 13.3 Phase 2, the proxies and the agents (2026-10-02)

Code: `interceptors/{anthropic,openai}-proxy/src/prompt-filter.ts`
(`PromptBlocked`, `PromptBlockLedger`), `rewrite-request.ts`
(`RewriteBlocked`), `proxy.ts`.

1. **The policy runs on every segment.** The human's own text reaches the
   model OUTSIDE the segments placed as `human`: Claude Code's title request
   is a side call that quotes the prompt, `count_tokens` carries the
   conversation without tools, and a slash command's arguments or a `!`
   command sit in harness tags. With the policy on `human` only, a card the
   policy blocked in the main request reached the model in the title
   request. So every filter the policy turns on runs over `harness` and
   `side-call` text too; there `block` (and `ask`) act as `redact`, the
   registered-value floor stays `mask` whatever its switch says, and the
   exceptions apply. A heuristic filter may misfire on text the human did not
   write: a redaction, never a leak. A filter failure there blocks like
   anywhere else (fail-closed).
2. **`block` on the wire.** A blocked segment refuses the request with a 400
   in the wire's own error shape (Messages `invalid_request_error`, which
   Claude Code prints; Claude Code 2.1.289 first retries it once at once
   with another beta set, see item 3; the OpenAI shape for Codex and the
   routed OpenClaw and OpenCode wires). The message is the arbiter's reason,
   never a value. A 502 stays the answer for an arbiter that fails.
3. **Refused once, then the safe text.** The agents keep a refused message in
   their history and resend it with the next turn; refusing it again would
   leave the session stuck. So each proxy keeps a ledger (session, category
   and a SHA-256 of the span, never the span; bounded; in memory) of the
   blocked spans it refused: the first request that carries one is refused,
   a later one is forwarded with the SAFE text once the human has written
   after it (a human segment follows the blocked one in the request). A
   request in which the blocked segment is still the human's LAST segment is
   the same message again, the agent's own retry, and is refused again
   (2026-10-04: Claude Code 2.1.289 in its TUI retries a refused request at
   once with another beta set; the ledger counted that retry as the resend,
   forwarded it, and the human never saw the reason; found by the drill
   `conf-prompt-block`). The reason tells the human so. A token count is
   forwarded with the safe text and never refused. A block with NO safe text
   (a filter that could not run) is refused every time.
4. **Events.** A refused request still emits its `prompt_filter` events; a
   blocked segment forwarded later is `rewrite`, its findings still `block`.
5. **`log`** needs nothing of the proxies; **`redact`** is a `rewrite` like
   `mask`.
6. **End to end per agent family**: `LIVE prompt filter policy` in
   `claude-code.test.ts` and `codex.test.ts` (a token
   nobody registered reaches the model only as
   `[redacted: secret.shape.github-token]`; an AWS key id the policy blocks
   never reaches it and the agent shows the refusal), and the `prompt-policy`
   scenario of `openclaw-e2e.test.ts` and `opencode-e2e.test.ts`
   (`tests/lib/agent-prompt-checks.ts`). Stack:
   `tests/stack/prompt-filter-policy.test.ts` asserts the 400, the reason,
   the resend's `[blocked: …]` on each family's wire and a title side call's
   `[redacted: …]`. Proxies: `prompt-filter-block.test.ts` (the agent's own
   retry refused again). The replay drills `conf-prompt-block` (the refusal
   on the human's screen, nothing of the message reaching the model, the
   next turn carrying `[blocked: …]`), `conf-prompt-ask-send` (§13.6) and
   `conf-prompt-ask-locked` (§13.6 item 6) run the real Claude Code and Codex
   TUIs under the launcher against a scripted model (2026-10-04;
   test-reorganization.md §6.4, "The prompt filter's drills").

### 13.4 Phase 2, the panel's editing (2026-10-02)

Code: `dashboard/src/server/prompt-filter-routes.ts`,
`dashboard/src/arbiter-adapter.ts`, and the developer view's `prompt-filters.js`.

1. **One write path.** A switch, an action or an exception is ONE typed
   `PolicyEdit` per click, through the route Settings › Models uses
   (`applyAsHuman`: preview, refuse a loosening that was not shown, propose
   on the admin channel, approve at once). A relaxation is answered `confirm`
   with what it would let through; the panel resends with `expected` only
   after the person agrees. Recorded and undoable from History.
2. **Packs on their own path** (§13.2 item 9); the full listing comes from
   the human-plane `promptFilterPacks`, served only with the CSRF header and
   the admin session.
3. **The regex check** is the pack editor's dry run (§8.1).
4. **Locks.** A locked row shows who set it and has no control.
5. "Let a finding through", plugins and the classifier's endpoint came with
   phase 3 (§13.5 item 17, §13.6 item 17).

### 13.5 Phase 3, the plugins (2026-10-03)

1. **The asynchronous seam.** A filter's `scan` may answer a promise; the
   engine awaits every scan, scans segments in order so mints keep request
   order, and treats a rejected scan as a filter error under its `on_error`.
2. **Plugin packs** (`packs.ts`). A pack holds patterns and keywords OR a
   `plugin:` (`exec` + `sha256`, an optional `script` + `script_sha256`,
   optional `modules:` (each `{path, sha256}`, 2026-10-07, item 6),
   `args`, `cost`, `endpoint: required | none`, `deadline_ms` 100 to 30000,
   default 5000) with its `categories:` (each with an optional `level`). A
   plugin may not declare a built-in filter's category. Quote the hashes in
   YAML: an all-digit value would read as a number and refuse the pack.
3. **What a plugin reads.** Every registered value in a segment, at any level
   and below the prompt floor, is replaced by as many `█` as it has UTF-16
   code units before a plugin reads the segment (`engine.ts` `shield`), so
   offsets still match. A classifier's endpoint is a model, and a `no-model`
   value must reach no model; the registered-value floor masks those spans
   anyway, so the plugin loses nothing it could act on.
4. **The protocol** (`plugin-protocol.ts`): stdin `{"protocol":
   "mandu-prompt-filter/1", "filter", "segments": [{id, origin, text}],
   "categories", "deadlineMs", "endpoint"?: {name, url, wire, model?,
   tokenEnv?}}`; stdout `{"findings": [{segment, start, end, category,
   confidence?}]}` (at most 1 MiB, 10 000 findings). Any other key, an
   unknown segment, a span outside its segment or an undeclared category
   refuses the whole answer. A level is never read from the answer.
5. **One run per request** (`batchScans`): every segment the cache cannot
   answer goes to a plugin in one run (identical texts once), plugins side
   by side, at most two runs of one plugin at a time. A failure is NOT
   cached, so a plugin that timed out once (a model still loading) is asked
   again.
6. **The pin** (`plugin-pin.ts`). At every spawn each pinned file is read,
   hashed and compared with its pin (a stat comparison is not enough: a
   same-size rewrite within one timestamp tick keeps every stat field); the
   verified bytes are copied to `<state>/prompt-plugins/pinned/<sha256>/`
   (written from the very bytes the check hashed, renamed, hashed again) and
   the plugin runs from the copy. The check reads 1 MiB per awaited read and
   runs one at a time, so a cold check of a large pinned `node` never holds
   the arbiter's event loop (which once starved the progress frames of
   item 11 and failed the request closed).
   **Modules (2026-10-07).** Every other file the plugin loads (an
   interpreter's imports, a rules or word list) is listed under `modules:`,
   each by absolute path and SHA-256, at most 256, each under the
   directory of the file that loads it (the script, else the program; a
   path elsewhere, a duplicate or the script itself refuses the pack). At
   every spawn each is checked as the program is, and the script (else the
   program) and the modules are copied into ONE tree,
   `<state>/prompt-plugins/pinned/tree/<id>/`, at their paths below that
   directory, so `import './lib/rules.mjs'` loads the verified copy; `<id>`
   hashes every name and pin, so another module set gets another tree. A
   changed, swapped or missing module is a filter error (`on_error`). Until
   then the files beside the script loaded unpinned from the install
   directory, which stayed readable (a write there, by the agent say, could
   make a classifier find nothing). What a plugin loads from the system
   roots (`/usr`: an interpreter's standard library, a package installed
   there) is the system's and not pinned; a file over 512 MiB cannot be
   pinned. The panel's row lists the module pins.
7. **The confinement** (`plugin-confine.ts`), outermost first: bubblewrap
   (`--unshare-pid --unshare-ipc --unshare-uts --unshare-cgroup-try
   --die-with-parent --new-session --cap-drop ALL`, only the read roots, the
   tools and the scratch bound); `mandu-net-guard` (`--allow` the endpoint
   only: its literal address, `localhost` as both loopbacks, or the
   perimeter's networks; no endpoint, no allow at all);
   `mandu-landlock-apply --clean --seccomp-deny` (reads under the system
   roots and the plugin's verified copies only, never the directory it was
   installed in (2026-10-07; until then that directory was a read root, so
   its unpinned files loaded); read-write only the scratch; every TCP connect and bind denied in-kernel, so only the
   guard's own connect for the allowed address goes through). The applier's
   `--seccomp-deny` and `--seccomp-only` modes were added for this.
8. **The probe** (`plugin-probe.ts`) runs the composed wrap around a tiny
   program that must reach one loopback port and not another: the guard
   alone (required), then Landlock with the deny filter, then bubblewrap
   around them. A leg that fails is dropped and named in a note; a guard that
   confines nothing is caught.
9. **The endpoint.** The validator checks it against the effective `models:`
   (declared, `local: true`, not cloud-backed: `checkPromptEndpoints`), and
   the plugin re-checks it at every spawn (`resolveLocalEndpoint`). It must
   be an address, `localhost`, or a name inside the perimeter's networks that
   resolves from `/etc/hosts`: the plugin's own name lookups are denied (DNS
   is a channel too).
10. **The environment**: `PATH` (system directories), `LANG`, `LC_ALL`,
    `HOME` = `TMPDIR` = the scratch, `MANDU_PROMPT_FILTER_ENDPOINT` and the
    cleared entry's token variable; nothing else of the arbiter's.
11. **The proxies' wait: progress frames.** A plugin may run longer than the
    client's ordinary 5 s timeout, and an arbiter that never answers must
    still fail closed at 5 s. So `filterPrompt` asks for progress frames
    (`progress: true`): while the op runs, the arbiter writes `{id,
    progress: true}` every second on that connection, and the client re-arms
    its 5 s idle deadline on each, up to 60 s in all
    (`FILTER_PROMPT_TIMEOUT_MS`, above the longest plugin deadline); then it
    refuses. A client that does not ask gets no frame.
12. **The panel's data** (`promptFilters`): a plugin's row carries its pin,
    cost, model, deadline, runs, errors, last latency and the confinement
    legs with their notes. Never a prompt.
13. **Tests.** Unit: `prompt-filter-plugins.test.ts`,
    `prompt-filter-actions.test.ts` (the batch, the shield, failures not
    cached), `server-args.test.ts`. Component:
    `prompt-filter-plugin-op.test.ts` (over the real sockets: the cache, the
    private copy, the environment, every failure blocking, `on_error: pass`,
    a non-local endpoint refused). Stack:
    `tests/stack/prompt-filter-plugin.test.ts` (both proxies over the
    production client: the code name the classifier finds and a registered
    value reach the provider only as symbols, the classifier never reads the
    registered value, a missed deadline refuses the prompt). Sandbox:
    `tests/sandbox/prompt-plugin-confine.test.ts` (the real bins: only the
    cleared model reached, no file outside the roots, no port without an
    endpoint, the probe catching a guard that confines nothing).
14. **The reference classifier** (`plugins/local-classifier.mjs`, node
    built-ins only, so the pin covers all of it). It needs a model and speaks
    the entry's wire (`/v1/chat/completions`, which Ollama serves, or
    `/v1/messages`). Per segment, in chunks of at most 6000 characters cut at
    whitespace: one tool-less, history-less call, temperature 0, a fixed
    system prompt naming the pack's categories and saying the text is data.
    The model answers `{"findings": [{"category", "text"}]}`; the PROGRAM
    finds each quoted text in the chunk and reports offsets, for a declared
    category only; a text under 2 characters or holding the shield is
    dropped. A reply of the wrong shape is asked once more, then the run
    fails. **The chunks overlap (2026-10-07):** each chunk after the first
    starts at least 1000 characters (`OVERLAP_CHARS`) before the previous
    one ended (at whitespace when one lies within 200 more), so a span of up
    to 1000 characters lies wholly inside one chunk and is read whole by one
    call; a chunk never splits a surrogate pair. A span found by two chunks
    is one finding. The cost is about one sixth more input per cut on prose
    (a cut lands near a chunk's end); a span longer than 1000 characters
    across a cut may be found only in part. Until then the chunks only
    tiled the text, and a span a cut fell inside was missed.
15. **Installing it.** `local-classifier-pack.mjs` writes the pack (`node`
    and the script pinned, `endpoint: required`, `deadline_ms: 30000`,
    default categories `pii.person`, `pii.contact`, `pii.id-number`,
    `pii.financial`, `pii.health`, `org.confidential`, each `no-model` when
    masked); the policy turns it on with `endpoint:` (docs/usage.md,
    "Checking your own prompt"). Against a local Ollama, two short segments
    took about 3 s with a 7B model warm and up to 20 s cold, hence the 30 s
    deadline; the test suites use a fake model. **Shipped (2026-10-07):**
    the classifier and its pack writer are package assets
    (`bundle-manifest.json` `assets`, `dist/prompt-filters/`), and `mandu
    policy classifier-pack [--id] [--categories] [--deadline-ms] [--node]`
    prints the pack from the copy the install ships (a checkout's source
    in a checkout), pinning the node that runs it. Until then a release
    left both out: the documented command named a checkout path, so an
    installed user could not write the pack and the classifier did nothing
    (no pack, no filter); nothing fell through silently, since a switch
    turned on without its pack fails per its `on_error`.
16. **Tests.** `prompt-classifier.test.ts`,
    `prompt-classifier-plugin.test.ts` (each wire against a fake model, the
    retry, the deadline, and through a real arbiter: the model's span
    redacted, a registered value never sent); the stack and sandbox suites
    of item 13 run it too.
17. **The panel** (dashboard.md §4.31): `set-prompt-filter` takes
    `endpoint` (a cleared model's name, or null), always confirmed first (a
    relaxation, worded "Another model of your own would read what you type
    for the check <id>"); the Plugins table shows the pin (and how many
    modules it pins), the model, the last run and the legs. Tests: route and jsdom cases,
    `tests/stack/dashboard-prompt-plugins.test.ts`.
18. **Tests of 2026-10-07.** The overlap: `prompt-classifier.test.ts`
    (a span across the 6000 cut lies in one chunk; every span up to the
    overlap does, for random texts, with no split surrogate pair),
    `prompt-classifier-plugin.test.ts` (found once, at its offset; a span
    two chunks hold is one finding), `tests/stack/prompt-filter-plugin.test.ts`
    (a phrase the first cut falls inside reaches neither provider, both
    proxies). The modules: `prompt-filter-plugins.test.ts` (validation, the
    tree, a tampered, swapped or missing module refused, the copy
    directories only), `prompt-filter-plugin-op.test.ts` (a pinned module
    loads; a tampered one or an unpinned import blocks the prompt),
    `tests/sandbox/prompt-plugin-confine.test.ts` (under every leg the
    install directory is unreadable and a pinned module loads). The release:
    `launcher` `classifier-pack-command.test.ts` and `bundle-smoke.test.ts`
    (the built package's `mandu policy classifier-pack` pins the shipped
    copy, which answers the protocol and reads overlapping chunks).

### 13.6 Phase 3, `ask` and "let it through" (2026-10-03)

Code: `arbiter/prompt-filter/holds.ts` (the hold layer), the engine's `ask`
default, `lockedAction` (`policy.ts`), the ops in `arbiter/ipc/server.ts`.

1. **`ask` is a policy action** (`mask` < `ask` < `block`): raising a category
   to `ask` is a tightening the agent may make, because only the human can
   answer the hold, on the human plane.
2. **The engine answers `ask` with its default applied** (`mask` when a
   finding in the span carries a level, else `redact`) and reports the
   finding as `ask`. The scan stays cached; the HOLD LAYER
   (`PromptHolds.apply`) runs after it on every live request, so an answer
   takes effect on the next request with no rescan. On harness and side-call
   text `ask` acts as `redact` and no verdict is consulted: a title request
   or a token count is never held.
3. **The hold reuses the Inbox's approval queue** (`egress_approvals`). An
   `ask` finding on a `human` segment with no verdict files ONE pending row
   per message, keyed `prompt:<category>#<ref>` × `model:<session>#turn:<turn>`,
   and the segment is answered `hold`. The row's reason names the category
   and the filter, never the span (the queue is listed on the data plane);
   the span is kept in the arbiter's memory for the Inbox card and served by
   `promptHolds`, a human-plane op.
4. **References are keyed.** `ref` (the span) and `turn` (the message's text)
   are HMAC-SHA256 under a random key in mandu.db (`prompt_hold_state`), cut
   to 32 hex, so neither the queue nor the events (which reach the SIEM)
   carry a plain hash of a code name or a card number. The same table keeps
   the noted messages (§13.7 item 10), keyed the same way.
5. **"Once" means this message**, wherever it is resent; "this session"
   covers the span in every later message of the session. A message that
   carries the span in other words asks again.
6. **The answers** (`resolvePromptHold`, admin channel only): `send` (as
   written), `mask` (the default) or `cancel`, `once` or `session`. The
   Inbox's generic route works too (Allow = send, Deny = the default, Always
   = the session). `cancel` is the default for the message plus ONE refusal
   of the request still waiting. **Under a locked administrator's `ask` row,
   this message only** (§12, 2026-10-04): `lockedAsk` (`policy.ts`) finds any
   locked `ask` row covering the category, and then `resolvePromptHold` with
   `scope: session` (whatever the answer), an Always on
   `resolveEgressApproval` (an absent scope is the standing Always, so it is
   refused too) and a session `letPromptFindingThrough` are refused with
   "your administrator set <category> to ask every time (<file>), so it
   takes no answer for the session; answer it for this message only"
   (`sessionRefusal`, holds.ts). The row stays pending; nothing is
   downgraded. `afterResolve` files no session verdict for such a category
   (defensive), and `apply` does not consult a session verdict under the
   lock (one stored before the administrator locked the row). The hold
   carries `onceOnly: true` in `promptHolds` and on the waiting row in
   `egressApprovals` (read time, never stored), so the dashboard hides the
   session answer and says why; its routes answer the refusal with 409.
7. **The deadline** (default 30 s, `promptHoldMs` / `MANDU_PROMPT_HOLD_MS`)
   runs from the row's FIRST sighting, which the store persists: a resend
   after it goes with the default at once, and a restarted proxy or arbiter
   never holds one message twice. An answer given later applies to the next
   request that carries the message.
8. **Let it through** (`letPromptFindingThrough`, admin channel only): a
   finding the policy masked, redacted or blocked goes as written in its
   message (`once`, by its `ref` and `turn`) or for the session. A rebuilt
   segment is checked once more for a registered value; one found keeps the
   engine's answer.
9. **What never goes as written**, whatever the verdict: a registered value
   (category `secret.registered`, or a span holding a registered value of 8+
   characters: it has its own release paths, bindings and `declassify`); a
   finding under a LOCKED administrator's row other than `ask`; and under a
   locked `ask` the answer is the administrator's chosen action, for one
   message at a time (item 6). The dashboard offers no let-through for such
   a finding (2026-10-07): it reads the locks in force from `promptFilters`
   and says why (dashboard.md §4.25y, §4.31). The prompt
   filter's OWN masks (rows it minted) are not registered secrets here, or
   every asked span would count as "a registered value" from its second
   sighting on.
10. **Who may ask and who may answer** (plan 13 D9). Only an attested caller
    (the human socket while no unwalled launch is live, the admin channel)
    files a row, consults a verdict or is held; from the data socket an
    `ask` goes with its default. A caller that cannot wait (no `holds: true`)
    and a request without a session get the default. The answers are
    admin-only, so no process of the agent's world can answer its human's
    hold.
11. **A segment that blocks anyway** is not held: its `ask` findings take the
    default, and the request is refused once (§13.3 item 3).
12. **Tests.** `prompt-filter-holds.test.ts`, `prompt-filter-policy.test.ts`,
    and the component `prompt-filter-hold-op.test.ts` (the data socket never
    holds, the human socket holds, only the admin channel answers; a restart
    keeps the references and the deadline; under a locked `ask` row every
    session answer is refused, `onceOnly` is listed, the next message is
    held again).
13. **The proxies wait** (`waitOutHolds`, both proxies). Every
    `filterPrompt` says `holds: true` except a token count's, on the human
    client when the proxy has one. While a segment answers `hold`, the proxy
    asks again every half second; at the arbiter's deadline plus a second
    (capped at two minutes) it asks once more with `heldMs`, which is never
    answered `hold`; a hold still standing, an arbiter that fails while
    waiting, or a proxy restart refuses the request. Nothing of a held
    request is forwarded meanwhile; a side call and a token count of the same
    conversation go on. **The agent hanging up** (2026-10-18; it was killed,
    or its user pressed Esc, while held): every holding route (the
    anthropic-proxy's Messages and its routed Responses and Chat Completions,
    the openai-proxy's Responses and Chat Completions) hands the rewrite the
    client's signal (`clientGone`: the response closed before it finished),
    and `waitOutHolds` ends at once: its timer cleared, no further ask (not
    the last one with `heldMs` either), an answer already on the wire dropped
    whatever it says, `PromptHoldAbandoned` (a `PromptFilterRefusal`, so
    anything that catches that still refuses), mapped to `RewriteAbandoned`
    (a `RewriteRefusal`), on which the proxy logs and writes nothing.
    Nothing of the request is forwarded. The hold stays pending in the
    arbiter, as every unanswered ask does (pending asks are not expired,
    dashboard.md §4.25y): the Inbox card still offers its answers, and the
    answer decides the agent's retry, which carries the message again (item
    7). Before, the proxy polled on to the deadline and then forwarded the
    request to a model whose answer nobody read.
14. **Every agent's wire.** Claude Code (Messages), OpenClaw and OpenCode
    (Messages, their default, and the anthropic-proxy's routed Chat
    Completions wire for an OpenAI-family provider) and Codex (the
    openai-proxy's Responses and Chat Completions) share the two helpers. A
    hold needs the launcher's session key and the session's agent; text no
    segmenter places as the human's is never held.
15. **Events.** The findings carry `ref`, `let` and `hold`, the segment its
    `turn`: what the dashboard's "let it through" names. Never the span.
    Under a locked administrator's `ask` row a finding also carries
    `onceOnly: true`, the arbiter's word copied as is (a lock that comes or
    goes is a changed outcome, so `PromptEventLedger` records it).
16. **Tests, proxies and agents.** `prompt-filter-hold.test.ts` in both
    proxies; `tests/stack/prompt-filter-hold.test.ts` (the production
    two-client wiring per agent family: nothing reaches the fake model while
    held; an answer from the data or human socket releases nothing; "send as
    written" sends the code name raw and the registered key only as its
    symbol; cancel, the deadline, a title side call during a hold; under a
    locked administrator's `ask` row a session answer is refused while the
    request stays held, the next message is held again, and on both proxies
    the session's own event names the finding `onceOnly` while a session
    let-through by its reference is refused; the agent hanging up while
    held, on Claude Code's Messages and Codex's Responses and Chat
    Completions: the poll stops, nothing reaches the model, the hold stays
    pending, an answer given then releases nothing and decides the retry);
    `tests/stack/prompt-filter-ask-openclaw-opencode.test.ts`, OpenClaw's
    and OpenCode's own `ask` e2e (2026-10-18), on both of their wires
    (Messages, with the session's gate surface naming the agent so its own
    segmenter places the human's text, and the routed Chat Completions):
    held until the admin answers, a claimed answer releases nothing, sent as
    written (the registered key still only its symbol), masked, cancelled
    (a 400, nothing sent, the resend masked), and the agent hanging up while
    held; OpenCode's title call is not held. Its shared rig and oracles are
    `tests/lib/prompt-hold-rig.ts`. The unit tests of the hang-up:
    `prompt-filter-hold.test.ts` in both proxies (the poll ends at once, its
    timer cleared, no last ask, an answer in flight dropped, nothing
    rewritten; `clientGone` aborts only on a close before the response
    finished). The component `prompt-filter-events.test.ts` in both proxies
    (the mark copied, its lifting recorded); live: `LIVE prompt filter ask`
    in `claude-prompt-filter.test.ts` and `codex-prompt-filter.test.ts`.
    OpenClaw's and OpenCode's real binaries have no `ask` run of their own
    (their scripted e2e suites no longer run per push); the stack e2e above
    drives their request shapes through the real proxy.
17. **The panel**: `ask` in the Actions select; "Held for your answer" (the
    found text from `promptHolds`, behind the CSRF header and the admin
    session); "let it through" on Recent findings, which takes the category
    and references from the session's OWN proxy-recorded events, never from
    the request, and refuses harness text, a registered value and a claimed
    event.
18. **The Inbox card** (the product page): a `prompt:` row is worded by its
    category ("wants to send your message to the AI. It holds <category>."),
    never the found text, which the card fetches from the holds route and
    `/api/home` never carries; its answers are Send as written, Send masked
    and Cancel the message. Under a locked `ask` row (`onceOnly`) neither
    the product's Approvals card nor the inspector's offers the session
    answer; both say why ("Your administrator set this to ask every time,
    so your answer covers this message only. …", `ONLY_THIS_MESSAGE` in
    `view-model/ask-words.ts`), and the panel's held list shows "this
    message only" in place of the session button. The "let it through"
    notes do the same (closed 2026-10-04): the hold layer marks every
    referenced finding under a locked `ask` row `onceOnly` in the
    `filterPrompt` answer (`lockedAsk`; holds.ts), both proxies copy it into
    the `prompt_filter` event (item 15) without deciding anything, and the
    product page's note under the message and the inspector's Recent
    findings offer "let it through" for that message only, with the reason
    in place of the session button (`LET_ONLY_THIS_MESSAGE` in
    `view-model/prompt-notes.ts`; "this message only: locked to ask by your
    administrator" in the panel). The arbiter still decides: a session
    let-through under the lock is refused whatever the event says, and the
    let-through route answers that refusal 409 with its reason. `mandu why`
    and the dashboard's "Why this placeholder?" say "for that message only"
    and why when the answer's policy row is `onceOnly` (`whySymbolPolicy`).
19. **Tests.** `prompt-filter-hold-routes.test.ts`,
    `home-view-model.test.ts`, and `tests/stack/dashboard-prompt-holds.test.ts`
    (the production dashboard adapter, a real arbiter and the real
    anthropic-proxy: raised to `ask`, held, the found text gated and absent
    from `/api/home`, a claimed answer refused, answered, a finding let
    through once). The locked `ask` row: `home-view-model.test.ts` (no
    session action, the note), `prompt-filter-hold-routes.test.ts` and
    `egress-approvals-routes.test.ts` (409), `home-js-home.test.ts`,
    `egress-js-approvals.test.ts` and `prompt-filters-js.test.ts` (no session
    button, the note). The let-through under it: `prompt-filter-holds.test.ts`
    (the arbiter marks the findings), `prompt-notes.test.ts`,
    `home-js-prompt.test.ts`, `prompt-filters-js.test.ts` and
    `prompt-filter-hold-routes.test.ts` (no session button, the reason, the
    409), `prompt-filter-why-symbol.test.ts`, `why-symbol.test.ts` (the
    dashboard's) and the launcher's `why.test.ts` (that message only, and
    why).

20. **OpenCode 2's nested instructions are harness (2026-10-18).** After a
    `read` of a file under a subdirectory, OpenCode 2.0.23 sends the nearer
    `AGENTS.md` (or `CLAUDE.md` / `CONTEXT.md`) as a user message of its
    own: one text block, `Instructions from: <absolute path>` and a newline,
    then the file. OpenCode 1 puts the same text inside the read's tool
    result, in a `<system-reminder>`. The OpenCode segmenter tagged the
    block `human`, so a `block` finding in a repository's AGENTS.md refused
    the request and an `ask` finding held it on the human's Inbox answer,
    where "send as written" let text the human never typed through raw (the
    registered values stayed masked). The rule
    (`OPENCODE_INSTRUCTIONS_RE`, anthropic-proxy `prompt-filter.ts`): a
    whole text block that begins `Instructions from: /…/AGENTS.md` (or
    `CLAUDE.md`, `CONTEXT.md`; an absolute path, the header on the block's
    first line, then a newline or the end) is one `harness` segment. The
    header further into a text, a relative path, another file name and a
    different case are not this rule. OpenCode's OpenAI-family
    providers reach the anthropic-proxy's routed Chat Completions and
    Responses wires, whose shadows go through the same segmenter; the
    openai-proxy's segmenter is Codex's (a Chat Completions request without
    Codex's runtime context has no `human` segment), so it needs no rule.
    **A forged header.** A human who types the header into their own prompt
    gets the harness treatment for that text. That is the safe direction: on
    harness text every policy filter still runs, `block` and `ask` act as
    `redact` (the finding never reaches the model, no request is held, and
    nothing can be sent as written), and the registered-value floor masks
    always, whatever `prompt_filters:` says. What the human loses is the
    Inbox answer for their own text, not any protection; the reverse choice
    (a forged block treated as the human's) would let a repository file
    reach the Inbox's "send as written". Tests: anthropic-proxy
    `prompt-filter-opencode-instructions.test.ts` (the captured request on
    the Messages, Chat Completions and Responses wires; the rule's edges;
    the forged header) and `tests/stack/prompt-filter-opencode-instructions.test.ts`
    (the real proxy and arbiter in `secrets`, a mock model, both wires, the
    pack's category at `block` and at `ask`: the nested AGENTS.md is
    forwarded with the finding redacted and the key as its symbol, neither
    refused nor held; a forged header the same; the same text typed by the
    human with no header still refused or held).

### 13.7 Phase 4, the product page (2026-10-03)

Settings › Prompt filters and the note under the person's own message
(dashboard.md §4.25y). Code: `dashboard/src/view-model/prompt-settings.ts`,
`prompt-notes.ts`, `dashboard/src/server/prompt-filter-routes.ts`,
`dashboard/public/js/home.js`, `dual-lanes.ts` (`samePromptMessage`).

1. **Over the panel's projection.** `GET /api/policy/prompt-filters` runs the
   panel's projection through `promptSettingsVM`: every category a rule names
   or an enabled filter can find, each with the action in force (mirrored for
   display only), who set it, and the choices.
2. **The words.** `mask` is "Hide it", `redact` "Remove it", `ask` "Ask me",
   `block` "Block the message", `log` "Just note it"; `pass` reads "Send as
   written" and is never offered. A category Mandu knows reads in plain words
   ("An email address", "A GitHub token"); an organization's own category is
   shown as written.
3. **One write path, narrowed.** `POST /api/policy/prompt-filters/change`
   shares the panel's write path but accepts only `set-prompt-action`,
   `remove-prompt-action`, `add-prompt-exception` and
   `remove-prompt-exception`; anything else is a 400 before the arbiter is
   asked. Undoable from History.
4. **Gates.** The POST sits behind the global mutating gate (CSRF header +
   admin session). The GET is gated like the packs GET, since an exception's
   pattern may hold the person's own words. So are the developer view's
   reads that carry the same exceptions (2026-10-03): the panel's filters
   GET (`/api/prompt-filters/filters`) and the policy file's GET
   (`/api/policy/document`, the whole `prompt_filters:` mapping), all through
   one gate (`server.ts requireAdminRead`). Refused, the answer is the 403
   alone, nothing of the exceptions in it, and the arbiter is not asked; the
   panel says, as a plain note and not an error, that the admin sign-in is
   needed (`prompt-filters.js gatedNote`, also on the packs and held
   messages), as this section shows the server's words. The findings GET
   stays open: symbols, categories and counts.
   *The data plane* (2026-10-03). Enforcement needs no pattern outside the
   arbiter: the engine matches the exceptions itself (`filterPrompt`
   answers an excepted span `pass`), and no proxy reads them. So the data
   socket's `promptFilters` lists each exception with no `match`, and the
   patterns are a new HUMAN-plane op, `promptExceptions` (in
   `HUMAN_PLANE_OPS`, refused on the data socket). The dashboard's adapter
   reads them there and puts them back into the projection; an arbiter that
   still sends `match` in `promptFilters` is used as is. The SIEM exporter's
   vocabulary (ids, categories) is unchanged.
   *History and the rule-change cards* (`/api/policy/changes`,
   `/api/policy/proposals`, 2026-10-03) stay readable without the admin
   session, since the product page lists them (the Inbox count, History),
   but show an exception's pattern only to a read with the CSRF header AND
   the admin session (`server.ts adminRead`). Any other read gets the row
   as "… when it matches a pattern you set (sign in as the admin to see
   it)" and `patternsHidden: true` (`hidePromptPatterns`), and the page
   adds one plain line ("Some of these changes let words you chose through
   the prompt filter. Sign in as the admin to see them."). The product page
   sends the header on both reads, so an admin sees the patterns.
   *The three policy reads, closed (2026-10-03).* `policyDocument`,
   `policyProposals` and `policyChanges` stay on the data plane (their
   callers there, and "the data plane can READ the queue", policy-surface.md
   §8, are unchanged), but on the DATA socket every exception's pattern is
   replaced by `PROMPT_PATTERN_PLACEHOLDER` with `patternHidden: true`
   beside it (`policy/prompt-pattern-redact.ts`): in the document in force,
   the file's parse, the administrator's layer view, each exception edit
   (`add-` and `remove-prompt-exception`) and each delta line that names a
   pattern; a message (a problem, a conflict) or a comment in the file that
   repeats a known pattern has it replaced. The file's TEXT changes only in
   the `match:` values of its `prompt_filters:` block, byte for byte
   elsewhere; the edit is proven by parsing it back (it must equal the
   redacted parse), else the text is rebuilt from that parse
   (`onDisk.textRebuilt`, comments lost, no pattern kept). The answer
   carries `patternsHidden: true`. The human socket and the admin channel
   answer in full, and the dashboard's adapter reads all three there (it
   falls back to the data socket only when the arbiter names no human
   socket, and then shows the placeholder). No data-plane caller needs a
   pattern: the proxies never read these ops, the SIEM exporter reads ids
   and categories, the policy MCP server only proposes, and the eval and
   drill harnesses read nothing of `prompt_filters:`.
   *Writes.* The data plane cannot submit a whole document
   (`applyPolicyDocument` is admin-only), and the validator refuses the
   placeholder as a pattern and `patternHidden` as a key, so a document or
   an edit built from a data read is refused whole, never written over a
   stored pattern: `applyPolicyDocument` with the data read's document
   (with or without the flag), and `policyPropose` with an exception edit
   lifted from a data-read row (`add` with the placeholder, `remove` with
   it, either with the flag) all answer `invalid`, the file unchanged.
   *Left.* `policyPreview` and `policyPropose` judge an exception edit the
   caller writes against the law in force, so a guessed pattern removed
   answers differently from a wrong guess: a one-guess-per-call oracle, no
   different from proposing it, and every proposal is recorded.
5. **Locks.** A kind a locked administrator's rule covers names the file and
   offers only choices as strict or stricter; a change the lock forbids is
   refused by the arbiter and the page says so on the row.
6. **The note under the message.** Each story turn of the agent page gets a
   `promptNote` from the session's BELIEVED `prompt_filter` events (`origin:
   "human"`, while enforcing, only findings that changed something), grouped
   by the message's `turn` reference, the newest event telling where the
   message stands. A message no turn shows (a request the filter blocked) is
   placed in the story by its time as "A message you wrote". One line per
   outcome: hidden, removed, not sent, stopped once and then sent without it,
   each way an `ask` ended, let through.
7. **Never the value.** The note carries categories, plain words, counts, the
   event's id and the finding's index: no symbol, offset or reference.
   "Show what was hidden" posts `{session, eventId, index}` to the panel's
   reveal route, which answers only for a span the filter minted on its own,
   outside the `secret.*` kinds: the product page never shows a secret Mandu
   knows.
8. **Let it through, from the note**, where the panel's `canLet` holds,
   asked first, through `POST /api/prompt-filters/let-through`, which reads
   the category and references from the session's own events and calls
   `letPromptFindingThrough` on the admin channel. No new route reaches a
   value or relaxes a setting from the data plane.
9. **The conversation keeps extending.** The trace takes a model call's new
   user messages only when its prompt list extends the conversation seen so
   far; a resend in another form (masked after a policy change, as written
   after a "let it through") broke that. `samePromptMessage` treats two
   prompts as one message when they are equal but for the prompt filter's
   marks (a `$MDU:` token, `[redacted: …]`, `[blocked: …]`), with at least 8
   literal characters, matched leftmost with no backtracking.
10. **A resend with nothing found clears the note** (2026-10-03). Both
    proxies keep, per session and segment text hash, the outcome they last
    recorded (`PromptEventLedger`, in each proxy's `prompt-filter.ts`) and
    record an event whenever it changes. A segment recorded with a finding
    and now answered with none (an exception, a kind set to `pass`, a filter
    turned off) records one `prompt_filter` event with no findings, action
    `pass`, under the message's remembered `turn` (the arbiter names a turn
    only on a segment with a finding it can reference); the note reads the
    newest event and clears. Categories and counts only, never the value.
    A segment never recorded with a finding records nothing, and further
    resends record nothing more. The ledger is in memory, bounded (4096,
    oldest out).

    **Across a proxy restart** (2026-10-17). What a restarted proxy (a stack
    restart, a resumed conversation on a new proxy) lost was exactly the
    ledger entry: that the segment had been recorded with a finding, and the
    message's `turn`, which the arbiter names only beside a finding it can
    reference. So its resend with nothing found recorded nothing, and the
    note kept its old line for good. The arbiter now holds that state, out
    of band: the hold layer (`holds.ts`, *noted messages*) remembers, per
    session, each message it answered an attested caller with a referenced
    finding, and names that message's `turn` on its later answers that have
    none to reference (nothing found, or only `log` findings). A proxy takes
    a `turn` on such an answer as the arbiter's word that the message has a
    note, and records the cleared outcome under it once, whatever its own
    ledger holds (`PromptEventLedger.next`). The marks are kept in mandu.db
    (`noted:<key>` rows of `prompt_hold_state`, the key `HMAC(session, turn)`
    under the reference key, so the file names neither the session nor the
    message), loaded on start, so an arbiter restart keeps them too; bounded
    (20 000, oldest out). A fresh proxy files at most one clearing event per
    noted message, a repeat of one already filed only restating that nothing
    is hidden.

    *Why not a marker in the transcript.* The note is the product page's
    line under the person's message, read from the session's `prompt_filter`
    events; it never reaches the model, and the model's text never carries
    it. A marker the proxy looked for in the request (say, a reference in the
    message's text) would be text the agent, the model or a tool result can
    write. The mark here is never read from the text: it is the arbiter's own
    record, keyed under its key, matched only by the exact text of a `human`
    segment in the same session, and made only by an attested caller's live
    request (the human socket, the admin channel), which is also the only
    caller answered with one, so the agent's processes can neither plant,
    evict nor probe one on the data socket. And whatever happens to a mark,
    it changes no text: the segment's action and text are the engine's
    answer for this request, so a mark can make no text go or be dropped,
    and it hides nothing from the model or the person. The worst a wrong
    mark can do is file an event that says, truly, that nothing was found in
    the message this time. The worst a lost mark (evicted, an unwritable
    mandu.db, an older arbiter) can do is keep a stale note standing: fail
    closed is keeping the note, never dropping text. The events stay
    believed only from the attested channel (arbiter-human-plane.md §10.2),
    so a clearing event the agent emits itself is a claim no note reads.

    Still in memory, left as stated: the proxy's request numbers (the
    event's numeric `turn`) restart at 0 in a new proxy, and the blocked
    spans it refused once (`PromptBlockLedger`), so a restarted proxy
    refuses a blocked message once more.
11. **Tests.** `prompt-settings-view-model.test.ts`, `prompt-notes.test.ts`,
    `prompt-settings-routes.test.ts`, `home-js-prompt.test.ts`, and
    `tests/stack/dashboard-prompt-settings.test.ts` (the production adapter,
    a real arbiter with an administrator's lock, the real anthropic-proxy:
    a choice in force on the next request, a lock refused naming the file,
    the note with no found value in `/api/home`, show what was hidden, let it
    through, the story going on after the resend, the excepted messages'
    notes clearing, the registered key never raw at the model), and its
    Codex twin `tests/stack/dashboard-prompt-settings-codex.test.ts` (the
    real openai-proxy on the Responses wire, the same story, each clearing
    event the openai-proxy's under the message's own reference). The gates:
    `prompt-filter-routes.test.ts` and `policy-doc-routes.test.ts` (refused
    without the CSRF header or the session, no exception in the body, the
    arbiter never asked; served with both), `prompt-filters-panel.test.ts`
    (the production adapter), `prompt-filters-js.test.ts` (the gated note,
    no exception painted), `egress-js-document.test.ts` (the file's GET
    sends the header). The ledger: each proxy's
    `test/unit/prompt-event-ledger.test.ts` and
    `test/component/prompt-filter-events.test.ts` (the real proxy over HTTP:
    one clearing event with the turn, then nothing, the finding back
    recorded again; a fresh proxy on the same arbiter records it when the
    arbiter names the noted turn, nothing when it names none). The noted
    messages: `arbiter/test/unit/prompt-filter-holds.test.ts` (the turn on a
    later answer with none, the text unchanged; per session, `human` text
    only, the exact text, a reference written into the text matching
    nothing; never made or answered on the data socket or a dry run; kept
    in mandu.db across an arbiter restart, keyed, bounded, an evicted mark
    naming no turn) and `tests/stack/prompt-filter-note-restart.test.ts`
    (each real proxy over a real arbiter and the real dashboard: proxy A
    writes the notes, a fresh proxy B on the same arbiter and session
    carries the conversation on after an exception, the ticket's note
    clears under the message's reference while the registered key's
    stays, the key never raw at the model). The patterns off the data plane:
    `arbiter/test/component/prompt-filter-policy-op.test.ts` (an exception
    enforced in the arbiter, listed bare on data, `promptExceptions` refused
    there and served on human and admin), `human-plane-ops.test.ts`, and the
    parity test `tests/stack/dashboard-prompt-filters-parity.test.ts` (the
    production adapter reads the patterns on the human plane). History and
    the cards: `policy-proposal-routes.test.ts` (no pattern without both
    gates, `patternsHidden`; shown to the admin), `home-js-proposals.test.ts`
    (the header sent, the plain line), and the stack test above. The three
    policy reads: `arbiter/test/unit/prompt-pattern-redact.test.ts` (the
    text byte for byte but its `match:` values and repeating comments, the
    rebuild when the edit cannot be proven, the document, admin view,
    messages, edits and delta lines, the validator's refusals),
    `arbiter/test/component/policy-pattern-channel.test.ts` (over the real
    sockets: no pattern anywhere in the data answers, in full on human and
    admin; a document or an edit built from a data read refused, the file
    byte-identical, the exception still in force), and the parity test
    above (the production adapter reads all three on the human plane).

### 13.8 Phase 4, `mandu why` (2026-10-03)

A person who sees a `$MDU:` placeholder asks where it came from. Code:
`arbiter/prompt-filter/why-symbol.ts`, the `whySymbol` op,
`launcher/src/why.ts`.

1. **The form.** `mandu why '$MDU:tag[hex]'`, quoted (a shell expands `$MDU`
   and zsh globs `[…]`); `MDU:tag[hex]` and the `:tag[hex]` an unquoted
   `$MDU` leaves in bash are accepted too. `--json` prints the raw answer.
2. **What it says** for a span of the person's own message: that part was
   hidden and the model read the placeholder; the filter and the category in
   plain words; the action and how it ended; the session, the request that
   first carried the message, when, and how often it was resent; the
   verdicts on file now; the policy that decides the category now (row, who
   set it, lock, exceptions). Harness and side-call text are named as such.
3. **The ways out**, never in band (§7): let it through on the dashboard;
   change the category's action; add an exception. The CLI enacts none of
   them (the answers are admin-channel ops and the CLI holds no admin
   channel). A registered value has no way out here and the answer points at
   `mandu why <file>`; under a locked administrator's row the answer names
   the file.
4. **Never the value.** The op copies the event's `promptFilter` fields one
   by one and never reads an event's panes, the symbol row's value or the
   span.
5. **The plane split.** `whySymbol` is a HUMAN-PLANE op: from the data socket
   it is refused, and a claim gets only `symbolProvenance` (the minting
   tool). Where the human socket is out of reach (inside the agent's walls)
   the CLI answers from `symbolProvenance` alone and says so. Findings come
   from BELIEVED events only, so a forged event cannot make the answer say a
   span was let through.
6. **Narrow.** One read-only op, one round trip; at most 24 sessions searched
   and 10 findings; it records nothing. Only a resident arbiter knows a
   placeholder: with none running the CLI says so instead of starting a
   throwaway one.
   **`--session <id>`** (2026-10-09): the op's `session` hint from the CLI.
   The search order is the placeholder's own session, then the named one,
   then the most recent sessions active since the placeholder was minted,
   so a message in an older session (or a registered value found in a
   prompt, whose row keeps the session that registered it) is found when
   named. Placeholder only (with a file or a host it is a usage error);
   an id longer than 256 characters is refused (the arbiter ignores a
   longer hint). With no finding, the answer offers the flag and says how
   many sessions were searched; with the flag and no finding in that
   session, it says so (the arbiter searches only a session it has, so
   either the session holds none or the service has no such session).
   Tests: `launcher/test/unit/why.test.ts`, `tests/stack/why-symbol-cli.test.ts`.
7. **Tests.** `prompt-filter-why-symbol.test.ts`, `human-plane-ops.test.ts`,
   `launcher/test/unit/why.test.ts`, the component `why-symbol-op.test.ts`
   (the three sockets, a claimed event ignored, a pane carrying the value not
   copied), and `tests/stack/why-symbol-cli.test.ts` (the production proxy
   and CLI wiring: both placeholders explained without a value, and from the
   agent's side only the minting tool).
8. **The dashboard asks too** (dashboard.md §4.33, "Why masked?"): the
   developer view's Sessions page offers it beside a masked value (the
   Secrets tab, the ⊕ Masked values modal, the trace's ⊕ marks), one
   `GET /api/symbols/why` per click. The adapter sends `whySymbol` on the
   human plane; the route is gated like the other human-plane reads (CSRF
   header and admin session) and answers in plain words built from the
   answer's named fields, so a value never passes. With no finding
   (2026-10-10) it says how far Mandu looked, the hint among them (the
   `--session` note's two readings), and offers the Sessions page's
   sessions: Look asks again with the one picked as the hint, so the
   dashboard has the CLI's `--session`. Tests:
   `dashboard/test/unit/view-model/why-symbol.test.ts`,
   `…/server/why-symbol-routes.test.ts`, `…/ui/app-js-why-symbol.test.ts`,
   and `tests/stack/dashboard-why-symbol.test.ts` (the production wiring).

### 13.9 Phase 4, the SIEM mapping (2026-10-03)

The exporter is the enterprise component (siem-integration.md §4.2; not in
this repository); the arbiter's part is open. Detail and rules:
siem-integration.md §6.6.

1. **The arbiter stamps the answer.** `approval_resolved` for a `prompt:` row
   carries `promptAnswer` (`send`, `mask`, `cancel`, `let-through`) and
   `promptScope` (`once`, `session`); the row's status alone cannot tell
   "send masked" from "cancel". Never the span.
2. **The `prompt_filter` event is allowlisted, not only walked.** The found
   text has no `original` for the exporter's structural redactor to null, so
   the exporter keeps exactly the fields of `PromptFilterDetail`, checks each
   one's shape, drops everything else, counts the shape failures and rebuilds
   the summary from what survived.
3. **The vocabulary.** A code name is a valid category shape, so the
   finding's filter and category are also checked against what the policy
   declares (`promptFilters`: ids, categories and counts, never a pattern);
   anything else goes as `unverified` (fail closed). Cached for 30 s,
   refetched when a finding does not verify.
4. **One record per finding**, a derived `prompt_finding` with a one-word
   `promptOutcome` (`logged`, `passed`, `redacted`, `masked`, `blocked`,
   `blocked-resent`, `held`, `sent-as-written`, `sent-masked`, `cancelled`,
   `timed-out`, `ask-default`, `let-through`).
5. **The approval audit.** A session verdict is a standing grant and the
   stale-approval sweep flags it; a hold nobody answered past the deadline
   becomes a `prompt_hold_audit` event from the pending queue.
6. **Rules** (Wazuh 100228–100236, Sigma sources for the three named
   detections): believed findings, the `log`-only rollout summarised per
   category, a block, a hold timed out or unanswered, the human's answers
   (refining the egress-verdict rules), and one person sending as written or
   letting through three times in an hour.
7. **Decisions.** The answer is stamped by the arbiter, not inferred;
   categories are a closed vocabulary from the policy; findings are derived
   records beside the native event (siem-integration.md §4.4); the override
   rule keys on the arbiter's audit stream (authoritative, never claimed).
8. **Tests.** `prompt-filter-hold-op.test.ts` (each answer's audit event);
   the exporter's unit and component tests (the no-originals oracle with a
   found text in every field a buggy or claimed emitter might use; the
   production wiring over a real arbiter).
9. **Not done.** The Wazuh rules were not run through a live manager; the
   unit test pins their fields and values, not Wazuh's parse of them.

### 13.10 A HIGH session's own write (2026-10-09)

**The failure (live drill `conf-derived-label-next-session`, Claude Code
2.1.294, haiku, 2026-10-08).** Session A declassified an `any-model` brief
(A is HIGH). The human typed "Write a file named summary.md … containing
the sentence: The deal closes in the third quarter." The model wrote it;
the Write was labelled `any-model` on disk at the tool_use (Plan 9,
confidentiality.md §4), and the agent's next open registered the file, so
its text became a registered value. The registered set's version changed,
the next request re-scanned the human's earlier turn, and the
registered-value filter found the sentence there as a line of the file's
value: the human's own words went to the model as
`$MDU:anymodel_prompt_filter[…]`. The model read its user's request as a
token, decided it had written "a sentence I invented instead of the symbol
token you gave me", and overwrote summary.md with the token. The human's
file held `$MDU:…` on disk; the next session read it as a placeholder,
trivially.

**Why the mask was wrong.** It protected nothing: the same bytes were in
A's transcript as the model's own Write input, which the agent re-sends as
written (assistant text is not filtered, confidentiality.md "Masked after
the fact"), and A's watermark already holds data at that level and confines
everything A emits (confidentiality.md §8: in a high session the watermark
subsumes in-session derivation; the derived label is for *future*
sessions).

**The rule.** In a session's `human` segments, a registered-value finding is
reported as `log` (not enacted) when its row is the session's own write:

1. a registered file row (`isRegisteredFileRow`) whose value is, byte for
   byte, the `content` of a whole-content write (`Write`, OpenCode's and
   OpenClaw's `write`) this session's model made to that path, as the model
   proxy recorded it (`recordToolCall`, believed records only: a claim on
   the data socket is not evidence). The arbiter keeps a SHA-256 of each
   such content by session and path, in memory and bounded
   (`ownWriteHashes`, `noteOwnWrite`); a restart forgets them and the mask
   comes back, the safe direction;
2. the path's composed level and the row's level are at most the session's
   watermark, so a session that is not HIGH, or a human or catalog label
   above the watermark, keeps the mask;
3. or the prompt filter's own mask (`prompt_filter` row) of text inside such
   a row: the mask another session's prompt made of the same sentence.

Not exempt: an `Edit` (the file keeps bytes the model may never have read
raw), a file whose bytes changed since the write (another session, the
human, a program: its value no longer matches), the same value in `harness`
or `side-call` text (the floor, §3.1), and every other session, whose human
typing the sentence still gets the mask. The engine asks the server for the
exempt set once per request (`ownWrites`) and keys the cache of the
session's human segments by the session and the set's signature (the
written paths, their levels, the hashes, the watermark), so an exempt
answer is never served to another session or after the set changed
(`engine.ts`, `promptOwnWrites` in `server.ts`).

**The derived label is unchanged.** summary.md is still labelled at A's
watermark and registered; a later session's Read of it is a symbol, and the
reply filter shows that session's human the sentence.

**Why not resolve the token at the write instead.** In `secrets` mode there
is no AgentView and no write-back (fs-sync's is the frozen integrity
path): a model that writes a `$MDU:` token writes the token. Resolving it in
the tool_use the agent receives would put the value in the agent's own
transcript, which it re-sends to the model as assistant input the proxies
do not filter: for a `no-model` symbol that is the invariant broken. The
fix removes the cause instead: the model is never shown its user's words as
a token.

**Left as is on 2026-10-09, fixed 2026-10-11.** In the writer session, the
Write's own result ("File created successfully at …") was classified by its
path and came back as `$MDU:anymodel_Write[…]`. See "A Write's own result"
below.

**Tests.** `arbiter/test/unit/prompt-filter-own-write.test.ts` (the engine:
human vs harness and side-call, the cache never crossing sessions, a changed
set rescans, an uncovered value beside the exempt one, the axis off);
`arbiter/test/component/prompt-filter-own-write-op.test.ts` (the server's
rule over the real ops: the prompt-filter mint of another session, an
`Edit`, a label above the watermark, changed bytes, a claimed Write, a
session that is not HIGH); `tests/stack/high-session-own-write-prompt.test.ts`
(the live shape through the production proxy wiring: A's human turn stays
the sentence on every resend after the file is registered and the Write the
agent receives holds it; B's Read of summary.md is a symbol and B's typed
sentence is masked).

**A Write's own result (2026-10-11).** *Why it was masked.* The proxy asks
the arbiter to classify every tool result; the confidentiality derivation
gives a result the level of the paths its call names (`labelForClassify`
reads the call's `file_path`). The writer session's Write labelled
summary.md at the session's watermark at the tool_use (Plan 9), so the
Write's answer, "File created successfully at: <path> (file state is
current in your context — no need to Read it back)" followed by Claude
Code's token-budget reminder, was `any-model` by its path alone and went to
the model as `$MDU:anymodel_Write[…]` (reproduced in the drill's replay on
Claude Code 2.1.296). Neither the session being HIGH nor the prompt filter
played a part: any Write to a labelled path got the same mask.

*The rule* (`arbiter/policy/own-write-notice.ts`, applied in the policy's
confidentiality derivation before the path label is read, beside the Read
dedup notice, confidentiality.md §7.1 "The write notice"). A write tool's
result is `public` when the whole value, surrounding whitespace aside, is
exactly one of that agent's fixed success notices for this call:

| Agent | Tool | Notice | Free spans |
|---|---|---|---|
| Claude Code (2.1.296's bundle) | `Write` | `File created successfully at: <path>` or `The file <path> has been updated successfully.`, then optionally " The user modified your proposed content before accepting it." and/or " (file state is current in your context — no need to Read it back)", then optionally one or two token-budget blocks (digits only, at most 12) | the path |
| OpenCode 2 (2.0.23, the captured surface) | `write` | `Created file successfully: <path>` | the path |
| Goose (1.53, read off the wire) | `write` | `Created <path> (N lines)` | the path; N |
| OpenCode 1 (1.18.13, the CI pin; read in the compiled tool of the installed `opencode-ai` binary) | `write` | `Wrote file successfully.` | none |
| OpenClaw (2026.7.1-2, the CI pin; `createWriteToolDefinition` in the installed package's `dist/sessions-*.js`; same sentence in 2026.9.9's `dist/tools-*.mjs`) | `write` | `Successfully wrote N bytes to <path>` | the path; N |

The path must equal the call's own path field (`file_path` for Claude Code;
`path` for OpenCode 2, Goose and OpenClaw) as the model wrote it, N must be
the line count (Goose) or the length (OpenClaw) of the call's own `content`,
and the call must carry `content` as a string (a whole-content write the
model authored). OpenCode 1's sentence names no path; its call must carry
its own path field, `filePath`, and each OpenCode generation's sentence is
taken only under its own field (one session spec serves both). OpenClaw
2026.7.1-2 prints the content's string length (`content.length`, UTF-16
units) and 2026.9.9 its UTF-8 byte length (`Buffer.byteLength`): both are
counts of the model's own input, and either is accepted. The tool must resolve to that
agent's built-in write entry by identity: a `policy.yaml` tool rule for it,
another agent's session, an MCP tool named like it, a dispatched call or a
field-addressed request never takes the release. For OpenClaw the entry is
the defended agent's spec (`openclaw-agent`), never the lifted reference
spec (`openclaw`); a call through OpenClaw's Tool Search dispatcher
(`tool_call`) is not the built-in entry. A plugin tool that takes a
built-in's bare name resolves to the same entry, which does not weaken the
release: its value must still be exactly the sentence computed from the
call's own input. The value backstop in the
arbiter's classify op still runs on the verdict (raise-only), and the
proxy's taint and agent-receipt raises are untouched.

*Why it is safe.* The released text is a function of the call's own input,
which the model wrote and which the agent re-sends to it as assistant input
anyway, and a choice among at most eight fixed sentences, plus the
harness's token count. It holds no byte of the file on disk and nothing the
model did not write. The choice says whether a file was at the path (create
or update: metadata, never content; Claude Code refuses to replace a file
the model has not Read) and whether the human edited the proposed content
(the human's act). OpenCode 1's sentence carries only that the write
worked. OpenClaw's has one more bit, by elimination: OpenClaw answers a
write whose content equals the file's bytes with "No changes made to
<path>. The file already has identical content." instead, and that answer
keeps the mask, so a raw success notice says the file did not already hold
exactly the model's content. That is one exact whole-file guess per call,
and a wrong guess replaces the file with the guess, so it cannot be
repeated against the same bytes: no usable channel. Everything that could
carry a byte the model has not
seen keeps the path's mask: the notice with anything else before or after
it (another reminder block, OpenCode's diagnostics, which quote the file
and other files, or the snippet of the file an older Claude Code printed
after an update), a lookalike, another path, a count that is not the
content's, an `Edit`'s or `MultiEdit`'s notice (the file keeps lines the
model may never have read raw), a Read of the file. The session's level
plays no part, so the release holds in a session that is not HIGH, beside a
`no-model` file.

Pinned for OpenCode 1 and OpenClaw the same day (they were left masked
first, with no captured result): each sentence was read in the agent's own
source as installed at the CI pins (`scripts/ci/pins.env`), and neither can
echo a byte of the content. OpenCode 1.18.13's tool builds `let b = "Wrote
file successfully."` and appends only LSP diagnostics; OpenClaw's
(`createWriteToolDefinition`, behind its `wrapToolParamValidation` and
workspace-root guard, which may rewrite `path` before the tool runs; a
rewritten path no longer equals the call's, so that result keeps the mask)
returns the sentence as its one text block, which OpenClaw's transport sends
as the `tool_result` string.

*Not released* (they keep the mask, fail-closed): OpenClaw's "No changes
made" answer and its write-verification error; a Claude Code
Write result that carries any other reminder block (the "MCP Server
Instructions" block on a session's first tool result), which the proxy
cannot split off a result masked whole; Claude Code's staged and synced-skill
variants of the notice; an `Edit`'s notice, though 2.1.296's carries no file
byte either.

*The notice is no piece (2026-10-11, later).* A result masked whole is
registered as a secret value: the whole value is a pattern of the value
backstop, and so is each line of 24 characters or more
(egress-fingerprint.ts `MIN_LINE_FINGERPRINT_LEN`). A write result masked
with more than its notice made the notice a piece of its row, and the
backstop then raised the agent's later notices back to a mask, each one
rightly released by the rule above:

- OpenCode 1, arbiter-wide. Its sentence is exactly 24 characters and names
  no path, so after one write to a labelled file came back with LSP
  diagnostics, every later OpenCode 1 write notice on that arbiter, in every
  session and for every path, was a symbol (reproduced in
  `tests/stack/write-notice-raw.test.ts` on the resend).
- The path-bearing sentences, for that path: OpenCode 2's with diagnostics,
  Goose's with anything after it, OpenClaw's with anything after it, and
  Claude Code's on a session's first tool result. There the proxy splits the
  "MCP Server Instructions" reminder off and mints the symbol for the body,
  which is the notice alone, so the row's WHOLE value was the notice.
- A call masked whole for another reason (no `content`, a `policy.yaml`
  rule, a session not bound to its agent's spec), and every row minted
  before the release, held the bare notice as its whole value.

The fix is the agent-result-head treatment (plan 10 §11.14), with a fourth
kind, `write-notice` (`arbiter/policy/agent-result-head.ts`
`writeNoticeHeadLength`). Both proxies name it on a known `Write` / `write`
call's text result they symbolize from its start: the whole result, or
Claude Code's body before a split-off reminder. The arbiter takes the mark
only when the row is a `Write` / `write` row that is not a field row, and
its first line is exactly one of the pinned sentences, the path span equal
to the row's own stored origin (or a relative path the arbiter placed under
it) and counts digits only. That line, and the line break after it, are
then no piece of the row. Every later line (the diagnostics, which quote
the file), every credential-shaped span and the whole value stay. A write
row whose whole value is a notice for its own origin is all head with no
mark (`isWholeWriteNotice`): it holds the fixed sentence, its own path and
digits, nothing a file wrote, whoever minted it. That covers the split-off
body and the older rows. A value that is all head, of any kind, gives the
index no pattern, its whole value included (`RegisteredValueIndex.sync`).
The marks are durable like the other kinds (`result_heads`). Fail-closed
wherever it does not hold: another tool's row, a field row, a notice
naming another path, a payload past the sentence, a notice not on the first
line, or a row the proxy did not name with a body after the notice keeps
every line.

*Tests.* `arbiter/test/unit/own-write-notice.test.ts` (the predicate per
agent, every near-notice false, the verdict public for the notice and
`no-model` for each other result, a policy rule winning, each agent's
sentence only in its own session, OpenClaw's two counts on non-ASCII
content, the axis off);
`tests/stack/write-notice-raw.test.ts` (the production proxy wiring over a
real arbiter: the drill's HIGH-session shape with the path labelled
`any-model` and the create and update notices forwarded byte for byte; in a
session that is not HIGH, the model's own Write notice for a `no-model`
file raw while its Read, an older update's snippet, the notice with another
reminder, an Edit, another path and a Write with no content stay symbols,
and no byte of the file reaches the model; the same for OpenClaw and
OpenCode 1 in sessions bound to their own specs, with OpenClaw's "No
changes made", a forged count or path, a notice with file lines after it,
OpenCode's diagnostics form and a call with no content masked, and each
agent's sentence masked in another agent's session). The drill
conf-derived-label-next-session's replay on Claude Code passes with the
step's Write result forwarded raw. For the notice as no piece: arbiter
`agent-result-head.test.ts` (each sentence as a head for its own origin,
relative paths, every miss, the whole-notice rows, the index, and a real
server: marks learned only on a write row, kept over a restart, the
diagnostics' lines still registered, and an Edit row, a field row, another
path or an unnamed row keeping the notice line); anthropic-proxy
`background-poll.test.ts` and openai-proxy `rewrite-request.test.ts` (the
proxies name the kind on a write result only); `write-notice-raw` (OpenClaw
and OpenCode 1 own notices raw on the resend after their masked forms, another
OpenCode 1 session's notice raw, and Claude Code, OpenCode 2 and Goose: a
later notice for the path raw after a masked first result, while a later
result that prints a masked row's other line is masked).

### 13.11 What a raised row registers (2026-10-12)

*What was registered.* The value backstop at the model door (plan 11 §8
row 1; the arbiter's classify op) raises a tool result the path rules call
public to the level of any registered secret it finds in it: the whole
value of a secret row (at or above `MIN_FINGERPRINT_LEN` = 8), one of its
long lines (`MIN_LINE_FINGERPRINT_LEN` = 24), or one of its
credential-shaped spans. The proxy then masks the result whole and mints
its row at that level, and the value index (`registered-values.ts`) took
every piece of the new row like any other: its whole value, the value
without its final line break, its credential-shaped spans, and EVERY line
of 24 characters or more. So one Read of a notes file that quoted a secret
line made the notes file's heading and log lines pieces of a `no-model`
row, and a later Read of an unrelated README, or a command output, that
shared one of them was masked whole by the backstop. Only the lines that
held the secret ever made the row secret; the others were ordinary text.
(The all-head rule of §13.10 is the same idea for an agent's own notice:
a value that is all head has no piece.)

*The rule.* Such a row, when the arbiter can tell its level is the
backstop's raise alone, keeps as pieces only what made it secret:

- the long lines a registered secret was found in (`raisedRowKeptLines`:
  every line an occurrence touches, a secret across a line break keeping
  each line), and any long line with a credential shape
  (`locateSecretShapes`), kept whatever the occurrences say;
- its whole value, the value without its final break, and its
  credential-shaped spans, unchanged.

Every other long line is no piece (`raisedRowPieces`). The row itself is
unchanged: its level, its bindings, its symbol, so the result stays one
symbol on every re-send. Nothing is lowered: the classify verdict and the
proxy's mask are the same.

*When.* All of these, else every line stays a piece (fail-closed):

1. the classify op raised a verdict its policy called public, and says so
   (`raisedBy: "value-backstop"` on the result), and it keeps a record of
   that call (`backstopCalls`: by session and call, and by session and
   value for the openai-proxy, whose classify names no call); a classify of
   the same call the policy called secret (a labelled path, a command
   naming one) makes the record `policySecret` for good;
2. the proxy's symbolize says the level is that raise and nothing else
   (`secretBy: "value-backstop"`): the anthropic-proxy and the openai-proxy
   set it only when their final verdict is the classify's own (no taint
   `maskWhole`, no agent-receipt raise) on a text result;
3. the row is that symbolize's own row, not a field row, active and
   secret; its stored origin carries no secret label (user, catalog or
   derived) and no secret origin symbol; and the call's process tree read
   no secret (`callTaint` level null: its output could hold a secret in a
   form no piece matches);
4. the registered secrets found in the row reach its level, counted live
   as the backstop counts them (`backstopRowLevel`). The row itself, a row
   with the same value (an earlier copy of the result), and another raised
   row's whole value are not counted as what made it secret, so a re-run
   of the same command narrows too.

The mark is durable (`raised_rows` in mandu.db, schema v14,
`symbol-table/raised-rows.ts`), bound to the SHA-256 of the row's value
with the kept line indices; a mark whose row is gone, holds another value
or whose list does not parse is not loaded. An adopted file's rows have no
mark: every line of a raised row counts, as before.

*Why it is safe.* The confidentiality invariant asks that a secret reach
the model only as a symbol. The narrowed row still holds, as pieces, every
line in which a secret was found and every credential-shaped span in it,
and the secret itself stays registered by its own source row (the file, or
the result it was first masked in): a later result that carries the
secret, a line of it, or a line of the raised result that held it is
masked as before. What stops being a piece is a line in which no
registered secret was found, which is text the tool printed around the
secret, not the secret. The backstop is a verbatim matcher; a transformed
copy of a secret (reversed, encoded) next to a verbatim one was a piece
only by accident before, and the call-tree taint (plan 10), not this index,
is what masks the output of code that read the secret: a tainted call is
never narrowed (condition 3).

*Tests.* `arbiter/test/unit/backstop-raised-row.test.ts` (the kept lines,
the pieces, the index with and without the mark, the store, and a real
server: a raised Read narrowed, each missing condition keeping every
line, the mark kept over a restart); anthropic-proxy
`backstop-secret-by.test.ts` and openai-proxy `rewrite-request.test.ts`
(the flag only on a verdict raised by the backstop alone);
`tests/stack/backstop-raised-row.test.ts` (the production proxy over a
real arbiter: a Read of an unlabelled notes file quoting a registered
secret line is masked and keeps its symbol on the re-send; a later README
and a command output sharing its ordinary lines are raw; THE ORACLE: a
later Read with the secret line, a command output with the token alone and
a grep line carrying it are masked, and no request to the model carries
the secret; a Read of the labelled file itself keeps every line, so a
result sharing one of its ordinary lines is masked). Mutation checks run:
without the arbiter and proxy change the README step fails; with the
policy and origin conditions removed and the proxy flag sent on any secret
verdict, the path-secret step fails.

### 13.12 What a path row registers (2026-10-17)

*What was registered.* A shell result whose command NAMES a secret path is
masked whole at the path's level, whatever the output holds (the
path-derived precaution, plan 10 §11.8 and confidentiality.md §7.1): the
arbiter cannot tell which bytes came from which file. The row (origin: the
command, no bindings) then gave every long line of the output as a piece,
like any secret row. In the live c6 demo (demo-notion-token, Codex,
2026-10-17) Codex printed `.env`, the app's script and the meeting notes in
ONE command. `.env` was served its twin, so the output held no secret byte,
yet the notes' lines became fingerprints of a row bound nowhere, and the
egress tripwire (confidentiality.md §4) blocked the script's upload of the
notes to `api.notion.com`, the very host the `.env`'s token is bound to.
Rows are global and durable, so the notes stayed un-sendable to any host in
every later session. The inbound value backstop already ignored such a row
(`backstopRowLevel`: an exec row on precaution does not count), so the
model read the same notes in clear one command later; only the tripwire and
the prompt filter held them. The run-apart advice of the path-derived note
cannot help: the fingerprint is minted by the first, batched command.

*The rule.* Such a row registers what §13.11's raised row registers: the
long lines a registered secret was found in (counted as the backstop
counts them), every line with a credential shape and every such span, the
value without its final break, and the whole value; and, besides, every
long line no plain file the command names holds verbatim (condition 5).
Every other long line is no piece (`raisedRowPieces`). Unlike §13.11, an
empty kept set is a usual case (no registered secret in the output, every
line found in a named plain file), and is stored as such. The row
itself is unchanged: its level, its symbol, its mask and its note; nothing
is lowered and nothing reaches the model that did not before.

*When.* All of these, else every line stays a piece (fail-closed):

1. *The path rule alone.* The proxy's symbolize says `secretBy:
   "path-rule"` (both proxies set it only when their verdict is the
   classify's own, secret, with no backstop raise and no raise of their
   own: no taint `maskWhole`, no agent-receipt mask, no unparsed user
   shell), and the arbiter's own classify record of the call (by call, and
   by value in the session for the openai-proxy) agrees: every
   policy-secret classify of it was the path rule's (`labelForClassify`,
   and for a tool the spec does not map the every-string scan of §11.11,
   `labelForUnmappedInput`) with EVERY secret reading placed on an
   absolute file (`namedFiles`), and none was raised by the backstop. A
   reading is placed when the token is absolute (or `~/…`), or relative
   and read in the directory the call runs in (Codex's `workdir`, the
   kernel's directory for Claude Code's `Bash`), or in the folder of a
   leading `cd` to one literal folder, absolute or relative to that
   directory ("A leading cd", below);
   a relative token with no
   known directory, a command that may change directory (`cd`, `source`,
   `eval`, `-C` … as `changesDirectory` reads them, and the same with the
   shell's quoting and escapes removed, `\cd`, `c""d`, or a `chdir(` in
   code the command runs: `directoryMayChange`; since 2026-10-17 the same
   test also stops a label LIFTING the level, and such a command's tokens
   are read raise-only wherever they could name a label, confidentiality.md
   §6 "A directory change only raises"; a reading so raised places
   nothing), a glob,
   a `..` segment (the kernel resolves it through symlinks, the scan
   lexically), a `~` (the shell's HOME may not be the arbiter's), quoting
   or an escape inside a token, or a source secret with no secret token in
   it places nothing, and one unplaced reading spoils the record for the
   call. The files stay in the arbiter: the classify op strips
   `namedFiles` from its answer (they are HumanView paths).
2. *The row.* The symbolize's own row: not a field row, active, secret, an
   exec tool's (`EXEC_OUTPUT_TOOLS`), minted for this call, no higher than
   the path rule's level, and with no placeholder anywhere in its origin
   (`MDU:`): a command that carries one may be run with the value it
   stands for and print it.
3. *The tree.* The call's process tree was bound by the recorder (`exact`
   or `shared`; a claim, a guess or no tree fails) and no process in it,
   nor an orphan root it may have started, opened a secret raw.
4. *The files.* Every placed file is registered as it is on disk now
   (`fileRegisteredAsIs`: a registry base row of that path whose value is
   the file's current text, at a level at least its label's) and its
   pieces are complete (`fileUnpieced`: not over the piece bound). A
   labelled file nobody registered (one the guard never confined, so a
   program read its raw bytes), one changed since its registration, one
   that is not its own real path (a symlink), one unreadable: no mark.
5. *What may go* (review, 2026-10-17). A long line stops being a piece
   only when a file the command names as a plain path token (absolute, or
   relative where the call runs, as in condition 1), that is no label's
   secret, is its own real path, has one link (not a hard link to another
   file) and was not changed since the proxy relayed the call (the call
   did not write it: `call_pending`), holds it verbatim when the mark is
   learned. Every read here is one bounded read of the descriptor's own
   regular, non-empty size, never under `/proc`, `/sys`, `/dev`, `/run`
   or Mandu's own state and events (a second review hung the arbiter on a
   size-0 `/proc/<pid>/pagemap` named in a comment). A line of unknown origin
   stays a piece: the review showed reads the path scan cannot place
   (`$(printf …)`, `find … -exec cat`, a name split by quotes) printing a
   labelled file nobody registered beside a registered one, whose lines
   condition 4 alone would have dropped.

The mark is durable (`path_rows` in mandu.db, schema v15, beside
`raised_rows`: `symbol-table/raised-rows.ts` with kind `path`), bound to
the SHA-256 of the row's value; an adopted file's path rows have no mark.

*A leading cd* (2026-10-19). Found by the live c1 demo
(demo-poisoned-readme, Claude Code, Mandu with its default catalog only,
battery 2026-10-18). Claude Code ran ONE command, `cd /…/weather-app && ls;
echo ---; cat config/settings.json 2>/dev/null; echo ---; cat logs/app.log
2>/dev/null; echo ---ENV---; cat .env 2>/dev/null`. It was masked whole, as
it must be (it names `.env`). But the `cd` made the whole command one that
"may change directory", so the path scan placed `.env` on no file, the
classify record was spoiled (`pathMixed`, condition 1), and the row was
never narrowed: every long line of the settings and the log became a piece
of a row bound nowhere. When the human then asked for the report without
`.env`, `report-bug.sh --no-env`, and even a `curl` of the settings alone or
the log alone, were refused by the tripwire as "text Mandu holds as a
secret", with no approval to offer, in that session and every later one.
The same drill under its own settings passed only because the model read
each file with its own `Read` there; the drill names no label, so the two
settings differ in the model's choice of command, not in Mandu.

The rule (`leadingCdDir`, secret-catalog.ts): a command that is exactly
`cd <dir>`, then `&&`, `;` or a line break, then the rest, where `cd` is
the first word as written (no `\cd`, no option), `<dir>` one literal
path (a pair of quotes around the whole of it allowed; no expansion,
glob, brace, escape, `~` or `..` segment), absolute or relative ("A
relative folder", below), and the rest does
not change directory itself (`directoryMayChange` of the rest: no second
`cd`, subshell `cd`, `source`, `-C` …), places the rest's relative tokens
in `<dir>`: both the secret readings (`files`) and the plain path tokens
(`placed`, condition 5). Anything else after a `cd` places nothing, as
before (`||`, `&`, a pipe or a redirection after the `cd`, a `cd` that is
not the first command, a second one). It is placement only: no label is read
exactly there (no public label is lifted; the readings after the `cd` stay
raise-only, confidentiality.md §6 "A directory change only raises").

Why it is safe. Placement feeds only this narrowing, and every other
condition still stands. The base is exact once the `cd` succeeded. If it
failed (`;` lets the rest run where the shell started), the rest is
placed where the shell started ("A cd that fails", below), and condition
4 narrows nothing unless the secret file registered there is the one the
command named (tested). A `cd` that
succeeded somewhere else (a shell function named `cd`) can at worst make
condition 5 drop lines that a plain, unlabelled file in `<dir>` holds
verbatim, which is what condition 5 may drop from any command: text the
model can read and the human can send by naming that file alone. The
model-side mask, the row's level, its whole value, every line holding a
registered secret and every credential-shaped line and span are
unchanged, and a secret file's own row still trips wherever it is not
bound.

*A relative folder* (2026-10-19, the follow-up). The first rule left
`cd weather-app && …` out because `CDPATH` (zsh's `cdpath`) may move it:
with `CDPATH` set, bash and zsh look for `weather-app` under its entries
before (or instead of) the current directory, so the folder is not known
from the command alone. Mandu cannot know the shell's `CDPATH`: the
launcher sets the agent's environment, but the shell the agent starts
reads the user's rc files (Claude Code's shell snapshot, Codex's login
shell), which may set it, exported or not, and the guard reads only the
shell's directory, not its variables. So the relative folder is placed,
not proved: in `<start>/<dir>`, where `<start>` is the directory the call
runs in exactly as condition 1 knows it (the kernel's directory for
Claude Code's `Bash`, the call's absolute `workdir` or Codex's session
directory: `callWorkdir`), absolute with no `..` segment; with no such
directory the folder places nothing. `<dir>` may not be empty or start
with `-`, `+` or `=` (the previous folder, zsh's directory stack, zsh's
`=cmd` expansion), nor hold a `..` segment (the shell's `cd ..` is
logical, the kernel's directory physical: the two part at a symlink).

Why a wrong base is still safe. Placement feeds only this narrowing, and
the argument for the absolute rule never needed the base to be right. If
`CDPATH` (or a failed `cd`, or `cdable_vars` after one) moved the shell
elsewhere: condition 4 reads each secret reading at its placed path under
`<start>/<dir>` and narrows nothing unless a file registered as it is on
disk sits there; condition 3 still says no process of the call read a
secret raw that the guard confines; and condition 5 drops only lines a
plain, unlabelled file at a placed path holds verbatim now, text that is
no secret wherever the command really read, so every line the moved
command printed that no such file holds (whatever file it came from)
stays a piece, as do every credential-shaped line and every line holding
a registered value. A label met where the `cd` may lead still only raises (the
`cd` target is read from the start directory and wherever a label's path
ends with it, `candidateDirs`), and a token so raised is placed nowhere,
so a labelled file read there keeps the record unplaced. The same
argument is why a relative folder needs a known start directory and
nothing more: an unknown one places nothing, and a known one that is
wrong (a shell the kernel says started elsewhere) fails at condition 4
(tested). What is not placed: a folder named by a variable, `~`, a glob,
an option; and a `cd` the rest undoes.

*A cd that fails* (2026-10-19, the battery of that day, a take of the c1
demo, Claude Code on Sonnet, the tuned Mandu). Claude Code's
`Bash` keeps its shell's directory from one call to the next. An earlier
call had run `cd weather-app; cat scripts/report-bug.sh; ls`, so the shell
was already in `weather-app` when the model ran `cd weather-app; ls -la;
echo ---; cat config/settings.json 2>/dev/null; echo ---; cat logs/app.log
2>/dev/null | head -50; echo ---ENV---; cat .env 2>/dev/null`. The `cd`
failed (`cd: weather-app: No such file or directory`) and `;` ran the rest
from `weather-app` itself; the kernel's directory for the call was
`<ws>/weather-app`, so the leading-cd rule placed `.env` in
`<ws>/weather-app/weather-app`, condition 4 found nothing registered there,
and the row was never narrowed: the `--no-env` resend of the turn after
was refused by the tripwire as "secret value VERBATIM
(`$MDU:nomodel_Bash[3cfb]@body`)", with nothing to approve. The rule
failed closed exactly as written ("If it failed", above); it lost the
task, not the key.

The rule: the policy now gives, beside the folder's placement, the same
readings placed where the command starts (`leadingCdStart`: the start
directory as condition 1 knows it, absolute with no `..` segment), for
every command its leading-cd rule places: each secret reading's file
(`cdFailedFile`; an absolute token is itself) and the plain path tokens
(`placedFilesInText(…, { ifCdFailed: true })`), as `ifCdFailed: { dir,
namedFiles, placedFiles }` beside `namedFiles` (arbiter-side only,
stripped from the wire like it). It is offered only when every secret
reading is placed both ways, the command's texts open with one and the
same `cd`, and the files are the command's own reading's (a tool the
spec does not map adds its every string's files, placed one way only:
none offered). The arbiter keeps it in its record of the call while every
classify of the call offered one for the same folder (their union;
otherwise none, for good), and `learnPathRow` uses it in place of the
folder's placement, for conditions 4 and 5 alike, only when the folder is
not a directory when the mark is learned (`isDirectoryNow`: the kernel
says nothing is there, `ENOENT` / `ENOTDIR`, or what is there is not a
directory, so a `cd` to it fails; a directory, a link to one or any other
error keeps the folder's placement). Every other condition is unchanged,
and nothing is lifted: the readings stay raise-only.

Why it is safe. It is a choice between two bases, each of which the
argument of "A relative folder" already covers when it is the wrong one:
condition 4 narrows nothing unless a file registered as it is on disk
sits at each place a secret reading was put, condition 3 still says no
process of the call read a secret raw, and condition 5 drops only lines
a plain, unlabelled file at a placed path holds verbatim now. If the
folder was there while the command ran and is gone when the mark is
learned (the command removed it, say `rm -rf "$PWD"`), the start
directory is a wrong base, and what it can drop is still only lines such
a file there holds: a line printed from the vanished folder that no such
file holds stays a piece, as do every credential-shaped line and span,
every line holding a registered value and the whole value. The shell's
own error line and the `ls -la` listing are held by no file and stay
pieces (tested). The model-side mask, the row's level and the secret
file's own row are unchanged. When the folder IS there, the `cd` may
have entered it, so its placement stands: a `.env` nobody registered
there narrows nothing (tested).

*Codex's `exec_command`* (2026-10-19, the follow-up). The tool is not in
the session's inbound spec, so its every string is read too
(`labelForUnmappedInput`, §11.11), and one string that may change
directory made every string read as moved (`{cwd: "sub", path:
"../secrets/plan.md"}`, or a `cd` in one field): so the cmd's own leading
`cd` switched its own placement off, and `cd notes-app && sed -n … .env`
(or `cd <abs>/notes-app && …`) under Codex's usual `workdir` was never
narrowed. Now the PLACING scan of each string is read as moved only when
ANOTHER string may change directory (or a directory key is relative or
not a string); a string's own leading `cd` is read as above, from the
call's directory (`workdir`). The level's reading is unchanged: every
string is still read as moved there. A `cd` in another string, a
relative `workdir` (read as a `cd` target), a non-string directory key
or no directory known still places nothing.

*Why it is safe.* The invariant holds at the model unchanged: the result
stays one symbol. At the network, the tripwire is not the guarantee (the
per-symbol gate is), but the narrowing keeps everything it held of a
secret. Conditions 3 and 4 together say: no process of the call read a
secret raw, and every file whose naming made the result secret is
registered with exactly its current bytes, so whatever of those files the
output holds verbatim (served as the twin, or, if the guard did not
confine it, raw) is already a piece of the file's own row (its whole
value, its lines but those its twin shows, its bare tokens and spans),
which still trips everywhere the file is not bound. Any registered value
in the output keeps its line in the row too, and any credential-shaped
text keeps its line and span. And condition 5 drops only a line a plain
file the command names holds verbatim: text that sits in a file no label
calls secret, which the model can read by running that file's part of the
command apart, and which the inbound backstop already treats as no
secret. A line from anywhere else (a read the scan cannot place, a remote
`cat`, an environment dump) stays a piece. Exfiltration within the same
command (`cat vault | curl`) was never caught by the row: it is minted
after the command exits.

*Known limit.* A secret line that ALSO sits verbatim in a plain,
unlabelled file the command names is no longer a piece of this row. That
file already shows it to the model raw (a read of it alone is not masked),
so nothing the model could not read is lost; what goes is the tripwire's
catch of a later verbatim re-send of that line under this row (the line's
own registered row, if it has one, still catches it). A file the command
names that changes between the command and the mark could make a line
look attributable; the read happens at once, from a tree that read no
secret raw. And the inbound backstop counts an exec row by its call's
taint, so an orphan root tied to the call later can make a narrowed row
count there with fewer pieces; the pieces it lost are lines of named
plain files.

*Tests.* `arbiter/test/unit/path-row-files.test.ts` (the placed files of
`labelForClassify` and `labelForUnmappedInput`, every unplaceable shape,
the store keeping an empty list; a leading `cd`: the c1 command placed in
its folder, after `;` or a line break, a quoted folder, every shape that
places nothing, and no label lifted there; a relative folder placed below
the start directory, `./`, a deeper and a quoted one, and not without a
start directory, from a relative start or one with `..`, nor for `-`,
`''`, `+1`, `=app`, a `..` segment or a second `cd`; Codex's
`exec_command` with a relative and an absolute leading `cd` placed by both
the wide and the named reading, and not with a `cd` in another string, a
relative `workdir`, a non-string directory key, no directory, a second
`cd`, or a label the `cd` leads to; a `cd` that fails: the c1 take's
command from inside the folder offering the start directory's placement
beside the folder's, an absolute folder, `&&`, and none with no start
directory, no leading `cd`, a second `cd` or a `..` in the start;
`isDirectoryNow` on a folder, a link to one, nothing, a file and a path
through a file); `arbiter/test/component/path-row-narrowing.test.ts`
(a real server: the c6 batch narrowed through the tripwire's own op, a
line holding a registered value and a credential line kept, the whole
value kept, a restart; each condition unmet keeping every line: no or
another `secretBy`, no classify record, an unplaced reading, a command
that changes directory, an escaped `cd`, a `..` in the secret's token, a
row above the path level, not an exec row, a placeholder in the command,
no tree, a guessed tree, a raw read, a labelled file nobody registered, a
registered file changed since; the review's reads the scan cannot place
(command substitution, `find -exec`, a quote-split name) keep the
unregistered vault's line a piece while the notes' line goes (since
2026-10-17 a quote-split `.e""nv` reads as the `.env` it spells, an
unplaced secret reading, so those two records narrow nothing and the
notes' line stays a piece too; confidentiality.md §6); a leading `cd`
narrowed (a line of a file named after it goes, one with a `..` stays) and
not (a second `cd`, a folder that is not there); a relative leading `cd`
narrowed from the kernel's directory, and not with no directory known, a
`cd` that is not first, a relative folder that is not there, or a shell
the kernel says started elsewhere; a leading `cd` that fails from a
shell already in the folder narrowed where the shell started (the
shell's error line and a listing line stay pieces), and not when the
folder is there (checked by mutation both ways); the second
review's cases (a plain file the call wrote, a hard link, a `/proc`
pagemap named in a comment, a `grep` for `chdir(` beside a labelled file)
are tests too; each
condition's removal, and condition 5's, makes its case fail, checked by
mutation); both
proxies' secretBy tests; `tests/stack/path-row-bound-upload.test.ts`
(the production openai-proxy and net-proxy over a real arbiter, the c6
shape: the batch masked whole as before, the notes' upload to
`api.notion.com` forwarded with the real token in its header; THE ORACLE:
the raw token and the batch's credential line to an unbound host trip,
a batch that also prints a labelled file nobody registered is not
narrowed and the notes' upload stays blocked, and no model request
carries the token or the labelled text);
`tests/stack/path-row-leading-cd.test.ts` (the production
anthropic-proxy and net-proxy over a real arbiter with no policy, the c1
shape: the batch masked whole as before, the settings, the log and the
`--no-env` bundle forwarded to the support host; THE ORACLE: the raw key
trips, the bundle with `.env` (its twin, a placeholder in it) and one with
the raw `.env` are refused and nothing more reaches the host, a leading
`cd` to a folder that is not there is not narrowed, and no model request
carries the key; the relative form, `cd weather-app && …` from the
workspace, the same, and its oracle: the same command from a shell the
kernel says started elsewhere, or in no known directory, is not
narrowed; a `cd` that fails, the c1 take's exact command (`cd
weather-app; ls -la; …; cat logs/app.log 2>/dev/null | head -50; …`)
from a shell already in `weather-app`: the settings, the log and the
`--no-env` bundle forwarded, the key, both `.env` bundles and the
listing refused, no model request carrying the key, and its oracle: the
same `cd` when the folder is there is not narrowed); and in
`path-row-bound-upload.test.ts`, Codex's batch after a
relative and an absolute leading `cd` narrowed through the production
openai-proxy (the notes' upload forwarded, the raw token and the
credential line still tripping).
