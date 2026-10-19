# Read results: what a Read symbol stands for, and the two shapes that pass raw

> **Status: built 2026-09-21; frozen with the integrity axis (2026-09-28,
> [`protection-modes.md §10`](../architecture/protection-modes.md)).** The record
> stays; nothing here is extended.
>
> **Still running in `secrets` mode:** §3, and §4 as it applies to a
> secret-labelled result. The proxy un-renders every symbolized `Read`
> result whatever the reason for the symbol, so a secret-labelled Read
> stores the file's bytes, and a reminder tail never rides inside a secret
> value. Integrity-only, frozen: the two raw shapes of
> §5 and §6, which are trust verdicts (the whole-file twins of §5 exist only
> while fs-sync runs, [`fs-sync.md`](./fs-sync.md)).
>
> Scope: the model-API chokepoint for Claude Code's `Read` tool
> (`interceptors/anthropic-proxy/src/rewrite-request.ts`,
> `arbiter/policy/claude-code-inbound.ts`). Companion to
> [`symbol-twin-shell-blindness.md`](./symbol-twin-shell-blindness.md) (the
> same twins, read through the shell).

## 1. The incidents

Three findings from the live drills (2026-09-20), all on the `Read` path,
reproduced on haiku and sonnet.

**The write-back carried the rendering (U17, U22).** An AgentView (repo: Agent
File System / agent-view) twin holds nothing but the file's `$MDU:*` token.
Claude Code renders any Read as `<line number><separator><line>` per line, so
the tool_result of a twin is

```
1	$MDU:Read[530e].source.txt
2
```

The Read rule is whole-result fail-closed UNTRUSTED, so the proxy wrapped that
rendering in a second symbol, `$MDU:Read[e5ba]`. The model copied the file by
writing `$MDU:Read[e5ba]`; fs-sync desymbolized it deeply into the HumanView
(repo: Human File System / human-view), and the user's file received the
wrapper's value: a `1<TAB>` gutter, the file, a stray `2` row. U17 had passed
on a substring match. Under an exact-content check it fails, and in U22 the
renamed `src/util.js` no longer parsed.

**The reminder rode inside the symbol (U17, U25).** Claude Code appends an
"MCP Server Instructions" `<system-reminder>` to a session's first tool_result.
Only the digits-only token-budget reminder was split off; any other tail sent
the result down the whole-result path, reminder included. It was part of the
symbol's value, so it was part of the write-back.

**A harness notice was symbolized like content (U25).** The second Read of an
unchanged file returns, instead of content, `Wasted call — file unchanged since
your last Read. Refer to that earlier tool_result instead.` The Read rule
symbolized it; haiku wrote that token into the user's file.

A fourth effect was never reported as a failure but is the same defect: with
only the wrapper in context, the model never learned the twin's own token,
which is the only `old_string` an `Edit` of that file can match.

## 2. Principle

A symbol's **value is what every later resolve yields**: the HumanView
write-back, the reply filter's terminal, an inspect. For a Read that value must
be the **file's bytes**. The rendering is harness framing, like the reminder
tails, and framing does not belong in a value.

Nothing here relaxes the invariant. Every byte of file content still reaches
T-LLM (repo: privileged LLM) only as a symbol. The two shapes that pass raw
carry no file byte at all.

## 3. The symbol stands for the file's bytes

`unrenderReadResult` (proxy) undoes the rendering before `symbolize`:
`<n><sep><line>` per line, `sep` a tab, `:` (Claude Code's tab-aware form) or
`→` (older padded builds). It is strict: every line must carry a gutter and the
numbers must run consecutively. A trailing number-only row is the rendering of
the empty line after a final newline, whose separator the harness trims when a
reminder follows; it restores that newline. Anything else (a truncation header,
a notice, a forged shape) returns null and the wire bytes are symbolized exactly
as before.

It grants no trust and forwards nothing. It only chooses the value stored
behind a symbol that is minted either way. It is `Read`-only: a Bash `cat -n`
output that looks numbered keeps its bytes.

The audit keeps the wire span (`value`, `symbolizedSpan`) for the §9 oracle and
records the stored value as `symbolValue`; the symbolize event shows the latter.
`mustNotSurvive` deliberately checks the wire span only: the un-rendered bytes
are derived from it line by line, so its absence proves theirs, and being
shorter they would collide with trusted text far more often.

## 4. An unvouched reminder tail is dropped

When the body is untrusted and the trailing `<system-reminder>` block(s) are
not the token-budget shape, the body is symbolized alone and the tail is
**dropped** from the forwarded result. It is never raw, and it is no longer part
of any value.

Dropped rather than symbolized on its own: T-LLM could not read it either way,
and a second token beside the result is the decoy this proxy already paid for
once (a weak T-LLM answers with it; see the token-budget rule). Nothing is lost
to the audit: `value` keeps the wire bytes and `droppedTail` names what was cut.
A reminder forged inside a tool's own output is cut the same way. This applies
to every tool, not only Read. A token-budget tail is dropped too when its
verdict carries a secret level (a labelled Read's tail inherits the path's
level); the §9 oracle then looks for it in the Read's own block only, since the
harness appends the same reminder to the turn's other results
(`crossResultSpans`, implementation-plan.md §9).

The trusted-body path is unchanged: there the tail is still symbolized under
`system_reminder`, because the body next to it is readable text, not a token.

## 5. Raw shape one: the rendering of a whole-file twin

`isPureSymbolicReadRendering` (arbiter). A `Read` whole-result is TRUSTED iff
every line is a gutter followed by nothing or by exactly one complete `$MDU:*`
token, at least one line carries a token, and **every token is an allocated
name in the arbiter's own symbol table, by exact match**.

The exact-allocation test is the point. The token grammar's field tail admits
identifier characters, and the resolution walk (`findSymbolByName`) is lenient
about mutated tails by design, so without it a forged file could pass
`$MDU:Read[530e].any_words_it_likes` through as "a token". With it a line
carries a name the arbiter itself minted, or the result stays symbolized. It is
injected as `symbolAllocated` (`symbols.has`, not the walk); an engine without
it never fires the rule.

**What a forger gets.** A file outside the AgentView may literally contain
token text, so its author chooses which existing tokens the model sees bare.
The wrapper withheld nothing there: desymbolization is deep, so a wrapper
resolves through the inner token at the same egress gate under the same labels.
The wrapper hid the choice from the model only, never from the policy.

**Confidentiality is untouched.** The label derivation runs after the trust
verdict, so the twin of a secret path is still symbolized by the proxy with its
label, and §3 gives that symbol the right bytes.

Keyed like the inspect refinement: `spec === CLAUDE_CODE_INBOUND_SPEC.Read`, so
the tool is exactly `Read` under the claude-code spec and an explicit override
(a YAML tool rule) still wins. Whole-result only.

## 6. Raw shape two: Claude Code's Read notices

`isReadHarnessNotice` (arbiter), extracted from the 2.1.273 bundle, each matched
as the whole value under tool `Read`:

- the two "file unchanged" sentences, exact match;
- the seeded form (`This file is already in your context (see "Contents of
  <path>" above)…`), whose one free span must equal the call's own
  `file_path`;
- the empty-file and shorter-than-offset warnings, whose only free spans are
  integers.

A reminder-wrapped notice may be followed by token-budget block(s), because the
proxy cannot split a value that is all reminder blocks.

A file cannot forge one: genuine content is always rendered behind a gutter
(`1<TAB>…`), so no file's Read result can equal a notice, and an exact-match
channel carries no attacker-chosen byte. Same bar as the input-validation
rejection rule.

Version drift is safe in one direction only, the right one: a reworded notice
in a later Claude Code simply stays symbolized.

## 7. What this does not fix

- A partly literal file (a human-edited twin, [`fs-sync.md`](./fs-sync.md) §2.5a) is not
  purely symbolic, so its Read is still one symbol. §3 makes that symbol
  resolve to the file's bytes.
- `offset`/`limit` Reads and harness truncation (2000 lines, long lines)
  symbolize the range the harness returned; a write-back of it is that range.
- A CRLF file loses its `\r` in Claude Code's own rendering, before the proxy
  sees it.
- Other agents' read tools (`read` on OpenClaw, OpenCode) have their own
  renderings and keep today's behavior.

## 8. Tests

- `arbiter/test/unit/claude-code-policy.test.ts`: the live renderings, the
  forgery list (prose beside a token, two tokens, a literal line among twins,
  an invented tail, an unminted name, no allocation test wired), Read-only and
  whole-result-only, the secret-path label, every notice and its forgeries.
- `interceptors/anthropic-proxy/test/unit/rewrite-request.test.ts`:
  `unrenderReadResult` shapes and refusals, file bytes as the symbol's value,
  the budget and MCP tails, Read-only scope, the raw twin passthrough, and the
  five split tests moved to the dropped-tail contract.
- `tests/integrity/read-result-rendering.test.ts`, real arbiter and real
  proxy: a raw file Read resolves byte for byte to the file (U22); a twin is
  forwarded byte-identical (U17); four forgeries are symbolized; the notice
  passes raw while a file containing that sentence does not (U25). Every case
  asserts that no raw untrusted byte is forwarded.
- Live: drills U17, U22 and U25 (`file_matches`, exact content) pass on
  haiku: `deploy.txt` is exactly the token's value, both renamed source files
  start with their first statement and `node src/app.js` runs, and
  `out-b.txt` holds the value.
