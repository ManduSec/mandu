# Reply row reservation — multi-line secrets on the human's terminal under a live TUI

> **Status: BUILT (2026-09-30).** This is the reply filter's design spine for
> what the human sees under a live TUI. v1 (§3) reserves one row per value
> line for a token alone on its line; v2 (§11) wraps long lines, expands a
> token inside a sentence, and covers Codex; the span form (§12) handles a
> token that is a whole code span (Claude Code only); a resize re-lays a block
> out at the narrower width (§13); text after a mid-line value breaks where
> vanilla wraps it, and a table's first cell is left alone (§14). The
> structured (`json` / `stream-json`) pipe output is §15, and Goose's ACP
> stream to an editor §15.4. A TUI that leaves the wrap to the terminal
> (Goose) gets its rows laid out by the terminal's character wrap instead of
> Ink's word wrap (§17). A TAB in a value reaches the stop the agent's TUI
> puts it at: counted from the screen's column 0 (Codex, §19), or from the
> text's own left edge (Claude Code, which expands its TABs itself, §19.7).
> The live gates
> (`echo-fidelity-rows`, `-wrap`, `-inline`, `-codespan`, `-resize`,
> `-suffix`, `-long`) match vanilla Claude Code on both renderers at 80×24
> and 160×40 (§7). §8 lists what is left; §9 records the decisions. §16
> says how the launcher starts the filter (early, handed the agent at the end).
>
> **Vocabulary.** The token `$MDU:` and the levels `public | any-model |
> local-model | no-model` (confidentiality.md).
> T-LLM (repo: privileged LLM) is the model that acts. HumanView is what the
> human sees. The *reply filter* is `interceptors/reply-filter`, and the
> *proxy* is `interceptors/anthropic-proxy`. In this note a **reserve block** is
> the placeholder text defined in §3.1. It is not the user-facing word
> "placeholder", which the product uses for a `$MDU:` token.

## 1. The problem

The model sees a `no-model` file only as a token, so its reply names the token:

```
Mandu has locked your ~/.ssh/config at the no-model level, so I can't see
what's in it. The reply filter should show you the real file below:

$MDU:nomodel_Bash[464e]
```

The reply filter resolves the token on the way to the terminal. In pipe mode
(`claude -p`, a non-TTY stdout) it writes the whole value with its real line
breaks. Under a live TUI (the PTY relay, eager mode) it cannot:

- Claude Code lays out its frame from the text it received, and that text is
  one short token on one row.
- Writing a multi-line value there pushes the cursor through rows the TUI
  does not know it painted. Its next repaint then erases the wrong regions.
  The differential harness caught this on its first run.
- So the filter renders the value frame-safely (`filter.ts`, FRAME-SAFE VALUE
  RENDERING): one row, newlines as ` ⏎ `, auto-wrap off so the row clips at the
  right edge. The fullscreen reconciler (`screen-reconcile.ts`) does the same.

The result is readable for a one-line credential. For any real file it is
useless: `Host a ⏎   HostName … ⏎   User git ⏎ …`, cut off at column 80.

Both headers say it outright: *multi-line values CANNOT be reflowed into a
positioned frame from outside the renderer.* This note keeps that statement and
works around it: **the renderer lays out the rows itself, because the text it
receives already has them.**

## 2. The idea

Claude Code counts rows from the text the API returns. The proxy sits on that
path. When the model's reply holds a token on a line of its own, and the token
stands for an N-line value, the proxy sends Claude Code an N-row **reserve
block** in its place. Claude Code wraps, lays out and repaints N rows with its
own arithmetic. The reply filter then paints line *i* of the value into
reserved row *i*. Each row is still rendered frame-safely, so a wrong guess
degrades to today's clip and never to a corrupted frame. On the next request,
the proxy collapses the block back to the exact token before the model sees
its own history.

```
model ──SSE──▶ proxy ──expand──▶ Claude Code ──lays out N rows──▶ PTY ──▶ reply filter ──paints lines──▶ human
  ▲                                   │
  └──── request ◀── proxy ◀─collapse──┘  (history carries the block; the model gets the token back)
```

The value never leaves the arbiter on this path, except to the reply filter as
today. The proxy learns only N, the line count (§3.3, security in §5).

### 2.1 Where this sits among the options already weighed

The differential harness's notes weighed three ways forward for renderer
trouble:

- **A**, a screen-cell reply filter: built as the fullscreen reconciler
  (`screen-reconcile.ts`). It cannot reflow.
- **B**, releasing originals at the proxy and re-symbolizing on the way back:
  the "designed follow-up" for this exact clip. The reconciler's design set
  it aside as a new release surface. Originals would live in Claude Code's memory and its
  transcript on disk, and the proxy would need a general originals→symbols
  reverse map.
- **C**, the status quo.

Row reservation takes B's one good property, that the renderer lays out the
right geometry, without B's release surface. Claude Code receives a line
count, never an original. The reverse map is exact and stateless, because the
block embeds its token (§3.4).

Other options considered and not taken as the fix. They stay as fallbacks or
follow-ups (§8):

- **The first line plus a pointer** (`Host a … (+22 lines)`): honest, but
  still not the file.
- **`mandu reveal <token>`** in a second terminal: useful, but a detour.
- **Printing the flattened values after the TUI exits:** correct, but late.
- **Clear-and-redraw from the filter:** this is A's race between two writers
  of one screen.

## 3. Design

### 3.1 The reserve block

A token that is alone on its line, `T` = `$MDU:<tag>[<hash>]<.field…>`, with
an N-line value (N ≥ 2 after the trailing newline is dropped), is replaced by
exactly N lines:

```
T/1:N
$MDU/<hash>/2
$MDU/<hash>/3
…
$MDU/<hash>/N
```

- **The head row** is the token verbatim, followed by `/1:N`. It keeps the
  whole token, so collapse needs no state (§3.4), and a reader of the raw
  transcript still sees which secret stood there. The `/` ends the
  token grammar (`SYMBOL_TOKEN_RE` stops at `]` or at the field path), so an
  older filter still resolves `T` and leaves `/1:N` visible. That degrades,
  but does not corrupt.
- **A continuation row** is `$MDU/<hash>/<i>`. It carries no `:`, so it can
  never match the token grammar or the candidate-prefix hold in `filter.ts`.
- **Every row is non-empty and a single word.** Claude Code turns single
  newlines inside a paragraph into rows (measured: the echo scenarios,
  `differential-screen.test.ts:120`). Ink wraps a word whole, and the words
  are far below any sane content width. A blank value line still gets a
  marker row, so Markdown can never merge two blank lines into a paragraph
  break and lose a row.
- **ASCII only**, with no Markdown-significant characters at the start of a
  row (`#`, `>`, `-`, `+ `, `*`, `1.`, a backtick, `~`). `$`, `/`, hex digits,
  `:` and the token's own characters are inert. The underscore inside `T`
  already renders intact today.

*Phase 0 confirmed this grammar* (§7.1). Every row rendered as its own row
with its marker intact, at the 2-column content indent, or 4 columns when
Markdown folds the block into a preceding list item. A fenced code block is
not needed. A model's fenced block still works: the fence rows vanish and the
markers render in the code color. A Markdown-escaped head
(`\$MDU:nomodel\_Bash[…]`) renders unescaped on screen, so the filter matches
the unescaped form, while collapse restores the escaped text exactly as the
model wrote it.

### 3.2 Which tokens are expanded (eligibility)

The proxy expands `T` only when **all** of the following hold. Otherwise `T`
passes through byte-identical, which is today's behavior:

1. **The session is relayed through a PTY** by a reply filter that knows
   reserve blocks. The filter reports its mode to the arbiter (§3.6). An
   unknown, pipe or passthrough mode means no expansion: pipe mode already
   renders multi-line values in full, and a block there would be noise.
2. **The model is on the Messages wire, streamed.** This is Claude Code's
   interactive path. The non-streaming JSON path (`bufferAndSniffJson`), the
   routed OpenAI path inside the proxy, and the Codex `openai-proxy` are out of
   scope for v1; v2 adds the Codex proxy (§11.7).
3. **The block is a text block of an assistant message.** It is never a
   `thinking` block (its signature must survive) or a `tool_use` input.
4. **`T` stands alone on its line:** the character before it is the block
   start or `\n`, and the character after it (and its Markdown escapes,
   handled as `unescapeSymbols` does) is `\n` or the block end. A token in the
   middle of a sentence keeps today's one-row rendering.
5. **The arbiter knows the value's shape** (§3.3), and N ≥ 2.
6. **N is at most `RESERVE_MAX_ROWS`** (default 40, `MANDU_REPLY_RESERVE_MAX`).
   A longer value reserves `RESERVE_MAX_ROWS` rows, and the filter paints the
   last one as `… +K more lines (full value: mandu dashboard)`. The cap bounds
   both the visual cost and the line-count information (§5).

A kill switch, `MANDU_REPLY_RESERVE=0`, disables expansion everywhere. The
launcher passes it to the proxy's environment.

### 3.3 Learning N without the value: the `symbolShape` op

The proxy never calls `desymbolize` or `resolve` today, and this plan keeps it
that way. It adds one arbiter op:

```
symbolShape { token } → { lines: number } | null
```

- It resolves deeply, as `desymbolize` does, so nested chains and field paths
  resolve.
- It drops one trailing newline, then counts lines.
- It returns only the count: no length, no widths, no label.
- An unknown token returns `null`, and the proxy does not expand.

It is served on the data socket with the same exposure as `desymbolize`. That
is deliberate, and §5.3 states what it implies.

Caching N at mint time was also considered. The proxy handles the raw value
when it symbolizes a `tool_result`, but that misses field paths, derived and
U-LLM symbols, registered secrets, and tokens minted in an earlier proxy
process. A cache also keeps no promise the op does not already keep. It is
not taken.

### 3.4 Collapse on the request path (the model gets its token back)

Claude Code re-sends the whole history on every request, including the
compaction request and any `--resume`. So the reserve block comes back in the
assistant turns, and in anything Claude Code wrote to disk that a tool later
reads. Before the model sees any of it:

1. **Exact collapse, in assistant text blocks only.** Each well-formed block
   (a head row `T/1:N` followed by exactly the N−1 continuation rows with the
   same hash and indices 2..N) is replaced by `T`. Expansion only ever fires on
   a line boundary, so `collapse(expand(t)) === t` byte for byte. That is the
   property the prompt cache needs: the assistant prefix the model produced is
   the prefix it gets back. Thinking blocks are never touched.
2. **Residual strip, everywhere.** After collapse, any leftover fragment,
   whether a head suffix `/1:N` after a token or a continuation row
   `$MDU/<hex>/<n>`, is removed. This covers user text, `tool_result` content
   (for example, the agent read Claude Code's own transcript file) and an
   assistant turn the client edited or truncated. Removal is the fail-closed
   choice here. The fragment carries only line-count information, so
   refusing the whole request (`RewriteRefusal`) would brick the session to
   protect a count the model can do nothing with. The strip emits a
   `reserve_residual` event, so a surprising source shows on the dashboard.
3. **Order.** Both steps run on the parsed body **before** `rewriteRequest`,
   so the trusted-context haystack (`buildTrustedContextHaystack`, whose
   TRIPWIRE requires any change to non-`tool_result` blocks to be reflected
   there) and every later step see the model's own text. The count_tokens
   branch gets the same pass.

Collapse is pure and needs no arbiter or proxy state. It survives a proxy
restart, a reused proxy daemon and `--resume`. It never throws: a malformed
block falls through to the residual strip.

### 3.5 Expansion on the response path

- **Where.** A new transformer runs after `SseTextDeltaRepacker` in
  `streamAndSniffSse` (`proxy.ts` ~2036, plus the drain paths at ~2057 and
  ~2088). The repacker already guarantees a token arrives whole in one
  `text_delta`. The expander adds a one-character lookahead hold for the
  eligibility test in §3.2 item 4. The hold is per content-block index, the
  repacker's model, and is released on `content_block_stop` or any
  non-text event of the block.
- **The sniffer taps before the expander**, so `SseToolUseParser`,
  `assistantText()` and the `tllm_call` event record the model's real text,
  never the block.
- **The arbiter call is asynchronous inside the stream.** The existing
  promise chain keeps event order. A `symbolShape` that fails or exceeds its
  deadline (default 150 ms) means no expansion. On the response side the fail
  safe is "no rewrite, never guess" (`sse-rewrite.ts`). The latency is one
  IPC round trip per eligible token, paid only when a token is alone on a
  line.
- **The expanded text goes out as one `text_delta`**, so Claude Code never
  lays out half a block.

### 3.6 The session's relay mode: `setSessionRelay`

Nothing tells the proxy today whether a reply filter relays this session
through a PTY. The launcher gives the proxy no terminal information, and the
reply filter's `relay_mode` is an event, not state. This plan adds:

```
setSessionRelay { sessionKey, mode: "pty" | "pipe" | "passthrough", reserve: boolean, cols, rows }
sessionRelay    { sessionKey } → the same, or null
```

- The reply filter calls `setSessionRelay` once it has decided its mode, and
  again on resize. `reserve` says it can paint reserve blocks, so an older
  filter never gets blocks it would render raw.
- The proxy reads the state per response, cached for one second.
- The session key is the one both already share (`MANDU_SCOPE_ID` =
  `MANDU_SESSION_KEY`).
- `setSessionSpec` (`protocol.ts` ~691) is the precedent for this in-memory,
  session-keyed state.
- **Null means no expansion.** A race at start, where the first response
  arrives before the filter reports, costs one reply its reservation and
  nothing else.

`cols` and `rows` were unused in v1. v2 sets the wrap width from `cols` and
adds `wrap`, and both relay ops moved to the human plane (§11.5).

### 3.7 Painting on the reply filter

- **The value cache.** The filter resolves `T` once per session through
  `desymbolize`, as today, and caches the value's lines. The reconciler
  already caches this way. The stream filter gains the same bounded cache.
- **Two writers, on both screens.** Phase 0 showed that the stream alone
  cannot paint the rows (§7.1). The first paint of a marker row is
  contiguous on the wire. But when a later frame shifts the reply by a row,
  Ink's cell-diff repaint compares the new row with the old one at the same
  position. `$MDU/464e/3` replacing `$MDU/464e/2` then goes out as a cursor
  move and the one changed cell (`\r ESC[14C ESC[1B 3`). This happens on the
  main screen (the inline renderer) as well as the alternate screen. So:
  - the **stream splice** paints every contiguous marker it sees. That covers
    the first paint, including rows that scroll into scrollback within the
    same write, where no later repaint can reach them;
  - the **screen reconciler** repaints every visible row that holds a
    marker. It is extended to the main screen for reserve rows (tokens on
    the main screen keep the stream-only path but after a split fragment,
    docs/testing/differential-interactive.md §30), and it heals the
    fragments the cell diff leaves.

  This is the reconciler's existing convergence rule: a row the splice
  already made right compares equal and is left alone.
  On the alternate screen a fragment that carries the marker's `$MDU/`
  (the cell diff skipped a cell inside the hash, `ESC[3G $MDU/ ESC[9G
  101/3`) would reach the terminal raw before the reconciler heals the row,
  so the relay blanks every `$MDU` run in the stream's output there and the
  reconciler paints the row (differential-interactive.md §19.1, the
  `echo-fidelity-long` @160×40 flake).
- **The stream splice.** The filter recognizes a head row `T/1:N` and each
  continuation row `$MDU/<hash>/<i>` as a splice unit, like a token today.
  A head whose token the TUI restyled mid-token (SGR sequences inside it,
  no line break: Goose's Markdown streamer colors `$MDU:nomodel` and
  `_shell[…]` apart) is still one unit; before 2026-10-06 it fell to the
  plain-token path and left `/1:N:W:F` on the screen
  (differential-interactive.md §32).
  It splices `frameSafeValue(line_i)` over the marker bytes:
  - one row, control bytes stripped, a TAB expanded to its tab stop;
  - padded with spaces to the marker's width when shorter (the ghost-tail
    rule). The screen reconciler does not pad: its desired(row) puts the
    text that follows a row's marker right after the value and erases the
    row's tail (CLOSE UP, differential-interactive.md §31), so suffix text
    after a short last row never sits behind a run of spaces;
  - bracketed in `ESC[?7l … ESC[?7h` and clipped at the edge when longer.

  Leading spaces in `line_i` are painted, so indentation, such as the
  `HostName` lines of an ssh config, survives. The column-translation model
  (POST-SPLICE COLUMN TRANSLATION) applies unchanged, one row at a time.
- **The screen reconciler, main and alternate screen.** `screen-reconcile.ts`
  reads rows. A row whose cells hold a head or continuation marker gets
  desired(row) = that row with the marker replaced by `line_i`, and the
  existing repaint path does the rest. On the main screen, the models must
  follow scrolling, which `@xterm/headless` does. A repaint addresses only
  viewport rows and puts the cursor back where the TUI believes it is, as on
  the alternate screen. A repaint drops the code color of a fenced block's
  row (the pen is reset), which is accepted.
- **Residual, stated honestly.** A cell-diff fragment written to a row that
  scrolls into scrollback within the same write, before the reconciler runs,
  stays there, for example a value line with one stray marker digit. Phase 0's
  captures show fragments only on re-layout frames, not on first paint.
  *Measured (2026-09-30), §7.2:* none in practice. A 33-row block that
  scrolls off at 80×24 and 160×40 left 0 residue rows, with all 32 value lines
  in the human's scroll history, on every inline lane.
- **A row stays owned once it holds a value.** The first version released a
  row the stream had already painted right, and only kept rows the
  reconciler repainted. But the TUI believes such a row holds the shorter
  marker. When a re-layout later cell-diffs prose of the marker's width over
  it with no erase, the value's tail survives past the prose
  (`DIFF_S1_DONEnovember DL30END`, fullscreen 160×40, §7.2). Every row that
  holds a substitution is now owned, so it is reconciled again when the TUI
  rewrites it.
- **Both models see the same bytes.** At the end of a read the stream filter
  holds anything that could still be an in-flight token; a reserve head
  `T/1:N:W:F` that ends a read is held together with its line break, because
  the head grammar is open-ended. The TUI model takes only what the stream
  filter has let through: run.ts passes `filter.held`, the held suffix of the
  input, to `feedTui`, which keeps those bytes back until a later write or
  the idle drain releases them. Otherwise the TUI model's cursor runs a row
  ahead of the terminal's, and a relative repaint (`CUU 1`) lands on the row
  above the head — a vanished prefix, a value row painted over the line
  above, or every later row shifted by one (an intermittent e2e failure
  before the fix).
  - Unit tests split a mid-line first paint at every offset, with the block
    at the top of the screen and below shell output, and check every row.
  - The e2e keeps the banner on the terminal above the block and asserts
    that no row above it holds any of the value.
- **A headless block** (§3.8): a continuation row whose head the filter never
  saw finds the head through the arbiter's block registry, then paints as
  above.
- **Without the arbiter**, when the value is unknown or `desymbolize` fails, a
  continuation row is painted as blank spaces of its width. The row carries
  no information, and a column of `$MDU/464e/7` rows reads as broken. The
  head row stays `T` plus a plain ` (N lines)` suffix in place of `/1:N`.
  Nothing can leak, because there is no value to leak.
- **The cap row.** Past `RESERVE_MAX_ROWS`, the last row shows the `… +K more
  lines` note.
- **Observability.** The `onResolve` event records the head splice with the
  whole value, so the dashboard and `human_sees` keep one record for each
  value, not N.

### 3.8 The block registry: a block whose head never reaches the screen

A continuation row carries only its token's hash, and the filter finds its
value through the last head it saw with that hash. **Claude Code's
fullscreen renderer can show a block without ever painting its head.** A
block taller than the viewport is laid out, and only its tail is painted.
`echo-fidelity-long` (§7.2) found every such row blank: 16 blank rows at
80×24, and 31 at 160×40 whenever the head had scrolled out before it was
painted. The inline renderer always paints the head first, so it never
showed this.

**The registry.** The proxy knows every block it sends, so it records each
one with the arbiter before the block goes out:

```
noteReserveBlock { sessionKey, token, n, width?, first? }   (proxy → arbiter)
reserveBlock     { sessionKey, hash } → { token, n, width?, first? } | null   (filter ← arbiter)
```

- **The proxy** (`SseReserveExpander` and the Codex `ResponsesReserveExpander`)
  awaits `noteReserveBlock` under the same 150 ms deadline as its other calls.
  The note is sent before the block, so it is recorded before any of the
  block's rows can reach a screen. A failure or a timeout is ignored: the
  block still goes out, and a headless row paints blank, as before.
- **The arbiter** takes exactly one symbol token (unescaped, like
  `symbolShape`), takes the hash from the token itself, and validates `n`
  (2..200) and `width`/`first` (§11.3 ranges, together or not at all). It
  keeps the blocks in memory per session, 1,024 per session and 4,096
  sessions, dropping the least recently noted. `deleteSession` clears them.
  Nothing is resolved and no value is held.
- **The filter's reconciler** asks `reserveBlock` when a continuation row's
  hash has no head it saw. It notes the head as if it had been seen, resolves
  the value as it does for a head, and lays the row out. An unknown hash is
  asked again only after the unknown-token backoff (300 ms). The stream
  splice keeps its blank fallback, and the reconciler repaints over it.

**Security.** Both ops are human-plane (`HUMAN_PLANE_OPS`,
arbiter-human-plane.md §3). The registry holds tokens and the N the proxy
already got from `symbolShape`, which is where that count already lives.
Nothing on the model's path changes. The agent's world can neither write a
record, which would make the filter paint a different secret into a row,
nor read one.

## 4. What the human sees

| Situation | Today | With row reservation |
|---|---|---|
| Multi-line token alone on a line, PTY relay | One `⏎`-joined row, clipped | The value line by line, each line clipped at the edge |
| Token in the middle of a sentence | One row, clipped | Unchanged |
| Pipe mode, `-p`, stream-json | Full multi-line value | Unchanged (no expansion) |
| Arbiter down | The token | The token, a `(N lines)` note and blank rows (only when the proxy expanded before the arbiter went down) |
| `MANDU_REPLY_RESERVE=0` | — | Today's behavior |
| Value longer than 40 lines | One row, clipped | 40 rows, the last a `+K more lines` note |
| Block taller than a fullscreen viewport (head never painted) | One row, clipped | The visible rows, each its value line (§3.8) |
| A line wider than the terminal | Clipped | Wrapped over reserved rows, as Claude Code wraps prose (v2, §11) |

## 5. Security

The rule this must not break: a secret reaches a model only as an opaque
symbol unless its level admits that model, and never leaves the machine
unless a binding or the human allows it
([CONTRIBUTING.md](../../../CONTRIBUTING.md); the integrity form is frozen and
does not change here.)

### 5.1 No original moves anywhere new

- The proxy gets N from `symbolShape`. It never receives a value on this path.
- Claude Code gets the reserve block: the token it already had, a count and
  inert markers.
- The reply filter resolves exactly as today. It writes to the human's
  terminal, which the agent cannot read (confidentiality.md §7, reply-filter
  row).
- No egress, gate or label decision reads the block. A reserve block in an
  outbound network body carries no original.

### 5.2 The new information is N, and the model never receives it

This is the one new flow, stated so it is not missed: **the line count of a
secret value now exists in the agent's world.** It sits in Claude Code's
memory and in its transcript under `~/.claude/projects/`, which the agent's
tools can read. Nothing on the model's path carries it:

- **History.** Exact collapse (§3.4, step 1) returns the model's own token.
- **Anything else.** The residual strip (§3.4, step 2) removes every marker
  from every text block, `tool_result` content included, before
  `rewriteRequest`. So an agent that `cat`s its own transcript gets the
  markers stripped on the way to the model.
- **Accepted residual, stated honestly.** A tool that *transforms* the
  transcript before the model sees it (`base64`, `wc -l`, a script that
  counts marker rows) can carry N past the strip, because the strip matches
  the literal grammar. To do that, the model must already be steering tools
  at Mandu's own bookkeeping. The prize is a line count capped at
  `RESERVE_MAX_ROWS`: at most about 5.3 bits (log2 40) per displayed secret, with no
  byte of content. It is accepted and documented, not closed.
- **The option to shrink it** (§9, D1) is to round N up to a bucket (2, 4, 8,
  16, 24, 40) and paint the spare rows blank, at the cost of trailing blank
  rows on screen.

### 5.3 `symbolShape` on the data socket

- The op answers any data-socket client, as `desymbolize` does. `desymbolize`
  is label-unrestricted by design and returns originals. Anything that can
  reach it already gets strictly more than a line count, so `symbolShape`
  adds nothing to that surface.
- **The probe (§7.1) found that the agent's own tools could reach the data
  socket and call `desymbolize`.** The socket is allowed through every
  default layer on purpose, for the shims (`unix-policy.ts`,
  `claude-sandbox.ts`), and the classify-time value backstop re-masks an
  original that comes back verbatim in a `tool_result`, but not a
  transformed one. That was a finding against the existing surface, fixed
  before this feature shipped
  ([`arbiter-human-plane.md`](../architecture/arbiter-human-plane.md)): the
  ops that return originals answer only on a third socket, the human plane,
  which the launcher walls off from the agent's world. `symbolShape` is a
  member of that set. The Claude proxy alone among the context proxies receives
  `MANDU_ARBITER_HUMAN_SOCK` (`launcher/src/services/context-proxy.ts`) and
  asks for shapes over a second client (`ArbiterClientAdapter(client, human)`).
  Without it, `symbolShape` answers null and nothing expands. In v1 the
  relay ops stayed on the data socket, where a forged report cost at most a
  reservation. v2 moved them to the human plane too, because `cols` now sets
  the width that rows are counted at (§11.5). The block registry's two ops
  (§3.8) are human-plane as well.

### 5.4 Fail-closed character

- **The response side** fails to *no expansion*: the token as today.
- **The request side** fails to *strip*: markers removed, never passed on.
- **The reply filter** fails to *blank rows*: no value shown, nothing
  corrupted.
- None of the three fails open, and the first two cannot fail toward the
  model.

## 6. Tests

Every test file is listed in `tests/suites.mjs` with its kind and axis
(`secrets`), and every test states its axes.

**Unit**
- `arbiter`: `symbolShape` (deep resolution, a field path, the trailing
  newline dropped, an unknown token → `null`, no value in the response shape;
  `symbol-shape.test.ts`); `setSessionRelay` / `sessionRelay` round trip and
  per-session isolation (`session-relay.test.ts`); the block registry's store
  and ops (`reserve-block-store.test.ts`).
- `anthropic-proxy` (and the verbatim copies in `openai-proxy`): the
  reserve-block grammar; eligibility (line and block edges, Markdown-escaped
  tokens, a token in the middle of a sentence, thinking and tool_use
  untouched); the expander over deltas split at every offset; the property
  `collapse(expand(t)) === t` over generated text; the residual strip over
  every block type; the sniffer recording the model's real text.
- `reply-filter`: splice of head and continuation rows in synthetic
  Ink-shaped frames (CHA per word, relative row moves, CHA+EL); padding and
  clipping per row, and a TAB inside a line; the value cache; blank rows
  without the arbiter; the reconciler's marker rows on both screens,
  including the headless and ghost-tail cases (`screen-reconcile.test.ts`);
  `setSessionRelay` reported once per mode and on resize.

**End-to-end: the invariant oracle**
- **Proxy e2e (fake upstream, real arbiter).** The client-bound stream holds
  the block and no original; the next request's upstream-bound body holds `T`
  byte-exact and no marker and no `/1:N`. A mangled block is stripped and a
  `reserve_residual` event is emitted. With the arbiter down, or the relay
  unset or in pipe mode, there is no expansion.
- **Reply-filter e2e (`run.test.ts`).** A fake inline TUI and a fake
  fullscreen TUI under real `script(1)` paint a block; on the rendered
  headless-xterm screen, row *i* reads line *i*.
- **Integration e2e (`tests/stack/reply-row-reservation.test.ts`).** A real
  arbiter, proxy and reply-filter CLI under `script(1)`, a fake agent, and a
  registered multi-line `no-model` file. The human's screen shows every line;
  nothing bound for the model holds an original or a marker; turn 2 reaches
  the upstream byte-exact; the agent's world holds no original. The kill
  switch, pipe mode and a stopped arbiter all leave the plain token. A fake
  TUI that paints only a block's tail on the alternate screen covers §3.8.
- **Parity.** `tests/stack/reserve-block-parity.test.ts` (the proxy's emitter
  against the filter's recognizer, with a 20k-line seeded corpus);
  `proxy-real-client-parity.test.ts` and the filter's
  `human-plane-parity.test.ts` (`new XAdapter(new ArbiterClient(sock))` over a
  real `ArbiterServer` for every new op, the arbiter-client pattern).

**Live (the differential harness, `docs/testing/differential-interactive.md`)**
- `echo-fidelity-rows` (a five-line, Markdown-inert file with one blank line)
  gates full screen parity with vanilla on the inline and fullscreen
  renderers, at 80×24 and 160×40, and on the real-config lane.
- **F4** (`differential-oracles.ts`, `reserveResidue` in `screen.ts`) renders
  each side's full scroll history and fails on any reserve marker or
  fragment, on any value row that equals no file line, and on a value line
  vanilla shows that the wrapped side lacks. `echo-fidelity-long` (a 33-row
  block, taller than the viewport) exercises it (§7.2).
- `echo-fidelity` keeps a divergence marker for one reason: its first line is
  a Markdown heading, which vanilla renders as a heading while the reserved
  rows show the file's raw line (§11.8).

## 7. Build record

The feature was built as a phased plan, each phase behind the previous:

- **Phase 0, the probe** (§7.1): settle that Claude Code renders a reserve
  block as N intact rows before writing product code, and record who can
  reach the arbiter's data socket from inside the agent's world.
- **Prerequisite:** the ops that return originals moved to the human plane
  (§5.3, [`arbiter-human-plane.md`](../architecture/arbiter-human-plane.md)).
- **Phase 1, the arbiter.** `symbolShape`, `setSessionRelay`, `sessionRelay`:
  types in `arbiter/ipc/protocol.ts` (`SymbolShapeResult`, `SessionRelayMode`,
  `SessionRelayWire`), dispatch in `ipc/server.ts`, client methods in
  `ipc/client.ts`, and the pure pieces (the line count, the relay validation,
  a store capped at 4096 sessions evicting the least recently reported) in
  `ipc/reply-reservation.ts`. `symbolShape` answers only for a string that is
  exactly one token (after unescaping); it deep-resolves the token's entry
  without the trailing-dot re-attachment `desymbolize` applies to prose.
  `setSessionRelay` is not bind-once: the filter re-reports on resize, and a
  wrong entry only costs a reservation. `deleteSession` clears the entry.
- **Phase 2, collapse and strip ship before expansion**, so a rolled-back
  proxy never meets blocks it cannot collapse:
  `interceptors/anthropic-proxy/src/reserve-block.ts` (`expandText`,
  `collapseText`, `stripResiduals`, `standaloneTokens`) and
  `reserve-request.ts` (the request pass, before `rewriteRequest` and for
  count_tokens too). Collapse touches only assistant `text` blocks; the strip
  also covers the system prompt, and never `thinking`, `redacted_thinking` or
  `tool_use`. The routed OpenAI path is left alone; no block ever comes from
  it.
- **Phase 3, the reply filter.** `interceptors/reply-filter/src/reserve-block.ts`
  (the recognizer; its token source is asserted equal to `SYMBOL_TOKEN_RE`),
  the splice in `filter.ts`, the main-screen reserve rows in
  `screen-reconcile.ts`. The filter takes N from the head row, never from its
  own environment, so a proxy and a filter with different caps still agree.
  One session value cache is shared by both writers (head token → value, and
  hash → the last head seen); the `desymbolize` event fires once per head. On
  the main screen the reconciler tracks its rows with xterm markers so they
  follow scrolling, and moves the cursor relative to the TUI's cursor, since a
  session does not start at the terminal's top-left. In pipe mode a block
  collapses to the full value.
- **Phase 4, expansion on**, behind eligibility and the kill switch:
  `interceptors/anthropic-proxy/src/sse-reserve-expand.ts`, chained after the
  text-delta repacker, with the SSE sniffer tapping before it. Events:
  `reserve_expand` and `reserve_residual`.
- **Phase 5, live:** the differential gates of §6.

### 7.1 Phase 0 results

**Method.** A scratch driver over the differential harness (the drill runners'
shared library: the scripted fake Anthropic, the outer sized PTY, the `ScreenTap` screen
model) drove Claude Code 2.1.285 with no Mandu in the path. Seven turns each
replied with a hand-written reserve block, streamed as the proxy would send
it, on the inline and fullscreen renderers at 80×24 and 160×40.

| Case | Reply shape | Result, all four configurations |
|---|---|---|
| P1 | a paragraph, a blank line, a 5-row block, a blank line | N rows, markers intact, column 2 |
| P2 | a list, then the block with no blank line | N rows, intact, column 4 (Markdown folds the block into the last list item) |
| P3 | a `##` heading, then the block | N rows, intact |
| P4 | prose lines directly above and below | N rows, intact; the neighbors stay on their own rows |
| P5 | the block inside a ```` ``` ```` fence | N rows, intact; the fence rows vanish; markers in the code color |
| P6 | a Markdown-escaped head (`\$MDU:…\_…`) | N rows; the head renders unescaped |
| P7 | a 30-row block | 30 rows; at 24 rows the top scrolls away and the visible rows stay consecutive |

All 28 settled screens had exactly the expected rows, so the bare-row form
(§9, D3) stands.

**The paint bytes.** The first paint of a marker row is contiguous on the
wire (`\r ESC[1B  $MDU/464e/2`). But in every configuration a later frame
re-laid the reply out and repainted marker rows by cell diff, writing only
the cells that differ (`\r ESC[8C ESC[1B /464e/2`, then `\r ESC[14C ESC[1B
3`). Hence §3.7: the stream splice alone cannot paint the rows, and the
screen reconciler takes reserve rows on the main screen too.

**The data socket** (§5.3). In `secrets` mode with the default layers, a
process started by the agent read a fake credentials twin and sent
`desymbolize` over `$MANDU_ARBITER_SOCK`, which returned the fake original;
shallow `resolve` did the same. The net-guard Unix allow-list names the
socket, Landlock limits TCP only, and the secret-twins wrap keeps the path
and the variable; the classify backstop re-masked a verbatim original but
passed an encoded, reversed, spaced or split one. The fix (the human plane)
came first.

### 7.2 The scrollback measurement

§3.7 left one residual to measure: a cell-diff fragment on a reserved row
that scrolls into the scrollback before the reconciler repaints it. The F4
oracle and the `echo-fidelity-long` scenario (§6; each of its lines carries
two anchors, `DIFFLONG_<nn>` and `DL<nn>END`, so a fragment's index digits
cannot erase both) measure it.

**Results** (CI guest, Claude Code 2.1.285):
- **Inline renderer, and the real-config lane:** 0 residue rows; all 32
  value lines in the wrapped scroll history; full screen parity with vanilla
  at both sizes. The residual did not occur.
- **Fullscreen renderer:** two bugs, neither of them the residual, both
  fixed: blank rows where the head was never painted (the block registry,
  §3.8), and a ghost tail where a value row the stream had painted was later
  cell-diffed to shorter text (every value row is owned, §3.7).
- **With both fixes:** every lane of the reserve scenarios passes.

## 8. Out of scope, and follow-ups

- **OpenClaw and OpenCode.** They ride the Claude proxy's rewrite (§17.7).
  OpenCode gets v1 heads only (`MANDU_REPLY_WRAP_RULE=none`): its wrap is
  not modelled (differential-interactive.md §35).
- **A token that shares its code span with other text**, and any code span
  on Codex, keep the one-row form (§12.4).
- **The Codex span form and live parity** beyond the §14 gates are
  unmeasured.
- **Fallbacks considered and not needed:** the first line plus a pointer,
  `mandu reveal`, and printing the flattened values after exit (§2.1).

## 9. Decisions

- **D1: an exact N or a bucketed N. Exact.** Buckets (2, 4, 8, 16, 24, 40,
  spare rows painted blank) were weighed:
  - *For buckets:* the §5.2 residual drops from about 5.3 bits to about 2.6
    (log2 6) per displayed secret, and they would blur the line-width
    information in `rows` (§11.6).
  - *Against:* up to 15 blank rows under a value (25 lines reserve 40); a
    mid-line block's suffix (§11.4) lands below the blank rows, detached from
    its sentence; every reserve gate loses parity with vanilla; a model that
    steers its prefix can still find a bucket's edge (§11.6), so buckets
    shrink the residual rather than close it; and the gain is only on the
    path already accepted as contrived — collapse and the strip keep N from
    the model on every direct path.
- **D2: `RESERVE_MAX_ROWS` = 40.** It fits most config files and keeps the
  residual under 6 bits.
- **D3: the continuation-row form:** the bare `$MDU/<hash>/<i>` rows, settled
  by the probe (§7.1).
- **D4: no handling-prompt change** asking the model to put a multi-line
  token on its own line. Models already tend to, v2 expands a token inside a
  sentence (§11.4), and a measurement of real replies (§12.1) found
  backticked tokens only for one-line values, which the span form (§12)
  covers.

## 11. v2: wrapped lines and tokens in a sentence

v1 reserves one row per value line, and only for a token alone on its line.
That leaves two gaps, which v2 closes:
- A line wider than the terminal is clipped at the edge. A long single-line
  value, such as an API key or a JWT, gets no reservation at all.
- A token inside a sentence ("the key is `$MDU:…` and …") keeps the one-row,
  `⏎`-joined form.

### 11.1 Probe (vanilla Claude Code 2.1.285)

The phase-0 driver (§7.1) replied with nine shapes, on both renderers, at
80×24 and 160×40. The results were identical in all four configurations.

| Case | Reply | Screen |
|---|---|---|
| wrap prose | 30 words of 7 characters, one paragraph line | Word wrap at `cols − 2`: at 80 columns, 9 words (71 columns) per row. Wrapped rows start at the indent, not with a space. |
| unbroken | 120 × `Z` | Hard break at `cols − 2`: 78 + 42. |
| list item | `- ` + the 30 words | Wrap at `cols − 4`; wrapped rows at column 4. |
| leading spaces | `    HostName …` as a paragraph's second line | The four spaces kept on the first row; wrapped rows at column 2. |
| wide | 50 Hangul syllables, then ` 끝` | Hard break at 78 columns (39 syllables), each syllable 2 columns. |
| mid-line | `The value is T/1:3` + rows + ` and that is all.` | The prefix stays on the head's row; the suffix stays on the last row. |
| mid-line, list | `- key: T/1:3` + rows | Continuation rows at column 4. |
| mid-line, bold | `**T/1:3` + rows + `** done.` | Three rows, markers intact. |
| code span | `` `T/1:3 `` + rows + `` ` `` | **One row**: the code span joins the rows with spaces. |

This matches Ink's `wrap-ansi` call (`hard: true, trim: false`):
- greedy word wrap on single spaces;
- a word longer than a row is broken by display columns;
- the space at a break stays, invisible, at the end of the upper row.

### 11.2 The layout rule, one function in three packages

`layoutRows(value, W, F)` turns a value into the rows it occupies:

1. The lines are `valueLines(value)`: one trailing newline dropped, split on
   `\r\n`, `\r` or `\n`.
2. Each line is cleaned as `frameSafeValue` cleans it:
   - CSI sequences and C0 bytes other than TAB are removed;
   - a TAB becomes the spaces to the TUI's next tab stop: the next
     multiple of 8 of the column counted from the TUI's TAB origin, the
     line starting at the content area's column (`indent`), or on line 1's
     head row `W − F` columns further in (§19). `indent` is `cols − W` for a
     TUI whose stops are the screen's (Codex) and 0 for one that counts
     from its text (Claude Code, §19.7).
3. Each line is wrapped by the `wrap-ansi` algorithm above. Row widths are
   display columns: wide glyphs (the filter's `WIDE_RE`) are 2, and
   combining and zero-width marks are 0.
   - Line 1's first row is `F` columns wide; every other row is `W`.
   - `F = 0` means line 1 starts on the row after the head, and the head
     row shows no value text.
   - An empty line is one empty row.

Each row records which line it came from. When `rows > N`, row N shows `… +K
more lines`, where K is the number of lines not shown in full on rows 1..N−1.

The arbiter counts these rows, the proxies use the same wrap on the model's
prefix (§11.4), and the filter paints them. The module is copied verbatim:
- `interceptors/reply-filter/src/reserve-layout.ts` (the canonical copy);
- `arbiter/ipc/reserve-layout.ts`;
- `interceptors/anthropic-proxy/src/reserve-layout.ts`;
- `interceptors/openai-proxy/src/reserve-layout.ts` (§11.7).

`tests/stack/reserve-layout-parity.test.ts` fails unless the copies are
byte-identical, and pins the probe's screens. This is the text-repack
precedent (architecture-map.md §9 ①).

This is the `ink` rule. Since §17 the function takes the TUI's wrap rule as
a fourth argument: `terminal` cuts each line by the terminal's own autowrap
at the full width, for a TUI that prints its reply raw (Goose).

### 11.3 The grammar, v2

```
head v1   T/1:N            one row per value line (fences; relays without wrap)
head v2   T/1:N:W:F        layoutRows(value, W, F), W = the content width
row i     $MDU/<hash>/<i>  unchanged
```

- `W` is an integer from 20 to 1000.
- `F` is 0 or an integer from ⌈W/2⌉ to W. The arbiter refuses anything else
  (§11.5).
- A v2 block may sit inside a line:
  - the head may be preceded on its line by prefix text;
  - the last row may be followed on its line by suffix text, which starts
    with a character that is not a digit.
- **Collapse:** `T` + suffix + `\n$MDU/<hash>/2` … `\n$MDU/<hash>/N`, not
  followed by a digit, becomes `T` wherever it stands. Expansion inserts
  exactly those bytes after `T`, so `collapse(expand(t)) === t` still holds.
  Collapse finds a head anywhere that is directly followed by a row.
- **The residual strip** takes `/1:N`, and `:W:F` when present, after a
  token, as well as every continuation marker together with the line break
  before it (`pre T\n$MDU/h/2 tail` → `pre T tail`).
- **Mixed versions:**
  - A v1 proxy strips a v2 head suffix only up to `/1:N`, so `:W:F` (two
    numbers) reaches the model. Only a downgrade in the middle of a session
    can cause this.
  - A v1 filter paints a v2 head as the value's first line, plus a visible
    `:W:F`. A v2 proxy never sends v2 heads to a v1 filter: the filter must
    report `wrap: true` (§11.5).
- The filter parses v2 before v1: a `/1:N:` followed by a digit is v2 or
  nothing, never a fallback to v1.

### 11.4 Eligibility, v2 (the proxy)

Expansion needs everything in §3.2, and the relay reporting `wrap: true`
with its `cols`. Then:

- **The indent.** It is 2, plus the list indent when the line is a list item
  (`- `, `* `, `+ `, `1. `) or directly continues one with no blank line
  between (phase 0's P2). The list indent is the item's leading spaces plus
  its marker width.
- **The width.** `W = cols − indent`. When `W < 20`, or the head word would
  not fit in `W` columns, the proxy falls back to a v1 head if the token is
  alone on its line, and does no expansion otherwise.
- **Inside a fenced code block** (tracked per content block, from lines
  opening with ```` ``` ```` or `~~~`), only a token alone on its line
  expands, and with a v1 head. Code blocks were not probed for wrapping.
- **A token alone on its line:** `F = W`.
- **A token inside a line** expands only when all of the following hold:
  - the character before it is the line start, a space, a TAB, `*`, `_`,
    `"` or `'`;
  - the character after it is the line end, whitespace, or one of
    `. , ; : ! ? ) * _ " '`;
  - the line is not a heading (`#` after up to three spaces), a blockquote
    (`>`) or a table row (it contains `|`; since §14, before or after the
    token);
  - the token is not inside a code span (an odd number of backticks before
    it on the line) or link text (an unclosed `[` before it on the line).
    A token that is a whole code span takes the span form (§12).

  Then `p` = the width of the last row of `wrapLine(prefix, W, W)`, where
  the prefix is the raw text of the line before `T`:
  - If `p` + the head word's width > `W`, Ink moves the head to its own row,
    so `F = W`.
  - Otherwise `F = W − p`.
  - If `F < ⌈W/2⌉`, then `F = 0`.

  **As built, `F` is only ever too small, never too large** (`reserve-context.ts`
  `decideReserve`, which answers none, v1 or v2 with `W` and `F`). `F = 0` is
  right wherever the head lands, so the proxy falls back to it whenever it
  cannot prove the head's position:
  - The head word's width is bounded, not known, before `symbolShape`
    answers: at most T plus `/1:<cap>:W:W`, at least canonical T plus `/1:2:W:0`.
  - **A plain prefix** (no Markdown characters, no leading space, no other
    token) is measured exactly:
    - The head stays on the prefix's row when even the widest head fits.
    - It gets its own row (`F = W` minus the glue before T) when even the
      narrowest head does not fit.
    - Between the two, `F = 0`.
  - **Any other prefix:** `F = W − p` minus the glue, only if the raw prefix
    plus the widest head fits on one row. Otherwise `F = 0`.
  - **Glue**, the non-space text right before T (`**`, `"`), is part of
    Ink's word and counts at its raw width.
  - A list item's marker is not part of the prefix, because it sits outside
    `W`.
  - A prefix holding another token gives `F = 0`, and a line gets at most one
    block.
- **N** is `min(rows, cap)` with `rows = symbolShape{token, width: W,
  first: F}.rows`. The proxy expands when `N ≥ 2`. A one-line value that
  wraps expands too. A value that fits in one row keeps the one-row splice
  (but see §14.4 for the text after it).
- The mode is fixed per stream when the first possible token appears. A
  relay without `wrap` gives v1 streams byte-identical to v1.
  `reserve_expand` records the head's version, `W` and `F`.

### 11.5 Arbiter and relay changes

- **`symbolShape { token, width?, first? } → { lines, rows?, last? }`.** With
  `width`, it also returns `rows = layoutRows(value, width, first ?? width)
  .length` (and `last`, §14.4). It refuses a `width` outside 20..1000, or a
  `first` that is not 0 and not in ⌈W/2⌉..W. It validates the layout before
  the lookup, so a known and an unknown token are refused alike, and a JSON
  `null` for `width` or `first` counts as present and is refused
  (`parseShapeLayout`, `shapeRows` in `ipc/reply-reservation.ts`).
- **`setSessionRelay` gains `wrap: boolean`.** The filter reports `true`,
  meaning it paints v2 heads.
- **Since §17:** `symbolShape` also takes `rule` (`ink`, the default, or
  `terminal`), and `setSessionRelay` / `sessionRelay` carry the TUI's
  `rule`.
- **Since §19:** `symbolShape` also takes `indent`, the screen column the
  content area starts at (`cols − W`), an integer 0..10000 that requires
  `width`; it moves only the TAB stops. Since §19.7 `setSessionRelay` /
  `sessionRelay` carry the TUI's TAB origin (`tabs`), and under `content`
  the proxy sends `indent` 0.
- **`setSessionRelay`, `sessionRelay` and `symbolShape` are human-plane ops**
  (`HUMAN_PLANE_OPS`, arbiter-human-plane.md); the data socket's refusal
  names the reason for each. v1 left the relay ops on the data socket because
  a forged report cost only a reservation. With v2, `cols` sets `W`, and an
  agent that could set `W` could replay one secret at widths of its choosing
  and learn its line lengths from the row counts. The filter reports over the
  human socket (and skips the report without one); the proxy reads
  `sessionRelay` over its human client.

### 11.6 Security, v2

- **Still no original moves.** The proxy learns `rows`, which is one
  integer capped at 40 per displayed token, as N was (§5.2). Collapse and the
  strip keep it away from the model as before.
- **What `rows` adds over `lines`:** a function of the lines' widths at `W`.
  - `W` is the human's terminal width. The agent can no longer set it
    (§11.5).
  - The model does steer `F`, through the length of its prefix, but only
    within ⌈W/2⌉..W or 0.
  - Across repeated displays, a model steering its prefix could narrow the
    length of a value's first line when that line is longer than about W/2.
    That takes one reply per probe, a transcript read and an encoding step
    past the strip (§5.2). It is recorded as an accepted residual. A
    credential shorter than W/2, which covers passwords and most API keys at
    80 columns, never wraps and yields nothing.

### 11.7 Codex

**Probe (vanilla codex-cli 0.159.1).** The phase-0 cases, plus a mid-line
block and a wrap case, against the harness's fake Responses server, on both
Codex renderers (the default alternate screen and `--no-alt-screen`), at
80×24 and 160×40, with a resize on the last turn:

- **Every block settles as N intact rows, each marker whole on its own
  row** — a paragraph, a list (folded in at column 4), a heading (Codex
  prints `##` literally), prose above and below, a fence (its rows vanish),
  an escaped head (rendered unescaped) and 30 rows; about 2,500 marker rows
  were checked across every captured frame, and none was partial.
- **Mid-line:** the prefix stays on the head's row and the suffix on the
  last row, as with Claude Code.
- **Wrap:** Codex wraps lines itself with a 2-column indent, by the same
  greedy rule as §11.2, so the layout function is shared.
- **Paint bytes:** *inline*, every marker row is painted whole through a
  scroll region, and a resize reprints the transcript reflowed with the rows
  whole; on the *alternate screen* the first paint is already a cell diff and
  is re-diffed on every scroll (hundreds of fragments per run), which the
  screen reconciler paints (§3.7).

**As built.**
- **The copies.** `interceptors/openai-proxy` carries `reserve-block.ts`,
  `reserve-context.ts` and their unit suites as verbatim copies of the Claude
  proxy's, plus `reserve-layout.ts`. `reserve-layout-parity.test.ts` holds all
  of them byte-identical and runs one text corpus through both proxies'
  expand, collapse and strip.
- **`ResponsesReserveExpander`** (`sse-reserve-expand.ts`) follows the
  Responses repacker's rule: it moves text only between existing delta
  events, and never emits a new event. A delta whose token's following
  character is unknown is held whole; the next delta of the same part decides
  it, the part's `.done` counts as the end of the text, and anything else
  releases it unexpanded.
- **The snapshot events.** `.output_text.done`, `.content_part.done`,
  `.output_item.done` and every `response.output[]` of `response.completed`
  get the expanded text, but only when the snapshot's text equals the model's
  text the deltas carried. `sequence_number` is never touched, and a part
  with `logprobs` is never changed.
- **The request side** (`reserve-request.ts`, before `rewriteRequest`):
  collapse runs in every message's `output_text` part; the strip runs in
  `instructions`, a string `input`, every `input_text` and every `*_output`
  item; reasoning items, `function_call` arguments and `custom_tool_call`
  input are never touched.
- **Not covered:** the Chat Completions route and `stream: false` get no
  expansion and no request pass; no block is ever sent there.
- **Launcher:** `context-proxy.ts` hands `MANDU_ARBITER_HUMAN_SOCK` to both
  context proxies.
- **Live:** the Codex differential lane runs `echo-fidelity-rows`, `-wrap`,
  `-inline` and `-suffix` (§14.6). The lane's profile pins
  `notice.model_migrations` so a model-migration dialog never swallows its
  first keystrokes (differential-interactive.md §16).

### 11.8 The Markdown divergence: raw rows stay (decision)

Vanilla shows a model's echo of a file as Markdown: an ssh config's
`# comment` line becomes a heading, and `*` wildcards can become bullets.
Reserved rows show the file's raw lines. This is kept on purpose:
- The value is data, not the model's prose. The raw line is what is on
  disk, which is what the human asked to see.
- Rendering it as Markdown would need a copy of Claude Code's renderer
  inside the filter, and it would still differ between Claude Code
  versions.

`echo-fidelity` keeps its divergence marker for the heading row only.

### 11.10 As built: the filter, limits and tests

- **Filter:**
  - Row text comes from `layoutRows`, memoized for the last eight blocks.
  - A v2 row wider than its marker keeps its wrap-off bracket open while the
    TUI keeps printing on that row, so text after it clips at the edge
    instead of wrapping onto a row the TUI never counted (within one write).
    A token or a v1 row keeps it open only over the blanks the TUI pads the
    row with, when they would run past the edge (differential-interactive.md
    §32).
  - Under Ink's rule, with the terminal width known, what a widened row
    pushes past the right edge is not sent at all (`filter.ts` CLIP PAST THE
    EDGE, differential-interactive.md §36): the value is cut to the columns
    its row has left, and the TUI's later text on the row, an erase from
    past the edge, and a relative move from there are clipped or made
    absolute. Before 2026-10-17 a token's bracket closed after the value and
    the text the column translation moved past the edge wrapped onto a row
    the TUI never counted (a 107-column Stripe key in a Claude Code reply).
  - Values are measured in display columns. A wide value is bracketed rather
    than padded past the edge; this also applies to ordinary tokens with CJK
    values.
  - In pipe mode, each row is dropped together with the line break before
    it. A line that ends in a marker holds its line break across writes
    until the next line arrives.
- **Limitations:** with the arbiter down, a v2 head reads `T (N lines)` with
  N counting rows. (The suffix clip and the table's first cell, limits of the
  first v2, are closed by §14.)
- **Tests:** unit — `reserve-layout.test.ts` (the probe's screens as
  fixtures, wide glyphs, TAB, `F = 0`, an empty line, a word longer than `W`,
  no row wider than its cap over a seeded corpus), `symbolShape` with `width`
  and `first` and its refusals, the relay ops refused on the data socket, v2
  eligibility for every rule in §11.4, the expander with a mid-line token
  split at every delta offset, `collapse(expand(t))` with mid-line tokens,
  the v2 strip, v2 head parsing, and a chunk-size sweep for the pipe hold;
  integration — `reserve-layout-parity.test.ts`, `reserve-block-parity.test.ts`
  (v2 heads and the pipe rendering of a mid-line block),
  `proxy-real-client-parity.test.ts` (`rows`, the relay refused on data),
  `reply-row-reservation.test.ts` (a wrapped key and a mid-line value on an
  80×24 outer terminal); live — `echo-fidelity-wrap` (a line wider than 80
  columns of words) and `echo-fidelity-inline` (a one-line value in a
  sentence) reach full parity with vanilla on both renderers, at both sizes,
  and on the real-config lane. At 80 columns either gate fails under v1,
  which clips.

## 12. The span form: a token that is a whole code span

> **Status: BUILT for Claude Code; off for Codex.**

### 12.1 The measurement

How often does a model wrap a token in backticks? A count over the
assistant text of Mandu-wrapped Claude Code transcripts from manual and
watch sessions (and Codex session logs, none of which held a token) found
15 replies holding 16 tokens:

| Placement | Tokens | Values |
|---|---|---|
| alone on its line | 5 | files, command output |
| inside a sentence | 7 | files, command output, two keys |
| a whole code span, `` `T` `` | 4 | one-line values: keys (`…API_KEY`), a count, a `base64 -w0` line |
| in a table, in a fence | 0 | |

v1 and v2 already reserve rows for the first two placements. The sample is
small, but its shape is clear: models put a multi-line value on its own
line or at the end of a sentence, and use a code span for a one-line value.
A one-line value in a span still matters: an Anthropic key is 108
characters and a JWT hundreds, so at 80 columns the span clips. That is the
case this section builds for. (An earlier count over the arbiter's event logs
included the model's tool inputs, so it was not a count of replies and is
not used.)

### 12.2 Probe (vanilla Claude Code 2.1.285)

The phase-0 method (§7.1), both renderers, 80×24 and 160×40.

| Reply | Screen, every configuration |
|---|---|
| `` is `T/1:3:78:40` `` + `` \n`$MDU/h/2` `` + `` \n`$MDU/h/3`, and more `` | three rows, markers intact, backticks not drawn, the suffix after the last row |
| the same in a list item, rows indented or not | three rows at column 4 |
| `` `T/1:3 `` + rows + `` ` `` (one span, §11.1) | one row: the span joins its lines with spaces |
| `` The key is `sk-ant-…` `` (108 characters, no Mandu) | the key wraps across two rows, from the column after the prefix |

A code span cannot hold a line break, but a line break between two spans is
a soft break, and Claude Code draws soft breaks as rows (§3.1). So each row
gets its own span.

### 12.3 The grammar

The span form is a v2 block whose row separator is `` `\n` `` instead of
`\n`:

```
model   The value is `T`, and that is all.
wire    The value is `T/1:N:W:F`
        `$MDU/<hash>/2`
        …
        `$MDU/<hash>/N`, and that is all.
```

- The proxy inserts only the head suffix and `` `\n`$MDU/<hash>/i `` for i =
  2..N after T. The model's own backticks stay where the model put them;
  the last row is closed by the model's closing backtick.
- **Collapse:** a head followed by `` `\n`$MDU/ `` takes the span separator
  for the whole block. A block that mixes the two separators is not well
  formed and is left to the strip. `collapse(expand(t)) === t` still holds;
  the v2 property test expands 30% of its v2 tokens in the span form.
- **The strip** removes a span marker together with its separator, before
  the plain markers: `` `T/1:4:78:43`\n`$MDU/h/2`\n`$MDU/h/3` `` strips to
  `` `T` ``.
- **The reply filter is unchanged.** It finds heads and rows by position, and
  Claude Code draws neither backtick. `reserve-block-parity.test.ts` pins
  that the filter reads a span-form block as the same N, W and F.

### 12.4 Eligibility

`decideReserve` takes the span form only when the caller passes `codeSpan`
and the token is the span's whole content:
- an odd number of backticks before T on its line (the §11.4 test);
- the character before T is that single opening backtick, not part of a
  run and not escaped (`` \` ``);
- the character after T is a backtick.

Every other §11.4 rule still applies (heading, blockquote, table, link text,
one block per line). A token that shares its span with other text (`` `echo
T` ``, `` `KEY=T` ``) is not expanded. The character after the closing
backtick is not yet known when the proxy decides. A closing run of two
backticks therefore still expands; it costs only the rendering, never the
collapse.

**F.** The opening backtick is not glue: the span closes on the next
character, so neither backtick is drawn. A plain prefix is then measured
exactly, and `F` equals vanilla's free width (`echo-fidelity-codespan`
depends on it). Other backticked spans earlier on the line keep the upper
bound (§11.4), which only makes `F` too small.

**Codex** keeps `codeSpan` off: its renderer was not probed for spans.

### 12.5 Security

Nothing new moves. The span form carries the same `N`, `W` and `F` as a
mid-line v2 block, the same `symbolShape` call answers it, and the §3.8
registry records it the same way. The model receives its own text back
byte for byte: collapse restores the backticks, and a span-form fragment
that is not well formed strips to the span.

### 12.6 Tests

- **Unit, proxy (both copies):** the grammar (the block, the collapse, a
  mixed-separator block, the strip of mangled blocks); the v2 property with
  span-form expansions; eligibility (accepts, rejects, `F` exact and
  bounded, off without `codeSpan`); the expander at every split offset;
  Codex off by default.
- **Integration:** `reserve-block-parity.test.ts` (the filter reads
  span-form heads and rows); `reply-row-reservation.test.ts` (a value in a
  code span on an 80×24 outer terminal; the fake agent drops backticks as a
  Markdown renderer does, `RR_RENDER=md-spans`, and the model gets back its
  sentence, backticks and all).
- **Live:** `echo-fidelity-codespan`, a one-line value echoed as a whole
  code span inside a sentence, gates full parity with vanilla on both
  renderers, at both sizes, and on the real-config lane. As a control, with
  `codeSpan` off the 80×24 lanes fail (the value clips in its one row), so
  the gate tests the span form.

## 13. A resize after the reply

> **Status: BUILT.**

### 13.1 What happens

A block's `W` is fixed when the proxy expands it. On SIGWINCH, Claude Code
reprints its transcript at the new width, on both renderers. Each reserved
row stays one row, because a marker is one short word, and the filter
repaints every row it is handed — from the old layout, unless told
otherwise. A probe with `echo-fidelity-wrap`'s file:
- **80×24 → 60.** Row 1 was the old 78-column row clipped at column 60, and
  row 2 the old second row. Vanilla re-wraps the long line at 58 into the
  same two rows.
- **160×40 → 60.** The block had 3 rows, laid out at 158, where the long
  line fits. Vanilla now needs 4.
- **60 → 120.** Vanilla joins the wrapped line into one row. The block
  keeps 2.

### 13.2 The rule: re-lay out when narrower, keep the layout otherwise

The reply filter records, per block, the terminal's columns when it first
sees the head (`ReserveValueCache.noteHead`). A repaint of the same head
after a resize keeps that width. At paint time, `paintLayout` (in the
filter's `reserve-block.ts`) compares it with the width now:
- **The same width, or wider:** the block's own `(W, F)`. Its rows still
  fit, and N rows cannot shrink to vanilla's fewer rows. The human sees the
  value wrapped at the old width.
- **Narrower by `d`:** `(W − d, F − d)`. `F = 0` stays 0, and a head row left
  with less than half of `W − d` goes blank (the proxy's clamp). A value
  that still fits in N rows paints as vanilla lays it out. One that needs
  more rows shows the cap note on row N (`… +K more lines`, the §3.7 cap
  form), so the tail is named instead of clipped away row by row.
- **Below the grammar's minimum width (`W − d < 20`):** the old layout, which
  clips.

Both painters use it: the stream splice with `opts.cols` (read live, so it
follows `process.stdout.columns`) and the screen reconciler with its own
size, which `resize` sets.

**`F − d` assumes the text before the head keeps its last row.** A prefix
that wraps anew can push the head right. The head row then clips at the
edge, and the other rows are unaffected. A block first seen after a resize,
a headless block (§3.8) among them, takes the width of that first sighting.

**Security.** Nothing new moves. The re-layout is the filter's own
arithmetic over a value it already holds, and nothing reaches the agent or
the model: the proxy is not asked again, and the TUI's text is unchanged.

### 13.3 Tests

- **Unit, filter:** `paintLayout` (same, wider, narrower, `F = 0`, the clamp,
  below the minimum, an unknown first width); row text after narrowing,
  including the cap note; the cache keeps the width of a block's first
  sighting; the stream splice repaints a reprinted block at 60 columns and
  keeps its layout at 120; the reconciler lays a headless block out anew
  after `resize`.
- **Harness:** `DiffTurn.resizeBy`, a resize relative to each run size
  (`resizeTarget`), so a single scenario narrows 80→60 and 160→140.
- **Live:** `echo-fidelity-resize` (`echo-fidelity-wrap`'s file, then a
  20-column narrowing) gates full parity at both checkpoints, on both
  renderers, at both sizes and on real-config. Widening, and a narrowing past
  what N rows can hold, cannot reach parity, and no gate asks for it.

## 14. Text after a mid-line value, and a table's first cell

> **Status: BUILT, Claude Code and Codex.**

### 14.1 The two gaps

- **The text after a value clipped.** A v2 mid-line block reserves the rows
  the value takes. The model's text after it (the *suffix*, up to the line
  end) follows the last row on its line. When the value's last row plus the
  suffix is wider than `W`, the filter keeps the row from wrapping (§11.10),
  and the end of the sentence is cut at the edge, where vanilla wraps the
  suffix onto the next rows. Example: "The key is `<108 characters>` — it's
  a protected secret, so I passed it through." at 80 columns.
- **A token in a table's first cell expanded.** "`T | desc |`" has no `|`
  before T, so §11.4's table test missed it, and the inserted rows broke the
  table apart.

Both need the rest of the line, which the proxy did not know: it decided a
token once the character after it arrived.

### 14.2 The hold: a line holding a token waits for its end

In v2 mode the expander holds text from the first token on the unfinished
last line (or a token still arriving, whichever comes first) until that line
ends: a `\n`, or the text block's end. Text before the token goes out at
once. So each token is decided with its whole line in hand. The delay is one
line of streamed text. A v1 relay keeps the old hold and stays
byte-identical. The Codex expander holds the same way; since it never emits a
new event, it carries the held text forward into the next delta.

### 14.3 The table check

`decideReserve` gets `rest`, the model's text after the token to its line
end. A `|` there makes the line a table row, and the token is not expanded,
as a `|` before it already did.

### 14.4 The break

The exact break was chosen over leaving the clip (simpler, but the sentence
is cut) and over reserving spare rows for the suffix (blank rows on screen,
and no parity with vanilla).

- **`symbolShape` returns `last`**, the display width of the value's last row
  under the requested layout. It is a width, never text, served on the human
  plane like the rest of the op (`shapeRowsLast`).
- **The proxy computes the break** with `suffixBreak` (`reserve-context.ts`),
  given `last`, `W`, and the width of the last row's marker `$MDU/<h>/<N>`:
  - It walks the suffix the way wrap-ansi does: first the glue (the
    non-space text touching the value), then single-space-separated words.
    The row ends after the last word that fits after `max(last, marker)`. On
    the screen the text follows the value; in the TUI it follows the marker,
    so it must fit after both.
  - If a word does not fit, one `\n` goes after the space before it, and
    the rest of the sentence starts a row of its own. The TUI then wraps it
    exactly as vanilla wraps what follows. At the break, CommonMark drops
    the single trailing space, which is invisible either way.
  - **No break** when the suffix fits; when it holds another token, a TAB
    or a double space; when the glue alone does not fit (vanilla would move
    the value's own last word); when a word is wider than `W`; when the
    break would fall inside a code span or link text; or when the rest
    would start a Markdown block (a list marker, `#`, `>`, a fence, `|`,
    `<`, a setext line). In all of these the clip stays.
  - Widths are raw, and Markdown only removes characters, so a break is
    never later than vanilla's: the text never clips, though with Markdown
    in the suffix it may break a word early.
  - A capped block (the last row is the cap note) gets no break.
  - **A value that fits its row** (`rows` 1) reserves nothing, but it can
    still push the text after it past the edge: the one-row splice is
    longer than the token the TUI laid out, so the terminal auto-wraps a row
    the TUI never counted and the screen garbles. Such a value gets a
    head-only block, `T/1:1:W:F:K`: no rows, only the break. Its value
    starts `W − F` columns into the row, so the walk starts from
    `(W − F) + last`, and in the TUI from `(W − F) +` the head's width.
    When no break is needed, the token stays as it is. N = 1 is legal only
    with a break field, in the proxy's collapse and in the filter's parse.
    It is not recorded in the §3.8 registry, which serves rows and has
    none to serve here. After a narrowing (§13) that leaves the value too wide
    for its one row, the row shows the cap note, `… +1 more lines`.
- **The break field must fit.** It widens the head by up to five
  characters, so a break is dropped when the head with `:K` no longer fits
  in `F` (the head would move to its own row in the TUI).
- **The grammar: a fifth head field.** `T/1:N:W:F:K` says the proxy
  inserted one `\n` K characters (UTF-16 units, 1 to 9999) after the
  block's last row. Collapse needs that `\n` exactly there, with none before
  it, and removes it with the block, so `collapse(expand(t)) === t` still
  holds; the v2 property test inserts breaks in 40% of its v2 blocks. The
  strip removes `:K` with the head suffix, but it cannot tell an inserted
  `\n` from the model's own, so a mangled block keeps its break.
- **The filter** reads `:K` as part of the head (`HEAD_V2_SUFFIX_RE`,
  `HEAD_SUFFIX_MAX` 22) and paints as before. The TUI lays out the break.

### 14.5 Security

- **What is new, in the agent's world:** the break's position, which bounds
  the width of the value's last row (at most about 7 bits for `W ≤ 120`). It
  is the same class of information as N (§5.2): it exists only in the
  agent's process and transcript. Collapse returns the model's text byte for
  byte, and the strip removes `:K`. The residual is one more `\n` that a
  mangled block can leave in the model's history, at the position the
  value's width chose. It is accepted like the §5.2 residual.
- **The arbiter** returns one more integer from an op that is already human
  plane. The hold moves no data; it only delays text.

### 14.6 Tests

- **Unit, proxy (both copies):** the grammar (`:K`, collapse with the break,
  three malformed breaks, the strip); the v2 property with breaks;
  `suffixBreak` (fits, glue, marker wider than the value's last row, each
  refusal, code spans, link text, each Markdown block start); the table
  rest; the expander (the hold, the break at every split offset, the table
  row); Codex (the break across deltas with every snapshot agreeing, the
  table row); head-only blocks (a 94-column value at 160 columns).
- **Unit, arbiter:** `shapeRowsLast`, and `last` on every `symbolShape`
  answer with a width.
- **Unit, filter:** the head with `:K`, including split at a chunk edge;
  `:K` never on screen; N = 1 only with `:K`.
- **Integration:** `reserve-block-parity.test.ts` (heads with `:K`);
  `reply-row-reservation.test.ts` (a sentence whose tail would clip, which
  breaks and comes back byte-exact; a table row, which is not expanded; a
  49-column value at 80 columns, head-only).
- **Live:** `echo-fidelity-suffix` (Claude Code), and on the Codex lane
  `echo-fidelity-rows`, `-wrap`, `-inline` and `-suffix`. On the Codex lane
  the reply rows match vanilla, the §14 break included. A real Codex session
  (codex-cli 0.159.1, a 9-line fake `~/.ssh/config`) expanded the block at
  80×24 and 160×40, rendered every line on its own row with the 111-column
  line word-wrapped at 78, left no marker on any settled screen, collapsed on
  turn 2, and leaked no fake value to any model-bound event. Codex's own
  tool-output preview row stays `⏎`-joined: it is the tool cell, not the
  reply.

## 15. Structured reply output (`json`, `stream-json`)

The reply filter is a HumanView utility surface: it transforms the outbound
copy of an agent reply while AgentView (repo: Agent File System /
agent-view) and the privileged T-LLM transcript retain symbols. It is not an
authorization or model-ingress path. Resolving a symbol inside serialized
JSON with the plain terminal filter would insert literal newlines and quotes
into a JSON string and break Claude's `--output-format stream-json` framing,
so structured output gets its own filter (`interceptors/reply-filter/src/structured-filter.ts`).

### 15.1 Format and field contract

The launcher determines framing from the original `plan.argv` before security
prefixes obscure the agent executable. It passes the validated enum as a
wrapper-only `--mandu-output-format=<format>` option before `--`. The reply
filter consumes this option; it is not inherited in environment variables or
forwarded to supervisors or agents. All net-guard, Landlock and
secret-confinement prefixes remain intact. Standalone reply-filter calls
detect their direct command. The launcher and the reply filter share the
detector through a provenance-marked copy and cross-package parity tests.

For the original or direct `claude` argv, the detector recognizes
`--output-format json` and `--output-format stream-json`, including the
equals form, before an argv `--` delimiter. Explicit text output and
invocations without an output format keep the text/TTY behavior.
Required-value options consume their value; optional-value flags such as
`--resume`/`-r` consume only a following non-option argument (the optional
flag inventory comes from Claude Code 2.1.267's help). Ambiguous or
unsupported explicit formats pass through. Interpreter-launched CLIs are
outside this detection contract.

Stream JSON is one record per LF (CRLF and final records without LF are
supported). JSON is one complete document, optionally a verbose array of
records, buffered until EOF. The only resolved strings are `result.result`
on a record with `type: "result"` and `assistant.message.content[].text` on
blocks with `type: "text"` in a record with `type: "assistant"` and
`message.role: "assistant"` — the shapes of native Claude CLI captures. Tool
input, user records, metadata, IDs, `result_symbol`, and arbitrary
`structured_output` values are untouched. Unknown record types pass through.
Incremental `stream_event` deltas pass through because a symbol can span
multiple events; completed assistant/result records carry the resolved
human-facing text. No cross-event reconstruction is claimed.

The parser records string spans and edits only selected spans, using JSON
string serialization for replacement values. Every other byte is retained,
including whitespace, CRLF, property order, numeric spelling, large integer
precision and metadata escape spelling. Duplicate object keys are rejected as
ambiguous. This avoids a parse/stringify round trip that could silently round
machine data.

### 15.2 Bounds and failure behavior

Each record or document is limited to 1 MiB of UTF-8 input, 64 container
levels, 20,000 parsed values and 128 human-text fields. Output expansion is
limited to 4 MiB per record or document. Resolution has a total two-second
deadline. On a malformed or truncated record, an exceeded bound, an unknown
schema or an arbiter error, the complete original record passes through
unchanged; no partial replacement is committed. Oversized stream records pass
through until the next LF, then parsing resumes; oversized JSON documents pass
through to EOF. Diagnostics contain fixed reason codes only, never record
content or exception text.

An explicit structured format selects pipe mode, including on a TTY, unless
PTY is explicitly forced; forced-PTY structured invocations pass through,
because terminal relay transformations cannot promise JSON byte fidelity.
Ordinary text and interactive PTY rendering are unaffected. The wrapper
pauses child stdout while processing a chunk and awaits downstream write
backpressure, so queued records cannot bypass the buffer limits. If the
output consumer closes its pipe or a queued operation rejects, the wrapper
closes its arbiter connection and stops its child (SIGTERM, then SIGKILL
after one second), exiting with status 1, so a paused child is never
orphaned by an unhandled write rejection.

Successful resolution records the complete original and transformed
serialized record in the existing privileged observability event.
Diagnostics go to stderr and do not alter stdout. Unknown or failed records
retain opaque symbols; this utility degradation does not weaken the model
boundary.

### 15.3 Tests

Unit tests cover arbitrary chunk splits, escaped originals, valid JSON and
type preservation, lossless numeric and metadata bytes, schema selection,
malformed and unknown records, duplicate keys, bounds, timeouts, and failure
atomicity. The launcher's composition e2e keeps multiple executable
supervisor prefixes and checks that the internal format option never reaches
the child. A real arbiter and the actual reply-filter subprocess run a
benign Claude-shaped stdout fixture without provider calls, checking both
output formats, the child's original output, and the serialized
observability records; the plain stdout and PTY suites remain regression
coverage. An offline native-CLI test parses every retained stdout record and
requires a completed string-valued result. These local fixtures make no
provider calls and do not count as real-model utility results.

### 15.4 Goose's ACP stream (the launcher's relay, 2026-10-07)

`mandu goose acp` serves an editor over ACP (JSON-RPC, one message per line
on stdio), and the launcher already relays that stream itself
(`launcher/src/goose-acp-relay.ts`; supported-agents.md §5.6 "Recipes, review
and ACP"). The byte-stream filter stays off for it, as it was; the relay's own
editor-bound pass (`launcher/src/goose-acp-display.ts`) does this section's
job instead, in the launcher process, which holds the human-plane socket
(arbiter-human-plane.md) and calls `desymbolize` over it directly. It follows
§15.1's method, with ACP's shapes:

- **Which strings.** Only Goose → editor lines, and in them only the
  human-display strings of known shapes (captured from goose 1.53.0):
  `session/update` `agent_message_chunk` / `agent_thought_chunk` (the content
  block's `text`, a `resource`'s `resource.text`, a `resource_link`'s
  `title` / `description`); `tool_call` / `tool_call_update` (`title`, each
  content item's text or a `diff`'s `oldText` / `newText`, every string inside
  `rawInput` / `rawOutput`, Goose's live output
  `_meta.toolNotification.params.chunks[].output`); `plan` entries'
  `content`; `session_info_update`'s `title`; the `toolCall` of a
  `session/request_permission`; and the `title`s in the answer to
  `session/list`. Never `user_message_chunk` (see the flow-back below), ids,
  paths, kinds, keys or anything else.
- **The bytes.** The span parser of §15.1 (copied, provenance-marked, with
  bounds for a tool's output: 8 MiB per line, 200,000 values, 512 display
  strings); only the selected spans change, re-serialized by
  `JSON.stringify`, so a resolved value's newlines and quotes stay escaped
  and the line stays one line. A line without `$MDU:` is written untouched
  without parsing. A Markdown-escaped token resolves as in the text filter.
- **Order and failure.** Every line toward the editor (the relay's own
  refusals included) goes through one ordered queue. A line that does not
  parse, is over a bound, or meets an arbiter error or the two-second
  deadline passes as Goose wrote it (the symbols stay); after a missed
  deadline the next ten seconds pass unresolved, so a wedged arbiter does not
  stall the stream, and the launcher says so once on stderr. No human-plane
  socket, or `--no-reply-filter` / `MANDU_REPLY_FILTER=0`, turns the pass
  off. Split tokens are not reassembled across messages: the proxy's text
  repacker already delivers each token whole within one text delta
  (`sse-text-repack.ts`), and Goose forwards a delta as one chunk; a token
  split anyway stays a symbol.
- **The model's side.** Nothing the relay writes toward Goose is touched:
  the editor's requests and answers pass as the editor wrote them, and
  Goose's own history, from which every later turn is built, is what the
  model wrote (symbols).

**Flow-back (can an original the editor shows reach the model?).** The ACP
paths from the editor to Goose are the editor's requests (the allowlisted
session methods) and its answers to Goose's requests. (1) An answer carries
no display text back: the only Goose request that reaches the editor is
`session/request_permission`, answered with an option id; `fs/*` and
`terminal/*` are answered by the relay and never reach the editor, so the
editor never writes a desymbolized diff to a file on Goose's behalf. (2) An
ACP client sends only the new prompt; the conversation lives in Goose, so a
replayed or displayed message is not sent back by the protocol. (3) What an
editor re-sends by itself is the human's own turn (Zed edits and resends a
user message): `user_message_chunk` is not desymbolized, so a symbol the
human's turn held goes back as that symbol. (4) What remains is a human or
editor action that quotes displayed text into a new prompt (a paste, an
"add selection to the thread"): that is a `human` segment of the prompt, and
the prompt filter's registered-value filter masks a secret's value back to
its symbol (confidentiality-plan-15-prompt-filter.md §4.1). The real-goose
component test echoes the displayed original into the next prompt and the
model reads only the symbol. The residual is the prompt floor of that plan:
a value under 12 characters or under 3.0 bits per character of entropy in a
human segment reaches the model as typed, exactly as when the human retypes
what the terminal reply filter showed; it is the human's own text (plan 15
§2, decision 1), not a path this pass opens.

Tests: `launcher/test/unit/goose-acp-display.test.ts` (the field selection,
non-display fields and the human's turns untouched, escapes and unicode, a
`\u`-escaped line, a Markdown-escaped token, every failure a passthrough,
the order behind a slow resolution and the back-off, the relay never
desymbolizing toward Goose, the parse switch);
`launcher/test/component/goose-acp-real.test.ts` ("display": the REAL goose
behind the launcher, the scripted model quoting the symbol it read, the
editor reading the original, no request to the model holding the value, the
editor's echo masked, a load replaying originals; `--no-reply-filter`
keeping the symbol); `tests/stack/goose-acp-display.test.ts` (the production
resolver over a real arbiter's human plane: originals in every display
field, nothing toward Goose desymbolized, the data socket resolving nothing,
the arbiter gone a passthrough in order).

## 16. How the filter is started (early start)

Since 2026-10-04 the launcher starts the reply filter's process alongside the
session's services and hands it the agent at the end over a socket pair on
its fd 3 (`src/handoff.ts`; packaging.md §5.3). Nothing in this note changes
with it: once handed its command, environment and directory, the filter
decides pipe / PTY relay / passthrough from the same facts, paints the same
blocks and reports the same relay mode as the serial form
(`reply-filter --mandu-output-format=<f> -- <command>`), which the hand-off
reproduces exactly. Two things are new. The launch scope's prefix
(`systemd-run --user --scope … --`) is run by the filter in front of what it
spawns, so under a systemd scope the filter sits outside the session's scope
while `script(1)` and the agent stay in it. And before the hand-off the
filter connects to no arbiter and reads or writes no terminal, so no relay
report or event exists for a launch that stopped first; such a launch ends
the waiting filter (an end of file on fd 3: it exits 0, silently). Tests:
`test/unit/handoff.test.ts`, `test/component/handoff.test.ts`.

## 17. The terminal wrap rule (Goose)

> **Status: BUILT (2026-10-07).** A TUI that prints the model's reply raw at
> column 0 and leaves the wrap to the terminal gets its reserved rows laid
> out by the terminal's own autowrap. The launcher selects it for Goose.

### 17.1 The cause, and the probe (vanilla Goose 1.53.0)

The Goose differential lane (differential-interactive.md §32) showed six
scenarios whose long lines broke one word earlier under Mandu than without
it. The raw PTY bytes of `fidelity-echo-wrap` gave the cause:

- **Vanilla.** Goose writes the value's long line in one run, with SGR
  changes and no line break inside it. The terminal wraps it at column 80,
  mid-word: `… SEGW09 SEG` / `W10 SEGW11 …`.
- **Mandu.** The proxy sent a v2 block laid out by Ink's rule (§11.2): word
  wrap at `W = cols − 2 = 78`, after a 2-column content indent. The filter
  painted `… SEGW09 ` into row 2 and `SEGW10 …` into row 3, each bracketed
  with autowrap off, one row per marker Goose printed.

Nothing was wrong with the width that `script(1)` passed (80 on both sides),
nor with the symbol's length: the head and its markers never reach the
screen. The layout rule was Claude Code's, and Goose does not lay out its
reply at all. A probe of `goose session` against a scripted model, at 80
columns, with Markdown in the reply, confirmed the rest of the rule:

| Reply | Screen |
|---|---|
| a long paragraph, a long list item, a long numbered item | printed from column 0 and broken by the terminal at column 80, mid-word; no hanging indent |
| `**bold**`, `*italic*`, `` `code` ``, `> quote`, `# Heading` | every character drawn as written (colors only) |
| a fenced block with a long line | the fence lines drawn; the long line wraps at 80 like prose |
| a TAB | the terminal's tab stop |
| a line of Hangul | a syllable that would straddle column 80 moves whole to the next row |
| a table | its rows drawn raw, but the line break after the last row is lost (the next line joins it) |

### 17.2 The rule

`layoutRows(value, W, F, rule)` takes a fourth argument, `ink` (the default,
§11.2) or `terminal`. Under `terminal` each cleaned line is cut glyph by
glyph: a row ends when the next glyph does not fit; a wide glyph that would
straddle the edge starts the next row; a zero-width glyph stays on its row;
spaces are kept wherever they fall, at a row's start too. The first row is
`F` wide and every other row `W`, as before. `wrapLineTerminal` implements
it in the shared `reserve-layout.ts`, so the four copies stay byte-identical.

### 17.3 Who selects it

- **The launcher** sets `MANDU_REPLY_WRAP_RULE=terminal` in the reply
  filter's own environment for the `goose` target (`reply-filter.ts`
  `replyWrapRuleEnv`), in the serial form and in the hand-off. The filter
  removes it from its child's environment, like the human-plane socket.
- **The filter** reports `rule: "terminal"` with `reserve` and `wrap` in
  `setSessionRelay`, and stamps the rule on every head it records
  (`ReserveValueCache`), so the stream splice, the screen reconciler and the
  §3.8 registry path all paint by it. An `ink` session sends no `rule` key.
- **The arbiter** stores the rule with the relay state, returns it from
  `sessionRelay`, and takes `rule` on `symbolShape` beside `width` and
  `first`. It refuses any value other than `ink` or `terminal`, and a `rule`
  without a `width`. Both ops stay human plane only (§11.5).
- **The proxy** reads the rule with the relay's columns (`ReserveEligibility`
  `layout`), fixes it with the stream's mode, and passes it to
  `decideReserve`, `suffixBreak` and `symbolShape`. The shape cache keys on
  it. Any rule it does not know is read as `ink`.

### 17.4 Eligibility under the terminal rule

`decideReserve` (`reserve-context.ts`) takes a `terminal` branch:

- **W is the full width**, with no content indent and no list indent. A list
  item's marker is text on its row.
- **A standalone token** takes `F = W`, inside a fence too, since Goose
  draws fences raw.
- **A mid-line token**: the head's column is the terminal's arithmetic over
  the raw text before it (`terminalColumn`: autowrap at W, TAB stops, wide
  glyphs). Nothing on the line is Markdown, so `F = W − p` is exact. When
  the prefix fills its last row to the edge, the token is not expanded: the
  cursor then waits to wrap, and a splice written with autowrap off would
  land on that row's last cell. A control byte in the prefix also means no
  expansion. Another token earlier on the line gives `F = 0`, and the ⌈W/2⌉
  clamp applies, as under `ink`.
- **A code span is text.** The backticks are drawn, so the span form (§12)
  never applies. A token inside backticks takes the plain mid-line form, and
  a backtick counts as an allowed character before or after it.
- **The structural refusals stay:** a heading, a blockquote, a table row,
  link text, and a mid-line token inside a fence. The table refusal is
  needed because Goose loses the line break after a table. The others stay
  only because they were not probed with an expansion.
- **The break (§14).** The terminal breaks the text after the value where
  the row is full, mid-word. So `K` is the number of the suffix's
  characters that fit after `max(last, marker)`, which is never later than
  the screen's own break, so the text never clips. No break is made when
  the suffix fits, holds another token or a control byte, or when not one
  character fits. The Ink-only check that the head with `:K` fits in `F`
  is skipped, because Goose never lays the head out.
- **No head-only block.** A one-row value's splice closes its wrap-off
  bracket right after the value. The text after it then wraps by itself,
  exactly where vanilla's does. (The clip of what a widened row pushes past
  the edge, §11.10, is Ink's rule only: under this rule nothing after the
  value is clipped.)

### 17.5 Security

Nothing new moves, and nothing new reaches the model.

- `rows` and `last` under `terminal` are the same kind of count and width as
  under `ink` (§11.6, §14.5).
- The rule is chosen by the launcher and reported on the human plane only.
  An agent cannot select it, any more than it can set `cols`.
- Asking for both rules gives the proxy two counts of one value at one
  width instead of one. The proxy is not in the agent's world, and §11.6
  already treats it as able to learn line widths across replies.
- Collapse is unchanged: a terminal-rule block is a v2 block (`T/1:N:W:F`,
  optional `:K`), and the model gets back its text byte for byte.

### 17.6 What stays different: a resize

`fidelity-echo-resize` keeps a declared divergence. Vanilla's long line is
one line that the terminal wrapped, so after a narrowing the terminal (here
the harness's emulator; many real terminals do the same) re-wraps it at the
new width. On the Mandu side each reserved row is a line that Goose itself
ended: the block's markers are lines of the model's text. So the emulator
keeps the 80-column break and re-wraps only the rows wider than the new
width. Goose never reprints its transcript, so the §13 re-layout has nothing
to repaint.

This follows from the design: a reservation is made of line breaks the TUI
prints. A bounded fix was considered and not built. For a row that fills
the width and continues the same value line, the filter would write it with
autowrap on and drop the CR LF that Goose prints after its marker, so that
the terminal soft-wraps it as vanilla does. That means removing bytes the
TUI wrote, across writes and SGR changes. It is sound only for a TUI that
never moves the cursor over its reply, and it would be the filter's first
deletion of TUI line breaks in a live relay.

### 17.7 Other agents

Claude Code and Codex keep `ink`, which was probed against both (§11.1,
§11.7). OpenClaw also gets `ink`. Its differential lane does not echo a
value wider than the row (`fidelity-echo-short`), so the rule is unprobed
for it. A wrapped reserved value there may break where its renderer would
not.

OpenCode broke exactly so (differential-interactive.md §35, 2026-10-10):
it indents its reply by 5, lays it out narrower than `cols − 2`, and breaks
a word that does not fit at its punctuation, so a v2 head split across two
rows and its suffix stayed on screen. The launcher now sets
`MANDU_REPLY_WRAP_RULE=none` for `--target opencode`: the filter reports
the relay without `wrap` (`wrapLayoutKnown`), and the proxy sends only v1
heads, for a token alone on its line. A token inside a sentence keeps the
one-row splice. `none` changes nothing else: a v2 head that arrives anyway
is painted by `ink`, and the arbiter and the proxies need no change (a
relay without `wrap` has meant v1 since §11.4).

### 17.8 Tests

- **Unit, layout** (`reserve-layout.test.ts`, the filter's and the Codex
  proxy's copies): the probe's break, `first`, spaces at a row's start, wide
  and zero-width glyphs, `ink` as the default, and a seeded property: no row
  is wider than its cap, and the rows rejoin to the cleaned line.
- **Unit, arbiter:** `parseShapeLayout` with `rule` (stored only when
  given, refused unless `ink` or `terminal`, needs `width`); `shapeRows` /
  `shapeRowsLast` under both rules; `symbolShape` with `rule` over dispatch,
  human plane only, refused before the lookup; the relay's `rule` round
  trip and its refusals (`session-relay.test.ts`).
- **Unit, proxy** (`reserve-context.test.ts`, both copies):
  `terminalColumn`; `decideReserve` under `terminal` (W, standalone and in
  a fence, F exact with Markdown characters and leading spaces, the
  full-row refusal, code spans as text, the refusals that stay);
  `suffixBreak` under `terminal`. `sse-reserve-expand.test.ts`: the
  standalone and mid-line blocks with the exact break at every split
  offset, no span form, no head-only block, and the eligibility's rule and
  cache key. The adapter forwards `rule` only when given.
- **Unit, filter:** `wrapRule`, the relay report with `rule`, the cache
  stamping its rule, the memo keyed on the rule, a narrowing under
  `terminal` (`reserve-block.test.ts`); in `filter.test.ts` a Goose-printed
  standalone block and a mid-line block with its break render exactly
  vanilla's screen, and the same block painted by `ink` breaks a word early.
- **Unit, launcher:** `MANDU_REPLY_WRAP_RULE=terminal` for `goose` only, in
  both start forms, and the name is the filter's.
- **Integration:** `reserve-layout-parity.test.ts` (the copies);
  `proxy-real-client-parity.test.ts` (the rule from the filter's adapter to
  the proxy's, `symbolShape` with `rule` over the real client, a bad rule
  refused).
- **Live:** the Goose lane (differential-interactive.md §32).
  `fidelity-echo`, `-wrap`, `-inline`, `-codespan` and `-suffix` now reach
  full parity. `-resize` keeps the §17.6 divergence.

## 18. A resolver that refuses: the S8 miss (2026-10-07)

### 18.1 What was seen

S8's first live run (2026-09-30, Claude Code 2.1.285; today's drill
`conf-hold-once`, then `cat .env` allowed once) ended with the reply row
reading `  $MDU:nomodel_Bash[66b7]` on the human's terminal. The model held
one whole-result `no-model` symbol for the tainted Bash call (correct), and
the reply filter, which should have shown the value, passed the token
through. The run's arbiter log had nine `refused on data channel:
desymbolize` right after the reply, from a process it did not name, and
the session's events had no `desymbolize`. The next three runs resolved.

### 18.2 The cause: two builds in one run

The human plane (arbiter-human-plane.md) merged at `489f7e42`
(2026-09-30 00:03 UTC): the arbiter began refusing `desymbolize` on the
data socket, and the reply filter moved to `MANDU_ARBITER_HUMAN_SOCK` in the
same merge. The drill runner's `--own-arbiter` (new that morning) starts
the arbiter from the runner's checkout, a worktree at `489f7e42`, but
launches the `mandu` on PATH, the main checkout, which sat at `dc1d7c57`
(before the merge) until 00:18 UTC. Run 1 started at 00:14: the old reply
filter resolved over `MANDU_ARBITER_SOCK`, the new arbiter refused each of
the nine lookups (the "unknown process" was the filter itself), and the
filter's utility posture turned every refusal into a silent pass-through.
Run 2 (00:20) came after the main checkout moved and resolved. The token
family was never the problem.

Both builds were one version, so the release check that came later
(runtime-instances.md §4.1, 2026-10-09) could not see this skew either.
Since 2026-10-17 it can: `hello` reports which build the arbiter runs
(`build`: the hash of its bundle, the checkout rev it came from), and the
launcher compares it with the build it would start. Here the arbiter ran
`489f7e42`'s code and the `mandu` was `dc1d7c57`'s, and the arbiter tree
differs between the two (the merge changed the arbiter), so the launch
would have refused that arbiter before the agent started, naming both
builds (a pinned socket is never restarted). Two commits whose
`arbiter/` trees are the same, or two bundles that hash alike, still count
as one build.

### 18.3 Hypotheses ruled out

Each has a test that passes on the code before this change:

| Hypothesis | Evidence | Test |
|---|---|---|
| The token grammar misses `nomodel_Bash` (an underscore, a tool-name suffix) | `SYMBOL_TOKEN_RE` takes `[a-zA-Z_][a-zA-Z0-9_]*`; the Markdown-escaped `\$MDU:nomodel\_Bash` resolves too | `resolve-health.test.ts` H1, H5 |
| A token straddling a chunk boundary | one byte per write resolves, pipe and eager | H3 |
| A hard wrap inside the token | CRLF + indent after `nomodel_` resolves | H4 |
| A restyle inside the token | an SGR at the `_` resolves | H5b |
| A cell-diff split on the main screen (the !601 shape) | `$MDU:` CHA `omodel_Bash[…]` over `Running…`: no `$MDU` on the wire, the row reads the value | `refused-resolver.test.ts` (x5) |
| The alternate screen, the token in two pieces | the screen model repaints the value | (x6) |
| The level: the human plane does not resolve `no-model` | `desymbolize` is label-unrestricted on the human plane; the real arbiter resolves a `nomodel_Bash` mint for the filter | `tests/stack/reply-filter-refused-plane.test.ts` (run 1) |
| The run itself was not under a reply filter | the session's `relay_mode` was `pty` | the run's events |

### 18.4 The fix

Two halves, the record and the harness.

**The filter says when it cannot resolve** (`src/resolve-health.ts`).
Every lookup the stream filter and the screen model make goes through
`WatchedResolver`. It changes no result and no error: a failure still
throws, and each caller keeps its pass-through. It reports state changes:
the first failure after a healthy state emits `relay_mode` again, same
mode, with `resolveFailure` (the error message, one line, at most 240
characters) and the line `DEGRADED: the arbiter did not resolve a
placeholder (…)`; the first success after a failure emits a plain
`relay_mode`. At most 20 such records per session. When the agent exits,
the wrapper prints `N placeholder lookups failed (first: …); those $MDU:
placeholders stayed opaque on your terminal (nothing leaked).` The
dashboard's session health (dashboard.md §4.21) is `broken` while the last
`relay_mode` carries `resolveFailure`. S8's run would have shown the
refusal on the chip, in the run's events and on stderr.

**The harness refuses the mixed build** (`drill-preflight.ts`
`mixedCheckoutRefusal`, drill-runner.md §3): `--own-arbiter` with an
arbiter checkout and a `mandu` checkout at different commits refuses to
start unless `--allow-mixed-checkouts`. `scripts/drills-live.sh` launches
its own checkout's `mandu`.

### 18.5 Security

No original moves anywhere new. The filter still never asks the data socket
(`humanSockFromEnv`); a refused or failed lookup leaves the token
byte-exact, never a part of it and never a blank. The new record carries an
error message: the arbiter's refusal names the op and the channel, a socket
error names the path, and neither the filter nor the arbiter puts a value
in one (the filter sends only the agent's own placeholders). The stack
test asserts no original in the record, on the terminal, in the agent's
stream or in either model request.

### 18.6 Residuals

- ~~**No launcher-arbiter version handshake.** A long-running arbiter of
  another release than the launcher (an upgrade under a running service)
  can still refuse a filter's lookups, or lack an op it needs. It is now on
  the record and on stderr, not silent; the launch does not refuse it.~~
  **Closed (2026-10-09):** `hello` reports the arbiter's release, and the
  launch compares it with its own before any session op: an older resident
  stack no other session uses is restarted as this release; one in use, a
  newer one, a pinned one and one this launch started are refused, the
  resident ones naming `mandu stop --stack <dir>` (runtime-instances.md
  §4.1). ~~Two commits of one version still look alike to it: the S8 case
  itself stays with the harness's mixed-checkout refusal (§18.4).~~
  **Closed (2026-10-17):** `hello` reports the build too, and another build
  of this release is handled like an older one (an unused resident stack is
  replaced, one in use, a pinned one and one this launch started are
  refused, naming both builds); the dashboard flags an adopted arbiter of
  another release or build STALE (runtime-instances.md §4, §4.1). The S8
  case no longer rests on the dashboard's flag, `update-main.sh` and the
  harness's refusal, which stay as further layers. Left: two dirty work
  trees at one rev, both from source, still look alike.
- **The refusal does not name its caller.** The arbiter logs `refused on
  data channel: <op>` without the peer's pid (node exposes no
  `SO_PEERCRED`); the filter's own record is what names it now.
- ~~**An arbiter restarted under a session** listens on a new human socket
  (the path carries the instance id), and the filter keeps dialling the old
  one.~~ **Closed (2026-10-07):** the filter's client re-learns the human
  socket from the data socket's `hello` when its own stops answering, with
  backoff, and never asks the data socket for a human-plane op
  (arbiter-human-plane.md §5.1). The first lookup answered on the new socket
  emits the recovery `relay_mode`, and the filter re-reports its relay. The
  proxies, net-proxy and fs-sync use the same client. Lookups made while no
  arbiter answers still fail (recorded, the token stays opaque). The Rust
  consumers (the guard's report channel, net-supervisor's transform) re-learn
  the same way (§5.1 there).

### 18.7 Tests

- **Unit** (`test/unit/resolve-health.test.ts`): the §18.3 hypotheses at the
  stream filter, pipe and eager; a refused lookup leaves the token
  byte-exact; `WatchedResolver`'s state changes, the cap, a throwing hook,
  the exit note, the reason's clipping.
- **Component** (`test/component/refused-resolver.test.ts`, the real
  `run.ts` over a socket mock): pipe and PTY with every lookup refused (the
  token on the row, the degraded record, the note), PTY answering (the
  value, no `$MDU` on the wire), refused once then answered (down, then
  up), and the two split shapes with this token.
- **Dashboard** (`session-health.test.ts`): `broken` while the last record
  carries `resolveFailure`, `ok` after a plain one.
- **Stack e2e** (`tests/stack/reply-filter-refused-plane.test.ts`): a real
  arbiter, the real anthropic-proxy and the real filter in PTY mode around
  a fake agent; the S8 mint (`symbolize`, tool `Bash`, `no-model`). On the
  human plane the screen reads the program's line and never the token,
  while both model requests and the agent's stream carry only the token. On
  the data socket (the S8 skew) the screen reads the token, nothing leaks,
  the arbiter logs the refusal, and the degraded record and the note are
  there.
- **Harness** (`drill-runner.test.ts`, `scripts/test/drills-live.test.mjs`):
  the mixed-checkout refusal and its exits; `drills-live.sh` names its own
  checkout's `mandu`.
- **Restart** (`tests/stack/reply-filter-arbiter-restart.test.ts`): a real
  arbiter stops after the filter is up and a second one starts on the same
  data socket and symbol DB with a new human socket; the human's screen
  reads the value, the model and the agent's stream only the token, the
  recovery `relay_mode` and the re-reported relay are on the new arbiter,
  and no data socket was asked to desymbolize. `resolve-health.test.ts`: a
  success on a moved endpoint is one recovery.

## 19. TAB stops from the screen's column 0 (2026-10-18)

### 19.1 What was seen

A `no-model` file of tab-separated lines, read and echoed back as its one
symbol, against vanilla Claude Code 2.1.292 at 120 columns
(differential-interactive.md §19). Vanilla leaves each TAB to the terminal,
which advances to the next multiple of 8 of the screen column: with the
reply at column 2, `● name  port    owner` puts `port` at column 8 and
`owner` at 16. The reserved rows put them at 10 and 18: `cleanLine`
counted the stops from the value line's own column 0, so every stop landed
2 columns right of vanilla's. The columns still lined up with each other and
nothing was lost.

### 19.2 The rule

`layoutRows(value, W, F, rule, indent)` (§11.2) takes the screen column the
content area starts at. A line's first glyph sits at `indent`, except line 1
on a head row `F` wide, which sits at `indent + W − F` (that row ends at the
right edge), and `cleanLine(line, col0)` expands each TAB to the next
multiple of 8 of `col0` plus the columns before it. The wrap then runs on
the expanded line as before. An absent `indent` is 0.

- **Codex:** `indent = cols − W`, which is 2, or 2 plus the list indent in
  a list item (§11.4). This rule was Claude Code's too until §19.7 found
  that Claude Code counts from its text: there `indent` is 0.
- **The `terminal` rule (Goose):** `W = cols`, so `indent = 0`; a mid-line
  head's line 1 starts at `W − F`, the prefix's own column (§17.4).

### 19.3 Who knows the indent

The rows the arbiter counts and the rows the filter paints must be the same
rows, so both sides lay out with the same `indent`. Neither the head nor
the grammar changes.

- **The proxy** fixes `cols` with the stream's mode, decides `W` and `F`
  (`decideReserve`), and passes `indent = cols − W` (0 when the relay
  reports `tabs: "content"`, §19.7) to `symbolShape`
  (`sse-reserve-expand.ts` in both proxies; `ReserveEligibility.shape`
  sends it when it is not 0 and keys its shape cache on it).
- **The arbiter** validates `indent` with the other layout fields
  (`parseShapeLayout`) and counts `rows` and `last` with it.
- **The filter** derives it from the head: the terminal's columns when it
  first saw the block (`HeadShape.cols`, §13) minus `W` (`blockIndent` in
  `reserve-block.ts`), or 0 under a `content` origin (§19.7). A resize keeps it: the rows start where they did
  (`paintLayout`). With the width unknown, or for a v1 head, it is 0; a v1
  row goes through the writers' frame-safe pass, which already counts from
  the row's known column (differential-interactive.md §19).

### 19.4 Security

No original moves anywhere new. `indent` is one more integer on a
human-plane op the proxy sends, never the agent. The model steers it only
through a list item's indent, inside the range `F` already gives it (§11.6),
and it changes a count only for a value that holds a TAB.

### 19.5 Residuals

- **A TAB on a wrapped row** is counted along its line, from the line's
  first row: the TAB is expanded before the wrap places the line's words, so
  a stop on a later row of the same line is the line's, not the row's. A
  line of tab-separated cells that wraps is rare, and was not probed.
- **A head row whose `F` is smaller than the room it has** (the proxy's
  fallback when it cannot prove the head's column, §11.4) counts the head's
  stops from `W − F`, which can be right of the head's real column.
- **A TAB at the right edge**: a terminal's TAB never wraps (the cursor stops
  at the last column), while the expanded spaces wrap like text. It only
  matters for a row already at its edge.

### 19.6 Tests

- **Unit, layout** (`reserve-layout.test.ts`, the filter's and the Codex
  proxy's copy): `cleanLine` at every start column against a reference
  terminal over a seeded corpus; the capture's three TSV lines at indent 2
  give vanilla's columns; the head row's offset `W − F`, `F = 0`, the
  terminal rule; every single-row line of a seeded corpus reads as the
  terminal prints it at its column, under both rules.
- **Unit, filter** (`reserve-block.test.ts`): `blockIndent`, and a v2
  row's stops at indent 2, in a list item, on a mid-line head row, after a
  narrowing, and with the width unknown.
- **Unit, arbiter** (`symbol-shape.test.ts`): `indent` parsed and refused,
  a row count it changes, and over dispatch.
- **Unit, proxies** (`sse-reserve-expand.test.ts`): the expander passes
  `cols − W` (2, 4, 0 under the terminal rule) and the eligibility sends and
  caches it; on Codex, through the eligibility, a value that only the right
  count expands.
- **Integration:** `reserve-layout-parity.test.ts` runs its corpus with a
  random indent and rule through all four copies;
  `proxy-real-client-parity.test.ts` forwards `indent` over both proxies'
  production wiring.
- **Stack e2e** (`reply-row-reservation.test.ts`): the fake agent lays its
  reply out two columns in, as Claude Code does (`RR_RENDER=indent2`); the
  reserved rows of a TSV secret on the 80×24 screen equal the same emulator's
  rendering of vanilla's bytes (each line two columns in, its raw TABs), and
  no cell reaches the agent or the model. The §3.8 alternate-screen case now
  paints from column 2 too.

### 19.7 Claude Code counts from its text (2026-10-21)

**What was seen.** The differential drill `fidelity-echo-tabs` (a
`no-model` file of tab-separated lines echoed back, no word-gap mask:
differential-interactive.md §19) failed against the real Claude Code TUI,
2.1.295 (the CI pin) and 2.1.305, on both renderers at 80×24 and 160×40.
Vanilla's raw output holds no TAB byte at all: Claude Code's renderer
expands each TAB in the text it draws to the next multiple of 8 counted
from the text's own column 0 (the reply at screen column 2), resetting at
each line break, before it wraps the line. So `DIFFTAB_HOST\tport` puts
`port` at 2 + 16 = 18 and `db1\t5432` puts `5432` at 2 + 8 = 10, where the
reserved rows of §19.2 put them at 16 and 8. The same origin holds for a
value inside a sentence (`The value is DIFFTAB_HOST\tport …`: `port` at
2 + 32, the prefix counted) and in a list item (the item's text at column
4, the stops from there). The 2026-10-07 capture on 2.1.292 (§19.1) showed
the terminal's stops; no local copy of 2.1.292 is left to say whether that
release passed the TAB through or the capture misread it. Codex 0.162,
measured the same way, keeps its stops on the screen's grid, so §19.2's
rule stays right for it.

**The rule.** The TAB origin is a property of the agent's TUI:

- `screen` (the default): the stops are the terminal's, counted from the
  screen's column 0. Codex; Goose prints at column 0, where the two agree.
- `content`: the TUI expands each TAB from the left edge of the text it is
  in. Claude Code. A reserved block's layout then takes `indent` 0: line 1
  on a head row counts from `W − F`, every other line from the content
  area's column 0 (a list item's text included, as its `W` already
  excludes the list indent). A value the filter splices into a row with no
  block around it (the one-row splice of filter.ts, the reconciler's
  repaint on the alternate screen) counts from `CONTENT_TAB_COL`, column 2,
  Claude Code's reply indent.

**Who knows it.** One source, as the wrap rule's (§17.3):

- **The launcher** sets `MANDU_REPLY_TAB_ORIGIN=content` in the reply
  filter's own environment for the `claude` target (`replyTabOriginEnv`),
  in the serial form and in the hand-off. The filter removes it from its
  child's environment (`childEnv`), and the SDK route does not force it.
- **The filter** reads it (`tabOrigin`), reports `tabs: "content"` with
  `reserve` in `setSessionRelay`, and stamps it on every head it records
  (`ReserveValueCache`), so `blockIndent` returns 0; the writers read
  `spliceTabOrigin` for a spliced value (`frameSafeValue`'s `origin`).
- **The arbiter** stores `tabs` with the relay state and returns it from
  `sessionRelay`; it refuses any value other than `screen` or `content`.
  `symbolShape` is unchanged: it counts with the `indent` it is sent.
- **Both proxies** read `tabs` with the relay and send `indent` 0 under
  `content` (`cols − W` otherwise). Codex never reports it; the
  openai-proxy honors it so a filter and its proxy never count apart.

**Security.** No original moves anywhere new. `tabs` is one more field on a
human-plane op the filter sends; the agent can neither set it (the
launcher sets the filter's environment, the filter strips it from the
child's) nor read it. It changes a count only for a value that holds a
TAB, as `indent` did.

**Residuals.** A value spliced into a row inside a list item, a table cell
or a code block counts from column 2, not from that text's own left edge,
which the filter does not know there (a reserved block knows it from `W`).
A future Claude Code that hands its TABs back to the terminal would show as
a red `fidelity-echo-tabs` again.

**Tests.** Unit: `reserve-block.test.ts` (`tabOrigin`, the relay report,
the capture's rows under `content` and under `screen`, a list item, a
mid-line head, the cache's stamp), `filter.test.ts` (`frameSafeValue`'s
origin; the eager splice under `content`), `screen-reconcile.test.ts` (an
alternate-screen repaint under `content`), `human-plane-env.test.ts`
(`childEnv`), `session-relay.test.ts` (`tabs` stored, refused, human plane
only), both proxies' `sse-reserve-expand.test.ts` (indent 0 under
`content`, at a list item and mid-line; the eligibility forwards `tabs`),
the launcher's `reply-filter.test.ts` (`claude` only). Integration:
`proxy-real-client-parity.test.ts` carries `tabs` over the production
wiring. Stack e2e: `reply-row-reservation.test.ts` runs the TSV under
`content` against Claude Code's own rendering (and keeps the `screen` case
against the terminal's). The differential drill `fidelity-echo-tabs` gates
the real Claude Code TUI per push (inline and fullscreen lanes, both
sizes, and the real-config lane) and the real Codex TUI nightly. A live run
on the subscription sign-in then matched vanilla on both renderers, and the
launcher without the fix showed the divergence (differential-interactive.md
§19.2).
