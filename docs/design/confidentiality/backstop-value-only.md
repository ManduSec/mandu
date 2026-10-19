# The value backstop's value-only release

Decision note, 2026-10-17. Status: built. Amends the verbatim-value backstop
of [plan 10 §2.2](./confidentiality-plan-10-flow-taint.md) and its notes in
[`confidentiality.md`](./confidentiality.md) §4 and §7.1.

## 1. The problem

The value backstop (the arbiter's `classify`, `arbiter/ipc/server.ts`)
looks for every registered secret value in each tool result that the path
rules call public. When it finds one, it raises the whole result to the
secret's level, and the model proxy masks the whole result as one symbol.
That catches the common accident: an app that echoes its credential, a
`set -x` trace, a debug dump, a labelled file committed to git and read back
through `git show`.

It also hides everything around the secret. A scripted probe of the reworked
401 demo showed the cost. The agent reads yesterday's application log,
`shop-app/logs/payments-2026-10-16.log`. The app's debug lines printed the
labelled `.env`'s Stripe key on two runs, so `cat`, `grep` and Read of the
log each reached the model as one `$MDU:nomodel_*` symbol. The model could
not read the log at all, so it could not do the task it was asked: find out
from the log what broke. Claude Code's own credential mask leaves the same
log alone and hands the model the key raw. So the demo could show that
Mandu keeps the key from the model, but not that the model can still do
the job.

## 2. The rule

When the value backstop raises a result, the arbiter also tries a narrower
release and offers it beside the raise. Each occurrence of a registered
single-line value is replaced by that value's own symbol: the field symbol
the model already sees in the `.env`'s twin, which the net-proxy puts back
at the value's bound host. Every other byte of the result stays as it is.
The arbiter makes the offer only if it can prove the released text clean.
The proxy takes it only if the call's own evidence shows no secret read.
In every other case the result is masked whole, as before.

**The arbiter's rules** (`valueOnlyOffer` in `arbiter/ipc/server.ts`, and the
pure `planValueOnly` and `ResidueScanner` in
`arbiter/policy/value-only-release.ts`). No offer, so the result is masked
whole, unless every rule holds:

- **A1.** The backstop's existing conditions hold. The confidentiality axis
  is on, the policy verdict is public (so the result is not path-derived:
  the call names no secret path), and the tool is not one of Mandu's
  quarantine or policy tools. The tool is also one whose result is a file
  read or a command's output (`VALUE_ONLY_TOOLS`: Claude Code's `Read` and
  `Bash`, Codex's `exec_command`, `shell` and `local_shell`, the other
  agents' `read`, `view`, `bash` and `exec`). An agent's or subagent's
  answer, an MCP tool, a fetch and a background poll are masked whole as
  before (the CI run of the first build found a moved OpenCode subagent's
  answer released value by value: a model's answer is no tool's output).
- **A2.** The result is at most 256 KiB (`VALUE_ONLY_MAX_CHARS`).
- **A3.** The result holds no `$MDU` text in any case. A forged or relayed
  token never rides in a release.
- **A4.** Every occurrence the backstop counts must be one of two kinds:
  - a whole-value occurrence of a row whose value is a single line (no CR,
    LF, U+2028 or U+2029), at least 12 characters long
    (`VALUE_ONLY_MIN_LEN`), with entropy of at least 3.0 bits per character;
  - a piece occurrence (a long line of a multi-line secret, a credential
    span, a bare token of a registered file) lying inside a replaced
    whole-value span.

  So a multi-line value (a document's long line, a whole file printed raw)
  is refused, and so is a short or low-entropy value. A copy of a
  registered file is refused too, because its long lines are pieces of its
  row that no field value covers. Each occurrence must locate its row's
  value exactly (`text.slice(start, end) === value`).
- **A5.** Two rows may hold the same span as their whole value. That span
  takes the strictest of those rows' symbols, then the first row in the
  symbol map's order. Different spans that overlap are refused. A piece of
  a stricter row inside a replaced span is refused too: the span's symbol
  would stand at a lower level than that row. A value glued to text the
  symbol's grammar would run on over (a letter, a digit, `_`, a bracket,
  or a dot followed by one of those, as in `KEY.json`) is refused, so that
  the symbol keeps naming the value. A session holding a row whose pieces
  were cut at the bound (plan 10 §11.18) gets no offer at all: a piece past
  the bound is matched by nothing.
- **A6.** The planned text is verified on what would actually be released:
  - **(a)** the backstop's own scan (`secretValueHits`) finds nothing in the
    text with the symbols in place;
  - **(b)** the residue scan finds nothing in the original text with each
    replaced span cut out (a NUL in its place).

  The residue scan covers every active secret row whose value is one line of
  8 or more characters, except a row whose value holds a symbol token (a
  twin's piece) or is a vetted config's own text. Exec-output rows are
  included even without the call-tree evidence the backstop asks for. It
  looks for each row's value in each of these forms:
  - verbatim;
  - base64 at each of the three byte alignments, standard and URL-safe;
  - hex, lower and upper case;
  - percent-encoded, with lower and upper case hex digits;
  - JSON-escaped;
  - reversed;
  - rot13;
  - octal, three digits a byte (`od -b`, octal escapes);
  - spread: its letters and digits in order, with only other characters
    (no letter or digit) between them, case folded, forwards or reversed;
  - any 8-character fragment, case folded: a prefix (past the value's public
    format prefix, such as `sk_test_`, which only names the kind of key), a
    suffix or a chunk; and any 8-byte fragment of its hex. Fragments and the
    spread form are looked for in the values this release replaces, and in
    every other row that reads as a credential (`looksLikeSecretValue`) and
    is no command's whole output. An ordinary row (a one-line output masked
    earlier, a host name or an e-mail address a `.env` field holds) is
    looked for whole in every form, but its words are no fragment.

  Each check reads several views of the text:
  - the text as it is;
  - the text with every blank and line break taken out, which catches an
    encoding wrapped at a fixed width (`base64` at 76 columns, `openssl
    base64` at 64, `xxd -p` at 60) or a value spaced out;
  - that view with literal `\n`, `\r` and `\t` escapes taken out, for a
    value wrapped inside a JSON or C string;
  - a hex dump's hex column and its ASCII column, each joined across its
    lines (`dumpColumns`), so a value split across two rows of `xxd` or
    `hexdump -C` is whole again;
  - a byte dump's skeleton (`dumpSkeleton`): each line's leading offset or
    line-number column dropped (`od`, `hexdump`, `xxd`, `cat -n`, `grep -n`,
    a Read's gutter with a tab, `:` or `→`), the `\x`, `0x` and `\u00` of hex escapes and the backslash of
    octal ones dropped, and every blank, comma, colon and bar dropped. So
    `od -c`, `od -tx1`, `od -b`, `xxd -i`, `printf '\x..'`, `aa:bb` hex and
    a numbered fold come out as the value, its hex, its octal or its `od -c`
    form (printable bytes as themselves, the others as octal), unbroken.

  Hex and octal are matched in any mix of cases. Every view is read twice: as it
  is, and folded (NFKC, which maps full-width and other compatibility
  letters to plain ones, with every format character removed, the
  zero-width ones included). A copy written in look-alike or padded
  characters is the same copy. The scan is deliberately stricter than the
  backstop. It reads exec-output rows whatever their tree held, where the
  backstop counts such a row only with that evidence, so a stale row can
  refuse a release but never allow one.
- **A7.** Any error while planning or scanning means no offer.

**The proxies' rules** (`acceptValueOnlyOffer` and `valueOnlyEvidenceClean`,
byte-identical in `interceptors/anthropic-proxy/src/rewrite-request.ts` and
`interceptors/openai-proxy/src/rewrite-request.ts`). The offer is taken only
when all of these hold:

- **P1.** The classify verdict is the backstop's raise (`raisedBy:
  "value-backstop"`), and this proxy raised the level no further.
- **P2.** The call's own evidence is clean:
  - no taint answer masks the call, and its taint level is not secret;
  - the tree read no file, not even through a listed reader's release
    (rule ii/iii);
  - no open was refused, no twin was served or matched (`twinOf`), no
    connection was refused and no command was blocked in the tree;
  - the agent received nothing from a secret holder during the call (plan
    13 §4.5.1; that leg is built in the Claude proxy only, so for Codex
    the rule rests on the call's taint answer and the residue scan), and
    no harness mask applies;
  - the result has no non-text block (the openai-proxy: the output is a
    string or text parts only), and the integrity axis does not distrust
    it;
  - for Codex, the result is not an unparsed user shell record;
  - the result was not forwarded in clear in an earlier request ("masked
    after the fact" keeps the whole mask and its note).

  A Read has no process tree, so its taint is null. That counts as clean:
  for a Read, the path rule's public verdict is the evidence.
- **P3.** The offer is rebuilt from the proxy's own copy of the result:
  - the spans are integers, sorted, disjoint, in bounds and non-empty;
  - each symbol is one whole `$MDU` token;
  - the text rebuilt from the proxy's own copy equals the offered text;
  - no replaced value still occurs in the rebuilt text.

The released result gets no `[mandu:secret]` note, since it is not masked.
Each replaced value gets a `symbolize` event (the value is the event's
HumanView original, as with any symbolized result). The values are the §9
oracle's must-not-survive spans for that result; the rest of it survives by
design. An older proxy, or another classify consumer, does not know the
offer and masks the result whole: the default is the old behaviour.

## 3. Why the invariant holds

The model receives two things:

- **(i)** text that the path rules call public and that came from a call
  whose own evidence shows no secret read;
- **(ii)** in place of every occurrence of a registered value, that value's
  own symbol.

After the replacement, no registered single-line value is in the text in
any form the arbiter knows how to detect. The text also holds no long line
or piece of any registered secret that the backstop matches. Before this
change, the same result was masked whole only because of the verbatim hit.
A public result with no hit was never masked, even if it held an encoded
copy or a fragment of a secret. So the release gives the model no more than
any public result already gives it. Because a verbatim hit is evidence that
something printed the secret, the release is also checked more strictly
than a public result is: encoded copies, spread copies and fragments of
every registered value are looked for and refused.

The symbol is the value's own symbol, so every gate keyed on it stays in
force: the per-symbol egress decision, the bound-host release, the session
watermark. A model that puts the symbol in a request to the value's bound
host has it put back there (the 401 demo's fixed request). Sent anywhere
else, the request is gated like any other use of the secret.

## 4. What this widens

The cases below were masked by coincidence before (a verbatim hit in the
same result masked everything else in it), and now ride along with the
release, as they ride in any public result:

1. A secret Mandu does not know as a registered value (unlabelled,
   unregistered, or a field the extractor did not find) that sits in the
   same text.
2. Pieces of a multi-line secret below the line floor (24 characters), and
   fragments of one. The residue scan covers single-line values only,
   because 8-character fragments of every line of every labelled document
   would refuse almost any prose.
3. Transforms the residue scan does not know: a hash, compressed text, a
   custom cipher, base64 of a fragment, base32, base85, uuencode, UTF-16, a
   dump in byte-swapped words (`hexdump` without `-C`, `od -x`), a
   fragment shorter than 8 characters, a value interleaved with letters or
   digits (the spread form allows only other characters between). The
   same is true of every encoded copy of a piece of a multi-line secret:
   its long lines and bare tokens are matched verbatim only (A4, A6a),
   since the residue scan reads single-line rows. A value holding a
   backslash, JSON-escaped and then wrapped with literal `\n` escapes that
   cut an escape pair, is not read back. Fragments of a row that
   does not read as a credential, and that this release does not replace,
   are not looked for either (A6b).
4. The value's place and length. The model learns that a secret value stood
   at that position (`Bearer <symbol>`), as a structured twin already
   shows.
5. Anything in the surrounding text from which the value can be derived
   (a log line that prints the key's checksum or its last four characters
   next to it). The mask was the only thing that hid these, and only
   because the key was in the same result.
6. A released result is not recorded as forwarded in clear. If a later
   request masks the same result whole (a new row, a refused offer), it
   gets no "masked after the fact" note, though the model has read most of
   it. That loses a note, not a secret.

## 5. Tests

- Arbiter `test/unit/value-only-release.test.ts`: the plan and the residue
  scan, one test per fail-closed case (too long, `$MDU` in any case, no
  whole value, multi-line, short, low-entropy, not located exactly, out of
  bounds, a row that is gone, overlapping values, a piece outside every
  span), the tie-break, and every form the residue scan knows (base64 at
  three alignments and inside a larger stream, URL-safe, hex both cases,
  percent-encoded both cases, JSON-escaped, reversed, rot13, spread across
  lines, spaced, case changed, reversed and spread, 8-character prefix,
  suffix and chunk in any case; 7 characters pass).
- Arbiter `test/component/value-only-offer.test.ts`: the classify op over a
  real server offers the release for the old log, and makes no offer with
  the axis off, for a path-derived result, a quarantine tool, another
  registered value's encoded copy or fragment beside the hit, a labelled
  document's line, or a row cut at the piece bound; an earlier one-line
  output sharing a word with the log refuses nothing. The unit tests also
  cover each review round's forms (§6).
- Both proxies' `test/unit/value-only-release.test.ts`: the offer is
  checked and rebuilt, and refused on every malformed shape. The evidence
  rule is tested case by case. A clean `cat` and a Read are released.
  These are masked whole: a tainted tree, a listed reader's release, a
  refused open, no offer, a malformed offer, a path-rule level, a result
  forwarded in clear before, an integrity-distrusted result, a non-text
  block.
- `tests/stack/value-only-release.test.ts`, the e2e oracle over the real
  arbiter and the production adapter:
  - a `cat` and a Read of the old log come back with the key as the
    `.env`'s own field symbol;
  - these are masked whole: the log carrying the key base64'd, a 12-character
    prefix, a `$MDU` token, a call whose tree read a labelled file through
    a listed reader, and a `cat` of the `.env` itself;
  - no request to the model carries the key verbatim, base64'd at any
    alignment, as hex, reversed, rot13 or as any 8-character piece;
  - a recorded HTTP test fixture (2026-10-18, the stale-fixture demo):
    a Read of a nock-style recording whose sign-in body holds a labelled
    `.env`'s ordinary password comes back with the password as its field
    symbol and the JSON as it is; a diff of it beside the re-recording's
    placeholder is masked whole (A3); no form of the password reaches the
    model.

## 6. Review rounds

Adversarial reviews (a reviewer told to find any way a registered value, or
a recoverable piece of one, reaches the model through the new path), in
order:

- **Round 1** (a review of the note, `value-only-release.ts` and the
  arbiter's classify handler; it stopped before the proxies). It found no
  leak, and asked four questions:
  1. The residue scan did not fold Unicode, and it matched hex in two
     cases only. Fixed: the folded second pass, and hex matched in any
     case. Tests: full-width, zero-width inside, mixed-case hex.
  2. Exec-output rows are counted differently by the backstop and by the
     residue scan. This is intended (stricter) and is now stated in A6.
  3. The scanner is cached by its values. A row whose level falls to
     public, or that is obsoleted, leaves the indexable set, so the key
     changes and the scanner is rebuilt.
  4. Both scans read one table state: the classify handler is
     synchronous.
- **Round 2** (an audit of the proxies' P1-P3 against this note, the plan
  and the scan, with probes over a real arbiter). It confirmed P1 and P3
  and the checks in A2-A5, and found:
  1. **A leak, high.** base64 or hex of a long key, wrapped at a fixed
     width (`base64`, `openssl`, `xxd -p`), got through: the forms were
     matched only unbroken. Fixed: every encoded form is also matched with
     blanks and line breaks removed. Tests: widths 76, 64 and 60, CRLF, and
     in the e2e.
  2. **A leak, medium.** The openai-proxy released a non-text output (an
     image part beside the text, flattened to JSON) with only the key
     replaced. Fixed: only a string or text-only output is released.
     Test added.
  3. P2 named the agent-receipt check for both proxies; the openai-proxy has
     no such leg. The note now says so.
  4. "No twin was served" was never true on this path (`twinOnly` is set
     only with a clean backstop). Fixed: a call whose result matched a
     twin (`twinOf`) is refused.
  5. A5's tie-break looked at whole values only. Fixed: a stricter row's
     piece inside a span refuses.
  6. Rows cut at the piece bound were not considered. Fixed: no offer while
     one exists. A value glued to text the symbol would absorb broke its
     resolution. Fixed: refused. The missing after-the-fact note is now
     §4 item 6. Smaller fixes: the residue cache key is the JSON of its
     values (a NUL inside a value was ambiguous).
  7. Gaps in the tests, closed: arbiter `test/component/value-only-offer.test.ts`
     (classify over a real server: offered; not offered with the axis
     off, for a path-derived result, a quarantine tool, another value's
     encoded copy or fragment, a document's line), and more proxy cases
     (agent receipt, a matched twin, a refused connection; for the
     openai-proxy a listed reader, a refused open, a path-rule level,
     integrity distrust, after the fact, a non-text output).
- **Round 3** (the round-2 fixes, the proxies' other result paths, and the
  common re-encodings a shell prints). It found the offer and its use race-free
  and no path that forwards an offered text without the P2 checks (the
  OpenAI shadow route, split tails, Codex MCP results,
  `custom_tool_call_output` and user-shell records included), and the A5
  refusals correct. It found:
  1. **A leak, high.** Byte dumps of the key beside a verbatim copy got
     through: `od -c` (spaced characters with octal offsets), `od -tx1`,
     `od -b`, `xxd -i`, `\x` and octal escapes, `aa:bb` hex, a numbered
     fold (`fold -w 4 | cat -n`), and wrapped base64 inside a JSON string.
     The fragment check did not read the squeezed text, and offsets or line
     numbers broke the spread form. Fixed: the escape-free and dump-skeleton
     views, the octal form, and 8-byte hex fragments, with a test for each.
     A6's "anything between them" was wrong. It now says only characters
     that are neither letters nor digits, and §4 item 3 lists the forms
     still not looked for.
  2. The e2e oracle only looked for forms the scanner already knew, so it
     could not find a gap. Fixed: the e2e also feeds an `od -c` dump and
     asserts the whole mask.
  3. The refusal while a row is cut at the piece bound had no test. Added
     (component, a bound of one piece).
  4. Encoded copies of a multi-line row's pieces were not stated as a
     limitation. Now in §4 item 3.
- **Round 4** (the residue scan's claimed forms against real dump tools, and
  false positives on ordinary logs). It confirmed each round-3 fix by
  taking it out (each one's test then fails), and found the claimed forms
  caught for values holding `:`, `,`, `|`, blanks or backslashes. It found:
  1. A value of 12 to 14 bytes split across two rows of `xxd` or
     `hexdump -C` (each row's hex interleaved with its ASCII column), and
     any value under `xxd -c` narrower than 8, got through. Fixed: the hex
     and ASCII column views.
  2. Gutters other than a tab (`→`, `:`, `grep -n`) were not stripped.
     Fixed.
  3. `od -c` of a value with non-ASCII bytes (printed as octal among
     characters) got through. Fixed: the `od -c` form.
  4. Taking out literal `\n` escapes also ate the `n` of an escaped
     backslash. Fixed.
  5. False positives: every single-line row was looked for in fragments,
     so an earlier one-line output (`payments: connected to Stripe`) or a
     field such as `noreply@shop.example.com` refused any log sharing a
     word with it. Fixed: fragments and spread only for credential-like
     rows and the values replaced (component test).
  6. False positive: `sk_test_` is an 8-character fragment of every Stripe
     test key, so Stripe's own `Invalid API Key provided: sk_test_****1828`
     refused the release. Fixed: no fragment wholly inside a public format
     prefix.
- **Round 5** (a verification of the round-4 fixes with round 4's own
  probes, over the scanner and a real arbiter). Every round-4 finding is
  fixed, with no regression and no new path for a registered value or a
  piece of one. The narrowing of fragment checks lets nothing through that
  a public result did not already carry: the replaced values and
  credential-like rows are still checked in fragments, and a labelled file
  read raw is registered under `Read`, not as a command's output. Left:
  1. `xxd -g5` to `-g8` (groups wider than 8 hex digits) dropped a row
     from the column views. Fixed: groups of up to 16 hex digits.
  2. `od -c` prints a tab, a line feed or a carriage return inside a value
     as an escape, which the skeleton takes out, while the `od -c` form
     wrote it as octal. Fixed: the form leaves those bytes out too.
  3. Text that was JSON-escaped and then wrapped with literal `\n` escapes
     at a width that cuts an escape pair in two cannot be read back by one
     pass. This affects only values holding a backslash, and is now §4
     item 3's.
  4. The column views and the `od -c` form are asserted on their helpers
     (`dumpColumns`, `odCharForm`), not through `find`. Taking them out of
     `find` fails no test. This is open: a test that feeds `find` a dump
     row pair is the follow-up.
  This round found nothing that lets a registered value reach the model
  beyond what §4 lists, so the reviews stop here.

## 7. Log

- 2026-10-17: built (this note). Prompted by the reworked 401 demo
  (demo-c5), where the whole-result mask hid an old log the model had to
  read.
- 2026-10-18: the stale-fixture demo (demo-c10) relies on it as built: its
  test recording's sign-in body holds the `.env`'s password, released
  value by value on Read and on Codex's shell read in the replays; the e2e
  gained that shape (§5). No rule changed.
