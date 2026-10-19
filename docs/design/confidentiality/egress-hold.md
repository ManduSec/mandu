# A held request — the egress proxy waits for the human's answer

Built 2026-10-17. Detail of [`confidentiality.md`](confidentiality.md) §4
("Send without it", "A held request"). Mandu-new (no reference origin).

Without a hold, the request that files an Approvals card is refused at
once and the answer decides the next try, so a task such as "open an
issue with the full error" takes two beats: the refusal, then the human
asking the agent to send again. With a hold (`MANDU_EGRESS_HOLD_MS`, read
by `interceptors/net-proxy/src/server-main.ts`; capped at 300 000 ms; the
launcher sets it for the proxy it starts, 60 s in an interactive session
and 0 elsewhere, see "The default" below; a proxy started without the
launcher defaults to 0, off) the net-proxy keeps the client waiting while the card is open and the
answer decides THAT request: *Send without it* sends it with the marker
(every encoding the spine lists, the strict value scan after it), *Allow
once* / *Always allow* resolve as for the next try, *Block* refuses. The
agent's command simply finishes. The mechanics (`egress.ts`
`holdForAnswer`, on the plain and the TLS-inspected legs):

- *What is held.* Only a block whose every withheld symbol is a whole
  `$MDU:` placeholder with a pending card (`requiresApproval` and the
  row's id: `awaitsAnswer`). A denial, an arbiter miss (no row), a failed
  resolve, a shell-emptied placeholder and every content-agnostic block (a
  program holding a secret, an unattributed connection, a HIGH session's
  request, the frozen taint gate) are refused at once as before; a
  placeholder in the destination host waits for its card like any other
  and is then refused, as the spine says. The legs before the per-symbol
  gate run once, at the request's arrival.
- *How it waits.* Every 500 ms it reads the queue (`awaitingApprovals`, the
  `egressApprovals` listing on the data socket: names and statuses only)
  and asks the per-symbol gate again only once a held card is no longer
  waiting, so the row's count is not bumped per poll; the decision is
  always the re-ask's, and a failed read just asks. An answer the request
  already got (an allow with its value, a Send without it) is kept for
  the rest of its hold and not asked for again, so a once is spent once.
  The TLS leg turns its keep-alive idle timeout off while it holds. One
  card may stand for several placeholders (a registered file's, "One card
  per file" below): the queue is read for each card once, and every ask of
  the request carries the request's one id.
- *Fail-closed.* The deadline passing refuses the request (403, the reason
  ends `egress:held-unanswered`, "nobody answered … answer it, then send
  the request again"); the card is left waiting and decides the next try.
  The arbiter gone mid-hold: the re-ask throws and the request is refused.
  The client gone (its socket closed): refused, nothing sent, even when
  the answer came. An answer spent by a request that is then refused for
  another symbol is lost, as before.
- *What it does not widen.* Holding releases nothing: every outcome is the
  one the same request, sent again after the answer, gets without a hold,
  through the same gate, the same marker substitution and the same strict
  scan. What it changes is who sends: the request the agent made, not a
  retry the agent chose to make. Where it is on (an interactive session,
  below) every unanswered card keeps the agent's command waiting up to the
  hold, as the guard's held open does (plan 10 §12.2). A request is held at
  most the hold, so keep it below the agent's own command limit (Claude
  Code's Bash tool: 120 s; the interactive default is 60 s). One window
  grows with it: a placeholder of the request allowed at its first ask
  stays allowed for that request while another one waits, so a binding
  removed during the hold does not retract it (the same window any request
  has between its decision and its send, now up to the hold long).
- *Not held.* A WebFetch (the model proxy's own pre-check refuses at once,
  as before) and a blind tunnel (no per-symbol gate there).
- *The trace.* The `forwarded` / `blocked` event of a held request carries
  `heldMs`, and `heldFor`: the cards it waited on, each with the rule that
  filed it (`[{ approvalId: "egr-1", rule: "egress:secret-unbound" }]`,
  `egress.ts` `heldForEvent`; ids and rule ids, never a value, and never in
  the agent's 403 body). A held request emits one event, the answer's, so
  its decision names only the human's verdict (`verdict:egr-1`); without
  `heldFor` the trace lost which rule had asked the human, which is what
  tells an unbound host (`egress:secret-unbound`) from a bound host's
  one-time approval (`egress:secret-bound-approval`). Added 2026-10-19,
  when a drill graded the human's Block of a held upload as "blocked by
  the wrong rule".

*Pinned by* `interceptors/net-proxy/test/unit/egress-hold.test.ts` (the
setting; which blocks are held; held then Send without it in a JSON body,
the URL, a form body, a header and a Basic pair; held then Allow once and
Block, the trace keeping the card and its rule; the deadline; the arbiter and the client gone; an answer kept
across the hold; the queue read pacing the asks), case (11) of
`interceptors/net-proxy/test/component/mitm.test.ts` (the TLS leg: held,
answered, the marker on the wire, `heldFor` on both events; nobody answering refuses) and e2e
`tests/stack/egress-hold-send-without.test.ts` (a real arbiter, the
net-proxy in its production wiring with a hold, the dashboard adapter
answering while the request waits, a recording sink: the same request on
the wire with the marker and without the value or the placeholder, the
row asked once; nobody answering, Block, and the arbiter gone each refuse
with nothing sent, and the Block's refusal names the verdict and keeps the card the rule filed). Drill demo-c8 (`demo-public-issue`) sets a 60 s hold
in its `env` and is one prompt; so does demo-c11
(`demo-env-to-production`, 2026-10-18), whose held requests are answered
*Always allow*: each goes out with the real value filled into its JSON
body, and its `forwarded` event carries `heldMs`. Demo-c17
(`demo-inbox-you-decide`, the dashboard video, 2026-10-18) holds both
uploads: *Allow once* lets the accountant's through, *Block* refuses the
share's (a `blocked` event with `heldMs` and `human-denied`, no approval
row); the drill grader counts either as a card the human was asked
(`approvalCardsFor`).

## One card per file (2026-10-19)

**The case.** Demo-c17 on a fresh install (`secrets-defaults`, takes m1r2
and m1r3 of the 2026-10-19 battery): the bank statement is a personal
document (secret-discovery.md §2.7) whose twin keeps each line's label and
makes each value a placeholder, so `curl --data-binary
@bank/statement-2026-09.md https://parktax.test/…` sent seven
placeholders. Each asked on its own card: seven cards for parktax.test at
once, a flood no person answers field by field. The human answered every
one *Allow once* and the request was still refused, for a second reason
(the tripwire below).

**The rule.** A request carrying two or more placeholders of one registered
file (field rows of the registry: `$MDU:…[h].KEY`, `isRegisteredFileRow`)
that the gate would ask about asks about them as their FILE: the card's
subject is the file's base symbol (`$MDU:…[h]`, the same registration,
active, same origin; `approvalGroupOf` in `arbiter/ipc/server.ts`), keyed
with the host as every card is. The net-proxy sends every placeholder the
request carries on each ask (`requestSymbols`, at most 512), and the arbiter
files the file's card when another of them is the same file's
(`fileSharesRequest`): ONE card (each ask bumps its count), and the human's
answer decides all of them. A lone placeholder of the file keeps its own
card, which names its key (`STRIPE_KEY` to `api.stripe.com`), as before; a
caller that sends no list (the model proxy's pre-check, the Rust
net-supervisor, the DevTools relay) files per placeholder as before. A
different file is a different card, a different host too, and a
re-registration (a changed file, a new hash) asks afresh. Anything else (a
masked output, a page, an environment variable, a whole-file twin's base
symbol) keeps its own card. The card names the file (`source.origin`, the
read-time provenance), offers *Send without it* (the base row is a secret
symbol), and its *Always allow* stands for the file at that host, a later
lone placeholder of it included.

**One spelling, one card.** An egress card about a placeholder is keyed by
the token without a sentence's trailing period when that names a row
(`cardKeyOf`): the net-proxy's scanner keeps such a period in a token
(`$MDU:…[h].extract_7.`, MR !2136), which the gate's lookup trims, so `X.`
and `X` asked on two cards before. Two spellings of one placeholder in a
request are one placeholder, never "two of the file's". A field path the
table holds no row for keeps its spelling (its card names that key). An
answer filed under a raw spelling before this change is still read.

**What the card says.** The arbiter attaches `fileValues` (the file's
active field rows, two or more) to a file's card at read time; the card
reads "The agent wants to send the secrets in `~/…/statement-2026-09.md`
to `parktax.test`" and "One answer covers all 7 of them." (`describeAsk`,
`dashboard/src/view-model/ask-words.ts`). A lone placeholder's card still
names its key.

**Where the file's answer is read.** Only after the gate itself asks: the
placeholder's own standing answer (an older card about it) is consulted
first, then the lockdown, the user's rules, the built-in law; the file's
answer only where that law says requires-approval. So it never releases a
placeholder the gate refuses outright (a wire credential outside its
header, plain HTTP for an https-only one), and it decides nothing the
placeholder's own card did not already ask. The tester (`testFlow`) reads it
the same way, without spending it.

**A once is spent by the request.** The net-proxy gives each request one id
(`gateRequest`, a random UUID) and sends it on every ask of that request,
its held re-asks included (`requestId` on `desymbolizationDecision`). The
first ask that finds the file's *Allow once* spends it, as before
(`consumeOnce`), and the arbiter remembers which request did
(`onceSpentBy`, in memory, bounded, at most six minutes: the longest hold
and a minute); the same request's other asks read the spent answer as
answering, any other request finds it spent, and the card asks again. A
*Send without it* is spent the same way (each placeholder gets the
marker), and *Block* refuses every placeholder of the file. An ask with no
id (an older net-proxy, the Rust net-supervisor, the DevTools relay) spends
the once on its first ask, as before: the next placeholder then asks again
(fail-closed, never wider). Only an attested channel spends anything; the
data socket reads an *Allow once* as no answer.

**What it keeps.** Nothing leaves without the human's answer for that file
and host: a request carrying two files waits on both cards, and one answered
alone leaves it held, then refused at the deadline with nothing sent (the
answer it spent is lost, as for any refused request). An answer for one
file never releases another's placeholders. A once never reaches a second
request. A restart mid-request forgets which request spent it: the next ask
finds it spent and the card asks again.

**The tripwire half.** With every placeholder allowed, the request was
refused by the egress tripwire ("there is nothing to approve for it"): the
model had read the statement in one command with other files (`cat
bank/statement-2026-09.md; cat contacts.md`), the guard served the twin,
the path rule masked the whole output as a new row, and each long line of
that row, the twin's own `Account: $MDU:…` lines included, was a
fingerprint. The upload carried those lines. Now a line of a registered
file's twin, holding none of that file's secret texts, is no piece of an
output row whose value carries that file's placeholders
(confidentiality.md §4, "A twin line is no piece of an output that prints
it").

*Pinned by* `arbiter/test/component/egress-one-card-per-file.test.ts` (one
card for a document's placeholders; Allow once covers that request only;
Block, another file and another host; no request id; the data socket; an
Always for the file; a lone placeholder's own card, its trailing-period
spelling, the file's answer covering it and its own Block winning),
`arbiter/test/component/test-flow-remembered-answer.test.ts` (the tester
reads the file's answer), `arbiter/test/component/document-twin-output-tripwire.test.ts`
(the batched read's row no longer trips on the twin; every raw value and
the output's other lines still do), the request id in
`interceptors/net-proxy/test/unit/egress-hold.test.ts`, the card's words in
`dashboard/test/unit/view-model/file-card-asks.test.ts`, and e2e
`tests/stack/egress-one-card-per-file.test.ts` (a real arbiter with the
content tier's statement and house codes, the net-proxy in its production
wiring with a hold, the dashboard adapter, a recording sink: after the
masked batched read, the statement's upload holds on ONE card and Allow
once sends the statement as it is on disk; the same upload again holds on
the same card and, unanswered, sends nothing; two files are two cards and
one answer sends nothing; Block sends nothing; another host is another
card).

## The default (2026-10-17)

The maintainer's decision: the hold is **on (60 s) when a person is
likely watching**, an interactive session, and **off for runs nobody
watches**: headless and print-mode invocations and CI. Holding helps only
when someone is there to answer; in an unattended run every unanswered
card would keep the agent's command waiting for nothing, and the refusal
it ends in is the one it got at once before. An explicit value always
wins.

The launcher decides once per launch (`launcher/src/egress-hold.ts`
`launcherEgressHold`, called by `run.ts` before the services start, kept
on the plan as `egressHold`) and hands the proxy it starts the answer in
`MANDU_EGRESS_HOLD_MS`, always set, so an ambient value it did not choose
never reaches the proxy. In order:

1. `MANDU_EGRESS_HOLD_MS` set and not blank (config `egress-hold-ms`):
   that value, as is; `0` is off. The proxy parses and caps it (a value
   it cannot read is 0).
2. CI (`CI` set to anything but an off word; the update check's own test,
   `update-check.ts runsInCi`): 0.
3. The launcher's stdout is not a terminal (piped, captured, an editor's
   ACP stream): 0.
4. A known one-shot: `claude -p` / `--print`, `codex exec`, `openclaw
   agent`, `opencode run`: 0.
5. Otherwise, an interactive session on a terminal: 60 000 ms, below
   Claude Code's 120 s Bash limit.

Steps 3 and 4 are the reply filter's own notion of an interactive run
(`interceptors/reply-filter/src/print-mode.ts decideMode`: stdout a
terminal and not a known print-mode invocation → the PTY relay), copied as
a pure function and pinned equal by a test, so a session holds exactly
when its reply is relayed as a live TUI. The same limits carry over:
`goose run` and a flag before the subcommand (`codex -m o3 exec`) read as
interactive, which costs at most a minute's wait on a terminal where a
person sits.

The net-proxy's own default stays 0: a proxy started without the launcher
(`npm run serve`, a test's in-process `NetProxy`) never holds. A proxy
adopted on a pinned port keeps the hold it was started with; the hold is
not part of the reuse key (`netProxyIdentityMatches`), since it changes
how long a refusal takes, never what is sent. The net-proxy's LIVE line
says when it holds and why.

*Tests and drills.* The test harnesses state the hold rather than inherit
it. A harness that runs the launcher on a pipe gets 0 by rule 3; the
launcher-live stack (`tests/lib/launcher-live.ts launcherEnv`, which the
PTY-driven suites, the differential lane and the replay drills use) sets
0 explicitly, since a PTY reads as interactive. The drill suite's live
runner starts every tmux pane (a terminal) with 0 too, under the drill's
own `env`; only a drill that wants the hold sets it (demo-c8, 60 s), and
the replay runner applies a drill's env over the stack's.

*Pinned by* `launcher/test/unit/egress-hold.test.ts` (the five rules, the
explicit value over each, the one-shot list equal to the reply filter's,
the cap and the variable equal to the proxy's, CI the update check's
test, the config key, `startNetProxy` always setting the plan's answer)
and e2e `tests/stack/egress-hold-launcher-default.test.ts` (a real
arbiter and the real net-proxy started by `startNetProxy`: the
interactive decision holds a request until the card is answered Send
without it, and that request reaches the sink with the marker;
`claude -p`, a pipe and an explicit 0 are each refused at once, nothing
sent, the card left waiting).
