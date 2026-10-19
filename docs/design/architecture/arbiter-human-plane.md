# The arbiter's human plane: a third channel for the ops that return originals

> **Status: decision note, BUILT (2026-09-30), extended 2026-10-03.** Code:
> `arbiter/ipc/server.ts` (`HUMAN_PLANE_OPS`, `channelRefusal`,
> `attachHumanChannel`), `arbiter/ipc/instance.ts` (`humanSockPath`,
> `ensurePrivateDir`, `resolveArbiterHumanSock`), the launcher's walls (§6)
> and the consumers (§5). Related: `policy-surface.md` §2.6 (the
> admin channel this extends), `confidentiality.md` §7.2 (Mandu's own stores
> of originals), [`runtime-instances.md`](./runtime-instances.md) §2 (where
> the socket lives). Beyond the ops that return originals (§1–§9): the
> guard's process records and the model proxies' records of a tool call are
> believed only on this channel and are claims from the data socket (§10,
> confidentiality-plan-13 §3 D9); while a launch whose agent can reach the
> human socket is live (no guard and no wrap), the human socket's records are
> claims too (§10.1), and the confined launch, the dashboard's Home page and
> the inspector name the launch that causes it and the fix (§10.1.1).

## 1. The hole

The arbiter had two channels. The **admin** channel is an inherited fd only
the dashboard supervisor holds; the human-decision ops (`ADMIN_ONLY_OPS`) are
accepted only there. Everything else was the **data** plane, served on the
named socket every interceptor dials: `$MANDU_ARBITER_SOCK`.

The data socket is reachable from the agent world by construction. The
agent's tools start processes (a shell, `python3`, `node`) that are not all
boxed; the launcher's unix allow-list lets them connect to the arbiter, as it
must, because agent-side components (inspect-mcp, the exec-box shims) are
arbiter clients. Several data-plane ops answered with ORIGINALS:

- `desymbolize`: the deep, label-unrestricted HumanView rewrite that fs-sync
  and the reply filter use;
- `resolve` without `deep` (shallow): the gated egress paths' per-symbol
  lookup, which is safe only after `desymbolizationDecision` and has no label
  check of its own;
- `events`, `subscribe`, `sessions`, `verifyEvents`: the observability store,
  whose `DualRepr.original` fields carry originals (reply-filter, proxy and
  fs-sync events). `subscribe` is started at the connection layer and never
  reached `dispatch`, so a check there alone would have missed it.

So any program the agent ran could turn a `$MDU:` token into the value behind
it, `no-model` secrets included, and hand the model an encoding of it: the
classify backstop matches verbatim originals only. Confirmed under a real
`mandu` launch in `secrets` mode. It is a class, not one call: whatever the
data socket answers, the agent world can ask.

A second, smaller gap sat beside it: deep `resolve` (the quarantined U-LLM's
read, which does stay on the data socket) applied its level gate only while
the confidentiality axis was on, so an arbiter restarted with the axis off
answered a `no-model` row minted earlier.

## 2. Three channels

| Channel | Where | Who holds it | How the agent world is kept out |
|---|---|---|---|
| `data` | `<runtime>/instances/<id>/arbiter.sock` (or a pinned `MANDU_ARBITER_SOCK`) | every interceptor, inspect-mcp, the exec-box shims | it is not: the data plane is designed to be agent-reachable |
| `human` | `<runtime>/human/<id>.sock`, directory `0700` | the reply filter, fs-sync, net-proxy, net-supervisor, the dashboard (and its SIEM exporter), the Claude and Codex context proxies (row counts, the relay, and their records of a tool call), and the session's guard `mandu-net-guard` (its process records, §10) | the launcher's walls (§6) |
| `admin` | an inherited fd (dev/test: `MANDU_ADMIN_SOCK`) | the dashboard supervisor | no filesystem name (`policy-surface.md` §2.6) |

The channels nest: **admin ⊇ human ⊇ data**. The human socket accepts every
data-plane op and every human-plane op but no admin-only op; the admin
channel accepts everything. An in-process `dispatch()` defaults to admin (a
caller holding the server object is trusted by construction). One function
decides the matrix, `channelRefusal(req, channel)`, used by `dispatch`, by
the socket path for `discoverSecrets`, and by `onConnection` before a
`subscribe` stream is started. A refusal has the shape of any refused
request: `{ok:false, error:"human-plane: '<op>' returns originals …"}`
(`humanPlaneOnlyError`). For the five ops that return no original
(`symbolShape`, `setSessionRelay`, `sessionRelay`, `noteReserveBlock`,
`reserveBlock`) the error names the real
reason instead of "returns originals"; every refusal starts with
`human-plane: '<op>'`. A refused `subscribe` gets that one error line
followed by EOF, so its client sees the refusal instead of an idle stream.

## 3. The op table

| Op | Channel | Why |
|---|---|---|
| `desymbolize` | human | deep and label-unrestricted by design: it serves surfaces that face the human, who owns every secret |
| `resolve` (shallow, `deep !== true`) | human | the gated egress lookup; the gate (`desymbolizationDecision`) is a separate data-plane op, so shallow resolve alone is an unrestricted read |
| `resolve` (`deep: true`) | data | the quarantined U-LLM's read (inspect-mcp runs in the agent's tree); level-gated by `admits(location, level)`, which refuses `no-model` **whatever the axis** (§4) |
| `events`, `subscribe`, `sessions`, `verifyEvents` | human | the event store holds `DualRepr.original` |
| `symbolShape` | human | a value's line count, and with a `width` its row count and the width of its last row: derived from an original, so it follows `desymbolize` (reply-row-reservation.md §5.3, §11.5, §14) |
| `setSessionRelay`, `sessionRelay` | human | the relay state. Its `cols` sets the wrap width the proxy asks `symbolShape` for. An agent that could set it could replay one secret at widths of its choosing and learn its line lengths from the row counts (reply-row-reservation.md §11.5) |
| `noteReserveBlock`, `reserveBlock` | human | the blocks the proxy expanded: a token and its row count, which is `symbolShape`'s answer, so it stays where that answer stays (reply-row-reservation.md §3.8) |
| `recordForwardedClear`, `forwardedClear` | human | the tool-call ids whose result a model proxy forwarded in clear, kept so a resumed conversation gets the after-the-fact note (confidentiality.md §7.1, *Across a resume*). No original, but from the data socket the agent world could name a call whose result the model never read, and Mandu's system note would then vouch, in Mandu's voice, that it did. Both proxies dial them on their human client |
| `recordForwardedPlaceholders`, `forwardedPlaceholders` | human | where Mandu's placeholders sat in an OpenClaw result a model proxy forwarded in clear, and a digest of it, kept so a relaunch can undo OpenClaw's history redaction (confidentiality.md §6, *Across a relaunch*). Tokens, offsets and a digest only, but from the data socket the agent world could plant a record (with its own digest) that a proxy would put back as Mandu's own text. The anthropic-proxy dials them on its human client |
| `cacheSeals`, `sealCacheEntries`, `beginLaunch`, `endLaunch` | human | the enforcement caches' seals and epochs (confidentiality-plan-14 §11.2). No original, but from the data socket a confined agent could re-seal a cache file planted during an earlier unconfined period (it knows the hash: it wrote the file), or hold every seal void with a fake live launch. The launcher dials them; the arbiter's own scan cache uses the store in-process |
| `clearSessionPathLabels` | human | drops a session's machine path labels (confidentiality.md §8, session labels). It lowers protection: from the data socket the agent world could drop the label on its own background output file and read the file raw. Nothing calls it on its own: the labels are memory-only, and clearing one would lower the protection of a file still on disk |
| `registerAuthGrant` | human | binds a field of the agent's own key file, or the agent's key variable (`env`, §3.8), to the host it authenticates to (agent-sign-in.md §3), which releases the key there: from the data socket the agent could bind its key to a host of its own. The launcher dials it, with its pid: the grant survives an arbiter restart while that launcher lives (agent-sign-in.md §3.2 item 4) |
| `humanPlaneStatus` | human | whether a launch with no wall is live, by pid and session (§10.1.1): display only, but it names sessions, which `sessions` keeps on the human plane |
| `placeholderKnown` | human | whether a placeholder's base (`$MDU:kind[code]`) names a row, its own or a field's: the DevTools relay asks it on the key that closes a typed placeholder's code and refuses that key on a no (devtools-relay.md §3.3). No value, label, binding or field name, and nothing the data socket does not answer already (the egress decision's `egress:unknown-symbol`), but it is the relay's own lookup beside its release gate, so it stays where that gate's values are and the agent world gets no new one. The relay dials it on its human client; no human client refuses the key |
| `filterPrompt` (`dryRun` absent or `false`) | data | the prompt filter (confidentiality-plan-15 §3.2): a model-API proxy's op, which answers symbols and the text the model may read. A proxy-only op: the data-socket caller classification must keep it to the proxies |
| `filterPrompt` (any other `dryRun`) | human | the developer dashboard's test bench (plan 15 §8.1): a dry run mints nothing, caches nothing and leaves no event, so from the data socket it would test guesses against the registered values without a trace. A truthy non-boolean counts as a dry run, so it is refused rather than run live |
| `emit` | data | write-only; interceptors report on the data socket as before |
| `recordExecRoot`, `processLineage`, `recordProcessFlow`, `taintProcessSecret`, `decideSecretOpen`, `decideProtectedWrite`, the `ancestors` of `taintedProcessBindings` and `labelWrittenPathTainted`, `execGate`'s gate time, `callTaint`'s binding | accepted on both; **believed on human** | the guard's and the proxies' records (plan 13 §3 D9): from the data socket each is a claim that may add taint and never lowers it (§10) |
| everything in `ADMIN_ONLY_OPS` | admin | human decisions (unchanged) |
| every other op | data | returns symbols, labels, decisions or metadata, never a stored original |

`declassifySymbol` (rung 3, the in-context read) stays on the data plane: it
is policy-decided, refuses `no-model` and watermarks the session.
`scanSecretValues` stays on data too: it answers which secret rows a text the
CALLER supplies contains, never a value (see §8 for what that still allows).

## 4. Deep resolve on the data plane

Deep `resolve` now runs its level gate with the confidentiality axis on or
off. The top-level symbol is refused (`value: null`) unless
`admits(location, level)`, and nested symbols expand only where their own
level is admitted. An unlabelled row parses `public` and is admitted, so an
axis-off stack with no secret rows answers exactly as before; with the axis
off the reply keeps the axis-off shape (`{ value }`). Tightening the gate
was chosen over moving the call out of the data plane, which needs the
follow-up below.

`resolveExecArgv` (the HumanShell argv lowering the exec shims ask for, also
on the data socket) had the same axis dependence: its secret-withholding
branch fired only with the axis on, so a persisted secret-labelled row came
back desymbolized in the argv of an axis-off arbiter. It now never resolves
a secret-labelled symbol whatever the axis: since 2026-10-05 the placeholder
stays in the argv as written and the command runs (confidentiality.md §7.1;
before, the whole command was withheld as `secret_symbol`); public rows
still resolve in-slot (`policy/exec-classify.ts`, `secret-egress.test.ts`
"exec OFF-dual").

**Follow-up (not built):** move the U-LLM call out of the agent's tree (a
service outside the agent world that inspect-mcp asks by symbol), so deep
`resolve` can leave the data plane too. Until then an `any-model` (or, at a
declared local endpoint, `local-model`) original is one data-socket call away
from a program the agent runs; that is the level's own contract (a cleared
model may read it) but the reader here is not a model.

## 5. Where each consumer runs and which channel it uses

| Consumer | Runs | Human-plane ops | Without the human socket |
|---|---|---|---|
| reply filter (`interceptors/reply-filter`) | the agent's PARENT, started by the launcher | `desymbolize`, `setSessionRelay` | PASSTHROUGH: tokens stay opaque on the terminal (never the data socket), and no relay report, so no reserve expansion. It deletes `MANDU_ARBITER_HUMAN_SOCK` from the agent's env. |
| fs-sync (`fs-sync/`) | launcher service, outside the agent world | `desymbolize`, `resolve`, event reads | its existing fail-closed rule: nothing is written raw from a symbol it could not resolve |
| net-proxy (`interceptors/net-proxy`) | launcher service | `desymbolizationDecision` (§10.3: only an ask here spends a human's *Allow once*) and the shallow `resolve` after it; the holder chains of `taintedProcessBindings` (§10, believed only here), and its `destination` (confidentiality plan 13 §5.4: a refused holder's send consults and spends the human's answer, or files the question naming every file, only here) | egress stays symbolic / blocked (the decision is asked on the data socket); a chain is asked on the data socket, where it is a claim (the answer is the same) |
| net-supervisor (`transform.rs`) | the guard, outside the agent's filter | shallow `resolve` via `ArbiterClient::human_from_env()` | withholds (as on any resolve failure) |
| the session's guard (`mandu-net-guard`) | outside its own filter and the wrap; the agent's parent | every report (plan 13 D9), on the socket `hello` names (`humanSock`), once its own `hello` answers `channel: human` (`report_channel.rs`) | reports on the data socket, where each is a claim: every secret open gets its twin, every protected write is refused (fail-closed); a HIGH session's command is still held (§5.2); it moves to the human plane once that is up and proven the arbiter's (§5.2) |
| dashboard (`arbiter-source.ts`) and its supervisor | the human's service | `events`, `subscribe`, `sessions`, `verifyEvents`, `desymbolize`, `resolve` | the existing unreachable-arbiter behavior |
| anthropic-proxy, openai-proxy | launcher services, outside the agent world | `symbolShape` and `sessionRelay`, over a second client (reply row reservation; Codex since v2, reply-row-reservation.md §11.7), and `execGate` and `callTaint` on the same client (plan 13 D9: only there does a call's gate time count and a call bind to the agent's shell); the Claude proxy's network, path and upload gates too (`desymbolizationDecision`, `fsPathDecision`, §10.3; `fileUploadDecision`, which reads the file only for an ask from there, supported-agents.md §2); the Claude proxy's agent-key release (agent-sign-in.md §3: `desymbolizationDecision` then the shallow `resolve`, for the auth header only) | no reserve expansion, and no call is bound: every shell result is masked while the session holds a raw read; the auth header keeps the placeholder (the provider answers 401); everything else is on the data socket, unchanged |
| inspect-mcp, openclaw-inspect-plugin, exec-wrap, exec-box | agent tree | none (deep `resolve`, symbolize, classify, decisions, emit) | unchanged |

The launcher learns the path from `hello` (`humanSock`) and passes it as
`MANDU_ARBITER_HUMAN_SOCK` to the human-facing children only; the agent's
environment never carries it (env-compose strips it). `hello` discloses the
path to any data client: the path is not a secret, the walls are the
boundary. `resolveArbiterHumanSock()` keys the default on the promoted
instance (`human/<current id>.sock`) and never falls back to the data socket.

### 5.1 Following a restart (2026-10-07)

The human socket's name carries the instance id, so an arbiter restarted
under a live session listens on a NEW human socket, while the data socket
keeps its spelling (`current/arbiter.sock`, or the pinned path the new
instance binds again). Until this change every human-facing TS consumer kept
dialling the dead path for the rest of the session: the reply filter showed
raw placeholders, the proxies' human-plane gates (`execGate`, `callTaint`,
the network and path decisions) and net-proxy's shallow `resolve` failed
closed, and fs-sync refused, until the session was relaunched.

`ArbiterClient.humanPlane(humanSock, dataSock)` (arbiter/ipc/client.ts) is
the client the reply filter, the anthropic-proxy, the openai-proxy,
net-proxy and fs-sync now build over `MANDU_ARBITER_HUMAN_SOCK`, given the
`MANDU_ARBITER_SOCK` they already have. When a dial of its human socket
finds no listener (`ENOENT`, `ECONNREFUSED`, `ENOTSOCK`), it re-learns the
path the way the launcher learned it (`humanPlaneRediscovery`):

1. `hello` on the data socket names `humanSock`;
2. the candidate must be an absolute `.sock` path in the SAME directory as
   the stale one (the walled `human/` directory), and not the data socket
   (`acceptableHumanSock`);
3. the candidate's own `hello` must answer `channel: human`, with the
   instance id the data socket reported.

Only then does the client dial it; a human-plane op is never sent to the data
socket, and a candidate that fails a check is not adopted (the request fails
as before: the reply filter passes the token through, an enforcement path
fails closed). Rediscovery runs with backoff, 250 ms doubling to 30 s while
the arbiter answers and names nothing usable, reset by a successful dial,
so a live arbiter is not asked on every request. While the arbiter is down
its data socket does not answer either: each request then costs one failed
connect, like the dial itself, and no window grows, so the first request
after the arbiter is back re-learns (a window grown during the downtime
failed the guard's first reports after a restart closed, found by the kernel
test below). A request already written into the dying
connection is not retried (some human-plane ops spend a verdict): it fails
like any request the old arbiter never answered, and the next one dials the
new socket.

The reply filter records the move: the first lookup answered on a re-learned
socket emits a plain `relay_mode` (the recovery record of
reply-row-reservation.md §18.4, even when no lookup failed in between), and
the filter reports its relay again, since the new arbiter holds none.

**The Rust consumers (2026-10-07).** `interceptors/mandu-arbiter` has the
same client: `ArbiterClient::human_plane(human, Some(data))`, with
`rediscover_human` and `acceptable_human_sock` the same checks, each
discovery `hello` bounded at 3 s, and the backoff kept process-wide per
original path, together with the path last re-learned for it, so a client
built later (net-supervisor builds one per proxied connection) starts at
the new socket. The guard's report client (`report_channel.rs client_for`)
and net-supervisor's egress transform (`transform.rs human_client_from`,
given the data socket it already has) use it; the guard's reports stay
believed across a restart, and the transform keeps resolving allowed
symbols on the human plane. A guard that chose the data socket at start
(no human plane then) moves later, under §5.2's checks.

One difference from the TS client: in Rust a write on a REUSED connection
whose peer is already gone fails with EPIPE before a byte is delivered (a
Unix stream does not buffer for a closed peer), so that request, which no
arbiter received, is sent once more on a fresh dial. Without it the guard's
first report after a restart (its connection to the old instance is
long-lived) would fail closed for no reason. A request the old arbiter read
and never answered is still never retried.

### 5.2 A guard that started with no human plane (2026-10-17)

The guard chooses its report socket once, before the agent's first trapped
call is answered (`report_channel.rs choose`). When the human plane is not
there then (the arbiter down or restarting at the launch, an arbiter that
names no human socket, a human socket that did not answer its `hello`), it
reports on the data socket. Until this change it stayed there for the
session, every report a claim.

**What a claims-only guard costs, and in which direction.** Almost
everything falls closed, as plan 13 D9 intends: every open of a registered
secret gets its twin (`decideSecretOpen`), every protected write is refused
(`decideProtectedWrite`), no exec is a call-root candidate (`recordExecRoot`:
no call binds to its shell, so a call's result is masked while the session
holds a raw read), lineage, flows and orphan roots only widen walks, an agent
flow's close is not recorded (its window stays open: more masking), a held
connection's destination asks no human (`taintedProcessBindings`: the refusal
stands), no refused connection is recorded for the call's `refused:` note
(`recordEgressRefusal`), and `guardAttach` is ignored (a HIGH session's command
card says an allowed run is not held, which understates). One check fell the
other way: **`sessionExecRoot` answered `holder: false`** on a claims
channel, before it looked at the session. A HIGH session's tool-call shell,
which confidentiality.md §4 holds to what the session read, then ran
unconfined: its connections went anywhere (the guard and net-proxy saw a
process holding nothing) and its writes were not labeled. The command card
said "not held" in that case, but the same answer came from the human
socket while an unwalled launch was live (§10.1), where the card said
"held". Now the arbiter answers a HIGH session's `sessionExecRoot` from any
channel with `holder: true`, the session rows recorded as claims
(`taintProcessSession`, `claimed`; the guard's believed report of the same
row clears the mark). A session row only confines: it never masks what the
model gets back and never buys a raw read (`attestedOnly` walks leave it
out), so a forged one from the agent's tree takes nothing away (it can only
make a process of its choosing a holder, as a claimed raw read already can).
Shown red before by `arbiter/test/component/session-exec-taint.test.ts` and
the kernel test below.

**The move.** A guard on the data socket keeps looking for the human plane on
a thread of its own (`spawn_upgrader`): first after 250 ms, the wait doubling
to 30 s while the arbiter answers and names nothing usable, unchanged while
it does not answer at all (a look then costs one failed connect), so the first
look after the arbiter is up finds it. It moves only when every check of
`decide_upgrade` passes. The guard's START choice (`choose`) applies the same
checks since 2026-10-17 (below, "At start"); before, it took any socket the
data socket's `hello`, or a rig's `MANDU_ARBITER_HUMAN_SOCK`, named once
that socket answered `channel: human`. The checks:

1. `hello` on the data socket names `humanSock` (the launcher's
   `MANDU_ARBITER_SOCK` is the root of trust: the agent's world cannot
   replace it, the runtime registries being on the guard's write-protect
   list, write-protection.md §2);
2. the candidate is an absolute `.sock`, not the data socket, directly in one
   of the directories this guard walls off (its policy's `unixDeny`, both
   spellings); a guard with no `unixDeny` never moves;
3. that directory is a real directory (not a link) of this account's, mode
   `0700`, and the candidate a socket of this account's;
4. the candidate's own `hello` answers `channel: human`, with the instance id
   the data socket reported;
5. the process listening on the candidate is the process listening on the
   data socket (`SO_PEERCRED`, read on the very connections the two `hello`s
   came on: it records who called `listen`, and no answer can change it),
   of this account, visible in this pid namespace, and not in the guard's own
   tree (its parent chain does not reach the guard; an unreadable chain counts
   as in the tree). A guard that could not become its tree's subreaper never
   moves: a program of the agent could then daemonize out of its tree.

Why the fifth check: a socket a program of the agent stood up in the human
directory would answer every word as the arbiter does. The launch already
refuses that (the wrap's `--tmpfs` hides the directory; the guard's
write-protect list holds `human/` and the guard performs or refuses every
pathname `bind` under it, write-protection.md §2, "Mandu's runtime
registries"), but the move must not rest on the launcher having written that
list: a socket the agent serves is served by a descendant of the guard,
never by the process that serves the data socket, whatever its path and
whatever it answers. The arbiter refuses to start over a live socket at its
human path (`attachHumanChannel`), and with both sockets served by one
process outside the agent's tree, the candidate is the arbiter's human
plane.

When the look passes, the guard builds its human-plane client as at start
(`client_for`: it follows a later restart, §5.1, and never sends a report to
the data socket) and swaps it in under the shared client's mutex
(`switch_to_human`). A report in flight completes on the data socket first
(each request is bounded, !1720); every report after the swap goes to the
human plane, the first being `guardAttach` again (ignored at start), so a
HIGH session's command card says an allowed run is held from then on. It
moves once and never back: the human-plane client has no path to the data
socket, and a human plane that goes away fails the guard's reports closed
until §5.1 re-learns it.

**Nothing is upgraded after the fact.** The swap sends nothing again. What
the data socket took stays what it was: a twin handed out stays a twin, a
refused write stays refused, a claimed edge or row stays claimed until the
guard reports the same fact again on the human plane, which is a new report,
believed on its own. Upgrading old claims would believe records the arbiter
cannot tell from a forger's (anything on the data socket may be one).

Tests: net-supervisor `report_channel.rs` unit tests (`decide_upgrade`: the
move, the arbiter down, every impersonation refused: a planted socket served by
another process, both sockets served by a program of the tree, a path outside
the walled directory or the data socket's, a link or an open directory, the
data channel, another instance, another account, a hidden pid, unread
credentials; the wait; `in_tree_of` on a fixture and on `/proc`;
`private_socket_place` on real files; the swap under the mutex, held by a
report in flight, replaying nothing; the looker over real sockets, moving once);
kernel lane `tests/sandbox/guard/report-channel-late.test.ts` (the REAL guard
starts beside an arbiter with no human plane, its first open the twin; an
arbiter with one comes up; the guard moves, announces itself, and its next
open is believed raw; and a guard with no human plane all session holds a
HIGH session's command: the unbound listener refused, its file labeled; both
red before).

**At start (2026-10-17).** The guard runs the same checks once before it
serves the agent's first trapped call (`choose`, over the shared `judge`):
the candidate is the data socket's `hello` `humanSock`, or a test rig's
`MANDU_ARBITER_HUMAN_SOCK` (which the launcher never gives the agent, hence
the guard), and every check above applies to either. Its secret policy is
loaded first, so the walled directories (`unixDeny`) are known. A guard that
is not its tree's subreaper starts on the data socket. Why the start needs
them: whatever answers on the socket the guard reports on decides its
questions (a secret open raw or twin, a protected write allowed), so a socket
that answers `channel: human` but is not the arbiter's (a process outside the
arbiter serving a path in the human directory, or a rig variable naming one)
would have been the guard's arbiter for the session. Anything short of all of
the checks, the arbiter not answering at the start included: the data
socket, every report a claim (fail-closed), and the looker keeps trying.

Where a setup cannot satisfy them, the guard is a claims guard and says so:
an `off` launch (no `unixDeny`; nothing is protected there), a guard whose
`prctl(PR_SET_CHILD_SUBREAPER)` failed, and an arbiter in another pid
namespace than the guard (`SO_PEERCRED` reads pid 0: the guard cannot tell
the arbiter's process from another's). The launcher runs the guard and the
arbiter in the account's own pid namespace (the guard outside the wrap), so
none of these is a protecting launch on Linux.

The test rigs that run the guard against an `ArbiterServer` of their own
now give it the walled directory the launcher gives it (`unixDeny:
[<tmp>/human]` in the secret policy): agent-flow, args-code-reader,
build-tool-reader, call-tree, cwd-file-holder, cwd-secret-name,
git-transport-printer, guard-provenance, high-session-command,
printer-downstream, reader-allow-list, reader-output-rule,
relative-path-label, report-channel-restart, script-reader-pin,
socket-flow, ssh-config-write-protect, tar-secret and task-output-twin under
`tests/sandbox/guard/` (forged-reports and report-channel-late already did),
and the shell rigs `launcher/test/secret-readers-live.test.sh`,
`pipe-taint-live.test.sh` and `derived-label-live.test.sh` (their dev
arbiter's `<runtime>/human`).
The rigs that start the real launcher get it from the launcher.

Tests: net-supervisor `report_channel.rs` (`choose`: the discovered socket
chosen under every check, a rig's path outside the walled directory refused,
the arbiter not up, no walled directory, and at start every impersonation of
`decide_upgrade`'s list); kernel lane
`tests/sandbox/guard/report-channel-start.test.ts` (a process that is not the
arbiter serves the human socket a rig names, in the walled directory,
answering every open `raw`: the guard reports on the data socket, the reader
gets the twin, the impostor gets no report; red before: a raw read).

### 5.3 `MANDU_NET_GUARD_EVENTS=0`: events off, reports on (2026-10-17)

The variable was documented as the opt-out of the guard's observability
events (exec-routing.md §7.5, "Observability"). It turned off the guard's
whole arbiter client: with it set the guard asked nothing and reported
nothing, as with no `MANDU_ARBITER_SOCK`. That fell closed for the opens
(every registered secret a twin, a vouched reader's too) and the protected
writes, but OPEN where the guard skips a question it has no client for: a
HIGH session's command was never made a holder (`sessionExecRoot` not
asked), a rename or hard link of a derived copy did not carry its label
(`derived_follows`, `label_follows`), and the derived-label index was never
read. Nothing in the tree sets it in a launch (one shell test sets it with
`MANDU_ARBITER_SOCK` unset, where it changes nothing); the launcher does not
strip it from the agent's environment, which the guard inherits, so a user
who exported it lost the guard's reports without a word.

Now it turns off `emit` only (`ArbiterClient::with_events(false)`, carried
across a move to the human plane): every report and question goes as
before. Tests: mandu-arbiter `emit_roundtrips_and_safe_emit_swallows_errors`
(events off: `emit` sends nothing, `ping` still goes), net-supervisor
`report_channel.rs` (the setting survives the move), kernel lane
`report-channel-start.test.ts` (with it set a vouched reader reads raw, the
guard announced itself, and a refused connect files no guard event; the
same run with events on files one; red before: the twin).

## 6. The walls

Every layer that decides what the agent world may reach names the human
directory `<runtime>/human`:

- **net-guard (seccomp connect guard):** the guard policy file's
  `unixDeny` list (`launcher/src/human-plane.ts` `applyHumanPlaneDeny`;
  `net-supervisor` `secret_open.rs`), written whenever the guard runs in a
  protecting mode, independently of the Unix allow-list and its
  `MANDU_UNIX_POLICY=0` opt-out. A non-empty list makes the guard supervise
  every pathname Unix `connect(2)`; the check runs on the opened inode (its
  resolved path, and its identity against the directory's entries), so a
  symlink, a directory symlink or a hard link to a denied socket is refused
  (`EACCES`) like the path itself. Kernels without `openat2` (< 5.6) fall back
  to a path-string check, with the symlink-swap race the WSL interop check
  already records.
- **unix allow-list (`launcher/src/unix-policy.ts`):** an entry that
  equals, contains or lies in a human directory is dropped and logged,
  whatever its source (built-in, `policy.yaml`, `MANDU_UNIX_ALLOW`, the scope
  dir, the arbiter entry); the directory is never under a scope dir. A launch
  whose `MANDU_ARBITER_SOCK` itself lies in the human directory is refused.
- **secret-twins wrap (bwrap):** `--tmpfs` over each human directory that
  exists, after the home mask and its carve-out binds and before every
  secret-twin bind.
- **macOS Seatbelt:** the launch's ONE whole-agent profile
  (`seatbelt-profile.ts`, `confidentiality.md` §7.3; run.ts hands it
  `plan.humanPlaneDirs` in every mode but `off`, as the guard's `unixDeny`,
  and `applySeatbelt` adds `<base>/human` for every registry base, so a
  launch with its own `MANDU_RUNTIME_DIR` walls off the resident stack's
  human plane under the account's default base and rendezvous too, since
  2026-09-30)
  denies `connect` (`(remote unix-socket (subpath …))`; the `file-read*` rules
  do not cover it) and every read and write under each human directory, in
  the given and the canonical spelling, after every file and socket allow and
  before the TCP rules (the unix/TCP ordering quirk). A path deny is escaped by
  renaming a directory ABOVE it, the runtime base included, so those get the
  profile's rename guard. Verified on macOS 26.5 (2026-09-30,
  `launcher/test/darwin/seatbelt-live.test.ts`): the direct path, a symlink, a
  directory symlink, a hard link and a rename of the human dir or of the
  runtime base are all refused, and the data socket beside it still answers.
  The macOS Unix allow-list names `<base>/instances`, never the whole runtime
  directory, and drops an entry touching the human plane as on Linux.
- **Claude Code's sandbox:** the `allowUnixSockets` overlay filters out any
  human path; a user settings entry naming one draws a warning.
- **The launcher's environment:** `MANDU_ARBITER_HUMAN_SOCK` goes to the
  reply filter (only when it filters), every fs-sync call (init, watch, the
  post-exit sync) and net-proxy, and is explicitly unset for them when the
  arbiter reported none; the agent's env drops any ambient value (direct and
  systemd-scope paths); the reply filter deletes it from its child's env too.
  An early-started reply filter (packaging.md §5.3) gets it only in its
  fd-3 hand-off, never in the scope's `--setenv` list, which the filter
  passes on to the agent's chain.
  The arbiter binds the human socket BEFORE the data socket, so a launcher
  that waits for the data socket always reads `humanSock` from `hello`.
- **The arbiter itself:** the directory must be a real directory, ours, mode
  `0700`, or the arbiter refuses to start; the socket is `0600`.

The directory also holds one socket that is not the arbiter's: the
dashboard's **sign-in socket**, `dashboard-<pid>.sock` (2026-10-05,
[policy-surface.md](../ui/policy-surface.md) §2.6 "Signing in"), where the
launcher and `mandu dashboard` ask for a one-time sign-in link. Every wall
above names the directory, so each covers it with no change; the dashboard
verifies the directory as the arbiter does and mints nothing while
`humanPlaneStatus` reports a launch with no wall. The arbiter's sweep never
touches it (it removes only `<instance id>.sock`), and the dashboard sweeps
dead dashboards' sockets at boot.

## 7. Rejected mechanisms

- **An inherited fd, as for admin:** the consumers are not the arbiter's
  children (the arbiter is shared across launches and adopted), so an fd
  would need a named rendezvous to be passed over, which is the socket again.
- **A token in the environment or a file:** `/proc/<pid>/environ` and any
  file the consumer can read are readable by the same uid; hiding the token
  needs the same wall as hiding the socket and adds a secret to leak.
- **Peer identity via `SO_PEERCRED` + `/proc`:** a pid is checked at connect
  time and can be reused or exec'd into the expected binary; ancestry is
  forgeable by reparenting. Not a boundary between processes of one uid.

## 8. Residuals

- **A launch with no wall** (the `gated` posture with neither the guard nor
  the wrap: no guard binary, or `--no-net-guard`, on a host where bubblewrap
  cannot mount or has nothing to mount; and every `off` launch): nothing
  hides the path, exactly as nothing hides the Mandu home there
  (`confidentiality.md` §7.2 residuals). `--require-confinement` refuses the
  posture. What a program of such an agent can do with the human socket
  (verified, §10.1): read every original (`desymbolize`, shallow
  `resolve`, the event reads), which it can also read straight out of
  `state/mandu.db`; record cache seals and launch rows, which the rotation
  that ends the unconfined period voids (plan 14 §11.2); and, until §10.1,
  have its reports believed as the guard's: a first-use reader pin written
  into `policy.yaml` by the arbiter itself (a hand edit of the file that
  relaxes the law is held, policy-surface.md §8.4.6, but the arbiter's
  own pin is not), an Inbox row in the guard's words, a concurrent confined
  launch's lineage and raw reads. It can NOT answer an Inbox hold or edit
  the law through the arbiter: those ops are admin-only (an inherited
  descriptor; the dashboard's admin token lives in its process's memory).
  Closed for the reports by §10.1; what stays open is the home itself (the
  last bullet below).
- **Yama `ptrace_scope` 0** is the floor, as for the admin channel: a
  same-uid process that may ptrace a human-plane consumer (or
  `pidfd_getfd` its connection) reads what it reads. At the Ubuntu default
  (1) the agent cannot trace the reply filter, its ancestor, or the services
  outside its tree. `mandu doctor` warns at 0 and with no Yama
  (rootless-confinement-ubuntu-2404.md §3.3).
- **`scanSecretValues` on data** confirms a GUESS (a caller-supplied text
  that contains a secret value), never reveals one. So does a live
  `filterPrompt` (it answers the value's symbol for a span it masks); its
  dry run, which would do it with no mint and no event, is human-plane.
- **Deep `resolve` for admitted levels** (§4 follow-up).
- **A same-uid process outside the agent's tree** can reach the socket: the
  walls confine the agent's world, not the account (the same line the admin
  channel draws). An unwalled launch's agent is such a process for as long
  as it runs (§10.1), and so is anything it leaves running after its
  launcher exits (the exposure ends when the launcher does, as the cache
  seals' unconfined period does, plan 14 §11.2 S3). It can also write
  `state/mandu.db` directly (a forged verdict or taint row), which no file
  on disk can stop without root: plan 14 §11.2 S3's line.
- **The dashboard's loopback HTTP port** reads what the human plane reads
  (it is a human-plane consumer) to any loopback client. The walls that hide
  the socket refuse the agent's world a direct connect to the port (the
  guard's loopback rules, the Landlock port wrap), and since 2026-10-05 the
  session's net-proxy no longer relays a request there either: it refuses
  every destination on this machine (exec-routing.md §7.5; before, `curl -x
  "$HTTP_PROXY" http://127.0.0.1:4500/api/events?session=…` from the
  agent's tree read secret values through it). A launch with no wall
  leaves the direct connect open, as it leaves the socket (the first bullet),
  for as long as the dashboard answers loopback reads without a sign-in
  (dashboard.md §6).
- **An unreadable guard policy file** makes the guard run without its deny
  list (existing guard behavior for the whole file).

## 9. Tests

- `arbiter/test/component/human-plane-rediscovery.test.ts` (§5.1): a real
  arbiter restarted on a new human socket, and `ArbiterClient.humanPlane`
  resolves again while a plain client stays on the dead path; a `hello`
  naming the data socket or a path outside the human directory, and a
  candidate answering as the data channel, are never adopted (the data
  socket sees only `hello`); the backoff; `acceptableHumanSock`.
  `tests/stack/reply-filter-arbiter-restart.test.ts`: the same restart under
  the real reply filter and anthropic-proxy. Rust: `mandu-arbiter`
  `rediscovery_tests.rs` (the checks, a re-learn over real sockets with only
  `hello` on the data socket, a client built later starting at the learned
  path, an undelivered EPIPE write sent once on a fresh dial, a read-but-
  unanswered request not retried, the backoff); net-supervisor
  `report_channel.rs` and `transform.rs` unit tests (the report client and
  the egress resolve follow a moved human socket; the data socket is never
  asked to resolve); kernel lane `tests/sandbox/guard/report-channel-restart.test.ts`
  (the REAL guard across a restart: its report reaches the new human plane
  and a vouched reader still reads raw). §5.2, a guard that started with no
  human plane: net-supervisor `report_channel.rs` (`decide_upgrade` and every
  impersonation it refuses, the swap, the looker over real sockets), arbiter
  `session-taint-rows.test.ts` and `session-exec-taint.test.ts` (a claimed
  session row confines, masks nothing, buys no raw read), kernel lane
  `tests/sandbox/guard/report-channel-late.test.ts` (the move, and a
  claims-only guard holding a HIGH session's command).
- `arbiter/test/unit/human-plane-ops.test.ts`: the op × channel matrix
  (data refuses the human-plane ops, `subscribe` and the reply-reservation
  ops included; human accepts them and refuses admin-only; admin accepts
  all), deep resolve on data with the axis OFF refusing a `no-model` row.
- `arbiter/test/unit/symbol-shape.test.ts`, `session-relay.test.ts` and
  `arbiter/test/component/reply-row-reservation.test.ts`: `symbolShape` and the
  relay ops refused on data and served on human, in dispatch and over real
  sockets.
- `arbiter/test/component/human-plane-channel.test.ts`: a real server with both
  sockets; the daemon's manifest, `hello`, directory checks and cleanup.
- Parity tests (production adapter over `new ArbiterClient(humanSock)`, no
  test bridge) for the reply filter, fs-sync, net-proxy and the dashboard.
- `tests/stack/agent-world-originals-refused.test.ts`: a child
  given only `$MANDU_ARBITER_SOCK` is refused every human-plane op, while the
  reply-filter CLI (`reply-filter-secret-render.test.ts`) and fs-sync still
  render originals over the human socket.
- `launcher/test/unit/human-plane.test.ts` (discovery, the allow-list
  refusal, env hygiene, the guard entry, the wrap order, the Seatbelt text,
  `allowUnixSockets`) and net-supervisor's `unix_deny` unit tests.
- `tests/sandbox/human-plane-wall.test.ts`: under the
  production guard and wrap, the agent world cannot connect to the human
  socket by its path, a symlink, a directory symlink or a hard link, by
  default, with `MANDU_UNIX_POLICY=0`, and guard-only
  (`--no-secret-bind`); the data socket stays reachable and the agent's env
  has no `MANDU_ARBITER_HUMAN_SOCK`.

**macOS integration: an applied wall is the claim.**
`humanPlaneWalled` is true only when the whole-agent Seatbelt profile was
applied and contains the human-directory read, write and Unix-connect denies
above. Finding `sandbox-exec`, or having it in the launch prefix, is insufficient.
This wall is independent of `homeSealed`, the stricter cache classification
(plan 14 §11.3): a walled `read-blocked` launch that does not seal the home
voids caches without exposing the guard-report channel; an unwalled launch
invalidates other sessions' guard attestation until it ends. The Linux wall,
session/workspace metadata and exposure notices keep their existing behavior.

## 10. The data plane's records: who is believed

Confidentiality plan 13 §3 D9 extends the human plane from the ops that
return originals to the RECORDS a confinement decision rests on. The
question for every op the data socket accepts: a program the agent runs
can send it with any arguments; can that lower a mask, a taint, a label or
a binding restriction, spend a human answer, pin a reader, or put the
agent's words in front of the human? Where it could, the op's record is
believed only from the human socket (or the admin channel) and is a claim
from the data socket (`ATTESTED_REPORT_OPS`, `attestedChannel`,
`arbiter/ipc/server.ts`; the per-op behavior is plan 13 §3 D9's table).

| Class | Ops | Who sends them, from where | Forged from the agent's tree |
|---|---|---|---|
| **Guard reports** (believed on human) | `recordExecRoot` (and its `orphanRoot`, plan 13 §3 D7's orphan subshell: it only widens the fold of earlier calls, so a data-socket report is kept as a claim, as is `decideSecretOpen`'s), `processLineage`, `recordProcessFlow` (plan 13 §9 R1: a process that received a holder's bytes through a descriptor; only adds taint, so a data-socket report is kept as a claimed flow), `recordAgentFlow` (plan 13 §4.5.1: the agent itself holds a channel a holder writes into, a socket or, a FIFO's path or a file it reads; an open from the data socket is a claim, which only adds masking, a close is not recorded), `taintProcessSecret`, `decideSecretOpen`, `decideProtectedWrite`, `taintedProcessBindings` / `labelWrittenPathTainted` (their `ancestors`), `recordEgressRefusal` (plan 10 §11.8: a connection the egress proxy refused, by process and kind, which the call's `refused:` note reads; one it could tie to no process, `unattributed`, by kind for the calls running then; nothing recorded from the data socket) | the guard (`mandu-net-guard`, outside the agent's tree, now on the human socket); `processLineage` also from the exec box (inside the tree: claims); `taintedProcessBindings` and `recordEgressRefusal` also from net-proxy (a launcher service that reads its holder chains from `/proc` outside the agent's tree; on its human client, so they are believed, and a claim only when it has no human client or that client fails) | before D9: a reader out of its call's tree, a forged reader pinned, a derived copy read raw, an Inbox row in the guard's words. Now: claims (widen only) |
| **Proxy records of a call** (believed on human) | `execGate` (the call's gate time and gated command), `recordCallCommand` (the command the agent was given, after the proxy's rewrites, the D9 follow-up; with no command, the call's relay time, plan 13 §4.5.1), `callTaint` (the first ask, the binding, by the recorded command), `agentReceiptTaint` (plan 13 §4.5.1: each call's first ask, the end of the window the agent's own connections to a holder mask; a file tool's result only by a flow on a FIFO or a file) | anthropic-proxy, openai-proxy (launcher services; now on their human client) | before D9: a call bound to another call's clean shell. Now: `execGate` and `recordCallCommand` record nothing; `callTaint` and `agentReceiptTaint` read only (a data-socket ask ends no window early). Before the D9 follow-up the proxy's own ask bound the call by the command the agent echoed back, which the agent chooses; now by the recorded one |
| **Human plane** (refused on data) | `HUMAN_PLANE_OPS` (§3) | the human-facing services | refused |
| **Admin** (refused on data and human) | `ADMIN_ONLY_OPS`. The prompt hold's answers (`resolvePromptHold`, `letPromptFindingThrough`, and `resolveEgressApproval` on a `prompt:` row) also refuse a SESSION answer under a locked administrator's `ask` row, whatever channel sends it (plan 15 §12, 2026-10-04): the hold lists `onceOnly` (`promptHolds`, and `egressApprovals` on a waiting row), and so does each referenced finding of a `filterPrompt` answer, which the proxies copy into their `prompt_filter` events for the dashboard's "let it through" (a display hint: the refusal stands whatever an event says) | the dashboard supervisor | refused |
| **Bind-once, the launcher first** | `setSessionSpec`, `setSessionUpstream` (and its `cleanReporter`) | the launcher, before any service or the agent exists | a later bind is refused or a no-op |
| **Token-authenticated** | `reportExecCleanVerdict` (after `claimCleanReporter`) | the guard's clean host (integrity axis, frozen) | resolves UNCLEAN without the guard's token |
| **Tightening only** | `registerSecret`, `registerEnvSecrets` (bindings come from the law, not the caller), `labelWrittenPath`, `followDerivedLabel` (raise-only), `sessionPathLabel` (a session's `no-model` label on one exact path, in memory; confidentiality.md §8), `taintProcess`, `taintFile` (integrity taint), `policyPropose` / `applySuggestion` (a proven tightening; a relaxation waits for the human), `registerRepository`, `scanSecretHistory`, `discoverSecrets`, `suggestPolicy` | the launcher, the guard, fs-sync, the dashboard, the inspect helper | adds protection, a pending proposal or a suggestion; never removes one |
| **Decisions and reads** | `classify`, `classifyExec`, `resolveExecArgv` (withholds secret rows, §4), `desymbolizationDecision`, `fsPathDecision`, `fileUploadDecision` (from here it reads no file and refuses, `fs:upload-unattested`), `sessionEgressDecision`, `egressFingerprintScan`, `declassifySymbol` (policy-decided, refuses `no-model`, watermarks the session), deep `resolve` (level-gated, §4), `documentText` (the text of a PDF block the caller holds, or a registered document's twin text: secret-discovery.md §2.8), `scanSecretValues` and a live `filterPrompt` (each confirms a guess, §8; `filterPrompt` is the proxies' op, and from the agent's tree it masks only text the caller supplied), `promptFilters` (the exceptions without their patterns: those are the human-plane `promptExceptions`, plan 15 §13.7 item 4), `symbolize` / `symbolizeDerived` (the level is the arbiter's), `pathLevel`, `pathLevels`, `pathLabels`, `whyPath`, `whyHost`, `testFlow`, `policyDocument`, `policyProposals`, `policySuggestions`, `policyChanges` (on the data socket each prompt exception's pattern is a placeholder with `patternHidden: true`; the human socket and the admin channel answer in full, plan 15 §13.7 item 4), `policyPreview`, `policySchema`, `policyExplain`, `policySnapshot`, `modelEndpoints`, `sessionUpstream`, `netConnectAllow`, `guardSettings`, `gitHistoryLocks`, `sshAgentPolicy`, `readerProgram` (what a binary is, by name and host hash; the guard asks it for a secret socket's reader), `envSecretNames`, `envSources`, `consumerPacks`, `protectPaths`, `confidentialityState`, `sessionState`, `secretRegistry` (names, never values), `handlingPrompt`, `toolSurface`, `gateSurface`, `execDecisionFor`, `execTwinsFor`, `execCleanVerdictFor`, `isProcessTainted`, `processSecretTaint`, `sessionSecretTaint`, `secretTaintedProcesses` (process keys, never files), `mcpServerTaint`, `derivedLabelsSince`, `labelRootsSince` and `labelledLevel` (where the labels and the catalog's files lie and a path's level, for the guard's gate of a labelled or catalog file the launch did not register; the record its `agentOpen` asks for, of the agent's own open, is kept from the human plane only: confidentiality.md §6, "The base follows the shell"), `fileTrust`, `symbolProvenance`, `egressApprovals`, `hello`, `ping` | every interceptor, the agent's own helpers | an answer to the caller; no stored original, no state that loosens a decision; a human's *Allow once* is neither granted nor spent from the data socket (§10.3; `declassifySymbol` excepted) |
| **The policy model** (plan 14 §14) | `modelSuggest`, `modelSuggestPreview` | the dashboard, `mandu policy suggest` | what the model is sent and where is decided by plan 14 §14's own rules (the law's model placement, the classifier's confine), not by this note; a run files suggestions, which only tighten |
| **Observability and hints** (accepted on both; **believed on human**, §10.2) | `emit`, `recordToolCall`; and, never believed, `reportExecTwins` (its only writer, the exec box, runs in the agent's tree), `escalateExec` (integrity, frozen), `recordCallRoot` (a claim on every channel); `relayNotice` / `takeRelayNotices` (the DevTools relay's refusal for the browser agent's model, devtools-relay.md §3.4: kinds, a host and `$MDU:` names only, checked; forged from the agent's tree, its model reads one of Mandu's own refusal sentences, or a pending one goes untold, never a value) | the model proxies, net-proxy, the launcher, fs-sync, the reply filter and the guard on the human socket; the dashboard's audit on the admin channel; inspect-mcp and the exec box from the agent's tree (claims) | before §10.2: an event in any component's name, in any session's log or the arbiter's own audit stream, and a tool-call record replaced. Now: a data-socket event is stored `claimed: true` (the audit stream refuses it), a claimed tool-call record never replaces the proxy's and is not answered by `symbolProvenance`; no decision reads a claim (§10.2) |

### 10.1 A launch with no wall: the human socket is not believed while it runs

The human socket is believed because the walls of §6 keep the agent's world
off it. A launch with none of them (§8's first residual) has no wall: its
agent's programs connect to `<runtime>/human/<id>.sock` like any process of
the account. Were the arbiter to believe them there, a program of that agent
could report a raw open of its own copy of `cat` as a system binary and the
arbiter would pin the bare-name reader to the copy in `policy.yaml` (a pin
that outlives the launch and binds every confined launch after it), or file
an Inbox row in the guard's words (both shown by
`arbiter/test/component/exposed-human-plane.test.ts` and
`tests/stack/exposed-human-plane.test.ts`).

Now every launch says whether its agent's world is walled off from the
human plane (`beginLaunch`'s `humanPlaneWalled`, launcher `human-plane.ts`
`humanPlaneWalled`: the guard's always-deny entry, or the wrap's `--tmpfs`
over every human directory, or the Seatbelt profile). The arbiter keeps
every unwalled launch (`CacheSealStore.humanPlaneExposure`: the launch row,
and a copy in memory, so a program of that agent that deletes the row from
`mandu.db` does not end it) and, while one is live, answers every
`ATTESTED_REPORT_OPS` request from the human socket as a claim, exactly as
from the data socket (`ArbiterServer.attested`; the reason names the
launch). The admin channel stays believed. A launcher that does not say
(an older one) counts as unwalled. The exposure ends with the launch
(`endLaunch`) or its launcher's pid (memoized for 250 ms).

The launcher's side (`cache-epoch.ts`): an unwalled launch in a protecting
mode that the arbiter could not record, while it has a human socket, is
refused unless `--best-effort` (`unrecordedExposureRefusal`), since
unrecorded its programs would be believed; and a confined launch is told
which unconfined launches are live beside it (`beginLaunch`'s `others`),
warns, and refuses under `--require-confinement`
(`concurrentLaunchNotice`).

Utility cost: while an unwalled launch runs, a confined launch beside it
loses its guard's attestation (every secret open gets the placeholder,
every protected write is refused, every shell result is masked while the
session holds a raw read; a HIGH session's command is still held, its rows
claims, §5.2: before 2026-10-17 it ran unconfined while its card said
"held"). The unwalled launch itself has no guard, so it
holds no raw read to mask. The bind-only `gated` posture is walled and
changes nothing. A launcher whose pid the arbiter cannot see (another pid
namespace) keeps the exposure until its `endLaunch`, at most 24 hours.

Rejected: a credential for the human ops (a file or environment token is
readable by that agent too, §7), and hiding the socket by other
unprivileged means (without the guard's trap or a user namespace for the
wrap nothing walls a pathname Unix socket: Landlock has no right for
`connect(2)` on one, and a directory mode does not separate processes of
one uid).

Not closed, by the privilege line: an unwalled agent can write the Mandu
home (the DB, the twin files of a concurrent launch) and outlive its
launcher (§8). `off` observes only: its exposure suppresses belief like any
unwalled launch's, and a launch the arbiter could not record is not refused
there (nothing is protected to begin with).

Tests: `arbiter/test/component/exposed-human-plane.test.ts` (the forged pin
and Inbox row while exposed, believed before and after, walled launches,
an older launcher, a deleted row, a gone launcher, `others`),
`launcher/test/unit/human-plane.test.ts` (`humanPlaneWalled`),
`launcher/test/unit/cache-seals.test.ts` (the refusal and the notice),
`tests/stack/exposed-human-plane.test.ts` (the production launch record
over a real server), and under a real launch
`tests/sandbox/exposed-human-plane.test.ts` (a program of a `gated`
launch's agent forging over the human socket by path: a claim; under the
guard, the walled launch leaves the socket believed).

#### 10.1.1 Telling it: the confined launch, the dashboard and the inspector

Decision: KEEP the rule above (fail closed: a confined launch beside an unwalled one loses its
guard's attestation), and make it visible, so the confined launch's user
knows why their secret opens get placeholders and their writes are
refused, which launch causes it, and how to fix it. No new security
decision: everything below reads the same exposure the belief rule reads,
and none of it changes an answer.

- **The record names the launch.** `beginLaunch` takes an optional
  `sessionId` (the launcher's scope id, display only; a value not shaped
  like one is dropped, and a row rewritten by a program of that agent is
  not believed over the in-memory copy). `CacheSealStore.humanPlaneExposure`
  answers each unwalled launch with its session and start time, oldest
  first (the `session` column is added to an older store in place). Since
  2026-10-17 it also takes the launch's `home`, which is not display only:
  the arbiter keeps it (in memory, from an attested request, until
  `endLaunch`) as that session's HOME for the catalog's `~` places
  (confidentiality-plan-10 §11.13, "The launch's HOME").
- **`humanPlaneStatus`** (a `HUMAN_PLANE_OPS` member: it names sessions,
  which `sessions` keeps on the human plane): `{exposed, since, launches:
  [{pid, mode, posture, session?, begunAt?}]}`. A store that cannot answer
  is exposed with one launch of pid 0, as for the belief rule.
- **The arbiter tells each change once.** When the set of unwalled
  launches changes (begins, grows, ends), the arbiter logs it and appends
  one `config_change` event to its audit stream (`arbiter-admin`) carrying
  `humanPlane: {state: exposed | walled, since, launches, ended?}`. A
  launch's begin and end re-read the exposure at once; while exposed, a
  one-second watch re-reads it, so a launcher that dies is told as the
  end even when nobody asks. (This also fixed a doubled log line: the
  begin and end used to drop the memo, so the next read told an exposure
  that had not changed.)
- **The confined launcher tells its user** (`launcher/src/human-plane-watch.ts`,
  started by `run.ts` for a walled launch in a protecting mode with a
  human socket, `watchesHumanPlane`): it asks once before the agent starts
  and every 2 s while it runs (unref'd, 3 s deadline; a failed ask prints
  nothing, an arbiter without the op retires the watch), and prints one
  WARNING block when the exposure begins (each launch's pid, session and
  mode; what is lost in this session; the fix: stop it, or start it again
  with its file guard on, not `--mode off` and not `--no-net-guard`), one
  line when the set changes, one line when the guard is believed again,
  and, after the agent exits, a recap of each period (a full-screen agent
  may have painted over the live lines). The block told before the agent
  starts is held until the banner (the mode line, the dashboard line, the
  notices) is out, and printed whole as the last thing before the agent
  takes the terminal (2026-10-17, `holdUntilBanner`, packaging.md §5 "Last
  before the agent"); it used to print above the mode line, where a
  full-screen agent's first frame pushed it away first. `concurrentLaunchNotice` keeps
  saying only what any unconfined launch costs (its programs can rewrite
  the placeholder files); the lost attestation is the watch's to say.
- **The dashboard shows it** (dashboard.md §4.25x): `loadPolicyPanel` adds
  `humanPlane` (from `humanPlaneStatus` over the dashboard's human-plane
  client; any failure is `unknown`, never walled). The inspector's Policy
  panel draws a `human plane walled | exposed | unknown` chip beside the
  posture chips (exposed is loud and names the first launch's pid and
  session; its ⓘ drawer lists each launch and the cost). The product Home
  page shows a notice in its own words ("Another agent can reach Mandu's
  own controls."), naming each agent as its Home row does, with a link to
  its page (by process id and session when Home has no row for it), and
  the fix; the Home verdict itself is unchanged (secrets stay guarded).

Utility: one human-plane read every 2 s per walled launch, and one per
dashboard poll. Security: unchanged (the masking stays, asserted by every
test below); the new op is refused on the data socket.

Tests: `arbiter/test/unit/cache-seals.test.ts` (sessions kept, dropped,
in-memory wins, the column migration), `arbiter/test/component/human-plane-status.test.ts`
(the op, one event per change, a dying launcher told, the report still a
claim, refused on data), `launcher/test/unit/human-plane-watch.test.ts`
(the lines, the state machine, the watch over a scripted arbiter),
`dashboard/test/unit/view-model/human-plane.test.ts` (the chip, the notice,
the vocabulary sweep), `dashboard/test/unit/ui/home-js-home.test.ts` and
`egress-js-panel.test.ts` (the notice and the chip in a DOM),
`tests/stack/human-plane-exposure-notice.test.ts` (a confined and an
unwalled launch over a real server: the warning with pid, session and fix,
the inspector and Home projections through the real `ArbiterEventSource`,
the masking kept, all three cleared at the end and when the launcher dies;
the served Home naming a recorded unwalled session's agent and opening its
page),
and under a real guarded launch `tests/sandbox/exposed-human-plane.test.ts`
(the launcher's own output; with the unwalled launch already running, the
block whole and last before the agent, below the mode and dashboard lines,
and the recap after it), with `launcher/test/unit/launch-banner.test.ts`
(`holdUntilBanner`: held, released whole and in order once, live lines at
once after).

### 10.2 The observability records: believed on human, claims elsewhere

`emit`, `recordToolCall` and `reportExecTwins` used to be accepted from the
data socket like any other op (§10's last row). None feeds an arbiter decision
(verified: no arbiter reader of the event store outside the
human-plane read ops; the plan 14 suggestion sources are git, the
workspace, the model and labels; `mandu why`, `mandu status` and the
doctor read no events), but several readers outside the arbiter act on, or
present, what a program of the agent could write there:

- the dashboard picked the folder the Suggested view's Scan reads
  (`sessionCwd`, from an event's "agent" prompt block), the repository
  `/api/git` runs on (`sessionViewRoots`), the symbols the prompt-filter
  page may reveal (`findingSymbols`), and the tokens the product page treats
  as known and not secret (`valueScope`) from events;
- the inspector, the Home verdicts and the SIEM showed every event in the
  `emitter`'s name, the arbiter's own audit stream (`arbiter-admin`)
  included, and a forged burst could fold a real event into a `coalesced`
  summary;
- the SIEM's campaign rule (100220) and its lockdown keyed on fields an
  event's sender chose (a tighten-only lever);
- the inspect helper's triage put the proxy's record of a tool call (by
  `recordToolCall`, last writer wins) in front of its model as the request.

Now:

- **Events.** The arbiter stamps `claimed: true` (under the hash chain;
  the caller's own value is never taken) on every event that did not
  arrive on a believed channel: the data socket, and the human socket
  while a launch with no wall is live (§10.1). Every production emitter
  with a human client sends there (the model proxies, net-proxy, the
  launcher; fs-sync, the reply filter and the guard already did), falling
  back to the data socket (a claim) when it has none. The dashboard's
  config audit rides its admin channel. The arbiter's audit stream refuses
  a claim outright. The coalescer keys on `claimed`.
- **Readers.** The dashboard's four decisions above read believed events
  only (`believedEvents`, and the same skip in `sessionCwd`,
  `sessionViewRoots`, `findingSymbols`); the inspector's event drawer
  says "CLAIMED" and "(claimed)" beside the recorder; the SIEM exporter
  ships the field (`labels.mandu_claimed`), rule 100227 shows a claim and
  rule 100214 (and so the burst, the campaign rule and its lockdown) skips
  one. The Home counts and the invariant chip still count claims (display
  only: a claim can add a red mark, never remove one).
- **Tool calls.** `recordToolCall` is believed only from the human socket
  (the Claude proxy sends it there); a claimed record never replaces a
  believed one, and `symbolProvenance` answers a claimed one as no record
  (triage takes its provenance-free prompt).
- **Twin hints.** `reportExecTwins` has no believed writer (the exec box
  runs in the agent's tree), so every hint is a claim; its one reader, the
  Claude proxy's twin note, re-applies the twin predicate under its own
  roots. Not closed (integrity axis, frozen; protection-modes.md §10.7):
  the note spells a hinted path as the box reported it (`asTyped`), so a
  forged hint, or a shell-expanded file name, reaches the privileged model
  in clear inside Mandu's note; the fix is to count hinted paths instead of
  naming them.

Who still writes claims in production: inspect-mcp (the agent's tree), a
component with no human socket, and anything during a launch with no wall.
Utility cost: none for a component on the human socket; the product page
reveals nothing a claimed event alone made known (an inspect-mcp result's
inner tokens stay chips there), and the Scan's default folders come only
from believed model calls.

Tests (each fails without the change):
`arbiter/test/component/claimed-observability.test.ts` (the mark, the
caller's value ignored, the audit stream, the exposure, the tool-call
record), `arbiter/test/unit/coalescer.test.ts` (a claimed run folds no
believed event), the dashboard's `session-paths.test.ts`,
`prompt-filter-routes.test.ts`, `dual-lanes-detail.test.ts` and
`arbiter-source-reveal.test.ts` (the product page asks for no token only a
claim made known), the launcher's `observe.test.ts`, the SIEM exporter's
`redact.test.ts`, the parity tests (both proxies' and net-proxy's
production wiring emits on the human socket), and the stack e2e
`tests/stack/claimed-events.test.ts` (a program of the agent forging a
model call that names another folder: marked, and the dashboard's cwd and
repository are the believed ones).

The rule for a new op: if its record can lower a decision, it joins
`ATTESTED_REPORT_OPS` (believed on human, a claim on data) or
`HUMAN_PLANE_OPS` (refused on data), and its callers move to the human
socket in the same change, with a parity test over the production client.

Tests: `arbiter/test/component/guard-report-attestation.test.ts` (each
forgery over a real data socket, the same records believed over the human
socket, an older guard and proxy failing closed),
`arbiter/test/unit/provenance-store.test.ts` (the D9 block),
`tests/stack/proxy-real-client-parity.test.ts` (both proxies' production
wiring), net-proxy's `human-plane-parity.test.ts` (its production wiring:
the holder chain believed on the human socket, a claim on a data-only
wiring), `net-supervisor` `report_channel.rs`, and under the real guard
`tests/sandbox/guard/forged-reports.test.ts`.

### 10.3 Human verdicts: who spends an *Allow once*

A human's answer to an Inbox row is kept per {subject, target}, and the gates
that queue rows consult it before the law: `desymbolizationDecision` (the
network gate), `fsPathDecision` (the path gate), `escalateExec` and
`execGate`'s program-text gate (integrity, frozen), `declassifySymbol` (an
in-context read), and, from the human socket only, `decideSecretOpen` and
`decideProtectedWrite`. An *Allow once* (`scope: "once"`) answers exactly one
consultation, which spends it (`consumedAt`); the next ask queues the row
again. The first three are data-plane ops: any program of the agent can ask
them, and until 2026-10-07 its ask spent the human's *once* like the gate's,
so an injected agent could spend every *Allow once* the human gave and the
real send, asked a moment later, found it spent and asked the human again.
Nothing was released (a spent approval re-queues and holds the send), but
the human was pushed toward *Always*.

The fix has two halves, landed in this order:

1. **The gates ask on the human socket.** The net-proxy's egress decision,
   and the Claude proxy's network and path gates (`net-gate.ts`,
   `fs-gate.ts`), ride the human client their adapters already hold (§5;
   `ArbiterClientAdapter` in each package), so the ask that should spend a
   *once* comes from a channel the agent's programs cannot reach. With no
   human client the decision goes to the data socket; a human client that
   fails is a gate error (block), not retried on the data socket. The Codex
   proxy has no network or path gate (its exec gate already rides the
   human client). Parity tests over the production wiring: net-proxy's
   `human-plane-parity.test.ts` and `tests/stack/proxy-real-client-parity.test.ts`
   (with the data client closed, the gates' asks still get the one use).
2. **The arbiter takes the channel.** `consultPriorVerdict`
   (`arbiter/ipc/server.ts`) is told whether the ask may spend a *once*:
   an ask on the human socket or the admin channel (`attestedChannel`)
   spends it, as before. From the data socket an unspent *once* is read
   and never spent: a *once* denial answers (reading a refusal grants
   nothing, and fail-closed), a *once* approval is no verdict (the law
   decides; a gate that still requires approval re-files the row, and
   `recordPending` keeps an unspent answer, so the row stays armed for the
   gate). A standing answer (*Always*, *Block*) is the same on every
   channel. The Test-a-flow probe reads and never spends.
   `declassifySymbol` keeps spending from any channel: its one caller, the
   quarantined inspect child (and the OpenClaw plugin tool over the same
   core), runs in the agent's tree by design, and the read it completes is
   the human's answer itself. `decideSecretOpen` and
   `decideProtectedWrite` consult only for an attested report (§10).

**The pre-check reads, the send spends.** A WebFetch carrying a symbol is
judged twice for the same {symbol, host}: by the Claude proxy's network gate
at the tool_use (`net-gate.ts`, the per-symbol leg) and by the net-proxy
when the fetch's request reaches the wire (TLS-inspected), where the value
is put back. Both ask on the human socket, so the first ask spent the
*once* and the real send was held again: one *Allow once*, nothing sent.
The gate's ask now carries `preflight: true`: from an attested channel it
reads an approval without spending it, and spends a denial (it enacts the
refusal; no send follows). Chosen over one ask id shared by the two asks,
which would need a correlation the agent's fetch does not carry; the
pre-check releases nothing itself (with TLS inspection off it blocks
anyway), so reading the approval unspent grants nothing the net-proxy does
not judge again, and the net-proxy's ask releases exactly one send. From the
data socket `preflight` changes nothing (no once is granted there). Test:
`tests/stack/once-verdict-webfetch.test.ts` (the model proxy's gate and the
real net-proxy over one arbiter: one *Allow once*, one send, no second
hold; red before), and `once-verdict-channel.test.ts`'s preflight case.

Why "no verdict" for an approval rather than answering it unspent: an
answer the data socket could read as *allow* would be granted again on
every ask until the gate spent it, and a gate left on the data socket (the
exec box's `escalateExec` in its `Gated` mode, which runs in the agent's
tree; not the production mode, integrity, frozen) would escalate on every
ask. As no verdict it stays in AgentShell and asks, which is fail-closed.
Every production consumer of an *Allow once* now asks on the human socket
(half 1), so nothing legitimate loses its use. A denial is answered rather
than ignored because ignoring it would let the law, which may have changed
since the row was filed, decide a pair the human refused.

The channel alone decides, not the exposure of §10.1: while a launch with
no wall is live its agent reaches the human socket and can spend a *once*
there, as it can call the human-plane ops themselves; narrowing the spend
to `attested()` would break *Allow once* for every confined session beside
such a launch while closing nothing the exposure does not already open.

Cost: none for a session whose proxies hold a human client. A component
with no human client (none in production) asks on the data socket, where
an *Allow once* is never granted: its send stays held until the human
answers *Always*.

Tests: `arbiter/test/component/once-verdict-channel.test.ts` (red before:
a data-socket ask on `desymbolizationDecision`, `fsPathDecision` and
`escalateExec` spent or was granted the *once*; a *once* denial read
without spending; *Always* on every channel), `rung3-completes.test.ts`
(the in-context read still spends from the data socket), the stack e2e
`tests/stack/once-verdict-net-proxy.test.ts` (the real net-proxy: the
agent's asks on the data socket leave the *once* armed and the real send
is released exactly once), and the parity tests of half 1, which also show
that a data-only wiring is not granted the *once*.
