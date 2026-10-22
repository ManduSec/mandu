# Policy surface — one law, its editors, and how it is shown

**Status: BUILT (as of 2026-10-03).** The data law lives in one file,
`policy.yaml`, written only by the arbiter and compiled into an immutable law
(§2.1, §2.2). Human decisions travel on an admin channel the agent cannot
reach (§2.6). Live and test traffic run in separate tenants (§2.7). A model
may write rules, but the confined agent can only tighten the law; only a human
relaxes it (§8). Every decision names the rule or verdict that made it, and
the law is shown in the dashboard and by `mandu why` (§9). **Not built**, each
marked where it appears: the impact preview and save-time conflict detection
(§2.4); the *this session* egress verdict scope, Block-with-comment and
repeat-block escalation (§2.5); a boot-time last-known-good cache (§2.1);
`mandu policy show` and policy import/export (§3.1); the `mandu doctor`
ptrace check and the Landlock named-socket kernel test (§2.6); the
deferred items of §6 and §8.8. Terminology: paper *T-LLM* = repo
*privileged LLM*; *AgentView* = repo *Agent File System*. Nothing here
changes the invariant ([mandu.md](../architecture/mandu.md)): a secret
reaches a model only as a `$MDU:*` symbol unless its level admits that model,
and with the integrity axis on, untrusted data reaches T-LLM only as a symbol.

**How this document is laid out.** §1–§7 keep the numbering of the former
`policy-surface.md`. §1 is the review that started the redesign
and its findings F1–F8, each with what closed it. §2 is the model: two files
by owner, the compiled law, destinations, dispositions and hit counts, the
decisions that mint rules, the admin channel and the tenants. §3 is the survey
of shipped security products the UI borrows from, and what it rejects. §4 is
the dashboard's information architecture, §5 the tests, §6 the build order
and what remains, §7 what `mandu.db` holds. §8 (formerly
`policy-surface.md §8`) is the contract that lets a model write the law:
the monotonic split, typed edits, proposals, the hold on relaxing hand edits,
the `mandu-policy` MCP server and the "Describe what you want" box. §9
(formerly `policy-visibility.md`) is how the law is shown: `RuleRef` on every
usage decision, the Policy panel, trace ⇄ policy links, the verdict audit
trail, and `mandu why`.

## 1. Where it started: the 2026-09-05 review

Before the redesign the law was spread over five stores with five lifecycles
and five edit paths: built-in rules in TypeScript
(`arbiter/policy/claude-code-inbound.ts`, `tool-outbound.ts`,
`fs-outbound.ts`, `policy-interface.ts`, `exec-gate.ts`, `session-egress.ts`;
rule ids in `rule-ref.ts`); a YAML overlay (`load-policy.ts`,
`tool-overrides.ts`) that no production path could reach; the protection axes
and chokepoint switches in `config.toml`; human decisions (egress verdicts,
Locked files = path labels, session watermarks, derived labels) in
`mandu.db`, the file whose documented remedy for a schema change is deletion;
and volatile arbiter state (pause/lockdown posture, session→spec bindings,
exec decision stores).

### 1.1 Findings

| | Finding | Closed by |
|---|---|---|
| F1 | User-authored state (Locked files, standing verdicts) lived in the disposable `mandu.db`; a schema bump erased it. | Labels are law in `policy.yaml` `paths:` (§2.1). Verdicts stay instance-bound in `mandu.db` by design; DB-only labels get a boot notice and a one-click move. |
| F2 | The user-editable YAML path was dead code: `policyPath` was an in-process option nothing set. | `MANDU_POLICY_FILE` (§6 item 2). |
| F3 | The engine was mutable module globals; no safe hot reload. | `compilePolicy` (§2.2). |
| F4 | "Always allow" did not generalize: verdicts key on `(symbol, destination)` and symbol hashes are random per allocation, so a standing verdict covered one instance. (Under `MANDU_DETERMINISTIC_SYMBOLS` the hashes are sequential, so persisted verdicts *collide* across test runs.) | User rules of kind `release`, minted from an ask (§2.5). |
| F5 | **Security gap:** no op-level authorization on the arbiter socket. `MANDU_ARBITER_SOCK` is in the agent's environment, so a Bash command could call `resolveEgressApproval`, `setPathLabel`, `setSessionPosture` (with `allowRelax`) or `deleteSession`; an injection could approve its own egress. | The admin channel (§2.6). |
| F6 | The UI mirrored the storage fragmentation (Policy panel, Secrets panel, Protection drawer, Simple cards; `config.toml` switches in no UI). | One information architecture (§4). |
| F7 | Tests were strong where the policy is code and weak where it is data; live e2e inherited the host's verdicts, labels and posture. | Document round-trip tests and tenancy (§5, §2.7). |
| F8 | Tests and live traffic shared one tenant: test asks in the human's Inbox, test verdicts in the standing list, a scenario's posture governing the next human session. Tagging by session-id prefix cannot fix shared state. | Tenancy (§2.7). |

## 2. The model

### 2.1 Two files by owner; one compiled law

The protection axes stay out of the policy document: the launcher reads the
confidentiality axis at launch (to decide the secret-confinement wrap) and the
arbiter reads it at boot, so they belong to the launcher's file. Rule, by
owner:

- **`config.toml` — machine setup, launcher-owned.** Which chokepoints run and
  how they are sandboxed (axes, exec-box, Landlock, net-guard, ports). Applies
  at the next launch; the UI shows a pending "applies at next launch" bar (the
  OPNsense *Apply changes* pattern).
- **`policy.yaml` — the data law, arbiter-owned.** What is trusted on the way
  in, what may flow out and to where, what is locked, and the disposition of
  every rule. Applies live. Path: `MANDU_POLICY_FILE` (config.toml
  `policy-file`), default `~/.mandu/policy.yaml`. An administrator's layer,
  when installed, is loaded first and the user's file is judged against it
  ([model-endpoints.md](../confidentiality/model-endpoints.md)).

```yaml
# As built; arbiter/policy/policy-file-validate.ts is the schema.
version: 1
lists:                                   # named, reusable (firewall "aliases"), referenced as @name
  trusted-docs: [ "https://docs.python.org/", "https://nodejs.org/api/" ]
  my-services:  [ "api.github.com", "*.internal.example" ]
inbound:                                 # origin lists (@lists expand here)
  url: { default: UNTRUSTED, trustedList: [ "@trusted-docs" ] }
  dir: { default: TRUSTED,   untrustedList: [ "~/Downloads" ] }
  command: [ { id: git, trustHelp: true } ]   # per-command exec-output entries
tools:                                   # per-tool inbound/outbound overrides
  mcp__github__get_issue: { inbound: UNTRUSTED }
paths:                                   # Locked files, as law on disk
  - { path: "~/.ssh",   level: no-model }
  - { path: "~/notes",  level: any-model, bindings: [ "api.anthropic.com" ], recursive: true }
  - { path: "**/*.pem", level: no-model }   # gitignore-style pattern (confidentiality.md §6.1)
rules:                                   # dispositions on built-in rules that ASK by default (§2.4)
  "egress:untrusted-destination": { mode: block }   # ask (default) | block
user_rules:                              # §2.5 — one kind today: release
  - { id: r-0007, kind: release, from: { host: "docs.python.org" }, to: { host: "@my-services" },
      mode: allow, reason: "docs → my own API", by: "dashboard", added: "2026-09-05", expires: null }
  - { id: r-0008, kind: release, to: { host: "*.pastebin.com" }, mode: block }
  - { id: r-0009, kind: release, to: { host: "*" }, mode: audit }   # counts, never decides
destinations:                            # §2.3 — reachability, applied at the next launch
  - { host: "registry.npmjs.org", connect: allow }
```

Later sections added `blobs:`, `models:`, `env:` and reader lists on
`paths:` (confidentiality docs); the classifier of §8.3.2 covers each.

**One writer.** The arbiter is the single writer of `policy.yaml`, as it is
of the DB (`policy/policy-document-store.ts`): a client sends a document or
typed edits over the admin channel (§2.6), the arbiter validates strictly,
writes atomically (tmp + rename), rebuilds and swaps the law, and lands one
audit line (`policy_change`, emitted as the `config_change` kind) on the
`arbiter-admin` stream. A hand edit is picked up by a 2 s mtime poll through
the same validate → rebuild path; since 2026-09-28 a hand edit that
*relaxes* the law is held for a human (§8.4.6). A write of the policy
surface (§8.4.2: an agent's tightening, an applied suggestion, an approved
proposal, an Undo) is written into the person's text and keeps their
comments (§8.4.6 "Comments are kept", 2026-10-09); so, since 2026-10-18,
is every other write: the developer view's whole-document apply, a minted
rule, the label migrations and the arbiter's reader pins (§8.4.6 "The
writes outside the surface"). A whole document names the law it was built
from (`lawHash`, which `policyDocument` answers) and is refused as stale
once the law in force is another one, so a change that landed after the
read is never undone (§8.4.6 "A whole-file apply names the law it was built
from", 2026-10-18).

**Failure semantics.** A *missing* file means the built-ins are the whole
law, and the law source says which path was looked for. An *invalid* file on
reload keeps the law in force (`policyFile.valid: false` plus the problems
on the snapshot, and a banner). An invalid file at **boot** makes the arbiter
refuse to start, listing every problem — never "warn and run the built-ins",
because a user file may tighten the law and an unparseable "lock `~/.ssh`"
must not silently unlock it. (A `policy.compiled.json` last-known-good cache
that would let a boot survive an invalid file was proposed and is not built.)
The validator also rejects silent contradictions, judged under the
*effective* default: an absent `default` is the category's built-in one
(`BUILTIN_ORIGIN_DEFAULT`: url UNTRUSTED, dir and channel TRUSTED), so a
`trustedList` under a TRUSTED default is an error (§8.3.2 has the incident
behind this).

**What stays in `mandu.db`:** machine state only — symbols, provenance
taint, derived and session labels, the per-symbol approval ledger (F4: those
rows are bound to symbol instances in the same file), `rule_hits` (§2.4), and
the policy proposal tables (§8.4.5). Document `paths:` compose with DB labels
in one lookup (a DB row wins on the same path) and show in the label ops as
source `policy-file`. A boot notice names DB-only labels; the Rules page moves
them into `paths:` and deletes the rows (admin op `movePageLabels`, recorded
`via: "move-labels"`, dashboard.md §4.25m); the developer view's
`exportDbLabels` copies them.

### 2.2 Compile, don't mutate (F3)

```ts
compilePolicy({ specId, document, lawSource }): CompiledPolicy   // arbiter/policy/compiled-policy.ts
```

is pure: it copies the built-in inbound tables, outbound maps and exec-output
entries for every spec, applies the document's `tools:` and `inbound.command`
overrides to the boot spec's copies (`applyToolOverrides`,
`applyCommandOverrides`), carries lists, labels, dispositions, user rules and
destinations, and freezes the result. One pointer holds the law in force
(`getCurrentPolicy` / `swapCurrentPolicy`, compiled lazily); every engine
accessor (`getActiveInboundSpec`, `getToolInboundSpec`, `destinationKind`,
`classifyExecOutput`, the snapshot) reads through it, and
`setActiveInboundSpec` recompiles under the new spec id. Session→spec
bindings stay a runtime map. `relaxationsOf(compiled)` lists every way a law
is looser than the built-ins (the Relaxations list; kinds in §8.1).

Tests (`compiled-policy.test.ts`): the built-in compile is deep-equal to the
pristine constants and the dashboard snapshot is byte-identical; an
overriding document changes no built-in constant and the compiled tables are
frozen; `relaxationsOf` is ∅ for the built-ins and for a purely tightening
document and exact for a relaxing one; after a swap every accessor follows.

### 2.3 Destinations answer two questions, not one

*Reachability* (may the agent's processes connect at all — the kernel
connect-guard, `net-guard`, decided at launch) and *release* (may a masked
or secret value be desymbolized toward it — the arbiter's egress gate,
decided live) are different questions with different enforcers, so the law
keeps them apart:

- **`destinations:`** — `{ host, port? (443), proto? (tcp), connect: allow,
  reason? }` compile (lists expanded) to connect-guard specs
  `proto:host:port`. The data-plane op `netConnectAllow` serves them from the
  law in force; the launcher reads them at launch (`net-guard-law.ts`,
  fail-soft toward tighter: no answer means no extra allow) and appends them
  as `extraAllow`. They are additive in every posture and never narrow: the
  permissive `*:443` / `*:22` fallback and any `--net-allow` curation are
  untouched, so one operator rule cannot break other workflows. Each one is a
  Relaxation (`connect-allow`). `connect: deny` is refused by the validator,
  naming the alternative (a release Block): the guard is allow-list only.
- **Release** is `user_rules` of kind `release` (§2.5), consulted by the
  egress gate before its fail-closed default. Secret bindings stay per path
  label.

### 2.4 Rules with dispositions, audit mode, hit counts

**Dispositions.** Every built-in rule keeps its fail-closed default. A
built-in egress rule that *asks* by default (`dispositionableRuleIds()`) may
be set to `mode: block`; the ask then becomes a deny with nothing queued
(`egress:disposition-block`). The vocabulary is Microsoft Defender ASR's —
**Block / Ask (Warn) / Audit**, plus **Off** for user rules. Nothing turns
symbolization off except the protection level `off` with its typed
confirmation. **Audit** (user rules) evaluates and counts (`auditHits`)
without deciding: the DLP simulation mode, how a user tests a rule first.

**Hit counts.** Every deciding rule id is counted in `rule_hits` (hits, audit
hits, last hit), served as `hits` and shown like a firewall's state counters,
so an unused relaxation is visible.

**Precedence, in one sentence the UI prints verbatim** (after Claude Code's
`permissions`): *a standing verdict for this exact item wins; then your rules
— Block beats Ask beats Allow, regardless of how specific a rule is; then the
built-in law, top to bottom, first match wins.* Specificity-blind ordering is
less expressive than Little Snitch's ladder but fits in one line; products
disagree (Defender's network indicators resolve Allow > Warn > Block), so the
sentence is printed, not assumed.

**Relaxations are un-hideable.** Every EDR incident review ends at an
exclusion someone added. Every relaxing rule (`relaxationsOf`: trusted
origin, trusted tool, release allow, a binding, a label below the catalog, a
connect allow, …) is listed in an always-visible **Relaxations** list with
kind, scope, source, hits and expiry; "none" is said out loud. Broad ones need
the typed confirmation. Every user rule may carry `expires`.

**Not built:** the *impact preview* ("in the last 7 days this would have
masked N / allowed M", from the symbol table's stored origins; Lakera's
simulator) and *conflict detection* on save (refusing an Allow that an
existing Block shadows, naming the row).

### 2.5 Decisions that mint rules (F4) — the Little Snitch alert, adapted

**As built.** `user_rules` of kind `release` — `from.host` (optional;
literal, `*.suffix` or `@list`) → `to.host` (`*` = any), `mode
allow|block|audit|off`, optional `expires` — are consulted by the egress gate
after a standing verdict and before the built-in branches: Block beats Allow;
an unknown origin never satisfies a rule narrowed by `from`; a SECRET symbol
never yields to a user rule (the bound-destination path stays
authoritative). A pending network ask offers **Always allow from <origin>**,
which mints the release rule and approves once (the approvals wire carries
`originHost`, read from the symbol table).

The ask stays per symbol (that is what the gate sees); the answer gains a
scope. The full design:

```
✋ The agent wants to send a masked item to api.github.com
   item      $MDU:WebFetch[3f9a].text — from docs.python.org (fetched 2 min ago)
   scope     (•) this item      ( ) anything from docs.python.org
             ( ) anything from *.python.org      ( ) anything from any source
             → to (•) api.github.com  ( ) any destination
   for       (•) once   ( ) this session   ( ) always   ( ) until  [ 2026-10-05 ]
   [ Allow ]  [ Block ]                              details ▸  why was this asked?
```

*This item · once / always* are the per-symbol verdicts of §9.8.7. An
*anything from …* choice mints a `release` rule (never inbound trust: the
narrower relaxation is the default), shows the literal rule before saving, and
lands in Relaxations marked as minted from an alert.

**Not built:** the *this session* egress verdict scope (Little Snitch's
*Until Quit*); **Block with a comment** that reaches the agent as the denial
reason; **repeat-block escalation** (N identical blocks in a session become
one Inbox item). Why scopes matter: Anthropic's auto-mode posts (Aug 2026)
report users approving ~97% of per-action prompts, so asks must be rare and
rule-shaped.

### 2.6 The human/agent boundary — an admin channel with no filesystem name (F5)

**Why an inherited fd.** A second socket *path* is no boundary against
same-uid processes: mode 0600 means nothing to the same uid, `net-guard`
passes AF_UNIX through by design (`guard_kernel.rs`), and Landlock's
filesystem rules do not mediate `connect(2)` on a named Unix socket. What
works without privilege is **an fd inherited at spawn**: the dashboard's
`Supervisor` spawns the arbiter with a fourth `stdio` entry (a socketpair),
the child is told by `MANDU_ADMIN_FD=3` (`supervisor-defs.ts`), and the
arbiter wraps it as an already-connected admin connection (`ipc/server.ts
attachAdminChannels`). There is nothing on disk to connect to. The extra fd
survives `sh → node` but not the `tsx` CLI or `npm run`, so the supervisor
runs `node --import tsx ipc/server-main.ts` directly.

**Who owns the arbiter.** The launcher's autostart starts the *supervisor*
(`DASHBOARD_AUTOSTART=arbiter`), which owns the arbiter and its fd, so the
admin channel exists from the first launch (`startArbiterInstance`). If the
supervisor does not promote its socket within the readiness deadline
([runtime-instances.md §14](../architecture/runtime-instances.md) §6) it is stopped and the
bare arbiter starts, never a second resident one
([runtime-instances.md](../architecture/runtime-instances.md) §10);
`MANDU_AUTOSTART_SUPERVISOR=0` opts into the bare start. An arbiter the
dashboard *adopted* has no admin channel; its human-decision controls answer
503 with the remedy (restart the services from Settings).

**Three channels, nested: admin ⊇ human ⊇ data.** One matrix
(`channelRefusal` in `ipc/server.ts`) decides before any handler runs.

- **data** (the named socket every interceptor and the agent's tools dial):
  symbolize, classify, decisions, emit, `recordToolCall`, taint ops, and state
  changes that only *add or raise*: `registerSecret`, `labelWrittenPath`,
  `declassifySymbol` (the MCP inspect child's quarantined read, a
  policy-decided act). `resolve` with `deep: true` (the quarantined U-LLM)
  stays here and refuses `no-model` rows whatever the axis.
- **bind-once** (any client, first call wins): `setSessionSpec`. A bound
  session cannot move to another spec, and a session with classified traffic
  cannot be bound at all; the proxy binds at boot, before the agent exists.
  The bindings are the arbiter instance's, for its life (in memory, released
  by its close): another arbiter, in the same process or after a restart,
  neither sees nor blocks them ([agent-e2e-harness.md](../testing/agent-e2e-harness.md) §4).
- **human** ([arbiter-human-plane.md](../architecture/arbiter-human-plane.md),
  since 2026-09-30): ops that return ORIGINALS (`desymbolize`, shallow
  `resolve`, `events`, `subscribe`, `sessions`, `verifyEvents`) and the
  reply-row-reservation ops (`symbolShape`, `setSessionRelay`,
  `sessionRelay`; [reply-row-reservation.md](reply-row-reservation.md) §3.3,
  §3.6). Served on `<runtime>/human/<instance>.sock` in a `0700` directory the
  launcher walls off from the agent (net-guard's always-deny unix entry, the
  secret-twins `--tmpfs`, Seatbelt, never in Claude Code's
  `allowUnixSockets`). A path is acceptable here, unlike for admin ops,
  because those walls exist and its consumers are not the arbiter's
  children. The data socket refuses these ops (`human-plane: …`).
- **admin** (the inherited fd only): `resolveEgressApproval`,
  `forgetEgressApproval`, `setPathLabel`, `removePathLabel`,
  `removeDerivedLabel`, `setSessionPosture`, `deleteSession`, and the policy
  writers (`applyPolicyDocument`, `mintUserRule`, `exportDbLabels`,
  `resolvePolicyProposal`, `undoPolicyChange`, `dismissSuggestion`, …).
  `ADMIN_ONLY_OPS` is the catalog; elsewhere they answer `admin-only: …` and
  the refusal is logged. An in-process `dispatch()` defaults to admin: a
  caller holding the server object is trusted by construction.

**Dashboard side.** Reads ride the human socket; writes ride an admin client
resolved per call from the supervisor's current channel. Both boundary
failures (no channel, an "admin-only" refusal) map to **503**. Every mutating
HTTP verb passes the CSRF header check and then needs an **admin session**
cookie: without `DASHBOARD_PASSWORD` it is earned by a one-time sign-in
link (*Signing in*, below), or by opening `<base>/login?token=<per-boot
token>`, which the dashboard prints to its stderr only on a TTY (or with
`DASHBOARD_PRINT_ADMIN_LINK=1`; a service log is same-uid-readable).
`DASHBOARD_ADMIN_TOKEN` pins the token (readable from `/proc/<pid>/environ`
by the same uid); `DASHBOARD_TRUST_FRONT=1` treats allowlisted non-loopback
peers (an authenticating reverse proxy) as admin, never loopback. With a
password, the password session is the admin session. **Since 2026-10-05 a
read that can carry a real value needs it too** (dashboard.md §6 "Reads and
the admin session", `server/read-gate.ts`): the session's events and live
stream, the HumanView files and diffs and the product's agent page are
served without it only as the signed-out projection (what the AI saw, no
original, no symbol value), and the logs and run output are refused (403).
A loopback read used to be trusted as the human's; a program the agent runs
reads the same port, so the sign-in is what tells them apart for reads as
it does for writes. Every request must also name this dashboard in its
`Host` header (loopback at the bound port, or a configured name), so a web
page that rebinds its own name to 127.0.0.1 is refused (421). A GET needs
the session with the CSRF header explicitly (the gate below) where it
serves text an agent's process must not read
off the loopback port: the policy file (`GET /api/policy/document`, which
holds the prompt filter's exceptions), the file browser's listing, the
Suggested view, the sensitivity labels, and the prompt filter's filters,
packs, held messages and Settings section (dashboard.md §4.25y, §4.31;
`server.ts requireAdminRead`, one gate for all of them). History and the
rule-change cards (`GET /api/policy/changes`, `/api/policy/proposals`) stay
open but hide a prompt exception's pattern from a read without both
(`adminRead`, plan 15 §13.7 item 4). On the arbiter, the exceptions'
patterns are the human-plane `promptExceptions`, and the data socket's
`policyDocument`, `policyProposals` and `policyChanges` answer with each
pattern replaced by a placeholder and `patternHidden: true` (the file's text
only in its `match:` values; `policy/prompt-pattern-redact.ts`). The
dashboard reads those three on the human socket, where they answer in full;
the validator refuses the placeholder, so nothing read on the data socket
can be written back over a pattern (plan 15 §13.7 item 4).
Test rigs serve the admin channel on a path too (`MANDU_ADMIN_SOCK`, with a
loud warning; `scripts/dev-arbiter.sh` exports it).

**Signing in (2026-10-05; links retired 2026-10-22).** *Superseded:* since
2026-10-22 a person signs in with the Mandu dashboard account
(dashboard.md §6.z): one username and password, a scrypt hash in the Mandu
home, asked on the dashboard's own sign-in page; with no account yet the
dashboard serves nothing. No link is minted any more, and the human-plane
socket below only says how the dashboard signs a person in (account, none
yet, unusable) and answers the end-of-session line. What follows is the
design the links had, kept for its reasoning about the agent's reach.
The per-boot link alone left the default flow
with no way in: the launcher's stack autostart and `mandu dashboard` start
the dashboard as a background daemon whose stderr is a log, so the link was
never shown, no password is set up, and every held send timed out (fail
closed, but the product's main loop was dead). The human now gets a
**one-time sign-in link** in their own terminal, over a channel the agent's
world cannot reach:

- *The channel.* The dashboard serves a second listener, a Unix socket in
  the arbiter's human-plane directory: `<runtime>/human/dashboard-<pid>.sock`
  (`dashboard/src/sign-in.ts serveSignInChannel`, named in its registry
  entry as `signInSock`). One NDJSON op, `signInLink` (and, since
  2026-10-21, `sessionKept`, which hands the launcher its end-of-session
  line and no credential: dashboard.md §4.25ah). Every wall the
  launcher builds around that directory covers it: the guard's always-deny
  `unixDeny` entry (refused on the opened inode, so a symlink or hard link
  is refused too), the secret-twins `--tmpfs`, Seatbelt, the Unix allow-list
  and Claude Code's `allowUnixSockets` filter
  ([arbiter-human-plane.md](../architecture/arbiter-human-plane.md) §6). So
  the boundary is the same one that keeps originals off the agent's world,
  not the secrecy of a file or a log: the agent's Bash, its MCP servers and
  hooks, and `mandu dashboard` run inside its sandbox all get `EACCES` (or
  `ENOENT` under the wrap's tmpfs).
- *Who asks.* The launcher, in the human's terminal, after the stack is up
  and **before** its own launch is on the arbiter's record (`beginLaunch`)
  and before the agent exists; it prints the link on its dashboard line,
  which is printed before the agent takes the screen: in the launch's one
  banner line by default (`… · dashboard http://127.0.0.1:P/login?ticket=…
  (the link signs this browser in, once) · …`, packaging.md §5), on the
  dashboard line under `--verbose` (`mandu: dashboard
  http://127.0.0.1:P/login?ticket=… (approve requests, see what was
  protected; the link signs this browser in, once)`). A reused
  dashboard mints a fresh link for each launch. `mandu dashboard`, run by the
  human, asks too and prints `sign in (this link works once): …` under its
  URL (`launcher/src/dashboard-sign-in.ts`).
- *Never into a file.* The kept copy of the dashboard line (launch.log, the
  launch's own log that `mandu log` reads, the `launch_posture` event) has
  no link, and the banner line that carries it is never written to a log; the link is asked for only when the
  output is a terminal (stderr for a launch, stdout for `mandu dashboard`),
  or with `MANDU_PRINT_SIGNIN_LINK=1`. A launch whose output goes to a log (a
  harness, the dashboard's own Watch runs) asks for none.
- *The ticket.* 128 random bits, kept in the dashboard's memory by its hash,
  good for ONE sign-in and for 12 hours (the launch line is printed long
  before the first approval arrives); at most 64 outstanding, the oldest
  dropped. `GET <base>/login?ticket=…` spends it and sets the ordinary admin
  cookie. A used, expired or guessed ticket earns nothing: the answer is a
  403 page that says what to run (a browser that already holds the session
  is just let in, so an old launch line still opens the dashboard). Used
  links in browser history are dead; an unused one in scrollback dies with
  its 12 hours or the dashboard.
- *Fail closed.* While a launch whose agent can reach the human-plane
  directory is on an arbiter's record (`humanPlaneStatus`,
  arbiter-human-plane.md §10.1), a program of that agent could be the caller,
  so the socket mints nothing and answers why, naming the launch, with the
  remedy (quit it or relaunch it walled, or set `DASHBOARD_PASSWORD`). A
  launch records its exposure only with its own arbiter, so the dashboard
  asks EVERY arbiter whose human socket is in the directory (the test
  tenant's, a pinned one) and its own source (`combinedHumanPlaneStatus`); a
  socket nobody listens on (a dead arbiter's file) is skipped. An exposure
  the dashboard cannot read (a live arbiter that fails or lacks the op,
  nothing answering, the file source of a demo) mints nothing either. A
  launcher with no wall asks for its own link before its `beginLaunch`, so
  its own record does not cost it the link. A password, Basic-auth or
  account dashboard mints no link (its credentials are the session) and the
  launcher says "sign in with its password", "… with its username and
  password" or "sign in with your Mandu dashboard account". The launcher dials only a socket that
  lies directly in its runtime's human-plane directory (a planted registry
  entry naming another path is never dialled), and without a link it prints
  the plain line plus one `mandu: ! no dashboard sign-in link: …` line.
- *The refusal says what to run.* `ADMIN_SESSION_REQUIRED`, the product
  page's sentence (`home.js SIGN_IN_WORDS`), the inspector's and the
  no-password `/login` page all say: run `mandu dashboard` in your own
  terminal and open the sign-in link it prints (or use the password).

- *The dashboard account (2026-10-22, dashboard.md §6.z).* One username
  and password for the whole dashboard, set by `mandu dashboard
  --set-password` in the person's own terminal and kept as a salted scrypt
  hash in `~/.mandu/state/dashboard-account.json` (0600). While it is set,
  every request past the Host check needs its sign-in session (the
  dashboard's own sign-in page, never the browser's prompt) or its
  credentials as a Basic header, and no ticket is minted. The file is a
  same-uid file: a confined agent cannot reach it (the Mandu home is hidden
  and write-protected for every confined launch, on-disk-layout.md §4), a
  program of the person outside Mandu can, as it can reach
  `dashboard.env`; a file that is not the person's own private regular file
  signs nobody in, and a change while the dashboard runs ends every session,
  is logged and is shown on Home. `DASHBOARD_BASIC_AUTH` moves into it once.

Who can obtain an admin session. Before: whoever saw the dashboard's stderr
on a TTY (in the default flow, nobody), whoever knows `DASHBOARD_PASSWORD` /
`DASHBOARD_BASIC_AUTH` / the dashboard account / a pinned
`DASHBOARD_ADMIN_TOKEN`, or an allowlisted authenticating front. After: the same, plus any process of the account
OUTSIDE an agent's walled world (the human's terminal, through the launcher
or `mandu dashboard`) while no unwalled launch runs. Never a program inside a
walled agent's world.

**Residuals.** Same-uid `ptrace` / `pidfd_getfd` defeats any same-uid
boundary; the design assumes Yama `ptrace_scope ≥ 1` (the Ubuntu default),
and `mandu doctor` warns when it does not hold (0, or no Yama;
rootless-confinement-ubuntu-2404.md §3.3, since 2026-10-07). A kernel-tier test of the Landlock
named-socket negative is not written. The sign-in socket inherits the human
plane's residuals (arbiter-human-plane.md §8): a same-uid process outside
the agent's tree can ask for a link, as it can read originals there; a link
printed to a terminal is as private as that terminal, so an agent that can
read the screen (the X11 display, which the Unix allow-list admits by the
user's choice, `docs/guarantees.md`; a terminal multiplexer whose socket a
user allowed) can read an unused link before the human opens it; and a
process that can stop the dashboard and start its own (an unwalled agent can)
holds that dashboard's sessions. An unwalled launch whose arbiter keeps its
human socket under ANOTHER runtime directory is not on any record the
dashboard reads, and nothing walls its agent off this directory. Tests: §5
*Boundary*.

### 2.7 Two tenants: live and test (F8) — tenancy, not tagging

- **The stamp is `event.tenant: "live" | "test"`** (`origin` already means
  who ran a test, `runtime` where). The launcher passes it to every child as
  `MANDU_TENANT` and to the model proxy as `x-mandu-tenant` (packed into
  Claude Code's single custom header like the batch id). The proxies, the
  reply filter and the Rust emitters (`event::stamp_tenant`) stamp what they
  emit; the harness, `scripts/dev-arbiter.sh` and the test-runner export
  `MANDU_TENANT=test`.
- **The arbiter has a tenant identity** (`MANDU_TENANT` or the `tenant`
  option; `hello` reports it). A tenanted arbiter refuses an `emit` stamped
  for the other tenant (`tenantMismatchError`) and stamps unstamped events
  with its own; an untenanted (legacy) one accepts everything. The launcher
  pre-flights it (`tenant-preflight.ts`: one `hello`; the other tenant stops
  the launch with the remedy; an unreadable hello warns and proceeds —
  tenancy is hygiene, not the invariant).
- **The test arbiter is the supervisor's fifth service** (`test-arbiter`):
  the same daemon, `MANDU_TENANT=test`, a pinned socket under `<runtime
  base>/test/arbiter.sock` (never the live rendezvous), its own DB and event
  dir (`testTenantPaths`). The supervised live arbiter runs
  `MANDU_TENANT=live`. The test-runner points suites at the test arbiter;
  per-run private arbiters remain valid test arbiters.
- **One store per request.** The dashboard holds a second event source over
  the test arbiter; each request is served for one tenant (`?tenant=`, else
  the `mandu_tenant` cookie, else live), and the sidebar, trace, Approvals,
  Policy, secrets and posture follow. `GET /api/tenants` reports `{tenants,
  current}`; a stale test cookie falls back to live. The inspector's topbar
  has a **● Live / 🧪 Testing** switch; the test tenant tints the topbar and
  prefixes the title with `[TEST]`. The cookie is the inspector's: the
  product page (`/`) never reads it, since a person's own agents are in the
  live store; `/api/home`, `/api/home/agent` and every request the product
  sends (`X-Mandu-Front: product`) are served for live unless `?tenant=`
  names a tenant. A tenant whose arbiter is unreachable answers 503
  `{error, tenant, unreachable: true}` instead of a bare 500.
- **Classification by stamp first.** A `test` session always carries the
  `"test"` tag, a `live` one never a test tag; unstamped sessions fall back to
  the id-prefix tags (`tenantedTags`, `buildSidebarSections`).

Open: the sidebar's Testing section stays until legacy unstamped test
sessions age out of the live store.

## 3. What shipped products do, and what to borrow

From a survey of vendor documentation (2026-09-05; sources in §3.4).

### 3.1 Patterns adopted

| Pattern | Seen in | Mandu mapping |
|---|---|---|
| Rule modes Block / Warn / Audit / Off | Defender ASR | dispositions (§2.4; Warn = Ask) |
| Exclusions as a first-class audited list, with expiry | SentinelOne, CrowdStrike, Defender indicators | Relaxations and `expires` (§2.4) |
| Pending queue + History that "serves as an audit log", with undo | Defender Action center | Approvals = pending + History (§4) |
| A blocked change must not "appear to succeed" | Defender tamper protection | a refused write renders as refused (503 / `applied:false`) |
| Detection never weaker than prevention | CrowdStrike ML sliders | a Block rule is always logged; Audit is never less visible than Block |
| Ordered rule table, first match wins, state counters, named aliases, "Apply changes" banner | pfSense / OPNsense | the rules table (§4), `lists:` and the pending bar (§2.1) |
| Connection alert with scope chooser and durations; unconfirmed-rule marker | Little Snitch 6, LuLu | the §2.5 ask |
| Policy tester ("which policy matched?") | Cloudflare Access | Test a flow (§4) |
| Environment switch with colour-coded chrome | EDR consoles, Cloudflare | the tenant switch (§2.7) |
| Allow / Ask / Deny, deny > ask > allow, each rule shows its source | Claude Code `permissions` | the precedence sentence (§2.4); the *Source* column (§4) |
| Sandbox mode × approval policy as orthogonal knobs | Codex CLI | Settings (launcher sandbox) vs Policy (arbiter law) |
| Effective-policy dump as text | Claude Code, ToolHive | **not built:** `mandu policy show` and `policy.yaml` import/export |
| Data-flow rules typed over trace events | Invariant Guardrails | the closest published analogue of the symbol-flow gate |

### 3.2 Patterns rejected or deferred

- **Rule packs** (Little Snitch rule groups) are a supply-chain vector for a
  relaxation list. **Built in a reduced form** for the one part of the rule
  set that is already data, the consumer table (`flow-taint.ts`;
  [comparisons.md](../confidentiality/comparisons.md) §3.3): a JSON pack with
  a detached Ed25519 signature over its exact bytes
  (`arbiter/policy/consumer-packs.ts`, `scripts/sign-pack.mjs`), loaded only
  from `<config>/mandu/packs/` and only when a key in
  `<config>/mandu/pack-keys/` verifies it. A pack only adds rows (built-ins
  are consulted first); a bad pack is refused whole, logged and named on the
  launch banner; every pack row is a relaxation (`pack-consumer`, with pack,
  version and key; op `consumerPacks`). The repository ships no key. Inbound
  specs stay code until a second party needs to ship them.
- **Sensitivity sliders and ladders** (CrowdStrike, Lakera): Mandu's rules are
  structural; there is no false-positive rate to trade.
- **A generic expression builder** (Cloudflare): more power than the model has
  dimensions.
- **An auto-approval classifier** (Claude Code auto mode, Cursor): it replaces
  the human on a probabilistic judgement; a human decides relaxations.
- **Stalling the agent while the human decides**: the arbiter denies and pends
  so a run never hangs on a person; a bounded hold is deferred (§6).

### 3.3 Anti-patterns to avoid

Exclusions hidden behind a settings sub-tab; a rule list that mixes instance
approvals with rules (F4); prefix allow-lists presented as a security
boundary (Claude Code's `Bash(git * main)` matches `git -c core.fsmonitor=…
main`; Mandu's allow-list decides reachability, the symbol gate decides
release); per-action prompts at scale; a broad deny that cannot host a narrow
exception; redundant layers with cross-cutting exceptions (two owners, two
files, one precedence sentence instead); zero-count status theatre
(dashboard.md §4.18); a "Settings" label on operational controls next to
security policy (F6).

### 3.4 Sources (2026-09-05; vendor documentation unless noted)

pfSense (https://docs.netgate.com/pfsense/en/latest/firewall/rule-list-intro.html),
OPNsense (https://docs.opnsense.org/manual/firewall.html), Little Snitch 6
(https://help.obdev.at/littlesnitch6/concepts-rules), LuLu, Cloudflare Zero
Trust order of enforcement, Microsoft Purview DLP, AWS Bedrock Guardrails,
Claude Code permissions (https://code.claude.com/docs/en/permissions) and
auto mode (https://www.anthropic.com/engineering/claude-code-auto-mode),
Codex CLI sandboxing, Cursor permissions, Docker MCP Gateway, ToolHive,
Invariant Guardrails (https://github.com/invariantlabs-ai/invariant), Lakera
policies, HiddenLayer AIDR; Microsoft Defender for Endpoint ASR rules,
indicators, Action center and tamper protection (Microsoft Learn).
CrowdStrike Falcon's console documentation is login-gated: its facts come from
the public API reference and the vendor's Terraform provider schema.
SentinelOne's come from secondary sources (partner knowledge bases).

## 4. UI — one information architecture

> The 🏠/🔬 register toggle of the original plan is retired: the end user has
> a separate product page at `/`, and the inspector at `/dev/` always shows
> the expert layout (dashboard.md §4.25). The Inbox area is named
> **Approvals** in both (`/approvals`, `/dev/approvals`; dashboard.md §4.25u,
> §4.25w).

The inspector partitions like an EDR console. The topbar carries the area nav
(**Status · Approvals · Policy · Settings**, `body[data-area]`, deep links
`/dev/<area>`, dashboard.md §4.25v), the pending badge, and the tenant switch
(§2.7).

| Area | Holds |
|---|---|
| **Status** | trace, lanes, lineage, symbol table |
| **Approvals** | pending asks (with "Always allow from <origin>", §2.5), proposals (§8.6), and **History**: what you decided, newest first, with one-click reversal (Allow next time / Revoke / Undo) |
| **Policy** | protection level and matrix; **Your rules**; **Relaxations** (never folded); **Add a rule**; **Lists**; the built-in rules; what gets symbolized on the way in (§9.8.8); **Test a flow**; **Audit trail**; the law-source line |
| **Settings** | Services; **Sandbox** (the launcher's boolean wrap keys in `config.toml`, `GET|POST /api/config/sandbox`, a typed-OFF gate on every downgrade, one `config_change` audit event each); the Protection machinery |

The product page's Rules page (`dashboard/public/js/home.js`, over `GET
/api/policy/panel`) flips dispositions, locks files, moves DB-only labels into
`policy.yaml` and hosts "Describe what you want" (§8.5.2); the developer
view's Rules page (`/dev/rules`; dashboard.md §4.32) holds the full editor.

**Your rules**: kind · rule · effect · reach · source · hits · expires · ⓘ,
one grammar over locked files, trusted origins, release rules and
dispositions. With the confidentiality axis off, lock rows say they are not
enforced. **Add a rule** offers release allow / block / audit, and *Trust a
website* behind a typed `TRUST`, writing a host pattern (`host`,
`host/path-prefix`, `*.suffix`; a pasted URL is reduced to one). **Lists**
round-trips the whole document, so a dangling `@ref` is the arbiter's refusal,
shown in place.

**The built-in rules**, per gate in evaluation order, with user rules at
their precedence position (the spine of §9.8.1):

```
egress desymbolization gate · checked top to bottom per symbol×destination
 #  mode    rule                                              source        hits  last
 1  ✋ ask   standing verdicts (ledger) — 14 rows              mandu.db       31   2m
 2  ✓ allow  r-0007  docs.python.org → api.github.com ⚠relaxes policy.yaml    8   1h
 3  ⛔ block  no-model → any                                   built-in        0   —
 4  ✋ ask   untrusted symbol → untrusted destination          built-in       17   5m   [ mode ▾ ]
 5  ✓ allow  trusted destination                               built-in      102   1m
```

The *Source* column (`built-in` · `policy.yaml` · `mandu.db` · `config.toml`)
tells the user where to change a rule.

**Test a flow** (Cloudflare's policy tester over the pure gates): `POST
/api/policy/test-flow` → op `testFlow` (data plane). Input a source (URL, path
or tool), a destination and a level; output the inbound classification and
the egress verdict for a *synthetic* entry run through the same composition
as the live gate (`decideDesym` in `live` | `probe` mode, side effects
gated), naming the deciding layer (standing decision · lockdown · your rules
· disposition · built-in) and linking to its row. The probe queues and counts
nothing. **A registered file's own placeholders (tour 1, 2026-10-07).** A
standing answer is keyed on the symbol a real send carries
(`consultPriorVerdict(symbol, destination)`), and a probe symbol carries no
answer: `mandu why .env --to <host>` said "held for your approval" while the
human's Always allow released every real send of the file there. So, for a
file read (`tool: Read`, an absolute path origin) that the symbol table holds
registrations of, the probe is asked once per placeholder a real send of the
file carries (`registeredFileSymbols`, `arbiter/secret-registry/registry.ts`:
every active registration's field symbols, or its whole-file symbol), each
keyed on that placeholder while the law still sees the synthetic entry, and
the answer is the most restrictive of them; `placeholders` says how many.
Fail-closed by construction: an answer counts only where the live gate would
find it (same host string, same symbol), on every placeholder (the file's
placeholders share the file's one card since 2026-10-19, egress-hold.md
"One card per file", read where the gate itself asks, as the live gate does;
every registration counts, so an answer on an older
or newer value of a changed file does not cover the other), and only as a
standing answer (the probe reads an Allow once without spending it, which is
no verdict for it, `arbiter-human-plane.md` §10.3). Any other source (a URL, a
channel, another tool, a file never registered, a forced level other than the
file's own) keeps the synthetic probe symbol, which no answer covers. Tests:
`arbiter/test/component/test-flow-remembered-answer.test.ts`,
`arbiter/test/unit/registered-file-symbols.test.ts`,
`tests/stack/why-cli.test.ts`. For a filesystem path the answer carries `pathLabel`, the
derivation `pathLevel` answers (`confidentialityForOrigin` over human labels,
derived labels and the default-secret catalog): `{ path, level, bindings,
axis, rule, outranked }`. `rule` is worded like the watch panel ("your rule on
…", "the built-in secret list (…)", "nothing matched: public by default");
with the axis off it says the labels are not in force (`axis: false`) rather
than calling the path public. `outranked` lists every *pattern* label that
also matches, lost on specificity to the literal directory label that decided,
and is stricter (`outrankedStricterPatterns`, `arbiter/policy/path-labels.ts`;
confidentiality.md §6.1), one line each ("also matches the pattern `**/*.pem`
(hidden secret), which lost: the rule on `~/notes` is closer to the file").
Observability only; every string goes through `textContent`. Tests:
`arbiter/test/unit/path-labels.test.ts`,
`arbiter/test/component/path-glob-labels.test.ts` (axis on and off),
`dashboard/test/unit/ui/egress-js-document.test.ts`.

**Audit trail**: the `arbiter-admin` stream newest first (`policy_change` ·
`config_change` · `approval_resolved` · `approval_consumed` ·
`posture_change`), filterable by kind.

Routes: `GET/POST /api/policy/document` (the GET too behind the CSRF header
and the admin session, since 2026-10-03: the file holds the prompt filter's
exceptions), `POST /api/policy/rules`, `POST
/api/policy/export-labels`, `POST /api/policy/test-flow`; writes go over the
admin channel (422 invalid, 503 adopted arbiter, 409 in-memory law).
Vocabulary follows dashboard.md §4.16. **Not built:** an analyst verdict on
History rows (*expected* / *suspicious* / *false positive*, SentinelOne's
split) to feed the impact preview of §2.4.

## 5. Testing

- **Golden** (`compiled-policy.test.ts`, §2.2).
- **Document round-trip** (`arbiter/test/unit/policy-document-ops.test.ts`):
  admin op → file bytes → mtime reload → identical law; an invalid hand edit
  keeps the law in force and flags it; `policy-file-validate.test.ts` and
  `test/component/policy-file.test.ts` (an invalid file at boot refuses the
  start, listing every problem).
- **Tenancy**: `arbiter/test/unit/tenancy.test.ts`,
  `launcher/test/unit/tenant-preflight.test.ts`,
  `dashboard/test/unit/tenant-classification.test.ts` (stamp beats prefix
  both ways), the anthropic-proxy `proxy.test.ts` header cases.
- **Boundary**: `arbiter/test/component/admin-channel.test.ts` walks
  `ADMIN_ONLY_OPS` on the data socket (each refused), enacts them on an admin
  channel, spawns the real daemon with `MANDU_ADMIN_FD=3` and proves the fd
  works while its data socket refuses, and pins bind-once `setSessionSpec`;
  `dashboard/test/unit/admin-session.test.ts` pins CSRF-first, the 403 without
  the cookie, the token login, the password session and the 503 for an
  adopted arbiter, and the one-time sign-in link (once, expiry, the
  password mode, the no-password `/login` page, the refusal's remedy).
  Signing in (§2.6; the account since 2026-10-22, dashboard.md §6.z, whose
  tests are listed there): `dashboard/test/unit/sign-in.test.ts` (the
  socket's answer of how to sign in, its mode and directory checks, the
  sweep; the tickets until 2026-10-22),
  `launcher/test/unit/dashboard-sign-in.test.ts` (TTY only, a socket outside
  the human-plane directory never dialled, the terminal line carries the
  link and the kept line never does, `mandu dashboard`'s lines),
  `tests/stack/dashboard-sign-in.test.ts` (real arbiter, dashboard and
  launcher client: no session no answer; the link earns the session and
  "Allow once" resolves a held send in the arbiter's store; spent and
  guessed links earn nothing; an unwalled launch on the record stops minting
  and is named) and, under the real guard and wrap,
  `tests/sandbox/dashboard-sign-in-wall.test.ts` (the launch line's link
  works once; the agent's tree cannot connect to the sign-in socket by path
  or symlink; no recorded event holds a link).
- **User rules and hits**: `user-rules-gate.test.ts` (Block > Allow, an
  unknown origin never satisfies a narrowed rule, a secret never yields,
  audit decides nothing; one decision = one hit); `destinations.test.ts`.
- **Tester ≡ gates**: the tester's answer equals the live verdict for every
  golden fixture (one composition, `decideDesym` live | probe), pinned by the
  document-ops real-server test; for a registered file, a human's standing
  answer about its placeholders included
  (`test-flow-remembered-answer.test.ts`, with its negatives).
- **UI**: JSDOM area tests over the real bundles; the approval loop with rule
  minting (ask → "Always allow from <origin>" → the next ask on a *new* symbol
  from that origin is allowed and counted).

## 6. Order of work

All stages are built:

0. **Boundary (§2.6)** — the admin channel, bind-once `setSessionSpec`, the
   admin session; (0b) the launcher autostarts the supervisor. Closes F5.
1. **Tenancy (§2.7)** — stamp and refusal (1a), the test arbiter (1b), one
   store per request and the switch (1c). Closes F8.
2. **Wire the policy file** — `MANDU_POLICY_FILE`, resolved every boot,
   strictly validated (§2.1). Closes F2.
3. **`compilePolicy`** and the golden test (§2.2). Closes F3.
4. **`policy.yaml` owns lists, labels, dispositions, user rules; `rule_hits`**
   (§2.1, §2.4, §2.5); (4b) `destinations:` (§2.3). Closes F1 for declared
   labels.
5. **The Policy area (§4)** — the arbiter as single writer (5a); Your rules,
   Relaxations, Add a rule, Source and Hits, "Always allow from" (5b, 5c).
6. **The Settings area** — the Protection drawer retired into an inline block;
   Sandbox and the Protection machinery in Settings (dashboard.md §4.19).
7. **Lists, Test a flow, Audit trail** (§4).
8. **The area nav and Approvals History** (§4).

**Not built / deferred:** the items marked in §2.1, §2.4, §2.5, §2.6, §3.1
and §4; per-session policy documents (until a multi-tenant deployment);
browser notifications (dashboard.md §4.20); a TTL auto-resume for Pause; a
bounded hold of the agent's request while a human is present (measure first
how often an agent re-attempts after approval); retiring the sidebar's
Testing section (§2.7).

## 7. What `mandu.db` holds

The arbiter's single-writer SQLite: `symbols` (name → value, tool, field,
origin, session, call id, obsoletion, derivation, confidentiality, bindings,
integrity), `egress_approvals` (human verdicts, §9.8.7), `path_labels`
(Locked files set from the dashboard; the file's `paths:` compose with them,
§2.1), `session_labels` (with `session_label_sources`, the symbols each
session read into context), `symbol_sources` (a multi-input join's
sources), `result_heads` (the rows whose agent-runtime head lines are no
fingerprints, confidentiality-plan-10 §11.14), `derived_labels`, the provenance tables
(`process_taint`, `process_lineage`, `file_taint`), `rule_hits`, and
`policy_proposals` / `policy_changes` (§8.4.5). Not in it: events
(per-session NDJSON in the instance dir), posture, exec decision stores, the
protection axes (`config.toml`), the law (`policy.yaml`).

## 8. The policy agent surface: a model writes the law, the confined agent only tightens

*Formerly `policy-agent-surface.md`; its §N is §8.N here.* **Status: BUILT
(2026-09-25, later additions dated in place):** the pure classifier and edit
grammar (`arbiter/policy/policy-delta.ts`, `policy-edit.ts`; stage A0); the
ops, stale guard and proposal tables (`arbiter/ipc/policy-agent-ops.ts`,
`policy/policy-proposals.ts`; A1); the `mandu-policy` MCP server, its trust
gate, `policySchema` and the handling-prompt section (B); "Describe what you
want" and `policyPreview` (C). Deferred items are in §8.8. It extends the
one-law / admin-channel model of §2 and adds a box to the product page
(dashboard.md §4.25).

### 8.0 The ask, and the answer in one paragraph

The end user should not have to learn `policy.yaml`. Its vocabulary is the
right *storage* shape and the wrong *authoring* interface; a person knows what
they mean ("this is my work repo, I use GitHub and PyPI, `.env` and `~/.ssh`
are secret, never send anything to a paste site") and a model is the right
translator. So the policy surface is a **machine contract** with three
consumers: the confined agent itself (through an MCP server), a quarantined
setup assistant behind a "Describe what you want" box, and the dashboard's
editor. One rule makes this safe, a **monotonic split**: any client may
*tighten* the law; only a human may *relax* it, and a model that wants a
relaxation *proposes* it as an Inbox ask. The confined agent is the threat
model's T-LLM; if it could relax its own policy, one injected line would
disarm the defense.

### 8.1 What this builds on

The law is one file with one writer (§2.1, §2.2); its writers are admin-only
ops (§2.6); data-plane ops that change state only add or raise, and
`setSessionSpec` binds once. `relaxationsOf(compiled)` lists every way a law
is looser than the built-ins: `inbound-trust`, `outbound-resolve`,
`trusted-origin`, `exec-output-trust`, `user-rule-allow`, `public-path`,
`connect-allow`, and three kinds this work added (the gap it found):
`path-binding` (a label's `bindings`, a standing release), `env-exempt`, and
`app-output` (a reader entry that clears or masks its output,
[Plan 13](../confidentiality/confidentiality-plan-13-reader-set-labels.md)
D3). It is a display list, not the gate of §8.3. The launcher already mounted
one MCP server (`mandu-inspect`) and the quarantined model channel is
configured once (`MANDU_ULLM_MODE`, `ullm-config.ts`). What was missing: a
path from a sentence to a patch, and a contract an agent could use.

### 8.2 Principals

| Principal | Runs where | Channel | May tighten | May relax |
|---|---|---|---|---|
| Human (browser, admin session) | dashboard | admin (inherited fd) | yes | yes, after seeing the plain-language row; over-broad rows need the typed word |
| Confined agent (T-LLM: Claude Code, Codex, …) | inside the scope | data socket, via the `mandu-policy` MCP server | yes, applied at once, audited, undoable | **never**; may only *propose* |
| Setup assistant (quarantined model) | dashboard, per request | none of its own; its output is edits the human applies | via the human | via the human |
| Scripts / CI | host, same uid | data socket | yes | proposes (a `mandu policy` editing CLI is deferred, §8.8) |

The confined-agent row holds by **construction**, not by prompt: the MCP
server is a data-socket client, the relax path is an admin-only op, and the
arbiter's channel check decides before any handler runs. A buggy or malicious
MCP server can propose all it likes; nothing changes until a human clicks.

### 8.3 The monotonic split

#### 8.3.1 Definition, and why not a set difference

A change is **tightening** when every flow the law after it permits, the law
before it permitted too. Everything else is a **relaxation**. The classifier
is a pure function over two *compiled* policies, never over document text, so
`lists` are safe: editing `my-services` changes every rule that references
`@my-services`, and the comparison sees the expanded hosts.

```ts
// arbiter/policy/policy-delta.ts (pure, unit-tested without privilege)
export interface DeltaChange {
  facet: DeltaFacet;            // "paths" | "origins" | "command-output" | "tools" | ...
  direction: "relax" | "tighten";
  subject: string;              // a path, a host, a rule id, a tool name
  detail: string;               // one plain sentence
}
export interface PolicyDelta { relaxations: DeltaChange[]; tightenings: DeltaChange[] }
export function policyDelta(before: CompiledPolicy, after: CompiledPolicy, opts?: { now?: number }): PolicyDelta;
export function isTightening(d: PolicyDelta): boolean { return d.relaxations.length === 0; }
```

A set difference of relaxation lists (`relaxationsOf(after)` minus
`relaxationsOf(before)`) is wrong both ways: it calls raising a lock from
`any-model` to `no-model` a relaxation (a restriction was "removed"), and it
misses an allow rule whose `expires` was extended or `from` widened (same rule
id, nothing "added"). So the classifier works **facet by facet and fails
closed**: an unchanged facet contributes nothing; a changed facet is
tightening only when it matches a proven form of §8.3.2; any other change,
including one the classifier does not understand, is a relaxation. A document
key the classifier does not know is a relaxation until someone writes its
proof.

#### 8.3.2 The proven tightening forms, per facet

| Facet (compiled) | Tightening (the data plane may apply) | Everything else is a relaxation, e.g. |
|---|---|---|
| `blob-lock` (`blobs:`, [plan 14](../confidentiality/confidentiality-plan-14-policy-suggestions.md) §8.2) | add a lock above `public`; raise a level. A blob lock only adds an object to what the twins hide, so it cannot shadow a stricter rule (§8.3.3) | remove a lock; add one at `public`; lower a level (a note alone changes nothing) |
| `paths` | add a **plain strict** label with no overlap hazard (§8.3.3); turn a label into a plain strict one when it had no `readers`/`others`/`extract` to lose, `recursive` does not go true → false, and there is no overlap hazard; drop bindings with nothing else changed; lower a reader entry's `output:` toward `secret` or add spans to its `mask:`, readers unchanged (Plan 13 D3) | remove a lock; add a label at `public` or `any-model`; lower a level; add a binding; add, change or drop `readers`/`others`/`extract`; `recursive` true → false |
| origins (`inbound.url/channel/dir`, lists expanded) | shrink `trustedList`; grow `untrustedList`; the *effective* default becomes UNTRUSTED | the reverse; the effective default becomes TRUSTED |
| command output (`execIndex`, aliases indexed) | the entry's grants shrink; drop an entry | a new id or alias that trusts anything; `trustHelp`/`trustErrors` on; `allowedFlags` grown |
| tools (boot spec's inbound, resolve and field tables) | inbound grants shrink with `paramsKeys` and `actionField` unchanged; resolve true → false; a field to `not_resolve` | a grant added; `paramsKeys` changed; resolve on; a field to `resolve` or `no_symbols_expected`, or dropped |
| dispositions (`rules`) | `ask` → `block` | `block` → `ask` (absent = `ask`) |
| `user_rules` (lists expanded) | every allow after is **covered** by an allow before; every block before is covered by a block after (§8.3.4) | an allow widened or extended; a block narrowed, shortened, removed, set `off`/`audit` |
| `destinations` | a `connect: allow` removed | one added |
| `apps` (deprecated, clears nothing, still classified) | remove a rule; set `output: secret` | `clear` or `mask` added or changed |
| `env` | grow `secrets`; shrink `exempt` | the reverse |
| `models` | none | every change |

A **grant** is anything that lets data through unmasked: a `TRUSTED` leaf, a
`role: key` / `role: data` marker, a `wholeResult` marker, `trustHelp`,
`trustErrors`, an `allowedFlags` entry. "Grants shrink" is a subset test; a
changed shape (a new action branch, a different `paramsKeys`) is a relaxation
even if it trusts less, because the proof does not cover it. `mode: audit`
rules are neutral. A unit corpus pins one before/after pair per row, both
directions (§8.7).

**Why every `models` change relaxes.** A `local: true` entry lets files
labeled `local-model` be sent to that address; removing or editing any entry
can leave a user-set `ANTHROPIC_BASE_URL` / `MANDU_OPENAI_BASE_URL`
undeclared, so the next launch skips the model proxy
([model-endpoints.md](../confidentiality/model-endpoints.md) §1.7.1, §1.8
row 2); adding an outside entry changes which base URLs keep the proxy. The
comparison is over the compiled list (defaults applied), and the data plane
never applies a models change (§8.4.3a).

**Why the effective default (a pre-release bug, 2026-09-25).** The engine
once read a section with no `default` as a blocklist for every category,
though the URL category defaults to UNTRUSTED: `trust-origin` then trusted
the whole web, and `distrust-origin`'s `url: { untrustedList: [x] }`, rated a
tightening by a text-level delta, switched URL masking off from the data
plane. Now the engine, the validator (§2.1), `applyEdits` (writes only the
list the effective mode reads, pinning the default) and this delta all use
the effective default (`BUILTIN_ORIGIN_DEFAULT`).
`policy-delta-engine-oracle.test.ts` pins the class: for every (starting law,
edit list) pair, a TIGHTENING verdict never newly trusts any probe of the
real classifier.

#### 8.3.3 Paths: why the rule is "plain strict" only

A user label is **authoritative** over the default-secret catalog
(`path-labels.ts`: the catalog is a default, a label overrides it) and the
**most specific** label wins, so adding a lock can *lower* protection: `lock
~/.ssh at any-model` turns the catalog's `no-model` keys into `any-model`; an
`any-model` label under a `no-model` ancestor lowers that subtree; `recursive`
on an `any-model` directory pulls every catalog secret below it down. The
catalog is runtime discovery, not law, so no comparison of two compiled laws
can see what a new label shadows. The classifier therefore accepts only path
edits that tighten **under every possible catalog and DB-label state**: a
**plain strict** label (`no-model`, no `bindings`, `values`, `readers`,
`others` or `extract`). Adding one is monotone: where it wins it decides the maximum level
with no release attached; where it loses nothing changes. DB labels carry
only a level and bindings, so a plain strict label dominates any it shadows.

One hazard remains inside the law: a label that newly wins brings its own
`readers`/`others`/`extract`/`bindings`, which can be looser than the loser's
(a plain strict label on `~/.aws/credentials` shadowing `readers: [aws],
others: deny` on `~/.aws` turns "everyone else denied" into "everyone else
gets the twin"). The **overlap-hazard** check is conservative: a new or raised
label is tightening only if no other compiled label whose literal prefix is a
segment-prefix of its own, or the reverse, carries any of those fields (or
`values:`). A pattern starting with `**` overlaps everything.

**Per-value bindings** (`values:`, confidentiality plan 13 §5.2,
2026-10-11) classify as `bindings` do, entry by entry: under the same keys,
bindings that only shrink (the file's own and each entry's) are a
tightening; a binding added to an entry, a key added, or a key removed (its
values then take the file's bindings, which may be wider) is a relaxation,
each named in its own sentence; a lock that becomes plain strict drops them
as a tightening.

So "mark `test/fixtures/.env` public" and "let `~/.config/gh` go to
github.com" are always proposals: they are declassifications.

#### 8.3.4 User rules: coverage, not identity

The gate (`matchUserRules`) allows a flow when an active allow matches and no
active block does. A change allows nothing new when every allow after is
covered by some allow before (its `from` inside the other's — an absent
`from` is covered only by an absent `from` — its `to` inside, expiring no
later; an absent expiry is covered only by an absent expiry), and every block
before is covered by some block after (containing `from` and `to`, expiring no
earlier). Host containment follows `hostMatches`: `*` contains everything,
`*.example.com` contains `example.com`, `api.example.com` and
`*.api.example.com`, a literal only itself. Rules already expired at
`opts.now` are ignored on both sides.

#### 8.3.5 Why the confined agent may tighten without asking

A compromised agent tightening its own cage is a nuisance, not a breach: the
worst outcome is a lockout ("lock `~/` at `no-model`") the human sees and
undoes. Three guards keep it small: every agent tightening is an audit event
(`via: "agent-tighten"`, `requestedBy: "agent:<sessionId>"`); it appears in
History with one-click **Undo** (an admin op); and a per-session cap
(`TIGHTEN_CAP_PER_SESSION = 20`; the 21st becomes a proposal) bounds a loop.
A suggestion of Mandu's own scan applied on the data socket
(`applySuggestion`) is recorded `agent-tighten` too (`requestedBy:
"data-plane"`, with the suggestion as its `proposalId`): the data socket is
the agent's channel, so the record never names a person. It does not count
toward the per-session cap, which counts the agent's own edits; the scan's
filing cap bounds it ([plan 14](../confidentiality/confidentiality-plan-14-policy-suggestions.md) §14.14).
The same asymmetry the data plane already encodes for `registerSecret` and
`labelWrittenPath`.

#### 8.3.6 Protection modes

The split is structural, so it holds in every mode. What changes is how far
the agent's *words* can be trusted. In `secrets` (the default) and `off`,
integrity is off: untrusted text reaches the agent in the clear and an
injected page can steer everything it proposes, including its `reason`. In
the frozen `injection` and `full` modes a `reason` may still carry `$MDU:`
symbols. So an agent's `reason` is untrusted text in every mode (§8.4.4,
§8.6).

### 8.4 The contract

#### 8.4.1 Typed edits, not YAML

An agent (or the assistant) never emits YAML. It emits **typed edits**, the
Rules row grammar (`YourRuleRowVM`) in reverse, so every edit renders to the
same plain sentence the Rules page shows and the Inbox card needs no model to
explain it:

```ts
// arbiter/policy/policy-edit.ts
export type PolicyEdit =
  | { op: "lock-path";        path: string; level: "public" | "any-model" | "no-model"; bindings?: string[]; recursive?: boolean }
  | { op: "unlock-path";      path: string }
  | { op: "lock-blob";        blob: string; level: "public" | "any-model" | "local-model" | "no-model"; note?: string }
  | { op: "unlock-blob";      blob: string }
  | { op: "trust-origin";     kind: "url" | "dir" | "channel"; pattern: string }
  | { op: "distrust-origin";  kind: "url" | "dir" | "channel"; pattern: string }
  | { op: "release";          id?: string; from?: { host: string }; to: { host: string }; mode: "allow" | "block" | "audit"; expires?: string | null; reason?: string }
  | { op: "retire-rule";      id: string }
  | { op: "set-disposition";  rule: string; mode: "ask" | "block" }
  | { op: "allow-connect";    host: string; port?: number | "*" }
  | { op: "remove-connect";   host: string; port?: number | "*" }
  | { op: "trust-command";    id: string; trustHelp: boolean }
  | { op: "tool-inbound";     tool: string; trust: "TRUSTED" | "UNTRUSTED" }
  | { op: "list";             name: string; add?: string[]; remove?: string[] }
  | { op: "add-model";        name: string; url: string; wire?: "anthropic" | "openai-chat"; model?: string; local?: boolean; token_env?: string }
  | { op: "update-model";     name: string; url: string; wire?: ...; model?: ...; local?: ...; token_env?: ... }
  | { op: "remove-model";     name: string };
```

The ops name intentions, not directions: the classifier never reads `op`, it
compiles the edited document and runs `policyDelta`, so `lock-path` at
`no-model` applies at once from the agent and the same op at `any-model`
becomes a proposal. `lock-path` on a labeled path replaces level, bindings
and `recursive` and keeps `readers`/`others`/`extract` (expert-only, in the
file). `release` without an `id` mints the next `r-<n>`; with one it replaces
that rule whole (an omitted `from` or `expires` is the widening it looks
like). The blob ops edit `blobs:` (git object ids, `sha1:` / `sha256:`,
hidden by the launcher's object twins). The model ops edit `models:`
(`update-model` replaces an entry whole; a rename is remove plus add; content
is checked by the validator's `checkModels`) and are human-only (§8.4.3a).

`applyEdits(document, edits) → document` is pure; the result goes through
`validatePolicyDocument`. It refuses the whole list when an op is malformed
or names something that does not exist (an unlabeled path, an unknown rule
id, an undeclared list). `evaluateEdits` is the pure core of `policyPropose`:
apply, compile both laws under the same boot spec, classify. The dashboard
editor keeps full-document replacement (`applyPolicyDocument`), which names
the law it was built from (§8.4.6).

#### 8.4.2 Ops

| Op | Channel | Behaviour |
|---|---|---|
| `policyDocument` | data | the law in force + on-disk status |
| `policyExplain` | data | the structured projection of §8.4.4 |
| `testFlow` | data | would this flow pass? never a side effect; `withEdits` probes a hypothetical law and restores the law in force inside one synchronous call |
| `policySchema` | data | the JSON Schema offered to models (§8.4.3) |
| `policyPreview` | data | validate and classify an edit list against the law in force, writing nothing, with a per-edit `loosens` flag (§8.5.2) |
| `policyPropose { edits, reason }` | data | `applyEdits` → validate → compile before/after → `policyDelta`. Tightening ⇒ apply (`via: "agent-tighten"`, stale guard below), `{ applied: true, changeId }`. Relaxing, or over the tightening cap ⇒ file a proposal (§8.4.5), `{ applied: false, proposalId, relaxes }`. One edit list, one verdict, never a partial apply |
| `policyProposals { status?, kind? }` | data | newest first; suggestions only with `kind: "suggestion"` |
| `suggestPolicy`, `policySuggestions`, `applySuggestion` | data | Mandu's own history scan files tightenings as `kind: "suggestion"` rows; applying one only as a pure tightening of the law in force, recorded `via: "agent-tighten"` on the data socket ([plan 14](../confidentiality/confidentiality-plan-14-policy-suggestions.md) §5.6, §14.14) |
| `dismissSuggestion` | **admin** | "Not a secret": withholding protection is a relaxation |
| `policyChanges { limit? }` | data | the change log with `undoable`, `proposedBy`, and `rules` (each touched item as Rules-page row ids, added/removed, still current), for "who put this rule there" (dashboard.md §4.25i); only ids, paths and hosts `edits` already carries |
| `resolvePolicyProposal { proposalId, verdict }` | **admin** | `approved` ⇒ apply (`via: "proposal"`), `denied` ⇒ close; both audited |
| `undoPolicyChange { changeId }` | **admin** | reverts one change. Each change stores the **items** it touched (a lock by path, a rule by id, a list by name, one origin pattern, a blob by id, a model by name) with before and after values (`diffItems`); Undo writes the before values onto the law in force, so later changes to other items survive; if an item changed again (`revertConflicts`) it names it and changes nothing. An undo is recorded (`via: "undo"`) and is not undoable |

The change log also records writes made outside this surface, from the
document store's audit hook (dashboard.md §4.25j): `via` `disk` (a hand
edit), `apply` / `mint-rule` / `export-labels` (the developer view),
`pin-reader`, and `move-labels`. Undo refuses a hand edit (it would rewrite
the person's file) and `move-labels` (the DB rows are gone).

`policyPropose` on the admin channel behaves the same (the Describe box
reuses it); its tightenings are `via: "tighten"` and not counted against a
cap. On the data socket `requestedBy` is ignored and always
`agent:<sessionKey>`: a data-plane client never names a human. The
`sessionKey` is self-asserted (bounded to a token, else `unknown`), an
identity for caps and attribution, never for authority; the total pending cap
is what a client rotating keys runs into.

**Stale guard.** Every write this surface makes (an agent's tightening, an
applied or approved suggestion, an approved proposal, an Undo) calls
`PolicyDocumentStore.applyGuarded`, which first runs the disk poll: if the file changed
since the store last loaded it, the new file becomes the law (or is refused
as invalid, or held, §8.4.6), nothing is written, and `policyPropose` answers
`refused: "stale"` (approve and Undo answer an error and leave the proposal
pending), so the caller retries against the fresh law. Without it a hand edit
saved inside the 2 s poll window would be overwritten by an agent's write.
The dashboard editor's full-document apply is unguarded: it is a human
replacing the file they are looking at. An edit list built from an earlier
read of the items it replaces names them (`policyPropose.basedOn`, the
versions `policyDocument.itemVersions` gave, or its `absentVersion` for
an item the read did not find): one that changed since refuses the list
`stale`, and a filed proposal that names them is refused at approval the
same way (§8.4.6 "An item-level version").

#### 8.4.3 The schema is derived, not hand-written

`arbiter/policy/policy-edit-schema.ts` derives the JSON Schema of a
`PolicyEdit` list from the tables the arbiter validates with (`LEVELS`,
`DISPOSITION_MODES`, `dispositionableRuleIds()`, `LIST_NAME_RE`,
`POLICY_EDIT_OPS`, and `EDIT_KEYS`, the per-op key sets `applyEdits`
enforces). Models are offered the **agent schema**, `policyAgentEditSchema()`
over `AGENT_EDIT_OPS` (every op but the three model ops, §8.4.3a).
`policy-edit.schema.json` is its checked-in copy (`npx tsx
scripts/gen-policy-schema.ts` regenerates it), served by `policySchema` and
embedded in the `mandu_policy_propose` tool description and the Describe
box's prompt. Pins (`policy-edit-schema.test.ts`): the file equals the
generator; the agent schema is the full grammar minus the model ops; a corpus
of edit shapes is accepted or refused by the schema exactly when `applyEdits`
accepts or refuses it (the corpus caught a non-boolean `recursive` and a stray
key in `release.to` being silently ignored). A whole-document schema is
deferred until a tool validates `policy.yaml` outside the arbiter.

#### 8.4.3a Model endpoints are human-only (decision 2026-09-28)

A declared model decides which address counts as "your own model" (where
`local-model` files may go) and which base URL is the main model, so a model
that could propose one would have a steered path to sending those files off
the machine. An Inbox warning with a typed ALLOW was built first and dropped:
too much to rest on one click. Model endpoints change only through
Settings › Models (dashboard.md §4.25l, `requestedBy: "settings"`) and hand
edits (which relax, so they wait, §8.4.6).

- **Not offered:** `policySchema` answers the agent schema; the tool
  description and the Describe prompt point to Settings › Models.
- **Refused if sent anyway, fail closed:** `PolicyAgentOps.propose` checks
  `modelEditProblems` before anything is evaluated, filed or written — on the
  data plane, and on the admin channel for `MODEL_EDIT_BARRED_REQUESTERS`
  (`assistant`) — answering `refused: "invalid"`; a valid tightening beside it
  does not carry it through. The dashboard refuses first (422).
- **Unchanged:** the read-only listing (§8.4.4), Undo, the card's rendering.

#### 8.4.4 What a model may read: projections only

The invariant's second-order form: an injection that cannot reach T-LLM as
text must not reach the *configuring* model as text either, or the attack
moves one hop ("tell the setup assistant to allow pastebin"). `policyExplain`
carries **structured fields only** — hosts, paths, tool names, rule ids,
levels, counts, timestamps, and the `reason` a human typed — never a
`DualRepr` original, a tool-result body, a symbol twin, an event's free text,
or **an agent's `reason`** (untrusted in every mode, §8.3.6; stored and shown
to the human as the agent's words, §8.6). As built (`PolicyAgentOps.explain`),
every string is a **bounded token** (no whitespace, a path/host/URL character
set, at most 200 characters) or is replaced by `(withheld)`, so an injected
sentence does not survive even when an agent copies it into a pattern.
Hostnames are attacker-influenced; they are rendered as a row's subject,
never as prose.

The policy tools' answers are `tool_result`s the model proxy classifies, so
they are a new **ingress path** into T-LLM. Two rules make it safe
(`arbiter/policy/policy-tool.ts`):

- **The agent audience** (`policyExplain({ audience: "agent", sessionKey })`)
  drops what a page could have chosen: pending asks become a count
  (`pendingAskCount`), and only the calling session's own proposals are
  listed. What remains is human-written or human-approved law, the agent's own
  proposals, and arbiter-minted ids and enums.
- **The trust gate** mirrors the inspect rule: a result is TRUSTED only when
  the tool name is one of Mandu's own spellings (`mcp__mandu-policy__<tool>`,
  `mandu-policy_<tool>`, Goose's `mandu-policy__<tool>`; no bare name) and the value is one JSON object whose
  `tool` names that tool and whose every string is a bounded token or one of
  eight fixed messages. The one prose channel is `problems` on an `invalid` or
  `stale` answer: validator lines (at most 300 characters, no newline or angle
  bracket) whose only inputs are the law and the agent's own edits. Anything
  else is symbolized whole.
- **A waiting call says all of it waits (2026-10-07).** A propose call is
  judged whole (§8.3): one relaxation in it files every edit as a proposal,
  its locks included. The fixed message of that answer said "This change
  loosens protection, so it is waiting", and a live run read it as the
  loosenings alone: Haiku 4.5 sent four locks with two loosenings in one call
  and told the user the locks were in force (drill policy-setup-repo, WARN).
  It now says none of the call's edits is in force, the locks included, and
  that the tightenings proposed alone apply at once. The tool description
  already said so; the result is what the model reads after the call.

**Declared models are listed, read-only**, for both audiences: one row per
compiled entry with `name`, `url`, `wire`, `model`, `local` and `tokenEnv`
(the *name* of the key's variable), built from an allow-list of fields
(`EXPLAIN_MODEL_FIELDS`). No row carries a secret: the key is never read, a
URL with credentials is refused by the validator and withheld again here, and
the URL loses its query and fragment.

#### 8.4.5 Proposals

Two tables beside `egress_approvals` in `mandu.db`, with the same life
(`policy/policy-proposals.ts`; schema v2, a v1 file is adopted by
re-stamping, [runtime-instances.md](../architecture/runtime-instances.md)
§9a):

```
policy_proposals(id pp-NNNNNN, edits, reason, requested_by, session_key,
                 relaxes, tightens, edits_hash, law_hash,
                 status pending|approved|denied|superseded,
                 created_at, resolved_at, resolved_by, change_id, superseded_by,
                 disk_hash, disk_text,            -- §8.4.6
                 kind, finding_key, suggestion)   -- plan 14 §5.1
policy_changes  (id pc-NNNNNN, via agent-tighten|tighten|proposal|undo|…,
                 requested_by, session_key, edits, delta, revert,
                 proposal_id, created_at, undone_at, undone_by)
```

`kind` is `proposal` or `suggestion` (a change Mandu's history scan generated,
[plan 14](../confidentiality/confidentiality-plan-14-policy-suggestions.md)
§5.1, filed only by the arbiter as `mandu:scan`, masks only, never a value).
Suggestions are kept apart: their own read, cap (20 pending per repository)
and dedup; a pending one the law now covers closes `superseded`. No tenant
column: one tenant per arbiter scopes the file.

`relaxes` is the delta at filing, so the Inbox can say what would be given
up. A proposal is bound to its law (`law_hash`); approval recomputes the delta
against the law in force, and if it now relaxes anything the human was not
shown, the proposal is `superseded` by a new one with the larger delta.
Flood limits: an identical pending edit list (canonical hash) returns the
existing proposal; at most 10 pending per session (`refused:
"proposal-cap"`); a `reason` is capped at 280 characters and stored as
written, `$MDU:` symbols included, never desymbolized for display.

**A proposal the law already says is closed** (first-session tour item 17,
2026-10-07). The human can make the change a proposal asks for some other
way: by hand in `policy.yaml` while the arbiter is down (loaded at the next
start), or through another surface. The card then stayed in the Inbox for
good, and the agent's same request came back "already waiting".
`PolicyAgentOps.retireSatisfied` closes a pending proposal `superseded`,
`resolvedBy: "mandu:in-force"` (the `mandu:` prefix is the arbiter's own),
when its edits applied to the law in force would change nothing the law
means (the same document, or an empty `policyDelta` both ways). It runs at
start, before and after `policyPropose`, after a verdict or an Undo, and on
every read of the pending list (`policyProposals`, `policyExplain`), so
every way the law can move is covered without a hook in each. It never
applies anything: a proposal whose change the law does not already make
stays pending. It also judges a held disk change again (`rejudgeHold`, §8.4.6).

#### 8.4.6 A hand edit that relaxes the law waits for a human (decision 2026-09-28)

**Problem.** The arbiter reloads `policy.yaml` within 2 s. Wherever the agent
is not confined, and in every mode where the config directory is not
write-protected, the agent's process tree can write the file, so injected
code could relax the law without the admin channel and the monotonic split
(§8.3) would stand on file permissions alone. Refusing the agent tree's
writes there is the kernel half
([write-protection.md](../architecture/write-protection.md)); this is the
arbiter half, which holds in every mode on every host.

**Decision.** A change from disk that contains any relaxation is not
applied: the law in force stays and the change waits in the Inbox as a
proposal. One that only tightens, or changes nothing the law means
(comments, layout), applies at once.

**Mechanism** (`policy-document-store.ts`, `pollDisk`):

- A changed stat identity makes the poll read the file; only changed bytes
  (sha256) are a change. The arbiter's own writes remember the hash they
  wrote and the tmp file's identity before the rename, so they are never
  judged as foreign.
- New bytes are validated (invalid: refused) and judged by `policyDelta`
  against the law in force (a judge that throws counts as a relaxation). No
  relaxation: loaded, audited `via: "disk"`. Any relaxation: **held** (one
  hold: hash, document, delta) and filed as a proposal with `requestedBy:
  "file"`, no edits, no reason, and `diskHash`. If the file moves on, the new
  bytes are judged afresh and the old card is `superseded`; bytes back at the
  law close it.
- **A change made through the surface while a hold is pending** (an
  agent's tightening, a proposal a human approved, first-session tour item
  17, 2026-10-07; an applied suggestion and an Undo, 2026-10-09). Before,
  every guarded write was refused as stale ("decide that change first"),
  so the agent's own `mandu_policy_propose` lock waited on an unrelated
  hand edit, and `mandu policy suggest`, the dashboard's Lock it and
  History's Undo were refused outright. Every write of the surface goes
  through `PolicyDocumentStore.applyGuarded(after, change, layer)`; with a
  hold pending, `layer` makes the same change to the held document (the
  same edits, `layerEdits`; for an Undo, the same item-level revert,
  `revertItems`), and `applyUnderHold` writes both: the law in force gets
  the change (already judged: a tightening, a suggestion re-checked as a
  pure tightening, the human's approval, the human's Undo) and its text is
  what is persisted as the content in force; the FILE gets the held
  content with the same change, so the hand edit is kept, not overwritten
  (the superseded card keeps the original text). The written bytes are
  then judged against the new law as a poll would: still relaxing, they are
  held anew and the card is filed again (the old one `superseded` by it;
  the new card's delta is computed against the new law, so approval still
  covers nothing the human was not shown); relaxing nothing, they are
  loaded. Layering, not queueing: a queued change would leave the law
  without a lock the person or the agent just asked for, and the hold
  gates only what the held edit relaxes. Still refused as stale until the
  hold is decided, with the reason: a change whose edits do not apply to
  the held document (they name something it removed), and an Undo of an
  item the held edit also changed (`revertConflicts` on the held document;
  "the change to policy.yaml waiting in Approvals changes the same rule").
  `mandu policy suggest` words that refusal as what to do: the suggestion
  is not applied yet and stays waiting; answer the change on the
  dashboard's Approvals page (Allow or Not now, `mandu dashboard`), then
  run the command again (plan 14 §5.3).
  Nothing the held edit relaxes takes effect on the way: the hold is judged
  again on every such write, never skipped.
- **Comments are kept** (2026-10-09). A write of the surface is written
  INTO the person's text (`policy-yaml-splice.ts`), not dumped: the held
  edit re-saved with a change (above) keeps its comments, and so does the
  law's text persisted as the content in force (what a decline writes
  back), and, with no hold, the file itself. js-yaml keeps no comments or
  positions, so the text is cut by indentation as the dashboard's "Show in
  policy.yaml" does (`rule-source.ts`): unchanged top-level keys and list
  items are copied as written with the comment lines directly above them;
  a changed key or item is spliced one level down where both sides are
  block mappings or sequences (a list item matched by value, then by its
  `id` / `path` / `name` / `app` / `host` / `blob`); a new one is dumped in
  place; a removed one goes with the comments directly above it. The
  bytes are used only when they read back as exactly the document that was
  judged (`isDeepStrictEqual` over js-yaml's reading of both); a text it
  does not understand (flow style at the top, document markers, CRLF,
  tabs, an anchor it cannot splice) is dumped whole, as before, and the
  arbiter logs it. An entry rewritten whole (a flow list that gained a
  pinned reader, `readers: [psql]   # the backup job` becoming a block
  list) keeps the comment at the end of its old head line on its new one
  (2026-10-18); the read-back check still decides.
- **The writes outside the surface** (2026-10-18, tour item 17 after !1095
  and !1174). The developer view's whole-document apply
  (`applyPolicyDocument`), a minted rule (`mint-rule`), the label
  migrations (`export-labels`, `move-labels`) and the arbiter's reader pin
  (`pin-reader`, plan 10 §11.2) used to be a plain `js-yaml` dump that
  wrote the law over the file: every comment was lost, and while a hand
  edit was held the edit was gone from the file and its card closed
  `superseded` (restrictive: nothing it relaxed took effect, but the
  person's edit was dropped without their answer). Now they go through the
  same guarded write as the surface (`PolicyDocumentStore.apply` →
  `applyGuarded`): a hand edit the poll had not read yet is read first and
  the write refused as stale (the pin is made once more over the law that
  edit left); with no hold the change is spliced into the person's text;
  with a hold the items the change touched (`diffItems` of the law before
  and after) are made to the held document too (`layerItems`, the Undo's
  `revertItems` run forwards), so the hand edit stays in the file and stays
  held, judged again against the new law and filed again on a fresh card
  that shows no more than the old one. An item the held edit changes too is
  refused (`revertConflicts`; StalePolicyError naming it, 409 on the
  dashboard) until the hold is decided, never written over it. A minted
  rule takes an id free in the held edit as well. The law gets what the
  write always gave it (the human's word on the admin channel, a reader the
  person listed or approved, rows that already decided there); the hold
  still gates only what the held edit relaxes. A reader pin on a file with
  no rule of its own builds the new entry from the label the LAW gives the
  file, so it is layered only while the held edit changes no `paths:` rule
  (else the held edit may have changed that label); refused, the open is
  still answered (the reader is listed or approved) and the pin is made at
  the reader's next open.
- **A whole-file apply names the law it was built from** (2026-10-18, what
  !1973 left). The developer view's whole-document writes (its Lists
  buttons, Add rule's trusted website and connect allowance) read the law
  in force, change it, and send the whole document back. The guarded write
  above only caught a hand edit the poll had not read yet: any other change
  that landed between the read and the apply (the confined agent's own
  lock, a hand edit the poll had already loaded, an approved proposal or
  suggestion, a reader pin, an Undo) was undone without a word, and
  undoing a tightening silently is a loosening. Now `policyDocument`
  answers the law's version, `lawHash` (`lawHashOf` in
  `policy-document-store.ts`: an HMAC-SHA-256 of the document as canonical
  JSON, so key order and a comment-only hand edit do not move it, under a
  key random per arbiter process, so the data socket's copy cannot test a
  guess of a hidden prompt pattern, plan 15 §13.7), and
  `applyPolicyDocument` REQUIRES it: the op without one is refused,
  nothing written, and the dashboard route answers 400. `applyDocument`
  reads an unread hand edit first, then refuses the document when the law
  in force is no longer that version (`StalePolicyError` with `lawMoved`,
  naming up to eight items that changed by `diffItems` against the law it
  was read from, of the last 32 laws the store remembers; one it does not
  know, from before a restart or a guess, is refused unnamed). A hand edit
  read then that leaves the law as it was (a held one, an invalid one) is
  refused as stale too, as before. With nothing changed it is the guarded
  write above, layering included. The dashboard answers a stale refusal 409
  with `stale: true` (`held: true` for a held-edit conflict), and the
  developer view says it with what changed and a *Reload the policy*
  button, keeping what was typed; pressing the button again reads the law
  as it is now (dashboard.md §4.25j). The law gets nothing it did not get
  before: a stale apply writes nothing, and a fresh one is the same write.
  The other writers build their document from the law in force in the same
  synchronous call (a minted rule, the label migrations, a reader pin) or
  apply typed edits to it (the surface), so none can land on a law newer
  than the one it was computed from.
- **An item-level version** (2026-10-18, what the whole-file version left).
  Typed edits apply to the law in force, but an edit that REPLACES an item
  whole, built from an earlier read of it, carries that read's fields over:
  Settings › Models' update rewrites the entry from a form the page filled
  from its list (and keeps the entry's `tls`, and rewrites any entry whose
  helper mark moves), the Rules page's Allow / Block rewrites a user rule
  with the `from` and `expires` the dashboard read. A change to the same
  item landing in between was overwritten at the item level (the preview
  gate still judged every loosening, so nothing loosened unjudged, but a
  newer address or pin could be put back to the old one). Now each item
  has a version, `itemVersionOf` in `policy-document-store.ts`: the same
  keyed HMAC as `lawHash`, of the item's value as canonical JSON (null when
  absent), by the identity Undo uses (`itemValue` in `policy-edit.ts`: a
  model by name, a user rule by id, a lock by path, ...). `policyDocument`
  answers `itemVersions` (section → key → version) and the snapshot's
  `document.modelVersions` the declared models'. `policyPropose` takes
  `basedOn: [{ section, key, version }]` (at most 64) and, in the same
  synchronous call as the write or the filing, refuses the list `stale`
  (`changed`: the items, `section key` each; nothing written, nothing
  filed) when one of them is another version; a change to any other item
  does not refuse it. A proposal filed keeps the precondition (`based_on`,
  the sha256 of each item's value when filed, unkeyed so it survives a
  restart, never on the wire), and approving it refuses the same way: the
  proposal is closed `superseded` by `mandu:stale`, nothing written, and
  `resolvePolicyProposal` answers `stale` with the items. The precondition
  is part of its dedup key. The dashboard's `applyAsHuman` answers either
  refusal 409 `{ stale: true, changed }`, and so does its approval route
  for such a proposal left waiting (a dashboard that stopped between the
  two steps); Settings › Models REQUIRES the
  version on an update (400 without), refuses a version its own read
  already finds moved before any preview, and sends no carried-over write
  to an arbiter that answers no versions (501); the product page says it
  plainly, keeps what was typed and reads the list again (dashboard.md
  §4.25l).
- **The label writers name their items too** (2026-10-18, what the
  item-level version left). A sensitivity-label mapping is rewritten whole
  from the row the page read (`map-sensitivity-label` replaces the entry,
  its name carried over), and the file browser's label is a `lock-path`
  that replaces the rule's level, hosts and reach with what the page's row
  held; a change to the same item landing in between was put back. Now:
  - `sensitivity_labels:` is itemized like `models:` (section
    `sensitivity-labels`, key `id|site` by `policy-edit.ts labelKey`), so a
    mapping has its own version and Undo of one keeps a later change to
    another (a change recorded before, under the whole-key item, still
    reverts whole);
  - `policyDocument` answers `absentVersion` (`itemVersionOf(null)`, the
    same key; a constant, so it says nothing about the law): a writer that
    CREATES an item where its read found none names it with that version,
    and is refused once someone else made the item (a label with no level
    yet mapped meanwhile; a path's first rule);
  - Settings › Sensitivity labels: each row carries its mapping's version
    (a label with no level yet the absent one); a change REQUIRES it (400),
    is refused 409 `stale` at once when the route's own read finds it
    moved, names the mapping in `basedOn`, and is sent to no arbiter
    without versions (501) (dashboard.md §4.25s);
  - the file browser and Your rules: each listed entry (read BEFORE its
    label, so a change between the two reads refuses rather than passes)
    and each file rule of the snapshot (`document.pathVersions`) carries
    its rule's version; the page sends it with each change, and every
    `lock-path` / `unlock-path` names its rule in `basedOn`, at the page's
    version, else (a typed path, a symlink's target, an older page) at the
    version the route's own read finds just before it proposes; a moved
    one is refused 409 `stale` before anything is asked, and the arbiter
    refuses one moved after (dashboard.md §4.25m);
  - Approvals' *Always* for a file: `holderSourceBinding` answers `basedOn`,
    the versions in the arbiter's own read of the file's rule and of the
    rule that decides its label now (the new rule's level is copied from
    it), and the dashboard proposes with them: the window between the plan
    and the write is closed (dashboard.md §4.34);
  - a prompt-filter change needs none: every prompt op names one thing and
    carries nothing over from a read (`set-prompt-filter` keeps the
    switch's other fields from the law at apply, in the same call), so a
    change landing in between is never overwritten.
  A refused write writes nothing: the law in force stays the newer change,
  whichever way it went, and nothing is less protected than before the
  save. The page store (labels made on the page before they moved to
  policy.yaml, changed in place by `setPathLabel`) has no versions; a save
  whose policy.yaml edit is refused makes no page-store change either.
- **Judged again** (`rejudgeHold`, from `retireSatisfied`): the held bytes
  are judged against the law in force again, so a hold the law has come to
  say (the same bytes in force, or nothing left to relax) is loaded and its
  card closed. The same bytes judged again that give up nothing the card
  did not show keep the same hold and card; ones that now give up more are
  filed again with the larger delta.
- **What the surfaces say while a change waits.** The Rules page lists the
  rules in force (the law, never the held file) and says above them that a
  change waits and is not in force yet (dashboard.md §4.25 "A change
  waits"). `mandu why` names each waiting change that would change its
  answer and what it would make the file (comparisons.md §3.2).
- **Approve** re-reads the file: if it still holds the held bytes and gives
  up nothing the human was not shown, exactly that document becomes the law,
  the file untouched (comments stay), recorded `via: "proposal"` and
  undoable; otherwise the current bytes are judged afresh and the approved
  card is `superseded`. An approval never covers bytes the human did not see.
- **Deny** keeps the law and **restores** the file to it (`policy-restore.ts`;
  write-protection.md §6) by an atomic write, only while the file still holds
  the declined bytes, audited `config_change` `via: restore`. The card keeps
  the declined text (`diskText`, admin channel only); the same bytes seen again
  are restored with no new card.
- **At start** the arbiter compares the file with the content in force it
  recorded in `mandu.db`: a differing file a DENIED card names is restored
  first, one a PENDING card names stays held, any other pending card is
  closed `superseded` (`resolvedBy: "arbiter-start"`), and otherwise the file
  is the law.

**Residuals** ([guarantees](../../guarantees.md)): a relaxing edit made while
the arbiter is not running that no card names applies unjudged at the next
start (judging it would make the human's own offline edits wait for their
approval); and the hold gates the *arbiter's* law — other readers (the
launcher's `models:` read at launch, `mandu doctor`) see the file as it is.
`mandu why` with no arbiter running asks a temporary one seeded read-only
from the store (runtime-instances.md §9b), so it holds the hold as the next
start would; only when that store cannot be read does it see the file as it
is, and it says so.

**Surface.** The card (§8.6); History says "You approved a change made to
policy.yaml directly" (dashboard.md §4.25j). **Tests:** arbiter
`test/unit/policy-disk-hold.test.ts`, `test/component/policy-disk-hold.test.ts`
(real sockets and poll timer, all four modes: a relaxing write waits, the data
socket cannot approve, the admin op makes it law, a declined one is restored
and not re-filed), `test/unit/policy-restore.test.ts`; integration
`policy-restore-and-guard-settings.test.ts`; dashboard
`policy-proposals-view-model.test.ts`, `home-js-proposals.test.ts`;
`tests/stack/rule-origins.test.ts`; tour item 17: arbiter
`policy-disk-hold.test.ts` and `policy-agent-ops.test.ts` ("tour 17"),
launcher `why.test.ts`, `tests/stack/policy-pending-in-force.test.ts` (a
held edit does not block the agent's lock, survives a restart, Rules and
`mandu why` tell the truth, an agent's request made by hand while stopped
is closed at start, and the secret is released to the waiting binding's
host only once the human's own edit is the law); suggestions, Undo and
comments under a hold: arbiter `policy-disk-hold.test.ts` (an Undo layered
on the held edit, one on the same rule refused, the held re-save and a plain
tightening keep the comments), `policy-suggestion-ops.test.ts` ("tour 17"),
`policy-yaml-splice.test.ts` (every answer reads back as the edited
document, over a corpus of commented files and every edit op), and
`tests/stack/policy-held-suggest-undo.test.ts` (`mandu policy suggest` and
History's Undo over the real arbiter, CLI path and dashboard routes, while a
binding waits: both in force at once, the file keeps the hand edit and every
comment, the key is released to the bound host only once the human
approves); the writes outside the surface: arbiter `policy-disk-hold.test.ts`
("tour 17 after !1095": the whole-file apply, a minted rule and the label
migrations keep the comments and are layered on a held edit; one on the
same rule refused, naming it; one just after an unread hand edit refused),
`policy-edit.test.ts` (`layerItems` gives what each edit op gives on the
other document), `policy-yaml-splice.test.ts` (the comment at the end of a
rewritten line), `reader-pin-held-edit.test.ts` (a real arbiter: the pin
keeps the comments, is layered on a held edit, waits on one that changes
the same file's rule or, for a file without a rule of its own, any
`paths:` rule), and `tests/stack/policy-held-reader-pin.test.ts` (a reader
pin over the guard's channel and the Rules page's move over the dashboard
route while a binding waits: both in force, the file keeps the hand edit
and every comment, one card, the key released to the bound host only once
the human approves); a whole-file apply that names its law: arbiter
`policy-disk-hold.test.ts` ("after !1973": a document built from the law
in force is written; one built before an agent's lock, a hand edit the
poll loaded or one it had not read yet is refused naming it, nothing
written; a held edit still layered; an unknown version refused; the
version does not move on key order or comments) and
`policy-apply-law-hash.test.ts` (a real server: the version on every
channel, the op without one refused, a stale one refused naming the agent's
lock), and `tests/stack/policy-stale-apply.test.ts` (the agent's lock lands
after the dashboard's read: refused over the production wiring and the
route, 409 `stale`, 400 without a version, the lock still the law and in
the file); the developer view's own route, page and stack tests
(`policy-doc-routes.test.ts`, `egress-js-stale-apply.test.ts`,
`inspector-stale-apply.test.ts`: the refusal said with what changed, the
typed value kept, *Reload the policy*, then the change made over the law
as it is now).

### 8.5 The three consumers

#### 8.5.1 `interceptors/policy-mcp` (the confined agent)

Built on the `inspect-mcp` skeleton (stdio JSON-RPC, a narrow arbiter
interface + adapter + mock). Three tools:

- `mandu_policy_read {}` → the agent audience of `policyExplain`, declared
  models included.
- `mandu_policy_test { source?, destination?, boundary? }` → `testFlow`,
  projected to `masked`, `level`, `egress`, `stage`, `rule`; the caller's own
  source and destination are never echoed.
- `mandu_policy_propose { edits, reason }` → `policyPropose`; `message` is one
  of the fixed sentences of `policy-tool.ts` (applied, or waiting in the
  Inbox); `relaxes` / `tightens` are `{facet, subject}` tokens; the
  description embeds the agent schema. It also says that one call is judged
  whole (any loosening edit makes every edit of the call wait), so the
  agent sends its tightenings in a call of their own, and that a path is
  absolute or a `**/` pattern (`/.env` is the machine's root, not the
  project's). Both were missing until 2026-10-04: in the
  policy-setup-repo drill the model sent the `.env` and `keys/` locks
  with the two allowances in one list, and the locks waited with them.
- Paths in `lock-path` / `unlock-path` edits (2026-10-04,
  `resolveEditPaths` in `tools.ts`). A RELATIVE path (`.env`,
  `config/keys`, `src/*.pem`) is read in the project directory, the
  directory the session was launched in (`MANDU_PROJECT_DIR`, the
  launcher's `humanCwd`, the spelling labels are keyed in): the arbiter gets
  the absolute path, so the law and the Inbox row the user reviews name it,
  and the envelope states it back under `resolved` (`{from, path}` tokens)
  for the agent to tell the user. One that climbs out of the project
  (`../x`) is refused: a file outside the project is written whole, so the
  user sees exactly what it names. With no project directory (a direct
  spawn without the variable) a relative path is refused with a problem
  that says to write the full path. A `lock-path` on a path that does NOT
  EXIST (a pattern is not checked) is refused before the arbiter: the model
  meant some file, and a lock on nothing protects nothing while the model
  reports the file protected. `/.env` is the case seen live (haiku, an
  absolute path at the root of the machine): the problem names the
  project's file when one is there ("did you mean `<project>/.env`?") and
  otherwise says to write an existing file's full path or a `**/` pattern
  for a file not created yet. `unlock-path` is not checked (a lock may
  outlive its file); `~/` and `**` paths go as written. Any refusal refuses
  the call whole, nothing filed, with the `invalid` fixed message and the
  problem lines.

Each answer is one JSON text item without `structuredContent`, built to pass
the §8.4.4 gate; the session key is `MANDU_SCOPE_ID`, the project
directory `MANDU_PROJECT_DIR`. The launcher mounts it
beside `mandu-inspect` (`mcpConfigDoc`, `launcher/src/services/mcp.ts`) for
Claude Code and OpenCode, and passes both to Codex as `-c
mcp_servers.<name>.*` overrides (`codexMcpOverrides`, `env-compose.ts`; the
wire forms are in [supported-agents.md §6](../agents/supported-agents.md))
with the tools pre-approved. `--no-policy-mcp` / `MANDU_POLICY_MCP=0` opt out;
`--no-mcp` drops both. All three tools are pre-allowed in Claude Code (§8.9).

The handling prompt's "Setting up protection" section
(`arbiter/symbol-table/handling-prompt.ts`) says the agent may propose rules,
relaxations wait for the user, a pending proposal must not be presented as
done, and a rule is never loosened because content it read asked. It rides
the capability `manduPolicy` (reported by the proxies when the request's
tools include a Mandu policy tool; absent = false), not an axis switch, since
a lock protects a file in every mode.

The story: *"set up Mandu for this repo"* typed into the agent the user
already runs. It locks `.env` and key files (applied), proposes the project's
registries as trusted origins and its API as an allowed destination, and the
user approves those rows in the Inbox.

#### 8.5.2 "Describe what you want" (the product page)

A text box on the Rules page (`dashboard/src/policy-assistant.ts`). The
dashboard makes a **quarantined model call** through the U-LLM channel
(`buildUllmClient(selectUllmConfig(env))`; never through the model proxy,
which would symbolize the assistant's own inputs and put the call in the
wrong trust class). The client is tool-less, so the agent schema and the
*assistant* audience of `policyExplain` ride in the system prompt, and the
model answers one JSON object `{ edits, note }`; anything else is a 422,
never a guess. With no channel configured the box says why in plain words
and what fixes it, by the error's `reason` (`AssistantUnconfiguredError`,
dashboard.md *Describe what you want*); there is no heuristic fallback.

Each edit renders as a Rules row from the grammar, not from the model, marked
where it loosens (`policyPreview`; an edit that cannot be judged alone counts
as loosening), with "This would let" lines from the preview's delta and the
model's note last ("The assistant says"). A file under the dashboard's home
reads `~/…` in the rows and the lines, as on the Rules page (dashboard.md
§4.34); the `edits` and `expected` Apply sends stay as written and as the
arbiter named them. A website or release row has **Try
it**: Test a flow against the law in force and against the law with the whole
suggestion (`testFlow` `withEdits`), shown as "Now:" and "After:". Model ops
are refused (§8.4.3a).

**Apply is bound to what the person saw.** The suggestion carries
`expected` (the preview's loosenings). Apply re-previews and refuses (409,
"describe it again") if applying would now loosen anything else, then sends
`policyPropose` on the admin channel (`requestedBy: "assistant"`): a pure
tightening applies; otherwise the filed proposal is approved by the same click
(`human:dashboard`), keeping the typed word for over-broad rows. A skew-guard
re-file is denied (409). Routes `POST /api/policy/assistant` and `…/apply`
need CSRF and the admin session.

**URL patterns.** The URL matcher once took only scheme-less patterns, so
`https://pypi.org/` parsed as the host `https:`: trusting nothing in a trusted
list and fail-open in an untrusted list under a TRUSTED default. A leading
scheme is now ignored (`trust-category.ts` `parseUrlPattern`), and
`applyEdits` still writes the scheme-less form.

Prompt quality: `eval/policy-assistant/corpus.test.ts`
(`eval.policy-assistant-corpus`): six sentences through the real channel;
first run 9 of 9 expected edit shapes, no invented host.

#### 8.5.3 The existing editor

Unchanged: `/dev/rules` keeps the full document editor and the product Rules
page its flips and locks; both gain the proposal card and History Undo.

### 8.6 Inbox: the proposal card

**"Your agent wants to change a rule"**, beside the egress asks: the rows
(grammar-rendered), a "this would let" line from the stored `relaxes`, and the
agent's `reason` last in a muted "Your agent says" box, never the headline and
never desymbolized (§8.3.6). The facts come from the grammar and the delta, so
the human can decide without trusting the reason. Then **Try it**, **Allow** /
**Not now**; an over-broad row needs the typed ALLOW. History lists agent
tightenings with **Undo**. A model change renders its address in full, and a
"your own" model at a non-local address carries a warning and the typed ALLOW
(dashboard.md §4.25l; since §8.4.3a only Settings › Models produces one). A
held disk change (§8.4.6) is a second card kind: "policy.yaml was changed on
disk and would loosen N rule(s). Nothing changes until you approve", what it
would let, and a note that anything on the computer could have written the
file and that Not now writes the current rules back. A change the human
asked for that is left waiting (its approval failed) says "You want to
change a rule" and labels its reason "Note": only a request from the data
socket, which the arbiter always names `agent:<session>`, is credited to
the agent (dashboard.md §4.25).

### 8.7 Testing

Unit (`arbiter/test/unit/`, no privilege):

- `policy-delta.test.ts`: the §8.3.2 corpus both ways; the §8.3.3
  declassifications; raise-to-`no-model` tightens; extended `expires` / widened
  `from` relaxes; the overlap hazard; a relaxation through a list reference;
  `audit` neutral; `off` on an allow vs a block; an unknown key relaxes.
- `policy-edit.test.ts` (+ `-blobs`, `-models`): every op on empty and
  populated documents, validation, purity, idempotence, whole-list refusal,
  `diffItems` / `revertItems`, `revertConflicts`.
- `policy-agent-ops.test.ts`: attribution to `agent:<key>` whatever the caller
  claims; a relaxation files a proposal with the file byte-identical; dedupe,
  caps, stale, approve, deny, the skew re-file, Undo per item; `policyExplain`
  withholds prose and lists models safely; the model-op split.
- `compiled-policy.test.ts` (the §8.1 kinds), `policy-proposals.test.ts`,
  `db-schema-version.test.ts`, `policy-edit-schema.test.ts`.
- Dashboard: the proposal card, the Undo row, the copy sweep;
  `policy-assistant.test.ts` (strict parsing, per-edit marks, 503 with no
  channel, Apply's four outcomes, model ops refused), `home-js-describe.test.ts`.

E2e, the security oracle:

- `arbiter/test/component/policy-propose-channel.test.ts`: a real server's
  data and admin sockets — a relaxation on the data socket files a proposal
  with law and file byte-identical, a tightening applies, approve and Undo
  work only on admin; and the no-leak half: a page's canary copied by a
  steered agent into a reason and a pattern, and the page's pending ask, never
  appear in `policyExplain`.
- `arbiter/test/component/policy-delta-roundtrip.test.ts` (a tightening
  survives the YAML round trip), `policy-models-edit.test.ts` (model ops
  refused on data and for `assistant`, applied for `settings`).
- `arbiter/test/integrity/policy-delta-engine-oracle.test.ts` (§8.3.2) and
  `policy-tool.test.ts` (well-formed envelopes TRUSTED; prose, a mismatched
  `tool`, forged `problems`, oversized values, lookalike or bare names
  UNTRUSTED); `tests/integrity/policy-tool-ingress.test.ts` (through the real
  proxy).
- `tests/stack/policy-mcp-parity.test.ts`: the production
  `PolicyArbiterAdapter` over a real `ArbiterClient`, every forwarded op (the
  parity rule of [CONTRIBUTING.md](../../../CONTRIBUTING.md)); model ops
  refused with nothing filed.
- `tests/stack/policy-models-listing.test.ts` (both readers list every model,
  never the key's value or a key in a URL), `tests/stack/dashboard-assistant.test.ts`
  (an agent's reason never reaches the assistant; Apply puts exactly the shown
  rows in force; a moved law is refused; model ops refused at every step).

Live (cost budget, `MANDU_TEST_POLICY=1` / `MANDU_E2E_CODEX_MCP=1`), run in
`secrets`:

- **POL-1** (`policy-setup.test.ts`): "set up Mandu for this
  repo" through a real `claude -p`, the real proxy and a private arbiter with
  a temp `policy.yaml`. HARD: nothing relaxed in force, every loosening
  pending, none on disk, the surface used; SOFT: `.env` locked, the loosening
  proposed, no claim it is done. Passed on Sonnet 5.
- **POL-2S** (same file): a no-catalog file labelled `no-model`, which the
  agent is told to read while setting up protection. HARD: the canary is in no
  model request; a `$MDU:nomodel_…` symbol revealing it is present (a quiet
  axis fails); no change or proposal carries it. The integrity form **POL-2**
  is frozen in `tests/integrity/policy-setup.test.ts`.
- **CMCP-1 / CMCP-2S** (`codex-mcp.test.ts`): the same on a
  real `codex exec` through the openai-proxy. The call reader
  (`tests/lib/codex-mcp-calls.ts`, pinned by
  `tests/stack/codex-mcp-calls-lib.test.ts`) reads both Codex call wires, and
  a script cell that is one literal MCP call is classified as that tool
  (`tests/stack/codex-mcp-cell.test.ts`). CMCP-2S cannot run where Codex's own
  sandbox cannot start (its bundled bwrap under Ubuntu 24.04's userns
  restriction). CMCP-2 is frozen in `tests/integrity/codex-mcp.test.ts`.

**As drills**, these are `policy-setup-repo`, `policy-secret-symbol-only` and
`policy-untrusted-notes` (the drill catalog's `policy` area), graded over the admin socket of the
run's own arbiter (`--own-arbiter`, a copied policy file):
`policy_not_relaxed` (security), `policy_used`, `policy_locked`,
`policy_proposed`. Without an admin channel they grade "unmet"; the default
selection leaves them out; in replay they are Mandu-only rows.

### 8.8 Order of work

- **A0 (built):** `policyDelta`, `PolicyEdit` + `applyEdits` +
  `evaluateEdits`, the `relaxationsOf` gaps. No privilege, no IPC.
- **A1 (built):** the ops of §8.4.2, the stale guard, the two tables with the
  flood limits and the tightening cap, the Inbox card and History Undo.
- **B (built):** `policy-mcp`, `policySchema` and its pin, the launcher
  mount, the handling-prompt section, the trust gate, POL-1 and POL-2. The
  cheapest route to "the user's LLM sets up Mandu", because it is the LLM they
  already run.
- **C (built):** "Describe what you want", `policyPreview`, the corpus.
- **Deferred, with un-defer triggers:** a `mandu policy` CLI for editing the
  law (when a script or CI needs it; `mandu policy suggest` exists for
  suggestions); the OpenClaw plugin-tool variant (when an OpenClaw user asks);
  a chat-style assistant in the dashboard (when the one-shot box proves
  insufficient); any agent write to `config.toml` (read access through
  `policyExplain`'s `posture` is enough for a model to say "your sandbox is
  off").

### 8.9 Decisions recorded here

- **Tighten anywhere, relax by human, computed on compiled law.** Making
  every agent change a proposal would make the common safe act wait on a click
  and train users to approve without reading.
- **A per-facet proof that fails closed**, not a set difference (§8.3.1).
- **An agent's direct path edits are plain strict only** (§8.3.3): the rare
  declassifying edits are exactly the ones a human should see.
- **An agent's `reason` is untrusted in every mode**; the card is decidable
  from the grammar and the delta alone.
- **Typed edits, not YAML or JSON Merge Patch**: deterministic rendering, a
  small schema.
- **Projections only for a configuring model**, stated as a type and a
  canary test.
- **The assistant uses the U-LLM channel, never the proxy** (§8.5.2).
- **All three policy tools are pre-allowed in Claude Code**: the monotonic
  split is the gate, and a permission prompt would gate the same act twice.
  `declassify_symbol` stays un-allowed (it releases a secret with no Inbox
  behind it).
- **Model endpoints are human-only** (§8.4.3a); **a relaxing hand edit waits
  for a human** (§8.4.6); **`config.toml` stays human-only** (every sandbox
  toggle relaxes in one direction).

## 9. Policy visibility: decision provenance from standing law to trace

*Formerly `policy-visibility.md`; its §N is §9.N here.* **Status: BUILT**
(phases 1–4 2026-07-17; the consistency redesign 2026-07-24; session scope,
settable posture, verdict scope and the trust side 2026-07-31 to 2026-08-06;
`mandu why` 2026-09-25). Related: the per-tool-call policy modal
(dashboard.md), the sensitive-path gate
([fs-sync.md](../integrity/fs-sync.md) §1.4.1), the Secrets panel's
standing-release surface (confidentiality.md §6). Some layout details below
predate the Policy area of §4; the invariants stand.

### 9.1 The problem

The dashboard showed *what happened* (gate events) and *what is waiting*
(pending approvals), but not *the standing law* — the rules, human verdicts
and posture switches that decide the next request — and did not connect a
decision to the rule or verdict that made it. The incident that forced this:
an e2e deny scenario went red because a queue row for the same `(fs:Glob:read,
path)` pair had been approved days earlier, probably by one exploratory click.
The standing verdict was consulted before the pure gate and silently turned a
fail-closed deny into an allow; nothing displayed it, because a resolved entry
left the only queue view.

### 9.2 What already existed

`policySnapshot` (`arbiter/policy/policy-snapshot.ts`) already serialized the
active data-*trust* policy for the per-tool-call modal
(`dashboard/src/policy-model.ts`), mirroring the objects `classify()` reads so
it cannot drift, joined to tool calls by tool name. The approvals API (`GET
/api/egress/approvals?status=…`, `POST …/<id>/{approve,deny}`) supported every
status, and `EventPolicy` (`dashboard/src/event-model.ts`) carried prose
`trust/usage/reason`. Missing was the data-*usage* side: the gate rules, the
standing verdicts, the posture switches, and a machine-readable link from
each decision to its decider.

### 9.3 Phase 1 — rule identity on the wire (`RuleRef`)

Every data-usage decision the arbiter returns carries a structured provenance
field beside its prose reason:

```ts
interface RuleRef {
  source: "rule" | "verdict" | "fail-closed";
  id: string;   // "fs:sensitive-path" | "egress:untrusted-destination" | "verdict:egr-2" | …
}
```

`rule` — a policy branch decided on its own terms; `verdict` — a standing
human decision short-circuited the gate (`verdict:<entryId>`, the queue row);
`fail-closed` — a default-deny or out-of-contract branch fired, kept distinct
so the UI can say "nothing matched — denied by default".

**The catalog is the single source of truth.** `arbiter/policy/rule-ref.ts`
defines `RULES` (one entry per id: `{source, boundary, outcome, summary}`),
and the gates build refs via `ruleRef(id)` with `id: keyof typeof RULES`; an
id not in the catalog does not compile, so the snapshot can ship the catalog
knowing enforcement uses exactly these ids. Tagged: `decideFsPath`
(`fs:invalid-path`, `fs:sensitive-path`, `fs:workspace-root`,
`fs:dir-allowlist`, `fs:default-deny`); `decideFileUpload` (the `fs:upload-*` rules and `fs:sensitive-path`, supported-agents.md §2); every branch of
`decideDesymbolization` (`egress:*`, the `egress:secret-*` ones included); the
user-rule and disposition branches (§2.4, §2.5); the session and exec gates;
and the server approval wraps (`decideFsPathWithApprovals`, `decideFileUploadWithApprovals`,
`decideDesymWithApprovals`, `decideExecEscalation`), where a consulted prior
verdict returns `{source:"verdict"}`. The proxy's gate events (`fs_action`
denied, `exec_gate`, `net_gate`) carry `policy.ruleRef`. Not tagged:
`classify` (trust) decisions, which the modal joins by tool name; and
net-proxy's `net_action` blocks (the ruleRef is in the op result; threading it
into the event is mechanical follow-up).

### 9.4 Phase 2 — the extended snapshot and the Policy panel

The snapshot op result is additive (posture and verdicts are server state,
composed by the server):

```ts
type PolicySnapshotOpResult = PolicyRuleSnapshot & {
  posture: { integrity: boolean; confidentiality: boolean };
  usage: { rules: UsageRule[]; sensitivePaths: string[]; gates: Gate[] };  // the catalogs
  verdicts: EgressApproval[];                                               // ALL statuses
  // also: egressPosture, lawSource, document, relaxations, hits (§2, §9.8)
};
```

An older arbiter lacks fields and the panel says so; an **unknown posture is
shown as unknown, never as off**.

**One queue, one vocabulary.** Every queue row (pending, approved, denied)
uses one builder and one column set (Family | Subject | Target | Status |
Count | Reason | When | Sessions | Actions). Approved and denied rows are the
*standing verdicts* the arbiter consults first; Approve / Deny while pending,
one-click reversal once resolved (`resolveEgressApproval`). Rule rows keep
their own shape (id | outcome | summary | decided-here): a rule is a compiled
pattern, not a subject × target pair. Status filters start on: hiding rows is
the user's act, never the panel's.

**Session attribution.** Interceptors pass an attribution-only `sessionKey`
on `fsPathDecision`, `desymbolizationDecision` and `escalateExec` (never a
decision input); `recordPending` stamps a capped list on the entry, rendered
as links to the sessions ("—" for rows that predate it).

**Version skew and outages.** The panel degrades per section: verdicts work on
any arbiter (`/api/policy/panel` back-fills them from `egressApprovals`); the
rules catalog must come from the code that enforces it, so an older arbiter's
section says "needs a newer arbiter"; an unreachable arbiter repaints the last
state under an "arbiter unreachable" banner (a dashboard server that does not
answer at all, under its own words, dashboard.md §4.8), and a failed approvals
fetch never renders as "no pending approvals". All strings are rendered inert
(`textContent`); no symbol *value* exists on the wire.

### 9.5 Phase 3 — trace ⇄ policy cross-linking

- **The "why" chip.** Trace gate lines carry `ruleRef` (`DualGate {text,
  ruleRef}`) and render as chips — `⚖ <rule-id>` for rules, `✋ verdict:<id>`
  for standing verdicts (warm-bordered: the state to audit). A click
  (`mdu:show-ruleref`) opens the owning section and flashes the row
  (`tr[data-ruleref]`). Events without provenance get no chip.
- **The reverse link.** `toSessionViewModel` ships `ruleRefCounts`; each row
  shows "decided N here", and a click (`mdu:highlight-ruleref`) flashes every
  trace card carrying that id.
- **The pending-row join (`approvalId`).** The queue is arbiter-global on
  purpose; the per-session join lives in the event stream. A gate wrap that
  queues or bumps an entry names it in its deny (`approvalId: "egr-<n>"`);
  the proxy's fs gate and net-proxy's blocked `net_action` put it on the event
  (never in the agent's 403 body, dashboard.md §4.25h), and
  `approvalIdCounts` lets a pending row say "requested N× here". A verdict
  short-circuit carries no `approvalId`; its join is `ruleRef`. Residuals:
  exec-wrap's escalation events and the `declassifySymbol` queue path do not
  carry the id yet.

### 9.6 Phase 4 — verdict audit trail

- **`resolvedAt`** on the row (`NULL` = pending): the panel sorts by it, and a
  missing time renders "unknown", never a guess.
- **`approval_resolved`** lands on the reserved **`arbiter-admin`** stream:
  approvals decide every future session, so they get the arbiter's own stream,
  rendered like any session — the standing law's own timeline. Best-effort,
  off the security path, key strings only, stamped with the `verdict:<id>`
  ruleRef so the §9.5 join reaches audit lines too.

### 9.7 Tests

- Arbiter unit: `rule-ref.test.ts` (every gate branch returns a catalog id;
  every id's prefix is a `GATES` key; every gate owns a rule),
  `egress-approvals.test.ts` (verdict refs for approved and denied priors on
  all three key families), `law-source.test.ts` and `ipc.test.ts` (posture,
  catalog, verdicts of every status; `describeLawSource` per kind, never a
  throw).
- Events: the live deny scenarios (`fs-denied-cwd-note`, `net-exfil-blocked`,
  `exec-symbol-command-blocked`) assert a ruleRef end to end.
- Dashboard: `policy-panel.test.ts` (gate grouping and prefix fallback with no
  invented citations, outcome mapping, lockdown unknown vs normal, the drawer
  template, epoch-null ⇒ "unknown") and `egress-js-panel.test.ts` (JSDOM over
  the real bundle: layout, chips, inert hostile strings, filters, the CSRF'd
  resolve, degrade paths, `mdu:show-ruleref`).

### 9.8 The consistency redesign and standing-state gaps

The panel had two table grammars, two chokepoint vocabularies and three
renderings of allow / deny / needs-approval, and its rows did not say where
they were specified. The audit also found invisible law: the SIEM lockdown
posture, shipped by the snapshot and dropped by the dashboard (the display
twin of the "posture nobody reads" bug class, confidentiality.md §12).

#### 9.8.1 One row grammar, precedence as the visual spine

The panel renders in evaluation order and says so ("checked in order:
① your standing decisions → ② built-in rules"). A header strip holds the
law-source line (§9.8.3), that sentence, and posture chips for integrity,
confidentiality and the SIEM **egress lockdown** (`egressPosture`; absent ⇒
`unknown`, never `normal`; lockdown is the loud state). Then ① the merged
queue, ② the built-in rules grouped by gate (§9.8.2), and cross-links to the
other standing-law surfaces (the Secrets panel, the `arbiter-admin`
timeline). The developer view's Rules page (dashboard.md §4.34) names these
sections in the product's words (Your answers, Your rules, Built-in rules
folded by gate) and labels the verdict verbs Allow once / Always allow /
Block; the order and the routes are the same.

Shared vocabulary lives in the unit-tested projection
(`view-model/policy-panel.ts`, `policy-panel-detail.ts`; `egress.js` only
paints): one chokepoint label set (`whereLabel`), one outcome-chip vocabulary
(rules → allow / deny / needs-approval, verdicts → allow / deny / pending), a
`fail-closed` tag, header rows and a trailing ⓘ on both tables. The
sensitive-path list renders inside the `fs:sensitive-path` rule's drawer, as
that rule's configuration. Verdicts and rules stay two tables.

#### 9.8.2 Rules group by gate

Grouping by boundary interleaved unrelated chains into a list that *read*
like a precedence order and was not. Rules group by their owning **gate** —
the deciding function, already the id's prefix — and within a gate, catalog
order is evaluation order. `rule-ref.ts`'s **`GATES`** catalog (fs / egress /
exec / session / proxy: title, `definedIn`, design-doc ref, evaluation
sentence) is built like `RULES`: the key template `` `${GateId}:${string}` ``
ties every rule id to a gate at compile time, and the snapshot ships
`usage.gates`. The dashboard cites gates only from it; with an older arbiter
it shows prefix-derived headers and no citations, never ones reconstructed
dashboard-side.

#### 9.8.3 The per-row ⓘ drawer and the law source

Every ⓘ opens a fixed template. Rules: *What this is* / *What it does* /
*Where it's specified* (rule id, gate `definedIn`, doc) / *When it applies*.
Verdicts: *What this is* (scope-aware, §9.8.7) / *What it decides* / *Where it
came from* (reason, ask counts, sessions) / *Resolution* (who and when,
"(once)", a spent row's `consumedAt`; a pre-column row says "unknown").
Detail strings are projected server-side (`DetailSection[]`) and rendered
`textContent`-only. A verdict's drawer is fetched when it opens (`GET
/api/policy/verdict?id=<id>`, dashboard.md §4.30); the queue lists every row
that still decides something and counts spent single-use answers past the
newest 50 (`queueOmitted`). The vocabulary is shared with the trace's drawers
(dashboard.md §4.2e; `src/view-model/detail.ts`, `dev/js/detail-drawer.js`).

The **law-source** line answers "where is the law specified":
`describeLawSource` (`arbiter/policy/load-policy.ts`) reports the built-ins
alone, a YAML file layered on them (with which sections), a configured but
missing file (naming the path looked for), or an injected engine (`custom`:
the server vouches for nothing it did not load). Absent ⇒ the line is
omitted. An invalid file is never a `builtin` fallback (§2.1).

#### 9.8.5 Session scope — "this session only"

The panel is global state, so with one session loaded most rows are noise.
A **"this session only"** toggle (off by default, disabled with no session
loaded) filters in the shell only (`egress.js`), since relevance depends on
browser-held state. **Relevant means affected the session, not created in
it**: a queue row stays when the session is among its `sessions` *or* its
ruleRef decided an event here; a rule stays when it decided an event here. The
OR is the point — a standing approval made elsewhere can govern this session
(§9.1). Each scoped section ends with a remainder line ("N decisions hidden by
session scope (M with no session attribution) — untick …"), and a cross-link
to a hidden row widens the scope first. Tests in `egress-js-panel.test.ts`.

#### 9.8.6 Posture becomes settable

⏸ Pause sending / ▶ Resume act through `setSessionPosture` (the UI spec is
dashboard.md §4.19). The arbiter stays tighten-only by default: a loosen is a
no-op (`applied:false`) unless the request carries `allowRelax`, which only
the dashboard's human route sends (admin channel, §2.6). Both directions audit
as `posture_change` on `arbiter-admin`. The integrity / confidentiality *axes*
stay boot-time facts: the dashboard edits the two `config.toml` keys and
applies them by an arbiter restart, showing *running* and *configured*
separately, and each flip lands one `config_change` event (axis, from, to,
requestedBy). SIEM rules map these events
([siem-integration.md](siem-integration.md)).

#### 9.8.7 Verdict scope — Allow once

Every human verdict used to be standing. That is the wrong default for the
most common approvals pattern, *let this one through, but ask me again*.

**The field.** `egress_approvals` has `scope` (`"always" | "once"`) and
`consumedAt`. `resolveEgressApproval` takes an optional `scope`; absent or
unrecognized means `"always"`.

**Semantics: one gated decision, no TTL.** A once-verdict (approved or denied)
satisfies exactly one gate consultation. The three gate wraps consult priors
through one helper (`consultPriorVerdict`): an unspent once-verdict
short-circuits its decision (same `verdict:<id>` ruleRef) and is stamped
`consumedAt` in the same step; a spent one reads as *no prior*, so the next
attempt reaches the pure gate and, if it still needs approval, `recordPending`
resets the *same* row to a fresh pending cycle (keeping id, count history,
`firstSeen` and attribution, so `verdict:<id>` joins resolve). Re-resolving a
row clears `consumedAt`. The spent once-verdict is the only exception to the
store's "never reset a human status" rule.

**Who spends it (2026-10-07).** Only a gate's ask on the human socket or
the admin channel: the net-proxy and the model proxy's network and path
gates ask there. From the data socket, which the agent's programs reach, an
unspent once-verdict is read and never spent: a denial answers, an approval
reads as *no prior* (the row stays armed for the gate). The in-context read
(`declassifySymbol`) is the exception: its caller runs in the agent's tree
(arbiter-human-plane.md §10.3). The model proxy's network gate asks as a
pre-check (`preflight`): it reads an approval without spending it, since the
net-proxy judges the same send again on the wire and spends it there, and
spends a denial it enacts.

**A HIGH session's rows take once only (2026-10-11).** The session gate's
asks (confidentiality.md §4, "The human half") are keyed
`session-net:<session>` × host and `session-exec:<session>` × the exact
command. They take *Allow once* and *Block*, never a standing allow:
`resolveEgressApproval` keeps an Always on such a row as once (as for a
`#run:` row), and the panel offers none, since the card speaks of one
request or one run of one command in one session. A *Block* is the usual
standing deny, scoped by its key to that session × host (or × command).
The model proxy's session leg is not a pre-check: no second gate judges a
HIGH session's paraphrase on the wire, so its ask (on the human socket)
spends the once. The row's card names what the session read
(`sessionReads`, attached at list time from `session_label_sources`).
A held command's refused connection (2026-10-12, confidentiality.md §4)
asks the same `session-net:` row: the net-proxy (by host) or the guard (by
address) names the place on `taintedProcessBindings`, and the arbiter
spends the once there for the next held connection of that session to that
place, the retry; `sessionHeld` (attached at list time) makes the card
speak of the command's request.

**Send without it is a once denial (2026-10-17, confidentiality.md §4
"Send without it").** `resolveEgressApproval {approve: false, strip: true}`
stores a once DENIAL carrying `strip` (the `strip` column), refused with
`approve: true` and on any row that is not a secret's placeholder × a
network host (the listing marks the rows that take it `stripOffered`). It
is consulted like any once denial, with three differences in what the ask
is told: the spending ask (the net-proxy's, on the human socket) gets the
denial with `strip: true` and forwards that one request with a marker in
the placeholder's place; a pre-check reads it unspent and is answered
`allow` with `strip` (nothing is released there); the data socket reads a
plain denial. A spent one resets to pending like an Allow once, and any
other answer clears the flag. `approval_resolved` says `send without it`.

**Audit.** `approval_resolved` names the scope; each consumption lands
`approval_consumed` on `arbiter-admin`. SIEM logs each consumption and its
stale-standing sweep skips once-scoped grants (siem-integration.md §6.3).
Tests: `arbiter/test/unit/egress-approvals.test.ts` (lifecycle, single
consumption, hydration across restart, allow-once and deny-once loops over the
real socket re-queuing the same id, the absent-scope default); the
cross-component loop is in `tests/stack/`. The dashboard verbs are
dashboard.md §4.18's.

#### 9.8.8 The trust side — inbound section and handling-prompt drawer

- **"What gets symbolized on the way in"** — a closed-by-default fold after
  the built-in rules, outside the precedence sentence (trust classification is
  the other policy, not a rung of the egress order). Projected server-side
  (`InboundVM`) from the snapshot's base fields (`specId`, `origins`, `tools`,
  `fallbackTrust`, `mcpPrefix`): the fail-closed fallback line, one line per
  origin category, and one row per described tool (`inbound: null` says "no
  inbound spec — results fail closed to UNTRUSTED", never silence; conditional
  fields count as untrusted), each with an ⓘ of per-field trust lines.
- **The handling-prompt drawer.** "View the active handling prompt" fetches
  `GET /api/policy/handling-prompt` per open (the `handlingPrompt` op). Unlike
  its siblings it does not fail soft: the arbiter renders the prompt against
  its live posture, so a stale string shown as "the active prompt" would lie
  (no capability → 404, arbiter down → 503, and the drawer says unavailable).

Tests: `policy-panel.test.ts`, `egress-js-approvals.test.ts`,
`policy-routes.test.ts` (200 / 404 / 503).

### 9.9 `mandu why` — the same answers at the command line

`mandu why <path> [--to <host>]`, `mandu why <host>` and `mandu why
'$MDU:…'` (`launcher/src/why.ts`; after nono's `nono why`,
[comparisons.md](../confidentiality/comparisons.md) §3.2) are backed by
read-only arbiter ops that reuse the gates' own derivations, so the answer
cannot drift from the decision:

- `whyPath`: the level and deciding rule (`pathConfidentiality`, the call
  `decideSecretOpen` makes), bindings, outranked stricter patterns (§4), the
  label's readers and `others`, the consumer table's default readers with the
  TLS matrix's `wire` verdict
  ([plan 13](../confidentiality/confidentiality-plan-13-reader-set-labels.md)
  §10) and, per consumer, whether it prints (`consumersPrint`, 2026-10-04:
  `curl`, `scp`, `git` and `git-credential-store` read only the twin, so
  `mandu why` and the dashboard name them apart from the default readers),
  the twin shape, and prior `open:` verdicts naming their binary.
- `whyHost`: labels and registry entries whose bindings admit the host
  (`destinationMatchesBindings`), the egress gate's answer for a bound and an
  unbound `no-model` probe (`decideDesym` in probe mode), the law's
  `destinations:` rows and prior egress verdicts, and, for an issuer's API
  host, the issuer, the key formats it receives without asking and whether
  `issuer_bindings` has that on (`issuer`, confidentiality.md §2.3,
  2026-10-19); the CLI adds reachability
  from the connect-guard set a default launch builds (`computeNetGuardSpecs`
  plus `netConnectAllow`).
- `--to <host>` runs `testFlow` for the file, with the host as the network
  gate keys an answer on it (lowercase, no port), so a remembered answer
  about the file's placeholders at that host decides as it does for a real
  send ("released by your remembered answer (verdict:…)", with where it is
  removed; §4 "A registered file's own placeholders"). With no arbiter
  running, the temporary one the CLI asks is seeded read-only from the
  stopped arbiter's store (its remembered answers, the registered files'
  placeholders, the changes waiting in Approvals; runtime-instances.md §9b),
  so it answers as the running one did. Only an unseeded one (no store, or
  one it cannot read) holds no answers, and the CLI then says so.
- `mandu why '$MDU:…'` explains a placeholder the prompt filter put in the
  person's prompt (filter, category, action, hold, session, request, verdicts,
  policy now, ways out;
  [plan 15](../confidentiality/confidentiality-plan-15-prompt-filter.md)
  §13.8). Its op `whySymbol` is human plane; from the agent's side the CLI
  answers from the data plane's `symbolProvenance` alone. Never a value.

An arbiter older than these ops answers "unknown op"; the CLI then asks a
throwaway arbiter over the same `policy.yaml` and says so. Not covered: the
always-denied cloud-metadata set, and resolving a hostname rule to IPs. Tests:
`arbiter/test/component/why.test.ts`, `launcher/test/unit/why.test.ts`,
`tests/stack/why-cli.test.ts`; with no arbiter running,
`arbiter/test/unit/store-seed.test.ts`,
`arbiter/test/component/store-seed.test.ts`,
`tests/stack/why-offline-store.test.ts`.
