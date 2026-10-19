# The DevTools relay: Mandu between a browser agent and Chrome

**Status (2026-10-18):** steps 1 and 2 built: the relay package
(`interceptors/cdp-relay/`) with its unit, component and stack tests (§7).
Step 3 built: `mandu --browser-cdp <Chrome's endpoint>` starts it for a
launch, gives the agent its URL and keeps Chrome's own port out of the
connect guards (§6.1); `mandu --browser` starts the Chrome itself, its own
traffic through the egress proxy (§6.4); the session page tells what the
relay did (§5.1). Mode `secrets`; the relay has no integrity behaviour.

## 1. Why

A browser agent (jev-ultrafast, browser-use, the Playwright and Chrome
DevTools MCP servers, Stagehand) does not read web pages from the network.
It reads them from Chrome over the DevTools protocol (CDP): the DOM, the
accessibility tree, the results of scripts it runs in the page, network
bodies. It acts over the same connection: clicks, `Input.insertText`. What
the agent reads it sends to its model, often a model API Mandu's model
proxies cannot read (jev's is a proprietary wire).

So the secrets at stake are the ones a page shows: a cloud console showing a
key that is also in `~/.aws/credentials`, a settings page echoing a token the
agent typed. Without Mandu they reach the model provider with no attacker
involved.

Two places could swap a secret for its placeholder:

| | In the network between Chrome and websites | On the DevTools connection (this design) |
|---|---|---|
| What it needs | Chrome started by Mandu, Mandu's CA in its own certificate store, every text response decompressed, rewritten and re-framed (HTML, JSON, streams, WebSocket frames) | a relay on one JSON connection |
| What the window shows | placeholders (it is the agent's browser, not the person's) | the real values: the person can keep using it |
| The person's own Chrome | no | yes |
| What it sees | only what crossed the network | everything the agent reads, including a value the person typed or a password manager filled |
| Pixels | the page itself holds placeholders | not masked (refused, §4) |

The relay is the one built. The network rewrite stays deferred: its only
remaining case is an agent that drives a browser through an extension
instead of CDP.

## 2. Where it sits

```text
 website ──real── Chrome (the window: real values, the HumanView)
                    │ CDP (Chrome's debugging endpoint, loopback)
               Mandu relay   Chrome → agent: secrets become placeholders
                    │        agent → Chrome: a placeholder becomes the value
                    │                        only for a page bound to it
                  agent ──placeholders── its model (the AgentView)
```

### 2.1 The endpoint

The relay answers like Chrome's own endpoint, on loopback only (a request
whose `Host` is not a loopback name is refused, Chrome's own DNS-rebinding
rule):

- `/json/version`, `/json`, `/json/list`, `/json/new`, `/json/activate/<id>`,
  `/json/close/<id>`, `/json/protocol` go to Chrome. The WebSocket URLs in
  the answer are rewritten to the relay's; the front-end links that embed
  one are dropped; every string (page titles, URLs) is masked like a
  message (§3.1), except in the protocol schema.
- A WebSocket on `/devtools/...` is paired with one to Chrome on the same
  path (`pair.ts`).

The server half of the WebSocket is the package's own (`ws-server.ts`: text
messages, fragmentation, ping, close; binary messages and extensions are
refused); the half to Chrome is Node's built-in client.

### 2.2 One connection pair

- **Agent → Chrome**, one message at a time, in order: a refused command
  (§4) is answered with an error and never reaches Chrome; a release
  command runs §3.2, and the agent's later commands wait for it (an Enter
  sent after typing lands after the text); anything else is forwarded under
  an id the relay assigns, so the relay's own commands share the id space
  without colliding with the agent's.
- **Chrome → agent**: an answer to the relay's own command goes to the
  relay and never to the agent. Every other message is masked (§3.1) and
  delivered in the order Chrome sent it: each message's filter call starts
  when it arrives, the deliveries wait for each other. Only the payload
  (`params`, `result`, `error`) is scanned; the envelope (`id`, `method`,
  `sessionId`) is the protocol's.

## 3. The two directions

### 3.1 Reading: what Chrome sends the agent (`inbound.ts`)

1. **Credential headers** are withheld wherever they sit, in each form Chrome
   sends them (a header object, a `[{name, value}]` list, a raw
   `headersText` block, a cookie object): `Cookie`, `Set-Cookie`,
   `Authorization`, `Proxy-Authorization`. They are replaced by a fixed text,
   not a symbol: a session cookie is not a registered secret, and the agent
   never needs it.
2. **Unreadable bytes**: a message carrying `base64Encoded: true` (a binary
   response body, a resource, a stream chunk) or a binary WebSocket frame is
   withheld whole. The relay cannot read it, so it cannot say it holds no
   secret.
3. **Every string** of at least 8 characters (the arbiter's own floor for a
   value it fingerprints), values and object keys alike, goes to the
   arbiter's prompt filter (confidentiality-plan-15) as `harness` text, one
   call per message, and the answer is put back: a registered secret comes
   back as its `$MDU:*` symbol, and any filter or pack the person turned on
   applies (the `key-shapes` filter, an organization's patterns). Page text
   is never the person's own words, so no prompt floor applies.

The filter unreachable, a segment held for the person's answer, or a blocked
segment with no safe text: the message is withheld. A withheld answer
reaches the agent as an error (`Mandu: the answer to <method> was withheld:
<why>`); a withheld event is dropped.

### 3.2 Typing: a placeholder the agent sends Chrome (`release.ts`)

`Input.insertText`, and an `Input.dispatchKeyEvent` that types (`keyDown` or
`char` with `text`), whose text holds a placeholder are **not forwarded**.
Instead:

1. The relay asks Chrome, on the agent's own target, for its main frame
   (`Page.getFrameTree`): the browser's account of the frame's origin, which
   the page's scripts cannot change. Only an `http(s)` origin can be named;
   `about:blank`, `data:` and other opaque origins are refused without
   asking.
2. For each placeholder, the arbiter's egress decision
   (`desymbolizationDecision`) with the network boundary and the page's host
   as the destination: typing a value into a page gives it to that origin,
   whose scripts can send it anywhere it may. The decision and the value
   ride the arbiter's human plane (arbiter-human-plane.md §10.3), so the
   relay's ask is the one that may spend a person's *Allow once*. A denial,
   an ask still open, a *Send without it*, or a gate that cannot be asked
   refuse the command. A denial and an open ask tell the agent the site may
   not have the value: leave it out (name it in plain words) and go on, and
   for an open ask, ask the person only if they asked for it to go there,
   then type it again (§3.4, *A site that may not have it*).
3. The value is inserted by a function the relay runs in an **isolated
   world** of that frame (`Page.createIsolatedWorld`), where the page's
   scripts cannot patch the prototypes it uses. In one turn of the page's
   event loop, so no page script runs in between, it checks the origin
   again, checks that the focus is on an element of this document (not in
   a frame of another page), and inserts with `execCommand("insertText")`,
   which fires the input events real typing fires. The value travels as a
   call argument (`Runtime.callFunctionOn`), never in the function's source,
   which `Debugger.getScriptSource` would hand back.

The agent gets an empty result, as from `Input.insertText`. Reading the field
back later goes through §3.1, so the agent reads its own placeholder while
the page holds the real value: the two views, in one browser.

A placeholder anywhere else (a script the agent runs, a URL it navigates
to) is forwarded **as written**: the page gets the literal `$MDU:…`, which
leaks nothing.

**A placeholder that names nothing (2026-10-19).** The egress decision
allows a placeholder the symbol table does not know (`egress:unknown-symbol`:
no value, nothing to leak), and the relay used to type it as written, traced
`released`. In the browser demos (§7) the model typed a placeholder one hash
digit off the one the page showed; the form saved the literal, the model was
told it had typed it, and two demos' tasks were left undone. Now, after an
allow, a `resolve` that answers null (unknown to the table, including a
field name the secret does not have) **refuses the whole command**: nothing
of it is typed, no isolated world is made, and the agent gets the error

```
Mandu: nothing was typed: no such placeholder $MDU:…[7f3b]: type the
placeholder exactly as the page shows it, every character (the pages
showed $MDU:…[7f3a], …)
```

The list is the nearest (fewest character edits, then the most recent) of
up to five placeholders the relay has shown the agent (`shown.ts`): every
placeholder the filter put into a message the relay delivered, on any of the
agent's connections, the last 64. Each was minted by the arbiter and read by
the agent already, so naming it back tells the agent nothing new; names
only, never a value. The trace says `refused`, reason `unknown placeholder`,
with the names in `unknown` (§5.1), never `released`. An arbiter that cannot
be asked or cannot resolve still refuses as before (fail-closed), with its
own reason, not as unknown.

**A placeholder lookalike (2026-10-19).** The relay knew a placeholder only
by its exact form, a code of 4 to 8 lowercase hex digits in brackets
(`symbols.ts` `symbolPattern`), so a token of the same shape with any other
code was not one at all: no refusal, no trace, no notice, the field got the
literal text. In the live expense-report demo (2026-10-19, Gemini 2.5
Flash) the model typed `$MDU:nomodel_Read[e213b2c2-8419-4809-b684-297d264f3319].number`,
a UUID it made up, into the card field, while the wallet page had shown
`$MDU:nomodel_Read[5958].extract_1`. Now a **lookalike** (`findLookalikes`:
`$MDU:`, a kind name, `[`, a code of 1 to 64 characters that are neither
whitespace nor `]`, `]`, then any `.NAME` parts) that is not a placeholder
(dashes, uppercase hex, a code too long or too short, a UUID) is refused
exactly like a placeholder that names nothing: the whole command, before
anything else, with the same error and the nearest placeholders the pages
showed, traced `refused` (`unknown placeholder`, the lookalike in
`unknown`), and the model told on its next call (§3.4). The arbiter is not
asked: the table mints only placeholders, so a lookalike can name nothing;
the relay asks Chrome only for the page's host, to name it to the model. A
command that carries a lookalike beside a real placeholder types nothing,
the real one included. Nothing raw could leak before either (a lookalike
resolves to no value): like the unknown placeholder, this is a utility fix,
so the model learns it typed the wrong thing.

*Prose.* The relay cannot tell a mistyped placeholder from text that merely
names one (a message explaining Mandu's `$MDU:kind[hash]` form, itself a
lookalike). Both are refused. Nothing raw can leak either way, since an
unknown name has no value; refusing is for the task, because the model
learns at once, and a placeholder-shaped token in typed text is far more
often a secret the model meant than prose. The cost: such a literal cannot
be typed with `Input.insertText` or key events through the relay (a script
the agent runs still carries it as written). Text with a `$MDU` that is not
placeholder-shaped (`$MDU docs`, `$MDU:` alone, `$MDU:foo` with no bracket,
a code with a space in it or longer than 64 characters) is typed as it is.

### 3.3 A placeholder typed a key at a time (`typing.ts`, 2026-10-19)

Agents that type like a person send one `Input.dispatchKeyEvent` per
character: browser-use's `input` (a `keyDown` without text, a `char` with
the character, a `keyUp`), Puppeteer's `type` (a `keyDown` with the text, a
`keyUp`). No single command carries a whole placeholder, so §3.2 never saw
one and the page got the placeholder's literal characters: browser-use's
first live run (§7) did its task and the deploy host saved `$MDU:…` instead
of the key. Nothing leaked; the task was undone.

The relay now holds a **key run** from the key that types a `$`:

- each held command is answered at once with an empty result (the agent
  waits for each key's answer before the next);
- while the text typed so far could still grow into a placeholder (the
  `$MDU:kind[hash].NAME` grammar, `placeholderPrefix`) or a lookalike of
  one (§3.2: any code of up to 64 characters that are neither whitespace
  nor `]`; `heldPrefix`), the next key that types is held, and so is every
  key event that types nothing (a `keyDown` without text, a `keyUp`). A run
  is bounded: at most 512 characters (`MAX_RUN_TEXT`) and 2048 key events
  (`MAX_RUN_KEYS`), so a lookalike cannot hold keys forever; past either,
  or once the code passes 64 characters or a space arrives in it, the run
  ends;
- the run ends at a key that cannot extend it, at any other command of the
  agent's, or after `KEY_RUN_IDLE_MS` (400 ms) without one. If its text is
  exactly one placeholder, it is **released** by §3.2's steps, unchanged
  (the frame's origin, the egress decision with the page's host as the
  destination, the isolated-world insert), and the textless key events that
  came after its last character are forwarded after the value, so an
  Enter's `keyDown` lands after it; a refusal types nothing and is traced
  `refused`. A run that is a lookalike, or a placeholder whose code no row
  has, does not wait for its end (below, *A lookalike is refused as it is
  typed* and *A code that names nothing is refused as it is typed*).
  Otherwise every held command is
  **forwarded as the agent sent it**, in order: a `$5` is typed as `$5`,
  and so is `$MDU:k[ab cd]`.

**A lookalike is refused as it is typed (2026-10-19).** A lookalike
(§3.2: a code no placeholder has) is certain on the key that closes its
code, the `]`: whatever follows (`.NAME` parts) it stays a lookalike and
names nothing. So the run says so there (`typing.ts`, step `decide`), and
the relay refuses **that key**: §3.2's lookalike refusal (the arbiter not
asked, Chrome asked only for the page's host), traced `refused`, reported
for the model (§3.4), and the key answered with the error. The agent's
typing command fails while it types, before it moves on: browser-use's
`input` raises on the key, falls back to typing the text to the page, which
is refused the same way, and the action fails, so the step's next action
(the form's Submit) never runs. The run goes on holding the token's
remaining keys and ends **dropped**: none of its keys reach the page (the
textless keys after its last character follow, as after a release), and an
agent that types on regardless gets nothing of the token typed. A
placeholder (a hex code) is checked on the same key, below; whether the
page's site may have it, and whether its field is one the secret has, need
its whole name and wait for the run's end.

Why (live, 2026-10-19, the expense-report demo, Gemini 2.5 Flash): the
model typed
`$MDU:nomodel_Read[6a91724a-25c2-4824-91b4-5c962b146473].content` into
the card field and, in the same step, clicked *Submit for approval*. The
run was refused when it ended, and the refusal waited for the next input
command, the click's first mouse event; browser-use answers a failed mouse
event with a script click (`element.click()`), so the expense was filed
without the card, and the model, told on its next call, read that the
system had accepted it and finished. Nothing leaked; the task was undone.

**A code that names nothing is refused as it is typed (2026-10-19).** The
same take, with a well-formed code: the model made up
`$MDU:web_fetch[8c4f].text` (hex, so a placeholder, not a lookalike),
clicked Submit in the same step, and the expense went out with the card
field empty, as above. Whether such a code names anything is certain on
the key that closes it too: the table either has a row named
`$MDU:kind[code]` or `$MDU:kind[code].<field>`, or every name the model
could go on to type after it names nothing. So on that `]` the run asks
(`typing.ts`, step `check`) and the relay asks the arbiter
(`placeholderKnown`, on the human socket, §5): does this base name a row,
its own or a field's beneath it?

- **No**: the relay refuses **that key** exactly as a placeholder that
  names nothing (§3.2: the message with the nearest placeholders the pages
  showed, traced `refused` with reason `unknown placeholder` and the base
  in `unknown`, reported `unknown` for the model, §3.4), and the run ends
  **dropped**, as a lookalike's does. browser-use's `input` fails on the
  key, its fallback typing fails the same way, and the step stops before
  its Submit click.
- **No answer** (no human socket, the arbiter gone or slow past its
  client's timeout, an arbiter without the op): refused the same way, as
  `failed` (`unavailable`), the run dropped. Fail-closed; and without the
  human plane the run could not be released at its end either.
- **Yes**: the key is held like any other and the run is decided at its
  end, unchanged (§3.2's gate needs the whole name). The relay's quiet
  timer waits for the answer, so a slow arbiter does not end the run early.

Only the first `]` asks (a field may carry its own, `.a[0]`), once per run;
Chrome is asked for the page's host only to name it in a refusal.

*What the lookup tells.* One bit per typed code, and none the model could
not learn before. Typing the base whole already answered it: an unknown
one is refused as `no such placeholder`, a known one is released or
refused naming the site (§3.2); the lookup gives the same answer earlier,
on the same input. A code is drawn at random when a value is minted
(`randomHash4`), never derived from the value, so an allocated code says
nothing about any value; the model only ever sees its own placeholders,
and a code it guesses that happens to be allocated tells it only that some
placeholder has that name, which typing it whole told before (one typed
attempt per guess of a 16-bit code, each traced on the session page). The
lookup names no field (the relay asks for the base only), no label, binding
or value, so it cannot enumerate a secret's fields. The agent world gains
nothing either: the op is served on the human socket only
(arbiter-human-plane.md §3), and the data socket's egress decision already
answers whether a name is known (`egress:unknown-symbol`).

*Why a no is sound.* Every name the arbiter's lookup can find for a typed
token (`findSymbolByName`, the walk the egress gate and `resolve` use: the
token shortened at `.` field boundaries down to its base, or extended at a
`.` boundary) is the base or `base.<field>`, and the check reads every row
as that walk does, obsoleted ones too. So a base with no row is a
placeholder the run's end would refuse as unknown anyway: the check changes
when the refusal comes, not whether. A yes decides nothing: the run is
still released only through §3.2's gate.

A run refused when it ends (an unbound site or one that needs the person's
approval, a known base with a field the secret lacks such as
`…[5958].bogus`, a gate that cannot be asked) was refused after each of its
keys was
answered, so the error cannot ride a key of its own. The relay keeps it and
answers the agent's **next `Input.*` command** with it (2026-10-19), not
sending that command: the key that ended the run (a space after the
placeholder), or, when another command or quiet ended it, the next click,
key or insert. A command that types nothing is not the one told:
browser-use follows its keys with its framework events and a read-back
(`Runtime.callFunctionOn`) and swallows their errors. When that next
command is a click's mouse event, browser-use falls back to a script click,
so the click still happens (above): for a field the secret lacks, or a site
that may not have the value, the form can still be sent without it (§8).
Told once; the message ends `(the keys typed before this
command; this command was not sent either)`. The model is also told on its
next call, whatever the agent does with the error (§3.4).

The run decides nothing itself: its text is only ever released through
§3.2's gate, dropped once refused on its way (a lookalike, or a code the
arbiter says names nothing, or no answer), or forwarded as typed (a run says
only WHEN its text is a lookalike or a code to check), so a key run can
never put more on a page
than a whole `Input.insertText` of the same text would. The agent's own
answers came when the keys were held, so Chrome's answers to the forwarded
keys are dropped.

### 3.4 The refusal, told to the agent's model (2026-10-19)

The refusals above answer a DevTools command with an error, and an agent
decides what its model sees of that. browser-use shows its model none of
it: it swallows a command's error, and its key-by-key typing puts a run's
refusal on the next input command (§3.3), whose error it swallows too. In
the live expense-report demo (2026-10-19, Gemini 2.5 Flash) the model typed
a placeholder it made up (`$MDU:web_fetch[8c4f].text`) into the card field,
the relay refused it correctly, the model saw an empty field, typed the same
token again, and submitted the report without the card.

Whatever the agent does with errors, its model's next request goes through
the egress proxy (§6.5), so the refusal is told there:

1. **The relay reports it.** Every refusal of §3.2 and §3.3 (`release.ts`)
   carries a *notice*: the refusal as structured names only, a kind
   (`unknown`, `malformed`, `not-allowed`, `needs-approval`, `declined`,
   `failed`), for `failed` a cause (`no-field`, `page-moved`, `frame`,
   `no-page`, `page-refused`, `unavailable`), the page's host as Chrome
   named the frame, the placeholders the refusal is about and, for
   `unknown` and `malformed`, the nearest ones the pages showed
   (`shown.ts`). `malformed` is a placeholder lookalike (§3.2): its notice
   names no placeholder of its own (`symbols` is empty, and the arbiter
   refuses one that is not), because a lookalike's code is free text the
   model could be made to read; the model is told what it was and shown
   the real ones. The relay sends it to the
   arbiter (`relayNotice`, data socket, its session key) and answers the
   agent after the arbiter took it or after `NOTICE_WAIT_MS` (500 ms),
   whichever is first; a report that fails changes nothing for the agent.
2. **The arbiter keeps it** (`arbiter/ipc/relay-notices.ts`), in memory,
   per session key: at most 8 per session (the oldest dropped first; a
   repeat of a pending one replaces it), 64 sessions (the least recently
   reported dropped first), none older than 10 minutes. It checks every
   field (kinds and causes from the lists, a host name, `$MDU:` names) and
   refuses a notice that fails, so whoever reports one can make the model
   read only what Mandu's own refusals say. In memory because a notice is
   for the very next model call: a restart loses a hint, nothing else.
3. **The proxy tells it.** On each Chat Completions call that gets the
   handling note (§6.5), the proxy also takes the session's pending notices
   (`takeRelayNotices`, which clears them: each is told once) and appends
   one message at the **end** of `messages`, after the latest one, so the
   model reacts to it in this turn:

   ```
   {"role": "user", "content": "Mandu (the protection layer on this
   computer; this message is from Mandu, not from the user): your last
   attempt to type into a field on ledgerly.localhost typed nothing:
   $MDU:web_fetch[8c4f].text is not a placeholder Mandu knows. Copy the
   placeholder character for character from the page that shows the secret
   (the pages showed $MDU:nomodel_Read[8c4e].CARD_NUMBER)."}
   ```

   A lookalike reads `the text typed looks like a placeholder but is not
   one Mandu made. Copy the placeholder character for character from the
   page that shows the secret, never make one up (the pages showed
   $MDU:nomodel_Read[5958].extract_1).` Several pending refusals make one
   message, a line each. A site that may not have the secret is told to
   leave it out and go on (below); a *Send without it* and each
   fail-closed cause have their own plain sentence
   (`interceptors/net-proxy/src/relay-notice.ts`). The forwarded event says
   `relayNotices: <n>` beside `modelNote`.

**A site that may not have it (2026-10-19).** In the live expense-report
demo (2026-10-19, Gemini 2.5 Flash) the model filed the
expense with the card's placeholder at the expense tool (bound, typed),
then pasted a summary into the team chat that repeated it ("Paid with:
company card $MDU:nomodel_Read[8db1].extract_1"). The relay refused the
card there, correctly: the chat is not bound, so the gate filed an ask.
Both the DevTools error and the notice then said only *ask the person,
then type it again*; the model stopped, asked for an approval, and never
posted, though the task did not need the card in the chat. The egress
hold's *Send without it* finishes such a request without the value
([egress-hold.md](../confidentiality/egress-hold.md)); here the model
writes the text, so the refusal now teaches it to do the same. For a
denial (`not-allowed`) and an open ask (`needs-approval`) the notice reads

```
huddle.localhost may not have the secret $MDU:… without the user's
approval in Mandu. Unless the user asked for that secret to go to
huddle.localhost, do not ask them: leave it out, write the rest without
it (name the secret in plain words if the text needs it, such as "the
card" or "the API key", never its placeholder), and go on with the task.
If they did ask for it there, ask them to approve it in Mandu, then type
it again.
```

and a denial `chat.localhost may not have the secret $MDU:…. Do not type
it there again: leave it out, … and go on with the task. Only if the user
asked for that secret to go to chat.localhost, tell them Mandu does not
let that site have it.` (the shared sentence is `relay-notice.ts`
`LEAVE_IT_OUT`). The DevTools error says the
same in short (`release.ts` `LEAVE_IT_OUT`: `huddle.localhost may not have
$MDU:… without the person's approval in Mandu; leave it out (name it in
plain words if the text needs it, never its placeholder) and go on; ask
the person only if they asked for it to go there, then type it again`),
and the note's *Web pages* section says it once for every call
([handling-prompt.md §11](handling-prompt.md)). The same words serve every
agent the relay fronts.

*Not a send-without in the relay.* The relay could type the text with the
placeholder dropped, but that decides for the person while their ask is
open (a *Send without it* is the person's answer, which the relay already
honours as `declined`), and the page would get a sentence the model never
wrote ("Paid with: company card "), which it then reads back as its own.
The model rewriting its text keeps both right: the ask stays on the
Approvals page for the person, and nothing is typed that nobody chose.
Every refusal is unchanged: the words change, not what is typed.

**Why `user`.** A Chat Completions service hands a model whose own API has
one system prompt (Gemini, Claude) every `system` message as that prompt,
wherever it stood in `messages`, so a late `system` message loses the place
that makes the model react to it now. A `user` message stays where it is on
every provider. The text says who speaks, so the model does not take it for
the person's request.

**Why it is safe.** The sentence is built in the proxy from the notice's
fields, each checked again: no free text and no value can reach it (a field
that fails is dropped, never quoted). The names are ones the model typed or
the relay showed it already. The handling note is untouched (it stays first
and byte for byte the same, so the prompt cache keeps it); the notice is a
separate message. It is utility, not security: an arbiter that cannot give
the notices sends the call without them, and a body the proxy cannot read
(compressed, not JSON, no `messages`) leaves as written with its notices
still pending for the next call.

**Session key.** The relay and the egress proxy are started with the same
one, the launch's scope id (`launcher/src/services/cdp-relay.ts` passes
`--session`, `services/net-proxy.ts` `MANDU_SESSION_KEY`). An egress proxy
reused from another launch (only with a pinned `MANDU_NET_PROXY_PORT`; the
reuse key is the arbiter socket, not the session) carries that launch's
key, and its notices do not match: the agent still gets the DevTools error.

**What the notice does not say.** The field's label: it is page text,
which would need masking like any read (§3.1); the model knows which field
it typed into.

## 4. The method tables (`policy.ts`)

- **Allowed domains**: Accessibility, Browser, CSS, Console, DOM, DOMDebugger,
  DOMSnapshot, DOMStorage, Debugger, Emulation, Fetch, IO, IndexedDB, Input,
  Inspector, Log, Network, Overlay, Page, Performance, Runtime, Schema,
  Security, ServiceWorker, Storage, Target: the domains browser agents
  drive, whose answers are text. A command in any other domain is refused;
  a domain is added when an agent needs it.
- **Refused commands**:
  - pixels: `Page.captureScreenshot`, `Page.startScreencast`,
    `Page.printToPDF`, `Page.captureSnapshot`, `Tracing.start`,
    `HeadlessExperimental.beginFrame`, `LayerTree.replaySnapshot`.
    Text first: an agent in its text mode (browser-use `use_vision=False`,
    the MCPs' snapshot tools, jev by design) loses nothing;
  - the cookie jar: `Network.getCookies`, `Network.getAllCookies`,
    `Storage.getCookies`;
  - the protocol past the relay: `Target.exposeDevToolsProtocol` (it hands
    the page the protocol) and `Target.sendMessageToTarget` (the nested
    session mode carries whole messages as strings, past every table here;
    agents use flat sessions).
- **Release commands**: `Input.insertText`, `Input.dispatchKeyEvent` (§3.2).

## 5. The arbiter

Six operations (`arbiter-client.ts`, the narrow interface and its adapter
over the real client); `relayNotice` (§3.4) and `placeholderKnown` (§3.3)
are the relay's own:

| Operation | Socket | Use |
|---|---|---|
| `filterPrompt` | data | §3.1, `harness` segments, agent `browser` |
| `desymbolizationDecision` | human | §3.2 step 2 |
| `resolve` | human | §3.2 step 2, after an allow; null refuses (a placeholder that names nothing) |
| `placeholderKnown` | human | §3.3, on the key that closes a typed placeholder's code: whether its base (`$MDU:kind[code]`) names a row; no, or no answer, refuses that key. A base only, a yes or a no; human-plane only (arbiter-human-plane.md §3) |
| `emit` | data | §5.1, the trace |
| `relayNotice` | data | §3.4, a refusal for the agent's model; names only |

No human socket (`MANDU_ARBITER_HUMAN_SOCK` unset): every release is refused
(a placeholder typed a key at a time, already on the key that closes its
code); the data socket is never asked instead.

### 5.1 The trace (2026-10-18)

The relay tells the session's trace what it did, one `browser_action` event
each (`events.ts`; emitter `cdp-relay`; the dashboard's `event-model.ts`
kind), names only: a placeholder, a method, a page's host, a reason; never a
value or page text.

| `action` | When | Fields |
|---|---|---|
| `masked` | Chrome's message reached the agent with placeholders the filter put in | `method`, `symbols` |
| `withheld` | Chrome's message did not reach the agent (the filter could not answer or held it; bytes it cannot read) | `method`, `reason` |
| `released` | a typed placeholder became its value on a page | `method`, `page`, `symbols` |
| `refused` | a typed placeholder was not typed | `method`, `symbols`, `reason` (`unknown placeholder` for one the arbiter does not know or a lookalike of one, §3.2, with those names in `unknown`) |
| `blocked` | a command the relay never sends Chrome (§4) | `method`, `reason` |

Best-effort and off the security path: an event is never awaited, a failed
emit is ignored and changes nothing the relay does. The session page tells
them as **On web pages** (dashboard.md §4.25af), beside the egress proxy's
`keptOpaque` sends to the model services the agent called itself
(agent-sign-in.md §3.12). Before this a browser session's page said only
that no conversation was recorded.

## 6. Running it

### 6.1 Through `mandu`

The person starts a Chrome for the agent, with its own profile (Chrome 136
and later refuse remote debugging on the default profile), then launches the
agent with the flag:

```sh
google-chrome --remote-debugging-port=9222 --user-data-dir="$HOME/.mandu-chrome"
mandu --browser-cdp http://127.0.0.1:9222 -- <the agent's command>
```

`--browser-cdp` (or `MANDU_BROWSER_CDP`) takes Chrome's HTTP endpoint on
this machine (`http://127.0.0.1|localhost|[::1]:<port>`; a `ws://` browser
URL is taken as its endpoint). A Chrome on another machine is refused: the
agent could reach it on the network around the relay. The launch
(`launcher/src/browser-cdp.ts`, `services/cdp-relay.ts`):

- **starts the relay** as its own process, outside the agent's tree, on a
  kernel-assigned loopback port, with the session's arbiter on both planes
  (the launch line: `cdp-relay LIVE on http://127.0.0.1:<port>`). The flag
  is a request: a relay that cannot start refuses the launch unless
  `--best-effort`, which launches with no browser endpoint given;
- **gives the agent the relay's URL** in `BU_CDP_URL` (Browser Harness,
  jev-ultrafast's browser layer, reads it and finds the browser through
  `/json/version`) and `MANDU_BROWSER_CDP_URL` (for an agent's own setting:
  browser-use `cdp_url`, Playwright `connect_over_cdp`, the MCPs'
  `--cdp-endpoint` / `--browserUrl`). Chrome's own port is in neither;
- **admits the relay's port in both connect guards** (landlock-net's TCP
  port set, Seatbelt's on macOS, the net guard's loopback rules) and never
  Chrome's. Chrome's port therefore must not be one the guards admit
  anyway: 443, 22 and 53 (admitted to every host by default) and Mandu's
  own service ports are refused, even under `--best-effort`. With neither
  guard running, the launch warns that the agent can reach Chrome around
  the relay.

A process holding a secret is refused at the relay's port like at the model
proxy's (the net guard admits only the egress proxy for it).

### 6.2 By hand

```sh
MANDU_ARBITER_SOCK=… MANDU_ARBITER_HUMAN_SOCK=… \
  npx tsx interceptors/cdp-relay/src/server-main.ts \
    --upstream http://127.0.0.1:9222 [--port 0] [--session <key>] [--port-file <path>]
```

It prints `cdp-relay: listening on http://127.0.0.1:<port>` (and writes the
port to `--port-file`, whole, by rename); the agent is given that URL where
it would take Chrome's.

### 6.3 jev-ultrafast

jev's two model calls leave from jev itself, not from Chrome: every step's
`POST https://api.typesafe.ai/v1/systemone` (a wire Mandu's model proxies do
not read) and the optional text helper's Chat Completions call (OpenRouter
in its example). Each carries the page text the agent read, which through
the relay is already placeholders, and a key in `Authorization: Bearer`.
Both keys are model services' keys a program sends itself
([agent-sign-in.md §3.12](agent-sign-in.md)): `TYPESAFE_API_KEY` and
`OPENROUTER_API_KEY` are masked in the session's environment and bound to
`api.typesafe.ai` and `openrouter.ai`, where the egress proxy puts each back
in the Authorization header of an https request, and nowhere else. Those two
hosts are the egress proxy's **model services**: the page secrets'
placeholders in jev's request leave as they are, where any other host
refuses them. A request carrying a registered value verbatim is still
refused there (the fingerprint tripwire). The first live run is recorded in
agent-sign-in.md §3.12.

```sh
mandu --browser-cdp http://127.0.0.1:9222 -- sh -c \
  'TEXT_MODEL_API_KEY="$OPENROUTER_API_KEY" TEXT_MODEL_BASE_URL=https://openrouter.ai/api/v1 \
   TEXT_MODEL=inception/mercury-2.5 exec uv run jev "<task>"'
```

The inner shell copies the OpenRouter key's placeholder into jev's own
variable; the placeholder is what the egress proxy releases, whatever the
variable is called. `--browser` (§6.4) in place of `--browser-cdp` runs the
same task on a Chrome Mandu starts.

### 6.4 A Chrome Mandu starts (`--browser`, 2026-10-18)

The relay masks what crosses the DevTools connection. It cannot see what
Chrome itself sends: a script the agent runs in a page
(`Runtime.evaluate`, `fetch(…, {body: document.body.innerText})`) or a
form it submits sends the page's real text, which holds the real value of
a secret the agent only ever saw as a placeholder. The person's own Chrome
sends that anywhere. So `mandu --browser` (or `MANDU_BROWSER=1`) starts
the agent's Chrome itself (`launcher/src/browser-launch.ts`,
`services/browser.ts`), after the egress proxy and before the relay, which
is then put in front of it exactly as in §6.1:

- **Its traffic goes through the egress proxy** (`--proxy-server`), and
  WebRTC is kept to proxied connections
  (`--force-webrtc-ip-handling-policy=disable_non_proxied_udp`), so no UDP
  leaves around it. Chrome is not one of the agent's processes and holds no
  secret taint; what the proxy judges is the request: a registered value
  verbatim to a host it is not bound to is refused (the fingerprint
  tripwire), one to its own host goes, and a request without one goes as
  any other. Loopback is not proxied (Chrome's default bypass; the proxy
  refuses this machine).
- **It trusts the session CA by its key pin**
  (`--ignore-certificate-errors-spki-list=<base64 SHA-256 of the CA's
  public key>`, which Chrome honours only with its own `--user-data-dir`),
  so the proxy reads its HTTPS bodies with nothing installed in a
  certificate store. Chrome matches the pin only against certificates the
  server sends, so the proxy's TLS-inspected leg sends the session CA after
  each leaf (net-proxy `mitm.ts`; measured 2026-10-18 on Chromium 153: the
  CA's pin with the leaf alone fails the handshake).
- **Its profile is Mandu's**: `state/browser` in the Mandu home
  (on-disk-layout.md), which the agent can neither read nor write, so the
  cookie store is not the agent's to read from the disk, and the sites the
  person signs in to stay signed in for the next session. One session's
  Chrome at a time: a profile whose `SingletonLock` names a live Chrome of
  this host refuses the launch, saying which pid.
- **Its debugging port is kernel-assigned** (`--remote-debugging-port=0`),
  read from the profile's `DevToolsActivePort` (the last run's removed
  first), and becomes the relay's upstream; the connect guards admit only
  the relay's port, as in §6.1.
- **Which Chrome**: `MANDU_BROWSER_BIN`, else `google-chrome-stable`,
  `google-chrome`, `chromium`, `chromium-browser` on `PATH`, then the
  platform's install paths. A window when there is a display, headless on
  Linux without one or with `MANDU_BROWSER_HEADLESS=1`. Its sandbox stays
  on (`MANDU_BROWSER_NO_SANDBOX=1` is for test hosts whose userns
  restriction stops it).
- **The flag is a request**: no Chrome found, a held profile, or a Chrome
  that never opens its port refuses the launch unless `--best-effort`
  (then no browser and no relay). With no egress proxy (`--no-net-proxy`)
  Chrome starts unproxied with a warning; with a proxy that reads no HTTPS
  (no session CA) the launch says its HTTPS requests are gated by
  destination only. `--browser` with `--browser-cdp` is refused.
- Chrome runs as its own process group outside the agent's tree, stopped
  at teardown with the relay. It does not watch the launcher's lifeline: a
  launcher killed outright leaves it open, and the next launch's lock check
  names it.

What the tripwire does not see here is what it does not see anywhere: a
value the script transforms first (base64, split). The relay's read side is
unchanged: the agent itself never holds the value to transform; only a
script in the page does.

### 6.5 The handling note for the agent's model (2026-10-19)

Claude Code and Codex reach their model through Mandu's model proxy, which
puts the handling note (what a `$MDU:*` placeholder is, and that it goes
where the value belongs) into every request. A browser agent such as
browser-use is a program that calls a model service itself (OpenRouter,
[agent-sign-in.md §3.12](agent-sign-in.md)): no model proxy fronts it, so
its model met a placeholder in a page with no word on what it is. In
browser-use's second live run Gemini 2.5 Flash refused to fill the key: it
wanted an `sk_live_…`, not a token.

So when the launch runs a relay (`--browser-cdp` or `--browser`), the
launcher starts the egress proxy with `MANDU_NET_PROXY_MODEL_NOTE=browser`
(`launcher/src/services/net-proxy.ts` `modelNoteOf`; always set, so an
ambient value cannot turn it on). Then a Chat Completions request (`POST
…/chat/completions`, a JSON body with a `messages` array) to a model
service, on the TLS-inspected leg, gets the note as one more `system`
message at the front (`interceptors/net-proxy/src/model-note.ts`, called
from `mitm.ts` once the gate and the tripwire have passed the request as
the agent wrote it). The note is the arbiter's own `handlingPrompt` for a
browser agent's model: no inspect, exec or policy tools, and the *Web
pages* section ([handling-prompt.md §11](handling-prompt.md)), asked per
request on the data socket. The forwarded event says `modelNote: "added"`,
or why not.

The same step appends the relay's pending refusals as the call's last
message (§3.4, `editModelCall`): the note stays first and unchanged, the
refusals are a `user` message after the agent's latest one, and the
forwarded event says `relayNotices: <n>`.

What is left as written: a request the step cannot read (another wire, such
as TypeSafe's `/v1/systemone` or a Responses call; a compressed or non-JSON
body; no `messages`), one that carries the note already (unless refusals
are pending), every request when the arbiter gives neither, and every
request of a launch with no relay. A user's own script calling OpenRouter
in a Claude Code session is untouched.

Why it is safe: the note is Mandu's fixed text and holds no secret, and it
is added after every check, so what the gate decided about the request is
unchanged; the placeholders stay opaque whether the model knows what they
are or not.

## 7. Tests

- **Unit** (`interceptors/cdp-relay/test/unit/`): the credential and byte
  rules, string collection and replacement, the filter's answers to
  verdicts; the release flow against a stand-in target (the decision's
  shape, the value only as an argument, every refusal before anything is
  typed, an opaque origin never asked about); the insert function itself
  against a stand-in page (origin, focus, shadow roots); the method tables;
  the WebSocket server (RFC 6455's handshake example, split and fragmented
  frames, ping, refusals); the key run (`typing.test.ts`, §3.3: every
  start of a placeholder and nothing else, browser-use's and Puppeteer's
  key events, a run ending as a release with the keys after it, or as every
  held command forwarded in order, a key on another target ending it, a
  placeholder-shaped run ending as a release for the gate to judge); a
  placeholder that names nothing (`release.test.ts`, §3.2: refused with the
  message and the nearest shown, reason `unknown placeholder`, beside a
  known one the whole command refused, an unbound page's known one refused
  as before, a resolve that fails refused as a failure, not as unknown) and
  the shown placeholders (`shown.test.ts`: recency, the cap, the nearest);
  a placeholder lookalike (§3.2: `release.test.ts`, which tokens are one
  (the live UUID, dashes, uppercase hex, a code too long or too short, a
  `.NAME`) and which are not (`$MDU docs`, `$MDU:` alone, `$MDU:foo`, a
  space in the code, a code over 64), each inserted whole refused as
  unknown with the nearest shown, the arbiter never asked, the notice
  `malformed` without quoting it, a real placeholder beside it never
  inserted; `typing.test.ts`, every start of one held, a run of one
  decided on the key that closes its code (once, browser-use's and
  Puppeteer's way) and ending dropped whatever it grew into, a placeholder
  never decided on its way, the non-placeholder controls forwarded in
  order, the run's bounds); a code checked on the key that closes it
  (§3.3: `typing.test.ts`, a `check` at the first `]` only, browser-use's
  and Puppeteer's way, a run the relay refuses there ending dropped
  whatever it grows into and the next run starting afresh;
  `release.test.ts` `checkTyped`, a base known through its field row going
  on with neither Chrome nor the gate asked, a made-up hex code refused as
  unknown with the nearest shown and the page named, no answer refused as
  `failed`; `policy.test.ts`, the adapter asking the human client, only a
  literal true known, no human socket throwing). Arbiter
  `test/unit/placeholder-known.test.ts`: a base known by its own row or a
  field row, obsoleted rows too, a longer code not beneath it, anything but
  a base false, and soundness: for every unknown base, no token typed after
  it resolves (`findSymbolByName`, `resolveSymbol`);
  `test/component/placeholder-known.test.ts`: the op on the human socket
  (a registered secret's base known, a made-up code not, a field path, a
  lookalike, a value refused), refused on the data socket, answered with
  both axes off; `test/unit/human-plane-ops.test.ts` lists it.
- **Component** (`test/component/relay.test.ts`): the real relay between a
  WebSocket agent and a fake Chrome, with a mock arbiter: discovery
  rewritten and titles masked; a registered value in a script result and in
  events reaches the agent only as its symbol, cookies withheld; screenshots
  and the cookie jar never reach Chrome; a base64 body withheld, a text body
  masked; a typed placeholder reaches a bound page only as the insert's
  argument and the Enter after it waits; an unbound page is refused and
  nothing raw reaches Chrome; an unreachable arbiter withholds answers,
  drops events and refuses typing; a placeholder typed a key at a time
  (§3.3) is answered key by key, inserted once at a bound page with the
  text around it in order and the Enter after it, refused at an unbound one
  with none of its keys reaching Chrome and the next input command told,
  released when the agent goes quiet, and a `$5` typed as it was; a
  placeholder that names nothing, inserted whole or typed a key at a time,
  never reaches Chrome, the agent is told (with the one the page showed) on
  the insert, or, typed, on the key that closes its code (the arbiter asked
  once, the gate and the values never, the next input command not told
  again), once, and the trace says `refused` (`unknown placeholder`), never
  `released`; a known base with a field the secret lacks, typed (the run
  ended by another command, by a key, by quiet), told on the next input
  command, each base checked and known; the same token in prose refused
  too; the live expense-report step with a made-up HEX placeholder
  (`$MDU:web_fetch[8c4f].text`) replayed as browser-use runs it (its
  `input`, its fallback typing, then its Submit click with the script-click
  fallback): the input fails on the `]`, so Submit is never clicked, by
  mouse or by script, and the field stays empty; the next step with the
  page's placeholder fills it and Submit fires once, after the value; with
  the lookup down the step stops the same way (fail-closed); a
  lookalike with a UUID for its code, inserted whole and typed a key at a
  time, never reaches Chrome, the agent is told with the one the page
  showed (typed, on the key that closes its code, the next input command
  not told again), the arbiter is not asked, the `malformed` notice
  reported once each, and prose with `$MDU` typed as written; the live
  expense-report failure replayed as browser-use's `input` runs (its keys,
  its fallback to typing to the page): the action fails, so its next action
  (the submit) would not run, none of the lookalike reaches the page, and
  the placeholder as the page shows it then goes in.
- **Stack** (`tests/stack/cdp-relay.test.ts`): the production wiring
  (`ArbiterClientAdapter` over a data and a human `ArbiterClient`) over a
  real arbiter, a `.env` bound by `policy.yaml`: the real filter masks, the
  real decision releases to a bound page and refuses an unbound one, a gone
  arbiter withholds. Then the same against a **real headless Chromium**
  (self-SKIP without one; `MANDU_TEST_CHROMIUM`), where Chrome itself holds
  the real value while the agent reads its placeholder, and a screenshot is
  refused; and a placeholder typed a key at a time, browser-use's way: a
  bound page's field holds the real value with the text around it, an
  unbound page's holds none of it and the next input command is told, and
  a lookalike (a UUID for its code) is refused on the key that closes its
  code, the field holding none of it, the real arbiter keeping the
  `malformed` notice. A
  placeholder the real arbiter never minted (a hash digit off, a field the
  secret lacks): refused with the page's own placeholder named, nothing at
  the fake Chrome, the stored events `refused` (`unknown placeholder`) and
  the session page's line for it; on the real Chromium, typed a key at a
  time into a bound page, the field holds none of it, the hash digit off
  refused on the key that closes its code (the real `placeholderKnown`, the
  next input command not told again) and the field the secret lacks when
  the run ends (the next input command told). The live expense-report step
  on a real form, as browser-use runs it: a made-up hex placeholder
  (`$MDU:web_fetch[8c4f].text`) fails the typing on its `]` and again on
  the fallback typing, so the step stops before Submit, the form is never
  submitted and its field holds nothing; the next step with the page's
  placeholder, then a real mouse click on Submit, sends the real value; the
  real arbiter keeps the `unknown` notice naming the page.
  `tests/stack/proxy-real-client-parity.test.ts`: the relay's production
  adapter asks `placeholderKnown` over the real human client (a registered
  secret's base known, a made-up code not) and the data client is refused
  it. `tests/stack/model-service-egress.test.ts`: the made-up placeholder
  typed a key at a time is refused on its `]` and the model's next call
  names its base.
- **The browser Mandu starts** (`launcher/test/unit/browser-launch.test.ts`):
  the Chrome found, its command line (the proxy, WebRTC, the CA's pin
  against openssl's, its profile, port 0), the lock and the port file, the
  flag and its conflict with `--browser-cdp`, the manager starting Chrome
  after the egress proxy and putting the relay in front of it, a failed
  start refusing the launch; `startBrowser` against a stand-in spawn.
  `tests/stack/browser-launch.test.ts`: the launcher's own `startBrowser`
  on a real headless Chromium (self-SKIP), through a real NetProxy's
  TLS-inspected leg to two loopback HTTPS sites only the proxy can route
  to, with the launcher's relay in front on a real arbiter: the agent reads
  the page's key as its placeholder; a page script posting the page's text
  to another site is refused there and the site gets nothing; the same post
  to the key's own host gets there with the real key; a post without it
  goes. Without the CA in the chain the page does not load (checked by
  hand). `interceptors/net-proxy` `mitm.test.ts` (12): the chain served is
  the leaf and the session CA.
- **The launch** (`launcher/test/unit/browser-cdp.test.ts`): the endpoint's
  rules, the flag and its variable, the refused Chrome ports, the agent's two
  variables (and Chrome's port in none), the relay's port in both guards'
  sets, the manager starting the relay, stopping it at teardown and refusing
  the launch when it cannot start. `tests/stack/cdp-relay-launch.test.ts`:
  the launcher's own `startCdpRelay` spawns the real relay through the
  checkout layout on a real arbiter, the agent finds the browser through
  `BU_CDP_URL`'s `/json/version`, and on a real Chromium (self-SKIP) the
  path Browser Harness takes: the browser endpoint, `Target.createTarget`,
  `Target.attachToTarget({flatten: true})`, every command on the session id,
  placeholders both ways.
- **The trace** (§5.1): a component test drives every action against the
  fake Chrome and checks one event each, names only, and that a failing
  emit changes nothing; the stack test reads the events back from the real
  event store through the production adapter and builds the session page's
  story from them (dashboard `browser-story.ts`, with its own unit test).
- **Live**: the drill suite has four browser-jev drills, the real
  jev-ultrafast on the real TypeSafe and OpenRouter, run by request only
  (they spend the maintainer's keys): an env list on a settings page (read
  masked, task done), a connected integration's key pasted on the deploy
  host the `.env` is bound to (the host gets the real value), the same key
  asked for by another site's support form (nothing typed there), and a
  signing secret in a read-only field's value (jev reads its placeholder,
  Chrome posts the real value). The oracle is jev's own outgoing bodies.
  All four passed on 2026-10-18. A run is a live drill run on the dev
  dashboard's Drills page: each drill's session with its trace and checks,
  and a video of Chrome during the task (dashboard.md §4.10.7). Three
  browser-use drills (2026-10-19, the maintainer's OpenRouter key; chores
  across a payments provider, a deploy host and a code host on
  `*.localhost`): the key revealed on the provider's page added on the
  deploy host (typed a key at a time, released there, §3.3), an issue filed
  from a failing webhook's page (useful, no signing secret), and a
  lookalike sign-in the agent followed and typed the key's placeholder into
  (refused: the lookalike got nothing). All three passed on 2026-10-19,
  after the relay's key run (§3.3), first with the drill handing
  browser-use the note itself, then with the note from the egress proxy
  (§6.5) and none from the drill. **Six browser demos** (2026-10-19, the
  drill suite's browser-demos, by request only): each chore run without
  Mandu (browser-use straight to Chrome and OpenRouter) and with it, on
  made-up branded sites; a video per side and the two side by side. On
  2026-10-19 (Gemini 2.5 Flash), without Mandu the model service received
  the payments key, the signing secret, the licence or a card number in
  every demo whose page showed one, and the lookalike sign-in and the
  fast-track ad received the key, the licence and the card; with Mandu
  nothing raw reached the model or an unbound host in any demo, the
  lookalike's inputs were refused, and the key reached the deploy host and
  the licence and card the registry. Two demos' Mandu sides were left
  undone by the model: it typed a placeholder that names nothing (a hash
  it made up), which the relay then typed as written, so the form got
  the literal text. Since then the relay refuses it and tells the model to
  type the placeholder as the page shows it (§3.2, *A placeholder that
  names nothing*); no demo has run live with that change yet. The
  support-chat and expense-report stories were
  reworked the same day so the chore itself carries the secret (the
  support desk's pre-chat form marks the key required and links the API
  keys page; the manager asks for the expense tool's summary, which repeats
  the card): without Mandu the desk received the payments key and the team
  chat the company card; with Mandu the desk got no key and answered by the
  account's email, the expense tool got the real card, and the relay
  refused the card's placeholder in the team chat, so the summary was
  posted without it.
- **The handling note** (§6.5): net-proxy `test/unit/model-note.test.ts`
  (the switch, the call, the note as the first system message, every
  request left as written and why); `test/component/model-note.test.ts` (a
  real NetProxy on its TLS-inspected leg, curl through it to a loopback
  OpenRouter: the note added with the placeholder as written, another path,
  host or a GET untouched, the note off and an arbiter without one leave
  the request as written, a request the gate refuses never asks for the
  note); `launcher/test/unit/browser-cdp.test.ts` (on only for a launch
  with a relay, never from an ambient value);
  `tests/stack/model-service-egress.test.ts` (the production adapter on a
  real arbiter: OpenRouter gets exactly the arbiter's note with the *Web
  pages* section, its key put back in the header, the page secret's
  placeholder as written and no value).
- **The refusal told to the model** (§3.4): arbiter
  `test/unit/relay-notices.test.ts` (every field checked, free text and
  values refused; per session, taken once, a repeat replacing the pending
  one; bounded per session, in sessions and in age) and
  `test/component/relay-notices.test.ts` (the two ops over the wire, a
  malformed report refused and nothing kept, both axes off still
  answered); cdp-relay `test/unit/release.test.ts` (each refusal's notice:
  kind, cause, host, names only) and `test/component/relay.test.ts` (a
  whole insert, a key run and an unbound page each reported once before
  the agent is answered, a failing report changing nothing); net-proxy
  `test/unit/relay-notice.test.ts` (the wording per kind and cause, a field
  that fails the check dropped and never quoted, one message after the
  latest, the note untouched, an unreadable body left as written with its
  notices not taken, an arbiter failing to give them) and
  `test/component/model-note.test.ts` (a real NetProxy and curl: the
  notice last, once, the proxy's own session's; a gzip body leaves it
  pending); `launcher/test/unit/browser-cdp.test.ts` (the relay and the
  proxy started with one session key);
  `tests/stack/proxy-real-client-parity.test.ts` (both production adapters
  over a real arbiter: reported through the relay's, taken once through
  the proxy's); `tests/stack/model-service-egress.test.ts` (the real relay
  over a fake Chrome and the real proxy on one real arbiter: a made-up
  placeholder inserted whole, then typed a key at a time and left, each
  reaches the next OpenRouter call as its last message, once, naming the
  typed placeholder and the one the page showed, no value anywhere; then a
  lookalike with a UUID for its code typed a key at a time reaches the next
  call as the `malformed` notice naming the page's real placeholder, never
  the lookalike, once). Arbiter `test/unit/relay-notices.test.ts` and
  net-proxy `test/unit/relay-notice.test.ts` check the `malformed` kind: no
  name of its own accepted, its wording, a forged one's free text dropped.
- **A site that may not have it** (§3.4): net-proxy
  `test/unit/relay-notice.test.ts` (the open ask's and the denial's
  sentences word for word: leave it out and go on, ask or tell only if the
  user asked for it there) and `test/component/model-note.test.ts` (both
  reach the next call through a real NetProxy as its last message);
  cdp-relay `test/unit/release.test.ts` and `test/component/relay.test.ts`
  (the DevTools error for each); `tests/stack/model-service-egress.test.ts`
  (the expense-report step on the production wiring: a summary carrying
  the card's placeholder inserted on an unbound chat is refused with
  nothing typed and the ask left pending, the next OpenRouter call is told
  to leave it out, the note says the same, and the summary with the card
  named in words is typed; no value anywhere); `tests/stack/cdp-relay.test.ts`
  (the deferred key-run error on a real Chromium).
- **The keys** (`tests/stack/provider-key-grant.test.ts`): the launcher's
  grants on a real arbiter's human socket, then its env-var mask: each key
  is a placeholder released only at its own host, in the Authorization
  header, over https; without the human plane it is still masked and asks.

## 8. Limits, and the steps after this one

Limits of step 1:

- **Only known values are masked**: registered secrets, and whatever filters
  the person turned on. A key born on a page ("create API key") passes until
  step 5's detectors and site packs register it.
- **A value split across strings** (a key spread over several text nodes) is
  not matched; the agent could join it.
- **Per-character typing** (`Input.dispatchKeyEvent` one character at a
  time: browser-use's `input`, Puppeteer's `type`) is released since
  2026-10-19 (§3.3). A placeholder split across commands of different
  kinds (part inserted, part typed) is typed as written. A run's refusal
  reaches the agent one input command late (§3.3) unless the run is a
  lookalike or a code no row has (both refused on the key that closes the
  code, since 2026-10-19); its model is told on its next call through the
  egress proxy (§3.4), but an agent whose model is on another wire and that
  sends no input command after it is never told (the trace still says
  `refused`). When that late command is a click, browser-use clicks by
  script instead, so a form can still be sent without the value when the
  run is refused at its end: a known base with a field the secret lacks
  (`…[5958].bogus`), or a known placeholder the page's site may not have or
  needs the person's approval for. Closing those on their way would mean
  answering for a field's start (which would let a typed run spell out the
  field names beneath a base, a lookup the relay does not make) or asking
  the release gate before the whole name is known (a field's binding can
  differ from its base's); the unbound case sends nothing raw either way.
- **The refusal reaches the model on Chat Completions calls only** (§3.4,
  the same wires as the note); on another wire the agent's own handling of
  the DevTools error is all there is. The notice does not name the field
  (its label is page text).
- **A placeholder-shaped literal** cannot be typed into a page with input
  commands (§3.2, *Prose*): it is refused as a placeholder that names
  nothing, and so is a lookalike of one (a code up to 64 characters
  without whitespace). A lookalike with a longer code, or one split by a
  space, is typed as written (nothing raw: it names nothing), and the
  model is not told.
- **The handling note reaches Chat Completions calls only** (§6.5): a
  browser agent on another wire (TypeSafe's decision model, the Responses
  API, a provider's own SDK wire) gets no note, and neither does a model
  service the launcher does not list.
- **A script the agent runs** can return a value transformed (base64), which
  a value match misses, and can make the browser send page data out itself.
  Under `--browser` Chrome's traffic goes through the egress proxy (§6.4),
  which refuses a registered value sent verbatim off its host; a value the
  script transforms first passes there too.
- **The focus in a frame**: a value is never typed into a frame, even of the
  same origin.
- **Images inside text** (`data:image/…` URLs in the DOM) are passed as
  text.

The steps:

1. The relay, its tests (this document). **Done.**
2. The stack test over a real arbiter and a real Chromium. **Done** (§7).
3. `mandu`: start the relay for a launch (`--browser-cdp <Chrome's
   endpoint>`), give the agent its URL, keep the agent off Chrome's own
   port: **done** (§6.1), with the keys jev needs (§6.3); the session page
   showing what the relay did: **done** (§5.1); a Chrome that Mandu starts
   itself, its traffic through the egress proxy: **done** (§6.4).
4. Live runs: jev-ultrafast and browser-use under `mandu`. **jev done**
   (2026-10-18, agent-sign-in.md §3.12: it found the model-service gap,
   fixed; four live drills, §7); **browser-use done** (2026-10-19: three
   drills and six demos with and without Mandu, §7).
5. Finding the secret on a page: context detectors (password inputs,
   one-time-code fields, a high-entropy value next to "API key" or a Copy
   button), **site packs** (per-site rules naming the element or API field
   that holds a secret, in the prompt filter's pack format), a value the
   person types into a secret field registered on submit; the screenshot
   cover (secret elements overlaid before a capture); an exec shim for
   agents that start Chromium over a pipe (Playwright's `launch`).
