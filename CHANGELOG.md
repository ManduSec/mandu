# Changelog

Mandu releases as one product with one version across every package
(`scripts/set-version.sh`, [`packaging.md §11`](docs/design/distribution/packaging.md)).
Entries describe what a user of `@mandusec/mandu` notices; design history
lives in `docs/design/`.

## 0.2.0 — first public release

Beta builds of this release are numbered `0.2.0-beta.N`. (0.1.0 was an
internal pilot and was never published.)

### New in 0.2.0-beta.8

- The dashboard has an account: one username and password for every page,
  wherever it runs. Set it with `mandu dashboard --set-password` (asked in
  your terminal; only a password hash is kept, in
  `~/.mandu/state/dashboard-account.json`). With an account, the dashboard
  shows a sign-in page with Username and Password instead of the browser's
  own password prompt, which was easy to miss and missing in some browsers,
  so you never put a password in the address. You stay signed in for up to
  7 days; Settings › Dashboard account has Sign out. Repeated wrong tries
  make the page wait before it checks again. Scripts can still send the
  username and password as HTTP Basic credentials. An existing
  `DASHBOARD_BASIC_AUTH` becomes the account the first time the dashboard
  starts, and the launch line, `mandu dashboard` and `mandu scan` say "sign
  in with your Mandu dashboard account".
- The dashboard account is now the only way into the dashboard. Until you
  make one, the dashboard shows nothing but a page that says how (`mandu
  dashboard --set-password`), and the launch line says "no account yet; set
  one". `mandu dashboard` and `mandu setup` offer to make it on the spot.
  The one-time sign-in links and `DASHBOARD_PASSWORD` are gone (a
  `DASHBOARD_PASSWORD` still set is ignored, and the log says so), and the
  dashboard prints no admin link any more.
- `mandu scan`: which of your secrets your AI agents already sent to the
  AI. It reads the transcripts Claude Code, Codex, OpenCode, Goose and
  OpenClaw keep on your computer (their SQLite stores too, read-only and
  without holding a running agent up), only the parts that went to the
  model, and lists each of your secrets it
  finds there with the file it lives in, how it got there and when, then
  the values that look like keys but are in no file now. No value is shown,
  nothing leaves the computer, and it needs no Mandu session: `npx
  @mandusec/mandu scan`. `--share` prints the counts alone. It also lists
  which of those secrets the agents' commands sent on the network (`curl`,
  `wget`, a web fetch), to the key's own service or to a host it cannot
  tie to the key, with the URLs there (the path shown, any password in
  the URL and every query value masked), and counts the riskier sessions: those that ran with the
  agent's permission prompts off, and those that printed your whole
  environment to the AI. A session that ran under Mandu is known exactly:
  Mandu's model proxies now record the id of each answer the AI gives
  (the same id Claude Code, Codex, OpenClaw and Goose keep in their
  transcripts, and OpenCode 2 on OpenAI's Responses API or Gemini; nothing
  else of the answer), so a session at the same time outside Mandu is no
  longer counted as under it. The join is per request: in a session you
  started outside Mandu and resumed under it, what it sent before the
  resume is reported as sent without Mandu, and only what went after counts
  as under it. Where OpenCode keeps no such id (1.x, and 2.x on Anthropic
  or Chat Completions), Mandu records the session id OpenCode sends with
  each request and keeps in its own store, and joins on it with the
  request's time. Sessions from before this release are still told by
  their time. Each finding is told step by step,
  from the record: the command the agent ran or the file it read, with the
  date, the project and the agent (for a web fetch, the URL it fetched,
  masked); that the output left your computer in the agent's next request
  to its provider (Anthropic or OpenAI, or "the model provider" when the
  agent's own settings, such as Claude Code's `settings.json` on Bedrock
  or Codex's `config.toml` on another provider, send it elsewhere, a
  trusted project's own `.codex/config.toml` included); what
  came next; and what Mandu would have done. A command is shown with every value it holds
  masked (`PGPASSWORD=‹DB_PASSWORD› psql …`), on one line. The findings
  are numbered, and `mandu scan --show <n>` prints one in full, every way
  it got there with up to ten examples.
- `mandu scan` also reads Gemini CLI's and Copilot CLI's sessions, agents
  Mandu does not run yet, and counts Cursor's chats without reading them
  (`3 Cursor chats not read`: Cursor's chat store has no format a reader
  can rely on). For those agents the report says Mandu does not run them
  instead of what it would have done, and names the agents it runs.
- `mandu scan` keeps its last report (names, files, hosts and counts, never
  a value) in `~/.mandu/state/last-scan.json`. The dashboard's Home shows
  how many of your secrets left the computer in your agents' requests
  before Mandu, and a new Scan page (*Scan* in the top bar, which on a
  phone is now two rows of three links; also linked from Home and History)
  tells each one's story: where it lives, what the agent ran or read, when
  and in which project, that it went to the AI provider, and what Mandu
  would have done instead. `mandu doctor` prints one line from it. With
  Mandu running, each file of yours whose key reached the AI and that no
  rule protects becomes a suggestion under Rules (Files and folders,
  Suggested); nothing changes until you save it.
- `mandu scan`'s report now ends with where to see it in the dashboard:
  the Scan page's address when your dashboard runs, else the command that
  opens it (`npx @mandusec/mandu dashboard` when you ran the scan through
  npx). `mandu dashboard` now opens even where Mandu never ran (it said
  "start a session first"); it starts the dashboard alone, and Home says
  "Protection is off: no agent runs with Mandu." with the command that
  starts it, instead of "Not connected.", whenever nothing of Mandu's
  runs. The top bar says "Protection off" then.
- `mandu scan --open` opens the dashboard's Scan page in your browser
  after the report, starting the dashboard first when none of yours runs
  (`Started the dashboard and opened its Scan page: <address>`). It uses
  the browser `BROWSER` names, else `open`, `wslview` or `xdg-open`, and
  gives it the plain address only, never a password or sign-in link. With
  no browser to open (an SSH session, no screen) it prints the address,
  and over SSH the `ssh -L` line that forwards the dashboard's port.
- `mandu scan` now knows more of your own secrets as yours ("rotate
  this"), where it used to list some only as values that "look like keys
  but are not in your files now": the GitHub CLI's and glab's tokens for
  every host they hold, your agents' own logins, and any credential store
  Mandu knows of, even on a computer with so many key files that Mandu's
  launch check stops before reaching them; a password or key in your
  systemd user services (`~/.config/systemd/user`, such as a proxy's
  `Environment=HTTPS_PROXY=http://user:password@…`) and in the
  `EnvironmentFile=` they name; and a key whose random letters happen to
  hold `xxxx` or `dummy`. A newer GitLab token (`glpat-….01.…`) is now
  found whole, past its dots: Mandu used to stop at the first dot, which
  left the rest of the token unmasked and made the scan list a piece of
  your own token as a second key.
- `mandu scan`'s report is now short and in colour on a terminal: `✗ 3 of
  your secrets leaked to the AI`, then one entry each (its name and file,
  sessions, how it got there in a few words, the command when one was all
  it took, and the hosts a command sent it to), the values that look like
  keys in one line by prefix (`sk-… ×190 · ghp_… ×24 · …`), the riskier
  sessions, and what to run next (`mandu claude`, `mandu scan --show 1`,
  `mandu scan --all`, the dashboard). `mandu scan --all` prints the long
  report with every finding's story and every send, under the same
  numbers. Colour only on a terminal: `NO_COLOR` turns it off,
  `FORCE_COLOR=1` on; never in `--json` or `--share`.
- A `mandu <agent>` session now ends with one line on stderr that says
  what Mandu kept from the AI, with the dashboard's own counts: ``mandu: in
  this session: 2 secrets masked before the AI saw them (DB_PASSWORD in
  ~/proj/.env and the file ~/.aws/credentials) · 1 send with a real value
  filled in (api.stripe.com) · details: `mandu dashboard` ``. Names, files
  and hosts only, never a value; printed after the agent's screen is gone,
  so `claude -p --output-format json` output stays clean.
  `--no-session-summary` or `MANDU_SESSION_SUMMARY=0` turns it off.
- Your MCP servers' tokens are protected with no label of yours: an MCP or
  editor config whose servers hold a credential (`.mcp.json`,
  `~/.claude.json`, Codex's `~/.codex/config.toml`, `~/.cursor/mcp.json`,
  `.vscode/mcp.json`, Claude Desktop's and Windsurf's configs) reaches the
  AI only with placeholders for those values, however it reads the file.
  The agent you launch keeps reading its own config as it is, so its MCP
  servers still start and log in; the programs it runs get a placeholder
  copy of every other MCP config, and an HTTP server's `Authorization`
  credential goes only to the host its own entry names. A config whose values only name variables
  (`"${GITHUB_TOKEN}"`) is left as it is.

### New in 0.2.0-beta.7

- npm-installed Mandu recommends the matching npm version when an update
  is available, keeping updates in the same install channel. The npm
  quickstart now documents supported Codex login and protection modes.
- Fewer questions on a fresh install: a key whose format names the
  service that issued it (a Stripe `sk_live_…`/`sk_test_…` key, a GitHub
  `ghp_…` token, a Notion `ntn_…` token, an OpenAI `sk-proj-…` key, Slack,
  npm, PyPI, Hugging Face and SendGrid tokens) now goes to that service's
  own API host without an Approvals card, over HTTPS and only in the
  request's `Authorization` header. Any other host, place in the request
  or plain HTTP still asks. `issuer_bindings: false` in `policy.yaml` turns
  it off (`issuers_off:` / `values_off:` for one issuer or one value).
- `mandu version` says which mandu you are running and what gets in its
  way: the file your shell ran, how Mandu is installed (npm package or
  source checkout), its version and commit, every other `mandu` on your
  PATH, background services of another version (and a systemd service
  that keeps them alive), and `MANDU_DEV_REPO`-style variables left by a
  source install, each with its fix. `--json` for bug reports;
  `mandu --version` is unchanged. `mandu doctor` shows the commit and the
  same problems.
- A launch that meets old Mandu services kept alive by a systemd service
  no longer stops them only to have them come back (or says the
  installation is mixed): it stops and names the service, with
  `systemctl --user disable --now <unit>` for a leftover one and, for one
  you keep, the `MANDU_HOME` and `MANDU_RUNTIME_DIR` that run this mandu
  beside it as a second Mandu.
- A person's name in a personal document Mandu found (the holder of a
  statement, say) is still a placeholder in the copy the agent reads, but
  it no longer masks every output that mentions you: a mail quoting "Alex
  Demo wrote:" reaches the agent as written. Account numbers, codes and
  passwords stay masked everywhere.
- On a session page, Your secrets names the file a key was read from
  ("STRIPE_KEY in ~/mandu-try/.env", not "STRIPE_KEY in a file").
- A bank or card statement, payslip, tax return, lab report, ID or note of
  house codes kept as a PDF (with a text layer, not a scan) or an Office
  file (`.docx`, `.xlsx`, `.odt`, `.ods`) is now recognised like the same
  document in `.md`, `.txt` or `.csv`: the AI reads its labels with every
  value a placeholder, and a send of a value asks you first.
- When Claude Code reads a PDF, the AI now gets the PDF's text (a personal
  document's labels with its values as placeholders) instead of one
  placeholder for the whole file. Images in the PDF, and a scanned PDF,
  are still not shown to the AI.

### New in 0.2.0-beta.6

Mandu is on npm: `npm install -g @mandusec/mandu` (Node 22.13 or newer).

Security fixes. beta.5 has these holes, so update:

- Mandu no longer writes its logs or the guard's status record through a
  link the agent planted. Its logs were checked at the file only: a
  `logs` folder in Mandu's runtime folder replaced by a link to any of
  your folders got the next launch's arbiter log made there, and the
  guard's end-of-session record followed a link in the session's folder
  and overwrote the file it named (a shell startup file, say) with
  `exited 0`. A per-launch arbiter (one started for `MANDU_ARBITER_SOCK`)
  appended its event records, which the agent can steer, through a link
  at a session's event file the same way. Now every folder on a log's way
  must be a real folder of yours or the system's, a link at a log's name
  is refused, and the record replaces a link instead of writing through
  it.
- A secret bound to a host with a port (`bindings: ["db.internal:5432"]`)
  was released to that host on any port; it now goes only to the port you
  named. Every place Mandu checks a binding now reads it the same way: a
  host covers the hosts under it, `*.example.com` covers the hosts under
  `example.com` but not `example.com` itself (before, a `*.` binding
  released nothing), and a program holding two secrets bound to
  `example.com` and `api.example.com` may send to `api.example.com` (before,
  nowhere).
- A program that read a secret can no longer pass it to a program of
  yours running outside Mandu's watch through a pipe, a socket pair or a
  named pipe (FIFO): when something outside holds the other end, Mandu
  refuses the program the secret's real bytes, or refuses the hand-off,
  before anything flows. A program whose open files Mandu cannot see (one
  of another user's, or one that hides them, such as `ssh-agent`) is not
  covered.
- A program that read a secret can no longer send it off the machine by
  writing through an overlay (or another stacked mount) whose upper
  folder is on a network mount, after the agent's own programs laid a
  local folder over that path or unmounted the network mount. Mandu now
  judges such a mount by the mount itself, not by the path its options
  name, and treats one that only the agent's programs can see as remote.
- Mandu runs only your system's bubblewrap: never a `bwrap` in the folder
  you launch in, the workspace, the AI's working copy of it, or reached
  through a PATH entry inside them. A planted `bwrap` there used to run
  outside any sandbox. An administrator can name the one to use with
  `bwrap_path:` in `/etc/mandu/policy.d/`; with only a planted one, the
  boxed command does not run.
- A program started in the background by one that read a secret can no
  longer send the secret out after both ended, when that program had
  started its own child before Mandu first saw it, or when the machine was
  too busy for Mandu to notice the first program's end at once.
- Claude Code's Artifact tools (in its interactive app) cannot upload a
  secret file: every file a publish or a data write names is checked, a
  secret one waits for your OK in Approvals, and a path relative to the
  working folder is refused with how to name it. Sessions that offer these
  tools are no longer reported as degraded.
- Another AI agent's login is masked like any credential file. Under
  `mandu claude` (or a plain command), Codex's `~/.codex/auth.json` used
  to stay readable to every program the agent ran, and Mandu did not know
  its key when it left the machine; under `mandu codex` the same held for
  Claude Code's `~/.claude.json` (your MCP servers' tokens) and its login.
  Now only the logins the session runs on stay readable (the launched
  agent's, Claude Code's where Mandu's AI helper runs `claude`, and both
  Claude Code's and Codex's under `mandu openclaw`, which reads them); the
  others are placeholder copies, also where `CODEX_HOME` or
  `CLAUDE_CONFIG_DIR` moves them, and the launch says so. A label in
  `policy.yaml` now applies to them. The agent that runs keeps using its
  own login with its own services (a token refresh, an MCP server's token)
  even after another session masked it. `MANDU_OTHER_AGENT_LOGINS=raw`
  keeps the others readable and usable, for an agent you start inside
  another. `mandu why` and `mandu doctor --secrets` no longer call those
  files placeholder copies where a launch leaves them as they are, and
  `mandu doctor --secrets --target <agent>` (with `--no-mcp` if you launch
  with it) shows one agent's launch.
- OpenClaw's Code Mode is turned off under Mandu. In it the model runs
  JavaScript that calls OpenClaw's tools inside OpenClaw, out of Mandu's
  sight (on 2026.9.9 it wrote a file with no call Mandu could check). The
  launch sets `tools.codeMode` to false, with a warning where you had
  turned it on, and a Code Mode call that still arrives is refused.
- OpenClaw's `web_fetch` now goes through Mandu's egress proxy. It used to
  connect to the web itself, around the proxy, so the proxy's check for a
  raw secret value in a request never saw it (only the check of the AI's
  tool call did). From OpenClaw 2026.9.6 its other web requests (an image
  or PDF URL a tool loads) go through the proxy too. On OpenClaw before
  2026.5.3, which cannot send `web_fetch` through a proxy, `web_fetch` is
  off under Mandu and the launch says so. The egress proxy also serves a
  plain `http://` request a client tunnels through it, which failed before.
- Secret environment variables that reached the agent as they were are
  masked now: `PGPASSWORD` and the other names ending in `PASSWORD`,
  `MYSQL_PWD` and the other `*_PWD` (one holding a directory, such as
  `HOST_PWD`, stays as it is), a personal access token in `*_PAT`
  (`GITHUB_PAT`), Terraform's `TF_TOKEN_*`, a Slack or Discord webhook in
  `*_WEBHOOK_URL` or `*_WEBHOOK`, and any variable whose value holds a key
  in a known format (a GitHub, GitLab, Stripe, Slack, Anthropic, npm or AWS
  key, a private key, also inside a JSON string such as a Google Cloud
  service-account key), whatever its name and however long the value. A
  Postgres or MySQL login with a password from the environment now fails in
  `secrets` mode, as one from `~/.pgpass` or `~/.my.cnf` already did;
  [`docs/usage.md`](docs/usage.md) lists the ways out. The agents' sign-in
  variables (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `CODEX_API_KEY`,
  `ANTHROPIC_CUSTOM_HEADERS`, which can carry an `Authorization` header, and
  the rest of the list in the usage guide) are still never masked, in any
  launch, and the docs that promise placeholders now say so.
- Your `~/.npmrc` token and a `pip.conf` or `PIP_INDEX_URL` index password
  are put back only in the `Authorization` header of a request to their own
  registry or index. The egress proxy used to put them back anywhere in such
  a request, so with default settings an agent steered by a web page could
  have `npm publish` put your token in a package's description, and the
  registry would publish it. The same placeholder in a request's body,
  address or another header now gets the request refused, whatever you
  approved. A host you bind a secret to yourself still receives it anywhere
  in the request: bind only hosts you trust with it. A placeholder with
  extra text added to its end no longer slips past the rule that sends
  these logins only over HTTPS.
- In the placeholder copy of a JSON, YAML or TOML file you labelled, the
  secret values in a list are now placeholders too. In an MCP config with
  an `env` block, every `args` value used to stay as written: the value
  after `--api-key` or `--token`, a `--token=…` value and a database URL's
  password reached the agent's programs, and a short one reached the AI.
  This covers the value after `--auth` or `--pat` and the password of
  `-u user:password` too, and a placeholder inside a YAML `[...]` list is
  quoted so the file still parses. `mandu why <file>` and the dashboard
  now say how many values the copy masks, or that it hides the file whole,
  instead of "each value is a placeholder". A short, plain word under an
  ordinary key is still not recognised, nor is a value inside a YAML
  inline mapping (`env: {TOKEN: …}`) or a `- |` list item; `extract:` or
  `readers:` on the file's entry covers it. When one placeholder covers
  several secrets (or a whole `[...]` item), a copy of each of them
  elsewhere in the file is a placeholder too. `--skip-auth`-style switches
  and `--exclude-pat`-style patterns no longer hide the item after them.
  A command line inside one list item (`sh -c "…"`) is now read word by
  word: before, a switch in front of a secret flag, as in `curl -s -u
  admin:…` or `tool --verbose --auth …`, left the secret as written, and
  so did `-H "Authorization: Bearer …"`, `docker login -p …` and
  `PGPASSWORD=…` there. psql's and mysql's `--password` alone (they ask for
  it) and docker's `-u user:group` stay as written only where that program
  is the command itself, not after a word that merely names it, such as a
  path (`/var/lib/mysql`) or an image (`mcp/mysql`). A `$`-led value is
  masked as a list item of its own after a secret flag or single-quoted on
  its own (`--password '$ecret…'`); inside an item of several words or a
  quoted word of a command line, `$NAME` is still taken for a variable and
  kept as written. The guarantees
  page lists the command lines this covers (curl, wget, httpie, psql,
  mysql, docker login, gh, npm, git) and what is still not recognised,
  such as a secret with no flag before it.
  `mandu why` on a file the agent made a named pipe (or a link to
  `/dev/zero`) answers at once instead of stopping Mandu's protection
  service, and it describes the placeholder copy only of a file up to
  256 KiB (a larger one gets the general answer).
- On Linux, Claude Code (seen with 2.1.299) no longer loses its connection
  to Claude partway through a session ("Unable to connect to API"). When a
  command that had read a secret ended, Mandu could take Claude Code
  itself for that command's leftover process, then refused its network
  connections and labelled every file it wrote (`~/.claude.json`, its
  history) as secret. Most likely in a session where the AI was shown a
  secret's content.
- On macOS, ending a session stops the agent's background jobs again. In
  recent betas they could outlive the session, still inside its macOS
  sandbox.
- `mandu stop` from an environment with its own `XDG_RUNTIME_DIR` (or, on
  macOS, its own `TMPDIR`) no longer stops every copy of Mandu you run. It
  used to count as your own, so a test script's stop ended your dashboard
  and the protection service of sessions running beside it. It now refuses,
  as one with `MANDU_RUNTIME_DIR` already did, and names `--stack` and
  `--every-stack`.
- Under Claude Code, what a background command printed after reading a
  secret (the secret in another encoding, say) is now caught when a later
  command prints it again. Mandu hid the background command's output
  when Claude Code checked on it (`BashOutput`), but did not remember
  those bytes as secret, so a copy of them could reach the AI later.
- On Linux, Mandu's egress proxy no longer fetches from this machine
  through an address of an interface that is down or has no cable or
  container behind it (a Docker bridge with no container running, say),
  or through a `local` route. It refused this machine's addresses as the
  system lists them, which leaves those out, yet a service listening on
  every address answers on them. It now reads the system's routing
  tables, which name every address that leads back to this machine.
- A program built on an agent SDK can no longer start its agent past
  Mandu's model proxy in four more ways. A Python program
  (`mandu --target claude -- python3 app.py`) that set its own
  `ANTHROPIC_BASE_URL` in the Python Claude Agent SDK's `env` option sent
  Claude Code's requests, with any file you labelled, straight to
  Anthropic; Mandu now loads its routing into Python as well. The Python
  Codex SDK's `codex app-server` ran with no Mandu routing at all behind a
  warning; it now refuses to start, as does `mandu --target codex` with
  Bun or Deno (`bun app.js`) or with `python3 -I`, `-E` or `-S`, which
  load neither hook. An agent started through a shell command string
  (`exec("codex …")`), Claude Code run as a script (`node cli.js`) and a
  CLI under another name that the SDK starts are now routed too, and an
  agent the SDK starts through another program (`docker exec`, `ssh`) is
  refused.
- A `claude` or `codex` started by its full path inside a session (or any
  program of the AI's that calls the model vendor itself) can no longer
  reach a model past Mandu's model proxy. With `ANTHROPIC_BASE_URL`
  removed or pointed at Anthropic it went straight to `api.anthropic.com`,
  carrying what it had read. Now, whenever secrets are protected, the
  agent's programs may call the vendors' hosts (`api.anthropic.com`,
  `platform.claude.com`, `api.openai.com`, `chatgpt.com`) only for the
  account, sign-in and usage calls Mandu lists: a model call there is
  refused (403) and a direct connection around Mandu's egress proxy is
  refused on Linux. The session's own model calls are unchanged. With
  `--no-net-proxy-mitm` those hosts are refused whole, so Claude Code's
  sign-in refresh fails there too (the launch says so).
- With the Unix socket allow-list on, the agent could reach a service of
  yours that is not on the list when it held a copy of that service's
  listening socket (one leaked into it by the program that started it):
  calling `listen()` on the copy made the agent's program count as the
  socket's owner. Mandu now notes every socket the agent's programs name
  when they name it, and an unlisted socket is reached only if the agent
  named it.

New and fixed:

- A server the agent starts that takes exactly one connection (one that
  listens, hands the socket to a child and exits, then serves a single
  client) now serves its client under the Unix socket allow-list. Mandu
  checked whose server it was by connecting to it first, and that test
  connection used up the server's one connection, so the real client
  waited forever; other servers saw an extra empty connection. It now
  checks without connecting (except for a server in a network namespace
  of its own, which is still checked the old way).

- A program connecting to Mandu's egress proxy over IPv6 (`::1`, or the
  proxy's IPv4 address written as `::ffff:127.0.0.1`) is now told apart
  from the others. Mandu could not tell which program had opened such a
  connection, so while a program in the session held a secret it refused
  every one of them, including those of programs that had read nothing.

- A command the AI writes with a secret's placeholder in double quotes or
  bare (`curl -H "Authorization: Bearer $MDU:…"`) now works: the shell
  used to read `$MDU` as an empty variable, so the request left with
  neither the key nor the placeholder, and the service answered 401 with
  no approval asked. Mandu now quotes the placeholder in the command the
  agent runs, so the key reaches the hosts it may go to and you are asked
  about any other. The AI is also told to single-quote it in scripts it
  writes, and a script that still loses it no longer fails with a silent
  401: Mandu stops the request and tells the AI (and you, on the session's
  page) to single-quote the placeholder. Nothing is sent and nothing waits
  for your OK.
- Under Codex, the AI reads back the command it wrote when Mandu stopped
  it or quoted a placeholder in it, as under Claude Code. It used to see
  Mandu's stand-in (`echo 'mandu-exec-gate: …'; exit 77`, or the quoted
  form) as its own command, so it could take the stop for one it made up,
  or retry with a command your Approvals answer did not name.
- A file that holds several keys (a `.env`) can send each key to its own
  hosts: `values:` on its `paths:` entry in `~/.mandu/policy.yaml`
  (`STRIPE_KEY: { bindings: [api.stripe.com] }`, `"AWS_*": { bindings:
  [amazonaws.com] }`). The AI's masked Stripe key reaches
  api.stripe.com as the real key, and the AWS keys never do. A program
  that opened the whole file may send it only where every key may go.
  Adding a host there is a loosening, held in Approvals. The Rules page
  shows such a file's second menu as *Per value*, with where each key may
  go, and `mandu why <file>` lists each key.
- After you update Mandu, the next launch no longer works with the
  Mandu services still running from the old version. When no other
  `mandu` session uses them, it restarts them as the new version and
  says so in one line; when one does (or they are newer than this
  `mandu`), it stops with a message naming `mandu stop --stack <dir>`.
- The same check now tells two builds of one version apart (a source
  checkout at another commit, an install beside a checkout): the
  services report a fingerprint of their code, and a launch of another
  build restarts them when nobody uses them, or stops naming both
  builds. Two launches started together on such services no longer
  both stop: one restarts them and the other waits for it and joins.
  The dashboard marks services of another version or build *STALE*.
- The first launch in a project after Mandu's services restart (an
  update, `mandu stop`, a reboot) no longer waits up to 1.5 seconds for
  the scan for unprotected keys when an earlier scan of that project
  finished: Mandu now remembers that scan across restarts, answers from
  it, and scans again in the background, as every later launch did.
- Codex can edit files in a session where the AI was shown a secret's
  content (by your OK, or by a label that lets that model see it). Mandu
  read Codex's patch tool (`apply_patch`) as a command to check, and in
  such a session, where Mandu stops the commands it cannot prove stay on
  your machine, it replaced the patch, so the edit failed.
- OpenCode 1 is marked *preview* too, like Goose and OpenCode 2: it
  works, but is tested less than Claude Code and Codex. The launch says
  so in one line (`MANDU_PREVIEW_NOTICE=0` hides it), `mandu doctor`
  marks its version row, and the dashboard shows a Preview tag by its
  name.
- Tested agent versions raised: Claude Code to 2.1.295, Codex to
  0.162.0, OpenClaw to 2026.9.9, OpenCode to 1.18.35 and OpenCode 2 to
  2.0.26, Goose to 1.54.0, so the "newer than tested" warning is gone for those versions.
- `mandu claude` starts Claude Code in its default permission mode, as
  it starts without Mandu. Before, Claude Code under Mandu started in
  `auto` mode (its classifier approved commands) because Mandu turns off
  the traffic that fetches its feature flags. A mode you choose yourself
  (`--permission-mode`, `--dangerously-skip-permissions`, or
  `defaultMode` in your Claude Code settings) is kept.
- A file you labelled public is no longer masked when Goose reads it with
  a shell command or OpenClaw reads it by a relative path. Your label
  decides either way: a no-model label on a folder now also masks such a
  relative read.
- When the agent's `git commit -a`, `git add -A`, `git add -f` or `git
  stash` swept a protected file's placeholder copy into your repository
  (git in the session reads that copy), nothing said so: your history held
  the placeholder, and a later `git checkout` or `git reset --hard` of the
  file would have written it over your real file. Mandu now checks the
  repository after the session and prints a warning naming the file and
  the commit, with the commands that repair it, in the order to run them;
  a session that crashed is checked at the next launch. git in the session
  only ever records the placeholder, and the repair only takes it out: no
  command adds your file on disk to git or brings back a version from
  another commit or branch. A file taken out this way is no longer tracked;
  if it belongs in git you add it back yourself, otherwise you list it in
  `.gitignore`.
- After the AI wrote a file you dictated, in a session already cleared
  for what it holds, your own sentence in the conversation is no longer
  masked as if it were that file's secret. The model used to read your
  request as a placeholder and write the placeholder into your file.
- On Linux, when the agent changes a protected file such as `.env` (`echo
  X=1 >> .env`), Mandu now says so when the session ends, one line per
  file: the change went into the file's placeholder copy and was
  discarded. The line says the real file is unchanged only after checking
  it, and says so when the real file changed too. If Mandu itself is
  killed before the session ends, `mandu reap` names the files. It used to
  be lost without a word. Tools that save a login into such a file (`npm
  login`, `goose configure`) still lose it under Mandu: run them outside.
- Under Goose, loading a skill and listing apps return their text instead
  of a placeholder. A labelled file a skill loads still reaches the model
  only masked.
- Under OpenClaw 2026.9, Mandu's `inspect_symbol` tool is visible to the
  model again (it failed with "Tool inspect_symbol not found"), and the
  new `presence` tool is recognised.
- Under Codex's own sandbox, a command run right after one that read a
  labelled file is no longer hidden from the AI now and then (about one
  time in five on a busy machine): Mandu now notes the moment a program
  holding a secret ends, instead of up to a fifth of a second later, and
  on a very busy machine notes it before the agent's next step goes on
  rather than whenever it gets to it.
- `mandu demo` no longer leaves its temporary folder behind now and then
  on a busy machine: it waits for its background services to exit before
  it removes the folder.
- On macOS, `mandu paths --json` is no longer cut short at 8 KiB, and
  `scripts/bootstrap.sh` no longer stops on the system's bash 3.2 when
  every install worked.
- While a hand edit of `policy.yaml` that loosens a rule waits in
  Approvals, `mandu policy suggest`, the dashboard's Keys Mandu found and
  Undo in History work again (they were refused until you decided the
  edit). The change goes into force and into the file; your edit stays in
  the file, still waiting, on a fresh card. When Mandu writes such a
  change (or a lock your agent asks for) into `policy.yaml`, your comments
  and layout stay as you wrote them.
- The rest of Mandu's own writes of `policy.yaml` keep your comments and
  layout too: the program Mandu pins when a listed reader first opens a
  secret, moving the Rules page's older rules into the file, and the
  developer view's apply. A comment at the end of a line Mandu changes
  stays on that line. And while a hand edit that loosens a rule waits in
  Approvals, these writes no longer write over it (a pin used to: your
  edit was gone from the file and its card closed): the change goes into
  force and into the file, your edit stays in the file, still waiting, on
  a fresh card. One that changes the same rule as your edit waits until
  you decide it (a pin is made at the reader's next open).
- The developer view's policy writes (its Lists buttons, trusting a
  website, allowing a connection) no longer undo a change that landed
  after the page read your policy, such as a file your agent locked a
  moment before, a hand edit, or an answer in Approvals: they used to
  write the whole policy as the page had read it, silently removing that
  change. Now the write is refused when the policy changed since, the page
  says what changed and keeps what you typed, and *Reload the policy* lets
  you make the change again to the policy as it is now.
- Saving a model in Settings › Models no longer overwrites a change made
  to the same model after the page showed it (in another window, or by
  hand in policy.yaml): the save rewrote the whole entry as the form had
  read it, its TLS checks included. Now the save is refused, nothing is
  written, the form keeps what you typed and the list shows the model as
  it is now, so you can compare and save again. A change to another model
  does not get in the way. Allow and Block on a rule of your own on the
  Rules page are checked the same way.
- The same holds for a file's label on the Rules page, a sensitivity
  label's level in Settings, and *Always* for a file in Approvals: a save
  made from what the page (or Mandu, for *Always*) read no longer puts back
  a rule that was changed meanwhile, its hosts and level included. The
  save is refused and nothing is written; Rules keeps your choice waiting
  and shows the label as it is now, Settings keeps the level you picked on
  the row, so you can look and save again. A change to another file's rule
  or another label does not get in the way.
- A conversation you resume under a new `mandu` launch (`claude --resume`,
  `--continue`, `codex resume`) keeps Mandu's note on results the AI read
  before you marked them secret, so it does not take its own earlier
  answer for an invention. Mandu remembers which results it let through,
  by the tool call's id only, never the content.
- Fewer results hidden behind a placeholder when nothing secret is in
  them. Claude Code's checks on a background command (`TaskOutput`,
  `BashOutput`) now show that command's output unless the command itself
  read a secret, and the status lines of one hidden check no longer hide
  every later one. Under Codex, the lines Codex adds in front of a
  command's output stay usable after Mandu's service restarts, an MCP
  tool's timing line no longer hides later results, and when Mandu blocks
  a whole code cell the agent is told why instead of seeing a
  placeholder. Secrets stay hidden as before.
- Codex installed with npm (`npm install -g @openai/codex`) keeps working
  after one of its commands reads a protected file through a program you
  allowed. Before, Mandu took npm's small start-up script for Codex itself,
  so the real Codex was treated like that program: it lost its connection
  to the AI ("stream disconnected") and could not read its own session
  file. Codex installed any other way was not affected.
- Under Codex running commands in its own sandbox (its default), a
  command's output is no longer hidden just because another command in
  the session read a secret: Mandu now tells which sandboxed command ran
  where. A command that read the secret is still hidden.
- `mandu doctor`, and a launch in one line, now warn when the `node` on
  your PATH is too old for Node programs the AI runs to have your secrets
  filled in on their web requests (older than 22.21, any 23.x, or 24.0 to
  24.4 for `http`/`https`). Their logins failed with no explanation; the fix
  is Node 22.21 or newer, or 24.5 or newer. Mandu itself still runs on 22.13.
- The README explains a protected file as two questions, each with its
  own key: which AI may read it (`level`) and where it may be sent
  (`bindings`). Its examples, and the design notes, no longer name `psql`
  as a program that gets the real password: a Postgres login from
  `~/.pgpass` fails under Mandu, as the user guide says.

Dashboard:

- The developer view (`/dev/`) is no longer part of the package: the
  dashboard is the product page. Each session's page is where you check
  what the AI saw beside what really happened. It now shows every turn,
  step and secret on request, where it used to send you to the "Detailed
  trace". Opening `/dev/` shows a page that says the developer view is
  not included and is available on request, instead of a bare "Not found".
- The status at the top right of the dashboard says **Protection on** or
  **Protection off**, the words of the Settings switch. It used to name the
  level ("Protection: Secrets"). A change saved for the next start reads
  "· off from the next start" (it was "saved: off, applies at the next
  start").
- The Rules page's labels say which AI may read a secret, and say it
  truly: "Secret, no AI", "Secret, your own AI only" and "Secret, any AI
  when it asks" (they were "hidden from the AI", "your own model only" and
  "the AI may read it"). The explanations add that no approval lets
  another AI read the file, that an `any-model` file starts as a
  placeholder and reaches your AI provider once the AI reads it, and that
  a database shell never gets the real file. `mandu why` uses the same
  words, and no longer calls a `local-model` file hidden from every AI.
- Each rule on the Rules page answers both questions in two menus: which AI
  may read it, and where it may be sent (Needs your OK, Listed hosts without
  asking, Not secret). A row with no hosts now says that sending needs your
  OK, and a line under the name says which programs may open the real
  file.
- The Rules page reads your rules the other way round too, in a card of
  its own, "Who may get your secrets": per program (which files it may
  open raw, and on whose word), per host (which files reach it without
  asking) and per AI (which files any AI, or an AI of your own, reads as
  written, may read when it asks, or always sees masked). It is read only.
- While Mandu's protection service is down, Home and Approvals say they
  could not check, instead of showing stale questions with live buttons,
  and an agent page says "Not connected" instead of "Session not found".
- An agent page shows the warning mark Home shows when the agent's
  version is outside the tested range, and an OpenCode 2 session is named
  "OpenCode 2".
- An OpenClaw 2026.9 session is named after your prompt, not after
  OpenClaw's "Conversation info" header.
- In the developer view, a step where Mandu asked says your answer; a
  session with no recorded mode makes no claim about untrusted text; the
  Secrets tab lists a key masked outside the session's events; and a
  placeholder the AI made up is not counted as masked.
- A step where the agent edits files with a patch (`apply_patch` in
  Codex, OpenClaw and OpenCode) names the files it edited, created, moved
  or deleted, on the agent page and in the developer view, instead of
  "Edited a file". A patch Codex applies from inside a code cell does too
  ("Ran `npm test` and edited `config.ts`"), when its text is written out
  in the cell.
- A program that read secret files and tries to send to a host not all of
  them may go to now asks in Approvals instead of only failing. The card
  names every file the program holds, where each may go and which are in
  the way, and offers Allow once, Allow this session, Block, and one
  *Always* per file in the way: "Always: add hooks.slack.com to .env"
  adds that host to that one file's rule and to no other. The send goes
  once every file may go there; until then the card says which files are
  left. A copy of a secret file is named by the files it came from, and
  its *Always* changes their rules.
- In a session where the AI read a secret, a command you allowed that
  then tries a host the secret may not go to now asks in Approvals too,
  on the session's card for that host, instead of only failing. The card
  says the command's request was stopped and holds data from what the
  session read; *Allow once* lets the next try (the AI runs the command
  again) connect there once, and *Block* stops the session's requests to
  that host. The AI is told you were asked.
- A rule on a file, such as one saved from Keys Mandu found, reads as that
  file on the Rules page ("this file only", with a file icon) instead of
  as a folder "and everything inside", and "Who may get your secrets"
  lists the file alone. The rule itself is unchanged.
- On a slow connection, the dashboard's Home, Approvals and Settings no
  longer go back to an older state when an earlier read answers late:
  the page never says your secrets are guarded after it found the
  protection service stopped, never "Not connected." after the service
  came back, and never shows a question you just answered as waiting
  again.
- On a slow connection, Rules › Keys Mandu found no longer brings back a
  key you marked as not a secret or saved when an earlier read answers
  late, so the next Save never sends it again; a scan's new keys and its
  "Scanning…" state stay.
- On the dashboard's product page, a box that scrolls with nothing to
  click in it (the model preview's list of names, a suggestion's
  policy.yaml lines, what Changes to save changes and the weaker-change
  question's lists, a code block in a reply, a value you chose to show)
  says what it holds when a screen reader reaches it with the keyboard,
  instead of reading all its text as its name.
- A screen reader tells apart the links and buttons a list repeats on
  every row. Each agent's *Details* on Home names the agent and its
  prompt. Each *Undo* and "See what the agent was doing" under *Rule
  changes* in Approvals names the change it belongs to. *Allow*, *Not
  now* and the agent link on each rule change your agent asked for name
  that request, never the reason your agent gave. On an agent's page, each
  *Show the real value* and *Hide it again* names the secret it shows
  ("Show the real value: The file ~/ws/.env"), never its value. Before, a
  list of links read the same word once per row.
- On the Settings page, the protection service's Start and Restart keep
  the keyboard focus. Restart's question takes the focus, and Escape
  cancels it. After a start or restart, the focus is on the line that says
  what the service does now; after a refusal, on the button you pressed,
  read with the refusal. When the page notices the service changed, the
  focus stays on the same button, or goes to the Protection heading when
  that button is gone. Before, each of these left a screen reader at the
  top of the page.
- A session that read a file you marked secret only after it ended no
  longer shows that read as a plain one. Its page says the AI read the
  file as it was and when the file was marked, *Your secrets* lists the
  file (with no placeholder, since nothing in that session masked it), and
  Home counts it as read before it was marked. The time comes from the
  record of rule changes (or the Rules page's own), and applies to the
  agent's file reads.
- The page of an agent that asked for a rule change says so under *Needs
  your OK* ("1 rule change this agent asked for is in Approvals"), and
  the request's card in Approvals links that agent's page ("See what the
  agent was doing"), as a question's card does. So does a row under *Rule
  changes* in Approvals for a change your agent made or asked for.
- In the developer view, the list of a session's steps beside its trace
  names the file each read, write or edit touched and the command each
  command step ran ("Read .env", "Bash npm test"), so two steps no longer
  look alike, and a step whose result Mandu did not check (every step in
  Secrets mode) says "trust not checked" when you point at it, as its card
  does, instead of "trusted result". Each card's ⚖ and *masked* button
  name that step too ("Rules for this tool call: Read .env"). A search
  names what it looked for, a web page its site, a folder listing its
  folder and a patch its files ("Grep TODO", "WebFetch docs.example.org",
  "LS src"). A call to Mandu's own tools names what it asked about: the
  sandboxed reader and a request for a real value their placeholder
  ("inspect_symbol $MDU:…"), a rule test where the data would go
  ("mandu_policy_test paste.example"), a rule change its kinds of edit
  ("mandu_policy_propose lock-path"). Your prompts and the AI's replies there say their first
  words ("You Find where the env token is used."), each turn is announced
  as a group to a screen reader, and each "⤢ full prompt" button names its
  turn. A window opened there says which item it shows: the full prompt
  its turn ("⤢ Full prompt · Turn 2"), a call's rules the call ("Rules ·
  Bash npm test"), and a screen reader reads a masked value's card, its
  "why masked?", the table of masked values and a file's content by the
  placeholder, moment or file they show, never one name for all. The
  buttons on each masked value's row (in the Secrets tab, the table of
  masked values and a step's *New token* lines) name it too: "why
  masked?: $MDU:…", "reveal: $MDU:…", and a birth by its moment and
  placeholder, never the value. In a masked value's card, each step of
  *What happened* names its "trace →" by its step ("t1 · 09:00:05 ·
  trace: step 2"), and a screen reader reads the step's sentence with it,
  so steps of one second no longer sound alike. That card now tells a
  session in the order it happened: the AI read the placeholder, then used
  it in a command, then the shell gate let the command through, where it
  read the gate first and the reading last. Its evidence graph draws its
  rows in the same order. The ⓘ on a step's check line names the call it
  checked, and so does the window it opens ("ⓘ exec_action · Bash npm
  test"), where every command's read "exec_action"; a screen reader reads
  each such window by what it shows, never "Trace event detail" for all.
  The same goes for the windows the developer view's Rules page opens: a
  screen reader reads each by the rule, answer or chip it shows ("Policy
  row detail: rule fs:sensitive-path"), never "Policy row detail" for all.
  On that page, its two Level choices no longer share one name: a screen
  reader reads "Level of the new label" in Secrets and "Level of the data
  to test" in Test a flow. The Audit trail's filter, which had no name,
  reads "Kind of audit entry". In a session's step list, a send names
  where it went ("Blocked send collector.example"), as its card does,
  where three stopped sends all read "Blocked send". On the Rules page, a
  screen reader names each Protection level by its word ("Secrets") and
  then reads the words under it, where it read the whole card as the
  name at every arrow key. The Protection controls on the Rules and
  Settings pages (the level choices, the Pause sending button and the
  switches) now keep the keyboard focus, where it was lost every few
  seconds and after each change; so does *→ your answers · N* when the
  number of your answers changes. The Rules page's *Restart services*,
  shown when a saved protection level waits for a restart, stays off and
  says "restarting services…" until the restart is done, where a second
  press restarted everything again; what it answered (sign in first, an
  error, done) stays under it, where it was gone within seconds. When the
  restart did not change what is running, it now says so, also when the
  protection service was started outside the dashboard and was left
  running. On the Settings page's Services, a service's Start, Stop and
  Restart stay off until the service has answered, and every service's
  stay off while *Start / Stop / Restart services* runs, where a press
  could start a service again in the middle of its own restart. A press
  there keeps the keyboard focus: an answer that worked puts it on the
  service's line, which says what it does now (on the line under the
  three buttons for *Restart services*), a refusal on the button pressed,
  described by the refusal, and a service that crashes moves a focused
  Stop or Restart to its line, never to Start; it used to fall to the top
  of the page.
- An agent page tells the AI's request to read a secret's real value into
  its conversation in words, where it read "Used `mandu-inspect
  declassify_symbol`": "Asked Mandu for the real value of" the secret, by
  its name, and what Mandu answered: that it did not give the value, that
  it asked for your OK in Approvals first, or that it gave it, after which
  the session's requests and commands that could carry it where it may not
  go wait for your OK.
- In the developer view, a call to the sandboxed reader always shows what
  the AI asked it and the placeholder it got back, with the reader's model
  and the masked chip, however the agent passed the answer on. Before, when
  Claude Code added a note after the answer, or the answer came as its bare
  placeholder, the step showed as one card marked "same on both sides"
  with the answer's raw record in it. What came after the answer is now
  shown under it ("after it"). OpenCode's calls to the reader get the same
  card, with the reader's own record joined to it. On an agent's page, an
  answer that came as its bare placeholder reads "Got the answer only as"
  the placeholder, where it read "Got the reader's answer."
- On Rules, the question Mandu asks before a weaker change names a rule on
  a file, such as one saved from Keys Mandu found, as that file. It used
  to add "This covers everything inside it that has no rule of its own",
  as if the file were a folder. A folder's rule is asked about as before,
  and what you confirm and what is saved are unchanged.
- In the developer view's Rules › Secrets, the Labels table's Scope column
  says "this file only" for a label on a file that reaches everything
  inside its path, such as one saved from Keys Mandu found or made with
  "Apply to the whole subtree". It used to say "subtree", a folder's word.
  A folder's label still says "subtree", and the label is unchanged.
- On Rules, pressing *Scan for keys* in Keys Mandu found puts the keyboard
  focus on the card's heading while the scan runs, and back on *Scan for
  keys* when it ends or is refused. Before, a screen reader was left at the
  top of the page for as long as the scan ran. A focus you move elsewhere
  meanwhile stays where you put it.
- In Settings › Protection, the switch holds from your press until the
  dashboard answers: a second press sends nothing and asks nothing. Before,
  a double press saved the setting twice, and while turning protection off
  a second press asked you to type OFF again. The keyboard focus stays on
  the switch, which then reads its new state.
- In the developer view, a session's Files tab fits a phone: the commit
  list sits above the picked commit's changes, each across the screen.
  Before, the changes were squeezed to nothing beside the list and could
  not be read. A session with no commits no longer keeps an empty column,
  so its "No dual-view commits for this session" note reads whole, also on
  a desktop.
- In the dark theme, the number of approvals waiting, beside Approvals at
  the top of every page, is dark on its amber dot, in the dashboard and the
  developer view. It used to be white on light amber, which was hard to
  read. The light theme is unchanged.
- On a phone, a question's answer buttons wrap onto another line inside
  its card. A held message's answers used to run off the screen and make
  the whole page scroll sideways, with Send masked out of sight; on a
  small phone a send's Block was cut off. A desktop is unchanged.
- On a small phone (under 352 px wide), an agent's page fits the screen:
  its Your secrets cards used to run off the right edge and make the page
  scroll sideways. In the developer view, the Run drills list of scenarios
  fits a phone's screen too. Wider screens are unchanged.
- The dashboard and the developer view follow your system's "reduce
  motion" setting. With it on, nothing pulses (the red banner of a session
  Mandu flagged, a running session's mark, a starting service's dot), a
  dialog appears without sliding in, a switch or a fold changes at once,
  and a jump to a rule, a step or a panel lands at once instead of
  scrolling there. The highlight that shows where a jump landed stays,
  held still, and then goes. Without the setting nothing changes.
- With a contrast theme (Windows' high-contrast themes, or a browser set to
  its own colors), the dashboard draws the Protection switch in Settings:
  an outline when off, filled in your theme's selection color when on.
  Before, the switch was not drawn at all. The page you are on is
  underlined in the top bar, and on Rules only the picked tab of Who may
  get your secrets is marked; before, they looked like the others. Without
  a contrast theme nothing changes.
- With a contrast theme, the developer view shows what is picked too. The
  page you are on, the session's tab, Files' tab and the picked half of
  Drills' Runs | Matrix and Replay | Live are underlined in your theme's
  selection color. The open session in the list, the step you picked in
  the trace's rail, the commit you opened and the section you are on in
  the Rules, Settings and Tests menus have an edge in that color, and the
  others none. Before, each looked like the others but for a bolder word,
  and every row of a list had the same edge. Without a contrast theme
  nothing changes.
- In the developer view's Rules and Settings menus, the section you go to
  is the one marked. That holds for a click, a link to `rules#audit`, or a
  jump such as *→ audit trail*, and also for the sections near the end of
  the page, which cannot scroll up to the top. Before, the menu marked the
  section above: Audit trail and Test a flow showed as Secrets, and
  Settings' last four sections showed as Sandbox.
- In the developer view's Rules and Settings, the address keeps the
  section you went to, so a reload, a copied address or Back returns there.
  Before, a link such as `rules#audit` lost its `#audit` as soon as the
  page loaded, and a jump such as *→ audit trail* left the address naming
  the section you were on before.
- In the developer view's Settings › Services, *Start / Stop / Restart
  services* stay off while one service's Start, Stop, Restart or Replace
  is under way, and come back with its answer. Before, *Stop services*
  pressed during a service's restart said "services stopped." while that
  service came back up.
- The developer view's tab title names the page you are on, as the
  dashboard's tabs do: "Mandu · Rules · Developer view", "Mandu · Tests ›
  CI · Developer view". Before, every page's tab read "Mandu · Developer
  view", so two tabs and the entries of the browser's history looked alike.
- On Rules, Your rules shows every file and folder rule in the page
  itself. Before, they sat in a box of their own about half a window high:
  on a phone one rule of six showed whole and the rest scrolled inside the
  box, with only a row cut at its edge to say there were more. A folder's
  entries in Add a rule and the list in Keys Mandu found keep their box.
- On Rules, *Changes to save* no longer hides the control you are on.
  While changes wait, the page scrolls a control you Tab to above the
  bar, and a rule's menu you just changed moves up when the bar comes up
  over it. Before, the bar covered them: with three changes waiting, about
  two in five of the page's Tab stops landed under it, and more on a
  phone.
- In the developer view, the top bar no longer hides the control you are
  on when you Shift+Tab back up a page, and on a phone a Rules or Settings
  section you pick in the menu shows below the menu's row, its heading in
  view. Before, Shift+Tab left up to 20 of a page's controls under the bar
  (on Rules), and a phone's menu row covered the heading of the section it
  showed.
- On Rules, on a phone, choosing a label or where a file may be sent in
  Your rules no longer moves the page. Before, each choice scrolled the
  page up by almost half a screen, and the menu you had just changed ended
  below the window.
- On an agent page, *Show the real value* and a prompt filter's *Show what
  was hidden* keep the keyboard focus. Once the value shows, the button
  reading *Hide it again* has it; when the dashboard cannot show the
  value, the button has it, and a screen reader reads why. Before, the
  focus fell to the top of the page either way.
- On Rules, *Describe what you want* keeps the keyboard focus. While the
  helper works, it waits on the card's heading; the suggested rules then
  have it, or *Suggest rules* has it back with the reason nothing came.
  *Try it* keeps it, and a screen reader reads its answer; *Apply* hands
  it to the line that says the rules are applied, or keeps it with the
  reason they were not. *Cancel*, *Discard* and *Describe it again* keep
  it in the card too. Before, every one of these left it at the top of
  the page, for as long as a minute while the helper worked.
- In the developer view's Rules and Settings, on a phone, the menu row
  shows the section you are in. As you scroll, or when a link such as
  `rules#secrets` opens the page, the row slides to bring that section's
  name into view. Before, the row stayed put: on Rules it showed only its
  first two names, so further down the page the marked name was off
  screen.
- In the developer view's Rules, *Test a flow* shows its answer as soon
  as it comes, also when the panel refreshes while the test runs. Before,
  that answer showed only at the next refresh, three seconds later.
- In the developer view's Rules, *＋ Add a rule* and *Lists* say why a
  change was refused as soon as the answer comes, also when the panel
  refreshes meanwhile; before, that showed at the next refresh. *Add
  rule* and *Test* keep the keyboard focus: once the answer is back, the
  button has it again, and a screen reader reads the refusal or Test's
  answer with it. An added rule closes the form and hands the focus to
  *＋ Add a rule*. Before, the focus fell to the top of the page. While a
  rule or a test is on its way, its button stays off even when the panel
  refreshes.
- On an agent page, *Show the real value* and *Show what was hidden* show
  their answer also when the page refreshes while the value is on its way
  (the agent did more): the value, or why it cannot be shown, appears
  under the same secret, and its button has the keyboard focus. If the
  page then says the protection service is not running, nothing is shown
  and the focus goes to the page's heading. Before, the answer showed
  nowhere and the focus fell to the top of the page.
- On Rules, in a window up to 1000 px wide (half a laptop screen, a
  tablet held upright), the file lists put the two menus under each name,
  as on a phone. Before, the menus kept their columns down to 721 px and
  left the name a sliver: names in Your rules, Add a rule and Keys Mandu
  found were drawn a letter or two per line. Wider windows keep the
  columns, with room for the name.
- In the developer view, a session's Trace fits its window from 761 px
  up, also with the session list dragged wider. Each term of *What these
  words mean* takes at most two fifths of the box and wraps beyond that,
  so its meaning keeps the rest. Before, the trace ran past the window's
  edge and the page scrolled sideways up to about 840 px. The meanings
  got the space the terms left, none at all at 800 px, where the open
  box ran thousands of pixels down the page.
- In the developer view, the session list never takes the trace's room:
  it is at most the window's width less 500 px, and gets the width you
  dragged back when the window widens. Before, a list dragged wide stayed
  up to 600 px wide in a narrower window, so in a window under 1100 px
  the trace shrank, to nothing at 800 px, and the page scrolled sideways.
- In the developer view's Rules and Settings, a link to a section
  (`rules#secrets`) no longer undoes your own scroll. If you scrolled,
  pressed a key or touched the page within its first moment, the page
  stays where you put it. Before, it went back to the linked section
  half a second later.
- In the developer view's Rules, *Lists* reads why a change was refused
  with the button you pressed (✕, ＋, 🗑 or *New list*), so a screen
  reader says it there. After you remove a host with its ✕, the keyboard
  focus goes to the list's name; after you delete a list, to *Lists (N)*.
  Before, it went on to the next host's ✕, where a second Enter removed
  that host too, or fell to the top of the page.
- In the developer view's Rules, a change Mandu refuses because it would
  leave your policy file invalid says "Not saved", that the file is
  unchanged, and what was wrong. Deleting a list a rule still uses says
  where it is used ("Not deleted: user_rules[0].to.host still uses
  @registries"). Before, both said Mandu "refuses to start", the words
  for a broken file at start-up, though nothing had stopped.
- On Rules, a change Mandu refuses as not valid says why. A pattern typed
  in Add a rule that Mandu cannot use reads, for example, "Not saved:
  ~/notes/[draft: '[' in '[draft' is never closed (a literal '[' is
  '\[')." A rule's menu says "Not changed:" and Describe's Apply "Not
  applied:", then the reason, and Apply offers *Describe it again*. Before,
  all three said only "this change is not valid", and the line above Save
  showed the reason in policy-file terms, with the full path.
- On Rules, a pattern you type in Add a rule that Mandu cannot use says
  why on its row as soon as you press Go, for example "Mandu cannot use
  this pattern: '[' in '[draft' is never closed (a literal '[' is '\[')."
  When its matches could not be worked out for another reason, the row
  names it, such as the protection service not running. Before, the row
  said only "Which files it matches could not be worked out.", and the
  reason came after you chose a label or pressed Save.
- In Approvals, a rule change you asked for that is still waiting is
  never credited to your agent. This happens when policy.yaml changed on
  disk just as you saved. It reads "You want to change a rule", with the
  page's note under "Note", below "Rule changes waiting for you", and Home
  says "1 rule change waits for you in Approvals". Before, it read "You
  wants to change a rule", put the page's note under "Your agent says",
  and Home said your agent had asked for it. A held change to policy.yaml
  is no longer listed under "Rule changes your agent asked for" either.
- History keeps up while it is open. A session that ended says "ended", a
  new session comes in on top, and each row's counts stay current, with
  the keyboard focus left where it was. Before, the page was read once
  when opened, so an agent that had exited still read "running now" until
  you opened History again.
- *Show more* in History and in Rules › Add a rule's file browser says
  why when it cannot read the next page, and stays there to try again,
  with the keyboard focus on it. When it works, the focus goes to the
  first row it brought. Before, a failed History *Show more* disappeared
  and the focus fell to the top of the page; the file browser's said
  nothing when it failed, and lost the focus when it worked.
- In Rules › Add a rule, a folder of more than 500 entries keeps the rows
  *Show more* brought when the protection service comes back and the
  folder is read again, with a row you ticked or opened among them and the
  keyboard focus. Before, the folder came back as its first 500 entries,
  and with the service stopped the rows *Show more* brought went at the
  next refresh.
- In Rules › Add a rule, Tab in the path box completes names past a
  folder's first 500 entries. A name that a folder and a file share there
  completes to the part they share (`~/big/notes` for `notes/` and
  `notes.md`). Before, Tab knew a folder's first 500 entries only, so it
  left such names as typed, or completed `~/big/not` to the folder
  `~/big/notes/` when the file was past them.
- In Rules › Add a rule, Go to a file past its folder's first 500 entries
  opens its row, and so do *Show in its folder* and *Show in the file
  browser*, which put the focus on that row's ⋯. Before, the file was not
  opened and stayed behind *Show more*, and the path box that named it
  read the folder.
- In Rules › Add a rule, Go to a folder shows its first 500 entries with
  nothing opened, even just after a *Show in its folder* that did not
  finish. Before, when the folder could not be read, or *Show more* or
  another Go came first, the file you had asked for stayed waiting, and
  the next Go to its folder opened that file's row and read the folder on
  to it.
- In Rules › Add a rule, Tab in the path box moves on to Go, the list and
  the rest of the page when there is no name to finish: after Go, on a
  whole name, on a pattern, or when you Tab into the box. Tab still
  finishes a name you are typing, and takes what typing filled in. Before,
  Tab never left the box, so the keyboard could leave it only with
  Shift+Tab. A path ending with `/` is no longer filled in with the name
  its entries share.
- The sessions you are reading stay still on Home (Running now and
  Earlier) and in History when a session starts or ends above them, or a
  count changes. Before, each such change drew the whole list again, and
  the browser could not hold the rows in view still: they moved by a whole
  row.
- A time on the dashboard never breaks between a number and its word.
  History's rows read "running now, started" over "1 minute ago", where
  they read "started 1" over "minute ago", and a time such as "Oct 15,
  15:31 · 2 minutes ago" breaks, if it must, only after the dot.
- A count on the dashboard never breaks from what it counts. A session's
  counts on Home and in History, such as "1 action blocked", and the
  dashboard's sentences on a session's page, such as "in 2 requests.",
  keep the number on the line of its word. Before, a line could end with
  the number alone.
- A command the dashboard names, such as `mandu dashboard` in Settings or
  `mandu paths` under Where your data lives, stays on one line. Before, a
  line could end with `mandu` and put the rest of the command on the next.
  History's empty list now shows its commands as code, as Home does.
- On Rules, in a window 801 to 1000 px wide (half of a 1920 px screen),
  the file lists put each name on its own line and the two menus side by
  side under it, each under its caption. Before, each menu took a line of
  its own, as on a phone, and a rule took about two and a half times the
  height it takes in a wider window. At 800 px and below the menus still
  stack.
- A session's page draws its count tiles in even rows. In a window 614 to
  821 px wide, four tiles sit two by two. Before, one sat alone under three
  (at 720 px, half of a 1440 px screen). Five or six tiles sit three to a
  row from 822 px, where they drew as four and one, or four and two.
- A rule change names a file in your home folder as `~/…`, as Rules does:
  Approvals' requests ("Make `~/proj/.env` a secret no AI may read", and
  what one would let), Approvals › Rule changes, a session's step when
  the AI asked Mandu for a rule change, and the rules Rules › Describe what
  you want suggests. Before, they spelled the whole path out,
  `/home/<you>/proj/.env`, beside a Rules row that said `~/proj/.env`, and
  a suggestion could name the same file both ways. A file outside your
  home folder is still named in full.
- On a phone narrower than 375 px, the dashboard's four page links fit
  their line when requests wait for you: Home, Approvals with its count,
  Rules and Settings sit a little closer together. Before, any count cut
  Settings off at the right edge at 320 to 355 px wide (or a 1280 px
  window zoomed to 400 %), and only scrolling the line sideways showed it.
- A waiting request on Approvals names the secret, its file, the host and
  the program in code under its title, as the title does: *Why it
  stopped*, *What the AI has now* and *If you click Allow* read
  "`STRIPE_KEY` comes from `~/mandu-try/.env`", and Home's short card
  does the same. A name of up to 24 characters stays on one line. Before,
  those lines named them as plain text, and a narrow window broke a path
  at its hyphen ("~/mandu-" at the end of one line, "try/.env" on the
  next).
- The rest of Approvals names things the same way: *What the program
  holds* (a program's send of the secret files it read) names each file,
  the copy it came through and the hosts it may go to in code, as the
  card's title does, and a name of up to 24 characters stays on one line
  there, in *Answered earlier*, in *Rule changes* and on a request to
  change a rule; so do the suggested rules of Rules › *Describe what you
  want*. Before, the hosts were plain text and those names could break at
  a hyphen ("uploads.example-" at the end of one line).
- A rule change that lets a file go to several hosts names each host in
  its own code ("may be sent to `api.github.com`,
  `deploy-hooks.example.com`"), on Approvals and in Rules › *Describe what
  you want*, so a host of up to 24 characters stays on one line and the
  line breaks between hosts; the same for the entries a change adds to or
  removes from a list. Before, the hosts were one block of code that a
  phone broke inside a host ("deploy-" at the end of one line).
- Rules names a file's hosts the same way. In an opened row, *What the
  rules say › May be sent to* names each host in code. The *Per value*
  sentence under a row's second menu names each value and each host in
  code too. A host of up to 24 characters stays on one line. Before, they
  were plain text that a phone broke inside a host ("deploy-" at the end
  of one line). For a file whose values each have their own hosts, *May be
  sent to* now says where each value may go. Before, it said "Nowhere
  without your OK." (true only of a program holding the whole file), while
  the row above said `STRIPE_KEY` may go to `api.stripe.com`.
- A change waiting on the Rules page names its hosts the same way: *Will
  be: … (not saved)* under the file and in its opened row, *Changes to
  save* (the label before and after), *Show the files*, and Save's
  question (*These changes make protection weaker* and *Files that become
  less protected*) name each host and the file in code. A name of up to
  24 characters stays on one line wherever its column is wide enough to
  hold it, and a comma never starts a line. Before, these were plain text
  that broke inside a host even in a wide window ("alerts-" at the end of
  one line).
- A rule change that lets your agent's programs connect somewhere names
  the port, on Approvals, in Rules › *Describe what you want* and on the
  session page: "connect to any address on port 22", "`*.example.org` on
  any port", and *This would let* says the same ("any address on port
  443" when the change named no port; "over UDP" for a UDP one). Before,
  the change said "connect to any address" while the line under it said
  `*:22`, and removing that rule read as `*:2222`.
- Rules › *Programs and connections* names a connection rule in the same
  words: "any address on port `2222`", "`*.example.org` on any port",
  "`10.0.0.0/8:53` over UDP". A named host with its port stays as it was
  (`pypi.org:443`). Before, the row showed the rule as one code (`*:2222`,
  `*.example.org:*`, `10.0.0.0/8:53 (udp)`), unlike the Approvals card
  that asked for it.
- Rules › *Sending data* names what each row covers as code: "sending only
  the file `~/proj/.env`", "sending any masked data from
  `docs.python.org`", and the files a program held. A rule that sends
  anywhere says "anywhere" in words. Before, the file and the sources were
  plain text, unlike the Approvals card that made the answer, and
  "anywhere" was drawn as if it were a host's name.
- On Rules, your answer to a held message ("Send as written for this
  session") is listed under *Sending data* and reads "`acme.codename` in
  your message to the AI". Before, it was listed with your answers about
  files, with a file icon and a *Show in the file browser* link that
  opened nothing useful.
- On Rules, your answer to a held message says what went to the AI:
  "Sent as written" or "Sent masked", and the session's menu offers the
  other. Before, it said *Always allowed* or *Always blocked*, though a
  masked message was sent, not stopped.
- A long file path or host name on a narrow screen now breaks only after
  a slash (a host: after a dot), as in `~/mandu-try/deploy/` over
  `staging.conf`. Before, it often broke at a hyphen inside a folder name
  ("`~/mandu-`" over "`try/…`"), on the session page, Approvals and
  Rules.
- In History, a running session's time reads "running now," over "started
  1 minute ago". Before, it read "running now, started" over "1 minute
  ago".
- On Rules › *Sending data*, a send rule from your rules file has the dot
  your answers have: red for *Always blocked*, green for *Always allowed*.
  Before, the rule's menu had a grey ring, so two rows that both said
  *Always blocked* looked different. An expired rule keeps the grey ring.
- On Rules › *Programs and connections*, a connection your agent may open
  says *Always allowed* in green with a ✓, and a built-in protection your
  rules file sets to Block says *Always blocked* in red with a ✗, as your
  answers beside them are coloured. Before, both were grey, so an
  allowance and a block looked alike.
- On Rules, a long host named by a rule (*Sending data*, *Programs and
  connections*) or under *Who may get your secrets* › Hosts breaks only
  after a dot, as on the rest of the page. Before, it broke at a hyphen:
  "`uploads.a-very-`" over "`long-subdomain-`" at 320 px.
- On a session's page, the folder the agent worked in ("in
  `~/projects/…`", under the title) breaks only after a slash, as the
  files on that page do. Before, it broke at a hyphen:
  "`~/projects/mandu-try/customer-`" over "`portal-backend/services`" at
  390 px.
- On a session's page, a name the agent writes as code in its reply (or
  you in your question) breaks as the page's own names do: a long path or
  address only after a slash, a short name such as `no-model` not at all
  unless it alone is wider than the line. Before, the browser broke it
  anywhere: "`no-`" over "`model`", and
  "`https://api.stripe.com/v1/customer`" over "`s`" at 390 px. Commands
  with spaces and code blocks are drawn as before.
- On a session's page, a command the agent writes as code in its reply
  (or you run with `!`) stays inside its column when it breaks over lines.
  Before, the code's box ran a few pixels past the column's edge on a
  narrow screen (6 px at 320 px wide), drawn over the space at the end of
  a line.
- Headings, labels and notes no longer end with one word alone on their
  last line. Approvals' "If you click Allow once or Always allow" left
  "Allow" alone at 1280 px, and on a phone Settings' notes, History's
  intro and a rule change ended on one word. Where a line may break is
  unchanged.
- On Approvals, a card's time reads "Oct 17, 02:31 · just now", with no
  period after it when nothing follows, as the *Answered earlier* rows
  under it do. A card whose agent has ended, and Home's card before its
  *Details in Approvals* link, keep the period.
- On Rules, in a window wider than 1000 px, a file's *Which AI may read
  it* menu shows its whole choice: "Your own AI only (none listed)" and
  "Any AI, when it asks (inherited)". Before, it was cut ("Your own AI only
  (none li…"), right where it said that no model of yours is listed or that
  the label comes from a folder. That menu's column is 20 px wider and the
  *Where it may be sent* column 20 px narrower, still wide enough for its
  longest choice, so the file name keeps its width.
- In a window wider than 1000 px, an opened row's *What the rules say* on
  Rules (and a found key's *What the scan found*) puts each heading over
  its answer, as a phone does. The box is half the row there, and its
  headings took half the box, so each answer had a column about 25
  characters wide (179 px at 1280 px), narrower than on a phone. Each
  answer now has the box's whole width.
- An opened rule on Rules says its warning once. The warning about a
  reader that prints what it reads (or runs code) was said in full beside
  the rule's controls and again in *What the rules say*, the same words
  twice in one row; the box now leaves out what the row already says.
- History says when a session has a question waiting for you in
  Approvals: "1 question waiting for you", and a running agent that waits
  for your OK gets the amber dot Home gives it. Before, History showed such
  an agent as just "running now" with a green dot, and never mentioned an
  ended session's question that still waited.
- Every text box and menu on the product page now looks like the rest.
  Three were drawn by the browser, square with its grey border and a grey
  box in the dark theme: the folder box and the *Ask a model too* menu in
  Rules › *Keys Mandu found*, and the *Type ALLOW to confirm* box of a
  wide rule change. In *Keys Mandu found*, the list also starts closer
  under the model line (an empty status line took 40 px), and the line
  under the menu reads "Asking a model to suggest rules is not offered
  yet: it is still being tested." in place of a sentence with two colons.
- The product page's secondary lines now read lighter than what they
  explain, as its notes already did: the captions over Your rules'
  patterns and places, where an opened rule comes from, Add a rule's
  "This folder:", the lines under *Keys Mandu found*, an empty list, the
  status of *Describe what you want*, and the foot of a wide rule change
  ("This change has no limit on one side."). They were drawn in the full
  text color. A row's times and counts keep their fainter gray.
- Settings › Prompt filters › Exceptions no longer explains how to write
  an exception when there is nowhere to add one. On a new install the
  only kind Mandu looks for in your messages is a secret it already knows,
  which takes no exception, so there is no add form, yet the page said
  "Use a `*` for any text, as in `*@example.com`." It now says why none
  can be added ("Exceptions are not offered for a secret Mandu already
  knows: the choice above decides what happens to it."), or names your
  administrator's lock when that is the reason. The empty list under that
  reason then reads just "No exceptions.", so it does not repeat the
  reason. With the form, the how-to and the list's own line are unchanged.

License:

- Mandu is now licensed under the Apache License, Version 2.0, in place of
  the AGPL-3.0-or-later the earlier betas carried. Contributions are made
  under the contributor agreement in `CLA.md`.

### New in 0.2.0-beta.5

No security fixes in this build. Fixes:

- Under Codex, sending a protected document to the one site it is
  allowed to go to works again after the agent printed the document with
  a shell command (`cat`): beta.4 blocked that send as if it were a leak.
  A send anywhere else is still blocked.
- If Mandu's background service restarts in the middle of your session,
  the network guard and the network proxy now follow it too. In beta.4
  they kept failing safe until the session ended: a program that had
  read a secret got only the masked copy of every secret file and could
  not write a protected one, and a send you had allowed went out with
  placeholders.
- Home no longer says "Your secrets are guarded." on a busy day when a
  session where protection failed is older than the newest 25: the hero
  turns red for it, and the counts say how many of the day's sessions
  they add up ("In 26 of the 31 sessions in the last 24 hours").

Dashboard:

- The agent page links every "detailed trace" it names, and a link
  about one step opens the developer view at that step.
- Home's counts say they cover the last 24 hours, the number of waiting
  questions is said once, and the hero links the place it names.
  "Protection is off" now points at Settings, where the switch is.
- Approvals shows past answers and rule changes in full instead of
  cutting them to one line, and an answered question links back to
  where the agent asked it.
- Scanning for keys on Rules counts the labelled documents it read,
  names the ones it left unchecked, and links Settings › Sensitivity
  labels; that card links back to Keys Mandu found and says when a scan
  found no label. A link to a card opens the page at that card.
- Settings rows fit their pickers and buttons, a prompt filter exception
  reads as one sentence, a host on Rules is a chip as wide as its name,
  and commands such as `mandu dashboard` are shown as code.
- In the developer view, a system log (such as the admin log a fresh
  install opens first) reads as a log, not as an empty agent session,
  and the step rail lists its entries.

### New in 0.2.0-beta.4

Security fixes. beta.3 has these holes, so update:

- The copy of a `.env` the AI reads no longer carries real bytes in the
  shapes it used to pass through: a quoted value over several lines (a
  PEM key), a value with an escaped quote, a key with `-` or `.` in its
  name, `KEY: value` lines, lines that are not assignments, and a quote
  left open. Single-quoted values, `export`, spacing and comments now
  stay as you wrote them.
- A program that read a secret is watched more closely: a child it forks
  cannot write into its open web tunnel, a pipe it writes cannot be read
  outside Mandu's watch, and it cannot pass the secret on through a
  message queue, an in-memory file (`memfd`), or a network or FUSE mount
  you have not marked trusted (including a file's owner and timestamps
  there).
- Settings files can no longer steer the agent around Mandu: a Claude
  Code settings file that points its model traffic elsewhere, a Goose
  provider Mandu does not route, Codex's own uploads to its cloud, or a
  project's git config or `~/.psqlrc` running code inside a program that
  holds a secret.
- Claude Code's DesignSync tool cannot upload a secret file to
  claude.ai: each file it names is checked, and a secret one waits for
  your OK in Approvals.
- A tool Mandu has no mapping for has its whole result masked; MCP tools
  are recognised when their server's config changes mid-session; every
  git credential helper and git's own transports are treated as printing
  secrets.
- `mandu doctor` and the launch warn when the bubblewrap Mandu uses is
  older than 0.12.0 (CVE-2026-87766), and say how to update it.

New:

- Mandu tells you when a newer release is out, in one line at launch and
  in `mandu doctor`, and says SECURITY when the release fixes leaks.
  `MANDU_UPDATE_CHECK=0` turns it off. It sends one request to GitHub
  with nothing about you or your session.
- Tested with Claude Code 2.1.292 and Codex 0.160, so the "newer than
  tested" warning is gone for both. Codex 0.160 can use Mandu's policy
  tools again.
- Goose and OpenCode 2 are marked *preview*: they work, but are tested
  less than Claude Code and Codex. The launch says so in one line
  (`MANDU_PREVIEW_NOTICE=0` hides it).
- If Mandu's background service restarts in the middle of your session,
  the agent keeps working and your screen shows real values again
  instead of placeholders. If a placeholder ever cannot be shown as its
  value, the session page and the exit message say so.
- `mandu why <file> --to <host>` respects an *Always allow* you gave, and
  says when a change you made to `policy.yaml` is still waiting for
  approval. A waiting change no longer stops the AI from adding a lock.
- Claude Code's "file unchanged" notice is no longer shown to you (or
  the AI) as if it were a masked file.
- `mandu` uses the folder it runs in, even when `$PWD` names another one.
- `mandu doctor` reports the kernel's `ptrace` setting, and the AI is
  told which program Mandu refused to run.

### New in 0.2.0-beta.3

Security fixes. beta.2 has these holes, so update:

- Signed out, the dashboard shows no real value, only what the AI saw:
  each secret as its placeholder, and "Sign in to see real values" where a
  value would be. This covers every page and feed, and also sessions
  recorded before this build. In beta.2 any program on your computer,
  including one your agent runs, could read the real value of every
  masked item the dashboard recorded, from its port, without signing in.
  Signed in, **Show the real value** shows one secret on a click
  ([the dashboard](docs/usage.md#the-dashboard-on-the-network)).
- The dashboard answers only to its own address (`127.0.0.1`,
  `localhost` or `[::1]` at its port), so a web page you visit cannot
  reach it by pointing its own name at your computer. Behind a tunnel or
  a reverse proxy, list the name browsers use in `DASHBOARD_SERVER_NAMES`.
- Mandu's network proxy no longer connects to this computer (loopback,
  `localhost`, `0.0.0.0` or the computer's own addresses). A program the
  agent ran could reach the dashboard, or another local service, through
  it.
- The output of a command you run yourself inside the agent (`!cat …` in
  Claude Code and in Codex) is masked like the agent's own commands.
  Before, a secret file that Mandu had labelled, but whose values were
  never registered, reached the model raw.
- A project's own OpenCode plugins and custom tools (under `.opencode/`)
  do not run in `secrets` mode: they run inside the agent and could copy
  a secret into a model request. `MANDU_OPENCODE_PROJECT_PLUGINS=1` runs
  them, with a warning. When the agent writes to those folders, the write
  waits for your answer.
- Your own OpenCode plugins and custom tools (in `~/.config/opencode/` and
  `~/.opencode/`, and npm plugins such as oh-my-opencode that your global
  `opencode.json` names) do not run in `secrets` mode either, for the same
  reason; the launch names what it left out, and
  `MANDU_OPENCODE_GLOBAL_PLUGINS=1` runs them, with a warning. OpenCode 1
  now starts without plugins instead of refusing (it is refused only where
  a custom tool would load). When the agent changes your OpenCode settings
  files (`opencode.json` and its kin), the change waits for your answer in
  Approvals, so it cannot add a plugin for your next session.

New:

- Goose 1.53.0: `mandu goose` runs a Goose session, and `mandu goose run`
  (also with `--recipe`), `mandu goose review` and `mandu goose acp`, the
  command your editor starts, work too. Goose runs Anthropic and OpenAI
  models. A login saved by `goose configure` works, or the launch says
  why not.
- OpenCode 2 (2.0.23) runs by default beside OpenCode 1;
  `MANDU_OPENCODE2=0` turns it off. In `secrets` mode it runs only where
  Mandu's Linux kernel guards run, and config edits apply at the next
  launch.
- `mandu demo` shows Claude Code and Codex in three short scenes, offline
  and with no key. The AI reads `.env` and gets placeholders. It uses a key
  at the host the key is bound to, and the real value goes in on the way
  out. It tries to send the key elsewhere, and the request is blocked
  before anything leaves.
- A `.env` with a long comment line is masked key by key, no longer as
  one placeholder for the whole file.
- The session page says why a step was blocked or held, and when Mandu
  asked for your OK in Approvals, linking that request. The agent's
  replies show as formatted text, not raw markdown.
- *Your secrets* lists each secret's sends and blocks in time order;
  click a time to open its step. It says when the AI read a secret before
  you marked it, and that the AI's own words about it are not masked.
- The Rules page keeps Discard and Save in view however many changes
  wait.

### New in 0.2.0-beta.2

- [Your first session](docs/first-session.md): a guided tour per agent
  (Claude Code, Codex, OpenClaw, OpenCode) of what the screen and the
  dashboard show.
- The dashboard is yours to answer: each launch, and `mandu dashboard` in
  your own terminal, prints a one-time sign-in link. Before, Allow and Block
  answered "Sign in first" with no way to sign in.
- A secret's placeholder on a command line (`curl -u "$KEY:"`) runs; the
  real value goes in only on the way to a host the secret may go to, or
  after you allow it. An allowed request now reaches the server intact (a
  duplicate `Host` header made servers such as Stripe's answer 400).
- `mandu codex` opens the network of Codex's own command sandbox, so Mandu
  decides where its commands connect (`--no-codex-shell-network` keeps
  Codex's default).
- A binding you add or remove applies at once, also to secrets the AI
  already holds and to running sessions. Before, a removed binding could
  keep letting a secret go to that host.
- The agent is told when output is hidden because its command names a
  secret file, and when an earlier result was hidden after you marked it
  secret, so it no longer guesses or apologises for "inventing" it.
- A value shorter than its placeholder no longer shows with trailing spaces.
- Home counts only agents, shows ended sessions as ended, and names the
  agent that asked; the session page says what the AI actually received at
  each step.

### macOS integration (experimental)

- A whole-agent Seatbelt profile blocks credential-file reads, protects
  Mandu's state and runtime registries, refuses writes to files that run
  later, and applies the TCP-port and Unix-socket lists. The posture remains
  `read-blocked`; committed versions of protected files stay readable.
- Claude Code and Codex's own sandboxes cannot nest inside that profile.
  Mandu disables them for the session only where their settings allow it,
  says so at launch, and preserves explicit or required sandbox choices.
- The BSD terminal relay forwards resize and shutdown signals through a
  companion. Process-tree teardown catches background children it observed;
  a daemon that reparents between samples can still escape.
- Long macOS temporary paths fall back to a short, private, owner-checked
  runtime directory. Registry files and logs refuse planted links.
- Background and launch-preparation git calls use their own Seatbelt
  sandbox where available, with no network, fork or exec beyond git.
  Hardened git ignores xcrun's user-writable cache.
- Home discovery skips large app-data and media folders while preserving
  labelled-file coverage. History-lock warnings and policy previews state
  that history protection holds on Linux only.
- A macOS launch that seals the Mandu home keeps advisory history caches.
  Cache sealing and human-plane isolation are separate claims; an unwalled
  launch still invalidates other sessions' guard attestation.
- Earlier Mac hardware results are recorded in the design docs. This
  combined branch still requires fresh Mac tests before release.

Mandu runs Claude Code, Codex, OpenCode and OpenClaw next to your real keys
and credentials, on Linux, as your user, with no root. The AI works with
placeholders (`$MDU:…`) for your secrets; you, and the programs you name,
still get the real values.

### What it does

- **`mandu claude`, `mandu codex`, `mandu opencode`, `mandu openclaw`** run
  your agent with your credential files and secret environment variables
  replaced by placeholders in the agent's world. The model API, the agent and
  every program it runs see placeholders; nothing carries a secret off the
  machine unless a rule or you allow it. Mandu uses the agent's own login (a
  Claude subscription, a Codex ChatGPT sign-in or an API key) and needs no
  key of its own.
- **Two modes.** `secrets` (the default) protects your credentials; `off`
  only records. `secrets` mode does not mask untrusted text, so it does not
  stop prompt injection. The paper's prompt-injection defense (`injection`,
  `full`) is in the tree, frozen and experimental, behind
  `MANDU_EXPERIMENTAL_INTEGRITY=1`.
- **Who may see a file.** `~/.mandu/policy.yaml` labels any file or folder
  `no-model`, `any-model` (a quarantined helper may summarize it) or
  `local-model` (only a model you run yourself, declared under `models:`,
  reads it). `readers:` names the programs that get the real bytes, and may
  condition a reader on its parent (`{ app: ssh, from: git }`); every other
  program is refused or gets the placeholder copy. A reader's output, the
  files it writes and the connections it opens are tracked: it may send only
  to the hosts its secret is bound to.
- **Secrets go back only where they belong.** The egress proxy puts a
  secret's real value back only in requests to the hosts it is bound to and
  holds anything else for your answer on the dashboard's Approvals page
  (*Allow once*, *Always allow*, *Block*). npm, yarn, pnpm and pip registry
  credentials are released this way without the tools ever holding them.
- **Git history too.** Earlier versions of a protected file in git (any
  branch, the reflog, the stash, the index) are hidden from the programs the
  agent runs, without changing your repository. `mandu doctor --secrets`
  finds keys left in history, and `mandu policy suggest` turns each into a
  rule.
- **Your prompt.** A registered secret you paste into your prompt reaches the
  AI as its placeholder; opt-in filters catch key shapes, personal data and
  your own patterns.
- **Kernel hardening without root, on by default where the kernel allows
  it:** a seccomp guard that serves placeholder copies of credential files
  and checks every connect, Landlock, a no-network command sandbox with its
  own namespaces, and capability dropping. `mandu doctor` reports the
  posture (`confined` or `gated`) and what each layer needs.
- **A dashboard for the person using the agent** (`mandu dashboard`, local
  only): whether you are protected, what each agent read, ran and was stopped
  from doing, Approvals, and your rules with a file browser. The full trace
  is at `/dev/`.
- **`mandu demo`** shows the whole idea offline, with no key; `mandu why
  <file>` says how a file is treated and which rule decided.
- Everything Mandu stores is in one folder, `~/.mandu`, that the agent can
  neither read nor write (`mandu paths` lists every location).

### Platforms and agents

- Linux x64, Ubuntu 24.04 and 26.04 tested, nothing installed as root.
  64-bit ARM Linux is included and checked under emulation, not yet on arm64
  hardware. WSL2 works as Linux and protects Windows-side credential files
  too. macOS is experimental; Windows has no secret protection.
- Tested agent versions are listed in the README and in
  [`supported-agents.md`](docs/design/agents/supported-agents.md); outside
  them a launch prints one warning line.
- OpenCode 1 (npm `opencode-ai`) only: OpenCode 2 (npm `@opencode/cli`) is
  refused at launch, because its background service could send model calls
  around Mandu.
- Node 22.13.0 or newer; `scripts/install.sh` brings its own Node.
- Programs built on the Claude Agent SDK or the Codex SDK run as `mandu
  --target claude|codex -- node app.js`: the agent they start keeps Mandu's
  protection even when the program gives it its own environment, and an
  agent Mandu cannot protect refuses to start. The Python Codex SDK is not
  covered yet ([`agent-sdks.md`](docs/design/agents/agent-sdks.md)).

### Known limitations

What is and is not guaranteed, per mode and posture, is in
[`docs/guarantees.md`](docs/guarantees.md): §3 lists the ways around each
claim that are known (a program you allowed to read a secret can leak it by
encoding, a secret Mandu was never told about reaches the AI as written, the
`gated` posture leaves credential files readable to the agent's programs).
