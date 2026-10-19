# What Mandu guarantees, and what it does not

This page is for the person deciding whether to trust Mandu with a machine
that holds secrets, and for the person auditing that decision. It states each
claim in the form a test asserts it, names the posture and mode the claim
needs, and lists the ways around it that we know of. The design detail
behind each line is in `docs/design/` (pointers at the end).

Two ideas run through everything:

- **A placeholder, not a value.** Data the AI must not read (a registered
  credential, or a file or git object labelled above `public`) reaches it
  only as an opaque token (`$MDU:…`), or not at all. The real value lives in
  a table only Mandu's arbiter can open, and is put back only where the rule
  allows.
- **By construction, not by detection.** Mandu does not scan text for things
  that look like secrets and hope to catch them. It removes the bytes from the
  agent's world at the operating-system chokepoints (the model API, the
  network, the filesystem, program execution) and decides by provenance.

## 1. The modes and the postures

| Mode | Untrusted text is masked from the AI | Your secrets are masked | Default |
|---|---|---|---|
| `secrets` | no | yes | **yes** |
| `off` | no | no (observe only) | |

The product offers these two modes. `injection` and `full` (untrusted text
masked, the paper's prompt-injection defense; `full` also masks secrets) are
frozen and experimental: they run only with `MANDU_EXPERIMENTAL_INTEGRITY=1`
set, every entry point refuses them otherwise, and this page makes no claim
about untrusted text for the product default
([`design/architecture/protection-modes.md §10`](design/architecture/protection-modes.md)). Where a line
below names `full` or `injection`, it describes those frozen modes.

| Secret posture | Where | What holds |
|---|---|---|
| **confined** | Linux with the native guard running (shipped in the package for linux-x64), with the `bwrap` mount as a second layer where the host allows it; a stock Ubuntu 24.04 is confined with no sudo | Raw secret bytes are absent from the agent's world. |
| **read-blocked** | macOS with `sandbox-exec` (every rule proven under `sandbox-exec`, and a live `mandu claude` session run, on macOS 26.5.1, §2a) | Secret files cannot be opened, changed or renamed by the agent or the programs it runs, and Mandu's own state is sealed (§2a). |
| **gated** | Anything else, including `bwrap` without the guard (the guard binary missing, or turned off with `--no-net-guard`) | The AI never sees a registered secret and Mandu gates what leaves, but a program the agent runs can read the file. With `bwrap` alone the mount still puts a placeholder over each credential file found at launch, but a file your system replaces while the agent runs (a token refresh, an editor save) is readable, so it is not called confined. |

`mandu doctor` prints the posture of this machine; `mandu doctor
--secrets` prints exactly which files a launch would mask and which it would
leave raw; every launch prints the mode it really runs in.

## 2. What is guaranteed in `secrets` mode, posture `confined`

Each claim below is asserted by an automated test on the real components,
and the last column names the test that fails if the claim breaks.

| Claim | Holds for | Test |
|---|---|---|
| A registered secret never reaches any model vendor, including the quarantined helper model, in any encoding. The AI sees `$MDU:nomodel_…`. | files the catalog or your labels register; environment variables whose name says secret (the list in [usage](usage.md)) or whose value holds a key in a known format, except the agents' sign-in variables (`ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, `ANTHROPIC_CUSTOM_HEADERS`, which can carry an `Authorization` header, `CLAUDE_CODE_OAUTH_TOKEN`, `OPENAI_API_KEY`, `CODEX_API_KEY`) and Mandu's own `MANDU_*` variables, which are never masked (§3) | `tests/stack/confidentiality-oracle.test.ts`, `protection-modes.test.ts`, `labeled-document-use-cases.test.ts` (a plain document labeled in `policy.yaml`), `tests/stack/env-secret-names-launch.test.ts` (a launch's environment: `PGPASSWORD`, `MYSQL_PWD`, `GITHUB_PAT`, `TF_TOKEN_*`, webhook URLs, a private key in a JSON string, a GitHub key under another name and inside a one-line value over 10,000 characters), the live S1–S6 battery |
| A registered secret value a program printed into a file no label covers (an old application log with its debug lines, a copied config) reaches the AI as its placeholder, and the rest of the text reaches it as written, when the command that read it read no secret itself. Anything Mandu cannot prove clean is hidden from the AI whole, as before: the same text holding the value in another form it looks for (base64, hex or octal, wrapped or in a byte dump such as `od -c` or `xxd`, percent- or JSON-escaped, reversed, rot13, spaced out, or any 8-character piece of it), a piece of a labelled document, a `$MDU` token, a value under 12 characters or a simple one, or a command whose tree read a secret. Forms it does not look for (a hash, compression, base32, base85) are not caught here, as in any other output. | every agent whose model requests go through Mandu's model proxies; values of single-line secrets Mandu registered | `tests/stack/value-only-release.test.ts`, `arbiter` `value-only-release` unit and `value-only-offer` component, the proxies' `value-only-release` unit tests |
| A `claude` the session starts by name (from the shell of `mandu -- bash`, a script, a hook, or the AI's own commands under `mandu claude`) reaches its model only through Mandu's model proxy, whatever its settings files say (your `~/.claude/settings.json`, a project's or one the AI writes during the session) and whatever `ANTHROPIC_BASE_URL` or proxy variable its command line sets; one given a `--settings` file, a cloud provider switch or `ANTHROPIC_UNIX_SOCKET` does not start. So what it reads is masked as the session's own Claude Code's is. A `claude` started by its full path is not routed, but its model calls are refused (next row). | every claude and shell launch where a `claude` is on `PATH` | `tests/stack/nested-claude-route.test.ts` (a nested `claude` under `mandu -- sh` and `mandu claude`, each way of re-pointing it, the refusals, a no-Mandu control; red before 2026-10-18), `launcher` unit `sdk-route` (`claudeShimSpawn` and its parity with `claude-route.ts`), the replay drill with the real Claude Code |
| A program the agent runs reaches a model only through Mandu's model proxy: one that calls the model vendor itself (a `claude` or `codex` started by its full path, with `ANTHROPIC_BASE_URL` removed or pointed at the vendor, an agent SDK's child past Mandu's route) gets its model call refused (403) before anything is sent, and a direct connection to the vendor's host around the egress proxy is refused at connect. Its account, sign-in and usage calls there still pass; the session's own model calls are untouched. | the hosts `api.anthropic.com`, `platform.claude.com`, `api.openai.com` and `chatgpt.com`, in every launch with the egress proxy (on by default) on Linux with the connect guard; with TLS inspection off those hosts are refused whole; without the connect guard, or on macOS, only a program that uses the proxy settings is covered | `tests/stack/model-host-deny.test.ts` (a stand-in `claude` by full path with a hostile environment through the real net-proxy and the launch's environment; red before 2026-10-18), `net-proxy` `model-host-paths` unit and `model-host-deny` e2e (the real curl through TLS inspection), `launcher` unit `model-host-deny`; checked live with the real Claude Code 2.1.302 on 2026-10-18 |
| A program the agent runs that opens a registered secret file gets a placeholder file, never the real file, unless it is on that file's allow-list: the file's own keys with each secret value Mandu recognizes as a placeholder, or one placeholder for the whole file (a value Mandu does not recognize stays as written: §3, "A value Mandu does not recognize in a structured file"). A write such a program makes to the file goes into that placeholder copy: it succeeds, the real file never changes (an open that asks to empty the file included, even one opened only to read), and the change is discarded when the session ends, where Mandu names each file the session changed (§3, "A change to a protected file"). A program on the allow-list writes the real file as it would without Mandu: a rewrite empties it first, so a shorter one (`aws configure` updating `~/.aws/credentials`) leaves nothing of the old content behind it. Its size is the placeholder file's too, whether the program asks the file it opened or the path (`git diff --no-index`, which sizes its read by the path, prints the placeholder file whole); where Mandu could not mount the placeholder over the file, `find -size` and `du` still see the real file's size; a look under another name (a symlink, or a hard link made before the launch) sees the placeholder file's in both postures; the file reached under a new path after the agent renamed a folder above it (`mv ~/.aws ~/.aws2`, a project folder) is still the placeholder file, for the whole session (Mandu holds each protected file by its inode) and in the next sessions (its label follows the folder), but one under a hard link made after the launch by a program outside the agent's tree, where Mandu mounts the placeholder, still sees the real file's size (§3, "Known gaps"). The allow-list names a program by its file (path and hash): a copy the agent made under the same name (an answer in Approvals is for the binary you saw), or the listed program started with a loader or interpreter variable (`LD_PRELOAD`, `PYTHONPATH`, …) that Mandu was not launched with does not count, nor does it when its command line or environment hands it code to run (`git -c alias.x=…`, `GIT_SSH_COMMAND` other than plain ssh, `ssh -o ProxyCommand=…`, `scp -S`, `sftp -b`, `psql -f`, `less +…`, `LESSOPEN`, `sed` with `e`, `tar --to-command`, `rsync -e`). An editor, a debugger or a tracer (`vim`, `emacs`, `gdb`, `strace`, `sqlite3`, …) is treated like a shell: named alone it admits nothing, and so is a renamed copy of any of these programs pinned by path and hash (Mandu recognizes a byte-identical copy of one installed on the machine, and an interpreter by its content: a `pyenv` python or an `nvm` node under any name). An interpreter is named with the script it runs (`{ app: python3, script: /opt/tools/report.py }`): only that file, out of the user's reach (an ACL on it or on a folder above it, or a capability of the user's that overrides file permissions, puts it in reach) and named by its absolute path, with no inline code, no per-user code path (`python3 -I` / `-s`) and no tracer, counts. A reader listed under a parent (`{ app: ssh, from: git }`) counts only when that parent is a program of the session itself, still running: the program that started Mandu (a `python3` or `node` behind an IDE's or a notebook's terminal) is never one. | every program in the agent's process tree, including MCP servers and hooks; static binaries and raw syscalls included (the guard traps `open`, `openat`, `openat2`; `io_uring` and `open_by_handle_at` are refused) | `launcher/test/secret-readers-live.test.sh` (steps 12 to 17: a copy, a preload, a renamed parent, a parent above the session), `tests/sandbox/secret-moved-folder.test.ts` (a folder above the file renamed, guard only: a save over the file before it, the path recreated, an exchange of folders, a move to another filesystem, a labelled file in the next session), `tests/stack/reader-identity.test.ts` (a renamed, pinned host interpreter refused), `arbiter/test/unit/code-runner-copies.test.ts`, `code-runner-content.test.ts` and `secret-readers-live.test.sh` (6f) (an interpreter no hash knows, by its content), `tests/sandbox/guard/script-reader-pin.test.ts` (the interpreter-and-script pin under the real guard), `tests/sandbox/guard/args-code-reader.test.ts` (a reader handed code by its command line, under the real guard), `tests/sandbox/guard/tar-secret.test.ts` and `tests/sandbox/launcher/tar-twin.test.ts` (an archive tar writes holds the placeholder file, never the bytes, unless tar is on the allow-list), `tests/stack/labeled-document-use-cases.test.ts` (the reader verdicts over the real arbiter: listed, unlisted, parent-conditioned, `others: twin`), `tests/sandbox/launcher/launcher-fixture-homes.test.ts`, `interceptors/net-supervisor/tests/guard_integration.rs` (the placeholder file's size, times and inode under a symlink or a hard link of another name, in both postures; a truncating open, read-only too, never empties the real file), `net-supervisor/tests/local_exits_integration.rs` (an allow-listed program's shorter rewrite leaves no stale tail), `tests/sandbox/launcher/hard-link-twin-meta.test.ts` (the same under the real launcher, with the mount), `tests/sandbox/launcher/twin-write-notice.test.ts` (a write lands in the placeholder copy, the real file stays as it was, and the session's end names the file), `tests/stack/labelled-mcp-config-twin.test.ts`, `arbiter/test/unit/secret-extract-lists.test.ts` and `secret-extract-command-lines.test.ts` (the values of a list in a labelled JSON, YAML or TOML config, and command lines in it, through the model-facing Read), the fresh-install VM suite |
| In `~/.ssh/config`, `pip.conf` and `~/.git-credentials` the placeholder copy keeps the file's own text only where the format makes it public (a host, a user, a port, a path, a known relay command), and every other place is a placeholder. A command in `~/.ssh/config` Mandu cannot vouch for (a `ProxyCommand` other than plain `ssh -W` or a known relay, any `LocalCommand`, `RemoteCommand`, `KnownHostsCommand` or `Match exec`) is withheld whole: in its place ssh prints which line of which file was withheld, why, and the way out, never the command's text. | every program in the agent's process tree that is not on the file's allow-list | `arbiter/test/unit/secret-extract.test.ts`, `tests/stack/config-twin-fidelity.test.ts` (real ssh over the twin: the notice reaches the model, no secret does), `tests/sandbox/launcher/twin-format-fidelity.test.ts` (under the real launcher and guard) |
| A program the agent runs cannot read or change anything in Mandu's own folder (`~/.mandu`, or `$MANDU_HOME`): the placeholder table with the real values behind every placeholder, the session history, your settings and rules. So no earlier launch's real values reach it that way. | every program in the agent's process tree | `launcher/test/kernel/own-stores-hidden.test.ts`, `net-supervisor` `guard_integration.rs` `the_whole_home_is_hidden_and_unwritable_but_its_carve_out_is_the_agents` |
| A program on a file's allow-list holds the real bytes, and every one of its exits is confined (the exceptions known today are listed in §3, "Known gaps"): its output reaches the AI as one placeholder (or filtered by the rule its entry on that file gives it, `readers: [{ app: deploy, prints: nothing, output: clear }]`; a rule is about that file only: a program holding another secret file whose entry does not clear it stays masked, and a program-wide `apps:` rule clears nothing), wherever in the tool call it ran (inside a subshell, a command substitution or a brace group too, and in a background subshell that runs it after the call's shell has returned, whose output then masks the result of every call made before it ran, and in two calls with the same command run at once, both of which are then masked, as they are when the report of one call's shell was lost; a tool result Mandu cannot tie to the agent's shell for that call, such as `BashOutput`'s or that of an agent started without a known executable, is masked whole once any program of the session has read a secret raw), it may connect or send only to the hosts the secret is bound to (a connection it opens after reading the file, a datagram it sends to an address, DNS included; a connection it opened before the read refuses the read; a socket handed to it refuses the hand-off if it leads anywhere unbound; a connection another machine opens to it is accepted only from this machine or a bound host, and reset otherwise; on `127.0.0.1` only Mandu's network proxy, which judges the program again on every request it carries, HTTPS included), files it writes inherit the label (a file it already had open for writing when it read the secret too, such as the `out.txt` of `reader > out.txt`) and are closed to the other users of this machine (no group or other permission bits, and no later `chmod` or ACL may add one), it may not write onto a network or FUSE mount (NFS, SMB, sshfs, …, or an overlay whose writable layer is on one) unless the secret is bound to that mount (`mount:<fstype>:<source>`), nor create, rename, link or remove a name there or change a file's length, mode or extended attributes there, nor write to a device other than the terminal and `/dev/null`-like sinks (a serial port, a printer, a USB device), and another program cannot hand it a writable descriptor of such a file or device, nor reach the display server (the clipboard) unless bound and from then on every other program, the AI's own process included, opens such a copy as a placeholder (a program that already holds every source of the copy reads it as is, and from then on the copy's own values, such as a session token it holds that its sources do not, are masked wherever they reach the AI; a copy over 16 MiB it reads as the placeholder too; a program you let read the copy may send it only where every file it was made from may go, as those files' rules stand now): at once in the same session, under a new name after `mv` or `ln` (or after a folder above it moved), and at every later launch (while Mandu's arbiter cannot be reached a file changed in the session is refused rather than read unchecked), a program that reads what it writes into a pipe, a named pipe or a socket pair is confined the same way (in `reader | curl …` curl may connect only where the secret may go; in `reader | tee copy.txt` copy.txt inherits the label; also a program that connects to it after the read, or that it hands a socket-pair or pipe end, and that program's output reaches the AI as a placeholder too; such a program outside the agent's process tree, other than your terminal or whatever reads the agent's own output, makes the read refused, §3), so is a program that has a file or shared memory open or mapped when it writes there (`tail -f` of its log started earlier, a `/dev/shm` object, System V shared memory, a memfd (one it creates after the read too) or an unlinked file it is handed or reopens; one that already holds a connection elsewhere makes the write fail), it cannot send on a message queue, its children inherit the taint (including a child it leaves running in the background after it exits), and no other program may read its memory, its command line or its environment, or trace it (so `ps` lists such a program, and its children, by name without their arguments, as `[name]`, and `pgrep -f` / `pkill -f` do not match them by their arguments). | listed readers Mandu knows keep a file out of what they print (`ssh`, `ssh-add`, also by default for their own files) and the programs your entries vouch for (`prints: nothing`); not `curl`, `scp` or `git`, which print files and get the placeholder copy | `secret-readers-live.test.sh`, `pipe-taint-live.test.sh` (a file opened before the read; a pipeline's next stage), `tests/sandbox/guard/socket-flow.test.ts` (a later command's client of a server that read the secret), `net-supervisor/tests/object_flow_integration.rs` (a file, shared memory and a message queue shared with such a program), `derived-label-live.test.sh` (a reader's copy, moved and linked, and moved with its folder, read and uploaded by other programs in the session and the next), `protection-modes.test.ts` (rules i, ii, iii and the value backstop), `tests/stack/large-file-pieces.test.ts` (a value only a holder's copy holds; a reader cleared for a file over 16 MiB is masked whole), `tests/stack/large-file-egress-prompt.test.ts` (a holder of a file over 16 MiB sends nowhere unbound; its `!cmd` output is masked whole), `reader-output-rule` unit, stack and sandbox tests (a rule cleared for one file never releases another, through the real guard and the production proxy), the guard's live checks, `net-proxy` `https-taint` e2e and `https-taint-parity` (the proxy's HTTPS legs), `tests/sandbox/launcher/https-proxy-taint.test.ts` (a reader's `curl` over the session `HTTPS_PROXY`), `tests/sandbox/guard/call-tree.test.ts` (a reader inside `( … ) | …`, `$( … )`, `{ …; } | …`; an agent spawning its shells as Claude Code does), `tests/stack/call-root-recorder.test.ts`, `net-supervisor/tests/local_exits_integration.rs` (a network or FUSE mount, an overlay over one, names and attributes there, a descriptor handed over, another local user, a device, the display server) |
| npm, yarn and pnpm read the placeholder `~/.npmrc`, not the real file, when every token in it is one npm sends to the registry its own key names (`//registry/:_authToken`, `//registry/:_auth`, and a `//registry/:username` with its `//registry/:_password`) and the session's egress proxy inspects HTTPS. The proxy puts each token or password back only in an HTTPS request to that registry (a password inside the HTTP Basic credential npm builds), and only in its `Authorization` header: the placeholder anywhere else in the request (an `npm publish` document's readme or description, the URL, another header) gets the whole request refused (403); a plain-HTTP request, even to that registry, gets nothing unless the same file declares that registry `http://`. So no program in the agent's tree holds it: `npm` commands and `npx`-launched MCP servers are not tainted by it. An unscoped token, a `_password` that is not base64 of text, a `proxy`/`https-proxy`/`noproxy`/`ca`/`cafile`/client-certificate setting, a registry in `NO_PROXY`, a `.npmrc` other than your home's, or `MANDU_WIRE_TWIN=0` keeps the earlier behavior (npm reads the real file and is confined as a reader). | your home's `~/.npmrc`, in sessions whose egress proxy inspects HTTPS | `arbiter` `npmrc-wire-twin` component and `secret-registry` / `flow-taint` / `secret-extract` unit, `net-proxy` `npmrc-registry-release`, `basic-wire-release` and `wire-credential-position` e2e, `tests/stack/wire-release-restart.test.ts` (across a restart of Mandu's service under the live session), `tests/sandbox/launcher/npmrc-wire-twin.test.ts` (real launcher, guard and proxy, `npx` against a fake registry, a decoy host) |
| A secret's placeholder on a command line stays a placeholder: after the agent sources a placeholder `.env`, a `curl` given `$STRIPE_KEY` as its HTTP Basic user (`-u`) or in `-H "Authorization: Bearer $STRIPE_KEY"` runs with the placeholder in its arguments, never the real value, and the session's egress proxy puts the value in only in an HTTPS request to a host the secret is bound to (HTTP Basic included). Any other host gets nothing: the request waits in Approvals and the program gets a 403. A request that goes around the proxy (`--noproxy`, its own `--proxy`, a raw socket) carries the placeholder. Before 2026-10-05 such a command was refused (exit 77) whatever the host. | `curl`, `wget` and `nc` under the command gate, and the exec box; the value goes in only where the egress proxy inspects HTTPS | `arbiter` `secret-egress` unit (exec), `exec-wrap` gate unit, `launcher.exec-wrap-live` and `exec-box-live` (the argv and the destination get the placeholder, never the value), `tests/sandbox/launcher/secret-placeholder-argv.test.ts` (real launcher, guard, command gate and inspecting proxy: the bound host gets the value, an unbound one nothing, no recorded argv holds it) |
| pip reads a private index's password from `pip.conf` or `PIP_INDEX_URL` as a placeholder, and the egress proxy puts the real password back, inside the HTTP Basic credential pip builds, only in a request to the host that index URL names, only in that request's `Authorization` header (the same placeholder in an upload's body, the URL or another header gets the request refused), and only over the URL's own scheme: an `https://` index's password never in a plain-HTTP request, even to that host. An index on an IPv6 address is matched as an address, however it is written, and one with a zone id releases nothing. The placeholder sent anywhere else is refused, and a `pip.conf` the agent can write (one outside your home) releases nothing. | `index-url` / `extra-index-url` in your home's `~/.config/pip/pip.conf` or `~/.pip/pip.conf`, and the `PIP_INDEX_URL` / `PIP_EXTRA_INDEX_URL` you launch with, on `http(s)://` URLs, through the egress proxy | `secret-extract` / `secret-registry` unit, `net-proxy` `basic-wire-release` e2e (with real pip where installed) and `wire-credential-position` e2e (the TLS-inspected leg: the password in an upload's body gets a 403), `tests/stack/pip-ipv6-wire-release.test.ts` (IPv6-literal indexes through the real proxy), `tests/sandbox/launcher/pip-wire-twin.test.ts` (real launcher, guard and proxy, a fake index and a decoy host) |
| A registered secret you paste into your own prompt reaches the AI as its placeholder (the same `$MDU:nomodel_…` it has everywhere else), and so does one inside text the agent's harness adds to your turn (a reminder, a pasted command's output, a fetched page it summarizes on its own). In your own typed text a short or simple value (under 12 characters, or as repetitive as `postgres`) is left as you typed it, so a registered `DB_PASSWORD=postgres` does not hide the word "postgres"; in text the harness added it is still masked. A file is matched by its lines and credential-looking words up to 16 MiB and 65,536 of them; a line you paste from past that point is not masked (the output of a program that read such a file, as a tool result or a `!cmd`, is masked whole; a hook's output gets only the line-and-word check, whatever file it read). You still see the original in your terminal. Your prompt is otherwise sent as you typed it: nothing else in it is masked. | Claude Code, Codex, OpenClaw and OpenCode, on every wire their model proxy reads; files and environment variables Mandu registered | `tests/stack/prompt-filter-ingress.test.ts` (each agent family through its real proxy), `web-fetch-secret-ingress.test.ts` (the fetched-page summary), the proxies' `prompt-filter` unit and component tests, `arbiter` `filter-prompt-op` |
| Under `mandu goose`, Goose's saved key (`secrets.yaml`) is a placeholder in the agent's world: Goose sends the placeholder, and the model proxy puts the real key back only in the `x-api-key` or `Authorization: Bearer` header of the request it sends to the provider the launch routes (Anthropic's or OpenAI's own API host, or a model server on this machine). The request body, and so the AI, keeps the placeholder; toward any other host the placeholder is sent, and the provider refuses it. A program the agent runs can make requests through the proxy with the key, but cannot read it. | Goose 1.53.0 on its anthropic and openai providers, a key saved in `secrets.yaml`; a provider on another host, or `MANDU_AUTH_SUBSTITUTION=0`, keeps the real file readable to Goose (its values still reach the AI only as placeholders) | `tests/stack/auth-substitution.test.ts`, `launcher` `goose-auth-substitution` (the real goose), `anthropic-proxy` `auth-substitution`, `arbiter` `auth-grant` |
| Another AI agent's login file is a credential file like any other in a session that does not run that agent: under `mandu claude` (or a plain command), Codex's `~/.codex/auth.json` is a placeholder copy to every program the agent runs, and its key is known to the egress proxy, which refuses it to any host it is not bound to; under `mandu codex`, so are Claude Code's `~/.claude.json` (which holds your MCP servers' tokens) and `~/.claude/.credentials.json`. The login of the agent you launched stays readable to it, and that session's egress proxy lets it reach the agent's own services even after another session registered it (§3, "The AI agents' own files"). `MANDU_OTHER_AGENT_LOGINS=raw` leaves another agent's login readable and usable in the session too, its values still masked for the AI. | Claude Code's, Codex's and OpenCode's login files at their usual places, and where the launch's `CLAUDE_CONFIG_DIR`, `CODEX_HOME` or `XDG_DATA_HOME` move them | `arbiter/test/unit/agent-login-discovery.test.ts`, `tests/stack/other-agent-logins.test.ts` (the real arbiter: the placeholder copy, the egress check per session, the opt-out, a moved `CODEX_HOME`), `tests/stack/own-login-net-proxy.test.ts` (the real egress proxy per session), `tests/sandbox/launcher/other-agent-logins.test.ts` (the real launcher: a shell launch and a codex launch, each sending Codex's token out) |
| Under `mandu goose`, a model provider Mandu does not route receives nothing from the session. A launch that names one is refused; a switch to one during the session (`/model --provider <name>`) reaches only Mandu's refusal: every endpoint setting of every such provider points there, and the provider hosts no setting moves are refused by the egress proxy. A provider of your own (`custom_providers`) whose address Mandu cannot fence refuses the launch. Goose's LiteLLM, OpenRouter, Ollama, xAI and Tetrate providers are routed through the model proxy like Anthropic and OpenAI: what the session's tools read reaches them only as placeholders, and a tool call an Ollama model writes as text is cut off before Goose can run it. | Goose 1.53.0: its built-in and bundled providers, and your own declarative providers | `tests/stack/goose-provider-fence.test.ts`, `tests/stack/goose-compat-providers.test.ts`, `launcher` `goose-provider-fence`, `goose-compat-real` |
| A placeholder is put back into an outgoing request only at a host the secret is bound to, and at the port a binding names when it names one (a binding with no port admits every port of its host). Anywhere else the request is held for your OK, or blocked if you said so. A registry or index credential Mandu reads from `~/.npmrc`, `pip.conf` or `PIP_INDEX_URL` is put back only over HTTPS unless its own declared URL is `http://`, and only in the request's `Authorization` header unless you bound that host to it yourself (§3), and no approval changes either. | HTTP and HTTPS through the egress proxy (HTTPS needs the per-session certificate the proxy installs for the agent's tools) | `net-proxy` e2e (`wire-credential-position`), `tests/stack/inspected-leg-port.test.ts` (the port, on every leg), `wire-release` live check |
| On a fresh install (no binding of yours), a key whose own format names the service that issued it (a Stripe `sk_live_`/`sk_test_`/`rk_…` key, a GitHub `ghp_`/`github_pat_` token, a Notion `ntn_` token, an OpenAI `sk-proj-` key, a Slack `xoxb-`/`xoxp-` token, an npm `npm_` token, a PyPI `pypi-` token, a Hugging Face `hf_` token, a SendGrid `SG.` key) is put back with no Approvals card only in an HTTPS request to that issuer's own API host, named exactly (`api.stripe.com`, never `api.stripe.com.evil.io`, `api-stripe.com`, `stripe.com` or a host under it), and only in the request's `Authorization` header: the same key anywhere else in that request, at another host, over plain HTTP, or a copy of it, waits for your OK as before. Only a value from your own credential file or a masked environment variable counts (not a file the AI's session wrote, not a commented-out line). `issuer_bindings: false` in policy.yaml turns it off (`issuers_off:` and `values_off:` for one issuer or one value), and an answer you gave (a Block) still wins. | the issuers and hosts listed in [`design/confidentiality/confidentiality.md`](design/confidentiality/confidentiality.md) §2.3, through the egress proxy with HTTPS inspection | `arbiter` `issuer-bindings` unit (the table, lookalike hosts and values, the switch) and `issuer-bindings-gate` component (the real gate), `tests/stack/issuer-bindings-egress.test.ts` (a `.env` Stripe key through the real egress proxy: Stripe gets it in the header, every lookalike host, the body, plain HTTP and the file's other value get nothing) |
| A file a tool uploads by its path, without the AI reading it, leaves only when it is not a secret file (or is one bound to every host the tool sends it to: Claude Code's uploads present as `claude.ai` and send the bytes to `api.anthropic.com`, so a binding names both), holds none of your registered secret values, and Mandu could read it to check; otherwise the whole call is refused and held for your OK. An upload that comes after another call of the same turn that could change files (a shell, a write) is refused until the AI makes it on its own, since the file is checked when the call is made. A placeholder in the text the call sends is never put back (the call is refused), and a session that read a secret into the AI uploads only with your OK. If Mandu cannot place the file (a plan with no absolute folder, a path relative to the agent's working folder) or check it, nothing is sent. A tool Mandu has not mapped is not given a path to a secret file, to a file holding one of your registered values, or to a file Mandu cannot read: the path is changed to one that names no file and held for your OK, and the rest of the call goes as the AI wrote it. | Claude Code's `DesignSync` (claude.ai/design, Claude Code 2.1.292) and, in interactive sessions, `Artifact` (a page and its files published to claude.ai) and `ArtifactData` (a document written from a local JSON file), with `ArtifactComments` replies through the same placeholder and session checks; OpenClaw's `message` (a file attached to a chat channel send, by any of the fields OpenClaw reads one from, `attachments` included: no binding can name a chat channel, so a secret file is always held for your OK), `browser` uploads, and `view_image`, `image`, `pdf` and the media generators (a file loaded into a model: one labelled `any-model` goes, a `local-model` or `no-model` one is held); a file a `MEDIA:` line of the AI's own reply names, which OpenClaw attaches when it sends the reply to a chat (checked like `message`'s; held when the same reply also calls a tool; a spot where OpenClaw's markup stripping would form such a line is broken); every tool Mandu has not mapped (an MCP server's, a claude.ai connector's file attachment, a tool a new agent release adds), on every agent Mandu supports (on Codex since 2026-10-17: its MCP tools, called directly or from a code-mode cell), by each local path in its input (absolute, `~/`, `file://`; a relative one under a path-like key, against the launch folder, Codex's session folder on Codex), except a tool of an MCP server the launch registered as a local program in a `confined` session (the guard confines that program); on every posture (the check is on the model wire) | `tests/stack/design-sync-upload.test.ts`, `tests/stack/artifact-upload.test.ts`, `tests/stack/unmapped-upload.test.ts` (an unmapped MCP upload, a Bash then an upload in one turn, a page bound to `claude.ai` only), `tests/stack/openclaw-local-file-senders.test.ts` (a registered `.env`, a copy of its key and a labelled file attached every way OpenClaw reads one, directly and through Tool Search; a model-bound image by its level), `tests/stack/openclaw-media-lines.test.ts` (a registered `.env` and a labelled file named on a reply's `MEDIA:` line by every spelling, split per character, behind markup, beside a tool call; the buffered answer), `tests/stack/codex-unmapped-upload.test.ts` (Codex: a namespaced MCP upload, an `exec_command` then an upload in one response, an MCP call in a code cell, the production adapter on the human socket), `anthropic-proxy` `design-sync-upload`, `upload-gate`, `openclaw-upload`, `reply-media`, `reply-media-route` and `unmapped-upload`, `openai-proxy` `unmapped-upload`, `arbiter` `file-upload` |
| The agent cannot reach a cloud metadata endpoint (`169.254.169.254` and the other cloud credential addresses) or any other link-local address except for DNS, so it cannot fetch the machine's cloud credentials. This holds under every allow rule, including the default "any host on 443". | direct connections the guard traps, and HTTP and HTTPS through the egress proxy, including names that resolve there; off only with `MANDU_NET_ALLOW_METADATA=1` | net-proxy `blocked-destinations` unit + e2e, `net-supervisor` `guard_integration.rs` (kernel) |
| Mandu's egress proxy never fetches anything from this machine for the agent: a request through it to `127.0.0.1`, `localhost`, `[::1]`, `0.0.0.0`, any other loopback spelling, this machine's own network addresses (on Linux including those of an interface that is down and a `local` route), or a name that resolves to one of them is refused, so the proxy cannot be used to reach the Mandu dashboard or any other service listening on this machine. A program that wants a local service connects to it directly, where the connect guard decides. | HTTP and HTTPS through the egress proxy, in every mode, with no opt-out | net-proxy `this-machine` unit + e2e, `tests/stack/net-proxy-local-only-ipv6.test.ts`, `tests/sandbox/dashboard-via-net-proxy.test.ts` (the real launcher, guard and proxy against a real dashboard) |
| OpenClaw's `web_fetch` goes through Mandu's egress proxy like a program's request: its gate, its HTTPS inspection and its check for a registered secret's raw value judge it, and a raw secret value in the URL or the body is refused. From OpenClaw 2026.9.6 every other request OpenClaw itself makes to the web (a media tool loading an image URL, a PDF URL) goes through it too. Before 2026.5.3 OpenClaw cannot send `web_fetch` through a proxy, so under Mandu it is off and the launch says so. (Until 2026-10-09 OpenClaw connected to the web itself, around the egress proxy, and only the check of the AI's tool call judged the URL.) | OpenClaw 2026.5.3 and later (`web_fetch`), 2026.9.6 and later (all of OpenClaw's own web requests); `http://` and `https://` URLs | launcher `agent-config` unit (each release), net-proxy `plain-http-tunnel` e2e, `tests/stack/openclaw-web-egress.test.ts` (the real launcher and OpenClaw, scripted model) |
| A secret that arrives from an untrusted source is both untrusted and secret: it is never released without a human decision. | the frozen `full` mode only (in `secrets` mode nothing is marked untrusted, and the other rows of this table apply) | `confidentiality-oracle.test.ts` (the untrusted × secret cell) |
| A file labeled `local-model` is read by no model except one you declared `local: true` under `models:` in `policy.yaml`. The AI sees `$MDU:localmodel_…`; the quarantined helper sends the file to your declared model and nowhere else, and its answer comes back as `$MDU:localmodel_…` too. The AI's own model reads it only when that model is itself one you declared `local: true` and you launched the AI pointed at it (`ANTHROPIC_BASE_URL`, or `MANDU_OPENAI_BASE_URL` for Codex, equal to the entry's `url`); every other main model is refused, even with your approval. With no model declared, no model reads it. When your declared model is unreachable (not running, timing out, answering with an error or nonsense), the helper refuses and says so; it never falls back to its default outside model. On Linux 6.7 or later the helper also runs under a kernel network confine: it can connect only to your declared local models and to its own default model's relay (or port 443 when no relay runs), not to Mandu's model proxy or egress proxy. | the quarantined helper (`inspect_symbol`); the AI's main model when it is your declared local model | inspect-mcp `local-endpoint-unreachable` unit and the unreachable-endpoint legs of `local-endpoint-routing` e2e (closed port, 5xx, no answer, garbage, both wires), launcher `inspect-mcp-confine` e2e (the helper's kernel confine, under the connect guard too), `net-supervisor` `guard_integration.rs` (kernel: a program's own TCP sandbox holds for the connects the guard performs), `arbiter/test/component/cleared-model-endpoints.test.ts`, `arbiter/test/component/session-upstream.test.ts` (the main model recorded once per session, forged and late claims refused), `tests/stack/local-main-model.test.ts`, `tests/stack/cleared-endpoint-parity.test.ts` (production wiring, three model servers on real wires), `labeled-document-use-cases.test.ts` (use cases 3 and 4), `confidentiality-oracle.test.ts` (no model declared), inspect-mcp `local-endpoint-routing` e2e, `arbiter/test/component/cloud-backed-local-model.test.ts` and anthropic-proxy `cloud-model-local-upstream` e2e (a cloud model is never your local model), `tests/stack/plain-http-local-endpoint.test.ts` and `model-placement-parity.test.ts` (plain http to another machine refused unless `allow_plain_http`, plan 12 D2), inspect-mcp `endpoint-tls` e2e, both proxies' `upstream-tls` e2e, `tls-endpoint-wiring.test.ts` and `endpoint-tls-parity.test.ts` (`tls:` checks: a private CA, pins, mutual TLS; a refusal sends nothing, plan 12 D3), `tests/sandbox/perimeter-netns.test.ts` (plan 12 D4 across a real network boundary in unprivileged namespaces: a name resolving outside `perimeter.networks`, or with one address outside, is refused by the launch, the helper and the model proxy with zero requests), `tests/stack/admin-model-layer.test.ts` and `arbiter/test/unit/admin-layer.test.ts` (plan 12 D5: the administrator's locked models; Settings, a proposal and a raw apply are refused, removal and an outside model pass; a lock that arrives under a running arbiter wins, the helper moves to the administrator's model and nothing reaches the user's) |
| The human always sees the real values in the terminal, the same way for every secret source (a `.env` value, a credential-file key, a masked environment variable). The dashboard's product page shows an original on a click, and never a secret's value. | all | `tests/stack/reply-filter-secret-render.test.ts`, reply-filter e2e and live checks |
| If Mandu's arbiter cannot be reached, nothing falls through to raw: the launch refuses, an egress stays symbolic, a masked result stays masked. | all | every package's fail-closed e2e |
| After the AI reads a secret's content into the conversation (`declassify_symbol`), its session reaches only the hosts that content is bound to. Any other web request and every shell command is stopped and waits for you in Approvals, on a card naming what the session read and the host or the exact command: *Allow once* lets one request, or one run of that command, through; *Block* holds for the session; no answer, or an arbiter that cannot be reached, is a refusal; an answer never covers another session. An allowed command (any command of that session) runs as a program that read that content does: it may connect only to the hosts the content is bound to, and the files it writes are marked secret at its level, so the next session reads them masked; its own output still reaches the AI, which already holds the content. Without the guard (any posture but `confined`) the card says the command is not held: it runs with the network your agent's commands normally have and its files are not marked. A held command's connection to another host is stopped and asks you on the session's card for that host: *Allow once* lets the next try (the command run again) connect there once. | agents whose model calls pass Mandu's model proxy; the command's hold on `confined` hosts | `tests/stack/high-session-approvals.test.ts`, `arbiter` `session-approvals` and `session-exec-taint` (unit and component), `tests/sandbox/guard/high-session-command.test.ts` (the real guard: the bound listener answers, another is refused and asks, after Allow once the retry connects and the third try is refused, the written file is labeled), the proxies' parity test |

Two guarantees that are stronger than they sound:

- **"Never reaches the vendor" includes our own helper model.** The quarantined
  model that summarizes data for the AI is also a vendor endpoint,
  and a `no-model` file is refused there too. A file you label
  `any-model` may be summarized inside that quarantine; the summary
  comes back as a placeholder.
- **Placeholder files keep their structure.** `. ./.env` works, a program
  finds its file where it looks for it, a script that lists variable names
  lists them. Each secret value Mandu recognizes is a placeholder; a value
  it does not recognize stays as written (§3 says which).

With the confidentiality axis on (`secrets`, and the frozen `full`) and the guard running,
the agent's programs reach only the Unix sockets on a short list (Mandu,
name service, logging, the ssh and gpg agents, the Wayland and X11 displays)
and the ones they open themselves. The host services that run a program on
request, and so could read your real files outside Mandu (`systemd-run
--user`, the D-Bus session bus, docker, a tmux server), are refused
([exec-routing.md §4.3](design/integrity/exec-routing.md)). Sockets you list under
`unix_sockets:` in `policy.yaml` are added; adding one loosens the rules, so
a hand edit that does waits for your OK. Test:
`tests/sandbox/unix-allow-list.test.ts`.

In every mode but `off`, with the guard running (every `confined` host):

- **The agent cannot change Mandu's own files.** Its programs cannot write,
  rename, delete, link or truncate anything in Mandu's folder (`~/.mandu`)
  or its installed program: the policy, the persisted approvals and the
  binaries the next launch runs stay yours
  ([write-protection.md](design/architecture/write-protection.md)).
- **The agent cannot impersonate Mandu.** Its programs cannot remove or
  replace the arbiter's socket, or bind one where the interceptors dial, so
  no program it runs can answer for Mandu. Where the bind layer is up, its
  programs also live in a process namespace of their own: they cannot see
  or signal the arbiter, the proxies or any other program of yours (and
  what they start in the background ends with the session). Where the
  guard alone protects your files, a program can still stop the arbiter,
  which blocks what it gates rather than letting it through. Test:
  `tests/sandbox/wrap-pid-namespace.test.ts`.
- **The agent cannot change Mandu's records in its runtime folder.** The
  arbiter's instance records and its `current` link, the dashboards' and
  test VMs' registries, `mandu dashboard`'s log and port files, Mandu's logs
  there and the human plane's folder, in the session's runtime folder and
  in your account's default one, cannot be written, replaced, linked or
  removed by its programs, and the runtime folder itself cannot be renamed:
  the agent cannot leave a forged record or a link there for a Mandu
  program to act on. It can still make an empty folder at one of those
  names, which can only make a later Mandu start fail. The rest of the
  runtime folder, which holds the session's own folder, stays writable.
  `MANDU_WRITE_PROTECT=0` turns this off with the rest of the list. Test:
  `tests/sandbox/write-protect-registry.test.ts`.
- **The agent cannot type into its own terminal.** `TIOCSTI` and
  `TIOCLINUX` are refused to its programs, whatever the kernel's own setting.
- **A file that runs later waits for you.** A change to a shell startup
  file, a systemd user unit, an autostart entry, a user environment file,
  `~/.ssh/authorized_keys` or `~/.ssh/config` (and every file ssh reads
  through its `Include` lines), your git settings, the
  workspace repository's hooks, an OpenCode plugin or custom tool folder
  (`plugin`, `plugins`, `tool`, `tools` in `~/.config/opencode`,
  `$OPENCODE_CONFIG_DIR`, `~/.opencode` and the workspace's `.opencode`
  folders up to the repository root), or one of your OpenCode settings
  files that can name a plugin (`opencode.json`, `opencode.jsonc`,
  `config.json`, `tui.json`, `tui.jsonc` in those three folders of yours,
  and your `OPENCODE_CONFIG` file), and moving or replacing a folder above
  one of them (`mv ~/.ssh ~/.ssh.old`, since 2026-10-07), is held while the dashboard's Approvals page asks you; no answer
  within a minute is a refusal. Your answer is about that one program file
  (its path and contents): a copy or a rebuild with the same name is asked
  again, and the program run with code the agent could have planted in it
  (`LD_PRELOAD` and the like) is refused without asking.
  `write_protect:` in `policy.yaml` adds files to refuse or to ask about,
  and can drop one of these from the list (a loosening, so a hand edit that
  does waits for your OK); Mandu's own files can never be dropped.
  Test: `tests/sandbox/write-protect.test.ts`,
  `tests/sandbox/guard/ssh-config-write-protect.test.ts` (an ssh include
  and the folder above it, under the real guard),
  `tests/stack/writer-identity.test.ts`,
  `guard_integration.rs` `guard_refuses_changes_under_write_protected_paths`.

## 2a. What holds on macOS, posture `read-blocked`

macOS has no mount namespaces and no guard, so the agent runs under one
Seatbelt profile that the kernel enforces on it and everything it starts
([confidentiality.md §7.3](design/confidentiality/confidentiality.md)). The model-side rows of
§2 (placeholders on the wire, release only at a bound host, the reply filter,
fail-closed without the arbiter) hold the same; the file and process rows
read as follows. Test: `launcher/test/darwin/seatbelt-live.test.ts` runs each
rule under `sandbox-exec` and a full `mandu --target shell` launch against a
real arbiter; `launcher/test/unit/seatbelt-profile.test.ts` pins the profile;
`launcher/test/darwin/git-sandbox-live.test.ts` runs Mandu's own git sandbox
(the last row) for real.
The profile is applied by `/usr/bin/sandbox-exec` and the terminal relay runs
`/usr/bin/script`, each named by its full path: a program of the same name
that the agent puts in a folder on your `PATH` (`~/.local/bin`) is never run
in their place, in this session or a later one.

| Claim | Mode |
|---|---|
| A credential file Mandu found cannot be read by the agent or any program it runs (the read fails; no placeholder). It cannot be written, truncated, replaced, linked, cloned or renamed, and no folder above it can be renamed or removed, so it cannot be moved to a name the rule does not cover. The home walk does not look inside `~/Library`, `~/.Trash`, `~/Pictures`, `~/Music` or `~/Movies` (§3, "Unregistered secrets"): label a file there to block it. | `secrets` |
| Mandu's own state cannot be read or changed by the agent or any program running under the profile: the symbol database (which holds registered values), the event log, the shadow repositories, the git-history caches; Mandu's config and install directories cannot be changed. A launch whose profile seals the whole home this way (with write-protect, the socket list and the human-plane wall on) is counted as protected for those caches, in `secrets` and the frozen `full`, so its end does not void them (confidentiality-plan-14 §11.3). Code a system service runs outside the profile is not covered (§3, "Services reached over Mach or XPC"). | `secrets` |
| Mandu's own files and the files that run later (shell startup files, `~/Library/LaunchAgents`, ssh and git settings, the workspace repository's hooks, the per-user cache that tells Apple's `/usr/bin/git` which git to run) cannot be changed. There is no Inbox hold on macOS: a change is refused. `MANDU_WRITE_PROTECT=0` opts out. | every mode but `off` |
| Mandu's records in its runtime folder (the arbiter's instance records and its `current` link, the dashboards' and test VMs' registries, `mandu dashboard`'s log and port files, Mandu's logs there), in the session's runtime folder and in your account's default one, cannot be changed: the agent cannot leave a forged record there, or a link there for a Mandu program outside the profile to write through. The arbiter stays reachable. The rest of the runtime folder, which holds the session's own folder, stays writable, and another session's folder there is not covered (§3). | every mode but `off` |
| TCP connects only to the landlock-net port set (Mandu's model proxy, egress proxy and helper relay on loopback only, a declared local model's port, and 443 and 22 unless `--landlock-net-strict`); a TCP listen only on `--landlock-net-bind` ports. UDP and name lookups are untouched. | every mode (`--no-landlock-net` opts out) |
| Unix sockets only on a short list (Mandu's runtime and session directories, mDNSResponder, syslog, the ssh and gpg agents, X11, the workspace); docker and its kin, a host tmux server, and the control sockets of WezTerm, iTerm2, kitty and an Emacs server are refused even inside an allowed folder. The workspace counts as a whole: a launch from your home folder admits every other socket under it (§3). | `secrets` (`MANDU_UNIX_POLICY=0` opts out) |
| `open`, `osascript`, `launchctl`, `crontab`, `at` and `batch` cannot run and Apple Events are refused: each hands work to a service that runs it outside the profile. | with the socket list |
| Mandu's background and launch-prep git (the launcher's launch-prep runner, which on macOS checks whether a credential file is committed or a locked version is held; the arbiter's history scan and lock resolver), reading a repository the agent can write, runs under a Seatbelt profile of its own wherever `/usr/bin/sandbox-exec` can run the git it finds: no program the repository names can start (no other program at all), no network, and no write but the cache it builds. Probe-gated: where it cannot (no Command Line Tools, a `git` on your `PATH` the profile cannot run), that git runs with its forced settings only, and `mandu doctor` says why. Mandu's other git calls (the net guard's read of the remotes, the working-copy probe, `mandu doctor`, the arbiter's version check, the dashboard, fs-sync) are hardened only, never sandboxed. Mandu's git profile is never nested in the agent's; a `mandu` command the agent itself runs gets no git profile (macOS cannot nest one) and is confined by the agent's profile instead. `MANDU_GIT_SANDBOX=0` turns the git profile off. | `secrets` |

## 3. What is not guaranteed

- **The X11 display.** It is on the socket list by the user's choice, and X11
  lets any program that can reach the display type into other windows,
  including a terminal outside Mandu. Wayland does not. Remove it with
  `MANDU_UNIX_POLICY=0` plus your own list (`unix_sockets:` in
  `policy.yaml`, or `MANDU_UNIX_ALLOW`), or run without a display.
- **A host service on loopback TCP, with the network layer off.** A local
  service that runs model calls and tools for whoever connects, such as
  OpenCode 2's background service (`opencode service`), is outside every
  Mandu confinement. The agent's programs cannot reach it while landlock-net
  or the net guard is on (they admit only Mandu's own loopback ports). With
  both off (`--no-kernel`, `--no-landlock-net` with `--no-net-guard`, or a
  host where both degrade), an `opencode run` the agent starts joins that
  service: its model calls skip the proxy and its tools read the real files
  ([supported-agents.md §2.3.1](design/agents/supported-agents.md)). The
  same holds for the private server every OpenCode 2 session gets: with the
  net guard on, only OpenCode's own client process reaches it; with it off,
  any program can. So OpenCode 2 runs in
  `secrets` only with the guard (and the write-protect guard and its config
  lockdown) in force, and is refused otherwise; mode `off` keeps nothing
  from the model.
- **OpenClaw's media fetches before 2026.9.6.** On OpenClaw 2026.5.3 to
  2026.9.5 `web_fetch` goes through the egress proxy, but the image, PDF and
  media tools still load a URL reference by connecting to the web
  themselves, around it: only the check of the AI's tool call judges that
  URL (a placeholder in it is refused there), and Mandu's kernel layer lets
  any host on port 443 through by default. OpenClaw 2026.9.6 and later send
  those through the egress proxy too
  ([supported-agents.md §2.1](design/agents/supported-agents.md)).
- **Code you install into the agent itself.** Mandu checks what the agent
  reports: tool results, your typed text, what leaves on the network. A
  plugin that runs inside the agent's own process (an OpenCode plugin or
  custom tool) writes the request to the AI itself, so it can put anything
  the agent process holds into it (the system prompt, a tool's result),
  including what Mandu masks only on its way to the AI: a program's output
  from your `readers:` list, and the logins the agent's world reads raw
  (OpenCode's `auth.json`, and Claude Code's `~/.claude/.credentials.json`
  and `~/.claude.json`, which holds your MCP servers' tokens, while Mandu's
  AI helper runs `claude`: neither `ANTHROPIC_API_KEY` nor
  `MANDU_ULLM_API_KEY` set, and no `--no-mcp`; another agent's login, such
  as Codex's `~/.codex/auth.json`, is only a placeholder copy there). In
  `secrets` mode Mandu runs no such code by default, neither what a project brings nor your own
  (the plugins and custom tools in `~/.config/opencode` and `~/.opencode`,
  and the npm plugins your global `opencode.json` names, such as
  oh-my-opencode): OpenCode 2 starts without them; OpenCode 1 starts with
  its own "no external plugins" switch (`OPENCODE_PURE=1`), and is refused,
  naming the files, only where a custom tool would load (the switch does
  not cover tools). The launch names what it left out. A change the agent
  makes to those folders or to your OpenCode settings files waits for your
  OK (§2). `MANDU_OPENCODE_PROJECT_PLUGINS=1` runs a project's and
  `MANDU_OPENCODE_GLOBAL_PLUGINS=1` your own, each with a warning, and then
  that code is unchecked: what it puts into a request is not read, and on
  OpenCode 2 a plugin runs inside the session's server, which Mandu treats
  as the agent's own process, so it can also send what that process holds
  out on port 443. The npm plugin packages OpenCode keeps in its cache
  (`~/.cache/opencode`) are not held: a change there runs only where you
  run the plugin (with the opt-in, or OpenCode outside Mandu)
  ([supported-agents.md §2.3 items 11 and 12](design/agents/supported-agents.md)).
- **Every file that runs later.** The write-protect list covers the common
  ones (see §2), not all: a repository's `.git/config` and Claude Code's
  `~/.claude/settings.json` are left writable on purpose (the agent and
  Claude Code write them in ordinary work), and both can name a program
  that runs later (`core.hooksPath`, `core.fsmonitor`, a hook, from git
  2.54 also a hook named in the config itself) when YOU next
  run git or Claude Code there. In `secrets` mode Mandu's own git never runs such a program: it
  forces them off. Its background and launch-prep git (the launcher's
  launch-prep runner; the arbiter's history scan, lock resolver and
  prepared copies) also runs in a sandbox with no network and a read-only
  filesystem wherever one can be made: bubblewrap on Linux, and on macOS
  `/usr/bin/sandbox-exec` running the git it finds, where no other program
  can start inside at all. Where none can be made, that git has the forced
  settings only. Mandu's other git calls (the net guard's read of the
  remotes, the working-copy probe, `mandu doctor`, the arbiter's version
  check, the dashboard, fs-sync) are hardened only, on both systems
  (`MANDU_GIT_SANDBOX=0` turns the sandbox off; `mandu doctor` says what
  this host gives, or why it gives none).
  Editor and
  IDE init files are not on the list either, and neither are the folders on
  your `PATH` (`~/.local/bin`, `/opt/homebrew/bin`, a Node version manager's
  `bin`) or Mandu's own launcher outside its install folder: the
  `~/.local/bin/mandu` wrapper, an `npm install -g` folder you can write to
  (Homebrew's `/opt/homebrew/lib/node_modules`), a source checkout. A program
  the agent puts or changes there runs outside Mandu the next time something
  calls it by name: you, a later session, or Mandu's own launcher and
  services (which run `bash` and `git` that way, and on Linux, without
  Mandu's own bubblewrap from `mandu setup`, `bwrap` too: the first one on
  `PATH` outside the folder you launch in, never one inside it nor through
  a `.` or relative `PATH` entry; test:
  `launcher/test/component/bwrap-path-launch.test.ts`). A `git` put there
  runs outside every sandbox, on both systems, in Mandu's git calls that
  are not sandboxed (the net guard's read of the remotes, the working-copy
  probe, `mandu doctor`, the arbiter's version check, the dashboard,
  fs-sync), and in all of them wherever no git sandbox could be made (on
  macOS a planted script is such a case: the git profile cannot start it,
  so there is none). Only where the sandbox holds does a planted `git` run
  inside it, and only for the background and launch-prep git (the
  launcher's launch-prep runner; the arbiter's history scan, lock resolver
  and prepared copies); on macOS the check that picks the git runs it
  sandboxed too, except Apple's own `/usr/bin/git`, which it runs as is.
  That program runs whichever git a per-user cache of Apple's developer
  tools names (`xcrun_db` in your account's temporary folder), a file the
  agent could rewrite; every git call Mandu makes ignores that cache
  (`xcrun_nocache=1`) and so runs the git your `xcode-select` setting
  names, and on macOS the agent's profile refuses changes to the cache
  like the other files that run later. Your own `git` in a terminal reads
  the cache too. Mandu trusts what git prints either way. A changed `mandu`
  can start the next session without protection. Mandu's install folder
  (`~/.local/share/mandu`, where `install.sh` puts it) is on the list. A
  write open, and a rename,
  delete, link, truncate, bind, node (`mknod`) or mode change (`chmod`,
  including by an open descriptor), is performed by the guard on the file it
  resolves, with each parent pinned so the kernel never re-resolves the path:
  a process racing a symlink into such a path can no longer slip a change
  past. A POSIX ACL set on a file (`setfacl`, an extended attribute) is not
  judged yet: it can still change a protected file's permission bits (the
  owner's entry is the owner's mode, so it can make a script executable).
- **A shell or an interpreter is not a reader.** A `readers:`
  entry naming only `bash`, `sh`, `python3`, `node`, `perl`, `ruby` or a
  launcher such as `env`, `xargs` or `awk` admits nothing: inline code
  (`bash -c '. .env'`, `python3 -c`, `node -e`), standard input, a module, a
  script in a place your user can write and any run that is not exactly a
  pinned script get no byte, and Mandu does not ask you about them, under
  any prompting setting (an *Always* for the interpreter does not
  count either). An interpreter reads a secret only as a script pinned
  with it (`{ app: python3, script: /opt/tools/report.py }`, below). This
  knowingly breaks setups that let a shell or a script of the agent's read a
  secret itself (`readers: [bash]` for a deploy script that sources `.env`,
  a `node` dev server or MCP server reading its key, npm with an `.npmrc`
  Mandu's placeholder cannot serve); [`usage.md`](./usage.md) ("Secrets in
  `policy.yaml`") lists the ways forward.
- **Only a program Mandu knows, or one you vouch for, reads the real
  bytes (since 2026-10-04).** A program on a file's `readers:` list gets
  the real file only if it is one checked not to print a file it is
  pointed at (`ssh`, `ssh-add`) or its
  entry carries your word, `prints: nothing`; any other program gets the
  placeholder copy, and under prompting for every program it is held with
  a warning that it may pass on what it reads (an *Always allow* writes
  your word into `policy.yaml`). Mandu does not check your word. It never
  lifts a program that prints or runs code (below). `git` is such a
  printer; `aws`, `gh`, `docker`, `kubectl` and `helm` are not on the list
  until someone checks them, so they read their credentials as the
  placeholder. The full rule is plan 13 §3 D8 (12) in
  [`design/confidentiality/confidentiality-plan-13-reader-set-labels.md`](./design/confidentiality/confidentiality-plan-13-reader-set-labels.md).
- **A program that prints or copies a file is not a reader either.** A
  `readers:` entry naming `cat`, `head`, `tail`, `less`,
  `base64`, `xxd`, `od`, `strings`, `sed`, `awk`, `grep`, `sort`, `cut`,
  `tr`, `diff`, `cp`, `dd`, `tee`, `rsync`, `tar`, `gzip`, `zip`, `jq`,
  `yq`, `envsubst`, `openssl`, `gpg`, `busybox` or another program whose job
  is to print or copy a file admits nothing, in any form: by name, pinned
  by path and hash, or with `from:`. Such a program gets what any program
  not on the list gets for that file (the masked copy, or a refusal), and
  Mandu does not ask you about it, under any prompting setting (a past
  *Always* for it does not count). The reason: a printer hands the file's
  bytes to whatever reads its output, and that can be the agent's own code
  (`cat .env | python3 -c '…'`). Mandu holds that code's content exits
  (what it prints, its connections, the programs it starts, the files it
  writes), but not its metadata: it could put the secret in the NAME of a
  file it creates (`touch "/tmp/$(cat .env | base64)"`) and read it back
  with `ls` later. Rather than follow every such channel, no printer ever
  gets the real bytes. The list is fail-closed (a program that can print a
  file when asked is on it, as is every program of a coreutils built as
  one binary, Ubuntu 26.04's; since 2026-10-04 also those that print one
  through an option, such as `file -f`, `date -f`, `wc --files0-from=`,
  a compiler's `-E` or `@file`, `nroff` and `man -l`) and is spelled out in
  [`design/confidentiality/confidentiality-plan-13-reader-set-labels.md`](./design/confidentiality/confidentiality-plan-13-reader-set-labels.md)
  §3 D8. What this costs: `readers: [cat]` and the like give no raw bytes,
  and `. <(cat .env)` hands your shell the masked copy; name the program
  that uses the secret (your own tool, with `prints: nothing`) instead. Since the
  same day the list also holds the programs that fetch or copy a URL or a
  file, a local one included (`curl file://…`, `wget`, `scp`, `sftp`,
  `rclone`, `gio`, text browsers' `-dump`), since 2026-10-04 `git` (`git
  diff --no-index /dev/null .env`, `git grep --no-index` and `git config
  -f` print any file it is pointed at), its credential helper and its HTTPS
  transport, and since 2026-10-07 the programs git ships as binaries of
  their own that read `.netrc` (`git-http-fetch`, `git-http-push`,
  `git-imap-send`: under `GIT_TRACE_CURL` they print the login they send)
  or send a file a request names (`git-http-backend`), every git
  credential helper by its name (any program called `git-credential-…`,
  such as `git-credential-libsecret` or the Credential Manager, and a
  script so named, such as `git-credential-netrc` run by `perl`: a helper
  prints the password it reads), and a copy of a
  printer you pin under another name is still that printer (the other
  `git-*` programs in git's own directory are links of `git` and are `git`
  this way; the few git builds as programs of their own are listed by name,
  or are scripts, which the interpreter runs): Mandu hashes the printers
  installed on your machine and recognizes a byte-identical copy anywhere,
  under any name. The same holds for a shell, an interpreter, a launcher
  or an editor: a copy of `python3` you rename and pin (`cp /usr/bin/python3
  ~/bin/mytool`) is `python3`, and like `python3` named alone it lets no
  program read the file; and clients that run a command they are given
  (`ftp`'s `!cmd`, `aria2c --on-download-*`, `wget --use-askpass`, `lftp`,
  `sftp`, `rclone`) count as such programs too. What this costs: such a
  copy reads no secret raw even pinned (pin a script with the installed
  interpreter instead), and the arbiter reads those programs' binaries once
  at start (about a quarter of a second). An interpreter that is no such
  copy (a `pyenv` python, an `nvm` node, a static `busybox`, under any
  name) is recognized by its content: the guard finds the interpreter's own
  command-line entry in the file it runs (python, perl, ruby, node, lua,
  LuaJIT, Tcl, Java, PHP, R, julia (every version), guile, Racket (CS and
  BC), bun, deno, PowerShell, the `dotnet` host, elvish, nushell, BusyBox,
  toybox, bash, zsh, dash, ksh (ksh93 and OpenBSD's), mksh, posh, yash,
  fish, tcsh, csh), and treats it as a shell named alone. This also makes every
  program built with `bun build --compile` (Claude Code's own binary
  among them) no reader: such a program carries bun whole, and one built
  with a recent bun becomes bun when its environment asks. Since
  2026-10-07 the same holds for a printer or a launcher that is no such
  copy: a GNU `cat`, `env` or `xargs` of another version, or a static
  build, under any name and even with `prints: nothing` on its entry, is
  recognized by the text its package carries (GNU coreutils, findutils,
  util-linux, diffutils, sed, grep, tar) and reads the file as any printer
  does; GNU's checksum tools (`sha256sum` and its kin) stay readers. A
  `from:` parent installed out of your agent's reach is read for its
  content too, so a disguised interpreter under the parent's name is not
  that parent; and a .NET program run with a .NET variable that loads code
  (`DOTNET_STARTUP_HOOKS`, `DOTNET_ROOT`, a profiler) your launch did not
  set reads nothing raw. What it does
  not close: a program you name that both
  uses a secret and can print one (a database client printing a query result), a script
  you pin that prints the file, and a program built to carry none of these
  marks (a printer of your own, an interpreter of a family Mandu does not
  know) that you pin under a new name: you vouch for what you pin, and
  what such a program prints reaches whatever reads it, with the metadata
  channels above. Of the programs that use a credential file Mandu knows
  (`psql`, `aws`, `gh`, `npm`, `docker`, `kubectl`, `ssh`, `twine`,
  `cargo`), only `ssh` and `ssh-add` read it raw without your word (since
  2026-10-04); the others read the masked copy, which logs in where Mandu
  puts the value back on the wire, unless you list one with `prints:
  nothing`, and `psql`, a printer, not even then; `curl` still gets `.netrc`'s masked copy, and `git` the
  masked copy of `~/.git-credentials` and `.netrc`, which the session's
  proxy completes on the way out, but no longer the real file (with TLS
  inspection off, or `MANDU_WIRE_TWIN=0`, their HTTPS login from those
  files fails); `ssh`, which `git` starts, still reads your ssh keys. The same rules hold under the names a
  distribution gives these programs (`gnucat`, `gnuenv`, `gtimeout`,
  `uu-env`), for `toybox` and `coreutils`, and for the relays `nc`,
  `ncat`, `netcat` and `socat`, which can run a program they are given;
  and for the `ssh_agent:` readers: a printer, a relay
  or a launcher listed there (`socat`, `nc`, `openssl`, `env`), or a copy of
  one under another name (by its hash, or an interpreter by its content:
  `perl5.40.1`), reaches your ssh-agent from no parent, since it would relay
  the agent to the AI's own code. The guard asks the arbiter about each
  program that connects there; while the arbiter is down, none does.
- **A configuration file the agent can write does not steer a program
  that holds a secret (since 2026-10-07).** Many programs run code, or
  print a file, because a configuration file says so: a repository's
  `.git/config` (`core.pager`, an alias, `credential.helper`),
  `~/.psqlrc`, `~/.lesskey` (and `LESSOPEN`), `~/.my.cnf`'s `pager`,
  `~/.ssh/config`. None of these lets the agent's code run inside a
  program that holds a secret's real bytes. `git`, `psql`, `less` and the
  other SQL and database shells (`mysql`, `mariadb`, `mysqlsh`, `duckdb`,
  `usql`, `sqlcmd`, `sqlplus`, `clickhouse`, `mongosh`, `mongo`) are
  printers: they never read a secret raw, so what their configuration runs
  sees only placeholders (a MySQL login from `~/.my.cnf` therefore fails
  under Mandu, as a Postgres one from `.pgpass` does). `ssh`, which reads
  your keys raw, reads `~/.ssh/config` as its placeholder copy, which
  withholds the commands it would run, and that file, every file it or
  `/etc/ssh/ssh_config` includes (`Include config.d/*`, OrbStack's or
  colima's file; followed to ssh's own depth), and every directory above
  them wait for your OK before they change (a configuration ssh reads
  could otherwise make it print a key, or load a library into it). The
  options and variables that hand these programs code on their command
  line are covered as above. What it does not close: an `Include` so broad
  that holding it would hold your home or a top-level directory such as
  `/tmp` (Mandu warns at launch and leaves it writable), one naming another
  account's home (`~bob/…`, warned too), and the configuration files of a
  program you vouch for with `prints: nothing`, which Mandu does not know:
  your word covers the program as it runs with them.
- **Your answer about a script names the script.** Allowing
  `python3` running `/opt/tools/report.py` to read a secret file, or to
  change a protected file such as `~/.bashrc`, allows that script only:
  another script, the same script changed, and inline code (`python3 -c`)
  are asked about separately. A shell running the agent's own command
  (`bash -c 'echo … >> ~/.bashrc'`) is asked about each change it makes;
  an *Always* there counts once. An answer given for an interpreter alone
  does not apply to its scripts (the dashboard and `mandu why` say so).
- **An *Allow once* is used by the send it was given for.** When you
  allow a held send (or a file the model proxy held) once, the next ask
  from Mandu's own gate, on the arbiter socket the agent's programs cannot
  reach, uses it, and that one send goes out. A program the agent runs
  that asks the same question on the socket it can reach is not granted
  your answer and does not use it up; a *Block once* answers it as a
  refusal. A WebFetch you allow once is judged twice, at the tool call and
  on the wire; only the request on the wire uses the answer, so it goes
  out once. Before 2026-10-07 such a program could use up each *Allow once*
  you gave, so the real send was held again and you were asked again
  (nothing was released). The in-context read (`declassify_symbol`), whose
  only caller is the agent's own helper, is the one answer an ask from
  that socket uses, by design. While a launch with no wall around the
  second socket runs (below), its agent's programs can reach it, and with
  it your *Allow once* answers. Tests:
  `arbiter/test/component/once-verdict-channel.test.ts`,
  `tests/stack/once-verdict-net-proxy.test.ts` (the real egress proxy:
  one release, the agent's asks spend nothing), the proxies' parity tests
  (`tests/stack/proxy-real-client-parity.test.ts`, net-proxy's
  `human-plane-parity.test.ts`).
- ***Send without it* sends the request, never the secret.** On a card
  about a secret's placeholder in a request to a host it may not go to,
  *Send without it* lets the next such request go with `[hidden by Mandu]`
  where the placeholder was (percent-encoded in the address and in a form
  body), once. The value is never filled in and the placeholder never
  leaves; before it goes, the request is checked for any secret value, and
  if the check finds one, or cannot run, it is not sent. The answer is
  offered and taken only on such a card: on a program's send of the files
  it holds, or a request of a session that read a secret, the request may
  hold the data itself, so Mandu refuses the answer there. A program the
  agent runs that asks the same question on the socket it can reach reads
  a refusal and does not use the answer up. Mandu unreachable: the request
  is blocked. In a session at a terminal the request waits up to a minute
  while you answer (`MANDU_EGRESS_HOLD_MS` sets the wait, 0 turns it off;
  `claude -p`, piped output and CI do not wait) and is itself the one that
  goes, through the same check; no answer in time, Mandu gone or the
  program gone while it waits, and it is stopped with nothing sent
  (`egress-hold.test.ts`, `tests/stack/egress-hold-send-without.test.ts`,
  `tests/stack/egress-hold-launcher-default.test.ts`). Tests: `arbiter/test/component/send-without-it.test.ts`,
  `arbiter/test/unit/send-without.test.ts`, net-proxy's
  `send-without.test.ts` (unit) and `send-without-wire.test.ts`,
  `tests/stack/send-without-net-proxy.test.ts` (the real egress proxy and
  dashboard adapter: the marker on the wire, without the value or the
  placeholder, once).
- **A program you allowed can leak by encoding.** A listed reader holds the
  bytes. Its stdout is masked and a verbatim value is caught by the backstop,
  but a program that prints the key base64-encoded, encodes it in file
  names, sizes, or timing, is outside the guarantee (exit codes: below).
  The AI does not see such a program's exit status: a result Mandu masks always reads as
  succeeded to the AI (Claude Code's error flag cleared; in Codex the exit
  code, the run time and the output size in the result's header blanked),
  so the AI cannot tell that a masked command failed, and
  says the result is masked; you see the real output. The
  exit status does not escape through the processes that learn it either:
  the shell (or any program) that started a program holding the bytes, or
  that waits for it, is held the same way from then on, so in `reader |
  prog; curl …` that `curl` reaches only the secret's hosts and a file the
  shell writes is labelled. The cost: after such a program, the rest of
  that command is confined like it, and a program that already holds a
  connection to another host cannot read the secret through its child (in
  the rare case where Mandu learns of such a child only later, the program
  is stopped before it learns the child's status). This is bounded by
  the allow-list: only programs you named, the well-known consumers, and
  whatever reads the output of a program you named (a program whose job is
  to print or copy a file, such as `cat`, is no reader,
  the bullet above), ever hold the bytes. Do not allow a shell or an interpreter (`bash`, `node`,
  `python`) to have clear output; Mandu refuses that setting, except on an
  entry that pins the script the interpreter runs (`{ app: python3, script:
  /opt/tools/report.py, output: clear }`), which matches
  only that file, out of your user's reach (an ACL on the file or a folder
  above it, a default ACL on such a folder, or a capability of your user's
  that overrides file permissions puts it in reach), run by its absolute path with no
  inline code, no per-user code path and no tracer, and whose output is shown
  only while the script started no other program. What such a script itself
  prints is yours to vouch for. A program's output is shown only while
  Mandu can check it against every line and credential-looking word of the
  files it read: after it reads a file over 16 MiB, or one with more than
  65,536 distinct such lines and words, its output reaches the AI as one
  placeholder whatever its entry says.
- **How a program you allowed is reached, in and out.** The check that keeps
  such a program to the secret's hosts judges every connection it opens and
  every datagram it sends to an address (a DNS query is one), and a connection
  it already held when it read the file makes the read fail. It
  also judges connections INTO the program and sockets handed to it: a
  server that loaded `.env` (a dev server) accepts a connection only from this
  machine — your own browser, the agent's own tools on `localhost` — or from a
  host the secret is bound to, and resets any other, which the connecting side
  sees as a dropped connection; an ordinary server that holds no secret still
  answers anyone (the gate does not break dev servers), and a child the
  program leaves running in the background keeps the restriction after the
  program exits. A **visible effect** of keeping such a program unreadable to
  the rest of the machine: `ps` lists it — and its children — by name without
  their command-line arguments (shown as `[name]`), and `pgrep -f` / `pkill
  -f`, which match on the whole command line, do not find it by its arguments.
  A program that read two secrets may reach only the hosts BOTH are bound
  to, never either one's alone (else a program holding `.env` and
  `~/.aws/credentials` could send the AWS key to the `.env`'s host). The
  same holds for the AI's session after it read two files in
  context. A program that reads its key after connecting (`ssh` does) needs the key's
  host as a binding, as any connection after the read always did. Such a
  program cannot look up names through DNS (only `/etc/hosts`, or a resolver
  you bound). Every process it starts is its own child and is held the
  same way: no program the agent runs can start a process
  as its own sibling (`clone` with `CLONE_PARENT` is refused, and `clone3`
  answers "not available", so programs use plain `clone`). Still not
  judged: a connection into it on a kernel older than 5.6 (no socket copy),
  where the coarser port wrap is the boundary. Details:
  `docs/design/integrity/exec-routing.md` §7.5.
- **What your own model does with a `local-model` file.** Mandu sends the
  bytes only to the address you declared `local: true` and confines what comes
  back. It cannot see what that server does next: a local gateway that
  forwards to a cloud vendor, or a model server that logs to one, is your
  decision. `mandu doctor` warns when a model you called local is not on this
  machine or a private network. When your AI's main model is your own (see
  the next item), the same holds for it.

  A model you called local on another machine is reached over https: a
  plain `http://` address to another machine stops the policy file from
  loading, and the helper refuses it too. The one exception is an entry you
  mark `allow_plain_http: true`, which sends `local-model` files to that
  server unencrypted by your choice; every launch warns about it and
  `mandu doctor` marks it ✗. An entry's `tls:` (your organization's CA,
  pinned keys, a client certificate) is checked in every TLS handshake
  Mandu makes to it, and a check that fails sends nothing. What TLS proves
  is the server's key, not what the server does with the files. With
  `perimeter: networks:` in `policy.yaml`, every address the server's name
  resolves to must be inside those networks, at launch and at every
  connection the helper or the model proxy makes; an address outside sends
  nothing. That proves where the bytes were sent, not who runs the machine
  at that address.

  Your organization can own the list: files under `/etc/mandu/policy.d/`
  set `models:`, `perimeter:` and `models_locked: true`, read at start and
  again when they change. With the lock, Settings › Models, a hand edit of
  `policy.yaml`, a proposal and the policy agent can remove one of the
  administrator's models or add an outside model, and nothing else: adding
  a model of your own or changing one of theirs is refused, naming the
  file. The administrator's `perimeter: networks:` can be narrowed in
  `policy.yaml`, never widened, lock or not. When the administrator's files
  change under a `policy.yaml` that breaks them, the administrator's side
  is what is used, and the lines of yours it overrides are named. The lock holds against Mandu's own surfaces and
  an injected agent. It does not hold against a person with a shell on the
  computer who runs a modified Mandu or points the agent past it; that needs
  a managed device or enforcement at the model gateway.

  One case the model's name gives away is refused: a cloud model. Ollama
  runs models such as `gpt-oss:120b-cloud` or `glm-4.6:cloud` (any tag that
  is or ends in `cloud`) on its vendor's servers, behind the same address
  as the models it runs on your machine. Mandu refuses a `models:` entry that
  names one and says `local: true` (the policy file does not load, and
  `mandu doctor` names the line), and when your AI's main model is your own
  local model, a request for a cloud model is refused and nothing is sent.
  `mandu doctor` also lists the cloud models your local server offers, so
  you know which names not to pick. A server can still give a remote model
  a local-sounding name; the name check does not catch that.

  Before you label files `local-model`, set up the server you call local so
  it keeps them:
  - **Listen on this machine only.** Bind it to `127.0.0.1` (Ollama:
    `OLLAMA_HOST=127.0.0.1`), not `0.0.0.0`, so other machines on the
    network cannot send it requests or read its answers.
  - **One user.** Do not share the server with other people or other
    programs you do not control. Researchers showed that a llama.cpp server
    shared between users leaked one user's prompts to another
    ([arXiv 2609.18526](https://arxiv.org/abs/2609.18526)); your labeled
    file is a prompt.
  - **Keep no history.** Turn off request logging and saved conversations
    or prompt caches written to disk, so the file does not stay on disk
    after the answer.
  - **No telemetry.** Turn off usage reporting and crash uploads that could
    carry request text.
  - **No cloud models.** Do not pull or pick a cloud model on that server
    (see above), and turn off any setting that sends requests to a hosted
    service when the local model is busy or missing.
- **A main model you point the AI at yourself.** When you set
  `ANTHROPIC_BASE_URL` to a model you declared under `models:` with
  `wire: anthropic`, Mandu keeps its model proxy in front of that model, so
  masking stays on, and a `local-model` file may enter the conversation when
  the entry is `local: true`. A model on another machine must be reached over
  https: plain http leaves this machine only in the clear, so the launch
  refuses it. When `ANTHROPIC_BASE_URL` names a model you did **not** declare,
  Mandu skips its model proxy for that session, as it always has: what the
  proxy masks (tool results, the instructions that teach the AI about
  placeholders) reaches that model unmasked. The launch warns and
  `mandu doctor` names it. Declare the model under `models:` to keep
  protection on. A Claude Code settings file cannot do the same behind your
  back: an `env` block in `~/.claude/settings.json`, the project's
  `.claude/settings.json` or `.claude/settings.local.json`, `~/.claude.json`
  or the SDK's `settings` that sets `ANTHROPIC_BASE_URL`, a proxy variable or
  a cloud provider switch no longer applies under Mandu, even when the agent
  writes it during the session (the launch names the file). Managed settings
  that would re-point it, a `--settings` file, and a launch environment
  naming Bedrock, Vertex, Foundry or `ANTHROPIC_UNIX_SOCKET` are refused
  (supported-agents.md §2.5). The same holds, since 2026-10-18, for a
  `claude` started by name inside the session (from the shell of `mandu --
  bash`, a script, or the AI's own commands under `mandu claude`): Mandu's
  `claude` shim gives it the launch's routing over its settings files and
  over an `ANTHROPIC_BASE_URL` its command line sets, and refuses a
  `--settings` file or a cloud provider switch. Before, such a `claude`
  followed its settings files around the model proxy, carrying what it read.
  One started by its full path keeps only its environment's routing, which
  whoever starts it can change (agent-sdks.md §3.5); since 2026-10-18 its
  model calls are refused at the network (agent-sdks.md §4, "The model-host
  deny"), except that without the connect guard (`--no-net-guard`, a host
  without it, macOS) one that ignores the proxy settings still reaches the
  vendor's host, and with `--no-net-proxy` nothing refuses it. Codex gets the same through `MANDU_OPENAI_BASE_URL` and a
  `wire: openai-chat` entry; a Codex session without one counts its main
  model as an outside model. `codex --oss` and `--local-provider` stay
  refused, since they would skip the model proxy. So do `codex --remote`
  and `codex agents`: they connect to a Codex background server Mandu did
  not start, which would run the agent and its tools outside Mandu's
  protection. The subcommands that start or manage a Codex server are
  refused for the same reason: `codex remote-control`, `codex app-server`
  and `codex exec-server` (such a server serves clients from outside the
  session and can outlive it), and `codex debug app-server`, whose model
  turn skips the model proxy. Under Mandu, Codex runs in the process Mandu
  launched (`--no-daemon`), so its footer has no "agents" entry. `codex
  cloud` is refused too: it runs your prompt as a task on OpenAI's machines.
- **Codex's own uploads are off.** Codex's process holds your tools' real
  output, so Mandu turns off what Codex would send past its model proxy:
  analytics, the feedback report (which uploads the session), OpenTelemetry
  export to a collector, the update check, and ChatGPT apps and connectors
  (an app's file parameter makes Codex upload the local file to ChatGPT; the
  launch says so on a ChatGPT sign-in). A `-c` or `--enable` of yours that
  turns one back on is refused at launch. The metrics host, the feedback
  host and the collectors your environment or Codex config names are also
  refused at the network layer. What stays allowed carries none of your
  session: the ChatGPT sign-in's account and plugin calls on `chatgpt.com`,
  the token refresh on `auth.openai.com`, and the fetch of OpenAI's public
  plugin repository on `github.com`. Not covered: a managed Codex
  configuration (`/etc/codex/managed_config.toml`, MDM) that turns one back
  on, since it sits above the command line, and a realtime (voice) base URL
  given on Codex's command line.
- **Environment-variable secrets are placeholder-only.** `GH_TOKEN` in the
  agent's environment is a placeholder in every process and is put back at
  the wire. A signing credential a program must hold (`AWS_SECRET_ACCESS_KEY`
  for a signed request) cannot work from the environment; keep it in
  `~/.aws/credentials`, where a listed reader gets the bytes. Nor can a
  database password (`PGPASSWORD`, `MYSQL_PWD`): no database protocol has a
  placeholder release, so the login fails ([usage](usage.md) lists the ways
  out).
- **A protected file committed to git.** A file you protect can also live
  in git history: your own repository if the file is committed, and Mandu's
  private per-workspace copy (`~/.mandu/state/workspaces/<id>/repo.git`) if it
  is tracked. A program reading that history (`git show`, `git diff`,
  `git log -p`) never opens the file itself. At launch Mandu finds every
  version of each protected file in your repository (any branch or tag, the
  reflog, the stash, the index) and hides those versions from the agent: the
  packs holding them are replaced, for the agent only, by copies without
  them, and loose copies are unreadable. In the agent's world `git show
  HEAD:<file>` then fails with "bad object", and a `git log -p` or `git
  diff` stops at the first change to that file; everything else in the
  repository works, including new commits. Mandu itself does not change
  your repository (but git in the session can commit the placeholder copy,
  the next point). In `secrets` mode Mandu's own copies are hidden from the agent
  too. Rebuilding a large history takes time once (the copies are cached);
  the first launch after one without protection (`--mode off`,
  `--no-net-guard`) has ended builds them again, since that launch could
  have changed them, and says so before it starts: `mandu: ! an earlier
  Mandu session without protection has ended, so Mandu is re-checking the
  git history of 2 repositories (slower this once)`;
  more than 1 GiB of packs to rebuild at one launch refuses the launch
  unless `--best-effort` (`MANDU_GIT_TWIN_MAX_MB` raises the cap). With
  `--best-effort`, only the repository that could not be sanitized keeps
  its history readable, and the launch names it; every other repository's
  history stays hidden.
  The same hiding covers two more things you can lock: a file you label that
  **no longer exists** (a deploy key committed and then deleted: label its
  old path in `policy.yaml` `paths:` or the dashboard, and every version the
  history holds is hidden), and one **old version** of a file by its git id
  (`policy.yaml` `blobs:`, e.g. `- { id: sha1:…, level: no-model }`: that
  version is hidden in the repository you launch in and in every repository
  holding a protected or labelled file, while the current file stays
  readable). Another repository holding a locked version (a clone, a fork,
  one you are not launched in) is covered by the version's id, when Mandu
  knows it (you launched or scanned there, a label names it, or it lies
  within five folders of your home): Mandu prepares its copies without the
  locked versions in the background, and a launch anywhere serves them, so
  git keeps working there; until they are ready (or when they are over the
  size caps, `MANDU_GIT_PREP_CYCLE_MB` and `MANDU_GIT_PREP_TOTAL_MB`), git in
  that repository is refused for the session instead, and the launch says
  which. `mandu doctor --secrets` counts the repositories prepared and not
  yet. A pattern or gone-path label on a repository Mandu has not found is
  not covered.
  What is still open: a version stored under an **older name** (the file was
  renamed) or copied into another file, objects that arrive **after** the
  launch (a `git fetch`), and in the frozen `full` mode Mandu's own copy, which the
  agent's working folder is part of (closing it needs the object-store split
  in `docs/design/integrity/fs-sync.md §3` §8). For those, a second check
  stays in front of the AI: any tool output that contains the protected
  value, any line of it 24 characters or longer (except a line the
  file's placeholder copy shows the AI as it is, such as a comment in a
  `.env`), or any word of it that looks like a credential (12 characters or
  more; a binary file's readable strings count as its lines), in a file of
  any size up to 16 MiB, is replaced by a placeholder at the file's level, and the same check stops such text
  leaving in a network request. That check cannot see the value encoded
  (base64, compressed), a short line or a plain word of a document when the
  whole does not appear, the part of a file past 16 MiB or past its first
  65,536 such lines and words, or a paraphrase, and it runs
  after the agent's own local session log (Claude Code's transcript under
  `~/.claude/projects/`) has recorded the output. Keep protected files out of
  version control where you can: `.gitignore`d files never enter Mandu's
  copy of the history. (In the frozen `full` and `injection` modes the AI's working copy
  still holds them, each as one placeholder kept outside git; heavy folders
  such as `node_modules`, files over 1 MiB, and binaries stay out, and the
  launch says which.)
- **git in the session can commit the placeholder copy of a protected
  file.** In a session a protected file reads as its placeholder copy, to
  git too (Linux; on macOS there is no placeholder copy, and git cannot read
  the file at all). For a file git tracks, a `git commit -a`, `git add -A`,
  `git add .` or `git stash` the agent runs after any other change records
  the placeholder copy in your repository in place of your file. A protected
  file git does not track goes in through `git add -A` or `git add .` and a
  commit, or through `git add -f` when `.gitignore` names it (`git commit
  -a` and a plain `git stash` leave untracked files out). git in the session
  never reads your secret, so what it records is the placeholder, and your
  file on disk keeps its real content; but your history holds the
  placeholder, `git status` outside the session shows the file as modified,
  and a push sends the placeholder to others. A commit of only the files the
  agent changed (`git add <file>`) is not affected. Mandu warns, it does not
  stop the commit: after the agent exits it checks the repository and prints
  a `WARNING` naming the file, whether it is staged or in which commit (and
  whether that commit was pushed), and the commands that take the
  placeholder out of git, in the order to run them; a session that ended
  before its check (a crash) is checked at the next launch, and again after
  that launch's agent exits. These commands only remove: none adds your file
  on disk to git or brings back a version of it from another commit or
  branch, so following them puts no version of that file into the history.
  To repair, outside a Mandu session: first take what is only staged out of
  the index, `git restore --staged -- <file>` (back to what your checked-out
  commit holds; on a branch with no commit yet, `git rm --cached -f --
  <file>`); then, for a placeholder in your checked-out commit, `git rm
  --cached -f -- <file>` and `git commit --amend --no-edit --allow-empty`
  when it is your last commit and not pushed, or a new commit otherwise. git
  then no longer tracks that file, even one it tracked before the session,
  and your file on disk stays as it is: if it belongs in git, check what the
  file on disk holds and add it back yourself (what you add is your real
  file; Mandu prints no command that puts it back), and otherwise list it in
  `.gitignore`. An older commit, one on another branch or a pushed one keeps
  its placeholder until you rewrite it, which is your decision; the warning
  names it. Unstaging comes first because the commit takes everything
  staged, a staged placeholder included; check `git status` before it for
  other staged work too. Until then, do not run `git checkout`, `git
  restore` without `--staged`, `git reset --hard` or `git stash` on that
  file: each can write the placeholder over your real file. To avoid it,
  keep protected files out of git: a file git already tracks stays tracked
  whatever `.gitignore` says, so stop tracking it first (`git rm --cached --
  <file>`, outside a Mandu session, then list it in `.gitignore`; the commit
  after that removes the file from the repository, and from a collaborator's
  checkout at their next pull); or ask the agent to add only the files it
  changed (`git add <file>`).
- **A Goose that a program in the session starts on its own terms.** The
  fence on Goose's other providers (section 2) is set in the session's
  environment and at the egress proxy. A program the agent runs can start
  another `goose` with those settings put back and the proxy variables
  removed, and reach a provider directly, like any program sending what it
  read; for a registered secret the network guard's holder rule still
  applies. Google Vertex AI's regional addresses are fenced by setting
  only, and with the network guard off a provider of your own on a local
  port is not fenced.
- **Unregistered secrets are unprotected.** Mandu masks what the catalog
  recognizes (`.env*`, `*credentials*` other than documentation pages and
  program source, so a `credentials.md`, `.rst` or `.html`, or a
  `credentials.ts`, `.py`, `.go` or other source file, is caught only if you
  label it or the value is registered elsewhere (a shell script, a data or
  configuration file and a name with no extension stay caught), `~/.ssh/*`, `~/.aws`, `~/.config/gh`,
  `~/.pgpass`, `~/.netrc`, `~/.npmrc`, private-key files, the login files
  of the tools in `docs/design/confidentiality/secret-discovery.md §2`, whose 84-file
  corpus is a test, a tool's login file in its own folder (`.<tool>/auth.json`,
  `~/.config/<tool>/access-token`, `~/.gemini/oauth_creds.json`), an HTTP
  client's `*.private.env.json`, a JSON, YAML, TOML, INI, `.conf`, `.cnf`,
  `.cfg` or `.properties` config file, or a project's `.npmrc`, `.pgpass`,
  `.netrc` or `.pypirc`, in which the launch finds a password, token or
  key under a name that says so (`password: …` in `accounts/power.yaml`,
  `password = …` in `config.ini`, `db_pw`, `SMTP_PASS`, `PGPASSWORD`,
  `card_pin`), a short one included (6 characters or more with a letter and
  a digit or a mark, or a PIN of 4 or more digits), but not a well-known
  default such as `postgres` or `changeit`, nor a password of letters
  alone (not in a test, fixture, example
  or docs folder, not an agent's or editor's own settings, and in your home
  only in a tool's own dot-folder and `~/.pg_service.conf`, `~/.odbc.ini`
  and `~/.wakatime.cfg`), a small text document (`.md`, `.txt`,
  `.csv`), PDF (`.pdf`, its text layer, not a scan) or Office file
  (`.docx`, `.xlsx`, `.odt`, `.ods`) the launch recognises as a personal
  document: a bank or card
  statement, a payslip, a tax return, a lab report, an identity document or
  a note of door, alarm and Wi-Fi codes, each on several signals together
  (an account, card, IBAN or taxpayer number of a valid shape, the
  document's own words and amounts, a patient line with lab results and
  reference ranges; in your project, or in your home's `Documents`,
  `Desktop` and `Downloads`; not in a test, example, docs or source folder,
  not inside a software project, not a README), whose labels the AI still
  reads with every value a placeholder (a PDF's copy is still a PDF, an
  Office file's copy is its text), each supported agent's login files, and each supported
  agent's own session store, where it keeps tool output as it saw it:
  `~/.claude`, `~/.codex`, OpenCode's `~/.local/share/opencode`, and Goose's
  `~/.local/share/goose` and `~/.local/state/goose`, whose request log holds
  each request to the AI whole; a store, and the login of an agent the
  session runs, is masked only where a command names its path: see "The
  AI agents' own files" below),
  what you lock in the dashboard or `policy.yaml`, and environment variables
  whose name says secret or whose value holds a key in a known format (a
  password in a variable named otherwise, such as `DB_PW`, stays raw, and
  so does a `*_PWD` other than `MYSQL_PWD` holding a directory path). The
  agents' sign-in variables (`ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`,
  `ANTHROPIC_CUSTOM_HEADERS`, which can carry an `Authorization` or
  `x-api-key` header, `CLAUDE_CODE_OAUTH_TOKEN`, `OPENAI_API_KEY`,
  `CODEX_API_KEY`, and under `mandu goose` the routed provider's key) are
  not masked, so the AI can read them, except the launched agent's own API
  key when Mandu's model proxy can put it back for the agent: under `mandu
  claude` `ANTHROPIC_API_KEY`, under `mandu codex` `OPENAI_API_KEY` and
  `CODEX_API_KEY`, and under `mandu goose` its routed providers' keys are
  placeholders when the provider is its vendor's own API host or this
  machine, and the proxy sends the real key to that host only. Mandu's own
  `MANDU_*` variables are left as they are, except the helper model's key,
  `MANDU_ULLM_API_KEY`, which is not in the agent's environment at all. The catalog decides by path, and reads only
  config files and those documents (above): a key pasted into `notes.txt`, a private key named
  `server.pem`, a well-known or letters-only password (`password: hunter2`,
  `password: sunshine`), one under a name that does not say so (`magic =
  …`), or a key alone in a config file under such a name, is not a secret
  to Mandu until you label it, and neither is
  a statement or a report Mandu cannot read the text of (a scanned PDF, a
  password-protected file, a legacy `.doc` or `.xls`), a personal document
  of another kind (clinical notes without lab results, a contract, a
  diary), or one with fewer signals (a statement with no account number, a
  note with a single code). A file
  Mandu labelled this way says so in `mandu why`, and a label of yours on
  it (`public` included) decides instead; a credential written into a
  config file during a session is found at the next launch. A file you label is found wherever it lies,
  outside your home and project or deeper than the home walk looks (up to
  256 files under your labels per launch), and labelling a folder while the
  AI works protects the files already in it. On Linux with the network
  guard, a file that appears later in a folder you labelled is protected
  too: a program the agent runs that reads it (`grep -r`, `tar`, a script)
  gets its placeholder file, unless your label lists that program as a
  reader. The same holds for a file the catalog names that the launch did
  not find: a `.env`, a key or a credentials file that appears during the
  session, sits deeper than the home walk looks, or lies outside your home
  and project, reads as its placeholder file to any program the agent runs,
  by the same rule the launch uses (a `.env.example` stays readable, and
  so do files in `node_modules`, `.git` and the other folders the walk
  skips, and a file another account owns outside your home). Without the
  network guard (macOS, `--no-net-guard`), files that appear after the
  launch started (a new `.env`, or a new file in a labelled folder) are not
  masked until the next launch, except where a command names their path. On macOS the home walk does not look inside `~/Library`,
  `~/.Trash`, `~/Pictures`, `~/Music` or `~/Movies` (app data and media,
  much of it behind macOS privacy prompts): it still checks the catalog's own
  paths there and every file you labeled, but a `.env` or key file kept there
  under any other name is not found, and no warning says so. Label it (or
  its folder) to block it.
- **A change to a protected file in the session is discarded (Linux).** A
  program in the agent's process tree (the agent itself included) that is
  not on a protected file's allow-list and writes the file in place (`echo
  X=1 >> .env`, `printf … > .env`) writes into the session's placeholder
  copy of the file, not the file: the write succeeds, the real file never
  changes, and the change is discarded when the session ends. Since
  2026-10-09 Mandu then prints one line for each protected file the session
  changed, by path only (`mandu: during this session the agent changed …`),
  whatever the display setting, and the session's record (its
  `session_exit` event) lists them; make the change yourself if
  you want it. The line says the real file is unchanged only when Mandu
  compared it with what it read at launch; if the real file changed too (a
  program on its allow-list wrote it, or you edited it meanwhile) the line
  says so, and if Mandu could not read it the line says that. Only a
  launcher that reaches its own end prints the lines. One that dies first
  (killed with `SIGKILL`, a crash, a `^\` (`SIGQUIT`), or a `SIGTERM` or a
  closed terminal while it is shutting down) leaves the session's folder
  behind, and `mandu reap` names each changed file before it removes that
  folder; a reboot or a logout that empties `$XDG_RUNTIME_DIR` first loses
  the change with no line. A program that replaces or removes the file fails
  instead: `sed -i`, an editor's save (a new file renamed over the old one)
  and `rm` get "Device or resource busy" (`EBUSY`) where Mandu mounts the
  placeholder, and "Permission denied" (`EACCES`) under the file guard
  alone. So `npm login`, `npm config set`, a save by git's credential store
  (`credential.helper=store`) and `goose configure` lose what they save: run
  them outside Mandu. And a new secret a program writes into the copy (a
  token refresh, the token `npm login` saves) is read as written by every
  program the agent runs later in that session, so it can reach the AI, and
  Mandu does not register it: the protection is the files as they were at
  launch.
- **The AI agents' own files.** Each supported agent's own data (its
  sessions and transcripts, which hold tool output as the agent saw it,
  its settings: `~/.claude`, `~/.codex`, OpenCode's and Goose's data
  folders) is left as it is in every session, whichever agent you launch,
  because the agent reads and writes it. So is the login of each agent the
  session runs: Claude Code's (`~/.claude/.credentials.json`,
  `~/.claude.json`, `~/.anthropic`) under `mandu claude`, a plain command
  and `mandu openclaw`, and under `mandu goose` or `mandu opencode` while
  Mandu's AI helper runs `claude` (neither `ANTHROPIC_API_KEY` nor
  `MANDU_ULLM_API_KEY` set, and no `--no-mcp`); Codex's
  (`~/.codex/auth.json`, `~/.openai`) under `mandu codex` and `mandu
  openclaw` (OpenClaw reads both agents' logins itself); OpenCode's
  `auth.json` under `mandu opencode`. A program the agent runs reads these
  files as they are. Their values are registered only by a session that
  does not run that agent, and in a session that does, its egress proxy
  does not check them, so nothing recognizes them leaving the machine
  there; the AI sees one masked when a command names its path (`cat
  ~/.codex/auth.json`; the agent's own read tool asks you first), or when
  another session registered the value, not when a script or `$HOME/...`
  reaches an unregistered one.
  `mandu why <path>` says which of these a file is. Another agent's login
  is masked like any credential file (§2). The agents' keys in the
  environment (`ANTHROPIC_API_KEY`, `CLAUDE_CODE_OAUTH_TOKEN`,
  `OPENAI_API_KEY`, `CODEX_API_KEY`) are never masked, whichever agent you
  launch.
- **A JSON, YAML, TOML, INI or XML file you label is protected only for
  the values Mandu recognizes in it.** This is a known gap in the
  guarantee, not a design choice. When a file you label (a `paths:` entry
  in `policy.yaml`, the dashboard or `mandu policy`) is in one of these
  formats and has at least one key whose name looks secret (`password`,
  `token`, `api_key`, …), it gets a per-key copy: only the values Mandu
  recognizes (the next item) become placeholders, and every other value
  reaches the AI as written, through the AI's own Read of the file and
  through any command that does not name the file (`cat ./ret*`, a script
  that opens it). A command that names the file (`cat return.yaml`) is
  hidden whole. For a labelled `return.yaml` holding `ssn`, `wages` and
  `password`, the AI sees `ssn` and `wages`. A labelled `.env`-style file
  is masked by value instead of by key, but a whole number or a plain word
  (`81234`, `joint`) stays as written there too. A labelled file in no
  format Mandu reads, or one with no key whose name looks secret, is one
  placeholder. The planned fix is a copy in which every value of a
  labelled data file is a placeholder
  ([confidentiality plan 16](design/confidentiality/confidentiality-plan-16-document-twins-writeback.md),
  §1.2 and §3). Until then:

  - name the values to mask with `extract:` on the file's entry, a
    regular expression whose first group is a value:
    `extract: ':[ \t]*(.+)'` masks every value of a `key: value` YAML
    file. Its matches
    replace Mandu's own recognition for that file, and a pattern that
    matches nothing hides the file whole;
  - or keep such data in a file Mandu hides whole, such as a `.txt` or
    `.csv` file;
  - a different `level` or a `readers:` list does not help: every level
    above `public` gets the same copy, and the AI's own process always
    reads the copy, whatever the list says;
  - `mandu why <path>` says which applies: "a placeholder copy that keeps
    the file's structure (yaml-keys); each secret value Mandu recognizes is
    a placeholder (1 in the file now)" means this gap applies, "a
    whole-file placeholder" means it does not.

  (Confirmed end to end and documented 2026-10-16, a security gap:
  `tests/stack/labelled-data-file-twin.test.ts` pins it, and must be
  flipped by the fix.)
- **A value Mandu does not recognize in a structured file stays as written
  in its placeholder copy.** In a `.json`, `.yaml`, `.toml`, INI or XML file
  Mandu masks the values it recognizes as secret: a value under a key whose
  name looks secret (`password`, `api_key`, `token`, …, and since
  2026-10-19 `pw`, `db_pw`, `passphrase`, `passcode`, `pin`, `card_pin`,
  `access_code`), a URL's password
  and a known credential format (a provider's key prefix, a private key)
  anywhere in the file, under any key or in a comment. In a comment, a
  whole line or one after a value (`PORT=3000 # backup …`), it also masks a
  word that looks like a random credential (`# backup password
  Tq7vZ2pX9kLm`). Still as written: a secret with no known format under a
  key that does not look secret (`notes: hunter2`), outside a comment. A copy of a value it masks elsewhere
  in the same file (under another key, in a comment) is masked too. A key
  found in a comment (a commented-out old key) can be sent nowhere unless
  you name it under `values:` on the file's entry (its name is shown in the
  placeholder, `cred.OLD_STRIPE_KEY`), so sending the whole file, even to a
  host the file is bound to, asks you first. A short secret (under 8
  characters) that also appears inside a longer word elsewhere in the file
  (`DB_PASS=owl` and `MODE=owlish`) stays as written in that word, so the
  programs reading the copy get the right value, but the AI never reads that
  line from the copy: a Read or a command whose output carries it is hidden
  whole. A command that does not name the file and prints an encoded copy
  of it (`base64 ./.e*`) still carries that word.
  (Security fix, 2026-10-17: until then a known credential format outside a
  secret-named key's value, such as `# OLD_STRIPE_KEY=sk_live_…` in a
  `.env`, stayed as written in the copy every program reads, and a command
  that did not name the file (`base64 ./.e*`, `cut -c9- ./.e*`) could hand
  it to the AI in a form Mandu's check for known values, which looks for
  the value as written, did not see. A short secret inside a longer word
  reached the AI as written through a Read of the copy.)
  In a list of a `.json`, `.yaml` or `.toml` file (not INI or XML), such as
  an MCP server's `args`, Mandu reads the items as a command line, one
  word per item, and an item that holds a command line itself (`sh -c
  "…"`, a quoted connection string) word by word, as a shell splits it
  (quotes, backslashes, and up to two levels of quotes inside it). There
  it also masks:

  - the value of a flag that takes a secret, as the next word, after `=`
    or glued: `--api-key`, `--token`, `--password`, `--secret`, `--auth`,
    `--pat`, `--oauth2-bearer`, wget's `--http-password` and
    `--proxy-password`, Go's `-password` and `-token=`;
  - the password of `user:password` after `-u`, `--user`, `--proxy-user`
    (also glued, `-uadmin:…`, or last in a group of switches, `-su`),
    curl's `-U`, and httpie's `-a` or `--auth` (a token alone after `-a`,
    with `-A bearer`, is masked whole);
  - the value after `docker login -p` or `podman login -p` (as the next
    word or glued), mysql's glued `-p…`, `sshpass -p`, `redis-cli -a`,
    curl's cookie `-b`, and `gh secret set … --body` or `-b`;
  - the value of an `Authorization` header (after `Bearer`, `token`,
    `Basic`, …) or of a header whose name says secret (`X-API-Key`,
    `PRIVATE-TOKEN`): after `-H` or `--header`, quoted or not (`-H
    X-Api-Key:…`, `-H"…"`, `--header="…"`), as an httpie item
    (`Authorization:"Bearer …"`) or in git's `-c http.extraHeader="…"`;
  - the value of `NAME=value` with a secret-looking name: `PGPASSWORD=…`,
    `MYSQL_PWD=…`, `GH_TOKEN=…`, `NPM_TOKEN=…`, `-e API_KEY=…`, httpie's
    `password=…` and `api_key==…`, `password=…` in a Postgres connection
    string, and a `client_secret=…` pair of a form body (`-d
    'grant_type=…&client_secret=…'`);
  - a setting named like a secret: `npm config set
    //registry.npmjs.org/:_authToken …` (or with `=`, or npm's
    `--//registry.npmjs.org/:_authToken=…`), `git config user.password …`;
  - and every item of a list under a secret-looking key.

  A switch that takes no value, before, between or after these flags (`curl
  -s -u admin:…`, `tool --verbose --auth …`), hides nothing, and a word that
  starts with `-` is the next flag, not a value, unless it looks random. A
  value that starts with `$` is masked in three places: as a list item of
  its own after a secret flag (`"--password", "$ecret…"`), single-quoted as
  a word of its own in a command line (`--password '$ecret…'`), and as a
  URL's password (`https://u:$PW@…`). `${API_KEY}` (an MCP client expands
  it) always stays as written. Inside a word Mandu reads as a command line,
  `$API_KEY` after a flag or a name (`--token $API_KEY`, `-u admin:$PW`) is
  taken for a variable the shell expands and stays as written, and so does
  every `$NAME` in an item that holds several words or in a quoted word
  inside a command line, even where nothing expands it (below). Everything
  else stays as written: a user name, a
  host, a port, `gh auth login -p https`, mysql's `-p` alone, wget's
  `--ask-password`, a switch such as `--skip-auth` or a pattern such as
  `--exclude-pat`. So do psql's or mysql's `--password` alone (they ask for
  it) and `-u` after `docker` or `podman` (a user and group: `docker run -p
  8080:80 -u app:staff`), but only where that program is the command itself:
  the list's `command` (an MCP server's), or the first word of a command
  line in an item, past `NAME=value`, a wrapper such as `sudo -u postgres`,
  `env`, `nice`, `timeout 30`, `exec` or `xargs`, and after an operator that
  starts a command (`;`, `&&`, `|`, `$(`). A word that only names the
  program (a path such as `/var/lib/mysql`, an image such as `mcp/mysql`, a
  value such as `--db-type mysql`, the first item of a list with no
  `command`) changes nothing: there `--password` and `-u` take their values.
  `arbiter/test/unit/secret-extract-command-lines.test.ts`
  holds a table of such command lines for curl, wget, httpie, psql, mysql,
  docker login, gh, npm and git. Not recognized in a list: a secret given
  with no flag or name before it (`cargo login …`, `poetry config
  http-basic.<repo> <user> <password>`) or on standard input (`echo … |
  docker login --password-stdin`); a value that starts with `-` and reads
  like a word (`--password -hunter2`); a JSON body (`-d '{"password":
  …}'`) or a URL's query value (`?access_token=…`); a word-like token
  written as a URL's user with no password (`https://<token>@github.com`;
  one in a known format, `ghp_…`, is caught); `-u`, `--user`, `-user` or
  `--proxy-user` with `x:y` later in a command whose command is `docker`,
  `podman`, `nerdctl`, `buildah` or `finch`, even past the image, unless a
  program Mandu knows (such as `curl`) is named between (`docker run img
  tool -u admin:…`); a `$`-led secret inside an item that holds several
  words (`"--password $ecret…"`, a connection string `"host=db
  password=$ecret…"`) or inside a quoted word of a command line (`sh -c
  "psql 'host=db password=$ecret…'"`), and bash's `$'…'` and `$"…"`
  quoting (`--password $'S3cret'`); a flag whose secret Mandu does not know (curl's `-E
  cert.pem:password`) and a header whose name does not say secret (`-H
  'X-Custom: …'`); a command line nested in more than two levels of
  quotes inside an item. These list rules only add to a file in which a key
  already gave a secret value: a file whose only secret Mandu recognizes is
  a list item (an MCP config whose only secret is a database URL in
  `args`) is hidden whole, as is a file in which Mandu recognizes no
  secret value at all. A short, word-like secret under an ordinary key
  (`"note": "hunter2"`), or alone in a list with no flag before it, is not
  recognized: the agent's programs read it as written, and the AI can too
  when it reads the copy (one that looks like a credential is still caught
  there). In a `.yaml` file neither is a value inside an inline mapping
  (`env: {GITHUB_TOKEN: …}`), a list item written as a block (`- |` and the
  lines under it), or the part of a list item that goes on to the next
  line. `mandu why <file>` says how many values the copy masks, or that it
  hides the file whole. For such a file, name what to mask with `extract:`
  on its entry in `policy.yaml` (a regular expression whose first group is
  the secret, such as `extract: 'pin: (\d+)'`), or list the programs that
  need it with `readers:`, so that any other program is refused (the AI's
  own Read still gets the copy: the item above).
  (Until 2026-10-09 every value in a list stayed as written. Until
  2026-10-10 a command line inside one item was not read word by word: a
  switch before a secret flag, as in `curl -s -u admin:…`, left the secret
  as written, and so did a header there.)
- **A secret that lives only in git history is unprotected until you lock
  it.** A key that was committed and later deleted is in no file Mandu
  protects, so until you add a rule a `git log -p` or `git show` of the old
  commit gives it to the AI as it is. Lock it and the next launch hides it
  (above): label its old path, even though the file is gone, or, when the
  key sat inline in a file that is fine now, lock that old version by its
  id. `mandu doctor --secrets` scans the history of the repository you run
  it in for such keys (private keys, known token formats, credential
  assignments, deleted files named like credential files), lists each one
  masked (never its value) with the commit that added it, and says what
  would close it; a locked one is listed as covered. The scan reports; it
  protects nothing by itself. Either way, treat a key that was ever
  committed as leaked: a lock keeps the AI from reading it from now on, it
  cannot undo a push or an earlier session. Rotate it, and scrub it from
  history if the repository is shared. On macOS a lock hides nothing yet:
  only Linux hides a protected file's or a locked version's committed bytes.
  A macOS launch instead names, in one warning, each of its repositories
  where a protected file is committed or a locked version (a `blobs:` lock,
  a labelled path's earlier versions) is held; `mandu doctor --secrets`,
  `mandu policy suggest` and the dashboard's Suggested view say on macOS
  that a lock holds on Linux only.
- **A rule is matched on the path as written, not through symlinks.** The
  open trap follows links, so a secret file's bytes are served as a
  placeholder whichever name a program opens it by. But the level Mandu gives
  what the AI read (and the `gated` posture's text gate) follows the name the
  agent used: a rule on `~/keys/deploy.key` does not cover a read of it
  through `~/ws/key-link`, and the reverse. The dashboard's file browser
  writes a rule chosen for a link on the file it points to as well
  (dashboard.md §4.25m); a rule written by hand on one name is not
  extended. Put it on both names, or on the folder that holds the real file.
- **The walk has limits, and says so.** The home walk stops four folders down
  and at 256 credential files; unreadable candidates are skipped. Every
  launch prints a `WARNING: … secrets NOT covered` block when that happens,
  and `mandu doctor --secrets` lists the paths. Deep folders inside package
  managers' caches (`~/.cargo/registry`, `~/go/pkg/mod`, …) and sockets
  named like a secret are not counted in that warning; the dry run lists
  them on their own lines. The macOS folders it skips
  on purpose (above) are not in that warning.
- **Programs that pin their own certificate, or ignore the proxy and CA
  settings,** cannot receive a placeholder's real value over HTTPS (Java,
  kubectl to a cluster, and the rest of `docs/design/confidentiality/confidentiality-plan-13-reader-set-labels.md §10`).
  Either list the program as a reader (it then holds the bytes and connects
  directly to the bound host, no proxy involved) or run with
  `--no-net-proxy-mitm`, in which case masked values cannot leave over HTTPS
  at all. A refused inspection certificate is named on the dashboard trace.
- **The egress proxy finds the sending program from `/proc`.** It judges
  every program holding the connection on every request it reads, and a
  connection it cannot tie to any program is refused while any program of
  the session holds a secret. A tunnel it cannot read (to a model host, or
  every HTTPS tunnel under `--no-net-proxy-mitm`) is judged before each chunk
  by the programs that held it when it opened and by every program holding
  it then that holds a secret: a child forked after the tunnel opened, which
  reads a secret and writes into the inherited connection, has its next
  chunk refused and the tunnel closed, and so does a program holding a
  secret that is handed the connection. Like the per-request check, it does
  not see a program whose descriptors it cannot read (another user's, or
  one of yours that made itself non-dumpable, as `ssh-agent` and
  `gpg-agent` do).
- **A sandbox a program sets up itself, without a pid namespace of its own,
  can be left by a double fork while Mandu's guard runs.** The guard opens
  files and makes network connections for the programs it watches and
  applies each program's own Landlock sandbox to both; it finds the sandbox
  through the program's parents. A process that double-forks out of such a
  sandbox (its parent exits before it opens or connects anything) is no
  longer found, and its file opens and connections are not held to that
  sandbox (the guard's own allow list still applies to the connections). Registered secrets are unaffected (the guard
  matches the file itself), and Mandu's command box and clean box are
  covered (each has its own pid namespace, which the guard also records).
  Affected: third-party sandboxes without a pid namespace, such as Codex's
  own (off by default under the command box), and the quarantined helper's
  network confine (the helper's own code, the process that holds a
  `local-model` file, does not double-fork). See
  `docs/design/confidentiality/confidentiality-plan-10-flow-taint.md` §4.1a.
- **On a network or FUSE mount, what a program holding a secret only looks
  up** (a `stat` or an `open` of a name, an attribute read: the file server
  sees each name asked for) and the offsets of its reads there cannot be
  gated call by call. So a program you named as a reader gets the
  placeholder copy instead of the real file while such a mount (NFS, SMB,
  sshfs and every other FUSE file system, 9p over a network or a socket, an
  automount point) is visible to it, unless the secret is bound to that
  mount or `policy.yaml` trusts the mount for lookups
  (`remote_mounts: trust_lookups:`, by mount point and type; the launch and
  `mandu doctor` name each such mount). A share from the machine's own
  hypervisor or from WSL (virtiofs, 9p over virtio, the Windows drives) does
  not count. Left: a trusted mount's server sees those names and offsets;
  the mounts are judged in the reader's own view when its raw open is
  answered, so a mount that appears after a program already holds the real
  file, and one visible only in another process's view (reached through
  `/proc/<pid>/root`, or by joining another mount namespace), are not.
  Tests: `net-supervisor` `local_exits_integration.rs` (V),
  `visible_mounts.rs`. The byte ranges of the file locks a program holding
  a secret takes there and the `ioctl`s it sends on a FUSE file it has open
  are not gated.
  Writing a file, creating (a socket file included), renaming, linking or removing a name, and
  changing a file's length, mode, owner, timestamps or extended attributes there are, unless
  the secret is bound to that mount; so is an overlay whose writable layer
  is on one (an overlay whose writable layer Mandu cannot find, as for a
  container's root seen from inside the container, counts as such a mount).
  Mandu follows an overlay's `upperdir=` only for an overlay mounted
  outside the agent's reach (in the namespace Mandu's guard runs in), and
  only where the guard itself finds that folder; an overlay the agent's
  programs mount themselves, in a user namespace of their own, counts as
  such a mount whatever folder it names (it could name a local folder it
  laid over the real, remote one), so a program holding a secret writes
  nothing through it until the secret is bound to the overlay itself
  (`mount:overlay:<source>`), even when its writable layer is local.
- **Signals between a tainted and an untainted process** (which signal is
  sent, and when) are not gated. The clipboard is: it lives in the display
  server, a Unix socket a program holding a secret reaches only when the
  secret is bound to it.
  A signal that carries data (`sigqueue`) from a program
  holding a secret to one that does not is refused, and so is such a
  program's write to a named pipe that a program outside Mandu's watch
  reads, alone or beside one inside it, or that no program inside it reads
  (whether the pipe is opened for writing or for reading and writing; a
  named pipe it already had open for writing when it read the secret, read
  by a program outside, refuses that read). Not
  covered there: a program outside that opens the pipe after the write
  began, or one running as another user, or one of yours that made
  itself non-dumpable (as `ssh-agent` and `gpg-agent` do; Mandu cannot
  read its open files), beside a reader inside. A Unix socket to a named
  peer is, and so is a file or shared memory a program
  holding a secret writes: a program that already has the file open or
  mapped when that program writes it (`tail -f` of its log, a `/dev/shm`
  object, System V shared memory, a memfd (one it creates after the read
  too) or an unlinked file it is handed or reopens) is confined like it,
  and one that already holds a connection
  elsewhere makes that write fail. A program holding a secret cannot send
  on a System V or POSIX message queue. The AI agent itself reading a file
  at the moment such a program writes it is not covered.
- **A channel to a program holding a secret, in two cases.** A program that
  reads what a program holding a secret writes into a pipe, a named pipe
  (FIFO) or a socket pair is confined like that program (see the reader
  row above), and so is one that connects to such a
  program's server after it read the secret (a later command's `curl
  localhost:3000` against a dev server that read `.env`: its output reaches
  the AI masked and it may send only where `.env` may go), or that is
  handed one end of a socket pair or a pipe by it, or hands it one; one
  that already holds a connection elsewhere is refused instead. The AI
  agent's own connection to such a server (an MCP server over HTTP, the
  agent fetching a local page itself) is not refused and the agent is not
  confined; what it receives reaches the AI masked
  instead: the result of the agent's own network tools (a web fetch, an
  MCP tool, a tool Mandu does not know) while it is connected to such a
  server, and the page a web fetch hands to its summarizer. The cost: while
  that connection stays open (an MCP server keeps one), every such result
  is masked, even one that held nothing; shell commands and file tools are
  not affected, and an MCP server that reads a secret while the agent is
  connected to it is not refused the file. Also: a
  named pipe such a program writes that the agent reads itself (its
  file-read tool on the pipe), or a file the agent already has open when
  such a program writes it, reaches the AI masked (a file tool's result is
  masked while the agent holds such a pipe or file); a request to such a server
  through Mandu's own web proxy (an address of this machine other than
  `localhost`, such as its LAN address) is refused, for the agent and for
  any command alike, since the proxy cannot say whom the reply is for (use
  `localhost`); and on a kernel older than 5.6, where Mandu does not take
  the server's side of a connection, the agent's own connection is recorded
  when it connects. A program of yours that Mandu does not run (outside
  the agent's process tree) and that reads a pipe such a program writes,
  holds the other end of its socket pair, or reads a named pipe it already
  had open for writing, cannot be confined, so the read of the secret is
  refused, and so is handing such a program a pipe or socket-pair end that
  leads to one, and its own send on a socket pair whose other end has
  reached one since. The agent's own input and output, which Mandu was
  started with (toward you), are not counted. Not caught: a pipe between
  two programs Mandu does not run; a program outside that joins the pipe
  after the read; one running as another user, or one of yours that made
  itself non-dumpable (as `ssh-agent` and `gpg-agent` do; Mandu cannot read
  its open files); a socket pair handed outside after the read and then
  written with `write` or `send` rather than `sendmsg`; and on a kernel older than
  5.6 a request through Mandu's web proxy that the server accepts after it
  read the secret.
- **Known gaps (2026-10-07).** The items below are known and not yet
  closed; each line changes when its fix lands. None lets a secret out on a
  stock setup. Several need what this list calls a steerable holder: a
  program that holds a secret's real bytes and also runs code the agent
  controls. Mandu refuses the obvious ones (a shell, an interpreter, a
  printer, an editor, a program handed code on its command line or steered
  by a configuration file the agent can write), so such a holder exists
  only through the residuals named above: a program you listed that both
  uses a secret and can print or run what it is given (a database client),
  a pinned script that runs code the agent wrote, the configuration files
  of a program you vouch for with `prints: nothing`, or an interpreter
  Mandu does not recognize. Other known limits are stated in their own
  bullets of this section: the names and read offsets a program holding a
  secret sends to a network mount you trust for lookups, and a program you
  pin that carries no mark Mandu knows (a printer of your own, an
  interpreter of a family Mandu does not know).
  - **A secret file's real size under a hard link made from outside.**
    Since 2026-10-09 every name of a protected file, a symlink of any name or
    a hard link made before the launch, shows the placeholder file's size,
    times and inode number in both postures; where Mandu mounts the
    placeholder and a protected file has such a hard link, the launch says
    so, and file lookups are slower that session (`git status` about 3 to 4
    times). A hard link made during the session by a program the agent runs
    is refused. Left: a hard link made after the launch by a program outside
    the agent's tree, where Mandu mounts the placeholder, shows the real
    file's size, times and inode number to a look at it, never its bytes
    (opening it gets the placeholder file); `find` and `du` see the real size
    under a hard link too, where they do under the file's own name (§2, the
    placeholder-file row). Severity low: one number per file, though for a
    file that holds one token the size is the token's length.
  - **Lookups through an overlay whose remote writable layer is out of
    sight.** Writes through an overlay are judged as above (an overlay the
    agent's own programs mount counts as remote), but the names a program
    holding a secret looks up through an overlay, and its read offsets
    there, are withheld only when the network or FUSE mount under it is
    itself visible to the program; one that unmounted that mount from its
    own view (the overlay keeps writing to it) is not withheld its raw
    read. Severity low to medium, as for lookups on a trusted mount. Also,
    the overlay rule assumes the agent's programs cannot mount in the
    namespace Mandu's guard runs in, true unless the agent runs with
    administrator rights over it (as root on the host, or in a privileged
    container).
- **A tool Mandu has no mapping for is masked whole.** With the
  confidentiality axis on (`secrets`, and `full`), the result of a tool
  Mandu has no mapping for reaches the AI as one `no-model` placeholder,
  whatever the session read, on every agent (Claude Code, Codex, OpenCode,
  OpenClaw, Goose): an MCP tool of a server Mandu could not tie to the
  agent's config (a remote server or connector, a server added where Mandu
  does not read), every MCP resource listing and read (Claude Code's
  `ListMcpResourcesTool` and `ReadMcpResourceTool`, Codex's
  `list_mcp_resources`, `list_mcp_resource_templates` and
  `read_mcp_resource`, called directly or from a Codex script cell), a plugin's or an extension's tool, and a tool a new
  agent release adds or renames. The tool result says why and how to let it
  through: list the tool, or `mcp:<server>` for every tool of an MCP server,
  under `mapped_tools:` in policy.yaml (the agent's policy tools cannot add
  one). A tool has a mapping when it is one of the agent's own tools Mandu
  maps (its inbound spec, its gate table, and for Codex, which has no spec,
  a fixed list of its built-ins; a few harness tools whose result is the
  agent's own bookkeeping, such as Claude Code's `ToolSearch`), one of
  Mandu's own, a tool of a local (stdio) MCP server the agent's config
  names (below), or listed under `mapped_tools:`. Those keep the rules
  that follow.
- **A tool with a mapping is masked by what its input names, and by what
  its command's programs read.** For the agents' own tools Mandu knows
  where the path is. For a tool no spec maps (a tool listed under
  `mapped_tools:`, an MCP server's) every string in the call's input is
  checked for a labeled or catalog path, and a hit masks the result. When
  its input also carries a command (`command`, `cmd`, `script`, `code`, …),
  its result is checked against the programs that command ran, as a
  shell's is. If Mandu cannot find those programs (the tool runs code
  in-process), the result is masked whenever any program in the session
  read a secret raw. On Codex the same session rule covers two more
  cases: a script cell whose tool calls Mandu cannot identify one by one,
  and a `wait` that Mandu cannot tie to the cell it continues (a `wait` it
  can tie is checked against that cell's programs). Such a script cell
  runs with every tool Mandu has no mapping for switched off: Mandu puts a
  guard at the head of the cell before Codex runs it, so a call to one
  fails, however the cell reaches it. A cell that does not carry that guard
  (one written before it, or under the `off` mode) is masked whole when it
  names such a tool or may reach a tool by a name it builds. A local (stdio)
  MCP server that the agent's own config names (its
  user, project and local configs; also Claude Code's
  managed file, its installed plugins' servers and a `--mcp-config` on its
  command line, and Codex's `-c mcp_servers…` overrides) is mapped to the
  process the agent starts for it, on Claude Code and Codex: its
  results are masked whenever that server, or a program it started, read
  a secret raw, and a server proven clean is not masked by the rest of the
  session. Mandu reads that config again whenever one of its files changes
  during the session, and until the new read is in, no server of the
  session counts as proven clean; a server whose command line changed is
  mapped to both, and is proven clean by neither. A configured server
  Mandu sees start more than once, or not with a command line its config
  names, is masked once any program of the session has read a secret raw
  (`ssh` with a default key, or a reader you vouched for with `prints:
  nothing`), for the rest of the session (an MCP server can hold what
  reached it unseen). A server started through `npx` on a machine with a
  `~/.npmrc` counts as having read it (npx reads it first), so its results
  are masked. For a moment after the agent rewrites one of its config
  files (Claude Code rewrites `~/.claude.json` during a session), a server
  proven clean is masked that way too. You still see the originals in the
  reply. An MCP tool
  whose input carries a command is also checked before it runs, on both
  agents, as a shell command is: in a session that has read a secret into
  the AI's context it is stopped and waits for your *Allow once* in
  Approvals, as a shell command and a request to an unbound host there do
  (one run of that exact command, or one request, per answer; a *Block*
  holds for the session). Output read back later by a tool that polls a
  background process is checked too: Codex's `write_stdin`
  takes the check of the `exec_command` that started the process it polls,
  and Claude Code's `BashOutput` and `TaskOutput` and OpenClaw's `process`,
  which name no command, are masked whole once any program of the session
  has read a secret raw. Claude Code's background output file, which its
  `Read` returns, takes the label of a reader that wrote into it. Registered secret files are
  unaffected either way (the guard serves every program except a listed
  reader their placeholder copy). See
  `docs/design/confidentiality/confidentiality-plan-10-flow-taint.md` §11.11 to §11.13, §11.17 and §11.18.
- **A tool that uploads a local file by its path is checked by the paths it
  names, when the call is made.** Some tools read a file themselves and send
  it off this computer, so its bytes never reach the AI and no placeholder
  is ever made for them. Claude Code's `DesignSync` (`write_files` with a
  `localPath`) is one Mandu knows: each file is checked before the call
  runs (§2), and its plan must name its folder by an absolute path (a plan
  that does not is refused with a note saying how to call it). Claude
  Code's `Artifact` (a page `file_path` and its `files`) and `ArtifactData`
  (a `file_path` JSON document) are others, checked the same way; each path
  must be absolute (a `files` source may be relative to an absolute
  `root`), and a path relative to the agent's working folder is refused
  with a note saying how to call it. Their bytes go to `api.anthropic.com`
  (read off Claude Code 2.1.302), a host the egress proxy did not carry, so
  this check is the decision these uploads meet (since 2026-10-18, with the
  egress proxy's model-host deny, their requests also pass its inspection,
  which checks them for your registered values). OpenClaw's `message`
  attaches files to a chat channel send (from `media`, `path`, `filePath`,
  `mediaUrl`, `fileUrl`, `image`, `mediaUrls`, every `attachments` entry,
  and a channel plugin's own path fields), its `browser` uploads files into
  a page, and its `view_image`, `image`, `pdf` and media generators load
  files into a model: each file is checked the same way (until 2026-10-17
  `message`'s attachments were not). The chat channel and the page are no
  host Mandu can name (OpenClaw delivers through its own process or a
  gateway, to a channel whose address is configurable), so a binding never
  releases a secret file there: it is held for your OK. A model-bound file
  labelled `any-model` goes (its level admits every model); a
  `local-model` or `no-model` one is held, since the model it reaches may
  not be local. A relative path is placed in the launch folder when Mandu
  knows OpenClaw reads it there, and refused with a note otherwise (always
  for `browser`, which reads it in its own uploads folder); a reference to
  OpenClaw's own media store (`media://`) is refused the same way. A large
  image, video or PDF is checked too: Mandu reads it in pieces, looking for
  your registered secrets, and lets it go if none is in it (since
  2026-10-17; before, anything over 8 MiB was held). A file over 256 MiB,
  or one that takes more than 45 seconds to check, cannot be checked and is
  held for your OK. OpenClaw also attaches every
  file a `MEDIA:` line of the AI's own reply names when it sends the reply
  to a chat (no tool call at all): Mandu reads each reply on its way to
  OpenClaw, checks each file such a line names the same way (held for
  your OK if it is a secret; the line then reads `[mandu] attachment not
  sent, …`), holds every file a reply names when that reply also calls a
  tool (the tool runs before OpenClaw reads the file), and breaks every
  other spot where OpenClaw would see a `MEDIA:` line once it strips
  markup from the reply (its colon becomes a lookalike); until 2026-10-17
  such a line attached the file unchecked. What is left:
  - *The file is checked when the call is made, not when the tool reads
    it.* An upload after another call of the same turn that could change
    files is refused (the agent runs that call first), but a program
    already running in the background (a shell started earlier with `&`)
    can still change the file between the check and the read. Under
    `confined` the file guard's placeholder copies still cover a
    registered secret file or a labelled one written that way; a file that
    merely holds a copy of a registered value is not covered, and an
    *Allow* you give is for that path.
  - *A tool Mandu has not mapped is checked by every local path in its
    input* (absolute, `~/`, `file://`; a relative one only under a key
    such as `path` or `file`, placed against the folder the agent was
    started in), with no host, so a binding releases nothing: a path to a
    secret file, to a file holding a registered value, or to a file Mandu
    cannot read is changed to one that names no file, and held for your
    OK. A path Mandu cannot recognize as one (a relative path under any
    other key, a path inside prose) is not checked, nor are the files
    inside a folder it names (only the folder's own label and the
    sensitive places). A path that names nothing yet passes, unless an
    earlier call of the same turn could create it. A tool of an MCP server
    the launch registered as a local program is not checked in a
    `confined` session: the guard confines that program like any the agent
    runs. Its result is masked whole while unmapped, as before.
  - *On Codex* the same check covers its MCP tools and any tool Codex does
    not ship (its own shell, patch, file and sub-agent tools keep their own
    checks), whether the call is made directly or from a code-mode cell. A
    cell whose call would send a held file does not run at all (it is
    replaced by one that prints why). In a cell Mandu cannot read call by
    call, only the paths the cell spells out are checked: a path the cell
    computes while it runs is not. Codex runs a call of an MCP server one
    at a time after the turn's earlier calls, so an upload after a shell
    call of the same turn is refused as above; a server you configure with
    `supports_parallel_tool_calls = true` runs its calls beside the turn's
    other ones, and a call that comes later in the same turn can then
    change the file while it is sent.
  See `docs/design/agents/supported-agents.md` §2, "The upload residuals".
- **Your prompt is sent as you type it, except registered secrets.** A key
  Mandu does not know (one you paste from somewhere Mandu never registered)
  reaches the AI as typed, and so does a short or simple registered value you
  type yourself (see §2). Filters that catch key shapes, personal data or an
  organization's code names are available and off by default
  ([Checking your own prompt](usage.md#checking-your-own-prompt)). A
  classifier you turn on (Mandu's own, `mandu policy classifier-pack`, or
  a plugin of yours) is a model and can miss things; what it misses goes
  as typed. It reads a long message in overlapping pieces, so a span of up
  to 1000 characters is never cut in two. It runs only from verified copies
  of the files its pack pins by SHA-256 (the program, the script and every
  module it loads): a pinned file that changed blocks the prompt (the
  default `on_error`), and nothing else of the folder it was installed in
  is readable to it where Landlock or the namespaces confine it.
- **`secrets` mode does not stop prompt injection.** An instruction hidden in
  a web page can still steer the agent to send out something that is not a
  registered secret, such as your source code. Masking untrusted text is the
  job of the `injection` and `full` modes, which are frozen and experimental
  (opt-in with `MANDU_EXPERIMENTAL_INTEGRITY=1`, no longer developed, with a
  utility cost and their own evidence). In `secrets` mode the claims of §2
  still hold when injected text steers the agent (the threat model in §4
  assumes it does), but nothing keeps that text from steering it.
- **A host you bind a secret to receives it wherever the agent puts it.**
  A binding you make (a label's `bindings:`, an `env.sources` entry, a
  `models[].token_env`, or an *Always allow* in Approvals) lets the egress
  proxy put the real value back anywhere a placeholder sits in a request to
  that host: its URL, its body or any header. A host that stores or
  publishes what it receives (GitHub, an issue tracker, a pastebin, a
  package registry) can therefore be made to publish the value by an agent
  that an instruction hidden in a web page steers. Bind a secret only to a
  host you would trust with it in any request. Asking you about a send that
  injected text may have steered is the job of the frozen modes; `secrets`
  mode does not. The bindings Mandu makes on its own are narrower: the
  `~/.npmrc` token, a `pip.conf` or `PIP_INDEX_URL` index password at the
  host its own file or variable names, an agent's own key under `mandu
  goose`, and a key whose format names its issuer at that issuer's own API
  host (since 2026-10-19), are put back only in the request's sign-in header
  (`Authorization`, or the provider's key header for Goose's key); the
  same placeholder anywhere else in that request gets it refused (403), and
  no approval changes that. Before 2026-10-09 they too were put back
  anywhere, so an agent could have had `npm publish` put your token in a
  package's description. `~/.git-credentials` gets no binding unless you
  give it one, and then it is yours.
- **macOS is read-blocked, not confined; Windows has no secret protection.**
  The dry run and the launch say which posture you have. On macOS a program
  the agent runs cannot read a credential file at all (no placeholder, so a
  tool that needs one, such as `aws` with `~/.aws/credentials`, fails) and no
  program can be allowed to read one. What the macOS profile (§2a) does not
  cover:
  - **The Keychain.** `security` and the Keychain services stay reachable
    (Claude Code keeps its own login there), so a token kept in the Keychain
    (`gh`, Docker Desktop, `git credential-osxkeychain`) can be printed by a
    program the agent runs.
  - **Services reached over Mach or XPC.** Only the six launchers are
    denied: a copy of `launchctl` still runs (a copied `open` or `osascript`
    is killed by code signing), and a program that talks to launchd or
    another service directly can have code run outside the profile. That
    code runs as you, outside Mandu: it can read your files and Mandu's
    folder, and it can change Mandu's git-history caches without a session
    end voiding the change, so a later `mandu doctor --secrets` or `mandu
    policy suggest` can miss a finding (confidentiality-plan-14 §11.2).
  - **A hard link made before the launch.** A second name for a credential
    file that already existed is not covered.
  - **Git history.** The committed bytes of a protected file stay readable
    (`git show`, `git log -p`), and so do the versions a history lock covers
    (a `blobs:` lock, a labelled path that no longer exists, the arbiter's
    global locked set): no lock is enforced on macOS. The launch prints one
    warning naming each of its repositories (the workspace, a protected
    file's) where one is committed or staged or a locked version is held; a
    repository whose labelled paths Mandu has not resolved yet is named as
    not checked. Linux hides them. Both lookups run the `git` found on your
    `PATH` ("Every file that runs later" above).
  - **Files that run later are refused, not asked about**, and the list's
    network pinning is by port only (as landlock-net; the connect guard that
    pins :443 to named hosts is Linux only). The folders on your `PATH` and
    Mandu's own launcher outside its install folder are not on the list
    ("Every file that runs later" above): the agent can put a program in
    `~/.local/bin` or `/opt/homebrew/bin`, or change a `mandu` it can write,
    and that runs outside the profile later. The programs that apply the
    profile and relay the terminal around the agent (`/usr/bin/sandbox-exec`,
    `/usr/bin/script`, `/bin/ps`, `/bin/stty`) are named by full path, so a
    planted copy is never run in their place.
  - **Sockets the agent's programs open outside the workspace** are refused
    (Linux admits any socket the agent's own tree listens on); list them in
    `unix_sockets:` or `MANDU_UNIX_ALLOW`.
  - **Every socket under the workspace is admitted**, because the profile
    cannot ask who listens on one. Launched from your home folder (or a
    folder above many projects), the agent's programs reach every Unix
    socket under it except the refused ones: docker and its kin, a host tmux
    server, and the control sockets of WezTerm (`~/.local/share/wezterm`),
    iTerm2 (`~/Library/Application Support/iTerm2`), kitty (when
    `KITTY_LISTEN_ON` names one) and an Emacs server. Another program's
    control socket there, one that types into a window or runs code, is
    reachable. Launch from the project folder.
  - **Another session's folder in Mandu's runtime folder.** The runtime
    folder stays writable (the session's own folder is in it). A session
    folder the agent makes in advance for a later launch is refused by that
    launch, and every launch hands its profile to `sandbox-exec` directly
    rather than through a file there. Mandu never writes through a link
    planted there: every file it writes in a session's folder (a proxy's
    port file, the agent's and MCP configs, `launch.log`, the guard's
    status record) is created fresh and renamed into place, a log Mandu
    appends to is opened only through real folders of yours or the
    system's (a `logs` folder replaced by a link to another folder gets no
    log there), and `mandu reap` deletes nothing through a link.
    But while another session runs, its folder is open to this agent: a
    file Mandu writes there as that session starts can be replaced by
    another one before it is read. A session named with `--id` reuses a
    folder that already exists.
  - **A nested sandbox cannot start** under the profile. Claude Code's own
    sandbox and Codex's per-command sandbox cannot run inside Mandu's
    Seatbelt profile (a nested `sandbox-exec` fails with "Operation not
    permitted"), so Mandu turns them off for the session and says so at
    launch. Their own limits on where commands write and connect then do not
    apply, and Mandu's profile does not replace them: it blocks credential
    reads, writes to files that run later, and TCP but to its proxies and
    ports 443 and 22. When the run asks for the agent's sandbox, managed
    settings require it, or it protects something Mandu does not, Mandu
    keeps it on and warns that the agent's commands will fail
    (`docs/design/confidentiality/confidentiality-plan-10-flow-taint.md` §12.3).
  - **Background processes and the session's end.** On macOS, what the agent
    starts in the background ends with the session, except a process that
    moves to a new session and loses its parent within about a second (a
    double-fork daemon, or `cmd &` inside one Bash call)
    (`docs/design/distribution/portable-wrapper.md` §3.5).
  - **Tested on one Mac so far** (macOS 26.5.1, arm64; 2026-09-29): a live
    `mandu claude` session, print mode and the interactive TUI, besides the
    probes and the `--target shell` launch above
    (`docs/design/distribution/packaging.md` §6 item 1). `mandu codex` was tested on
    2026-10-01 and 2026-10-02 (Codex 0.159.3, `codex exec`): its model turns
    go through Mandu, and its commands run with Codex's own sandbox off
    (Mandu turns it off for the session), confined by Mandu's profile.
- **The `gated` posture is honest about being weaker.** It prints on every
  launch and on the dashboard; `--require-confinement` refuses to launch
  instead, the `bwrap`-only case included (test:
  `tests/sandbox/bind-only-posture.test.ts`).
- **A bubblewrap that follows symlinks while it sets up a sandbox**
  (CVE-2026-87766; bubblewrap before 0.12.0, and Ubuntu 24.04's
  `0.9.0-1ubuntu0.3`, which dropped the backported fix). `mandu doctor` and
  every launch that uses the mount check the binary itself (one sandbox
  start onto a symlink) and warn, naming its version; where that sandbox
  cannot start, a version older than 0.12.0 warns too, saying the version
  proves nothing either way (distributions backport the fix and have
  removed it again) and what to check instead. They never refuse
  ([rootless-confinement-ubuntu-2404.md §13](design/confidentiality/rootless-confinement-ubuntu-2404.md)
  has why). What it exposes: the
  command box, nothing (its writable mounts are a private /tmp and either
  the AgentView or, in `secrets` mode, your project folder, both of which
  the agent can already write). The whole-agent mount is
  built once at launch over the real root; a program of yours already
  running (another session's agent) can race that setup, swap a credential
  file's folder for a symlink, and so leave the real file visible or make
  bubblewrap create an empty file where it chooses. The guard's lookup by
  path still hands out the placeholder, so this matters only without the
  guard, which is `gated` anyway. Fix: a bubblewrap with the fix (the
  distro package when it ships one, or 0.12.0 or newer).
- **A policy edit made while Mandu is not running.** A hand edit of
  `policy.yaml` that loosens a rule is not applied until you approve it in
  Approvals, in every mode and whether or not the agent is confined (test:
  `arbiter/test/component/policy-disk-hold.test.ts`). One you decline is written
  back out of the file, and neither a declined edit nor one still waiting is
  the law after a restart (test:
  `tests/sandbox/policy-restore-and-guard-settings.test.ts`).
  But an edit made while Mandu was not running, that you were never asked
  about, applies at the next start without a question
  ([policy-surface.md §8.4.6](design/ui/policy-surface.md)).

### Residual risk in Mandu itself

The claims above assume Mandu's own parts work as written. Three of them
are attack surface the agent can reach:

- **The supervisors.** The connect guard and the open trap parse data from
  the agent's processes (socket addresses, paths) while those processes wait
  on a seccomp trap. A memory-safety or logic bug there could let a process
  out of the rules it was launched under. The guard is Rust with its decision
  logic unit-tested in isolation; that narrows the risk and does not remove
  it. The guard runs as your user, and the agent cannot stop it: signals
  (by pid, by thread id, by descriptor), tracing, resource limits and
  scheduling calls aimed at it are refused. If it dies anyway (a crash, or a
  kill from outside the session), the agent's processes fail closed and the
  session ends with a warning
  ([rootless-confinement-ubuntu-2404.md §12.2](design/confidentiality/rootless-confinement-ubuntu-2404.md)).
- **The arbiter.** Its socket is reachable from the agent's process tree
  (Mandu's own command shims use it). Writing policy and approving requests
  need a separate admin channel the agent is never given (a loosening
  written straight into `policy.yaml` waits for that channel too), but a parser or
  logic bug in the operations the agent can call is within an injected
  agent's reach. The records the confinement rests on (which process
  started which, which tool call a shell ran, which program opened a file
  raw and whether the agent could have written it) are believed only when
  the guard and the model proxies send them on the arbiter's second socket,
  the one the agent's processes cannot reach; the same record sent on the
  socket the agent can reach may add protection but never removes any
  ([plan 13 §3 D9](design/confidentiality/confidentiality-plan-13-reader-set-labels.md)).
  An older guard binary that still reports on the reachable socket gets
  the placeholder for every protected file it would have let a program
  read: rebuild it with the new version. A launch with no wall around that
  second socket (`gated` with neither the guard nor the mount layer, or
  `off`) lets its agent's programs reach it, so while one runs the arbiter
  believes no such record from that socket either; a confined launch
  started beside one warns, and `--require-confinement` refuses it
  ([arbiter-human-plane.md §10.1](design/architecture/arbiter-human-plane.md)).
  That costs the confined session work, never protection: while such a
  launch runs, the confined session's secret files open as placeholders,
  its writes to protected files are refused and its shell output is masked
  once it has read a secret. Mandu says so where you look: the confined
  session's terminal prints one warning naming the other launch (its
  process id and session) and the fix (stop it, or start it again with
  its file guard on, without `--mode off` or `--no-net-guard`), a line
  when the guard is believed again, and a recap after the agent exits;
  the dashboard's Home page shows the same notice, and the developer
  view's Policy panel (on its Rules page) a `human plane exposed` chip
  ([arbiter-human-plane.md §10.1.1](design/architecture/arbiter-human-plane.md); tests:
  `tests/stack/human-plane-exposure-notice.test.ts`,
  `tests/sandbox/exposed-human-plane.test.ts`).
- **The egress proxy.** In `secrets` mode it terminates TLS with a
  per-session certificate authority the agent's tools trust, and it holds the
  real values it puts back into requests. A bug in it could release a value
  to the wrong host or accept a certificate it should not.

An event the arbiter did not get from Mandu's own components on the socket
the agent cannot reach is marked "claimed" in the log, on the dashboard and
in the SIEM feed: a program the agent runs can write one, and nothing
Mandu decides reads it
([arbiter-human-plane.md §10.2](design/architecture/arbiter-human-plane.md)).

The event log is written by the arbiter as the user and is hash-chained:
each line carries a link over the one before, so an edited, dropped or
reordered line is detectable (the arbiter's `verifyEvents` names the first
break). A chain is evidence, not a lock: a process with the user's own
permissions outside the agent's confinement could rewrite the file and
recompute every link. What anchors it is the SIEM exporter, which forwards
each line with its link off the machine. Report a bug in any of these as
described in [`SECURITY.md`](../SECURITY.md).

## 4. The threat model in three sentences

The adversary is the agent itself, driven by text it reads, together with
every program it runs, with the user's own permissions on a machine the user
controls. It may run arbitrary code, including native code, and it may try
any system call, but it cannot escape an unprivileged user namespace or the
seccomp filter installed before it started. The model vendor is honest but
must not be trusted with the bytes, which is why the guarantee is about what
reaches the wire, not about what the model promises.

## 5. How to check it yourself

```sh
mandu doctor                 # posture, what is live, what is missing, never a claim it cannot keep
mandu doctor --secrets       # the dry run: files, variables, what is left raw, keys in git history, would a launch start
mandu claude                 # the launch line names the mode and the counts
mandu dashboard              # every masked read, every held open, every release, with the placeholder and the value side by side
```

The automated evidence is in the repository, and every suite is listed in
`tests/suites.mjs`: `scripts/test-all.sh` runs the unit, end-to-end and kernel
suites (the frozen integrity suites run with `scripts/test-all.sh --integrity`),
and each claim above names the public test that asserts it.
`scripts/ci/vm-run.sh` runs the unit, component, stack and sandbox suites on
your machine, in a throwaway KVM guest with no network, as the maintainers'
CI runs them on every push. The maintainers also run agent drills: the real
agent CLIs and the real launcher around real reads, against a scripted model
on every push and a real model per release. The drills are their evidence
tooling and are not published; what they show, property by property, is in
[drill-results.md](testing/drill-results.md), regenerated at each release.
To get the drills themselves (for research, say), write to
hello@mandusecurity.com. The public GitHub CI
runs only the unit, component and stack suites: GitHub's runners cannot
create the unprivileged user namespaces the sandbox suites need, and do not
carry the pinned agent CLIs
([continuous-integration.md §12](design/testing/continuous-integration.md)). The fresh-install suite
installs the npm tarball on a throwaway Ubuntu 24.04 and 26.04 and asserts
the first launch keeps a canary from the agent.

**If you use your own model** (`local-model` files, `models:` in
`policy.yaml`): `mandu doctor` has a "Your own models" section with one row
per declared model (its address, whether it answers, whether the named
model is loaded, a hint when a model you called local is not on this
machine or a private network, and a ✗ for a cloud model declared local),
plus a row for `ANTHROPIC_BASE_URL` or `MANDU_OPENAI_BASE_URL` when you set
one. In the dashboard, the story of a summarized file says "Read by your
own model (<name>)". A live test checks the whole claim on your machine,
with a real Claude Code session on your subscription and an Ollama serving
`llama3.2` on `127.0.0.1:11434`: the file reaches your model and never the
vendor, on every wire together (it SKIPs without the Ollama):

```sh
cd tests && MANDU_LIVE_LOCAL_MODEL=1 npm run test:env:local-model
```

## 6. Where the detail is

- `docs/design/confidentiality/confidentiality.md` — the label model, the levels, the release
  rules, the claim scoping (§10) and the evaluation (§12).
- `docs/design/confidentiality/confidentiality-plan-10-flow-taint.md` — readers, the per-app
  output rule, the taint, what it does and does not close (§6), the
  measurements (§7, §13).
- `docs/design/confidentiality/model-endpoints.md §1` — the
  `local-model` level and `models:`: where a file may go per model, your own
  model as the helper or as the main model, what is not claimed (§3), and
  the live run's record (§8).
- `docs/design/confidentiality/rootless-confinement-ubuntu-2404.md` — the postures and the
  no-sudo story.
- `docs/design/confidentiality/secret-discovery.md §1` — the dry run and the
  fixture-home table.
- `docs/design/architecture/privilege-model.md` — why nothing needs root, and the
  cooperative-versus-hard boundary.
