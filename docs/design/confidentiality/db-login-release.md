# The database login release

Status: **BUILT (2026-10-24)**: Postgres (§2 to §7) and MySQL (§8);
`PGPASSWORD` / `MYSQL_PWD` bound to their host variable since 2026-10-25
(§3.3.1). Decision note on
the wire release ([`confidentiality-plan-10-flow-taint.md`](confidentiality-plan-10-flow-taint.md)
§11.5): how a database client in the agent's world logs in with the
placeholder its password file or variable holds, without the password ever
entering that world.

## 1. The problem

In `secrets` mode a program the agent runs reads `~/.pgpass` as a
placeholder copy and sees `PGPASSWORD` as a placeholder. The egress proxy
puts a placeholder back only inside an HTTP request it can read; a database
login is no HTTP request, so until now a `psql` login with a masked password
failed (plan 10 §11.4, "A masked database password logs nothing in"), and
the ways out were a socket login with no password, a non-printing reader
program, or exempting the variable (which hands the AI the password).
`psql` itself can never be a reader: it prints files when asked (plan 13
D8). That is the "Partly" on R4 ("programs can still use it") for
databases.

## 2. The design in one paragraph

The egress proxy opens one loopback **relay** per database the launch's own
files and environment name. The connect guard performs the agent tree's
connects to that database's address and port on the relay instead
(`mandu-net-guard --redirect`). The relay speaks the Postgres login to both
sides: it forwards the client's startup to the server, and when the server
asks for a password (md5 or SCRAM-SHA-256) it asks the **client** for its
password in cleartext on the loopback leg, runs that placeholder through
the egress gate as the login's credential at `host:port`, and answers the
server's own method with the value the gate put back. After
AuthenticationOk it copies bytes both ways. The password exists only inside
the egress proxy's process and in the server's exchange (where SCRAM and md5
never carry it); the client, and so the agent and the model, only ever hold
the placeholder.

## 3. Decisions

### 3.1 How a connection reaches the relay: the guard's redirect

Considered: pointing `PGHOST` at the relay (breaks `psql -h db.internal`,
and every other host), an `/etc/hosts` mapping inside the agent's mount
namespace (no IP literals, a mount the launch does not otherwise make),
and the guard. Chosen: **the guard**. It already performs every allowed
connect itself on its copy of the tracee's socket (TOCTOU-safe); a redirect
only changes the address it connects that copy to. So every client works
unchanged (`psql`, libpq, a JDBC, Go, Python or Node driver, an IP literal),
and the database's own address stays denied: the tracee never connects
anywhere but the relay. Details (`net-supervisor` `guard.rs`
`redirect_for`, `guard_kernel.rs`):

- A redirect is `tcp:<host>:<port>=<loopback>:<port>`, one host and one
  port, TCP only; a host name is resolved by the guard's resolver like an
  allow rule's. An always-denied destination or a `--deny` one is refused as
  it is, never redirected.
- The connect is decided **at the relay** (its loopback allow rule), and the
  relay ports are session-proxy ports: a process holding a secret reaches
  the relay, which judges its taint itself (§3.4), as the egress proxy does.
- With no copy of the socket (a kernel without `pidfd_getfd`, a copy that
  failed) a redirected connect is refused, never CONTINUEd: the kernel would
  connect the tracee's own address.
- An IPv6 socket gets the IPv4 relay as its v4-mapped address; a socket
  set `IPV6_V6ONLY` then fails to connect (a utility failure, not a leak).

Where there is no guard (macOS, a kernel below 5.6, the bin not built) there
is no redirect, and a database login fails as before.

### 3.2 Which databases get a relay

The launcher (the human's side, before the agent runs; `launcher`
`db-relays.ts`) reads the host and port fields, never the password, of each
line of the password file (`PGPASSFILE`, else `~/.pgpass`), and `PGHOST` /
`PGPORT` when `PGPASSWORD` is set. A `*` host names no one database and a
socket directory no TCP one: neither gets a relay. At most 32 relays; more
are named in the launch's notes. Only with the confidentiality axis on.

### 3.3 Which password is put back where: the file's own wire grant

A `.pgpass` line names the database its password is for. The launch HOME's
`~/.pgpass` is a wire file (`registry.ts` `HOME_WIRE_FILES`, as `~/.npmrc`
and `pip.conf` are, plan 10 §11.13.1): each line's password field symbol is
bound to that line's `host:port` (a `*` port as 5432, the port the relay
serves; `pgpassWireHost`), recorded as its wire grant. A wire grant is put
back only in the request's credential position
(`egress:secret-wire-position`): the relay presents the password as the
login's `authorization`, its only position. And it is put back **only in the
relay's login**: the relay states the scheme `postgres` on its gate request,
the HTTP legs state `http` or `https`, and the arbiter refuses a `.pgpass`
grant in any request that does not state `postgres`
(`egress:secret-db-login-only`, `wireSchemeRefusal`; `wireReleaseScheme`
answers `postgres` for such a field, and for one the file no longer has).

Security review (2026-10-24), finding 1: before this rule the grant was an
ordinary binding, which the HTTP egress proxy honours too, so `curl -x
$HTTP_PROXY -H "Authorization: <placeholder>" http://db.internal:5432/` got
the real password back, in cleartext; and a `*` port line bound the bare
host, every port of it and every host under it. Both are closed (the stack
e2e's step 3b, `rule-ref` units). A copy of the file elsewhere (a workspace `.pgpass`, a
`PGPASSFILE` outside HOME) gets no grant: its passwords are released where
the label's `bindings:` say, or asked for. `PGPASSWORD` gets its wire grant
from `PGHOST` (§3.3.1).

Who reads the twin (2026-10-25, found by the live run,
[`live-clients.md`](../testing/live-clients.md) §4.1): `psql` and
`pg_restore` are printers and always did. `pg_dump` is a known consumer of
the file that is neither a printer nor vetted, so its open was ASKED for the
raw file (plan 13 D8 (12)): refused where nobody answers, after which libpq
had no password and pg_dump prompted for one. It now reads the twin, unasked
and untainted, in a session whose proxy inspects TLS when every line's
password is bound to its own database (`wireServableDbTwin`, beside npm's
`wireServableTwin`): the relay puts each back. A `*` host line (no relay, no
binding) keeps the ask.

The twin had to change too: libpq reads a `.pgpass` password up to the first
unescaped `:`, so the token `$MDU:…` was read as `$MDU`. A pgpass span is
now `encoded: "pgpass"`: its value is the password as libpq reads it
(escapes removed, `pgpassPassword`), and the twin writes the token with its
`:` and `\` escaped. So a `.pgpass` twin read back holds `$MDU\:…`, never
`$MDU:…`: the model-side twin release reads that form as a token
(`escapedTwinTokens`), and so must anything that counts placeholders in a
program's output (the fixture-home sandbox test counted `$MDU:` only and
missed it, 2026-10-25).

### 3.3.1 `PGPASSWORD` and `MYSQL_PWD`: bound to the host variable beside them

Decided by the maintainer 2026-10-25, the way pip's index variable is bound
to the host its own URL names (plan 10 §11.13.1). The launcher registers
its whole environment in one `registerEnvSecrets` call (it always sent
every variable), so the arbiter reads the database next to the password:
`PGPASSWORD`'s row is bound to `PGHOST` at `PGPORT` (5432 when unset or
empty), `MYSQL_PWD`'s to `MYSQL_HOST` at `MYSQL_TCP_PORT` (3306), exactly
that `host:port` (`secret-extract.ts` `dbEnvWireHost`, `envSecretSpan`'s
`launchEnv`). It is a wire grant like a `.pgpass` line's: recorded when the
launcher registered it on the human plane, in the arbiter's memory only on
the data plane (confidentiality.md §2.1), and put back only in the
credential position of the relay's own login.

- **No binding** (the login asks, as before) for: no host variable, an
  empty one, a socket directory (`/…`) or an abstract socket (`@…`),
  libpq's several hosts (`a,b`) or several ports, a `*`, whitespace, a
  port that is not a number in 1..65535, or any host that does not parse
  (`pgpassWireHost`'s rule: a DNS name, an IPv4 address, or an IPv6
  address, bracketed and canonical; a zone id binds nothing). Unparseable
  is never bound.
- **A database on this machine.** `PGHOST=localhost` (or `127.0.0.1`,
  `::1`) is bound like any host: libpq connects there over TCP, as for a
  `.pgpass` line naming `localhost`, and the relay checks who holds the
  listening end before it sends a byte (§3.7). `MYSQL_HOST=localhost` is
  the client's socket, not TCP, so neither a relay nor a binding, as for a
  `~/.my.cnf` section (§8.3); `MYSQL_HOST=127.0.0.1` is TCP and bound.
- **Only the variable's whole plain value.** A `PGPASSWORD` holding a URL
  (its password is masked as any URL's) is not what libpq sends, so it is
  not bound.
- **Precedence, as for pip's variable.** An `env: exempt:` of the variable
  wins: it is not masked, so nothing is bound (the AI holds the value).
  An `env.sources` entry's `bindings` are added beside the automatic host
  (both release); a host in them is the user's, so the position rule does
  not narrow it (`releaseRestsOnWireGrant`).
- **The relay's login only, whatever binds it.** A database password
  variable's row answers its login's scheme (`wireReleaseScheme`:
  `postgres` for `env:PGPASSWORD`, `mysql` for `env:MYSQL_PWD`), bound or
  not, by its own host variable or by a binding of yours, so the egress
  proxy refuses its placeholder in any HTTP or HTTPS request
  (`egress:secret-db-login-only`, §3.3's security review finding 1); before
  this change an unbound one was an Approvals card there, and one you bound
  in `env.sources` was put back over HTTP too.
- **A later launch without the host.** The row is reused by value across
  launches; a registration that names no host drops the earlier launch's
  recorded host (`dropWireGrant`), so the binding always follows the
  current environment. A second launch naming another host replaces it
  (one wire host per row), so an earlier session still running asks at
  its own host from then on: the fail-closed direction.

### 3.4 The gate, the same as every leg

Before the server is even dialed, the holders of the client's socket are
judged at `host:port` by their secret taint, and the §4 tripwire runs over
the startup's parameters (`user`, `database`, `options`,
`application_name`: bytes a process holding a secret could fill). This holds
for a trust login too, and for a CancelRequest. Then, when the server asks
for a password, the relay calls `gateRequest` with the login as a request to
`postgres://host:port/` whose `authorization` is the client's password:

- the holders of the client's socket (`/proc`, plan 13 D6) are judged first:
  a process holding a secret bound elsewhere is refused before any ask, and
  an unattributed connection is refused while the session holds a secret;
- each placeholder is decided at `host:port`: bound (the wire grant, a label
  binding) → put back; unbound → an Approvals card, refused unless held and
  answered;
- the §4 tripwire runs over the password as the client sent it: a raw
  registered value at a host it is not bound to is refused;
- the arbiter unreachable → refused. "Send without it" makes no sense for a
  password and is refused;
- another secret's placeholder as the password is decided by its own
  rules, at this scheme: an AWS key's grant is HTTPS only, so it is refused
  in a login to an `*.rds.amazonaws.com` database too, and the SigV4
  re-signing check (aws-sigv4-resign.md) accepts only `http` and `https`
  and refuses a SigV4 header in any other scheme (fail-closed, 2026-10-25;
  `sigv4-gate` unit, the stack e2e's step 3c).

A password with no placeholder (a reader holding the real file) is sent as
given, subject to the same holder judgment and tripwire. After the login,
each chunk the client sends is judged again by the holders' secret taint, as
a blind tunnel's (a child forked later that read another secret closes the
connection).

### 3.5 The server's methods

| Server asks | The relay |
|---|---|
| trust (AuthenticationOk at once) | passes it on; no password asked, nothing resolved |
| md5 | answers `md5(md5(password ‖ user) ‖ salt)` wherever your own psql would: libpq's defaults (`sslmode=prefer`, no `require_auth`) answer it over plain TCP, and the relay refuses it where your `PGSSLMODE`, `PGREQUIREAUTH` or `PGCHANNELBINDING` would. Why not stricter (review finding 4, decided 2026-10-24): md5's answer is crackable offline by whoever receives it, but the relay's target is fixed at launch from your own files, a listener on this machine is checked first (§3.7), so the remaining exposure is a network attacker in the path, the same one your psql has without Mandu; refusing md5 without verified TLS would break the commonest setup (a local or LAN Postgres with md5) and leave R4 at Partly |
| SCRAM-SHA-256 | the client side of RFC 5802 / 7677 (no channel binding, gs2 `n,,`), the password SASLprep'd as libpq does; an iteration count below 4096 (Postgres's default) is refused before the proof is sent (review finding 3); the **server's signature is checked**, and a server that cannot prove it knows the password is cut off before the client is told anything but the refusal |
| cleartext password | only over TLS whose certificate was verified against your root certificate (§3.6); else refused |
| GSS, SSPI, Kerberos, any other | refused (no password to give) |

Every refusal reaches the client as an ErrorResponse (SQLSTATE `28000`,
`08006`, `08P01` or `0A000`) whose message starts `mandu:` and says why, so
`psql` prints it; it never names a value.

### 3.6 TLS

- **Client side** (loopback): the relay answers the client's SSLRequest
  with `S` and the session CA's leaf for the database's name when TLS
  inspection is on, else `N`. The agent's `PGSSLROOTCERT` is set to your own
  Postgres root certificate followed by the session CA (`writeDbRootCert`),
  so `sslmode=require` (which verifies when a root certificate exists) and
  `verify-full` (the name on the leaf) both pass. Bytes sent before the
  handshake are refused (CVE-2021-23214's shape).
- **Server side**: the relay always asks the server for TLS. A client that
  asked for TLS gets a relay that requires it (a server answering `N` is
  refused). The certificate is verified, with the database's name, against
  your root certificate (`PGSSLROOTCERT`, else `~/.postgresql/root.crt`, read
  by the egress proxy as your psql would) when there is one; without one it
  is not verified, which is libpq's own default (`prefer` / `require` with
  no root certificate). `PGSSLROOTCERT=system` verifies against the system
  store (Node's default), and counts as verified (review finding 2; before,
  it left the leg unverified). Bytes after `S` before the handshake are
  refused (CVE-2021-23222's shape).
- **Your own libpq settings** (the launch environment's, review finding 4):
  `PGSSLMODE=require` makes the relay require TLS of the server,
  `verify-ca` / `verify-full` a verified certificate (refused when there is
  no root certificate to verify with); `PGREQUIREAUTH` (a list of `none`,
  `password`, `md5`, `scram-sha-256`, each with `!` to forbid it) refuses a
  server asking for a method it rules out; `PGCHANNELBINDING=require` is
  refused, since the relay binds no channel.

Without a verified certificate a network attacker in the path could run the
md5 or SCRAM exchange against the relay and attack it offline, exactly as it
could against your own psql with the same settings; it never receives the
password itself. Set a root certificate to close that.

### 3.7 A database on this machine

The relay dials this machine for a local target (the target is fixed at
launch from your files). A program the agent runs could listen there first
and stand in for the database, to collect what the relay sends (review
finding 3). So, for a target on this machine, the relay reads who holds
the listening end (`/proc/net/tcp` and the descriptor tables;
`farEndOwner`) before it sends a byte: another uid's socket (a system
Postgres, a container's proxy) or one whose readable holders do not descend
from the launcher (`MANDU_NET_PROXY_SESSION_ROOT`, the launcher's pid;
`descendsFrom` walks the whole parent chain; the agent's tree has its own
pid namespace, so an orphan of it stays under the launcher) is served; a
holder that descends from the launcher, or a socket of yours that no
readable process holds (one that made itself non-dumpable), is refused.

## 4. What the invariant needs, and where it is held

The password reaches only the egress proxy's process (outside the agent's
tree) and the server's own method at a host it is bound to:

- the relay never writes the resolved value to the client, the log or an
  event (events carry symbols only);
- a server the relay was not told to serve is unreachable through it: each
  relay serves one target fixed at launch, never a destination the client
  names;
- the agent's tree connects to the database only through the relay (the
  guard denies the database's own address and refuses a redirect it cannot
  perform itself).

## 5. Tests

- `interceptors/net-proxy/test/unit/pg-wire.test.ts`: framing, startup
  packets, md5, SCRAM against RFC 7677's exchange byte for byte, the server
  signature, nonce and iteration checks, SASLprep.
- `interceptors/net-proxy/test/component/db-relay.test.ts`: the relay over
  a fake Postgres server (`test/fake-postgres.ts`): SCRAM and md5 logins,
  an unbound database, the arbiter unreachable, a tainted holder refused
  before the server is dialed (a trust login too), a bad SCRAM signature,
  trust, cleartext and GSS refused, the tripwire over the password and over
  the startup, TLS both sides (verified and not), the client asking for TLS
  the server lacks.
- `tests/stack/db-login-release.test.ts`: the real arbiter, the HOME
  `~/.pgpass` registered as the launcher does, the real egress proxy in its
  production wiring: the twin's escaped token read as libpq reads it, logins
  by SCRAM and md5 at their own databases, refused at another, no password
  or placeholder on any wire, none to the client, none in the twin, the
  arbiter gone refused; and `PGPASSWORD` + `PGHOST` / `PGPORT`, `MYSQL_PWD`
  + `MYSQL_HOST` / `MYSQL_TCP_PORT` registered as the launcher does: a
  login with no Approvals card at exactly that host and port, refused at
  another host or port, in the other's login, over HTTP, and after a
  launch without the host variable.
- `arbiter/test/unit/db-env-binding.test.ts`: `dbEnvWireHost` over every
  edge of §3.3.1, `envSecretSpan`'s mark (an exemption wins, a URL value is
  not bound), `registerEnvSecret`'s bindings and the dropped host,
  `wireReleaseScheme` for the two variables.
- `interceptors/net-supervisor` `guard.rs` units (the redirect's parse,
  match and sockaddr) and `tests/guard_integration.rs`
  `guard_redirects_a_database_connect_to_its_relay` (kernel: the tracee's
  connect to the database reaches the relay; denied without the redirect).
- `launcher/test/unit/db-relays.test.ts`: the targets from `~/.pgpass` and
  `PGHOST`, the relay port file, the guard's redirects and allow rules,
  `PGSSLROOTCERT`, the proxy's environment.
- `arbiter` `secret-extract` units: the pgpass wire host and the escaped
  token; `arbiter/test/component/pgpass-wire-twin.test.ts`: pg_dump reads
  the twin unasked in a session whose relay serves every line, asked before
  and for a `*` host line.
- `tests/sandbox/launcher/live-db-clients.test.ts` (the nightly): the real
  clients against real servers under a launched session
  ([`live-clients.md`](../testing/live-clients.md) §2).

## 6. Not done (open)

- ~~**A live `psql` run under a launched session**~~: done 2026-10-25
  ([`live-clients.md`](../testing/live-clients.md) §2,
  `integration.live-db-clients`): the real psql and pg_dump against real
  PostgreSQL 16 servers by SCRAM and md5, `sslmode` disable, prefer,
  require and verify-full, a name and an IP literal, and refusals at
  another relay target. Observed there: against a server with no TLS,
  reached by a name, the relay offers the client TLS and then refuses
  ("does not offer TLS, and the client asked for it"); libpq's `prefer`
  retries in plain text and logs in, as against the server itself, and
  `require` fails, as it would. The pg_dump twin (§3.3) came from it.
- ~~**A variable login live**~~: done 2026-10-25 (the live suite's
  `env-vars` launch): `PGPASSWORD` with `PGHOST`, no password file, the real
  psql logs in through the relay (§3.3.1).
- **Channel binding**: the client's `channel_binding=require` or
  `require_auth=scram-sha-256` (Postgres 16+) refuses the relay's cleartext
  ask; the client must leave them unset. The relay's own leg to the server
  does no `SCRAM-SHA-256-PLUS`.
- **`DATABASE_URL`** (`postgres://user:pw@host/db`): its password is masked
  (plan 10 §11.4 item 1) but gets no relay target or wire grant yet, and the
  token in the URL's userinfo is not percent-encoded for drivers that parse
  it.
- A server on a socket directory (`host=/var/run/postgresql`): no TCP, no
  relay; the socket login with no password stays the way.
- Logical replication and the `COPY` protocol need nothing more (they come
  after the login); GSS encryption (`gssencmode`) is answered `N`.

## 7. Figures

None yet.

## 8. MySQL

The same relay, the same redirect, gate, holder judgment, tripwire and copy
(`db-relay.ts` `serveMysql`, `mysql-wire.ts`). What differs is the
handshake, where the server speaks first.

### 8.1 Getting the client's password

MySQL has no way for a server to ask a client for its password in
cleartext that a stock client accepts: `mysql_clear_password` is refused by
libmysqlclient unless enabled (`LIBMYSQL_ENABLE_CLEARTEXT_PLUGIN`). Chosen
instead: `caching_sha2_password`'s **full path**, which every client since
MySQL 8 speaks. The relay dials the server (holders judged first: the
client has sent nothing yet), reads its handshake, and gives the client the
server's own handshake (version, connection id, capabilities, status) with
the relay's scramble, plugin `caching_sha2_password`, and TLS offered when
there is a session CA. A client that answers with another plugin is
switched (AuthSwitchRequest). Its scramble answer is then ignored and the
relay asks for full authentication (`0x01 0x04`), so the client sends
the password:

- in cleartext inside TLS, when the client took the TLS offer (the
  `mysql` client's default `ssl-mode=PREFERRED` does; the relay presents
  the session CA's leaf for the database's name);
- RSA-encrypted under the relay's own key (made once per relay), when the
  client asks for the server's public key (`--get-server-public-key`);
- a client with neither refuses itself ("Authentication requires secure
  connection"), as against a real server.

The MySQL SSLRequest has no answer, so the client's TLS hello may already
be read behind it: it rides in front of the socket into the TLS layer
(`prependChunk`).

### 8.2 Answering the server

| Server asks | The relay |
|---|---|
| `mysql_native_password` | SHA1(pw) XOR SHA1(scramble ‖ SHA1(SHA1(pw))) |
| `caching_sha2_password`, fast path (`0x01 0x03`) | SHA256(pw) XOR SHA256(SHA256(SHA256(pw)) ‖ scramble) |
| `caching_sha2_password`, full path (`0x01 0x04`) | the password itself, **only** over TLS whose certificate the relay verified against the `ssl-ca` of your `~/.my.cnf` (`[client]` or `[mysql]`); else refused. Its RSA variant is not used: a public key fetched without verified TLS can be an attacker's. |
| an auth switch to either | followed |
| `mysql_clear_password` | only over verified TLS |
| any other plugin | refused |

The relay always asks the server for TLS when it offers it, and requires it
when the client asked or your `~/.my.cnf` names an `ssl-ca` (security
review 2026-10-24: before, a server whose SSL flag was stripped in the path
was answered in plaintext). The startup's user, database and connect
attributes go through the tripwire before the password is asked for, and a
local listener is checked as for Postgres (§3.7). The server's OK or ERR goes to the client with the
client's next sequence id; then the bytes are copied.

A server whose cache does not hold the user yet (the first login after a
restart) needs the full path; without an `ssl-ca` that login is refused,
and the message says so. With one, the first login fills the cache and
later ones take the fast path.

### 8.3 Which databases, which passwords

The launcher's targets (`db-relays.ts`): each section of `~/.my.cnf` that
holds a password, at the host and port the section or `[client]` names
(3306 when no port is given; `localhost` is the client's socket, so no
relay), and `MYSQL_HOST` / `MYSQL_TCP_PORT` when `MYSQL_PWD` is set. The
launch HOME's `~/.my.cnf` is a wire file: each section's password is bound
to that section's `host:port` (`withMycnfWire`), put back only in the
relay's MySQL login: the relay states the scheme `mysql`, and the arbiter
refuses the grant anywhere else (`egress:secret-db-login-only`, as for
`.pgpass`, §3.3). `MYSQL_PWD` is bound to `MYSQL_HOST` at
`MYSQL_TCP_PORT` (3306), `localhost` excepted (§3.3.1).

### 8.4 Tests

`interceptors/net-proxy/test/unit/mysql-wire.test.ts` (framing, both
handshakes, native and caching_sha2 against their formulas, the RSA
answer), `test/component/db-relay-mysql.test.ts` over a fake MySQL server
(`test/fake-mysql.ts`): native by RSA, the fast path with a client switched,
a server's switch, the full path refused without verified TLS and sent over
it, an unbound database, the arbiter gone, a tainted holder (never dialed),
the server's own refusal passed on), `tests/stack/db-login-release.test.ts`
(a HOME `~/.my.cnf` registered: logins at each section's database, refused
at another, no password on any wire or at the client), the launcher's
`db-relays` (the `~/.my.cnf` and environment targets) and the arbiter's
`secret-extract` (`withMycnfWire`).

### 8.5 Not done (open)

- A client that verifies the server's certificate (`ssl-mode=VERIFY_CA` /
  `VERIFY_IDENTITY` with your `ssl-ca` in `~/.my.cnf`) refuses the relay's
  leaf: MySQL clients read no variable Mandu could point at the session CA.
  Measured live (2026-10-25): an `ssl-ca` in `[client]` with no `ssl-mode`
  makes the `mysql` client verify by default ("certificate verify failed"),
  so the `ssl-ca` the full path needs (§8.2) works today only with
  `ssl-mode=REQUIRED` beside it (the client then warns it does not verify).
- ~~A live run with the real `mysql` client and a real server~~: done
  2026-10-25 ([`live-clients.md`](../testing/live-clients.md) §2): MySQL
  8.0, `mysql_native_password`, `caching_sha2_password` by the fast path
  and (with `ssl-ca` and `ssl-mode=REQUIRED`) the full path, TLS on both
  legs, a refusal at another section's relay target, and `MYSQL_PWD` with
  `MYSQL_HOST` and no `~/.my.cnf` (§3.3.1).
- MariaDB's `ed25519` and `parsec` plugins, and `sha256_password`, are
  refused.
- The `COM_CHANGE_USER` command (a second login inside the connection)
  carries a password answer the relay does not see after the copy starts:
  it goes as the client wrote it, which is a placeholder's answer, so the
  server refuses it.
