# The live client lanes: real clients, real servers, a launched session

Status: **BUILT (2026-10-25)**. The database login release
([`db-login-release.md`](../confidentiality/db-login-release.md)) and the
kubectl and helm release ([`kube-wire-release.md`](../confidentiality/kube-wire-release.md))
were proven against fakes only: in-process fake servers, and a client-go
*reading* of the KUBECONFIG list in place of kubectl. These two suites run
the real `psql`, `pg_dump`, `mysql`, `kubectl` and `helm` against real
PostgreSQL, MySQL 8 and Kubernetes servers, under a real launch, with the
model's side and the network as the oracle. They found five bugs the fakes
could not (§4), fixed in the same change.

## 1. What every case runs through, and what is asserted

Each suite launches the real launcher in `secrets` (`mandu
--require-confinement claude -p …`, the guard live) around the stand-in
`claude` (`tests/lib/fake-claude-cli.mjs`): a scripted model
(`tests/lib/fake-anthropic.ts`, behind the HTTPS shim) answers each turn with
one `Bash` tool call, the stand-in runs it in the agent's world and sends the
output back through the real model proxy. A case is one command; its output
is also kept in the workspace (`.mdu-cases/<name>.out`, what the agent's
world saw). The launch HOME holds the credential files as a user keeps them,
with the real values; nothing is labelled or bound by hand (discovery and
the files' own wire grants do it). `tests/lib/live-clients.ts` holds this
half.

Asserted for every launch, besides each case's own result: no secret (as
written, base64, base64url or hex; a client key's PEM lines too) in any
request the model received, in any case's output, in the session's event
log or in the launch's output; the HOME files unchanged; a placeholder sent
anywhere but its own server is withheld, and the decoys (§2.2, §3.2) never
get a secret.

## 2. Databases: `integration.live-db-clients`

### 2.1 The topology, and the addresses

`tests/lib/netns.ts`'s two machines, with no root: one unprivileged user
namespace holding this side's network namespace (10.77.0.1) and the peer's
(10.77.0.2, and 203.0.113.9 outside "the organization's network"), joined by
a veth pair, names from a hosts file bind-mounted over `/etc/hosts`. Why not
loopback: the egress proxy (and so the relay's dial) refuses every address
of this machine, and a database on this machine takes the §3.7 listener
check; 10.77.0.2 is no address of this side, and 10.0.0.0/8 is not in the
always-denied set (blocked-destinations.ts refuses loopback, link-local and
metadata, this machine's own addresses; private ranges are a LAN's). Why not
the CI guest's root: this suite needs none, so it runs on any Linux host
with unprivileged user namespaces and the servers installed, self-SKIPping
otherwise.

The servers run as the test's own user (Postgres refuses root): the peer
(`tests/fixtures/live-db-peer.fixture.ts`) starts them through a nested
user namespace that maps that uid back (`unshare --map-user`), makes the
users over each server's Unix socket, and logs bob into MySQL once so the
server's cache holds him.

| Server | Where | TLS | Users |
|---|---|---|---|
| PostgreSQL pg1 | `pg.mandu-live.test` = 10.77.0.2:5432 | on, the suite's CA | alice (SCRAM-SHA-256; the password holds a `:`), bob (md5, stored md5) |
| PostgreSQL pg2 | 10.77.0.2:5433 (an IP literal in `.pgpass`), and `pg2.mandu-live.test` = 203.0.113.9:5433 | off | carol (SCRAM) |
| MySQL 8 | `mysql.mandu-live.test` = 10.77.0.2:3306 | on, the suite's CA | alice (`mysql_native_password`), bob (`caching_sha2_password`, cache warm), dave (`caching_sha2_password`, never logged in) |
| decoys (fakes that record every byte and know alice's real password, so a login that succeeds is a leak) | 10.77.0.2:3307 (eve's `~/.my.cnf` section: a relay target), 203.0.113.9:5432 and :3306 (named by no file) | | |

### 2.2 The cases (`tests/lib/live-db.ts`) and the results (2026-10-25)

Run in the CI guest (Ubuntu 24.04: PostgreSQL 16, MySQL 8.0). All pass.

| Case | What | Result |
|---|---|---|
| pg-scram-prefer | `psql -h pg…` (sslmode prefer) as alice | logs in; the relay's leg to the server is TLS |
| pg-md5-disable | bob, `PGSSLMODE=disable` on the client | logs in by md5; the server leg still TLS |
| pg-scram-require, pg-scram-verify-full, pg-md5-verify-full | `sslmode=require` / `verify-full` | log in: the session CA's leaf verifies for the name, the relay verifies the server against `~/.postgresql/root.crt` |
| pg-ip-notls-prefer, pg-ip-notls-disable | carol at an IP literal, a server with no TLS | log in, plain (no leaf is minted for an IP, so the relay answers the client `N`) |
| pg-name-notls-prefer | carol by a name, no TLS | logs in: the relay answers the client `S`, finds the server has no TLS and refuses ("does not offer TLS, and the client asked for it"); libpq's `prefer` then retries in plain text, as it does against the server itself |
| pg-name-notls-require | the same with `sslmode=require` | refused, as without Mandu |
| pg-dump | `pg_dump --schema-only` as alice | works (it did not before: §4.1) |
| pg-cross-unbound | alice's placeholder (as `PGPASSWORD`) at carol's server | refused, "was not put back" |
| pg-decoy-direct, my-decoy-direct | alice's placeholder to 203.0.113.9, a host no file names | the guard refuses the agent's own connect (no relay, and a direct connect off the machine is no session service) |
| my-native, my-native-required | `mysql` from `[client]` | logs in, TLS on both legs |
| my-sha2-fast | bob (`--defaults-group-suffix=_bob`) | logs in by the fast path |
| my-sha2-full | dave, no `ssl-ca` | refused as designed (§8.2: the full path needs a server the relay verified) |
| my-cross-unbound | alice's placeholder at eve's relay target | refused, "was not put back" |
| my-ca-sha2-full-required | `[client]` names `ssl-ca`; dave with `--ssl-mode=REQUIRED` | logs in by the full path (the client warns it does not verify) |
| my-ca-sha2-full-default, my-ca-native-default, my-ca-native-verify-ca | the same file, the client left to verify (`ssl-ca` set makes it `VERIFY_CA`) | refused by the client: "certificate verify failed" on the relay's leaf (db-login-release.md §8.5, still open) |

A third launch, `env-vars`, has no password file: its environment holds
`PGPASSWORD` with `PGHOST` and `MYSQL_PWD` with `MYSQL_HOST` (alice's real
passwords). The agent sees placeholders (`printenv`), and `psql -U alice`
and `mysql -u alice` log in through the relays: each variable is bound to
the host variable beside it (db-login-release.md §3.3.1).

## 3. Kubernetes: `integration.live-kube-clients`

### 3.1 The cluster: the CI guest's k3s fixture

The kubelet and containerd need what no user namespace gives them in the
guest (cgroups with the cpu controller, mounts, iptables), so the cluster is
a root fixture of the CI image, not the suite's own
([`continuous-integration.md`](continuous-integration.md) §4.2):
`scripts/ci/vm-run.sh --fixture k3s` has boot.sh run `fixture-k3s.sh`
before the pipeline: a network namespace `mandu-k3s` at 10.201.0.2 joined to
the guest by a veth pair (10.201.0.1), `k3s server` in it with the air-gap
images (pods start offline), ready in about 15 s. The address is no address
of the guest's (the proxy dials it as a LAN cluster). Outside the guest,
`MANDU_LIVE_KUBECONFIG` names any cluster's admin kubeconfig whose API
server is not on this machine.

The suite sets up, outside the session, a namespace of the run's own, a
service account `agent` with the `admin` role there and a token for it (the
bearer-token user), the admin's own client certificate (the
client-certificate user), and in a second namespace a decoy pod behind a
NodePort that prints every request it gets. `~/.kube/config` names the
cluster (its CA), both users and a context for each.

### 3.2 The cases (`tests/lib/live-kube.ts`) and the results (2026-10-25)

All pass, on both contexts where both are run.

| Case | Result |
|---|---|
| `kubectl auth whoami` (token, cert) | `system:serviceaccount:<ns>:agent`, `system:admin` |
| `kubectl apply -f` (two pods), `kubectl wait` | created, Ready |
| `kubectl get pods` (token, cert), `get -w` | listed; the watch streams |
| `kubectl logs -f` | three lines as the pod writes them |
| `kubectl exec` (token, cert), `exec -i` with stdin | output and stdin both ways (SPDY through the proxy's relay) |
| `kubectl port-forward` | the forwarded port, reached from outside the agent's world (the test, as the user's browser would), answers with the pod's page |
| port-forward reached by a program of the agent's | refused by the guard: a loopback port that is no session service (exec-routing.md §7.5) |
| `helm install` (a one-ConfigMap chart, `--wait`), `helm list` (token, cert) | deployed, listed |
| curl with the token's placeholder at the API server | the real token put back (`/version` answers) |
| the token's placeholder at the kubelet's port (HTTPS), at the NodePort decoy (HTTP) | 403, withheld; the decoy's log holds no token |

### 3.3 What the real kubectl did that the fake did not

See §4.2 to §4.4.

## 4. Bugs found, and fixed

1. **pg_dump was asked for the raw `~/.pgpass`** (§2.2). A known consumer of
   the file that is not a printer and not vetted is ASKED (plan 13 D8 (12));
   psql, a printer, reads the twin. With nobody to answer (the launch's ask
   timeout) the open was refused, libpq found no password and pg_dump asked
   for one on its terminal. Fixed: `wireServableDbTwin`
   (arbiter `secret-registry/registry.ts`) serves the twin, with no ask and
   no taint, in a session whose proxy inspects TLS when every line's
   password is bound to its own database (the relay puts it back); a `*`
   host line keeps the ask. db-login-release.md §3.3.
2. **kubectl was asked for the raw `~/.kube/config`**, the same rule: every
   kubectl and helm open was held, then refused ("permission denied"). An
   answered Allow would have handed kubectl the raw token. Fixed: the
   arbiter serves the twin of the HOME kubeconfig whose overlay a launcher
   built (`kubeOverlay`) for a session whose proxy inspects TLS.
   kube-wire-release.md §2.
3. **A certificate user made kubectl prompt for a username.** The overlay's
   certificate user had no credential at all, and client-go asks for a
   username and password on stdin for a user it cannot identify ("Please
   enter Username:"), which fails every command without a terminal. Fixed:
   the overlay gives it a session-local stand-in client certificate
   (`launcher/src/kube-overlay.ts` `mintStandInClientCert`; one PEM file not
   named like a key file, or the session's catalog would serve kubectl a
   placeholder copy of it). kube-wire-release.md §3.
4. **The §4 tripwire refused every request to the cluster.** The server URL
   `https://10.201.0.2:6443` (and a namespace such as `mdu-live-ed8562c7`)
   reads as a credential-shaped bare token of the kubeconfig's row, and
   kubectl sends both in every request. Fixed: a kubeconfig's structural
   values (names, server and proxy URLs without a user, password, query or
   fragment, namespaces; `kubeconfigPublicValues`) are no pieces of its row
   (egress-fingerprint.ts `ValueTwin.publicTokens`), unless one holds a
   secret text. kube-wire-release.md §6.
5. The stand-in claude's request after a long command failed on a kept-alive
   connection the proxy had closed: it now retries a failed send (a test
   harness fix).

None weakens the invariant: 1 and 2 serve a twin where an ask could hand
over the raw file (strictly less than before); 3 adds a certificate that is
no secret and reaches no cluster; 4 narrows the tripwire (defense in depth,
not the guarantee) by values the twin, the overlay and the client show as
they are and that are never secrets by the file's own grammar.

## 5. Running them

```sh
# the databases (the CI image has the servers; any Linux host with them too)
scripts/ci/vm-run.sh --worktree --only integration.live-db-clients
# the cluster: the fixture, then the suite
scripts/ci/vm-run.sh --worktree --fixture k3s --only integration.live-kube-clients
```

`integration.live-db-clients` is a `sandbox` entry that runs in the nightly
(`nightly`), not per push: it starts three database servers and two
launches (about 20 s in the guest, 40 s with the boot), and the per-push run
keeps the fake-server stack e2e. `integration.live-kube-clients` is
`manual`: its fixture turns the cpu controller on above the suites, which
the nightly's drills do not survive.

## 6. Open

- A MySQL client that verifies (`ssl-ca` set and no `ssl-mode`, or
  `VERIFY_CA`) refuses the relay's leaf (db-login-release.md §8.5).
- port-forward used from inside the session needs a rule admitting the
  forwarded loopback port; there is none per port today.
- The kube lane runs only when named; a guest of its own in the nightly
  would make it regular.
- The other known consumers asked for their raw file the way pg_dump and
  kubectl were (§4.1, §4.2): `aws` (`~/.aws/credentials`), `gh`, `twine`,
  `cargo`, `docker`. Where the session's wire release serves the file, the
  twin is the answer that works; not measured here (no real accounts).
