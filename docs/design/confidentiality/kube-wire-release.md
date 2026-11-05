# kubectl, helm and Java through the session proxy

Status: **BUILT** (2026-10-24). A decision note under
[`confidentiality.md`](./confidentiality.md) §2.1 (bindings) and
[plan 13 §10](./confidentiality-plan-13-reader-set-labels.md) (which
clients the wire release serves). Code: `arbiter/policy/kubeconfig.ts`,
`interceptors/net-proxy/src/mitm.ts` (`upstreamTlsOptions`),
`launcher/src/kube-overlay.ts`, `launcher/src/java-trust.ts`.

## 1. The problem

In `secrets` mode `kubectl` and `helm` read the placeholder copy (the twin)
of `~/.kube/config` (plan 13 §3 D8 (12): they are not vetted readers). Until
now nothing in that copy worked:

- kubectl trusts only the CA its kubeconfig names for the cluster
  (`certificate-authority-data`), so it refused the session proxy's
  certificate: the bearer token's placeholder was never put back
  (plan 13 §10.2, *refused*);
- the twin's `certificate-authority-data`, `client-certificate-data` and
  `client-key-data` were bare placeholders, which are not base64: client-go
  failed to load the file at all;
- a client certificate cannot be "put back" in a header: the key signs the
  TLS handshake.

Java read no proxy or CA variable, so a JVM in the session went around the
proxy (*bypass*), and a placeholder it sent was never put back.

None of these was a leak (the programs only ever held placeholders); each
was a utility failure, the reason the Why Mandu post scored Mandu *Partly*
on R4 ("programs can still use it"). The fix keeps every secret byte out of
the agent's process tree and every model, and lets the real values reach
only the cluster the kubeconfig binds them to.

## 2. The twin

`~/.kube/config` keeps its YAML reading (`yaml-keys`, every secret-named
key a span), with two changes for kubectl (`secret-extract.ts`
`kubeconfigSpans`):

- **A `*-data` field holding a base64 PEM block is an ENCODED span**
  (`encoded: "base64"`, as npm's `_password`): its value is the PEM, its
  twin the base64 of the placeholder. client-go decodes it at load, so the
  twin loads; the registry also mints the file's base64 text as an unbound
  row, so the fingerprint scans hold both forms.
- **A user's `token` is a wire credential** (`wire: bearer`, https only) to
  the one https server its contexts name (`kubeTokenWire`): host and port
  stated (`k8s.example:6443`). A token whose contexts name no server, a
  plain-http one, or several, gets no wire host and is put back nowhere.

The wire grant follows the npm and pip rule (plan 10 §11.13.1): only the
launch HOME's own file (`HOME_WIRE_FILES` gained `.kube/config`), read from
the real file at registration on the human socket, never a workspace copy
the agent can write. The release is the existing one: the egress gate puts
the real token back in the Authorization header of an HTTPS request to that
`host:port` (`wireReleaseScheme`, `wirePositionRefusal`); anywhere else the
placeholder is withheld (403).

**kubectl and helm are served the twin, unasked** (2026-10-25, found by the
live run, [`live-clients.md`](../testing/live-clients.md) §4.2). They are
the file's known consumers (flow-taint.ts `CONSUMER_TABLE`) and not vetted
readers, so `decideOpen` ASKED for the raw file: every kubectl open waited
for an Approvals answer and, with nobody to give one, was refused
("permission denied"); an Allow would have put the raw token in kubectl. The
arbiter now serves them the twin, with no taint, for the HOME kubeconfig a
launcher built this session's overlay from (`kubeOverlay`), in a session
whose proxy inspects TLS (`registerWireRelease`), as npm is served
`.npmrc`'s (`decideSecretOpen`, the `wireTwin` option). Before the overlay,
or in another session, they are asked as before.

**A kubeconfig's structure is no fingerprint** (2026-10-25, the same run,
§4.4). The §4 tripwire takes a labelled file's credential-shaped bare tokens
as pieces of its row, and `https://10.201.0.2:6443` (digits, a letter, enough
entropy) or a namespace like `mdu-live-ed8562c7` reads as one; kubectl
sends both in every request, so every request was refused ("1 secret
value(s) appeared VERBATIM … @url"). A kubeconfig's names, server and proxy
URLs (with no user, password, query or fragment), `tls-server-name`s and
namespaces (`kubeconfig.ts` `kubeconfigPublicValues`) are now no pieces of
its row (`ValueTwin.publicTokens`), unless one holds a secret text. The
twin, the overlay and kubectl show each as it is; none is a secret by the
file's grammar (`kubeconfigSpans` spans the secret keys).

## 3. The KUBECONFIG overlay

kubectl must trust the session CA for the cluster, and must not choke on a
client key it cannot parse. Rewriting the twin itself was rejected: the twin
is session-independent (the arbiter re-renders it to check a Read against),
and the session CA is not. Instead the launcher writes a session file and
lists it FIRST in KUBECONFIG (`launcher/src/kube-overlay.ts`):

- The arbiter builds its entries from the kubeconfig's TWIN (`kubeOverlay`
  op, human plane; `kubeconfig.ts` `kubeOverlay`), so no secret is in it:
  each https cluster without a `proxy-url` of the user's, minus every trust
  key (`certificate-authority`, `certificate-authority-data`,
  `insecure-skip-tls-verify`, `tls-server-name`), and each user with a
  client certificate or key, minus those four keys.
- The launcher adds to each cluster `certificate-authority: <session CA>`
  and `proxy-url: http://<session proxy>` (so a cluster on a port the
  session's network rules do not open, or in NO_PROXY, still goes through
  the proxy), and writes the JSON beside the session CA.
- client-go takes a named entry WHOLE from the first file that has it
  (Kubernetes' documented merge rule: "if two files specify a `red-user`,
  use only values from the first file's"), so the overlay's clusters and
  users replace the twin's; contexts and `current-context` stay the twin's.
- KUBECONFIG becomes `<overlay>:<the user's KUBECONFIG, else ~/.kube/config>`;
  no overlay when the user's KUBECONFIG leaves `~/.kube/config` out (it is
  the only file the overlay is built from), when the file is not twinned
  this launch, or without TLS inspection.

A client-certificate user in the overlay has no credential of its own:
kubectl sends none the cluster sees, and the proxy presents the real one
(§4). Since 2026-10-25 the entry names a session-local **stand-in**
certificate and key (`kube-overlay.ts` `mintStandInClientCert`, one PEM
file beside the session CA): with no credential at all the real kubectl
asks for a username and password on stdin (client-go's prompt for a user it
cannot identify, "Please enter Username:"), which fails every command run
without a terminal (the live run, [`live-clients.md`](../testing/live-clients.md)
§4.3). The stand-in is no secret (made for the session, presented to
nobody: the proxy's TLS server asks for no client certificate), carries no
Authorization header (which would stop the proxy presenting the real
certificate), and is not named like a key file, which the session's catalog
would serve kubectl as a placeholder copy. openssl failing leaves the entry
as before, and the launch note says so.

## 4. The proxy dials the cluster as kubectl would

Before it re-originates a request to `host:port`, the TLS-inspecting leg
asks the arbiter `kubeUpstream` (human plane: the answer holds a client
key; cached 30 s per authority). The arbiter answers only for a kubeconfig a
launcher named with `kubeOverlay`, from the registry's own copy of the real
text (`registeredFileText`), with:

- **the cluster's CA as the only trust anchor** (kubectl's rule; a CA file
  is read relative to the kubeconfig's folder), else the system store;
- `tls-server-name` as the SNI and the name verified;
- `insecure-skip-tls-verify: true` honored for that cluster only (the
  user's own choice in the user's own file);
- **the client certificate and key of the one user** the file's contexts
  pair with that server, presented ONLY for a request that carries no
  Authorization header (a bearer request authenticates as that token's
  user, never as the certificate's). Two such users on one server: none is
  presented (`clientWhy`), and the request goes without one.

The pooled upstream connection carries how it was dialed (`poolKey`), so a
request with a token never reuses a connection that presented a
certificate, nor the reverse. An arbiter that cannot answer fails the
request closed (502, nothing sent); no profile (any other host, or after an
arbiter restart until the next launch names the file again) dials as
before: the system store, no client certificate.

### 4.1 Streams: exec, attach, port-forward, watches, `logs -f`

Since 2026-10-24 (the follow-up). The inspecting leg buffers a request
and its response whole, which kubectl's streams cannot use. For a host with
a profile (a cluster of the launch's kubeconfig), and only there, two kinds
of request are relayed instead (`mitm.ts` `kubeStreamKind`, `relayStream`):

- **An upgrade** (`Connection: Upgrade` with an `Upgrade:` protocol:
  SPDY/3.1 or WebSocket, which `exec`, `attach` and `port-forward` send).
  The upgrade request is gated like any request: the real token is put back
  in its Authorization header, or the real client certificate presented on
  its dial, and nowhere else. The proxy dials a fresh connection (never
  pooled), sends the head with `Connection: Upgrade`, and writes the
  cluster's response head back. On `101 Switching Protocols` it relays the
  stream both ways: the cluster's bytes as they come; each chunk the client
  sends only after (1) a fresh verdict on the processes now holding the
  client's end, the blind tunnel's per-chunk rule (plan 13 D6, guarantees.md
  "finds the sending program from `/proc`": a holder that holds a secret
  not bound to the cluster, or one handed the connection, has its chunk
  refused and the stream closed), and (2) the verbatim-leak tripwire over
  the chunk's text. Both share `proxy.ts` `tunnelRecheck`. A connection
  that cannot be judged per chunk (no `streamCheck`) is answered 502 before
  anything is dialed. A placeholder inside the stream stays a placeholder:
  only the upgrade request's head is released.
- **A watch or a follow** (a GET with `watch=true|1` or `follow=true|1`:
  `get -w`, `logs -f`). The request goes with `Connection: close`; the
  response head is written back with `Connection: close`, and its body is
  relayed as it comes, framing and all, until its Content-Length or the
  cluster's close. Nothing goes from the client to the cluster after the
  request.

Neither side's idle timer applies once a stream runs (a watch, an idle
shell); either end's close ends it, and a client that keeps its end of a
finished stream open is closed after 5 s. A streamed response is not
classified (`observeResponse`): it returns the body raw in any case, and
the leg calls it without a process to tag. Any other host keeps the
buffered leg, which sends no `Connection: Upgrade` (an upgrade there fails
as before).

## 5. Java

`launcher/src/java-trust.ts`. At launch, with TLS inspection on, the
launcher writes a PKCS#12 trust store of the same certificates as the
combined bundle (system CAs and the session CA), with no JVM start: one
unencrypted certificate bag per certificate, each with Oracle's
trusted-key-usage attribute (what makes Java read a bag as a trusted
entry), and no MAC, which JDK 18+ (and 11.0.12+, 8u301+) loads with no
password. JAVA_TOOL_OPTIONS (which every JVM reads) names it and the
session proxy:

```
-Djavax.net.ssl.trustStore=<caDir>/mandu-java-truststore.p12 -Djavax.net.ssl.trustStoreType=PKCS12
-Dhttps.proxyHost=… -Dhttps.proxyPort=… -Dhttp.proxyHost=… -Dhttp.proxyPort=…
-Dhttp.nonProxyHosts=<NO_PROXY in Java's spelling>
```

then the user's own JAVA_TOOL_OPTIONS, whose `-D` wins (as a user's CA file
is kept for the other clients). Served: `HttpsURLConnection` and every
client on the default `ProxySelector` (`HttpClient` built with
`.proxy(ProxySelector.getDefault())`). Costs: every JVM prints `Picked up
JAVA_TOOL_OPTIONS: …` on stderr; `MANDU_JAVA_TRUST=0` leaves the variable
alone.

## 6. Why this keeps the invariant

- **The agent's world holds no secret byte.** The twin holds placeholders
  (the `*-data` ones base64-encoded), the overlay is built from the twin
  plus the session CA's path and the proxy's address (and the stand-in
  certificate's, a key made for the session that authenticates to
  nothing), the Java trust store holds public certificates. The stack test
  asserts no token, key or certificate byte in the twin or the overlay; the
  live suite, none in what the model received or the agent's world saw.
- **The tripwire's narrowing is to structure only.** The values no longer
  pieces of a kubeconfig's row (§2) are its names, addresses and
  namespaces, which the twin, the overlay and every request already show;
  a secret is spanned by key (`kubeconfigSpans`) and stays a piece, and a
  structural value that holds a secret text stays one too.
- **The real values reach only the bound cluster.** The token by the
  existing wire release (one `host:port`, https, Authorization only); the
  client key never leaves the proxy: it signs the handshake with the
  cluster whose server the user's own file names, verified with the CA the
  user's own file names. `kubeUpstream` is refused on the data socket, and
  answers only for the launch HOME's file a launcher named on the human
  socket.
- **Fail-closed.** Any reading that fails (a document that does not parse,
  a server that is not https, an ambiguous user) yields no wire host, no
  overlay entry or no client certificate: the placeholder stays, and the
  login fails as before.
- **What the agent gains is use, not bytes.** Any program of the session can
  talk to the bound cluster as the user, which is the point (R4); the same
  holds for every wire credential (a `gh` token). The responses are the
  cluster's data, not the credential.

A CA or key FILE a kubeconfig names (`client-key: certs/admin.key`) is read
by the arbiter at the dial. If that file is not itself protected, the agent
can replace it; the proxy would then present the agent's own key (no
secret) or verify the cluster with the agent's CA, which only matters to an
attacker who can also redirect the proxy's own connection to the cluster.

## 7. Tests

- `arbiter/test/unit/kubeconfig.test.ts`: the authority, the token's wire
  host (unique, ambiguous, http), strict PEM decoding, the twin's encoded
  spans, the overlay, the upstream profile (CA data and files, the name,
  `insecure`, the one certificate user, ambiguity, unreadable files,
  conflicting trust), the structural values and that they are no pieces
  (the token still one).
- `arbiter/test/component/kubeconfig-wire-twin.test.ts`: kubectl and helm
  read the twin unasked and untainted once the overlay is built in a
  session that inspects TLS; asked before, in another session, and after
  the session's word is withdrawn.
- `tests/sandbox/launcher/live-kube-clients.test.ts` (run when named): the
  real kubectl and helm against a real cluster under a launched session
  ([`live-clients.md`](../testing/live-clients.md) §3).
- `interceptors/net-proxy/test/unit/upstream-tls-options.test.ts` and
  `test/component/kube-upstream.test.ts`: the dial's CA and certificate,
  the pool split, no profile and a failing arbiter (502, nothing sent).
- `interceptors/net-proxy/test/unit/kube-stream-kind.test.ts` and
  `test/component/kube-stream.test.ts` (§4.1): which requests stream, the
  heads written, an upgrade (SPDY/3.1, WebSocket) relayed both ways with the
  client certificate on its dial, a holder tainted mid-stream (its next
  chunk never reaches the cluster, the stream closes), a chunk holding a
  registered secret (the tripwire closes it), a watch whose first event
  arrives while the cluster holds the second.
- `launcher/test/unit/kube-overlay.test.ts`, `java-trust.test.ts`: the
  overlay text and KUBECONFIG, the stand-in client certificate (in the
  certificate user's entry, a pair Node loads, 0600, not named like a key
  file), the trust store read back by openssl and
  keytool, NO_PROXY in Java's spelling, JAVA_TOOL_OPTIONS composed.
- `tests/stack/kube-wire-release.test.ts`: the real arbiter, the real proxy
  in its production wiring, the overlay, loopback clusters with their own
  CA; a client-go reading of the KUBECONFIG list (every file loads, entries
  merge whole, the cluster's CA alone is trusted), the real `kubectl` when
  installed, a real JVM when `java` is. The oracle: the real token and
  certificate only at their own cluster, nothing secret in the twin or the
  overlay, the placeholder refused at a decoy and over plain HTTP; an
  exec-style upgrade on the token and the certificate contexts (the real
  credential on its upgrade request only) and a watch that streams.

## 8. Open

- ~~**Measured against the real kubectl and helm**~~: done 2026-10-25
  ([`live-clients.md`](../testing/live-clients.md) §3,
  `integration.live-kube-clients`, `scripts/ci/vm-run.sh --fixture k3s`):
  kubectl 1.36 and helm 3.22 against a k3s 1.36 cluster off the machine,
  on a bearer-token and a client-certificate context: auth whoami, apply,
  wait, get, a watch, logs -f, exec (SPDY, stdin both ways), port-forward
  (reached from outside the agent's world), helm install and list; the
  token withheld at the kubelet's port and a decoy. It found the three bugs
  fixed in §2 and §3 (the ask, the tripwire, the username prompt). The lane
  runs only when named (its fixture turns the cpu controller on).
- **port-forward from inside the session**: kubectl's local listener is a
  loopback port that is no session service, so the guard refuses a program
  of the agent's connecting to it (exec-routing.md §7.5); a client outside
  the agent's world reaches it.
- **exec credential plugins** (`aws eks get-token`,
  `gke-gcloud-auth-plugin`, `kubelogin`) and `auth-provider` users: the
  plugin runs in the session with the session's credentials; a plugin that
  itself reaches its cloud through the proxy works where that cloud's
  credential does (gcloud's bearer calls are served; `aws` signs, see the
  SigV4 item). Untested.
- **A `tokenFile`**, and a token several servers share: no wire host.
- ~~**Streams and upgrades**~~: relayed since 2026-10-24 (§4.1), for a
  cluster of the launch's kubeconfig only. Still open: a stream to any other
  host (a WebSocket API) keeps the buffered leg. A real cluster's SPDY
  streams (exec with stdin, logs -f, a watch, port-forward) were measured
  2026-10-25 (the live suite); its WebSocket ones not yet.
- **A cluster on loopback** (`kind`, `minikube`): the proxy refuses to dial
  this machine (blocked-destinations.ts), so such a cluster keeps needing a
  readers entry.
- **A cluster behind the user's own `proxy-url`**: no overlay entry (the
  proxy does not chain to another proxy).
- **Java older than 18 (before 11.0.12 / 8u301)** cannot load a password-less
  trust store; a client that builds its own SSLContext or proxy settings
  (Maven, Gradle and others with their own config) is not covered.
- **After an arbiter restart** the upstream profiles are gone until the
  next launch names the file again (the dial then fails closed for a
  private-CA cluster).
