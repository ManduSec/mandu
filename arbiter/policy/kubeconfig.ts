/**
 * kubeconfig — what Mandu reads in a kubeconfig so `kubectl` and `helm` work
 * from its placeholder copy (docs/design/confidentiality/kube-wire-release.md).
 *
 * Mandu-new (no reference origin).
 *
 * kubectl verifies the cluster against the kubeconfig's own CA only, so it
 * refuses the session proxy's certificate, and its client key must parse as
 * a key. Three readings serve it:
 *
 *   - `kubeTokenWire` (the twin's spans): a user's bearer `token` is a wire
 *     credential to the ONE cluster server its contexts name, put back by
 *     the proxy in the Authorization header there, as npm's token is at its
 *     registry (plan 10 §11.13.1). A token whose contexts name no server, or
 *     several, gets no wire host: it stays a placeholder everywhere.
 *   - `kubeOverlay` (the launcher's session file): the twin's cluster entries
 *     with the cluster's CA left out (the launcher adds the session CA and
 *     the session proxy), and the twin's client-certificate users with the
 *     certificate and key left out. Listed first in KUBECONFIG, its entries
 *     replace the twin's of the same name (client-go merges whole entries).
 *     Built from the TWIN text: nothing in it is a secret.
 *   - `kubeUpstream` (the proxy's re-origination): for one `host:port`, the
 *     REAL file's CA, `tls-server-name`, `insecure-skip-tls-verify`, and the
 *     client certificate and key of the one user its contexts pair with that
 *     server. The proxy dials the cluster as kubectl would have.
 *
 * Fail-closed: anything this module cannot read (a document that does not
 * parse, a server that is not an https URL, a user several servers share)
 * gets no wire host, no overlay entry and no upstream profile, so the
 * program keeps today's placeholder and its login fails. Pure.
 */

import { load } from "js-yaml";
import { isIP } from "node:net";

export interface KubeCluster {
  name: string;
  /** The `server` URL as written. */
  server: string;
  /** `host:port` of an https server (port stated, 443 by default; an IPv6
   *  host bracketed), lower-cased; null for anything else. */
  authority: string | null;
  caData?: string;
  caFile?: string;
  tlsServerName?: string;
  insecure: boolean;
  proxyUrl?: string;
}

export interface KubeUser {
  name: string;
  token?: string;
  certData?: string;
  keyData?: string;
  certFile?: string;
  keyFile?: string;
}

export interface KubeContext {
  name: string;
  cluster: string;
  user: string;
}

export interface Kubeconfig {
  clusters: KubeCluster[];
  users: KubeUser[];
  contexts: KubeContext[];
}

/** Is `path` a kubeconfig by its name (`~/.kube/config`)? */
export function isKubeconfigPath(path: string): boolean {
  return /(^|\/)\.kube\/config$/.test(path);
}

/** `host:port` of an https `server` URL, lower-cased, the port stated (443 by
 *  default), an IPv6 host bracketed; null for any other scheme or a URL that
 *  does not parse. */
export function kubeServerAuthority(server: string): string | null {
  let u: URL;
  try {
    u = new URL(server.trim());
  } catch {
    return null;
  }
  if (u.protocol !== "https:" || u.hostname === "" || u.username !== "" || u.password !== "") return null;
  const host = u.hostname.toLowerCase();
  const bare = host.startsWith("[") ? host.slice(1, -1) : host;
  const shown = isIP(bare) === 6 ? `[${bare}]` : host;
  return `${shown}:${u.port !== "" ? u.port : "443"}`;
}

function str(v: unknown): string | undefined {
  return typeof v === "string" && v !== "" ? v : undefined;
}

function rec(v: unknown): Record<string, unknown> | null {
  return v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}

function named(list: unknown, inner: string): Array<{ name: string; body: Record<string, unknown> }> {
  if (!Array.isArray(list)) return [];
  const out: Array<{ name: string; body: Record<string, unknown> }> = [];
  for (const item of list) {
    const r = rec(item);
    const name = r ? str(r["name"]) : undefined;
    const body = r ? rec(r[inner]) : null;
    if (name !== undefined && body !== null) out.push({ name, body });
  }
  return out;
}

/** The document, or null when it does not parse as a kubeconfig map. */
export function kubeconfigDocument(text: string): Record<string, unknown> | null {
  try {
    return rec(load(text));
  } catch {
    return null;
  }
}

/**
 * The values of a kubeconfig that are its structure, not its secrets
 * (live-clients.md §3.3, 2026-10-25): every entry's `name`, each context's
 * `cluster`, `user` and `namespace`, `current-context`, and each cluster's
 * `server` and `tls-server-name` (a `server` or `proxy-url` only when it is
 * a URL with no user, password, query or fragment, whose every character is
 * then the address it names). The twin shows each as it is, the overlay
 * copies them, and kubectl sends the server's address and the namespace in
 * every request: as bare-token pieces of the file's row (egress-fingerprint.ts
 * `ValueTwin.publicTokens`) the §4 tripwire refused every request to the
 * cluster whose URL looks random enough (`https://10.201.0.2:6443`), or a
 * namespace that does (`mdu-live-ed8562c7`). A secret is never one of
 * these (kubeconfigSpans spans the secret keys), and a value that also holds
 * a secret text stays a piece (egress-fingerprint.ts `withoutTwinTokens`).
 * Empty for a text that does not parse. Pure.
 */
export function kubeconfigPublicValues(text: string): string[] {
  const doc = kubeconfigDocument(text);
  if (doc === null) return [];
  const out = new Set<string>();
  const add = (v: unknown): void => { const s = str(v); if (s !== undefined) out.add(s.trim()); };
  const addUrl = (v: unknown): void => {
    const s = str(v);
    if (s === undefined) return;
    try {
      const u = new URL(s.trim());
      if (u.username === "" && u.password === "" && u.search === "" && u.hash === "") out.add(s.trim());
    } catch { /* not a URL: not public */ }
  };
  for (const { name, body } of named(doc["clusters"], "cluster")) {
    out.add(name);
    addUrl(body["server"]);
    addUrl(body["proxy-url"]);
    add(body["tls-server-name"]);
  }
  for (const { name } of named(doc["users"], "user")) out.add(name);
  for (const { name, body } of named(doc["contexts"], "context")) {
    out.add(name);
    add(body["cluster"]);
    add(body["user"]);
    add(body["namespace"]);
  }
  add(doc["current-context"]);
  out.delete("");
  return [...out];
}

/** Read a kubeconfig's clusters, users and contexts; null when the text is
 *  not a YAML or JSON map. Entries without a name or body are skipped. */
export function parseKubeconfig(text: string): Kubeconfig | null {
  const doc = kubeconfigDocument(text);
  if (doc === null) return null;
  const clusters = named(doc["clusters"], "cluster").map(({ name, body }): KubeCluster => {
    const server = str(body["server"]) ?? "";
    return {
      name,
      server,
      authority: server === "" ? null : kubeServerAuthority(server),
      ...(str(body["certificate-authority-data"]) ? { caData: str(body["certificate-authority-data"])! } : {}),
      ...(str(body["certificate-authority"]) ? { caFile: str(body["certificate-authority"])! } : {}),
      ...(str(body["tls-server-name"]) ? { tlsServerName: str(body["tls-server-name"])! } : {}),
      insecure: body["insecure-skip-tls-verify"] === true,
      ...(str(body["proxy-url"]) ? { proxyUrl: str(body["proxy-url"])! } : {}),
    };
  });
  const users = named(doc["users"], "user").map(({ name, body }): KubeUser => ({
    name,
    ...(str(body["token"]) ? { token: str(body["token"])! } : {}),
    ...(str(body["client-certificate-data"]) ? { certData: str(body["client-certificate-data"])! } : {}),
    ...(str(body["client-key-data"]) ? { keyData: str(body["client-key-data"])! } : {}),
    ...(str(body["client-certificate"]) ? { certFile: str(body["client-certificate"])! } : {}),
    ...(str(body["client-key"]) ? { keyFile: str(body["client-key"])! } : {}),
  }));
  const contexts = named(doc["contexts"], "context").flatMap(({ name, body }): KubeContext[] => {
    const cluster = str(body["cluster"]);
    const user = str(body["user"]);
    return cluster !== undefined && user !== undefined ? [{ name, cluster, user }] : [];
  });
  return { clusters, users, contexts };
}

/** The https server authorities the contexts pair with user `user`. */
function serversOfUser(cfg: Kubeconfig, user: string): Set<string | null> {
  const out = new Set<string | null>();
  for (const c of cfg.contexts) {
    if (c.user !== user) continue;
    const cl = cfg.clusters.find((x) => x.name === c.cluster);
    out.add(cl?.authority ?? null);
  }
  return out;
}

/**
 * The wire host of each bearer token the file holds: the one https server
 * authority every context of every user holding that token names. A token
 * whose contexts name no server, a non-https one, or several, maps to null
 * (no release anywhere). Keyed by the token's text.
 */
export function kubeTokenWire(cfg: Kubeconfig): Map<string, string | null> {
  const out = new Map<string, string | null>();
  for (const u of cfg.users) {
    if (u.token === undefined) continue;
    const hosts = serversOfUser(cfg, u.name);
    const prev = out.has(u.token) ? out.get(u.token)! : undefined;
    const one = hosts.size === 1 ? [...hosts][0]! : null;
    out.set(u.token, prev === undefined ? one : prev === one ? one : null);
  }
  return out;
}

/** A base64 field's decoded text when it is a PEM block (what kubectl
 *  decodes it to), else null. Strict: the text must round-trip. */
export function decodedPem(b64: string): string | null {
  const t = b64.trim();
  if (t === "" || !/^[A-Za-z0-9+/]+={0,2}$/.test(t) || t.length % 4 !== 0) return null;
  const text = Buffer.from(t, "base64").toString("utf8");
  if (Buffer.from(text, "utf8").toString("base64") !== t) return null;
  return /^\s*-----BEGIN [A-Z0-9 ]+-----/.test(text) ? text : null;
}

/** The overlay entries of the session KUBECONFIG file (JSON-ready). */
export interface KubeOverlay {
  /** Each https cluster of the twin without a `proxy-url` of the user's:
   *  its entry minus every CA and verification key (`certificate-authority`,
   *  `certificate-authority-data`, `insecure-skip-tls-verify`,
   *  `tls-server-name`). The launcher adds the session CA and proxy. */
  clusters: Array<{ name: string; cluster: Record<string, unknown> }>;
  /** Each twin user with a client certificate or key: its entry minus them
   *  (the proxy presents the real ones at the bound cluster). */
  users: Array<{ name: string; user: Record<string, unknown> }>;
}

const CLUSTER_TRUST_KEYS = ["certificate-authority", "certificate-authority-data", "insecure-skip-tls-verify", "tls-server-name"];
const USER_CERT_KEYS = ["client-certificate", "client-certificate-data", "client-key", "client-key-data"];

/** The overlay for a twin text, or null when it names no https cluster.
 *  Only the twin's own entries are copied: nothing here is a secret. */
export function kubeOverlay(twinText: string): KubeOverlay | null {
  const doc = kubeconfigDocument(twinText);
  if (doc === null) return null;
  const clusters: KubeOverlay["clusters"] = [];
  for (const { name, body } of named(doc["clusters"], "cluster")) {
    const server = str(body["server"]);
    if (server === undefined || kubeServerAuthority(server) === null || body["proxy-url"] !== undefined) continue;
    const cluster: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(body)) if (!CLUSTER_TRUST_KEYS.includes(k)) cluster[k] = v;
    clusters.push({ name, cluster });
  }
  if (clusters.length === 0) return null;
  const users: KubeOverlay["users"] = [];
  for (const { name, body } of named(doc["users"], "user")) {
    if (!USER_CERT_KEYS.some((k) => body[k] !== undefined)) continue;
    const user: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(body)) if (!USER_CERT_KEYS.includes(k)) user[k] = v;
    users.push({ name, user });
  }
  return { clusters, users };
}

/** How the proxy dials one cluster (`kubeUpstream`). */
export interface KubeUpstream {
  /** The cluster's CA (PEM): the ONLY trust anchor, as kubectl's. Absent:
   *  the system store. */
  ca?: string;
  /** SNI and the name verified (`tls-server-name`). Absent: the host. */
  servername?: string;
  /** `insecure-skip-tls-verify: true` in the user's own file. */
  insecure: boolean;
  /** The client certificate and key (PEM) of the one user the contexts pair
   *  with this server; absent when none has one or several do. */
  client?: { cert: string; key: string };
  /** Why `client` is absent though a user of this server has a certificate. */
  clientWhy?: string;
}

/**
 * The upstream profile for `authority` (`host:port`, as `kubeServerAuthority`
 * states it) from the REAL kubeconfig text, or null when no cluster of the
 * file has that server, or two clusters with that server disagree on how to
 * trust it. `readFile` reads a path the file names (a CA, a certificate, a
 * key; relative to the file's folder `dir`); a read that fails leaves the
 * field out (no CA: the system store; no key: no client certificate).
 */
export function kubeUpstream(
  realText: string,
  authority: string,
  opts: { dir: string; readFile: (path: string) => string | null },
): KubeUpstream | null {
  const cfg = parseKubeconfig(realText);
  if (cfg === null) return null;
  const want = authority.toLowerCase();
  const clusters = cfg.clusters.filter((c) => c.authority === want);
  if (clusters.length === 0) return null;
  const abs = (p: string): string => (p.startsWith("/") ? p : `${opts.dir.replace(/\/$/, "")}/${p}`);
  const trustOf = (c: KubeCluster): { ca?: string; servername?: string; insecure: boolean } => {
    const ca = c.caData !== undefined ? decodedPem(c.caData) : c.caFile !== undefined ? opts.readFile(abs(c.caFile)) : null;
    return { ...(ca ? { ca } : {}), ...(c.tlsServerName ? { servername: c.tlsServerName } : {}), insecure: c.insecure };
  };
  const trusts = clusters.map(trustOf);
  const first = trusts[0]!;
  if (trusts.some((t) => t.ca !== first.ca || t.servername !== first.servername || t.insecure !== first.insecure)) return null;
  const names = new Set(clusters.map((c) => c.name));
  const certUsers = new Map<string, { cert: string; key: string } | null>();
  for (const ctx of cfg.contexts) {
    if (!names.has(ctx.cluster)) continue;
    const u = cfg.users.find((x) => x.name === ctx.user);
    if (!u || (u.certData === undefined && u.certFile === undefined && u.keyData === undefined && u.keyFile === undefined)) continue;
    const cert = u.certData !== undefined ? decodedPem(u.certData) : u.certFile !== undefined ? opts.readFile(abs(u.certFile)) : null;
    const key = u.keyData !== undefined ? decodedPem(u.keyData) : u.keyFile !== undefined ? opts.readFile(abs(u.keyFile)) : null;
    certUsers.set(u.name, cert && key ? { cert, key } : null);
  }
  const out: KubeUpstream = { ...first };
  if (certUsers.size === 1) {
    const only = [...certUsers.values()][0]!;
    if (only) out.client = only;
    else out.clientWhy = "the user's client certificate or key could not be read";
  } else if (certUsers.size > 1) {
    out.clientWhy = `${certUsers.size} users with a client certificate share this server (${[...certUsers.keys()].join(", ")})`;
  }
  return out;
}
