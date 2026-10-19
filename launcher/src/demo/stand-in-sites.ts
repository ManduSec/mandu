/**
 * demo/stand-in-sites — the offline web `mandu demo`'s curl talks to
 * (mandu-demo.md §4a).
 *
 * Three HTTPS listeners on 127.0.0.1, each recording every request it
 * receives, byte for byte:
 *   - `api.stripe.com`, the host the key is bound to (it answers like
 *     Stripe's list endpoint, an empty list);
 *   - `paste.example`, a host the key is not bound to;
 *   - "elsewhere", the catch-all for any other host, which should never be
 *     reached at all.
 * The demo's egress proxy (interceptors/net-proxy) is started with a host
 * route for each (`MANDU_NET_PROXY_MOCK_SITES`, its `hosts:` list): the gate
 * runs first, unchanged, and a request it lets out is re-originated to the
 * matching listener instead of the internet, over TLS the proxy still
 * verifies, against this module's throwaway CA, for the host's own name. So
 * the bound host's listener holds exactly what a real Stripe would have
 * received, and nothing the demo does can leave the machine.
 *
 * The certificates are minted with the host's `openssl` CLI, as the egress
 * proxy mints its own CA. PROVENANCE: the CA and leaf commands are adapted
 * from interceptors/net-proxy/src/ca.ts (`ensureCa`, `leafForHost`); one leaf
 * carries every host, since the listeners are throwaway.
 *
 * Mandu-new (no reference origin) apart from that adaptation.
 */
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createServer as createTlsServer, type Server, type TLSSocket } from "node:tls";
import type { AddressInfo } from "node:net";
import { join } from "node:path";
import { BOUND_HOST, UNBOUND_HOST } from "./fixture.js";

/** One request a listener received: its head (latin1, as sent) and body. */
export interface Received { head: string; body: string }

export interface Site {
  port: number;
  received: Received[];
}

export interface StandInSites {
  bound: Site;
  unbound: Site;
  elsewhere: Site;
  /** The CA the egress proxy verifies the listeners against. */
  caPath: string;
  close: () => Promise<void>;
}

function openssl(args: string[], cwd: string): void {
  execFileSync("openssl", args, { cwd, stdio: ["ignore", "ignore", "pipe"] });
}

/** True when the `openssl` CLI runs. */
export function opensslAvailable(): boolean {
  try { execFileSync("openssl", ["version"], { stdio: "ignore" }); return true; } catch { return false; }
}

/** Mint a throwaway CA and one leaf for `hosts` under `dir`. */
export function mintSiteCerts(dir: string, hosts: string[]): { caPath: string; keyPem: string; certPem: string } {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  // An explicit -config, not -addext: OpenSSL 1.1.1 merges -addext with the
  // system openssl.cnf and emits duplicate extensions (net-proxy ca.ts).
  writeFileSync(join(dir, "ca.cnf"), [
    "[req]", "distinguished_name = dn", "x509_extensions = v3_ca", "prompt = no",
    "[dn]", "CN = mandu demo sites CA", "O = Mandu demo",
    "[v3_ca]", "basicConstraints = critical,CA:TRUE", "keyUsage = critical,keyCertSign,cRLSign", "subjectKeyIdentifier = hash", "",
  ].join("\n"));
  openssl(["ecparam", "-genkey", "-name", "prime256v1", "-out", "ca.key"], dir);
  openssl(["req", "-x509", "-new", "-nodes", "-key", "ca.key", "-sha256", "-days", "2", "-config", "ca.cnf", "-out", "ca.pem"], dir);
  openssl(["ecparam", "-genkey", "-name", "prime256v1", "-out", "site.key"], dir);
  openssl(["req", "-new", "-key", "site.key", "-subj", `/CN=${hosts[0]}`, "-out", "site.csr"], dir);
  writeFileSync(join(dir, "site.ext"), [
    "basicConstraints=CA:FALSE", "keyUsage=digitalSignature,keyEncipherment", "extendedKeyUsage=serverAuth",
    `subjectAltName=${hosts.map((h) => `DNS:${h}`).join(",")}`,
    "subjectKeyIdentifier=hash", "authorityKeyIdentifier=keyid", "",
  ].join("\n"));
  openssl(["x509", "-req", "-in", "site.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-days", "2", "-sha256", "-extfile", "site.ext", "-out", "site.pem"], dir);
  return { caPath: join(dir, "ca.pem"), keyPem: readFileSync(join(dir, "site.key"), "utf8"), certPem: readFileSync(join(dir, "site.pem"), "utf8") };
}

/** A recording HTTPS/1.1 listener answering `status` + `json`. */
async function listen(tls: { key: string; cert: string }, status: number, json: string): Promise<{ site: Site; server: Server }> {
  const received: Received[] = [];
  const server = createTlsServer(tls, (sock: TLSSocket) => {
    let buf = Buffer.alloc(0);
    sock.on("data", (d: Buffer) => {
      buf = Buffer.concat([buf, d]);
      for (;;) {
        const end = buf.indexOf("\r\n\r\n");
        if (end === -1) return;
        const head = buf.subarray(0, end + 4).toString("latin1");
        const len = Number(/\r\ncontent-length:\s*(\d+)/i.exec(head)?.[1] ?? "0");
        if (buf.length < end + 4 + len) return;
        received.push({ head, body: buf.subarray(end + 4, end + 4 + len).toString("utf8") });
        buf = buf.subarray(end + 4 + len);
        sock.write(`HTTP/1.1 ${status} ${status === 200 ? "OK" : "Not Found"}\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(json)}\r\n\r\n${json}`);
      }
    });
    sock.on("error", () => { /* a client that went away */ });
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  return { site: { port: (server.address() as AddressInfo).port, received }, server };
}

export async function startStandInSites(dir: string): Promise<StandInSites> {
  const c = mintSiteCerts(dir, [BOUND_HOST, UNBOUND_HOST]);
  const tls = { key: c.keyPem, cert: c.certPem };
  const bound = await listen(tls, 200, '{"object":"list","data":[],"has_more":false}');
  const unbound = await listen(tls, 200, '{"ok":true}');
  const elsewhere = await listen(tls, 404, '{"error":"the demo has no such site"}');
  const servers = [bound.server, unbound.server, elsewhere.server];
  return {
    bound: bound.site,
    unbound: unbound.site,
    elsewhere: elsewhere.site,
    caPath: c.caPath,
    close: () => Promise.all(servers.map((s) => new Promise<void>((r) => s.close(() => r())))).then(() => undefined),
  };
}

/** The egress proxy's mock-sites file: a host route per listener, and the
 *  catch-all `*` for every other host, so no request the gate lets out is
 *  ever dialed off this machine (net-proxy mock-sites.ts). Pure. */
export function routesYaml(s: Pick<StandInSites, "bound" | "unbound" | "elsewhere" | "caPath">): string {
  const route = (host: string, port: number): string[] => [
    `  - host: ${JSON.stringify(host)}`,
    `    tls_to: "127.0.0.1:${port}"`,
    `    to: "127.0.0.1:${port}"`,
    `    tls_ca: ${JSON.stringify(s.caPath)}`,
  ];
  return ["hosts:", ...route(BOUND_HOST, s.bound.port), ...route(UNBOUND_HOST, s.unbound.port), ...route("*", s.elsewhere.port), ""].join("\n");
}
