/**
 * kube-overlay — the session KUBECONFIG file that lets `kubectl` and `helm`
 * reach the launch HOME's clusters from the kubeconfig's placeholder copy
 * (docs/design/confidentiality/kube-wire-release.md).
 *
 * Mandu-new (no reference origin).
 *
 * kubectl trusts only the CA its kubeconfig names, so it refuses the session
 * proxy's certificate. The arbiter builds, from the kubeconfig's TWIN (no
 * secret in it), one entry per https cluster without the cluster's CA and
 * one per client-certificate user without the certificate and key
 * (`kubeOverlay` op, human plane). This module adds to each cluster the
 * session CA and the session proxy (`proxy-url`, so a cluster on a port the
 * session's network rules do not open, or in NO_PROXY, still goes through
 * the proxy), writes the file beside the session CA, and puts it FIRST in
 * KUBECONFIG: client-go takes a named entry whole from the first file that
 * has it, so these replace the twin's. The proxy then dials each cluster
 * with the real CA and, for a request without a bearer token, the real
 * client certificate (`kubeUpstream`).
 *
 * A certificate user's overlay entry holds a session-local STAND-IN client
 * certificate and key (`mintStandInClientCert`, beside the session CA): a
 * kubeconfig user with no credential at all makes the real kubectl ask for
 * a username and password on stdin ("Please enter Username:", client-go's
 * prompt for a user it cannot identify), which fails every command run
 * without a terminal (found by the live kubectl run, live-clients.md §3.3).
 * The stand-in is no secret: it is made for this session, signs nothing the
 * cluster sees (the proxy's TLS server asks kubectl for no certificate, and
 * the proxy presents the real one upstream), and carries no Authorization
 * header that would keep the proxy from presenting the real certificate.
 *
 * Best-effort, utility only: any failure leaves KUBECONFIG as it was, and
 * kubectl refuses the proxy as before (nothing leaks: the twin holds
 * placeholders).
 */

import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";

/** The arbiter's overlay entries (arbiter/policy/kubeconfig.ts `KubeOverlay`,
 *  mirrored: the launcher does not import the arbiter). */
export interface KubeOverlayEntries {
  clusters: Array<{ name: string; cluster: Record<string, unknown> }>;
  users: Array<{ name: string; user: Record<string, unknown> }>;
}

/** A stand-in client certificate's files. */
export interface StandInClientCert {
  cert: string;
  key: string;
}

/** Make (or find) the session's stand-in client certificate in `dir`: a
 *  self-signed P-256 certificate for `mandu-kube-stand-in` and its key, in
 *  ONE file (`client-certificate` and `client-key` both name it: client-go
 *  takes the certificate blocks from the one and the key block from the
 *  other), 0600. Not named like a key file (`*.key`, `*-key.pem`): the
 *  session's secret catalog would serve kubectl a placeholder copy of it
 *  (secret-catalog.ts `shape:private-key-file`), which client-go cannot
 *  load ("failed to find any PEM data in key input", the live run). Null
 *  when openssl fails (the overlay then has no certificate for the user,
 *  and kubectl asks for a username, as before). */
export function mintStandInClientCert(dir: string): StandInClientCert | null {
  const both = join(dir, "kube-stand-in-client.pem");
  if (existsSync(both)) return { cert: both, key: both };
  const tmpKey = join(dir, `.kube-stand-in.${process.pid}.k`);
  const tmpCert = join(dir, `.kube-stand-in.${process.pid}.c`);
  try {
    const r = spawnSync("openssl", [
      "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
      "-keyout", tmpKey, "-out", tmpCert, "-days", "30", "-subj", "/CN=mandu-kube-stand-in",
    ], { stdio: "ignore", timeout: 20_000 });
    if (r.status !== 0 || !existsSync(tmpCert) || !existsSync(tmpKey)) return null;
    writeFileSync(both, readFileSync(tmpCert, "utf8") + readFileSync(tmpKey, "utf8"), { mode: 0o600 });
    chmodSync(both, 0o600);
    return { cert: both, key: both };
  } catch {
    return null;
  } finally {
    for (const f of [tmpKey, tmpCert]) { try { unlinkSync(f); } catch { /* none */ } }
  }
}

/** The overlay file's text (JSON is a kubeconfig too): each cluster with
 *  `certificate-authority` the session CA file and `proxy-url` the session
 *  proxy, each user as the arbiter gave it plus, given one, the stand-in
 *  client certificate. Pure. */
export function kubeOverlayText(entries: KubeOverlayEntries, caCertPath: string, proxyUrl: string, standIn?: StandInClientCert): string {
  return JSON.stringify({
    apiVersion: "v1",
    kind: "Config",
    clusters: entries.clusters.map((c) => ({
      name: c.name,
      cluster: { ...c.cluster, "certificate-authority": caCertPath, "proxy-url": proxyUrl },
    })),
    users: entries.users.map((u) => ({
      name: u.name,
      user: { ...u.user, ...(standIn ? { "client-certificate": standIn.cert, "client-key": standIn.key } : {}) },
    })),
    contexts: [],
  }, null, 2) + "\n";
}

/**
 * The session's KUBECONFIG: the overlay first, then what kubectl would read
 * without Mandu (the user's KUBECONFIG, else `~/.kube/config`). Null when
 * the user's KUBECONFIG does not list `~/.kube/config` (the overlay is built
 * from that file only, so it would add clusters the user did not ask for).
 * Pure.
 */
export function sessionKubeconfig(userKubeconfig: string | undefined, home: string, overlayPath: string): string | null {
  const own = join(home, ".kube", "config");
  if (userKubeconfig === undefined || userKubeconfig.trim() === "") return `${overlayPath}:${own}`;
  const listed = userKubeconfig.split(":").filter((p) => p !== "");
  if (!listed.some((p) => resolve(p) === resolve(own))) return null;
  return [overlayPath, ...listed].join(":");
}

export interface LaunchKubeOverlayArgs {
  /** The launch HOME. */
  home: string;
  /** The registered (twinned) secret files of this launch. */
  twinned: readonly string[];
  /** The session CA cert (the egress proxy inspects TLS). */
  caCertPath: string;
  /** The session egress proxy. */
  netProxy: { host: string; port: number };
  /** The user's KUBECONFIG, if any. */
  userKubeconfig: string | undefined;
  /** The arbiter's `kubeOverlay` op over the HUMAN socket. */
  askOverlay: (path: string, home: string) => Promise<{ overlay: KubeOverlayEntries | null; reason: string }>;
  /** Write the file (defaults to writeFileSync, mode 0600). A test knob. */
  write?: (path: string, text: string) => void;
  /** Make the stand-in client certificate in a folder (defaults to
   *  mintStandInClientCert). A test knob. */
  mintStandIn?: (dir: string) => StandInClientCert | null;
}

/** Write the overlay for the launch HOME's twinned `~/.kube/config` and
 *  return the session KUBECONFIG and a launch note, or null (with why). */
export async function writeLaunchKubeOverlay(args: LaunchKubeOverlayArgs): Promise<{ kubeconfig: string; note: string } | { kubeconfig: null; why: string }> {
  const own = resolve(join(args.home, ".kube", "config"));
  const path = args.twinned.find((p) => resolve(p) === own);
  if (path === undefined) return { kubeconfig: null, why: "~/.kube/config is not protected this launch" };
  const overlayPath = join(dirname(args.caCertPath), "kube-overlay.json");
  const kubeconfig = sessionKubeconfig(args.userKubeconfig, args.home, overlayPath);
  if (kubeconfig === null) return { kubeconfig: null, why: "KUBECONFIG does not list ~/.kube/config" };
  const r = await args.askOverlay(path, args.home);
  if (r.overlay === null || r.overlay.clusters.length === 0) return { kubeconfig: null, why: r.reason };
  const host = args.netProxy.host.includes(":") ? `[${args.netProxy.host}]` : args.netProxy.host;
  const standIn = r.overlay.users.length > 0 ? (args.mintStandIn ?? mintStandInClientCert)(dirname(args.caCertPath)) : null;
  const text = kubeOverlayText(r.overlay, args.caCertPath, `http://${host}:${args.netProxy.port}`, standIn ?? undefined);
  (args.write ?? ((p, t) => writeFileSync(p, t, { mode: 0o600 })))(overlayPath, text);
  const n = r.overlay.clusters.length;
  const certNote = r.overlay.users.length > 0 && standIn === null
    ? "; ! no stand-in client certificate could be made (openssl), so kubectl asks a certificate user for a username"
    : "";
  return {
    kubeconfig,
    note: `mandu: kubectl and helm reach ${n} cluster${n === 1 ? "" : "s"} of ~/.kube/config through Mandu's proxy, which signs in with the real token or certificate there${certNote}`,
  };
}
