/**
 * netns — two "machines" on one private network, on this host, with no root
 * (confidentiality plan 12 §6: the `network` legs; the stand-in for the VM
 * matrix's "two guests on one user-mode network").
 *
 * One unprivileged user namespace (`unshare -rnm`: user, network and mount)
 * holds two network namespaces joined by a veth pair:
 *
 *   this side (the test's scenario)          the peer ("the other machine")
 *   mandu0  10.77.0.1/24  ─────── veth ─────── mandu1  10.77.0.2/24
 *                                                      203.0.113.9/32
 *
 * 10.77.0.2 plays an address on the organization's network; 203.0.113.9 (a
 * documentation range, TEST-NET-3) plays one outside it. The peer answers on
 * both, so a check that lets the wrong one through is seen on the wire, not
 * just in an error string. Names resolve through a hosts file bind-mounted
 * over /etc/hosts in the private mount namespace (getaddrinfo reads files
 * first), which is how a test gives a name a DNS answer it chose.
 *
 * Everything is torn down with the namespaces when the script exits. What it
 * does not model: a separate filesystem or kernel (the peer shares both), and
 * routing beyond one link. For the transport rules (which address a client
 * connects to, what crosses the wire) that is the point.
 *
 * `peerHostLoopback` (the live leg) also gives the peer a way out to THIS
 * host's loopback: slirp4netns, started from the host side into the peer's
 * namespaces (as rootless containers do), answers 10.0.2.2 with the host's
 * 127.0.0.1, so a relay on the peer can front a real model server (an
 * Ollama) running on the host.
 *
 * `selfInternet` (the full live drill) gives THIS side a way out to the
 * internet the same way (slirp4netns with a default route, the host's
 * loopback disabled) and a resolv.conf naming slirp's DNS (10.0.2.3),
 * bind-mounted like the hosts file: the real `claude` reaches Anthropic
 * while the declared model is still reached only over the veth. Without it
 * this side has no route but the veth.
 *
 * Self-SKIP: `twoHostNetUnavailable()` names why (no unshare / nsenter / ip,
 * or user namespaces refused, e.g. an AppArmor userns restriction);
 * `slirpUnavailable()` for the live leg.
 * PROVENANCE: NEW Mandu test code.
 */
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export const TWO_HOST = {
  /** This side's address. */
  self: "10.77.0.1",
  /** The peer's address on "the organization's network". */
  inside: "10.77.0.2",
  /** The peer's second address, outside that network. */
  outside: "203.0.113.9",
  /** The organization's network, as a perimeter would list it. */
  network: "10.77.0.0/24",
} as const;

let probed: string | null | undefined;

/** null when the topology can be built here, else the reason to skip. */
export function twoHostNetUnavailable(): string | null {
  if (probed !== undefined) return probed;
  const r = spawnSync("unshare", ["-rnm", "--", "sh", "-c", "ip link add a0 type veth peer name a1 && ip link del a0 && command -v nsenter >/dev/null"], { encoding: "utf8", timeout: 10_000 });
  probed = r.error ? `unshare is not available (${r.error.message})` : r.status === 0 ? null : `unprivileged network namespaces are refused here (${(r.stderr || "").trim().split("\n")[0] || `exit ${r.status}`})`;
  return probed;
}

/** null when slirp4netns is on PATH, else the reason to skip. */
export function slirpUnavailable(): string | null {
  const r = spawnSync("slirp4netns", ["--version"], { encoding: "utf8" });
  return r.error || r.status !== 0 ? "slirp4netns is not on PATH" : null;
}

/** The host's loopback as the peer sees it with `peerHostLoopback`. */
export const HOST_FROM_PEER = "10.0.2.2";

const q = (s: string): string => `'${s.replace(/'/g, `'\\''`)}'`;

export interface TwoHostRun {
  /** The hosts file: name → addresses (one line per address). localhost is added. */
  hosts: Record<string, string[]>;
  /** argv of the peer's server, run in the peer namespace. */
  peer: string[];
  /** A file the peer creates when it listens. */
  peerReady: string;
  /** argv of the scenario, run on this side. */
  main: string[];
  env?: NodeJS.ProcessEnv;
  timeoutMs?: number;
  /** Give the peer a way out to this host's loopback (slirp4netns). */
  peerHostLoopback?: boolean;
  /** Give this side a way out to the internet (slirp4netns) and slirp's DNS. */
  selfInternet?: boolean;
  /** This side's resolver, bind-mounted over /etc/resolv.conf (one
   *  `nameserver` line per address): a DNS server the test runs on the peer.
   *  Ignored with `selfInternet`, which names slirp's. */
  resolvers?: string[];
  /** Resolve names through the hosts file and DNS only (an nsswitch.conf
   *  bind-mounted over /etc/nsswitch.conf): no host service (nss-resolve,
   *  systemd-resolved) answers a lookup made on this side. */
  plainNss?: boolean;
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/** Build the topology, start the peer, run the scenario, tear down. The
 *  scenario's exit status and output. */
export async function runTwoHostNet(o: TwoHostRun): Promise<{ status: number | null; stdout: string; stderr: string }> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-netns-"));
  const peerPid = join(dir, "peer.pid");
  const slirpReady = join(dir, "slirp.ready");
  const selfPid = join(dir, "self.pid");
  const selfReady = join(dir, "self-slirp.ready");
  const slirps: ChildProcess[] = [];
  try {
    const hosts = join(dir, "hosts");
    const lines = ["127.0.0.1 localhost", "::1 localhost"];
    for (const [name, addrs] of Object.entries(o.hosts)) for (const a of addrs) lines.push(`${a} ${name}`);
    writeFileSync(hosts, lines.join("\n") + "\n");
    const resolv = join(dir, "resolv.conf");
    writeFileSync(resolv, "nameserver 10.0.2.3\n");
    const ownResolv = join(dir, "resolv.own.conf");
    writeFileSync(ownResolv, (o.resolvers ?? []).map((a) => `nameserver ${a}`).join("\n") + "\noptions timeout:1 attempts:1\n");
    const nss = join(dir, "nsswitch.conf");
    writeFileSync(nss, "passwd: files\ngroup: files\nhosts: files dns\n");
    const script = join(dir, "run.sh");
    writeFileSync(script, [
      "set -eu",
      "ip link set lo up",
      "unshare -n -- sleep 600 &",
      "PEER=$!",
      "SELF=$(readlink /proc/self/ns/net)",
      'for i in $(seq 1 100); do [ "$(readlink /proc/$PEER/ns/net 2>/dev/null)" != "$SELF" ] && break; sleep 0.05; done',
      "trap 'kill $PEER ${SRV:-} 2>/dev/null || true' EXIT",
      ...(o.peerHostLoopback
        ? [
          `echo $PEER > ${q(peerPid)}`,
          `for i in $(seq 1 200); do [ -e ${q(slirpReady)} ] && break; sleep 0.05; done`,
          `[ -e ${q(slirpReady)} ] || { echo 'slirp4netns did not attach to the peer' >&2; exit 96; }`,
        ]
        : []),
      "ip link add mandu0 type veth peer name mandu1 netns $PEER",
      `ip addr add ${TWO_HOST.self}/24 dev mandu0`,
      "ip link set mandu0 up",
      `ip route add ${TWO_HOST.outside}/32 dev mandu0`,
      `nsenter -t $PEER -n -- sh -c 'ip link set lo up && ip addr add ${TWO_HOST.inside}/24 dev mandu1 && ip addr add ${TWO_HOST.outside}/32 dev mandu1 && ip link set mandu1 up'`,
      `mount --bind ${q(hosts)} /etc/hosts`,
      ...(o.resolvers && !o.selfInternet ? [`mount --bind ${q(ownResolv)} /etc/resolv.conf`] : []),
      ...(o.plainNss ? [`mount --bind ${q(nss)} /etc/nsswitch.conf`] : []),
      ...(o.selfInternet
        ? [
          `echo $$ > ${q(selfPid)}`,
          `for i in $(seq 1 200); do [ -e ${q(selfReady)} ] && break; sleep 0.05; done`,
          `[ -e ${q(selfReady)} ] || { echo 'slirp4netns did not attach to this side' >&2; exit 95; }`,
          `mount --bind ${q(resolv)} /etc/resolv.conf`,
        ]
        : []),
      `nsenter -t $PEER -n -- ${o.peer.map(q).join(" ")} &`,
      "SRV=$!",
      `for i in $(seq 1 400); do [ -e ${q(o.peerReady)} ] && break; sleep 0.05; done`,
      `[ -e ${q(o.peerReady)} ] || { echo 'the peer did not start' >&2; exit 97; }`,
      "set +e",
      o.main.map(q).join(" "),
      "exit $?",
    ].join("\n") + "\n");
    const child = spawn("unshare", ["-rnm", "--", "bash", script], { env: o.env ?? process.env, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8").on("data", (d: string) => { stdout += d; });
    child.stderr.setEncoding("utf8").on("data", (d: string) => { stderr += d; });
    const exited = new Promise<number | null>((resolve) => child.on("close", (code) => resolve(code)));
    const timer = setTimeout(() => child.kill("SIGKILL"), o.timeoutMs ?? 120_000);
    try {
      // slirp4netns from the host side, into a namespace's user and network
      // namespaces (inside the userns it would reach only the isolated ns).
      const attach = async (pidFile: string, ready: string, extra: string[]): Promise<void> => {
        for (let i = 0; i < 200 && !existsSync(pidFile); i++) await sleep(50);
        const pid = existsSync(pidFile) ? readFileSync(pidFile, "utf8").trim() : "";
        if (pid === "") return;
        slirps.push(spawn("slirp4netns", ["--configure", "--mtu=65520", ...extra, `--userns-path=/proc/${pid}/ns/user`, pid, "tap0"], { stdio: "ignore" }));
        await sleep(800);
        writeFileSync(ready, "up\n");
      };
      if (o.peerHostLoopback) await attach(peerPid, slirpReady, []);
      if (o.selfInternet) await attach(selfPid, selfReady, ["--disable-host-loopback"]);
      const status = await exited;
      return { status, stdout, stderr };
    } finally {
      clearTimeout(timer);
    }
  } finally {
    for (const s of slirps) s.kill();
    rmSync(dir, { recursive: true, force: true });
  }
}
