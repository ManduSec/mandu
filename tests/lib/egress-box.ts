/**
 * egress-box — the bypass oracle's recorder: run a program (an OpenClaw
 * Gateway, its clients, a launcher's agent) where NOTHING can leave except
 * through the Mandu model proxy, and record every connection it tries
 * (docs/design/agents/model-wires.md §11, "The bypass oracle").
 *
 * NEW Mandu test code (no reference origin). Every model call that slipped
 * around Mandu's proxy so far was found by hand (an OpenRouter model OpenClaw
 * 2026.3.12 did not know, GitHub Copilot's sign-in endpoint, Azure's endpoint
 * variables); this records the next one without the program's cooperation.
 *
 * THE BOX (strongest tier first; the first one this host allows is used, and
 * `tier` + `why` say which and why not a stronger one):
 *   netns+caps  `unshare` makes a user, network, mount and PID namespace
 *               (no host root: an unprivileged user namespace). Inside: only
 *               loopback, EVERY IPv4 address routed to it (`ip route add
 *               local 0.0.0.0/0 dev lo`), a hosts file with only localhost,
 *               nsswitch `files dns`, resolv.conf at the box's own DNS stub.
 *               The box host (egress-box-host.mjs) holds the only ways out
 *               (one bridge per allowed port: the proxy's), a catch-all on
 *               80, 443 and every catch port, and the DNS stub. The programs
 *               run in a nested user namespace as the invoking uid, with no
 *               capability. A dial to any IPv4 address on a catch port is
 *               recorded with the name it was looked up by, its TLS SNI or
 *               HTTP request line; a dial to any other port is refused.
 *   netns       where capabilities in a user namespace are refused (Ubuntu's
 *               AppArmor userns restriction: bubblewrap is allowed, without
 *               capabilities): `bwrap` makes the same namespaces, loopback
 *               only; the hosts file maps every known model-API host to an
 *               address of its own on loopback; no DNS stub (port 53) and no
 *               catch-all on 80/443 (ports below 1024): a dial to a provider
 *               host is refused, so nothing leaves, but it is not attributed;
 *               the catch ports above 1024 (the scripted upstreams' own) are.
 *   inproc      no namespace at all: the WEAK fallback. The programs run here
 *               with `NODE_OPTIONS=--require egress-inproc.cjs` (Node's
 *               `net`/`tls`/`dns` in each Node process that loads it: no
 *               child that is not Node, no native code) and HTTPS_PROXY at a
 *               refusing recorder. Every test that uses it must say so in
 *               its output (`tier`).
 *
 * THE PEEK CERTIFICATE (`tlsPeek`, default on where openssl is): the
 * catch-all terminates TLS with a throwaway certificate the programs in the
 * box (only) are told to accept, so a dial to a provider's 443 is recorded
 * with its request line and the head of its body.
 *
 * THE VERDICT (`judgeEgress`, pure): a bridged connection on a proxy port is
 * the route; a connection to a scripted upstream's own port, to a known
 * model-API host (by name, SNI or Host), or carrying a model-API path is a
 * BYPASS, except a request read in full that is a bodiless GET, HEAD or
 * OPTIONS on no model-API path (PROVIDER-SIDE: a catalog, a probe; reported);
 * anything else is UNKNOWN egress, which fails too unless the caller names
 * it benign with a reason (fail-closed). A model call that a version
 * sent anywhere but the proxy therefore either shows as a bypass or, where
 * the dial was refused unrecorded (netns tier, a port with no listener),
 * never reached a model: the caller's utility control (the scripted upstream
 * behind the proxy received the call) is what turns that into a red.
 *
 * What it does not see: a connection to a port outside the catch ports on
 * the strongest tier is refused, not recorded (no packet capture); IPv6 has
 * only ::1; the bridge is not the proxy (a program could speak to the proxy
 * port something that is not a model call: the proxy's own checks judge it).
 */
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { appendFileSync, chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { createServer as createHttpServer, type Server as HttpServer } from "node:http";
import { connect, createServer, type Server, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const HOST_SCRIPT = join(HERE, "egress-box-host.mjs");
const SHIM_SCRIPT = join(HERE, "egress-box-shim.mjs");
const INPROC = join(HERE, "egress-inproc.cjs");

export type EgressTier = "netns+caps" | "netns" | "inproc";
export const EGRESS_TIERS: readonly EgressTier[] = ["netns+caps", "netns", "inproc"];

/** One thing the box saw. */
export interface EgressRecord {
  t: number;
  /** bridge: through an allowed port (the proxy); catch: the catch-all;
   *  dns: a query at the stub; inproc / inproc-dns: the fallback recorder;
   *  proxy-env: a request at the fallback's HTTPS_PROXY recorder. */
  via: "bridge" | "catch" | "dns" | "inproc" | "inproc-dns" | "proxy-env";
  port?: number;
  laddr?: string;
  lport?: number;
  name?: string | null;
  sni?: string;
  http?: { method: string; path: string; host: string | null };
  host?: string;
  answer?: string;
  qtype?: number;
  bytes?: number;
  /** The head of the request body (a TLS connection read with the peek
   *  certificate, or plain HTTP at the catch-all). */
  body?: string;
  /** A TLS connection that sent no request after the handshake. */
  tls?: string;
  /** The process that dialed (a catch-all connection): its pid and the
   *  command lines of it and up to three parents. */
  dialer?: EgressDialer;
  /** Why no dialer could be named (the socket gone, or held by no process
   *  the box can see). */
  dialerWhy?: string;
  pid?: number;
}

/**
 * The model-API hosts a provider's calls go to when no route holds: the
 * built-in addresses of every provider OpenClaw (and the other agents Mandu
 * routes) knows. In the netns tier the hosts file maps each one to an
 * address of its own on loopback; the judge calls a connection to one (by
 * name, SNI or Host) a bypass. `isModelApiHost` adds the families whose
 * hosts carry a tenant or region (Azure, Vertex, Bedrock, Copilot).
 */
export const MODEL_API_HOSTS: readonly string[] = [
  "api.anthropic.com", "api.openai.com", "chatgpt.com", "openrouter.ai",
  "generativelanguage.googleapis.com", "aiplatform.googleapis.com", "us-central1-aiplatform.googleapis.com",
  "cloudcode-pa.googleapis.com", "oauth2.googleapis.com",
  "api.githubcopilot.com", "api.individual.githubcopilot.com", "api.github.com", "github.com",
  "ollama.com", "api.x.ai", "api.groq.com", "api.mistral.ai", "api.deepseek.com", "api.together.xyz",
  "api.fireworks.ai", "api.cerebras.ai", "api.moonshot.ai", "api.minimax.io", "api.z.ai", "open.bigmodel.cn",
  "dashscope.aliyuncs.com", "dashscope-intl.aliyuncs.com", "api.venice.ai", "api.perplexity.ai", "api.cohere.ai",
  "integrate.api.nvidia.com", "router.huggingface.co", "api-inference.huggingface.co", "api.synthetic.new",
  "bedrock-runtime.us-east-1.amazonaws.com", "bedrock.us-east-1.amazonaws.com",
  "mandu-lane.openai.azure.com", "mandu-lane.cognitiveservices.azure.com",
  "opencode.ai", "api.kimi.com", "qianfan.baidubce.com", "api.longcat.chat", "api.chutes.ai", "llm.chutes.ai",
];

/** Is `host` a model-API host (MODEL_API_HOSTS, or a tenant/region family)? */
export function isModelApiHost(host: string | null | undefined): boolean {
  if (!host) return false;
  const h = host.toLowerCase().replace(/:\d+$/, "").replace(/\.$/, "");
  if (MODEL_API_HOSTS.includes(h)) return true;
  if (/(^|[.-])aiplatform\.googleapis\.com$/.test(h)) return true; // Vertex AI: <region>-aiplatform…
  return /(^|\.)(openai\.azure\.com|cognitiveservices\.azure\.com|services\.ai\.azure\.com|githubcopilot\.com|generativelanguage\.googleapis\.com|bedrock-runtime\.[a-z0-9-]+\.amazonaws\.com|anthropic\.com|openai\.com|openrouter\.ai)$/.test(h);
}

/** Does an HTTP path name a model API (any wire Mandu or a provider speaks)? */
export function isModelApiPath(path: string | null | undefined): boolean {
  if (!path) return false;
  const p = path.split("?")[0]!;
  return /\/(chat\/completions|completions|responses|messages|embeddings)$/.test(p)
    || /:(stream)?[gG]enerateContent$/.test(p)
    || /\/api\/(chat|generate)$/.test(p)
    || /\/model\/[^/]+\/(converse|converse-stream|invoke|invoke-with-response-stream)$/.test(p)
    || /\/codex\/responses$/.test(p)
    || /\/interactions$/.test(p);
}

/** The process behind a connection or a lookup: one process (`pid`, its
 *  command line and up to three parents'), or, when the holder hid its
 *  descriptors (a non-dumpable process: /proc/<pid>/fd unreadable), the
 *  processes it must be one of (`pid: null`, `candidates`, `why`). */
export interface EgressDialer {
  pid: number | null;
  chain: string[];
  candidates?: Array<{ pid: number; chain: string[] }>;
  why?: string;
}

/** The command lines a dialer may be: its own, or each candidate's. */
export function dialerCommands(d: EgressDialer | undefined): string[] {
  if (d === undefined) return [];
  if (d.pid !== null) return [d.chain[0] ?? ""];
  return (d.candidates ?? []).map((c) => c.chain[0] ?? "");
}

/** A dialer for people. */
export function dialerWords(d: EgressDialer): string {
  if (d.pid !== null) return `by pid ${d.pid}: ${d.chain.map((c) => c.slice(0, 120)).join(" <- ")}`;
  return `by one of ${(d.candidates ?? []).map((c) => `pid ${c.pid}: ${(c.chain[0] ?? "").slice(0, 80)}`).join("; ")} (${d.why ?? "descriptors unreadable"})`;
}

/** One finding of the judge. */
export interface EgressFinding {
  record: EgressRecord;
  why: string;
}

export interface EgressVerdict {
  /** Connections through the proxy (bridged, or an in-process connect to it). */
  proxied: EgressRecord[];
  /** Model calls (or their first step) that went anywhere but the proxy. */
  bypass: EgressFinding[];
  /** Egress that is no known model call, not named benign: fails too. */
  unknown: EgressFinding[];
  /** Egress named benign by the caller (reported, not failed). */
  benign: EgressFinding[];
  /** A request READ in full to a model-API host that is no model call: a
   *  GET, HEAD or OPTIONS with no body on a path that names no model API (a
   *  model catalog, a connectivity probe). Reported, not failed: it carries
   *  no conversation. Anything less certain (a POST, a body, a TLS session
   *  whose request was not read) is a bypass. */
  providerSide: EgressFinding[];
  /** DNS queries for model-API hosts (with or without a connect after). */
  lookups: EgressRecord[];
}

export interface JudgeOptions {
  /** The Mandu proxy's ports (bridged out of the box). */
  proxyPorts: readonly number[];
  /** Each scripted upstream's port → the provider it stands for: a dial to
   *  one from inside the box is that provider's call sent around the proxy. */
  upstreamPorts?: Readonly<Record<number, string>>;
  /** Loopback ports of the program's own (the Gateway's): in-process
   *  records of connects to them are not egress (the inproc tier only). */
  ownPorts?: readonly number[];
  /** Hosts whose connections are no model call, each with why (reported). */
  benignHosts?: Readonly<Record<string, string>>;
  /** Programs whose connections are no model call, matched on the dialer's
   *  own command line, each with why: a connection one of them makes, on no
   *  model-API path, is reported as benign whatever its host (a CLI's sign-in
   *  check the agent runs, say). */
  benignDialers?: ReadonlyArray<{ command: RegExp; why: string }>;
}

const LOOPBACK = (h: string | undefined): boolean => h === undefined || h === "localhost" || /^127\./.test(h) || h === "::1" || h === "::ffff:127.0.0.1";

/** Judge what a box recorded. Pure. */
export function judgeEgress(records: readonly EgressRecord[], o: JudgeOptions): EgressVerdict {
  const v: EgressVerdict = { proxied: [], bypass: [], unknown: [], benign: [], providerSide: [], lookups: [] };
  const upstream = o.upstreamPorts ?? {};
  const benignOf = (h: string | null | undefined): string | undefined => {
    if (!h) return undefined;
    const k = h.toLowerCase().replace(/:\d+$/, "");
    return o.benignHosts?.[k];
  };
  for (const r of records) {
    if (r.via === "bridge") {
      if (r.port !== undefined && o.proxyPorts.includes(r.port)) v.proxied.push(r);
      else v.unknown.push({ record: r, why: `a bridged connection on port ${r.port}, which is not the proxy's` });
      continue;
    }
    if (r.via === "dns" || r.via === "inproc-dns") {
      if (isModelApiHost(r.name)) v.lookups.push(r);
      continue;
    }
    const name = r.via === "catch" ? (r.sni ?? r.http?.host ?? r.name ?? null) : (r.sni ?? r.host ?? null);
    const port = r.via === "catch" ? r.lport : r.port;
    const where = (r.via === "catch"
      ? `${r.laddr}:${r.lport}${r.name ? ` (${r.name})` : ""}${r.sni ? ` SNI ${r.sni}` : ""}${r.http ? ` ${r.http.method} ${r.http.path}${r.http.host ? ` Host ${r.http.host}` : ""}` : ""}`
      : `${r.host ?? "?"}:${r.port ?? "?"}${r.sni ? ` SNI ${r.sni}` : ""}`) + (r.tls ? ` [TLS: ${r.tls}]` : "")
      + (r.dialer ? ` [${dialerWords(r.dialer)}]` : r.dialerWhy ? ` [no dialer: ${r.dialerWhy}]` : "");
    if (r.via === "inproc") {
      if (LOOPBACK(r.host) && port !== undefined && o.proxyPorts.includes(port)) { v.proxied.push(r); continue; }
      if (LOOPBACK(r.host) && port !== undefined && upstream[port] !== undefined) {
        v.bypass.push({ record: r, why: `dialed the ${upstream[port]} provider's own address directly (${where}), around the proxy` });
        continue;
      }
      if (LOOPBACK(r.host)) continue; // the program's own loopback services (the inproc tier cannot tell more)
    }
    if (r.via === "catch" && port !== undefined && upstream[port] !== undefined && LOOPBACK(r.laddr)) {
      v.bypass.push({ record: r, why: `dialed the ${upstream[port]} provider's own address directly (${where}), around the proxy` });
      continue;
    }
    const benignDialer = (chain0: string): { why: string } | undefined => o.benignDialers?.find((d) => d.command.test(chain0));
    // Benign by its program only when every process it can be is named
    // benign (one process, or each of the hidden candidates).
    const benignAll = (d: EgressDialer | undefined): { why: string } | undefined => {
      const cmds = dialerCommands(d);
      const hits = cmds.map(benignDialer);
      return cmds.length > 0 && hits.every((h) => h !== undefined) ? hits[0] : undefined;
    };
    const byDialer = benignAll(r.dialer);
    if (byDialer !== undefined && !isModelApiPath(r.http?.path)) {
      v.benign.push({ record: r, why: `${where}: ${byDialer.why}` });
      continue;
    }
    // A dialer gone before its connection was read (a probe that exits at
    // once): the processes that looked its address up, when every one of
    // them is a benign program.
    if (r.via === "catch" && r.dialer === undefined && !isModelApiPath(r.http?.path)) {
      const askers = records.filter((x) => x.via === "dns" && x.answer === r.laddr);
      const named = askers.filter((x) => x.dialer !== undefined);
      const all = named.length > 0 && named.length === askers.length ? named.map((x) => benignAll(x.dialer)) : [];
      if (all.length > 0 && all.every((b) => b !== undefined)) {
        v.benign.push({ record: r, why: `${where} [looked up ${named.map((x) => dialerWords(x.dialer!)).join("; ")}]: ${all[0]!.why}` });
        continue;
      }
    }
    if ((isModelApiHost(name) || isModelApiHost(r.name)) && r.http !== undefined && /^(GET|HEAD|OPTIONS)$/.test(r.http.method)
      && (r.body ?? "") === "" && !isModelApiPath(r.http.path)) {
      v.providerSide.push({ record: r, why: `a ${r.http.method} with no body to a model-API host, no model call (${where})` });
      continue;
    }
    if (isModelApiHost(name) || isModelApiHost(r.name)) {
      v.bypass.push({ record: r, why: `a connection to a model-API host (${where}), around the proxy` });
      continue;
    }
    if (isModelApiPath(r.http?.path)) {
      v.bypass.push({ record: r, why: `a model-API request (${where}), around the proxy` });
      continue;
    }
    const b = benignOf(name) ?? benignOf(r.name);
    if (b !== undefined) { v.benign.push({ record: r, why: `${where}: ${b}` }); continue; }
    v.unknown.push({ record: r, why: `egress to ${where}: not the proxy, and not named benign` });
  }
  return v;
}

/** The judge's findings for a failure message. */
export function describeVerdict(v: EgressVerdict): string {
  const lines = [
    `${v.proxied.length} connection(s) through the proxy`,
    ...v.bypass.map((f) => `BYPASS: ${f.why}`),
    ...v.unknown.map((f) => `UNKNOWN: ${f.why}`),
    ...v.benign.map((f) => `benign: ${f.why}`),
    ...v.providerSide.map((f) => `provider-side: ${f.why}`),
    ...v.lookups.map((r) => `lookup: ${r.name}${r.answer ? ` → ${r.answer}` : ""}${r.dialer ? ` [${dialerWords(r.dialer)}]` : r.dialerWhy ? ` [no dialer: ${r.dialerWhy}]` : ""}`),
  ];
  return lines.join("\n");
}

// ── the box ──────────────────────────────────────────────────────────────────

export interface EgressExecResult {
  code: number | null;
  signal: string | null;
  stdout: string;
  stderr: string;
}

export interface EgressProc {
  done: Promise<EgressExecResult>;
  /** Signal the command's process group (in the box: through its control connection). */
  kill(signal?: NodeJS.Signals): void;
  exited(): boolean;
}

export interface EgressExecOptions {
  env: Record<string, string>;
  cwd: string;
  timeoutMs?: number;
  /** Append the command's output here as it comes (a long-running Gateway). */
  logFile?: string;
}

export interface EgressBox {
  tier: EgressTier;
  /** Why not a stronger tier (empty for netns+caps). */
  why: string;
  /** What the box host could set up (its ready.json), or null (inproc). */
  facts: Record<string, unknown> | null;
  dir: string;
  exec(argv: string[], o: EgressExecOptions): EgressProc;
  run(argv: string[], o: EgressExecOptions): Promise<EgressExecResult>;
  /** A directory holding an executable `name` that runs `real` in the box
   *  (put it first on PATH of a program that spawns `name`). */
  shimDir(name: string, real: string): string;
  /** Environment a program in the box should carry (inproc: the recorder). */
  envFor(env: Record<string, string>): Record<string, string>;
  records(): EgressRecord[];
  close(): Promise<void>;
}

export interface EgressBoxOptions {
  /** Ports bridged out of the box to the same port on this host's loopback:
   *  the Mandu model proxy's. */
  allow: number[];
  /** More ports for the catch-all (each scripted upstream's own port, so a
   *  dial straight to it from inside is recorded). */
  catchPorts?: number[];
  /** The tiers to try, strongest first (default: all). */
  tiers?: readonly EgressTier[];
  /** Terminate TLS at the catch-all with a throwaway certificate the
   *  programs in the box are told to accept (NODE_TLS_REJECT_UNAUTHORIZED=0
   *  in their environment), to read the request's path and body head
   *  (default true; needs openssl, else off and said in `facts`). */
  tlsPeek?: boolean;
  /** Host executables the box needs (node by default: this process's). */
  node?: string;
}

const MODEL_HOST_BASE = "127.77.1.";

/** The address each model-API host answers with in the box. */
export function modelHostAddresses(): Record<string, string> {
  const out: Record<string, string> = {};
  MODEL_API_HOSTS.forEach((h, i) => { out[`${MODEL_HOST_BASE}${i + 1}`] = h; });
  return out;
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

function which(cmd: string): string | null {
  for (const d of (process.env["PATH"] ?? "").split(":")) {
    if (d && existsSync(join(d, cmd))) return join(d, cmd);
  }
  return null;
}

/** Start a box (see the header). Never throws for a missing mechanism: the
 *  weakest tier asked for is the floor, and `tier` says which one ran. */
export async function startEgressBox(o: EgressBoxOptions): Promise<EgressBox> {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "mdu-box-")));
  chmodSync(dir, 0o700);
  const node = o.node ?? process.execPath;
  const outerServers: Server[] = [];
  // The outer half of each bridge: the unix socket the box host dials.
  for (const port of o.allow) {
    const srv = createServer((inner: Socket) => {
      const outer = connect({ host: "127.0.0.1", port });
      inner.pipe(outer);
      outer.pipe(inner);
      const end = (): void => { inner.destroy(); outer.destroy(); };
      inner.on("error", end); outer.on("error", end); inner.on("close", end); outer.on("close", end);
    });
    await new Promise<void>((r) => srv.listen(join(dir, `out-${port}.sock`), () => r()));
    outerServers.push(srv);
  }
  const tiers = o.tiers ?? EGRESS_TIERS;
  const why: string[] = [];
  const names = modelHostAddresses();
  for (const tier of tiers) {
    if (tier === "inproc") return startInproc(dir, o, outerServers, why.join("; "));
    const r = await tryNamespace(tier, dir, o, node, names);
    if (typeof r === "string") { why.push(`${tier}: ${r}`); continue; }
    return makeNsBox(tier, dir, r.child, r.facts, outerServers, why.join("; "));
  }
  for (const s of outerServers) s.close();
  rmSync(dir, { recursive: true, force: true });
  throw new Error(`no egress box tier is available here: ${why.join("; ")}`);
}

/** The reason no box of the netns tiers can be made here, or null (a
 *  cheap probe for a suite's skip line). */
export function egressNamespaceUnavailable(): string | null {
  const u = spawnSync("unshare", ["--user", "--map-root-user", "--net", "--", "ip", "link", "set", "lo", "up"], { encoding: "utf8", timeout: 10_000 });
  if (u.status === 0) return null;
  const b = spawnSync("bwrap", ["--unshare-user", "--unshare-net", "--ro-bind", "/", "/", "--", "/bin/true"], { encoding: "utf8", timeout: 10_000 });
  if (b.status === 0) return null;
  return `no private network namespace: unshare (${(u.stderr || u.error?.message || `exit ${u.status}`).trim().split("\n")[0]}), bwrap (${(b.stderr || b.error?.message || `exit ${b.status}`).trim().split("\n")[0]})`;
}

const q = (s: string): string => `'${s.replace(/'/g, `'\\''`)}'`;

async function tryNamespace(
  tier: "netns+caps" | "netns", dir: string, o: EgressBoxOptions, node: string, names: Record<string, string>,
): Promise<{ child: ChildProcess; facts: Record<string, unknown> } | string> {
  const sub = join(dir, tier === "netns+caps" ? "caps" : "plain");
  mkdirSync(sub, { recursive: true });
  // The peek certificate: throwaway, for this box only.
  let tls: { key: string; cert: string } | null = null;
  if (o.tlsPeek !== false) {
    const key = join(sub, "peek.key");
    const cert = join(sub, "peek.crt");
    const r = spawnSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert, "-days", "1", "-subj", "/CN=mandu-egress-box"], { encoding: "utf8", timeout: 30_000 });
    if (r.status === 0 && existsSync(cert)) tls = { key, cert };
  }
  // With a DNS stub (caps), the model hosts are left to it so each lookup is
  // recorded; without one, the hosts file answers them.
  const hostLines = ["127.0.0.1 localhost", "::1 localhost"];
  if (tier === "netns") for (const [a, h] of Object.entries(names)) hostLines.push(`${a} ${h}`);
  writeFileSync(join(sub, "hosts"), hostLines.join("\n") + "\n");
  writeFileSync(join(sub, "nsswitch.conf"), "passwd: files\ngroup: files\nhosts: files dns\n");
  writeFileSync(join(sub, "resolv.conf"), "nameserver 127.0.0.1\noptions timeout:1 attempts:1\n");
  const uid = process.getuid?.() ?? 0;
  const gid = process.getgid?.() ?? 0;
  const cfg = {
    dir, allow: o.allow, catchPorts: o.catchPorts ?? [], names,
    dns: tier === "netns+caps",
    ...(tls ? { tls } : {}),
    // The programs run as the invoking user, with no capability (caps tier).
    dropTo: tier === "netns+caps" ? { uid, gid } : null,
  };
  writeFileSync(join(sub, "config.json"), JSON.stringify(cfg));
  let resolv = "/etc/resolv.conf";
  try { resolv = realpathSync("/etc/resolv.conf"); } catch { /* a dangling link: handled in the box */ }
  let argv: string[];
  if (tier === "netns+caps") {
    if (!which("unshare") || !which("ip")) return "unshare or ip is not on PATH";
    writeFileSync(join(sub, "setup.sh"), [
      "set -eu",
      "ip link set lo up",
      `if ip route add local 0.0.0.0/0 dev lo 2>/dev/null; then echo yes > ${q(join(sub, "route"))}; fi`,
      `mount --bind ${q(join(sub, "hosts"))} /etc/hosts`,
      `mount --bind ${q(join(sub, "nsswitch.conf"))} /etc/nsswitch.conf`,
      `R=$(readlink -f /etc/resolv.conf 2>/dev/null || echo /etc/resolv.conf)`,
      `if [ -f "$R" ]; then mount --bind ${q(join(sub, "resolv.conf"))} "$R"; ` +
        `elif [ -d "$(dirname "$R")" ]; then mount -t tmpfs tmpfs "$(dirname "$R")" && cp ${q(join(sub, "resolv.conf"))} "$R"; fi`,
      `exec ${q(node)} ${q(HOST_SCRIPT)} ${q(join(sub, "config.json"))}`,
    ].join("\n") + "\n");
    argv = ["unshare", "--user", "--map-root-user", "--net", "--mount", "--pid", "--fork", "--mount-proc", "--kill-child=SIGKILL", "--", "/bin/sh", join(sub, "setup.sh")];
  } else {
    if (!which("bwrap")) return "bwrap is not on PATH";
    argv = [
      "bwrap", "--unshare-user", "--unshare-net", "--unshare-pid", "--die-with-parent",
      "--dev-bind", "/", "/", "--proc", "/proc",
      "--ro-bind", join(sub, "hosts"), "/etc/hosts",
      "--ro-bind", join(sub, "nsswitch.conf"), "/etc/nsswitch.conf",
      ...(existsSync(resolv) ? ["--ro-bind", join(sub, "resolv.conf"), resolv] : []),
      "--", node, HOST_SCRIPT, join(sub, "config.json"),
    ];
  }
  const log = join(sub, "host.log");
  const child = spawn(argv[0]!, argv.slice(1), { stdio: ["ignore", "pipe", "pipe"], detached: true });
  let out = "";
  child.stdout!.on("data", (d) => { out += String(d); appendFileSync(log, d); });
  child.stderr!.on("data", (d) => { out += String(d); appendFileSync(log, d); });
  let exit: number | null | undefined;
  child.on("exit", (c) => { exit = c; });
  child.on("error", (e) => { out += String(e); exit = -1; });
  const ready = join(dir, "ready.json");
  for (let i = 0; i < 200; i++) {
    if (existsSync(ready)) {
      const facts = JSON.parse(readFileSync(ready, "utf8")) as Record<string, unknown>;
      facts["route"] = existsSync(join(sub, "route"));
      rmSync(ready);
      return { child, facts };
    }
    if (exit !== undefined) return `the namespace did not start (exit ${exit}): ${out.trim().split("\n").slice(-2).join(" ").slice(0, 300) || "no output"}`;
    await sleep(50);
  }
  try { process.kill(-child.pid!, "SIGKILL"); } catch { /* gone */ }
  return `the box host did not get ready in 10 s: ${out.trim().slice(-300)}`;
}

function collect(onLine: (m: { t: string; d?: string; code?: number | null; signal?: string | null; error?: string }) => void): (d: Buffer) => void {
  let buf = "";
  return (d: Buffer) => {
    buf += d.toString("utf8");
    for (let i = buf.indexOf("\n"); i >= 0; i = buf.indexOf("\n")) {
      const line = buf.slice(0, i);
      buf = buf.slice(i + 1);
      try { onLine(JSON.parse(line)); } catch { /* a torn line */ }
    }
  };
}

function readRecords(dir: string): EgressRecord[] {
  try {
    return readFileSync(join(dir, "records.ndjson"), "utf8").split("\n").filter(Boolean).flatMap((l) => {
      try { return [JSON.parse(l) as EgressRecord]; } catch { return []; }
    });
  } catch { return []; }
}

function makeNsBox(tier: EgressTier, dir: string, host: ChildProcess, facts: Record<string, unknown>, outer: Server[], why: string): EgressBox {
  const procs = new Set<EgressProc>();
  const exec = (argv: string[], eo: EgressExecOptions): EgressProc => {
    const conn = connect(join(dir, "ctl.sock"));
    let stdout = "";
    let stderr = "";
    let isDone = false;
    let timer: NodeJS.Timeout | undefined;
    const done = new Promise<EgressExecResult>((resolve) => {
      let result: EgressExecResult = { code: null, signal: null, stdout: "", stderr: "" };
      conn.on("connect", () => {
        conn.write(JSON.stringify({ op: "exec", argv, env: eo.env, cwd: eo.cwd }) + "\n");
      });
      conn.on("data", collect((m) => {
        if (m.t === "o" || m.t === "e") {
          const s = Buffer.from(m.d ?? "", "base64").toString("utf8");
          if (m.t === "o") stdout += s; else stderr += s;
          if (eo.logFile) appendFileSync(eo.logFile, s);
        } else if (m.t === "x") {
          result = { code: m.code ?? null, signal: m.signal ?? null, stdout, stderr: m.error ? `${stderr}${m.error}\n` : stderr };
        }
      }));
      conn.on("error", (e) => { stderr += `egress box: ${e.message}\n`; });
      conn.on("close", () => {
        isDone = true;
        if (timer) clearTimeout(timer);
        resolve({ ...result, stdout, stderr: result.stderr || stderr });
      });
    });
    const p: EgressProc = {
      done,
      kill: (signal = "SIGTERM") => { if (!isDone) { try { conn.write(JSON.stringify({ op: "kill", signal }) + "\n"); } catch { /* gone */ } } },
      exited: () => isDone,
    };
    if (eo.timeoutMs) timer = setTimeout(() => { p.kill("SIGKILL"); }, eo.timeoutMs);
    procs.add(p);
    void done.then(() => procs.delete(p));
    return p;
  };
  return {
    tier, why, facts, dir,
    exec,
    run: (argv, eo) => exec(argv, eo).done,
    shimDir: (name, real) => {
      const d = join(dir, `shim-${name}`);
      mkdirSync(d, { recursive: true });
      const f = join(d, name);
      writeFileSync(f, `#!/bin/sh\nexec ${q(process.execPath)} ${q(SHIM_SCRIPT)} ${q(join(dir, "ctl.sock"))} ${q(real)} "$@"\n`, { mode: 0o755 });
      return d;
    },
    envFor: (env) => env,
    records: () => readRecords(dir),
    close: async () => {
      for (const p of procs) p.kill("SIGTERM");
      await Promise.race([Promise.all([...procs].map((p) => p.done)), sleep(8000)]);
      for (const p of procs) p.kill("SIGKILL");
      try { process.kill(-host.pid!, "SIGTERM"); } catch { /* gone */ }
      await Promise.race([new Promise((r) => host.once("exit", r)), sleep(3000)]);
      try { process.kill(-host.pid!, "SIGKILL"); } catch { /* gone */ }
      for (const s of outer) s.close();
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

async function startInproc(dir: string, o: EgressBoxOptions, outer: Server[], why: string): Promise<EgressBox> {
  const recordsFile = join(dir, "records.ndjson");
  // The refusing HTTPS_PROXY: a program that honours it shows its target here.
  const refuse: HttpServer = createHttpServer((req, res) => {
    appendFileSync(recordsFile, JSON.stringify({ t: Date.now(), via: "proxy-env", host: (req.headers.host ?? "").replace(/:\d+$/, ""), http: { method: req.method, path: req.url, host: req.headers.host ?? null } }) + "\n");
    res.writeHead(403); res.end();
  });
  refuse.on("connect", (req, sock: Socket) => {
    const [h, p] = String(req.url ?? "").split(":");
    appendFileSync(recordsFile, JSON.stringify({ t: Date.now(), via: "proxy-env", host: h, port: Number(p) || 443, sni: h }) + "\n");
    sock.end("HTTP/1.1 403 Forbidden\r\n\r\n");
  });
  await new Promise<void>((r) => refuse.listen(0, "127.0.0.1", () => r()));
  const proxyUrl = `http://127.0.0.1:${(refuse.address() as { port: number }).port}`;
  const noProxy = "127.0.0.1,localhost,::1";
  const envFor = (env: Record<string, string>): Record<string, string> => ({
    ...env,
    NODE_OPTIONS: `--require ${INPROC}${env["NODE_OPTIONS"] ? ` ${env["NODE_OPTIONS"]}` : ""}`,
    MANDU_EGRESS_RECORDS: recordsFile,
    HTTPS_PROXY: proxyUrl, HTTP_PROXY: proxyUrl, https_proxy: proxyUrl, http_proxy: proxyUrl,
    NO_PROXY: noProxy, no_proxy: noProxy,
  });
  const procs = new Set<{ child: ChildProcess; done: Promise<EgressExecResult> }>();
  const exec = (argv: string[], eo: EgressExecOptions): EgressProc => {
    const child = spawn(argv[0]!, argv.slice(1), { cwd: eo.cwd, env: envFor(eo.env), stdio: ["ignore", "pipe", "pipe"], detached: true });
    let stdout = "";
    let stderr = "";
    child.stdout!.on("data", (d) => { stdout += String(d); if (eo.logFile) appendFileSync(eo.logFile, d); });
    child.stderr!.on("data", (d) => { stderr += String(d); if (eo.logFile) appendFileSync(eo.logFile, d); });
    let isDone = false;
    const kill = (s: NodeJS.Signals = "SIGTERM"): void => { if (!isDone) { try { process.kill(-child.pid!, s); } catch { /* gone */ } } };
    const timer = eo.timeoutMs ? setTimeout(() => kill("SIGKILL"), eo.timeoutMs) : undefined;
    const done = new Promise<EgressExecResult>((resolve) => {
      child.on("error", (e) => { isDone = true; resolve({ code: 127, signal: null, stdout, stderr: `${stderr}${e.message}\n` }); });
      child.on("close", (code, signal) => { isDone = true; if (timer) clearTimeout(timer); resolve({ code, signal, stdout, stderr }); });
    });
    const entry = { child, done };
    procs.add(entry);
    void done.then(() => procs.delete(entry));
    return { done, kill, exited: () => isDone };
  };
  return {
    tier: "inproc", why, facts: null, dir,
    exec,
    run: (argv, eo) => exec(argv, eo).done,
    shimDir: (name, real) => {
      const d = join(dir, `shim-${name}`);
      mkdirSync(d, { recursive: true });
      const f = join(d, name);
      writeFileSync(f, [
        "#!/bin/sh",
        `export NODE_OPTIONS=${q(`--require ${INPROC}`)}" \${NODE_OPTIONS:-}"`,
        `export MANDU_EGRESS_RECORDS=${q(recordsFile)}`,
        `export HTTPS_PROXY=${q(proxyUrl)} HTTP_PROXY=${q(proxyUrl)} https_proxy=${q(proxyUrl)} http_proxy=${q(proxyUrl)} NO_PROXY=${q(noProxy)} no_proxy=${q(noProxy)}`,
        `exec ${q(real)} "$@"`,
      ].join("\n") + "\n", { mode: 0o755 });
      return d;
    },
    envFor,
    records: () => readRecords(dir),
    close: async () => {
      for (const p of procs) { try { process.kill(-p.child.pid!, "SIGTERM"); } catch { /* gone */ } }
      await Promise.race([Promise.all([...procs].map((p) => p.done)), sleep(8000)]);
      for (const p of procs) { try { process.kill(-p.child.pid!, "SIGKILL"); } catch { /* gone */ } }
      refuse.closeAllConnections();
      refuse.close();
      for (const s of outer) s.close();
      rmSync(dir, { recursive: true, force: true });
    },
  };
}
