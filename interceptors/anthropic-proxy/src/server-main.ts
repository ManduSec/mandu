/**
 * server-main — deployment entry point for the Track A model proxy.
 *
 * Mandu Track A (interceptors/anthropic-proxy). Boots the AnthropicProxy wired to the
 * REAL arbiter over its Unix socket (MANDU_ARBITER_SOCK, set by the launcher —
 * launcher/mandu-run.sh) and forwards to api.anthropic.com. The agent points
 * at this proxy via ANTHROPIC_BASE_URL=http://127.0.0.1:<port>.
 *
 * This file is the ONLY place that imports the sibling arbiter package; it is
 * never loaded by the test suite (tests use a mock arbiter), so the suite has no
 * dependency on the arbiter daemon or on the two new ops actually landing.
 *
 * Env:
 *   MANDU_ARBITER_SOCK   path to the arbiter Unix socket (required)
 *   MANDU_PROXY_PORT    listen port (default 8788)
 *   MANDU_PROXY_HOST    listen host (default 127.0.0.1)
 *   MANDU_UPSTREAM      upstream origin (default https://api.anthropic.com),
 *                         optionally with a base path that prefixes every
 *                         request (a declared model served under a prefix,
 *                         set by the launcher; plan 11 phase 3);
 *                         plain http:// only to a literal loopback address
 *                         (the offline demo's stand-in model, a model on this
 *                         machine; proxy.ts upstreamTransport), anything else
 *                         is refused
 *   MANDU_REPLY_RESERVE "0" turns reply row reservation's expansion off
 *                         (reply-row-reservation.md §3.2); anything else = on
 *   MANDU_REPLY_RESERVE_MAX the reserve row cap, an integer 2..200 (default 40)
 *   MANDU_UPSTREAM_LOCAL "1" when MANDU_UPSTREAM is a main model declared
 *                         `local: true` in policy.yaml `models:` (set by the
 *                         launcher; plan 11 §8 item 3): a request naming a
 *                         cloud-backed model (Ollama's `:cloud` / `-cloud`
 *                         tags, src/cloud-model.ts) is refused with a 400 and
 *                         never sent. Any other value, or unset = off.
 *   MANDU_OPENAI_UPSTREAMS optional JSON object, provider id → base URL: the
 *                         OpenAI-family providers of an OpenClaw / OpenCode
 *                         session routed through this proxy under
 *                         /_mandu/openai/<id> (openai-wire.ts; set by the
 *                         launcher). Malformed value = fatal.
 *   MANDU_OPENAI_TEXT_CALLS optional JSON array of those provider ids whose
 *                         agent runs a tool call the model writes in its
 *                         text (Goose's ollama provider): a response whose
 *                         text carries one is ended (openai-sse.ts).
 *                         Malformed value = fatal.
 *   MANDU_SESSION_KEY   optional session key threaded into arbiter calls
 *   MANDU_INBOUND_SPEC  optional agent trust-spec id for THIS session
 *                         (agent-e2e-harness.md §7.1): bound to
 *                         MANDU_SESSION_KEY on the arbiter at boot so one
 *                         arbiter can serve mixed agents. On the ARBITER's own
 *                         process the same var sets the process-global spec.
 *   MANDU_HANDLING_MODE optional handling-prompt mode
 *   MANDU_SECRET_POSTURE optional: the launch's secret posture (confined |
 *                         read-blocked | gated), reported with every
 *                         handling-prompt request (secret-posture.ts). An
 *                         unknown value is logged and not reported (utility
 *                         guidance only, never a gate).
 *   MANDU_VIEW_MAP      optional HumanView↔AgentView prefix map (P2), a JSON
 *                         array of {human, agent} root pairs set by the
 *                         launcher's fs-view service. Malformed value = fatal
 *                         (a silently-dropped map would run without the
 *                         rewrite while the operator believes it is on).
 *   MANDU_AGENT_CWD     optional HumanView directory the agent started in, set
 *                         by the launcher only when the agent's argv does not
 *                         move it: an agent whose gate surface resolves
 *                         relative paths against its launch directory
 *                         (OpenCode) has them placed there by the
 *                         sensitive-path gate and the derived label
 *                         (fs-gate.ts resolveRelative). Not absolute = fatal.
 *
 * Run: npm run serve   (or: tsx src/server-main.ts)
 */

import { upstreamTlsFromEnv } from "./upstream-tls.js";
import { secretPostureFromEnv } from "./secret-posture.js";
import { publishFile } from "./safe-file.js";
import { AnthropicProxy } from "./proxy.js";
import { ArbiterClientAdapter, type RealArbiterClient } from "./arbiter-client.js";
import { ViewMap, parseViewMapEnv } from "./view-map.js";
import { parseOpenAiTextCallsEnv, parseOpenAiUpstreamsEnv } from "./openai-wire.js";
import { armLifeline } from "./lifeline.js";
import { parseReserveMax, reserveEnabled } from "./reserve-block.js";

// Canonical process title (runtime-instances.md §7): ps/pgrep-visible identity.
process.title = "mandu-anthropic-proxy";

async function main(): Promise<void> {
  const sock = process.env["MANDU_ARBITER_SOCK"];
  if (!sock) {
    console.error("[anthropic-proxy] MANDU_ARBITER_SOCK is required (path to the arbiter Unix socket)");
    process.exit(2);
  }

  // Import the real arbiter client lazily so this file is the sole coupling
  // point. The specifier is built at runtime so TypeScript does NOT statically
  // resolve the sibling arbiter package into this package's program (which would
  // drag arbiter/**.ts under our rootDir and break the standalone typecheck).
  // tsx/Node resolve `../../../arbiter/ipc/client.{ts,js}` at runtime; tests
  // never execute this path (they inject a mock arbiter).
  // A BUNDLED build (packaging.md §5) sets MANDU_ARBITER_CLIENT_MODULE to the
  // co-located dist/arbiter-client.mjs — import.meta.url has moved to
  // launcher/dist/, so the relative fallback would resolve wrong. Unset in
  // dev/tsx and tests → the from-source relative path below.
  const arbiterClientSpecifier =
    process.env["MANDU_ARBITER_CLIENT_MODULE"] ?? ["..", "..", "..", "arbiter", "ipc", "client.js"].join("/");
  const arbiterMod = (await import(arbiterClientSpecifier)) as {
    // `humanPlane` (arbiter-human-plane.md §5.1): a human-plane client that
    // re-learns the human socket from the data socket after an arbiter
    // restart. Optional: an older client module has none.
    ArbiterClient: (new (sock: string) => RealArbiterClient) & {
      humanPlane?: (humanSock: string, dataSock?: string | null) => RealArbiterClient;
    };
  };
  const client: RealArbiterClient = new arbiterMod.ArbiterClient(sock);
  await client.connect();

  // Session-keyed trust spec (agent-e2e-harness.md §7.1): a launcher wrapping a
  // NON-Claude agent sets MANDU_INBOUND_SPEC on this proxy's env; we bind our
  // session to that spec at boot, BEFORE any request can classify. Requires
  // MANDU_SESSION_KEY — that is the identity every classify call threads
  // (rewrite-request.ts), so without it there is nothing to bind and the
  // arbiter's process-global spec applies (fail-closed for foreign tool names).
  // NOTE the same env var on the ARBITER's own process sets the process-global
  // spec (arbiter/ipc/server-main.ts) — one name, one meaning ("this is the
  // agent's spec"), scoped by which process it is set on.
  const inboundSpec = process.env["MANDU_INBOUND_SPEC"];
  const bootSessionKey = process.env["MANDU_SESSION_KEY"];
  if (inboundSpec) {
    if (!bootSessionKey) {
      console.error(
        "[anthropic-proxy] MANDU_INBOUND_SPEC set but MANDU_SESSION_KEY absent — cannot bind a session spec; the arbiter's global spec applies",
      );
    } else if (!client.setSessionSpec) {
      console.error(
        "[anthropic-proxy] MANDU_INBOUND_SPEC set but the arbiter build predates setSessionSpec — the arbiter's global spec applies",
      );
    } else {
      const r = await client.setSessionSpec({
        sessionKey: bootSessionKey,
        spec: inboundSpec,
        requestedBy: "anthropic-proxy boot (MANDU_INBOUND_SPEC)",
      });
      console.error(
        `[anthropic-proxy] session spec: ${bootSessionKey} → ${r.bound}${r.applied ? "" : ` (WARNING: ${r.reason})`}`,
      );
    }
  }

  // fs prefix map (P2): fatal on a malformed value — never silently run
  // without the rewrite the launcher asked for.
  let viewMap: ViewMap | undefined;
  const rawViewMap = process.env["MANDU_VIEW_MAP"];
  try {
    const pairs = parseViewMapEnv(rawViewMap);
    viewMap = pairs.length > 0 ? new ViewMap(pairs) : undefined;
  } catch (err) {
    console.error(`[anthropic-proxy] ${(err as Error).message}`);
    process.exit(2);
  }
  let openaiUpstreams: Record<string, string>;
  let openaiTextCalls: string[];
  try {
    openaiUpstreams = parseOpenAiUpstreamsEnv(process.env["MANDU_OPENAI_UPSTREAMS"]);
    openaiTextCalls = parseOpenAiTextCallsEnv(process.env["MANDU_OPENAI_TEXT_CALLS"]);
  } catch (err) {
    console.error(`[anthropic-proxy] ${(err as Error).message}`);
    process.exit(2);
  }
  if (viewMap && !viewMap.active) {
    console.error(
      `[anthropic-proxy] MANDU_VIEW_MAP has no usable root pair (degenerate/nested roots?): ${rawViewMap}`,
    );
    process.exit(2);
  }
  // The agent's start directory (relative paths, fs-gate.ts resolveRelative):
  // fatal when set but not absolute, like the view map, so a launch never
  // runs believing relative paths are placed when they are not.
  const agentCwd = process.env["MANDU_AGENT_CWD"] || undefined;
  if (agentCwd !== undefined && !agentCwd.startsWith("/")) {
    console.error(`[anthropic-proxy] MANDU_AGENT_CWD must be an absolute path, got '${agentCwd}'`);
    process.exit(2);
  }

  // The arbiter's human plane (arbiter-human-plane.md), for `symbolShape`
  // and `sessionRelay` (reply-row-reservation.md §3.3, §11.5: the data
  // socket refuses both) and for `execGate`, `recordCallCommand` and
  // `callTaint` (plan 13 §3 D9 and its follow-up:
  // only from here does the arbiter bind a call to the agent's shell), and
  // for the network and path gates (only an ask from here spends a human's
  // Allow once, arbiter-human-plane.md §10.3). Absent or unreachable → no reserve expansion, and every Bash result is
  // masked while the session holds a raw read (fail-closed).
  let humanClient: RealArbiterClient | undefined;
  const humanSock = process.env["MANDU_ARBITER_HUMAN_SOCK"];
  if (humanSock) {
    try {
      const c = (arbiterMod.ArbiterClient.humanPlane?.(humanSock, process.env["MANDU_ARBITER_SOCK"]) ?? new arbiterMod.ArbiterClient(humanSock));
      await c.connect();
      humanClient = c;
    } catch (err) {
      console.error(`[anthropic-proxy] arbiter human plane unreachable at ${humanSock} (${(err as Error).message}) — reply row reservation off, and no Bash call is bound to its shell (results masked while the session holds a raw read)`);
    }
  }
  const arbiter = new ArbiterClientAdapter(client, humanClient);
  const proxy = new AnthropicProxy({
    arbiter,
    upstreamOrigin: process.env["MANDU_UPSTREAM"] ?? "https://api.anthropic.com",
    sessionKey: process.env["MANDU_SESSION_KEY"],
    handlingMode: process.env["MANDU_HANDLING_MODE"],
    // The launch's secret posture (the launcher sets it; secret-posture.ts):
    // a `read-blocked` session's handling prompt says credential files
    // cannot be read. Unknown values are logged and not reported.
    secretPosture: secretPostureFromEnv(process.env["MANDU_SECRET_POSTURE"], (m) => console.error(`[anthropic-proxy] ${m}`)),
    viewMap,
    ...(agentCwd ? { agentCwd } : {}),
    // Set by the launcher when the net-proxy TLS-inspects (`--net-proxy-mitm`):
    // an allowed symbol in a WebFetch URL is then released THERE (net-gate.ts).
    netTlsInspected: process.env["MANDU_NET_TLS_INSPECTED"] === "1",
    // Set by the launcher when the upstream is a declared local main model:
    // a cloud-backed model name is refused there (plan 11 §8 item 3).
    upstreamLocal: process.env["MANDU_UPSTREAM_LOCAL"] === "1",
    // Plan 12 D3: the declared main model's tls checks (fail-closed: a
    // setting that cannot be used stops the proxy from starting).
    ...upstreamTlsFromEnv(process.env["MANDU_UPSTREAM_TLS"]),
    // The session's routed OpenAI-family providers (launcher agent-config.ts).
    openaiUpstreams,
    // The routes whose agent runs a tool call written in the model's text.
    openaiTextCalls,
    // Reply row reservation (reply-row-reservation.md §3.2): the kill switch
    // and the row cap. The request-side collapse and strip run regardless.
    replyReserve: {
      enabled: reserveEnabled(process.env["MANDU_REPLY_RESERVE"]),
      maxRows: parseReserveMax(process.env["MANDU_REPLY_RESERVE_MAX"]),
    },
    // Identity for the launcher's start-or-reuse safety check. The reuse key is
    // (arbiterSock, viewMap): the raw env pairs (NOT the normalized ViewMap
    // roots) so the launcher compares string-for-string against what it set.
    identity: {
      service: "anthropic-proxy",
      sessionKey: process.env["MANDU_SESSION_KEY"],
      arbiterSock: sock,
      viewMap: parseViewMapEnv(rawViewMap),
      ...(agentCwd ? { agentCwd } : {}),
    },
  });

  const port = Number(process.env["MANDU_PROXY_PORT"] ?? 8788);
  const host = process.env["MANDU_PROXY_HOST"] ?? "127.0.0.1";
  const bound = await proxy.listen(port, host);
  // Ephemeral-port discovery: with MANDU_PROXY_PORT=0 the kernel picks the
  // port; publish the bound one for the launcher (context-proxy.ts) via an
  // atomic tmp+rename so its waitForFile never reads a half-written value.
  const portFile = process.env["MANDU_PORT_FILE"];
  // Never through a link planted in the scope dir (runtime-instances.md §2,
  // "planted paths"; safe-file.ts): a fresh, exclusive, no-follow temp name in
  // a real directory of this user's, renamed into place. A refused directory
  // stops the proxy (the launcher, waiting for the port, fails closed).
  if (portFile) publishFile(portFile, String(bound));
  console.error(
    `[anthropic-proxy] ready — set ANTHROPIC_BASE_URL=http://${host}:${bound} ; arbiter=${sock}`,
  );
  for (const [id, url] of Object.entries(openaiUpstreams)) {
    console.error(`[anthropic-proxy] routed provider: ${id} → ${url} (at /_mandu/openai/${id})`);
  }
  if (viewMap) {
    for (const p of viewMap.roots()) {
      console.error(`[anthropic-proxy] view-map: ${p.human} ↔ ${p.agent}`);
    }
  }

  const shutdown = async (): Promise<void> => {
    await proxy.close();
    client.close();
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
  // Lifeline (lifeline.ts): the launcher spawns this proxy per-session with
  // MANDU_LIFELINE=stdin — stdin EOF means the launcher died (even by
  // SIGKILL), so shut down instead of orphaning + squatting the port.
  if (armLifeline(() => void shutdown())) {
    console.error("[anthropic-proxy] lifeline armed — exits when the launcher dies");
  }
}

main().catch((err) => {
  console.error(`[anthropic-proxy] fatal: ${(err as Error).message}`);
  process.exit(1);
});
