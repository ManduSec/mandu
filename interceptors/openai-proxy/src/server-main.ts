/**
 * server-main — deployment entry point for the Track A OpenAI Responses proxy.
 *
 * Mandu Track A (interceptors/openai-proxy). Boots the OpenAiProxy wired to the
 * REAL arbiter over its Unix socket (MANDU_ARBITER_SOCK, set by the launcher) and
 * forwards to api.openai.com. The Codex CLI points at this proxy via a custom
 * model_provider base_url, e.g.
 *   -c 'model_providers.mandu={name="mandu",base_url="http://127.0.0.1:<port>/v1",wire_api="responses",env_key="OPENAI_API_KEY"}'
 *
 * This file is the ONLY place that imports the sibling arbiter package; it is
 * never loaded by the test suite (tests use a mock arbiter), so the suite has no
 * dependency on the arbiter daemon.
 *
 * Env:
 *   MANDU_ARBITER_SOCK   path to the arbiter Unix socket (required)
 *   MANDU_PROXY_PORT    listen port (default 8789)
 *   MANDU_PROXY_HOST    listen host (default 127.0.0.1)
 *   MANDU_UPSTREAM      upstream origin (default https://api.openai.com);
 *                         plain http:// only to a literal loopback address
 *                         (a stand-in model; proxy.ts upstreamTransport),
 *                         anything else is refused
 *   MANDU_UPSTREAM_IS_BASE_URL "1" when MANDU_UPSTREAM is the model_provider
 *                         base_url of a main model declared under policy.yaml
 *                         `models:` (plan 11 §7.2): the proxy's own /v1 maps
 *                         onto its path (proxy.ts upstreamRequestPath)
 *   MANDU_UPSTREAM_LOCAL "1" when that declared main model is `local: true`:
 *                         a request for a cloud-backed model is refused (400)
 *   MANDU_CHATGPT_UPSTREAM where a request made on a ChatGPT sign-in (one
 *                         carrying `chatgpt-account-id`) goes, a base URL
 *                         (default https://chatgpt.com/backend-api/codex;
 *                         agent-sign-in.md §2.4); unused under
 *                         MANDU_UPSTREAM_IS_BASE_URL, where such a request is
 *                         refused (403). The same transport rule applies
 *   MANDU_SESSION_KEY  optional session key threaded into arbiter calls
 *                         (also the key the reply filter reports its relay
 *                         under, reply-row-reservation.md §3.6)
 *   MANDU_ARBITER_HUMAN_SOCK optional path to the arbiter's human-plane
 *                         socket (arbiter-human-plane.md), for `symbolShape`
 *                         and `sessionRelay` only (reply-row-reservation.md
 *                         §11.7). Absent or unreachable: no reserve
 *                         expansion, nothing else changes
 *   MANDU_REPLY_RESERVE "0" turns reply row reservation's expansion off
 *                         (reply-row-reservation.md §3.2); anything else = on
 *   MANDU_REPLY_RESERVE_MAX the reserve row cap, an integer 2..200 (default 40)
 *   MANDU_HANDLING_MODE optional handling-prompt mode
 *   MANDU_SECRET_POSTURE optional: the launch's secret posture (confined |
 *                         read-blocked | gated), reported with every
 *                         handling-prompt request (secret-posture.ts); an
 *                         unknown value is logged and not reported.
 *   MANDU_VIEW_MAP      optional HumanView↔AgentView prefix map (P4), a JSON
 *                         array of {human, agent} root pairs set by the
 *                         launcher's fs-view service (same env var the
 *                         anthropic-proxy reads). Malformed value = fatal.
 *
 * Run: npm run serve   (or: tsx src/server-main.ts)
 */

import { upstreamTlsFromEnv } from "./upstream-tls.js";
import { secretPostureFromEnv } from "./secret-posture.js";
import { publishFile } from "./safe-file.js";
import { OpenAiProxy } from "./proxy.js";
import { ArbiterClientAdapter, type RealArbiterClient } from "./arbiter-client.js";
import { ViewMap, parseViewMapEnv } from "./view-map.js";
import { armLifeline } from "./lifeline.js";
import { parseReserveMax, reserveEnabled } from "./reserve-block.js";

// Canonical process title (runtime-instances.md §7): ps/pgrep-visible identity.
process.title = "mandu-openai-proxy";

async function main(): Promise<void> {
  const sock = process.env["MANDU_ARBITER_SOCK"];
  if (!sock) {
    console.error("[openai-proxy] MANDU_ARBITER_SOCK is required (path to the arbiter Unix socket)");
    process.exit(2);
  }

  // Import the real arbiter client lazily so this file is the sole coupling point.
  // The specifier is built at runtime so TypeScript does NOT statically resolve
  // the sibling arbiter package into this package's program (which would drag
  // arbiter/**.ts under our rootDir and break the standalone typecheck).
  // tsx/Node resolve `../../../arbiter/ipc/client.{ts,js}` at runtime; tests never
  // execute this path (they inject a mock arbiter).
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

  // fs prefix map (P4): fatal on a malformed value — never silently run
  // without the rewrite the launcher asked for.
  let viewMap: ViewMap | undefined;
  const rawViewMap = process.env["MANDU_VIEW_MAP"];
  try {
    const pairs = parseViewMapEnv(rawViewMap);
    viewMap = pairs.length > 0 ? new ViewMap(pairs) : undefined;
  } catch (err) {
    console.error(`[openai-proxy] ${(err as Error).message}`);
    process.exit(2);
  }
  if (viewMap && !viewMap.active) {
    console.error(
      `[openai-proxy] MANDU_VIEW_MAP has no usable root pair (degenerate/nested roots?): ${rawViewMap}`,
    );
    process.exit(2);
  }

  // The arbiter's human plane (arbiter-human-plane.md), for `symbolShape`
  // and `sessionRelay` (reply-row-reservation.md §3.3, §11.5, §11.7: the
  // data socket refuses both) and for `execGate`, `recordCallCommand` and
  // `callTaint` (plan 13
  // §3 D9: only from here does the arbiter bind a call to the agent's
  // shell). Absent or unreachable → no reserve expansion, and every shell
  // result is masked while the session holds a raw read (fail-closed).
  let humanClient: RealArbiterClient | undefined;
  const humanSock = process.env["MANDU_ARBITER_HUMAN_SOCK"];
  if (humanSock) {
    try {
      const c = (arbiterMod.ArbiterClient.humanPlane?.(humanSock, process.env["MANDU_ARBITER_SOCK"]) ?? new arbiterMod.ArbiterClient(humanSock));
      await c.connect();
      humanClient = c;
    } catch (err) {
      console.error(`[openai-proxy] arbiter human plane unreachable at ${humanSock} (${(err as Error).message}) — reply row reservation off, and no shell call is bound to its shell (results masked while the session holds a raw read)`);
    }
  } else {
    console.error("[openai-proxy] no MANDU_ARBITER_HUMAN_SOCK — reply row reservation off, and no shell call is bound to its shell (results masked while the session holds a raw read)");
  }
  const arbiter = new ArbiterClientAdapter(client, humanClient);
  const proxy = new OpenAiProxy({
    arbiter,
    upstreamOrigin: process.env["MANDU_UPSTREAM"] ?? "https://api.openai.com",
    // Plan 11 §7.2: a declared main model (the launcher sets both).
    upstreamIsBaseUrl: process.env["MANDU_UPSTREAM_IS_BASE_URL"] === "1",
    // A ChatGPT sign-in's upstream (agent-sign-in.md §2.4): the fixed
    // ChatGPT backend, or a stand-in a test names (like MANDU_UPSTREAM).
    ...(process.env["MANDU_CHATGPT_UPSTREAM"] ? { chatgptOrigin: process.env["MANDU_CHATGPT_UPSTREAM"] } : {}),
    upstreamLocal: process.env["MANDU_UPSTREAM_LOCAL"] === "1",
    // Plan 12 D3: the declared main model's tls checks (fail-closed: a
    // setting that cannot be used stops the proxy from starting).
    ...upstreamTlsFromEnv(process.env["MANDU_UPSTREAM_TLS"]),
    sessionKey: process.env["MANDU_SESSION_KEY"],
    handlingMode: process.env["MANDU_HANDLING_MODE"],
    // The launch's secret posture (the launcher sets it; secret-posture.ts).
    secretPosture: secretPostureFromEnv(process.env["MANDU_SECRET_POSTURE"], (m) => console.error(`[openai-proxy] ${m}`)),
    viewMap,
    // Reply row reservation (reply-row-reservation.md §3.2, §11.7): the kill
    // switch and the row cap. The request-side collapse and strip run regardless.
    replyReserve: {
      enabled: reserveEnabled(process.env["MANDU_REPLY_RESERVE"]),
      maxRows: parseReserveMax(process.env["MANDU_REPLY_RESERVE_MAX"]),
    },
    // Identity for the launcher's start-or-reuse safety check. Reuse key is
    // (arbiterSock, viewMap): the raw env pairs so the launcher compares
    // string-for-string against what it set.
    identity: {
      service: "openai-proxy",
      sessionKey: process.env["MANDU_SESSION_KEY"],
      arbiterSock: sock,
      viewMap: parseViewMapEnv(rawViewMap),
    },
  });

  const port = Number(process.env["MANDU_PROXY_PORT"] ?? 8789);
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
    `[openai-proxy] ready — point Codex's model_provider base_url at http://${host}:${bound}/v1 ; arbiter=${sock}`,
  );
  if (viewMap) {
    for (const p of viewMap.roots()) {
      console.error(`[openai-proxy] view-map: ${p.human} ↔ ${p.agent}`);
    }
  }

  const shutdown = async (): Promise<void> => {
    await proxy.close();
    client.close();
    humanClient?.close();
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
  // Lifeline (lifeline.ts): the launcher spawns this proxy per-session with
  // MANDU_LIFELINE=stdin — stdin EOF means the launcher died (even by
  // SIGKILL), so shut down instead of orphaning + squatting the port.
  if (armLifeline(() => void shutdown())) {
    console.error("[openai-proxy] lifeline armed — exits when the launcher dies");
  }
}

main().catch((err) => {
  console.error(`[openai-proxy] fatal: ${(err as Error).message}`);
  process.exit(1);
});
