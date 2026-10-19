/**
 * server-main — deployment entry point for the egress data-usage gate.
 *
 * Mandu (interceptors/net-proxy). Boots the NetProxy wired to the REAL
 * arbiter over its Unix socket (MANDU_ARBITER_SOCK, set by the launcher). The
 * agent points at this FORWARD proxy via HTTP_PROXY / HTTPS_PROXY =
 * http://127.0.0.1:<port>.
 *
 * This file is the ONLY place that imports the sibling arbiter package; it is
 * never loaded by the test suite (tests use a mock arbiter), so the suite has no
 * dependency on the arbiter daemon.
 *
 * Env:
 *   MANDU_ARBITER_SOCK        path to the arbiter Unix socket (required)
 *   MANDU_ARBITER_HUMAN_SOCK  the arbiter's HUMAN-PLANE socket: the shallow
 *                              `resolve` of an ALLOWED symbol goes there, and
 *                              only there (docs/design/architecture/arbiter-human-plane.md).
 *                              Unset/unreachable → every allowed symbol is
 *                              WITHHELD (the request is blocked, fail-closed);
 *                              the data socket is never asked instead.
 *   MANDU_NET_PROXY_PORT     listen port (default 8790; 0 = kernel-assigned,
 *                              published via MANDU_PORT_FILE)
 *   MANDU_NET_PROXY_HOST     listen host (default 127.0.0.1)
 *   MANDU_PORT_FILE          when set, the BOUND port is published here via
 *                              atomic tmp+rename (runtime-instances.md §8 —
 *                              same rendezvous as the model proxies, so
 *                              concurrent stacks need no fixed ports)
 *   MANDU_MODEL_HOSTS        comma-separated extra model-API hosts to exclude
 *   MANDU_NET_PROXY_MODEL_SERVICES  comma-separated model services a program
 *                              calls itself: placeholders outside the auth
 *                              header leave as they are (egress.ts modelService)
 *   MANDU_NET_PROXY_MODEL_NOTE  `browser` = a Chat Completions call to a model
 *                              service gets Mandu's handling note (model-note.ts;
 *                              the launcher's, when it runs a DevTools relay)
 *   MANDU_SESSION_KEY        optional session id threaded into emitted events
 *   MANDU_NET_PROXY_MITM     1 = OPT-IN MITM (terminate TLS to gate HTTPS request
 *                              bodies). DEFAULT OFF — without it HTTPS is blind-
 *                              tunneled (today's behavior, unchanged).
 *   MANDU_NET_PROXY_MITM_CA_DIR dir for the session-local CA + per-host leaf cache
 *                              (default: a temp dir under the system tmp). The CA
 *                              cert path is logged so the launcher/user can trust
 *                              it (NODE_EXTRA_CA_CERTS / CURL_CA_BUNDLE).
 *   MANDU_NET_PROXY_MITM_INSECURE_UPSTREAM  1 = TEST ONLY: skip UPSTREAM TLS
 *                              verification when re-originating. DEFAULT OFF (verify
 *                              against the system CA store). NEVER use in production.
 *   MANDU_NET_PROXY_MOCK_SITES  path to a mock-sites YAML (url→canned response).
 *                              When set, matching outbound requests are served the
 *                              canned response instead of being forwarded (still
 *                              symbolized) — for deterministic agent loops / demos
 *                              offline. Absent → normal forwarding only.
 *   MANDU_NET_PROXY_DENY_HOSTS  comma list of the agent's upload hosts (`host`,
 *                              `host:port`, `.suffix`; launcher upload-deny.ts):
 *                              a CONNECT or plain-HTTP request to one is refused
 *                              403 before any dial, in every mode (deny-hosts.ts).
 *   MANDU_NET_PROXY_SESSION_LOGINS  JSON: the AI agents' login files this
 *                              session leaves raw (session-logins.ts; launcher
 *                              agent-login.ts `sessionLogins`),
 *                              sent with each tripwire scan. Absent or
 *                              malformed: nothing is exempt.
 *   MANDU_NET_PROXY_MODEL_HOST_DENY  1 = the model-host deny (model-host-paths.ts):
 *                              a request to a model vendor's host passes only
 *                              when its path is on that host's list (TLS-
 *                              inspected and plain legs); with TLS inspection
 *                              off such a CONNECT is refused whole. Set by the
 *                              launcher whenever the confidentiality axis is on.
 *   MANDU_EGRESS_HOLD_MS     how long (ms) a request whose only obstacle is an
 *                              unanswered card on the Approvals page waits for
 *                              the human's answer (confidentiality.md §4, "A
 *                              held request"; egress.ts `EgressHold`). Absent,
 *                              0 or invalid: no hold, refused at once. Capped
 *                              at 300 000.
 *
 * Run: npm run serve   (or: tsx src/server-main.ts)
 */

import { publishFile } from "./safe-file.js";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { NetProxy } from "./proxy.js";
import {
  ArbiterClientAdapter, HUMAN_SOCK_ENV, humanSockFromEnv,
  type HumanResolveClient, type RealArbiterClient,
} from "./arbiter-client.js";
import { defaultCaDir, opensslAvailable } from "./ca.js";
import { MockSites } from "./mock-sites.js";
import { armLifeline } from "./lifeline.js";
import type { MitmConfig } from "./mitm.js";
import { ALLOW_METADATA_ENV } from "./blocked-destinations.js";
import { DENY_HOSTS_ENV, parseDenyHosts } from "./deny-hosts.js";
import { SESSION_LOGINS_ENV, parseSessionLogins } from "./session-logins.js";
import { egressHoldMs } from "./egress.js";
import { MODEL_HOST_DENY_ENV } from "./model-host-paths.js";
import { MODEL_NOTE_ENV, modelNoteFromEnv } from "./model-note.js";

// Canonical process title (runtime-instances.md §7): ps/pgrep-visible identity.
process.title = "mandu-net-proxy";

async function main(): Promise<void> {
  const sock = process.env["MANDU_ARBITER_SOCK"];
  if (!sock) {
    console.error("[net-proxy] MANDU_ARBITER_SOCK is required (path to the arbiter Unix socket)");
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

  // The human plane (arbiter-human-plane.md): a second client, dialed lazily on
  // the first symbol, for the egress decision (only an ask from here spends a
  // human's Allow once, §10.3) and the shallow resolve.
  const humanSock = humanSockFromEnv(process.env);
  const humanClient: HumanResolveClient | null = humanSock
    ? (arbiterMod.ArbiterClient.humanPlane?.(humanSock, process.env["MANDU_ARBITER_SOCK"]) ?? new arbiterMod.ArbiterClient(humanSock))
    : null;
  if (!humanClient) {
    console.error(
      `[net-proxy] WARNING: ${HUMAN_SOCK_ENV} is not set — an ALLOWED symbol cannot be resolved, ` +
        "so every request carrying one is blocked (fail-closed; the data socket is never asked instead)",
    );
  }
  const arbiter = new ArbiterClientAdapter(client, humanClient);
  const modelHosts = (process.env["MANDU_MODEL_HOSTS"] ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s !== "");
  // Model services a program calls itself (egress.ts GateInput.modelService):
  // a placeholder in a request to one leaves as it is (agent-sign-in.md §3.12).
  const modelServices = (process.env["MANDU_NET_PROXY_MODEL_SERVICES"] ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s !== "");
  if (modelServices.length) console.error(`[net-proxy] model services (placeholders sent as they are, the key in the auth header put back): ${modelServices.join(", ")}`);
  // A browser agent's own model calls get Mandu's handling note (model-note.ts).
  const modelNote = modelNoteFromEnv(process.env[MODEL_NOTE_ENV]);
  if (modelNote && modelServices.length) console.error(`[net-proxy] a Chat Completions call to a model service gets Mandu's handling note (${modelNote} agent)`);

  // ── OPT-IN MITM (DEFAULT OFF). When MANDU_NET_PROXY_MITM=1 we terminate TLS for
  // non-model HTTPS hosts so the egress gate can inspect decrypted request bodies.
  // GRACEFUL DEGRADE: if openssl is missing we WARN and fall back to non-MITM
  // (blind tunnel) rather than failing — the launcher does the same upstream.
  let mitm: MitmConfig | undefined;
  if (process.env["MANDU_NET_PROXY_MITM"] === "1") {
    if (!opensslAvailable()) {
      console.error(
        "[net-proxy] WARNING: MANDU_NET_PROXY_MITM=1 but openssl is not on PATH — " +
          "FALLBACK: HTTPS is blind-tunneled (request bodies are NOT gated).",
      );
    } else {
      const caDir =
        process.env["MANDU_NET_PROXY_MITM_CA_DIR"] ?? defaultCaDir(tmpdir());
      const insecureUpstream = process.env["MANDU_NET_PROXY_MITM_INSECURE_UPSTREAM"] === "1";
      mitm = { caDir, insecureUpstream };
      if (insecureUpstream) {
        console.error(
          "[net-proxy] *** WARNING: MANDU_NET_PROXY_MITM_INSECURE_UPSTREAM=1 — UPSTREAM TLS " +
            "verification is DISABLED. TEST ONLY; never use against real destinations. ***",
        );
      }
    }
  }

  // OPTIONAL offline web mock. A bad/missing config is non-fatal: warn and run
  // WITHOUT the mock (the proxy still forwards normally) rather than refusing to
  // start over test infrastructure.
  let mockSites: MockSites | undefined;
  const mockPath = process.env["MANDU_NET_PROXY_MOCK_SITES"];
  if (mockPath) {
    try {
      mockSites = MockSites.fromFile(mockPath);
      console.error(`[net-proxy] web mock LIVE — ${mockSites.size} site(s)${mockSites.routeCount ? ` and ${mockSites.routeCount} host route(s) to loopback` : ""} from ${mockPath}`);
    } catch (err) {
      console.error(
        `[net-proxy] WARNING: could not load mock sites from ${mockPath} (${(err as Error).message}) — running WITHOUT the web mock.`,
      );
    }
  }

  // Identity for the launcher's start-or-reuse safety check (services/net-proxy.ts):
  // the reuse key is the arbiter socket; sessionKey is informational.
  const identity = {
    service: "net-proxy" as const,
    sessionKey: process.env["MANDU_SESSION_KEY"],
    arbiterSock: sock,
  };

  // The always-denied destinations (cloud metadata, link-local) stay refused
  // unless the operator opted out for this launch (blocked-destinations.ts).
  // This machine (loopback, the unspecified address, `localhost`, this
  // machine's own interface addresses) is refused with no opt-out: the
  // constructor's `allowThisMachine` is for in-process tests and is never
  // set here; only a mock-sites host route's own dial skips it.
  const allowMetadata = process.env[ALLOW_METADATA_ENV] === "1";
  if (allowMetadata) {
    console.error(`[net-proxy] WARNING: ${ALLOW_METADATA_ENV}=1: cloud metadata and link-local destinations are NOT refused.`);
  }
  // The agent's upload hosts (launcher upload-deny.ts), refused before any dial.
  const denyHosts = parseDenyHosts(process.env[DENY_HOSTS_ENV]);
  if (denyHosts.length > 0) {
    console.error(`[net-proxy] ${denyHosts.length} upload host(s) of this agent denied (${DENY_HOSTS_ENV})`);
  }
  // The logins this session leaves raw (session-logins.ts): a malformed
  // value exempts nothing (the tripwire stays as strict as before) and says so.
  const parsedLogins = parseSessionLogins(process.env[SESSION_LOGINS_ENV]);
  if (parsedLogins.error !== undefined) {
    console.error(`[net-proxy] WARNING: ${SESSION_LOGINS_ENV} ignored (${parsedLogins.error}): no login is exempt from the tripwire`);
  }
  const sessionLogins = parsedLogins.logins ?? undefined;
  // A held request (confidentiality.md §4): off unless set.
  const holdMs = egressHoldMs(process.env["MANDU_EGRESS_HOLD_MS"]);
  // The model-host deny (model-host-paths.ts): on only when the launcher says.
  const modelHostDeny = process.env[MODEL_HOST_DENY_ENV] === "1";
  if (modelHostDeny) console.error(`[net-proxy] model hosts take only their listed account and sign-in paths (${MODEL_HOST_DENY_ENV})`);
  if (holdMs > 0) console.error(`[net-proxy] a request waiting on an unanswered card is held up to ${Math.round(holdMs / 1000)} s for the answer (MANDU_EGRESS_HOLD_MS)`);

  let proxy: NetProxy;
  try {
    proxy = new NetProxy({
      arbiter,
      modelHosts,
      modelServices,
      modelNote,
      sessionId: process.env["MANDU_SESSION_KEY"],
      tenant: process.env["MANDU_TENANT"],
      mitm,
      mockSites,
      identity,
      allowMetadata,
      denyHosts,
      ...(sessionLogins ? { sessionLogins } : {}),
      egressHoldMs: holdMs,
      modelHostDeny,
    });
  } catch (err) {
    // MITM CA setup failed (e.g. openssl threw / unwritable CA dir) → degrade to
    // non-MITM rather than refusing to start (fail-closed for the GATE; the blind
    // tunnel still applies the destination/symbol-as-destination checks).
    console.error(
      `[net-proxy] WARNING: MITM CA setup failed (${(err as Error).message}) — FALLBACK: non-MITM blind tunnel.`,
    );
    proxy = new NetProxy({
      arbiter,
      modelHosts,
      modelServices,
      modelNote,
      sessionId: process.env["MANDU_SESSION_KEY"],
      tenant: process.env["MANDU_TENANT"],
      mockSites,
      identity,
      allowMetadata,
      denyHosts,
      ...(sessionLogins ? { sessionLogins } : {}),
      egressHoldMs: holdMs,
      modelHostDeny,
    });
    mitm = undefined;
  }

  const port = Number(process.env["MANDU_NET_PROXY_PORT"] ?? 8790);
  const host = process.env["MANDU_NET_PROXY_HOST"] ?? "127.0.0.1";
  const bound = await proxy.listen(port, host);
  // Ephemeral-port discovery (mirror of anthropic-proxy/server-main): with
  // PORT=0 the kernel picks; publish the bound port atomically so a launcher's
  // waitForFile never reads a half-written value.
  const portFile = process.env["MANDU_PORT_FILE"];
  // Never through a link planted in the scope dir (runtime-instances.md §2,
  // "planted paths"; safe-file.ts): a fresh, exclusive, no-follow temp name in
  // a real directory of this user's, renamed into place. A refused directory
  // stops the proxy (the launcher, waiting for the port, fails closed).
  if (portFile) publishFile(portFile, String(bound));
  console.error(
    `[net-proxy] ready — set HTTP_PROXY=HTTPS_PROXY=http://${host}:${bound} ; arbiter=${sock}` +
      (modelHosts.length ? ` ; extra model hosts: ${modelHosts.join(", ")}` : ""),
  );
  if (mitm && proxy.mitmCaCertPath) {
    console.error(
      `[net-proxy] MITM LIVE — HTTPS request bodies are gated (TLS terminated). ` +
        `Trust the session CA: NODE_EXTRA_CA_CERTS=${proxy.mitmCaCertPath} CURL_CA_BUNDLE=${proxy.mitmCaCertPath} ` +
        (modelHostDeny ? "(model-API hosts are terminated too, and take only their listed paths)." : "(model-API hosts remain blind-tunnel passthrough)."),
    );
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
    console.error("[net-proxy] lifeline armed — exits when the launcher dies");
  }
}

main().catch((err) => {
  console.error(`[net-proxy] fatal: ${(err as Error).message}`);
  process.exit(1);
});
