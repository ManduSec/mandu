/**
 * server-main — run the DevTools relay (docs/design/agents/devtools-relay.md
 * §6). Mandu-new (no reference origin).
 *
 *   MANDU_ARBITER_SOCK=… MANDU_ARBITER_HUMAN_SOCK=… \
 *     tsx src/server-main.ts --upstream http://127.0.0.1:9222 [--port 0] [--session <key>] [--port-file <path>]
 *
 * Prints `cdp-relay: listening on http://127.0.0.1:<port>`; the agent is
 * given that URL in place of Chrome's.
 */
import { renameSync, writeFileSync } from "node:fs";
import { ArbiterClientAdapter, HUMAN_SOCK_ENV, humanSockFromEnv, type RealArbiterClient } from "./arbiter-client.js";
import { CdpRelay } from "./relay.js";

process.title = "mandu-cdp-relay";

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

async function main(): Promise<void> {
  const sock = process.env["MANDU_ARBITER_SOCK"];
  if (!sock) {
    console.error("[cdp-relay] MANDU_ARBITER_SOCK is required (path to the arbiter Unix socket)");
    process.exit(2);
  }
  const upstream = arg("upstream") ?? process.env["MANDU_CDP_UPSTREAM"];
  if (!upstream) {
    console.error("[cdp-relay] --upstream <Chrome's http://host:port debugging endpoint> is required");
    process.exit(2);
  }
  // The real client, built at run time so this package typechecks without
  // the arbiter's sources (net-proxy's server-main does the same; a bundled
  // build names the module in MANDU_ARBITER_CLIENT_MODULE).
  const spec = process.env["MANDU_ARBITER_CLIENT_MODULE"] ?? ["..", "..", "..", "arbiter", "ipc", "client.js"].join("/");
  const mod = (await import(spec)) as {
    ArbiterClient: (new (sock: string) => RealArbiterClient & { connect(): Promise<void> }) & {
      humanPlane?: (humanSock: string, dataSock?: string | null) => RealArbiterClient;
    };
  };
  const data = new mod.ArbiterClient(sock);
  await data.connect();
  const humanSock = humanSockFromEnv(process.env);
  const human = humanSock ? (mod.ArbiterClient.humanPlane?.(humanSock, sock) ?? new mod.ArbiterClient(humanSock)) : null;
  if (!human) {
    console.error(`[cdp-relay] WARNING: ${HUMAN_SOCK_ENV} is not set: every placeholder the agent types is refused (fail-closed)`);
  }
  const session = arg("session") ?? process.env["MANDU_SESSION_KEY"];
  const port = Number(arg("port") ?? "0");
  const relay = new CdpRelay({
    upstream,
    arbiter: new ArbiterClientAdapter(data, human),
    ...(session ? { session } : {}),
    port: Number.isInteger(port) && port >= 0 ? port : 0,
    log: (line) => console.error(line),
  });
  const at = await relay.listen();
  // Written whole, then renamed: the launcher polls for the file and must
  // never read it half-written.
  const portFile = arg("port-file");
  if (portFile) {
    writeFileSync(`${portFile}.tmp`, `${at.port}\n`);
    renameSync(`${portFile}.tmp`, portFile);
  }
  console.log(`cdp-relay: listening on ${at.url}`);
  const stop = (): void => {
    void relay.close().finally(() => process.exit(0));
  };
  process.on("SIGTERM", stop);
  process.on("SIGINT", stop);
}

main().catch((err: unknown) => {
  console.error(`[cdp-relay] ${(err as Error).message}`);
  process.exit(1);
});
