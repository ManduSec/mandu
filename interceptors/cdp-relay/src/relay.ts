/**
 * relay — the DevTools relay server (docs/design/agents/devtools-relay.md
 * §2). Mandu-new (no reference origin).
 *
 * It looks like Chrome's own debugging endpoint to the agent:
 *   - HTTP `/json/version`, `/json`, `/json/list`, `/json/new`,
 *     `/json/activate/<id>`, `/json/close/<id>`, `/json/protocol` go to
 *     Chrome; the answer's WebSocket URLs are rewritten to the relay's and
 *     its strings (page titles, URLs) masked like any message;
 *   - a WebSocket on `/devtools/...` is paired with one to Chrome on the
 *     same path, and every message crosses `pair.ts`'s rules.
 * Only a loopback `Host` is served (Chrome's own DNS-rebinding rule).
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import type { Arbiter } from "./arbiter-client.js";
import { maskMessage } from "./inbound.js";
import { RelayPair, MAX_PAYLOAD } from "./pair.js";
import { ShownPlaceholders } from "./shown.js";
import { acceptUpgrade, type WsConnection } from "./ws-server.js";

export interface RelayOptions {
  /** Chrome's debugging endpoint, e.g. `http://127.0.0.1:9222`. */
  upstream: string;
  arbiter: Arbiter;
  /** The Mandu session the filter mints in and the decisions name. */
  session?: string;
  host?: string;
  port?: number;
  log?: (line: string) => void;
}

const DISCOVERY = /^\/json(?:\/(?:version|list|protocol|new|activate\/[^/]+|close\/[^/]+))?\/?$/;
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]", "::1"]);

export class CdpRelay {
  private server: Server | null = null;
  private readonly pairs = new Set<RelayPair>();
  private readonly upstream: URL;
  private readonly log: (line: string) => void;
  /** The placeholders shown to the agent, on any of its connections. */
  private readonly shown = new ShownPlaceholders();

  constructor(private readonly opts: RelayOptions) {
    this.upstream = new URL(opts.upstream);
    if (this.upstream.protocol !== "http:") throw new Error(`the upstream must be Chrome's http:// debugging endpoint, not ${opts.upstream}`);
    this.log = opts.log ?? (() => {});
  }

  /** Start listening; resolves with the bound address. */
  async listen(): Promise<{ host: string; port: number; url: string }> {
    const server = createServer((req, res) => void this.onHttp(req, res));
    server.on("upgrade", (req, socket, head) => {
      if (!loopbackHost(req) || !(req.url ?? "").startsWith("/devtools/")) {
        socket.end("HTTP/1.1 403 Forbidden\r\n\r\n");
        return;
      }
      const ws = acceptUpgrade(req, socket, head, { maxPayload: MAX_PAYLOAD });
      if (ws !== null) this.onAgent(ws, req.url!);
    });
    this.server = server;
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(this.opts.port ?? 0, this.opts.host ?? "127.0.0.1", () => resolve());
    });
    const a = server.address() as AddressInfo;
    return { host: a.address, port: a.port, url: `http://${a.address}:${a.port}` };
  }

  async close(): Promise<void> {
    for (const p of this.pairs) p.close();
    this.server?.closeAllConnections();
    await new Promise<void>((resolve) => (this.server ? this.server.close(() => resolve()) : resolve()));
  }

  private onAgent(ws: WsConnection, path: string): void {
    const target = new URL(path, `ws://${this.upstream.host}`);
    const pair = new RelayPair(ws, target.toString(), {
      arbiter: this.opts.arbiter,
      ...(this.opts.session !== undefined ? { session: this.opts.session } : {}),
      log: this.log,
      shown: this.shown,
    });
    this.pairs.add(pair);
    pair.onClose(() => this.pairs.delete(pair));
  }

  private async onHttp(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const path = (req.url ?? "/").split("?")[0]!;
    if (!loopbackHost(req)) return send(res, 403, "text/plain", "Host must be a loopback address\n");
    if (!DISCOVERY.test(path)) return send(res, 404, "text/plain", "not a DevTools discovery endpoint\n");
    let upstream: Response;
    try {
      upstream = await fetch(new URL(req.url ?? "/", this.upstream), { method: req.method === "PUT" ? "PUT" : "GET" });
    } catch (err) {
      return send(res, 502, "text/plain", `Chrome did not answer: ${(err as Error).message}\n`);
    }
    const body = await upstream.text();
    let json: unknown;
    try {
      json = JSON.parse(body);
    } catch {
      return send(res, upstream.status, "text/plain", body);
    }
    const self = req.headers.host ?? "";
    json = this.rewriteUrls(json, self);
    if (!path.startsWith("/json/protocol")) {
      const v = await maskMessage(json, { arbiter: this.opts.arbiter, ...(this.opts.session !== undefined ? { session: this.opts.session } : {}) });
      if (v.kind === "withhold") return send(res, 503, "text/plain", `Mandu: withheld: ${v.reason}\n`);
      json = v.message;
    }
    send(res, upstream.status, "application/json", JSON.stringify(json));
  }

  /** Chrome's WebSocket URLs point at the relay; the DevTools front-end
   *  link (which embeds one) is dropped. */
  private rewriteUrls(json: unknown, self: string): unknown {
    const fix = (o: Record<string, unknown>): Record<string, unknown> => {
      const out = { ...o };
      if (typeof out["webSocketDebuggerUrl"] === "string") {
        const u = new URL(out["webSocketDebuggerUrl"]);
        out["webSocketDebuggerUrl"] = `ws://${self}${u.pathname}`;
      }
      delete out["devtoolsFrontendUrl"];
      delete out["devtoolsFrontendUrlCompat"];
      return out;
    };
    if (Array.isArray(json)) return json.map((x) => (typeof x === "object" && x !== null ? fix(x as Record<string, unknown>) : x));
    if (typeof json === "object" && json !== null) return fix(json as Record<string, unknown>);
    return json;
  }
}

function loopbackHost(req: IncomingMessage): boolean {
  const host = req.headers.host ?? "";
  const name = host.startsWith("[") ? host.slice(0, host.indexOf("]") + 1) : host.split(":")[0]!;
  return LOOPBACK_HOSTS.has(name);
}

function send(res: ServerResponse, status: number, type: string, body: string): void {
  res.writeHead(status, { "content-type": type });
  res.end(body);
}
