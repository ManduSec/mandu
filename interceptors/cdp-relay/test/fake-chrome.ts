/**
 * fake-chrome — a DevTools endpoint for the relay's component tests: the
 * discovery JSON and a WebSocket that answers the commands the tests send,
 * records every message, and can push events. Its isolated-world insert
 * mirrors release.ts INSERT_FUNCTION's contract: it types only when the
 * origin argument is the page's current origin. Mandu-new (no reference
 * origin).
 */
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { acceptUpgrade, type WsConnection } from "../src/ws-server.js";

export interface FakeChromeOptions {
  /** The page's URL (its origin is what Page.getFrameTree reports). */
  url: string;
  /** What `Runtime.evaluate` returns as a string value. */
  pageText: string;
  title?: string;
}

export class FakeChrome {
  /** Every message the relay sent, parsed. */
  readonly received: Array<Record<string, unknown>> = [];
  /** Text typed into the page (by the isolated-world insert or Input.*). */
  readonly typed: string[] = [];
  private server: Server | null = null;
  private socket: WsConnection | null = null;
  port = 0;

  constructor(public opts: FakeChromeOptions) {}

  async listen(): Promise<void> {
    const server = createServer((req, res) => {
      const self = `127.0.0.1:${this.port}`;
      const page = { id: "PAGE1", type: "page", title: this.opts.title ?? "page", url: this.opts.url, webSocketDebuggerUrl: `ws://${self}/devtools/page/PAGE1`, devtoolsFrontendUrl: `/devtools/inspector.html?ws=${self}/devtools/page/PAGE1` };
      const routes: Record<string, unknown> = {
        "/json/version": { Browser: "FakeChrome/1.0", "Protocol-Version": "1.3", webSocketDebuggerUrl: `ws://${self}/devtools/browser/B1` },
        "/json": [page],
        "/json/list": [page],
      };
      const body = routes[(req.url ?? "").split("?")[0]!];
      res.writeHead(body === undefined ? 404 : 200, { "content-type": "application/json" });
      res.end(body === undefined ? "{}" : JSON.stringify(body));
    });
    server.on("upgrade", (req, socket, head) => {
      const ws = acceptUpgrade(req, socket, head, { maxPayload: 64 * 1024 * 1024 });
      if (ws !== null) this.onSocket(ws);
    });
    this.server = server;
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
    this.port = (server.address() as AddressInfo).port;
  }

  get url(): string {
    return `http://127.0.0.1:${this.port}`;
  }

  /** Push an event to the relay. */
  emit(method: string, params: Record<string, unknown>, sessionId?: string): void {
    this.socket?.send(JSON.stringify({ method, params, ...(sessionId ? { sessionId } : {}) }));
  }

  async close(): Promise<void> {
    this.socket?.close();
    await new Promise<void>((resolve) => (this.server ? this.server.close(() => resolve()) : resolve()));
  }

  private onSocket(ws: WsConnection): void {
    this.socket = ws;
    ws.onMessage((data) => {
      const msg = JSON.parse(data) as { id: number; method: string; params?: Record<string, unknown>; sessionId?: string };
      this.received.push(msg as unknown as Record<string, unknown>);
      const answer = (result: Record<string, unknown>) => ws.send(JSON.stringify({ id: msg.id, result, ...(msg.sessionId ? { sessionId: msg.sessionId } : {}) }));
      const p = msg.params ?? {};
      switch (msg.method) {
        case "Page.getFrameTree":
          return answer({ frameTree: { frame: { id: "F1", loaderId: "L1", url: this.opts.url, securityOrigin: new URL(this.opts.url).origin, mimeType: "text/html" } } });
        case "Page.createIsolatedWorld":
          return answer({ executionContextId: 77 });
        case "Runtime.callFunctionOn": {
          const args = (p["arguments"] as Array<{ value: unknown }> | undefined) ?? [];
          if (p["executionContextId"] !== 77) return answer({ result: { type: "string", value: "wrong-world" } });
          if (args[0]?.value !== new URL(this.opts.url).origin) return answer({ result: { type: "string", value: "origin" } });
          this.typed.push(String(args[1]?.value));
          return answer({ result: { type: "string", value: "ok" } });
        }
        case "Runtime.evaluate":
          return answer({ result: { type: "string", value: this.opts.pageText } });
        case "Input.insertText":
        case "Input.dispatchKeyEvent":
          if (typeof p["text"] === "string") this.typed.push(p["text"]);
          return answer({});
        case "Network.getResponseBody":
          return answer({ body: Buffer.from(this.opts.pageText).toString("base64"), base64Encoded: true });
        case "Network.getRequestPostData":
          return answer({ postData: this.opts.pageText });
        default:
          return answer({});
      }
    });
  }
}
