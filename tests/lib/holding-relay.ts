/**
 * holding-relay — an HTTP relay in front of the dashboard that holds one
 * chosen answer back, as a slow network does, so a stack test can make a
 * read the page asked first answer after one it asked later (dashboard.md
 * §4.25 *An older poll's answer never draws over a newer one*, *A read
 * asked before a change never draws over it*).
 *
 * Every request goes through unchanged (its Host named as the dashboard's,
 * which checks it); `holdNext(path)` keeps the next answer to a GET of
 * `path` once the dashboard has answered it, until released, and
 * `holdNext(path, "POST")` the next answer to a POST (a change the page
 * made, still on its way); `seen` lists every request relayed, as
 * "METHOD path". Used by tests/stack/home-poll-order.test.ts,
 * suggestions-order.test.ts and protection-switch-holds.test.ts.
 * Mandu-new test plumbing.
 */
import { createServer, request, type IncomingMessage, type Server } from "node:http";

/** One held answer: `asked` once the dashboard answered it (the relay keeps
 *  it), `release()` sends it on and resolves once the page has it all. */
export interface Held { asked: Promise<number>; release: () => Promise<void> }

export interface HoldingRelay {
  /** The relay's origin: the page is served through it. */
  base: string;
  /** Hold the next answer to `method` (GET by default) of `path`. */
  holdNext: (path: string, method?: string) => Held;
  /** Every request relayed so far, in order, as "METHOD path". */
  seen: string[];
  close: () => Promise<void>;
}

/** A relay to the dashboard on `port` (127.0.0.1). */
export async function holdingRelay(port: number): Promise<HoldingRelay> {
  const holds: Array<{ path: string; method: string; answered: (status: number) => void; released: Promise<void>; delivered: () => void }> = [];
  const seen: string[] = [];
  const server: Server = createServer((req, res) => {
    seen.push(`${req.method} ${req.url}`);
    const at = holds.findIndex((h) => req.method === h.method && req.url === h.path);
    const hold = at >= 0 ? holds.splice(at, 1)[0] : undefined;
    const up = request({ host: "127.0.0.1", port, method: req.method, path: req.url, headers: { ...req.headers, host: `127.0.0.1:${port}` } }, (answer: IncomingMessage) => {
      if (!hold) {
        res.writeHead(answer.statusCode ?? 502, answer.headers);
        answer.pipe(res);
        return;
      }
      const chunks: Buffer[] = [];
      answer.on("data", (c: Buffer) => chunks.push(c));
      answer.on("end", () => {
        hold.answered(answer.statusCode ?? 0);
        void hold.released.then(() => {
          const { "transfer-encoding": _te, ...headers } = answer.headers;
          const body = Buffer.concat(chunks);
          res.writeHead(answer.statusCode ?? 502, { ...headers, "content-length": String(body.length) });
          res.end(body, hold.delivered);
        });
      });
    });
    up.on("error", () => { res.destroy(); });
    req.pipe(up);
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("the relay has no port");
  return {
    base: `http://127.0.0.1:${address.port}`,
    seen,
    holdNext(path: string, method = "GET"): Held {
      let answered!: (status: number) => void;
      let release!: () => void;
      let delivered!: () => void;
      const asked = new Promise<number>((r) => { answered = r; });
      const released = new Promise<void>((r) => { release = r; });
      const sent = new Promise<void>((r) => { delivered = r; });
      holds.push({ path, method, answered, released, delivered });
      return { asked, release: () => { release(); return sent; } };
    },
    close: () => new Promise<void>((r) => { server.closeAllConnections(); server.close(() => r()); }),
  };
}
