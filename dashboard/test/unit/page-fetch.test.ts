/**
 * page-fetch.test — the jsdom page bridge's fetch (page-fetch.ts) survives
 * an event loop blocked past the server's keep-alive timeout, which is what
 * a loaded CI guest does to a served page's first request.
 *
 * The scenario of product-empty-states' "Home: no agent is running" flake:
 * the test fetches the page with the global fetch, which leaves an idle
 * keep-alive socket in its pool; then the page's script runs for longer
 * than the server's keep-alive timeout and makes its first request inside
 * that block. The test's script runs in the continuation of an I/O
 * callback (its fetch of home.js answered), in the loop's poll phase, so
 * after the block the loop runs its timers before it reads the request: the
 * server's keep-alive timer closes the socket with the request unread, and
 * the client gets `read ECONNRESET`. A request the pool put on that idle
 * socket fails so (the control below, with the `Connection: close` header
 * the bridge sent until 2026-10-11); one on a socket of its own does not.
 *
 * The server's keep-alive timeout is 1 s here, not Node's 5 s, and the
 * block 3 s.
 * Axes: none (a test helper; no arbiter). Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { readFile, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import type { Socket } from "node:net";
import { fileURLToPath } from "node:url";

import { pageFetch } from "./page-fetch.js";
import { reservePort } from "./reserve-port.js";

const KEEP_ALIVE_MS = 1_000;
const BLOCK_MS = 3_000;

async function server(): Promise<{ base: string; http: Server; open: Set<Socket> }> {
  const http = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => { body += c; });
    req.on("end", () => {
      if (req.url === "/r") { res.writeHead(302, { location: "/after" }); res.end(); return; }
      if (req.url === "/z") { res.writeHead(200, { "content-encoding": "gzip" }); res.end(gzipSync("squeezed")); return; }
      // A long hint, so the pool keeps the idle socket however slow the
      // test runs (Node's own 1 s hint is under the pool's threshold, so it
      // would not keep it at all); the server's timer is what closes it.
      res.writeHead(200, { "content-type": "application/json", "keep-alive": "timeout=600" });
      res.end(JSON.stringify({ method: req.method, path: req.url, body, type: req.headers["content-type"] ?? null }));
    });
  });
  http.keepAliveTimeout = KEEP_ALIVE_MS;
  // Newer Node adds a buffer to the timeout (1 s); the CI guest's Node 22.13
  // has none.
  (http as Server & { keepAliveTimeoutBuffer?: number }).keepAliveTimeoutBuffer = 0;
  const open = new Set<Socket>();
  http.on("connection", (s: Socket) => { open.add(s); s.on("close", () => open.delete(s)); });
  await new Promise<void>((r) => http.listen(0, "127.0.0.1", r));
  const addr = http.address();
  return { base: `http://127.0.0.1:${typeof addr === "object" && addr ? addr.port : 0}`, http, open };
}

/** Leave an idle keep-alive socket in the global fetch's pool, then, from
 *  an I/O callback (the loop's poll phase), block the event loop past the
 *  server's keep-alive timeout and start `go` inside the block, as a page's
 *  synchronous script does. */
async function afterBlock<T>(srv: { base: string; open: Set<Socket> }, go: () => Promise<T>): Promise<{ r: PromiseSettledResult<T>; idle: boolean }> {
  await (await fetch(`${srv.base}/page.html`)).text();
  await new Promise((r) => setTimeout(r, 50)); // the socket is back in the pool
  await new Promise((r) => readFile(fileURLToPath(import.meta.url), r));
  // Whether the idle socket was still open when the block began: a stall
  // past the server's timeout before here closes it first.
  const idle = srv.open.size === 1;
  const until = Date.now() + BLOCK_MS;
  const p = go();
  while (Date.now() < until) { /* the page's script, on a loaded guest */ }
  const [r] = await Promise.allSettled([p]);
  return { r: r!, idle };
}

test("control: the global fetch with Connection: close is put on the pool's idle socket, and loses it to the server's keep-alive timer", async () => {
  // A run where a stall closed the idle socket before the block proves
  // nothing; the next one tries again.
  for (let tries = 1; ; tries++) {
    const srv = await server();
    try {
      const { r, idle } = await afterBlock(srv, () => fetch(`${srv.base}/api/home`, { headers: { connection: "close" } }).then((res) => res.text()));
      if (!idle && tries < 5) continue;
      assert.ok(idle, "the idle socket was open when the block began");
      assert.equal(r.status, "rejected", "the request on the idle socket failed, as the flake did");
      return;
    } finally {
      srv.http.closeAllConnections();
      srv.http.close();
    }
  }
});

test("pageFetch: a request started in a block past the keep-alive timeout gets its answer", async () => {
  const srv = await server();
  const { base, http } = srv;
  try {
    const { r } = await afterBlock(srv, () => pageFetch(`${base}/api/home`).then((res) => res.json()));
    assert.equal(r.status, "fulfilled", r.status === "rejected" ? String(r.reason) : "");
    assert.deepEqual(r.value, { method: "GET", path: "/api/home", body: "", type: null });
  } finally {
    http.closeAllConnections();
    http.close();
  }
});

test("pageFetch: answers like fetch — status, headers, a POST's string body with its content type, a stream, a redirect, a gzipped body, an abort, no answer", async () => {
  const { base, http } = await server();
  try {
    const res = await pageFetch(`${base}/api/x`, { method: "POST", body: JSON.stringify({ a: 1 }) });
    assert.equal(res.status, 200);
    assert.equal(res.ok, true);
    assert.equal(res.headers.get("content-type"), "application/json");
    assert.deepEqual(await res.json(), { method: "POST", path: "/api/x", body: "{\"a\":1}", type: "text/plain;charset=UTF-8" });
    const streamed = await pageFetch(`${base}/s`);
    const reader = streamed.body!.getReader();
    let text = "";
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      text += new TextDecoder().decode(value);
    }
    assert.match(text, /"path":"\/s"/);
    const moved = await pageFetch(`${base}/r`, { method: "POST", body: "x" });
    assert.equal(moved.redirected, true);
    assert.deepEqual(await moved.json(), { method: "GET", path: "/after", body: "", type: null });
    const zipped = await pageFetch(`${base}/z`);
    assert.equal(await zipped.text(), "squeezed", "a gzipped body is read decoded");
    assert.equal(zipped.url, `${base}/z`);
    const kept = await pageFetch(`${base}/r`, { redirect: "manual" });
    assert.deepEqual([kept.status, kept.headers.get("location"), kept.redirected], [302, "/after", false]);
    const abort = new AbortController();
    abort.abort();
    await assert.rejects(pageFetch(`${base}/a`, { signal: abort.signal }), { name: "AbortError" });
    await assert.rejects(pageFetch(`http://127.0.0.1:${await reservePort()}/none`), (e: Error) => e instanceof TypeError && e.message === "fetch failed");
  } finally {
    http.closeAllConnections();
    http.close();
  }
});

test("a file that runs a served page in jsdom fetches from the server only through pageFetch", () => {
  // Not only the page's bridge: the harness's own fetch right after it ran
  // a page's script is on the same race (served-page.ts fetched each module
  // after evaluating the one before: "fetch failed", pipeline 10380), and
  // two component files still bridged the page to the global fetch until
  // 2026-10-11 ("the dashboard server did not answer", pipeline 10295).
  const component = fileURLToPath(new URL("../component/", import.meta.url));
  const files = [
    ...readdirSync(component).filter((f) => f.endsWith(".ts")).map((f) => join(component, f)),
    fileURLToPath(new URL("./ui/served-page.ts", import.meta.url)),
  ].map((f) => ({ f, src: readFileSync(f, "utf8") })).filter(({ src }) => /new JSDOM\(/.test(src));
  assert.ok(files.length >= 10, `the scan finds the files (${files.length})`);
  for (const { f, src } of files) {
    assert.match(src, /pageFetch\(/, `${f} fetches through pageFetch`);
    assert.doesNotMatch(src, /(?<![\w.])fetch\(/, `${f}: no call of the global fetch`);
  }
});
