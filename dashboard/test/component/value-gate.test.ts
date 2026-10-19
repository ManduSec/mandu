/**
 * value-gate.test — the read gate and the Host check over a REAL socket
 * (src/server/read-gate.ts; dashboard.md §6 "Reads and the admin session").
 * Mandu-new.
 *
 * A real DashboardServer over a FileEventSource whose one session carries a
 * canary value in every place a value can sit: a tool result's original, a
 * symbol's resolved value, a reply the human saw, a seeded file, a
 * HumanView final file, and two shapes logs written before 2026-10-06
 * carry: a `symbolize` event's input (the value before masking in BOTH
 * forms, its `symbolized` too) and a reply-filter frame (the terminal write,
 * a tool's raw output in it, as its `symbolized` form). Then:
 * The server is the product's alone (no developer view; its routes are
 * value-gate-inspector.test.ts's, dashboard.md §4.25ac).
 *   V1  every GET in READ_ROUTES, signed out (also with the CSRF header and
 *       Sec-Fetch-Site, which any process can send): an `admin` route is
 *       403, and NO route's body carries the canary;
 *   V2  signed in (cookie + CSRF header), the projection routes carry it:
 *       the events, the stream, the agent page;
 *   V3  an /api/ GET no entry names is 403 signed out (fail closed);
 *   V4  the Host check: a rebinding page's name is 421 before any route
 *       (even /login), a missing Host too; loopback names at the port and a
 *       configured name pass.
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { request } from "node:http";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { DashboardServer } from "../../src/server.js";
import { FileEventSource } from "../../src/event-source.js";
import { ADMIN_OPTS, CSRF_ADMIN } from "../unit/admin-session.js";
import { tmpDir } from "../unit/tmp-dir.js";
import { allSamples } from "../unit/read-route-samples.js";

const CANARY = "sk-value-gate-canary-7f3a9c";
const SID = "1791000000-4242";
const SYM = "$MDU:Read[c0de]";

function ev(seq: number, over: Record<string, unknown>): Record<string, unknown> {
  return {
    id: `01J${String(seq).padStart(23, "0")}`, sessionId: SID, turn: 1, ts: `2026-10-05T10:00:0${seq}.000Z`, seq,
    callId: "call-1", parentId: null, view: "AgentView", boundary: "model_context", emitter: "anthropic-proxy",
    input: null, output: null, invariant: { violatedInvariant: false }, ...over,
  };
}

const dual = (symbolized: string, original: string) => ({
  symbolized, original, differs: true,
  symbols: [{ name: SYM, tool: "Read", field: null, origin: "/w/.env", value: original, confidentiality: "no-model" }],
});

let server: DashboardServer;
let base: string;
let port: number;

before(async () => {
  const dir = tmpDir("mandu-value-gate-");
  const events = join(dir, "events");
  mkdirSync(events, { recursive: true });
  const lines = [
    ev(1, { kind: "tllm_call", input: { symbolized: "Read the .env file", original: null, differs: false, symbols: [] }, output: { symbolized: "ok", original: null, differs: false, symbols: [] } }),
    ev(2, { kind: "tool_result", output: dual(SYM, `API_KEY=${CANARY}`), policy: { trust: "TRUSTED", confidentiality: "no-model" } }),
    ev(3, { kind: "desymbolize", view: "HumanView", boundary: "network", emitter: "net-proxy", input: dual(`curl -H "k: ${SYM}"`, `curl -H "k: ${CANARY}"`) }),
    ev(4, { kind: "workspace_seed", emitter: "test-harness", seedFiles: [{ path: ".env", content: `API_KEY=${CANARY}\n`, poisoned: false }] }),
    ev(5, { kind: "workspace_final", emitter: "test-harness", finalViews: [
      { view: "HumanView", root: "/w", truncated: false, files: [{ path: "notes.txt", content: `key ${CANARY}`, size: 40, truncated: false, binary: false }] },
      { view: "AgentView", root: "/a", truncated: false, files: [{ path: "notes.txt", content: `key ${SYM}`, size: 20, truncated: false, binary: false }] },
    ] }),
    ev(6, { kind: "symbolize", input: { symbolized: `API_KEY=${CANARY}`, original: `API_KEY=${CANARY}`, differs: false, symbols: [] }, output: dual(SYM, `API_KEY=${CANARY}`) }),
    ev(7, { kind: "desymbolize", view: "HumanView", emitter: "reply-filter", callId: null,
      input: { symbolized: `  ⎿  API_KEY=${CANARY}\n● Saved as ${SYM}`, original: null, differs: false, symbols: [] },
      output: { symbolized: `  ⎿  API_KEY=${CANARY}\n● Saved as ${SYM}`, original: `  ⎿  API_KEY=${CANARY}\n● Saved as API_KEY=${CANARY}`, differs: true, symbols: [] } }),
  ];
  writeFileSync(join(events, `${SID}.ndjson`), lines.map((l) => JSON.stringify(l)).join("\n") + "\n");
  server = new DashboardServer({
    ...ADMIN_OPTS, source: new FileEventSource(events), log: () => {},
    configEnv: { MANDU_HOME: join(dir, "home") }, fileBrowserHome: dir,
    allowedHosts: ["dash.example.org"],
  });
  port = await server.listen(0);
  base = `http://127.0.0.1:${port}`;
});

after(async () => {
  await server.close();
});

/** GET `path` and read the body; an SSE route is read for a moment, then cut. */
async function get(path: string, headers: Record<string, string>): Promise<{ status: number; body: string }> {
  const ac = new AbortController();
  const res = await fetch(base + path, { headers, signal: ac.signal });
  let body = "";
  if ((res.headers.get("content-type") ?? "").startsWith("text/event-stream")) {
    const reader = res.body!.getReader();
    const end = Date.now() + 400;
    const timer = setTimeout(() => ac.abort(), 400);
    try {
      while (Date.now() < end) {
        const { value, done } = await reader.read();
        if (done) break;
        body += new TextDecoder().decode(value);
      }
    } catch { /* aborted */ }
    clearTimeout(timer);
  } else {
    body = await res.text();
  }
  return { status: res.status, body };
}

test("V1: signed out, every listed read: an admin route is 403, and no body carries a value", async () => {
  const forged: Array<Record<string, string>> = [{}, { "X-Mandu-Control": "1" }, { "Sec-Fetch-Site": "same-origin" }, { "X-Mandu-Control": "1", Cookie: "mandu_session=forged" }];
  for (const { route, path } of allSamples(SID)) {
    for (const headers of forged) {
      const { status, body } = await get(path, headers);
      if (route.access === "admin") assert.equal(status, 403, `${path} ${JSON.stringify(headers)}`);
      assert.ok(!body.includes(CANARY), `${path} carried the value signed out (${status})`);
    }
  }
});

test("V2: signed in, the projection routes carry the value (cookie and CSRF header)", async () => {
  const events = await get(`/api/events?session=${SID}`, CSRF_ADMIN);
  assert.equal(events.status, 200);
  assert.ok(events.body.includes(CANARY), "the original and the seeded file");
  assert.match(events.body, /"valuesShown":true/);
  // signed out the same events go out as what the AI saw
  const out = await get(`/api/events?session=${SID}`, {});
  assert.equal(out.status, 200);
  assert.ok(!out.body.includes(CANARY), "signed out: no value");
  assert.match(out.body, /"valuesShown":false/);
  // the SSE stream with a browser's own same-origin header and the cookie
  const stream = await get(`/api/stream?session=${SID}&sinceSeq=0`, { Cookie: CSRF_ADMIN.Cookie!, "Sec-Fetch-Site": "same-origin" });
  assert.ok(stream.body.includes(CANARY), "the stream carries it for the signed-in browser");
});

test("V3: an /api/ GET no entry names is 403 signed out (fail closed)", async () => {
  const r = await get("/api/not-a-route-yet", {});
  assert.equal(r.status, 403);
  assert.equal((await get("/api/not-a-route-yet", CSRF_ADMIN)).status, 404);
});

/** A raw request with exactly this Host header (fetch would set its own). */
function withHost(path: string, host: string | null): Promise<number> {
  return new Promise((resolve, reject) => {
    const req = request({ host: "127.0.0.1", port, path, method: "GET", setHost: false, headers: host === null ? {} : { Host: host } }, (res) => {
      res.resume();
      resolve(res.statusCode ?? 0);
    });
    req.on("error", reject);
    req.end();
  });
}

test("V4: the Host check runs before every route: a rebinding page's name is 421", async () => {
  assert.equal(await withHost("/api/sessions", `attacker.example:${port}`), 421);
  assert.equal(await withHost("/login", `attacker.example:${port}`), 421, "even /login");
  assert.equal(await withHost(`/api/events?session=${SID}`, `127.0.0.1.attacker.example:${port}`), 421);
  assert.notEqual(await withHost("/api/sessions", null), 200, "no Host at all (node answers 400 itself)");
  assert.equal(await withHost("/api/sessions", `127.0.0.1:${port + 1}`), 421, "another port");
  assert.equal(await withHost("/api/sessions", `localhost:${port}`), 200);
  assert.equal(await withHost("/api/sessions", `127.0.0.1:${port}`), 200);
  assert.equal(await withHost("/api/sessions", "dash.example.org"), 200, "a configured name");
});
