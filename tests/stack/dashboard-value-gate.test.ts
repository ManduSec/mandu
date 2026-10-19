/**
 * dashboard-value-gate.test — a program on the dashboard's host gets no
 * secret value from it without the human's sign-in, across the REAL
 * components (dashboard.md §6 "Reads and the admin session";
 * dashboard src/server/read-gate.ts).
 *
 * A real ArbiterServer (`secrets` axes) holding a registered secret and a
 * session whose events carry its value where the proxies put it (the raw
 * tool result, a send with the value filled in, and two shapes logs before
 * 2026-10-06 carry: a mint whose input holds the value in both forms, a
 * reply-filter frame holding a tool's raw output), a real DashboardServer
 * over a real ArbiterEventSource, and the dashboard's real sign-in socket.
 *
 *   G1  a SEPARATE process on this host (a child node, no cookie: the
 *       position of a program the agent runs) walks every read the
 *       dashboard lists, with every header it can forge (the CSRF header,
 *       Sec-Fetch-Site, a made-up cookie): no answer carries the value, and
 *       a page that rebound its own name to 127.0.0.1 is refused (421);
 *   G2  the human signs in with a one-time link from the human-plane
 *       socket: the same session's events carry the value;
 *   G3  "Show the real value" on the product page (POST /api/home/reveal):
 *       the same-host process is refused (403, with the CSRF header it can
 *       forge); the signed-in human gets that one secret's value from the
 *       arbiter, and a ref the session did not record gets nothing.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { serveSignInChannel, signInDepsFor, signInSockPath } from "../../dashboard/src/sign-in.js";
import { requestSignInLink } from "../../launcher/src/dashboard-sign-in.js";
import { allSamples } from "../../dashboard/test/unit/read-route-samples.js";
import { secretRef } from "../../dashboard/src/view-model/secret-ref.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets");

/** Run a node child without blocking this process (the dashboard under test
 *  answers it from here). */
const node = async (args: string[]): Promise<{ status: number; stdout: string; stderr: string }> => {
  try {
    const r = await promisify(execFile)(process.execPath, args, { encoding: "utf8", timeout: 100_000, maxBuffer: 16 << 20 });
    return { status: 0, stdout: r.stdout, stderr: r.stderr };
  } catch (err) {
    const e = err as { code?: number; stdout?: string; stderr?: string };
    return { status: typeof e.code === "number" ? e.code : 1, stdout: e.stdout ?? "", stderr: e.stderr ?? String(err) };
  }
};

const CANARY = "sk-value-gate-stack-canary-91c2";
const SESSION = "1791100000-777";

/** What the program the agent runs would do: GET each path with each forged
 *  header set, read a little of a stream, and report any body carrying the
 *  value. A separate process: it has nothing the test process holds. */
const CRAWLER = `
const [base, canary, pathsJson] = process.argv.slice(1);
const forged = [{}, { "X-Mandu-Control": "1" }, { "Sec-Fetch-Site": "same-origin" }, { "X-Mandu-Control": "1", Cookie: "mandu_session=" + "0".repeat(64) }];
const out = [];
for (const path of JSON.parse(pathsJson)) {
  for (const headers of forged) {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), 1500);
    let status = 0, body = "";
    try {
      const res = await fetch(base + path, { headers, signal: ac.signal });
      status = res.status;
      const reader = res.body.getReader();
      const end = Date.now() + 500;
      while (Date.now() < end) {
        const { value, done } = await reader.read();
        if (done) break;
        body += new TextDecoder().decode(value);
      }
      ac.abort();
    } catch {}
    clearTimeout(timer);
    out.push({ path, headers: Object.keys(headers).join("+") || "none", status, leak: body.includes(canary) });
  }
}
console.log(JSON.stringify(out));
`;

test("a same-host process gets no secret value from any dashboard read; the signed-in human does", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-value-gate-stack-"));
  const socketPath = join(tmp, "arbiter.sock");
  const humanPath = humanSockIn(tmp);
  const server = new ArbiterServer({
    socketPath, adminSocketPath: join(tmp, "admin.sock"), humanSocketPath: humanPath,
    dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false, // the `secrets` axes, stated
  });
  await server.listen();
  const gate = new ArbiterClient(socketPath); await gate.connect();
  const human = new ArbiterClient(humanPath); await human.connect();
  const source = new ArbiterEventSource({ socketPath, humanSocketPath: humanPath });
  const dashboard = new DashboardServer({ source, log: () => {} });
  const port = await dashboard.listen(0);
  const base = `http://127.0.0.1:${port}`;
  const signIn = await serveSignInChannel(signInSockPath(tmp), signInDepsFor(dashboard, source, join(tmp, "human")));
  try {
    // A registered secret, and a session whose events carry its value where
    // the proxies put it.
    const env = join(tmp, ".env");
    writeFileSync(env, `API_KEY=${CANARY}\n`);
    const reg = await gate.registerSecret({ path: env, sessionKey: SESSION });
    const sym = String(reg.symbol);
    assert.match(sym, /^\$MDU:/, JSON.stringify(reg));
    const now = (): string => new Date().toISOString();
    const dual = (symbolized: string, original: string) => ({ symbolized, original, differs: true, symbols: [{ name: sym, tool: "Read", field: null, origin: env, value: original, confidentiality: "no-model" }] });
    await human.emit({ id: "vg-call", sessionId: SESSION, ts: now(), kind: "tllm_call", view: "AgentView", boundary: "model_context", emitter: "anthropic-proxy", input: { symbolized: "Read .env", original: null, differs: false, symbols: [] } } as never);
    await human.emit({ id: "vg-result", sessionId: SESSION, ts: now(), kind: "tool_result", view: "AgentView", boundary: "model_context", emitter: "anthropic-proxy", callId: "c1", output: dual(sym, `API_KEY=${CANARY}`) } as never);
    await human.emit({ id: "vg-send", sessionId: SESSION, ts: now(), kind: "desymbolize", view: "HumanView", boundary: "network", emitter: "net-proxy", input: dual(`curl -H "k: ${sym}"`, `curl -H "k: ${CANARY}"`) } as never);
    // A mint as logs written before 2026-10-06 carry it: the value before
    // masking in both forms of the input, its `symbolized` too.
    await human.emit({ id: "vg-mint", sessionId: SESSION, ts: now(), kind: "symbolize", view: "AgentView", boundary: "model_context", emitter: "anthropic-proxy", callId: "c1", input: { symbolized: `API_KEY=${CANARY}`, original: `API_KEY=${CANARY}`, differs: false, symbols: [] }, output: dual(sym, `API_KEY=${CANARY}`) } as never);
    // And a reply-filter frame as such logs carry it: the terminal write,
    // with a tool's raw output in it, as its `symbolized` form.
    const frame = `  ⎿  API_KEY=${CANARY}\n● Saved as ${sym}`;
    await human.emit({ id: "vg-reply", sessionId: SESSION, ts: now(), kind: "desymbolize", view: "HumanView", boundary: "model_context", emitter: "reply-filter", callId: null, input: { symbolized: frame, original: null, differs: false, symbols: [] }, output: { symbolized: frame, original: frame.replace(sym, `API_KEY=${CANARY}`), differs: true, symbols: [] } } as never);
    const recorded = await source.readEvents(SESSION);
    assert.ok(JSON.stringify(recorded).includes(CANARY), "the store holds the value (what there is to leak)");

    // G1: a separate process, every listed read, every forgeable header.
    const paths = allSamples(SESSION).map((s) => s.path);
    const run = await node(["--input-type=module", "-e", CRAWLER, base, CANARY, JSON.stringify(paths)]);
    assert.equal(run.status, 0, run.stderr);
    const results = JSON.parse(run.stdout) as Array<{ path: string; headers: string; status: number; leak: boolean }>;
    assert.equal(results.length, paths.length * 4);
    assert.deepEqual(results.filter((r) => r.leak), [], "no read carried the value to a process without the sign-in");
    assert.ok(results.some((r) => r.path.startsWith("/api/events") && r.status === 200), "the events read answered (without the value)");
    // DNS rebinding: the page's own name in Host is refused before any route.
    const rebound = await node(["--input-type=module", "-e",
      `import { request } from "node:http"; const r = request({ host: "127.0.0.1", port: ${port}, path: "/api/events?session=${SESSION}", setHost: false, headers: { Host: "attacker.example:${port}" } }, (res) => { console.log(res.statusCode); res.resume(); }); r.end();`,
    ]);
    assert.equal(rebound.stdout.trim(), "421");

    // G2: the human's one-time link earns the session; the same read carries the value.
    const got = await requestSignInLink({ host: "127.0.0.1", port, signInSock: signIn.path }, tmp);
    assert.equal(got.kind, "link", JSON.stringify(got));
    const opened = await fetch((got as { url: string }).url, { redirect: "manual" });
    const cookie = (opened.headers.get("set-cookie") ?? "").split(";")[0]!;
    assert.match(cookie, /^mandu_session=[0-9a-f]{64}$/);
    const signedIn = await (await fetch(`${base}/api/events?session=${SESSION}`, { headers: { Cookie: cookie, "X-Mandu-Control": "1" } })).text();
    assert.ok(signedIn.includes(CANARY), "signed in, the human sees the real value");
    assert.match(signedIn, /"valuesShown":true/);

    // G3: one secret's value on a click. The page names it by its ref.
    const ref = secretRef(SESSION, sym);
    const page = await (await fetch(`${base}/api/home/agent?session=${SESSION}`, { headers: { Cookie: cookie, "X-Mandu-Control": "1" } })).text();
    assert.ok(!page.includes(CANARY), "even signed in, the page carries no secret value until a click");
    // The whole original behind a step's mask (dashboard.md §4.25ae) is the
    // signed-in reader's, and never a secret's: the `.env` read's has none.
    const whole = await fetch(`${base}/api/home/original?session=${SESSION}&step=${encodeURIComponent("tool:c1")}`, { headers: { Cookie: cookie, "X-Mandu-Control": "1" } });
    const wholeText = await whole.text();
    assert.equal(whole.status, 404, wholeText);
    assert.ok(!wholeText.includes(CANARY), "the whole-original route never carries a secret's value");
    // History lists the session, signed out and in, with no value.
    const history = await (await fetch(`${base}/api/home/history`, { headers: { Cookie: cookie, "X-Mandu-Control": "1" } })).text();
    assert.match(history, new RegExp(`"id":"${SESSION}"`));
    assert.ok(!history.includes(CANARY), "History carries no value");
    const forged = await node(["--input-type=module", "-e",
      `const r = await fetch(${JSON.stringify(base + "/api/home/reveal")}, { method: "POST", headers: { "X-Mandu-Control": "1", "Content-Type": "application/json" }, body: JSON.stringify({ session: ${JSON.stringify(SESSION)}, ref: ${JSON.stringify(ref)} }) }); const t = await r.text(); console.log(JSON.stringify({ status: r.status, leak: t.includes(${JSON.stringify(CANARY)}) }));`,
    ]);
    assert.deepEqual(JSON.parse(forged.stdout), { status: 403, leak: false }, forged.stderr);
    const reveal = async (body: unknown) => fetch(`${base}/api/home/reveal`, { method: "POST", headers: { Cookie: cookie, "X-Mandu-Control": "1", "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const shown = await reveal({ session: SESSION, ref });
    assert.equal(shown.status, 200);
    assert.match(((await shown.json()) as { value: string }).value, new RegExp(CANARY), "the arbiter's value of that one secret");
    assert.equal((await reveal({ session: SESSION, ref: secretRef("another-session", sym) })).status, 404, "not a general desymbolize");
  } finally {
    await signIn.close();
    gate.close();
    human.close();
    await dashboard.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
