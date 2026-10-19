/**
 * dashboard-prompt-settings-codex — the Codex twin of
 * dashboard-prompt-settings.test.ts: plan 15 phase 4 on the PRODUCT page over
 * the PRODUCTION wiring (confidentiality-plan-15-prompt-filter.md §11 phase 4,
 * §13.7; dashboard.md §4.25y), with the REAL openai-proxy on the Responses
 * wire in place of the anthropic-proxy: a real ArbiterServer (data, human and
 * admin sockets) with a file-backed law, the person's pack and an
 * administrator's lock, the proxy over HTTP on its two production clients, a
 * scripted fake Responses model, and the real DashboardServer over
 * `makeApprovalsArbiter(dataSock, admin)` and `ArbiterEventSource` (CONTRIBUTING.md:
 * the parity test builds the production wiring).
 *
 * Proves, end to end, for Codex:
 *   - a choice made in Settings › Prompt filters (a kind raised from "Remove
 *     it" to "Hide it") is in force on the NEXT request through the real
 *     openai-proxy: the span masked instead of removed;
 *   - a change the administrator locked is refused, naming who locked it;
 *   - the agent page's note under the message says what was hidden, in plain
 *     words; "Show what was hidden" answers the original on demand (a
 *     registered secret never); "Let it through" from the note makes the
 *     message's resend carry the span as written;
 *   - an exception added there is asked about first, then in force on the
 *     next request; the earlier messages it now lets through are resent
 *     with nothing found, the proxy records that (a `prompt_filter` event
 *     with no findings, categories and counts only), and their notes clear;
 *   - no found value and no registered secret appear in /api/home, nor in
 *     the agent page's data before the person let the span through, and the
 *     registered key never reaches the fake model raw.
 *
 * Axes: secrets (stated; the arbiter's confidentiality pinned ON).
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { NO_ADMIN_LAYER, setAdminLayer } from "../../arbiter/policy/admin-layer.js";
import { OpenAiProxy } from "../../interceptors/openai-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/openai-proxy/src/arbiter-client.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { startScriptedResponses } from "../lib/fake-responses.js";
import { humanSockIn } from "../lib/human-plane.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // the confidentiality axis the prompt filter serves; integrity off

const dirs: string[] = [];
after(() => {
  setAdminLayer(NO_ADMIN_LAYER);
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

const KEY = "sk-live-CodexSettingsCanary7Rm3Wd9Ty5";
const TICKET = "ACME-20417";
const OTHER_TICKET = "ACME-99031";
const LOCK_FILE = "10-org.yaml";

function post(port: number, body: unknown, session: string): Promise<{ status: number; body: string }> {
  const data = Buffer.from(JSON.stringify(body));
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: "127.0.0.1", port, method: "POST", path: "/v1/responses",
        headers: { "content-type": "application/json", "content-length": String(data.length), "x-mandu-session-id": session, authorization: "Bearer sk-test-not-real" },
      },
      (res) => {
        let buf = "";
        res.setEncoding("utf8");
        res.on("data", (c) => (buf += c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: buf }));
      },
    );
    req.on("error", reject);
    req.end(data);
  });
}

async function waitFor<T>(what: string, f: () => Promise<T | undefined>, ms = 10_000): Promise<T> {
  const until = Date.now() + ms;
  for (;;) {
    const v = await f();
    if (v !== undefined) return v;
    if (Date.now() > until) throw new Error(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 50));
  }
}

type Turn = { id: string; prompt: string | null; promptNote: { lines: string[]; items: Array<{ eventId: string; index: number; category: string; canShow: boolean; canLetOnce: boolean }> } | null };

test("Codex: Settings › Prompt filters and the note under the message over the real arbiter and openai-proxy: a choice and an exception apply on the next request, a lock refuses, the note lets a span through and clears once nothing is found (secrets axes)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-pf-settings-codex-"));
  dirs.push(dir);
  const dataSock = join(dir, "arbiter.sock");
  const adminSock = join(dir, "admin.sock");
  const humanSock = humanSockIn(dir);
  const packs = join(dir, "prompt-filters");
  mkdirSync(packs);
  writeFileSync(join(packs, "acme.yaml"), "pack: acme-dlp\nversion: 1\npatterns:\n  - id: ticket\n    category: acme.ticket\n    regex: 'ACME-\\d{4,}'\n");
  const adminDir = join(dir, "policy.d");
  mkdirSync(adminDir);
  writeFileSync(join(adminDir, LOCK_FILE), "prompt_filters:\n  actions:\n    secret.shape: { action: redact, locked: true }\n");
  const policyPath = join(dir, "policy.yaml");
  writeFileSync(policyPath, "version: 1\nprompt_filters:\n  filters:\n    acme-dlp: on\n");
  const arbiter = new ArbiterServer({
    socketPath: dataSock, adminSocketPath: adminSock, humanSocketPath: humanSock, dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"),
    policyPath, policyPollMs: 0, integrity: false, confidentiality: true, log: () => {},
    promptPackDir: packs, adminPromptPackDir: null, adminPolicyDir: adminDir, packDir: null, packKeysDir: join(dir, "keys"),
  });
  await arbiter.listen();
  const data = new ArbiterClient(dataSock);
  await data.connect();
  const human = new ArbiterClient(humanSock);
  await human.connect();
  await data.registerEnvSecrets({ vars: [{ name: "STRIPE_API_KEY", value: KEY }] });
  const session = `dash-settings-codex-${process.pid}`;
  const fake = await startScriptedResponses({ script: [], fallbackText: "ok" });
  const proxy = new OpenAiProxy({ arbiter: new ArbiterClientAdapter(data, human), upstreamOrigin: fake.origin, sessionKey: session, log: () => {} });
  const proxyPort = await proxy.listen(0);
  const wired = await makeApprovalsArbiter(dataSock, () => ({ socketPath: adminSock }));
  assert.ok(wired?.policyDoc);
  const doc = wired.policyDoc;
  assert.ok(doc.promptFilters && doc.policyPropose && doc.letPromptFindingThrough, "the production adapter forwards the ops the product page uses");
  const source = new ArbiterEventSource({ socketPath: dataSock, humanSocketPath: humanSock });
  const server = new DashboardServer({ source, policyDocArbiter: doc, approvalsArbiter: wired.arbiter, log: () => {}, ...ADMIN_OPTS });
  const port = await server.listen(0);
  const call = async (method: "GET" | "POST", path: string, body?: unknown, headers: Record<string, string> = { ...CSRF_ADMIN, "Content-Type": "application/json" }) => {
    const r = await fetch(`http://127.0.0.1:${port}/api/${path}`, { method, headers, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
    return { status: r.status, body: (await r.json().catch(() => ({}))) as Record<string, any> };
  };
  // Codex's Responses wire: the environment context, then the conversation,
  // resent whole with each request.
  const msg = (role: "user" | "assistant", text: string) => ({ type: "message", role, content: [{ type: role === "user" ? "input_text" : "output_text", text }] });
  const convo: string[] = [];
  const say = async (text: string) => {
    const r = await post(proxyPort, {
      model: "gpt-5", stream: true,
      tools: [{ type: "function", name: "exec_command", parameters: { type: "object" } }],
      input: [msg("user", "<environment_context>\n  <cwd>/w</cwd>\n</environment_context>"), ...convo.flatMap((h) => [msg("user", h), msg("assistant", "ok")]), msg("user", text)],
    }, session);
    convo.push(text);
    return r;
  };
  const sent = () => fake.requests.filter((q) => q.url.includes("/responses") && q.body.includes('"tools"')).map((q) => q.body);
  const agentPage = async () => (await call("GET", `home/agent?session=${encodeURIComponent(session)}`, undefined, {})).body;
  const story = async () => ((await agentPage())["story"] ?? []) as Turn[];
  const noFound = (what: string, json: string, values: string[]) => {
    for (const v of values) assert.ok(!json.includes(v), `${what} carries a found value (${v})`);
  };
  try {
    // ── Before: the ticket is removed. ──
    assert.equal((await say(`see ${TICKET} today`)).status, 200);
    assert.ok(sent().at(-1)!.includes("see [redacted: acme.ticket] today"), sent().at(-1));

    // ── A choice: Hide it (a tightening), applied at once, in force next. ──
    const hide = await call("POST", "policy/prompt-filters/change", { edit: { op: "set-prompt-action", category: "acme.ticket", action: "mask" } });
    assert.equal(hide.status, 200, JSON.stringify(hide.body));
    assert.equal(hide.body["applied"], true, JSON.stringify(hide.body));
    assert.equal((await say(`deploy ${TICKET} with ${KEY}`)).status, 200);
    const afterHide = sent().at(-1)!;
    assert.match(afterHide, /deploy \$MDU:[A-Za-z_][A-Za-z0-9_]*\[[0-9a-f]{4,8}\] with \$MDU:/, `the next request carries the ticket masked: ${afterHide}`);
    assert.ok(!afterHide.includes(TICKET), "the ticket is not sent");

    // ── A locked kind is refused, naming who locked it. ──
    const locked = await call("POST", "policy/prompt-filters/change", { edit: { op: "set-prompt-action", category: "secret.shape", action: "log" } });
    assert.notEqual(locked.body["applied"], true, JSON.stringify(locked.body));
    assert.match(JSON.stringify(locked.body), new RegExp(`set by your administrator \\([^)]*${LOCK_FILE.replace(".", "\\.")}\\)`));

    // ── The note under the message, and nothing found in the page's data. ──
    const TWO = "Two values in your prompt were hidden from the AI (acme.ticket, a secret Mandu already knows).";
    const turn = await waitFor("the note under the masked message", async () => (await story()).find((t) => t.promptNote?.lines.includes(TWO)));
    const turns = await story();
    assert.equal(turns.at(-1)!.id, turn.id, "the note sits under the message it is about, the newest");
    assert.deepEqual(turns.at(-2)!.promptNote?.lines, ["One value in your prompt was hidden from the AI (acme.ticket)."], "the first message, resent after the choice, is hidden now too");
    noFound("the agent page", JSON.stringify(await agentPage()), [TICKET, KEY, "$MDU:"]);
    noFound("/api/home", JSON.stringify((await call("GET", "home", undefined, {})).body), [TICKET, OTHER_TICKET, KEY]);
    const ticketItem = turn.promptNote!.items.find((i) => i.category === "acme.ticket")!;
    const keyItem = turn.promptNote!.items.find((i) => i.category === "secret.registered")!;
    assert.equal(ticketItem.canShow, true);
    assert.equal(keyItem.canShow, false);
    assert.equal((await call("POST", "prompt-filters/reveal", { session, eventId: ticketItem.eventId, index: ticketItem.index }, { "Content-Type": "application/json" })).status, 403, "never without the admin session");
    const shown = await call("POST", "prompt-filters/reveal", { session, eventId: ticketItem.eventId, index: ticketItem.index });
    assert.equal(shown.status, 200, JSON.stringify(shown.body));
    assert.equal(shown.body["original"], TICKET);
    const keyShown = await call("POST", "prompt-filters/reveal", { session, eventId: keyItem.eventId, index: keyItem.index });
    assert.equal(keyShown.status, 409, JSON.stringify(keyShown.body));
    assert.ok(!JSON.stringify(keyShown.body).includes(KEY));

    // ── Let it through, once, from the note: the message's resend carries it. ──
    assert.equal(ticketItem.canLetOnce, true);
    const let1 = await call("POST", "prompt-filters/let-through", { session, eventId: ticketItem.eventId, index: ticketItem.index, scope: "once" });
    assert.equal(let1.status, 200, JSON.stringify(let1.body));
    assert.equal((await say("and now?")).status, 200);
    assert.ok(sent().at(-1)!.includes(`deploy ${TICKET} with $MDU:`), `the resend carries the ticket as written, the key still masked: ${sent().at(-1)}`);
    const later = await waitFor("the next message in the story", async () => {
      const s = await story();
      return s.some((t) => t.prompt === "and now?") ? s : undefined;
    });
    assert.ok(later.some((t) => t.promptNote?.lines.includes("One value in your prompt went to the AI as you wrote it: you let it through in this message (acme.ticket).")),
      JSON.stringify(later.map((t) => t.promptNote?.lines)));

    // ── An exception (a relaxation): asked first, then in force next. ──
    const exc = { op: "add-prompt-exception", category: "acme.ticket", match: "ACME-2*" };
    const q = await call("POST", "policy/prompt-filters/change", { edit: exc });
    assert.equal(q.status, 200, JSON.stringify(q.body));
    assert.equal(q.body["confirm"], true, JSON.stringify(q.body));
    assert.equal((await say(`ticket ${TICKET} please`)).status, 200);
    assert.ok(!sent().at(-1)!.includes(`ticket ${TICKET} please`), "nothing changed before the person agreed");
    const agreed = await call("POST", "policy/prompt-filters/change", { edit: exc, expected: q.body["expected"] });
    assert.equal(agreed.body["applied"], true, JSON.stringify(agreed.body));
    assert.equal((await say(`tickets ${TICKET} and ${OTHER_TICKET}`)).status, 200);
    const afterExc = sent().at(-1)!;
    assert.ok(afterExc.includes(`tickets ${TICKET} and $MDU:`), `the matching ticket goes as written, the other masked: ${afterExc}`);
    assert.ok(afterExc.includes(`see ${TICKET} today`) && afterExc.includes(`ticket ${TICKET} please`), "the earlier messages go as written now");
    assert.ok(!afterExc.includes(OTHER_TICKET));

    // ── Plan 15 §13.7: the resends with nothing found clear their notes. ──
    const cleared = await waitFor("the excepted messages' notes to clear", async () => {
      const s = await story();
      const of = (re: RegExp) => s.find((t) => typeof t.prompt === "string" && re.test(t.prompt));
      const see = of(/^see .* today$/), please = of(/^ticket .* please$/);
      return see && please && see.promptNote === null && please.promptNote === null ? s : undefined;
    });
    const deploy = cleared.find((t) => typeof t.prompt === "string" && t.prompt.startsWith("deploy "));
    assert.deepEqual(deploy?.promptNote?.lines, ["One value in your prompt was hidden from the AI (a secret Mandu already knows)."], JSON.stringify(cleared.map((t) => [t.prompt, t.promptNote?.lines])));
    const events = (await human.events(session)) as unknown as Array<{ kind: string; emitter: string; promptFilter?: { origin: string; agent: string; findings: unknown[]; turn?: string } }>;
    const clearing = events.filter((e) => e.kind === "prompt_filter" && e.promptFilter?.origin === "human" && e.promptFilter.findings.length === 0);
    assert.ok(clearing.length >= 2, `the openai-proxy recorded each excepted message's resend with no findings: ${clearing.length}`);
    for (const e of clearing) {
      assert.equal(e.emitter, "openai-proxy");
      assert.equal(e.promptFilter!.agent, "codex");
      assert.match(e.promptFilter!.turn ?? "", /^[0-9a-f]{32}$/, "under the message's own reference, so the note it clears is its own");
      assert.ok(!JSON.stringify(e).includes(TICKET), "a clearing event carries no value");
    }

    // ── The invariant: the registered key never reached the model raw. ──
    for (const b of sent()) assert.ok(!b.includes(KEY), "CONFIDENTIALITY VIOLATION: the registered key reached the model raw");
    noFound("/api/home (end)", JSON.stringify((await call("GET", "home", undefined, {})).body), [KEY, OTHER_TICKET]);
  } finally {
    await server.close?.();
    wired.close();
    await proxy.close();
    await fake.close();
    data.close();
    human.close();
    await arbiter.close();
    setAdminLayer(NO_ADMIN_LAYER);
  }
});
