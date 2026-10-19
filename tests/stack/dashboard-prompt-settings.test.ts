/**
 * dashboard-prompt-settings — plan 15 phase 4 on the PRODUCT page over the
 * PRODUCTION wiring (confidentiality-plan-15-prompt-filter.md §11 phase 4,
 * §13.7; dashboard.md §4.25y): a real ArbiterServer (data, human and admin
 * sockets) with a file-backed law, the person's pack and an administrator's
 * lock, the REAL anthropic-proxy over HTTP on its two production clients, a
 * scripted fake model, and the real DashboardServer over
 * `makeApprovalsArbiter(dataSock, admin)` and `ArbiterEventSource` (CONTRIBUTING.md:
 * the parity test builds the production wiring).
 *
 * Proves, end to end:
 *   - Settings › Prompt filters (GET /api/policy/prompt-filters) lists the
 *     kinds in plain words with the administrator's lock and its file, only
 *     with the CSRF header and the admin session;
 *   - a choice made there (a kind raised from "Remove it" to "Hide it") is a
 *     tightening applied at once, and the NEXT request through the real proxy
 *     carries the span masked instead of removed;
 *   - an exception added there is a relaxation: answered with a question and
 *     applied only when resent with what was shown; the next request carries
 *     the matching span as written, a non-matching one still masked; the
 *     earlier messages it now lets through lose their notes (the proxy
 *     records their resend with no findings, plan 15 §13.7);
 *   - the exception's pattern is not on the data socket (`promptFilters`
 *     lists it bare, `promptExceptions` is refused there) and not in History
 *     read without the admin session (plan 15 §13.7 item 4);
 *   - a change the administrator locked is refused, naming who locked it;
 *   - the agent page's note under the message says what was hidden, in plain
 *     words; "Show what was hidden" answers the original on demand (and a
 *     registered secret never); "Let it through" from the note makes that
 *     message's resend carry the span as written;
 *   - no found value and no registered secret appear in /api/home, nor in the
 *     agent page's data before the person let the span through, and the
 *     registered key never reaches the fake model raw.
 *
 * The Codex twin (the real openai-proxy, the Responses wire) is
 * dashboard-prompt-settings-codex.test.ts.
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
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { startScriptedAnthropic } from "../lib/fake-anthropic.js";
import { humanSockIn } from "../lib/human-plane.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // the confidentiality axis the prompt filter serves; integrity off

const dirs: string[] = [];
after(() => {
  setAdminLayer(NO_ADMIN_LAYER);
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

const KEY = "sk-live-DashSettingsCanary4Kp8Vb2Nq6";
const TICKET = "ACME-20417";
const OTHER_TICKET = "ACME-99031";
const LOCK_FILE = "10-org.yaml";

function post(port: number, body: unknown, session: string): Promise<{ status: number; body: string }> {
  const data = Buffer.from(JSON.stringify(body));
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: "127.0.0.1", port, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json", "content-length": String(data.length), "x-mandu-session-id": session } },
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

test("Settings › Prompt filters and the note under the message over the real arbiter and proxy: a choice and an exception apply on the next request, a lock refuses, the note lets a span through (secrets axes)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-pf-settings-"));
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
  const session = `dash-settings-${process.pid}`;
  await data.setSessionSpec({ sessionKey: session, spec: "claude-code" });
  const fake = await startScriptedAnthropic({ script: [], fallbackText: "ok" });
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(data, human), upstreamOrigin: fake.origin, sessionKey: session, log: () => {} });
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
  const ask = (text: string, history: string[] = []) => post(proxyPort, {
    model: "claude-sonnet-4-5", stream: true, max_tokens: 64,
    tools: [{ name: "Read", input_schema: { type: "object" } }],
    messages: [
      ...history.flatMap((h) => [{ role: "user", content: [{ type: "text", text: h }] }, { role: "assistant", content: [{ type: "text", text: "ok" }] }]),
      { role: "user", content: [{ type: "text", text }] },
    ],
  }, session);
  // One conversation, resent whole with each request as the agents do.
  const convo: string[] = [];
  const say = async (text: string) => {
    const r = await ask(text, [...convo]);
    convo.push(text);
    return r;
  };
  const sent = () => fake.requests.filter((q) => q.url.includes("/v1/messages") && q.body.includes('"tools"')).map((q) => q.body);
  const noFound = (what: string, json: string, values: string[]) => {
    for (const v of values) assert.ok(!json.includes(v), `${what} carries a found value (${v})`);
  };
  try {
    // ── The section: plain words, the lock and its file, behind the gates. ──
    assert.equal((await call("GET", "policy/prompt-filters", undefined, {})).status, 403, "no CSRF header, no admin session");
    const listed = await call("GET", "policy/prompt-filters");
    assert.equal(listed.status, 200, JSON.stringify(listed.body));
    const kinds = listed.body["settings"].kinds as Array<{ category: string; action: string; who: string; locked: boolean; choices: Array<{ action: string }> }>;
    const ticketKind = kinds.find((k) => k.category === "acme.ticket");
    assert.ok(ticketKind, `the pack's kind is listed: ${JSON.stringify(kinds.map((k) => k.category))}`);
    assert.equal(ticketKind!.action, "redact", "an organization's kind starts at the fallback");
    const shape = kinds.find((k) => k.category === "secret.shape")!;
    assert.equal(shape.locked, true);
    assert.equal(shape.who, `Locked by your administrator (${LOCK_FILE}).`);
    assert.ok(!shape.choices.some((c) => c.action === "log"), "never weaker than the lock");

    // ── Before: the ticket is removed. ──
    assert.equal((await say(`see ${TICKET} today`)).status, 200);
    assert.ok(sent().at(-1)!.includes("see [redacted: acme.ticket] today"), sent().at(-1));

    // ── A choice: Hide it (a tightening), applied at once, in force next. ──
    const hide = await call("POST", "policy/prompt-filters/change", { edit: { op: "set-prompt-action", category: "acme.ticket", action: "mask" } });
    assert.equal(hide.status, 200, JSON.stringify(hide.body));
    assert.equal(hide.body["applied"], true, JSON.stringify(hide.body));
    const masked = `deploy ${TICKET} with ${KEY}`;
    assert.equal((await say(masked)).status, 200);
    const afterHide = sent().at(-1)!;
    assert.match(afterHide, /deploy \$MDU:[A-Za-z_][A-Za-z0-9_]*\[[0-9a-f]{4,8}\] with \$MDU:/, `the next request carries the ticket masked: ${afterHide}`);
    assert.ok(!afterHide.includes(TICKET), "the ticket is not sent");

    // ── A locked kind is refused, naming who locked it. ──
    const locked = await call("POST", "policy/prompt-filters/change", { edit: { op: "set-prompt-action", category: "secret.shape", action: "log" } });
    assert.notEqual(locked.body["applied"], true, JSON.stringify(locked.body));
    assert.match(JSON.stringify(locked.body), new RegExp(`set by your administrator \\([^)]*${LOCK_FILE.replace(".", "\\.")}\\)`));

    // ── The note under the message, and nothing found in the page's data. ──
    const TWO = "Two values in your prompt were hidden from the AI (acme.ticket, a secret Mandu already knows).";
    const page = await waitFor("the note under the masked message", async () => {
      const r = await call("GET", `home/agent?session=${encodeURIComponent(session)}`, undefined, {});
      const turn = (r.body["story"] ?? []).find((t: { promptNote: { lines: string[] } | null }) => t.promptNote?.lines.includes(TWO));
      return turn ? { body: r.body, turn } : undefined;
    });
    const note = page.turn.promptNote as { lines: string[]; items: Array<{ eventId: string; index: number; category: string; canShow: boolean; canLetOnce: boolean }> };
    const story = page.body["story"] as Array<{ id: string; promptNote: { lines: string[] } | null }>;
    assert.equal(story.at(-1)!.id, page.turn.id, "the note sits under the message it is about, the newest");
    // The first message, resent after the choice, is hidden now too: a note
    // tells where the message stands (its newest record).
    assert.deepEqual(story.at(-2)!.promptNote?.lines, ["One value in your prompt was hidden from the AI (acme.ticket)."]);
    noFound("the agent page", JSON.stringify(page.body), [TICKET, KEY, "$MDU:"]);
    const home = await call("GET", "home", undefined, {});
    noFound("/api/home", JSON.stringify(home.body), [TICKET, OTHER_TICKET, KEY]);
    const ticketItem = note.items.find((i) => i.category === "acme.ticket")!;
    const keyItem = note.items.find((i) => i.category === "secret.registered")!;
    assert.equal(ticketItem.canShow, true);
    assert.equal(keyItem.canShow, false);
    // Show what was hidden: on demand, the human plane; a registered secret never.
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
    const resent = sent().at(-1)!;
    assert.ok(resent.includes(`deploy ${TICKET} with $MDU:`), `the resend carries the ticket as written, the key still masked: ${resent}`);
    // The story keeps going although an earlier message now goes in another
    // form (dual-lanes samePromptMessage), and its note says it was let through.
    const later = await waitFor("the next message in the story", async () => {
      const r = await call("GET", `home/agent?session=${encodeURIComponent(session)}`, undefined, {});
      const story = (r.body["story"] ?? []) as Array<{ prompt: string | null; promptNote: { lines: string[] } | null }>;
      return story.some((t) => t.prompt === "and now?") ? story : undefined;
    });
    assert.ok(later.some((t) => t.promptNote?.lines.includes("One value in your prompt went to the AI as you wrote it: you let it through in this message (acme.ticket).")),
      JSON.stringify(later.map((t) => t.promptNote?.lines)));

    // ── An exception (a relaxation): asked first, then in force next. ──
    const exc = { op: "add-prompt-exception", category: "acme.ticket", match: "ACME-2*" };
    const q = await call("POST", "policy/prompt-filters/change", { edit: exc });
    assert.equal(q.status, 200, JSON.stringify(q.body));
    assert.equal(q.body["confirm"], true, JSON.stringify(q.body));
    assert.ok(Array.isArray(q.body["rows"][0]), "the question's rows are parts");
    assert.equal((await say(`ticket ${TICKET} please`)).status, 200);
    assert.ok(!sent().at(-1)!.includes(`ticket ${TICKET} please`), "nothing changed before the person agreed");
    const agreed = await call("POST", "policy/prompt-filters/change", { edit: exc, expected: q.body["expected"] });
    assert.equal(agreed.status, 200, JSON.stringify(agreed.body));
    assert.equal(agreed.body["applied"], true, JSON.stringify(agreed.body));
    assert.equal((await say(`tickets ${TICKET} and ${OTHER_TICKET}`)).status, 200);
    const afterExc = sent().at(-1)!;
    assert.ok(afterExc.includes(`tickets ${TICKET} and $MDU:`), `the matching ticket goes as written, the other masked: ${afterExc}`);
    assert.ok(!afterExc.includes(OTHER_TICKET));
    // Plan 15 §13.7: the earlier messages the exception now lets through
    // were resent with nothing found; the proxy recorded that, so their
    // notes are gone (the newest record has no findings), while the message
    // still holding the registered key keeps its line.
    const clearedStory = await waitFor("the excepted messages' notes to clear", async () => {
      const r = await call("GET", `home/agent?session=${encodeURIComponent(session)}`, undefined, {});
      const story = (r.body["story"] ?? []) as Array<{ prompt: string | null; promptNote: { lines: string[] } | null }>;
      const of = (re: RegExp) => story.find((t) => typeof t.prompt === "string" && re.test(t.prompt));
      const see = of(/^see .* today$/), please = of(/^ticket .* please$/);
      return see && please && see.promptNote === null && please.promptNote === null ? story : undefined;
    });
    const deploy = clearedStory.find((t) => typeof t.prompt === "string" && t.prompt.startsWith("deploy "));
    assert.deepEqual(deploy?.promptNote?.lines, ["One value in your prompt was hidden from the AI (a secret Mandu already knows)."], JSON.stringify(clearedStory.map((t) => [t.prompt, t.promptNote?.lines])));
    const clearEvents = (await human.events(session) as unknown as Array<{ kind: string; promptFilter?: { origin: string; findings: unknown[] } }>).filter((e: { kind: string; promptFilter?: { origin: string; findings: unknown[] } }) => e.kind === "prompt_filter" && e.promptFilter?.origin === "human" && e.promptFilter.findings.length === 0);
    assert.ok(clearEvents.length >= 2, `the proxy recorded each excepted message's resend with no findings: ${clearEvents.length}`);
    for (const e of clearEvents) assert.ok(!JSON.stringify(e).includes(TICKET), "a clearing event carries no value");
    const listedAfter = await call("GET", "policy/prompt-filters");
    assert.ok(listedAfter.body["settings"].exceptions.some((x: { match: string; removable: boolean }) => x.match === "ACME-2*" && x.removable));
    // Plan 15 §13.7 item 4: the exception's pattern stays off the data
    // socket and out of History read without the admin session.
    assert.ok(!JSON.stringify(await data.promptFilters()).includes("ACME-2*"), "the data plane lists the exception without its pattern");
    await assert.rejects(() => data.promptExceptions(), /human-plane/);
    const historyOpen = await call("GET", "policy/changes", undefined, {});
    assert.equal(historyOpen.status, 200);
    assert.ok(!JSON.stringify(historyOpen.body).includes("ACME-2*") && historyOpen.body["patternsHidden"] === true, JSON.stringify(historyOpen.body));
    assert.ok(JSON.stringify((await call("GET", "policy/changes")).body).includes("ACME-2*"), "the admin's History shows it");

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
