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
 *     carries the span masked instead of removed. It is made on the served
 *     Settings page with the keyboard, which waits for Enter (dashboard.md
 *     §4.25 *A menu that saves at once waits for Enter from the keyboard*):
 *     an Up arrow alone, then Escape, leaves the kind removed in the
 *     arbiter; an Up arrow and Enter makes it, the focus back on the menu;
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
 * And Try a message (dashboard.md §4.25y), on the same production wiring
 * without a proxy: an email address and a registered secret's value in a
 * tried message are marked; after an exception added on the same page the
 * address is not; the try mints no symbol and writes no event (the
 * confidentiality oracle for a dry run: no record may come to hold the
 * typed secret); without the admin session it is refused.
 *
 * And an exception added on the served Settings page (dashboard.md §4.25n):
 * the arbiter's question is asked on the page, in the form above its
 * button, never in a browser dialog; Cancel leaves the arbiter's list as it
 * was, Apply anyway adds the exception with its Undo, and the registered
 * secret is on no page and in no answer.
 *
 * And Try a message follows the card on the served page (dashboard.md
 * §4.25y *The answer follows the card*): after Try it marks an address, an
 * exception added through the page's form draws the answer again for the
 * tried text, the address unmarked, with no second press; no symbol and no
 * registered secret on the page.
 *
 * The Codex twin (the real openai-proxy, the Responses wire) is
 * dashboard-prompt-settings-codex.test.ts.
 *
 * Axes: secrets (stated; the arbiter's confidentiality pinned ON).
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
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
import { ADMIN_COOKIE, ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
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
    const r = await pageFetch(`http://127.0.0.1:${port}/api/${path}`, { method, headers, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
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

    // ── A choice: Hide it (a tightening), made on the Settings page with
    // the keyboard, applied on Enter, in force next. ──
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const ticketMenu = (d: any) => d.querySelector('#settings-prompt-kinds .prompt-kind[data-category="acme.ticket"] select.prompt-action');
    const ticketAction = async () => ((await call("GET", "policy/prompt-filters")).body["settings"].kinds as Array<{ category: string; action: string }>).find((k) => k.category === "acme.ticket")?.action;
    const pageTexts: string[] = [];
    await servedProductPage(`http://127.0.0.1:${port}`, "/settings", (d) => !!ticketMenu(d), async (d) => {
      const win = d.defaultView;
      const key = (k: string) => ticketMenu(d).dispatchEvent(new win.KeyboardEvent("keydown", { key: k, bubbles: true, cancelable: true }));
      const up = () => {
        const sel = ticketMenu(d);
        sel.focus();
        key("ArrowUp");
        sel.value = "mask";
        sel.dispatchEvent(new win.Event("change", { bubbles: true }));
      };
      assert.equal(ticketMenu(d).value, "redact");
      up();
      assert.equal(d.querySelector('.prompt-kind[data-category="acme.ticket"] .menu-wait').textContent, "Press Enter to change it to Hide it, or Escape to keep Remove it.");
      await new Promise((r) => setTimeout(r, 300));
      assert.equal(await ticketAction(), "redact", "an Up arrow alone changes nothing");
      key("Escape");
      assert.equal(ticketMenu(d).value, "redact", "Escape: the choice in force");
      assert.equal(await ticketAction(), "redact");
      up();
      const sel = ticketMenu(d);
      key("Enter");
      await waitWhile(() => ticketMenu(d) === sel);
      assert.equal(ticketMenu(d).value, "mask");
      assert.equal(d.activeElement, ticketMenu(d), "the focus back on the kind's menu, drawn again");
      assert.match(d.getElementById("prompt-notice").textContent, /: Hide it\. It applies to your next message\./);
      pageTexts.push(d.body.textContent ?? "");
    }, { headers: { Cookie: ADMIN_COOKIE } });
    assert.equal(await ticketAction(), "mask", "Enter made it");
    noFound("the Settings page", pageTexts.join("\n"), [KEY, TICKET]);
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
    // Approvals › Rule changes names the card the change was made on (dashboard.md §4.25i).
    const sentences = ((await call("GET", "policy/changes")).body["changes"] as Array<{ sentence: string }>).map((c) => c.sentence);
    assert.ok(sentences.includes("You changed your prompt filters in Settings"), JSON.stringify(sentences));
    assert.ok(!sentences.some((x) => /models/.test(x)), `no Prompt filters change says "models": ${JSON.stringify(sentences)}`);

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

/** Every line of every file under `dir` (the arbiter's event logs). */
function eventLines(dir: string): number {
  if (!existsSync(dir)) return 0;
  let n = 0;
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    n += statSync(p).isDirectory() ? eventLines(p) : readFileSync(p, "utf8").split("\n").filter((l) => l.trim() !== "").length;
  }
  return n;
}

test("Settings › Prompt filters › Try a message over the real arbiter: an address and a registered secret are marked, an exception unmarks the address, nothing is minted or recorded (secrets axes)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-pf-try-"));
  dirs.push(dir);
  const dataSock = join(dir, "arbiter.sock");
  const adminSock = join(dir, "admin.sock");
  const humanSock = humanSockIn(dir);
  const packs = join(dir, "prompt-filters");
  mkdirSync(packs);
  writeFileSync(join(packs, "mine.yaml"), "pack: mine\nversion: 1\npatterns:\n  - id: email\n    category: pii.email\n    regex: '[A-Za-z0-9._-]+@[A-Za-z0-9.-]+\\.[a-z]{2,}'\n");
  const policyPath = join(dir, "policy.yaml");
  // Hide it: a real run would mint a symbol for the address, so the count
  // below would see one (the positive control at the end proves it).
  writeFileSync(policyPath, "version: 1\nprompt_filters:\n  filters:\n    mine: on\n  actions:\n    pii.email: mask\n");
  const dbPath = join(dir, "mandu.db");
  const eventDir = join(dir, "events");
  const arbiter = new ArbiterServer({
    socketPath: dataSock, adminSocketPath: adminSock, humanSocketPath: humanSock, dbPath, eventDir,
    policyPath, policyPollMs: 0, integrity: false, confidentiality: true, log: () => {},
    promptPackDir: packs, adminPromptPackDir: null, adminPolicyDir: null, packDir: null, packKeysDir: join(dir, "keys"),
  });
  await arbiter.listen();
  const data = new ArbiterClient(dataSock);
  await data.connect();
  const human = new ArbiterClient(humanSock);
  await human.connect();
  await data.registerEnvSecrets({ vars: [{ name: "STRIPE_API_KEY", value: KEY }] });
  const wired = await makeApprovalsArbiter(dataSock, () => ({ socketPath: adminSock }));
  assert.ok(wired?.policyDoc?.filterPromptDryRun, "the production adapter forwards the dry run");
  const source = new ArbiterEventSource({ socketPath: dataSock, humanSocketPath: humanSock });
  const server = new DashboardServer({ source, policyDocArbiter: wired.policyDoc, approvalsArbiter: wired.arbiter, log: () => {}, ...ADMIN_OPTS });
  const port = await server.listen(0);
  const call = async (path: string, body: unknown, headers: Record<string, string> = { ...CSRF_ADMIN, "Content-Type": "application/json" }) => {
    const r = await pageFetch(`http://127.0.0.1:${port}/api/${path}`, { method: "POST", headers, body: JSON.stringify(body) });
    return { status: r.status, body: (await r.json().catch(() => ({}))) as Record<string, any> };
  };
  const symbols = (): number => {
    const db = new DatabaseSync(dbPath, { readOnly: true });
    try {
      return Number((db.prepare("SELECT COUNT(*) AS n FROM symbols").get() as { n: number | bigint }).n);
    } finally {
      db.close();
    }
  };
  const ADDRESS = "ann@example.com";
  const text = `mail ${ADDRESS} the key ${KEY} please`;
  const at = (v: string) => ({ start: text.indexOf(v), end: text.indexOf(v) + v.length });
  try {
    // ── Refused without the admin session; nothing reaches the arbiter. ──
    const before = { symbols: symbols(), events: eventLines(eventDir), sessions: (await human.sessions()).length };
    const out = await call("policy/prompt-filters/try", { text }, { "X-Mandu-Control": "1", "Content-Type": "application/json" });
    assert.equal(out.status, 403, JSON.stringify(out.body));

    // ── The address and the registered secret are marked, in the card's words. ──
    const r = await call("policy/prompt-filters/try", { text, origin: "harness" });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(r.body["enforcing"], true);
    const found = r.body["findings"] as Array<{ start: number; end: number; category: string; name: string; action: string }>;
    const email = found.find((f) => f.category === "pii.email");
    assert.deepEqual(email && { start: email.start, end: email.end, name: email.name }, { ...at(ADDRESS), name: "An email address" }, JSON.stringify(found));
    assert.equal(email!.action, "mask", "the kind's choice");
    const key = found.find((f) => f.category.startsWith("secret.registered"));
    assert.deepEqual(key && { start: key.start, end: key.end, name: key.name, action: key.action }, { ...at(KEY), name: "A secret Mandu already knows", action: "mask" }, JSON.stringify(found));
    const answer = JSON.stringify(r.body);
    assert.ok(!answer.includes("$MDU:"), "no symbol in the answer");
    assert.ok(!answer.includes(KEY) && !answer.includes(ADDRESS), "spans of the typed text, never the text itself");

    // ── The oracle: a dry run mints nothing and records nothing. ──
    assert.deepEqual({ symbols: symbols(), events: eventLines(eventDir), sessions: (await human.sessions()).length }, before,
      "CONFIDENTIALITY: a try created a symbol or a record that could hold the typed secret");

    // ── An exception added on the same page lets the address through. ──
    const exc = { op: "add-prompt-exception", category: "pii.email", match: "*@example.com" };
    const q = await call("policy/prompt-filters/change", { edit: exc });
    assert.equal(q.body["confirm"], true, JSON.stringify(q.body));
    const agreed = await call("policy/prompt-filters/change", { edit: exc, expected: q.body["expected"] });
    assert.equal(agreed.body["applied"], true, JSON.stringify(agreed.body));
    const again = await call("policy/prompt-filters/try", { text });
    assert.equal(again.status, 200, JSON.stringify(again.body));
    const left = again.body["findings"] as Array<{ category: string; start: number; end: number }>;
    assert.ok(!left.some((f) => f.category === "pii.email"), `the excepted address is no longer marked: ${JSON.stringify(left)}`);
    assert.ok(left.some((f) => f.category.startsWith("secret.registered") && f.start === at(KEY).start), "the registered secret still is");
    assert.equal(symbols(), before.symbols, "still nothing minted");

    // ── The positive control: the same filter run for real mints, so the
    // count above would have seen a try that did. ──
    await data.filterPrompt({ agent: "control", segments: [{ id: "c", origin: "human", text: "mail bob@corp.test" }] });
    assert.ok(symbols() > before.symbols, "a real run of the filter mints a symbol the count sees");
  } finally {
    await server.close?.();
    wired.close();
    data.close();
    human.close();
    await arbiter.close();
  }
});

test("Settings › Prompt filters over the real arbiter: an exception added on the page asks on the page; Cancel leaves the arbiter's list as it was, Apply anyway adds it with its Undo; no secret on the page (secrets axes)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-pf-ask-"));
  dirs.push(dir);
  const dataSock = join(dir, "arbiter.sock");
  const adminSock = join(dir, "admin.sock");
  const humanSock = humanSockIn(dir);
  const packs = join(dir, "prompt-filters");
  mkdirSync(packs);
  writeFileSync(join(packs, "mine.yaml"), "pack: mine\nversion: 1\npatterns:\n  - id: email\n    category: pii.email\n    regex: '[A-Za-z0-9._-]+@[A-Za-z0-9.-]+\\.[a-z]{2,}'\n");
  const policyPath = join(dir, "policy.yaml");
  writeFileSync(policyPath, "version: 1\nprompt_filters:\n  filters:\n    mine: on\n  actions:\n    pii.email: mask\n");
  const arbiter = new ArbiterServer({
    socketPath: dataSock, adminSocketPath: adminSock, humanSocketPath: humanSock, dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"),
    policyPath, policyPollMs: 0, integrity: false, confidentiality: true, log: () => {},
    promptPackDir: packs, adminPromptPackDir: null, adminPolicyDir: null, packDir: null, packKeysDir: join(dir, "keys"),
  });
  await arbiter.listen();
  const data = new ArbiterClient(dataSock);
  await data.connect();
  await data.registerEnvSecrets({ vars: [{ name: "STRIPE_API_KEY", value: KEY }] });
  const wired = await makeApprovalsArbiter(dataSock, () => ({ socketPath: adminSock }));
  assert.ok(wired?.policyDoc);
  const source = new ArbiterEventSource({ socketPath: dataSock, humanSocketPath: humanSock });
  const server = new DashboardServer({ source, policyDocArbiter: wired.policyDoc, approvalsArbiter: wired.arbiter, log: () => {}, ...ADMIN_OPTS });
  const port = await server.listen(0);
  const MATCH = "*@example.com";
  const answers: string[] = [];
  const exceptions = async (): Promise<string[]> => {
    const r = await pageFetch(`http://127.0.0.1:${port}/api/policy/prompt-filters`, { headers: CSRF_ADMIN });
    const text = await r.text();
    answers.push(text);
    return (JSON.parse(text).settings.exceptions as Array<{ match: string }>).map((x) => x.match);
  };
  try {
    assert.deepEqual(await exceptions(), []);
    const pages: string[] = [];
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    await servedProductPage(`http://127.0.0.1:${port}`, "/settings", (d: any) => !d.getElementById("prompt-exception-form").hidden && d.querySelectorAll("#prompt-exception-kind option").length > 0, async (d: any) => {
      const win = d.defaultView;
      win.confirm = () => { throw new Error("window.confirm called"); };
      const form = d.getElementById("prompt-exception-form");
      const match = d.getElementById("prompt-exception-match");
      const add = d.getElementById("prompt-exception-add");
      const asked = () => form.querySelector(".ask-in-place");
      const submit = () => {
        add.focus();
        form.dispatchEvent(new win.Event("submit", { cancelable: true }));
      };
      d.getElementById("prompt-exception-kind").value = "pii.email";
      match.value = MATCH;
      submit();
      // The arbiter says it lets more reach the AI: asked in the form, above
      // its button (dashboard.md §4.25n), its sentence holding the focus.
      await waitWhile(() => !asked());
      assert.equal(asked().nextElementSibling, form.querySelector(".form-actions"));
      assert.ok(asked().querySelector(".ask-in-place-words").textContent.includes(MATCH), asked().textContent);
      assert.equal(asked().querySelector(".ask-in-place-k")?.textContent, "This changes what Mandu protects:");
      assert.ok(asked().querySelectorAll(".ask-in-place-list li").length > 0, "what it opens, as a list");
      assert.equal(d.activeElement, asked().querySelector(".ask-in-place-words"), "the sentence, never Apply anyway");
      // Cancel: nothing is sent; the arbiter's list is unchanged.
      [...asked().querySelectorAll("button")].find((b: { textContent: string }) => b.textContent === "Cancel").click();
      assert.equal(asked(), null);
      assert.equal(d.activeElement, add, "the focus back on Add exception");
      assert.equal(match.value, MATCH, "what was typed stays");
      await new Promise((r) => setTimeout(r, 200));
      assert.deepEqual(await exceptions(), [], "Cancel added nothing");
      // Asked again, Apply anyway: added, with its Undo.
      submit();
      await waitWhile(() => !asked());
      const yes = asked().querySelector(".ask-in-place-yes");
      assert.equal(yes.textContent, "Apply anyway");
      yes.focus();
      yes.click();
      // The notice, then the list read again and the box emptied.
      await waitWhile(() => !d.getElementById("prompt-notice").textContent || match.value !== "");
      assert.match(d.getElementById("prompt-notice").textContent, /^Added the exception for \*@example\.com\. It applies to your next message\./);
      assert.equal(asked(), null);
      assert.equal(match.value, "", "the box is empty again");
      assert.deepEqual(await exceptions(), [MATCH], "the arbiter lists the exception");
      const undo = [...d.querySelectorAll("#prompt-notice button")].find((b: { textContent: string }) => b.textContent === "Undo");
      assert.ok(undo, "with its Undo");
      pages.push(d.body.textContent ?? "");
      undo.click();
      await waitWhile(() => d.getElementById("prompt-notice").textContent !== "Undone.");
      assert.deepEqual(await exceptions(), [], "Undo takes it back");
      pages.push(d.body.textContent ?? "");
    }, { headers: { Cookie: ADMIN_COOKIE } });
    // The oracle: the registered secret is on no page and in no answer.
    for (const text of [...pages, ...answers]) assert.ok(!text.includes(KEY), "CONFIDENTIALITY: the registered key reached the page");
  } finally {
    await server.close?.();
    wired.close();
    data.close();
    await arbiter.close();
  }
});

test("Settings › Prompt filters over the real arbiter: Try a message on the served page answers again after an exception added there, with no second press; no symbol and no secret on the page (secrets axes)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-pf-tryagain-"));
  dirs.push(dir);
  const dataSock = join(dir, "arbiter.sock");
  const adminSock = join(dir, "admin.sock");
  const humanSock = humanSockIn(dir);
  const packs = join(dir, "prompt-filters");
  mkdirSync(packs);
  writeFileSync(join(packs, "mine.yaml"), "pack: mine\nversion: 1\npatterns:\n  - id: email\n    category: pii.email\n    regex: '[A-Za-z0-9._-]+@[A-Za-z0-9.-]+\\.[a-z]{2,}'\n");
  const policyPath = join(dir, "policy.yaml");
  writeFileSync(policyPath, "version: 1\nprompt_filters:\n  filters:\n    mine: on\n  actions:\n    pii.email: mask\n");
  const arbiter = new ArbiterServer({
    socketPath: dataSock, adminSocketPath: adminSock, humanSocketPath: humanSock, dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"),
    policyPath, policyPollMs: 0, integrity: false, confidentiality: true, log: () => {},
    promptPackDir: packs, adminPromptPackDir: null, adminPolicyDir: null, packDir: null, packKeysDir: join(dir, "keys"),
  });
  await arbiter.listen();
  const data = new ArbiterClient(dataSock);
  await data.connect();
  await data.registerEnvSecrets({ vars: [{ name: "STRIPE_API_KEY", value: KEY }] });
  const wired = await makeApprovalsArbiter(dataSock, () => ({ socketPath: adminSock }));
  assert.ok(wired?.policyDoc?.filterPromptDryRun, "the production adapter forwards the dry run");
  const source = new ArbiterEventSource({ socketPath: dataSock, humanSocketPath: humanSock });
  const server = new DashboardServer({ source, policyDocArbiter: wired.policyDoc, approvalsArbiter: wired.arbiter, log: () => {}, ...ADMIN_OPTS });
  const port = await server.listen(0);
  const ADDRESS = "ann@example.com";
  const TRIED = `mail ${ADDRESS} today`;
  const pages: string[] = [];
  try {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    await servedProductPage(`http://127.0.0.1:${port}`, "/settings", (d: any) => !d.getElementById("settings-prompt-try").hidden && !d.getElementById("prompt-exception-form").hidden && d.querySelectorAll("#prompt-exception-kind option").length > 0, async (d: any) => {
      const win = d.defaultView;
      const answer = d.getElementById("prompt-try-answer");
      const marks = (): string[] => [...answer.querySelectorAll("mark")].map((m: { textContent: string }) => m.textContent);
      // Try it marks the address.
      d.getElementById("prompt-try-text").value = TRIED;
      d.getElementById("prompt-try-form").dispatchEvent(new win.Event("submit", { cancelable: true }));
      await waitWhile(() => answer.hidden);
      assert.deepEqual(marks(), [ADDRESS], answer.textContent);
      assert.match(answer.textContent, /An email address: hidden\./);
      assert.equal(answer.querySelector(".prompt-try-except"), null, "no exception in force yet");
      // The box is edited after the try; the answer stays about what was tried.
      d.getElementById("prompt-try-text").value = "something else";
      // The exception, added through the page's form: asked, then Apply anyway.
      const form = d.getElementById("prompt-exception-form");
      d.getElementById("prompt-exception-kind").value = "pii.email";
      d.getElementById("prompt-exception-match").value = "*@example.com";
      form.dispatchEvent(new win.Event("submit", { cancelable: true }));
      await waitWhile(() => !form.querySelector(".ask-in-place"));
      form.querySelector(".ask-in-place .ask-in-place-yes").click();
      await waitWhile(() => !d.getElementById("prompt-notice").textContent);
      assert.match(d.getElementById("prompt-notice").textContent, /^Added the exception for \*@example\.com\./);
      // With no second press, the answer is drawn again: the address unmarked.
      await waitWhile(() => !answer.querySelector(".prompt-try-except"));
      assert.deepEqual(marks(), [], answer.textContent);
      assert.match(answer.textContent, /^Nothing in it would be held or masked\.What matches one of your exceptions is not marked/);
      assert.equal(answer.querySelector(".prompt-try-stale"), null);
      assert.equal(d.getElementById("prompt-try-error").textContent, "");
      pages.push(d.body.innerHTML);
    }, { headers: { Cookie: ADMIN_COOKIE } });
    // The oracle: no symbol and no registered secret on the page.
    for (const html of pages) {
      assert.ok(!html.includes("$MDU"), "CONFIDENTIALITY: a symbol reached the page");
      assert.ok(!html.includes(KEY), "CONFIDENTIALITY: the registered key reached the page");
    }
  } finally {
    await server.close?.();
    wired.close();
    data.close();
    await arbiter.close();
  }
});
