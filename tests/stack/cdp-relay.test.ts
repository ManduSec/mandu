/**
 * cdp-relay — the DevTools relay's PRODUCTION wiring over a real arbiter
 * (docs/design/agents/devtools-relay.md §7): `new ArbiterClientAdapter(
 * new ArbiterClient(data), new ArbiterClient(human))`, exactly as
 * interceptors/cdp-relay/src/server-main.ts builds it, with a `.env` bound
 * by policy.yaml to `vercel.com` and `127.0.0.1`.
 *
 * Against the relay's fake Chrome (always runs): a registered value on the
 * page reaches the agent only as its placeholder (the real prompt filter);
 * the placeholder the agent types reaches a bound page as the real value and
 * an unbound one not at all (the real egress decision on the human socket);
 * the arbiter gone, the answer is withheld. A placeholder the real arbiter
 * never minted (a near-miss of the page's, a field the secret lacks) is
 * refused, never reaches Chrome, the agent is told with the page's own
 * placeholder named, and the stored trace says `unknown placeholder`.
 *
 * Against a real headless Chromium (self-SKIP without one; set
 * MANDU_TEST_CHROMIUM to its binary, or have Playwright's headless shell in
 * ~/.cache/ms-playwright): the same over a live page, and Chrome itself
 * holds the real value while the agent reads the placeholder (the two
 * views); and a placeholder typed a key at a time (browser-use's input,
 * devtools-relay.md §3.3) lands in a bound page's field as the real value
 * and in an unbound page's not at all, and a made-up one in neither: one
 * whose hex code the real arbiter never minted is refused on the key that
 * closes its code (`placeholderKnown`), one with a field the secret lacks
 * when its run ends, the agent's next input command told (§3.3); the live
 * expense-report step replayed on a real form as browser-use runs it (a
 * made-up hex placeholder, its fallback typing, then Submit): the form is
 * never sent with the field empty; a lookalike (a UUID for its code)
 * is refused on the very key that closes its code, so the agent's typing
 * fails before its next action, and the page gets none of it. Chromium runs with --no-sandbox: the
 * page is the test's own.
 *
 * Secrets axes, explicit.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import type { ChildProcess } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { READY, chromiumBinary, startChromium, stopChromium } from "../lib/chromium.js";
import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { ArbiterClientAdapter, type RealArbiterClient } from "../../interceptors/cdp-relay/src/arbiter-client.js";
import { CdpRelay } from "../../interceptors/cdp-relay/src/relay.js";
import { FakeChrome } from "../../interceptors/cdp-relay/test/fake-chrome.js";
import { stateAxes } from "../lib/axes.js";
import { browserStory } from "../../dashboard/src/view-model/browser-story.js";
import type { ManduEvent } from "../../dashboard/src/event-model.js";

stateAxes("secrets");

const KEY = "sk_live_51CdpRelayStackQz8Yv3kT9mN2";
const SESSION = "s-cdp-relay";

interface Stack {
  server: ArbiterServer;
  field: string;
  adapter: ArbiterClientAdapter;
  data: ArbiterClient;
  human: ArbiterClient;
  close(): Promise<void>;
}

async function stack(): Promise<Stack> {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-cdp-relay-"));
  const ws = join(tmp, "ws");
  mkdirSync(ws);
  const env = join(ws, ".env");
  writeFileSync(env, `STRIPE_KEY=${KEY}\n`);
  const policy = join(tmp, "policy.yaml");
  writeFileSync(policy, ["version: 1", "paths:", `  - path: ${env}`, "    level: no-model", "    bindings: [vercel.com, 127.0.0.1]", ""].join("\n"));
  const sock = join(tmp, "a.sock");
  const humanSock = join(tmp, "h", "h.sock");
  const server = new ArbiterServer({
    socketPath: sock, adminSocketPath: join(tmp, "admin.sock"), humanSocketPath: humanSock,
    dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), log: () => {},
    confidentiality: true, integrity: false, policyPath: policy, policyPollMs: 0,
  });
  await server.listen();
  // The type-level pin: the real class IS the relay's RealArbiterClient.
  const data: RealArbiterClient = new ArbiterClient(sock);
  const human: RealArbiterClient = new ArbiterClient(humanSock);
  await (data as unknown as ArbiterClient).connect();
  await (human as unknown as ArbiterClient).connect();
  const reg = await (human as unknown as ArbiterClient).registerSecret({ path: env, sessionKey: SESSION });
  assert.match(String(reg.symbol), /^\$MDU:/, JSON.stringify(reg));
  return {
    server,
    field: `${reg.symbol}.STRIPE_KEY`,
    adapter: new ArbiterClientAdapter(data, human),
    data: data as unknown as ArbiterClient,
    human: human as unknown as ArbiterClient,
    close: async () => {
      data.close();
      human.close();
      await server.close().catch(() => undefined);
      rmSync(tmp, { recursive: true, force: true });
    },
  };
}

/** A DevTools client over Node's built-in WebSocket. */
async function agent(wsUrl: string) {
  const ws = new WebSocket(wsUrl);
  await new Promise<void>((resolve, reject) => {
    ws.addEventListener("open", () => resolve(), { once: true });
    ws.addEventListener("error", () => reject(new Error(`no relay at ${wsUrl}`)), { once: true });
  });
  const waiting = new Map<number, (m: any) => void>();
  const all: any[] = [];
  ws.addEventListener("message", (ev) => {
    const m = JSON.parse(String(ev.data));
    all.push(m);
    if (typeof m.id === "number") waiting.get(m.id)?.(m);
  });
  let id = 1;
  return {
    all,
    send(method: string, params: Record<string, unknown> = {}): Promise<any> {
      const my = id++;
      return new Promise((resolve) => { waiting.set(my, resolve); ws.send(JSON.stringify({ id: my, method, params })); });
    },
    close: () => ws.close(),
  };
}

test("the production wiring over a real arbiter: the agent reads the placeholder, a bound page gets the value, an unbound one nothing, and a gone arbiter withholds", async () => {
  const s = await stack();
  const bound = new FakeChrome({ url: "https://vercel.com/settings/env", pageText: `Your key: ${KEY}` });
  const unbound = new FakeChrome({ url: "https://evil.example/collect", pageText: "nothing" });
  await bound.listen();
  await unbound.listen();
  const r1 = new CdpRelay({ upstream: bound.url, arbiter: s.adapter, session: SESSION });
  const r2 = new CdpRelay({ upstream: unbound.url, arbiter: s.adapter, session: SESSION });
  const a1 = await agent(`ws://${new URL((await r1.listen()).url).host}/devtools/page/PAGE1`);
  const a2 = await agent(`ws://${new URL((await r2.listen()).url).host}/devtools/page/PAGE1`);
  try {
    const read = await a1.send("Runtime.evaluate", { expression: "document.body.innerText", returnByValue: true });
    const text = String(read.result?.result?.value);
    assert.ok(!text.includes(KEY), `no raw value: ${text}`);
    assert.match(text, /^Your key: \$MDU:/, "the real filter put the placeholder in its place");

    const typed = await a1.send("Input.insertText", { text: s.field });
    assert.deepEqual(typed.result, {}, JSON.stringify(typed));
    assert.deepEqual(bound.typed, [KEY], "the bound page got the real value");

    const refused = await a2.send("Input.insertText", { text: s.field });
    assert.match(String(refused.error?.message), /evil\.example/, JSON.stringify(refused));
    assert.deepEqual(unbound.typed, []);
    assert.ok(!JSON.stringify(unbound.received).includes(KEY), "nothing raw reached the unbound page");
    assert.ok(!JSON.stringify([...a1.all, ...a2.all]).includes(KEY), "the agent never saw the value");

    // The trace, through the production adapter into the real event store,
    // as the session page reads it (dashboard browser-story.ts).
    await new Promise((r) => setTimeout(r, 200));
    const stored = await s.human.events(SESSION);
    assert.ok(!JSON.stringify(stored).includes(KEY), "no event carries the value");
    const story = browserStory(stored as unknown as ManduEvent[]);
    assert.ok(story, "the session page has an On web pages story");
    assert.deepEqual(story!.secrets, ["STRIPE_KEY"]);
    assert.deepEqual(story!.typed.map((t) => [t.outcome, t.site, t.secret]), [["filled", "vercel.com", "STRIPE_KEY"], ["refused", null, "STRIPE_KEY"]]);

    await s.server.close();
    const gone = await a1.send("Runtime.evaluate", { expression: "document.body.innerText", returnByValue: true });
    assert.match(String(gone.error?.message), /withheld/, JSON.stringify(gone));
  } finally {
    a1.close();
    a2.close();
    await r1.close();
    await r2.close();
    await bound.close();
    await unbound.close();
    await s.close();
  }
});

/** A placeholder the real arbiter never minted, one hash digit off `field`
 *  (the live demos' near-miss, devtools-relay.md §3.2). */
const nearMiss = (field: string): string => field.replace(/\[([0-9a-f]+)\]/, (_m, h: string) => `[${h.slice(0, -1)}${h.endsWith("0") ? "1" : "0"}]`);

test("the production wiring over a real arbiter: a placeholder it does not know is refused, never reaches Chrome, the agent is told with the one the page showed, and the trace says refused (unknown placeholder)", async () => {
  const s = await stack();
  const chrome = new FakeChrome({ url: "https://vercel.com/settings/env", pageText: `Your key: ${KEY}` });
  await chrome.listen();
  const relay = new CdpRelay({ upstream: chrome.url, arbiter: s.adapter, session: SESSION });
  const a = await agent(`ws://${new URL((await relay.listen()).url).host}/devtools/page/PAGE1`);
  try {
    const read = await a.send("Runtime.evaluate", { expression: "document.body.innerText", returnByValue: true });
    const shown = String(read.result?.result?.value).replace(/^Your key: /, "");
    assert.equal(shown, s.field, "the page showed the field's placeholder");
    for (const bad of [nearMiss(s.field), `${s.field}S`]) {
      assert.notEqual(bad, s.field);
      const t = await a.send("Input.insertText", { text: `STRIPE_KEY=${bad}` });
      assert.ok(String(t.error?.message).includes(`no such placeholder ${bad}: type the placeholder exactly as the page shows it`), JSON.stringify(t));
      assert.ok(String(t.error?.message).includes(`the pages showed ${s.field}`), "the one the page showed is named");
    }
    assert.deepEqual(chrome.typed, [], "nothing was typed");
    assert.ok(!chrome.received.some((m) => m["method"] === "Input.insertText" || m["method"] === "Runtime.callFunctionOn"), "no insert reached Chrome");
    assert.ok(!JSON.stringify(chrome.received).includes("$MDU:"), "no placeholder literal reached Chrome");
    // Typed as the page shows it, it goes in (the real decision, unchanged).
    assert.deepEqual((await a.send("Input.insertText", { text: s.field })).result, {});
    assert.deepEqual(chrome.typed, [KEY]);
    assert.ok(!JSON.stringify(a.all).includes(KEY), "the agent never saw the value");

    await new Promise((r) => setTimeout(r, 200));
    const stored = (await s.human.events(SESSION)) as unknown as Array<Record<string, unknown>>;
    const typing = stored.filter((e) => e["kind"] === "browser_action" && (e["action"] === "refused" || e["action"] === "released"));
    assert.deepEqual(typing.map((e) => [e["action"], e["reason"]]), [["refused", "unknown placeholder"], ["refused", "unknown placeholder"], ["released", undefined]]);
    const story = browserStory(stored as unknown as ManduEvent[]);
    assert.deepEqual(story!.typed.map((t) => [t.outcome, t.site]), [["unknown", null], ["filled", "vercel.com"]], "the session page tells the unknown ones apart");
    assert.equal(story!.typed[0]!.count, 2);
    assert.ok(!JSON.stringify(story).includes("$MDU:"));
  } finally {
    a.close();
    await relay.close();
    await chrome.close();
    await s.close();
  }
});

const BIN = chromiumBinary();

test("a real headless Chromium: the agent reads and types placeholders, Chrome holds the real value", { skip: BIN === null ? "no headless Chromium (MANDU_TEST_CHROMIUM)" : false }, async () => {
  const s = await stack();
  const page: Server = createServer((_q, res) => {
    res.writeHead(200, { "content-type": "text/html" });
    res.end(`<html><head><title>Keys</title></head><body><p>Secret key ${KEY}</p><input id="f"></body></html>`);
  });
  await new Promise<void>((resolve) => page.listen(0, "127.0.0.1", () => resolve()));
  const pagePort = (page.address() as AddressInfo).port;
  const profile = mkdtempSync(join(tmpdir(), "mandu-cdp-chromium-"));
  let chrome: ChildProcess | null = null;
  let relay: CdpRelay | null = null;
  let a: Awaited<ReturnType<typeof agent>> | null = null;
  let direct: WebSocket | null = null;
  try {
    const started = await startChromium(BIN!, profile, `http://127.0.0.1:${pagePort}/`);
    chrome = started.proc;
    const port = started.port;
    relay = new CdpRelay({ upstream: `http://127.0.0.1:${port}`, arbiter: s.adapter, session: SESSION });
    const at = await relay.listen();
    let target: any = null;
    for (let i = 0; i < 50 && target === null; i++) {
      const list = (await (await fetch(`${at.url}/json/list`)).json()) as any[];
      target = list.find((p) => p.type === "page" && String(p.url).includes(`:${pagePort}`)) ?? null;
      if (target === null) await new Promise((r) => setTimeout(r, 100));
    }
    assert.ok(target, "the page is listed");
    assert.ok(String(target.webSocketDebuggerUrl).includes(new URL(at.url).host), "the agent is pointed at the relay");
    a = await agent(target.webSocketDebuggerUrl);
    for (let i = 0; i < 150; i++) {
      const ready = await a.send("Runtime.evaluate", { expression: READY, returnByValue: true });
      if (ready.result?.result?.value === true) break;
      await new Promise((r) => setTimeout(r, 100));
    }

    const read = await a.send("Runtime.evaluate", { expression: "document.body.innerText", returnByValue: true });
    const text = String(read.result?.result?.value);
    assert.ok(!text.includes(KEY), `no raw value: ${text}`);
    assert.match(text, /Secret key \$MDU:/);

    await a.send("Runtime.evaluate", { expression: "document.getElementById('f').focus()" });
    const typed = await a.send("Input.insertText", { text: `K=${s.field}` });
    assert.deepEqual(typed.result, {}, JSON.stringify(typed));
    const back = await a.send("Runtime.evaluate", { expression: "document.getElementById('f').value", returnByValue: true });
    assert.match(String(back.result?.result?.value), /^K=\$MDU:/, "the agent reads its field as the placeholder");

    // Chrome itself, past the relay: the real value (the HumanView).
    direct = new WebSocket(`ws://127.0.0.1:${port}/devtools/page/${target.id}`);
    await new Promise<void>((resolve) => direct!.addEventListener("open", () => resolve(), { once: true }));
    const real = await new Promise<any>((resolve) => {
      direct!.addEventListener("message", (ev) => resolve(JSON.parse(String(ev.data))), { once: true });
      direct!.send(JSON.stringify({ id: 1, method: "Runtime.evaluate", params: { expression: "document.getElementById('f').value", returnByValue: true } }));
    });
    assert.equal(real.result?.result?.value, `K=${KEY}`, "the page holds the real value");

    const shot = await a.send("Page.captureScreenshot");
    assert.match(String(shot.error?.message), /not pixels/);
    assert.ok(!JSON.stringify(a.all).includes(KEY), "nothing the agent got carried the value");
  } finally {
    direct?.close();
    a?.close();
    await relay?.close();
    await stopChromium(chrome, profile);
    page.close();
    await s.close();
  }
});

/** What a field holds, read on Chrome's own endpoint (the HumanView). */
async function fieldOnChrome(port: number, targetId: string): Promise<string> {
  return evalOnChrome(port, targetId, "document.getElementById('f').value");
}

/** An expression's value on Chrome's own endpoint, as a string. */
async function evalOnChrome(port: number, targetId: string, expression: string): Promise<string> {
  const ws = new WebSocket(`ws://127.0.0.1:${port}/devtools/page/${targetId}`);
  await new Promise<void>((resolve) => ws.addEventListener("open", () => resolve(), { once: true }));
  try {
    const answer = await new Promise<any>((resolve) => {
      ws.addEventListener("message", (ev) => resolve(JSON.parse(String(ev.data))), { once: true });
      ws.send(JSON.stringify({ id: 1, method: "Runtime.evaluate", params: { expression, returnByValue: true } }));
    });
    return String(answer.result?.result?.value);
  } finally {
    ws.close();
  }
}

test("a real headless Chromium, a placeholder typed a key at a time (browser-use's input, devtools-relay.md §3.3): a bound page's field holds the real value, an unbound page's holds nothing of it", { skip: BIN === null ? "no headless Chromium (MANDU_TEST_CHROMIUM)" : false }, async () => {
  const s = await stack();
  const page: Server = createServer((q, res) => {
    res.writeHead(200, { "content-type": "text/html" });
    // `/form`: the expense form, whose submit records what the field held.
    if (q.url === "/form") {
      res.end(`<html><body><form onsubmit="window.sent = document.getElementById('f').value; return false"><input id="f"><button id="go" style="position:absolute;left:20px;top:80px;width:120px;height:40px">Submit</button></form></body></html>`);
      return;
    }
    res.end(`<html><body><input id="f"></body></html>`);
  });
  await new Promise<void>((resolve) => page.listen(0, "127.0.0.1", () => resolve()));
  const pagePort = (page.address() as AddressInfo).port;
  const profile = mkdtempSync(join(tmpdir(), "mandu-cdp-keys-"));
  let chrome: ChildProcess | null = null;
  let relay: CdpRelay | null = null;
  const agents: Array<Awaited<ReturnType<typeof agent>>> = [];
  try {
    const started = await startChromium(BIN!, profile, "about:blank");
    chrome = started.proc;
    relay = new CdpRelay({ upstream: `http://127.0.0.1:${started.port}`, arbiter: s.adapter, session: SESSION });
    const at = await relay.listen();
    /** Open `url` in a new tab, the agent on it through the relay, its field focused. */
    const open = async (url: string) => {
      const tab = (await (await fetch(`http://127.0.0.1:${started.port}/json/new?${url}`, { method: "PUT" })).json()) as { id: string };
      const a = await agent(`ws://${new URL(at.url).host}/devtools/page/${tab.id}`);
      agents.push(a);
      for (let i = 0; i < 150; i++) {
        const ready = await a.send("Runtime.evaluate", { expression: "document.readyState === 'complete' && !!document.getElementById('f')", returnByValue: true });
        if (ready.result?.result?.value === true) break;
        await new Promise((r) => setTimeout(r, 100));
      }
      await a.send("Runtime.evaluate", { expression: "document.getElementById('f').focus()" });
      return { a, id: tab.id };
    };
    /** browser-use's three events per character, each awaited. */
    const typeKeys = async (a: Awaited<ReturnType<typeof agent>>, text: string) => {
      const answers: any[] = [];
      for (const ch of text) {
        answers.push(await a.send("Input.dispatchKeyEvent", { type: "keyDown", key: ch }));
        answers.push(await a.send("Input.dispatchKeyEvent", { type: "char", text: ch, key: ch }));
        answers.push(await a.send("Input.dispatchKeyEvent", { type: "keyUp", key: ch }));
      }
      return answers;
    };

    // bound (127.0.0.1): the field holds the text around it and the real value
    const bound = await open(`http://127.0.0.1:${pagePort}/`);
    const answers = await typeKeys(bound.a, `K=${s.field} ok`);
    assert.ok(answers.every((x) => x.error === undefined), JSON.stringify(answers.find((x) => x.error)));
    assert.equal(await fieldOnChrome(started.port, bound.id), `K=${KEY} ok`, "the page holds the real value where the placeholder was typed");
    const back = await bound.a.send("Runtime.evaluate", { expression: "document.getElementById('f').value", returnByValue: true });
    assert.equal(String(back.result?.result?.value), `K=${s.field} ok`, "the agent reads its field as the placeholder");

    // unbound (localhost): refused, the field holds none of it
    const other = await open(`http://localhost:${pagePort}/`);
    await typeKeys(other.a, `K=${s.field}`);
    await other.a.send("Runtime.evaluate", { expression: "1" }); // another command ends the run
    const there = await fieldOnChrome(started.port, other.id);
    assert.equal(there, "K=", "nothing of the placeholder or its value was typed there");
    const toldThere = await other.a.send("Input.dispatchKeyEvent", { type: "keyDown", key: "Enter" });
    assert.match(String(toldThere.error?.message), /not typed: localhost may not have \$MDU:\S+ without the person.s approval in Mandu; leave it out .*this command was not sent either/, "the next input command carries the refusal");

    // bound, but a placeholder whose code the arbiter never minted: the key
    // that closes its code carries the error (the real arbiter's
    // placeholderKnown, on the human socket), nothing of it is typed, and the
    // agent's next input command is not told again (§3.3)
    const third = await open(`http://127.0.0.1:${pagePort}/`);
    const madeUp = nearMiss(s.field);
    const keyAnswers = await typeKeys(third.a, `K=${madeUp}`);
    const closes = (2 + madeUp.indexOf("]")) * 3 + 1;
    assert.deepEqual(keyAnswers.flatMap((x, i) => (x.error !== undefined ? [i] : [])), [closes], "only the ]'s char event carries the refusal");
    const madeBase = madeUp.slice(0, madeUp.indexOf("]") + 1);
    assert.ok(String(keyAnswers[closes].error.message).includes(`no such placeholder ${madeBase}: type the placeholder exactly as the page shows it`), JSON.stringify(keyAnswers[closes]));
    await third.a.send("Runtime.evaluate", { expression: "1" }); // browser-use's read-back: ends the run
    assert.equal(await fieldOnChrome(started.port, third.id), "K=", "the page got none of the made-up placeholder");
    const told = await third.a.send("Input.dispatchKeyEvent", { type: "keyDown", key: "Enter" });
    assert.equal(told.error, undefined, "told on its key: the next input command is not refused again");

    // bound, a known base with a field the secret lacks: still decided when
    // the run ends (the field needs the whole name), the next input command told
    const fifth = await open(`http://127.0.0.1:${pagePort}/`);
    const noField = `${s.field}S`;
    const fieldAnswers = await typeKeys(fifth.a, `K=${noField}`);
    assert.ok(fieldAnswers.every((x) => x.error === undefined), "each key answered as it came: its base is known");
    await fifth.a.send("Runtime.evaluate", { expression: "1" });
    assert.equal(await fieldOnChrome(started.port, fifth.id), "K=", "the page got none of it");
    const toldField = await fifth.a.send("Input.dispatchKeyEvent", { type: "keyDown", key: "Enter" });
    assert.ok(String(toldField.error?.message).includes(`no such placeholder ${noField}: type the placeholder exactly as the page shows it`), JSON.stringify(toldField));

    // bound, and a LOOKALIKE (a UUID for its code, the live expense-report
    // demo's): the key that closes its code is answered with the error, so
    // the agent's typing command fails while it types, before its next
    // action (a submit) can run; the page got none of it (§3.3)
    const fourth = await open(`http://127.0.0.1:${pagePort}/`);
    const uuid = s.field.replace(/\[[0-9a-f]+\]/, "[6a91724a-25c2-4824-91b4-5c962b146473]");
    const uuidAnswers = await typeKeys(fourth.a, `K=${uuid}`);
    const failedAt = uuidAnswers.findIndex((x) => x.error !== undefined);
    assert.equal(failedAt, (2 + uuid.indexOf("]")) * 3 + 1, "the ]'s char event carries the refusal, not a later command");
    assert.ok(String(uuidAnswers[failedAt].error.message).includes(`no such placeholder ${uuid.slice(0, uuid.indexOf("]") + 1)}`), JSON.stringify(uuidAnswers[failedAt]));
    await fourth.a.send("Runtime.evaluate", { expression: "1" }); // ends the run: dropped
    assert.equal(await fieldOnChrome(started.port, fourth.id), "K=", "the page got none of the lookalike");
    const after = await fourth.a.send("Input.dispatchKeyEvent", { type: "keyDown", key: "Enter" });
    assert.equal(after.error, undefined, "told on the key: the next input command is not refused again");

    // The live expense-report step, as browser-use runs it, on a real form:
    // the model typed a made-up HEX placeholder and clicked Submit in the
    // same step. Its input fails on the ] that closes the code, and again on
    // its fallback typing, so multi_act stops and the Submit click (with its
    // script-click fallback) never runs: the form is never sent with the
    // field empty. The next step, the page's own placeholder: typed,
    // released, and Submit sends the real value.
    const form = await open(`http://127.0.0.1:${pagePort}/form`);
    /** browser-use's typing loop: stops at the first key answered with an error. */
    const typeUntilError = async (a: Awaited<ReturnType<typeof agent>>, text: string): Promise<string | null> => {
      for (const ch of text) {
        for (const params of [{ type: "keyDown", key: ch }, { type: "char", text: ch, key: ch }, { type: "keyUp", key: ch }]) {
          const x = await a.send("Input.dispatchKeyEvent", params);
          if (x.error !== undefined) return String(x.error.message);
        }
      }
      return null;
    };
    const made = "$MDU:web_fetch[8c4f].text";
    const firstTry = await typeUntilError(form.a, made);
    assert.ok(String(firstTry).includes("no such placeholder $MDU:web_fetch[8c4f]: type the placeholder exactly as the page shows it"), String(firstTry));
    await form.a.send("Runtime.evaluate", { expression: "document.getElementById('f').focus()" }); // the fallback: the field again
    const fallback = await typeUntilError(form.a, made);
    assert.ok(fallback !== null, "the fallback typing fails the same way: the input action fails, the step stops before Submit");
    await form.a.send("Runtime.evaluate", { expression: "1" }); // ends the held run: dropped
    assert.equal(await evalOnChrome(started.port, form.id, "String(window.sent)"), "undefined", "the form was never submitted");
    assert.equal(await fieldOnChrome(started.port, form.id), "", "and its field holds nothing of the made-up placeholder");
    // The model's next step: the placeholder as the page showed it, then Submit.
    assert.equal(await typeUntilError(form.a, s.field), null);
    await form.a.send("Runtime.evaluate", { expression: "1" }); // browser-use's read-back: ends the run, released
    for (const type of ["mousePressed", "mouseReleased"]) {
      const m = await form.a.send("Input.dispatchMouseEvent", { type, x: 80, y: 100, button: "left", clickCount: 1 });
      assert.equal(m.error, undefined, `${type}: not told of the earlier refusal (it was told on its key)`);
    }
    let sent = "undefined";
    for (let i = 0; i < 50 && sent === "undefined"; i++) {
      sent = await evalOnChrome(started.port, form.id, "String(window.sent)");
      if (sent === "undefined") await new Promise((r) => setTimeout(r, 50));
    }
    assert.equal(sent, KEY, "Submit sent the real value, the only time it fired");

    const { notices } = await s.data.takeRelayNotices({ sessionKey: SESSION });
    assert.ok(notices.some((n) => n.kind === "malformed" && n.symbols.length === 0), JSON.stringify(notices));
    assert.ok(notices.some((n) => n.kind === "unknown" && n.symbols[0] === "$MDU:web_fetch[8c4f]" && n.page === "127.0.0.1"), JSON.stringify(notices));
    assert.ok(!JSON.stringify(notices).includes(KEY));
    for (const a of agents) assert.ok(!JSON.stringify(a.all).includes(KEY), "nothing the agent got carried the value");
  } finally {
    for (const a of agents) a.close();
    await relay?.close();
    await stopChromium(chrome, profile);
    page.close();
    await s.close();
  }
});
