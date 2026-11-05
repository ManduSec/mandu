/**
 * agent-page-print e2e — a session page printed or saved as a PDF holds the
 * whole record, with no controls, and never a secret's value (dashboard.md
 * §4.25b *A printed session is whole*), across the REAL components: a real
 * ArbiterServer in `secrets`, the real anthropic-proxy in its production
 * wiring (`new ArbiterClientAdapter(data, human)`) with a scripted model
 * behind it, and the real dashboard over the arbiter's store with the
 * PRODUCTION surfaces (`makeApprovalsArbiter`).
 *
 * Until 2026-10-23 a print was the screen as it was: the steps past a
 * turn's first 6 were left out, a long reply printed 10 lines under its
 * fade, a long question its first 360 characters, and every button printed.
 *
 *   P1  the session: a ~900-character question, then 9 Reads, the first of
 *       a registered .env (the AI gets the key as a placeholder) and the
 *       7th of a file of a distinct name, then a ~4,000-character reply
 *       naming the key's placeholder; the page records it; then a second,
 *       plain session, newer, so the page ends with a Newer link (#293);
 *   P2  the oracle: the model never got the key, and no read carries it, a
 *       `$MDU` token or the admin token, signed out or in;
 *   P3  a real headless Chromium with the served stylesheet, signed in
 *       with values hidden (no "Show the real value" pressed): under the
 *       print media no control shows (only count tiles and step times
 *       stay as buttons), the top bar is gone, the folded reply has no
 *       height cap or fade and the Newer link drawn on screen is gone; `Page.printToPDF` (which fires `beforeprint`
 *       and `afterprint`, as a print does) gives a PDF whose text holds
 *       the 7th step, the question's end and the reply's last line, the
 *       secret's masked chip, no "Show" or "Hide" words, no "Newer:" nor
 *       the newer session's question, and never the key or a `$MDU` token; after it the screen is folded as before;
 *   P4  signed out, likewise: the whole record, its chip, no value;
 *   P5  on paper, the light palette (2026-10-26): with Dark stored, and with
 *       Same as this computer on a dark system, the print media gives the
 *       heading, the line under it, the question and the masked chip the
 *       light print's computed colours; back on screen, the dark ones.
 *
 * The PDF's text is read by `pdfText` below (node:zlib only): Chromium's
 * Skia writes each page's text as hex glyph codes of Type0 fonts, each with
 * a ToUnicode map, so the text is those codes mapped back.
 *
 * The Chromium half self-SKIPs without a Chromium (probeBrowser:
 * MANDU_TOUR_BROWSER, CHROME_PATH, a Playwright headless shell).
 *
 * Axes explicit: secrets (confidentiality ON, integrity OFF).
 *
 * Run: npm test  (tests/)
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { inflateSync } from "node:zlib";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { AnthropicProxy, type UpstreamFetcher } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse, buildToolUseSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { ADMIN_COOKIE, ADMIN_OPTS, ADMIN_TOKEN } from "../../dashboard/test/unit/admin-session.js";
import type { AgentPageVM } from "../../dashboard/src/view-model/agent-page.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the product default

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
// eslint-disable-next-line @typescript-eslint/no-explicit-any
interface Cdp { send(method: string, params?: object, sessionId?: string): Promise<any>; close(): void }
const tour = (await import(pathToFileURL(join(REPO, "scripts", "tour-screenshots.mjs")).href)) as {
  probeBrowser: (o?: object) => string | null;
  startBrowser: (path: string, dataDir: string, env: NodeJS.ProcessEnv) => Promise<{ proc: unknown; wsUrl: string }>;
  stopProc: (proc: unknown) => Promise<void>;
  Cdp: { connect(url: string): Promise<Cdp> };
};
const chromium = tour.probeBrowser({});

const KEY = `sk_live_printCanary_${process.pid}_8Vn3Yt6Qa1`;
const SESSION = `agent-print-${process.pid}`;
/** Words only at the end of the question, past its 360-character clip.
 *  Without spaces or hyphens: a PDF line is one run of text. */
const QEND = "questionEndWombat";
const QUESTION = "Please go through the parser and its retries, file by file, and keep notes. ".repeat(12).slice(0, 880) + ` ${QEND}`;
/** The file the 7th step reads: past the first 6, folded. */
const SEVENTH = "seventhStepQuokka.md";
/** Words only in the last line of the long reply. */
const TAIL = "replyTailMarmot";
/** The newer, plain session: its question's words are not printed with
 *  this one's record (#293). */
const NEWER = `agent-print-newer-${process.pid}`;
const NEWER_WORD = "newerSessionPelican";
const NEWER_Q = `Rename the parser helper ${NEWER_WORD}`;
const FILES = [".env", "part-2.md", "part-3.md", "part-4.md", "part-5.md", "part-6.md", SEVENTH, "part-8.md", "part-9.md"];
const render = (s: string) => s.split("\n").slice(0, -1).map((l, i) => `${String(i + 1).padStart(6)}\t${l}`).join("\n") + "\n";
/** A coding agent's summary of ~4,000 characters, naming the key's placeholder. */
function summary(token: string): string {
  const lines = ["Done. Here is what I changed and why:", ""];
  for (let i = 1; i <= 34; i++) lines.push(`- **Step ${i}**: updated \`src/module-${i}.ts\` so the parser keeps its place across a retry, and its tests.`);
  lines.push("", `The service reads its key from .env (${token}); I left it as it was.`, "", `Last: ${TAIL}`);
  return lines.join("\n");
}

// ── The PDF's text ─────────────────────────────────────────────────────────
/** The text of a PDF Chromium printed: per page, each text object's hex
 *  glyph codes (`<…> Tj`, `[<…> …] TJ`) mapped through its font's
 *  ToUnicode map, one line per text object. Enough for Skia's output: no
 *  object streams, direct lengths, Type0 fonts. */
function pdfText(pdf: Buffer): string {
  const s = pdf.toString("latin1");
  const objs = new Map<number, { dict: string; stream: Buffer | null }>();
  const head = /(\d+) 0 obj\b/g;
  for (let m = head.exec(s); m; m = head.exec(s)) {
    const start = m.index + m[0].length;
    const sAt = s.indexOf("stream", start);
    const eAt = s.indexOf("endobj", start);
    if (sAt < 0 || (eAt >= 0 && eAt < sAt)) { objs.set(Number(m[1]), { dict: s.slice(start, eAt), stream: null }); continue; }
    const dict = s.slice(start, sAt);
    const len = Number(/\/Length (\d+)/.exec(dict)?.[1]);
    let from = sAt + "stream".length;
    if (s[from] === "\r") from++;
    if (s[from] === "\n") from++;
    const raw = pdf.subarray(from, from + len);
    objs.set(Number(m[1]), { dict, stream: /\/FlateDecode/.test(dict) ? inflateSync(raw) : raw });
    head.lastIndex = from + len;
  }
  const ref = (dict: string, key: string) => { const m = new RegExp(`/${key} (\\d+) 0 R`).exec(dict); return m ? Number(m[1]) : null; };
  const utf16 = (hex: string) => String.fromCharCode(...(hex.match(/.{4}/g) ?? []).map((h) => parseInt(h, 16)));
  /** A ToUnicode map: code (hex) → text, and its code width in hex digits. */
  const cmaps = new Map<number, { width: number; map: Map<number, string> }>();
  const cmapOf = (font: number) => {
    if (cmaps.has(font)) return cmaps.get(font)!;
    const to = ref(objs.get(font)?.dict ?? "", "ToUnicode");
    const text = to === null ? "" : objs.get(to)?.stream?.toString("latin1") ?? "";
    const map = new Map<number, string>();
    for (const block of text.matchAll(/beginbfchar([\s\S]*?)endbfchar/g)) {
      for (const [, src, dst] of block[1].matchAll(/<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>/g)) map.set(parseInt(src, 16), utf16(dst));
    }
    for (const block of text.matchAll(/beginbfrange([\s\S]*?)endbfrange/g)) {
      for (const [, lo, hi, dst] of block[1].matchAll(/<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>/g)) {
        const first = parseInt(dst, 16);
        for (let c = parseInt(lo, 16), i = 0; c <= parseInt(hi, 16); c++, i++) map.set(c, String.fromCharCode(first + i));
      }
    }
    const width = /begincodespacerange\s*<([0-9A-Fa-f]+)>/.exec(text)?.[1].length ?? 4;
    const out = { width, map };
    cmaps.set(font, out);
    return out;
  };
  const lines: string[] = [];
  for (const page of [...objs.values()].filter((o) => /\/Type \/Page\b/.test(o.dict))) {
    const fonts = new Map<string, number>();
    const fontDict = /\/Font <<([^>]*)>>/.exec(page.dict)?.[1] ?? "";
    for (const [, name, id] of fontDict.matchAll(/\/([^\s/]+) (\d+) 0 R/g)) fonts.set(name, Number(id));
    const contents = /\/Contents \[([^\]]*)\]/.exec(page.dict)?.[1] ?? /\/Contents (\d+ 0 R)/.exec(page.dict)?.[1] ?? "";
    for (const [, id] of contents.matchAll(/(\d+) 0 R/g)) {
      const ops = objs.get(Number(id))?.stream?.toString("latin1") ?? "";
      let font: { width: number; map: Map<number, string> } | null = null;
      let line = "";
      for (const [, name, hexes, op] of ops.matchAll(/\/([^\s/]+) [\d.]+ Tf|(<[0-9A-Fa-f]*>|\[[^\]]*\])\s*(Tj|TJ)|\bET\b/g)) {
        if (name) font = fonts.has(name) ? cmapOf(fonts.get(name)!) : null;
        else if (op && font) {
          for (const [, hex] of hexes.matchAll(/<([0-9A-Fa-f]*)>/g)) {
            for (let i = 0; i + font.width <= hex.length; i += font.width) line += font.map.get(parseInt(hex.slice(i, i + font.width), 16)) ?? "";
          }
        } else if (!op) { lines.push(line); line = ""; }
      }
    }
  }
  return lines.filter(Boolean).join("\n");
}

const dirs: string[] = [];
const closers: Array<() => Promise<void>> = [];
after(async () => {
  for (const c of closers.reverse()) await c();
  resetCurrentPolicyForTests("claude-code");
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

let stack: { base: string; page: AgentPageVM; seen: string[] } | null = null;
/** The recorded session, once for every test. */
async function start() {
  if (stack) return stack;
  const tmp = mkdtempSync(join(tmpdir(), "mandu-agent-print-"));
  dirs.push(tmp);
  const ws = join(tmp, "ws");
  mkdirSync(ws, { recursive: true });
  for (const f of FILES.slice(1)) writeFileSync(join(ws, f), `Notes in ${f}.\n`);
  const env = join(ws, ".env");
  writeFileSync(env, `STRIPE_KEY=${KEY}\n`);
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, `version: 1\npaths:\n  - path: ${join(tmp, "other.key")}\n    level: no-model\n`);
  const sock = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanSock = join(tmp, "human", "h.sock");
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const arbiter = new ArbiterServer({
    socketPath: sock, adminSocketPath: adminSock, humanSocketPath: humanSock, dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"),
    policyPath, policyPollMs: 0, log: () => {}, confidentiality: true, integrity: false,
  });
  await arbiter.listen();
  const clients: ArbiterClient[] = [];
  const open = async (s: string): Promise<ArbiterClient> => { const c = new ArbiterClient(s); await c.connect(); clients.push(c); return c; };
  const gate = await open(sock);
  const reg = await gate.registerSecret({ path: env, sessionKey: SESSION });
  assert.ok(reg.symbol || reg.twin, `the .env is registered: ${JSON.stringify(reg)}`);

  // The scripted model: a Read of each file, one request a step, then the
  // long summary, which names the placeholder the AI got for the key.
  const seen: string[] = [];
  let reads = 0;
  const upstream: UpstreamFetcher = async (a) => {
    let sse: string;
    if (reads < FILES.length) {
      const f = FILES[reads++];
      sse = buildToolUseSse({ id: `toolu_print_${reads}`, name: "Read", input: { file_path: f === ".env" ? env : join(ws, f) } });
    } else {
      const token = /\$MDU:[A-Za-z_]+\[[0-9a-f]+\](?:\.[A-Za-z_]+)?/.exec(a.body.toString("utf8"))?.[0];
      assert.ok(token, "the AI got the key as a placeholder");
      sse = buildTextSse(summary(token!));
    }
    const m = new MockUpstream({ sse });
    const res = await m.fetcher(a);
    seen.push(m.requests.at(-1)!.bodyText);
    return res;
  };
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(await open(sock), await open(humanSock)), upstream, sessionKey: SESSION, log: () => {} });
  const port = await proxy.listen(0);
  // The newer, plain session's proxy: one question, one reply.
  const newerProxy = new AnthropicProxy({
    arbiter: new ArbiterClientAdapter(await open(sock), await open(humanSock)), sessionKey: NEWER, log: () => {},
    upstream: async (a) => new MockUpstream({ sse: buildTextSse("Done.") }).fetcher(a),
  });
  const newerPort = await newerProxy.listen(0);
  const wired = await makeApprovalsArbiter(sock, () => ({ socketPath: adminSock }));
  assert.ok(wired?.secrets, "the production wiring connects");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath: sock }), log: () => {}, ...ADMIN_OPTS,
    approvalsArbiter: wired.arbiter, secretsArbiter: wired.secrets, policyDocArbiter: wired.policyDoc,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  closers.push(async () => {
    await dashboard.close(); await proxy.close(); await newerProxy.close(); wired.close();
    for (const c of clients) c.close();
    await arbiter.close();
  });

  // ── P1: the session ─────────────────────────────────────────────────────
  type Msg = { role: string; content: unknown };
  const ask = async (messages: Msg[], to = port, session = SESSION) => {
    const res = await fetch(`http://127.0.0.1:${to}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mandu-session-id": session, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({ model: "claude-sonnet-4-5", stream: true, max_tokens: 2048, tools: [{ name: "Read", input_schema: { type: "object" } }], messages }),
    });
    assert.equal(res.status, 200, await res.text());
  };
  let msgs: Msg[] = [{ role: "user", content: QUESTION }];
  for (const [i, f] of FILES.entries()) {
    await ask(msgs);
    const id = `toolu_print_${i + 1}`;
    const path = f === ".env" ? env : join(ws, f);
    msgs = [
      ...msgs,
      { role: "assistant", content: [{ type: "tool_use", id, name: "Read", input: { file_path: path } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: id, content: render(f === ".env" ? `STRIPE_KEY=${KEY}\n` : `Notes in ${f}.\n`) }] },
    ];
  }
  await ask(msgs);
  assert.ok(!seen.join("\n").includes(KEY), "CONFIDENTIALITY VIOLATION: the key reached the model");

  let page: AgentPageVM | undefined;
  const settled = (vm?: AgentPageVM) => !!vm && vm.story?.length === 1 && vm.story[0].steps.length === FILES.length && !!vm.story[0].reply;
  for (let i = 0; i < 200 && !settled(page); i++) {
    // emission is best-effort and asynchronous
    const r = await fetch(`${base}/api/home/agent?session=${SESSION}`, { headers: { Cookie: ADMIN_COOKIE } });
    assert.equal(r.status, 200);
    page = (await r.json()) as AgentPageVM;
    if (!settled(page)) await new Promise((res) => setTimeout(res, 25));
  }
  assert.ok(settled(page), `one turn of ${FILES.length} steps and a reply: ${JSON.stringify(page?.story.map((t) => [t.prompt?.slice(0, 20), t.steps.length, !!t.reply]))}`);

  // Then a second, plain session: History lists it above this one, so the
  // page ends with a Newer link to it.
  await ask([{ role: "user", content: NEWER_Q }], newerPort, NEWER);
  const linked = (vm?: AgentPageVM) => settled(vm) && vm!.neighbours?.newer?.id === NEWER && !!vm!.neighbours.newer.title?.includes(NEWER_WORD);
  for (let i = 0; i < 200 && !linked(page); i++) {
    const r = await fetch(`${base}/api/home/agent?session=${SESSION}`, { headers: { Cookie: ADMIN_COOKIE } });
    assert.equal(r.status, 200);
    page = (await r.json()) as AgentPageVM;
    if (!linked(page)) await new Promise((res) => setTimeout(res, 25));
  }
  assert.ok(linked(page), `the newer session is this one's Newer: ${JSON.stringify(page?.neighbours)}`);
  stack = { base, page: page!, seen };
  return stack;
}

test("a long question, 9 reads with a masked .env and a long reply are recorded, and no read carries the key, a token or the admin token (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const { base, page, seen } = await start();
  assert.equal(page.story[0].prompt, QUESTION, "the whole question is recorded");

  // ── P2: the oracle ──────────────────────────────────────────────────────
  assert.ok(!seen.join("\n").includes(KEY), "CONFIDENTIALITY VIOLATION: the model got the key");
  for (const [what, url, cookie] of [
    ["the session page, signed out", `/api/home/agent?session=${SESSION}`, null],
    ["the session page, signed in", `/api/home/agent?session=${SESSION}`, ADMIN_COOKIE],
    ["the served page", `/agents/${SESSION}`, ADMIN_COOKIE],
  ] as const) {
    const r = await fetch(base + url, cookie ? { headers: { Cookie: cookie } } : {});
    assert.equal(r.status, 200, what);
    const body = await r.text();
    assert.ok(!body.includes(KEY), `CONFIDENTIALITY VIOLATION: ${what} carries the key`);
    assert.doesNotMatch(body, /\$MDU/, `${what} carries a token`);
    assert.ok(!body.includes(ADMIN_TOKEN), `${what} carries the admin token`);
  }
});

test("in a real Chromium, signed in with values hidden and signed out: the printed PDF holds the whole record and the masked chip, no button words, never the key; the screen is as before after (secrets axes, explicit)", {
  skip: chromium ? false : "no Chromium found (MANDU_TOUR_BROWSER, CHROME_PATH, a Playwright headless shell)", timeout: 180_000,
}, async () => {
  const { base } = await start();
  const tmp = mkdtempSync(join(tmpdir(), "mandu-agent-print-cdp-"));
  dirs.push(tmp);
  const { proc, wsUrl } = await tour.startBrowser(chromium as string, join(tmp, "chrome"), process.env);
  const cdp = await tour.Cdp.connect(wsUrl);
  try {
    for (const signedIn of [true, false]) {
      const who = signedIn ? "signed in" : "signed out";
      const { targetId } = await cdp.send("Target.createTarget", { url: "about:blank" });
      const { sessionId } = await cdp.send("Target.attachToTarget", { targetId, flatten: true });
      const send = (method: string, params: object = {}) => cdp.send(method, params, sessionId);
      const evaluate = async (expression: string) => {
        const r = await send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
        if (r.exceptionDetails) throw new Error(`page script failed: ${r.exceptionDetails.exception?.description ?? r.exceptionDetails.text}`);
        return r.result.value;
      };
      const until = async (what: string, expression: string) => {
        let ok = false;
        for (const end = Date.now() + 30_000; Date.now() < end && !ok; await new Promise((r) => setTimeout(r, 100))) {
          try { ok = await evaluate(expression); } catch { /* navigating */ }
        }
        assert.ok(ok, what);
      };
      await send("Page.enable");
      await send("Runtime.enable");
      await send("Network.enable");
      await send("Network.clearBrowserCookies");
      if (signedIn) {
        const eq = ADMIN_COOKIE.indexOf("=");
        await send("Network.setCookie", { name: ADMIN_COOKIE.slice(0, eq), value: ADMIN_COOKIE.slice(eq + 1), url: base, httpOnly: true, sameSite: "Strict" });
      }
      await send("Emulation.setDeviceMetricsOverride", { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });
      await send("Page.navigate", { url: `${base}/agents/${SESSION}` });
      const card = `document.querySelector("#agent-story .step.reply")`;
      await until(`the page drawn, ${who}`, `!!${card} && !!document.querySelector("#agent-story .steps-more") && document.fonts.status === "loaded"`);
      await until(`the reply folded, ${who}`, `${card}.querySelector(".reply-text").classList.contains("folded")`);
      /** The folds as the screen shows them. */
      const folds = () => evaluate(`(() => {
        const fold = document.querySelector("#agent-story .steps-more");
        const btn = fold.nextElementSibling.querySelector(".steps-toggle");
        const q = document.querySelector("#agent-story .turn-q .q-text");
        return {
          fold: fold.getAttribute("hidden"), steps: btn.textContent, open: btn.getAttribute("aria-expanded"),
          question: q.textContent.includes(${JSON.stringify(QEND)}), reply: ${card}.querySelector(".reply-text").classList.contains("folded"),
          replyWords: ${card}.querySelector("button.reply-fold").textContent,
        };
      })()`);
      const before = await folds();
      assert.deepEqual(before, { fold: "until-found", steps: "Show 3 more steps", open: "false", question: false, reply: true, replyWords: "Show the whole reply" }, `drawn folded, ${who}`);
      const chips: string[] = await evaluate(`[...document.querySelectorAll("#agent-story .mask-chip.secret")].map((c) => c.textContent)`);
      assert.ok(chips.length > 0, `the secret shows as its masked chip, ${who}`);
      if (!signedIn) assert.ok(await evaluate(`!!document.querySelector("#agent-story .values-withheld")`), "signed out, the page says values need a sign-in");
      // On screen, the page ends with the Newer link to the other session.
      await until(`the Newer link drawn, ${who}`, `document.querySelector("#agent-neighbours a")?.dataset.session === ${JSON.stringify(NEWER)}`);
      const nav = `document.getElementById("agent-neighbours")`;
      assert.ok(await evaluate(`getComputedStyle(${nav}).display !== "none" && ${nav}.getClientRects().length > 0 && ${nav}.textContent.includes(${JSON.stringify(NEWER_WORD)})`),
        `on screen the Newer link shows, ${who}`);

      // Under the print media, before any beforeprint: the controls go, a
      // folded reply has no cap or fade.
      await send("Emulation.setEmulatedMedia", { media: "print" });
      const media = await evaluate(`(() => {
        const visible = (x) => getComputedStyle(x).display !== "none" && x.getClientRects().length > 0;
        const t = ${card}.querySelector(".reply-text");
        const cs = getComputedStyle(t);
        return {
          top: visible(document.getElementById("top")), back: visible(document.getElementById("agent-back")),
          buttons: [...document.querySelectorAll("#page-agent button")].filter(visible).filter((b) => !b.matches(".tile, .step-link")).map((b) => b.textContent),
          tiles: [...document.querySelectorAll("#agent-facts .tile")].filter(visible).length,
          maxHeight: cs.maxHeight, mask: cs.maskImage || cs.webkitMaskImage || "",
          step: getComputedStyle(document.querySelector("#agent-story .step")).breakInside,
          neighbours: getComputedStyle(document.getElementById("agent-neighbours")).display,
        };
      })()`);
      assert.equal(media.top, false, "no top bar in the print");
      assert.equal(media.back, false, "no back link");
      assert.deepEqual(media.buttons, [], "no control shows in the print");
      assert.ok(media.tiles > 0, "the count tiles stay");
      assert.equal(media.maxHeight, "none", "a folded reply prints whole");
      assert.ok(!/gradient/.test(media.mask), "without its fade");
      assert.equal(media.step, "avoid", "a step is not split across pages");
      assert.equal(media.neighbours, "none", "no Newer/Older line in the print");
      await send("Emulation.setEmulatedMedia", { media: "" });

      // The print itself: Chromium fires beforeprint, prints, then afterprint.
      const { data } = await send("Page.printToPDF", { printBackground: false });
      const pdf = Buffer.from(data, "base64");
      assert.equal(pdf.subarray(0, 5).toString("latin1"), "%PDF-");
      const text = pdfText(pdf);
      assert.ok(text.includes("What happened"), `the PDF's text reads (${text.slice(0, 200)})`);
      assert.ok(text.includes(SEVENTH.replace(/\.md$/, "")), `the PDF holds the 7th step, ${who}`);
      assert.ok(text.includes(QEND), `the PDF holds the question's end, ${who}`);
      assert.ok(text.includes(TAIL), `the PDF holds the reply's last line, ${who}`);
      assert.doesNotMatch(text, /\bShow\b|\bHide\b|Back to home|Only where Mandu/, `no button words in the PDF, ${who}`);
      assert.doesNotMatch(text, /Newer:|Older:/, `no link to another session in the PDF, ${who}`);
      assert.ok(!text.includes(NEWER_WORD), `the PDF holds none of the other session's question, ${who}`);
      for (const c of chips) assert.ok(text.includes(c), `the PDF holds the masked chip "${c}", ${who}`);
      assert.ok(!text.includes(KEY), `CONFIDENTIALITY VIOLATION: the PDF holds the key, ${who}`);
      assert.ok(!pdf.toString("latin1").includes(KEY), `CONFIDENTIALITY VIOLATION: the PDF's bytes hold the key, ${who}`);
      assert.doesNotMatch(text, /\$MDU/, `the PDF holds a token, ${who}`);

      // After the print the screen is as it was.
      assert.deepEqual(await folds(), before, `afterprint folds back what the print opened, ${who}`);
      const body = await evaluate(`document.body.innerText + document.documentElement.outerHTML`);
      assert.ok(!body.includes(KEY), `CONFIDENTIALITY VIOLATION: the page shows the key, ${who}`);
      await cdp.send("Target.closeTarget", { targetId });
    }
  } finally {
    cdp.close();
    await tour.stopProc(proc);
  }
});

// ── P5: on paper, the light palette ────────────────────────────────────────
// Until 2026-10-26 a print kept the screen's theme: from the dark theme the
// heading printed light grey on white and a masked chip a dark bar.
test("in a real Chromium, the print media draws the light theme's colours from a stored Dark and from Same as this computer on a dark system; the screen keeps its dark ones (secrets axes, explicit)", {
  skip: chromium ? false : "no Chromium found (MANDU_TOUR_BROWSER, CHROME_PATH, a Playwright headless shell)", timeout: 180_000,
}, async () => {
  const { base } = await start();
  const tmp = mkdtempSync(join(tmpdir(), "mandu-agent-print-theme-"));
  dirs.push(tmp);
  const { proc, wsUrl } = await tour.startBrowser(chromium as string, join(tmp, "chrome"), process.env);
  const cdp = await tour.Cdp.connect(wsUrl);
  try {
    const { targetId } = await cdp.send("Target.createTarget", { url: "about:blank" });
    const { sessionId } = await cdp.send("Target.attachToTarget", { targetId, flatten: true });
    const send = (method: string, params: object = {}) => cdp.send(method, params, sessionId);
    const evaluate = async (expression: string) => {
      const r = await send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
      if (r.exceptionDetails) throw new Error(`page script failed: ${r.exceptionDetails.exception?.description ?? r.exceptionDetails.text}`);
      return r.result.value;
    };
    const until = async (what: string, expression: string) => {
      let ok = false;
      for (const end = Date.now() + 30_000; Date.now() < end && !ok; await new Promise((r) => setTimeout(r, 100))) {
        try { ok = await evaluate(expression); } catch { /* navigating */ }
      }
      assert.ok(ok, what);
    };
    await send("Page.enable");
    await send("Runtime.enable");
    await send("Network.enable");
    const eq = ADMIN_COOKIE.indexOf("=");
    await send("Network.setCookie", { name: ADMIN_COOKIE.slice(0, eq), value: ADMIN_COOKIE.slice(eq + 1), url: base, httpOnly: true, sameSite: "Strict" });
    await send("Emulation.setDeviceMetricsOverride", { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });
    /** The heading, the line under it, the question's words and the masked chip, as drawn. */
    const colours = () => evaluate(`(() => {
      const cs = (sel) => getComputedStyle(document.querySelector(sel));
      const chip = cs("#agent-story .mask-chip.secret");
      return {
        scheme: getComputedStyle(document.documentElement).colorScheme,
        heading: cs("#agent-name").color, sub: cs("#agent-sub").color, question: cs("#agent-story .turn-q .q-text").color,
        chip: chip.color, chipGround: chip.backgroundColor, chipEdge: chip.borderTopColor,
      };
    })()`);
    /** The session page with `stored` under the Appearance key, the system's scheme `scheme`. */
    const open = async (stored: string, scheme: string) => {
      const features = [{ name: "prefers-color-scheme", value: scheme }];
      await send("Emulation.setEmulatedMedia", { media: "", features });
      await send("Page.navigate", { url: `${base}/agents/${SESSION}` });
      await until(`the page loaded (${stored})`, `document.readyState === "complete"`);
      await evaluate(`localStorage.setItem("mandu.theme", ${JSON.stringify(stored)}), true`);
      await send("Page.navigate", { url: `${base}/agents/${SESSION}` });
      await until(`the page drawn (${stored}, a ${scheme} system)`, `!!document.querySelector("#agent-story .mask-chip.secret") && document.fonts.status === "loaded"`);
      const theme = await evaluate(`document.documentElement.getAttribute("data-theme")`);
      assert.equal(theme, stored === "system" ? null : stored, `the stored ${stored} is the page's`);
      const screen = await colours();
      await send("Emulation.setEmulatedMedia", { media: "print", features });
      const print = await colours();
      await send("Emulation.setEmulatedMedia", { media: "", features });
      return { screen, print, back: await colours() };
    };

    const light = await open("light", "light");
    assert.equal(light.print.scheme, "light");
    assert.deepEqual(light.print, light.screen, "a light-theme print is drawn as the light screen");
    assert.equal(light.print.heading, "rgb(28, 28, 32)", "the heading in the light ink, #1c1c20");
    for (const [what, stored, scheme] of [["a stored Dark", "dark", "light"], ["Same as this computer on a dark system", "system", "dark"]] as const) {
      const dark = await open(stored, scheme);
      assert.equal(dark.screen.scheme, "dark", `${what}: the screen is dark`);
      assert.equal(dark.screen.heading, "rgb(236, 235, 230)", `${what}: the screen's heading is the dark ink, #ecebe6`);
      assert.notEqual(dark.screen.chipGround, light.screen.chipGround, `${what}: the chip is drawn dark on screen`);
      assert.deepEqual(dark.print, light.print, `${what}: on paper the heading, the line under it, the question and the masked chip are the light print's`);
      assert.deepEqual(dark.back, dark.screen, `${what}: back on screen, the dark colours return`);
    }
    await cdp.send("Target.closeTarget", { targetId });
  } finally {
    cdp.close();
    await tour.stopProc(proc);
  }
});
