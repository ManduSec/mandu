/**
 * warn-chip-contrast e2e — the session page's amber words (the secret chips,
 * the "Masked only later" and "No AI since" tags, the "The AI read your
 * secret as it was" turn summary) read at least 4.5:1 on the ground they are
 * drawn on, in both themes (dashboard.md §4.25k *The faintest ink reads
 * too*, the `--warn` row), across the REAL components: a real ArbiterServer
 * in `secrets`, the real anthropic-proxy in its production wiring (`new
 * ArbiterClientAdapter(data, human)`) with a scripted model behind it, and
 * the real dashboard over the arbiter's store with the PRODUCTION surfaces
 * (`makeApprovalsArbiter`), signed in.
 *
 * Until 2026-10-25 the light theme's `--warn` `#a35d00` read 4.45:1 on its
 * tint `--warn-bg` `#fbeedb`: on a session page, every one of these, the
 * page's most important warnings, sat just under WCAG AA.
 *
 *   W1  the session: a turn reads a registered .env (the AI gets the key
 *       as a placeholder: secret chips), a turn reads an unlabelled
 *       deploy/staging.conf as it was; the session ends, and only then the
 *       Rules page marks the file a secret, so its read is "Masked only
 *       later", its turn says the AI read it as it was, and its card's tag
 *       reads "No AI since …";
 *   W2  the oracle: the model never got the key, and no read carries it, a
 *       `$MDU` token or the admin token;
 *   W3  a real headless Chromium with the served stylesheet, light and
 *       dark (the stored `mandu.theme`): each of `.mask-chip.secret`,
 *       `.tag.raw` (a step's), `.tag.level.raw` (a card's) and
 *       `.turn-summary.raw` is drawn, and every one drawn reads 4.5:1 at
 *       the least, its computed color on the computed background of the
 *       nearest box that fills one; the drawn page carries no key and no
 *       `$MDU` token.
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
import { contrastRatio } from "../../dashboard/test/unit/ui/css-flatten.js";
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

const KEY = `sk_live_warnChipCanary_${process.pid}_8Qd3Lm`;
const CONF_TOKEN = "ghp_FakeWarnChip5Tn8Yw2Ld6Rq4Zx9Kc";
const CONF = `[staging]\nhost = "staging.warnchip.example"\ntoken = "${CONF_TOKEN}"\n`;
const SESSION = `warn-chip-${process.pid}`;
/** The amber words of the session page, each drawn at least once. */
const AMBER = [".mask-chip.secret", ".tag.raw:not(.level)", ".tag.level.raw", ".turn-summary.raw"];
const render = (s: string) => s.split("\n").slice(0, -1).map((l, i) => `${String(i + 1).padStart(6)}\t${l}`).join("\n") + "\n";

const dirs: string[] = [];
const closers: Array<() => Promise<void>> = [];
after(async () => {
  for (const c of closers.reverse()) await c();
  resetCurrentPolicyForTests("claude-code");
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

let stack: { base: string; page: AgentPageVM; seen: string[] } | null = null;
/** The recorded session, once for both tests. */
async function start() {
  if (stack) return stack;
  const tmp = mkdtempSync(join(tmpdir(), "mandu-warn-chip-"));
  dirs.push(tmp);
  const ws = join(tmp, "mandu-try");
  mkdirSync(join(ws, "deploy"), { recursive: true });
  const env = join(ws, ".env");
  writeFileSync(env, `STRIPE_KEY=${KEY}\n`);
  const conf = join(ws, "deploy", "staging.conf");
  writeFileSync(conf, CONF);
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

  // The scripted model answers each request with the next of `replies`.
  const replies: string[] = [];
  const seen: string[] = [];
  const upstream: UpstreamFetcher = async (a) => {
    const m = new MockUpstream({ sse: replies.shift() ?? buildTextSse("Done.", { deltas: 1 }) });
    const res = await m.fetcher(a);
    seen.push(m.requests.at(-1)!.bodyText);
    return res;
  };
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(await open(sock), await open(humanSock)), upstream, sessionKey: SESSION, log: () => {} });
  const port = await proxy.listen(0);
  const wired = await makeApprovalsArbiter(sock, () => ({ socketPath: adminSock }));
  assert.ok(wired?.secrets?.setPathLabel, "the production wiring connects, with the Rules page's label op");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath: sock }), log: () => {}, ...ADMIN_OPTS,
    approvalsArbiter: wired.arbiter, secretsArbiter: wired.secrets, policyDocArbiter: wired.policyDoc,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  closers.push(async () => {
    await dashboard.close(); await proxy.close(); wired.close();
    for (const c of clients) c.close();
    await arbiter.close();
  });

  type Msg = { role: string; content: unknown };
  const ask = async (messages: Msg[], reply: string): Promise<string> => {
    replies.push(reply);
    const res = await fetch(`http://127.0.0.1:${port}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-mandu-session-id": SESSION, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({ model: "claude-sonnet-4-5", stream: true, max_tokens: 512, tools: [{ name: "Read", input_schema: { type: "object" } }], messages }),
    });
    assert.equal(res.status, 200, await res.text());
    return seen.at(-1)!;
  };
  /** One turn: the question, a Read of `path` holding `text`, then the answer. */
  let history: Msg[] = [];
  let n = 0;
  const turn = async (q: string, path: string, text: string, answer: string): Promise<string> => {
    const id = `toolu_warn_${++n}`;
    let msgs: Msg[] = [...history, { role: "user", content: q }];
    await ask(msgs, buildToolUseSse({ id, name: "Read", input: { file_path: path } }));
    msgs = [
      ...msgs,
      { role: "assistant", content: [{ type: "tool_use", id, name: "Read", input: { file_path: path } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: id, content: render(text) }] },
    ];
    const got = await ask(msgs, buildTextSse(answer, { deltas: 1 }));
    history = [...msgs, { role: "assistant", content: answer }];
    await new Promise((r) => setTimeout(r, 5));
    return got;
  };

  // ── W1: the session ─────────────────────────────────────────────────────
  const got = await turn("What is in .env?", env, `STRIPE_KEY=${KEY}\n`, "It holds STRIPE_KEY.");
  assert.ok(!got.includes(KEY), "CONFIDENTIALITY VIOLATION: the key reached the model");
  assert.match(got, /\$MDU:/, "the AI got the key as a placeholder");
  assert.ok((await turn("What is in deploy/staging.conf?", conf, CONF, "A staging host and a GitHub token.")).includes(CONF_TOKEN),
    "unlabelled: the Read reaches the model as read");
  const getPage = async (): Promise<AgentPageVM> => {
    const r = await fetch(`${base}/api/home/agent?session=${SESSION}`, { headers: { Cookie: ADMIN_COOKIE } });
    assert.equal(r.status, 200);
    return (await r.json()) as AgentPageVM;
  };
  const reads = (vm?: AgentPageVM) => (vm?.story ?? []).flatMap((t) => t.steps).filter((s) => s.kind === "action" && s.icon === "file");
  let page: AgentPageVM | undefined;
  for (let i = 0; i < 200 && reads(page).length < 2; i++) {
    // emission is best-effort and asynchronous
    page = await getPage();
    if (reads(page).length < 2) await new Promise((r) => setTimeout(r, 25));
  }
  assert.equal(reads(page).length, 2, JSON.stringify(page?.story.map((t) => t.summary)));
  await new Promise((r) => setTimeout(r, 20)); // the label comes strictly after the read
  await wired.secrets!.setPathLabel!({ path: conf, confidentiality: "no-model" });
  page = await getPage();
  assert.deepEqual(reads(page).map((s) => s.kind === "action" && s.outcome), ["secret", "raw"], "the .env masked, staging.conf masked only later");
  assert.deepEqual(page.story.map((t) => t.tone), ["secret", "raw"]);
  assert.ok(page.secrets.secrets.some((c) => c.saw === "early" && c.since), "staging.conf's card: read before it was marked, and since when");
  stack = { base, page, seen };
  return stack;
}

test("a masked .env and a read masked only later are recorded, and no read carries the key, a token or the admin token (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const { base, seen } = await start();
  // ── W2: the oracle ──────────────────────────────────────────────────────
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

test("in a real Chromium: every secret chip, raw tag and raw turn summary reads 4.5:1 at the least, light and dark (secrets axes, explicit)", {
  skip: chromium ? false : "no Chromium found (MANDU_TOUR_BROWSER, CHROME_PATH, a Playwright headless shell)", timeout: 180_000,
}, async () => {
  const { base } = await start();
  const tmp = mkdtempSync(join(tmpdir(), "mandu-warn-chip-cdp-"));
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

    // ── W3: each theme, as the stored choice pins it ──────────────────────
    for (const theme of ["light", "dark"] as const) {
      await send("Page.navigate", { url: `${base}/agents/${SESSION}` });
      await until("the page loads", `document.readyState === "complete"`);
      await evaluate(`localStorage.setItem("mandu.theme", ${JSON.stringify(theme)}), true`);
      await send("Page.reload", {});
      const drawn = AMBER.map((sel) => `document.querySelectorAll(${JSON.stringify(sel)}).length > 0`).join(" && ");
      await until(`${theme}: the session page draws every amber word`, `${drawn} && document.fonts.status === "loaded"`);
      assert.equal(await evaluate(`document.documentElement.getAttribute("data-theme")`), theme, `${theme}: the stored choice pins the theme`);
      const found = await evaluate(`(() => {
        const ground = (e) => {
          for (let n = e; n; n = n.parentElement) {
            const bg = getComputedStyle(n).backgroundColor;
            if (bg && bg !== "transparent" && !/^rgba\\([^)]*,\\s*0\\)$/.test(bg)) return bg;
          }
          return getComputedStyle(document.body).backgroundColor;
        };
        return ${JSON.stringify(AMBER)}.map((sel) => [...document.querySelectorAll(sel)]
          .filter((e) => e.getClientRects().length > 0 && e.textContent.trim())
          .map((e) => ({ sel, text: e.textContent.trim().replace(/\\s+/g, " ").slice(0, 60), color: getComputedStyle(e).color, bg: ground(e) })));
      })()`) as Array<Array<{ sel: string; text: string; color: string; bg: string }>>;
      for (const [i, list] of found.entries()) assert.ok(list.length > 0, `${theme}: a ${AMBER[i]} is drawn and shows`);
      for (const e of found.flat()) {
        const ratio = contrastRatio(e.color, e.bg);
        assert.ok(ratio >= 4.5, `${theme}: ${e.sel} "${e.text}" reads ${ratio.toFixed(2)}:1 (${e.color} on ${e.bg}), under 4.5:1`);
      }
      if (theme === "light") {
        const chip = found[0]![0]!;
        assert.deepEqual([chip.color, chip.bg], ["rgb(152, 87, 0)", "rgb(251, 238, 219)"], "light: the amber #985700 on its tint");
      }
      const body = await evaluate(`document.body.innerText + document.documentElement.outerHTML`);
      assert.ok(!body.includes(KEY), `CONFIDENTIALITY VIOLATION: the ${theme} page shows the key`);
      assert.doesNotMatch(body, /\$MDU/, `the ${theme} page carries a token`);
    }
  } finally {
    cdp.close();
    await tour.stopProc(proc);
  }
});
