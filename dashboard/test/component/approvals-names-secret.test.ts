/**
 * approvals-names-secret.test — a send question names the secret it would
 * send (dashboard.md §4.34 "A send names its secret"), end to end over the
 * served product page. Found 2026-10-07 on a first-time pass over Approvals
 * with real asks: every send card read "The agent wants to send a secret to
 * …", so a key of `.env` and an environment variable bound for one host
 * were the same card twice, and Always allow did not say what it allowed,
 * while the Rules row for the same answer said "sending only the file
 * ~/proj/.env".
 *
 * The REAL DashboardServer over a FileEventSource whose policy snapshot
 * serves the queue the arbiter would: each verdict with the provenance the
 * arbiter attaches at read time (`source`, arbiter/ipc/server.ts
 * withProvenance), and one without (an older arbiter). The served product
 * page (index.html, home.js) runs in jsdom with its fetch bridged to that
 * server, opened at /approvals and at /. The real-arbiter version (the
 * registry's field symbol, the env variable's, the gate's asks) is
 * tests/stack/approval-names-secret.test.ts.
 * Axes: the store serves the Secrets posture; display only, no arbiter runs.
 */

import { test, after } from "node:test";
import assert from "node:assert/strict";
import { rmSync } from "node:fs";
import { JSDOM } from "jsdom";

import { DashboardServer } from "../../src/server.js";
import { FileEventSource } from "../../src/event-source.js";
import type { PolicySnapshot, VerdictEntry } from "../../src/policy-model.js";
import type { PolicyPanelVM } from "../../src/view-model/policy-panel.js";
import { tmpDir } from "../unit/tmp-dir.js";
import { waitWhile } from "../unit/page-wait.js";
import { pageFetch } from "../unit/page-fetch.js";

const HOME = "/home/u";
const NOW = Date.now();

const ask = (over: Partial<VerdictEntry>): VerdictEntry => ({
  id: "egr-0", symbol: "", destination: "api.stripe.com", status: "pending", reason: "secret symbol (no-model) at unbound destination",
  count: 1, firstSeen: NOW - 120_000, lastSeen: NOW - 60_000, resolvedAt: null, sessions: [],
  ...over,
} as VerdictEntry);

const VERDICTS: VerdictEntry[] = [
  ask({ id: "egr-1", symbol: "$MDU:nomodel_Read[9bbd].STRIPE_KEY", lastSeen: NOW - 5_000, source: { tool: "Read", origin: `${HOME}/proj/.env` } }),
  ask({ id: "egr-2", symbol: "$MDU:nomodel_Env[e5b9].GITHUB_TOKEN", destination: "gist.github.com", lastSeen: NOW - 40_000, source: { tool: "Env", origin: "env:GITHUB_TOKEN" } }),
  ask({ id: "egr-3", symbol: "$MDU:nomodel_Read[1131]", destination: "paste.example", lastSeen: NOW - 30_000, source: { tool: "Read", origin: `${HOME}/proj/deploy/staging.conf` } }),
  ask({ id: "egr-4", symbol: "$MDU:nomodel_Read[9bbd].STRIPE_KEY", destination: "evil.example", lastSeen: NOW - 20_000 }),
  ask({ id: "egr-5", symbol: "$MDU:nomodel_Read[9bbd].STRIPE_KEY", destination: "webhook.example", status: "denied", resolvedAt: NOW - 10_000, source: { tool: "Read", origin: `${HOME}/proj/.env` } }),
];

/** A file source behind which the arbiter serves the Secrets posture and
 *  the queue above. */
class QueueSource extends FileEventSource {
  override async policySnapshot(): Promise<PolicySnapshot | null> {
    return {
      specId: "claude-code", origins: [], tools: {}, fallbackTrust: "UNTRUSTED", mcpPrefix: "mcp__",
      posture: { integrity: false, confidentiality: true },
      usage: { rules: [], sensitivePaths: [] },
      verdicts: VERDICTS,
    } as unknown as PolicySnapshot;
  }
}

const events = tmpDir("mandu-approvals-names-secret-");
const mHome = tmpDir("mandu-approvals-names-secret-home-");
const server = new DashboardServer({ source: new QueueSource(events), configEnv: { MANDU_HOME: mHome }, fileBrowserHome: HOME, log: () => {} });
const base = `http://127.0.0.1:${await server.listen(0)}`;

after(async () => {
  await server.close();
  for (const d of [events, mHome]) rmSync(d, { recursive: true, force: true });
});

/** The served page at `path`, running against the server. */
async function openPage(path: string) {
  const html = await (await pageFetch(`${base}${path}`)).text();
  const js = await (await pageFetch(`${base}/js/home.js`)).text();
  const dom = new JSDOM(html.replace(/<script type="module"[^>]*><\/script>/, ""), {
    url: `${base}${path}`, runScripts: "outside-only", pretendToBeVisual: true,
  });
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const w = dom.window as any;
  let closed = false;
  const gate = <T>(p: Promise<T>): Promise<T> =>
    p.then((v) => (closed ? new Promise<T>(() => {}) : v), (e) => (closed ? new Promise<T>(() => {}) : Promise.reject(e)));
  w.fetch = (url: string, { signal: _signal, ...init }: RequestInit = {}) =>
    gate(pageFetch(new URL(url, base).href, init).then(async (res) => {
      const body = await res.text();
      return { ok: res.ok, status: res.status, json: () => gate(Promise.resolve().then(() => JSON.parse(body))) };
    }));
  w.setInterval = () => 0;
  w.scrollTo = () => {};
  w.eval(js);
  return { doc: w.document as Document, close: () => { closed = true; w.close(); } };
}

async function until(check: () => boolean, what: string): Promise<void> {
  await waitWhile(() => !check());
  assert.ok(check(), what);
}

const squash = (s: string | null | undefined) => (s ?? "").replace(/\s+/g, " ").trim();

test("Approvals: each send card names its secret, its key or variable, else its file; the why says where it comes from, with `~`", async () => {
  const { doc, close } = await openPage("/approvals");
  try {
    const cards = () => [...doc.querySelectorAll("#approvals-waiting .ask")] as Element[];
    await until(() => cards().length === 4, `four waiting cards (got ${cards().length})`);
    const card = (id: string) => cards().find((c) => c.getAttribute("data-id") === id)!;
    const sentence = (id: string) => squash(card(id).querySelector(".ask-sentence")?.textContent);
    const why = (id: string) => squash(card(id).querySelector(".ask-detail .v")?.textContent);
    assert.equal(sentence("egr-1"), "The agent wants to send your secret STRIPE_KEY to api.stripe.com");
    assert.equal(why("egr-1"), "STRIPE_KEY comes from ~/proj/.env. Mandu masked it, so the AI never read it. Sending it would show the real secret to api.stripe.com.");
    assert.equal(sentence("egr-2"), "The agent wants to send your secret GITHUB_TOKEN to gist.github.com");
    assert.match(why("egr-2"), /^GITHUB_TOKEN is an environment variable\. Mandu masked it/);
    assert.equal(sentence("egr-3"), "The agent wants to send a secret from ~/proj/deploy/staging.conf to paste.example");
    // The name and the file are code, like the destination.
    assert.deepEqual([...card("egr-1").querySelectorAll(".ask-sentence code")].map((c) => c.textContent), ["STRIPE_KEY", "api.stripe.com"]);
    assert.deepEqual([...card("egr-3").querySelectorAll(".ask-sentence code")].map((c) => c.textContent), ["~/proj/deploy/staging.conf", "paste.example"]);
    // An arbiter that did not say where it came from: as before.
    assert.equal(sentence("egr-4"), "The agent wants to send a secret to evil.example");
    assert.match(why("egr-4"), /^Mandu masked it, so the AI never read it\./);
    // Answered earlier names it too, whole: the words wrap in the row's
    // widest cell, when on the line under them (§4.25, *Read in full*). Until
    // 2026-10-08 they kept one ellipsized line, so a phone read "…your
    // secret STRIPE_…" above Allow instead.
    await until(() => doc.querySelectorAll("#approvals-answered .row.answered").length === 1, "one answered row");
    const answered = doc.querySelector("#approvals-answered .row.answered")!;
    assert.match(squash(answered.textContent), /^The agent wants to send your secret STRIPE_KEY to webhook\.example/);
    assert.equal(answered.querySelector(".ellipsis"), null, "nothing in the row is cut to one line");
    const what = answered.firstElementChild!;
    assert.equal(what.className, "answered-what");
    assert.equal(squash(what.querySelector(".answered-sentence")?.textContent), "The agent wants to send your secret STRIPE_KEY to webhook.example");
    assert.equal(what.lastElementChild?.className, "dim answered-when");
    assert.equal(what.lastElementChild?.querySelector("time")?.getAttribute("datetime"), new Date(NOW - 10_000).toISOString());
    assert.deepEqual([...answered.children].slice(1).map((c) => squash(c.textContent)), ["Blocked", "Allow instead"], "then the answer and its reversal");
    // Never the token on the product page.
    assert.doesNotMatch(doc.body.textContent ?? "", /\$MDU/);
  } finally {
    close();
  }
});

test("Home: the waiting card names the secret and says where it comes from", async () => {
  const { doc, close } = await openPage("/");
  try {
    // The newest ask (Home shows the first three).
    const card = () => doc.querySelector('#home-waiting .ask[data-id="egr-1"]');
    await until(() => card() !== null, "the STRIPE_KEY card is on Home");
    assert.equal(squash(card()!.querySelector(".ask-sentence")?.textContent), "The agent wants to send your secret STRIPE_KEY to api.stripe.com");
    assert.match(squash(card()!.querySelector(".ask-sub")?.textContent), /^STRIPE_KEY comes from ~\/proj\/\.env\. /);
  } finally {
    close();
  }
});

test("the served queue: the inspector's words name it with the full path; /api/home carries words, never the origin or the token", async () => {
  const panel = ((await (await pageFetch(`${base}/api/policy/panel`)).json()) as { panel: PolicyPanelVM }).panel;
  const row = panel.queue.find((r) => r.id === "egr-1")!;
  assert.equal(row.origin, `${HOME}/proj/.env`);
  assert.equal(row.words.sentence.map((p) => p.text).join(""), "The agent wants to send your secret STRIPE_KEY to api.stripe.com");
  assert.match(row.words.why ?? "", /^STRIPE_KEY comes from \/home\/u\/proj\/\.env\. /);
  const home = await (await pageFetch(`${base}/api/home`)).text();
  assert.match(home, /STRIPE_KEY comes from ~\/proj\/\.env\./);
  assert.doesNotMatch(home, /\$MDU|"origin"/);
});
