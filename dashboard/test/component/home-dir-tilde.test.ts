/**
 * home-dir-tilde.test — `~` is the dashboard's home (dashboard.md §4.34),
 * end to end over the served product page. Before 2026-10-07 the page's
 * `shortPath` and the Rules words (`rule-words.ts compactPath`) turned ANY
 * `/home/<name>/` into `~`, so another account's file read as the person's
 * own, while a macOS home was never shortened; and the Approvals card named
 * a program under the home in full, the account name the first-session
 * tour's screenshots had to redact (work ledger, tour item 2).
 *
 * The REAL DashboardServer over a FileEventSource whose policy snapshot
 * serves an approval queue: a waiting program read (an interpreter under the
 * home running a script there), answered sends from the person's own file
 * and from another account's, and an answered file. The served product page
 * (index.html with the server's `home-dir`, home.js) runs in jsdom with its
 * fetch bridged to that server. Display words only: no value is in any row.
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
const H = "c".repeat(64);

const ask = (over: Partial<VerdictEntry>): VerdictEntry => ({
  id: "egr-0", symbol: "", destination: "paste.example", status: "approved", reason: "held for the human",
  count: 1, firstSeen: NOW - 120_000, lastSeen: NOW - 60_000, resolvedAt: NOW - 30_000, sessions: [],
  ...over,
} as VerdictEntry);

const VERDICTS: VerdictEntry[] = [
  ask({ id: "egr-1", symbol: `open:${HOME}/.nvm/versions/node/v22.11.0/bin/node#${H}#script:${encodeURIComponent(`${HOME}/proj/x.js`)}#${H}`, destination: `${HOME}/proj/.env`, status: "pending", resolvedAt: null, lastSeen: NOW - 5_000 }),
  ask({ id: "egr-2", symbol: "$MDU:Read[727f].notes.md", source: { tool: "Read", origin: `${HOME}/proj/notes.md` } }),
  ask({ id: "egr-3", symbol: "$MDU:Read[727e].notes.md", destination: "notes-sink.test", source: { tool: "Read", origin: "/home/alice/proj/notes.md" } }),
  ask({ id: "egr-4", symbol: `open:/usr/bin/cat#${H}`, destination: `${HOME}/.pgpass` }),
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

const events = tmpDir("mandu-home-dir-tilde-");
const mHome = tmpDir("mandu-home-dir-tilde-home-");
const server = new DashboardServer({ source: new QueueSource(events), configEnv: { MANDU_HOME: mHome }, fileBrowserHome: HOME, log: () => {} });
const base = `http://127.0.0.1:${await server.listen(0)}`;
// A home folder whose name would break the page's markup if written raw.
const oddHome = '/home/a"b<c&d';
const odd = new DashboardServer({ source: new QueueSource(events), configEnv: { MANDU_HOME: mHome }, fileBrowserHome: oddHome, log: () => {} });
const oddBase = `http://127.0.0.1:${await odd.listen(0)}`;

after(async () => {
  await server.close();
  await odd.close();
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
const metaOf = (html: string, name: string) =>
  new JSDOM(html).window.document.querySelector(`meta[name="${name}"]`)?.getAttribute("content") ?? null;

test("the product page is served with the dashboard's home folder, escaped; the inspector's page is not", async () => {
  assert.equal(metaOf(await (await pageFetch(`${base}/`)).text(), "home-dir"), HOME);
  assert.equal(metaOf(await (await pageFetch(`${base}/rules`)).text(), "home-dir"), HOME, "every product route serves it");
  assert.equal(metaOf(await (await pageFetch(`${base}/dev/`)).text(), "home-dir"), null, "the inspector keeps full paths");
  const oddHtml = await (await pageFetch(`${oddBase}/`)).text();
  assert.equal(metaOf(oddHtml, "home-dir"), oddHome, "a folder name with quotes or brackets reads back exactly");
  assert.ok(!oddHtml.includes(oddHome), "and is never written into the markup raw");
});

test("Approvals: a program and its script under the home read `~/…`; the inspector's card keeps the full path", async () => {
  const { doc, close } = await openPage("/approvals");
  try {
    const card = () => doc.querySelector('#approvals-waiting .ask[data-id="egr-1"]');
    await until(() => !!card(), "the waiting program read");
    assert.equal(squash(card()!.querySelector(".ask-sentence")?.textContent),
      "The agent's program ~/.nvm/versions/node/v22.11.0/bin/node running ~/proj/x.js wants to read a secret file: .env");
    assert.match(squash(card()!.textContent), /The AI's program ~\/\.nvm\/versions\/node\/v22\.11\.0\/bin\/node running ~\/proj\/x\.js (is waiting for your answer now, and goes on at once: it reads|stopped waiting and could not read the file)/);
    assert.ok(!squash(card()!.textContent).includes(`${HOME}/`), "no path under the home is spelled out on the card");
  } finally {
    close();
  }
  const { panel } = await (await pageFetch(`${base}/api/policy/panel`)).json() as { panel: PolicyPanelVM };
  const row = panel.queue.find((q) => q.id === "egr-1")!;
  assert.equal(row.words!.sentence.map((p) => p.text).join(""),
    `The agent's program ${HOME}/.nvm/versions/node/v22.11.0/bin/node running ${HOME}/proj/x.js wants to read a secret file: .env`);
});

test("Rules: an answer's file is `~/…` only under the dashboard's home; another account's file stays as recorded", async () => {
  const { panel } = await (await pageFetch(`${base}/api/policy/panel`)).json() as { panel: PolicyPanelVM };
  const reach = (id: string) => panel.queue.find((q) => q.id === id)!.plain!.reach;
  assert.equal(reach("egr-2"), "sending only the file ~/proj/notes.md");
  assert.equal(reach("egr-3"), "sending only the file /home/alice/proj/notes.md", "alice's file is never `~`");
  const { doc, close } = await openPage("/rules");
  try {
    const rows = () => [...doc.querySelectorAll("#rules-list .row")].map((r) => squash(r.textContent));
    await until(() => rows().some((t) => t.includes("pgpass")), `the answered rows (got ${rows().length})`);
    assert.ok(rows().some((t) => t.includes("sending only the file ~/proj/notes.md")), rows().join("\n"));
    assert.ok(rows().some((t) => t.includes("sending only the file /home/alice/proj/notes.md")), rows().join("\n"));
    const file = [...doc.querySelectorAll("#rules-list .row")].find((r) => /pgpass/.test(r.textContent ?? ""))!;
    assert.equal(file.querySelector("code")?.textContent, "~/.pgpass", "an answer about one file names it as the file rules do");
  } finally {
    close();
  }
});
