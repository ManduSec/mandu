/**
 * show-more-answers.test — the product page's two Show more buttons that
 * read the server for the next page, across the REAL components
 * (dashboard.md §4.25ae *History*, §4.25m *Browsing*). Mandu-new.
 *
 * Until 2026-10-15 a History Show more that failed was drawn away, its words
 * in its place, so the keyboard focus fell to <body> and nothing tried again
 * until a poll; the file browser's Show more said nothing when its read
 * failed, and when it answered, the focus fell to <body>. Here a real
 * ArbiterServer runs at the `secrets` axes with a policy.yaml rule on a
 * file, the REAL anthropic-proxy on its production client carries one
 * session that reads a `.env`, the launcher's real `session_exit` records
 * 25 more, and a real DashboardServer reaches the arbiter over a real
 * ArbiterEventSource and the production adapter (`makeApprovalsArbiter`).
 * The served product page (its own index.html and home.js in jsdom) stays
 * open while the service and a folder go away under it:
 *
 *   S1  History (signed out) lists 25 of 26 sessions; the service stops and
 *       Show more says so beside the button, which keeps the focus; the
 *       service starts again and the same Show more brings the 26th row,
 *       which takes the focus;
 *   S2  the file browser (signed in) in a folder of 502 entries lists 500;
 *       the folder is renamed and Show more says the route's own words over
 *       the button, which keeps the focus; renamed back, the same Show more
 *       brings the last two entries and the first takes the focus;
 *   S3  no unhandled rejection in the page; the oracle: the model never got
 *       the `.env` value, and no rendered page carries it, the labelled
 *       file's value or a token.
 *
 * Axes: secrets (stated; the arbiter's confidentiality pinned ON).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { Readable } from "node:stream";
import { mkdirSync, mkdtempSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy, type UpstreamFetcher } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { buildTextSse, sseEvent } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { emitLauncherEvent, sessionExitEvent } from "../../launcher/src/services/observe.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import type { HistoryVM } from "../../dashboard/src/view-model/home.js";
import { ADMIN_COOKIE, ADMIN_OPTS } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const ENV_VALUE = `sk_live_showMoreEnvCanary_${process.pid}_00000`;
const KEY_VALUE = `sk_live_showMoreKeyCanary_${process.pid}_00000`;
/** The session that reads the `.env`, the oldest; the launcher records 25 after it. */
const FIRST = `1791700000-${process.pid}`;
const LATER = Array.from({ length: 25 }, (_, i) => `${1791700100 + i}-${process.pid}`);
const FILES = 501; // f000.txt … f500.txt, with deploy.token: 502 entries, 500 a page

function readTurn(path: string): string {
  return sseEvent("message_start", { type: "message_start", message: { id: "msg_sm_1", role: "assistant", content: [] } })
    + sseEvent("content_block_start", { type: "content_block_start", index: 0, content_block: { type: "tool_use", id: "toolu_sm_0", name: "Read", input: {} } })
    + sseEvent("content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "input_json_delta", partial_json: JSON.stringify({ file_path: path }) } })
    + sseEvent("content_block_stop", { type: "content_block_stop", index: 0 })
    + sseEvent("message_delta", { type: "message_delta", delta: { stop_reason: "tool_use" } })
    + sseEvent("message_stop", { type: "message_stop" });
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const historyRows = (doc: any) => [...doc.querySelectorAll("#history-list .row.agent")] as any[];
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const historyMore = (doc: any) => doc.querySelector("#history-list .history-more") as any;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const fileRows = (doc: any) => [...doc.querySelectorAll("#files-list .row.file:not(.up)")] as any[];
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const filesMore = (doc: any) => doc.querySelector("#files-list .files-more") as any;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const describedBy = (doc: any, btn: any): string | undefined => doc.getElementById(btn.getAttribute("aria-describedby"))?.textContent;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const go = (doc: any) => doc.getElementById("files-go").dispatchEvent(new doc.defaultView.Event("submit", { cancelable: true }));

test("Show more on the product page: a failure says why beside the button, which keeps the focus, and the answer's first row takes it (History signed out, the file browser signed in; real arbiter, proxy, launcher events, production adapter, dashboard, served page; secrets axes, explicit)", { timeout: 240_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-show-more-"));
  const home = join(tmp, "home");
  const ws = join(home, "ws");
  const big = join(home, "big");
  mkdirSync(ws, { recursive: true });
  mkdirSync(big, { recursive: true });
  const env = join(ws, ".env");
  writeFileSync(env, `STRIPE_KEY=${ENV_VALUE}\n`);
  writeFileSync(join(big, "deploy.token"), `${KEY_VALUE}\n`);
  for (let i = 0; i < FILES; i++) writeFileSync(join(big, `f${String(i).padStart(3, "0")}.txt`), "nothing secret\n");
  const socketPath = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanPath = humanSockIn(tmp);
  const policy = join(tmp, "policy.yaml");
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${join(big, "deploy.token")}\n    level: no-model\n`);
  // One protection service, then another on the same sockets and store, as
  // a start from a terminal or Settings brings it back.
  const serve = () => new ArbiterServer({
    socketPath, adminSocketPath: adminSock, humanSocketPath: humanPath,
    dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), log: () => {},
    policyPath: policy, policyPollMs: 0,
    adminPolicyDir: null, promptPackDir: null, adminPromptPackDir: null,
    confidentiality: true, integrity: false, // the `secrets` axes, stated
  });
  let arbiter = serve();
  await arbiter.listen();
  let arbiterOpen = true;
  const wired = await makeApprovalsArbiter(socketPath, () => ({ socketPath: adminSock }));
  assert.ok(wired?.secrets, "the production adapter has the secrets surface");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter, secretsArbiter: wired.secrets, policyDocArbiter: wired.policyDoc,
    fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mhome"), MANDU_POLICY_FILE: policy },
    log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const unhandled: string[] = [];
  const onUnhandled = (e: unknown) => unhandled.push(String((e as Error)?.message ?? e));
  process.on("unhandledRejection", onUnhandled);
  const rendered: string[] = [];
  const seen: string[] = [];
  /** The server's History once `done` holds for it (emission is asynchronous). */
  const history = async (done: (h: HistoryVM) => boolean): Promise<HistoryVM> => {
    let h: HistoryVM = { total: 0, rows: [], next: null };
    let text = "";
    for (let i = 0; i < 400; i++) {
      const res = await pageFetch(`${base}/api/home/history`);
      text = await res.text();
      if (res.ok) {
        h = JSON.parse(text) as HistoryVM;
        if (done(h)) break;
      }
      await new Promise((r) => setTimeout(r, 25));
    }
    assert.ok(done(h), text.slice(0, 600));
    return h;
  };
  try {
    // The first session reads the .env through the REAL proxy (production
    // client); the model gets a placeholder.
    const data = new ArbiterClient(socketPath); await data.connect();
    const human = new ArbiterClient(humanPath); await human.connect();
    const upstream: UpstreamFetcher = async ({ body }) => {
      seen.push(body.toString("utf8"));
      const sse = seen.length === 1 ? readTurn(env) : buildTextSse("Done.", { deltas: 1 });
      return { status: 200, headers: { "content-type": "text/event-stream" }, body: Readable.from([Buffer.from(sse, "utf8")]) };
    };
    const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(data, human), upstream, sessionKey: FIRST, log: () => {} });
    const port = await proxy.listen(0);
    // Through pageFetch, a socket of its own, as every request in a file
    // that runs a served page (served-page-fetch.test.ts).
    const ask = async (messages: unknown[]) => {
      const res = await pageFetch(`http://127.0.0.1:${port}/v1/messages`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-mandu-session-id": FIRST, "anthropic-version": "2023-06-01" },
        body: JSON.stringify({ model: "claude-opus-4", stream: true, max_tokens: 512, tools: [{ name: "Read", input_schema: { type: "object" } }], messages }),
      });
      assert.equal(res.status, 200, await res.text());
    };
    const q = "Read the .env file.";
    await ask([{ role: "user", content: q }]);
    await ask([
      { role: "user", content: q },
      { role: "assistant", content: [{ type: "tool_use", id: "toolu_sm_0", name: "Read", input: { file_path: env } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_sm_0", content: `     1\tSTRIPE_KEY=${ENV_VALUE}\n` }] },
    ]);
    assert.ok(!seen.join("\n").includes(ENV_VALUE), "CONFIDENTIALITY VIOLATION: the model got the .env value");
    await history((h) => h.rows.some((r) => r.id === FIRST && r.secrets.masked === 1));
    await proxy.close();
    data.close();
    human.close();
    // 25 more sessions, each recorded by the launcher's real exit event.
    for (const id of LATER) {
      assert.ok(await emitLauncherEvent(socketPath, sessionExitEvent({ scopeId: id, code: 0, durationMs: 1_000 }), humanPath), "the launcher's emit lands");
    }
    await history((h) => h.total === 26);

    // S1: History, signed out.
    await servedProductPage(base, "/history", (doc) => historyRows(doc).length === 25 && !!historyMore(doc), async (doc) => {
      const keep = () => rendered.push(doc.body.textContent ?? "");
      assert.equal(historyMore(doc).textContent, "1 more session. Show more");
      keep();
      await arbiter.close(); arbiterOpen = false;
      let btn = historyMore(doc).querySelector("button");
      btn.focus();
      btn.click();
      await waitWhile(() => /^1 more session/.test(historyMore(doc).textContent));
      assert.equal(historyMore(doc).textContent, "Could not read more of the history. The protection service is not running. Show more");
      btn = historyMore(doc).querySelector("button");
      assert.equal(btn.disabled, false, "Show more stays, to try again");
      assert.equal(describedBy(doc, btn), "Could not read more of the history. The protection service is not running.");
      assert.equal(doc.activeElement, btn, "the focus is back on Show more, never on <body>");
      assert.equal(historyRows(doc).length, 25, "the rows drawn stay");
      keep();

      arbiter = serve();
      await arbiter.listen(); arbiterOpen = true;
      await history((h) => h.total === 26);
      btn.click();
      await waitWhile(() => historyRows(doc).length < 26);
      assert.equal(historyRows(doc).length, 26);
      assert.equal(doc.activeElement, historyRows(doc)[25], "the row it brought takes the focus");
      assert.equal(historyMore(doc), null, "nothing more");
      assert.match(historyRows(doc).find((r) => r.dataset.session === FIRST)?.textContent ?? "", /1 secret masked/);
      keep();
    });

    // S2: the file browser under Rules › Add a rule, signed in.
    await servedProductPage(base, "/rules", (doc) => (doc.getElementById("files-tree")?.textContent ?? "").includes("deploy.token"), async (doc) => {
      const keep = () => rendered.push(doc.body.textContent ?? "");
      doc.getElementById("rules-add").click();
      await waitWhile(() => !doc.querySelector("#files-list .row.file"));
      (doc.getElementById("lock-path") as { value: string }).value = "~/big/";
      go(doc);
      await waitWhile(() => fileRows(doc).length < 500);
      assert.equal(fileRows(doc).length, 500);
      assert.equal(filesMore(doc).textContent, "Show more (2 more)");
      assert.match(fileRows(doc)[0].textContent, /deploy\.token/);
      keep();

      renameSync(big, `${big}-moved`);
      let btn = filesMore(doc);
      btn.focus();
      btn.click();
      await waitWhile(() => !doc.getElementById("files-more-words"));
      const words = "Could not read more of this folder: That folder does not exist. Use ~ to go to your home folder.";
      assert.equal(doc.getElementById("files-more-words").textContent, words);
      btn = filesMore(doc);
      assert.equal(btn.textContent, "Show more (2 more)", "Show more stays, to try again");
      assert.equal(describedBy(doc, btn), words);
      assert.equal(doc.activeElement, btn, "the focus is back on Show more, never on <body>");
      assert.equal(fileRows(doc).length, 500, "the entries drawn stay");
      keep();

      renameSync(`${big}-moved`, big);
      btn.click();
      await waitWhile(() => fileRows(doc).length < 502);
      assert.equal(fileRows(doc).length, 502);
      const brought = fileRows(doc).find((r) => r.getAttribute("data-path") === join(big, "f499.txt"));
      assert.ok(brought, "the next page is drawn");
      assert.equal(doc.activeElement, brought.querySelector(".file-tick"), "the first entry it brought takes the focus");
      assert.equal(doc.getElementById("files-more-words"), null, "the words go with the answer");
      assert.equal(filesMore(doc), null, "nothing more");
      keep();
    }, { headers: { Cookie: ADMIN_COOKIE } });
    await new Promise((r) => setTimeout(r, 50));
    assert.deepEqual(unhandled, [], "no unhandled rejection in the page");

    // S3: the oracle on every page drawn above.
    assert.equal(rendered.length, 6);
    for (const page of rendered) {
      assert.ok(!page.includes(ENV_VALUE), "CONFIDENTIALITY VIOLATION: a rendered page carries the .env value");
      assert.ok(!page.includes(KEY_VALUE), "CONFIDENTIALITY VIOLATION: a rendered page carries the labelled file's value");
      assert.doesNotMatch(page, /\$MDU/, "nor a token");
    }
  } finally {
    process.off("unhandledRejection", onUnhandled);
    await dashboard.close();
    if (arbiterOpen) await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
