/**
 * product-service-cut.test — a request the protection service (the arbiter)
 * never answered because it stopped with the request on its way, on the
 * product page, across the REAL components (dashboard.md §4.25 "Refusals",
 * *A stopped service, however the route says it*, *A connection cut on its
 * way*). Mandu-new.
 *
 * Until 2026-10-11 the page said a stopped service in its own words only
 * when the route passed on the failed dial ("connect ENOENT /…") or the
 * arbiter client's words bare. A request already sent when the service
 * stopped is rejected by the client as "arbiter connection closed", which
 * the suggestion, sensitivity-label and file-browser routes wrap as "the
 * protection service did not answer (…)", so Keys Mandu found said "the
 * protection service did not answer (arbiter connection closed)" (stack
 * e2e product-could-not-read-why caught it once, on master), and a scan cut
 * short said "The scan did not finish: arbiter connection closed".
 *
 * A real ArbiterServer runs at the `secrets` axes, a real DashboardServer
 * reaches it over the production adapter (`makeApprovalsArbiter`), and the
 * served Rules page (its own index.html and home.js in jsdom) is open,
 * signed in. Between the adapter and the arbiter's data socket sits a
 * pass-through that stands for the arbiter's process: armed with an op, it
 * closes the connection that carries it, as a process that exits does,
 * and can stop the arbiter at that moment.
 *
 *   C1  the service restarts during a scan: the scan's request is cut, the
 *       next read is answered; the line under Scan says "The scan did not
 *       finish because the protection service stopped. Press Scan for keys
 *       to try again.", and Scan for keys works again;
 *   C2  the service stops with Keys Mandu found's read on its way: the line
 *       says "The protection service is not running. Start it under
 *       Settings, or try again in a moment." with its link, never the
 *       route's or the client's words;
 *   C3  the oracle: no rendered page carries the key's value, the socket
 *       path, an errno or the word "arbiter".
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { connect, createServer, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { ADMIN_COOKIE, ADMIN_OPTS } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets");

const KEY_VALUE = "sk_" + "live_productServiceCutStackCanary0001";
const SESSION = "1791900000-0130";
const UNREACHABLE_WORDS = "The protection service is not running. Start it under Settings, or try again in a moment.";
const SCAN_STOPPED = "The scan did not finish because the protection service stopped. Press Scan for keys to try again.";
/** What the route and the client say, which the page must not. */
const THEIRS = /arbiter|did not answer|connection closed|ENOENT|ECONNREFUSED|\.sock\b/;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const text = (doc: any, id: string): string => doc.getElementById(id)?.textContent ?? "";
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const links = (node: any): string[][] => [...node.querySelectorAll("a")].map((a: any) => [a.textContent, a.getAttribute("href"), a.dataset.pageLink]);
/** The page reads Home again when it is shown (its 10 s poll is inert here). */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const poll = (doc: any) => doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));

/** The arbiter's data socket as the dashboard reaches it: a pass-through
 *  at `path` to `target`. `cut(op, then)` arms it: the connection that
 *  carries the next request for `op` is closed before the request reaches
 *  the arbiter (so it gets no answer), then `then` runs. */
async function passThrough(path: string, target: string) {
  let armed: { op: string; then: () => Promise<void> } | null = null;
  const cuts: string[] = [];
  const sockets = new Set<Socket>();
  const server = createServer((down) => {
    const up = connect(target);
    sockets.add(down);
    sockets.add(up);
    let tail = "";
    const end = () => { down.destroy(); up.destroy(); sockets.delete(down); sockets.delete(up); };
    down.on("data", (chunk: Buffer) => {
      const seen = tail + chunk.toString("utf8");
      tail = seen.slice(seen.lastIndexOf("\n") + 1);
      if (armed && seen.includes(`"op":"${armed.op}"`)) {
        const { op, then } = armed;
        armed = null;
        cuts.push(op);
        end();
        void then();
        return;
      }
      up.write(chunk);
    });
    up.on("data", (chunk: Buffer) => down.write(chunk));
    down.on("close", end);
    up.on("close", end);
    down.on("error", () => {});
    up.on("error", () => {});
  });
  await new Promise<void>((resolve) => server.listen(path, resolve));
  let open = true;
  return {
    cuts,
    cut(op: string, then: () => Promise<void> = async () => {}) { armed = { op, then }; },
    async close() {
      if (!open) return;
      open = false;
      for (const s of sockets) s.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

test("a request the stopped protection service never answered is said in the page's words: a scan cut short, Keys Mandu found's list (real arbiter, production adapter, dashboard, served page)", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-service-cut-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "proj"), { recursive: true });
  const socketPath = join(tmp, "arbiter.sock");
  const viaPath = join(tmp, "via.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, adminSocketPath: adminSock, humanSocketPath: humanPath,
    dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), log: () => {},
    adminPolicyDir: null, promptPackDir: null, adminPromptPackDir: null,
    confidentiality: true, integrity: false, // the `secrets` axes, stated
  });
  await arbiter.listen();
  let arbiterOpen = true;
  const via = await passThrough(viaPath, socketPath);
  // The dashboard's own adapter, as server-main.ts builds it, dialling the
  // data socket through the pass-through; the admin channel is the
  // MANDU_ADMIN_SOCK path form of its adminTarget.
  const wired = await makeApprovalsArbiter(viaPath, () => ({ socketPath: adminSock }));
  assert.ok(wired?.policyDoc, "the production adapter has the policy surface");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath: viaPath, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter, policyDocArbiter: wired.policyDoc,
    fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mhome") },
    log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  let dashboardOpen = true;
  const unhandled: string[] = [];
  const onUnhandled = (e: unknown) => unhandled.push(String((e as Error)?.message ?? e));
  process.on("unhandledRejection", onUnhandled);
  const rendered: string[] = [];
  try {
    // A registered key in the project the scan reads, for the oracle.
    const env = join(home, "proj", ".env");
    writeFileSync(env, `API_KEY=${KEY_VALUE}\n`);
    const gate = new ArbiterClient(socketPath); await gate.connect();
    const reg = await gate.registerSecret({ path: env, sessionKey: SESSION });
    assert.match(String(reg.symbol), /^\$MDU:/, JSON.stringify(reg));
    gate.close();

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const rulesShown = (doc: any) => doc.getElementById("page-rules")?.hidden === false && text(doc, "hero-headline") !== "";
    await servedProductPage(base, "/rules", rulesShown, async (doc) => {
      const w = doc.defaultView;
      const keep = () => rendered.push(doc.body.textContent ?? "");
      const scanButton = doc.getElementById("suggest-scan");
      doc.getElementById("suggest-open").click();
      // The view's read settles first: a read on its way would be cut too.
      await waitWhile(() => !/^No suggestions\./.test(text(doc, "files-suggested-list")));
      assert.match(text(doc, "files-suggested-list"), /^No suggestions\./, "the list was read");
      assert.equal(text(doc, "suggest-error"), "");
      const scan = () => {
        doc.getElementById("suggest-root").value = join(home, "proj");
        doc.getElementById("suggest-form").dispatchEvent(new w.Event("submit", { cancelable: true }));
      };

      // C1: the service restarts during a scan. Its request is cut; the
      // next read (the route's listing) is answered.
      via.cut("suggestPolicy");
      scan();
      await waitWhile(() => text(doc, "suggest-error") !== SCAN_STOPPED);
      assert.deepEqual(via.cuts, ["suggestPolicy"], "the scan's request was cut on its way");
      assert.equal(text(doc, "suggest-error"), SCAN_STOPPED, "the page's words, never \"The scan did not finish: arbiter connection closed\"");
      assert.deepEqual(links(doc.getElementById("suggest-error")), [], "the service answers again: no Start link");
      assert.equal(scanButton.disabled, false, "Scan for keys works again");
      assert.equal(scanButton.textContent, "Scan for keys");
      keep();
      // Pressed again, the scan runs to its end and the line gives way.
      scan();
      await waitWhile(() => text(doc, "suggest-error") !== "" || scanButton.disabled || text(doc, "suggest-status") === "");
      assert.equal(text(doc, "suggest-error"), "", "the scan finished");
      assert.match(text(doc, "suggest-status"), /^(Scanned|No git history)/, text(doc, "suggest-status"));
      keep();

      // C2: the service stops with Keys Mandu found's read on its way: the
      // next poll's Home read is answered, its list read is cut, and the
      // arbiter and its socket are gone at that moment.
      via.cut("policySuggestions", async () => {
        await arbiter.close();
        arbiterOpen = false;
        await via.close();
      });
      poll(doc);
      await waitWhile(() => text(doc, "suggest-error") === "" || via.cuts.length < 2);
      assert.deepEqual(via.cuts, ["suggestPolicy", "policySuggestions"], "the list's request was cut on its way");
      const line = doc.getElementById("suggest-error");
      assert.equal(line.textContent, UNREACHABLE_WORDS, "the page's words, never \"the protection service did not answer (arbiter connection closed)\"");
      assert.deepEqual(links(line), [["Start it under Settings", "/settings", "settings"]], "Start is a link to Settings");
      assert.doesNotMatch(text(doc, "page-rules"), THEIRS, "nothing on Rules in the route's or the client's words");
      keep();
    }, { headers: { Cookie: ADMIN_COOKIE } });
    await new Promise((r) => setTimeout(r, 50));
    assert.deepEqual(unhandled, [], "no unhandled rejection in the page");

    // C3: the oracle on every page drawn above.
    assert.equal(rendered.length, 3);
    for (const r of rendered) {
      assert.ok(!r.includes(KEY_VALUE), "no rendered page carries the key's value");
      assert.ok(!r.includes(tmp), "nor a socket path");
    }
  } finally {
    process.off("unhandledRejection", onUnhandled);
    if (dashboardOpen) await dashboard.close();
    dashboardOpen = false;
    await via.close();
    if (arbiterOpen) await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
