/**
 * product-could-not-read-why.test — the agent page, Settings › Protection and
 * Settings › Prompt filters say why they could not be read, across the REAL
 * components (dashboard.md §4.25 *A could-not line names the cause the page
 * knows*). Mandu-new.
 *
 * Until 2026-10-10 these three were left out of the could-not words: the
 * agent page said "The dashboard could not load this session." for an error
 * and for no answer alike, Settings › Protection said "The protection
 * settings could not be read." with no cause, and Prompt filters said "The
 * protection service did not answer." (its route's words for the failed
 * dial) where Models and Sensitivity labels beside it said the service is
 * not running. Here a real ArbiterServer runs at the `secrets` axes, a real
 * DashboardServer reaches it over the production adapter
 * (`makeApprovalsArbiter`), and two served product pages (its own index.html
 * and home.js in jsdom) stay open while the components stop under them: a
 * session's agent page signed out, and Settings signed in.
 *
 *   W1  both running: the agent page shows the session; Settings ›
 *       Protection reads config.toml and Prompt filters lists its kinds;
 *   W2  the arbiter stops: Prompt filters says the service is not running
 *       with the link, the same words as Sensitivity labels; Settings ›
 *       Protection still reads (config.toml is the dashboard's); the agent
 *       page says "Not connected";
 *   W3  the dashboard server stops too: Settings › Protection says "The
 *       protection settings could not be read. The dashboard could not
 *       reach its own server. Refresh in a moment.", its switch off limits;
 *       the agent page says "Session not loaded" with "This session could
 *       not be loaded." and the same cause; no unhandled rejection;
 *   W4  the oracle: no rendered page carries the session's secret value,
 *       and the signed-out agent page no token.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
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

const KEY_VALUE = "sk_live_productCouldNotReadWhyCanary0001";
const SESSION = "1791900000-1830";
const DOWN_LINKED = "The protection service is not running. Start it under Settings, or try again in a moment.";
const GONE = "The dashboard could not reach its own server. Refresh in a moment.";
const PROTECT_LEAD = "The protection settings could not be read.";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const text = (doc: any, sel: string): string => doc.querySelector(sel)?.textContent ?? "";
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const links = (doc: any, sel: string) => [...doc.querySelectorAll(`${sel} a`)].map((a: any) => [a.textContent, a.getAttribute("href")]);
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const promptKinds = (doc: any): number => doc.querySelectorAll("#settings-prompt-kinds .prompt-kind").length;
/** Open a page of the product as its nav does. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const visit = (doc: any, page: string) => doc.querySelector(`[data-page-link="${page}"]`)
  .dispatchEvent(new doc.defaultView.MouseEvent("click", { bubbles: true, cancelable: true, button: 0 }));
/** The page reads again when it is shown (its 10 s poll is inert here). */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const poll = (doc: any) => doc.dispatchEvent(new doc.defaultView.Event("visibilitychange"));

test("the agent page, Settings › Protection and Prompt filters say why they could not be read: the service stopped, then the dashboard gone (real arbiter, production adapter, dashboard, served pages)", { timeout: 240_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-could-not-read-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "proj"), { recursive: true });
  const socketPath = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanPath = humanSockIn(tmp);
  const policy = join(tmp, "policy.yaml");
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${join(home, "proj", "deploy.token")}\n    level: no-model\n`);
  const arbiter = new ArbiterServer({
    socketPath, adminSocketPath: adminSock, humanSocketPath: humanPath,
    dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), log: () => {},
    policyPath: policy, policyPollMs: 0,
    adminPolicyDir: null, promptPackDir: null, adminPromptPackDir: null,
    confidentiality: true, integrity: false, // the `secrets` axes, stated
  });
  await arbiter.listen();
  let arbiterOpen = true;
  const wired = await makeApprovalsArbiter(socketPath, () => ({ socketPath: adminSock }));
  assert.ok(wired?.policyDoc, "the production adapter has the policy surface");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter, policyDocArbiter: wired.policyDoc,
    fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mhome"), MANDU_POLICY_FILE: policy },
    log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  let dashboardOpen = true;
  const unhandled: string[] = [];
  const onUnhandled = (e: unknown) => unhandled.push(String((e as Error)?.message ?? e));
  process.on("unhandledRejection", onUnhandled);
  const rendered: { page: string; signedIn: boolean; text: string }[] = [];
  try {
    // A session whose events carry a registered secret's value where the
    // proxies put it, for the oracle: no page below may show it.
    const env = join(home, "proj", ".env");
    writeFileSync(env, `API_KEY=${KEY_VALUE}\n`);
    const gate = new ArbiterClient(socketPath); await gate.connect();
    const human = new ArbiterClient(humanPath); await human.connect();
    const reg = await gate.registerSecret({ path: env, sessionKey: SESSION });
    const sym = String(reg.symbol);
    assert.match(sym, /^\$MDU:/, JSON.stringify(reg));
    const now = (): string => new Date().toISOString();
    const dual = (symbolized: string, original: string) => ({ symbolized, original, differs: true, symbols: [{ name: sym, tool: "Read", field: null, origin: env, value: original, confidentiality: "no-model" }] });
    await human.emit({ id: "cnr-call", sessionId: SESSION, ts: now(), kind: "tllm_call", view: "AgentView", boundary: "model_context", emitter: "anthropic-proxy", input: { symbolized: "Read .env", original: null, differs: false, symbols: [] } } as never);
    await human.emit({ id: "cnr-result", sessionId: SESSION, ts: now(), kind: "tool_result", view: "AgentView", boundary: "model_context", emitter: "anthropic-proxy", callId: "c1", output: dual(sym, `API_KEY=${KEY_VALUE}`) } as never);
    gate.close(); human.close();

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const agentShown = (doc: any) => text(doc, "#agent-name") !== "Agent";
    await servedProductPage(base, `/agents/${SESSION}`, agentShown, async (agentDoc) => {
      const keepAgent = () => rendered.push({ page: "agent", signedIn: false, text: agentDoc.body.textContent ?? "" });
      // W1: the session is shown (signed out: only what the AI saw).
      assert.doesNotMatch(text(agentDoc, "#agent-name"), /^(Session not (found|loaded)|Not connected)$/, text(agentDoc, "#agent-sub"));
      assert.equal(agentDoc.getElementById("agent-story-block").hidden, false, "its story is shown");
      keepAgent();

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const settingsRead = (doc: any) => promptKinds(doc) > 0 && text(doc, "#settings-protect-text") !== "Checking…";
      await servedProductPage(base, "/settings", settingsRead, async (doc) => {
        const keep = () => rendered.push({ page: "settings", signedIn: true, text: doc.body.textContent ?? "" });
        // W1: Settings reads config.toml and the prompt filters.
        assert.doesNotMatch(text(doc, "#settings-protect-text"), /could not be read/);
        assert.equal(doc.getElementById("switch-protection").disabled, false);
        assert.ok(promptKinds(doc) > 0, "the prompt filters are listed");
        keep();

        // W2: the protection service stops; Settings is opened again.
        visit(doc, "home");
        await arbiter.close();
        arbiterOpen = false;
        poll(doc);
        await waitWhile(() => text(doc, "#hero-headline") !== "Not connected.");
        visit(doc, "settings");
        await waitWhile(() => text(doc, "#settings-labels") !== DOWN_LINKED || text(doc, "#settings-prompt-kinds") !== DOWN_LINKED);
        assert.equal(text(doc, "#settings-labels"), DOWN_LINKED);
        assert.equal(text(doc, "#settings-prompt-kinds"), DOWN_LINKED, "the same words as Sensitivity labels, never \"did not answer\"");
        assert.deepEqual(links(doc, "#settings-prompt-kinds"), [["Start it under Settings", "/settings"]]);
        assert.equal(promptKinds(doc), 0);
        assert.doesNotMatch(text(doc, "#settings-protect-text"), /could not be read/, "config.toml is the dashboard's own read");
        keep();
        poll(agentDoc);
        await waitWhile(() => text(agentDoc, "#agent-name") !== "Not connected");
        assert.equal(text(agentDoc, "#agent-name"), "Not connected");
        keepAgent();

        // W3: the dashboard server goes too; no read gets an answer.
        await dashboard.close();
        dashboardOpen = false;
        poll(doc);
        await waitWhile(() => text(doc, "#hero-sentence") !== GONE);
        visit(doc, "settings");
        await waitWhile(() => text(doc, "#settings-protect-text") !== `${PROTECT_LEAD} ${GONE}`);
        assert.equal(text(doc, "#settings-protect-text"), `${PROTECT_LEAD} ${GONE}`);
        assert.equal(doc.getElementById("switch-protection").disabled, true, "the switch is off limits");
        assert.equal(text(doc, "#settings-prompt-kinds"), GONE);
        keep();
        poll(agentDoc);
        await waitWhile(() => text(agentDoc, "#agent-name") !== "Session not loaded");
        assert.equal(text(agentDoc, "#agent-name"), "Session not loaded");
        assert.equal(text(agentDoc, "#agent-sub"), `This session could not be loaded. ${GONE}`);
        assert.equal(agentDoc.getElementById("agent-story-block").hidden, true, "nothing of the session is left");
        keepAgent();
      }, { headers: { Cookie: ADMIN_COOKIE } });
    });
    await new Promise((r) => setTimeout(r, 50));
    assert.deepEqual(unhandled, [], "no unhandled rejection in the pages");
    assert.doesNotMatch(rendered.map((r) => r.text).join("\n"), /did not answer|could not load this session|fetch failed|Failed to fetch/, "never the old words, nor the browser's");

    // W4: the oracle on every page drawn above.
    assert.ok(rendered.length >= 6);
    for (const r of rendered) {
      assert.ok(!r.text.includes(KEY_VALUE), `no rendered page carries the secret value (${r.page})`);
      if (!r.signedIn) assert.doesNotMatch(r.text, /\$MDU/, `nor a token (${r.page})`);
    }
  } finally {
    process.off("unhandledRejection", onUnhandled);
    if (dashboardOpen) await dashboard.close();
    if (arbiterOpen) await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
