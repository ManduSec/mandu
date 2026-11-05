/**
 * product-command-copy — every command the product page asks you to run has
 * a Copy, and only those, across the REAL components (dashboard.md §4.25b,
 * *A command Mandu asks you to run has one too*). Mandu-new.
 *
 * Until 2026-10-26 only a fenced block in an agent's reply had a Copy; the
 * security update's `curl -fsSL … | sh`, the first-run commands, `mandu
 * scan` and a session's `mandu log <id>` were bare codes to select by hand.
 * Here a real ArbiterServer runs at the `secrets` axes with a labelled
 * `.env`; a real DashboardServer over a real ArbiterEventSource serves the
 * product page (no extensions), signed in, its Mandu home holding the
 * launcher's update-check cache (written by the launcher's own writer)
 * naming a newer release with security fixes:
 *
 *   C1  no session yet: the served Home (its own index.html and home.js in
 *       jsdom, a stubbed clipboard) draws the first-run card, the scan card
 *       and the security notice; each Copy on the page writes one of the
 *       expected commands, exactly (the launcher's install line in full,
 *       each first-run command `/api/home` names, `mandu scan` (Home's
 *       scan card and History's scan line), `mandu dashboard
 *       --set-password`), named for it; Settings › About's update
 *       line too;
 *   C2  a session whose two commands could not start (the real
 *       anthropic-proxy on its production wiring, as
 *       product-session-notice.test.ts drives it) and which read the
 *       labelled file: its served page's notice has the one Copy that
 *       writes `mandu log <session>`; the read's masked value and the
 *       commands the AI ran get none;
 *   C4  the rest of the commands (#193): Settings › About's `mandu doctor`
 *       and Settings › Protection's `mandu dashboard` (this dashboard is
 *       started without the service controls, as the render harness starts
 *       it) each draw a Copy that writes exactly the command, named for
 *       it, the sentence's words as before;
 *   C3  the oracle: no Copy sits on text holding the secret's value, a
 *       mask chip or a token, the clipboard never gets the value, and the
 *       model never got it raw.
 *
 * Axes: secrets (stated; the arbiter's confidentiality pinned ON).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { MockUpstream, buildTextSse, buildToolUseSse } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { emitLauncherEvent, launchPostureEvent } from "../../launcher/src/services/observe.js";
import * as launcherUpdate from "../../launcher/src/update-check.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { manduPath } from "../../dashboard/src/generated/mandu-paths.js";
import type { HomeVM } from "../../dashboard/src/view-model/home.js";
import { ADMIN_COOKIE, ADMIN_OPTS } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the product default

const CANARY = `CMD_COPY_STACK_CANARY_${process.pid}_7e1b`;
const NOT_FOUND = "Exit code 127\n/bin/bash: line 1: python3: command not found";
const NEWER = "99.0.0";
const INSTALL = launcherUpdate.installLine(NEWER, "release");
const SET_PASSWORD = "mandu dashboard --set-password";
const SIGNED_IN = { Cookie: ADMIN_COOKIE };
const TOOLS = [
  { name: "Bash", description: "run", input_schema: { type: "object" } },
  { name: "Read", description: "read", input_schema: { type: "object" } },
];

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;

/** A clipboard for the page, its writes kept in `wrote`. */
function clipboard(wrote: string[]) {
  return (w: Doc) => {
    Object.defineProperty(w.navigator, "clipboard", { configurable: true, value: { writeText: (t: string) => (wrote.push(t), w.Promise.resolve()) } });
  };
}

/** Every Copy on the page: its command, its name; pressed in turn. */
async function pressEach(doc: Doc): Promise<Array<{ cmd: string; name: string; at: Doc }>> {
  const out: Array<{ cmd: string; name: string; at: Doc }> = [];
  for (const r of [...doc.querySelectorAll(".run-code")] as Doc[]) {
    const btn = r.querySelector(":scope > button.code-copy");
    assert.ok(btn, "each command has its Copy");
    out.push({ cmd: r.querySelector(":scope > code").textContent, name: btn.getAttribute("aria-label"), at: r });
    btn.click();
  }
  await new Promise((r) => setTimeout(r, 20));
  return out;
}

/** The oracle over one served page: no Copy on a value, a chip or a token. */
function noCopyOnSecrets(doc: Doc, wrote: string[], where: string): void {
  for (const b of [...doc.querySelectorAll("button.code-copy")] as Doc[]) {
    const box = b.parentElement;
    assert.ok(!box.textContent.includes(CANARY), `CONFIDENTIALITY VIOLATION: ${where}: a Copy sits on the secret's value`);
    assert.equal(box.querySelector(".mask-chip"), null, `${where}: a Copy sits on a masked item`);
    assert.doesNotMatch(box.textContent, /\$MDU/, `${where}: a Copy sits on a token`);
  }
  for (const t of wrote) {
    assert.ok(!t.includes(CANARY), `CONFIDENTIALITY VIOLATION: ${where}: the clipboard got the secret's value`);
    assert.doesNotMatch(t, /\$MDU/, `${where}: the clipboard got a token`);
  }
}

test("every command the product page asks you to run has a Copy that writes exactly it, and no Copy sits on a secret (secrets axes, explicit)", { timeout: 90_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-command-copy-"));
  const ws = join(tmp, "ws");
  mkdirSync(ws, { recursive: true });
  const secret = join(ws, ".env");
  writeFileSync(secret, `API_TOKEN=${CANARY}\n`);
  const policy = join(tmp, "policy.yaml");
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${secret}\n    level: no-model\n`);
  const socketPath = join(tmp, "arbiter.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, humanSocketPath: humanPath, adminSocketPath: join(tmp, "admin.sock"),
    dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"), policyPath: policy, log: () => {},
    confidentiality: true, integrity: false, // the `secrets` axes, stated
  });
  await arbiter.listen();
  const clients: ArbiterClient[] = [];
  const open = async (s: string): Promise<ArbiterClient> => { const c = new ArbiterClient(s); await c.connect(); clients.push(c); return c; };
  let up = new MockUpstream({ sse: buildTextSse("ok") });
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(await open(socketPath), await open(humanPath)), upstream: (a) => up.fetcher(a), log: () => {} });
  const proxyPort = await proxy.listen(0);
  const configEnv = { MANDU_HOME: join(tmp, "mandu-home") };
  const now = Date.now();
  assert.ok(launcherUpdate.writeUpdateCache(manduPath("update-check", configEnv, tmp), {
    v: 1, checkedAt: now - 3_600_000, ok: true, releasesAt: now - 3_600_000, releases: [{ version: NEWER, security: true }],
  }), "the launcher's writer wrote the cache");
  // No `extensions`: the product page only, as the shipped package.
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    fileBrowserHome: tmp, configEnv, log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const toModel: string[] = [];
  const reads: string[] = [];
  const homeVm = async (): Promise<HomeVM> => {
    const text = await (await pageFetch(`${base}/api/home`, { headers: SIGNED_IN })).text();
    reads.push(text);
    return JSON.parse(text) as HomeVM;
  };

  try {
    // ── C1: no session yet ──
    const first = await homeVm();
    assert.ok(first.firstRun, "the first-run card is sent");
    assert.equal(first.about?.update?.state, "newer");
    assert.equal(first.about?.update?.install, INSTALL);
    const commands = first.firstRun.steps.flatMap((s) => s.commands.map((c) => c.command));
    assert.ok(commands.includes("mandu doctor"), commands.join(", "));
    // One document holds every page: the update line is Home's notice's
    // and Settings › About's; the account command is the account-changed
    // card's and Settings › Dashboard account's (index.html); `mandu scan`
    // is Home's scan card's and History's scan line's (no scan kept);
    // `mandu paths` is Where your data lives' line, `mandu doctor` (once
    // more) Settings › About's (index.html, #193).
    const expected = [INSTALL, INSTALL, ...commands, "mandu scan", "mandu scan", SET_PASSWORD, SET_PASSWORD, "mandu paths", "mandu doctor"];
    const wrote: string[] = [];
    await servedProductPage(base, "/", (doc: Doc) => doc.getElementById("home-update")?.hidden === false && doc.querySelector("#first-run-steps .run-code") !== null && doc.querySelector("#home-scan-again .run-code") !== null, async (doc: Doc) => {
      const copies = await pressEach(doc);
      // Compared sorted, each with its count.
      assert.deepEqual(copies.map((c) => c.cmd).sort(), [...expected].sort(), "each command the page asks for, and nothing else");
      assert.deepEqual(wrote.slice().sort(), [...expected].sort(), "each Copy wrote exactly its command");
      assert.equal(doc.querySelector("#update-fix .run-code code").textContent, INSTALL, "the update line in full");
      assert.equal(doc.querySelector("#update-fix .run-code button").getAttribute("aria-label"), "Copy the update command");
      assert.equal(doc.querySelector("#home-scan-again .run-code button").getAttribute("aria-label"), "Copy mandu scan");
      assert.equal(doc.querySelector("#history-scan .run-code button").getAttribute("aria-label"), "Copy mandu scan");
      for (const c of copies) if (c.cmd !== INSTALL) assert.equal(c.name, `Copy ${c.cmd}`);
      assert.equal(doc.querySelector("#home-scan-sentence .run-code"), null, "the scan sentence's mention is no ask");
      noCopyOnSecrets(doc, wrote, "Home");
      assert.ok(!doc.body.textContent.includes(CANARY), "CONFIDENTIALITY VIOLATION: Home carries the value");
    }, { headers: SIGNED_IN, beforeScripts: clipboard(wrote) });
    const aboutWrote: string[] = [];
    await servedProductPage(base, "/settings", (doc: Doc) => doc.querySelector("#settings-about-version .run-code") !== null, async (doc: Doc) => {
      const row = doc.getElementById("settings-about-version");
      assert.equal(row.querySelector(".run-code code").textContent, INSTALL);
      row.querySelector(".run-code button").click();
      await new Promise((r) => setTimeout(r, 20));
      assert.deepEqual(aboutWrote, [INSTALL]);
      noCopyOnSecrets(doc, aboutWrote, "Settings");
    }, { headers: SIGNED_IN, beforeScripts: clipboard(aboutWrote) });

    // ── C4: Settings › About's mandu doctor, Protection's mandu dashboard ──
    const settingsWrote: string[] = [];
    await servedProductPage(base, "/settings", (doc: Doc) => doc.querySelector("#settings-services .service-none .run-code") !== null, async (doc: Doc) => {
      const doctor = [...doc.querySelectorAll("#settings-about-block p.note")].find((p: Doc) => p.textContent.startsWith("To check this computer's setup")) as Doc;
      const service = doc.querySelector("#settings-services .service-none");
      for (const [node, cmd, text] of [
        [doctor, "mandu doctor", "To check this computer's setup, run mandu doctor in a terminal."],
        [service, "mandu dashboard", "This dashboard was started without the service controls. Start it with mandu dashboard to manage the protection service here."],
      ] as Array<[Doc, string, string]>) {
        const runs = [...node.querySelectorAll(".run-code")] as Doc[];
        assert.equal(runs.length, 1, text);
        assert.equal(runs[0].querySelector("code").textContent, cmd);
        assert.equal(runs[0].querySelector("button").getAttribute("aria-label"), `Copy ${cmd}`);
        assert.equal(node.textContent, text.replace(cmd, `${cmd}Copy`), "the words as before");
        runs[0].querySelector("button").click();
        await new Promise((r) => setTimeout(r, 20));
      }
      assert.deepEqual(settingsWrote, ["mandu doctor", "mandu dashboard"], "each Copy wrote exactly its command");
      noCopyOnSecrets(doc, settingsWrote, "Settings › About and Protection");
    }, { headers: SIGNED_IN, beforeScripts: clipboard(settingsWrote) });

    // ── C2: a session whose commands could not start ──
    const FAIL = `${Math.floor(now / 1000)}-${process.pid}-copy`;
    assert.ok(await emitLauncherEvent(socketPath, launchPostureEvent({ scopeId: FAIL, target: "claude", argv0: "/usr/local/bin/claude", notes: [] })));
    const turn = async (messages: unknown[], sse: string): Promise<void> => {
      up = new MockUpstream({ sse });
      const res = await pageFetch(`http://127.0.0.1:${proxyPort}/v1/messages`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-mandu-session-id": FAIL, "user-agent": "claude-cli/2.1.289 (external, cli)" },
        body: JSON.stringify({ model: "claude-opus-4", stream: true, system: "You are Claude Code.", tools: TOOLS, messages }),
      });
      assert.equal(res.status, 200, await res.text());
      toModel.push(up.requests[0]!.bodyText);
    };
    const use = (id: string, name: string, input: Record<string, unknown>) => ({ role: "assistant", content: [{ type: "tool_use", id, name, input }] });
    const result = (id: string, content: string) => ({ role: "user", content: [{ type: "tool_result", tool_use_id: id, content }] });
    const h0 = [{ role: "user", content: "Read the env, then build it." }];
    const h1 = [...h0, use("toolu_cc_0", "Read", { file_path: secret }), result("toolu_cc_0", `API_TOKEN=${CANARY}\n`)];
    const h2 = [...h1, use("toolu_cc_1", "Bash", { command: "python3 build.py" }), result("toolu_cc_1", NOT_FOUND)];
    const h3 = [...h2, use("toolu_cc_2", "Bash", { command: "python3 -m pytest" }), result("toolu_cc_2", NOT_FOUND)];
    await turn(h0, buildToolUseSse({ id: "toolu_cc_0", name: "Read", input: { file_path: secret } }));
    await turn(h1, buildToolUseSse({ id: "toolu_cc_1", name: "Bash", input: { command: "python3 build.py" } }));
    await turn(h2, buildToolUseSse({ id: "toolu_cc_2", name: "Bash", input: { command: "python3 -m pytest" } }));
    await turn(h3, buildTextSse("python3 is not installed here. Run `python3 --version` to check."));
    const file = join(tmp, "events", `${FAIL}.ndjson`);
    for (let i = 0; i < 100; i++) {
      let text = "";
      try { text = readFileSync(file, "utf8"); } catch { /* not yet */ }
      if (text.includes("toolu_cc_2") && text.split("python3: command not found").length > 2) break;
      await new Promise((r) => setTimeout(r, 30));
    }
    const LOG = `mandu log ${FAIL}`;
    let vm: HomeVM | null = null;
    for (let i = 0; i < 100; i++) {
      vm = await homeVm();
      if (vm.agents.find((a) => a.id === FAIL)?.noticeParts?.some((p) => p.run)) break;
      await new Promise((r) => setTimeout(r, 30));
    }
    const row = vm!.agents.find((a) => a.id === FAIL);
    assert.deepEqual(row?.noticeParts?.filter((p) => p.run).map((p) => p.text), [LOG], JSON.stringify(row?.noticeParts));
    const agentText = await (await pageFetch(`${base}/api/home/agent?session=${encodeURIComponent(FAIL)}`, { headers: SIGNED_IN })).text();
    reads.push(agentText);
    const pageWrote: string[] = [];
    await servedProductPage(base, `/agents/${encodeURIComponent(FAIL)}`, (doc: Doc) => doc.querySelector("#agent-notice .run-code") !== null && doc.querySelector("#agent-story .mask-chip") !== null, async (doc: Doc) => {
      const notice = doc.getElementById("agent-notice");
      const runs = ([...notice.querySelectorAll(".run-code")] as Doc[]);
      assert.equal(runs.length, 1, "one command in the notice to run");
      assert.equal(runs[0].querySelector("code").textContent, LOG);
      assert.equal(runs[0].querySelector("button").getAttribute("aria-label"), `Copy ${LOG}`);
      runs[0].querySelector("button").click();
      await new Promise((r) => setTimeout(r, 20));
      assert.deepEqual(pageWrote, [LOG], "the id in full");
      // The story: the commands the AI ran and the reply's inline code get no Copy of this kind.
      assert.equal(doc.querySelector("#agent-story .run-code"), null, "nothing from the session's events is a command to run");
      // Every Copy in the document: the notice's, or one C1 found (the
      // other pages' commands, still in the one document).
      for (const r of [...doc.querySelectorAll(".run-code")] as Doc[]) assert.ok([LOG, ...expected].includes(r.querySelector("code").textContent), r.textContent);
      noCopyOnSecrets(doc, pageWrote, "signed in, the session page");
    }, { headers: SIGNED_IN, beforeScripts: clipboard(pageWrote) });

    // ── C3: the oracle over the answers and the model's requests ──
    assert.ok(toModel.length === 4);
    for (const body of toModel) assert.ok(!body.includes(CANARY), "CONFIDENTIALITY VIOLATION: the labelled secret reached the model raw");
    for (const text of reads.slice(0, -1)) assert.ok(!text.includes(CANARY), "CONFIDENTIALITY VIOLATION: Home's answer carries the value");
  } finally {
    await dashboard.close();
    await proxy.close();
    for (const c of clients) c.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
