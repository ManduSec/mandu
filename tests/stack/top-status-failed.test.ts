/**
 * top-status-failed — the top bar says "Protection failed" on every page,
 * and links to where it happened, across the REAL components and the served
 * styles (dashboard.md §4.25 *The top bar says on or off*, 2026-10-23).
 * Mandu-new.
 *
 * Until 2026-10-23 Home's hero said "Protection failed." while the top bar
 * of every page said "Protection on" with a green dot. Here a real
 * ArbiterServer runs at the `secrets` axes, the REAL anthropic-proxy on its
 * production client carries one turn in which a scripted model reads a
 * `.env`, the leak check's record of that Read is flagged over the arbiter's
 * IPC (`violatedInvariant`, as the fixtures record one), and a product-only
 * DashboardServer reads it over a real ArbiterEventSource:
 *
 *   F1  `/api/home`'s verdict is `failed`, its sentence linking that session;
 *   F2  the served `/rules` page's top bar says "Protection failed" beside a
 *       red dot, as one link in the status's own ink and size, named "open
 *       the session where it happened", whose address is that session's
 *       page; a plain click opens it in place;
 *   F3  the bar still fits: at 830 to 1280 px beside the brand and the
 *       links (the measured model, nav-row.ts), and at 320 to 829 px on the
 *       row it shares with the brand;
 *   F4  the oracle: the model never got the value, and no top-bar text,
 *       name, address or title, nor any answer or page read here, carries
 *       the value or a token.
 *
 * Axes: secrets (stated; the arbiter's confidentiality pinned ON).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { Readable } from "node:stream";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { AnthropicProxy, type UpstreamFetcher } from "../../interceptors/anthropic-proxy/src/proxy.js";
import { ArbiterClientAdapter } from "../../interceptors/anthropic-proxy/src/arbiter-client.js";
import { buildTextSse, sseEvent } from "../../interceptors/anthropic-proxy/test/helpers/mock-upstream.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import type { HomeVM } from "../../dashboard/src/view-model/home.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { resolveCssVars, stylesAt } from "../../dashboard/test/unit/ui/css-flatten.js";
import { BRAND_PX, MARGIN, STATUS_PX, drawnNav, navRow } from "../../dashboard/test/unit/ui/nav-row.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

const SESSION = `1791900000-${process.pid}`;
const VALUE = `sk_live_topStatusFailedCanary_${process.pid}_0000`;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type El = any;

function readTurn(path: string): string {
  return sseEvent("message_start", { type: "message_start", message: { id: "msg_tf_1", role: "assistant", content: [] } })
    + sseEvent("content_block_start", { type: "content_block_start", index: 0, content_block: { type: "tool_use", id: "toolu_tf_0", name: "Read", input: {} } })
    + sseEvent("content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "input_json_delta", partial_json: JSON.stringify({ file_path: path }) } })
    + sseEvent("content_block_stop", { type: "content_block_stop", index: 0 })
    + sseEvent("message_delta", { type: "message_delta", delta: { stop_reason: "tool_use" } })
    + sseEvent("message_stop", { type: "message_stop" });
}

function post(port: number, messages: unknown[]): Promise<number> {
  const body = JSON.stringify({ model: "claude-opus-4", stream: true, max_tokens: 512, tools: [{ name: "Read", input_schema: { type: "object" } }], messages });
  return new Promise((resolve, reject) => {
    const r = httpRequest({ host: "127.0.0.1", port, method: "POST", path: "/v1/messages", headers: { "content-type": "application/json", "x-mandu-session-id": SESSION } },
      (res) => { res.resume(); res.on("end", () => resolve(res.statusCode ?? 0)); });
    r.on("error", reject);
    r.end(body);
  });
}

test("a session whose Read the leak check flagged: every page's top bar says \"Protection failed\" and links that session (secrets axes, explicit)", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-top-status-failed-"));
  const ws = join(tmp, "ws");
  mkdirSync(ws, { recursive: true });
  const sock = join(tmp, "arbiter.sock");
  const human = join(tmp, "human", "h.sock");
  mkdirSync(join(tmp, "human"), { mode: 0o700 });
  const arbiter = new ArbiterServer({ socketPath: sock, humanSocketPath: human, dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), log: () => {}, confidentiality: true, integrity: false });
  await arbiter.listen();
  const gate = new ArbiterClient(sock); await gate.connect();
  const humanClient = new ArbiterClient(human); await humanClient.connect();
  // No `extensions`: the product page only, as the shipped package.
  const dashboard = new DashboardServer({ source: new ArbiterEventSource({ socketPath: sock, humanSocketPath: human }), log: () => {} });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const env = join(ws, ".env");
  writeFileSync(env, `STRIPE_KEY=${VALUE}\n`);
  const seen: string[] = [];
  const upstream: UpstreamFetcher = async ({ body }) => {
    seen.push(body.toString("utf8"));
    const sse = seen.length === 1 ? readTurn(env) : buildTextSse("Done.", { deltas: 1 });
    return { status: 200, headers: { "content-type": "text/event-stream" }, body: Readable.from([Buffer.from(sse, "utf8")]) };
  };
  const proxy = new AnthropicProxy({ arbiter: new ArbiterClientAdapter(gate, humanClient), upstream, sessionKey: SESSION, log: () => {} });
  const proxyPort = await proxy.listen(0);
  const noValue = (text: string, where: string) => {
    assert.ok(!text.includes(VALUE), `CONFIDENTIALITY VIOLATION: ${where} carries the secret value`);
    assert.doesNotMatch(text, /\$MDU/, `${where} carries a token`);
  };
  try {
    const ask = "Read the .env file.";
    assert.equal(await post(proxyPort, [{ role: "user", content: ask }]), 200);
    assert.equal(await post(proxyPort, [
      { role: "user", content: ask },
      { role: "assistant", content: [{ type: "tool_use", id: "toolu_tf_0", name: "Read", input: { file_path: env } }] },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_tf_0", content: `     1\tSTRIPE_KEY=${VALUE}\n` }] },
    ]), 200);
    // F4 on the model's side.
    assert.ok(!seen.join("\n").includes(VALUE), "CONFIDENTIALITY VIOLATION: the model got the .env value");
    // Wait for the proxy's record of the Read, then flag that result as the
    // leak check records one (the detail quotes what it found).
    for (let i = 0; i < 200; i++) {
      const text = await (await pageFetch(`${base}/api/home/agent?session=${SESSION}`)).text();
      if (text.includes("toolu_tf_0") && /The result held your secret/.test(text)) break;
      await new Promise((r) => setTimeout(r, 25));
    }
    await gate.emit({
      id: `leak-${process.pid}`, sessionId: SESSION, turn: 1, ts: new Date().toISOString(), seq: 0, callId: "toolu_tf_0", parentId: null,
      kind: "tool_result", view: "AgentView", boundary: "model_context", emitter: "anthropic-proxy",
      input: null, output: null, invariant: { violatedInvariant: true, detail: `un-symbolized span survived: STRIPE_KEY=${VALUE}` },
    } as never);

    // ── F1: Home's verdict ──
    let vm: HomeVM | null = null;
    let homeText = "";
    for (let i = 0; i < 200; i++) {
      homeText = await (await pageFetch(`${base}/api/home`)).text();
      vm = JSON.parse(homeText) as HomeVM;
      if (vm.verdict === "failed") break;
      await new Promise((r) => setTimeout(r, 25));
    }
    assert.equal(vm?.verdict, "failed", `the hero's verdict: ${vm?.verdict} ${vm?.headline}`);
    assert.equal(vm!.protection.level !== "off" && vm!.protection.connected, true, "protection is on and connected");
    const link = vm!.sentenceParts.find((p) => p.kind === "link") as { to?: string; session?: string } | undefined;
    assert.deepEqual([link?.to, link?.session], ["agent", SESSION], "the hero links that session's page");
    noValue(homeText, "/api/home");

    // ── F2: the served Rules page ──
    const sheets = `${await (await pageFetch(`${base}/mandu.css`)).text()}\n${await (await pageFetch(`${base}/app.css`)).text()}`;
    const statusLinks = (doc: El): El[] => [...doc.getElementById("top-status").querySelectorAll("a")];
    for (const width of [1280, 390]) {
      const where = `Rules at ${width}px`;
      await servedProductPage(base, "/rules", (doc) => statusLinks(doc).length > 0, async (doc) => {
        const w = doc.defaultView;
        const host = doc.getElementById("top-status");
        assert.equal(host.textContent, "Protection failed", `${where}: the top bar says what the hero says`);
        assert.ok(host.querySelector(":scope > .dot.bad"), `${where}: a red dot`);
        const links = statusLinks(doc);
        assert.equal(links.length, 1, `${where}: one link`);
        const a = links[0];
        assert.equal(new URL(a.href).pathname, `/agents/${encodeURIComponent(SESSION)}`, `${where}: it leads to that session's page`);
        assert.equal(a.getAttribute("aria-label"), "Protection failed: open the session where it happened", `${where}: its name says where it goes`);
        const hs = w.getComputedStyle(host);
        const ls = w.getComputedStyle(a);
        assert.equal(ls.color, hs.color, `${where}: the status's ink, not a link's`);
        assert.deepEqual([ls.fontSize, ls.textDecorationLine], [hs.fontSize, "none"], `${where}: its size, no underline until hovered`);
        // F4 on the top bar.
        for (const s of [host.textContent, a.getAttribute("aria-label"), a.href, a.getAttribute("title") ?? "", doc.title]) noValue(s, `${where}: the top bar or title`);

        const click = new w.MouseEvent("click", { bubbles: true, cancelable: true });
        a.dispatchEvent(click);
        assert.equal(click.defaultPrevented, true, "the page opens the session itself");
        await waitWhile(() => doc.getElementById("page-agent").hidden);
        assert.equal(w.location.pathname, `/agents/${encodeURIComponent(SESSION)}`, `${where}: the session's page opens`);
        assert.deepEqual([...doc.querySelectorAll("#main > section[data-page]")].filter((x: El) => !x.hidden).map((x: El) => x.dataset.page), ["agent"]);
        await waitWhile(() => doc.getElementById("agent-finding-block").hidden);
        assert.equal(doc.getElementById("agent-finding-block").hidden, false, `${where}: the page shows what the leak check found`);
        noValue(doc.body.textContent, `${where}: the rendered session page`);
      }, { css: resolveCssVars(stylesAt(sheets, width)) });
    }

    // ── F3: the bar fits ──
    const model = navRow(sheets);
    await servedProductPage(base, "/rules", (doc) => statusLinks(doc).length > 0, (doc) => {
      const nav = drawnNav(doc);
      for (let w = 830; w <= 1280; w++) {
        const spare = model.bar(w, { ...nav, count: "99" }, "Protection failed");
        assert.ok(spare >= MARGIN, `${w}px: the bar has ${spare}px to spare with "Protection failed" and 99 waiting`);
      }
      // Narrower, the links take a row of their own: the brand and the
      // status share the first, `column-gap` apart.
      for (let w = 320; w < 830; w++) {
        const spare = model.row(w) - BRAND_PX - parseFloat(model.at(w, ".top-inner", "column-gap")) - STATUS_PX["Protection failed"]!;
        assert.ok(spare >= MARGIN, `${w}px: the brand and "Protection failed" have ${spare}px to spare`);
      }
    });

    // ── F4: the answers and pages read here ──
    for (const route of ["/api/home", "/rules", "/approvals", `/api/home/agent?session=${SESSION}`]) {
      noValue(await (await pageFetch(base + route)).text(), route);
    }
  } finally {
    await proxy.close();
    await dashboard.close();
    gate.close();
    humanClient.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
