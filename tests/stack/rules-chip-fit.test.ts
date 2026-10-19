/**
 * rules-chip-fit.test — on the Rules page a rule's subject chip is as wide as
 * its words, across the REAL components (dashboard.md §4.25c *The subject's
 * chip fits it*). Mandu-new.
 *
 * Until 2026-10-08 a rule's subject `<code>` sat straight in `.rule-text`, a
 * flex column, which stretched it: in a browser every host in *Sending data*
 * and *Programs and connections* was a grey bar across the row (504px for
 * `pypi.org:443` at 1280px), like an empty field to type in.
 *
 * Here a real ArbiterServer (secrets) holds a policy file with two send rules
 * and two connection allowances, a registered key, and a send of that key
 * waiting for an answer. A real DashboardServer over the production adapter
 * (`makeApprovalsArbiter`) serves the Rules page; signed in, its own
 * index.html and home.js run in jsdom with the served mandu.css and app.css
 * applied, and show:
 *
 *   C1  every host row, under its group, with its host as the chip (the
 *       served panel's compiled form: lower-cased, a connection's port);
 *   C2  each chip keeps its own width (`align-self: flex-start` in the flex
 *       column), and a long host still breaks inside it; the reach line
 *       under it spans the column;
 *   C3  the oracle: neither the panel nor the rendered page carries the
 *       registered key, and the page carries no token.
 *
 * jsdom does no layout: it reads the declared values the served styles give
 * the served rows, which is what failed (the page's markup and the
 * stylesheet's rules met as a stretch). Axes: secrets (stated).
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { ADMIN_COOKIE, ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { resolveCssVars } from "../../dashboard/test/unit/ui/css-flatten.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

after(() => resetCurrentPolicyForTests("claude-code"));

const KEY = "ghp_rulesChipFitStackCanary000000000000001";
const LONG = "uploads.very-long-subdomain.storage.example.org";

test("Rules over the real arbiter: every host rule's chip is as wide as its host, its reach line spans the column; no value on the page", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-rules-chip-fit-"));
  const home = join(tmp, "home");
  mkdirSync(home, { recursive: true });
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, [
    "version: 1",
    "user_rules:",
    "  - { id: r-0001, kind: release, to: { host: api.example.com }, mode: allow }",
    `  - { id: r-0002, kind: release, to: { host: ${LONG} }, mode: allow }`,
    "destinations:",
    "  - { host: Registry.Example, connect: allow }",
    "  - { host: pypi.org, connect: allow }",
    "",
  ].join("\n"));
  const socketPath = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, adminSocketPath: adminSock, humanSocketPath: humanPath,
    dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), policyPath, policyPollMs: 0,
    confidentiality: true, integrity: false, log: () => {},
  });
  await arbiter.listen();
  const data = new ArbiterClient(socketPath);
  await data.connect();
  const wired = await makeApprovalsArbiter(socketPath, () => ({ socketPath: adminSock }));
  assert.ok(wired?.policyDoc, "the production adapter has the policy surface");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter, policyDocArbiter: wired.policyDoc,
    fileBrowserHome: home, configEnv: { MANDU_HOME: join(tmp, "mandu-home") }, log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const bodies: string[] = [];
  try {
    // A registered key and a send of it waiting for an answer, for the
    // oracle: the page has a value it could show, and must not.
    const reg = await data.registerEnvSecrets({ vars: [{ name: "GITHUB_TOKEN", value: KEY }] });
    const sym = reg.vars[0]?.symbol;
    assert.match(String(sym), /^\$MDU:nomodel_Env\[/, "the key has its placeholder");
    const ask = await data.desymbolizationDecision({ symbol: sym!, boundary: "network", destination: "gist.github.com", scheme: "https" });
    assert.equal(ask.allow, false);
    assert.equal((ask as { requiresApproval?: boolean }).requiresApproval, true, `the send waits for an answer: ${JSON.stringify(ask)}`);

    const panel = await pageFetch(`${base}/api/policy/panel`, { headers: CSRF_ADMIN });
    const panelText = await panel.text();
    bodies.push(panelText);
    assert.equal(panel.status, 200, panelText);

    const css = async (f: string) => {
      const r = await pageFetch(`${base}/${f}`);
      assert.equal(r.status, 200, `${f} is served`);
      return r.text();
    };
    const styles = resolveCssVars((await css("mandu.css")) + "\n" + (await css("app.css")));
    await servedProductPage(base, "/rules",
      (doc) => doc.querySelectorAll("#rules-list .row.rule").length >= 4,
      (doc) => {
        const style = (e: Element) => doc.defaultView.getComputedStyle(e);
        // C1: each host row under its group, its host the chip.
        const groups = [...doc.querySelectorAll("#rules-list .rules-group")].map((g: Element) => g.firstChild?.textContent);
        assert.deepEqual(groups, ["Sending data", "Programs and connections"]);
        const texts = [...doc.querySelectorAll("#rules-list .row.rule .rule-text")] as HTMLElement[];
        assert.deepEqual(texts.map((t) => t.firstElementChild?.textContent), ["api.example.com", LONG, "registry.example:443", "pypi.org:443"],
          "the send rules, then the connections, as the arbiter compiled them");
        for (const text of texts) {
          const chip = text.firstElementChild as HTMLElement;
          assert.equal(chip.tagName, "CODE", "the subject is a chip");
          // C2: the chip keeps its own width in the flex column.
          assert.equal(style(text).display, "flex");
          assert.equal(style(text).flexDirection, "column");
          assert.equal(style(chip).alignSelf, "flex-start", `${chip.textContent}: the chip is as wide as its words, not the column`);
          assert.equal(style(chip).overflowWrap, "anywhere", `${chip.textContent}: a long host breaks inside its chip`);
          const reach = text.querySelector(":scope > .dim") as HTMLElement;
          assert.ok(reach && reach.textContent, `${chip.textContent}: a reach line under it`);
          assert.notEqual(style(reach).alignSelf, "flex-start", `${chip.textContent}: the reach line spans the column`);
        }
        // C3 on the rendered page.
        const page = doc.body.textContent ?? "";
        assert.ok(!page.includes(KEY), "the rendered page carries no registered key");
        assert.doesNotMatch(page, /\$MDU/, "nor a token");
      },
      { headers: { Cookie: ADMIN_COOKIE }, css: styles },
    );
    // C3 on the panel the page reads (signed in, it names the waiting
    // send's placeholder, which is opaque; never the value).
    for (const b of bodies) assert.ok(!b.includes(KEY), "the panel carries no registered key");
  } finally {
    await dashboard.close();
    data.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
