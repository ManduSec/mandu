/**
 * fields-look — every text box and menu the product page draws has the
 * page's field look, across the REAL components (dashboard.md §4.25r *Every
 * field has the page's look*). Mandu-new.
 *
 * Until 2026-10-16 three of them had no look of their own, so the browser
 * drew them square and grey: Keys Mandu found's scan box, its "Ask a model
 * too" menu, and the ALLOW box of a wide rule change. Its empty status line
 * also put 40 px of nothing under the model line, and the line under the
 * menu read "Asking a model to suggest rules: not offered yet: asking a
 * model is still being tested." jsdom draws nothing, so the served page
 * runs with its served stylesheets, and a property no rule sets reads
 * empty, as the browser's own look would.
 *
 * A real ArbiterServer (secrets) holds a policy.yaml with a file rule over a
 * real file holding a value. The agent's own channel asks the real
 * policyPropose op to let its programs connect anywhere: a wide change,
 * held for the person. A real DashboardServer over the production adapter
 * serves Rules and Approvals, signed in, with the model picker as shipped
 * (not offered without MANDU_EXPERIMENTAL_POLICY_MODEL=1):
 *
 *   F1  Rules, with Add a rule and Keys Mandu found opened, in the light
 *       and the dark theme: every text box, search box, text area and menu
 *       of the page has a radius, a 1 px solid border in the line color,
 *       and one of the page's own backgrounds (a menu that cannot be
 *       changed has the held one, --panel-2); the scan box is drawn as
 *       the filter box, and the model menu as a choice menu in a row;
 *   F2  the line under the menu is the real route's, one sentence;
 *   F3  Approvals: the wide change's ALLOW box has the same look, and the
 *       height of the buttons beside it, in both themes;
 *   F4  the oracle: no page or answer read here carries the file's value
 *       or a minted token; policy.yaml is as it was, and the change still
 *       waits.
 *
 * Axes: secrets (stated).
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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
import { perSelector, resolveCssVars, stylesAt } from "../../dashboard/test/unit/ui/css-flatten.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

const FLAG = process.env.MANDU_EXPERIMENTAL_POLICY_MODEL;
delete process.env.MANDU_EXPERIMENTAL_POLICY_MODEL; // the picker as shipped
after(() => {
  resetCurrentPolicyForTests("claude-code");
  if (FLAG !== undefined) process.env.MANDU_EXPERIMENTAL_POLICY_MODEL = FLAG;
});

const VALUE = `sk_live_fieldsLookCanary_${process.pid}_0`;
/** A minted token (the panel's own help text names the `$MDU:` form). */
const TOKEN = /\$MDU:[A-Za-z_][A-Za-z0-9_-]*\[[0-9a-f]{4,8}\]/;
const FIELDS = 'input[type="text"], input[type="search"], textarea, select';
const NOT_OFFERED = "Asking a model to suggest rules is not offered yet: it is still being tested.";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;

/** A color as jsdom computes it (`rgb(…)`). */
function computedColor(doc: Doc, value: string): string {
  const p = doc.createElement("i");
  p.style.color = value;
  doc.body.append(p);
  const out = doc.defaultView.getComputedStyle(p).color;
  p.remove();
  return out;
}
/** A theme's token in the served styles. */
function token(css: string, name: string, theme: "light" | "dark"): string {
  return /\.token-probe \{ --probe:\s*([^;]+);/.exec(resolveCssVars(`${css}\n.token-probe { --probe: var(${name}); }`, theme))![1]!.trim();
}
const nameOf = (f: Doc): string => f.id || `.${String(f.className).split(" ")[0]}`;
function look(doc: Doc, el: Doc) {
  const cs = doc.defaultView.getComputedStyle(el);
  return { radius: cs.borderRadius, border: [cs.borderTopWidth, cs.borderTopStyle, cs.borderTopColor].join(" "), ground: cs.backgroundColor, height: cs.height };
}
/** The fields in `doc` that have no look of the page's, in `theme`. */
function bare(doc: Doc, css: string, theme: "light" | "dark", fields: Doc[]): string[] {
  const line = computedColor(doc, token(css, "--line", theme));
  const grounds = new Set(["--bg", "--panel", "--panel-2"].map((t) => computedColor(doc, token(css, t, theme))));
  return fields.filter((f) => {
    const l = look(doc, f);
    return !(/^(8|10)px$/.test(l.radius) && l.border === `1px solid ${line}` && grounds.has(l.ground));
  }).map((f) => `${nameOf(f)} ${JSON.stringify(look(doc, f))}`);
}

test("the product page over the real arbiter: every text box and menu has the page's field look, the scan's lines and the ALLOW box too; no value on the page", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-fields-look-"));
  const home = join(tmp, "home");
  mkdirSync(join(home, "mandu-try"), { recursive: true });
  const env = join(home, "mandu-try", ".env");
  writeFileSync(env, `STRIPE_KEY=${VALUE}\n`);
  const policyPath = join(tmp, "policy.yaml");
  const policy = ["version: 1", "paths:", `  - { path: "${env}", level: no-model, bindings: [api.stripe.com] }`, ""].join("\n");
  writeFileSync(policyPath, policy);
  const socketPath = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, adminSocketPath: adminSock, humanSocketPath: humanPath,
    dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), policyPath, policyPollMs: 0,
    adminPolicyDir: null, promptPackDir: null, adminPromptPackDir: null,
    confidentiality: true, integrity: false, log: () => {},
  });
  await arbiter.listen();
  const agent = new ArbiterClient(socketPath);
  await agent.connect();
  const wired = await makeApprovalsArbiter(socketPath, () => ({ socketPath: adminSock }));
  assert.ok(wired?.secrets && wired.policyDoc, "the production adapter has the secrets and policy surfaces");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter, secretsArbiter: wired.secrets, policyDocArbiter: wired.policyDoc,
    fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mhome"), MANDU_POLICY_FILE: policyPath, HOME: home },
    log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const signedIn = { Cookie: ADMIN_COOKIE };
  const noValue = (body: string, where: string) => {
    assert.ok(!body.includes(VALUE), `CONFIDENTIALITY VIOLATION: ${where} carries the file's value`);
    assert.doesNotMatch(body, TOKEN, `${where} carries no token`);
  };
  const read = async (path: string, headers: Record<string, string>): Promise<string> => {
    const r = await pageFetch(base + path, { headers });
    const body = await r.text();
    assert.equal(r.status, 200, `${path}: ${body.slice(0, 200)}`);
    noValue(body, path);
    return body;
  };
  try {
    // The agent asks to let its programs connect anywhere: a wide change.
    const asked = await agent.policyPropose({ edits: [{ op: "allow-connect", host: "*" }], reason: "fields look", sessionKey: "s-fields" });
    assert.ok(!asked.applied && "proposalId" in asked, `a wide change waits for the person: ${JSON.stringify(asked)}`);
    const proposalId = asked.proposalId;
    const sheets = `${await read("/mandu.css", signedIn)}\n${await read("/app.css", signedIn)}`;
    const styled = (doc: Doc, theme: "light" | "dark") => {
      const sheet = [...doc.head.querySelectorAll("style")].at(-1);
      assert.ok(sheet, "the served styles are applied");
      sheet.textContent = perSelector(resolveCssVars(stylesAt(sheets, 1280), theme));
    };

    // ── F1, F2: Rules ──
    const picker = JSON.parse(await read("/api/suggestions", CSRF_ADMIN)) as { model?: { offered: boolean; hint: string } };
    assert.equal(picker.model?.offered, false, "the picker as shipped: not offered");
    assert.equal(picker.model?.hint, NOT_OFFERED, "the route's line is one sentence");
    await servedProductPage(base, "/rules", (doc: Doc) => !!doc.querySelector(`#files-tree .row.file-rule[data-path="${env}"]`), async (doc: Doc) => {
      doc.getElementById("suggest-open").click();
      await waitWhile(() => doc.getElementById("files-suggested-view").hidden || !doc.getElementById("suggest-model-why").textContent);
      const addRule = [...doc.querySelectorAll("button")].find((b: Doc) => b.textContent.trim() === "Add a rule");
      assert.ok(addRule, "Rules has Add a rule");
      addRule.click();
      await waitWhile(() => !doc.querySelector("#files-list .row.file"));
      // ── F2 ──
      assert.equal(doc.getElementById("suggest-model-why").textContent, NOT_OFFERED, "the page draws the route's line");
      for (const theme of ["light", "dark"] as const) {
        styled(doc, theme);
        const fields = [...doc.querySelectorAll(FIELDS)] as Doc[];
        const names = fields.map(nameOf);
        for (const must of ["describe-text", "lock-path", "files-filter", "suggest-root", "suggest-model-tier", ".label-select"]) assert.ok(names.includes(must), `${theme}: Rules has ${must}`);
        assert.deepEqual(bare(doc, sheets, theme, fields), [], `${theme}: these fields have no look of the page's`);
        assert.deepEqual(look(doc, doc.getElementById("suggest-root")), look(doc, doc.getElementById("files-filter")), `${theme}: the scan box is drawn as the filter box`);
        const menu = doc.getElementById("suggest-model-tier");
        const row = ([...doc.querySelectorAll("#files-tree select.label-select")] as Doc[])[0];
        const m = look(doc, menu);
        const r = look(doc, row);
        assert.deepEqual([m.radius, m.border], [r.radius, r.border], `${theme}: the model menu has a row's menu frame`);
        const status = doc.defaultView.getComputedStyle(doc.getElementById("suggest-model-status"));
        assert.deepEqual([status.marginTop, status.marginBottom], ["0px", "0px"], `${theme}: the empty status line takes no margin`);
      }
      noValue(doc.body.textContent, "the rendered Rules page");
    }, { headers: signedIn, css: "" });

    // ── F3: Approvals ──
    await servedProductPage(base, "/approvals", (doc: Doc) => !!doc.querySelector("#approvals-proposals .proposal-confirm"), async (doc: Doc) => {
      const box = doc.querySelector("#approvals-proposals .proposal-confirm");
      const allow = ([...doc.querySelectorAll("#approvals-proposals button")] as Doc[]).find((b) => b.textContent === "Allow");
      assert.ok(allow?.disabled, "Allow waits for ALLOW to be typed");
      for (const theme of ["light", "dark"] as const) {
        styled(doc, theme);
        assert.deepEqual(bare(doc, sheets, theme, [box]), [], `${theme}: the ALLOW box has the page's look`);
        assert.equal(look(doc, box).height, look(doc, allow).height, `${theme}: as high as the buttons beside it`);
      }
      noValue(doc.body.textContent, "the rendered Approvals page");
    }, { headers: signedIn, css: "" });

    // ── F4: the oracle ──
    for (const route of ["/api/home", "/api/policy/panel", "/api/secrets", "/api/policy/proposals?status=pending", "/rules", "/approvals", "/"]) await read(route, route.startsWith("/api/") ? CSRF_ADMIN : signedIn);
    const pending = JSON.parse(await read("/api/policy/proposals?status=pending", CSRF_ADMIN)) as { proposals: Array<{ id: string; overBroad: boolean }> };
    assert.deepEqual(pending.proposals.map((p) => [p.id, p.overBroad]), [[proposalId, true]], "the wide change still waits");
    assert.equal(readFileSync(policyPath, "utf8"), policy, "nothing was saved");
  } finally {
    await dashboard.close();
    wired.close();
    agent.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
