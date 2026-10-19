/**
 * ask-top-row.test — a question card with a short sentence keeps its icon
 * beside its words, across the REAL components (dashboard.md §4.25 *A short
 * question keeps its icon beside its words*). Mandu-new.
 *
 * Every question card draws its icon and its words in one row that wraps. A
 * browser sizes that row by its own width first (icon, gap, the sentence's
 * own width), so a sentence shorter than the words' 320 px basis wrapped it:
 * until 2026-10-12 a headless Chromium drew Approvals' "Your agent wants to
 * change a rule" with a 109 px header holding 49 px of content. The row is
 * now `.ask-top`, whose min-width keeps it as wide as the icon and the words
 * side by side (or the card). The served page runs in jsdom with the served
 * mandu.css and app.css applied, so the rule is read as the page computes it.
 *
 * A real ArbiterServer (secrets) holds a policy.yaml rule on `.env`; the
 * agent's binding of it to a host waits for the human (a rule change your
 * agent asked for); the real workspace scan files a key in a work tree (the
 * possible-keys card); the real egress gate asks about a masked variable at
 * a host no rule binds it to (a waiting question). A real DashboardServer
 * over the production adapter serves the pages, signed in:
 *
 *   A1  Approvals: the rule change, the possible-keys card and the waiting
 *       question each draw their icon in an `.ask-top` with no inline
 *       style, a wrapping flex row whose computed min-width is
 *       min(100%, 380px);
 *   A2  Home: the waiting question's card does too.
 *   A3  each card's moment line (dashboard.md §4.25u *A moment line ends
 *       where it ends*): on Approvals, the rule change's and the waiting
 *       question's end at the moment, with no period after it; on Home,
 *       the short card's keeps its period before "Details in Approvals".
 *
 * The oracle: no page or answer read here carries the key, the `.env`'s
 * value or the variable's value.
 *
 * Axes: secrets (stated).
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
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
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

after(() => resetCurrentPolicyForTests("claude-code"));

const KEY = "sk_live_askTopRowStackCanary000000000001";
const ENV_VALUE = "askTopRowStackEnvValue0000000002";
const VAR_VALUE = "ghp_askTopRowStackVariable00000000000003";
const SESSION = "ask-top-row-session";
/** A moment's clock time (home.js `clockWords`), and a card's moment line
 *  with nothing after the moment (§4.25u). */
const CLOCK = String.raw`[A-Z][a-z]{2} \d{1,2}(?:, \d{4})?, \d{2}:\d{2}`;
const MOMENT_ALONE = new RegExp(`^${CLOCK} · just now$`);

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;

/** The served product styles, tokens resolved, to apply in jsdom. */
async function servedStyles(base: string): Promise<string> {
  const css = async (f: string) => {
    const r = await pageFetch(`${base}/${f}`);
    assert.equal(r.status, 200, `${f} is served`);
    return r.text();
  };
  return resolveCssVars((await css("mandu.css")) + "\n" + (await css("app.css")));
}

/** The card's icon sits in its `.ask-top`, which the served styles make a
 *  wrapping row never measured narrower than icon and words side by side.
 *  Returns the card's sentence. */
function headerOf(card: Doc): string {
  assert.ok(card, "the card is drawn");
  const icon = card.querySelector(".ask-icon");
  assert.ok(icon, "the card has its icon");
  const top = icon.parentElement;
  const sentence = card.querySelector(".ask-sentence").textContent;
  assert.equal(top.parentElement, card, `${sentence}: the header row is the card's own child`);
  assert.equal(top.className, "ask-top", `${sentence}: the header row`);
  assert.equal(top.getAttribute("style"), null, `${sentence}: no inline style`);
  const cs = card.ownerDocument.defaultView.getComputedStyle(top);
  assert.equal(cs.display, "flex", sentence);
  assert.equal(cs.flexWrap, "wrap", `${sentence}: a phone still puts the icon above the words`);
  assert.equal(cs.minWidth, "min(100%, 380px)", `${sentence}: never measured narrower than the icon and the words side by side`);
  return sentence;
}

test("Approvals and Home over the real arbiter: a rule change your agent asked for, the possible-keys card and a waiting question draw their icon beside their words, and their moment line ends with a period only when something follows it; no secret anywhere", { timeout: 120_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-ask-top-row-"));
  const home = join(tmp, "home");
  const repo = join(home, "proj");
  mkdirSync(join(repo, "deploy"), { recursive: true });
  const gitEnv = { ...process.env, HOME: home, GIT_CONFIG_NOSYSTEM: "1", GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@t", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@t" };
  execFileSync("git", ["init", "-q", "-b", "main"], { cwd: repo, env: gitEnv });
  writeFileSync(join(repo, "README.md"), "a project\n");
  writeFileSync(join(repo, "deploy", "app.conf"), `[api]\nAPI_TOKEN=${KEY}\n`);
  const env = join(repo, ".env");
  writeFileSync(env, `DB_PASSWORD=${ENV_VALUE}\n`);
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, `version: 1\npaths:\n  - path: ${env}\n    level: no-model\n`);
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
  const data = new ArbiterClient(socketPath);
  await data.connect();
  const wired = await makeApprovalsArbiter(socketPath, () => ({ socketPath: adminSock }));
  assert.ok(wired?.secrets && wired.policyDoc, "the production adapter has the secrets and policy surfaces");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter, secretsArbiter: wired.secrets, policyDocArbiter: wired.policyDoc,
    fileBrowserHome: home,
    configEnv: { MANDU_HOME: join(tmp, "mhome"), MANDU_POLICY_FILE: policyPath },
    log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const bodies: string[] = [];
  const call = async (method: "GET" | "POST", path: string, body?: unknown) => {
    const r = await pageFetch(base + path, { method, headers: { ...CSRF_ADMIN, ...(body !== undefined ? { "Content-Type": "application/json" } : {}) }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
    const text = await r.text();
    bodies.push(text);
    return { status: r.status, body: JSON.parse(text) };
  };
  const signedIn = { headers: { Cookie: ADMIN_COOKIE } };
  try {
    // A rule change your agent asked for: binding `.env` to a host waits.
    const asked = await data.policyPropose({ edits: [{ op: "lock-path", path: env, level: "no-model", bindings: ["api.stripe.com"] }], sessionKey: SESSION, reason: "deploy needs it" });
    assert.ok("proposalId" in asked, `a binding waits for the human: ${JSON.stringify(asked)}`);
    // The possible-keys card: the real scan files the key.
    assert.equal((await call("POST", "/api/suggestions/scan", { root: "~/proj" })).status, 200);
    const listed = (await call("GET", "/api/suggestions")).body.suggestions as Array<{ path: string }>;
    assert.deepEqual(listed.map((s) => s.path), [join(repo, "deploy", "app.conf")], "the real scan files the key");
    // A waiting question: the egress gate asks about a masked variable.
    const vars = await data.registerEnvSecrets({ vars: [{ name: "GITHUB_TOKEN", value: VAR_VALUE }], sessionKey: SESSION });
    const sym = String(vars.vars[0]?.symbol);
    const d = await data.desymbolizationDecision({ symbol: sym, boundary: "network", destination: "gist.github.com", sessionKey: SESSION, scheme: "https" });
    assert.equal((d as { requiresApproval?: boolean }).requiresApproval, true, "the gate asks the human");
    const css = await servedStyles(base);
    const pages: string[] = [];

    // A1: Approvals.
    const approvalsReady = (doc: Doc) => !!doc.querySelector("#approvals-proposals .ask.proposal")
      && !!doc.querySelector("#approvals-suggestions .ask.suggestion-card") && !!doc.querySelector("#approvals-waiting .ask.expanded");
    await servedProductPage(base, "/approvals", approvalsReady, (doc: Doc) => {
      assert.equal(headerOf(doc.querySelector("#approvals-proposals .ask.proposal")), "Your agent wants to change a rule");
      assert.match(headerOf(doc.querySelector("#approvals-suggestions .ask.suggestion-card")), /^Mandu found 1 possible key in /);
      assert.match(headerOf(doc.querySelector("#approvals-waiting .ask.expanded")), /GITHUB_TOKEN/);
      // A3: the moment alone, no period after it.
      for (const sel of ["#approvals-proposals .ask.proposal", "#approvals-waiting .ask.expanded"]) {
        assert.match(doc.querySelector(`${sel} .ask-sub`).textContent, MOMENT_ALONE, sel);
      }
      pages.push(doc.documentElement.outerHTML);
    }, { css, ...signedIn });

    // A2: Home.
    await servedProductPage(base, "/", (doc: Doc) => !!doc.querySelector("#home-waiting .ask"), (doc: Doc) => {
      assert.match(headerOf(doc.querySelector("#home-waiting .ask")), /GITHUB_TOKEN/);
      // A3: the link follows the moment, so the period stays.
      assert.match(doc.querySelector("#home-waiting .ask .ask-sub").textContent, new RegExp(`${CLOCK} · just now\\. Details in Approvals$`));
      pages.push(doc.documentElement.outerHTML);
    }, { css, ...signedIn });

    // The oracle: no secret value in any page or answer read here.
    bodies.push(JSON.stringify((await call("GET", "/api/home")).body), JSON.stringify((await call("GET", "/api/policy/proposals?status=pending")).body));
    for (const text of [...pages, ...bodies]) {
      for (const value of [KEY, ENV_VALUE, VAR_VALUE]) assert.ok(!text.includes(value), "no secret value in a page or an answer");
    }
  } finally {
    await dashboard.close();
    data.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
