/**
 * home-js-refusals.test — dashboard.md §4.25 "Refusals" on the PRODUCT page
 * (public/js/home.js), driven in jsdom over the shared fetch stub
 * (home-js-fixtures.ts) with the server's OWN refusal bodies: the admin
 * session gate (server.ts ADMIN_SESSION_REQUIRED), a route with no
 * protection service behind it (server/approval-routes.ts arbiterDisabled)
 * and a protection service that stopped answering (server/tenant.ts
 * unreachableBody).
 *
 * Pins: each of the three is said in the page's words wherever a refused
 * request is shown (a Settings block, a Home card's answer, the file
 * explorer's folder and impact lines), never as the server wrote it; every
 * other error (the protection service's own refusal, any other 403 or 404)
 * is still shown as written; no body at all keeps the page's own fallback.
 * The sign-in sentence names its command as code (`mandu dashboard`, never
 * in quotes or backticks) on every path that shows a refusal; a server's
 * own text with backticks stays one text node, as written.
 * Because the bodies are the server's real strings, a rewording on the
 * server fails here instead of leaking again. A stopped protection service
 * is said the same way however the route passes it on (the 503
 * `unreachable` body, or the failed dial to its socket, bare or wrapped),
 * with "Start it under Settings" a link that opens Settings; so is a
 * connection the service closed with a request on its way, as the real
 * routes wrap it, and a scan it cut short says so in words; a refusal that
 * only looks like one (a TCP refusal, a spawn error) stays as written
 * (tests/stack/product-service-down-refusals and product-service-cut prove
 * the real routes).
 * Axes: none (display only).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import type { IncomingMessage, ServerResponse } from "node:http";
import { Readable } from "node:stream";

import { load, tick, FILES_URL, FILES_ROUTES, list, dot } from "./home-js-fixtures.js";
import { ADMIN_SESSION_REQUIRED } from "../../../src/server.js";
import { arbiterDisabled } from "../../../src/server/approval-routes.js";
import { unreachableBody } from "../../../src/server/tenant.js";
import { getSuggestions, postApply } from "../../../src/server/suggestion-routes.js";
import { getSensitivityLabels } from "../../../src/server/sensitivity-label-routes.js";
import { postExportLabels } from "../../../src/server/policy-doc-routes.js";

/** What a route handler answered, through a stand-in response. */
function answered(write: (res: ServerResponse) => void): { status: number; body: unknown } {
  let status = 0;
  let text = "";
  const res = { writeHead(s: number) { status = s; return res; }, end(t: string) { text = t; } };
  write(res as unknown as ServerResponse);
  return { status, body: JSON.parse(text) };
}
/** The same for a route that awaits the protection service first. */
async function answeredLater(write: (res: ServerResponse) => Promise<void>): Promise<{ status: number; body: { error: string } }> {
  let status = 0;
  let text = "";
  const res = { writeHead(s: number) { status = s; return res; }, end(t: string) { text = t; } };
  await write(res as unknown as ServerResponse);
  return { status, body: JSON.parse(text) };
}
/** A request body, as the routes read it. */
const sent = (body: unknown) => Readable.from([JSON.stringify(body)]) as unknown as IncomingMessage;

const ADMIN = { status: 403, body: { error: ADMIN_SESSION_REQUIRED } };
const NOT_CONNECTED = answered((res) => arbiterDisabled(res));
const DOWN = { status: 503, body: unreachableBody("live", new Error("arbiter connection failed: connect ECONNREFUSED")) };

const SIGN_IN = "Sign in first: in your own terminal, run mandu dashboard and open the sign-in link it prints (each link works once), or sign in with the dashboard's password if it has one.";
const NOT_CONNECTED_WORDS = "The protection service is not connected.";
const UNREACHABLE_WORDS = "The protection service is not running. Start it under Settings, or try again in a moment.";
/** What the server's own refusals say that the page must not. */
const DEVELOPER = /arbiter|admin session|DASHBOARD_|login\?token|X-Mandu|under Services/i;

const SETTINGS = "http://127.0.0.1:4500/mandu/settings";

/** The code elements under `node`, by their text. */
const codes = (node: any): string[] => [...node.querySelectorAll("code")].map((c: any) => c.textContent);
/** The links under `node`: text, href, the page they open. */
const links = (node: any): string[][] => [...node.querySelectorAll("a")].map((a: any) => [a.textContent, a.getAttribute("href"), a.dataset.pageLink]);
/** The one link of UNREACHABLE_WORDS: Settings, where the Start of the service is. */
const START = ["Start it under Settings", "/mandu/settings", "settings"];

/** A protection service that stopped, as most routes pass it on: the failed
 *  dial to its socket, bare (the approval routes over MANDU_ADMIN_SOCK, the
 *  policy routes) or wrapped (file-browser, sensitivity-label and suggestion
 *  routes: "the protection service did not answer (…)"), or the words of the
 *  arbiter client for the same (server/tenant.ts isArbiterUnreachable). */
const DIALS = [
  { status: 404, body: { error: "connect ENOENT /run/user/1000/mandu/admin.sock", approvalId: "egr-1" } },
  { status: 502, body: { error: "connect ECONNREFUSED /run/user/1000/mandu/current/arbiter.sock" } },
  { status: 502, body: { error: "the protection service did not answer (connect ENOENT /run/user/1000/mandu/current/arbiter.sock)" } },
  { status: 503, body: { error: "arbiter connection closed" } },
  { status: 503, body: { error: "arbiter connection failed (/run/user/1000/mandu/h.sock): connect ENOENT /run/user/1000/mandu/h.sock" } },
];
/** A connection the stopped service closed with a request on its way, in
 *  the words of the arbiter client (arbiter/ipc/client.ts onClose; the
 *  bare form is in DIALS), as the real routes wrap it: in the brackets of
 *  "the protection service did not answer (…)" (the suggestion,
 *  sensitivity-label and file-browser routes), after "…; nothing was saved"
 *  (a suggestion's Save), or after "arbiter: " (the policy-doc routes). */
const CUT = new Error("arbiter connection closed");
const cut = () => Promise.reject(CUT);
const CUTS = await Promise.all([
  answeredLater((res) => getSuggestions({ arbiter: { policySuggestions: cut }, workspaces: async () => [] }, res)),
  answeredLater((res) => getSensitivityLabels({ policyDocument: cut } as never, res)),
  answeredLater((res) => postApply({ arbiter: { policySuggestions: cut, resolvePolicyProposal: cut }, workspaces: async () => [] }, sent({ ids: ["pp-000001"] }), res)),
  answeredLater((res) => postExportLabels({ exportDbLabels: cut } as never, sent({}), res)),
]);
/** What a failed dial says that the page must not. */
const DIAL = /ENOENT|ECONNREFUSED|\.sock|\/run\/user|arbiter/;

test("the refusals are the server's own: the gate's 403, a 404 with no protection service, a 503 unreachable", () => {
  assert.match(ADMIN_SESSION_REQUIRED, DEVELOPER, "the gate's words name the admin session");
  assert.equal(NOT_CONNECTED.status, 404);
  assert.match((NOT_CONNECTED.body as { error: string }).error, DEVELOPER);
  assert.equal(DOWN.body.unreachable, true);
  assert.match(DOWN.body.error, DEVELOPER);
});

test("the routes wrap a connection cut with a request on its way in their own words, which the page must not show", () => {
  assert.deepEqual(CUTS.map((c) => [c.status, c.body.error]), [
    [502, "the protection service did not answer (arbiter connection closed)"],
    [502, "the protection service did not answer (arbiter connection closed)"],
    [502, "the protection service did not answer; nothing was saved (arbiter connection closed)"],
    [502, "arbiter: arbiter connection closed"],
  ]);
});

test("Settings: a block with no protection service says it is not connected; one the gate refuses says to sign in", async () => {
  const { doc } = load({ url: SETTINGS, routes: { "GET policy/sensitivity-labels": NOT_CONNECTED, "GET policy/prompt-filters": ADMIN } });
  await tick();
  assert.equal(doc.getElementById("settings-labels").textContent, NOT_CONNECTED_WORDS);
  assert.equal(doc.getElementById("settings-prompt-kinds").textContent, SIGN_IN);
  assert.deepEqual(codes(doc.getElementById("settings-prompt-kinds")), ["mandu dashboard"], "the command is code");
  assert.deepEqual(codes(doc.getElementById("settings-labels")), [], "a sentence with no command has none");
  assert.equal(doc.getElementById("prompt-exception-form").hidden, true, "nothing to add to while refused");
  assert.doesNotMatch(doc.getElementById("page-settings").textContent, DEVELOPER);
  // The other way round: the labels behind the gate, the service down.
  const swapped = load({ url: SETTINGS, routes: { "GET policy/sensitivity-labels": ADMIN, "GET policy/prompt-filters": DOWN } });
  await tick();
  assert.equal(swapped.doc.getElementById("settings-labels").textContent, SIGN_IN);
  assert.deepEqual(codes(swapped.doc.getElementById("settings-labels")), ["mandu dashboard"]);
  assert.equal(swapped.doc.getElementById("settings-prompt-kinds").textContent, UNREACHABLE_WORDS);
  assert.deepEqual(links(swapped.doc.getElementById("settings-prompt-kinds")), [START], "Start is a link to Settings");
  assert.doesNotMatch(swapped.doc.getElementById("page-settings").textContent, DEVELOPER);
});

/** Press Allow once on the first Home card, answered `answer`; the card's error line. */
async function allowOnce(answer: unknown): Promise<string> {
  return (await allowOnceLine(answer)).textContent;
}
/** The same, the line itself. */
async function allowOnceLine(answer: unknown): Promise<any> {
  const { doc } = load({ routes: { "POST egress/approvals/egr-1/approve-once": answer } });
  await tick();
  const btn = [...doc.querySelectorAll("#home-waiting .ask button")].find((b: any) => b.textContent === "Allow once") as any;
  btn.click();
  await tick();
  const e = doc.querySelector("#home-waiting .ask .ask-error");
  assert.ok(e, "the card says why the answer did not count");
  assert.equal(btn.disabled, false, "and the buttons work again");
  return e;
}

test("an answer the gate refuses, or one sent while the protection service is down, is said in the page's words on the card", async () => {
  const line = await allowOnceLine(ADMIN);
  assert.equal(line.textContent, SIGN_IN);
  assert.deepEqual(codes(line), ["mandu dashboard"], "the command is code, as on the rest of the page");
  assert.equal(await allowOnce(DOWN), UNREACHABLE_WORDS);
  assert.deepEqual(links(await allowOnceLine(DOWN)), [START], "Start is a link to Settings");
  assert.equal(await allowOnce(NOT_CONNECTED), NOT_CONNECTED_WORDS);
});

test("a protection service that stopped, however the route passes it on, is said in the page's words with Start a link to Settings", async () => {
  for (const answer of [...DIALS, ...CUTS]) {
    const line = await allowOnceLine(answer);
    assert.equal(line.textContent, UNREACHABLE_WORDS, answer.body.error);
    assert.doesNotMatch(line.textContent, DIAL, "no socket, no errno, no inspector word");
    assert.deepEqual(links(line), [START], answer.body.error);
    assert.deepEqual(codes(line), []);
  }
});

test("Start it under Settings opens Settings, where the Start of the service is", async () => {
  const { doc, window } = load({ routes: { "POST egress/approvals/egr-1/approve-once": DIALS[0] } });
  await tick();
  const btn = [...doc.querySelectorAll("#home-waiting .ask button")].find((b: any) => b.textContent === "Allow once") as any;
  btn.click();
  await tick();
  const link = doc.querySelector("#home-waiting .ask .ask-error a") as any;
  assert.ok(link, "the line has its link");
  link.dispatchEvent(new window.MouseEvent("click", { bubbles: true, cancelable: true }));
  await tick();
  assert.equal(doc.getElementById("page-settings").hidden, false, "Settings is open");
  assert.equal(doc.getElementById("page-home").hidden, true);
  assert.equal(window.location.pathname, "/mandu/settings");
  assert.ok(doc.getElementById("settings-protection-block"), "with its Protection block, the Start of the service");
});

test("on Settings, a card the stopped service could not fill says it with the link too", async () => {
  for (const answer of [DIALS[2], CUTS[1]]) {
    const { doc } = load({ url: SETTINGS, routes: { "GET policy/sensitivity-labels": answer } });
    await tick();
    const labels = doc.getElementById("settings-labels");
    assert.equal(labels.textContent, UNREACHABLE_WORDS, answer.body.error);
    assert.deepEqual(links(labels), [START]);
    assert.doesNotMatch(doc.getElementById("page-settings").textContent, DIAL);
  }
});

/** Rules with Keys Mandu found open, its list answered `answer`: the line under Scan. */
async function suggestError(answer: unknown): Promise<any> {
  const { doc } = load({ url: FILES_URL, routes: { ...FILES_ROUTES, "GET suggestions": answer } });
  await tick();
  doc.getElementById("suggest-open").click();
  await tick();
  return doc.getElementById("suggest-error");
}

test("Keys Mandu found: a list the stopped service cut short says it in the page's words, with the link", async () => {
  for (const answer of [CUTS[0], DIALS[2]]) {
    const line = await suggestError(answer);
    assert.equal(line.textContent, UNREACHABLE_WORDS, answer.body.error);
    assert.deepEqual(links(line), [START]);
  }
});

test("a scan the stopped service cut short says so in words; another scan's error stays as written", async () => {
  const scan = (error: string) => ({ suggestions: [], count: 0, scan: { running: false, startedAt: 1, finishedAt: 2, roots: ["~/proj"], includeHome: false, summary: null, summaryParts: null, error, filed: 0 } });
  const SCAN_STOPPED = "The scan did not finish because the protection service stopped. Press Scan for keys to try again.";
  for (const error of [
    // The client's words (arbiter/ipc/client.ts onClose) after the scan's
    // lead (server/suggestion-routes.ts postScan), and the failed dial.
    "The scan did not finish: arbiter connection closed",
    "The scan did not finish: connect ENOENT /run/user/1000/mandu/current/arbiter.sock",
  ]) {
    const line = await suggestError(scan(error));
    assert.equal(line.textContent, SCAN_STOPPED, error);
    assert.doesNotMatch(line.textContent, DIAL);
  }
  for (const error of [
    "Another scan is running (started from the terminal or when an agent started). Try again when it ends.",
    "The scan did not finish: the folder could not be read",
  ]) assert.equal((await suggestError(scan(error))).textContent, error);
});

test("a refusal that only looks like a stopped service is shown as written", async () => {
  for (const error of [
    // A model endpoint (an address and a port), not the socket of the service.
    "connect ECONNREFUSED 127.0.0.1:443",
    // A program that could not start: no socket was dialled.
    "spawn node ENOENT",
    "readiness timeout after 15000ms (endpoint /run/user/1000/mandu/current/arbiter.sock)",
    // The words of the client inside a sentence of its own, not a wrapper.
    "the model said: arbiter connection closed is not a key",
  ]) {
    const line = await allowOnceLine({ status: 502, body: { error } });
    assert.equal(line.textContent, error);
    assert.deepEqual(links(line), []);
  }
});

test("any other refusal is shown as the server wrote it, and no body keeps the page's own fallback", async () => {
  // The protection service's own refusal (the design shows its text).
  assert.equal(await allowOnce({ status: 409, body: { error: "This question was already answered." } }), "This question was already answered.");
  // Not every 403 is the gate, nor every 404 a missing service.
  assert.equal(await allowOnce({ status: 403, body: { error: "Your administrator decides this one." } }), "Your administrator decides this one.");
  assert.equal(await allowOnce({ status: 404, body: { error: "This question is gone." } }), "This question is gone.");
  // A 503 that is not `unreachable` (the admin channel lost) keeps its remedy.
  assert.equal(await allowOnce({ status: 503, body: { error: "Restart the services from Settings to regain control." } }), "Restart the services from Settings to regain control.");
  assert.equal(await allowOnce({ status: 502, body: null }), "could not record your answer (502)");
});

test("the sign-in sentence names its command as code, never quoted; a server's backticks stay as written", async () => {
  // The page's own sentence: no quote and no backtick around the command
  // (a path that showed it as a string would read plain words, not marks).
  const line = await allowOnceLine(ADMIN);
  assert.doesNotMatch(line.textContent, /["`]/);
  const code = line.querySelector("code");
  assert.equal(code.textContent, "mandu dashboard");
  assert.equal(code.previousSibling.textContent, "Sign in first: in your own terminal, run ");
  assert.match(code.nextSibling.textContent, /^ and open the sign-in link it prints/);
  // A server's own text is not the page's: shown as written, one text node.
  const theirs = await allowOnceLine({ status: 409, body: { error: "Answer it with `mandu why` first." } });
  assert.equal(theirs.textContent, "Answer it with `mandu why` first.");
  assert.deepEqual(codes(theirs), []);
  assert.equal(theirs.childNodes.length, 1);
});

test("Files and folders: a folder the gate refuses, and a refused impact line, say to sign in", async () => {
  // The real server refuses both the start folder and the home folder the
  // page falls back to.
  const { doc, calls } = load({ url: FILES_URL, routes: { [list("/home/u/ws")]: ADMIN, [list("~")]: ADMIN } });
  await tick();
  doc.getElementById("rules-add").click();
  await tick();
  const note = doc.getElementById("files-note");
  assert.equal(note.hidden, false);
  assert.equal(note.textContent, SIGN_IN);
  assert.deepEqual(codes(note), ["mandu dashboard"]);
  assert.ok(calls.some((c) => c.url.endsWith("/api/files/list?path=~")), "after the fallback too");

  // The impact line: a refusal the page words is a sentence of its own; a
  // reason the server worded follows the colon, as before.
  for (const [answer, want] of [
    [ADMIN, `What this changes could not be worked out. ${SIGN_IN}`],
    [{ status: 500, body: { error: "the folder is too large to check" } }, "What this changes could not be worked out: the folder is too large to check."],
    [{ status: 500, body: null }, "What this changes could not be worked out."],
  ] as const) {
    const page = load({ url: FILES_URL, routes: { ...FILES_ROUTES, "POST files/impact": answer } });
    await tick();
    page.doc.getElementById("rules-add").click();
    await tick();
    dot(page.doc, /^config\//, "public");
    await tick();
    assert.equal(page.doc.getElementById("files-impact").textContent, want);
    assert.deepEqual(codes(page.doc.getElementById("files-impact")), answer === ADMIN ? ["mandu dashboard"] : []);
  }
});
