/**
 * page-routes.test — the dashboard's page URL table (dashboard.md §4.25v):
 * which base-stripped paths each front-end's index.html answers (pageFor),
 * and the path form of every retired query-string page URL (legacyRedirect).
 * Pure functions, no server. Axes: none (routing only). Mandu-new test.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { legacyRedirect, pageFor } from "../../../src/server/page-routes.js";

test("the product's route table: home, approvals (± a question), rules, settings, an agent", () => {
  for (const p of ["/", "/index.html", "/approvals", "/approvals/egr-1", "/rules", "/settings", "/agents/s1"]) {
    assert.equal(pageFor(p), "product", p);
  }
  assert.equal(pageFor("/agents/sess%20b%2F2"), "product", "an encoded segment is one segment");
  assert.equal(pageFor("/approvals/%22%5D%2C*"), "product");
});

test("the developer view's route table (§4.32): its root, the six pages, the sub-pages, a session on each session page", () => {
  for (const p of [
    "/dev/", "/dev/index.html",
    "/dev/sessions", "/dev/drills", "/dev/tests", "/dev/approvals", "/dev/rules", "/dev/settings",
    "/dev/drills/matrix", "/dev/drills/agents", "/dev/drills/comparison", "/dev/drills/videos", "/dev/tests/suites", "/dev/tests/coverage", "/dev/tests/vm", "/dev/tests/ci",
    "/dev/sessions/s1", "/dev/sessions/a%2Fb", "/dev/drills/gl-1-2%2Ffidelity-echo-claude-80x24", "/dev/tests/e2e-x-1",
  ]) {
    assert.equal(pageFor(p), "inspector", p);
  }
});

test("everything else is no page: assets, API, unknown paths, a missing or extra segment, a garbled encoding", () => {
  for (const p of [
    "/app.css", "/js/home.js", "/mandu.css", "/fonts/x.woff2", "/api/home", "/login", "/slides/deck.html",
    "/inbox", "/agent", "/agents", "/agents/", "/agents/s1/x", "/approvals/", "/approvals/a/b", "/rules/", "/rules/x", "/settings/x",
    "/agents/%E0%A4%A", "/approvals/%zz",
    "/dev", "/dev/js/app.js", "/dev/js/pages.js", "/dev/dashboard.css", "/dev/nowhere", "/dev/sessions/", "/dev/sessions/a/b", "/dev/status/x",
    "/dev/sessions/%E0%A4%A", "/nope", "/index.htm", "/dev/approvals/x", "/dev/rules/x", "/dev/settings/x", "/dev/drills/matrix/x", "/dev/drills/agents/x", "/dev/drills/comparison/x", "/dev/drills/videos/x", "/dev/tests/ci/x",
    "/dev/inbox", "/dev/status", "/dev/policy", // the renamed pages: a redirect (below), not a page
  ]) {
    assert.equal(pageFor(p), null, p);
  }
});

test("retired product URLs map to their path, the query's other keys kept", () => {
  const cases: [string, string][] = [
    ["/?page=inbox", "/approvals"],
    ["/?page=inbox&ask=egr-1", "/approvals/egr-1"],
    ["/?page=inbox&ask=a%2Fb%20c", "/approvals/a%2Fb%20c"],
    ["/?page=approvals&ask=x", "/approvals/x"],
    ["/?page=rules", "/rules"],
    ["/?page=settings", "/settings"],
    ["/?page=agent&session=s1", "/agents/s1"],
    ["/?page=agent&session=s1&ask=egr-7", "/agents/s1?ask=egr-7"],
    ["/?page=agent&session=sess%20b%2F2&ask=a%26b", "/agents/sess%20b%2F2?ask=a%26b"],
    ["/?page=agent", "/"],
    ["/?page=home", "/"],
    ["/?page=nowhere", "/"],
    ["/index.html?page=rules", "/rules"],
    ["/?page=rules&tenant=test", "/rules?tenant=test"],
    ["/?tenant=test&page=inbox&ask=q", "/approvals/q?tenant=test"],
  ];
  for (const [from, to] of cases) assert.equal(legacyRedirect(from), to, from);
});

test("retired inspector URLs map to their path", () => {
  const cases: [string, string][] = [
    ["/dev/?session=s1", "/dev/sessions/s1"],
    ["/dev?session=s1", "/dev/sessions/s1"],
    ["/dev/?session=a%2Fb", "/dev/sessions/a%2Fb"],
    ["/dev/?area=status", "/dev/sessions"],
    ["/dev/?area=status&session=s1", "/dev/sessions/s1"],
    ["/dev/?area=approvals", "/dev/approvals"],
    ["/dev/?area=inbox", "/dev/approvals"],
    ["/dev/?area=inbox&session=s1", "/dev/approvals?session=s1"],
    ["/dev/?area=policy&session=s1", "/dev/rules?session=s1"],
    ["/dev/?area=policy", "/dev/rules"],
    ["/dev/?area=rules", "/dev/rules"],
    ["/dev/?area=tests", "/dev/tests"],
    ["/dev/?area=settings", "/dev/settings"],
    ["/dev/?area=nowhere", "/dev/sessions"],
    ["/dev/?area=nowhere&session=s1", "/dev/sessions/s1"],
    ["/dev/?area=", "/dev/"],
    ["/dev/index.html?area=inbox&tenant=test", "/dev/approvals?tenant=test"],
  ];
  for (const [from, to] of cases) assert.equal(legacyRedirect(from), to, from);
});

test("the renamed pages: /dev/inbox (Inbox until 2026-10-02), /dev/status and /dev/policy (until 2026-10-03) are a 302 to the new page, the query kept", () => {
  const cases: [string, string][] = [
    ["/dev/inbox", "/dev/approvals"],
    ["/dev/inbox?session=s1", "/dev/approvals?session=s1"],
    ["/dev/inbox?tenant=test&session=a%2Fb", "/dev/approvals?tenant=test&session=a%2Fb"],
    ["/dev/status", "/dev/sessions"],
    ["/dev/status?session=s1", "/dev/sessions?session=s1"],
    ["/dev/policy", "/dev/rules"],
    ["/dev/policy?session=s1&tenant=live", "/dev/rules?session=s1&tenant=live"],
  ];
  for (const [from, to] of cases) assert.equal(legacyRedirect(from), to, from);
  // Only the page path itself: deeper paths and the product's names are not it.
  for (const u of ["/dev/inbox/x", "/dev/policy/x", "/dev/sessions/inbox", "/dev/sessions/policy", "/inbox", "/policy", "/dev/approvals", "/dev/approvals?session=s1", "/dev/rules?session=s1"]) {
    assert.equal(legacyRedirect(u), null, u);
  }
});

test("a path URL, or a query without the retired keys, is not a redirect", () => {
  for (const u of ["/", "/rules", "/?x=1", "/agents/s1?ask=a", "/approvals/q", "/dev/", "/dev/?x=1", "/dev/rules?session=s1", "/dev/tests/ci?session=s1", "/rules?page=inbox", "/api/home?page=inbox", "/dev/sessions/s1?area=inbox"]) {
    assert.equal(legacyRedirect(u), null, u);
  }
});
