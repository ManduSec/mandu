/**
 * product-only-build.test — dashboard.md §4.25ac: a dashboard handed no
 * extension (the default; what a build without the developer view runs)
 * serves the product page only. `/dev` and its pages answer 404 with a page
 * that says the developer view is available on request (never the product's
 * index), its files a plain 404, the developer view's routes are
 * not there (its reads are `admin` in the read gate, so a signed-in read
 * finds nothing and a signed-out one is refused), the product's index tells
 * home.js which front-ends exist (`extensions`), and the product's own
 * routes, the session read API among them, are unchanged.
 */

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { DashboardServer } from "../../src/server.js";
import { FileEventSource } from "../../src/event-source.js";
import { pageFetch } from "../unit/page-fetch.js";

const FIXTURES_DIR = join(fileURLToPath(new URL(".", import.meta.url)), "..", "..", "fixtures");

let server: DashboardServer;
let base: string;

before(async () => {
  server = new DashboardServer({ source: new FileEventSource(FIXTURES_DIR), basePath: "/mandu", log: () => {} });
  base = `http://127.0.0.1:${await server.listen(0)}/mandu`;
});

after(async () => {
  await server.close();
});

test("/dev and its pages answer 404 with a page that says the developer view is on request; never the product's index", async () => {
  for (const path of ["/dev", "/dev/", "/dev/sessions", "/dev/sessions/sess-7af3", "/dev/rules"]) {
    const r = await pageFetch(`${base}${path}`, { redirect: "manual" });
    assert.equal(r.status, 404, path);
    assert.match(r.headers.get("content-type") ?? "", /^text\/html/, path);
    const html = await r.text();
    assert.match(html, /The developer view is not included in this version/, path);
    assert.match(html, /available on request: write to <a href="mailto:hello@mandusecurity\.com">/, path);
    assert.match(html, /<base href="\/mandu\/">/, `${path}: the product's stylesheets and Back link resolve under the base path`);
    assert.match(html, /<a class="btn link-btn" href="\.\/">Back to Mandu<\/a>/, path);
    assert.doesNotMatch(html, /mandu-app|<script/i, `${path}: not the product's index, and no script`);
  }
  // HEAD answers the same status; another verb is not a page.
  assert.equal((await pageFetch(`${base}/dev/`, { method: "HEAD" })).status, 404);
  // A sibling of the mount is not under it.
  assert.doesNotMatch(await (await pageFetch(`${base}/devices`)).text(), /developer view is not included/);
});

test("the developer view's files answer a plain 404, never a page", async () => {
  for (const path of ["/dev/js/app.js", "/dev/dashboard.css", "/dev/index.html"]) {
    const r = await pageFetch(`${base}${path}`, { redirect: "manual" });
    assert.equal(r.status, 404, path);
    assert.doesNotMatch(await r.text(), /<html/i, `${path}: never a page`);
  }
});

test("the product page is served, naming no extension; its routes and the session read API answer", async () => {
  const r = await pageFetch(`${base}/`);
  assert.equal(r.status, 200);
  assert.match(await r.text(), /<meta name="extensions" content="">/);
  assert.equal((await pageFetch(`${base}/js/home.js`)).status, 200);
  assert.equal((await pageFetch(`${base}/api/home`)).status, 200);
  const sessions = await pageFetch(`${base}/api/sessions`);
  assert.equal(sessions.status, 200);
  const body = (await sessions.json()) as { sessions: Array<{ id: string }>; canStart: Record<string, boolean> };
  assert.ok(body.sessions.some((s) => s.id === "sess-7af3"), "the store's sessions");
  assert.deepEqual(body.canStart, { agent: false, suite: false, drill: false }, "nothing to start without the developer view");
  assert.equal((await pageFetch(`${base}/api/events?session=sess-7af3`)).status, 200);
});

test("the developer view's routes are not there: refused signed out, not found signed in", async () => {
  const admin = { cookie: server.adminCookie(), "x-mandu-control": "1" };
  for (const path of ["/api/test", "/api/run", "/api/drills", "/api/control/status", "/api/policy/document", "/api/fs?session=sess-7af3", "/api/run/samples"]) {
    assert.equal((await pageFetch(`${base}${path}`)).status, 403, `${path} signed out`);
    assert.equal((await pageFetch(`${base}${path}`, { headers: admin })).status, 404, `${path} signed in`);
  }
});
