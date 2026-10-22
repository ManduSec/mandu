/**
 * sign-in-gate.test — the pure pieces of the dashboard's sign-in page
 * (src/server/sign-in-gate.ts; dashboard.md §6.z): where a sign-in may send
 * the person, which POSTs come from the dashboard's own page, which
 * requests are a browser opening a page, the throttle's schedule, the
 * sessions' lifetime and the page's own HTML.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import type { IncomingMessage } from "node:http";

import {
  SESSION_CAP, SESSION_IDLE_MS, SESSION_MAX_MS, SignInSessions, SignInThrottle, THROTTLE_MAX_LOCK_MS,
  arrivedOverHttps, fromOwnPage, isNavigation, safeNext, signInCookieOf, signInPage,
} from "../../src/server/sign-in-gate.js";

const req = (headers: Record<string, string>, method = "GET", encrypted = false): IncomingMessage =>
  ({ headers, method, socket: { encrypted } }) as unknown as IncomingMessage;

test("safeNext: a path of this dashboard, else Home", () => {
  for (const ok of ["/", "/rules", "/agents/x?ask=1", "/rules#keys-found", "/a/b/c"]) assert.equal(safeNext(ok), ok);
  for (const bad of [null, undefined, "", "rules", "//evil", "/\\evil", "https://evil/", "javascript:x", "/a b", "/a\tb", "/x\\y", "/login", "/logout?x=1", "/" + "a".repeat(3000)]) {
    assert.equal(safeNext(bad as string), "/", JSON.stringify(bad));
  }
});

test("fromOwnPage: the Origin (or Referer) must name this dashboard; Sec-Fetch-Site must be same-origin", () => {
  const own = (h: string): boolean => h === "localhost:4500";
  assert.equal(fromOwnPage(req({ host: "127.0.0.1:4500", origin: "http://127.0.0.1:4500" }), own), true);
  assert.equal(fromOwnPage(req({ host: "127.0.0.1:4500", origin: "http://localhost:4500" }), own), true, "another name of this dashboard");
  assert.equal(fromOwnPage(req({ host: "dash.example.org", origin: "https://dash.example.org" }), own), true, "behind a tunnel: the Host it forwards");
  assert.equal(fromOwnPage(req({ host: "127.0.0.1:4500", referer: "http://127.0.0.1:4500/login" }), own), true);
  assert.equal(fromOwnPage(req({ host: "127.0.0.1:4500", origin: "http://evil.example" }), own), false);
  assert.equal(fromOwnPage(req({ host: "127.0.0.1:4500", origin: "null" }), own), false);
  assert.equal(fromOwnPage(req({ host: "127.0.0.1:4500" }), own), false, "neither header");
  assert.equal(fromOwnPage(req({ host: "127.0.0.1:4500", origin: "http://127.0.0.1:4500", "sec-fetch-site": "cross-site" }), own), false);
  assert.equal(fromOwnPage(req({ host: "127.0.0.1:4500", origin: "http://127.0.0.1:4500", "sec-fetch-site": "same-site" }), own), false, "another port of localhost is same-site");
  assert.equal(fromOwnPage(req({ host: "127.0.0.1:4500", origin: "ftp://127.0.0.1:4500" }), own), false);
  assert.equal(fromOwnPage(req({ host: "127.0.0.1:4500", referer: "not a url" }), own), false);
});

test("isNavigation: a page the person opens, not a fetch, a stream or a script", () => {
  assert.equal(isNavigation(req({ accept: "text/html,application/xhtml+xml" })), true);
  assert.equal(isNavigation(req({ accept: "text/html", "sec-fetch-dest": "document" })), true);
  assert.equal(isNavigation(req({ accept: "text/html" }, "HEAD")), true);
  assert.equal(isNavigation(req({ accept: "*/*" })), false);
  assert.equal(isNavigation(req({ accept: "text/event-stream" })), false);
  assert.equal(isNavigation(req({ accept: "text/html", "sec-fetch-dest": "empty" })), false, "a fetch() asking for HTML");
  assert.equal(isNavigation(req({ accept: "text/html" }, "POST")), false);
});

test("arrivedOverHttps: the socket's TLS or the front's X-Forwarded-Proto", () => {
  assert.equal(arrivedOverHttps(req({})), false);
  assert.equal(arrivedOverHttps(req({}, "GET", true)), true);
  assert.equal(arrivedOverHttps(req({ "x-forwarded-proto": "https" })), true);
  assert.equal(arrivedOverHttps(req({ "x-forwarded-proto": "https, http" })), true);
  assert.equal(arrivedOverHttps(req({ "x-forwarded-proto": "http" })), false);
});

test("signInCookieOf: the sign-in cookie among others", () => {
  assert.equal(signInCookieOf(req({ cookie: "a=1; mandu_signin=abc; mandu_session=x" })), "abc");
  assert.equal(signInCookieOf(req({ cookie: "mandu_session=x" })), null);
  assert.equal(signInCookieOf(req({})), null);
});

test("the throttle: 5 failures in a minute lock 30 s, then 60 s, … up to 15 min; an hour's quiet or a success forgets", () => {
  let t = 0;
  const th = new SignInThrottle(() => t);
  const five = (): number => { let lock = 0; for (let i = 0; i < 5; i++) lock = th.fail(); return lock; };
  assert.equal(five(), 30_000);
  assert.ok(th.waitMs() > 0);
  t += 30_001;
  assert.equal(th.waitMs(), 0);
  assert.equal(five(), 60_000);
  t += 60_001;
  const locks: number[] = [];
  for (let i = 0; i < 8; i++) { locks.push(five()); t += locks[locks.length - 1]! + 1; }
  assert.equal(Math.max(...locks), THROTTLE_MAX_LOCK_MS, "capped: never locked for good");
  t += 3_600_001;
  assert.equal(five(), 30_000, "an hour without a failure forgets the earlier locks");
  t += 30_001;
  th.fail(); th.fail();
  th.succeed();
  assert.equal(th.recent(), 0);
  // Failures spread wider than the window never lock.
  for (let i = 0; i < 20; i++) { assert.equal(th.fail(), 0); t += 15_000; }
});

test("sessions: random ids, 12 h idle, 7 days at most, a cap, drop and drop all", () => {
  let t = 0;
  const s = new SignInSessions(() => t);
  const a = s.create();
  assert.match(a, /^[A-Za-z0-9_-]{43}$/);
  assert.notEqual(s.create(), a);
  assert.equal(s.valid(a), true);
  assert.equal(s.valid("x"), false);
  for (let i = 0; i < 6; i++) { t += SESSION_IDLE_MS - 1000; assert.equal(s.valid(a), true, `day ${i}: used, kept`); }
  t += SESSION_MAX_MS;
  assert.equal(s.valid(a), false, "7 days at most");
  const b = s.create();
  s.drop(b);
  assert.equal(s.valid(b), false);
  const c = s.create();
  s.dropAll();
  assert.equal(s.valid(c), false);
  const first = s.create();
  for (let i = 0; i < SESSION_CAP; i++) s.create();
  assert.equal(s.size, SESSION_CAP);
  assert.equal(s.valid(first), false, "the oldest goes past the cap");
});

test("the page: the fields, escaped values, no script; no form without a usable account", () => {
  const page = signInPage("/mandu", `/x"><script>`, { kind: "wrong" }, `a"<b`);
  assert.match(page, /action="\/mandu\/login"/);
  assert.match(page, /Wrong username or password\./);
  assert.ok(!page.includes(`"><script>`) && !page.includes(`a"<b`), "values are escaped");
  assert.doesNotMatch(page, /<script/i);
  assert.match(signInPage("", "/", { kind: "wait", seconds: 1 }), /Wait 1 second,/);
  const none = signInPage("", "/", { kind: "no-account" });
  assert.doesNotMatch(none, /<form/);
  assert.match(none, /mandu dashboard --set-password/);
  const unsafe = signInPage("", "/", { kind: "unsafe" });
  assert.doesNotMatch(unsafe, /<form/);
  assert.match(unsafe, /cannot be used/);
});
