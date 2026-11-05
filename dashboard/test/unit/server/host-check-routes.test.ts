/**
 * host-check-routes.test — `GET /api/policy/host-check?host=…`, Rules'
 * "Check a host" box (dashboard.md §4.25aa *Check a host*), over a REAL
 * DashboardServer with a FAKE arbiter that records what it was asked.
 *
 * What it pins:
 *   - the host is checked before the arbiter is asked: a pasted URL or path
 *     is stripped, an empty, spaced or too long one refused 400 in words;
 *   - 501 with no `whyHost` (an older arbiter: the page hides the box);
 *   - 503 on the admin boundary, 502 on any other failure, as files/why;
 *   - the answer is `{ check }` in words, with no placeholder;
 *   - the read gate's entry: open, as `/api/policy/by-who`.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { DashboardServer, type SecretsArbiter } from "../../../src/server.js";
import type { EventSource } from "../../../src/event-source.js";
import { readAccessOf, readRouteOf } from "../../../src/server/read-gate.js";
import { ADMIN_UNAVAILABLE_PREFIX } from "../../../src/server/http-util.js";

const fakeSource: EventSource = {
  async listSessions() { return []; },
  async readEvents() { return []; },
  subscribe() { return () => {}; },
  close() {},
};

const SYMBOL = "$MDU:nomodel_Read[0123abcd].STRIPE_KEY";

async function start(whyHost: SecretsArbiter["whyHost"] | null) {
  const asked: string[] = [];
  const secrets = {
    async confidentialityState() { return { enabled: true, secrets: [] }; },
    async setPathLabel() { throw new Error("no write"); },
    async removePathLabel() { throw new Error("no write"); },
    ...(whyHost ? { whyHost: async (host: string) => { asked.push(host); return whyHost(host); } } : {}),
  } as unknown as SecretsArbiter;
  const server = new DashboardServer({ source: fakeSource, secretsArbiter: secrets, fileBrowserHome: "/home/u", log: () => {} });
  const base = `http://127.0.0.1:${await server.listen(0)}`;
  const get = async (host: string | null) => {
    const r = await fetch(`${base}/api/policy/host-check${host === null ? "" : `?host=${encodeURIComponent(host)}`}`);
    const raw = await r.text();
    return { status: r.status, raw, body: JSON.parse(raw) as any };
  };
  return { base, asked, get, close: () => server.close() };
}

const answer = (host: string) => ({
  host,
  axis: true,
  bound: host === "api.stripe.com" ? [{ path: "/home/u/app/.env", level: "no-model", binding: ["api.stripe.com"], source: "label" }] : [],
  release: { bound: null, unbound: { decision: { allow: false, requiresApproval: true }, stage: "built-in" } },
  destinations: [],
  verdicts: [{ symbol: SYMBOL, status: "approved", scope: "always" }],
});

test("the answer in words: the host as checked, the bound file, any other secret, the earlier answers counted, no placeholder", async () => {
  const h = await start(async (host) => answer(host));
  try {
    const r = await h.get(" HTTPS://API.Stripe.com/v1/charges ");
    assert.equal(r.status, 200);
    assert.deepEqual(h.asked, ["api.stripe.com"], "asked for the host alone");
    assert.equal(r.body.check.host, "api.stripe.com");
    assert.deepEqual(r.body.check.lines.map((l: any) => l.text), [
      "1 of your secrets may be sent there: ~/app/.env.",
      "Any other secret sent there: Mandu asks you first.",
      "You answered 1 earlier send to this host. Find them in Approvals.",
    ]);
    assert.ok(!r.raw.includes("$MDU:"), "CONFIDENTIALITY VIOLATION: a placeholder in the answer");
  } finally { await h.close(); }
});

test("a host the box refuses: 400 in words, the arbiter never asked", async () => {
  const h = await start(async (host) => answer(host));
  try {
    for (const bad of [null, "", "  ", "api stripe.com", "user@host.com", "a".repeat(254)]) {
      const r = await h.get(bad);
      assert.equal(r.status, 400, String(bad));
      assert.match(r.body.error, /^Type a host name, like api\.example\.com/, String(bad));
    }
    assert.deepEqual(h.asked, []);
    // A path pasted after the host is stripped, not refused.
    assert.equal((await h.get("pastebin.com/raw/x")).status, 200);
    assert.deepEqual(h.asked, ["pastebin.com"]);
  } finally { await h.close(); }
});

test("an arbiter with no whyHost: 501, so the page hides the box", async () => {
  const h = await start(null);
  try {
    const r = await h.get("api.stripe.com");
    assert.equal(r.status, 501);
    assert.match(r.body.error, /cannot check a host/);
  } finally { await h.close(); }
});

test("no protection service behind the dashboard: 501 too", async () => {
  const server = new DashboardServer({ source: fakeSource, log: () => {} });
  const base = `http://127.0.0.1:${await server.listen(0)}`;
  try {
    assert.equal((await fetch(`${base}/api/policy/host-check?host=api.stripe.com`)).status, 501);
  } finally { await server.close(); }
});

test("the protection service did not answer: 503 at the admin boundary, 502 otherwise", async () => {
  const boundary = await start(async () => { throw new Error(`${ADMIN_UNAVAILABLE_PREFIX}: restart`); });
  try {
    const r = await boundary.get("api.stripe.com");
    assert.equal(r.status, 503);
    assert.match(r.body.error, /^the protection service did not answer/);
  } finally { await boundary.close(); }
  const other = await start(async () => { throw new Error("socket closed"); });
  try {
    const r = await other.get("api.stripe.com");
    assert.equal(r.status, 502);
    assert.equal(r.body.error, "the protection service did not answer (socket closed)");
  } finally { await other.close(); }
});

test("read gate: open, its own entry, as /api/policy/by-who (names, hosts and counts, never a value)", () => {
  assert.equal(readRouteOf("/api/policy/host-check")?.path, "/api/policy/host-check");
  assert.equal(readAccessOf("/api/policy/host-check"), "open");
  assert.equal(readAccessOf("/api/policy/host-check"), readAccessOf("/api/policy/by-who"));
  assert.equal(readAccessOf("/api/policy/host-check/x"), "admin", "nothing under it");
});

test("a POST is no route: the box changes nothing and asks nothing", async () => {
  const h = await start(async (host) => answer(host));
  try {
    const r = await fetch(`${h.base}/api/policy/host-check?host=api.stripe.com`, { method: "POST", headers: { "X-Mandu-Control": "1" } });
    assert.notEqual(r.status, 200);
    assert.deepEqual(h.asked, []);
  } finally { await h.close(); }
});
