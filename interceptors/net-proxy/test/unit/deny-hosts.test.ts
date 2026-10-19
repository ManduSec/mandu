/**
 * deny-hosts.test — the agent upload-host list (supported-agents.md §5.3.4
 * rule 1): parsing MANDU_NET_PROXY_DENY_HOSTS and matching a destination. A
 * twin of launcher upload-deny.ts `parseDenyEntry`; the two must agree.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { deniedHost, denyHostReason, denyHostsForIdentity, parseDenyHost, parseDenyHosts } from "../../src/deny-hosts.js";

test("parseDenyHost: host, host:port, .suffix, [v6]:port; junk is dropped", () => {
  assert.deepEqual(parseDenyHost("US.I.PostHog.com"), { host: "us.i.posthog.com", port: null, suffix: false });
  assert.deepEqual(parseDenyHost("collector.example:4318"), { host: "collector.example", port: 4318, suffix: false });
  assert.deepEqual(parseDenyHost(".traces.example."), { host: "traces.example", port: null, suffix: true });
  assert.deepEqual(parseDenyHost("[2001:db8::1]:443"), { host: "2001:db8::1", port: 443, suffix: false });
  for (const bad of ["", " ", "http://x.example/", "a..b", "x.example:0", "x.example:70000", ".[::1]", "a b", "x/y"]) {
    assert.equal(parseDenyHost(bad), null, bad);
  }
  assert.deepEqual(parseDenyHosts(" relay.damus.io, ,bad host,nos.lol:443").map((r) => r.host), ["relay.damus.io", "nos.lol"]);
  assert.deepEqual(parseDenyHosts(undefined), []);
});

test("deniedHost: exact host (case, brackets, trailing dot), port, and subdomains only for a .suffix", () => {
  const rules = parseDenyHosts("us.i.posthog.com,collector.example:4318,.traces.example,[2001:db8::1]");
  assert.ok(deniedHost("us.i.posthog.com", 443, rules));
  assert.ok(deniedHost("US.I.POSTHOG.COM.", 80, rules), "case and a trailing dot ignored");
  assert.equal(deniedHost("eu.i.posthog.com", 443, rules), null, "another host");
  assert.equal(deniedHost("x.us.i.posthog.com", 443, rules), null, "no subdomain without a leading dot");
  assert.ok(deniedHost("collector.example", 4318, rules));
  assert.equal(deniedHost("collector.example", 443, rules), null, "a port rule matches its port only");
  assert.ok(deniedHost("traces.example", 443, rules));
  assert.ok(deniedHost("a.b.traces.example", 443, rules), "a .suffix matches subdomains");
  assert.equal(deniedHost("nottraces.example", 443, rules), null, "a suffix matches on a label boundary");
  assert.ok(deniedHost("[2001:db8::1]", 443, rules));
  assert.equal(deniedHost("anything", 443, []), null, "no rules: nothing denied");
});

test("the reason names the host and nothing else; the identity form round-trips", () => {
  assert.match(denyHostReason("us.i.posthog.com"), /us\.i\.posthog\.com is an upload host/);
  const rules = parseDenyHosts("US.I.posthog.com,.traces.example,collector.example:4318,[2001:db8::1]:443");
  assert.deepEqual(denyHostsForIdentity(rules), ["us.i.posthog.com", ".traces.example", "collector.example:4318", "[2001:db8::1]:443"]);
  assert.deepEqual(denyHostsForIdentity(parseDenyHosts(denyHostsForIdentity(rules).join(","))), denyHostsForIdentity(rules));
});
