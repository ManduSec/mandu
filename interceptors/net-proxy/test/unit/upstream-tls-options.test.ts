/**
 * upstream-tls-options — what a Kubernetes cluster's dial adds to the
 * re-origination (docs/design/confidentiality/kube-wire-release.md §4): its
 * CA, `tls-server-name`, `insecure-skip-tls-verify`, and the client
 * certificate only for a request without an Authorization header; the pool
 * key keeps the two kinds of connection apart. Pure.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { upstreamTlsOptions } from "../../src/mitm.js";

const client = { cert: "CERT-PEM", key: "KEY-PEM" };

test("no profile: nothing added, the default pool key", () => {
  assert.deepEqual(upstreamTlsOptions(null, false), { poolKey: "" });
  assert.deepEqual(upstreamTlsOptions(null, true), { poolKey: "" });
});

test("a profile: its CA and name; the client certificate only without Authorization", () => {
  const p = { ca: "CA-PEM", servername: "api.internal", insecure: false, client };
  assert.deepEqual(upstreamTlsOptions(p, false), { poolKey: "kube:client", ca: "CA-PEM", servername: "api.internal", cert: "CERT-PEM", key: "KEY-PEM" });
  assert.deepEqual(upstreamTlsOptions(p, true), { poolKey: "kube", ca: "CA-PEM", servername: "api.internal" });
  assert.deepEqual(upstreamTlsOptions({ insecure: true }, false), { poolKey: "kube", insecure: true });
  assert.deepEqual(upstreamTlsOptions({ insecure: false, clientWhy: "2 users" }, false), { poolKey: "kube" });
});
