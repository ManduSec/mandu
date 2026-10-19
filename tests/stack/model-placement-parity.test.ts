/**
 * model-placement-parity.test.ts — ONE placement rule in four packages
 * (docs/design/confidentiality/model-endpoints.md §2 D1, D2).
 *
 * "Is this declared model on this computer (`host`) or on a network
 * (`network`)?" decides whether plain http is refused, and is answered in
 * four places that ship standalone and cannot import each other:
 *   - arbiter/policy/model-placement.ts        refuses the policy file at load
 *   - launcher/src/model-endpoints.ts          the launch belt, the warning,
 *                                              and the doctor rows
 *   - interceptors/inspect-mcp/src/ullm-client.ts  the helper's per-call refusal
 *   - dashboard/src/view-model/model-endpoints.ts  the Settings rows, the
 *                                              probe and the Inbox warning
 * A drift would let an address through one door that another refuses. This
 * runs all four over one table and asserts they agree with the expected
 * answer.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { endpointPlacement as arbiterRule } from "../../arbiter/policy/model-placement.js";
import { endpointPlacement as launcherRule } from "../../launcher/src/model-endpoints.js";
import { endpointPlacement as helperRule } from "../../interceptors/inspect-mcp/src/ullm-client.js";
import { endpointPlacement as dashboardRule } from "../../dashboard/src/view-model/model-endpoints.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // the rule protects local-model data (the confidentiality axis); it reads no axis itself

const TABLE: ReadonlyArray<readonly [string, "host" | "network" | null]> = [
  // Every loopback spelling.
  ["http://127.0.0.1:11434", "host"],
  ["http://127.1.2.3:1", "host"],
  ["http://127.0.0.1.:1", "host"],
  ["http://localhost:8080", "host"],
  ["http://LOCALHOST:8080/v1", "host"],
  ["http://localhost.:1", "host"],
  ["http://gpu.localhost:1", "host"],
  ["http://[::1]:8000", "host"],
  ["http://[0:0:0:0:0:0:0:1]:8000", "host"],
  ["http://[::]:1", "host"],
  ["http://0.0.0.0:1", "host"],
  ["http://[::ffff:127.0.0.1]:1", "host"],
  ["http://0x7f000001:1", "host"],
  ["http://2130706433:1", "host"],
  ["https://127.0.0.1:8443", "host"],
  // Other machines.
  ["http://10.0.3.7:8000", "network"],
  ["http://192.168.1.2", "network"],
  ["http://172.16.0.1", "network"],
  ["http://169.254.1.1", "network"],
  ["http://8.8.8.8", "network"],
  ["http://[fd00::1]:8000", "network"],
  ["http://[fe80::1]:8000", "network"],
  ["http://[::ffff:10.0.0.1]:1", "network"],
  ["https://llm.ml.corp.example/v1", "network"],
  ["http://localhost.corp.example", "network"],
  ["http://127.0.0.1.nip.io", "network"],
  ["http://my-box:11434", "network"],
  // Not an endpoint.
  ["ftp://127.0.0.1", null],
  ["file:///etc/passwd", null],
  ["not a url", null],
];

test("placement parity: the arbiter, the launcher, the helper and the dashboard agree on every row", () => {
  for (const [url, want] of TABLE) {
    assert.equal(arbiterRule(url), want, `arbiter: ${url}`);
    assert.equal(launcherRule(url), want, `launcher: ${url}`);
    assert.equal(helperRule(url), want, `helper: ${url}`);
    assert.equal(dashboardRule(url), want, `dashboard: ${url}`);
  }
});
