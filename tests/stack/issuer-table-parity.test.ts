/**
 * issuer-table-parity — the Rules page's copy of the issuer bindings
 * (dashboard/src/view-model/issuer-words.ts, dashboard.md §4.25z) equals the
 * arbiter's (arbiter/policy/issuer-bindings.ts, confidentiality.md §2.3).
 *
 * The dashboard does not import the arbiter (the arbiter-client
 * convention), so it keeps a display copy of `ISSUERS` (id, name, hosts) and
 * its own reading of policy.yaml's `issuer_bindings`. A drift would make
 * Built-in protections list a company whose keys ask, miss one whose keys go
 * without asking, or say "on" where the arbiter compiled "off":
 *
 *   1. the two tables hold the same companies, in the same order, with the
 *      same names and hosts;
 *   2. `issuerState` answers what `compileIssuerBindings` compiles, over one
 *      table of inputs (absent, booleans, exceptions, every malformed shape).
 *
 * Axes explicit: secrets (the issuer bindings are a confidentiality rule; no
 * axis is read).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { compileIssuerBindings, ISSUERS } from "../../arbiter/policy/issuer-bindings.js";
import { ISSUER_TABLE, issuerState } from "../../dashboard/src/view-model/issuer-words.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets");

test("the dashboard's issuer table is the arbiter's: ids, names and hosts, in order", () => {
  assert.deepEqual(
    ISSUER_TABLE.map((i) => ({ id: i.id, name: i.name, hosts: [...i.hosts] })),
    ISSUERS.map((i) => ({ id: i.id, name: i.name, hosts: [...i.hosts] })),
    "copy ISSUERS' id, name and hosts into dashboard/src/view-model/issuer-words.ts",
  );
});

test("issuerState reads issuer_bindings as compileIssuerBindings compiles it", () => {
  const CASES: unknown[] = [
    undefined, null, true, false, {}, "yes", 0, 1, [], ["stripe"],
    ...ISSUERS.map((i) => ({ issuers_off: [i.id] })),
    { issuers_off: ["stripe", "github", "stripe"] },
    { issuers_off: [] }, { values_off: [] },
    { values_off: ["PROD_*", "STRIPE_LIVE_KEY", "PROD_*"] },
    { issuers_off: ["stripe"], values_off: ["X"] },
    { issuers_off: "stripe" }, { issuers_off: ["acme"] }, { issuers_off: [1] }, { issuers_off: null },
    { values_off: "PROD_*" }, { values_off: ["has space"] }, { values_off: ["tab\tname"] }, { values_off: [""] },
    { values_off: ["x".repeat(256)] }, { values_off: ["x".repeat(257)] }, { values_off: [null] },
    { other: true }, { issuers_off: [], typo: 1 }, { ISSUERS_OFF: ["stripe"] },
  ];
  for (const raw of CASES) {
    const a = compileIssuerBindings(raw);
    assert.deepEqual(issuerState(raw), { enabled: a.enabled, issuersOff: [...a.issuersOff], valuesOff: [...a.valuesOff] }, JSON.stringify(raw));
  }
});
