/** The fixture-home oracle reads report fields independently of JSON order. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { doctorSecretsReport } from "../lib/doctor-secrets-report.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // the fixture oracle compares confidentiality coverage.

const fields = {
  roots: ["/tmp/home", "/tmp/workspace"],
  files: [{ path: '/tmp/home/key-{quoted}"', level: "no-model", bind: "bind" }],
  notCovered: { counts: { depth: 1 }, truncated: false },
  launch: { ok: true },
};

test("doctor report: platform-first output and roots-first output retain the fixture inventory and ledger", () => {
  for (const report of [{ platform: "linux", ...fields }, { ...fields, platform: "darwin" }]) {
    for (const indent of [undefined, 2]) {
      const out = JSON.stringify(report, null, indent);
      assert.deepEqual(doctorSecretsReport(out), report);
    }
  }
});

test("doctor report: warnings, unrelated JSON, nested braces and escaped quotes do not replace or truncate the report", () => {
  const report = { platform: "linux", ...fields };
  const out = `warning: probe failed {not JSON}\n${JSON.stringify({ diagnostic: "unrelated" }, null, 2)}\n` +
    `${JSON.stringify(report, null, 2)}\n(node:7) ExperimentalWarning: SQLite\n` +
    `${JSON.stringify({ launch: { ok: false }, diagnostic: "trailing" }, null, 2)}\n`;
  assert.deepEqual(doctorSecretsReport(out), report);
});

test("doctor report: absent, malformed and structurally incomplete reports fail the fixture oracle", () => {
  for (const out of ["no report", '{\n  "platform": "linux",', JSON.stringify({ launch: { ok: true } }),
    JSON.stringify({ ...fields, files: null }), JSON.stringify({ ...fields, notCovered: { counts: [], truncated: false } }),
    JSON.stringify({ ...fields, launch: { ok: "true" } })]) {
    assert.throws(() => doctorSecretsReport(out), /no dry-run JSON report in output/);
  }
});
