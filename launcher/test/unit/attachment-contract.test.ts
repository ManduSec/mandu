/**
 * attachment-contract — what `mandu serve`'s proxy pool and its readers agree
 * on (src/attachment-contract.ts; docs/design/agents/openclaw-plugin.md §3.2,
 * §8): the declared-attachments file, the pool's record, the port file's
 * text. Pure. The dashboard carries the same bytes (module-copies).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  attachmentsRoot,
  declareAttachment,
  parseDeclared,
  parsePortFile,
  poolMarkerFile,
  poolRecordPid,
  portFileText,
  renderDeclared,
  undeclareAttachment,
} from "../../src/attachment-contract.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets");

test("the declared file: a missing one is none; a broken one is none, with why", () => {
  assert.deepEqual(parseDeclared(null), { attachments: [], problems: [] });
  assert.deepEqual(parseDeclared("  "), { attachments: [], problems: [] });
  assert.match(parseDeclared("{").problems[0]!, /not JSON/);
  assert.match(parseDeclared("[]").problems[0]!, /not a JSON object/);
  assert.match(parseDeclared(JSON.stringify({ version: 3, attachments: [] })).problems[0]!, /version 3 is not 1 or 2/);
  assert.match(parseDeclared(JSON.stringify({ version: 1 })).problems[0]!, /no attachments list/);
});

test("the declared file: each entry exactly, the session derived from the agent, the first of two kept", () => {
  const r = parseDeclared(JSON.stringify({
    version: 1,
    attachments: [
      { kind: "openclaw-plugin", agent: "Main", session: "openclaw:someone-else", port: 41234 },
      { kind: "openclaw-plugin", agent: "ops team", port: 80 },
      { kind: "openclaw-plugin", agent: "main", port: 5000 },
      { kind: "other", agent: "x" },
      { kind: "openclaw-plugin" },
      7,
    ],
  }));
  assert.deepEqual(r.attachments, [
    { kind: "openclaw-plugin", agent: "main", session: "openclaw:main", port: 41234 },
    { kind: "openclaw-plugin", agent: "ops-team", session: "openclaw:ops-team", port: null },
  ]);
  assert.equal(r.problems.length, 5, r.problems.join("\n"));
  assert.ok(r.problems.some((p) => /port 80 is not 1024\.\.65535/.test(p)));
  assert.ok(r.problems.some((p) => /openclaw:main is declared twice/.test(p)));
  assert.ok(r.problems.some((p) => /unknown kind "other"/.test(p)));
});

test("declare / undeclare: idempotent, a port kept unless another is named, round-trips through the file", () => {
  const a = declareAttachment([], "main", 41000);
  assert.equal(a.changed, true);
  assert.deepEqual(a.entry, { kind: "openclaw-plugin", agent: "main", session: "openclaw:main", port: 41000 });
  const again = declareAttachment(a.list, "MAIN", null);
  assert.equal(again.changed, false, "the same session, no port named: unchanged");
  assert.equal(again.entry.port, 41000);
  const moved = declareAttachment(a.list, "main", 42000);
  assert.equal(moved.changed, true);
  assert.equal(moved.list.length, 1);
  assert.equal(moved.entry.port, 42000);
  const two = declareAttachment(moved.list, "ops", null).list;
  assert.deepEqual(parseDeclared(renderDeclared(two)), { attachments: two, problems: [] });
  const u = undeclareAttachment(two, "openclaw:main");
  assert.equal(u.removed?.session, "openclaw:main");
  assert.deepEqual(u.list.map((x) => x.session), ["openclaw:ops"]);
  assert.equal(undeclareAttachment(u.list, "openclaw:main").removed, null);
});

test("the pool record and the port file", () => {
  assert.equal(attachmentsRoot("/run/u/mandu/"), "/run/u/mandu/attachments");
  assert.equal(poolMarkerFile("/run/u/mandu"), "/run/u/mandu/attachments/pool.json");
  assert.equal(poolRecordPid(JSON.stringify({ pid: 4242, startedAt: "x" })), 4242);
  for (const bad of ["", "{", JSON.stringify({ pid: 1 }), JSON.stringify({ pid: "4242" }), JSON.stringify({ pid: 4.5 })]) assert.equal(poolRecordPid(bad), null, bad);
  assert.equal(portFileText(41234), "41234\n");
  assert.equal(parsePortFile(portFileText(41234)), 41234);
});
