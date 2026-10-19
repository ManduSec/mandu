/**
 * label-mapping-stale e2e — Settings › Sensitivity labels names the mapping
 * as the page read it, and a change to that same mapping landing in between
 * is never overwritten (policy-surface.md §8.4.6 "An item-level version";
 * dashboard.md §4.25s *A change names the label as it was read*). Mandu-new.
 *
 * Across the real components: a REAL ArbiterServer (secrets) with a
 * file-backed policy.yaml mapping two labels (Highly Confidential at No AI,
 * General at Any AI), a real DashboardServer over the production adapter
 * (`makeApprovalsArbiter`) serving the Settings page (its own index.html and
 * home.js in jsdom, every request through pageFetch):
 *
 *   S1  the page reads the list; on Highly Confidential the person picks
 *       Your own AI only; meanwhile ANOTHER mapping (General) changes:
 *       Save still applies (asked first) — another mapping's change does
 *       not refuse it, and that change is kept;
 *   S2  the person picks Not secret on Highly Confidential; meanwhile a
 *       change to that same mapping lands (raised back to No AI, as a
 *       second Settings window would): Save is refused, said on the row in
 *       the page's words, the level picked kept, the row read again;
 *   S3  THE INVARIANT: nothing was written — policy.yaml and the law keep
 *       the stricter, newer level, nothing waits in Approvals; the route's
 *       own answer to the same stale body is 409 `stale`;
 *   S4  the person saves again: applied against the mapping as it is now;
 *   S5  the oracle: no page or answer carries the registered key.
 *
 * Axes: secrets (stated).
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import type { PolicyFileConfig } from "../../arbiter/policy/load-policy.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { labelStaleWords } from "../../dashboard/src/view-model/sensitivity-labels.js";
import { ADMIN_COOKIE, ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

after(() => resetCurrentPolicyForTests("claude-code"));

const KEY = "sk_live_labelMappingStaleStackCanary000000001";
const HC = "9fbde396-1a24-4c79-8edf-9254a0f35055";
const GEN = "0e4c2b8a-3b1d-4f5e-9a6b-7c8d9e0f1a2b";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
const labelRow = (doc: Doc, id: string) => [...doc.querySelectorAll("#settings-labels .label-row")].find((r: Doc) => r.dataset.id === id);

test("Settings › Sensitivity labels over the real arbiter: a change read before another change to the same mapping is refused, nothing overwritten; another mapping's change does not refuse it", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-label-mapping-stale-"));
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, [
    "version: 1",
    "sensitivity_labels:",
    `  - { id: "${HC}", name: Highly Confidential, level: no-model }`,
    `  - { id: "${GEN}", name: General, level: any-model }`,
    "",
  ].join("\n"));
  const socketPath = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const humanPath = humanSockIn(tmp);
  const arbiter = new ArbiterServer({
    socketPath, adminSocketPath: adminSock, humanSocketPath: humanPath,
    dbPath: join(tmp, "mandu.db"), eventDir: join(tmp, "events"), policyPath, policyPollMs: 0,
    adminPolicyDir: null, promptPackDir: null, adminPromptPackDir: null,
    confidentiality: true, integrity: false, log: () => {},
  });
  await arbiter.listen();
  const data = new ArbiterClient(socketPath);
  await data.connect();
  const admin = new ArbiterClient(adminSock);
  await admin.connect();
  const wired = await makeApprovalsArbiter(socketPath, () => ({ socketPath: adminSock }));
  assert.ok(wired?.policyDoc, "the production adapter has the policy surface");
  const dashboard = new DashboardServer({
    source: new ArbiterEventSource({ socketPath, humanSocketPath: humanPath }),
    approvalsArbiter: wired.arbiter, policyDocArbiter: wired.policyDoc,
    log: () => {}, ...ADMIN_OPTS,
  });
  const base = `http://127.0.0.1:${await dashboard.listen(0)}`;
  const bodies: string[] = [];
  const call = async (method: string, path: string, body?: unknown) => {
    const r = await pageFetch(base + path, { method, headers: { ...CSRF_ADMIN, "Content-Type": "application/json" }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    const text = await r.text();
    bodies.push(text);
    return { status: r.status, body: JSON.parse(text) as Record<string, unknown> };
  };
  /** Another window's Settings: a change applied on the admin channel. */
  const elsewhere = async (edits: unknown[]) => {
    const r = await admin.policyPropose({ edits, requestedBy: "settings" });
    if (r.applied) return;
    assert.ok("proposalId" in r, JSON.stringify(r));
    const done = await admin.resolvePolicyProposal(r.proposalId, "approved", "human:settings");
    assert.ok(done.changeId, JSON.stringify(done));
  };
  const levelOf = async (id: string) => ((await admin.policyDocument()).inForce as PolicyFileConfig | null)?.sensitivity_labels?.find((l) => l.id === id)?.level;
  const pages: string[] = [];
  try {
    await data.registerEnvSecrets({ vars: [{ name: "STRIPE_API_KEY", value: KEY }] });
    const ready = (doc: Doc) => !!labelRow(doc, HC) && !!labelRow(doc, GEN);

    await servedProductPage(base, "/settings", ready, async (doc) => {
      doc.defaultView.confirm = () => true;
      const save = () => labelRow(doc, HC).querySelector(".label-save-btn").click();

      // S1: General changes meanwhile; the save on Highly Confidential applies.
      const first = labelRow(doc, HC);
      first.querySelector("select.label-level").value = "local-model";
      await elsewhere([{ op: "map-sensitivity-label", id: GEN, name: "General", level: "public" }]);
      save();
      await waitWhile(() => !/^Saved Highly Confidential\./.test(doc.getElementById("labels-notice").textContent ?? ""));
      assert.equal(await levelOf(HC), "local-model", "another mapping's change does not refuse the save");
      assert.equal(await levelOf(GEN), "public", "and that change is kept");

      // S2: the same mapping changes meanwhile; Save is refused. (The list
      // is read again after the save: the row is drawn anew.)
      await waitWhile(() => labelRow(doc, HC) === first || labelRow(doc, HC)?.querySelector("select.label-level")?.value !== "local-model");
      labelRow(doc, HC).querySelector("select.label-level").value = "public";
      await elsewhere([{ op: "map-sensitivity-label", id: HC, name: "Highly Confidential", level: "no-model" }]);
      const bytes = readFileSync(policyPath, "utf8");
      save();
      await waitWhile(() => !labelRow(doc, HC)?.querySelector(".ask-error"));
      const row = labelRow(doc, HC);
      assert.equal(row.querySelector(".ask-error").textContent, labelStaleWords("Highly Confidential", "map"), "said on the row, in the page's words");
      assert.equal(row.querySelector("select.label-level").value, "public", "the level picked is kept");

      // S3: the invariant — nothing was written; the stricter, newer level stands.
      assert.equal(readFileSync(policyPath, "utf8"), bytes, "policy.yaml is unchanged");
      assert.equal(await levelOf(HC), "no-model", "the stricter level stays in force");
      assert.deepEqual((await admin.policyProposals("pending")).proposals, [], "nothing waits in Approvals");
      const raw = await call("POST", "/api/policy/sensitivity-labels/change", { action: "unmap", id: HC, version: "0".repeat(32) });
      assert.equal(raw.status, 409, JSON.stringify(raw.body));
      assert.equal(raw.body["stale"], true);
      assert.equal(readFileSync(policyPath, "utf8"), bytes, "the route wrote nothing either");

      // S4: saved again, against the mapping as it is now.
      save();
      await waitWhile(() => !/^Saved Highly Confidential\./.test(doc.getElementById("labels-notice").textContent ?? "") || labelRow(doc, HC)?.querySelector(".ask-error") != null);
      assert.equal(await levelOf(HC), "public");
      pages.push(doc.body.textContent ?? "");
    }, { headers: { Cookie: ADMIN_COOKIE } });

    // S5: the oracle.
    assert.equal((await call("GET", "/api/policy/sensitivity-labels")).status, 200);
    for (const text of [...pages, ...bodies]) assert.ok(!text.includes(KEY), "no page or answer carries the registered key");
  } finally {
    await dashboard.close();
    wired.close();
    admin.close();
    data.close();
    await arbiter.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
