/**
 * model-update-stale e2e — Settings › Models' update names the entry as the
 * page read it, and a change to that same entry landing in between is never
 * overwritten (policy-surface.md §8.4.6 "An item-level version";
 * dashboard.md §4.25l *A save names the model as it was read*). Mandu-new.
 *
 * Across the real components: a REAL ArbiterServer (secrets) with a
 * file-backed policy.yaml declaring two models (lab, outside; mine, your
 * own at a loopback address), a real DashboardServer over the production
 * adapter (`makeApprovalsArbiter`) serving the Settings page (its own
 * index.html and home.js in jsdom, every request through pageFetch):
 *
 *   S1  the page reads the list; Edit on lab; the person types a model;
 *   S2  meanwhile an unrelated entry (mine) changes: Save still applies
 *       (asked first) — a change to another entry does not refuse it;
 *   S3  Edit on lab again; meanwhile ANOTHER change to lab lands (a new
 *       address, applied on the admin channel as a second Settings window
 *       would); Save is refused: the form says so in the page's words,
 *       keeps what was typed, the row shows lab as it is now;
 *   S4  THE INVARIANT: nothing was written — policy.yaml and the law keep
 *       the newer address, nothing is waiting in Approvals; the route's
 *       own answer to the same stale body is 409 `stale`;
 *   S5  the person compares, keeps the newer address, saves again: applied
 *       against lab as it is now, the typed model and the newer address;
 *   S6  the oracle: no page or answer carries the registered key.
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
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { DashboardServer } from "../../dashboard/src/server.js";
import { ArbiterEventSource } from "../../dashboard/src/event-source.js";
import { ADMIN_COOKIE, ADMIN_OPTS, CSRF_ADMIN } from "../../dashboard/test/unit/admin-session.js";
import { servedProductPage } from "../../dashboard/test/unit/ui/served-page.js";
import { waitWhile } from "../../dashboard/test/unit/page-wait.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";
import { pageFetch } from "../../dashboard/test/unit/page-fetch.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF

after(() => resetCurrentPolicyForTests("claude-code"));

const KEY = "sk_" + "live_modelUpdateStaleStackCanary0000000001";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Doc = any;
const modelRow = (doc: Doc, name: string) => [...doc.querySelectorAll("#settings-models .model-row")].find((r: Doc) => r.dataset.name === name);
const byId = (doc: Doc, id: string) => doc.getElementById(id);
const submit = (doc: Doc) => byId(doc, "model-form").dispatchEvent(new doc.defaultView.Event("submit", { cancelable: true }));

test("Settings over the real arbiter: an update read before another change to the same model is refused, nothing overwritten; an unrelated change does not refuse it", { timeout: 180_000 }, async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-model-update-stale-"));
  const policyPath = join(tmp, "policy.yaml");
  writeFileSync(policyPath, [
    "version: 1",
    "models:",
    "  - { name: lab, url: 'https://lab.example/v1', wire: openai-chat, model: mistral }",
    "  - { name: mine, url: 'http://127.0.0.1:11434', wire: openai-chat, model: llama3.2, local: true }",
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
  const post = async (path: string, body: unknown) => {
    const text = await (await pageFetch(base + path, { method: "POST", headers: { ...CSRF_ADMIN, "Content-Type": "application/json" }, body: JSON.stringify(body) })).text();
    bodies.push(text);
    return JSON.parse(text) as Record<string, unknown>;
  };
  /** Another window's Settings: the same change, applied on the admin channel. */
  const elsewhere = async (edits: unknown[]) => {
    const r = await admin.policyPropose({ edits, requestedBy: "settings" });
    assert.ok(!r.applied && "proposalId" in r, JSON.stringify(r));
    const done = await admin.resolvePolicyProposal(r.proposalId, "approved", "human:settings");
    assert.ok(done.changeId, JSON.stringify(done));
  };
  const endpoint = async (name: string) => (await data.modelEndpoints()).find((m: { name: string }) => m.name === name);
  const pages: string[] = [];
  try {
    await data.registerEnvSecrets({ vars: [{ name: "STRIPE_API_KEY", value: KEY }] });
    const ready = (doc: Doc) => doc.querySelectorAll("#settings-models .model-row").length === 2;

    await servedProductPage(base, "/settings", ready, async (doc) => {
      doc.defaultView.confirm = () => true;

      // S1 + S2: the form read lab; mine changes meanwhile; Save applies.
      modelRow(doc, "lab").querySelector(".model-edit-btn").click();
      byId(doc, "model-model").value = "mistral-large";
      await elsewhere([{ op: "update-model", name: "mine", url: "http://127.0.0.1:11434", wire: "openai-chat", model: "llama3.3", local: true }]);
      submit(doc);
      await waitWhile(() => !/^Saved lab\./.test(byId(doc, "models-notice").textContent ?? ""));
      assert.match(byId(doc, "models-notice").textContent, /^Saved lab\./, "a change to another model does not refuse the save");
      assert.equal((await endpoint("lab"))?.model, "mistral-large");
      assert.equal((await endpoint("mine"))?.model, "llama3.3", "and the other change is kept");

      // S3: the form read lab; another change to lab lands; Save is refused.
      await waitWhile(() => !modelRow(doc, "lab") || /mistral,/.test(modelRow(doc, "lab").querySelector(".sub").textContent));
      modelRow(doc, "lab").querySelector(".model-edit-btn").click();
      byId(doc, "model-model").value = "mistral-xl";
      await elsewhere([{ op: "update-model", name: "lab", url: "https://lab2.example/v1", wire: "openai-chat", model: "mistral-large" }]);
      const bytes = readFileSync(policyPath, "utf8");
      submit(doc);
      await waitWhile(() => (byId(doc, "model-error").textContent ?? "") === "");
      assert.equal(byId(doc, "model-error").textContent,
        "lab was changed somewhere else while you were editing it, so nothing was saved. What you typed is still in the form: compare it with lab as it is now, then save again.");
      assert.equal(byId(doc, "model-form").hidden, false, "the form stays open");
      assert.equal(byId(doc, "model-model").value, "mistral-xl", "what was typed is kept");
      assert.equal(byId(doc, "model-url").value, "https://lab.example/v1", "and the form is not refilled over it");
      await waitWhile(() => !/lab2\.example/.test(modelRow(doc, "lab")?.querySelector(".sub")?.textContent ?? ""));
      assert.match(modelRow(doc, "lab").querySelector(".sub").textContent, /^https:\/\/lab2\.example\/v1/, "the row shows lab as it is now");

      // S4: the invariant — nothing was written; the newer change stands.
      assert.equal(readFileSync(policyPath, "utf8"), bytes, "policy.yaml is unchanged");
      assert.deepEqual(await endpoint("lab"), { name: "lab", url: "https://lab2.example/v1", wire: "openai-chat", model: "mistral-large", local: false });
      assert.deepEqual((await admin.policyProposals("pending")).proposals, [], "nothing waits in Approvals");
      const raw = await post("/api/policy/models/change", {
        action: "update", name: "lab", version: "0".repeat(32),
        model: { name: "lab", url: "https://lab.example/v1", wire: "openai-chat", model: "mistral-xl", local: false },
      });
      assert.equal(raw.stale, true, JSON.stringify(raw));
      assert.equal(readFileSync(policyPath, "utf8"), bytes, "the route wrote nothing either");

      // S5: compared, the newer address kept, saved again.
      byId(doc, "model-url").value = "https://lab2.example/v1";
      submit(doc);
      await waitWhile(() => !/^Saved lab\./.test(byId(doc, "models-notice").textContent ?? "") || !byId(doc, "model-form").hidden);
      assert.equal(byId(doc, "model-form").hidden, true);
      assert.deepEqual(await endpoint("lab"), { name: "lab", url: "https://lab2.example/v1", wire: "openai-chat", model: "mistral-xl", local: false });
      pages.push(doc.body.textContent ?? "");
    }, { headers: { Cookie: ADMIN_COOKIE } });

    // S6: the oracle.
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
