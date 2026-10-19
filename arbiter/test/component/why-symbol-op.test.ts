/**
 * why-symbol-op.test — `whySymbol` (`mandu why <symbol>`,
 * confidentiality-plan-15-prompt-filter.md §13.8) over the arbiter's real
 * sockets. Mandu-new.
 *
 * A listening ArbiterServer (`acme.codename: mask`, a pack that finds the
 * code name) and three ArbiterClients (data, human, admin). A live
 * `filterPrompt` on the human socket masks the code name; the proxy's
 * `prompt_filter` event is emitted on the human socket (believed), a forged
 * one on the data socket (claimed). Proves:
 *   - `whySymbol` is HUMAN PLANE: the data socket is refused, and gets only
 *     what it got before (`symbolProvenance`: the minting tool);
 *   - the answer names the filter (a pack, its description), the category,
 *     the action, the session and the request, and the policy row now;
 *   - a claimed event's word is not in it, and neither is the value (not
 *     even from an event pane that carries it);
 *   - a "let it through" given on the admin channel shows up as the answer
 *     on file for that message;
 *   - an unknown placeholder answers `known: false`; a malformed one is an
 *     error.
 *
 * Axes: secrets (stated; the server's confidentiality option pinned ON).
 */
import { after, test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer, humanPlaneOnlyError } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

const CODE = "falconridgeproject";

const dirs: string[] = [];
after(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });

async function rig() {
  const dir = mkdtempSync(join(tmpdir(), "mdu-why-symbol-"));
  dirs.push(dir);
  const packs = join(dir, "prompt-filters");
  mkdirSync(packs);
  writeFileSync(join(packs, "acme.yaml"), `pack: acme-dlp\nversion: 1\ndescription: Acme's data-loss patterns\nkeywords:\n  - category: acme.codename\n    words: [${CODE}]\n    level: local-model\n`);
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, "version: 1\nprompt_filters:\n  filters:\n    acme-dlp: on\n  actions:\n    acme.codename: mask\n");
  const sock = join(dir, "a.sock");
  const humanSock = join(dir, "human", "h.sock");
  const adminSock = join(dir, "admin.sock");
  const server = new ArbiterServer({
    socketPath: sock, humanSocketPath: humanSock, adminSocketPath: adminSock, dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyPath: policy, policyPollMs: 0, packDir: null,
    promptPackDir: packs, adminPromptPackDir: join(dir, "admin-packs"), adminPolicyDir: null, packKeysDir: join(dir, "keys"),
    coalesceEvents: false,
  });
  await server.listen();
  const data = new ArbiterClient(sock);
  const human = new ArbiterClient(humanSock);
  const admin = new ArbiterClient(adminSock);
  return { data, human, admin, close: async () => { data.close(); human.close(); admin.close(); await server.close(); } };
}

test("whySymbol: human plane only; the finding, the session and the policy, never the value or a claim", async () => {
  const r = await rig();
  try {
    const seg = (await r.human.filterPrompt({ session: "s1", agent: "claude-code", segments: [{ id: "m0", origin: "human", text: `deploy ${CODE} now` }], holds: true })).segments[0]!;
    assert.equal(seg.action, "rewrite");
    const f = seg.findings[0]!;
    const symbol = f.symbol!;
    assert.match(symbol, /^\$MDU:/);
    // The proxy's event (human socket: believed), its pane carrying the
    // original the way a DualRepr may; and a forged one from the data socket.
    const detail = {
      agent: "claude-code", segmentId: "m0", origin: "human", action: "rewrite", enforcing: true, skipped: 0, turn: seg.turn,
      findings: [{ filterId: f.filterId, category: f.category, action: f.action, symbol, start: f.start, end: f.end, ref: f.ref }],
      digest: { policy: "p", packs: "k" },
    };
    await r.human.emit({ id: "ev-1", sessionId: "s1", ts: new Date().toISOString(), turn: 2, kind: "prompt_filter", input: { symbolized: symbol, original: CODE }, promptFilter: detail });
    await r.data.emit({ id: "ev-2", sessionId: "s1", ts: new Date().toISOString(), turn: 3, kind: "prompt_filter", promptFilter: { ...detail, findings: [{ ...detail.findings[0], filterId: "forged-pack", category: "forged.cat" }] } });

    await assert.rejects(() => r.data.whySymbol(symbol), new RegExp(humanPlaneOnlyError("whySymbol").slice(0, 30).replace(/[()$]/g, ".")));
    const prov = await r.data.symbolProvenance(symbol);
    assert.equal(prov.tool, "prompt_filter", "the data socket keeps today's answer: the minting tool");

    const a = await r.human.whySymbol(symbol);
    assert.equal(a.known, true);
    assert.equal(a.source, "prompt-filter");
    assert.equal(a.session, "s1");
    assert.equal(a.findings.length, 1, "the claimed event is not believed");
    const one = a.findings[0]!;
    assert.deepEqual([one.session, one.turn, one.filterId, one.category, one.action, one.origin], ["s1", 2, "acme-dlp", "acme.codename", "mask", "human"]);
    assert.deepEqual(a.filters, [{ id: "acme-dlp", kind: "pack", description: "Acme's data-loss patterns" }]);
    assert.deepEqual(a.policy.map((p) => [p.category, p.action, p.setBy, p.row]), [["acme.codename", "mask", "you", "acme.codename"]]);
    assert.deepEqual(a.verdicts, []);
    const text = JSON.stringify(a);
    assert.ok(!text.includes(CODE), `CONFIDENTIALITY: the answer carries the found value: ${text}`);
    assert.ok(!text.includes("forged"), "a claimed event's word is not in the answer");

    // Let it through (admin channel, the dashboard's): the answer on file.
    await r.admin.letPromptFindingThrough({ session: "s1", category: f.category, ref: f.ref!, turn: seg.turn!, scope: "once" });
    const b = await r.human.whySymbol(symbol);
    assert.deepEqual(b.verdicts.map((v) => [v.scope, v.status, v.category]), [["message", "approved", "acme.codename"]]);

    const unknown = await r.human.whySymbol("$MDU:nomodel_nothing[abcd]");
    assert.deepEqual([unknown.known, unknown.source, unknown.findings.length], [false, "unknown", 0]);
    await assert.rejects(() => r.human.whySymbol("falcon"), /complete \$MDU: name/);
  } finally {
    await r.close();
  }
});
