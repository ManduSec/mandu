/**
 * goose-tool-surface — Goose's advertised tools over the REAL arbiter IPC
 * (supported-agents.md §5.6, "The tool_surface unknown list").
 *
 * The 2026-10-08 live drills on goose 1.53.0 recorded a `tool_surface`
 * event naming nine tools UNKNOWN: analyze, read_image (gated by the gate
 * surface, left out of the spec on purpose), load, load_skill,
 * apps__list_apps, apps__delete_app, extensionmanager__list_resources,
 * extensionmanager__read_resource and extensionmanager__search_available_extensions
 * (no mapping at all: masked whole). This proves the fix end to end:
 *
 *   toolSurface  the captured 1.53.0 default surface (1.54.0 advertises the
 *                same) plus Mandu's mounts reads fully known for a `goose`
 *                session; a tool nobody looked at is still reported;
 *   callTaint    the §11.18 answer the proxy masks by, per tool: the mapped
 *                ones answer empty, the two MCP resource tools stay masked
 *                whole (by decision), a brand-new tool is masked whole.
 *
 * Run: npm run test:component   (or: npx tsx --test test/component/goose-tool-surface.test.ts)
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the built-in default: the §11.18 masking rule rides the confidentiality axis

const capture = JSON.parse(readFileSync(new URL("../fixtures/goose-tool-surface-2026-10-05.json", import.meta.url), "utf8")) as Record<string, Record<string, string[]>>;
const MOUNTS = [
  "mandu-inspect__inspect_symbol", "mandu-inspect__declassify_symbol",
  "mandu-policy__mandu_policy_read", "mandu-policy__mandu_policy_test", "mandu-policy__mandu_policy_propose",
];
/** The nine names the 2026-10-08 live tool_surface event listed. */
const LIVE_UNKNOWN = [
  "analyze", "apps__delete_app", "apps__list_apps", "extensionmanager__list_resources",
  "extensionmanager__read_resource", "extensionmanager__search_available_extensions",
  "load", "load_skill", "read_image",
];

async function withArbiter(fn: (c: ArbiterClient, server: ArbiterServer) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-goose-tsurf-"));
  const server = new ArbiterServer({
    socketPath: join(dir, "arbiter.sock"),
    dbPath: join(dir, "symbols.db"),
    eventDir: join(dir, "events"),
    log: () => {},
    confidentiality: true,
    integrity: false,
  });
  await server.listen();
  const client = new ArbiterClient(join(dir, "arbiter.sock"));
  try {
    await client.connect();
    await client.setSessionSpec({ sessionKey: "g", spec: "goose", requestedBy: "goose-tool-surface component test" });
    await fn(client, server);
  } finally {
    client.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

test("real IPC: goose's captured default surface and Mandu's mounts read fully known; the nine the live event named are among them; drift is still reported", async () => {
  await withArbiter(async (c) => {
    const surface = [...Object.keys(capture["1.53.0"]!), ...MOUNTS];
    for (const t of LIVE_UNKNOWN) assert.ok(surface.includes(t), `${t} is on the captured surface`);
    assert.deepEqual(await c.toolSurface(surface, "g"), [], "no advertised tool reads as unknown");
    assert.deepEqual(await c.toolSurface(Object.keys(capture["1.53.0 subagent"]!), "g"), [], "a delegate subagent's surface");
    // an opt-in builtin nobody mapped, and a tool a later release might add
    assert.deepEqual(await c.toolSurface(["shell", "memory__retrieve_memories", "brand_new_goose_tool"], "g"), ["memory__retrieve_memories", "brand_new_goose_tool"]);
    // the decision is Goose's: a Claude Code session does not inherit it
    assert.deepEqual(await c.toolSurface(["extensionmanager__read_resource"]), ["extensionmanager__read_resource"]);
  });
});

test("real IPC: the §11.18 answer per tool: mapped ones answer empty, the MCP resource tools and a new tool are masked whole", async () => {
  await withArbiter(async (c) => {
    let n = 0;
    const ask = (tool: string) => c.callTaint(`toolu_g_${n++}`, { session: "g", unmappedTool: tool });
    for (const t of ["apps__list_apps", "extensionmanager__search_available_extensions", "analyze", "read_image", "apps__delete_app"]) {
      const r = await ask(t);
      assert.equal(r.level, null, `${t}: mapped, not masked for being unmapped`);
      assert.notEqual(r.evidence, "unmapped", t);
    }
    for (const t of ["extensionmanager__list_resources", "extensionmanager__read_resource", "brand_new_goose_tool"]) {
      const r = await ask(t);
      assert.equal(r.level, "no-model", `${t}: masked whole`);
      assert.equal(r.evidence, "unmapped", t);
      assert.match(r.why ?? "", /mapped_tools:/, `${t}: the note says how to let it through`);
    }
  });
});

/** A launch record as the launcher sends it on the human plane (here the
 *  admin channel, attested like a walled human plane). */
function beginLaunch(server: ArbiterServer, sessionId: string, posture: string, pid = process.pid): string {
  const r = server.dispatch({ id: `bl-${sessionId}-${posture}`, op: "beginLaunch", pid, mode: "secrets", posture, writeProtect: true, humanPlaneWalled: true, sessionId } as never);
  assert.equal(r.ok, true, JSON.stringify(r));
  return (r.result as { token: string }).token;
}

test("real IPC: load / load_skill are mapped only in a session the file guard confines; gated, unknown, mixed or ended: masked whole (fail-closed)", async () => {
  await withArbiter(async (c, server) => {
    let n = 0;
    const ask = (session: string, tool: string) => c.callTaint(`toolu_gl_${n++}`, { session, unmappedTool: tool });
    const bind = async (k: string) => { await c.setSessionSpec({ sessionKey: k, spec: "goose", requestedBy: "goose-tool-surface component test" }); };
    const masked = async (session: string, why: string) => {
      for (const t of ["load", "load_skill"]) {
        const r = await ask(session, t);
        assert.equal(r.level, "no-model", `${t} in ${why}: masked whole`);
        assert.equal(r.evidence, "unmapped", `${t} in ${why}`);
        assert.match(r.why ?? "", /without Mandu's file guard/, `${t} in ${why}: the note says why`);
      }
    };
    const forwarded = async (session: string, why: string) => {
      for (const t of ["load", "load_skill"]) assert.equal((await ask(session, t)).level, null, `${t} in ${why}: forwarded`);
    };

    // no launch record (posture unknown), and no session at all
    await masked("g", "a session with no launch record");
    assert.equal((await c.callTaint("toolu_gl_nosession", { unmappedTool: "load_skill" })).level, "no-model", "no session");

    // a `confined` launch: the guard serves Goose's own opens the twin
    await bind("g-conf");
    const tok = beginLaunch(server, "g-conf", "confined");
    await forwarded("g-conf", "a confined session");

    // a `gated` launch (no guard), and `read-blocked`: masked
    await bind("g-gated");
    beginLaunch(server, "g-gated", "gated");
    await masked("g-gated", "a gated session");
    await bind("g-rb");
    beginLaunch(server, "g-rb", "read-blocked");
    await masked("g-rb", "a read-blocked session");

    // a session any launch claimed without the guard stays unguarded
    await bind("g-mixed");
    beginLaunch(server, "g-mixed", "confined");
    beginLaunch(server, "g-mixed", "gated");
    await masked("g-mixed", "a session with a gated launch");

    // the confined launch ends: the session is no longer known guarded
    assert.equal(server.dispatch({ id: "el", op: "endLaunch", token: tok } as never).ok, true);
    await masked("g-conf", "a session whose confined launch ended");

    // the other mapped tools never needed the guard
    assert.equal((await ask("g-gated", "apps__list_apps")).level, null);

    // an unwalled launch live anywhere: its programs reach the human plane
    // and could forge a record, so no session is believed guarded
    await bind("g-conf2");
    beginLaunch(server, "g-conf2", "confined");
    await forwarded("g-conf2", "a confined session");
    const r = server.dispatch({ id: "bl-open", op: "beginLaunch", pid: process.pid, mode: "secrets", posture: "gated", writeProtect: true, humanPlaneWalled: false, sessionId: "other" } as never);
    assert.equal(r.ok, true);
    await masked("g-conf2", "a session while the human plane is exposed");
    assert.equal(server.dispatch({ id: "el-open", op: "endLaunch", token: (r.result as { token: string }).token } as never).ok, true);
    await forwarded("g-conf2", "a confined session once the exposure ended");
  });
});
