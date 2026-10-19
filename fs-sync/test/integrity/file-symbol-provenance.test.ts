/** Real arbiter IPC + real git: opaque nested filenames survive human edits. */
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { ArbiterClientAdapter, extractSymbols, type SymbolizeArgs } from "../../src/arbiter-client.js";
import { ViewSync } from "../../src/view-sync.js";
import { makeTempRepo, gitIn } from "../helpers/temp-repo.js";
import { stateAxes } from "../axes.js";

stateAxes("injection"); // this suite states its axes (protection-modes.md §4)

// Runtime imports keep fs-sync's standalone compilation boundary narrow.
const serverModule = new URL("../../../arbiter/ipc/server.ts", import.meta.url).href;
const clientModule = new URL("../../../arbiter/ipc/client.ts", import.meta.url).href;

test("real arbiter preserves nested file provenance and opaque untouched bytes through human edits", async () => {
  const [{ ArbiterServer }, { ArbiterClient }] = await Promise.all([import(serverModule), import(clientModule)]);
  const dir = mkdtempSync(join(tmpdir(), "mdu-fs-field-"));
  const repo = makeTempRepo({ "seed.txt": "fixture seed\n" });
  const rel = "src/남쪽 stock.json";
  const original = "untrusted head marker\nuntrusted middle marker\nuntrusted tail marker\n";
  const humanPath = join(repo.workspacePath, rel);
  mkdirSync(dirname(humanPath), { recursive: true });
  writeFileSync(humanPath, original);
  gitIn(repo.workspacePath, ["add", "--", rel]);
  gitIn(repo.workspacePath, ["commit", "-qm", "seed nested file"]);
  // fs-sync's production wiring is a client of the HUMAN-plane socket
  // (docs/design/architecture/arbiter-human-plane.md): resolve/desymbolize live only there.
  const server = new ArbiterServer({ socketPath: join(dir, "a.sock"), humanSocketPath: join(dir, "human", "h.sock"), dbPath: join(dir, "s.db"), eventDir: join(dir, "events"), log: () => {} });
  const client = new ArbiterClient(join(dir, "human", "h.sock"));
  const minted: SymbolizeArgs[] = [];
  class RecordingAdapter extends ArbiterClientAdapter {
    override async symbolize(args: SymbolizeArgs): Promise<string> {
      minted.push(args);
      return super.symbolize(args);
    }
  }
  try {
    await server.listen();
    await client.connect();
    const adapter = new RecordingAdapter(client);
    const dv = new ViewSync({ workspacePath: repo.workspacePath, stateBase: repo.stateBase, arbiter: adapter });
    await dv.initialize();
    const agentPath = join(dv.agentViewPath, rel);
    const seeded = (await dv.readForAgent(rel)).toString("utf8");
    assert.equal(seeded.includes("untrusted"), false, "Unicode filename is symbolized at initial ingress");
    const [parent] = extractSymbols(seeded);
    assert.ok(parent);
    assert.equal((await client.symbolProvenance(parent)).field, rel);
    assert.equal(await client.resolve(parent), original);
    assert.deepEqual(dv.agentViewLeaks(), []);

    writeFileSync(humanPath, original.replace("untrusted middle marker", "HUMAN REVIEWED"));
    assert.equal((await dv.reconcileHumanEdits())?.committed, true);
    const agentAfter = readFileSync(agentPath, "utf8");
    assert.ok(agentAfter.includes("HUMAN REVIEWED"));
    assert.equal(agentAfter.includes("untrusted"), false);
    const children = extractSymbols(agentAfter);
    assert.equal(children.length, 2);
    assert.deepEqual(await Promise.all(children.map(async (symbol) => (await client.symbolProvenance(symbol)).field)), [
      `${rel}.__mdu_split[0]`, `${rel}.__mdu_split[1]`,
    ]);
    assert.deepEqual(minted.filter((args) => args.derivedFrom).map((args) => [args.derivedFrom, args.lineRange]), [[parent, "0:1"], [parent, "2:4"]]);
    assert.deepEqual(await Promise.all(children.map((symbol) => client.resolve(symbol))), ["untrusted head marker", "untrusted tail marker\n"]);
    assert.equal(readFileSync(humanPath, "utf8"), original.replace("untrusted middle marker", "HUMAN REVIEWED"));

    // A lookup outage must leave the existing opaque AgentView file untouched.
    const beforeFailure = readFileSync(agentPath, "utf8");
    writeFileSync(humanPath, readFileSync(humanPath, "utf8").replace("untrusted tail marker", "SECOND HUMAN EDIT"));
    adapter.symbolProvenance = async () => { throw new Error("provenance unavailable"); };
    await assert.rejects(dv.reconcileHumanEdits(), /provenance unavailable/);
    assert.equal(readFileSync(agentPath, "utf8"), beforeFailure);
    assert.equal(readFileSync(agentPath, "utf8").includes("untrusted"), false);
  } finally {
    client.close();
    await server.close();
    repo.cleanup();
    rmSync(dir, { recursive: true, force: true });
  }
});
