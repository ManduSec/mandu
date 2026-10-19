/**
 * placeholder-known — the `placeholderKnown` op over the wire (ipc/server.ts;
 * devtools-relay.md §3.3, arbiter-human-plane.md §3). Pinned: on the human
 * socket it answers whether a base names a row (a registered secret's field
 * rows, a made-up code), and refuses anything but one base (a field path,
 * free text, a value); the data socket refuses it as a human-plane op, so
 * the agent world gets no new lookup; it answers whatever the axes say (it
 * reads the table, as `resolve`). Mandu-new.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF; one test below runs both off, by name

async function arbiter(dir: string, confidentiality: boolean) {
  mkdirSync(join(dir, "human"), { mode: 0o700, recursive: true });
  const s = new ArbiterServer({
    socketPath: join(dir, "a.sock"), humanSocketPath: join(dir, "human", "h.sock"), dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"),
    log: () => {}, adminPolicyDir: null, packDir: null, confidentiality, integrity: false,
  });
  await s.listen();
  const data = new ArbiterClient(join(dir, "a.sock")); await data.connect();
  const human = new ArbiterClient(join(dir, "human", "h.sock")); await human.connect();
  return { data, human, close: async () => { data.close(); human.close(); await s.close(); } };
}

test("placeholderKnown: on the human socket, a registered secret's base is known (through its field rows) and a made-up code is not; anything but a base is refused; the data socket refuses the op", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-ph-known-c-"));
  const a = await arbiter(dir, true);
  try {
    const env = join(dir, ".env");
    writeFileSync(env, "CARD_NUMBER=4242424242424242\n");
    const reg = await a.human.registerSecret({ path: env, sessionKey: "s1" });
    const base = String(reg.symbol);
    assert.match(base, /^\$MDU:[a-zA-Z_][a-zA-Z0-9_]*\[[0-9a-f]{4,8}\]$/, JSON.stringify(reg));
    assert.deepEqual(await a.human.placeholderKnown({ base }), { known: true });
    const code = /\[([0-9a-f]+)\]/.exec(base)![1]!;
    const made = base.replace(`[${code}]`, `[${code === "8c4f" ? "8c4e" : "8c4f"}]`);
    assert.deepEqual(await a.human.placeholderKnown({ base: made }), { known: false }, "a hex code no row has");
    assert.deepEqual(await a.human.placeholderKnown({ base: "$MDU:web_fetch[8c4f]" }), { known: false }, "the live demo's made-up one");
    for (const bad of [`${base}.CARD_NUMBER`, "$MDU:web_fetch[e213b2c2-8419]", "4242424242424242", "", "$MDU:k[012]"]) {
      await assert.rejects(a.human.placeholderKnown({ base: bad }), /placeholderKnown: base must be one placeholder's base/, bad);
    }
    await assert.rejects(a.human.placeholderKnown({ base: 42 as unknown as string }), /placeholderKnown/);
    await assert.rejects(a.data.placeholderKnown({ base }), /human-plane: 'placeholderKnown' is the DevTools relay's lookup/, "never on the data socket");
  } finally {
    await a.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("placeholderKnown answers with both protection axes off (it reads the table, as resolve does)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-ph-known-off-"));
  const a = await arbiter(dir, false);
  try {
    assert.deepEqual(await a.human.placeholderKnown({ base: "$MDU:web_fetch[8c4f]" }), { known: false });
  } finally {
    await a.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
