/**
 * consumer-packs — signed additions to the consumer table (comparisons.md
 * §3.3, to-do #10 reduced): a pack signed by a trusted key loads and adds its
 * consumers after the built-ins; an unsigned, wrongly signed, tampered or
 * malformed pack is refused whole; the signing script round-trips.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { defaultPackDirs, loadConsumerPacks } from "../../policy/consumer-packs.js";
import { consumerWireRelease, knownConsumers, setPackConsumers } from "../../policy/flow-taint.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets");

const SIGN = join(import.meta.dirname, "..", "..", "..", "scripts", "sign-pack.mjs");
after(() => setPackConsumers([]));

function rig(): { dir: string; packs: string; keys: string; key: string; write: (name: string, doc: unknown, sign?: boolean) => string } {
  const dir = mkdtempSync(join(tmpdir(), "mdu-packs-"));
  const packs = join(dir, "packs"), keys = join(dir, "keys"), priv = join(dir, "priv");
  for (const d of [packs, keys, priv]) mkdirSync(d);
  execFileSync("node", [SIGN, "--keygen", priv, "acme"]);
  execFileSync("cp", [join(priv, "acme.pem"), keys]);
  const write = (name: string, doc: unknown, signIt = true): string => {
    const f = join(packs, `${name}.json`);
    writeFileSync(f, JSON.stringify(doc, null, 2));
    if (signIt) execFileSync("node", [SIGN, f, join(priv, "acme.key")]);
    return f;
  };
  return { dir, packs, keys, key: join(priv, "acme.key"), write };
}

const GOOD = { format: "mandu-consumer-pack/1", name: "acme/cli", version: "2026.09.25",
  consumers: [{ basename: ".vault-token", apps: ["vault"] }, { pathSuffix: "/.config/stripe/config.toml", apps: ["stripe"], wire: { served: true, why: "Go; a bearer token" } }] };

test("a pack signed by a trusted key loads; its consumers follow the built-ins", () => {
  const r = rig();
  try {
    r.write("acme", GOOD);
    const { packs, errors } = loadConsumerPacks(r.packs, r.keys);
    assert.deepEqual(errors, []);
    assert.deepEqual(packs.map((p) => [p.name, p.version, p.keyId, p.consumers.length]), [["acme/cli", "2026.09.25", "acme", 2]]);
    setPackConsumers(packs.flatMap((p) => p.consumers));
    assert.deepEqual([...knownConsumers("/h/.vault-token")], ["vault"]);
    assert.equal(consumerWireRelease("/h/.config/stripe/config.toml")?.served, true);
    assert.deepEqual([...knownConsumers("/h/.pgpass")], ["psql", "pg_dump", "pg_restore"], "a built-in row is untouched");
  } finally { setPackConsumers([]); rmSync(r.dir, { recursive: true, force: true }); }
});

test("unsigned, wrongly signed, tampered or malformed packs are refused whole", () => {
  const r = rig();
  try {
    r.write("unsigned", { ...GOOD, name: "u" }, false);
    const tampered = r.write("tampered", { ...GOOD, name: "t" });
    writeFileSync(tampered, JSON.stringify({ ...GOOD, name: "t", consumers: [{ basename: ".bashrc", apps: ["curl"] }] }, null, 2));
    r.write("malformed", { ...GOOD, name: "m", consumers: [{ basename: "a/b", apps: ["x"] }] });
    r.write("wrongformat", { ...GOOD, format: "other/1" });
    const { packs, errors } = loadConsumerPacks(r.packs, r.keys);
    assert.deepEqual(packs, []);
    assert.equal(errors.length, 4, errors.join("\n"));
    assert.ok(errors.some((e) => /unsigned\.json: unsigned/.test(e)));
    assert.ok(errors.some((e) => /tampered\.json: signature does not verify/.test(e)));
    assert.ok(errors.some((e) => /malformed\.json: a consumer entry is malformed/.test(e)));
    // no trusted key at all: nothing loads
    rmSync(join(r.keys, "acme.pem"));
    r.write("acme", GOOD);
    assert.equal(loadConsumerPacks(r.packs, r.keys).packs.length, 0);
  } finally { rmSync(r.dir, { recursive: true, force: true }); }
});

test("the default pack and key dirs are the path table's packs and pack-keys; only MANDU_HOME moves them", () => {
  assert.deepEqual(defaultPackDirs({}, "/home/u"), { packDir: "/home/u/.mandu/packs", keysDir: "/home/u/.mandu/pack-keys" });
  // The one home (on-disk-layout.md §3): MANDU_HOME moves them, XDG_CONFIG_HOME no longer does.
  assert.deepEqual(defaultPackDirs({ MANDU_HOME: "/x" }, "/home/u"), { packDir: "/x/packs", keysDir: "/x/pack-keys" });
  assert.deepEqual(defaultPackDirs({ XDG_CONFIG_HOME: "/x" }, "/home/u"), defaultPackDirs({}, "/home/u"));
  // The retired MANDU_CONFIG moves nothing (on-disk-layout.md §5).
  assert.deepEqual(defaultPackDirs({ MANDU_CONFIG: "/tmp/c/config.toml" }, "/home/u"), defaultPackDirs({}, "/home/u"));
});
