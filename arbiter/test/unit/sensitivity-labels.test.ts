/**
 * sensitivity-labels.test — the label reader and the mapping of confidentiality
 * plan 14 §14.1 (4a), sensitivity-labels.ts. Fixtures are OOXML archives built
 * at run time (test/helpers/office-zip.ts), never committed binaries.
 *
 * Pins:
 *   - LabelInfo.xml (the 2022 format), custom.xml (the older properties),
 *     both (LabelInfo wins), a disabled or removed label, another tenant, no
 *     label, stored and deflated entries, a UTF-16 part;
 *   - the reader keeps ids and tenants only: never a display name, never
 *     the document's text;
 *   - hostile archives: a Purview encrypted container (CFB) is counted, a
 *     zip bomb stops at 256 KiB, Zip64 (markers or the locator) and
 *     multi-disk are unreadable, an encrypted entry, a central directory
 *     over 1 MiB, records pointing outside the file, every truncation of a
 *     real fixture and random byte flips: never a throw, never past the
 *     byte budget;
 *   - the byte budget: over-budget is its own outcome;
 *   - the mapping: user and administrator merged stricter-wins, site
 *     matching, the strictest of a file's labels.
 *
 * No privilege; the protection axes are not read by this code.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  LABEL_READ_LIMITS, effectiveLabelMapping, isOfficeName, mapLabel, normalizeGuid, parseCustomPropsXml, parseLabelInfoXml,
  readOfficeLabels, strictestMapping, type OfficeByteReader,
} from "../../policy/sensitivity-labels.js";
import { bombLabelInfo, buildEncryptedContainer, buildOfficeFile, buildZip, customPropsXml, labelInfoXml } from "../helpers/office-zip.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4); none is read

const HC = "9fbde396-1a24-4c79-8edf-9254a0f35055";
const GEN = "1e4f7c2a-3b5d-4e6f-8a9b-0c1d2e3f4a5b";
const TENANT = "5b3c2d4e-1111-4222-8333-444455556666";
const OTHER_TENANT = "0a0b0c0d-1111-4222-8333-999988887777";
const BODY_CANARY = "CANARY-BODY-7f3e1d2c";
const NAME_CANARY = "CANARY-DISPLAY-NAME-5a6b";

/** A reader over a buffer that records how much was read. */
function reader(buf: Buffer): OfficeByteReader & { read_: number } {
  const r = {
    size: buf.length,
    read_: 0,
    async read(offset: number, length: number): Promise<Buffer> {
      r.read_ += length;
      return buf.subarray(offset, offset + length);
    },
  };
  return r;
}

test("the Office extensions, in any case; nothing else", () => {
  for (const n of ["a.docx", "b.DOCM", "c.dotx", "d.dotm", "e.xlsx", "f.xlsm", "g.xltx", "h.xltm", "i.pptx", "j.pptm", "k.potx", "l.potm"]) assert.ok(isOfficeName(n), n);
  for (const n of ["a.doc", "b.pdf", "docx", ".docx", "a.docx.txt", "a.", "a.zip", "x.odt"]) assert.ok(!isOfficeName(n), n);
});

test("GUIDs: braces and case optional; anything else is not one", () => {
  assert.equal(normalizeGuid(`{${HC.toUpperCase()}}`), HC);
  assert.equal(normalizeGuid(` ${HC} `), HC);
  for (const bad of ["", "9fbde396", `${HC}0`, `{${HC}`, "zzzzzzzz-1a24-4c79-8edf-9254a0f35055", 42, null]) assert.equal(normalizeGuid(bad), null);
});

test("LabelInfo.xml: id, tenant and enabled; a removed or disabled label is not enabled; names never kept", () => {
  const xml = labelInfoXml([{ id: HC, site: TENANT }, { id: GEN, site: TENANT, enabled: false }, { id: "2a2a2a2a-1111-4222-8333-444455556666", removed: true }]);
  assert.deepEqual(parseLabelInfoXml(xml), [
    { id: HC, site: TENANT, enabled: true },
    { id: GEN, site: TENANT, enabled: false },
    { id: "2a2a2a2a-1111-4222-8333-444455556666", site: null, enabled: false },
  ]);
  // Single quotes, another prefix, attributes in another order.
  assert.deepEqual(parseLabelInfoXml(`<x:label siteId='{${TENANT}}' enabled='true' id='${HC}'/>`), [{ id: HC, site: TENANT, enabled: true }]);
  assert.deepEqual(parseLabelInfoXml(`<labelList><label id="not-a-guid" enabled="1"/></labelList>`), []);
});

test("custom.xml: the MSIP_Label properties; the _Name property is never read", () => {
  const xml = customPropsXml([{ id: HC, site: TENANT, name: NAME_CANARY }, { id: GEN, enabled: false }]);
  const labels = parseCustomPropsXml(xml);
  assert.deepEqual(labels, [{ id: HC, site: TENANT, enabled: true }, { id: GEN, site: null, enabled: false }]);
  assert.doesNotMatch(JSON.stringify(labels), new RegExp(NAME_CANARY));
});

test("the reader: LabelInfo, custom.xml, both (LabelInfo wins), none; ids only, never text", async () => {
  const both = buildOfficeFile({ labelInfo: [{ id: HC, site: TENANT }], custom: [{ id: GEN, site: TENANT, name: NAME_CANARY }], body: BODY_CANARY });
  const r = await readOfficeLabels(reader(both));
  assert.equal(r.kind, "labels");
  assert.deepEqual(r.kind === "labels" && r.labels, [{ id: HC, site: TENANT, enabled: true }]);
  assert.doesNotMatch(JSON.stringify(r), new RegExp(`${BODY_CANARY}|${NAME_CANARY}`));

  const old = await readOfficeLabels(reader(buildOfficeFile({ custom: [{ id: GEN, site: TENANT, name: NAME_CANARY }] })));
  assert.deepEqual(old.kind === "labels" && old.labels, [{ id: GEN, site: TENANT, enabled: true }]);
  assert.doesNotMatch(JSON.stringify(old), new RegExp(NAME_CANARY));

  const none = await readOfficeLabels(reader(buildOfficeFile({ body: BODY_CANARY })));
  assert.deepEqual(none.kind === "labels" && none.labels, []);

  const stored = buildZip([{ name: "docMetadata/LabelInfo.xml", data: labelInfoXml([{ id: HC }]), method: 0 }]);
  const s = await readOfficeLabels(reader(stored));
  assert.deepEqual(s.kind === "labels" && s.labels, [{ id: HC, site: null, enabled: true }]);

  // An OPC part name is case-insensitive; an archive comment is fine.
  const cased = buildZip([{ name: "DocMetadata/LABELINFO.xml", data: labelInfoXml([{ id: HC }]) }], { comment: "made by a test" });
  const c = await readOfficeLabels(reader(cased));
  assert.deepEqual(c.kind === "labels" && c.labels, [{ id: HC, site: null, enabled: true }]);

  // A UTF-16 part with a byte order mark.
  const u16 = Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(labelInfoXml([{ id: HC, site: TENANT }]), "utf16le")]);
  const w = await readOfficeLabels(reader(buildZip([{ name: "docMetadata/LabelInfo.xml", data: u16 }])));
  assert.deepEqual(w.kind === "labels" && w.labels, [{ id: HC, site: TENANT, enabled: true }]);
});

test("the reader reads the head, the tail, the directory and one entry: never the whole file", async () => {
  const big = Buffer.alloc(2 * 1024 * 1024, 0x41);
  const f = buildZip([
    { name: "word/media/image1.bin", data: big, method: 0 },
    { name: "docMetadata/LabelInfo.xml", data: labelInfoXml([{ id: HC }]) },
  ]);
  const rd = reader(f);
  const r = await readOfficeLabels(rd);
  assert.equal(r.kind, "labels");
  assert.ok(rd.read_ < LABEL_READ_LIMITS.eocdTail + 4096, `read ${rd.read_} bytes of ${f.length}`);
  assert.equal(r.bytes, rd.read_);
});

test("hostile: an encrypted container is counted; a bomb stops at 256 KiB; Zip64 and multi-disk are unreadable", async () => {
  const enc = await readOfficeLabels(reader(buildEncryptedContainer()));
  assert.equal(enc.kind, "encrypted");

  const bomb = buildOfficeFile({ labelInfoRaw: bombLabelInfo(16) });
  assert.ok(bomb.length < LABEL_READ_LIMITS.entryInMax, "the bomb is small on disk");
  const before = process.memoryUsage().arrayBuffers;
  const b = await readOfficeLabels(reader(bomb));
  assert.deepEqual(b.kind === "unreadable" && b.reason, "a label entry that inflates past 256 KiB");
  assert.ok(process.memoryUsage().arrayBuffers - before < 8 * 1024 * 1024, "no 16 MiB buffer was built");

  const z64 = await readOfficeLabels(reader(buildOfficeFile({ labelInfo: [{ id: HC }], zip: { zip64Markers: true } })));
  assert.deepEqual(z64.kind === "unreadable" && z64.reason, "a Zip64 archive");
  const loc = await readOfficeLabels(reader(buildOfficeFile({ labelInfo: [{ id: HC }], zip: { zip64Locator: true } })));
  assert.deepEqual(loc.kind === "unreadable" && loc.reason, "a Zip64 archive");
  const md = await readOfficeLabels(reader(buildOfficeFile({ labelInfo: [{ id: HC }], zip: { multiDisk: true } })));
  assert.deepEqual(md.kind === "unreadable" && md.reason, "a multi-disk archive");

  const encEntry = await readOfficeLabels(reader(buildZip([{ name: "docMetadata/LabelInfo.xml", data: labelInfoXml([{ id: HC }]), flags: 1 }])));
  assert.deepEqual(encEntry.kind === "unreadable" && encEntry.reason, "an encrypted entry");

  const notZip = await readOfficeLabels(reader(Buffer.from("this is plain text pretending to be a document, long enough")));
  assert.deepEqual(notZip.kind === "unreadable" && notZip.reason, "not a zip archive");
  const tiny = await readOfficeLabels(reader(Buffer.from("PK")));
  assert.equal(tiny.kind, "unreadable");
});

test("hostile: a central directory over 1 MiB, a stored entry over the cap, records pointing outside", async () => {
  // Many entries push the directory past 1 MiB.
  const many = Array.from({ length: 12_000 }, (_, i) => ({ name: `x/${"n".repeat(60)}${i}.xml`, data: "", method: 0 as const }));
  const huge = await readOfficeLabels(reader(buildZip(many)));
  assert.deepEqual(huge.kind === "unreadable" && huge.reason, "a central directory over 1 MiB");

  const fat = await readOfficeLabels(reader(buildZip([{ name: "docMetadata/LabelInfo.xml", data: Buffer.alloc(300 * 1024, 0x20), method: 0 }])));
  assert.deepEqual(fat.kind === "unreadable" && fat.reason, "a label entry over its size limit");

  // The EOCD's directory offset pointed past itself.
  const f = buildOfficeFile({ labelInfo: [{ id: HC }] });
  const bad = Buffer.from(f);
  bad.writeUInt32LE(bad.length, bad.length - 22 + 16);
  const r = await readOfficeLabels(reader(bad));
  assert.equal(r.kind, "unreadable");
});

test("fuzz: every truncation and 500 random byte flips of a real fixture never throw and stay in budget", async () => {
  const f = buildOfficeFile({ labelInfo: [{ id: HC, site: TENANT }], custom: [{ id: GEN }], body: BODY_CANARY });
  for (let n = 0; n <= f.length; n++) {
    const r = await readOfficeLabels(reader(f.subarray(0, n)), { maxBytes: 4096 });
    assert.ok(["labels", "unreadable", "over-budget", "encrypted"].includes(r.kind), `truncated at ${n}`);
    assert.ok(r.bytes <= 4096);
    assert.doesNotMatch(JSON.stringify(r), new RegExp(BODY_CANARY));
  }
  let seed = 12345;
  const rnd = (m: number): number => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed % m; };
  for (let i = 0; i < 500; i++) {
    const g = Buffer.from(f);
    for (let k = 0; k < 4; k++) g[rnd(g.length)] = rnd(256);
    const r = await readOfficeLabels(reader(g), { maxBytes: 64 * 1024 });
    assert.ok(r.bytes <= 64 * 1024);
    if (r.kind === "labels") for (const l of r.labels) assert.match(l.id, /^[0-9a-f-]{36}$/);
  }
});

test("the byte budget: a read that would pass it stops as over-budget", async () => {
  const r = await readOfficeLabels(reader(buildOfficeFile({ labelInfo: [{ id: HC }] })), { maxBytes: 100 });
  assert.equal(r.kind, "over-budget");
  assert.ok(r.bytes <= 100);
});

test("the mapping: administrator and user merged stricter-wins; a site holds for its tenant only; the strictest label decides", () => {
  const admin = { sensitivityLabels: [{ entry: { id: `{${HC.toUpperCase()}}`, name: "Highly Confidential", level: "any-model" }, file: "/etc/mandu/policy.d/10-org.yaml" }] };
  const user = [
    { id: HC, name: "Mine", level: "public" }, // cannot lower the administrator's
    { id: GEN, site: TENANT, name: "General", level: "no-model" },
    { id: "bad", name: "x", level: "no-model" }, // left out
  ];
  const m = effectiveLabelMapping(user, admin);
  assert.deepEqual(m.map((e) => [e.id, e.site, e.name, e.level, e.adminFile ?? null]), [
    [HC, null, "Highly Confidential", "any-model", "/etc/mandu/policy.d/10-org.yaml"],
    [GEN, TENANT, "General", "no-model", null],
  ]);
  const raised = effectiveLabelMapping([{ id: HC, name: "Mine", level: "no-model" }], admin);
  assert.deepEqual(raised.map((e) => [e.name, e.level]), [["Mine", "no-model"]], "a user file may raise it");

  assert.equal(mapLabel({ id: GEN, site: TENANT }, m)?.level, "no-model");
  assert.equal(mapLabel({ id: GEN, site: OTHER_TENANT }, m), null, "another tenant's label with the same id is unmapped");
  assert.equal(mapLabel({ id: GEN, site: null }, m), null);
  assert.equal(mapLabel({ id: HC, site: OTHER_TENANT }, m)?.level, "any-model", "no site: every tenant");
  assert.equal(strictestMapping([{ id: HC, site: null }, { id: GEN, site: TENANT }], m)?.name, "General");
  assert.equal(strictestMapping([{ id: "3a3a3a3a-1111-4222-8333-444455556666", site: null }], m), null);
});
