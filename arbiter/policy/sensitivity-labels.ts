/**
 * sensitivity-labels — S4 of confidentiality plan 14 (§14.1, step 4a): read
 * the Microsoft Purview / MIP sensitivity labels Office already wrote into a
 * file, and map them to levels through the person's (or the organization's)
 * `sensitivity_labels:` section. This module READS and MAPS; it enforces
 * nothing, writes nothing and opens no file itself (the workspace walk,
 * secret-workspace-scan.ts, hands it a bounded byte reader over a file it
 * opened safely).
 *
 * WHAT OFFICE WRITES. An OOXML file (`.docx`, `.xlsx`, `.pptx` and their
 * macro and template forms) is a zip. Its label is in
 *   - `docMetadata/LabelInfo.xml` (the format since 2022):
 *       <clbl:label id="{guid}" enabled="1" siteId="{tenant}" removed="0" …/>
 *   - else the older custom properties, `docProps/custom.xml`:
 *       <property … name="MSIP_Label_<guid>_Enabled"><vt:lpwstr>true</vt:lpwstr></property>
 *       <property … name="MSIP_Label_<guid>_SiteId"><vt:lpwstr>{tenant}</vt:lpwstr></property>
 * A file Purview encrypted is an OLE compound file (CFB) holding an
 * `EncryptedPackage`: it is not read (a reader would get ciphertext), only
 * counted. Any CFB file with an OOXML extension is counted so: the magic is
 * all that is looked at.
 *
 * THE BOUNDED READ (the file may be the agent's: hostile input):
 *   - the end-of-central-directory record is looked for in the last
 *     64 KiB + 22 bytes only;
 *   - a Zip64 archive (the markers, or the Zip64 locator) or a multi-disk one
 *     is unreadable, counted, not guessed at;
 *   - the central directory is at most 1 MiB;
 *   - only the two entries above are ever read, each at most 320 KiB
 *     compressed, and inflated with zlib's `maxOutputLength` of 256 KiB, so a
 *     zip bomb stops there (the entry is unreadable);
 *   - an entry must lie before the central directory, its local header must
 *     carry the local signature, and an encrypted entry is unreadable;
 *   - every read goes through the caller's reader and counts against the
 *     caller's byte budget (`maxBytes`);
 *   - the XML is read by a few anchored regular expressions over at most
 *     256 KiB of text, never by a general parser (no entity expansion, no
 *     external reference, no recursion).
 *
 * WHAT IS KEPT. A label's GUID and its tenant's GUID, normalized (lowercase,
 * no braces), and whether it is enabled. Never the label's display name as
 * the file spells it, nor any other text of the file: that is the file's
 * content (§14.1 "A finding").
 *
 * THE MAPPING (§14.1 "The mapping is the human's, in the law"): the user's
 * `sensitivity_labels:` entries and the administrator's layer's, merged by
 * (id, site) with the stricter level winning (`effectiveLabelMapping`), so a
 * user file cannot lower what the organization mapped. A label matches an
 * entry with its id and either no `site` or its own tenant; among several
 * matches the strictest level wins (`mapLabel`).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 */
import { inflateRawSync } from "node:zlib";

// ── The files ────────────────────────────────────────────────────────────────

/** The OOXML extensions whose labels S4 reads (Word, Excel, PowerPoint: the
 *  documents, their macro-enabled forms and their templates). */
export const OFFICE_EXTENSIONS: ReadonlySet<string> = new Set([
  "docx", "docm", "dotx", "dotm",
  "xlsx", "xlsm", "xltx", "xltm",
  "pptx", "pptm", "potx", "potm",
]);

/** Is this file NAME an Office document S4 reads? Pure. */
export function isOfficeName(name: string): boolean {
  const dot = name.lastIndexOf(".");
  if (dot <= 0 || dot === name.length - 1) return false;
  return OFFICE_EXTENSIONS.has(name.slice(dot + 1).toLowerCase());
}

/** The reader's version: part of the cache key, so a reader that changes
 *  what it keeps reads every file again. */
export const SENSITIVITY_LABEL_READER_VERSION = "mip-labels-1";

/** The bounded read's limits (§14.1 "How"). */
export const LABEL_READ_LIMITS = {
  /** The EOCD is searched for in this many bytes at the end. */
  eocdTail: 64 * 1024 + 22,
  /** The central directory, at most. */
  centralDirMax: 1024 * 1024,
  /** One entry's compressed bytes, at most. */
  entryInMax: 320 * 1024,
  /** One entry inflated, at most (`maxOutputLength`). */
  entryOutMax: 256 * 1024,
  /** Labels kept per file, at most. */
  labelsPerFile: 64,
} as const;

/** The scan's own budgets for the label read (§14.1 "Budgets"). */
export interface LabelScanLimits {
  /** Office files examined per scan. */
  maxFiles: number;
  /** Bytes read per scan, across every Office file. */
  totalMaxBytes: number;
}

export const DEFAULT_LABEL_LIMITS: LabelScanLimits = { maxFiles: 2_000, totalMaxBytes: 32 * 1024 * 1024 };

/** The entries read, as OPC part names (compared without regard to case). */
export const LABEL_INFO_PART = "docmetadata/labelinfo.xml";
export const CUSTOM_PROPS_PART = "docprops/custom.xml";

// ── The read ─────────────────────────────────────────────────────────────────

/** A byte range reader over one opened file. */
export interface OfficeByteReader {
  /** The file's size (from `fstat` on the descriptor). */
  readonly size: number;
  /** Read `length` bytes at `offset` (fewer only at the end of the file). */
  read(offset: number, length: number): Promise<Buffer>;
}

/** One label as the file states it. */
export interface OfficeLabel {
  /** The label's GUID, lowercase, no braces. */
  id: string;
  /** The tenant's GUID, lowercase, no braces; null when the file names none. */
  site: string | null;
  enabled: boolean;
}

export type OfficeLabelRead =
  | { kind: "labels"; labels: OfficeLabel[]; bytes: number }
  /** An OLE compound file: Purview's encrypted container. Not read. */
  | { kind: "encrypted"; bytes: number }
  | { kind: "unreadable"; reason: string; bytes: number }
  /** The caller's byte budget ran out first: not cached, counted. */
  | { kind: "over-budget"; bytes: number };

const SIG_LOCAL = 0x04034b50;
const SIG_CENTRAL = 0x02014b50;
const SIG_EOCD = 0x06054b50;
const SIG_ZIP64_LOCATOR = 0x07064b50;
const CFB_MAGIC = Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);

// ── The bounded zip core (shared with office-text.ts, the T2 text read) ──────

/** The caller's byte budget ran out (the read is `over-budget`). */
export class ZipBudgetError extends Error {}
/** The archive is not one we read (the read is `unreadable`, this reason). */
export class ZipBadError extends Error {}

/** A byte reader that counts every byte against `maxBytes` and refuses a
 *  range outside the file. */
export interface BoundedRead {
  readonly size: number;
  read(offset: number, length: number): Promise<Buffer>;
  /** Bytes read so far. */
  bytes(): number;
}

export function boundedRead(reader: OfficeByteReader, maxBytes: number = Number.POSITIVE_INFINITY): BoundedRead {
  let bytes = 0;
  const size = reader.size;
  return {
    size,
    bytes: () => bytes,
    read: async (offset: number, length: number): Promise<Buffer> => {
      if (length <= 0) return Buffer.alloc(0);
      if (offset < 0 || offset + length > size) throw new ZipBadError("a record points outside the file");
      if (bytes + length > maxBytes) throw new ZipBudgetError();
      bytes += length;
      const b = await reader.read(offset, length);
      if (b.length !== length) throw new ZipBadError("the file is shorter than it says");
      return b;
    },
  };
}

/** One central-directory entry the caller selected. */
export interface ZipEntryRef {
  flags: number;
  method: number;
  comp: number;
  uncomp: number;
  local: number;
}

/** An archive whose central directory was read: the entries selected (by
 *  lowercase OPC part name, the first of a duplicated name) and where the
 *  central directory starts (every entry must lie before it). */
export interface OpenZip {
  cdOffset: number;
  entries: Map<string, ZipEntryRef>;
}

/**
 * Open an OOXML archive through `r` (§14.9 "The read, as built"): the CFB
 * magic (`encrypted`), the local signature, the EOCD in the last 64 KiB + 22
 * bytes, no Zip64 and no multi-disk, a central directory of at most 1 MiB
 * inside the archive; keeps the entries `select` accepts (lowercase names),
 * a Zip64 marker in one of them refused. Throws ZipBadError (unreadable,
 * with a reason) or ZipBudgetError.
 */
export async function openOfficeZip(r: BoundedRead, select: (lowerName: string) => boolean): Promise<OpenZip | "encrypted"> {
  const size = r.size;
  if (!Number.isSafeInteger(size) || size < 22) {
    if (size >= 8) {
      const head = await r.read(0, 8);
      if (head.equals(CFB_MAGIC)) return "encrypted";
    }
    throw new ZipBadError("too small to be a zip archive");
  }
  const head = await r.read(0, 8);
  if (head.equals(CFB_MAGIC)) return "encrypted";
  if (head.readUInt32LE(0) !== SIG_LOCAL) throw new ZipBadError("not a zip archive");

  // The end-of-central-directory record, in the last 64 KiB + 22 bytes.
  const tailLen = Math.min(size, LABEL_READ_LIMITS.eocdTail);
  const tailAt = size - tailLen;
  const tail = await r.read(tailAt, tailLen);
  let e = -1;
  for (let i = tail.length - 22; i >= 0; i--) {
    if (tail.readUInt32LE(i) !== SIG_EOCD) continue;
    if (i + 22 + tail.readUInt16LE(i + 20) === tail.length) { e = i; break; }
    if (e < 0) e = i; // a record whose comment length does not reach the end: kept as a fallback
  }
  if (e < 0) throw new ZipBadError("no end of central directory");
  const disk = tail.readUInt16LE(e + 4);
  const cdDisk = tail.readUInt16LE(e + 6);
  const onDisk = tail.readUInt16LE(e + 8);
  const total = tail.readUInt16LE(e + 10);
  const cdSize = tail.readUInt32LE(e + 12);
  const cdOffset = tail.readUInt32LE(e + 16);
  if (total === 0xffff || onDisk === 0xffff || cdSize === 0xffffffff || cdOffset === 0xffffffff) throw new ZipBadError("a Zip64 archive");
  if (e >= 20 && tail.readUInt32LE(e - 20) === SIG_ZIP64_LOCATOR) throw new ZipBadError("a Zip64 archive");
  if (disk !== 0 || cdDisk !== 0 || onDisk !== total) throw new ZipBadError("a multi-disk archive");
  if (cdSize > LABEL_READ_LIMITS.centralDirMax) throw new ZipBadError("a central directory over 1 MiB");
  const eocdAt = tailAt + e;
  if (cdOffset + cdSize > eocdAt) throw new ZipBadError("a central directory outside the archive");

  const cd = await r.read(cdOffset, cdSize);
  const entries = new Map<string, ZipEntryRef>();
  let p = 0;
  for (let n = 0; n < total; n++) {
    if (p + 46 > cd.length || cd.readUInt32LE(p) !== SIG_CENTRAL) throw new ZipBadError("a malformed central directory");
    const nameLen = cd.readUInt16LE(p + 28);
    const extraLen = cd.readUInt16LE(p + 30);
    const commentLen = cd.readUInt16LE(p + 32);
    if (p + 46 + nameLen > cd.length) throw new ZipBadError("a malformed central directory");
    const name = cd.toString("latin1", p + 46, p + 46 + nameLen).toLowerCase();
    if (!entries.has(name) && select(name)) {
      const entry: ZipEntryRef = {
        flags: cd.readUInt16LE(p + 8),
        method: cd.readUInt16LE(p + 10),
        comp: cd.readUInt32LE(p + 20),
        uncomp: cd.readUInt32LE(p + 24),
        local: cd.readUInt32LE(p + 42),
      };
      if (entry.comp === 0xffffffff || entry.uncomp === 0xffffffff || entry.local === 0xffffffff) throw new ZipBadError("a Zip64 archive");
      entries.set(name, entry);
    }
    p += 46 + nameLen + extraLen + commentLen;
  }
  return { cdOffset, entries };
}

/** The words a refused entry is counted with (the label read's, or the text
 *  read's). */
export interface EntryWords {
  overSize: string;
  bomb: string;
  inflate: string;
}

/**
 * One entry's bytes, inflated with zlib's `maxOutputLength` (a bomb stops
 * there): at most `inMax` compressed (a stored one at most `outMax`), its
 * local header checked, lying before the central directory; an encrypted
 * entry or a method other than stored or deflate refused. Throws
 * ZipBadError / ZipBudgetError.
 */
export async function readZipEntry(r: BoundedRead, zip: OpenZip, en: ZipEntryRef, lim: { inMax: number; outMax: number }, words: EntryWords): Promise<Buffer> {
  if ((en.flags & 1) !== 0) throw new ZipBadError("an encrypted entry");
  if (en.method !== 0 && en.method !== 8) throw new ZipBadError("an unsupported compression method");
  if (en.comp > lim.inMax) throw new ZipBadError(words.overSize);
  if (en.method === 0 && en.comp > lim.outMax) throw new ZipBadError(words.overSize);
  const lh = await r.read(en.local, 30);
  if (lh.readUInt32LE(0) !== SIG_LOCAL) throw new ZipBadError("a malformed local header");
  const dataAt = en.local + 30 + lh.readUInt16LE(26) + lh.readUInt16LE(28);
  if (dataAt + en.comp > zip.cdOffset) throw new ZipBadError("an entry outside the archive");
  const data = await r.read(dataAt, en.comp);
  if (en.method === 0) return data;
  try {
    return inflateRawSync(data, { maxOutputLength: lim.outMax });
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    throw new ZipBadError(code === "ERR_BUFFER_TOO_LARGE" || err instanceof RangeError ? words.bomb : words.inflate);
  }
}

const LABEL_WORDS: EntryWords = {
  overSize: "a label entry over its size limit",
  bomb: "a label entry that inflates past 256 KiB",
  inflate: "a label entry that cannot be inflated",
};

/** One label part (LabelInfo.xml or custom.xml) as text, under the label
 *  read's bounds. Throws as `readZipEntry`. */
export async function readLabelPart(r: BoundedRead, zip: OpenZip, en: ZipEntryRef): Promise<string> {
  const raw = await readZipEntry(r, zip, en, { inMax: LABEL_READ_LIMITS.entryInMax, outMax: LABEL_READ_LIMITS.entryOutMax }, LABEL_WORDS);
  return decodeXml(raw.subarray(0, LABEL_READ_LIMITS.entryOutMax));
}

/**
 * Read the labels of one OOXML file through `reader`, reading at most
 * `maxBytes` in all. Never throws: what cannot be read is `unreadable` with a
 * short reason (no file text in it).
 */
export async function readOfficeLabels(reader: OfficeByteReader, opts: { maxBytes?: number } = {}): Promise<OfficeLabelRead> {
  const r = boundedRead(reader, opts.maxBytes ?? Number.POSITIVE_INFINITY);
  try {
    const zip = await openOfficeZip(r, (name) => name === LABEL_INFO_PART || name === CUSTOM_PROPS_PART);
    if (zip === "encrypted") return { kind: "encrypted", bytes: r.bytes() };
    const info = zip.entries.get(LABEL_INFO_PART);
    if (info) return { kind: "labels", labels: parseLabelInfoXml(await readLabelPart(r, zip, info)), bytes: r.bytes() };
    const custom = zip.entries.get(CUSTOM_PROPS_PART);
    if (custom) return { kind: "labels", labels: parseCustomPropsXml(await readLabelPart(r, zip, custom)), bytes: r.bytes() };
    return { kind: "labels", labels: [], bytes: r.bytes() };
  } catch (err) {
    if (err instanceof ZipBudgetError) return { kind: "over-budget", bytes: r.bytes() };
    if (err instanceof ZipBadError) return { kind: "unreadable", reason: err.message, bytes: r.bytes() };
    return { kind: "unreadable", reason: "the file could not be read", bytes: r.bytes() };
  }
}

/** XML bytes → text: a UTF-16 byte order mark is honoured, else UTF-8. */
export function decodeXml(b: Buffer): string {
  if (b.length >= 2 && b[0] === 0xff && b[1] === 0xfe) return b.subarray(2).toString("utf16le");
  if (b.length >= 2 && b[0] === 0xfe && b[1] === 0xff) {
    const body = b.subarray(2, 2 + ((b.length - 2) & ~1));
    return Buffer.from(body).swap16().toString("utf16le");
  }
  return b.toString("utf8");
}

// ── The XML, by anchored patterns ────────────────────────────────────────────

const GUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** A GUID as written (braces and case optional) → lowercase without braces,
 *  or null when it is not one. Pure. */
export function normalizeGuid(v: unknown): string | null {
  if (typeof v !== "string") return null;
  let s = v.trim().toLowerCase();
  if (s.startsWith("{") && s.endsWith("}")) s = s.slice(1, -1);
  return GUID_RE.test(s) ? s : null;
}

/** `<label …/>` or `<prefix:label …>` elements' attribute text. */
const LABEL_EL_RE = /<(?:[A-Za-z_][\w.-]{0,32}:)?label\s([^<>]{0,4096}?)\/?>/g;
const ATTR_RE = /(?:^|\s)([A-Za-z_][\w.:-]{0,64})\s*=\s*(?:"([^"<>]{0,256})"|'([^'<>]{0,256})')/g;

function attrs(text: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const m of text.matchAll(ATTR_RE)) {
    const k = m[1]!.toLowerCase().replace(/^.*:/, "");
    if (!out.has(k)) out.set(k, m[2] ?? m[3] ?? "");
  }
  return out;
}

const truthy = (v: string | undefined): boolean => v !== undefined && /^\s*(1|true)\s*$/i.test(v);

function keep(labels: OfficeLabel[], l: OfficeLabel): void {
  if (labels.length >= LABEL_READ_LIMITS.labelsPerFile) return;
  const same = labels.find((x) => x.id === l.id && x.site === l.site);
  if (same) same.enabled ||= l.enabled;
  else labels.push(l);
}

/** `docMetadata/LabelInfo.xml` → its labels (id, site, enabled; `removed="1"`
 *  is not enabled). Pure; no name is kept. */
export function parseLabelInfoXml(xml: string): OfficeLabel[] {
  const out: OfficeLabel[] = [];
  const text = xml.length > LABEL_READ_LIMITS.entryOutMax ? xml.slice(0, LABEL_READ_LIMITS.entryOutMax) : xml;
  for (const m of text.matchAll(LABEL_EL_RE)) {
    const a = attrs(m[1]!);
    const id = normalizeGuid(a.get("id"));
    if (id === null) continue;
    keep(out, { id, site: normalizeGuid(a.get("siteid")), enabled: truthy(a.get("enabled")) && !truthy(a.get("removed")) });
  }
  return out;
}

const PROPERTY_RE = /<(?:[A-Za-z_][\w.-]{0,32}:)?property\s([^<>]{0,4096})>([^]{0,2048}?)<\/(?:[A-Za-z_][\w.-]{0,32}:)?property\s*>/g;
const MSIP_NAME_RE = /^MSIP_Label_([0-9A-Fa-f-]{36})_(Enabled|SiteId)$/i;
const LPWSTR_RE = /<(?:[A-Za-z_][\w.-]{0,32}:)?(?:lpwstr|bstr)\s*>([^<]{0,256})<\/(?:[A-Za-z_][\w.-]{0,32}:)?(?:lpwstr|bstr)\s*>/;

/** `docProps/custom.xml` → the `MSIP_Label_<guid>_Enabled` / `_SiteId`
 *  properties as labels. Pure; the `_Name` property (the display name) is
 *  never read. */
export function parseCustomPropsXml(xml: string): OfficeLabel[] {
  const text = xml.length > LABEL_READ_LIMITS.entryOutMax ? xml.slice(0, LABEL_READ_LIMITS.entryOutMax) : xml;
  const byId = new Map<string, { enabled: boolean; site: string | null }>();
  for (const m of text.matchAll(PROPERTY_RE)) {
    const name = attrs(m[1]!).get("name");
    const k = name === undefined ? null : MSIP_NAME_RE.exec(name);
    if (!k) continue;
    const id = normalizeGuid(k[1]);
    if (id === null) continue;
    const value = LPWSTR_RE.exec(m[2]!)?.[1];
    const cur = byId.get(id) ?? { enabled: false, site: null };
    if (k[2]!.toLowerCase() === "enabled") cur.enabled = truthy(value);
    else cur.site = normalizeGuid(value);
    byId.set(id, cur);
  }
  const out: OfficeLabel[] = [];
  for (const [id, v] of byId) keep(out, { id, site: v.site, enabled: v.enabled });
  return out;
}

// ── The mapping ──────────────────────────────────────────────────────────────

export type LabelLevel = "public" | "any-model" | "local-model" | "no-model";

const RANK: Readonly<Record<string, number>> = { "public": 0, "any-model": 1, "local-model": 2, "no-model": 3 };

/** A level's rank (an unknown level ranks as no-model: fail closed). */
export function labelLevelRank(level: string): number {
  return RANK[level] ?? 3;
}

/** One mapping entry in force (the user's or the administrator's). */
export interface LabelMappingEntry {
  id: string;
  site: string | null;
  name: string;
  level: LabelLevel;
  /** Set when the administrator's layer decides it (its file). */
  adminFile?: string;
}

/** The administrator's entries as the layer carries them (admin-layer.ts). */
export interface AdminLabelEntries {
  readonly sensitivityLabels?: ReadonlyArray<{ readonly entry: { id: string; site?: string; name: string; level: string }; readonly file: string }>;
}

function asEntry(raw: unknown, adminFile?: string): LabelMappingEntry | null {
  if (raw === null || typeof raw !== "object") return null;
  const r = raw as Record<string, unknown>;
  const id = normalizeGuid(r["id"]);
  const site = r["site"] === undefined || r["site"] === null ? null : normalizeGuid(r["site"]);
  if (id === null || (r["site"] !== undefined && r["site"] !== null && site === null)) return null;
  const level = typeof r["level"] === "string" && r["level"] in RANK ? (r["level"] as LabelLevel) : null;
  if (level === null) return null;
  const name = typeof r["name"] === "string" ? r["name"] : "";
  return { id, site, name, level, ...(adminFile !== undefined ? { adminFile } : {}) };
}

/**
 * The mapping in force: the administrator's entries, then the user's, merged
 * by (id, site). When both map the same (id, site) the STRICTER level wins
 * (the administrator's on a tie), so a user file never lowers what the
 * organization mapped. Entries the validator would refuse are left out.
 * Pure.
 */
export function effectiveLabelMapping(userEntries: unknown, admin: AdminLabelEntries | null = null): LabelMappingEntry[] {
  const out = new Map<string, LabelMappingEntry>();
  const put = (e: LabelMappingEntry): void => {
    const k = `${e.id}|${e.site ?? ""}`;
    const was = out.get(k);
    if (was === undefined || labelLevelRank(e.level) > labelLevelRank(was.level)) out.set(k, e);
  };
  for (const a of admin?.sensitivityLabels ?? []) {
    const e = asEntry(a.entry, a.file);
    if (e) put(e);
  }
  for (const u of Array.isArray(userEntries) ? userEntries : []) {
    const e = asEntry(u);
    if (e) put(e);
  }
  return [...out.values()];
}

/** The mapping entry that decides one label: its id, and no site or the
 *  label's own; among several, the strictest. Null: unmapped. Pure. */
export function mapLabel(label: { id: string; site: string | null }, mapping: readonly LabelMappingEntry[]): LabelMappingEntry | null {
  let best: LabelMappingEntry | null = null;
  for (const m of mapping) {
    if (m.id !== label.id) continue;
    if (m.site !== null && m.site !== label.site) continue;
    if (best === null || labelLevelRank(m.level) > labelLevelRank(best.level)) best = m;
  }
  return best;
}

/** A file's labels → the strictest mapped entry (null: none is mapped). */
export function strictestMapping(labels: ReadonlyArray<{ id: string; site: string | null }>, mapping: readonly LabelMappingEntry[]): LabelMappingEntry | null {
  let best: LabelMappingEntry | null = null;
  for (const l of labels) {
    const m = mapLabel(l, mapping);
    if (m !== null && (best === null || labelLevelRank(m.level) > labelLevelRank(best.level))) best = m;
  }
  return best;
}

// ── The finding and the summary ──────────────────────────────────────────────

/** One labelled Office file (§14.1 "A finding"): no other field. A label's
 *  display name inside the file is the file's text and is not kept. */
export interface SensitivityLabelFinding {
  /** Absolute. */
  path: string;
  /** The nearest work tree above it, else the scan root it was found under. */
  repoRoot: string;
  /** Its ENABLED labels. */
  labels: Array<{ id: string; site: string | null }>;
}

/** Most unmapped label ids the summary lists. */
export const UNMAPPED_LABELS_MAX = 50;

/** What the label read did in one scan (`workspaceScan.labels`). */
export interface SensitivityLabelScanSummary {
  /**
   * `mapped`: a mapping is in force, so Office files were read; `count`: no
   * mapping, but an explicit scan (`countLabels`) read them to count the
   * labels; `off`: no mapping and no count asked, so no Office file was
   * opened (every count below is 0).
   */
  mode: "mapped" | "count" | "off";
  /** Office files looked at. */
  examined: number;
  /** Office files opened this call. */
  read: number;
  /** Answered from the in-memory cache (unchanged since read). */
  cached: number;
  /** Bytes read this call. */
  bytes: number;
  /** Protected already: never opened. */
  covered: number;
  /** Files carrying at least one enabled label. */
  files: number;
  /** Of those, files carrying at least one mapped label. */
  mapped: number;
  /** Files carrying at least one enabled label that no entry maps. */
  unmappedFiles: number;
  /** The unmapped label ids, with how many files carry each; most files
   *  first, at most UNMAPPED_LABELS_MAX. */
  unmapped: Array<{ id: string; site: string | null; files: number }>;
  /** Further unmapped ids not listed. */
  unmappedMore: number;
  /** Purview-encrypted files (an OLE container): not read. */
  encrypted: number;
  /** Not a zip we read (Zip64, multi-disk, malformed, a bomb). */
  unreadable: number;
  capped: { overFiles: number; overBytes: number };
  limits: LabelScanLimits;
}

export function emptyLabelSummary(mode: SensitivityLabelScanSummary["mode"], limits: LabelScanLimits = DEFAULT_LABEL_LIMITS): SensitivityLabelScanSummary {
  return {
    mode, examined: 0, read: 0, cached: 0, bytes: 0, covered: 0, files: 0, mapped: 0, unmappedFiles: 0,
    unmapped: [], unmappedMore: 0, encrypted: 0, unreadable: 0, capped: { overFiles: 0, overBytes: 0 }, limits,
  };
}
