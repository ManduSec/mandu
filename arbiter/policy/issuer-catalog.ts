/**
 * issuer-catalog — the issuer files of the default catalog's ISSUER
 * BINDINGS, checked and compiled (confidentiality.md §2.3, "Where the table
 * lives, and what checks a file"). One JSON file per issuer under
 * `policy/issuers/` (listed, in table order, by `issuers/index.ts`);
 * `issuer-bindings.ts` exports the compiled table as `ISSUERS`.
 *
 * Because the table releases a secret WITHOUT asking, a wrong file is a
 * security regression, so every file passes every check below or is left
 * out WHOLE (fail-closed: an issuer whose file fails gives no put-back, and
 * the reason is in `problems`, which the arbiter prints at start and
 * `npm run check:issuers` prints and exits 1 on). Never a looser match: a
 * file is taken as it is or not at all.
 *
 * Per file:
 *   - the fields are exactly `id`, `name`, `formats`, `shapes`, `hosts`,
 *     `docs`, `examples` and optionally `non_examples` (no unknown field,
 *     none missing, each array non-empty with no repeat);
 *   - `id` is lower case (`[a-z0-9-]`) and equals the file name;
 *   - each format compiles with no flags, is anchored (`^…$`, no top-level
 *     `|`), uses `(?:…)` groups only (no capture, lookaround or
 *     backreference), repeats no group that itself repeats (no exponential
 *     backtracking), and begins with a fixed literal prefix of 3 or more
 *     characters (`literalPrefixes`: literal characters, a small `[abc]`
 *     set or a `(?:ab|cd)` choice of literals, each unrepeated);
 *   - the shapes in words are exactly those prefixes, each followed by `…`;
 *   - each host is a lower-case DNS name as the egress gate reads one
 *     (`issuerDestinationHost` returns it unchanged): no scheme, port,
 *     path, wildcard, address or trailing dot, two labels or more, not a
 *     public suffix (`co.uk`) and not under a shared-hosting suffix anyone
 *     can register a name under (`github.io`, `vercel.app`, …);
 *   - each doc is an `https://` URL with no user name;
 *   - each example and non-example is written with its random part as a
 *     run (`{x*36}` stands for 36 `x`s), so the file never holds a real
 *     key, and expands to a value Mandu's own stand-in test calls a
 *     placeholder; each example matches one of the issuer's formats, every
 *     format has an example, and no non-example matches.
 *
 * Across files (each offender is left out, both sides of a clash):
 *   - no two files share an id or a host;
 *   - no prefix of one issuer is a prefix of another's (`sk_` and `sk_live_`
 *     clash; `sk_live_` and `sk-proj-` do not): this PROVES no value can
 *     match two issuers' formats, so no new file can claim a value
 *     another issuer's format already names;
 *   - no example of one issuer matches another issuer's format.
 *
 * The host checks are a backstop. The guard is the maintainer, who checks
 * every host and prefix against the issuer's own documentation (the
 * `docs` URLs) before a file is merged (CONTRIBUTING.md, "Add a service").
 *
 * Pure. Mandu-new (no reference origin).
 */
import { isPlaceholder } from "./secret-detectors.js";

export interface Issuer {
  /** The id `issuers_off` names. */
  id: string;
  /** For people: "Stripe". */
  name: string;
  /** The key formats, each anchored over the whole value. */
  formats: readonly RegExp[];
  /** The formats in words, for `mandu why` and the docs. */
  shapes: readonly string[];
  /** The exact API hosts (lower case, no port). */
  hosts: readonly string[];
  /** Where each host is documented by the issuer itself. */
  docs: readonly string[];
}

/** The host of `destination` when it is a plain DNS name on port 443 or on
 *  no stated port (`host`, `host:443`, `https://host[:443]/…`), lower case,
 *  a trailing dot dropped; null for anything else (an address, userinfo, a
 *  wildcard, another port, another scheme). Pure. */
export function issuerDestinationHost(destination: unknown): string | null {
  if (typeof destination !== "string") return null;
  let s = destination.trim();
  const m = /^([a-z][a-z0-9+.-]*):\/\/([^/?#]*)(?:[/?#].*)?$/is.exec(s);
  if (m) {
    if (m[1]!.toLowerCase() !== "https") return null;
    s = m[2]!;
  }
  if (s.includes("@") || s.includes("[") || s.includes("*") || s.includes("/")) return null;
  const parts = s.split(":");
  if (parts.length > 2) return null;
  if (parts.length === 2 && parts[1] !== "443") return null;
  let host = parts[0]!.toLowerCase();
  if (host.endsWith(".")) host = host.slice(0, -1);
  if (!/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(host)) return null;
  return host;
}

// ── the checks ───────────────────────────────────────────────────────────────

/** The fields an issuer file has (`non_examples` optional). */
export const ISSUER_FILE_FIELDS = ["id", "name", "formats", "shapes", "hosts", "docs", "examples", "non_examples"] as const;
const REQUIRED_FIELDS = ISSUER_FILE_FIELDS.filter((f) => f !== "non_examples");

/** The shortest fixed literal prefix a format may begin with. */
export const MIN_ISSUER_PREFIX = 3;
const MAX_PREFIXES = 64;
const MAX_FORMAT_LENGTH = 512;
const MAX_VALUE_LENGTH = 4096; // issuerOfValue's own cap

/** Multi-label public suffixes (a small built-in list, not the whole PSL):
 *  a host equal to one is no one's. */
const PUBLIC_SUFFIXES: ReadonlySet<string> = new Set([
  "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk",
  "com.au", "net.au", "org.au", "edu.au", "gov.au", "co.nz", "org.nz", "net.nz",
  "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "co.kr", "or.kr", "ne.kr",
  "com.br", "net.br", "org.br", "com.cn", "net.cn", "org.cn", "com.tw", "com.hk",
  "com.sg", "com.my", "co.in", "net.in", "org.in", "co.za", "com.mx", "com.ar",
  "co.il", "com.tr", "co.id", "com.ph", "com.vn", "co.th", "com.ua", "com.pl",
]);

/** Shared-hosting suffixes anyone can register a name under: no host at or
 *  under one is an issuer's fixed API host. */
const SHARED_SUFFIXES: readonly string[] = [
  "github.io", "githubusercontent.com", "gitlab.io", "herokuapp.com", "vercel.app", "now.sh",
  "netlify.app", "pages.dev", "workers.dev", "r2.dev", "web.app", "firebaseapp.com", "appspot.com",
  "azurewebsites.net", "cloudfront.net", "amazonaws.com", "blogspot.com", "ngrok.io", "ngrok-free.app",
  "ngrok.app", "onrender.com", "fly.dev", "glitch.me", "repl.co", "replit.dev", "deno.dev", "surge.sh",
  "trycloudflare.com", "loca.lt", "railway.app", "up.railway.app", "azurestaticapps.net", "codeberg.page",
];

/** A `{c*n}` run in an example: the character `c` written `n` times. */
const RUN = /\{([0-9A-Za-z])\*(\d{1,4})\}/g;

/** An example or non-example with its runs written out, or why it cannot be. */
export function expandSample(template: unknown): { value: string; runs: number } | { problem: string } {
  if (typeof template !== "string" || template === "") return { problem: "must be a non-empty string" };
  if (/[{}]/.test(template.replace(RUN, ""))) return { problem: "has a { or } that is not a {c*n} run (write the random part as {x*36})" };
  let runs = 0;
  let zero = false;
  const value = template.replace(RUN, (_m, c: string, n: string) => {
    runs++;
    if (Number(n) < 1) zero = true;
    return c.repeat(Number(n));
  });
  if (zero) return { problem: "has a {c*0} run" };
  if (value.length > MAX_VALUE_LENGTH) return { problem: `expands to more than ${MAX_VALUE_LENGTH} characters` };
  return { value, runs };
}

/**
 * The fixed literal prefixes every value `source` matches begins with: the
 * literal characters after `^`, a `[abc]` set of letters, digits or `_`, or
 * a `(?:ab|cd)` choice of literals, each taken while unrepeated (at most 64
 * prefixes). `[]` when the source is not `^`-anchored. Pure.
 */
export function literalPrefixes(source: string): string[] {
  if (!source.startsWith("^")) return [];
  const end = source.endsWith("$") && !/(?:^|[^\\])(?:\\\\)*\\\$$/.test(source) ? source.length - 1 : source.length;
  const PLAIN = /^[^\\^$.|?*+()[\]{}]$/;
  const lit = (k: number): [string, number] | null => {
    if (k >= end) return null;
    const c = source[k]!;
    if (c === "\\") {
      const d = source[k + 1];
      return d !== undefined && k + 1 < end && /^[^0-9A-Za-z]$/.test(d) ? [d, k + 2] : null;
    }
    return PLAIN.test(c) ? [c, k + 1] : null;
  };
  const repeated = (k: number): boolean => k < end && "*+?{".includes(source[k]!);
  let set = [""];
  let i = 1;
  while (i < end) {
    let alts: string[] | null = null;
    let next = i;
    const l = lit(i);
    if (l) {
      alts = [l[0]];
      next = l[1];
    } else if (source[i] === "[") {
      const close = source.indexOf("]", i + 1);
      const body = close === -1 ? "" : source.slice(i + 1, close);
      if (close !== -1 && close < end && /^[0-9A-Za-z_]+$/.test(body)) {
        alts = [...new Set(body)];
        next = close + 1;
      }
    } else if (source.startsWith("(?:", i)) {
      const out: string[] = [];
      let k = i + 3, cur = "", closed = false;
      while (k < end) {
        if (source[k] === "|") { out.push(cur); cur = ""; k++; continue; }
        if (source[k] === ")") { out.push(cur); closed = true; k++; break; }
        const c = lit(k);
        if (!c) break;
        cur += c[0];
        k = c[1];
      }
      if (closed) {
        alts = [...new Set(out)];
        next = k;
      }
    }
    if (alts === null || repeated(next)) break;
    const grown = set.flatMap((p) => alts!.map((a) => p + a));
    if (grown.length > MAX_PREFIXES) break;
    set = grown;
    i = next;
  }
  return [...new Set(set)];
}

/** Why `source` is not a format the table may hold ([] when it is). Pure. */
export function formatProblems(source: unknown): string[] {
  if (typeof source !== "string" || source.length === 0 || source.length > MAX_FORMAT_LENGTH) {
    return [`must be a string of 1 to ${MAX_FORMAT_LENGTH} characters`];
  }
  try {
    new RegExp(source);
  } catch (e) {
    return [`does not compile: ${(e as Error).message}`];
  }
  const out: string[] = [];
  if (!source.startsWith("^")) out.push("must start with ^ (a format matches the whole value)");
  if (!source.endsWith("$")) out.push("must end with $ (a format matches the whole value)");
  if (out.length > 0) return out;
  const end = source.length - 1;
  const groups: boolean[] = [false]; // per open group: does it hold a quantifier ([0]: the top level)
  let closedGroupRepeats: boolean | null = null; // the atom just read was a group: did it hold one
  for (let i = 1; i < end;) {
    const c = source[i]!;
    if (c === "\\") {
      if (i + 1 >= end) { out.push("ends with \\$, an escaped $: the format is not anchored"); break; }
      const d = source[i + 1]!;
      if (/[1-9]/.test(d) || d === "k") out.push("has a backreference");
      i += 2;
      closedGroupRepeats = null;
      continue;
    }
    if (c === "[") {
      let j = i + 1;
      while (j < end && source[j] !== "]") j += source[j] === "\\" ? 2 : 1;
      if (j >= end) { out.push("has an unclosed [ set"); break; }
      i = j + 1;
      closedGroupRepeats = null;
      continue;
    }
    if (c === "(") {
      if (!source.startsWith("(?:", i)) { out.push("may use (?: … ) groups only (no capture, lookaround or named group)"); break; }
      groups.push(false);
      i += 3;
      closedGroupRepeats = null;
      continue;
    }
    if (c === ")") {
      const had = groups.pop()!;
      if (groups.length === 0) { out.push("has an unbalanced )"); break; }
      groups[groups.length - 1] = groups[groups.length - 1]! || had;
      closedGroupRepeats = had;
      i++;
      continue;
    }
    if (c === "|") {
      if (groups.length === 1) out.push("has a top-level |, which unanchors a branch: write ^(?:a|b)…$");
      i++;
      closedGroupRepeats = null;
      continue;
    }
    if (c === "*" || c === "+" || c === "?" || c === "{") {
      let len = 1;
      if (c === "{") {
        const m = /^\{\d+(?:,\d*)?\}/.exec(source.slice(i, end));
        if (!m) { out.push("has a { that is not a {n,m} count (write \\{)"); break; }
        len = m[0].length;
      }
      if (closedGroupRepeats === true) out.push("repeats a group that itself repeats (nested repetition can take exponential time)");
      groups[groups.length - 1] = true;
      i += len;
      if (source[i] === "?" && i < end) i++;
      closedGroupRepeats = null;
      continue;
    }
    if (c === "^" || c === "$") out.push(`has ${c} inside: the anchors go at the two ends only`);
    i++;
    closedGroupRepeats = null;
  }
  const prefixes = literalPrefixes(source);
  if (prefixes.length === 0 || prefixes.some((p) => p.length < MIN_ISSUER_PREFIX)) {
    out.push(`must begin with a fixed literal prefix of ${MIN_ISSUER_PREFIX} or more characters that names the issuer (got ${JSON.stringify(prefixes)})`);
  }
  return out;
}

/** Why `host` cannot be an issuer's API host (null when it can). Pure. */
export function issuerHostProblem(host: unknown): string | null {
  if (typeof host !== "string") return "must be a string";
  if (issuerDestinationHost(host) !== host) {
    return "must be a lower-case DNS name with no scheme, port, path, wildcard, address or trailing dot";
  }
  if (host.split(".").length < 2) return "must have two labels or more";
  if (PUBLIC_SUFFIXES.has(host)) return "is a public suffix, no one's host";
  const shared = SHARED_SUFFIXES.find((s) => host === s || host.endsWith(`.${s}`));
  if (shared !== undefined) return `is under ${shared}, where anyone can register a name`;
  return null;
}

/** Why `url` cannot be a doc citation (null when it can). Pure. */
export function issuerDocProblem(url: unknown): string | null {
  if (typeof url !== "string") return "must be a string";
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return "is not a URL";
  }
  if (u.protocol !== "https:") return "must be an https:// URL";
  if (u.username !== "" || u.password !== "") return "must carry no user name or password";
  if (issuerDestinationHost(u.hostname) !== u.hostname) return "must name a DNS host";
  return null;
}

/** One file, checked: the issuer it compiles to, or null with the reasons. */
export interface CheckedIssuerFile {
  issuer: Issuer | null;
  /** Each format's literal prefixes, flattened (for the overlap check). */
  prefixes: readonly string[];
  examples: readonly string[];
  nonExamples: readonly string[];
  problems: readonly string[];
}

const stringList = (v: unknown, field: string, out: string[], optional = false): string[] => {
  if (v === undefined && optional) return [];
  if (!Array.isArray(v) || v.length === 0) { out.push(`${field}: must be a non-empty list`); return []; }
  if (!v.every((e) => typeof e === "string")) { out.push(`${field}: every entry must be a string`); return []; }
  if (new Set(v).size !== v.length) out.push(`${field}: has a repeated entry`);
  return v as string[];
};

/** Check one issuer file (`file` its name, `data` its parsed JSON). Pure. */
export function checkIssuerFile(file: string, data: unknown): CheckedIssuerFile {
  const out: string[] = [];
  const fail = (): CheckedIssuerFile => ({ issuer: null, prefixes: [], examples: [], nonExamples: [], problems: out.map((p) => `${file}: ${p}`) });
  if (data === null || typeof data !== "object" || Array.isArray(data)) {
    out.push("must be a JSON object");
    return fail();
  }
  const o = data as Record<string, unknown>;
  for (const k of Object.keys(o)) {
    if (!(ISSUER_FILE_FIELDS as readonly string[]).includes(k)) out.push(`unknown field '${k}' (allowed: ${ISSUER_FILE_FIELDS.join(", ")})`);
  }
  for (const k of REQUIRED_FIELDS) if (!(k in o)) out.push(`missing field '${k}'`);
  if (out.length > 0) return fail();

  const id = o.id;
  if (typeof id !== "string" || !/^[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?$/.test(id)) out.push("id: must be lower-case letters, digits and -");
  else if (file !== `${id}.json`) out.push(`id: '${id}' must equal the file name (${id}.json)`);
  if (typeof o.name !== "string" || o.name.trim() === "" || o.name.length > 64 || /[\u0000-\u001f\u007f]/.test(o.name)) {
    out.push("name: must be a short non-empty name");
  }

  const sources = stringList(o.formats, "formats", out);
  const formats: RegExp[] = [];
  const prefixes: string[] = [];
  sources.forEach((s, i) => {
    const p = formatProblems(s);
    for (const x of p) out.push(`formats[${i}] ${JSON.stringify(s)}: ${x}`);
    if (p.length === 0) {
      formats.push(new RegExp(s));
      prefixes.push(...literalPrefixes(s));
    }
  });

  const shapes = stringList(o.shapes, "shapes", out);
  for (const s of shapes) if (!s.includes("…")) out.push(`shapes: ${JSON.stringify(s)} must show the prefix followed by …`);
  if (formats.length === sources.length && sources.length > 0) {
    const said = [...new Set(shapes.map((s) => s.split("…")[0]!))].sort();
    const real = [...new Set(prefixes)].sort();
    if (JSON.stringify(said) !== JSON.stringify(real)) {
      out.push(`shapes: must name exactly the formats' prefixes, each followed by … (the formats begin with ${real.map((p) => `${p}…`).join(", ")})`);
    }
  }

  const hosts = stringList(o.hosts, "hosts", out);
  for (const h of hosts) {
    const p = issuerHostProblem(h);
    if (p !== null) out.push(`hosts: ${JSON.stringify(h)} ${p}`);
  }
  const docs = stringList(o.docs, "docs", out);
  for (const d of docs) {
    const p = issuerDocProblem(d);
    if (p !== null) out.push(`docs: ${JSON.stringify(d)} ${p}`);
  }

  const samples = (field: "examples" | "non_examples", optional: boolean): string[] => {
    const values: string[] = [];
    for (const t of stringList(o[field], field, out, optional)) {
      const x = expandSample(t);
      if ("problem" in x) { out.push(`${field}: ${JSON.stringify(t)} ${x.problem}`); continue; }
      if (x.runs === 0 || !isPlaceholder(x.value)) {
        out.push(`${field}: ${JSON.stringify(t)} must write its random part as a run of x ({x*36}), so the file never holds a real key`);
        continue;
      }
      values.push(x.value);
    }
    return values;
  };
  const examples = samples("examples", false);
  const nonExamples = samples("non_examples", true);
  if (formats.length === sources.length) {
    for (const [i, v] of examples.entries()) {
      if (!formats.some((f) => f.test(v))) out.push(`examples[${i}]: does not match any of this issuer's formats`);
    }
    formats.forEach((f, i) => {
      if (!examples.some((v) => f.test(v))) out.push(`formats[${i}]: no example matches it`);
    });
    for (const [i, v] of nonExamples.entries()) {
      if (formats.some((f) => f.test(v))) out.push(`non_examples[${i}]: matches this issuer's format`);
    }
  }

  if (out.length > 0) return fail();
  const issuer: Issuer = Object.freeze({
    id: id as string,
    name: o.name as string,
    formats: Object.freeze(formats),
    shapes: Object.freeze([...shapes]),
    hosts: Object.freeze([...hosts]),
    docs: Object.freeze([...docs]),
  });
  return { issuer, prefixes, examples, nonExamples, problems: [] };
}

/** The compiled table and what was left out of it. */
export interface IssuerCatalog {
  /** The issuers whose files passed every check, in file order. */
  issuers: readonly Issuer[];
  /** Why each left-out file was left out (empty when none was). */
  problems: readonly string[];
  /** Each kept issuer's examples and non-examples, written out (tests). */
  samples: ReadonlyMap<string, { examples: readonly string[]; nonExamples: readonly string[] }>;
}

/** Check every file and compile the table: a file that fails a check, and
 *  both sides of a clash between files, are left out (fail-closed: that
 *  issuer's keys ask). Pure. */
export function loadIssuerCatalog(files: readonly { file: string; data: unknown }[]): IssuerCatalog {
  const problems: string[] = [];
  const checked = files.map((f) => {
    const c = checkIssuerFile(f.file, f.data);
    problems.push(...c.problems);
    return { file: f.file, ...c };
  });
  const ok = checked.filter((c): c is typeof c & { issuer: Issuer } => c.issuer !== null);
  const out = new Set<number>();
  for (let a = 0; a < ok.length; a++) {
    for (let b = a + 1; b < ok.length; b++) {
      const A = ok[a]!, B = ok[b]!;
      const clash: string[] = [];
      if (A.issuer.id === B.issuer.id) clash.push(`both have id '${A.issuer.id}'`);
      const host = A.issuer.hosts.find((h) => B.issuer.hosts.includes(h));
      if (host !== undefined) clash.push(`both name host ${host}`);
      const pair = A.prefixes.flatMap((p) => B.prefixes.filter((q) => p.startsWith(q) || q.startsWith(p)).map((q) => [p, q]));
      if (pair.length > 0) clash.push(`prefixes overlap (${pair[0]![0]}… and ${pair[0]![1]}…), so a value could match both`);
      if (A.examples.some((v) => B.issuer.formats.some((f) => f.test(v))) || B.examples.some((v) => A.issuer.formats.some((f) => f.test(v)))) {
        clash.push("an example of one matches the other's format");
      }
      if (clash.length > 0) {
        problems.push(`${A.file} and ${B.file}: ${clash.join("; ")}; both left out`);
        out.add(a);
        out.add(b);
      }
    }
  }
  const kept = ok.filter((_, i) => !out.has(i));
  return {
    issuers: Object.freeze(kept.map((c) => c.issuer)),
    problems: Object.freeze(problems),
    samples: new Map(kept.map((c) => [c.issuer.id, { examples: c.examples, nonExamples: c.nonExamples }])),
  };
}
