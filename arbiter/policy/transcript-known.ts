/**
 * transcript-known — the files `mandu scan` reads for the values it looks
 * for by exact match, its "known" findings (one of your secrets, still where
 * it was found: rotate it), and those values
 * (docs/design/confidentiality/confidentiality-plan-17-past-sessions-scan.md
 * §3 item 5, "Where the known values come from").
 *
 * The launch walk (secret-discovery.ts) is built for twins: it stops at
 * MAX_FILES (a launch's bind argv), and its `skipped` records, where an
 * agent's own login files are named, are capped at MAX_SKIP_RECORDS with the
 * agent logins LAST. A value the walk did not list was not known, so a key
 * that reached the model was reported only by its shape (`github-token`,
 * "not in your files now") when it was the person's live one. The scan's
 * walk now runs to SCAN_MAX_FILES, and its list is the walk's files AND,
 * read by their own places whatever the walk's caps did:
 *
 *   - every agent's login files (`agentLoginPaths`, each agent);
 *   - every credential store the catalog names under the home
 *     (SECRET_PREFIXES: `~/.config/gh/hosts.yml`, `~/.config/glab-cli`,
 *     `~/.netrc`, …), a store that is a folder walked to STORE_MAX_DEPTH,
 *     at most STORE_MAX_FILES of it, shallowest first; an agent's own store
 *     (its transcripts) is not; a file still has to be secret by the path
 *     rules and labels in force (a `public` label of the person's wins);
 *   - the person's systemd user units (`~/.config/systemd/user`) and the
 *     `EnvironmentFile=` each names under the home: a service's
 *     `Environment=HTTPS_PROXY=http://user:pass@127.0.0.1:3128` holds a
 *     password the agent can print (`systemctl --user cat`), read with the
 *     environment's own rules (`envSecretSpan`), plus any password in a URL
 *     and any key of a known format elsewhere in the unit.
 *
 * Read-only, and for the scan only: nothing here registers, labels or twins
 * a file (a unit file is no twin shape; the launch walk is unchanged). The
 * values never leave the arbiter: the scanner keeps an HMAC of each and the
 * credential-like ones (`knownIsCredential`).
 *
 * Mandu-new (no reference origin).
 */
import { lstatSync, readdirSync, readFileSync, realpathSync, statSync } from "node:fs";
import path from "node:path";
import { normalizedPrefixes } from "./secret-catalog.js";
import { agentLoginPaths, LOGIN_OWNERS, storeOwnerOf } from "./secret-discovery.js";
import { findSecretValues } from "./secret-detectors.js";
import { envSecretSpan, extractSecretSpans } from "./secret-extract.js";
import type { KnownSecret } from "./transcript-scan.js";

/** The launch walk's file cap for the scan's own walk (secret-discovery.ts
 *  `DiscoveryOptions.maxFiles`; a launch's is MAX_FILES, 256). */
export const SCAN_MAX_FILES = 4096;
/** How deep a store that is a folder is walked (`~/.aws/sso/cache/x.json`). */
export const STORE_MAX_DEPTH = 3;
/** At most this many files of one store (a `~/.kube/cache` holds thousands). */
export const STORE_MAX_FILES = 128;
/** One file larger than this is not read. */
export const KNOWN_MAX_FILE_BYTES = 4 * 1024 * 1024;
/** All files together: past this the rest are not read. */
export const KNOWN_MAX_TOTAL_BYTES = 64 * 1024 * 1024;
/** The unit files of a systemd user folder read (and `EnvironmentFile=`s). */
export const UNIT_MAX_FILES = 256;

/** How a file's values are read: by the extractor's shape for its path, as a
 *  systemd unit, or as the environment file a unit names. */
export type KnownFileKind = "extract" | "unit" | "env-file";
export interface KnownFile {
  path: string;
  kind: KnownFileKind;
  /** Listed by the launch walk: read whatever KNOWN_MAX_TOTAL_BYTES says,
   *  as before these places were added (its own caps bound it). */
  walked?: boolean;
}

const isUnder = (p: string, dir: string): boolean => p === dir || p.startsWith(`${dir}/`);

/** A regular file at `p` (a link to one counts), never a FIFO or device,
 *  which a read would block on or never finish. */
function regularFile(p: string): boolean {
  try {
    return statSync(p).isFile();
  } catch {
    return false;
  }
}

/** The regular files of `root` (a file, or a folder walked breadth first to
 *  STORE_MAX_DEPTH, names in order, at most STORE_MAX_FILES), never inside
 *  an agent's own store and never through a linked folder below the root
 *  (the launch walk's rule; the root itself may be one: the scan only
 *  reads). */
export function storeFiles(root: string, home: string): string[] {
  let st: ReturnType<typeof lstatSync> | undefined;
  try { st = lstatSync(root, { throwIfNoEntry: false }); } catch { st = undefined; }
  if (st === undefined) return [];
  // The store's own folder may be a link (`~/.config/gh` kept in a dotfiles
  // repository): followed there only, never below it.
  let isDir = st.isDirectory();
  if (st.isSymbolicLink()) {
    try { isDir = statSync(root).isDirectory(); } catch { return []; }
  }
  if (!isDir) return regularFile(root) ? [root] : [];
  const out: string[] = [];
  let level = [root];
  for (let depth = 0; depth <= STORE_MAX_DEPTH && level.length > 0 && out.length < STORE_MAX_FILES; depth++) {
    const next: string[] = [];
    for (const dir of level) {
      let names: string[];
      try { names = readdirSync(dir).sort(); } catch { continue; }
      for (const name of names) {
        const p = path.posix.join(dir, name);
        let e: ReturnType<typeof lstatSync> | undefined;
        try { e = lstatSync(p, { throwIfNoEntry: false }); } catch { e = undefined; }
        if (e === undefined) continue;
        if (e.isDirectory()) {
          if (storeOwnerOf(p, home) === null) next.push(p);
        } else if (regularFile(p) && out.length < STORE_MAX_FILES) {
          out.push(p);
        }
      }
    }
    level = next;
  }
  return out;
}

/** A systemd unit's name (`app.service`, a kept copy `app.service.bak`), or
 *  a drop-in (`app.service.d/proxy.conf`, matched by its folder). */
const UNIT_NAME_RE = /\.(?:service|socket|timer|path|mount|automount|swap|target|slice|scope)(?:\.[A-Za-z0-9_-]+|~)?$/;

/** The unit files of a systemd user folder (`~/.config/systemd/user`): its
 *  units and their drop-ins, each file once (a `*.wants/` link to a unit is
 *  the unit), at most UNIT_MAX_FILES. */
export function systemdUnitFiles(dir: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const add = (p: string): void => {
    if (out.length >= UNIT_MAX_FILES || !regularFile(p)) return;
    let real = p;
    try { real = realpathSync(p); } catch { /* keep the spelling */ }
    if (seen.has(real)) return;
    seen.add(real);
    out.push(p);
  };
  let names: string[];
  try { names = readdirSync(dir).sort(); } catch { return out; }
  const dirs: string[] = [];
  // The units first, so a `*.wants/` link to one is named by the unit's own path.
  for (const name of names) {
    const p = path.posix.join(dir, name);
    let e: ReturnType<typeof lstatSync> | undefined;
    try { e = lstatSync(p, { throwIfNoEntry: false }); } catch { e = undefined; }
    if (e === undefined) continue;
    if (e.isDirectory()) {
      // `app.service.d/*.conf` (drop-ins) and `*.wants/` (links to units).
      if (/\.(?:d|wants|requires)$/.test(name)) dirs.push(name);
    } else if (UNIT_NAME_RE.test(name)) {
      add(p);
    }
  }
  for (const name of dirs) {
    const p = path.posix.join(dir, name);
    let inner: string[];
    try { inner = readdirSync(p).sort(); } catch { continue; }
    for (const n of inner) if (name.endsWith(".d") ? n.endsWith(".conf") : UNIT_NAME_RE.test(n)) add(path.posix.join(p, n));
  }
  return out;
}

/** The words of one `Environment=` value as systemd splits them: blanks
 *  outside quotes end a word, `"…"` and `'…'` quote, a backslash escapes the
 *  next character. Pure. */
function unitWords(s: string): string[] {
  const out: string[] = [];
  let cur = "";
  let any = false;
  let q: string | null = null;
  for (let i = 0; i < s.length; i++) {
    const c = s[i]!;
    if (q !== null) {
      if (c === q) q = null;
      else if (c === "\\" && q === '"' && i + 1 < s.length) cur += s[++i]!;
      else cur += c;
    } else if (c === '"' || c === "'") {
      q = c;
      any = true;
    } else if (c === "\\" && i + 1 < s.length) {
      cur += s[++i]!;
      any = true;
    } else if (/\s/.test(c)) {
      if (any || cur !== "") out.push(cur);
      cur = "";
      any = false;
    } else {
      cur += c;
      any = true;
    }
  }
  if (any || cur !== "") out.push(cur);
  return out;
}

/** One `NAME=value` assignment's credential, by the environment's own rules
 *  (`envSecretSpan`: a secret-named variable's value, the password of a URL,
 *  a key of a known format), an agent's key variable included: in a unit it
 *  is a service's key, not the launched agent's. */
function assignmentValue(name: string, value: string): { name: string; value: string } | null {
  const sp = envSecretSpan(name, value, { agentKeys: [name] });
  return sp === null ? null : { name: sp.key, value: sp.value };
}

/** Every value in the text a vendor format or a URL's password marks
 *  (`url.password`, `cred.<shape>`) that its assignments did not give. */
function shapedValues(text: string, given: readonly { value: string }[]): Array<{ name: string; value: string }> {
  const have = new Set(given.map((g) => g.value));
  const out: Array<{ name: string; value: string }> = [];
  for (const h of findSecretValues(text)) {
    if (h.shape === "credential-assignment" || have.has(h.value)) continue;
    have.add(h.value);
    out.push({ name: h.shape === "url-password" ? "url.password" : `cred.${h.shape}`, value: h.value });
  }
  return out;
}

/**
 * The credentials a systemd unit holds: each `Environment=` assignment's
 * (`assignmentValue`), any URL password or key of a known format elsewhere
 * (an `ExecStart=` flag), and the `EnvironmentFile=` paths it names (`%h`
 * is the home; a leading `-` only makes the file optional). Comment lines
 * (`#`, `;`) are not read. Pure.
 */
export function systemdUnitValues(content: string, home: string): { values: Array<{ name: string; value: string }>; environmentFiles: string[] } {
  const values: Array<{ name: string; value: string }> = [];
  const environmentFiles: string[] = [];
  const live: string[] = [];
  for (const raw of content.split("\n")) {
    const line = raw.replace(/\r$/, "");
    if (/^\s*[#;]/.test(line)) continue;
    live.push(line);
    const m = /^\s*(Environment|EnvironmentFile)\s*=\s*(.*)$/.exec(line);
    if (m === null) continue;
    if (m[1] === "EnvironmentFile") {
      const p = m[2]!.trim().replace(/^-/, "").replace(/^%h(?=\/)/, home);
      if (p.startsWith("/")) environmentFiles.push(path.posix.normalize(p));
      continue;
    }
    for (const w of unitWords(m[2]!)) {
      const eq = w.indexOf("=");
      if (eq <= 0) continue;
      const v = assignmentValue(w.slice(0, eq), w.slice(eq + 1));
      if (v !== null) values.push(v);
    }
  }
  values.push(...shapedValues(live.join("\n"), values));
  return { values, environmentFiles };
}

/** The credentials of an environment file a unit names (`NAME=value` a line,
 *  `export ` allowed, quotes removed, `#`/`;` comments). Pure. */
export function envFileValues(content: string): Array<{ name: string; value: string }> {
  const values: Array<{ name: string; value: string }> = [];
  const live: string[] = [];
  for (const raw of content.split("\n")) {
    const line = raw.replace(/\r$/, "");
    if (/^\s*(?:[#;]|$)/.test(line)) continue;
    live.push(line);
    const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.]*)\s*=\s*(.*?)\s*$/.exec(line);
    if (m === null) continue;
    let v = m[2]!;
    if (v.length >= 2 && (v[0] === '"' || v[0] === "'") && v[v.length - 1] === v[0]) v = v.slice(1, -1);
    const got = assignmentValue(m[1]!, v);
    if (got !== null) values.push(got);
  }
  values.push(...shapedValues(live.join("\n"), values));
  return values;
}

/**
 * The files the scan reads its known values from: the walk's (`discovered`,
 * as they are), every agent's login files, every catalog credential store
 * under `home` (`isSecretPath` decides each of its files, with the labels in
 * force), and the systemd user units under `configHome` (default
 * `~/.config`). A transcript store's file is never one (`isTranscript`).
 * Each path once, in that order. Not pure: it lists folders.
 */
export function transcriptKnownFiles(opts: {
  home: string;
  discovered: readonly string[];
  isSecretPath: (p: string) => boolean;
  isTranscript: (p: string) => boolean;
  /** The agents' login variables (`CLAUDE_CONFIG_DIR`, `CODEX_HOME`, …) of
   *  this home's own process; another home's are at their defaults. */
  loginEnv?: Readonly<Record<string, string | undefined>>;
  configHome?: string;
}): KnownFile[] {
  const home = opts.home.replace(/\/+$/, "");
  const out = new Map<string, KnownFile>();
  const add = (p: string, kind: KnownFileKind, walked = false): void => {
    if (!out.has(p) && !opts.isTranscript(p)) out.set(p, { path: p, kind, ...(walked ? { walked } : {}) });
  };
  for (const p of opts.discovered) add(p, "extract", true);
  // Every agent's logins, as the walk's `agent-login` records named them
  // (that list is capped): a folder login (`~/.anthropic`) by its files.
  for (const owner of LOGIN_OWNERS) {
    for (const l of agentLoginPaths(owner, home, opts.loginEnv ?? {})) for (const f of storeFiles(l, home)) add(f, "extract");
  }
  for (const prefix of normalizedPrefixes(home)) {
    if (!isUnder(prefix, home) || prefix === home || storeOwnerOf(prefix, home) !== null) continue;
    for (const f of storeFiles(prefix, home)) if (opts.isSecretPath(f)) add(f, "extract");
  }
  const units = path.posix.join(opts.configHome ?? path.posix.join(home, ".config"), "systemd", "user");
  for (const f of systemdUnitFiles(units)) add(f, "unit");
  return [...out.values()];
}

/**
 * The known values of `files`, each as a {@link KnownSecret} (its path with
 * the home as `~`, its key as the name). A unit's `EnvironmentFile=` under
 * the home is read too. A file past KNOWN_MAX_FILE_BYTES, or (one the walk
 * did not list) once the total passed KNOWN_MAX_TOTAL_BYTES, is not read;
 * an unreadable one is skipped. The total counts only the files the walk did
 * not list: the walk's own are bounded by its caps, and counting them let a
 * large walk (the scan's 4096 files) use up the budget before a credential
 * store was read (step 0 on a developer's machine, 2026-10-22: the GitHub
 * CLI's token in `~/.config/gh/hosts.yml` was never known).
 */
export function knownSecretsOf(files: readonly KnownFile[], opts: { home: string; isTranscript: (p: string) => boolean; maxTotalBytes?: number }): KnownSecret[] {
  const home = opts.home.replace(/\/+$/, "");
  const tilde = (p: string): string => (p.startsWith(`${home}/`) ? `~${p.slice(home.length)}` : p);
  const budget = opts.maxTotalBytes ?? KNOWN_MAX_TOTAL_BYTES;
  let total = 0;
  const read = (p: string, walked = false): string | null => {
    try {
      if (!regularFile(p)) return null;
      const size = statSync(p).size;
      if (size > KNOWN_MAX_FILE_BYTES || (!walked && total + size > budget)) return null;
      if (!walked) total += size;
      return readFileSync(p, "utf8");
    } catch {
      return null;
    }
  };
  const known: KnownSecret[] = [];
  const envFiles = new Set<string>();
  for (const f of files) {
    const content = read(f.path, f.walked === true);
    if (content === null) continue;
    if (f.kind === "extract") {
      for (const sp of extractSecretSpans(f.path, content).spans) known.push({ value: sp.value, path: tilde(f.path), name: sp.key });
    } else if (f.kind === "unit") {
      const u = systemdUnitValues(content, home);
      for (const v of u.values) known.push({ value: v.value, path: tilde(f.path), name: v.name });
      for (const e of u.environmentFiles) if (isUnder(e, home) && e !== home && !opts.isTranscript(e)) envFiles.add(e);
    } else {
      for (const v of envFileValues(content)) known.push({ value: v.value, path: tilde(f.path), name: v.name });
    }
  }
  for (const e of envFiles) {
    const content = read(e);
    if (content === null) continue;
    for (const v of envFileValues(content)) known.push({ value: v.value, path: tilde(e), name: v.name });
  }
  return known;
}
