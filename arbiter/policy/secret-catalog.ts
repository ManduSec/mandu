/**
 * secret-catalog — the Phase-A default-secret catalog
 * (docs/design/confidentiality/confidentiality.md §6 item 1).
 *
 * Path-provenance classifier: given where a datum came FROM (a file path, or
 * free text that references paths — a Bash command, an origin hint), return
 * its default confidentiality level. Zero-config: every match defaults to
 * `no-model` — no task requires a vendor model to READ a credential —
 * and NOTHING here yields `any-model` (that level is a deliberate
 * labeling act, Phase B).
 *
 * An unmatched path is `public` BY DESIGN: §6's "mislabeling fails silent"
 * is the accepted, documented risk (mitigated by this catalog and the later
 * labeling UI). The fail-closed doctrine covers uncertain LEVEL values and
 * unreachable arbiters, not unlabeled files. One amendment (2026-10-19,
 * secret-discovery.md §2.6): the catalog's CONTENT tier. A JSON, YAML or
 * TOML config file the launch walk READ and found a credential in is no
 * longer unmatched: the walk records a found label (found-labels.ts), which
 * the label lookup gives as `CONTENT_RULE`; likewise a text document it read
 * and found to be a personal document (a statement, a tax return, a lab
 * report, household codes: personal-documents.ts, §2.7), `DOCUMENT_RULE`.
 * This module still reads no file; an unmatched path the walk never read,
 * or read and found nothing in, stays public.
 *
 * The text scan is the wrapper-layer approximation of the kernel tier's
 * ground-truth openat() observation — conservative on purpose: a false
 * positive costs utility (an over-labeled datum), never security.
 *
 * Mandu-new (no reference origin): designed in docs/design/confidentiality/confidentiality.md;
 * reuses fs-outbound's SENSITIVE_PATHS as the single curated prefix source.
 */
import { withoutGrepExclusions } from "./exclusion-flags.js";
import { homedir } from "os";
import { isAbsolute, resolve as resolvePath } from "path";
import { SENSITIVE_PATHS, normalizeFsPath } from "./fs-outbound.js";
import type { LabelDecision } from "./path-labels.js";
import type { ValueRule } from "./value-bindings.js";
import {
  type ConfidentialityLevel,
  isSecret,
  maxConfidentiality,
} from "../symbol-table/confidentiality.js";

export interface SecretCatalogMatch {
  level: ConfidentialityLevel;
  /** Per-datum bound destinations granted by the rule (§2). Phase A ships
   * none — bindings arrive per datum via egress approvals (Plan 2) and the
   * labeling UI (Phase B). The field exists so rules CAN carry them. */
  bindings: string[];
  /** Which catalog rule matched, for audit/events. null = no match. */
  rule: string | null;
  /** A user `extract` regex from the deciding label (plan 10 §2.4). */
  extract?: string;
  /** Plan 13 §5.2: the deciding HUMAN label's `values:` and its declared
   *  `bindings` (`bindings` above is then the whole file's, the narrower
   *  intersection). Never set from a derived or catalog verdict. */
  values?: ValueRule[];
  fileBindings?: string[];
}

const NO_MATCH: SecretCatalogMatch = { level: "public", bindings: [], rule: null };

/** The rule of the catalog's CONTENT tier (found-labels.ts, 2026-10-19,
 *  secret-discovery.md §2.6): a config file the launch walk read and found a
 *  credential in. Decided by a found label through the label lookup, never
 *  by `secretPathConfidentiality` (which reads no file). */
export const CONTENT_RULE = "content:secret-key";

/** The rule of the content tier's PERSONAL DOCUMENTS (personal-documents.ts,
 *  2026-10-19, secret-discovery.md §2.7): a text document the launch walk
 *  read and found to be a statement, a payslip, a tax return, a lab report,
 *  an identity document or household codes. Decided by a found label of
 *  kind `document`, which carries the document twin's `extract`. */
export const DOCUMENT_RULE = "content:personal-document";

/** Is `rule` one of the content tier's (a found label decides it)? */
export function isContentRule(rule: string | null): boolean {
  return rule === CONTENT_RULE || rule === DOCUMENT_RULE;
}

/** Prefix entries → no-model. Reuses the curated fs-outbound deny-list
 * (single source of truth) + credential stores its narrower job (exfil
 * staging paths) omits. Exported for the launcher's Windows-profile list
 * (launcher/src/wsl.ts `WINDOWS_PROFILE_SECRET_PATHS`, parity-tested in
 * tests/stack `windows-profile-secrets-parity`). */
export const SECRET_PREFIXES: readonly string[] = [
  ...SENSITIVE_PATHS,
  "~/.local/share/keyrings",
  "~/.password-store",
  // Where developer tools keep their login state, from the catalog recall
  // audit (docs/design/confidentiality/secret-discovery.md §2; the corpus is
  // test/fixtures/credential-corpus.ts). Home-anchored: a project file of
  // the same name (a `.npmrc` with `engine-strict=true`) is usually not a
  // credential, and a whole-file twin of it would break the tool.
  // databases and object stores
  "~/.pgpass", "~/.my.cnf", "~/.boto", "~/.s3cfg", "~/.databrickscfg", "~/.snowflake",
  "~/.config/rclone",
  // package registries
  "~/.npmrc", "~/.yarnrc.yml", "~/.pypirc", "~/.config/pip", "~/.pip",
  "~/.config/composer/auth.json", "~/.composer/auth.json",
  "~/.m2/settings.xml", "~/.m2/settings-security.xml", "~/.gradle/gradle.properties",
  "~/.nuget/NuGet/NuGet.Config", "~/.terraformrc",
  // clouds and clusters
  "~/.azure", "~/.oci", "~/.aliyun", "~/.config/doctl", "~/.config/hcloud",
  "~/.config/openstack", "~/.config/containers/auth.json", "~/.config/helm/registry",
  "~/.vault-token", "~/.config/sops",
  // source hosting
  "~/.config/glab-cli", "~/.config/hub",
  // platforms and SaaS CLIs
  "~/.local/share/com.vercel.cli", "~/.config/netlify", "~/.config/.wrangler", "~/.wrangler",
  "~/.fly", "~/.supabase", "~/.config/stripe", "~/.config/configstore", "~/.config/ngrok",
  "~/.ngrok2", "~/.circleci/cli.yml", "~/.sentryclirc", "~/.kaggle", "~/.huggingface",
  "~/.cache/huggingface/token", "~/.cache/huggingface/stored_tokens",
  "~/.config/github-copilot", "~/.config/op", "~/.op",
  // (OpenCode's own data directory, `~/.local/share/opencode`, comes in with
  // SENSITIVE_PATHS, as `~/.claude` and `~/.codex` do; a custom
  // XDG_DATA_HOME is covered by OPENCODE_DATA_SHAPE_RE below; Goose's
  // `~/.local/share/goose` and `~/.local/state/goose` the same way, with
  // GOOSE_DATA_SHAPE_RE.)
  // The same stores where a WINDOWS profile keeps them (WSL: secret discovery
  // walks each /mnt/<drive>/Users/<name> with that profile as the home,
  // confidentiality.md §7.2 "WSL2"). The rest of this list is already
  // spelled the same under %USERPROFILE% (.aws, .ssh, .kube, .azure, …).
  // Inert on a Linux home, which has no such paths.
  "~/_netrc",
  "~/AppData/Roaming/gcloud", "~/AppData/Roaming/GitHub CLI", "~/AppData/Roaming/rclone",
  "~/AppData/Roaming/pip", "~/AppData/Roaming/Composer/auth.json", "~/AppData/Roaming/NuGet/NuGet.Config",
  "~/AppData/Roaming/terraform.rc", "~/AppData/Roaming/doctl", "~/AppData/Roaming/postgresql/pgpass.conf",
  "~/AppData/Roaming/helm/registry", "~/AppData/Roaming/sops", "~/AppData/Roaming/com.vercel.cli",
];

/** Committed-template basenames that must NOT match their secret shape. */
const SHAPE_EXCEPTIONS = new Set([
  ".env.example", ".env.template", ".env.sample",
  "secrets.example.json",
]);

/** A template by name (`secrets.example.yaml`, `prod.env.sample`): never a
 *  secret shape, whatever else the name says. */
const TEMPLATE_NAME_RE = /[._-](example|sample|template|dist|tmpl)([._-]|$)/i;

/** Extensions of DATA files; the `*secret*` shape fires only on these (or on
 *  an extension-less name that ENDS in secret(s): `jwt-secret`, `client_secret`),
 *  so `secrets.ts`, `secret_manager.py` and a doc named `…-secrets-…` stay out. */
const SECRET_DATA_EXT_RE = /\.(json|ya?ml|toml|tfvars|env|ini|conf|cfg|properties|xml|txt)$/i;

/** Extensions of DOCUMENTATION pages; the `*credentials*` shape skips them,
 *  so a page ABOUT credentials (the Linux kernel's
 *  `Documentation/security/credentials.rst`) is not a credential file. A
 *  page that does hold one is labelled in policy.yaml (a label wins over the
 *  catalog, §6). `.txt` stays in: `credentials.txt` is a common store. */
const DOC_EXTS = ["md", "markdown", "rst", "html", "htm"] as const;

/**
 * Extensions of PROGRAM SOURCE (2026-10-17, secret-discovery.md §1.12); the
 * `*credentials*` shape skips them too. A project names a module after what
 * it handles (`src/auth/providers/credentials.ts`, `botocore/credentials.py`,
 * `CredentialsProvider.java`), and a file a compiler, a bundler or a test
 * runner reads must not be a placeholder. Only languages whose files are
 * compiled or run as PROGRAMS: no shell script (`credentials.sh` is a file a
 * user sources to set AWS_* or a token: a store in practice), and no data or
 * configuration format (`json`, `yaml`, `toml`, `ini`, `conf`, `cfg`, `env`,
 * `properties`, `xml`, `txt`, `tfvars`, `plist`, an encrypted
 * `credentials.yml.enc`, no extension at all), each of which holds the
 * credential itself. A key pasted into a source file is not lost: the
 * workspace scan reads it (secret-workspace-scan.ts, which never opens a
 * file the catalog covers, so it never read these before), a human label
 * still wins (`pathConfidentiality` reads it first), a catalog PREFIX still
 * covers a source-named file under it (`~/.aws/credentials.py`), and a value
 * registered elsewhere still masks at the model (the value backstop). The
 * other shapes need no such list: `*secret*` fires on data extensions only,
 * and the rest name data files (secret-catalog.test.ts checks every shape
 * against this list).
 */
export const SOURCE_EXTS = [
  "ts", "tsx", "mts", "cts", "js", "jsx", "mjs", "cjs", "vue", "svelte",
  "py", "pyi", "rb", "php", "go", "rs", "java", "kt", "kts", "scala", "groovy",
  "swift", "m", "mm", "c", "h", "cc", "cpp", "cxx", "hh", "hpp", "cs", "fs",
  "dart", "lua", "ex", "exs", "erl", "hs", "clj", "zig",
] as const;

/** The name suffixes (`.<ext>`) the `*credentials*` shape never matches:
 *  documentation pages and program source. ONE list: the shape's own test
 *  reads it, and its anchor ships it to the guard (`NameAnchor.notSuffixes`),
 *  so the walk, `labelledLevel` and the guard's prefilter agree. */
const CREDENTIALS_NOT_SUFFIXES: readonly string[] = [...DOC_EXTS, ...SOURCE_EXTS].map((x) => `.${x}`);

/**
 * A NECESSARY condition on a file name for a basename shape to match: the
 * guard's prefilter (2026-10-17, confidentiality.md §6 "Read by a program the
 * launch did not see"), which spares a name no shape can match the round trip
 * to the arbiter. Every condition given must hold (`ci`: ASCII case folded,
 * which is all a non-`u` JavaScript `i` flag folds for an ASCII pattern).
 * Never the matcher: the shape's own `test` decides, in the arbiter.
 */
export interface NameAnchor {
  exact?: string;
  prefix?: string;
  suffix?: string;
  contains?: string;
  /** The name ends in NONE of these (the `*credentials*` shape's documentation
   *  and source extensions, 2026-10-17). No condition by itself: an anchor
   *  with nothing else is malformed, and the guard admits no name by it. */
  notSuffixes?: readonly string[];
  ci?: boolean;
}

/** Does `name` meet every condition of `a`? Pure; the guard's
 *  `label_index::NameAnchor::admits` is the same test. */
export function nameAnchorAdmits(a: NameAnchor, name: string): boolean {
  const n = a.ci ? name.replace(/[A-Z]/g, (c) => c.toLowerCase()) : name;
  const f = (s: string): string => (a.ci ? s.replace(/[A-Z]/g, (c) => c.toLowerCase()) : s);
  if (a.exact !== undefined && n !== f(a.exact)) return false;
  if (a.prefix !== undefined && !n.startsWith(f(a.prefix))) return false;
  if (a.suffix !== undefined && !n.endsWith(f(a.suffix))) return false;
  if (a.contains !== undefined && !n.includes(f(a.contains))) return false;
  if (a.notSuffixes !== undefined && a.notSuffixes.some((x) => n.endsWith(f(x)))) return false;
  return true;
}

/** The `*credentials*` shape IS its anchor: the name holds `credentials` (any
 *  ASCII case, as `/credentials/i`) and ends in no documentation or source
 *  extension. So the guard's prefilter is exact for it (a `credentials.ts`
 *  costs no round trip), and a guard that predates `notSuffixes` asks and
 *  gets the same answer (`labelledLevel`: public). */
const CREDENTIALS_ANCHOR: NameAnchor = { contains: "credentials", notSuffixes: CREDENTIALS_NOT_SUFFIXES, ci: true };

const SECRET_DATA_EXTS = ["json", "yaml", "yml", "toml", "tfvars", "env", "ini", "conf", "cfg", "properties", "xml", "txt"] as const;

/** The names a CLI gives the file it keeps its login in, inside a directory
 *  of its own (`shape:tool-login-file`, 2026-10-19, secret-discovery.md
 *  §2.6): `auth.json` (Codex, Composer, Vercel's old `~/.now`, a hosting
 *  platform's project `.launchdeck/`), its YAML and TOML forms, Gemini CLI's
 *  and Qwen Code's `oauth_creds.json`, and a bare `access-token` file
 *  (PlanetScale, Supabase). */
const TOOL_LOGIN_NAME_RE = /^(?:auth\.(?:json|ya?ml|toml)|oauth_creds\.json|access[-_]token)$/i;

/** A directory that is a tool's own: a dot-directory (`.launchdeck`,
 *  `~/.railway`), or a directory right under a `.config` (`~/.config/turso`).
 *  `.` and `..` are no names. Pure. */
function toolDirectory(parent: string, grand: string): boolean {
  return (parent.length > 1 && parent.startsWith(".") && parent !== "..") || grand === ".config";
}

/** Basename shapes → no-model wherever the file lives (a key copied
 * into the workspace is still a key). Matched on the final path segment,
 * and for a shape that says so on its parent (`parent`) and grandparent
 * (`grand`) directory names too ("" where the path has none).
 * `anchors`: the shape's prefilter (`NameAnchor`), on the name alone; a
 * name the shape matches meets one of them (secret-catalog.test.ts checks
 * it over a corpus). */
const SECRET_BASENAME_SHAPES: ReadonlyArray<{
  rule: string;
  test: (base: string, parent: string, grand: string) => boolean;
  anchors: readonly NameAnchor[];
}> = [
  { rule: "shape:.env*", test: (b) => b === ".env" || b.startsWith(".env."), anchors: [{ exact: ".env" }, { prefix: ".env." }] },
  { rule: "shape:*credentials*", test: (b) => nameAnchorAdmits(CREDENTIALS_ANCHOR, b), anchors: [CREDENTIALS_ANCHOR] },
  { rule: "shape:secrets*.json", test: (b) => /^secrets.*\.json$/.test(b), anchors: [{ prefix: "secrets", suffix: ".json" }] },
  { rule: "shape:ssh-private-key", test: (b) => /^id_(rsa|dsa|ecdsa|ed25519)$/.test(b), anchors: ["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"].map((exact) => ({ exact })) },
  { rule: "shape:*.keytab", test: (b) => b.endsWith(".keytab"), anchors: [{ suffix: ".keytab" }] },
  // From the catalog recall audit (secret-discovery.md §2).
  { rule: "shape:*.env", test: (b) => b.endsWith(".env") || b === ".envrc", anchors: [{ suffix: ".env" }, { exact: ".envrc" }] },
  {
    rule: "shape:*secret*", test: (b) => /secret/i.test(b) && (SECRET_DATA_EXT_RE.test(b) || /(^|[-_])secrets?$/i.test(b)),
    anchors: [...SECRET_DATA_EXTS.map((x) => ({ contains: "secret", suffix: `.${x}`, ci: true })), { suffix: "secret", ci: true }, { suffix: "secrets", ci: true }],
  },
  {
    rule: "shape:private-key-file", test: (b) => /\.(key|p12|pfx|jks|keystore|ppk|kdbx)$/i.test(b) || /(^privkey|[._-]key)\.pem$/i.test(b),
    anchors: [...["key", "p12", "pfx", "jks", "keystore", "ppk", "kdbx"].map((x) => ({ suffix: `.${x}`, ci: true })), { suffix: "key.pem", ci: true }],
  },
  {
    rule: "shape:service-account-key", test: (b) => /service[-_]?account.*\.json$/i.test(b) || /[-_.]key\.json$/i.test(b) || b === "keyfile.json",
    anchors: [{ contains: "account", suffix: ".json", ci: true }, { suffix: "key.json", ci: true }, { exact: "keyfile.json" }],
  },
  { rule: "shape:*.tfstate", test: (b) => /\.tfstate(\.backup)?$/.test(b), anchors: [{ contains: ".tfstate" }] },
  // 2026-10-19 (secret-discovery.md §2.6): a CLI's login file in its own
  // directory, in a project (`.launchdeck/auth.json`) or in HOME
  // (`~/.gemini/oauth_creds.json`, `~/.config/planetscale/access-token`).
  // Never by the name alone: `locales/en/auth.json` is an app's strings.
  {
    rule: "shape:tool-login-file", test: (b, parent, grand) => TOOL_LOGIN_NAME_RE.test(b) && toolDirectory(parent, grand),
    anchors: [
      ...["auth.json", "auth.yaml", "auth.yml", "auth.toml", "oauth_creds.json", "access-token", "access_token"].map((exact) => ({ exact, ci: true })),
    ],
  },
  // The JetBrains HTTP Client's private environment file (and any
  // `*.private.env.json`): where its convention says the passwords and
  // tokens of each environment go, kept out of version control.
  { rule: "shape:*.private.env.json", test: (b) => /\.private\.env\.json$/i.test(b), anchors: [{ suffix: ".private.env.json", ci: true }] },
];

/** Every basename shape's anchors, without repeats: what the arbiter ships
 *  the guard as its catalog prefilter (`labelRootsSince`). The catalog's
 *  PREFIXES go as roots of their own (secret-discovery.ts `catalogGateRoots`);
 *  the agents' data shapes (OPENCODE_DATA_SHAPE_RE, GOOSE_DATA_SHAPE_RE) are
 *  never gated (the agent's own files). */
export function catalogNameAnchors(): NameAnchor[] {
  const seen = new Set<string>();
  const out: NameAnchor[] = [];
  for (const s of SECRET_BASENAME_SHAPES) {
    for (const a of s.anchors) {
      const k = JSON.stringify(a);
      if (!seen.has(k)) { seen.add(k); out.push(a); }
    }
  }
  return out;
}

/** The anchors' soundness check: the rules of the shapes that match `base`
 *  although none of their own anchors admits it (empty: sound). A shape
 *  that reads the directories is tried in a tool's own directory, where it
 *  matches most. Pure. */
export function unanchoredShapes(base: string): string[] {
  return SECRET_BASENAME_SHAPES.filter((s) => s.test(base, ".tool", ".config") && !s.anchors.some((a) => nameAnchorAdmits(a, base))).map((s) => s.rule);
}

/** One or two real-world names per basename shape above, plus near-variants:
 *  what `patternTargetsCatalogSecret` probes a pattern's file-name segment
 *  with. A probe list, not the catalog: the shapes' own `test` stays the rule. */
const SHAPE_SAMPLE_NAMES: readonly string[] = [
  ".env", ".env.local", ".env.production",
  "credentials", "credentials.json", "aws_credentials", "Credentials.xml",
  "secrets.json", "secrets.local.json",
  "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
  "krb5.keytab", "service.keytab",
  "prod.env", ".envrc", "secrets.yaml", "client_secret.json", "server.key", "privkey.pem",
  "client.p12", "release.jks", "service-account.json", "sa-key.json", "terraform.tfstate",
];

/**
 * REPORTING ONLY (the locked-files surface's DECLASSIFIED flag): does a
 * below-strict PATTERN label aim at files the catalog calls no-model?
 * A pattern names a class of files, so there is no single catalog verdict to
 * compare with (what `declassifies` does for a literal path). Two cheap, sound-
 * for-what-they-claim probes instead: the pattern's literal prefix sits under a
 * catalog prefix (`~/.ssh/*`), or its final file-name segment matches a
 * catalog-shaped name (`**` + `/.env*`, `*credentials*`). A pattern that names a
 * whole directory (`contracts/**`) is NOT flagged for the `.env` that might sit
 * inside it: that is parity with a literal directory label, which is judged on
 * the directory's own path. Heuristic by construction: a miss leaves the flag
 * off, never a decision wrong (`pathLevel.rule` holds the per-file truth).
 */
export function patternTargetsCatalogSecret(
  glob: { literalPrefix: string },
  lastSegmentMatches: (name: string) => boolean | null,
  home: string = homedir(),
): boolean {
  if (glob.literalPrefix !== "" && secretPathConfidentiality(glob.literalPrefix + "/x", home).rule?.startsWith("prefix:")) return true;
  return SHAPE_SAMPLE_NAMES.some((n) => !SHAPE_EXCEPTIONS.has(n) && lastSegmentMatches(n) === true);
}

/**
 * The catalog prefixes (normalized) that lie strictly UNDER `dir`. The walk
 * prunes cache directories wholesale (`~/.cache`); a credential the catalog
 * names inside one (`~/.cache/huggingface/token`) is visited by this list.
 */
export function catalogPrefixesUnder(dir: string, home: string = homedir()): string[] {
  const d = normalizeFsPath(dir, home);
  return normalizedPrefixes(home).filter((p) => p.startsWith(d + "/"));
}

function underPrefix(p: string, prefix: string): boolean {
  return p === prefix || p.startsWith(prefix + "/");
}

/**
 * The catalog prefixes normalized for ONE home, computed once per home. This
 * matcher runs on every entry of the secret-discovery walk (140k entries of a
 * developer HOME at depth 4); re-normalizing the ~20 prefixes per path cost
 * 35 us a path, 5 s of every `mandu` launch (measured 2026-09-17). The memo
 * is keyed on the home string, so tests that pass different homes stay exact.
 */
const normalizedPrefixesByHome = new Map<string, readonly string[]>();
/** Exported for the memo's unit test (secret-catalog.test.ts), which pins the
 *  memo itself instead of timing it. */
export function normalizedPrefixes(home: string): readonly string[] {
  let list = normalizedPrefixesByHome.get(home);
  if (!list) {
    list = SECRET_PREFIXES.map((entry) => normalizeFsPath(entry, home));
    normalizedPrefixesByHome.set(home, list);
  }
  return list;
}

/**
 * Files directly in `~/.ssh` that hold only PUBLIC material: host keys and
 * host names (`known_hosts`), the public keys allowed to log in or sign
 * (`authorized_keys`, `allowed_signers`), and public keys (`*.pub`). None is
 * a credential, so the `~/.ssh` prefix does not label them (2026-10-02,
 * plan 10 §11.13): a whole-file twin of `known_hosts` made every host
 * unknown to ssh, and ssh writes new host keys there. They stay on
 * fs-outbound's SENSITIVE_PATHS (a tool's read or write of them asks) and
 * `authorized_keys` on the write-protect list (write-protection.md): what
 * guards them is integrity of the file, not secrecy of its text. A user
 * label still wins (pathConfidentiality reads the label first).
 */
const SSH_PUBLIC_FILE_RE = /^(known_hosts2?|known_hosts\.old|authorized_keys2?|allowed_signers|[^/]+\.pub)$/;

const sshDirByHome = new Map<string, string>();
function isSshPublicFile(p: string, home: string): boolean {
  let dir = sshDirByHome.get(home);
  if (dir === undefined) { dir = normalizeFsPath("~/.ssh", home); sshDirByHome.set(home, dir); }
  if (!p.startsWith(dir + "/")) return false;
  const rest = p.slice(dir.length + 1);
  return !rest.includes("/") && SSH_PUBLIC_FILE_RE.test(rest);
}

/**
 * OpenCode's data files wherever XDG_DATA_HOME puts them (the prefix above
 * covers the default `~/.local/share/opencode`): the shell output files of
 * OpenCode 2 (`…/opencode/shell/<40 hex>/…`, or anything under a
 * `…/share/opencode/shell` directory) and the session database of either
 * generation (`…/opencode/opencode.db`, its `-wal`, `-shm`, `-journal`).
 * The arbiter does not know the agent's XDG_DATA_HOME; these shapes are
 * specific enough to match there and nowhere else in practice. A path the
 * shape matches is never twinned either (secret-discovery.ts
 * `isAgentAuthPath`).
 */
export const OPENCODE_DATA_SHAPE_RE =
  /(?:\/opencode\/shell\/[0-9a-f]{40}(?:\/|$)|\/share\/opencode\/shell(?:\/|$)|\/opencode\/opencode\.db(?:-wal|-shm|-journal)?$)/;

/**
 * Goose's data and state files wherever its paths put them (the prefixes
 * `~/.local/share/goose` and `~/.local/state/goose` cover the defaults;
 * supported-agents.md §5.6.2). Goose 1.53.0 (config/paths.rs) keeps its data
 * in `$XDG_DATA_HOME/goose` and its state in `$XDG_STATE_HOME/goose`, or,
 * under an absolute GOOSE_PATH_ROOT, in `<root>/data` and `<root>/state`
 * (no `goose` segment); on macOS in an Application Support directory whose
 * name ends in `goose`. The shapes:
 *   - the session store: `…/sessions/sessions.db` (its `-wal`, `-shm`,
 *     `-journal`) under a `…goose` or `data` directory, and the older
 *     per-session `…goose/sessions/<id>.jsonl` files;
 *   - the request log: `…/logs/llm_request.<n or uuid>.jsonl` under a
 *     `…goose` or `state` directory (providers/utils.rs: every request
 *     whole, before the model proxy symbolizes it);
 *   - the CLI logs and the prompt history under a `…goose` directory
 *     (`logs/cli/…`, `history.txt`).
 * Specific enough to match there and nowhere else in practice; a path the
 * shape matches is never twinned either (secret-discovery.ts
 * `isAgentAuthPath`).
 */
export const GOOSE_DATA_SHAPE_RE =
  /(?:\/(?:[^/]*goose|data)\/sessions\/sessions\.db(?:-wal|-shm|-journal)?$|\/[^/]*goose\/sessions\/[^/]+\.jsonl$|\/(?:[^/]*goose|state)\/logs\/llm_request\.[^/]+\.jsonl$|\/[^/]*goose\/logs\/cli(?:\/|$)|\/[^/]*goose\/history\.txt$)/;

/** Classify one filesystem path against the catalog. */
export function secretPathConfidentiality(
  rawPath: string,
  home: string = homedir(),
): SecretCatalogMatch {
  const p = normalizeFsPath(rawPath, home);
  if (p === "") return NO_MATCH;
  if (isSshPublicFile(p, home)) return NO_MATCH;
  const prefixes = normalizedPrefixes(home);
  for (let i = 0; i < SECRET_PREFIXES.length; i++) {
    if (underPrefix(p, prefixes[i]!)) {
      return { level: "no-model", bindings: [], rule: `prefix:${SECRET_PREFIXES[i]}` };
    }
  }
  if (OPENCODE_DATA_SHAPE_RE.test(p)) return { level: "no-model", bindings: [], rule: "shape:opencode-data" };
  if (GOOSE_DATA_SHAPE_RE.test(p)) return { level: "no-model", bindings: [], rule: "shape:goose-data" };
  const base = p.slice(p.lastIndexOf("/") + 1);
  if (SHAPE_EXCEPTIONS.has(base) || TEMPLATE_NAME_RE.test(base)) return NO_MATCH;
  const segs = p.split("/");
  const parent = segs.length >= 2 ? segs[segs.length - 2]! : "";
  const grand = segs.length >= 3 ? segs[segs.length - 3]! : "";
  for (const shape of SECRET_BASENAME_SHAPES) {
    if (shape.test(base, parent, grand)) {
      return { level: "no-model", bindings: [], rule: shape.rule };
    }
  }
  return NO_MATCH;
}

/**
 * Resolve a path against the LABEL stores: the user labeling store (Plan 6,
 * path-labels.ts) and — folded in by the arbiter's composed lookup — the derived
 * taint store (Plan 9, derived-labels.ts). Injected, not imported: the derivation
 * stays a PURE function of its inputs so it remains unit-testable as an oracle
 * (tests pass a map; the arbiter server passes the live stores). Returning null
 * means "no label" — fall through to the catalog.
 *
 * `roots` (2026-10-17): where the labels above `public` lie, for reading a
 * relative token whose directory the scan does not know
 * (`findSecretPathsInText`). The arbiter's live lookup carries it
 * (label-lookup.ts `labelRoots`); a lookup without it reads such a token
 * as written and at the start directory only, and never takes the
 * precaution of an unresolved directory change.
 */
export type LabelLookup = ((path: string) => LabelDecision | null) & {
  roots?: () => readonly LabelRoot[];
};

/** A place a label above `public` covers, as the text scan reads it
 *  (`findSecretPathsInText`, 2026-10-17). */
export interface LabelRoot {
  /** Absolute and normalized: the labelled file or directory, or a
   *  pattern's literal directory prefix (`/` when it has none). */
  path: string;
  level: ConfidentialityLevel;
  /** A pattern that matches below `path` at any depth (its part after the
   *  prefix starts with `**`): a token read in any directory inside `path`
   *  may match it, so that reading is tried too. */
  anyDepth?: boolean;
  /** A pattern's own matcher (an absolute path → whether the pattern
   *  covers it); absent for a literal path, which covers itself and what
   *  lies below it. */
  matches?: (absPath: string) => boolean;
}

/**
 * The AUTHORITATIVE level for ONE path: the user label if there is one, else
 * the catalog (§6 — the catalog is the zero-config DEFAULT; an explicit human
 * label overrides it, in either direction) — RAISED by a derived taint label if
 * a high session wrote this file (§8; a machine may taint, never declassify).
 * Absent a lookup this is exactly `secretPathConfidentiality`, byte for byte —
 * every pre-Plan-6 caller is unaffected.
 */
export function pathConfidentiality(
  rawPath: string,
  home: string = homedir(),
  resolveLabel?: LabelLookup,
): SecretCatalogMatch {
  const label = resolveLabel?.(rawPath);
  if (!label) return secretPathConfidentiality(rawPath, home);

  // A FOUND label (found-labels.ts): the catalog's content tier, `no-model`
  // and bound nowhere. The lookup gives it only where no human label speaks
  // (a human label overrides it as it overrides the catalog); nothing a
  // machine records is stricter, so a path rule of the catalog on the same
  // file (same level) keeps its own name.
  if (label.origin === "found") {
    const base = secretPathConfidentiality(rawPath, home);
    if (base.rule !== null && maxConfidentiality(base.level, label.level) === base.level) return base;
    // A personal document (§2.7) carries the document twin's `extract`
    // (label-lookup.ts `foundLabel`): its labels stay, its values are
    // placeholders.
    if (label.extract !== undefined) return { level: label.level, bindings: [], rule: DOCUMENT_RULE, extract: label.extract };
    return { level: label.level, bindings: [], rule: CONTENT_RULE };
  }

  if (label.origin !== "derived") {
    // A HUMAN label. Including a `public` one on a catalog-matching path: that is
    // the override, and it is the whole point of the store. The caller reports it
    // as a declassification (§6's visible standing surface).
    return {
      level: label.level, bindings: label.bindings, rule: `label:${label.via}`,
      ...(label.extract ? { extract: label.extract } : {}),
      ...(label.values && label.fileBindings ? { values: label.values, fileBindings: label.fileBindings } : {}),
    };
  }

  // A DERIVED label (Plan 9, §8): the record that a HIGH session wrote this file.
  // It RAISES the base verdict; it never lowers it — a machine may taint, never
  // declassify. When no human label covers the path, the base is the CATALOG, and
  // it still gets its say: `model-ok` derived over a `no-model` catalog path
  // (a key, a `.env`) must stay strict, or this feature would be a machine-
  // authored declassification of a credential. (When a human label DOES cover the
  // path, the resolver has already folded it in and suppressed the catalog, as
  // any human label does.)
  if (!label.overridesCatalog) {
    const base = secretPathConfidentiality(rawPath, home);
    if (maxConfidentiality(base.level, label.level) === base.level) return base;
  }
  return { level: label.level, bindings: label.bindings, rule: `derived:${label.via}` };
}

/** Shell-ish token separators for the conservative text scan. */
const TEXT_TOKEN_SPLIT = /[\s;|&<>()]+/;

/** What a caller knows about where a text's tokens are read. */
export interface ScanOptions {
  /** Read as if the text changed directory. */
  movesDirectory?: boolean;
  /** Absolute directories the text may also be read in (an unmapped
   *  tool's `cwd`): its relative tokens are read there too, labels only,
   *  raise-only, and none is placed on a file. */
  extraBases?: readonly string[];
  /** Directories, as written, the text's tool works in (a relative
   *  honoured `workdir`, an unmapped tool's relative `cwd`): read as the
   *  targets of a `cd` (`candidateDirs`). */
  targets?: readonly string[];
}

/** Scan free text (a Bash command, an origin hint) for catalog-matching path
 * references. Token-based and conservative: every token is checked as a
 * candidate path (relative shapes like `.env` included).
 *
 * With a `resolveLabel` lookup, every token is ALSO checked against the user
 * labels, so `cat ~/contracts/q3.pdf` picks up a `model-ok` label on a path the
 * catalog knows nothing about.
 *
 * A RELATIVE token and the label store (2026-10-04). The store is keyed by
 * ABSOLUTE paths (a relative path has no stable identity), while the catalog
 * also matches relative shapes. So without a base directory a user `public`
 * label on `/proj/test/fixtures/.env` does NOT suppress the catalog hit on
 * the token `test/fixtures/.env` in a shell command: that classifies
 * no-model, over-restriction and never a leak. With `baseDir` (the directory
 * the command runs in, which the call names: Codex's `exec_command`
 * `workdir`; or, for Claude Code's `Bash`, which names none, the directory
 * the kernel says the call's shell started in; see `callWorkdir` and
 * `labelForClassify`) a relative token is also read as
 * `baseDir/<token>`, and a HUMAN label there decides it as it decides a
 * `Read` of that path, in either direction. Only where the base is known to
 * be the directory the token is read in: never for a command that may
 * change directory (`directoryMayChange`), nor for a token that is a flag,
 * a glob or an expansion. Without a human label the stricter of the two
 * readings stands (raise-only). Every other token keeps its own verdict, so
 * a command that also names another secret stays masked.
 *
 * A directory change only RAISES (2026-10-17). Where the scan cannot place
 * a token exactly (the command may change directory, or no base is known),
 * a label must still be able to raise it, or `cd . && cat vault/plan.md`
 * reads `vault/plan.md` as written, matches no label, and a labelled file's
 * text reaches the model in clear. So each relative token is then also
 * read, raise-only (a `public` label there never lowers anything):
 *   - at `baseDir`, when known (the shell's directory before any `cd`);
 *   - in every directory the command's literal targets lead to
 *     (`candidateDirs`: `cd`, `pushd`, `-C`, `--directory=` and kin, an
 *     interpreter's `chdir('x')` or `cwd='x'`, resolved from the start
 *     directory, from each other, and, from an unknown directory, where a
 *     label's path ends with them), labels only;
 *   - under every label it could name from an unknown directory
 *     (`tailConfidentiality`: the token, past its leading `./` and `../`,
 *     starts with the last segments of a labelled path, as
 *     `../vault/plan.md` does for `/proj/vault`), and every place an
 *     any-depth pattern could match it;
 * each token also in the spelling the shell reads (`va""ult/plan.md`,
 * `vault\/plan.md`, a line continuation, `$PWD/x`, `$HOME/x`), and the
 * pieces of a token another reading would miss (`--chdir=vault`,
 * `-Cvault`, `HEAD:../vault/plan.md`, `'plan.md','utf8'`) labels only
 * (`subTokens`). A directory change whose target the scan cannot read at
 * all (`cd "$X"`, `cd -`, `popd`, `cd vau*`, `find -execdir`,
 * `os.chdir(d)`: `unresolvedDirChange`), or one that leads to more
 * directories than the scan follows, masks a command that also passes any
 * argument while a label stands, at the strictest label's level (the
 * precaution, rule `dir-change:unresolved`). A reading so raised places no
 * file (plan 15 §13.12); but a command that is one leading `cd` to a
 * literal folder (absolute, or relative to a known `baseDir`), then a rest
 * that changes directory no further (`leadingCdDir`), places the rest's
 * relative tokens in that folder when their reading is the token's own
 * (2026-10-19), never lifting a label there, and gives each such token's
 * file again as placed where the command started (`cdFailedFile`, for a
 * `cd` that failed: `leadingCdStart`). What stays out is indirection the command does
 * not show (a sourced file, an alias, a script that computes a path),
 * which §10.1 scopes out behind the twin layer, the call's process taint
 * and the value backstop.
 */
export function findSecretPathsInText(
  text: string,
  home: string = homedir(),
  resolveLabel?: LabelLookup,
  baseDir?: string,
  opts: ScanOptions = {},
): Array<SecretCatalogMatch & { token: string; file?: string; cdDir?: string; cdFailedFile?: string }> {
  const out: Array<SecretCatalogMatch & { token: string; file?: string; cdDir?: string; cdFailedFile?: string }> = [];
  const seen = new Set<string>();
  const known = baseDir !== undefined && resolveLabel !== undefined && isAbsolute(baseDir) ? baseDir : undefined;
  const extra = (opts.extraBases ?? []).filter((d) => isAbsolute(d));
  const targets = opts.targets ?? [];
  // A directory change also where the shell's quoting hides it (`\cd`,
  // `c""d`) or in code the command runs (`os.chdir(`): the same test that
  // stops PLACING a token on a file (plan 15 §13.12), now that a change
  // of directory only ever raises (2026-10-17).
  const moves = opts.movesDirectory === true || targets.length > 0 || directoryMayChange(text);
  // The exact reading, where a human label decides in either direction and
  // a relative token is placed on its file.
  const liftBase = known !== undefined && !moves ? known : undefined;
  // A leading `cd` to one literal directory (`leadingCdDir`: absolute, or
  // relative to the start directory): where the rest's relative tokens are
  // PLACED on files (plan 15 §13.12), never where a label is read exactly
  // (its readings stay raise-only, below).
  const cdBase = liftBase === undefined && extra.length === 0 && targets.length === 0 && opts.movesDirectory !== true ? leadingCdDir(text, baseDir) : undefined;
  // …and where they run if that `cd` fails (the shell's start directory:
  // `;` or a line break runs the rest anyway; plan 15 §13.12, "A cd that
  // fails"): the alternative placement, chosen only by the arbiter, only
  // when the folder is not there when the mark is learned.
  const cdStart = cdBase !== undefined ? leadingCdStart(baseDir) : undefined;
  const index = resolveLabel !== undefined ? lazyRootIndex(resolveLabel) : undefined;
  // Where a token is read is not known for certain: every label it could name.
  const tails = liftBase === undefined ? index : undefined;
  // (an unmapped tool's own absolute directory is always one of them)
  const places = moves && tails !== undefined ? candidateDirs(text, known, extra, targets, tails, home) : { dirs: [...extra], over: false };
  // The precaution (below) first: when it stands, the level is already the
  // strictest any label could give, and the readings that only look for a
  // label elsewhere are skipped (they cost a lookup per token per place).
  const precaution = moves && tails !== undefined && tails().top !== null &&
    (places.over || targets.some((t) => unreadableTarget(t)) || unresolvedDirChange(text)) && hasArgumentWord(text);

  /** A raise-only reading of one absolute path: the full lookup only where
   *  a label above `public` may cover it or the catalog names it. */
  const readAt = (abs: string, labelsOnly: boolean): SecretCatalogMatch => {
    if (index !== undefined && !index().covers(abs)) {
      if (labelsOnly || secretPathConfidentiality(abs, home).rule === null) return NO_MATCH;
    }
    const m = pathConfidentiality(abs, home, resolveLabel);
    return labelsOnly ? labelOnly(m) : m;
  };
  let deep = 0;
  /** The raise-only readings of a relative token (labels only when asked). */
  const raises = (token: string, labelsOnly: boolean): SecretCatalogMatch => {
    let m = NO_MATCH;
    if (resolveLabel === undefined || !isResolvableRelativeToken(token)) return m;
    const take = (r: SecretCatalogMatch): void => {
      if (isSecret(r.level)) m = stricter(m, r);
    };
    // at the start directory (where the base is exact, the placed reading is this one)
    if (known !== undefined && (liftBase === undefined || labelsOnly)) take(readAt(resolvePath(known, token), labelsOnly));
    if (precaution) return m;
    // bounded: past MAX_DEEP_TOKENS tokens the rest are not looked for
    // elsewhere, and the strictest label stands instead (below)
    if (++deep > MAX_DEEP_TOKENS) return m;
    // a token read from no known place names a path only when it looks like one
    if (tails !== undefined && (moves || /[./]/.test(token) || argWords.has(token))) take(labelsOnly ? labelOnly(tailConfidentiality(token, tails, home, resolveLabel)) : tailConfidentiality(token, tails, home, resolveLabel));
    for (const d of places.dirs) take(readAt(resolvePath(d, token), true));
    return m;
  };
  /** A glob or brace token below a literal directory (`vault/*`,
   *  `notes/*.md`, `vault/{a,b}`): the directory is read, raise-only, as
   *  covered by a label, and as holding one (any label at or below it,
   *  at that label's level). A glob with no literal directory
   *  (`*.md`, `vau*\/x`) names no place and is left to §10.1. */
  const globRaise = (token: string): SecretCatalogMatch => {
    if (index === undefined || URL_ORIGIN_RE.test(token) || token.startsWith("-") || !/[*?[\]{}]/.test(token)) return NO_MATCH;
    const lead: string[] = [];
    for (const s of token.split("/")) {
      if (/[*?[\]{}$`]/.test(s)) break;
      lead.push(s);
    }
    const prefix = lead.join("/");
    if (prefix === "~" || (prefix.startsWith("~") && !prefix.startsWith("~/"))) return NO_MATCH;
    const dirs = new Set<string>();
    // a bare name glob (`*.md`) after a change of directory: the directories
    // the command moved to (in the start directory it is §10.1's)
    if (prefix === "") for (const d of places.dirs) dirs.add(d);
    else if (prefix.startsWith("/")) dirs.add(resolvePath(prefix));
    else if (prefix.startsWith("~/")) dirs.add(resolvePath(home, prefix.slice(2)));
    else {
      if (known !== undefined) dirs.add(resolvePath(known, prefix));
      for (const d of places.dirs) dirs.add(resolvePath(d, prefix));
      if (tails !== undefined) {
        const tp = tailPlaces(prefix, tails);
        if (tp.length > MAX_TAIL_READS) {
          const level = tailLevel(prefix, tails);
          if (level !== null) return { level, bindings: [], rule: `label:${prefix}` };
        }
        for (const p of tp) dirs.add(p);
      }
    }
    let m = NO_MATCH;
    for (const d of dirs) {
      if (d === "/") continue;
      if (index().covers(d)) {
        const r = pathConfidentiality(d, home, resolveLabel);
        if (isSecret(r.level)) m = stricter(m, r);
      }
      const below = index().atOrBelow(d);
      if (below !== null) m = stricter(m, { level: below.level, bindings: [], rule: `label:${below.path}` });
    }
    return m;
  };

  // Each token as written, and as the shell reads it (`exact` false: never placed).
  const tokens: Array<{ t: string; exact: boolean }> = [];
  const joined = text.replace(/\\\r?\n/g, "");
  const spelled = withCurrentDirSpelled(joined);
  const variants = [...new Set([text, joined, spelled])];
  for (const tx of variants) {
    for (let token of tx.split(TEXT_TOKEN_SPLIT)) {
      token = token.replace(/^["']+|["']+$/g, "");
      if (token === "") continue;
      tokens.push({ t: token, exact: tx === text });
      for (const v of shellSpellings(token)) tokens.push({ t: v, exact: false });
    }
    // the words as the shell splits them: a quoted or escaped space stays
    // inside its path (`"my vault/plan.md"`, `my\ vault`)
    if (resolveLabel !== undefined) {
      for (const { w, sep } of shellWords(tx)) {
        const d = dequoted(w);
        if (sep || d === w || d === "") continue;
        tokens.push({ t: d, exact: false });
        for (const v of shellSpellings(d)) tokens.push({ t: v, exact: false });
      }
    }
  }
  // the bare words a shell command passes as arguments (`grep -r x vault`):
  // read as paths from an unknown directory too
  const argWords = tails !== undefined && !moves ? new Set(argumentWords(spelled)) : new Set<string>();
  for (const { t: token, exact } of tokens) {
    if (seen.has(token)) continue;
    seen.add(token);
    const relative = liftBase !== undefined && isResolvableRelativeToken(token);
    const placed = relative
      ? relativeTokenConfidentiality(token, liftBase, home, resolveLabel!)
      : pathConfidentiality(token, home, resolveLabel);
    let m = placed;
    if (tails !== undefined || extra.length > 0) m = stricter(m, raises(token, false));
    m = stricter(m, globRaise(token));
    if (m.rule === null) continue;
    // placed on a file only by the reading that read it there, as written,
    // and never where the tool names a directory of its own (`extra`); after
    // a leading `cd` to one absolute directory, a relative token in it
    const file = exact && m === placed ? placedTokenFile(token, relative && extra.length === 0 ? liftBase : cdBase) : undefined;
    // the same token placed as if the leading `cd` failed (an absolute one is itself)
    const cdFailedFile = file !== undefined && cdBase !== undefined ? placedTokenFile(token, cdStart) : undefined;
    out.push({
      ...m, token,
      ...(file !== undefined ? { file } : {}),
      ...(file !== undefined && cdBase !== undefined ? { cdDir: cdBase, ...(cdFailedFile !== undefined ? { cdFailedFile } : {}) } : {}),
    });
  }
  if (resolveLabel !== undefined) {
    for (const sub of subTokens(tokens.map((x) => x.t))) {
      if (seen.has(sub)) continue;
      seen.add(sub);
      const m = stricter(labelOnly(pathConfidentiality(sub, home, resolveLabel)), raises(sub, true));
      if (m.rule !== null && isSecret(m.level)) out.push({ ...m, token: sub });
    }
  }
  if (precaution) out.push({ level: tails!().top!, bindings: [], rule: "dir-change:unresolved", token: "" });
  else if (deep > MAX_DEEP_TOKENS && index !== undefined && index().top !== null) {
    out.push({ level: index().top!, bindings: [], rule: "scan:too-many-tokens", token: "" });
  }
  return out;
}

/** How many directories `candidateDirs` follows before it gives up and
 *  the precaution masks instead. */
const MAX_CANDIDATE_DIRS = 64;

/** How many places one token's tail reading reads before it takes the
 *  strictest of them unread instead. */
const MAX_TAIL_READS = 32;

/** How many distinct relative tokens of one text are looked for under
 *  every label they could name (the readings that cost a lookup per
 *  place) before the rest are not, and the strictest label stands for
 *  the text instead (rule `scan:too-many-tokens`; fail-closed, and the
 *  arbiter, single-threaded, is never held long by one command). */
const MAX_DEEP_TOKENS = 2000;

/**
 * The directories a command that changes directory may read its relative
 * tokens in (2026-10-17): each literal target (`dirTargets`, and the
 * caller's `targets`) resolved from the start directory, from the
 * `extra` bases, from each other (three rounds: `cd a; cd b`), and, as no
 * directory may be known, from the place a label's path ends with it
 * (`tailPlaces`: `notes` is `/proj/notes` for a pattern `/proj/notes/*.md`).
 * An absolute or `~` target is itself. `over` when there were more than
 * {@link MAX_CANDIDATE_DIRS}: the caller takes the precaution. Pure.
 */
function candidateDirs(
  text: string,
  known: string | undefined,
  extra: readonly string[],
  extraTargets: readonly string[],
  tails: () => RootIndex,
  home: string,
): { dirs: string[]; over: boolean } {
  const dirs = new Set<string>(extra);
  let over = false;
  const add = (d: string): void => {
    if (dirs.has(d)) return;
    if (dirs.size >= MAX_CANDIDATE_DIRS) { over = true; return; }
    dirs.add(d);
  };
  const relative: string[] = [];
  for (const raw of [...dirTargets(text), ...extraTargets]) {
    if (unreadableTarget(raw)) continue;
    const t = shellVarPath(dequoted(raw)) ?? dequoted(raw);
    if (t === "") continue;
    if (t.startsWith("/")) add(resolvePath(t));
    else if (t === "~" || t.startsWith("~/")) add(resolvePath(home, t.slice(1).replace(/^\//, "")));
    else if (t.startsWith("~")) continue; // ~user: unreadableTarget
    else {
      relative.push(t);
      for (const p of tailPlaces(t, tails)) add(p);
    }
  }
  // inside each any-depth pattern's prefix too (`cd hr` for `**\/hr/*.md`
  // with no start directory)
  for (const p of tails().anyDepth) for (const t of relative) add(resolvePath(p, t));
  // as many rounds as there are relative targets (`cd ..; cd ..; cd x`),
  // within the cap
  for (let round = 0; round < Math.max(1, relative.length) && relative.length > 0 && !over; round++) {
    const from = [...(known !== undefined ? [known] : []), ...dirs];
    const before = dirs.size;
    for (const b of from) for (const t of relative) add(resolvePath(b, t));
    if (dirs.size === before) break;
  }
  return { dirs: [...dirs], over };
}

/** Where a relative directory token could be from an unknown directory:
 *  each labelled path its segments (past leading `./` and `../`) run
 *  through to the end, joined with the rest of it. Pure. */
function tailPlaces(token: string, index: () => RootIndex): string[] {
  const segs = tokenSegments(token);
  if (segs.length === 0) return [];
  const out: string[] = [];
  const idx = index();
  const rest = segs.join("/");
  for (let k = 1; k <= segs.length; k++) {
    for (const from of idx.bySuffix.get(segs.slice(0, k).join("/")) ?? []) {
      out.push(from === "/" ? "/" + rest : from + "/" + rest);
    }
  }
  return out;
}

/** The strictest level among the labels whose path ends with the token's
 *  first segments (what {@link tailPlaces} would read, without reading). */
function tailLevel(token: string, index: () => RootIndex): ConfidentialityLevel | null {
  const segs = tokenSegments(token);
  let level: ConfidentialityLevel | null = null;
  for (let k = 1; k <= segs.length; k++) {
    const l = index().suffixLevel.get(segs.slice(0, k).join("/"));
    if (l !== undefined) level = level === null ? l : maxConfidentiality(level, l);
  }
  return level;
}

/** A relative token's segments past its leading `.` and `..` (an unknown
 *  directory's parent is as unknown), `a/../b` folded. Pure. */
function tokenSegments(token: string): string[] {
  const segs: string[] = [];
  for (const p of token.split("/")) {
    if (p === "" || p === ".") continue;
    if (p === "..") { segs.pop(); continue; }
    segs.push(p);
  }
  return segs;
}

/** A word with the shell's quoting removed: `$'…'` / `$"…"` openers,
 *  quotes and backslashes (`va""ult`, `vau\lt`, `'vault'/x`). Pure. */
function dequoted(word: string): string {
  return word
    .replace(/\$'((?:[^'\\]|\\.)*)'/g, (_m, body: string) => decodeAnsiC(body))
    .replace(/\$"/g, '"')
    .replace(/['"\\]/g, "");
}

/** The text of a `$'…'` word: its `\xHH`, `\uHHHH`, `\UHHHHHHHH` and
 *  octal escapes decoded (`$'\x63d'` is `cd`); any other escaped character
 *  stands for itself. Pure. */
function decodeAnsiC(body: string): string {
  return body.replace(/\\(x[0-9a-fA-F]{1,2}|u[0-9a-fA-F]{1,4}|U[0-9a-fA-F]{1,8}|[0-7]{1,3}|.)/g, (_m, e: string) => {
    if (/^[xuU]/.test(e)) {
      const cp = parseInt(e.slice(1), 16);
      return cp <= 0x10ffff ? String.fromCodePoint(cp) : "";
    }
    if (/^[0-7]/.test(e)) return String.fromCharCode(parseInt(e, 8));
    return ({ n: "\n", t: "\t", r: "\r", a: "\x07", b: "\b", e: "\x1b", E: "\x1b", f: "\f", v: "\v" } as Record<string, string>)[e] ?? e;
  });
}

/** The command with `$(pwd)`, `` `pwd` ``, `~+` written as `.`, and the
 *  previous directory (`~-`, `$OLDPWD`) as `.` too: one more place a token
 *  is read, raise-only (2026-10-17). Pure. */
function withCurrentDirSpelled(text: string): string {
  return text
    .replace(/\$\(\s*pwd(?:\s+-[LP])?\s*\)|`\s*pwd(?:\s+-[LP])?\s*`/g, ".")
    .replace(/\$\{?OLDPWD\}?/g, ".")
    .replace(/(^|[\s=:'"(])~[+-](?=\/|\s|$|['")])/g, "$1.");
}

/** The other spellings of a token the shell reads as one path: dequoted,
 *  and `$PWD` / `$HOME` written as `.` / `~`. Pure. */
function shellSpellings(token: string): string[] {
  const out: string[] = [];
  const d = dequoted(token);
  for (const t of d !== token ? [token, d] : [token]) {
    if (t !== token) out.push(t);
    const named = shellVarPath(t);
    if (named !== null) out.push(named);
  }
  return out;
}

/** The literal targets a command changes directory to, as written: the
 *  word after `cd`, `pushd` or `chdir` (past their options; `~` for a bare
 *  `cd`), after a `-C` (also in a cluster: `-xC`) or a `--directory`-kin
 *  flag, attached to one (`-Cx`, `--directory=x`), after `sudo -D`; and
 *  the quoted literal of an interpreter's `chdir('x')` / `chdir "x"` or a
 *  `cwd='x'` / `cwd: "x"` argument. Words, not checked: the caller drops
 *  an {@link unreadableTarget}. Pure. */
function dirTargets(text: string): string[] {
  const out: string[] = [];
  const words = shellWords(text.replace(/\\\r?\n/g, ""));
  const flag = new RegExp(`^(?:-[A-Za-z]*C|--(?:${DIR_FLAG_NAMES}))$`);
  const attached = new RegExp(`^(?:-C|--(?:${DIR_FLAG_NAMES})=)(.+)$`);
  let sudo = false;
  for (let i = 0; i < words.length; i++) {
    const { w, sep } = words[i]!;
    if (sep) { sudo = false; continue; }
    const bare = dequoted(w);
    if (bare === "sudo") sudo = true;
    const next = (j: number): string | undefined => (j < words.length && !words[j]!.sep ? words[j]!.w : undefined);
    if (bare === "cd" || bare === "pushd" || bare === "chdir") {
      let j = i + 1;
      while (next(j) !== undefined && /^(?:-[LPe@]+|--)$/.test(dequoted(next(j)!))) j++;
      const t = next(j);
      if (t !== undefined) out.push(t);
      else if (bare === "cd") out.push("~");
      continue;
    }
    const value = attached.exec(bare);
    if (value !== null) { out.push(value[1]!); continue; }
    if (flag.test(bare) || (sudo && bare === "-D")) {
      const t = next(i + 1);
      if (t !== undefined) out.push(t);
    }
  }
  for (const m of text.matchAll(/chdir\s*\(?\s*(['"])([^'"]*)\1/g)) out.push(m[2]!);
  for (const m of text.matchAll(/(?<![-\w])cwd\s*[=:]\s*(['"])([^'"]*)\1/g)) out.push(m[2]!);
  return out;
}

/** The absolute file a shell token names (plan 15 §13.12, "a path row's
 *  files"): an absolute path, or a relative one read in `base` (the
 *  directory the command is known to run in); a plain path only: no glob,
 *  no expansion, no quoting or escape left in it, no `..` segment (the
 *  kernel resolves `..` through symlinks, this lexically), no `~` (the
 *  shell's HOME may not be the arbiter's). Undefined otherwise. Pure. */
function placedTokenFile(token: string, base: string | undefined): string | undefined {
  if (/[*?[\]{}$`'"\\~]/.test(token) || URL_ORIGIN_RE.test(token) || token.startsWith("-")) return undefined;
  if (token.split("/").includes("..")) return undefined;
  if (isAbsolute(token)) return resolvePath(token);
  return base !== undefined && isAbsolute(base) ? resolvePath(base, token) : undefined;
}

/** The leading `cd <dir>` of a command (plan 15 §13.12, "A leading cd",
 *  2026-10-19): the directory the rest of `text` runs in, for PLACING its
 *  relative tokens on files, when the command is exactly `cd <dir>` then
 *  `&&`, `;` or a line break, then the rest, and:
 *    - `cd` is the first word, as written (no `\cd`, no option);
 *    - `<dir>` is one literal path (a pair of quotes around the whole of it
 *      allowed): no expansion, glob, brace, escape, `~` or `..` segment;
 *      absolute, or relative (not empty, not `-…`, `+…` or `=…`: the
 *      previous folder, zsh's directory stack, zsh's `=cmd`) and then read
 *      in `startDir`, the directory the command starts in (the kernel's
 *      for Claude Code's `Bash`, the call's absolute `workdir` or Codex's
 *      session directory: `callWorkdir`), absolute with no `..` segment;
 *      with no such `startDir`, a relative folder places nothing;
 *    - the rest may not change directory itself (`directoryMayChange`).
 *  Claude Code's own shape for a command in another folder
 *  (`cd /abs/app && ls; cat config/settings.json; cat .env`, the live c1
 *  demo under the defaults, 2026-10-18; `cd weather-app && …` for a folder
 *  below its own). The base is the one the rest runs in once the `cd`
 *  succeeded and, for a relative folder, no `CDPATH` moved it; where it is
 *  not, the narrowing it feeds fails closed or drops only what it may drop
 *  from any command (plan 15 §13.12, "A relative folder"): the arbiter
 *  narrows only when a registered file is found at each place a secret
 *  reading was put (`learnPathRow` condition 4), and drops only lines a
 *  plain file at a placed path holds (condition 5). A `cd` that failed
 *  (Claude Code's shell already in the folder, battery 2026-10-19) has the
 *  rest placed where the command started instead ({@link leadingCdStart};
 *  the arbiter's choice, when the folder is not there: "A cd that fails").
 *  Labels never read this base: a reading after a `cd` stays raise-only
 *  (`findSecretPathsInText`). Undefined otherwise. Pure. */
export function leadingCdDir(text: string, startDir?: string): string | undefined {
  const m = /^[ \t]*cd[ \t]+('[^'\n]*'|"[^"\n]*"|[^\s;&|()<>'"`]+)[ \t]*(?:&&|;|\n)([\s\S]*)$/.exec(text);
  if (m === null) return undefined;
  const dir = m[1]!.replace(/^(['"])([\s\S]*)\1$/, "$2");
  if (dir === "" || /^[-+=]/.test(dir) || /[*?[\]{}$`\\~'"]/.test(dir) || dir.split("/").includes("..")) return undefined;
  if (directoryMayChange(m[2]!)) return undefined;
  if (dir.startsWith("/")) return resolvePath(dir);
  if (startDir === undefined || !isAbsolute(startDir) || startDir.split("/").includes("..")) return undefined;
  return resolvePath(startDir, dir);
}

/** The directory the rest of a command with a leading `cd`
 *  ({@link leadingCdDir}) runs in when that `cd` FAILS (plan 15 §13.12, "A
 *  cd that fails", 2026-10-19): the directory the command starts in, when
 *  it is known (absolute, no `..` segment); undefined otherwise. After `;`
 *  or a line break the shell runs the rest anyway, and after `&&` the
 *  commands past the first `;` (Claude Code keeps its shell's directory
 *  from one call to the next, so `cd weather-app; …` from inside
 *  `weather-app` fails and prints the rest from there: the live c1 demo,
 *  battery 2026-10-19). Only the arbiter picks this placement over the
 *  folder's, and only when the folder is not there when the mark is
 *  learned. Pure. */
export function leadingCdStart(startDir?: string): string | undefined {
  if (startDir === undefined || !isAbsolute(startDir) || startDir.split("/").includes("..")) return undefined;
  return resolvePath(startDir);
}

/** Every file the plain-path tokens of `text` name (`placedTokenFile`),
 *  whatever their label: where the narrowing of a path row looks for the
 *  lines it may drop (plan 15 §13.12). A command that may change directory
 *  places only its absolute tokens, but for a leading `cd` to one literal
 *  folder ({@link leadingCdDir}: absolute, or relative to `baseDir`), whose
 *  relative tokens are placed in it, or, with `ifCdFailed`, where the
 *  command started ({@link leadingCdStart}: the placement for a `cd` that
 *  failed; a command with no leading `cd` is placed as without it). Pure. */
export function placedFilesInText(text: string, baseDir?: string, opts: { ifCdFailed?: boolean } = {}): string[] {
  const exact = baseDir !== undefined && isAbsolute(baseDir) && !directoryMayChange(text);
  const cd = exact ? undefined : leadingCdDir(text, baseDir);
  const base = exact ? baseDir : cd !== undefined && opts.ifCdFailed === true ? leadingCdStart(baseDir) : cd;
  const out = new Set<string>();
  for (let token of text.split(TEXT_TOKEN_SPLIT)) {
    token = token.replace(/^["']+|["']+$/g, "");
    if (token === "") continue;
    const f = placedTokenFile(token, base);
    if (f !== undefined) out.add(f);
  }
  return [...out].sort();
}

/** The stricter of two readings; on a tie the first (its rule and bindings
 *  stand). A reading with no rule never wins. Pure. */
function stricter(a: SecretCatalogMatch, b: SecretCatalogMatch): SecretCatalogMatch {
  if (b.rule === null) return a;
  if (a.rule === null) return b;
  return maxConfidentiality(a.level, b.level) === a.level ? a : b;
}

/** A reading a label decided (human or derived), else none: what a piece
 *  of a token may add (the catalog's shapes are read on whole tokens only,
 *  so a flag's value does not newly match one). Pure. */
function labelOnly(m: SecretCatalogMatch): SecretCatalogMatch {
  // A found label (the content tier) is keyed on one real path, as a
  // derived one is: no name of a piece matches it by chance.
  return m.rule !== null && (m.rule.startsWith("label:") || m.rule.startsWith("derived:") || isContentRule(m.rule)) ? m : NO_MATCH;
}

/** `$PWD/x`, `${PWD}/x`, `$HOME/x`, `${HOME}/x` (and the bare variables) as
 *  the path they name (`./x`, `~/x`), else null. Pure. */
function shellVarPath(token: string): string | null {
  const m = /^\$(?:\{(PWD|HOME)\}|(PWD|HOME)(?![A-Za-z0-9_]))(\/.*)?$/.exec(token);
  if (m === null) return null;
  return ((m[1] ?? m[2]) === "PWD" ? "." : "~") + (m[3] ?? "");
}

/** The pieces of each token that may name a path another reading would
 *  miss: a short flag's attached value (`-Cvault`), the parts around
 *  `=`, `:`, `,`, `@` and quotes (`--chdir=vault`, `HEAD:../x`,
 *  `'plan.md','utf8'`, `-d@x`), and their `$PWD` / `$HOME` spellings. A
 *  URL is not split. Pure. */
function subTokens(tokens: readonly string[]): string[] {
  const out: string[] = [];
  const add = (s: string): void => {
    const t = s.replace(/^["'`]+|["'`]+$/g, "");
    if (t === "") return;
    out.push(t);
    const named = shellVarPath(t);
    if (named !== null) out.push(named);
  };
  for (const token of tokens) {
    if (URL_ORIGIN_RE.test(token)) continue;
    const flag = /^-[A-Za-z](.+)$/.exec(token);
    if (flag !== null && !flag[1]!.startsWith("=")) add(flag[1]!);
    for (const piece of token.split(/[=:,@'"`]+/)) if (piece !== token) add(piece);
  }
  return out;
}

/** The labelled places, indexed for the tail reading. */
interface RootIndex {
  /** The last segments of a root path (`vault`, `proj/vault`, …) → the
   *  directories they follow (`/home/u/proj`, `/home/u`, …): a token that
   *  starts with those segments runs through that root. Keyed by the exact
   *  suffix, so a lookup costs one probe per segment of the token, however
   *  many roots share a segment name. */
  bySuffix: Map<string, Set<string>>;
  /** The strictest level of the roots ending with each suffix. */
  suffixLevel: Map<string, ConfidentialityLevel>;
  /** The strictest label at or below a directory, or null. */
  atOrBelow: (dir: string) => { path: string; level: ConfidentialityLevel } | null;
  /** The prefixes of the any-depth patterns. */
  anyDepth: readonly string[];
  /** The strictest level of any root; null when no label stands. */
  top: ConfidentialityLevel | null;
  /** Whether a label above `public` may cover an absolute path: the path
   *  is a literal root or below one, or a pattern matches it. A cheap
   *  test before the full lookup (which reads every store); a path no
   *  root covers can only meet a `public` label or none. */
  covers: (absPath: string) => boolean;
}

const ROOT_INDEX = new WeakMap<readonly LabelRoot[], RootIndex>();

/** The lookup's roots, read and indexed once, when first needed. */
function lazyRootIndex(resolveLabel: LabelLookup): () => RootIndex {
  let idx: RootIndex | undefined;
  return () => {
    if (idx !== undefined) return idx;
    const roots = resolveLabel.roots?.() ?? [];
    idx = ROOT_INDEX.get(roots);
    if (idx === undefined) {
      const bySuffix = new Map<string, Set<string>>();
      const suffixLevel = new Map<string, ConfidentialityLevel>();
      const anyDepth: string[] = [];
      const literal = new Set<string>();
      const patterns: Array<{ under: string; m: (p: string) => boolean }> = [];
      const list: Array<{ path: string; level: ConfidentialityLevel }> = [];
      let top: ConfidentialityLevel | null = null;
      for (const r of roots) {
        if (!isSecret(r.level) || !isAbsolute(r.path)) continue;
        top = top === null ? r.level : maxConfidentiality(top, r.level);
        list.push({ path: r.path, level: r.level });
        const segs = r.path.split("/").filter((s) => s !== "");
        for (let at = 0; at < segs.length; at++) {
          const key = segs.slice(at).join("/");
          const from = "/" + segs.slice(0, at).join("/");
          let dirs = bySuffix.get(key);
          if (dirs === undefined) bySuffix.set(key, (dirs = new Set()));
          dirs.add(from);
          const was = suffixLevel.get(key);
          suffixLevel.set(key, was === undefined ? r.level : maxConfidentiality(was, r.level));
        }
        if (r.anyDepth === true) anyDepth.push(r.path);
        if (r.matches !== undefined) patterns.push({ under: r.path === "/" ? "/" : r.path + "/", m: r.matches });
        else literal.add(r.path);
      }
      const covers = (p: string): boolean => {
        for (let a = p; ; a = a.slice(0, a.lastIndexOf("/")) || "/") {
          if (literal.has(a)) return true;
          if (a === "/" || a === "") break;
        }
        return patterns.some(({ under, m }) => p.startsWith(under) && m(p));
      };
      // a lookup that cannot say where its labels lie: any path may be covered
      const atOrBelow = (dir: string): { path: string; level: ConfidentialityLevel } | null => {
        const under = dir === "/" ? "/" : dir + "/";
        let best: { path: string; level: ConfidentialityLevel } | null = null;
        for (const r of list) {
          if ((r.path === dir || r.path.startsWith(under)) && (best === null || maxConfidentiality(best.level, r.level) !== best.level)) best = r;
        }
        return best;
      };
      idx = { bySuffix, suffixLevel, atOrBelow, anyDepth, top, covers: resolveLabel.roots === undefined ? () => true : covers };
      ROOT_INDEX.set(roots, idx);
    }
    return idx;
  };
}

/** A relative token read from a directory the scan does not know: the
 *  strictest label among the places it could name: under each labelled
 *  path whose last segments it starts with ({@link tailPlaces}:
 *  `vault/plan.md` under `/proj` for a label on `/proj/vault`; `plan.md`
 *  under `/proj/notes` for one on `/proj/notes/plan.md`), and inside each
 *  any-depth pattern's prefix. Not inside a labelled directory itself:
 *  every name is there, and only the start directory or a target the
 *  command names (`candidateDirs`) puts the shell there, or the
 *  precaution stands. Raise-only by its caller. Pure. */
function tailConfidentiality(
  token: string,
  index: () => RootIndex,
  home: string,
  resolveLabel: LabelLookup,
): SecretCatalogMatch {
  const segs = tokenSegments(token);
  if (segs.length === 0) return NO_MATCH;
  const idx = index();
  if (idx.top === null) return NO_MATCH;
  let best = NO_MATCH;
  const read = (abs: string): void => {
    if (!idx.covers(abs)) return;
    const m = pathConfidentiality(abs, home, resolveLabel);
    if (isSecret(m.level)) best = stricter(best, m);
  };
  const places = new Set(tailPlaces(token, index));
  if (places.size > MAX_TAIL_READS) {
    // too many to read one by one (a name thousands of derived files end
    // with): the strictest of them, unread (fail-closed, and bounded)
    const level = tailLevel(token, index);
    if (level !== null) best = stricter(best, { level, bindings: [], rule: `label:${token}` });
  } else {
    for (const p of places) read(p);
  }
  for (const dir of idx.anyDepth) read(resolvePath(dir, segs.join("/")));
  return best;
}

/** A relative token read in `base`: a human label on `base/<token>` decides
 *  it (the override, as for a typed path); otherwise the stricter of the
 *  token as written and the resolved path. Pure. */
function relativeTokenConfidentiality(
  token: string,
  base: string,
  home: string,
  resolveLabel: LabelLookup,
): SecretCatalogMatch {
  const resolved = pathConfidentiality(resolvePath(base, token), home, resolveLabel);
  if (resolved.rule?.startsWith("label:")) return resolved;
  const asWritten = pathConfidentiality(token, home, resolveLabel);
  if (resolved.rule === null) return asWritten;
  if (asWritten.rule === null) return resolved;
  return maxConfidentiality(asWritten.level, resolved.level) === asWritten.level ? asWritten : resolved;
}

/** A token worth resolving against a base directory: relative, and a path
 *  as written (not a flag, a home path, a glob, an expansion or a URL). */
function isResolvableRelativeToken(token: string): boolean {
  if (token.startsWith("/") || token.startsWith("~") || token.startsWith("-")) return false;
  if (/[*?[\]{}$`]/.test(token) || URL_ORIGIN_RE.test(token)) return false;
  return true;
}

/** {@link changesDirectory}, or the same with the shell's quoting and
 *  escapes removed (`\cd`, `c""d`, `c$''d` run `cd`); a `chdir` in code
 *  the command runs (`os.chdir(`, `Dir.chdir "x"`, `os.fchdir`); a
 *  `cwd=` / `cwd:` argument (`subprocess.run(…, cwd="..")`); a `-C` in a
 *  cluster of short flags (`env -iC ..`); `sudo -D`; a `cd` assigned to a
 *  variable (`C=cd`) or a variable in a command's place (`$C ..`). The
 *  test for PLACING a relative token on a file (plan 15 §13.12, review of
 *  2026-10-17), and since the same day for the level too: a change of
 *  directory only ever raises (`findSecretPathsInText`), so a false
 *  positive (a `grep` for `chdir(`) costs only the label lift of an exact
 *  base, never a level. Pure. */
export function directoryMayChange(text: string): boolean {
  return changesDirectory(text) || changesDirectory(dequoted(text)) || /chdir/.test(text)
    || /(?<![-\w])cwd\s*[=:]/.test(text)
    || /(?:^|\s)-[A-Za-z]+C(?=$|[\s"'])/.test(text)
    || /\bsudo\b[^;&|\n]*\s-D\b/.test(text)
    || DIR_WORD_ASSIGNED_RE.test(dequoted(text))
    || /(?:^|[;&|(`\n{]|\$\()\s*["']?\$\{?[A-Za-z_]/.test(text);
}

/** An assignment whose value holds a directory-change word (`C=cd`,
 *  `C=${X:-cd}`): a variable that may then run `cd`. */
const DIR_WORD_ASSIGNED_RE = /[A-Za-z_]\w*=\S*\b(?:cd|pushd|popd|chdir)\b/;

/** The flags that make a program read in another directory, by name. */
const DIR_FLAG_NAMES = "directory|cwd|chdir|dir|working-directory|workdir|wd|root|git-dir|work-tree|prefix";

/** A command that may read its paths somewhere other than the directory it
 *  starts in: a `cd` / `pushd` / `popd` / `chdir` word (also `\cd`; since
 *  2026-10-17); an interpreter's `chdir(` (`os.chdir`, `process.chdir`,
 *  `Dir.chdir`; 2026-10-17); a word that runs shell text the command does
 *  not show (`source`, `.`, `eval`: a sourced file or an evaluated string
 *  can change directory; 2026-10-04); or a flag that names another
 *  directory (`-C` in any spelling, `--directory`, `--cwd`, `--chdir`,
 *  `--git-dir`, `--work-tree`, `--prefix`, `-execdir`, `-okdir`, and since
 *  2026-10-17 `--dir`, `--working-directory`, `--workdir`, `--wd`,
 *  `--root`). Conservative: a false positive keeps the catalog's verdict
 *  (no label lifts a token) and reads every label a token could name
 *  (`findSecretPathsInText`), never lowers one. Pure. */
export function changesDirectory(text: string): boolean {
  return /(?:^|[\s;|&(`"'{\\])(?:cd|pushd|popd|chdir|source|eval)(?=$|[\s;|&)`"'}])/.test(text)
    || /\bchdir\s*\(/.test(text)
    || /(?:^|[;|&({`])\s*\.(?=\s)/.test(text)
    || /(?:^|[\s"'=])(?:-C|--directory|--cwd|--chdir|--git-dir|--work-tree|--prefix|-execdir|-okdir)/.test(text)
    || /(?:^|[\s"'=])--(?:dir|working-directory|workdir|wd|root)(?=$|[=\s"'])/.test(text);
}

/** A directory target the scan cannot read: an expansion other than
 *  `$PWD` / `$HOME`, a command substitution, a glob or a brace, `-` (the
 *  previous directory), `~user`, a directory-stack index. Pure. */
function unreadableTarget(word: string): boolean {
  const quoted = word.replace(/^["']+|["']+$/g, "");
  const w = shellVarPath(quoted) ?? quoted;
  if (w === "-" || /^[+-]\d+$/.test(w)) return true;
  if (/^~[^/]/.test(w)) return true;
  return /[*?[\]{}`$]/.test(w);
}

/** The command with each command substitution (`$(…)`, a backtick pair)
 *  written as one opaque expansion `$_`. Pure. */
function withoutSubstitutions(text: string): string {
  let t = text;
  for (let i = 0; i < 16; i++) {
    const next = t.replace(/\$\([^()]*\)/g, "$_");
    if (next === t) break;
    t = next;
  }
  return t.replace(/`[^`]*`/g, "$_");
}

/** The words of a command, in order, with its separators (`;`, `&`, `|`,
 *  `(`, `)`, a backtick, a newline, a redirection's `<` / `>`) kept as
 *  their own entries. Pure. */
function shellWords(text: string): Array<{ w: string; sep: boolean }> {
  // Quote-aware: a space or a separator inside quotes, or escaped, stays in
  // its word (`"my vault"`, `my\ vault`, `'fix cd - handling'`); the quotes
  // stay in the word too (callers dequote).
  const out: Array<{ w: string; sep: boolean }> = [];
  const SEP = /[;|&()`<>\n]/;
  let cur = "";
  let quote: string | null = null;
  const flush = (): void => {
    if (cur !== "") out.push({ w: cur, sep: false });
    cur = "";
  };
  for (let i = 0; i < text.length; i++) {
    const c = text[i]!;
    if (quote !== null) {
      cur += c;
      if (c === "\\" && quote === '"' && i + 1 < text.length) cur += text[++i]!;
      else if (c === quote) quote = null;
      continue;
    }
    if (c === "\\" && i + 1 < text.length) { cur += c + text[++i]!; continue; }
    if (c === "'" || c === '"') { quote = c; cur += c; continue; }
    if (SEP.test(c)) {
      flush();
      let s = c;
      while (i + 1 < text.length && SEP.test(text[i + 1]!)) s += text[++i]!;
      out.push({ w: s, sep: true });
      continue;
    }
    if (/\s/.test(c)) { flush(); continue; }
    cur += c;
  }
  flush();
  return out;
}

/** A directory change whose target the scan cannot read (2026-10-17):
 *  a {@link dirTargets} target that is an {@link unreadableTarget}
 *  (`cd "$X"`, `cd -`, `cd $(…)`, `pushd +1`, `-C "$D"`); `popd` (the
 *  stack is the shell's); `find`'s `-execdir` / `-okdir` (a directory per
 *  file found); `eval` of an expansion; a variable in a command's place
 *  (`$C ..`); an interpreter's `chdir` or `cwd=` of anything but one
 *  quoted literal (`os.chdir(d)`, `os.fchdir(…)`). `source` and `.` run a
 *  file the command does not show (§10.1) and are not counted. Pure. */
export function unresolvedDirChange(text: string): boolean {
  const flat = withoutSubstitutions(text.replace(/\\\r?\n/g, ""));
  if (dirTargets(flat).some((t) => unreadableTarget(t))) return true;
  const words = shellWords(flat);
  // a variable in a command's place counts only where the command itself
  // sets one to a directory-change word (`C=cd; $C ..`); `$PYTHON -m x`
  // does not
  const varMayCd = DIR_WORD_ASSIGNED_RE.test(dequoted(flat));
  let first = true;
  let pushd = false;
  for (let i = 0; i < words.length; i++) {
    const { w, sep } = words[i]!;
    if (sep) { first = true; continue; }
    const bare = dequoted(w).replace(/^\\/, "");
    if (first && varMayCd && /^\$\{?[A-Za-z_]/.test(bare)) return true;
    first = false;
    if (bare === "pushd") pushd = true;
    // `popd` after the command's own `pushd` returns to a place it shows
    if ((bare === "popd" && !pushd) || bare === "-execdir" || bare === "-okdir") return true;
    if (bare === "eval") {
      for (let j = i + 1; j < words.length && !words[j]!.sep; j++) if (/[$`]/.test(words[j]!.w)) return true;
    }
    if (bare === "cd") {
      // zsh's `cd old new` substitutes in the current path: a computed place
      let j = i + 1;
      while (j < words.length && !words[j]!.sep && /^(?:-[LPe@]+|--)$/.test(dequoted(words[j]!.w))) j++;
      if (j + 1 < words.length && !words[j]!.sep && !words[j + 1]!.sep) return true;
    }
  }
  // an interpreter's chdir or cwd= of anything but one quoted literal
  // (`os.chdir(d)`, `os.fchdir(…)`, `cwd=base`); a mere mention (`grep -rn
  // chdir src`, `grep 'cwd=' x`) is no call and is not counted
  const count = (re: RegExp): number => [...text.matchAll(re)].length;
  if (count(/chdir\s*(?:\(|\s+(?=['"]))/g) > count(/chdir\s*\(?\s*(['"])[^'"$`\\]*\1/g)) return true;
  if (/(?<![-\w])cwd\s*[=:]\s*[A-Za-z_$({[]/.test(text)) return true;
  return false;
}

/** Whether the command passes an argument a program could read as a
 *  relative path: any word that is not a command's first word (past
 *  `builtin`, `command`, `env`, `sudo` and kin, and assignments), a bare
 *  flag, the target of a `cd`, or the target of an output redirection; a
 *  glob, an expansion or a command substitution counts (`cat *.md`,
 *  `echo "$(cat plan.md)"`), and so does an input redirection's source
 *  (`cat<plan.md`). `cd "$X" && ls` passes none. Pure. */
function hasArgumentWord(text: string): boolean {
  return argumentWords(withoutSubstitutions(text)).length > 0 || /chdir\s*\(/.test(text);
}

/** The arguments of a shell command, dequoted: every word that is not a
 *  command's first word (past `builtin`, `command`, `env`, `sudo` and kin,
 *  and assignments), a bare flag, a `cd`'s own target, an output
 *  redirection's file or a descriptor number before a redirection; an
 *  empty quoted word (`grep -r ''`), a glob, an expansion and an input
 *  redirection's source (`cat<plan.md`) count. Pure. */
function argumentWords(text: string): string[] {
  const out: string[] = [];
  let first = true;
  let skip = 0; // words to pass over: a cd's target, an output file
  let input = false;
  const words = shellWords(text.replace(/\\\r?\n/g, ""));
  for (let i = 0; i < words.length; i++) {
    const { w, sep } = words[i]!;
    if (sep) {
      if (/^[<>&]+$/.test(w) && /[<>]/.test(w)) {
        if (w.includes("<")) input = true; else skip = 1;
        continue;
      }
      first = true; skip = 0; input = false;
      continue;
    }
    const bare = dequoted(w).replace(/^\\/, "");
    if (input) { input = false; out.push(bare); continue; }
    if (skip > 0) { if (!/^(?:-[LPe@]+|--)$/.test(bare)) skip--; continue; }
    if (first) {
      first = /^(?:builtin|command|exec|env|nohup|time|sudo|[A-Za-z_][A-Za-z0-9_]*=.*)$/.test(bare);
      if (bare === "cd" || bare === "pushd" || bare === "chdir") skip = 1;
      continue;
    }
    if (bare.startsWith("-") && !bare.includes("=")) continue;
    // a descriptor number right before a redirection (`2>&1`)
    if (/^\d+$/.test(w) && words[i + 1]?.sep === true && /^[<>]/.test(words[i + 1]!.w)) continue;
    out.push(bare);
  }
  return out;
}

const URL_ORIGIN_RE = /^[a-z][a-z0-9+.-]*:\/\//i;

/**
 * Level for a symbolize/classify `origin` hint. A path-like origin
 * classifies directly; any other text (a Bash command string) is scanned for
 * secret path references. URL origins are EXEMPT: a remote URL is not a
 * local secret path, and strict-labeling fetched pages would only make them
 * uninspectable by the U-LLM. Runs server-side so no client can forget.
 */
export function confidentialityForOrigin(
  origin: string | null | undefined,
  home: string = homedir(),
  resolveLabel?: LabelLookup,
  /** The directory the command runs in, when the call names it
   *  (`findSecretPathsInText`). */
  baseDir?: string,
  /** As `findSecretPathsInText`'s. */
  opts: ScanOptions = {},
): SecretCatalogMatch {
  if (!origin) return NO_MATCH;
  if (URL_ORIGIN_RE.test(origin)) return NO_MATCH;
  // A user label on the origin path SHORT-CIRCUITS — including a `public` one,
  // which is the override (§6). It must beat the text scan below, or a
  // declassified `.env` would still be caught by its own basename shape.
  //
  // A CATALOG hit on the whole string, though, is only meaningful when the
  // origin IS a single path. On multi-token text (a Bash command) it is a
  // false match — basename(`grep KEY /ws/fixtures/.env`) is `.env`, so the
  // whole command classifies strict and would SKIP the label-aware token scan
  // below, silently defeating a §6 declassification (found live: CONF-public-label-override at
  // int ON). The label store has no such false positive (its keys are real
  // normalized paths), so a label verdict keeps the short-circuit.
  // A single relative path read in a known directory: the same reading the
  // token scan below gives it (findSecretPathsInText).
  //
  // A LABEL hit on multi-token text short-circuits only when it is an exact
  // label on that very string (a path with a space in it). Any other label
  // that matched the whole string (a pattern, an ancestor directory:
  // `**/*.md` matches `/bin/cat /proj/secrets/plan.md`) is a false match
  // like the catalog's, and a `public` one must not stand over what the
  // token scan finds (2026-10-17): it joins the scan's hits, raise-only.
  const multi = TEXT_TOKEN_SPLIT.test(origin);
  // one path, read where it is known to be read
  const single = !multi && opts.movesDirectory !== true && (opts.extraBases?.length ?? 0) === 0 && (opts.targets?.length ?? 0) === 0;
  const direct = baseDir !== undefined && resolveLabel !== undefined && isAbsolute(baseDir) &&
      single && isResolvableRelativeToken(origin)
    ? relativeTokenConfidentiality(origin, baseDir, home, resolveLabel)
    : pathConfidentiality(origin, home, resolveLabel);
  const catalogRule = (direct.rule?.startsWith("prefix:") || direct.rule?.startsWith("shape:")) === true;
  if (direct.rule !== null && (single || (multi && !catalogRule && exactLabelOn(direct, origin, home)))) return direct;
  const hits: SecretCatalogMatch[] = findSecretPathsInText(origin, home, resolveLabel, baseDir, opts);
  if (direct.rule !== null && !catalogRule) hits.push(direct);
  if (hits.length === 0) return NO_MATCH;
  // Carry the BINDINGS of the hit that SET the level — a bound destination is
  // per-datum metadata (§2), and dropping it here would make every label's
  // bindings unreachable from a command-text reference.
  const level = maxConfidentiality(...hits.map((h) => h.level));
  const top = hits.find((h) => h.level === level) ?? hits[0];
  return { level, bindings: top.bindings, rule: top.rule };
}

/** `params` without `key`. Pure. */
function withoutKey(params: Record<string, unknown>, key: string): Record<string, unknown> {
  const { [key]: _dropped, ...rest } = params;
  return rest;
}

/** Whether a label verdict is an exact label on `origin` itself (its
 *  `via` is the normalized string), not a pattern or an ancestor. Pure. */
function exactLabelOn(m: SecretCatalogMatch, origin: string, home: string): boolean {
  const via = m.rule?.replace(/^(?:label|derived):/, "");
  return via !== undefined && via !== m.rule && via === normalizeFsPath(origin, home);
}

/** Params keys worth checking on a classify request: the typed path fields
 * plus the Bash command text (scanned for path references). */
const CLASSIFY_PARAM_KEYS = ["file_path", "path", "notebook_path", "command"] as const;

/** How an agent's tool takes a `workdir` its runtime HONOURS (the command
 *  runs in the directory it names): `"always"`, on every call of the tool;
 *  `"argv"`, only on a call whose `command` is an argv array of strings
 *  (Codex's classic `shell{command: string[], workdir}`: the same name with
 *  a string `command` is another agent's tool, Goose's `shell{command}` or
 *  OpenCode 2's, and is not Codex's). */
export type WorkdirShape = "always" | "argv";

/** An agent's tools whose `workdir` it honours (tool → shape), the
 *  `workdir` table of the session's gate surface (tool-gate-surface.ts):
 *  keyed by AGENT, not by tool name alone, because two agents share a name
 *  (`shell` is Codex's classic tool, OpenCode 2's and Goose's, and only
 *  Goose's has no `workdir`). Empty: no tool's `workdir` is believed. */
export type WorkdirTools = Readonly<Record<string, WorkdirShape>>;

/** Whether this call's `workdir` (named or not) is one its agent acts on:
 *  the tool is in the agent's `workdirTools` and the call has the shape the
 *  entry needs. Pure. */
export function honoursWorkdir(
  tool: string,
  params: Record<string, unknown> | undefined,
  workdirTools: WorkdirTools,
): boolean {
  if (!Object.prototype.hasOwnProperty.call(workdirTools, tool)) return false;
  const shape = workdirTools[tool];
  if (shape === "always") return true;
  if (shape !== "argv" || params === undefined) return false;
  const cmd = params["command"];
  return Array.isArray(cmd) && cmd.length > 0 && cmd.every((x) => typeof x === "string");
}

/** The absolute directory a call's command runs in, when the arbiter can
 *  say, else undefined.
 *
 *  A tool whose `workdir` its AGENT honours (`honoursWorkdir` over the
 *  session's `workdirTools`: Codex's `exec_command` and argv `shell`,
 *  OpenCode's `bash` / `shell`) runs in the `workdir` the call names, an
 *  absolute path only (a relative one is no base, never the default). A
 *  call that names none runs where Codex runs it, its session's directory:
 *  `sessionDefault`, the one the model proxy read off the request for
 *  certain (the openai-proxy's `codexSessionCwd`), else the kernel's start
 *  directory below. A named `workdir` and Codex's session default come
 *  first: Codex may start a wrapper that changes into the `workdir` after
 *  the exec the guard saw.
 *
 *  Any other call (Claude Code's `Bash`, which names no directory; Goose's
 *  `shell`, a fresh `bash -c` in the launch directory) runs in `startDir`
 *  when the arbiter knows it (2026-10-04): the directory the kernel says the
 *  call's own shell started in, read by the guard at that shell's exec and
 *  bound to the call by the call-root recorder (`ClassifyRequest.
 *  callStartDir`, which only the arbiter sets, from its own record;
 *  confidentiality.md §6). Without it, nothing. A start directory that is
 *  not absolute, or has a `..` segment, is no base. A `workdir` such a call
 *  names is the MODEL's claim, which its agent never acts on, and is
 *  ignored (2026-10-11: Goose's `shell` shares Codex's tool name, so a
 *  forged `workdir` used to be believed over the kernel's directory, and a
 *  relative token read where it did not run; see confidentiality.md §6).
 *
 *  `workdirTools` defaults to none: a caller that does not say which agent
 *  the call is from has no `workdir` believed (fail-closed: a base only
 *  ever lets a human label decide, and a forged one picks the label). Pure. */
export function callWorkdir(
  tool: string | undefined,
  params: Record<string, unknown> | undefined,
  sessionDefault?: string,
  startDir?: string,
  workdirTools: WorkdirTools = {},
): string | undefined {
  if (tool === undefined) return undefined;
  const kernel = typeof startDir === "string" && isAbsolute(startDir) && !startDir.split("/").includes("..") ? startDir : undefined;
  if (!honoursWorkdir(tool, params, workdirTools)) return kernel;
  if (params !== undefined && Object.prototype.hasOwnProperty.call(params, "workdir")) {
    const v = params["workdir"];
    return typeof v === "string" && isAbsolute(v) ? v : undefined;
  }
  return typeof sessionDefault === "string" && isAbsolute(sessionDefault) ? sessionDefault : kernel;
}

/** Where a call's TYPED path fields are read when relative (2026-10-09):
 *  the directory its agent resolves them against and the fields it does so
 *  for. Built by the classify wrapper (policy-interface.ts
 *  `relativePathBase`) only for an agent whose gate surface says
 *  `relativeBase: "launch"` (OpenClaw, OpenCode, Goose) and a tool that
 *  surface lists in `paths`, from the launch directory the launcher named the
 *  model proxy (MANDU_AGENT_CWD), HumanView. */
export interface TypedPathBase {
  dir: string;
  fields: readonly string[];
}

/** A typed path value worth reading in a base directory: a relative path
 *  as written (`isResolvableRelativeToken`), printable ASCII only, and not
 *  `@`-prefixed. OpenClaw's `read` strips a leading `@`, turns Unicode
 *  spaces into spaces and, when the path does not exist, tries Unicode and
 *  quote variants of it, so such a value may name another file than
 *  `dir/<value>`; it keeps the catalog's verdict. Pure. */
function isBaseResolvableTypedPath(value: string): boolean {
  return value !== "" && /^[\x20-\x7e]+$/.test(value) && !value.startsWith("@") && isResolvableRelativeToken(value);
}

/** Where the agent read ONE typed path value (a `path` / `file_path` field)
 *  when it is relative: `<dir>/<value>`, for a value
 *  {@link isBaseResolvableTypedPath} keeps (one the agent's tool may read
 *  elsewhere keeps no place) and a usable `dir` (absolute, no `..`
 *  segment); else undefined. The place the symbolize op stores a relative
 *  read's row at (SymbolizeRequest.relativeBase), so the label that decides
 *  its level in {@link typedPathConfidentiality} gives it its bindings too.
 *  Pure. */
export function resolveTypedPathOrigin(value: string, dir: string): string | undefined {
  if (!isAbsolute(dir) || dir.split("/").includes("..")) return undefined;
  if (!isBaseResolvableTypedPath(value)) return undefined;
  return resolvePath(dir, value);
}

/** The level of ONE typed path value (a `path` / `file_path` field: a single
 *  path, never shell text) read in `base`: a HUMAN label on `base/<value>`
 *  decides it, in either direction, as it decides a `Read` of that absolute
 *  path; otherwise the stricter of the value as written (the reading without
 *  a base) and the resolved path, so without a human label a base only ever
 *  raises. The value is resolved WHOLE (a path with a space is one path, not
 *  two tokens). Pure. */
function typedPathConfidentiality(
  value: string,
  base: string,
  home: string,
  resolveLabel: LabelLookup,
): SecretCatalogMatch {
  const asWritten = confidentialityForOrigin(value, home, resolveLabel);
  if (!isBaseResolvableTypedPath(value)) return asWritten;
  const resolved = pathConfidentiality(resolvePath(base, value), home, resolveLabel);
  if (resolved.rule?.startsWith("label:")) return resolved;
  if (resolved.rule === null) return asWritten;
  if (asWritten.rule === null) return resolved;
  return maxConfidentiality(asWritten.level, resolved.level) === asWritten.level ? asWritten : resolved;
}

/** `pathBase` when it can be used: an absolute directory with no `..`
 *  segment, and a lookup to read its labels. Pure. */
function usablePathBase(pathBase: TypedPathBase | undefined, resolveLabel: LabelLookup | undefined): TypedPathBase | undefined {
  if (pathBase === undefined || resolveLabel === undefined) return undefined;
  const { dir } = pathBase;
  return typeof dir === "string" && isAbsolute(dir) && !dir.split("/").includes("..") ? pathBase : undefined;
}

/**
 * The full label for a classify request: max over the origin hint and any
 * path-ish params, with the winning source's bindings. One call site (the
 * engine-backed classify wrapper) so the per-branch trust returns stay untouched.
 * A call that names its working directory (`callWorkdir`) has its relative
 * path tokens read there too, so a human label on the file decides them
 * (`findSecretPathsInText`).
 *
 * `pathBase` (2026-10-09): a relative value in one of its typed path fields,
 * and the origin hint when it is that same value, is read in `pathBase.dir`
 * (`typedPathConfidentiality`): OpenClaw's `read {path: "test/fixtures/.env"}`
 * resolves against its workspace, so the human's label on that absolute file
 * decides it as it decides Claude Code's `Read` of the absolute path. The
 * command text is never read there (a shell may have changed directory);
 * every other source keeps its own verdict and the MAX still holds.
 *
 * `paths` (2026-10-05): when the level is secret, the tokens of the sources
 * read above (the origin hint, which for a shell call is its command, Codex's
 * `cmd` included; the path fields; the command text) that name a secret
 * path, as written there. The model proxy names them in the note it appends
 * to a result masked whole by this path-derived level (confidentiality.md
 * §7.1, "the path-derived note"); it keeps only a token it finds verbatim in
 * the model's own command, so a translated spelling (`originHuman`,
 * `paramsHuman`) never reaches the model.
 */
export function labelForClassify(
  req: { tool?: string; origin?: string; params?: Record<string, unknown>; workdirDefault?: string; callStartDir?: string; pathBase?: TypedPathBase; workdirTools?: WorkdirTools; agentOpened?: ReadonlyArray<{ token: string; path: string }> },
  home: string = homedir(),
  lookup?: LabelLookup,
): { level: ConfidentialityLevel; bindings: string[]; paths: string[]; files?: string[]; placed?: string[]; ifCdFailed?: { dir: string; files: string[]; placed: string[] } } {
  const resolveLabel = withRootsOnce(lookup);
  const p = req.params ?? {};
  const pathBase = usablePathBase(req.pathBase, resolveLabel);
  // The typed path values read in the agent's directory (never `command`).
  const typed = new Set<string>();
  if (pathBase !== undefined) {
    for (const key of CLASSIFY_PARAM_KEYS) {
      if (key !== "command" && pathBase.fields.includes(key) && typeof p[key] === "string") typed.add(p[key] as string);
    }
  }
  const sources: Array<string | undefined> = [req.origin];
  for (const key of CLASSIFY_PARAM_KEYS) {
    if (typeof p[key] === "string") sources.push(p[key] as string);
  }
  // exclusion-flags.md (2026-10-18): the shell command (`command`, or
  // Codex's `cmd`, and the origin when it is that same text) is read with
  // each `--exclude-dir=NAME` word of one plain grep blanked: no grep opens
  // it. Never a typed path field, in both passes below.
  // (`cmd` first, as the openai-proxy's `originFor` reads it)
  const commandText = typeof p["cmd"] === "string" ? p["cmd"] as string : typeof p["command"] === "string" ? p["command"] as string : undefined;
  const shellTool = typeof req.tool === "string" && ["Bash", "bash", "shell", "exec_command", "local_shell", "exec"].includes(req.tool);
  const scanned = (s: string): string => shellTool && s === commandText && !typed.has(s) ? withoutGrepExclusions(s) : s;
  const workdir = callWorkdir(req.tool, p, req.workdirDefault, req.callStartDir, req.workdirTools);
  // A RELATIVE `workdir` the agent honours (2026-10-17): Codex joins it to
  // its own directory, so it is no base (`callWorkdir`), but the command
  // still runs there: read like a `cd` target from the directory the call
  // would run in without it, raise-only (`findSecretPathsInText`).
  const wd = p["workdir"];
  const relWorkdir = typeof wd === "string" && wd !== "" && !isAbsolute(wd) && req.tool !== undefined && honoursWorkdir(req.tool, p, req.workdirTools ?? {}) ? wd : undefined;
  const scanBase = relWorkdir === undefined ? workdir : callWorkdir(req.tool, withoutKey(p, "workdir"), req.workdirDefault, req.callStartDir, req.workdirTools);
  const scanOpts: ScanOptions = relWorkdir === undefined ? {} : { targets: [relWorkdir] };
  // one reading per distinct source (the origin is often the command itself)
  const readings = new Map<string | undefined, SecretCatalogMatch>();
  const read = (s: string | undefined): SecretCatalogMatch => {
    let m = readings.get(s);
    if (m === undefined) {
      m = pathBase !== undefined && typeof s === "string" && typed.has(s)
        ? typedPathConfidentiality(s, pathBase.dir, home, resolveLabel!)
        : confidentialityForOrigin(typeof s === "string" ? scanned(s) : s, home, resolveLabel, scanBase, scanOpts);
      readings.set(s, m);
    }
    return m;
  };
  const matches = sources.map(read);
  // 2026-10-17 (confidentiality.md §6, "The base follows the shell"): a
  // file the agent itself opened in the call's window, as the kernel named
  // it, whose path ends with a relative path value of the call
  // (`agentOpened`, set by the arbiter alone): read too, raise-only (a
  // `public` reading there lowers nothing), and never placed on a file.
  const opened: Array<{ token: string; m: SecretCatalogMatch }> = [];
  for (const o of req.agentOpened ?? []) {
    if (typeof o?.path !== "string" || !isAbsolute(o.path) || typeof o.token !== "string") continue;
    const m = pathConfidentiality(o.path, home, resolveLabel);
    if (isSecret(m.level)) opened.push({ token: o.token, m });
  }
  const level = maxConfidentiality(...matches.map((m) => m.level), ...opened.map((o) => o.m.level));
  const winner = [...matches, ...opened.map((o) => o.m)].find((m) => m.level === level && m.bindings.length > 0);
  const paths: string[] = [];
  // Plan 15 §13.12: the files every secret reading resolves to, or none at
  // all (`complete` false) when one cannot be placed: a source secret with
  // no secret token found in it, a relative token read nowhere, a glob.
  const files = new Set<string>();
  let complete = true;
  // Plan 15 §13.12, "A cd that fails" (2026-10-19): the same readings
  // placed where the command started, for when its leading `cd` failed
  // (`leadingCdStart`); offered only when every reading is placed both
  // ways and the command's texts open with one and the same `cd`.
  const failedFiles = new Set<string>();
  const cdDirs = new Set<string>();
  let failedComplete = true;
  if (isSecret(level)) {
    for (const [i, s] of sources.entries()) {
      if (typeof s !== "string" || s === "" || URL_ORIGIN_RE.test(s)) continue;
      const sourceSecret = isSecret(matches[i]!.level);
      if (typed.has(s)) {
        // one path: named only when it is itself secret where it is read
        if (isSecret(read(s).level) && isPathShaped(s) && !paths.includes(s)) paths.push(s);
        if (sourceSecret) {
          const file = s.split("/").includes("..") ? undefined : resolveTypedPathOrigin(s, pathBase!.dir) ?? placedTokenFile(s, undefined);
          if (file === undefined) complete = false; else { files.add(file); failedFiles.add(file); }
        }
        continue;
      }
      let placed = false;
      for (const hit of findSecretPathsInText(scanned(s), home, resolveLabel, scanBase, scanOpts)) {
        if (!isSecret(hit.level)) continue;
        if (isPathShaped(hit.token) && !paths.includes(hit.token)) paths.push(hit.token);
        if (hit.file === undefined) complete = false; else { files.add(hit.file); placed = true; }
        if (hit.file !== undefined && hit.cdDir !== undefined) {
          cdDirs.add(hit.cdDir);
          if (hit.cdFailedFile === undefined) failedComplete = false; else failedFiles.add(hit.cdFailedFile);
        } else if (hit.file !== undefined) failedFiles.add(hit.file);
      }
      if (sourceSecret && !placed) complete = false;
    }
    // a value read where the agent opened it: named, never placed
    for (const o of opened) {
      if (isPathShaped(o.token) && !paths.includes(o.token)) paths.push(o.token);
      complete = false;
    }
  }
  // Plan 15 §13.12: every file the call's plain path tokens name, whatever
  // its label (the files whose lines a path row may stop fingerprinting).
  const placed = new Set<string>();
  const failedPlaced = new Set<string>();
  if (isSecret(level) && complete && files.size > 0) {
    for (const s of sources) {
      if (typeof s !== "string" || s === "" || URL_ORIGIN_RE.test(s)) continue;
      if (typed.has(s)) {
        const f = s.split("/").includes("..") ? undefined : resolveTypedPathOrigin(s, pathBase!.dir) ?? placedTokenFile(s, undefined);
        if (f !== undefined) { placed.add(f); failedPlaced.add(f); }
        continue;
      }
      for (const f of placedFilesInText(scanned(s), workdir)) placed.add(f);
      if (cdDirs.size === 1) for (const f of placedFilesInText(scanned(s), workdir, { ifCdFailed: true })) failedPlaced.add(f);
    }
  }
  const ifCdFailed = isSecret(level) && complete && files.size > 0 && cdDirs.size === 1 && failedComplete && failedFiles.size > 0
    ? { dir: [...cdDirs][0]!, files: [...failedFiles].sort(), placed: [...failedPlaced].sort() }
    : undefined;
  return {
    level, bindings: winner?.bindings ?? [], paths,
    ...(isSecret(level) && complete && files.size > 0 ? { files: [...files].sort(), placed: [...placed].sort(), ...(ifCdFailed !== undefined ? { ifCdFailed } : {}) } : {}),
  };
}

/** A token the path-derived note may name: written like a path (a `/`, a
 *  leading `~`, or a `.` as in `.env` or `notes.md`), not a flag. A bare word
 *  (`cat`) can still read as secret, being resolved under a labelled
 *  directory, but naming it would mislead. Pure. */
function isPathShaped(token: string): boolean {
  return !token.startsWith("-") && (token.includes("/") || token.startsWith("~") || token.includes("."));
}

/** Bounds of the unmapped-input scan. Past any of them the scan stops and the
 * verdict is `no-model` (fail-closed: an input too large to read is not
 * an input known to name no secret). A real tool call is far inside them. */
export const UNMAPPED_INPUT_SCAN_LIMITS = { depth: 16, strings: 4096, chars: 1024 * 1024 } as const;

const FILE_URL_RE = /^file:\/\//i;

/** An input key that names a directory the tool may work in (`cwd`,
 *  `workdir`, `working_directory`, `dir`, `chdir`, `root`, `base_dir`). */
const DIR_KEY_RE = /^(?:[a-z]+[_-])?(?:cwd|chdir|workdir|work_?dir|working[_-]?dir(?:ectory)?|dir|directory|root)$/i;

/** The lookup with its `roots` read once for this request (several texts
 *  share one index; `findSecretPathsInText`). */
function withRootsOnce(lookup: LabelLookup | undefined): LabelLookup | undefined {
  if (lookup?.roots === undefined) return lookup;
  const source = lookup.roots;
  let roots: readonly LabelRoot[] | undefined;
  const once: LabelLookup = (p: string) => lookup(p);
  once.roots = () => (roots ??= source());
  return once;
}

/**
 * The path-derived label of a tool the session's spec does not map
 * (confidentiality-plan-10 §11.11). `labelForClassify` reads the origin and
 * four named params; a tool nobody mapped may name its path anything
 * (`target`, `files[0]`, `{src: {path}}`) or be a shell under another name
 * (OpenClaw's `terminal`, a plugin's exec, an MCP tool). So EVERY string in
 * its input, at any depth, and every object key is read as
 * {@link confidentialityForOrigin} reads a Bash command: a path-like string
 * classifies directly, other text is scanned token by token for catalog and
 * label hits. A `file://` URL is read as its path (the URL exemption is for
 * remote pages). Raise-only by construction: the caller takes the MAX with
 * the named-param verdict, so a `public` declassification label on one
 * string never lowers what another string, or the origin, derived.
 *
 * False positives (a string that merely MENTIONS `.env`) over-mask the
 * result: the model gets a handle instead of the text. That is the
 * fail-closed side; the alternative reads a labeled file's text raw.
 */
export function labelForUnmappedInput(
  inputs: readonly unknown[],
  home: string = homedir(),
  resolveLabel?: LabelLookup,
  /** The directory the call's command runs in (`callWorkdir`): its relative
   *  tokens are read there too, as `labelForClassify` reads them. */
  baseDir?: string,
): { level: ConfidentialityLevel; bindings: string[]; rule: string | null; files?: string[] } {
  const texts: string[] = [];
  let chars = 0;
  let over = false;
  let movesDir = false;
  const extraBases: string[] = [];
  const targets: string[] = [];
  const push = (s: string): void => {
    if (s === "") return;
    if (texts.length >= UNMAPPED_INPUT_SCAN_LIMITS.strings || chars + s.length > UNMAPPED_INPUT_SCAN_LIMITS.chars) { over = true; return; }
    texts.push(s);
    chars += s.length;
  };
  const walk = (v: unknown, depth: number): void => {
    if (over) return;
    if (typeof v === "string") { push(v); return; }
    if (v === null || typeof v !== "object") return;
    if (depth >= UNMAPPED_INPUT_SCAN_LIMITS.depth) { over = true; return; }
    if (Array.isArray(v)) { for (const x of v) walk(x, depth + 1); return; }
    for (const [k, x] of Object.entries(v as Record<string, unknown>)) {
      push(k);
      // a directory the tool may work in: an absolute one is read at too
      // (labels only, raise-only); any other leaves no token placed exactly
      if (DIR_KEY_RE.test(k)) {
        if (typeof x === "string" && isAbsolute(x)) { if (baseDir === undefined || resolvePath(x) !== resolvePath(baseDir)) extraBases.push(x); }
        else if (typeof x === "string" && x !== "") targets.push(x);
        else movesDir = true;
      }
      walk(x, depth + 1);
    }
  };
  for (const input of inputs) walk(input, 0);
  if (over) return { level: "no-model", bindings: [], rule: "unmapped-input:too-large" };
  // One string may move where another is read (`{cwd: "sub", path:
  // "../secrets/plan.md"}`, or a `cd` in one field): then no string is read
  // as placed exactly, and every label a token could name is read
  // (2026-10-17, `findSecretPathsInText`).
  const movesDirectory = movesDir || texts.some((t) => directoryMayChange(t));
  const lookup = withRootsOnce(resolveLabel);
  let best: SecretCatalogMatch = NO_MATCH;
  // Plan 15 §13.12: every secret reading placed on a file, as
  // `labelForClassify`'s `files`; absent when one cannot be.
  const files = new Set<string>();
  let complete = true;
  // A text whose own command changes directory is read as moved by its
  // own scan anyway; what it adds for PLACING is whether ANOTHER string
  // may move it (2026-10-19, Codex's `exec_command {cmd: "cd app && …",
  // workdir}`: the `cd` is the cmd's own, and `movesDirectory` for every
  // string switched its leading `cd` placement off). The level's reading
  // above keeps every string moved.
  const moving = new Set(texts.filter((t) => directoryMayChange(t)));
  for (const t of texts) {
    const text = FILE_URL_RE.test(t) ? safeFileUrlPath(t) : t;
    const m = confidentialityForOrigin(text, home, lookup, baseDir, { movesDirectory, extraBases, targets });
    if (m.rule !== null && (best.rule === null || maxConfidentiality(best.level, m.level) !== best.level)) best = m;
    if (!isSecret(m.level)) continue;
    let placed = false;
    const movedByAnother = movesDir || moving.size > (moving.has(t) ? 1 : 0);
    for (const hit of findSecretPathsInText(text, home, lookup, baseDir, { movesDirectory: movedByAnother, extraBases, targets })) {
      if (!isSecret(hit.level)) continue;
      if (hit.file === undefined) complete = false; else { files.add(hit.file); placed = true; }
    }
    if (!placed) complete = false;
  }
  return {
    level: best.level, bindings: best.bindings, rule: best.rule,
    ...(isSecret(best.level) && complete && files.size > 0 ? { files: [...files].sort() } : {}),
  };
}

function safeFileUrlPath(url: string): string {
  const rest = url.replace(FILE_URL_RE, "");
  // file:///p and file://localhost/p name /p; anything else keeps its text.
  const path = rest.startsWith("/") ? rest : rest.replace(/^localhost(?=\/)/i, "");
  try {
    return decodeURIComponent(path);
  } catch {
    return path;
  }
}

/** Level-only view of {@link labelForClassify} — the pre-Plan-6 signature. */
export function confidentialityForClassify(
  req: { tool?: string; origin?: string; params?: Record<string, unknown> },
  home: string = homedir(),
  resolveLabel?: LabelLookup,
): ConfidentialityLevel {
  return labelForClassify(req, home, resolveLabel).level;
}
