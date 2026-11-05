/**
 * builtin-files — the files Mandu keeps secret with no rule of the person's,
 * as Rules › Built-in protections names them under **Which files**
 * (dashboard.md §4.25z). Mandu-new (no reference origin).
 *
 * A DISPLAY COPY of the arbiter's default-secret catalog
 * (arbiter/policy/secret-catalog.ts): `SECRET_PREFIXES` (with fs-outbound's
 * `SENSITIVE_PATHS`), the basename shapes, and the agents' own data shapes
 * (`shape:opencode-data`, `shape:goose-data`). The dashboard does not import
 * the arbiter (the arbiter-client convention), so
 * tests/stack/builtin-files-parity keeps the copy equal: the places are the
 * arbiter's prefixes in order, each example name below gets its kind's rule
 * from the arbiter, and every basename shape the arbiter has is a kind here.
 * A new place or shape in the catalog adds its line here.
 *
 * Display only: nothing here decides what is secret. The words of each rule
 * are also the file browser's ("Built in: environment files"), one set.
 *
 * Pure.
 */

import type { HomeTextPart } from "./ask-words.js";

/** One kind of file the catalog keeps secret by its name, in any folder. */
export interface BuiltinFileKind {
  /** The arbiter's rule ids for this kind (`shape:…`). */
  rules: readonly string[];
  /** The kind in the page's words, lower case ("environment files"). */
  words: string;
  /** Example names, a `*` standing for any characters. */
  names: readonly string[];
  /** Where or when the names count, when not always ("in a tool's own folder"). */
  where?: string;
  /** The names count only inside a tool's own folder (`.tool/auth.json`). */
  inToolFolder?: true;
}

/** The catalog's basename shapes as kinds, in the arbiter's order. */
export const BUILTIN_FILE_KINDS: readonly BuiltinFileKind[] = [
  { rules: ["shape:.env*", "shape:*.env"], words: "environment files", names: [".env", ".env.*", "*.env", ".envrc"] },
  { rules: ["shape:*credentials*"], words: "credential files", names: ["credentials", "*credentials*"], where: "not program source or documentation pages" },
  { rules: ["shape:secrets*.json"], words: "secrets files", names: ["secrets*.json"] },
  { rules: ["shape:ssh-private-key"], words: "SSH keys", names: ["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"] },
  { rules: ["shape:*.keytab"], words: "keytab files", names: ["*.keytab"] },
  { rules: ["shape:*secret*"], words: "files named secret", names: ["secret", "*-secret", "*_secrets", "*secret*.json", "*secret*.yaml", "*secret*.toml", "*secret*.ini", "*secret*.txt"] },
  { rules: ["shape:private-key-file"], words: "private keys", names: ["*.key", "*-key.pem", "privkey.pem", "*.p12", "*.pfx", "*.jks", "*.keystore", "*.ppk", "*.kdbx"] },
  { rules: ["shape:service-account-key"], words: "service account keys", names: ["*service-account*.json", "*-key.json", "keyfile.json"] },
  { rules: ["shape:*.tfstate"], words: "Terraform state", names: ["*.tfstate", "*.tfstate.backup"] },
  { rules: ["shape:tool-login-file"], words: "a tool's saved sign-in", names: ["auth.json", "auth.yaml", "auth.toml", "oauth_creds.json", "access-token"], where: "in a tool's own folder", inToolFolder: true },
  { rules: ["shape:*.private.env.json"], words: "HTTP client private settings", names: ["*.private.env.json"] },
];

/** Template names the catalog leaves out, whatever their shape. */
export const BUILTIN_TEMPLATE_EXAMPLES: readonly string[] = [".env.example", "secrets.example.json"];

/** The catalog's places in the home folder (its prefixes, in order, without
 *  the system files and the Windows profile's). */
export const BUILTIN_HOME_PLACES: readonly string[] = [
  "~/.ssh", "~/.gnupg", "~/.aws", "~/.kube", "~/.docker/config.json", "~/.netrc", "~/.git-credentials",
  "~/.config/gh", "~/.config/gcloud", "~/.claude", "~/.claude.json", "~/.codex", "~/.anthropic", "~/.openai",
  "~/.local/share/opencode", "~/.config/goose/secrets.yaml", "~/.local/share/goose", "~/.local/state/goose",
  "~/.local/share/keyrings", "~/.password-store",
  "~/.pgpass", "~/.my.cnf", "~/.boto", "~/.s3cfg", "~/.databrickscfg", "~/.snowflake", "~/.config/rclone",
  "~/.npmrc", "~/.yarnrc.yml", "~/.pypirc", "~/.config/pip", "~/.pip",
  "~/.config/composer/auth.json", "~/.composer/auth.json",
  "~/.m2/settings.xml", "~/.m2/settings-security.xml", "~/.gradle/gradle.properties",
  "~/.nuget/NuGet/NuGet.Config", "~/.terraformrc",
  "~/.azure", "~/.oci", "~/.aliyun", "~/.config/doctl", "~/.config/hcloud",
  "~/.config/openstack", "~/.config/containers/auth.json", "~/.config/helm/registry",
  "~/.vault-token", "~/.config/sops",
  "~/.config/glab-cli", "~/.config/hub",
  "~/.local/share/com.vercel.cli", "~/.config/netlify", "~/.config/.wrangler", "~/.wrangler",
  "~/.fly", "~/.supabase", "~/.config/stripe", "~/.config/configstore", "~/.config/ngrok",
  "~/.ngrok2", "~/.circleci/cli.yml", "~/.sentryclirc", "~/.kaggle", "~/.huggingface",
  "~/.cache/huggingface/token", "~/.cache/huggingface/stored_tokens",
  "~/.config/github-copilot", "~/.config/op", "~/.op",
  "~/.mandu/state/dashboard-account.json",
];

/** The catalog's system files (absolute). */
export const BUILTIN_SYSTEM_PLACES: readonly string[] = ["/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/etc/sudoers.d"];

/** The same stores where a Windows profile keeps them (WSL), one closing
 *  line on the page. */
export const BUILTIN_WINDOWS_PLACES: readonly string[] = [
  "~/_netrc",
  "~/AppData/Roaming/gcloud", "~/AppData/Roaming/GitHub CLI", "~/AppData/Roaming/rclone",
  "~/AppData/Roaming/pip", "~/AppData/Roaming/Composer/auth.json", "~/AppData/Roaming/NuGet/NuGet.Config",
  "~/AppData/Roaming/terraform.rc", "~/AppData/Roaming/doctl", "~/AppData/Roaming/postgresql/pgpass.conf",
  "~/AppData/Roaming/helm/registry", "~/AppData/Roaming/sops", "~/AppData/Roaming/com.vercel.cli",
];

/** The agents' own data shapes, one line on the page. */
export const BUILTIN_AGENT_DATA_RULES: readonly string[] = ["shape:opencode-data", "shape:goose-data"];

/** Every built-in rule id in the page's words: the kinds above, and the
 *  catalog's content tier (secret-discovery.md §2.6-2.7), which has no name. */
export const BUILTIN_RULE_WORDS: Readonly<Record<string, string>> = {
  ...Object.fromEntries(BUILTIN_FILE_KINDS.flatMap((k) => k.rules.map((r) => [r, k.words]))),
  // §2.6: no name, a credential Mandu read in the file.
  "content:secret-key": "a saved password or key Mandu found in it",
  // §2.7: a statement, a tax return, a lab report, household codes.
  "content:personal-document": "a personal document Mandu recognised",
};

/** The Which files fold as `/api/home?files=1` carries it
 *  (`HomeBuiltIn.files`; fixed copy, so the polled home leaves it out). */
export interface HomeBuiltInFiles {
  /** "Named like this, in any folder": one row per kind, its words with a
   *  capital ("Environment files"), its names, and a limit or null. */
  kinds: Array<{ words: string; names: string[]; where: string | null }>;
  /** Template names left out (`.env.example`). */
  templates: string[];
  /** "These places in your home folder" (`~/…`). */
  places: string[];
  /** System files (absolute). */
  system: string[];
  /** Closing lines under the places, each with its names as code. */
  also: Array<{ text: string; parts: HomeTextPart[] }>;
  /** The content tier, as plain words. */
  found: string;
  /** How to make one readable: its words and parts, Your rules a link. */
  change: { text: string; parts: Array<HomeTextPart | { kind: "link"; text: string; to: "your-rules" }> };
}

/** The files in `~/.ssh` the catalog leaves out (public material). */
export const SSH_PUBLIC_EXAMPLES: readonly string[] = ["*.pub", "known_hosts", "authorized_keys", "allowed_signers"];

/** A sentence written with its names between backticks: its words and its
 *  parts, the marked spans as code. Only this module's literals. */
function marked(s: string): { text: string; parts: HomeTextPart[] } {
  const parts = s.split("`").map((text, i): HomeTextPart => ({ kind: i % 2 ? "code" : "text", text })).filter((p) => p.text !== "");
  return { text: parts.map((p) => p.text).join(""), parts };
}

const capital = (s: string): string => s.charAt(0).toUpperCase() + s.slice(1);

/** The fold's lists. Pure. */
export function builtinFiles(): HomeBuiltInFiles {
  const lead = "To make one of these readable by the AI, give it a rule of your own under ";
  const tail = ": your rules are checked first.";
  return {
    kinds: BUILTIN_FILE_KINDS.map((k) => ({ words: capital(k.words), names: [...k.names], where: k.where ?? null })),
    templates: [...BUILTIN_TEMPLATE_EXAMPLES],
    places: [...BUILTIN_HOME_PLACES],
    system: [...BUILTIN_SYSTEM_PLACES],
    also: [
      `In \`~/.ssh\`, its public files are not: ${SSH_PUBLIC_EXAMPLES.map((n) => `\`${n}\``).join(", ")}.`,
      "And the same stores in a Windows profile, under WSL.",
      "And OpenCode's and Goose's own data, wherever it is kept.",
    ].map(marked),
    found:
      "Mandu also keeps secret a settings file it found a saved password or key in, and a personal document it recognised, " +
      "such as a bank statement or a lab report. It looks for these when an agent starts.",
    change: {
      text: `${lead}Your rules${tail}`,
      parts: [{ kind: "text", text: lead }, { kind: "link", text: "Your rules", to: "your-rules" }, { kind: "text", text: tail }],
    },
  };
}
