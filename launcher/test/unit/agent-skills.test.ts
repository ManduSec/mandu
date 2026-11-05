/**
 * agent-skills — the public agent skills (`skills/<name>/SKILL.md` at the
 * repository root, installed with `npx skills add mandusec/mandu`;
 * docs/design/agents/handling-prompt.md §12) stay installable and true:
 *
 *   - each SKILL.md opens with the Agent Skills frontmatter: `name` equal to
 *     its directory (1-64 lowercase letters, digits and single hyphens) and a
 *     `description` of 1-1024 characters, as the agentskills.io spec says;
 *   - every `mandu <verb> [--flag]` a skill names is a real command: the verb
 *     is in the launcher's command table (RESERVED_SUBCOMMANDS, or an agent a
 *     launch takes) and each flag is in that verb's own usage text (a launch's
 *     in the launch parser), so a skill never teaches a command that fails;
 *   - every link is an absolute URL into the public repository naming a file
 *     (and a heading) that exists: an installed skill has no repo around it;
 *   - each skill keeps the safety words: the human decides approvals and rules;
 *   - README.md and docs/usage.md give the install command (so this file reads
 *     docs and runs in the docs lane, launcher.docs).
 *
 * Reads only the tree; no arbiter, no network, no HOME.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { DOCS_BASE_URL } from "../../src/docs-url.js";
import { RESERVED_SUBCOMMANDS } from "../../src/subcommands.js";
import { SUBCOMMAND_USAGE } from "../../src/subcommand-help.js";
import { usageText } from "../../src/usage.js";
import { TARGETS } from "../../src/types.js";

const PKG_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const REPO_ROOT = join(PKG_ROOT, "..");
const SKILLS = join(REPO_ROOT, "skills");

interface Skill { dir: string; file: string; text: string; front: Record<string, string>; body: string }

/** The frontmatter as `key: value` lines. A strict subset of YAML, so a file
 *  this accepts is valid YAML for every reader: one line per key, a plain
 *  scalar that holds no `: ` or ` #` and does not open with a YAML indicator. */
export function parseFrontmatter(text: string): { front: Record<string, string>; body: string } {
  const m = /^---\n([\s\S]*?)\n---\n/.exec(text);
  if (!m) throw new Error("no --- frontmatter block at the top");
  const front: Record<string, string> = {};
  for (const line of m[1]!.split("\n")) {
    const kv = /^([a-z][a-z-]*): (.+)$/.exec(line);
    if (!kv) throw new Error(`not a one-line key: value: ${JSON.stringify(line)}`);
    const [, key, value] = kv as unknown as [string, string, string];
    if (key in front) throw new Error(`duplicate key ${key}`);
    if (/: | #|\t/.test(value) || /^[[\]{}&*!|>'"%@`#,?:-]/.test(value)) {
      throw new Error(`${key}: not a plain YAML scalar (quote-free, no ": " or " #"): ${value.slice(0, 60)}`);
    }
    front[key] = value.trim();
  }
  return { front, body: text.slice(m[0].length) };
}

function skills(): Skill[] {
  return readdirSync(SKILLS).filter((d) => statSync(join(SKILLS, d)).isDirectory()).map((dir) => {
    const file = join(SKILLS, dir, "SKILL.md");
    const text = readFileSync(file, "utf8");
    return { dir, file, text, ...parseFrontmatter(text) };
  });
}

/** One `mandu …` mention: the verb (or a top-level flag), what follows it. */
interface Mention { verb: string; flags: string[]; sub?: string; where: string }

/** The command-shaped text of a skill: its inline code spans and the lines of
 *  its fenced blocks, where a command's flags are written. */
function codeSegments(body: string): string[] {
  const out: string[] = [];
  let fenced = false;
  for (const line of body.split("\n")) {
    if (/^\s*```/.test(line)) { fenced = !fenced; continue; }
    if (fenced) { out.push(line); continue; }
    for (const m of line.matchAll(/`([^`]+)`/g)) out.push(m[1]!);
  }
  return out;
}

// `mandu` as a word of its own: not a part of a path or a host (github.com/
// mandusec/mandu/…, ManduSec/mandu), except the npm package's own name.
const MANDU = /(?:(?<![\w./-])|(?<=@mandusec\/))mandu[ \t]+([^\s`'"),;|&#]+)/g;

export function mentions(segment: string, where: string): Mention[] {
  const out: Mention[] = [];
  for (const m of segment.matchAll(MANDU)) {
    const verb = m[1]!;
    // The rest of this command: up to a comment, a separator or the next `mandu`.
    let rest = segment.slice(m.index! + m[0].length);
    rest = rest.split(/\s#|;|&&|\|\||\||\)|,\s|\bor:\s/)[0]!;
    const next = rest.search(/(?<![\w./-])mandu\s/);
    if (next >= 0) rest = rest.slice(0, next);
    const words = rest.trim().split(/\s+/).filter(Boolean);
    const flags = words.filter((w) => /^--?[a-zA-Z]/.test(w)).map((w) => w.replace(/=.*$/, ""));
    const sub = verb === "policy" ? words[0] : undefined;
    out.push({ verb, flags, ...(sub ? { sub } : {}), where });
  }
  return out;
}

/** Every flag the launch parser accepts: its `a === "--x"` / `startsWith("--x=")` arms. */
function launchFlags(): Set<string> {
  const src = readFileSync(join(PKG_ROOT, "src", "parse.ts"), "utf8");
  const flags = new Set<string>();
  for (const m of src.matchAll(/a === "(--?[a-z][a-z0-9-]*)"/g)) flags.add(m[1]!);
  for (const m of src.matchAll(/a\.startsWith\("(--[a-z][a-z0-9-]*)="\)/g)) flags.add(m[1]!);
  return flags;
}

/** The flags a verb's usage text names (`--x`, `-y`). */
function usageFlags(text: string): Set<string> {
  return new Set([...text.matchAll(/(?<![\w-])(--?[a-zA-Z][\w-]*)/g)].map((m) => m[1]!));
}

const SLUG = (h: string): string => h.trim().toLowerCase().replace(/[^\w\- ]/g, "").replace(/ /g, "-");

test("the skills tree holds the two public skills", () => {
  assert.deepEqual(skills().map((s) => s.dir).sort(), ["mandu", "mandu-setup"]);
});

test("each SKILL.md has the spec's frontmatter: name = its directory, a description within 1-1024 characters", () => {
  for (const s of skills()) {
    const { name, description } = s.front;
    assert.equal(name, s.dir, `${s.file}: name must equal the directory`);
    assert.ok(name!.length >= 1 && name!.length <= 64, `${s.file}: name is 1-64 characters`);
    assert.match(name!, /^[a-z0-9]+(-[a-z0-9]+)*$/, `${s.file}: lowercase letters, digits, single hyphens, none at an end`);
    assert.ok(description && description.length >= 1 && description.length <= 1024, `${s.file}: description is 1-1024 characters (${description?.length})`);
    assert.doesNotMatch(description, /[<>]/, `${s.file}: no angle brackets in the description (some readers refuse them)`);
    for (const k of Object.keys(s.front)) {
      assert.ok(["name", "description", "license", "compatibility", "metadata", "allowed-tools"].includes(k), `${s.file}: ${k} is not a spec field`);
    }
    assert.ok(s.body.split("\n").length < 500, `${s.file}: the spec asks for a SKILL.md under 500 lines`);
  }
});

test("the frontmatter reader refuses what is not plain one-line YAML", () => {
  assert.deepEqual(parseFrontmatter("---\nname: a\ndescription: b c\n---\nbody\n").front, { name: "a", description: "b c" });
  assert.throws(() => parseFrontmatter("# no frontmatter\n"), /no --- frontmatter/);
  assert.throws(() => parseFrontmatter("---\nname: a\ndescription: use: when\n---\n"), /plain YAML scalar/);
  assert.throws(() => parseFrontmatter("---\nname: a\ndescription: \"quoted\"\n---\n"), /plain YAML scalar/);
  assert.throws(() => parseFrontmatter("---\nname: a\nname: b\n---\n"), /duplicate/);
});

test("the mention reader finds verbs, sub-verbs and flags, and skips paths and hosts", () => {
  assert.deepEqual(mentions("mandu why .env --to api.stripe.com", "t").map((m) => [m.verb, m.flags]), [["why", ["--to"]]]);
  assert.deepEqual(mentions("mandu policy suggest --dry-run", "t")[0]!.sub, "suggest");
  assert.deepEqual(mentions("npx @mandusec/mandu scan", "t").map((m) => m.verb), ["scan"]);
  assert.deepEqual(mentions("gh release download -R ManduSec/mandu -p '*'", "t"), []);
  assert.deepEqual(mentions("https://github.com/mandusec/mandu/blob/main/docs/usage.md", "t"), []);
  assert.deepEqual(mentions("mandu stop --all   # stop", "t")[0]!.flags, ["--all"]);
  assert.deepEqual(mentions("mandu claude     # or: mandu codex, mandu goose", "t").map((m) => m.verb), ["claude", "codex", "goose"]);
});

test("every `mandu <command> [--flag]` a skill names exists in the launcher's command table", () => {
  const agents = new Set<string>(TARGETS.filter((t) => t !== "shell"));
  const launch = launchFlags();
  const top = usageFlags(usageText());
  const all: Mention[] = [];
  for (const s of skills()) {
    for (const seg of codeSegments(s.body)) all.push(...mentions(seg, `${s.dir}: \`${seg}\``));
    // Prose names commands too (the description, a sentence): the verb must exist.
    const prose = [s.front["description"] ?? "", s.body.replace(/```[\s\S]*?```/g, "").replace(/`[^`]*`/g, "")].join("\n");
    for (const m of prose.matchAll(MANDU)) all.push({ verb: m[1]!.replace(/[.:]$/, ""), flags: [], where: `${s.dir} (prose)` });
  }
  assert.ok(all.length >= 20, `expected the skills to name the everyday commands, found ${all.length}`);
  for (const m of all) {
    if (m.verb.startsWith("-")) {
      assert.ok(top.has(m.verb), `${m.where}: \`mandu ${m.verb}\` is not a top-level option of mandu --help`);
      continue;
    }
    if (agents.has(m.verb)) {
      for (const f of m.flags) assert.ok(launch.has(f) || top.has(f), `${m.where}: launch flag ${f} does not exist`);
      continue;
    }
    assert.ok(RESERVED_SUBCOMMANDS.has(m.verb), `${m.where}: \`mandu ${m.verb}\` is not a command (verbs: ${[...RESERVED_SUBCOMMANDS].join(", ")}; agents: ${[...agents].join(", ")})`);
    const usage = (SUBCOMMAND_USAGE[m.verb] ?? []).join("\n");
    const known = usageFlags(usage);
    for (const f of m.flags) {
      assert.ok(known.has(f) || f === "--help" || f === "-h", `${m.where}: \`mandu ${m.verb} ${f}\`: ${f} is not in mandu ${m.verb} --help`);
    }
    if (m.sub) assert.ok(usage.includes(`mandu ${m.verb} ${m.sub}`), `${m.where}: \`mandu ${m.verb} ${m.sub}\` is not a sub-command`);
  }
});

test("every link is an absolute URL into the public repository, to a file and heading that exist", () => {
  for (const s of skills()) {
    const links = [...s.body.matchAll(/\]\(([^)\s]+)\)/g)].map((m) => m[1]!);
    for (const href of links) {
      assert.ok(href.startsWith(DOCS_BASE_URL), `${s.dir}: link ${href} is not under ${DOCS_BASE_URL} (an installed skill has no repository around it)`);
      const [path, anchor] = href.slice(DOCS_BASE_URL.length).split("#") as [string, string | undefined];
      assert.ok(existsSync(join(REPO_ROOT, path)), `${s.dir}: ${href} names ${path}, which does not exist`);
      if (anchor) {
        const slugs = readFileSync(join(REPO_ROOT, path), "utf8").split("\n").filter((l) => /^#{1,6} /.test(l)).map((l) => SLUG(l.replace(/^#+ /, "")));
        assert.ok(slugs.includes(anchor), `${s.dir}: ${href}: no heading #${anchor} in ${path}`);
      }
    }
  }
});

test("the front page and the user guide give the install command, and the guide names each skill", () => {
  const readme = readFileSync(join(REPO_ROOT, "README.md"), "utf8");
  const guide = readFileSync(join(REPO_ROOT, "docs/usage.md"), "utf8");
  assert.ok(readme.includes("npx skills add mandusec/mandu"), "README.md: the install command");
  assert.ok(readme.includes("](docs/usage.md#agent-skills)"), "README.md: links the guide's section");
  assert.match(guide, /^## Agent skills$/m, "docs/usage.md: the section the README links");
  assert.ok(guide.includes("npx skills add mandusec/mandu"), "docs/usage.md: the install command");
  for (const s of skills()) assert.ok(guide.includes(`**\`${s.dir}\`**`), `docs/usage.md: names the ${s.dir} skill`);
});

test("each skill keeps the safety words: the human answers approvals and changes rules, and the agent never unmasks", () => {
  const byName = new Map(skills().map((s) => [s.dir, s.text]));
  for (const [name, text] of byName) {
    assert.match(text, /\*\*Never\*\*|never/i, name);
    assert.match(text, /answer an Approvals card/, `${name}: never answer an Approvals card`);
    assert.match(text, /policy\.yaml/, `${name}: names the rules file the agent must not edit`);
    assert.match(text, /dashboard password/, `${name}: never the dashboard password`);
    assert.match(text, /manipulate you/, `${name}: says the agent may be reading text written to steer it`);
    // A skill teaches no way around a protection: no opt-out flag, no off switch.
    assert.doesNotMatch(text, /--no-[a-z]/, `${name}: names a --no-… opt-out`);
    assert.doesNotMatch(text, /mandu mode off|MANDU_[A-Z_]+=0/, `${name}: names a way to turn protection off`);
  }
  const mandu = byName.get("mandu")!;
  assert.match(mandu, /opaque handle/, "the handling prompt's word for a token");
  assert.match(mandu, /single-quote it/, "the shell-quoting rule");
  assert.match(mandu, /Never guess, reconstruct, decode or restate/);
  assert.match(mandu, /make the same call again/, "the retry after the user's answer (handling-prompt.md §8)");
  assert.match(mandu, /Do not refuse a call yourself/);
});
