/**
 * goose-recipe — `mandu goose run --recipe <r>`: read the recipe before the
 * launch, refuse one Mandu could not run safely or honestly, and pin the
 * provider so the recipe cannot pick another (supported-agents.md §5.6).
 *
 * WHAT A RECIPE CAN DO (goose 1.53.0, crates/goose/src/recipe/mod.rs and
 * goose-cli/src/session/builder.rs, read 2026-10-06):
 *   - `settings.goose_provider` / `goose_model`: the session's provider is
 *     `--provider`, then a resumed session's saved one, then the RECIPE's,
 *     then env GOOSE_PROVIDER, then the config. A recipe therefore outranks
 *     the env routing Mandu sets (goose-route.ts). The launch pins
 *     `--provider <routed>` on the argv, which outranks the recipe whatever
 *     it renders to (recipes are Jinja templates with `--params` and
 *     `{% include %}`, which the launcher cannot render): the model calls go
 *     through the proxy. A recipe that NAMES another provider (or a templated
 *     one) is refused rather than silently switched, as goose-route.ts
 *     refuses a config that names one.
 *   - `sub_recipes` (and `--sub-recipe`): run only as `delegate{source}`,
 *     which the wire refuses (tool-gate-surface.ts: a sub-recipe's settings
 *     name its subagent's provider above GOOSE_SUBAGENT_PROVIDER). Refused
 *     here up front, since they could never run.
 *   - `extensions`: stdio MCP servers (host subprocesses of goose, so inside
 *     the wrap like a `--with-extension`), streamable-HTTP ones (like
 *     `--with-streamable-http-extension`: their tool results reach the model
 *     through the proxy) and builtins. A `code_execution` builtin is code
 *     mode (decision D4), refused as `--with-builtin code_execution` is.
 *   - `retry.checks` / `on_failure`: shell commands goose runs itself, inside
 *     the wrap; their output decides a retry and is not sent to the model.
 *   - `parameters` of `input_type: file`: goose reads the named file into the
 *     prompt, inside the wrap, where a labelled secret file is its twin.
 *   - Where the recipe comes from: a `.yaml` / `.json` path, else a name
 *     looked up in goose's local recipe directories, else (with
 *     GOOSE_RECIPE_GITHUB_REPO) a GitHub fetch through `gh`. The launcher
 *     resolves the name the way goose does (local_recipes.rs) and hands goose
 *     the ABSOLUTE path it read, so goose runs the file Mandu checked; a
 *     recipe it cannot find locally (the GitHub fetch) is refused.
 *
 * The scan below reads the recipe text (and the files its `{% include %}` /
 * `{% extends %}` name) without rendering it: the provider pin, the wire's
 * `delegate{source}` refusal and the `execute_typescript` stub are what hold
 * whatever the template renders to; the scan makes the refusal honest.
 *
 * Pure except readGooseRecipe / gooseRecipePlan's default reader;
 * unit-tested in test/unit/goose-recipe.test.ts.
 */
import { existsSync, lstatSync, readFileSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, join, normalize, resolve } from "node:path";
import { gooseFlagValues, gooseValueFlags, readGooseArgv } from "./goose-argv.js";
import { GOOSE_ROUTED_PROVIDER, GOOSE_ROUTED_SPELLED, gooseConfigDir } from "./goose-route.js";

/** Goose 1.53.0 RECIPE_FILE_EXTENSIONS (no `.yml`). */
const RECIPE_EXTENSIONS = ["yaml", "json"] as const;

/** How the launcher reads the filesystem (injectable for tests). */
export interface RecipeFs {
  isFile(p: string): boolean;
  read(p: string): string;
  /** realpath, or the input when it cannot be resolved (goose's
   *  `canonicalize().unwrap_or(dir)`). */
  canonical(p: string): string;
}

export const REAL_RECIPE_FS: RecipeFs = {
  isFile: (p) => { try { return lstatSync(p).isFile(); } catch { return false; } },
  read: (p) => readFileSync(p, "utf8"),
  canonical: (p) => { try { return existsSync(p) ? realpathSync(p) : p; } catch { return p; } },
};

/** Rust's `PathBuf` ordering: component by component, each compared by its
 *  bytes (not the whole string: `/a/b` sorts before `/a-b`). */
function comparePaths(a: string, b: string): number {
  const ca = a.split("/").filter(Boolean);
  const cb = b.split("/").filter(Boolean);
  const absA = a.startsWith("/"), absB = b.startsWith("/");
  if (absA !== absB) return absA ? -1 : 1; // RootDir sorts before a Normal component
  for (let i = 0; i < Math.min(ca.length, cb.length); i++) {
    const x = Buffer.from(ca[i]!), y = Buffer.from(cb[i]!);
    const c = Buffer.compare(x, y);
    if (c !== 0) return c;
  }
  return ca.length - cb.length;
}

/** Goose's local recipe directories, in its search order (1.53.0
 *  local_recipes.rs local_recipe_dirs): the working directory, each
 *  GOOSE_RECIPE_PATH entry, `<config>/recipes`, `./.goose/recipes`,
 *  `./.agents/recipes`, `~/.agents/recipes`; canonicalized, sorted, deduped. */
export function gooseRecipeDirs(env: Record<string, string | undefined>, cwd: string, fs: RecipeFs = REAL_RECIPE_FS): string[] {
  const dirs: string[] = [cwd];
  const rp = env["GOOSE_RECIPE_PATH"];
  if (rp) for (const d of rp.split(":")) dirs.push(resolve(cwd, d));
  dirs.push(join(gooseConfigDir(env), "recipes"));
  dirs.push(join(cwd, ".goose", "recipes"));
  dirs.push(join(cwd, ".agents", "recipes"));
  dirs.push(join(env["HOME"] || homedir(), ".agents", "recipes"));
  const out = [...new Set(dirs.map((d) => fs.canonical(d)))];
  out.sort(comparePaths);
  return out;
}

/** Where goose would read `--recipe <name>` from, or why the launcher cannot
 *  tell. Pure over `fs`. */
export function resolveGooseRecipe(
  name: string,
  env: Record<string, string | undefined>,
  cwd: string,
  fs: RecipeFs = REAL_RECIPE_FS,
): { path: string } | { error: string } {
  const home = env["HOME"] || homedir();
  if (RECIPE_EXTENSIONS.some((e) => name.endsWith(`.${e}`))) {
    const p = name.startsWith("~/") ? join(home, name.slice(2)) : resolve(cwd, name);
    return fs.isFile(p) ? { path: p } : { error: `the recipe file ${p} does not exist (or is not a regular file)` };
  }
  if (/[/\\]/.test(name) || name.startsWith("~") || name.startsWith(".") || /\.[^./\\]+$/.test(basename(name))) {
    return { error: `\`${name}\` is not a .yaml or .json recipe file` };
  }
  for (const dir of gooseRecipeDirs(env, cwd, fs)) {
    for (const e of RECIPE_EXTENSIONS) {
      const p = join(dir, `${name}.${e}`);
      if (fs.isFile(p)) return { path: p };
    }
  }
  return {
    error: `no local recipe \`${name}\` (.yaml or .json) in goose's recipe directories; Mandu reads a recipe before the ` +
      "launch, so a recipe goose would fetch from GOOSE_RECIPE_GITHUB_REPO is not one it can run",
  };
}

/** A recipe's top-level scalar `key: value` (YAML or JSON spelling) found
 *  anywhere in its text: each value as written, quotes stripped; a value on
 *  the next, deeper-indented line is read too. Pure. */
function keyValues(text: string, key: string): string[] {
  const out: string[] = [];
  const lines = text.split(/\r?\n/);
  const re = new RegExp(`^(\\s*)(?:-\\s+)?["']?${key}["']?\\s*:\\s*(.*)$`);
  const inline = new RegExp(`[{,]\\s*["']?${key}["']?\\s*:\\s*([^,}\\n]*)`, "g");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    const m = re.exec(line);
    if (m) {
      let v = m[2]!;
      if (v.trim() === "" && i + 1 < lines.length) {
        const next = lines[i + 1]!;
        const ind = /^(\s*)/.exec(next)![1]!.length;
        if (ind > m[1]!.length && !/^\s*["']?[A-Za-z_][\w-]*["']?\s*:/.test(next)) v = next;
      }
      out.push(clean(v));
      continue;
    }
    for (const f of line.matchAll(inline)) out.push(clean(f[1]!));
  }
  return out;
}

function clean(v: string): string {
  let s = v.replace(/\s+#.*$/, "").trim().replace(/,$/, "").trim();
  if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) s = s.slice(1, -1);
  return s.trim();
}

const UNSET = new Set(["", "null", "~", "[]", "{}"]);
const TEMPLATED = /\{\{|\{%/;

/** What in one recipe text keeps Mandu from running it, as phrases. Pure. */
export function gooseRecipeFindings(text: string, routed: string = GOOSE_ROUTED_PROVIDER): string[] {
  const bad: string[] = [];
  for (const v of keyValues(text, "goose_provider")) {
    if (UNSET.has(v.toLowerCase())) continue;
    if (TEMPLATED.test(v)) bad.push(`its settings.goose_provider is a template (\`${v}\`) Mandu cannot read before the launch`);
    else if (v.toLowerCase() !== routed) bad.push(`its settings.goose_provider names the provider \`${v}\``);
  }
  for (const v of keyValues(text, "sub_recipes")) {
    if (UNSET.has(v)) continue;
    bad.push("it has sub_recipes, which run only through `delegate` with a `source`, refused on the wire (a sub-recipe's settings name its subagent's provider)");
    break;
  }
  for (const v of keyValues(text, "name")) {
    if (v === "code_execution") {
      bad.push("it enables code_execution (code mode: model-written TypeScript calling tools inside Goose, where Mandu cannot check them)");
      break;
    }
  }
  return bad;
}

/** The template names a recipe pulls in with `{% include %}`, `{% extends %}`,
 *  `{% import %}` or `{% from … import %}`; `dynamic` when one is not a
 *  string literal. Pure. */
export function gooseRecipeIncludes(text: string): { names: string[]; dynamic: boolean } {
  const names: string[] = [];
  let dynamic = false;
  for (const m of text.matchAll(/\{%-?\s*(?:include|extends|import|from)\s+([^%]*?)\s*-?%\}/g)) {
    const lit = /^(["'])([^"']+)\1/.exec(m[1]!);
    if (lit) names.push(lit[2]!);
    else dynamic = true;
  }
  return { names, dynamic };
}

/** Read a recipe and the templates it includes (from its own directory, as
 *  goose's loader does), and collect the findings. */
export function readGooseRecipe(path: string, fs: RecipeFs = REAL_RECIPE_FS, routed: string = GOOSE_ROUTED_PROVIDER): string[] {
  const dir = dirname(path);
  const seen = new Set<string>();
  const bad: string[] = [];
  const visit = (p: string, depth: number): void => {
    if (seen.has(p)) return;
    seen.add(p);
    let text: string;
    try { text = fs.read(p); } catch (e) {
      bad.push(`${p === path ? "the recipe" : `its template ${p}`} could not be read (${(e as Error).message})`);
      return;
    }
    for (const f of gooseRecipeFindings(text, routed)) bad.push(p === path ? f : `${f} (in ${p})`);
    const inc = gooseRecipeIncludes(text);
    if (inc.dynamic) bad.push("it includes a template by a computed name Mandu cannot read before the launch");
    for (const n of inc.names) {
      if (isAbsolute(n) || normalize(n).split("/").includes("..")) continue; // goose's loader refuses it too
      const q = join(dir, n);
      if (depth >= 8) { bad.push("its templates nest deeper than Mandu reads"); return; }
      if (fs.isFile(q)) visit(q, depth + 1);
    }
  };
  visit(path, 0);
  return [...new Set(bad)];
}

/** What the launch does with a goose argv: the refusal for a recipe it
 *  cannot run, or the argv to launch (unchanged without `--recipe`; with
 *  one, the recipe's absolute path and `--provider <routed>` right after
 *  `run` when the user gave none). */
export function gooseRecipePlan(
  argv: readonly string[],
  env: Record<string, string | undefined>,
  cwd: string,
  fs: RecipeFs = REAL_RECIPE_FS,
  routed: string = GOOSE_ROUTED_PROVIDER,
): { refusal: string | null; argv: string[] } {
  const g = readGooseArgv(argv);
  if (!g || g.command !== "run") return { refusal: null, argv: [...argv] };
  const names = gooseFlagValues(g.rest, "--recipe");
  if (names.length === 0) return { refusal: null, argv: [...argv] };
  const name = names.at(-1)!;
  const shown = `goose run --recipe ${name}`;
  const where = resolveGooseRecipe(name, env, cwd, fs);
  if ("error" in where) {
    return { refusal: `mandu: refusing \`${shown}\`: ${where.error}. Give the recipe's .yaml or .json path.`, argv: [...argv] };
  }
  const bad = readGooseRecipe(where.path, fs, routed);
  if (bad.length > 0) {
    return {
      refusal:
        `mandu: refusing \`${shown}\` (${where.path}): ${bad.join("; ")}. This launch routes Goose's ${routed} provider ` +
        `through Mandu's model proxy (Goose's ${GOOSE_ROUTED_SPELLED} providers can be routed; GOOSE_PROVIDER or \`--provider\` ` +
        "picks one) and checks every tool call; edit the recipe, or run it without `mandu`.",
      argv: [...argv],
    };
  }
  // Every `--recipe` value (Goose keeps the last) becomes the file read here.
  const out = [...argv];
  const at = g.subIndex + 1;
  for (let k = at; k < out.length; k++) {
    const a = out[k]!;
    if (a === "--") break;
    if (a === "--recipe" && k + 1 < out.length) { out[k + 1] = where.path; k++; continue; }
    if (a.startsWith("--recipe=")) { out[k] = `--recipe=${where.path}`; continue; }
    if (gooseValueFlags("run").has(a)) k++;
  }
  if (gooseFlagValues(g.rest, "--provider").length === 0) out.splice(at, 0, "--provider", routed);
  return { refusal: null, argv: out };
}
