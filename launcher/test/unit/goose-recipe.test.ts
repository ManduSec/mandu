/**
 * goose-recipe — `mandu goose run --recipe` (src/goose-recipe.ts): where goose
 * 1.53.0 finds a recipe, what in it is refused (another or a templated
 * provider, sub-recipes, code mode, in the file or a template it includes),
 * and the argv the launch hands goose (the absolute file read, `--provider`
 * pinned). supported-agents.md §5.6.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  gooseRecipeDirs,
  gooseRecipeFindings,
  gooseRecipeIncludes,
  gooseRecipePlan,
  readGooseRecipe,
  resolveGooseRecipe,
  type RecipeFs,
} from "../../src/goose-recipe.js";

/** An in-memory filesystem: path → text. */
function memFs(files: Record<string, string>): RecipeFs {
  return {
    isFile: (p) => p in files,
    read: (p) => { if (!(p in files)) throw new Error(`ENOENT ${p}`); return files[p]!; },
    canonical: (p) => p,
  };
}

const ENV = { HOME: "/home/u", GOOSE_PATH_ROOT: "/g" };
const OK = "version: 1.0.0\ntitle: T\ndescription: d\nprompt: hello\n";

test("findings: another provider (YAML block, flow, JSON) is named; anthropic, unset and null pass", () => {
  assert.deepEqual(gooseRecipeFindings(`${OK}settings:\n  goose_provider: anthropic\n  goose_model: claude-x\n`), []);
  assert.deepEqual(gooseRecipeFindings(`${OK}settings:\n  goose_provider: Anthropic # mine\n`), []);
  assert.deepEqual(gooseRecipeFindings(`${OK}settings:\n  goose_provider: null\n`), []);
  assert.deepEqual(gooseRecipeFindings(`${OK}settings:\n  goose_provider:\n`), []);
  assert.match(gooseRecipeFindings(`${OK}settings:\n  goose_provider: openai\n`).join(), /names the provider `openai`/);
  assert.match(gooseRecipeFindings(`${OK}settings: {goose_model: m, goose_provider: 'ollama'}\n`).join(), /`ollama`/);
  assert.match(gooseRecipeFindings(`${OK}settings:\n  goose_provider:\n    google\n`).join(), /`google`/, "a value on the next line");
  assert.match(gooseRecipeFindings('{"title":"t","settings":{"goose_provider":"openrouter"}}').join(), /`openrouter`/);
  assert.match(gooseRecipeFindings('{\n  "settings": {\n    "goose_provider": "databricks",\n    "goose_model": "m"\n  }\n}').join(), /`databricks`/);
});

test("findings: a templated provider, sub_recipes, a code_execution extension", () => {
  assert.match(gooseRecipeFindings(`${OK}settings:\n  goose_provider: "{{ provider }}"\n`).join(), /template/);
  assert.match(gooseRecipeFindings(`${OK}sub_recipes:\n  - name: a\n    path: a.yaml\n`).join(), /sub_recipes/);
  assert.deepEqual(gooseRecipeFindings(`${OK}sub_recipes: []\n`), [], "an empty list is no sub-recipe");
  assert.match(gooseRecipeFindings(`${OK}extensions:\n  - type: builtin\n    name: code_execution\n`).join(), /code_execution/);
  assert.match(gooseRecipeFindings('{"extensions":[{"type":"platform","name":"code_execution"}]}').join(), /code_execution/);
  assert.deepEqual(gooseRecipeFindings(`${OK}extensions:\n  - type: stdio\n    name: notes\n    cmd: notes-mcp\n`), [], "a stdio MCP server runs inside the wrap");
  assert.deepEqual(gooseRecipeFindings(`${OK}instructions: "{{ task }} with your shell"\nparameters:\n  - key: task\n    input_type: string\n    requirement: required\n    description: d\n`), [], "templates elsewhere are fine");
});

test("includes: literal template names are followed, a computed one is reported", () => {
  assert.deepEqual(gooseRecipeIncludes('{% extends "base.yaml" %}\n{%- include \'part.yaml\' -%}'), { names: ["base.yaml", "part.yaml"], dynamic: false });
  assert.deepEqual(gooseRecipeIncludes("{% include name %}"), { names: [], dynamic: true });
  const fs = memFs({
    "/r/main.yaml": `${OK}{% include "settings.yaml" %}\n`,
    "/r/settings.yaml": "settings:\n  goose_provider: openai\n",
  });
  assert.match(readGooseRecipe("/r/main.yaml", fs).join(), /`openai` \(in \/r\/settings\.yaml\)/);
  assert.match(readGooseRecipe("/r/dyn.yaml", memFs({ "/r/dyn.yaml": `${OK}{% include x %}` })).join(), /computed name/);
  assert.match(readGooseRecipe("/r/missing.yaml", memFs({})).join(), /could not be read/);
});

test("resolve: a .yaml / .json path against the launch directory, ~ expanded, .yml and other paths refused", () => {
  const fs = memFs({ "/w/r.yaml": OK, "/home/u/r/x.json": "{}" });
  assert.deepEqual(resolveGooseRecipe("r.yaml", ENV, "/w", fs), { path: "/w/r.yaml" });
  assert.deepEqual(resolveGooseRecipe("~/r/x.json", ENV, "/w", fs), { path: "/home/u/r/x.json" });
  assert.match((resolveGooseRecipe("gone.yaml", ENV, "/w", fs) as { error: string }).error, /does not exist/);
  assert.match((resolveGooseRecipe("r.yml", ENV, "/w", fs) as { error: string }).error, /not a \.yaml or \.json/);
  assert.match((resolveGooseRecipe("./r", ENV, "/w", fs) as { error: string }).error, /not a \.yaml or \.json/);
});

test("resolve: a name is looked up in goose's directories in its (component-sorted) order; none found is the GitHub case, refused", () => {
  const dirs = gooseRecipeDirs({ ...ENV, GOOSE_RECIPE_PATH: "/z/recipes:rel" }, "/w", memFs({}));
  assert.deepEqual(dirs, ["/g/config/recipes", "/home/u/.agents/recipes", "/w", "/w/.agents/recipes", "/w/.goose/recipes", "/w/rel", "/z/recipes"]);
  // Rust orders `/a/b` before `/a-b` (by component), not by string
  assert.deepEqual(gooseRecipeDirs({ HOME: "/h", GOOSE_PATH_ROOT: "/a", GOOSE_RECIPE_PATH: "/a-b" }, "/w", memFs({})).slice(0, 2), ["/a/config/recipes", "/a-b"]);
  const fs = memFs({ "/w/.goose/recipes/triage.yaml": OK, "/home/u/.agents/recipes/triage.json": "{}" });
  assert.deepEqual(resolveGooseRecipe("triage", ENV, "/w", fs), { path: "/home/u/.agents/recipes/triage.json" }, "the first directory in goose's order wins");
  assert.match((resolveGooseRecipe("nightly", ENV, "/w", fs) as { error: string }).error, /GOOSE_RECIPE_GITHUB_REPO/);
});

test("plan: the recipe's absolute path, `--provider` pinned right after `run`; argv without a recipe untouched", () => {
  const fs = memFs({ "/w/r.yaml": OK });
  assert.deepEqual(
    gooseRecipePlan(["goose", "run", "--recipe", "r.yaml", "--params", "a=b"], ENV, "/w", fs),
    { refusal: null, argv: ["goose", "run", "--provider", "anthropic", "--recipe", "/w/r.yaml", "--params", "a=b"] },
  );
  assert.deepEqual(
    gooseRecipePlan(["goose", "run", "--recipe=r.yaml"], ENV, "/w", fs).argv,
    ["goose", "run", "--provider", "anthropic", "--recipe=/w/r.yaml"],
  );
  assert.deepEqual(
    gooseRecipePlan(["goose", "run", "--provider", "anthropic", "--recipe", "r.yaml"], ENV, "/w", fs).argv,
    ["goose", "run", "--provider", "anthropic", "--recipe", "/w/r.yaml"],
    "the user's own (checked) --provider stays the only one",
  );
  assert.deepEqual(
    gooseRecipePlan(["goose", "run", "--params", "--recipe=x", "--recipe", "r.yaml"], ENV, "/w", fs).argv,
    ["goose", "run", "--provider", "anthropic", "--params", "--recipe=x", "--recipe", "/w/r.yaml"],
    "a flag's value is never read as a recipe",
  );
  for (const argv of [["goose", "run", "-t", "hi"], ["goose", "session"], ["goose", "review"], ["wrapper.sh", "run", "--recipe", "r.yaml"]]) {
    assert.deepEqual(gooseRecipePlan(argv, ENV, "/w", fs), { refusal: null, argv }, argv.join(" "));
  }
});

test("plan: an openai launch pins `--provider openai`, and a recipe naming anthropic there is refused, not silently switched", () => {
  const fs = memFs({ "/w/r.yaml": OK, "/w/a.yaml": `${OK}settings:\n  goose_provider: anthropic\n`, "/w/o.yaml": `${OK}settings:\n  goose_provider: openai\n` });
  assert.deepEqual(gooseRecipePlan(["goose", "run", "--recipe", "r.yaml"], ENV, "/w", fs, "openai").argv, ["goose", "run", "--provider", "openai", "--recipe", "/w/r.yaml"]);
  assert.equal(gooseRecipePlan(["goose", "run", "--recipe", "o.yaml"], ENV, "/w", fs, "openai").refusal, null);
  const r = gooseRecipePlan(["goose", "run", "--recipe", "a.yaml"], ENV, "/w", fs, "openai").refusal;
  assert.match(r ?? "", /goose_provider names the provider `anthropic`/);
  assert.match(r ?? "", /This launch routes Goose's openai provider/);
});

test("plan: a recipe Mandu cannot run is refused with the file and every reason", () => {
  const fs = memFs({ "/w/r.yaml": `${OK}settings:\n  goose_provider: openai\nsub_recipes:\n  - name: s\n    path: s.yaml\n` });
  const r = gooseRecipePlan(["goose", "run", "--recipe", "r.yaml"], ENV, "/w", fs);
  assert.match(r.refusal!, /^mandu: refusing `goose run --recipe r\.yaml` \(\/w\/r\.yaml\): /);
  assert.match(r.refusal!, /`openai`.*sub_recipes/);
  assert.match(gooseRecipePlan(["goose", "run", "--recipe", "nightly"], ENV, "/w", fs).refusal!, /no local recipe `nightly`/);
});

test("the real filesystem: a symlinked recipe is not a regular file (goose refuses it too)", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-goose-recipe-"));
  try {
    mkdirSync(join(dir, "w"));
    writeFileSync(join(dir, "real.yaml"), OK);
    symlinkSync(join(dir, "real.yaml"), join(dir, "w", "link.yaml"));
    writeFileSync(join(dir, "w", "plain.yaml"), OK);
    assert.deepEqual(resolveGooseRecipe("plain.yaml", ENV, join(dir, "w")), { path: join(dir, "w", "plain.yaml") });
    assert.ok("error" in resolveGooseRecipe("link.yaml", ENV, join(dir, "w")));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
