/**
 * own-paths.test — the launcher's helpers over the path table
 * (src/own-paths.ts; on-disk-layout.md §4, §5): the per-path override
 * helpers left for the locations outside the home, and the home's
 * carve-outs from its one deny rule, per mode.
 *
 * Run: npm run test:unit
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { stateAxes } from "../axes.js";
import { cwdsInsideHome, homeCarveOuts, pathAndDefault } from "../../src/own-paths.js";

stateAxes("secrets"); // the carve-out tests name each mode's axes explicitly below

test("pathAndDefault: the default alone, or the default then the override", () => {
  assert.deepEqual(pathAndDefault("install-prefix", {}, "/h"), ["/h/.local/share/mandu"]);
  assert.deepEqual(pathAndDefault("install-prefix", { MANDU_PREFIX: "" }, "/h"), ["/h/.local/share/mandu"], "empty counts as unset");
  assert.deepEqual(pathAndDefault("install-prefix", { MANDU_PREFIX: "/opt/m" }, "/h"), ["/h/.local/share/mandu", "/opt/m"]);
  assert.deepEqual(pathAndDefault("install-prefix", { MANDU_PREFIX: "/h/.local/share/mandu" }, "/h"), ["/h/.local/share/mandu"], "no duplicate");
  assert.deepEqual(pathAndDefault("state-root", { MANDU_HOME: "/m" }, "/h"), ["/m/state"], "an entry in the home has no override");
  // The retired per-path overrides move nothing (on-disk-layout.md §9.1).
  assert.deepEqual(pathAndDefault("symbol-db", { MANDU_SYMBOL_DB: "/o/x.db" }, "/h"), ["/h/.mandu/state/mandu.db"]);
  assert.deepEqual(pathAndDefault("events", { MANDU_EVENT_DIR: "/o/ev", MANDU_HOME: "/m" }, "/h"), ["/m/events"]);
});

test("pathAndDefault: pure, never process.env", () => {
  const saved = process.env["MANDU_PREFIX"];
  process.env["MANDU_PREFIX"] = "/must/not/be/read";
  try {
    assert.deepEqual(pathAndDefault("install-prefix", {}, "/h"), ["/h/.local/share/mandu"]);
  } finally {
    if (saved === undefined) delete process.env["MANDU_PREFIX"];
    else process.env["MANDU_PREFIX"] = saved;
  }
});

const HOME = "/h/.mandu";
const AV = "/h/.mandu/state/workspaces/proj-0123456789ab/agentview";
const REPO = "/h/.mandu/state/workspaces/proj-0123456789ab/repo.git";
const AXES = {
  off: { confidentiality: false, integrity: false },
  secrets: { confidentiality: true, integrity: false },
  injection: { confidentiality: false, integrity: true },
  full: { confidentiality: true, integrity: true },
} as const;

test("homeCarveOuts per mode: none in `off` and `secrets`; the AgentView in `injection`; the AgentView and its repo.git in `full`", () => {
  assert.deepEqual(homeCarveOuts(AXES.off, HOME, [AV]), []);
  assert.deepEqual(homeCarveOuts(AXES.secrets, HOME, [AV]), [], "`secrets` mode has no AgentView to keep: the whole home is hidden");
  assert.deepEqual(homeCarveOuts(AXES.injection, HOME, [AV]), [AV]);
  assert.deepEqual(homeCarveOuts(AXES.full, HOME, [AV]), [AV, REPO]);
  assert.deepEqual(homeCarveOuts(AXES.full, HOME, [`${AV}/`, AV, undefined]), [AV, REPO], "a trailing slash, a duplicate, an unset cwd");
});

test("homeCarveOuts: only an exact <home>/state/workspaces/<id>/agentview counts; nothing else opens the home", () => {
  for (const bad of [
    HOME, `${HOME}/state`, `${HOME}/state/workspaces`, `${HOME}/state/workspaces/proj`,
    `${HOME}/state/workspaces/proj/repo.git`, `${HOME}/state/workspaces/proj/agentview/src`,
    `${HOME}/state/workspaces/a/b/agentview`, `${HOME}/cache/object-twins/agentview`, `${HOME}/agentview`,
    `${HOME}/state/workspaces/../workspaces/proj/agentview`, `${HOME}/state/workspaces/./agentview`,
    "/elsewhere/state/workspaces/proj/agentview", "relative/state/workspaces/proj/agentview", "",
  ]) {
    assert.deepEqual(homeCarveOuts(AXES.full, HOME, [bad]), [], bad);
  }
  // MANDU_HOME moves the whole home, carve-outs included.
  assert.deepEqual(homeCarveOuts(AXES.injection, "/m", ["/m/state/workspaces/w/agentview"]), ["/m/state/workspaces/w/agentview"]);
  assert.deepEqual(homeCarveOuts(AXES.injection, "/m", [AV]), [], "an AgentView under another home");
});

test("cwdsInsideHome: a working directory in the home outside every carve-out is named (the launch refuses)", () => {
  assert.deepEqual(cwdsInsideHome(HOME, [], ["/h/work", "/h"]), [], "the user's home or a project beside ~/.mandu");
  assert.deepEqual(cwdsInsideHome(HOME, [], [HOME]), [HOME]);
  assert.deepEqual(cwdsInsideHome(HOME, [], [`${HOME}/state`]), [`${HOME}/state`]);
  assert.deepEqual(cwdsInsideHome(HOME, [AV], [AV, `${AV}/src`]), [], "the AgentView carve-out is the agent's cwd in the integrity modes");
  assert.deepEqual(cwdsInsideHome(HOME, [AV], [`${HOME}/state/workspaces/proj-0123456789ab`]), [`${HOME}/state/workspaces/proj-0123456789ab`]);
  assert.deepEqual(cwdsInsideHome(HOME, [], ["/h/.mandu-other"]), [], "whole components");
});
