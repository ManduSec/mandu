/**
 * launch-in-dir — `main()` for a test that runs a launch IN-PROCESS, launched
 * for the folder the env it hands `main()` names as PWD.
 *
 * The CLI launches for its real working directory (src/launch-cwd.ts): a
 * `$PWD` naming another folder is ignored. An in-process test cannot chdir
 * per launch (the runner's cwd is the package, shared by every launch in the
 * file), so it declares the launch's folder the way it always has, as the
 * env's PWD, and this hands that folder to `main()` explicitly
 * (`MainOptions.cwd`). A test that spawns the CLI as a child instead gives
 * the child that `cwd` (and PWD agreeing with it), as a shell would.
 *
 * Deliberately no side effect: a launcher test still imports
 * `../lib/private-home.js` itself (test-organization.md §8.4).
 */
import { main as cliMain } from "../../src/run.js";

export function main(argv: string[], env: NodeJS.ProcessEnv = process.env): Promise<number> {
  const dir = env["PWD"];
  return cliMain(argv, env, dir ? { cwd: dir } : {});
}
