/**
 * platform/index — the ONE place that reads process.platform (spec §2 rule).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy):
 *   NEW Mandu code. Selects the platform implementation; win32 is admitted by
 *   the interface but unimplemented (spec §8) and throws a clear error.
 */
import type { Platform } from "./types.js";
import { linuxPlatform } from "./linux.js";
import { darwinPlatform } from "./darwin.js";

export function getPlatform(plat: NodeJS.Platform = process.platform): Platform {
  if (plat === "linux") return linuxPlatform;
  if (plat === "darwin") return darwinPlatform;
  throw new Error(`mandu: platform '${plat}' is not supported yet (Linux + macOS only; Windows is designed but unbuilt)`);
}

export type {
  Platform, ScopePlan, Availability, AgentTree, TrackTreeOpts, KillTreeOpts, KillTreeResult,
} from "./types.js";
