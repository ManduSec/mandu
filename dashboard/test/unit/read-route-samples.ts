/**
 * read-route-samples — one concrete request path per read-gate entry
 * (src/server/read-gate.ts), for the suites that walk a whole table over a
 * real server: test/component/value-gate.test.ts and the stack e2e
 * tests/stack/dashboard-value-gate.test.ts walk the product's READ_ROUTES;
 * the developer view's suites walk its rows too, passing their samples
 * (dashboard.md §4.25ac). A new pattern entry without a sample fails the
 * walk (samplePath throws), so it covers every route.
 */
import { READ_ROUTES, type ReadRoute } from "../../src/server/read-gate.js";

/** Samples: a concrete path for each pattern entry, keyed by the pattern's
 *  source text, and the query each string route needs. `${S}` is the
 *  session id. */
export interface RouteSamples {
  patterns: Record<string, string>;
  queries: Record<string, string>;
}

/** The product's: READ_ROUTES has string paths only, some with a query. */
export const PRODUCT_SAMPLES: RouteSamples = {
  patterns: {},
  queries: {
    "/api/events": "?session=${S}", "/api/stream": "?session=${S}&sinceSeq=0", "/api/home/agent": "?session=${S}",
    "/api/home/original": "?session=${S}&step=tool%3Ac1",
  },
};

/** The request path for one entry, addressing session `sessionId`. */
export function samplePath(route: ReadRoute, sessionId: string, samples: RouteSamples = PRODUCT_SAMPLES): string {
  const raw = typeof route.path === "string" ? route.path + (samples.queries[route.path] ?? "") : samples.patterns[String(route.path)];
  if (raw === undefined) throw new Error(`no sample for ${String(route.path)}: add one beside the table`);
  return raw.replaceAll("${S}", encodeURIComponent(sessionId));
}

/** Every entry of `routes` with its sample path. */
export function allSamples(
  sessionId: string,
  routes: readonly ReadRoute[] = READ_ROUTES,
  samples: RouteSamples = PRODUCT_SAMPLES,
): Array<{ route: ReadRoute; path: string }> {
  return routes.map((route) => ({ route, path: samplePath(route, sessionId, samples) }));
}
