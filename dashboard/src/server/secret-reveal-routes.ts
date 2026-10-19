/**
 * server/secret-reveal-routes — POST /api/home/reveal: the product page's
 * "Show the real value" (dashboard.md §4.25b "Showing a real value").
 * Mandu-new.
 *
 * ONE value, of ONE secret, of ONE session, to a signed-in person. A POST,
 * so the server's global gate has already required the CSRF header and the
 * admin session (a program the agent runs has neither). The page names the
 * secret by its opaque ref (view-model/secret-ref.ts); the route recomputes
 * the refs of the secrets that session RECORDED (agent-page.ts
 * `revealableSecrets`, over its believed events) and resolves only a match,
 * through the source's human-plane read. So it is never a general
 * desymbolize: an unknown ref, another session's secret or a token the
 * session never recorded resolves nothing (404). The value goes back in the
 * answer only; it is never logged. Mirrors /api/prompt-filters/reveal's
 * scoping (prompt-filter-routes.ts `postPromptReveal`).
 */
import { type IncomingMessage, type ServerResponse } from "node:http";

import { json, readJson } from "./http-util.js";
import { type EventSource } from "../event-source.js";
import { believedEvents } from "../event-model.js";
import { toSessionViewModel } from "../view-model.js";
import { revealableSecrets } from "../view-model/agent-page.js";
import { SECRET_REF_RE, secretRef } from "../view-model/secret-ref.js";

export async function postSecretReveal(
  source: EventSource,
  req: IncomingMessage,
  res: ServerResponse,
  log: (msg: string) => void,
): Promise<void> {
  const body = (await readJson(req).catch(() => null)) as { session?: unknown; ref?: unknown } | null;
  const session = typeof body?.session === "string" ? body.session : "";
  const ref = typeof body?.ref === "string" ? body.ref : "";
  if (!session || !SECRET_REF_RE.test(ref)) {
    json(res, 400, { error: "session and ref are required" });
    return;
  }
  if (!source.desymbolize) {
    json(res, 501, { error: "this dashboard has no protection service to ask" });
    return;
  }
  let events;
  try {
    events = await source.readEvents(session);
  } catch {
    json(res, 502, { error: "could not read the session" });
    return;
  }
  // Only what the session's believed events recorded (a claimed event,
  // arbiter-human-plane.md §10.2, cannot add a token to the set).
  const believed = believedEvents(events);
  const vm = believed.length ? toSessionViewModel(session, believed) : null;
  const name = vm ? [...revealableSecrets(vm)].find((n) => secretRef(session, n) === ref) : undefined;
  if (!name) {
    json(res, 404, { error: "this session recorded no such secret" });
    return;
  }
  let value: string;
  try {
    value = await source.desymbolize(name);
  } catch {
    json(res, 502, { error: "the protection service could not show it" });
    return;
  }
  // The arbiter answers a token it does not hold with the token itself.
  if (value === name || value.includes("$MDU:")) {
    json(res, 404, { error: "the protection service no longer holds its value" });
    return;
  }
  log(`showed one secret value of session ${session} to a signed-in viewer`);
  json(res, 200, { value });
}
