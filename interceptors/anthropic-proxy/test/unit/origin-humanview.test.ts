/**
 * origin-humanview.test.ts — the origin the arbiter derives a LEVEL from must be
 * spelled in the arbiter's own world (Plan 9; confidentiality.md §6).
 *
 * ── THE BUG THIS PINS ───────────────────────────────────────────────────────
 *
 * Under fs-sync (DEFAULT-ON for a git workspace) the agent executes the AgentView
 * twin, so the `tool_use` args it echoes back — where `originFor()` reads the
 * origin — carry the AGENTVIEW path. Every path policy the arbiter owns is keyed
 * in HumanView: the catalog says `~/.ssh`, the human labels `~/contracts`, and a
 * derived label is minted on the path the MODEL asked to write. The two never
 * met, so a LABELED file classified `public`: the label was written and never
 * read, and every path-labeled secret silently lost its level in the posture that
 * actually ships.
 *
 * ── AND THE SAFETY PROPERTY THAT MAKES THE FIX LEGAL ────────────────────────
 *
 * The translation rides a SEPARATE field (`originHuman`) that only the
 * CONFIDENTIALITY derivation reads. `origin` and `params` — the TRUST inputs, and
 * `Read`'s trust is DIR-keyed off `params.file_path` — reach the arbiter
 * BYTE-IDENTICAL. A spelling change must never be able to move a datum from
 * UNTRUSTED to TRUSTED; that is the assertion below, and it is the one that would
 * make this an integrity regression if it broke.
 *
 * Run: npm run test:unit
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { rewriteRequest } from "../../src/rewrite-request.js";
import { ViewMap } from "../../src/view-map.js";
import { MockArbiter } from "../helpers/mock-arbiter.js";
import type { MessagesRequest } from "../../src/messages-types.js";

const HUMAN = "/home/u/project/webapp";
const AGENT = "/home/u/.mandu/workspaces/wid/agentview";

function viewMap(): ViewMap {
  return new ViewMap([{ human: HUMAN, agent: AGENT }], { dialect: "posix", home: "/home/u" });
}

/** A Read whose echoed tool_use names the AGENTVIEW twin — what the agent really
 *  sends back, because that is the path it was given to execute. */
function readOfAgentPath(file: string): MessagesRequest {
  return {
    model: "claude-opus-4",
    messages: [
      { role: "user", content: "read it" },
      {
        role: "assistant",
        content: [{ type: "tool_use", id: "tu1", name: "Read", input: { file_path: file } }],
      },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "tu1", content: "…bytes…" }] },
    ],
  } as unknown as MessagesRequest;
}

test("with a view map: the arbiter is told the HUMANVIEW origin for the level", async () => {
  const arbiter = new MockArbiter();
  const vm = viewMap();
  await rewriteRequest(readOfAgentPath(`${AGENT}/contracts/acme.md`), {
    arbiter,
    toHumanView: (o) => vm.mapText(o, "reverse"),
  });

  const cls = arbiter.classifyCalls[0]!;
  assert.equal(
    cls.originHuman, `${HUMAN}/contracts/acme.md`,
    "the LEVEL must be derived from the path the human labeled, not the AgentView twin",
  );
  const sym = arbiter.symbolizeCalls[0]!;
  assert.equal(sym.originHuman, `${HUMAN}/contracts/acme.md`);
});

test("the PATH-ISH PARAMS are translated too — or the catalog overrides the human's label", async () => {
  // Not redundant with `originHuman`. The confidentiality derivation takes the MAX
  // over the origin AND the path-ish params, and a catalog rule matches on the
  // BASENAME (`.env`, `id_rsa`) — which survives any prefix translation. So an
  // untranslated param keeps hitting the catalog, and that hit OVERRIDES the human's
  // label. It cannot leak (max only raises) — it silently kills §6's
  // DECLASSIFICATION: the fixture `.env` a human marked `public` stays strict.
  const arbiter = new MockArbiter();
  const vm = viewMap();
  await rewriteRequest(readOfAgentPath(`${AGENT}/test/fixtures/.env`), {
    arbiter,
    toHumanView: (o) => vm.mapText(o, "reverse"),
  });
  assert.deepEqual(
    arbiter.classifyCalls[0]!.paramsHuman,
    { file_path: `${HUMAN}/test/fixtures/.env` },
  );
});

test("CONTENT fields are translated ONLY in the confidentiality copy; the trust params and the wire keep them as written", async () => {
  // `Write.content` / `Edit.old_string` are the agent's DATA: prefix-substituting
  // inside them ON THE WIRE (or in the trust inputs) is the use-vs-mention
  // corruption the view map's rule 2 forbids. `paramsHuman` is neither: only
  // the arbiter's confidentiality derivation reads it, and for a tool the
  // session's spec does not map it reads EVERY string (plan 10 §11.11), where
  // a labeled path under any key must be spelled as the label is (HumanView).
  // For a mapped tool the extra translated strings are never read.
  const arbiter = new MockArbiter();
  const vm = viewMap();
  const body = {
    model: "claude-opus-4",
    messages: [
      { role: "user", content: "write it" },
      {
        role: "assistant",
        content: [{
          type: "tool_use", id: "tu1", name: "Write",
          input: { file_path: `${AGENT}/out.md`, content: `see ${AGENT}/other.md` },
        }],
      },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "tu1", content: "ok" }] },
    ],
  } as unknown as MessagesRequest;
  const out = await rewriteRequest(body, { arbiter, toHumanView: (o) => vm.mapText(o, "reverse") });

  const cls = arbiter.classifyCalls[0]!;
  const ph = cls.paramsHuman as Record<string, unknown>;
  assert.equal(ph["file_path"], `${HUMAN}/out.md`, "the PATH is translated");
  assert.equal(ph["content"], `see ${HUMAN}/other.md`, "the confidentiality copy reads every string in HumanView");
  assert.equal((cls.params as Record<string, unknown>)["content"], `see ${AGENT}/other.md`, "the TRUST params keep the content as written");
  const echoed = (out.request.messages[1]!.content as Array<{ input: Record<string, unknown> }>)[0]!.input;
  assert.equal(echoed["content"], `see ${AGENT}/other.md`, "the wire keeps the content as written");
});

test("THE SAFETY PROPERTY: the TRUST inputs reach the arbiter byte-identical", async () => {
  // `Read`'s trust is DIR-keyed off params.file_path (claude-code-inbound.ts). If
  // the translation touched `origin` or `params`, a spelling change could move a
  // datum from UNTRUSTED to TRUSTED — an integrity regression smuggled in through
  // a confidentiality fix. It must not, and this is where we would find out.
  const arbiter = new MockArbiter();
  const vm = viewMap();
  const agentPath = `${AGENT}/contracts/acme.md`;
  await rewriteRequest(readOfAgentPath(agentPath), {
    arbiter,
    toHumanView: (o) => vm.mapText(o, "reverse"),
  });

  const cls = arbiter.classifyCalls[0]!;
  assert.equal(cls.origin, agentPath, "the TRUST origin is what the agent actually touched");
  assert.deepEqual(
    cls.params, { file_path: agentPath },
    "the TRUST params are untouched — the DIR key must not be rewritten",
  );
  // …and the symbolize row's stored provenance origin is likewise the real one.
  assert.equal(arbiter.symbolizeCalls[0]!.origin, agentPath);
});

test("with NO view map: no `originHuman` is sent at all — byte-identical requests", async () => {
  // The no-regression fold. Every deployment without fs-sync must see the exact
  // arbiter requests it saw before this change.
  const arbiter = new MockArbiter();
  await rewriteRequest(readOfAgentPath("/home/u/plain/notes.md"), { arbiter });

  assert.equal(arbiter.classifyCalls[0]!.originHuman, undefined);
  assert.equal(arbiter.classifyCalls[0]!.paramsHuman, undefined);
  assert.equal(arbiter.symbolizeCalls[0]!.originHuman, undefined);
  assert.equal(arbiter.classifyCalls[0]!.origin, "/home/u/plain/notes.md");
});

test("a path the map does not touch adds no field (the translation is not a rewrite-everything)", async () => {
  // An origin OUTSIDE every root (and a URL, and a Bash command with no AgentView
  // path in it) comes back identical from mapText — and an identical translation
  // must add nothing to the wire, or every request in the system would grow a
  // redundant field.
  const arbiter = new MockArbiter();
  const vm = viewMap();
  await rewriteRequest(readOfAgentPath("/etc/hosts"), {
    arbiter,
    toHumanView: (o) => vm.mapText(o, "reverse"),
  });
  assert.equal(arbiter.classifyCalls[0]!.originHuman, undefined);
  assert.equal(arbiter.classifyCalls[0]!.origin, "/etc/hosts");
});
