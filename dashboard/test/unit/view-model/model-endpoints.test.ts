/**
 * model-endpoints.test — confidentiality plan 11 D2/D6 as the dashboard shows
 * it: the declared `models:` rows (never a token value, `local` only when it
 * is literally true), the picker gate (`hasLocalModel`), and "which model read
 * this" from an inspect event's `endpoint` (absent → null, the caller renders
 * as before). Pure projections: no axis is involved (they render whatever the
 * snapshot and the events say, under any protection mode).
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  toModelEndpointRows, hasLocalModel, endpointOf, readByWords, OWN_MODEL, OUTSIDE_MODEL, placementWords, tlsWordsOf,
} from "../../../src/view-model/model-endpoints.js";

test("rows: every declared field, in words; own vs outside by the declaration only", () => {
  const rows = toModelEndpointRows([
    { name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", model: "llama3.2", local: true },
    { name: "zdr", url: "https://zdr.example/v1", wire: "anthropic", local: false, tokenEnv: "ZDR_KEY" },
  ]);
  assert.deepEqual(rows, [
    { name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", wireWords: "OpenAI chat", model: "llama3.2", local: true, where: OWN_MODEL, tokenEnv: null, helperMarked: false, helper: true,
      placement: "host", placementWords: "On this computer", allowPlainHttp: false, notEncrypted: false, tlsWords: null, perimeterWords: null, admin: false, locked: false, version: null },
    { name: "zdr", url: "https://zdr.example/v1", wire: "anthropic", wireWords: "Anthropic Messages", model: null, local: false, where: OUTSIDE_MODEL, tokenEnv: "ZDR_KEY", helperMarked: false, helper: false,
      placement: "network", placementWords: null, allowPlainHttp: false, notEncrypted: false, tlsWords: null, perimeterWords: null, admin: false, locked: false, version: null },
  ]);
  assert.equal(OWN_MODEL, "Your own model");
  assert.equal(OUTSIDE_MODEL, "Outside model");
});

test("rows: a token-shaped field on the wire never reaches a row (explicit copy, not a spread)", () => {
  const rows = toModelEndpointRows([
    { name: "gw", url: "http://10.0.0.2:4000", local: true, tokenEnv: "GW_TOKEN", token: "sk-live-SECRET", apiKey: "sk-2", headers: { authorization: "Bearer x" } },
  ]);
  const json = JSON.stringify(rows);
  assert.doesNotMatch(json, /sk-live-SECRET|sk-2|Bearer/);
  assert.deepEqual(Object.keys(rows[0]!).sort(), ["admin", "allowPlainHttp", "helper", "helperMarked", "local", "locked", "model", "name", "notEncrypted", "perimeterWords", "placement", "placementWords", "tlsWords", "tokenEnv", "url", "version", "where", "wire", "wireWords"]);
  assert.equal(rows[0]!.tokenEnv, "GW_TOKEN", "only the NAME of the variable");
});

test("rows: each carries its entry's version from the snapshot (policy-surface.md §8.4.6), only a well-formed one", () => {
  const V = "e".repeat(32);
  const rows = toModelEndpointRows(
    [{ name: "a", url: "http://127.0.0.1:1" }, { name: "b", url: "http://127.0.0.1:2" }, { name: "c", url: "http://127.0.0.1:3" }],
    { a: V, b: "not a version", toString: V },
  );
  assert.deepEqual(rows.map((r) => [r.name, r.version]), [["a", V], ["b", null], ["c", null]]);
  assert.deepEqual(toModelEndpointRows([{ name: "a", url: "u" }], "x").map((r) => r.version), [null], "no map: no version");
});

test("rows: fail closed on shape (local only for literal true; no name, no row; absent list = [])", () => {
  const rows = toModelEndpointRows([
    { name: "typo", url: "http://127.0.0.1:1", local: "true" },
    { name: "loopback", url: "http://127.0.0.1:2" },
    { url: "http://nameless" },
    null,
    "ollama",
  ]);
  assert.deepEqual(rows.map((r) => [r.name, r.local, r.wire]), [["typo", false, "anthropic"], ["loopback", false, "anthropic"]],
    "a loopback address is not a declaration; a string 'true' is not true; wire defaults to anthropic");
  assert.deepEqual(toModelEndpointRows(undefined), []);
  assert.deepEqual(toModelEndpointRows({ name: "x" }), []);
  assert.deepEqual(toModelEndpointRows([]), []);
});

test("rows: the helper's model is the local entry marked helper: true, else the first local one; a mark on an outside entry never counts", () => {
  const own = (name: string, extra: Record<string, unknown> = {}) => ({ name, url: "http://127.0.0.1:11434", local: true, ...extra });
  const pick = (raw: unknown[]) => toModelEndpointRows(raw).map((r) => [r.name, r.helperMarked, r.helper]);
  assert.deepEqual(pick([{ name: "gw", url: "https://gw.example" }, own("a"), own("b")]), [["gw", false, false], ["a", false, true], ["b", false, false]]);
  assert.deepEqual(pick([own("a"), own("b", { helper: true })]), [["a", false, false], ["b", true, true]]);
  assert.deepEqual(pick([{ name: "gw", url: "https://gw.example", helper: true }, own("a")]), [["gw", false, false], ["a", false, true]]);
  assert.deepEqual(pick([{ name: "gw", url: "https://gw.example" }]), [["gw", false, false]], "no model of your own: no helper row");
});

test("hasLocalModel: true only with a local row", () => {
  assert.equal(hasLocalModel(null), false);
  assert.equal(hasLocalModel([]), false);
  assert.equal(hasLocalModel(toModelEndpointRows([{ name: "zdr", url: "u", local: false }])), false);
  assert.equal(hasLocalModel(toModelEndpointRows([{ name: "zdr", url: "u" }, { name: "ollama", url: "v", local: true }])), true);
});

test("endpointOf: the event's own top-level field; malformed or absent = null", () => {
  assert.deepEqual(endpointOf({ kind: "ullm_call", endpoint: { name: "ollama", location: "local" } }), { name: "ollama", location: "local" });
  assert.deepEqual(endpointOf({ kind: "ullm_call", endpoint: { name: "default", location: "external" } }), { name: "default", location: "external" });
  assert.equal(endpointOf({ kind: "ullm_call", input: { symbolized: "x", endpoint: { name: "ollama", location: "local" } } }), null, "only the event's own field is the contract");
  assert.deepEqual(endpointOf({ endpoint: { name: "odd", location: "somewhere" } }), { name: "odd", location: "external" }, "only a literal 'local' is local");
  assert.equal(endpointOf({ kind: "ullm_call" }), null);
  assert.equal(endpointOf({ endpoint: { location: "local" } }), null, "no name, nothing to show");
  assert.equal(endpointOf({ endpoint: "ollama" }), null);
  assert.equal(endpointOf(null), null);
});

test("readByWords: your own model by name; the default helper; a named outside one", () => {
  assert.equal(readByWords({ name: "ollama", location: "local" }), "read by your own model (ollama)");
  assert.equal(readByWords({ name: "default", location: "external" }), "read by the helper");
  assert.equal(readByWords({ name: "zdr", location: "external" }), "read by an outside model (zdr)", "a named outside endpoint (inspect-mcp never routes to one) never reads as the helper or as local");
  assert.equal(readByWords(null), null);
  assert.equal(readByWords(undefined), null);
});

test("plan 12 D1/D2: placement in words, and Not encrypted only for your own model over plain http on another machine", () => {
  assert.equal(placementWords("http://127.0.0.1:11434"), "On this computer");
  assert.equal(placementWords("http://localhost:18000/v1"), "On this computer");
  assert.equal(placementWords("https://llm.corp.example/v1"), "On your network (llm.corp.example)");
  assert.equal(placementWords("https://[fd00::7]:8443"), "On your network (fd00::7)");
  assert.equal(placementWords("nope"), null);
  const rows = toModelEndpointRows([
    { name: "lab", url: "http://10.0.3.7:8000", local: true, allowPlainHttp: true },
    { name: "corp", url: "https://llm.corp.example/v1", local: true },
    { name: "outside", url: "http://10.0.3.8:8000" },
  ]);
  assert.deepEqual(rows.map((r) => [r.name, r.placement, r.placementWords, r.allowPlainHttp, r.notEncrypted]), [
    ["lab", "network", "On your network (10.0.3.7)", true, true],
    ["corp", "network", "On your network (llm.corp.example)", false, false],
    ["outside", "network", null, false, false],
  ]);
});

test("plan 12 D6: which model read it, with its placement when the event records one", () => {
  assert.equal(readByWords(endpointOf({ endpoint: { name: "corp-vllm", location: "local", placement: "network" } })), "read by your own model (corp-vllm), on your network");
  assert.equal(readByWords(endpointOf({ endpoint: { name: "ollama", location: "local", placement: "host" } })), "read by your own model (ollama), on this computer");
  assert.equal(readByWords(endpointOf({ endpoint: { name: "lab", location: "local", placement: "network", plainHttp: true } })), "read by your own model (lab), on your network, not encrypted");
  assert.equal(readByWords(endpointOf({ endpoint: { name: "ollama", location: "local" } })), "read by your own model (ollama)", "an older inspect-mcp: as before");
  assert.deepEqual(endpointOf({ endpoint: { name: "x", location: "external", placement: "network", plainHttp: true } }), { name: "x", location: "external", placement: "network" },
    "plainHttp is kept only on a local record");
  assert.deepEqual(endpointOf({ endpoint: { name: "x", location: "local", placement: "moon" } }), { name: "x", location: "local" }, "an unknown placement is dropped");
});

test("plan 12 D3: the configured TLS checks in words, never a path", () => {
  const PIN = Buffer.alloc(32, 1).toString("base64");
  assert.equal(tlsWordsOf(undefined), null);
  assert.equal(tlsWordsOf({}), null);
  assert.equal(tlsWordsOf({ caFile: "/etc/ssl/corp.pem" }), "TLS checked with your CA");
  assert.equal(tlsWordsOf({ caFile: "/a", pinSha256: [PIN] }), "TLS checked with your CA and a pinned key");
  assert.equal(tlsWordsOf({ caFile: "/a", pinSha256: [PIN], clientCert: "/c", clientKey: "/k" }), "TLS checked with your CA, a pinned key and a client certificate");
  const [row] = toModelEndpointRows([{ name: "corp", url: "https://llm.corp.example", local: true, tls: { caFile: "/etc/ssl/corp.pem", clientKey: "/home/u/k.pem", clientCert: "/c" } }]);
  assert.equal(row!.tlsWords, "TLS checked with your CA and a client certificate");
  assert.doesNotMatch(JSON.stringify(row), /corp\.pem|k\.pem/, "no path reaches the row");
});

test("plan 12 D4: an entry held to perimeter.networks says so; a name under perimeter.domains is on your organization's network", () => {
  const [held, loose] = toModelEndpointRows([
    { name: "corp", url: "https://llm.corp.example", local: true, perimeter: ["10.0.0.0/8", "fd00::/8"], orgDomain: true },
    { name: "lab", url: "https://lab.example", local: true },
  ]);
  assert.equal(held!.perimeterWords, "only at addresses in 10.0.0.0/8, fd00::/8");
  assert.equal(held!.placementWords, "On your organization's network (llm.corp.example)");
  assert.equal(loose!.perimeterWords, null);
  assert.equal(loose!.placementWords, "On your network (lab.example)");
  assert.equal(placementWords("http://127.0.0.1:11434", true), "On this computer", "loopback stays this computer");
});

test("plan 12 D5: a row set by the administrator says so; locked only with a file", () => {
  const [a, b, c] = toModelEndpointRows([
    { name: "corp", url: "https://llm.corp.example", local: true, adminFile: "/etc/mandu/policy.d/10-corp.yaml", locked: true },
    { name: "gw", url: "https://gw.corp.example", adminFile: "/etc/mandu/policy.d/10-corp.yaml" },
    { name: "mine", url: "http://127.0.0.1:11434", local: true, locked: true },
  ]);
  assert.deepEqual([a!.admin, a!.locked, b!.admin, b!.locked, c!.admin, c!.locked], [true, true, true, false, false, false]);
  assert.doesNotMatch(JSON.stringify(a), /policy\.d/, "the file path is not on the row");
});
