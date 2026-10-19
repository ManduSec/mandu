import { test } from "node:test";
import assert from "node:assert/strict";
import { stripBasePath } from "../../../src/server.js";

test("stripBasePath strips only at a path-segment boundary", () => {
  assert.equal(stripBasePath("/mandu/app.css", "/mandu"), "/app.css");
  assert.equal(stripBasePath("/mandu", "/mandu"), "/");
  assert.equal(stripBasePath("/mandu/", "/mandu"), "/");
  assert.equal(stripBasePath("/mandu?x=1", "/mandu"), "/?x=1");
  assert.equal(stripBasePath("/mandu.css", "/mandu"), "/mandu.css", "a file named like the base path is not prefixed");
  assert.equal(stripBasePath("/mandu.css?v=abc", "/mandu"), "/mandu.css?v=abc");
  assert.equal(stripBasePath("/manduX/app.css", "/mandu"), "/manduX/app.css");
  assert.equal(stripBasePath("/app.css", "/mandu"), "/app.css", "unprefixed requests pass through");
  assert.equal(stripBasePath("/mandu.css", ""), "/mandu.css", "no base path, no change");
});
