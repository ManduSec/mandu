/**
 * key-pages.test — the display table of where each company's keys are
 * replaced (view-model/key-pages.ts, dashboard.md §4.25r *The advice says
 * where to replace the key*).
 *
 * Pins: every address is an `https:` page of its company's own site, and
 * none carries a query, a fragment or any value (the table is static, so a
 * key can never reach an address); the rules that name no company have no
 * entry; one line per company, in order; the lead words, and the
 * conditional lead for an owner not known (the Scan page).
 *
 * Axes: none read (a display table).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { KEY_PAGES, replaceAtFor } from "../../../src/view-model/key-pages.js";

test("every address is https, with no query, fragment, credentials or value", () => {
  assert.ok(Object.keys(KEY_PAGES).length >= 10);
  for (const [rule, p] of Object.entries(KEY_PAGES)) {
    const u = new URL(p.url);
    assert.equal(u.protocol, "https:", rule);
    assert.equal(u.search, "", `${rule}: no query`);
    assert.equal(u.hash, "", `${rule}: no fragment`);
    assert.equal(u.username + u.password, "", `${rule}: no credentials`);
    assert.equal(p.url, u.href, `${rule}: written as the browser reads it`);
    assert.ok(p.company && p.page, rule);
  }
});

test("the rules that name no company have no page; npm's unconfirmed page is not guessed", () => {
  for (const rule of ["private-key", "url-password", "credential-assignment", "npm-token"]) assert.equal(KEY_PAGES[rule], undefined, rule);
  assert.deepEqual(replaceAtFor(["private-key", "constructor", "toString", "catalog:dotenv"]), []);
});

test("one line per company, in the order given; the lead words", () => {
  assert.deepEqual(replaceAtFor(["aws-secret-key", "gitlab-token", "aws-access-key-id", "openai-key"]).map((r) => r.lead + ": " + r.page + (r.after ?? "")), [
    "Replace it on AWS: IAM console, then Security credentials under your user name",
    "Replace it on GitLab: Personal access tokens on gitlab.com, or your own GitLab's",
    "If it is an OpenAI key, replace it on OpenAI: API keys",
  ]);
  assert.equal(KEY_PAGES["anthropic-key"]!.url, "https://platform.claude.com/settings/keys");
});

test("unsure (the Scan page, an owner not known): the conditional lead, the words after kept; the default lead unchanged", () => {
  assert.deepEqual(replaceAtFor(["github-token", "openai-key", "aws-access-key-id", "private-key"], { unsure: true }).map((r) => r.lead + ": " + r.page + (r.after ?? "")), [
    "If this key is still yours, replace it on GitHub: Personal access tokens",
    "If it is your OpenAI key, replace it on OpenAI: API keys",
    "If this key is still yours, replace it on AWS: IAM console, then Security credentials under your user name",
  ]);
  assert.equal(replaceAtFor(["openai-key"], { unsure: true })[0]!.maybe, true);
  assert.deepEqual(replaceAtFor(["github-token", "openai-key"], {}).map((r) => r.lead), ["Replace it on GitHub", "If it is an OpenAI key, replace it on OpenAI"]);
});
