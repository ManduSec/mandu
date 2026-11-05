/**
 * key-pages — where each company's keys are replaced (dashboard.md §4.25r
 * *The advice says where to replace the key*; the Scan page too, §4.25ai
 * *A key links to where it is replaced*).
 *
 * A display table keyed by the content detector's rule ids, the keys of the
 * arbiter's `SHAPE_WORDS` (arbiter/policy/policy-suggestions.ts). The
 * dashboard does not import the arbiter, so tests/stack/key-pages-parity.test.ts
 * fails when a rule id here is no longer one of the arbiter's. Pure.
 *
 * A company can move its key page, and no test sees that. Each address was
 * checked against the company's own documentation on 2026-10-23:
 *
 *   github-token       docs.github.com, "Managing your personal access tokens":
 *                      Settings › Developer settings › Personal access tokens
 *                      (the page github.com/settings/tokens)
 *   gitlab-token       docs.gitlab.com, "Personal access tokens":
 *                      <your GitLab>/-/user_settings/personal_access_tokens
 *   anthropic-key      platform.claude.com/docs, "API overview": the API keys
 *                      page, platform.claude.com/settings/keys
 *   openai-key         developers.openai.com, "Production best practices":
 *                      platform.openai.com/api-keys
 *   slack-token        docs.slack.dev, "Tokens": app settings, api.slack.com/apps
 *   stripe-key         docs.stripe.com/keys: the API keys page,
 *                      dashboard.stripe.com/apikeys
 *   google-api-key     docs.cloud.google.com, "Manage API keys": the
 *                      Credentials page, console.cloud.google.com/apis/credentials
 *   pypi-token         pypi.org/help, "API tokens": account settings,
 *                      pypi.org/manage/account/
 *   huggingface-token  huggingface.co/docs/hub, "User access tokens":
 *                      huggingface.co/settings/tokens
 *   aws-access-key-id, docs.aws.amazon.com, IAM "How IAM users can manage
 *   aws-secret-key     their own access keys": the IAM console
 *                      (console.aws.amazon.com/iam/), then your user name ›
 *                      Security credentials
 *
 * npm-token has no entry: npm's documentation names the page (profile
 * picture › Access Tokens) but gives no address, and an address is not
 * guessed. private-key, url-password and credential-assignment name no
 * company, so they have none either.
 */

export interface KeyPage {
  company: string;
  /** The page's name, as the company's documentation names it. */
  page: string;
  url: string;
  /** The rule's shape is shared with other companies' keys ("an
   *  OpenAI-style API key"): the line says "If it is an OpenAI key". */
  maybe?: true;
  /** Words after the link (", then Security credentials under your user name"). */
  after?: string;
}

export const KEY_PAGES: Readonly<Record<string, KeyPage>> = {
  "github-token": { company: "GitHub", page: "Personal access tokens", url: "https://github.com/settings/tokens" },
  "gitlab-token": {
    company: "GitLab", page: "Personal access tokens", url: "https://gitlab.com/-/user_settings/personal_access_tokens",
    after: " on gitlab.com, or your own GitLab's",
  },
  "anthropic-key": { company: "Anthropic", page: "API keys", url: "https://platform.claude.com/settings/keys" },
  "openai-key": { company: "OpenAI", page: "API keys", url: "https://platform.openai.com/api-keys", maybe: true },
  "slack-token": { company: "Slack", page: "App settings", url: "https://api.slack.com/apps" },
  "stripe-key": { company: "Stripe", page: "API keys", url: "https://dashboard.stripe.com/apikeys" },
  "google-api-key": { company: "Google Cloud", page: "Credentials", url: "https://console.cloud.google.com/apis/credentials" },
  "pypi-token": { company: "PyPI", page: "Account settings", url: "https://pypi.org/manage/account/" },
  "huggingface-token": { company: "Hugging Face", page: "Access Tokens", url: "https://huggingface.co/settings/tokens" },
  "aws-access-key-id": {
    company: "AWS", page: "IAM console", url: "https://console.aws.amazon.com/iam/",
    after: ", then Security credentials under your user name",
  },
  "aws-secret-key": {
    company: "AWS", page: "IAM console", url: "https://console.aws.amazon.com/iam/",
    after: ", then Security credentials under your user name",
  },
};

/** One line of a row's advice: its lead words, the link, the words after. */
export interface ReplaceAtVM {
  company: string;
  page: string;
  url: string;
  maybe?: true;
  /** "Replace it on GitHub", "If it is an OpenAI key, replace it on OpenAI";
   *  unsure: "If this key is still yours, replace it on GitHub". */
  lead: string;
  after?: string;
}

/** The lines for a row's detector rule ids, in their order, one per
 *  company; a rule with no page gives none. `unsure`: whose key it is is
 *  not known (the Scan page's key not in your files), so the lead says
 *  "If this key is still yours, replace it on GitHub" ("If it is your
 *  OpenAI key, …" for a shared shape). */
export function replaceAtFor(rules: Iterable<string>, opts: { unsure?: boolean } = {}): ReplaceAtVM[] {
  const out: ReplaceAtVM[] = [];
  const seen = new Set<string>();
  for (const rule of rules) {
    const p = Object.prototype.hasOwnProperty.call(KEY_PAGES, rule) ? KEY_PAGES[rule] : undefined;
    if (!p || seen.has(p.company)) continue;
    seen.add(p.company);
    const a = /^[AEIOU]/.test(p.company) ? "an" : "a";
    const lead = opts.unsure
      ? p.maybe ? `If it is your ${p.company} key, replace it on ${p.company}` : `If this key is still yours, replace it on ${p.company}`
      : p.maybe ? `If it is ${a} ${p.company} key, replace it on ${p.company}` : `Replace it on ${p.company}`;
    out.push({
      company: p.company, page: p.page, url: p.url, lead,
      ...(p.maybe ? { maybe: true as const } : {}),
      ...(p.after ? { after: p.after } : {}),
    });
  }
  return out;
}
