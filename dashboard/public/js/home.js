/**
 * home.js — the Mandu PRODUCT dashboard (dashboard.md §4.25), served at `/`.
 *
 * Four pages on one shell (Home / Approvals / Rules / Settings, plus the agent
 * page; each a PATH, dashboard.md §4.25v — see routeHref), all
 * rendered from server projections:
 *   - GET /api/home            the home VM (verdict, counts, asks, agents,
 *                              and the first-run card until a session exists)
 *   - GET /api/home/answered   Approvals › Answered earlier past its newest 20
 *                              (Show more; dashboard.md §4.25 *Past the newest 20*)
 *   - GET /api/data-locations  where Mandu keeps files (the `mandu paths` rows),
 *                              when "Where your data lives" is opened
 *   - GET /api/policy/panel    your rules (policy.yaml) + built-in counts
 *   - GET /api/secrets         secret files
 *   - GET /api/config/axes     the on/off in Settings › Protection; POST {mode} flips it
 *   - GET /api/control/status  the protection service
 *   - POST /api/egress/approvals/<id>/{approve,approve-once,deny,send-without}
 *   - POST /api/egress/approvals/<id>/always-source {path} (the Always of one file)
 *   - GET  /api/prompt-filters/holds              the found text of a held message
 *   - POST /api/prompt-filters/holds/answer {approvalId, answer, scope}
 *                                                 Send as written / Send masked / Cancel
 *   - GET  /api/policy/proposals?status=pending   rule changes the agent asked for
 *   - POST /api/policy/proposals/<id> {verdict}   Allow / Not now
 *   - GET  /api/policy/changes                    rule-change history
 *   - POST /api/policy/changes/<id>/undo          Undo
 *   - POST /api/policy/assistant {sentence}       Describe what you want → suggested rules
 *   - POST /api/policy/assistant/apply {edits, expected}   Apply them
 *   - GET  /api/suggestions                       keys Mandu's scan found (Suggested)
 *   - POST /api/suggestions/scan {root?, includeHome?}   scan the files and git history
 *   - POST /api/suggestions/apply {ids}           Save the ticked suggestions
 *   - POST /api/suggestions/dismiss {id}          Not a secret
 *   - POST /api/suggestions/model/preview {tier, endpoint?, root?, includeHome?}
 *                                                 the model picker: what it would send
 *   - POST /api/suggestions/model/send {digest, tier}   Send exactly that, once
 *   - GET  /api/policy/sensitivity-labels         Settings › Sensitivity labels
 *   - POST /api/policy/sensitivity-labels/change {action, id, site?, name?, level?, version}
 *   - GET  /api/policy/prompt-filters             Settings › Prompt filters
 *   - POST /api/policy/prompt-filters/change {edit, expected?}   the choice for a kind, an exception
 *   - POST /api/prompt-filters/reveal {session, eventId, index}  "Show what was hidden" under a message
 *   - POST /api/home/reveal {session, ref}        "Show the real value" of one secret, signed in
 *   - POST /api/prompt-filters/let-through {session, eventId, index, scope}
 *                                                 "Let it through" under a message
 *
 * Conventions shared with the inspector (dev/js): BASE from the base-path
 * meta, every mutating POST carries `X-Mandu-Control: 1` (CSRF), and every
 * server string lands in the DOM as TEXT. No markup is built from data.
 *
 * Vocabulary: protected / masked / blocked / waiting / allowed / secret /
 * agent / rule. The unit test pins that nothing else leaks into this file's
 * copy.
 */

const BASE = document.querySelector('meta[name="base-path"]')?.content || '';
/** The folder `~` means: the home folder of the server, which server.ts
 *  serves with the page; none: every path as recorded. */
const HOME_DIR = (document.querySelector('meta[name="home-dir"]')?.content || '').replace(/(.)\/+$/, '$1');
const DEV_URL = (BASE || '') + '/dev/';
/** Does this build serve the developer view? The server names the extra
 *  front-ends it serves in the extensions meta (dashboard.md §4.25ac); a
 *  build without the developer view gets no link into it: a link part is
 *  its text, and the elements that only link there are hidden. */
const SERVES_DEV = (document.querySelector('meta[name="extensions"]')?.content || '').split(' ').includes('inspector');
/** View as public (dashboard.md §4.25ac): in a build that serves the
 *  developer view, this browser may ask to see the page as a build without
 *  it shows it. A per-browser choice, kept across a reload; the server
 *  still serves the developer view. */
const AS_PUBLIC_KEY = 'mandu.home.viewAsPublic';
const AS_PUBLIC = SERVES_DEV && lsGet(AS_PUBLIC_KEY) === '1';
const HAS_DEV = SERVES_DEV && !AS_PUBLIC;
const POLL_MS = 10_000;
/** Asks shown on the home before "N more in Approvals". */
const HOME_ASK_CAP = 3;

/** Every request this page makes names the product as its sender
 *  (dashboard.md §6.y): the server then serves the live store whatever the
 *  Tests cookie of the inspector says, since the agents of the person are
 *  there. (No apostrophes in comments here: the vocabulary sweep reads
 *  single-quoted strings.) */
const FRONT = { 'X-Mandu-Front': 'product' };

/** A failed GET: the status, and whether the server said its protection
 *  service is down (a 503 `unreachable`), so the page can say so plainly. */
async function apiGet(path) {
  // X-Mandu-Control on every read too (dashboard.md §6): signed in, it marks
  // the read as coming from this page, so a read that can carry a real value gets
  // it; signed out, the server sends only what the AI saw.
  const res = await fetch(BASE + '/api/' + path, { headers: { ...FRONT, 'X-Mandu-Control': '1' } });
  if (!res.ok) {
    let data = null;
    try { data = await res.json(); } catch { data = null; }
    const err = new Error(path + ' → ' + res.status);
    err.status = res.status;
    err.unreachable = !!(data && data.unreachable);
    throw err;
  }
  return res.json();
}
/** The answer to a request of this page, as { ok, status, data }. No answer
 *  at all (the dashboard server is gone) is status 0, which refusalText says
 *  in words, never a throw that leaves a row disabled over an unhandled
 *  rejection (dashboard.md §4.25 *A click with no answer says so*). Only a
 *  request the page cancelled itself (its `signal`) still throws. */
async function answerOf(path, init) {
  let res;
  try { res = await fetch(BASE + '/api/' + path, init); }
  catch (e) {
    if (init.signal && init.signal.aborted) throw e;
    return { ok: false, status: 0, data: null };
  }
  let data = null;
  try { data = await res.json(); } catch { data = null; }
  return { ok: res.ok, status: res.status, data };
}
async function apiPost(path, body, signal) {
  const headers = { ...FRONT, 'X-Mandu-Control': '1' };
  const init = { method: 'POST', headers };
  if (signal) init.signal = signal;
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body);
  }
  return answerOf(path, init);
}

async function apiSend(method, path, body) {
  return answerOf(path, {
    method,
    headers: { ...FRONT, 'X-Mandu-Control': '1', 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

// ── Refusals in the words of the page (dashboard.md §4.25 "Refusals") ────────
// Three refusals come from the gates of the dashboard server and are written
// for a developer: no admin session (server.ts ADMIN_SESSION_REQUIRED, which
// names an environment variable), no protection service behind the route
// (server/approval-routes.ts arbiterDisabled) and a protection service that
// stopped answering (the 503 `unreachable` body, in the words of the
// inspector, or, from most routes, the failed dial to its socket as the
// route got it). The page says each in its own words. Any other error (a refusal
// of the protection service itself, a problem with what was sent) is shown as
// the server wrote it. The matchers are regex literals: the server text is not
// copy of this page. home-js-refusals.test.ts pins them to the server strings.
const ADMIN_REFUSAL = /^admin session required\b/;
const NOT_CONNECTED_REFUSAL = /^arbiter not connected$/;
// A stopped protection service as most routes pass it on: the failed dial
// to its socket, an absolute path (`connect ENOENT /…/arbiter.sock`, bare or
// after the words of the route), or the words of its client for the same
// (server/tenant.ts isArbiterUnreachable), which also says a connection the
// service closed with a request on its way: bare, in the brackets of "the
// protection service did not answer (…)", or after "arbiter: ". A TCP
// refusal (a model, an address and a port) is not one.
const UNREACHABLE_REFUSAL = /\bconnect (?:ENOENT|ECONNREFUSED) \/|(?:^(?:arbiter: )?|\()arbiter connection (?:failed|closed)\b/;
// The page's own sentences that name a command or a place (dashboard.md
// §4.25 "Refusals"): a part given as ['…'] is the command, one given as
// { to, text } a link placeLink draws. Each is a plain string (no quotes, no
// backticks) wherever only a string fits; `words()` draws it with the
// command as code, as every command the page names is, and the place as
// its link.
const OWN_WORDS = new Map();
function ownWords(...parts) {
  const text = parts.map((p) => (Array.isArray(p) ? p[0] : typeof p === 'object' ? p.text : p)).join('');
  OWN_WORDS.set(text, parts);
  return text;
}
const SIGN_IN_WORDS = ownWords('Sign in first: in your own terminal, run ', ['mandu dashboard'], ' and open the sign-in link it prints (each link works once), or sign in with the dashboard\'s password if it has one.');
const NOT_CONNECTED_WORDS = 'The protection service is not connected.';
// Settings has the Start of the service, at its top: the words link there,
// as in the hero and on the agent page.
const UNREACHABLE_WORDS = ownWords('The protection service is not running. ', { to: 'settings', text: 'Start it under Settings' }, ', or try again in a moment.');
// The two failures of the dashboard itself, in the words of the hero
// (§4.25, *The hero says why in words*): no answer at all, or an error.
const NO_ANSWER_WORDS = 'The dashboard could not reach its own server. Refresh in a moment.';
function errorWords(status) { return 'The dashboard server answered with an error (' + status + '). Refresh in a moment.'; }
/** Where a signed-out page would show a real value (dashboard.md §6). */
const SIGN_IN_VALUES = ownWords('Sign in to see real values: in your own terminal, run ', ['mandu dashboard'], ' and open the sign-in link it prints.');

/** The own words of the page for a refused request, or null for an error
 *  the server worded itself: `r` is an apiPost / apiSend / apiGetControl answer
 *  ({ ok, status, data }, status 0 when no answer came) or null. */
function ownRefusal(r) {
  const d = r && r.data;
  const error = d && typeof d.error === 'string' ? d.error : '';
  if (r && r.status === 0) return NO_ANSWER_WORDS;
  if (r && r.status === 403 && ADMIN_REFUSAL.test(error)) return SIGN_IN_WORDS;
  if (r && r.status === 503 && d && d.unreachable === true) return UNREACHABLE_WORDS;
  if (UNREACHABLE_REFUSAL.test(error)) return UNREACHABLE_WORDS;
  if (r && r.status === 404 && NOT_CONNECTED_REFUSAL.test(error)) return NOT_CONNECTED_WORDS;
  return null;
}
/** What to show for a refused request: the own words of the page, else
 *  the error of the server, else `fallback`, the sentence for an error the
 *  server did not word. */
function refusalText(r, fallback) {
  const d = r && r.data;
  return ownRefusal(r) || (d && typeof d.error === 'string' && d.error) || fallback;
}

// ── A change that is not valid says why (dashboard.md §4.25 "Refusals") ─────
// The protection service checks a change of the rules before anything
// changes. One it finds not valid comes back 422 with its `problems`, each a
// line in the terms of policy.yaml: `paths[1].path: pattern "<path>": <why>`
// for a typed pattern it cannot use, `edits[0] (<op>): <why>` for a change
// that no longer fits the rules. Until 2026-10-15 Your rules' Save, a rule's
// menu and Describe's Apply showed only the error of the route ("this change
// is not valid"); the Settings cards already showed the problems
// (modelError). A problem is shown without its place in the file, and a path
// in it as the page shows paths (shortPath); a line of another shape as
// the service wrote it.
const PATTERN_PROBLEM = /^paths\[\d+\]\.path: pattern ("(?:[^"\\]|\\.)*"): /;
const PLACE_PROBLEM = /^(?:edits\[\d+\] \([a-z-]+\)|paths\[\d+\](?:\.[a-z_]+)?): /;
const PROBLEM_PATH = /(^|[\s(])(\/[^\s,;()]+)/g;
function problemWords(line) {
  const m = PATTERN_PROBLEM.exec(line);
  let path = null;
  if (m) { try { path = JSON.parse(m[1]); } catch { path = null; } }
  if (typeof path === 'string') return shortPath(path) + ': ' + line.slice(m[0].length);
  return line.replace(PLACE_PROBLEM, '').replace(PROBLEM_PATH, (all, before, p) => before + shortPath(p));
}
/** `lead`, then each problem in the words of the page (`say`), one after
 *  the other. */
function problemsSentence(lead, problems, say = problemWords) {
  const text = lead + ': ' + problems.map((p) => say(p)).join('; ');
  return /[.!?]$/.test(text) ? text : text + '.';
}
/** What to show for a refused change: `lead`, then each problem the service
 *  named; with none, refusalText's words. */
function changeRefusal(r, lead, fallback) {
  const d = r && r.data;
  const problems = r && r.status === 422 && d && Array.isArray(d.problems) ? d.problems.filter((p) => typeof p === 'string' && p !== '') : [];
  return problems.length ? problemsSentence(lead, problems) : refusalText(r, fallback);
}
// What Changes to save would change is worked out with the changes on the
// rules as they are (files/impact). A change the service cannot make comes
// back 422 as one line: "withEdits: ", then the same problems joined by "; "
// (arbiter server.ts pathLevels). A problem starts at its place in the file,
// so the line is cut there, never at a "; " inside a problem.
const IMPACT_PROBLEMS = /^withEdits: /;
/** The problems of a files/impact refusal, or null for any other. */
function impactProblems(r) {
  const error = r && r.status === 422 && r.data && typeof r.data.error === 'string' ? r.data.error : '';
  if (!IMPACT_PROBLEMS.test(error)) return null;
  const problems = error.replace(IMPACT_PROBLEMS, '').split(/; (?=(?:paths|edits)\[\d+\])/).filter((p) => p !== '');
  return problems.length ? problems : null;
}
// A pattern typed in Add a rule is worked out as its row is drawn
// (previewPattern). Until 2026-10-15 one the service cannot use said only
// "Which files it matches could not be worked out.", and the reason came
// after a label was chosen or Save pressed. Now its row says why: the row
// names the pattern, so a problem about it is its reason alone, and any
// other problem as problemWords says it. Another refusal names its cause as
// the line under Changes to save does.
/** The line of a typed pattern whose matches could not be worked out, as
 *  parts each drawn with words(). */
function patternRefusal(r, typed) {
  const problems = impactProblems(r);
  if (problems) {
    return [problemsSentence('Mandu cannot use this pattern', problems, (line) => {
      const m = PATTERN_PROBLEM.exec(line);
      let path = null;
      if (m) { try { path = JSON.parse(m[1]); } catch { path = null; } }
      return typeof path === 'string' && shortPath(path) === typed.display ? line.slice(m[0].length) : problemWords(line);
    })];
  }
  const lead = 'Which files it matches could not be worked out';
  const why = refusalText(r, '');
  if (!why) return [lead + '.'];
  if (why === (r && r.data && r.data.error)) return [lead + ': ' + (/[.!?]$/.test(why) ? why : why + '.')];
  return [lead + '.', why];
}
/** The line of a typed pattern, its parts one after the other. */
function previewNodes(preview) {
  return preview.flatMap((p, i) => (i ? [' ', words(p)] : [words(p)]));
}

// ── A could-not line names the cause the page knows (dashboard.md §4.25
// *Empty states*) ─────────────────────────────────────────────────────────────
/** Why an apiGet failed: down (the 503 `unreachable` of the server: its
 *  protection service is not running), the status the dashboard server
 *  answered with, or gone (no answer at all). */
function readFailure(err) {
  if (err && err.unreachable) return 'down';
  return (err && err.status) || 'gone';
}
/** The parts of a could-not line: `lead`, then the cause in words; a cause
 *  the page does not know (null) keeps the hedge. With `link`, the words
 *  of a stopped service link to Settings, which has its Start; a line
 *  under another that has the link (the hero, the list above) goes without. */
function cannotCheck(lead, cause, link) {
  const why = cause === 'down' ? (link ? words(UNREACHABLE_WORDS) : 'The protection service is not running.')
    : cause === 'gone' ? NO_ANSWER_WORDS
    : cause ? errorWords(cause)
    : 'The protection service may be unreachable.';
  return [lead + ' ', why];
}
/** Why the policy panel could not be read: the failure of its own read, else,
 *  when it answered `available: false` (no service behind the route, which
 *  a dashboard with none configured answers too), the cause of the latest
 *  Home poll if that one is not an error of the dashboard: the service not
 *  running, or no answer at all. */
function panelCause(failure) {
  if (failure) return failure;
  return S.homeFailure === 'down' || S.homeFailure === 'gone' ? S.homeFailure : null;
}
/** Rules › Your rules and Settings › Models take that cause when drawn, and
 *  a Home poll that ended after their read, or knows another cause now,
 *  draws their line again: only a changed cause, so a focused "add a rule"
 *  stays as it is. Settings › Prompt filters follows the same way. */
function followCannotCheck() {
  if (S.page === 'rules' && !S.panel && F.unreadCause !== false && F.unreadCause !== panelCause(S.panelFailure)) renderLabeled();
  if (S.page === 'settings' && M.unread && M.unread.cause !== panelCause(M.unread.failure)) drawModelsUnread(document.getElementById('settings-models'));
  if (S.page === 'settings' && S.promptUnread && S.promptUnread.shown !== promptUnreadWords(S.promptUnread)) drawPromptUnread();
}
/** A Home poll answered after one that failed: the service (or the
 *  dashboard) is back, so Rules and Settings read again what they could not
 *  read (dashboard.md §4.25 *Empty states*, *What could not be read is read
 *  again*), in place of drawing the hedge over it. Only what is unread: a
 *  list that was read stays as you left it. The file browser under Add a
 *  rule is read on whatever page: a visit to Rules does not read it again. */
function readAgainUnread() {
  readWhyAgain();
  if (F.unread) readFolderAgain();
  if (S.page === 'rules' && !S.panel) loadRules();
  if (S.page !== 'settings') return;
  if (!(S.axes && S.axes.effective)) loadProtection();
  if (M.unread) loadModels();
  if (S.unread.has('labels')) loadLabels();
  if (S.unread.has('prompt')) loadPromptSettings();
}

// ── DOM helpers ───────────────────────────────────────────────────────────────
function el(tag, attrs, ...children) {
  const n = document.createElement(tag);
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v === undefined || v === null || v === false) continue;
      if (k === 'class') n.className = v;
      else if (k === 'text') n.textContent = v;
      else if (k.startsWith('on') && typeof v === 'function') n.addEventListener(k.slice(2), v);
      else n.setAttribute(k, v === true ? '' : String(v));
    }
  }
  for (const c of children) {
    if (c === null || c === undefined || c === false) continue;
    n.append(typeof c === 'string' ? document.createTextNode(c) : c);
  }
  return n;
}
function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
/** `text` to show: one of the page's own sentences (ownWords) with its
 *  command as code and its place as a link; any other text, such as a
 *  server's error, as written, one text node. */
function words(text) {
  const parts = OWN_WORDS.get(text);
  if (!parts) return document.createTextNode(text == null ? '' : String(text));
  const frag = document.createDocumentFragment();
  for (const p of parts) frag.append(Array.isArray(p) ? ownCode(p[0]) : typeof p === 'object' ? placeLink(p) : p);
  return frag;
}
/** The longest code ownCode keeps on one line: `mandu doctor --secrets` is
 *  22. At the code font, 24 characters fit the narrowest column that holds
 *  one (320 px). */
const WHOLE_MAX = 24;
/** A code in the own words of the page: a command, a flag, a file or a key
 *  it names. One with a space in it and at most WHOLE_MAX characters long is a
 *  `.code-whole`, which app.css keeps on one line, so a line never ends
 *  with "mandu" before "dashboard" (dashboard.md §4.25u, *A command keeps
 *  its words*). Data (a command the AI ran, its reply, a prompt) is never
 *  drawn through it. */
function ownCode(text) {
  const s = text == null ? '' : String(text);
  return el('code', { class: /\s/.test(s) && s.length <= WHOLE_MAX ? 'code-whole' : null, text: s });
}
function setWords(node, text) { clear(node); node.append(words(text)); }
/** A name an Approvals card gives (a secret, a file, a host, a program, a
 *  command): a <code>, and a `.code-whole` when it is at most WHOLE_MAX
 *  long, so a line never ends inside it, at a hyphen ("~/mandu-" over
 *  "try/.env") or a space (dashboard.md §4.25u, *The cells name things
 *  as the headline does*). A longer one is cut at its slashes (longName). */
function nameCode(text) {
  const s = text == null ? '' : String(text);
  return longName(el('code', { class: s.length <= WHOLE_MAX ? 'code-whole' : null, text: s }));
}
/** A name longer than WHOLE_MAX with no space in it (a path, a host), cut
 *  into the parts a line may end after: each `/` of a path, else each `.`
 *  of a host. Each part is a `.name-part`, which app.css draws as a box no
 *  wider than its line, so the line breaks between parts ("~/mandu-try/"
 *  over "deploy/staging.conf"), never at a hyphen inside one ("~/mandu-"
 *  over "try/…"), and inside a part only when the part alone is wider than
 *  the line (dashboard.md §4.25u, *A long name breaks at its slashes*).
 *  The text is the same; a shorter name, one with a space (a command) and
 *  one with a chip in it stay as they are. Returns `code`. */
function longName(code) {
  if (code.childNodes.length !== 1 || code.firstChild.nodeType !== 3) return code;
  const s = code.textContent;
  if (s.length <= WHOLE_MAX || /\s/.test(s)) return code;
  const parts = s.match(s.includes('/') ? /[^/]*(?:\/+|$)/g : /[^.]*(?:\.+|$)/g).filter(Boolean);
  if (parts.length < 2) return code;
  clear(code);
  for (const p of parts) code.append(el('span', { class: 'name-part', text: p }));
  return code;
}
/** The names under `node`, the <code>s that sentenceNode drew, kept whole
 *  as nameCode keeps one: each of at most WHOLE_MAX characters is marked
 *  `.code-whole` (dashboard.md §4.25u, *Approvals names things whole*). */
function keepNamesWhole(node) {
  for (const c of node.querySelectorAll('code')) if (c.textContent.length <= WHOLE_MAX) c.classList.add('code-whole');
  return node;
}
/** A cell of an Approvals card (`whyParts`, …), or a Rules line naming
 *  hosts (*May be sent to* of a file, its *Per value* sentence): each name as
 *  nameCode, the words around them through countWords. Without parts (an
 *  older server), its plain `text`, as written. */
function askCellWords(parts, text) {
  if (!Array.isArray(parts) || !parts.length) return document.createTextNode(text == null ? '' : String(text));
  const frag = document.createDocumentFragment();
  for (const p of parts) frag.append(p.kind === 'code' ? nameCode(p.text) : countWords(p.text));
  return frag;
}
/** A name in a line whose column can be narrower than WHOLE_MAX characters
 *  of code (a Rules row under its name is 134 px wide at 320 px), where a
 *  nowrap .code-whole would run past it. One of at most WHOLE_MAX is a code
 *  in a .name-fit with the punctuation right after it (`after`): app.css
 *  draws the .name-fit as a box no wider than its line, so the name moves
 *  whole to the next line when it fits one and wraps inside only when the
 *  column is narrower than the name, and a comma never starts a line. A
 *  longer one is a code cut at its slashes, as nameCode draws it
 *  (§4.25u, *A waiting change names each host*). */
function fitName(text, after) {
  const s = text == null ? '' : String(text);
  const code = el('code', { text: s });
  if (s.length > WHOLE_MAX) return after ? [longName(code), after] : [longName(code)];
  return [el('span', { class: 'name-fit' }, code, after || null)];
}
/** askCellWords for a line drawn with fitName: each code part a fitName
 *  with the punctuation that starts the text after it. */
function fitWords(parts, text) {
  if (!Array.isArray(parts) || !parts.length) return document.createTextNode(text == null ? '' : String(text));
  const frag = document.createDocumentFragment();
  let skip = 0;
  parts.forEach((p, i) => {
    if (p.kind !== 'code') { frag.append(countWords(p.text.slice(skip))); skip = 0; return; }
    const next = parts[i + 1];
    const stuck = next && next.kind !== 'code' ? /^[,.;:]*/.exec(next.text)[0] : '';
    frag.append(...fitName(p.text, stuck));
    skip = stuck.length;
  });
  return frag;
}
/** A number and the word after it: the number a whole word (digits, with
 *  `.` or `,` groups), the word its letters after one space, at most 24.
 *  (`\x27` is the apostrophe, spelled so no quote opens a string here.) */
const COUNT_WORD = /(^|[\s(“"\x27])(\d+(?:[.,]\d+)*) ([A-Za-z][A-Za-z\x27’-]{0,23})(?![\w\x27’-])/g;
/** `text`, one of the page's own sentences, with each number and the word
 *  after it in a `.count-word` that app.css keeps on one line, so a line
 *  never ends with "2" before "requests." (dashboard.md §4.25u, *A count
 *  keeps its word*). The text is the same; with no number it is one text
 *  node, as before. Data (a command's output, the AI's reply, a prompt) is
 *  never drawn through it. */
function countWords(text) {
  const s = text == null ? '' : String(text);
  let at = 0;
  let frag = null;
  for (const m of s.matchAll(COUNT_WORD)) {
    const from = m.index + m[1].length;
    frag = frag || document.createDocumentFragment();
    if (from > at) frag.append(s.slice(at, from));
    frag.append(el('span', { class: 'count-word', text: m[2] + ' ' + m[3] }));
    at = from + m[2].length + 1 + m[3].length;
  }
  if (!frag) return document.createTextNode(s);
  if (at < s.length) frag.append(s.slice(at));
  return frag;
}
/** A server sentence sent as parts (`{kind: 'text' | 'code' | 'link', text}`),
 *  such as a first-run step or the sentence of the hero: each code part as
 *  <code> (ownCode), a link part as placeLink draws it, every text part as
 *  words (countWords), never markup. Without parts (an older server), its
 *  plain `text`. */
function textParts(parts, text) {
  if (!Array.isArray(parts) || !parts.length) return countWords(text);
  const frag = document.createDocumentFragment();
  for (const p of parts) frag.append(p.kind === 'code' ? ownCode(p.text) : p.kind === 'link' ? placeLink(p) : countWords(p.text));
  return frag;
}
/** A link part names a place, never an address (dashboard.md §4.25, *The
 *  hero links where it points*): Settings on this page, or the detailed
 *  trace in the developer view, of one session (`session`) or of every
 *  session (null), in a new tab like Detailed trace on an agent page; or
 *  Keys Mandu found on Rules, opened where Scan for keys is (`suggested`,
 *  the note under Settings › Sensitivity labels, §4.25s), as Review them on
 *  Approvals opens it; or that Sensitivity labels card itself (`labels`,
 *  the line under Scan for keys, §4.25r); or the page of one agent (`agent`,
 *  its `session`: the agent a Home notice names, §4.25x). The page builds
 *  the link; a place it does not know is plain text. */
function placeLink(p) {
  if (p.to === 'settings') return el('a', { href: routeHref('settings'), 'data-page-link': 'settings', text: p.text });
  if (p.to === 'agent' && typeof p.session === 'string' && p.session !== '') {
    return el('a', { href: routeHref('agent', p.session), 'data-page-link': 'agent', 'data-session': p.session, text: p.text });
  }
  if (p.to === 'trace' && HAS_DEV) {
    const one = typeof p.session === 'string' && p.session !== '';
    return el('a', { href: DEV_URL + 'sessions' + (one ? '/' + encodeURIComponent(p.session) : ''), target: '_blank', rel: 'noopener', text: p.text });
  }
  if (p.to === 'suggested') {
    // A modifier click is left to the browser: Rules, in a new tab or window,
    // at that card (its address, §4.25 *Section links*).
    return el('a', { href: routeHref('rules') + '#keys-found', text: p.text, onclick: (e) => {
      if (e.metaKey || e.ctrlKey || e.shiftKey) return;
      e.preventDefault();
      openSuggested();
    } });
  }
  if (p.to === 'labels') {
    // The same: a modifier click opens Settings at that card.
    return el('a', { href: routeHref('settings') + '#sensitivity-labels', text: p.text, onclick: (e) => {
      if (e.metaKey || e.ctrlKey || e.shiftKey) return;
      e.preventDefault();
      openLabels();
    } });
  }
  return document.createTextNode(p.text);
}
/** Words on an agent page that name the detailed trace (dashboard.md §4.25,
 *  *The page links the trace it names*): a link to the trace of the session
 *  the page shows, in a new tab like its Detailed trace button. `tab`
 *  'secrets' opens the Secrets tab there, `ask` the moment Mandu asked, and
 *  `step` one step (the id of a step in the story); the developer view
 *  marks either. The page builds the address from its own session id; a
 *  server part names only a tab. Off an agent page, text. */
function traceLink(text, tab, ask, step) {
  const id = S.page === 'agent' ? S.agentId : null;
  if (!HAS_DEV || typeof id !== 'string' || id === '') return document.createTextNode(text);
  const query = tab === 'secrets' ? '?tab=secrets'
    : typeof ask === 'string' && ask !== '' ? '?ask=' + encodeURIComponent(ask)
    : typeof step === 'string' && step !== '' ? '?step=' + encodeURIComponent(step)
    : '';
  return el('a', { href: DEV_URL + 'sessions/' + encodeURIComponent(id) + query, target: '_blank', rel: 'noopener', text });
}
function svg(path, size = 20) {
  const ns = 'http://www.w3.org/2000/svg';
  const s = document.createElementNS(ns, 'svg');
  s.setAttribute('viewBox', '0 0 24 24');
  s.setAttribute('width', String(size));
  s.setAttribute('height', String(size));
  s.setAttribute('fill', 'none');
  s.setAttribute('stroke', 'currentColor');
  s.setAttribute('stroke-width', '2');
  s.setAttribute('stroke-linecap', 'round');
  s.setAttribute('stroke-linejoin', 'round');
  s.setAttribute('aria-hidden', 'true');
  for (const d of Array.isArray(path) ? path : [path]) {
    const p = document.createElementNS(ns, 'path');
    p.setAttribute('d', d);
    s.append(p);
  }
  return s;
}
const ICON = {
  shield: ['M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z', 'm9 12 2 2 4-4'],
  shieldOff: ['M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z', 'm9 9 6 6M15 9l-6 6'],
  alert: ['M12 9v4M12 17h.01', 'M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z'],
  clock: ['M12 6v6l4 2', 'M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0z'],
  globe: ['M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0z', 'M3 12h18M12 3a14 14 0 0 1 0 18 14 14 0 0 1 0-18z'],
  terminal: ['m4 17 6-6-6-6M12 19h8'],
  file: ['M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z', 'M14 2v6h6'],
  folder: ['M3 6a2 2 0 0 1 2-2h4l2 3h8a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z'],
  chevron: ['m6 9 6 6 6-6'],
  lock: ['M5 11h14v11H5z', 'M7 11V7a5 5 0 0 1 10 0v4'],
  eye: ['M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z', 'M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6z'],
  check: ['M20 6 9 17l-5-5'],
  x: ['M18 6 6 18M6 6l12 12'],
  plug: ['M12 22v-5', 'M9 7V2M15 7V2', 'M6 7h12v4a6 6 0 0 1-12 0z'],
  search: ['M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14z', 'm21 21-4.3-4.3'],
  tool: ['M14.7 6.3a4 4 0 0 0-5.4 5.4L3 18l3 3 6.3-6.3a4 4 0 0 0 5.4-5.4l-2.5 2.5-2.4-.6-.6-2.4z'],
  user: ['M20 21a8 8 0 0 0-16 0', 'M12 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8z'],
  chat: ['M21 12a8 8 0 0 1-11.6 7.1L3 21l1.9-6.4A8 8 0 1 1 21 12z'],
  // The label buttons (dashboard.md §4.25n) and a pattern rule.
  eyeOff: ['M3 3l18 18', 'M10.6 5.1A10 10 0 0 1 12 5c6.5 0 10 7 10 7a17 17 0 0 1-3.2 4.2', 'M6.6 6.6A17 17 0 0 0 2 12s3.5 7 10 7a9.7 9.7 0 0 0 5.4-1.6', 'M9.9 9.9a3 3 0 0 0 4.2 4.2'],
  monitor: ['M3 4h18v12H3z', 'M8 20h8M12 16v4'],
  unlock: ['M5 11h14v11H5z', 'M7 11V7a5 5 0 0 1 9.9-1'],
  pattern: ['M12 4v16M5 8l14 8M19 8 5 16'],
};
const FAMILY_ICON = { send: 'globe', run: 'terminal', read: 'lock', show: 'eye', prompt: 'eye', other: 'alert' };

/** Plan 15 §7: the found text of each held message, by the id of its ask. Fetched
 *  with the CSRF header (the route serves it only to the signed-in person);
 *  never part of /api/home. Null until loaded or when it cannot be. */
async function loadPromptHolds() {
  try {
    const res = await fetch(BASE + '/api/prompt-filters/holds', { headers: { ...FRONT, 'X-Mandu-Control': '1' } });
    if (!res.ok) return null;
    const d = await res.json();
    const m = new Map();
    for (const h of (d && d.holds) || []) m.set(h.approvalId, h);
    return m;
  } catch {
    return null;
  }
}

function fillPromptFound(host, holds) {
  for (const node of host.querySelectorAll('.ask-found[data-id]')) {
    const h = holds.get(node.getAttribute('data-id'));
    clear(node);
    if (!h || typeof h.span !== 'string') continue;
    node.append('It found: ', el('code', { text: h.span }));
  }
}

function maskChip(p) {
  const secret = p.text === 'secret';
  // A secret in a command, named as the send steps name it.
  const name = secret && typeof p.name === 'string' && p.name ? p.name : null;
  // A secret the AI read as it was before it was marked one (p.early, the
  // moment its card gives): masked here, never "never" (dashboard.md §4.25b).
  const early = secret && typeof p.early === 'string' && p.early;
  const when = early ? hhmm(p.early) : '';
  const title = early
    ? (name ? 'Your secret ' + name : 'A secret') + ', masked here. The AI read its real value'
      + (when ? ' at ' + when : '') + ', before it was marked a secret.'
    : name ? 'Your secret ' + name + ', masked: the AI never got the real value'
    : secret ? 'A secret, masked: the AI never got the real value' : 'Masked: the AI never got the real text';
  return el('span', { class: 'mask-chip' + (secret ? ' secret' : ''), title, text: name || p.text });
}

/** What "masked" means, for the help button (dashboard.md §4.25u). True in
 *  every mode; the last sentence follows the running level, because in the
 *  default Secrets mode untrusted text is NOT masked (CONTRIBUTING.md, protection
 *  modes) and the page must never claim it is. */
function maskedHelpText() {
  const level = S.home && S.home.protection ? S.home.protection.level : 'unknown';
  const masksText = level === 'full' || level === 'injection';
  return 'Masked: before the AI saw it, Mandu replaced the real value with a short code that stands for it. '
    + 'The AI can use the code, but it never reads the value behind it. '
    + 'Mandu puts the real value back only where you or your rules allow it, such as a request to the site a key is for. '
    + (masksText
      ? 'In this mode, untrusted content, such as a web page, is masked too.'
      : 'In the Secrets mode (the default), only secrets are masked; untrusted content reaches the AI as-is.');
}
let helpSeq = 0;
/** A small "?" button that opens a short explanation under it: a real
 *  button (keyboard and touch, never hover-only) with aria-expanded and
 *  aria-controls; Escape or a click elsewhere closes it. `text` is a
 *  string, or a node (a sentence with a link in it). `icon` draws that ICON
 *  instead of the "?", `face` that word, `cls` adds a class. */
function helpButton(label, text, { icon, face, cls } = {}) {
  const id = 'help-' + (++helpSeq);
  const wrap = el('span', { class: 'help' });
  const own = typeof text === 'string';
  const pop = el('span', { class: 'help-pop', id, role: 'note', hidden: true, text: own ? text : null }, own ? null : text);
  const btn = el('button', { type: 'button', class: 'help-btn' + (cls ? ' ' + cls : ''), 'aria-expanded': 'false', 'aria-controls': id, 'aria-label': label, title: label, text: icon ? null : face || '?' },
    icon ? svg(ICON[icon], 14) : null);
  btn.addEventListener('click', (e) => {
    e.stopPropagation();
    setHelp(btn, btn.getAttribute('aria-expanded') !== 'true');
  });
  // The Escape it takes is marked taken: in a form that Escape closes (the
  // Models form), it closes the note alone.
  wrap.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && btn.getAttribute('aria-expanded') === 'true') { e.preventDefault(); setHelp(btn, false); btn.focus(); }
  });
  wrap.append(btn, pop);
  return wrap;
}
function setHelp(btn, open) {
  btn.setAttribute('aria-expanded', open ? 'true' : 'false');
  const pop = document.getElementById(btn.getAttribute('aria-controls'));
  if (!pop) return;
  pop.hidden = !open;
  if (open) keepInWindow(pop);
}
/** An open note that would run past the window's right edge (a mark far
 *  along a phone's row) moves left until it ends 16 px inside it, never
 *  past the left margin; its width already fits (`.help-pop` max-width). */
function keepInWindow(pop) {
  pop.style.left = '';
  const r = pop.getBoundingClientRect();
  const over = r.right - (document.documentElement.clientWidth - 16);
  if (over > 0) pop.style.left = -Math.min(over, Math.max(0, r.left - 16)) + 'px';
}
function maskedHelp() { return helpButton('What masked means', maskedHelpText()); }
/** The notice of an agent row (supported-agents.md §3): a warning mark by its
 *  name that opens the sentence, so the row stays one line. */
function agentNoticeMark(notice) {
  return helpButton('Warning about this agent', notice, { icon: 'alert', cls: 'notice-btn' });
}
/** A preview agent's tag (supported-agents.md §2.0), by its name on its
 *  Home row and its page: "Preview", a button that opens what that means
 *  and a link to report a problem (no referrer: the page's address names
 *  the session). */
function agentPreviewMark(p) {
  const note = document.createDocumentFragment();
  note.append(p.sentence + ' ', el('a', { href: p.issues, target: '_blank', rel: 'noopener noreferrer', text: 'Report a problem' }), '.');
  return helpButton(p.label + ' support is a preview', note, { face: 'Preview', cls: 'preview-btn' });
}
// A click outside an open help closes it (one listener for every help).
document.addEventListener('click', (e) => {
  for (const b of document.querySelectorAll('.help-btn[aria-expanded="true"]')) {
    if (!b.parentNode.contains(e.target)) setHelp(b, false);
  }
});
/** Story parts as one line of the page. `md` says whose words they are:
 *  true, the AI's reply or the person's prompt (markdownNode); 'data', what
 *  a command the person ran printed, its text as written; otherwise the
 *  page's own words, each text part through countWords. */
function sentenceNode(parts, cls, md, at) {
  if (md === true) return markdownNode(parts, cls);
  const s = el('div', { class: cls });
  const list = parts || [];
  // A command and the chips of the items in it are one <code>: a chip next
  // to a code part is drawn inside it. Two code parts with no chip between
  // them stay two.
  let code = null;
  list.forEach((p, i) => {
    if (p.kind === 'code') {
      if (code && code.lastChild && code.lastChild.nodeType === 1) code.append(document.createTextNode(p.text));
      else code = s.appendChild(el('code', { text: p.text }));
    } else if (p.kind === 'masked') {
      // An item the AI never saw: a chip, never the placeholder spelling.
      if (!code && list[i + 1] && list[i + 1].kind === 'code') code = s.appendChild(el('code'));
      (code || s).append(maskChip(p));
    } else if (p.kind === 'time') {
      // A moment (ISO): the local clock time, as each turn's time is drawn.
      // With `step` (a Your secrets card), a link to the step that shows it.
      code = null;
      const time = el('time', { datetime: p.text, text: hhmm(p.text) || p.text });
      s.append(p.step ? stepLink(p.step, time) : time);
    } else if (p.ask) {
      // The Approvals row Mandu filed ("…asked for your OK in Approvals").
      code = null;
      s.append(askRowLink(p.ask, p.text));
    } else if (p.trace) {
      // Words that name this session's detailed trace ("Open the detailed
      // trace"); under a step (`at`, its id), the trace opens at that step.
      code = null;
      s.append(traceLink(p.text, p.trace, null, at));
    } else {
      code = null;
      s.append(md === 'data' ? document.createTextNode(p.text) : countWords(p.text));
    }
  });
  // A long path or host breaks at its slashes or dots (longName).
  for (const c of s.children) if (c.tagName === 'CODE') longName(c);
  return s;
}
/** A link to the Approvals row `askId` (an id, never a value), which that
 *  page marks (§4.25b, *A stop says Mandu asked you*). */
function askRowLink(askId, text) {
  return el('a', { href: routeHref('approvals', askId), 'data-page-link': 'approvals', 'data-ask': askId, text });
}
/** A time on a Your secrets card that opens the step it tells of under What
 *  happened (§4.25b, *A time opens its step*): a button, since it moves the
 *  page rather than going anywhere. `stepId` is data, never markup. */
function stepLink(stepId, time) {
  return el('button', { type: 'button', class: 'step-link', 'data-opens': stepId, title: 'Show this step under What happened', onclick: () => showStep(stepId) }, time);
}
/** Brings the story's step `stepId` into view: unfolds the fold that hides
 *  it, marks it (the mark moves with the next such click), gives it the
 *  keyboard focus and scrolls to it. Ids are compared as values, never
 *  spliced into a selector. False when the page does not show the step. */
function showStep(stepId) {
  const story = document.getElementById('agent-story');
  const target = story ? [...story.querySelectorAll('[data-step-id]')].find((x) => x.dataset.stepId === stepId) : null;
  if (!target) return false;
  openQuiet(target);
  const fold = target.closest('.steps-more');
  if (fold && fold.hidden) {
    // Each fold's button is in the row right after it.
    const btn = fold.nextElementSibling && fold.nextElementSibling.querySelector('.steps-toggle');
    if (btn) btn.click();
  }
  for (const x of story.querySelectorAll('.step.shown')) x.classList.remove('shown');
  target.classList.add('shown');
  target.setAttribute('tabindex', '-1');
  if (target.focus) target.focus({ preventScroll: true });
  if (target.scrollIntoView) target.scrollIntoView({ block: 'center' });
  return true;
}
/** Text the agent or you wrote, with its markdown drawn as the agent meant
 *  it (dashboard.md §4.25b): `inline` spans and ``` fenced blocks as code;
 *  **bold** as bold when its pair is on the same line and each `**` touches
 *  a word; a line starting `- `, `* `, `+ ` or `1. ` as a list item with a
 *  hanging indent (two spaces of indent per level, three levels); `# ` to
 *  `###### ` as a heading line. Inside code nothing else applies. The rest
 *  stays as written: no links, tables or italics (an `_` or `*` in a name
 *  such as STRIPE_KEY never turns italic). A chip stays a chip wherever it
 *  falls. Built with text nodes and plain elements only, never HTML; an odd
 *  count of inline backticks leaves them as written. */
function markdownNode(parts, cls) {
  const s = el('div', { class: cls });
  // The text as one string, a chip or a code part one stand-in character,
  // so a `**` can look ahead along its line.
  const all = (parts || []).map((p) => (p.kind === 'masked' || p.kind === 'code' ? '\uFFFC' : p.text)).join('');
  const inlineOk = (all.replace(/```/g, '').match(/`/g) || []).length % 2 === 0;
  let block = null; // the open fenced <pre>
  let span = null; // the open inline <code>
  let strong = null; // the open <strong>
  let line = null; // the open body of a list item, or a heading
  let bol = true; // at the start of a line, outside code
  let pos = 0; // where the current piece starts in `all`
  let fenceLine = false; // still on the opening line of a fence (its language)
  let afterFence = false; // the newline that ends a closing fence
  const inline = () => strong || line || s;
  const at = () => block || span || inline();
  const word = (ch) => ch !== undefined && !/\s/.test(ch);
  // A `**` at `i` opens bold when a word follows it and a closing `**`
  // (after a word) comes later on the same line.
  const opens = (i) => {
    if (!word(all[i + 2])) return false;
    const nl = all.indexOf('\n', i + 2);
    for (let j = all.indexOf('**', i + 3); j !== -1 && (nl === -1 || j < nl); j = all.indexOf('**', j + 1)) {
      if (word(all[j - 1])) return true;
    }
    return false;
  };
  // At the start of a line, a list item or a heading opens an element that
  // holds the rest of the line. Returns what is left of the text.
  const lineStart = (text) => {
    const h = text.match(/^ {0,3}#{1,6}[ \t]+/);
    if (h) {
      line = s.appendChild(el('span', { class: 'md-h' }));
      return text.slice(h[0].length);
    }
    const m = text.match(/^([ \t]*)([-*+]|\d{1,9}[.)])[ \t]+/);
    if (!m) return text;
    const depth = Math.min(3, Math.floor(m[1].replace(/\t/g, '  ').length / 2));
    const li = s.appendChild(el('span', { class: 'md-li' + (depth ? ' md-d' + depth : '') },
      el('span', { class: 'md-mark', text: /\d/.test(m[2]) ? m[2] : '\u2022' })));
    line = li.appendChild(el('span', { class: 'md-body' }));
    return text.slice(m[0].length);
  };
  // Plain text outside code: a newline ends bold and a list item or heading
  // (whose element already ends its line, so the newline is not drawn).
  const plain = (text) => {
    text.split('\n').forEach((seg, k) => {
      if (k > 0) {
        strong = null;
        if (line) line = null;
        else s.append(document.createTextNode('\n'));
        bol = true;
      }
      if (bol && seg) seg = lineStart(seg);
      if (seg) { inline().append(document.createTextNode(seg)); bol = false; }
      else if (line) bol = false;
    });
  };
  for (const p of parts || []) {
    if (p.kind === 'masked') { at().append(maskChip(p)); pos += 1; if (!block) bol = false; continue; }
    if (p.kind === 'code') { at().append(block || span ? document.createTextNode(p.text) : el('code', { text: p.text })); pos += 1; if (!block) bol = false; continue; }
    for (const piece of p.text.split(/(```|`|\*\*)/)) {
      const i = pos;
      pos += piece.length;
      if (piece === '```') {
        if (block) {
          const last = block.lastChild;
          if (last && last.nodeType === 3) last.textContent = last.textContent.replace(/\n$/, '');
          block = null;
          afterFence = true;
          bol = true;
        } else {
          span = null;
          strong = null;
          line = null;
          const prev = s.lastChild;
          if (prev && prev.nodeType === 3) prev.textContent = prev.textContent.replace(/\n$/, '');
          // A wide block scrolls on its own: a Tab stop with nothing in it
          // to focus, so it is a named group (dashboard.md §4.25 *A box
          // that scrolls says what it holds*).
          block = el('pre', { class: 'code-block', role: 'group', 'aria-label': 'Code' });
          s.append(block);
          fenceLine = true;
        }
        continue;
      }
      if (piece === '`' && inlineOk && !block) {
        span = span ? null : inline().appendChild(el('code'));
        bol = false;
        continue;
      }
      if (piece === '**' && !block && !span) {
        if (strong && word(all[i - 1])) { strong = null; continue; }
        if (!strong && opens(i)) { strong = inline().appendChild(el('strong')); bol = false; continue; }
      }
      let text = piece;
      if (fenceLine) {
        const nl = text.indexOf('\n');
        if (nl === -1) continue;
        text = text.slice(nl + 1);
        fenceLine = false;
      }
      if (afterFence && text) { text = text.replace(/^\n/, ''); afterFence = false; }
      if (!text) continue;
      if (block || span) at().append(document.createTextNode(text));
      else plain(text);
    }
  }
  // A name in the text (an inline code with no space in it) breaks as the
  // names of the page do: a long one only at its slashes or dots
  // (longName), a short one only when it alone is wider than its line
  // (.name-fit), never at a hyphen or a letter inside it. A command with a
  // space, a code holding a chip and a fenced block are as written
  // (dashboard.md §4.25u, *A name in a reply breaks as elsewhere*).
  for (const c of s.querySelectorAll('code')) {
    if (c.closest('pre') || c.childNodes.length !== 1 || c.firstChild.nodeType !== 3 || /\s/.test(c.textContent)) continue;
    if (c.textContent.length > WHOLE_MAX) longName(c);
    else c.classList.add('name-fit');
  }
  return s;
}

function ago(ms) {
  if (!Number.isFinite(ms)) return '';
  const d = Math.max(0, Date.now() - ms);
  const m = Math.round(d / 60_000);
  if (m < 1) return 'just now';
  if (m < 60) return m + (m === 1 ? ' minute ago' : ' minutes ago');
  const h = Math.round(m / 60);
  if (h < 24) return h + (h === 1 ? ' hour ago' : ' hours ago');
  const days = Math.round(h / 24);
  return days + (days === 1 ? ' day ago' : ' days ago');
}
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
/** The local clock time of `ms`: "Sep 30, 14:12", with the year when it is
 *  not this year ("Sep 30, 2025, 14:12"). Built by hand, not by the
 *  browser's locale, so every viewer reads the same words. */
function clockWords(ms, nowMs) {
  const d = new Date(ms);
  const now = new Date(nowMs === undefined ? Date.now() : nowMs);
  const pad = (k) => String(k).padStart(2, '0');
  const year = d.getFullYear() === now.getFullYear() ? '' : ', ' + d.getFullYear();
  return MONTHS[d.getMonth()] + ' ' + d.getDate() + year + ', ' + pad(d.getHours()) + ':' + pad(d.getMinutes());
}
/** When something happened, absolute and relative (dashboard.md §4.25u):
 *  <time datetime="ISO">Sep 30, 14:12 · 2 days ago</time>, text only, in
 *  the two parts sayWhen writes. Every place that names a moment uses it;
 *  null when the time is unknown. */
function whenNode(ms) {
  if (!Number.isFinite(ms)) return null;
  const t = el('time', { class: 'when', datetime: new Date(ms).toISOString() });
  sayWhen(t, ms);
  return t;
}
/** A whenNode moment's words: the clock time with its dot, then the
 *  relative words, each a part app.css keeps on one line (`.when-at`,
 *  `.when-ago`), so a line breaks only between them, never between a
 *  number and its word (§4.25u: "· 2" over "minutes ago" on a phone until
 *  2026-10-15). The text is the same: "Sep 30, 14:12 · 2 days ago". */
function sayWhen(t, ms) {
  clear(t);
  t.append(el('span', { class: 'when-at', text: clockWords(ms) + ' ·' }), ' ', el('span', { class: 'when-ago', text: ago(ms) }));
}
/** Every poll: each moment whenNode wrote says its words again from its own
 *  datetime, so a section the poll leaves as it is never reads "just now"
 *  an hour on (§4.25 *The poll keeps your place*); so does each Home row's
 *  "started …" or "ended …" (whenLine), its clock time on hover, and each
 *  day heading of History (dayWords). */
function refreshWhen() {
  for (const t of document.querySelectorAll('time.when')) {
    const ms = Date.parse(t.getAttribute('datetime'));
    if (Number.isFinite(ms)) sayWhen(t, ms);
  }
  for (const t of document.querySelectorAll('time.ago')) {
    const ms = Date.parse(t.getAttribute('datetime'));
    if (Number.isFinite(ms)) { t.textContent = ago(ms); t.title = clockWords(ms); }
  }
  // History day headings (historyDay): past midnight Today reads Yesterday,
  // the rows under it left as they are.
  for (const t of document.querySelectorAll('.history-day > time')) {
    const key = t.getAttribute('datetime');
    if (/^\d{4}-\d{2}-\d{2}$/.test(key || '')) t.textContent = dayWords(key);
  }
}
function n(k, one, many) { return k + ' ' + (k === 1 ? one : many); }
/** A path as the page shows it: `~/…` under the home folder of the dashboard
 *  (HOME_DIR, the `home-dir` of the served page; rule-words.ts `tildePath` in
 *  the words of the server), anything else as recorded, the home folder of
 *  another account included, so `~` never names the wrong folder
 *  (dashboard.md §4.34). */
function shortPath(p) {
  if (!p) return '';
  if (!HOME_DIR || HOME_DIR === '/') return p;
  if (p === HOME_DIR) return '~';
  return p.startsWith(HOME_DIR + '/') ? '~' + p.slice(HOME_DIR.length) : p;
}

// ── State ─────────────────────────────────────────────────────────────────────
const S = { home: null, panel: null, secrets: null, axes: null, services: null, page: 'home', visit: 0, busy: new Set(), proposals: [], proposalPatternsHidden: false, proposalNotice: null,
  // Why the latest Home poll failed (readFailure), null when it answered;
  // why the policy panel of Rules could not be read (null: not known); and
  // why Settings › Protection could not read config.toml (null: not known).
  homeFailure: null, panelFailure: null, axesFailure: null,
  // The Home polls asked so far, and the latest one whose answer the page
  // took (loadHome): an answer to a poll asked before that one is dropped.
  homeAsked: 0, homeTaken: 0,
  // The Settings blocks whose last read left them unread ('labels',
  // 'prompt'), read again when the service comes back (readAgainUnread).
  unread: new Set(),
  // Settings › Prompt filters, unread: its line, the answer it says and the
  // words it was drawn with (drawPromptUnread); null when read.
  promptUnread: null,
  // What runs (runningKey) as Settings › Protection and the Rules line last drew it.
  runningShown: { settings: null, rules: null },
  // The service line of Settings › Protection: the summary it was drawn from
  // (`services`, as JSON), its state for the row's dot (protectDot) and how
  // many of its own requests are out (followServices).
  serviceState: null,
  serviceOut: 0,
  // A flip of the Protection switch is on its way: the switch holds
  // (flipProtection).
  protectOut: false,
  // What you typed in the ALLOW field of each over-broad rule change, by its id.
  proposalTyped: new Map(),
  // The words of the answer to the last button of each card or row the poll
  // draws, by its place and id (keepAnswer).
  answers: new Map(),
  // The lists of the past on Approvals, past their newest 20 (dashboard.md
  // §4.25 *Past the newest 20*): the rows of Answered earlier once Show more
  // brought more (null: the newest 20 of Home), the answer `/approvals/<id>` sought past
  // them (seekAnswered), and how many Rule changes draws (loadRuleHistory).
  answered: null, answeredSought: null,
  changes: { want: 20, last: null, failure: null, out: 0 },
  // The heading the last page change gave the focus (focusPage), null before
  // any; the card or step that took it from there (focusMarked).
  pageHeading: null, marked: null,
  // The answer pressed with the focus in its card or row, and where the
  // focus goes once it is answered (holdFocus); null when none.
  answerFocus: null,
  // What the agent page asked to see past its caps this visit (agentShow),
  // where the focus goes once a "Show them" is drawn (landAgent), and the
  // visit whose Earlier list shows every session (renderEarlier;
  // dashboard.md §4.25ad).
  agentShow: null, agentLand: null, earlierAll: null,
  // The step each count tile of the agent page last went to, this visit
  // (tileAt; dashboard.md §4.25 *A tile takes you to what it counts*).
  agentTileAt: null,
  // The agent page shows only the turns where Mandu stepped in (its switch,
  // `?only=stepped-in`; dashboard.md §4.25ae *Only where Mandu stepped in*).
  agentOnly: false,
  // History lists only the sessions where Mandu stepped in (its switch, the
  // same `?only=`; §4.25ae *Only the sessions where Mandu stepped in*).
  historyOnly: false };

/** What each section the poll redraws was last drawn from (dashboard.md
 *  §4.25 *The poll keeps your place*): a poll whose answer for a section is
 *  the one it shows leaves it as it is, so what you typed, the focus, the
 *  words of an answer and what you opened stay; the moments are refreshed in
 *  place (refreshWhen). Settings › Protection does the same by runningKey. */
let drawn = new Map();
function sameAsDrawn(section, data) {
  const key = JSON.stringify(data === undefined ? null : data);
  if (drawn.get(section) === key) return true;
  drawn.set(section, key);
  return false;
}
/** After a write of your own that worked: every section draws again, so an
 *  answered card leaves even when the next answer still lists it. */
function forgetDrawn() { drawn = new Map(); }

/** A changed answer draws a list again from nothing, so the words of the
 *  answer to the last button of each card or row there live in S.answers,
 *  by its place and id, with the state of the item they answered
 *  (`data-state`). Each draw of the place writes them again on the card
 *  with that id in that state (putBackAnswers). They go with the next
 *  button on the card, or once the card is no longer drawn there in that
 *  state: answered elsewhere, its outcome changed, undone. The inspector
 *  keeps E.rowAnswers much the same way, by id alone (dashboard.md §4.25
 *  *The poll keeps your place*). Each place, by the list it draws into
 *  (the agent page's Waiting cards, and the rows of the note under your
 *  message anywhere in its story): */
const ANSWER_PLACES = { home: 'home-waiting', approvals: 'approvals-waiting', answered: 'approvals-answered', proposal: 'approvals-proposals', change: 'approvals-rule-history', agent: 'agent-waiting', note: 'agent-story' };
/** The place of a card or row the poll draws, null for any other. */
function answerPlace(card) {
  if (card.classList.contains('prompt-note-item')) return 'note';
  const list = card.parentElement;
  return list ? Object.keys(ANSWER_PLACES).find((p) => ANSWER_PLACES[p] === list.id) || null : null;
}
/** The cards drawn in `list` now, by id. Compared as values, never spliced
 *  into a selector: ids are server data. */
function drawnCards(list) {
  const cards = !list ? [] : list.id === ANSWER_PLACES.note ? list.querySelectorAll('.prompt-note-item') : list.children;
  return new Map([...cards].filter((c) => c.dataset.id !== undefined).map((c) => [c.dataset.id, c]));
}
/** The words of the answer on `card` of `place` (null: a card no poll
 *  draws), kept for the next draws and shown on the card drawn now: a poll
 *  may have drawn it again while the answer was on its way. `done`: the
 *  words of an answer that worked and leaves the card in place (letDone). */
function keepAnswer(place, card, text, done = false) {
  if (!place) { showAskError(card, text); return; }
  const id = card.dataset.id;
  const state = card.dataset.state || '';
  S.answers.set(place + ' ' + id, { place, id, state, text, done });
  const list = document.getElementById(ANSWER_PLACES[place]);
  const now = card.isConnected ? card : drawnCards(list).get(id);
  const shown = !!now && (now.dataset.state || '') === state;
  if (shown) showAnswer(now, { text, done });
  focusAnswered(place, id, list, shown && !done ? now : null);
}
function showAnswer(card, a) {
  if (a.done) letDone(card, a.text);
  else showAskError(card, a.text);
}
/** A button pressed on a card: the words of its last answer go, and where
 *  the focus was is kept (holdFocus). */
function dropAnswer(place, card) {
  if (place) S.answers.delete(place + ' ' + card.dataset.id);
  holdFocus(place, card);
}
/** After each draw of `place` into `list`: each card drawn there in the
 *  state its last answer was for gets the words back; the words of any
 *  other go. An answer that worked gives the focus on (focusOn). */
function putBackAnswers(place, list) {
  const cards = drawnCards(list);
  for (const [key, a] of S.answers) {
    if (a.place !== place) continue;
    const card = cards.get(a.id);
    if (card && (card.dataset.state || '') === a.state) showAnswer(card, a);
    else S.answers.delete(key);
  }
  const f = S.answerFocus;
  if (f && f.worked && f.place === place) focusOn(f, list);
}

/** An answer keeps the keyboard focus in its list (dashboard.md §4.25 *An
 *  answer keeps the focus in its list*). A card's buttons go off while its
 *  answer is on its way, and a browser drops the focus of a button turned
 *  off to the page (<body>): the next card, a refusal's words and an empty
 *  list were never read out. An answer pressed with the focus in its card or
 *  row keeps its place, the card's id and rank there, and the words of the
 *  button (S.answerFocus, dropped by a focus moved elsewhere). */
function holdFocus(place, card) {
  const a = document.activeElement;
  S.answerFocus = null;
  if (!place || !a || !card.contains(a)) return;
  const ids = [...drawnCards(document.getElementById(ANSWER_PLACES[place])).keys()];
  S.answerFocus = { place, id: card.dataset.id, rank: Math.max(0, ids.indexOf(card.dataset.id)), words: a.textContent, worked: false, on: null };
}
/** The answer pressed on `card` of `place` worked: the next draw of its
 *  list gives the focus on (putBackAnswers). */
function answerWorked(place, card) {
  const f = S.answerFocus;
  if (f && f.place === place && f.id === card.dataset.id) f.worked = true;
}
/** The focus fell to the page: a button turned off, a card drawn again. */
function focusFell() {
  const a = document.activeElement;
  return !a || a === document.body || !a.isConnected;
}
/** A button that went off while its request was out, once the answer is
 *  drawn (dashboard.md §4.25b *Show the real value keeps the focus*): a
 *  browser drops the focus of a button turned off to the page (<body>). It
 *  gets the focus back only if it had it at the press (`had`) and the focus
 *  fell: one the person moved stays. `said`: the words drawn for it that
 *  describe it (a refusal's, or Try it's answer); none drops them. */
function focusBack(btn, had, said) {
  if (said) btn.setAttribute('aria-describedby', said.id);
  else btn.removeAttribute('aria-describedby');
  if (had && focusFell() && btn.isConnected) btn.focus({ preventScroll: true });
}
/** A heading for a focus whose place is gone: its section's, while shown,
 *  else the page's. */
function focusHeading(block) {
  const heading = (block && block.isConnected && !block.closest('[hidden]') && block.querySelector('h2'))
    || document.querySelector('#main > section[data-page="' + S.page + '"] h1');
  if (heading) focusThere(heading);
}

/** The agent page is drawn again from nothing when a read brings a changed
 *  answer, also while a reveal asks the server (dashboard.md §4.25b *An
 *  answer that comes after a redraw*). Each reveal button drawn → its box's
 *  `key` (the same secret or finding, named alike) and `answered(r, had)`,
 *  which draws an answer in that box, so an answer to a button the page
 *  no longer has goes to the box drawn now. */
const REVEALS = new WeakMap();
/** The reveal buttons shown with `key`, in page order. */
function revealButtons(key) {
  return [...document.querySelectorAll('#page-agent button.reveal')].filter((b) => REVEALS.has(b) && REVEALS.get(b).key === key && !b.closest('[hidden]'));
}
/** Where a reveal was pressed: its key, its rank among the buttons drawn
 *  with it, its session and its section. */
function revealPlace(btn) {
  const key = REVEALS.get(btn).key;
  return { key, rank: revealButtons(key).indexOf(btn), session: S.agentId, block: btn.closest('section.block') };
}
/** The answer to the reveal pressed at `at` (`had`: its button had the
 *  focus): in its box, else in the box drawn now with the same key at its
 *  rank, never another's. One that asks for itself or shows its value
 *  already keeps its own answer. With none drawn now (the page says Not
 *  connected), nothing is drawn, and a focus that fell goes to a heading. */
function revealAnswered(btn, at, r, had) {
  if (btn.isConnected) { REVEALS.get(btn).answered(r, had); return; }
  const alike = S.page === 'agent' && S.agentId === at.session ? revealButtons(at.key) : [];
  const to = alike[Math.min(Math.max(at.rank, 0), alike.length - 1)];
  if (!to) { if (had && focusFell()) focusHeading(at.block); return; }
  if (to.disabled || to.getAttribute('aria-expanded') === 'true') return;
  REVEALS.get(to).answered(r, had);
}
/** Focus a card, a row, a line or a heading: none is a control, so none is
 *  a Tab stop (tabindex -1); the page keeps its scroll. */
function focusThere(x) {
  if (!x.hasAttribute('tabindex')) x.setAttribute('tabindex', '-1');
  x.focus({ preventScroll: true });
}
/** An Escape that closes what it is pressed in: not one a note took
 *  (`preventDefault`), one that ends an IME composition (keyCode 229 where a
 *  browser does not say isComposing), or one with a modifier. */
function plainEscape(e) {
  if (e.key !== 'Escape' || e.defaultPrevented || e.isComposing || e.keyCode === 229) return false;
  return !(e.shiftKey || e.ctrlKey || e.altKey || e.metaKey);
}
/** The answer pressed on card `id` of `place` came back where it was:
 *  refused, or a let-through that worked. A refusal shown on its card
 *  (`refusedOn`) gives the focus back to the button pressed, on again, and
 *  its words describe the button. A let-through's row, or a card drawn
 *  meanwhile in another state, takes the focus itself; a card gone, its
 *  list does (focusOn). */
function focusAnswered(place, id, list, refusedOn) {
  const f = S.answerFocus;
  if (!f || f.place !== place || f.id !== id) return;
  S.answerFocus = null;
  if (!focusFell()) return;
  const b = refusedOn && [...refusedOn.querySelectorAll('button')].find((x) => x.textContent === f.words && !x.disabled);
  const words = refusedOn && refusedOn.querySelector('.ask-error');
  if (b && words) {
    b.setAttribute('aria-describedby', words.id);
    b.focus({ preventScroll: true });
    return;
  }
  const now = drawnCards(list).get(id);
  if (now) focusThere(now);
  else focusOn(f, list);
}
/** An answer that worked, its list drawn again with the focus fallen: the
 *  card with its id when still drawn (an answered row's new outcome), else
 *  the one that took its place, else the one before it; with none left, the
 *  list's own line ("Nothing is waiting for you."), else the heading of its
 *  section, else the page's. Never an answer button: a second Enter must not
 *  answer another question. A card still drawn keeps the focus across the
 *  next draws while it has it (`on`). */
function focusOn(f, list) {
  // The focus did not fall: the person has it somewhere.
  if (!focusFell()) { S.answerFocus = null; return; }
  const shown = (x) => !!x && x.isConnected && !x.closest('[hidden]');
  const cards = [...drawnCards(list).values()].filter(shown);
  const same = cards.find((c) => c.dataset.id === f.id);
  const block = list && list.closest('section.block');
  const to = same || cards[Math.min(f.rank, cards.length - 1)]
    || (list && [...list.children].find((c) => c.classList.contains('empty') && shown(c)))
    || (shown(block) ? block.querySelector('h2') : null)
    || document.querySelector('#main > section[data-page="' + S.page + '"] h1');
  if (same) f.on = same;
  else S.answerFocus = null;
  if (to) focusThere(to);
}

/** The poll keeps the keyboard focus (dashboard.md §4.25 *The poll keeps
 *  the focus*). A changed answer draws a list again from nothing, and the
 *  focused control leaves the page: the focus falls to <body>, a screen
 *  reader loses its place and the next Tab starts over. Before the poll
 *  draws, `pollPlace(root)` says where the focus is under the root it draws
 *  into (#main, the agent page, Rule changes), in terms the draw makes
 *  again, as the inspector's render-helpers.js focusPlace does: each
 *  keyed element on the way down (its id, or the data-* it is drawn with: a
 *  card's data-id, a row's or a Details link's data-session) and its rank
 *  among those keyed alike, then the control's tag, rank and words. Keys
 *  are compared as values, never spliced into a selector: ids are server
 *  data. Ids the page numbers as it draws (a note, an answer's words, the
 *  words that name a card: nameBy) are no keys, nor is a menu's colour
 *  (a rule's `data-effect`, a label menu's `data-level`, `data-send` and
 *  `data-from`: what the menu shows, not which it is). A menu
 *  with a name reads as its name, not its options: a change in it changes
 *  what it shows (a rule's "What happens for <host>" turned from allowed to
 *  blocked), not which menu it is. While an answer holds the focus
 *  (holdFocus), it says where the focus goes, so the poll takes no place. */
const DRAWN_ID = /^(help|ask-error|ask-name)-\d+$/;
const COLOUR_DATA = new Set(['data-effect', 'data-level', 'data-send', 'data-from', 'data-outcome']);
function placeKey(x) {
  const keys = x.id && !DRAWN_ID.test(x.id) ? [['id', x.id]] : [...x.attributes].filter((a) => a.name.startsWith('data-') && !COLOUR_DATA.has(a.name)).map((a) => [a.name, a.value]);
  return keys.length ? JSON.stringify([x.tagName, keys]) : null;
}
/** The elements of a live HTMLCollection, its length read once. Spread
 *  (or for…of) reads the length again at every step, and in jsdom that
 *  read scans the whole collection for an element named "length": with
 *  the file browser's 521 rows drawn and the focus in one, one poll's
 *  place took 7 s on an idle host and over a minute on the CI guest
 *  (pipelines 10830 to 10834). */
function listed(coll) {
  const out = [];
  for (let i = 0, n = coll.length; i < n; i++) out.push(coll[i]);
  return out;
}
function keyedAlike(at, key) { return listed(at.getElementsByTagName(JSON.parse(key)[0])).filter((x) => placeKey(x) === key); }
function readsAs(x) {
  if (x.tagName === 'SELECT' && x.getAttribute('aria-label')) return 'SELECT ' + x.getAttribute('aria-label');
  return x.tagName + ' ' + (x.type || '') + ' ' + String(x.textContent || '').replace(/\s+/g, ' ').trim();
}
function isControl(x) { return x.matches('a[href], button, input, select, textarea, summary, [role="button"]'); }
function reachable(x) {
  return !x.disabled && !x.closest('[hidden]') && !(x.closest('details:not([open])') && !x.closest('details:not([open]) > summary'));
}
function pollPlace(root) {
  const x = root && root.ownerDocument.activeElement;
  if (S.answerFocus || !x || x === root || !root.contains(x)) return null;
  const keyed = [];
  for (let p = x; p !== root; p = p.parentElement) if (placeKey(p)) keyed.unshift(p);
  const steps = [];
  let at = root;
  for (const p of keyed) {
    const key = placeKey(p);
    steps.push({ key, rank: keyedAlike(at, key).indexOf(p) });
    at = p;
  }
  const tag = at === x ? null : x.tagName;
  return {
    root, steps, tag, rank: tag ? listed(at.getElementsByTagName(tag)).indexOf(x) : 0, words: readsAs(x), control: isControl(x),
    // A help note open at the place (helpButton) opens again with it.
    open: x.classList.contains('help-btn') && x.getAttribute('aria-expanded') === 'true',
    block: x.closest('section.block'),
  };
}
/** After the draw, only if the focus fell (an answer's or a mark's own
 *  focus, or one the person moved, stays): the control drawn at that place
 *  that reads the same, or the card, row or step that had the focus itself,
 *  found by its key; else its section's heading, else the page's (as an
 *  answer does, focusOn). Never another action, never <body>. */
function pollRefocus(place) {
  const doc = place && place.root.ownerDocument;
  const now = doc && doc.activeElement;
  if (!place || (now && now !== doc.body && now.isConnected)) return;
  let at = place.root;
  for (const s of place.steps) at = at && keyedAlike(at, s.key)[s.rank];
  // A control reads as before; a keyed card, row or step is the same one
  // by its key, whatever its words (its count, its moment) say now.
  const fits = (c) => !!c && reachable(c) && (!place.tag && !place.control ? true : readsAs(c) === place.words);
  let to = null;
  if (at && !place.tag) to = fits(at) ? at : null;
  else if (at) {
    const alike = listed(at.getElementsByTagName(place.tag));
    to = fits(alike[place.rank]) ? alike[place.rank] : alike.find(fits) || null;
  }
  if (to) {
    to.focus({ preventScroll: true });
    // A card or the line of a list an answer landed on (focusThere) is drawn
    // anew without its tabindex, and focus() alone leaves it on <body>.
    if (doc.activeElement !== to && !place.control) focusThere(to);
    if (place.open) setHelp(to, true);
    return;
  }
  focusHeading(place.block);
}

// ── Pages ─────────────────────────────────────────────────────────────────────
// Pages are PATHS under the base path (History API; dashboard.md §4.25v), the
// server answering each with this one index.html:
//   /                     home
//   /approvals[/<askId>]  approvals, that waiting question marked
//   /rules  /settings  /history (every session, dashboard.md §4.25ae)
//   /history?q=<words>    History found by a search (*Finding a session*);
//                         `&only=stepped-in` (or `?only=`) keeps the sessions
//                         where Mandu stepped in
//   /agents/<sessionId>   the agent page; `?ask=<askId>` marks a moment,
//                         `?only=stepped-in` shows only where Mandu stepped in
//   /rules#<key>  /settings#<key>  that page at one of its cards (SECTIONS)
// A path names the resource, the query only view state (the agent page's
// mark, History's search). Segments are encodeURIComponent-written and decoded on read.
const PAGES = ['home', 'approvals', 'rules', 'settings', 'agent', 'history'];
/** The `?only=` of the agent page's switch and History's (§4.25ae *Only
 *  where Mandu stepped in*, *Only the sessions where Mandu stepped in*);
 *  any other value reads as off. */
const ONLY_STEPPED_IN = 'stepped-in';
/** The cards of Rules and Settings, each with its address (dashboard.md
 *  §4.25 *Section links*): `[key, the card's id, the words of its link]`.
 *  The row under each page's title links them in this order, and
 *  `/rules#<key>` opens Rules at that card. */
const SECTIONS = {
  rules: [
    ['describe', 'describe-block', 'Describe'],
    ['your-rules', 'rules-block', 'Your rules'],
    ['who', 'by-who-block', 'Who may get your secrets'],
    ['keys-found', 'suggested-block', 'Keys Mandu found'],
    ['built-in', 'builtin-block', 'Built-in protections'],
  ],
  settings: [
    ['protection', 'settings-protection-block', 'Protection'],
    ['models', 'settings-models-block', 'Models'],
    ['sensitivity-labels', 'settings-labels-block', 'Sensitivity labels'],
    ['prompt-filters', 'settings-prompt-block', 'Prompt filters'],
    ['notifications', 'settings-notify-block', 'Notifications'],
    ['appearance', 'settings-appearance-block', 'Appearance'],
  ],
};
/** The section of `page` a hash names (`#keys-found`), or null. */
function sectionOf(page, hash) {
  const key = String(hash || '').replace(/^#/, '');
  return SECTIONS[page] && SECTIONS[page].some((s) => s[0] === key) ? key : null;
}
/** The key of the card `id` on `page`, or null. */
function sectionKey(page, id) {
  const s = SECTIONS[page] && SECTIONS[page].find((x) => x[1] === id);
  return s ? s[0] : null;
}
/** Each page's name as the person reads it (the tab title, the nav). */
const PAGE_NAMES = { home: 'Home', approvals: 'Approvals', rules: 'Rules', settings: 'Settings', agent: 'Agent', history: 'History' };
const enc = encodeURIComponent;

/** The URL (absolute, under the base path) of a page; `id` is the agent
 *  page's session or the approvals page's question, `ask` the agent page's
 *  marked moment. An agent page with no session is Home. */
function routeHref(page, id, ask) {
  if (page === 'approvals') return BASE + '/approvals' + (id ? '/' + enc(id) : '');
  if (page === 'rules' || page === 'settings' || page === 'history') return BASE + '/' + page;
  if (page === 'agent' && id) return BASE + '/agents/' + enc(id) + (ask ? '?ask=' + enc(ask) : '');
  return BASE + '/';
}

/** The page a URL names: { page, session, ask }, and on Rules and Settings
 *  the card its hash names (`section`, only a key SECTIONS knows). A retired
 *  query-string URL (`?page=inbox&ask=…`, `?page=agent&session=…`) reads as
 *  its page (the server already 302s those; this keeps a stale tab working).
 *  An unknown or garbled path reads as Home. */
function parseRoute(pathname, search, hash) {
  const q = new URLSearchParams(search || '');
  let path = pathname || '/';
  if (BASE && (path === BASE || path.startsWith(BASE + '/'))) path = path.slice(BASE.length) || '/';
  const home = { page: 'home', session: null, ask: null };
  if ((path === '/' || path === '/index.html') && q.has('page')) {
    const p = q.get('page');
    if (p === 'inbox' || p === 'approvals') return { page: 'approvals', session: null, ask: q.get('ask') || null };
    if (p === 'rules' || p === 'settings') return { page: p, session: null, ask: null };
    if (p === 'agent' && q.get('session')) return { page: 'agent', session: q.get('session'), ask: q.get('ask') || null };
    return home;
  }
  let segs;
  try { segs = path.split('/').slice(1).map(decodeURIComponent); } catch { return home; }
  const [first, second, ...more] = segs;
  if (more.length) return home;
  if (first === 'approvals' && second === undefined) return { page: 'approvals', session: null, ask: null };
  if (first === 'approvals' && second) return { page: 'approvals', session: null, ask: second };
  if (first === 'history' && second === undefined) return { page: first, session: null, ask: null, q: historyQuery(q.get('q')), ...(q.get('only') === ONLY_STEPPED_IN ? { only: true } : {}) };
  if ((first === 'rules' || first === 'settings') && second === undefined) {
    const section = sectionOf(first, hash);
    return { page: first, session: null, ask: null, ...(section ? { section } : {}) };
  }
  if (first === 'agents' && second) return { page: 'agent', session: second, ask: q.get('ask') || null, ...(q.get('only') === ONLY_STEPPED_IN ? { only: true } : {}) };
  return home;
}
const currentRoute = () => parseRoute(location.pathname, location.search, location.hash);

/** The URL a page state is canonically at. */
function stateHref() {
  if (S.page === 'agent') {
    const href = routeHref('agent', S.agentId, S.agentAsk);
    return S.agentOnly ? href + (href.includes('?') ? '&' : '?') + 'only=' + ONLY_STEPPED_IN : href;
  }
  if (S.page === 'approvals') return routeHref('approvals', S.approvalsAsk);
  if (S.page === 'history' && (S.historyQ || S.historyOnly)) return routeHref('history') + '?' + historyParams(S.historyQ, S.historyOnly);
  if (S.section && SECTIONS[S.page]) return routeHref(S.page) + '#' + S.section;
  return routeHref(S.page);
}

/** `nav`: a page change the person made (a link, Back or Forward), which
 *  moves the focus to the page (focusPage); not the first load. `restore`:
 *  the place Back or Forward returns to (savePlace; dashboard.md §4.25
 *  *Back and Forward keep your place*), which History, Approvals and Home
 *  return to; a link starts the page at its top. */
function setPage(page, push, sessionId, askId, nav = push, restore = null) {
  // The page left keeps its place in its own entry, and the new one names
  // it (the back link of the agent page, agentBack).
  const left = S.page;
  if (push) savePlace(page === 'agent' ? sessionId || null : null);
  S.page = PAGES.includes(page) ? page : 'home';
  if (S.page === 'agent') S.agentId = sessionId || currentRoute().session || S.agentId || null;
  // `ask`: the ask whose moment the agent page marks (dashboard.md §4.25h).
  // A plain link to an agent (no data-ask) opens the page unmarked.
  const urlAsk = () => (askId === undefined ? currentRoute().ask : askId) || null;
  S.agentAsk = S.page === 'agent' ? urlAsk() : null;
  // On approvals, `ask` is the waiting question a Home card's Details link
  // (or a notification) opened it for: that card is marked and scrolled to
  // (dashboard.md §4.25, "Details").
  S.approvalsAsk = S.page === 'approvals' ? urlAsk() : null;
  S.approvalsScrolled = false;
  // History's search lives in its address: a link starts without one, Back
  // or Forward and a typed address keep theirs (§4.25ae *Finding a session*).
  clearTimeout(historySearchTimer);
  // Rules' Find a rule is never kept (§4.25f *Find a rule*): every page
  // change empties it, so the next visit lists every rule.
  clearRuleFind(false);
  S.historyQ = S.page === 'history' && !push ? currentRoute().q || '' : '';
  if (S.page === 'history') document.getElementById('history-q').value = S.historyQ;
  // And its switch (§4.25ae *Only the sessions where Mandu stepped in*).
  S.historyOnly = S.page === 'history' && !push && currentRoute().only === true;
  if (S.page === 'history') document.getElementById('history-only').setAttribute('aria-checked', String(S.historyOnly));
  // So does the agent page's switch (§4.25ae *Only where Mandu stepped in*):
  // a link to a session opens it whole.
  S.agentOnly = S.page === 'agent' && !push && currentRoute().only === true;
  // And Rules' and Settings' card (§4.25 *Section links*): a typed address,
  // a new tab or Back opens at the card its hash names; a link opens the
  // page at its top (openAtCard names its card after).
  S.section = SECTIONS[S.page] && !push ? currentRoute().section || null : null;
  if (S.page === 'agent' && !S.agentId) S.page = 'home';
  for (const sec of document.querySelectorAll('#main > section[data-page]')) sec.hidden = sec.dataset.page !== S.page;
  for (const a of document.querySelectorAll('#nav [data-page-link]')) {
    if (a.dataset.pageLink === S.page) a.setAttribute('aria-current', 'page');
    else a.removeAttribute('aria-current');
  }
  // A push is a navigation; otherwise (boot, back/forward) the address bar is
  // only made canonical: a retired query URL or an unknown path is replaced
  // by the page's own path, adding no history entry. On Rules and Settings
  // the hash counts too: one that names no card goes.
  const href = stateHref();
  const at = location.pathname + location.search + (SECTIONS[S.page] ? location.hash : '');
  if (push) history.pushState({ from: left }, '', href);
  else if (at !== href) history.replaceState(history.state, '', href);
  S.pageTitle = S.page === 'home' ? 'Mandu' : 'Mandu · ' + PAGE_NAMES[S.page];
  renderTitle();
  const back = restore && PLACE_PAGES.includes(S.page) ? restore : null;
  window.scrollTo(0, back ? back.y || 0 : 0);
  S.visit++;
  // Held until the page has landed there: a scroll on the way (the page
  // shorter until its read draws) is not the place.
  S.placeHeld = back ? S.visit : 0;
  // Back to Approvals keeps the place you left, not that of its marked
  // card (markApprovalsAsk still gives the card the focus).
  S.approvalsPlace = !!back && S.page === 'approvals';
  if (S.page === 'agent') agentBack();
  if (nav) focusPage();
  // Rules and Settings return their reads, done once drawn: a link to one of
  // their cards scrolls there then (openAtCard). Rules' include the folder
  // Add a rule opens with on its first read, when it was left open.
  let load = null;
  if (S.page === 'rules') load = loadRules().then(() => F.listing);
  // A link to Approvals starts its lists of the past over at their newest
  // 20, as a link to History does; Back keeps the rows you had brought.
  if (S.page === 'approvals' && !back) startPastOver();
  if (S.page === 'approvals') keepPlace(loadRuleHistory(), back);
  if (S.page === 'approvals' && S.home) markApprovalsAsk();
  if (S.page === 'settings') load = loadSettings();
  if (S.page === 'agent') loadAgent();
  if (S.page === 'history') loadHistory(false, back);
  if (S.page === 'home') keepPlace(null, back);
  return load;
}
/** An address that names a card (§4.25 *Section links*: a typed address, a
 *  new tab, Back or Forward): the page lands there once `load`, what draws
 *  above the card, has drawn, as a link to it does (openAtCard), the focus
 *  on the card's heading. */
function landAtSection(load) {
  const card = S.section && SECTIONS[S.page] && SECTIONS[S.page].find((x) => x[0] === S.section);
  if (!card) return;
  focusPage();
  landAtCard(load, card[1]);
}

// ── Back and Forward keep your place (dashboard.md §4.25) ────────────────────
/** The pages Back and Forward return to where you left them; the others
 *  start at their top, as a link does. */
const PLACE_PAGES = ['history', 'approvals', 'home'];
/** Writes the place of the page shown into its own history entry, which Back or
 *  Forward hands back (popstate): how far it was scrolled (`y`), how many
 *  History rows were loaded (`rows`) and the session whose agent page it
 *  opened (`opened`, kept from the last push when not given). A browser that
 *  refuses the write (too many) keeps the last one. */
function savePlace(opened) {
  const st = history.state && typeof history.state === 'object' ? history.state : {};
  const had = st.place || {};
  // Still landing on a place Back gave (placeHeld): that place stays, only
  // the session a push opens is new.
  const held = !!S.placeHeld && S.placeHeld === S.visit;
  if (held && opened === undefined) return;
  const place = {
    y: held ? had.y || 0 : Math.round(window.scrollY || 0),
    rows: held ? had.rows || 0 : S.page === 'history' && S.history ? S.history.rows.length : 0,
    opened: opened === undefined ? had.opened || null : opened,
  };
  try { history.replaceState({ ...st, place }, ''); } catch { /* the last place stays */ }
}
/** Back to Approvals or Home, once what the page reads has drawn (`read`,
 *  the rule changes of Approvals): scrolled again to the place, if a page shorter
 *  meanwhile held it above and nobody scrolled since. Then the place is
 *  the page itself to keep again (savePlace). */
function keepPlace(read, back) {
  if (!back) return;
  const visit = S.visit;
  const at = window.scrollY;
  Promise.resolve(read).then(() => {
    if (S.visit !== visit) return;
    if (window.scrollY === at && at !== back.y) window.scrollTo(0, back.y || 0);
    S.placeHeld = 0;
  });
}
/** The names of the pages the back link of the agent page returns to. */
const BACK_TO = { history: 'Back to History', approvals: 'Back to Approvals', home: 'Back to home' };
/** The back link of the agent page names the page it was opened from in this
 *  tab (the entry before it, `from`), and returns there as Back does
 *  (wireNav), so that page keeps your place. Opened from a fresh tab, a
 *  typed address or another page: "Back to home", a link Home. */
function agentBack() {
  const a = document.getElementById('agent-back');
  if (!a) return;
  const from = history.state && history.state.from;
  const to = Object.prototype.hasOwnProperty.call(BACK_TO, from) ? from : 'home';
  a.textContent = BACK_TO[to];
  a.dataset.pageLink = to;
  a.href = routeHref(to);
  a.dataset.back = to === from ? '1' : '';
}
function wireNav() {
  document.addEventListener('click', (e) => {
    const a = e.target.closest('a[data-page-link]');
    if (!a) { rowClick(e); return; }
    if (e.metaKey || e.ctrlKey || e.shiftKey) return;
    e.preventDefault();
    // The back link of the agent page, to the page before it in this tab, is Back.
    if (a.id === 'agent-back' && a.dataset.back) { history.back(); return; }
    setPage(a.dataset.pageLink, true, a.dataset.session, a.dataset.ask || null);
  });
  // A middle click on a session row opens it in a new tab, as on its link.
  document.addEventListener('auxclick', (e) => { if (e.button === 1) rowClick(e); });
  window.addEventListener('popstate', () => {
    const r = currentRoute();
    const st = history.state;
    landAtSection(setPage(r.page, false, r.session, r.ask, true, st && st.place ? st.place : null));
  });
  // Back and Forward return to the place a page had (savePlace): the page
  // decides it, never the restore of the browser, which landed before the
  // rows were read again.
  if ('scrollRestoration' in history) history.scrollRestoration = 'manual';
  let placeTimer = 0;
  window.addEventListener('scroll', () => {
    clearTimeout(placeTimer);
    placeTimer = setTimeout(() => savePlace(), 250);
  }, { passive: true });
  // A focus the person moves elsewhere leaves the mark (focusMarked) and an
  // answer's place (holdFocus).
  document.addEventListener('focusin', (e) => {
    if (S.marked && e.target !== S.marked) S.marked = null;
    if (S.answerFocus && e.target !== S.answerFocus.on) S.answerFocus = null;
  });
  // The page's own links are written relative (they resolve against the
  // served <base href>); made absolute from BASE here like every built route.
  for (const a of document.querySelectorAll('a[data-page-link]')) a.href = routeHref(a.dataset.pageLink, a.dataset.session, a.dataset.ask);
  for (const a of document.querySelectorAll('a[href^="dev/"]')) a.href = DEV_URL + a.getAttribute('href').slice('dev/'.length);
  // No developer view in this build: what only points there goes.
  if (!HAS_DEV) for (const e of document.querySelectorAll('[data-dev-only]')) e.hidden = true;
  // View as public: the Developer view card turns it on; the bar it shows
  // on every page turns it off. The page reloads so each part draws again.
  document.getElementById('as-public').hidden = !AS_PUBLIC;
  document.getElementById('settings-view-public').addEventListener('click', () => setViewAsPublic(true));
  document.getElementById('as-public-off').addEventListener('click', () => setViewAsPublic(false));
}

/** A pointer click anywhere on a session row of Home or History opens that
 *  session as its Details does (dashboard.md §4.25 *A click on a session's
 *  row opens it*): a plain click in place, a Ctrl/⌘/Shift-click or a middle
 *  click in a new tab, at the link's address. Not a click on a control in
 *  the row (Details, the Preview and warning marks, their open note and its
 *  link) nor one that ends a text selection. The row stays no control:
 *  Details is its one tab stop and keeps its name. One listener for every
 *  row, so a row keepRows keeps is no different. */
function rowClick(e) {
  const row = e.target.closest('.row.agent[data-session]');
  if (!row || e.target.closest('a, button, input, label, .help')) return;
  const sel = window.getSelection ? window.getSelection() : null;
  if (sel && String(sel).trim()) return;
  const link = row.querySelector('a[data-page-link="agent"]');
  if (!link) return;
  if (e.button === 1 || e.metaKey || e.ctrlKey || e.shiftKey) {
    window.open(link.href, '_blank', 'noopener');
    return;
  }
  setPage('agent', true, link.dataset.session);
}

/** Turn View as public on or off in this browser, and draw the page again. */
function setViewAsPublic(on) {
  if (on) lsSet(AS_PUBLIC_KEY, '1');
  else lsDel(AS_PUBLIC_KEY);
  location.reload();
}

/** A page change gives the keyboard focus to the page shown (dashboard.md
 *  §4.25 *A page change moves the focus*): its heading, which a screen
 *  reader reads, so the next Tab starts in the page. Without it the focus
 *  stayed on the link the change hid (on <body> in a browser), and a Tab
 *  from a link to an earlier page left the document. Not on the first load,
 *  where the browser places it. preventScroll: the page keeps its scroll. */
function focusPage() {
  S.marked = null;
  S.pageHeading = document.querySelector('#main > section[data-page="' + S.page + '"] h1');
  if (!S.pageHeading) return;
  S.pageHeading.setAttribute('tabindex', '-1');
  S.pageHeading.focus({ preventScroll: true });
}
/** What a page scrolls to by itself once a visit (the marked Approvals card,
 *  the step where Mandu asked, the card a link opens at) takes the focus
 *  from the heading a page change gave it (`scrolled`); a person who moved
 *  the focus keeps it. Drawn again by a poll while it still had the focus
 *  (S.marked, dropped by a focus elsewhere), which then fell to the page,
 *  the new one takes it back. No ring: it is not a control, and its mark
 *  shows it. */
function focusMarked(target, scrolled) {
  if (!target) return;
  const now = document.activeElement;
  const take = scrolled
    ? !!S.pageHeading && now === S.pageHeading
    : !!S.marked && !S.marked.isConnected && (!now || now === document.body);
  if (!take) return;
  // A control (the Protection switch) keeps its place in the tab order.
  if (target.tabIndex < 0) target.setAttribute('tabindex', '-1');
  target.focus({ preventScroll: true });
  S.marked = target;
}

/** "See what the agent was doing": the agent page, opened at the step where
 *  this ask was raised (dashboard.md §4.25h), or at its top without an ask
 *  (a rule the agent asked for, §4.25i). `about`: the words of a row that
 *  shares its sentence with others, which name the link (rowControlName). */
function askLink(sessionId, askId, style, about) {
  const text = 'See what the agent was doing';
  return el('a', {
    href: routeHref('agent', sessionId, askId),
    'data-page-link': 'agent', 'data-session': sessionId, 'data-ask': askId || null,
    class: 'ask-link', text, style, 'aria-label': about ? rowControlName(text, about) : null,
  });
}

// ── Home ──────────────────────────────────────────────────────────────────────
async function loadHome() {
  // Polls overlap (the first read, the 10 s poll, a return to the tab, the
  // read after an answer), and on a slow network one can answer after a
  // poll asked later. Its answer is older than what the page shows, so it is
  // dropped (dashboard.md §4.25 *An older poll's answer never draws over a
  // newer one*): never the service running again after a newer poll found
  // it stopped, nor a question you answered drawn as waiting again.
  const asked = ++S.homeAsked;
  // Back: this poll answered after one that failed (readAgainUnread). Read
  // after the await, so of two polls that overlap only one is back.
  let back = false;
  try {
    const answer = await apiGet('home');
    if (asked < S.homeTaken) return;
    S.homeTaken = asked;
    S.home = answer;
    back = S.homeFailure !== null;
    S.homeFailure = null;
  } catch (err) {
    if (asked < S.homeTaken) return;
    S.homeTaken = asked;
    S.home = null;
    S.homeFailure = readFailure(err);
    notifyAlarms(null, S.homeFailure);
    const place = pollPlace(document.getElementById('main'));
    renderTopStatus(null);
    followRunning();
    renderHero(null, S.homeFailure);
    renderBuiltIn(null);
    renderFirstRun(null);
    renderExposure(null);
    // Every section the answer fills says it could not check, never a bare
    // heading, nor the last poll's questions with live buttons (dashboard.md
    // §4.25 *Empty states*), each with the cause this poll knows. The open
    // agent page reads again, and says why it cannot show the session.
    renderHomeWaiting(null);
    renderAgents(null);
    renderEarlier(null);
    renderApprovals(null);
    markApprovalsAsk();
    followCannotCheck();
    renderTitle();
    refreshWhen();
    pollRefocus(place);
    if (S.page === 'agent') loadAgent();
    return;
  }
  // Here, before the reads below, so a poll that fails meanwhile follows
  // this answer (the stop is told once, after a read that listed an agent).
  notifyAlarms(S.home, null);
  // Mandu's suggestions ride the same poll: the Approvals card, the Suggested
  // badge and view follow a scan, a Save or a dismissal made anywhere.
  // A viewer without the admin session is refused them: not asked again
  // on every poll (the view still asks when opened).
  await Promise.all([loadProposals(), G.denied ? null : loadSuggestions()]);
  // Where the focus is before the sections draw, to give it back after a
  // changed answer drew its list again (pollPlace).
  const place = pollPlace(document.getElementById('main'));
  renderRulesPending();
  renderTopStatus(S.home);
  followRunning();
  renderHero(S.home);
  renderBuiltIn(S.home);
  renderFirstRun(S.home);
  renderExposure(S.home);
  renderHomeWaiting(S.home);
  renderAgents(S.home);
  renderEarlier(S.home);
  renderApprovals(S.home);
  renderProposals();
  markApprovalsAsk();
  if (back) readAgainUnread();
  else { followCannotCheck(); if (F.unread === 'new') readFolderAgain(); }
  if (S.page === 'approvals') { loadRuleHistory(); followAnswered(asked); }
  if (S.page === 'history') followHistory(asked);
  notifyNewAsks(S.home);
  renderTitle();
  refreshWhen();
  pollRefocus(place);
  if (S.page === 'agent') loadAgent();
}

/** The waiting cards of Home and the line to the rule changes under them,
 *  drawn again only when the answer changed (sameAsDrawn): the words of a
 *  refused answer stay on its card, also when drawn again (putBackAnswers).
 *  No answer: the cards say they could not check. */
function renderHomeWaiting(home) {
  const host = document.getElementById('home-waiting');
  if (!home) {
    if (!sameAsDrawn('home-waiting', ['failed', S.homeFailure])) { renderAsks(host, null, false); putBackAnswers('home', host); }
    return;
  }
  const asks = home.waitingKnown ? home.waiting : 'unknown';
  if (sameAsDrawn('home-waiting', [asks, S.proposals.length, S.proposals.some((p) => p.onDisk)])) return;
  renderAsks(host, home, false, S.proposals.length > 0);
  putBackAnswers('home', host);
  renderHomeProposalLink();
}

function renderTopStatus(home) {
  const host = document.getElementById('top-status');
  const badge = document.getElementById('nav-approvals-count');
  const waiting = (home && home.waitingKnown ? home.waiting.length : 0) + S.proposals.length;
  badge.textContent = String(waiting);
  badge.hidden = waiting === 0;
  // Home's summary of the Approvals page counts what the nav badge counts.
  const title = document.getElementById('home-waiting-title');
  if (title) title.textContent = waiting ? 'Approvals waiting (' + waiting + ')' : 'Approvals waiting';
  // A live region: written again only when what it says changed, never
  // every poll (§4.25 *The poll keeps your place*).
  if (sameAsDrawn('top-status', home ? [home.protection.level, home.protection.connected, home.protection.configured] : 'failed')) return;
  clear(host);
  if (!home) {
    host.append(el('span', { class: 'dot bad' }), protectionLink('Not connected'));
    return;
  }
  // On or off, the words of the Settings switch (§4.25 *The top bar says on
  // or off*): the product offers no level to name.
  const state = protectionState(home.protection.level);
  const cls = state === 'off' ? 'warn' : state === 'unknown' ? '' : 'ok';
  const words = { on: 'Protection on', off: 'Protection off', unknown: 'Protection unknown' }[state];
  const saved = protectionState(home.protection.configured);
  const next = home.protection.connected && state !== 'unknown' && saved !== 'unknown' && saved !== state
    ? ' · ' + saved + ' from the next start' : '';
  host.append(el('span', { class: 'dot ' + cls }));
  // On, with nothing saved for the next start, there is nothing to do: words.
  if (state === 'on' && !next) host.append(words);
  else host.append(protectionLink(words, next));
}

/** The top bar's words while protection is not plainly on: a link to
 *  Settings that opens at the Protection card (openProtection). A modifier
 *  click is left to the browser: Settings, whose first card it is. Its name
 *  says where it goes; the words, and so the width, are those of the text. */
function protectionLink(words, next = '') {
  const a = el('a', { href: routeHref('settings'), class: 'top-status-link', 'aria-label': words + next + ': open Settings', onclick: (e) => {
    if (e.metaKey || e.ctrlKey || e.shiftKey) return;
    e.preventDefault();
    openProtection();
  } }, words);
  if (next) a.append(el('span', { class: 'dim', text: next }));
  return a;
}

/** A level as the product says it: off, unknown, or on (any level that
 *  protects). */
function protectionState(level) {
  return level === 'off' ? 'off' : (level === 'unknown' || !level) ? 'unknown' : 'on';
}

/** The Rules page "Built-in protections" (dashboard.md §4.25z): the list
 *  the server built for the mode running now, so the page never claims masking
 *  the mode does not do. Without the home, nothing is claimed. */
function renderBuiltIn(home) {
  const list = document.getElementById('builtin-list');
  const note = document.getElementById('builtin-note');
  if (!list || !note) return;
  const b = home && home.builtIn;
  if (sameAsDrawn('built-in', b || null)) return;
  clear(list);
  note.textContent = b ? b.note : 'not connected';
  const items = b ? b.items : ['The protection service is not reachable, so Mandu cannot say what is on.'];
  for (const text of items) list.append(el('li', { text }));
}

/** Without a home, `status` is the HTTP status the server answered (null
 *  when no answer came) and `serviceDown` its 503 `unreachable`. */
function renderHero(home, failure) {
  const hero = document.getElementById('hero');
  const icon = hero.querySelector('.hero-icon');
  const headline = document.getElementById('hero-headline');
  const sentence = document.getElementById('hero-sentence');
  const facts = document.getElementById('hero-facts');
  // Drawn again only when what it shows changed: its words, its counts and
  // their window, and the protection level its "?" names (maskedHelpText).
  if (sameAsDrawn('hero', home ? [home.verdict, home.headline, home.sentence, home.sentenceParts, home.window, home.ruleChangesWaiting, home.protection && home.protection.level] : ['failed', failure])) return;
  clear(icon); clear(facts); clear(sentence);
  if (!home) {
    hero.dataset.verdict = 'unknown';
    icon.append(svg(ICON.plug, 28));
    headline.textContent = 'Not connected.';
    // A 503 `unreachable`: the dashboard server answered, its protection
    // service did not (dashboard.md §6.y). Settings has its Start. Each
    // failure in words (readFailure), never the request (home → 503) or the
    // browser text of a fetch that threw (§4.25, *The hero says why in words*).
    if (failure === 'down') {
      sentence.append('The protection service is not running, so nothing can be checked. ',
        placeLink({ text: 'Start it under Settings', to: 'settings' }), ', or refresh in a moment.');
    } else sentence.append(failure === 'gone' ? NO_ANSWER_WORDS : errorWords(failure));
    return;
  }
  hero.dataset.verdict = home.verdict;
  const iconFor = { protected: 'shield', quiet: 'shield', 'secrets-only': 'shield', waiting: 'clock', failed: 'alert', off: 'shieldOff', unknown: 'plug' };
  icon.append(svg(ICON[iconFor[home.verdict] || 'shield'], 28));
  headline.textContent = home.headline;
  // The place the sentence names is a link (§4.25, *The hero links where it
  // points*): Settings, or the trace of the session where protection failed.
  sentence.append(textParts(home.sentenceParts, home.sentence));
  const w = home.window;
  const fact = (k, label, warn) => el('span', {}, el('strong', { class: warn ? 'warn' : '', text: String(k) }), ' ' + label);
  if (home.verdict !== 'unknown' && home.verdict !== 'off') {
    // The same counts and words as each session's page tiles (dashboard.md
    // §4.25): secrets as its Your secrets cards tell them, never the masked
    // tokens (one file masked twice is one secret, and a secret the AI read
    // before it was marked was not masked before the AI saw it). The first
    // masked count carries the "?".
    // A question waiting is about now, of any age, not the window's: it comes
    // first, before the window's lead (§4.25, *The counts name their window*).
    // Said once: the waiting verdict's headline already counts them ("2
    // questions are waiting for you."), so only a headline that does not
    // (Protection failed.) gets the fact. It counts the rule changes too,
    // as the Approvals badge does.
    const waitingNow = w.waiting + (home.ruleChangesWaiting || 0);
    if (waitingNow > 0 && home.verdict !== 'waiting') facts.append(fact(waitingNow, 'waiting for you', true));
    const counts = []; // the window's counts: [fact, its "?" or null]
    const masked = [];
    if (w.secretsMasked > 0) masked.push(fact(w.secretsMasked, w.secretsMasked === 1 ? 'secret masked before the AI saw it' : 'secrets masked before the AI saw them'));
    if (w.untrusted > 0) masked.push(fact(w.untrusted, w.untrusted === 1 ? 'untrusted item masked before the AI saw it' : 'untrusted items masked before the AI saw them'));
    masked.forEach((f, i) => counts.push([f, i === 0 ? maskedHelp() : null]));
    if (w.secretsEarly > 0) {
      const early = fact(w.secretsEarly, w.secretsEarly === 1 ? 'secret the AI read before it was marked a secret' : 'secrets the AI read before they were marked secrets', true);
      early.title = 'The AI read the real value as it was, before it was marked a secret. A session\'s page says when.';
      counts.push([early, null]);
    }
    if (w.blocked > 0) counts.push([fact(w.blocked, w.blocked === 1 ? 'action blocked' : 'actions blocked'), null]);
    if (w.sent > 0) {
      const sent = fact(w.sent, w.sent === 1 ? 'send with a real value filled in' : 'sends with a real value filled in');
      sent.title = (w.sent === 1 ? 'It' : 'Each') + ' went to a destination allowed to receive it. A session\'s page shows where.';
      counts.push([sent, null]);
    }
    // The window the counts cover leads the first of them, in its words
    // ("In the last 24 hours:"); not known, no lead, as the earlier list's
    // heading. A session counts whole, so one that began before the window
    // brings its earlier steps: the lead's title says so. On a busy day the
    // server adds up only some of the window's sessions, and the lead says
    // how many ("In 26 of the 31 sessions in the last 24 hours:").
    const span = windowWords(home);
    const scope = countedWords(w, span);
    const whole = span ? 'Each session active ' + span + ' counts whole, including its steps before then.' : '';
    const title = partlyCounted(w)
      ? 'Only ' + w.counted + ' of the ' + n(w.sessions, 'session', 'sessions') + (span ? ' active ' + span : '') + ' are added up (the newest, and any where protection failed), so the totals may be higher. History lists every session with its own counts.' + (span ? ' Each counts whole, including its steps before then.' : '')
      : whole;
    counts.forEach(([f, help], i) => {
      const lead = i === 0 && scope
        ? el('span', { class: 'facts-when', text: scope.charAt(0).toUpperCase() + scope.slice(1) + ':', title })
        : null;
      facts.append(lead || help ? el('span', {}, lead, lead && ' ', f, help && ' ', help) : f);
    });
    if (facts.childElementCount === 0) facts.append(el('span', { class: 'dim', text: nothingCounted(w, span, scope) }));
  }
}

/** The server added up only some of the window's sessions (`window.counted`
 *  under `window.sessions`: its cap, or a session it could not read), so the
 *  counts are a floor. A payload without `counted` (an older server): all. */
function partlyCounted(w) {
  return !!w && Number.isFinite(w.counted) && Number.isFinite(w.sessions) && w.counted < w.sessions;
}

/** The sessions the hero's counts add up, in words: the window's own ("in
 *  the last 24 hours") when every one is counted, else how many of them ("in
 *  26 of the 31 sessions in the last 24 hours"); '' when neither is known. */
function countedWords(w, span) {
  if (!partlyCounted(w)) return span;
  return 'in ' + w.counted + ' of the ' + n(w.sessions, 'session', 'sessions') + (span ? ' ' + span : '');
}

/** The hero's line when it has nothing to show: never "nothing" over sessions
 *  it did not count. */
function nothingCounted(w, span, scope) {
  if (partlyCounted(w) && w.counted === 0) {
    return (w.sessions === 1 ? 'The one session' : 'None of the ' + n(w.sessions, 'session', 'sessions')) + (span ? ' ' + span : '') + (w.sessions === 1 ? ' could not be counted.' : ' could be counted.');
  }
  return 'Nothing to count' + (scope ? ' ' + scope : '') + '.';
}

/** Another agent can reach Mandu's own controls (dashboard.md §4.25x): the
 *  server sends `exposure` only while that is so; the card names each agent
 *  that causes it, as its Home row does with a link to its page, and the
 *  fix, and hides as soon as it stops coming. */
function renderExposure(home) {
  const block = document.getElementById('home-exposure');
  if (!block) return;
  const x = home && home.exposure;
  if (sameAsDrawn('exposure', x || null)) return;
  block.hidden = !x;
  const causes = document.getElementById('exposure-causes');
  clear(causes);
  if (!x) return;
  document.getElementById('exposure-headline').textContent = x.headline;
  const sentence = document.getElementById('exposure-sentence');
  clear(sentence);
  sentence.append(x.sentence);
  if (Number.isFinite(x.since)) sentence.append(' Since ', whenNode(x.since), '.');
  for (const c of x.causes || []) causes.append(el('li', { 'data-pid': String(c.pid) }, textParts(c.parts, c.words)));
  const fix = document.getElementById('exposure-fix');
  clear(fix);
  fix.append(textParts(x.fixParts, x.fix));
}

/** The first-run setup card (dashboard.md §4.25, "First-run card"). The
 *  server sends `firstRun` only while no session exists; the card hides as
 *  soon as it stops coming (the first session, or a failed load). */
function renderFirstRun(home) {
  const block = document.getElementById('home-first-run');
  const fr = home && home.firstRun;
  if (sameAsDrawn('first-run', fr || null)) return;
  block.hidden = !fr;
  block.dataset.mode = fr ? fr.mode : '';
  const list = document.getElementById('first-run-steps');
  clear(list);
  if (!fr) return;
  document.getElementById('first-run-headline').textContent = fr.headline;
  document.getElementById('first-run-protects').textContent = fr.protects;
  for (const step of fr.steps || []) {
    const li = el('li', { class: 'first-run-step', 'data-step': step.id });
    li.append(el('div', { class: 'first-run-title', text: step.title }));
    li.append(el('p', { class: 'note' }, textParts(step.parts, step.text)));
    if (step.commands && step.commands.length) {
      const cmds = el('ul', { class: 'first-run-commands' });
      for (const c of step.commands) cmds.append(el('li', {}, el('code', { text: c.command }), el('span', { class: 'dim', text: c.does })));
      li.append(cmds);
    }
    if (step.link) li.append(el('a', { href: routeHref(step.link.page), 'data-page-link': step.link.page, text: step.link.text }));
    list.append(li);
  }
}

/** A card or row that asks for an answer, or records one, is a group named
 *  by its own words (dashboard.md §4.25 *A question has a name*). Its buttons
 *  sit beside its sentence, and the cards of a page offer the same ones, so
 *  until 2026-10-11 a screen reader read "Allow once, button" three times
 *  with no word of what each allows. The name is read as the focus enters
 *  the card, and when an answer gives the focus to the card itself
 *  (focusOn). The id is numbered as drawn (DRAWN_ID): Home and Approvals
 *  draw the same question at once, and ids are server data. */
let askNameSeq = 0;
function nameBy(box, words) {
  if (!words.id) words.id = 'ask-name-' + (++askNameSeq);
  box.setAttribute('role', 'group');
  box.setAttribute('aria-labelledby', words.id);
  return box;
}

/** Which session asked, on the moment line of a waiting card (dashboard.md
 *  §4.25u *A question says which session asked*): " · from Claude Code in
 *  ~/projects/shop", or " · from 2 sessions, last Claude Code in …" when
 *  more than one raised it, so two agents of one kind tell apart. The
 *  folder is a name as the cards draw one (nameCode: whole, or cut at its
 *  slashes). Null when the server knows no folder: the line is as before. */
function askedFrom(ask) {
  if (typeof ask.askerCwd !== 'string' || !ask.askerCwd) return null;
  const who = ask.askerAgent || 'the agent';
  const many = ask.askerSessions > 1 ? 'from ' + ask.askerSessions + ' sessions, last ' : 'from ';
  return el('span', { class: 'ask-from' }, ' · ' + many + who + ' in ', nameCode(shortPath(ask.askerCwd)));
}

function askCard(ask, expanded) {
  const card = el('div', { class: 'ask' + (expanded ? ' expanded' : ''), 'data-id': ask.id });
  const top = el('div', { class: 'ask-top' });
  top.append(el('div', { class: 'ask-icon' }, svg(ICON[FAMILY_ICON[ask.family] || 'alert'])));
  const body = el('div', { class: 'ask-body' });
  // Its names are kept whole, as in the cells (nameCode).
  const sentence = keepNamesWhole(sentenceNode(ask.sentence, 'ask-sentence'));
  body.append(sentence);
  nameBy(card, sentence);
  // Home's short card links to the same question on Approvals, where it is
  // shown in full and marked (dashboard.md §4.25, "Details"). The moment is
  // absolute and relative (§4.25u); the count stays.
  // A held open or change (`held` present) is asked again every half second
  // while the program waits, so its count is no number of tries. An agent
  // that ended since it asked waits on nothing (dashboard.md §4.34 "After
  // you answer"). The moment ends with a period only when a sentence or the
  // link follows it, as an Answered earlier row does (answeredWhat); alone
  // it reads as a row of History does, without one (§4.25u). The session
  // that asked last is named after the moment, where it works (askedFrom).
  const followed = !expanded || ask.askerEnded;
  body.append(el('div', { class: 'ask-sub' },
    expanded ? null : askCellWords(ask.whyParts, ask.why), expanded ? null : ' ',
    whenNode(ask.askedAt), ask.count > 1 && !('held' in ask) ? ', ' + ask.count + ' times' : '', askedFrom(ask), followed ? '.' : null,
    ask.askerEnded ? el('span', { class: 'ask-ended', text: ' The agent that asked has ended, so nothing is waiting on this now. Your answer counts the next time an agent asks.' }) : null,
    expanded ? null : ' ', expanded ? null : el('a', {
      href: routeHref('approvals', ask.id), 'data-page-link': 'approvals', 'data-ask': ask.id,
      class: 'ask-details', text: 'Details in Approvals',
    })));
  top.append(body);
  const actions = el('div', { class: 'ask-actions' });
  if (ask.family === 'prompt') {
    // Plan 15 §7: a held message the person wrote. The found text comes
    // from the holds route (filled in once it answers), and the three answers
    // go to the hold, for this message (the Approvals page adds the session,
    // except under a rule the administrator locked to ask every time:
    // plan 15 §12, 2026-10-04, `onlyThisMessage` says why).
    body.append(el('div', { class: 'ask-found', 'data-id': ask.id }));
    const onlyThis = typeof ask.onlyThisMessage === 'string' && ask.onlyThisMessage !== '';
    if (onlyThis && expanded) body.append(el('div', { class: 'ask-once-only note', text: ask.onlyThisMessage }));
    const verbs = [
      { label: 'Send as written', prompt: 'send', scope: 'once' },
      ...(expanded && !onlyThis ? [{ label: 'Send as written for this session', prompt: 'send', scope: 'session' }] : []),
      { label: 'Send masked', prompt: 'mask', scope: 'once', primary: true },
      { label: 'Cancel the message', prompt: 'cancel', scope: 'once' },
    ];
    for (const v of verbs) actions.append(el('button', { type: 'button', class: 'btn' + (v.primary ? ' primary' : ''), text: v.label, onclick: () => answer(ask, v, card) }));
  } else {
    // "Send without it" (dashboard.md §4.34): the next such request goes
    // with a marker where the secret was. Drawn only when the server offers
    // it (a secret's placeholder in a request); an older server's card,
    // which lists no answers, never shows it.
    const verbs = [
      { label: 'Allow once', approve: true, scope: 'once' },
      { label: 'Always allow', approve: true },
      { label: 'Send without it', approve: false, scope: 'once', strip: true },
      { label: 'Block', approve: false, primary: true },
    ];
    const keyOf = (a) => (a.strip ? 'strip' : a.scope === 'once' ? 'once' : a.approve ? 'approve' : 'deny');
    const offered = new Set((ask.actions || []).map(keyOf));
    // The word the server gives a verb where it differs: a send by a program of
    // the files it holds answers "Allow this session" (confidentiality plan
    // 13 §5.4), its Always being one per file below.
    const said = new Map((ask.actions || []).map((a) => [keyOf(a), a.label]));
    for (const v of verbs) {
      const key = keyOf(v);
      if (offered.size && !offered.has(key)) continue;
      if (key === 'strip' && !offered.has(key)) continue;
      const b = el('button', { type: 'button', class: 'btn' + (v.primary ? ' primary' : ''), text: said.get(key) || v.label, onclick: () => answer(ask, v, card) });
      actions.append(b);
    }
  }
  if (expanded) {
    card.append(top);
    if (ask.sources && ask.sources.length) card.append(askSources(ask, card));
    const detail = el('div', { class: 'ask-detail' });
    // Three cells, the AI the subject of the last two (dashboard.md §4.25u);
    // the server words each family (view-model/home.ts describeAsk).
    // Each cell names things as the sentence does (askCellWords).
    const cell = (k, parts, v, help) => el('div', {}, el('div', { class: 'k' }, k, help ? ' ' : null, help || null), el('div', { class: 'v' }, askCellWords(parts, v)));
    detail.append(cell('Why it stopped', ask.whyParts, ask.why));
    detail.append(cell('What the AI has now', ask.aiNowParts, ask.aiNow, maskedHelp()));
    // Named for the buttons the card offers: a run's change takes no Always
    // allow (confidentiality plan 13 §8 (c)).
    const always = !(ask.actions || []).length || (ask.actions || []).some((a) => a.approve && a.scope !== 'once');
    detail.append(cell(ask.family === 'prompt' || ask.sources ? 'What each answer does' : always ? 'If you click Allow once or Always allow' : 'If you click Allow once', ask.ifAllowedParts, ask.ifAllowed));
    card.append(detail);
    // What Send without it does, under the three cells (their grid stays
    // three): only on a card that offers it.
    if ((ask.actions || []).some((a) => a.strip)) card.append(el('p', { class: 'note ask-without' }, el('strong', { text: 'If you click Send without it: ' }), SEND_WITHOUT_WORDS));
    const foot = el('div', { style: 'display:flex;gap:8px;align-items:center;flex-wrap:wrap' });
    if (ask.sessions && ask.sessions.length) {
      const sid = ask.sessions[ask.sessions.length - 1];
      foot.append(askLink(sid, ask.id, 'margin-right:auto;font-size:14px'));
    }
    foot.append(actions);
    card.append(foot);
  } else {
    top.append(actions);
    card.append(top);
  }
  return card;
}

/** A send by a program of the secret files it holds (confidentiality plan 13
 *  §5.4, dashboard.md §4.34 "A send names every file"): each file, where it
 *  may go, and, for each file in the way, its own Always button, which adds
 *  the place to the rule of that file and nothing else. */
function askSources(ask, card) {
  const box = el('div', { class: 'ask-sources' });
  box.append(el('div', { class: 'k', text: 'What the program holds' }));
  const list = el('ul', { class: 'ask-source-list' });
  for (const s of ask.sources) {
    const li = el('li', { class: 'ask-source' + (s.blocks ? ' blocks' : '') });
    // Its file, its copy and its hosts as code, as the cells of the card
    // name them (askCellWords); from an older server, the name is one code
    // and the hosts are text.
    const what = el('div', { class: 'ask-source-what' },
      Array.isArray(s.nameParts) && s.nameParts.length ? askCellWords(s.nameParts, s.name) : nameCode(s.name),
      s.via ? el('span', { class: 'dim' }, ' (copied into ', nameCode(s.via), ')') : null,
      ' ', askCellWords(s.mayGoParts, s.mayGo),
      s.blocks ? el('span', { class: 'ask-source-state', text: ' Not to this place.' }) : null);
    li.append(what);
    if (s.always) {
      li.append(el('button', { type: 'button', class: 'btn ask-source-always', text: s.always, onclick: () => alwaysSource(ask, s, card) }));
    } else if (s.noAlways) {
      li.append(el('div', { class: 'note ask-source-why', text: s.noAlways }));
    }
    list.append(li);
  }
  box.append(list);
  if (ask.sourcesLeft) box.append(el('p', { class: 'note ask-sources-left' }, askCellWords(ask.sourcesLeftParts, ask.sourcesLeft)));
  return box;
}

/** One Always of a send by a program: the rule of that file gains the place
 *  (`always-source`). The question stays while another file is in the way,
 *  and the card says which; once none is, it is gone and the next send goes. */
async function alwaysSource(ask, src, card) {
  if (S.busy.has(ask.id)) return;
  S.busy.add(ask.id);
  const place = answerPlace(card);
  dropAnswer(place, card);
  for (const b of card.querySelectorAll('button')) b.disabled = true;
  let r;
  try {
    r = await apiPost('egress/approvals/' + encodeURIComponent(ask.id) + '/always-source', { path: src.path });
  } finally {
    S.busy.delete(ask.id);
  }
  if (!r.ok) {
    keepAnswer(place, card, refusalText(r, 'could not change the rule (' + r.status + ')'));
    return;
  }
  const d = r.data || {};
  const left = Array.isArray(d.left) ? d.left.map((p) => shortPath(p)) : [];
  keepAnswer(place, card, d.released
    ? 'Done: every file may go there now, so the program\'s next send goes. ' + 'After you answer, tell the agent to try again.'
    : 'Done: ' + src.name + ' may go there now. Still in the way: ' + (left.join(', ') || 'another file') + '.', true);
  answerWorked(place, card);
  AGENT_READS.wrote();
  forgetDrawn();
  await loadHome();
  if (S.page === 'rules') loadRules();
}

/** What "Send without it" does (dashboard.md §4.34), in the card's cell. */
const SEND_WITHOUT_WORDS = 'The next such request goes with [hidden by Mandu] where the secret was, so the task can finish. The secret is not sent. This answer covers one request; the next one asks again.';

async function answer(ask, verb, card) {
  if (S.busy.has(ask.id)) return;
  S.busy.add(ask.id);
  const place = answerPlace(card);
  dropAnswer(place, card);
  for (const b of card.querySelectorAll('button')) b.disabled = true;
  const path = 'egress/approvals/' + encodeURIComponent(ask.id) + '/' + (verb.strip ? 'send-without' : verb.scope === 'once' ? 'approve-once' : verb.approve ? 'approve' : 'deny');
  try {
    const r = verb.prompt
      ? await apiPost('prompt-filters/holds/answer', { approvalId: ask.id, answer: verb.prompt, scope: verb.scope || 'once' })
      : await apiPost(path);
    if (!r.ok) {
      keepAnswer(place, card, refusalText(r, 'could not record your answer (' + r.status + ')'));
      return;
    }
  } finally {
    S.busy.delete(ask.id);
  }
  // Answered here: Approvals no longer points at it ("already answered" would
  // read as someone else's answer), and a reload does not bring the mark back.
  if (S.approvalsAsk === ask.id) {
    S.approvalsAsk = null;
    if (S.page === 'approvals') history.replaceState(history.state, '', routeHref('approvals'));
  }
  answerWorked(place, card);
  // The agent page reads it again after (loadHome): a read of it asked
  // before this answer still has the question waiting (readsInOrder).
  AGENT_READS.wrote();
  forgetDrawn();
  await loadHome();
  if (S.page === 'rules') loadRules();
}
let askErrorSeq = 0;
function showAskError(card, text) {
  for (const b of card.querySelectorAll('button, select')) b.disabled = false;
  // Allow on an over-broad change stays off until ALLOW is typed, also after
  // a refusal (the poll no longer redraws the card that would turn it off).
  const typed = card.querySelector('.proposal-confirm');
  const allow = card.querySelector('.proposal-allow');
  if (typed && allow) allow.disabled = typed.value !== 'ALLOW';
  let e = card.querySelector('.ask-error');
  // Its id: the button pressed, given the focus back, is described by it
  // (focusAnswered).
  if (!e) { e = el('div', { class: 'ask-error', id: 'ask-error-' + (++askErrorSeq) }); card.append(e); }
  setWords(e, text);
}

/** The waiting questions of a list. `changesWait`: a rule change waits too
 *  (Home and Approvals pass S.proposals), so an empty list says no question
 *  waits, never "Nothing" under the "Approvals waiting (1)" and the nav
 *  badge that count it (dashboard.md §4.25 *An empty list never says
 *  nothing waits over a rule change*). */
function renderAsks(host, home, expanded, changesWait) {
  clear(host);
  if (!home || !home.waitingKnown) {
    // The cause the poll knows; a home that answered without its queue does
    // not say why. On Approvals the words of a stopped service link to Settings;
    // on Home the hero above has the link.
    host.append(el('div', { class: 'empty' }, ...cannotCheck('Could not check for waiting questions.', home ? null : S.homeFailure, expanded)));
    return;
  }
  if (!home.waiting.length) {
    // Keyed (placeKey), so a focus on the line stays on it when a poll
    // draws it with the other words.
    host.append(el('div', { class: 'empty', 'data-empty': 'questions', text: changesWait ? 'No question is waiting for you.' : 'Nothing is waiting for you.' }));
    return;
  }
  const shown = expanded ? home.waiting : home.waiting.slice(0, HOME_ASK_CAP);
  for (const ask of shown) host.append(askCard(ask, expanded));
  if (shown.some((a) => a.family === 'prompt')) {
    void loadPromptHolds().then((holds) => { if (holds) fillPromptFound(host, holds); });
  }
  const more = home.waiting.length - shown.length;
  if (more > 0) host.append(el('a', { href: routeHref('approvals'), 'data-page-link': 'approvals', class: 'more', text: n(more, 'more question', 'more questions') + ' in Approvals' }));
}

function renderAgents(home) {
  const host = document.getElementById('home-agents');
  const hist = document.getElementById('home-history');
  hist.href = routeHref('history');
  const shown = home ? home.agents.filter((a) => a.state !== 'idle') : [];
  if (sameAsDrawn('agents', home ? [home.history.total, shown.map((a) => rowDrawnFrom(a, 'startedAt'))] : ['failed', S.homeFailure])) return;
  if (!home) {
    hist.textContent = '';
    keepRows(host, [el('div', { class: 'empty' }, ...cannotCheck('Could not check which agents are running.', S.homeFailure, false))]);
    return;
  }
  hist.textContent = home.history.total ? 'History: ' + n(home.history.total, 'session', 'sessions') : '';
  if (!shown.length) {
    keepRows(host, [el('div', { class: 'empty' }, 'No agent is running right now. Start one with ',
      ownCode('mandu claude'), ' or ', ownCode('mandu codex'), '.')]);
    return;
  }
  keepRows(host, shown.map((a) => keptRow(a, 'startedAt', () => {
    const dot = el('span', { class: 'dot ' + (!a.holds ? 'bad' : a.state === 'waiting' ? 'warn' : 'ok') });
    // A row waiting for your OK keeps what you asked, as History's does: the
    // amber dot and the count that leads its counts say it waits
    // (dashboard.md §4.25 *Agents, not sessions*).
    const what = promptLine(a, 'No prompt yet');
    const bits = [];
    if (!a.holds) bits.push('protection failed');
    if (a.waiting) bits.push(n(a.waiting, 'question waiting for you', 'questions waiting for you'));
    bits.push(...rowCounts(a));
    return agentRow(a, dot, what, countsLine('sub', bits),
      whenLine('agent-started', 'started', a.startedAt));
  })));
}

/** A session row's first line under Running now, Earlier and History: what
 *  you asked (`none` when no prompt is known), then " in ~/folder" where it
 *  ran, both whole on hover, so a session reads the same in the three lists
 *  (dashboard.md §4.25 *Agents, not sessions*). */
function promptLine(a, none) {
  const what = el('div', { class: 'sub ellipsis', text: a.title || none });
  if (a.cwd) what.append(' in ', el('code', { text: shortPath(a.cwd) }));
  what.title = (a.title || '') + (a.cwd ? ' — ' + a.cwd : '');
  return what;
}

/** What each row keepRows left or made was drawn from (keptRow's `from`). */
const ROW_DRAWN = new WeakMap();
/** A row of a session list for keepRows: its session, what it is drawn
 *  from (rowDrawnFrom with the list's moment, the key sameAsDrawn reads),
 *  and how to draw it. */
function keptRow(a, moment, make) {
  return { key: a.id, from: JSON.stringify(rowDrawnFrom(a, moment)), make };
}
/** Draws a session list the poll follows (Home's Running now and Earlier,
 *  History) without drawing again the rows that did not change
 *  (dashboard.md §4.25 *The rows you read stay still*). A row (keptRow)
 *  whose session is drawn from what it was is the node already there, left
 *  in place; a new or changed one is drawn and put in its place; the rows
 *  no longer listed go first, so a row kept is never moved. So the
 *  browser's scroll anchoring, which holds still the rows in view while
 *  its anchor stays in the page, keeps them where they are when a session
 *  comes in above them, and a row's focused Details keeps its focus. Until
 *  2026-10-15 each change drew the list from nothing, and the rows in view
 *  moved a whole row. A part that is a node (an empty state, a Show more
 *  line) is drawn anew each time. */
function keepRows(host, parts) {
  const had = new Map();
  for (const x of host.children) if (ROW_DRAWN.has(x)) had.set(x.dataset.session, x);
  const want = parts.map((p) => {
    if (p.nodeType) return p;
    const old = had.get(p.key);
    if (old && ROW_DRAWN.get(old) === p.from) return old;
    const made = p.make();
    ROW_DRAWN.set(made, p.from);
    return made;
  });
  const keep = new Set(want);
  for (const x of [...host.childNodes]) if (!keep.has(x)) x.remove();
  want.forEach((x, i) => { if (host.children[i] !== x) host.insertBefore(x, host.children[i] || null); });
}

/** A Home row, under Running now or Earlier (dashboard.md §4.25): the agent;
 *  its prompt with the counts on the line under it, in the row's widest
 *  column, so they read as a line or two and not four in a narrow one; when
 *  it started or ended, alone in its column; then Details, named by the
 *  agent and what its row says (*Details, Undo and the agent link name
 *  their row*). */
function agentRow(a, dot, what, counts, when) {
  const row = el('div', { class: 'row agent', 'data-session': a.id });
  row.append(el('div', { class: 'name' }, dot, a.agent, a.preview ? agentPreviewMark(a.preview) : null, a.notice ? agentNoticeMark(a.notice) : null));
  row.append(el('div', { class: 'agent-what' }, what, counts));
  row.append(el('div', { class: 'dim agent-when' }, when));
  const link = agentLink(a.id, 'Details');
  link.setAttribute('aria-label', rowControlName('Details', [a.agent, lineWords(what)].filter(Boolean).join(', ')));
  row.append(link);
  return row;
}

/** A control every row of a list repeats (Details on Home, the Undo and
 *  the link of a Rule changes row, the answers on a card of Rule changes
 *  your agent asked for) is named by its row (dashboard.md §4.25
 *  *Details, Undo and the agent link name their row*): its own words first,
 *  so a voice command that says what it sees still works (WCAG 2.5.3), then
 *  the words of the row. Until 2026-10-12 a screen reader listed "Details"
 *  once per agent on Home, and "Undo" once per change on Approvals. */
function rowControlName(own, about) {
  return about ? own + ': ' + about : own;
}

/** The words an element draws, on one line. */
function lineWords(x) {
  return String(x.textContent || '').replace(/\s+/g, ' ').trim();
}

/** What a Home row is drawn from (sameAsDrawn): the agent without what no
 *  row shows (its stats), with only its own moment (`startedAt` under
 *  Running now, `lastAt` under Earlier), whose words refreshWhen keeps
 *  current. A working agent's next step draws its row again only when its
 *  prompt, a count or its state changed. */
function rowDrawnFrom(a, moment) {
  return { ...a, stats: undefined, startedAt: undefined, lastAt: undefined, at: a[moment] };
}

/** "started 3 minutes ago" or "ended 3 hours ago", the clock time on hover
 *  (compact rows keep the relative form, §4.25u), kept current by
 *  refreshWhen; null when the time is not known, never a bare "started ".
 *  app.css keeps `time.ago` on one line, so a line never breaks after its
 *  "1". The verb's last word and the moment are one `.when-phrase`, a box
 *  no wider than its line: History's 150 px column reads "running now," over
 *  "started 1 minute ago", not "running now, started" over "1 minute ago"
 *  (§4.25u *A row's moment keeps its verb*). */
function whenLine(cls, verb, iso) {
  const ms = iso ? Date.parse(iso) : NaN;
  if (!Number.isFinite(ms)) return null;
  const cut = verb.lastIndexOf(' ') + 1;
  return el('div', { class: cls }, cut ? verb.slice(0, cut) : null,
    el('span', { class: 'when-phrase' }, verb.slice(cut) + ' ', el('time', { class: 'ago', datetime: new Date(ms).toISOString(), title: clockWords(ms), text: ago(ms) })));
}

/** A Home row's counts in the words and numbers of the tiles on the page
 *  its Details link opens (dashboard.md §4.25): its secrets as Your secrets
 *  tells them, the untrusted items a masking level hid, the blocked steps,
 *  and the sends that left this machine with a real value filled in. */
function rowCounts(a) {
  const bits = [];
  const s = a.secrets || { masked: 0, early: 0 };
  if (s.masked) bits.push(n(s.masked, 'secret masked', 'secrets masked'));
  if (s.early) bits.push(s.early === 1 ? '1 secret read before it was marked' : s.early + ' secrets read before they were marked');
  if (a.untrusted) bits.push(n(a.untrusted, 'untrusted item masked', 'untrusted items masked'));
  if (a.blocked) bits.push(n(a.blocked, 'action blocked', 'actions blocked'));
  if (a.sent) bits.push(n(a.sent, 'send with a real value filled in', 'sends with a real value filled in'));
  return bits;
}
/** A row's counts as one line ("1 secret masked, 1 action blocked"), each
 *  number with its word (countWords); null with none. */
function countsLine(tone, bits) {
  return bits.length ? el('div', { class: tone + ' agent-counts' }, countWords(bits.join(', '))) : null;
}

function agentLink(id, text) {
  return el('a', { class: 'right', href: routeHref('agent', id), 'data-page-link': 'agent', 'data-session': id, text });
}

/** "in the last 24 hours": the window the server counts (home.window.hours,
 *  rolling, not the calendar day); '' when it is not known. */
function windowWords(home) {
  const h = home.window ? home.window.hours : NaN;
  return Number.isFinite(h) && h > 0 ? 'in the last ' + n(h, 'hour', 'hours') : '';
}

/** Ended sessions Earlier lists before its "Show them" (dashboard.md §4.25ad). */
const EARLIER_SHOWN = 10;

/** Sessions in the window that already ended, newest first, each with when it
 *  ended. Headed by the window, never "today": after midnight the window
 *  still holds yesterday evening's sessions. The first EARLIER_SHOWN, and
 *  every one after "Show them" until the page changes (§4.25ad: the server
 *  sends them all). */
function renderEarlier(home) {
  const block = document.getElementById('home-earlier-block');
  const host = document.getElementById('home-earlier');
  const idle = home ? home.agents.filter((a) => a.state === 'idle') : [];
  const span = home ? windowWords(home) : '';
  const shown = S.earlierAll === S.visit ? idle : idle.slice(0, EARLIER_SHOWN);
  if (sameAsDrawn('earlier', home ? [span, idle.length, shown.map((a) => rowDrawnFrom(a, 'lastAt'))] : 'failed')) return;
  // Not known: Running now above says so once.
  if (!home) { keepRows(host, []); block.hidden = true; return; }
  block.hidden = idle.length === 0;
  document.getElementById('home-earlier-title').textContent = span ? 'Earlier ' + span : 'Earlier';
  const parts = shown.map((a) => keptRow(a, 'lastAt', () => {
    const what = promptLine(a, 'No prompt reached the AI');
    const bits = [];
    if (!a.holds) bits.push('protection failed');
    bits.push(...rowCounts(a));
    // A question it asked before it ended still waits in Approvals.
    if (a.waiting) bits.push(n(a.waiting, 'question waiting for you', 'questions waiting for you'));
    return agentRow(a, el('span', { class: 'dot' + (a.holds ? '' : ' bad') }), what,
      countsLine('dim', bits),
      whenLine('agent-ended', 'ended', a.lastAt));
  }));
  const rest = idle.length - shown.length;
  if (rest > 0) {
    // The rest, in place: the first of them takes the focus (showRest).
    parts.push(showRest(el('div', { class: 'row dim earlier-more' }), n(rest, 'more session', 'more sessions') + (span ? ' ' + span : '') + '.', [], rest, () => {
      S.earlierAll = S.visit;
      renderEarlier(S.home);
      const first = host.children[shown.length];
      if (first) landOn(first);
    }));
  }
  keepRows(host, parts);
}

// ── History (dashboard.md §4.25ae) ───────────────────────────────────────────
/** Every session on record, newest first, a page at a time (GET
 *  /api/home/history): each row as Earlier draws one, opening its agent page.
 *  Read when the page opens; "Show more" reads the next page after the last
 *  row drawn and gives the first new row the focus, or, when that read
 *  fails, says why beside Show more, which keeps the focus; each Home poll
 *  reads the drawn rows again (followHistory). A link to the page starts
 *  over; Back or Forward (`restore`, savePlace) reads as many rows as you
 *  had loaded and lands on the row you opened (historyLand). */
const HISTORY_READS = readsInOrder();
/** The rows one History read brings when it names no limit (the server's
 *  HISTORY_PAGE), and the most one read brings (HISTORY_PAGE_MAX). */
const HISTORY_PAGE = 25;
const HISTORY_PAGE_MAX = 100;
/** The most rows Back reads to return to (a few reads). */
const HISTORY_RESTORE_MAX = 300;
async function loadHistory(more, restore) {
  const host = document.getElementById('history-list');
  const visit = S.visit;
  // `out`: its reads not answered yet; `homeAt`: the Home polls asked
  // when the last one answered (followHistory).
  // `q`: the search it reads (§4.25ae *Finding a session*), and `only` the
  // switch (*Only the sessions where Mandu stepped in*), kept for every read
  // of this list, Show more's, Back's and the poll's; `through`, the
  // sessions the switch's reads looked through.
  if (!more) S.history = { visit, q: S.historyQ || '', only: !!S.historyOnly, rows: [], next: null, total: 0, all: 0, through: 0, failure: null, out: 0, homeAt: 0 };
  const h = S.history;
  const after = more && h ? h.next : null;
  const want = restore ? Math.min(HISTORY_RESTORE_MAX, Math.max(0, Number(restore.rows) || 0)) : 0;
  const asked = HISTORY_READS.ask();
  let r = null;
  let failure = null;
  // One `out` for every read of a restore: the poll waits for them all.
  h.out++;
  try {
    r = await apiGet(historyRead(after ? '?after=' + enc(after) : want > HISTORY_PAGE ? '?limit=' + Math.min(want, HISTORY_PAGE_MAX) : '', h));
    if (restore) r = await historyReadOn(r, want, restore.opened || null, visit, h);
  } catch (err) { failure = readFailure(err); }
  h.out--;
  h.homeAt = S.homeAsked;
  if (S.page !== 'history' || S.visit !== visit || S.history !== h || !HISTORY_READS.take(asked)) return;
  const had = S.history.rows.length;
  if (r) {
    const seen = new Set(S.history.rows.map((x) => x.id));
    S.history.rows.push(...(r.rows || []).filter((x) => !seen.has(x.id)));
    S.history.next = r.next || null;
    S.history.total = r.total || 0;
    S.history.all = historyAll(r);
    S.history.through = historyThrough(r);
    S.history.failure = null;
  } else S.history.failure = failure;
  renderHistory(host);
  if (restore) historyLand(host, restore);
  else savePlace();
  if (!more) return;
  // "Show more": the first row it brought takes the focus (showRest). One
  // that failed is drawn again beside why, and gets back the focus that
  // fell with it (a button turned off drops it): one moved elsewhere stays.
  const again = host.querySelector('.history-more .show-rest');
  // Counted past the rows, not the day headings between them.
  const first = [...host.children].filter((x) => !x.matches('.history-day'))[had];
  if (r && first) landOn(first);
  else if (!r && again && focusFell()) again.focus({ preventScroll: true });
}
/** Back to History: reads on past the first answer `r`, a page at a time,
 *  until as many rows as you had loaded (`want`) and the one you opened
 *  (pushed down by sessions that came in since) are in, at most
 *  HISTORY_RESTORE_MAX. A read that fails stops there with the rows read:
 *  Show more goes on from them. */
async function historyReadOn(r, want, opened, visit, h) {
  let rows = (r && r.rows) || [];
  let next = (r && r.next) || null;
  let total = (r && r.total) || 0;
  let only = r && r.only;
  const most = Math.min(HISTORY_RESTORE_MAX, want + HISTORY_PAGE_MAX);
  const missing = () => rows.length < want || (!!opened && !rows.some((x) => x.id === opened));
  while (next && rows.length < most && missing() && S.visit === visit) {
    let more;
    try { more = await apiGet(historyRead('?after=' + enc(next) + '&limit=' + Math.min(HISTORY_PAGE_MAX, Math.max(HISTORY_PAGE, want - rows.length)), h)); } catch { break; }
    const seen = new Set(rows.map((x) => x.id));
    rows = rows.concat((more.rows || []).filter((x) => !seen.has(x.id)));
    next = more.next || null;
    total = more.total || total;
    only = more.only || only;
  }
  return { ...r, rows, next, total, ...(only ? { only } : {}) };
}
/** Back to History, its rows drawn: the page at the place you left it, the
 *  row you opened in view (brought there if the rows moved) with the focus,
 *  as a marked card takes it (`scrolled` of focusMarked: not if you moved the
 *  focus meanwhile). A row no longer listed leaves the place alone. */
function historyLand(host, restore) {
  if (S.placeHeld === S.visit) S.placeHeld = 0;
  window.scrollTo(0, restore.y || 0);
  // Compared as values, never spliced into a selector: ids are server data.
  const row = restore.opened ? [...host.children].find((x) => x.dataset.session === restore.opened) || null : null;
  if (!row) return;
  const b = row.getBoundingClientRect();
  if ((b.top < 0 || b.bottom > window.innerHeight) && row.scrollIntoView) row.scrollIntoView({ block: 'center' });
  focusMarked(row, true);
}
/** While History is shown, each Home poll that answered (`homeAsked`, its
 *  number) reads its rows again (dashboard.md §4.25ae *History follows the
 *  poll*): as many as are drawn, so a session that ended says so, a new one
 *  comes in on top and each row's counts are current. Not while a read of
 *  its own is out, nor when one answered after the poll was asked (opening
 *  the page reads it once, not twice). The list is drawn again only when the
 *  answer changed, the focus kept as the poll keeps it (pollPlace); a read
 *  that fails leaves the rows drawn, and a page that has none says why
 *  again. */
async function followHistory(homeAsked) {
  const h = S.history;
  if (S.page !== 'history' || !h || h.visit !== S.visit || h.out || h.homeAt >= homeAsked) return;
  const host = document.getElementById('history-list');
  const asked = HISTORY_READS.ask();
  let r = null;
  let failure = null;
  h.out++;
  try { r = await apiGet(historyRead(h.rows.length > HISTORY_PAGE ? '?limit=' + h.rows.length : '', h)); } catch (err) { failure = readFailure(err); }
  h.out--;
  h.homeAt = S.homeAsked;
  if (S.page !== 'history' || S.visit !== h.visit || S.history !== h || !HISTORY_READS.take(asked)) return;
  if (r) Object.assign(h, historyFollowed(h, r), { total: r.total || 0, all: historyAll(r), failure: null });
  else if (h.rows.length) return;
  else h.failure = failure;
  const place = pollPlace(document.getElementById('main'));
  if (renderHistory(host, true)) pollRefocus(place);
}
/** A History read: `query` its `?after=`/`?limit=` part (or ''), with the
 *  search `h.q` and the switch `h.only` the list was opened with, when it
 *  has them. */
function historyRead(query, h) {
  const more = historyParams(h.q, h.only);
  return 'home/history' + query + (more ? (query ? '&' : '?') + more : '');
}
/** History's search and switch as an address's query (no `?`), or ''. */
function historyParams(q, only) {
  return [q ? 'q=' + enc(q) : '', only ? 'only=' + ONLY_STEPPED_IN : ''].filter(Boolean).join('&');
}
/** How many sessions a read with the switch on looked through, from the
 *  newest (`only.through`); 0 without it. */
function historyThrough(r) {
  return r.only && Number.isFinite(r.only.through) ? r.only.through : 0;
}
/** Every session on record, as a read says it: `query.all` when it was
 *  found by a search, else its `total`. */
function historyAll(r) {
  return r.query && Number.isFinite(r.query.all) ? r.query.all : r.total || 0;
}

// ── Finding a session (dashboard.md §4.25ae) ────────────────────────────────
/** The longest search History sends (the server's HISTORY_QUERY_MAX). */
const HISTORY_QUERY_MAX = 200;
/** How long History waits after the last key before it reads. */
const HISTORY_SEARCH_MS = 250;
let historySearchTimer = 0;
/** A search as History keeps it: cut at HISTORY_QUERY_MAX, its spaces one. */
function historyQuery(q) {
  return String(q || '').slice(0, HISTORY_QUERY_MAX).replace(/\s+/g, ' ').trim();
}
/** The box's words, read: once the typing stops (HISTORY_SEARCH_MS), or at
 *  once (`now`, Enter or Clear). A search that changed starts the list over,
 *  as a page change does, and writes itself into the address (replaced, not
 *  pushed: no entry per key). Only the list is drawn again, so the focus
 *  stays in the box. */
function findSessions(text, now) {
  clearTimeout(historySearchTimer);
  const run = () => {
    if (S.page !== 'history') return;
    const q = historyQuery(text);
    if (q === (S.historyQ || '') && S.history && S.history.q === q) return;
    S.historyQ = q;
    const href = stateHref();
    if (location.pathname + location.search !== href) history.replaceState(history.state, '', href);
    loadHistory(false);
  };
  if (now) run();
  else historySearchTimer = setTimeout(run, HISTORY_SEARCH_MS);
}
function wireHistorySearch() {
  document.getElementById('history-only').addEventListener('click', () => setHistoryOnly(!S.historyOnly));
  const box = document.getElementById('history-q');
  box.addEventListener('input', () => findSessions(box.value, false));
  document.getElementById('history-search').addEventListener('submit', (e) => {
    e.preventDefault();
    findSessions(box.value, true);
  });
}
/** History's switch turned on or off (§4.25ae *Only the sessions where
 *  Mandu stepped in*): the list starts over with it, as a search that
 *  changed does, and the address says so (replaced, not pushed). Only the
 *  list is drawn again, so the focus stays on the switch. */
function setHistoryOnly(on) {
  if (S.page !== 'history') return;
  S.historyOnly = !!on;
  document.getElementById('history-only').setAttribute('aria-checked', String(S.historyOnly));
  const href = stateHref();
  if (location.pathname + location.search !== href) history.replaceState(history.state, '', href);
  loadHistory(false);
}
/** Clear: the box empty, every session listed again, the box focused. */
function clearHistorySearch() {
  const box = document.getElementById('history-q');
  box.value = '';
  findSessions('', true);
  box.focus();
}

/** The rows History shows once a poll read them again: the rows the read
 *  brought, newest first, then the rows drawn past the last of them, which
 *  it did not reach (pushed down by new sessions, or past the most one read
 *  brings), and the cursor (and, with the switch, how far it looked) of
 *  whichever ends the list. A row the read should have brought and did not
 *  is no longer listed, and goes. A read that brought none and stopped
 *  short (the switch's look ended on its budget before the first drawn
 *  row) reached none of them: they all stay. */
function historyFollowed(h, r) {
  const fresh = r.rows || [];
  if (!fresh.length && r.next && h.rows.length) return { rows: h.rows, next: h.next, through: h.through };
  const seen = new Set(fresh.map((x) => x.id));
  const last = fresh.length ? h.rows.findIndex((x) => x.id === fresh[fresh.length - 1].id) : -1;
  const tail = r.next && last >= 0 ? h.rows.slice(last + 1).filter((x) => !seen.has(x.id)) : [];
  return { rows: fresh.concat(tail), next: tail.length ? h.next : r.next || null, through: tail.length ? h.through : historyThrough(r) };
}
/** Draws History's list; `poll`: only when it changed since drawn
 *  (sameAsDrawn: a row by what it shows, its moment kept current by
 *  refreshWhen), and then only the rows that changed (keepRows). Whether
 *  it drew. */
function renderHistory(host, poll) {
  const h = S.history;
  const same = sameAsDrawn('history', [h.q, h.only, h.total, h.all, h.next, h.through, h.failure, h.rows.map((a) => rowDrawnFrom(a, a.state !== 'idle' ? 'startedAt' : 'lastAt'))]);
  if (poll && same) return false;
  // A search's count: "3 of 214 sessions" (none while it finds none: the
  // list says so, nor without a search). With the switch, what the list
  // keeps: how many it keeps is not known before every session is read.
  const count = document.getElementById('history-count');
  const counted = (!!h.q || h.only) && h.rows.length > 0;
  count.textContent = !counted ? ''
    : h.only ? 'Showing the sessions where Mandu stepped in' + (h.q ? ', of ' + n(h.total, 'session', 'sessions') + ' found' : '')
    : h.total + ' of ' + n(h.all, 'session', 'sessions');
  count.hidden = !counted;
  // With the switch: Show more goes on while sessions are left to look
  // through, and says how far it looked, since how many more it will keep
  // is not known (none yet: "has not stepped in in the newest 200").
  const lookedLine = () => moreLine('history-more', h.failure ? cannotCheck('Could not read more of the history.', h.failure, false)
    : [h.rows.length ? 'Looked through ' + h.through + ' of ' + n(h.total, 'session', 'sessions') + '.' : 'Mandu has not stepped in in the newest ' + h.through + ' of ' + n(h.total, 'session', 'sessions') + '.'], () => loadHistory(true));
  if (!h.rows.length && h.only && h.next) {
    keepRows(host, [lookedLine()]);
    return true;
  }
  if (!h.rows.length && h.failure) {
    keepRows(host, [el('div', { class: 'empty' }, ...cannotCheck('Could not read the history.', h.failure, false))]);
    return true;
  }
  if (!h.rows.length && h.only && h.total > 0) {
    const allBtn = el('button', { type: 'button', class: 'btn small history-all', text: 'Show every session' });
    allBtn.addEventListener('click', () => {
      setHistoryOnly(false);
      document.getElementById('history-only').focus();
    });
    keepRows(host, [el('div', { class: 'empty' }, (h.q ? 'Mandu has not stepped in in any session that matches \u201c' + h.q + '\u201d. ' : 'Mandu has not stepped in in any session on record. '), allBtn)]);
    return true;
  }
  if (!h.rows.length && h.q && h.all > 0) {
    const clearBtn = el('button', { type: 'button', class: 'btn small history-clear', text: 'Clear' });
    clearBtn.addEventListener('click', clearHistorySearch);
    keepRows(host, [el('div', { class: 'empty' }, 'No session matches \u201c' + h.q + '\u201d. ', clearBtn)]);
    return true;
  }
  if (!h.rows.length) {
    keepRows(host, [el('div', { class: 'empty' }, 'No session has been recorded yet. Start one with ',
      ownCode('mandu claude'), ' or ', ownCode('mandu codex'), '.')]);
    return true;
  }
  // Each day the rows are on gets its heading before its first row
  // (historyDay): a row ended belongs to the day it ended, a running one to
  // the day it started, the moment its line names. A row with no time
  // starts no day. Show more continues the last day: all the rows loaded are
  // drawn together, so a page that starts on the same day adds no heading.
  const parts = [];
  const days = new Map();
  let lastDay = null;
  for (const a of h.rows) {
    const moment = a.state !== 'idle' ? 'startedAt' : 'lastAt';
    const ms = Date.parse(a[moment] || '');
    if (Number.isFinite(ms)) {
      const key = localDay(ms).key;
      if (key !== lastDay) {
        days.set(key, (days.get(key) || 0) + 1);
        parts.push(historyDay(key, days.get(key)));
      }
      lastDay = key;
    }
    parts.push(historyRow(a, moment));
  }
  const rest = h.total - h.rows.length;
  if (h.only && h.next) {
    parts.push(lookedLine());
  } else if (h.next && rest > 0) {
    // A press that failed says why in place of the count, and the button
    // stays to try again.
    parts.push(moreLine('history-more', h.failure ? cannotCheck('Could not read more of the history.', h.failure, false) : [n(rest, 'more session', 'more sessions') + '.'], () => loadHistory(true)));
  } else if (h.failure) {
    parts.push(el('div', { class: 'row dim history-more' }, ...cannotCheck('Could not read more of the history.', h.failure, false)));
  }
  keepRows(host, parts);
  return true;
}
/** A History row for keepRows: Home's row (agentRow), its moment
 *  `moment`, when the session started if it runs, else when it ended. */
function historyRow(a, moment) {
  return keptRow(a, moment, () => {
    const what = promptLine(a, 'No prompt reached the AI');
    const bits = [];
    if (!a.holds) bits.push('protection failed');
    bits.push(...rowCounts(a));
    // A question it raised still waits in Approvals, in Home's words (the
    // row keeps its prompt, as Home's do); a running agent waiting for it
    // has Running now's dot (§4.25ae *History says what waits for you*).
    if (a.waiting) bits.push(n(a.waiting, 'question waiting for you', 'questions waiting for you'));
    const running = a.state !== 'idle';
    return agentRow(a, el('span', { class: 'dot' + (!a.holds ? ' bad' : a.state === 'waiting' ? ' warn' : running ? ' ok' : '') }), what,
      countsLine('dim', bits),
      running ? whenLine('agent-started', 'running now, started', a.startedAt) : whenLine('agent-ended', 'ended', a.lastAt));
  });
}

// ── The day a History row is on (dashboard.md §4.25ae *Sessions sit under their day*) ──
/** A heading of History for keepRows: the local day `key` ("2026-07-10",
 *  localDay), an h2 under the page h1 so a screen reader can go from day
 *  to day, slim in the list (app.css `.history-day`). Its key is the day
 *  (with `nth` past its first heading, when a running row started on a day
 *  listed again further down), so a poll leaves a heading already there in
 *  place as it does a row; its words are said again by refreshWhen. */
function historyDay(key, nth) {
  const id = 'day:' + key + (nth > 1 ? ':' + nth : '');
  return { key: id, from: id, make: () => el('h2', { class: 'history-day', 'data-session': id }, el('time', { datetime: key, text: dayWords(key) })) };
}
/** The words of a day heading for the local day `key`: "Today",
 *  "Yesterday", else the words localDay gives the session page ("Friday,
 *  Jul 10", with the year when it is not this year), built by hand as
 *  clockWords is, so every viewer reads the same. */
function dayWords(key, nowMs) {
  const now = new Date(nowMs === undefined ? Date.now() : nowMs);
  if (key === localDay(now.getTime()).key) return 'Today';
  if (key === localDay(new Date(now.getFullYear(), now.getMonth(), now.getDate() - 1, 12).getTime()).key) return 'Yesterday';
  const [y, m, d] = key.split('-').map(Number);
  return localDay(new Date(y, m - 1, d, 12).getTime(), now.getTime()).words;
}

/** The line under a list read a page at a time (History, dashboard.md
 *  §4.25ae; Answered earlier and Rule changes on Approvals, §4.25 *Past the
 *  newest 20*): `said`, what is left or why the last read failed, as parts,
 *  then "Show more", described by them (`<cls>-words`). A page at a time,
 *  so "Show more", never "Show them" (the words of §4.25ad for a press
 *  that brings the whole rest). The button is off while `press` reads. */
function moreLine(cls, said, press) {
  const words = el('span', { id: cls + '-words' }, ...said);
  const btn = el('button', { type: 'button', class: 'btn small show-rest', 'aria-describedby': words.id, text: 'Show more' });
  btn.addEventListener('click', () => { btn.disabled = true; press(); });
  return el('div', { class: 'row dim ' + cls }, words, ' ', btn);
}

/** A line saying what a list leaves out, and its "Show them" (dashboard.md
 *  §4.25ad): `words` the sentence, `extra` parts after it (the detailed
 *  trace, in a build with the developer view), `count` for "Show it" or
 *  "Show them", `show` what the press does. The button is described by the
 *  sentence. */
let showRestIds = 0;
function showRest(line, words, extra, count, show) {
  const said = el('span', { id: 'show-rest-' + (++showRestIds), text: words });
  const btn = el('button', { type: 'button', class: 'btn small show-rest', 'aria-describedby': said.id, text: count === 1 ? 'Show it' : 'Show them' });
  btn.addEventListener('click', show);
  line.append(said, ...extra, ' ', btn);
  return line;
}

/** Give the focus to what a "Show them" brought (dashboard.md §4.25ad), as
 *  a card or a line takes it (focusThere), in view. */
function landOn(x) {
  focusThere(x);
  if (x.scrollIntoView) x.scrollIntoView({ block: 'nearest' });
}

// ── Where your data lives (on-disk-layout.md §9 decision 2) ────────────────────
/** Loaded each time the closed-by-default section is opened: the path table's
 *  locations, never their contents (GET /api/data-locations). */
async function loadDataLocations() {
  const list = document.getElementById('home-data-list');
  let d = null;
  try { d = await apiGet('data-locations'); } catch { d = null; }
  if (!d || !Array.isArray(d.locations)) {
    clear(list);
    document.getElementById('home-data-open').hidden = true;
    list.append(el('div', { class: 'empty' }, 'The list could not be loaded. Run ', ownCode('mandu paths'), ' in a terminal to see it.'));
    return;
  }
  renderDataLocations(d);
}
function renderDataLocations(d) {
  document.getElementById('home-data-folder').textContent = d.home || '~/.mandu';
  const list = document.getElementById('home-data-list');
  clear(list);
  // A place only Mandu's developers use is listed only when it is there,
  // after the rest of Mandu's folder under its own line (§4.25q); a row
  // without `developer` (an older server) is drawn as before.
  const shown = d.locations.filter((l) => l.developer !== true || l.exists);
  const inHome = shown.filter((l) => l.where === 'home');
  const outside = shown.filter((l) => l.where !== 'home');
  const forDevs = inHome.filter((l) => l.developer === true);
  for (const l of inHome) if (l.developer !== true) list.append(dataRow(l, true));
  if (forDevs.length) {
    list.append(el('div', { class: 'row data-where-group', text: 'For Mandu\'s developers' }));
    for (const l of forDevs) list.append(dataRow(l, true));
  }
  if (outside.length) {
    list.append(el('div', { class: 'row data-where-group', text: 'Outside Mandu\'s folder' }));
    for (const l of outside) list.append(dataRow(l, false));
  }
  const open = inHome.filter((l) => l.exists && l.ownerOnly === false);
  const note = document.getElementById('home-data-open');
  note.hidden = open.length === 0;
  clear(note);
  if (open.length) {
    note.append('Other people on this computer can open ' + n(open.length, 'place', 'places') + ' in Mandu\'s folder. Run ',
      ownCode('mandu paths'), ' in a terminal for the command that makes them yours only.');
  }
}
/** One location: what it holds, where, and (for Mandu's own folder) whether
 *  only you can open it. */
function dataRow(l, badge) {
  const row = el('div', { class: 'row data-where-row' + (l.exists ? '' : ' missing'), 'data-name': l.name });
  const holds = String(l.holds || '');
  row.append(el('div', { class: 'sub', text: holds.charAt(0).toUpperCase() + holds.slice(1) }));
  row.append(el('div', { class: 'ellipsis' }, el('code', { text: l.path, title: l.path })));
  let mark = el('span');
  if (!l.exists) mark = el('span', { class: 'dim', text: 'not there yet' });
  else if (l.brokenLink) mark = el('span', { class: 'tag broken-link', text: 'broken link', title: 'A link here points at something that is not there; Mandu cannot use this place until it is fixed or removed' });
  else if (badge && l.ownerOnly === true) mark = el('span', { class: 'tag only-you', text: 'only you', title: 'Only your user account can open it' });
  else if (badge && l.ownerOnly === false) mark = el('span', { class: 'tag open-to-others', text: 'open to others', title: 'Other people on this computer can open it' });
  row.append(el('div', { class: 'right' }, mark));
  return row;
}

// ── Approvals ─────────────────────────────────────────────────────────────────
function renderApprovals(home) {
  // A poll that brings the same questions and answers leaves both lists as
  // they are (sameAsDrawn): the words of an answer stay on its card or row.
  // Drawn again, each card or row still there gets them back (putBackAnswers).
  // A rule change that comes or goes while no question waits changes the
  // line of the list ("No question …" / "Nothing …"), so it is part of the key.
  // Answered earlier is keyed by the rows it draws, those Show more brought
  // too (answeredList), so a poll never draws its newest 20 over them; a
  // read of its own draws it alone (renderAnswered).
  if (sameAsDrawn('approvals', approvalsKey(home))) return;
  const waiting = document.getElementById('approvals-waiting');
  renderAsks(waiting, home, true, S.proposals.length > 0);
  putBackAnswers('approvals', waiting);
  renderAnswered(home, true);
}

// ── Past the newest 20 (dashboard.md §4.25 *Past the newest 20*) ────────────
/** The answers one read of Answered earlier brings (ANSWERED_PAGE of the
 *  server), and the most one read brings (ANSWERED_PAGE_MAX). */
const ANSWERED_PAGE = 20;
const ANSWERED_PAGE_MAX = 500;
const ANSWERED_READS = readsInOrder();
/** The rule changes one Show more adds, and the most the route reads. */
const CHANGES_PAGE = 20;
const CHANGES_MAX = 500;

/** A link to Approvals: both lists back to their newest 20. */
function startPastOver() {
  S.answered = null;
  S.answeredSought = null;
  S.changes = { want: CHANGES_PAGE, last: null, failure: null, out: 0 };
  if (S.home) renderAnswered(S.home);
}

/** The answers Answered earlier draws: the newest ANSWERED_PAGE of Home, and
 *  once Show more brought more (S.answered) the rows past them, kept as
 *  the poll of History keeps its rows (historyFollowed): the poll never takes
 *  them away, and an answer given since comes in on top. `total`: every
 *  answer; `next`: the id of the last row while more follow. */
function answeredList(home) {
  const rows = Array.isArray(home.answered) ? home.answered : [];
  const homeTotal = Number.isFinite(home.answeredTotal) ? home.answeredTotal : rows.length;
  const first = { rows, next: homeTotal > rows.length && rows.length ? rows[rows.length - 1].id : null };
  const a = S.answered;
  if (!a) return { ...first, total: homeTotal, failure: null };
  const kept = historyFollowed(a, first);
  return { ...kept, total: Math.max(homeTotal, a.total || 0, kept.rows.length), failure: a.failure };
}

/** What the two lists of questions on Approvals are drawn from (sameAsDrawn). A
 *  rule change that comes or goes while no question waits changes the line
 *  of the list ("No question …" / "Nothing …"), so it is part of the key. */
function approvalsKey(home) {
  if (!home || !home.waitingKnown) return ['failed', S.homeFailure];
  return [home.waiting, answeredKey(answeredList(home)), !home.waiting.length && S.proposals.length > 0];
}
/** What Answered earlier is drawn from (sameAsDrawn). */
function answeredKey(list) {
  return [list.rows, list.total, list.next, list.failure];
}

/** Draws Answered earlier when what it shows changed (`force`: always, as
 *  a Show more that answered draws). Whether it drew. */
function renderAnswered(home, force) {
  const host = document.getElementById('approvals-answered');
  const list = home && home.waitingKnown ? answeredList(home) : null;
  const same = sameAsDrawn('answered', list ? answeredKey(list) : ['failed', S.homeFailure]);
  if (same && !force) return false;
  drawAnswered(host, home, list);
  putBackAnswers('answered', host);
  // Drawn by a read of its own: the next poll that brings the same leaves
  // both lists as they are.
  if (home === S.home) sameAsDrawn('approvals', approvalsKey(home));
  return true;
}

/** Show more under Answered earlier: the next ANSWERED_PAGE after the last
 *  row drawn (GET /api/home/answered), whose first row then takes the
 *  focus, as on History. A read that fails says why beside Show more,
 *  which gets back the focus that fell with it. */
async function moreAnswered() {
  const home = S.home;
  if (!home || !home.waitingKnown) return;
  const host = document.getElementById('approvals-answered');
  const drawnNow = answeredList(home);
  const a = S.answered || (S.answered = { rows: [], next: null, total: 0, failure: null, out: 0, homeAt: S.homeAsked });
  Object.assign(a, { rows: drawnNow.rows.slice(), next: drawnNow.next, total: drawnNow.total });
  const had = new Set(a.rows.map((x) => x.id));
  const asked = ANSWERED_READS.ask();
  let r = null;
  let failure = null;
  a.out++;
  try { r = await apiGet('home/answered?after=' + enc(a.next || '') + '&limit=' + ANSWERED_PAGE); } catch (err) { failure = readFailure(err); }
  a.out--;
  a.homeAt = S.homeAsked;
  if (S.answered !== a || !ANSWERED_READS.take(asked)) return;
  let first = null;
  if (r) {
    const fresh = (r.rows || []).filter((x) => !had.has(x.id));
    a.rows.push(...fresh);
    a.next = r.next || null;
    a.total = r.total || 0;
    a.failure = null;
    first = fresh.length ? fresh[0].id : null;
  } else a.failure = failure;
  renderAnswered(S.home, true);
  const row = first ? drawnCards(host).get(first) : null;
  if (row) landOn(row);
  else {
    const again = host.querySelector('.answered-more .show-rest');
    if (again && focusFell()) again.focus({ preventScroll: true });
  }
}

/** While Approvals is shown with more than the newest answers of Home drawn,
 *  each Home poll that answered (`homeAsked`) reads them again, as many as
 *  are drawn, as History follows the poll: the outcome of each row current, an
 *  answer given since on top, the rows pushed down kept. A read that fails
 *  leaves the rows drawn. */
async function followAnswered(homeAsked) {
  const a = S.answered;
  if (S.page !== 'approvals' || !a || a.out || a.homeAt >= homeAsked) return;
  const asked = ANSWERED_READS.ask();
  let r = null;
  a.out++;
  try { r = await apiGet('home/answered?limit=' + Math.min(Math.max(a.rows.length, ANSWERED_PAGE), ANSWERED_PAGE_MAX)); } catch { r = null; }
  a.out--;
  a.homeAt = S.homeAsked;
  if (S.page !== 'approvals' || S.answered !== a || !ANSWERED_READS.take(asked) || !r) return;
  Object.assign(a, historyFollowed(a, r), { total: r.total || 0, failure: null });
  const place = pollPlace(document.getElementById('main'));
  if (renderAnswered(S.home)) pollRefocus(place);
}

/** `/approvals/<id>` names an answer past the rows drawn: one read of the
 *  answers (up to ANSWERED_PAGE_MAX), then Answered earlier draws down to
 *  the page that holds it, so it is marked in place (markApprovalsAsk).
 *  Whether that read is out (the page says nothing of the question yet);
 *  false once it answered, or when no more answers exist to read. */
function seekAnswered(id, home) {
  const was = S.answeredSought;
  if (was && was.id === id) return !was.done;
  if (!answeredList(home).next) return false;
  const sought = S.answeredSought = { id, done: false };
  (async () => {
    let r = null;
    try { r = await apiGet('home/answered?limit=' + ANSWERED_PAGE_MAX); } catch { r = null; }
    sought.done = true;
    if (S.answeredSought !== sought) return;
    const rows = r && Array.isArray(r.rows) ? r.rows : [];
    const at = rows.findIndex((x) => x.id === id);
    if (at >= 0) {
      const kept = rows.slice(0, Math.ceil((at + 1) / ANSWERED_PAGE) * ANSWERED_PAGE);
      const more = kept.length < rows.length || !!r.next;
      S.answered = { rows: kept, next: more ? kept[kept.length - 1].id : null, total: r.total || 0, failure: null, out: 0, homeAt: S.homeAsked };
      if (S.home) renderAnswered(S.home, true);
    }
    if (S.approvalsAsk === id) markApprovalsAsk();
  })();
  return true;
}

/** Approvals › Answered earlier (`list`: as answeredList gives it). The state of each
 *  row is its outcome, so the words of a refused Block instead go once it
 *  was answered otherwise. More than drawn: "Showing 20 of 63 answers."
 *  and Show more (moreAnswered). */
function drawAnswered(host, home, list) {
  clear(host);
  if (!home || !home.waitingKnown || !list) {
    // No link: Waiting for your answer above has it.
    host.append(el('div', { class: 'empty' }, ...cannotCheck('Could not check your earlier answers.', home ? null : S.homeFailure, false)));
    return;
  }
  if (!list.rows.length) {
    host.append(el('div', { class: 'empty', text: 'You have not answered anything yet.' }));
    return;
  }
  for (const a of list.rows) {
    const row = el('div', { class: 'row answered', 'data-id': a.id, 'data-state': a.outcome });
    // Its names are kept whole, as on the card it answered.
    const said = keepNamesWhole(sentenceNode(a.sentence, 'answered-sentence'));
    nameBy(row, said);
    const what = answeredWhat(said, a.decidedAt, a);
    // An answer that applies to nothing any more says why, and offers no
    // change (dashboard.md §4.34 "Answers that no longer apply").
    if (a.staleNote) what.append(el('div', { class: 'note answered-stale', text: a.staleNote }));
    row.append(what);
    const out = el('div', { class: 'outcome' });
    if (a.staleNote) { /* no mark: it decides nothing */ } else if (a.outcome === 'blocked') out.append(svg(ICON.x, 16));
    else if (a.outcome === 'allowed') out.append(svg(ICON.check, 16));
    out.classList.add(a.staleNote ? 'dim' : a.outcome === 'blocked' ? 'bad' : a.outcome === 'allowed' ? 'ok' : 'dim');
    out.append(a.staleNote ? 'No longer applies' : answerLabel(a.outcome) || 'Allowed once');
    if (a.staleNote) out.title = answerLabel(a.outcome) || '';
    row.append(out);
    const reversal = (a.actions || [])[0];
    if (reversal) {
      // A session's answer to a held message flips as itself (§4.34).
      const message = /^(sent|masked)/.test(a.outcome);
      const text = message ? (reversal.approve ? 'Send as written instead' : 'Send masked instead') : reversal.approve ? 'Allow instead' : 'Block instead';
      row.append(el('button', { type: 'button', class: 'btn small right', text, onclick: () => answer({ id: a.id }, { approve: reversal.approve, scope: reversal.scope }, row) }));
    } else row.append(el('span'));
    host.append(row);
  }
  // Nothing on the page said the list was cut (until 2026-10-18): the 20
  // rows read as every answer. A failed Show more says why in their place.
  if (list.next) {
    const shown = list.rows.length;
    host.append(moreLine('answered-more', list.failure
      ? cannotCheck('Could not read more of your answers.', list.failure, false)
      : ['Showing ' + shown + ' of ' + n(Math.max(list.total, shown), 'answer', 'answers') + '.'], moreAnswered));
  }
}

/** A held message's standing answer on Rules, in Answered earlier's words
 *  (rule-words.ts `promptAnswerWords`): what went to the AI. */
function messageEffect(asWritten) {
  return asWritten ? 'Sent as written' : 'Sent masked';
}

/** The outcome of an answered question (view-model/home.ts `answeredOutcome`) in
 *  the words of Answered earlier; on the agent page, the step that asked
 *  says the same (§4.25b *A stop says Mandu asked you*). An outcome this
 *  page does not know: null, so the step claims no answer. */
function answerLabel(outcome) {
  if (outcome === 'blocked') return 'Blocked';
  if (outcome === 'allowed') return 'Always allowed';
  if (outcome === 'allowed-once') return 'Allowed once, unused';
  if (outcome === 'allowed-once-used') return 'Allowed once';
  // "Send without it" (§4.34): the request went with a marker where the
  // secret was; the secret was not sent.
  if (outcome === 'without') return 'Send without it, unused';
  if (outcome === 'without-used') return 'Sent without it';
  // A held message's answer says what went to the AI (§4.34).
  if (outcome === 'sent') return 'Sent as written';
  if (outcome === 'sent-session') return 'Sent as written for the session';
  if (outcome === 'masked') return 'Sent masked, or cancelled';
  if (outcome === 'masked-session') return 'Masked for the session';
  return null;
}

/** The words cell of an Approvals row, under Answered earlier or Rule
 *  changes (dashboard.md §4.25, Approvals, *Read in full*): what was asked or
 *  changed, whole, and when on the line under it, as the waiting card puts
 *  it. Never cut: the button in the row reverses exactly what these words
 *  say, so until 2026-10-08 a phone read "…your secret GITHUB_…" above
 *  Block instead, and "Make ~/proj/deploy/stagi" above Undo.
 *  An answer (`asked`, its id and sessions) ends that line with the link to
 *  where it was asked, as its waiting card and the answer rows of the Rules
 *  page do (§4.25h): until 2026-10-08 an Answered earlier row led nowhere,
 *  and an Allowed once answer, which Rules does not list, had no way to its
 *  moment. A rule change your agent made or asked for (`asked` with no id)
 *  links the agent page at its top, the link named by what the change did
 *  (`asked.about`). No session recorded: no link. */
function answeredWhat(words, ms, asked) {
  const what = el('div', { class: 'answered-what' }, words);
  const when = whenNode(ms);
  const sessions = asked && Array.isArray(asked.sessions) ? asked.sessions : [];
  if (!when && !sessions.length) return what;
  const line = el('div', { class: 'dim answered-when' }, when);
  if (sessions.length) {
    if (when) line.append('. ');
    line.append(askLink(sessions[sessions.length - 1], asked.id, undefined, asked.about));
    if (sessions.length > 1) line.append(' (asked in ' + sessions.length + ' sessions, this shows the latest)');
  }
  what.append(line);
  return what;
}

/**
 * Approvals opened for one question (`/approvals/<id>`, from a Home
 * card's Details link or a notification; dashboard.md §4.25 "Details"): its
 * card is marked, and scrolled to once. Re-applied after every repaint (the
 * poll rebuilds the cards), scrolled only the first time. A question that is
 * no longer waiting says so above the list, and its row under Answered
 * earlier is marked when it is there.
 */
function markApprovalsAsk() {
  const note = document.getElementById('approvals-focus-note');
  const id = S.approvalsAsk;
  // A page switch does not rebuild the cards, so an earlier visit's mark
  // would outlive it: clear, then mark afresh.
  for (const x of document.querySelectorAll('#page-approvals .focus')) x.classList.remove('focus');
  // Compared as values, never spliced into a selector: ids are server data.
  const find = (sel) => [...document.querySelectorAll(sel)].find((x) => x.dataset.id === id) || null;
  // Or the waiting rule change a notification opened it for (§4.25
  // *Notifications*), drawn whatever the answer about the asks.
  const proposal = id ? find('#approvals-proposals .proposal') : null;
  if (!proposal && (!id || !S.home || !S.home.waitingKnown)) { note.hidden = true; return; }
  const card = proposal || find('#approvals-waiting .ask');
  const row = card ? null : find('#approvals-answered .row.answered');
  // An answer older than the rows drawn is read, then marked in place
  // (seekAnswered): never "no longer waiting" while it may be there.
  const seeking = !card && !row && seekAnswered(id, S.home);
  const target = card || row;
  if (target) target.classList.add('focus');
  note.hidden = !!card || seeking;
  note.textContent = card || seeking ? ''
    : row ? 'That question was already answered. Its answer is marked below, under Answered earlier.'
    : 'That question is no longer waiting for you.';
  if (seeking) return;
  const to = target || note;
  if (S.page === 'approvals') focusMarked(to, false);
  if (S.approvalsScrolled || S.page !== 'approvals') return;
  S.approvalsScrolled = true;
  focusMarked(to, true);
  // Back to Approvals: the place you left, not that of the card (setPage).
  if (S.approvalsPlace) return;
  requestAnimationFrame(() => { if (to.scrollIntoView) to.scrollIntoView({ block: 'center' }); });
}

// ── Rule changes the agent asked for (policy-surface.md §8.6) ─────────────
// Every row comes from the server's fixed grammar, so the card can be decided
// without trusting the agent. The agent's own words come last, as text, in a
// muted box: they may have been written by a page the agent read.
// With the X-Mandu-Control header (and the admin session's cookie) the
// server shows an exception's pattern; without the session it hides it and
// says so (`patternsHidden`, plan 15 §13.7 item 4), and the list says it in
// plain words.

/** The reads of one list overlap (the Home poll, the read a page makes when
 *  it opens, the read after your answer), and on a slow network one asked
 *  first can answer last. `readsInOrder()` numbers them: an answer, or a
 *  failure, to a read asked before the latest one taken, or before your own
 *  write to the list answered, is older than what the page knows and is
 *  dropped before it touches anything (dashboard.md §4.25 *A read asked
 *  before your answer to a rule change never draws over it*, *A read asked
 *  before your change never draws over it*). Answers that come in the order
 *  they were asked are each taken. Each list has its own: the rule changes
 *  here, the agent page, Your rules, the Models, Sensitivity labels and
 *  Prompt filters cards of Settings, and the protection switch. */
function readsInOrder() {
  let asked = 0;
  let taken = 0;
  let written = 0;
  return {
    /** A read is asked: its number, for `take`. */
    ask: () => ++asked,
    /** The read numbered `n` answered or failed: whether to take it. */
    take(n) {
      if (n < taken || n <= written) return false;
      taken = n;
      return true;
    },
    /** A write to the list answered: every read asked so far is older. */
    wrote() { written = asked; },
  };
}
// Rule changes your agent asked for, and Rule changes (the history).
const PROPOSAL_READS = readsInOrder();
const CHANGE_READS = readsInOrder();

async function loadProposals() {
  const asked = PROPOSAL_READS.ask();
  const r = await apiGetControl('policy/proposals?status=pending').catch(() => null);
  if (!PROPOSAL_READS.take(asked)) return;
  // Known: the read answered with a list (a refused one notifies nothing).
  S.proposalsKnown = !!(r && r.ok && r.data && Array.isArray(r.data.proposals));
  S.proposals = S.proposalsKnown ? r.data.proposals : [];
  S.proposalPatternsHidden = !!(r && r.ok && r.data && r.data.patternsHidden);
}

/** The plain line under a list whose exception patterns the server hid. */
const PATTERNS_HIDDEN_NOTE = 'Some of these changes let words you chose through the prompt filter. Sign in as the admin to see them.';

/** Your agent asked for this rule change (the card `byAgent`). A held change
 *  to policy.yaml (policy-surface.md §8.4.6), the setup assistant and a
 *  change you asked for that is left waiting are not from the agent
 *  (dashboard.md §4.25 *A rule change you asked for is never credited to
 *  your agent*). A card without byAgent reads as from the agent, as every
 *  card did before the server sent it. */
function askedByAgent(p) {
  return !p.onDisk && p.byAgent !== false;
}

function renderHomeProposalLink() {
  const host = document.getElementById('home-waiting');
  if (!S.proposals.length) return;
  const text = !S.proposals.every(askedByAgent)
    ? n(S.proposals.length, 'rule change waits', 'rule changes wait') + ' for you in Approvals'
    : n(S.proposals.length, 'rule change your agent asked for is', 'rule changes your agent asked for are') + ' in Approvals';
  host.append(el('a', { href: routeHref('approvals'), 'data-page-link': 'approvals', class: 'more', text }));
}

/** The rows of a rule change (a request, a change made, what it would let), each
 *  file, pattern or host in it as nameCode, so a short one is kept whole as
 *  on a waiting card (dashboard.md §4.25u, *Approvals names things whole*). */
function rowList(rows, cls) {
  const ul = el('ul', { class: cls });
  for (const r of rows || []) {
    const li = el('li');
    for (const p of r) li.append(p.kind === 'code' ? nameCode(p.text) : document.createTextNode(p.text));
    ul.append(li);
  }
  return ul;
}

function proposalCard(p) {
  const card = el('div', { class: 'ask expanded proposal', 'data-id': p.id });
  const top = el('div', { class: 'ask-top' });
  top.append(el('div', { class: 'ask-icon' }, svg(ICON.lock)));
  const body = el('div', { class: 'ask-body' });
  const headline = el('div', { class: 'ask-sentence', text: p.headline || (p.requester || 'Your agent') + ' wants to change a rule' });
  body.append(headline);
  nameBy(card, headline);
  // The moment alone, with no period, as the waiting cards below (askCard);
  // no moment recorded, no words.
  const when = whenNode(p.createdAt);
  body.append(el('div', { class: 'ask-sub' }, when && p.onDisk ? 'Seen ' : null, when));
  top.append(body);
  card.append(top);
  const rows = rowList(p.rows, 'proposal-rows');
  card.append(rows);
  let lets = null;
  if (p.wouldLet && p.wouldLet.length) {
    card.append(el('div', { class: 'proposal-k', text: 'This would let' }));
    lets = rowList(p.wouldLet, 'proposal-let');
    card.append(lets);
  } else if (p.capped) {
    card.append(el('div', { class: 'proposal-notice', text: 'This only tightens your rules. It waits for you because your agent already changed many rules in this session.' }));
  }
  if (p.onDisk) {
    // policy-surface.md §8.4.6: a program on this computer (your agent
    // included) can write the file, so a loosening waits for you.
    card.append(el('div', { class: 'proposal-notice', text: 'Anything on this computer that can write the file, your agent included, could have made this change, so it waits for you. Not now keeps your current rules and writes them back to policy.yaml, so the file always says what Mandu enforces.' }));
  }
  for (const w of p.warnings || []) {
    const warn = sentenceNode(w, 'proposal-warn');
    warn.setAttribute('role', 'note');
    warn.prepend('Warning: ');
    card.append(warn);
  }
  if (p.reason) {
    // Only words from your agent are labelled as said by it; the note of
    // a page or program you used (where you made the change) is a Note.
    const says = el('div', { class: 'agent-says' });
    says.append(el('div', { class: 'proposal-k', text: askedByAgent(p) ? 'Your agent says' : 'Note' }));
    says.append(el('div', { class: 'agent-says-text', text: p.reason }));
    card.append(says);
  }
  // Every request of your agent has one headline, so two cards share their
  // group name: Allow, Not now, the link and the ALLOW field are named by
  // what this request changes, and a held change to policy.yaml, which lists
  // no edit, by what it would let (*Details, Undo and the agent link name
  // their row*). Only lines drawn above, never the reason your agent gave.
  const about = changeWords(headline.textContent, rows.children.length || !lets ? rows : lets);
  const actions = el('div', { class: 'ask-actions' });
  const allow = el('button', { type: 'button', class: 'btn proposal-allow', text: 'Allow', 'aria-label': rowControlName('Allow', about), onclick: () => decideProposal(p, 'approved', card) });
  const notNow = el('button', { type: 'button', class: 'btn primary', text: 'Not now', 'aria-label': rowControlName('Not now', about), onclick: () => decideProposal(p, 'denied', card) });
  const foot = el('div', { style: 'display:flex;gap:8px;align-items:center;flex-wrap:wrap' });
  // The agent that asked, as a question card links it (dashboard.md §4.25
  // *A rule change and the agent that asked*).
  if (p.session) foot.append(askLink(p.session, null, p.overBroad ? 'font-size:14px' : 'margin-right:auto;font-size:14px', about));
  if (p.overBroad) {
    const input = el('input', { type: 'text', class: 'proposal-confirm', placeholder: 'Type ALLOW to confirm', 'aria-label': rowControlName('Type ALLOW to confirm this wide change', about) });
    input.value = S.proposalTyped.get(p.id) || '';
    allow.disabled = input.value !== 'ALLOW';
    input.addEventListener('input', () => {
      S.proposalTyped.set(p.id, input.value);
      allow.disabled = input.value !== 'ALLOW';
    });
    foot.append(wideWhy(p.overBroadWhy, p.warnings && p.warnings.length), input);
  }
  actions.append(allow, notNow);
  foot.append(actions);
  card.append(foot);
  return card;
}

/** The foot line of a wide change, before its Type ALLOW field: what it
 *  opens, one sentence per wide edit as the server words it, and why it
 *  asks for the typed word (dashboard.md §4.25 *A wide change says what is
 *  open*). With a warning, the line about it, as before; an older server
 *  that sends no sentences, the old words. */
function wideWhy(why, warned) {
  const line = el('span', { class: 'dim wide-why', style: 'margin-right:auto;font-size:14px' });
  const list = Array.isArray(why) ? why : [];
  list.forEach((parts, i) => line.append(i ? ' ' : '', fitWords(parts)));
  const tail = warned ? 'Read the warning above before you allow this.' : list.length ? 'Type ALLOW if you mean it.' : 'This change has no limit on one side.';
  line.append((list.length ? ' ' : '') + tail);
  return line;
}

async function decideProposal(p, verdict, card) {
  if (S.busy.has(p.id)) return;
  S.busy.add(p.id);
  const place = answerPlace(card);
  dropAnswer(place, card);
  for (const b of card.querySelectorAll('button')) b.disabled = true;
  try {
    const r = await apiPost('policy/proposals/' + encodeURIComponent(p.id), { verdict });
    if (!r.ok) {
      keepAnswer(place, card, refusalText(r, 'could not record your answer (' + r.status + ')'));
      return;
    }
    S.proposalNotice = r.data && r.data.refiled
      ? { id: r.data.refiled.id, text: 'The rules changed since ' + (askedByAgent(r.data.refiled) ? 'your agent asked' : 'this was asked') + '; here is the updated request.' }
      : null;
    // Answered: the request no longer waits, whatever a read asked before
    // this answer still lists (readsInOrder drops it). A poll that draws
    // before the read after this answer draws without it too.
    S.proposals = S.proposals.filter((q) => q.id !== p.id);
    PROPOSAL_READS.wrote();
  } finally {
    S.busy.delete(p.id);
  }
  answerWorked(place, card);
  forgetDrawn();
  await loadHome();
  if (S.page === 'rules') loadRules();
}

function renderProposals() {
  const block = document.getElementById('approvals-proposals-block');
  const host = document.getElementById('approvals-proposals');
  // The same requests: the cards stay as they are, with what you typed, the
  // focus and the words of an answer (sameAsDrawn). Drawn again, each ALLOW
  // field keeps what you typed in it, and the focus when it had it.
  if (sameAsDrawn('proposals', [S.proposals, S.proposalPatternsHidden, S.proposalNotice])) return;
  const ids = new Set(S.proposals.map((p) => p.id));
  for (const id of S.proposalTyped.keys()) if (!ids.has(id)) S.proposalTyped.delete(id);
  const active = document.activeElement;
  const typing = active && active.classList && active.classList.contains('proposal-confirm') && host.contains(active)
    ? { id: active.closest('.proposal').dataset.id, start: active.selectionStart, end: active.selectionEnd } : null;
  clear(host);
  block.hidden = S.proposals.length === 0;
  document.getElementById('approvals-proposals-head').textContent = S.proposals.every(askedByAgent)
    ? 'Rule changes your agent asked for' : 'Rule changes waiting for you';
  for (const p of S.proposals) {
    if (S.proposalNotice && S.proposalNotice.id === p.id) host.append(el('div', { class: 'proposal-notice', text: S.proposalNotice.text }));
    host.append(proposalCard(p));
  }
  if (S.proposalPatternsHidden && S.proposals.length) host.append(el('div', { class: 'empty patterns-hidden', text: PATTERNS_HIDDEN_NOTE }));
  putBackAnswers('proposal', host);
  // Compared as values, never spliced into a selector: ids are server data.
  const card = typing && [...host.querySelectorAll('.proposal')].find((c) => c.dataset.id === typing.id);
  const field = card && card.querySelector('.proposal-confirm');
  if (field) {
    field.focus();
    try { field.setSelectionRange(typing.start, typing.end); } catch { /* a field that has no caret */ }
  }
}

/** Rule changes, the newest `S.changes.want` (20, and 20 more for each Show
 *  more; dashboard.md §4.25 *Past the newest 20*). The route says no total,
 *  so the read asks for one more than is drawn: one came, Show more is
 *  offered. Each poll reads as many as are drawn. `more`: the read of Show more,
 *  whose first new row takes the focus; one that fails keeps the rows and
 *  says why beside Show more, which gets the focus back. */
async function loadRuleHistory(more) {
  const block = document.getElementById('approvals-rule-history-block');
  const host = document.getElementById('approvals-rule-history');
  const st = S.changes;
  // The poll does not read while the read of Show more is out (as on History).
  if (!more && st.out) return;
  const want = more ? st.want + CHANGES_PAGE : st.want;
  const asked = CHANGE_READS.ask();
  if (more) st.out = (st.out || 0) + 1;
  const got = await apiGetControl('policy/changes?limit=' + Math.min(want + 1, CHANGES_MAX)).catch(() => null);
  if (more) st.out--;
  if (S.changes !== st) return;
  // An older read than the list knows (an Undo answered meanwhile): one of
  // the poll is dropped; one of Show more draws the list again, its button on.
  const taken = CHANGE_READS.take(asked);
  if (!taken && !more) return;
  const r = taken && got && got.ok ? got.data : null;
  const had = st.last && Array.isArray(st.last.changes) ? st.last.changes.slice(0, st.want).map((x) => x.id) : [];
  if (r) Object.assign(st, { want, last: r, failure: null });
  else if (more && taken) st.failure = !got || got.status === 0 ? 'gone' : got.data && got.data.unreachable ? 'down' : got.status;
  else if (!more) st.last = null;
  // The same changes: the rows stay as they are, the words of an Undo too.
  if (sameAsDrawn('rule-history', [st.last, st.want, st.failure]) && !more) return;
  const place = more ? null : pollPlace(host);
  const all = st.last && Array.isArray(st.last.changes) ? st.last.changes : [];
  const changes = all.slice(0, st.want);
  clear(host);
  block.hidden = changes.length === 0;
  if (st.last && st.last.patternsHidden && changes.length) host.append(el('div', { class: 'empty patterns-hidden', text: PATTERNS_HIDDEN_NOTE }));
  for (const c of changes) {
    // Its state: whether Undo is on it, so the words of a refused Undo go
    // once it was undone.
    const row = el('div', { class: 'row answered', 'data-id': c.id, 'data-state': c.undoable ? 'undoable' : 'done' });
    const said = el('div', { text: c.sentence });
    nameBy(row, said);
    const list = rowList(c.rows, 'proposal-let');
    const words = el('div', { class: 'answered-sentence' }, said, list);
    // Two rows can share a sentence ("Your agent tightened your rules"):
    // their Undo and link are named by what each changed (*Details, Undo
    // and the agent link name their row*).
    const about = changeWords(c.sentence, list);
    // A change your agent made or asked for links its page at the top, as
    // the Rules origin line does (dashboard.md §4.25 *A rule change and the
    // agent that asked*).
    row.append(answeredWhat(words, c.createdAt, c.session ? { id: null, sessions: [c.session], about } : null));
    row.append(el('div', { class: 'dim', text: c.undone ? 'Undone' : '' }));
    if (c.undoable) {
      row.append(el('button', { type: 'button', class: 'btn small right', text: 'Undo', 'aria-label': rowControlName('Undo', about), onclick: () => undoChange(c, row) }));
    } else row.append(el('span'));
    host.append(row);
  }
  // No total to give: the newest shown, and Show more while one more came.
  if (all.length > changes.length) {
    host.append(moreLine('changes-more', st.failure
      ? cannotCheck('Could not read more of the rule changes.', st.failure, false)
      : ['Showing the newest ' + n(changes.length, 'change', 'changes') + '.'], () => loadRuleHistory(true)));
  }
  putBackAnswers('change', host);
  if (!more) { pollRefocus(place); return; }
  const first = changes.find((x) => !had.includes(x.id));
  const row = r && first ? drawnCards(host).get(first.id) : null;
  if (row) landOn(row);
  else {
    const again = host.querySelector('.changes-more .show-rest');
    if (again && focusFell()) again.focus({ preventScroll: true });
  }
}

/** What a Rule changes row did, in the words drawn under its sentence: the
 *  first line, and how many more ("…, and 2 more"); the sentence when the
 *  row lists none. */
function changeWords(sentence, list) {
  const lines = [...list.children].map(lineWords).filter(Boolean);
  if (!lines.length) return sentence;
  return lines.length > 1 ? lines[0] + ', and ' + (lines.length - 1) + ' more' : lines[0];
}

async function undoChange(c, row) {
  if (S.busy.has(c.id)) return;
  S.busy.add(c.id);
  const place = answerPlace(row);
  dropAnswer(place, row);
  for (const b of row.querySelectorAll('button')) b.disabled = true;
  try {
    const r = await apiPost('policy/changes/' + encodeURIComponent(c.id) + '/undo');
    if (!r.ok) {
      keepAnswer(place, row, refusalText(r, 'could not undo (' + r.status + ')'));
      return;
    }
    // Undone: a history read asked before this answer still offers Undo.
    CHANGE_READS.wrote();
  } finally {
    S.busy.delete(c.id);
  }
  answerWorked(place, row);
  forgetDrawn();
  await loadRuleHistory();
  if (S.page === 'rules') loadRules();
}

// ── Rules ─────────────────────────────────────────────────────────────────────
// Your rules: read when Rules opens and after each change made on it
// (readsInOrder). Each change marks the reads asked before it answered:
// never a rule drawn as it was before a later change.
const RULES_READS = readsInOrder();

async function loadRules() {
  const asked = RULES_READS.ask();
  // The protection setting has a guard of its own, shared with Settings.
  const axesAsked = AXES_READS.ask();
  const [, axes, panel, secrets, origins, byWho] = await Promise.all([
    // What waits in Approvals (renderRulesPending); its failure is no list.
    loadProposals().then(() => null, () => null),
    apiGet('config/axes').catch(() => null),
    // With no protection service the route still answers, with a panel that
    // says `available: false` and holds no rules: that reads as unread, never
    // as "no rules" (dashboard.md §4.25 "Empty states"). A read that failed
    // keeps why (readFailure), for the line that says it.
    apiGet('policy/panel').then((r) => r.panel, (err) => ({ failed: readFailure(err) })),
    apiGet('secrets').catch(() => null),
    // Who put each rule there (§4.25i). Unreadable: the rows just say nothing.
    apiGet('policy/rules/origins').catch(() => null),
    // Who may get your secrets (§4.25aa). Unread: the card stays hidden.
    apiGet('policy/by-who').then((r) => (r && r.byWho) || null, () => null),
  ]);
  if (!RULES_READS.take(asked)) return;
  if (AXES_READS.take(axesAsked)) S.axes = axes;
  S.secrets = secrets; S.origins = origins && origins.origins ? origins : null;
  S.byWho = byWho;
  S.panel = panel && !panel.failed && panel.available !== false ? panel : null;
  S.panelFailure = (panel && panel.failed) || null;
  renderRulesOff();
  renderRulesPending();
  renderRules();
  renderByWho();
}

/** Above Your rules while a rule change waits for you in Approvals (tour
 *  item 17): the rules listed are the ones Mandu enforces, and what waits is
 *  not among them until you answer. A change made to policy.yaml on disk is
 *  in the file but not in force, so the page says the file says more. */
function renderRulesPending() {
  const box = document.getElementById('rules-pending');
  if (!box) return;
  const k = S.proposals.length;
  const onDisk = S.proposals.some((p) => p.onDisk);
  if (sameAsDrawn('rules-pending', [k, onDisk])) return;
  clear(box);
  if (k) {
    box.append(
      onDisk
        ? 'policy.yaml has a change that waits for your OK, so it is not in force yet. '
        : n(k, 'rule change waits', 'rule changes wait') + ' for your OK. ',
      'Until you answer, the rules below are the ones Mandu enforces. ',
      el('a', { href: routeHref('approvals'), 'data-page-link': 'approvals', text: 'Review ' + (k === 1 ? 'it' : 'them') + ' in Approvals' }),
      '.',
    );
  }
  box.hidden = !box.firstChild;
}

/** Above Your rules while the rules are not enforced, or will not be after
 *  the next start: what RUNS (the `protection` of Home) says which, and the
 *  switch is in Settings (dashboard.md §4.25 "The on/off says what runs"). */
function renderRulesOff() {
  const box = document.getElementById('rules-off');
  S.runningShown.rules = runningKey(S.home);
  const savedOn = !!(S.axes && S.axes.effective && S.axes.effective.confidentiality);
  const savedOff = !!(S.axes && S.axes.effective && !S.axes.effective.confidentiality);
  const now = secretsRunning(S.home);
  const toSettings = () => el('a', { href: routeHref('settings'), 'data-page-link': 'settings', text: 'Turn it on in Settings' });
  clear(box);
  if (now === 'off' && savedOff) box.append('Protection is off, so these rules are kept but not enforced. ', toSettings(), '.');
  else if (now === 'off' && savedOn) box.append('Protection is still off until the protection service restarts, so these rules are kept but not enforced.');
  else if (savedOff) box.append('Protection is saved as off: once the protection service restarts, these rules are kept but not enforced. ', toSettings(), '.');
  box.hidden = !box.firstChild;
}

/** What the protection service RUNS now on the secrets axis, the axis of
 *  the one switch: on, off, or null when Mandu cannot say (no protection
 *  service connected, or one that reports no posture). The `protection` of
 *  Home is what runs; `config/axes` is only what is saved for the next start. */
function secretsRunning(home) {
  const p = home && home.protection;
  if (!p || !p.connected) return null;
  if (p.level === 'secrets' || p.level === 'full') return 'on';
  if (p.level === 'off' || p.level === 'injection') return 'off';
  return null;
}
/** What the words of the on/off depend on in the Home answer; a poll that leaves
 *  it as it was repaints nothing (a refusal in the note stays). */
function runningKey(home) {
  const p = home && home.protection;
  return p ? (p.connected ? 'connected' : 'not connected') + ':' + p.level : 'no home';
}
/** The Home poll: Settings › Protection and the Rules line follow what runs
 *  (the first paint of a direct visit may come before Home answers, and a
 *  restart changes what runs while the page is open). */
function followRunning() {
  if (!S.axes) return;
  const key = runningKey(S.home);
  if (S.runningShown.settings !== key) renderProtection();
  if (S.runningShown.rules !== key) renderRulesOff();
}

/** Under a "your own model only" rule while no model of your own is listed
 *  (the same words as model-endpoints.ts NO_OWN_MODEL_WARNING). */
const NO_OWN_MODEL_WARNING = 'No AI of your own is listed, so no AI reads this file. Add one in Settings › Models.';

/** Does the rules file name a model the person runs themselves? (plan 11 D6;
 *  the same test as model-endpoints.ts hasLocalModel.) Unknown reads as no. */
function hasOwnModel(panel) {
  return !!(panel && Array.isArray(panel.models) && panel.models.some((m) => m && m.local === true));
}

// The saved setting the switch shows is read by Settings and by Rules, and
// a flip answers it too: one guard orders all three (readsInOrder), so a
// read asked before a newer one taken, or before your flip answered, never
// draws the switch as it was (dashboard.md §4.25 *The protection switch
// keeps what you saved*).
const AXES_READS = readsInOrder();

/** The one on/off in Settings (dashboard.md §4.25 Settings): guarding secrets, the
 *  confidentiality axis. Mandu is about secrets, so the frozen integrity axis
 *  (protection-modes.md §10) has no switch here: a flip keeps it only where
 *  this dashboard opted in to it, and otherwise turns a stale one off too
 *  (turning it off is always allowed; the server refuses keeping it on). */
async function loadProtection() {
  const asked = AXES_READS.ask();
  // Why it could not be read (readFailure), for the line that says it.
  let failure = null;
  const axes = await apiGet('config/axes').catch((err) => { failure = readFailure(err); return null; });
  if (!AXES_READS.take(asked)) return;
  S.axes = axes;
  S.axesFailure = failure;
  renderProtection();
}

function renderProtection() {
  const a = S.axes;
  const sw = document.getElementById('switch-protection');
  const name = document.querySelector('#settings-protect-row .name');
  const text = document.getElementById('settings-protect-text');
  const note = document.getElementById('settings-protect-note');
  clear(name);
  S.runningShown.settings = runningKey(S.home);
  if (!a || !a.effective) {
    sw.disabled = true;
    sw.setAttribute('aria-checked', 'false');
    name.append(el('span', { class: 'dot ' + protectDot() }), 'Unknown');
    // The cause its read tells (dashboard.md §4.25 *A could-not line names
    // the cause the page knows*): the dashboard reads config.toml itself,
    // so with none known the sentence goes alone, never the hedge about
    // the protection service.
    const lead = 'The protection settings could not be read.';
    clear(text);
    text.append(...(S.axesFailure ? cannotCheck(lead, S.axesFailure, true) : [lead]));
    note.textContent = '';
    return;
  }
  // The switch and its name are the SAVED setting; the dot and the sentence
  // say what runs now, which differs until the protection service restarts
  // (dashboard.md §4.25 "The on/off says what runs").
  const on = !!a.effective.confidentiality;
  const now = secretsRunning(S.home);
  sw.disabled = false;
  sw.setAttribute('aria-checked', on ? 'true' : 'false');
  sw.onclick = () => flipProtection(!on);
  name.append(el('span', { class: 'dot ' + protectDot() }), on ? 'On' : 'Off');
  // The words Home uses: a rule sends a secret with no question asked, so
  // the row never promises an OK for every send (dashboard.md §4.25d).
  const ON_WORDS = 'Keys and secret files leave this computer only where a rule or your OK allows.';
  const OFF_WORDS = 'Mandu only watches. Your secrets are not masked, and nothing is stopped.';
  if (now === null) {
    const connected = !!(S.home && S.home.protection && S.home.protection.connected);
    text.textContent = 'Saved as ' + (on ? 'on' : 'off') + '. ' + (connected
      ? 'Mandu cannot say what the protection service runs now.'
      : 'The protection service is not reachable, so Mandu cannot say what is on now.');
  } else if ((now === 'on') === on) text.textContent = on ? ON_WORDS : OFF_WORDS;
  else text.textContent = now === 'on'
    ? 'Still on until the protection service restarts: keys and secret files leave this computer only where a rule or your OK allows.'
    : 'Still off until the protection service restarts: Mandu only watches, and your secrets are not masked.';
  const running = S.home && S.home.protection.level;
  note.textContent = running && running !== 'unknown' && running !== a.effectiveMode
    ? 'Saved. It applies when the protection service next starts.'
    : 'A change applies when the protection service next starts.';
}

/** The one dot of the Protection row, for the switch and the service line
 *  under it (dashboard.md §4.25 *One Protection row*): red when the service
 *  stopped unexpectedly, amber while it starts or while protection is off
 *  (saved or running), green only when on is both saved and running and the
 *  line does not say Stopped, else grey (not known, or stopped as usual). */
function protectDot() {
  if (S.serviceState === 'crashed') return 'bad';
  const a = S.axes;
  if (!a || !a.effective) return '';
  const now = secretsRunning(S.home);
  if (!a.effective.confidentiality || now === 'off' || S.serviceState === 'starting') return 'warn';
  return now === 'on' && S.serviceState !== 'stopped' ? 'ok' : '';
}

async function flipProtection(on) {
  // While a flip is on its way the switch holds (dashboard.md §4.25 *The
  // switch holds while its change is on its way*): a second press would post
  // again, or ask for the typed OFF again. Not `disabled`, which drops the
  // focus to the page: `aria-disabled` keeps the focus on the switch and says
  // it is off-limits, and the press is ignored here. A redraw meanwhile
  // (the Home poll, a read of the setting) leaves it as it is.
  if (S.protectOut) return;
  if (!on && window.prompt('Turning this off lets your secrets leave this computer. Type OFF to confirm.') !== 'OFF') return;
  const keepIntegrity = !!(S.axes.integrityAllowed && S.axes.effective.integrity);
  const mode = on ? (keepIntegrity ? 'full' : 'secrets') : (keepIntegrity ? 'injection' : 'off');
  const sw = document.getElementById('switch-protection');
  // Held until the answer, whatever it is: every request answers (answerOf).
  S.protectOut = true;
  sw.setAttribute('aria-disabled', 'true');
  let r;
  try { r = await apiPost('config/axes', { mode }); } finally {
    S.protectOut = false;
    sw.removeAttribute('aria-disabled');
  }
  if (!r.ok) {
    setWords(document.getElementById('settings-protect-note'), refusalText(r, 'could not save the change (' + r.status + ')'));
    return;
  }
  AXES_READS.wrote();
  S.axes = r.data;
  renderProtection();
}

/** A secret-file label in the product's words. A label reaching everything
 *  inside a file reads as that file (`pathIsFile`). */
function labelReach(l) {
  return l.pattern ? 'every matching file' : l.scope === 'subtree' && !l.pathIsFile ? 'and everything inside' : 'this file only';
}
/** The same terms as rule-words.ts on the server (dashboard.md §4.25d). */
function labelEffect(l) {
  if (l.levelClass === 'public') return 'Not secret';
  const base = l.modelOk ? 'Any AI, when it asks' : l.levelClass === 'local-only' ? 'Your own AI only' : 'No AI';
  const to = (l.bindings || []).filter(Boolean);
  return to.length ? base + '; may be sent to ' + to.join(', ') : base;
}

const RULE_ICON = { lock: 'lock', 'trusted-origin': 'globe', 'untrusted-origin': 'globe', 'release-allow': 'globe', 'release-block': 'globe', 'release-audit': 'globe', 'release-off': 'globe', 'connect-allow': 'globe', disposition: 'terminal' };

/** The groups the Rules list is cut into, in order: the question a person
 *  would ask ("what about my files?"), never where a rule is stored. Each
 *  says, under its title, what its rules decide (dashboard.md §4.25e). */
const RULE_GROUPS = [
  // Your file rules are the Files and folders list above (§4.25n); what is
  // left of this group is your answers about single files.
  { key: 'files', title: 'Your answers about files',
    about: 'what you answered when Mandu asked about one file' },
  { key: 'send', title: 'Sending data',
    about: 'where masked data and secrets may go without asking you' },
  { key: 'sources', title: 'Trusted sources',
    about: 'places whose content reaches the AI unmasked' },
  { key: 'run', title: 'Programs and connections',
    about: 'programs whose output the AI may read, and connections the agent may open' },
];
/** The colour of a rule from your rules: what it does now, as the answers
 *  beside it are coloured. Read from the kind of the rule, never its words:
 *  a send rule (`release-allow` / `release-block`), a connection the agent
 *  may open (`connect-allow`, always allowed) and a built-in protection set
 *  to Block (`disposition`, always blocked). An expired rule decides
 *  nothing; a source, a program and a file rule say masked or trusted, not
 *  allowed or blocked, so they have no colour. */
function ruleTone(r) {
  if (r.expired) return null;
  if (r.kind === 'release-allow' || r.kind === 'connect-allow') return 'ok';
  if (r.kind === 'release-block' || r.kind === 'disposition') return 'bad';
  return null;
}
function ruleGroup(kind, id) {
  if (String(id).startsWith('app:')) return 'run';
  if (kind === 'lock') return 'files';
  if (kind === 'trusted-origin' || kind === 'untrusted-origin') return 'sources';
  if (kind === 'connect-allow' || kind === 'disposition') return 'run';
  return 'send';
}

// ── Find a rule (dashboard.md §4.25f *Find a rule*) ─────────────────────────
// The box beside Your rules' heading narrows the rows the page drew to those
// whose words hold its text, case-insensitive. Presentation only: no read, no
// write. Never in the address, and emptied by a page change (setPage), so a
// filter you forgot never makes a rule look missing on your next visit. Changes
// to save is never narrowed: it lists F.pending, not the rows drawn.

/** The text the rows are narrowed to: '' when the box is empty. */
function findText() {
  return String(S.ruleFind || '').replace(/\s+/g, ' ').trim().toLowerCase();
}
/** The words a row of Your rules draws, and only those (never the raw
 *  subject a row keeps for its tooltip, nor anything a read held back):
 *  - a file or folder of the tree: its path as drawn (`~/…`, and in full,
 *    its tooltip), its reach, its label, the Opens it line, the hosts it may
 *    be sent to (per value, with the value's name);
 *  - any other row: what it covers (a host, a program, an address and
 *    port, a source), its second line (the file it sends, from where), and
 *    what it does. */
function ruleWords(r) {
  if (F.rules.includes(r)) {
    return [shortPath(r.path), r.path, r.reach, r.effect,
      r.opens && r.level !== 'public' ? r.opens : null,
      ...(r.bindings || []), ...(r.values || []).flatMap((v) => [v.key, ...(v.bindings || [])])];
  }
  return [r.subject, r.reach, r.effect];
}
/** Does row `r` hold the text `q` (findText) in the words it draws? */
function ruleMatches(r, q) {
  if (!q) return true;
  return ruleWords(r).filter((w) => typeof w === 'string').join('\n').toLowerCase().includes(q);
}
/** The text typed looks like a path: a line offers Add a rule for it. */
function looksLikePath(q) {
  return /[/~*]/.test(q) || /^\.[^\s.]/.test(q);
}
/** The box emptied (Clear, Escape, a page change, a jump to a row it
 *  hid). `redraw`: the rows are drawn again at once. */
function clearRuleFind(redraw) {
  const box = document.getElementById('rules-find');
  if (box) box.value = '';
  if (!S.ruleFind) return;
  S.ruleFind = '';
  if (redraw) renderRules();
}
/** Under the heading while nothing drawn holds the text: says so, with
 *  Clear, and Add a rule when the text looks like a path. */
function renderFindNone(q, none) {
  const box = document.getElementById('rules-find-none');
  if (!box) return;
  clear(box);
  if (q && none) {
    const typed = document.getElementById('rules-find').value.trim();
    box.append(el('p', null, 'No rule mentions \u201c' + typed + '\u201d. ',
      el('button', { type: 'button', class: 'link-btn', text: 'Clear', onclick: () => {
        clearRuleFind(true);
        document.getElementById('rules-find').focus();
      } })));
    if (looksLikePath(q)) {
      box.append(el('p', { class: 'dim' }, 'To make one, ',
        el('button', { type: 'button', class: 'link-btn', text: 'add a rule', onclick: () => {
          // A full path or a pattern goes in the path box and is opened, as
          // Go opens it; any other text opens the browser where it starts.
          const full = /^(?:\/|~|\*\*\/)/.test(typed);
          setFilesView('all', null, full);
          const path = document.getElementById('lock-path');
          if (full) {
            path.value = typed;
            document.getElementById('files-go').requestSubmit();
          }
          path.focus();
        } }), '.'));
    }
  }
  box.hidden = !box.firstChild;
}
function wireRuleFind() {
  const box = document.getElementById('rules-find');
  box.addEventListener('input', () => {
    S.ruleFind = box.value;
    renderRules();
  });
  // Escape empties the box (a plain one, and only with text in it: an empty
  // box leaves Escape to whatever else takes it).
  box.addEventListener('keydown', (e) => {
    if (!plainEscape(e) || !box.value) return;
    e.preventDefault();
    clearRuleFind(true);
  });
}

/**
 * Every row is one sentence with its buttons, and every button acts here:
 * nothing on this page opens the developer view (dashboard.md §4.25c).
 *   - a rule from your rules: Remove (and Allow/Block instead for a send
 *     rule), through POST policy/rules/change; a change that loosens
 *     protection asks first; every change offers Undo;
 *   - a file you locked on this page: Remove, through the label route;
 *   - a past answer: Allow/Block instead, and Remove, which forgets it so
 *     you are asked again.
 */
function renderRules() {
  const host = document.getElementById('rules-list');
  clear(host);
  const rows = [];
  const panel = S.panel;
  // The PROJECTED label rows (panel.labels: levelClass / modelOk / scope /
  // pattern), never the raw arbiter rows beside them. Labels from the rules
  // file are already rows of panel.yourRules (worded by the server in the
  // terms of this page, `plain`); only the ones made on this page are listed on
  // their own.
  const labels = (S.secrets && S.secrets.panel && S.secrets.panel.labels) || [];
  if (panel && panel.yourRules) {
    for (const r of panel.yourRules) {
      const words = r.plain || { subject: r.subject, reach: r.reach, effect: r.effect };
      const acts = r.actions || { remove: false, flip: null };
      const isFile = r.kind === 'lock' && !r.id.startsWith('app:');
      rows.push({
        group: ruleGroup(r.kind, r.id),
        icon: RULE_ICON[r.kind] || 'file',
        path: isFile ? words.subject : null,
        covers: isFile ? (r.covers || (words.reach === 'every matching file' ? 'pattern' : words.reach === 'and everything inside' ? 'subtree' : 'exact')) : null,
        pathIsFile: isFile && r.pathIsFile === true,
        // For the side panel of the explorer (§4.25n): the label buttons press the
        // level in force and fill in its hosts; Remove there needs an edit op.
        level: isFile ? r.level : null,
        bindings: isFile ? (r.bindings || []) : null,
        // The rule's version as read: a label chosen on it sends it back
        // (dashboard.md §4.25m *A save names the rules as they were read*).
        version: isFile ? (r.version || null) : null,
        opens: isFile ? (words.opens || null) : null,
        // Plan 13 §5.2: per-value hosts, and their sentence (read only).
        values: isFile && r.values && r.values.length ? r.values : null,
        send: isFile ? (words.send || null) : null,
        sendParts: isFile ? (words.sendParts || null) : null,
        editable: acts.remove,
        subject: isFile ? shortPath(words.subject) : words.subject,
        // A connection rule's words around its names (§4.25u, *Rules names
        // a connection in words*); an older server sends none.
        subjectParts: !isFile ? partsOf(words.subjectParts) : null,
        title: r.subject,
        reach: words.reach,
        reachParts: partsOf(words.reachParts),
        effect: words.effect,
        // The menu of a send rule has the dot an answer with the same words
        // has (§4.25u, the dot of a send rule): red for Always blocked,
        // green for Always allowed; expired, audit or off, grey. A connection
        // or a built-in protection set to Block has no menu: its words take
        // the ✓ or ✗ of an answer without one (§4.25u, a connection rule is
        // coloured as its answer).
        effectClass: ruleTone(r),
        used: r.hits === null || r.hits === undefined ? '' : r.hits === 0 ? 'Never used' : n(r.hits, 'use', 'uses'),
        flip: acts.flip ? { text: acts.flip === 'allow' ? 'Always allowed' : 'Always blocked', run: (row) => changeRule(r, acts.flip, row) } : null,
        remove: acts.remove ? (row) => changeRule(r, 'remove', row) : null,
        note: acts.flip || acts.remove ? null : 'Set in policy.yaml',
        sourceId: r.id,
        origin: ruleOrigin(r.id),
        warning: r.warning || null,
      });
    }
  }
  for (const l of labels) {
    if (l.source === 'policy-file') continue;
    rows.push({
      group: 'files',
      icon: 'lock',
      path: l.path,
      covers: l.pattern ? 'pattern' : l.scope === 'subtree' ? 'subtree' : 'exact',
      pathIsFile: l.pathIsFile === true,
      subject: shortPath(l.path),
      title: l.path,
      reach: labelReach(l),
      effect: labelEffect(l),
      used: 'Added here',
      level: pageLabelLevel(l),
      bindings: l.bindings || [],
      editable: true,
      sourceNote: 'Saved by Mandu, not in policy.yaml',
      warning: l.levelClass === 'local-only' && !hasOwnModel(panel) ? NO_OWN_MODEL_WARNING : null,
    });
  }
  if (panel && panel.verdictsKnown) {
    for (const v of panel.queue) {
      if (v.status === 'pending' || v.scope === 'once') continue;
      const flip = v.actions && v.actions[0] ? v.actions[0] : null;
      // The server's words (rule-words.ts answerWords): a sending answer
      // names the one piece of data it covers, never just the place.
      const words = v.plain || { subject: v.target || v.subject, reach: null };
      // A held message's answer (dashboard.md §4.25u, *Rules names a held
      // message's answer*) is about what went to the AI, not a file: its
      // target is the session (`model:<session>`), never a path.
      const prompt = v.where === 'prompt';
      const path = v.where === 'network' || v.where === 'exec' || prompt ? null : (v.target || null);
      rows.push({
        group: v.where === 'network' || prompt ? 'send' : v.where === 'exec' ? 'run' : 'files',
        icon: v.where === 'network' ? 'globe' : v.where === 'exec' ? 'terminal' : prompt ? FAMILY_ICON.prompt : 'file',
        path,
        covers: 'exact',
        // An answer about one file names it as the file rules do (`~/…`).
        subject: path && words.subject === path ? shortPath(path) : words.subject,
        // The category as code, the words as words; an older server sends none.
        subjectParts: partsOf(words.subjectParts),
        title: prompt ? words.subject : v.target || v.subject,
        reach: words.reach,
        // The file, address or command the answer covers, as code (§4.25u,
        // *Rules names what a send covers*); an older server sends none.
        reachParts: partsOf(words.reachParts),
        // A message's answer says what went to the AI, as Approvals does
        // (§4.25u *A held message's answer says what was sent*): masked is
        // not "Always blocked", since the message was not stopped.
        effect: prompt ? messageEffect(v.status === 'approved') : v.status === 'approved' ? 'Always allowed' : 'Always blocked',
        effectClass: v.status === 'approved' ? 'ok' : 'bad',
        used: 'Your answer' + (v.count > 1 ? ', asked ' + v.count + ' times' : ''),
        sourceNote: 'Saved when you answered, not in policy.yaml',
        // Where it was asked (dashboard.md §4.25h): the session the ask was
        // raised in (the latest, as Approvals links it) and when you answered.
        asked: { id: v.id, session: v.sessions && v.sessions.length ? v.sessions[v.sessions.length - 1] : null, sessions: (v.sessions || []).length, answeredAt: v.resolvedAt },
        flip: flip ? { text: prompt ? messageEffect(flip.approve) : flip.approve ? 'Always allowed' : 'Always blocked', run: (row) => answerAgain(v.id, flip.approve, row, prompt) } : null,
        // An answer that applies to nothing any more says why; Remove stays
        // (dashboard.md §4.34 "Answers that no longer apply").
        warning: v.staleNote || null,
        remove: (row) => forgetAnswer(v.id, row),
      });
    }
  }
  // Your file rules are the Labeled view of the explorer (dashboard.md §4.25n);
  // the list below keeps the rest, answers about single files included.
  F.rules = rows.filter((r) => r.group === 'files' && r.path && !r.asked);
  // Find a rule (§4.25f): the count says how many of them the box keeps.
  const q = panel ? findText() : '';
  const found = rows.filter((r) => ruleMatches(r, q)).length;
  document.getElementById('rules-count').textContent = !rows.length ? '' : q ? found + ' of ' + rows.length : String(rows.length);
  renderFindNone(q, found === 0);
  renderExplorer();
  const rest = rows.filter((r) => !F.rules.includes(r) && ruleMatches(r, q));
  // A row the box hides is closed: its ⋯ is gone with it.
  if (q && S.openRule && !rest.some((r) => ruleRowKey(r) === S.openRule)) S.openRule = null;
  host.hidden = false;
  if (!panel) {
    // Unread: the Labeled view above says so for the whole of Your rules,
    // so this list says nothing rather than the same sentence twice.
    host.hidden = true;
    return;
  }
  if (!rest.length) {
    host.hidden = true;
    return;
  }
  for (const g of RULE_GROUPS) {
    // A group the box leaves empty is not drawn, its title with it.
    const mine = rest.filter((r) => r.group === g.key);
    if (!mine.length) continue;
    host.append(el('div', { class: 'rules-group' }, g.title, ' ', el('span', { class: 'muted', text: g.about })));
    const list = el('div', { class: 'table rules-rows', role: 'list' });
    for (const r of mine) {
      list.append(ruleRow(r));
      if (S.openRule === ruleRowKey(r)) list.append(ruleDetail(r));
    }
    host.append(list);
  }
}

/**
 * Your file rules as a tree, the Labeled view of the explorer (dashboard.md §4.25f,
 * §4.25n), built from the
 * paths alone:
 *   - a rule on a folder "and everything inside" holds the rules on paths
 *     inside it as its children: the more specific literal rule wins there
 *     (path-labels.ts, "specificity decides"), so the nesting is the truth;
 *   - rules that share a folder no rule names are listed under that folder,
 *     as a plain heading you can fold;
 *   - a pattern is never a parent: a pattern that starts with `**` has no
 *     literal prefix, so a pattern "inside" it does not simply win. Patterns
 *     share folder headings like any path.
 * A node is { kind: 'rule', row, label, children } or
 * { kind: 'folder', label, full, pattern, count, children }. Labels are
 * relative to the node above; the full path stays in the tooltip.
 */
function fileTree(rows) {
  const root = { seg: null, path: '', depth: 0, entries: [], kids: new Map() };
  const shown = new Map(rows.map((r) => [r, shortPath(r.path)]));
  for (const r of rows) {
    const segs = shown.get(r).split('/');
    // `memo/**` names the folder `memo`: it sits on that folder's node.
    if (segs.length > 1 && segs[segs.length - 1] === '**') segs.pop();
    let node = root;
    for (const [i, seg] of segs.entries()) {
      if (!node.kids.has(seg)) node.kids.set(seg, { seg, path: segs.slice(0, i + 1).join('/'), depth: i + 1, entries: [], kids: new Map() });
      node = node.kids.get(seg);
    }
    node.entries.push(r);
  }
  const rel = (path, base) => (base === null ? path : path.slice(base.length + 1)) || path;
  const label = (r, base) => rel(shown.get(r), base);
  const count = (n) => n.entries.length + [...n.kids.values()].reduce((k, c) => k + count(c), 0);
  // Paths before patterns, then by name.
  const glob = (seg) => (/[*?[]/.test(seg) ? 1 : 0);
  const below = (n, base) => [...n.kids.values()]
    .sort((a, b) => glob(a.seg) - glob(b.seg) || a.seg.localeCompare(b.seg))
    .flatMap((c) => walk(c, base));
  function walk(n, base) {
    const holder = n.entries.find((r) => r.covers === 'subtree');
    if (holder) {
      const out = [{ kind: 'rule', row: holder, label: label(holder, base), children: below(n, n.path) }];
      for (const r of n.entries) if (r !== holder) out.push({ kind: 'rule', row: r, label: label(r, base), children: [] });
      return out;
    }
    const here = n.entries.map((r) => ({ kind: 'rule', row: r, label: label(r, base), children: [] }));
    if (here.length) return [...here, ...below(n, base)];
    if (n.kids.size === 1) return below(n, base);
    // Two or more branches under a folder no rule names. The first segment
    // (`~`, `/`, `**`) is too broad to be a heading of its own.
    if (n.depth <= 1) return below(n, base);
    return [{ kind: 'folder', label: rel(n.path, base), full: n.path, pattern: /[*?[]/.test(n.path), count: count(n), children: below(n, n.path) }];
  }
  return below(root, null);
}

function renderFileTree(host, nodes, depth) {
  for (const node of nodes) {
    if (node.kind === 'rule') {
      appendRule(host, node.row, node.label, depth, node.context);
      if (node.children.length) renderFileTree(host, node.children, depth + 1);
      continue;
    }
    // Folded stays folded when the tree is drawn again (a change, a row opened).
    // A folder on the way to a rule Find a rule found (`found`) is drawn
    // open, and folding it then changes only what is drawn: the person's own
    // folds (F.folded) are back once the box is emptied (§4.25f *Find a rule*).
    const folded = !node.found && F.folded.has(node.full);
    const kids = el('div', { class: 'rules-children' });
    kids.hidden = folded;
    const head = el('button', {
      type: 'button', class: 'rules-folder', 'aria-expanded': folded ? 'false' : 'true', style: '--depth:' + depth, title: node.full,
      onclick: () => {
        const open = head.getAttribute('aria-expanded') !== 'true';
        head.setAttribute('aria-expanded', open ? 'true' : 'false');
        kids.hidden = !open;
        if (node.found) return;
        if (open) F.folded.delete(node.full); else F.folded.add(node.full);
      },
    },
      el('span', { class: 'rules-folder-caret' }, svg(ICON.chevron, 16)),
      el('span', { class: 'row-icon' }, svg(ICON.folder, 18)),
      el('code', { text: node.label + '/' }),
      el('span', { class: 'dim', text: (node.pattern ? 'every folder that matches, ' : '') + n(node.count, 'rule', 'rules') }));
    host.append(head, kids);
    renderFileTree(kids, node.children, depth + 1);
  }
}

/** The tree of fileTree narrowed by Find a rule: a rule that holds the
 *  text, and on the way to each, the folders and folder rules above it
 *  (the nesting is the truth, so a match keeps its place); the rest goes.
 *  A folder kept counts the rules found under it and is drawn open
 *  (`found`). */
function findTree(nodes, q) {
  const out = [];
  for (const node of nodes) {
    const children = findTree(node.children, q);
    const hit = node.kind === 'rule' && ruleMatches(node.row, q);
    if (!hit && !children.length) continue;
    // A folder rule kept only for a rule inside it is `context`: drawn,
    // not counted as found.
    const kept = { ...node, children, found: true, context: !hit };
    if (node.kind === 'folder') kept.count = foundCount(children);
    out.push(kept);
  }
  return out;
}
function foundCount(nodes) {
  return nodes.reduce((k, x) => k + (x.kind === 'rule' && !x.context ? 1 : 0) + foundCount(x.children), 0);
}

/** Which row of the other groups is open (its ⋯ pressed). */
function ruleRowKey(r) { return r.asked ? 'answer:' + r.asked.id : r.sourceId || r.title || r.subject; }

/** A server's parts (`subjectParts`, `reachParts`), or null when it sent
 *  none (an older server). */
function partsOf(parts) { return Array.isArray(parts) && parts.length ? parts : null; }

/** A rule of the other groups (dashboard.md §4.25c): what it covers, ONE
 *  effect (a menu when it can be turned around here: Always allowed /
 *  Always blocked, changed at once with Undo), and a ⋯ that opens the rest
 *  under it. */
function ruleRow(r) {
  const key = ruleRowKey(r);
  const isOpen = S.openRule === key;
  const row = el('div', { class: 'row rule' + (isOpen ? ' open' : ''), role: 'listitem', 'data-rule': key });
  row.append(el('span', { class: 'row-icon' }, svg(ICON[r.icon] || ICON.file, 18)));
  const subj = el('div', { class: 'rule-text' }, ruleSubject(r));
  if (r.reach) subj.append(el('div', { class: 'dim rule-reach' }, r.reachParts ? fitWords(r.reachParts, r.reach) : r.reach));
  subj.title = r.title || r.subject;
  if (r.warning) subj.append(el('div', { class: 'rule-warn', role: 'note', text: r.warning }));
  row.append(subj, effectCell(r, row));
  row.append(moreButton(isOpen, r.subject, () => {
    S.openRule = isOpen ? null : key;
    renderRules();
    for (const r of document.querySelectorAll('#rules-list .row[data-rule]')) {
      if (r.getAttribute('data-rule') === key) r.querySelector('.file-more').focus();
    }
  }));
  return row;
}

/** What a rule of the other groups is about. A name is its chip, as wide as
 *  its words (§4.25c *The subject's chip fits it*), and a long one is cut
 *  at its dots or slashes (longName) as everywhere else on the page
 *  (§4.25u *A rule's long name breaks as elsewhere*). Words around names (a
 *  connection rule: "any address on port 2222", §4.25u *Rules names a
 *  connection in words*) are one line, each name a code that fitWords keeps
 *  whole where the column can hold it. */
function ruleSubject(r) {
  const parts = r.subjectParts;
  if (!Array.isArray(parts) || parts.every((p) => p.kind === 'code')) return longName(el('code', { text: r.subject }));
  return el('span', { class: 'rule-subject' }, fitWords(parts, r.subject));
}

/** The effect of a rule: a menu when it can be turned around, else words. */
function effectCell(r, row) {
  const cls = r.effectClass === 'ok' ? 'allow' : r.effectClass === 'bad' ? 'block' : 'none';
  if (r.flip) {
    const sel = el('select', { class: 'effect-select', 'aria-label': 'What happens for ' + r.subject });
    sel.append(el('option', { value: '', text: r.effect }), el('option', { value: 'flip', text: r.flip.text }));
    sel.addEventListener('change', async () => {
      if (sel.value !== 'flip') return;
      await r.flip.run(row);
      if (sel.isConnected) sel.value = '';
    });
    return el('span', { class: 'label-pick', 'data-effect': cls }, el('span', { class: 'label-dot', 'aria-hidden': 'true' }), sel);
  }
  const eff = el('div', { class: r.effectClass ? 'outcome ' + r.effectClass : 'sub' });
  if (r.effectClass === 'ok') eff.append(svg(ICON.check, 16));
  if (r.effectClass === 'bad') eff.append(svg(ICON.x, 16));
  eff.append(r.effect);
  return eff;
}

/** Under an opened rule: when and where it was made, how often it was used,
 *  its policy.yaml lines, and Remove. Each button names its row, its own
 *  words first (dashboard.md §4.25 *A label chosen in Your rules keeps the
 *  focus*): "Remove the rule for b.example", "Show in policy.yaml: b.example". */
function ruleDetail(r) {
  const box = el('div', { class: 'rule-detail', role: 'listitem', 'aria-label': 'About ' + r.subject });
  if (r.asked) box.append(askedLine(r.asked));
  if (r.origin) box.append(originLine(r.origin));
  if (r.used) box.append(el('div', { class: 'dim', text: r.used }));
  if (r.sourceNote) box.append(el('div', { class: 'dim rule-source-note', text: r.sourceNote }));
  const links = el('div', { class: 'detail-links' });
  const lines = el('div', { class: 'detail-source' });
  if (r.sourceId) links.append(sourceButton(lines, r.sourceId, r.subject));
  if (r.group === 'files' && r.path && r.covers !== 'pattern' && !GLOB_RE.test(r.path)) {
    links.append(el('button', { type: 'button', class: 'link-btn rule-source-btn', text: 'Show in the file browser', 'aria-label': 'Show in the file browser: ' + r.subject,
      onclick: (ev) => setFilesView('all', { folder: parentOf(r.path), pick: r.path, by: ev.currentTarget }) }));
  }
  if (r.remove) {
    links.append(el('button', { type: 'button', class: 'btn small rule-remove', text: 'Remove', 'aria-label': (r.asked ? 'Remove your answer about ' : 'Remove the rule for ') + r.subject, onclick: () => r.remove(box) }));
  }
  else if (r.note) links.append(el('span', { class: 'dim', text: r.note }));
  box.append(links, lines);
  return box;
}

/** Who put a rules-file row there (§4.25i): the newest recorded change that
 *  wrote it; "no record" only when the record was read whole; else nothing. */
function ruleOrigin(id) {
  const o = S.origins;
  if (!o) return null;
  return Object.prototype.hasOwnProperty.call(o.origins, id) ? o.origins[id] : o.complete ? o.unrecorded : null;
}

/** The origin line under a rules-file row. */
function originLine(o) {
  const line = el('div', { class: 'dim rule-origin' });
  const at = whenNode(o.at);
  line.append(o.sentence, at ? ', ' : '', at || '', '.');
  // A later edit Mandu did not see happen (made while it was not running).
  if (o.changedSince) line.append(' It was changed in policy.yaml after that, while Mandu was not running.');
  if (o.session) line.append(' ', askLink(o.session, null));
  return line;
}

/** Under an answer: when you answered, and the link to where it was asked.
 *  An answer older than session attribution has no session to show. */
function askedLine(a) {
  const line = el('div', { class: 'dim rule-asked' });
  const at = whenNode(a.answeredAt);
  if (at) line.append('You answered ', at, '.');
  if (!a.session) {
    if (at) line.append(' Where it was asked was not recorded.');
    return line;
  }
  if (at) line.append(' ');
  line.append(askLink(a.session, a.id));
  if (a.sessions > 1) line.append(' (asked in ' + a.sessions + ' sessions, this shows the latest)');
  return line;
}

/** Open or close the policy.yaml lines under a rule row (read-only). */
async function toggleRuleSource(row, btn, id, depth) {
  const open = row.nextElementSibling && row.nextElementSibling.classList.contains('rule-source') ? row.nextElementSibling : null;
  if (open) {
    open.remove();
    btn.setAttribute('aria-expanded', 'false');
    btn.textContent = 'Show in policy.yaml';
    return;
  }
  btn.disabled = true;
  const panel = await ruleSourcePanel(id);
  btn.disabled = false;
  panel.style.setProperty('--depth', String(depth));
  row.after(panel);
  btn.setAttribute('aria-expanded', 'true');
  btn.textContent = 'Hide policy.yaml';
}

/** "Show in policy.yaml" under an opened rule, named by its row (`about`):
 *  it opens the rule's lines in `host`, and closes them again. */
function sourceButton(host, id, about) {
  const btn = el('button', { type: 'button', class: 'link-btn rule-source-btn', 'aria-expanded': 'false' });
  sourceWords(btn, false, about);
  btn.onclick = () => toggleSourceInto(host, btn, id, about);
  return btn;
}
function sourceWords(btn, open, about) {
  btn.textContent = open ? 'Hide policy.yaml' : 'Show in policy.yaml';
  btn.setAttribute('aria-label', btn.textContent + ': ' + about);
}

/** The same lines inside the side panel of the explorer. The button goes
 *  off while they are read, and a browser drops the focus of a button
 *  turned off: until 2026-10-11 Show in policy.yaml left a screen reader on
 *  <body>. It gets the focus back, only if the focus fell. */
async function toggleSourceInto(host, btn, id, about) {
  if (host.firstChild) {
    clear(host);
    btn.setAttribute('aria-expanded', 'false');
    sourceWords(btn, false, about);
    return;
  }
  const had = document.activeElement === btn;
  btn.disabled = true;
  const panel = await ruleSourcePanel(id);
  btn.disabled = false;
  host.append(panel);
  btn.setAttribute('aria-expanded', 'true');
  sourceWords(btn, true, about);
  if (had && focusFell() && btn.isConnected) btn.focus({ preventScroll: true });
}

/** The lines of a rule in policy.yaml, its own lines marked (the comment above
 *  it is context), or why they cannot be shown. */
async function ruleSourcePanel(id) {
  const got = await apiGetControl('policy/rules/source?id=' + encodeURIComponent(id));
  const r = got.ok && got.data && !got.data.error ? got.data : null;
  const panel = el('div', { class: 'rule-source' });
  if (!r) {
    // The cause in the own words of the page where it knows one, else the
    // status the dashboard server answered with; never the error of the server,
    // which is written for a developer (dashboard.md §4.25 *Empty states*).
    panel.append(el('p', { class: 'dim' }, 'policy.yaml could not be read. ',
      words(ownRefusal(got) || (got.ok ? 'The protection service may be unreachable.' : errorWords(got.status)))));
  } else if (!r.found) {
    panel.append(el('p', { class: 'dim', text: r.reason }));
  } else {
    const first = r.mark.length ? r.mark[0] : r.start;
    const last = r.mark.length ? r.mark[r.mark.length - 1] : r.start + r.lines.length - 1;
    panel.append(el('p', { class: 'rule-source-head' },
      (first === last ? 'Line ' + first : 'Lines ' + first + ' to ' + last) + ' of ',
      el('strong', { text: r.path ? shortPath(r.path) : 'policy.yaml' })));
    if (r.note) panel.append(el('p', { class: 'rule-source-warn', text: r.note }));
    const pre = el('pre', { class: 'rule-source-lines' });
    r.lines.forEach((text, i) => {
      const n = r.start + i;
      pre.append(el('span', { class: r.mark.includes(n) ? 'ln mark' : 'ln' },
        el('span', { class: 'ln-no', text: String(n) }),
        el('span', { class: 'ln-text', text: text || ' ' })));
    });
    panel.append(pre);
  }
  return panel;
}

function busyRow(row, on) {
  for (const b of row.querySelectorAll('button, select')) b.disabled = on;
}

/** A notice's words, and its Undo (Your rules' and each Settings card's).
 *  A notice stays until its card's next change, so a model removed and
 *  then a label saved leave two; until 2026-10-11 both buttons read "Undo",
 *  with no word of what each undoes. Its Undo is named by its card, its own
 *  word first, and described by the notice's words (dashboard.md §4.25 *A
 *  notice's Undo says which change it undoes*). */
function noticeWords(box, text) { return el('span', { id: box.id + '-words' }, words(text)); }
function noticeUndo(box, card, onclick) {
  return el('button', { type: 'button', class: 'btn small', text: 'Undo', 'aria-label': 'Undo the change in ' + card, 'aria-describedby': box.id + '-words', onclick });
}

/** Show what just changed above the list, with Undo when the change has one.
 *  Undo keeps the keyboard focus in Your rules (settingsPlace): its button
 *  gone, the block's heading. */
function rulesNotice(text, changeId) {
  const box = document.getElementById('rules-notice');
  clear(box);
  box.hidden = !text;
  if (!text) return;
  box.append(noticeWords(box, text));
  if (changeId) {
    box.append(noticeUndo(box, 'Your rules', async () => {
      const place = settingsPlace(box);
      for (const b of box.querySelectorAll('button')) b.disabled = true;
      const r = await apiPost('policy/changes/' + encodeURIComponent(changeId) + '/undo');
      if (!r.ok) { rulesNotice(refusalText(r, 'could not undo (' + r.status + ')'), null); settingsRefocus(place); return; }
      RULES_READS.wrote();
      rulesNotice('Undone.', null);
      await loadRules();
      settingsRefocus(place);
    }));
  }
}

/** A rule from your rules: remove it or flip it, here. The server plans the
 *  edit from the row; a change that loosens protection comes back asking
 *  for a confirmation, which is sent back as `expected`. The keyboard focus
 *  stays in Your rules as in a Settings card (settingsPlace): the row's menu,
 *  drawn again with its new effect; the block's heading once the row is
 *  gone; the menu or button pressed, described, after a refusal. */
async function changeRule(rule, action, row) {
  const place = settingsPlace(row);
  busyRow(row, true);
  const body = { id: rule.id, action };
  let r = await apiPost('policy/rules/change', body);
  if (r.ok && r.data && r.data.confirm) {
    const what = action === 'remove' ? 'Removing this rule' : action === 'allow' ? 'Always allowing this' : 'This change';
    if (!window.confirm(what + ' makes protection weaker for ' + rule.subject + '. Continue?')) { busyRow(row, false); settingsRefocus(place); return; }
    r = await apiPost('policy/rules/change', { ...body, expected: r.data.expected });
  }
  if (!r.ok || !r.data || !r.data.applied) {
    showAskError(row, changeRefusal(r, 'Not changed', 'could not change the rule (' + r.status + ')'));
    settingsRefocus(place, row);
    return;
  }
  RULES_READS.wrote();
  rulesNotice(action === 'remove' ? 'Rule removed.' : action === 'allow' ? 'Now always allowed.' : 'Now always blocked.', r.data.changeId);
  await loadRules();
  settingsRefocus(place);
}

async function answerAgain(id, approve, row, message = false) {
  const place = settingsPlace(row);
  busyRow(row, true);
  const r = await apiPost('egress/approvals/' + encodeURIComponent(id) + '/' + (approve ? 'approve' : 'deny'));
  if (!r.ok) { showAskError(row, refusalText(r, 'could not change the answer (' + r.status + ')')); settingsRefocus(place, row); return; }
  RULES_READS.wrote();
  // A session's answer to a held message says what goes to the AI (§4.25u).
  rulesNotice(message ? (approve ? 'Now sent as written for that session.' : 'Now sent masked for that session.') : approve ? 'Now always allowed.' : 'Now always blocked.', null);
  await loadRules();
  settingsRefocus(place);
  await loadHome();
}

/** Remove on a past answer: forget it, so your agent asks again next time.
 *  Never loosens anything, so there is no confirmation. */
async function forgetAnswer(id, row) {
  const place = settingsPlace(row);
  busyRow(row, true);
  const r = await apiPost('egress/approvals/' + encodeURIComponent(id) + '/forget');
  if (!r.ok) { showAskError(row, refusalText(r, 'could not remove the answer (' + r.status + ')')); settingsRefocus(place, row); return; }
  RULES_READS.wrote();
  rulesNotice('Answer removed. You will be asked again next time.', null);
  await loadRules();
  settingsRefocus(place);
}

// ── Who may get your secrets (dashboard.md §4.25aa, plan 13 §5.3) ───────────
// The file rules read the other way round, per program, per host and per AI,
// as the server projects them (view-model/rules-by-who.ts). Read only: a
// change is made in a file's menus under Your rules, and each file here
// opens its rule's row there (openRuleRow). The tab shown is a per-viewer
// convenience, kept in localStorage.
const BY_WHO_TABS = ['programs', 'hosts', 'models'];
const BY_WHO_KEY = 'mandu.rules.byWho';
const BY_WHO_EMPTY = 'No rule of yours makes a file secret yet.';
const BY_WHO_PARTIAL = 'Some rules made on this page could not be read, so these lists may miss files.';

function byWhoTab() {
  const v = S.byWhoTab || lsGet(BY_WHO_KEY);
  return BY_WHO_TABS.includes(v) ? v : 'programs';
}

function setByWhoTab(key, focus) {
  S.byWhoTab = key;
  lsSet(BY_WHO_KEY, key);
  renderByWho();
  if (focus) document.getElementById('by-who-tab-' + key).focus();
}

function renderByWho() {
  const block = document.getElementById('by-who-block');
  const v = S.byWho;
  // Unread, or an older server: nothing is shown, never "nothing" (the
  // Your rules card already says when the rules could not be read).
  if (!v || v.available !== true) { block.hidden = true; return; }
  block.hidden = false;
  const tab = byWhoTab();
  for (const key of BY_WHO_TABS) {
    const b = document.getElementById('by-who-tab-' + key);
    const on = key === tab;
    b.setAttribute('aria-selected', on ? 'true' : 'false');
    b.tabIndex = on ? 0 : -1;
    if (!b.dataset.wired) {
      b.dataset.wired = '1';
      b.addEventListener('click', () => setByWhoTab(key, false));
      b.addEventListener('keydown', (e) => {
        const i = BY_WHO_TABS.indexOf(byWhoTab());
        const to = e.key === 'ArrowRight' ? (i + 1) % BY_WHO_TABS.length
          : e.key === 'ArrowLeft' ? (i + BY_WHO_TABS.length - 1) % BY_WHO_TABS.length
          : e.key === 'Home' ? 0 : e.key === 'End' ? BY_WHO_TABS.length - 1 : -1;
        if (to < 0) return;
        e.preventDefault();
        setByWhoTab(BY_WHO_TABS[to], true);
      });
    }
  }
  const list = document.getElementById('by-who-list');
  list.setAttribute('aria-labelledby', 'by-who-tab-' + tab);
  clear(list);
  const t = v[tab] || { rows: [], note: '' };
  if (!t.rows.length) list.append(el('div', { class: 'empty', text: BY_WHO_EMPTY }));
  else list.append(el('div', { class: 'table by-who-rows', role: 'list' }, ...t.rows.map((r) => byWhoRow(r, tab))));
  const note = document.getElementById('by-who-note');
  note.textContent = [v.partial ? BY_WHO_PARTIAL : '', t.note || ''].filter(Boolean).join(' ');
}

/** One program, host or AI: its name (a long one cut as longName cuts
 *  it), and each list of files under a coloured mark saying what it may do
 *  with them. */
function byWhoRow(r, tab) {
  const plain = r.kind === 'any' || tab === 'models';
  const name = el('div', { class: 'by-who-name' },
    plain ? el('strong', { text: r.name }) : longName(el('code', { class: 'by-who-subject', text: r.name })),
    r.about ? el('p', { class: 'by-who-about', text: r.about }) : null);
  const groups = el('div', { class: 'by-who-groups' });
  for (const g of r.groups) {
    const items = el('ul', { class: 'by-who-items' });
    for (const it of g.items) {
      // "~/.ssh and everything inside (checked by Mandu)", as the Opens it line words a program.
      const more = [it.reach, it.how ? '(' + it.how + ')' : null].filter(Boolean).join(' ');
      const chip = longName(el('code', { text: it.path }));
      // A file whose rule has a row in the tree drawn now opens it; any
      // other stays plain code, so nothing points to a row that is not there.
      const file = treeRule(it.rule) ? el('button', {
        type: 'button', class: 'link-btn by-who-link', 'aria-label': 'Show the rule for ' + it.path + ' in Your rules',
        onclick: () => openRuleRow(it.rule),
      }, chip) : chip;
      items.append(el('li', null, file, more ? el('span', { class: 'by-who-more', text: ' ' + more }) : null));
    }
    groups.append(el('div', { class: 'by-who-group' },
      el('span', { class: 'by-who-label' }, el('span', { class: 'dot ' + (g.tone || 'bad'), 'aria-hidden': 'true' }), g.label),
      items));
  }
  if (!r.groups.length) groups.append(el('span', { class: 'by-who-none', text: 'Nothing under your rules.' }));
  return el('div', { class: 'row by-who-row' + (r.kind === 'any' ? ' any' : ''), role: 'listitem' }, name, groups);
}

/** The row of Your rules for a rule's own path (a by-who item's `rule`), or
 *  null. policy.yaml's comes first, as the by-who read keeps it. */
function treeRule(path) {
  return (typeof path === 'string' && F.rules.find((r) => r.path === path)) || null;
}

/** A file under Who may get your secrets, pressed: its rule's row under
 *  Your rules opens, as a click on its name does, with the folders above it
 *  unfolded; afterToggle scrolls it into view (clear of Changes to save, the
 *  window's scroll padding) and puts the focus on its ⋯. */
function openRuleRow(path) {
  const r = treeRule(path);
  // Gone since the card was drawn: the card is drawn again, plain.
  if (!r) { renderByWho(); return; }
  // A Find a rule text that would hide the row is emptied first (§4.25f
  // *Find a rule*): the jump never lands on nothing.
  if (!ruleMatches(r, findText())) clearRuleFind(true);
  const shown = shortPath(r.path);
  for (const full of [...F.folded]) if (shown.startsWith(full + '/')) F.folded.delete(full);
  F.rule = ruleKey(r);
  renderLabeled();
  afterToggle('#files-tree', r.path);
}

// ── Files and folders: the file explorer (dashboard.md §4.25m, §4.25n, §4.25p)
// Two views of one explorer. Labeled: the files and folders with a rule of
// yours, as a tree (fileTree), patterns first. All files: one folder at a
// time, each entry with the label a read gets today and where it came from
// (GET files/list), folders marked when rules sit inside. The labels are
// columns (§4.25p): each row has one dot per label, in the glossary's order,
// and the hosts it may still be sent to. A click on a dot waits as a pending
// change (kept in this browser across a reload) with what it would do to the
// files under it (POST files/impact), and Save sends them as ONE change (POST
// files/labels, Undo under Rule changes in Approvals). A change that makes protection weaker comes
// back asking, naming the files it reaches, and is saved only after the
// person has seen exactly that. A click on a name opens a row under it: where
// the label comes from, what the rules say about it (GET files/why), its
// policy.yaml lines and the hosts to edit. Ticked rows are labeled together
// from the bar under the list. A typed path, a file that does not exist yet,
// or a pattern gets a row too; a pattern shows which files it would decide.
const F = {
  view: 'labeled',     // 'labeled' | 'all'
  rules: [],           // the file rules of yours (renderRules rows with a path)
  rule: null,          // the rule opened in Labeled (ruleKey)
  open: null,          // the entry opened in All files (its path)
  path: null,          // the folder shown in All files (absolute)
  data: null,          // the last answer for it
  entries: [],         // its entries so far (pages are appended)
  moreFailure: null,   // why its last Show more read nothing, as parts (moreRefusal); a listing drops it
  selected: new Map(), // path → { path, display, kind, label, target }: ticked
  pending: new Map(),  // path → { path, display, level, bindings, recursive, file, before, target }
  expected: null,      // what the person was shown, while a weaker change waits
  seq: 0,              // the newest listing asked for; older answers are dropped
  answered: 0,         // the newest listing answered (seq): below seq, one is on its way
  // The folder shown has no labels, or its listing got no answer: 'new',
  // read again by the next Home poll that answers; 'again', still so when
  // read again, so only a return reads it (readFolderAgain); false: read.
  unread: false,
  listing: null,       // the listing Add a rule opened with, while it is read
  impactSeq: 0,        // the newest impact asked for
  names: new Map(),    // folder → { entries, more }: its entries read so far, for Tab completion
  typed: null,         // a typed file, missing path or pattern shown above the list
  why: new Map(),      // path → what files/why said, for the opened row
  folded: new Set(),   // the folder headings of the Labeled tree folded shut
  started: false,      // the explorer was set up on this page load
  unreadCause: false,  // the cause Your rules said it could not be read with; false: read
};
const FILES_VIEW_KEY = 'mandu.files.view';
const FILES_LAST_KEY = 'mandu.files.folder';
const FILES_HIDDEN_KEY = 'mandu.files.hidden';
const FILES_PENDING_KEY = 'mandu.files.pending';
const SUGG_OPEN_KEY = 'mandu.files.suggested';
// A pattern (such as **/.env) rather than a path: chosen as typed, never listed.
const GLOB_RE = /[*?[]/;

/** One column per label, in the order of the glossary (strictest first): a
 *  short name on the column and on the buttons of the bar under the list, the
 *  term and sentence of the glossary in their tooltips (the same words,
 *  checked by policy-panel.test). */
const LEVEL_BUTTONS = [
  { level: 'no-model', icon: 'eyeOff', text: 'No AI', cls: 'strict',
    term: 'No AI', meaning: 'Every AI sees it masked, Mandu\'s helper included, and your OK does not change that. Only the programs allowed to open it get the real file: ssh, and programs you name, never a database shell. It is sent only where a rule or your OK allows.' },
  { level: 'local-model', icon: 'monitor', text: 'Your own AI only', cls: 'local-only',
    term: 'Your own AI only', meaning: 'Only your own AI may read it, when it asks: one you or your organization run, on this computer or your organization\'s network, listed in Settings › Models. Any other AI sees it masked, and your OK does not change that. It is sent only where a rule or your OK allows.' },
  { level: 'any-model', icon: 'eye', text: 'Any AI, when it asks', cls: 'model-ok',
    term: 'Any AI, when it asks', meaning: 'The AI first sees it masked. When it needs the contents, Mandu\'s helper reads them for it, or the AI reads them itself. Each read is logged, and your AI provider gets what is read. It is sent only where a rule or your OK allows.' },
  { level: 'public', icon: 'unlock', text: 'Not secret', cls: 'public',
    term: 'Not secret', meaning: 'Treated like any other file, even if it looks like a secret (a test .env, for example).' },
];

function lsGet(k) { try { return localStorage.getItem(k); } catch { return null; } }
/** Store `v`; false where this browser keeps nothing (a private window). */
function lsSet(k, v) { try { localStorage.setItem(k, v); return true; } catch { /* private window: not remembered */ return false; } }
function lsDel(k) { try { localStorage.removeItem(k); } catch { /* private window */ } }

/** A GET that carries the page's control header (the listing is served only
 *  to this page, dashboard.md §4.25m). */
async function apiGetControl(path) {
  return answerOf(path, { headers: { ...FRONT, 'X-Mandu-Control': '1' } });
}

/** A level in the glossary's words. */
function levelText(level, bindings) {
  if (level === null) return 'No rule of its own';
  const base = level === 'public' ? 'Not secret'
    : level === 'any-model' ? 'Any AI, when it asks'
    : level === 'local-model' ? 'Your own AI only'
    : 'No AI';
  const to = (bindings || []).filter(Boolean);
  return to.length && level !== 'public' ? base + '; may be sent to ' + to.join(', ') : base;
}
/** levelText as parts, each host a code (as the server sends levelParts). */
function levelParts(level, bindings) {
  const to = (bindings || []).filter(Boolean);
  if (!to.length || level === null || level === 'public') return [{ kind: 'text', text: levelText(level, bindings) }];
  const out = [{ kind: 'text', text: levelText(level, []) + '; may be sent to ' }];
  to.forEach((h, i) => out.push(...(i ? [{ kind: 'text', text: ', ' }] : []), { kind: 'code', text: h }));
  return out;
}
/** levelText with each host a fitName, so a change waiting to be saved
 *  never breaks a short host (dashboard.md §4.25u, *A waiting change names
 *  each host*). The text is levelText. */
function levelNodes(level, bindings) {
  return fitWords(levelParts(level, bindings), levelText(level, bindings));
}
/** A change waiting, as its line under a name says it. */
function willBe(p) {
  return ['Will be: ', levelNodes(p.level, p.bindings), ' (not saved)'];
}
/** The label a waiting change replaces (`before`, its words when queued),
 *  with each host a nameCode when those words are its level and hosts;
 *  else the words as written (a change kept from an older page). */
function beforeNodes(p) {
  if (p.beforeLevel !== undefined && Array.isArray(p.beforeHosts) && levelText(p.beforeLevel, p.beforeHosts) === p.before) return levelNodes(p.beforeLevel, p.beforeHosts);
  return document.createTextNode(p.before);
}
function chipClass(level) {
  return level === 'public' ? 'public' : level === 'any-model' ? 'model-ok' : level === 'local-model' ? 'local-only' : 'strict';
}
function labelChip(l) {
  return el('span', { class: 'label-chip ' + (l.source === 'none' ? 'none' : chipClass(l.level)), text: l.words });
}
/** A label made on this page before rules lived in policy.yaml, as a level. */
function pageLabelLevel(l) {
  return l.levelClass === 'public' ? 'public' : l.modelOk ? 'any-model' : l.levelClass === 'local-only' ? 'local-model' : 'no-model';
}

/** `text`: one sentence (words), or the parts of one (cannotCheck). */
function filesNote(text) {
  const note = document.getElementById('files-note');
  if (Array.isArray(text)) { clear(note); note.append(...text); } else setWords(note, text || '');
  note.hidden = !text;
}
/** The note over a folder whose labels could not be read: a stopped
 *  protection service in the words of the page, with the link to its Start,
 *  never the socket the route could not dial; any other cause as the
 *  server wrote it. */
function labelsUnknownNote(d) {
  const error = d.labelError || 'the protection service did not answer';
  if (UNREACHABLE_REFUSAL.test(error)) return [...cannotCheck('Labels could not be read.', 'down', true), ' You can still choose rules.'];
  return 'Labels could not be read: ' + error + '. You can still choose rules.';
}

/** Where to start: the last folder shown, else the newest agent's folder, else home. */
function filesStart() {
  const last = lsGet(FILES_LAST_KEY);
  if (last) return last;
  const cwd = ((S.home && S.home.agents) || []).map((a) => a.cwd).find(Boolean);
  return cwd || '~';
}

function parentOf(p) {
  const cut = p.replace(/\/+$/, '').lastIndexOf('/');
  return cut <= 0 ? '/' : p.slice(0, cut);
}
function baseName(p) {
  const t = p.replace(/\/+$/, '');
  return t.slice(t.lastIndexOf('/') + 1) || t;
}

/** The explorer's panels (dashboard.md §4.25n): 'all' opens Add a rule (the
 *  file browser), 'labeled' closes it, 'suggested' opens Keys Mandu found.
 *  `at` opens a folder with one entry picked; without it, the browser opens
 *  where it was (or where to start), unless `stay`. */
function setFilesView(view, at, stay) {
  if (view === 'suggested') { setSuggestedOpen(true); return; }
  F.view = view;
  lsSet(FILES_VIEW_KEY, view);
  const open = view === 'all';
  document.getElementById('lock-form').hidden = !open;
  document.getElementById('rules-add').setAttribute('aria-expanded', open ? 'true' : 'false');
  if (open) {
    renderFileStarts();
    renderFileSelection();
    if (at) {
      // `at.by`: the button pressed; with the focus, it follows (focusPicked).
      const by = at.by && document.activeElement === at.by ? at.by : null;
      const read = openFolder(at.folder, { pick: at.pick || null });
      if (by) read.then(() => focusPicked(by));
      const panel = document.getElementById('lock-form');
      if (panel.scrollIntoView) panel.scrollIntoView({ block: 'start' });
    } else if (!F.data && !stay) {
      F.listing = openFolder(filesStart()).then((d) => (!d && !F.data ? openFolder('~') : null));
    }
  }
}

/** Show in its folder, Show in the file browser: the page scrolls to the
 *  browser with the file's row opened, and the keyboard focus follows, to
 *  that row's ⋯, else (the file is not listed) the path box. Until
 *  2026-10-11 it stayed on the button, out of view, and the next Tab went on
 *  from there. Only if the button pressed had the focus and keeps it, or
 *  it fell; a press without the focus moves nothing. */
function focusPicked(by) {
  if (document.activeElement !== by && !focusFell()) return;
  const row = F.open && [...document.querySelectorAll('#files-list .row.file')].find((x) => x.getAttribute('data-path') === F.open);
  const to = (row && row.querySelector('.file-more')) || document.getElementById('lock-path');
  if (to && !to.closest('[hidden]')) to.focus({ preventScroll: true });
}

/** Open or close Keys Mandu found. Once opened, its ticked rows wait in
 *  Changes to save (G.shown), also after it is closed again. */
function setSuggestedOpen(open) {
  G.open = open ? G.open : null;
  lsSet(SUGG_OPEN_KEY, open ? '1' : '0');
  document.getElementById('files-suggested-view').hidden = !open;
  const btn = document.getElementById('suggest-open');
  btn.setAttribute('aria-expanded', open ? 'true' : 'false');
  btn.textContent = open ? 'Close' : 'Review';
  if (!open) return;
  G.shown = true;
  renderSuggested();
  renderPending();
  loadSuggestions();
}

/** `opts.again`: the folder shown, read again where it stands
 *  (readFolderAgain): what was typed, ticked and opened stays; with
 *  `opts.upTo`, as far as it was shown (pagesUpTo). `opts.pick`: an entry
 *  to open once its folder is shown (Go to a file, Show in its folder).
 *  The pick is this read's own: a read overtaken (another folder, Show
 *  more) or refused leaves none behind. Until 2026-10-15 it waited in the
 *  page's state for the next listing of its folder, which opened that row
 *  unasked and read the folder on to it. */
async function openFolder(path, opts = {}) {
  const seq = ++F.seq;
  const pick = opts.pick || null;
  const r = await apiGetControl('files/list?path=' + encodeURIComponent(path));
  if (seq !== F.seq) return null;
  if (!r.ok) {
    F.answered = seq;
    const d = r.data || {};
    if (d.file && d.path) {
      // A file: show its folder with the file opened.
      return openFolder(parentOf(d.path), { keepTyped: true, pick: d.path });
    }
    if (r.status === 404 && opts.typed) {
      // Not there yet: it can still be given a rule.
      showTyped({ path: d.path || path, kind: 'missing' });
      return null;
    }
    filesNote(refusalText(r, 'The folder could not be opened (' + r.status + ').'));
    // No answer, or an error of the server rather than of the folder: read
    // again when the dashboard or the service is back.
    F.unread = r.status === 0 || r.status >= 500 ? (opts.again ? 'again' : 'new') : false;
    return null;
  }
  // A picked entry past the first page: the pages down to the one it is on.
  const shown = opts.upTo ? await pagesUpTo(r.data, opts.upTo, seq)
    : pickAhead(r.data, pick) ? await pagesUpTo(r.data, NAMES_MAX, seq, pick)
    : { data: r.data, failure: null };
  if (!shown) return null;
  F.answered = seq;
  const first = !F.path;
  F.path = r.data.path;
  F.data = shown.data;
  F.entries = shown.data.entries;
  F.moreFailure = shown.failure;
  F.names.set(r.data.path, { entries: F.entries, more: !!F.data.more });
  F.unread = shown.data.labels === 'unknown' ? (opts.again ? 'again' : 'new') : false;
  if (opts.again) {
    // The ticked rows keep their tick, with what the new listing says of
    // them; the opened row stays open while it is listed or typed.
    for (const p of F.selected.keys()) {
      const e = F.entries.find((x) => x.path === p);
      if (e) F.selected.set(p, e);
    }
    if (F.open && !(F.typed && F.typed.path === F.open) && !F.entries.some((x) => x.path === F.open)) F.open = null;
  } else {
    if (!opts.keepTyped) F.typed = null;
    F.selected.clear();
    if (!F.typed) F.open = null;
  }
  if (pick) {
    const e = pickedEntry(F.entries, pick);
    if (e) F.open = e.path;
  }
  lsSet(FILES_LAST_KEY, r.data.path);
  // Read again, the path box keeps what may have been typed in it since.
  if (!opts.again || first) document.getElementById('lock-path').value = r.data.display === '~' ? '~/' : r.data.display + '/';
  const typing = opts.again ? keepTyping() : null;
  renderFiles();
  if (typing) typing();
  if (pick) {
    const row = document.querySelector('#files-list .row.file.open');
    if (row && row.scrollIntoView) row.scrollIntoView({ block: 'nearest' });
  }
  if (opts.focus) focusRow(0);
  return r.data;
}

/** A folder read again where it stands reads as far as it was shown: after
 *  its first page (`data`), the next ones, a page at a time, until it has
 *  `upTo` entries or the folder ends, so the rows a Show more brought stay,
 *  with a row opened among them and the focus. Labels that one page could
 *  not read are unknown for the folder. A page that fails leaves the pages
 *  read, and says why over Show more, as a failed Show more does
 *  (moreRefusal). Null: a newer listing was asked meanwhile. Until
 *  2026-10-15 it read the first page only, so the rows past it went.
 *  With `pick`, a folder opened with an entry picked (Go to a file, Show in
 *  its folder) reads on only while the pick is ahead (pickAhead). */
async function pagesUpTo(data, upTo, seq, pick = null) {
  let at = data.entries.length;
  let unknown = data.labels === 'unknown' ? data : null;
  let failure = null;
  while (data.more && at < upTo && (!pick || pickAhead(data, pick))) {
    const r = await apiGetControl('files/list?path=' + encodeURIComponent(data.path) + '&offset=' + at);
    if (seq !== F.seq) return null;
    if (!r.ok) { failure = moreRefusal(r); break; }
    if (!r.data.entries.length) break;
    at += r.data.entries.length;
    if (!unknown && r.data.labels === 'unknown') unknown = r.data;
    // A folder that changed between two pages may list an entry twice.
    const seen = new Set(data.entries.map((e) => e.path));
    data = { ...r.data, entries: data.entries.concat(r.data.entries.filter((e) => !seen.has(e.path))) };
  }
  if (unknown && data.labels !== 'unknown') data = { ...data, labels: 'unknown', labelError: unknown.labelError };
  return { data, failure };
}

/** The entry a pick names among `entries`: its absolute path, or as
 *  written with ~ (a rule's path). */
function pickedEntry(entries, pick) {
  return entries.find((x) => x.path === pick || x.display === pick.replace(/\/+$/, ''));
}

/** Is a picked entry on a page of `data`'s folder not read yet? Only a
 *  pick in this folder (its path, or its ~ spelling, as the listing writes
 *  them) and not among the entries read. The listing is in order,
 *  folders first and then by name (§4.25m *Browsing*): after a file whose
 *  name sorts after the pick's, it cannot follow (unreadMayMatch). Until
 *  2026-10-15 the pick was looked for on the first page only, so a file
 *  past it was not opened and stayed behind Show more. */
function pickAhead(data, pick) {
  if (!pick || !data.more) return false;
  const dir = parentOf(pick);
  if (dir !== data.path && dir !== data.display) return false;
  if (pickedEntry(data.entries, pick)) return false;
  const last = data.entries[data.entries.length - 1];
  return !last || last.kind === 'dir' || last.name < baseName(pick);
}

/** The folder shown is unread (F.unread): its labels could not be read, or
 *  its listing got no answer. A return (readAgainUnread), or the next Home
 *  poll that answers after the browser's own read failed (an outage too
 *  short for the poll to see), reads it again once, where it stands and as
 *  far as it was shown (pagesUpTo); a browser that never showed a folder
 *  opens where it starts. A "What the rules say" that could not be read
 *  asks again. A listing on its way (a folder you just opened, or the
 *  pages of one read again) is never overtaken. */
function readFolderAgain() {
  if (F.answered !== F.seq) return;
  for (const [p, st] of F.why) if (st.error) F.why.delete(p);
  if (F.path) openFolder(F.path, { again: true, upTo: F.entries.length });
  else F.listing = openFolder(filesStart(), { again: true }).then((d) => (!d && !F.data ? openFolder('~', { again: true }) : null));
}

/** What is typed in the browser's own fields (an opened row's hosts, the
 *  hosts for the ticked rows) and which of them has the focus, put back
 *  after a redraw nobody asked for (readFolderAgain). */
function keepTyping() {
  const fields = [...document.querySelectorAll('#files-list input[type=text], #files-selected input[type=text]')].map((i) => ({
    id: i.id, path: i.getAttribute('data-path'), value: i.value,
    focused: document.activeElement === i, start: i.selectionStart, end: i.selectionEnd,
  }));
  return () => {
    for (const f of fields) {
      const i = f.id && document.getElementById(f.id);
      if (!i || i.getAttribute('data-path') !== f.path) continue;
      i.value = f.value;
      if (f.focused) { i.focus(); i.setSelectionRange(f.start, f.end); }
    }
  };
}

/** Show more under a folder's first page (dashboard.md §4.25m): the next
 *  page, whose first entry then takes the focus, as a Show more or a Show
 *  them gives it to what it brought (§4.25ad). A read that fails says why
 *  over the button, which stays to try again and gets the focus back. Both
 *  only when the focus fell with the redraw: one the person moved stays.
 *  Until 2026-10-15 a failed read said nothing, and an answered one left
 *  the focus on the page (<body>). */
async function moreFiles() {
  if (!F.data || !F.data.more) return;
  const seq = ++F.seq;
  const r = await apiGetControl('files/list?path=' + encodeURIComponent(F.path) + '&offset=' + F.entries.length);
  if (seq !== F.seq) return;
  F.answered = seq;
  if (!r.ok) {
    F.moreFailure = moreRefusal(r);
    renderFiles();
    const again = document.querySelector('#files-list .files-more');
    if (again && focusFell()) again.focus({ preventScroll: true });
    return;
  }
  F.moreFailure = null;
  // Compared as values, never spliced into a selector: paths are server data.
  const fresh = new Set(r.data.entries.map((e) => e.path));
  F.entries = F.entries.concat(r.data.entries);
  F.data = { ...r.data, entries: F.entries };
  F.names.set(F.path, { entries: F.entries, more: !!r.data.more });
  if (!F.unread && r.data.labels === 'unknown') F.unread = 'new';
  renderFiles();
  if (!focusFell()) return;
  // The filter may hide all it brought: then Show more again, else the last row.
  const first = listRows().findIndex((x) => fresh.has(x.getAttribute('data-path')));
  const again = document.querySelector('#files-list .files-more');
  if (first >= 0) focusRow(first);
  else if (again) again.focus();
  else focusRow(listRows().length - 1);
}
/** Why a Show more read nothing, as parts each drawn with words(): an error
 *  the server worded after a colon, as a typed pattern's row says it
 *  (patternRefusal), else the page's own words for the cause. */
function moreRefusal(r) {
  const lead = 'Could not read more of this folder';
  const why = refusalText(r, errorWords(r.status));
  if (why === (r.data && r.data.error)) return [lead + ': ' + (/[.!?]$/.test(why) ? why : why + '.')];
  return [lead + '.', why];
}

function showTyped(t) {
  const display = shortPath(t.path);
  F.typed = { path: t.path, display, kind: t.kind, label: null, target: null, preview: null };
  // Opened, so what it would decide and its hosts are in view.
  F.open = t.path;
  renderFiles();
  if (t.kind === 'pattern') previewPattern(F.typed);
}

/** Which files a typed pattern would decide, under the folder shown. */
async function previewPattern(typed) {
  const r = await apiPost('files/impact', { changes: [{ path: typed.path, level: 'no-model' }], folder: F.path || '~' });
  if (F.typed !== typed) return;
  const impact = r.ok && r.data ? r.data.impact : null;
  typed.preview = impact ? [patternLine(impact)] : patternRefusal(r, typed);
  renderFiles();
}

/** "Decides 3 files under this folder: a, b, c" from an impact answer. */
function patternLine(impact) {
  let count = 0;
  const sample = [];
  for (const [via, d] of Object.entries(impact.decidedBy || {})) {
    if (!GLOB_RE.test(via)) continue;
    count += d.count;
    for (const s of d.sample) if (sample.length < 5) sample.push(s);
  }
  const where = 'under ' + (F.data ? F.data.display : 'this folder') + (impact.truncated ? ' (checked the first ' + impact.scanned + ' files)' : '');
  return count === 0 ? 'Matches no file ' + where + ' yet.'
    : 'Matches ' + n(count, 'file', 'files') + ' ' + where + ': ' + sample.join(', ') + (count > sample.length ? ', …' : '');
}

/** The pending change for a path, by how it is shown (a rule is written with
 *  ~, a listed entry is absolute: both show the same). */
function pendingFor(t) {
  for (const p of F.pending.values()) if (p.path === t.path || p.display === t.display) return p;
  return null;
}

/** The lines under a name: where the label comes from, a link's file, and
 *  the change waiting. The label itself is the row's dots (§4.25p). */
function fileSub(entry) {
  const out = [];
  const p = pendingFor(entry);
  const l = entry.label;
  if (l) {
    if (l.from) out.push(el('div', { class: 'dim file-from', text: l.from, title: l.via || '' }));
  } else if (entry.kind === 'missing' || entry.kind === 'pattern') {
    out.push(el('div', { class: 'dim file-from', text: entry.kind === 'pattern' ? 'Every file that matches' : 'Not there yet' }));
    if (entry.preview) out.push(el('div', { class: 'dim file-from' }, ...previewNodes(entry.preview)));
  } else {
    out.push(el('div', {}, el('span', { class: 'label-chip unknown', text: 'Label unknown' })));
  }
  if (entry.targetLabel) {
    // A symlink whose file is labeled differently: say so, the rule on one
    // spelling alone does not cover the other.
    out.push(el('div', { class: 'file-link-note' }, 'The file it points to: ', labelChip(entry.targetLabel)));
  }
  if (p) out.push(el('div', { class: 'file-pending' }, ...willBe(p)));
  return out;
}

/** What each box's row says itself (whyBox's `said`). */
const WHY_SAID = new WeakMap();
/** What the rules say about one path (GET files/why), in its opened row.
 *  Asked once per path; a save or a new folder forgets the answers.
 *  `said`: the warnings its row already says in full (§4.25p, *A warning
 *  is said once*); kept with the box, so its redraws leave them out too. */
function whyBox(path, said) {
  let st = F.why.get(path);
  if (!st) {
    st = { loading: true };
    F.why.set(path, st);
    loadWhy(path);
  }
  const box = whyPanel(st, said);
  box.setAttribute('data-path', path);
  box.prepend(el('div', { class: 'detail-cap', text: 'What the rules say' }));
  if (said && said.length) WHY_SAID.set(box, said);
  return box;
}
/** A return (readAgainUnread): each "What the rules say" that could not be
 *  read asks again, in its open box; a closed row asks when opened. */
function readWhyAgain() {
  for (const [p, st] of F.why) if (st.error) F.why.delete(p);
  for (const box of document.querySelectorAll('.file-why[data-path]')) {
    const p = box.getAttribute('data-path');
    if (!F.why.has(p)) box.replaceWith(whyBox(p, WHY_SAID.get(box)));
  }
}
async function loadWhy(path) {
  const r = await apiGetControl('files/why?path=' + encodeURIComponent(path)).catch(() => null);
  if (!F.why.has(path)) return;
  F.why.set(path, r && r.ok && r.data && r.data.why ? { why: r.data.why } : { error: refusalText(r, 'Could not be read' + (r ? ' (' + r.status + ')' : '') + '.') });
  // Only the box is redrawn: hosts being typed in the same row stay.
  for (const box of document.querySelectorAll('.file-why')) {
    if (box.getAttribute('data-path') === path) box.replaceWith(whyBox(path, WHY_SAID.get(box)));
  }
}

function whyPanel(state, said) {
  const box = el('div', { class: 'file-why', role: 'region', 'aria-label': 'What the rules say' });
  if (state.loading) { box.append(el('span', { class: 'dim', text: 'Reading the rules…' })); return box; }
  if (state.error) { box.append(el('span', { class: 'ask-error' }, words(state.error))); return box; }
  const w = state.why;
  if (w.off) box.append(el('p', { class: 'dim', text: 'Protection is off, so none of this is enforced now.' }));
  const dl = el('dl');
  // A warning its row already says, word for word, is not said again; a
  // different one (another judgment of the same readers) still is.
  const lines = w.lines.filter((line) => !(line.term === 'Warning' && (said || []).some((s) => s.includes(line.text))));
  // A line naming hosts comes as parts too: each host a name kept whole
  // (§4.25u, *Rules names each host*); without them, its text as written.
  for (const line of lines) dl.append(el('dt', { text: line.term }), el('dd', {}, askCellWords(line.parts, line.text)));
  if (!w.lines.length) dl.append(el('dt', { text: 'Rules' }), el('dd', { text: 'No rule and no built-in secret covers it.' }));
  box.append(dl);
  return box;
}

// ── The label columns (dashboard.md §4.25p) ─────────────────────────────────
// A row decides on a target: an entry of All files, a typed path, or one of
// your rules in Labeled (shaped like an entry by ruleTarget).

/** Set in policy.yaml: changed there, not on this page. */
function isLocked(t) { return !!(t.rule && !t.rule.editable); }

/** How a row's dots read: the level the person's own rule on exactly this
 *  target sets (a solid dot), the level it gets from anywhere else, such as a
 *  folder, a pattern or a built-in secret (a ring), and the change waiting
 *  (undefined when none; null for a removal). */
function dotState(t) {
  const p = pendingFor(t);
  const l = t.label;
  const mine = l && l.source === 'yours' ? l.level : null;
  const from = l && mine === null && l.source !== 'none' ? l.level : null;
  return { mine, from, waiting: p ? p.level : undefined };
}

function splitHosts(v) { return v.split(',').map((x) => x.trim()).filter(Boolean); }
function sameHosts(a, b) { return a.length === b.length && a.every((h, i) => h === b[i]); }

/** The hosts of the change waiting, else of the person's own rule (one set
 *  in the rules file too). */
function currentHosts(t) {
  const p = pendingFor(t);
  if (p && p.level !== null && p.level !== 'public') return p.bindings || [];
  return t.label && t.label.source === 'yours' ? (t.label.bindings || []) : [];
}

/** The hosts a secret label chosen for the target gets: the ones typed in
 *  its opened row, else those it has now. Not secret has none. */
function hostsFor(t, level) {
  if (level === null || level === 'public') return [];
  const box = document.getElementById('lock-to');
  if (box && box.getAttribute('data-path') === t.path) return splitHosts(box.value);
  return currentHosts(t);
}

/** A click on a label's dot: that label waits in Changes to save. Choosing
 *  again what the person's own rule already says drops the waiting change. */
function chooseLevel(t, level) {
  const own = t.label && t.label.removable ? t.label : null;
  const hosts = hostsFor(t, level);
  if (own && own.level === level && sameHosts(hosts, level === 'public' ? [] : (own.bindings || []))) {
    const p = pendingFor(t);
    if (p) { F.pending.delete(p.path); pendingChanged(); }
    return;
  }
  queueChanges(level, hosts, [t]);
}

/** A row's label: ONE menu with the four labels (dashboard.md §4.25p). It
 *  shows the change waiting, else the person's own rule on exactly this
 *  target, else "No rule" with the label it gets from elsewhere (a folder, a
 *  pattern, a built-in secret). Choosing waits in Changes to save; "Remove
 *  my rule" queues the removal of the person's own rule. */
function labelPick(t) {
  const st = dotState(t);
  const shown = st.waiting !== undefined ? st.waiting : st.mine;
  const ownModel = hasOwnModel(S.panel);
  const own = st.mine !== null || !!(t.label && t.label.removable);
  const sel = el('select', { class: 'label-select', 'aria-label': 'Which AI may read ' + t.display });
  const from = st.from !== null ? LEVEL_BUTTONS.find((b) => b.level === st.from) : null;
  sel.append(el('option', { value: '', text: own ? 'Remove my rule' : from ? from.text + ' (inherited)' : 'No rule' }));
  for (const b of LEVEL_BUTTONS) {
    const off = b.level === 'local-model' && !ownModel;
    sel.append(el('option', { value: b.level, text: b.text + (off ? ' (none listed)' : ''), title: b.term + '. ' + b.meaning, disabled: off }));
  }
  sel.value = shown === null ? '' : shown;
  sel.disabled = isLocked(t);
  sel.addEventListener('change', () => {
    if (sel.value) { chooseLevel(t, sel.value); return; }
    if (own || t.kind === 'pattern') { queueChanges(null, [], [t]); return; }
    const p = pendingFor(t);
    if (p) { F.pending.delete(p.path); pendingChanged(); }
  });
  // No rule of its own: the dot is a ring in the color of what it inherits.
  const level = shown !== null ? shown : 'none';
  return el('span', { class: 'label-pick' + (st.waiting !== undefined ? ' waiting' : ''), 'data-level': level, 'data-from': shown === null && from ? from.level : null },
    el('span', { class: 'label-dot', 'aria-hidden': 'true' }), sel);
}

/** The second question of a label (dashboard.md §4.25p, two questions):
 *  where the real value may be sent. Its choices: Needs your OK, Listed
 *  hosts without asking (the hosts as chips; Edit, or choosing it, opens the
 *  row with the hosts field), or Not secret, the one point where both
 *  questions are open, so it is the first menu's Not secret too. A label
 *  from elsewhere shows greyed with its hosts, its choice whole (no
 *  "(inherited)": the ring, the grey and the first menu say so) and its
 *  rule in its tooltip and name (inheritedSend); a target with no label at
 *  all has nothing to send. */
const SEND_CHOICES = [
  { value: 'ask', text: 'Needs your OK', term: 'Needs your OK' },
  { value: 'hosts', text: 'Listed hosts without asking', term: 'Listed hosts without asking' },
  { value: 'public', text: 'Not secret', term: 'Not secret' },
];
function sendPick(t, open) {
  const cell = el('div', { class: 'file-hosts' });
  const st = dotState(t);
  const own = st.waiting !== undefined ? st.waiting : st.mine;
  const level = own !== null ? own : st.from;
  if (perValue(t, level)) return perValuePick(cell, t, st, own);
  const hosts = own !== null ? currentHosts(t) : ((t.label && t.label.bindings) || []);
  const mode = level === null ? '' : level === 'public' ? 'public' : hosts.length ? 'hosts' : 'ask';
  const sel = el('select', { class: 'label-select send-select', 'aria-label': 'Where ' + t.display + ' may be sent' });
  if (level === null) sel.append(el('option', { value: '', text: 'No rule' }));
  for (const c of SEND_CHOICES) {
    const g = LEVEL_BUTTONS.find((b) => b.term === c.term);
    sel.append(el('option', { value: c.value, text: c.text, title: g ? g.term + '. ' + g.meaning : sendMeaning(c.value) }));
  }
  sel.value = mode;
  if (own === null && level !== null) {
    const source = t.label && t.label.source;
    const words = inheritedSend(t, (SEND_CHOICES.find((c) => c.value === mode) || {}).text || '', source === 'inherited' || source === 'pattern' ? 'Change it there.' : '');
    sel.setAttribute('aria-label', words);
    sel.title = words;
  }
  // A choice here changes a rule of the person's own: with none, the first
  // menu is where a label starts.
  sel.disabled = isLocked(t) || own === null;
  sel.addEventListener('change', () => chooseSend(t, own, sel.value, open));
  cell.append(el('span', { class: 'label-pick send-pick' + (st.waiting !== undefined ? ' waiting' : ''), 'data-send': mode || 'none', 'data-from': own === null && level !== null ? mode : null },
    el('span', { class: 'label-dot', 'aria-hidden': 'true' }), sel));
  if (mode === 'hosts') {
    const chips = el('div', { class: 'file-host-chips' });
    for (const h of hosts) chips.append(el('span', { class: 'host-chip' + (own === null ? ' from' : ''), text: h }));
    if (own !== null && !isLocked(t)) chips.append(el('button', { type: 'button', class: 'link-btn file-hosts-edit', text: 'Edit', 'aria-label': 'Edit where ' + t.display + ' may still be sent', onclick: () => open(true) }));
    cell.append(chips);
  }
  return cell;
}
/** Plan 13 §5.2: the label binds its values one by one (`values:` in
 *  policy.yaml). The second menu then says so, read only ("Per value"), and
 *  the sentence under it says where each value may go. Another choice here
 *  would have to rewrite the per-value hosts, which only policy.yaml says;
 *  a level chosen in the first menu keeps them (the save keeps `values:`). */
function perValue(t, level) {
  return !!(t.label && t.label.values && t.label.values.length && t.label.send) && level !== null && level !== 'public';
}
function perValuePick(cell, t, st, own) {
  const each = 'Each value has its own hosts. Change them in policy.yaml.';
  const words = own === null ? inheritedSend(t, 'Per value', each) : null;
  const sel = el('select', { class: 'label-select send-select', 'aria-label': words || 'Where ' + t.display + ' may be sent', title: words || each });
  sel.append(el('option', { value: 'values', text: 'Per value' }));
  sel.value = 'values';
  sel.disabled = true;
  cell.append(el('span', { class: 'label-pick send-pick' + (st.waiting !== undefined ? ' waiting' : ''), 'data-send': 'values', 'data-from': own === null ? 'values' : null },
    el('span', { class: 'label-dot', 'aria-hidden': 'true' }), sel));
  // Each key and host a name kept whole (§4.25u, *Rules names each host*).
  cell.append(el('p', { class: 'dim file-values' }, askCellWords(t.label.sendParts, t.label.send)));
  return cell;
}

/** The tooltip and name of a second menu that follows a label from
 *  elsewhere: its choice and where it comes from, as the row's line says it
 *  ("Where ~/proj/notes/a.md may be sent: listed hosts without asking. From
 *  your rule on ~/proj/notes. Change it there."). */
function inheritedSend(t, choice, more) {
  const from = ((t.label && t.label.from) || '').replace(/\.$/, '');
  return 'Where ' + t.display + ' may be sent: ' + choice.charAt(0).toLowerCase() + choice.slice(1) + '.' + (from ? ' ' + from + '.' : '') + (more ? ' ' + more : '');
}

/** The glossary's sentence for a send choice (the page lists them). Each
 *  row's menu asks it, so the terms are looked for in the glossary only,
 *  not in the whole page: '#rules-glossary dt' went through every element
 *  drawn, once a row, which a folder of 500 rows made quadratic. */
function sendMeaning(value) {
  const glossary = document.getElementById('rules-glossary');
  const g = glossary ? glossary.querySelectorAll('dt') : [];
  const want = (SEND_CHOICES.find((c) => c.value === value) || {}).term;
  for (const dt of g) if (dt.textContent === want && dt.nextElementSibling) return want + '. ' + dt.nextElementSibling.textContent;
  return want || '';
}
/** A choice in the second menu. Needs your OK drops the hosts; Listed hosts
 *  opens the row with the hosts field (Update queues them); Not secret is
 *  the label Not secret. Leaving Not secret here keeps the AI's answer it
 *  had (any AI) and changes only where the value may go. */
function chooseSend(t, own, value, open) {
  if (value === 'public') { chooseLevel(t, 'public'); return; }
  const level = own === 'public' ? 'any-model' : own;
  if (value === 'ask') {
    const rule = t.label && t.label.removable ? t.label : null;
    if (rule && rule.level === level && !(rule.bindings || []).length) {
      const p = pendingFor(t);
      if (p) { F.pending.delete(p.path); pendingChanged(); }
      return;
    }
    queueChanges(level, [], [t]);
    return;
  }
  if (own === 'public') queueChanges(level, [], [t]);
  open(true);
}

/** A row's two menus, each in a cell that names its question. The heads
 *  over the list name them on a wide screen; on a phone, where the heads
 *  are hidden and the menus stack under the name, each cell's caption does. */
function questionCells(t, open) {
  return [
    el('div', { class: 'q-cell' }, el('span', { class: 'q-cap', text: 'Which AI may read it' }), labelPick(t)),
    el('div', { class: 'q-cell' }, el('span', { class: 'q-cap', text: 'Where it may be sent' }), sendPick(t, open)),
  ];
}

/** The ⋯ at the end of a row: opens the rest of it under the row. */
function moreButton(isOpen, display, toggle) {
  return el('button', {
    type: 'button', class: 'file-more', 'aria-expanded': isOpen ? 'true' : 'false',
    'aria-label': (isOpen ? 'Close ' : 'More about ') + display, title: isOpen ? 'Close' : 'More',
    onclick: () => toggle(false),
  }, el('span', { 'aria-hidden': 'true', text: '⋯' }));
}

/** The toggle of a row: `hosts` opens it with the hosts field in focus. */
function entryToggle(entry) {
  return (hosts) => {
    F.open = F.open === entry.path && !hosts ? null : entry.path;
    renderFiles();
    afterToggle('#files-list', entry.path, hosts);
  };
}
/** Keep the keyboard where it was: on the row's button, or in its hosts. The
 *  opened row scrolls into view inside the list. */
function afterToggle(list, path, hosts) {
  const opened = document.querySelector(list + ' .file-detail');
  if (opened && opened.scrollIntoView) opened.scrollIntoView({ block: 'nearest' });
  const box = document.getElementById('lock-to');
  if (hosts && box && !box.disabled) { box.focus(); return; }
  for (const row of document.querySelectorAll(list + ' .row')) {
    if (row.getAttribute('data-path') !== path) continue;
    const b = row.querySelector('.file-more');
    if (b) b.focus();
    return;
  }
}

function fileRow(entry) {
  const ticked = F.selected.has(entry.path);
  const isOpen = F.open === entry.path;
  const row = el('div', { class: 'row file' + (ticked ? ' selected' : '') + (isOpen ? ' open' : ''), role: 'listitem', 'data-path': entry.path });
  const box = el('input', { type: 'checkbox', class: 'file-tick', 'aria-label': 'Tick ' + entry.display });
  box.checked = ticked;
  box.addEventListener('change', () => {
    if (box.checked) F.selected.set(entry.path, entry);
    else F.selected.delete(entry.path);
    // Not a full re-render: the ticked box keeps focus for the keyboard.
    row.classList.toggle('selected', box.checked);
    renderFileSelection();
  });
  row.append(box);
  const name = el('div', { class: 'file-name' });
  if (entry.kind === 'dir') {
    name.append(el('button', { type: 'button', class: 'link-btn file-open', text: entry.name + '/', title: 'Open ' + entry.display, onclick: () => openFolder(entry.path, { focus: true }) }));
  } else {
    name.append(el('code', { text: entry.name || entry.display, title: entry.display }));
  }
  if (entry.link) name.append(' ', el('span', { class: 'dim', text: '→ ' + entry.link }));
  // A folder with rules inside says so: follow the dots to them.
  if (entry.inside) name.append(' ', el('span', { class: 'file-inside' }, el('span', { class: 'file-dot' }), n(entry.inside, 'rule inside', 'rules inside')));
  row.append(el('div', { class: 'file-cell' },
    el('span', { class: 'row-icon' }, svg(entry.kind === 'dir' ? ICON.folder : entry.kind === 'pattern' ? ICON.pattern : ICON.file, 18)),
    el('div', { class: 'file-text' }, name, ...fileSub(entry))));
  const toggle = entryToggle(entry);
  row.append(...questionCells(entry, toggle), moreButton(isOpen, entry.display, toggle));
  // A click on the row itself (not a box, a menu, the name of a folder, or a
  // link) opens it.
  row.addEventListener('click', (e) => {
    if (e.target.closest && e.target.closest('input, button, a, select')) return;
    toggle(false);
  });
  return row;
}

function visibleEntries() {
  const q = document.getElementById('files-filter').value.trim().toLowerCase();
  const hidden = document.getElementById('files-hidden').checked;
  const marked = document.getElementById('files-labeled').checked;
  return F.entries.filter((e) => (hidden || !e.name.startsWith('.'))
    && (!q || e.name.toLowerCase().includes(q))
    && (!marked || !e.label || e.label.source !== 'none' || e.inside > 0 || pendingFor(e)));
}

/** `opts.placed`: the caller gives the focus back itself (pendingChanged),
 *  so a focus in the list is not moved to its row's tick box. */
function renderFiles(opts) {
  const list = document.getElementById('files-list');
  const placed = !!(opts && opts.placed === true);
  const focused = !placed && document.activeElement && list.contains(document.activeElement) ? rowIndexOf(document.activeElement) : -1;
  clear(list);
  const d = F.data;
  // Breadcrumbs: each folder above is one click away.
  const crumbs = document.getElementById('files-crumbs');
  clear(crumbs);
  if (d) {
    (d.crumbs || []).forEach((c, i) => {
      if (i > 0 && d.crumbs[i - 1].name !== '/') crumbs.append(el('span', { class: 'dim', text: '/' }));
      crumbs.append(i === d.crumbs.length - 1
        ? el('span', { class: 'crumb-here', 'aria-current': 'location', text: c.name })
        : el('button', { type: 'button', class: 'link-btn crumb', text: c.name, onclick: () => openFolder(c.path) }));
    });
  }
  // Notes: the labels could not be read, or they are not enforced now.
  if (d && d.labels === 'unknown') filesNote(labelsUnknownNote(d));
  else if (d && d.axis === false) filesNote('Protection is off. These rules take effect when you turn it on in Settings.');
  else filesNote('');
  // The folder's own label.
  const self = document.getElementById('files-self');
  clear(self);
  self.hidden = !(d && d.self);
  if (d && d.self) {
    self.append(el('span', { class: 'dim', text: 'This folder: ' }), labelChip(d.self));
    if (d.self.from) self.append(' ', el('span', { class: 'dim', text: d.self.from }));
  }
  const withRow = (e) => {
    list.append(fileRow(e));
    if (F.open === e.path) list.append(rowDetail(e, 0));
  };
  if (F.typed) withRow(F.typed);
  if (d && d.parent) {
    list.append(el('button', { type: 'button', class: 'row file up', onclick: () => openFolder(d.parent, { focus: true }) },
      el('span'), el('span', { class: 'file-cell' }, el('span', { class: 'row-icon' }, svg(ICON.folder, 18)), el('span', { class: 'file-name', text: '..' }), el('span', { class: 'dim', text: 'Up one folder' }))));
  }
  const shown = visibleEntries();
  for (const e of shown) withRow(e);
  if (d && !shown.length) list.append(el('div', { class: 'empty-row dim', text: F.entries.length ? 'Nothing here matches.' : 'This folder is empty.' }));
  if (d && d.more) {
    const btn = el('button', { type: 'button', class: 'btn small files-more', text: 'Show more (' + (d.total - F.entries.length) + ' more)', onclick: moreFiles });
    if (F.moreFailure) {
      // Why the last press brought nothing, over the button that tries again.
      const said = el('div', { id: 'files-more-words', class: 'files-more-failed' }, ...previewNodes(F.moreFailure));
      btn.setAttribute('aria-describedby', said.id);
      list.append(said);
    }
    list.append(btn);
  }
  if (focused >= 0) focusRow(focused);
  renderFileSelection();
  renderPending();
  renderMoveNotice();
}

// ── The keyboard: arrows move between rows, Right/Enter opens a folder,
//    Left goes up one folder; Space ticks (the checkbox's own key).
function listRows() {
  return [...document.querySelectorAll('#files-list > .row.file')];
}
function rowIndexOf(node) {
  const row = node.closest ? node.closest('.row.file') : null;
  return row ? listRows().indexOf(row) : -1;
}
function focusRow(i) {
  const rows = listRows();
  if (!rows.length) return;
  const row = rows[Math.max(0, Math.min(i, rows.length - 1))];
  const target = row.matches('button') ? row : row.querySelector('.file-tick');
  if (target) target.focus();
}
function onListKey(e) {
  const i = rowIndexOf(e.target);
  // A label menu keeps its own arrow keys.
  if (i < 0 || e.target.matches('input[type="text"], input:not([type]), select')) return;
  const row = listRows()[i];
  if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
    e.preventDefault();
    focusRow(i + (e.key === 'ArrowDown' ? 1 : -1));
  } else if (!e.target.matches('.file-tick, .file-open, .row')) {
    // Left and Right on a row's other buttons are theirs.
  } else if (e.key === 'ArrowRight' || (e.key === 'Enter' && e.target.classList.contains('file-tick'))) {
    const open = row.querySelector('.file-open');
    if (open) { e.preventDefault(); open.click(); }
  } else if (e.key === 'ArrowLeft') {
    if (F.data && F.data.parent) { e.preventDefault(); openFolder(F.data.parent, { focus: true }); }
  }
}

/** Under the list: a hint, or, with rows ticked, one button per label that
 *  labels them all together (dashboard.md §4.25p). */
function renderFileSelection() {
  const bar = document.getElementById('files-selected');
  clear(bar);
  const t = [...F.selected.values()];
  bar.classList.toggle('ticked', t.length > 0);
  bar.hidden = !t.length;
  if (!t.length) return;
  const ownModel = hasOwnModel(S.panel);
  const to = el('input', { type: 'text', id: 'files-bulk-to', placeholder: 'api.example.com', autocomplete: 'off', spellcheck: 'false' });
  const group = el('div', { class: 'level-buttons', role: 'group', 'aria-label': 'Which AI may read the ticked items' });
  for (const b of LEVEL_BUTTONS) {
    const btn = el('button', {
      type: 'button', class: 'level-btn ' + b.cls, 'data-level': b.level, title: b.term + '. ' + b.meaning,
      onclick: () => queueChanges(b.level, b.level === 'public' ? [] : splitHosts(to.value), t),
    }, svg(ICON[b.icon], 16), el('span', { text: b.text }));
    btn.disabled = b.level === 'local-model' && !ownModel;
    group.append(btn);
  }
  bar.append(el('div', { class: 'files-bulk-head' },
    el('strong', { text: n(t.length, 'item', 'items') + ' ticked.' }), ' Which AI may read them:',
    el('button', { type: 'button', class: 'link-btn', id: 'files-bulk-clear', text: 'Clear the ticks', onclick: () => { F.selected.clear(); renderFiles(); } })));
  bar.append(group);
  bar.append(el('label', { class: 'field detail-to' },
    el('span', {}, 'May still be sent to ', el('span', { class: 'muted', text: '(optional, comma-separated)' })), to));
  const notes = [];
  if (t.some((x) => x.kind === 'dir' || x.kind === 'missing')) notes.push('A folder\'s rule covers everything inside it, except files with a rule of their own.');
  if (t.some((x) => x.target)) notes.push('A link gets the rule, and so does the file it points to.');
  for (const text of notes) bar.append(el('p', { class: 'dim detail-note', text }));
  // Remove is for rules of the person's own on exactly these paths.
  if (t.every((x) => (x.label && x.label.removable) || x.kind === 'pattern')) {
    bar.append(el('button', { type: 'button', class: 'link-btn rule-source-btn', id: 'files-bulk-unset', text: 'Remove my rules', onclick: () => queueChanges(null, [], t) }));
  }
}

// ── Labeled: your file rules as a tree ──────────────────────────────────────
function ruleKey(r) { return (r.sourceId || 'page') + '\0' + r.path; }
function isPatternRule(r) { return r.covers === 'pattern' || GLOB_RE.test(r.path); }
/** What a rule's row is drawn as: 'pattern', 'dir' or 'file'. A rule that
 *  reaches everything inside a path that is a file (`pathIsFile`, the
 *  server's look at the disk) is drawn as that file (dashboard.md §4.25f
 *  *A rule on a file reads as a file*); `covers` still says what an edit
 *  made here keeps. */
function ruleShape(r) { return isPatternRule(r) ? 'pattern' : r.covers === 'subtree' && !r.pathIsFile ? 'dir' : 'file'; }

function renderLabeled() {
  const host = document.getElementById('files-tree');
  if (!host) return;
  clear(host);
  if (!S.panel) {
    // Said once for all of Your rules (the list below stays hidden), with the
    // cause the page knows (panelCause; followCannotCheck draws it again).
    // The file browser works without the service and marks its labels
    // unknown, but not without the dashboard: no answer offers no add.
    showFilesGroup(true);
    const cause = panelCause(S.panelFailure);
    F.unreadCause = cause;
    const line = el('div', { class: 'empty-row dim' }, ...cannotCheck('Your rules could not be read.', cause, true));
    if (cause !== 'gone') line.append(' You can still ', el('button', { type: 'button', class: 'link-btn', text: 'add a rule', onclick: () => setFilesView('all') }), '.');
    host.append(line);
    return;
  }
  F.unreadCause = false;
  // Find a rule (§4.25f): only the rules that hold the text, and the folders
  // on the way to them; with none, the group is not drawn, its title with it.
  const q = findText();
  const found = F.rules.filter((r) => ruleMatches(r, q));
  showFilesGroup(!q || found.length > 0);
  // A row the box hides is closed: its ⋯ is gone with it.
  if (q && F.rule && !found.some((r) => ruleKey(r) === F.rule)) F.rule = null;
  if (!F.rules.length) {
    host.append(el('div', { class: 'empty-row dim' }, 'No file or folder has a rule of yours yet. ',
      el('button', { type: 'button', class: 'link-btn', text: 'Add a rule', onclick: () => setFilesView('all') }), ' to mark one secret.'));
    return;
  }
  const patterns = found.filter(isPatternRule).sort((a, b) => a.path.localeCompare(b.path));
  const all = F.rules.filter((r) => !isPatternRule(r));
  const places = q ? findTree(fileTree(all), q) : fileTree(all);
  if (patterns.length) {
    host.append(el('div', { class: 'files-tree-cap' }, el('strong', { text: 'Patterns' }), ' ', el('span', { class: 'dim', text: 'apply to every file that matches' })));
    for (const r of patterns) appendRule(host, r, shortPath(r.path), 0);
  }
  if (places.length) {
    if (patterns.length) host.append(el('div', { class: 'files-tree-cap' }, el('strong', { text: 'Places' }), ' ', el('span', { class: 'dim', text: 'a rule inside a folder rule is more specific, so it wins for its own files' })));
    renderFileTree(host, places, 0);
  }
}
/** The Files and folders group, its title and column heads with it: not
 *  drawn while Find a rule finds none of its rules. */
function showFilesGroup(shown) {
  for (const id of ['files-group', 'files-heads', 'files-tree']) {
    const x = document.getElementById(id);
    if (x) x.hidden = !shown;
  }
}

/** A rule's row, and the row under it when it is open. */
function appendRule(host, r, label, depth, context) {
  const row = ruleTreeRow(r, label, depth);
  // A folder rule drawn only for a rule Find a rule found inside it.
  if (context) row.setAttribute('data-find', 'context');
  host.append(row);
  if (F.rule === ruleKey(r)) host.append(rowDetail(ruleTarget(r), depth));
}

/** One of your rules in the tree: its dots and hosts act in place, and a
 *  click on its name opens what the rules say about it under it. */
function ruleTreeRow(r, label, depth) {
  const key = ruleKey(r);
  const t = ruleTarget(r);
  const isOpen = F.rule === key;
  const row = el('div', { class: 'row file-rule' + (isOpen ? ' open' : ''), role: 'listitem', style: '--depth:' + depth, title: r.title || r.path, 'data-path': r.path });
  const name = el('span', { class: 'file-name' }, el('code', { text: label }), r.reach ? ' ' : null, r.reach ? el('span', { class: 'dim', text: r.reach }) : null);
  if (!r.editable) name.append(' ', el('span', { class: 'file-tag', text: 'Set in policy.yaml' }));
  if (r.warning) name.append(' ', el('span', { class: 'file-warn-mark', role: 'img', 'aria-label': r.warning, title: r.warning }, svg(ICON.alert, 14)));
  const text = el('div', { class: 'file-text' }, name);
  if (r.opens && r.level !== 'public') text.append(el('div', { class: 'dim file-opens' }, el('span', { class: 'file-opens-k', text: 'Opens it' }), ' ', r.opens));
  const p = pendingFor(t);
  if (p) text.append(el('div', { class: 'file-pending' }, ...willBe(p)));
  const toggle = (hosts) => {
    F.rule = F.rule === key && !hosts ? null : key;
    renderLabeled();
    afterToggle('#files-tree', r.path, hosts);
  };
  row.append(
    el('div', { class: 'file-cell' }, el('span', { class: 'row-icon' }, svg(t.kind === 'pattern' ? ICON.pattern : t.kind === 'dir' ? ICON.folder : ICON.file, 18)), text),
    ...questionCells(t, toggle), moreButton(isOpen, t.display, toggle));
  row.addEventListener('click', (e) => {
    if (e.target.closest && e.target.closest('input, button, a, select')) return;
    toggle(false);
  });
  return row;
}

function ruleTarget(r) {
  const kind = ruleShape(r);
  return {
    path: r.path, display: shortPath(r.path), name: baseName(shortPath(r.path)), kind, rule: r, version: r.version || null,
    label: { level: r.level, words: r.effect, source: 'yours', from: 'Your rule' + (r.reach ? ', ' + r.reach : ''), removable: r.editable, bindings: r.bindings || [], ...(r.values ? { values: r.values, send: r.send, sendParts: r.sendParts } : {}) },
  };
}

// ── The opened row ──────────────────────────────────────────────────────────
/** Under an opened row: the label in words and where it comes from, the
 *  hosts to edit, Remove, and what the side panel held before §4.25p. */
function rowDetail(t, depth) {
  const box = el('div', { class: 'file-detail', role: 'listitem', 'aria-label': 'About ' + t.display, style: '--depth:' + depth });
  const main = el('div', { class: 'file-detail-main' });
  main.append(el('p', { class: 'detail-path', text: t.rule ? (t.rule.title || t.path) : t.display }));
  const now = el('div', { class: 'detail-label' });
  if (t.label) {
    now.append(labelChip(t.label));
    if (t.label.from) now.append(el('span', { class: 'dim', text: t.label.from }));
  } else {
    now.append(el('span', { class: 'dim', text: t.kind === 'pattern' ? 'Every file that matches' : t.kind === 'missing' ? 'Not there yet' : 'Label unknown' }));
  }
  main.append(now);
  if (t.preview) main.append(el('p', { class: 'dim detail-note' }, ...previewNodes(t.preview)));
  const p = pendingFor(t);
  if (p) main.append(el('p', { class: 'file-pending' }, ...willBe(p)));
  main.append(hostsEditor(t));
  const locked = isLocked(t);
  const notes = [];
  if (locked) notes.push('Set in policy.yaml. Change it there.');
  if (t.kind === 'dir' || t.kind === 'missing') notes.push('A folder\'s rule covers everything inside it, except files with a rule of their own.');
  if (t.target) notes.push('A link gets the rule, and so does the file it points to.');
  for (const text of notes) main.append(el('p', { class: 'dim detail-note', text }));
  // Remove is for a rule of the person's own on exactly this path.
  if (!locked && ((t.label && t.label.removable) || t.kind === 'pattern')) {
    main.append(el('button', { type: 'button', class: 'link-btn rule-source-btn', id: 'files-unset', text: 'Remove my rule', 'aria-label': 'Remove my rule on ' + t.display, onclick: () => queueChanges(null, [], [t]) }));
  }
  const facts = detailFacts(t);
  const why = facts.find((x) => x.classList && x.classList.contains('file-why'));
  main.append(...facts.filter((x) => x !== why));
  box.append(main);
  if (why) box.append(why);
  return box;
}

/** "May still be sent to": the hosts of the rule in force (or waiting), with
 *  Update to queue the same label with new hosts. Under Not secret there are
 *  none to edit; the field shows the hosts in force, greyed, so a secret
 *  label chosen again starts from them. */
function hostsEditor(t) {
  const st = dotState(t);
  const current = st.waiting !== undefined ? st.waiting : st.mine;
  const locked = isLocked(t);
  const to = el('input', { type: 'text', id: 'lock-to', 'data-path': t.path, placeholder: 'api.example.com', autocomplete: 'off', spellcheck: 'false' });
  to.value = currentHosts(t).join(', ');
  to.disabled = locked || current === 'public';
  const canUpdate = current && current !== 'public' && !locked;
  if (canUpdate) to.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); chooseLevel(t, current); } });
  const row = el('div', { class: 'detail-to-row' }, el('label', { class: 'field detail-to' },
    el('span', {}, 'May still be sent to ', el('span', { class: 'muted', text: '(optional, comma-separated)' })), to));
  if (canUpdate) {
    row.append(el('button', { type: 'button', class: 'btn small', id: 'files-to-update', text: 'Update', 'aria-label': 'Update where ' + t.display + ' may still be sent', onclick: () => chooseLevel(t, current) }));
  }
  return row;
}

function detailFacts(e) {
  const out = [];
  const r = e.rule;
  if (r) {
    if (r.warning) out.push(el('p', { class: 'rule-warn', role: 'note', text: r.warning }));
    if (r.sourceNote) out.push(el('p', { class: 'dim detail-note', text: r.sourceNote }));
    if (r.origin) out.push(originLine(r.origin));
    if (r.used) out.push(el('p', { class: 'dim detail-note', text: r.used }));
    const links = el('div', { class: 'detail-links' });
    if (r.sourceId) {
      const lines = el('div', { class: 'detail-source' });
      links.append(sourceButton(lines, r.sourceId, e.display));
      out.push(links, lines);
    } else {
      out.push(links);
    }
    if (e.kind !== 'pattern') {
      links.append(el('button', { type: 'button', class: 'link-btn rule-source-btn', text: 'Show in its folder', 'aria-label': 'Show in its folder: ' + e.display,
        onclick: (ev) => setFilesView('all', { folder: parentOf(r.path), pick: r.path, by: ev.currentTarget }) }));
    }
  }
  if (!r && e.kind === 'dir') {
    const open = el('div', { class: 'detail-links' },
      el('button', { type: 'button', class: 'btn small', text: 'Open', 'aria-label': 'Open ' + e.display, onclick: () => openFolder(e.path, { focus: true }) }));
    if (e.inside) open.append(' ', el('span', { class: 'dim', text: n(e.inside, 'rule inside', 'rules inside') }));
    out.push(open);
  }
  // What the rules say, where there is something to explain: a rule, a
  // label, or a link whose file is treated differently. The rule's warning,
  // said above in full, is not said again there (§4.25p).
  if (e.kind !== 'pattern' && e.kind !== 'missing' && (r || (e.label && e.label.source !== 'none') || e.targetLabel)) {
    out.push(whyBox(e.path, r && r.warning ? [r.warning] : []));
  }
  return out;
}

function savePending() {
  if (F.pending.size) lsSet(FILES_PENDING_KEY, JSON.stringify([...F.pending.values()]));
  else lsDel(FILES_PENDING_KEY);
}
function restorePending() {
  try {
    const list = JSON.parse(lsGet(FILES_PENDING_KEY) || '[]');
    if (!Array.isArray(list)) return;
    for (const p of list) if (p && typeof p.path === 'string') F.pending.set(p.path, p);
  } catch { /* a damaged entry: start empty */ }
}

/** Changes to save keeps the keyboard focus (dashboard.md §4.25 "Changes to
 *  save keeps the focus"). Save goes off while the changes are on their way,
 *  and a change saved, discarded or dropped draws the list again or hides
 *  the bar: until 2026-10-11 each left a screen reader on <body>. The bar is
 *  no card (it sits after them, and hides once nothing waits), so it has its
 *  own rule. A press counts only with the focus in the bar (barPlace); after
 *  it, only if the focus fell (or sits in the hidden bar), it goes to `to`
 *  when that is still shown (Save after a refusal or a partial save, the
 *  question before a weaker change: never Save anyway, so a second Enter
 *  loosens nothing), else the bar's heading while changes still wait (never
 *  another row's button), else the Your rules heading, where the notice says
 *  what was saved. */
function barPlace() {
  const bar = document.getElementById('files-pending');
  const a = document.activeElement;
  return !!(bar && a && a !== bar && bar.contains(a));
}
function barRefocus(had, to) {
  const a = document.activeElement;
  if (!had || !(focusFell() || a.closest('[hidden]'))) return;
  const bar = document.getElementById('files-pending');
  const shown = (x) => x && x.isConnected && !x.closest('[hidden]');
  const at = shown(to) ? to : !bar.hidden ? bar.querySelector('h3') : document.getElementById('rules-title');
  if (isControl(at)) at.focus({ preventScroll: true }); else focusThere(at);
}

/** Changes to save never hides the focus (dashboard.md §4.25n *It never
 *  hides the focus*). The bar sticks to the bottom of the window, over the
 *  rules: until 2026-10-14 a Tab to a rule's menu scrolled the menu to the
 *  window's bottom edge, under the bar. The window now keeps the bar's room
 *  (its height, its 12px margin and 8px more: `--bar-room`, app.css
 *  scroll-padding-bottom) below what it scrolls into view, and a bar that
 *  comes or grows over the focused control scrolls the control above it.
 *  A control in the bar is the bar's own: nothing moves for it. The bar
 *  hidden, or its page, keeps no room. */
function trackBarRoom() {
  const bar = document.getElementById('files-pending');
  const root = document.documentElement;
  const room = () => {
    const b = bar.getBoundingClientRect();
    if (!b.height) { root.style.removeProperty('--bar-room'); return; }
    root.style.setProperty('--bar-room', Math.ceil(b.height) + 20 + 'px');
    const a = document.activeElement;
    if (!a || a === document.body || bar.contains(a)) return;
    const r = a.getBoundingClientRect();
    if (r.bottom > b.top && r.top < b.bottom && a.scrollIntoView) a.scrollIntoView({ block: 'nearest' });
  };
  room();
  if (typeof ResizeObserver === 'function') new ResizeObserver(room).observe(bar);
}

function renderPending() {
  const box = document.getElementById('files-pending');
  const list = document.getElementById('files-pending-list');
  clear(list);
  const sugg = suggestedPending();
  const count = F.pending.size + sugg.length;
  box.hidden = count === 0;
  document.getElementById('files-pending-count').textContent = count ? String(count) : '';
  // Mandu's suggestions first: each hides a file, or its old versions, from the AI.
  for (const s of sugg) {
    list.append(el('li', { class: 'pending-suggestion', 'data-id': s.id },
      el('code', { text: s.kind === 'versions' ? s.name + ' (' + s.display + ')' : s.display }), ' ',
      el('strong', { text: levelText(s.level || 'no-model', []) }),
      el('span', { class: 'dim', text: ', ' + (s.by ? s.by.charAt(0).toLowerCase() + s.by.slice(1) : 'suggested by Mandu\'s scan') + '. ' + s.impact }), ' ',
      el('button', { type: 'button', class: 'link-btn', 'aria-label': 'Skip the suggestion for ' + suggestionName(s), text: 'Skip', onclick: () => {
        const had = barPlace();
        tickSuggestion(s, false);
        barRefocus(had);
      } })));
  }
  for (const p of F.pending.values()) {
    const li = el('li', {},
      ...fitName(p.display), ' ',
      p.before ? el('span', { class: 'dim' }, beforeNodes(p), ' → ') : el('span', { class: 'dim' }),
      el('strong', {}, levelNodes(p.level, p.bindings)),
      p.recursive && !p.file && p.level !== null ? el('span', { class: 'dim', text: ', and everything inside' }) : null,
      p.target && p.level !== null ? el('span', { class: 'dim', text: ', and the file it points to (' + shortPath(p.target) + ')' }) : null,
      ' ',
      el('button', { type: 'button', class: 'link-btn', 'aria-label': 'Drop the change to ' + p.display, text: 'Drop', onclick: () => {
        const had = barPlace();
        F.pending.delete(p.path);
        pendingChanged();
        barRefocus(had);
      } }));
    list.append(li);
  }
  document.getElementById('files-confirm').hidden = F.expected === null;
  document.getElementById('files-save').textContent = F.expected === null ? 'Save changes' : 'Save anyway';
}

function pendingChanges() {
  return [...F.pending.values()].map((p) => ({
    path: p.path, level: p.level,
    ...(p.bindings && p.bindings.length ? { bindings: p.bindings } : {}),
    ...(p.recursive !== undefined && p.recursive !== null ? { recursive: p.recursive } : {}),
    ...(p.version ? { version: p.version } : {}),
  }));
}

/** After a save refused because a rule it was made from changed somewhere
 *  else (the rules and the folder were read again): each waiting change
 *  takes its path's label and the version of its rule as they are now,
 *  from the new reads, so Changes to save says what it changes from now
 *  and the next Save names the rules as they are now. A path neither read
 *  lists any more sends none (the server's own read names it). */
function pendingVersionsNow() {
  for (const p of F.pending.values()) {
    const entry = F.entries.find((e) => e.path === p.path);
    const rule = F.rules.find((r) => r.path === p.path || shortPath(r.path) === p.display);
    const t = entry || (rule ? ruleTarget(rule) : null);
    p.version = (t && t.version) || null;
    if (t && t.label) Object.assign(p, { before: t.label.words, beforeLevel: t.label.level, beforeHosts: t.label.bindings || [] });
  }
  savePending();
}

/** The pending list changed: forget any question asked about the old list,
 *  keep it across a reload, repaint, and work out what it would do.
 *
 *  A label chosen in Your rules keeps the keyboard focus (dashboard.md
 *  §4.25 *A label chosen in Your rules keeps the focus*). A choice waits in
 *  Changes to save, and the tree and the browser are drawn again from
 *  nothing: until 2026-10-11 a choice in a tree row's menu, Remove my rule
 *  and Update left a screen reader on <body>, and one in the browser moved
 *  the focus to the row's tick box. Where the focus is in the Your rules
 *  card is taken before the draw, as the poll takes it (pollPlace: a row by
 *  its data-path, a button or the hosts field by its id; a menu reads as its
 *  name, and its colour is no key), and given back after, only if it fell:
 *  to the control drawn at that place that reads the same, else the card's
 *  heading (pollRefocus). Changes to save keeps its own rule (barRefocus). */
function pendingChanged() {
  const block = document.getElementById('rules-block');
  const place = block ? pollPlace(block) : null;
  F.expected = null;
  savePending();
  renderPending();
  if (F.data || F.typed) renderFiles({ placed: !!place });
  renderLabeled();
  pollRefocus(place);
  refreshImpact();
}

/** "This changes 12 files, 3 of them less protected" under the pending list. */
async function refreshImpact() {
  const box = document.getElementById('files-impact');
  const seq = ++F.impactSeq;
  clear(box);
  if (!F.pending.size) { box.hidden = true; return; }
  box.hidden = false;
  box.append(el('span', { class: 'dim', text: 'Working out what this changes…' }));
  const r = await apiPost('files/impact', { changes: pendingChanges(), folder: F.path || '~' });
  if (seq !== F.impactSeq) return;
  clear(box);
  if (!r.ok || !r.data) {
    // A change the service cannot make says why as Save does; the reason of
    // the server follows a colon; a refusal the page words is a sentence of
    // its own.
    const problems = impactProblems(r);
    if (problems) { box.append(el('span', { class: 'dim', text: problemsSentence('What this changes could not be worked out', problems) })); return; }
    const why = refusalText(r, '');
    box.append(!why ? el('span', { class: 'dim', text: 'What this changes could not be worked out.' })
      : why === (r.data && r.data.error) ? el('span', { class: 'dim', text: 'What this changes could not be worked out: ' + why + '.' })
      : el('span', { class: 'dim' }, 'What this changes could not be worked out. ', words(why)));
    return;
  }
  renderImpact(box, r.data.impact, r.data.page || 0);
}

/** The label of a file before and after, with each host a fitName when the
 *  server sends the parts (an older one: its words, as written). */
function levelChange(f) {
  if (!Array.isArray(f.beforeParts) || !Array.isArray(f.afterParts)) return [f.before + ' → ' + f.after];
  return [fitWords(f.beforeParts, f.before), ' → ', fitWords(f.afterParts, f.after)];
}

/** An impact answer as words: the count, the weaker ones named, the rest folded. */
function renderImpact(box, impact, page) {
  if (!impact) {
    box.append(el('span', { class: 'dim', text: page ? n(page, 'rule made on this page earlier changes', 'rules made on this page earlier change') + ' in place.' : 'Nothing under these changes to check.' }));
    return;
  }
  const head = impact.changed === 0 ? 'No file under these changes gets a different label'
    : 'Changes the label of ' + n(impact.changed, 'file', 'files') + (impact.weaker ? ', ' + impact.weaker + ' of them less protected' : '');
  box.append(el('p', { class: impact.weaker ? 'impact-head weaker' : 'impact-head', text: head + (impact.truncated ? ' (checked the first ' + impact.scanned + ' files; there may be more)' : '') + '.' }));
  if (impact.files.length) {
    const det = el('details', { class: 'impact-files' });
    if (impact.weaker) det.open = true;
    det.append(el('summary', { text: 'Show the files' }));
    const ul = el('ul');
    for (const f of impact.files) {
      ul.append(el('li', { class: f.weaker ? 'weaker' : null }, ...fitName(f.display), ' ', ...levelChange(f)));
    }
    if (impact.changed > impact.files.length) ul.append(el('li', { class: 'dim', text: 'and ' + (impact.changed - impact.files.length) + ' more' }));
    det.append(ul);
    box.append(det);
  }
  for (const p of F.pending.values()) {
    if (GLOB_RE.test(p.path)) box.append(el('p', { class: 'dim', text: p.display + ': ' + patternLine(impact) }));
  }
}

/** Queue one change per target (a rule keeps its own reach). Ticked rows
 *  stay ticked, and each row's dots show the choice waiting. */
function queueChanges(level, bindings, targets) {
  for (const e of targets) {
    const old = pendingFor(e);
    if (old) F.pending.delete(old.path);
    const folder = e.kind === 'dir' || e.kind === 'missing';
    F.pending.set(e.path, {
      path: e.path,
      display: e.display,
      level,
      bindings: level === null || level === 'public' ? [] : bindings,
      recursive: e.kind === 'pattern' ? null : e.rule ? e.rule.covers === 'subtree' : folder,
      // A rule kept reaching everything inside a file reads as that file.
      file: e.kind === 'file',
      before: e.label ? e.label.words : '',
      // The level and hosts those words say, to draw each host as a name.
      ...(e.label ? { beforeLevel: e.label.level, beforeHosts: e.label.bindings || [] } : {}),
      target: e.target || null,
      // The version of the path's own rule as the row was read (the
      // listing's, or the rule list's): Save sends it, so a rule changed
      // somewhere else meanwhile refuses the save instead of being put back.
      version: e.version || null,
    });
  }
  pendingChanged();
}

/** Save, for Mandu's ticked suggestions: each is approved as its own change
 *  (Undo under Rule changes in Approvals). They only add protection, so nothing is asked. Returns
 *  how many were saved, or null when nothing more should be sent. */
async function saveSuggestions(err) {
  const ids = suggestedPending().map((s) => s.id);
  if (!ids.length) return 0;
  const save = document.getElementById('files-save');
  save.disabled = true;
  const r = await apiPost('suggestions/apply', { ids });
  save.disabled = false;
  if (!r.ok || !r.data) {
    setWords(err, refusalText(r, 'could not save the suggestions (' + r.status + ')'));
    await loadSuggestions();
    return null;
  }
  if (Array.isArray(r.data.suggestions)) setWritten(r.data); else await loadSuggestions();
  const applied = r.data.applied || [];
  const refused = r.data.refused || [];
  if (refused.length) {
    err.textContent = n(refused.length, 'suggestion was', 'suggestions were') + ' not saved: ' + refused.map((x) => x.error).join(' ');
  }
  if (applied.length) {
    RULES_READS.wrote();
    rulesNotice(n(applied.length, 'suggestion', 'suggestions') + ' saved.' + (applied.length > 1 ? ' Each is its own change in Approvals, under Rule changes.' : ''),
      applied.length === 1 ? applied[0].changeId : null);
  }
  renderSuggestionViews();
  return applied.length;
}

async function saveFileChanges() {
  const err = document.getElementById('lock-error');
  const save = document.getElementById('files-save');
  const had = barPlace();
  err.textContent = '';
  const saved = await saveSuggestions(err);
  if (saved === null) { barRefocus(had, save); return; }
  if (!F.pending.size) {
    if (saved) await loadRules();
    barRefocus(had, save);
    return;
  }
  const body = { changes: pendingChanges(), folder: F.path || '~' };
  if (F.expected !== null) {
    body.expected = F.expected;
    const why = document.getElementById('files-reason').value.trim();
    if (why) body.reason = why;
  }
  save.disabled = true;
  const r = await apiPost('files/labels', body);
  save.disabled = false;
  if (r.ok && r.data && r.data.confirm) {
    F.expected = r.data.expected;
    const list = document.getElementById('files-confirm-list');
    clear(list);
    for (const l of r.data.loosens || []) list.append(el('li', {}, ...fitName(l.subject), ' ', fitWords(l.detailParts, l.detail)));
    const reach = document.getElementById('files-confirm-files');
    clear(reach);
    const im = r.data.impact;
    const weaker = im ? im.files.filter((f) => f.weaker) : [];
    reach.hidden = weaker.length === 0;
    if (weaker.length) {
      reach.append(el('p', { id: 'files-confirm-files-head', text: 'Files that become less protected' + (im.truncated ? ' (from the first ' + im.scanned + ' checked)' : '') + ':' }));
      const ul = el('ul', { 'aria-labelledby': 'files-confirm-files-head' });
      for (const f of weaker) ul.append(el('li', {}, ...fitName(f.display), ' ', ...levelChange(f)));
      if (im.weaker > weaker.length) ul.append(el('li', { text: 'and ' + (im.weaker - weaker.length) + ' more' }));
      reach.append(ul);
    }
    renderPending();
    barRefocus(had, document.querySelector('#files-confirm > p'));
    return;
  }
  if (!r.ok) {
    setWords(err, changeRefusal(r, 'Not saved', 'could not save the changes (' + r.status + ')'));
    // What the person was shown no longer holds: ask again on the next Save.
    if (r.status === 409) { F.expected = null; renderPending(); }
    if (r.status === 409 && r.data && r.data.stale) {
      // A rule it was made from changed somewhere else: nothing was saved.
      // The choices stay waiting; the rules and the folder are read again
      // so the rows show the labels as they are now, and the next Save
      // names the rules as they are now (dashboard.md §4.25m).
      await Promise.all([F.path ? openFolder(F.path, { again: true }) : null, loadRules()]);
      pendingVersionsNow();
      renderPending();
    }
    barRefocus(had, save);
    return;
  }
  RULES_READS.wrote();
  const count = F.pending.size;
  F.pending.clear();
  F.expected = null;
  F.why.clear();
  savePending();
  document.getElementById('files-reason').value = '';
  rulesNotice(n(count, 'change', 'changes') + ' saved' + (saved ? ', and ' + n(saved, 'suggestion', 'suggestions') : '') + '.', saved ? null : r.data.changeId || null);
  refreshImpact();
  renderPending();
  await Promise.all([F.path ? openFolder(F.path) : null, loadRules()]);
  barRefocus(had, save);
}

/** How many names of one folder Tab completion reads at most: 20 of the
 *  listing's 500-entry pages (dashboard.md §4.25m *Typed paths and Tab
 *  completion*). A folder opened with an entry picked reads as far at most
 *  to find it (pickAhead). */
const NAMES_MAX = 10000;
/** The reads of a folder's names on their way, by the folder as typed: a
 *  keystroke meanwhile waits for the same read. */
const NAMES_READS = new Map();

/** A folder's names for Tab completion, { entries, more }: its pages in
 *  the listing's order, read once each as Show more reads them, up to
 *  NAMES_MAX names; the pages the browser read for it are used as they are.
 *  A page that fails is read again at the next completion. Null: the folder
 *  could not be listed. Until 2026-10-15 completion knew the first page
 *  only. */
function completionNames(dir) {
  if (!NAMES_READS.has(dir)) NAMES_READS.set(dir, readNames(dir).finally(() => NAMES_READS.delete(dir)));
  return NAMES_READS.get(dir);
}
/** The folder `dir` (as typed) under which its names were read
 *  (F.names, keyed by the listing's path), or null. */
function namesKey(dir) {
  let path = null;
  for (const k of F.names.keys()) if (shortPath(k) === dir || k === dir || (dir === '~' && F.data && k === F.data.home)) path = k;
  return path;
}
async function readNames(dir) {
  let path = namesKey(dir);
  if (path === null) {
    const r = await apiGetControl('files/list?path=' + encodeURIComponent(dir));
    if (!r.ok) return null;
    path = r.data.path;
    F.names.set(path, { entries: r.data.entries, more: !!r.data.more });
  }
  let known = F.names.get(path);
  while (known.more && known.entries.length < NAMES_MAX) {
    const r = await apiGetControl('files/list?path=' + encodeURIComponent(path) + '&offset=' + known.entries.length);
    if (!r.ok) break;
    // A folder that changed between two pages may list an entry twice.
    const seen = new Set(known.entries.map((e) => e.path));
    const fresh = r.data.entries.filter((e) => !seen.has(e.path));
    known = { entries: known.entries.concat(fresh), more: !!r.data.more };
    F.names.set(path, known);
    if (!fresh.length) break;
  }
  return known;
}

/** Could a name not read yet start with `stem`? The listing is in order,
 *  folders first and then by name (§4.25m *Browsing*), so every name not
 *  read sorts after the last one read: after a folder, any file may follow;
 *  after a file, only files whose names sort after it. */
function unreadMayMatch(known, stem) {
  if (!known.more) return false;
  const last = known.entries[known.entries.length - 1];
  return !last || last.kind === 'dir' || last.name.startsWith(stem) || last.name < stem;
}

/** Tab completion on the path box, VS Code style (the rest of the one
 *  matching name, or the shared start of several), and the suggestions list
 *  under it (a datalist the browser shows). Where names of the folder are
 *  not read (past NAMES_MAX, or a page that failed) and one could match,
 *  the text stays as typed rather than be completed to the wrong name. */
async function completePath(input, accept) {
  const v = input.value;
  if (GLOB_RE.test(v) || !(v.startsWith('/') || v.startsWith('~'))) return false;
  const cut = v.lastIndexOf('/');
  if (cut < 0) return false;
  const dir = v.slice(0, cut) || '/';
  const known = await completionNames(dir);
  if (!known) return false;
  if (input.value !== v) return false; // typed on meanwhile
  const { hits, done } = completionOf(v, known);
  const suggest = document.getElementById('files-suggest');
  clear(suggest);
  for (const h of hits.slice(0, 20)) suggest.append(el('option', { value: v.slice(0, cut + 1) + h.name + (h.kind === 'dir' ? '/' : '') }));
  if (!done) return false;
  input.value = done;
  if (accept) input.setSelectionRange(done.length, done.length);
  else input.setSelectionRange(v.length, done.length);
  return true;
}

/** What completion makes of the text `v` with a folder's names read so far
 *  (`known`): the names that start with the one typed (`hits`), and the
 *  text completed (`done`), or null when there is nothing to add or a name
 *  not read could change it (unreadMayMatch). */
function completionOf(v, known) {
  const cut = v.lastIndexOf('/');
  const stem = v.slice(cut + 1);
  const hits = known.entries.filter((e) => e.name.startsWith(stem) && (stem.startsWith('.') || !e.name.startsWith('.') || document.getElementById('files-hidden').checked));
  if (!hits.length || unreadMayMatch(known, stem)) return { hits, done: null };
  let common = hits[0].name;
  for (const h of hits) while (!h.name.startsWith(common)) common = common.slice(0, -1);
  let done = v.slice(0, cut + 1) + common;
  if (hits.length === 1 && hits[0].kind === 'dir') done += '/';
  return { hits, done: done === v ? null : done };
}

/** The text a Tab completed nothing in, while it stays as it is: the next
 *  Tab on it moves on (tabCompletes). Typing drops it. */
let tabAddedNothing = null;

/** Does Tab in the path box finish a name, or move the focus on as on any
 *  field (dashboard.md §4.25m *Tab moves on*)? It finishes the name being
 *  typed: the selection ends at the end of the text but is not all of it
 *  (Tab selects it all on the way in), the text is a path (not a pattern)
 *  and a name is started after its last /. Then it stays when what typing
 *  added is selected (Tab takes it), or when the folder's names may add
 *  something: they add to it, or they are not all read yet and no Tab on
 *  this text added nothing yet (a folder that cannot be listed, a page
 *  that failed). Until 2026-10-15 every Tab at the end of the text stayed,
 *  so the keyboard could not leave the box but backwards. */
function tabCompletes(input) {
  const v = input.value;
  if (!v || input.selectionEnd !== v.length || input.selectionStart === 0) return false;
  if (GLOB_RE.test(v) || !(v.startsWith('/') || v.startsWith('~'))) return false;
  if (input.selectionStart < v.length) return true;
  const cut = v.lastIndexOf('/');
  if (cut < 0 || cut === v.length - 1 || tabAddedNothing === v) return false;
  const path = namesKey(v.slice(0, cut) || '/');
  const known = path === null ? null : F.names.get(path);
  if (!known || (known.more && known.entries.length < NAMES_MAX)) return true;
  return completionOf(v, known).done !== null;
}

/** Rules made on this page before rules lived in policy.yaml: one button
 *  moves them there, unchanged, so they get History and Undo like the rest. */
function renderMoveNotice() {
  const box = document.getElementById('files-move');
  clear(box);
  const labels = (S.secrets && S.secrets.panel && S.secrets.panel.labels) || [];
  const count = labels.filter((l) => l.source && l.source !== 'policy-file').length;
  box.hidden = count === 0;
  if (!count) return;
  box.append(el('span', { text: n(count, 'rule was', 'rules were') + ' made on this page before rules were kept in policy.yaml. Changes to them are not listed under Rule changes and cannot be undone. ' }));
  box.append(el('button', { type: 'button', class: 'btn small', text: 'Move them into policy.yaml', onclick: async (e) => {
    if (!window.confirm('Move ' + n(count, 'rule', 'rules') + ' into policy.yaml? Protection does not change. Afterwards they are changed and undone like any other rule; the move itself cannot be undone.')) return;
    // The focus stays in Your rules (settingsPlace): the heading once the
    // notice is gone; the button, described, after a refusal, whose words
    // are shown here (Changes to save, hidden while nothing waits, said
    // nothing until 2026-10-11).
    const place = settingsPlace(e.target);
    e.target.disabled = true;
    const r = await apiPost('files/move-page-rules');
    if (!r.ok) {
      showAskError(box, refusalText(r, 'could not move the rules'));
      settingsRefocus(place, box);
      return;
    }
    RULES_READS.wrote();
    rulesNotice('Moved ' + n(r.data.moved, 'rule', 'rules') + ' into policy.yaml.', null);
    await loadRules();
    if (F.path) await openFolder(F.path);
    settingsRefocus(place);
  } }));
}

/** The explorer after the rules are read: the tree, the list (its own-model
 *  column follows the declared models), and on the first read the view last
 *  used and any changes still waiting. */
function renderExplorer() {
  renderLabeled();
  renderMoveNotice();
  if (!F.started) {
    F.started = true;
    const last = lsGet(FILES_VIEW_KEY);
    // A page from before the panels were separate remembered 'suggested'.
    setFilesView(last === 'all' ? 'all' : 'labeled');
    if (lsGet(SUGG_OPEN_KEY) === '1' || last === 'suggested') setSuggestedOpen(true);
    renderPending();
    if (F.pending.size) refreshImpact();
    return;
  }
  if (F.data || F.typed) renderFiles();
}

function wireLockForm() {
  const input = document.getElementById('lock-path');
  restorePending();
  restoreSkipped();
  document.getElementById('rules-add').addEventListener('click', () => setFilesView(F.view === 'all' ? 'labeled' : 'all'));
  document.getElementById('rules-add-close').addEventListener('click', () => setFilesView('labeled'));
  document.getElementById('suggest-open').addEventListener('click', () => setSuggestedOpen(document.getElementById('files-suggested-view').hidden));
  document.getElementById('suggest-form').addEventListener('submit', (e) => { e.preventDefault(); scanForKeys(); });
  document.getElementById('suggest-model-tier').addEventListener('change', renderModelPicker);
  document.getElementById('suggest-model-run').addEventListener('click', previewModel);
  document.getElementById('suggest-model-cancel').addEventListener('click', cancelModelPreview);
  document.getElementById('suggest-model-send').addEventListener('click', sendModel);
  // Escape in the preview is Cancel: a plain one, and not while a send is
  // on its way (Cancel is off then too).
  document.getElementById('suggest-model-preview').addEventListener('keydown', (e) => {
    if (!plainEscape(e) || G.sending) return;
    e.preventDefault();
    cancelModelPreview();
  });
  document.getElementById('files-home').addEventListener('click', () => { setFilesView('all', null, true); openFolder('~'); });
  const hidden = document.getElementById('files-hidden');
  hidden.checked = lsGet(FILES_HIDDEN_KEY) !== '0';
  hidden.addEventListener('change', () => { lsSet(FILES_HIDDEN_KEY, hidden.checked ? '1' : '0'); renderFiles(); });
  document.getElementById('files-labeled').addEventListener('change', renderFiles);
  document.getElementById('files-filter').addEventListener('input', renderFiles);
  document.getElementById('files-list').addEventListener('keydown', onListKey);

  document.getElementById('files-go').addEventListener('submit', async (e) => {
    e.preventDefault();
    const v = input.value.trim();
    if (!v) return;
    if (F.view !== 'all') setFilesView('all', null, true);
    if (!v.startsWith('/') && !v.startsWith('~') && !v.startsWith('**/')) {
      filesNote('Give the full path, starting with / or ~, or a pattern starting with **/.');
      return;
    }
    if (GLOB_RE.test(v)) { showTyped({ path: v, kind: 'pattern' }); return; }
    await openFolder(v, { typed: true });
  });
  input.addEventListener('keydown', (e) => {
    if (e.key !== 'Tab' || e.shiftKey || !tabCompletes(input)) return;
    e.preventDefault();
    // What typing added is taken: the caret goes after it.
    const v = input.value;
    input.setSelectionRange(v.length, v.length);
    if (v.endsWith('/')) return;
    completePath(input, true).then((added) => { if (!added && input.value === v) tabAddedNothing = v; });
  });
  input.addEventListener('input', (e) => {
    tabAddedNothing = null;
    if (e.inputType && e.inputType.startsWith('insert')) completePath(input, false);
  });
  document.getElementById('files-discard').addEventListener('click', () => {
    const had = barPlace();
    // Discard skips the suggestions too; each can be ticked again.
    for (const sg of suggestedPending()) G.skip.add(sg.id);
    saveSkipped();
    renderSuggested();
    F.pending.clear();
    pendingChanged();
    barRefocus(had);
  });
  document.getElementById('files-save').addEventListener('click', saveFileChanges);
  trackBarRoom();
}

/** Quick starts: home and the folders the agents worked in. */
function renderFileStarts() {
  const box = document.getElementById('files-starts');
  clear(box);
  const seen = new Set();
  const folders = ((S.home && S.home.agents) || []).map((a) => a.cwd).filter((c) => c && !seen.has(c) && seen.add(c)).slice(0, 5);
  box.hidden = folders.length === 0;
  if (!folders.length) return;
  box.append(el('span', { class: 'dim', text: 'Where your agents worked:' }));
  for (const f of folders) box.append(el('button', { type: 'button', class: 'btn small', text: shortPath(f), title: f, onclick: () => openFolder(f) }));
}

// ── Suggested: keys Mandu's scan found (dashboard.md §4.25r, plan 14 §5.4) ──
// The third view of the explorer. Mandu's scans read the git history and the
// files of the projects the agents worked in, and the home folder when asked
// ("Also look in your home folder", plan 14 §13.6), in the protection
// service, never here, and file what no rule covers yet as suggestions: a
// rule that hides a file, or the old versions of one, from the AI. A file
// found as it is now (`source: "workspace"`) is an ordinary row: no commits,
// and the softer advice to replace the key. Each suggestion is a change waiting
// in Changes to save, ticked, as if the person had clicked its label;
// unticking skips it (remembered in this browser), and Save applies the
// ticked ones (POST suggestions/apply), one change each in History. Every
// suggestion only adds protection, so Save never asks the weaker-change
// question for them. A row opens in place to what the scan found, when, the
// advice to replace the key, the lines Save adds to policy.yaml, and "Not a
// secret" (POST suggestions/dismiss: Mandu will not suggest it again). The
// page shows only what the server sends: paths, commit ids, the kind of key
// in words and its masked start, never a key.
const G = {
  rows: [],            // the pending suggestions (server rows, SuggestionRowVM)
  loaded: false,       // GET suggestions answered at least once
  error: null,         // why they could not be read
  scan: null,          // the scan this dashboard started: { running, summary, error, roots, … }
  shown: false,        // the view was opened on this page load: its ticks wait in Changes to save
  skip: new Set(),     // ids the person unticked (skipped), kept in this browser
  open: null,          // the opened row (its id)
  yaml: false,         // its policy.yaml lines are shown (Show in policy.yaml)
  posting: false,      // Scan for keys' POST is on its way: the button stays off
  scanFocus: false,    // Scan for keys had the focus when it went off: it waits on the heading
  poll: null,          // the timer re-reading while a scan runs
  loading: null,       // the read in flight
  loadingAt: 0,        // the count of changes' lists taken when it was asked
  wrote: 0,            // how many changes' lists were taken (setWritten)
  sig: null,           // what the last read drew (null: a change's list was drawn since)
  denied: false,       // refused (no admin session, an older service): the poll stops asking
  model: null,         // the model picker the server offers (ModelPickerVM), or null
  preview: null,       // the model preview on screen (ModelPreviewVM), or null
  sending: false,      // a model run is being followed
};
const SUGG_SKIP_KEY = 'mandu.files.skipped';
const SUGGESTED_BY = 'Suggested by Mandu\'s scan';
const SCAN_LABEL = 'Scan for keys';
// A scan the protection service cut short by stopping: the scan's own lead
// (server/suggestion-routes.ts), then the failed dial or the closed
// connection in its client's words, which the page says in its own. The
// line is drawn from a read that answered, so the service runs again.
const SCAN_CUT = /^The scan did not finish: /;
const SCAN_STOPPED_WORDS = 'The scan did not finish because the protection service stopped. Press ' + SCAN_LABEL + ' to try again.';

function restoreSkipped() {
  try {
    const list = JSON.parse(lsGet(SUGG_SKIP_KEY) || '[]');
    if (Array.isArray(list)) for (const id of list) if (typeof id === 'string') G.skip.add(id);
  } catch { /* a damaged entry: nothing skipped */ }
}
function saveSkipped() {
  // Only ids still waiting are worth remembering.
  const live = new Set(G.rows.map((s) => s.id));
  const keep = [...G.skip].filter((id) => !G.loaded || live.has(id));
  if (keep.length) lsSet(SUGG_SKIP_KEY, JSON.stringify(keep)); else lsDel(SUGG_SKIP_KEY);
}

function isTicked(s) { return !!s.applicable && !G.skip.has(s.id); }
/** The ticked suggestions, once the view has been opened: what Save applies. */
function suggestedPending() { return G.shown ? G.rows.filter(isTicked) : []; }

/** Read the suggestions (the poll, the view, after a scan). A change made
 *  on the card answers with the server's list (setWritten), newer than a
 *  read asked before that answer came: such a read's answer, or its
 *  failure, is dropped, and a call made meanwhile reads again rather than
 *  wait on it (dashboard.md §4.25 *A read asked before a change never draws
 *  over it*): never a key marked Not a secret, or saved, back in the list. */
async function loadSuggestions() {
  if (G.loading && G.loadingAt === G.wrote) return G.loading;
  const at = G.wrote;
  const read = (async () => {
    const r = await apiGetControl('suggestions').catch(() => null);
    if (at !== G.wrote) return;
    if (r && r.ok && r.data && Array.isArray(r.data.suggestions)) {
      G.error = null;
      G.denied = false;
      setSuggestions(r.data);
    } else {
      G.error = refusalText(r, 'Suggestions could not be read' + (r ? ' (' + r.status + ')' : '') + '.');
      G.denied = !!(r && (r.status === 403 || r.status === 501));
    }
    G.loaded = true;
    // The poll reads every few seconds: redraw only what changed, so an
    // opened row stays as the person left it.
    const sig = JSON.stringify([G.rows, G.scan, G.error]);
    if (sig === G.sig) return;
    G.sig = sig;
    renderSuggestionViews();
  })();
  G.loading = read;
  G.loadingAt = at;
  try { await read; } finally { if (G.loading === read) G.loading = null; }
}

/** The list a change answered (a scan, Save, Not a secret, a model run's
 *  step): taken, and newer than a read on its way (loadSuggestions). The
 *  page draws it, so the next read is drawn even when it lists what the
 *  last read did (a key Undo brought back). */
function setWritten(d) {
  G.wrote++;
  G.sig = null;
  setSuggestions(d);
}

/** A listing the server sent (the GET, or after a scan, Save or dismissal). */
function setSuggestions(d) {
  if (Array.isArray(d.suggestions)) G.rows = d.suggestions;
  if (d.scan !== undefined) G.scan = d.scan;
  if (d.model !== undefined) { G.model = d.model; renderModelPicker(); }
  G.loaded = true;
  if (G.open && !G.rows.some((s) => s.id === G.open)) G.open = null;
  saveSkipped();
  // While a scan runs, read again until it ends.
  if (G.scan && G.scan.running && !G.poll) G.poll = setTimeout(() => { G.poll = null; loadSuggestions(); }, 3000);
}

/** Everything that shows the suggestions: the badge, the Approvals card, the
 *  view, and Changes to save. */
function renderSuggestionViews() {
  const count = G.rows.length;
  const badge = document.getElementById('files-suggested-count');
  if (badge) badge.textContent = count ? String(count) : '';
  const line = document.getElementById('suggested-line');
  if (line) line.textContent = count ? 'Possible keys in ' + suggestionWhere(G.rows) + ' that no rule covers yet.' : 'Possible keys in your projects that no rule covers yet.';
  renderSuggestionCard();
  renderSuggested();
  renderPending();
}

/** Where the waiting suggestions were found, for the Approvals card: "this
 *  project's git history", "the files of 2 projects", "your home folder". */
function suggestionWhere(rows) {
  const hist = rows.some((s) => s.source !== 'workspace' && s.source !== 'sensitivity-label' && s.source !== 'model-names');
  const files = rows.some((s) => s.source === 'workspace' || s.source === 'sensitivity-label' || s.source === 'model-names');
  const what = hist && files ? 'files and git history' : files ? 'files' : 'git history';
  const repos = new Set(rows.map((s) => s.repo));
  if (repos.size === 1 && repos.has('~')) return 'your home folder' + (hist ? '\'s ' + what : '');
  return repos.size === 1 ? 'this project\'s ' + what : 'the ' + what + ' of ' + repos.size + ' projects';
}

/** "Mandu found N possible keys in this project's files and git history":
 *  one card on Approvals that opens the Suggested view. */
function renderSuggestionCard() {
  const block = document.getElementById('approvals-suggestions-block');
  const host = document.getElementById('approvals-suggestions');
  if (!block || !host) return;
  clear(host);
  const count = G.rows.length;
  block.hidden = count === 0;
  if (!count) return;
  const where = suggestionWhere(G.rows);
  const card = el('div', { class: 'ask expanded suggestion-card' });
  const top = el('div', { class: 'ask-top' });
  top.append(el('div', { class: 'ask-icon' }, svg(ICON.lock)));
  const body = el('div', { class: 'ask-body' });
  const sentence = el('div', { class: 'ask-sentence', text: 'Mandu found ' + n(count, 'possible key', 'possible keys') + ' in ' + where });
  body.append(sentence);
  nameBy(card, sentence);
  body.append(el('div', { class: 'ask-sub', text: 'No rule covers them yet, so the AI can still read them. Review them and press Save to hide them from the AI.' }));
  top.append(body);
  card.append(top);
  const actions = el('div', { class: 'ask-actions' });
  actions.append(el('button', { type: 'button', class: 'btn primary', id: 'approvals-suggestions-open', text: 'Review them', onclick: openSuggested }));
  card.append(actions);
  host.append(card);
}

/** The Rules page with Keys Mandu found open, at that card. */
function openSuggested() {
  lsSet(SUGG_OPEN_KEY, '1');
  return openAtCard('rules', 'suggested-block', () => { if (F.started) setSuggestedOpen(true); });
}

/** Opens `page` scrolled to its card `id` once the page's reads have drawn
 *  (dashboard.md §4.25r *A link opens at its card*): what they draw above the
 *  card (your rules on Rules, Protection and Models on Settings) would push
 *  it down, off the screen, after a scroll made at the click. A scroll, key
 *  or tap by the person before then, or another page, is left alone. `opened`
 *  runs as the page opens; `focus`, given the card, names what takes the
 *  focus there (by default the card's heading). */
async function openAtCard(page, id, opened, focus) {
  const load = setPage(page, true);
  // The address names the card (§4.25 *Section links*): a reload or a copy
  // of it opens there again.
  const key = sectionKey(page, id);
  if (key) {
    S.section = key;
    try { history.replaceState(history.state, '', stateHref()); } catch { /* the page's own address stays */ }
  }
  if (opened) opened();
  return landAtCard(load, id, focus);
}
/** Scrolls the card `id` of the page shown to the top once `load` (the
 *  page's reads) has drawn, and gives `focus(card)` the focus, by default
 *  the card's heading; unless the person scrolled, pressed a key or tapped
 *  meanwhile, or another page opened. */
async function landAtCard(load, id, focus = (card) => card && card.querySelector('h2')) {
  const visit = S.visit;
  let moved = false;
  const theirs = () => { moved = true; };
  const kinds = ['wheel', 'touchmove', 'keydown', 'pointerdown'];
  for (const k of kinds) window.addEventListener(k, theirs, true);
  try { await load; } catch { /* each card says what it could not read */ }
  for (const k of kinds) window.removeEventListener(k, theirs, true);
  if (moved || S.visit !== visit) return;
  const card = document.getElementById(id);
  if (card && card.scrollIntoView) card.scrollIntoView({ block: 'start' });
  focusMarked(focus(card), true);
}

/** The row of links under the titles of Rules and Settings, one per card
 *  (dashboard.md §4.25 *Section links*). A click scrolls its card to the
 *  top, gives the card's heading the focus and puts the card's key in the
 *  address, replaced, so Back still leaves the page. A modifier click is
 *  the browser's: the page at that card, in a new tab or window. */
function drawSectionLinks() {
  for (const nav of document.querySelectorAll('nav.section-links[data-sections]')) {
    const page = nav.dataset.sections;
    const list = el('ul');
    for (const [key, id, words] of SECTIONS[page] || []) {
      list.append(el('li', null, el('a', { href: routeHref(page) + '#' + key, 'data-section': key, text: words, onclick: (e) => {
        if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button > 0) return;
        e.preventDefault();
        goToSection(page, key, id);
      } })));
    }
    clear(nav);
    nav.append(list);
  }
}
/** The card `id` of the page shown, scrolled to the top with its heading
 *  focused, and its key in the address. A card the page hides (Who may get
 *  your secrets before the rules are read) leaves the page where it is. */
function goToSection(page, key, id) {
  if (S.page !== page) return openAtCard(page, id);
  S.section = key;
  try { history.replaceState(history.state, '', stateHref()); } catch { /* the page's own address stays */ }
  const card = document.getElementById(id);
  const head = card && !card.hidden && card.querySelector('h2');
  if (!head) return;
  if (card.scrollIntoView) card.scrollIntoView({ block: 'start' });
  head.setAttribute('tabindex', '-1');
  head.focus({ preventScroll: true });
  S.marked = head;
}

/** The line beside Scan: its words, or a finished scan as the server sent
 *  it, parts with the place it names as a link (dashboard.md §4.25r). */
function scanStatus(text, parts) {
  const node = document.getElementById('suggest-status');
  clear(node);
  node.append(textParts(parts, text || ''));
}

/** Settings, at its Sensitivity labels card: where the line under Scan for
 *  keys says a level is set. */
function openLabels() {
  return openAtCard('settings', 'settings-labels-block');
}

/** Settings, at its Protection card: where the top bar's words lead while
 *  protection is not plainly on (dashboard.md §4.25 *The top bar says on or
 *  off*). The focus goes to the switch, or to the card's heading while the
 *  switch cannot be pressed (the setting could not be read). */
function openProtection() {
  return openAtCard('settings', 'settings-protection-block', null, (card) => {
    const sw = document.getElementById('switch-protection');
    return sw && !sw.disabled ? sw : card && card.querySelector('h2');
  });
}

// ── the model picker (dashboard.md §4.25t, plan 14 §14.5, §14.11) ──────────
// Off by default. Names only: a model the person chose reads the NAMES of
// the files, never what they hold. Contents: only a model of the person's
// own reads the start of the documents their rules leave unprotected. A run
// first shows exactly what would be sent (the names as sent, or the files
// and their sizes, never their text) and where it goes; Send sends exactly
// that, once. Both are "not offered yet" unless the server offers them. The
// page shows only the server's words and counts: nothing a model wrote.

function modelStatus(text) { document.getElementById('suggest-model-status').textContent = text || ''; }

/** The picker from the server's offer: which choices can be made and why not. */
function renderModelPicker() {
  const m = G.model;
  const sel = document.getElementById('suggest-model-tier');
  const own = document.getElementById('suggest-model-own');
  const run = document.getElementById('suggest-model-run');
  const why = document.getElementById('suggest-model-why');
  const opts = (m && m.options) || [];
  for (const o of sel.options) {
    const vm = opts.find((x) => x.value === o.value);
    o.disabled = o.value !== 'off' && !(vm && vm.enabled);
    o.title = vm && vm.why ? vm.why : '';
  }
  if (sel.selectedOptions[0] && sel.selectedOptions[0].disabled) sel.value = 'off';
  const picked = opts.find((x) => x.value === sel.value);
  const owned = (m && m.ownModels) || [];
  own.hidden = sel.value !== 'contents' || owned.length < 2;
  if (!own.hidden && own.options.length !== owned.length) {
    clear(own);
    for (const name of owned) own.append(el('option', { value: name, text: name }));
  }
  run.disabled = sel.value === 'off' || G.sending || !(picked && picked.enabled);
  // Why a choice is unavailable, else what the picker does.
  const off = opts.filter((x) => x.value !== 'off' && !x.enabled && x.why);
  why.textContent = !m ? '' : !m.offered ? m.hint : sel.value === 'off' && off.length ? m.hint + ' ' + off.map((x) => x.label + ': ' + x.why).join(' ') : m.hint;
}

function closeModelPreview(status) {
  G.preview = null;
  document.getElementById('suggest-model-preview').hidden = true;
  if (status !== undefined) modelStatus(status);
  renderModelPicker();
}

// The preview keeps the keyboard focus (dashboard.md §4.25t *The preview
// keeps the focus*). It opens with the focus on its headline, the sentence
// Send agrees to, never on Send: a second Enter sends nothing. Closed, it
// gives the focus back to what opened it. The focus moves only from where
// the press left it: a focus moved elsewhere meanwhile stays.
function modelHead() { return document.getElementById('suggest-model-head'); }
function inModelPreview() {
  const a = document.activeElement;
  return !!a && document.getElementById('suggest-model-preview').contains(a);
}
/** The focus is still on `x` or fell from it: a browser drops the focus of
 *  a button turned off or hidden (jsdom keeps it there). */
function focusLeftOn(x) {
  return focusFell() || document.activeElement === x;
}
/** Back to See what it would send, else the picker, else the card's
 *  heading. */
function modelPreviewBack() {
  const run = document.getElementById('suggest-model-run');
  const tier = document.getElementById('suggest-model-tier');
  const to = [run, tier].find(reachable);
  if (to) to.focus();
  else focusThere(document.getElementById('suggested-title'));
}
/** Cancel, Close, or Escape: nothing is sent. */
function cancelModelPreview() {
  const had = inModelPreview();
  closeModelPreview('Nothing was sent.');
  if (had) modelPreviewBack();
}

/** Ask the server what a run would send (it builds and keeps it). */
async function previewModel() {
  const tier = document.getElementById('suggest-model-tier').value;
  if (tier !== 'names' && tier !== 'contents') return;
  const body = { tier };
  const root = document.getElementById('suggest-root').value.trim();
  if (root) body.root = root;
  if (document.getElementById('suggest-home').checked) body.includeHome = true;
  const own = document.getElementById('suggest-model-own');
  if (tier === 'contents' && !own.hidden && own.value) body.endpoint = own.value;
  const run = document.getElementById('suggest-model-run');
  const had = document.activeElement === run;
  run.disabled = true;
  modelStatus('Looking at what it would send…');
  document.getElementById('suggest-error').textContent = '';
  const r = await apiPost('suggestions/model/preview', body);
  renderModelPicker();
  const back = had && focusLeftOn(run);
  if (!r.ok || !r.data || !r.data.preview) {
    modelStatus('');
    setWords(document.getElementById('suggest-error'), refusalText(r, 'could not work out what it would send (' + r.status + ')'));
    // Back to the button, on again: the error line describes it.
    if (back) modelPreviewBack();
    return;
  }
  showModelPreview(r.data.preview);
  if (back) focusThere(modelHead());
}

/** The preview: what is sent, where it goes, what was left out; then Send. */
function showModelPreview(p) {
  G.preview = p;
  const box = document.getElementById('suggest-model-preview');
  modelHead().textContent = p.empty || p.headline;
  document.getElementById('suggest-model-where').textContent = p.empty ? '' : 'Where it goes: ' + p.where + '.';
  const roots = document.getElementById('suggest-model-roots');
  clear(roots);
  for (const r of p.empty ? [] : p.roots || []) roots.append(el('li', { text: r }));
  document.getElementById('suggest-model-caption').textContent = p.empty ? '' : p.caption;
  const list = document.getElementById('suggest-model-list');
  clear(list);
  // It scrolls, so it is named (dashboard.md §4.25): by the caption's words,
  // not the caption, drawn in capitals a browser would put in the name.
  if (p.empty) list.removeAttribute('aria-label');
  else list.setAttribute('aria-label', p.caption);
  for (const it of p.empty ? [] : p.list || []) list.append(el('li', {}, el('code', { text: it.text }), it.size ? el('span', { class: 'dim', text: '  ' + it.size }) : null));
  const notes = document.getElementById('suggest-model-notes');
  clear(notes);
  for (const n of p.notes || []) notes.append(el('li', { text: n }));
  const send = document.getElementById('suggest-model-send');
  send.hidden = !!p.empty || !p.digest;
  send.disabled = false;
  document.getElementById('suggest-model-cancel').textContent = p.empty ? 'Close' : 'Cancel';
  box.hidden = false;
  modelStatus(p.empty ? '' : 'Nothing is sent until you press Send.');
  if (box.scrollIntoView) box.scrollIntoView({ block: 'nearest' });
}

/** Send exactly the preview (its digest), then follow the run. Send and
 *  Cancel are off while it is on its way: it cannot be called back, and
 *  Cancel would say "Nothing was sent." of names already sent. */
async function sendModel() {
  const p = G.preview;
  if (!p || !p.digest || G.sending) return;
  G.sending = true;
  const box = document.getElementById('suggest-model-preview');
  const cancel = document.getElementById('suggest-model-cancel');
  const had = inModelPreview();
  document.getElementById('suggest-model-send').disabled = true;
  cancel.disabled = true;
  // Both buttons are off: the focus waits on the headline.
  if (had) focusThere(modelHead());
  modelStatus('Sending…');
  let refused = false;
  try {
    for (;;) {
      const r = await apiPost('suggestions/model/send', { digest: p.digest, tier: p.tier });
      if (!r.ok || !r.data || !r.data.run) {
        setWords(document.getElementById('suggest-error'), refusalText(r, 'could not send it (' + r.status + ')'));
        modelStatus('');
        refused = true;
        break;
      }
      modelStatus(r.data.run.line);
      if (Array.isArray(r.data.suggestions)) { setWritten(r.data); renderSuggestionViews(); }
      if (!r.data.run.running) {
        G.preview = null;
        box.hidden = true;
        break;
      }
      await new Promise((res) => setTimeout(res, 2000));
    }
  } finally {
    G.sending = false;
    cancel.disabled = false;
    renderModelPicker();
  }
  // From where it waited: a run that ended goes back to what opened the
  // preview; a refusal keeps the preview, and Cancel, on again, takes the
  // focus, described by the error line.
  if (!had || !(focusLeftOn(modelHead()) || inModelPreview())) return;
  if (refused && !box.hidden) cancel.focus({ preventScroll: true });
  else modelPreviewBack();
}

/** The line beside Scan: what the last scan found, or that one runs. */
function renderScanLine() {
  const s = G.scan;
  const btn = document.getElementById('suggest-scan');
  const running = !!(s && s.running);
  scanButtonOff(btn, running || G.posting);
  btn.textContent = running || G.posting ? 'Scanning…' : SCAN_LABEL;
  // Its own POST wrote the line; the answer draws the rest.
  if (G.posting && !running) return;
  if (running) scanStatus('Scanning ' + scanWhere(s.roots && s.roots.length ? s.roots.join(', ') : '', !!s.includeHome) + '… This can take a minute.');
  else if (s && !s.error && s.summary) scanStatus(s.summary, s.summaryParts);
  else scanStatus('');
  setWords(document.getElementById('suggest-error'), s && !running && s.error ? scanErrorText(s.error) : (G.error || ''));
}

/** Scan for keys is off while a scan runs, and a browser drops the focus of
 *  a button turned off: until 2026-10-11 a scan left a screen reader on
 *  <body>, and until 2026-10-13 it stayed there while the scan ran. Now a
 *  focused Scan for keys gives the focus to the heading of the card before
 *  it goes off, as Send gives it to the headline of the preview, and the
 *  line beside it says what runs. On again, it gets the focus back if the
 *  focus still waits there or fell meanwhile; a focus moved elsewhere
 *  stays, also once something brings it back to the heading. Its error
 *  line describes it (index.html), so a refusal is read with it. */
function scanButtonOff(btn, off) {
  const head = document.getElementById('suggested-title');
  if (off && document.activeElement === btn) {
    G.scanFocus = true;
    focusThere(head);
    head.addEventListener('focusout', scanFocusMoved);
  }
  btn.disabled = off;
  if (off || !G.scanFocus) return;
  scanWaitEnds(head);
  if (focusLeftOn(head) && !btn.closest('[hidden]')) btn.focus({ preventScroll: true });
}
/** The focus left the heading for another place on the page: the person
 *  moved it, so the end of the scan leaves it there. */
function scanFocusMoved(e) {
  if (e.relatedTarget) scanWaitEnds(e.currentTarget);
}
function scanWaitEnds(head) {
  G.scanFocus = false;
  head.removeEventListener('focusout', scanFocusMoved);
}

/** A finished scan's error: a stopped protection service in the page's
 *  words, any other (another scan running, a refusal) as the server wrote it. */
function scanErrorText(error) {
  return SCAN_CUT.test(error) && UNREACHABLE_REFUSAL.test(error.replace(SCAN_CUT, '')) ? SCAN_STOPPED_WORDS : error;
}

/** "~/proj and your home folder", for the line while a scan runs. */
function scanWhere(folders, home) {
  if (!folders) return home ? 'your home folder' : 'the projects your agents worked in';
  return home ? folders + ' and your home folder' : folders;
}

async function scanForKeys() {
  const root = document.getElementById('suggest-root').value.trim();
  const home = !!document.getElementById('suggest-home').checked;
  const btn = document.getElementById('suggest-scan');
  // Off until the answer: a redraw meanwhile (a tick, the poll) keeps it off.
  G.posting = true;
  scanButtonOff(btn, true);
  btn.textContent = 'Scanning…';
  document.getElementById('suggest-error').textContent = '';
  scanStatus('Scanning ' + scanWhere(root || (home ? '' : 'the projects your agents worked in'), home) + '… This can take a minute.');
  const body = {};
  if (root) body.root = root;
  if (home) body.includeHome = true;
  const r = await apiPost('suggestions/scan', body);
  G.posting = false;
  if (!r.ok || !r.data) {
    btn.textContent = SCAN_LABEL;
    scanStatus('');
    setWords(document.getElementById('suggest-error'), refusalText(r, 'could not scan (' + r.status + ')'));
    if (r.data && r.data.needsRoot) document.getElementById('suggest-root').focus();
    scanButtonOff(btn, false);
    return;
  }
  G.error = null;
  setWritten(r.data);
  renderSuggestionViews();
}

/** The label a suggestion gives: a chip (a suggestion only ever hides a
 *  file, or gives it the level its sensitivity label is mapped to). The tick
 *  saves or skips it. */
function suggestionChip(s) {
  const level = s.level || 'no-model';
  const b = LEVEL_BUTTONS.find((x) => x.level === level) || LEVEL_BUTTONS[0];
  return el('span', { class: 'label-chip ' + chipClass(level), title: b.term + '. ' + b.meaning + ' ' + (s.by || SUGGESTED_BY) + '.', text: b.text });
}

/** The words that name a suggestion on its controls and in what the page
 *  says of it ("Save app.conf", "Not a secret: app.conf"): the row's name,
 *  or, where another suggestion has the same name (two app.conf in
 *  different folders, or their old versions), its path, so no two rows'
 *  controls share a name and a question says which file it means. */
function suggestionName(s) {
  if (!G.rows.some((r) => r.id !== s.id && r.name === s.name)) return s.name;
  const p = s.parent;
  if (p && p.name && s.name.endsWith(p.name)) return s.name.slice(0, s.name.length - p.name.length) + p.display;
  return s.kind === 'versions' ? s.name + ' (' + s.display + ')' : s.display;
}

function tickSuggestion(s, on) {
  if (!s.applicable) return;
  if (on) G.skip.delete(s.id); else G.skip.add(s.id);
  saveSkipped();
  renderSuggested();
  renderPending();
}

function suggestionRow(s) {
  const ticked = isTicked(s);
  const named = suggestionName(s);
  const isOpen = G.open === s.id;
  const row = el('div', {
    class: 'row file suggested' + (s.historyOnly ? ' history-only' : '') + (s.kind === 'versions' ? ' sub' : '') + (ticked ? ' selected' : '') + (isOpen ? ' open' : ''),
    role: 'listitem', 'data-id': s.id, 'data-path': s.path, style: '--depth:' + (s.kind === 'versions' ? 1 : 0),
  });
  const box = el('input', { type: 'checkbox', class: 'file-tick', 'aria-label': (ticked ? 'Skip ' : 'Save ') + named });
  box.checked = ticked;
  box.disabled = !s.applicable;
  box.addEventListener('change', () => tickSuggestion(s, box.checked));
  row.append(box);
  const name = el('div', { class: 'file-name' }, el('code', { text: s.name, title: s.display }));
  if (s.tag) name.append(' ', el('span', { class: 'file-tag history', text: s.tag }));
  const sub = [el('div', { class: 'dim file-from', text: s.kind === 'versions' ? s.sentence : s.display })];
  if (!s.applicable) sub.push(el('div', { class: 'dim file-from', text: 'Cannot be saved yet. Open it to see why.' }));
  else if (ticked) sub.push(el('div', { class: 'file-pending', text: 'Will be: ' + levelText(s.level || 'no-model', []) + ' (not saved)' }));
  else sub.push(el('div', { class: 'dim file-from', text: 'Skipped: not saved' }));
  row.append(el('div', { class: 'file-cell' },
    el('span', { class: 'row-icon' }, svg(ICON.file, 18)),
    el('div', { class: 'file-text' }, name, ...sub)));
  const toggle = () => {
    G.open = G.open === s.id ? null : s.id;
    G.yaml = false;
    renderSuggested();
    const opened = document.querySelector('#files-suggested-list .file-detail');
    if (opened && opened.scrollIntoView) opened.scrollIntoView({ block: 'nearest' });
  };
  row.append(suggestionChip(s), el('div', { class: 'file-hosts' }), moreButton(isOpen, named, toggle));
  row.addEventListener('click', (e) => {
    if (e.target.closest && e.target.closest('input, button, a')) return;
    toggle();
  });
  return row;
}

/** The file old versions sit under: shown as it is now, which does not change. */
function suggestionParent(p) {
  return el('div', { class: 'row file suggested-parent', role: 'listitem', 'data-path': p.path },
    el('span'),
    el('div', { class: 'file-cell' }, el('span', { class: 'row-icon' }, svg(ICON.file, 18)),
      el('div', { class: 'file-text' }, el('div', { class: 'file-name' }, el('code', { text: p.name, title: p.display })),
        el('div', { class: 'dim file-from', text: p.display + ' as it is now: not changed' }))),
    el('span'), el('span'), el('span'));
}

/** The opened row: what the scan found, when, what Save does, the advice to
 *  replace the key, the policy.yaml lines, and Not a secret. */
function suggestionDetail(s) {
  const named = suggestionName(s);
  const box = el('div', { class: 'file-detail', role: 'listitem', 'aria-label': 'About ' + named, style: '--depth:' + (s.kind === 'versions' ? 1 : 0) });
  const main = el('div', { class: 'file-detail-main' });
  main.append(el('p', { class: 'detail-path', text: s.display + (s.repo ? ' (in ' + s.repo + ')' : '') }));
  main.append(el('p', {}, el('strong', { text: s.sentence })));
  if (s.historyOnly) main.append(el('p', { class: 'dim detail-note', text: 'This file is gone from the project; only its git history still holds it.' }));
  if (s.note) main.append(el('p', { class: 'dim detail-note', text: s.note }));
  if (s.more && s.more.length) main.append(el('p', { class: 'dim detail-note', text: 'The same key was also at ' + s.more.join(', ') + '.' }));
  main.append(el('p', { class: 'suggestion-impact', text: s.impact }));
  if (s.blocked) main.append(el('p', { class: 'rule-warn', role: 'note', text: s.blocked }));
  // A file found as it is now: nothing shows the key left the machine, so
  // the advice is the softer one, and not a warning.
  if (s.rotate) main.append(el('p', { class: s.rotateSoft ? 'detail-note suggestion-advice' : 'rule-warn', role: 'note', text: s.rotate }));
  main.append(el('p', { class: 'dim detail-note', text: s.by }));
  const links = el('div', { class: 'detail-links' });
  const lines = el('div', { class: 'detail-source' });
  // Named by its row, and Hide while the lines show, as in Your rules
  // (sourceWords). The lines stay shown through a redraw (G.yaml): the
  // button keeps its words, so the focus finds it again (pollRefocus).
  const show = el('button', { type: 'button', class: 'link-btn rule-source-btn' });
  const drawLines = () => {
    show.setAttribute('aria-expanded', G.yaml ? 'true' : 'false');
    sourceWords(show, G.yaml, named);
    clear(lines);
    if (!G.yaml) return;
    const said = el('p', { class: 'dim detail-note', text: 'Save adds these lines to policy.yaml:' });
    // A box that scrolls, named by the words above it (dashboard.md §4.25).
    lines.append(said, nameBy(el('pre', { class: 'suggestion-yaml' }, el('code', { text: s.yaml })), said));
  };
  show.onclick = () => { G.yaml = !G.yaml; drawLines(); };
  drawLines();
  links.append(show);
  links.append(el('button', { type: 'button', class: 'link-btn rule-source-btn suggestion-dismiss', text: 'Not a secret', 'aria-label': 'Not a secret: ' + named, onclick: (e) => dismissSuggestion(s, e.target) }));
  main.append(links, lines);
  box.append(main);
  // What the scan found, beside it.
  const found = el('div', { class: 'file-why', role: 'region', 'aria-label': 'What the scan found' });
  found.append(el('div', { class: 'detail-cap', text: 'What the scan found' }));
  const dl = el('dl');
  for (const f of s.found || []) {
    const dd = el('dd', {}, el('code', { text: f.mask }));
    if (typeof f.line === 'number') dd.append(' on line ' + f.line);
    dl.append(el('dt', { text: f.words }), dd);
  }
  for (const w of s.when || []) dl.append(el('dt', { text: 'When' }), el('dd', { text: w }));
  found.append(dl);
  box.append(found);
  return box;
}

/** The button goes off during its POST, and a browser drops the focus of a
 *  button turned off, so the focus's place is taken first. Done, the row is
 *  gone: the card's heading (pollRefocus), as Remove in Your rules. Refused:
 *  the button again, described by the card's error line. */
async function dismissSuggestion(s, btn) {
  const named = suggestionName(s);
  if (!window.confirm('Mark ' + named + ' as not a secret? Mandu will not suggest it again, and the AI can still read it.')) return;
  const place = pollPlace(document.getElementById('files-suggested-list'));
  if (btn) btn.disabled = true;
  const r = await apiPost('suggestions/dismiss', { id: s.id });
  if (!r.ok || !r.data) {
    if (btn) btn.disabled = false;
    setWords(document.getElementById('suggest-error'), refusalText(r, 'could not mark it as not a secret (' + r.status + ')'));
    pollRefocus(place);
    if (btn && document.activeElement === btn) btn.setAttribute('aria-describedby', 'suggest-error');
    return;
  }
  G.skip.delete(s.id);
  setWritten(r.data);
  renderSuggestionViews();
  pollRefocus(place);
  rulesNotice(named + ' is marked as not a secret. Mandu will not suggest it again.', null);
}

/** Every tick, ⋯ and poll draws the list again from nothing: the focus's
 *  place in it is given back after the draw, only if it fell (pollPlace /
 *  pollRefocus): the row's tick box or ⋯, an opened row's button, else the
 *  card's heading. Until 2026-10-11 each left a screen reader on <body>.
 *  The scan line comes after, so a scan that ends here never takes a
 *  focus the list gives back. */
function renderSuggested() {
  const list = document.getElementById('files-suggested-list');
  if (!list) return;
  const place = pollPlace(list);
  drawSuggested(list);
  pollRefocus(place);
  renderScanLine();
}

function drawSuggested(list) {
  clear(list);
  if (!G.loaded) { list.append(el('div', { class: 'empty-row dim', text: 'Reading the suggestions…' })); return; }
  if (!G.rows.length) {
    if (!G.error) list.append(el('div', { class: 'empty-row dim', text: 'No suggestions. Press ' + SCAN_LABEL + ' to look for keys your rules do not cover.' }));
    return;
  }
  const withDetail = (s) => {
    list.append(suggestionRow(s));
    if (G.open === s.id) list.append(suggestionDetail(s));
  };
  // Files first (the ones only in git history lead, as the server sorts
  // them), then old versions of a file under the file.
  for (const s of G.rows) if (s.kind !== 'versions') withDetail(s);
  const parents = new Map();
  for (const s of G.rows) {
    if (s.kind !== 'versions') continue;
    const k = s.parent ? s.parent.path : s.path;
    if (!parents.has(k)) parents.set(k, { parent: s.parent || { path: s.path, display: s.display, name: s.name }, rows: [] });
    parents.get(k).rows.push(s);
  }
  for (const g of parents.values()) {
    list.append(suggestionParent(g.parent));
    for (const s of g.rows) withDetail(s);
  }
}

// ── Describe what you want (policy-surface.md §8.5.2) ─────────────────────
// The sentence goes to a helper model on the server; the page shows what came
// back as plain rows (written by the server from the rule itself, never by the
// model), marks the ones that loosen protection, and changes nothing until
// Apply. The helper's own words (`note`) come last and as text.
// The keyboard focus stays in the card (dashboard.md §4.25 *Describe what
// you want keeps the focus*): `focus` while it waits on the heading.
const D = { ctrl: null, sentence: '', focus: false };

function wireDescribe() {
  const form = document.getElementById('describe-form');
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    suggestRules(document.getElementById('describe-text').value.trim());
  });
  document.getElementById('describe-cancel').addEventListener('click', () => { if (D.ctrl) D.ctrl.abort(); });
}

function describeStatus(text) { document.getElementById('describe-status').textContent = text || ''; }

function setDescribeBusy(on) {
  const submit = document.getElementById('describe-submit');
  const cancel = document.getElementById('describe-cancel');
  const hadCancel = !on && document.activeElement === cancel;
  submit.disabled = on;
  cancel.hidden = !on;
  describeStatus(on ? 'Working out the rules. This can take up to a minute.' : '');
  // Cancel hidden with the focus on it: Suggest rules, on again, takes it.
  if (hadCancel) submit.focus({ preventScroll: true });
}

/** Suggest rules is off while the helper works, up to a minute, and a
 *  browser drops the focus of a button turned off or removed (Describe it
 *  again) to the page: until 2026-10-14 it stayed on <body> all that time.
 *  A press made with the focus on Suggest rules or in the answer drawn
 *  gives it to the card's heading first, as Scan for keys does
 *  (scanButtonOff); the status line says what runs. A focus the person
 *  moves off the heading ends the wait. */
function describeWaits() {
  const a = document.activeElement;
  if (!a || !(a === document.getElementById('describe-submit') || document.getElementById('describe-result').contains(a))) return;
  const head = describeHead();
  D.focus = true;
  focusThere(head);
  head.addEventListener('focusout', describeFocusMoved);
}
function describeHead() { return document.querySelector('#describe-block h2'); }
function describeFocusMoved(e) {
  if (e.relatedTarget) describeWaitEnds();
}
function describeWaitEnds() {
  D.focus = false;
  describeHead().removeEventListener('focusout', describeFocusMoved);
}
/** The answer is drawn: a focus still waiting on the heading, or fallen,
 *  goes to `first` (the suggestion's first line), else to Suggest rules, on
 *  again. `said` (a refusal, an empty answer) describes Suggest rules. */
function describeAnswered(first, said) {
  const submit = document.getElementById('describe-submit');
  if (said) submit.setAttribute('aria-describedby', said.id);
  else submit.removeAttribute('aria-describedby');
  if (!D.focus) return;
  describeWaitEnds();
  if (!focusLeftOn(describeHead())) return;
  if (first) focusThere(first);
  else submit.focus({ preventScroll: true });
}

async function suggestRules(sentence) {
  const host = document.getElementById('describe-result');
  if (!sentence) { describeStatus('Write what you want first.'); return; }
  if (D.ctrl) D.ctrl.abort();
  const ctrl = new AbortController();
  D.ctrl = ctrl;
  D.sentence = sentence;
  describeWaits();
  clear(host);
  host.hidden = true;
  setDescribeBusy(true);
  let r = null;
  let failure = '';
  try {
    r = await apiPost('policy/assistant', { sentence }, ctrl.signal);
  } catch {
    // Only a request this page cancelled throws (answerOf): no answer at
    // all comes back as status 0, which renderDescribeError words.
    failure = 'Cancelled.';
  } finally {
    if (D.ctrl === ctrl) D.ctrl = null;
    setDescribeBusy(false);
  }
  if (!r) { describeStatus(failure); describeAnswered(null, null); return; }
  let first = null;
  if (r.ok) first = renderSuggestion(r.data || {});
  else renderDescribeError(r);
  describeAnswered(first, first ? null : host);
}

function renderDescribeError(r) {
  const host = document.getElementById('describe-result');
  clear(host);
  host.hidden = false;
  const d = r.data || {};
  host.append(el('div', { class: 'ask-error', role: 'alert' }, words(refusalText(r, 'could not suggest rules (' + r.status + ')'))));
  if (r.status === 503 && d.unconfigured) {
    host.append(el('a', { href: routeHref('settings'), 'data-page-link': 'settings', class: 'more', text: 'Open Settings' }));
    return;
  }
  if (r.status === 422) {
    if (Array.isArray(d.problems) && d.problems.length) {
      const ul = el('ul', { class: 'describe-problems' });
      for (const p of d.problems) ul.append(el('li', { text: String(p) }));
      host.append(ul);
    }
    host.append(el('div', { class: 'dim', text: 'Try saying it another way.' }));
  }
}

/** Draws what came back; its first line, or null when nothing did. */
function renderSuggestion(s) {
  const host = document.getElementById('describe-result');
  clear(host);
  host.hidden = false;
  const rows = Array.isArray(s.rows) ? s.rows : [];
  if (!rows.length) {
    host.append(el('div', { class: 'empty', text: 'No rule changes came back. Try saying it another way.' }));
    return null;
  }
  const card = el('div', { class: 'ask expanded suggestion' });
  const first = el('div', { class: 'proposal-k', text: 'Suggested rules' });
  card.append(first);
  const ul = el('ul', { class: 'proposal-rows suggestion-rows' });
  rows.forEach((row, i) => {
    const li = el('li', { class: row.loosens ? 'loosens' : '' });
    for (const p of row.parts || []) li.append(p.kind === 'code' ? nameCode(p.text) : document.createTextNode(p.text));
    if (row.loosens) li.append(el('span', { class: 'tag-loosens', text: 'loosens protection' }));
    // A wide row says so beside its words; the foot says what it opens.
    if (row.overBroad) li.append(el('span', { class: 'tag-loosens tag-wide', text: 'Wide: type ALLOW' }));
    if (row.tryable) {
      const btn = el('button', { type: 'button', class: 'btn small try-row', text: 'Try it' });
      btn.addEventListener('click', () => tryRow(s, i, li, btn));
      li.append(btn);
    }
    ul.append(li);
  });
  card.append(ul);
  if (Array.isArray(s.loosens) && s.loosens.length) {
    card.append(el('div', { class: 'proposal-k', text: 'This would let' }));
    card.append(rowList(s.loosens.map((l) => l.line), 'proposal-let'));
  }
  if (s.note) {
    const says = el('div', { class: 'agent-says' });
    says.append(el('div', { class: 'proposal-k', text: 'The assistant says' }));
    says.append(el('div', { class: 'agent-says-text', text: s.note }));
    card.append(says);
  }
  const apply = el('button', { type: 'button', class: 'btn primary', text: 'Apply', onclick: () => applySuggestion(s, card) });
  const discard = el('button', { type: 'button', class: 'btn', text: 'Discard', onclick: () => {
    const had = card.contains(document.activeElement);
    clear(host);
    host.hidden = true;
    // Its card gone: Suggest rules takes the focus, as after Cancel.
    if (had) document.getElementById('describe-submit').focus({ preventScroll: true });
  } });
  const foot = el('div', { style: 'display:flex;gap:8px;align-items:center;flex-wrap:wrap' });
  if (rows.some((row) => row.overBroad)) {
    apply.disabled = true;
    const input = el('input', { type: 'text', class: 'proposal-confirm', placeholder: 'Type ALLOW to confirm', 'aria-label': 'Type ALLOW to confirm this wide change' });
    input.addEventListener('input', () => { apply.disabled = input.value !== 'ALLOW'; });
    foot.append(wideWhy(s.overBroadWhy, false), input);
  }
  const actions = el('div', { class: 'ask-actions' });
  actions.append(discard, apply);
  foot.append(actions);
  card.append(foot);
  host.append(card);
  return first;
}

/** "Try it" on one suggested row: what happens now, and after applying the
 *  whole suggestion (Test a flow on the server; nothing is written). The
 *  button keeps the focus, described by what came back (focusBack). */
let tryResultSeq = 0;
async function tryRow(s, index, li, btn) {
  const had = document.activeElement === btn;
  btn.disabled = true;
  const prev = li.querySelector('.try-result');
  if (prev) prev.remove();
  const box = el('div', { class: 'try-result', id: 'try-result-' + (++tryResultSeq) });
  const r = await apiPost('policy/assistant/try', { edits: s.edits, index });
  if (r.ok && r.data) {
    for (const [label, parts] of [['Now: ', r.data.now], ['After: ', r.data.after]]) {
      const line = el('div', {}, el('strong', { text: label }));
      for (const p of parts || []) line.append(p.kind === 'code' ? el('code', { text: p.text }) : document.createTextNode(p.text));
      box.append(line);
    }
  } else {
    box.append(el('div', { class: 'warn' }, words(refusalText(r, 'Could not try this row.'))));
  }
  li.append(box);
  btn.disabled = false;
  focusBack(btn, had, box);
}

/** Apply keeps the focus: applied, the line that says so takes it (the card
 *  is gone); refused, Apply has it back, described by the refusal. */
async function applySuggestion(s, card) {
  const host = document.getElementById('describe-result');
  const applyBtn = [...card.querySelectorAll('button')].find((b) => b.textContent === 'Apply');
  const had = !!applyBtn && document.activeElement === applyBtn;
  for (const b of card.querySelectorAll('button')) b.disabled = true;
  const r = await apiPost('policy/assistant/apply', { edits: s.edits, expected: s.expected });
  if (r.ok) {
    RULES_READS.wrote();
    clear(host);
    const done = el('div', { class: 'describe-done', text: 'Applied. Your rules are updated, and you can undo this under Rule changes in Approvals.' });
    host.append(done);
    if (had && focusFell()) focusThere(done);
    await loadRules();
    await loadRuleHistory();
    return;
  }
  for (const b of card.querySelectorAll('button')) b.disabled = false;
  // A wide change keeps its typed confirmation after a failed Apply.
  const confirm = card.querySelector('.proposal-confirm');
  if (confirm && applyBtn) applyBtn.disabled = confirm.value !== 'ALLOW';
  for (const old of card.querySelectorAll('.ask-error, .describe-again')) old.remove();
  const msg = changeRefusal(r, 'Not applied', 'could not apply the rules (' + r.status + ')');
  const said = el('div', { class: 'ask-error', role: 'alert', id: 'ask-error-' + (++askErrorSeq) }, words(msg));
  card.append(said);
  // The rules moved on (409), or the change no longer fits them (422).
  if (r.status === 409 || r.status === 422) {
    card.append(el('button', { type: 'button', class: 'btn small describe-again', text: 'Describe it again', onclick: () => suggestRules(D.sentence) }));
  }
  if (applyBtn) focusBack(applyBtn, had, said);
}

// ── Agent page ────────────────────────────────────────────────────────────────
// "What happened" (dashboard.md §4.25b): one card per turn, the paired rows of
// the /dev/ trace in product words. A step where the view of the AI and reality
// differ splits into two halves; the original behind a masked item shows on a click.
const STORY_TAG = {
  unmasked: 'Not masked',
  masked: 'Masked',
  secret: 'Secret hidden',
  blocked: 'Blocked',
  waiting: 'Waiting for you',
  raw: 'Masked only later',
  sandbox: 'Sandboxed',
  sent: 'Sent out',
};
/** Outcomes a long turn never folds away, nor the step just before each:
 *  what Mandu stopped, what waits for you, what reached the AI unmasked (or
 *  as it was, masked only later), and what left this machine. */
const STEP_KEEP = new Set(['blocked', 'waiting', 'unmasked', 'raw', 'sent']);
const STORY_ICON = { file: 'file', edit: 'file', run: 'terminal', web: 'globe', search: 'search', tool: 'tool', shield: 'shield' };
/** Steps shown before a long turn folds the rest behind a button. */
const STEP_FOLD = 6;
/** A long question shows this much until "Show all". */
const PROMPT_CLIP = 360;

// The agent page: read when it opens, by every Home poll while it is open,
// and after an answer to one of its questions (readsInOrder).
const AGENT_READS = readsInOrder();

/** What this visit of the agent page asked to see past its caps (dashboard.md
 *  §4.25ad): every turn, every secret, and every step of the turns named.
 *  Each read asks for it, the polls too, until the page changes. */
function agentShow() {
  const key = S.visit + ':' + S.agentId;
  if (!S.agentShow || S.agentShow.key !== key) S.agentShow = { key, turns: false, secrets: false, steps: [], background: [] };
  return S.agentShow;
}
function agentShowQuery() {
  const s = agentShow();
  return (s.turns ? '&turns=all' : '') + (s.secrets ? '&secrets=all' : '') + s.steps.map((t) => '&steps=' + encodeURIComponent(t)).join('')
    + s.background.map((t) => '&background=' + encodeURIComponent(t)).join('');
}
/** A "Show them" on the agent page: ask for the rest, and once a read that
 *  asked for it is drawn, give the focus to the first of it (`land`: where,
 *  landAgent). */
function showAgentRest(btn, ask, land) {
  btn.disabled = true;
  ask(agentShow());
  S.agentLand = { ...land, key: agentShow().key, read: null };
  loadAgent();
}

async function loadAgent() {
  const id = S.agentId;
  if (!id) return;
  const asked = AGENT_READS.ask();
  if (S.agentLand && S.agentLand.read === null) S.agentLand.read = asked;
  let vm = null;
  // Why the page could not be read (readFailure): 'down' (its protection
  // service is not running, a 503 unreachable), the status the dashboard
  // server answered with, or 'gone' (no answer). An unknown session is no
  // failure: the route answers `found: false` for it.
  let failure = null;
  const ask = S.agentAsk;
  try { vm = await apiGet('home/agent?session=' + encodeURIComponent(id) + (ask ? '&ask=' + encodeURIComponent(ask) : '') + agentShowQuery()); } catch (err) {
    vm = null;
    failure = readFailure(err);
  }
  if (S.page !== 'agent' || S.agentId !== id || S.agentAsk !== ask) return; // navigated away meanwhile
  if (!AGENT_READS.take(asked)) return;
  renderAgentPage(vm, id, failure, asked);
}

/** After the read a "Show them" asked (`asked`, its number, or a later one)
 *  is drawn: the focus goes to the first thing it brought (a turn, a step,
 *  a secret's card), else to its section's heading. True when it took the
 *  focus. */
function landAgent(asked) {
  const land = S.agentLand;
  if (!land || land.read === null || asked < land.read) return false;
  S.agentLand = null;
  if (land.key !== agentShow().key) return false;
  // A count tile asked for every turn: it goes on to its next step now.
  if (land.kind === 'outcome') {
    goToOutcome(land.outcome, null);
    return true;
  }
  const story = document.getElementById('agent-story');
  let to = null;
  if (land.kind === 'turns') {
    // The first it brought; folded by the switch, the line it folds into.
    to = story.querySelector('article.turn[data-turn-id]');
    const quiet = to && to.hidden ? quietButton(to) : null;
    if (quiet) to = quiet.closest('.story-quiet');
  }
  else if (land.kind === 'steps') {
    // Compared as values, never spliced into a selector: ids are server data.
    const turn = [...story.querySelectorAll('article.turn[data-turn-id]')].find((t) => t.dataset.turnId === land.turn);
    to = turn ? [...turn.querySelectorAll('[data-step-id]')].find((x) => x.dataset.stepId === land.step) || turn : null;
    const fold = to && to.closest('.steps-more');
    if (fold && fold.hidden) {
      // Each fold's button is in the row right after it (markFocus).
      const btn = fold.nextElementSibling && fold.nextElementSibling.querySelector('.steps-toggle');
      if (btn) btn.click();
    }
  } else if (land.kind === 'secrets') to = document.querySelectorAll('#agent-secrets .secret-card')[land.from] || null;
  else if (land.kind === 'background') {
    const turn = [...story.querySelectorAll('article.turn[data-turn-id]')].find((t) => t.dataset.turnId === land.turn);
    to = turn ? turn.querySelector('.routine-list li') || turn.querySelector('.routine') : null;
  }
  if (to && !to.closest('[hidden]')) landOn(to);
  else focusHeading(document.getElementById(land.kind === 'secrets' ? 'agent-secrets-block' : 'agent-story-block'));
  return true;
}

function hhmm(iso) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  return String(d.getHours()).padStart(2, '0') + ':' + String(d.getMinutes()).padStart(2, '0');
}

// ── The day a turn was on (dashboard.md §4.25, the per-agent page) ──────────
/** A turn's time: <time datetime="ISO" title="Oct 16, 23:50">23:50</time>,
 *  the clock time in its column and the whole moment on hover; a turn with
 *  no time gets an empty span, which starts no day (storyDayLines). */
function turnTime(ts) {
  const ms = ts ? Date.parse(ts) : NaN;
  if (!Number.isFinite(ms)) return el('span', { class: 'time' });
  return el('time', { class: 'time', datetime: ts, title: clockWords(ms), text: hhmm(ts) });
}
const WEEKDAYS = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
/** The viewer's local day of `ms`: its key ("2026-10-16", a <time>'s
 *  datetime) and its words ("Thursday, Oct 16", with the year when it is not
 *  this year, as clockWords). */
function localDay(ms, nowMs) {
  const d = new Date(ms);
  const now = new Date(nowMs === undefined ? Date.now() : nowMs);
  const pad = (k) => String(k).padStart(2, '0');
  const year = d.getFullYear() === now.getFullYear() ? '' : ', ' + d.getFullYear();
  return {
    key: d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()),
    words: WEEKDAYS[d.getDay()] + ', ' + MONTHS[d.getMonth()] + ' ' + d.getDate() + year,
  };
}
/** When the turns drawn (and the messages Mandu stopped, in their places)
 *  are on more than one day, a line naming the day goes before the first of
 *  each day, the first day's too; within one day, none. Worked out from the
 *  cards drawn and their own times, never the clock's day, so a redraw draws
 *  the same lines. A card with no time starts no day. The lines sit between
 *  the cards, so a run of quiet turns the switch folds (foldQuiet) folds day
 *  by day. */
function storyDayLines(story) {
  for (const line of story.querySelectorAll('.story-day')) line.remove();
  const firsts = [];
  let last = null;
  for (const card of [...story.children]) {
    if (!card.matches('article.turn')) continue;
    const t = card.querySelector('.turn-head > time.time');
    const ms = t ? Date.parse(t.getAttribute('datetime')) : NaN;
    if (!Number.isFinite(ms)) continue;
    const day = localDay(ms);
    if (day.key !== last) firsts.push({ card, day });
    last = day.key;
  }
  if (new Set(firsts.map((f) => f.day.key)).size < 2) return;
  for (const { card, day } of firsts) card.before(el('div', { class: 'story-day' }, el('time', { datetime: day.key, text: day.words })));
}

/** How long something ran, in words: "36 seconds", "3 minutes 12 seconds",
 *  "2 hours 5 minutes". The inspector's buckets (transcript.js
 *  `elapsedLabel`: "36s", "3m 12s", "2h 5m") spelled out, so both views say
 *  the same; '' under a second or when unknown. */
function spanWords(ms) {
  const s = Number.isFinite(ms) && ms > 0 ? Math.round(ms / 1000) : 0;
  if (s < 1) return '';
  if (s < 60) return n(s, 'second', 'seconds');
  const m = Math.floor(s / 60);
  if (m < 60) return n(m, 'minute', 'minutes') + (s % 60 ? ' ' + n(s % 60, 'second', 'seconds') : '');
  const h = Math.floor(m / 60);
  return n(h, 'hour', 'hours') + (m % 60 ? ' ' + n(m % 60, 'minute', 'minutes') : '');
}

/** The agent page's time line (dashboard.md §4.25, the per-agent page): how
 *  long the session ran and when it ended, each moment absolute and relative
 *  (`whenNode`, §4.25u). "ran" counts from its first recorded step to its
 *  last; "ended" means not running (no event for the running window). A
 *  moment the session did not record is left out, never a bare "ended". */
function agentWhenParts(vm) {
  const start = vm.startedAt ? Date.parse(vm.startedAt) : NaN;
  const end = vm.lastAt ? Date.parse(vm.lastAt) : NaN;
  if (vm.running) return Number.isFinite(start) ? ['running now, started ', whenNode(start)] : ['running now'];
  const parts = [];
  const ran = Number.isFinite(start) && Number.isFinite(end) ? spanWords(end - start) : '';
  if (ran) parts.push(el('span', { class: 'agent-ran', title: 'From its first recorded step (' + clockWords(start) + ') to its last.', text: 'ran ' + ran }), ', ');
  if (Number.isFinite(end)) parts.push('ended ', whenNode(end));
  else if (Number.isFinite(start)) parts.push('started ', whenNode(start));
  return parts;
}

/** How many rule changes the agent of this session asked for wait in
 *  Approvals (the server gives a request its session only when an agent
 *  asked, never for a held change to policy.yaml). */
function agentChanges(id) {
  return S.proposals.filter((p) => !p.onDisk && p.session === id).length;
}

function renderAgentPage(vm, id, failure, asked) {
  // A poll that brings the page it shows leaves it as it is (sameAsDrawn):
  // where you scrolled, what you opened, the words of an answer. A new visit
  // draws it afresh. A rule change of this agent that a poll brings or takes
  // away draws it again too.
  if (sameAsDrawn('agent', [S.visit, id, failure, vm, agentChanges(id)])) return;
  // Drawn again (the agent did more): the focus goes back to its place
  // (pollPlace).
  const place = pollPlace(document.getElementById('page-agent'));
  // A focus in a turn the switch folds goes to the line it folds into
  // (quietRefocus), never the heading.
  const inTurn = place && document.activeElement.closest('#agent-story article.turn[data-turn-id]');
  const turnId = inTurn ? inTurn.dataset.turnId : null;
  drawAgentPage(vm, id, failure);
  if (!landAgent(asked) && !quietRefocus(turnId)) pollRefocus(place);
}
function drawAgentPage(vm, id, failure) {
  const name = document.getElementById('agent-name');
  const sub = document.getElementById('agent-sub');
  const facts = document.getElementById('agent-facts');
  const story = document.getElementById('agent-story');
  const trace = document.getElementById('agent-trace');
  trace.href = DEV_URL + 'sessions/' + encodeURIComponent(id);
  // Drawn again in the same visit (the agent did more): the toggles of the
  // story go back as you left them.
  const left = S.agentDrawn === S.visit + ':' + id ? storyToggles(story) : null;
  S.agentDrawn = S.visit + ':' + id;
  // The replies drawn before go: their folds are measured no more.
  if (replySizes) replySizes.disconnect();
  clear(facts); clear(story); clear(sub);
  const storyBlock = document.getElementById('agent-story-block');
  if (!vm || !vm.found) {
    // A page that could not be read is not a missing session: with the
    // protection service down the session is still there (dashboard.md
    // §4.25 *Empty states*). No section stands empty under its heading.
    if (failure === 'down') {
      name.textContent = 'Not connected';
      sub.append('The protection service is not running, so Mandu cannot show this session now. ',
        placeLink({ text: 'Start it under Settings', to: 'settings' }), ', or refresh in a moment.');
    } else if (failure) {
      // An error with its status, or no answer in the words of the hero.
      name.textContent = 'Session not loaded';
      sub.append(...cannotCheck('This session could not be loaded.', failure, true));
    } else {
      name.textContent = 'Session not found';
      sub.textContent = 'It may have been deleted, or it belongs to the other tenant. Mandu keeps a session\'s record for 90 days.';
    }
    const valuesNote = document.getElementById('agent-values-note');
    if (valuesNote) valuesNote.hidden = true;
    document.getElementById('agent-waiting-block').hidden = true;
    clear(document.getElementById('agent-waiting'));
    putBackAnswers('agent', document.getElementById('agent-waiting'));
    putBackAnswers('note', story);
    renderAgentSecrets(null);
    renderAgentBrowser(null);
    renderAgentFinding(null);
    drawOnlySwitch(null);
    storyBlock.hidden = true;
    return;
  }
  storyBlock.hidden = false;
  name.textContent = vm.agent;
  // The tag and the warning mark by the name, in its Home row's order.
  if (vm.preview) name.append(' ', agentPreviewMark(vm.preview));
  if (vm.notice) name.append(' ', agentNoticeMark(vm.notice));
  // Signed out, the page shows only what the AI saw (dashboard.md §6).
  S.valuesShown = vm.valuesShown !== false;
  const valuesNote = document.getElementById('agent-values-note');
  if (valuesNote) {
    valuesNote.hidden = S.valuesShown;
    setWords(valuesNote, SIGN_IN_VALUES);
  }
  S.pageTitle = 'Mandu · ' + vm.agent;
  renderTitle();
  const bits = [];
  if (vm.title) bits.push(vm.title);
  sub.append(bits.join(''));
  const when = agentWhenParts(vm);
  const metaLine = el('div', { class: 'dim agent-when', style: 'font-size:14px;margin-top:4px' }, ...when);
  // A long folder breaks at its slashes (longName), as the cards below cut
  // their files (dashboard.md §4.25u, *The session's folder breaks as elsewhere*).
  if (vm.cwd) metaLine.append(when.length ? ', in ' : 'in ', longName(el('code', { text: shortPath(vm.cwd) })));
  sub.append(metaLine);
  // Which declared model the conversation goes to (dashboard.md §4.25l).
  if (vm.mainModel) sub.append(el('div', { class: 'dim agent-main-model', 'data-local': vm.mainModel.local ? 'true' : 'false', style: 'font-size:14px;margin-top:2px', text: vm.mainModel.words }));

  // The tiles count what the page below shows (dashboard.md §4.25, the
  // per-agent page): secrets as Your secrets tells each one (the server's
  // `counts`, by each card's first line), blocks and sends by the story's
  // steps. A secret the AI read before it was marked is never counted as
  // masked before the AI saw it.
  // A tile with steps to go to is a button (`goes`: its outcome, or
  // 'waiting'; §4.25 *A tile takes you to what it counts*); at 0 it stays a
  // plain tile. Its parts are spans, as a button holds no div, and the
  // spaces between them keep its name "3 actions blocked".
  const tile = (k, label, cls, title, goes) => {
    const parts = [el('span', { class: 'big', text: String(k) }), ' ', el('span', { class: 'lbl', text: label })];
    if (!goes) return el('div', { class: 'tile' + (cls ? ' ' + cls : ''), title: title || null }, ...parts);
    const b = el('button', { type: 'button', class: 'tile goes' + (cls ? ' ' + cls : ''), title: title || null, 'data-goes': goes },
      ...parts, ' ', el('span', { class: 'at' }), el('span', { class: 'go', 'aria-hidden': 'true', text: 'Show' }));
    b.addEventListener('click', () => (goes === 'waiting' ? goToWaiting() : goToOutcome(goes, { count: k, more: !!vm.earlier && vm.allTurns !== true, btn: b })));
    return b;
  };
  // Blocks and sends the page has, or can ask for: every counted step of a
  // drawn turn is drawn (the story keeps a turn's first TURN_STEP_CAP steps,
  // the ones counted), so one not drawn is in a turn before them.
  const reach = (outcome) => (vm.story.some((t) => t.steps.some((s) => s.kind === 'action' && s.outcome === outcome)) || (!!vm.earlier && vm.allTurns !== true)) ? outcome : null;
  if (!vm.holds) {
    const bad = tile(vm.violations || 1, 'reached the AI unmasked.' + (HAS_DEV ? ' ' : ''), 'bad');
    if (HAS_DEV) bad.querySelector('.lbl').append(traceLink('Open the detailed trace'), '.');
    facts.append(bad);
  }
  const secrets = vm.secrets && vm.secrets.counts ? vm.secrets : null;
  // Masked untrusted text is the frozen masking levels' (Secrets and Off
  // mask none, so a non-secret item there is not one).
  const mode = vm.secrets ? vm.secrets.mode : null;
  const untrusted = mode === 'secrets' || mode === 'off' ? 0 : Math.max(0, vm.stats.flows - vm.stats.secret);
  if (secrets) {
    const { masked, early } = secrets.counts;
    const listed = secrets.secrets.length + secrets.more;
    if (masked || (!listed && !untrusted && !secrets.flagged)) {
      facts.append(tile(masked, masked === 1 ? 'secret masked before the AI saw it' : 'secrets masked before the AI saw them', '',
        'The AI got only the masked version of each, from the first time it could see it. Your secrets, below, names them.'));
    }
    if (early) {
      facts.append(tile(early, early === 1 ? 'secret the AI read before it was marked a secret' : 'secrets the AI read before they were marked secrets', 'warn',
        'The AI read the real value as it was, before it was marked a secret. Your secrets, below, says when.'));
    }
  }
  if (untrusted) facts.append(tile(untrusted, untrusted === 1 ? 'untrusted item masked before the AI saw it' : 'untrusted items masked before the AI saw them'));
  const blockedGoes = vm.blocked ? reach('blocked') : null;
  facts.append(tile(vm.blocked, vm.blocked === 1 ? 'action blocked' : 'actions blocked', '',
    'Each is a step Mandu stopped: a command, a file or a send. ' + (blockedGoes ? (vm.blocked === 1 ? 'Press to go to it under What happened.' : 'Press to go to each in turn under What happened.') : 'What happened, below, shows it.'),
    blockedGoes));
  if (vm.sent) {
    const sentGoes = reach('sent');
    facts.append(tile(vm.sent, vm.sent === 1 ? 'send with a real value filled in' : 'sends with a real value filled in', '',
      (vm.sent === 1 ? 'It' : 'Each') + ' went to a destination allowed to receive it. ' + (sentGoes ? (vm.sent === 1 ? 'Press to go to it under What happened.' : 'Press to go to each in turn under What happened.') : 'What happened, below, shows where.'),
      sentGoes));
  }
  if (vm.waiting.length) facts.append(tile(vm.waiting.length, 'waiting for you', 'warn', 'Press to go to Needs your OK, below.', 'waiting'));
  // What the leak check found, under the tiles (dashboard.md §4.25ae).
  renderAgentFinding(vm.finding || null);

  // A rule change this agent asked for waits in Approvals, and the list
  // links it as Home does (dashboard.md §4.25 *A rule change and the agent
  // that asked*).
  const changes = agentChanges(id);
  const wb = document.getElementById('agent-waiting-block');
  wb.hidden = vm.waiting.length === 0 && changes === 0;
  const waitingHost = document.getElementById('agent-waiting');
  renderAsks(waitingHost, { waitingKnown: true, waiting: vm.waiting }, true, changes > 0);
  if (changes) {
    waitingHost.append(el('a', { href: routeHref('approvals'), 'data-page-link': 'approvals', class: 'more',
      text: n(changes, 'rule change this agent asked for is', 'rule changes this agent asked for are') + ' in Approvals' }));
  }
  // Drawn again while the agent works: each card gets the words of its last
  // answer back (the rows of the note under your message, once the story is).
  putBackAnswers('agent', waitingHost);

  renderAgentSecrets(vm.secrets, vm.allSecrets === true);
  renderAgentBrowser(vm.browser || null);

  // The turns before the ones shown: "Show them" asks for every turn; past
  // what the page shows, the line only says so (dashboard.md §4.25ad).
  if (vm.earlier) story.append(restLine(vm.earlier, 'earlier turn', 'earlier turns', vm.allTurns === true, [],
    (btn) => showAgentRest(btn, (s) => { s.turns = true; }, { kind: 'turns' })));
  if (!vm.story.length) {
    // A browser agent that talks to its own AI services has no conversation
    // through Mandu's model proxy; On web pages, above, tells its run.
    story.append(el('div', { class: 'story-more', text: vm.running ? 'Nothing recorded yet.'
      : vm.browser ? 'No conversation went through Mandu: the agent talked to its AI services itself. On web pages, above, says what Mandu did.'
        : 'No conversation was recorded for this session.' }));
  }
  // A turn where Mandu did nothing is `quiet`, which the switch folds; the
  // turn an ask opened the page for never is (§4.25ae *Only where Mandu
  // stepped in*).
  for (const turn of vm.story) {
    const card = turnNode(turn);
    if (quietTurn(turn) && !(vm.focus && vm.focus.turnId === turn.id)) card.classList.add('quiet');
    story.append(card);
  }
  drawOnlySwitch(vm.story);
  // A message Mandu stopped never reached the AI, so no turn shows it: its
  // note goes in the story by its time (plan 15 §13.7).
  for (const note of vm.unplacedNotes || []) {
    const card = el('article', { class: 'turn prompt-unsent' },
      el('div', { class: 'turn-head' }, turnTime(note.ts),
        el('div', { class: 'turn-q' }, el('div', { class: 'note', text: 'A message you wrote' }), promptNoteNode(note))));
    const next = [...story.querySelectorAll('article.turn[data-turn-id]')].find((t) => {
      const turn = vm.story.find((x) => x.id === t.dataset.turnId);
      return turn && turn.ts && note.ts && turn.ts > note.ts;
    });
    if (next) story.insertBefore(card, next);
    else story.append(card);
  }
  storyDayLines(story);
  if (vm.focus) markFocus(story, vm.focus);
  foldQuiet(story);
  if (left) putBackToggles(story, left);
  putBackAnswers('note', story);
  // Each tile says where its presses are, drawn again or not.
  for (const b of facts.querySelectorAll('button.tile[data-goes]')) tileWhere(b);
}

// ── A tile takes you to what it counts (dashboard.md §4.25) ─────────────────
/** Where each count tile of the agent page last went this visit: the id of
 *  the step, by its outcome. A poll redraw keeps it, so the next press goes
 *  on from there. */
function tileAt() {
  const key = S.visit + ':' + S.agentId;
  if (!S.agentTileAt || S.agentTileAt.key !== key) S.agentTileAt = { key, blocked: null, sent: null };
  return S.agentTileAt;
}
/** The story's steps with `outcome`, in page order (`data-outcome`). */
function outcomeSteps(outcome) {
  const story = document.getElementById('agent-story');
  return story ? [...story.querySelectorAll('[data-outcome]')].filter((x) => x.dataset.outcome === outcome) : [];
}
/** The tile `b` says which of its steps the last press went to ("Showing 2
 *  of 3"), once there was one, and only past one step. */
function tileWhere(b) {
  const at = b.querySelector('.at');
  const kind = b.dataset.goes;
  if (!at || kind === 'waiting') return;
  const steps = outcomeSteps(kind);
  const i = steps.findIndex((x) => x.dataset.stepId === tileAt()[kind]);
  const count = Number(b.querySelector('.big').textContent) || 0;
  const of = Math.max(count, steps.length);
  at.textContent = i === -1 || of < 2 ? '' : 'Showing ' + (i + 1) + ' of ' + of;
}
/** A press on the tile of `outcome` ('blocked', 'sent'): the step after
 *  the one it last went to, after the last the first (showStep: its folds
 *  opened, marked, focused, in view). When the page has fewer such steps
 *  than the tile counts and turns before them are not drawn (`from.more`),
 *  the page asks for every turn first and goes on once they are drawn
 *  (landAgent). With none to go to, the line that says turns are left out
 *  takes the focus, else the story's heading: never nothing. `from` is the
 *  press (its tile's count, its button); null once the asked read is drawn. */
function goToOutcome(outcome, from) {
  const steps = outcomeSteps(outcome);
  if (from && from.more && steps.length < from.count) {
    showAgentRest(from.btn, (s) => { s.turns = true; }, { kind: 'outcome', outcome });
    return;
  }
  const story = document.getElementById('agent-story');
  if (!steps.length) {
    const line = story && story.querySelector('.story-more');
    if (line) landOn(line);
    else focusHeading(document.getElementById('agent-story-block'));
    return;
  }
  const at = tileAt();
  const i = steps.findIndex((x) => x.dataset.stepId === at[outcome]);
  const to = steps[(i + 1) % steps.length];
  at[outcome] = to.dataset.stepId;
  showStep(to.dataset.stepId);
  const b = [...document.querySelectorAll('#agent-facts button.tile[data-goes]')].find((x) => x.dataset.goes === outcome);
  if (b) tileWhere(b);
}
/** A press on "N waiting for you": Needs your OK, its first card focused
 *  and in view; without a card, its heading. */
function goToWaiting() {
  const block = document.getElementById('agent-waiting-block');
  const card = [...document.getElementById('agent-waiting').children].find((c) => c.classList.contains('ask'));
  if (!card || block.hidden) { focusHeading(block); return; }
  focusThere(card);
  if (card.scrollIntoView) card.scrollIntoView({ block: 'center' });
}

// ── Only where Mandu stepped in (dashboard.md §4.25ae) ──────────────────────
/** A turn where Mandu did nothing: every step plain (no block, mask, wait,
 *  send, sandboxed read or workspace masking: its `tone`, the most severe
 *  outcome), and no note under your message. A summary alone does not make
 *  a turn count: a turn of ordinary steps says "Nothing here needed
 *  guarding." A turn without a tone is never quiet. */
function quietTurn(turn) {
  return turn.tone === 'plain' && !turn.promptNote;
}
/** The switch beside the heading: shown with a story to fold, its words
 *  counting the turns drawn where Mandu stepped in. `turns` null: hidden. */
function drawOnlySwitch(turns) {
  const row = document.getElementById('agent-only-row');
  document.getElementById('agent-only').setAttribute('aria-checked', String(S.agentOnly));
  row.hidden = !turns || !turns.length;
  if (row.hidden) return;
  const stepped = turns.filter((t) => !quietTurn(t)).length;
  document.getElementById('agent-only-words').textContent = 'Only where Mandu stepped in (' + stepped + ' of ' + n(turns.length, 'turn', 'turns') + ')';
}
/** The switch pressed: the story folds (or unfolds) in place, with no read,
 *  and the address says so (replaced, not pushed). The focus stays on it. */
function flipAgentOnly() {
  if (S.page !== 'agent') return;
  S.agentOnly = !S.agentOnly;
  const href = stateHref();
  if (location.pathname + location.search !== href) history.replaceState(history.state, '', href);
  document.getElementById('agent-only').setAttribute('aria-checked', String(S.agentOnly));
  foldQuiet(document.getElementById('agent-story'));
}
/** With the switch on, each run of quiet turns folds behind one line ("5
 *  turns where Mandu did nothing") whose button shows them in place; off,
 *  every turn shows. A focus the fold hides goes to its line's button. */
let quietSeq = 0;
function foldQuiet(story) {
  const had = document.activeElement;
  for (const line of story.querySelectorAll('.story-quiet')) line.remove();
  for (const t of story.querySelectorAll('article.turn.quiet')) t.hidden = false;
  if (!S.agentOnly) return;
  let run = [];
  const flush = () => {
    if (run.length) quietLine(run);
    run = [];
  };
  for (const x of [...story.children]) {
    if (x.matches('article.turn.quiet')) run.push(x);
    else flush();
  }
  flush();
  const turn = had && had.isConnected && had.closest('#agent-story article.turn.quiet');
  if (turn && turn.hidden) quietButton(turn).focus({ preventScroll: true });
}
function quietLine(run) {
  const count = run.length;
  const show = count === 1 ? 'Show it' : 'Show them';
  const hide = count === 1 ? 'Hide it' : 'Hide them';
  // Keyed by its first turn (data-quiet-from), as the poll finds it again.
  const line = el('div', { class: 'story-more story-quiet', 'data-quiet-from': run[0].dataset.turnId });
  const said = el('span', { id: 'quiet-' + (++quietSeq), text: n(count, 'turn', 'turns') + ' where Mandu did nothing' });
  const btn = el('button', { type: 'button', class: 'btn small show-rest quiet-toggle', 'aria-expanded': 'false', 'aria-describedby': said.id, text: show });
  btn.addEventListener('click', () => {
    const open = btn.getAttribute('aria-expanded') !== 'true';
    for (const t of run) t.hidden = !open;
    btn.setAttribute('aria-expanded', String(open));
    btn.textContent = open ? hide : show;
  });
  for (const t of run) t.hidden = true;
  line.append(said, ' ', btn);
  run[0].before(line);
}
/** The button of the line a folded quiet turn is behind (the line sits
 *  just before the run's first turn). */
function quietButton(turn) {
  let x = turn.previousElementSibling;
  while (x && x.matches('article.turn.quiet')) x = x.previousElementSibling;
  return x && x.classList.contains('story-quiet') ? x.querySelector('.quiet-toggle') : null;
}
/** After a redraw whose focus was in turn `turnId`, only if the focus fell:
 *  that turn folded now, the focus goes to its line's button. True when it
 *  took the focus. */
function quietRefocus(turnId) {
  if (!turnId || !focusFell()) return false;
  // Compared as values, never spliced into a selector: ids are server data.
  const turn = [...document.querySelectorAll('#agent-story article.turn[data-turn-id]')].find((t) => t.dataset.turnId === turnId);
  const btn = turn && turn.hidden ? quietButton(turn) : null;
  if (!btn) return false;
  btn.focus({ preventScroll: true });
  return true;
}
/** Opens the folded run that holds `x`, if one does (a step a link shows,
 *  the turn a Show them brought). */
function openQuiet(x) {
  const turn = x && x.closest('article.turn.quiet');
  const btn = turn && turn.hidden ? quietButton(turn) : null;
  if (btn) btn.click();
}

/** The toggles of the story as you left them (dashboard.md §4.25 *The poll
 *  keeps your place*): each fold, "Show all", "Show what was hidden", file
 *  list and long reply (foldReply) by the turn it is in, its kind and its
 *  place among that kind there (new
 *  steps come last, so an earlier place stays); and the step a Your secrets
 *  time marked. "Show the real value" is not one: it asks the server, so it
 *  asks again only on your click. */
const STORY_TOGGLES = { fold: '.steps-toggle', all: '.linkish', hidden: '.hidden-box > .reveal:not(.secret-reveal)', files: 'details.files', reply: '.reply-fold' };
function storyToggles(story) {
  const toggles = [];
  for (const turn of story.querySelectorAll('article.turn[data-turn-id]')) {
    for (const [kind, sel] of Object.entries(STORY_TOGGLES)) {
      turn.querySelectorAll(sel).forEach((t, i) => {
        toggles.push({ turn: turn.dataset.turnId, kind, i, open: t.tagName === 'DETAILS' ? t.open : t.getAttribute('aria-expanded') === 'true' });
      });
    }
  }
  const shown = story.querySelector('.step.shown');
  // The quiet runs you opened, by their first turn (§4.25ae).
  const quiet = [...story.querySelectorAll('.story-quiet')].filter((l) => l.querySelector('.quiet-toggle').getAttribute('aria-expanded') === 'true').map((l) => l.dataset.quietFrom);
  return { toggles, shown: shown ? shown.dataset.stepId : null, quiet };
}
function putBackToggles(story, left) {
  // Compared as values, never spliced into a selector: ids are server data.
  const turns = new Map([...story.querySelectorAll('article.turn[data-turn-id]')].map((t) => [t.dataset.turnId, t]));
  for (const line of story.querySelectorAll('.story-quiet')) {
    const btn = line.querySelector('.quiet-toggle');
    if (left.quiet.includes(line.dataset.quietFrom) && btn.getAttribute('aria-expanded') !== 'true') btn.click();
  }
  for (const x of left.toggles) {
    const turn = turns.get(x.turn);
    const t = turn ? turn.querySelectorAll(STORY_TOGGLES[x.kind])[x.i] : null;
    if (!t) continue;
    if (t.tagName === 'DETAILS') t.open = x.open;
    else if ((t.getAttribute('aria-expanded') === 'true') !== x.open) t.click();
  }
  const step = left.shown ? [...story.querySelectorAll('[data-step-id]')].find((x) => x.dataset.stepId === left.shown) : null;
  if (step) {
    step.classList.add('shown');
    step.setAttribute('tabindex', '-1');
  }
}

/** The line under a capped list of the agent page (dashboard.md §4.25ad):
 *  "3 more steps are not shown here." and its "Show them" (`show(btn)`);
 *  once the page asked for them all (`past`), "… are past what this page
 *  shows." alone. With the developer view, the detailed trace has them
 *  too (`trace`: traceLink's tab, ask and step). */
function restLine(count, one, many, past, trace, show) {
  const line = el('div', { class: 'story-more' });
  const words = n(count, one + ' is', many + ' are') + (past ? ' past what this page shows.' : ' not shown here.');
  const extra = HAS_DEV ? [' The ', traceLink('detailed trace', ...trace), count === 1 ? ' has it.' : ' has them.'] : [];
  if (past) {
    line.append(words, ...extra);
    return line;
  }
  return showRest(line, words, extra, count, function () { show(this); });
}

// ── What the leak check found (dashboard.md §4.25ae) ────────────────────────
/** Each place a recorded event says something reached the AI without its
 *  mask: when (a time the story shows opens its step), the step's words and
 *  the secrets it held by name. Never the text the check found: a value is
 *  only where the step itself shows one, signed in. */
function renderAgentFinding(f) {
  const block = document.getElementById('agent-finding-block');
  const list = document.getElementById('agent-finding');
  const intro = document.getElementById('agent-finding-intro');
  clear(list);
  if (!f) { block.hidden = true; return; }
  block.hidden = false;
  const places = f.items.length + f.more;
  intro.textContent = places
    ? 'Mandu\'s leak check found ' + n(places, 'place', 'places') + ' where something reached the AI without its mask. Each line says where and when, never the text itself.'
    : 'Mandu\'s leak check flagged this session.';
  for (const item of f.items) list.append(el('li', { class: 'finding-line' }, svg(ICON.alert, 14), sentenceNode(item.parts, '')));
  if (f.more) list.append(el('li', { class: 'finding-line dim', text: n(f.more, 'more place is', 'more places are') + ' past what this page lists.' }));
}

// ── Your secrets (dashboard.md §4.25b) ──────────────────────────────────────
/** Each secret the session recorded, in the server's plain lines (every one
 *  backed by an event; secret-story.ts), and what Mandu does not cover. The
 *  page names a secret by its variable or file, never by its value. */
const SECRET_LINE_ICON = { good: 'check', warn: 'clock', bad: 'alert', plain: 'globe' };
/** Why Mandu stops a browser command, in plain words (browser-story.ts). */
const BROWSER_STOP_WHY = {
  'screenshot': 'a picture of the page can show a secret Mandu cannot mask in it',
  'screen recording': 'a recording of the page can show a secret Mandu cannot mask in it',
  'PDF capture': 'a capture of the page can show a secret Mandu cannot mask in it',
  'cookie read': 'your sign-in cookies stay in the browser',
  'debugging access': 'it would reach the browser around Mandu',
};
/** "On web pages" (dashboard.md §4.25af): a browser agent's run through
 *  Mandu's DevTools relay. One line each: what the agent read masked, each
 *  secret it typed and where, what Mandu stopped, the AI services the agent
 *  called itself. Secret names only, never a value. */
function renderAgentBrowser(b) {
  const block = document.getElementById('agent-browser-block');
  const list = document.getElementById('agent-browser');
  const intro = document.getElementById('agent-browser-intro');
  if (!block || !list || !intro) return;
  clear(list);
  if (!b) { block.hidden = true; return; }
  block.hidden = false;
  intro.textContent = 'The agent used a browser through Mandu. Your browser showed the real pages; the agent got them from Mandu.';
  const line = (tone, text) => list.append(el('li', { class: 'secret-line ' + tone }, svg(ICON[SECRET_LINE_ICON[tone]] || ICON.check, 14), el('span', { text })));
  const names = (xs) => xs.length <= 1 ? (xs[0] || '') : xs.slice(0, -1).join(', ') + ' and ' + xs[xs.length - 1];
  if (b.secrets.length) {
    line('good', names(b.secrets) + (b.secrets.length === 1 ? ' was' : ' were') + ' masked in what the agent read from the pages (' + n(b.maskedReads, 'time', 'times') + '): the agent and its AI never saw the real value.');
  } else {
    line('plain', 'No secret of yours was on the pages the agent read.');
  }
  for (const t of b.typed) {
    const times = t.count > 1 ? ' (' + n(t.count, 'time', 'times') + ')' : '';
    if (t.outcome === 'filled') line('good', 'The agent typed ' + t.secret + ' into ' + (t.site || 'a page') + times + ': Mandu filled in the real value there, because ' + t.secret + ' may go to that site.');
    else if (t.outcome === 'unknown') line('warn', 'The agent tried to type a masked value that is none of your secrets' + times + ', a mistyped or made-up one: Mandu typed nothing and told the agent to copy it exactly as the page shows it.');
    else line('bad', 'The agent tried to type ' + t.secret + ' into a page' + times + ': Mandu typed nothing, because that site may not receive it.');
  }
  for (const s of b.stopped) line('bad', 'Mandu stopped ' + n(s.count, s.what, s.what + 's') + ': ' + (BROWSER_STOP_WHY[s.what] || 'the agent may not use it') + '.');
  if (b.withheld) line('warn', 'Mandu held back ' + n(b.withheld, 'page message', 'page messages') + ' it could not check, so the agent never got ' + (b.withheld === 1 ? 'it.' : 'them.'));
  for (const s of b.services) {
    line('good', 'The agent sent ' + n(s.requests, 'request', 'requests') + ' to ' + s.host + ' itself' +
      (s.masked.length ? ', with ' + names(s.masked) + ' masked in ' + (s.requests === 1 ? 'it' : 'them') : '') + '.');
  }
}
function renderAgentSecrets(story, all) {
  const block = document.getElementById('agent-secrets-block');
  const list = document.getElementById('agent-secrets');
  const intro = document.getElementById('agent-secrets-intro');
  const limits = document.getElementById('agent-secrets-limits');
  clear(list);
  if (!story) { block.hidden = true; return; }
  block.hidden = false;
  const count = story.secrets.length + story.more;
  intro.textContent = count
    ? n(count, 'secret you registered or labeled', 'secrets you registered or labeled') + ' came up in this session. Each line below comes from what Mandu recorded.'
    : 'No secret you registered or labeled came up in this session.';
  for (const s of story.secrets) {
    const what = sentenceNode(s.what, 'secret-what');
    const card = el('div', { class: 'secret-card' },
      el('div', { class: 'secret-head' }, what, secretLevelTag(s)));
    const ul = el('ul', { class: 'secret-lines' });
    for (const line of s.lines) ul.append(el('li', { class: 'secret-line ' + line.tone }, svg(ICON[SECRET_LINE_ICON[line.tone]] || ICON.check, 14), sentenceNode(line.parts, '')));
    card.append(ul);
    // Signed in, its real value on a click (never on the page by default),
    // named by the card heading drawn above it.
    if (s.ref && S.valuesShown !== false) card.append(secretValueBox(s.ref, null, card, lineWords(what)));
    list.append(card);
  }
  if (story.more) {
    const from = story.secrets.length;
    list.append(restLine(story.more, 'more secret', 'more secrets', all === true, ['secrets'],
      (btn) => showAgentRest(btn, (s) => { s.secrets = true; }, { kind: 'secrets', from })));
  }
  limits.textContent = story.mode === 'off'
    ? 'Protection was off in this session: Mandu only watched and masked nothing.'
    : 'Mandu protects only the secrets you registered and the files you labeled. Anything else the AI read, it saw as it was.' +
      (story.mode === 'secrets' ? ' In this mode Mandu does not stop prompt injection: the AI may follow instructions hidden in what it reads. Mandu guards where your secrets go.' : '');
}

/** The level tag of a secret card, coloured by what the AI got (`saw`, the
 *  first line of the card; §4.25b, *The tag agrees with the card*): green
 *  only where the level held, amber for a read before the label ("… since
 *  10:42", the moment it was masked from) and for Off, red for a fired leak
 *  check, and neutral when the answer is not known. */
const SECRET_TAG_TONE = { masked: 'secret', readable: 'secret', 'own-model': 'secret', early: 'raw', off: 'raw', flagged: 'unmasked' };
function secretLevelTag(s) {
  const tone = Object.prototype.hasOwnProperty.call(SECRET_TAG_TONE, s.saw) ? SECRET_TAG_TONE[s.saw] : '';
  const tag = el('span', { class: 'tag level' + (tone ? ' ' + tone : ''), text: s.level });
  const at = s.saw === 'early' && s.since ? hhmm(s.since) : '';
  if (at) tag.append(' since ', el('time', { datetime: s.since, text: at }));
  return tag;
}

// ── The note under your message (plan 15 §7, §13.7; dashboard.md §4.25y) ────
/** What the prompt filter changed in a message you wrote, in plain words.
 *  The page never has the value: "Show what was hidden" asks the server for
 *  it on a click (the developer view's reveal, only for what you typed that
 *  is not a secret Mandu knows), and "Let it through" sends the finding's
 *  name to the route the Approvals card uses, which reads the rest from the
 *  session's own record. */
function promptNoteNode(note) {
  const box = el('div', { class: 'prompt-note', role: 'note' });
  for (const line of note.lines || []) box.append(el('div', { class: 'prompt-note-line' }, svg(ICON.eyeOff, 14), el('span', { text: line })));
  for (const it of note.items || []) {
    // Under a locked administrator's `ask` row there is no session button,
    // and the item says why (plan 15 §12, 2026-10-04: `onlyThisMessage`);
    // under one that is not `ask` there is no let-through at all, and the
    // item says why (`lockedWhy`, dashboard.md §4.25y).
    const onlyThis = typeof it.onlyThisMessage === 'string' && it.onlyThisMessage !== '';
    const lockedWhy = typeof it.lockedWhy === 'string' && it.lockedWhy !== '' ? it.lockedWhy : null;
    if (!it.canShow && !it.canLetOnce && !it.canLetSession && !onlyThis && !lockedWhy) continue;
    // The finding as the route names it, and where it stands: the words of
    // an answer go back on this row while both hold (putBackAnswers). A
    // later request is a new event, so they go once it records the answer.
    const row = el('div', { class: 'prompt-note-item', 'data-id': JSON.stringify([it.eventId, it.index]), 'data-state': it.state });
    const what = el('span', { class: 'prompt-note-what' }, it.words ? it.words.charAt(0).toUpperCase() + it.words.slice(1) : el('code', { text: it.category }));
    row.append(what);
    nameBy(row, what);
    const shown = it.canShow && S.valuesShown !== false ? promptReveal(it, row) : null;
    if (shown) row.append(shown.btn);
    if (it.canLetOnce) row.append(el('button', { type: 'button', class: 'btn small prompt-let-once', text: 'Let it through in this message', onclick: () => letPromptThrough(it, 'once', row) }));
    if (it.canLetSession && !onlyThis) row.append(el('button', { type: 'button', class: 'btn small prompt-let-session', text: 'Let it through for this session', onclick: () => letPromptThrough(it, 'session', row) }));
    if (onlyThis) row.append(el('span', { class: 'prompt-let-once-only', text: it.onlyThisMessage }));
    if (lockedWhy) row.append(el('span', { class: 'prompt-let-locked', text: lockedWhy }));
    box.append(row);
    if (shown) box.append(shown.pre);
  }
  return box;
}

/** "Show what was hidden": the button, and the text it fills on a click. */
function promptReveal(it, row) {
  const pre = el('pre', { class: 'hidden-text prompt-hidden-text', role: 'group', 'aria-label': 'What was hidden', hidden: true });
  const btn = el('button', { type: 'button', class: 'btn small reveal prompt-reveal', 'aria-expanded': 'false', text: 'Show what was hidden' });
  btn.addEventListener('click', async () => {
    if (btn.getAttribute('aria-expanded') === 'true') {
      pre.hidden = true; clear(pre);
      btn.setAttribute('aria-expanded', 'false');
      btn.textContent = 'Show what was hidden';
      return;
    }
    const had = document.activeElement === btn;
    const at = revealPlace(btn);
    btn.disabled = true;
    const r = await apiPost('prompt-filters/reveal', { session: S.agentId, eventId: it.eventId, index: it.index });
    btn.disabled = false;
    revealAnswered(btn, at, r, had);
  });
  const answered = (r, had) => {
    if (!r.ok || !r.data || typeof r.data.original !== 'string') {
      showAskError(row, refusalText(r, 'could not show it'));
      focusBack(btn, had, row.querySelector('.ask-error'));
      return;
    }
    pre.textContent = r.data.original;
    pre.hidden = false;
    btn.setAttribute('aria-expanded', 'true');
    btn.textContent = 'Hide it again';
    focusBack(btn, had, null);
  };
  REVEALS.set(btn, { key: JSON.stringify(['prompt', it.eventId, it.index]), answered });
  return { btn, pre };
}

async function letPromptThrough(it, scope, row) {
  const what = it.words || it.category;
  const q = scope === 'once'
    ? 'Let ' + what + ' through in this message? The AI reads it as you wrote it from the agent\'s next request on.'
    : 'Let ' + what + ' through for the rest of this session? The AI reads it as you wrote it in every message of this session.';
  if (!window.confirm(q)) return;
  dropAnswer('note', row);
  busyRow(row, true);
  const r = await apiPost('prompt-filters/let-through', { session: S.agentId, eventId: it.eventId, index: it.index, scope });
  if (!r.ok) {
    busyRow(row, false);
    keepAnswer('note', row, refusalText(r, 'could not record your answer'));
    return;
  }
  // Until the agent's next request records it, the server still offers the
  // buttons: a redraw meanwhile puts this line back in their place.
  keepAnswer('note', row, scope === 'once' ? 'Let through in this message. The AI reads it from the agent\'s next request.' : 'Let through for this session. The AI reads it from the agent\'s next request.', true);
}
/** A let-through that worked: its line in place of the buttons, and of the
 *  words of an earlier refusal. */
function letDone(row, text) {
  for (const b of row.querySelectorAll('.prompt-let-once, .prompt-let-session, .prompt-let-once-only, .ask-error, .prompt-let-done')) b.remove();
  row.append(el('span', { class: 'prompt-let-done', text }));
}

/**
 * Opened for an ask (dashboard.md §4.25h): a note above the story, and the
 * step where Mandu stopped marked, unfolded and scrolled to. When the step
 * is not on the page, the note says so; nothing else is marked.
 */
function markFocus(story, focus) {
  const found = !!focus.turnId;
  const note = found
    ? el('div', { class: 'focus-note', role: 'note' },
      'You came here from an answer. The marked step is where Mandu stopped and asked you.' +
      (focus.match === 'destination' ? ' It was found by where the data was going, as this record is older than the exact link.' : ''))
    : el('div', { class: 'focus-note missing', role: 'note' },
      ...(HAS_DEV ? ['Mandu could not find the moment it asked in this session. ', traceLink('The detailed trace', null, focus.ask), ' has every step.'] : ['Mandu could not find the moment it asked in this session.']));
  story.prepend(note);
  if (!found) return;
  // Compared as values, never spliced into a selector: ids are server data.
  const turn = [...story.querySelectorAll('article.turn')].find((t) => t.dataset.turnId === focus.turnId);
  if (!turn) return;
  let target = focus.stepId ? [...turn.querySelectorAll('[data-step-id]')].find((x) => x.dataset.stepId === focus.stepId) : null;
  if (target) {
    const fold = target.closest('.steps-more');
    if (fold && fold.hidden) {
      // Each fold's button is in the row right after it.
      const btn = fold.nextElementSibling && fold.nextElementSibling.querySelector('.steps-toggle');
      if (btn) btn.click();
    }
    target.classList.add('focus');
    (target.querySelector('.what') || target).append(el('div', { class: 'focus-tag', text: 'Mandu asked you here' }));
  } else {
    target = turn;
    turn.classList.add('focus');
  }
  // Scrolled to once a visit, as the marked card of Approvals is: a redraw
  // (the agent did more) leaves you where you scrolled.
  focusMarked(target, false);
  if (S.agentScrolled === S.visit) return;
  S.agentScrolled = S.visit;
  focusMarked(target, true);
  requestAnimationFrame(() => { if (target.scrollIntoView) target.scrollIntoView({ block: 'center' }); });
}

function storyTag(outcome) {
  return STORY_TAG[outcome] ? el('span', { class: 'tag ' + outcome, text: STORY_TAG[outcome] }) : el('span');
}
function storyIcon(name) {
  return el('span', { class: 'ic' }, svg(ICON[STORY_ICON[name] || name] || ICON.tool, 18));
}

function turnNode(turn) {
  const card = el('article', { class: 'turn', 'data-turn-id': turn.id });
  const q = el('div', { class: 'turn-q' }, el('div', { class: 'note', text: turn.shell ? 'You ran' : turn.prompt ? 'You asked' : 'Before your first question' }));
  if (turn.shell) {
    q.append(el('div', { class: 'q-text' }, el('code', { text: turn.shell.command })));
    if (turn.shell.output.length) q.append(clipped(turn.shell.output, 'q-out', 'data'));
  } else if (turn.prompt) q.append(clipped(turn.promptParts || [{ kind: 'text', text: turn.prompt }], 'q-text', true));
  if (turn.promptNote) q.append(promptNoteNode(turn.promptNote));
  card.append(el('div', { class: 'turn-head' }, turnTime(turn.ts), q));
  // The secrets it names draw as code, as in the steps below it.
  if (turn.summary) card.append(sentenceNode(turn.summaryParts || [{ kind: 'text', text: turn.summary }], 'turn-summary ' + turn.tone));

  const hasSplit = turn.steps.some((s) => s.kind === 'action' && s.split) || !!(turn.reply && turn.reply.ai);
  if (hasSplit) {
    card.append(el('div', { class: 'cols-head', 'aria-hidden': 'true' },
      el('span', { text: 'What the AI saw' }), el('span', { text: 'What really happened' })));
  }
  for (const s of turn.steps.slice(0, STEP_FOLD)) card.append(stepNode(s));
  // Past the first steps, runs of ordinary steps fold behind a button each.
  // A step in STEP_KEEP stays in sight, in its place, and so does the step
  // just before it: what the agent did right before a block, a wait, a send
  // or an unmasked item (shown in time order; no cause is claimed). A lone
  // step is shown, not folded: its button would take the same room.
  let run = [];
  const flush = () => {
    if (run.length === 1) card.append(stepNode(run[0]));
    else if (run.length) {
      const count = run.length;
      const more = el('div', { class: 'steps-more', hidden: true });
      for (const s of run) more.append(stepNode(s));
      const btn = el('button', { type: 'button', class: 'btn small steps-toggle', 'aria-expanded': 'false', text: 'Show ' + n(count, 'more step', 'more steps') });
      btn.addEventListener('click', () => {
        more.hidden = !more.hidden;
        btn.setAttribute('aria-expanded', String(!more.hidden));
        btn.textContent = more.hidden ? 'Show ' + n(count, 'more step', 'more steps') : 'Show fewer steps';
      });
      card.append(more, el('div', { class: 'step toggle-row' }, btn));
    }
    run = [];
  };
  for (const s of turn.steps.slice(STEP_FOLD)) {
    if (!(s.kind === 'action' && STEP_KEEP.has(s.outcome))) { run.push(s); continue; }
    const lead = run.pop();
    flush();
    if (lead) card.append(stepNode(lead));
    card.append(stepNode(s));
  }
  flush();
  // "Show them" asks for every step of this turn, and the first of them
  // (`moreFrom`, its step id) takes the focus; the trace link opens there.
  if (turn.moreSteps) {
    card.append(restLine(turn.moreSteps, 'more step', 'more steps', turn.allSteps === true, [null, null, turn.moreFrom],
      (btn) => showAgentRest(btn, (s) => { if (!s.steps.includes(turn.id)) s.steps.push(turn.id); }, { kind: 'steps', turn: turn.id, step: turn.moreFrom })));
  }
  if (turn.reply) card.append(replyNode(turn.reply));
  if (turn.routine) {
    // Each kind in plain words ("4 connections to api.anthropic.com"), never
    // "checks" for traffic; a server without the words still gets a count.
    const line = sentenceNode(turn.routine.parts || [{ kind: 'text', text: 'In the background: ' + n(turn.routine.count, 'step', 'steps') + '.' }], 'routine');
    line.title = 'Steps that needed nothing from you.' + (HAS_DEV ? ' The detailed trace lists each one.' : '');
    // Each of them on a press, in every build (dashboard.md §4.25ae): the
    // page asks for this turn's list, and its first line takes the focus.
    // The button sits in the line's own row, before its words (drawn on the
    // right), so the line still ends the turn until the list comes.
    if (Array.isArray(turn.routine.items)) card.append(line, routineList(turn.routine));
    else {
      const btn = el('button', { type: 'button', class: 'btn small routine-show', text: turn.routine.count === 1 ? 'List it' : 'List them' });
      btn.setAttribute('aria-label', rowControlName(btn.textContent, lineWords(line)));
      btn.addEventListener('click', () => showAgentRest(btn, (s) => { if (!s.background.includes(turn.id)) s.background.push(turn.id); }, { kind: 'background', turn: turn.id }));
      card.append(el('div', { class: 'routine-more' }, btn), line);
    }
  }
  return card;
}

/** A turn's background steps, one line each: the time, then what. */
function routineList(r) {
  const ul = el('ul', { class: 'routine-list' });
  for (const item of r.items) {
    const ms = Date.parse(item.ts);
    ul.append(el('li', null, el('time', { datetime: item.ts, title: Number.isFinite(ms) ? clockWords(ms) : null, text: hhmm(item.ts) || item.ts }), ' ', sentenceNode(item.parts, 'routine-what')));
  }
  if (r.moreItems) ul.append(el('li', { class: 'dim', text: n(r.moreItems, 'more background step is', 'more background steps are') + ' past what this page shows.' }));
  return ul;
}

/** Long text shows its start and a "Show all" toggle. */
/** Story parts clipped to PROMPT_CLIP characters behind "Show all"; a
 *  masked item stays a chip either way; `md` as sentenceNode takes it. */
function clipped(parts, cls, md) {
  const len = parts.reduce((a, p) => a + p.text.length, 0);
  if (len <= PROMPT_CLIP) return sentenceNode(parts, cls, md);
  const cut = [];
  let left = PROMPT_CLIP;
  for (const p of parts) {
    if (left <= 0) break;
    cut.push(p.kind === 'masked' || p.text.length <= left ? p : { ...p, text: p.text.slice(0, left).trimEnd() });
    left -= p.text.length;
  }
  cut.push({ kind: 'text', text: '…' });
  const node = el('div', { class: cls });
  let body = sentenceNode(cut, '', md);
  const btn = el('button', { type: 'button', class: 'linkish', 'aria-expanded': 'false', text: 'Show all' });
  btn.addEventListener('click', () => {
    const open = btn.getAttribute('aria-expanded') !== 'true';
    const next = sentenceNode(open ? parts : cut, '', md);
    body.replaceWith(next);
    body = next;
    btn.setAttribute('aria-expanded', String(open));
    btn.textContent = open ? 'Show less' : 'Show all';
  });
  node.append(body, ' ', btn);
  return node;
}

function stepNode(s) {
  if (s.kind === 'setup') {
    const list = el('details', { class: 'files' },
      el('summary', { text: 'Show the ' + n(s.files.length, 'file', 'files') }),
      el('ul', null, ...s.files.map((f) => el('li', null, el('code', { text: f })))));
    return el('div', { class: 'step wide' }, storyIcon('shield'),
      el('div', { class: 'what' }, el('div', { text: 'Prepared the workspace: ' + n(s.files.length, 'file was', 'files were') + ' masked before the agent started.' }), list),
      storyTag('masked'));
  }
  if (s.kind === 'aside') {
    return el('div', { class: 'step wide said' }, storyIcon('chat'), el('div', { class: 'what', text: 'The agent condensed the conversation to save room.' }), el('span'));
  }
  if (s.kind === 'said') {
    const what = el('div', { class: 'what' }, el('div', { class: 'note', text: 'The agent said' }), sentenceNode(s.parts, '', true));
    return el('div', { class: 'step wide said' }, storyIcon('chat'), what, el('span'));
  }
  const what = el('div', { class: 'what' }, sentenceNode(s.sentence, ''));
  // A note with a link (a step that reached the AI unmasked) comes as parts;
  // the link opens the trace at this step.
  if (Array.isArray(s.noteParts) && s.noteParts.length) what.append(sentenceNode(s.noteParts, 'note', false, s.id));
  else if (s.note) what.append(el('div', { class: 'note', text: s.note }));
  // Why Mandu blocked or held it, from the rule its event recorded
  // (agent-page.ts decidingGate / osSentence, block-why.ts; §4.25b).
  if (s.why && s.why.length) {
    const why = sentenceNode(s.why, 'note why');
    why.prepend(el('span', { class: 'why-label', text: 'Why:' }), ' ');
    what.append(why);
  }
  // The Approvals row it filed, so the story leads to where you answer
  // (§4.25b, *A stop says Mandu asked you*); that page marks the row. Once
  // answered, the answer of that row, in the words of that page.
  if (s.askId) {
    const asked = el('div', { class: 'note asked' }, 'Mandu asked for your OK in ', askRowLink(s.askId, 'Approvals'), '.');
    const answer = answerLabel(s.answer);
    if (answer) asked.append(' Your answer: ' + answer + '.');
    what.append(asked);
  }
  // What changed for it after this step ("Masked from 10:42 on, …").
  if (s.later && s.later.length) what.append(sentenceNode(s.later, 'note later'));
  // Its outcome is data too, the hook a count tile finds it by (goToOutcome).
  if (!s.split) return el('div', { class: 'step wide ' + s.outcome, 'data-step-id': s.id, 'data-outcome': s.outcome }, storyIcon(s.icon), what, storyTag(s.outcome));
  what.append(sentenceNode(s.split.ai, 'saw-line'));
  return el('div', { class: 'step split ' + s.outcome, 'data-step-id': s.id, 'data-outcome': s.outcome },
    el('div', { class: 'half saw' },
      el('div', { class: 'half-label', text: 'What the AI saw' }),
      el('div', { class: 'half-body' }, storyIcon(s.icon), what, storyTag(s.outcome))),
    el('div', { class: 'half real' },
      el('div', { class: 'half-label', text: 'What really happened' }),
      sentenceNode(s.split.real, 'real-line'),
      hiddenNode(s.split.hidden, s.id)));
}

/** "Show the real value" of one secret (dashboard.md §4.25b): signed in
 *  only, one click, one value. The page never has it: the click asks the
 *  server for that secret by its ref, the answer goes in the box as text,
 *  and hiding it again takes it out of the page. `name` labels the button
 *  when an item held more than one secret; `about` (the words the page
 *  draws for the secret: a Your secrets card heading, a step secret name)
 *  names it otherwise, so no two read alike, and "Hide it again" is named
 *  by either (§4.25b, *Show the real value names its secret*). A name is
 *  only words already drawn, never the value. */
function secretValueBox(ref, name, host, about) {
  const label = name ? 'Show the real value of ' + name : 'Show the real value';
  const of = name || about || '';
  const caption = el('div', { class: 'hidden-caption', hidden: true, text: 'Only you see this. The AI still has only the masked version.' });
  // A box that scrolls, named (dashboard.md §4.25): never the value itself.
  const pre = el('pre', { class: 'hidden-text secret-value', role: 'group', 'aria-label': name ? 'The real value of ' + name : 'The real value', hidden: true });
  const btn = el('button', { type: 'button', class: 'btn small reveal secret-reveal', 'aria-expanded': 'false' });
  // The visible words, and the name when they do not say the secret.
  const say = (words, named) => {
    btn.textContent = words;
    if (named && of) btn.setAttribute('aria-label', rowControlName(words, of));
    else btn.removeAttribute('aria-label');
  };
  say(label, !name);
  btn.addEventListener('click', async () => {
    if (btn.getAttribute('aria-expanded') === 'true') {
      pre.hidden = true; caption.hidden = true; clear(pre);
      btn.setAttribute('aria-expanded', 'false');
      say(label, !name);
      return;
    }
    const had = document.activeElement === btn;
    const at = revealPlace(btn);
    btn.disabled = true;
    const r = await apiPost('home/reveal', { session: S.agentId, ref });
    btn.disabled = false;
    revealAnswered(btn, at, r, had);
  });
  // The value goes only in a box of its own ref (revealAnswered).
  const answered = (r, had) => {
    if (!r.ok || !r.data || typeof r.data.value !== 'string') {
      showAskError(host, refusalText(r, 'could not show it'));
      focusBack(btn, had, host.querySelector('.ask-error'));
      return;
    }
    pre.textContent = r.data.value;
    pre.hidden = false; caption.hidden = false;
    btn.setAttribute('aria-expanded', 'true');
    say('Hide it again', true);
    focusBack(btn, had, null);
  };
  REVEALS.set(btn, { key: JSON.stringify(['secret', ref, name, about]), answered });
  return el('div', { class: 'hidden-box secret-value-box' }, btn, caption, pre);
}

/** The original behind a masked item: behind a button. A secret: signed in,
 *  its real value on a click (secretValueBox); signed out, how to sign in.
 *  `at`: the step it is under, where "The detailed trace" opens. */
function hiddenNode(h, at) {
  if (!h) return null;
  if (h.secret && S.valuesShown === false) return el('div', { class: 'hidden-note values-withheld' }, svg(ICON.lock, 14), el('span', null, words(SIGN_IN_VALUES)));
  if (h.secret && h.secrets && h.secrets.length) {
    const box = el('div', { class: 'secret-values' });
    for (const s of h.secrets) box.append(secretValueBox(s.ref, h.secrets.length > 1 ? s.name : null, box, s.name));
    return box;
  }
  if (h.secret) return el('div', { class: 'hidden-note' }, svg(ICON.lock, 14), el('span', { text: 'Its value is not on this page.' }));
  if (h.text === null && S.valuesShown === false) return el('div', { class: 'hidden-note values-withheld' }, svg(ICON.lock, 14), el('span', null, words(SIGN_IN_VALUES)));
  if (h.text === null) {
    return el('div', { class: 'hidden-note' }, el('span', null, ...(HAS_DEV ? ['The original was not recorded here. ', traceLink('The detailed trace', null, null, at), ' may have it.'] : ['The original was not recorded here.'])));
  }
  const caption = el('div', { class: 'hidden-caption', hidden: true, text: 'Content from outside. Mandu kept it away from the AI.' });
  const pre = el('pre', { class: 'hidden-text', role: 'group', 'aria-label': 'What was hidden', hidden: true, text: h.text + (h.truncated ? '\n…' : '') });
  const btn = el('button', { type: 'button', class: 'btn small reveal', 'aria-expanded': 'false', text: 'Show what was hidden' });
  // Cut at the page's cap: signed in, the rest on a click (dashboard.md
  // §4.25ae, GET /api/home/original, admin only), shown while the box is.
  const whole = h.truncated && at && S.valuesShown !== false ? wholeOriginalButton(pre, at) : null;
  btn.addEventListener('click', () => {
    const open = pre.hidden;
    pre.hidden = !open;
    caption.hidden = !open;
    if (whole && !whole.dataset.done) whole.hidden = !open;
    btn.setAttribute('aria-expanded', String(open));
    btn.textContent = open ? 'Hide it again' : 'Show what was hidden';
  });
  return el('div', { class: 'hidden-box' }, btn, caption, pre, whole);
}

/** "Show the whole original" under an original cut at the page's cap: asks
 *  the server for that step's whole original (admin only; dashboard.md
 *  §4.25ae) and puts it in the box as text. Once shown, the button goes and
 *  the box takes the focus; a refusal says why beside it. */
function wholeOriginalButton(pre, stepId) {
  const btn = el('button', { type: 'button', class: 'btn small whole-original', hidden: true, text: 'Show the whole original' });
  btn.addEventListener('click', async () => {
    const box = btn.parentElement;
    btn.disabled = true;
    const r = await apiGetControl('home/original?session=' + enc(S.agentId || '') + '&step=' + enc(stepId));
    btn.disabled = false;
    if (!r.ok || !r.data || typeof r.data.text !== 'string') {
      if (box) showAskError(box, refusalText(r, 'could not show the whole original'));
      return;
    }
    pre.textContent = r.data.text + (r.data.truncated ? '\n…' : '');
    btn.dataset.done = '1';
    btn.hidden = true;
    pre.setAttribute('tabindex', '-1');
    focusThere(pre);
  });
  return btn;
}

/** Under a reply (dashboard.md §4.25b): the secrets it held, which this
 *  page keeps masked, and for an ordinary item it could not fill in, why
 *  (as a step does: signed out, how to sign in). */
function replyNotes(r) {
  const out = [];
  if (r.kept && r.kept.length) out.push(el('div', { class: 'hidden-note reply-kept' }, svg(ICON.lock, 14), sentenceNode(r.kept, 'kept-text')));
  if (r.unresolved) out.push(hiddenNode({ text: null, secret: false, truncated: false }));
  return out;
}

/** A reply splits only when this page filled in a masked item (r.ai); else
 *  it is one card, since both halves would read the same. A long one folds
 *  (foldReply), its button last, under what the reply held. */
function replyNode(r) {
  if (!r.ai) {
    const text = sentenceNode(r.parts, 'reply-text', true);
    return el('div', { class: 'step wide reply' }, storyIcon('chat'),
      el('div', { class: 'what' }, el('div', { class: 'note', text: 'The agent replied' }), text, ...replyNotes(r), foldReply([text])), el('span'));
  }
  const saw = sentenceNode(r.ai, 'reply-text', true);
  const real = sentenceNode(r.parts, 'reply-text', true);
  return el('div', { class: 'step split reply' },
    el('div', { class: 'half saw' },
      el('div', { class: 'half-label', text: 'What the AI saw' }),
      el('div', { class: 'half-body' }, storyIcon('chat'),
        el('div', { class: 'what' }, el('div', { class: 'note', text: 'The agent wrote' }), saw), el('span'))),
    el('div', { class: 'half real' },
      el('div', { class: 'half-label', text: 'What really happened' }),
      el('div', { class: 'note', text: 'You saw, with the masked items filled in' }),
      real, ...replyNotes(r)),
    foldReply([saw, real]));
}

/** A long reply folds to its first lines (dashboard.md §4.25b, *A long
 *  reply folds*). Taller as drawn than 12 of its lines, each text shows its
 *  first 10, fading out (`.reply-text.folded`, whose height app.css holds),
 *  under one "Show the whole reply"; a split passes both halves, which fold
 *  together. Measured where the page draws it, so a phone folds sooner, and
 *  again when its width changes (replySizes). A browser that scrolls a
 *  folded text to show something in it (find in page, a Tab to a link in
 *  it) opens the fold, and the page keeps that spot in view. Returns the
 *  button row, hidden while the reply fits. */
let replyFolds = 0;
const replyFits = new WeakMap();
const replySizes = typeof ResizeObserver === 'function'
  ? new ResizeObserver((seen) => { for (const x of seen) { const fit = replyFits.get(x.target); if (fit) fit(); } })
  : null;
function foldReply(texts) {
  for (const t of texts) t.id = 'reply-text-' + (++replyFolds);
  const btn = el('button', { type: 'button', class: 'btn small reply-fold', 'aria-expanded': 'false', 'aria-controls': texts.map((t) => t.id).join(' '), text: 'Show the whole reply' });
  const row = el('div', { class: 'reply-fold-row', hidden: true }, btn);
  const fit = () => {
    // Not drawn (another page shows): left as it is until it is.
    if (texts.every((t) => !t.scrollHeight)) return;
    let long = false;
    for (const t of texts) {
      const was = t.classList.contains('folded');
      t.classList.add('folded');
      const cut = parseFloat(getComputedStyle(t).maxHeight) || 210;
      if (!was) t.classList.remove('folded');
      if (t.scrollHeight > cut * 1.2) long = true;
    }
    row.hidden = !long;
    const fold = long && btn.getAttribute('aria-expanded') !== 'true';
    for (const t of texts) t.classList.toggle('folded', fold);
  };
  const toggle = (open) => {
    btn.setAttribute('aria-expanded', String(open));
    btn.textContent = open ? 'Show less' : 'Show the whole reply';
    fit();
  };
  btn.addEventListener('click', () => {
    const open = btn.getAttribute('aria-expanded') !== 'true';
    toggle(open);
    // Folded again: the button stays in view, under the text it folded.
    if (!open && btn.getBoundingClientRect().top < 0 && btn.scrollIntoView) btn.scrollIntoView({ block: 'nearest' });
  });
  for (const t of texts) {
    replyFits.set(t, fit);
    if (replySizes) replySizes.observe(t);
    t.addEventListener('scroll', () => {
      if (!t.classList.contains('folded') || t.scrollTop <= 0) return;
      const top = t.getBoundingClientRect().top - t.scrollTop;
      toggle(true);
      window.scrollBy(0, t.getBoundingClientRect().top - top);
    });
  }
  if (!replySizes) requestAnimationFrame(fit);
  return row;
}

// ── Notifications, tab title and badge ───────────────────────────────────────
const SEEN_KEY = 'mandu.home.seenAsks';
function readSeen() {
  try { return new Set(JSON.parse(localStorage.getItem(SEEN_KEY) || '[]')); } catch { return new Set(); }
}
function writeSeen(ids) {
  try { localStorage.setItem(SEEN_KEY, JSON.stringify([...ids].slice(-500))); } catch { /* private mode: notify again next load */ }
}
function notifySupported() { return typeof window.Notification === 'function'; }

/** Settings › Notifications' Turn off, a choice of this browser (another
 *  browser or profile still notifies). Where storage fails (private mode)
 *  it holds for this tab, as priming does. */
const NOTIFY_OFF_KEY = 'mandu.home.notifyOff';
function notifyOff() {
  if (S.notifyOffTab !== undefined) return S.notifyOffTab;
  try { return localStorage.getItem(NOTIFY_OFF_KEY) === '1'; } catch { return false; }
}
function setNotifyOff(off) {
  try {
    if (off) localStorage.setItem(NOTIFY_OFF_KEY, '1'); else localStorage.removeItem(NOTIFY_OFF_KEY);
    S.notifyOffTab = undefined;
  } catch { S.notifyOffTab = off; }
}

/** One notification per ask and per rule change this browser has not seen
 *  (dashboard.md §4.25 *Notifications*). The first visit in a browser
 *  records the backlog silently, so opening the page never floods; after
 *  that, every new one notifies once: asks first, at most three per poll,
 *  and past three one more line, "Mandu: 2 more need your OK". While turned
 *  off in Settings nothing is shown, but every one is still recorded as
 *  seen, so turning them on again never brings the backlog. */
function notifyNewAsks(home) {
  const fresh = [];
  if (home && home.waitingKnown) {
    let primed = false;
    try { primed = localStorage.getItem(PRIMED_KEY) === '1'; } catch { primed = S.notifyPrimed === true; }
    const seen = readSeen();
    const news = home.waiting.filter((a) => !seen.has(a.id));
    for (const a of home.waiting) seen.add(a.id);
    writeSeen(seen);
    S.notifyPrimed = true;
    try { localStorage.setItem(PRIMED_KEY, '1'); } catch { /* per-tab priming only */ }
    if (primed) {
      for (const a of news) {
        fresh.push(['Mandu: ' + (a.agents[0] || 'An agent') + ' needs your OK', a.sentence.map((p) => p.text).join(''),
          'mandu-ask-' + a.id, () => setPage('approvals', true, undefined, a.id)]);
      }
    }
  }
  // Rule changes: only from a read that answered (a viewer without the
  // admin session is refused them), so a refused read primes nothing.
  if (S.proposalsKnown) {
    const seen = readProposalsSeen();
    const news = seen ? S.proposals.filter((p) => !seen.has(p.id)) : [];
    const ids = seen || new Set();
    for (const p of S.proposals) ids.add(p.id);
    writeProposalsSeen(ids);
    for (const p of news) {
      const title = proposalNoteTitle(p);
      if (title) fresh.push([title, 'Open Approvals to answer it.', 'mandu-proposal-' + p.id, () => setPage('approvals', true, undefined, p.id)]);
    }
  }
  for (const f of fresh.slice(0, 3)) showAlarm(...f);
  if (fresh.length > 3) {
    showAlarm('Mandu: ' + n(fresh.length - 3, 'more needs', 'more need') + ' your OK', 'Open Approvals to see them.',
      'mandu-more', () => setPage('approvals', true));
  }
}
const PRIMED_KEY = 'mandu.home.notifyPrimed';
/** A waiting rule change's notification title, or null for one you asked
 *  for yourself (you know about it). Fixed words: never the card's rows,
 *  the agent's reason (UNTRUSTED text) nor a file or host it names, since a
 *  desktop notification can be mirrored off the machine. */
function proposalNoteTitle(p) {
  if (p.onDisk) return 'Mandu: a change to policy.yaml waits for your OK';
  return askedByAgent(p) ? 'Mandu: your agent asks to change a rule' : null;
}
/** The rule changes this browser has seen waiting; null on its first visit,
 *  which records them silently (the asks' priming rule, under its own key:
 *  a browser primed for asks before rule changes notified does not get
 *  their backlog). Where storage fails (private mode) the tab keeps them. */
const SEEN_PROPOSALS_KEY = 'mandu.home.seenProposals';
function readProposalsSeen() {
  try {
    const v = localStorage.getItem(SEEN_PROPOSALS_KEY);
    if (v !== null) return new Set(JSON.parse(v));
  } catch { /* the tab's own copy, below */ }
  return S.seenProposalsTab ? new Set(S.seenProposalsTab) : null;
}
function writeProposalsSeen(ids) {
  S.seenProposalsTab = [...ids].slice(-500);
  try { localStorage.setItem(SEEN_PROPOSALS_KEY, JSON.stringify(S.seenProposalsTab)); } catch { /* the tab keeps them */ }
}

/** The product's two worst states, told to a person not looking at the tab
 *  (dashboard.md §4.25 *Notifications*): a session that newly shows
 *  protection failed, and the protection service stopping right after a
 *  read that listed a running agent. Called with the answer `loadHome`
 *  keeps (`home`), or with the cause of the poll that failed (`failure`).
 *  The words name the agent only, never a file, host, prompt or secret: a
 *  desktop notification can be mirrored off the machine. */
function notifyAlarms(home, failure) {
  if (home) {
    const failed = (home.agents || []).filter((a) => a.holds === false);
    const seen = readFailedSeen();
    const fresh = seen ? failed.filter((a) => !seen.has(a.id)) : [];
    const ids = seen || new Set();
    for (const a of failed) ids.add(a.id);
    writeFailedSeen(ids);
    S.alarmRunning = (home.agents || []).some((a) => a.state && a.state !== 'idle');
    for (const a of fresh.slice(0, 3)) {
      showAlarm('Mandu: protection failed in ' + (a.agent || 'an agent'),
        'Something reached the AI unmasked. Open its page to see what.',
        'mandu-failed-' + a.id, () => setPage('agent', true, a.id));
    }
    return;
  }
  // Once per stop: the next failed polls follow a failed one, not a read
  // that listed a running agent. A stop between agents says nothing.
  const running = S.alarmRunning === true;
  S.alarmRunning = false;
  if (failure !== 'down' || !running) return;
  showAlarm('Mandu: the protection service stopped',
    "Your agent's requests are blocked until it runs again. Open Settings to start it.",
    'mandu-service-stopped', () => setPage('settings', true));
}
/** The sessions this browser has seen failed; null on its first visit,
 *  which records them silently (the asks' priming rule). Where storage
 *  fails (private mode) the tab keeps them. */
const FAILED_KEY = 'mandu.home.seenFailed';
function readFailedSeen() {
  try {
    const v = localStorage.getItem(FAILED_KEY);
    if (v !== null) return new Set(JSON.parse(v));
  } catch { /* the tab's own copy, below */ }
  return S.seenFailedTab ? new Set(S.seenFailedTab) : null;
}
function writeFailedSeen(ids) {
  S.seenFailedTab = [...ids].slice(-500);
  try { localStorage.setItem(FAILED_KEY, JSON.stringify(S.seenFailedTab)); } catch { /* the tab keeps them */ }
}
function showAlarm(title, body, tag, open) {
  if (notifyOff() || !notifySupported() || Notification.permission !== 'granted') return;
  try {
    const note = new Notification(title, { body, tag });
    note.onclick = () => { window.focus(); open(); note.close(); };
  } catch { /* some browsers only allow notifications from a service worker */ }
}

function renderNotifyControls() {
  const offer = document.getElementById('notify-offer');
  const state = document.getElementById('notify-state');
  const enable = document.getElementById('notify-enable');
  if (!notifySupported()) {
    offer.hidden = true;
    state.textContent = 'This browser cannot show notifications here. They need a secure address (https or localhost).';
    enable.hidden = true;
    return;
  }
  const p = Notification.permission;
  // Granted: the button turns them off and on in this browser (a page cannot
  // take a permission back). The Home offer stays hidden either way.
  const off = p === 'granted' && notifyOff();
  offer.hidden = p !== 'default';
  enable.hidden = p === 'denied';
  enable.textContent = p === 'granted' && !off ? 'Turn off' : 'Turn on';
  state.textContent = p === 'granted'
    ? (off ? 'Off in this browser. The tab title still counts what waits.' : 'On. You get a notification when an agent needs your OK, when protection fails, and when the protection service stops under a running agent.')
    : p === 'denied'
      ? 'Blocked in this browser. Allow notifications for this site in the browser settings.'
      : 'Off.';
}

async function askNotifyPermission() {
  if (!notifySupported()) return;
  try { await Notification.requestPermission(); } catch { /* old callback-style API: ignore */ }
  // Asking from a button means wanting them, even after an earlier Turn off.
  if (Notification.permission === 'granted') setNotifyOff(false);
  renderNotifyControls();
}

/** Settings' button: with permission granted it flips this browser's choice
 *  and redraws only its own row, so the focus stays on it (§4.25 *A
 *  Settings row's button names its row; a change keeps the focus*);
 *  otherwise it asks for the permission. */
function pressNotifyButton() {
  if (!notifySupported()) return;
  if (Notification.permission !== 'granted') { askNotifyPermission(); return; }
  setNotifyOff(!notifyOff());
  renderNotifyControls();
}

// ── Settings › Appearance (dashboard.md §4.25 Settings, §4.25k) ──────────────
// Light, dark or the system's, in this browser. The key and values are the
// developer view's Appearance row's, so a pick on either page is the other's
// too (on its next load). 'system' leaves <html> bare, so mandu.css follows
// prefers-color-scheme; 'light' / 'dark' pin data-theme. A stored value this
// page does not know (the retired theme-* palettes) reads as 'system'.
// js/theme-early.js applies the stored choice before the first paint, by the
// same rule; this applies it again (a no-op then) and wires the menu.
const THEME_KEY = 'mandu.theme';
const THEMES = ['system', 'light', 'dark'];
function applyTheme(theme) {
  const t = THEMES.includes(theme) ? theme : THEMES[0];
  if (t === 'system') document.documentElement.removeAttribute('data-theme');
  else document.documentElement.setAttribute('data-theme', t);
  return t;
}
function wireAppearance() {
  const sel = document.getElementById('settings-theme');
  const note = document.getElementById('settings-theme-note');
  sel.value = applyTheme(lsGet(THEME_KEY));
  sel.addEventListener('change', () => {
    const t = applyTheme(sel.value);
    sel.value = t;
    // A private window still switches the page; it only cannot keep it.
    note.textContent = lsSet(THEME_KEY, t) ? '' : 'Not remembered in this window.';
  });
}

/** "(3) Mandu" in the tab, and a count on the favicon. */
function renderTitle() {
  const k = (S.home && S.home.waitingKnown ? S.home.waiting.length : 0) + S.proposals.length;
  document.title = (k ? '(' + k + ') ' : '') + (S.pageTitle || 'Mandu');
  const link = document.getElementById('favicon');
  if (!link) return;
  if (!S.baseFavicon) S.baseFavicon = link.href;
  if (!k) { link.href = S.baseFavicon; return; }
  const label = k > 9 ? '9+' : String(k);
  const svgText = "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'>"
    + "<path d='M16 3l10 4v8c0 7-5 11-10 14C11 26 6 22 6 15V7z' fill='%231e7f4f'/>"
    + "<circle cx='23' cy='9' r='9' fill='%23a35d00'/>"
    + "<text x='23' y='13' font-size='" + (label.length > 1 ? 9 : 12) + "' font-family='sans-serif' font-weight='700' fill='white' text-anchor='middle'>" + label + '</text></svg>';
  link.href = 'data:image/svg+xml,' + svgText.replace(/#/g, '%23').replace(/</g, '%3C').replace(/>/g, '%3E');
}

// ── Settings ──────────────────────────────────────────────────────────────────
/** The declared models (plan 11 D6; dashboard.md §4.25l): add, edit, remove
 *  and test them here. The page sends the form's fields; the server plans the
 *  change and asks before it applies (every change to this list loosens
 *  protection somewhere). Never a token: only the name of the setting that
 *  holds it. */
const M = { models: [], locked: false,
  // An unread list with no service behind it: why its read failed
  // (readFailure, null: it answered) and the cause its line says.
  unread: null,
  // What opened the form: the model whose Edit was pressed, null for Add
  // a model (modelFormBack).
  formFrom: null,
  // The version of the model the form was filled from (the panel's
  // models[].version): Save sends it, so a change made to that model
  // meanwhile refuses the save instead of being overwritten
  // (dashboard.md §4.25l *A save names the model as it was read*).
  formVersion: null };

/** A change made in a Settings card, or in Your rules on the Rules page,
 *  keeps the keyboard focus (dashboard.md §4.25 *A change in Settings keeps
 *  the focus*, *A change in Your rules keeps the focus*). The row's buttons
 *  go off while the change is on its way, and the card's list is drawn again
 *  after it: Chromium drops the focus of a button turned off, or gone, to
 *  the page (<body>), so until 2026-10-11 every Save, Remove, Use the
 *  default, Test connection, a rule's menu and Undo left a screen reader at
 *  the top of the page. Where the focus is in the card is taken before the
 *  buttons go off, as the poll takes it (pollPlace: a row by its data-id,
 *  data-name, data-category and data-match, a rule or answer by its
 *  data-rule), and given back after, only if it fell: to the control drawn
 *  at that place that reads the same, else the card's heading (pollRefocus),
 *  never another row's button. A refusal shown on the row (`refused`)
 *  describes the button given the focus back. */
function settingsPlace(x) {
  const card = x.closest('section.block');
  return card ? pollPlace(card) : null;
}
function settingsRefocus(place, refused) {
  pollRefocus(place);
  const words = refused && refused.querySelector('.ask-error');
  const a = document.activeElement;
  if (words && a && refused.contains(a)) a.setAttribute('aria-describedby', words.id);
}

/** The line of an unread model list: with no service behind it, the
 *  cause the page knows (panelCause; followCannotCheck draws it again). */
function drawModelsUnread(host) {
  clear(host);
  const lead = 'The model list could not be read.';
  if (!M.unread) { host.append(el('div', { class: 'empty', text: lead })); return; }
  M.unread.cause = panelCause(M.unread.failure);
  host.append(el('div', { class: 'empty' }, ...cannotCheck(lead, M.unread.cause, true)));
}

// Settings: each card is read when the page opens and after each change made
// in it (readsInOrder): never a row drawn as it was before a later change.
const MODEL_READS = readsInOrder();
const LABEL_READS = readsInOrder();
const PROMPT_READS = readsInOrder();

async function loadModels() {
  const host = document.getElementById('settings-models');
  if (!host) return;
  const asked = MODEL_READS.ask();
  let panel = null;
  let failure = null;
  try { panel = (await apiGet('policy/panel')).panel; } catch (err) { panel = null; failure = readFailure(err); }
  if (!MODEL_READS.take(asked)) return;
  clear(host);
  // A list that could not be read offers no Add: there is nothing to add to
  // (dashboard.md §4.25 "Empty states").
  const unread = !panel || !Array.isArray(panel.models);
  modelField('model-open').hidden = unread;
  if (unread) {
    M.models = [];
    closeModelForm();
    // The reason only when no service answered (an older one sends no list).
    M.unread = !panel || panel.available === false ? { failure, cause: null } : null;
    drawModelsUnread(host);
    return;
  }
  M.unread = null;
  M.models = panel.models;
  // Plan 12 D5: your administrator owns part of the list, and may lock it.
  const admin = panel.modelsAdmin || null;
  M.locked = !!(admin && admin.locked);
  if (M.locked) {
    host.append(el('div', { class: 'note model-admin-lock', text: 'Your administrator has locked your own models. You can remove one of theirs or add an outside model; you cannot add or change a model of your own here.' }));
  }
  if (admin && (admin.refused || []).length) {
    host.append(el('div', { class: 'note model-admin-refused', text: "Your administrator's settings changed but could not be used, so the ones read before still apply: " + admin.refused.join('; ') }));
  }
  if (admin && (admin.conflicts || []).length) {
    // The administrator wins: these lines of policy.yaml are not in force.
    const box = el('div', { class: 'note model-admin-conflicts' }, el('div', { text: "Not in use, because your administrator's settings take priority. Change policy.yaml to match:" }));
    const ul = el('ul');
    // Each line without its list position ("models[0]: "): the name of the
    // entry follows.
    for (const c of admin.conflicts) ul.append(el('li', { text: c.replace(/^models\[\d+\](\.[a-z_]+)?: /, '') }));
    box.append(ul);
    host.append(box);
  }
  // Plan 12 D4: where your own models on another machine may be.
  const p = panel.perimeter;
  if (p && p.networks && p.networks.length) {
    const by = p.by === 'administrator' ? ' (set by your administrator)' : p.by === 'narrowed' ? ' (your administrator\'s networks, narrowed in policy.yaml)' : '';
    host.append(el('div', { class: 'model-perimeter', text: 'Your own models on another computer are used only at addresses in ' + p.networks.join(', ') + by + '.' }));
  }
  if (!panel.models.length) {
    host.append(el('div', { class: 'empty', text: 'No models listed. Until you add one of your own, no model reads files marked "Your own AI only".' }));
  } else {
    for (const m of panel.models) host.append(modelRow(m));
  }
  // Plan 12 D5: your administrator's models you removed, with a way back.
  for (const r of (admin && admin.removed) || []) host.append(removedAdminRow(r));
}

function removedAdminRow(r) {
  const row = el('div', { class: 'row service model-row model-removed', 'data-name': r.name });
  row.append(el('div', { class: 'name', text: r.name }));
  row.append(el('div', { class: 'sub', text: "Your administrator's model, removed from your list." }));
  const acts = el('div', { class: 'model-actions' });
  acts.append(el('button', { type: 'button', class: 'btn small model-restore-btn', text: 'Bring back', 'aria-label': 'Bring back the model ' + r.name, onclick: () => restoreModel(r, row) }));
  row.append(acts);
  return row;
}

function modelRow(m) {
  const row = el('div', { class: 'row service model-row', 'data-local': m.local ? 'true' : 'false', 'data-name': m.name });
  row.append(el('div', { class: 'name', text: m.name }));
  const parts = [m.url, m.wireWords || m.wire];
  if (m.model) parts.push('model ' + m.model);
  if (m.tokenEnv) parts.push('key from ' + m.tokenEnv);
  row.append(el('div', { class: 'sub', text: parts.filter(Boolean).join(', ') }));
  row.append(el('div', { class: 'model-where', text: modelWhere(m) }));
  // The buttons take the row's last column; the notes below span the row.
  // Each is named by its row, its own words first (dashboard.md §4.25 *A
  // Settings row's button names its row*).
  const acts = el('div', { class: 'model-actions' });
  acts.append(el('button', { type: 'button', class: 'btn small model-test-btn', text: 'Test connection', 'aria-label': 'Test connection to ' + m.name, onclick: () => testModel(m, row) }));
  if (!m.admin) acts.append(el('button', { type: 'button', class: 'btn small model-edit-btn', text: 'Edit', 'aria-label': 'Edit the model ' + m.name, onclick: () => openModelForm(m) }));
  acts.append(el('button', { type: 'button', class: 'btn small model-remove-btn', text: 'Remove', 'aria-label': 'Remove the model ' + m.name, onclick: () => removeModel(m, row) }));
  row.append(acts);
  if (m.notEncrypted) row.append(el('div', { class: 'model-plain-http', text: 'Not encrypted: files marked "Your own AI only" cross the network in the clear. Use an https address to fix this.' }));
  // Plan 12 D5: set in your administrator's file, so no Edit here.
  if (m.admin) row.append(el('div', { class: 'model-admin', text: m.locked ? 'Set by your administrator. You can remove it, not change it.' : 'Set by your administrator.' }));
  return row;
}

/** "Your own model, on this computer" | "Your own model, on your network
 *  (llm.corp.example), reads your own-model files" | "Outside model". The
 *  placement words come from the server (view-model/model-endpoints.ts). */
function modelWhere(m) {
  if (!m.local) return 'Outside model';
  const parts = ['Your own model'];
  if (m.placementWords) parts.push(m.placementWords.charAt(0).toLowerCase() + m.placementWords.slice(1));
  if (m.tlsWords) parts.push(m.tlsWords);
  if (m.perimeterWords) parts.push(m.perimeterWords);
  if (m.helper) parts.push('reads your own-model files');
  return parts.join(', ');
}

/** Above the list: what just changed, the restart note, and Undo. */
function modelsNotice(text, changeId) {
  const box = document.getElementById('models-notice');
  clear(box);
  box.hidden = !text;
  if (!text) return;
  box.append(noticeWords(box, text));
  if (changeId) {
    box.append(noticeUndo(box, 'Models', async () => {
      const place = settingsPlace(box);
      for (const b of box.querySelectorAll('button')) b.disabled = true;
      const r = await apiPost('policy/changes/' + encodeURIComponent(changeId) + '/undo');
      if (!r.ok) { modelsNotice(refusalText(r, 'could not undo (' + r.status + ')'), null); settingsRefocus(place); return; }
      MODEL_READS.wrote();
      modelsNotice('Undone. New sessions use the list as it was. Restart a running agent to use it there.', null);
      await loadModels();
      settingsRefocus(place);
    }));
  }
}

function modelField(id) { return document.getElementById(id); }

function openModelForm(m) {
  const form = modelField('model-form');
  form.reset();
  modelField('model-error').textContent = '';
  modelField('model-original').value = m ? m.name : '';
  if (m) {
    modelField('model-name').value = m.name || '';
    modelField('model-url').value = m.url || '';
    modelField('model-wire').value = m.wire === 'openai-chat' ? 'openai-chat' : 'anthropic';
    modelField('model-model').value = m.model || '';
    modelField('model-local').checked = m.local === true;
    modelField('model-helper').checked = m.local === true && m.helperMarked === true;
    modelField('model-plain-http').checked = m.local === true && m.allowPlainHttp === true;
    modelField('model-token-env').value = m.tokenEnv || '';
  }
  // Plan 12 D5: under the lock only an outside model can be added.
  modelField('model-local').disabled = M.locked;
  if (M.locked) modelField('model-local').checked = false;
  syncHelperBox();
  modelField('model-save').textContent = m ? 'Save changes' : 'Save model';
  M.formFrom = m ? m.name : null;
  M.formVersion = m ? m.version || null : null;
  form.hidden = false;
  modelField('model-open').setAttribute('aria-expanded', 'true');
  modelField('model-name').focus();
}

/** "Read my own-model files with this one" means something only for a model
 *  of your own (the validator refuses it on an outside model). */
function syncHelperBox() {
  const own = modelField('model-local').checked;
  const box = modelField('model-helper');
  box.disabled = !own;
  if (!own) box.checked = false;
  // "Send without encryption" means something only for your own model at an
  // http address (the validator refuses it on https; plan 12 D2).
  const plain = modelField('model-plain-http');
  const http = /^http:\/\//i.test(modelField('model-url').value.trim());
  plain.disabled = !own || !http;
  if (plain.disabled) plain.checked = false;
}

function closeModelForm() {
  const form = modelField('model-form');
  form.reset();
  form.hidden = true;
  modelField('model-open').setAttribute('aria-expanded', 'false');
}

/** The Models form keeps the keyboard focus (dashboard.md §4.25 *The Models
 *  form keeps the focus*). Cancel hides the form with the focus on it, and
 *  Save goes off while the change is on its way: until 2026-10-11 each left
 *  a screen reader on <body>. A press counts only with the focus in the form
 *  (modelFormHad); after it, only if the focus fell or sits in the hidden
 *  form (modelFormFell). A form closed gives it back to what opened it: the
 *  Edit of the model's row (after a Save, the row of the name saved), else
 *  Add a model, else the Models heading. A refused or declined Save gives
 *  it back to Save, which the form's error line describes. Escape is
 *  Cancel (wireModelForm). */
function modelFormHad() {
  const a = document.activeElement;
  return !!a && modelField('model-form').contains(a);
}
function modelFormFell(had) {
  const a = document.activeElement;
  return had && (focusFell() || !!a.closest('[hidden]'));
}
function modelFormBack(name) {
  const row = name == null ? null : [...document.querySelectorAll('#settings-models .model-row')].find((r) => r.dataset.name === name);
  const opener = name == null ? modelField('model-open') : row && row.querySelector('.model-edit-btn');
  // The opener may be out of view (a row far down the list): focus()
  // brings it there.
  if (opener && reachable(opener)) { opener.focus(); return; }
  const heading = document.getElementById('settings-models-title');
  if (heading && !heading.closest('[hidden]')) focusThere(heading);
}

/** What the person is asked before a change to the list applies: the change
 *  in plain rows, what it would let, and any warning, all from the server. */
function modelConfirmText(d) {
  const line = (parts) => (parts || []).map((p) => p.text).join('');
  const out = [];
  for (const r of d.rows || []) out.push(line(r) + '.');
  if ((d.wouldLet || []).length) out.push('', 'This changes what Mandu protects:', ...(d.wouldLet || []).map((r) => '- ' + line(r)));
  if ((d.warnings || []).length) out.push('', ...(d.warnings || []).map((r) => 'Warning: ' + line(r)));
  out.push('', 'Continue?');
  return out.join('\n');
}

/** Send one change; ask first when the server says it loosens protection. */
async function sendModelChange(body) {
  let r = await apiPost('policy/models/change', body);
  if (r.ok && r.data && r.data.confirm) {
    if (!window.confirm(modelConfirmText(r.data))) return { cancelled: true };
    r = await apiPost('policy/models/change', { ...body, expected: r.data.expected });
  }
  return r;
}

function modelError(r) {
  const d = r && r.data;
  if (d && Array.isArray(d.problems) && d.problems.length) return (d.error || 'Not saved.') + ' ' + d.problems.join('; ');
  return refusalText(r, 'could not save the model (' + (r ? r.status : 'no answer') + ')');
}

function wireModelForm() {
  const form = modelField('model-form');
  if (!form) return;
  modelField('model-open').addEventListener('click', () => (form.hidden ? openModelForm(null) : closeModelForm()));
  const cancel = () => {
    const had = modelFormHad();
    closeModelForm();
    if (modelFormFell(had)) modelFormBack(M.formFrom);
  };
  modelField('model-cancel').addEventListener('click', cancel);
  // Escape is Cancel (dashboard.md §4.25 *The Models form keeps the
  // focus*): a plain one (plainEscape), and not while Save's change is on
  // its way, which cannot be called back: its answer closes the form or
  // says why not.
  form.addEventListener('keydown', (e) => {
    if (!plainEscape(e)) return;
    if (modelField('model-save').disabled) return;
    e.preventDefault();
    cancel();
  });
  modelField('model-local').addEventListener('change', syncHelperBox);
  modelField('model-url').addEventListener('input', syncHelperBox);
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    // Save pressed, or Enter in a field: the focus is in the form.
    const had = modelFormHad();
    const err = modelField('model-error');
    err.textContent = '';
    const original = modelField('model-original').value;
    const model = {
      name: modelField('model-name').value.trim(),
      url: modelField('model-url').value.trim(),
      wire: modelField('model-wire').value,
      model: modelField('model-model').value.trim(),
      local: modelField('model-local').checked,
      helper: modelField('model-local').checked && modelField('model-helper').checked,
      allowPlainHttp: modelField('model-local').checked && modelField('model-plain-http').checked,
      tokenEnv: modelField('model-token-env').value.trim(),
    };
    const save = modelField('model-save');
    save.disabled = true;
    const r = await sendModelChange(original ? { action: 'update', name: original, model, version: M.formVersion } : { action: 'add', model });
    save.disabled = false;
    if (r.cancelled) { if (modelFormFell(had)) save.focus(); return; }
    if (r.status === 409 && r.data && r.data.stale) {
      // The model changed somewhere else while the form was open: nothing
      // was saved. The list is read again and the form keeps what was
      // typed; its next Save names the model as it is now.
      setWords(err, modelError(r));
      if (modelFormFell(had)) save.focus();
      await modelFormReread(original, err);
      return;
    }
    if (!r.ok || !r.data || !r.data.applied) { setWords(err, modelError(r)); if (modelFormFell(had)) save.focus(); return; }
    closeModelForm();
    MODEL_READS.wrote();
    // Taken before the list is drawn again, which drops a focus put on one
    // of its rows meanwhile: that one was moved by the person.
    const back = modelFormFell(had);
    modelsNotice((original ? 'Saved ' : 'Added ') + model.name + '. ' + (r.data.note || ''), r.data.changeId);
    await loadModels();
    if (back && modelFormFell(had)) modelFormBack(original ? model.name : null);
  });
}

/** After a save refused because the model changed meanwhile: read the list
 *  again, and give the open form the model's version as it is now, the
 *  fields untouched. A model gone since says so. */
async function modelFormReread(name, err) {
  await loadModels();
  const now = (M.models || []).find((x) => x.name === name);
  if (modelField('model-form').hidden || modelField('model-original').value !== name) return;
  if (!now) { setWords(err, 'Nothing was saved: ' + name + ' is no longer in your list.'); return; }
  M.formVersion = now.version || null;
}

async function removeModel(m, row) {
  const place = settingsPlace(row);
  busyRow(row, true);
  const r = await sendModelChange({ action: 'remove', name: m.name });
  if (r.cancelled) { busyRow(row, false); settingsRefocus(place); return; }
  if (!r.ok || !r.data || !r.data.applied) { busyRow(row, false); showAskError(row, modelError(r)); settingsRefocus(place, row); return; }
  MODEL_READS.wrote();
  modelsNotice('Removed ' + m.name + '. ' + (r.data.note || ''), r.data.changeId);
  await loadModels();
  settingsRefocus(place);
}

async function restoreModel(r, row) {
  const place = settingsPlace(row);
  busyRow(row, true);
  const res = await sendModelChange({ action: 'restore', name: r.name });
  if (res.cancelled) { busyRow(row, false); settingsRefocus(place); return; }
  if (!res.ok || !res.data || !res.data.applied) { busyRow(row, false); showAskError(row, modelError(res)); settingsRefocus(place, row); return; }
  MODEL_READS.wrote();
  modelsNotice('Brought back ' + r.name + '. ' + (res.data.note || ''), res.data.changeId);
  await loadModels();
  settingsRefocus(place);
}

/** Test connection: the server connects to the saved address and, where it
 *  can, reads the server's model list, as mandu doctor does. */
async function testModel(m, row) {
  const place = settingsPlace(row);
  const old = row.querySelector('.model-test');
  if (old) old.remove();
  const out = el('ul', { class: 'model-test', 'aria-live': 'polite' }, el('li', { text: 'Testing...' }));
  row.append(out);
  busyRow(row, true);
  const r = await apiPost('policy/models/test', { name: m.name });
  busyRow(row, false);
  settingsRefocus(place);
  clear(out);
  if (!r.ok || !r.data || !r.data.result) {
    out.append(el('li', { class: 'bad' }, words(refusalText(r, 'could not test the model (' + r.status + ')'))));
    return;
  }
  for (const l of r.data.result.lines || []) out.append(el('li', { class: l.tone, text: l.text }));
}

// ── Settings › Sensitivity labels (plan 14 §14.1; dashboard.md §4.25s) ──────
/** The labels Office put on documents, and the level each is suggested at.
 *  The server lists the levels you chose (and your administrator's, read
 *  only) and the labels the last scan found with no level yet; Save sends
 *  one change, asked about first when it lowers what Mandu suggests. */
async function loadLabels() {
  const host = document.getElementById('settings-labels');
  if (!host) return;
  const asked = LABEL_READS.ask();
  const r = await apiGetControl('policy/sensitivity-labels').catch(() => null);
  if (!LABEL_READS.take(asked)) return;
  clear(host);
  const vm = r && r.ok && r.data && r.data.labels;
  if (!vm || !Array.isArray(vm.mappings) || !Array.isArray(vm.unmapped)) {
    S.unread.add('labels');
    host.append(el('div', { class: 'empty' }, words(refusalText(r, 'The sensitivity labels could not be read.'))));
    return;
  }
  S.unread.delete('labels');
  for (const m of vm.mappings) host.append(labelMappingRow(m, vm));
  for (const u of vm.unmapped) host.append(labelUnmappedRow(u, vm));
  if (vm.unmappedMore > 0) host.append(el('div', { class: 'note', text: vm.unmappedMore + ' more labels were found. Give these a level, then scan again to see the rest.' }));
  // A link in the note opens Keys Mandu found, where Scan for keys is (§4.25s).
  if (vm.note) host.append(el('div', { class: 'empty labels-note' }, textParts(vm.noteParts, vm.note)));
}

function labelLevelPicker(vm, current, name) {
  const sel = el('select', { class: 'label-level', 'aria-label': 'Level for ' + name });
  for (const l of vm.levels || []) {
    const o = el('option', { value: l.level, text: l.words });
    if (l.level === current) o.selected = true;
    sel.append(o);
  }
  return sel;
}

/** A label that has a level: its name, its id, the level, and Save / Remove
 *  (read only when your administrator set it). */
function labelMappingRow(m, vm) {
  const row = el('div', { class: 'row service label-row', 'data-id': m.id, 'data-site': m.site || '' });
  row.append(el('div', { class: 'name', text: m.name || m.id }));
  row.append(el('div', { class: 'sub' }, el('code', { text: m.id }), m.site ? ' (organization ' + m.site + ')' : ''));
  if (m.admin) {
    row.append(el('div', { class: 'label-level-words', text: m.levelWords }));
    row.append(el('div', { class: 'model-admin', text: 'Set by your administrator.' }));
    return row;
  }
  const pick = labelLevelPicker(vm, m.level, m.name || m.id);
  const acts = el('div', { class: 'model-actions' });
  acts.append(pick);
  acts.append(el('button', { type: 'button', class: 'btn small label-save-btn', text: 'Save', 'aria-label': 'Save the level for ' + (m.name || m.id), onclick: () =>
    sendLabelChange({ action: 'map', id: m.id, ...(m.site ? { site: m.site } : {}), name: m.name, level: pick.value, version: m.version }, row, 'Saved ' + (m.name || m.id) + '.') }));
  acts.append(el('button', { type: 'button', class: 'btn small label-remove-btn', text: 'Remove', 'aria-label': 'Remove the level for ' + (m.name || m.id), onclick: () =>
    sendLabelChange({ action: 'unmap', id: m.id, ...(m.site ? { site: m.site } : {}), version: m.version }, row, 'Removed ' + (m.name || m.id) + '.') }));
  row.append(acts);
  return row;
}

/** A label the last scan found with no level: its id, how many files carry
 *  it, a name box and a level picker. */
function labelUnmappedRow(u, vm) {
  const row = el('div', { class: 'row service label-row label-unmapped', 'data-id': u.id, 'data-site': u.site || '' });
  row.append(el('div', { class: 'name' }, el('code', { text: u.id })));
  row.append(el('div', { class: 'sub', text: u.filesWords + (u.site ? ' (organization ' + u.site + ')' : '') + '. No level yet, so Mandu suggests nothing for it.' }));
  const name = el('input', { type: 'text', class: 'label-name', placeholder: 'Its name, e.g. Highly Confidential', maxlength: '64', 'aria-label': 'Name of the label ' + u.id, autocomplete: 'off', spellcheck: 'false' });
  const pick = labelLevelPicker(vm, vm.defaultLevel || 'no-model', u.id);
  const acts = el('div', { class: 'model-actions' });
  acts.append(name, pick);
  acts.append(el('button', { type: 'button', class: 'btn small label-save-btn', text: 'Save', 'aria-label': 'Save the level for ' + u.id, onclick: () =>
    sendLabelChange({ action: 'map', id: u.id, ...(u.site ? { site: u.site } : {}), name: name.value.trim(), level: pick.value, version: u.version }, row, 'Saved ' + (name.value.trim() || u.id) + '.') }));
  row.append(acts);
  row.append(el('div', { class: 'field-hint', text: 'A label your organization lets cloud AI read is usually "Any AI, when it asks"; any other, "No AI". Mandu cannot read your organization\'s settings, so you choose.' }));
  return row;
}

function labelsNotice(text, changeId) {
  const box = document.getElementById('labels-notice');
  if (!box) return;
  clear(box);
  box.hidden = !text;
  if (!text) return;
  box.append(noticeWords(box, text));
  if (changeId) {
    box.append(noticeUndo(box, 'Sensitivity labels', async () => {
      const place = settingsPlace(box);
      for (const b of box.querySelectorAll('button')) b.disabled = true;
      const r = await apiPost('policy/changes/' + encodeURIComponent(changeId) + '/undo');
      if (!r.ok) { labelsNotice(refusalText(r, 'could not undo (' + r.status + ')'), null); settingsRefocus(place); return; }
      LABEL_READS.wrote();
      labelsNotice('Undone.', null);
      await loadLabels();
      settingsRefocus(place);
    }));
  }
}

/** One change: asked about first when the server says it lowers what Mandu
 *  suggests (the same question as Settings › Models). It names the
 *  mapping's version as the row was read (dashboard.md §4.25s *A change
 *  names the label as it was read*). */
async function sendLabelChange(body, row, done) {
  const place = settingsPlace(row);
  busyRow(row, true);
  let r = await apiPost('policy/sensitivity-labels/change', body);
  if (r.ok && r.data && r.data.confirm) {
    if (!window.confirm(modelConfirmText(r.data))) { busyRow(row, false); settingsRefocus(place); return; }
    r = await apiPost('policy/sensitivity-labels/change', { ...body, expected: r.data.expected });
  }
  if (r.status === 409 && r.data && r.data.stale) { await labelStaleReread(row, r, place); return; }
  if (!r.ok || !r.data || !r.data.applied) { busyRow(row, false); showAskError(row, modelError(r)); settingsRefocus(place, row); return; }
  LABEL_READS.wrote();
  labelsNotice(done + ' ' + (r.data.note || ''), r.data.changeId);
  await loadLabels();
  settingsRefocus(place);
}

/** After a change refused because the label's mapping changed somewhere
 *  else meanwhile: nothing was saved. The list is read again, so the row
 *  shows the mapping as it is now and carries its version now; the level
 *  picked and the name typed are put back on it, with the refusal under
 *  it; its next Save names the mapping as it is now. A label gone from the
 *  list says so where the notice goes. */
async function labelStaleReread(row, r, place) {
  const id = row.getAttribute('data-id');
  const site = row.getAttribute('data-site') || '';
  const pick = row.querySelector('.label-level');
  const name = row.querySelector('.label-name');
  const kept = { level: pick ? pick.value : null, name: name ? name.value : null };
  const said = modelError(r);
  await loadLabels();
  let again = null;
  for (const x of document.querySelectorAll('#settings-labels .label-row')) {
    if (x.getAttribute('data-id') === id && (x.getAttribute('data-site') || '') === site) { again = x; break; }
  }
  if (!again) { labelsNotice(said + ' It is no longer in the list.', null); settingsRefocus(place); return; }
  const pickNow = again.querySelector('.label-level');
  if (pickNow && kept.level !== null) pickNow.value = kept.level;
  const nameNow = again.querySelector('.label-name');
  if (nameNow && kept.name !== null) nameNow.value = kept.name;
  showAskError(again, said);
  settingsRefocus(place, again);
}

// ── Settings › Prompt filters (plan 15 §13.7; dashboard.md §4.25y) ──────────
/** The words of unread prompt filter settings: the refusal in the words of
 *  the page. Its route answers the failed dial to a stopped service as "did
 *  not answer" (a 502, as for a service that hangs), so while the latest
 *  Home poll knows the service is not running, the block says so as Models
 *  and Sensitivity labels beside it do (dashboard.md §4.25 *A could-not
 *  line names the cause the page knows*). */
function promptUnreadWords(u) {
  if (u.r && u.r.status === 502 && S.homeFailure === 'down') return UNREACHABLE_WORDS;
  return refusalText(u.r, u.note || 'The prompt filter settings could not be read.');
}
/** Draw the unread line again with the words it says now: a Home poll that
 *  learns the cause after the read changes them (followCannotCheck). */
function drawPromptUnread() {
  const u = S.promptUnread;
  u.shown = promptUnreadWords(u);
  setWords(u.line, u.shown);
}

/** What Mandu does with each kind of thing it finds in what you type, and
 *  the exceptions. The server lists them in plain words (the developer
 *  view's own listing, view-model/prompt-settings.ts); each change is ONE
 *  edit, asked about first when it lets more reach the AI. A kind your
 *  administrator locked offers only stricter choices and names the file. */
async function loadPromptSettings() {
  const host = document.getElementById('settings-prompt-kinds');
  if (!host) return;
  const exHost = document.getElementById('settings-prompt-exceptions');
  const meanings = document.getElementById('settings-prompt-meanings');
  const form = document.getElementById('prompt-exception-form');
  const asked = PROMPT_READS.ask();
  const r = await apiGetControl('policy/prompt-filters').catch(() => null);
  if (!PROMPT_READS.take(asked)) return;
  clear(host); clear(exHost); clear(meanings);
  const vm = r && r.ok && r.data && r.data.settings;
  const unread = !vm || !vm.available || !Array.isArray(vm.kinds);
  if (unread) S.unread.add('prompt'); else S.unread.delete('prompt');
  // Unread, the block is its refusal alone: no meanings, and no Exceptions
  // heading over a list that cannot be read (dashboard.md §4.25 "Empty states").
  // The meanings go with their fold: a "What the choices mean" that opens
  // on nothing is hidden too, as when a server sends no meanings.
  const noMeanings = unread || !(vm.meanings || []).length;
  for (const id of ['settings-prompt-meanings-fold', 'settings-prompt-meanings', 'settings-prompt-exceptions-head', 'settings-prompt-exceptions-about', 'settings-prompt-exceptions']) {
    const part = document.getElementById(id);
    if (part) part.hidden = id.startsWith('settings-prompt-meanings') ? noMeanings : unread;
  }
  S.promptUnread = null;
  if (unread) {
    S.promptUnread = { line: el('div', { class: 'empty' }), r, note: (vm && vm.note) || null, shown: null };
    host.append(S.promptUnread.line);
    drawPromptUnread();
    form.hidden = true;
    return;
  }
  if (!vm.editable) host.append(el('div', { class: 'empty prompt-readonly', text: vm.note }));
  if (!vm.enforcing) host.append(el('div', { class: 'empty prompt-off', text: 'Protection is off, so Mandu only notes what it finds. These choices apply when it is on.' }));
  for (const k of vm.kinds) host.append(promptKindRow(k));
  for (const m of vm.meanings || []) meanings.append(el('dt', { text: m.words }), el('dd', { text: m.meaning }));
  const kind = document.getElementById('prompt-exception-kind');
  clear(kind);
  for (const k of vm.exceptionKinds || []) kind.append(el('option', { value: k.category, text: k.name }));
  form.hidden = !vm.editable || !(vm.exceptionKinds || []).length;
  // How to write an exception only over the form that takes one; without
  // it, why not, in the server's words (dashboard.md §4.25y *An exception
  // that cannot be added says why*). Read only, neither: the note above
  // the kinds says why nothing can be changed.
  document.getElementById('settings-prompt-exceptions-how').hidden = form.hidden;
  const why = document.getElementById('settings-prompt-exceptions-why');
  why.textContent = form.hidden && vm.exceptionNotOffered ? vm.exceptionNotOffered : '';
  why.hidden = !why.textContent;
  // The reason already says what happens to what Mandu finds, so under it
  // the empty list says only that it is empty (§4.25y).
  if (!vm.exceptions.length) exHost.append(el('div', { class: 'empty', text: why.hidden ? 'No exceptions. Everything Mandu finds gets the choice above.' : 'No exceptions.' }));
  for (const x of vm.exceptions) exHost.append(promptExceptionRow(x));
}

function promptKindName(k) {
  return k.named ? el('code', { text: k.name }) : k.name;
}
/** A kind's name inside a sentence: "an email address", "a secret Mandu
 *  already knows", "acme.ticket". The server capitalises only its first
 *  letter (view-model/prompt-settings.ts kindName), so only that one goes. */
function promptKindWords(k) {
  return k.named ? k.name : k.name.charAt(0).toLowerCase() + k.name.slice(1);
}

/** One kind: its name, who set it, and what happens to it (a choice, or
 *  the words alone when nothing can be chosen). */
function promptKindRow(k) {
  const row = el('div', { class: 'row service prompt-kind', 'data-category': k.category });
  row.append(el('div', { class: 'name' }, promptKindName(k)));
  row.append(el('div', { class: 'sub prompt-who', text: k.who }));
  const acts = el('div', { class: 'model-actions' });
  if (!k.choices.length) {
    acts.append(el('span', { class: 'prompt-action-words', text: k.actionWords }));
    row.append(acts);
    return row;
  }
  const sel = el('select', { class: 'prompt-action', 'aria-label': 'What happens to ' + promptKindWords(k) });
  for (const c of k.choices) {
    const o = el('option', { value: c.action, text: c.words });
    if (c.action === k.action) o.selected = true;
    sel.append(o);
  }
  sel.addEventListener('change', () => {
    const words = (k.choices.find((c) => c.action === sel.value) || {}).words || sel.value;
    sendPromptChange({ op: 'set-prompt-action', category: k.category, action: sel.value }, row, k.name + ': ' + words + '.');
  });
  acts.append(sel);
  if (k.canReset) {
    acts.append(el('button', { type: 'button', class: 'btn small prompt-reset-btn', text: 'Use the default', 'aria-label': 'Use the default for ' + promptKindWords(k), onclick: () =>
      sendPromptChange({ op: 'remove-prompt-action', category: k.category }, row, k.name + ': back to the default.') }));
  }
  row.append(acts);
  return row;
}

/** One exception: its kind and what it matches as one sentence, who added
 *  it on the line under it, and Remove for your own (dashboard.md §4.25y
 *  *An exception reads as a sentence*). One a locked kind keeps out of
 *  force says so. */
function promptExceptionRow(x) {
  // Keyed by its pattern too: two exceptions of one kind are two rows
  // (settingsPlace gives the focus back to the right one).
  const row = el('div', { class: 'row service prompt-exception', 'data-category': x.category, 'data-match': x.match });
  row.append(el('div', { class: 'prompt-exception-what' },
    el('div', { class: 'name' }, promptKindName(x), ' matching ', el('code', { text: x.match })),
    el('div', { class: 'sub', text: x.who + (x.inForce ? '.' : '. Not in force: your administrator locked this kind.') })));
  if (x.removable) {
    row.append(el('button', { type: 'button', class: 'btn small right prompt-exception-remove', text: 'Remove', 'aria-label': 'Remove the exception for ' + promptKindWords(x) + ' matching ' + x.match, onclick: () =>
      sendPromptChange({ op: 'remove-prompt-exception', category: x.category, match: x.match }, row, 'Removed the exception for ' + x.match + '.') }));
  }
  return row;
}

function promptNotice(text, changeId) {
  const box = document.getElementById('prompt-notice');
  if (!box) return;
  clear(box);
  box.hidden = !text;
  if (!text) return;
  box.append(noticeWords(box, text));
  if (changeId) {
    box.append(noticeUndo(box, 'Prompt filters', async () => {
      const place = settingsPlace(box);
      for (const b of box.querySelectorAll('button')) b.disabled = true;
      const r = await apiPost('policy/changes/' + encodeURIComponent(changeId) + '/undo');
      if (!r.ok) { promptNotice(refusalText(r, 'could not undo (' + r.status + ')'), null); settingsRefocus(place); return; }
      PROMPT_READS.wrote();
      promptNotice('Undone.', null);
      await loadPromptSettings();
      settingsRefocus(place);
    }));
  }
}

/** One change: asked about first when the server says it lets more reach
 *  the AI (the same question as Settings › Models). A refusal, such as a
 *  kind your administrator locked, is said on the row. */
async function sendPromptChange(edit, row, done) {
  const place = settingsPlace(row);
  busyRow(row, true);
  let r = await apiPost('policy/prompt-filters/change', { edit });
  if (r.ok && r.data && r.data.confirm) {
    if (!window.confirm(modelConfirmText(r.data))) { await loadPromptSettings(); settingsRefocus(place); return false; }
    r = await apiPost('policy/prompt-filters/change', { edit, expected: r.data.expected });
  }
  if (!r.ok || !r.data || !r.data.applied) { busyRow(row, false); showAskError(row, modelError(r)); settingsRefocus(place, row); return false; }
  PROMPT_READS.wrote();
  promptNotice(done + ' It applies to your next message.', r.data.changeId);
  await loadPromptSettings();
  settingsRefocus(place);
  return true;
}

function wirePromptExceptionForm() {
  const form = document.getElementById('prompt-exception-form');
  if (!form) return;
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const err = document.getElementById('prompt-exception-error');
    const match = document.getElementById('prompt-exception-match');
    const kind = document.getElementById('prompt-exception-kind');
    err.textContent = '';
    if (!match.value.trim()) { err.textContent = 'Type what it should match.'; return; }
    const ok = await sendPromptChange({ op: 'add-prompt-exception', category: kind.value, match: match.value.trim() }, form, 'Added the exception for ' + match.value.trim() + '.');
    if (ok) match.value = '';
  });
}

/** Every card of Settings, read at once; done once each has drawn (a link to
 *  a card scrolls there then, openAtCard). */
async function loadSettings() {
  await Promise.all([loadProtection(), loadModels(), loadLabels(), loadPromptSettings(), loadServices()]);
}

async function loadServices() {
  S.serviceOut++;
  let r = null;
  try { r = await apiGet('control/summary'); } catch { r = null; } finally { S.serviceOut--; }
  drawServices(r && r.summary);
}

/** The poll: the service row follows the service while Settings is open
 *  (dashboard.md §4.25 *The service row follows the service*). A crash, or
 *  a start from the developer view or another tab, changes it with no click
 *  here. The row is drawn again only when the summary changed, so the answer
 *  to its button stays; never under the Restart question or while a request
 *  of its own is out (whose answer draws the row). No answer: the row stays
 *  as drawn. */
async function followServices() {
  const held = () => S.page !== 'settings' || S.serviceOut > 0 || !!document.getElementById('settings-service-confirm');
  if (held()) return;
  let sum = null;
  try { const r = await apiGet('control/summary'); sum = r && r.summary; } catch { sum = null; }
  if (!sum || held() || JSON.stringify(sum) === S.services) return;
  // Drawn anew from nothing: the focus keeps its place, as the poll keeps
  // it on Home (pollPlace; dashboard.md §4.25 *The service row keeps the
  // focus*).
  const place = pollPlace(document.getElementById('settings-protection-block'));
  drawServices(sum);
  pollRefocus(place);
}

/** After an answer to the service row, only if the focus fell from the
 *  Protection card where it was pressed (dashboard.md §4.25 *The service
 *  row keeps the focus*). A refusal gives it back to the button pressed
 *  (`refused`: its words, Restart for Restart now), on again and described
 *  by the words of the refusal; else, and after an answer that worked, the
 *  line takes it and reads what the service does now. */
function serviceFocus(refused) {
  if (!focusFell()) return;
  const line = document.getElementById('settings-service-main');
  const said = line && line.querySelector('.ask-error');
  const b = refused && said && [...line.querySelectorAll('button')].find((x) => x.textContent === refused && !x.disabled);
  if (b) {
    b.setAttribute('aria-describedby', said.id);
    b.focus({ preventScroll: true });
    return;
  }
  const to = line || document.getElementById('settings-services');
  if (to) focusThere(to);
}
/** The focus is in the Protection card: a press made there keeps it. */
function inProtectionCard() {
  const a = document.activeElement;
  const card = document.getElementById('settings-protection-block');
  return !!a && !!card && card.contains(a);
}

function drawServices(sum) {
  const host = document.getElementById('settings-services');
  clear(host);
  // Restart's question sits under the row, outside the line: it goes with it.
  const asked = document.getElementById('settings-service-confirm');
  if (asked) asked.remove();
  S.services = sum ? JSON.stringify(sum) : null;
  S.serviceState = sum && sum.available ? sum.state : null;
  const dot = document.querySelector('#settings-protect-row .name .dot');
  if (dot) dot.className = 'dot ' + protectDot();
  if (!sum) {
    host.append(el('span', { class: 'service-none' }, 'This dashboard was started without the service controls. Start it with ',
      ownCode('mandu dashboard'), ' to manage the protection service here.'));
    return;
  }
  // The second line of the Protection row, in plain words built by the
  // server (view-model/service-summary.ts, dashboard.md §4.25 *One
  // Protection row*): the state, a sentence, when it started, and Start or
  // Restart. The row's dot covers it (protectDot); the developer view keeps
  // every service.
  if (!sum.available) host.append(el('span', { class: 'service-none', text: sum.sentence }));
  else {
    const since = whenNode(sum.since);
    const line = el('div', { id: 'settings-service-main' }, el('span', { class: 'service-state', text: sum.name }), '.',
      sum.sentence ? ' ' + sum.sentence : null, since ? ' Started ' : null, since, since ? '.' : null);
    if (sum.action) {
      // The answer is said on the line (§4.25 *Refusals*): signed out every
      // control POST is refused, and a repaint alone read as if it worked.
      // `kept`: pressed with the focus in the card, so the answer gives the
      // focus on once it fell (serviceFocus).
      const act = async (kept) => {
        btn.disabled = true;
        S.serviceOut++;
        try {
          const r = await apiPost(sum.action.path);
          if (r.ok) {
            await loadSettings();
            if (kept) serviceFocus(null);
            return;
          }
          const text = refusalText(r, 'could not ' + sum.action.label.toLowerCase() + ' the protection service (' + r.status + ')');
          // Drawn again first (a start that failed can leave it stopped
          // unexpectedly), then the answer goes on the line drawn now.
          await loadServices();
          const fresh = document.getElementById('settings-service-main');
          if (fresh) showAskError(fresh, text);
          else document.getElementById('settings-services').append(el('div', { class: 'ask-error' }, words(text)));
          if (kept) serviceFocus(sum.action.label);
        } finally { S.serviceOut--; }
      };
      const btn = el('button', { type: 'button', class: 'btn small service-btn', text: sum.action.label, onclick: () => {
        if (!sum.action.confirm) return act(inProtectionCard());
        // Restart asks first, inline under the row: running agents are
        // blocked while it is down. Start needs no question. The question
        // takes the focus of the button, which goes off; Escape is Cancel,
        // and Cancel gives the button the focus back. Once Restart now is
        // on its way it cannot be called back, so Cancel goes off with it.
        const had = document.activeElement === btn;
        btn.disabled = true;
        const cancel = () => { ask.remove(); btn.disabled = false; btn.focus(); };
        const no = el('button', { type: 'button', class: 'btn small', text: 'Cancel', onclick: cancel });
        const ask = el('div', { class: 'service-confirm', id: 'settings-service-confirm', role: 'alert' },
          el('p', { text: sum.action.confirm }),
          el('div', { class: 'service-confirm-actions' },
            no,
            el('button', { type: 'button', class: 'btn small primary', text: sum.action.label + ' now', onclick: (e) => {
              const kept = inProtectionCard();
              e.currentTarget.disabled = true;
              no.disabled = true;
              return act(kept);
            } })));
        ask.addEventListener('keydown', (e) => {
          if (!plainEscape(e) || no.disabled) return;
          e.preventDefault();
          cancel();
        });
        document.getElementById('settings-protect-row').after(ask);
        if (had) focusThere(ask.querySelector('p'));
      } });
      line.append(' ', btn);
    }
    host.append(line);
  }
  if (sum.helperNote) host.append(el('p', { class: 'note', id: 'settings-service-helper', text: sum.helperNote }));
}

/** index.html keeps a long explanation in `<span data-help="label">text</span>`:
 *  shown as a "?" that opens it, so a form reads as its labels first. */
function wireStaticHelp() {
  for (const span of document.querySelectorAll('[data-help]')) {
    span.replaceWith(helpButton(span.getAttribute('data-help'), span.textContent.trim()));
  }
}

// ── Boot ──────────────────────────────────────────────────────────────────────
function boot() {
  wireStaticHelp();
  wireNav();
  drawSectionLinks();
  wireHistorySearch();
  document.getElementById('agent-only').addEventListener('click', flipAgentOnly);
  wireLockForm();
  wireRuleFind();
  wireModelForm();
  wirePromptExceptionForm();
  wireDescribe();
  renderNotifyControls();
  wireAppearance();
  document.getElementById('notify-offer-btn').addEventListener('click', askNotifyPermission);
  document.getElementById('notify-enable').addEventListener('click', pressNotifyButton);
  // Another tab's Turn off / Turn on: this tab's row says so too.
  window.addEventListener('storage', (e) => { if (e.key === NOTIFY_OFF_KEY || e.key === null) renderNotifyControls(); });
  const dataWhere = document.getElementById('home-data');
  dataWhere.addEventListener('toggle', () => { if (dataWhere.open) loadDataLocations(); });
  const route = currentRoute();
  const load = setPage(route.page, false, route.session, route.ask);
  // The first read of Home draws Rules' Built-in protections and part of
  // Settings: a card the address names waits for it too.
  const homeRead = loadHome();
  landAtSection(Promise.all([load, homeRead]));
  // The poll, every POLL_MS while the tab is shown and on a return to it:
  // Home, and on Settings the service row (followServices).
  const poll = () => { if (document.visibilityState === 'visible') { loadHome(); followServices(); } };
  setInterval(poll, POLL_MS);
  document.addEventListener('visibilitychange', poll);
}
boot();
